package secrets_test

// Audit-first tests for secret rotation: no version may be archived and no
// value replaced unless the critical attempt row was written first, and the
// scheduler must skip and retry a secret it cannot audit.

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	auditServices "rocketvault/internal/services/audit"
	"rocketvault/internal/services/secrets"
	"rocketvault/model"
)

// rotationAudit records calls in order, can fail critical writes, and runs
// onCritical while the attempt row is being written.
type rotationAudit struct {
	mu          sync.Mutex
	criticalErr error
	onCritical  func()
	calls       []string
	critical    []auditServices.AuditEvent
	events      []auditServices.AuditEvent
}

func (a *rotationAudit) RecordEvent(_ context.Context, ev auditServices.AuditEvent) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.calls = append(a.calls, "event:"+ev.Outcome)
	a.events = append(a.events, ev)
	return nil
}

func (a *rotationAudit) RecordCritical(_ context.Context, ev auditServices.AuditEvent) error {
	if a.onCritical != nil {
		a.onCritical()
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	a.calls = append(a.calls, "critical:"+ev.Outcome)
	a.critical = append(a.critical, ev)
	return a.criticalErr
}

func (a *rotationAudit) PersistAudit(_, _, _ string) error { return nil }

// rotationState is every row a rotation could write.
type rotationState struct {
	value    string
	version  int
	versions int
	history  int
	next     string
}

func (f *rotationFixture) state(t *testing.T) rotationState {
	t.Helper()
	var s rotationState
	require.NoError(t, f.conn.QueryRow("SELECT value, version FROM secrets WHERE id = ?", f.secretID.String()).Scan(&s.value, &s.version))
	require.NoError(t, f.conn.QueryRow("SELECT COUNT(*) FROM secret_versions").Scan(&s.versions))
	require.NoError(t, f.conn.QueryRow("SELECT COUNT(*) FROM secret_rotation_history").Scan(&s.history))
	require.NoError(t, f.conn.QueryRow("SELECT COALESCE(CAST(next_rotation_at AS TEXT), '') FROM secret_policies WHERE secret_id = ?", f.secretID.String()).Scan(&s.next))
	return s
}

func requireRotationAuditUnavailable(t *testing.T, err error) {
	t.Helper()
	require.Error(t, err)
	assert.True(t, errors.Is(err, auditServices.ErrAuditUnavailable), "%v", err)
	assert.Equal(t, "audit unavailable", err.Error(), "the cause must not reach the caller")
}

func TestPerformManualRotation_AuditFailureWritesNoVersion(t *testing.T) {
	f := newRotationFixture(t, "original-password")
	before := f.state(t)
	audit := &rotationAudit{criticalErr: errors.New("pq: disk full on audit_logs")}
	f.rotationSvc.SetAuditService(audit)

	err := f.rotationSvc.PerformManualRotation(context.Background(), secrets.ManualRotationRequest{
		SecretID: f.secretID, PolicyID: f.policyID, Scope: f.scope(), NewValue: "new-password",
	})

	requireRotationAuditUnavailable(t, err)
	assert.Equal(t, before, f.state(t), "no version, value, history or schedule may change")
	require.Len(t, audit.critical, 1)
	ev := audit.critical[0]
	assert.Equal(t, "rotate_secret", ev.Action)
	assert.Equal(t, "attempt", ev.Outcome)
	assert.Equal(t, "secret", ev.ResourceType)
	assert.Equal(t, f.secretID.String(), ev.ResourceID)
	assert.Equal(t, f.userID.String(), ev.UserID)
}

// TestPerformManualRotation_AttemptPrecedesArchive pins the order and that
// the actor is the caller, not the secret's owner.
func TestPerformManualRotation_AttemptPrecedesArchive(t *testing.T) {
	f := newRotationFixture(t, "original-password")
	before := f.state(t)
	audit := &rotationAudit{}
	audit.onCritical = func() {
		assert.Equal(t, before, f.state(t), "nothing may be written before the attempt row")
	}
	f.rotationSvc.SetAuditService(audit)
	actor := uuid.New()

	require.NoError(t, f.rotationSvc.PerformManualRotation(context.Background(), secrets.ManualRotationRequest{
		SecretID: f.secretID, PolicyID: f.policyID, Scope: model.NewVaultScope(f.vaultID, actor), NewValue: "new-password",
	}))

	assert.Equal(t, []string{"critical:attempt", "event:success"}, audit.calls)
	after := f.state(t)
	assert.Equal(t, before.version+1, after.version)
	assert.Equal(t, before.versions+1, after.versions)
	require.Len(t, audit.critical, 1)
	assert.Equal(t, actor.String(), audit.critical[0].UserID)
	assert.Equal(t, f.secretID.String(), audit.critical[0].ResourceID)
}

// TestPerformManualRotation_RefusalsAreNotCritical pins that a request
// refused before the effect writes no critical row.
func TestPerformManualRotation_RefusalsAreNotCritical(t *testing.T) {
	f := newRotationFixture(t, "original-password")
	audit := &rotationAudit{criticalErr: errors.New("down")}
	f.rotationSvc.SetAuditService(audit)
	ctx := context.Background()

	err := f.rotationSvc.PerformManualRotation(ctx, secrets.ManualRotationRequest{SecretID: f.secretID, PolicyID: f.policyID, Scope: f.scope()})
	assert.ErrorIs(t, err, secrets.ErrRotationValueRequired)
	err = f.rotationSvc.PerformManualRotation(ctx, secrets.ManualRotationRequest{SecretID: uuid.New(), PolicyID: f.policyID, Scope: f.scope(), NewValue: "x"})
	assert.Error(t, err)
	assert.NotErrorIs(t, err, auditServices.ErrAuditUnavailable)
	err = f.rotationSvc.PerformManualRotation(ctx, secrets.ManualRotationRequest{
		SecretID: f.secretID, PolicyID: f.policyID, Scope: model.NewVaultScope(uuid.New(), f.userID), NewValue: "x",
	})
	assert.NotErrorIs(t, err, auditServices.ErrAuditUnavailable, "an out-of-scope secret is refused first")

	assert.Empty(t, audit.critical)
}

// TestAutomaticRotation_AuditDownSkipsAndRetries pins that the scheduler
// neither rotates nor reschedules a secret it cannot audit, does not fail
// the sweep, and rotates it on the next tick once audit is back.
func TestAutomaticRotation_AuditDownSkipsAndRetries(t *testing.T) {
	f := newRotationFixture(t, "original-password")
	before := f.state(t)
	audit := &rotationAudit{criticalErr: errors.New("down")}
	f.rotationSvc.SetAuditService(audit)
	ctx := context.Background()

	require.NoError(t, f.schedulerSvc.ProcessUserRotations(ctx, f.userID))
	assert.Equal(t, before, f.state(t), "the secret stays due and unchanged")
	require.Len(t, audit.critical, 1)
	assert.Equal(t, "system", audit.critical[0].UserID, "an unattended rotation has no acting principal")
	assert.Contains(t, audit.critical[0].Details, f.userID.String(), "the owner is kept in the details")

	audit.criticalErr = nil
	require.NoError(t, f.schedulerSvc.ProcessUserRotations(ctx, f.userID))
	after := f.state(t)
	assert.Equal(t, before.version+1, after.version, "the next tick retries")
	assert.NotEqual(t, before.next, after.next)
}

// TestAutomaticRotation_ResultRowIsSystem pins that both chained rows of a
// successful scheduled rotation name "system", not the secret owner.
func TestAutomaticRotation_ResultRowIsSystem(t *testing.T) {
	f := newRotationFixture(t, "original-password")
	audit := &rotationAudit{}
	f.rotationSvc.SetAuditService(audit)

	require.NoError(t, f.schedulerSvc.ProcessUserRotations(context.Background(), f.userID))

	require.Len(t, audit.critical, 1)
	assert.Equal(t, "system", audit.critical[0].UserID)
	require.Len(t, audit.events, 1)
	assert.Equal(t, "system", audit.events[0].UserID)
	assert.Equal(t, f.secretID.String(), audit.events[0].ResourceID)
}

// TestPerformManualRotation_NilActorIsSystem pins that a rotation with no
// acting principal records "system", never the zero UUID.
func TestPerformManualRotation_NilActorIsSystem(t *testing.T) {
	f := newRotationFixture(t, "original-password")
	audit := &rotationAudit{}
	f.rotationSvc.SetAuditService(audit)

	require.NoError(t, f.rotationSvc.PerformManualRotation(context.Background(), secrets.ManualRotationRequest{
		SecretID: f.secretID, PolicyID: f.policyID, Scope: model.NewAdminScope(uuid.Nil), NewValue: "new-password",
	}))

	require.Len(t, audit.critical, 1)
	assert.Equal(t, "system", audit.critical[0].UserID)
}
