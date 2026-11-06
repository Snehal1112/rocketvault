package authorization

// Audit-first tests: a role assignment must not be granted or revoked unless
// its critical attempt row was written first, and a refused request writes no
// critical row.

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	auditServices "rocketvault/internal/services/audit"
	"rocketvault/model"
)

// fakeRoleAudit records calls in order, can fail critical writes, and runs
// onCritical while the attempt row is being written.
type fakeRoleAudit struct {
	mu          sync.Mutex
	criticalErr error
	onCritical  func()
	calls       []string
	critical    []auditServices.AuditEvent
	events      []auditServices.AuditEvent
}

func (f *fakeRoleAudit) RecordEvent(_ context.Context, ev auditServices.AuditEvent) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, "event:"+ev.Outcome)
	f.events = append(f.events, ev)
	return nil
}

func (f *fakeRoleAudit) RecordCritical(_ context.Context, ev auditServices.AuditEvent) error {
	if f.onCritical != nil {
		f.onCritical()
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, "critical:"+ev.Outcome)
	f.critical = append(f.critical, ev)
	return f.criticalErr
}

func (f *fakeRoleAudit) PersistAudit(_, _, _ string) error { return nil }

func requireRoleAuditUnavailable(t *testing.T, err error) {
	t.Helper()
	require.Error(t, err)
	assert.True(t, errors.Is(err, auditServices.ErrAuditUnavailable), "%v", err)
	assert.Equal(t, "audit unavailable", err.Error(), "the cause must not reach the caller")
}

// roleAuditFixture holds a service with audit wired and one existing assignment.
type roleAuditFixture struct {
	rr       *fakeRoleRepo
	pr       *fakePolicyRepo
	svc      RoleAssignmentService
	alice    uuid.UUID
	actor    uuid.UUID
	vault    uuid.UUID
	existing *model.RoleAssignment
}

func newRoleAuditFixture(audit auditServices.AuditServiceInterface) *roleAuditFixture {
	f := &roleAuditFixture{rr: newFakeRoleRepo(), pr: newFakePolicyRepo(), alice: uuid.New(), actor: uuid.New(), vault: uuid.New()}
	f.existing = &model.RoleAssignment{ID: uuid.New(), PrincipalID: uuid.New(), Role: model.RoleKeyVaultSecretsUser, VaultID: f.vault}
	f.rr.rows[f.existing.ID] = f.existing
	ul := &fakeUserLookup{users: map[string]model.User{"alice": {ID: f.alice, Username: "alice"}}}
	f.svc = NewRoleAssignmentService(f.rr, f.pr, ul, nil, audit)
	return f
}

func (f *roleAuditFixture) grant(role string, globalAdmin bool) (*model.RoleAssignment, error) {
	return f.svc.AssignRole(context.Background(), AssignRoleInput{
		Principal: "alice", Role: role, VaultID: f.vault, CreatedBy: f.actor, CallerIsGlobalAdmin: globalAdmin,
	})
}

func TestAssignRole_AuditFailureCreatesNothing(t *testing.T) {
	audit := &fakeRoleAudit{criticalErr: errors.New("pq: disk full on audit_logs")}
	f := newRoleAuditFixture(audit)

	ra, err := f.grant(model.RoleKeyVaultSecretsOfficer, false)

	requireRoleAuditUnavailable(t, err)
	assert.Nil(t, ra)
	assert.Len(t, f.rr.rows, 1, "no assignment may be created")
	assert.Empty(t, f.pr.created, "no policy may be expanded")
	require.Len(t, audit.critical, 1)
	ev := audit.critical[0]
	assert.Equal(t, "assign_role", ev.Action)
	assert.Equal(t, "attempt", ev.Outcome)
	assert.Equal(t, "role_assignment", ev.ResourceType)
	assert.Equal(t, f.actor.String(), ev.UserID, "the actor is the granting caller, not the grantee")
	assert.NotEqual(t, f.alice.String(), ev.ResourceID)
	assert.Contains(t, ev.Details, f.alice.String())
	assert.Contains(t, ev.Details, model.RoleKeyVaultSecretsOfficer)
}

func TestRevokeAssignment_AuditFailureRemovesNothing(t *testing.T) {
	audit := &fakeRoleAudit{criticalErr: errors.New("down")}
	f := newRoleAuditFixture(audit)

	err := f.svc.RevokeAssignment(context.Background(), f.existing.ID, f.vault, f.actor, false)

	requireRoleAuditUnavailable(t, err)
	assert.Contains(t, f.rr.rows, f.existing.ID, "the assignment must stay")
	assert.Empty(t, f.pr.deleted, "its policies must stay")
	require.Len(t, audit.critical, 1)
	assert.Equal(t, "revoke_role_assignment", audit.critical[0].Action)
	assert.Equal(t, f.actor.String(), audit.critical[0].UserID)
	assert.Equal(t, f.existing.ID.String(), audit.critical[0].ResourceID)
}

func TestAssignRole_AttemptPrecedesCreate(t *testing.T) {
	audit := &fakeRoleAudit{}
	f := newRoleAuditFixture(audit)
	audit.onCritical = func() {
		assert.Len(t, f.rr.rows, 1, "nothing may be created before the attempt row")
		assert.Empty(t, f.pr.created)
	}

	ra, err := f.grant(model.RoleKeyVaultSecretsOfficer, false)

	require.NoError(t, err)
	assert.Equal(t, []string{"critical:attempt", "event:success"}, audit.calls)
	assert.Equal(t, ra.ID.String(), audit.critical[0].ResourceID, "the row names the created assignment")
	assert.Equal(t, ra.ID.String(), audit.events[0].ResourceID)
}

func TestRevokeAssignment_AttemptPrecedesDelete(t *testing.T) {
	audit := &fakeRoleAudit{}
	f := newRoleAuditFixture(audit)
	audit.onCritical = func() {
		assert.Contains(t, f.rr.rows, f.existing.ID, "nothing may be removed before the attempt row")
		assert.Empty(t, f.pr.deleted)
	}

	require.NoError(t, f.svc.RevokeAssignment(context.Background(), f.existing.ID, f.vault, f.actor, false))

	assert.Equal(t, []string{"critical:attempt", "event:success"}, audit.calls)
	assert.NotContains(t, f.rr.rows, f.existing.ID)
}

// TestRoleAssignment_RefusalsAreNotCritical pins that every authorization or
// validation refusal, including the global-admin-only roles, runs before the
// attempt row, so an unauthorized caller cannot generate critical rows.
func TestRoleAssignment_RefusalsAreNotCritical(t *testing.T) {
	audit := &fakeRoleAudit{criticalErr: errors.New("down")}
	f := newRoleAuditFixture(audit)
	ctx := context.Background()

	for _, role := range []string{model.RoleKeyVaultDataAccessAdministrator, model.RoleKeyVaultPurgeOperator, model.RoleKeyVaultCertificateUser} {
		_, err := f.grant(role, false)
		assert.ErrorIs(t, err, ErrRoleNotGrantable, role)
	}
	for _, role := range model.AzureRoleNames() {
		if !nonAdminGrantableRoles[role] {
			_, err := f.grant(role, false)
			assert.ErrorIs(t, err, ErrRoleNotGrantable, "only a global admin grants %s", role)
		}
	}
	_, err := f.grant("Not A Role", true)
	assert.ErrorIs(t, err, ErrInvalidRole)
	_, err = f.svc.AssignRole(ctx, AssignRoleInput{Principal: "nobody", Role: model.RoleKeyVaultReader, VaultID: f.vault, CreatedBy: f.actor})
	assert.ErrorIs(t, err, ErrPrincipalNotFound)

	err = f.svc.RevokeAssignment(ctx, uuid.New(), f.vault, f.actor, true)
	assert.ErrorIs(t, err, ErrAssignmentNotFound)
	err = f.svc.RevokeAssignment(ctx, f.existing.ID, uuid.New(), f.actor, true)
	assert.ErrorIs(t, err, ErrAssignmentNotFound, "another vault's assignment")
	f.existing.Role = model.RoleKeyVaultPurgeOperator
	err = f.svc.RevokeAssignment(ctx, f.existing.ID, f.vault, f.actor, false)
	assert.ErrorIs(t, err, ErrRoleNotGrantable)

	assert.Empty(t, audit.critical)
	assert.Len(t, f.rr.rows, 1)
}

// TestAssignRole_ExistingAssignmentIsNotCritical pins that an idempotent
// grant of an assignment that already exists changes nothing and writes no
// critical row.
func TestAssignRole_ExistingAssignmentIsNotCritical(t *testing.T) {
	audit := &fakeRoleAudit{criticalErr: errors.New("down")}
	f := newRoleAuditFixture(audit)
	f.rr.byTuple = f.existing

	ra, err := f.grant(model.RoleKeyVaultSecretsUser, false)

	require.NoError(t, err)
	assert.Equal(t, f.existing, ra)
	assert.Empty(t, audit.critical)
}
