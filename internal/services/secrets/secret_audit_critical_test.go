package secrets

// Audit-first tests: a purge must not remove a secret unless the critical
// audit row was written first.

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"rocketvault/internal/repositories"
	auditServices "rocketvault/internal/services/audit"
	"rocketvault/model"
)

// fakeSecretAudit records calls in order and can fail critical writes.
// internal/testutils cannot be used here because it imports this package.
type fakeSecretAudit struct {
	mu          sync.Mutex
	criticalErr error
	calls       []string
	critical    []auditServices.AuditEvent
}

func (f *fakeSecretAudit) RecordEvent(_ context.Context, ev auditServices.AuditEvent) error {
	f.note("event:" + ev.Outcome)
	return nil
}

func (f *fakeSecretAudit) RecordCritical(_ context.Context, ev auditServices.AuditEvent) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, "critical:"+ev.Outcome)
	f.critical = append(f.critical, ev)
	return f.criticalErr
}

func (f *fakeSecretAudit) PersistAudit(_, _, _ string) error { return nil }

func (f *fakeSecretAudit) note(call string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, call)
}

// purgeableSecretFixture returns a service whose repository holds secretID
// as soft-deleted in scope, with audit wired.
func purgeableSecretFixture(t *testing.T, scope model.Scope, secretID uuid.UUID, audit auditServices.AuditServiceInterface) (*MockSecretRepository, *secretService) {
	t.Helper()
	repo, svc := newScopeServiceFixture(t)
	svc.auditService = audit
	deletedAt := time.Now().UTC()
	repo.On("List", mock.Anything, scope, repositories.SecretFilter{OnlyDeleted: true}).
		Return([]model.Secret{{ID: secretID, DeletedAt: &deletedAt}}, nil).Once()
	return repo, svc
}

func TestPurgeSecret_AuditFailureLeavesSecretSoftDeleted(t *testing.T) {
	scope := model.NewOwnerScope(uuid.Nil, uuid.New())
	secretID := uuid.New()
	audit := &fakeSecretAudit{criticalErr: errors.New("pq: disk full on audit_logs")}
	repo, svc := purgeableSecretFixture(t, scope, secretID, audit)

	err := svc.PurgeSecret(context.Background(), secretID, scope)

	require.Error(t, err)
	assert.True(t, errors.Is(err, auditServices.ErrAuditUnavailable), "%v", err)
	assert.Equal(t, "audit unavailable", err.Error())
	repo.AssertNotCalled(t, "PurgeSecret", mock.Anything, mock.Anything)
}

func TestPurgeSecret_WritesAttemptBeforePurge(t *testing.T) {
	scope := model.NewOwnerScope(uuid.Nil, uuid.New())
	secretID := uuid.New()
	audit := &fakeSecretAudit{}
	repo, svc := purgeableSecretFixture(t, scope, secretID, audit)
	repo.On("PurgeSecret", mock.Anything, secretID).Run(func(mock.Arguments) { audit.note("purge") }).Return(nil).Once()

	require.NoError(t, svc.PurgeSecret(context.Background(), secretID, scope))

	assert.Equal(t, []string{"critical:attempt", "purge", "event:success"}, audit.calls)
	assert.Equal(t, "purge_secret", audit.critical[0].Action)
	assert.Equal(t, "secret", audit.critical[0].ResourceType)
	assert.Equal(t, secretID.String(), audit.critical[0].ResourceID)
}

// TestNewSecretService_WiresAuditService pins the constructor path the
// container uses.
func TestNewSecretService_WiresAuditService(t *testing.T) {
	audit := &fakeSecretAudit{}
	svc := NewSecretService(SecretServiceConfig{AuditService: audit}).(*secretService)
	assert.Same(t, audit, svc.auditService)
}
