package users

// Audit-first tests: a user delete must not run unless the critical audit
// row was written first.

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	auditServices "rocketvault/internal/services/audit"
)

// fakeUserAudit records calls in order and can fail critical writes.
// internal/testutils cannot be used here because it imports this package.
type fakeUserAudit struct {
	mu          sync.Mutex
	criticalErr error
	calls       []string
	critical    []auditServices.AuditEvent
}

func (f *fakeUserAudit) RecordEvent(_ context.Context, ev auditServices.AuditEvent) error {
	f.note("event:" + ev.Outcome)
	return nil
}

func (f *fakeUserAudit) RecordCritical(_ context.Context, ev auditServices.AuditEvent) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, "critical:"+ev.Outcome)
	f.critical = append(f.critical, ev)
	return f.criticalErr
}

func (f *fakeUserAudit) PersistAudit(_, _, _ string) error { return nil }

func (f *fakeUserAudit) note(call string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, call)
}

func newAuditedUserService(repo *mockUserRepository, revoker *mockSessionRevoker, audit auditServices.AuditServiceInterface) UserService {
	return NewUserService(UserServiceConfig{
		UserRepository: repo, PasswordService: &mockPasswordService{}, TOTPService: &mockTOTPService{},
		SessionRevoker: revoker, Logger: testLogger(), AuditService: audit,
	})
}

func TestDeleteUser_AuditFailureLeavesUserInPlace(t *testing.T) {
	repo := &mockUserRepository{}
	revoker := &mockSessionRevoker{}
	audit := &fakeUserAudit{criticalErr: errors.New("pq: disk full on audit_logs")}
	svc := newAuditedUserService(repo, revoker, audit)

	err := svc.DeleteUser(context.Background(), uuid.New(), uuid.New())

	require.Error(t, err)
	assert.True(t, errors.Is(err, auditServices.ErrAuditUnavailable), "%v", err)
	assert.Equal(t, "audit unavailable", err.Error())
	repo.AssertNotCalled(t, "Delete", mock.Anything, mock.Anything)
	revoker.AssertNotCalled(t, "RevokeAllUserSessions", mock.Anything, mock.Anything, mock.Anything)
}

func TestDeleteUser_WritesAttemptBeforeDelete(t *testing.T) {
	repo := &mockUserRepository{}
	audit := &fakeUserAudit{}
	revoker := &mockSessionRevoker{}
	userID := uuid.New()
	revoker.On("RevokeAllUserSessions", mock.Anything, userID, mock.Anything).
		Run(func(mock.Arguments) { audit.note("revoke") }).Return(nil)
	repo.On("Delete", mock.Anything, userID).Run(func(mock.Arguments) { audit.note("delete") }).Return(nil)
	svc := newAuditedUserService(repo, revoker, audit)

	actor := uuid.New()
	require.NoError(t, svc.DeleteUser(context.Background(), userID, actor))

	assert.Equal(t, []string{"critical:attempt", "revoke", "delete", "event:success"}, audit.calls)
	assert.Equal(t, "delete_user", audit.critical[0].Action)
	assert.Equal(t, "user", audit.critical[0].ResourceType)
	assert.Equal(t, actor.String(), audit.critical[0].UserID, "the row names who deleted")
	assert.Equal(t, userID.String(), audit.critical[0].ResourceID, "the row names who was deleted")
}

// TestDeleteUser_NilActorIsRecordedAsSystem pins the actor for a caller
// with no principal, matching the vault service.
func TestDeleteUser_NilActorIsRecordedAsSystem(t *testing.T) {
	repo := &mockUserRepository{}
	audit := &fakeUserAudit{}
	userID := uuid.New()
	repo.On("Delete", mock.Anything, userID).Return(nil)
	svc := newAuditedUserService(repo, acceptingRevoker(), audit)

	require.NoError(t, svc.DeleteUser(context.Background(), userID, uuid.Nil))

	assert.Equal(t, "system", audit.critical[0].UserID)
}
