package auth

// Audit-first tests: a login must not issue a session unless its critical
// audit row was written, and a denied login still records a plain event.

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

	"rocketvault/internal/logging"
	auditServices "rocketvault/internal/services/audit"
	"rocketvault/model"
)

// auditCause is the underlying failure text that must never reach a caller.
const auditCause = "pq: disk full on audit_logs"

// fakeAuditService records calls in order. internal/testutils cannot be used
// here because it imports this package.
type fakeAuditService struct {
	mu          sync.Mutex
	criticalErr error
	calls       []string
	critical    []auditServices.AuditEvent
	events      []auditServices.AuditEvent
}

func (f *fakeAuditService) RecordEvent(_ context.Context, ev auditServices.AuditEvent) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, "event:"+ev.Outcome)
	f.events = append(f.events, ev)
	return nil
}

func (f *fakeAuditService) RecordCritical(_ context.Context, ev auditServices.AuditEvent) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, "critical:"+ev.Outcome)
	if f.criticalErr != nil {
		return f.criticalErr
	}
	f.critical = append(f.critical, ev)
	return nil
}

func (f *fakeAuditService) PersistAudit(_, _, _ string) error { return nil }

func (f *fakeAuditService) snapshot() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.calls...)
}

// auditLoginFixture wires an authentication service whose credentials for
// "gooduser" / "goodpass" / "123456" are valid.
type auditLoginFixture struct {
	svc      AuthenticationService
	sessions *MockSessionRepository
	jwt      *MockJWTService
	audit    *fakeAuditService
	user     model.User
}

func newAuditLoginFixture(t *testing.T, audit *fakeAuditService) *auditLoginFixture {
	t.Helper()
	user := model.User{
		ID: uuid.New(), Username: "gooduser", PasswordHash: "hash",
		TOTPSecret: "secret123", Roles: []string{model.RoleUser},
	}
	users := &MockUserRepository{}
	users.On("ReadByUsername", mock.Anything, "gooduser").Return(user, nil)
	pwd := &MockPasswordService{}
	pwd.On("ValidatePassword", "goodpass", "hash").Return(nil)
	pwd.On("ValidatePassword", "wrongpass", "hash").Return(errors.New("mismatch"))
	totp := &MockTOTPService{}
	totp.On("ValidateCodeWithStep", "123456", "secret123", mock.AnythingOfType("time.Time")).Return(int64(7), true, nil)
	steps := &MockTOTPStepRepository{}
	steps.On("ClaimTOTPStep", mock.Anything, user.ID, int64(7)).Return(true, nil)
	sessions := &MockSessionRepository{}
	jwt := &MockJWTService{}

	svc := NewAuthenticationService(AuthenticationConfig{
		UserRepository:     users,
		SessionRepository:  sessions,
		PasswordService:    pwd,
		TOTPService:        totp,
		JWTService:         jwt,
		TOTPStepRepository: steps,
		Logger:             logging.InitLogger(),
		AuditService:       audit,
	})
	return &auditLoginFixture{svc: svc, sessions: sessions, jwt: jwt, audit: audit, user: user}
}

func TestAuthenticateUser_AuditUnavailable_IssuesNoSession(t *testing.T) {
	t.Parallel()
	audit := &fakeAuditService{criticalErr: errors.New(auditCause)}
	f := newAuditLoginFixture(t, audit)

	result, err := f.svc.AuthenticateUser(context.Background(), "gooduser", "goodpass", "123456")

	require.Error(t, err)
	assert.Nil(t, result, "no token may be returned when the audit write fails")
	assert.ErrorIs(t, err, auditServices.ErrAuditUnavailable)
	assert.Equal(t, "audit unavailable", err.Error())
	assert.NotContains(t, err.Error(), auditCause)
	f.sessions.AssertNotCalled(t, "CreateSession", mock.Anything, mock.Anything)
	f.jwt.AssertNotCalled(t, "GenerateToken", mock.Anything, mock.Anything, mock.Anything, mock.Anything)
}

func TestAuthenticateUser_AuditAttemptPrecedesSession(t *testing.T) {
	t.Parallel()
	audit := &fakeAuditService{}
	f := newAuditLoginFixture(t, audit)
	var seenAtCreate []string
	f.sessions.On("CreateSession", mock.Anything, mock.AnythingOfType("*model.Session")).
		Run(func(mock.Arguments) { seenAtCreate = audit.snapshot() }).Return(nil)
	f.jwt.On("GenerateToken", f.user.ID, "gooduser", f.user.Roles, mock.AnythingOfType("uuid.UUID")).Return("jwt", nil)

	result, err := f.svc.AuthenticateUser(context.Background(), "gooduser", "goodpass", "123456")

	require.NoError(t, err)
	assert.Equal(t, "jwt", result.Token)
	assert.Equal(t, []string{"critical:attempt"}, seenAtCreate, "the attempt row must exist before the session")
	assert.Equal(t, []string{"critical:attempt", "event:success"}, audit.snapshot())
	require.Len(t, audit.critical, 1)
	assert.Equal(t, "authenticate_user", audit.critical[0].Action)
	assert.Equal(t, f.user.ID.String(), audit.critical[0].ResourceID)
}

func TestAuthenticateUser_AuditBadPassword_StaysPlainEvent(t *testing.T) {
	t.Parallel()
	// The critical write would fail, but a denial never reaches it.
	audit := &fakeAuditService{criticalErr: errors.New(auditCause)}
	f := newAuditLoginFixture(t, audit)

	result, err := f.svc.AuthenticateUser(context.Background(), "gooduser", "wrongpass", "123456")

	require.Error(t, err)
	assert.Nil(t, result)
	assert.Equal(t, "invalid credentials", err.Error())
	assert.NotErrorIs(t, err, auditServices.ErrAuditUnavailable)
	assert.Equal(t, []string{"event:failure"}, audit.snapshot())
	assert.Equal(t, "invalid password", audit.events[0].Details)
}

func TestIssueSessionForUser_AuditUnavailable_IssuesNoSession(t *testing.T) {
	t.Parallel()
	audit := &fakeAuditService{criticalErr: errors.New(auditCause)}
	f := newAuditLoginFixture(t, audit)

	result, err := f.svc.IssueSessionForUser(context.Background(), &f.user)

	require.Error(t, err)
	assert.Nil(t, result)
	assert.ErrorIs(t, err, auditServices.ErrAuditUnavailable)
	assert.NotContains(t, err.Error(), auditCause)
	f.sessions.AssertNotCalled(t, "CreateSession", mock.Anything, mock.Anything)
}

// newAuditRefreshFixture wires a refresh for a live session of "carol".
func newAuditRefreshFixture(audit *fakeAuditService) (AuthenticationService, *MockSessionRepository, *MockJWTService, *model.Session) {
	userID := uuid.New()
	session := &model.Session{ID: uuid.New(), UserID: userID, ExpiresAt: time.Now().Add(time.Hour)}
	users := &MockUserRepository{}
	users.On("Read", mock.Anything, userID).Return(&model.User{ID: userID, Username: "carol", Roles: []string{model.RoleUser}}, nil)
	sessions := &MockSessionRepository{}
	sessions.On("GetSessionByRefreshToken", mock.Anything, mock.AnythingOfType("string")).Return(session, nil)
	jwt := &MockJWTService{}
	svc := NewAuthenticationService(AuthenticationConfig{
		UserRepository:    users,
		SessionRepository: sessions,
		PasswordService:   &MockPasswordService{},
		TOTPService:       &MockTOTPService{},
		JWTService:        jwt,
		Logger:            logging.InitLogger(),
		AuditService:      audit,
	})
	return svc, sessions, jwt, session
}

func TestRefreshAccessToken_AuditUnavailable_IssuesNoToken(t *testing.T) {
	t.Parallel()
	audit := &fakeAuditService{criticalErr: errors.New(auditCause)}
	svc, sessions, jwt, _ := newAuditRefreshFixture(audit)

	result, err := svc.RefreshAccessToken(context.Background(), "refresh-token-value")

	require.Error(t, err)
	assert.Nil(t, result, "no token may be returned when the audit write fails")
	assert.ErrorIs(t, err, auditServices.ErrAuditUnavailable)
	assert.NotContains(t, err.Error(), auditCause)
	jwt.AssertNotCalled(t, "GenerateToken", mock.Anything, mock.Anything, mock.Anything, mock.Anything)
	sessions.AssertNotCalled(t, "UpdateSessionLastUsed", mock.Anything, mock.Anything, mock.Anything)
}

func TestRefreshAccessToken_AuditAttemptPrecedesToken(t *testing.T) {
	t.Parallel()
	audit := &fakeAuditService{}
	svc, sessions, jwt, session := newAuditRefreshFixture(audit)
	var seenAtMint []string
	jwt.On("GenerateToken", session.UserID, "carol", []string{model.RoleUser}, session.ID).
		Run(func(mock.Arguments) { seenAtMint = audit.snapshot() }).Return("new-access-token", nil)
	sessions.On("UpdateSessionLastUsed", mock.Anything, session.ID, mock.AnythingOfType("time.Time")).Return(nil)

	result, err := svc.RefreshAccessToken(context.Background(), "refresh-token-value")

	require.NoError(t, err)
	assert.Equal(t, "new-access-token", result.Token)
	assert.Equal(t, []string{"critical:attempt"}, seenAtMint)
	assert.Equal(t, []string{"critical:attempt", "event:success"}, audit.snapshot())
	require.Len(t, audit.critical, 1)
	assert.Equal(t, "refresh_access_token", audit.critical[0].Action)
	assert.Equal(t, "session", audit.critical[0].ResourceType)
	assert.Equal(t, session.ID.String(), audit.critical[0].ResourceID)
	assert.Equal(t, session.UserID.String(), audit.critical[0].UserID)
}
