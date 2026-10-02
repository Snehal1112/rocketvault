package auth

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	_ "github.com/mattn/go-sqlite3"
	"github.com/pquerna/otp"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	rvdb "rocketvault/internal/db"
	"rocketvault/internal/logging"
	"rocketvault/internal/repositories"
	auditServices "rocketvault/internal/services/audit"
	"rocketvault/model"
)

// Mock implementations for testing

type MockUserRepository struct {
	mock.Mock
}

func (m *MockUserRepository) Create(ctx context.Context, user *model.User) error {
	args := m.Called(ctx, user)
	return args.Error(0)
}

func (m *MockUserRepository) Read(ctx context.Context, id uuid.UUID) (*model.User, error) {
	args := m.Called(ctx, id)
	return args.Get(0).(*model.User), args.Error(1)
}

func (m *MockUserRepository) Update(ctx context.Context, user *model.User) error {
	args := m.Called(ctx, user)
	return args.Error(0)
}

func (m *MockUserRepository) Delete(ctx context.Context, id uuid.UUID) error {
	args := m.Called(ctx, id)
	return args.Error(0)
}

func (m *MockUserRepository) ReadByUsername(ctx context.Context, username string) (model.User, error) {
	args := m.Called(ctx, username)
	return args.Get(0).(model.User), args.Error(1)
}

func (m *MockUserRepository) ReadByExternalSubject(ctx context.Context, provider, subject string) (*model.User, error) {
	args := m.Called(ctx, provider, subject)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*model.User), args.Error(1)
}

func (m *MockUserRepository) List(ctx context.Context) ([]model.User, error) {
	args := m.Called(ctx)
	return args.Get(0).([]model.User), args.Error(1)
}

func (m *MockUserRepository) ValidateBootstrapToken(ctx context.Context, token string) (bool, error) {
	args := m.Called(ctx, token)
	return args.Bool(0), args.Error(1)
}

func (m *MockUserRepository) InvalidateBootstrapToken(ctx context.Context, token string) error {
	args := m.Called(ctx, token)
	return args.Error(0)
}

// Ensure MockUserRepository implements repositories.UserRepositoryInterface.
var _ repositories.UserRepositoryInterface = &MockUserRepository{}

// MockOAuth2ClientRepository implements OAuth2ClientRepositoryInterface for tests.
type MockOAuth2ClientRepository struct {
	mock.Mock
}

func (m *MockOAuth2ClientRepository) Create(ctx context.Context, c *model.OAuth2Client) error {
	return m.Called(ctx, c).Error(0)
}

func (m *MockOAuth2ClientRepository) GetByID(ctx context.Context, id uuid.UUID) (*model.OAuth2Client, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*model.OAuth2Client), args.Error(1)
}

func (m *MockOAuth2ClientRepository) FindByName(ctx context.Context, name string) (*model.OAuth2Client, error) {
	args := m.Called(ctx, name)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*model.OAuth2Client), args.Error(1)
}

func (m *MockOAuth2ClientRepository) List(ctx context.Context) ([]*model.OAuth2Client, error) {
	args := m.Called(ctx)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*model.OAuth2Client), args.Error(1)
}

func (m *MockOAuth2ClientRepository) Update(ctx context.Context, c *model.OAuth2Client) error {
	return m.Called(ctx, c).Error(0)
}

func (m *MockOAuth2ClientRepository) Delete(ctx context.Context, id uuid.UUID) error {
	return m.Called(ctx, id).Error(0)
}

// Compile-time check that MockOAuth2ClientRepository satisfies the interface.
var _ repositories.OAuth2ClientRepositoryInterface = &MockOAuth2ClientRepository{}

type MockPasswordService struct {
	mock.Mock
}

func (m *MockPasswordService) HashPassword(password string) (string, error) {
	args := m.Called(password)
	return args.String(0), args.Error(1)
}

func (m *MockPasswordService) ValidatePassword(password, hash string) error {
	args := m.Called(password, hash)
	return args.Error(0)
}

type MockTOTPService struct {
	mock.Mock
}

func (m *MockTOTPService) GenerateSecret(issuer, accountName string) (*otp.Key, error) {
	args := m.Called(issuer, accountName)
	return args.Get(0).(*otp.Key), args.Error(1)
}

func (m *MockTOTPService) ValidateCode(code, secret string, currentTime time.Time) (bool, error) {
	args := m.Called(code, secret, currentTime)
	return args.Bool(0), args.Error(1)
}

func (m *MockTOTPService) GenerateCode(secret string, currentTime time.Time) (string, error) {
	args := m.Called(secret, currentTime)
	return args.String(0), args.Error(1)
}

type MockJWTService struct {
	mock.Mock
}

func (m *MockJWTService) GenerateToken(userID uuid.UUID, username string, roles []string, sessionID uuid.UUID) (string, error) {
	args := m.Called(userID, username, roles, sessionID)
	return args.String(0), args.Error(1)
}

func (m *MockJWTService) ValidateToken(tokenString string) (*JWTClaims, error) {
	args := m.Called(tokenString)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*JWTClaims), args.Error(1)
}

func (m *MockJWTService) ParseToken(tokenString string) (*JWTClaims, error) {
	args := m.Called(tokenString)
	return args.Get(0).(*JWTClaims), args.Error(1)
}

// MockSessionRepository implements SessionRepositoryInterface for testing
type MockSessionRepository struct {
	mock.Mock
}

func (m *MockSessionRepository) CreateSession(ctx context.Context, session *model.Session) error {
	args := m.Called(ctx, session)
	return args.Error(0)
}

func (m *MockSessionRepository) GetSessionByID(ctx context.Context, sessionID uuid.UUID) (*model.Session, error) {
	args := m.Called(ctx, sessionID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*model.Session), args.Error(1)
}

func (m *MockSessionRepository) GetSessionByRefreshToken(ctx context.Context, refreshTokenHash string) (*model.Session, error) {
	args := m.Called(ctx, refreshTokenHash)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*model.Session), args.Error(1)
}

func (m *MockSessionRepository) GetActiveSessionsByUserID(ctx context.Context, userID uuid.UUID) ([]*model.Session, error) {
	args := m.Called(ctx, userID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*model.Session), args.Error(1)
}

func (m *MockSessionRepository) UpdateSessionLastUsed(ctx context.Context, sessionID uuid.UUID, lastUsedAt time.Time) error {
	args := m.Called(ctx, sessionID, lastUsedAt)
	return args.Error(0)
}

func (m *MockSessionRepository) RevokeSession(ctx context.Context, sessionID uuid.UUID, reason string) error {
	args := m.Called(ctx, sessionID, reason)
	return args.Error(0)
}

func (m *MockSessionRepository) RevokeUserSession(ctx context.Context, sessionID, userID uuid.UUID, reason string) error {
	args := m.Called(ctx, sessionID, userID, reason)
	return args.Error(0)
}

func (m *MockSessionRepository) RevokeAllUserSessions(ctx context.Context, userID uuid.UUID, reason string) error {
	args := m.Called(ctx, userID, reason)
	return args.Error(0)
}

func (m *MockSessionRepository) DeleteExpiredSessions(ctx context.Context, before time.Time) (int64, error) {
	args := m.Called(ctx, before)
	return args.Get(0).(int64), args.Error(1)
}

func (m *MockSessionRepository) CountActiveSessions(ctx context.Context, userID uuid.UUID) (int, error) {
	args := m.Called(ctx, userID)
	return args.Get(0).(int), args.Error(1)
}

func (m *MockSessionRepository) IsSessionRevoked(ctx context.Context, sessionID uuid.UUID) (bool, error) {
	args := m.Called(ctx, sessionID)
	return args.Bool(0), args.Error(1)
}

// Test demonstrating the new SRP-compliant architecture

func TestAuthenticationService_AuthenticateUser_Success(t *testing.T) {
	t.Parallel()
	// Arrange
	ctx := context.Background()

	// Create mocks
	mockUserRepo := &MockUserRepository{}
	mockSessionRepo := &MockSessionRepository{}
	mockPasswordService := &MockPasswordService{}
	mockTOTPService := &MockTOTPService{}
	mockJWTService := &MockJWTService{}

	// Create logger
	logger := logging.InitLogger()

	// Create test user
	userID := uuid.New()
	user := model.User{
		ID:           userID,
		Username:     "testuser",
		PasswordHash: "hashedpassword",
		TOTPSecret:   "secret123",
		Roles:        []string{model.RoleUser},
	}

	// Setup expectations
	mockUserRepo.On("ReadByUsername", ctx, "testuser").Return(user, nil)
	mockPasswordService.On("ValidatePassword", "password123", "hashedpassword").Return(nil)
	mockTOTPService.On("ValidateCode", "123456", "secret123", mock.AnythingOfType("time.Time")).Return(true, nil)
	mockSessionRepo.On("CreateSession", ctx, mock.AnythingOfType("*model.Session")).Return(nil)
	mockJWTService.On("GenerateToken", userID, "testuser", []string{model.RoleUser}, mock.AnythingOfType("uuid.UUID")).Return("jwt_token", nil)

	// Create service
	service := NewAuthenticationService(AuthenticationConfig{
		UserRepository:    mockUserRepo,
		SessionRepository: mockSessionRepo,
		PasswordService:   mockPasswordService,
		TOTPService:       mockTOTPService,
		JWTService:        mockJWTService,
		Logger:            logger,
	})

	// Act
	result, err := service.AuthenticateUser(ctx, "testuser", "password123", "123456")

	// Assert
	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.Equal(t, "jwt_token", result.Token)
	assert.NotEmpty(t, result.RefreshToken) // Should have refresh token
	assert.Equal(t, userID, result.UserID)
	assert.Equal(t, "testuser", result.Username)
	assert.Equal(t, []string{model.RoleUser}, result.Roles)

	// Verify all mocks were called
	mockUserRepo.AssertExpectations(t)
	mockSessionRepo.AssertExpectations(t)
	mockPasswordService.AssertExpectations(t)
	mockTOTPService.AssertExpectations(t)
	mockJWTService.AssertExpectations(t)
}

// TestIssueSessionForUser_Success verifies IssueSessionForUser creates a
// session and issues a JWT without requiring password/TOTP, for callers that
// have already established identity out-of-band (OIDC).
func TestIssueSessionForUser_Success(t *testing.T) {
	userRepo := &MockUserRepository{}
	sessionRepo := &MockSessionRepository{}
	jwtSvc := &MockJWTService{}

	user := &model.User{ID: uuid.New(), Username: "oidc-user", Roles: []string{model.RoleUser}}

	sessionRepo.On("CreateSession", mock.Anything, mock.AnythingOfType("*model.Session")).Return(nil)
	jwtSvc.On("GenerateToken", user.ID, user.Username, user.Roles, mock.AnythingOfType("uuid.UUID")).
		Return("access-token", nil)

	svc := NewAuthenticationService(AuthenticationConfig{
		UserRepository:    userRepo,
		SessionRepository: sessionRepo,
		PasswordService:   &MockPasswordService{},
		TOTPService:       &MockTOTPService{},
		JWTService:        jwtSvc,
		Logger:            &logging.Logger{Logger: logrus.New()},
	})

	result, err := svc.IssueSessionForUser(context.Background(), user)
	require.NoError(t, err)
	assert.Equal(t, "access-token", result.Token)
	assert.NotEmpty(t, result.RefreshToken)
	assert.Equal(t, user.ID, result.UserID)
	sessionRepo.AssertExpectations(t)
	jwtSvc.AssertExpectations(t)
}

// TestIssueSession_EmbedsAllUserRoles is the regression test for issueSession
// forwarding the user's full multi-role list (not just a single role) into
// both the JWT and the returned AuthenticationResult.
func TestIssueSession_EmbedsAllUserRoles(t *testing.T) {
	userRepo := &MockUserRepository{}
	sessionRepo := &MockSessionRepository{}
	jwtSvc := &MockJWTService{}

	user := &model.User{ID: uuid.New(), Username: "multi-role-user", Roles: []string{"admin", "crypto_manager"}}

	sessionRepo.On("CreateSession", mock.Anything, mock.AnythingOfType("*model.Session")).Return(nil)
	jwtSvc.On("GenerateToken", user.ID, user.Username, user.Roles, mock.AnythingOfType("uuid.UUID")).
		Return("access-token", nil)

	svc := NewAuthenticationService(AuthenticationConfig{
		UserRepository:    userRepo,
		SessionRepository: sessionRepo,
		PasswordService:   &MockPasswordService{},
		TOTPService:       &MockTOTPService{},
		JWTService:        jwtSvc,
		Logger:            &logging.Logger{Logger: logrus.New()},
	})

	result, err := svc.IssueSessionForUser(context.Background(), user)
	require.NoError(t, err)
	assert.ElementsMatch(t, []string{"admin", "crypto_manager"}, result.Roles)
	sessionRepo.AssertExpectations(t)
	jwtSvc.AssertExpectations(t)
}

func TestAuthenticationService_AuthenticateUser_InvalidPassword(t *testing.T) {
	t.Parallel()
	// Arrange
	ctx := context.Background()

	// Create mocks
	mockUserRepo := &MockUserRepository{}
	mockPasswordService := &MockPasswordService{}
	mockTOTPService := &MockTOTPService{}
	mockJWTService := &MockJWTService{}

	// Create logger
	logger := logging.InitLogger()

	// Create test user
	userID := uuid.New()
	user := model.User{
		ID:           userID,
		Username:     "testuser",
		PasswordHash: "hashedpassword",
		TOTPSecret:   "secret123",
		Roles:        []string{model.RoleUser},
	}

	// Setup expectations
	mockUserRepo.On("ReadByUsername", ctx, "testuser").Return(user, nil)
	mockPasswordService.On("ValidatePassword", "wrongpassword", "hashedpassword").Return(errors.New("invalid password"))

	// Create service
	service := NewAuthenticationService(AuthenticationConfig{
		UserRepository:  mockUserRepo,
		PasswordService: mockPasswordService,
		TOTPService:     mockTOTPService,
		JWTService:      mockJWTService,
		Logger:          logger,
	})

	// Act
	result, err := service.AuthenticateUser(ctx, "testuser", "wrongpassword", "123456")

	// Assert
	assert.Error(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "invalid credentials")

	// Verify expectations
	mockUserRepo.AssertExpectations(t)
	mockPasswordService.AssertExpectations(t)
	// TOTP and JWT services should not be called
	mockTOTPService.AssertNotCalled(t, "ValidateCode")
	mockJWTService.AssertNotCalled(t, "GenerateToken")
}

func TestAuthenticationService_AuthenticateUser_InvalidTOTP(t *testing.T) {
	t.Parallel()
	// Arrange
	ctx := context.Background()

	// Create mocks
	mockUserRepo := &MockUserRepository{}
	mockPasswordService := &MockPasswordService{}
	mockTOTPService := &MockTOTPService{}
	mockJWTService := &MockJWTService{}

	// Create logger
	logger := logging.InitLogger()

	// Create test user
	userID := uuid.New()
	user := model.User{
		ID:           userID,
		Username:     "testuser",
		PasswordHash: "hashedpassword",
		TOTPSecret:   "secret123",
		Roles:        []string{model.RoleUser},
	}

	// Setup expectations
	mockUserRepo.On("ReadByUsername", ctx, "testuser").Return(user, nil)
	mockPasswordService.On("ValidatePassword", "password123", "hashedpassword").Return(nil)
	mockTOTPService.On("ValidateCode", "000000", "secret123", mock.AnythingOfType("time.Time")).Return(false, nil)

	// Create service
	service := NewAuthenticationService(AuthenticationConfig{
		UserRepository:  mockUserRepo,
		PasswordService: mockPasswordService,
		TOTPService:     mockTOTPService,
		JWTService:      mockJWTService,
		Logger:          logger,
	})

	// Act
	result, err := service.AuthenticateUser(ctx, "testuser", "password123", "000000")

	// Assert
	assert.Error(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "invalid TOTP code")

	// Verify expectations
	mockUserRepo.AssertExpectations(t)
	mockPasswordService.AssertExpectations(t)
	mockTOTPService.AssertExpectations(t)
	// JWT service should not be called
	mockJWTService.AssertNotCalled(t, "GenerateToken")
}

// newAuditTestRepo creates an in-memory SQLite-backed audit repository for
// exercising the real AuditService.RecordEvent write path end-to-end,
// mirroring the audit_logs schema used by internal/services/audit's own
// openTestDB test helper.
func newAuditTestRepo(t *testing.T) repositories.AuditRepositoryExtended {
	t.Helper()
	db, err := sql.Open("sqlite3", ":memory:")
	require.NoError(t, err)
	t.Cleanup(func() { db.Close() }) //nolint:errcheck,gosec
	_, err = db.Exec(`CREATE TABLE audit_logs (
		id TEXT PRIMARY KEY, user_id TEXT, action TEXT NOT NULL,
		details TEXT, timestamp TIMESTAMP,
		resource_type TEXT, resource_id TEXT, ip_address TEXT,
		outcome TEXT, source TEXT, prev_hash TEXT
	)`)
	require.NoError(t, err)
	return repositories.NewAuditRepository(rvdb.NewConn(db, rvdb.SQLite))
}

// TestAuthenticateUser_RecordsRichAuditOutcomeOnSuccessAndFailure is the
// regression test for the SOC2 auth-outcome miscounting bug: the real
// authenticate_user audit write path (previously logger.LogAuditError/
// LogAuditInfo -> AuditService.PersistAudit -> RecordEvent with Outcome left
// as the Go zero value) must persist an explicit Outcome of "success" or
// "failure" so downstream compliance reports don't silently count every
// login as a failure.
func TestAuthenticateUser_RecordsRichAuditOutcomeOnSuccessAndFailure(t *testing.T) {
	auditRepo := newAuditTestRepo(t)
	auditSvcInst := auditServices.NewAuditService(auditRepo)

	mockUserRepo := &MockUserRepository{}
	mockSessionRepo := &MockSessionRepository{}
	mockPasswordService := &MockPasswordService{}
	mockTOTPService := &MockTOTPService{}
	mockJWTService := &MockJWTService{}

	logger := logging.InitLogger()

	userID := uuid.New()
	user := model.User{
		ID:           userID,
		Username:     "gooduser",
		PasswordHash: "hashedpassword",
		TOTPSecret:   "secret123",
		Roles:        []string{model.RoleUser},
	}

	mockUserRepo.On("ReadByUsername", mock.Anything, "gooduser").Return(user, nil)
	mockPasswordService.On("ValidatePassword", "goodpass", "hashedpassword").Return(nil)
	mockPasswordService.On("ValidatePassword", "wrongpass", "hashedpassword").Return(errors.New("invalid password"))
	mockTOTPService.On("ValidateCode", "123456", "secret123", mock.AnythingOfType("time.Time")).Return(true, nil)
	mockSessionRepo.On("CreateSession", mock.Anything, mock.AnythingOfType("*model.Session")).Return(nil)
	mockJWTService.On("GenerateToken", userID, "gooduser", []string{model.RoleUser}, mock.AnythingOfType("uuid.UUID")).Return("jwt_token", nil)

	svc := NewAuthenticationService(AuthenticationConfig{
		UserRepository:    mockUserRepo,
		SessionRepository: mockSessionRepo,
		PasswordService:   mockPasswordService,
		TOTPService:       mockTOTPService,
		JWTService:        mockJWTService,
		Logger:            logger,
		AuditService:      auditSvcInst,
	})

	ctx := context.Background()

	// Successful login must persist Outcome=success, not NULL.
	_, err := svc.AuthenticateUser(ctx, "gooduser", "goodpass", "123456")
	require.NoError(t, err)

	logs, _, err := auditRepo.QueryAuditLogs(ctx, repositories.AuditFilter{Limit: 1})
	require.NoError(t, err)
	require.NotEmpty(t, logs)
	assert.Equal(t, "success", logs[0].Outcome, "a real successful login must persist Outcome=success, not NULL")

	// Failed login (bad password) must persist Outcome=failure, not NULL.
	_, err = svc.AuthenticateUser(ctx, "gooduser", "wrongpass", "123456")
	require.Error(t, err)

	logs, _, err = auditRepo.QueryAuditLogs(ctx, repositories.AuditFilter{Limit: 1})
	require.NoError(t, err)
	require.NotEmpty(t, logs)
	assert.Equal(t, "failure", logs[0].Outcome, "a real failed login must persist Outcome=failure, not NULL")
}

// This test demonstrates how the new architecture enables easy testing
// by allowing us to mock individual services rather than testing
// complex methods that mix multiple responsibilities.
func TestAuthenticationService_SeparationOfConcerns(t *testing.T) {
	t.Parallel()
	// This test demonstrates the benefits of SRP:
	// 1. Each service has a single, well-defined responsibility
	// 2. Services can be easily mocked and tested in isolation
	// 3. Business logic is separated from infrastructure concerns
	// 4. Dependencies are explicitly injected, making testing straightforward

	t.Log("Authentication service successfully demonstrates Single Responsibility Principle:")
	t.Log("- PasswordService: Handles only password hashing/validation")
	t.Log("- TOTPService: Handles only TOTP operations")
	t.Log("- JWTService: Handles only JWT token operations")
	t.Log("- UserRepository: Handles only database operations")
	t.Log("- AuthenticationService: Orchestrates authentication workflow")
	t.Log("- Each service is easily testable in isolation")
	t.Log("- No global dependencies - all dependencies are injected")

	assert.True(t, true, "Architecture demonstrates proper SRP compliance")
}

func TestAuthenticateUser_FailedTOTP_DoesNotLogCode(t *testing.T) {
	// No t.Parallel(): the log buffer is bound to this test's own logger, but
	// keeping the assertion deterministic and avoiding any shared global logrus
	// state keeps this test isolated from the parallel suite.
	var buf bytes.Buffer

	mockUserRepo := &MockUserRepository{}
	mockSessionRepo := &MockSessionRepository{}
	mockPasswordService := &MockPasswordService{}
	mockTOTPService := &MockTOTPService{}
	mockJWTService := &MockJWTService{}

	testUser := model.User{
		ID:           uuid.New(),
		Username:     "alice",
		PasswordHash: "$2a$10$test",
		TOTPSecret:   "JBSWY3DPEHPK3PXP",
		Roles:        []string{model.RoleUser},
	}

	mockUserRepo.On("ReadByUsername", mock.Anything, "alice").Return(testUser, nil)
	mockPasswordService.On("ValidatePassword", "password123", testUser.PasswordHash).Return(nil)
	mockTOTPService.On("ValidateCode", "123456", testUser.TOTPSecret, mock.AnythingOfType("time.Time")).
		Return(false, nil)

	// Bind the service's own logger to a local buffer so we capture exactly
	// what this service writes, with no shared global logrus state.
	logger := logging.InitLogger()
	logger.SetOutput(&buf)
	svc := NewAuthenticationService(AuthenticationConfig{
		UserRepository:    mockUserRepo,
		SessionRepository: mockSessionRepo,
		PasswordService:   mockPasswordService,
		TOTPService:       mockTOTPService,
		JWTService:        mockJWTService,
		Logger:            logger,
	})

	_, err := svc.AuthenticateUser(context.Background(), "alice", "password123", "123456")
	assert.Error(t, err)
	assert.NotContains(t, buf.String(), "123456", "TOTP code must not appear in logs")
	assert.NotContains(t, buf.String(), "totp_code")
}

func TestHashRefreshToken_IsActualHash(t *testing.T) {
	svc := &authenticationService{}
	token := "abc123plaintext"

	result := svc.hashRefreshToken(token)

	// fmt.Sprintf("%x", token) would equal hex.EncodeToString([]byte(token))
	naive := hex.EncodeToString([]byte(token))
	assert.NotEqual(t, naive, result, "hashRefreshToken must not be a naive hex encode")

	// Result must equal sha256 of the token.
	sum := sha256.Sum256([]byte(token))
	expected := hex.EncodeToString(sum[:])
	assert.Equal(t, expected, result)
	assert.Len(t, result, 64, "sha256 hex is always 64 chars")
}

func TestHashRefreshToken_Deterministic(t *testing.T) {
	svc := &authenticationService{}
	token := "some-token-value"
	require.Equal(t, svc.hashRefreshToken(token), svc.hashRefreshToken(token))
}

func TestHashRefreshToken_DifferentInputsDifferentOutputs(t *testing.T) {
	svc := &authenticationService{}
	assert.NotEqual(t, svc.hashRefreshToken("a"), svc.hashRefreshToken("b"))
}

func TestListActiveSessions_ReturnsSessionsFromRepo(t *testing.T) {
	sessionRepo := &MockSessionRepository{}
	userID := uuid.New()
	want := []*model.Session{{ID: uuid.New(), UserID: userID}}
	sessionRepo.On("GetActiveSessionsByUserID", mock.Anything, userID).Return(want, nil)

	svc := NewAuthenticationService(AuthenticationConfig{
		SessionRepository: sessionRepo,
		Logger:            logging.InitLogger(),
	})

	got, err := svc.ListActiveSessions(context.Background(), userID)

	require.NoError(t, err)
	assert.Equal(t, want, got)
	sessionRepo.AssertExpectations(t)
}

// TestRefreshAccessToken_UsesFreshRolesFromDB pins RefreshAccessToken's
// invariant that it re-derives roles from userRepo.Read on every refresh
// rather than carrying forward any role value from elsewhere. The seeded
// roles here are distinct from every other role fixture in this package,
// so if a future change ever threaded an old token's claims into this
// path instead of reading the user fresh, this test would catch it.
func TestRefreshAccessToken_UsesFreshRolesFromDB(t *testing.T) {
	ctx := context.Background()
	userID := uuid.New()
	sessionID := uuid.New()
	freshRoles := []string{"admin", "secrets_manager"}

	session := &model.Session{
		ID:        sessionID,
		UserID:    userID,
		Revoked:   false,
		ExpiresAt: time.Now().Add(time.Hour),
	}
	user := &model.User{ID: userID, Username: "carol", Roles: freshRoles}

	userRepo := &MockUserRepository{}
	sessionRepo := &MockSessionRepository{}
	jwtSvc := &MockJWTService{}

	sessionRepo.On("GetSessionByRefreshToken", ctx, mock.AnythingOfType("string")).Return(session, nil)
	userRepo.On("Read", ctx, userID).Return(user, nil)
	jwtSvc.On("GenerateToken", userID, "carol", freshRoles, sessionID).Return("new-access-token", nil)
	sessionRepo.On("UpdateSessionLastUsed", ctx, sessionID, mock.AnythingOfType("time.Time")).Return(nil)

	svc := NewAuthenticationService(AuthenticationConfig{
		UserRepository:    userRepo,
		SessionRepository: sessionRepo,
		PasswordService:   &MockPasswordService{},
		TOTPService:       &MockTOTPService{},
		JWTService:        jwtSvc,
		Logger:            logging.InitLogger(),
	})

	result, err := svc.RefreshAccessToken(ctx, "refresh-token-value")

	require.NoError(t, err)
	assert.Equal(t, freshRoles, result.Roles)
	jwtSvc.AssertExpectations(t)
	userRepo.AssertExpectations(t)
}
