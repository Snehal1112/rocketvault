package auth

// Critical path tests for ValidateSession, RefreshAccessToken, and RevokeSession.
// The mock types and helpers are defined in authentication_service_test.go.

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"rocketvault/common"
	"rocketvault/internal/logging"
	"rocketvault/internal/repositories"
	"rocketvault/internal/retry"
	"rocketvault/model"
)

func newAuthService(
	userRepo *MockUserRepository,
	sessionRepo *MockSessionRepository,
	pwd *MockPasswordService,
	totp *MockTOTPService,
	jwt *MockJWTService,
	oauth2Repo *MockOAuth2ClientRepository,
) AuthenticationService {
	return NewAuthenticationService(AuthenticationConfig{
		UserRepository:         userRepo,
		SessionRepository:      sessionRepo,
		PasswordService:        pwd,
		TOTPService:            totp,
		JWTService:             jwt,
		OAuth2ClientRepository: oauth2Repo,
		Logger:                 logging.InitLogger(),
	})
}

// --- AuthenticateUser: user not found ---

func TestAuthenticateUser_UserNotFound(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	userRepo := &MockUserRepository{}
	sessionRepo := &MockSessionRepository{}
	pwd := &MockPasswordService{}
	totp := &MockTOTPService{}
	jwt := &MockJWTService{}

	userRepo.On("ReadByUsername", ctx, "nobody").Return(model.User{}, errors.New("not found"))

	svc := newAuthService(userRepo, sessionRepo, pwd, totp, jwt, nil)
	result, err := svc.AuthenticateUser(ctx, "nobody", "pass", "123456")

	require.Error(t, err)
	assert.Nil(t, result)
	pwd.AssertNotCalled(t, "ValidatePassword")
	totp.AssertNotCalled(t, "ValidateCodeWithStep")
}

// burnSpy stands in for the dummy bcrypt compare and records each password
// it was asked to burn.
type burnSpy struct {
	mu     sync.Mutex
	burned []string
}

// install points svc's dummy compare at the spy.
func (b *burnSpy) install(svc AuthenticationService) {
	svc.(*authenticationService).burnCompare = func(password string) {
		b.mu.Lock()
		defer b.mu.Unlock()
		b.burned = append(b.burned, password)
	}
}

// calls returns the passwords burned so far.
func (b *burnSpy) calls() []string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]string(nil), b.burned...)
}

// An unknown user must pay one bcrypt compare with the supplied password, the
// same work a known user with a wrong password costs, and still get the same
// generic client error.
func TestAuthenticateUser_UserNotFound_BurnsPasswordCompare(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	userRepo := &MockUserRepository{}
	pwd := &MockPasswordService{}
	userRepo.On("ReadByUsername", ctx, "nobody").Return(model.User{}, fmt.Errorf("user not found: %w", repositories.ErrNotFound))

	svc := newAuthService(userRepo, &MockSessionRepository{}, pwd, &MockTOTPService{}, &MockJWTService{}, nil)
	spy := &burnSpy{}
	spy.install(svc)

	_, err := svc.AuthenticateUser(ctx, "nobody", "whatever", "123456")

	require.Error(t, err)
	assert.Equal(t, "invalid credentials", err.Error())
	assert.True(t, retry.IsClientError(err))
	assert.Equal(t, []string{"whatever"}, spy.calls())
	pwd.AssertNotCalled(t, "ValidatePassword")
}

// A wrong password already pays the real compare, so it must not burn a
// second one and become slower than an unknown user.
func TestAuthenticateUser_WrongPassword_DoesNotBurn(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	userRepo := &MockUserRepository{}
	pwd := &MockPasswordService{}
	userRepo.On("ReadByUsername", ctx, "alice").Return(model.User{ID: uuid.New(), Username: "alice", PasswordHash: "hashed", TOTPSecret: "secret"}, nil)
	pwd.On("ValidatePassword", "wrong", "hashed").Return(errors.New("mismatch"))

	svc := newAuthService(userRepo, &MockSessionRepository{}, pwd, &MockTOTPService{}, &MockJWTService{}, nil)
	spy := &burnSpy{}
	spy.install(svc)

	_, err := svc.AuthenticateUser(ctx, "alice", "wrong", "123456")

	require.Error(t, err)
	assert.Equal(t, "invalid credentials", err.Error())
	assert.Empty(t, spy.calls())
}

// The default dummy compare is the real bcrypt one. The bound is a loose lower
// limit: cost 12 takes far longer than 20ms, and a slow machine only adds time.
func TestAuthenticateUser_UserNotFound_CostsAsMuchAsWrongPassword(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	userRepo := &MockUserRepository{}
	userRepo.On("ReadByUsername", ctx, "nobody").Return(model.User{}, errors.New("not found"))
	svc := newAuthService(userRepo, &MockSessionRepository{}, &MockPasswordService{}, &MockTOTPService{}, &MockJWTService{}, nil)
	common.PrimeBurnPasswordCompare()

	start := time.Now()
	_, err := svc.AuthenticateUser(ctx, "nobody", "whatever", "123456")
	elapsed := time.Since(start)

	require.Error(t, err)
	assert.Equal(t, "invalid credentials", err.Error())
	assert.Greater(t, elapsed, 20*time.Millisecond, "an unknown user must still pay for a bcrypt compare")
}

// --- ValidateSession ---

func TestValidateSession_InvalidToken(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	userRepo := &MockUserRepository{}
	sessionRepo := &MockSessionRepository{}
	pwd := &MockPasswordService{}
	totp := &MockTOTPService{}
	jwt := &MockJWTService{}

	jwt.On("ValidateToken", "bad-token").Return((*JWTClaims)(nil), errors.New("token expired"))

	svc := newAuthService(userRepo, sessionRepo, pwd, totp, jwt, nil)
	_, err := svc.ValidateSession(ctx, "bad-token")

	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid session")
}

// --- RefreshAccessToken ---

func TestRefreshAccessToken_HappyPath(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	userID := uuid.New()
	sessionID := uuid.New()

	session := &model.Session{
		ID:        sessionID,
		UserID:    userID,
		Revoked:   false,
		ExpiresAt: time.Now().Add(time.Hour),
	}
	user := &model.User{ID: userID, Username: "bob", Roles: []string{model.RoleUser}}

	userRepo := &MockUserRepository{}
	sessionRepo := &MockSessionRepository{}
	pwd := &MockPasswordService{}
	totp := &MockTOTPService{}
	jwt := &MockJWTService{}

	sessionRepo.On("GetSessionByRefreshToken", ctx, mock.AnythingOfType("string")).Return(session, nil)
	userRepo.On("Read", ctx, userID).Return(user, nil)
	jwt.On("GenerateToken", userID, "bob", []string{model.RoleUser}, sessionID).Return("new-token", nil)
	sessionRepo.On("UpdateSessionLastUsed", ctx, sessionID, mock.AnythingOfType("time.Time")).Return(nil)

	svc := newAuthService(userRepo, sessionRepo, pwd, totp, jwt, nil)
	result, err := svc.RefreshAccessToken(ctx, "refresh-token-value")

	require.NoError(t, err)
	assert.Equal(t, "new-token", result.Token)
	assert.Equal(t, "bob", result.Username)
	jwt.AssertExpectations(t)
}

func TestRefreshAccessToken_RevokedSession(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	session := &model.Session{
		ID:        uuid.New(),
		UserID:    uuid.New(),
		Revoked:   true,
		ExpiresAt: time.Now().Add(time.Hour),
	}

	userRepo := &MockUserRepository{}
	sessionRepo := &MockSessionRepository{}
	pwd := &MockPasswordService{}
	totp := &MockTOTPService{}
	jwt := &MockJWTService{}

	sessionRepo.On("GetSessionByRefreshToken", ctx, mock.AnythingOfType("string")).Return(session, nil)

	svc := newAuthService(userRepo, sessionRepo, pwd, totp, jwt, nil)
	_, err := svc.RefreshAccessToken(ctx, "revoked-refresh-token")

	require.Error(t, err)
	assert.Contains(t, err.Error(), "session revoked")
}

func TestRefreshAccessToken_ExpiredSession(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	session := &model.Session{
		ID:        uuid.New(),
		UserID:    uuid.New(),
		Revoked:   false,
		ExpiresAt: time.Now().Add(-time.Hour), // already expired
	}

	userRepo := &MockUserRepository{}
	sessionRepo := &MockSessionRepository{}
	pwd := &MockPasswordService{}
	totp := &MockTOTPService{}
	jwt := &MockJWTService{}

	sessionRepo.On("GetSessionByRefreshToken", ctx, mock.AnythingOfType("string")).Return(session, nil)

	svc := newAuthService(userRepo, sessionRepo, pwd, totp, jwt, nil)
	_, err := svc.RefreshAccessToken(ctx, "expired-refresh-token")

	require.Error(t, err)
	assert.Contains(t, err.Error(), "session expired")
}

func TestRefreshAccessToken_InvalidRefreshToken(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	userRepo := &MockUserRepository{}
	sessionRepo := &MockSessionRepository{}
	pwd := &MockPasswordService{}
	totp := &MockTOTPService{}
	jwt := &MockJWTService{}

	sessionRepo.On("GetSessionByRefreshToken", ctx, mock.AnythingOfType("string")).Return(nil, errors.New("not found"))

	svc := newAuthService(userRepo, sessionRepo, pwd, totp, jwt, nil)
	_, err := svc.RefreshAccessToken(ctx, "unknown-token")

	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid refresh token")
}

// --- RevokeSession ---

func TestRevokeSession_OwnSession_Revoked(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	sessionID := uuid.New()
	callerID := uuid.New()

	sessionRepo := &MockSessionRepository{}
	sessionRepo.On("RevokeUserSession", ctx, sessionID, callerID, "logout").Return(nil)

	svc := newAuthService(&MockUserRepository{}, sessionRepo, &MockPasswordService{}, &MockTOTPService{}, &MockJWTService{}, nil)
	err := svc.RevokeSession(ctx, RevokeSessionRequest{
		SessionID:   sessionID.String(),
		CallerID:    callerID,
		CallerRoles: []string{model.RoleUser},
		Reason:      "logout",
	})

	require.NoError(t, err)
	sessionRepo.AssertExpectations(t)
	sessionRepo.AssertNotCalled(t, "RevokeSession", mock.Anything, mock.Anything, mock.Anything)
}

func TestRevokeSession_OtherUsersSession_NotFound(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	sessionID := uuid.New()
	callerID := uuid.New()

	sessionRepo := &MockSessionRepository{}
	sessionRepo.On("RevokeUserSession", ctx, sessionID, callerID, "logout").
		Return(fmt.Errorf("session not found or already revoked: %w", repositories.ErrNotFound))

	svc := newAuthService(&MockUserRepository{}, sessionRepo, &MockPasswordService{}, &MockTOTPService{}, &MockJWTService{}, nil)
	err := svc.RevokeSession(ctx, RevokeSessionRequest{
		SessionID:   sessionID.String(),
		CallerID:    callerID,
		CallerRoles: []string{model.RoleUser},
		Reason:      "logout",
	})

	require.ErrorIs(t, err, ErrSessionNotFound)
	sessionRepo.AssertNotCalled(t, "RevokeSession", mock.Anything, mock.Anything, mock.Anything)
}

func TestRevokeSession_AdminBypassesOwnership(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	sessionID := uuid.New()

	sessionRepo := &MockSessionRepository{}
	sessionRepo.On("RevokeSession", ctx, sessionID, "admin action").Return(nil)

	svc := newAuthService(&MockUserRepository{}, sessionRepo, &MockPasswordService{}, &MockTOTPService{}, &MockJWTService{}, nil)
	err := svc.RevokeSession(ctx, RevokeSessionRequest{
		SessionID:   sessionID.String(),
		CallerID:    uuid.New(),
		CallerRoles: []string{model.RoleAdmin},
		Reason:      "admin action",
	})

	require.NoError(t, err)
	sessionRepo.AssertExpectations(t)
	sessionRepo.AssertNotCalled(t, "RevokeUserSession", mock.Anything, mock.Anything, mock.Anything, mock.Anything)
}

func TestRevokeSession_InvalidSessionIDFormat(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	sessionRepo := &MockSessionRepository{}

	svc := newAuthService(&MockUserRepository{}, sessionRepo, &MockPasswordService{}, &MockTOTPService{}, &MockJWTService{}, nil)
	err := svc.RevokeSession(ctx, RevokeSessionRequest{SessionID: "not-a-uuid", CallerID: uuid.New(), Reason: "logout"})

	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid session ID format")
	sessionRepo.AssertNotCalled(t, "RevokeSession", mock.Anything, mock.Anything, mock.Anything)
	sessionRepo.AssertNotCalled(t, "RevokeUserSession", mock.Anything, mock.Anything, mock.Anything, mock.Anything)
}

func TestValidateSession_RevokedSession(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	sessionID := uuid.New()
	userID := uuid.New()

	claims := &JWTClaims{
		UserID:   userID,
		Username: "alice",
		Roles:    []string{model.RoleUser},
	}
	claims.ID = sessionID.String()

	userRepo := &MockUserRepository{}
	sessionRepo := &MockSessionRepository{}
	pwd := &MockPasswordService{}
	totp := &MockTOTPService{}
	jwt := &MockJWTService{}

	jwt.On("ValidateToken", "revoked-token").Return(claims, nil)
	sessionRepo.On("IsSessionRevoked", ctx, sessionID).Return(true, nil)

	svc := newAuthService(userRepo, sessionRepo, pwd, totp, jwt, nil)
	_, err := svc.ValidateSession(ctx, "revoked-token")

	require.Error(t, err)
	assert.Contains(t, err.Error(), "session revoked")
	sessionRepo.AssertExpectations(t)
}

func TestValidateSession_ActiveSession(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	sessionID := uuid.New()
	userID := uuid.New()

	claims := &JWTClaims{
		UserID:   userID,
		Username: "alice",
		Roles:    []string{model.RoleUser},
	}
	claims.ID = sessionID.String()

	userRepo := &MockUserRepository{}
	sessionRepo := &MockSessionRepository{}
	pwd := &MockPasswordService{}
	totp := &MockTOTPService{}
	jwt := &MockJWTService{}

	jwt.On("ValidateToken", "good-token").Return(claims, nil)
	sessionRepo.On("IsSessionRevoked", ctx, sessionID).Return(false, nil)
	userRepo.On("Read", ctx, userID).Return(&model.User{ID: userID, Username: "alice"}, nil)

	svc := newAuthService(userRepo, sessionRepo, pwd, totp, jwt, nil)
	got, err := svc.ValidateSession(ctx, "good-token")

	require.NoError(t, err)
	assert.Equal(t, userID, got.UserID)
	userRepo.AssertExpectations(t)
	sessionRepo.AssertExpectations(t)
}

// SQLite keeps user_sessions rows after a user delete, so a live token must
// not outlive its user.
func TestValidateSession_DeletedUser_Rejected(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	sessionID := uuid.New()
	userID := uuid.New()

	claims := &JWTClaims{UserID: userID, Username: "ghost", Roles: []string{model.RoleUser}}
	claims.ID = sessionID.String()

	userRepo := &MockUserRepository{}
	sessionRepo := &MockSessionRepository{}
	jwt := &MockJWTService{}

	jwt.On("ValidateToken", "orphan-token").Return(claims, nil)
	sessionRepo.On("IsSessionRevoked", ctx, sessionID).Return(false, nil)
	userRepo.On("Read", ctx, userID).Return(nil, fmt.Errorf("user not found: %w", repositories.ErrNotFound))

	svc := newAuthService(userRepo, sessionRepo, &MockPasswordService{}, &MockTOTPService{}, jwt, nil)
	got, err := svc.ValidateSession(ctx, "orphan-token")

	require.Error(t, err)
	assert.Nil(t, got)
	assert.EqualError(t, err, "invalid session")
	userRepo.AssertExpectations(t)
}

// A failed user lookup must deny, never allow, and must not reveal why.
func TestValidateSession_UserLookupError_Rejected(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	sessionID := uuid.New()
	userID := uuid.New()

	claims := &JWTClaims{UserID: userID, Username: "alice", Roles: []string{model.RoleUser}}
	claims.ID = sessionID.String()

	userRepo := &MockUserRepository{}
	sessionRepo := &MockSessionRepository{}
	jwt := &MockJWTService{}

	jwt.On("ValidateToken", "lookup-fails").Return(claims, nil)
	sessionRepo.On("IsSessionRevoked", ctx, sessionID).Return(false, nil)
	userRepo.On("Read", ctx, userID).Return(nil, errors.New("db unavailable"))

	svc := newAuthService(userRepo, sessionRepo, &MockPasswordService{}, &MockTOTPService{}, jwt, nil)
	got, err := svc.ValidateSession(ctx, "lookup-fails")

	require.Error(t, err)
	assert.Nil(t, got)
	assert.EqualError(t, err, "invalid session")
	assert.NotContains(t, err.Error(), "db unavailable")
	userRepo.AssertExpectations(t)
}

// A deleted user and a failed lookup must be indistinguishable to the caller.
func TestValidateSession_UserErrors_NoOracle(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	run := func(readErr error) error {
		sessionID := uuid.New()
		userID := uuid.New()
		claims := &JWTClaims{UserID: userID, Username: "x", Roles: []string{model.RoleUser}}
		claims.ID = sessionID.String()

		userRepo := &MockUserRepository{}
		sessionRepo := &MockSessionRepository{}
		jwt := &MockJWTService{}
		jwt.On("ValidateToken", "tok").Return(claims, nil)
		sessionRepo.On("IsSessionRevoked", ctx, sessionID).Return(false, nil)
		userRepo.On("Read", ctx, userID).Return(nil, readErr)

		svc := newAuthService(userRepo, sessionRepo, &MockPasswordService{}, &MockTOTPService{}, jwt, nil)
		_, err := svc.ValidateSession(ctx, "tok")
		return err
	}

	notFound := run(fmt.Errorf("user not found: %w", repositories.ErrNotFound))
	lookupErr := run(errors.New("connection refused"))

	require.Error(t, notFound)
	require.Error(t, lookupErr)
	assert.Equal(t, notFound.Error(), lookupErr.Error())
	assert.NotErrorIs(t, notFound, repositories.ErrNotFound)
}

func TestValidateSession_RevocationCheckError(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	sessionID := uuid.New()
	userID := uuid.New()

	claims := &JWTClaims{UserID: userID, Username: "alice", Roles: []string{model.RoleUser}}
	claims.ID = sessionID.String()

	userRepo := &MockUserRepository{}
	sessionRepo := &MockSessionRepository{}
	pwd := &MockPasswordService{}
	totp := &MockTOTPService{}
	jwt := &MockJWTService{}

	jwt.On("ValidateToken", "db-error-token").Return(claims, nil)
	sessionRepo.On("IsSessionRevoked", ctx, sessionID).Return(false, errors.New("db unavailable"))

	svc := newAuthService(userRepo, sessionRepo, pwd, totp, jwt, nil)
	_, err := svc.ValidateSession(ctx, "db-error-token")

	require.Error(t, err)
	assert.Contains(t, err.Error(), "revocation check failed")
	sessionRepo.AssertExpectations(t)
}

func TestValidateSession_DeletedServiceAccount_Rejected(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	clientID := uuid.New()

	// Service-account token uses client.ID as jti.
	claims := &JWTClaims{UserID: clientID, Username: "my-app", Roles: []string{model.RoleServiceAccount}}
	claims.ID = clientID.String()

	userRepo := &MockUserRepository{}
	sessionRepo := &MockSessionRepository{}
	pwd := &MockPasswordService{}
	totp := &MockTOTPService{}
	jwt := &MockJWTService{}
	oauth2Repo := &MockOAuth2ClientRepository{}

	jwt.On("ValidateToken", "sa-token").Return(claims, nil)
	// Client not found (deleted).
	oauth2Repo.On("GetByID", ctx, clientID).Return(nil, errors.New("not found"))

	svc := newAuthService(userRepo, sessionRepo, pwd, totp, jwt, oauth2Repo)
	_, err := svc.ValidateSession(ctx, "sa-token")

	require.Error(t, err)
	assert.Contains(t, err.Error(), "service account")
	sessionRepo.AssertNotCalled(t, "IsSessionRevoked")
	oauth2Repo.AssertExpectations(t)
}

func TestValidateSession_DisabledServiceAccount_Rejected(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	clientID := uuid.New()

	claims := &JWTClaims{UserID: clientID, Username: "my-app", Roles: []string{model.RoleServiceAccount}}
	claims.ID = clientID.String()

	userRepo := &MockUserRepository{}
	sessionRepo := &MockSessionRepository{}
	pwd := &MockPasswordService{}
	totp := &MockTOTPService{}
	jwt := &MockJWTService{}
	oauth2Repo := &MockOAuth2ClientRepository{}

	jwt.On("ValidateToken", "sa-token").Return(claims, nil)
	// Client exists but is disabled.
	oauth2Repo.On("GetByID", ctx, clientID).Return(&model.OAuth2Client{
		ID:      clientID,
		Enabled: false,
	}, nil)

	svc := newAuthService(userRepo, sessionRepo, pwd, totp, jwt, oauth2Repo)
	_, err := svc.ValidateSession(ctx, "sa-token")

	require.Error(t, err)
	assert.Contains(t, err.Error(), "service account")
	oauth2Repo.AssertExpectations(t)
}

func TestValidateSession_ActiveServiceAccount_Allowed(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	clientID := uuid.New()

	claims := &JWTClaims{UserID: clientID, Username: "my-app", Roles: []string{model.RoleServiceAccount}}
	claims.ID = clientID.String()

	userRepo := &MockUserRepository{}
	sessionRepo := &MockSessionRepository{}
	pwd := &MockPasswordService{}
	totp := &MockTOTPService{}
	jwt := &MockJWTService{}
	oauth2Repo := &MockOAuth2ClientRepository{}

	jwt.On("ValidateToken", "sa-token").Return(claims, nil)
	oauth2Repo.On("GetByID", ctx, clientID).Return(&model.OAuth2Client{
		ID:      clientID,
		Enabled: true,
	}, nil)

	svc := newAuthService(userRepo, sessionRepo, pwd, totp, jwt, oauth2Repo)
	got, err := svc.ValidateSession(ctx, "sa-token")

	require.NoError(t, err)
	assert.Equal(t, clientID, got.UserID)
	sessionRepo.AssertNotCalled(t, "IsSessionRevoked")
	// Service accounts have no users row, so the user check must not run.
	userRepo.AssertNotCalled(t, "Read", mock.Anything, mock.Anything)
	oauth2Repo.AssertExpectations(t)
}

func TestValidateSession_MalformedJti(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	userID := uuid.New()

	claims := &JWTClaims{UserID: userID, Username: "alice", Roles: []string{model.RoleUser}}
	claims.ID = "not-a-uuid"

	userRepo := &MockUserRepository{}
	sessionRepo := &MockSessionRepository{}
	pwd := &MockPasswordService{}
	totp := &MockTOTPService{}
	jwt := &MockJWTService{}

	jwt.On("ValidateToken", "bad-jti-token").Return(claims, nil)

	svc := newAuthService(userRepo, sessionRepo, pwd, totp, jwt, nil)
	_, err := svc.ValidateSession(ctx, "bad-jti-token")

	require.Error(t, err)
	assert.Contains(t, err.Error(), "malformed jti")
	sessionRepo.AssertNotCalled(t, "IsSessionRevoked")
}

// An account with no TOTP secret must never log in with a password alone.
func TestAuthenticateUser_EmptyTOTPSecret_FailsClosed(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	userRepo := &MockUserRepository{}
	sessionRepo := &MockSessionRepository{}
	pwd := &MockPasswordService{}
	totp := &MockTOTPService{}
	jwt := &MockJWTService{}

	user := model.User{
		ID:           uuid.New(),
		Username:     "oidc-user",
		PasswordHash: "hashed",
		TOTPSecret:   "",
		Roles:        []string{model.RoleUser},
		AuthProvider: model.AuthProviderOIDC,
	}
	userRepo.On("ReadByUsername", ctx, "oidc-user").Return(user, nil)
	pwd.On("ValidatePassword", "pass", "hashed").Return(nil)

	svc := newAuthService(userRepo, sessionRepo, pwd, totp, jwt, nil)
	result, err := svc.AuthenticateUser(ctx, "oidc-user", "pass", "123456")

	require.ErrorIs(t, err, ErrMFANotEnrolled)
	assert.Nil(t, result)
	totp.AssertNotCalled(t, "ValidateCodeWithStep", mock.Anything, mock.Anything, mock.Anything)
	sessionRepo.AssertNotCalled(t, "CreateSession", mock.Anything, mock.Anything)
	jwt.AssertNotCalled(t, "GenerateToken", mock.Anything, mock.Anything, mock.Anything, mock.Anything)
}

// The unenrolled error must read exactly like a wrong TOTP code, so the
// message never tells a caller that the account has no second factor.
func TestAuthenticateUser_EmptyTOTPSecret_LooksLikeWrongCode(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	// An unenrolled account with the right password.
	unenrolledRepo := &MockUserRepository{}
	unenrolledPwd := &MockPasswordService{}
	unenrolled := model.User{ID: uuid.New(), Username: "bob", PasswordHash: "hashed", Roles: []string{model.RoleUser}}
	unenrolledRepo.On("ReadByUsername", ctx, "bob").Return(unenrolled, nil)
	unenrolledPwd.On("ValidatePassword", "pass", "hashed").Return(nil)
	_, unenrolledErr := newAuthService(unenrolledRepo, &MockSessionRepository{}, unenrolledPwd,
		&MockTOTPService{}, &MockJWTService{}, nil).AuthenticateUser(ctx, "bob", "pass", "123456")

	// An enrolled account with the right password and a wrong code.
	enrolledRepo := &MockUserRepository{}
	enrolledPwd := &MockPasswordService{}
	enrolledTOTP := &MockTOTPService{}
	enrolled := model.User{ID: uuid.New(), Username: "carol", PasswordHash: "hashed", TOTPSecret: "JBSWY3DPEHPK3PXP", Roles: []string{model.RoleUser}}
	enrolledRepo.On("ReadByUsername", ctx, "carol").Return(enrolled, nil)
	enrolledPwd.On("ValidatePassword", "pass", "hashed").Return(nil)
	enrolledTOTP.On("ValidateCodeWithStep", "123456", "JBSWY3DPEHPK3PXP", mock.Anything).Return(int64(0), false, nil)
	_, wrongCodeErr := newAuthService(enrolledRepo, &MockSessionRepository{}, enrolledPwd,
		enrolledTOTP, &MockJWTService{}, nil).AuthenticateUser(ctx, "carol", "pass", "123456")

	require.ErrorIs(t, unenrolledErr, ErrMFANotEnrolled)
	require.Error(t, wrongCodeErr)
	assert.NotErrorIs(t, wrongCodeErr, ErrMFANotEnrolled)
	assert.Equal(t, wrongCodeErr.Error(), unenrolledErr.Error())
}

// A wrong password on an unenrolled account must not reveal that it is unenrolled.
func TestAuthenticateUser_EmptyTOTPSecret_WrongPasswordStaysGeneric(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	userRepo := &MockUserRepository{}
	pwd := &MockPasswordService{}

	user := model.User{ID: uuid.New(), Username: "oidc-user", PasswordHash: "hashed", Roles: []string{model.RoleUser}}
	userRepo.On("ReadByUsername", ctx, "oidc-user").Return(user, nil)
	pwd.On("ValidatePassword", "wrong", "hashed").Return(errors.New("mismatch"))

	svc := newAuthService(userRepo, &MockSessionRepository{}, pwd, &MockTOTPService{}, &MockJWTService{}, nil)
	_, err := svc.AuthenticateUser(ctx, "oidc-user", "wrong", "123456")

	require.Error(t, err)
	assert.NotErrorIs(t, err, ErrMFANotEnrolled)
	assert.Equal(t, "invalid credentials", err.Error())
}
