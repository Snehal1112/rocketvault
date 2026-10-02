// Package auth_test contains edge-case tests that bring coverage of the auth
// package to ≥80% by exercising paths not covered by the primary test files.
package auth

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"rocketvault/internal/logging"
	"rocketvault/model"
)

// ---------------------------------------------------------------------------
// PasswordService
// ---------------------------------------------------------------------------

func TestPasswordService_HashAndValidate_RoundTrip(t *testing.T) {
	t.Parallel()
	svc := NewPasswordService()

	hash, err := svc.HashPassword("my-secret-password")
	require.NoError(t, err)
	assert.NotEmpty(t, hash)

	err = svc.ValidatePassword("my-secret-password", hash)
	assert.NoError(t, err)
}

func TestPasswordService_ValidatePassword_WrongPassword(t *testing.T) {
	t.Parallel()
	svc := NewPasswordService()

	hash, err := svc.HashPassword("correct-password")
	require.NoError(t, err)

	err = svc.ValidatePassword("wrong-password", hash)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid password")
}

func TestPasswordService_ValidatePassword_InvalidHash(t *testing.T) {
	t.Parallel()
	svc := NewPasswordService()

	// An invalid hash string should return an error.
	err := svc.ValidatePassword("some-password", "not-a-valid-bcrypt-hash")
	assert.Error(t, err)
}

// ---------------------------------------------------------------------------
// TOTPService
// ---------------------------------------------------------------------------

func TestTOTPService_GenerateSecret(t *testing.T) {
	t.Parallel()
	svc := NewTOTPService()

	key, err := svc.GenerateSecret("RocketVault", "alice")
	require.NoError(t, err)
	assert.NotNil(t, key)
	assert.NotEmpty(t, key.Secret())
}

func TestTOTPService_GenerateCode_And_ValidateCode(t *testing.T) {
	t.Parallel()
	svc := NewTOTPService()

	// Generate a real TOTP secret.
	key, err := svc.GenerateSecret("RocketVault", "bob")
	require.NoError(t, err)

	now := time.Now()

	// Generate a valid TOTP code for now.
	code, err := svc.GenerateCode(key.Secret(), now)
	require.NoError(t, err)
	assert.NotEmpty(t, code)

	// That code must validate against the same secret.
	valid, err := svc.ValidateCode(code, key.Secret(), now)
	require.NoError(t, err)
	assert.True(t, valid)
}

func TestTOTPService_ValidateCode_WrongCode(t *testing.T) {
	t.Parallel()
	svc := NewTOTPService()

	key, err := svc.GenerateSecret("RocketVault", "charlie")
	require.NoError(t, err)

	// "000000" is almost never the correct TOTP for a fresh secret.
	valid, err := svc.ValidateCode("000000", key.Secret(), time.Now())
	require.NoError(t, err)
	assert.False(t, valid)
}

func TestTOTPService_ValidateCode_InvalidSecret(t *testing.T) {
	t.Parallel()
	svc := NewTOTPService()

	// An invalid base32 secret must return an error.
	_, err := svc.ValidateCode("123456", "!!! not base32 !!!", time.Now())
	assert.Error(t, err)
}

func TestTOTPService_GenerateCode_InvalidSecret(t *testing.T) {
	t.Parallel()
	svc := NewTOTPService()

	_, err := svc.GenerateCode("!!! not base32 !!!", time.Now())
	assert.Error(t, err)
}

// ---------------------------------------------------------------------------
// RevokeAllUserSessions
// ---------------------------------------------------------------------------

func TestRevokeAllUserSessions_HappyPath(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	userID := uuid.New()

	userRepo := &MockUserRepository{}
	sessionRepo := &MockSessionRepository{}
	pwd := &MockPasswordService{}
	totp := &MockTOTPService{}
	jwt := &MockJWTService{}

	sessionRepo.On("RevokeAllUserSessions", ctx, userID, "admin-action").Return(nil)

	svc := newAuthService(userRepo, sessionRepo, pwd, totp, jwt, nil)
	err := svc.RevokeAllUserSessions(ctx, userID, "admin-action")

	require.NoError(t, err)
	sessionRepo.AssertExpectations(t)
}

func TestRevokeAllUserSessions_Error(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	userID := uuid.New()

	userRepo := &MockUserRepository{}
	sessionRepo := &MockSessionRepository{}
	pwd := &MockPasswordService{}
	totp := &MockTOTPService{}
	jwt := &MockJWTService{}

	sessionRepo.On("RevokeAllUserSessions", ctx, userID, "logout").
		Return(errors.New("db error"))

	svc := newAuthService(userRepo, sessionRepo, pwd, totp, jwt, nil)
	err := svc.RevokeAllUserSessions(ctx, userID, "logout")

	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to revoke all user sessions")
	sessionRepo.AssertExpectations(t)
}

// ---------------------------------------------------------------------------
// AuthenticateUser: TOTP validation error path
// ---------------------------------------------------------------------------

func TestAuthenticateUser_TOTPValidationError(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	userRepo := &MockUserRepository{}
	sessionRepo := &MockSessionRepository{}
	pwd := &MockPasswordService{}
	totp := &MockTOTPService{}
	jwt := &MockJWTService{}

	user := model.User{
		ID:           uuid.New(),
		Username:     "dave",
		PasswordHash: "hashed",
		TOTPSecret:   "secret",
		Roles:        []string{model.RoleUser},
	}

	userRepo.On("ReadByUsername", ctx, "dave").Return(user, nil)
	pwd.On("ValidatePassword", "pass", "hashed").Return(nil)
	totp.On("ValidateCode", "badcode", "secret", mock.AnythingOfType("time.Time")).
		Return(false, errors.New("totp internal error"))

	svc := NewAuthenticationService(AuthenticationConfig{
		UserRepository:    userRepo,
		SessionRepository: sessionRepo,
		PasswordService:   pwd,
		TOTPService:       totp,
		JWTService:        jwt,
		Logger:            logging.InitLogger(),
	})

	_, err := svc.AuthenticateUser(ctx, "dave", "pass", "badcode")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "authentication failed")

	jwt.AssertNotCalled(t, "GenerateToken")
}

// ---------------------------------------------------------------------------
// AuthenticateUser: session creation failure
// ---------------------------------------------------------------------------

func TestAuthenticateUser_SessionCreationFails(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	userRepo := &MockUserRepository{}
	sessionRepo := &MockSessionRepository{}
	pwd := &MockPasswordService{}
	totp := &MockTOTPService{}
	jwt := &MockJWTService{}

	userID := uuid.New()
	user := model.User{
		ID:           userID,
		Username:     "eve",
		PasswordHash: "hashed",
		TOTPSecret:   "secret",
		Roles:        []string{model.RoleUser},
	}

	userRepo.On("ReadByUsername", ctx, "eve").Return(user, nil)
	pwd.On("ValidatePassword", "pass", "hashed").Return(nil)
	totp.On("ValidateCode", "123456", "secret", mock.AnythingOfType("time.Time")).
		Return(true, nil)
	sessionRepo.On("CreateSession", ctx, mock.AnythingOfType("*model.Session")).
		Return(errors.New("db write error"))

	svc := NewAuthenticationService(AuthenticationConfig{
		UserRepository:    userRepo,
		SessionRepository: sessionRepo,
		PasswordService:   pwd,
		TOTPService:       totp,
		JWTService:        jwt,
		Logger:            logging.InitLogger(),
	})

	_, err := svc.AuthenticateUser(ctx, "eve", "pass", "123456")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "authentication failed")

	jwt.AssertNotCalled(t, "GenerateToken")
}

// ---------------------------------------------------------------------------
// AuthenticateUser: JWT generation failure
// ---------------------------------------------------------------------------

func TestAuthenticateUser_JWTGenerationFails(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	userRepo := &MockUserRepository{}
	sessionRepo := &MockSessionRepository{}
	pwd := &MockPasswordService{}
	totp := &MockTOTPService{}
	jwt := &MockJWTService{}

	userID := uuid.New()
	user := model.User{
		ID:           userID,
		Username:     "frank",
		PasswordHash: "hashed",
		TOTPSecret:   "secret",
		Roles:        []string{model.RoleUser},
	}

	userRepo.On("ReadByUsername", ctx, "frank").Return(user, nil)
	pwd.On("ValidatePassword", "pass", "hashed").Return(nil)
	totp.On("ValidateCode", "123456", "secret", mock.AnythingOfType("time.Time")).
		Return(true, nil)
	sessionRepo.On("CreateSession", ctx, mock.AnythingOfType("*model.Session")).Return(nil)
	jwt.On("GenerateToken", userID, "frank", []string{model.RoleUser}, mock.AnythingOfType("uuid.UUID")).
		Return("", errors.New("signing error"))

	svc := NewAuthenticationService(AuthenticationConfig{
		UserRepository:    userRepo,
		SessionRepository: sessionRepo,
		PasswordService:   pwd,
		TOTPService:       totp,
		JWTService:        jwt,
		Logger:            logging.InitLogger(),
	})

	_, err := svc.AuthenticateUser(ctx, "frank", "pass", "123456")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "authentication failed")
}

// ---------------------------------------------------------------------------
// RefreshAccessToken: user not found path
// ---------------------------------------------------------------------------

func TestRefreshAccessToken_UserNotFound(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	userID := uuid.New()

	session := &model.Session{
		ID:        uuid.New(),
		UserID:    userID,
		Revoked:   false,
		ExpiresAt: time.Now().Add(time.Hour),
	}

	userRepo := &MockUserRepository{}
	sessionRepo := &MockSessionRepository{}
	pwd := &MockPasswordService{}
	totp := &MockTOTPService{}
	jwt := &MockJWTService{}

	sessionRepo.On("GetSessionByRefreshToken", ctx, mock.AnythingOfType("string")).Return(session, nil)
	userRepo.On("Read", ctx, userID).Return((*model.User)(nil), errors.New("not found"))

	svc := newAuthService(userRepo, sessionRepo, pwd, totp, jwt, nil)
	_, err := svc.RefreshAccessToken(ctx, "some-refresh-token")

	require.Error(t, err)
	assert.Contains(t, err.Error(), "user not found")
}

// ---------------------------------------------------------------------------
// RefreshAccessToken: JWT generation failure
// ---------------------------------------------------------------------------

func TestRefreshAccessToken_JWTGenerationFails(t *testing.T) {
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
	user := &model.User{ID: userID, Username: "greta", Roles: []string{model.RoleUser}}

	userRepo := &MockUserRepository{}
	sessionRepo := &MockSessionRepository{}
	pwd := &MockPasswordService{}
	totp := &MockTOTPService{}
	jwt := &MockJWTService{}

	sessionRepo.On("GetSessionByRefreshToken", ctx, mock.AnythingOfType("string")).Return(session, nil)
	userRepo.On("Read", ctx, userID).Return(user, nil)
	jwt.On("GenerateToken", userID, "greta", []string{model.RoleUser}, sessionID).
		Return("", errors.New("signing error"))

	svc := newAuthService(userRepo, sessionRepo, pwd, totp, jwt, nil)
	_, err := svc.RefreshAccessToken(ctx, "some-refresh-token")

	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to generate access token")
}

// ---------------------------------------------------------------------------
// RevokeSession: repo returns error
// ---------------------------------------------------------------------------

func TestRevokeSession_RepoError(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	sessionID := uuid.New()
	callerID := uuid.New()

	sessionRepo := &MockSessionRepository{}
	sessionRepo.On("RevokeUserSession", ctx, sessionID, callerID, "logout").
		Return(errors.New("db error"))

	svc := newAuthService(&MockUserRepository{}, sessionRepo, &MockPasswordService{}, &MockTOTPService{}, &MockJWTService{}, nil)
	err := svc.RevokeSession(ctx, RevokeSessionRequest{
		SessionID: sessionID.String(), CallerID: callerID, CallerRoles: []string{model.RoleUser}, Reason: "logout",
	})

	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to revoke session")
	assert.NotErrorIs(t, err, ErrSessionNotFound)
}

// ---------------------------------------------------------------------------
// ValidateSession: service-account with expired client
// ---------------------------------------------------------------------------

func TestValidateSession_ExpiredServiceAccount_Rejected(t *testing.T) {
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

	jwt.On("ValidateToken", "sa-token-expired").Return(claims, nil)

	expiredAt := time.Now().Add(-time.Hour)
	oauth2Repo.On("GetByID", ctx, clientID).Return(&model.OAuth2Client{
		ID:        clientID,
		Enabled:   true,
		ExpiresAt: &expiredAt,
	}, nil)

	svc := newAuthService(userRepo, sessionRepo, pwd, totp, jwt, oauth2Repo)
	_, err := svc.ValidateSession(ctx, "sa-token-expired")

	require.Error(t, err)
	assert.Contains(t, err.Error(), "service account")
	sessionRepo.AssertNotCalled(t, "IsSessionRevoked")
}
