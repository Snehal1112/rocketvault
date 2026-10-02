package auth

// Critical path tests for ValidateSession, RefreshAccessToken, and RevokeSession.
// The mock types and helpers are defined in authentication_service_test.go.

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"rocketvault/internal/logging"
	"rocketvault/internal/repositories"
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
	totp.AssertNotCalled(t, "ValidateCode")
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

	svc := newAuthService(userRepo, sessionRepo, pwd, totp, jwt, nil)
	got, err := svc.ValidateSession(ctx, "good-token")

	require.NoError(t, err)
	assert.Equal(t, userID, got.UserID)
	sessionRepo.AssertExpectations(t)
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
