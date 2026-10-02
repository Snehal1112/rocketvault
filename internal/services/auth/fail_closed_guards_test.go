package auth

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"rocketvault/internal/logging"
	"rocketvault/model"
)

// A service-account token must be denied when no client repository is wired,
// because none of the client checks can run.
func TestValidateSession_ServiceAccount_NilClientRepository_Denies(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	clientID := uuid.New()

	claims := &JWTClaims{UserID: clientID, Username: "my-app", Roles: []string{model.RoleServiceAccount}}
	claims.ID = clientID.String()

	userRepo := &MockUserRepository{}
	sessionRepo := &MockSessionRepository{}
	jwt := &MockJWTService{}
	jwt.On("ValidateToken", "sa-token").Return(claims, nil)

	// The repository field is left unset, so the interface is a true nil.
	svc := NewAuthenticationService(AuthenticationConfig{
		UserRepository:    userRepo,
		SessionRepository: sessionRepo,
		PasswordService:   &MockPasswordService{},
		TOTPService:       &MockTOTPService{},
		JWTService:        jwt,
		Logger:            logging.InitLogger(),
	})

	got, err := svc.ValidateSession(ctx, "sa-token")

	require.Error(t, err)
	assert.Nil(t, got)
	assert.Equal(t, "invalid session", err.Error())
	sessionRepo.AssertNotCalled(t, "IsSessionRevoked", mock.Anything, mock.Anything)
	userRepo.AssertNotCalled(t, "Read", mock.Anything, mock.Anything)
}

// Secrets made only of whitespace or base32 padding carry no key material.
// They must be treated as not enrolled, exactly like an empty secret.
func TestAuthenticateUser_BlankTOTPSecret_FailsClosed(t *testing.T) {
	t.Parallel()

	for _, secret := range []string{"   ", "========", " \t\n", "  ====  "} {
		t.Run(secret, func(t *testing.T) {
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
				TOTPSecret:   secret,
				Roles:        []string{model.RoleUser},
				AuthProvider: model.AuthProviderOIDC,
			}
			userRepo.On("ReadByUsername", ctx, "oidc-user").Return(user, nil)
			pwd.On("ValidatePassword", "pass", "hashed").Return(nil)

			svc := newAuthService(userRepo, sessionRepo, pwd, totp, jwt, nil)
			result, err := svc.AuthenticateUser(ctx, "oidc-user", "pass", "123456")

			require.ErrorIs(t, err, ErrMFANotEnrolled)
			assert.Equal(t, "invalid TOTP code", err.Error())
			assert.Nil(t, result)
			totp.AssertNotCalled(t, "ValidateCodeWithStep", mock.Anything, mock.Anything, mock.Anything)
			sessionRepo.AssertNotCalled(t, "CreateSession", mock.Anything, mock.Anything)
		})
	}
}

func TestTOTPService_ValidateCodeWithStep_BlankSecret(t *testing.T) {
	t.Parallel()
	svc := NewTOTPService()

	// This code is what the empty HMAC key produces, so only the guard stops it.
	code, err := svc.GenerateCode("", stepTestNow)
	require.NoError(t, err)

	for _, secret := range []string{"   ", "========", " \t\n"} {
		step, valid, err := svc.ValidateCodeWithStep(code, secret, stepTestNow)
		require.Error(t, err, "secret %q", secret)
		assert.False(t, valid, "secret %q", secret)
		assert.Zero(t, step, "secret %q", secret)
	}
}

func TestTOTPSecretIsEmpty(t *testing.T) {
	t.Parallel()

	for secret, want := range map[string]bool{
		"":                 true,
		"   ":              true,
		"========":         true,
		"  ====  ":         true,
		"JBSWY3DPEHPK3PXP": false,
		"jbswy3dpehpk3pxp": false,
		"!!! not base32 !": false,
	} {
		assert.Equal(t, want, totpSecretIsEmpty(secret), "secret %q", secret)
	}
}
