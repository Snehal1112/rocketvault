package users

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"rocketvault/common"
	"rocketvault/internal/logging"
	"rocketvault/internal/repositories"
	authServices "rocketvault/internal/services/auth"
	"rocketvault/model"
)

// cliLoginUserRepo serves fixed users by username. Other methods are not used.
type cliLoginUserRepo struct {
	repositories.UserRepositoryInterface
	users map[string]model.User
}

func (r *cliLoginUserRepo) ReadByUsername(_ context.Context, username string) (model.User, error) {
	u, ok := r.users[username]
	if !ok {
		return model.User{}, errors.New("not found")
	}
	return u, nil
}

// cliLoginSessionRepo accepts every new session. Other methods are not used.
type cliLoginSessionRepo struct {
	repositories.SessionRepositoryInterface
}

func (r *cliLoginSessionRepo) CreateSession(_ context.Context, _ *model.Session) error {
	return nil
}

// cliLoginJWT issues a fixed token. Other methods are not used.
type cliLoginJWT struct {
	authServices.JWTService
}

func (j *cliLoginJWT) GenerateToken(_ uuid.UUID, _ string, _ []string, _ uuid.UUID) (string, error) {
	return "tok", nil
}

// The CLI password login on an account with no TOTP secret is refused, saves
// no session, and fails with the same message as a wrong code.
func TestPerformPasswordLogin_EmptyTOTPSecret_FailsClosedLikeWrongCode(t *testing.T) {
	common.SessionBaseDir = t.TempDir()

	hash, err := authServices.NewPasswordService().HashPassword("Correct-Horse-9")
	require.NoError(t, err)
	totp := authServices.NewTOTPService()

	const enrolledSecret = "JBSWY3DPEHPK3PXP"
	authSvc := authServices.NewAuthenticationService(authServices.AuthenticationConfig{
		UserRepository: &cliLoginUserRepo{users: map[string]model.User{
			"bob":   {ID: uuid.New(), Username: "bob", PasswordHash: hash, Roles: []string{model.RoleUser}, AuthProvider: model.AuthProviderOIDC},
			"carol": {ID: uuid.New(), Username: "carol", PasswordHash: hash, TOTPSecret: enrolledSecret, Roles: []string{model.RoleUser}},
		}},
		SessionRepository: &cliLoginSessionRepo{},
		PasswordService:   authServices.NewPasswordService(),
		TOTPService:       totp,
		JWTService:        &cliLoginJWT{},
		Logger:            logging.InitLogger(),
	})

	// The code an attacker computes from an empty secret.
	emptySecretCode, err := totp.GenerateCode("", time.Now())
	require.NoError(t, err)
	_, unenrolledErr := performPasswordLogin(context.Background(), authSvc, "bob", "Correct-Horse-9", emptySecretCode)

	wrongCode := wrongCodeFor(t, enrolledSecret)
	_, wrongCodeErr := performPasswordLogin(context.Background(), authSvc, "carol", "Correct-Horse-9", wrongCode)

	require.ErrorIs(t, unenrolledErr, authServices.ErrMFANotEnrolled)
	require.Error(t, wrongCodeErr)
	assert.Equal(t, wrongCodeErr.Error(), unenrolledErr.Error())
	cached, err := common.LoadSession("bob")
	require.NoError(t, err)
	assert.Nil(t, cached)
}
