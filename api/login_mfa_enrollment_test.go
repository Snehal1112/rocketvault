package api

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"rocketvault/internal/logging"
	"rocketvault/internal/repositories"
	authServices "rocketvault/internal/services/auth"
	"rocketvault/model"
)

// loginStubUserRepo serves fixed users by username. Other methods are not used.
type loginStubUserRepo struct {
	repositories.UserRepositoryInterface
	users map[string]model.User
}

func (r *loginStubUserRepo) ReadByUsername(_ context.Context, username string) (model.User, error) {
	u, ok := r.users[username]
	if !ok {
		return model.User{}, errors.New("not found")
	}
	return u, nil
}

// loginStubSessionRepo accepts every new session. Other methods are not used.
type loginStubSessionRepo struct {
	repositories.SessionRepositoryInterface
}

func (r *loginStubSessionRepo) CreateSession(_ context.Context, _ *model.Session) error {
	return nil
}

// loginStubJWT issues a fixed token. Other methods are not used.
type loginStubJWT struct {
	authServices.JWTService
}

func (j *loginStubJWT) GenerateToken(_ uuid.UUID, _ string, _ []string, _ uuid.UUID) (string, error) {
	return "tok", nil
}

// loginStubStepRepo records the last claimed TOTP step per user in memory,
// with the same newer-step-only rule as the real repository.
type loginStubStepRepo struct {
	mu   sync.Mutex
	last map[uuid.UUID]int64
}

func (r *loginStubStepRepo) ClaimTOTPStep(_ context.Context, userID uuid.UUID, step int64) (bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if step <= r.last[userID] {
		return false, nil
	}
	r.last[userID] = step
	return true, nil
}

// newRealLoginAuthService builds the real authentication service with real
// password and TOTP checks over the given users.
func newRealLoginAuthService(t *testing.T, users ...model.User) authServices.AuthenticationService {
	t.Helper()
	repo := &loginStubUserRepo{users: map[string]model.User{}}
	for _, u := range users {
		repo.users[u.Username] = u
	}
	return authServices.NewAuthenticationService(authServices.AuthenticationConfig{
		UserRepository:     repo,
		SessionRepository:  &loginStubSessionRepo{},
		PasswordService:    authServices.NewPasswordService(),
		TOTPService:        authServices.NewTOTPService(),
		JWTService:         &loginStubJWT{},
		TOTPStepRepository: &loginStubStepRepo{last: map[uuid.UUID]int64{}},
		Logger:             logging.InitLogger(),
	})
}

// postLogin runs loginUser and returns the recorded response.
func postLogin(authSvc authServices.AuthenticationService, username, password, code string) *httptest.ResponseRecorder {
	c := newUserCtx(nil, authSvc, RequestClaims{})
	w := httptest.NewRecorder()
	r := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/users/login", encodeBody(map[string]string{
		"username": username, "password": password, "totp_code": code,
	}))
	loginUser(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}
	return w
}

// A password login on an account with no TOTP secret is refused over HTTP,
// even with the code anyone can compute from the empty secret, and the
// response matches a wrong code on an enrolled account.
func TestLoginUser_EmptyTOTPSecret_FailsClosedLikeWrongCode(t *testing.T) {
	hash, err := authServices.NewPasswordService().HashPassword("Correct-Horse-9")
	require.NoError(t, err)
	totp := authServices.NewTOTPService()

	const enrolledSecret = "JBSWY3DPEHPK3PXP"
	unenrolled := model.User{ID: uuid.New(), Username: "bob", PasswordHash: hash, Roles: []string{model.RoleUser}, AuthProvider: model.AuthProviderOIDC}
	enrolled := model.User{ID: uuid.New(), Username: "carol", PasswordHash: hash, TOTPSecret: enrolledSecret, Roles: []string{model.RoleUser}}
	authSvc := newRealLoginAuthService(t, unenrolled, enrolled)

	// The code an attacker computes from an empty secret.
	emptySecretCode, err := totp.GenerateCode("", time.Now())
	require.NoError(t, err)
	unenrolledResp := postLogin(authSvc, "bob", "Correct-Horse-9", emptySecretCode)

	// A code that is wrong for the enrolled account.
	goodCode, err := totp.GenerateCode(enrolledSecret, time.Now())
	require.NoError(t, err)
	wrongCode := "000000"
	if goodCode == wrongCode {
		wrongCode = "111111"
	}
	wrongCodeResp := postLogin(authSvc, "carol", "Correct-Horse-9", wrongCode)

	assert.Equal(t, http.StatusForbidden, unenrolledResp.Code)
	assert.Equal(t, wrongCodeResp.Code, unenrolledResp.Code)
	assert.Equal(t, wrongCodeResp.Body.String(), unenrolledResp.Body.String())
	assert.NotContains(t, unenrolledResp.Body.String(), "tok")

	// An enrolled account with the right code still logs in.
	okResp := postLogin(authSvc, "carol", "Correct-Horse-9", goodCode)
	assert.Equal(t, http.StatusOK, okResp.Code)
}
