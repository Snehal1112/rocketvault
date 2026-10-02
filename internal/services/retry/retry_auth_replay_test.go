package retry

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"rocketvault/internal/logging"
	"rocketvault/internal/repositories"
	"rocketvault/internal/services/auth"
	"rocketvault/model"
)

// replayUserRepo serves one fixed user. Other methods are not used.
type replayUserRepo struct {
	repositories.UserRepositoryInterface
	user model.User
}

func (r *replayUserRepo) ReadByUsername(_ context.Context, _ string) (model.User, error) {
	return r.user, nil
}

// replaySessionRepo counts session writes and fails them with err when set.
type replaySessionRepo struct {
	repositories.SessionRepositoryInterface
	err   error
	calls atomic.Int32
}

func (r *replaySessionRepo) CreateSession(_ context.Context, _ *model.Session) error {
	r.calls.Add(1)
	return r.err
}

// replayJWT issues a fixed token. Other methods are not used.
type replayJWT struct {
	auth.JWTService
}

func (j *replayJWT) GenerateToken(_ uuid.UUID, _ string, _ []string, _ uuid.UUID) (string, error) {
	return "tok", nil
}

// countingStepRepo keeps the newer-step-only rule in memory and counts claims.
type countingStepRepo struct {
	mu     sync.Mutex
	last   int64
	claims atomic.Int32
}

func (r *countingStepRepo) ClaimTOTPStep(_ context.Context, _ uuid.UUID, step int64) (bool, error) {
	r.claims.Add(1)
	r.mu.Lock()
	defer r.mu.Unlock()
	if step <= r.last {
		return false, nil
	}
	r.last = step
	return true, nil
}

// newRetriedLoginService wraps the real authentication service, with real
// password and TOTP checks, in the real retry layer.
func newRetriedLoginService(t *testing.T, sessions *replaySessionRepo, steps *countingStepRepo) (auth.AuthenticationService, string) {
	t.Helper()
	totp := auth.NewTOTPService()
	key, err := totp.GenerateSecret("PasswordManager", "retry-replay")
	require.NoError(t, err)
	hash, err := auth.NewPasswordService().HashPassword("Correct-Horse-9")
	require.NoError(t, err)

	quiet := logrus.New()
	quiet.SetLevel(logrus.PanicLevel)
	base := auth.NewAuthenticationService(auth.AuthenticationConfig{
		UserRepository: &replayUserRepo{user: model.User{
			ID: uuid.New(), Username: "retry-replay", PasswordHash: hash, TOTPSecret: key.Secret(), Roles: []string{model.RoleUser},
		}},
		SessionRepository:  sessions,
		PasswordService:    auth.NewPasswordService(),
		TOTPService:        totp,
		JWTService:         &replayJWT{},
		TOTPStepRepository: steps,
		Logger:             logging.WrapLogrus(quiet),
	})
	code, err := totp.GenerateCode(key.Secret(), time.Now())
	require.NoError(t, err)
	return NewRetryAuthenticationService(base, newRealRetryService(t)), code
}

// A replay rejection is final: the retry layer runs the login once and
// claims once.
func TestRetryAuth_ReplayedTOTPCode_NotRetried(t *testing.T) {
	sessions := &replaySessionRepo{}
	steps := &countingStepRepo{}
	svc, code := newRetriedLoginService(t, sessions, steps)
	ctx := context.Background()

	_, err := svc.AuthenticateUser(ctx, "retry-replay", "Correct-Horse-9", code)
	require.NoError(t, err)
	require.Equal(t, int32(1), steps.claims.Load())

	_, err = svc.AuthenticateUser(ctx, "retry-replay", "Correct-Horse-9", code)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid TOTP code")
	assert.Equal(t, int32(2), steps.claims.Load(), "the replay must be tried once, not retried")
	assert.Equal(t, int32(1), sessions.calls.Load())
}

// A retryable session-store error after a successful claim is not retried. A
// retry could only fail on the step it already claimed, which would turn a
// storage error into a false replay.
func TestRetryAuth_SessionErrorAfterClaim_NotRetried(t *testing.T) {
	sessions := &replaySessionRepo{err: errors.New("database is locked")}
	steps := &countingStepRepo{}
	svc, code := newRetriedLoginService(t, sessions, steps)

	_, err := svc.AuthenticateUser(context.Background(), "retry-replay", "Correct-Horse-9", code)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "database is locked")
	assert.NotContains(t, err.Error(), "invalid TOTP code")
	assert.Equal(t, int32(1), steps.claims.Load(), "the login must not be retried after its step was claimed")
	assert.Equal(t, int32(1), sessions.calls.Load())
}
