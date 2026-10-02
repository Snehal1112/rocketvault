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
	"rocketvault/internal/repositories"
	"rocketvault/model"
)

// throttleFixture holds the mocks of one throttled authentication service.
type throttleFixture struct {
	clk      *throttleClock
	repo     *fakeFailureRepo
	users    *MockUserRepository
	sessions *MockSessionRepository
	pw       *MockPasswordService
	totp     *MockTOTPService
	jwt      *MockJWTService
	steps    *MockTOTPStepRepository
}

func newThrottleFixture() *throttleFixture {
	return &throttleFixture{
		clk:      &throttleClock{t: time.Unix(1_700_000_000, 0)},
		repo:     newFakeFailureRepo(),
		users:    &MockUserRepository{},
		sessions: &MockSessionRepository{},
		pw:       &MockPasswordService{},
		totp:     &MockTOTPService{},
		jwt:      &MockJWTService{},
		steps:    &MockTOTPStepRepository{},
	}
}

// service builds the authentication service. withSteps false leaves the TOTP
// step repository nil, which models a misconfigured server.
func (f *throttleFixture) service(withSteps bool) AuthenticationService {
	cfg := AuthenticationConfig{
		UserRepository:    f.users,
		SessionRepository: f.sessions,
		PasswordService:   f.pw,
		TOTPService:       f.totp,
		JWTService:        f.jwt,
		Logger:            logging.InitLogger(),
		LoginThrottle:     NewLoginThrottle(f.repo, f.clk.now),
	}
	if withSteps {
		cfg.TOTPStepRepository = f.steps
	}
	return NewAuthenticationService(cfg)
}

// failures returns the recorded failure count for username, or 0.
func (f *throttleFixture) failures(t *testing.T, username string) int {
	t.Helper()
	row, err := f.repo.Get(context.Background(), username)
	if errors.Is(err, repositories.ErrNotFound) {
		return 0
	}
	require.NoError(t, err)
	return row.Failures
}

// enrolledUser registers alice with a password and a TOTP secret.
func (f *throttleFixture) enrolledUser(ctx context.Context) model.User {
	user := model.User{
		ID: uuid.New(), Username: "alice", PasswordHash: "hashed",
		TOTPSecret: "secret123", Roles: []string{model.RoleUser},
	}
	f.users.On("ReadByUsername", ctx, "alice").Return(user, nil)
	return user
}

func TestAuthenticateUser_ThrottledAfterRepeatedWrongPasswords(t *testing.T) {
	ctx := context.Background()
	f := newThrottleFixture()
	f.enrolledUser(ctx)
	f.pw.On("ValidatePassword", "wrong", "hashed").Return(errors.New("bad"))
	svc := f.service(true)

	for i := 0; i < 6; i++ {
		_, err := svc.AuthenticateUser(ctx, "alice", "wrong", "123456")
		require.Error(t, err)
		require.NotErrorIs(t, err, ErrLoginThrottled)
		assert.Equal(t, "invalid credentials", err.Error())
	}
	_, err := svc.AuthenticateUser(ctx, "alice", "wrong", "123456")
	require.ErrorIs(t, err, ErrLoginThrottled)
	// The throttled attempt never reached the user lookup or the password check.
	f.pw.AssertNumberOfCalls(t, "ValidatePassword", 6)
	f.users.AssertNumberOfCalls(t, "ReadByUsername", 6)
	assert.Equal(t, 6, f.failures(t, "alice"), "a throttled attempt must not grow the counter")
}

// A throttled correct login is refused too; once the window passes, the same
// login succeeds and clears the counter.
func TestAuthenticateUser_SuccessResetsThrottle(t *testing.T) {
	ctx := context.Background()
	f := newThrottleFixture()
	user := f.enrolledUser(ctx)
	f.pw.On("ValidatePassword", "password123", "hashed").Return(nil)
	f.totp.On("ValidateCodeWithStep", "123456", "secret123", mock.AnythingOfType("time.Time")).Return(int64(100), true, nil)
	f.steps.On("ClaimTOTPStep", mock.Anything, user.ID, int64(100)).Return(true, nil)
	f.sessions.On("CreateSession", ctx, mock.AnythingOfType("*model.Session")).Return(nil)
	f.jwt.On("GenerateToken", user.ID, "alice", user.Roles, mock.AnythingOfType("uuid.UUID")).Return("jwt_token", nil)
	svc := f.service(true)

	for i := 0; i < 6; i++ {
		NewLoginThrottle(f.repo, f.clk.now).RecordFailure(ctx, "alice")
	}
	_, err := svc.AuthenticateUser(ctx, "alice", "password123", "123456")
	require.ErrorIs(t, err, ErrLoginThrottled, "correct credentials inside the window are refused")

	f.clk.t = f.clk.t.Add(time.Minute) // Past the 2s window.
	result, err := svc.AuthenticateUser(ctx, "alice", "password123", "123456")
	require.NoError(t, err)
	assert.Equal(t, "jwt_token", result.Token)
	assert.Equal(t, 0, f.failures(t, "alice"), "a successful login must clear the counter")
}

func TestAuthenticateUser_UnknownUserIsThrottledLikeKnownUser(t *testing.T) {
	ctx := context.Background()
	f := newThrottleFixture()
	f.enrolledUser(ctx)
	f.users.On("ReadByUsername", ctx, "ghost").Return(model.User{}, errors.New("not found"))
	f.pw.On("ValidatePassword", "x", "hashed").Return(errors.New("bad"))
	svc := f.service(true)

	var knownErr, unknownErr error
	for i := 0; i < 6; i++ {
		_, knownErr = svc.AuthenticateUser(ctx, "alice", "x", "123456")
		_, unknownErr = svc.AuthenticateUser(ctx, "ghost", "x", "123456")
		require.Error(t, unknownErr)
		assert.Equal(t, knownErr.Error(), unknownErr.Error())
	}
	_, knownErr = svc.AuthenticateUser(ctx, "alice", "x", "123456")
	_, unknownErr = svc.AuthenticateUser(ctx, "ghost", "x", "123456")
	require.ErrorIs(t, unknownErr, ErrLoginThrottled, "a missing account must throttle too, or the response leaks existence")
	require.ErrorIs(t, knownErr, ErrLoginThrottled)
	assert.Equal(t, knownErr.Error(), unknownErr.Error(), "throttle responses must be identical")
	var known, unknown *ThrottledError
	require.ErrorAs(t, knownErr, &known)
	require.ErrorAs(t, unknownErr, &unknown)
	assert.Equal(t, known.RetryAfter, unknown.RetryAfter)
}

// Every credential failure exit counts once, and none of them clears the
// counter. The client-visible message stays the one the identity work set.
func TestAuthenticateUser_EveryFailureExitCountsOnce(t *testing.T) {
	ctx := context.Background()
	tests := []struct {
		name      string
		setup     func(f *throttleFixture)
		withSteps bool
		wantMsg   string
		wantIs    error
	}{
		{
			name: "unknown user",
			setup: func(f *throttleFixture) {
				f.users.On("ReadByUsername", ctx, "alice").Return(model.User{}, errors.New("not found"))
			},
			withSteps: true,
			wantMsg:   "invalid credentials",
		},
		{
			name: "wrong password",
			setup: func(f *throttleFixture) {
				f.enrolledUser(ctx)
				f.pw.On("ValidatePassword", "pw", "hashed").Return(errors.New("bad"))
			},
			withSteps: true,
			wantMsg:   "invalid credentials",
		},
		{
			name: "empty TOTP secret",
			setup: func(f *throttleFixture) {
				f.users.On("ReadByUsername", ctx, "alice").Return(model.User{ID: uuid.New(), Username: "alice", PasswordHash: "hashed"}, nil)
				f.pw.On("ValidatePassword", "pw", "hashed").Return(nil)
			},
			withSteps: true,
			wantMsg:   "invalid TOTP code",
			wantIs:    ErrMFANotEnrolled,
		},
		{
			name: "malformed TOTP code",
			setup: func(f *throttleFixture) {
				f.enrolledUser(ctx)
				f.pw.On("ValidatePassword", "pw", "hashed").Return(nil)
				f.totp.On("ValidateCodeWithStep", "123456", "secret123", mock.AnythingOfType("time.Time")).Return(int64(0), false, errors.New("bad length"))
			},
			withSteps: true,
		},
		{
			name: "wrong TOTP code",
			setup: func(f *throttleFixture) {
				f.enrolledUser(ctx)
				f.pw.On("ValidatePassword", "pw", "hashed").Return(nil)
				f.totp.On("ValidateCodeWithStep", "123456", "secret123", mock.AnythingOfType("time.Time")).Return(int64(0), false, nil)
			},
			withSteps: true,
			wantMsg:   "invalid TOTP code",
		},
		{
			name: "replayed TOTP code",
			setup: func(f *throttleFixture) {
				f.enrolledUser(ctx)
				f.pw.On("ValidatePassword", "pw", "hashed").Return(nil)
				f.totp.On("ValidateCodeWithStep", "123456", "secret123", mock.AnythingOfType("time.Time")).Return(int64(100), true, nil)
				f.steps.On("ClaimTOTPStep", mock.Anything, mock.Anything, int64(100)).Return(false, nil)
			},
			withSteps: true,
			wantMsg:   "invalid TOTP code",
		},
		{
			name: "TOTP step claim error",
			setup: func(f *throttleFixture) {
				f.enrolledUser(ctx)
				f.pw.On("ValidatePassword", "pw", "hashed").Return(nil)
				f.totp.On("ValidateCodeWithStep", "123456", "secret123", mock.AnythingOfType("time.Time")).Return(int64(100), true, nil)
				f.steps.On("ClaimTOTPStep", mock.Anything, mock.Anything, int64(100)).Return(false, errors.New("database is locked"))
			},
			withSteps: true,
		},
		{
			name: "replay protection not configured",
			setup: func(f *throttleFixture) {
				f.enrolledUser(ctx)
				f.pw.On("ValidatePassword", "pw", "hashed").Return(nil)
				f.totp.On("ValidateCodeWithStep", "123456", "secret123", mock.AnythingOfType("time.Time")).Return(int64(100), true, nil)
			},
			withSteps: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newThrottleFixture()
			tt.setup(f)
			// A prior failure must survive the attempt, so nothing on this
			// path may reset the counter.
			NewLoginThrottle(f.repo, f.clk.now).RecordFailure(ctx, "alice")

			_, err := f.service(tt.withSteps).AuthenticateUser(ctx, "alice", "pw", "123456")

			require.Error(t, err)
			require.NotErrorIs(t, err, ErrLoginThrottled)
			if tt.wantMsg != "" {
				assert.Equal(t, tt.wantMsg, err.Error())
			}
			if tt.wantIs != nil {
				assert.ErrorIs(t, err, tt.wantIs)
			}
			assert.Equal(t, 2, f.failures(t, "alice"), "the failure must be recorded exactly once")
		})
	}
}

// A server fault after the credentials were accepted is not a credential
// failure. It neither counts nor clears the counter.
func TestAuthenticateUser_SessionIssueFailureKeepsCounter(t *testing.T) {
	ctx := context.Background()
	f := newThrottleFixture()
	user := f.enrolledUser(ctx)
	f.pw.On("ValidatePassword", "pw", "hashed").Return(nil)
	f.totp.On("ValidateCodeWithStep", "123456", "secret123", mock.AnythingOfType("time.Time")).Return(int64(100), true, nil)
	f.steps.On("ClaimTOTPStep", mock.Anything, user.ID, int64(100)).Return(true, nil)
	f.sessions.On("CreateSession", ctx, mock.AnythingOfType("*model.Session")).Return(errors.New("disk full"))
	NewLoginThrottle(f.repo, f.clk.now).RecordFailure(ctx, "alice")

	_, err := f.service(true).AuthenticateUser(ctx, "alice", "pw", "123456")

	require.Error(t, err)
	assert.Equal(t, 1, f.failures(t, "alice"))
}

// Refresh and session validation are not logins, so their failures never
// touch the counter.
func TestAuthenticationService_RefreshAndValidateDoNotCountAsLoginFailures(t *testing.T) {
	ctx := context.Background()
	f := newThrottleFixture()
	f.sessions.On("GetSessionByRefreshToken", ctx, mock.Anything).Return(nil, errors.New("not found"))
	f.jwt.On("ValidateToken", "bad-token").Return(nil, errors.New("bad signature"))
	svc := f.service(true)

	_, err := svc.RefreshAccessToken(ctx, "bad-refresh")
	require.Error(t, err)
	_, err = svc.ValidateSession(ctx, "bad-token")
	require.Error(t, err)

	assert.Empty(t, f.repo.rows)
}

// Without a throttle the service behaves exactly as before.
func TestAuthenticateUser_NilThrottleDisablesBackoff(t *testing.T) {
	ctx := context.Background()
	users := &MockUserRepository{}
	users.On("ReadByUsername", ctx, "ghost").Return(model.User{}, errors.New("not found"))
	svc := NewAuthenticationService(AuthenticationConfig{
		UserRepository: users, SessionRepository: &MockSessionRepository{}, PasswordService: &MockPasswordService{},
		TOTPService: &MockTOTPService{}, JWTService: &MockJWTService{}, Logger: logging.InitLogger(),
	})
	for i := 0; i < 10; i++ {
		_, err := svc.AuthenticateUser(ctx, "ghost", "x", "123456")
		require.NotErrorIs(t, err, ErrLoginThrottled)
	}
}
