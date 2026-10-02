package auth

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	rvdb "rocketvault/internal/db"
	"rocketvault/internal/logging"
	"rocketvault/internal/repositories"
	auditServices "rocketvault/internal/services/audit"
	"rocketvault/model"
)

type MockTOTPStepRepository struct {
	mock.Mock
}

func (m *MockTOTPStepRepository) ClaimTOTPStep(ctx context.Context, userID uuid.UUID, step int64) (bool, error) {
	args := m.Called(ctx, userID, step)
	return args.Bool(0), args.Error(1)
}

func TestAuthenticateUser_ReplayedStep_Rejected(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	userRepo := &MockUserRepository{}
	sessionRepo := &MockSessionRepository{}
	pwd := &MockPasswordService{}
	totp := &MockTOTPService{}
	steps := &MockTOTPStepRepository{}

	user := model.User{ID: uuid.New(), Username: "replay", PasswordHash: "hashed", TOTPSecret: "secret", Roles: []string{model.RoleUser}}
	userRepo.On("ReadByUsername", ctx, "replay").Return(user, nil)
	pwd.On("ValidatePassword", "pass", "hashed").Return(nil)
	totp.On("ValidateCodeWithStep", "123456", "secret", mock.AnythingOfType("time.Time")).Return(int64(56666666), true, nil)
	steps.On("ClaimTOTPStep", ctx, user.ID, int64(56666666)).Return(false, nil)

	svc := NewAuthenticationService(AuthenticationConfig{
		UserRepository: userRepo, SessionRepository: sessionRepo, PasswordService: pwd,
		TOTPService: totp, JWTService: &MockJWTService{}, TOTPStepRepository: steps, Logger: logging.InitLogger(),
	})
	_, err := svc.AuthenticateUser(ctx, "replay", "pass", "123456")

	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid TOTP code")
	// The replay must read exactly like a wrong code, so a caller cannot tell
	// that the code was right but already used.
	assert.Equal(t, invalidTOTPCodeMessage, err.Error())
	steps.AssertExpectations(t)
	sessionRepo.AssertNotCalled(t, "CreateSession", mock.Anything, mock.Anything)
}

func TestAuthenticateUser_NoStepRepository_FailsClosed(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	userRepo := &MockUserRepository{}
	sessionRepo := &MockSessionRepository{}
	pwd := &MockPasswordService{}
	totp := &MockTOTPService{}

	user := model.User{ID: uuid.New(), Username: "nostep", PasswordHash: "hashed", TOTPSecret: "secret", Roles: []string{model.RoleUser}}
	userRepo.On("ReadByUsername", ctx, "nostep").Return(user, nil)
	pwd.On("ValidatePassword", "pass", "hashed").Return(nil)
	totp.On("ValidateCodeWithStep", "123456", "secret", mock.AnythingOfType("time.Time")).Return(int64(1), true, nil)

	svc := NewAuthenticationService(AuthenticationConfig{
		UserRepository: userRepo, SessionRepository: sessionRepo, PasswordService: pwd,
		TOTPService: totp, JWTService: &MockJWTService{}, Logger: logging.InitLogger(),
	})
	_, err := svc.AuthenticateUser(ctx, "nostep", "pass", "123456")

	require.Error(t, err)
	assert.Contains(t, err.Error(), "replay protection is not configured")
	sessionRepo.AssertNotCalled(t, "CreateSession", mock.Anything, mock.Anything)
}

// End to end with the real TOTP service and a real SQLite claim.
func TestAuthenticateUser_SameCodeTwice_SecondRejected(t *testing.T) {
	ctx := context.Background()
	conn, err := sql.Open("sqlite3", ":memory:")
	require.NoError(t, err)
	conn.SetMaxOpenConns(1) // Each :memory: connection is its own database.
	t.Cleanup(func() { _ = conn.Close() })
	_, err = conn.ExecContext(context.Background(), `CREATE TABLE users (id TEXT PRIMARY KEY, totp_last_step BIGINT NOT NULL DEFAULT 0)`)
	require.NoError(t, err)

	totpSvc := NewTOTPService()
	key, err := totpSvc.GenerateSecret("RocketVault", "replay")
	require.NoError(t, err)
	user := model.User{ID: uuid.New(), Username: "replay", PasswordHash: "hashed", TOTPSecret: key.Secret(), Roles: []string{model.RoleUser}}
	_, err = conn.ExecContext(context.Background(), `INSERT INTO users (id) VALUES (?)`, user.ID.String())
	require.NoError(t, err)

	userRepo := &MockUserRepository{}
	sessionRepo := &MockSessionRepository{}
	pwd := &MockPasswordService{}
	jwt := &MockJWTService{}
	userRepo.On("ReadByUsername", ctx, "replay").Return(user, nil)
	pwd.On("ValidatePassword", "pass", "hashed").Return(nil)
	sessionRepo.On("CreateSession", ctx, mock.AnythingOfType("*model.Session")).Return(nil)
	jwt.On("GenerateToken", user.ID, "replay", user.Roles, mock.AnythingOfType("uuid.UUID")).Return("jwt", nil)

	svc := NewAuthenticationService(AuthenticationConfig{
		UserRepository: userRepo, SessionRepository: sessionRepo, PasswordService: pwd,
		TOTPService: totpSvc, JWTService: jwt, Logger: logging.InitLogger(),
		TOTPStepRepository: repositories.NewTOTPStepRepository(rvdb.NewConn(conn, rvdb.SQLite)),
	})

	code, err := totpSvc.GenerateCode(key.Secret(), time.Now())
	require.NoError(t, err)

	_, err = svc.AuthenticateUser(ctx, "replay", "pass", code)
	require.NoError(t, err, "the first use of a code must succeed")

	_, err = svc.AuthenticateUser(ctx, "replay", "pass", code)
	require.Error(t, err, "a replayed code must be rejected")
	assert.Contains(t, err.Error(), "invalid TOTP code")
	assert.Equal(t, invalidTOTPCodeMessage, err.Error())
	sessionRepo.AssertNumberOfCalls(t, "CreateSession", 1)
}

// newFileStepDB opens a file-backed SQLite database with several pooled
// connections, so concurrent claims genuinely contend for the row.
func newFileStepDB(t *testing.T, userID uuid.UUID) *sql.DB {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "totp-replay.db")
	conn, err := sql.Open("sqlite3", "file:"+dbPath+"?_busy_timeout=10000&_journal_mode=WAL")
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })
	conn.SetMaxOpenConns(8)
	_, err = conn.ExecContext(context.Background(), `CREATE TABLE users (id TEXT PRIMARY KEY, totp_last_step BIGINT NOT NULL DEFAULT 0)`)
	require.NoError(t, err)
	_, err = conn.ExecContext(context.Background(), `INSERT INTO users (id) VALUES (?)`, userID.String())
	require.NoError(t, err)
	return conn
}

// Logins racing with the same valid code must produce exactly one session.
func TestAuthenticateUser_ConcurrentSameCode_ExactlyOneSucceeds(t *testing.T) {
	ctx := context.Background()
	totpSvc := NewTOTPService()
	key, err := totpSvc.GenerateSecret("RocketVault", "racer")
	require.NoError(t, err)
	user := model.User{ID: uuid.New(), Username: "racer", PasswordHash: "hashed", TOTPSecret: key.Secret(), Roles: []string{model.RoleUser}}
	conn := newFileStepDB(t, user.ID)

	userRepo := &MockUserRepository{}
	sessionRepo := &MockSessionRepository{}
	pwd := &MockPasswordService{}
	jwt := &MockJWTService{}
	userRepo.On("ReadByUsername", mock.Anything, "racer").Return(user, nil)
	pwd.On("ValidatePassword", "pass", "hashed").Return(nil)
	sessionRepo.On("CreateSession", mock.Anything, mock.AnythingOfType("*model.Session")).Return(nil)
	jwt.On("GenerateToken", user.ID, "racer", user.Roles, mock.AnythingOfType("uuid.UUID")).Return("jwt", nil)

	svc := NewAuthenticationService(AuthenticationConfig{
		UserRepository: userRepo, SessionRepository: sessionRepo, PasswordService: pwd,
		TOTPService: totpSvc, JWTService: jwt, Logger: logging.InitLogger(),
		TOTPStepRepository: repositories.NewTOTPStepRepository(rvdb.NewConn(conn, rvdb.SQLite)),
	})

	code, err := totpSvc.GenerateCode(key.Secret(), time.Now())
	require.NoError(t, err)

	const racers = 8
	var (
		wins     atomic.Int32
		wg       sync.WaitGroup
		start    = make(chan struct{})
		failures = make(chan error, racers)
	)
	for range racers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			if _, loginErr := svc.AuthenticateUser(ctx, "racer", "pass", code); loginErr != nil {
				failures <- loginErr
				return
			}
			wins.Add(1)
		}()
	}
	close(start)
	wg.Wait()
	close(failures)

	assert.Equal(t, int32(1), wins.Load(), "exactly one login may use a given code")
	for e := range failures {
		assert.Equal(t, invalidTOTPCodeMessage, e.Error(), "every losing racer must see a plain wrong-code error")
	}
	sessionRepo.AssertNumberOfCalls(t, "CreateSession", 1)
}

// A claim that errors or reports false must deny the login, never allow it.
func TestAuthenticateUser_ClaimFailure_FailsClosed(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name    string
		claimed bool
		err     error
	}{
		{name: "repository error", claimed: false, err: errors.New("database is locked")},
		{name: "unknown user row", claimed: false, err: nil},
		{name: "error with claimed true", claimed: true, err: errors.New("failed to get rows affected")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			ctx := context.Background()
			userRepo := &MockUserRepository{}
			sessionRepo := &MockSessionRepository{}
			pwd := &MockPasswordService{}
			totp := &MockTOTPService{}
			steps := &MockTOTPStepRepository{}
			jwt := &MockJWTService{}

			user := model.User{ID: uuid.New(), Username: "claim", PasswordHash: "hashed", TOTPSecret: "secret", Roles: []string{model.RoleUser}}
			userRepo.On("ReadByUsername", ctx, "claim").Return(user, nil)
			pwd.On("ValidatePassword", "pass", "hashed").Return(nil)
			totp.On("ValidateCodeWithStep", "123456", "secret", mock.AnythingOfType("time.Time")).Return(int64(7), true, nil)
			steps.On("ClaimTOTPStep", ctx, user.ID, int64(7)).Return(tc.claimed, tc.err)

			svc := NewAuthenticationService(AuthenticationConfig{
				UserRepository: userRepo, SessionRepository: sessionRepo, PasswordService: pwd,
				TOTPService: totp, JWTService: jwt, TOTPStepRepository: steps, Logger: logging.InitLogger(),
			})
			result, err := svc.AuthenticateUser(ctx, "claim", "pass", "123456")

			require.Error(t, err)
			assert.Nil(t, result)
			steps.AssertExpectations(t)
			sessionRepo.AssertNotCalled(t, "CreateSession", mock.Anything, mock.Anything)
			jwt.AssertNotCalled(t, "GenerateToken", mock.Anything, mock.Anything, mock.Anything, mock.Anything)
		})
	}
}

// A step is claimed only after the password and the code were both accepted.
// A wrong password must never burn a step, or an attacker without the
// password could lock a real user out of the current code.
func TestAuthenticateUser_RejectedAttempts_NeverClaim(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name      string
		password  error
		step      int64
		valid     bool
		totpErr   error
		wantInMsg string
	}{
		{name: "wrong password", password: errors.New("mismatch"), wantInMsg: "invalid credentials"},
		{name: "wrong code", step: 0, valid: false, wantInMsg: "invalid TOTP code"},
		{name: "validation error", step: 0, valid: false, totpErr: errors.New("malformed secret"), wantInMsg: "authentication failed"},
		{name: "validation error with a step", step: 9, valid: true, totpErr: errors.New("malformed secret"), wantInMsg: "authentication failed"},
		{name: "invalid with a step", step: 9, valid: false, wantInMsg: "invalid TOTP code"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			ctx := context.Background()
			userRepo := &MockUserRepository{}
			sessionRepo := &MockSessionRepository{}
			pwd := &MockPasswordService{}
			totp := &MockTOTPService{}
			steps := &MockTOTPStepRepository{}

			user := model.User{ID: uuid.New(), Username: "noclaim", PasswordHash: "hashed", TOTPSecret: "secret", Roles: []string{model.RoleUser}}
			userRepo.On("ReadByUsername", ctx, "noclaim").Return(user, nil)
			pwd.On("ValidatePassword", "pass", "hashed").Return(tc.password)
			totp.On("ValidateCodeWithStep", "123456", "secret", mock.AnythingOfType("time.Time")).Return(tc.step, tc.valid, tc.totpErr)

			svc := NewAuthenticationService(AuthenticationConfig{
				UserRepository: userRepo, SessionRepository: sessionRepo, PasswordService: pwd,
				TOTPService: totp, JWTService: &MockJWTService{}, TOTPStepRepository: steps, Logger: logging.InitLogger(),
			})
			_, err := svc.AuthenticateUser(ctx, "noclaim", "pass", "123456")

			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.wantInMsg)
			steps.AssertNotCalled(t, "ClaimTOTPStep", mock.Anything, mock.Anything, mock.Anything)
			sessionRepo.AssertNotCalled(t, "CreateSession", mock.Anything, mock.Anything)
			if tc.password != nil {
				totp.AssertNotCalled(t, "ValidateCodeWithStep", mock.Anything, mock.Anything, mock.Anything)
			}
		})
	}
}

// A wrong-length code is a wrong code: the new validator reports it as
// invalid rather than as an error, and nothing is claimed.
func TestAuthenticateUser_WrongLengthCode_IsInvalidCode(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	auditRepo := newAuditTestRepo(t)

	totpSvc := NewTOTPService()
	key, err := totpSvc.GenerateSecret("RocketVault", "short")
	require.NoError(t, err)
	user := model.User{ID: uuid.New(), Username: "short", PasswordHash: "hashed", TOTPSecret: key.Secret(), Roles: []string{model.RoleUser}}

	userRepo := &MockUserRepository{}
	pwd := &MockPasswordService{}
	steps := &MockTOTPStepRepository{}
	sessionRepo := &MockSessionRepository{}
	userRepo.On("ReadByUsername", ctx, "short").Return(user, nil)
	pwd.On("ValidatePassword", "pass", "hashed").Return(nil)

	svc := NewAuthenticationService(AuthenticationConfig{
		UserRepository: userRepo, SessionRepository: sessionRepo, PasswordService: pwd,
		TOTPService: totpSvc, JWTService: &MockJWTService{}, TOTPStepRepository: steps,
		Logger: logging.InitLogger(), AuditService: auditServices.NewAuditService(auditRepo),
	})
	_, err = svc.AuthenticateUser(ctx, "short", "pass", "12345")

	require.Error(t, err)
	assert.Equal(t, invalidTOTPCodeMessage, err.Error())
	steps.AssertNotCalled(t, "ClaimTOTPStep", mock.Anything, mock.Anything, mock.Anything)
	sessionRepo.AssertNotCalled(t, "CreateSession", mock.Anything, mock.Anything)

	logs, _, err := auditRepo.QueryAuditLogs(ctx, repositories.AuditFilter{Limit: 1})
	require.NoError(t, err)
	require.NotEmpty(t, logs)
	assert.Equal(t, "invalid TOTP code", logs[0].Details)
}

// The audit trail names a replay, while the caller sees only a wrong code.
func TestAuthenticateUser_Replay_AuditSaysReplay(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	auditRepo := newAuditTestRepo(t)

	userRepo := &MockUserRepository{}
	pwd := &MockPasswordService{}
	totp := &MockTOTPService{}
	steps := &MockTOTPStepRepository{}
	user := model.User{ID: uuid.New(), Username: "audited", PasswordHash: "hashed", TOTPSecret: "secret", Roles: []string{model.RoleUser}}
	userRepo.On("ReadByUsername", ctx, "audited").Return(user, nil)
	pwd.On("ValidatePassword", "pass", "hashed").Return(nil)
	totp.On("ValidateCodeWithStep", "123456", "secret", mock.AnythingOfType("time.Time")).Return(int64(42), true, nil)
	steps.On("ClaimTOTPStep", ctx, user.ID, int64(42)).Return(false, nil)

	svc := NewAuthenticationService(AuthenticationConfig{
		UserRepository: userRepo, SessionRepository: &MockSessionRepository{}, PasswordService: pwd,
		TOTPService: totp, JWTService: &MockJWTService{}, TOTPStepRepository: steps,
		Logger: logging.InitLogger(), AuditService: auditServices.NewAuditService(auditRepo),
	})
	_, err := svc.AuthenticateUser(ctx, "audited", "pass", "123456")
	require.Error(t, err)
	assert.Equal(t, invalidTOTPCodeMessage, err.Error())

	logs, _, err := auditRepo.QueryAuditLogs(ctx, repositories.AuditFilter{Limit: 1})
	require.NoError(t, err)
	require.NotEmpty(t, logs)
	assert.Equal(t, "failure", logs[0].Outcome)
	assert.Equal(t, "replayed TOTP code", logs[0].Details)
	assert.Equal(t, user.ID.String(), logs[0].UserID)
}
