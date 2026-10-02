package repositories_test

import (
	"context"
	"database/sql"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	rvdb "rocketvault/internal/db"
	"rocketvault/internal/repositories"
	"rocketvault/model"
)

func TestTOTPStepRepository_ClaimTOTPStep(t *testing.T) {
	t.Parallel()
	db := setupUserDB(t)
	conn := rvdb.NewConn(db, rvdb.SQLite)
	users := repositories.NewUserRepository(conn, newLogger())
	steps := repositories.NewTOTPStepRepository(conn)
	ctx := context.Background()

	u := newUser("stepper", model.RoleUser)
	require.NoError(t, users.Create(ctx, u))

	claimed, err := steps.ClaimTOTPStep(ctx, u.ID, 100)
	require.NoError(t, err)
	assert.True(t, claimed, "the first use of a step must be accepted")

	claimed, err = steps.ClaimTOTPStep(ctx, u.ID, 100)
	require.NoError(t, err)
	assert.False(t, claimed, "the same step must not be accepted twice")

	claimed, err = steps.ClaimTOTPStep(ctx, u.ID, 99)
	require.NoError(t, err)
	assert.False(t, claimed, "an older step must be rejected")

	claimed, err = steps.ClaimTOTPStep(ctx, u.ID, 101)
	require.NoError(t, err)
	assert.True(t, claimed, "a newer step must be accepted")

	var stored int64
	require.NoError(t, db.QueryRowContext(ctx, "SELECT totp_last_step FROM users WHERE id = ?", u.ID.String()).Scan(&stored))
	assert.Equal(t, int64(101), stored, "the stored step must be the newest accepted one")
}

func TestTOTPStepRepository_ClaimTOTPStep_UnknownUser(t *testing.T) {
	t.Parallel()
	db := setupUserDB(t)
	steps := repositories.NewTOTPStepRepository(rvdb.NewConn(db, rvdb.SQLite))

	claimed, err := steps.ClaimTOTPStep(context.Background(), uuid.New(), 100)
	require.NoError(t, err)
	assert.False(t, claimed, "a missing user can never claim a step")
}

// A claim for one user must not move another user's step.
func TestTOTPStepRepository_ClaimTOTPStep_IsPerUser(t *testing.T) {
	t.Parallel()
	db := setupUserDB(t)
	conn := rvdb.NewConn(db, rvdb.SQLite)
	users := repositories.NewUserRepository(conn, newLogger())
	steps := repositories.NewTOTPStepRepository(conn)
	ctx := context.Background()

	alice := newUser("alice-step", model.RoleUser)
	bob := newUser("bob-step", model.RoleUser)
	require.NoError(t, users.Create(ctx, alice))
	require.NoError(t, users.Create(ctx, bob))

	claimed, err := steps.ClaimTOTPStep(ctx, alice.ID, 500)
	require.NoError(t, err)
	require.True(t, claimed)

	claimed, err = steps.ClaimTOTPStep(ctx, bob.ID, 500)
	require.NoError(t, err)
	assert.True(t, claimed, "another user's claim must not consume this user's step")
}

// Steps beyond the 32-bit range must round-trip on SQLite. Postgres uses BIGINT
// for this column, which the Postgres integration test covers.
func TestTOTPStepRepository_ClaimTOTPStep_LargeStep(t *testing.T) {
	t.Parallel()
	db := setupUserDB(t)
	conn := rvdb.NewConn(db, rvdb.SQLite)
	users := repositories.NewUserRepository(conn, newLogger())
	steps := repositories.NewTOTPStepRepository(conn)
	ctx := context.Background()

	u := newUser("big-step", model.RoleUser)
	require.NoError(t, users.Create(ctx, u))

	const big = int64(1) << 40
	claimed, err := steps.ClaimTOTPStep(ctx, u.ID, big)
	require.NoError(t, err)
	require.True(t, claimed)

	claimed, err = steps.ClaimTOTPStep(ctx, u.ID, big-1)
	require.NoError(t, err)
	assert.False(t, claimed, "a step below a large stored step must be rejected")
}

// Many logins racing with the same code must produce exactly one success. The
// database is a real file with several pooled connections, so the goroutines
// genuinely contend for the row.
func TestTOTPStepRepository_ClaimTOTPStep_ConcurrentSameStep(t *testing.T) {
	t.Parallel()
	dbPath := filepath.Join(t.TempDir(), "totp-step.db")
	sqlDB, err := sql.Open("sqlite3", "file:"+dbPath+"?_busy_timeout=10000&_journal_mode=WAL")
	require.NoError(t, err)
	t.Cleanup(func() { sqlDB.Close() }) //nolint:errcheck,gosec
	sqlDB.SetMaxOpenConns(8)

	_, err = sqlDB.ExecContext(context.Background(), `
		CREATE TABLE users (
			id             TEXT PRIMARY KEY,
			username       TEXT UNIQUE NOT NULL,
			totp_last_step BIGINT NOT NULL DEFAULT 0
		);
	`)
	require.NoError(t, err)

	userID := uuid.New()
	_, err = sqlDB.ExecContext(context.Background(), "INSERT INTO users (id, username) VALUES (?, ?)", userID.String(), "racer")
	require.NoError(t, err)

	steps := repositories.NewTOTPStepRepository(rvdb.NewConn(sqlDB, rvdb.SQLite))

	const racers = 16
	var (
		wins  atomic.Int32
		wg    sync.WaitGroup
		start = make(chan struct{})
		errs  = make(chan error, racers)
	)
	for range racers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			claimed, claimErr := steps.ClaimTOTPStep(context.Background(), userID, 4242)
			if claimErr != nil {
				errs <- claimErr
				return
			}
			if claimed {
				wins.Add(1)
			}
		}()
	}
	close(start)
	wg.Wait()
	close(errs)

	for e := range errs {
		require.NoError(t, e)
	}
	assert.Equal(t, int32(1), wins.Load(), "exactly one racer may claim a given step")
}
