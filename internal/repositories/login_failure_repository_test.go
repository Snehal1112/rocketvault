package repositories_test

import (
	"context"
	"database/sql"
	"path/filepath"
	"sync"
	"testing"
	"time"

	_ "github.com/mattn/go-sqlite3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	rvdb "rocketvault/internal/db"
	"rocketvault/internal/repositories"
)

// setupLoginFailureDB opens a file-backed SQLite database with several pooled
// connections, so concurrent writers genuinely contend for the same row.
func setupLoginFailureDB(t *testing.T) *sql.DB {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "login-failures.db")
	db, err := sql.Open("sqlite3", "file:"+dbPath+"?_busy_timeout=10000&_journal_mode=WAL")
	require.NoError(t, err)
	db.SetMaxOpenConns(8)
	_, err = db.ExecContext(context.Background(), `CREATE TABLE login_failures (
		username        TEXT PRIMARY KEY,
		failures        INTEGER NOT NULL,
		last_failure_at TIMESTAMP NOT NULL
	)`)
	require.NoError(t, err)
	t.Cleanup(func() { db.Close() }) //nolint:errcheck,gosec
	return db
}

func TestLoginFailureRepository_RecordGetDelete(t *testing.T) {
	t.Parallel()
	repo := repositories.NewLoginFailureRepository(rvdb.NewConn(setupLoginFailureDB(t), rvdb.SQLite))
	ctx := context.Background()
	t0 := time.Now().UTC().Truncate(time.Second)
	stale := t0.Add(-24 * time.Hour)

	_, err := repo.Get(ctx, "alice")
	assert.ErrorIs(t, err, repositories.ErrNotFound)

	require.NoError(t, repo.RecordFailure(ctx, "alice", t0, stale))
	require.NoError(t, repo.RecordFailure(ctx, "alice", t0.Add(time.Second), stale))
	got, err := repo.Get(ctx, "alice")
	require.NoError(t, err)
	assert.Equal(t, "alice", got.Username)
	assert.Equal(t, 2, got.Failures)
	assert.True(t, got.LastFailureAt.Equal(t0.Add(time.Second)), "got %s", got.LastFailureAt)

	require.NoError(t, repo.Delete(ctx, "alice"))
	_, err = repo.Get(ctx, "alice")
	assert.ErrorIs(t, err, repositories.ErrNotFound)
}

// A row whose last failure predates staleBefore restarts at one in the same
// statement that records the new failure.
func TestLoginFailureRepository_StaleRowRestartsAtOne(t *testing.T) {
	t.Parallel()
	repo := repositories.NewLoginFailureRepository(rvdb.NewConn(setupLoginFailureDB(t), rvdb.SQLite))
	ctx := context.Background()
	t0 := time.Now().UTC().Truncate(time.Second)

	for i := 0; i < 8; i++ {
		require.NoError(t, repo.RecordFailure(ctx, "bob", t0, t0.Add(-24*time.Hour)))
	}
	later := t0.Add(25 * time.Hour)
	require.NoError(t, repo.RecordFailure(ctx, "bob", later, later.Add(-24*time.Hour)))

	got, err := repo.Get(ctx, "bob")
	require.NoError(t, err)
	assert.Equal(t, 1, got.Failures, "a stale counter must restart, not continue at 9")
	assert.True(t, got.LastFailureAt.Equal(later))
}

// Concurrent failures for one account must all be counted.
func TestLoginFailureRepository_ConcurrentFailuresAreNotUndercounted(t *testing.T) {
	t.Parallel()
	repo := repositories.NewLoginFailureRepository(rvdb.NewConn(setupLoginFailureDB(t), rvdb.SQLite))
	ctx := context.Background()
	now := time.Now().UTC()

	const racers = 16
	var (
		wg    sync.WaitGroup
		start = make(chan struct{})
		errs  = make(chan error, racers)
	)
	for i := 0; i < racers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			errs <- repo.RecordFailure(ctx, "racer", now, now.Add(-24*time.Hour))
		}()
	}
	close(start)
	wg.Wait()
	close(errs)
	for err := range errs {
		require.NoError(t, err)
	}

	got, err := repo.Get(ctx, "racer")
	require.NoError(t, err)
	assert.Equal(t, racers, got.Failures)
}

func TestLoginFailureRepository_DeleteOlderThan(t *testing.T) {
	t.Parallel()
	repo := repositories.NewLoginFailureRepository(rvdb.NewConn(setupLoginFailureDB(t), rvdb.SQLite))
	ctx := context.Background()
	now := time.Now().UTC()
	stale := now.Add(-72 * time.Hour)
	require.NoError(t, repo.RecordFailure(ctx, "old", now.Add(-48*time.Hour), stale))
	require.NoError(t, repo.RecordFailure(ctx, "new", now, stale))

	n, err := repo.DeleteOlderThan(ctx, now.Add(-24*time.Hour))
	require.NoError(t, err)
	assert.EqualValues(t, 1, n)
	_, err = repo.Get(ctx, "old")
	assert.ErrorIs(t, err, repositories.ErrNotFound)
	_, err = repo.Get(ctx, "new")
	assert.NoError(t, err)
}

// Times in another zone are stored as UTC, so comparisons against the stored
// text stay correct on SQLite.
func TestLoginFailureRepository_NonUTCTimesCompareCorrectly(t *testing.T) {
	t.Parallel()
	repo := repositories.NewLoginFailureRepository(rvdb.NewConn(setupLoginFailureDB(t), rvdb.SQLite))
	ctx := context.Background()
	zone := time.FixedZone("UTC+5", 5*3600)
	now := time.Now().In(zone)
	require.NoError(t, repo.RecordFailure(ctx, "zoned", now.Add(-2*time.Hour), now.Add(-24*time.Hour)))

	n, err := repo.DeleteOlderThan(ctx, now.Add(-time.Hour).UTC())
	require.NoError(t, err)
	assert.EqualValues(t, 1, n, "a failure two hours old must be older than a one-hour cutoff")
}
