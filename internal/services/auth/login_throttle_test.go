package auth

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"rocketvault/internal/repositories"
	"rocketvault/model"
)

// fakeFailureRepo is an in-memory LoginFailureRepositoryInterface with the
// same stale-restart rule as the SQL upsert.
type fakeFailureRepo struct {
	mu     sync.Mutex
	rows   map[string]*model.LoginFailure
	getErr error
}

func newFakeFailureRepo() *fakeFailureRepo {
	return &fakeFailureRepo{rows: map[string]*model.LoginFailure{}}
}

func (f *fakeFailureRepo) Get(_ context.Context, u string) (*model.LoginFailure, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.getErr != nil {
		return nil, f.getErr
	}
	if r, ok := f.rows[u]; ok {
		c := *r
		return &c, nil
	}
	return nil, repositories.ErrNotFound
}

func (f *fakeFailureRepo) RecordFailure(_ context.Context, u string, at, staleBefore time.Time) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if r, ok := f.rows[u]; ok {
		if r.LastFailureAt.Before(staleBefore) {
			r.Failures = 1
		} else {
			r.Failures++
		}
		r.LastFailureAt = at
		return nil
	}
	f.rows[u] = &model.LoginFailure{Username: u, Failures: 1, LastFailureAt: at}
	return nil
}

func (f *fakeFailureRepo) Delete(_ context.Context, u string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.rows, u)
	return nil
}

func (f *fakeFailureRepo) DeleteOlderThan(_ context.Context, cutoff time.Time) (int64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var n int64
	for k, r := range f.rows {
		if r.LastFailureAt.Before(cutoff) {
			delete(f.rows, k)
			n++
		}
	}
	return n, nil
}

type throttleClock struct{ t time.Time }

func (c *throttleClock) now() time.Time { return c.t }

func TestLoginDelay(t *testing.T) {
	t.Parallel()
	assert.Equal(t, time.Duration(0), loginDelay(0))
	assert.Equal(t, time.Duration(0), loginDelay(5))
	assert.Equal(t, 2*time.Second, loginDelay(6))
	assert.Equal(t, 4*time.Second, loginDelay(7))
	assert.Equal(t, 512*time.Second, loginDelay(14))
	assert.Equal(t, 15*time.Minute, loginDelay(15))
	assert.Equal(t, 15*time.Minute, loginDelay(10_000), "no shift overflow at huge counts")
}

func TestLoginThrottle_FreeAttemptsThenBackoff(t *testing.T) {
	t.Parallel()
	clk := &throttleClock{t: time.Unix(1_700_000_000, 0)}
	th := NewLoginThrottle(newFakeFailureRepo(), clk.now)
	ctx := context.Background()

	for i := 0; i < 5; i++ {
		require.NoError(t, th.Check(ctx, "Alice"))
		th.RecordFailure(ctx, "Alice")
	}
	err := th.Check(ctx, "alice") // Case-insensitive key; 5 failures are still free.
	require.NoError(t, err)

	th.RecordFailure(ctx, "alice") // Sixth failure: 2s wait.
	err = th.Check(ctx, "alice")
	require.ErrorIs(t, err, ErrLoginThrottled)
	var te *ThrottledError
	require.True(t, errors.As(err, &te))
	assert.Equal(t, 2*time.Second, te.RetryAfter)

	clk.t = clk.t.Add(2 * time.Second)
	assert.NoError(t, th.Check(ctx, "alice"), "the throttle is a delay, not a lock")
}

func TestLoginThrottle_AttemptsDuringWindowDoNotGrowCounter(t *testing.T) {
	t.Parallel()
	clk := &throttleClock{t: time.Unix(1_700_000_000, 0)}
	repo := newFakeFailureRepo()
	th := NewLoginThrottle(repo, clk.now)
	ctx := context.Background()
	for i := 0; i < 6; i++ {
		th.RecordFailure(ctx, "admin")
	}
	for i := 0; i < 100; i++ {
		require.ErrorIs(t, th.Check(ctx, "admin"), ErrLoginThrottled)
	}
	row, err := repo.Get(ctx, "admin")
	require.NoError(t, err)
	assert.Equal(t, 6, row.Failures, "Check must never write")

	clk.t = clk.t.Add(2 * time.Second)
	assert.NoError(t, th.Check(ctx, "admin"), "hammering during the window must not push it out")
}

func TestLoginThrottle_StaleCounterIsIgnoredAndResetClears(t *testing.T) {
	t.Parallel()
	clk := &throttleClock{t: time.Unix(1_700_000_000, 0)}
	repo := newFakeFailureRepo()
	th := NewLoginThrottle(repo, clk.now)
	ctx := context.Background()
	for i := 0; i < 8; i++ {
		th.RecordFailure(ctx, "bob")
	}
	clk.t = clk.t.Add(25 * time.Hour)
	assert.NoError(t, th.Check(ctx, "bob"))
	th.RecordFailure(ctx, "bob") // A stale row restarts at 1, not 9.
	row, err := repo.Get(ctx, "bob")
	require.NoError(t, err)
	assert.Equal(t, 1, row.Failures)

	th.Reset(ctx, "bob")
	_, err = repo.Get(ctx, "bob")
	assert.ErrorIs(t, err, repositories.ErrNotFound)
}

// RecordFailure prunes rows past the reset age, which bounds the table under
// username spraying.
func TestLoginThrottle_RecordFailurePrunesStaleRows(t *testing.T) {
	t.Parallel()
	clk := &throttleClock{t: time.Unix(1_700_000_000, 0)}
	repo := newFakeFailureRepo()
	th := NewLoginThrottle(repo, clk.now)
	ctx := context.Background()
	th.RecordFailure(ctx, "sprayed-1")
	th.RecordFailure(ctx, "sprayed-2")

	clk.t = clk.t.Add(25 * time.Hour)
	th.RecordFailure(ctx, "fresh")

	assert.Len(t, repo.rows, 1)
	assert.Contains(t, repo.rows, "fresh")
}

func TestLoginThrottle_KeyIsNormalizedAndCapped(t *testing.T) {
	t.Parallel()
	repo := newFakeFailureRepo()
	th := NewLoginThrottle(repo, time.Now)
	ctx := context.Background()
	th.RecordFailure(ctx, strings.Repeat("x", 500))
	th.RecordFailure(ctx, "  Carol \t")
	for k := range repo.rows {
		assert.LessOrEqual(t, len(k), 64)
	}
	assert.Contains(t, repo.rows, "carol", "case and surrounding whitespace must not split the counter")
}

// A key cut at 64 bytes must stay valid UTF-8, so a multi-byte name never
// produces a broken key.
func TestLoginThrottle_KeyCapKeepsValidUTF8(t *testing.T) {
	t.Parallel()
	key := throttleKey(strings.Repeat("é", 100))
	assert.LessOrEqual(t, len(key), 64)
	assert.True(t, strings.HasPrefix(strings.Repeat("é", 100), key))
}

// A storage error on lookup fails open. The per-IP limiter still applies,
// and a database outage already fails the login itself.
func TestLoginThrottle_LookupErrorFailsOpen(t *testing.T) {
	t.Parallel()
	repo := newFakeFailureRepo()
	repo.getErr = errors.New("database is locked")
	th := NewLoginThrottle(repo, time.Now)
	assert.NoError(t, th.Check(context.Background(), "alice"))
}

// The retry layer must never repeat a throttled login.
func TestThrottledError_IsNotRetryable(t *testing.T) {
	t.Parallel()
	err := &ThrottledError{RetryAfter: time.Second}
	assert.False(t, err.Retryable())
	assert.Equal(t, "too many failed login attempts; retry in 1s", err.Error())
}
