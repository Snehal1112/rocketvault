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

func (f *fakeFailureRepo) RecordFailure(ctx context.Context, u string, at, staleBefore time.Time) error {
	if err := ctx.Err(); err != nil {
		return err
	}
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

func (f *fakeFailureRepo) Delete(ctx context.Context, u string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
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
	th := NewLoginThrottle(newFakeFailureRepo(), nil, clk.now)
	ctx := context.Background()

	for i := 0; i < 5; i++ {
		require.NoError(t, th.Check(ctx, "alice"))
		th.RecordFailure(ctx, "alice")
	}
	err := th.Check(ctx, "alice") // 5 failures are still free.
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
	th := NewLoginThrottle(repo, nil, clk.now)
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
	th := NewLoginThrottle(repo, nil, clk.now)
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
	th := NewLoginThrottle(repo, nil, clk.now)
	ctx := context.Background()
	th.RecordFailure(ctx, "sprayed-1")
	th.RecordFailure(ctx, "sprayed-2")

	clk.t = clk.t.Add(25 * time.Hour)
	th.RecordFailure(ctx, "fresh")

	assert.Len(t, repo.rows, 1)
	assert.Contains(t, repo.rows, "fresh")
}

// Usernames are case and whitespace sensitive, so distinct accounts that
// differ only in case or spacing must have distinct counters.
func TestLoginThrottle_KeyIsExactUsername(t *testing.T) {
	t.Parallel()
	clk := &throttleClock{t: time.Unix(1_700_000_000, 0)}
	repo := newFakeFailureRepo()
	th := NewLoginThrottle(repo, nil, clk.now)
	ctx := context.Background()
	for i := 0; i < 6; i++ {
		th.RecordFailure(ctx, "Admin")
	}
	require.ErrorIs(t, th.Check(ctx, "Admin"), ErrLoginThrottled)
	assert.NoError(t, th.Check(ctx, "admin"), "admin is a different account from Admin")
	assert.NoError(t, th.Check(ctx, " Admin"), "a leading space names a different account")

	th.RecordFailure(ctx, "admin")
	th.Reset(ctx, "admin")
	assert.ErrorIs(t, th.Check(ctx, "Admin"), ErrLoginThrottled, "a success on admin must not reset Admin")
	assert.Equal(t, 6, repo.rows["Admin"].Failures)
}

// Names longer than the key limit are stored as a fixed-size hash of the
// whole name, so two long names that share a prefix never collide.
func TestLoginThrottle_LongNamesAreHashedWithoutCollision(t *testing.T) {
	t.Parallel()
	clk := &throttleClock{t: time.Unix(1_700_000_000, 0)}
	repo := newFakeFailureRepo()
	th := NewLoginThrottle(repo, nil, clk.now)
	ctx := context.Background()
	prefix := strings.Repeat("x", 64)
	for i := 0; i < 6; i++ {
		th.RecordFailure(ctx, prefix+"-one")
	}
	require.ErrorIs(t, th.Check(ctx, prefix+"-one"), ErrLoginThrottled)
	assert.NoError(t, th.Check(ctx, prefix+"-two"), "names sharing a 64-byte prefix must not share a counter")

	th.RecordFailure(ctx, strings.Repeat("y", 500))
	for k := range repo.rows {
		assert.LessOrEqual(t, len(k), maxThrottleKeyLen)
	}
	assert.Len(t, repo.rows, 2)
}

// A short name that looks like a hashed key is hashed as well, so it can never
// share a counter with a long name.
func TestLoginThrottle_KeyPrefixCannotBeForged(t *testing.T) {
	t.Parallel()
	long := strings.Repeat("z", 100)
	forged := throttleKey(long)
	assert.NotEqual(t, forged, throttleKey(forged))
	assert.Equal(t, "carol", throttleKey("carol"))
	assert.Equal(t, strings.Repeat("a", 64), throttleKey(strings.Repeat("a", 64)))
}

// The counter writes outlive a cancelled request, so a client that hangs up
// after a failed check still has the failure counted.
func TestLoginThrottle_WritesIgnoreRequestCancellation(t *testing.T) {
	t.Parallel()
	repo := newFakeFailureRepo()
	th := NewLoginThrottle(repo, nil, time.Now)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	th.RecordFailure(ctx, "dave")
	require.Contains(t, repo.rows, "dave", "a cancelled request must still count its failure")

	th.Reset(ctx, "dave")
	assert.NotContains(t, repo.rows, "dave", "a cancelled request must still clear the counter")
}

// A storage error on lookup fails open. The per-IP limiter still applies,
// and a database outage already fails the login itself.
func TestLoginThrottle_LookupErrorFailsOpen(t *testing.T) {
	t.Parallel()
	repo := newFakeFailureRepo()
	repo.getErr = errors.New("database is locked")
	th := NewLoginThrottle(repo, nil, time.Now)
	assert.NoError(t, th.Check(context.Background(), "alice"))
}

// The retry layer must never repeat a throttled login.
func TestThrottledError_IsNotRetryable(t *testing.T) {
	t.Parallel()
	err := &ThrottledError{RetryAfter: time.Second}
	assert.False(t, err.Retryable())
	assert.Equal(t, "too many failed login attempts; retry in 1s", err.Error())
}
