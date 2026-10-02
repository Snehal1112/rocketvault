package auth

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"github.com/sirupsen/logrus"

	"rocketvault/internal/logging"
	"rocketvault/internal/repositories"
)

const (
	// loginFreeAttempts failures are tolerated before any wait is imposed.
	loginFreeAttempts = 5
	// loginBaseDelay is the wait after the first failure past the free ones.
	loginBaseDelay = 2 * time.Second
	// loginMaxDelay caps the wait so an attacker can never lock an account out
	// for longer than this at a time.
	loginMaxDelay = 15 * time.Minute
	// loginResetAfter forgets a counter whose last failure is this old.
	loginResetAfter = 24 * time.Hour
	// throttleKeyHashPrefix marks a key as a hash of the username.
	throttleKeyHashPrefix = "sha256:"
	// throttleWriteTimeout bounds each counter write, which is detached from
	// the request so a client cannot cancel it.
	throttleWriteTimeout = 5 * time.Second
)

// ErrLoginThrottled is returned when an account is inside its backoff window.
var ErrLoginThrottled = errors.New("too many failed login attempts")

// ThrottledError carries how long the caller must wait.
type ThrottledError struct {
	RetryAfter time.Duration
}

// Error names the wait, rounded to the second.
func (e *ThrottledError) Error() string {
	return fmt.Sprintf("%s; retry in %s", ErrLoginThrottled, e.RetryAfter.Round(time.Second))
}

// Is lets errors.Is(err, ErrLoginThrottled) match.
func (e *ThrottledError) Is(target error) bool { return target == ErrLoginThrottled }

// Retryable reports false, so the retry layer never repeats a throttled login.
func (e *ThrottledError) Retryable() bool { return false }

// ClientFault reports true: a throttled login is a client outcome, so it never
// counts toward the database circuit breaker.
func (e *ThrottledError) ClientFault() bool { return true }

// loginDelay returns the wait imposed after the given number of consecutive failures.
func loginDelay(failures int) time.Duration {
	over := failures - loginFreeAttempts
	if over <= 0 {
		return 0
	}
	// 2s << 10 already exceeds the cap; bail out before the shift can overflow.
	if over > 10 {
		return loginMaxDelay
	}
	d := loginBaseDelay << (over - 1)
	if d > loginMaxDelay {
		return loginMaxDelay
	}
	return d
}

// LoginThrottle applies exponential backoff to repeated failed logins per
// account. It is a delay, never a permanent lock.
type LoginThrottle struct {
	repo   repositories.LoginFailureRepositoryInterface
	logger *logging.Logger
	now    func() time.Time
}

// NewLoginThrottle builds a throttle. A nil logger falls back to the standard
// logrus logger, and now is injectable for tests.
func NewLoginThrottle(repo repositories.LoginFailureRepositoryInterface, logger *logging.Logger, now func() time.Time) *LoginThrottle {
	if logger == nil {
		logger = logging.WrapLogrus(logrus.StandardLogger())
	}
	if now == nil {
		now = time.Now
	}
	return &LoginThrottle{repo: repo, logger: logger, now: now}
}

// throttleKey maps a username to its counter key. The key is always a
// SHA-256 hash of the exact name, so the attempted username is never stored.
// People sometimes type a password into the username field, and the table is
// kept for a day and copied into backups. Usernames are case and whitespace
// sensitive, so the name is hashed as typed, with no folding. Every key has
// the same fixed size, and no name can forge the key of another.
func throttleKey(username string) string {
	sum := sha256.Sum256([]byte(username))
	return throttleKeyHashPrefix + base64.RawURLEncoding.EncodeToString(sum[:])
}

// Check returns a *ThrottledError while the account is inside its window.
// It never writes, so attempts made during the window cannot extend it.
// A storage error fails open: the per-IP limiter still applies.
func (t *LoginThrottle) Check(ctx context.Context, username string) error {
	row, err := t.repo.Get(ctx, throttleKey(username))
	if err != nil {
		if !errors.Is(err, repositories.ErrNotFound) {
			t.logger.WithError(err).Warn("login throttle lookup failed")
		}
		return nil
	}
	now := t.now()
	if now.Sub(row.LastFailureAt) >= loginResetAfter {
		return nil
	}
	wait := row.LastFailureAt.Add(loginDelay(row.Failures)).Sub(now)
	if wait > 0 {
		return &ThrottledError{RetryAfter: wait}
	}
	return nil
}

// RecordFailure counts one failed attempt. The repository restarts a stale
// counter in the same statement. It also prunes rows past the reset age,
// which keeps the table bounded under username spraying. The write ignores
// request cancellation, so a client that hangs up cannot dodge the count,
// and it is bounded by throttleWriteTimeout.
func (t *LoginThrottle) RecordFailure(ctx context.Context, username string) {
	ctx, cancel := detachedWriteContext(ctx)
	defer cancel()
	now := t.now()
	staleBefore := now.Add(-loginResetAfter)
	if err := t.repo.RecordFailure(ctx, throttleKey(username), now, staleBefore); err != nil {
		t.logger.WithError(err).Warn("recording login failure failed")
		return
	}
	if _, err := t.repo.DeleteOlderThan(ctx, staleBefore); err != nil {
		t.logger.WithError(err).Warn("pruning stale login failures failed")
	}
}

// Reset clears the counter after a successful login. Like RecordFailure, it
// ignores request cancellation and is bounded by throttleWriteTimeout.
func (t *LoginThrottle) Reset(ctx context.Context, username string) {
	ctx, cancel := detachedWriteContext(ctx)
	defer cancel()
	if err := t.repo.Delete(ctx, throttleKey(username)); err != nil {
		t.logger.WithError(err).Warn("clearing login failures failed")
	}
}

// detachedWriteContext keeps ctx's values but not its cancellation, and
// bounds the result by throttleWriteTimeout.
func detachedWriteContext(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.WithoutCancel(ctx), throttleWriteTimeout)
}
