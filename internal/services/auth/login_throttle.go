package auth

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/sirupsen/logrus"

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
	// maxThrottleKeyLen bounds stored usernames in bytes, so spraying long
	// names cannot grow rows without limit.
	maxThrottleKeyLen = 64
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
	repo repositories.LoginFailureRepositoryInterface
	now  func() time.Time
}

// NewLoginThrottle builds a throttle; now is injectable for tests.
func NewLoginThrottle(repo repositories.LoginFailureRepositoryInterface, now func() time.Time) *LoginThrottle {
	if now == nil {
		now = time.Now
	}
	return &LoginThrottle{repo: repo, now: now}
}

// throttleKey normalizes a username to its counter key. It is lower-cased,
// trimmed and cut to maxThrottleKeyLen bytes on a rune boundary.
func throttleKey(username string) string {
	k := strings.ToLower(strings.TrimSpace(username))
	if len(k) <= maxThrottleKeyLen {
		return k
	}
	cut := maxThrottleKeyLen
	for cut > 0 && !utf8.RuneStart(k[cut]) {
		cut--
	}
	return k[:cut]
}

// Check returns a *ThrottledError while the account is inside its window.
// It never writes, so attempts made during the window cannot extend it.
// A storage error fails open: the per-IP limiter still applies.
func (t *LoginThrottle) Check(ctx context.Context, username string) error {
	row, err := t.repo.Get(ctx, throttleKey(username))
	if err != nil {
		if !errors.Is(err, repositories.ErrNotFound) {
			logrus.WithError(err).Warn("login throttle lookup failed")
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
// which keeps the table bounded under username spraying.
func (t *LoginThrottle) RecordFailure(ctx context.Context, username string) {
	now := t.now()
	staleBefore := now.Add(-loginResetAfter)
	if err := t.repo.RecordFailure(ctx, throttleKey(username), now, staleBefore); err != nil {
		logrus.WithError(err).Warn("recording login failure failed")
		return
	}
	if _, err := t.repo.DeleteOlderThan(ctx, staleBefore); err != nil {
		logrus.WithError(err).Warn("pruning stale login failures failed")
	}
}

// Reset clears the counter after a successful login.
func (t *LoginThrottle) Reset(ctx context.Context, username string) {
	if err := t.repo.Delete(ctx, throttleKey(username)); err != nil {
		logrus.WithError(err).Warn("clearing login failures failed")
	}
}
