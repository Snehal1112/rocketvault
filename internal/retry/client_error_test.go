package retry

import (
	"context"
	"errors"
	"testing"
	"time"
)

// countUnlessClient is the classifier the database breaker uses.
func countUnlessClient(err error) bool { return !IsClientError(err) }

func TestClientError_WrapsAndClassifies(t *testing.T) {
	cause := errors.New("invalid credentials")
	err := ClientError(cause)

	if err.Error() != "invalid credentials" {
		t.Fatalf("message changed: %q", err.Error())
	}
	if !errors.Is(err, cause) {
		t.Fatal("ClientError must unwrap to its cause")
	}
	if !IsClientError(err) {
		t.Fatal("IsClientError must recognise a ClientError")
	}
	if !IsClientError(errors.Join(errors.New("context"), err)) {
		t.Fatal("IsClientError must look through wrapping")
	}
	if IsClientError(errors.New("connection refused")) {
		t.Fatal("a plain error is not a client error")
	}
	if IsClientError(NonRetryable(errors.New("disk full"))) {
		t.Fatal("NonRetryable alone does not make an error a client error")
	}
	if ClientError(nil) != nil {
		t.Fatal("ClientError(nil) must be nil")
	}
}

// A client error is returned on the first attempt, never retried.
func TestClientError_IsNotRetried(t *testing.T) {
	policy := Policy{
		Enabled: true, MaxAttempts: 3, InitialDelay: time.Millisecond, MaxDelay: time.Millisecond,
		BackoffMultiplier: 1, RetryableErrors: []string{"invalid"},
	}
	calls := 0
	err := WithExponentialBackoff(context.Background(), policy, func() error {
		calls++
		return ClientError(errors.New("invalid credentials"))
	})
	if calls != 1 {
		t.Fatalf("client error was retried: %d calls", calls)
	}
	if !IsClientError(err) {
		t.Fatal("the client error must survive the retry wrapping")
	}
}

// A flood of client errors never opens the breaker; a flood of other errors does.
func TestCircuitBreaker_ExecuteClassified_IgnoresClientErrors(t *testing.T) {
	cb := NewCircuitBreaker(CircuitBreakerConfig{FailureThreshold: 3, Timeout: time.Hour, HalfOpenRequests: 1})
	for i := 0; i < 50; i++ {
		_ = cb.ExecuteClassified(func() error { return ClientError(errors.New("invalid token")) }, countUnlessClient)
	}
	if cb.GetState() != StateClosed {
		t.Fatal("client errors must not open the breaker")
	}

	for i := 0; i < 3; i++ {
		_ = cb.ExecuteClassified(func() error { return errors.New("connection refused") }, countUnlessClient)
	}
	if cb.GetState() != StateOpen {
		t.Fatal("infrastructure errors must still open the breaker")
	}
}

// Client errors between infrastructure failures do not reset the count, so an
// attacker cannot keep a failing database looking healthy.
func TestCircuitBreaker_ExecuteClassified_ClientErrorsDoNotResetCount(t *testing.T) {
	cb := NewCircuitBreaker(CircuitBreakerConfig{FailureThreshold: 3, Timeout: time.Hour, HalfOpenRequests: 1})
	for i := 0; i < 3; i++ {
		_ = cb.ExecuteClassified(func() error { return errors.New("connection refused") }, countUnlessClient)
		_ = cb.ExecuteClassified(func() error { return ClientError(errors.New("invalid token")) }, countUnlessClient)
	}
	if cb.GetState() != StateOpen {
		t.Fatal("interleaved client errors must not hide infrastructure failures")
	}
}

// openThenWait trips cb with one counted failure and waits out its timeout,
// so the next call is a half-open trial.
func openThenWait(t *testing.T, cb *CircuitBreaker) {
	t.Helper()
	_ = cb.ExecuteClassified(func() error { return errors.New("connection refused") }, countUnlessClient)
	if cb.GetState() != StateOpen {
		t.Fatal("breaker should be open")
	}
	time.Sleep(20 * time.Millisecond)
}

// A client error during a half-open trial proves nothing about the backend,
// because a bad token is rejected before any database call. It must neither
// close nor reopen the breaker; it only releases its trial slot.
func TestCircuitBreaker_ExecuteClassified_HalfOpenClientErrorDoesNotClose(t *testing.T) {
	cb := NewCircuitBreaker(CircuitBreakerConfig{FailureThreshold: 1, Timeout: 10 * time.Millisecond, HalfOpenRequests: 1})
	openThenWait(t, cb)

	err := cb.ExecuteClassified(func() error { return ClientError(errors.New("invalid token")) }, countUnlessClient)
	if !IsClientError(err) {
		t.Fatalf("the client error must be returned, got %v", err)
	}
	if cb.GetState() != StateHalfOpen {
		t.Fatalf("a client error in the half-open trial must leave the breaker half-open, got %v", cb.GetState())
	}
	cb.mu.RLock()
	failures, slots := cb.failures, cb.halfOpenCount
	cb.mu.RUnlock()
	if failures != 1 {
		t.Fatalf("a client error must not change the failure count, got %d", failures)
	}
	if slots != 0 {
		t.Fatalf("a client error must release its trial slot, got %d held", slots)
	}
}

// After a released slot, a real success still closes the breaker.
func TestCircuitBreaker_ExecuteClassified_HalfOpenSlotReleasedThenSuccessCloses(t *testing.T) {
	cb := NewCircuitBreaker(CircuitBreakerConfig{FailureThreshold: 1, Timeout: 10 * time.Millisecond, HalfOpenRequests: 1})
	openThenWait(t, cb)

	_ = cb.ExecuteClassified(func() error { return ClientError(errors.New("invalid token")) }, countUnlessClient)
	if err := cb.ExecuteClassified(func() error { return nil }, countUnlessClient); err != nil {
		t.Fatalf("the trial after a released slot must be admitted, got %v", err)
	}
	if cb.GetState() != StateClosed {
		t.Fatal("a real success in the half-open trial must close the breaker")
	}
}

// Many client errors in half-open never close or reopen the breaker and never
// use up the trial slots.
func TestCircuitBreaker_ExecuteClassified_HalfOpenClientErrorsNeverExhaustSlots(t *testing.T) {
	cb := NewCircuitBreaker(CircuitBreakerConfig{FailureThreshold: 1, Timeout: 10 * time.Millisecond, HalfOpenRequests: 2})
	openThenWait(t, cb)

	for i := 0; i < 50; i++ {
		err := cb.ExecuteClassified(func() error { return ClientError(errors.New("invalid token")) }, countUnlessClient)
		if errors.Is(err, ErrCircuitBreakerOpen) {
			t.Fatalf("call %d was refused: client errors must not exhaust the trial slots", i)
		}
		if cb.GetState() != StateHalfOpen {
			t.Fatalf("call %d moved the breaker to %v", i, cb.GetState())
		}
	}
}

// A real error in half-open reopens the breaker.
func TestCircuitBreaker_ExecuteClassified_HalfOpenRealErrorReopens(t *testing.T) {
	cb := NewCircuitBreaker(CircuitBreakerConfig{FailureThreshold: 1, Timeout: 10 * time.Millisecond, HalfOpenRequests: 1})
	openThenWait(t, cb)

	_ = cb.ExecuteClassified(func() error { return errors.New("connection refused") }, countUnlessClient)
	if cb.GetState() != StateOpen {
		t.Fatal("a real error in the half-open trial must reopen the breaker")
	}
}

// A real success in half-open closes the breaker.
func TestCircuitBreaker_ExecuteClassified_HalfOpenSuccessCloses(t *testing.T) {
	cb := NewCircuitBreaker(CircuitBreakerConfig{FailureThreshold: 1, Timeout: 10 * time.Millisecond, HalfOpenRequests: 1})
	openThenWait(t, cb)

	if err := cb.ExecuteClassified(func() error { return nil }, countUnlessClient); err != nil {
		t.Fatal(err)
	}
	if cb.GetState() != StateClosed {
		t.Fatal("a real success in the half-open trial must close the breaker")
	}
}

// A nil classifier counts every error, exactly like Execute.
func TestCircuitBreaker_ExecuteClassified_NilClassifierCountsAll(t *testing.T) {
	cb := NewCircuitBreaker(CircuitBreakerConfig{FailureThreshold: 2, Timeout: time.Hour, HalfOpenRequests: 1})
	for i := 0; i < 2; i++ {
		_ = cb.ExecuteClassified(func() error { return ClientError(errors.New("invalid token")) }, nil)
	}
	if cb.GetState() != StateOpen {
		t.Fatal("a nil classifier must count every error")
	}
}
