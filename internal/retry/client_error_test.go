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

// A client error during a half-open trial shows the backend answered, so it
// closes the breaker like a success instead of reopening it.
func TestCircuitBreaker_ExecuteClassified_HalfOpenClientErrorCloses(t *testing.T) {
	cb := NewCircuitBreaker(CircuitBreakerConfig{FailureThreshold: 1, Timeout: 10 * time.Millisecond, HalfOpenRequests: 1})
	_ = cb.ExecuteClassified(func() error { return errors.New("connection refused") }, countUnlessClient)
	if cb.GetState() != StateOpen {
		t.Fatal("breaker should be open")
	}
	time.Sleep(20 * time.Millisecond)

	err := cb.ExecuteClassified(func() error { return ClientError(errors.New("invalid token")) }, countUnlessClient)
	if !IsClientError(err) {
		t.Fatalf("the client error must be returned, got %v", err)
	}
	if cb.GetState() != StateClosed {
		t.Fatal("a client error in the half-open trial must close the breaker")
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
