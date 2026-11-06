package retry

import (
	"errors"
	"testing"
)

func TestNonRetryable_KeepsSentinelForErrorsIs(t *testing.T) {
	sentinel := errors.New("sentinel")
	if !errors.Is(NonRetryable(sentinel), sentinel) {
		t.Fatal("errors.Is must find the sentinel behind NonRetryable")
	}
}

func TestNonRetryable_WinsOverRetryableInnerError(t *testing.T) {
	inner := errors.New("database is locked")
	if !IsRetryable(inner, DatabasePolicy()) {
		t.Fatal("precondition: the inner error must be retryable on its own")
	}
	if IsRetryable(NonRetryable(inner), DatabasePolicy()) {
		t.Fatal("NonRetryable must stop a retry even when the inner error is retryable")
	}
}
