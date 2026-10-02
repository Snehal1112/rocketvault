package retry

import (
	"errors"
	"testing"
	"time"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"

	internalRetry "rocketvault/internal/retry"
	"rocketvault/internal/services/auth"
)

// ---------------------------------------------------------------------------
// Circuit breaker wiring tests (internal/services/retry/retry_service.go).
//
// These prove RetryService actually constructs and uses internal/retry's
// CircuitBreaker per policy type, rather than silently ignoring the
// retry.circuit_breaker YAML block.
// ---------------------------------------------------------------------------

// newCircuitBreakerTestViper builds a viper config with fast, deterministic
// retry policies (max_attempts=1, negligible delay) so each
// Execute*Operation call maps to exactly one pass through its circuit
// breaker, and a short breaker timeout so half-open tests don't slow down
// the suite.
func newCircuitBreakerTestViper(failureThreshold, halfOpenRequests int, cbTimeout time.Duration) *viper.Viper {
	v := viper.New()

	for _, prefix := range []string{"retry.database", "retry.external_services", "retry.service_operations"} {
		v.Set(prefix+".enabled", true)
		v.Set(prefix+".max_attempts", 1)
		v.Set(prefix+".initial_delay", "1ms")
		v.Set(prefix+".max_delay", "1ms")
		v.Set(prefix+".backoff_multiplier", 1.0)
		v.Set(prefix+".jitter_enabled", false)
	}

	v.Set("retry.circuit_breaker.failure_threshold", failureThreshold)
	v.Set("retry.circuit_breaker.timeout", cbTimeout.String())
	v.Set("retry.circuit_breaker.half_open_requests", halfOpenRequests)

	return v
}

// (a) Breaker trips after failure_threshold consecutive failures, and while
// open, subsequent calls fail fast with the circuit-open error WITHOUT
// invoking the wrapped operation at all.
func TestRetryService_CircuitBreaker_TripsAndShortCircuits(t *testing.T) {
	v := newCircuitBreakerTestViper(2, 1, time.Hour) // long timeout: won't accidentally half-open mid-test
	svc, err := NewRetryService(v)
	assert.NoError(t, err)

	callCount := 0
	failingOp := func() error {
		callCount++
		return errors.New("boom")
	}

	// First failureThreshold calls actually invoke the operation and fail.
	for i := 0; i < 2; i++ {
		execErr := svc.ExecuteDatabaseOperation(ctx, failingOp)
		assert.Error(t, execErr)
	}
	assert.Equal(t, 2, callCount, "operation should have been called for each failure leading up to the threshold")

	// Breaker is now open. The next call must fail fast with
	// ErrCircuitBreakerOpen and must NOT invoke the operation.
	execErr := svc.ExecuteDatabaseOperation(ctx, failingOp)
	assert.ErrorIs(t, execErr, internalRetry.ErrCircuitBreakerOpen)
	assert.Equal(t, 2, callCount, "operation must not be called while the circuit breaker is open")

	// Call again for good measure - still short-circuited.
	execErr = svc.ExecuteDatabaseOperation(ctx, failingOp)
	assert.ErrorIs(t, execErr, internalRetry.ErrCircuitBreakerOpen)
	assert.Equal(t, 2, callCount)
}

// (b) After the configured Timeout elapses, a call is allowed through again
// (the breaker transitions to half-open and, on success, closes).
func TestRetryService_CircuitBreaker_HalfOpensAfterTimeout(t *testing.T) {
	shortTimeout := 30 * time.Millisecond
	v := newCircuitBreakerTestViper(1, 1, shortTimeout)
	svc, err := NewRetryService(v)
	assert.NoError(t, err)

	callCount := 0

	// Trip the breaker with a single failure (threshold=1).
	execErr := svc.ExecuteDatabaseOperation(ctx, func() error {
		callCount++
		return errors.New("boom")
	})
	assert.Error(t, execErr)
	assert.Equal(t, 1, callCount)

	// Immediately retrying should short-circuit - breaker is open.
	execErr = svc.ExecuteDatabaseOperation(ctx, func() error {
		callCount++
		return nil
	})
	assert.ErrorIs(t, execErr, internalRetry.ErrCircuitBreakerOpen)
	assert.Equal(t, 1, callCount, "operation must not run while open, even if it would have succeeded")

	// Wait out the breaker timeout so it becomes eligible for half-open.
	time.Sleep(shortTimeout + 20*time.Millisecond)

	// This call should now be let through (half-open trial) and, since it
	// succeeds and half_open_requests=1, the breaker closes.
	execErr = svc.ExecuteDatabaseOperation(ctx, func() error {
		callCount++
		return nil
	})
	assert.NoError(t, execErr)
	assert.Equal(t, 2, callCount, "operation must run once the timeout has elapsed (half-open trial)")

	// Breaker should be closed again now - further calls execute normally.
	execErr = svc.ExecuteDatabaseOperation(ctx, func() error {
		callCount++
		return nil
	})
	assert.NoError(t, execErr)
	assert.Equal(t, 3, callCount)
}

// (c) The three breakers (database, external services, service operations)
// are genuinely independent: tripping the database breaker must not affect
// the external services breaker's state.
func TestRetryService_CircuitBreaker_IndependentPerPolicy(t *testing.T) {
	// failure_threshold=1 so a single database failure trips only the
	// database breaker.
	v := newCircuitBreakerTestViper(1, 1, time.Hour)
	svc, err := NewRetryService(v)
	assert.NoError(t, err)

	dbCallCount := 0
	extCallCount := 0
	svcCallCount := 0

	// Trip the database breaker.
	execErr := svc.ExecuteDatabaseOperation(ctx, func() error {
		dbCallCount++
		return errors.New("db down")
	})
	assert.Error(t, execErr)
	assert.Equal(t, 1, dbCallCount)

	// Database breaker is now open - confirm short-circuit.
	execErr = svc.ExecuteDatabaseOperation(ctx, func() error {
		dbCallCount++
		return nil
	})
	assert.ErrorIs(t, execErr, internalRetry.ErrCircuitBreakerOpen)
	assert.Equal(t, 1, dbCallCount, "database operation must not run while its breaker is open")

	// External services breaker must be unaffected - a call goes through
	// and succeeds normally.
	execErr = svc.ExecuteExternalServiceOperation(ctx, func() error {
		extCallCount++
		return nil
	})
	assert.NoError(t, execErr, "external services breaker must be independent of the database breaker's open state")
	assert.Equal(t, 1, extCallCount)

	// Service operations breaker must likewise be unaffected.
	execErr = svc.ExecuteServiceOperation(ctx, func() error {
		svcCallCount++
		return nil
	})
	assert.NoError(t, execErr, "service operations breaker must be independent of the database breaker's open state")
	assert.Equal(t, 1, svcCallCount)

	// And an external failure trips only the external breaker.
	execErr = svc.ExecuteExternalServiceOperation(ctx, func() error {
		extCallCount++
		return errors.New("external down")
	})
	assert.Error(t, execErr)
	assert.Equal(t, 2, extCallCount)

	execErr = svc.ExecuteExternalServiceOperation(ctx, func() error {
		extCallCount++
		return nil
	})
	assert.ErrorIs(t, execErr, internalRetry.ErrCircuitBreakerOpen)
	assert.Equal(t, 2, extCallCount, "external operation must not run while its breaker is open")

	// Service operations breaker should still be untouched.
	execErr = svc.ExecuteServiceOperation(ctx, func() error {
		svcCallCount++
		return nil
	})
	assert.NoError(t, execErr)
	assert.Equal(t, 2, svcCallCount)
}

// ---------------------------------------------------------------------------
// B90: client outcomes must not open the shared database breaker.
// ---------------------------------------------------------------------------

// A flood of invalid credentials, invalid tokens and throttled logins never
// opens the database breaker, with the policy enabled or disabled, and a
// following real operation still runs.
func TestRetryService_DatabaseBreaker_IgnoresClientOutcomes(t *testing.T) {
	for _, enabled := range []bool{true, false} {
		v := newCircuitBreakerTestViper(5, 1, time.Hour)
		v.Set("retry.database.enabled", enabled)
		svc, err := NewRetryService(v)
		assert.NoError(t, err)

		clientErrs := []error{
			internalRetry.ClientError(errors.New("invalid credentials")),
			internalRetry.ClientError(errors.New("invalid session: token is malformed")),
			&auth.ThrottledError{RetryAfter: time.Minute},
		}
		for i := 0; i < 30; i++ {
			execErr := svc.ExecuteDatabaseOperation(ctx, func() error { return clientErrs[i%len(clientErrs)] })
			assert.True(t, internalRetry.IsClientError(execErr), "enabled=%v: got %v", enabled, execErr)
		}

		ran := false
		execErr := svc.ExecuteDatabaseOperation(ctx, func() error { ran = true; return nil })
		assert.NoError(t, execErr, "enabled=%v", enabled)
		assert.True(t, ran, "enabled=%v: client outcomes must leave the breaker closed", enabled)
	}
}

// Real database errors still open the breaker, retryable or not, with the
// policy enabled or disabled.
func TestRetryService_DatabaseBreaker_StillOpensOnInfrastructureErrors(t *testing.T) {
	for _, enabled := range []bool{true, false} {
		for _, infraErr := range []error{
			errors.New("dial tcp: connection refused"),
			errors.New("sql: database is closed"),
			internalRetry.NonRetryable(errors.New("failed to create session: disk I/O error")),
		} {
			v := newCircuitBreakerTestViper(5, 1, time.Hour)
			v.Set("retry.database.enabled", enabled)
			svc, err := NewRetryService(v)
			assert.NoError(t, err)

			for i := 0; i < 5; i++ {
				_ = svc.ExecuteDatabaseOperation(ctx, func() error { return infraErr })
			}
			execErr := svc.ExecuteDatabaseOperation(ctx, func() error { return nil })
			assert.ErrorIs(t, execErr, internalRetry.ErrCircuitBreakerOpen, "enabled=%v err=%v", enabled, infraErr)
		}
	}
}
