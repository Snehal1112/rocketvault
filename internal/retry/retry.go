// Package retry provides retry logic with exponential backoff for resilient operations.
package retry

import (
	"context"
	"errors"
	"fmt"
	"math"
	"math/rand"
	"strings"
	"sync"
	"time"
)

// Policy defines retry behavior for different types of operations.
type Policy struct {
	Enabled           bool          `yaml:"enabled" json:"enabled"`
	MaxAttempts       int           `yaml:"max_attempts" json:"max_attempts"`
	InitialDelay      time.Duration `yaml:"initial_delay" json:"initial_delay"`
	MaxDelay          time.Duration `yaml:"max_delay" json:"max_delay"`
	BackoffMultiplier float64       `yaml:"backoff_multiplier" json:"backoff_multiplier"`
	RetryableErrors   []string      `yaml:"retryable_errors" json:"retryable_errors"`
	RetryableStatuses []int         `yaml:"retryable_statuses" json:"retryable_statuses"`
	JitterEnabled     bool          `yaml:"jitter_enabled" json:"jitter_enabled"`
}

// DefaultPolicy returns a default retry policy suitable for most operations.
func DefaultPolicy() Policy {
	return Policy{
		Enabled:           true,
		MaxAttempts:       3,
		InitialDelay:      100 * time.Millisecond,
		MaxDelay:          5 * time.Second,
		BackoffMultiplier: 2.0,
		RetryableErrors:   []string{},
		RetryableStatuses: []int{500, 502, 503, 504, 429}, // 5xx errors and rate limiting
		JitterEnabled:     true,
	}
}

// DatabasePolicy returns a retry policy optimized for database operations.
func DatabasePolicy() Policy {
	return Policy{
		Enabled:           true,
		MaxAttempts:       3,
		InitialDelay:      100 * time.Millisecond,
		MaxDelay:          5 * time.Second,
		BackoffMultiplier: 2.0,
		RetryableErrors: []string{
			"connection refused",
			"database is locked",
			"busy",
			"timeout",
			"connection reset by peer",
			"broken pipe",
		},
		JitterEnabled: true,
	}
}

// ExternalServicePolicy returns a retry policy for external HTTP services.
func ExternalServicePolicy() Policy {
	return Policy{
		Enabled:           true,
		MaxAttempts:       5,
		InitialDelay:      1 * time.Second,
		MaxDelay:          30 * time.Second,
		BackoffMultiplier: 2.0,
		RetryableErrors: []string{
			"connection refused",
			"no such host",
			"timeout",
			"temporary failure",
			"service unavailable",
			"too many requests",
			// 5xx reason phrases: HTTP client libraries (e.g. go-oidc, when a
			// server returns an unexpected status) often surface these in the
			// error text verbatim rather than as a structured status code, so
			// matching on the phrase is what actually makes a real upstream
			// 5xx retryable. "service unavailable" (503) and "gateway timeout"
			// (504, caught by "timeout" above) are already covered.
			"internal server error",
			"bad gateway",
		},
		JitterEnabled: true,
	}
}

// InteractivePolicy returns a retry policy for external calls made on a
// synchronous, user-facing request path (e.g. an OAuth2/OIDC callback
// holding a browser redirect's HTTP response open). Deliberately short
// compared to ExternalServicePolicy's up-to-~19.5s-per-call worst-case
// backoff budget (5 attempts, 1s-30s): a caller here can't let several
// stacked retried calls risk exceeding a typical 30s reverse-proxy or
// browser timeout.
func InteractivePolicy() Policy {
	return Policy{
		Enabled:           true,
		MaxAttempts:       2,
		InitialDelay:      250 * time.Millisecond,
		MaxDelay:          2 * time.Second,
		BackoffMultiplier: 2.0,
		RetryableErrors:   ExternalServicePolicy().RetryableErrors,
		JitterEnabled:     true,
	}
}

// CircuitBreakerConfig defines circuit breaker behavior for protecting against cascading failures.
type CircuitBreakerConfig struct {
	FailureThreshold int           `yaml:"failure_threshold" json:"failure_threshold"`
	Timeout          time.Duration `yaml:"timeout" json:"timeout"`
	HalfOpenRequests int           `yaml:"half_open_requests" json:"half_open_requests"`
}

// DefaultCircuitBreaker returns a default circuit breaker configuration.
func DefaultCircuitBreaker() CircuitBreakerConfig {
	return CircuitBreakerConfig{
		FailureThreshold: 5,
		Timeout:          60 * time.Second,
		HalfOpenRequests: 3,
	}
}

// CircuitBreaker provides circuit breaker functionality for protecting external services.
type CircuitBreaker struct {
	config        CircuitBreakerConfig
	failures      int
	lastFailure   time.Time
	state         CircuitState
	halfOpenCount int
	mu            sync.RWMutex
}

// CircuitState represents the state of a circuit breaker.
type CircuitState int

const (
	StateClosed CircuitState = iota
	StateOpen
	StateHalfOpen
)

// NewCircuitBreaker creates a new circuit breaker with the given configuration.
func NewCircuitBreaker(config CircuitBreakerConfig) *CircuitBreaker {
	return &CircuitBreaker{
		config: config,
		state:  StateClosed,
	}
}

// Execute runs fn through the circuit breaker. It returns
// ErrCircuitBreakerOpen without calling fn if the breaker denies admission:
// always denied while open (until config.Timeout has elapsed since the last
// failure), and capped at config.HalfOpenRequests concurrent/total trial
// calls while half-open.
func (cb *CircuitBreaker) Execute(fn func() error) error {
	return cb.ExecuteClassified(fn, nil)
}

// ExecuteClassified is Execute with a classifier that decides whether an
// error counts as a breaker failure. An error the classifier rejects, such as
// a client error, proves nothing about the backend: a bad token is refused
// before any database call. It neither counts nor resets the failure count.
// In a half-open trial it only releases its trial slot, so it can neither
// close nor reopen the breaker nor use up the slots. A nil classifier counts
// every error.
func (cb *CircuitBreaker) ExecuteClassified(fn func() error, counts func(error) bool) error {
	admitted, halfOpen := cb.admit()
	if !admitted {
		return ErrCircuitBreakerOpen
	}
	if counts == nil {
		counts = func(error) bool { return true }
	}
	if halfOpen {
		return cb.finishHalfOpen(fn, counts)
	}
	return cb.executeClosed(fn, counts)
}

// admit atomically decides whether to let a call through, performing the
// Open→HalfOpen transition and reserving a half-open trial slot in the same
// critical section as the state check. This closes the race where multiple
// concurrent callers each observe a stale Open state (or a stale
// lastFailure) and each independently transition and admit themselves —
// the previous two-step "read state under RLock, then act unlocked"
// version allowed unbounded concurrent callers into the half-open trial
// regardless of config.HalfOpenRequests.
func (cb *CircuitBreaker) admit() (admitted bool, halfOpen bool) {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	switch cb.state {
	case StateClosed:
		return true, false
	case StateOpen:
		if time.Since(cb.lastFailure) < cb.config.Timeout {
			return false, false
		}
		cb.state = StateHalfOpen
		cb.halfOpenCount = 1
		return true, true
	case StateHalfOpen:
		if cb.halfOpenCount >= cb.config.HalfOpenRequests {
			return false, false
		}
		cb.halfOpenCount++
		return true, true
	default:
		return false, false
	}
}

func (cb *CircuitBreaker) executeClosed(fn func() error, counts func(error) bool) error {
	err := fn()
	switch {
	case err == nil:
		cb.recordSuccess()
	case counts(err):
		cb.recordFailure()
	}
	return err
}

// finishHalfOpen runs fn for an already-admitted half-open trial (slot
// reserved by admit) and applies its outcome. Any half-open trial failure
// reopens the breaker immediately, rather than delegating to
// recordFailure's FailureThreshold-counted reopen: a single failed trial
// during the half-open probe is standard circuit-breaker semantics for
// re-tripping, and not coupling the half-open reopen decision to the
// FailureThreshold counter (now that admission during half-open is capped
// at config.HalfOpenRequests, generally well below FailureThreshold in
// every shipped config) avoids relying on cb.failures already sitting at or
// above FailureThreshold by the time a half-open trial is reached. The
// trial whose reservation brought halfOpenCount up to
// config.HalfOpenRequests still closes the breaker on success.
func (cb *CircuitBreaker) finishHalfOpen(fn func() error, counts func(error) bool) error {
	err := fn()
	if err != nil && !counts(err) {
		// Release the slot and change nothing else. Holding it would leave
		// the breaker stuck half-open once every slot was taken this way.
		cb.mu.Lock()
		if cb.state == StateHalfOpen && cb.halfOpenCount > 0 {
			cb.halfOpenCount--
		}
		cb.mu.Unlock()
		return err
	}
	if err != nil {
		cb.mu.Lock()
		cb.failures++
		cb.lastFailure = time.Now()
		cb.state = StateOpen
		cb.halfOpenCount = 0
		cb.mu.Unlock()
		return err
	}

	cb.mu.Lock()
	if cb.halfOpenCount >= cb.config.HalfOpenRequests {
		cb.state = StateClosed
		cb.failures = 0
		cb.halfOpenCount = 0
	}
	cb.mu.Unlock()

	return nil
}

func (cb *CircuitBreaker) recordFailure() {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	cb.failures++
	cb.lastFailure = time.Now()

	if cb.failures >= cb.config.FailureThreshold {
		cb.state = StateOpen
	}
}

func (cb *CircuitBreaker) recordSuccess() {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	cb.failures = 0
}

// GetState returns the current state of the circuit breaker.
func (cb *CircuitBreaker) GetState() CircuitState {
	cb.mu.RLock()
	defer cb.mu.RUnlock()
	return cb.state
}

// Common errors
var (
	ErrCircuitBreakerOpen = errors.New("circuit breaker is open")
	ErrMaxRetriesExceeded = errors.New("max retry attempts exceeded")
	ErrNonRetryable       = errors.New("error is not retryable")
)

// RetryableError represents an error that can be retried.
type RetryableError interface {
	error
	Retryable() bool
}

// retryableError implements RetryableError.
type retryableError struct {
	err       error
	retryable bool
}

func (e *retryableError) Error() string {
	return e.err.Error()
}

func (e *retryableError) Retryable() bool {
	return e.retryable
}

// IsRetryable determines if an error should be retried based on the policy.
func IsRetryable(err error, policy Policy) bool {
	if err == nil {
		return false
	}

	// Check if error implements RetryableError interface
	var retryableErr RetryableError
	if errors.As(err, &retryableErr) {
		return retryableErr.Retryable()
	}

	// Check against configured retryable error patterns
	errStr := strings.ToLower(err.Error())
	for _, pattern := range policy.RetryableErrors {
		if strings.Contains(errStr, strings.ToLower(pattern)) {
			return true
		}
	}

	return false
}

// IsRetryableStatus determines if an HTTP status code should be retried based on the policy.
func IsRetryableStatus(statusCode int, policy Policy) bool {
	for _, retryableStatus := range policy.RetryableStatuses {
		if statusCode == retryableStatus {
			return true
		}
	}
	return false
}

// WithExponentialBackoff executes the given function with exponential backoff retry logic.
func WithExponentialBackoff(ctx context.Context, policy Policy, fn func() error) error {
	if !policy.Enabled {
		return fn()
	}

	var lastErr error

	for attempt := 0; attempt < policy.MaxAttempts; attempt++ {
		// Check context cancellation
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		// Execute the function
		err := fn()
		if err == nil {
			return nil
		}

		lastErr = err

		// Check if error is retryable. The inner error is wrapped with %w, not
		// %v, so a caller can still match a domain sentinel (for example
		// repositories.ErrSecretPurgeProtected) with errors.Is after the retry
		// layer has handled it.
		if !IsRetryable(err, policy) {
			return fmt.Errorf("%w: %w", ErrNonRetryable, err)
		}

		// Don't sleep after the last attempt
		if attempt == policy.MaxAttempts-1 {
			break
		}

		// Calculate delay with exponential backoff
		delay := calculateDelay(attempt, policy)

		// Sleep with context cancellation support
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(delay):
			// Continue to next attempt
		}
	}

	// %w for the inner error keeps the caller's sentinel matchable; see the
	// non-retryable branch above.
	return fmt.Errorf("%w: %w", ErrMaxRetriesExceeded, lastErr)
}

// WithExponentialBackoffResult executes the given function with exponential backoff and returns a result.
func WithExponentialBackoffResult[T any](ctx context.Context, policy Policy, fn func() (T, error)) (T, error) {
	if !policy.Enabled {
		return fn()
	}

	var result T
	var lastErr error

	for attempt := 0; attempt < policy.MaxAttempts; attempt++ {
		// Check context cancellation
		select {
		case <-ctx.Done():
			return result, ctx.Err()
		default:
		}

		// Execute the function
		result, err := fn()
		if err == nil {
			return result, nil
		}

		lastErr = err

		// Check if error is retryable
		if !IsRetryable(err, policy) {
			return result, fmt.Errorf("%w: %w", ErrNonRetryable, err)
		}

		// Don't sleep after the last attempt
		if attempt == policy.MaxAttempts-1 {
			break
		}

		// Calculate delay with exponential backoff
		delay := calculateDelay(attempt, policy)

		// Sleep with context cancellation support
		select {
		case <-ctx.Done():
			return result, ctx.Err()
		case <-time.After(delay):
			// Continue to next attempt
		}
	}

	return result, fmt.Errorf("%w: %w", ErrMaxRetriesExceeded, lastErr)
}

// calculateDelay calculates the delay for the given attempt with exponential backoff and optional jitter.
func calculateDelay(attempt int, policy Policy) time.Duration {
	// Calculate exponential backoff
	delay := float64(policy.InitialDelay) * math.Pow(policy.BackoffMultiplier, float64(attempt))

	// Apply max delay cap
	if delay > float64(policy.MaxDelay) {
		delay = float64(policy.MaxDelay)
	}

	// Add jitter to prevent thundering herd
	if policy.JitterEnabled {
		jitter := rand.Float64() * 0.3 * delay // Up to 30% jitter
		delay = delay + jitter
	}

	return time.Duration(delay)
}

// Retryable wraps an error to indicate it can be retried.
func Retryable(err error) error {
	if err == nil {
		return nil
	}
	return &retryableError{err: err, retryable: true}
}

// clientError marks a client or domain outcome, such as invalid credentials
// or an invalid token. It keeps the cause's message and unwraps to it.
type clientError struct {
	err error
}

func (e *clientError) Error() string { return e.err.Error() }

func (e *clientError) Unwrap() error { return e.err }

// Retryable reports false: retrying cannot change a client outcome.
func (e *clientError) Retryable() bool { return false }

// ClientFault reports true, so circuit breakers do not count the error.
func (e *clientError) ClientFault() bool { return true }

// ClientError marks err as a client or domain outcome. Such an error is never
// retried and never counts as a circuit breaker failure. Use it only for
// results the caller caused, never for storage or network faults.
func ClientError(err error) error {
	if err == nil {
		return nil
	}
	return &clientError{err: err}
}

// IsClientError reports whether err, or an error it wraps, is a client
// outcome: it carries a ClientFault method that returns true.
func IsClientError(err error) bool {
	var ce interface{ ClientFault() bool }
	return errors.As(err, &ce) && ce.ClientFault()
}

// NonRetryable wraps an error to indicate it should not be retried.
func NonRetryable(err error) error {
	if err == nil {
		return nil
	}
	return &retryableError{err: err, retryable: false}
}
