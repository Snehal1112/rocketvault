package retry

import (
	"context"
	"fmt"

	"github.com/spf13/viper"

	"rocketvault/internal/retry"
)

// RetryService provides retry functionality for application operations.
// It manages retry policies and provides retry wrappers for different
// types of operations (database, external services, service operations).
type RetryService interface {
	// ExecuteDatabaseOperation executes a database operation with retry logic
	ExecuteDatabaseOperation(ctx context.Context, operation func() error) error

	// ExecuteExternalServiceOperation executes an external service call with retry logic
	ExecuteExternalServiceOperation(ctx context.Context, operation func() error) error

	// ExecuteServiceOperation executes an internal service operation with retry logic
	ExecuteServiceOperation(ctx context.Context, operation func() error) error

	// ExecuteInteractiveOperation executes an external call on a
	// synchronous, user-facing request path with a bounded retry budget
	// (see retry.InteractivePolicy)
	ExecuteInteractiveOperation(ctx context.Context, operation func() error) error

	// GetDatabasePolicy returns the database retry policy
	GetDatabasePolicy() retry.Policy

	// GetExternalServicesPolicy returns the external services retry policy
	GetExternalServicesPolicy() retry.Policy

	// GetServiceOperationsPolicy returns the service operations retry policy
	GetServiceOperationsPolicy() retry.Policy

	// GetInteractivePolicy returns the interactive (request-path) retry policy
	GetInteractivePolicy() retry.Policy
}

// retryService implements RetryService with configurable policies
type retryService struct {
	databasePolicy          retry.Policy
	externalServicesPolicy  retry.Policy
	serviceOperationsPolicy retry.Policy
	interactivePolicy       retry.Policy

	// One circuit breaker per policy type. Each protects an independent
	// failure domain, so e.g. a database outage does not trip the breaker
	// guarding unrelated external service calls.
	databaseBreaker          *retry.CircuitBreaker
	externalServicesBreaker  *retry.CircuitBreaker
	serviceOperationsBreaker *retry.CircuitBreaker
	interactiveBreaker       *retry.CircuitBreaker
}

// NewRetryService creates a new retry service with policies loaded from configuration
func NewRetryService(viper *viper.Viper) (RetryService, error) {
	// Load retry configuration
	config, err := retry.LoadConfigFromViper(viper)
	if err != nil {
		return nil, fmt.Errorf("failed to load retry configuration: %w", err)
	}

	// All four breakers share the same configuration, since there is only
	// one retry.circuit_breaker block in the YAML, but each gets its own
	// independent instance and state.
	return &retryService{
		databasePolicy:          config.Database,
		externalServicesPolicy:  config.ExternalServices,
		serviceOperationsPolicy: config.ServiceOperations,
		interactivePolicy:       config.Interactive,

		databaseBreaker:          retry.NewCircuitBreaker(config.CircuitBreaker),
		externalServicesBreaker:  retry.NewCircuitBreaker(config.CircuitBreaker),
		serviceOperationsBreaker: retry.NewCircuitBreaker(config.CircuitBreaker),
		interactiveBreaker:       retry.NewCircuitBreaker(config.CircuitBreaker),
	}, nil
}

// ExecuteDatabaseOperation executes a database operation with retry logic.
// A client outcome, such as invalid credentials, an invalid token or a
// throttled login, does not count toward the database breaker (B90). The
// classification reads a marker on the error itself, so it holds whether or
// not the policy wraps the error.
func (s *retryService) ExecuteDatabaseOperation(ctx context.Context, operation func() error) error {
	return s.databaseBreaker.ExecuteClassified(func() error {
		return retry.WithExponentialBackoff(ctx, s.databasePolicy, operation)
	}, countsAsDatabaseFailure)
}

// countsAsDatabaseFailure reports whether err is a fault of the database path
// rather than a client outcome.
func countsAsDatabaseFailure(err error) bool {
	return !retry.IsClientError(err)
}

// ExecuteExternalServiceOperation executes an external service call with retry logic
func (s *retryService) ExecuteExternalServiceOperation(ctx context.Context, operation func() error) error {
	return s.externalServicesBreaker.Execute(func() error {
		return retry.WithExponentialBackoff(ctx, s.externalServicesPolicy, operation)
	})
}

// ExecuteServiceOperation executes an internal service operation with retry logic
func (s *retryService) ExecuteServiceOperation(ctx context.Context, operation func() error) error {
	return s.serviceOperationsBreaker.Execute(func() error {
		return retry.WithExponentialBackoff(ctx, s.serviceOperationsPolicy, operation)
	})
}

// ExecuteInteractiveOperation executes an external call on a synchronous,
// user-facing request path with a bounded retry budget
func (s *retryService) ExecuteInteractiveOperation(ctx context.Context, operation func() error) error {
	return s.interactiveBreaker.Execute(func() error {
		return retry.WithExponentialBackoff(ctx, s.interactivePolicy, operation)
	})
}

// GetDatabasePolicy returns the database retry policy
func (s *retryService) GetDatabasePolicy() retry.Policy {
	return s.databasePolicy
}

// GetExternalServicesPolicy returns the external services retry policy
func (s *retryService) GetExternalServicesPolicy() retry.Policy {
	return s.externalServicesPolicy
}

// GetServiceOperationsPolicy returns the service operations retry policy
func (s *retryService) GetServiceOperationsPolicy() retry.Policy {
	return s.serviceOperationsPolicy
}

// GetInteractivePolicy returns the interactive (request-path) retry policy
func (s *retryService) GetInteractivePolicy() retry.Policy {
	return s.interactivePolicy
}
