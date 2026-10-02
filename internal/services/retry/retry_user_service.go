package retry

import (
	"context"

	"github.com/google/uuid"

	"rocketvault/internal/services/users"
	"rocketvault/model"
)

// RetryUserService wraps user operations with retry logic
type RetryUserService interface {
	users.UserService
}

// retryUserService implements RetryUserService with retry logic
type retryUserService struct {
	baseService  users.UserService
	retryService RetryService
}

// NewRetryUserService creates a new retry-aware user service
func NewRetryUserService(baseService users.UserService, retryService RetryService) RetryUserService {
	return &retryUserService{
		baseService:  baseService,
		retryService: retryService,
	}
}

// CreateUser creates a user with retry logic for database operations
func (s *retryUserService) CreateUser(ctx context.Context, req users.CreateUserRequest) (*users.CreateUserResult, error) {
	return retried(ctx, s.retryService, func() (*users.CreateUserResult, error) {
		return s.baseService.CreateUser(ctx, req)
	})
}

// UpdateUser updates a user with retry logic for database operations.
// The base result is passed through, so a one-time TOTP enrollment URL is not lost.
func (s *retryUserService) UpdateUser(ctx context.Context, req users.UpdateUserRequest) (*users.UpdateUserResult, error) {
	return retried(ctx, s.retryService, func() (*users.UpdateUserResult, error) {
		return s.baseService.UpdateUser(ctx, req)
	})
}

// FindOrCreateExternalUser resolves an externally-authenticated user with
// retry logic for database operations.
func (s *retryUserService) FindOrCreateExternalUser(ctx context.Context, req users.FindOrCreateExternalUserRequest) (*model.User, error) {
	return retried(ctx, s.retryService, func() (*model.User, error) {
		return s.baseService.FindOrCreateExternalUser(ctx, req)
	})
}

// GetUser retrieves a user with retry logic for database operations
func (s *retryUserService) GetUser(ctx context.Context, userID uuid.UUID) (*model.User, error) {
	return retried(ctx, s.retryService, func() (*model.User, error) {
		return s.baseService.GetUser(ctx, userID)
	})
}

// GetUserByUsername retrieves a user by username with retry logic for database operations
func (s *retryUserService) GetUserByUsername(ctx context.Context, username string) (*model.User, error) {
	return retried(ctx, s.retryService, func() (*model.User, error) {
		return s.baseService.GetUserByUsername(ctx, username)
	})
}

// ListUsers lists users with retry logic for database operations
func (s *retryUserService) ListUsers(ctx context.Context) ([]model.User, error) {
	return retried(ctx, s.retryService, func() ([]model.User, error) {
		return s.baseService.ListUsers(ctx)
	})
}

// DeleteUser deletes a user with retry logic for database operations
func (s *retryUserService) DeleteUser(ctx context.Context, userID uuid.UUID) error {
	return s.retryService.ExecuteDatabaseOperation(ctx, func() error {
		return s.baseService.DeleteUser(ctx, userID)
	})
}

// ValidateBootstrapToken validates a bootstrap token with retry logic for database operations
func (s *retryUserService) ValidateBootstrapToken(ctx context.Context, token string) (bool, error) {
	return retried(ctx, s.retryService, func() (bool, error) {
		return s.baseService.ValidateBootstrapToken(ctx, token)
	})
}

// InvalidateBootstrapToken invalidates a bootstrap token with retry logic for database operations
func (s *retryUserService) InvalidateBootstrapToken(ctx context.Context, token string) error {
	return s.retryService.ExecuteDatabaseOperation(ctx, func() error {
		return s.baseService.InvalidateBootstrapToken(ctx, token)
	})
}
