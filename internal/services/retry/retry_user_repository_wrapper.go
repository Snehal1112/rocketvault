package retry

import (
	"context"

	"github.com/google/uuid"

	"rocketvault/internal/repositories"
	"rocketvault/model"
)

// RetryUserRepositoryWrapper wraps user repository operations with retry logic
type RetryUserRepositoryWrapper struct {
	baseRepo     repositories.UserRepositoryInterface
	retryService RetryService
}

// NewRetryUserRepositoryWrapper creates a new retry-aware user repository wrapper
func NewRetryUserRepositoryWrapper(baseRepo repositories.UserRepositoryInterface, retryService RetryService) repositories.UserRepositoryInterface {
	return &RetryUserRepositoryWrapper{
		baseRepo:     baseRepo,
		retryService: retryService,
	}
}

// Create wraps the Create operation with retry logic
func (r *RetryUserRepositoryWrapper) Create(ctx context.Context, user *model.User) error {
	return r.retryService.ExecuteDatabaseOperation(ctx, func() error {
		return r.baseRepo.Create(ctx, user)
	})
}

// Read wraps the Read operation with retry logic
func (r *RetryUserRepositoryWrapper) Read(ctx context.Context, id uuid.UUID) (*model.User, error) {
	return retried(ctx, r.retryService, func() (*model.User, error) {
		return r.baseRepo.Read(ctx, id)
	})
}

// Update wraps the Update operation with retry logic
func (r *RetryUserRepositoryWrapper) Update(ctx context.Context, user *model.User) error {
	return r.retryService.ExecuteDatabaseOperation(ctx, func() error {
		return r.baseRepo.Update(ctx, user)
	})
}

// Delete wraps the Delete operation with retry logic
func (r *RetryUserRepositoryWrapper) Delete(ctx context.Context, id uuid.UUID) error {
	return r.retryService.ExecuteDatabaseOperation(ctx, func() error {
		return r.baseRepo.Delete(ctx, id)
	})
}

// ReadByUsername wraps the ReadByUsername operation with retry logic
func (r *RetryUserRepositoryWrapper) ReadByUsername(ctx context.Context, username string) (model.User, error) {
	return retried(ctx, r.retryService, func() (model.User, error) {
		return r.baseRepo.ReadByUsername(ctx, username)
	})
}

// ReadByExternalSubject wraps the ReadByExternalSubject operation with retry logic
func (r *RetryUserRepositoryWrapper) ReadByExternalSubject(ctx context.Context, provider, subject string) (*model.User, error) {
	return retried(ctx, r.retryService, func() (*model.User, error) {
		return r.baseRepo.ReadByExternalSubject(ctx, provider, subject)
	})
}

// UpdateEmail wraps the UpdateEmail operation with retry logic
func (r *RetryUserRepositoryWrapper) UpdateEmail(ctx context.Context, id uuid.UUID, email string) error {
	return r.retryService.ExecuteDatabaseOperation(ctx, func() error {
		return r.baseRepo.UpdateEmail(ctx, id, email)
	})
}

// List wraps the List operation with retry logic
func (r *RetryUserRepositoryWrapper) List(ctx context.Context) ([]model.User, error) {
	return retried(ctx, r.retryService, func() ([]model.User, error) {
		return r.baseRepo.List(ctx)
	})
}

// ValidateBootstrapToken wraps the ValidateBootstrapToken operation with retry logic
func (r *RetryUserRepositoryWrapper) ValidateBootstrapToken(ctx context.Context, token string) (bool, error) {
	return retried(ctx, r.retryService, func() (bool, error) {
		return r.baseRepo.ValidateBootstrapToken(ctx, token)
	})
}

// InvalidateBootstrapToken wraps the InvalidateBootstrapToken operation with retry logic
func (r *RetryUserRepositoryWrapper) InvalidateBootstrapToken(ctx context.Context, token string) error {
	return r.retryService.ExecuteDatabaseOperation(ctx, func() error {
		return r.baseRepo.InvalidateBootstrapToken(ctx, token)
	})
}
