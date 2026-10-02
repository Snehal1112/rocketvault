package retry

import (
	"context"

	"github.com/google/uuid"

	"rocketvault/internal/services/keys"
	"rocketvault/model"
)

// RetryKeyService wraps key operations with retry logic
type RetryKeyService interface {
	keys.KeyService
}

// retryKeyService implements RetryKeyService with retry logic
type retryKeyService struct {
	baseService  keys.KeyService
	retryService RetryService
}

// NewRetryKeyService creates a new retry-aware key service
func NewRetryKeyService(baseService keys.KeyService, retryService RetryService) RetryKeyService {
	return &retryKeyService{
		baseService:  baseService,
		retryService: retryService,
	}
}

// CreateRSAKey creates an RSA key with retry logic for database operations.
func (s *retryKeyService) CreateRSAKey(ctx context.Context, req keys.CreateKeyRequest) (*keys.CreateKeyResult, error) {
	return retried(ctx, s.retryService, func() (*keys.CreateKeyResult, error) {
		return s.baseService.CreateRSAKey(ctx, req)
	})
}

// CreateECDSAKey creates an ECDSA key with retry logic for database operations.
func (s *retryKeyService) CreateECDSAKey(ctx context.Context, req keys.CreateKeyRequest) (*keys.CreateKeyResult, error) {
	return retried(ctx, s.retryService, func() (*keys.CreateKeyResult, error) {
		return s.baseService.CreateECDSAKey(ctx, req)
	})
}

// CreateOctKey creates a symmetric AES key with retry logic for database operations.
func (s *retryKeyService) CreateOctKey(ctx context.Context, req keys.CreateKeyRequest) (*keys.CreateKeyResult, error) {
	return retried(ctx, s.retryService, func() (*keys.CreateKeyResult, error) {
		return s.baseService.CreateOctKey(ctx, req)
	})
}

// ImportKey imports a key with retry logic for database operations.
func (s *retryKeyService) ImportKey(ctx context.Context, req keys.ImportKeyRequest) (*keys.CreateKeyResult, error) {
	return retried(ctx, s.retryService, func() (*keys.CreateKeyResult, error) {
		return s.baseService.ImportKey(ctx, req)
	})
}

// GetKey retrieves a key with retry logic for database operations.
func (s *retryKeyService) GetKey(ctx context.Context, keyID uuid.UUID, scope model.Scope) (*model.Key, error) {
	return retried(ctx, s.retryService, func() (*model.Key, error) {
		return s.baseService.GetKey(ctx, keyID, scope)
	})
}

// ListKeys lists keys with retry logic for database operations.
func (s *retryKeyService) ListKeys(ctx context.Context, scope model.Scope, filter model.KeyFilter) ([]model.Key, error) {
	return retried(ctx, s.retryService, func() ([]model.Key, error) {
		return s.baseService.ListKeys(ctx, scope, filter)
	})
}

// UpdateKey updates a key with retry logic for database operations.
func (s *retryKeyService) UpdateKey(ctx context.Context, req keys.UpdateKeyRequest) error {
	return s.retryService.ExecuteDatabaseOperation(ctx, func() error {
		return s.baseService.UpdateKey(ctx, req)
	})
}

// DeleteKey soft-deletes a key with retry logic for database operations.
func (s *retryKeyService) DeleteKey(ctx context.Context, keyID uuid.UUID, scope model.Scope) (*model.Key, error) {
	return retried(ctx, s.retryService, func() (*model.Key, error) {
		return s.baseService.DeleteKey(ctx, keyID, scope)
	})
}

// RotateKey rotates a key with retry logic for database operations.
func (s *retryKeyService) RotateKey(ctx context.Context, keyID uuid.UUID, scope model.Scope) (*keys.CreateKeyResult, error) {
	return retried(ctx, s.retryService, func() (*keys.CreateKeyResult, error) {
		return s.baseService.RotateKey(ctx, keyID, scope)
	})
}

// ListDeletedKeys lists soft-deleted keys with retry logic for database operations.
func (s *retryKeyService) ListDeletedKeys(ctx context.Context, scope model.Scope) ([]model.Key, error) {
	return retried(ctx, s.retryService, func() ([]model.Key, error) {
		return s.baseService.ListDeletedKeys(ctx, scope)
	})
}

// RecoverKey restores a soft-deleted key with retry logic for database operations.
func (s *retryKeyService) RecoverKey(ctx context.Context, keyID uuid.UUID, scope model.Scope) error {
	return s.retryService.ExecuteDatabaseOperation(ctx, func() error {
		return s.baseService.RecoverKey(ctx, keyID, scope)
	})
}

// PurgeKey permanently deletes a soft-deleted key with retry logic for database operations.
func (s *retryKeyService) PurgeKey(ctx context.Context, keyID uuid.UUID, scope model.Scope) error {
	return s.retryService.ExecuteDatabaseOperation(ctx, func() error {
		return s.baseService.PurgeKey(ctx, keyID, scope)
	})
}

// ValidateKeyAccess validates access to a key with retry logic for database operations.
func (s *retryKeyService) ValidateKeyAccess(ctx context.Context, keyID, userID uuid.UUID, role string) error {
	return s.retryService.ExecuteDatabaseOperation(ctx, func() error {
		return s.baseService.ValidateKeyAccess(ctx, keyID, userID, role)
	})
}

// GetKeyRotationPolicy retrieves a key's rotation policy with retry logic for database operations.
func (s *retryKeyService) GetKeyRotationPolicy(ctx context.Context, keyID uuid.UUID, scope model.Scope) (*model.KeyRotationPolicy, error) {
	return retried(ctx, s.retryService, func() (*model.KeyRotationPolicy, error) {
		return s.baseService.GetKeyRotationPolicy(ctx, keyID, scope)
	})
}

// UpsertKeyRotationPolicy creates or replaces a key's rotation policy with retry logic for database operations.
func (s *retryKeyService) UpsertKeyRotationPolicy(ctx context.Context, keyID uuid.UUID, scope model.Scope, req model.UpsertKeyRotationPolicyRequest) (*model.KeyRotationPolicy, error) {
	return retried(ctx, s.retryService, func() (*model.KeyRotationPolicy, error) {
		return s.baseService.UpsertKeyRotationPolicy(ctx, keyID, scope, req)
	})
}

// DeleteKeyRotationPolicy removes a key's rotation policy with retry logic for database operations.
func (s *retryKeyService) DeleteKeyRotationPolicy(ctx context.Context, keyID uuid.UUID, scope model.Scope) error {
	return s.retryService.ExecuteDatabaseOperation(ctx, func() error {
		return s.baseService.DeleteKeyRotationPolicy(ctx, keyID, scope)
	})
}

// ListKeyRotationPolicies lists a vault's key rotation policies with retry logic for database operations.
func (s *retryKeyService) ListKeyRotationPolicies(ctx context.Context, scope model.Scope) ([]model.KeyRotationPolicyWithKeyName, error) {
	return retried(ctx, s.retryService, func() ([]model.KeyRotationPolicyWithKeyName, error) {
		return s.baseService.ListKeyRotationPolicies(ctx, scope)
	})
}

// ListDueKeyRotationPolicies lists due key rotation policies with retry logic for database operations.
func (s *retryKeyService) ListDueKeyRotationPolicies(ctx context.Context, scope model.Scope) ([]model.KeyRotationPolicy, error) {
	return retried(ctx, s.retryService, func() ([]model.KeyRotationPolicy, error) {
		return s.baseService.ListDueKeyRotationPolicies(ctx, scope)
	})
}

// ListKeyVersions lists a key's version history with retry logic for database operations.
func (s *retryKeyService) ListKeyVersions(ctx context.Context, keyID uuid.UUID, scope model.Scope) ([]model.KeyVersion, error) {
	return retried(ctx, s.retryService, func() ([]model.KeyVersion, error) {
		return s.baseService.ListKeyVersions(ctx, keyID, scope)
	})
}

// GetKeyVersion retrieves one version of a key with retry logic for database operations.
func (s *retryKeyService) GetKeyVersion(ctx context.Context, keyID uuid.UUID, version int, scope model.Scope) (*model.KeyVersion, error) {
	return retried(ctx, s.retryService, func() (*model.KeyVersion, error) {
		return s.baseService.GetKeyVersion(ctx, keyID, version, scope)
	})
}

// GetPublicJWK retrieves the public components of one version of a key with retry logic for database operations.
func (s *retryKeyService) GetPublicJWK(ctx context.Context, keyID uuid.UUID, version int, scope model.Scope) (*model.PublicJWK, error) {
	return retried(ctx, s.retryService, func() (*model.PublicJWK, error) {
		return s.baseService.GetPublicJWK(ctx, keyID, version, scope)
	})
}

// ExportKey is deliberately not retried. A failed export is reported once;
// replaying it would decrypt the key again for one request.
func (s *retryKeyService) ExportKey(ctx context.Context, scope model.Scope, id uuid.UUID, version int) (*keys.ExportKeyResult, error) {
	return s.baseService.ExportKey(ctx, scope, id, version)
}
