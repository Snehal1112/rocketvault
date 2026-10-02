// Package secrets provides business logic services for secret management operations.
// This package follows the established service layer patterns with dependency injection
// and proper separation of concerns.
package secrets

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"

	"rocketvault/internal/logging"
	"rocketvault/internal/repositories"
	"rocketvault/model"
)

// VersioningServiceInterface defines the business logic contract for secret versioning operations.
// It orchestrates version creation, retrieval, and management with proper encryption handling.
type VersioningServiceInterface interface {
	// Version creation and management
	CreateVersion(ctx context.Context, req CreateVersionRequest) (*model.SecretVersion, error)
	// GetVersions returns every decrypted version of a secret the scope
	// authorizes. Callers that only need to enumerate versions must use
	// GetVersionsMetadata instead -- see § B30.
	GetVersions(ctx context.Context, secretID uuid.UUID, scope model.Scope) ([]model.SecretVersion, error)
	// GetVersionsMetadata returns every version of a secret the scope
	// authorizes, without values and without ever decrypting one.
	GetVersionsMetadata(ctx context.Context, secretID uuid.UUID, scope model.Scope) ([]model.SecretVersionMetadata, error)
	// GetVersion returns one decrypted version the scope authorizes.
	GetVersion(ctx context.Context, secretID uuid.UUID, version int, scope model.Scope) (*model.SecretVersion, error)
	// GetLatestVersion returns the newest decrypted version the scope authorizes.
	GetLatestVersion(ctx context.Context, secretID uuid.UUID, scope model.Scope) (*model.SecretVersion, error)
	DeleteVersions(ctx context.Context, secretID uuid.UUID, userID uuid.UUID) error
	DeleteSpecificVersion(ctx context.Context, secretID uuid.UUID, version int, userID uuid.UUID) error

	// Version rollback
	RollbackToVersion(ctx context.Context, req RollbackRequest) (*model.Secret, error)
}

// CreateVersionRequest represents the request to create a new secret version.
type CreateVersionRequest struct {
	SecretID uuid.UUID `json:"secret_id" validate:"required"`
	UserID   uuid.UUID `json:"user_id" validate:"required"`
	Name     string    `json:"name" validate:"required,min=1,max=255"`
	Value    string    `json:"value" validate:"required,min=1"`
	Version  int       `json:"version" validate:"required,min=1"`
}

// RollbackRequest represents the request to rollback a secret to a specific version.
type RollbackRequest struct {
	SecretID      uuid.UUID `json:"secret_id" validate:"required"`
	TargetVersion int       `json:"target_version" validate:"required,min=1"`
	UserID        uuid.UUID `json:"user_id" validate:"required"`
	Notes         string    `json:"notes" validate:"max=500"`
}

// versioningService implements VersioningServiceInterface.
type versioningService struct {
	versionRepo repositories.SecretVersionRepositoryInterface
	secretRepo  repositories.SecretRepositoryInterface
	userRepo    repositories.UserRepositoryInterface
	cryptoSvc   CryptographyService
	cacheInv    SecretCacheInvalidator
	log         *logging.Logger
}

// NewVersioningService creates a new versioning service with the required
// dependencies. cacheInv is needed because RollbackToVersion writes the
// secrets table without going through CachedSecretService. The container
// always constructs a real (possibly no-op-backed) invalidator; a nil
// cacheInv (e.g. from a test) is defaulted to a no-op implementation so
// invalidateCache never nil-derefs.
func NewVersioningService(
	versionRepo repositories.SecretVersionRepositoryInterface,
	secretRepo repositories.SecretRepositoryInterface,
	userRepo repositories.UserRepositoryInterface,
	cryptoSvc CryptographyService,
	log *logging.Logger,
	cacheInv SecretCacheInvalidator,
) VersioningServiceInterface {
	if cacheInv == nil {
		cacheInv = noopSecretCacheInvalidator{}
	}
	return &versioningService{
		versionRepo: versionRepo,
		secretRepo:  secretRepo,
		userRepo:    userRepo,
		cryptoSvc:   cryptoSvc,
		cacheInv:    cacheInv,
		log:         log,
	}
}

// invalidateCache evicts every cached view of a secret after a direct write.
// A failure is logged but never fails the operation that already succeeded.
func (s *versioningService) invalidateCache(ctx context.Context, secretID uuid.UUID) {
	if err := s.cacheInv.DeleteByID(ctx, secretID); err != nil {
		s.log.WithError(err).WithField("secret_id", secretID).Warn("Failed to invalidate cached secret")
	}
}

// CreateVersion creates a new version of a secret with encryption and validation.
func (s *versioningService) CreateVersion(ctx context.Context, req CreateVersionRequest) (*model.SecretVersion, error) {
	// Validate user exists
	user, err := s.userRepo.Read(ctx, req.UserID)
	if err != nil {
		s.log.WithError(err).WithField("user_id", req.UserID).Error("User not found for version creation")
		return nil, fmt.Errorf("user not found: %w", err)
	}

	// Validate secret exists and user owns it. The read itself is unchecked
	// (admin scope): CreateVersion is called both directly by owner-scoped
	// callers and internally by UpdateSecret with the secret's real owner, so
	// the explicit ownership check below is the actual authorization gate.
	secret, err := s.secretRepo.Read(ctx, req.SecretID, model.NewAdminScope(req.UserID))
	if err != nil {
		s.log.WithError(err).WithField("secret_id", req.SecretID).Error("Secret not found for version creation")
		return nil, fmt.Errorf("secret not found: %w", err)
	}

	if secret.UserID != req.UserID {
		return nil, fmt.Errorf("user does not own this secret")
	}

	// Encrypt the secret value
	encryptedValue, err := s.cryptoSvc.EncryptSecret(req.Value)
	if err != nil {
		s.log.WithError(err).Error("Failed to encrypt secret version")
		return nil, fmt.Errorf("failed to encrypt secret version: %w", err)
	}

	// Create version domain object
	now := time.Now()
	version := &model.SecretVersion{
		ID:        uuid.New(),
		SecretID:  req.SecretID,
		UserID:    user.ID,
		Name:      req.Name,
		Value:     encryptedValue, // Store encrypted value
		Version:   req.Version,
		CreatedAt: now,
	}

	err = s.versionRepo.CreateVersion(ctx, version)
	if err != nil {
		s.log.WithError(err).Error("Failed to create secret version")
		return nil, fmt.Errorf("failed to create secret version: %w", err)
	}

	s.log.WithFields(map[string]any{
		"version_id": version.ID,
		"secret_id":  version.SecretID,
		"user_id":    version.UserID,
		"version":    version.Version,
	}).Info("Secret version created successfully")

	// Return decrypted version for response
	version.Value = req.Value
	return version, nil
}

// readAccessibleParent authorizes the scope against the parent secret and
// enforces its lifecycle, so a disabled or expired secret cannot be read back
// through its version history.
func (s *versioningService) readAccessibleParent(ctx context.Context, secretID uuid.UUID, scope model.Scope) error {
	parent, err := s.secretRepo.Read(ctx, secretID, scope)
	if err != nil {
		return fmt.Errorf("%w: %s", ErrSecretNotFound, err.Error())
	}
	if !parent.IsAccessible() {
		return fmt.Errorf("%w", ErrSecretLifecycleDenied)
	}
	return nil
}

// GetVersions retrieves all versions of a secret the scope authorizes.
// The scoped read on the parent secret is the access check.
func (s *versioningService) GetVersions(ctx context.Context, secretID uuid.UUID, scope model.Scope) ([]model.SecretVersion, error) {
	if err := s.readAccessibleParent(ctx, secretID, scope); err != nil {
		return nil, err
	}

	encryptedVersions, err := s.versionRepo.GetVersions(ctx, secretID)
	if err != nil {
		s.log.WithError(err).WithField("secret_id", secretID).Error("Failed to get secret versions")
		return nil, fmt.Errorf("failed to get secret versions: %w", err)
	}

	var versions []model.SecretVersion
	for _, encVersion := range encryptedVersions {
		decryptedValue, decErr := s.cryptoSvc.DecryptSecret(encVersion.Value)
		if decErr != nil {
			s.log.WithError(decErr).WithField("version_id", encVersion.ID).Error("Failed to decrypt secret version")
			return nil, fmt.Errorf("failed to decrypt secret version: %w", decErr)
		}
		decVersion := encVersion
		decVersion.Value = decryptedValue
		versions = append(versions, decVersion)
	}
	return versions, nil
}

// GetVersionsMetadata returns every version of a secret the scope authorizes,
// without values.
//
// It deliberately never calls DecryptSecret. Returning model.SecretVersionMetadata
// would already prevent a value reaching the caller, but decrypting and then
// discarding would leave every historical plaintext in process memory for no
// reason, and would leave the guarantee resting on the caller's choice of
// return type -- which is precisely how § B30 happened. Not obtaining the
// plaintext is the guarantee.
func (s *versioningService) GetVersionsMetadata(ctx context.Context, secretID uuid.UUID, scope model.Scope) ([]model.SecretVersionMetadata, error) {
	if _, err := s.secretRepo.Read(ctx, secretID, scope); err != nil {
		return nil, fmt.Errorf("%w: %s", ErrSecretNotFound, err.Error())
	}

	encryptedVersions, err := s.versionRepo.GetVersions(ctx, secretID)
	if err != nil {
		s.log.WithError(err).WithField("secret_id", secretID).Error("Failed to get secret versions")
		return nil, fmt.Errorf("failed to get secret versions: %w", err)
	}

	versions := make([]model.SecretVersionMetadata, 0, len(encryptedVersions))
	for _, v := range encryptedVersions {
		versions = append(versions, model.SecretVersionMetadata{
			ID:        v.ID,
			SecretID:  v.SecretID,
			Name:      v.Name,
			Version:   v.Version,
			CreatedAt: v.CreatedAt,
		})
	}
	return versions, nil
}

// GetVersion retrieves one version of a secret the scope authorizes.
func (s *versioningService) GetVersion(ctx context.Context, secretID uuid.UUID, version int, scope model.Scope) (*model.SecretVersion, error) {
	if err := s.readAccessibleParent(ctx, secretID, scope); err != nil {
		return nil, err
	}

	encryptedVersion, err := s.versionRepo.GetVersion(ctx, secretID, version)
	if err != nil {
		s.log.WithError(err).WithFields(map[string]any{"secret_id": secretID, "version": version}).
			Error("Failed to get secret version")
		// A missing version row is a 404, same as a missing parent secret; any
		// other repository failure (e.g. a real DB error) stays a 500.
		if errors.Is(err, repositories.ErrNotFound) {
			return nil, fmt.Errorf("%w: %s", ErrSecretNotFound, err.Error())
		}
		return nil, fmt.Errorf("failed to get secret version: %w", err)
	}

	decryptedValue, err := s.cryptoSvc.DecryptSecret(encryptedVersion.Value)
	if err != nil {
		s.log.WithError(err).WithField("version_id", encryptedVersion.ID).Error("Failed to decrypt secret version")
		return nil, fmt.Errorf("failed to decrypt secret version: %w", err)
	}
	encryptedVersion.Value = decryptedValue
	return encryptedVersion, nil
}

// GetLatestVersion retrieves the newest version the scope authorizes.
func (s *versioningService) GetLatestVersion(ctx context.Context, secretID uuid.UUID, scope model.Scope) (*model.SecretVersion, error) {
	if err := s.readAccessibleParent(ctx, secretID, scope); err != nil {
		return nil, err
	}

	encryptedVersion, err := s.versionRepo.GetLatestVersion(ctx, secretID)
	if err != nil {
		s.log.WithError(err).WithField("secret_id", secretID).Error("Failed to get latest secret version")
		// No version rows at all is a 404, same as a missing parent secret;
		// any other repository failure (e.g. a real DB error) stays a 500.
		if errors.Is(err, repositories.ErrNotFound) {
			return nil, fmt.Errorf("%w: %s", ErrSecretNotFound, err.Error())
		}
		return nil, fmt.Errorf("failed to get latest secret version: %w", err)
	}

	decryptedValue, err := s.cryptoSvc.DecryptSecret(encryptedVersion.Value)
	if err != nil {
		s.log.WithError(err).WithField("version_id", encryptedVersion.ID).Error("Failed to decrypt secret version")
		return nil, fmt.Errorf("failed to decrypt secret version: %w", err)
	}
	encryptedVersion.Value = decryptedValue
	return encryptedVersion, nil
}

// DeleteVersions deletes all versions of a secret with ownership validation.
func (s *versioningService) DeleteVersions(ctx context.Context, secretID uuid.UUID, userID uuid.UUID) error {
	// Validate secret exists and user owns it. The read itself is unchecked
	// (admin scope); the explicit ownership check below is the actual gate.
	secret, err := s.secretRepo.Read(ctx, secretID, model.NewAdminScope(userID))
	if err != nil {
		return fmt.Errorf("secret not found: %w", err)
	}

	if secret.UserID != userID {
		return fmt.Errorf("user does not own this secret")
	}

	err = s.versionRepo.DeleteVersions(ctx, secretID)
	if err != nil {
		s.log.WithError(err).WithField("secret_id", secretID).Error("Failed to delete secret versions")
		return fmt.Errorf("failed to delete secret versions: %w", err)
	}

	s.log.WithFields(map[string]any{
		"secret_id": secretID,
		"user_id":   userID,
	}).Info("Secret versions deleted successfully")

	return nil
}

// DeleteSpecificVersion deletes a specific version of a secret with ownership validation.
func (s *versioningService) DeleteSpecificVersion(ctx context.Context, secretID uuid.UUID, version int, userID uuid.UUID) error {
	// Validate secret exists and user owns it. The read itself is unchecked
	// (admin scope); the explicit ownership check below is the actual gate.
	secret, err := s.secretRepo.Read(ctx, secretID, model.NewAdminScope(userID))
	if err != nil {
		return fmt.Errorf("secret not found: %w", err)
	}

	if secret.UserID != userID {
		return fmt.Errorf("user does not own this secret")
	}

	err = s.versionRepo.DeleteSpecificVersion(ctx, secretID, version)
	if err != nil {
		s.log.WithError(err).WithFields(map[string]any{
			"secret_id": secretID,
			"version":   version,
		}).Error("Failed to delete secret version")
		return fmt.Errorf("failed to delete secret version: %w", err)
	}

	s.log.WithFields(map[string]any{
		"secret_id": secretID,
		"version":   version,
		"user_id":   userID,
	}).Info("Secret version deleted successfully")

	return nil
}

// RollbackToVersion rolls back a secret to a specific version.
//
// It writes the secrets table directly rather than through the secret service,
// so it owns both its audit trail and its cache invalidation. The actor is
// req.UserID, which the ownership gate below proves is also the secret's owner.
func (s *versioningService) RollbackToVersion(ctx context.Context, req RollbackRequest) (*model.Secret, error) {
	actor := req.UserID.String()

	// Validate secret exists and user owns it. The read itself is unchecked
	// (admin scope); the explicit ownership check below is the actual gate.
	secret, err := s.secretRepo.Read(ctx, req.SecretID, model.NewAdminScope(req.UserID))
	if err != nil {
		s.log.LogAuditError(actor, "rollback_secret", "failed", "Secret not found", err)
		return nil, fmt.Errorf("secret not found: %w", err)
	}

	if secret.UserID != req.UserID {
		s.log.LogAuditError(actor, "rollback_secret", "denied", "User does not own this secret", nil)
		return nil, fmt.Errorf("user does not own this secret")
	}

	// Get the target version
	targetVersion, err := s.versionRepo.GetVersion(ctx, req.SecretID, req.TargetVersion)
	if err != nil {
		s.log.LogAuditError(actor, "rollback_secret", "failed", "Target version not found", err)
		return nil, fmt.Errorf("target version not found: %w", err)
	}

	// Decrypt the target version value
	decryptedValue, err := s.cryptoSvc.DecryptSecret(targetVersion.Value)
	if err != nil {
		s.log.WithError(err).Error("Failed to decrypt target version for rollback")
		s.log.LogAuditError(actor, "rollback_secret", "failed", "Failed to decrypt target version", err)
		return nil, fmt.Errorf("failed to decrypt target version: %w", err)
	}

	// The stored value is ciphertext and CreateVersion encrypts whatever it is
	// given, so the pre-rollback plaintext is what must be archived. Passing
	// the ciphertext straight through would store it doubly encrypted and the
	// pre-rollback state would be unrecoverable -- see § B46.
	currentPlaintext, err := s.cryptoSvc.DecryptSecret(secret.Value)
	if err != nil {
		s.log.WithError(err).Error("Failed to decrypt current value for rollback")
		s.log.LogAuditError(actor, "rollback_secret", "failed", "Failed to decrypt current value", err)
		return nil, fmt.Errorf("failed to decrypt current value: %w", err)
	}

	// Create new version from current state before rollback
	currentVersionReq := CreateVersionRequest{
		SecretID: req.SecretID,
		UserID:   req.UserID,
		Name:     secret.Name,
		Value:    currentPlaintext,
		Version:  secret.Version + 1,
	}

	_, err = s.CreateVersion(ctx, currentVersionReq)
	if err != nil {
		s.log.WithError(err).Error("Failed to create backup version during rollback")
		s.log.LogAuditError(actor, "rollback_secret", "failed", "Failed to create backup version", err)
		return nil, fmt.Errorf("failed to create backup version: %w", err)
	}

	// secretRepo.Update always expects ciphertext in the value column, so the
	// target version's plaintext has to be re-encrypted before it is written.
	// Storing the plaintext would leave the secret undecryptable on the next
	// read -- see § B46.
	encryptedValue, err := s.cryptoSvc.EncryptSecret(decryptedValue)
	if err != nil {
		s.log.WithError(err).Error("Failed to encrypt target version value for rollback")
		s.log.LogAuditError(actor, "rollback_secret", "failed", "Failed to encrypt target version value", err)
		return nil, fmt.Errorf("failed to encrypt target version value: %w", err)
	}

	// Update secret with target version data
	secret.Value = encryptedValue
	secret.Version = secret.Version + 2 // Increment beyond backup version

	err = s.secretRepo.Update(ctx, secret, model.NewOwnerScope(secret.VaultID, secret.UserID))
	if err != nil {
		s.log.WithError(err).Error("Failed to update secret during rollback")
		s.log.LogAuditError(actor, "rollback_secret", "failed", "Failed to update secret during rollback", err)
		return nil, fmt.Errorf("failed to update secret during rollback: %w", err)
	}

	// The write bypassed CachedSecretService, so evict every cached view
	// explicitly or the pre-rollback value keeps being served for the full TTL.
	s.invalidateCache(ctx, req.SecretID)

	s.log.LogAuditInfo(actor, "rollback_secret", "success",
		fmt.Sprintf("Secret %s rolled back to version %d (new version %d)", req.SecretID, req.TargetVersion, secret.Version))

	s.log.WithFields(map[string]any{
		"secret_id":      req.SecretID,
		"target_version": req.TargetVersion,
		"new_version":    secret.Version,
		"user_id":        req.UserID,
	}).Info("Secret rolled back successfully")

	// Return plaintext to the caller, matching CreateSecret. The ciphertext
	// above exists only for the repository write -- see § B46.
	secret.Value = decryptedValue

	return secret, nil
}
