package secrets

import (
	"bytes"
	"context"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"

	"rocketvault/common"
	"rocketvault/internal/logging"
	"rocketvault/internal/pwgen"
	"rocketvault/internal/repositories"
	vvalidation "rocketvault/internal/validation"
	"rocketvault/model"
)

// ErrSecretNotFound is returned when a secret does not exist or is not accessible
// within the requested scope (vault or user ownership).
var ErrSecretNotFound = errors.New("secret not found")

// ErrInvalidContentType is returned when a content type is not in the allowlist.
var ErrInvalidContentType = errors.New("unsupported content type")

// ErrSecretLifecycleDenied is returned when a secret exists but is disabled or
// outside its valid time window (not_before / expires_at).
var ErrSecretLifecycleDenied = errors.New("secret is disabled or outside its valid time window")

// ErrExportPassphraseRequired is returned when an export asks for encryption
// without supplying a passphrase. The export fails rather than quietly writing
// plaintext under a flag that promises encryption.
var ErrExportPassphraseRequired = errors.New("export encryption requested but no passphrase was supplied")

// ErrImportDataIsSealed is returned when import data is a passphrase-sealed
// export envelope. The caller must open it first; the service holds no
// passphrase and must never prompt for one.
var ErrImportDataIsSealed = errors.New("import data is an encrypted RocketVault export: decrypt it before importing")

// CreateSecretRequest represents a request to create a new secret.
type CreateSecretRequest struct {
	UserID      uuid.UUID
	VaultID     uuid.UUID // Target vault; defaults to the default vault when nil.
	Name        string
	Value       string
	Tags        []string
	ContentType string     // Optional media type (e.g. "application/json").
	Enabled     *bool      // Defaults to true when nil.
	ExpiresAt   *time.Time // Optional expiry time.
	NotBefore   *time.Time // Optional activation time.
	// PurgeProtection is optional; nil leaves the stored default (false).
	PurgeProtection *bool
}

// UpdateSecretRequest represents a request to update an existing secret.
type UpdateSecretRequest struct {
	SecretID    uuid.UUID
	Scope       model.Scope // Authorization scope for the read and the write.
	Name        *string     // Optional - nil means no change.
	Value       *string     // Optional - nil means no change.
	Tags        *[]string   // Optional - nil means no change.
	ContentType *string     // Optional - nil means no change.
	Enabled     *bool       // Optional - nil means no change.
	ExpiresAt   *time.Time  // Optional - nil means no change.
	NotBefore   *time.Time  // Optional - nil means no change.
	// PurgeProtection is optional; nil means no change.
	PurgeProtection *bool
}

// validContentTypes is the allowlist of accepted MIME types for secret content.
var validContentTypes = map[string]struct{}{
	"":                         {},
	"text/plain":               {},
	"application/json":         {},
	"application/xml":          {},
	"application/x-pem-file":   {},
	"application/x-pkcs12":     {},
	"application/octet-stream": {},
}

// validateContentType returns an error when ct is not in the allowlist.
func validateContentType(ct string) error {
	if _, ok := validContentTypes[ct]; !ok {
		return fmt.Errorf("%w: %q", ErrInvalidContentType, ct)
	}
	return nil
}

// GenerateSecretRequest represents a request to generate a random secret.
type GenerateSecretRequest struct {
	UserID       uuid.UUID
	VaultID      uuid.UUID // Target vault; defaults to the default vault when nil.
	Name         string
	Length       int
	UseSymbols   bool
	UseNumbers   bool
	UseUppercase bool
	UseLowercase bool
}

// ExportSecretsRequest represents a request to export secrets.
type ExportSecretsRequest struct {
	Scope       model.Scope // Authorization scope for the listing and the audit actor.
	Format      string      // "json" or "csv"
	FilterTags  []string    // Optional tag filter
	IncludeTags bool        // Include tags in export
	// Encrypt asks for a passphrase-sealed export. Passphrase must then be
	// non-empty; the export fails rather than falling back to plaintext.
	Encrypt bool
	// Passphrase seals the formatted export via common.SealExport. It is never
	// logged and never appears in an error message.
	Passphrase string
}

// ImportSecretsRequest represents a request to import secrets.
type ImportSecretsRequest struct {
	Scope     model.Scope // Authorization scope; its resolved vault id targets created secrets and its actor id is the audit actor.
	Data      []byte
	Format    string // "json" or "csv"
	Overwrite bool   // Overwrite existing secrets with same name
}

// ImportResult represents the result of importing secrets.
type ImportResult struct {
	ImportedCount int
	SkippedCount  int
	// FailedCount counts records that were attempted (create or overwrite)
	// but errored. It is reported separately from SkippedCount, which counts
	// records the import intentionally did not act on: a record missing a
	// name or value, or an existing name with Overwrite unset.
	FailedCount int
	TotalCount  int
	Errors      []string
}

// SecretService orchestrates secret management operations.
// It coordinates encryption, versioning, tagging, and storage
// while maintaining proper separation of concerns.
type SecretService interface {
	CreateSecret(ctx context.Context, req CreateSecretRequest) (*model.Secret, error)
	// GetSecret retrieves a decrypted secret authorized by scope.
	GetSecret(ctx context.Context, secretID uuid.UUID, scope model.Scope) (*model.Secret, error)
	// ListSecrets lists decrypted secrets authorized by scope. limit caps the
	// number of rows returned (0 means unlimited); offset skips this many
	// matching rows first and is ignored when limit is 0.
	ListSecrets(ctx context.Context, scope model.Scope, tags []string, limit, offset int) ([]model.Secret, error)
	// DeleteSecret soft-deletes a secret authorized by scope.
	DeleteSecret(ctx context.Context, secretID uuid.UUID, scope model.Scope) error
	// ListDeletedSecrets lists soft-deleted secrets authorized by scope.
	ListDeletedSecrets(ctx context.Context, scope model.Scope) ([]model.Secret, error)
	// UpdateSecret updates a secret authorized by req.Scope. The scoped
	// read is the check and the write repeats the same predicate, so there is
	// no TOCTOU window even if the row's vault changes between them.
	UpdateSecret(ctx context.Context, req UpdateSecretRequest) error
	GenerateSecret(ctx context.Context, req GenerateSecretRequest) (*model.Secret, error)
	ExportSecrets(ctx context.Context, req ExportSecretsRequest) ([]byte, error)
	ImportSecrets(ctx context.Context, req ImportSecretsRequest) (*ImportResult, error)
	// GetSecretVersions returns every version of a secret the scope
	// authorizes, with values decrypted. Use GetSecretVersionsMetadata to
	// merely enumerate versions -- see § B30.
	GetSecretVersions(ctx context.Context, secretID uuid.UUID, scope model.Scope) ([]model.SecretVersion, error)
	// GetSecretVersionsMetadata enumerates a secret's versions without values.
	GetSecretVersionsMetadata(ctx context.Context, secretID uuid.UUID, scope model.Scope) ([]model.SecretVersionMetadata, error)
	// GetSecretVersion returns one version the scope authorizes.
	GetSecretVersion(ctx context.Context, secretID uuid.UUID, version int, scope model.Scope) (*model.SecretVersion, error)
	// GetLatestSecretVersion returns the newest version the scope authorizes.
	GetLatestSecretVersion(ctx context.Context, secretID uuid.UUID, scope model.Scope) (*model.SecretVersion, error)
	// RecoverSecret restores a soft-deleted secret authorized by scope.
	RecoverSecret(ctx context.Context, secretID uuid.UUID, scope model.Scope) error
	// PurgeSecret permanently deletes a soft-deleted secret authorized by scope.
	PurgeSecret(ctx context.Context, secretID uuid.UUID, scope model.Scope) error
}

// secretService implements SecretService by coordinating multiple services.
type secretService struct {
	secretRepo     repositories.SecretRepositoryInterface
	cryptoService  CryptographyService
	versionService VersioningServiceInterface
	tagService     TagService
	logger         *logging.Logger
	// vaultRepo is optional. When set, PurgeSecret refuses to purge a secret
	// whose containing vault has purge protection enabled.
	vaultRepo repositories.VaultRepositoryInterface
	// globalPurgeProtection mirrors soft_delete.purge_protection. When true,
	// PurgeSecret refuses every purge instance-wide, regardless of this
	// secret's or its vault's own purge_protection flag.
	globalPurgeProtection bool
}

// SecretServiceConfig holds the dependencies for secret service.
type SecretServiceConfig struct {
	SecretRepository repositories.SecretRepositoryInterface
	CryptoService    CryptographyService
	VersionService   VersioningServiceInterface
	TagService       TagService
	Logger           *logging.Logger
	// VaultRepository is optional; it enables the vault-level purge-protection
	// cascade check in PurgeSecret.
	VaultRepository repositories.VaultRepositoryInterface
	// GlobalPurgeProtection mirrors soft_delete.purge_protection. See
	// secretService.globalPurgeProtection.
	GlobalPurgeProtection bool
}

// NewSecretService creates a new SecretService with the provided dependencies.
// It orchestrates secret operations by coordinating different services.
//
// Parameters:
//
//	config: Configuration containing all required dependencies.
//
// Returns:
//
//	A SecretService implementation for secret management operations.
func NewSecretService(config SecretServiceConfig) SecretService {
	return &secretService{
		secretRepo:            config.SecretRepository,
		cryptoService:         config.CryptoService,
		versionService:        config.VersionService,
		tagService:            config.TagService,
		logger:                config.Logger,
		vaultRepo:             config.VaultRepository,
		globalPurgeProtection: config.GlobalPurgeProtection,
	}
}

// CreateSecret creates a new secret with encryption and tagging.
// It orchestrates the creation workflow by coordinating encryption,
// storage, and tag assignment.
//
// Parameters:
//
//	ctx: The context for the operation.
//	req: The secret creation request.
//
// Returns:
//
//	The created secret or an error if creation fails.
func (s *secretService) CreateSecret(ctx context.Context, req CreateSecretRequest) (*model.Secret, error) {
	logrus.WithFields(logrus.Fields{
		"user_id": req.UserID.String(),
		"name":    req.Name,
	}).Info("Creating new secret")

	// Validate content type before any I/O.
	if err := validateContentType(req.ContentType); err != nil {
		return nil, err
	}

	// Encrypt before touching the DB — pure CPU work.
	encryptedValue, err := s.cryptoService.EncryptSecret(req.Value)
	if err != nil {
		s.logger.LogAuditError(req.UserID.String(), "create_secret", "failed", "Failed to encrypt secret", err)
		return nil, fmt.Errorf("failed to encrypt secret: %w", err)
	}

	// Default Enabled to true when the caller does not specify it.
	enabled := true
	if req.Enabled != nil {
		enabled = *req.Enabled
	}

	// Default the vault to the well-known default vault when not specified,
	// so legacy callers that do not set a vault keep targeting it.
	vaultID := req.VaultID
	if vaultID == uuid.Nil {
		vaultID = uuid.MustParse(model.DefaultVaultID)
	}

	secret := &model.Secret{
		ID:          uuid.New(),
		UserID:      req.UserID,
		VaultID:     vaultID,
		Name:        req.Name,
		Value:       encryptedValue,
		Version:     1,
		Tags:        req.Tags,
		ContentType: req.ContentType,
		CreatedAt:   time.Now(),
		Enabled:     enabled,
		ExpiresAt:   req.ExpiresAt,
		NotBefore:   req.NotBefore,
	}

	// Persist the secret. The repository's Create method inserts the secret
	// row and its tags as a single logical unit via its own db.DB handle.
	if err = s.secretRepo.Create(ctx, secret); err != nil {
		s.logger.LogAuditError(req.UserID.String(), "create_secret", "failed", "Failed to store secret", err)
		return nil, fmt.Errorf("failed to create secret: %w", err)
	}

	// Purge protection lives in its own column, so it is set as a follow-up
	// write rather than through Create's insert. Honor an explicit false the
	// same way UpdateSecret does, so "--purge-protection=false" is not
	// silently inert (B41).
	if req.PurgeProtection != nil {
		if err = s.secretRepo.SetPurgeProtection(ctx, secret.ID, *req.PurgeProtection); err != nil {
			s.logger.LogAuditError(req.UserID.String(), "create_secret", "failed", "Failed to set purge protection", err)
			return nil, fmt.Errorf("failed to set purge protection: %w", err)
		}
	}

	// Return plaintext to the caller.
	secret.Value = req.Value

	s.logger.LogAuditInfo(req.UserID.String(), "create_secret", "success",
		fmt.Sprintf("Secret created: %s", req.Name))
	logrus.WithFields(logrus.Fields{
		"secret_id": secret.ID.String(),
		"user_id":   req.UserID.String(),
		"name":      req.Name,
	}).Info("Secret created successfully")

	return secret, nil
}

// UpdateSecret updates a secret with versioning support, authorized by
// req.Scope. Authorization lives entirely in the scope: the scoped read is the
// check, and the write repeats the same predicate.
func (s *secretService) UpdateSecret(ctx context.Context, req UpdateSecretRequest) error {
	actor := req.Scope.ActorID().String()
	logrus.WithFields(logrus.Fields{
		"secret_id": req.SecretID.String(),
		"scope":     req.Scope.String(),
	}).Info("Updating secret")

	currentSecret, err := s.secretRepo.Read(ctx, req.SecretID, req.Scope)
	if err != nil {
		s.logger.LogAuditError(actor, "update_secret", "failed", "Secret not found or access denied", err)
		return fmt.Errorf("%w: %s", ErrSecretNotFound, err.Error())
	}

	currentValue, err := s.cryptoService.DecryptSecret(currentSecret.Value)
	if err != nil {
		s.logger.LogAuditError(actor, "update_secret", "failed", "Failed to decrypt current secret", err)
		return fmt.Errorf("failed to decrypt current secret: %w", err)
	}

	// CreateVersion gates on secret.UserID == UserID; pass the secret's real
	// owner here, not the scope's actor, so a legitimate vault-scoped update
	// by a non-owner member is not rejected by CreateVersion's internal
	// ownership check. Scope.ActorID is for audit only — never an access
	// predicate — so it must not be threaded into that gate.
	if _, err = s.versionService.CreateVersion(ctx, CreateVersionRequest{
		SecretID: currentSecret.ID,
		UserID:   currentSecret.UserID,
		Name:     currentSecret.Name,
		Value:    currentValue,
		Version:  currentSecret.Version,
	}); err != nil {
		s.logger.LogAuditError(actor, "update_secret", "failed", "Failed to create version", err)
		return fmt.Errorf("failed to create version: %w", err)
	}

	updatedSecret, err := applySecretUpdate(currentSecret, req, s.cryptoService.EncryptSecret)
	if err != nil {
		s.logger.LogAuditError(actor, "update_secret", "failed", "Failed to apply update", err)
		return err
	}

	if err := s.secretRepo.Update(ctx, updatedSecret, req.Scope); err != nil {
		s.logger.LogAuditError(actor, "update_secret", "failed", "Failed to update secret", err)
		return fmt.Errorf("failed to update secret: %w", err)
	}

	// Purge protection lives in its own column, so it is written separately
	// from the scoped Update above.
	if req.PurgeProtection != nil {
		if err := s.secretRepo.SetPurgeProtection(ctx, req.SecretID, *req.PurgeProtection); err != nil {
			s.logger.LogAuditError(actor, "update_secret", "failed", "Failed to set purge protection", err)
			return fmt.Errorf("failed to set purge protection: %w", err)
		}
	}

	if req.Tags != nil {
		if err := s.tagService.RemoveAllTags(ctx, req.SecretID); err != nil {
			s.logger.LogAuditError(actor, "update_secret", "failed", "Failed to remove old tags", err)
			return fmt.Errorf("failed to remove old tags: %w", err)
		}
		if len(*req.Tags) > 0 {
			if err := s.tagService.AddTags(ctx, req.SecretID, *req.Tags); err != nil {
				s.logger.LogAuditError(actor, "update_secret", "failed", "Failed to add new tags", err)
				return fmt.Errorf("failed to add new tags: %w", err)
			}
		}
	}

	s.logger.LogAuditInfo(actor, "update_secret", "success", fmt.Sprintf("Secret updated: %s", updatedSecret.Name))
	return nil
}

// GetSecret retrieves a secret authorized by scope, decrypts it, loads
// its tags, and enforces the lifecycle policy. The scoped read is the access
// check — there is no separate in-Go ownership comparison.
func (s *secretService) GetSecret(ctx context.Context, secretID uuid.UUID, scope model.Scope) (*model.Secret, error) {
	actor := scope.ActorID().String()

	secret, err := s.secretRepo.Read(ctx, secretID, scope)
	if err != nil {
		s.logger.LogAuditError(actor, "get_secret", "failed", "Secret not found or access denied", err)
		return nil, fmt.Errorf("%w", ErrSecretNotFound)
	}

	decryptedValue, err := s.cryptoService.DecryptSecret(secret.Value)
	if err != nil {
		s.logger.LogAuditError(actor, "get_secret", "failed", "Failed to decrypt secret", err)
		return nil, fmt.Errorf("failed to decrypt secret: %w", err)
	}
	secret.Value = decryptedValue

	tags, err := s.tagService.GetTags(ctx, secretID)
	if err != nil {
		s.logger.LogAuditError(actor, "get_secret", "failed", "Failed to load tags", err)
		return nil, fmt.Errorf("failed to load tags: %w", err)
	}
	secret.Tags = tags

	if !secret.IsAccessible() {
		s.logger.LogAuditError(actor, "get_secret", "denied", "Secret is disabled or outside its valid time window", nil)
		return nil, fmt.Errorf("%w", ErrSecretLifecycleDenied)
	}

	return secret, nil
}

// ListSecrets lists secrets authorized by scope, decrypting values and
// loading tags for each.
func (s *secretService) ListSecrets(ctx context.Context, scope model.Scope, tags []string, limit, offset int) ([]model.Secret, error) {
	actor := scope.ActorID().String()

	secretList, err := s.secretRepo.List(ctx, scope, repositories.SecretFilter{Tags: tags, Limit: limit, Offset: offset})
	if err != nil {
		s.logger.LogAuditError(actor, "list_secrets", "failed", "Failed to list secrets", err)
		return nil, fmt.Errorf("failed to list secrets: %w", err)
	}

	for i := range secretList {
		secret := &secretList[i]

		decryptedValue, decErr := s.cryptoService.DecryptSecret(secret.Value)
		if decErr != nil {
			s.logger.LogAuditError(actor, "list_secrets", "failed", "Failed to decrypt secret", decErr)
			return nil, fmt.Errorf("failed to decrypt secret %s: %w", secret.ID.String(), decErr)
		}
		secret.Value = decryptedValue

		secretTags, tagErr := s.tagService.GetTags(ctx, secret.ID)
		if tagErr != nil {
			s.logger.LogAuditError(actor, "list_secrets", "failed", "Failed to load tags", tagErr)
			return nil, fmt.Errorf("failed to load tags for secret %s: %w", secret.ID.String(), tagErr)
		}
		secret.Tags = secretTags
	}

	logrus.WithFields(logrus.Fields{
		"scope":        scope.String(),
		"secret_count": len(secretList),
	}).Debug("Listed secrets")

	return secretList, nil
}

// DeleteSecret soft-deletes a secret authorized by scope. The scoped read
// is the access check.
func (s *secretService) DeleteSecret(ctx context.Context, secretID uuid.UUID, scope model.Scope) error {
	actor := scope.ActorID().String()

	secret, err := s.secretRepo.Read(ctx, secretID, scope)
	if err != nil {
		s.logger.LogAuditError(actor, "delete_secret", "failed", "Secret not found or access denied", err)
		return fmt.Errorf("%w: %s", ErrSecretNotFound, err.Error())
	}

	if err := s.tagService.RemoveAllTags(ctx, secretID); err != nil {
		s.logger.LogAuditError(actor, "delete_secret", "failed", "Failed to remove tags", err)
		return fmt.Errorf("failed to remove tags: %w", err)
	}

	if err := s.secretRepo.SoftDelete(ctx, secretID); err != nil {
		s.logger.LogAuditError(actor, "delete_secret", "failed", "Failed to soft delete secret", err)
		return fmt.Errorf("failed to soft delete secret: %w", err)
	}

	s.logger.LogAuditInfo(actor, "delete_secret", "success", fmt.Sprintf("Secret soft deleted: %s", secret.Name))
	return nil
}

// ListDeletedSecrets lists soft-deleted secrets authorized by scope. The
// filter runs in SQL rather than pulling every secret into memory to discard
// most of them.
func (s *secretService) ListDeletedSecrets(ctx context.Context, scope model.Scope) ([]model.Secret, error) {
	secretList, err := s.secretRepo.List(ctx, scope, repositories.SecretFilter{OnlyDeleted: true})
	if err != nil {
		return nil, fmt.Errorf("failed to list deleted secrets: %w", err)
	}
	return secretList, nil
}

// GetSecretVersions returns every version of a secret the scope authorizes.
func (s *secretService) GetSecretVersions(ctx context.Context, secretID uuid.UUID, scope model.Scope) ([]model.SecretVersion, error) {
	return s.versionService.GetVersions(ctx, secretID, scope)
}

// GetSecretVersionsMetadata enumerates a secret's versions without values.
func (s *secretService) GetSecretVersionsMetadata(ctx context.Context, secretID uuid.UUID, scope model.Scope) ([]model.SecretVersionMetadata, error) {
	return s.versionService.GetVersionsMetadata(ctx, secretID, scope)
}

// GetSecretVersion returns one version the scope authorizes.
func (s *secretService) GetSecretVersion(ctx context.Context, secretID uuid.UUID, version int, scope model.Scope) (*model.SecretVersion, error) {
	return s.versionService.GetVersion(ctx, secretID, version, scope)
}

// GetLatestSecretVersion returns the newest version the scope authorizes.
func (s *secretService) GetLatestSecretVersion(ctx context.Context, secretID uuid.UUID, scope model.Scope) (*model.SecretVersion, error) {
	return s.versionService.GetLatestVersion(ctx, secretID, scope)
}

// GenerateSecret generates a random password or secret with specified criteria.
// It creates a new secret with a randomly generated value.
//
// Parameters:
//
//	ctx: The context for the operation.
//	req: The secret generation request with password criteria.
//
// Returns:
//
//	The created secret with generated value or an error if generation fails.
func (s *secretService) GenerateSecret(ctx context.Context, req GenerateSecretRequest) (*model.Secret, error) {
	logrus.WithFields(logrus.Fields{
		"user_id": req.UserID.String(),
		"name":    req.Name,
		"length":  req.Length,
	}).Info("Generating random secret")

	// Validate length
	if req.Length < 8 || req.Length > 128 {
		s.logger.LogAuditError(req.UserID.String(), "generate_secret", "failed", "Invalid length: must be between 8 and 128", nil)
		return nil, fmt.Errorf("invalid length: must be between 8 and 128")
	}

	// Ensure at least one character type is selected
	if !req.UseSymbols && !req.UseNumbers && !req.UseUppercase && !req.UseLowercase {
		s.logger.LogAuditError(req.UserID.String(), "generate_secret", "failed", "At least one character type must be selected", nil)
		return nil, fmt.Errorf("at least one character type must be selected")
	}

	// Generate random password using the shared, unbiased pwgen generator
	// (B45 — the old modulo-based selection here skewed character frequency).
	generatedValue, err := pwgen.Generate(pwgen.Options{
		Length:  req.Length,
		Upper:   req.UseUppercase,
		Lower:   req.UseLowercase,
		Numbers: req.UseNumbers,
		Special: req.UseSymbols,
	})
	if err != nil {
		s.logger.LogAuditError(req.UserID.String(), "generate_secret", "failed", "Failed to generate random password", err)
		return nil, fmt.Errorf("failed to generate random password: %w", err)
	}

	// Create secret with generated value. Thread the target vault through so
	// the generated secret lands in the resolved vault; CreateSecret resolves
	// uuid.Nil to the default vault, matching the legacy behaviour.
	createReq := CreateSecretRequest{
		UserID:  req.UserID,
		VaultID: req.VaultID,
		Name:    req.Name,
		Value:   generatedValue,
		Tags:    []string{"generated"},
	}

	secret, err := s.CreateSecret(ctx, createReq)
	if err != nil {
		s.logger.LogAuditError(req.UserID.String(), "generate_secret", "failed", "Failed to create secret with generated value", err)
		return nil, fmt.Errorf("failed to create secret: %w", err)
	}

	s.logger.LogAuditInfo(req.UserID.String(), "generate_secret", "success",
		fmt.Sprintf("Generated secret: %s (length: %d)", req.Name, req.Length))
	logrus.WithFields(logrus.Fields{
		"secret_id": secret.ID.String(),
		"user_id":   req.UserID.String(),
		"name":      req.Name,
		"length":    req.Length,
	}).Info("Random secret generated successfully")

	return secret, nil
}

// accessibleOnly drops disabled, expired and not-yet-active secrets, matching
// what GetSecret refuses to return. Export must not be a side door around it.
func accessibleOnly(in []model.Secret) []model.Secret {
	out := make([]model.Secret, 0, len(in))
	for i := range in {
		if in[i].IsAccessible() {
			out = append(out, in[i])
		}
	}
	return out
}

// ExportSecrets exports secrets in JSON or CSV format.
// It retrieves secrets for the user and formats them according to the request.
//
// Parameters:
//
//	ctx: The context for the operation.
//	req: The export request with format and filter options.
//
// Returns:
//
//	The exported data as bytes or an error if export fails.
func (s *secretService) ExportSecrets(ctx context.Context, req ExportSecretsRequest) ([]byte, error) {
	logrus.WithFields(logrus.Fields{
		"user_id": req.Scope.ActorID().String(),
		"format":  req.Format,
		"tags":    req.FilterTags,
	}).Info("Exporting secrets")

	// Validate format
	if req.Format != "json" && req.Format != "csv" {
		s.logger.LogAuditError(req.Scope.ActorID().String(), "export_secrets", "failed", "Invalid format: must be json or csv", nil)
		return nil, fmt.Errorf("invalid format: must be json or csv")
	}

	// List secrets with optional tag filter, authorized by scope. Export must
	// see every matching secret, so it is never paginated.
	secretsList, err := s.ListSecrets(ctx, req.Scope, req.FilterTags, 0, 0)
	if err != nil {
		s.logger.LogAuditError(req.Scope.ActorID().String(), "export_secrets", "failed", "Failed to list secrets", err)
		return nil, fmt.Errorf("failed to list secrets: %w", err)
	}
	secretsList = accessibleOnly(secretsList)

	var data []byte
	if req.Format == "json" {
		// Export as JSON
		type exportSecret struct {
			Name  string   `json:"name"`
			Value string   `json:"value"`
			Tags  []string `json:"tags,omitempty"`
		}

		exportData := make([]exportSecret, len(secretsList))
		for i, secret := range secretsList {
			exportData[i] = exportSecret{
				Name:  secret.Name,
				Value: secret.Value,
			}
			if req.IncludeTags {
				exportData[i].Tags = secret.Tags
			}
		}

		data, err = json.MarshalIndent(exportData, "", "  ")
		if err != nil {
			s.logger.LogAuditError(req.Scope.ActorID().String(), "export_secrets", "failed", "Failed to marshal JSON", err)
			return nil, fmt.Errorf("failed to marshal JSON: %w", err)
		}
	} else {
		// Export as CSV via encoding/csv, which quotes and escapes embedded
		// quotes, commas and newlines correctly. Hand-rolled string
		// concatenation could not do this safely (B42). Name/Value are
		// escapeCR'd first so an embedded CR round-trips too — encoding/csv
		// itself silently converts CR to LF with no way to disable that (B49).
		var buf bytes.Buffer
		writer := csv.NewWriter(&buf)

		header := []string{"name", "value"}
		if req.IncludeTags {
			header = append(header, "tags")
		}
		if err := writer.Write(header); err != nil {
			s.logger.LogAuditError(req.Scope.ActorID().String(), "export_secrets", "failed", "Failed to write CSV header", err)
			return nil, fmt.Errorf("failed to write CSV header: %w", err)
		}

		for _, secret := range secretsList {
			row := []string{csvFormulaGuard(escapeCR(secret.Name)), csvFormulaGuard(escapeCR(secret.Value))}
			if req.IncludeTags {
				tagsField, tagErr := csvEncodeTags(secret.Tags)
				if tagErr != nil {
					s.logger.LogAuditError(req.Scope.ActorID().String(), "export_secrets", "failed", "Failed to encode tags", tagErr)
					return nil, fmt.Errorf("failed to encode tags for %q: %w", secret.Name, tagErr)
				}
				row = append(row, csvFormulaGuard(tagsField))
			}
			if err := writer.Write(row); err != nil {
				s.logger.LogAuditError(req.Scope.ActorID().String(), "export_secrets", "failed", "Failed to write CSV row", err)
				return nil, fmt.Errorf("failed to write CSV row for %q: %w", secret.Name, err)
			}
		}

		writer.Flush()
		if err := writer.Error(); err != nil {
			s.logger.LogAuditError(req.Scope.ActorID().String(), "export_secrets", "failed", "Failed to flush CSV writer", err)
			return nil, fmt.Errorf("failed to flush CSV writer: %w", err)
		}
		data = buf.Bytes()
	}

	// Seal after formatting, so a CSV export is sealed too. The file on disk is
	// then the JSON envelope and the chosen format describes its payload.
	if req.Encrypt || req.Passphrase != "" {
		if req.Passphrase == "" {
			s.logger.LogAuditError(req.Scope.ActorID().String(), "export_secrets", "failed",
				"Encryption requested without a passphrase", nil)
			return nil, ErrExportPassphraseRequired
		}
		sealed, sealErr := common.SealExport(data, req.Passphrase)
		if sealErr != nil {
			s.logger.LogAuditError(req.Scope.ActorID().String(), "export_secrets", "failed",
				"Failed to seal export", sealErr)
			return nil, fmt.Errorf("failed to encrypt export: %w", sealErr)
		}
		data = sealed
	}

	s.logger.LogAuditInfo(req.Scope.ActorID().String(), "export_secrets", "success",
		fmt.Sprintf("Exported %d secrets in %s format (encrypted: %v)", len(secretsList), req.Format, req.Encrypt || req.Passphrase != ""))
	logrus.WithFields(logrus.Fields{
		"user_id":      req.Scope.ActorID().String(),
		"format":       req.Format,
		"secret_count": len(secretsList),
		"encrypted":    req.Encrypt || req.Passphrase != "",
	}).Info("Secrets exported successfully")

	return data, nil
}

// ImportSecrets imports secrets from JSON or CSV format.
// It parses the data and creates secrets for the user.
//
// Parameters:
//
//	ctx: The context for the operation.
//	req: The import request with data and options.
//
// Returns:
//
//	The import result with counts and errors, or an error if import fails.
func (s *secretService) ImportSecrets(ctx context.Context, req ImportSecretsRequest) (*ImportResult, error) {
	logrus.WithFields(logrus.Fields{
		"user_id":   req.Scope.ActorID().String(),
		"format":    req.Format,
		"overwrite": req.Overwrite,
	}).Info("Importing secrets")

	result := &ImportResult{
		Errors: []string{},
	}

	// Validate format
	if req.Format != "json" && req.Format != "csv" {
		s.logger.LogAuditError(req.Scope.ActorID().String(), "import_secrets", "failed", "Invalid format: must be json or csv", nil)
		return nil, fmt.Errorf("invalid format: must be json or csv")
	}

	// A sealed export is opened by the caller, which is the only layer that can
	// prompt for a passphrase. Refusing here beats a confusing parse error.
	if common.IsSealedExport(req.Data) {
		s.logger.LogAuditError(req.Scope.ActorID().String(), "import_secrets", "failed",
			"Import data is an encrypted export", nil)
		return nil, ErrImportDataIsSealed
	}

	type importSecret struct {
		Name  string   `json:"name"`
		Value string   `json:"value"`
		Tags  []string `json:"tags,omitempty"`
	}

	var secretsToImport []importSecret

	if req.Format == "json" {
		// Parse JSON
		if err := json.Unmarshal(req.Data, &secretsToImport); err != nil {
			s.logger.LogAuditError(req.Scope.ActorID().String(), "import_secrets", "failed", "Failed to parse JSON", err)
			return nil, fmt.Errorf("failed to parse JSON: %w", err)
		}
	} else {
		// Parse CSV via encoding/csv, which handles doubled-quote escaping
		// and embedded newlines inside a quoted field correctly — the
		// hand-rolled parseCSVLine could not (B42).
		reader := csv.NewReader(strings.NewReader(string(req.Data)))
		reader.FieldsPerRecord = 0 // Locked to the header row's own column count.

		header, err := reader.Read()
		if err != nil && err != io.EOF {
			s.logger.LogAuditError(req.Scope.ActorID().String(), "import_secrets", "failed", "Failed to parse CSV header", err)
			return nil, fmt.Errorf("failed to parse CSV: %w", err)
		}
		hasTags := len(header) > 2

		lineNum := 1
		for {
			record, readErr := reader.Read()
			if readErr == io.EOF {
				break
			}
			lineNum++
			if readErr != nil {
				// A row with the wrong number of fields, or an unescaped
				// quote, is reported here instead of silently mis-split —
				// the defect this replaces (B42). No "Line N:" prefix here:
				// our lineNum counts CSV records, not physical lines, and a
				// record can legitimately span multiple physical lines (an
				// embedded newline inside a quoted field), so our count can
				// under-count relative to the real line. readErr is a
				// *csv.ParseError whose own Error() already includes the
				// correct physical line number (e.g. "record on line 4:
				// wrong number of fields") — prepending our own would risk a
				// second, conflicting number in the same message.
				result.Errors = append(result.Errors, fmt.Sprintf("invalid CSV: %v", readErr))
				continue
			}
			if len(record) < 2 {
				result.Errors = append(result.Errors, fmt.Sprintf("Line %d: invalid format", lineNum))
				continue
			}

			secret := importSecret{
				Name:  unescapeCR(csvFormulaUnguard(record[0])),
				Value: unescapeCR(csvFormulaUnguard(record[1])),
			}
			if hasTags && len(record) > 2 && record[2] != "" {
				tags, tagErr := csvDecodeTags(csvFormulaUnguard(record[2]))
				if tagErr != nil {
					result.Errors = append(result.Errors, fmt.Sprintf("Line %d: invalid tags: %v", lineNum, tagErr))
					continue
				}
				secret.Tags = tags
			}
			secretsToImport = append(secretsToImport, secret)
		}
	}

	result.TotalCount = len(secretsToImport)

	// Import each secret. A record whose name already exists in the target
	// vault is only overwritten when the caller asked for it; otherwise it is
	// skipped and counted separately from a record that fails outright, so
	// the printed summary distinguishes "chose not to" from "tried and
	// failed".
	for _, importSec := range secretsToImport {
		if importSec.Name == "" || importSec.Value == "" {
			result.Errors = append(result.Errors, "Secret missing name or value")
			result.SkippedCount++
			continue
		}

		// Apply the same name, value-size and tag-count rules as create, so
		// import cannot store what create refuses.
		if vErr := vvalidation.ValidateSecretCreate(vvalidation.SecretCreateRequest{
			Name:  importSec.Name,
			Value: importSec.Value,
			Tags:  importSec.Tags,
		}); vErr != nil {
			result.Errors = append(result.Errors, fmt.Sprintf("Invalid '%s': %v", importSec.Name, vErr))
			result.FailedCount++
			continue
		}

		existing, err := s.secretRepo.FindByName(ctx, importSec.Name, req.Scope)
		if err != nil && !errors.Is(err, repositories.ErrNotFound) {
			result.Errors = append(result.Errors, fmt.Sprintf("Failed to look up '%s': %v", importSec.Name, err))
			result.FailedCount++
			continue
		}

		if existing != nil {
			if !req.Overwrite {
				result.SkippedCount++
				continue
			}

			value := importSec.Value
			updateReq := UpdateSecretRequest{
				SecretID: existing.ID,
				Scope:    req.Scope,
				Value:    &value,
			}
			// Tags is nil-means-no-change. Only set it when the import
			// record actually specified tags, so a record that says
			// nothing about tags does not wipe the existing ones.
			if importSec.Tags != nil {
				updateReq.Tags = &importSec.Tags
			}
			if err := s.UpdateSecret(ctx, updateReq); err != nil {
				result.Errors = append(result.Errors, fmt.Sprintf("Failed to overwrite '%s': %v", importSec.Name, err))
				result.FailedCount++
			} else {
				result.ImportedCount++
			}
			continue
		}

		createReq := CreateSecretRequest{
			UserID:  req.Scope.ActorID(),
			VaultID: req.Scope.ResolvedVaultID(),
			Name:    importSec.Name,
			Value:   importSec.Value,
			Tags:    importSec.Tags,
		}

		if _, err := s.CreateSecret(ctx, createReq); err != nil {
			result.Errors = append(result.Errors, fmt.Sprintf("Failed to import '%s': %v", importSec.Name, err))
			result.FailedCount++
		} else {
			result.ImportedCount++
		}
	}

	s.logger.LogAuditInfo(req.Scope.ActorID().String(), "import_secrets", "success",
		fmt.Sprintf("Imported %d/%d secrets (%d skipped, %d failed)",
			result.ImportedCount, result.TotalCount, result.SkippedCount, result.FailedCount))
	logrus.WithFields(logrus.Fields{
		"user_id":        req.Scope.ActorID().String(),
		"format":         req.Format,
		"imported_count": result.ImportedCount,
		"skipped_count":  result.SkippedCount,
		"failed_count":   result.FailedCount,
		"total_count":    result.TotalCount,
	}).Info("Secrets import completed")

	return result, nil
}

// softDeletedInScope reports whether secretID names a soft-deleted secret the
// scope authorizes. It replaces the handler-level IsSecretSoftDeleted* checks,
// which used a different scope from the mutation that followed them.
func (s *secretService) softDeletedInScope(ctx context.Context, secretID uuid.UUID, scope model.Scope) (bool, error) {
	deleted, err := s.secretRepo.List(ctx, scope, repositories.SecretFilter{OnlyDeleted: true})
	if err != nil {
		return false, fmt.Errorf("failed to list deleted secrets: %w", err)
	}
	for _, secret := range deleted {
		if secret.ID == secretID {
			return true, nil
		}
	}
	return false, nil
}

// RecoverSecret restores a soft-deleted secret authorized by scope.
func (s *secretService) RecoverSecret(ctx context.Context, secretID uuid.UUID, scope model.Scope) error {
	inScope, err := s.softDeletedInScope(ctx, secretID, scope)
	if err != nil {
		return err
	}
	if !inScope {
		s.logger.LogAuditError(scope.ActorID().String(), "recover_secret", "failed",
			"Secret not found in deleted state within scope", nil)
		return fmt.Errorf("%w", ErrSecretNotFound)
	}
	if err := s.secretRepo.RecoverSecret(ctx, secretID); err != nil {
		return fmt.Errorf("failed to recover secret: %w", err)
	}
	s.logger.LogAuditInfo(scope.ActorID().String(), "recover_secret", "success",
		fmt.Sprintf("Secret recovered: %s", secretID))
	return nil
}

// PurgeSecret permanently deletes a soft-deleted secret authorized by scope.
func (s *secretService) PurgeSecret(ctx context.Context, secretID uuid.UUID, scope model.Scope) error {
	if s.globalPurgeProtection {
		s.logger.LogAuditError(scope.ActorID().String(), "purge_secret", "failed",
			"Global purge protection is enabled", nil)
		return repositories.ErrGlobalPurgeProtectionEnabled
	}

	inScope, err := s.softDeletedInScope(ctx, secretID, scope)
	if err != nil {
		return err
	}
	if !inScope {
		s.logger.LogAuditError(scope.ActorID().String(), "purge_secret", "failed",
			"Secret not found in deleted state within scope", nil)
		return fmt.Errorf("%w", ErrSecretNotFound)
	}

	// Vault-level purge protection cascades to the secrets the vault contains,
	// so a protected vault blocks the per-item purge path too. This check fails
	// closed: for a secret with no flag of its own it is the only protection
	// layer, so a vault that cannot be read blocks the purge rather than
	// silently skipping the check.
	if s.vaultRepo != nil && scope.VaultID() != uuid.Nil {
		vault, err := s.vaultRepo.ReadByID(ctx, scope.VaultID())
		if err != nil {
			s.logger.LogAuditError(scope.ActorID().String(), "purge_secret", "failed",
				"Failed to check vault purge protection", err)
			return fmt.Errorf("failed to check vault purge protection: %w", err)
		}
		if vault.PurgeProtection {
			s.logger.LogAuditError(scope.ActorID().String(), "purge_secret", "failed",
				"Vault has purge protection enabled", nil)
			return repositories.ErrSecretPurgeProtected
		}
	}

	if err := s.secretRepo.PurgeSecret(ctx, secretID); err != nil {
		return fmt.Errorf("failed to purge secret: %w", err)
	}
	s.logger.LogAuditInfo(scope.ActorID().String(), "purge_secret", "success",
		fmt.Sprintf("Secret purged: %s", secretID))
	return nil
}

// csvFormulaGuard prefixes a single quote to a cell a spreadsheet would
// evaluate as a formula. A cell already starting with a quote is prefixed too,
// so csvFormulaUnguard can strip exactly one quote and restore every input.
func csvFormulaGuard(s string) string {
	if s == "" {
		return s
	}
	switch s[0] {
	case '=', '+', '-', '@', '\t', '\'':
		return "'" + s
	}
	return s
}

// csvFormulaUnguard reverses csvFormulaGuard by stripping one leading quote.
func csvFormulaUnguard(s string) string {
	if strings.HasPrefix(s, "'") {
		return s[1:]
	}
	return s
}

// crEscape is the sentinel byte escapeCR/unescapeCR use to hide a literal CR
// from encoding/csv. Chosen because it is vanishingly unlikely to occur in a
// secret name, value or tag; escapeCR escapes any literal occurrence of it
// too, so the transform is still correct (bijective) on the rare input that
// already contains one.
const crEscape = '\x00'

// escapeCR makes s safe to round-trip through encoding/csv, which
// unconditionally converts an embedded "\r\n" (or a bare "\r") to "\n"
// inside a quoted field, with no way to disable it (B49). It replaces every
// literal CR with crEscape+'r', and escapes any literal crEscape byte
// already in s as crEscape+crEscape, so unescapeCR can reverse it exactly
// regardless of what s contains. A LF needs no escaping — encoding/csv
// already preserves it correctly.
func escapeCR(s string) string {
	if !strings.ContainsAny(s, "\r\x00") {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case crEscape:
			b.WriteByte(crEscape)
			b.WriteByte(crEscape)
		case '\r':
			b.WriteByte(crEscape)
			b.WriteByte('r')
		default:
			b.WriteByte(s[i])
		}
	}
	return b.String()
}

// unescapeCR reverses escapeCR. A malformed escape (crEscape followed by
// neither crEscape nor 'r') cannot come from escapeCR's own output; it is
// preserved byte-for-byte rather than silently dropped, so no case can lose
// data even if fed input escapeCR never produced.
func unescapeCR(s string) string {
	if !strings.ContainsRune(s, crEscape) {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		if s[i] == crEscape && i+1 < len(s) {
			i++
			switch s[i] {
			case crEscape:
				b.WriteByte(crEscape)
			case 'r':
				b.WriteByte('\r')
			default:
				b.WriteByte(crEscape)
				b.WriteByte(s[i])
			}
			continue
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

// csvEncodeTags packs a secret's tags into a single CSV field using
// encoding/csv itself, so a tag containing a comma or a quote survives
// being embedded in the outer record (B42). Each tag is escapeCR'd first so
// an embedded CR survives too (B49). Note: a tags slice containing exactly
// one empty-string tag ([]string{""}) encodes to the empty string, which
// import treats as "no tags present" — that one case does not round-trip.
func csvEncodeTags(tags []string) (string, error) {
	if len(tags) == 0 {
		return "", nil
	}
	escaped := make([]string, len(tags))
	for i, t := range tags {
		escaped[i] = escapeCR(t)
	}
	var buf bytes.Buffer
	w := csv.NewWriter(&buf)
	if err := w.Write(escaped); err != nil {
		return "", err
	}
	w.Flush()
	if err := w.Error(); err != nil {
		return "", err
	}
	return strings.TrimSuffix(buf.String(), "\n"), nil
}

// csvDecodeTags reverses csvEncodeTags, including each tag's escapeCR
// (B49). An empty field means no tags (B42).
func csvDecodeTags(field string) ([]string, error) {
	if field == "" {
		return nil, nil
	}
	r := csv.NewReader(strings.NewReader(field))
	tags, err := r.Read()
	if err != nil {
		return nil, err
	}
	for i, t := range tags {
		tags[i] = unescapeCR(t)
	}
	return tags, nil
}
