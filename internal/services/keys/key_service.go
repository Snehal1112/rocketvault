// Package keys provides key management services for the password manager.
// It handles cryptographic key generation, lifecycle, and access control
// while maintaining proper separation of concerns.
package keys

import (
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"

	"rocketvault/common"
	"rocketvault/internal/crypto"
	"rocketvault/internal/keycache"
	"rocketvault/internal/logging"
	"rocketvault/internal/repositories"
	"rocketvault/internal/signing"
	"rocketvault/model"
)

// ErrKeyNotFound is returned when a key does not exist or is not accessible
// within the requested scope (vault or user ownership).
var ErrKeyNotFound = errors.New("key not found")

// ErrKeyLifecycleDenied is returned when a key exists but is disabled or
// outside its valid time window (not_before / expires_at).
var ErrKeyLifecycleDenied = errors.New("key is disabled or outside its valid time window")

// ErrKeyForbidden is returned when the caller does not own the key or the key
// does not belong to the requested vault.
var ErrKeyForbidden = errors.New("forbidden: key access denied")

// ErrKeyRevoked is returned when the caller attempts to use a revoked key.
var ErrKeyRevoked = errors.New("key is revoked")

// ErrUnsupportedAlgorithm is returned when an unsupported algorithm is requested.
var ErrUnsupportedAlgorithm = errors.New("unsupported algorithm")

// ErrInvalidJWK is returned when ImportKey's JWK input is malformed, has no
// private key material, or is an unsupported key type.
var ErrInvalidJWK = errors.New("invalid jwk")

// CreateKeyRequest represents a request to create a new cryptographic key.
type CreateKeyRequest struct {
	Name      string
	Type      string // "RSA" or "ECDSA"
	Bits      int    // For RSA: 2048, 3072, or 4096
	Curve     string // For ECDSA: P-256, P-384, P-521
	Tags      []string
	UserID    uuid.UUID
	VaultID   uuid.UUID // Target vault; defaults to the default vault when nil.
	Enabled   *bool     // Defaults to true if nil.
	ExpiresAt *time.Time
	NotBefore *time.Time
	// PurgeProtection is optional: nil leaves the stored default alone, true
	// enables purge protection on the freshly created key.
	PurgeProtection *bool
}

// ImportKeyRequest represents a request to import externally-generated key
// material supplied as a JWK.
type ImportKeyRequest struct {
	Name            string
	JWK             []byte // raw JWK JSON, parsed via signing.ParseJWK
	Tags            []string
	UserID          uuid.UUID
	VaultID         uuid.UUID // Target vault; defaults to the default vault when nil.
	Enabled         *bool     // Defaults to true if nil.
	ExpiresAt       *time.Time
	NotBefore       *time.Time
	PurgeProtection *bool
}

// resolveVaultID returns the requested vault id, falling back to the default
// vault when the caller did not specify one.
func resolveVaultID(vaultID uuid.UUID) uuid.UUID {
	if vaultID == uuid.Nil {
		return uuid.MustParse(model.DefaultVaultID)
	}
	return vaultID
}

// CreateKeyResult represents the result of creating a new key.
type CreateKeyResult struct {
	KeyID     uuid.UUID
	Name      string
	Type      string
	Tags      []string
	CreatedAt time.Time
}

// UpdateKeyRequest represents a request to update an existing key.
type UpdateKeyRequest struct {
	KeyID     uuid.UUID
	Scope     model.Scope // Authorization scope for the read and the write.
	Name      *string     // Optional - nil means no change
	Tags      []string    // Optional - nil means no change; empty slice clears
	Revoked   *bool       // Optional - nil means no change
	Enabled   *bool       // Optional - nil means no change
	ExpiresAt *time.Time  // Optional - nil means no change
	NotBefore *time.Time  // Optional - nil means no change
	// PurgeProtection is optional - nil means no change.
	PurgeProtection *bool
}

// KeyService handles cryptographic key management operations.
// It orchestrates key generation, validation, and access control
// while delegating storage to repositories.
type KeyService interface {
	CreateRSAKey(ctx context.Context, req CreateKeyRequest) (*CreateKeyResult, error)
	CreateECDSAKey(ctx context.Context, req CreateKeyRequest) (*CreateKeyResult, error)
	// CreateOctKey creates a symmetric AES key. HSM-only — see
	// crypto.ErrOctKeysRequireHSM.
	CreateOctKey(ctx context.Context, req CreateKeyRequest) (*CreateKeyResult, error)
	// ImportKey stores externally-generated key material supplied as a JWK.
	// The imported key is subject to the same non-extractability guarantee as
	// a generated key of the same backend -- see
	// docs/superpowers/specs/2026-08-25-key-export-decision-record.md.
	ImportKey(ctx context.Context, req ImportKeyRequest) (*CreateKeyResult, error)
	// GetKey retrieves a key authorized by scope and enforces its lifecycle.
	GetKey(ctx context.Context, keyID uuid.UUID, scope model.Scope) (*model.Key, error)
	// ListKeys lists keys authorized by scope and narrowed by filter.
	ListKeys(ctx context.Context, scope model.Scope, filter model.KeyFilter) ([]model.Key, error)
	// UpdateKey updates a key authorized by req.Scope.
	UpdateKey(ctx context.Context, req UpdateKeyRequest) error
	// DeleteKey soft-deletes a key authorized by scope.
	DeleteKey(ctx context.Context, keyID uuid.UUID, scope model.Scope) (*model.Key, error)
	// RotateKey rotates a key authorized by scope.
	RotateKey(ctx context.Context, keyID uuid.UUID, scope model.Scope) (*CreateKeyResult, error)
	// ListDeletedKeys lists soft-deleted keys authorized by scope.
	ListDeletedKeys(ctx context.Context, scope model.Scope) ([]model.Key, error)
	// RecoverKey restores a soft-deleted key authorized by scope.
	RecoverKey(ctx context.Context, keyID uuid.UUID, scope model.Scope) error
	// PurgeKey permanently deletes a soft-deleted key authorized by scope.
	PurgeKey(ctx context.Context, keyID uuid.UUID, scope model.Scope) error
	ValidateKeyAccess(ctx context.Context, keyID, userID uuid.UUID, role string) error
	// GetKeyRotationPolicy retrieves the rotation policy for keyID, authorized
	// by scope against the parent key.
	GetKeyRotationPolicy(ctx context.Context, keyID uuid.UUID, scope model.Scope) (*model.KeyRotationPolicy, error)
	// UpsertKeyRotationPolicy creates or replaces the rotation policy for
	// keyID, authorized by scope against the parent key.
	UpsertKeyRotationPolicy(ctx context.Context, keyID uuid.UUID, scope model.Scope, req model.UpsertKeyRotationPolicyRequest) (*model.KeyRotationPolicy, error)
	// DeleteKeyRotationPolicy removes the rotation policy for keyID,
	// authorized by scope against the parent key.
	DeleteKeyRotationPolicy(ctx context.Context, keyID uuid.UUID, scope model.Scope) error
	// ListKeyRotationPolicies lists every rotation policy set in scope's
	// vault, each paired with its parent key's name, for the "keys
	// rotation-policy list" report. Keys with no policy set are absent.
	ListKeyRotationPolicies(ctx context.Context, scope model.Scope) ([]model.KeyRotationPolicyWithKeyName, error)
	// ListDueKeyRotationPolicies lists enabled rotation policies in scope's
	// vault whose next rotation has already passed, for the "keys
	// rotation-policy status" due section. This is the same query the
	// background scheduler sweeps (see rotation_executor.go), exposed here
	// read-only for CLI reporting.
	ListDueKeyRotationPolicies(ctx context.Context, scope model.Scope) ([]model.KeyRotationPolicy, error)
	// ListKeyVersions returns keyID's version history, authorized by scope
	// against the parent key. Resolving the owner from the authorized key
	// (not the caller's own id) keeps vault-member access consistent with
	// GetKey, since KeyRepository.ListVersions filters on owner with no
	// vault predicate.
	ListKeyVersions(ctx context.Context, keyID uuid.UUID, scope model.Scope) ([]model.KeyVersion, error)
	// GetKeyVersion returns metadata for one version of keyID, authorized
	// by scope against the parent key.
	GetKeyVersion(ctx context.Context, keyID uuid.UUID, version int, scope model.Scope) (*model.KeyVersion, error)
	// GetPublicJWK returns the public components of one version of keyID,
	// authorized by scope against the parent key. version 0 means the key's
	// current version.
	//
	// This lives in the service layer, not the handler, because the material
	// is master-key-encrypted in storage and api/ has no decryption
	// precedent. An HSM-backed key yields an empty PublicJWK and a nil error.
	GetPublicJWK(ctx context.Context, keyID uuid.UUID, version int, scope model.Scope) (*model.PublicJWK, error)
}

// keyService implements KeyService by coordinating key operations
// and access control while delegating to repository layer.
type keyService struct {
	keyRepo     repositories.KeyRepositoryInterface
	keyProvider crypto.KeyProvider
	keyCache    keycache.Cache
	policyRepo  repositories.KeyRotationPolicyRepositoryInterface
	logger      *logging.Logger
	// vaultRepo is optional. When set, PurgeKey refuses to purge a key whose
	// containing vault has purge protection enabled.
	vaultRepo repositories.VaultRepositoryInterface
	// globalPurgeProtection mirrors soft_delete.purge_protection. When true,
	// PurgeKey refuses every purge instance-wide, regardless of this key's or
	// its vault's own purge_protection flag.
	globalPurgeProtection bool
}

// KeyServiceConfig holds the dependencies for key service.
type KeyServiceConfig struct {
	KeyRepository repositories.KeyRepositoryInterface
	KeyProvider   crypto.KeyProvider
	// KeyCache is optional. When nil, a NopCache is used and mutations still
	// call Invalidate (which is a no-op on NopCache).
	KeyCache         keycache.Cache
	PolicyRepository repositories.KeyRotationPolicyRepositoryInterface
	Logger           *logging.Logger
	// VaultRepository is optional; it enables the vault-level purge-protection
	// cascade check in PurgeKey.
	VaultRepository repositories.VaultRepositoryInterface
	// GlobalPurgeProtection mirrors soft_delete.purge_protection. See
	// keyService.globalPurgeProtection.
	GlobalPurgeProtection bool
}

// NewKeyService creates a new KeyService with the provided dependencies.
// It orchestrates key management operations while maintaining SRP compliance.
//
// Parameters:
//
//	config: Configuration containing all required dependencies.
//
// Returns:
//
//	A KeyService implementation for key management operations.
func NewKeyService(config KeyServiceConfig) KeyService {
	if config.KeyCache == nil {
		config.KeyCache = keycache.NewNopCache()
	}
	return &keyService{
		keyRepo:               config.KeyRepository,
		keyProvider:           config.KeyProvider,
		keyCache:              config.KeyCache,
		policyRepo:            config.PolicyRepository,
		logger:                config.Logger,
		vaultRepo:             config.VaultRepository,
		globalPurgeProtection: config.GlobalPurgeProtection,
	}
}

// applyCreatePurgeProtection turns on purge protection for a freshly created
// key when the caller asked for it. A nil request field leaves the stored
// default alone, so the three create paths share one implementation and only
// differ in the audit action they report.
func (s *keyService) applyCreatePurgeProtection(ctx context.Context, purgeProtection *bool, keyID uuid.UUID, action string, userID uuid.UUID) error {
	if purgeProtection == nil || !*purgeProtection {
		return nil
	}
	if err := s.keyRepo.SetPurgeProtection(ctx, keyID, true); err != nil {
		s.logger.LogAuditError(userID.String(), action, "failed", "failed to set purge protection", err)
		return fmt.Errorf("failed to set purge protection: %w", err)
	}
	return nil
}

// CreateRSAKey creates a new RSA cryptographic key.
// It validates parameters, generates the key, encrypts it, and handles storage.
//
// Parameters:
//
//	ctx: The context for the operation.
//	req: The key creation request with RSA-specific parameters.
//
// Returns:
//
//	The created key information or an error if creation fails.
func (s *keyService) CreateRSAKey(ctx context.Context, req CreateKeyRequest) (*CreateKeyResult, error) {
	logrus.WithFields(logrus.Fields{
		"name":    req.Name,
		"type":    req.Type,
		"bits":    req.Bits,
		"user_id": req.UserID.String(),
	}).Info("Creating RSA key")

	// Validate RSA-specific parameters
	if req.Bits != 2048 && req.Bits != 3072 && req.Bits != 4096 {
		s.logger.LogAuditError(req.UserID.String(), "create_rsa_key", "failed", "invalid RSA key size: must be 2048, 3072, or 4096", nil)
		return nil, fmt.Errorf("invalid RSA key size: must be 2048, 3072, or 4096")
	}

	// Generate key via the configured provider (software or PKCS#11 HSM).
	handle, err := s.keyProvider.GenerateRSAKey(ctx, req.Bits)
	if err != nil {
		s.logger.LogAuditError(req.UserID.String(), "create_rsa_key", "failed", "failed to generate RSA key", err)
		return nil, fmt.Errorf("failed to generate RSA key: %w", err)
	}

	// For software keys, the handle is PEM — encrypt before storage.
	// For PKCS#11 keys, the handle is a UUID label — prefix and store as-is.
	var storedValue string
	if isPKCS11Handle(handle) {
		storedValue = "pkcs11:" + handle
	} else {
		storedValue, err = common.EncryptSecret(handle)
		if err != nil {
			s.logger.LogAuditError(req.UserID.String(), "create_rsa_key", "failed", "failed to encrypt key", err)
			return nil, fmt.Errorf("failed to encrypt key: %w", err)
		}
	}

	// Default to enabled when caller did not specify.
	enabled := true
	if req.Enabled != nil {
		enabled = *req.Enabled
	}

	// Create key entity.
	key := &model.Key{
		ID:        uuid.New(),
		UserID:    req.UserID,
		VaultID:   resolveVaultID(req.VaultID),
		Name:      req.Name,
		Type:      model.KeyTypeRSA,
		Value:     storedValue,
		Revoked:   false,
		CreatedAt: time.Now(),
		Tags:      req.Tags,
		Enabled:   enabled,
		Bits:      req.Bits,
		ExpiresAt: req.ExpiresAt,
		NotBefore: req.NotBefore,
	}

	// Store in repository.
	if err := s.keyRepo.Create(ctx, key); err != nil {
		s.logger.LogAuditError(req.UserID.String(), "create_rsa_key", "failed", "failed to store key", err)
		return nil, fmt.Errorf("failed to store RSA key: %w", err)
	}

	if err := s.applyCreatePurgeProtection(ctx, req.PurgeProtection, key.ID, "create_rsa_key", req.UserID); err != nil {
		return nil, err
	}

	s.logger.LogAuditInfo(req.UserID.String(), "create_rsa_key", "success", fmt.Sprintf("RSA key created: %s, ID: %s", req.Name, key.ID))
	logrus.WithFields(logrus.Fields{
		"key_id": key.ID.String(),
		"name":   key.Name,
		"type":   key.Type,
	}).Info("RSA key created successfully")

	return &CreateKeyResult{
		KeyID:     key.ID,
		Name:      key.Name,
		Type:      key.Type,
		Tags:      key.Tags,
		CreatedAt: key.CreatedAt,
	}, nil
}

// CreateECDSAKey creates a new ECDSA cryptographic key.
// It validates parameters, generates the key, encrypts it, and handles storage.
//
// Parameters:
//
//	ctx: The context for the operation.
//	req: The key creation request with ECDSA-specific parameters.
//
// Returns:
//
//	The created key information or an error if creation fails.
func (s *keyService) CreateECDSAKey(ctx context.Context, req CreateKeyRequest) (*CreateKeyResult, error) {
	logrus.WithFields(logrus.Fields{
		"name":    req.Name,
		"type":    req.Type,
		"curve":   req.Curve,
		"user_id": req.UserID.String(),
	}).Info("Creating ECDSA key")

	// Validate ECDSA-specific parameters.
	if req.Curve != "P-256" && req.Curve != "P-384" && req.Curve != "P-521" && req.Curve != "P-256K" {
		s.logger.LogAuditError(req.UserID.String(), "create_ecdsa_key", "failed", "invalid ECDSA curve: must be P-256, P-384, P-521, or P-256K", nil)
		return nil, fmt.Errorf("invalid ECDSA curve: must be P-256, P-384, P-521, or P-256K")
	}

	// Generate key via the configured provider (software or PKCS#11 HSM).
	handle, err := s.keyProvider.GenerateECDSAKey(ctx, req.Curve)
	if err != nil {
		s.logger.LogAuditError(req.UserID.String(), "create_ecdsa_key", "failed", "failed to generate ECDSA key", err)
		return nil, fmt.Errorf("failed to generate ECDSA key: %w", err)
	}

	var storedValue string
	if isPKCS11Handle(handle) {
		storedValue = "pkcs11:" + handle
	} else {
		storedValue, err = common.EncryptSecret(handle)
		if err != nil {
			s.logger.LogAuditError(req.UserID.String(), "create_ecdsa_key", "failed", "failed to encrypt key", err)
			return nil, fmt.Errorf("failed to encrypt key: %w", err)
		}
	}

	// P-256K keys use a distinct type so the crypto layer routes them correctly.
	keyType := model.KeyTypeECDSA
	if req.Curve == "P-256K" {
		keyType = model.KeyTypeES256K
	}

	// Default to enabled when caller did not specify.
	enabled := true
	if req.Enabled != nil {
		enabled = *req.Enabled
	}

	// Create key entity.
	key := &model.Key{
		ID:        uuid.New(),
		UserID:    req.UserID,
		VaultID:   resolveVaultID(req.VaultID),
		Name:      req.Name,
		Type:      keyType,
		Value:     storedValue,
		Revoked:   false,
		CreatedAt: time.Now(),
		Tags:      req.Tags,
		Enabled:   enabled,
		Curve:     req.Curve,
		ExpiresAt: req.ExpiresAt,
		NotBefore: req.NotBefore,
	}

	// Store in repository.
	if err := s.keyRepo.Create(ctx, key); err != nil {
		s.logger.LogAuditError(req.UserID.String(), "create_ecdsa_key", "failed", "failed to store key", err)
		return nil, fmt.Errorf("failed to store ECDSA key: %w", err)
	}

	if err := s.applyCreatePurgeProtection(ctx, req.PurgeProtection, key.ID, "create_ecdsa_key", req.UserID); err != nil {
		return nil, err
	}

	s.logger.LogAuditInfo(req.UserID.String(), "create_ecdsa_key", "success", fmt.Sprintf("ECDSA key created: %s, ID: %s", req.Name, key.ID))
	logrus.WithFields(logrus.Fields{
		"key_id": key.ID.String(),
		"name":   key.Name,
		"type":   key.Type,
	}).Info("ECDSA key created successfully")

	return &CreateKeyResult{
		KeyID:     key.ID,
		Name:      key.Name,
		Type:      key.Type,
		Tags:      key.Tags,
		CreatedAt: key.CreatedAt,
	}, nil
}

// CreateOctKey creates a new symmetric AES key. Requires an HSM-backed key
// provider — see crypto.ErrOctKeysRequireHSM.
func (s *keyService) CreateOctKey(ctx context.Context, req CreateKeyRequest) (*CreateKeyResult, error) {
	logrus.WithFields(logrus.Fields{
		"name":    req.Name,
		"bits":    req.Bits,
		"user_id": req.UserID.String(),
	}).Info("Creating AES (oct) key")

	if req.Bits != 128 && req.Bits != 192 && req.Bits != 256 {
		s.logger.LogAuditError(req.UserID.String(), "create_oct_key", "failed", "invalid AES key size: must be 128, 192, or 256", nil)
		return nil, fmt.Errorf("invalid AES key size: must be 128, 192, or 256")
	}

	handle, err := s.keyProvider.GenerateAESKey(ctx, req.Bits)
	if err != nil {
		s.logger.LogAuditError(req.UserID.String(), "create_oct_key", "failed", "failed to generate AES key", err)
		return nil, fmt.Errorf("failed to generate AES key: %w", err)
	}

	// AES keys are HSM-only: GenerateAESKey never returns a software (PEM)
	// handle, so the value is always the PKCS#11 label — no plaintext key
	// material ever reaches this process.
	storedValue := "pkcs11:" + handle

	enabled := true
	if req.Enabled != nil {
		enabled = *req.Enabled
	}

	key := &model.Key{
		ID:        uuid.New(),
		UserID:    req.UserID,
		VaultID:   resolveVaultID(req.VaultID),
		Name:      req.Name,
		Type:      model.KeyTypeOct,
		Value:     storedValue,
		Revoked:   false,
		CreatedAt: time.Now(),
		Tags:      req.Tags,
		Enabled:   enabled,
		Bits:      req.Bits,
		ExpiresAt: req.ExpiresAt,
		NotBefore: req.NotBefore,
	}

	if err := s.keyRepo.Create(ctx, key); err != nil {
		s.logger.LogAuditError(req.UserID.String(), "create_oct_key", "failed", "failed to store key", err)
		return nil, fmt.Errorf("failed to store AES key: %w", err)
	}

	if err := s.applyCreatePurgeProtection(ctx, req.PurgeProtection, key.ID, "create_oct_key", req.UserID); err != nil {
		return nil, err
	}

	s.logger.LogAuditInfo(req.UserID.String(), "create_oct_key", "success", fmt.Sprintf("AES key created: %s, ID: %s", req.Name, key.ID))

	return &CreateKeyResult{
		KeyID:     key.ID,
		Name:      key.Name,
		Type:      key.Type,
		Tags:      key.Tags,
		CreatedAt: key.CreatedAt,
	}, nil
}

// ImportKey stores externally-generated key material supplied as a JWK. It
// follows the same generate-then-store shape as CreateRSAKey/CreateECDSAKey,
// substituting JWK parsing + provider import for provider generation.
func (s *keyService) ImportKey(ctx context.Context, req ImportKeyRequest) (*CreateKeyResult, error) {
	logrus.WithFields(logrus.Fields{
		"name":    req.Name,
		"user_id": req.UserID.String(),
	}).Info("Importing key")

	privateKey, keyType, err := signing.ParseJWK(req.JWK)
	if err != nil {
		s.logger.LogAuditError(req.UserID.String(), "import_key", "failed", "invalid JWK", err)
		// Both %w: this must satisfy errors.Is against ErrInvalidJWK (api's
		// writeKeyError) AND against the underlying signing sentinels (e.g.
		// signing.ErrJWKNoPrivateKey, asserted by
		// TestImportKey_PublicOnlyJWK_Rejected) -- a single %w with the rest
		// as %s would drop the original error from the chain.
		return nil, fmt.Errorf("%w: %w", ErrInvalidJWK, err)
	}

	// Derive the key's strength up front: RSA bit length / EC curve name.
	// These feed both the minimum-size check below and the model.Key record
	// itself, so RotateKey later regenerates at the imported key's true
	// strength instead of falling back to hardcoded defaults (2048/P-256).
	var bits int
	var curve string
	switch k := privateKey.(type) {
	case *rsa.PrivateKey:
		bits = k.N.BitLen()
	case *ecdsa.PrivateKey:
		curve = k.Curve.Params().Name
	}

	// Enforce the same minimum RSA key size CreateRSAKey enforces at
	// generation time. go-jose validates mathematical correctness but not
	// size, so without this an under-strength RSA JWK (e.g. 512 or 1024
	// bits) would otherwise be importable. EC keys are already bounded by
	// go-jose's own curve allow-list (P-256/P-384/P-521 only), so this check
	// is RSA-only.
	if keyType == "RSA" && bits < 2048 {
		s.logger.LogAuditError(req.UserID.String(), "import_key", "failed", "imported RSA key is too small", nil)
		return nil, fmt.Errorf("imported RSA key is too small: %d bits (minimum 2048)", bits)
	}

	handle, err := s.keyProvider.ImportKey(ctx, keyType, privateKey)
	if err != nil {
		s.logger.LogAuditError(req.UserID.String(), "import_key", "failed", "failed to import key material", err)
		return nil, fmt.Errorf("failed to import key: %w", err)
	}

	var storedValue string
	if isPKCS11Handle(handle) {
		storedValue = "pkcs11:" + handle
	} else {
		storedValue, err = common.EncryptSecret(handle)
		if err != nil {
			s.logger.LogAuditError(req.UserID.String(), "import_key", "failed", "failed to encrypt key", err)
			return nil, fmt.Errorf("failed to encrypt key: %w", err)
		}
	}

	enabled := true
	if req.Enabled != nil {
		enabled = *req.Enabled
	}

	modelType := model.KeyTypeRSA
	if keyType == "ECDSA" {
		modelType = model.KeyTypeECDSA
	}

	key := &model.Key{
		ID:        uuid.New(),
		UserID:    req.UserID,
		VaultID:   resolveVaultID(req.VaultID),
		Name:      req.Name,
		Type:      modelType,
		Value:     storedValue,
		Revoked:   false,
		CreatedAt: time.Now(),
		Tags:      req.Tags,
		Enabled:   enabled,
		Bits:      bits,
		Curve:     curve,
		ExpiresAt: req.ExpiresAt,
		NotBefore: req.NotBefore,
	}

	if err := s.keyRepo.Create(ctx, key); err != nil {
		s.logger.LogAuditError(req.UserID.String(), "import_key", "failed", "failed to store key", err)
		return nil, fmt.Errorf("failed to store imported key: %w", err)
	}

	if err := s.applyCreatePurgeProtection(ctx, req.PurgeProtection, key.ID, "import_key", req.UserID); err != nil {
		return nil, err
	}

	s.logger.LogAuditInfo(req.UserID.String(), "import_key", "success", fmt.Sprintf("key imported: %s, ID: %s", req.Name, key.ID))

	return &CreateKeyResult{
		KeyID:     key.ID,
		Name:      key.Name,
		Type:      key.Type,
		Tags:      key.Tags,
		CreatedAt: key.CreatedAt,
	}, nil
}

// GetKey retrieves a key authorized by scope. The scoped read is the
// access check; a key outside the scope is reported as not found so the
// endpoint is not an existence oracle.
func (s *keyService) GetKey(ctx context.Context, keyID uuid.UUID, scope model.Scope) (*model.Key, error) {
	actor := scope.ActorID().String()
	s.logger.LogAuditInfo(actor, "get_key", "attempt", fmt.Sprintf("Accessing key: %s", keyID))

	key, err := s.keyRepo.Read(ctx, keyID, scope)
	if err != nil {
		s.logger.LogAuditError(actor, "get_key", "failed", fmt.Sprintf("Key not found: %s", keyID), err)
		return nil, fmt.Errorf("%w: %s", ErrKeyNotFound, err.Error())
	}

	if !key.IsAccessible() {
		s.logger.LogAuditError(actor, "get_key", "denied",
			fmt.Sprintf("Key is disabled or outside its valid time window: %s", keyID), nil)
		return nil, fmt.Errorf("%w", ErrKeyLifecycleDenied)
	}

	logrus.WithFields(logrus.Fields{
		"key_id":   key.ID,
		"key_name": key.Name,
		"key_type": key.Type,
		"scope":    scope.String(),
		"revoked":  key.Revoked,
	}).Info("Key accessed successfully")

	s.logger.LogAuditInfo(actor, "get_key", "success",
		fmt.Sprintf("Key accessed: %s (name: %s, type: %s, revoked: %t)", key.ID, key.Name, key.Type, key.Revoked))

	return key, nil
}

// ListKeyVersions returns keyID's version history, authorized by scope
// against the parent key.
//
// A never-rotated key has zero key_versions rows, but its material in
// keys.value is version 1 implicitly — the exact fallback GetKeyVersion and
// every crypto operation already apply. Synthesizing that entry here keeps
// the list endpoint from reporting "no versions" for a key whose version 1
// is addressable and usable. RotateKey deliberately does NOT go through this
// method: its version-numbering math needs the true zero-row count.
func (s *keyService) ListKeyVersions(ctx context.Context, keyID uuid.UUID, scope model.Scope) ([]model.KeyVersion, error) {
	key, err := s.GetKey(ctx, keyID, scope)
	if err != nil {
		return nil, err
	}
	versions, err := s.keyRepo.ListVersions(ctx, keyID)
	if err != nil {
		return nil, err
	}
	if len(versions) == 0 {
		return []model.KeyVersion{{KeyID: keyID, Version: 1, CreatedAt: key.CreatedAt}}, nil
	}
	return versions, nil
}

// GetKeyVersion returns metadata for one version of keyID, authorized by
// scope against the parent key. Mirrors ListKeyVersions exactly.
func (s *keyService) GetKeyVersion(ctx context.Context, keyID uuid.UUID, version int, scope model.Scope) (*model.KeyVersion, error) {
	// The scoped read is the authorization for the version rows below.
	if _, err := s.GetKey(ctx, keyID, scope); err != nil {
		return nil, err
	}
	return s.keyRepo.GetVersion(ctx, keyID, version)
}

// GetPublicJWK returns the public components of one version of keyID,
// authorized by scope against the parent key. version 0 means the current
// version.
//
// Why this is not in the handler: every software key is stored
// master-key-encrypted (see CreateKey, which runs common.EncryptSecret before
// KeyRepository.Create). api/keys.go used to call
// crypto.ExtractPublicComponents(key.Value, ...) directly and discard the
// error, so pem.Decode saw base64 ciphertext, returned a nil block, and all
// four components came back empty on every response -- .claude/known-bugs.md
// § B34. Decryption belongs in this layer; the handler just copies the result.
func (s *keyService) GetPublicJWK(ctx context.Context, keyID uuid.UUID, version int, scope model.Scope) (*model.PublicJWK, error) {
	// The scoped read is the authorization for the version rows below.
	key, err := s.GetKey(ctx, keyID, scope)
	if err != nil {
		return nil, err
	}

	// An HSM key's material never leaves the token, so there is nothing to
	// extract. Empty components with a nil error, not a failure.
	if strings.HasPrefix(key.Value, pkcs11Prefix) {
		return &model.PublicJWK{}, nil
	}

	// version 0 means current, which is the material on the key row itself.
	// Any other version has to come from key_versions.
	storedValue := key.Value
	if version != 0 {
		current, err := s.keyRepo.CurrentVersion(ctx, keyID)
		if err != nil {
			return nil, fmt.Errorf("resolve current version: %w", err)
		}
		if version != current {
			storedValue, err = s.keyRepo.ReadVersionValue(ctx, keyID, version)
			if err != nil {
				return nil, fmt.Errorf("read key version %d: %w", version, err)
			}
		}
	}

	// An archived version of a key that has since moved to an HSM, or was
	// always HSM-backed, carries a handle rather than PEM.
	if strings.HasPrefix(storedValue, pkcs11Prefix) {
		return &model.PublicJWK{}, nil
	}

	pemKey, err := common.DecryptSecret(storedValue)
	if err != nil {
		return nil, fmt.Errorf("decrypt key material: %w", err)
	}

	n, e, x, y, err := crypto.ExtractPublicComponents(pemKey, key.Type)
	if err != nil {
		return nil, fmt.Errorf("extract public components: %w", err)
	}
	return &model.PublicJWK{N: n, E: e, X: x, Y: y}, nil
}

// GetKeyRotationPolicy retrieves the rotation policy for keyID, authorized by
// scope against the parent key.
func (s *keyService) GetKeyRotationPolicy(ctx context.Context, keyID uuid.UUID, scope model.Scope) (*model.KeyRotationPolicy, error) {
	if _, err := s.GetKey(ctx, keyID, scope); err != nil {
		return nil, err
	}
	return s.policyRepo.GetByKeyID(ctx, keyID, scope)
}

// UpsertKeyRotationPolicy creates or replaces the rotation policy for keyID,
// authorized by scope against the parent key.
func (s *keyService) UpsertKeyRotationPolicy(ctx context.Context, keyID uuid.UUID, scope model.Scope, req model.UpsertKeyRotationPolicyRequest) (*model.KeyRotationPolicy, error) {
	key, err := s.GetKey(ctx, keyID, scope)
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()

	// Pre-read the existing policy (if any) so we can preserve its rotation
	// history rather than resetting the due-date clock on every edit. Only
	// "no policy exists yet" (sql.ErrNoRows) is treated as a fresh create --
	// any other read error (e.g. a transient DB failure) must propagate
	// rather than being silently treated as "no existing policy", which
	// would also incorrectly reset an update's due-date to key.CreatedAt.
	existing, err := s.policyRepo.GetByKeyID(ctx, keyID, scope)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("read existing key rotation policy: %w", err)
	}

	var lastRotatedAt *time.Time
	var nextRotationAt time.Time
	switch {
	case existing == nil:
		// First-time creation: anchor on the key's own CreatedAt. This is a
		// deliberate, single-key admin choice, not a mass retroactive event
		// -- contrast with the migration backfill (internal/db/db.go),
		// which anchors on the migration's own run time instead, precisely
		// to avoid a mass-rotation hazard across every existing key at once.
		nextRotationAt = key.CreatedAt.AddDate(0, 0, req.RotateAfterDays)
	case existing.LastRotatedAt != nil:
		// The policy has already auto-rotated at least once: recompute from
		// that rotation, mirroring MarkRotated's own formula.
		lastRotatedAt = existing.LastRotatedAt
		nextRotationAt = lastRotatedAt.AddDate(0, 0, req.RotateAfterDays)
	case req.RotateAfterDays != existing.RotateAfterDays:
		// Never auto-rotated, but the caller is deliberately changing the
		// rotation window itself -- a conscious admin choice on this
		// specific key, so recompute from key.CreatedAt like a fresh policy.
		nextRotationAt = key.CreatedAt.AddDate(0, 0, req.RotateAfterDays)
	default:
		// Never auto-rotated, and the rotation window (RotateAfterDays) is
		// unchanged: this is a metadata-only edit (e.g. toggling Enabled or
		// changing NotifyBeforeExpiryDays). Preserve the existing due-date
		// instead of recomputing it from key.CreatedAt -- recomputing here
		// would silently undo a migration backfill anchored on migration
		// time (see internal/db/db.go) and could move the due-date into the
		// past for any key older than its own rotation window, causing an
		// unplanned immediate rotation on the next scheduler tick.
		nextRotationAt = existing.NextRotationAt
	}

	policy := &model.KeyRotationPolicy{
		ID:                     uuid.New(),
		KeyID:                  keyID,
		UserID:                 scope.ActorID(),
		VaultID:                key.VaultID, // derived from the parent key, never from the caller
		RotateAfterDays:        req.RotateAfterDays,
		NotifyBeforeExpiryDays: req.NotifyBeforeExpiryDays,
		ExpiryDays:             req.ExpiryDays,
		Enabled:                req.Enabled,
		LastRotatedAt:          lastRotatedAt,
		NextRotationAt:         nextRotationAt,
		CreatedAt:              now,
		UpdatedAt:              now,
	}
	if err := s.policyRepo.Upsert(ctx, policy); err != nil {
		return nil, err
	}
	// Read-after-write so the caller gets the canonical stored row.
	return s.policyRepo.GetByKeyID(ctx, keyID, scope)
}

// DeleteKeyRotationPolicy removes the rotation policy for keyID, authorized
// by scope against the parent key.
func (s *keyService) DeleteKeyRotationPolicy(ctx context.Context, keyID uuid.UUID, scope model.Scope) error {
	if _, err := s.GetKey(ctx, keyID, scope); err != nil {
		return err
	}
	return s.policyRepo.DeleteByKeyID(ctx, keyID, scope)
}

// ListKeyRotationPolicies lists every rotation policy set in scope's vault,
// each paired with its parent key's name.
func (s *keyService) ListKeyRotationPolicies(ctx context.Context, scope model.Scope) ([]model.KeyRotationPolicyWithKeyName, error) {
	return s.policyRepo.ListByVault(ctx, scope)
}

// ListDueKeyRotationPolicies lists enabled rotation policies in scope's
// vault whose next rotation has already passed.
func (s *keyService) ListDueKeyRotationPolicies(ctx context.Context, scope model.Scope) ([]model.KeyRotationPolicy, error) {
	return s.policyRepo.GetDuePolicies(ctx, scope)
}

// ListKeys lists keys authorized by scope and narrowed by filter.
func (s *keyService) ListKeys(ctx context.Context, scope model.Scope, filter model.KeyFilter) ([]model.Key, error) {
	keys, err := s.keyRepo.List(ctx, scope, filter)
	if err != nil {
		s.logger.LogAuditError(scope.ActorID().String(), "list_keys", "failed", "Failed to list keys", err)
		return nil, fmt.Errorf("failed to list keys: %w", err)
	}
	logrus.WithFields(logrus.Fields{"scope": scope.String(), "key_count": len(keys)}).Info("Keys listed successfully")
	return keys, nil
}

// UpdateKey updates a key authorized by req.Scope. It reads with the
// scope directly rather than through GetKey so operators can still
// re-enable a disabled or expired key.
func (s *keyService) UpdateKey(ctx context.Context, req UpdateKeyRequest) error {
	actor := req.Scope.ActorID().String()
	logrus.WithFields(logrus.Fields{
		"key_id": req.KeyID.String(),
		"scope":  req.Scope.String(),
	}).Info("Updating key")

	key, err := s.keyRepo.Read(ctx, req.KeyID, req.Scope)
	if err != nil {
		return fmt.Errorf("%w: %s", ErrKeyNotFound, err.Error())
	}

	updatedKey, err := applyKeyUpdate(key, req)
	if err != nil {
		return err
	}

	if err := s.keyRepo.Update(ctx, updatedKey, req.Scope); err != nil {
		s.logger.LogAuditError(actor, "update_key", "failed", "Failed to update key", err)
		return fmt.Errorf("failed to update key: %w", err)
	}

	// Purge protection lives outside the key entity, so it is a separate write.
	if req.PurgeProtection != nil {
		if err := s.keyRepo.SetPurgeProtection(ctx, req.KeyID, *req.PurgeProtection); err != nil {
			s.logger.LogAuditError(actor, "update_key", "failed", "failed to set purge protection", err)
			return fmt.Errorf("failed to set purge protection: %w", err)
		}
	}

	// Evict stale cached material (covers revoke, disable, and expiry changes).
	if s.keyCache != nil {
		s.keyCache.Invalidate(updatedKey.ID)
	}

	s.logger.LogAuditInfo(actor, "update_key", "success", fmt.Sprintf("Key updated: %s", updatedKey.Name))
	return nil
}

// DeleteKey soft-deletes a key authorized by scope and returns the
// deleted record so callers can read Azure-style deletion metadata.
func (s *keyService) DeleteKey(ctx context.Context, keyID uuid.UUID, scope model.Scope) (*model.Key, error) {
	actor := scope.ActorID().String()

	key, err := s.keyRepo.Read(ctx, keyID, scope)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", ErrKeyNotFound, err.Error())
	}

	// B6 conjunction: an owner scope may carry an advisory vault id, and the
	// pre-refactor two-argument delete (key ID plus vault ID) required BOTH
	// predicates. A Scope cannot express AND, so the vault half stays in Go.
	//
	// Dead in production today, kept deliberately: the B11 flat-route fix
	// (docs/superpowers/specs/2026-08-16-flat-route-vault-scope-fix-design.md)
	// changed scopeFromRequest (api/context.go) to always return a vault
	// scope, so no HTTP or CLI caller builds an owner scope for a key
	// operation anymore -- see cmd/keys/delete.go, which passes
	// model.NewVaultScope. This branch only still fires from tests that call
	// DeleteKey directly with a hand-built owner scope carrying a non-nil
	// vault id. It stays as defense-in-depth for any future direct
	// caller of this exported method that reintroduces an owner scope.
	if _, ownerScoped := scope.OwnerID(); ownerScoped && scope.VaultID() != uuid.Nil && key.VaultID != scope.VaultID() {
		s.logger.LogAuditError(actor, "delete_key", "forbidden", "key does not belong to the requested vault", nil)
		return nil, fmt.Errorf("%w: key does not belong to the requested vault", ErrKeyNotFound)
	}

	if err := s.keyRepo.SoftDelete(ctx, keyID); err != nil {
		s.logger.LogAuditError(actor, "delete_key", "failed", "Failed to soft-delete key", err)
		return nil, fmt.Errorf("failed to delete key: %w", err)
	}

	if s.keyCache != nil {
		s.keyCache.Invalidate(keyID)
	}

	deleted, err := s.keyRepo.ReadDeletedScoped(ctx, keyID, scope)
	if err != nil {
		s.logger.LogAuditInfo(actor, "delete_key", "success", "Key deleted (metadata unavailable)")
		return key, nil
	}

	s.logger.LogAuditInfo(actor, "delete_key", "success", "Key deleted successfully")
	return deleted, nil
}

// keyDeletedInScope reports whether keyID names a soft-deleted key the scope
// authorizes.
func (s *keyService) keyDeletedInScope(ctx context.Context, keyID uuid.UUID, scope model.Scope) (bool, error) {
	deleted, err := s.keyRepo.List(ctx, scope, repositories.KeyFilter{OnlyDeleted: true})
	if err != nil {
		return false, fmt.Errorf("failed to list deleted keys: %w", err)
	}
	for _, key := range deleted {
		if key.ID == keyID {
			return true, nil
		}
	}
	return false, nil
}

// ListDeletedKeys lists soft-deleted keys authorized by scope.
func (s *keyService) ListDeletedKeys(ctx context.Context, scope model.Scope) ([]model.Key, error) {
	keys, err := s.keyRepo.List(ctx, scope, repositories.KeyFilter{OnlyDeleted: true})
	if err != nil {
		return nil, fmt.Errorf("failed to list deleted keys: %w", err)
	}
	return keys, nil
}

// RecoverKey restores a soft-deleted key authorized by scope.
func (s *keyService) RecoverKey(ctx context.Context, keyID uuid.UUID, scope model.Scope) error {
	inScope, err := s.keyDeletedInScope(ctx, keyID, scope)
	if err != nil {
		return err
	}
	if !inScope {
		s.logger.LogAuditError(scope.ActorID().String(), "recover_key", "failed",
			"Key not found in deleted state within scope", nil)
		return fmt.Errorf("%w", ErrKeyNotFound)
	}
	if err := s.keyRepo.RecoverKey(ctx, keyID); err != nil {
		return fmt.Errorf("failed to recover key: %w", err)
	}
	s.logger.LogAuditInfo(scope.ActorID().String(), "recover_key", "success",
		fmt.Sprintf("Key recovered: %s", keyID))
	return nil
}

// PurgeKey permanently deletes a soft-deleted key authorized by scope.
func (s *keyService) PurgeKey(ctx context.Context, keyID uuid.UUID, scope model.Scope) error {
	if s.globalPurgeProtection {
		s.logger.LogAuditError(scope.ActorID().String(), "purge_key", "failed",
			"Global purge protection is enabled", nil)
		return repositories.ErrGlobalPurgeProtectionEnabled
	}

	inScope, err := s.keyDeletedInScope(ctx, keyID, scope)
	if err != nil {
		return err
	}
	if !inScope {
		s.logger.LogAuditError(scope.ActorID().String(), "purge_key", "failed",
			"Key not found in deleted state within scope", nil)
		return fmt.Errorf("%w", ErrKeyNotFound)
	}

	// Vault-level purge protection cascades to the keys the vault contains, so
	// a protected vault blocks the per-item purge path too. This check fails
	// closed: for a key with no flag of its own it is the only protection
	// layer, so a vault that cannot be read blocks the purge rather than
	// silently skipping the check.
	if s.vaultRepo != nil && scope.VaultID() != uuid.Nil {
		vault, err := s.vaultRepo.ReadByID(ctx, scope.VaultID())
		if err != nil {
			s.logger.LogAuditError(scope.ActorID().String(), "purge_key", "failed",
				"Failed to check vault purge protection", err)
			return fmt.Errorf("failed to check vault purge protection: %w", err)
		}
		if vault.PurgeProtection {
			s.logger.LogAuditError(scope.ActorID().String(), "purge_key", "failed",
				"Vault has purge protection enabled", nil)
			return repositories.ErrKeyPurgeProtected
		}
	}

	if err := s.keyRepo.PurgeKey(ctx, keyID); err != nil {
		return fmt.Errorf("failed to purge key: %w", err)
	}
	s.logger.LogAuditInfo(scope.ActorID().String(), "purge_key", "success",
		fmt.Sprintf("Key purged: %s", keyID))
	return nil
}

// RotateKey rotates an existing key in-place by generating new key material,
// archiving the current and new material into key_versions, and updating the
// key's value field to the freshly generated material.
//
// Unlike the old implementation, rotation does NOT create a new key with a
// "-rotated" suffix. The key identity (ID, name, tags) is preserved.
//
// Parameters:
//
//	ctx: The context for the operation.
//	keyID: The key to rotate.
//	scope: The authorization scope for the read and the write.
//
// Returns:
//
//	A CreateKeyResult describing the (unchanged) key identity, or an error.
func (s *keyService) RotateKey(ctx context.Context, keyID uuid.UUID, scope model.Scope) (*CreateKeyResult, error) {
	userID := scope.ActorID()

	// Read with the scope directly rather than through GetKey, matching
	// UpdateKey: rotation must still work on a disabled or expired key. The
	// scoped read is the access check -- there is no separate in-Go ownership
	// comparison.
	existing, err := s.keyRepo.Read(ctx, keyID, scope)
	if err != nil {
		return nil, fmt.Errorf("rotate key: %w", err)
	}

	// B6 conjunction: identical to DeleteKey, including why it's dead in
	// production today and kept as defense-in-depth -- see the comment there.
	if _, ownerScoped := scope.OwnerID(); ownerScoped && scope.VaultID() != uuid.Nil && existing.VaultID != scope.VaultID() {
		s.logger.LogAuditError(userID.String(), "rotate_key", "forbidden", "key does not belong to the requested vault", nil)
		return nil, fmt.Errorf("%w: key does not belong to the requested vault", ErrKeyNotFound)
	}

	bits := existing.Bits
	if bits == 0 {
		bits = 2048 // Fallback for keys without stored bit size.
	}
	curve := existing.Curve
	if curve == "" {
		curve = "P-256" // Fallback for keys without stored curve.
	}

	// Generate new key material via the configured provider.
	var newHandle string
	switch existing.Type {
	case model.KeyTypeRSA:
		newHandle, err = s.keyProvider.GenerateRSAKey(ctx, bits)
	case model.KeyTypeECDSA:
		newHandle, err = s.keyProvider.GenerateECDSAKey(ctx, curve)
	case model.KeyTypeES256K:
		newHandle, err = s.keyProvider.GenerateECDSAKey(ctx, "P-256K")
	default:
		s.logger.LogAuditError(userID.String(), "rotate_key", "failed", "unsupported key type for rotation", nil)
		return nil, fmt.Errorf("unsupported key type for rotation: %s", existing.Type)
	}
	if err != nil {
		s.logger.LogAuditError(userID.String(), "rotate_key", "failed", "key generation failed", err)
		return nil, fmt.Errorf("key generation failed: %w", err)
	}

	var encryptedNew string
	if isPKCS11Handle(newHandle) {
		encryptedNew = "pkcs11:" + newHandle
	} else {
		encryptedNew, err = common.EncryptSecret(newHandle)
		if err != nil {
			s.logger.LogAuditError(userID.String(), "rotate_key", "failed", "key encryption failed", err)
			return nil, fmt.Errorf("key encryption failed: %w", err)
		}
	}

	// Determine next version number from existing history. The scoped Read
	// of existing above is the authorization; ListVersions itself performs
	// none.
	versions, err := s.keyRepo.ListVersions(ctx, keyID)
	if err != nil {
		return nil, fmt.Errorf("list versions: %w", err)
	}
	nextVersion := len(versions) + 1

	// If this is the first rotation, archive the original material as version 1 first.
	if len(versions) == 0 {
		if err := s.keyRepo.CreateVersion(ctx, keyID, 1, existing.Value); err != nil {
			return nil, fmt.Errorf("archive original key version: %w", err)
		}
		nextVersion = 2
	}

	// Archive the new material as the next version.
	if err := s.keyRepo.CreateVersion(ctx, keyID, nextVersion, encryptedNew); err != nil {
		return nil, fmt.Errorf("create new key version: %w", err)
	}

	// Apply the rotation policy's expiry_days lifetime action, if
	// configured: stamp ExpiresAt on every rotation (scheduled or manual),
	// matching Azure's expiryTime, which governs the version a rotation
	// produces regardless of what triggered it. policyRepo is optional
	// (nil in some minimally-constructed test/service instances, matching
	// the vaultRepo convention in PurgeKey); most keys also simply have no
	// policy configured, which is the common case, not an error.
	if s.policyRepo != nil {
		policy, err := s.policyRepo.GetByKeyID(ctx, keyID, scope)
		switch {
		case err == nil && policy.Enabled && policy.ExpiryDays > 0:
			expiresAt := time.Now().UTC().AddDate(0, 0, policy.ExpiryDays)
			existing.ExpiresAt = &expiresAt
		case errors.Is(err, sql.ErrNoRows):
			// No policy configured for this key -- nothing to stamp.
		case err != nil:
			s.logger.LogAuditError(userID.String(), "rotate_key", "failed", "rotation policy lookup failed", err)
			return nil, fmt.Errorf("rotate key: look up rotation policy: %w", err)
		}
	}

	// Update the key's active value in place, repeating the scope predicate
	// that authorized the read.
	existing.Value = encryptedNew
	if err := s.keyRepo.Update(ctx, existing, scope); err != nil {
		return nil, fmt.Errorf("update key value: %w", err)
	}

	// Evict stale cached material now that the key has new material.
	if s.keyCache != nil {
		s.keyCache.Invalidate(keyID)
	}

	s.logger.LogAuditInfo(userID.String(), "rotate_key", "success",
		fmt.Sprintf("Key %s rotated to version %d.", keyID, nextVersion))

	return &CreateKeyResult{
		KeyID:     keyID,
		Name:      existing.Name,
		Type:      existing.Type,
		Tags:      existing.Tags,
		CreatedAt: existing.CreatedAt,
	}, nil
}

// ValidateKeyAccess validates that a user has access to a specific key.
// It handles role-based access control for key operations.
//
// Parameters:
//
//	ctx: The context for the operation.
//	keyID: The key's unique identifier.
//	userID: The requesting user's ID.
//	role: The user's role for permission checking.
//
// Returns:
//
//	An error if access is denied.
func (s *keyService) ValidateKeyAccess(ctx context.Context, keyID, userID uuid.UUID, role string) error {
	// Admin users have access to all keys
	if role == model.RoleAdmin {
		return nil
	}

	// Non-admin users can only access their own keys
	key, err := s.keyRepo.Read(ctx, keyID, model.NewAdminScope(userID))
	if err != nil {
		s.logger.LogAuditError(userID.String(), "validate_key_access", "failed", fmt.Sprintf("key not found: %s", err), err)
		return fmt.Errorf("key not found: %w", err)
	}

	if key.UserID != userID {
		s.logger.LogAuditError(userID.String(), "validate_key_access", "failed", "forbidden: cannot access other users' keys", nil)
		return fmt.Errorf("forbidden: cannot access other users' keys")
	}

	return nil
}

// isPKCS11Handle returns true when handle is a UUID label returned by the
// PKCS#11 provider rather than a PEM string from the software provider.
func isPKCS11Handle(handle string) bool {
	return len(handle) == 36 &&
		handle[8] == '-' && handle[13] == '-' &&
		handle[18] == '-' && handle[23] == '-'
}
