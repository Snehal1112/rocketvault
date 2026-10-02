// Package certificates provides certificate management services for the password manager.
// It handles X.509 certificate lifecycle, validation, and access control
// while maintaining proper separation of concerns.
package certificates

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"

	"rocketvault/common"
	"rocketvault/internal/crypto"
	"rocketvault/internal/logging"
	"rocketvault/internal/repositories"
	"rocketvault/model"
)

// ErrCertNotFound is returned when a certificate does not exist or is not
// accessible within the requested scope (vault or user ownership).
var ErrCertNotFound = errors.New("certificate not found")

// ErrCertLifecycleDenied is returned when a certificate exists but is disabled
// or outside its valid time window (not_before / expires_at).
var ErrCertLifecycleDenied = errors.New("certificate is disabled or outside its valid time window")

// ErrRenewKeyForbidden is returned by RenewCertificate when the certificate's
// key belongs to another user.
var ErrRenewKeyForbidden = errors.New("forbidden: cannot use other users' keys")

// ErrRenewKeyNotFound is returned by RenewCertificate when the certificate's
// key cannot be read, for example because it was deleted.
var ErrRenewKeyNotFound = errors.New("key not found")

// ErrRenewNotPossible is returned by RenewCertificate when the certificate
// cannot be renewed in its current state, such as a missing key link or a
// signing CA this installation no longer records.
var ErrRenewNotPossible = errors.New("certificate cannot be renewed")

// ErrSigningKeyUnusable is returned when a certificate's signing key, or the
// key linked to its signing CA, is revoked, disabled, or outside its validity
// window (B77).
var ErrSigningKeyUnusable = errors.New("signing key is revoked, disabled or outside its valid time window")

// renewError carries a fixed message while still matching a renew sentinel
// through errors.Is, so the text callers already see does not change.
type renewError struct {
	msg      string
	sentinel error
}

func (e *renewError) Error() string { return e.msg }
func (e *renewError) Unwrap() error { return e.sentinel }

// ErrCertVersioningUnavailable is returned when the service was built
// without a version repository. Renewal and the version operations fail
// closed rather than overwrite a certificate with no history kept.
var ErrCertVersioningUnavailable = errors.New("certificate versioning is not configured")

// CreateCertificateRequest represents a request to create a new X.509 certificate.
type CreateCertificateRequest struct {
	Name         string
	KeyID        uuid.UUID
	ValidityDays int
	Tags         []string
	UserID       uuid.UUID
	VaultID      uuid.UUID  // Target vault; defaults to the default vault when nil.
	CACertID     *uuid.UUID // Optional for CA-signed certificates.
	// IsCA requests a Certificate Authority certificate. False -- the zero
	// value -- issues an ordinary leaf, which is what almost every caller
	// wants. Both self-signed call sites used to hardcode true, so every
	// certificate was a CA (B44).
	IsCA        bool
	AutoRenew   bool
	RenewalDays int        // 0 defaults to 30.
	Enabled     *bool      // nil defaults to true.
	NotBefore   *time.Time // Optional activation timestamp.
	// PurgeProtection is optional: nil leaves the stored default alone, true
	// enables purge protection on the freshly created certificate.
	PurgeProtection *bool

	// Exportable requests an exportable certificate. It requires a key whose
	// own exportable flag is true, because the certificate keeps a copy of
	// that key; otherwise the create fails with model.ErrExportableKeyRequired.
	Exportable bool
}

// resolveVaultID returns the requested vault id, falling back to the default
// vault when the caller did not specify one.
func resolveVaultID(vaultID uuid.UUID) uuid.UUID {
	if vaultID == uuid.Nil {
		return uuid.MustParse(model.DefaultVaultID)
	}
	return vaultID
}

// requireExportableKey refuses an exportable certificate over a key whose
// exportable flag is false, so a certificate cannot carry out a key its
// creator marked non-exportable.
func (s *certificateService) requireExportableKey(req CreateCertificateRequest, key *model.Key, action string) error {
	if !req.Exportable || key.Exportable {
		return nil
	}
	s.logger.LogAuditError(req.UserID.String(), action, "failed", "exportable certificate requested over a non-exportable key", nil)
	return fmt.Errorf("%w: key %s has exportable=false", model.ErrExportableKeyRequired, req.KeyID)
}

// CreateCertificateResult represents the result of creating a new certificate.
type CreateCertificateResult struct {
	CertID       uuid.UUID
	Name         string
	Tags         []string
	CreatedAt    time.Time
	ExpiresAt    *time.Time
	Version      int    // The certificate's current version number.
	Exportable   bool   // The immutable exportable flag the certificate was created with.
	KeyAlgorithm string // The leaf public key's algorithm, such as RSA-2048.
}

// UpdateCertificateRequest represents a request to update an existing certificate.
type UpdateCertificateRequest struct {
	CertID      uuid.UUID
	Scope       model.Scope // Authorization scope for the read and the write.
	Name        *string     // Optional - nil means no change.
	Tags        []string    // Optional - empty means no change.
	AutoRenew   *bool       // Optional - nil means no change.
	RenewalDays *int        // Optional - nil means no change.
	Enabled     *bool       // Optional - nil means no change.
	NotBefore   *time.Time  // Optional - nil means no change.
	// PurgeProtection is optional - nil means no change.
	PurgeProtection *bool
}

// UpdateCertificateVersionRequest changes one version's lifecycle
// attributes. Nil fields are left as they are; at least one must be set.
type UpdateCertificateVersionRequest struct {
	CertID    uuid.UUID
	Version   int
	Scope     model.Scope // Authorization scope, checked against the parent certificate.
	Enabled   *bool
	ExpiresAt *time.Time
	NotBefore *time.Time
}

// CertificateService handles X.509 certificate management operations.
// It orchestrates certificate generation, validation, and access control
// while delegating storage to repositories.
type CertificateService interface {
	CreateSelfSignedCertificate(ctx context.Context, req CreateCertificateRequest) (*CreateCertificateResult, error)
	CreateCASignedCertificate(ctx context.Context, req CreateCertificateRequest) (*CreateCertificateResult, error)
	// GetCertificate retrieves a certificate authorized by scope.
	GetCertificate(ctx context.Context, certID uuid.UUID, scope model.Scope) (*model.Certificate, error)
	// ListCertificates lists certificates authorized by scope.
	ListCertificates(ctx context.Context, scope model.Scope, filter model.CertificateFilter) ([]model.Certificate, error)
	// UpdateCertificate updates a certificate authorized by req.Scope.
	UpdateCertificate(ctx context.Context, req UpdateCertificateRequest) error
	// DeleteCertificate soft-deletes a certificate authorized by scope.
	DeleteCertificate(ctx context.Context, certID uuid.UUID, scope model.Scope) error
	// RenewCertificate renews certID, authorized by scope. scope.ActorID() is
	// also the audit-log principal and the identity used by the internal
	// key-ownership checks below.
	RenewCertificate(ctx context.Context, certID uuid.UUID, scope model.Scope, validityDays int) (*CreateCertificateResult, error)
	// ListCertificateVersions returns certID's versions, oldest first with
	// the current one last, authorized by scope against the parent.
	ListCertificateVersions(ctx context.Context, certID uuid.UUID, scope model.Scope) ([]model.CertificateVersion, error)
	// GetCertificateVersion returns one version's metadata, authorized by
	// scope against the parent.
	GetCertificateVersion(ctx context.Context, certID uuid.UUID, version int, scope model.Scope) (*model.CertificateVersion, error)
	// UpdateCertificateVersion changes one version's lifecycle attributes,
	// authorized by req.Scope against the parent.
	UpdateCertificateVersion(ctx context.Context, req UpdateCertificateVersionRequest) (*model.CertificateVersion, error)
	// ExportCertificate returns one exportable certificate version as a
	// leaf-first chain plus an unencrypted PKCS#8 key, or as PKCS12,
	// authorized by scope. It always reads the repository, never a cache.
	ExportCertificate(ctx context.Context, scope model.Scope, id uuid.UUID, req ExportCertificateRequest) (*ExportCertificateResult, error)
	// ListDeletedCertificates lists soft-deleted certificates authorized by scope.
	ListDeletedCertificates(ctx context.Context, scope model.Scope) ([]model.Certificate, error)
	// RecoverCertificate restores a soft-deleted certificate authorized by scope.
	RecoverCertificate(ctx context.Context, certID uuid.UUID, scope model.Scope) error
	// PurgeCertificate permanently deletes a soft-deleted certificate authorized by scope.
	PurgeCertificate(ctx context.Context, certID uuid.UUID, scope model.Scope) error
	ValidateCertificateAccess(ctx context.Context, certID uuid.UUID, scope model.Scope) error
	ValidateKeyOwnership(ctx context.Context, keyID uuid.UUID, scope model.Scope) error
	// GetCertificatePolicy retrieves the policy for certID, authorized by scope
	// against the parent certificate.
	GetCertificatePolicy(ctx context.Context, certID uuid.UUID, scope model.Scope) (*model.CertificatePolicy, error)
	// UpsertCertificatePolicy creates or replaces the policy for certID,
	// authorized by scope against the parent certificate.
	UpsertCertificatePolicy(ctx context.Context, certID uuid.UUID, scope model.Scope, req model.UpsertCertificatePolicyRequest) (*model.CertificatePolicy, error)
	// DeleteCertificatePolicy removes the policy for certID, authorized by
	// scope against the parent certificate.
	DeleteCertificatePolicy(ctx context.Context, certID uuid.UUID, scope model.Scope) error
	// ListCertificatePolicies lists every certificate policy in scope's
	// vault, each paired with its parent certificate's name. Certificates
	// with no policy set are simply absent -- this lists policies, not all
	// certificates.
	ListCertificatePolicies(ctx context.Context, scope model.Scope) ([]model.CertificatePolicyWithCertName, error)
	// ListCertificatesDueForRenewal lists certificates in scope's vault whose
	// auto-renewal window has been entered, evaluated the same way the real
	// auto-renewal scheduler (CertificateRenewalService.CheckAndRenewCertificates)
	// does: directly off each certificate's own AutoRenew/RenewalDays/ExpiresAt
	// columns, not CertificatePolicy's separate AutoRenew/DaysBeforeExpiry
	// fields, which the scheduler does not consult.
	ListCertificatesDueForRenewal(ctx context.Context, scope model.Scope) ([]model.Certificate, error)
}

// certificateService implements CertificateService by coordinating certificate operations
// and access control while delegating to repository layers.
type certificateService struct {
	certRepo    repositories.CertificateRepositoryInterface
	keyRepo     repositories.KeyRepositoryInterface
	policyRepo  repositories.CertificatePolicyRepositoryInterface
	versionRepo repositories.CertificateVersionRepositoryInterface
	logger      *logging.Logger
	// vaultRepo is optional. When set, PurgeCertificate refuses to purge a
	// certificate whose containing vault has purge protection enabled.
	vaultRepo repositories.VaultRepositoryInterface
	// globalPurgeProtection mirrors soft_delete.purge_protection. When true,
	// PurgeCertificate refuses every purge instance-wide, regardless of this
	// certificate's or its vault's own purge_protection flag.
	globalPurgeProtection bool
}

// CertificateServiceConfig holds the dependencies for certificate service.
type CertificateServiceConfig struct {
	CertificateRepository repositories.CertificateRepositoryInterface
	KeyRepository         repositories.KeyRepositoryInterface
	PolicyRepository      repositories.CertificatePolicyRepositoryInterface
	// VersionRepository stores archived versions. Renewal and the version
	// operations fail closed with ErrCertVersioningUnavailable without it.
	VersionRepository repositories.CertificateVersionRepositoryInterface
	Logger            *logging.Logger
	// VaultRepository is optional; it enables the vault-level purge-protection
	// cascade check in PurgeCertificate.
	VaultRepository repositories.VaultRepositoryInterface
	// GlobalPurgeProtection mirrors soft_delete.purge_protection. See
	// certificateService.globalPurgeProtection.
	GlobalPurgeProtection bool
}

// NewCertificateService creates a new CertificateService with the provided dependencies.
// It orchestrates certificate management operations while maintaining SRP compliance.
//
// Parameters:
//
//	config: Configuration containing all required dependencies.
//
// Returns:
//
//	A CertificateService implementation for certificate management operations.
func NewCertificateService(config CertificateServiceConfig) CertificateService {
	return &certificateService{
		certRepo:              config.CertificateRepository,
		keyRepo:               config.KeyRepository,
		policyRepo:            config.PolicyRepository,
		versionRepo:           config.VersionRepository,
		logger:                config.Logger,
		vaultRepo:             config.VaultRepository,
		globalPurgeProtection: config.GlobalPurgeProtection,
	}
}

// applyCreatePurgeProtection turns on purge protection for a freshly created
// certificate when the caller asked for it. A nil request field leaves the
// stored default alone, so the self-signed and CA-signed create paths share
// one implementation and only differ in the audit action they report.
func (s *certificateService) applyCreatePurgeProtection(ctx context.Context, req CreateCertificateRequest, certID uuid.UUID, action string) error {
	if req.PurgeProtection == nil || !*req.PurgeProtection {
		return nil
	}
	if err := s.certRepo.SetPurgeProtection(ctx, certID, true); err != nil {
		s.logger.LogAuditError(req.UserID.String(), action, "failed", "failed to set purge protection", err)
		return fmt.Errorf("failed to set purge protection: %w", err)
	}
	return nil
}

// CreateSelfSignedCertificate creates a new self-signed X.509 certificate.
// It validates parameters, verifies key ownership, generates the certificate, and handles storage.
//
// Parameters:
//
//	ctx: The context for the operation.
//	req: The certificate creation request.
//
// Returns:
//
//	The created certificate information or an error if creation fails.
func (s *certificateService) CreateSelfSignedCertificate(ctx context.Context, req CreateCertificateRequest) (*CreateCertificateResult, error) {
	logrus.WithFields(logrus.Fields{
		"name":          req.Name,
		"key_id":        req.KeyID.String(),
		"validity_days": req.ValidityDays,
		"user_id":       req.UserID.String(),
	}).Info("Creating self-signed certificate")

	// Validate parameters
	if req.ValidityDays <= 0 {
		s.logger.LogAuditError(req.UserID.String(), "create_self_signed_cert", "failed", "validity days must be positive", nil)
		return nil, fmt.Errorf("validity days must be positive")
	}

	// Authorize the signing key against the vault this certificate is being
	// created in, never against the key's own vault (B32).
	keyScope := model.NewVaultScope(resolveVaultID(req.VaultID), req.UserID)
	if err := s.ValidateKeyOwnership(ctx, req.KeyID, keyScope); err != nil {
		return nil, err
	}

	// Re-read under the same scope to pull the private key. This used to use an
	// admin scope on the grounds that ownership had already been verified --
	// true, but ownership is not vault authorization, so the admin scope
	// reintroduced exactly the gap ValidateKeyOwnership had just closed.
	key, err := s.keyRepo.Read(ctx, req.KeyID, keyScope)
	if err != nil {
		s.logger.LogAuditError(req.UserID.String(), "create_self_signed_cert", "failed", "failed to read key", err)
		return nil, fmt.Errorf("failed to read key: %w", err)
	}
	// ValidateKeyOwnership checked an earlier read. The key could have been
	// revoked or disabled since, so the key actually used to sign is checked
	// again (B77).
	if err := requireUsableKey(key); err != nil {
		s.logger.LogAuditError(req.UserID.String(), "create_self_signed_cert", "failed", "signing key is unusable", nil)
		return nil, err
	}
	if err := s.requireExportableKey(req, key, "create_self_signed_cert"); err != nil {
		return nil, err
	}

	// Decrypt the private key
	privateKeyPEM, err := common.DecryptSecret(key.Value)
	if err != nil {
		s.logger.LogAuditError(req.UserID.String(), "create_self_signed_cert", "failed", "failed to decrypt key", err)
		return nil, fmt.Errorf("failed to decrypt key: %w", err)
	}

	// Generate the self-signed certificate. IsCA is opt-in: this used to be
	// hardcoded true, so an ordinary TLS server certificate was issued as a
	// Certificate Authority and a leak of its key meant a leak of an issuer
	// (B44).
	certPEM, err := crypto.CreateSelfSignedCertificatePEM(privateKeyPEM, key.Type, crypto.CertificateTemplate{
		CommonName:   req.Name,
		ValidityDays: req.ValidityDays,
		IsCA:         req.IsCA,
	})
	if err != nil {
		s.logger.LogAuditError(req.UserID.String(), "create_self_signed_cert", "failed", "failed to generate certificate", err)
		return nil, fmt.Errorf("failed to generate self-signed certificate: %w", err)
	}

	// Parse the expiry date from the generated certificate.
	expiresAt, err := extractExpiresAt(certPEM)
	if err != nil {
		s.logger.LogAuditError(req.UserID.String(), "create_self_signed_cert", "failed", "failed to parse certificate expiry", err)
		return nil, fmt.Errorf("failed to determine certificate expiry: %w", err)
	}

	// Encrypt the private key for storage
	encryptedKey, err := common.EncryptSecret(privateKeyPEM)
	if err != nil {
		s.logger.LogAuditError(req.UserID.String(), "create_self_signed_cert", "failed", "failed to encrypt private key", err)
		return nil, fmt.Errorf("failed to encrypt private key: %w", err)
	}

	renewalDays := req.RenewalDays
	if renewalDays <= 0 {
		renewalDays = 30
	}

	// Default Enabled to true when not explicitly set.
	enabled := true
	if req.Enabled != nil {
		enabled = *req.Enabled
	}

	// Create certificate entity
	cert := &model.Certificate{
		ID:          uuid.New(),
		UserID:      req.UserID,
		VaultID:     resolveVaultID(req.VaultID),
		KeyID:       req.KeyID,
		Name:        req.Name,
		Certificate: certPEM,
		PrivateKey:  encryptedKey,
		CreatedAt:   time.Now(),
		Tags:        req.Tags,
		ExpiresAt:   expiresAt,
		AutoRenew:   req.AutoRenew,
		RenewalDays: renewalDays,
		Enabled:     enabled,
		NotBefore:   req.NotBefore,
		Version:     1,
		Exportable:  req.Exportable,
	}

	// Store in repository
	if err := s.certRepo.Create(ctx, cert); err != nil {
		s.logger.LogAuditError(req.UserID.String(), "create_self_signed_cert", "failed", "failed to store certificate", err)
		return nil, fmt.Errorf("failed to store self-signed certificate: %w", err)
	}

	if err := s.applyCreatePurgeProtection(ctx, req, cert.ID, "create_self_signed_cert"); err != nil {
		return nil, err
	}

	s.logger.LogAuditInfo(req.UserID.String(), "create_self_signed_cert", "success", fmt.Sprintf("self-signed certificate created: %s, ID: %s", req.Name, cert.ID))
	logrus.WithFields(logrus.Fields{
		"cert_id": cert.ID.String(),
		"name":    cert.Name,
		"key_id":  req.KeyID.String(),
	}).Info("Self-signed certificate created successfully")

	return &CreateCertificateResult{
		CertID:       cert.ID,
		Name:         cert.Name,
		Tags:         cert.Tags,
		CreatedAt:    cert.CreatedAt,
		ExpiresAt:    expiresAt,
		Version:      1,
		Exportable:   cert.Exportable,
		KeyAlgorithm: crypto.KeyAlgorithmFromCertificatePEM(certPEM),
	}, nil
}

// CreateCASignedCertificate creates a new CA-signed X.509 certificate.
// It validates parameters, verifies key ownership, generates the certificate with CA signing, and handles storage.
//
// Parameters:
//
//	ctx: The context for the operation.
//	req: The certificate creation request with CA certificate ID.
//
// Returns:
//
//	The created certificate information or an error if creation fails.
func (s *certificateService) CreateCASignedCertificate(ctx context.Context, req CreateCertificateRequest) (*CreateCertificateResult, error) {
	logrus.WithFields(logrus.Fields{
		"name":          req.Name,
		"key_id":        req.KeyID.String(),
		"ca_cert_id":    req.CACertID.String(),
		"validity_days": req.ValidityDays,
		"user_id":       req.UserID.String(),
	}).Info("Creating CA-signed certificate")

	// Validate parameters
	if req.CACertID == nil {
		s.logger.LogAuditError(req.UserID.String(), "create_ca_signed_cert", "failed", "CA certificate ID required for CA-signed certificates", nil)
		return nil, fmt.Errorf("CA certificate ID required for CA-signed certificates")
	}

	if req.ValidityDays <= 0 {
		s.logger.LogAuditError(req.UserID.String(), "create_ca_signed_cert", "failed", "validity days must be positive", nil)
		return nil, fmt.Errorf("validity days must be positive")
	}

	// A CA-signed certificate is always a leaf here: issuing an intermediate
	// CA is a separate feature nobody has asked for yet. Refusing is
	// deliberate -- silently issuing a leaf when a CA was requested is the
	// same quiet wrongness as B44 itself.
	if req.IsCA {
		s.logger.LogAuditError(req.UserID.String(), "create_ca_signed_cert", "failed", "CA opt-in is not supported on the CA-signed path", nil)
		return nil, fmt.Errorf("cannot issue a CA-signed certificate as a CA: intermediate CA certificates are not supported")
	}

	// Both the signing key and the CA certificate are authorized against the
	// vault this certificate is being created in (B32).
	certScope := model.NewVaultScope(resolveVaultID(req.VaultID), req.UserID)

	if err := s.ValidateKeyOwnership(ctx, req.KeyID, certScope); err != nil {
		return nil, err
	}

	// Verify CA certificate access
	if err := s.ValidateCertificateAccess(ctx, *req.CACertID, certScope); err != nil {
		s.logger.LogAuditError(req.UserID.String(), "create_ca_signed_cert", "failed", "cannot access CA certificate", err)
		return nil, fmt.Errorf("cannot access CA certificate: %w", err)
	}

	// Re-read under the same scope; see CreateSelfSignedCertificate for why an
	// admin scope here would undo the check immediately above it.
	key, err := s.keyRepo.Read(ctx, req.KeyID, certScope)
	if err != nil {
		s.logger.LogAuditError(req.UserID.String(), "create_ca_signed_cert", "failed", "failed to read key", err)
		return nil, fmt.Errorf("failed to read key: %w", err)
	}
	// See CreateSelfSignedCertificate: the key actually used to sign is
	// checked again (B77).
	if err := requireUsableKey(key); err != nil {
		s.logger.LogAuditError(req.UserID.String(), "create_ca_signed_cert", "failed", "signing key is unusable", nil)
		return nil, err
	}
	if err := s.requireExportableKey(req, key, "create_ca_signed_cert"); err != nil {
		return nil, err
	}

	// Decrypt the private key
	privateKeyPEM, err := common.DecryptSecret(key.Value)
	if err != nil {
		s.logger.LogAuditError(req.UserID.String(), "create_ca_signed_cert", "failed", "failed to decrypt key", err)
		return nil, fmt.Errorf("failed to decrypt key: %w", err)
	}

	// Re-read the CA certificate under the same scope, for the same reason.
	caCert, err := s.certRepo.Read(ctx, *req.CACertID, certScope)
	if err != nil {
		s.logger.LogAuditError(req.UserID.String(), "create_ca_signed_cert", "failed", "failed to read CA certificate", err)
		return nil, fmt.Errorf("failed to read CA certificate: %w", err)
	}

	// x509.CreateCertificate does not check the parent's IsCA/KeyUsage bits, so
	// it will happily sign through a certificate that cannot actually verify as
	// an issuer -- a pre-fix pseudo-CA (CA:TRUE with no keyCertSign, the B43
	// shape) or an ordinary leaf a ca_cert_id was pointed at by mistake. Refuse
	// before signing rather than minting a certificate that reports success and
	// then fails CheckSignatureFrom/Verify against its own CA. Renewal applies
	// the identical gate in renewCASignedBody.
	caStatus, err := inspectCertificateCA(caCert.Certificate)
	if err != nil {
		s.logger.LogAuditError(req.UserID.String(), "create_ca_signed_cert", "failed", "failed to inspect CA certificate", err)
		return nil, fmt.Errorf("cannot issue a CA-signed certificate: failed to inspect CA %s: %w", *req.CACertID, err)
	}
	if caStatus != caStatusCA {
		s.logger.LogAuditError(req.UserID.String(), "create_ca_signed_cert", "failed", "CA certificate cannot sign certificates", nil)
		return nil, fmt.Errorf("signing CA %s cannot sign certificates (asserts CA without keyCertSign, or is not a CA); reissue it with --is-ca", *req.CACertID)
	}

	// The CA signs with its row's embedded copy of its key, so that key's
	// lifecycle decides whether it may still sign (B77).
	if err := s.requireCAKeyUsable(ctx, caCert, certScope); err != nil {
		s.logger.LogAuditError(req.UserID.String(), "create_ca_signed_cert", "failed", "CA signing key is unusable", err)
		return nil, fmt.Errorf("cannot issue a CA-signed certificate: %w", err)
	}

	// Decrypt CA private key
	caKeyPEM, err := common.DecryptSecret(caCert.PrivateKey)
	if err != nil {
		s.logger.LogAuditError(req.UserID.String(), "create_ca_signed_cert", "failed", "failed to decrypt CA key", err)
		return nil, fmt.Errorf("failed to decrypt CA key: %w", err)
	}

	// Derive the CA key type from the CA key material itself. This was
	// hardcoded to "RSA" ("assume CA uses RSA for simplicity"), which sent an
	// ECDSA CA down the RSA parsing path and failed (B37).
	caKeyType, err := crypto.DetectPrivateKeyType(caKeyPEM)
	if err != nil {
		s.logger.LogAuditError(req.UserID.String(), "create_ca_signed_cert", "failed", "failed to determine CA key type", err)
		return nil, fmt.Errorf("failed to determine CA key type: %w", err)
	}

	certPEM, err := crypto.CreateCASignedCertificatePEM(privateKeyPEM, key.Type, caCert.Certificate, caKeyPEM, caKeyType, crypto.CertificateTemplate{
		CommonName:   req.Name,
		ValidityDays: req.ValidityDays,
		IsCA:         false,
	})
	if err != nil {
		s.logger.LogAuditError(req.UserID.String(), "create_ca_signed_cert", "failed", "failed to generate certificate", err)
		return nil, fmt.Errorf("failed to generate CA-signed certificate: %w", err)
	}

	// Parse the expiry date from the generated certificate.
	expiresAt, err := extractExpiresAt(certPEM)
	if err != nil {
		s.logger.LogAuditError(req.UserID.String(), "create_ca_signed_cert", "failed", "failed to parse certificate expiry", err)
		return nil, fmt.Errorf("failed to determine certificate expiry: %w", err)
	}

	// Encrypt the private key for storage
	encryptedKey, err := common.EncryptSecret(privateKeyPEM)
	if err != nil {
		s.logger.LogAuditError(req.UserID.String(), "create_ca_signed_cert", "failed", "failed to encrypt private key", err)
		return nil, fmt.Errorf("failed to encrypt private key: %w", err)
	}

	renewalDays := req.RenewalDays
	if renewalDays <= 0 {
		renewalDays = 30
	}

	// Default Enabled to true when not explicitly set.
	enabled := true
	if req.Enabled != nil {
		enabled = *req.Enabled
	}

	// Create certificate entity
	cert := &model.Certificate{
		ID:          uuid.New(),
		UserID:      req.UserID,
		VaultID:     resolveVaultID(req.VaultID),
		KeyID:       req.KeyID,
		CACertID:    req.CACertID,
		Name:        req.Name,
		Certificate: certPEM,
		PrivateKey:  encryptedKey,
		CreatedAt:   time.Now(),
		Tags:        req.Tags,
		ExpiresAt:   expiresAt,
		AutoRenew:   req.AutoRenew,
		RenewalDays: renewalDays,
		Enabled:     enabled,
		NotBefore:   req.NotBefore,
		Version:     1,
		Exportable:  req.Exportable,
	}

	// Store in repository
	if err := s.certRepo.Create(ctx, cert); err != nil {
		s.logger.LogAuditError(req.UserID.String(), "create_ca_signed_cert", "failed", "failed to store certificate", err)
		return nil, fmt.Errorf("failed to store CA-signed certificate: %w", err)
	}

	if err := s.applyCreatePurgeProtection(ctx, req, cert.ID, "create_ca_signed_cert"); err != nil {
		return nil, err
	}

	s.logger.LogAuditInfo(req.UserID.String(), "create_ca_signed_cert", "success", fmt.Sprintf("CA-signed certificate created: %s, ID: %s", req.Name, cert.ID))
	logrus.WithFields(logrus.Fields{
		"cert_id":    cert.ID.String(),
		"name":       cert.Name,
		"key_id":     req.KeyID.String(),
		"ca_cert_id": req.CACertID.String(),
	}).Info("CA-signed certificate created successfully")

	return &CreateCertificateResult{
		CertID:       cert.ID,
		Name:         cert.Name,
		Tags:         cert.Tags,
		CreatedAt:    cert.CreatedAt,
		ExpiresAt:    expiresAt,
		Version:      1,
		Exportable:   cert.Exportable,
		KeyAlgorithm: crypto.KeyAlgorithmFromCertificatePEM(certPEM),
	}, nil
}

// GetCertificate retrieves a certificate authorized by scope and
// enforces its lifecycle policy.
func (s *certificateService) GetCertificate(ctx context.Context, certID uuid.UUID, scope model.Scope) (*model.Certificate, error) {
	actor := scope.ActorID().String()

	cert, err := s.certRepo.Read(ctx, certID, scope)
	if err != nil {
		s.logger.LogAuditError(actor, "get_certificate", "failed",
			fmt.Sprintf("Certificate not found: %s", certID), err)
		return nil, fmt.Errorf("%w: %s", ErrCertNotFound, err.Error())
	}

	if !cert.IsAccessible() {
		s.logger.LogAuditError(actor, "get_certificate", "denied",
			fmt.Sprintf("Certificate is disabled or outside its valid time window: %s", certID), nil)
		return nil, fmt.Errorf("%w", ErrCertLifecycleDenied)
	}

	return cert, nil
}

// GetCertificatePolicy retrieves the policy for certID, authorized by scope
// against the parent certificate.
func (s *certificateService) GetCertificatePolicy(ctx context.Context, certID uuid.UUID, scope model.Scope) (*model.CertificatePolicy, error) {
	if _, err := s.GetCertificate(ctx, certID, scope); err != nil {
		return nil, err
	}
	return s.policyRepo.GetByCertificateIDAny(ctx, certID)
}

// UpsertCertificatePolicy creates or replaces the policy for certID,
// authorized by scope against the parent certificate.
func (s *certificateService) UpsertCertificatePolicy(ctx context.Context, certID uuid.UUID, scope model.Scope, req model.UpsertCertificatePolicyRequest) (*model.CertificatePolicy, error) {
	if _, err := s.GetCertificate(ctx, certID, scope); err != nil {
		return nil, err
	}
	now := time.Now()
	policy := &model.CertificatePolicy{
		ID:               uuid.New(),
		CertificateID:    certID,
		UserID:           scope.ActorID(),
		ValidityMonths:   req.ValidityMonths,
		KeyType:          req.KeyType,
		KeySize:          req.KeySize,
		Curve:            req.Curve,
		Subject:          req.Subject,
		SANs:             req.SANs,
		AutoRenew:        req.AutoRenew,
		DaysBeforeExpiry: req.DaysBeforeExpiry,
		IssuerName:       req.IssuerName,
		CreatedAt:        now,
		UpdatedAt:        now,
	}
	if err := s.policyRepo.Upsert(ctx, policy); err != nil {
		return nil, err
	}
	// Read-after-write so the caller gets the canonical stored row.
	return s.policyRepo.GetByCertificateIDAny(ctx, certID)
}

// DeleteCertificatePolicy removes the policy for certID, authorized by scope
// against the parent certificate.
func (s *certificateService) DeleteCertificatePolicy(ctx context.Context, certID uuid.UUID, scope model.Scope) error {
	if _, err := s.GetCertificate(ctx, certID, scope); err != nil {
		return err
	}
	return s.policyRepo.DeleteByCertificateIDAny(ctx, certID)
}

// ListCertificatePolicies lists every certificate policy in scope's vault,
// each paired with its parent certificate's name.
func (s *certificateService) ListCertificatePolicies(ctx context.Context, scope model.Scope) ([]model.CertificatePolicyWithCertName, error) {
	policies, err := s.policyRepo.ListByVault(ctx, scope)
	if err != nil {
		return nil, fmt.Errorf("failed to list certificate policies: %w", err)
	}
	return policies, nil
}

// ListCertificatesDueForRenewal lists certificates in scope's vault whose
// auto-renewal window has been entered. See the interface doc for why this
// reads the certificates table directly rather than CertificatePolicy.
func (s *certificateService) ListCertificatesDueForRenewal(ctx context.Context, scope model.Scope) ([]model.Certificate, error) {
	due, err := s.certRepo.ListDueForRenewal(ctx, scope)
	if err != nil {
		return nil, fmt.Errorf("failed to list certificates due for renewal: %w", err)
	}
	return due, nil
}

// ListCertificates lists certificates authorized by scope.
func (s *certificateService) ListCertificates(ctx context.Context, scope model.Scope, filter model.CertificateFilter) ([]model.Certificate, error) {
	certs, err := s.certRepo.List(ctx, scope, filter)
	if err != nil {
		s.logger.LogAuditError(scope.ActorID().String(), "list_certificates", "failed", "Failed to list certificates", err)
		return nil, fmt.Errorf("failed to list certificates: %w", err)
	}
	return certs, nil
}

// UpdateCertificate updates a certificate authorized by req.Scope.
func (s *certificateService) UpdateCertificate(ctx context.Context, req UpdateCertificateRequest) error {
	actor := req.Scope.ActorID().String()

	cert, err := s.certRepo.Read(ctx, req.CertID, req.Scope)
	if err != nil {
		s.logger.LogAuditError(actor, "update_certificate", "failed", "Certificate not found", err)
		return fmt.Errorf("%w: %s", ErrCertNotFound, err.Error())
	}

	updated := *cert
	if req.Name != nil {
		updated.Name = *req.Name
	}
	if req.Tags != nil {
		updated.Tags = req.Tags
	}
	if req.AutoRenew != nil {
		updated.AutoRenew = *req.AutoRenew
	}
	if req.RenewalDays != nil {
		updated.RenewalDays = *req.RenewalDays
	}
	if req.Enabled != nil {
		updated.Enabled = *req.Enabled
	}
	if req.NotBefore != nil {
		updated.NotBefore = req.NotBefore
	}

	if err := s.certRepo.Update(ctx, &updated, req.Scope); err != nil {
		s.logger.LogAuditError(actor, "update_certificate", "failed", "Failed to update certificate", err)
		return fmt.Errorf("failed to update certificate: %w", err)
	}

	// Purge protection lives outside the certificate entity, so it is a
	// separate write.
	if req.PurgeProtection != nil {
		if err := s.certRepo.SetPurgeProtection(ctx, req.CertID, *req.PurgeProtection); err != nil {
			s.logger.LogAuditError(actor, "update_certificate", "failed", "failed to set purge protection", err)
			return fmt.Errorf("failed to set purge protection: %w", err)
		}
	}

	s.logger.LogAuditInfo(actor, "update_certificate", "success", fmt.Sprintf("Certificate updated: %s", updated.Name))
	return nil
}

// DeleteCertificate soft-deletes a certificate authorized by scope.
func (s *certificateService) DeleteCertificate(ctx context.Context, certID uuid.UUID, scope model.Scope) error {
	actor := scope.ActorID().String()

	cert, err := s.certRepo.Read(ctx, certID, scope)
	if err != nil {
		s.logger.LogAuditError(actor, "delete_certificate", "failed", "Certificate not found", err)
		return fmt.Errorf("%w: %s", ErrCertNotFound, err.Error())
	}

	if err := s.certRepo.SoftDelete(ctx, certID); err != nil {
		s.logger.LogAuditError(actor, "delete_certificate", "failed", "Failed to soft-delete certificate", err)
		return fmt.Errorf("failed to delete certificate: %w", err)
	}

	s.logger.LogAuditInfo(actor, "delete_certificate", "success", fmt.Sprintf("Certificate deleted: %s", cert.Name))
	return nil
}

// certDeletedInScope reports whether certID names a soft-deleted certificate
// the scope authorizes.
func (s *certificateService) certDeletedInScope(ctx context.Context, certID uuid.UUID, scope model.Scope) (bool, error) {
	deleted, err := s.certRepo.List(ctx, scope, repositories.CertificateFilter{OnlyDeleted: true})
	if err != nil {
		return false, fmt.Errorf("failed to list deleted certificates: %w", err)
	}
	for _, cert := range deleted {
		if cert.ID == certID {
			return true, nil
		}
	}
	return false, nil
}

// ListDeletedCertificates lists soft-deleted certificates authorized by scope.
func (s *certificateService) ListDeletedCertificates(ctx context.Context, scope model.Scope) ([]model.Certificate, error) {
	certs, err := s.certRepo.List(ctx, scope, repositories.CertificateFilter{OnlyDeleted: true})
	if err != nil {
		return nil, fmt.Errorf("failed to list deleted certificates: %w", err)
	}
	return certs, nil
}

// RecoverCertificate restores a soft-deleted certificate authorized by scope.
func (s *certificateService) RecoverCertificate(ctx context.Context, certID uuid.UUID, scope model.Scope) error {
	inScope, err := s.certDeletedInScope(ctx, certID, scope)
	if err != nil {
		return err
	}
	if !inScope {
		s.logger.LogAuditError(scope.ActorID().String(), "recover_certificate", "failed",
			"Certificate not found in deleted state within scope", nil)
		return fmt.Errorf("%w", ErrCertNotFound)
	}
	if err := s.certRepo.RecoverCertificate(ctx, certID); err != nil {
		return fmt.Errorf("failed to recover certificate: %w", err)
	}
	s.logger.LogAuditInfo(scope.ActorID().String(), "recover_certificate", "success",
		fmt.Sprintf("Certificate recovered: %s", certID))
	return nil
}

// PurgeCertificate permanently deletes a soft-deleted certificate authorized by scope.
func (s *certificateService) PurgeCertificate(ctx context.Context, certID uuid.UUID, scope model.Scope) error {
	if s.globalPurgeProtection {
		s.logger.LogAuditError(scope.ActorID().String(), "purge_certificate", "failed",
			"Global purge protection is enabled", nil)
		return repositories.ErrGlobalPurgeProtectionEnabled
	}

	inScope, err := s.certDeletedInScope(ctx, certID, scope)
	if err != nil {
		return err
	}
	if !inScope {
		s.logger.LogAuditError(scope.ActorID().String(), "purge_certificate", "failed",
			"Certificate not found in deleted state within scope", nil)
		return fmt.Errorf("%w", ErrCertNotFound)
	}

	// Vault-level purge protection cascades to the certificates the vault
	// contains, so a protected vault blocks the per-item purge path too. This
	// check fails closed: for a certificate with no flag of its own it is the
	// only protection layer, so a vault that cannot be read blocks the purge
	// rather than silently skipping the check.
	if s.vaultRepo != nil && scope.VaultID() != uuid.Nil {
		vault, err := s.vaultRepo.ReadByID(ctx, scope.VaultID())
		if err != nil {
			s.logger.LogAuditError(scope.ActorID().String(), "purge_certificate", "failed",
				"Failed to check vault purge protection", err)
			return fmt.Errorf("failed to check vault purge protection: %w", err)
		}
		if vault.PurgeProtection {
			s.logger.LogAuditError(scope.ActorID().String(), "purge_certificate", "failed",
				"Vault has purge protection enabled", nil)
			return repositories.ErrCertPurgeProtected
		}
	}

	if err := s.certRepo.PurgeCertificate(ctx, certID); err != nil {
		return fmt.Errorf("failed to purge certificate: %w", err)
	}
	s.logger.LogAuditInfo(scope.ActorID().String(), "purge_certificate", "success",
		fmt.Sprintf("Certificate purged: %s", certID))
	return nil
}

// renewCASignedBody re-issues a CA-signed certificate through the CA that
// signed the original, so the issuer and the chain survive the renewal.
//
// The CA is resolved with the same authorization CreateCASignedCertificate
// uses -- the scoped read plus the owner comparison -- and then read again
// through GetCertificate, which adds the lifecycle gate. A CA that was
// deleted, moved out of scope, disabled or has itself expired therefore
// refuses the renewal. That is deliberately stricter than creation, which
// will still sign with an expired CA: a renewal exists to produce a usable
// certificate, and one signed by an expired CA cannot chain-verify.
func (s *certificateService) renewCASignedBody(ctx context.Context, original *model.Certificate, scope model.Scope, privateKeyPEM, keyType string, validityDays int) (string, error) {
	userID := scope.ActorID()
	caCertID := *original.CACertID

	if err := s.ValidateCertificateAccess(ctx, caCertID, scope); err != nil {
		s.logger.LogAuditError(userID.String(), "renew_certificate", "failed", "cannot access signing CA certificate", err)
		return "", fmt.Errorf("cannot renew CA-signed certificate: signing CA %s is not accessible: %w", caCertID, err)
	}

	caCert, err := s.GetCertificate(ctx, caCertID, scope)
	if err != nil {
		s.logger.LogAuditError(userID.String(), "renew_certificate", "failed", "signing CA certificate is unusable", err)
		return "", fmt.Errorf("cannot renew CA-signed certificate: signing CA %s is unusable: %w", caCertID, err)
	}

	// x509.CreateCertificate does not check the parent's IsCA/KeyUsage bits,
	// so it will happily sign through a certificate that cannot actually
	// verify as an issuer. Refuse before that happens rather than producing a
	// certificate that reports success but fails CheckSignatureFrom/Verify.
	caStatus, err := inspectCertificateCA(caCert.Certificate)
	if err != nil {
		s.logger.LogAuditError(userID.String(), "renew_certificate", "failed", "failed to inspect signing CA certificate", err)
		return "", fmt.Errorf("cannot renew CA-signed certificate: failed to inspect signing CA %s: %w", caCertID, err)
	}
	if caStatus != caStatusCA {
		s.logger.LogAuditError(userID.String(), "renew_certificate", "failed", "signing CA certificate cannot sign certificates", nil)
		return "", fmt.Errorf("signing CA %s cannot sign certificates (asserts CA without keyCertSign, or is not a CA); reissue it with --is-ca", caCertID)
	}

	// See CreateCASignedCertificate: the CA's own key must still be usable.
	if err := s.requireCAKeyUsable(ctx, caCert, scope); err != nil {
		s.logger.LogAuditError(userID.String(), "renew_certificate", "failed", "signing CA key is unusable", err)
		return "", fmt.Errorf("cannot renew CA-signed certificate: %w", err)
	}

	caKeyPEM, err := common.DecryptSecret(caCert.PrivateKey)
	if err != nil {
		s.logger.LogAuditError(userID.String(), "renew_certificate", "failed", "failed to decrypt CA key", err)
		return "", fmt.Errorf("failed to decrypt CA key: %w", err)
	}

	caKeyType, err := crypto.DetectPrivateKeyType(caKeyPEM)
	if err != nil {
		s.logger.LogAuditError(userID.String(), "renew_certificate", "failed", "failed to determine CA key type", err)
		return "", fmt.Errorf("failed to determine CA key type: %w", err)
	}

	certPEM, err := crypto.CreateCASignedCertificatePEM(privateKeyPEM, keyType, caCert.Certificate, caKeyPEM, caKeyType, crypto.CertificateTemplate{
		CommonName:   original.Name,
		ValidityDays: validityDays,
		IsCA:         false,
	})
	if err != nil {
		s.logger.LogAuditError(userID.String(), "renew_certificate", "failed", "failed to generate CA-signed certificate", err)
		return "", fmt.Errorf("failed to generate renewed certificate: %w", err)
	}
	return certPEM, nil
}

// isSelfSignedPEM reports whether a stored certificate signed itself. It
// requires both that the certificate verifies against its own public key and
// that its issuer equals its own subject. The signature check alone is not
// enough: a legacy row with no ca_cert_id link whose CA happens to share the
// leaf's keypair would self-verify while still naming a different issuer, and
// treating that as self-signed would silently re-sign it under a new issuer
// on renewal -- the exact failure this check exists to catch.
func isSelfSignedPEM(certPEM string) (bool, error) {
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		return false, fmt.Errorf("failed to decode PEM block from certificate")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return false, fmt.Errorf("failed to parse X.509 certificate: %w", err)
	}
	if !bytes.Equal(cert.RawIssuer, cert.RawSubject) {
		return false, nil
	}
	return cert.CheckSignature(cert.SignatureAlgorithm, cert.RawTBSCertificate, cert.Signature) == nil, nil
}

// RenewCertificate creates a new certificate to replace an expiring one.
// It generates a new certificate with the same properties as the original.
//
// Parameters:
//
//	ctx: The context for the operation.
//	certID: The certificate to renew.
//	scope: The authorization scope for the read and the write; scope.ActorID()
//	  is also used for audit logging and the internal key-ownership checks.
//	validityDays: The validity period for the new certificate.
//
// Returns:
//
//	The new certificate information or an error if renewal fails.
func (s *certificateService) RenewCertificate(ctx context.Context, certID uuid.UUID, scope model.Scope, validityDays int) (*CreateCertificateResult, error) {
	userID := scope.ActorID()

	// Verify certificate exists and access; original carries AutoRenew/RenewalDays.
	original, err := s.GetCertificate(ctx, certID, scope)
	if err != nil {
		return nil, err
	}

	if original.KeyID == (uuid.UUID{}) {
		return nil, &renewError{"certificate has no associated key ID; cannot renew", ErrRenewNotPossible}
	}

	if validityDays <= 0 {
		s.logger.LogAuditError(userID.String(), "renew_certificate", "failed", "validity days must be positive", nil)
		return nil, fmt.Errorf("validity days must be positive")
	}

	// The row keeps its name and ID: the current version is archived and the
	// row is bumped to the next version in one transaction (ArchiveAndRenew).
	// The caller's own scope already names the vault the certificate lives in,
	// so the signing key is authorized against that vault too (B32).
	key, err := s.keyRepo.Read(ctx, original.KeyID, scope)
	if err != nil {
		s.logger.LogAuditError(userID.String(), "renew_certificate", "failed", fmt.Sprintf("key not found: %s", err), err)
		return nil, &renewError{"key not found: " + err.Error(), ErrRenewKeyNotFound}
	}
	if key.UserID != userID {
		s.logger.LogAuditError(userID.String(), "renew_certificate", "failed", "forbidden: cannot use other users' keys", nil)
		return nil, ErrRenewKeyForbidden
	}
	// Renewal signs with the key, so it refuses the keys the key crypto path
	// refuses in loadAndAuthorize (B77).
	if err := requireUsableKey(key); err != nil {
		s.logger.LogAuditError(userID.String(), "renew_certificate", "failed", "signing key is unusable", nil)
		return nil, err
	}

	privateKeyPEM, err := common.DecryptSecret(key.Value)
	if err != nil {
		s.logger.LogAuditError(userID.String(), "renew_certificate", "failed", "failed to decrypt key", err)
		return nil, fmt.Errorf("failed to decrypt key: %w", err)
	}

	// Renewal preserves what the certificate already was. This used to pass
	// IsCA: true unconditionally, so the first renewal promoted any
	// certificate to a Certificate Authority (B44). Forcing false instead
	// would be the mirror-image bug: it would strip the CA bit off a real CA.
	//
	// The one status that is not preserved is caStatusUnsignableCA. Every
	// certificate issued before this release asserts CA:TRUE without
	// keyCertSign, and that missing bit is the only reason none of them ever
	// worked as a CA. Renewing such a certificate as a CA would hand it the
	// keyCertSign the fixed template now adds and turn it into a working
	// authority, unattended, via the auto-renew scheduler. It is renewed as a
	// leaf instead, and the demotion is audit-logged below.
	status, err := inspectCertificateCA(original.Certificate)
	if err != nil {
		s.logger.LogAuditError(userID.String(), "renew_certificate", "failed", "failed to inspect stored certificate", err)
		return nil, fmt.Errorf("failed to inspect stored certificate: %w", err)
	}
	isCA := status == caStatusCA
	demoted := status == caStatusUnsignableCA

	var certPEM string
	if original.CACertID != nil {
		certPEM, err = s.renewCASignedBody(ctx, original, scope, privateKeyPEM, key.Type, validityDays)
		if err != nil {
			return nil, err
		}
	} else {
		// A row created before ca_cert_id existed carries no CA link. Renewing
		// it self-signed would silently drop a real issuer -- the bug this
		// branch exists to fix -- so refuse when the stored body says the
		// certificate was signed by somebody else.
		selfSigned, inspectErr := isSelfSignedPEM(original.Certificate)
		if inspectErr != nil {
			s.logger.LogAuditError(userID.String(), "renew_certificate", "failed", "failed to inspect stored certificate", inspectErr)
			return nil, fmt.Errorf("failed to inspect stored certificate: %w", inspectErr)
		}
		if !selfSigned {
			s.logger.LogAuditError(userID.String(), "renew_certificate", "failed", "certificate records no signing CA but is not self-signed", nil)
			return nil, &renewError{fmt.Sprintf("cannot renew certificate %s: it was signed by a CA this installation no longer records; re-create it against its CA instead", original.ID), ErrRenewNotPossible}
		}

		// isCA is the flag read off the certificate being replaced, above.
		// Renewal preserves it: forcing true would make every renewal issue a
		// CA (B44), and forcing false would strip the CA bit from every CA
		// this system issued, the first time it renewed.
		certPEM, err = crypto.CreateSelfSignedCertificatePEM(privateKeyPEM, key.Type, crypto.CertificateTemplate{
			CommonName:   original.Name,
			ValidityDays: validityDays,
			IsCA:         isCA,
		})
		if err != nil {
			s.logger.LogAuditError(userID.String(), "renew_certificate", "failed", "failed to generate certificate", err)
			return nil, fmt.Errorf("failed to generate renewed certificate: %w", err)
		}
	}

	notBefore, notAfter, err := extractValidity(certPEM)
	if err != nil {
		s.logger.LogAuditError(userID.String(), "renew_certificate", "failed", "failed to parse certificate validity", err)
		return nil, fmt.Errorf("failed to determine certificate validity: %w", err)
	}

	encryptedKey, err := common.EncryptSecret(privateKeyPEM)
	if err != nil {
		s.logger.LogAuditError(userID.String(), "renew_certificate", "failed", "failed to encrypt private key", err)
		return nil, fmt.Errorf("failed to encrypt private key: %w", err)
	}

	if s.versionRepo == nil {
		s.logger.LogAuditError(userID.String(), "renew_certificate", "failed", "certificate version repository is not configured", nil)
		return nil, ErrCertVersioningUnavailable
	}

	// Every guard above has passed, so only now is anything written. The
	// current version is archived under its own number and the row moves to
	// the next one, in one repository transaction guarded by the version the
	// row was read at. A concurrent renewal that committed first makes this
	// one a conflict and writes nothing.
	archived := original.ArchiveRecord()
	renewed := *original
	renewed.Certificate = certPEM
	renewed.PrivateKey = encryptedKey
	renewed.Version = archived.Version + 1
	renewed.CreatedAt = time.Now()
	renewed.ExpiresAt = &notAfter
	renewed.NotBefore = &notBefore
	renewed.Enabled = true

	if err := s.versionRepo.ArchiveAndRenew(ctx, archived, &renewed, scope); err != nil {
		s.logger.LogAuditError(userID.String(), "renew_certificate", "failed", "failed to store renewed certificate", err)
		return nil, fmt.Errorf("failed to store renewed certificate: %w", err)
	}

	// The demotion is logged only once the renewed certificate is actually
	// stored, so the audit trail never claims a change that did not land.
	if demoted {
		s.logger.LogAuditInfo(userID.String(), "renew_certificate", "ca_demoted",
			fmt.Sprintf("certificate %s (ID: %s) asserted CA:TRUE without keyCertSign and was renewed as a non-CA leaf; reissue it with --is-ca if it is genuinely a certificate authority",
				renewed.Name, renewed.ID))
	}

	s.logger.LogAuditInfo(userID.String(), "renew_certificate", "success",
		fmt.Sprintf("certificate renewed: %s, ID: %s, version %d archived, now version %d", renewed.Name, renewed.ID, archived.Version, renewed.Version))

	return &CreateCertificateResult{
		CertID:    renewed.ID,
		Name:      renewed.Name,
		Tags:      renewed.Tags,
		CreatedAt: renewed.CreatedAt,
		ExpiresAt: renewed.ExpiresAt,
		Version:   renewed.Version,

		Exportable:   renewed.Exportable,
		KeyAlgorithm: crypto.KeyAlgorithmFromCertificatePEM(renewed.Certificate),
	}, nil
}

// readVersionedParent authorizes a version operation against the parent
// certificate. The scoped read is the whole gate: certificate_versions has no
// vault column, so a version is reachable only through a parent the caller
// can read. It is deliberately not lifecycle-gated, so a disabled
// certificate's history can still be inspected and re-enabled, the same way
// UpdateCertificate reads a disabled certificate.
func (s *certificateService) readVersionedParent(ctx context.Context, certID uuid.UUID, scope model.Scope, action string) (*model.Certificate, error) {
	actor := scope.ActorID().String()
	if s.versionRepo == nil {
		s.logger.LogAuditError(actor, action, "failed", "certificate version repository is not configured", nil)
		return nil, ErrCertVersioningUnavailable
	}
	cert, err := s.certRepo.Read(ctx, certID, scope)
	if err != nil {
		s.logger.LogAuditError(actor, action, "failed", "Certificate not found", err)
		return nil, fmt.Errorf("%w: %s", ErrCertNotFound, err.Error())
	}
	return cert, nil
}

// ListCertificateVersions returns certID's versions, oldest first, with the
// current one, read off the certificate row, last.
func (s *certificateService) ListCertificateVersions(ctx context.Context, certID uuid.UUID, scope model.Scope) ([]model.CertificateVersion, error) {
	parent, err := s.readVersionedParent(ctx, certID, scope, "list_certificate_versions")
	if err != nil {
		return nil, err
	}
	archived, err := s.versionRepo.ListVersions(ctx, certID)
	if err != nil {
		return nil, fmt.Errorf("failed to list certificate versions: %w", err)
	}
	return append(archived, parent.VersionMetadata()), nil
}

// GetCertificateVersion returns one version's metadata. The current version
// comes from the certificate row; earlier ones from certificate_versions.
func (s *certificateService) GetCertificateVersion(ctx context.Context, certID uuid.UUID, version int, scope model.Scope) (*model.CertificateVersion, error) {
	if version < 1 {
		return nil, fmt.Errorf("%w: version must be >= 1", model.ErrCertificateVersionNotFound)
	}
	parent, err := s.readVersionedParent(ctx, certID, scope, "get_certificate_version")
	if err != nil {
		return nil, err
	}
	current := parent.CurrentVersion()
	switch {
	case version == current:
		meta := parent.VersionMetadata()
		return &meta, nil
	case version > current:
		return nil, fmt.Errorf("%w: certificate %s has no version %d", model.ErrCertificateVersionNotFound, certID, version)
	}
	return s.versionRepo.GetVersion(ctx, certID, version)
}

// UpdateCertificateVersion changes one version's lifecycle attributes.
// Updating the current version writes the certificate row, exactly as a
// certificate update of the same attributes would; the write is guarded by
// the version number, so a renewal in between turns it into a conflict.
func (s *certificateService) UpdateCertificateVersion(ctx context.Context, req UpdateCertificateVersionRequest) (*model.CertificateVersion, error) {
	actor := req.Scope.ActorID().String()
	if req.Enabled == nil && req.ExpiresAt == nil && req.NotBefore == nil {
		return nil, fmt.Errorf("%w: at least one of enabled, expires_at or not_before is required", model.ErrInvalidCertificateVersionAttributes)
	}

	target, err := s.GetCertificateVersion(ctx, req.CertID, req.Version, req.Scope)
	if err != nil {
		s.logger.LogAuditError(actor, "update_certificate_version", "failed", "Certificate version not found", err)
		return nil, err
	}

	attrs := model.CertificateVersionAttributes{Enabled: target.Enabled, ExpiresAt: target.ExpiresAt, NotBefore: target.NotBefore}
	if req.Enabled != nil {
		attrs.Enabled = *req.Enabled
	}
	if req.ExpiresAt != nil {
		attrs.ExpiresAt = req.ExpiresAt
	}
	if req.NotBefore != nil {
		attrs.NotBefore = req.NotBefore
	}
	if err := model.ValidateCertificateVersionWindow(attrs.NotBefore, attrs.ExpiresAt); err != nil {
		s.logger.LogAuditError(actor, "update_certificate_version", "failed", "invalid version attributes", err)
		return nil, err
	}

	if target.Current {
		err = s.versionRepo.UpdateCurrentLifecycle(ctx, req.CertID, target.Version, attrs, req.Scope)
	} else {
		err = s.versionRepo.UpdateVersionLifecycle(ctx, req.CertID, target.Version, attrs)
	}
	if err != nil {
		s.logger.LogAuditError(actor, "update_certificate_version", "failed", "Failed to update certificate version", err)
		return nil, fmt.Errorf("failed to update certificate version: %w", err)
	}

	updated := *target
	updated.Enabled = attrs.Enabled
	updated.ExpiresAt = attrs.ExpiresAt
	updated.NotBefore = attrs.NotBefore
	s.logger.LogAuditInfo(actor, "update_certificate_version", "success",
		fmt.Sprintf("Certificate %s version %d updated", req.CertID, target.Version))
	return &updated, nil
}

// ValidateCertificateAccess validates that the caller may use a specific
// certificate as a signing CA.
//
// The scoped read is the vault half of the authorization: the repository's
// predicate makes a certificate in another vault simply invisible, so a caller
// cannot reach across the vault boundary. The owner comparison that follows is
// retained deliberately (see ValidateKeyOwnership for why).
//
// Parameters:
//
//	ctx: The context for the operation.
//	certID: The certificate's unique identifier.
//	scope: The caller's vault scope, carrying both the target vault and the
//	  acting user.
//
// Returns:
//
//	An error if access is denied.
func (s *certificateService) ValidateCertificateAccess(ctx context.Context, certID uuid.UUID, scope model.Scope) error {
	actorID := scope.ActorID()

	cert, err := s.certRepo.Read(ctx, certID, scope)
	if err != nil {
		s.logger.LogAuditError(actorID.String(), "validate_certificate_access", "failed", fmt.Sprintf("certificate not found: %s", err), err)
		return fmt.Errorf("certificate not found: %w", err)
	}

	if cert.UserID != actorID {
		s.logger.LogAuditError(actorID.String(), "validate_certificate_access", "failed", "forbidden: cannot access other users' certificates", nil)
		return fmt.Errorf("forbidden: cannot access other users' certificates")
	}

	return nil
}

// ValidateKeyOwnership validates that the caller may use a specific key to
// sign a certificate.
//
// Two checks, and both matter (B32):
//
//   - The scoped read enforces the vault boundary. This used to be an admin
//     scope, which carries no vault predicate, so a user who owned a key in
//     vault A could mint a certificate in vault B signed by it. The vault is
//     the security boundary everywhere else in the system; it applies here now.
//   - The owner comparison is kept on purpose. Dropping it would match how the
//     rest of the data plane works -- where a scoped read is the whole gate --
//     but it would also let any vault member sign with another member's key,
//     which is strictly more access than before. Widening permissions is not
//     something a security fix should do on the way past; that call belongs in
//     its own change.
//
// The key must also be usable: not revoked, enabled, and inside its validity
// window, matching loadAndAuthorize in the key crypto path (B77).
//
// Parameters:
//
//	ctx: The context for the operation.
//	keyID: The key's unique identifier.
//	scope: The caller's vault scope, carrying both the target vault and the
//	  acting user.
//
// Returns:
//
//	An error if access is denied.
func (s *certificateService) ValidateKeyOwnership(ctx context.Context, keyID uuid.UUID, scope model.Scope) error {
	actorID := scope.ActorID()

	key, err := s.keyRepo.Read(ctx, keyID, scope)
	if err != nil {
		s.logger.LogAuditError(actorID.String(), "validate_key_ownership", "failed", fmt.Sprintf("key not found: %s", err), err)
		return fmt.Errorf("key not found: %w", err)
	}

	if key.UserID != actorID {
		s.logger.LogAuditError(actorID.String(), "validate_key_ownership", "failed", "forbidden: cannot use other users' keys", nil)
		return fmt.Errorf("forbidden: cannot use other users' keys")
	}

	// Issuing a certificate signs with the key, so it refuses the keys the
	// key crypto path refuses in loadAndAuthorize (B77).
	if err := requireUsableKey(key); err != nil {
		s.logger.LogAuditError(actorID.String(), "validate_key_ownership", "failed", "signing key is unusable", nil)
		return err
	}

	return nil
}

// requireCAKeyUsable refuses to sign through a CA certificate whose own
// linked key is revoked, disabled, outside its validity window, or no longer
// readable in scope. The CA row stores a copy of that key's private PEM, so
// without this check revoking the key would not stop the CA from issuing
// (B77). A CA row with no key link is refused too: every CA that passes
// inspectCertificateCA was issued after key_id existed, so a missing link
// means it was dropped at restore (B76) and the key cannot be checked.
func (s *certificateService) requireCAKeyUsable(ctx context.Context, caCert *model.Certificate, scope model.Scope) error {
	if caCert.KeyID == uuid.Nil {
		return fmt.Errorf("%w: CA certificate %s records no signing key", ErrSigningKeyUnusable, caCert.ID)
	}
	key, err := s.keyRepo.Read(ctx, caCert.KeyID, scope)
	if err != nil {
		return fmt.Errorf("%w: CA signing key %s is not readable: %w", ErrSigningKeyUnusable, caCert.KeyID, err)
	}
	return requireUsableKey(key)
}

// requireUsableKey refuses a key that is revoked, disabled, or outside its
// validity window, with an error wrapping ErrSigningKeyUnusable.
func requireUsableKey(key *model.Key) error {
	if key.Revoked || !key.IsAccessible() {
		return fmt.Errorf("%w: %s", ErrSigningKeyUnusable, key.ID)
	}
	return nil
}

// extractExpiresAt parses the NotAfter field from a PEM-encoded X.509 certificate.
func extractExpiresAt(certPEM string) (*time.Time, error) {
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block from certificate")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse X.509 certificate: %w", err)
	}
	t := cert.NotAfter
	return &t, nil
}

// extractValidity returns the NotBefore and NotAfter of a PEM-encoded X.509
// certificate. A new version takes both dates from its certificate.
func extractValidity(certPEM string) (time.Time, time.Time, error) {
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		return time.Time{}, time.Time{}, fmt.Errorf("failed to decode PEM block from certificate")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return time.Time{}, time.Time{}, fmt.Errorf("failed to parse certificate: %w", err)
	}
	return cert.NotBefore, cert.NotAfter, nil
}

// caStatus describes what authority a stored certificate actually carries.
type caStatus int

const (
	// caStatusLeaf is an ordinary certificate: no CA basic constraint.
	caStatusLeaf caStatus = iota
	// caStatusCA is a working certificate authority. It asserts CA:TRUE and
	// carries the keyCertSign usage that verifiers require of a signer.
	caStatusCA
	// caStatusUnsignableCA is a certificate that asserts CA:TRUE but has no
	// keyCertSign, so nothing it signed ever verified. This shape identifies a
	// certificate issued before B43 and B44 were fixed; the current template
	// cannot produce it, because IsCA now always implies keyCertSign.
	caStatusUnsignableCA
)

// inspectCertificateCA reports what authority a stored certificate carries.
// Renewal reads this out of the certificate it is replacing, so a leaf renews
// as a leaf and a real CA renews as a CA -- neither value is forced. This
// replaced an earlier certificateIsCA helper that returned cert.IsCA alone and
// so could not tell a working CA from a pre-fix one.
//
// Parse failures are fail-closed on purpose: the caller aborts the renewal
// rather than guessing an authority for a certificate it cannot read.
//
// Parameters:
//   - certPEM: The PEM-encoded certificate.
//
// Returns:
//
//	The certificate's CA status, or an error if it cannot be parsed.
func inspectCertificateCA(certPEM string) (caStatus, error) {
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		return caStatusLeaf, fmt.Errorf("failed to decode PEM block from certificate")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return caStatusLeaf, fmt.Errorf("failed to parse X.509 certificate: %w", err)
	}
	if !cert.IsCA {
		return caStatusLeaf, nil
	}
	if cert.KeyUsage&x509.KeyUsageCertSign == 0 {
		return caStatusUnsignableCA, nil
	}
	return caStatusCA, nil
}
