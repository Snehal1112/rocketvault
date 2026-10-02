package certificates

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"

	"rocketvault/common"
	"rocketvault/internal/crypto"
	"rocketvault/model"
)

// maxExportChainDepth caps the CA walk, so an edited ca_cert_id cannot make
// an export loop or walk forever.
const maxExportChainDepth = 10

// ErrCertificateChainUnavailable is returned when the issuer chain cannot be
// built: a CA is missing, soft-deleted, outside the caller's vault, part of
// a cycle, deeper than maxExportChainDepth, or did not sign the certificate
// below it. Nothing is exported.
var ErrCertificateChainUnavailable = errors.New("certificate chain cannot be built")

// ExportCertificateRequest selects what ExportCertificate returns. Password
// is a pointer so pkcs12 can tell "absent" from "empty"; an empty password is
// allowed.
type ExportCertificateRequest struct {
	Format   string  // model.ExportFormatPEM or model.ExportFormatPKCS12.
	Password *string // Required for pkcs12; ignored for pem.
	Compat   string  // "", model.ExportCompatModern or model.ExportCompatLegacy.
	Version  int     // 0 means the current version.
}

// ExportCertificateResult is one exported certificate version. It carries
// private material and must never be logged, cached or stored.
type ExportCertificateResult struct {
	ID             uuid.UUID
	Name           string
	Version        int
	Format         string
	CertificatePEM string // Leaf first, then intermediates; pem only.
	PrivateKeyPEM  string // Unencrypted PKCS#8; pem only.
	PKCS12         []byte // pkcs12 only.
	NotBefore      *time.Time
	ExpiresAt      *time.Time
	KeyAlgorithm   string
}

// validateExportRequest rejects a malformed request before anything is read.
// The messages are fixed phrases and never include the password.
func validateExportRequest(req ExportCertificateRequest) error {
	switch req.Format {
	case model.ExportFormatPEM, model.ExportFormatPKCS12:
	default:
		return fmt.Errorf("%w: format must be pem or pkcs12", model.ErrInvalidExportRequest)
	}
	switch req.Compat {
	case "", model.ExportCompatModern, model.ExportCompatLegacy:
	default:
		return fmt.Errorf("%w: compat must be modern or legacy", model.ErrInvalidExportRequest)
	}
	if req.Format == model.ExportFormatPKCS12 && req.Password == nil {
		return fmt.Errorf("%w: pkcs12 requires a password field (it may be empty)", model.ErrInvalidExportRequest)
	}
	if req.Version < 0 {
		return fmt.Errorf("%w: version must be 0 or a positive version number", model.ErrInvalidExportRequest)
	}
	return nil
}

// ExportCertificate implements CertificateService.ExportCertificate.
func (s *certificateService) ExportCertificate(ctx context.Context, scope model.Scope, id uuid.UUID, req ExportCertificateRequest) (*ExportCertificateResult, error) {
	actor := scope.ActorID().String()
	if err := validateExportRequest(req); err != nil {
		return nil, err
	}

	// 1. The scoped repository read is the vault gate; a cache is never used.
	parent, err := s.certRepo.Read(ctx, id, scope)
	if err != nil {
		s.logger.LogAuditError(actor, "export_certificate", "failed", fmt.Sprintf("Certificate not found: %s", id), nil)
		return nil, fmt.Errorf("%w: %s", ErrCertNotFound, err.Error())
	}
	if !parent.IsAccessible() {
		s.logger.LogAuditError(actor, "export_certificate", "denied", fmt.Sprintf("Certificate %s is disabled or outside its valid time window", id), nil)
		return nil, ErrCertLifecycleDenied
	}

	// 2. Resolve the version and apply the per-version gate.
	meta, certPEM, keyCipher, err := s.resolveExportVersion(ctx, parent, req.Version)
	if err != nil {
		return nil, err
	}
	if !parent.VersionUsable(meta) {
		s.logger.LogAuditError(actor, "export_certificate", "denied", fmt.Sprintf("Certificate %s version %d is disabled or outside its valid time window", id, meta.Version), nil)
		return nil, ErrCertLifecycleDenied
	}
	keyAlgorithm := crypto.KeyAlgorithmFromCertificatePEM(certPEM)
	refuse := func(reason string) error {
		s.logger.LogAuditError(actor, "export_certificate", "denied", fmt.Sprintf("Certificate %s not exportable: %s", id, reason), nil)
		return &model.ExportRefusedError{Sentinel: model.ErrCertificateNotExportable, Reason: reason, Name: parent.Name, KeyAlgorithm: keyAlgorithm}
	}

	// 3. The immutable flag.
	if !parent.Exportable {
		return nil, refuse("the certificate was not created with exportable: true")
	}

	// 4. Decrypt the version's own key copy and re-marshal it as PKCS#8.
	keyPEM, err := common.DecryptSecret(keyCipher)
	if err != nil {
		return nil, fmt.Errorf("decrypt certificate key: %w", err)
	}
	keyType, err := crypto.DetectPrivateKeyType(keyPEM)
	if err != nil {
		return nil, fmt.Errorf("classify certificate key: %w", err)
	}
	if keyType == model.KeyTypeES256K {
		return nil, refuse("ES256K (secp256k1) keys cannot be encoded as PKCS#8")
	}
	priv, err := crypto.ParsePrivateKey(keyPEM, keyType)
	if err != nil {
		return nil, fmt.Errorf("parse certificate key: %w", err)
	}
	pkcs8PEM, err := crypto.MarshalPKCS8PrivateKeyPEM(priv)
	if errors.Is(err, crypto.ErrNotPKCS8Encodable) {
		return nil, refuse("the key type cannot be encoded as PKCS#8")
	}
	if err != nil {
		return nil, fmt.Errorf("encode certificate key: %w", err)
	}

	// 5. Leaf first, then intermediates, root excluded.
	leaf, err := parseLeaf(certPEM)
	if err != nil {
		return nil, err
	}
	intermediates, err := s.exportChain(ctx, parent, leaf, scope)
	if err != nil {
		s.logger.LogAuditError(actor, "export_certificate", "failed", fmt.Sprintf("Certificate %s chain unavailable", id), nil)
		return nil, err
	}

	notBefore, notAfter := leaf.NotBefore, leaf.NotAfter
	result := &ExportCertificateResult{
		ID: parent.ID, Name: parent.Name, Version: meta.Version, Format: req.Format,
		NotBefore: &notBefore, ExpiresAt: &notAfter, KeyAlgorithm: keyAlgorithm,
	}

	// 6. Encode.
	if req.Format == model.ExportFormatPKCS12 {
		pfx, err := crypto.EncodePKCS12(priv, leaf, intermediates, *req.Password, req.Compat == model.ExportCompatLegacy)
		if err != nil {
			return nil, err
		}
		result.PKCS12 = pfx
	} else {
		var chain strings.Builder
		chain.Write(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leaf.Raw}))
		for _, c := range intermediates {
			chain.Write(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw}))
		}
		result.CertificatePEM = chain.String()
		result.PrivateKeyPEM = pkcs8PEM
	}

	s.logger.LogAuditInfo(actor, "export_certificate", "success",
		fmt.Sprintf("Certificate %s version %d exported as %s", id, meta.Version, req.Format))
	return result, nil
}

// resolveExportVersion returns the addressed version's metadata, body and
// encrypted key copy. 0 or the current number reads the parent row; an
// archived number reads certificate_versions, whose only gate is the scoped
// parent read the caller already made.
func (s *certificateService) resolveExportVersion(ctx context.Context, parent *model.Certificate, version int) (model.CertificateVersion, string, string, error) {
	current := parent.CurrentVersion()
	if version == 0 || version == current {
		return parent.VersionMetadata(), parent.Certificate, parent.PrivateKey, nil
	}
	if version > current {
		return model.CertificateVersion{}, "", "", fmt.Errorf("%w: certificate %s has no version %d", model.ErrCertificateVersionNotFound, parent.ID, version)
	}
	if s.versionRepo == nil {
		return model.CertificateVersion{}, "", "", ErrCertVersioningUnavailable
	}
	records, err := s.versionRepo.ListVersionRecords(ctx, parent.ID)
	if err != nil {
		return model.CertificateVersion{}, "", "", fmt.Errorf("read certificate versions: %w", err)
	}
	for _, rec := range records {
		if rec.Version == version {
			return rec.Metadata(), rec.Certificate, rec.PrivateKey, nil
		}
	}
	return model.CertificateVersion{}, "", "", fmt.Errorf("%w: certificate %s has no version %d", model.ErrCertificateVersionNotFound, parent.ID, version)
}

// parseLeaf decodes the first certificate in certPEM.
func parseLeaf(certPEM string) (*x509.Certificate, error) {
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		return nil, fmt.Errorf("decode stored certificate: no PEM block")
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse stored certificate: %w", err)
	}
	return leaf, nil
}

// exportChain walks CACertID from parent and returns the intermediates in
// order, stopping before the self-signed root. Every hop is a scoped read,
// so a CA outside the caller's vault is never read. A missing hop, a cycle
// or a walk past maxExportChainDepth fails with
// ErrCertificateChainUnavailable. Each hop uses the CA's current PEM, so
// every hop must have signed the certificate below it. A CA renewed after
// its key was rotated carries a new public key that did not sign the child;
// such a chain also fails closed instead of exporting a chain that cannot
// verify.
func (s *certificateService) exportChain(ctx context.Context, parent *model.Certificate, leaf *x509.Certificate, scope model.Scope) ([]*x509.Certificate, error) {
	if self, err := isSelfSignedPEM(string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leaf.Raw}))); err == nil && self {
		return nil, nil
	}
	var chain []*x509.Certificate
	child := leaf
	seen := map[uuid.UUID]bool{parent.ID: true}
	next := parent.CACertID
	for depth := 0; next != nil; depth++ {
		if depth >= maxExportChainDepth {
			return nil, fmt.Errorf("%w: deeper than %d", ErrCertificateChainUnavailable, maxExportChainDepth)
		}
		if seen[*next] {
			return nil, fmt.Errorf("%w: cycle at %s", ErrCertificateChainUnavailable, *next)
		}
		seen[*next] = true
		hop, err := s.certRepo.Read(ctx, *next, scope)
		if err != nil {
			return nil, fmt.Errorf("%w: issuer %s is not readable", ErrCertificateChainUnavailable, *next)
		}
		cert, err := parseLeaf(hop.Certificate)
		if err != nil {
			return nil, fmt.Errorf("%w: issuer %s: %w", ErrCertificateChainUnavailable, *next, err)
		}
		if err := child.CheckSignatureFrom(cert); err != nil {
			return nil, fmt.Errorf("%w: issuer %s did not sign the certificate below it: %w", ErrCertificateChainUnavailable, *next, err)
		}
		self, err := isSelfSignedPEM(hop.Certificate)
		if err != nil {
			return nil, fmt.Errorf("%w: issuer %s: %w", ErrCertificateChainUnavailable, *next, err)
		}
		if self {
			return chain, nil
		}
		chain = append(chain, cert)
		child = cert
		next = hop.CACertID
	}
	return chain, nil
}
