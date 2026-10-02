// Package certcache: integration between the cache layer and the
// certificate service layer. Implements a caching decorator pattern for
// certificate read operations, mirroring internal/cache's
// CachedSecretService.
package certcache

import (
	"context"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"

	"rocketvault/internal/services/certificates"
	"rocketvault/model"
)

// CachedCertificateService wraps a CertificateService with caching
// functionality. It implements the CertificateService interface while
// adding transparent caching for GetCertificate.
type CachedCertificateService struct {
	certificateService certificates.CertificateService
	cache              *Cache
	logger             *logrus.Logger
}

// NewCachedCertificateService creates a new cached certificate service wrapper.
func NewCachedCertificateService(certificateService certificates.CertificateService, cache *Cache, logger *logrus.Logger) *CachedCertificateService {
	return &CachedCertificateService{
		certificateService: certificateService,
		cache:              cache,
		logger:             logger,
	}
}

// GetCertificate retrieves a scoped certificate, using cache when available.
// The entry is keyed by (scope, id), so a value admitted under one scope can
// never satisfy a read under another, and the hit path rechecks
// IsAccessible so a certificate that expired or was disabled while cached
// is not served anyway.
func (s *CachedCertificateService) GetCertificate(ctx context.Context, certID uuid.UUID, scope model.Scope) (*model.Certificate, error) {
	if cached, found := s.cache.Get(ctx, certID, scope); found {
		if cached.IsAccessible() {
			s.logger.WithFields(logrus.Fields{
				"cert_id": certID,
				"scope":   scope.String(),
			}).Debug("Cache hit for certificate")
			return cached, nil
		}
		if err := s.cache.DeleteByID(ctx, certID); err != nil {
			s.logger.WithError(err).Warn("Failed to evict inaccessible cached certificate")
		}
	}

	cert, err := s.certificateService.GetCertificate(ctx, certID, scope)
	if err != nil {
		return nil, err
	}

	if err := s.cache.Set(ctx, cert, scope); err != nil {
		s.logger.WithError(err).Warn("Failed to cache certificate")
	}

	return cert, nil
}

// CreateSelfSignedCertificate creates a new certificate. The reading scope
// is not known at write time, so the cache is left to be populated by the
// first read.
func (s *CachedCertificateService) CreateSelfSignedCertificate(ctx context.Context, req certificates.CreateCertificateRequest) (*certificates.CreateCertificateResult, error) {
	return s.certificateService.CreateSelfSignedCertificate(ctx, req)
}

// CreateCASignedCertificate creates a new CA-signed certificate. The reading
// scope is not known at write time, so the cache is left to be populated by
// the first read.
func (s *CachedCertificateService) CreateCASignedCertificate(ctx context.Context, req certificates.CreateCertificateRequest) (*certificates.CreateCertificateResult, error) {
	return s.certificateService.CreateCASignedCertificate(ctx, req)
}

// ListCertificates lists scoped certificates (not cached).
func (s *CachedCertificateService) ListCertificates(ctx context.Context, scope model.Scope, filter model.CertificateFilter) ([]model.Certificate, error) {
	return s.certificateService.ListCertificates(ctx, scope, filter)
}

// UpdateCertificate updates a scoped certificate and invalidates the cache entry.
func (s *CachedCertificateService) UpdateCertificate(ctx context.Context, req certificates.UpdateCertificateRequest) error {
	if err := s.certificateService.UpdateCertificate(ctx, req); err != nil {
		return err
	}
	if err := s.cache.DeleteByID(ctx, req.CertID); err != nil {
		s.logger.WithError(err).Warn("Failed to invalidate cached certificate")
	}
	return nil
}

// DeleteCertificate soft-deletes a scoped certificate and evicts it from cache.
func (s *CachedCertificateService) DeleteCertificate(ctx context.Context, certID uuid.UUID, scope model.Scope) error {
	if err := s.certificateService.DeleteCertificate(ctx, certID, scope); err != nil {
		return err
	}
	if err := s.cache.DeleteByID(ctx, certID); err != nil {
		s.logger.WithError(err).Warn("Failed to remove deleted certificate from cache")
	}
	return nil
}

// RenewCertificate renews a scoped certificate and evicts it from cache —
// renewal rewrites the certificate/private-key/expiry fields in place under
// the same ID, so a cached pre-renewal copy must not survive.
func (s *CachedCertificateService) RenewCertificate(ctx context.Context, certID uuid.UUID, scope model.Scope, validityDays int) (*certificates.CreateCertificateResult, error) {
	result, err := s.certificateService.RenewCertificate(ctx, certID, scope, validityDays)
	if err != nil {
		return nil, err
	}
	if err := s.cache.DeleteByID(ctx, certID); err != nil {
		s.logger.WithError(err).Warn("Failed to invalidate cached certificate after renewal")
	}
	return result, nil
}

// ListDeletedCertificates lists scoped soft-deleted certificates (not cached).
func (s *CachedCertificateService) ListDeletedCertificates(ctx context.Context, scope model.Scope) ([]model.Certificate, error) {
	return s.certificateService.ListDeletedCertificates(ctx, scope)
}

// RecoverCertificate recovers a scoped soft-deleted certificate and evicts
// it from cache.
func (s *CachedCertificateService) RecoverCertificate(ctx context.Context, certID uuid.UUID, scope model.Scope) error {
	if err := s.certificateService.RecoverCertificate(ctx, certID, scope); err != nil {
		return err
	}
	if err := s.cache.DeleteByID(ctx, certID); err != nil {
		s.logger.WithError(err).Warn("Failed to invalidate cached certificate")
	}
	return nil
}

// PurgeCertificate purges a scoped soft-deleted certificate and evicts it
// from cache.
func (s *CachedCertificateService) PurgeCertificate(ctx context.Context, certID uuid.UUID, scope model.Scope) error {
	if err := s.certificateService.PurgeCertificate(ctx, certID, scope); err != nil {
		return err
	}
	if err := s.cache.DeleteByID(ctx, certID); err != nil {
		s.logger.WithError(err).Warn("Failed to remove purged certificate from cache")
	}
	return nil
}

// ValidateCertificateAccess passes through: an authorization check, not a
// data read, so it neither populates nor needs the cache.
func (s *CachedCertificateService) ValidateCertificateAccess(ctx context.Context, certID uuid.UUID, scope model.Scope) error {
	return s.certificateService.ValidateCertificateAccess(ctx, certID, scope)
}

// ValidateKeyOwnership passes through: it validates a key, not a
// certificate, so the certificate cache is not involved.
func (s *CachedCertificateService) ValidateKeyOwnership(ctx context.Context, keyID uuid.UUID, scope model.Scope) error {
	return s.certificateService.ValidateKeyOwnership(ctx, keyID, scope)
}

// GetCertificatePolicy passes through: policies are a separate object from
// the cached *model.Certificate, not embedded in it.
func (s *CachedCertificateService) GetCertificatePolicy(ctx context.Context, certID uuid.UUID, scope model.Scope) (*model.CertificatePolicy, error) {
	return s.certificateService.GetCertificatePolicy(ctx, certID, scope)
}

// UpsertCertificatePolicy passes through: it mutates a certificate's policy,
// not the certificate record the cache holds.
func (s *CachedCertificateService) UpsertCertificatePolicy(ctx context.Context, certID uuid.UUID, scope model.Scope, req model.UpsertCertificatePolicyRequest) (*model.CertificatePolicy, error) {
	return s.certificateService.UpsertCertificatePolicy(ctx, certID, scope, req)
}

// DeleteCertificatePolicy passes through, for the same reason as UpsertCertificatePolicy.
func (s *CachedCertificateService) DeleteCertificatePolicy(ctx context.Context, certID uuid.UUID, scope model.Scope) error {
	return s.certificateService.DeleteCertificatePolicy(ctx, certID, scope)
}

// ListCertificatePolicies lists scoped certificate policies (not cached).
func (s *CachedCertificateService) ListCertificatePolicies(ctx context.Context, scope model.Scope) ([]model.CertificatePolicyWithCertName, error) {
	return s.certificateService.ListCertificatePolicies(ctx, scope)
}

// ListCertificatesDueForRenewal lists scoped certificates due for renewal (not cached).
func (s *CachedCertificateService) ListCertificatesDueForRenewal(ctx context.Context, scope model.Scope) ([]model.Certificate, error) {
	return s.certificateService.ListCertificatesDueForRenewal(ctx, scope)
}

// GetCacheStats returns cache statistics for monitoring.
func (s *CachedCertificateService) GetCacheStats() map[string]interface{} {
	return s.cache.GetStats()
}

// ClearCache removes every cached certificate.
func (s *CachedCertificateService) ClearCache(ctx context.Context) error {
	return s.cache.Flush(ctx)
}

// ListCertificateVersions lists a certificate's versions (not cached).
func (s *CachedCertificateService) ListCertificateVersions(ctx context.Context, certID uuid.UUID, scope model.Scope) ([]model.CertificateVersion, error) {
	return s.certificateService.ListCertificateVersions(ctx, certID, scope)
}

// GetCertificateVersion reads one version (not cached; archived versions
// never are).
func (s *CachedCertificateService) GetCertificateVersion(ctx context.Context, certID uuid.UUID, version int, scope model.Scope) (*model.CertificateVersion, error) {
	return s.certificateService.GetCertificateVersion(ctx, certID, version, scope)
}

// UpdateCertificateVersion updates one version and evicts the cached
// certificate when the version was the current one, whose attributes live on
// the cached row. Archived versions are not cached, so updating one leaves
// the cache alone.
func (s *CachedCertificateService) UpdateCertificateVersion(ctx context.Context, req certificates.UpdateCertificateVersionRequest) (*model.CertificateVersion, error) {
	updated, err := s.certificateService.UpdateCertificateVersion(ctx, req)
	if err != nil {
		return nil, err
	}
	if updated.Current {
		if err := s.cache.DeleteByID(ctx, req.CertID); err != nil {
			s.logger.WithError(err).Warn("Failed to invalidate cached certificate after version update")
		}
	}
	return updated, nil
}

// ExportCertificate passes straight through. An export is never served from
// or stored in the cache: the result carries a private key, and the export
// must reflect the committed row.
func (s *CachedCertificateService) ExportCertificate(ctx context.Context, scope model.Scope, id uuid.UUID, req certificates.ExportCertificateRequest) (*certificates.ExportCertificateResult, error) {
	return s.certificateService.ExportCertificate(ctx, scope, id, req)
}
