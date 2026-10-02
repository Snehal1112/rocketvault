package retry

import (
	"context"

	"github.com/google/uuid"

	"rocketvault/internal/services/certificates"
	"rocketvault/model"
)

// RetryCertificateService wraps certificate operations with retry logic
type RetryCertificateService interface {
	certificates.CertificateService
}

// retryCertificateService implements RetryCertificateService with retry logic
type retryCertificateService struct {
	baseService  certificates.CertificateService
	retryService RetryService
}

// NewRetryCertificateService creates a new retry-aware certificate service
func NewRetryCertificateService(baseService certificates.CertificateService, retryService RetryService) RetryCertificateService {
	return &retryCertificateService{
		baseService:  baseService,
		retryService: retryService,
	}
}

// CreateSelfSignedCertificate creates a self-signed certificate with retry logic for database operations.
func (s *retryCertificateService) CreateSelfSignedCertificate(ctx context.Context, req certificates.CreateCertificateRequest) (*certificates.CreateCertificateResult, error) {
	return retried(ctx, s.retryService, func() (*certificates.CreateCertificateResult, error) {
		return s.baseService.CreateSelfSignedCertificate(ctx, req)
	})
}

// CreateCASignedCertificate creates a CA-signed certificate with retry logic for database operations.
func (s *retryCertificateService) CreateCASignedCertificate(ctx context.Context, req certificates.CreateCertificateRequest) (*certificates.CreateCertificateResult, error) {
	return retried(ctx, s.retryService, func() (*certificates.CreateCertificateResult, error) {
		return s.baseService.CreateCASignedCertificate(ctx, req)
	})
}

// GetCertificate retrieves a certificate with retry logic for database operations.
func (s *retryCertificateService) GetCertificate(ctx context.Context, certID uuid.UUID, scope model.Scope) (*model.Certificate, error) {
	return retried(ctx, s.retryService, func() (*model.Certificate, error) {
		return s.baseService.GetCertificate(ctx, certID, scope)
	})
}

// ListCertificates lists certificates with retry logic for database operations.
func (s *retryCertificateService) ListCertificates(ctx context.Context, scope model.Scope, filter model.CertificateFilter) ([]model.Certificate, error) {
	return retried(ctx, s.retryService, func() ([]model.Certificate, error) {
		return s.baseService.ListCertificates(ctx, scope, filter)
	})
}

// UpdateCertificate updates a certificate with retry logic for database operations.
func (s *retryCertificateService) UpdateCertificate(ctx context.Context, req certificates.UpdateCertificateRequest) error {
	return s.retryService.ExecuteDatabaseOperation(ctx, func() error {
		return s.baseService.UpdateCertificate(ctx, req)
	})
}

// DeleteCertificate soft-deletes a certificate with retry logic for database operations.
func (s *retryCertificateService) DeleteCertificate(ctx context.Context, certID uuid.UUID, scope model.Scope) error {
	return s.retryService.ExecuteDatabaseOperation(ctx, func() error {
		return s.baseService.DeleteCertificate(ctx, certID, scope)
	})
}

// RenewCertificate renews a certificate with retry logic for database operations.
func (s *retryCertificateService) RenewCertificate(ctx context.Context, certID uuid.UUID, scope model.Scope, validityDays int) (*certificates.CreateCertificateResult, error) {
	return retried(ctx, s.retryService, func() (*certificates.CreateCertificateResult, error) {
		return s.baseService.RenewCertificate(ctx, certID, scope, validityDays)
	})
}

// ListDeletedCertificates lists soft-deleted certificates with retry logic for database operations.
func (s *retryCertificateService) ListDeletedCertificates(ctx context.Context, scope model.Scope) ([]model.Certificate, error) {
	return retried(ctx, s.retryService, func() ([]model.Certificate, error) {
		return s.baseService.ListDeletedCertificates(ctx, scope)
	})
}

// RecoverCertificate restores a soft-deleted certificate with retry logic for database operations.
func (s *retryCertificateService) RecoverCertificate(ctx context.Context, certID uuid.UUID, scope model.Scope) error {
	return s.retryService.ExecuteDatabaseOperation(ctx, func() error {
		return s.baseService.RecoverCertificate(ctx, certID, scope)
	})
}

// PurgeCertificate permanently deletes a soft-deleted certificate with retry logic for database operations.
func (s *retryCertificateService) PurgeCertificate(ctx context.Context, certID uuid.UUID, scope model.Scope) error {
	return s.retryService.ExecuteDatabaseOperation(ctx, func() error {
		return s.baseService.PurgeCertificate(ctx, certID, scope)
	})
}

// ValidateCertificateAccess validates access to a certificate with retry logic for database operations.
func (s *retryCertificateService) ValidateCertificateAccess(ctx context.Context, certID uuid.UUID, scope model.Scope) error {
	return s.retryService.ExecuteDatabaseOperation(ctx, func() error {
		return s.baseService.ValidateCertificateAccess(ctx, certID, scope)
	})
}

// ValidateKeyOwnership validates key ownership with retry logic for database operations.
func (s *retryCertificateService) ValidateKeyOwnership(ctx context.Context, keyID uuid.UUID, scope model.Scope) error {
	return s.retryService.ExecuteDatabaseOperation(ctx, func() error {
		return s.baseService.ValidateKeyOwnership(ctx, keyID, scope)
	})
}

// GetCertificatePolicy retrieves a certificate's policy with retry logic for database operations.
func (s *retryCertificateService) GetCertificatePolicy(ctx context.Context, certID uuid.UUID, scope model.Scope) (*model.CertificatePolicy, error) {
	return retried(ctx, s.retryService, func() (*model.CertificatePolicy, error) {
		return s.baseService.GetCertificatePolicy(ctx, certID, scope)
	})
}

// UpsertCertificatePolicy creates or replaces a certificate's policy with retry logic for database operations.
func (s *retryCertificateService) UpsertCertificatePolicy(ctx context.Context, certID uuid.UUID, scope model.Scope, req model.UpsertCertificatePolicyRequest) (*model.CertificatePolicy, error) {
	return retried(ctx, s.retryService, func() (*model.CertificatePolicy, error) {
		return s.baseService.UpsertCertificatePolicy(ctx, certID, scope, req)
	})
}

// DeleteCertificatePolicy removes a certificate's policy with retry logic for database operations.
func (s *retryCertificateService) DeleteCertificatePolicy(ctx context.Context, certID uuid.UUID, scope model.Scope) error {
	return s.retryService.ExecuteDatabaseOperation(ctx, func() error {
		return s.baseService.DeleteCertificatePolicy(ctx, certID, scope)
	})
}

// ListCertificatePolicies lists a vault's certificate policies with retry logic for database operations.
func (s *retryCertificateService) ListCertificatePolicies(ctx context.Context, scope model.Scope) ([]model.CertificatePolicyWithCertName, error) {
	return retried(ctx, s.retryService, func() ([]model.CertificatePolicyWithCertName, error) {
		return s.baseService.ListCertificatePolicies(ctx, scope)
	})
}

// ListCertificatesDueForRenewal lists certificates due for renewal with retry logic for database operations.
func (s *retryCertificateService) ListCertificatesDueForRenewal(ctx context.Context, scope model.Scope) ([]model.Certificate, error) {
	return retried(ctx, s.retryService, func() ([]model.Certificate, error) {
		return s.baseService.ListCertificatesDueForRenewal(ctx, scope)
	})
}

// ListCertificateVersions lists versions with retry logic for database operations.
func (s *retryCertificateService) ListCertificateVersions(ctx context.Context, certID uuid.UUID, scope model.Scope) ([]model.CertificateVersion, error) {
	return retried(ctx, s.retryService, func() ([]model.CertificateVersion, error) {
		return s.baseService.ListCertificateVersions(ctx, certID, scope)
	})
}

// GetCertificateVersion reads one version with retry logic for database operations.
func (s *retryCertificateService) GetCertificateVersion(ctx context.Context, certID uuid.UUID, version int, scope model.Scope) (*model.CertificateVersion, error) {
	return retried(ctx, s.retryService, func() (*model.CertificateVersion, error) {
		return s.baseService.GetCertificateVersion(ctx, certID, version, scope)
	})
}

// UpdateCertificateVersion updates one version with retry logic for database operations.
func (s *retryCertificateService) UpdateCertificateVersion(ctx context.Context, req certificates.UpdateCertificateVersionRequest) (*model.CertificateVersion, error) {
	return retried(ctx, s.retryService, func() (*model.CertificateVersion, error) {
		return s.baseService.UpdateCertificateVersion(ctx, req)
	})
}

// ExportCertificate is deliberately not retried. A failed export is reported
// once; replaying it would decrypt the key again and write a second audit
// trail for one request.
func (s *retryCertificateService) ExportCertificate(ctx context.Context, scope model.Scope, id uuid.UUID, req certificates.ExportCertificateRequest) (*certificates.ExportCertificateResult, error) {
	return s.baseService.ExportCertificate(ctx, scope, id, req)
}
