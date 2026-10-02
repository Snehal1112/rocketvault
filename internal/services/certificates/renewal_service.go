// Package certificates provides certificate management services for the password manager.
// This file implements the certificate renewal service which scans all certificates
// and either auto-renews or emits warnings based on the auto_renew flag.
package certificates

import (
	"context"
	"time"

	"github.com/google/uuid"

	"rocketvault/internal/logging"
	"rocketvault/internal/repositories"
	"rocketvault/model"
)

// CertificateRenewalService checks all certificates and renews or warns based on auto_renew flag.
type CertificateRenewalService interface {
	CheckAndRenewCertificates(ctx context.Context) (renewed int, warned int, err error)
}

// RenewalServiceConfig holds dependencies for the renewal service.
type RenewalServiceConfig struct {
	CertRepository     repositories.CertificateRepositoryInterface
	CertificateService CertificateService
	Logger             *logging.Logger
}

type certRenewalService struct {
	certRepo repositories.CertificateRepositoryInterface
	certSvc  CertificateService
	logger   *logging.Logger
}

// NewCertificateRenewalService constructs the renewal service with the given configuration.
func NewCertificateRenewalService(cfg RenewalServiceConfig) CertificateRenewalService {
	return &certRenewalService{
		certRepo: cfg.CertRepository,
		certSvc:  cfg.CertificateService,
		logger:   cfg.Logger,
	}
}

// CheckAndRenewCertificates scans all certificates and either auto-renews or warns for each
// certificate that is within its renewal window but has not yet expired.
func (s *certRenewalService) CheckAndRenewCertificates(ctx context.Context) (int, int, error) {
	certs, err := s.certRepo.ListAll(ctx)
	if err != nil {
		return 0, 0, err
	}

	var renewed, warned int
	now := time.Now()

	for _, cert := range certs {
		if cert.ExpiresAt == nil {
			continue
		}

		// Skip certificates that are already expired.
		if cert.ExpiresAt.Before(now) {
			s.logger.LogAuditInfo(cert.UserID.String(), "cert_expiry_warning", "warning",
				"Certificate already expired: "+cert.Name)
			continue
		}

		daysUntilExpiry := int(cert.ExpiresAt.Sub(now).Hours() / 24)
		renewalDays := cert.RenewalDays
		if renewalDays <= 0 {
			renewalDays = 30
		}

		// Certificate is not yet within the renewal window.
		if daysUntilExpiry > renewalDays {
			continue
		}

		if cert.AutoRenew {
			// A row with no vault cannot be scoped to one, so it is never
			// renewed. Renewing under an admin scope is what let a restored
			// row reach keys and CA certificates in other vaults (B76).
			if cert.VaultID == uuid.Nil {
				s.logger.LogAuditError(cert.UserID.String(), "cert_auto_renew", "failed",
					"Auto-renewal skipped, certificate has no vault: "+cert.Name, nil)
				continue
			}

			// Preserve the current version's validity period when renewing.
			validityDays := CurrentValidityDays(&cert)

			// The renewal is scoped to the certificate's own vault, so its key
			// and CA links are only followed inside that vault, and
			// ArchiveAndRenew only updates a row in that vault (B76).
			_, err := s.certSvc.RenewCertificate(ctx, cert.ID, model.NewVaultScope(cert.VaultID, cert.UserID), validityDays)
			if err != nil {
				s.logger.LogAuditError(cert.UserID.String(), "cert_auto_renew", "failed",
					"Auto-renewal failed for: "+cert.Name, err)
				continue
			}
			s.logger.LogAuditInfo(cert.UserID.String(), "cert_auto_renew", "success",
				"Auto-renewed certificate: "+cert.Name)
			renewed++
		} else {
			s.logger.LogAuditInfo(cert.UserID.String(), "cert_expiry_warning", "warning",
				"Certificate expiring soon (auto_renew disabled): "+cert.Name)
			warned++
		}
	}

	return renewed, warned, nil
}

// CurrentValidityDays returns the validity period of cert's current version
// in whole days: expires_at minus created_at. It falls back to 365 when
// either is missing or the difference is not positive. The auto-renew
// scheduler and the renew route both use it, so a renewal without an
// explicit validity keeps the period the certificate already had.
func CurrentValidityDays(cert *model.Certificate) int {
	if cert == nil || cert.CreatedAt.IsZero() || cert.ExpiresAt == nil {
		return 365
	}
	days := int(cert.ExpiresAt.Sub(cert.CreatedAt).Hours() / 24)
	if days <= 0 {
		return 365
	}
	return days
}
