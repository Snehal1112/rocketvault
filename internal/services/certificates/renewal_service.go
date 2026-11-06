// Package certificates provides certificate management services for the password manager.
// This file implements the certificate renewal service which scans all certificates
// and either auto-renews or emits warnings based on the auto_renew flag.
package certificates

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"

	"rocketvault/internal/logging"
	"rocketvault/internal/repositories"
	"rocketvault/internal/services/authorization"
	"rocketvault/model"
)

// CertificateRenewalService checks all certificates and renews or warns based on auto_renew flag.
type CertificateRenewalService interface {
	CheckAndRenewCertificates(ctx context.Context) (renewed int, warned int, err error)
}

// KeySignAuthorizer returns nil when principalID may sign with keys in
// vaultID, and an error otherwise. A refusal wraps
// authorization.ErrDataPlaneDenied. Any other error is a fault, such as a
// failed lookup, and is never treated as permission to renew.
type KeySignAuthorizer func(ctx context.Context, principalID, vaultID uuid.UUID) error

// NewKeySignAuthorizer returns the KeySignAuthorizer the container wires into
// the scheduler. It runs the same two-stage check the HTTP handlers and the
// CLI run before issuing or renewing: the explicit-deny policy on
// (keys, sign), then a role grant of keys/sign/action in the vault (B77). The
// policy resource type matches the action, so a deny on key sign is
// evaluated. Nil services make every call fail closed with a fault.
func NewKeySignAuthorizer(policies authorization.AccessPolicyService, roles authorization.RoleAssignmentService) KeySignAuthorizer {
	return func(ctx context.Context, principalID, vaultID uuid.UUID) error {
		return authorization.RequireDataPlaneAccess(ctx, policies, roles, principalID, vaultID,
			model.PolicyResourceKeys, model.OpSign, model.ActionKeysSign)
	}
}

// ErrOwnerInactive marks a certificate owner that no longer exists or is a
// disabled or expired service account (B99).
var ErrOwnerInactive = errors.New("certificate owner is inactive")

// OwnerChecker returns nil when ownerID is a principal that may still act. A
// refusal wraps ErrOwnerInactive. Any other error is a fault, such as a failed
// lookup, and is never treated as permission to renew.
type OwnerChecker func(ctx context.Context, ownerID uuid.UUID) error

// OwnerUserReader is the user lookup an OwnerChecker needs.
type OwnerUserReader interface {
	Read(ctx context.Context, id uuid.UUID) (*model.User, error)
}

// OwnerClientReader is the service-account lookup an OwnerChecker needs.
type OwnerClientReader interface {
	GetByID(ctx context.Context, id uuid.UUID) (*model.OAuth2Client, error)
}

// NewOwnerChecker returns the OwnerChecker the container wires into the
// scheduler. An owner is a users row or an oauth2_clients row. A user has no
// disabled or expiry state, so finding one is enough. A service account must
// also be enabled and unexpired, as session validation requires. Nil readers
// make every call fail closed with a fault.
func NewOwnerChecker(users OwnerUserReader, clients OwnerClientReader) OwnerChecker {
	return func(ctx context.Context, ownerID uuid.UUID) error {
		if users == nil || clients == nil {
			return errors.New("owner lookups are not configured")
		}
		_, err := users.Read(ctx, ownerID)
		if err == nil {
			return nil
		}
		if !errors.Is(err, repositories.ErrNotFound) {
			return fmt.Errorf("look up user owner: %w", err)
		}
		client, err := clients.GetByID(ctx, ownerID)
		if errors.Is(err, repositories.ErrNotFound) {
			return fmt.Errorf("%w: no such user or service account", ErrOwnerInactive)
		}
		if err != nil {
			return fmt.Errorf("look up service account owner: %w", err)
		}
		if !client.Enabled {
			return fmt.Errorf("%w: service account disabled", ErrOwnerInactive)
		}
		if client.ExpiresAt != nil && client.ExpiresAt.Before(time.Now()) {
			return fmt.Errorf("%w: service account expired", ErrOwnerInactive)
		}
		return nil
	}
}

// RenewalServiceConfig holds dependencies for the renewal service.
type RenewalServiceConfig struct {
	CertRepository     repositories.CertificateRepositoryInterface
	CertificateService CertificateService
	Logger             *logging.Logger
	// OwnerChecker confirms, before every unattended renewal, that the
	// certificate's owner still exists and may act (B99). Nil refuses every
	// renewal rather than skipping the check.
	OwnerChecker OwnerChecker
	// SignAuthorizer re-checks, before every unattended renewal, that the
	// certificate's owner may still sign with keys in its vault (B77). Nil
	// refuses every renewal rather than skipping the check.
	SignAuthorizer KeySignAuthorizer
}

type certRenewalService struct {
	certRepo   repositories.CertificateRepositoryInterface
	certSvc    CertificateService
	logger     *logging.Logger
	ownerCheck OwnerChecker
	signAuthz  KeySignAuthorizer
}

// NewCertificateRenewalService constructs the renewal service with the given configuration.
func NewCertificateRenewalService(cfg RenewalServiceConfig) CertificateRenewalService {
	return &certRenewalService{
		certRepo:   cfg.CertRepository,
		certSvc:    cfg.CertificateService,
		logger:     cfg.Logger,
		ownerCheck: cfg.OwnerChecker,
		signAuthz:  cfg.SignAuthorizer,
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

			// A role grant says nothing about whether its holder still
			// exists, so this check runs first (B99).
			if !s.ownerIsActive(ctx, &cert) {
				continue
			}

			// Renewal re-signs with the certificate's key on its owner's
			// behalf, so the owner must still hold keys/sign in the vault
			// (B77). The check runs before RenewCertificate, and every
			// outcome other than a grant skips the row.
			if !s.ownerMaySign(ctx, &cert) {
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

// ownerIsActive reports whether cert's owner still exists and may act. It logs
// every refusal and fault, and fails closed: a missing checker and a failed
// lookup both answer false.
func (s *certRenewalService) ownerIsActive(ctx context.Context, cert *model.Certificate) bool {
	if s.ownerCheck == nil {
		s.logger.LogAuditError(cert.UserID.String(), "cert_auto_renew", "failed",
			"Auto-renewal refused, no owner check is configured: "+cert.Name, nil)
		return false
	}
	err := s.ownerCheck(ctx, cert.UserID)
	if err == nil {
		return true
	}
	if errors.Is(err, ErrOwnerInactive) {
		s.logger.LogAuditError(cert.UserID.String(), "cert_auto_renew", "failed",
			"Auto-renewal skipped, owner no longer exists or is inactive: "+cert.Name, err)
		return false
	}
	s.logger.LogAuditError(cert.UserID.String(), "cert_auto_renew", "failed",
		"Auto-renewal skipped, the owner check could not be completed: "+cert.Name, err)
	return false
}

// ownerMaySign reports whether cert's owner may still sign with keys in
// cert's vault. It logs every refusal and fault, and fails closed: a missing
// authorizer and a failed lookup both answer false. Only an error wrapping
// authorization.ErrDataPlaneDenied is logged as a refusal; anything else is a
// fault the operator must look at, so it is logged as one.
func (s *certRenewalService) ownerMaySign(ctx context.Context, cert *model.Certificate) bool {
	if s.signAuthz == nil {
		s.logger.LogAuditError(cert.UserID.String(), "cert_auto_renew", "failed",
			"Auto-renewal refused, no sign authorizer is configured: "+cert.Name, nil)
		return false
	}
	err := s.signAuthz(ctx, cert.UserID, cert.VaultID)
	if err == nil {
		return true
	}
	if errors.Is(err, authorization.ErrDataPlaneDenied) {
		s.logger.LogAuditError(cert.UserID.String(), "cert_auto_renew", "denied",
			"Auto-renewal refused, owner may not sign with keys in this vault: "+cert.Name, err)
		return false
	}
	s.logger.LogAuditError(cert.UserID.String(), "cert_auto_renew", "failed",
		"Auto-renewal skipped, the keys/sign check could not be completed: "+cert.Name, err)
	return false
}

// CurrentValidityDays returns the validity period of cert's current version
// in whole days: expires_at minus created_at. It falls back to 365 when
// either is missing or the difference is not positive, and is clamped to
// model.MaxCertificateValidityDays, so a certificate issued before the cap
// still renews (B78). The auto-renew scheduler and the renew route both use
// it, so a renewal without an explicit validity keeps the period the
// certificate already had.
func CurrentValidityDays(cert *model.Certificate) int {
	if cert == nil || cert.CreatedAt.IsZero() || cert.ExpiresAt == nil {
		return 365
	}
	days := int(cert.ExpiresAt.Sub(cert.CreatedAt).Hours() / 24)
	if days <= 0 {
		return 365
	}
	return min(days, model.MaxCertificateValidityDays)
}
