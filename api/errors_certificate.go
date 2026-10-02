package api

import (
	"errors"

	"rocketvault/internal/repositories"
	certServices "rocketvault/internal/services/certificates"
	"rocketvault/model"
)

// signingKeyUnusableMessage is the fixed text for ErrSigningKeyUnusable on
// both routes. It names no key, so no key ID reaches the response.
const signingKeyUnusableMessage = "the signing key, or its CA's key, is unusable: revoked, disabled, missing or outside its valid time window"

// writeCertificateError maps a certificate-service error onto an HTTP response.
//
// It mirrors writeSecretError and writeKeyError so every certificate handler
// agrees on the mapping. A lifecycle denial is a 403, not a 500:
// updateCertificate reads the certificate back after a successful update, and
// that read-back legitimately hits ErrCertLifecycleDenied when the update
// disabled the certificate or the certificate has expired. That is a state
// condition, not a server fault.
func writeCertificateError(c *Context, err error) {
	switch {
	case errors.Is(err, certServices.ErrCertLifecycleDenied):
		c.SetPermissionError("certificate is disabled or outside its valid time window")
	case errors.Is(err, certServices.ErrCertNotFound):
		c.SetNotFound("certificate")
	case errors.Is(err, model.ErrCertPurgeProtected):
		c.SetPermissionError(purgeProtectedMessage("certificate"))
	case errors.Is(err, model.ErrGlobalPurgeProtectionEnabled):
		c.SetPermissionError(err.Error())
	case errors.Is(err, model.ErrCertificateVersionNotFound):
		c.SetNotFound("certificate version")
	case errors.Is(err, model.ErrInvalidCertificateVersionAttributes):
		c.SetInvalidParam("version attributes: at least one of enabled, expires_at or not_before is required, and not_before must not be after expires_at")
	case errors.Is(err, model.ErrCertificateVersionConflict):
		c.SetConflict("certificate was renewed or updated concurrently; re-read it and retry")
	case errors.Is(err, repositories.ErrNameTaken):
		c.SetConflict("a resource with this name already exists in this vault")
	// B78: refusals about the caller's signing key or CA are client problems.
	// Each uses a fixed message, so no key ID or wrapped repository text
	// reaches the response.
	case errors.Is(err, certServices.ErrSigningKeyForbidden):
		c.SetPermissionError("the signing key belongs to another user")
	case errors.Is(err, certServices.ErrCACertForbidden):
		c.SetPermissionError("the CA certificate belongs to another user")
	case errors.Is(err, certServices.ErrSigningKeyUnusable):
		// The sentinel also comes from the CA's own key (B77), so the text
		// covers both keys and a CA key that is missing.
		c.SetPermissionError(signingKeyUnusableMessage)
	case errors.Is(err, certServices.ErrSigningKeyNotFound):
		c.SetNotFound("key")
	case errors.Is(err, certServices.ErrCACertNotFound):
		c.SetNotFound("CA certificate")
	case errors.Is(err, certServices.ErrInvalidValidityDays):
		c.SetInvalidParam("validity_days")
	default:
		c.SetInternalError(err)
	}
}

// writeCertificateRenewError maps a renewal error. Renewal goes through
// GetCertificate, so a disabled certificate, or one outside its valid time
// window, is refused with ErrCertLifecycleDenied, which the design maps to 409
// for this route. The other arms below are renewal refusals too; anything
// else falls through to writeCertificateError.
func writeCertificateRenewError(c *Context, err error) {
	if errors.Is(err, certServices.ErrCertLifecycleDenied) {
		c.SetConflict("certificate is disabled or outside its valid time window and cannot be renewed")
		return
	}
	if errors.Is(err, certServices.ErrRenewKeyForbidden) {
		c.SetPermissionError("renewing this certificate requires ownership of its signing key")
		return
	}
	if errors.Is(err, certServices.ErrRenewKeyNotFound) {
		c.SetConflict("the certificate's signing key is not available, so it cannot be renewed")
		return
	}
	if errors.Is(err, certServices.ErrRenewNotPossible) {
		c.SetConflict("the certificate cannot be renewed in its current state")
		return
	}
	// A key or signing CA that has become unusable is a state the caller can
	// fix, like the arms above, so renewal reports it as 409 (B77, B78).
	if errors.Is(err, certServices.ErrSigningKeyUnusable) {
		c.SetConflict(signingKeyUnusableMessage)
		return
	}
	if errors.Is(err, certServices.ErrCACertNotFound) {
		c.SetConflict("the certificate's signing CA is not available, so it cannot be renewed")
		return
	}
	writeCertificateError(c, err)
}
