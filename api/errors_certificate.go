package api

import (
	"errors"

	certServices "rocketvault/internal/services/certificates"
	"rocketvault/model"
)

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
	default:
		c.SetInternalError(err)
	}
}

// writeCertificateRenewError maps a renewal error. It differs from
// writeCertificateError in one arm: renewal goes through GetCertificate, so a
// disabled certificate, or one outside its valid time window, is refused with
// ErrCertLifecycleDenied, which the design maps to 409 for this route.
func writeCertificateRenewError(c *Context, err error) {
	if errors.Is(err, certServices.ErrCertLifecycleDenied) {
		c.SetConflict("certificate is disabled or outside its valid time window and cannot be renewed")
		return
	}
	writeCertificateError(c, err)
}
