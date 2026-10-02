package api

import (
	"errors"

	"rocketvault/common"
	"rocketvault/internal/repositories"
	"rocketvault/internal/services/secrets"
	"rocketvault/model"
)

// writeSecretError maps a secret-service error onto an HTTP response. It
// replaces the identical three-way errors.Is chain that was repeated across
// getSecret, updateSecret, deleteSecret and the three version handlers — and
// with it the inconsistency where listSecretVersionsHandler returned 500 for a
// wrong-vault lookup while its two siblings returned 404.
func writeSecretError(c *Context, err error) {
	switch {
	case errors.Is(err, secrets.ErrSecretLifecycleDenied):
		c.SetPermissionError("secret is disabled or outside its valid time window")
	case errors.Is(err, secrets.ErrSecretNotFound):
		c.SetNotFound("secret")
	case errors.Is(err, model.ErrSecretPurgeProtected):
		c.SetPermissionError(purgeProtectedMessage("secret"))
	case errors.Is(err, model.ErrGlobalPurgeProtectionEnabled):
		c.SetPermissionError(err.Error())
	case errors.Is(err, secrets.ErrExportPassphraseRequired):
		c.SetInvalidParam("passphrase: required to produce an encrypted export (encrypt is true, or a passphrase was supplied)")
	case errors.Is(err, common.ErrPassphraseRequired):
		c.SetInvalidParam("passphrase: required to import an encrypted export")
	case errors.Is(err, common.ErrWrongPassphrase):
		c.SetInvalidParam("passphrase: incorrect, or the uploaded file is not a valid encrypted export")
	case errors.Is(err, repositories.ErrNameTaken):
		c.SetConflict("a resource with this name already exists in this vault")
	case errors.Is(err, secrets.ErrInvalidContentType):
		c.SetInvalidParam("content_type")
	default:
		c.SetInternalError(err)
	}
}
