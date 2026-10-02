package api

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/google/uuid"
	"github.com/gorilla/mux"

	"rocketvault/internal/backup"
	"rocketvault/internal/repositories"
)

// InitBackupItem registers per-item backup and restore routes onto the
// legacy flat Secrets, Keys, and Certificates subrouters, and — mirroring
// registerSecretRoutes/registerKeyRoutes/registerCertificateRoutes — onto the
// vault-scoped equivalents, so both URL shapes resolve to the same handlers.
func (api *API) InitBackupItem() {
	api.registerBackupItemRoutes(api.BaseRoutes.Secrets, api.BaseRoutes.Keys, api.BaseRoutes.Certificates)

	if api.BaseRoutes.VaultScoped != nil {
		api.registerBackupItemRoutes(
			api.BaseRoutes.VaultScoped.PathPrefix("/secrets").Subrouter(),
			api.BaseRoutes.VaultScoped.PathPrefix("/keys").Subrouter(),
			api.BaseRoutes.VaultScoped.PathPrefix("/certificates").Subrouter(),
		)
	}
}

// registerBackupItemRoutes registers the backup/restore handlers on the given
// secrets, keys, and certificates subrouters.
func (api *API) registerBackupItemRoutes(s, k, c *mux.Router) {
	// Secret backup / restore.
	s.Handle("/{secret_id:[A-Fa-f0-9-]+}/backup",
		ApiSessionRequired(api.App, backupSecretHandler)).Methods("POST")
	s.Handle("/restore",
		ApiSessionRequired(api.App, restoreSecretHandler)).Methods("POST")

	// Key backup / restore.
	k.Handle("/{key_id:[A-Fa-f0-9-]+}/backup",
		ApiSessionRequired(api.App, backupKeyHandler)).Methods("POST")
	k.Handle("/restore",
		ApiSessionRequired(api.App, restoreKeyHandler)).Methods("POST")

	// Certificate backup / restore.
	c.Handle("/{certificate_id:[A-Fa-f0-9-]+}/backup",
		ApiSessionRequired(api.App, backupCertificateHandler)).Methods("POST")
	c.Handle("/restore",
		ApiSessionRequired(api.App, restoreCertificateHandler)).Methods("POST")
}

// itemBackupSvc is a helper that retrieves the ItemBackupService from the
// container. It sets an internal error on the context when unavailable.
func itemBackupSvc(c *Context) *backup.ItemBackupService {
	if c.App == nil || c.App.ServiceContainer == nil {
		c.SetInternalError(nil)
		return nil
	}
	return c.App.ServiceContainer.GetItemBackupService()
}

// getUserID extracts and parses the caller's user ID from JWT claims.
// It sets an appropriate error on the context when the ID is missing or invalid.
func getUserID(c *Context) (uuid.UUID, bool) {
	userID, err := uuid.Parse(c.Claims.UserID)
	if err != nil {
		c.SetInvalidParam("user_id")
		return uuid.Nil, false
	}
	return userID, true
}

// restoreRequest is the JSON body expected by all restore endpoints.
type restoreRequest struct {
	Blob string `json:"blob"`
}

// backupSecretHandler creates a backup blob for a secret and returns it.
func backupSecretHandler(c *Context, w http.ResponseWriter, r *http.Request) {
	secretID, secretOK := resourceID(c, c.Params.SecretID, "secret_id")
	if !secretOK {
		return
	}

	userID, ok := getUserID(c)
	if !ok {
		return
	}

	vaultID, err := vaultIDFromRequest(r)
	if err != nil {
		c.SetInvalidParam("vault")
		return
	}

	svc := itemBackupSvc(c)
	if svc == nil {
		return
	}

	// A secret outside the authorized vault does not resolve under the
	// scoped read, so it reports as not-found — the same shape every other
	// scoped secret route uses for an out-of-scope ID.
	blob, err := svc.BackupSecret(r.Context(), secretID, userID, vaultID)
	if err != nil {
		// An unconfigured seal key is a server fault, not a missing item.
		if errors.Is(err, backup.ErrSealKeyUnset) {
			c.SetInternalError(err)
			return
		}
		c.SetNotFound("secret")
		return
	}

	writeJSON(w, map[string]string{"blob": blob})
}

// restoreSecretHandler decodes a backup blob and re-inserts the secret.
func restoreSecretHandler(c *Context, w http.ResponseWriter, r *http.Request) {
	var req restoreRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Blob == "" {
		c.SetInvalidParam("blob")
		return
	}

	userID, ok := getUserID(c)
	if !ok {
		return
	}

	vaultID, err := vaultIDFromRequest(r)
	if err != nil {
		c.SetInvalidParam("vault")
		return
	}

	svc := itemBackupSvc(c)
	if svc == nil {
		return
	}

	if err := svc.RestoreSecret(r.Context(), req.Blob, userID, vaultID, uuid.New()); err != nil {
		switch {
		case errors.Is(err, backup.ErrInvalidBlob):
			c.SetInvalidParam("blob")
		case errors.Is(err, repositories.ErrNameTaken):
			c.SetConflict("a resource with this name already exists in this vault")
		default:
			c.SetInternalError(err)
		}
		return
	}

	ReturnStatusOK(w)
}

// backupKeyHandler creates a backup blob for a key and returns it.
func backupKeyHandler(c *Context, w http.ResponseWriter, r *http.Request) {
	keyID, keyOK := resourceID(c, c.Params.KeyID, "key_id")
	if !keyOK {
		return
	}

	userID, ok := getUserID(c)
	if !ok {
		return
	}

	vaultID, err := vaultIDFromRequest(r)
	if err != nil {
		c.SetInvalidParam("vault")
		return
	}

	svc := itemBackupSvc(c)
	if svc == nil {
		return
	}

	// A key outside the authorized vault does not resolve under the scoped
	// read, so it reports as not-found — the same shape every other scoped key
	// route uses for an out-of-scope ID.
	blob, err := svc.BackupKey(r.Context(), keyID, userID, vaultID)
	if err != nil {
		// An unconfigured seal key is a server fault, not a missing item.
		if errors.Is(err, backup.ErrSealKeyUnset) {
			c.SetInternalError(err)
			return
		}
		c.SetNotFound("key")
		return
	}

	writeJSON(w, map[string]string{"blob": blob})
}

// restoreKeyHandler decodes a backup blob and re-inserts the key.
func restoreKeyHandler(c *Context, w http.ResponseWriter, r *http.Request) {
	var req restoreRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Blob == "" {
		c.SetInvalidParam("blob")
		return
	}

	userID, ok := getUserID(c)
	if !ok {
		return
	}

	vaultID, err := vaultIDFromRequest(r)
	if err != nil {
		c.SetInvalidParam("vault")
		return
	}

	svc := itemBackupSvc(c)
	if svc == nil {
		return
	}

	if err := svc.RestoreKey(r.Context(), req.Blob, userID, vaultID, uuid.New()); err != nil {
		switch {
		case errors.Is(err, backup.ErrInvalidBlob):
			c.SetInvalidParam("blob")
		case errors.Is(err, repositories.ErrNameTaken):
			c.SetConflict("a resource with this name already exists in this vault")
		default:
			c.SetInternalError(err)
		}
		return
	}

	ReturnStatusOK(w)
}

// backupCertificateHandler creates a backup blob for a certificate and returns it.
func backupCertificateHandler(c *Context, w http.ResponseWriter, r *http.Request) {
	certID, certOK := resourceID(c, c.Params.CertificateID, "certificate_id")
	if !certOK {
		return
	}

	userID, ok := getUserID(c)
	if !ok {
		return
	}

	vaultID, err := vaultIDFromRequest(r)
	if err != nil {
		c.SetInvalidParam("vault")
		return
	}

	svc := itemBackupSvc(c)
	if svc == nil {
		return
	}

	// A certificate outside the authorized vault does not resolve under the
	// scoped read, so it reports as not-found — the same shape every other
	// scoped certificate route uses for an out-of-scope ID.
	blob, err := svc.BackupCertificate(r.Context(), certID, userID, vaultID)
	if err != nil {
		// An unconfigured seal key is a server fault, not a missing item.
		if errors.Is(err, backup.ErrSealKeyUnset) {
			c.SetInternalError(err)
			return
		}
		c.SetNotFound("certificate")
		return
	}

	writeJSON(w, map[string]string{"blob": blob})
}

// restoreCertificateHandler decodes a backup blob and re-inserts the certificate.
func restoreCertificateHandler(c *Context, w http.ResponseWriter, r *http.Request) {
	var req restoreRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Blob == "" {
		c.SetInvalidParam("blob")
		return
	}

	userID, ok := getUserID(c)
	if !ok {
		return
	}

	vaultID, err := vaultIDFromRequest(r)
	if err != nil {
		c.SetInvalidParam("vault")
		return
	}

	svc := itemBackupSvc(c)
	if svc == nil {
		return
	}

	if err := svc.RestoreCertificate(r.Context(), req.Blob, userID, vaultID, uuid.New()); err != nil {
		switch {
		case errors.Is(err, backup.ErrInvalidBlob):
			c.SetInvalidParam("blob")
		case errors.Is(err, repositories.ErrNameTaken):
			c.SetConflict("a resource with this name already exists in this vault")
		default:
			c.SetInternalError(err)
		}
		return
	}

	ReturnStatusOK(w)
}
