/*
Copyright © 2025 Snehal Dangroshiya

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
*/

package api

import (
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/mux"

	"rocketvault/internal/container"
	keyservices "rocketvault/internal/services/keys"
	vvalidation "rocketvault/internal/validation"
	"rocketvault/model"
)

// keyJWK fetches a key's public components for a response body. version 0
// means the key's current version, which is what the four single-key handlers
// pass; getKeyVersion passes the version actually being addressed.
//
// A failure here is deliberately not fatal to the request: the JWK is
// supplementary to a response whose primary content (identifiers, attributes)
// is already in hand, and a key created moments ago should not 500 because its
// public components could not be derived. The error is logged and the
// components are omitted. HSM-backed keys legitimately return an empty JWK
// with no error at all.
func keyJWK(c *Context, r *http.Request, keySvc keyservices.KeyService, keyID uuid.UUID, scope model.Scope, version int) *model.PublicJWK {
	jwk, err := keySvc.GetPublicJWK(r.Context(), keyID, version, scope)
	if err != nil {
		if c.Logger != nil {
			c.Logger.LogAuditError(c.Claims.UserID, "get_public_jwk", "failed",
				"failed to derive public JWK components", err)
		}
		return nil
	}
	return jwk
}

// buildKeyResponse converts a model.Key to a KeyResponse.
// When the key's value carries a "pkcs11:" prefix the type is suffixed with
// "-HSM" (e.g. "RSA" → "RSA-HSM", "ECDSA" → "EC-HSM") to match Azure Key
// Vault's convention for hardware-backed keys.
//
// jwk carries the public components and may be nil, which leaves n/e/x/y
// omitted -- that is what listKeys passes, since fetching a JWK per row would
// mean an N-way decrypt on a list endpoint. It is a parameter rather than
// something extracted here because the material in key.Value is
// master-key-encrypted: this function used to call
// crypto.ExtractPublicComponents(key.Value, ...) itself and discard the error,
// so every response carried four empty fields (.claude/known-bugs.md § B34).
// Decryption belongs in KeyService.GetPublicJWK.
func buildKeyResponse(key *model.Key, jwk *model.PublicJWK) KeyResponse {
	kty := key.Type
	if strings.HasPrefix(key.Value, "pkcs11:") {
		switch kty {
		case "ECDSA", "ES256K":
			kty = "EC-HSM"
		default:
			kty = kty + "-HSM"
		}
	}
	var n, e, x, y string
	if jwk != nil {
		n, e, x, y = jwk.N, jwk.E, jwk.X, jwk.Y
	}
	return KeyResponse{
		ID:        key.ID,
		Name:      key.Name,
		Type:      kty,
		UserID:    key.UserID,
		Revoked:   key.Revoked,
		CreatedAt: key.CreatedAt,
		UpdatedAt: key.UpdatedAt,
		Tags:      key.Tags,
		Enabled:   key.Enabled,
		ExpiresAt: key.ExpiresAt,
		NotBefore: key.NotBefore,
		Bits:      key.Bits,
		Curve:     key.Curve,

		Exportable:   key.Exportable,
		KeyAlgorithm: key.KeyAlgorithm(),

		N: n,
		E: e,
		X: x,
		Y: y,
	}
}

// InitKeys initializes the routes for cryptographic keys management API.
// It sets up the following endpoints:
// - POST /keys: Create a new cryptographic key.
// - GET /keys: List all keys for authenticated user (with filtering).
// - GET /keys/{key_id}: Get a specific key by ID.
// - PUT /keys/{key_id}: Update a key.
// - DELETE /keys/{key_id}: Delete a key.
// - POST /keys/{key_id}/rotate: Rotate a key (generate new key pair, revoke old).
// - POST /keys/{key_id}/export: Export an exportable software key as PKCS#8 PEM.
func (api *API) InitKeys() {
	api.registerKeyRoutes(api.BaseRoutes.Keys, "legacy")
	if api.BaseRoutes.VaultScoped != nil {
		api.registerKeyRoutes(api.BaseRoutes.VaultScoped.PathPrefix("/keys").Subrouter(), "vault-scoped")
	}
}

// registerKeyRoutes registers the key handlers on the provided subrouter. It is
// called for both the legacy flat routes and the vault-scoped routes; scope
// identifies which one, for the completion log line.
func (api *API) registerKeyRoutes(k *mux.Router, scope string) {
	// Basic CRUD operations.
	k.Handle("", ApiSessionRequired(api.App, createKey)).Methods("POST")
	k.Handle("/import", ApiSessionRequired(api.App, importKey)).Methods("POST")
	k.Handle("", ApiSessionRequired(api.App, listKeys)).Methods("GET")
	k.Handle("/{key_id:[A-Fa-f0-9-]+}", ApiSessionRequired(api.App, getKey)).Methods("GET")
	k.Handle("/{key_id:[A-Fa-f0-9-]+}", ApiSessionRequired(api.App, updateKey)).Methods("PUT")
	k.Handle("/{key_id:[A-Fa-f0-9-]+}", ApiSessionRequired(api.App, deleteKey)).Methods("DELETE")

	// Additional operations.
	k.Handle("/{key_id:[A-Fa-f0-9-]+}/rotate", ApiSessionRequired(api.App, rotateKey)).Methods("POST")
	k.Handle("/{key_id:[A-Fa-f0-9-]+}/versions", ApiSessionRequired(api.App, listKeyVersions)).Methods("GET")
	k.Handle("/{key_id:[A-Fa-f0-9-]+}/versions/{version:[0-9]+}", ApiSessionRequired(api.App, getKeyVersion)).Methods("GET")
	k.Handle("/{key_id:[A-Fa-f0-9-]+}/wrap", ApiSessionRequired(api.App, wrapKey)).Methods("POST")
	k.Handle("/{key_id:[A-Fa-f0-9-]+}/unwrap", ApiSessionRequired(api.App, unwrapKey)).Methods("POST")
	k.Handle("/{key_id:[A-Fa-f0-9-]+}/sign", ApiSessionRequired(api.App, signKey)).Methods("POST")
	k.Handle("/{key_id:[A-Fa-f0-9-]+}/verify", ApiSessionRequired(api.App, verifyKey)).Methods("POST")
	k.Handle("/{key_id:[A-Fa-f0-9-]+}/encrypt", ApiSessionRequired(api.App, encryptKey)).Methods("POST")
	k.Handle("/{key_id:[A-Fa-f0-9-]+}/decrypt", ApiSessionRequired(api.App, decryptKey)).Methods("POST")
	// Per-key export of an exportable software key. Requires ActionKeysExport;
	// see api/keys_export.go.
	k.Handle("/{key_id:[A-Fa-f0-9-]+}/export", ApiSessionRequired(api.App, exportKey)).Methods("POST")

	// Rotation policy sub-resource: GET/PUT/DELETE /keys/{key_id}/rotationpolicy
	k.Handle("/{key_id:[A-Fa-f0-9-]+}/rotationpolicy", ApiSessionRequired(api.App, getKeyRotationPolicy)).Methods("GET")
	k.Handle("/{key_id:[A-Fa-f0-9-]+}/rotationpolicy", ApiSessionRequired(api.App, upsertKeyRotationPolicy)).Methods("PUT")
	k.Handle("/{key_id:[A-Fa-f0-9-]+}/rotationpolicy", ApiSessionRequired(api.App, deleteKeyRotationPolicy)).Methods("DELETE")

	api.Logger.WithField("scope", scope).Infoln("Keys API routes initialized")
}

// createKey creates a new cryptographic key.
func createKey(c *Context, w http.ResponseWriter, r *http.Request) {
	// Authorization happens in PolicyMiddleware: creating a key requires the
	// Microsoft.KeyVault/vaults/keys/create data action, granted by Key Vault
	// Crypto Officer or Key Vault Administrator in this vault. A second gate on
	// the caller's global role would contradict that per-vault decision.

	req, ok := decodeBody[CreateKeyRequest](c, r)
	if !ok {
		return
	}

	// Validate required fields.
	if req.Name == "" || req.Type == "" {
		c.SetInvalidParam("name and type are required")
		return
	}

	// Validate key type.
	req.Type = strings.ToUpper(req.Type)
	if req.Type != "RSA" && req.Type != "ECDSA" && req.Type != "OCT" {
		c.SetInvalidParam("type: must be RSA, ECDSA, or OCT")
		return
	}

	// Validate name format and tag limits.
	if err := vvalidation.ValidateKeyCreate(vvalidation.KeyCreateRequest{
		Name:  req.Name,
		Type:  req.Type,
		Bits:  req.Bits,
		Curve: req.Curve,
		Tags:  req.Tags,
	}); err != nil {
		c.SetInvalidParam(err.Error())
		return
	}

	// Get user ID from claims.
	userID, err := uuid.Parse(c.Claims.UserID)
	if err != nil {
		c.SetInvalidParam("user_id")
		return
	}

	// Resolve the target vault from the request context.
	vaultID, err := vaultIDFromRequest(r)
	if err != nil {
		c.SetInvalidParam("vault")
		return
	}

	keyService, svcOK := svc(c, container.ServiceContainerInterface.GetKeyService)
	if !svcOK {
		return
	}

	// Default Enabled to true when not specified.
	enabled := req.Enabled
	if enabled == nil {
		t := true
		enabled = &t
	}

	// Build create key request.
	createReq := keyservices.CreateKeyRequest{
		Name:            req.Name,
		Type:            req.Type,
		Tags:            req.Tags,
		UserID:          userID,
		VaultID:         vaultID,
		Enabled:         enabled,
		ExpiresAt:       req.ExpiresAt,
		NotBefore:       req.NotBefore,
		PurgeProtection: req.PurgeProtection,
		Exportable:      req.Exportable,
	}

	var result *keyservices.CreateKeyResult
	switch req.Type {
	case "RSA":
		// Validate RSA key size.
		if req.Bits != 2048 && req.Bits != 3072 && req.Bits != 4096 {
			if req.Bits == 0 {
				req.Bits = 2048 // Default RSA key size.
			} else {
				c.SetInvalidParam("bits: must be 2048, 3072, or 4096")
				return
			}
		}
		createReq.Bits = req.Bits
		result, err = keyService.CreateRSAKey(r.Context(), createReq)
	case "OCT":
		if req.Bits != 128 && req.Bits != 192 && req.Bits != 256 {
			c.SetInvalidParam("bits: must be 128, 192, or 256")
			return
		}
		createReq.Bits = req.Bits
		result, err = keyService.CreateOctKey(r.Context(), createReq)
	default:
		// Validate ECDSA curve.
		if req.Curve == "" {
			req.Curve = "P-256" // Default ECDSA curve.
		}
		if req.Curve != "P-256" && req.Curve != "P-384" && req.Curve != "P-521" && req.Curve != "P-256K" {
			c.SetInvalidParam("curve: must be P-256, P-384, P-521, or P-256K")
			return
		}
		createReq.Curve = req.Curve
		result, err = keyService.CreateECDSAKey(r.Context(), createReq)
	}

	if err != nil {
		writeKeyError(c, err)
		return
	}

	// Fetch the full key record so buildKeyResponse can inspect the stored value.
	createScope := model.NewVaultScope(vaultID, userID)
	key, err := keyService.GetKey(r.Context(), result.KeyID, createScope)
	if err != nil {
		c.SetInternalError(err)
		return
	}

	writeJSONStatus(w, http.StatusCreated, buildKeyResponse(key, keyJWK(c, r, keyService, result.KeyID, createScope, 0)))
}

// importKey imports a cryptographic key from caller-supplied JWK material.
func importKey(c *Context, w http.ResponseWriter, r *http.Request) {
	// Authorization happens in PolicyMiddleware: importing a key requires the
	// Microsoft.KeyVault/vaults/keys/import/action data action, granted by
	// Key Vault Crypto Officer or Key Vault Administrator in this vault.

	req, ok := decodeBody[ImportKeyRequest](c, r)
	if !ok {
		return
	}
	if req.Name == "" || len(req.JWK) == 0 {
		c.SetInvalidParam("name and jwk are required")
		return
	}

	// Validate name format/length and tag limits, same as every other
	// key-creation path. ValidateKeyCreate can't be reused here: it requires
	// a Type field (RSA/ECDSA/OCT), and import's type comes from the parsed
	// JWK, not the caller. ValidateKeyUpdate validates exactly Name+Tags with
	// no Type dependency.
	if err := vvalidation.ValidateKeyUpdate(vvalidation.KeyUpdateRequest{
		Name: &req.Name,
		Tags: req.Tags,
	}); err != nil {
		c.SetInvalidParam(err.Error())
		return
	}

	userID, err := uuid.Parse(c.Claims.UserID)
	if err != nil {
		c.SetInvalidParam("user_id")
		return
	}

	vaultID, err := vaultIDFromRequest(r)
	if err != nil {
		c.SetInvalidParam("vault")
		return
	}

	keyService, svcOK := svc(c, container.ServiceContainerInterface.GetKeyService)
	if !svcOK {
		return
	}

	enabled := req.Enabled
	if enabled == nil {
		t := true
		enabled = &t
	}

	result, err := keyService.ImportKey(r.Context(), keyservices.ImportKeyRequest{
		Name:            req.Name,
		JWK:             []byte(req.JWK),
		Tags:            req.Tags,
		UserID:          userID,
		VaultID:         vaultID,
		Enabled:         enabled,
		ExpiresAt:       req.ExpiresAt,
		NotBefore:       req.NotBefore,
		PurgeProtection: req.PurgeProtection,
		Exportable:      req.Exportable,
	})
	if err != nil {
		writeKeyError(c, err)
		return
	}

	createScope := model.NewVaultScope(vaultID, userID)
	key, err := keyService.GetKey(r.Context(), result.KeyID, createScope)
	if err != nil {
		c.SetInternalError(err)
		return
	}

	writeJSONStatus(w, http.StatusCreated, buildKeyResponse(key, keyJWK(c, r, keyService, result.KeyID, createScope, 0)))
}

// listKeys lists cryptographic keys. Legacy flat routes list the default
// vault; explicit vault-scoped routes list the vault named in the path. Both
// use vault-level "members see all" visibility, optionally filtered by type
// and tags.
func listKeys(c *Context, w http.ResponseWriter, r *http.Request) {
	keyService, svcOK := svc(c, container.ServiceContainerInterface.GetKeyService)
	if !svcOK {
		return
	}

	scope, ok := scopeFromRequest(c, r)
	if !ok {
		return
	}

	keysList, err := keyService.ListKeys(r.Context(), scope, model.KeyFilter{
		Type:   r.URL.Query().Get("type"),
		Tags:   c.Params.Tags,
		Limit:  c.Params.PerPage,
		Offset: c.Params.Page * c.Params.PerPage,
	})
	if err != nil {
		c.SetInternalError(err)
		return
	}

	// Convert to response format.
	response := KeyListResponse{Keys: make([]KeyResponse, len(keysList))}
	for i := range keysList {
		response.Keys[i] = buildKeyResponse(&keysList[i], nil)
	}

	writeJSON(w, response)
}

// getKey retrieves a specific cryptographic key by ID.
func getKey(c *Context, w http.ResponseWriter, r *http.Request) {
	keyID, keyOK := resourceID(c, c.Params.KeyID, "key_id")
	if !keyOK {
		return
	}

	keyService, svcOK := svc(c, container.ServiceContainerInterface.GetKeyService)
	if !svcOK {
		return
	}

	scope, ok := scopeFromRequest(c, r)
	if !ok {
		return
	}

	key, err := keyService.GetKey(r.Context(), keyID, scope)
	if err != nil {
		writeKeyError(c, err)
		return
	}

	writeJSON(w, buildKeyResponse(key, keyJWK(c, r, keyService, key.ID, scope, 0)))
}

// updateKey updates a cryptographic key.
func updateKey(c *Context, w http.ResponseWriter, r *http.Request) {
	keyID, keyOK := resourceID(c, c.Params.KeyID, "key_id")
	if !keyOK {
		return
	}

	req, ok := decodeBody[UpdateKeyRequest](c, r)
	if !ok {
		return
	}

	if req.Name == nil && req.Revoked == nil && req.Tags == nil && req.Enabled == nil && req.ExpiresAt == nil && req.NotBefore == nil && req.PurgeProtection == nil {
		c.SetInvalidParam("at least one update field (name, revoked, tags, enabled, expires_at, not_before, purge_protection) must be provided")
		return
	}

	if err := vvalidation.ValidateKeyUpdate(vvalidation.KeyUpdateRequest{
		Name: req.Name,
		Tags: req.Tags,
	}); err != nil {
		c.SetInvalidParam(err.Error())
		return
	}

	keyService, svcOK := svc(c, container.ServiceContainerInterface.GetKeyService)
	if !svcOK {
		return
	}

	scope, ok := scopeFromRequest(c, r)
	if !ok {
		return
	}

	if err := keyService.UpdateKey(r.Context(), keyservices.UpdateKeyRequest{
		KeyID:           keyID,
		Scope:           scope,
		Name:            req.Name,
		Tags:            req.Tags,
		Revoked:         req.Revoked,
		Enabled:         req.Enabled,
		ExpiresAt:       req.ExpiresAt,
		NotBefore:       req.NotBefore,
		PurgeProtection: req.PurgeProtection,
	}); err != nil {
		writeKeyError(c, err)
		return
	}

	// Get updated key for response, using the same scope as the update. The
	// read-back can legitimately be lifecycle-denied — the update may have
	// just disabled the key — so map it like any other lifecycle denial
	// rather than reporting an internal error for a write that succeeded.
	key, err := keyService.GetKey(r.Context(), keyID, scope)
	if err != nil {
		writeKeyError(c, err)
		return
	}

	writeJSON(w, buildKeyResponse(key, keyJWK(c, r, keyService, key.ID, scope, 0)))
}

// deleteKey deletes a cryptographic key.
func deleteKey(c *Context, w http.ResponseWriter, r *http.Request) {
	keyID, keyOK := resourceID(c, c.Params.KeyID, "key_id")
	if !keyOK {
		return
	}

	keyService, svcOK := svc(c, container.ServiceContainerInterface.GetKeyService)
	if !svcOK {
		return
	}

	scope, ok := scopeFromRequest(c, r)
	if !ok {
		return
	}

	deleted, err := keyService.DeleteKey(r.Context(), keyID, scope)
	if err != nil {
		writeKeyError(c, err)
		return
	}

	// Return deletion metadata matching Azure Key Vault's DELETE /keys/{name} response.
	type deleteResponse struct {
		ID               string     `json:"id"`
		Name             string     `json:"name"`
		DeletedAt        *time.Time `json:"deleted_at"`
		ScheduledPurgeAt *time.Time `json:"scheduled_purge_at,omitempty"`
		RecoveryID       string     `json:"recovery_id,omitempty"`
	}

	resp := deleteResponse{
		ID:               deleted.ID.String(),
		Name:             deleted.Name,
		DeletedAt:        deleted.DeletedAt,
		ScheduledPurgeAt: deleted.ScheduledPurgeAt,
		RecoveryID:       "/deleted/keys/" + deleted.ID.String() + "/restore",
	}

	writeJSON(w, resp)
}
