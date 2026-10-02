package api

import (
	"errors"
	"net/http"

	"github.com/google/uuid"
	"github.com/gorilla/mux"

	authzServices "rocketvault/internal/services/authorization"
	vaultServices "rocketvault/internal/services/vaults"
	"rocketvault/model"
)

// webhookSvc returns the vault webhook service, setting an internal error if
// unavailable. Mirrors vaultSvc in vault.go.
func (c *Context) webhookSvc() vaultServices.VaultWebhookService {
	if c.App == nil || c.App.ServiceContainer == nil {
		c.SetInternalError(nil)
		return nil
	}
	svc := c.App.ServiceContainer.GetVaultWebhookService()
	if svc == nil {
		c.SetInternalError(nil)
		return nil
	}
	return svc
}

// resolveAndAuthorizeVault resolves the {name} path variable to a vault and
// checks CanManageVault against it, writing the 404 or 403 itself and
// returning ok=false when the caller must stop.
//
// The resolve-then-authorize order is load-bearing, not stylistic: the {name}
// vault routes bypass VaultResolutionMiddleware, so PolicyMiddleware only ever
// evaluated the default vault for them (see InitVault's doc comment). Each
// handler restores the per-vault check here.
func resolveAndAuthorizeVault(c *Context, r *http.Request) (*model.Vault, uuid.UUID, bool) {
	name := mux.Vars(r)["name"]

	svc := c.vaultSvc()
	if svc == nil {
		return nil, uuid.Nil, false
	}
	target, err := svc.GetVault(r.Context(), name)
	if err != nil {
		if errors.Is(err, vaultServices.ErrVaultNotFound) {
			c.SetNotFound("vault")
			return nil, uuid.Nil, false
		}
		c.SetInternalError(err)
		return nil, uuid.Nil, false
	}
	roles, userID, ok := callerIdentity(c)
	if !ok {
		c.SetInternalError(nil)
		return nil, uuid.Nil, false
	}
	if !authzServices.CanManageVault(r.Context(), roles, c.App.ServiceContainer.GetAccessPolicyService(), userID, target.ID) {
		c.auditDenied("manage_vault_webhook", "admin or vaults/manage required")
		return nil, uuid.Nil, false
	}
	return target, userID, true
}

// upsertVaultWebhook creates or updates a vault's webhook config.
//
// The response carries the plaintext signing secret only when this call minted
// one -- on create, or on an explicit rotate. That is the entire show-once
// contract: there is no other path, here or in getVaultWebhook, that emits it.
func upsertVaultWebhook(c *Context, w http.ResponseWriter, r *http.Request) {
	target, actor, ok := resolveAndAuthorizeVault(c, r)
	if !ok {
		return
	}
	svc := c.webhookSvc()
	if svc == nil {
		return
	}

	req, err := model.UpsertVaultWebhookRequestFromJson(r.Body)
	if err != nil {
		c.SetInvalidParam("request body")
		return
	}

	cfg, plaintextSecret, err := svc.Upsert(r.Context(), target.ID, vaultServices.UpsertWebhookRequest{
		URL:          req.URL,
		RotateSecret: req.RotateSecret,
		Enabled:      req.Enabled,
	}, actor)
	if err != nil {
		if errors.Is(err, vaultServices.ErrInvalidWebhookURL) {
			c.SetInvalidParam("url: " + err.Error())
			return
		}
		c.SetInternalError(err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if plaintextSecret != "" {
		created := model.VaultWebhookConfigCreatedResponse{
			VaultWebhookConfigResponse: cfg.ToResponse(),
			SigningSecret:              plaintextSecret,
		}
		w.Write([]byte(created.ToJson())) //nolint:errcheck,gosec
		return
	}
	resp := cfg.ToResponse()
	w.Write([]byte(resp.ToJson())) //nolint:errcheck,gosec
}

// getVaultWebhook returns a vault's webhook config. It never emits the signing
// secret in any form -- VaultWebhookConfigResponse has no field for it.
func getVaultWebhook(c *Context, w http.ResponseWriter, r *http.Request) {
	target, _, ok := resolveAndAuthorizeVault(c, r)
	if !ok {
		return
	}
	svc := c.webhookSvc()
	if svc == nil {
		return
	}

	cfg, err := svc.Get(r.Context(), target.ID)
	if err != nil {
		if errors.Is(err, vaultServices.ErrWebhookNotFound) {
			c.SetNotFound("webhook config")
			return
		}
		c.SetInternalError(err)
		return
	}

	resp := cfg.ToResponse()
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(resp.ToJson())) //nolint:errcheck,gosec
}

// deleteVaultWebhook removes a vault's webhook config.
func deleteVaultWebhook(c *Context, w http.ResponseWriter, r *http.Request) {
	target, actor, ok := resolveAndAuthorizeVault(c, r)
	if !ok {
		return
	}
	svc := c.webhookSvc()
	if svc == nil {
		return
	}

	if err := svc.Delete(r.Context(), target.ID, actor); err != nil {
		c.SetInternalError(err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
