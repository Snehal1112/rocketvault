package api

import (
	"net/http"

	"rocketvault/common"
	"rocketvault/internal/middleware"
	auditSvc "rocketvault/internal/services/audit"
	"rocketvault/internal/signing"
	"rocketvault/model"
)

// InitJWKS registers the JWKS endpoints on the router.
func (a *API) InitJWKS() {
	// GET /jwks.json — public, no auth, uses the JWKS subrouter so CORS is applied.
	a.BaseRoutes.JWKS.Handle("/jwks.json", ApiHandler(a.App, getJWKS)).Methods(http.MethodGet)

	// POST /api/v1/jwks/rotate — admin only, behind the auth middleware.
	a.BaseRoutes.ApiRoot.Handle("/jwks/rotate", ApiSessionRequired(a.App, rotateJWKS)).Methods(http.MethodPost)
}

// getJWKS serves GET /jwks.json — RFC 7517 JWK Set with all active public keys.
func getJWKS(c *Context, w http.ResponseWriter, r *http.Request) {
	provider := c.App.ServiceContainer.GetSigningProvider()
	if provider == nil {
		writeJSONStatus(w, http.StatusServiceUnavailable, map[string]string{"error": "signing provider not available"})
		return
	}

	jwks, err := buildJWKSet(provider.PublicKeys())
	if err != nil {
		writeJSONStatus(w, http.StatusInternalServerError, map[string]string{"error": "failed to build JWK set"})
		return
	}

	w.Header().Set("Cache-Control", "public, max-age=3600")
	writeJSON(w, jwks)
}

// rotateJWKS serves POST /api/v1/jwks/rotate — only available with the self_pki provider.
// Admin-only: rotating the signing key is a sensitive, availability-affecting action.
func rotateJWKS(c *Context, w http.ResponseWriter, r *http.Request) {
	if !common.HasAnyRole(c.Claims.Roles, model.RoleAdmin) {
		c.SetPermissionError("admin role required to rotate signing keys")
		return
	}

	provider := c.App.ServiceContainer.GetSigningProvider()
	if provider == nil {
		c.Err = common.NewAppError("api.jwks.rotate", "api.jwks.provider_unavailable", nil,
			"signing provider not available", http.StatusServiceUnavailable)
		return
	}

	rotatable, ok := provider.(signing.RotatableProvider)
	if !ok {
		c.Err = common.NewAppError("api.jwks.rotate", "api.jwks.rotate_not_supported", nil,
			"key rotation is only supported for the self_pki key source", http.StatusBadRequest)
		return
	}

	newKID, overlapUntil, err := rotatable.Rotate()
	if err != nil {
		recordJWKSRotateAudit(c, r, "", "failure")
		c.logInternalError(err)
		c.Err = common.NewAppError("api.jwks.rotate", "api.jwks.rotate_failed", nil,
			internalErrorDetail, http.StatusInternalServerError)
		return
	}

	recordJWKSRotateAudit(c, r, newKID, "success")

	writeJSON(w, map[string]string{
		"status":        "ok",
		"new_kid":       newKID,
		"overlap_until": overlapUntil,
	})
}

// recordJWKSRotateAudit writes an audit entry for a signing-key rotation attempt.
// Swallows a nil audit service (test doubles, or a container without one wired) —
// audit failures must never block vault operations.
func recordJWKSRotateAudit(c *Context, r *http.Request, newKID, outcome string) {
	svc := c.App.ServiceContainer.GetAuditService()
	if svc == nil {
		return
	}
	_ = svc.RecordEvent(r.Context(), auditSvc.AuditEvent{
		UserID:       c.Claims.UserID,
		Action:       "jwks_rotate",
		Outcome:      outcome,
		Source:       "api",
		ResourceType: "signing_key",
		ResourceID:   newKID,
		IPAddress:    middleware.ExtractClientIP(r),
	})
}

// buildJWKSet converts a slice of PublicKeyInfo into a RFC 7517 JWK Set map.
func buildJWKSet(keys []signing.PublicKeyInfo) (map[string]any, error) {
	jwkList := make([]map[string]any, 0, len(keys))
	for _, info := range keys {
		jwk, err := signing.PublicKeyInfoToJWK(info)
		if err != nil {
			return nil, err
		}
		jwkList = append(jwkList, jwk)
	}
	return map[string]any{"keys": jwkList}, nil
}
