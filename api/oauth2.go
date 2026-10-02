package api

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"rocketvault/common"
	"rocketvault/internal/middleware"
	auditSvc "rocketvault/internal/services/audit"
	"rocketvault/model"
)

// InitOAuth2 registers the public OAuth2 token endpoint and authenticated service-account routes.
// The token endpoint is placed outside the authenticated ApiRoot subrouter so it doesn't require
// a pre-existing JWT.
//
// Routes:
//   - POST /oauth2/token                          — Client-credentials grant (RFC 6749 §4.4)
//   - POST   /service-accounts                    — Create a new service account
//   - GET    /service-accounts                    — List all service accounts
//   - GET    /service-accounts/{service_account_id}               — Get a service account by ID
//   - DELETE /service-accounts/{service_account_id}               — Delete a service account
//   - POST   /service-accounts/{service_account_id}/rotate        — Rotate client secret
func (api *API) InitOAuth2() {
	api.BaseRoutes.OAuth2.HandleFunc("/oauth2/token", api.tokenHandler).Methods("POST")
	api.Logger.Infoln("OAuth2 token endpoint initialized")

	sa := api.BaseRoutes.ServiceAccounts
	sa.Handle("", ApiSessionRequired(api.App, createServiceAccount)).Methods("POST")
	sa.Handle("", ApiSessionRequired(api.App, listServiceAccounts)).Methods("GET")
	sa.Handle("/{service_account_id:[A-Fa-f0-9-]+}", ApiSessionRequired(api.App, getServiceAccount)).Methods("GET")
	sa.Handle("/{service_account_id:[A-Fa-f0-9-]+}", ApiSessionRequired(api.App, deleteServiceAccount)).Methods("DELETE")
	sa.Handle("/{service_account_id:[A-Fa-f0-9-]+}/rotate", ApiSessionRequired(api.App, rotateServiceAccountSecret)).Methods("POST")
	api.Logger.Infoln("Service accounts API routes initialized")
}

// ─── Token endpoint (public) ─────────────────────────────────────────────────

// tokenHandler handles POST /oauth2/token.
//
// Accepts client credentials via two methods (RFC 6749 §2.3.1):
//   - HTTP Basic authentication: Authorization: Basic base64(client_id:client_secret)
//   - Request body: client_id and client_secret as form parameters
//
// Body must be application/x-www-form-urlencoded with grant_type=client_credentials.
// Parameters in the URL query string are ignored, so a secret placed there
// never authenticates and fails like a missing secret.
//
// On success returns (RFC 6749 §5.1):
//
//	{ "access_token": "...", "token_type": "Bearer", "expires_in": <seconds> }
func (api *API) tokenHandler(w http.ResponseWriter, r *http.Request) {
	// RFC 6749 §5.1 MUST: prevent caching of token responses.
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")

	// Enforce Content-Type — credentials MUST be in the body, not the query string (RFC 6749 §2.3.1).
	ct := r.Header.Get("Content-Type")
	if !strings.HasPrefix(ct, "application/x-www-form-urlencoded") {
		writeTokenError(w, http.StatusBadRequest, "invalid_request", "Content-Type must be application/x-www-form-urlencoded")
		return
	}

	if err := r.ParseForm(); err != nil {
		writeTokenError(w, http.StatusBadRequest, "invalid_request", "malformed request body")
		return
	}

	// PostFormValue reads the body only. FormValue would also read the query.
	grantType := r.PostFormValue("grant_type")
	if grantType != "client_credentials" {
		writeTokenError(w, http.StatusBadRequest, "unsupported_grant_type", "only client_credentials is supported")
		return
	}

	// Resolve client credentials: HTTP Basic takes priority over form body (RFC 6749 §2.3.1).
	clientID, clientSecret, ok := extractClientCredentials(r)
	if !ok || clientID == "" || clientSecret == "" {
		// RFC 6749 §5.2: respond with 401 + WWW-Authenticate when credentials are missing/malformed.
		w.Header().Set("WWW-Authenticate", `Basic realm="rocketvault"`)
		writeTokenError(w, http.StatusUnauthorized, "invalid_client", "client authentication failed")
		return
	}

	svc := api.App.ServiceContainer.GetOAuth2Service()
	if svc == nil {
		writeTokenError(w, http.StatusInternalServerError, "server_error", "authorization server is temporarily unavailable")
		return
	}

	tokenResp, err := svc.IssueToken(r.Context(), clientID, clientSecret)
	if err != nil {
		api.recordOAuth2TokenAudit(r, clientID, "failure")
		// RFC 6749 §5.2: 401 + WWW-Authenticate for invalid_client.
		w.Header().Set("WWW-Authenticate", `Basic realm="rocketvault"`)
		writeTokenError(w, http.StatusUnauthorized, "invalid_client", "invalid client credentials")
		return
	}

	api.recordOAuth2TokenAudit(r, clientID, "success")

	writeJSONStatus(w, http.StatusOK, tokenResp)
}

// maxAuditClientIDLen bounds the caller-supplied client_id written into an
// audit row. The endpoint is public and unauthenticated, so this stops an
// attacker from growing audit_logs rows without limit.
const maxAuditClientIDLen = 255

// recordOAuth2TokenAudit writes an audit entry for a token-issuance attempt.
// clientID is the caller-supplied identifier — safe to log even on failure
// since the response never reveals whether the ID or the secret was wrong
// (RFC 6749 §5.2 non-enumerating error). Swallows a nil audit service.
//
// Unlike recordServiceAccountAudit below, which keys ResourceID on the
// client's UUID, this uses the client NAME: IssueToken returns only a token
// (never the resolved client record), and on invalid-credentials failure
// there is no resolved client to take a UUID from. The name is the only
// identifier available on both the success and failure paths.
func (api *API) recordOAuth2TokenAudit(r *http.Request, clientID, outcome string) {
	svc := api.App.ServiceContainer.GetAuditService()
	if svc == nil {
		return
	}
	if len(clientID) > maxAuditClientIDLen {
		clientID = clientID[:maxAuditClientIDLen]
	}
	_ = svc.RecordEvent(r.Context(), auditSvc.AuditEvent{
		UserID:       clientID,
		Action:       "oauth2_token_issue",
		Outcome:      outcome,
		Source:       "api",
		ResourceType: "oauth2_client",
		ResourceID:   clientID,
		IPAddress:    middleware.ExtractClientIP(r),
	})
}

// extractClientCredentials resolves client_id and client_secret from the request.
// HTTP Basic (Authorization header) takes priority over the form body per RFC 6749 §2.3.1.
// Only the request body is read, never the URL query string, because RFC 6749
// §2.3.1 forbids credentials in the URI and URLs end up in proxy and access logs.
// The caller must have called ParseForm, which fills PostForm.
func extractClientCredentials(r *http.Request) (clientID, clientSecret string, ok bool) {
	// Try HTTP Basic first.
	if auth := r.Header.Get("Authorization"); strings.HasPrefix(auth, "Basic ") {
		decoded, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(auth, "Basic "))
		if err != nil {
			return "", "", false
		}
		parts := strings.SplitN(string(decoded), ":", 2)
		if len(parts) != 2 {
			return "", "", false
		}
		return parts[0], parts[1], true
	}

	// Fall back to the form body.
	return r.PostFormValue("client_id"), r.PostFormValue("client_secret"), true
}

// writeTokenError writes an RFC 6749 §5.2 compliant JSON error response.
// Cache-control headers must already be set by the caller.
func writeTokenError(w http.ResponseWriter, status int, errCode, description string) {
	writeJSONStatus(w, status, map[string]string{
		"error":             errCode,
		"error_description": description,
	})
}

// recordServiceAccountAudit writes an audit entry for a service-account
// lifecycle action. Swallows a nil audit service.
func recordServiceAccountAudit(c *Context, r *http.Request, action, resourceID, outcome string) {
	svc := c.App.ServiceContainer.GetAuditService()
	if svc == nil {
		return
	}
	_ = svc.RecordEvent(r.Context(), auditSvc.AuditEvent{
		UserID:       c.Claims.UserID,
		Action:       action,
		Outcome:      outcome,
		Source:       "api",
		ResourceType: "oauth2_client",
		ResourceID:   resourceID,
		IPAddress:    middleware.ExtractClientIP(r),
	})
}

// ─── Service-account management handlers (authenticated) ─────────────────────

// createServiceAccount handles POST /service-accounts.
// Admin-only. Body: { "name": "...", "description": "...", "expires_at": "<RFC3339 optional>" }
// Returns the new client object plus the one-time plain-text secret.
func createServiceAccount(c *Context, w http.ResponseWriter, r *http.Request) {
	// Enforce admin-only access to prevent privilege escalation.
	if !common.HasAnyRole(c.Claims.Roles, model.RoleAdmin) {
		c.SetPermissionError("admin role required to create service accounts")
		return
	}

	var req struct {
		Name        string     `json:"name"`
		Description string     `json:"description"`
		ExpiresAt   *time.Time `json:"expires_at"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Name == "" {
		c.SetInvalidParam("name is required")
		return
	}

	svc := c.App.ServiceContainer.GetOAuth2Service()
	client, plainSecret, err := svc.CreateClient(r.Context(), req.Name, req.Description, req.ExpiresAt)
	if err != nil {
		recordServiceAccountAudit(c, r, "service_account_create", "", "failure")
		c.SetInternalError(err)
		return
	}

	recordServiceAccountAudit(c, r, "service_account_create", client.ID.String(), "success")

	writeJSONStatus(w, http.StatusCreated, map[string]any{
		"id":            client.ID.String(),
		"name":          client.Name,
		"description":   client.Description,
		"enabled":       client.Enabled,
		"created_at":    client.CreatedAt,
		"expires_at":    client.ExpiresAt,
		"client_secret": plainSecret, // returned once only
	})
}

// listServiceAccounts handles GET /service-accounts.
func listServiceAccounts(c *Context, w http.ResponseWriter, r *http.Request) {
	// Enforce admin-only access to prevent privilege escalation.
	if !common.HasAnyRole(c.Claims.Roles, model.RoleAdmin) {
		c.SetPermissionError("admin role required to manage service accounts")
		return
	}

	svc := c.App.ServiceContainer.GetOAuth2Service()
	clients, err := svc.ListClients(r.Context())
	if err != nil {
		c.SetInternalError(err)
		return
	}

	writeJSON(w, map[string]any{
		"service_accounts": clients,
		"total":            len(clients),
	})
}

// getServiceAccount handles GET /service-accounts/{service_account_id}.
func getServiceAccount(c *Context, w http.ResponseWriter, r *http.Request) {
	// Enforce admin-only access to prevent privilege escalation.
	if !common.HasAnyRole(c.Claims.Roles, model.RoleAdmin) {
		c.SetPermissionError("admin role required to manage service accounts")
		return
	}

	id, ok := resourceID(c, c.Params.ServiceAccountID, "service_account_id")
	if !ok {
		return
	}

	svc := c.App.ServiceContainer.GetOAuth2Service()
	client, err := svc.GetClient(r.Context(), id)
	if err != nil {
		c.SetNotFound("service account")
		return
	}

	writeJSON(w, client)
}

// deleteServiceAccount handles DELETE /service-accounts/{service_account_id}.
func deleteServiceAccount(c *Context, w http.ResponseWriter, r *http.Request) {
	// Enforce admin-only access to prevent privilege escalation.
	if !common.HasAnyRole(c.Claims.Roles, model.RoleAdmin) {
		c.SetPermissionError("admin role required to manage service accounts")
		return
	}

	id, ok := resourceID(c, c.Params.ServiceAccountID, "service_account_id")
	if !ok {
		return
	}

	svc := c.App.ServiceContainer.GetOAuth2Service()
	if err := svc.DeleteClient(r.Context(), id); err != nil {
		recordServiceAccountAudit(c, r, "service_account_delete", id.String(), "failure")
		c.SetInternalError(err)
		return
	}

	recordServiceAccountAudit(c, r, "service_account_delete", id.String(), "success")

	ReturnStatusOK(w)
}

// rotateServiceAccountSecret handles POST /service-accounts/{service_account_id}/rotate.
// Returns the new plain-text client secret (one-time).
func rotateServiceAccountSecret(c *Context, w http.ResponseWriter, r *http.Request) {
	// Enforce admin-only access to prevent privilege escalation.
	if !common.HasAnyRole(c.Claims.Roles, model.RoleAdmin) {
		c.SetPermissionError("admin role required to manage service accounts")
		return
	}

	id, ok := resourceID(c, c.Params.ServiceAccountID, "service_account_id")
	if !ok {
		return
	}

	svc := c.App.ServiceContainer.GetOAuth2Service()
	newSecret, err := svc.RotateSecret(r.Context(), id)
	if err != nil {
		recordServiceAccountAudit(c, r, "service_account_rotate_secret", id.String(), "failure")
		c.SetInternalError(err)
		return
	}

	recordServiceAccountAudit(c, r, "service_account_rotate_secret", id.String(), "success")

	writeJSON(w, map[string]string{
		"client_secret": newSecret, // returned once only — store securely
	})
}
