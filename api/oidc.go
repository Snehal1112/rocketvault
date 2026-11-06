package api

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/sirupsen/logrus"
	"golang.org/x/oauth2"

	userServices "rocketvault/internal/services/users"
	"rocketvault/model"
)

const (
	oidcStateCookie       = "oidc_state"
	oidcNonceCookie       = "oidc_nonce"
	oidcPKCECookie        = "oidc_pkce"
	oidcCLIRedirectCookie = "oidc_cli_redirect"
	oidcCookieMaxAge      = 5 * time.Minute
)

// logBypassError logs an error for handlers that write plain-text responses
// and so have no Context to carry a request id.
func logBypassError(r *http.Request, scope string, err error) {
	logrus.WithFields(logrus.Fields{
		"scope":  scope,
		"method": r.Method,
		"path":   r.URL.Path,
		"error":  fmt.Sprint(err),
	}).Error("OIDC handler error")
}

// InitOIDC registers the public OIDC login/callback routes, plus the CLI
// exchange endpoint, on the same unauthenticated router that already
// serves POST /oauth2/token.
//
// Routes:
//   - GET  /oidc/login       — redirects to the configured provider's authorization endpoint
//   - GET  /oidc/callback    — completes the authorization code flow and issues a session
//   - POST /oidc/cli/exchange — redeems a one-time code from the CLI loopback flow for a session
func (api *API) InitOIDC() {
	api.cliExchange = newCLIExchangeStore()
	api.BaseRoutes.OAuth2.HandleFunc("/oidc/login", api.oidcLoginHandler).Methods("GET")
	api.BaseRoutes.OAuth2.HandleFunc("/oidc/callback", api.oidcCallbackHandler).Methods("GET")
	api.BaseRoutes.OAuth2.HandleFunc("/oidc/cli/exchange", api.cliExchangeHandler).Methods("POST")
	api.Logger.Infoln("OIDC login/callback/cli-exchange routes initialized")
}

// oidcLoginHandler redirects the caller to the configured OIDC provider's
// authorization endpoint, having first stashed a random state, nonce and
// PKCE verifier (and, for the CLI loopback flow, a validated cli_redirect_uri) in
// short-lived cookies for oidcCallbackHandler to verify.
func (api *API) oidcLoginHandler(w http.ResponseWriter, r *http.Request) {
	svc := api.App.ServiceContainer.GetOIDCService()
	if svc == nil {
		http.Error(w, "OIDC is not configured", http.StatusServiceUnavailable)
		return
	}

	cliRedirectURI, err := validateCLIRedirectURI(r.URL.Query().Get("cli_redirect_uri"))
	if err != nil {
		http.Error(w, "invalid cli_redirect_uri", http.StatusBadRequest)
		return
	}

	state, err := randomOIDCToken()
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	nonce, err := randomOIDCToken()
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	setOIDCCookie(w, oidcStateCookie, state)
	setOIDCCookie(w, oidcNonceCookie, nonce)
	verifier := oauth2.GenerateVerifier()
	setOIDCCookie(w, oidcPKCECookie, verifier)
	if cliRedirectURI != "" {
		setOIDCCookie(w, oidcCLIRedirectCookie, cliRedirectURI)
	}

	http.Redirect(w, r, svc.AuthCodeURL(state, nonce, verifier), http.StatusFound)
}

// oidcCallbackHandler completes the authorization code flow: verifies
// state, exchanges the code, verifies the ID token (including nonce),
// finds or creates the corresponding local user, and issues a session
// exactly as POST /users/login does. If the login was started with a
// cli_redirect_uri, the session is handed off via a one-time exchange
// code instead of being returned directly (see api/oidc_cli.go).
func (api *API) oidcCallbackHandler(w http.ResponseWriter, r *http.Request) {
	svc := api.App.ServiceContainer.GetOIDCService()
	if svc == nil {
		http.Error(w, "OIDC is not configured", http.StatusServiceUnavailable)
		return
	}

	// The cookies are single-use. Expire them up front, before any response
	// write, so every return path below clears them (headers set after a
	// write would be lost).
	clearOIDCCookies(w)

	stateCookie, err := r.Cookie(oidcStateCookie)
	if err != nil {
		http.Error(w, "missing or expired oidc_state cookie", http.StatusBadRequest)
		return
	}
	nonceCookie, err := r.Cookie(oidcNonceCookie)
	if err != nil {
		http.Error(w, "missing or expired oidc_nonce cookie", http.StatusBadRequest)
		return
	}

	pkceCookie, err := r.Cookie(oidcPKCECookie)
	if err != nil {
		http.Error(w, "missing or expired oidc_pkce cookie", http.StatusBadRequest)
		return
	}

	cliRedirectURI := ""
	if cliCookie, err := r.Cookie(oidcCLIRedirectCookie); err == nil {
		validated, err := validateCLIRedirectURI(cliCookie.Value)
		if err != nil {
			http.Error(w, "invalid cli redirect", http.StatusBadRequest)
			return
		}
		cliRedirectURI = validated
	}

	// An empty cookie must never match an empty state parameter.
	if stateCookie.Value == "" || subtle.ConstantTimeCompare([]byte(r.URL.Query().Get("state")), []byte(stateCookie.Value)) != 1 {
		http.Error(w, "state mismatch", http.StatusBadRequest)
		return
	}

	code := r.URL.Query().Get("code")
	if code == "" {
		http.Error(w, "missing code parameter", http.StatusBadRequest)
		return
	}

	identity, err := svc.HandleCallback(r.Context(), code, nonceCookie.Value, pkceCookie.Value)
	if err != nil {
		logBypassError(r, "callback", err)
		http.Error(w, "authentication failed", http.StatusUnauthorized)
		return
	}

	userSvc := api.App.ServiceContainer.GetUserService()
	if userSvc == nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	user, err := userSvc.FindOrCreateExternalUser(r.Context(), userServices.FindOrCreateExternalUserRequest{
		Provider:          model.AuthProviderOIDC,
		Subject:           identity.Subject,
		PreferredUsername: identity.PreferredUsername,
		Email:             identity.Email,
		EmailVerified:     identity.EmailVerified,
		Claims:            identity.Claims,
	})
	if err != nil {
		logBypassError(r, "resolve_user", err)
		// A policy denial is a 403 and never echoes the reason.
		if errors.Is(err, userServices.ErrExternalUserNotAllowed) {
			http.Error(w, "access denied", http.StatusForbidden)
			return
		}
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	authSvc := api.App.ServiceContainer.GetAuthenticationService()
	if authSvc == nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	result, err := authSvc.IssueSessionForUser(r.Context(), user)
	if err != nil {
		logBypassError(r, "issue_session", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	response := model.LoginResponse{
		Token:        result.Token,
		RefreshToken: result.RefreshToken,
		UserID:       result.UserID.String(),
		Username:     result.Username,
		Roles:        result.Roles,
	}

	if cliRedirectURI != "" {
		exchangeCode, err := api.cliExchange.put(response)
		if err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		http.Redirect(w, r, cliRedirectURI+"?code="+exchangeCode, http.StatusFound)
		return
	}

	writeJSON(w, response)
}

// randomOIDCToken returns a 32-byte, hex-encoded random token suitable for
// state/nonce values.
func randomOIDCToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func setOIDCCookie(w http.ResponseWriter, name, value string) {
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    value,
		Path:     "/",
		MaxAge:   int(oidcCookieMaxAge.Seconds()),
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})
}

// clearOIDCCookies expires every single-use cookie the login flow sets.
func clearOIDCCookies(w http.ResponseWriter) {
	for _, name := range []string{oidcStateCookie, oidcNonceCookie, oidcPKCECookie, oidcCLIRedirectCookie} {
		clearOIDCCookie(w, name)
	}
}

func clearOIDCCookie(w http.ResponseWriter, name string) {
	http.SetCookie(w, &http.Cookie{
		Name: name, Value: "", Path: "/", MaxAge: -1, HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode,
	})
}
