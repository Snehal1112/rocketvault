package auth

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

// OIDCIdentity is the verified identity extracted from an OIDC ID token.
type OIDCIdentity struct {
	Subject           string
	Email             string
	PreferredUsername string
	// EmailVerified is taken from the same source as Email (ID token or
	// userinfo), never mixed across sources.
	EmailVerified bool
	// Claims holds the verified ID token's claims, undecoded beyond JSON.
	Claims map[string]any
}

// oidcClaims is the subset of standard OIDC claims OIDCService reads from a
// verified ID token or the userinfo endpoint. Not every provider populates
// every field on every source — e.g. Kopano Konnect omits preferred_username
// entirely and leaves name/email out of the ID token, returning them only
// from userinfo.
type oidcClaims struct {
	Subject           string `json:"sub"`
	Email             string `json:"email"`
	EmailVerified     any    `json:"email_verified"`
	PreferredUsername string `json:"preferred_username"`
	Name              string `json:"name"`
	GivenName         string `json:"given_name"`
	FamilyName        string `json:"family_name"`
}

// displayName returns the best available human-readable name from claims:
// name, then given_name + family_name, then empty.
func (c oidcClaims) displayName() string {
	if c.Name != "" {
		return c.Name
	}
	switch {
	case c.GivenName != "" && c.FamilyName != "":
		return c.GivenName + " " + c.FamilyName
	case c.GivenName != "":
		return c.GivenName
	case c.FamilyName != "":
		return c.FamilyName
	default:
		return ""
	}
}

// parseEmailVerified reports whether v is a true email_verified claim. Some
// providers send it as the string "true" instead of a JSON bool. Anything
// else, including numbers and absent values, is false.
func parseEmailVerified(v any) bool {
	switch t := v.(type) {
	case bool:
		return t
	case string:
		return strings.EqualFold(t, "true")
	default:
		return false
	}
}

// RetryExecutor is the subset of retryServices.RetryService this package
// needs. Defined locally (not imported from internal/services/retry) because
// that package already imports this one for its Auth/User retry decorators —
// importing it back here would create an import cycle. Go's structural
// typing means retryServices.RetryService satisfies this interface without
// either package needing to know about the other; test mocks can implement
// it directly too.
type RetryExecutor interface {
	ExecuteExternalServiceOperation(ctx context.Context, operation func() error) error
	ExecuteInteractiveOperation(ctx context.Context, operation func() error) error
}

// withRetry executes fn directly if executor is nil, otherwise routes it
// through the executor's retry/circuit-breaker policy. A free function
// rather than a method so NewOIDCService can use it before *oidcService
// exists.
func withRetry(ctx context.Context, executor RetryExecutor, fn func() error) error {
	if executor == nil {
		return fn()
	}
	return executor.ExecuteExternalServiceOperation(ctx, fn)
}

// withInteractiveRetry is withRetry's counterpart for calls on a
// synchronous, user-facing request path (see
// RetryExecutor.ExecuteInteractiveOperation) — used by HandleCallback's
// Verify and UserInfo calls, which hold an HTTP response open while they
// run and so cannot use ExecuteExternalServiceOperation's much longer
// worst-case backoff budget.
func withInteractiveRetry(ctx context.Context, executor RetryExecutor, fn func() error) error {
	if executor == nil {
		return fn()
	}
	return executor.ExecuteInteractiveOperation(ctx, fn)
}

// OIDCConfig holds OIDCService's configuration.
type OIDCConfig struct {
	IssuerURL    string
	ClientID     string
	ClientSecret string
	RedirectURL  string
	Scopes       []string
	// CACertPath, if set, is the path to a PEM-encoded CA certificate added
	// to the system trust pool for every outbound HTTPS call this service
	// makes to the issuer (discovery, token exchange, userinfo). Needed when
	// the issuer's TLS certificate is signed by a private CA the OS doesn't
	// already trust. This is the config-driven alternative to setting the
	// SSL_CERT_FILE environment variable process-wide before starting
	// RocketVault — SSL_CERT_FILE is invisible in .rocketvault.yaml and easy
	// to forget on restart, silently leaving OIDC unavailable. Empty (the
	// default) means use the system trust store only, unchanged from before
	// this field existed.
	CACertPath string
	// RetryExecutor, if set, wraps each outbound network call this service
	// makes (issuer discovery, code exchange, ID token verification,
	// userinfo) with retry.external_services' exponential-backoff +
	// circuit-breaker policy. Nil (the default, and the only behavior before
	// this field existed) makes every call attempt exactly once.
	RetryExecutor RetryExecutor
}

// OIDCService builds the OIDC authorization redirect and verifies the
// resulting ID token on callback.
type OIDCService interface {
	// AuthCodeURL builds the provider's authorization endpoint URL for state
	// and nonce, both of which the caller must independently store (e.g. in
	// short-lived cookies) and re-verify in HandleCallback. The PKCE S256
	// challenge is derived from verifier, which the caller also stores.
	AuthCodeURL(state, nonce, verifier string) string
	// HandleCallback exchanges code (proving possession of verifier) for
	// tokens and verifies the returned ID token, including that its nonce
	// claim equals expectedNonce.
	HandleCallback(ctx context.Context, code, expectedNonce, verifier string) (*OIDCIdentity, error)
}

type oidcService struct {
	provider     *oidc.Provider
	verifier     *oidc.IDTokenVerifier
	oauth2Config oauth2.Config
	// httpClient is nil unless OIDCConfig.CACertPath was set. When non-nil,
	// HandleCallback must wrap its context with it too (oidc.ClientContext),
	// so the token-exchange and userinfo calls trust the same CA pool
	// discovery used.
	httpClient *http.Client
	// retryExecutor, if set, wraps outbound network calls with a retry and
	// circuit-breaker policy. See OIDCConfig.RetryExecutor.
	retryExecutor RetryExecutor
}

// NewOIDCService fetches the provider's discovery document (a network round
// trip to issuerURL) and returns a ready-to-use OIDCService, or an error if
// the issuer is unreachable or malformed.
func NewOIDCService(ctx context.Context, cfg OIDCConfig) (OIDCService, error) {
	var httpClient *http.Client
	if cfg.CACertPath != "" {
		client, err := httpClientWithExtraCA(cfg.CACertPath)
		if err != nil {
			return nil, fmt.Errorf("oidc: failed to load oidc.ca_cert_path %q: %w", cfg.CACertPath, err)
		}
		httpClient = client
		ctx = oidc.ClientContext(ctx, httpClient)
	}

	var provider *oidc.Provider
	err := withRetry(ctx, cfg.RetryExecutor, func() error {
		var err error
		provider, err = oidc.NewProvider(ctx, cfg.IssuerURL)
		return err
	})
	if err != nil {
		return nil, fmt.Errorf("oidc: failed to discover issuer %q: %w", cfg.IssuerURL, err)
	}

	return &oidcService{
		provider:      provider,
		verifier:      provider.Verifier(&oidc.Config{ClientID: cfg.ClientID}),
		httpClient:    httpClient,
		retryExecutor: cfg.RetryExecutor,
		oauth2Config: oauth2.Config{
			ClientID:     cfg.ClientID,
			ClientSecret: cfg.ClientSecret,
			RedirectURL:  cfg.RedirectURL,
			Endpoint:     provider.Endpoint(),
			Scopes:       cfg.Scopes,
		},
	}, nil
}

// httpClientWithExtraCA returns an *http.Client whose TLS trust pool is the
// system pool plus the PEM-encoded certificate at path. Falls back to a
// fresh empty pool if the system pool is unavailable (x509.SystemCertPool
// can return an error on some platforms), matching the standard library's
// own documented fallback pattern for this case.
func httpClientWithExtraCA(path string) (*http.Client, error) {
	pemData, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read CA cert file: %w", err)
	}

	pool, err := x509.SystemCertPool()
	if err != nil || pool == nil {
		// SystemCertPool() failing is rare (effectively unreachable on Linux)
		// but would otherwise silently drop all public CA trust with no
		// diagnostic trail. This package has no logger wired in; fall back to
		// stderr rather than adding a new logging dependency for one line.
		if err != nil {
			fmt.Fprintf(os.Stderr, "oidc: system cert pool unavailable, starting from an empty pool: %v\n", err)
		}
		pool = x509.NewCertPool()
	}
	if !pool.AppendCertsFromPEM(pemData) {
		return nil, fmt.Errorf("no valid PEM certificate found in %q", path)
	}

	// Clone DefaultTransport rather than starting from a bare &http.Transport{}
	// literal, so we keep its dial/handshake timeouts, proxy support, and
	// connection pooling — only the TLS trust pool is overridden. A bare
	// literal has TLSHandshakeTimeout: 0 (unbounded), which could hang the
	// server's startup indefinitely against a stalled issuer.
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = &tls.Config{RootCAs: pool}

	return &http.Client{Transport: transport}, nil
}

// AuthCodeURL builds the provider's authorization endpoint URL.
func (s *oidcService) AuthCodeURL(state, nonce, verifier string) string {
	return s.oauth2Config.AuthCodeURL(state, oidc.Nonce(nonce), oauth2.S256ChallengeOption(verifier))
}

// HandleCallback exchanges code for tokens, verifies the ID token's
// signature and claims (including that its nonce matches expectedNonce), and
// returns the caller's identity.
func (s *oidcService) HandleCallback(ctx context.Context, code, expectedNonce, verifier string) (*OIDCIdentity, error) {
	if s.httpClient != nil {
		ctx = oidc.ClientContext(ctx, s.httpClient)
	}

	// Exchange redeems a single-use authorization code — it is not safe to
	// retry. If the response is lost after the IdP has already processed
	// the request (e.g. a timeout), replaying it sends the same code again
	// and the IdP correctly rejects it as invalid_grant, turning what was
	// actually a successful exchange into a failed login. Call it exactly
	// once; on failure the user can simply retry the login from the start,
	// which obtains a fresh code.
	token, err := s.oauth2Config.Exchange(ctx, code, oauth2.VerifierOption(verifier))
	if err != nil {
		return nil, fmt.Errorf("oidc: code exchange failed: %w", err)
	}

	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok || rawIDToken == "" {
		return nil, fmt.Errorf("oidc: token response did not include an id_token")
	}

	var idToken *oidc.IDToken
	err = withInteractiveRetry(ctx, s.retryExecutor, func() error {
		var err error
		idToken, err = s.verifier.Verify(ctx, rawIDToken)
		return err
	})
	if err != nil {
		return nil, fmt.Errorf("oidc: id_token verification failed: %w", err)
	}

	if idToken.Nonce != expectedNonce {
		return nil, fmt.Errorf("oidc: nonce mismatch")
	}

	var claims oidcClaims
	if err := idToken.Claims(&claims); err != nil {
		return nil, fmt.Errorf("oidc: failed to parse id_token claims: %w", err)
	}
	if claims.Subject == "" {
		return nil, fmt.Errorf("oidc: id_token missing sub claim")
	}

	preferredUsername := claims.PreferredUsername
	if preferredUsername == "" {
		preferredUsername = claims.displayName()
	}
	email := claims.Email
	emailVerified := parseEmailVerified(claims.EmailVerified)

	var rawClaims map[string]any
	if err := idToken.Claims(&rawClaims); err != nil {
		return nil, fmt.Errorf("oidc: failed to parse id_token claims: %w", err)
	}

	// Some providers (e.g. Kopano/Konnect) leave name/email out of the ID
	// token and only return them from userinfo. Best-effort: a failure here
	// must not fail the login, since FindOrCreateExternalUser already falls
	// back to the subject when PreferredUsername is empty.
	var userInfo *oidc.UserInfo
	if uiErr := withInteractiveRetry(ctx, s.retryExecutor, func() error {
		var err error
		userInfo, err = s.provider.UserInfo(ctx, oauth2.StaticTokenSource(token))
		return err
	}); uiErr == nil {
		var uiClaims oidcClaims
		if err := userInfo.Claims(&uiClaims); err == nil {
			if preferredUsername == "" {
				preferredUsername = uiClaims.PreferredUsername
			}
			if preferredUsername == "" {
				preferredUsername = uiClaims.displayName()
			}
			if email == "" {
				email = uiClaims.Email
				emailVerified = parseEmailVerified(uiClaims.EmailVerified)
			}
		}
	}

	return &OIDCIdentity{
		Subject:           claims.Subject,
		Email:             email,
		EmailVerified:     emailVerified,
		PreferredUsername: preferredUsername,
		Claims:            rawClaims,
	}, nil
}
