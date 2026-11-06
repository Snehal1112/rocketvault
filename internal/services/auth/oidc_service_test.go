package auth

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"
)

// countingRetryExecutor is a minimal RetryExecutor fake for testing that
// oidc_service.go actually routes calls through an injected executor,
// without depending on internal/services/retry (which would create an
// import cycle from this in-package test file). It calls operation up to
// maxAttempts times, returning as soon as one succeeds, with no real delay —
// the retry ALGORITHM's correctness (backoff timing, circuit breaker) is
// already covered by internal/services/retry's own tests; this only proves
// oidc_service.go threads calls through whatever executor it's given.
type countingRetryExecutor struct {
	maxAttempts      int
	calls            int
	interactiveCalls int
}

func (e *countingRetryExecutor) ExecuteExternalServiceOperation(ctx context.Context, operation func() error) error {
	var lastErr error
	for i := 0; i < e.maxAttempts; i++ {
		e.calls++
		lastErr = operation()
		if lastErr == nil {
			return nil
		}
	}
	return lastErr
}

func (e *countingRetryExecutor) ExecuteInteractiveOperation(ctx context.Context, operation func() error) error {
	var lastErr error
	for i := 0; i < e.maxAttempts; i++ {
		e.interactiveCalls++
		lastErr = operation()
		if lastErr == nil {
			return nil
		}
	}
	return lastErr
}

// callbackFakeIdP is a fake IdP for HandleCallback tests, exposing discovery,
// jwks, token, and userinfo endpoints with per-endpoint call counters and
// configurable flakiness, so tests can prove exactly which stage of
// HandleCallback (Exchange, Verify, UserInfo) retried and which didn't.
type callbackFakeIdP struct {
	srv    *httptest.Server
	key    *rsa.PrivateKey
	issuer string

	tokenCalls    int32
	jwksCalls     int32
	userInfoCalls int32

	// jwksFailUntil: jwks requests numbered <= this value return 500.
	jwksFailUntil int32
	// tokenFailUntil: token requests numbered <= this value return 500.
	tokenFailUntil int32
	// userInfoAlwaysFail: if true, the userinfo endpoint always returns 500.
	userInfoAlwaysFail bool

	// idToken is embedded verbatim in the token endpoint's response. Must be
	// set (via signIDToken) before HandleCallback is invoked; it is read at
	// request time, not at server-start time, so setting it after
	// newCallbackFakeIdP returns but before calling HandleCallback is safe.
	idToken string

	// userInfoBody, if set, replaces the default userinfo response.
	userInfoBody map[string]any

	formMu        sync.Mutex
	lastTokenForm url.Values
}

// tokenForm returns the form values of the last token endpoint request.
func (f *callbackFakeIdP) tokenForm() url.Values {
	f.formMu.Lock()
	defer f.formMu.Unlock()
	return f.lastTokenForm
}

// newCallbackFakeIdP starts the fake IdP's HTTP server. Callers must set
// idToken (via signIDToken) before exercising HandleCallback.
func newCallbackFakeIdP(t *testing.T) *callbackFakeIdP {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	f := &callbackFakeIdP{key: key}

	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer":                                f.issuer,
			"authorization_endpoint":                f.issuer + "/authorize",
			"token_endpoint":                        f.issuer + "/token",
			"jwks_uri":                              f.issuer + "/jwks",
			"userinfo_endpoint":                     f.issuer + "/userinfo",
			"id_token_signing_alg_values_supported": []string{"RS256"},
		})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		n := atomic.AddInt32(&f.jwksCalls, 1)
		if n <= atomic.LoadInt32(&f.jwksFailUntil) {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"keys": []map[string]any{{
				"kty": "RSA", "kid": "test-key", "use": "sig", "alg": "RS256",
				"n": jwtBase64URLEncode(key.N.Bytes()),
				"e": jwtBase64URLEncode([]byte{1, 0, 1}),
			}},
		})
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		n := atomic.AddInt32(&f.tokenCalls, 1)
		_ = r.ParseForm()
		f.formMu.Lock()
		f.lastTokenForm = r.PostForm
		f.formMu.Unlock()
		if n <= atomic.LoadInt32(&f.tokenFailUntil) {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": "test-access-token",
			"token_type":   "Bearer",
			"expires_in":   3600,
			"id_token":     f.idToken,
		})
	})
	mux.HandleFunc("/userinfo", func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&f.userInfoCalls, 1)
		if f.userInfoAlwaysFail {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		body := map[string]any{
			"sub":   "user-123",
			"email": "userinfo@example.com",
		}
		if f.userInfoBody != nil {
			body = f.userInfoBody
		}
		_ = json.NewEncoder(w).Encode(body)
	})

	f.srv = httptest.NewServer(mux)
	t.Cleanup(f.srv.Close)
	f.issuer = f.srv.URL
	return f
}

// signIDToken produces a compact-serialized JWT signed with f's RSA key and
// "kid": "test-key", matching the key served from /jwks, so
// OIDCService.HandleCallback's verifier accepts it.
func (f *callbackFakeIdP) signIDToken(t *testing.T, clientID, subject, nonce string) string {
	t.Helper()
	return f.signIDTokenWith(t, clientID, subject, nonce, nil)
}

// signIDTokenWith is signIDToken with extra claims merged into the payload.
func (f *callbackFakeIdP) signIDTokenWith(t *testing.T, clientID, subject, nonce string, extra map[string]any) string {
	t.Helper()
	claims := map[string]any{
		"iss":   f.issuer,
		"aud":   clientID,
		"sub":   subject,
		"nonce": nonce,
		"exp":   time.Now().Add(time.Hour).Unix(),
		"iat":   time.Now().Unix(),
	}
	for k, v := range extra {
		claims[k] = v
	}
	payload, err := json.Marshal(claims)
	require.NoError(t, err)

	signerOpts := (&jose.SignerOptions{}).WithType("JWT").WithHeader(jose.HeaderKey("kid"), "test-key")
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: f.key}, signerOpts)
	require.NoError(t, err)

	jws, err := signer.Sign(payload)
	require.NoError(t, err)

	compact, err := jws.CompactSerialize()
	require.NoError(t, err)
	return compact
}

// newTestOIDCProvider starts an httptest server serving a minimal OIDC
// discovery document and JWKS so OIDCService can be constructed against it
// without any real network access.
func newTestOIDCProvider(t *testing.T) (*httptest.Server, *rsa.PrivateKey) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	mux := http.NewServeMux()
	var issuer string
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer":                                issuer,
			"authorization_endpoint":                issuer + "/authorize",
			"token_endpoint":                        issuer + "/token",
			"jwks_uri":                              issuer + "/jwks",
			"id_token_signing_alg_values_supported": []string{"RS256"},
		})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"keys": []map[string]any{{
				"kty": "RSA", "kid": "test-key", "use": "sig", "alg": "RS256",
				"n": jwtBase64URLEncode(key.N.Bytes()),
				"e": jwtBase64URLEncode([]byte{1, 0, 1}),
			}},
		})
	})
	srv := httptest.NewServer(mux)
	issuer = srv.URL
	t.Cleanup(srv.Close)
	return srv, key
}

func jwtBase64URLEncode(b []byte) string {
	return base64.RawURLEncoding.EncodeToString(b)
}

// caCertPathFromServer writes srv's own leaf certificate to a temp PEM file
// and returns the path. httptest.NewTLSServer's certificate is self-signed,
// so it is its own trust anchor for these tests — exactly analogous to a
// private CA's root certificate in production.
func caCertPathFromServer(t *testing.T, srv *httptest.Server) string {
	t.Helper()
	block := &pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}
	path := filepath.Join(t.TempDir(), "test-ca.pem")
	require.NoError(t, os.WriteFile(path, pem.EncodeToMemory(block), 0o600))
	return path
}

// newTestOIDCTLSProvider is newTestOIDCProvider's TLS counterpart, needed to
// test CA trust — a plain-HTTP test server can't exercise TLS verification
// at all. Duplicated rather than parameterizing newTestOIDCProvider because
// httptest.NewServer and httptest.NewTLSServer return incompatible startup
// sequences (TLS needs the server started before its URL is known, to read
// back its own certificate).
func newTestOIDCTLSProvider(t *testing.T) (*httptest.Server, *rsa.PrivateKey) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	mux := http.NewServeMux()
	var issuer string
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer":                                issuer,
			"authorization_endpoint":                issuer + "/authorize",
			"token_endpoint":                        issuer + "/token",
			"jwks_uri":                              issuer + "/jwks",
			"id_token_signing_alg_values_supported": []string{"RS256"},
		})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"keys": []map[string]any{{
				"kty": "RSA", "kid": "test-key", "use": "sig", "alg": "RS256",
				"n": jwtBase64URLEncode(key.N.Bytes()),
				"e": jwtBase64URLEncode([]byte{1, 0, 1}),
			}},
		})
	})
	srv := httptest.NewTLSServer(mux)
	issuer = srv.URL
	t.Cleanup(srv.Close)
	return srv, key
}

func TestOIDCService_AuthCodeURL_IncludesStateAndNonce(t *testing.T) {
	srv, _ := newTestOIDCProvider(t)

	svc, err := NewOIDCService(context.Background(), OIDCConfig{
		IssuerURL: srv.URL, ClientID: "client-1", ClientSecret: "secret",
		RedirectURL: "http://localhost/callback", Scopes: []string{"openid"},
	})
	require.NoError(t, err)

	url := svc.AuthCodeURL("state-123", "nonce-456", "verifier-789")
	require.Contains(t, url, "state=state-123")
	require.Contains(t, url, "nonce=nonce-456")
	require.Contains(t, url, "client_id=client-1")
}

func TestNewOIDCService_UnreachableIssuer_ReturnsError(t *testing.T) {
	_, err := NewOIDCService(context.Background(), OIDCConfig{
		IssuerURL: "http://127.0.0.1:1", ClientID: "x", ClientSecret: "y",
		RedirectURL: "http://localhost/callback", Scopes: []string{"openid"},
	})
	require.Error(t, err)
}

func TestNewOIDCService_CustomCACert_TrustsSelfSignedIssuer(t *testing.T) {
	srv, _ := newTestOIDCTLSProvider(t)
	caPath := caCertPathFromServer(t, srv)

	_, err := NewOIDCService(context.Background(), OIDCConfig{
		IssuerURL: srv.URL, ClientID: "client-1", ClientSecret: "secret",
		RedirectURL: "http://localhost/callback", Scopes: []string{"openid"},
		CACertPath: caPath,
	})
	require.NoError(t, err)
}

func TestNewOIDCService_WithoutCACertPath_RejectsUntrustedTLSIssuer(t *testing.T) {
	srv, _ := newTestOIDCTLSProvider(t)

	_, err := NewOIDCService(context.Background(), OIDCConfig{
		IssuerURL: srv.URL, ClientID: "client-1", ClientSecret: "secret",
		RedirectURL: "http://localhost/callback", Scopes: []string{"openid"},
		// CACertPath deliberately empty.
	})
	require.Error(t, err, "a self-signed issuer must be rejected without an explicit CACertPath")
}

func TestNewOIDCService_InvalidCACertPath_ReturnsClearError(t *testing.T) {
	srv, _ := newTestOIDCProvider(t) // plain HTTP is fine here; discovery never happens

	_, err := NewOIDCService(context.Background(), OIDCConfig{
		IssuerURL: srv.URL, ClientID: "client-1", ClientSecret: "secret",
		RedirectURL: "http://localhost/callback", Scopes: []string{"openid"},
		CACertPath: "/nonexistent/path/does-not-exist.pem",
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "ca_cert_path")
}

func TestNewOIDCService_NilRetryExecutor_AttemptsOnce(t *testing.T) {
	srv, _ := newTestOIDCProvider(t)

	svc, err := NewOIDCService(context.Background(), OIDCConfig{
		IssuerURL: srv.URL, ClientID: "client-1", ClientSecret: "secret",
		RedirectURL: "http://localhost/callback", Scopes: []string{"openid"},
		// RetryExecutor deliberately omitted (nil) — must behave exactly as
		// it did before this field existed: a single discovery attempt.
	})
	require.NoError(t, err)
	require.NotNil(t, svc)
}

func TestNewOIDCService_RetriesDiscoveryOnFailure(t *testing.T) {
	var discoveryCalls int32
	var issuer string
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		n := atomic.AddInt32(&discoveryCalls, 1)
		if n < 3 {
			// Simulate a transient failure on the first two attempts.
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer":                                issuer,
			"authorization_endpoint":                issuer + "/authorize",
			"token_endpoint":                        issuer + "/token",
			"jwks_uri":                              issuer + "/jwks",
			"id_token_signing_alg_values_supported": []string{"RS256"},
		})
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	issuer = srv.URL

	executor := &countingRetryExecutor{maxAttempts: 5}
	svc, err := NewOIDCService(context.Background(), OIDCConfig{
		IssuerURL: srv.URL, ClientID: "client-1", ClientSecret: "secret",
		RedirectURL: "http://localhost/callback", Scopes: []string{"openid"},
		RetryExecutor: executor,
	})
	require.NoError(t, err, "discovery should eventually succeed once the executor retries past the transient failures")
	require.NotNil(t, svc)
	require.Equal(t, 3, executor.calls, "executor should have attempted discovery exactly 3 times (2 failures + 1 success)")
	require.Equal(t, int32(3), atomic.LoadInt32(&discoveryCalls))
}

func TestHandleCallback_RetriesExchangeAndVerifyIndependently(t *testing.T) {
	f := newCallbackFakeIdP(t)
	f.idToken = f.signIDToken(t, "client-1", "user-123", "nonce-abc")

	executor := &countingRetryExecutor{maxAttempts: 3}
	svc, err := NewOIDCService(context.Background(), OIDCConfig{
		IssuerURL: f.issuer, ClientID: "client-1", ClientSecret: "secret",
		RedirectURL: "http://localhost/callback", Scopes: []string{"openid"},
		RetryExecutor: executor,
	})
	require.NoError(t, err)

	// jwks (needed by Verify) fails once, then succeeds — this must force a
	// retry of Verify alone, never a second Exchange (the authorization code
	// is single-use; replaying Exchange with an already-consumed code would
	// be a real bug).
	atomic.StoreInt32(&f.jwksFailUntil, 1)

	identity, err := svc.HandleCallback(context.Background(), "auth-code-xyz", "nonce-abc", "verifier-1")
	require.NoError(t, err)
	require.Equal(t, "user-123", identity.Subject)

	require.Equal(t, int32(1), atomic.LoadInt32(&f.tokenCalls),
		"Exchange must be attempted exactly once even though Verify needed a retry")
	require.GreaterOrEqual(t, atomic.LoadInt32(&f.jwksCalls), int32(2),
		"Verify should have retried its jwks fetch after the first failure")
}

func TestHandleCallback_ExchangeIsNeverRetried(t *testing.T) {
	f := newCallbackFakeIdP(t)
	f.idToken = f.signIDToken(t, "client-1", "user-123", "nonce-abc")
	// tokenFailUntil is 2, not 1, because golang.org/x/oauth2's Exchange has
	// its own internal behavior independent of our retry wrapper: on its
	// first-ever call for a given oauth2.Config (AuthStyle unset, i.e.
	// AuthStyleAutoDetect), a request error makes it transparently retry
	// once more with the other client-auth style before giving up
	// (golang.org/x/oauth2/internal.RetrieveToken's auth-style probing).
	// That means a single injected /token failure (tokenFailUntil=1) gets
	// silently absorbed by the library itself and Exchange still succeeds —
	// true regardless of whether our own retry wrapper is present, so it
	// can't distinguish the fix from the bug (verified empirically: both
	// the buggy and fixed code produce tokenCalls=2, err=nil for
	// tokenFailUntil=1).
	//
	// Setting tokenFailUntil=2 fails both of the library's internal
	// auth-style attempts, so a single logical call to
	// s.oauth2Config.Exchange exhausts them (2 HTTP requests) and returns
	// an error. If our retry wrapper were still present, it would call
	// Exchange again — and that second logical call's first HTTP request
	// (request #3) is past tokenFailUntil, so it would succeed, silently
	// replaying the already-consumed authorization code. This is exactly
	// the bug this test guards against.
	atomic.StoreInt32(&f.tokenFailUntil, 2)

	executor := &countingRetryExecutor{maxAttempts: 3}
	svc, err := NewOIDCService(context.Background(), OIDCConfig{
		IssuerURL: f.issuer, ClientID: "client-1", ClientSecret: "secret",
		RedirectURL: "http://localhost/callback", Scopes: []string{"openid"},
		RetryExecutor: executor,
	})
	require.NoError(t, err)

	_, err = svc.HandleCallback(context.Background(), "auth-code-xyz", "nonce-abc", "verifier-1")
	require.Error(t, err, "Exchange failing must fail the login outright, not be silently retried")

	require.Equal(t, int32(2), atomic.LoadInt32(&f.tokenCalls),
		"Exchange must be attempted exactly once at our layer — the 2 HTTP calls are both the oauth2 "+
			"library's own internal auth-style probe within that single attempt, not a retry by our wrapper; "+
			"a third call would mean our wrapper retried and replayed the single-use authorization code")
}

func TestHandleCallback_VerifyAndUserInfoUseInteractivePolicy(t *testing.T) {
	f := newCallbackFakeIdP(t)
	f.idToken = f.signIDToken(t, "client-1", "user-123", "nonce-abc")

	executor := &countingRetryExecutor{maxAttempts: 3}
	svc, err := NewOIDCService(context.Background(), OIDCConfig{
		IssuerURL: f.issuer, ClientID: "client-1", ClientSecret: "secret",
		RedirectURL: "http://localhost/callback", Scopes: []string{"openid"},
		RetryExecutor: executor,
	})
	require.NoError(t, err)
	// NewOIDCService's discovery call already used one
	// ExecuteExternalServiceOperation attempt above; reset so this test
	// only observes calls made by HandleCallback itself.
	executor.calls = 0

	identity, err := svc.HandleCallback(context.Background(), "auth-code-xyz", "nonce-abc", "verifier-1")
	require.NoError(t, err)
	require.Equal(t, "user-123", identity.Subject)

	require.Equal(t, 0, executor.calls,
		"HandleCallback must not use ExecuteExternalServiceOperation: Exchange is never retried (Task 3) and Verify/UserInfo must use the interactive policy instead")
	require.Equal(t, 2, executor.interactiveCalls,
		"Verify and UserInfo should each make exactly one successful call through the interactive policy")
}

func TestHandleCallback_UserInfoFailureIsSwallowed(t *testing.T) {
	f := newCallbackFakeIdP(t)
	f.userInfoAlwaysFail = true
	f.idToken = f.signIDToken(t, "client-1", "user-123", "nonce-abc")

	executor := &countingRetryExecutor{maxAttempts: 3}
	svc, err := NewOIDCService(context.Background(), OIDCConfig{
		IssuerURL: f.issuer, ClientID: "client-1", ClientSecret: "secret",
		RedirectURL: "http://localhost/callback", Scopes: []string{"openid"},
		RetryExecutor: executor,
	})
	require.NoError(t, err)

	identity, err := svc.HandleCallback(context.Background(), "auth-code-xyz", "nonce-abc", "verifier-1")
	require.NoError(t, err, "UserInfo failing on every attempt must not fail the overall login")
	require.Equal(t, "user-123", identity.Subject)
	require.GreaterOrEqual(t, atomic.LoadInt32(&f.userInfoCalls), int32(3),
		"UserInfo should have been retried up to maxAttempts before its failure was swallowed")
}

func newCallbackTestService(t *testing.T, f *callbackFakeIdP) OIDCService {
	t.Helper()
	svc, err := NewOIDCService(context.Background(), OIDCConfig{
		IssuerURL: f.issuer, ClientID: "client-1", ClientSecret: "secret",
		RedirectURL: "http://localhost/callback", Scopes: []string{"openid"},
	})
	require.NoError(t, err)
	return svc
}

func TestOIDCService_AuthCodeURL_IncludesS256Challenge(t *testing.T) {
	srv, _ := newTestOIDCProvider(t)
	svc, err := NewOIDCService(context.Background(), OIDCConfig{
		IssuerURL: srv.URL, ClientID: "client-1", ClientSecret: "secret",
		RedirectURL: "http://localhost/callback", Scopes: []string{"openid"},
	})
	require.NoError(t, err)

	v := oauth2.GenerateVerifier()
	u, err := url.Parse(svc.AuthCodeURL("s", "n", v))
	require.NoError(t, err)
	require.Equal(t, "S256", u.Query().Get("code_challenge_method"))
	require.Equal(t, oauth2.S256ChallengeFromVerifier(v), u.Query().Get("code_challenge"))
}

func TestHandleCallback_SendsCodeVerifier(t *testing.T) {
	f := newCallbackFakeIdP(t)
	f.idToken = f.signIDToken(t, "client-1", "user-123", "nonce-abc")
	svc := newCallbackTestService(t, f)

	_, err := svc.HandleCallback(context.Background(), "auth-code-xyz", "nonce-abc", "my-verifier")
	require.NoError(t, err)
	require.Equal(t, "my-verifier", f.tokenForm().Get("code_verifier"))
}

func TestHandleCallback_ParsesEmailVerified(t *testing.T) {
	cases := []struct {
		name string
		val  any
		set  bool
		want bool
	}{
		{"bool true", true, true, true},
		{"bool false", false, true, false},
		{"string true", "true", true, true},
		{"string TRUE", "TRUE", true, true},
		{"string false", "false", true, false},
		{"string yes", "yes", true, false},
		{"number one", 1, true, false},
		{"absent", nil, false, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newCallbackFakeIdP(t)
			extra := map[string]any{"email": "a@example.com"}
			if tc.set {
				extra["email_verified"] = tc.val
			}
			f.idToken = f.signIDTokenWith(t, "client-1", "user-123", "nonce-abc", extra)
			svc := newCallbackTestService(t, f)

			identity, err := svc.HandleCallback(context.Background(), "c", "nonce-abc", "v")
			require.NoError(t, err)
			require.Equal(t, "a@example.com", identity.Email)
			require.Equal(t, tc.want, identity.EmailVerified)
		})
	}
}

func TestHandleCallback_EmailFromUserInfoUsesUserInfoVerified(t *testing.T) {
	f := newCallbackFakeIdP(t)
	// The ID token has no email but claims email_verified; it must be ignored.
	f.idToken = f.signIDTokenWith(t, "client-1", "user-123", "nonce-abc", map[string]any{"email_verified": true})
	f.userInfoBody = map[string]any{"sub": "user-123", "email": "ui@example.com", "email_verified": false}
	svc := newCallbackTestService(t, f)

	identity, err := svc.HandleCallback(context.Background(), "c", "nonce-abc", "v")
	require.NoError(t, err)
	require.Equal(t, "ui@example.com", identity.Email)
	require.False(t, identity.EmailVerified)

	f.userInfoBody = map[string]any{"sub": "user-123", "email": "ui@example.com", "email_verified": true}
	identity, err = svc.HandleCallback(context.Background(), "c", "nonce-abc", "v")
	require.NoError(t, err)
	require.True(t, identity.EmailVerified)
}

func TestHandleCallback_ReturnsRawClaims(t *testing.T) {
	f := newCallbackFakeIdP(t)
	f.idToken = f.signIDTokenWith(t, "client-1", "user-123", "nonce-abc", map[string]any{
		"groups": []string{"eng", "ops"}, "hd": "example.com",
	})
	svc := newCallbackTestService(t, f)

	identity, err := svc.HandleCallback(context.Background(), "c", "nonce-abc", "v")
	require.NoError(t, err)
	require.Equal(t, "user-123", identity.Claims["sub"])
	require.Equal(t, "example.com", identity.Claims["hd"])
	require.Equal(t, []any{"eng", "ops"}, identity.Claims["groups"])
}
