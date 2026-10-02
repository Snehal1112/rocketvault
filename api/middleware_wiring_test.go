// Package api — proves SecurityHeadersMiddleware is actually attached to the
// real production router, not just implemented and never used.
package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gorilla/mux"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"rocketvault/app"
)

// assertSecurityHeaders fails the test if any of the headers
// SecurityHeadersMiddleware sets are missing.
func assertSecurityHeaders(t *testing.T, w *httptest.ResponseRecorder) {
	t.Helper()
	assert.Equal(t, "nosniff", w.Header().Get("X-Content-Type-Options"))
	assert.Equal(t, "DENY", w.Header().Get("X-Frame-Options"))
	assert.Equal(t, "1; mode=block", w.Header().Get("X-XSS-Protection"))
	assert.Equal(t, "default-src 'self'", w.Header().Get("Content-Security-Policy"))
}

// TestSecurityHeadersMiddleware_WiredOnPublicRoute walks the REAL router
// built by api.Init — the same construction production uses, with the full
// middleware chain — and hits the public /config route, asserting the
// security headers are present. A future accidental removal of
// SecurityHeadersMiddleware's ".Use" registration would fail this, not just
// pass silently the way it did before that middleware was wired in.
func TestSecurityHeadersMiddleware_WiredOnPublicRoute(t *testing.T) {
	container := &routerWalkContainer{policyContainer: &policyContainer{}, logger: userTestLog()}
	a := &app.App{ServiceContainer: container, Logger: userTestLog()}

	router := mux.NewRouter()
	built := Init(
		WithAPP(a),
		WithRouter(router),
		WithBasePath("/api/v1"),
		WithLogger(userTestLog()),
	)
	require.NotNil(t, built)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/config", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)
	assertSecurityHeaders(t, w)
}

// TestRateLimitMiddleware_WiredOnConfigRoute walks the real router and
// proves the public /config route is rate limited per client IP.
func TestRateLimitMiddleware_WiredOnConfigRoute(t *testing.T) {
	previous := viper.Get("rate_limit.default")
	viper.Set("rate_limit.default", 3)
	t.Cleanup(func() { viper.Set("rate_limit.default", previous) })

	container := &routerWalkContainer{policyContainer: &policyContainer{}, logger: userTestLog()}
	a := &app.App{ServiceContainer: container, Logger: userTestLog()}

	router := mux.NewRouter()
	built := Init(
		WithAPP(a),
		WithRouter(router),
		WithBasePath("/api/v1"),
		WithLogger(userTestLog()),
	)
	require.NotNil(t, built)

	get := func(remoteAddr string) int {
		req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/api/v1/config", nil)
		req.RemoteAddr = remoteAddr
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		return w.Code
	}

	for i := range 3 {
		require.Equal(t, http.StatusOK, get("198.51.100.7:4000"), "request %d is within the burst", i+1)
	}
	assert.Equal(t, http.StatusTooManyRequests, get("198.51.100.7:4001"), "the fourth request from one IP is throttled")
	assert.Equal(t, http.StatusOK, get("203.0.113.9:4000"), "another IP keeps its own bucket")
}

// TestSecurityHeadersMiddleware_WiredOnRejectedRequest hits a real vault
// data-plane route with no Authorization header, which AuthenticationMiddleware
// rejects with 401 before touching the container (so routerWalkContainer's
// "panic if called" stub methods are never reached). SecurityHeadersMiddleware
// runs before AuthenticationMiddleware in the chain, so the rejected response
// should still carry the security headers.
func TestSecurityHeadersMiddleware_WiredOnRejectedRequest(t *testing.T) {
	container := &routerWalkContainer{policyContainer: &policyContainer{}, logger: userTestLog()}
	a := &app.App{ServiceContainer: container, Logger: userTestLog()}

	router := mux.NewRouter()
	built := Init(
		WithAPP(a),
		WithRouter(router),
		WithBasePath("/api/v1"),
		WithLogger(userTestLog()),
	)
	require.NotNil(t, built)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/secrets", nil) // no auth token
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	require.Equal(t, http.StatusUnauthorized, w.Code)
	assertSecurityHeaders(t, w)
}
