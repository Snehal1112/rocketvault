package middleware

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"

	"rocketvault/common"
	"rocketvault/internal/logging"
	vaultServices "rocketvault/internal/services/vaults"
	"rocketvault/model"
)

// collidingNames are resource names that end a public path or a health probe
// path. Suffix matching once let a resource with one of these names skip
// authentication or vault resolution (B80).
var collidingNames = []string{"login", "health", "refresh", "register", "config", "jwks.json", "ready", "live", "database", "token", "callback", "exchange"}

// collidingPaths returns name at every resource position a caller controls.
// User ids are omitted because /api/v1/users/login is itself public.
func collidingPaths(name string) []string {
	return []string{
		"/api/v1/vaults/" + name,
		"/api/v1/vaults/" + name + "/purge",
		"/api/v1/vaults/" + name + "/secrets",
		"/api/v1/vaults/prod/secrets/" + name,
		"/api/v1/vaults/prod/keys/" + name,
		"/api/v1/vaults/prod/certificates/" + name,
		"/api/v1/vaults/prod/role-assignments/" + name,
		"/api/v1/secrets/" + name,
		"/api/v1/keys/" + name,
		"/api/v1/certificates/" + name,
		"/api/v1/service-accounts/" + name,
		"/api/v1/access-policies/" + name,
		"/api/v1/vaults/" + name + "/health",
		"/api/v1/vaults/prod/secrets/x/health/ready",
		"/api/v1/vaults/" + name + "/users/login",
		"/api/v1/vaults/" + name + "/oauth2/token",
		"/api/v1/vaults/" + name + "/auth/login",
	}
}

// TestAuthenticationMiddleware_VaultNamedLikePublicEndpointRequiresToken is the
// B80 regression. Suffix matching let "/api/v1/vaults/login" skip
// authentication, so a vault named login, health, refresh or register could
// not be managed over HTTP. Matching is now exact.
func TestAuthenticationMiddleware_VaultNamedLikePublicEndpointRequiresToken(t *testing.T) {
	t.Parallel()
	for _, name := range []string{"login", "health", "refresh", "register"} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			mw, _, _, _ := setupTestMiddleware()
			nextCalled := false
			rr := httptest.NewRecorder()
			mw.AuthenticationMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				nextCalled = true
			})).ServeHTTP(rr, httptest.NewRequestWithContext(context.Background(), http.MethodDelete, "/api/v1/vaults/"+name, nil))

			assert.False(t, nextCalled, "a vault named %q must not be treated as a public endpoint", name)
			assert.Equal(t, http.StatusUnauthorized, rr.Code)
		})
	}
}

// TestAuthenticationMiddleware_PublicNamesAtAnyResourcePositionRequireToken
// covers every resource position a caller can name, for every colliding name.
func TestAuthenticationMiddleware_PublicNamesAtAnyResourcePositionRequireToken(t *testing.T) {
	t.Parallel()
	mw, _, _, _ := setupTestMiddleware()
	for _, name := range collidingNames {
		for _, path := range collidingPaths(name) {
			for _, method := range []string{http.MethodGet, http.MethodPost, http.MethodPut, http.MethodDelete} {
				nextCalled := false
				rr := httptest.NewRecorder()
				mw.AuthenticationMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					nextCalled = true
				})).ServeHTTP(rr, httptest.NewRequestWithContext(context.Background(), method, path, nil))

				assert.False(t, nextCalled, "%s %s must require a session", method, path)
				assert.Equal(t, http.StatusUnauthorized, rr.Code, "%s %s", method, path)
			}
		}
	}
}

// TestAuthorizationMiddleware_VaultNamedLikePublicEndpointIsNotSkipped pins
// that the authorization skip uses the same exact matcher. A request with no
// roles in context must be refused rather than passed through.
func TestAuthorizationMiddleware_VaultNamedLikePublicEndpointIsNotSkipped(t *testing.T) {
	t.Parallel()
	mw, _, _, _ := setupTestMiddleware()
	for _, name := range collidingNames {
		for _, path := range collidingPaths(name) {
			nextCalled := false
			rr := httptest.NewRecorder()
			mw.AuthorizationMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				nextCalled = true
			})).ServeHTTP(rr, httptest.NewRequestWithContext(context.Background(), http.MethodDelete, path, nil))

			assert.False(t, nextCalled, "%s must not skip authorization", path)
			assert.Equal(t, http.StatusForbidden, rr.Code, path)
		}
	}
}

// TestPublicPathsSkipAuthenticationAndAuthorization pins that every public
// path still reaches its handler with no session and no roles.
func TestPublicPathsSkipAuthenticationAndAuthorization(t *testing.T) {
	t.Parallel()
	mw, _, _, _ := setupTestMiddleware()
	for _, path := range PublicPaths() {
		nextCalled := false
		rr := httptest.NewRecorder()
		mw.AuthenticationMiddleware(mw.AuthorizationMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			nextCalled = true
			w.WriteHeader(http.StatusOK)
		}))).ServeHTTP(rr, httptest.NewRequestWithContext(context.Background(), http.MethodPost, path, nil))

		assert.True(t, nextCalled, "%s must skip authentication and authorization", path)
		assert.Equal(t, http.StatusOK, rr.Code, path)
	}
}

// TestIsPublicPath_ExactMatchOnly pins the public set and its exactness.
func TestIsPublicPath_ExactMatchOnly(t *testing.T) {
	t.Parallel()
	public := []string{"/api/v1/health", "/api/v1/health/ready", "/api/v1/health/live",
		"/api/v1/users/login", "/api/v1/users/refresh", "/api/v1/oauth2/token",
		"/api/v1/oidc/login", "/api/v1/oidc/callback", "/api/v1/oidc/cli/exchange",
		"/api/v1/config"}
	for _, p := range public {
		assert.True(t, IsPublicPath(p), "%s must be public", p)
	}
	for _, p := range []string{"/api/v1/vaults/login", "/api/v1/vaults/health", "/api/v1/vaults/refresh",
		"/api/v1/vaults/register", "/api/v1/health/database", "/api/v1/register", "/api/v1/auth/login",
		"/health", "/login", "/api/v1/users/login/", "/api/v1//health", "/API/v1/health",
		"/api/v1/vaults/x/users/login", "/api/v1/vaults/x/oauth2/token", "/api/v1/vaults/x/oidc/callback",
		"/api/v1/vaults/x/config", "/api/v1/jwks/rotate", "/jwks.json", "/metrics", ""} {
		assert.False(t, IsPublicPath(p), "%s must not be public", p)
	}
	assert.ElementsMatch(t, public, PublicPaths())
	assert.IsIncreasing(t, PublicPaths(), "PublicPaths must be sorted")
}

// TestIsHealthProbe_ExactMatchOnly pins that a vault named health is still
// resolved and rate limited like any other vault.
func TestIsHealthProbe_ExactMatchOnly(t *testing.T) {
	t.Parallel()
	for _, p := range []string{"/api/v1/health", "/api/v1/health/ready", "/api/v1/health/live", "/api/v1/health/database"} {
		assert.True(t, isHealthProbe(p), p)
	}
	for _, p := range []string{"/api/v1/vaults/health", "/api/v1/vaults/prod/secrets/health", "/health",
		"/api/v1/vaults/x/health/ready", "/api/v1/vaults/x/health/live", "/api/v1/vaults/x/health/database",
		"/api/v1/health/", "/api/v1/health/other"} {
		assert.False(t, isHealthProbe(p), p)
	}
}

// TestPublicHealthPathsAreHealthProbes pins that both lists derive from one
// source: every public health path is a probe, and only /health/database is a
// probe that still requires a session.
func TestPublicHealthPathsAreHealthProbes(t *testing.T) {
	t.Parallel()
	for _, p := range []string{"/api/v1/health", "/api/v1/health/ready", "/api/v1/health/live"} {
		assert.True(t, IsPublicPath(p) && isHealthProbe(p), p)
	}
	assert.True(t, isHealthProbe("/api/v1/health/database"))
	assert.False(t, IsPublicPath("/api/v1/health/database"))
}

// TestVaultResolutionMiddleware_VaultNamedHealthIsResolved pins that a vault
// named after a health probe is resolved like any other vault.
func TestVaultResolutionMiddleware_VaultNamedHealthIsResolved(t *testing.T) {
	t.Parallel()
	for _, path := range []string{"/api/v1/vaults/health", "/api/v1/vaults/x/health/ready",
		"/api/v1/vaults/x/health/live", "/api/v1/vaults/x/health/database"} {
		logger := &logging.Logger{Logger: logrus.New()}
		logger.SetLevel(logrus.ErrorLevel)
		mockContainer := &MockServiceContainer{logger: logger}
		stub := &stubVaultService{err: vaultServices.ErrVaultNotFound}
		mockContainer.On("GetVaultService").Return(stub).Maybe()
		mw := NewMiddleware(mockContainer)

		called := false
		rec := httptest.NewRecorder()
		mw.VaultResolutionMiddleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			called = true
		})).ServeHTTP(rec, httptest.NewRequestWithContext(context.Background(), http.MethodGet, path, nil))

		assert.Falsef(t, called, "%s must not skip vault resolution", path)
		assert.Equalf(t, http.StatusNotFound, rec.Code, "%s", path)
		assert.Positivef(t, stub.getVaultCalls, "vault service must be consulted for %s", path)
	}
}

// TestVaultRateLimitMiddleware_VaultNamedHealthIsCounted pins that a vault
// named health spends its budget like any other vault.
func TestVaultRateLimitMiddleware_VaultNamedHealthIsCounted(t *testing.T) {
	t.Parallel()
	mw := newVaultRateLimitTestMiddleware(1, nil)
	handler := mw.VaultRateLimitMiddleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	codes := make([]int, 0, 2)
	for i := 0; i < 2; i++ {
		req := httptest.NewRequestWithContext(context.Background(), http.MethodDelete, "/api/v1/vaults/health", nil)
		req = req.WithContext(context.WithValue(req.Context(), common.VaultIDKey, model.DefaultVaultID))
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		codes = append(codes, rr.Code)
	}
	assert.Equal(t, []int{http.StatusOK, http.StatusTooManyRequests}, codes)
}
