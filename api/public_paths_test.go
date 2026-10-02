package api

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"testing"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"rocketvault/app"
	"rocketvault/internal/middleware"
)

// legacySkipsAuthentication is the suffix matcher AuthenticationMiddleware
// used before B80, kept here only to prove that exact matching changes no
// registered route's classification.
func legacySkipsAuthentication(path string) bool {
	return strings.HasSuffix(path, "/health") ||
		strings.HasSuffix(path, "/health/ready") ||
		strings.HasSuffix(path, "/health/live") ||
		strings.HasSuffix(path, "/login") ||
		strings.HasSuffix(path, "/register") ||
		strings.HasSuffix(path, "/refresh") ||
		strings.Contains(path, "/auth/login") ||
		strings.Contains(path, "/auth/register") ||
		strings.Contains(path, "/auth/refresh") ||
		strings.HasSuffix(path, "/oauth2/token") ||
		strings.HasSuffix(path, "/oidc/login") ||
		strings.HasSuffix(path, "/oidc/callback")
}

// walkedRoute is one registered route and whether it runs behind the
// authentication chain on the API root router.
type walkedRoute struct {
	RouteInfo
	route   *mux.Route
	onChain bool
}

// publicRouteTable is every route served without a session. A route that
// leaves this table, or joins it, must be a deliberate change.
var publicRouteTable = map[RouteInfo]bool{
	{Method: http.MethodGet, Path: "/api/v1/health"}:             true,
	{Method: http.MethodGet, Path: "/api/v1/health/ready"}:       true,
	{Method: http.MethodGet, Path: "/api/v1/health/live"}:        true,
	{Method: http.MethodPost, Path: "/api/v1/users/login"}:       true,
	{Method: http.MethodPost, Path: "/api/v1/users/refresh"}:     true,
	{Method: http.MethodPost, Path: "/api/v1/oauth2/token"}:      true,
	{Method: http.MethodGet, Path: "/api/v1/oidc/login"}:         true,
	{Method: http.MethodGet, Path: "/api/v1/oidc/callback"}:      true,
	{Method: http.MethodPost, Path: "/api/v1/oidc/cli/exchange"}: true,
	{Method: http.MethodGet, Path: "/api/v1/config"}:             true,
	{Method: http.MethodGet, Path: "/jwks.json"}:                 true,
	{Method: http.MethodGet, Path: "/metrics"}:                   true,
}

// buildPublicPathRouter builds the real router through api.Init and returns
// it with the API, whose ApiRoot carries the authentication chain.
func buildPublicPathRouter(t *testing.T, metrics bool) (*mux.Router, *API) {
	t.Helper()
	container := &routerWalkContainer{policyContainer: &policyContainer{}, logger: userTestLog()}
	a := &app.App{ServiceContainer: container, Logger: userTestLog()}
	router := mux.NewRouter()
	api := Init(WithAPP(a), WithRouter(router), WithBasePath("/api/v1"),
		WithLogger(userTestLog()), WithMetricsEnabled(metrics))
	require.NotNil(t, api)
	return router, api
}

// walkAllRoutes lists every route with a path template. A route registered
// without methods is reported as method ANY so that it cannot escape.
func walkAllRoutes(t *testing.T, router *mux.Router) []*mux.Route {
	t.Helper()
	var out []*mux.Route
	require.NoError(t, router.Walk(func(route *mux.Route, _ *mux.Router, _ []*mux.Route) error {
		if _, err := route.GetPathTemplate(); err == nil && route.GetHandler() != nil {
			out = append(out, route)
		}
		return nil
	}))
	return out
}

// classifyRoutes walks router and marks each route that runs behind the
// authentication chain.
func classifyRoutes(t *testing.T, router *mux.Router, api *API) []walkedRoute {
	t.Helper()
	chain := map[*mux.Route]bool{}
	for _, r := range walkAllRoutes(t, api.BaseRoutes.ApiRoot) {
		chain[r] = true
	}
	var out []walkedRoute
	for _, r := range walkAllRoutes(t, router) {
		tmpl, _ := r.GetPathTemplate()
		methods, err := r.GetMethods()
		if err != nil || len(methods) == 0 {
			methods = []string{"ANY"}
		}
		for _, m := range methods {
			out = append(out, walkedRoute{RouteInfo: RouteInfo{Method: m, Path: tmpl}, route: r, onChain: chain[r]})
		}
	}
	require.NotEmpty(t, out)
	return out
}

// TestPublicRoutes_ExactMatchingKeepsEveryRouteClassification walks the real
// router and proves that exact matching makes no public route authenticated
// and no authenticated route public. A route off the authentication chain is
// public by construction; a route on it is public only through IsPublicPath.
func TestPublicRoutes_ExactMatchingKeepsEveryRouteClassification(t *testing.T) {
	for _, metrics := range []bool{true, false} {
		t.Run(fmt.Sprintf("metrics=%v", metrics), func(t *testing.T) {
			router, api := buildPublicPathRouter(t, metrics)
			seenPublic := map[RouteInfo]bool{}
			publicUnderBase := map[string]bool{}
			for _, r := range classifyRoutes(t, router, api) {
				before := !r.onChain || legacySkipsAuthentication(r.Path)
				after := !r.onChain || middleware.IsPublicPath(r.Path)
				assert.Equal(t, before, after, "%s %s changed classification", r.Method, r.Path)
				assert.Equal(t, publicRouteTable[r.RouteInfo], after,
					"%s %s public=%v does not match the public route table", r.Method, r.Path, after)
				if after {
					seenPublic[r.RouteInfo] = true
					if strings.HasPrefix(r.Path, "/api/v1/") {
						publicUnderBase[r.Path] = true
					}
				}
				if strings.Contains(r.Path, "{") {
					assert.False(t, middleware.IsPublicPath(r.Path), "%s %s has a variable and must not be public", r.Method, r.Path)
				}
			}
			for info := range publicRouteTable {
				if info.Path == "/metrics" && !metrics {
					continue
				}
				assert.True(t, seenPublic[info], "%s %s is in the public table but not registered as public", info.Method, info.Path)
			}

			// PublicPaths is exactly the set of public routes under the base
			// path, whether they are served on the chain or off it.
			want := make([]string, 0, len(publicUnderBase))
			for p := range publicUnderBase {
				want = append(want, p)
			}
			sort.Strings(want)
			assert.Equal(t, want, middleware.PublicPaths())
		})
	}
}

// collidingResourceNames end a public path or a health probe path.
var collidingResourceNames = []string{"login", "health", "refresh", "register", "config", "jwks.json", "ready", "live", "database", "token", "callback", "exchange"}

// TestPublicRoutes_ResourceNamedLikePublicEndpointRequiresSession substitutes
// every colliding name into every path variable of every authenticated route
// in the real router, and sends the request with no session. Each one that
// the router routes must be refused with 401.
func TestPublicRoutes_ResourceNamedLikePublicEndpointRequiresSession(t *testing.T) {
	router, api := buildPublicPathRouter(t, true)
	sent := 0
	ip := 0
	for _, r := range classifyRoutes(t, router, api) {
		if !r.onChain || r.Method == "ANY" {
			continue
		}
		names, err := r.route.GetVarNames()
		require.NoError(t, err)
		if len(names) == 0 {
			continue
		}
		for _, name := range collidingResourceNames {
			for _, target := range names {
				pairs := make([]string, 0, 2*len(names))
				for _, n := range names {
					v := "0f0e0d0c-0b0a-4908-8706-050403020100"
					if n == target {
						v = name
					}
					if n == "vault_name" || n == "name" {
						if n != target {
							v = "prod"
						}
					}
					pairs = append(pairs, n, v)
				}
				u, err := r.route.URLPath(pairs...)
				if err != nil {
					// The variable's pattern rejects this name, so no request
					// with it can reach this route.
					continue
				}
				req := httptest.NewRequestWithContext(context.Background(), r.Method, u.Path, nil)
				ip++
				req.RemoteAddr = fmt.Sprintf("10.%d.%d.%d:1234", (ip>>16)&0xff, (ip>>8)&0xff, ip&0xff)
				var match mux.RouteMatch
				if !router.Match(req, &match) || match.MatchErr != nil || match.Route != r.route {
					continue
				}
				rr := httptest.NewRecorder()
				router.ServeHTTP(rr, req)
				assert.Equal(t, http.StatusUnauthorized, rr.Code, "%s %s (template %s) must require a session", r.Method, u.Path, r.Path)
				sent++
			}
		}
	}
	assert.Positive(t, sent, "the walk must exercise at least one route")
	t.Logf("sent %d colliding-name requests", sent)
}
