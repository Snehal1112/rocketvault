// Package api — tests for the route authorization allow-list (B80).
package api

import (
	"net/http"
	"slices"
	"sort"
	"strings"
	"testing"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"rocketvault/app"
	"rocketvault/internal/middleware"
)

// The tests in this file mutate the package-level allow-list, so none of them
// call t.Parallel().

// newAuthzCheckRouter builds the real production router, exactly as
// bootstrap does, with metrics on or off.
func newAuthzCheckRouter(t *testing.T, metrics bool) *mux.Router {
	t.Helper()
	container := &routerWalkContainer{policyContainer: &policyContainer{}, logger: userTestLog()}
	a := &app.App{ServiceContainer: container, Logger: userTestLog()}
	router := mux.NewRouter()
	require.NotNil(t, Init(WithAPP(a), WithRouter(router), WithBasePath("/api/v1"),
		WithLogger(userTestLog()), WithMetricsEnabled(metrics)))
	return router
}

// withAllowList replaces the allow-list for one test and restores it after.
func withAllowList(t *testing.T, entries []routeEntry) {
	t.Helper()
	saved := nonDataPlaneRoutes
	nonDataPlaneRoutes = entries
	t.Cleanup(func() { nonDataPlaneRoutes = saved })
}

// allowListWithout returns a copy of the allow-list without route.
func allowListWithout(t *testing.T, route RouteInfo) []routeEntry {
	t.Helper()
	out := make([]routeEntry, 0, len(nonDataPlaneRoutes))
	for _, e := range nonDataPlaneRoutes {
		if e.Route != route {
			out = append(out, e)
		}
	}
	require.Len(t, out, len(nonDataPlaneRoutes)-1, "%v must be on the allow-list exactly once", route)
	return out
}

// allowListWith returns a copy of the allow-list with route's access changed.
func allowListWith(t *testing.T, route RouteInfo, access RouteAccess) []routeEntry {
	t.Helper()
	out := slices.Clone(nonDataPlaneRoutes)
	found := false
	for i := range out {
		if out[i].Route == route {
			out[i].Access = access
			found = true
		}
	}
	require.True(t, found, "%v must be on the allow-list", route)
	return out
}

// TestVerifyRouteAuthorization_RealRouterPasses proves every registered route
// is either a mapped data-plane route or on the allow-list.
func TestVerifyRouteAuthorization_RealRouterPasses(t *testing.T) {
	for _, metrics := range []bool{true, false} {
		require.NoError(t, VerifyRouteAuthorization(newAuthzCheckRouter(t, metrics), "/api/v1"),
			"metrics enabled = %v", metrics)
	}
}

// TestVerifyRouteAuthorization_RejectsUnlistedRoute is the core B80 property:
// a new non-data-plane route that nobody classified fails the check.
func TestVerifyRouteAuthorization_RejectsUnlistedRoute(t *testing.T) {
	router := newAuthzCheckRouter(t, false)
	router.Handle("/api/v1/unlisted", http.NotFoundHandler()).Methods(http.MethodGet)

	err := VerifyRouteAuthorization(router, "/api/v1")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "GET /api/v1/unlisted is not a data-plane route and has no entry")
}

// TestVerifyRouteAuthorization_RejectsMissingEntry removes one real route from
// the allow-list and proves the check names it.
func TestVerifyRouteAuthorization_RejectsMissingEntry(t *testing.T) {
	removed := RouteInfo{Method: http.MethodDelete, Path: "/api/v1/users/{user_id:[A-Fa-f0-9-]+}"}
	withAllowList(t, allowListWithout(t, removed))

	err := VerifyRouteAuthorization(newAuthzCheckRouter(t, false), "/api/v1")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "DELETE /api/v1/users/{user_id:[A-Fa-f0-9-]+} is not a data-plane route and has no entry")
}

// TestVerifyRouteAuthorization_RejectsMethodlessRoute closes the gap that
// WalkRoutes leaves open: a leaf route with no .Methods(...) is skipped by
// every inventory walk, so it must be refused outright.
func TestVerifyRouteAuthorization_RejectsMethodlessRoute(t *testing.T) {
	router := newAuthzCheckRouter(t, false)
	router.Handle("/api/v1/nomethod", http.NotFoundHandler())

	err := VerifyRouteAuthorization(router, "/api/v1")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "/api/v1/nomethod has a handler but no .Methods")
}

// TestVerifyRouteAuthorization_RejectsMethodlessRouteOnSubrouter proves the
// methodless check also reaches a leaf registered on a nested subrouter.
func TestVerifyRouteAuthorization_RejectsMethodlessRouteOnSubrouter(t *testing.T) {
	router := newAuthzCheckRouter(t, false)
	router.PathPrefix("/api/v1/vaults").Subrouter().Handle("/{name}/nomethod", http.NotFoundHandler())

	err := VerifyRouteAuthorization(router, "/api/v1")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "/api/v1/vaults/{name}/nomethod has a handler but no .Methods")
}

// TestVerifyRouteAuthorization_RejectsHandlerWithoutPathTemplate refuses a
// catch-all leaf route, which has neither a path nor methods to classify.
func TestVerifyRouteAuthorization_RejectsHandlerWithoutPathTemplate(t *testing.T) {
	router := newAuthzCheckRouter(t, false)
	router.NewRoute().Handler(http.NotFoundHandler())

	err := VerifyRouteAuthorization(router, "/api/v1")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "a route has a handler but no path template")
}

// TestVerifyRouteAuthorization_RejectsBasePathMismatch pins the fail-closed
// base-path assertion for every caller of api.Init, not only bootstrap.
func TestVerifyRouteAuthorization_RejectsBasePathMismatch(t *testing.T) {
	err := VerifyRouteAuthorization(newAuthzCheckRouter(t, false), "/api/v2")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "does not match the data-plane base path")
}

// TestVerifyRouteAuthorization_RejectsStaleEntry proves a removed route
// cannot leave a dead allow-list entry behind.
func TestVerifyRouteAuthorization_RejectsStaleEntry(t *testing.T) {
	stale := routeEntry{Route: RouteInfo{Method: http.MethodGet, Path: "/api/v1/removed"}, Access: RouteAccessAdmin, Gate: "test"}
	withAllowList(t, append(slices.Clone(nonDataPlaneRoutes), stale))

	err := VerifyRouteAuthorization(newAuthzCheckRouter(t, false), "/api/v1")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "GET /api/v1/removed is on the allow-list but is not registered")
}

// TestVerifyRouteAuthorization_RejectsDuplicateEntry proves one route cannot
// be classified twice, possibly with two different gates.
func TestVerifyRouteAuthorization_RejectsDuplicateEntry(t *testing.T) {
	dup := routeEntry{Route: RouteInfo{Method: http.MethodGet, Path: "/api/v1/users"}, Access: RouteAccessAnySession, Gate: "test"}
	withAllowList(t, append(slices.Clone(nonDataPlaneRoutes), dup))

	err := VerifyRouteAuthorization(newAuthzCheckRouter(t, false), "/api/v1")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "GET /api/v1/users is on the allow-list more than once")
}

// TestVerifyRouteAuthorization_RejectsMalformedEntry refuses an entry with an
// unknown access class or no named gate.
func TestVerifyRouteAuthorization_RejectsMalformedEntry(t *testing.T) {
	entries := slices.Clone(nonDataPlaneRoutes)
	entries = append(entries,
		routeEntry{Route: RouteInfo{Method: http.MethodGet, Path: "/api/v1/unlisted"}, Access: "anyone", Gate: "test"},
		routeEntry{Route: RouteInfo{Method: http.MethodPost, Path: "/api/v1/unlisted"}, Access: RouteAccessAdmin})
	withAllowList(t, entries)
	router := newAuthzCheckRouter(t, false)
	router.Handle("/api/v1/unlisted", http.NotFoundHandler()).Methods(http.MethodGet, http.MethodPost)

	err := VerifyRouteAuthorization(router, "/api/v1")
	require.Error(t, err)
	assert.Contains(t, err.Error(), `GET /api/v1/unlisted has unknown access class "anyone"`)
	assert.Contains(t, err.Error(), "POST /api/v1/unlisted names no gate")
}

// TestVerifyRouteAuthorization_RejectsDataPlaneRouteOnAllowList proves a
// data-plane route cannot be waved through by an allow-list entry.
func TestVerifyRouteAuthorization_RejectsDataPlaneRouteOnAllowList(t *testing.T) {
	entry := routeEntry{Route: RouteInfo{Method: http.MethodGet, Path: "/api/v1/secrets"}, Access: RouteAccessAnySession, Gate: "test"}
	withAllowList(t, append(slices.Clone(nonDataPlaneRoutes), entry))

	err := VerifyRouteAuthorization(newAuthzCheckRouter(t, false), "/api/v1")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "GET /api/v1/secrets is a data-plane route and must not be on the allow-list")
}

// TestVerifyRouteAuthorization_RejectsUnmappedDataPlaneRoute proves a
// data-plane route that maps to no data action fails closed.
func TestVerifyRouteAuthorization_RejectsUnmappedDataPlaneRoute(t *testing.T) {
	router := newAuthzCheckRouter(t, false)
	router.Handle("/api/v1/vaults/{vault_name:[a-z0-9-]+}/secrets", http.NotFoundHandler()).Methods(http.MethodPatch)

	err := VerifyRouteAuthorization(router, "/api/v1")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "PATCH /api/v1/vaults/{vault_name:[a-z0-9-]+}/secrets is a data-plane route with no data action")
}

// TestVerifyRouteAuthorization_RejectsPublicEntryOnAuthenticatedRoute proves
// an entry cannot claim a route is public when the chain requires a session.
func TestVerifyRouteAuthorization_RejectsPublicEntryOnAuthenticatedRoute(t *testing.T) {
	route := RouteInfo{Method: http.MethodGet, Path: "/api/v1/health/database"}
	withAllowList(t, allowListWith(t, route, RouteAccessPublic))

	err := VerifyRouteAuthorization(newAuthzCheckRouter(t, false), "/api/v1")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "GET /api/v1/health/database is listed as public but requires a session")
}

// TestVerifyRouteAuthorization_RejectsGatedEntryOnPublicRoute proves an entry
// cannot claim a gate on a route that skips authentication.
func TestVerifyRouteAuthorization_RejectsGatedEntryOnPublicRoute(t *testing.T) {
	for _, route := range []RouteInfo{
		{Method: http.MethodPost, Path: "/api/v1/users/login"},
		{Method: http.MethodGet, Path: "/jwks.json"},
	} {
		t.Run(route.Path, func(t *testing.T) {
			withAllowList(t, allowListWith(t, route, RouteAccessAdmin))
			err := VerifyRouteAuthorization(newAuthzCheckRouter(t, false), "/api/v1")
			require.Error(t, err)
			assert.Contains(t, err.Error(), route.Method+" "+route.Path+" skips authentication but is not listed as public")
		})
	}
}

// TestVerifyRouteAuthorization_RejectsUnauthenticatedDataPlaneRoute proves a
// data-plane route outside the base path, which no authentication chain
// covers, fails the check.
func TestVerifyRouteAuthorization_RejectsUnauthenticatedDataPlaneRoute(t *testing.T) {
	router := newAuthzCheckRouter(t, false)
	router.Handle("/secrets", http.NotFoundHandler()).Methods(http.MethodGet)

	err := VerifyRouteAuthorization(router, "/api/v1")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "GET /secrets is a data-plane route that skips authentication")
}

// TestVerifyRouteAuthorization_ReportsEveryViolationSorted proves the error
// lists every problem, one per line, in sorted order.
func TestVerifyRouteAuthorization_ReportsEveryViolationSorted(t *testing.T) {
	router := newAuthzCheckRouter(t, false)
	router.Handle("/api/v1/zzz", http.NotFoundHandler()).Methods(http.MethodGet)
	router.Handle("/api/v1/aaa", http.NotFoundHandler()).Methods(http.MethodGet)
	router.Handle("/api/v1/nomethod", http.NotFoundHandler())

	err := VerifyRouteAuthorization(router, "/api/v1")
	require.Error(t, err)
	lines := strings.Split(err.Error(), "\n")
	require.Len(t, lines, 4, err.Error())
	problems := lines[1:]
	assert.True(t, sort.StringsAreSorted(problems), "problems must be sorted:\n%s", err.Error())
	assert.Contains(t, err.Error(), "GET /api/v1/aaa")
	assert.Contains(t, err.Error(), "GET /api/v1/zzz")
	assert.Contains(t, err.Error(), "/api/v1/nomethod")
}

// TestVerifyRouteAuthorization_PublicEntriesMatchPublicRouteTable ties the
// allow-list to the public route table that the public path tests walk, so
// the two inventories cannot drift apart.
func TestVerifyRouteAuthorization_PublicEntriesMatchPublicRouteTable(t *testing.T) {
	listed := map[RouteInfo]bool{}
	for _, e := range nonDataPlaneRoutes {
		if e.Access == RouteAccessPublic {
			listed[e.Route] = true
		}
	}
	assert.Equal(t, publicRouteTable, listed)

	// Every path the middleware serves without a session is a public entry.
	for _, p := range middleware.PublicPaths() {
		found := false
		for info := range listed {
			found = found || info.Path == p
		}
		assert.True(t, found, "public path %s has no public allow-list entry", p)
	}
}

// TestVerifyRouteAuthorization_RejectsPublicPathWithoutEntry exercises the
// standalone public path branch. With no routes and an empty allow-list, no
// other check fires, so every middleware public path must be reported on its
// own, even though no route serves it.
func TestVerifyRouteAuthorization_RejectsPublicPathWithoutEntry(t *testing.T) {
	withAllowList(t, nil)

	err := VerifyRouteAuthorization(mux.NewRouter(), "/api/v1")
	require.Error(t, err)
	public := middleware.PublicPaths()
	require.NotEmpty(t, public)
	lines := strings.Split(err.Error(), "\n")
	require.Len(t, lines, len(public)+1, err.Error())
	for _, p := range public {
		assert.Contains(t, err.Error(), "public path "+p+" has no public entry in nonDataPlaneRoutes")
	}
}

// TestVerifyRouteAuthorization_RejectsPublicPathWithGatedEntryOnly proves a
// public path is reported when its only allow-list entry is not public. The
// route is not registered, so the walk raises nothing for it.
func TestVerifyRouteAuthorization_RejectsPublicPathWithGatedEntryOnly(t *testing.T) {
	path := "/api/v1/users/login"
	require.Contains(t, middleware.PublicPaths(), path)
	withAllowList(t, []routeEntry{
		{Route: RouteInfo{Method: http.MethodPost, Path: path}, Access: RouteAccessAdmin, Gate: "test", Optional: true},
	})

	err := VerifyRouteAuthorization(mux.NewRouter(), "/api/v1")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "public path "+path+" has no public entry in nonDataPlaneRoutes")
	assert.NotContains(t, err.Error(), "POST "+path)
}

// TestVerifyRouteAuthorization_OnlyMetricsIsOptional pins that the only route
// allowed to be absent is the configuration-gated metrics endpoint.
func TestVerifyRouteAuthorization_OnlyMetricsIsOptional(t *testing.T) {
	var optional []RouteInfo
	for _, e := range nonDataPlaneRoutes {
		if e.Optional {
			optional = append(optional, e.Route)
		}
	}
	assert.Equal(t, []RouteInfo{{Method: http.MethodGet, Path: "/metrics"}}, optional)
}
