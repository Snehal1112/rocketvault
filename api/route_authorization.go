package api

import (
	"fmt"
	"net/http"
	"sort"
	"strings"

	"github.com/gorilla/mux"

	"rocketvault/internal/middleware"
	authzServices "rocketvault/internal/services/authorization"
)

// RouteAccess names the gate that authorizes a route that is not a vault
// data-plane route. PolicyMiddleware passes such routes through, so each one
// must be listed in nonDataPlaneRoutes with the gate that protects it.
type RouteAccess string

const (
	// RouteAccessPublic is served without a session.
	RouteAccessPublic RouteAccess = "public"
	// RouteAccessAnySession needs a session and nothing more. The handler
	// confines the caller to its own records or to non-sensitive data.
	RouteAccessAnySession RouteAccess = "any-session"
	// RouteAccessAdmin needs a session, and the global admin role is
	// required, by the handler or by the RBAC users:* permissions that
	// AuthorizationMiddleware and ApiSessionRequired enforce.
	RouteAccessAdmin RouteAccess = "admin"
	// RouteAccessVaultManagement needs a session, and the handler calls
	// CanCreateVault, CanManageVault or CanManageRoleAssignments.
	RouteAccessVaultManagement RouteAccess = "vault-management"
)

// knownRouteAccess is every valid RouteAccess value.
var knownRouteAccess = map[RouteAccess]bool{
	RouteAccessPublic:          true,
	RouteAccessAnySession:      true,
	RouteAccessAdmin:           true,
	RouteAccessVaultManagement: true,
}

// routeEntry records how one non-data-plane route is authorized.
type routeEntry struct {
	Route  RouteInfo
	Access RouteAccess
	// Gate names the function that enforces the decision, for reviewers.
	Gate string
	// Optional marks a route that is registered only under some
	// configuration, such as /metrics.
	Optional bool
}

// Path templates shared by several entries below.
const (
	accessPolicyPath   = "/api/v1/access-policies/{policy_id:[A-Fa-f0-9-]+}"
	serviceAccountPath = "/api/v1/service-accounts/{service_account_id:[A-Fa-f0-9-]+}"
	userPath           = "/api/v1/users/{user_id:[A-Fa-f0-9-]+}"
	grantPath          = "/api/v1/vault-provisioning-grants/{principal_id}"
	vaultPath          = "/api/v1/vaults/{name}"
	roleAssignmentPath = "/api/v1/vaults/{vault_name:[a-z0-9-]+}/role-assignments"
	usersRBACGate      = "AuthorizationMiddleware users:* permission (admin role only)"
)

// nonDataPlaneRoutes is the allow-list of every registered route that is not a
// vault data-plane route. A route that is neither a mapped data-plane route
// nor listed here fails VerifyRouteAuthorization, at test time and at
// startup, so a new handler that forgets its own check cannot ship silently.
// It is a slice, not a map, so that a duplicate entry is detected rather than
// silently overwritten.
var nonDataPlaneRoutes = []routeEntry{
	// Access policies are managed by the global admin only.
	{Route: RouteInfo{http.MethodGet, "/api/v1/access-policies"}, Access: RouteAccessAdmin, Gate: "requireAccessPolicyAdmin"},
	{Route: RouteInfo{http.MethodPost, "/api/v1/access-policies"}, Access: RouteAccessAdmin, Gate: "requireAccessPolicyAdmin"},
	{Route: RouteInfo{http.MethodGet, "/api/v1/access-policies/principal/{principal_id:[A-Fa-f0-9-]+}"}, Access: RouteAccessAdmin, Gate: "requireAccessPolicyAdmin"},
	{Route: RouteInfo{http.MethodDelete, accessPolicyPath}, Access: RouteAccessAdmin, Gate: "requireAccessPolicyAdmin"},
	{Route: RouteInfo{http.MethodGet, accessPolicyPath}, Access: RouteAccessAdmin, Gate: "requireAccessPolicyAdmin"},
	{Route: RouteInfo{http.MethodPut, accessPolicyPath}, Access: RouteAccessAdmin, Gate: "requireAccessPolicyAdmin"},

	// Audit logs, reports and configuration check the admin role in the handler.
	{Route: RouteInfo{http.MethodGet, "/api/v1/audit/config"}, Access: RouteAccessAdmin, Gate: "getAuditConfig admin check"},
	{Route: RouteInfo{http.MethodPatch, "/api/v1/audit/config"}, Access: RouteAccessAdmin, Gate: "patchAuditConfig admin check"},
	{Route: RouteInfo{http.MethodGet, "/api/v1/audit/logs"}, Access: RouteAccessAdmin, Gate: "getAuditLogs admin check"},
	{Route: RouteInfo{http.MethodGet, "/api/v1/audit/reports/gdpr"}, Access: RouteAccessAdmin, Gate: "getGDPRReport admin check"},
	{Route: RouteInfo{http.MethodGet, "/api/v1/audit/reports/soc2"}, Access: RouteAccessAdmin, Gate: "getSOC2Report admin check"},

	// Frontend configuration is public and rate limited per client IP.
	{Route: RouteInfo{http.MethodGet, "/api/v1/config"}, Access: RouteAccessPublic, Gate: "Config router, no authentication chain"},

	// Health probes are public; the database probe needs a session. B97
	// tracks the driver error text the database probe returns.
	{Route: RouteInfo{http.MethodGet, "/api/v1/health"}, Access: RouteAccessPublic, Gate: "middleware.IsPublicPath"},
	{Route: RouteInfo{http.MethodGet, "/api/v1/health/live"}, Access: RouteAccessPublic, Gate: "middleware.IsPublicPath"},
	{Route: RouteInfo{http.MethodGet, "/api/v1/health/ready"}, Access: RouteAccessPublic, Gate: "middleware.IsPublicPath"},
	{Route: RouteInfo{http.MethodGet, "/api/v1/health/database"}, Access: RouteAccessAnySession, Gate: "AuthenticationMiddleware, no handler check"},

	// Signing keys are public; rotating them is admin only.
	{Route: RouteInfo{http.MethodPost, "/api/v1/jwks/rotate"}, Access: RouteAccessAdmin, Gate: "rotateJWKS admin check"},
	{Route: RouteInfo{http.MethodGet, "/jwks.json"}, Access: RouteAccessPublic, Gate: "JWKS router, public signing keys"},
	{Route: RouteInfo{http.MethodGet, "/metrics"}, Access: RouteAccessPublic, Gate: "monitoring.enable_metrics", Optional: true},

	// Token issuance and OIDC login authenticate the caller themselves.
	{Route: RouteInfo{http.MethodPost, "/api/v1/oauth2/token"}, Access: RouteAccessPublic, Gate: "tokenHandler client credentials"},
	{Route: RouteInfo{http.MethodGet, "/api/v1/oidc/callback"}, Access: RouteAccessPublic, Gate: "oidcCallbackHandler state and nonce"},
	{Route: RouteInfo{http.MethodPost, "/api/v1/oidc/cli/exchange"}, Access: RouteAccessPublic, Gate: "cliExchangeHandler one-time exchange code"},
	{Route: RouteInfo{http.MethodGet, "/api/v1/oidc/login"}, Access: RouteAccessPublic, Gate: "oidcLoginHandler redirect to the provider"},

	// Service accounts check the admin role in the handler.
	{Route: RouteInfo{http.MethodGet, "/api/v1/service-accounts"}, Access: RouteAccessAdmin, Gate: "listServiceAccounts admin check"},
	{Route: RouteInfo{http.MethodPost, "/api/v1/service-accounts"}, Access: RouteAccessAdmin, Gate: "createServiceAccount admin check"},
	{Route: RouteInfo{http.MethodDelete, serviceAccountPath}, Access: RouteAccessAdmin, Gate: "deleteServiceAccount admin check"},
	{Route: RouteInfo{http.MethodGet, serviceAccountPath}, Access: RouteAccessAdmin, Gate: "getServiceAccount admin check"},
	{Route: RouteInfo{http.MethodPost, serviceAccountPath + "/rotate"}, Access: RouteAccessAdmin, Gate: "rotateServiceAccountSecret admin check"},

	// Login and refresh are public. Every other /users route needs a users:*
	// RBAC permission, which only the admin role holds. The session and
	// profile handlers also confine a caller to its own records, but the
	// RBAC gate runs first and refuses every non-admin. B96 tracks opening
	// those routes to their owners.
	{Route: RouteInfo{http.MethodPost, "/api/v1/users/login"}, Access: RouteAccessPublic, Gate: "middleware.IsPublicPath"},
	{Route: RouteInfo{http.MethodPost, "/api/v1/users/refresh"}, Access: RouteAccessPublic, Gate: "middleware.IsPublicPath"},
	{Route: RouteInfo{http.MethodGet, "/api/v1/users"}, Access: RouteAccessAdmin, Gate: "listUsers admin check and " + usersRBACGate},
	{Route: RouteInfo{http.MethodPost, "/api/v1/users"}, Access: RouteAccessAdmin, Gate: "createUser admin check and " + usersRBACGate},
	{Route: RouteInfo{http.MethodDelete, userPath}, Access: RouteAccessAdmin, Gate: "deleteUser admin check and " + usersRBACGate},
	{Route: RouteInfo{http.MethodGet, userPath}, Access: RouteAccessAdmin, Gate: usersRBACGate + "; getUser also allows the profile owner"},
	{Route: RouteInfo{http.MethodPut, userPath}, Access: RouteAccessAdmin, Gate: usersRBACGate + "; updateUser also allows the profile owner"},
	{Route: RouteInfo{http.MethodDelete, "/api/v1/users/sessions"}, Access: RouteAccessAdmin, Gate: usersRBACGate + "; revokeAllSessions scopes to the caller"},
	{Route: RouteInfo{http.MethodGet, "/api/v1/users/sessions"}, Access: RouteAccessAdmin, Gate: usersRBACGate + "; listUserSessions scopes to the caller"},
	{Route: RouteInfo{http.MethodDelete, "/api/v1/users/sessions/{session_id:[A-Fa-f0-9-]+}"}, Access: RouteAccessAdmin, Gate: usersRBACGate + "; revokeSession scopes to the caller"},

	// Provisioning grants are admin only and deliberately non-delegable.
	{Route: RouteInfo{http.MethodGet, "/api/v1/vault-provisioning-grants"}, Access: RouteAccessAdmin, Gate: "requireGrantAdmin"},
	{Route: RouteInfo{http.MethodDelete, grantPath}, Access: RouteAccessAdmin, Gate: "requireGrantAdmin"},
	{Route: RouteInfo{http.MethodPut, grantPath}, Access: RouteAccessAdmin, Gate: "requireGrantAdmin"},

	// Vault management checks the caller's right over the named vault.
	{Route: RouteInfo{http.MethodGet, "/api/v1/vaults"}, Access: RouteAccessVaultManagement, Gate: "listVaults scopes by CanManageVault"},
	{Route: RouteInfo{http.MethodPost, "/api/v1/vaults"}, Access: RouteAccessVaultManagement, Gate: "CanCreateVault"},
	{Route: RouteInfo{http.MethodDelete, vaultPath}, Access: RouteAccessVaultManagement, Gate: "CanManageVault"},
	{Route: RouteInfo{http.MethodGet, vaultPath}, Access: RouteAccessVaultManagement, Gate: "CanManageVault"},
	{Route: RouteInfo{http.MethodPatch, vaultPath}, Access: RouteAccessVaultManagement, Gate: "CanManageVault"},
	{Route: RouteInfo{http.MethodDelete, vaultPath + "/webhook"}, Access: RouteAccessVaultManagement, Gate: "resolveAndAuthorizeVault (CanManageVault)"},
	{Route: RouteInfo{http.MethodGet, vaultPath + "/webhook"}, Access: RouteAccessVaultManagement, Gate: "resolveAndAuthorizeVault (CanManageVault)"},
	{Route: RouteInfo{http.MethodPut, vaultPath + "/webhook"}, Access: RouteAccessVaultManagement, Gate: "resolveAndAuthorizeVault (CanManageVault)"},

	// Role assignments check CanManageRoleAssignments in the handler.
	{Route: RouteInfo{http.MethodGet, roleAssignmentPath}, Access: RouteAccessVaultManagement, Gate: "CanManageRoleAssignments"},
	{Route: RouteInfo{http.MethodPost, roleAssignmentPath}, Access: RouteAccessVaultManagement, Gate: "CanManageRoleAssignments"},
	{Route: RouteInfo{http.MethodDelete, roleAssignmentPath + "/{assignment_id:[A-Fa-f0-9-]+}"}, Access: RouteAccessVaultManagement, Gate: "CanManageRoleAssignments"},
	{Route: RouteInfo{http.MethodGet, roleAssignmentPath + "/{assignment_id:[A-Fa-f0-9-]+}"}, Access: RouteAccessVaultManagement, Gate: "CanManageRoleAssignments"},
}

// VerifyRouteAuthorization checks that every route registered on router is
// authorized by construction: a vault data-plane route must map to a data
// action and run behind the authentication chain, and every other route must
// be on nonDataPlaneRoutes with an access class that matches whether the
// route skips authentication. It also refuses a base path the authorization
// layer does not strip, a leaf route registered without methods or without a
// path template, a stale, duplicate or malformed allow-list entry, and any
// disagreement with the middleware's public-path set. The error lists every
// problem in sorted order.
func VerifyRouteAuthorization(router *mux.Router, basePath string) error {
	if basePath != authzServices.DataPlaneBasePath {
		return fmt.Errorf("api base path %q does not match the data-plane base path %q",
			basePath, authzServices.DataPlaneBasePath)
	}

	var problems []string
	entries := make(map[RouteInfo]routeEntry, len(nonDataPlaneRoutes))
	for _, e := range nonDataPlaneRoutes {
		name := e.Route.Method + " " + e.Route.Path
		if _, dup := entries[e.Route]; dup {
			problems = append(problems, name+" is on the allow-list more than once")
			continue
		}
		entries[e.Route] = e
		if !knownRouteAccess[e.Access] {
			problems = append(problems, fmt.Sprintf("%s has unknown access class %q", name, e.Access))
		}
		if strings.TrimSpace(e.Gate) == "" {
			problems = append(problems, name+" names no gate")
		}
	}

	seen := make(map[RouteInfo]bool)
	err := router.Walk(func(route *mux.Route, _ *mux.Router, _ []*mux.Route) error {
		// A subrouter prefix has no handler and serves nothing itself.
		if route.GetHandler() == nil {
			return nil
		}
		tmpl, err := route.GetPathTemplate()
		if err != nil {
			problems = append(problems, "a route has a handler but no path template")
			return nil
		}
		methods, err := route.GetMethods()
		if err != nil || len(methods) == 0 {
			// WalkRoutes skips such a route, so it would escape every
			// inventory check.
			problems = append(problems, tmpl+" has a handler but no .Methods(...)")
			return nil
		}
		public := skipsAuthentication(tmpl, basePath)
		for _, method := range methods {
			info := RouteInfo{Method: method, Path: tmpl}
			name := method + " " + tmpl
			seen[info] = true
			action, kind := authzServices.MapRouteToDataAction(method, tmpl)
			entry, listed := entries[info]
			switch {
			case kind == authzServices.RouteVaultData && listed:
				problems = append(problems, name+" is a data-plane route and must not be on the allow-list")
			case kind == authzServices.RouteVaultData && action == "":
				problems = append(problems, name+" is a data-plane route with no data action")
			case kind == authzServices.RouteVaultData && public:
				problems = append(problems, name+" is a data-plane route that skips authentication")
			case kind != authzServices.RouteVaultData && !listed:
				problems = append(problems, name+" is not a data-plane route and has no entry in nonDataPlaneRoutes")
			case entry.Access == RouteAccessPublic && !public:
				problems = append(problems, name+" is listed as public but requires a session")
			case entry.Access != RouteAccessPublic && public && listed:
				problems = append(problems, name+" skips authentication but is not listed as public")
			}
		}
		return nil
	})
	if err != nil {
		return fmt.Errorf("walk routes: %w", err)
	}

	for _, e := range nonDataPlaneRoutes {
		if !seen[e.Route] && !e.Optional {
			problems = append(problems, fmt.Sprintf("%s %s is on the allow-list but is not registered", e.Route.Method, e.Route.Path))
		}
	}
	for _, p := range middleware.PublicPaths() {
		if !isListedPublic(p) {
			problems = append(problems, fmt.Sprintf("public path %s has no public entry in nonDataPlaneRoutes", p))
		}
	}

	if len(problems) > 0 {
		sort.Strings(problems)
		return fmt.Errorf("route authorization check failed:\n  %s", strings.Join(problems, "\n  "))
	}
	return nil
}

// skipsAuthentication reports whether a route with path template tmpl is
// served without a session. Only the base path router carries the
// authentication chain, and on it only the exact public paths skip it.
func skipsAuthentication(tmpl, basePath string) bool {
	if !strings.HasPrefix(tmpl, basePath+"/") {
		return true
	}
	return middleware.IsPublicPath(tmpl)
}

// isListedPublic reports whether path has a public entry for any method.
func isListedPublic(path string) bool {
	for _, e := range nonDataPlaneRoutes {
		if e.Route.Path == path && e.Access == RouteAccessPublic {
			return true
		}
	}
	return false
}
