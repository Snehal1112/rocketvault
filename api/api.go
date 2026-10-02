package api

import (
	"net/http"
	"strings"

	"github.com/gorilla/mux"

	"rocketvault/app"
	"rocketvault/internal/logging"
	"rocketvault/internal/metrics"
	"rocketvault/internal/middleware"
	authzServices "rocketvault/internal/services/authorization"
)

// Routes holds all subrouters for the API — typed for compile-time safety.
type Routes struct {
	ApiRoot                 *mux.Router // /api/v1
	Vault                   *mux.Router // /api/v1/vault
	Vaults                  *mux.Router // /api/v1/vaults (vault management)
	VaultScoped             *mux.Router // /api/v1/vaults/{vault_name} (vault-scoped resources)
	RoleAssignments         *mux.Router // /api/v1/vaults/{vault_name}/role-assignments
	RoleAssignment          *mux.Router // /api/v1/vaults/{vault_name}/role-assignments/{assignment_id}
	Secrets                 *mux.Router // /api/v1/secrets
	Secret                  *mux.Router // /api/v1/secrets/{secret_id}
	Users                   *mux.Router // /api/v1/users
	User                    *mux.Router // /api/v1/users/{user_id}
	Keys                    *mux.Router // /api/v1/keys
	Key                     *mux.Router // /api/v1/keys/{key_id}
	Certificates            *mux.Router // /api/v1/certificates
	Certificate             *mux.Router // /api/v1/certificates/{certificate_id}
	Health                  *mux.Router // /api/v1/health
	Deleted                 *mux.Router // /api/v1/deleted
	AccessPolicies          *mux.Router // /api/v1/access-policies
	AccessPolicy            *mux.Router // /api/v1/access-policies/{policy_id}
	VaultProvisioningGrants *mux.Router // /api/v1/vault-provisioning-grants
	ServiceAccounts         *mux.Router // /api/v1/service-accounts
	ServiceAccount          *mux.Router // /api/v1/service-accounts/{service_account_id}
	Audit                   *mux.Router // /api/v1/audit
	OAuth2                  *mux.Router // /api/v1/oauth2 (public — no auth middleware)
	Config                  *mux.Router // /api/v1/config (public — no auth middleware)
	JWKS                    *mux.Router // /jwks.json (public — no auth middleware)
	Metrics                 *mux.Router // /metrics (public — no auth middleware; gated by monitoring.enable_metrics)
}

// API is the main API structure for the vault service.
type API struct {
	App            *app.App
	BaseRoutes     *Routes
	basePath       string
	rootRouter     *mux.Router
	Logger         *logging.Logger
	metricsEnabled bool
	cliExchange    *cliExchangeStore
}

// Init initializes the API, wires middleware, and registers all route handlers.
func Init(options ...Options) *API {
	api := &API{
		BaseRoutes: &Routes{},
	}

	for _, option := range options {
		option(api)
	}

	mw := middleware.NewMiddleware(api.App.ServiceContainer)
	// Count per-vault throttling only when /metrics is actually served —
	// registering the collector otherwise would export a metric nothing reads.
	if api.metricsEnabled {
		mw.SetVaultRateLimitMetrics(metrics.NewDefaultPrometheusVaultRateLimitMetrics())
	}
	api.Logger.WithField("basePath", api.basePath).Infoln("Api configured with")

	r := api.BaseRoutes
	r.ApiRoot = api.rootRouter.PathPrefix(api.basePath).Subrouter()
	r.ApiRoot.Use(
		mw.CORSMiddleware,
		mw.SecurityHeadersMiddleware,
		mw.RequestBodySizeLimitMiddleware,
		mw.RateLimitMiddleware,
		mw.AuthenticationMiddleware,
		mw.VaultResolutionMiddleware,
		// Must follow VaultResolutionMiddleware — the target vault is not known
		// before it. Complements the per-IP RateLimitMiddleware above: that one
		// stops a single noisy host, this stops a single noisy tenant.
		mw.VaultRateLimitMiddleware,
		mw.PolicyMiddleware,
		mw.AuthorizationMiddleware,
	)

	r.Vault = r.ApiRoot.PathPrefix("/vault").Subrouter()

	// Vault management routes use the path var {name} (not {vault_name}) so that
	// VaultResolutionMiddleware falls back to the default vault and never blocks
	// management of a disabled or soft-deleted vault. The handlers read {name}
	// themselves and do not depend on the resolved context vault.
	r.Vaults = r.ApiRoot.PathPrefix("/vaults").Subrouter()

	// Vault-scoped resource routes, e.g. /api/v1/vaults/{vault_name}/secrets.
	// The deeper {vault_name}/<resource> path never collides with the single
	// segment management routes (/vaults/{name}). VaultResolutionMiddleware reads
	// {vault_name} and resolves that vault for these routes.
	r.VaultScoped = r.Vaults.PathPrefix("/{vault_name:[a-z0-9-]+}").Subrouter()

	r.RoleAssignments = r.VaultScoped.PathPrefix("/role-assignments").Subrouter()
	r.RoleAssignment = r.RoleAssignments.PathPrefix("/{assignment_id:[A-Fa-f0-9-]+}").Subrouter()

	r.Secrets = r.ApiRoot.PathPrefix("/secrets").Subrouter()
	r.Secret = r.Secrets.PathPrefix("/{secret_id:[A-Fa-f0-9-]+}").Subrouter()

	r.Users = r.ApiRoot.PathPrefix("/users").Subrouter()
	r.User = r.Users.PathPrefix("/{user_id:[A-Fa-f0-9-]+}").Subrouter()

	r.Keys = r.ApiRoot.PathPrefix("/keys").Subrouter()
	r.Key = r.Keys.PathPrefix("/{key_id:[A-Fa-f0-9-]+}").Subrouter()

	r.Certificates = r.ApiRoot.PathPrefix("/certificates").Subrouter()
	r.Certificate = r.Certificates.PathPrefix("/{certificate_id:[A-Fa-f0-9-]+}").Subrouter()

	r.Health = r.ApiRoot.PathPrefix("/health").Subrouter()
	r.Deleted = r.ApiRoot.PathPrefix("/deleted").Subrouter()

	r.AccessPolicies = r.ApiRoot.PathPrefix("/access-policies").Subrouter()
	r.AccessPolicy = r.AccessPolicies.PathPrefix("/{policy_id:[A-Fa-f0-9-]+}").Subrouter()

	// VaultProvisioningGrants routes are not scoped to any vault -- there is
	// no vault yet when one is issued -- so this does not collide with the
	// "/vaults" prefix: "vault-" differs from "vaults" at the 6th character,
	// and resolvePolicy's "/vaults" substring match (internal/middleware/
	// middleware.go) does not match "/vault-provisioning-grants" either.
	r.VaultProvisioningGrants = r.ApiRoot.PathPrefix("/vault-provisioning-grants").Subrouter()

	r.ServiceAccounts = r.ApiRoot.PathPrefix("/service-accounts").Subrouter()
	r.ServiceAccount = r.ServiceAccounts.PathPrefix("/{service_account_id:[A-Fa-f0-9-]+}").Subrouter()

	r.Audit = r.ApiRoot.PathPrefix("/audit").Subrouter()

	// OAuth2 is public — registered on rootRouter to bypass auth middleware.
	// Rate limited because every request (success or failure) now writes an
	// audit log entry, and this endpoint is reachable without authentication.
	r.OAuth2 = api.rootRouter.PathPrefix(api.basePath).Subrouter()
	r.OAuth2.Use(mw.CORSMiddleware, mw.SecurityHeadersMiddleware, mw.RequestBodySizeLimitMiddleware, mw.RateLimitMiddleware)

	// Config is public — registered on rootRouter to bypass auth middleware.
	// Rate limited per client IP because it is reachable without authentication.
	r.Config = api.rootRouter.PathPrefix(api.basePath).Subrouter()
	r.Config.Use(mw.CORSMiddleware, mw.SecurityHeadersMiddleware, mw.RateLimitMiddleware)

	// JWKS is public — registered on rootRouter to bypass auth middleware.
	r.JWKS = api.rootRouter.NewRoute().Subrouter()
	r.JWKS.Use(mw.CORSMiddleware, mw.SecurityHeadersMiddleware)

	// Metrics is public — registered on rootRouter to bypass auth middleware,
	// matching the Prometheus convention of an unversioned /metrics path.
	r.Metrics = api.rootRouter.NewRoute().Subrouter()

	api.InitVault()
	api.InitSecrets()
	api.InitUsers()
	api.InitKeys()
	api.InitCertificates()
	api.InitHealth()
	api.InitConfig()
	api.InitDeleted()
	api.InitAccessPolicies()
	api.InitVaultProvisioningGrants()
	api.InitRoleAssignments()
	api.InitOAuth2()
	api.InitOIDC()
	api.InitJWKS()
	api.InitMetrics(api.metricsEnabled)
	api.InitBackupItem()
	api.InitAudit()

	// Catch-all 404 for unmatched routes.
	api.rootRouter.NotFoundHandler = http.HandlerFunc(Handle404)

	names := []string{"Vault", "Secrets", "Users", "Keys", "Certificates",
		"Health", "Config", "Deleted", "AccessPolicies", "VaultProvisioningGrants", "ServiceAccounts", "OAuth2", "OIDC", "JWKS", "BackupItem", "Audit"}
	api.Logger.WithField("api", strings.Join(names, ",")).Infoln("Initialized api")
	return api
}

// InitForTest wires a minimal API onto router for unit tests (no middleware, no auth).
func InitForTest(application *app.App, router *mux.Router) *API {
	a := &API{
		App:        application,
		BaseRoutes: &Routes{},
		basePath:   authzServices.DataPlaneBasePath,
		rootRouter: router,
	}
	a.BaseRoutes.ApiRoot = router.PathPrefix(authzServices.DataPlaneBasePath).Subrouter()
	// Register config handler without auth for testing.
	a.BaseRoutes.ApiRoot.Handle("/config",
		ApiHandler(application, getConfig),
	).Methods("GET")
	return a
}

// Handle404 returns a structured JSON 404 response for unmatched routes.
func Handle404(w http.ResponseWriter, r *http.Request) {
	writeJSONStatus(w, http.StatusNotFound, map[string]any{
		"id":          "api.not_found",
		"message":     "Not found",
		"status_code": http.StatusNotFound,
	})
}

// ReturnStatusOK writes a standard {"status":"OK"} response.
func ReturnStatusOK(w http.ResponseWriter) {
	writeJSON(w, map[string]string{"status": "OK"})
}
