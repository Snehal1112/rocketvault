// Package middleware provides HTTP middleware with proper separation of concerns.
// This refactored version focuses only on HTTP concerns while delegating
// authentication and authorization logic to dedicated services.
package middleware

import (
	"container/list"
	"context"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	"sync"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	"golang.org/x/time/rate"

	"rocketvault/common"
	"rocketvault/config"
	"rocketvault/internal/logging"
	auditSvc "rocketvault/internal/services/audit"
	authServices "rocketvault/internal/services/auth"
	authzServices "rocketvault/internal/services/authorization"
	vaultServices "rocketvault/internal/services/vaults"
	"rocketvault/model"
)

// ResponseWriter is a custom http.ResponseWriter that captures the status code.
// It embeds the original ResponseWriter and adds a statusCode field.
type ResponseWriter struct {
	http.ResponseWriter
	statusCode int
	log        *logging.Logger
}

// WriteHeader captures the response body and status code.
// It logs the response body and status code.
func (rw *ResponseWriter) WriteHeader(code int) {
	rw.statusCode = code
	rw.ResponseWriter.WriteHeader(code)
}

// Container defines the interface for service container dependencies.
// This allows for easier testing with mock implementations.
type Container interface {
	GetLogger() *logging.Logger
	GetAuthenticationService() authServices.AuthenticationService
	GetRBACService() authzServices.RBACService
	GetAccessPolicyService() authzServices.AccessPolicyService
	GetRoleAssignmentService() authzServices.RoleAssignmentService
	GetAuditService() auditSvc.AuditServiceInterface
	GetVaultService() vaultServices.VaultService
}

const (
	// limiterIdleTTL is how long a bucket may sit unused before it is dropped.
	// A bucket refills completely within a minute, so dropping an idle one
	// loses no rate-limit state.
	limiterIdleTTL = 2 * time.Minute
	// limiterSweepInterval bounds how often get() scans for idle buckets.
	limiterSweepInterval = time.Minute
	// defaultLimiterMaxEntries caps the map so a flood of distinct keys cannot
	// exhaust memory.
	defaultLimiterMaxEntries = 100000
)

// limiterEntry is one tracked bucket and the last time its key was seen.
type limiterEntry struct {
	key      string
	lim      *rate.Limiter
	lastSeen time.Time
}

// keyedRateLimiter manages token-bucket limiters keyed by an arbitrary string.
// The key is a client IP (IPv6 grouped by /64) for the per-IP limiters and a
// vault id for the per-vault limiter. Token buckets refill continuously, so
// steady traffic is never blocked by a fixed-window reset. The map is bounded:
// idle buckets are swept lazily and the oldest is evicted at the cap.
//
// Entries are kept in a recency list (front is most recently seen), so a
// sweep stops at the first live entry and cap eviction takes the back in
// O(1). The lock is therefore held only for the work of removing entries
// that are actually expired, never for a scan of the whole map.
//
// Known limit: once the map holds maxEntries live keys, every new key evicts
// the least recently seen one, and that key starts over with a full burst if
// it returns. A caller who can present more than maxEntries distinct keys
// within limiterIdleTTL can therefore reset a quieter client's bucket. With
// IPv6 bucketed by /64 that needs 100000 distinct IPv4 addresses or /64
// prefixes inside two minutes, so the bound trades this residual risk for
// fixed memory.
type keyedRateLimiter struct {
	mu         sync.Mutex
	entries    map[string]*list.Element
	order      *list.List // Values are *limiterEntry, most recent at the front.
	r          rate.Limit // tokens added per second
	b          int        // burst size (= configured per-minute limit)
	maxEntries int
	now        func() time.Time
	lastSweep  time.Time
}

func newKeyedRateLimiter(perMinute int64) *keyedRateLimiter {
	return newKeyedRateLimiterWith(perMinute, defaultLimiterMaxEntries, time.Now)
}

// newKeyedRateLimiterWith lets tests inject the clock and the entry cap.
// The rate.Limiter buckets keep using real time; only eviction uses now.
func newKeyedRateLimiterWith(perMinute int64, maxEntries int, now func() time.Time) *keyedRateLimiter {
	if maxEntries < 1 {
		maxEntries = 1
	}
	return &keyedRateLimiter{
		entries:    make(map[string]*list.Element),
		order:      list.New(),
		r:          rate.Every(time.Minute / time.Duration(perMinute)),
		b:          int(perMinute),
		maxEntries: maxEntries,
		now:        now,
		lastSweep:  now(),
	}
}

// get returns the limiter for the given key, creating one if it doesn't exist.
func (l *keyedRateLimiter) get(key string) *rate.Limiter {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	if now.Sub(l.lastSweep) >= limiterSweepInterval {
		l.sweepLocked(now)
	}
	if el, ok := l.entries[key]; ok {
		e := el.Value.(*limiterEntry)
		e.lastSeen = now
		l.order.MoveToFront(el)
		return e.lim
	}
	if len(l.entries) >= l.maxEntries {
		l.sweepLocked(now)
		if len(l.entries) >= l.maxEntries {
			l.evictOldestLocked()
		}
	}
	e := &limiterEntry{key: key, lim: rate.NewLimiter(l.r, l.b), lastSeen: now}
	l.entries[key] = l.order.PushFront(e)
	return e.lim
}

// sweepLocked drops every entry idle for limiterIdleTTL or longer. It walks
// from the least recently seen end and stops at the first live entry.
func (l *keyedRateLimiter) sweepLocked(now time.Time) {
	l.lastSweep = now
	for el := l.order.Back(); el != nil; el = l.order.Back() {
		e := el.Value.(*limiterEntry)
		if now.Sub(e.lastSeen) < limiterIdleTTL {
			return
		}
		l.removeLocked(el)
	}
}

// evictOldestLocked drops the least recently seen entry.
func (l *keyedRateLimiter) evictOldestLocked() {
	if el := l.order.Back(); el != nil {
		l.removeLocked(el)
	}
}

func (l *keyedRateLimiter) removeLocked(el *list.Element) {
	e := l.order.Remove(el).(*limiterEntry)
	delete(l.entries, e.key)
}

// len reports the number of tracked keys.
func (l *keyedRateLimiter) len() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.entries)
}

// Middleware provides HTTP middleware with single responsibilities.
// It delegates authentication and authorization to dedicated services,
// following the Single Responsibility Principle.
type Middleware struct {
	container      Container
	logger         *logging.Logger
	defaultLimiter *keyedRateLimiter
	authLimiter    *keyedRateLimiter
	// vaultLimiter buckets by vault id, so one tenant cannot spend another's
	// request budget. It shares the idle eviction of the per-IP maps above,
	// but its keyspace is bounded by the number of vaults anyway.
	vaultLimiter      *keyedRateLimiter
	vaultLimitMetrics VaultRateLimitRecorder
	corsOrigins       map[string]bool
	// clientIPs decides the caller's address for rate limiting, logs and
	// audit rows. A nil resolver trusts no proxy headers.
	clientIPs *ClientIPResolver
}

// NewMiddleware creates a new middleware with service dependencies.
// It uses dependency injection instead of global state access.
// Rate limiter stores are created once here and shared across requests.
// CORS allowed origins are loaded from configuration.
//
// Parameters:
//
//	container: Service container for dependency access.
//
// Returns:
//
//	A Middleware instance with injected dependencies.
func NewMiddleware(container Container) *Middleware {
	defaultLimit := viper.GetInt64("rate_limit.default")
	if defaultLimit <= 0 {
		defaultLimit = 300
	}
	authLimit := viper.GetInt64("rate_limit.auth")
	if authLimit <= 0 {
		authLimit = 5
	}
	perVaultLimit := viper.GetInt64("rate_limit.per_vault")
	if perVaultLimit <= 0 {
		perVaultLimit = defaultVaultRateLimit
	}

	// Load CORS allowed origins from configuration.
	allowed := viper.GetStringSlice("server.cors_allowed_origins")
	corsOrigins := make(map[string]bool, len(allowed))
	for _, o := range allowed {
		corsOrigins[o] = true
	}

	logger := container.GetLogger()
	trusted, err := config.LoadTrustedProxies()
	if err != nil {
		// Fail closed: with no trusted proxies the headers are simply ignored.
		if logger != nil {
			logger.WithError(err).Error("Invalid server.trusted_proxies, ignoring forwarded headers")
		}
		trusted = nil
	}
	resolver := NewClientIPResolver(trusted)
	SetClientIPResolver(resolver)

	return &Middleware{
		container:      container,
		logger:         logger,
		defaultLimiter: newKeyedRateLimiter(defaultLimit),
		authLimiter:    newKeyedRateLimiter(authLimit),
		vaultLimiter:   newKeyedRateLimiter(perVaultLimit),
		corsOrigins:    corsOrigins,
		clientIPs:      resolver,
	}
}

// clientIP resolves the caller's address through the configured resolver.
func (m *Middleware) clientIP(r *http.Request) string {
	return m.clientIPs.ClientIP(r)
}

// LoggingMiddleware logs HTTP request and response details.
// It focuses only on logging concerns without mixing other responsibilities.
func (m *Middleware) LoggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		userID, _ := r.Context().Value(common.UserIDKey).(string)

		// Create response writer to capture status code
		rw := &ResponseWriter{ResponseWriter: w, statusCode: http.StatusOK, log: m.logger}
		next.ServeHTTP(rw, r)

		// Log request details
		duration := time.Since(start)
		operation := fmt.Sprintf("%s %s", r.Method, r.URL.Path)
		status := "success"
		if rw.statusCode >= 400 {
			status = "failed"
		}

		requestID, _ := r.Context().Value(requestIDKey).(string)
		logFields := logrus.Fields{
			"method":      r.Method,
			"path":        r.URL.Path,
			"client_ip":   m.clientIP(r),
			"status_code": rw.statusCode,
			"duration_ms": duration.Milliseconds(),
			"request_id":  requestID,
		}

		logEntry := m.logger.WithAuditFields(userID, operation, status).WithFields(logFields)
		if status == "success" {
			logEntry.Info("HTTP request processed")
		} else {
			logEntry.Error("HTTP request failed")
		}
	})
}

// RateLimitMiddleware applies per-IP token-bucket rate limiting.
// Default: 300 req/min (configurable). Auth endpoints: 5 req/min.
// Token buckets refill continuously — steady traffic is never blocked
// by a fixed-window boundary the way a counter-based limiter would be.
func (m *Middleware) RateLimitMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Key on the resolved client IP without a port, so that connections
		// from the same client share the rate limit counter.
		ip := m.clientIP(r)

		// Select appropriate limiter based on endpoint.
		// Matches /users/login and /users/refresh regardless of base path prefix.
		selectedLimiter := m.defaultLimiter
		isAuthEndpoint := false
		if strings.HasSuffix(r.URL.Path, "/users/login") ||
			strings.HasSuffix(r.URL.Path, "/users/refresh") ||
			strings.HasSuffix(r.URL.Path, "/oauth2/token") {
			selectedLimiter = m.authLimiter
			isAuthEndpoint = true
		}

		lim := selectedLimiter.get(rateLimitKey(ip))
		tokens := lim.Tokens()
		w.Header().Set("X-RateLimit-Limit", fmt.Sprintf("%d", selectedLimiter.b))
		w.Header().Set("X-RateLimit-Remaining", fmt.Sprintf("%d", max(0, int(tokens))))
		// Reset approximation: when the bucket will be full again.
		w.Header().Set("X-RateLimit-Reset", fmt.Sprintf("%d", time.Now().Add(time.Minute).Unix()))

		if !lim.Allow() {
			endpoint := "default"
			if isAuthEndpoint {
				endpoint = "auth"
			}
			m.logger.LogAuditError("", "rate_limit", "failed",
				fmt.Sprintf("Rate limit exceeded for %s endpoint", endpoint), nil)
			logrus.WithFields(logrus.Fields{
				"client_ip": ip,
				"endpoint":  r.URL.Path,
				"limit":     selectedLimiter.b,
			}).Warn("Rate limit exceeded")
			http.Error(w, "Rate limit exceeded", http.StatusTooManyRequests)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// isHealthProbe reports whether path is a health probe that carries no vault.
// VaultResolutionMiddleware skips these, so anything downstream that needs a
// resolved vault must skip them too. Matching is exact, so a vault named
// "health" is resolved and rate limited like any other vault.
func isHealthProbe(path string) bool {
	_, ok := healthProbePaths[path]
	return ok
}

// publicHealthProbePaths are the health probes served without a session.
var publicHealthProbePaths = []string{
	authzServices.DataPlaneBasePath + "/health",
	authzServices.DataPlaneBasePath + "/health/ready",
	authzServices.DataPlaneBasePath + "/health/live",
}

// healthProbePaths are the health routes that carry no vault. The set adds
// /health/database to the public probes, and that probe still requires a
// session.
var healthProbePaths = pathSet(append([]string{
	authzServices.DataPlaneBasePath + "/health/database",
}, publicHealthProbePaths...))

// publicPaths are the only request paths served without a session. Matching
// is exact: suffix matching once made any vault named login, health, refresh
// or register skip authentication (B80). The set lists every public route
// under the base path. The oauth2, oidc and config routes are registered on
// routers outside the authentication chain and are listed so that the set
// stays the complete public inventory. The bootstrap guarantees the base path
// equals DataPlaneBasePath.
var publicPaths = pathSet(append([]string{
	authzServices.DataPlaneBasePath + "/users/login",
	authzServices.DataPlaneBasePath + "/users/refresh",
	authzServices.DataPlaneBasePath + "/oauth2/token",
	authzServices.DataPlaneBasePath + "/oidc/login",
	authzServices.DataPlaneBasePath + "/oidc/callback",
	authzServices.DataPlaneBasePath + "/oidc/cli/exchange",
	authzServices.DataPlaneBasePath + "/config",
}, publicHealthProbePaths...))

// pathSet builds an exact-match lookup set from paths.
func pathSet(paths []string) map[string]struct{} {
	set := make(map[string]struct{}, len(paths))
	for _, p := range paths {
		set[p] = struct{}{}
	}
	return set
}

// IsPublicPath reports whether path is served without authentication.
func IsPublicPath(path string) bool {
	_, ok := publicPaths[path]
	return ok
}

// PublicPaths returns every public path in sorted order, so the route
// authorization check can prove each one is a registered public route.
func PublicPaths() []string {
	out := make([]string, 0, len(publicPaths))
	for p := range publicPaths {
		out = append(out, p)
	}
	sort.Strings(out)
	return out
}

// AuthenticationMiddleware handles JWT token validation and user context.
// It delegates authentication logic to the AuthenticationService.
func (m *Middleware) AuthenticationMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Skip authentication for the exact public paths only.
		if IsPublicPath(r.URL.Path) {
			next.ServeHTTP(w, r)
			return
		}

		// Extract token from Authorization header
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			m.logger.LogAuditError("", "auth", "failed", "Missing Authorization header", nil)
			http.Error(w, "Unauthorized: missing token", http.StatusUnauthorized)
			return
		}

		// Validate Bearer token format
		if !strings.HasPrefix(authHeader, "Bearer ") {
			m.logger.LogAuditError("", "auth", "failed", "Invalid token format", nil)
			http.Error(w, "Unauthorized: invalid token format", http.StatusUnauthorized)
			return
		}

		tokenString := strings.TrimPrefix(authHeader, "Bearer ")

		// Validate token using authentication service
		claims, err := m.container.GetAuthenticationService().ValidateSession(r.Context(), tokenString)
		if err != nil {
			m.logger.LogAuditError("", "auth", "failed", "Token validation failed", err)
			logrus.WithError(err).Warn("Token validation failed")
			http.Error(w, "Unauthorized: invalid token", http.StatusUnauthorized)
			return
		}

		// Add user information to request context
		ctx := context.WithValue(r.Context(), common.UserIDKey, claims.UserID.String())
		ctx = context.WithValue(ctx, common.UsernameKey, claims.Username)
		ctx = context.WithValue(ctx, common.RoleKey, claims.Roles)

		if svc := m.container.GetAuditService(); svc != nil {
			_ = svc.RecordEvent(r.Context(), auditSvc.AuditEvent{
				UserID:    claims.UserID.String(),
				Action:    "auth",
				Outcome:   "success",
				Source:    "api",
				IPAddress: m.clientIP(r),
			})
		} else {
			m.logger.LogAuditInfo(claims.UserID.String(), "auth", "success", "Authentication successful")
		}
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// AuthorizationMiddleware checks if the authenticated user has permission for the endpoint.
// It delegates authorization logic to the RBACService.
func (m *Middleware) AuthorizationMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Skip authorization for the same exact public paths.
		if IsPublicPath(r.URL.Path) {
			next.ServeHTTP(w, r)
			return
		}

		// Get user roles from context (set by authentication middleware)
		roles, ok := r.Context().Value(common.RoleKey).([]string)
		if !ok {
			m.logger.LogAuditError("", "authz", "failed", "Missing role in context", nil)
			http.Error(w, "Forbidden: missing role", http.StatusForbidden)
			return
		}

		// Check endpoint access using RBAC service
		if err := m.container.GetRBACService().ValidateEndpointAccess(roles, r.Method, r.URL.Path); err != nil {
			m.logger.LogAuditError("", "authz", "failed", "Access denied", err)
			logrus.WithFields(logrus.Fields{
				"roles":  roles,
				"method": r.Method,
				"path":   r.URL.Path,
			}).Warn("Authorization failed")
			http.Error(w, "Forbidden: insufficient permissions", http.StatusForbidden)
			return
		}

		m.logger.LogAuditInfo("", "authz", "success", "Authorization successful")
		next.ServeHTTP(w, r)
	})
}

// stripVaultNameSegment removes the {name} path segment from a
// "/vaults/{name}/..." request path, leaving the "/vaults" marker and
// whatever resource segments follow the name untouched. ValidateVaultName
// (model/vault.go) has no reserved-word check, so a vault can legally be
// named "secrets", "keys", or "certificates" — without this, a request like
// "/api/v1/vaults/secrets/keys/{id}/sign" would substring-match "/secrets"
// (the vault's name) below instead of "/keys" (the actual resource), and an
// explicit deny policy targeting keys would never be evaluated for it.
// MapRouteToDataAction (internal/services/authorization/data_actions.go) is
// immune to this because it strips the whole "vaults/{name}/" prefix before
// matching; this mirrors that approach for resolvePolicy's substring match.
func stripVaultNameSegment(path string) string {
	const marker = "/vaults/"
	idx := strings.Index(path, marker)
	if idx == -1 {
		return path
	}
	rest := path[idx+len(marker):]
	slash := strings.Index(rest, "/")
	if slash == -1 {
		// "/vaults/{name}" with nothing after — no resource segment to strip.
		return path
	}
	// Drop the {name} segment; keep the "/vaults" marker and everything from
	// the following "/" onward.
	return path[:idx+len(marker)-1] + rest[slash:]
}

// lastPathSegment returns the text after the final "/" in path. A path that
// ends in "/" yields "", which matches no named sub-resource.
func lastPathSegment(path string) string {
	return path[strings.LastIndex(path, "/")+1:]
}

// resolvePolicy maps an HTTP request's method and URL path to the
// PolicyResourceType and PolicyOperation used for access-policy evaluation.
// Returns ("", "") when the route does not correspond to a managed resource.
func resolvePolicy(method, path string) (model.PolicyResourceType, model.PolicyOperation) {
	// Match resource type against the path with the vault NAME segment
	// removed (see stripVaultNameSegment), so a vault literally named
	// "secrets"/"keys"/"certificates" cannot be mistaken for the resource.
	matchPath := stripVaultNameSegment(path)

	// Determine resource type from path segments.
	var resourceType model.PolicyResourceType
	switch {
	case strings.Contains(matchPath, "/secrets"):
		resourceType = model.PolicyResourceSecrets
	case strings.Contains(matchPath, "/keys"):
		resourceType = model.PolicyResourceKeys
	case strings.Contains(matchPath, "/certificates"):
		resourceType = model.PolicyResourceCertificates
	case strings.Contains(matchPath, "/vaults"):
		// Vault management routes (resource routes are matched by the cases above,
		// since /vaults/{name}/secrets contains "/secrets").
		return model.PolicyResourceVaults, model.OpManage
	default:
		return "", ""
	}

	// Map HTTP method (and special sub-paths) to an operation. Sub-paths are
	// matched against the whole last path segment, never a suffix of it, so
	// "/unwrap" cannot resolve as "/wrap" and a vault name or ID that merely
	// ends in an operation word cannot change the operation.
	last := lastPathSegment(path)
	var op model.PolicyOperation
	switch {
	case last == "purge" && method == http.MethodDelete:
		op = model.OpPurge
	case last == "restore" && method == http.MethodPost:
		op = model.OpRecover
	case last == "rotate" && method == http.MethodPost:
		op = model.OpRotate
	case last == "import" && method == http.MethodPost:
		op = model.OpImport
	case last == "renew" && method == http.MethodPost:
		op = model.OpRenew
	// B33 and B79: every key crypto route and item backup resolves to its own
	// operation, so an explicit-deny policy naming one is evaluated over HTTP.
	// Sign, verify, wrap and unwrap match the operations the CLI checks.
	// Encrypt, decrypt and item backup have no CLI command. Export is
	// deliberately absent and stays the fail-closed create below, as does any
	// other unknown POST sub-resource. The api package walks the real router
	// to prove each named route resolves as intended.
	case last == "sign" && method == http.MethodPost:
		op = model.OpSign
	case last == "verify" && method == http.MethodPost:
		op = model.OpVerify
	case last == "encrypt" && method == http.MethodPost:
		op = model.OpEncrypt
	case last == "decrypt" && method == http.MethodPost:
		op = model.OpDecrypt
	case last == "wrap" && method == http.MethodPost:
		op = model.OpWrap
	case last == "unwrap" && method == http.MethodPost:
		op = model.OpUnwrap
	case last == "backup" && method == http.MethodPost:
		op = model.OpBackup
	case method == http.MethodGet:
		op = model.OpGet
	case method == http.MethodPost:
		op = model.OpCreate
	case method == http.MethodPut:
		op = model.OpSet
	case method == http.MethodDelete:
		op = model.OpDelete
	default:
		return resourceType, ""
	}

	return resourceType, op
}

// ResolvePolicy exposes resolvePolicy so a router walk in another package can
// prove every registered route resolves to the operation the CLI passes.
func ResolvePolicy(method, path string) (model.PolicyResourceType, model.PolicyOperation) {
	return resolvePolicy(method, path)
}

// PolicyMiddleware authorizes every request against the vault resolved by
// VaultResolutionMiddleware. It must run after AuthenticationMiddleware so that
// common.UserIDKey is set.
//
// Vault data-plane routes are DENY-BY-DEFAULT: the route maps to a single Azure
// data action, and the caller must hold a role assignment granting that action
// in that specific vault. No matching assignment is a 403. This is the P2
// inversion; before it, zero matching policy rows meant "continue".
//
// access_policies survives only as an explicit-deny override and is evaluated
// FIRST, so a deny cannot be outvoted by a role grant.
//
// Routes that are not vault data-plane routes (vault management, role
// assignments, users, audit) keep the previous AccessFallback pass-through.
// Vault-management and role-assignment routes are authorized entirely by the
// handlers themselves, via authorization.CanManageVault and
// authorization.CanManageRoleAssignments; users and audit routes are still
// gated by AuthorizationMiddleware's global role permissions.
func (m *Middleware) PolicyMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resourceType, op := resolvePolicy(r.Method, r.URL.Path)
		action, routeKind := authzServices.MapRouteToDataAction(r.Method, r.URL.Path)

		// Unmanaged by both mechanisms — health probes and the like.
		if (resourceType == "" || op == "") && routeKind == authzServices.RouteUnmanaged {
			next.ServeHTTP(w, r)
			return
		}

		// Extract caller identity set by AuthenticationMiddleware.
		userIDStr, ok := r.Context().Value(common.UserIDKey).(string)
		if !ok || userIDStr == "" {
			m.logger.LogAuditError("", "policy", "failed", "Missing user ID in context for policy check", nil)
			http.Error(w, "Forbidden: missing identity", http.StatusForbidden)
			return
		}
		principalID, err := uuid.Parse(userIDStr)
		if err != nil {
			m.logger.LogAuditError(userIDStr, "policy", "failed", "Invalid user ID format", err)
			http.Error(w, "Forbidden: invalid identity", http.StatusForbidden)
			return
		}

		// Resolve the target vault. VaultResolutionMiddleware sets this for every
		// route it covers; a legacy flat route with no value resolves to the
		// default vault so flat and vault-scoped routes carry identical semantics.
		vaultIDStr, _ := r.Context().Value(common.VaultIDKey).(string)
		if vaultIDStr == "" {
			vaultIDStr = model.DefaultVaultID
		}
		vaultID, err := uuid.Parse(vaultIDStr)
		if err != nil {
			m.logger.LogAuditError(userIDStr, "policy", "failed", "Invalid vault ID in context", err)
			http.Error(w, "Forbidden: invalid vault", http.StatusForbidden)
			return
		}

		// Use the route template for richer audit logs when available.
		routeTemplate := r.URL.Path
		if route := mux.CurrentRoute(r); route != nil {
			if tmpl, err2 := route.GetPathTemplate(); err2 == nil {
				routeTemplate = tmpl
			}
		}

		// 1. Explicit-deny override, evaluated before any allow decision.
		decision := authzServices.AccessFallback
		if resourceType != "" && op != "" {
			decision, err = m.container.GetAccessPolicyService().
				CheckAccess(r.Context(), principalID, resourceType, op, vaultID)
			if err != nil {
				m.logger.LogAuditError(userIDStr, "policy", "error",
					"Access policy check failed — denying request", err)
				http.Error(w, "Internal server error", http.StatusInternalServerError)
				return
			}
			if decision == authzServices.AccessDenied {
				m.logger.LogAuditError(userIDStr, "policy", "denied",
					fmt.Sprintf("Access denied by explicit policy: %s %s (resource=%s op=%s)",
						r.Method, routeTemplate, resourceType, op), nil)
				http.Error(w, "Forbidden: access policy denied", http.StatusForbidden)
				return
			}
		}

		// 2. Deny-by-default for vault data-plane routes.
		if routeKind == authzServices.RouteVaultData {
			if action == "" {
				// A data-plane path with no mapped action. Refusing keeps an
				// unrecognised route from becoming an unauthorized one.
				m.logger.LogAuditError(userIDStr, "policy", "denied",
					fmt.Sprintf("No data action mapped for %s %s", r.Method, routeTemplate), nil)
				http.Error(w, "Forbidden: unsupported operation", http.StatusForbidden)
				return
			}
			allowed, err := m.container.GetRoleAssignmentService().
				HasDataAction(r.Context(), principalID, vaultID, action)
			if err != nil {
				m.logger.LogAuditError(userIDStr, "policy", "error",
					"Role assignment lookup failed — denying request", err)
				http.Error(w, "Internal server error", http.StatusInternalServerError)
				return
			}
			if !allowed {
				m.logger.LogAuditError(userIDStr, "policy", "denied",
					fmt.Sprintf("Access denied: %s %s (action=%s vault=%s)",
						r.Method, routeTemplate, action, vaultID), nil)
				http.Error(w, "Forbidden: no role assignment grants this operation in this vault",
					http.StatusForbidden)
				return
			}
			m.logger.LogAuditInfo(userIDStr, "policy", "allowed",
				fmt.Sprintf("Access allowed: %s %s (action=%s vault=%s)",
					r.Method, routeTemplate, action, vaultID))
			next.ServeHTTP(w, r)
			return
		}

		// 3. Non-data-plane managed routes keep the previous semantics.
		if decision == authzServices.AccessAllowed {
			m.logger.LogAuditInfo(userIDStr, "policy", "allowed",
				fmt.Sprintf("Access allowed: %s %s (resource=%s op=%s)",
					r.Method, routeTemplate, resourceType, op))
		}
		next.ServeHTTP(w, r)
	})
}

// VaultResolutionMiddleware resolves the target vault from the request and injects
// its ID into the request context. Resolution order: the {vault_name} path
// variable, then the default vault. A missing vault yields 404; a disabled vault
// yields 403. Subdomain-based resolution is intentionally not handled here; it is
// an optional, config-gated extension added separately.
func (m *Middleware) VaultResolutionMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Skip vault resolution for health/liveness probes so they stay
		// independent of the database and the vaults table.
		if isHealthProbe(r.URL.Path) {
			next.ServeHTTP(w, r)
			return
		}

		name := model.DefaultVaultName
		if v := mux.Vars(r)["vault_name"]; v != "" {
			name = v
		}

		// The vault-purge route (DELETE /vaults/{name}/purge — distinct from
		// per-object purge routes like /deleted/secrets/{id}/purge, which
		// always contain "/deleted/") must resolve its target regardless of
		// soft-delete or enabled state: that is the entire point of purge,
		// normally invoked against an already soft-deleted vault (see
		// VaultService.PurgeVault's own findDeleted-first logic) and
		// occasionally against an active one. Every OTHER vault-scoped route
		// must keep rejecting a disabled or soft-deleted vault, so this
		// bypass is intentionally narrow to this one route shape.
		if r.Method == http.MethodDelete && strings.HasSuffix(r.URL.Path, "/purge") && !strings.Contains(r.URL.Path, "/deleted/") {
			vaultID, err := m.resolveVaultForPurge(r.Context(), name)
			if err != nil {
				m.logger.LogAuditError("", "vault_resolve", "failed", "Vault not found: "+name, err)
				http.Error(w, `{"error":"vault not found"}`, http.StatusNotFound)
				return
			}
			ctx := context.WithValue(r.Context(), common.VaultIDKey, vaultID.String())
			next.ServeHTTP(w, r.WithContext(ctx))
			return
		}

		vault, err := m.container.GetVaultService().GetVault(r.Context(), name)
		if err != nil {
			m.logger.LogAuditError("", "vault_resolve", "failed", "Vault not found: "+name, err)
			http.Error(w, `{"error":"vault not found"}`, http.StatusNotFound)
			return
		}
		if !vault.Enabled {
			m.logger.LogAuditError("", "vault_resolve", "failed", "Vault is disabled: "+name, nil)
			http.Error(w, `{"error":"vault is disabled"}`, http.StatusForbidden)
			return
		}
		ctx := context.WithValue(r.Context(), common.VaultIDKey, vault.ID.String())
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// resolveVaultForPurge finds a vault's ID by name, active or soft-deleted --
// used only by the vault-purge route (see VaultResolutionMiddleware); every
// other route must not resolve a soft-deleted vault, so this stays private
// to that one caller rather than becoming VaultService's default behavior.
func (m *Middleware) resolveVaultForPurge(ctx context.Context, name string) (uuid.UUID, error) {
	vaults, err := m.container.GetVaultService().ListVaults(ctx, true)
	if err != nil {
		return uuid.Nil, err
	}
	for _, v := range vaults {
		if v.Name == name {
			return v.ID, nil
		}
	}
	return uuid.Nil, vaultServices.ErrVaultNotFound
}

// SecurityHeadersMiddleware adds security headers to responses.
// It focuses solely on HTTP security headers.
func (m *Middleware) SecurityHeadersMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Add security headers.
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-XSS-Protection", "1; mode=block")
		w.Header().Set("Content-Security-Policy", "default-src 'self'")

		// Only send HSTS when the connection is TLS.
		if r.TLS != nil {
			w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		}

		next.ServeHTTP(w, r)
	})
}

// CORSMiddleware handles Cross-Origin Resource Sharing headers.
// It checks the request origin against a configurable allowlist.
// Only whitelisted origins receive CORS headers.
func (m *Middleware) CORSMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if origin != "" && m.corsOrigins[origin] {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
			w.Header().Set("Vary", "Origin")
		}

		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusOK)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// RequestIDMiddleware adds a unique request ID to each request.
// It focuses solely on request tracking.
// contextKey is a custom type for context keys in this package.
type contextKey string

const (
	requestIDKey contextKey = "request_id"
)

// RequestIDMiddleware adds a unique request ID to each HTTP request for tracking purposes.
func (m *Middleware) RequestIDMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestID := generateRequestID()
		w.Header().Set("X-Request-ID", requestID)

		ctx := context.WithValue(r.Context(), requestIDKey, requestID)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// generateRequestID creates a unique request identifier.
func generateRequestID() string {
	return uuid.New().String()
}

// RequestBodySizeLimitMiddleware rejects requests that exceed the allowed body size.
// Default endpoints are limited to 10 MB; import endpoints allow up to 50 MB.
func (m *Middleware) RequestBodySizeLimitMiddleware(next http.Handler) http.Handler {
	const (
		defaultLimit int64 = 10 << 20 // 10 MB.
		importLimit  int64 = 50 << 20 // 50 MB for import operations.
	)

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		limit := defaultLimit
		if strings.HasSuffix(r.URL.Path, "/import") {
			limit = importLimit
		}

		r.Body = http.MaxBytesReader(w, r.Body, limit)
		next.ServeHTTP(w, r)
	})
}

// AuthMiddleware is deprecated. Use AuthenticationMiddleware and AuthorizationMiddleware instead.
//
// Deprecated: AuthMiddleware is deprecated, use AuthenticationMiddleware and AuthorizationMiddleware instead.
func (m *Middleware) AuthMiddleware(next http.Handler) http.Handler {
	logrus.Warn("AuthMiddleware is deprecated, use AuthenticationMiddleware and AuthorizationMiddleware instead")
	return m.AuthenticationMiddleware(m.AuthorizationMiddleware(next))
}
