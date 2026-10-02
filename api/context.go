package api

import (
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"

	"rocketvault/app"
	"rocketvault/common"
	"rocketvault/internal/container"
	"rocketvault/internal/logging"
	"rocketvault/internal/middleware"
	"rocketvault/internal/retry"
	authServices "rocketvault/internal/services/auth"
	certServices "rocketvault/internal/services/certificates"
	keyServices "rocketvault/internal/services/keys"
	secretServices "rocketvault/internal/services/secrets"
	userServices "rocketvault/internal/services/users"
	"rocketvault/model"
)

// serviceUnavailableRetryAfterSeconds is the Retry-After hint sent when a
// request fails because a retry.RetryService circuit breaker is open or its
// retry budget was exhausted. Deliberately shorter than any shipped
// retry.circuit_breaker.timeout (default 60s, commonly tuned to 30s): the
// breaker may close again well before its own timeout via a successful
// half-open trial from another request, and a short, fixed hint keeps a
// well-behaved client from either hammering immediately or waiting far
// longer than necessary.
const serviceUnavailableRetryAfterSeconds = 5

// RequestClaims holds the identity claims ApiSessionRequired attaches to an
// authenticated request. It is a value type (not a pointer) so a Context left
// at its zero value — as ApiHandler leaves it for public routes — still
// yields safe, empty field reads rather than a nil-pointer panic.
type RequestClaims struct {
	UserID string
	Roles  []string
}

// Context holds request-scoped data for every API handler.
type Context struct {
	App            *app.App
	T              common.TranslateFunc
	Err            *common.AppError
	RequestID      string
	IPAddress      string
	Token          string
	Claims         RequestClaims
	Path           string
	UserAgent      string
	AcceptLanguage string
	Params         *ApiParams
	Logger         *logging.Logger
}

// vaultIDFromRequest returns the vault id resolved by VaultResolutionMiddleware
// and stored in the request context. When the value is absent or empty (for
// example in unit tests that bypass the middleware), it falls back to the
// well-known default vault id so legacy flat routes keep working.
func vaultIDFromRequest(r *http.Request) (uuid.UUID, error) {
	s, _ := r.Context().Value(common.VaultIDKey).(string)
	if s == "" {
		s = model.DefaultVaultID
	}
	return uuid.Parse(s)
}

// scopeFromRequest builds the authorization scope for a resource operation. It
// is the only scope constructor on the data plane: ownership is provenance and
// audit metadata, never an access predicate. Crypto operations are gated by the
// Key Vault Crypto User role at vault scope, not by who created the key.
//
// Every route shape yields a vault scope. Vault-scoped routes
// (/api/v1/vaults/{vault_name}/...) carry the vault resolved from the path;
// legacy flat routes carry the default vault, which is the same vault
// PolicyMiddleware authorized the request against, because
// VaultResolutionMiddleware resolves model.DefaultVaultName for any route with
// no vault_name variable.
//
// Flat routes used to yield an owner scope, whose SQL predicate is "user_id = ?"
// with no vault term (internal/repositories/scope_predicate.go). That let a
// caller authorized against the default vault read and write their own
// resources in any other vault, surviving revocation of their role assignment
// there. See docs/superpowers/specs/2026-08-16-flat-route-vault-scope-fix-design.md.
//
// It sets c.Err and returns false when the caller's identity cannot be
// determined, so a handler can never proceed with an invalid scope.
func scopeFromRequest(c *Context, r *http.Request) (model.Scope, bool) {
	userID, ok := userIDFromClaims(c)
	if !ok {
		return model.Scope{}, false
	}

	vaultID, err := vaultIDFromRequest(r)
	if err != nil {
		c.SetInvalidParam("vault")
		return model.Scope{}, false
	}

	return model.NewVaultScope(vaultID, userID), true
}

// SetInvalidParam sets a 400 error for a missing or malformed parameter.
func (c *Context) SetInvalidParam(parameter string) {
	c.Err = common.NewAppError("api.context.set_invalid_param",
		"Invalid or missing parameter: "+parameter, nil, "", http.StatusBadRequest)
}

// SetPermissionError sets a 403 error for insufficient permissions.
func (c *Context) SetPermissionError(permission string) {
	c.Err = common.NewAppError("api.context.set_permission_error",
		"Insufficient permissions: "+permission, nil, "", http.StatusForbidden)
}

// SetConflict sets a 409 error for a request that collides with existing state.
func (c *Context) SetConflict(message string) {
	c.Err = common.NewAppError("api.context.set_conflict", message, nil, "", http.StatusConflict)
}

// SetNotFound sets a 404 error for a missing resource.
func (c *Context) SetNotFound(resource string) {
	c.Err = common.NewAppError("api.context.set_not_found",
		resource+" not found", nil, "", http.StatusNotFound)
}

// internalErrorDetail is the only detail a generic 500 sends to a client.
const internalErrorDetail = "An internal error occurred. Quote the request_id when contacting support."

// logInternalError records the real error server-side with the request id.
// It tolerates a nil logger, which public handlers in tests can carry.
func (c *Context) logInternalError(err error) {
	base := logrus.StandardLogger()
	if c.Logger != nil && c.Logger.Logger != nil {
		base = c.Logger.Logger
	}
	base.WithFields(logrus.Fields{
		"request_id": c.RequestID,
		"path":       c.Path,
		"error":      fmt.Sprint(err),
	}).Error("Internal server error")
}

// SetInternalError sets a 500 error for unexpected failures — or a 503 with
// a Retry-After hint when err is a retry.RetryService circuit-breaker-open or
// retry-budget-exhausted error. That distinction matters beyond the status
// code: retry.WithExponentialBackoff wraps both with %w specifically so the
// caller's own sentinel survives errors.Is, but this switch runs first and
// intentionally does not unwrap further — the detail string stays a fixed,
// generic message rather than err.Error(), which could otherwise serialize a
// wrapped driver error (e.g. a raw SQL error string) into the response body,
// the same information-disclosure class as known-bugs.md's B24/B25/B55.
// A plain 500 also always carries the fixed internalErrorDetail, and the real
// error is logged server-side keyed by the request id.
func (c *Context) SetInternalError(err error) {
	if err != nil && (errors.Is(err, retry.ErrCircuitBreakerOpen) || errors.Is(err, retry.ErrMaxRetriesExceeded)) {
		c.Err = common.NewAppError("api.context.set_service_unavailable",
			"Service temporarily unavailable, please retry", nil, "", http.StatusServiceUnavailable)
		c.Err.RetryAfterSeconds = serviceUnavailableRetryAfterSeconds
		return
	}

	c.logInternalError(err)
	c.Err = common.NewAppError("api.context.set_internal_error", "Internal server error", nil,
		internalErrorDetail, http.StatusInternalServerError)
}

// ApiHandler wraps public (unauthenticated) handlers.
func ApiHandler(app *app.App, handler func(*Context, http.ResponseWriter, *http.Request)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		ctx := &Context{
			App:            app,
			Params:         ApiParamsFromRequest(r),
			RequestID:      "req-" + uuid.New().String()[:8],
			IPAddress:      middleware.ExtractClientIP(r),
			Path:           r.URL.Path,
			UserAgent:      r.UserAgent(),
			AcceptLanguage: r.Header.Get("Accept-Language"),
			Logger:         app.Logger,
		}

		if ctx.Logger != nil {
			ctx.Logger.Printf("Handling %s %s", r.Method, r.URL.Path)
		}

		handler(ctx, w, r)

		if ctx.Logger != nil {
			ctx.Logger.Printf("Completed %s %s in %dms", r.Method, r.URL.Path, time.Since(start).Milliseconds())
		}

		if ctx.Err != nil {
			writeError(w, ctx)
		}
	}
}

// SessionRequired is an alias for ApiSessionRequired for backward compatibility.
var SessionRequired = ApiSessionRequired

// ApiSessionRequired wraps handlers that require an authenticated session.
func ApiSessionRequired(a *app.App, handler func(*Context, http.ResponseWriter, *http.Request)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		userIDStr, ok := r.Context().Value(common.UserIDKey).(string)
		if !ok || userIDStr == "" {
			writeJSONStatus(w, http.StatusUnauthorized, map[string]any{
				"id":          "api.context.session_required",
				"message":     "Unauthorized: missing session",
				"status_code": http.StatusUnauthorized,
			})
			return
		}

		roles, _ := r.Context().Value(common.RoleKey).([]string)

		if a.ServiceContainer != nil {
			if err := a.ServiceContainer.GetRBACService().ValidateEndpointAccess(roles, r.Method, r.URL.Path); err != nil {
				writeJSONStatus(w, http.StatusForbidden, map[string]any{
					"id":          "api.context.permissions",
					"message":     "Access denied",
					"status_code": http.StatusForbidden,
				})
				return
			}
		}

		ctx := &Context{
			App: a,
			Claims: RequestClaims{
				UserID: userIDStr,
				Roles:  roles,
			},
			Params:         ApiParamsFromRequest(r),
			RequestID:      "req-" + uuid.New().String()[:8],
			IPAddress:      middleware.ExtractClientIP(r),
			Path:           r.URL.Path,
			UserAgent:      r.UserAgent(),
			AcceptLanguage: r.Header.Get("Accept-Language"),
			Logger:         a.Logger,
		}

		setNoStore(w)

		if ctx.Logger != nil {
			ctx.Logger.Printf("Handling %s %s (user: %s)", r.Method, r.URL.Path, userIDStr)
		}

		handler(ctx, w, r)

		if ctx.Logger != nil {
			ctx.Logger.Printf("Completed %s %s in %dms", r.Method, r.URL.Path, time.Since(start).Milliseconds())
		}

		if ctx.Err != nil {
			writeError(w, ctx)
		}
	}
}

// writeError writes a structured JSON error response with request_id.
func writeError(w http.ResponseWriter, c *Context) {
	body := map[string]any{
		"id":             c.Err.ID,
		"message":        c.Err.Message,
		"detailed_error": c.Err.DetailedError,
		"status_code":    c.Err.StatusCode,
		"request_id":     c.RequestID,
	}

	// Retry-After must be set before writeJSONStatus's WriteHeader call
	// commits the header map (see writeJSONStatus's own comment on this).
	if c.Err.RetryAfterSeconds > 0 {
		w.Header().Set("Retry-After", strconv.Itoa(c.Err.RetryAfterSeconds))
		body["retry_after_seconds"] = c.Err.RetryAfterSeconds
	}

	writeJSONStatus(w, c.Err.StatusCode, body)
}

// svc resolves a service from the request's container.
//
// It replaces six accessors that were each the same six lines, and it changes
// the call shape from a nil comparison to a checked ok. That matters: a nil
// comparison is easy to omit and compiles fine when omitted, whereas ignoring
// the second return here leaves the caller with a zero value it must still
// reason about.
//
// The failure behavior matches the accessors it replaces: a nil App or
// container sets a 500 with no detail and returns false, and so does a
// getter that itself returns a nil service. The nil-service check is
// `any(resolved) == nil`, which only catches a genuinely nil interface
// value; a non-nil interface wrapping a nil concrete pointer would still
// pass through as ok. That gap is acceptable here because the container
// stores interface values directly, never typed nil pointers.
func svc[T any](c *Context, get func(container.ServiceContainerInterface) T) (T, bool) {
	var zero T
	if c.App == nil || c.App.ServiceContainer == nil {
		c.SetInternalError(nil)
		return zero, false
	}
	resolved := get(c.App.ServiceContainer)
	if any(resolved) == nil {
		c.SetInternalError(nil)
		return zero, false
	}
	return resolved, true
}

// The five accessors below are kept as one-line delegations to svc rather
// than deleted outright: context_accessors_test.go calls them directly, and
// the plan for this refactor forbids editing test files. cryptoSvc had no
// such test and was removed outright; every production call site for all six
// now goes through svc directly.

func (c *Context) secretSvc() secretServices.SecretService {
	v, _ := svc(c, container.ServiceContainerInterface.GetSecretService)
	return v
}

func (c *Context) keySvc() keyServices.KeyService {
	v, _ := svc(c, container.ServiceContainerInterface.GetKeyService)
	return v
}

func (c *Context) userSvc() userServices.UserService {
	v, _ := svc(c, container.ServiceContainerInterface.GetUserService)
	return v
}

func (c *Context) certSvc() certServices.CertificateService {
	v, _ := svc(c, container.ServiceContainerInterface.GetCertificateService)
	return v
}

func (c *Context) authSvc() authServices.AuthenticationService {
	v, _ := svc(c, container.ServiceContainerInterface.GetAuthenticationService)
	return v
}
