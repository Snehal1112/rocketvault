# Secrets and Error Responses Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (- [ ]) syntax for tracking.

**Goal:** Stop generic 500 responses leaking internal error text, make disabled or expired secrets unreadable through export and version reads, and make secret import enforce the same validation as create.

**Architecture:** `SetInternalError` logs the real error server-side keyed by request id and emits a fixed `detailed_error`; the three resource error mappers gain a 409 arm for `repositories.ErrNameTaken` and a 400 arm for content-type validation. Lifecycle enforcement (`IsAccessible()`) moves into the service layer for export and version reads, and `ImportSecrets` runs `ValidateSecretCreate` per item. The HTTP and CLI import paths both call `ImportSecrets`, so one service fix covers both.

**Tech Stack:** Go 1.24, Gorilla Mux, testify, ozzo-validation, SQLite in-memory fixtures for service round trips.

**Spec:**
- GitHub issue #41 (generic 500 leaks `err.Error()`), tracked as **B82**; also closes **B55** (duplicate name returns 500).
- GitHub issue #44 (export and version reads bypass enabled/expiry), tracked as **B83**.
- GitHub issue #48 (import skips create-time validation), tracked as **B84**.
- Audit: static audit of `api/` on 2026-09-30 (quoted in the three issues).
- Existing design notes: `.claude/known-bugs.md` B55 (fix recipe), B24/B25 (PKCS#11 leak precedent), B30 (version plaintext precedent).

**Priority:** P2. **B-number range:** B82-B84.

## Global Constraints

- Commits: invoke the `dev-workflow-skills:1-git-commit` plugin skill via the Skill tool. Never use a freeform `git commit -m`. All commits and tags are GPG signed (key 61D246B30285ED35).
- Code comments are short full sentences ending with a punctuation mark.
- Before any PR: `go build ./...`, `go vet ./...` and `go test ./...` must pass. golangci-lint currently fails locally (snap Go toolchain incompatibility), so lint must run in CI or on a fixed toolchain.
- CLI commands call the service layer directly and bypass HTTP middleware, so every behavior change is tested on the HTTP path and the CLI path (`cmd/secrets`).
- Repositories are pure CRUD; lifecycle and validation logic lives in services (service-layer-conventions).
- No schema change is needed; no `internal/db/db.go` edit.
- Fixed `detailed_error` text for every generic 500 is exactly: `An internal error occurred. Quote the request_id when contacting support.`
- Each fixed issue gets a `.claude/known-bugs.md` entry (structure of B69) and its commit carries a `Fixes #N` footer (#41, #44, #48).
- Documentation goes under `.claude/` or `docs/`, never new top-level files.
- Service tests in package `secrets` (internal) cannot import `internal/testutils` (import cycle); use the local mocks `MockSecretRepository`, `MockSecretVersionRepository`, `fakeCrypto`, `newTestLogger`. The external package `secrets_test` uses `newImportFixture` (real SQLite + real crypto) from `internal/services/secrets/import_overwrite_roundtrip_test.go`.

## Review Focus

1. A secret that is disabled, expired or not-yet-active must not appear in any export format (json, csv, sealed). Pinned in Task 7.
2. `GetVersion`, `GetLatestVersion` and `GetVersions` must refuse a disabled parent while `GetVersionsMetadata` (no plaintext) stays allowed. Pinned in Task 6.
3. A PUT that only sets `enabled=true` on a disabled secret must succeed (200), and an identical-value PUT must not return a 400 that reveals equality. Pinned in Task 8.
4. Import items with a bad name, an oversized value (25601 bytes) or 16 tags must fail per item while valid siblings still import, on both JSON and CSV. Pinned in Task 9; CLI surfacing pinned in Task 10.
5. CSV cells starting with `=`, `+`, `-`, `@`, tab or `'` must export guarded and re-import to the exact original value. Pinned in Task 11.
6. A duplicate name must give 409 with no `UNIQUE constraint` text for secrets, keys and certificates. Pinned in Task 2.
7. Nil `Context.Logger` (public handlers in tests) must not panic inside `SetInternalError`. Pinned in Task 1.

---

## Issue #41 (B82, closes B55): generic 500 responses leak internal errors

### Task 1: SetInternalError logs server-side and sends a fixed detail

**Files:**
- Modify: `api/context.go:141-146` (SetInternalError body; current `detail = err.Error()` at 141-146 region, function starts line 133)
- Modify: `api/context_test.go:369-385` (control test currently asserts the leak)
- Test: `api/context_test.go` (package `api_test`, uses `api.ApiHandler`)

**Interfaces:**
- Consumes: `Context.RequestID string`, `Context.Logger *logging.Logger` (embeds `*logrus.Logger`), `common.NewAppError(id, msg string, params map[string]any, detail string, status int)`.
- Produces: `const internalErrorDetail = "An internal error occurred. Quote the request_id when contacting support."` and `func (c *Context) logInternalError(err error)` in package `api`, relied on by Tasks 3 and 4.

- [ ] Step 1: Replace the control test with failing tests. In `api/context_test.go` replace `TestSetInternalError_OrdinaryError_StillReturns500` with:

```go
// TestSetInternalError_OrdinaryError_Returns500WithFixedDetail verifies that an
// unrelated error is still a 500 but its text never reaches the response body.
func TestSetInternalError_OrdinaryError_Returns500WithFixedDetail(t *testing.T) {
	plain := errors.New("pq: relation \"secrets\" does not exist at /var/lib/rv/db")

	testApp := &app.App{}
	handler := api.ApiHandler(testApp, func(c *api.Context, w http.ResponseWriter, r *http.Request) {
		c.SetInternalError(plain)
	})

	req := httptest.NewRequest(http.MethodGet, "/api/secrets", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusInternalServerError, rr.Code)
	assert.Empty(t, rr.Header().Get("Retry-After"))
	assert.NotContains(t, rr.Body.String(), "secrets")
	assert.NotContains(t, rr.Body.String(), "/var/lib/rv/db")

	var body map[string]any
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &body))
	assert.Equal(t, "An internal error occurred. Quote the request_id when contacting support.", body["detailed_error"])
	assert.NotEmpty(t, body["request_id"])
}

// TestSetInternalError_LogsErrorWithRequestID verifies the detail is not lost:
// the real error goes to the server log keyed by the same request id.
func TestSetInternalError_LogsErrorWithRequestID(t *testing.T) {
	var buf bytes.Buffer
	l := logrus.New()
	l.SetOutput(&buf)
	testApp := &app.App{Logger: &logging.Logger{Logger: l}}

	handler := api.ApiHandler(testApp, func(c *api.Context, w http.ResponseWriter, r *http.Request) {
		c.SetInternalError(errors.New("driver exploded"))
	})
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/api/secrets", nil))

	var body map[string]any
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &body))
	assert.Contains(t, buf.String(), "driver exploded")
	assert.Contains(t, buf.String(), body["request_id"].(string))
}
```

Add any missing imports to the file (`bytes`, `encoding/json`, `github.com/sirupsen/logrus`, `rocketvault/internal/logging`, `github.com/stretchr/testify/require`); check the existing import block first and only add what is absent.

- [ ] Step 2: Run `go test ./api/ -run 'TestSetInternalError' -count=1`. Expected: FAIL (the body still contains the raw text, and no log line exists).

- [ ] Step 3: Implement. In `api/context.go`, add the constant and helper above `SetInternalError`, and replace the tail of `SetInternalError` (the `msg`/`detail` block):

```go
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
```

```go
	c.logInternalError(err)
	c.Err = common.NewAppError("api.context.set_internal_error", "Internal server error", nil,
		internalErrorDetail, http.StatusInternalServerError)
}
```

Also update the doc comment of `SetInternalError` to say the detail is always the fixed string. Add imports `fmt` and `github.com/sirupsen/logrus` to `api/context.go` if absent (check the import block).

- [ ] Step 4: Run `go test ./api/ -run 'TestSetInternalError' -count=1`. Expected: PASS. Then run `go test ./api/ -count=1` and fix any test that asserted raw detail text in a 500 body by asserting the fixed detail instead (grep hits: `api/keys_crypto_test.go:634` region, `api/vault_webhook_test.go:270` region; these currently assert status only, so none are expected to change).

- [ ] Step 5: Commit. Invoke the `dev-workflow-skills:1-git-commit` plugin skill via the Skill tool (GPG signed). Message subject: "Fix: stop SetInternalError echoing err.Error() to clients".

### Task 2: Conflict and validation mapping (closes B55)

**Files:**
- Modify: `api/context.go` (add `SetConflict` after `SetNotFound`, line ~121)
- Modify: `api/errors_secret.go:15-33`, `api/errors_key.go:19-62`, `api/errors_certificate.go:19-33`
- Modify: `internal/services/secrets/secret_service.go:84-89` (`validateContentType`) and the error vars near the other `Err*` declarations in that package (find with `grep -n "ErrSecretLifecycleDenied =" internal/services/secrets/*.go`)
- Test: `api/errors_mapping_test.go` (create)

**Interfaces:**
- Consumes: `repositories.ErrNameTaken` (`internal/repositories/name_taken_errors.go:9`), `secrets.ErrSecretLifecycleDenied`.
- Produces: `func (c *Context) SetConflict(message string)` (409, id `api.context.set_conflict`), `secrets.ErrInvalidContentType`, both used in Tasks 8 and 10.

- [ ] Step 1: Write the failing test `api/errors_mapping_test.go`:

```go
package api

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"

	"rocketvault/internal/repositories"
	"rocketvault/internal/services/secrets"
)

// nameTakenChain mimics what the repositories return: the sentinel wrapped
// next to the raw driver text.
func nameTakenChain() error {
	return fmt.Errorf("failed to create: %w: UNIQUE constraint failed: secrets.vault_id, secrets.name",
		repositories.ErrNameTaken)
}

func errorBody(c *Context) (int, string) {
	w := httptest.NewRecorder()
	writeError(w, c)
	return w.Code, w.Body.String()
}

func TestWriteErrors_NameTaken_Returns409WithoutDriverText(t *testing.T) {
	mappers := map[string]func(*Context, error){
		"secret":      writeSecretError,
		"key":         writeKeyError,
		"certificate": writeCertificateError,
	}
	for name, mapper := range mappers {
		t.Run(name, func(t *testing.T) {
			c := &Context{RequestID: "req-test"}
			mapper(c, nameTakenChain())
			code, body := errorBody(c)
			assert.Equal(t, http.StatusConflict, code)
			assert.NotContains(t, body, "UNIQUE constraint")
			assert.Contains(t, body, "already exists")
		})
	}
}

func TestWriteSecretError_InvalidContentType_Returns400(t *testing.T) {
	c := &Context{RequestID: "req-test"}
	writeSecretError(c, fmt.Errorf("%w: %q", secrets.ErrInvalidContentType, "x/y"))
	code, _ := errorBody(c)
	assert.Equal(t, http.StatusBadRequest, code)
}
```

- [ ] Step 2: Run `go test ./api/ -run 'TestWriteErrors_NameTaken|TestWriteSecretError_InvalidContentType' -count=1`. Expected: FAIL to compile (`secrets.ErrInvalidContentType` undefined).

- [ ] Step 3: Implement.
  - `internal/services/secrets/secret_service.go`: add `var ErrInvalidContentType = errors.New("unsupported content type")` beside the other sentinels, and change `validateContentType` to `return fmt.Errorf("%w: %q", ErrInvalidContentType, ct)` (text is unchanged, so `content_type_test.go` string assertions still hold).
  - `api/context.go` after `SetNotFound`:

```go
// SetConflict sets a 409 error for a request that collides with existing state.
func (c *Context) SetConflict(message string) {
	c.Err = common.NewAppError("api.context.set_conflict", message, nil, "", http.StatusConflict)
}
```

  - In `writeSecretError`, `writeKeyError` and `writeCertificateError`, insert before `default:` (import `rocketvault/internal/repositories`):

```go
	case errors.Is(err, repositories.ErrNameTaken):
		c.SetConflict("a resource with this name already exists in this vault")
```

  - In `writeSecretError` add before `default:`:

```go
	case errors.Is(err, secrets.ErrInvalidContentType):
		c.SetInvalidParam("content_type")
```

- [ ] Step 4: Run the same command. Expected: PASS. Run `go test ./api/ ./internal/services/secrets/ -count=1`; expected PASS.

- [ ] Step 5: Commit via the `dev-workflow-skills:1-git-commit` skill (subject: "Fix: map duplicate names to 409 and bad content types to 400").

### Task 3: Generic messages at the bypass sites (JWKS rotate, OIDC, /health/ready)

**Files:**
- Modify: `api/jwks.go:62-67` (rotate failure branch)
- Modify: `api/oidc.go:49, 120, 135, 146` (and the `validateCLIRedirectURI` error at 49)
- Modify: `api/health.go:136-143` (ReadinessCheck error body)
- Test: `api/error_bypass_test.go` (create; JWKS rotate and OIDC callback only, see the readiness note in Step 1)

**Interfaces:**
- Consumes: `internalErrorDetail` and `(*Context).logInternalError` from Task 1; `recordJWKSRotateAudit`.
- Produces: `func logBypassError(r *http.Request, scope string, err error)` in `api/oidc.go` (package-level logger for handlers that have no `*Context`).

- [ ] Step 1: Failing tests. Look at how existing tests build these: `grep -n "rotateJWKS\|oidcCallbackHandler\|ReadinessCheck" api/*_test.go | head` and reuse their fixtures (a fake `signing.RotatableProvider` whose `Rotate()` returns `errors.New("PKCS#11 slot 3: CKR_DEVICE_ERROR")`; an OIDC service double whose `HandleCallback` returns `errors.New("oidc: id token signature invalid: key abc")`; Assertions, one test per site. There is deliberately no readiness test: `HealthHandler.collector` is the concrete `*health.HealthCollector` and `CollectMetrics` (`internal/health/health.go:146-225`) always returns a nil error, so the `/health/ready` error branch is unreachable through the public constructor and a failing-collector test cannot be written without a new interface seam. The body change for that branch is a one-line removal of an already-unreachable leak and is covered by review, not by a test):

```go
func TestRotateJWKS_Failure_DoesNotLeakProviderError(t *testing.T) {
	// Arrange with the existing rotate fixture and a failing provider.
	w := runRotateWithFailingProvider(t, "PKCS#11 slot 3: CKR_DEVICE_ERROR")
	assert.Equal(t, http.StatusInternalServerError, w.Code)
	assert.NotContains(t, w.Body.String(), "CKR_DEVICE_ERROR")
	assert.Contains(t, w.Body.String(), "An internal error occurred.")
}

func TestOIDCCallback_Failure_DoesNotLeakIssuerError(t *testing.T) {
	w := runOIDCCallbackWithHandleCallbackError(t, "oidc: id token signature invalid: key abc")
	assert.Equal(t, http.StatusUnauthorized, w.Code)
	assert.NotContains(t, w.Body.String(), "signature invalid")
	assert.Contains(t, w.Body.String(), "authentication failed")
}
```

The two `run...` helpers are defined in the same new test file, built by copying the setup of the closest existing test located by the grep above (the OIDC callback needs the state and nonce cookies set to equal values and `?code=x&state=<cookie>`). Write them fully against the fixtures you find; do not leave them as stubs.

- [ ] Step 2: Run `go test ./api/ -run 'TestRotateJWKS_Failure|TestOIDCCallback_Failure' -count=1`. Expected: FAIL (raw text present).

- [ ] Step 3: Implement.
  - `api/jwks.go` rotate failure branch:

```go
	newKID, overlapUntil, err := rotatable.Rotate()
	if err != nil {
		recordJWKSRotateAudit(c, r, "", "failure")
		c.logInternalError(err)
		c.Err = common.NewAppError("api.jwks.rotate", "api.jwks.rotate_failed", nil,
			internalErrorDetail, http.StatusInternalServerError)
		return
	}
```

  - `api/oidc.go`: add near the top

```go
// logBypassError logs an error for handlers that write plain-text responses
// and so have no Context to carry a request id.
func logBypassError(r *http.Request, scope string, err error) {
	logrus.WithFields(logrus.Fields{
		"scope":  scope,
		"method": r.Method,
		"path":   r.URL.Path,
		"error":  fmt.Sprint(err),
	}).Error("OIDC handler error")
}
```

    then: line 49 becomes `http.Error(w, "invalid cli_redirect_uri", http.StatusBadRequest)`; line 120 becomes `logBypassError(r, "callback", err)` then `http.Error(w, "authentication failed", http.StatusUnauthorized)`; line 135 becomes `logBypassError(r, "resolve_user", err)` then `http.Error(w, "internal error", http.StatusInternalServerError)`; line 146 becomes `logBypassError(r, "issue_session", err)` then `http.Error(w, "internal error", http.StatusInternalServerError)`. Add `logrus` and `fmt` imports if absent.
  - `api/health.go` ReadinessCheck: keep the existing `h.logger.LogAuditError(...)` (already logs the cause) and change the body to `map[string]string{"status": "not ready"}` with no `error` key. No test pins this (see Step 1); `go build ./api/` and the existing `api/health_check_test.go` success-path tests cover compilation.

- [ ] Step 4: Run the Step 2 command. Expected: PASS. Run `go test ./api/ -count=1`; if an existing OIDC test asserted the old `"oidc callback failed: "` prefix, update it to `"authentication failed"`.

- [ ] Step 5: Commit via the `dev-workflow-skills:1-git-commit` skill (subject: "Fix: generic errors from JWKS rotate, OIDC callback and readiness").

### Task 4: Cache-Control no-store on authenticated and JSON responses

**Files:**
- Modify: `api/respond.go:15-31` (`writeJSON`, `writeJSONStatus`)
- Modify: `api/context.go:182-201` (`ApiSessionRequired` wrapper, before the handler runs)
- Test: `api/cache_control_test.go` (create)

**Interfaces:**
- Consumes: `ApiSessionRequired`, `writeJSON`, `writeJSONStatus`.
- Produces: `func setNoStore(w http.ResponseWriter)` in `api/respond.go` (sets `Cache-Control: no-store` only when the handler has not already set one, so `api/jwks.go:36` `public, max-age=3600` and `api/oauth2.go:55` keep their values).

- [ ] Step 1: Failing test:

```go
package api

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestWriteJSON_SetsNoStore(t *testing.T) {
	w := httptest.NewRecorder()
	writeJSON(w, map[string]string{"a": "b"})
	assert.Equal(t, "no-store", w.Header().Get("Cache-Control"))
}

func TestWriteJSONStatus_SetsNoStore(t *testing.T) {
	w := httptest.NewRecorder()
	writeJSONStatus(w, http.StatusConflict, map[string]string{"a": "b"})
	assert.Equal(t, "no-store", w.Header().Get("Cache-Control"))
}

func TestWriteJSON_KeepsExplicitCacheControl(t *testing.T) {
	w := httptest.NewRecorder()
	w.Header().Set("Cache-Control", "public, max-age=3600")
	writeJSON(w, map[string]string{"a": "b"})
	assert.Equal(t, "public, max-age=3600", w.Header().Get("Cache-Control"))
}

func TestApiSessionRequired_SetsNoStoreOnDirectWrites(t *testing.T) {
	c := newSecretCtx(&mockSecretService{})
	h := ApiSessionRequired(c.App, func(c *Context, w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{}`)) //nolint:errcheck,gosec
	})
	r := httptest.NewRequest(http.MethodGet, "/x", nil)
	r = r.WithContext(context.WithValue(r.Context(), common.UserIDKey, secretHTestUserID))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	assert.Equal(t, "no-store", w.Header().Get("Cache-Control"))
}
```

Add imports `context` and `rocketvault/common`. If `ValidateEndpointAccess` on the test container panics with a nil RBAC service, use an `&app.App{}` with nil `ServiceContainer` (the wrapper skips the RBAC call then).

- [ ] Step 2: Run `go test ./api/ -run 'NoStore|KeepsExplicitCacheControl' -count=1`. Expected: FAIL.

- [ ] Step 3: Implement in `api/respond.go`:

```go
// setNoStore marks a response as uncacheable unless the handler chose its own
// Cache-Control value, as the public JWKS document does.
func setNoStore(w http.ResponseWriter) {
	if w.Header().Get("Cache-Control") == "" {
		w.Header().Set("Cache-Control", "no-store")
	}
}
```

Call `setNoStore(w)` as the first line of `writeJSON` and `writeJSONStatus`. In `ApiSessionRequired`, call `setNoStore(w)` right after the `ctx := &Context{...}` block and before `handler(ctx, w, r)` so handlers that write with `w.Write` are covered.

- [ ] Step 4: Run the Step 2 command. Expected: PASS. Run `go test ./api/ -count=1`. Expected PASS (`api/response_shape_test.go` compares bodies only, and `api/openapi_drift_test.go` compares routes only, so neither is affected; confirm by running both explicitly: `go test ./api/ -run 'TestResponseShape|TestOpenAPISpec' -count=1`).

- [ ] Step 5: Commit via the `dev-workflow-skills:1-git-commit` skill (subject: "Fix: send Cache-Control no-store on authenticated API responses").

### Task 5: B82 documentation, B55 closure and API spec note

**Files:**
- Modify: `.claude/known-bugs.md` (append B82 entry after the last `### B` entry that precedes `## Deferred Refactors`, near line 4270; change B55 at line 3201-3203 to Fixed)
- Modify: `docs/api-specification.yaml:4661` (description of `detailed_error`)

- [ ] Step 1: Add the B82 entry, structure copied from B69:

```markdown
### B82 — Generic 500 responses leaked `err.Error()` in `detailed_error`

**Status**: Fixed in the commits of plan `docs/superpowers/plans/2026-09-30-secrets-and-error-responses.md` (GitHub #41)
**Severity**: Medium
**Files**: `api/context.go`, `api/jwks.go`, `api/oidc.go`, `api/health.go`, `api/errors_secret.go`, `api/errors_key.go`, `api/errors_certificate.go`, `api/respond.go`

**Symptom**: SQL fragments, driver errors and crypto failure text reached clients through `detailed_error`, through the unauthenticated OIDC callback and `/health/ready`, and through the JWKS rotate endpoint.

**Root cause**: `SetInternalError` stored `err.Error()` as the detail and `writeError` always serialized it; three handlers bypassed it with their own `err.Error()`.

**What was fixed**: `SetInternalError` logs the error with the request id and sends the fixed string `An internal error occurred. Quote the request_id when contacting support.`; the OIDC callback, JWKS rotate and readiness bodies are generic; authenticated responses carry `Cache-Control: no-store` (an explicit handler value, such as the JWKS `public, max-age=3600`, is kept).
```

- [ ] Step 2: Set B55's status line to `**Status**: Fixed by B82's plan (`docs/superpowers/plans/2026-09-30-secrets-and-error-responses.md`): `ErrNameTaken` now maps to 409 in `writeSecretError`, `writeKeyError` and `writeCertificateError`, pinned by `api/errors_mapping_test.go`.`

- [ ] Step 3: In `docs/api-specification.yaml` near line 4661 change the `detailed_error` description to state it is either empty or a fixed, non-diagnostic string, and that the `request_id` correlates with server logs. Run `go test ./api/ -run TestOpenAPISpec -count=1`. Expected PASS.

- [ ] Step 4: Commit via the `dev-workflow-skills:1-git-commit` skill with footer `Fixes #41` (subject: "docs: record B82 and close B55").

---

## Issue #44 (B83): export and version reads bypass enabled and expiry

### Task 6: Version reads enforce the parent secret's lifecycle

**Files:**
- Modify: `internal/services/secrets/versioning_service.go:166-169` (`GetVersions`), `225-228` (`GetVersion`), `252-255` (`GetLatestVersion`)
- Modify: `internal/services/secrets/versioning_scope_test.go` (lines 95, 112, 141, 159, 178, 196 build `&model.Secret{ID: secretID}` with `Enabled` false)
- Modify: `internal/services/secrets/versioning_service_vault_test.go:29` (`TestGetVersions_VaultScope_HappyPath`)
- Modify: `internal/services/secrets/coverage_boost_test.go:757` (`TestVersioningServiceHappyPathAndOwnershipErrors`, calls `GetVersions`) and `:839` (`TestVersioningServiceGetLatestAndDeleteMethods`, calls `GetVersion` and `GetLatestVersion`)
- Test: `internal/services/secrets/versioning_lifecycle_test.go` (create, package `secrets`)

**Interfaces:**
- Consumes: `(*model.Secret).IsAccessible()`, `ErrSecretLifecycleDenied`, `newVersioningScopeFixture(t)` returning `(*MockSecretRepository, *MockSecretVersionRepository, *versioningService)`.
- Produces: `func (s *versioningService) readAccessibleParent(ctx, secretID, scope) error` (private), used by the three methods.

- [ ] Step 1: Failing test file:

```go
package secrets

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"rocketvault/model"
)

func lifecycleParents(secretID uuid.UUID) map[string]*model.Secret {
	past := time.Now().Add(-time.Hour)
	return map[string]*model.Secret{
		"disabled": {ID: secretID, Enabled: false},
		"expired":  {ID: secretID, Enabled: true, ExpiresAt: &past},
	}
}

func TestVersionReads_DeniedForInaccessibleParent(t *testing.T) {
	for name, parent := range lifecycleParents(uuid.New()) {
		t.Run(name, func(t *testing.T) {
			secretRepo, versionRepo, svc := newVersioningScopeFixture(t)
			ctx := context.Background()
			scope := model.NewVaultScope(uuid.New(), uuid.New())
			secretRepo.On("Read", ctx, parent.ID, scope).Return(parent, nil)

			_, err := svc.GetVersion(ctx, parent.ID, 1, scope)
			require.ErrorIs(t, err, ErrSecretLifecycleDenied)
			_, err = svc.GetLatestVersion(ctx, parent.ID, scope)
			require.ErrorIs(t, err, ErrSecretLifecycleDenied)
			_, err = svc.GetVersions(ctx, parent.ID, scope)
			require.ErrorIs(t, err, ErrSecretLifecycleDenied)

			versionRepo.AssertNotCalled(t, "GetVersion", mock.Anything, mock.Anything, mock.Anything)
			versionRepo.AssertNotCalled(t, "GetLatestVersion", mock.Anything, mock.Anything)
			versionRepo.AssertNotCalled(t, "GetVersions", mock.Anything, mock.Anything)
		})
	}
}

// Metadata carries no plaintext, so a disabled parent may still be enumerated.
func TestGetVersionsMetadata_AllowedForDisabledParent(t *testing.T) {
	secretRepo, versionRepo, svc := newVersioningScopeFixture(t)
	ctx := context.Background()
	secretID := uuid.New()
	scope := model.NewVaultScope(uuid.New(), uuid.New())
	secretRepo.On("Read", ctx, secretID, scope).Return(&model.Secret{ID: secretID, Enabled: false}, nil).Once()
	versionRepo.On("GetVersions", ctx, secretID).Return([]model.SecretVersion{{SecretID: secretID, Version: 1}}, nil).Once()

	got, err := svc.GetVersionsMetadata(ctx, secretID, scope)
	require.NoError(t, err)
	assert.Len(t, got, 1)
}
```

- [ ] Step 2: Run `go test ./internal/services/secrets/ -run 'TestVersionReads_DeniedForInaccessibleParent|TestGetVersionsMetadata_AllowedForDisabledParent' -count=1`. Expected: first test FAIL (no error returned), second PASS.

- [ ] Step 3: Implement in `versioning_service.go`:

```go
// readAccessibleParent authorizes the scope against the parent secret and
// enforces its lifecycle, so a disabled or expired secret cannot be read back
// through its version history.
func (s *versioningService) readAccessibleParent(ctx context.Context, secretID uuid.UUID, scope model.Scope) error {
	parent, err := s.secretRepo.Read(ctx, secretID, scope)
	if err != nil {
		return fmt.Errorf("%w: %s", ErrSecretNotFound, err.Error())
	}
	if !parent.IsAccessible() {
		return fmt.Errorf("%w", ErrSecretLifecycleDenied)
	}
	return nil
}
```

In `GetVersions`, `GetVersion` and `GetLatestVersion` replace the leading `if _, err := s.secretRepo.Read(...); err != nil { return nil, fmt.Errorf("%w: %s", ErrSecretNotFound, err.Error()) }` block with:

```go
	if err := s.readAccessibleParent(ctx, secretID, scope); err != nil {
		return nil, err
	}
```

Leave `GetVersionsMetadata` unchanged.

- [ ] Step 4: Run `go test ./internal/services/secrets/ -count=1`. Existing tests built on `&model.Secret{ID: secretID}` for GetVersion(s)/GetLatestVersion now fail with lifecycle denial: change those fixtures (versioning_scope_test.go lines 95, 112, 141, 159, 178, 196 as applicable; only tests that call the three changed methods, not the metadata tests in `versioning_metadata_test.go`) to `&model.Secret{ID: secretID, Enabled: true}`. Three more fixtures need the same flag, with these exact edits:
  - `versioning_service_vault_test.go:29`: `&model.Secret{ID: secretID, VaultID: vaultID}` becomes `&model.Secret{ID: secretID, VaultID: vaultID, Enabled: true}`.
  - `coverage_boost_test.go:757`: `secret := &model.Secret{ID: secretID, UserID: userID, Name: "db", Value: "current", Version: 2}` gains `Enabled: true`.
  - `coverage_boost_test.go:839`: `secret := &model.Secret{ID: secretID, UserID: userID, Name: "db", Value: "current", Version: 3}` gains `Enabled: true`.

  Re-run; expected PASS. Then `go test ./api/ ./cmd/secrets/ -count=1`; the API already maps `ErrSecretLifecycleDenied` to 403 via `writeSecretError`.

- [ ] Step 5: Commit via the `dev-workflow-skills:1-git-commit` skill (subject: "Fix: enforce secret lifecycle on version reads").

### Task 7: Export omits inaccessible secrets

**Files:**
- Modify: `internal/services/secrets/secret_service.go:614-625` (after the `ListSecrets` call in `ExportSecrets`)
- Test: `internal/services/secrets/export_lifecycle_test.go` (create, package `secrets_test`, uses `newImportFixture`)

**Interfaces:**
- Consumes: `importFixture` (`f.secretSvc`, `f.scope()`), `secrets.ExportSecretsRequest{Scope, Format, FilterTags, IncludeTags, Encrypt, Passphrase}`, `secrets.CreateSecretRequest{UserID, VaultID, Name, Value, Enabled *bool, ExpiresAt *time.Time}`.
- Produces: `func accessibleOnly(in []model.Secret) []model.Secret` (private helper in `secret_service.go`).

- [ ] Step 1: Failing test:

```go
package secrets_test

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"rocketvault/internal/services/secrets"
)

func TestExportSecrets_SkipsDisabledAndExpired(t *testing.T) {
	ctx := context.Background()
	f := newImportFixture(t)
	off, past := false, time.Now().Add(-time.Hour)
	mk := func(name, value string, enabled *bool, exp *time.Time) {
		_, err := f.secretSvc.CreateSecret(ctx, secrets.CreateSecretRequest{
			UserID: f.userID, VaultID: f.vaultID, Name: name, Value: value, Enabled: enabled, ExpiresAt: exp,
		})
		require.NoError(t, err)
	}
	mk("live-secret", "live-value", nil, nil)
	mk("disabled-secret", "disabled-value", &off, nil)
	mk("expired-secret", "expired-value", nil, &past)

	for _, format := range []string{"json", "csv"} {
		data, err := f.secretSvc.ExportSecrets(ctx, secrets.ExportSecretsRequest{Scope: f.scope(), Format: format})
		require.NoError(t, err)
		assert.Contains(t, string(data), "live-value", format)
		assert.NotContains(t, string(data), "disabled-value", format)
		assert.NotContains(t, string(data), "expired-value", format)
	}

	data, err := f.secretSvc.ExportSecrets(ctx, secrets.ExportSecretsRequest{Scope: f.scope(), Format: "json"})
	require.NoError(t, err)
	var got []map[string]any
	require.NoError(t, json.Unmarshal(data, &got))
	assert.Len(t, got, 1)
}
```

- [ ] Step 2: Run `go test ./internal/services/secrets/ -run TestExportSecrets_SkipsDisabledAndExpired -count=1`. Expected: FAIL (disabled value present).

- [ ] Step 3: Implement. After the `ListSecrets` error check in `ExportSecrets` add `secretsList = accessibleOnly(secretsList)` and add the helper:

```go
// accessibleOnly drops disabled, expired and not-yet-active secrets, matching
// what GetSecret refuses to return. Export must not be a side door around it.
func accessibleOnly(in []model.Secret) []model.Secret {
	out := make([]model.Secret, 0, len(in))
	for i := range in {
		if in[i].IsAccessible() {
			out = append(out, in[i])
		}
	}
	return out
}
```

Existing `ExportSecrets` unit tests in `secret_service_test.go` (stored slices at lines 689, 716, 756, 784, 819, 1234, 1306, 1374, 1583) build `model.Secret` without `Enabled: true`; add `Enabled: true` to each of those literals.

- [ ] Step 4: Run `go test ./internal/services/secrets/ ./cmd/secrets/ ./api/ -count=1`. Expected PASS. The CLI path (`cmd/secrets/export.go`) calls `ExportSecrets`, so `cmd/secrets/export_test.go` mock tests are unaffected; add no duplicate CLI test, but state in the commit body that the CLI shares the service path.

- [ ] Step 5: Commit via the `dev-workflow-skills:1-git-commit` skill (subject: "Fix: exclude disabled and expired secrets from export").

### Task 8: updateSecret no longer pre-reads the secret (403 on enable, equality oracle)

**Files:**
- Modify: `api/secrets.go:313-396` (`updateSecret` body after the validation block; remove the `GetSecret` pre-read and field-by-field diff)
- Modify: `api/coverage_boost_test.go:474-545`, `api/extra_coverage_test.go:156-240`, `api/secrets_handlers_test.go:526+` as required by the new call sequence
- Test: `api/secrets_update_lifecycle_test.go` (create, package `api`)

**Interfaces:**
- Consumes: `secrets.UpdateSecretRequest` (nil pointer means no change), `secrets.ErrSecretLifecycleDenied`, `mockSecretService`, `newSecretCtx`, `makeSecretModel`, `secretHTestUserID`, `writeSecretError`.
- Produces: new handler behavior: `UpdateSecret` is called once with exactly the fields the client sent, then `GetSecret` is used only for the response body.

- [ ] Step 1: Failing tests:

```go
package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"rocketvault/internal/services/secrets"
)

// putSecret sets the SecretID route param itself: newSecretCtx leaves it empty,
// and resourceID answers 400 for an empty id before updateSecret does anything.
func putSecret(t *testing.T, c *Context, id uuid.UUID, body map[string]any) *httptest.ResponseRecorder {
	t.Helper()
	c.Params = &ApiParams{SecretID: id.String(), PerPage: 60}
	b, err := json.Marshal(body)
	require.NoError(t, err)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPut, "/secrets/"+id.String(), bytes.NewReader(b))
	updateSecret(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}
	return w
}

// Enabling a disabled secret must work: the old pre-read returned 403.
func TestUpdateSecret_EnableDisabledSecret_Returns200(t *testing.T) {
	id := uuid.New()
	svc := &mockSecretService{}
	enabled := makeSecretModel(id)
	svc.On("UpdateSecret", mock.Anything, mock.MatchedBy(func(r secrets.UpdateSecretRequest) bool {
		return r.Enabled != nil && *r.Enabled && r.Value == nil && r.Name == nil
	})).Return(nil).Once()
	svc.On("GetSecret", mock.Anything, id, mock.Anything).Return(enabled, nil).Once()

	w := putSecret(t, newSecretCtx(svc), id, map[string]any{"enabled": true})
	assert.Equal(t, http.StatusOK, w.Code)
	svc.AssertExpectations(t)
}

// A PUT whose value equals the stored value must not be told apart from any
// other PUT: it is accepted, never a 400 "no changes provided".
func TestUpdateSecret_IdenticalValue_Returns200NotEqualityOracle(t *testing.T) {
	id := uuid.New()
	svc := &mockSecretService{}
	same := makeSecretModel(id)
	svc.On("UpdateSecret", mock.Anything, mock.Anything).Return(nil).Once()
	svc.On("GetSecret", mock.Anything, id, mock.Anything).Return(same, nil).Once()

	w := putSecret(t, newSecretCtx(svc), id, map[string]any{"value": same.Value})
	assert.Equal(t, http.StatusOK, w.Code)
}

// Disabling a secret makes the read-back legitimately refuse it; the update
// itself succeeded, so the handler still answers 200 with a minimal body.
func TestUpdateSecret_DisableSecret_Returns200WithMinimalBody(t *testing.T) {
	id := uuid.New()
	svc := &mockSecretService{}
	svc.On("UpdateSecret", mock.Anything, mock.Anything).Return(nil).Once()
	svc.On("GetSecret", mock.Anything, id, mock.Anything).Return(nil, secrets.ErrSecretLifecycleDenied).Once()

	w := putSecret(t, newSecretCtx(svc), id, map[string]any{"enabled": false})
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), id.String())
	assert.Contains(t, w.Body.String(), `"enabled":false`)
}

func TestUpdateSecret_DuplicateName_Returns409(t *testing.T) {
	id := uuid.New()
	svc := &mockSecretService{}
	svc.On("UpdateSecret", mock.Anything, mock.Anything).Return(nameTakenChain()).Once()

	w := putSecret(t, newSecretCtx(svc), id, map[string]any{"name": "taken-name"})
	assert.Equal(t, http.StatusConflict, w.Code)
	assert.NotContains(t, w.Body.String(), "UNIQUE constraint")
}
```

- [ ] Step 2: Run `go test ./api/ -run 'TestUpdateSecret_EnableDisabledSecret|TestUpdateSecret_IdenticalValue|TestUpdateSecret_DisableSecret|TestUpdateSecret_DuplicateName' -count=1`. Expected: FAIL (pre-read consumed `GetSecret`, mock expectations unmet, 400 returned).

- [ ] Step 3: Implement. In `api/secrets.go` replace everything in `updateSecret` from `secret, err := secretService.GetSecret(...)` through the `updateReq` construction and the response build with:

```go
	// "No changes" is decided from the request alone. Comparing against the
	// stored value would make the 400 an equality oracle for the secret.
	noFields := req.Name == "" && req.Value == "" && req.Tags == nil &&
		req.ContentType == nil && req.Enabled == nil && req.ExpiresAt == nil &&
		req.NotBefore == nil && req.PurgeProtection == nil
	if noFields {
		c.SetInvalidParam("no changes provided")
		return
	}

	updateReq := secrets.UpdateSecretRequest{
		SecretID:        secretID,
		Scope:           scope,
		ContentType:     req.ContentType,
		Enabled:         req.Enabled,
		ExpiresAt:       req.ExpiresAt,
		NotBefore:       req.NotBefore,
		PurgeProtection: req.PurgeProtection,
	}
	if req.Name != "" {
		updateReq.Name = &req.Name
	}
	if req.Value != "" {
		updateReq.Value = &req.Value
	}
	if req.Tags != nil {
		updateReq.Tags = &req.Tags
	}
	if err := secretService.UpdateSecret(r.Context(), updateReq); err != nil {
		writeSecretError(c, err)
		return
	}

	// The read-back only builds the response. When the update just disabled or
	// expired the secret, it is refused by design, so answer with a minimal body.
	response := model.SecretResponse{ID: secretID.String(), Enabled: req.Enabled != nil && *req.Enabled}
	if secret, getErr := secretService.GetSecret(r.Context(), secretID, scope); getErr == nil {
		response = model.SecretResponse{
			ID:          secret.ID.String(),
			Name:        secret.Name,
			Tags:        secret.Tags,
			Version:     secret.Version,
			ContentType: secret.ContentType,
			CreatedAt:   secret.CreatedAt.Format(time.RFC3339),
			Enabled:     secret.Enabled,
			ExpiresAt:   secret.ExpiresAt,
			NotBefore:   secret.NotBefore,
		}
	} else if !errors.Is(getErr, secrets.ErrSecretLifecycleDenied) {
		writeSecretError(c, getErr)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(response.ToJson())) //nolint:errcheck,gosec

	c.Logger.Printf("User %s updated secret %s", scope.ActorID(), secretID)
```

Add the `errors` import if absent. The service's `UpdateSecret` still increments the version and archives the prior value; the handler no longer does `secret.Version++`.

- [ ] Step 4: Run the Step 2 command; expected PASS. Then `go test ./api/ -count=1`. Six existing tests in `api/secrets_handlers_test.go` (lines 526-650) encode the old pre-read and must be edited as follows; each keeps its `c := newSecretCtx(svc)` and `c.Params = &ApiParams{SecretID: ...}` lines.

  - `TestUpdateSecret_NoChanges_Returns400` (line 543): the old body (same name and value) is now a real update. Replace the mock line and body with an empty update, which is the only "no changes" case left:

```go
	svc := &mockSecretService{}
	// No mock expectations: an empty body is rejected before any service call.
	...
	body, _ := json.Marshal(map[string]any{})
```

    and keep `assert.Equal(t, http.StatusBadRequest, w.Code)` and `svc.AssertExpectations(t)`. Delete the comment line "Same name and value as makeSecretModel".
  - `TestUpdateSecret_ServiceError_Returns500` (line 564): delete the `original := makeSecretModel(secretID)` line and the `svc.On("GetSecret", ...)` line; keep only `svc.On("UpdateSecret", mock.Anything, mock.Anything).Return(errors.New("db error"))`. An unmet `GetSecret` expectation would fail `AssertExpectations`.
  - `TestUpdateSecret_NotFound_Returns404` (line 586): replace the `GetSecret` expectation with

```go
	svc.On("UpdateSecret", mock.Anything, mock.Anything).
		Return(secretServices.ErrSecretNotFound)
```

  - `TestUpdateSecret_LifecycleDenied_Returns403` (line 607): replace the `GetSecret` expectation with

```go
	svc.On("UpdateSecret", mock.Anything, mock.Anything).
		Return(secretServices.ErrSecretLifecycleDenied)
```

  - `TestUpdateSecret_GetSecretError_Returns500` (line 628): the read-back now runs after the update, so add the update expectation before the existing `GetSecret` one:

```go
	svc.On("UpdateSecret", mock.Anything, mock.Anything).Return(nil)
	svc.On("GetSecret", mock.Anything, secretID, mock.Anything).
		Return(nil, errors.New("disk I/O"))
```

  - `TestUpdateSecret_NoChangesProvided_Returns400` (line ~526): drop its `.On("GetSecret"...)` if present, for the same unmet-expectation reason.

  Also update `api/coverage_boost_test.go:474-545` and `api/extra_coverage_test.go:156-240` the same way: each success-path test keeps its `GetSecret` mock (now the read-back) and needs a matching `svc.On("UpdateSecret", mock.Anything, mock.Anything).Return(nil)` if it lacks one; where a test asserted `UpdateSecret` received `Tags: &secret.Tags` or an incremented `Version`, assert the request fields instead. Re-run `go test ./api/ -count=1`; expected PASS.

- [ ] Step 5: CLI check. `cmd/secrets/update.go` calls the service directly and has its own tests; run `go test ./cmd/secrets/ -count=1`. Expected PASS, and no CLI change is needed because the CLI never had the handler's pre-read.

- [ ] Step 6: Add the B83 entry to `.claude/known-bugs.md` (structure of B69): symptom (export and version reads returned disabled or expired values; enabling a disabled secret returned 403; identical-value PUT returned 400), root cause (`ExportSecrets` via `ListSecrets` without `IsAccessible`, `versioning_service.go` reads without parent check, handler pre-read), fix (`readAccessibleParent`, `accessibleOnly`, handler rewrite), accepted behavior change (version metadata listing still allowed for a disabled secret because it carries no plaintext; an update of a disabled secret's value is now allowed, matching Azure where attributes of a disabled secret stay editable).

- [ ] Step 7: Commit via the `dev-workflow-skills:1-git-commit` skill with footer `Fixes #44` (subject: "Fix: updateSecret no longer pre-reads; enable works, no equality oracle").

---

## Issue #48 (B84): import skips create-time validation

### Task 9: ImportSecrets validates every item like create

**Files:**
- Modify: `internal/services/secrets/secret_service.go:~830-843` (the loop head in `ImportSecrets` that currently only checks empty name or value)
- Test: `internal/services/secrets/import_validation_test.go` (create, package `secrets_test`)

**Interfaces:**
- Consumes: `vvalidation "rocketvault/internal/validation"` `ValidateSecretCreate(SecretCreateRequest{Name, Value, Tags, ExpiresAt, NotBefore, Enabled})`, `importFixture`, `marshalRecords`, `importRecord`, `secrets.ImportResult{ImportedCount, SkippedCount, FailedCount, TotalCount, Errors []string}`.
- Produces: per-item failure strings of the form `Invalid '<name>': <validation error>`, with `FailedCount` incremented. The empty name/value check keeps its existing `SkippedCount` behavior.

- [ ] Step 1: Failing tests:

```go
package secrets_test

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"rocketvault/internal/services/secrets"
)

func TestImportSecrets_ValidatesEachItem_JSON(t *testing.T) {
	ctx := context.Background()
	f := newImportFixture(t)

	tooMany := make([]string, 16)
	for i := range tooMany {
		tooMany[i] = fmt.Sprintf("tag%d", i)
	}
	data := marshalRecords(t,
		importRecord{Name: "good-secret", Value: "ok"},
		importRecord{Name: "1-bad-name", Value: "ok"},
		importRecord{Name: "big-value", Value: strings.Repeat("x", 25601)},
		importRecord{Name: "many-tags", Value: "ok", Tags: tooMany},
		importRecord{Name: "edge-value", Value: strings.Repeat("x", 25600)},
	)

	result, err := f.secretSvc.ImportSecrets(ctx, secrets.ImportSecretsRequest{Scope: f.scope(), Format: "json", Data: data})
	require.NoError(t, err)
	assert.Equal(t, 2, result.ImportedCount, "good-secret and the 25600-byte edge value")
	assert.Equal(t, 3, result.FailedCount)
	require.Len(t, result.Errors, 3)
	assert.Contains(t, strings.Join(result.Errors, "\n"), "1-bad-name")
	assert.Contains(t, strings.Join(result.Errors, "\n"), "big-value")
	assert.Contains(t, strings.Join(result.Errors, "\n"), "many-tags")

	_, err = f.secretRepo.FindByName(ctx, "1-bad-name", f.scope())
	assert.Error(t, err, "an invalid record must not be stored")
}

func TestImportSecrets_ValidatesEachItem_CSV(t *testing.T) {
	ctx := context.Background()
	f := newImportFixture(t)
	csvData := "name,value\ngood-secret,ok\nbad_name_underscore,ok\n"

	result, err := f.secretSvc.ImportSecrets(ctx, secrets.ImportSecretsRequest{Scope: f.scope(), Format: "csv", Data: []byte(csvData)})
	require.NoError(t, err)
	assert.Equal(t, 1, result.ImportedCount)
	assert.Equal(t, 1, result.FailedCount)
}

// Overwrite takes the update path, which must be validated too.
func TestImportSecrets_OverwriteValidatesValueSize(t *testing.T) {
	ctx := context.Background()
	f := newImportFixture(t)
	_, err := f.secretSvc.ImportSecrets(ctx, secrets.ImportSecretsRequest{
		Scope: f.scope(), Format: "json", Data: marshalRecords(t, importRecord{Name: "db-password", Value: "v1"}),
	})
	require.NoError(t, err)

	result, err := f.secretSvc.ImportSecrets(ctx, secrets.ImportSecretsRequest{
		Scope: f.scope(), Format: "json", Overwrite: true,
		Data: marshalRecords(t, importRecord{Name: "db-password", Value: strings.Repeat("x", 25601)}),
	})
	require.NoError(t, err)
	assert.Equal(t, 0, result.ImportedCount)
	assert.Equal(t, 1, result.FailedCount)
}
```

- [ ] Step 2: Run `go test ./internal/services/secrets/ -run 'TestImportSecrets_Validates|TestImportSecrets_OverwriteValidates' -count=1`. Expected: FAIL (invalid records are imported).

- [ ] Step 3: Implement. In `ImportSecrets`, directly after the existing empty name/value `continue` block, insert:

```go
		// Apply the same name, value-size and tag-count rules as create, so
		// import cannot store what create refuses.
		if vErr := vvalidation.ValidateSecretCreate(vvalidation.SecretCreateRequest{
			Name:  importSec.Name,
			Value: importSec.Value,
			Tags:  importSec.Tags,
		}); vErr != nil {
			result.Errors = append(result.Errors, fmt.Sprintf("Invalid '%s': %v", importSec.Name, vErr))
			result.FailedCount++
			continue
		}
```

Add the import `vvalidation "rocketvault/internal/validation"` (alias matches `api/secrets.go`). Confirm `internal/validation` does not import `internal/services/secrets` (`go build ./...` will show a cycle if it does; `grep -rn "services/secrets" internal/validation` should return nothing).

- [ ] Step 4: Run the Step 2 command; expected PASS. Run `go test ./internal/services/secrets/ -count=1`; existing import tests that use names failing the pattern `^[a-zA-Z][a-zA-Z0-9-]{0,126}$` must be renamed. The one known case is `TestImportSecretsCSV_UnescapesDoubledQuote` (`secret_service_test.go:1269`), whose CSV row `"d""b"` makes the name `d"b`. Edit it so the quote escaping is still exercised through the value column only:
  - `repo.On("FindByName", ctx, `d"b`, scope)` becomes `repo.On("FindByName", ctx, "d-b", scope)`.
  - `data := []byte("name,value\n" + `"d""b","a""b"` + "\n")` becomes `data := []byte("name,value\n" + `d-b,"a""b"` + "\n")`.
  - `assert.Equal(t, `d"b`, created.Name)` becomes `assert.Equal(t, "d-b", created.Name)`.

  The value `a"b` stays as is, so the doubled-quote unescape assertion on `created.Value` and `crypto.AssertCalled(t, "EncryptSecret", `a"b`)` still pin the original behavior. (The export-side test at line ~1245 only formats names and is not affected.) Grep for other hits with `grep -n 'Name:' internal/services/secrets/secret_service_test.go` near each `ImportSecrets` call and rename any other invalid names the same way.

- [ ] Step 5: Commit via the `dev-workflow-skills:1-git-commit` skill (subject: "Fix: validate each imported secret like create").

### Task 10: HTTP response and CLI surface per-item failures

**Files:**
- Modify: `model/secret.go:298-305` (`ImportResponse`)
- Modify: `api/secrets_transfer.go:~165-179` (response build)
- Modify: `docs/api-specification.yaml:6070-6093` (`ImportResponse` schema)
- Modify: `cmd/secrets/import.go:189-240` (remote path `runSecretsImportRemote`, plus its doc comment at 193-196)
- Test: `api/secrets_import_failures_test.go` (create) and `cmd/secrets/import_remote_report_test.go` (create)

**Interfaces:**
- Consumes: `secrets.ImportResult`, `model.ImportResponse`, existing multipart helper used in `api/extra_coverage_test.go:26-63` (copy its request construction), `testutils.NewTestContext`, `MockRoleAssignmentService`, `MockAccessPolicyService`.
- Produces: `model.ImportResponse` gains `SkippedCount int json:"skipped_count"`, `FailedCount int json:"failed_count"`, `Errors []string json:"errors,omitempty"`; `Success` becomes `FailedCount == 0`.

- [ ] Step 1: Failing HTTP test. Build a multipart request exactly as in `api/extra_coverage_test.go:26-63` with `format=json`, call `importSecrets`, with `svc.On("ImportSecrets", ...)` returning `&secrets.ImportResult{ImportedCount: 1, TotalCount: 3, FailedCount: 2, SkippedCount: 0, Errors: []string{"Invalid 'a': bad", "Invalid 'b': bad"}}`. Assertions:

```go
	assert.Equal(t, http.StatusOK, w.Code)
	var resp model.ImportResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.False(t, resp.Success)
	assert.Equal(t, 2, resp.FailedCount)
	assert.Equal(t, []string{"Invalid 'a': bad", "Invalid 'b': bad"}, resp.Errors)
	assert.Contains(t, resp.Message, "2 failed")
```

- [ ] Step 2: No new local-CLI test. `TestImportCommand_ReturnsErrorAndPrintsDetailsOnFailure` (`cmd/secrets/import_cmd_test.go:345`) already pins that a nonzero `FailedCount` prints each `result.Errors` entry and exits non-zero, and the local path just relays whatever `ImportSecrets` returns, so a second test with a validation-shaped message would assert the same code path. The CLI surfacing for validation errors is therefore covered by that test plus Task 9's service tests. The remote path is the one that does not relay failures; it is fixed and tested in Step 6.

- [ ] Step 3: Run `go test ./api/ -run TestImportSecrets_ReportsPerItemFailures -count=1` (name the HTTP test that) Expected: FAIL to compile or assert (missing fields).

- [ ] Step 4: Implement. `model/secret.go`:

```go
type ImportResponse struct {
	Success       bool     `json:"success"`
	Message       string   `json:"message"`
	ImportedCount int      `json:"imported_count"`
	SkippedCount  int      `json:"skipped_count"`
	FailedCount   int      `json:"failed_count"`
	TotalCount    int      `json:"total_count"`
	Format        string   `json:"format"`
	ImportedAt    string   `json:"imported_at"`
	Errors        []string `json:"errors,omitempty"`
}
```

In `api/secrets_transfer.go` build the response with:

```go
	message := fmt.Sprintf("Successfully imported %d/%d secrets", result.ImportedCount, result.TotalCount)
	if result.FailedCount > 0 {
		message = fmt.Sprintf("Imported %d/%d secrets, %d failed", result.ImportedCount, result.TotalCount, result.FailedCount)
	}
	response := model.ImportResponse{
		Success:       result.FailedCount == 0,
		Message:       message,
		ImportedCount: result.ImportedCount,
		SkippedCount:  result.SkippedCount,
		FailedCount:   result.FailedCount,
		TotalCount:    result.TotalCount,
		Format:        format,
		ImportedAt:    time.Now().Format(time.RFC3339),
		Errors:        result.Errors,
	}
```

In `docs/api-specification.yaml` add `skipped_count` (integer), `failed_count` (integer) and `errors` (array of string, per-record failure reasons) to `ImportResponse` properties; leave `required` unchanged except add `failed_count`. Check `model` tests for a JSON golden of `ImportResponse` with `grep -rn "ImportResponse" --include=*_test.go .` and update them.

- [ ] Step 5: Run `go test ./api/ ./cmd/secrets/ ./model/ -count=1`, then `go test ./api/ -run TestOpenAPISpec -count=1`. Expected PASS. The remote CLI path is not safe to leave alone; Step 6 fixes it.

- [ ] Step 6: Remote CLI path reports failures. `cliclient.ImportSecretsRemote` (`internal/cliclient/secrets.go:275`) already decodes the whole `model.ImportResponse`, so after Step 4 the new `FailedCount` and `Errors` fields arrive in `result`. But `runSecretsImportRemote` prints only imported and total, so a remote import with failures would print "Secrets imported successfully" and exit 0, while local mode exits non-zero. First the failing test, `cmd/secrets/import_remote_report_test.go`:

```go
package secrets

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"rocketvault/model"
)

func TestReportRemoteImport_FailuresPrintDetailsAndReturnError(t *testing.T) {
	var out bytes.Buffer
	err := reportRemoteImport(&out, &model.ImportResponse{
		ImportedCount: 1,
		SkippedCount:  0,
		FailedCount:   2,
		TotalCount:    3,
		Errors:        []string{"Invalid 'a': bad", "Invalid 'b': bad"},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "2 record(s) failed to import")
	assert.Contains(t, out.String(), "Failed: 2")
	assert.Contains(t, out.String(), "  - Invalid 'a': bad")
	assert.Contains(t, out.String(), "  - Invalid 'b': bad")
	assert.NotContains(t, out.String(), "imported successfully")
}

func TestReportRemoteImport_CleanRunReturnsNil(t *testing.T) {
	var out bytes.Buffer
	err := reportRemoteImport(&out, &model.ImportResponse{ImportedCount: 2, TotalCount: 2})
	require.NoError(t, err)
	assert.Equal(t, "Secrets imported successfully\nImported: 2\nSkipped: 0\nFailed: 0\nTotal: 2\n", out.String())
}
```

Run `go test ./cmd/secrets/ -run TestReportRemoteImport -count=1`; expected FAIL to compile (`reportRemoteImport` undefined). Then in `cmd/secrets/import.go` replace the final `fmt.Printf("Secrets imported successfully\nImported: %d\nTotal: %d\n", ...)` and `return nil` of `runSecretsImportRemote` with `return reportRemoteImport(os.Stdout, result)`, add this helper below it (import `io` if absent), and replace the stale doc comment lines 193-196 (`Unlike local mode, the server's ImportResponse only reports imported/total counts...`) with "The server's ImportResponse carries the same imported, skipped, failed and per-record error details as local mode, and this path exits non-zero on any failed record exactly like local mode.":

```go
// reportRemoteImport prints the server's import result and returns an error
// when any record failed, matching the local import command's exit behavior.
func reportRemoteImport(w io.Writer, result *model.ImportResponse) error {
	if result.FailedCount == 0 {
		fmt.Fprintf(w, "Secrets imported successfully\nImported: %d\nSkipped: %d\nFailed: %d\nTotal: %d\n", //nolint:errcheck,gosec
			result.ImportedCount, result.SkippedCount, result.FailedCount, result.TotalCount)
		return nil
	}

	fmt.Fprintf(w, "Import finished with errors\nImported: %d\nSkipped: %d\nFailed: %d\nTotal: %d\n", //nolint:errcheck,gosec
		result.ImportedCount, result.SkippedCount, result.FailedCount, result.TotalCount)
	if len(result.Errors) > 0 {
		fmt.Fprintf(w, "Errors:\n") //nolint:errcheck,gosec
		for _, e := range result.Errors {
			fmt.Fprintf(w, "  - %s\n", e) //nolint:errcheck,gosec
		}
	}
	return fmt.Errorf("%d record(s) failed to import; see errors above", result.FailedCount)
}
```

Check that `cmd/secrets/import.go` already imports `rocketvault/model` (it uses `model.ActionSecretsSet` in the authorization path; add it if absent). Re-run the two tests; expected PASS, then `go test ./cmd/secrets/ ./internal/cliclient/ -count=1`; if `internal/cliclient/secrets_test.go` asserts the old import response shape, it only checks decoded counts and keeps passing.

- [ ] Step 7: Commit via the `dev-workflow-skills:1-git-commit` skill (subject: "Fix: report per-item import failures over HTTP and remote CLI").

### Task 11: CSV export guards formula cells and import reverses it

**Files:**
- Modify: `internal/services/secrets/secret_service.go:~683-686` (CSV row build in `ExportSecrets`) and `:~815-821` (CSV decode in `ImportSecrets`); add helpers near `escapeCR` (line ~1002)
- Test: `internal/services/secrets/csv_formula_guard_test.go` (create)

**Interfaces:**
- Consumes: `escapeCR`, `unescapeCR`, `csvEncodeTags`, `csvDecodeTags`.
- Produces: `func csvFormulaGuard(s string) string` and `func csvFormulaUnguard(s string) string` (private). Rule: if `s` starts with one of `=`, `+`, `-`, `@`, tab or `'`, prefix a single `'`; unguard strips exactly one leading `'`. The leading-`'` case is included so guard and unguard are exact inverses.

- [ ] Step 1: Failing tests:

```go
package secrets

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCSVFormulaGuard_PrefixesTriggers(t *testing.T) {
	t.Parallel()
	for _, s := range []string{"=1+1", "+cmd", "-2", "@SUM(A1)", "\tx", "'quoted"} {
		assert.Equal(t, "'"+s, csvFormulaGuard(s), s)
	}
	for _, s := range []string{"", "plain", "a=b", "1-2"} {
		assert.Equal(t, s, csvFormulaGuard(s), s)
	}
}

func TestCSVFormulaGuard_RoundTrips(t *testing.T) {
	t.Parallel()
	for _, s := range []string{"", "=cmd|' /C calc'!A0", "-secret", "'already", "''two", "@x", "plain"} {
		assert.Equal(t, s, csvFormulaUnguard(csvFormulaGuard(s)), s)
	}
}
```

and, in `internal/services/secrets/csv_formula_roundtrip_test.go` (package `secrets_test`), a service round trip:

```go
func TestCSVExportImport_FormulaValuesRoundTripAndAreGuarded(t *testing.T) {
	ctx := context.Background()
	f := newImportFixture(t)
	for name, value := range map[string]string{"dash-secret": "-dash", "eq-secret": "=1+1", "quote-secret": "'lead"} {
		_, err := f.secretSvc.CreateSecret(ctx, secrets.CreateSecretRequest{UserID: f.userID, VaultID: f.vaultID, Name: name, Value: value})
		require.NoError(t, err)
	}

	data, err := f.secretSvc.ExportSecrets(ctx, secrets.ExportSecretsRequest{Scope: f.scope(), Format: "csv"})
	require.NoError(t, err)
	assert.Contains(t, string(data), "'=1+1")
	assert.NotContains(t, string(data), ",=1+1")

	g := newImportFixture(t)
	result, err := g.secretSvc.ImportSecrets(ctx, secrets.ImportSecretsRequest{Scope: g.scope(), Format: "csv", Data: data})
	require.NoError(t, err)
	assert.Equal(t, 3, result.ImportedCount)
	got, err := g.secretSvc.ListSecrets(ctx, g.scope(), nil, 0, 0)
	require.NoError(t, err)
	values := map[string]string{}
	for _, s := range got {
		values[s.Name] = s.Value
	}
	assert.Equal(t, "-dash", values["dash-secret"])
	assert.Equal(t, "=1+1", values["eq-secret"])
	assert.Equal(t, "'lead", values["quote-secret"])
}
```

Use the fixture-local `newImportFixture` twice: it swaps the global viper `master_key` per call, which is fine for sequential use but the second fixture replaces the first key; values are exported as plaintext so this is safe.

- [ ] Step 2: Run `go test ./internal/services/secrets/ -run 'TestCSVFormulaGuard|TestCSVExportImport_Formula' -count=1`. Expected: FAIL (helpers undefined).

- [ ] Step 3: Implement next to `escapeCR`:

```go
// csvFormulaGuard prefixes a single quote to a cell a spreadsheet would
// evaluate as a formula. A cell already starting with a quote is prefixed too,
// so csvFormulaUnguard can strip exactly one quote and restore every input.
func csvFormulaGuard(s string) string {
	if s == "" {
		return s
	}
	switch s[0] {
	case '=', '+', '-', '@', '\t', '\'':
		return "'" + s
	}
	return s
}

// csvFormulaUnguard reverses csvFormulaGuard by stripping one leading quote.
func csvFormulaUnguard(s string) string {
	if strings.HasPrefix(s, "'") {
		return s[1:]
	}
	return s
}
```

Export: `row := []string{csvFormulaGuard(escapeCR(secret.Name)), csvFormulaGuard(escapeCR(secret.Value))}` and `row = append(row, csvFormulaGuard(tagsField))`. Import: `Name: unescapeCR(csvFormulaUnguard(record[0]))`, `Value: unescapeCR(csvFormulaUnguard(record[1]))`, and `csvDecodeTags(csvFormulaUnguard(record[2]))` (guarded `record[2] != ""` check stays on the raw record). Because guard runs after `escapeCR` on export, unguard runs before `unescapeCR` on import (inverse order).

- [ ] Step 4: Run the Step 2 command; expected PASS. Run `go test ./internal/services/secrets/ ./cmd/secrets/ ./api/ -count=1`. Existing CSV round-trip tests (`csv_cr_escape_test.go`, `secret_service_test.go` lines ~1234 to 1583) that assert exact CSV bytes for values starting with a trigger character must be updated to the guarded form; values without a trigger are unchanged. CLI path: `cmd/secrets/export_test.go` and `import_cmd_test.go` mock the service, so they are unaffected; the service round trip above covers the CLI path because `cmd/secrets/export.go` and `import.go` call `ExportSecrets` and `ImportSecrets` directly.

- [ ] Step 5: Add the B84 entry to `.claude/known-bugs.md` (structure of B69): symptom (import stored names, values and tag counts create refuses; CSV export cells starting with `=`, `+`, `-`, `@` were spreadsheet formulas), root cause (`ImportSecrets` only checked for empty name or value; export wrote raw cells), fix (`ValidateSecretCreate` per item with `Invalid '<name>': ...` errors and `FailedCount`; `csvFormulaGuard`/`csvFormulaUnguard`), accepted behavior change (CSV exports now carry a leading `'` on guarded cells; importing a CSV written by an older version whose cell begins with `'` loses that one quote; JSON exports are unchanged), and the related open Low item from the issue: `UpdateSecret` is still not atomic across version, secret and tag writes (recorded here as a deferred item, not fixed in this plan).

- [ ] Step 6: Commit via the `dev-workflow-skills:1-git-commit` skill with footer `Fixes #48` (subject: "Fix: guard CSV formula cells and record B84").

---

### Task 12: Release note and full verification

**Files:**
- Create: `docs/release-notes/v4.6.1-secrets-and-error-responses.md` (style of `docs/release-notes/v4.6.0-narrow-global-vault-manage.md`: title line `# v4.6.1 — ...`, then "The breaking change", "Upgrade procedure" sections)
- Modify: `scripts/docsgen/docs.go:45` (add `{"docs/release-notes/v4.6.1-secrets-and-error-responses.md", "docs/release-notes/v4.6.1-secrets-and-error-responses.html"},` after the v4.6.0 line)

- [ ] Step 1: Write the release note. Sections: (1) 500 responses now carry a fixed `detailed_error` and the real error is in the server log under the `request_id`; clients that parsed `detailed_error` must use `request_id` instead; (2) duplicate names return 409 instead of 500; unsupported `content_type` returns 400; (3) authenticated responses send `Cache-Control: no-store`; (4) export omits disabled, expired and not-yet-active secrets, and version reads of such secrets return 403; (5) `PUT /secrets/{id}` no longer returns 403 when it enables a disabled secret, no longer returns 400 for an identical value, and returns a minimal body when the update disables or expires the secret; (6) import rejects items failing create validation, reporting `failed_count` and `errors`; (7) CSV export guards formula-leading cells with a leading `'` and import strips it. Upgrade procedure: rerun any export that must include disabled secrets after re-enabling them; update automation that keyed on `detailed_error` text.

- [ ] Step 2: Run `./scripts/docs.sh build` (renders the new page; confirm it exits 0). If the script needs a toolchain unavailable in this environment, run `cd scripts/docsgen && go build ./...` instead and note the limitation.

- [ ] Step 3: Full verification: `go build ./...`, `go vet ./...`, `go test ./... -count=1`. Expected: all PASS. State in the PR description that golangci-lint must run in CI or on a fixed toolchain because the local snap Go toolchain is incompatible.

- [ ] Step 4: Commit via the `dev-workflow-skills:1-git-commit` skill (subject: "docs: release note for error-response and secret lifecycle fixes").

---

## Self-Review

- **Spec coverage:** #41: SetInternalError (Task 1), 409 and 400 mapping with B55 (Task 2), jwks rotate, OIDC callback, `/health/ready` (untested, unreachable error branch), `errors_key.go` default arm (Tasks 1 and 3), Cache-Control (Task 4), response_shape, drift tests and OpenAPI (Tasks 4 and 5). #44: export (Task 7), GetVersion, GetLatestVersion and GetVersions (Task 6), enable-403 and equality oracle (Task 8). #48: per-item validation, name, 25600-byte cap and 15-tag limit (Task 9), per-item failure reporting over HTTP and the remote CLI (Task 10; the local CLI is already pinned by `TestImportCommand_ReturnsErrorAndPrintsDetailsOnFailure`), CSV formula escaping (Task 11). Release note and known-bugs B82 to B84 (Tasks 5, 8, 11, 12).
- **Placeholder scan:** Task 3's three `run...` helpers are specified by behavior and must be written against fixtures located with the stated grep; every other step shows code. No TBD or TODO left.
- **Type consistency:** `internalErrorDetail` and `logInternalError` (Task 1) are used in Task 3; `SetConflict` and `ErrInvalidContentType` (Task 2) are used in Tasks 8 and 10; `nameTakenChain()` (Task 2 test file) is reused in Task 8, same package `api`; `readAccessibleParent` (Task 6) and `accessibleOnly` (Task 7) are private and used in one place each; `ImportResponse` fields added in Task 10 match the YAML edit.
- **Assumptions:** release note version `v4.6.1` is a guess (latest existing is v4.6.0); confirm with the release owner. Task 8 answers 200 with a minimal body when the update disables the secret, which is a judgment call to confirm.
