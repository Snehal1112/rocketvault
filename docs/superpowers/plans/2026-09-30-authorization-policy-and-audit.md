# Authorization Policy and Audit Hardening Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (- [ ]) syntax for tracking.

**Goal:** Make explicit-deny policies for key crypto and backup operations evaluate identically over HTTP and the CLI, make non-data-plane route coverage fail closed by construction, and attribute and record every security-relevant policy, role and vault change and refusal in the audit trail.

**Architecture:** Three independent fixes, each owning its own B-number. B79 gives every key crypto and backup route its own `model.PolicyOperation` in `resolvePolicy`, adds `OpWrap`/`OpUnwrap`, and switches the CLI wrap/unwrap commands to them so both entry points pass the same triple to `AccessPolicyService.CheckAccess`. B80 replaces suffix matching of public paths with an exact set, reserves the colliding vault names for new vaults, and adds `api.VerifyRouteAuthorization`, an allow-list of non-data-plane routes checked in a test and at startup. B81 threads an `actorID uuid.UUID` through `RevokeAssignment`, `DeleteVault`/`RecoverVault`/`PurgeVault` and the access-policy CRUD methods, audits handler-level and CLI-level refusals, and puts a 90-day floor on audit retention.

**Tech Stack:** Go 1.24, gorilla/mux v1.8.1, testify (`assert`, `require`, `mock`), Cobra CLI, SQLite and Postgres through `internal/db`.

**Cross-plan ordering:** this plan must land before `2026-09-30-certificate-restore-renewal-isolation.md`, which replaces `internal/services/authorization/data_action_authz.go` wholesale. This plan edits `internal/services/authorization/data_action_authz_test.go:33` (the `RevokeAssignment` call sites), so the certificate plan must rebase its own test edits onto that change.

**Known unresolved gap (recorded as not fixed in B79):** `POST /{resource}/restore` still resolves to `OpRecover` in `resolvePolicy`, so an explicit deny on restore is not checked over HTTP. The CLI and HTTP paths therefore still differ for restore.

**Spec:**
- GitHub issue #42, "Explicit-deny policies for key encrypt, decrypt, wrap, unwrap and backup are not evaluated over HTTP" (B79)
- GitHub issue #50, "Non-data-plane routes fail open in middleware and rely on per-handler admin checks" (B80)
- GitHub issue #49, "Audit gaps: empty actors and missing entries for policy and role changes" (B81), which supersedes `.claude/known-bugs.md` § B58 and GitHub issue #18
- Source audit: static audit of `api/` on 2026-09-30, quoted in each issue body
- Prior art: `.claude/known-bugs.md` § B33 (sign/verify operations), § B16 and § B17 (audit of grant/revoke and item purge), § B58 (unattributed vault actors)

## Global Constraints

- Every commit goes through the `dev-workflow-skills:1-git-commit` plugin skill (Skill tool); never a freeform `git commit -m`.
- Every commit and tag is GPG signed with key `61D246B30285ED35`.
- Code comments are short full sentences that end with a punctuation mark.
- Before any PR: `go build ./...`, `go vet ./...` and `go test ./...` pass. `golangci-lint` fails in this environment (snap Go toolchain incompatibility), so lint runs in CI or on a fixed toolchain.
- CLI commands bypass HTTP middleware, so each behavior change is tested on both the HTTP path and the CLI path.
- Repositories stay pure CRUD; audit writes and authorization logic live in services or handlers.
- No schema change is made by this plan, so no `internal/db/db.go` migration is needed.
- B-numbers used: B79 (issue #42), B80 (issue #50), B81 (issue #49). No other B-number is created.
- The API base path is exactly `/api/v1` (`authzServices.DataPlaneBasePath`).
- The audit retention floor is exactly 90 days (`auditSvc.MinRetentionDays = 90`); the default stays 365.
- Reserved names for new vaults are exactly `login`, `health`, `refresh`, `register`.
- The background purge scheduler's actor is recorded as the literal string `system`, matching `internal/services/secrets/expiration_service.go:64`.

## Review Focus

1. Suffix collision in `resolvePolicy`: `/unwrap` must not resolve as `/wrap`, and a vault or path segment ending in an operation word must not change the resolved operation. Pinned by `TestResolvePolicy_KeyCryptoAndBackupResolveToTheirOwnOperations` (Task 1) and `TestKeyCryptoRoutesResolveToTheirOwnPolicyOperation` (Task 3).
2. A vault named after a public endpoint (`login`, `health`, `refresh`, `register`) at `/api/v1/vaults/{name}`: it must require a session and must not skip vault resolution. Pinned by `TestAuthenticationMiddleware_VaultNamedLikePublicEndpointRequiresToken` and `TestIsHealthProbe_ExactMatchOnly` (Task 4).
3. A route registered without `.Methods(...)`, which `WalkRoutes` silently skips and so would escape every route-inventory check. Pinned by `TestVerifyRouteAuthorization_RejectsMethodlessRoute` (Task 6).
4. `uuid.Nil` as an actor: the purge scheduler legitimately passes it and must be recorded as `system`, while HTTP and CLI callers must never pass it. Pinned by `TestPurgeVault_SchedulerActorIsRecordedAsSystem` (Task 9), `TestPurgeExpiredVaults_PassesSystemActor` (Task 9), `TestDeleteVault_AuditsCallerAsActor` (Task 9) and `TestVaultsDelete` (Task 9).
5. A stored `retention_days` below the new floor (for example `1`, which the old API accepted): the next purge must not delete anything younger than 90 days. Pinned by `TestComplianceReportService_StoredRetentionBelowFloorIsClamped` (Task 12).

---

## B79: Explicit deny for key crypto and backup operations (issue #42)

### CLI versus HTTP, established before designing

| Operation | CLI command | CLI passes today | HTTP resolves today | After this plan (both) |
|---|---|---|---|---|
| sign | `cmd/keys/sign.go:67` | `OpSign` | `OpSign` (B33) | `OpSign` |
| verify | `cmd/keys/verify.go:71` | `OpVerify` | `OpVerify` (B33) | `OpVerify` |
| wrap | `cmd/keys/wrap.go:67` | `OpCreate` | `OpCreate` | `OpWrap` (new) |
| unwrap | `cmd/keys/unwrap.go:67` | `OpCreate` | `OpCreate` | `OpUnwrap` (new) |
| encrypt | none (HTTP only) | n/a | `OpCreate` | `OpEncrypt` (existing constant) |
| decrypt | none (HTTP only) | n/a | `OpCreate` | `OpDecrypt` (existing constant) |
| backup | none (HTTP only; `cmd/backup.go` is the whole-database backup, not item backup) | n/a | `OpCreate` | `OpBackup` (existing constant) |

Decision: reuse `OpEncrypt`, `OpDecrypt` and `OpBackup`, and add `OpWrap` (`"wrap"`) and `OpUnwrap` (`"unwrap"`). Reusing `OpEncrypt` for wrap would repeat the defect this issue is about: a deny on encrypt would collaterally block wrap, as a deny on create blocks all five today. Azure keeps them apart in both access-policy key permissions (`wrapKey`, `unwrapKey`) and RBAC data actions (`keys/wrap/action`, `keys/unwrap/action`), and RocketVault already models the data actions separately (`model.ActionKeysWrap`, `model.ActionKeysUnwrap`). The existing comment that wrap and unwrap "deliberately" use `OpCreate` described agreement, not intent, so the CLI moves with HTTP.

### Task 1: Resolve key crypto and backup routes to their own operations over HTTP

**Files:**
- Modify: `model/access_policy.go:37-55` (constants), `model/access_policy.go:106-114` (`ValidatePolicyOperation`)
- Modify: `internal/middleware/middleware.go:443-451` (`resolvePolicy`, the B33 arm)
- Modify: `internal/services/authorization/roles.go:20` (stale comment)
- Modify: `docs/api-specification.yaml:5488-5507` (operation enum)
- Create: `model/access_policy_test.go`
- Test: `internal/middleware/middleware_test.go:1478-1511` (B33 table), new tests appended after it

**Interfaces:**
- Consumes: `setupDataPlaneMiddlewareTest(t) (*Middleware, *MockAccessPolicyService, *MockRoleAssignmentService)` and `dataPlaneRequest(method, path string, userID, vaultID uuid.UUID) *http.Request` from `internal/middleware/middleware_test.go:1262-1282`.
- Produces: `model.OpWrap PolicyOperation = "wrap"`, `model.OpUnwrap PolicyOperation = "unwrap"`; `resolvePolicy` returns `OpEncrypt`, `OpDecrypt`, `OpWrap`, `OpUnwrap`, `OpBackup` for POST `/encrypt`, `/decrypt`, `/wrap`, `/unwrap`, `/backup`.

- [ ] **Step 1: Write the failing model test**

Create `model/access_policy_test.go`:

```go
package model

import "testing"

// TestValidatePolicyOperation_AcceptsWrapAndUnwrap pins B79: an explicit deny
// on wrap or unwrap must be expressible, so both are valid operations.
func TestValidatePolicyOperation_AcceptsWrapAndUnwrap(t *testing.T) {
	for _, op := range []string{"wrap", "unwrap", "encrypt", "decrypt", "backup"} {
		if err := ValidatePolicyOperation(op); err != nil {
			t.Fatalf("ValidatePolicyOperation(%q) = %v, want nil", op, err)
		}
	}
	if OpWrap != "wrap" || OpUnwrap != "unwrap" {
		t.Fatalf("OpWrap=%q OpUnwrap=%q, want wrap and unwrap", OpWrap, OpUnwrap)
	}
}
```

- [ ] **Step 2: Run it and see it fail**

Run: `go test ./model/ -run TestValidatePolicyOperation_AcceptsWrapAndUnwrap -count=1`
Expected: build failure, `undefined: OpWrap` and `undefined: OpUnwrap`.

- [ ] **Step 3: Add the constants and validation**

In `model/access_policy.go`, after `OpDecrypt PolicyOperation = "decrypt"` add:

```go
	OpWrap    PolicyOperation = "wrap"
	OpUnwrap  PolicyOperation = "unwrap"
```

Replace the `ValidatePolicyOperation` switch case with:

```go
	case OpGet, OpList, OpSet, OpCreate, OpDelete, OpBackup, OpRestore, OpPurge,
		OpRecover, OpRotate, OpSign, OpVerify, OpEncrypt, OpDecrypt, OpWrap, OpUnwrap,
		OpImport, OpRenew, OpManage:
		return nil
```

In `docs/api-specification.yaml`, in the access-policy `operation` enum (after `- decrypt` at line 5504), add:

```yaml
            - wrap
            - unwrap
```

- [ ] **Step 4: Run it and see it pass**

Run: `go test ./model/ -run TestValidatePolicyOperation_AcceptsWrapAndUnwrap -count=1`
Expected: `ok  	rocketvault/model`.

- [ ] **Step 5: Write the failing middleware tests**

In `internal/middleware/middleware_test.go`, replace `TestResolvePolicy_SignAndVerifyResolveToTheirOwnOperations` (lines 1477-1511, including its doc comment) with:

```go
// TestResolvePolicy_KeyCryptoAndBackupResolveToTheirOwnOperations is the
// regression for B33 (sign, verify) and B79 (encrypt, decrypt, wrap, unwrap,
// backup). Each POST route resolves to its own operation, so an explicit-deny
// policy naming it is evaluated over HTTP exactly as on the CLI, and a deny on
// create no longer blocks all of them collaterally.
func TestResolvePolicy_KeyCryptoAndBackupResolveToTheirOwnOperations(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name         string
		path         string
		wantResource model.PolicyResourceType
		wantOp       model.PolicyOperation
	}{
		{"sign, flat", "/api/v1/keys/abc/sign", model.PolicyResourceKeys, model.OpSign},
		{"sign, scoped", "/api/v1/vaults/prod/keys/abc/sign", model.PolicyResourceKeys, model.OpSign},
		{"verify, flat", "/api/v1/keys/abc/verify", model.PolicyResourceKeys, model.OpVerify},
		{"verify, scoped", "/api/v1/vaults/prod/keys/abc/verify", model.PolicyResourceKeys, model.OpVerify},
		{"encrypt, flat", "/api/v1/keys/abc/encrypt", model.PolicyResourceKeys, model.OpEncrypt},
		{"encrypt, scoped", "/api/v1/vaults/prod/keys/abc/encrypt", model.PolicyResourceKeys, model.OpEncrypt},
		{"decrypt, flat", "/api/v1/keys/abc/decrypt", model.PolicyResourceKeys, model.OpDecrypt},
		{"decrypt, scoped", "/api/v1/vaults/prod/keys/abc/decrypt", model.PolicyResourceKeys, model.OpDecrypt},
		{"wrap, flat", "/api/v1/keys/abc/wrap", model.PolicyResourceKeys, model.OpWrap},
		{"wrap, scoped", "/api/v1/vaults/prod/keys/abc/wrap", model.PolicyResourceKeys, model.OpWrap},
		{"unwrap, flat", "/api/v1/keys/abc/unwrap", model.PolicyResourceKeys, model.OpUnwrap},
		{"unwrap, scoped", "/api/v1/vaults/prod/keys/abc/unwrap", model.PolicyResourceKeys, model.OpUnwrap},
		{"key backup, flat", "/api/v1/keys/abc/backup", model.PolicyResourceKeys, model.OpBackup},
		{"key backup, scoped", "/api/v1/vaults/prod/keys/abc/backup", model.PolicyResourceKeys, model.OpBackup},
		{"secret backup", "/api/v1/secrets/abc/backup", model.PolicyResourceSecrets, model.OpBackup},
		{"certificate backup", "/api/v1/certificates/abc/backup", model.PolicyResourceCertificates, model.OpBackup},
		// Unchanged neighbours, to pin that the new cases did not widen.
		{"vault named wrap, key create", "/api/v1/vaults/wrap/keys", model.PolicyResourceKeys, model.OpCreate},
		{"rotate keeps its own operation", "/api/v1/keys/abc/rotate", model.PolicyResourceKeys, model.OpRotate},
		{"key create stays create", "/api/v1/keys", model.PolicyResourceKeys, model.OpCreate},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			resourceType, op := resolvePolicy(http.MethodPost, c.path)
			assert.Equal(t, c.wantResource, resourceType, "resolvePolicy(POST, %s) resource", c.path)
			assert.Equal(t, c.wantOp, op, "resolvePolicy(POST, %s) operation", c.path)
		})
	}
}

// TestPolicyMiddleware_ExplicitDenyEvaluatedPerKeyOperation proves, end to end
// through PolicyMiddleware, that a deny naming each operation blocks its route
// before the role-assignment check runs (B79).
func TestPolicyMiddleware_ExplicitDenyEvaluatedPerKeyOperation(t *testing.T) {
	t.Parallel()

	cases := []struct {
		path     string
		resource model.PolicyResourceType
		op       model.PolicyOperation
	}{
		{"/api/v1/keys/abc/encrypt", model.PolicyResourceKeys, model.OpEncrypt},
		{"/api/v1/vaults/prod/keys/abc/encrypt", model.PolicyResourceKeys, model.OpEncrypt},
		{"/api/v1/keys/abc/decrypt", model.PolicyResourceKeys, model.OpDecrypt},
		{"/api/v1/vaults/prod/keys/abc/decrypt", model.PolicyResourceKeys, model.OpDecrypt},
		{"/api/v1/keys/abc/wrap", model.PolicyResourceKeys, model.OpWrap},
		{"/api/v1/vaults/prod/keys/abc/wrap", model.PolicyResourceKeys, model.OpWrap},
		{"/api/v1/keys/abc/unwrap", model.PolicyResourceKeys, model.OpUnwrap},
		{"/api/v1/vaults/prod/keys/abc/unwrap", model.PolicyResourceKeys, model.OpUnwrap},
		{"/api/v1/keys/abc/backup", model.PolicyResourceKeys, model.OpBackup},
		{"/api/v1/vaults/prod/keys/abc/backup", model.PolicyResourceKeys, model.OpBackup},
		{"/api/v1/secrets/abc/backup", model.PolicyResourceSecrets, model.OpBackup},
		{"/api/v1/certificates/abc/backup", model.PolicyResourceCertificates, model.OpBackup},
	}
	for _, c := range cases {
		t.Run(c.path, func(t *testing.T) {
			t.Parallel()
			mw, policySvc, roleSvc := setupDataPlaneMiddlewareTest(t)

			userID, vaultID := uuid.New(), uuid.New()
			policySvc.On("CheckAccess", mock.Anything, userID, c.resource, c.op, vaultID).
				Return(authzServices.AccessDenied, nil)

			nextCalled := false
			rr := httptest.NewRecorder()
			mw.PolicyMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				nextCalled = true
			})).ServeHTTP(rr, dataPlaneRequest(http.MethodPost, c.path, userID, vaultID))

			assert.False(t, nextCalled, "the explicit deny on %s must block the request", c.op)
			assert.Equal(t, http.StatusForbidden, rr.Code)
			policySvc.AssertExpectations(t)
			roleSvc.AssertNotCalled(t, "HasDataAction", mock.Anything, mock.Anything, mock.Anything, mock.Anything)
		})
	}
}

// TestPolicyMiddleware_CreateDenyNoLongerBlocksKeyCrypto pins the other half of
// B79: before the fix, a deny on (keys, create) blocked encrypt collaterally.
func TestPolicyMiddleware_CreateDenyNoLongerBlocksKeyCrypto(t *testing.T) {
	t.Parallel()
	mw, policySvc, roleSvc := setupDataPlaneMiddlewareTest(t)

	userID, vaultID := uuid.New(), uuid.New()
	policySvc.On("CheckAccess", mock.Anything, userID, model.PolicyResourceKeys, model.OpCreate, vaultID).
		Return(authzServices.AccessDenied, nil).Maybe()
	policySvc.On("CheckAccess", mock.Anything, userID, model.PolicyResourceKeys, model.OpEncrypt, vaultID).
		Return(authzServices.AccessFallback, nil)
	roleSvc.On("HasDataAction", mock.Anything, userID, vaultID, model.ActionKeysEncrypt).
		Return(true, nil)

	nextCalled := false
	rr := httptest.NewRecorder()
	mw.PolicyMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
		w.WriteHeader(http.StatusOK)
	})).ServeHTTP(rr, dataPlaneRequest(http.MethodPost, "/api/v1/keys/abc/encrypt", userID, vaultID))

	assert.True(t, nextCalled, "a deny on create must not block encrypt")
	assert.Equal(t, http.StatusOK, rr.Code)
}
```

- [ ] **Step 6: Run them and see them fail**

Run: `go test ./internal/middleware/ -run 'TestResolvePolicy_KeyCryptoAndBackup|TestPolicyMiddleware_ExplicitDenyEvaluatedPerKeyOperation|TestPolicyMiddleware_CreateDenyNoLongerBlocksKeyCrypto' -count=1`
Expected: FAIL. The resolver table reports `operation: expected "encrypt", actual "create"` (and likewise for decrypt, wrap, unwrap, backup); the per-operation deny subtests fail with a testify `mock: Unexpected Method Call` for `CheckAccess(..., "create", ...)`; the create-deny test reports `a deny on create must not block encrypt` and status 403.

- [ ] **Step 7: Implement the resolver arms**

In `internal/middleware/middleware.go`, replace lines 443-451 (the B33 comment and the sign/verify arms) with:

```go
	// B33 and B79: every key crypto route and item backup resolves to its own
	// operation, so an explicit-deny policy naming one is evaluated over HTTP
	// exactly as on the CLI, which passes the same operation. /unwrap is
	// listed before /wrap for readability; the leading slash already keeps
	// "/unwrap" from matching the "/wrap" suffix.
	case strings.HasSuffix(path, "/sign") && method == http.MethodPost:
		op = model.OpSign
	case strings.HasSuffix(path, "/verify") && method == http.MethodPost:
		op = model.OpVerify
	case strings.HasSuffix(path, "/encrypt") && method == http.MethodPost:
		op = model.OpEncrypt
	case strings.HasSuffix(path, "/decrypt") && method == http.MethodPost:
		op = model.OpDecrypt
	case strings.HasSuffix(path, "/unwrap") && method == http.MethodPost:
		op = model.OpUnwrap
	case strings.HasSuffix(path, "/wrap") && method == http.MethodPost:
		op = model.OpWrap
	case strings.HasSuffix(path, "/backup") && method == http.MethodPost:
		op = model.OpBackup
```

In `internal/services/authorization/roles.go:20`, replace the comment line
`// Only operations defined in model/access_policy.go are used (no wrap/unwrap).` with:

```go
// These legacy bundles are frozen and can no longer be granted, so they omit
// the wrap and unwrap operations added for B79.
```

- [ ] **Step 8: Run them and see them pass**

Run: `go test ./internal/middleware/ ./model/ ./internal/services/authorization/ -count=1`
Expected: `ok` for all three packages.

- [ ] **Step 9: Commit**

Invoke the `dev-workflow-skills:1-git-commit` skill via the Skill tool to commit `model/access_policy.go`, `model/access_policy_test.go`, `internal/middleware/middleware.go`, `internal/middleware/middleware_test.go`, `internal/services/authorization/roles.go` and `docs/api-specification.yaml`. The commit is GPG signed with key 61D246B30285ED35.

### Task 2: Pass OpWrap and OpUnwrap from the CLI

**Files:**
- Modify: `cmd/keys/wrap.go:67`, `cmd/keys/unwrap.go:67`
- Test: `cmd/keys/keys_cmd_test.go:1470` (`TestWrapCmd_Authorized`), `cmd/keys/keys_cmd_test.go:1642` (`TestUnwrapCmd_Authorized`), new tests appended

**Interfaces:**
- Consumes: `model.OpWrap`, `model.OpUnwrap` (Task 1); `newAllowedContainer(keySvc, cryptoSvc) (*keysTestContainer, uuid.UUID)`, `newTestCmd`, `setFlags`, `newLogger` from `cmd/keys/keys_cmd_test.go`.
- Produces: `wrapCmd` and `unwrapCmd` call `CheckAccess(..., model.PolicyResourceKeys, model.OpWrap|OpUnwrap, vaultID)`.

- [ ] **Step 1: Update the authorized tests and write the failing deny tests**

In `cmd/keys/keys_cmd_test.go`, change line 1470 to use `model.OpWrap` and line 1642 to use `model.OpUnwrap` in place of `model.OpCreate`. Append:

```go
// TestWrapCmd_ExplicitDenyOnWrapIsEvaluated is the CLI half of B79: a deny on
// (keys, wrap) must refuse the command, the same decision HTTP now reaches.
func TestWrapCmd_ExplicitDenyOnWrapIsEvaluated(t *testing.T) {
	cryptoSvc := &keyCmdCryptoService{}
	userID := uuid.New()
	keyID := uuid.New()
	sc, vaultID := newAllowedContainer(nil, cryptoSvc)

	policies := &testutils.MockAccessPolicyService{}
	policies.On("CheckAccess", mock.Anything, userID, model.PolicyResourceKeys, model.OpWrap, vaultID).
		Return(authzServices.AccessDenied, nil).Once()
	sc.AccessPolicyService = policies

	claims := &model.Claims{UserID: userID, Roles: []string{model.RoleAdmin}}
	ctx := context.WithValue(context.Background(), common.ClaimsKey, claims)
	ctx = context.WithValue(ctx, common.LogKey, newLogger())
	ctx = context.WithValue(ctx, common.ServiceContainerKey, sc)

	cmd, _ := newTestCmd(wrapCmd.RunE, nil)
	setFlags(cmd, map[string]any{"key-id": keyID.String(),
		"key-material": base64.StdEncoding.EncodeToString([]byte("material"))})
	cmd.SetContext(ctx)
	err := cmd.Execute()
	assert.ErrorContains(t, err, "forbidden")
	cryptoSvc.AssertNotCalled(t, "WrapKey", mock.Anything, mock.Anything)
	policies.AssertExpectations(t)
}

// TestUnwrapCmd_ExplicitDenyOnUnwrapIsEvaluated mirrors the wrap case.
func TestUnwrapCmd_ExplicitDenyOnUnwrapIsEvaluated(t *testing.T) {
	cryptoSvc := &keyCmdCryptoService{}
	userID := uuid.New()
	keyID := uuid.New()
	sc, vaultID := newAllowedContainer(nil, cryptoSvc)

	policies := &testutils.MockAccessPolicyService{}
	policies.On("CheckAccess", mock.Anything, userID, model.PolicyResourceKeys, model.OpUnwrap, vaultID).
		Return(authzServices.AccessDenied, nil).Once()
	sc.AccessPolicyService = policies

	claims := &model.Claims{UserID: userID, Roles: []string{model.RoleAdmin}}
	ctx := context.WithValue(context.Background(), common.ClaimsKey, claims)
	ctx = context.WithValue(ctx, common.LogKey, newLogger())
	ctx = context.WithValue(ctx, common.ServiceContainerKey, sc)

	cmd, _ := newTestCmd(unwrapCmd.RunE, nil)
	setFlags(cmd, map[string]any{"key-id": keyID.String(),
		"wrapped-key": base64.StdEncoding.EncodeToString([]byte("wrapped"))})
	cmd.SetContext(ctx)
	err := cmd.Execute()
	assert.ErrorContains(t, err, "forbidden")
	cryptoSvc.AssertNotCalled(t, "UnwrapKey", mock.Anything, mock.Anything)
	policies.AssertExpectations(t)
}
```

- [ ] **Step 2: Run them and see them fail**

Run: `go test ./cmd/keys/ -run 'TestWrapCmd|TestUnwrapCmd' -count=1`
Expected: FAIL with testify `mock: Unexpected Method Call` for `CheckAccess(..., "create", ...)` in all four changed or new tests.

- [ ] **Step 3: Switch the CLI operations**

`cmd/keys/wrap.go:67`:

```go
			Audit: "wrap_key", Action: model.ActionKeysWrap, Policy: model.OpWrap,
```

`cmd/keys/unwrap.go:67`:

```go
			Audit: "unwrap_key", Action: model.ActionKeysUnwrap, Policy: model.OpUnwrap,
```

- [ ] **Step 4: Run them and see them pass**

Run: `go test ./cmd/keys/ -count=1`
Expected: `ok  	rocketvault/cmd/keys`.

- [ ] **Step 5: Commit**

Invoke the `dev-workflow-skills:1-git-commit` skill via the Skill tool for `cmd/keys/wrap.go`, `cmd/keys/unwrap.go` and `cmd/keys/keys_cmd_test.go` (GPG signed, key 61D246B30285ED35).

### Task 3: Router-walk proof of per-operation resolution, and the B79 entry

**Files:**
- Modify: `internal/middleware/middleware.go` (add `ResolvePolicy` directly below `resolvePolicy`, which ends at line 464)
- Create: `api/route_policy_operation_test.go`
- Modify: `.claude/known-bugs.md` (insert B79 after the B71 section, before `## Deferred Refactors` at line 4270)

**Interfaces:**
- Consumes: `routerWalkContainer` and `policyContainer` (`api/router_authorization_matrix_test.go:25-31`, `api/access_policies_test.go`), `WalkRoutes(router) ([]RouteInfo, error)` (`api/route_inventory.go:17`), `userTestLog()` (`api/users_test.go:48`).
- Produces: `func middleware.ResolvePolicy(method, path string) (model.PolicyResourceType, model.PolicyOperation)`.

- [ ] **Step 1: Write the failing router test**

Create `api/route_policy_operation_test.go`:

```go
// Package api — proves every registered crypto and backup route resolves to
// the policy operation the CLI passes for the same command (B79).
package api

import (
	"net/http"
	"strings"
	"testing"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"rocketvault/app"
	"rocketvault/internal/middleware"
	"rocketvault/model"
)

// TestKeyCryptoRoutesResolveToTheirOwnPolicyOperation walks the real router
// and checks each POST route ending in a crypto or backup verb. The CLI side
// of the same table is pinned in cmd/keys: sign.go passes OpSign, verify.go
// OpVerify, wrap.go OpWrap and unwrap.go OpUnwrap. Encrypt, decrypt and item
// backup have no CLI command.
func TestKeyCryptoRoutesResolveToTheirOwnPolicyOperation(t *testing.T) {
	container := &routerWalkContainer{policyContainer: &policyContainer{}, logger: userTestLog()}
	a := &app.App{ServiceContainer: container, Logger: userTestLog()}
	router := mux.NewRouter()
	require.NotNil(t, Init(WithAPP(a), WithRouter(router), WithBasePath("/api/v1"), WithLogger(userTestLog())))

	want := map[string]model.PolicyOperation{
		"sign":    model.OpSign,
		"verify":  model.OpVerify,
		"encrypt": model.OpEncrypt,
		"decrypt": model.OpDecrypt,
		"wrap":    model.OpWrap,
		"unwrap":  model.OpUnwrap,
		"backup":  model.OpBackup,
	}

	routes, err := WalkRoutes(router)
	require.NoError(t, err)

	found := map[string]int{}
	for _, rt := range routes {
		if rt.Method != http.MethodPost {
			continue
		}
		verb := rt.Path[strings.LastIndex(rt.Path, "/")+1:]
		wantOp, ok := want[verb]
		if !ok {
			continue
		}
		_, op := middleware.ResolvePolicy(rt.Method, rt.Path)
		assert.Equal(t, wantOp, op, "%s %s", rt.Method, rt.Path)
		found[verb]++
	}

	// Each key verb has a flat and a vault-scoped route. Backup also exists for
	// secrets and certificates, so it has six.
	for verb := range want {
		expected := 2
		if verb == "backup" {
			expected = 6
		}
		assert.Equal(t, expected, found[verb], "registered POST routes ending in /%s", verb)
	}
}
```

- [ ] **Step 2: Run it and see it fail**

Run: `go test ./api/ -run TestKeyCryptoRoutesResolveToTheirOwnPolicyOperation -count=1`
Expected: build failure, `undefined: middleware.ResolvePolicy`.

- [ ] **Step 3: Export the resolver**

In `internal/middleware/middleware.go`, directly after the closing brace of `resolvePolicy`, add:

```go
// ResolvePolicy exposes resolvePolicy so a router walk in another package can
// prove every registered route resolves to the operation the CLI passes.
func ResolvePolicy(method, path string) (model.PolicyResourceType, model.PolicyOperation) {
	return resolvePolicy(method, path)
}
```

- [ ] **Step 4: Run it and see it pass**

Run: `go test ./api/ -run TestKeyCryptoRoutesResolveToTheirOwnPolicyOperation -count=1`
Expected: `ok  	rocketvault/api`.

- [ ] **Step 5: Add the B79 known-bugs entry**

Insert into `.claude/known-bugs.md` immediately before `## Deferred Refactors`:

```markdown
### B79 — Explicit-deny policies for key encrypt, decrypt, wrap, unwrap and backup were not evaluated over HTTP

**Status**: Fixed 2026-09-30 (GitHub #42)
**Severity**: Medium — an explicit deny, the one mechanism that overrides a
role grant, silently did nothing for five operations over HTTP, and a deny on
`create` blocked all five as collateral damage.
**Files**: `internal/middleware/middleware.go` (`resolvePolicy`),
`model/access_policy.go`, `cmd/keys/wrap.go`, `cmd/keys/unwrap.go`

**Symptom**: B33 gave `/sign` and `/verify` their own policy operations. The
remaining POST routes `/encrypt`, `/decrypt`, `/wrap`, `/unwrap` and
`/{id}/backup` fell to the plain POST arm and resolved to `OpCreate`, so a
deny naming `encrypt`, `decrypt` or `backup` was never looked up, and a deny
on `create` refused every one of them.

**Root cause**: `resolvePolicy` special-cased only the verbs B33 needed. The
code comment that justified leaving wrap and unwrap on `OpCreate` described
the CLI's then-current value, not a design decision; encrypt, decrypt and item
backup have no CLI command at all, so nothing forced a choice.

**What was fixed**: `resolvePolicy` maps `/encrypt` to `OpEncrypt`, `/decrypt`
to `OpDecrypt`, `/wrap` to the new `OpWrap`, `/unwrap` to the new `OpUnwrap`
and item `/backup` (keys, secrets and certificates) to `OpBackup`. The CLI
`keys wrap` and `keys unwrap` commands pass `OpWrap` and `OpUnwrap`, so both
entry points evaluate the same triple. Wrap and unwrap got their own
operations rather than reusing encrypt and decrypt, matching Azure's separate
`wrapKey`/`unwrapKey` permissions and avoiding the same collateral blocking
one level down.

**Accepted behavior change**: a deny on `(keys, create)` no longer blocks
encrypt, decrypt, wrap, unwrap or backup, and a deny on `(secrets|certificates,
create)` no longer blocks item backup. An operator who relied on that side
effect must add denies naming the specific operations (see
`docs/release-notes/v4.7.0-authorization-policy-and-audit.md`).

**Not fixed here**: `POST /{resource}/restore` (restore from a backup blob)
still resolves to `OpRecover`, because its suffix matches the soft-delete
`/deleted/{resource}/{id}/restore` route. A deny on `restore` is therefore
still not evaluated over HTTP. It has no CLI command.

---
```

- [ ] **Step 6: Commit**

Invoke the `dev-workflow-skills:1-git-commit` skill via the Skill tool for `internal/middleware/middleware.go`, `api/route_policy_operation_test.go` and `.claude/known-bugs.md`, with a `Fixes #42` footer (GPG signed, key 61D246B30285ED35).

---

## B80: Non-data-plane routes fail open (issue #50)

Design choice: the issue allows either default-deny in the middleware or an explicit allow-list checked at startup. This plan uses the allow-list. Default-deny would need `PolicyMiddleware` to understand admin, self-service and vault-management gates that today live, correctly, in the handlers; duplicating them in middleware creates a second source of truth that can drift. The allow-list instead makes an unclassified route a test failure and a boot failure, which is the property the issue asks for ("coverage ... guaranteed by construction"). The base-path assertion the issue asks for already exists at startup (`bootstrap/bootstrap.go:172`, `validateAuthorizationBasePath`, called at line 252); Task 6 repeats it inside `VerifyRouteAuthorization` so any caller of `api.Init` gets it, and Task 7 updates the comments that still describe it as missing.

### Task 4: Exact-path matching for public endpoints and health probes

**Files:**
- Modify: `internal/middleware/middleware.go:235-245` (`isHealthProbe`), `:268-282` (`AuthenticationMiddleware` skip), `:335-349` (`AuthorizationMiddleware` skip)
- Test: `internal/middleware/middleware_test.go:414-429` (two public cases), new tests appended

**Interfaces:**
- Consumes: `authzServices.DataPlaneBasePath`; `setupTestMiddleware()` from `internal/middleware/middleware_test.go` (returns `mw, _, mockAuthService, _`).
- Produces: `func middleware.IsPublicPath(path string) bool`, `func middleware.PublicPaths() []string` (sorted).

- [ ] **Step 1: Write the failing tests**

In `internal/middleware/middleware_test.go`, `TestAuthenticationMiddleware`: change the `path` of the case `"public endpoint - health"` from `"/health"` to `"/api/v1/health"`, and the case `"public endpoint - login"` from `"/login"` to `"/api/v1/users/login"`. Append:

```go
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
			})).ServeHTTP(rr, httptest.NewRequest(http.MethodDelete, "/api/v1/vaults/"+name, nil))

			assert.False(t, nextCalled, "a vault named %q must not be treated as a public endpoint", name)
			assert.Equal(t, http.StatusUnauthorized, rr.Code)
		})
	}
}

// TestIsPublicPath_ExactMatchOnly pins the public set and its exactness.
func TestIsPublicPath_ExactMatchOnly(t *testing.T) {
	t.Parallel()
	for _, p := range []string{"/api/v1/health", "/api/v1/health/ready", "/api/v1/health/live",
		"/api/v1/users/login", "/api/v1/users/refresh", "/api/v1/oauth2/token",
		"/api/v1/oidc/login", "/api/v1/oidc/callback"} {
		assert.True(t, IsPublicPath(p), "%s must be public", p)
	}
	for _, p := range []string{"/api/v1/vaults/login", "/api/v1/vaults/health", "/api/v1/vaults/refresh",
		"/api/v1/vaults/register", "/api/v1/health/database", "/api/v1/register", "/api/v1/auth/login",
		"/health", "/login"} {
		assert.False(t, IsPublicPath(p), "%s must not be public", p)
	}
	assert.Len(t, PublicPaths(), 8)
}

// TestIsHealthProbe_ExactMatchOnly pins that a vault named health is still
// resolved and rate limited like any other vault.
func TestIsHealthProbe_ExactMatchOnly(t *testing.T) {
	t.Parallel()
	for _, p := range []string{"/api/v1/health", "/api/v1/health/ready", "/api/v1/health/live", "/api/v1/health/database"} {
		assert.True(t, isHealthProbe(p), p)
	}
	for _, p := range []string{"/api/v1/vaults/health", "/api/v1/vaults/prod/secrets/health", "/health"} {
		assert.False(t, isHealthProbe(p), p)
	}
}
```

- [ ] **Step 2: Run them and see them fail**

Run: `go test ./internal/middleware/ -run 'TestAuthenticationMiddleware|TestIsPublicPath_ExactMatchOnly|TestIsHealthProbe_ExactMatchOnly' -count=1`
Expected: build failure, `undefined: IsPublicPath` and `undefined: PublicPaths`. After a stub is added, the vault-name subtests would report status 200 instead of 401.

- [ ] **Step 3: Implement exact matching**

In `internal/middleware/middleware.go`, add `"sort"` to the standard-library imports. Replace `isHealthProbe` (lines 235-245, keeping its doc comment's first two sentences) with:

```go
// isHealthProbe reports whether path is a health probe that carries no vault.
// VaultResolutionMiddleware skips these, so anything downstream that needs a
// resolved vault must skip them too. Matching is exact, so a vault named
// "health" is resolved like any other vault.
func isHealthProbe(path string) bool {
	_, ok := healthProbePaths[path]
	return ok
}

// healthProbePaths are the health routes that carry no vault. The set
// includes /health/database, which is not public.
var healthProbePaths = map[string]struct{}{
	authzServices.DataPlaneBasePath + "/health":          {},
	authzServices.DataPlaneBasePath + "/health/ready":    {},
	authzServices.DataPlaneBasePath + "/health/live":     {},
	authzServices.DataPlaneBasePath + "/health/database": {},
}

// publicPaths are the only request paths served without a session. Matching
// is exact: suffix matching once made any vault named login, health, refresh
// or register skip authentication (B80). The oauth2 and oidc entries are
// registered on a router outside this middleware chain and are listed only as
// defense in depth. The bootstrap guarantees the base path equals
// DataPlaneBasePath.
var publicPaths = map[string]struct{}{
	authzServices.DataPlaneBasePath + "/health":        {},
	authzServices.DataPlaneBasePath + "/health/ready":  {},
	authzServices.DataPlaneBasePath + "/health/live":   {},
	authzServices.DataPlaneBasePath + "/users/login":   {},
	authzServices.DataPlaneBasePath + "/users/refresh": {},
	authzServices.DataPlaneBasePath + "/oauth2/token":  {},
	authzServices.DataPlaneBasePath + "/oidc/login":    {},
	authzServices.DataPlaneBasePath + "/oidc/callback": {},
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
```

In `AuthenticationMiddleware`, replace the whole `if strings.HasSuffix(r.URL.Path, "/health") || ... strings.HasSuffix(r.URL.Path, "/oidc/callback") {` condition (lines 268-279) and its comment with:

```go
		// Skip authentication for the exact public paths only.
		if IsPublicPath(r.URL.Path) {
```

In `AuthorizationMiddleware`, replace the same condition (lines 335-346) and its comment with:

```go
		// Skip authorization for the same exact public paths.
		if IsPublicPath(r.URL.Path) {
```

The dropped `/register` and `/auth/{login,register,refresh}` entries matched no registered route; requests to them now get 401 instead of reaching the 404 handler unauthenticated.

- [ ] **Step 4: Run them and see them pass**

Run: `go test ./internal/middleware/ ./api/ -count=1`
Expected: `ok` for both packages.

- [ ] **Step 5: Commit**

Invoke the `dev-workflow-skills:1-git-commit` skill via the Skill tool for `internal/middleware/middleware.go` and `internal/middleware/middleware_test.go` (GPG signed, key 61D246B30285ED35).

### Task 5: Reserve the colliding names for new vaults

The brief placed the reservation in `ValidateVaultName`. That function is also the syntax check for lookups (`internal/mcpserver/gating.go:95`), so reserving there would lock MCP callers out of any existing vault with one of these names. This task adds `ValidateNewVaultName` for the two create paths instead; existing vaults stay reachable everywhere.

**Files:**
- Modify: `model/vault.go:1-11` (imports), `model/vault.go:40-46` (add after `ValidateVaultName`)
- Modify: `internal/services/vaults/vault_service.go:324` (`CreateVault`), `:366` (`CreateVaultProvisioned`)
- Test: `model/vault_test.go`, `internal/services/vaults/vault_service_test.go`

**Interfaces:**
- Consumes: `model.ValidateVaultName(name string) error`.
- Produces: `func model.ValidateNewVaultName(name string) error`, `var model.ErrReservedVaultName error`.

- [ ] **Step 1: Write the failing tests**

Append to `model/vault_test.go`:

```go
// TestValidateNewVaultName_RefusesReservedNames pins B80's reservation, and
// that lookups through ValidateVaultName still accept the same names.
func TestValidateNewVaultName_RefusesReservedNames(t *testing.T) {
	for _, name := range []string{"login", "health", "refresh", "register"} {
		err := ValidateNewVaultName(name)
		if !errors.Is(err, ErrReservedVaultName) {
			t.Fatalf("ValidateNewVaultName(%q) = %v, want ErrReservedVaultName", name, err)
		}
		if err := ValidateVaultName(name); err != nil {
			t.Fatalf("ValidateVaultName(%q) = %v, want nil so existing vaults stay reachable", name, err)
		}
	}
	if err := ValidateNewVaultName("prod"); err != nil {
		t.Fatalf("ValidateNewVaultName(prod) = %v, want nil", err)
	}
	if err := ValidateNewVaultName("ab"); err == nil {
		t.Fatal("ValidateNewVaultName(ab) must still apply the syntax rule")
	}
}
```

Add `"errors"` to the imports of `model/vault_test.go` if it is absent.

Append to `internal/services/vaults/vault_service_test.go`:

```go
// TestCreateVault_RefusesReservedName proves both create paths use the
// reservation (B80).
func TestCreateVault_RefusesReservedName(t *testing.T) {
	svc := NewVaultService(newFakeRepo(), &noopCascade{}, nil)
	_, err := svc.CreateVault(context.Background(), model.CreateVaultRequest{Name: "login"}, uuid.New())
	if !errors.Is(err, model.ErrReservedVaultName) {
		t.Fatalf("CreateVault(login) err = %v, want ErrReservedVaultName", err)
	}
	_, err = svc.CreateVaultProvisioned(context.Background(), model.CreateVaultRequest{Name: "health"}, uuid.New(), false, false)
	if !errors.Is(err, model.ErrReservedVaultName) {
		t.Fatalf("CreateVaultProvisioned(health) err = %v, want ErrReservedVaultName", err)
	}
}
```

- [ ] **Step 2: Run them and see them fail**

Run: `go test ./model/ ./internal/services/vaults/ -run 'TestValidateNewVaultName|TestCreateVault_RefusesReservedName' -count=1`
Expected: build failure, `undefined: ValidateNewVaultName`, `undefined: ErrReservedVaultName`.

- [ ] **Step 3: Implement the reservation**

In `model/vault.go`, add `"errors"` to the imports, and after `ValidateVaultName` add:

```go
// ErrReservedVaultName is returned when a new vault would take a reserved name.
var ErrReservedVaultName = errors.New("reserved vault name")

// reservedVaultNames are refused for new vaults. Each is the last segment of
// a public endpoint, which the authentication middleware once matched by
// suffix, so a vault with that name could not be managed over HTTP (B80).
// Exact matching removed the collision; the reservation keeps it from coming
// back if suffix matching is ever reintroduced.
var reservedVaultNames = map[string]struct{}{
	"login":    {},
	"health":   {},
	"refresh":  {},
	"register": {},
}

// ValidateNewVaultName applies ValidateVaultName plus the reserved-name rule.
// Use it only when creating a vault. Lookups keep using ValidateVaultName, so
// a vault created before the reservation stays reachable.
func ValidateNewVaultName(name string) error {
	if err := ValidateVaultName(name); err != nil {
		return err
	}
	if _, reserved := reservedVaultNames[name]; reserved {
		return fmt.Errorf("%w: %q is reserved for an API endpoint", ErrReservedVaultName, name)
	}
	return nil
}
```

In `internal/services/vaults/vault_service.go`, change line 324 (`CreateVault`) and line 366 (`CreateVaultProvisioned`) from `model.ValidateVaultName(req.Name)` to `model.ValidateNewVaultName(req.Name)`. The HTTP handler's existing default arm (`api/vault.go:108`, `c.SetInvalidParam(err.Error())`) returns 400 for it, and the CLI prints the error.

- [ ] **Step 4: Run them and see them pass**

Run: `go test ./model/ ./internal/services/vaults/ ./api/ ./cmd/vaults/ -count=1`
Expected: `ok` for all four packages.

- [ ] **Step 5: Commit**

Invoke the `dev-workflow-skills:1-git-commit` skill via the Skill tool for `model/vault.go`, `model/vault_test.go`, `internal/services/vaults/vault_service.go` and `internal/services/vaults/vault_service_test.go` (GPG signed, key 61D246B30285ED35).

### Task 6: Route authorization allow-list and VerifyRouteAuthorization

**Files:**
- Create: `api/route_authorization.go`
- Create: `api/route_authorization_test.go`

**Interfaces:**
- Consumes: `RouteInfo` (`api/route_inventory.go:7`), `authzServices.MapRouteToDataAction(method, path string) (model.DataAction, RouteKind)`, `authzServices.RouteVaultData`, `authzServices.DataPlaneBasePath`, `middleware.IsPublicPath`, `middleware.PublicPaths` (Task 4).
- Produces: `type RouteAccess string` with `RouteAccessPublic`, `RouteAccessAnySession`, `RouteAccessAdmin`, `RouteAccessVaultManagement`; `func VerifyRouteAuthorization(router *mux.Router, basePath string) error`.

- [ ] **Step 1: Write the failing tests**

Create `api/route_authorization_test.go`:

```go
// Package api — tests for the route authorization allow-list (B80).
package api

import (
	"net/http"
	"testing"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"rocketvault/app"
)

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
	stale := RouteInfo{Method: http.MethodGet, Path: "/api/v1/removed"}
	nonDataPlaneRoutes[stale] = routeGate{Access: RouteAccessAdmin, Gate: "test"}
	defer delete(nonDataPlaneRoutes, stale)

	err := VerifyRouteAuthorization(newAuthzCheckRouter(t, false), "/api/v1")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "GET /api/v1/removed is on the allow-list but is not registered")
}
```

`TestVerifyRouteAuthorization_RejectsStaleEntry` mutates a package-level map, so none of these tests call `t.Parallel()`.

- [ ] **Step 2: Run them and see them fail**

Run: `go test ./api/ -run TestVerifyRouteAuthorization -count=1`
Expected: build failure, `undefined: VerifyRouteAuthorization`, `undefined: nonDataPlaneRoutes`, `undefined: routeGate`, `undefined: RouteAccessAdmin`.

- [ ] **Step 3: Implement the allow-list and the check**

Create `api/route_authorization.go`:

```go
package api

import (
	"fmt"
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
	// RouteAccessAnySession needs a session, and the handler confines the
	// caller to its own records or to non-sensitive data.
	RouteAccessAnySession RouteAccess = "any-session"
	// RouteAccessAdmin needs a session, and the handler requires the global
	// admin role.
	RouteAccessAdmin RouteAccess = "admin"
	// RouteAccessVaultManagement needs a session, and the handler calls
	// CanCreateVault, CanManageVault or CanManageRoleAssignments.
	RouteAccessVaultManagement RouteAccess = "vault-management"
)

// routeGate records how one non-data-plane route is authorized.
type routeGate struct {
	Access RouteAccess
	// Gate names the function that enforces the decision, for reviewers.
	Gate string
	// Optional marks a route that is registered only under some
	// configuration, such as /metrics.
	Optional bool
}

// nonDataPlaneRoutes is the allow-list of every registered route that is not a
// vault data-plane route. A route that is neither a mapped data-plane route
// nor listed here fails VerifyRouteAuthorization, at test time and at
// startup, so a new handler that forgets its own check cannot ship silently.
var nonDataPlaneRoutes = map[RouteInfo]routeGate{
	{"GET", "/api/v1/access-policies"}:                                   {Access: RouteAccessAdmin, Gate: "requireAccessPolicyAdmin"},
	{"POST", "/api/v1/access-policies"}:                                  {Access: RouteAccessAdmin, Gate: "requireAccessPolicyAdmin"},
	{"GET", "/api/v1/access-policies/principal/{principal_id:[A-Fa-f0-9-]+}"}: {Access: RouteAccessAdmin, Gate: "requireAccessPolicyAdmin"},
	{"DELETE", "/api/v1/access-policies/{policy_id:[A-Fa-f0-9-]+}"}:      {Access: RouteAccessAdmin, Gate: "requireAccessPolicyAdmin"},
	{"GET", "/api/v1/access-policies/{policy_id:[A-Fa-f0-9-]+}"}:         {Access: RouteAccessAdmin, Gate: "requireAccessPolicyAdmin"},
	{"PUT", "/api/v1/access-policies/{policy_id:[A-Fa-f0-9-]+}"}:         {Access: RouteAccessAdmin, Gate: "requireAccessPolicyAdmin"},

	{"GET", "/api/v1/audit/config"}:        {Access: RouteAccessAdmin, Gate: "getAuditConfig admin check"},
	{"PATCH", "/api/v1/audit/config"}:      {Access: RouteAccessAdmin, Gate: "patchAuditConfig admin check"},
	{"GET", "/api/v1/audit/logs"}:          {Access: RouteAccessAdmin, Gate: "getAuditLogs admin check"},
	{"GET", "/api/v1/audit/reports/gdpr"}:  {Access: RouteAccessAdmin, Gate: "getGDPRReport admin check"},
	{"GET", "/api/v1/audit/reports/soc2"}:  {Access: RouteAccessAdmin, Gate: "getSOC2Report admin check"},

	{"GET", "/api/v1/config"}: {Access: RouteAccessPublic, Gate: "public frontend config"},

	{"GET", "/api/v1/health"}:          {Access: RouteAccessPublic, Gate: "middleware.IsPublicPath"},
	{"GET", "/api/v1/health/live"}:     {Access: RouteAccessPublic, Gate: "middleware.IsPublicPath"},
	{"GET", "/api/v1/health/ready"}:    {Access: RouteAccessPublic, Gate: "middleware.IsPublicPath"},
	{"GET", "/api/v1/health/database"}: {Access: RouteAccessAnySession, Gate: "AuthenticationMiddleware"},

	{"POST", "/api/v1/jwks/rotate"}: {Access: RouteAccessAdmin, Gate: "rotateJWKS admin check"},
	{"GET", "/jwks.json"}:           {Access: RouteAccessPublic, Gate: "public signing keys"},
	{"GET", "/metrics"}:             {Access: RouteAccessPublic, Gate: "monitoring.enable_metrics", Optional: true},

	{"POST", "/api/v1/oauth2/token"}:      {Access: RouteAccessPublic, Gate: "client credentials in the request"},
	{"GET", "/api/v1/oidc/callback"}:      {Access: RouteAccessPublic, Gate: "OIDC state and nonce"},
	{"POST", "/api/v1/oidc/cli/exchange"}: {Access: RouteAccessPublic, Gate: "one-time CLI exchange code"},
	{"GET", "/api/v1/oidc/login"}:         {Access: RouteAccessPublic, Gate: "redirect to the OIDC provider"},

	{"GET", "/api/v1/service-accounts"}:                                                  {Access: RouteAccessAdmin, Gate: "listServiceAccounts admin check"},
	{"POST", "/api/v1/service-accounts"}:                                                 {Access: RouteAccessAdmin, Gate: "createServiceAccount admin check"},
	{"DELETE", "/api/v1/service-accounts/{service_account_id:[A-Fa-f0-9-]+}"}:           {Access: RouteAccessAdmin, Gate: "deleteServiceAccount admin check"},
	{"GET", "/api/v1/service-accounts/{service_account_id:[A-Fa-f0-9-]+}"}:              {Access: RouteAccessAdmin, Gate: "getServiceAccount admin check"},
	{"POST", "/api/v1/service-accounts/{service_account_id:[A-Fa-f0-9-]+}/rotate"}:      {Access: RouteAccessAdmin, Gate: "rotateServiceAccountSecret admin check"},

	{"GET", "/api/v1/users"}:                                          {Access: RouteAccessAdmin, Gate: "listUsers admin check"},
	{"POST", "/api/v1/users"}:                                         {Access: RouteAccessAdmin, Gate: "createUser admin check"},
	{"POST", "/api/v1/users/login"}:                                   {Access: RouteAccessPublic, Gate: "middleware.IsPublicPath"},
	{"POST", "/api/v1/users/refresh"}:                                 {Access: RouteAccessPublic, Gate: "middleware.IsPublicPath"},
	{"DELETE", "/api/v1/users/sessions"}:                              {Access: RouteAccessAnySession, Gate: "revokeAllSessions scopes to the caller"},
	{"GET", "/api/v1/users/sessions"}:                                 {Access: RouteAccessAnySession, Gate: "listUserSessions scopes to the caller"},
	{"DELETE", "/api/v1/users/sessions/{session_id:[A-Fa-f0-9-]+}"}:   {Access: RouteAccessAnySession, Gate: "revokeSession scopes to the caller"},
	{"DELETE", "/api/v1/users/{user_id:[A-Fa-f0-9-]+}"}:               {Access: RouteAccessAdmin, Gate: "deleteUser admin check"},
	{"GET", "/api/v1/users/{user_id:[A-Fa-f0-9-]+}"}:                  {Access: RouteAccessAnySession, Gate: "getUser allows admin or the profile owner"},
	{"PUT", "/api/v1/users/{user_id:[A-Fa-f0-9-]+}"}:                  {Access: RouteAccessAnySession, Gate: "updateUser allows admin or the profile owner"},

	{"GET", "/api/v1/vault-provisioning-grants"}:                   {Access: RouteAccessAdmin, Gate: "requireGrantAdmin"},
	{"DELETE", "/api/v1/vault-provisioning-grants/{principal_id}"}: {Access: RouteAccessAdmin, Gate: "requireGrantAdmin"},
	{"PUT", "/api/v1/vault-provisioning-grants/{principal_id}"}:    {Access: RouteAccessAdmin, Gate: "requireGrantAdmin"},

	{"GET", "/api/v1/vaults"}:                 {Access: RouteAccessVaultManagement, Gate: "listVaults scopes by CanManageVault"},
	{"POST", "/api/v1/vaults"}:                {Access: RouteAccessVaultManagement, Gate: "CanCreateVault"},
	{"DELETE", "/api/v1/vaults/{name}"}:       {Access: RouteAccessVaultManagement, Gate: "CanManageVault"},
	{"GET", "/api/v1/vaults/{name}"}:          {Access: RouteAccessVaultManagement, Gate: "CanManageVault"},
	{"PATCH", "/api/v1/vaults/{name}"}:        {Access: RouteAccessVaultManagement, Gate: "CanManageVault"},
	{"DELETE", "/api/v1/vaults/{name}/webhook"}: {Access: RouteAccessVaultManagement, Gate: "resolveAndAuthorizeVault"},
	{"GET", "/api/v1/vaults/{name}/webhook"}:    {Access: RouteAccessVaultManagement, Gate: "resolveAndAuthorizeVault"},
	{"PUT", "/api/v1/vaults/{name}/webhook"}:    {Access: RouteAccessVaultManagement, Gate: "resolveAndAuthorizeVault"},

	{"GET", "/api/v1/vaults/{vault_name:[a-z0-9-]+}/role-assignments"}:                                     {Access: RouteAccessVaultManagement, Gate: "CanManageRoleAssignments"},
	{"POST", "/api/v1/vaults/{vault_name:[a-z0-9-]+}/role-assignments"}:                                    {Access: RouteAccessVaultManagement, Gate: "CanManageRoleAssignments"},
	{"DELETE", "/api/v1/vaults/{vault_name:[a-z0-9-]+}/role-assignments/{assignment_id:[A-Fa-f0-9-]+}"}:     {Access: RouteAccessVaultManagement, Gate: "CanManageRoleAssignments"},
	{"GET", "/api/v1/vaults/{vault_name:[a-z0-9-]+}/role-assignments/{assignment_id:[A-Fa-f0-9-]+}"}:        {Access: RouteAccessVaultManagement, Gate: "CanManageRoleAssignments"},
}

// VerifyRouteAuthorization checks that every route registered on router is
// authorized by construction: a vault data-plane route must map to a data
// action, and every other route must be on nonDataPlaneRoutes. It also
// refuses a base path the authorization layer does not strip, a leaf route
// registered without methods, a stale allow-list entry, and any disagreement
// with the middleware's public-path set. Bootstrap calls it after api.Init
// and refuses to start on an error.
func VerifyRouteAuthorization(router *mux.Router, basePath string) error {
	if basePath != authzServices.DataPlaneBasePath {
		return fmt.Errorf("api base path %q does not match the data-plane base path %q",
			basePath, authzServices.DataPlaneBasePath)
	}

	var problems []string
	seen := make(map[RouteInfo]bool)
	err := router.Walk(func(route *mux.Route, _ *mux.Router, _ []*mux.Route) error {
		tmpl, err := route.GetPathTemplate()
		if err != nil {
			return nil
		}
		methods, err := route.GetMethods()
		if err != nil || len(methods) == 0 {
			// A subrouter prefix has no handler and is fine. A leaf with a
			// handler but no method would escape every inventory walk.
			if route.GetHandler() != nil {
				problems = append(problems, fmt.Sprintf("%s has a handler but no .Methods(...)", tmpl))
			}
			return nil
		}
		for _, method := range methods {
			info := RouteInfo{Method: method, Path: tmpl}
			seen[info] = true
			action, kind := authzServices.MapRouteToDataAction(method, tmpl)
			gate, listed := nonDataPlaneRoutes[info]
			switch {
			case kind == authzServices.RouteVaultData && action == "":
				problems = append(problems, fmt.Sprintf("%s %s is a data-plane route with no data action", method, tmpl))
			case kind == authzServices.RouteVaultData && listed:
				problems = append(problems, fmt.Sprintf("%s %s is a data-plane route and must not be on the allow-list", method, tmpl))
			case kind != authzServices.RouteVaultData && !listed:
				problems = append(problems, fmt.Sprintf("%s %s is not a data-plane route and has no entry in nonDataPlaneRoutes", method, tmpl))
			}
			if gate.Access != RouteAccessPublic && middleware.IsPublicPath(tmpl) {
				problems = append(problems, fmt.Sprintf("%s %s skips authentication but is not listed as public", method, tmpl))
			}
		}
		return nil
	})
	if err != nil {
		return fmt.Errorf("walk routes: %w", err)
	}

	for info, gate := range nonDataPlaneRoutes {
		if !seen[info] && !gate.Optional {
			problems = append(problems, fmt.Sprintf("%s %s is on the allow-list but is not registered", info.Method, info.Path))
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

// isListedPublic reports whether path has a public entry for any method.
func isListedPublic(path string) bool {
	for info, gate := range nonDataPlaneRoutes {
		if info.Path == path && gate.Access == RouteAccessPublic {
			return true
		}
	}
	return false
}
```

Run `gofmt -w api/route_authorization.go` to align the map literal.

- [ ] **Step 4: Run them and see them pass**

Run: `go test ./api/ -run TestVerifyRouteAuthorization -count=1`
Expected: `ok  	rocketvault/api`. If `TestVerifyRouteAuthorization_RealRouterPasses` lists a route, compare it with `docs/api-routes.generated.txt`; a missing entry means a route was added since this plan was written and must be classified, not the check loosened.

- [ ] **Step 5: Commit**

Invoke the `dev-workflow-skills:1-git-commit` skill via the Skill tool for `api/route_authorization.go` and `api/route_authorization_test.go` (GPG signed, key 61D246B30285ED35).

### Task 7: Run the check at startup, and the B80 entry

**Files:**
- Modify: `bootstrap/bootstrap.go:435-449` (`initializeAPI`)
- Modify: `internal/services/authorization/data_actions.go:25-30` (comment), `internal/services/authorization/rbac_service.go:178-193` (comment)
- Modify: `bootstrap/bootstrap.go:149-171` (comment of `validateAuthorizationBasePath`)
- Modify: `.claude/known-bugs.md` (B80, after B79)
- Test: `bootstrap/bootstrap_test.go:309` (`TestBoot_FullStack`)

**Interfaces:**
- Consumes: `api.VerifyRouteAuthorization(router *mux.Router, basePath string) error` (Task 6); `(*app.App).GetRouter() *mux.Router` (`app/app.go:97`).
- Produces: startup fails with `route authorization check failed` when a route is unclassified.

- [ ] **Step 1: Confirm the existing full-stack boot test is the guard**

Run: `go test ./bootstrap/ -run TestBoot_FullStack -count=1 -v`
Expected: PASS today. It boots through `setup`, which calls `initializeAPI`, so after the next step it fails if the real route table does not pass `VerifyRouteAuthorization`.

- [ ] **Step 2: Wire the check**

Replace the body of `initializeAPI` in `bootstrap/bootstrap.go` with:

```go
	logrus.Info("Initializing API layer")

	api.Init(
		api.WithAPP(app),
		api.WithBasePath(cfg.BasePath),
		api.WithRouter(app.GetRouter()),
		api.WithLogger(b.cfg.Logger),
		api.WithMetricsEnabled(b.monitoringCfg.EnableMetrics),
	)

	// Refuse to serve a route whose authorization nobody classified. See
	// api.VerifyRouteAuthorization and B80 in .claude/known-bugs.md.
	if err := api.VerifyRouteAuthorization(app.GetRouter(), cfg.BasePath); err != nil {
		return fmt.Errorf("refusing to start: %w", err)
	}

	logrus.Info("API layer initialized successfully")
	return nil
```

- [ ] **Step 3: Update the stale comments**

In `internal/services/authorization/data_actions.go`, replace the `DataPlaneBasePath` doc comment (lines 25-29) with:

```go
// DataPlaneBasePath is the API version prefix stripped from request paths
// before route-to-data-action mapping. It must match the base path the API
// is served under, or every data-plane route would fall through to
// RouteUnmanaged. Startup refuses a mismatch twice: in
// bootstrap.validateAuthorizationBasePath and in api.VerifyRouteAuthorization.
```

In `internal/services/authorization/rbac_service.go`, add these sentences at the end of the `ValidateEndpointAccess` doc comment (before the `func` line at 190):

```go
//
// An unrecognized path is allowed here on purpose: this is the global-role
// gate, and every route it does not recognize is either a vault data-plane
// route (PolicyMiddleware) or a handler-authorized route listed in
// api.nonDataPlaneRoutes, which api.VerifyRouteAuthorization enforces at
// startup.
```

In `bootstrap/bootstrap.go`, replace the last paragraph of the `validateAuthorizationBasePath` comment (lines 166-170, "Until the authorization layer accepts ... silent authorization bypass.") with:

```go
// api.VerifyRouteAuthorization repeats this assertion for every caller of
// api.Init, and additionally refuses any route whose authorization is not
// classified. Both stay: this one fails before the database is touched.
```

- [ ] **Step 4: Run the tests**

Run: `go build ./... && go test ./bootstrap/ ./api/ ./internal/services/authorization/ -count=1`
Expected: `ok` for all three packages.

- [ ] **Step 5: Add the B80 known-bugs entry**

Insert after the B79 entry in `.claude/known-bugs.md`:

```markdown
### B80 — Non-data-plane routes failed open, and a vault named login, health, refresh or register was unmanageable

**Status**: Fixed 2026-09-30 (GitHub #50)
**Severity**: Medium (design; no exploitable instance was found). Coverage of
admin-only routes depended on every handler remembering its own check.
**Files**: `internal/middleware/middleware.go` (`IsPublicPath`,
`isHealthProbe`, both skip lists), `api/route_authorization.go` (new),
`bootstrap/bootstrap.go` (`initializeAPI`), `model/vault.go`
(`ValidateNewVaultName`), `internal/services/vaults/vault_service.go`

**Symptom**: `ValidateEndpointAccess` allowed unrecognized paths,
`resolvePolicy` returned an empty pair for them and `PolicyMiddleware`
passed them through, so `/audit`, `/access-policies`, `/service-accounts`,
`/vault-provisioning-grants` and `/jwks/rotate` were protected only by an
admin check inside each handler. A new route that forgot the check would have
been open to any authenticated user. Separately, the public-path bypass used
`HasSuffix`/`Contains`, so `DELETE /api/v1/vaults/login` skipped
authentication and then failed closed with 401 in `ApiSessionRequired`: a
vault with one of those names could not be managed over HTTP.

**What was fixed**: `api.VerifyRouteAuthorization` walks the real router and
requires every route to be either a vault data-plane route with a mapped data
action or an entry in `nonDataPlaneRoutes`, which names its gate. It also
refuses method-less leaf routes, stale entries, a wrong base path, and any
disagreement with the middleware's public set. It runs in a unit test and in
`bootstrap.initializeAPI`, which refuses to start on an error. Public paths
and health probes match exactly. New vaults may not be named `login`,
`health`, `refresh` or `register`; existing ones keep working.

**Design note**: the middleware is not made default-deny. Admin, self-service
and vault-management decisions stay in the handlers, which already make them
correctly; the allow-list makes forgetting to classify a route a test and
boot failure instead of a silent hole.

---
```

- [ ] **Step 6: Commit**

Invoke the `dev-workflow-skills:1-git-commit` skill via the Skill tool for `bootstrap/bootstrap.go`, `internal/services/authorization/data_actions.go`, `internal/services/authorization/rbac_service.go` and `.claude/known-bugs.md`, with a `Fixes #50` footer (GPG signed, key 61D246B30285ED35).

---

## B81: Audit gaps (issue #49, supersedes B58 and issue #18)

### Callers and implementations to update

| Method | Production callers | Interface | Implementations and test doubles |
|---|---|---|---|
| `RoleAssignmentService.RevokeAssignment` | `api/role_assignments.go:226`, `cmd/vault-access/revoke.go:83` | `internal/services/authorization/role_assignment_service.go:87-92` | `role_assignment_service.go:185`; `cmd/testutils/test_utils.go:723`; `internal/middleware/middleware_test.go:1243`; `api/role_assignments_test.go:36`; `cmd/vault-access/authz_test.go:61`; `cmd/vaults/vaults_more_test.go:453`; `internal/services/authorization/data_action_authz_test.go:33` |
| `VaultService.DeleteVault` | `api/vault.go:301`, `cmd/vaults/delete.go:43` | `internal/services/vaults/vault_service.go:173` | `vault_service.go:627`; `cmd/testutils/test_utils.go:651`; `internal/middleware/middleware_test.go:119` |
| `VaultService.RecoverVault` | `cmd/vaults/recover.go:42` (no HTTP route) | `vault_service.go:174` | `vault_service.go:694`; `cmd/testutils/test_utils.go:656`; `internal/middleware/middleware_test.go:120` |
| `VaultService.PurgeVault` | `api/vault.go:338`, `cmd/vaults/purge.go:49`, `internal/services/softdelete/purge_scheduler.go:135` | `vault_service.go:175`, `softdelete.VaultPurger` (`purge_scheduler.go:22`) | `vault_service.go:746`; `cmd/testutils/test_utils.go:661`; `internal/middleware/middleware_test.go:121`; `internal/services/softdelete/purge_scheduler_test.go:77` |
| `AccessPolicyService.CreatePolicy/UpdatePolicy/DeletePolicy` | `api/access_policies.go:122, 187, 208` (no CLI) | `access_policy_service.go:44-50` | `access_policy_service.go:113-141`; `internal/middleware/middleware_test.go:948-985`; `internal/services/authorization/vault_authz_test.go:38-53`; `api/access_policies_test.go:60-97`; `cmd/vault-webhook/authz_test.go:28-39`; `cmd/vaults/vaults_test.go:187-202`; `cmd/vault-access/authz_test.go:30-41`; `cmd/testutils/test_utils.go:756-793` |
| `NewAccessPolicyService` | `internal/container/service_container.go:521` | n/a | 9 calls in `internal/services/authorization/access_policy_service_test.go` |

`internal/vaultapi/destructive.go:74` (`Client.PurgeVault`) and `internal/mcpserver/tools_destructive.go:180` are HTTP clients, not `VaultService` implementations, and do not change.

### Task 8: Attribute role-assignment revocation to its actor

**Files:**
- Create: `internal/logging/logtest/recorder.go`
- Modify: `internal/services/authorization/role_assignment_service.go:87-92` (interface method, doc comment at 87-91), `:185-207` (`RevokeAssignment`)
- Modify: `api/role_assignments.go:226`, `cmd/vault-access/revoke.go:79-83`
- Modify test doubles: `cmd/testutils/test_utils.go:723-726`, `internal/middleware/middleware_test.go:1243`, `api/role_assignments_test.go:36-39`, `cmd/vault-access/authz_test.go:44-66`, `cmd/vaults/vaults_more_test.go:453`, `internal/services/authorization/data_action_authz_test.go:33`
- Test: `internal/services/authorization/role_assignment_service_test.go:678-693`, `api/role_assignments_test.go:278, 361, 408`, `cmd/vault-access/revoke_remote_test.go:20`, `cmd/vault-access/authz_test.go`

**Interfaces:**
- Consumes: `logging.WrapLogrus(*logrus.Logger) *logging.Logger`, `(*logging.Logger).SetAuditPersister(logging.AuditPersister)`, `vaultcli.CallerIdentity(ctx) ([]string, uuid.UUID, error)`, `callerIdentity(c *Context) ([]string, uuid.UUID, bool)` (`api/role_assignments.go:47`).
- Produces: `RevokeAssignment(ctx context.Context, assignmentID, vaultID, actorID uuid.UUID, callerIsGlobalAdmin bool) error`; package `logtest` with `type Record struct{ UserID, Action, Details string }`, `type Recorder`, `func (r *Recorder) PersistAudit(userID, action, details string) error`, `func (r *Recorder) Find(action, status string) (Record, bool)`, `func NewLogger() (*logging.Logger, *Recorder)`.

- [ ] **Step 1: Create the shared audit recorder**

Create `internal/logging/logtest/recorder.go`:

```go
// Package logtest provides an in-memory audit recorder for tests that assert
// who an audit entry was attributed to. It imports only internal/logging, so
// any test package can use it without an import cycle.
package logtest

import (
	"strings"
	"sync"

	"github.com/sirupsen/logrus"

	"rocketvault/internal/logging"
)

// Record is one audit row captured by Recorder.
type Record struct {
	UserID  string
	Action  string
	Details string
}

// Recorder is a logging.AuditPersister that keeps every row in memory.
type Recorder struct {
	mu      sync.Mutex
	records []Record
}

// PersistAudit implements logging.AuditPersister.
func (r *Recorder) PersistAudit(userID, action, details string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.records = append(r.records, Record{UserID: userID, Action: action, Details: details})
	return nil
}

// Find returns the first row for action whose details carry status=<status>.
func (r *Recorder) Find(action, status string) (Record, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, rec := range r.records {
		if rec.Action == action && strings.Contains(rec.Details, "status="+status) {
			return rec, true
		}
	}
	return Record{}, false
}

// NewLogger returns a quiet logger whose audit rows go to a new Recorder.
func NewLogger() (*logging.Logger, *Recorder) {
	l := logrus.New()
	l.SetLevel(logrus.PanicLevel)
	logger := logging.WrapLogrus(l)
	rec := &Recorder{}
	logger.SetAuditPersister(rec)
	return logger, rec
}
```

- [ ] **Step 2: Write the failing service test**

Replace `TestRevokeAssignment_LogsSuccessAudit` in `internal/services/authorization/role_assignment_service_test.go` (lines 678-693) with:

```go
// TestRevokeAssignment_LogsSuccessAudit pins B81 (formerly B58): the revoke
// row names the acting principal, as the grant row already did.
func TestRevokeAssignment_LogsSuccessAudit(t *testing.T) {
	rr, pr := newFakeRoleRepo(), newFakePolicyRepo()
	uid := uuid.New()
	ul := &fakeUserLookup{users: map[string]model.User{"alice": {ID: uid, Username: "alice"}}}
	svc, audit := newAuditingSvc(rr, pr, ul)
	createdBy := uuid.New()
	ra, err := svc.AssignRole(context.Background(), AssignRoleInput{
		Principal: "alice", PrincipalType: model.PrincipalTypeUser,
		Role: model.RoleKeyVaultSecretsUser, VaultID: uuid.New(), CreatedBy: createdBy,
	})
	require.NoError(t, err)

	revoker := uuid.New()
	require.NoError(t, svc.RevokeAssignment(context.Background(), ra.ID, ra.VaultID, revoker, true))

	rec, ok := audit.find("revoke_role_assignment", "success")
	require.True(t, ok, "RevokeAssignment must emit a success audit row")
	assert.Equal(t, revoker.String(), rec.userID, "the revoke row must name the revoker")
}
```

- [ ] **Step 3: Run it and see it fail**

Run: `go test ./internal/services/authorization/ -run TestRevokeAssignment_LogsSuccessAudit -count=1`
Expected: build failure, `too many arguments in call to svc.RevokeAssignment`.

- [ ] **Step 4: Change the signature and the audit call**

In `internal/services/authorization/role_assignment_service.go`, replace the interface method (line 84) and its doc comment's first sentence with:

```go
	// RevokeAssignment revokes assignmentID in vaultID on behalf of actorID,
	// who is recorded in the audit row. callerIsGlobalAdmin
	// mirrors AssignRoleInput.CallerIsGlobalAdmin: when false, revoking an
	// assignment whose Role is outside nonAdminGrantableRoles is refused with
	// ErrRoleNotGrantable, so a non-global-admin Data Access Administrator
	// can't revoke a role they aren't allowed to grant.
	RevokeAssignment(ctx context.Context, assignmentID, vaultID, actorID uuid.UUID, callerIsGlobalAdmin bool) error
```

Change the method header at line 185 to:

```go
func (s *roleAssignmentService) RevokeAssignment(ctx context.Context, assignmentID, vaultID, actorID uuid.UUID, callerIsGlobalAdmin bool) error {
```

and line 203 to:

```go
		s.log.LogAuditInfo(actorID.String(), "revoke_role_assignment", "success",
```

- [ ] **Step 5: Update the callers**

`api/role_assignments.go:226`:

```go
	if err := svc.RevokeAssignment(r.Context(), id, vaultID, callerID, isGlobalAdmin); err != nil {
```

`cmd/vault-access/revoke.go`, replace lines 79-83 with:

```go
			callerRoles, callerID, err := vaultcli.CallerIdentity(ctx)
			if err != nil {
				return err
			}
			isGlobalAdmin := common.HasAnyRole(callerRoles, string(model.RoleAdmin))
			if err := sc.GetRoleAssignmentService().RevokeAssignment(ctx, id, vaultID, callerID, isGlobalAdmin); err != nil {
```

- [ ] **Step 6: Update the test doubles**

`cmd/testutils/test_utils.go:723-726`:

```go
func (m *MockRoleAssignmentService) RevokeAssignment(ctx context.Context, assignmentID, vaultID, actorID uuid.UUID, callerIsGlobalAdmin bool) error {
	args := m.Called(ctx, assignmentID, vaultID, actorID, callerIsGlobalAdmin)
	return args.Error(0)
}
```

Apply the identical body to `internal/middleware/middleware_test.go:1243` and `api/role_assignments_test.go:36` (receiver names `MockRoleAssignmentService` and `mockRoleAssignmentService`).

`internal/services/authorization/data_action_authz_test.go:33`:

```go
func (f *fakeRoleAssignmentService) RevokeAssignment(ctx context.Context, assignmentID, vaultID, actorID uuid.UUID, callerIsGlobalAdmin bool) error {
```

`cmd/vaults/vaults_more_test.go:453`:

```go
func (s *stubRoleAssignmentService) RevokeAssignment(context.Context, uuid.UUID, uuid.UUID, uuid.UUID, bool) error {
```

In `cmd/vault-access/authz_test.go`, add a field `revokeActor uuid.UUID` to `fakeRoleSvc` and replace its `RevokeAssignment` with:

```go
func (f *fakeRoleSvc) RevokeAssignment(_ context.Context, _, _ uuid.UUID, actorID uuid.UUID, callerIsGlobalAdmin bool) error {
	f.revokeCalled = true
	f.revokeActor = actorID
	f.revokeCallerIsGlobalAdmin = callerIsGlobalAdmin
	return nil
}
```

and append to `TestVaultAccessRevoke_PassesNonAdminCallerFlag`:

```go
	assert.Equal(t, tc.TestUserID, roleSvc.revokeActor, "the CLI must pass the caller as the audit actor")
```

Update the mock expectations: `api/role_assignments_test.go:278` becomes `roleSvc.On("RevokeAssignment", mock.Anything, assignmentID, vaultID, callerID, false).`; line 361 becomes `roleSvc.On("RevokeAssignment", mock.Anything, assignmentID, vaultID, callerID, false).Return(nil)`; line 408 becomes `roleSvc.On("RevokeAssignment", mock.Anything, assignmentID, vaultA, callerID, false).Return(nil)`. `cmd/vault-access/revoke_remote_test.go:20` becomes `roleSvc.On("RevokeAssignment", mock.Anything, id, mock.Anything, mock.Anything, mock.Anything).`.

Rewrite the remaining direct calls in the service test with:

```bash
perl -pi -e 's/\.RevokeAssignment\(context\.Background\(\), ([^,]+), ([^,]+), (true|false)\)/.RevokeAssignment(context.Background(), $1, $2, uuid.New(), $3)/g' internal/services/authorization/role_assignment_service_test.go
```

- [ ] **Step 7: Run the tests**

Run: `go build ./... && go vet ./... && go test ./internal/services/authorization/ ./api/ ./cmd/vault-access/ ./cmd/vaults/ ./internal/middleware/ -count=1`
Expected: `ok` for every package. A remaining compile error names a call site the table above missed; fix it by passing the caller's principal, never `uuid.Nil`.

- [ ] **Step 8: Commit**

Invoke the `dev-workflow-skills:1-git-commit` skill via the Skill tool for every file changed in this task (GPG signed, key 61D246B30285ED35).

### Task 9: Attribute vault delete, recover and purge to their actor

**Files:**
- Modify: `internal/services/vaults/vault_service.go:173-175` (interface), `:627`, `:688`, `:694`, `:740`, `:746`, `:820`
- Modify: `internal/services/softdelete/purge_scheduler.go:5-14` (imports), `:22`, `:135`
- Modify: `api/vault.go:301` (`deleteVault`), `:329-338` (`purgeVault`)
- Modify: `cmd/vaults/authz.go:91-124`, `cmd/vaults/delete.go:38-43`, `cmd/vaults/recover.go:37-42`, `cmd/vaults/purge.go:44-49`, `cmd/vaults/get.go:41`, `cmd/vaults/update.go:44`
- Modify test doubles: `cmd/testutils/test_utils.go:651-664`, `internal/middleware/middleware_test.go:119-121`, `internal/services/softdelete/purge_scheduler_test.go:63-82`
- Create: `internal/services/vaults/vault_service_audit_test.go`, `api/vault_audit_test.go`
- Test: `cmd/vaults/vaults_test.go:132`, `cmd/vaults/vaults_more_test.go:53, 69, 87, 103, 318, 422, 440, 481, 492`, all vault service tests, `internal/container/container_test.go:689-690`

**Interfaces:**
- Consumes: `logtest.NewLogger()` (Task 8); `callerIdentity(c)`; `vaultcli.CallerIdentity(ctx)`.
- Produces: `DeleteVault(ctx context.Context, name string, actorID uuid.UUID) error`, `RecoverVault(ctx context.Context, name string, actorID uuid.UUID) error`, `PurgeVault(ctx context.Context, name string, actorID uuid.UUID) error`; `softdelete.VaultPurger.PurgeVault(ctx, name string, actorID uuid.UUID) error`; `requireCanManageVault(ctx, sc, vaultName string) (uuid.UUID, error)` and `requireCanPurgeVault(ctx, sc, vaultName string) (uuid.UUID, error)` in `cmd/vaults`.

- [ ] **Step 1: Write the failing service tests**

Create `internal/services/vaults/vault_service_audit_test.go`:

```go
package vaults

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"rocketvault/internal/logging/logtest"
	"rocketvault/model"
)

// TestVaultDestructiveOps_AuditTheActor is the B81 regression that supersedes
// B58: delete, recover and purge each record the acting principal.
func TestVaultDestructiveOps_AuditTheActor(t *testing.T) {
	logger, rec := logtest.NewLogger()
	repo := newFakeRepo()
	id := uuid.New()
	repo.byName["stg"] = &model.Vault{ID: id, Name: "stg", Enabled: true}
	repo.byID[id.String()] = repo.byName["stg"]
	svc := NewVaultService(repo, &noopCascade{}, logger)
	actor := uuid.New()

	require.NoError(t, svc.DeleteVault(context.Background(), "stg", actor))
	require.NoError(t, svc.RecoverVault(context.Background(), "stg", actor))
	require.NoError(t, svc.DeleteVault(context.Background(), "stg", actor))
	require.NoError(t, svc.PurgeVault(context.Background(), "stg", actor))

	for _, action := range []string{"delete_vault", "recover_vault", "purge_vault"} {
		row, ok := rec.Find(action, "success")
		require.True(t, ok, "%s must emit a success audit row", action)
		assert.Equal(t, actor.String(), row.UserID, "%s must name the actor", action)
	}
}

// TestPurgeVault_SchedulerActorIsRecordedAsSystem pins the one legitimate
// uuid.Nil caller, the background purge scheduler.
func TestPurgeVault_SchedulerActorIsRecordedAsSystem(t *testing.T) {
	logger, rec := logtest.NewLogger()
	repo := newFakeRepo()
	id := uuid.New()
	now := nowForTest()
	repo.byName["old"] = &model.Vault{ID: id, Name: "old", DeletedAt: &now}
	repo.byID[id.String()] = repo.byName["old"]
	svc := NewVaultService(repo, &noopCascade{}, logger)

	require.NoError(t, svc.PurgeVault(context.Background(), "old", uuid.Nil))

	row, ok := rec.Find("purge_vault", "success")
	require.True(t, ok)
	assert.Equal(t, "system", row.UserID)
}
```

- [ ] **Step 2: Run them and see them fail**

Run: `go test ./internal/services/vaults/ -run 'TestVaultDestructiveOps_AuditTheActor|TestPurgeVault_SchedulerActorIsRecordedAsSystem' -count=1`
Expected: build failure, `too many arguments in call to svc.DeleteVault` (and RecoverVault, PurgeVault).

- [ ] **Step 3: Change the service**

In the `VaultService` interface (lines 173-175):

```go
	// DeleteVault, RecoverVault and PurgeVault record actorID in the audit
	// row. uuid.Nil is recorded as "system" and is reserved for the
	// background purge scheduler.
	DeleteVault(ctx context.Context, name string, actorID uuid.UUID) error
	RecoverVault(ctx context.Context, name string, actorID uuid.UUID) error
	PurgeVault(ctx context.Context, name string, actorID uuid.UUID) error
```

Change the three method headers to take `actorID uuid.UUID` as the last parameter, and the three audit lines to:

```go
		s.log.LogAuditInfo(auditActor(actorID), "delete_vault", "success", fmt.Sprintf("Vault deleted: %s", name))
```

```go
		s.log.LogAuditInfo(auditActor(actorID), "recover_vault", "success", fmt.Sprintf("Vault recovered: %s", name))
```

```go
		s.log.LogAuditInfo(auditActor(actorID), "purge_vault", "success", fmt.Sprintf("Vault purged: %s", name))
```

Add below `findDeleted`:

```go
// systemActor is the audit actor for work no principal requested, matching
// the expiration service's background rows.
const systemActor = "system"

// auditActor renders actorID for an audit row. Only the purge scheduler
// passes uuid.Nil.
func auditActor(actorID uuid.UUID) string {
	if actorID == uuid.Nil {
		return systemActor
	}
	return actorID.String()
}
```

- [ ] **Step 4: Update the scheduler**

In `internal/services/softdelete/purge_scheduler.go`, add `"github.com/google/uuid"` to the imports, change line 22 to `PurgeVault(ctx context.Context, name string, actorID uuid.UUID) error`, and line 135 to:

```go
		// The scheduler acts for no principal, which the vault service
		// records as "system".
		if err := s.vaults.PurgeVault(ctx, v.Name, uuid.Nil); err != nil {
```

In `internal/services/softdelete/purge_scheduler_test.go`, add `"github.com/google/uuid"` to the imports, add a field `actors []uuid.UUID` to `fakeVaultPurger`, and replace its `PurgeVault`:

```go
func (f *fakeVaultPurger) PurgeVault(_ context.Context, name string, actorID uuid.UUID) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.purged = append(f.purged, name)
	f.actors = append(f.actors, actorID)
	return nil
}
```

Append:

```go
// TestPurgeExpiredVaults_PassesSystemActor pins that the scheduler purges as
// uuid.Nil, which the vault service audits as "system" (B81).
func TestPurgeExpiredVaults_PassesSystemActor(t *testing.T) {
	rawDB := newTestDB(t)
	createPurgeTables(rawDB)
	conn := newTestConn(t, rawDB)

	deletedAt := time.Now().AddDate(0, 0, -40)
	vaults := &fakeVaultPurger{vaults: []model.Vault{{Name: "expired", DeletedAt: &deletedAt}}}

	s := NewPurgeScheduler(conn, testConfig(), testLogger(), vaults)
	s.Start(context.Background())
	time.Sleep(30 * time.Millisecond)
	s.Stop()

	vaults.mu.Lock()
	defer vaults.mu.Unlock()
	require.Equal(t, []uuid.UUID{uuid.Nil}, vaults.actors)
}
```

- [ ] **Step 5: Update the HTTP handlers and write their test**

`api/vault.go:301`:

```go
	if err := svc.DeleteVault(r.Context(), name, userID); err != nil {
```

In `purgeVault`, insert before the `svc.PurgeVault` call and change the call:

```go
	// PolicyMiddleware authorized the request; the identity is read here only
	// to attribute the audit row.
	_, actorID, ok := callerIdentity(c)
	if !ok {
		c.SetInternalError(nil)
		return
	}

	if err := svc.PurgeVault(r.Context(), name, actorID); err != nil {
```

Create `api/vault_audit_test.go`:

```go
// Package api — audit attribution tests for vault handlers (B81).
package api

import (
	"net/http"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"rocketvault/internal/logging/logtest"
	vaultServices "rocketvault/internal/services/vaults"
	"rocketvault/model"
)

// TestDeleteVault_AuditsCallerAsActor proves the HTTP delete passes the
// session principal to the service, which records it.
func TestDeleteVault_AuditsCallerAsActor(t *testing.T) {
	logger, rec := logtest.NewLogger()
	repo := newVaultFakeRepo()
	id := uuid.New()
	repo.byName["stg"] = &model.Vault{ID: id, Name: "stg", Enabled: true}
	repo.byID[id.String()] = repo.byName["stg"]
	svc := vaultServices.NewVaultService(repo, vaultNoopCascade{}, logger)
	api := newVaultTestAPIWithContainer(&vaultSvcTestContainer{vaultSvc: svc, policySvc: &mockAccessPolicyService{}})

	w := doVaultRequest(api, http.MethodDelete, "/api/v1/vaults/stg", nil)
	require.Equal(t, http.StatusNoContent, w.Code)

	row, ok := rec.Find("delete_vault", "success")
	require.True(t, ok)
	assert.Equal(t, vaultTestUserID, row.UserID)
}

// TestPurgeVault_AuditsCallerAsActor mirrors the delete case for purge.
func TestPurgeVault_AuditsCallerAsActor(t *testing.T) {
	logger, rec := logtest.NewLogger()
	repo := newVaultFakeRepo()
	id := uuid.New()
	deletedAt := nowForVaultTest()
	repo.byName["stg"] = &model.Vault{ID: id, Name: "stg", Enabled: true, DeletedAt: &deletedAt}
	repo.byID[id.String()] = repo.byName["stg"]
	svc := vaultServices.NewVaultService(repo, vaultNoopCascade{}, logger)
	api := newVaultTestAPIWithContainer(&vaultSvcTestContainer{vaultSvc: svc, policySvc: &mockAccessPolicyService{}})

	w := doVaultRequest(api, http.MethodDelete, "/api/v1/vaults/stg/purge", nil)
	require.Equal(t, http.StatusNoContent, w.Code)

	row, ok := rec.Find("purge_vault", "success")
	require.True(t, ok)
	assert.Equal(t, vaultTestUserID, row.UserID)
}
```

- [ ] **Step 6: Update the CLI**

In `cmd/vaults/authz.go`, replace `requireCanManageVault` and `requireCanPurgeVault` (lines 91-124) with versions that return the principal:

```go
// requireCanManageVault resolves vaultName to an ID, checks CanManageVault
// against it, and returns the caller's principal for audit attribution.
func requireCanManageVault(ctx context.Context, sc container.ServiceContainerInterface, vaultName string) (uuid.UUID, error) {
	roles, principalID, err := vaultcli.CallerIdentity(ctx)
	if err != nil {
		return uuid.Nil, err
	}
	vaultID, err := resolveTargetVaultID(ctx, sc.GetVaultService(), vaultName)
	if err != nil {
		return uuid.Nil, fmt.Errorf("resolve vault %q: %w", vaultName, err)
	}
	if !authz.CanManageVault(ctx, roles, sc.GetAccessPolicyService(), principalID, vaultID) {
		return uuid.Nil, fmt.Errorf("permission denied: admin or vaults/manage required for vault %q", vaultName)
	}
	return principalID, nil
}

// requireCanPurgeVault resolves vaultName to an ID, checks CanPurgeVault
// against it, and returns the caller's principal for audit attribution.
func requireCanPurgeVault(ctx context.Context, sc container.ServiceContainerInterface, vaultName string) (uuid.UUID, error) {
	roles, principalID, err := vaultcli.CallerIdentity(ctx)
	if err != nil {
		return uuid.Nil, err
	}
	vaultID, err := resolveTargetVaultID(ctx, sc.GetVaultService(), vaultName)
	if err != nil {
		return uuid.Nil, fmt.Errorf("resolve vault %q: %w", vaultName, err)
	}
	if !authz.CanPurgeVault(ctx, roles, sc.GetRoleAssignmentService(), principalID, vaultID) {
		return uuid.Nil, fmt.Errorf("permission denied: admin or Key Vault Purge Operator required for vault %q", vaultName)
	}
	return principalID, nil
}
```

`cmd/vaults/delete.go:38-43`:

```go
		actorID, err := requireCanManageVault(ctx, serviceContainer, name)
		if err != nil {
			return err
		}
		vaultService := serviceContainer.GetVaultService()

		if err := vaultService.DeleteVault(ctx, name, actorID); err != nil {
```

`cmd/vaults/recover.go:37-42`: the same shape with `vaultService.RecoverVault(ctx, name, actorID)`.

`cmd/vaults/purge.go:44-49`: the same shape with `actorID, err := requireCanPurgeVault(ctx, serviceContainer, name)` and `vaultService.PurgeVault(ctx, name, actorID)`.

`cmd/vaults/get.go:41` and `cmd/vaults/update.go:44`: change `if err := requireCanManageVault(ctx, serviceContainer, name); err != nil {` to `if _, err := requireCanManageVault(ctx, serviceContainer, name); err != nil {`.

- [ ] **Step 7: Update the test doubles and existing tests**

`cmd/testutils/test_utils.go:651-664`:

```go
func (m *MockVaultService) DeleteVault(ctx context.Context, name string, actorID uuid.UUID) error {
	args := m.Called(ctx, name, actorID)
	return args.Error(0)
}

func (m *MockVaultService) RecoverVault(ctx context.Context, name string, actorID uuid.UUID) error {
	args := m.Called(ctx, name, actorID)
	return args.Error(0)
}

func (m *MockVaultService) PurgeVault(ctx context.Context, name string, actorID uuid.UUID) error {
	args := m.Called(ctx, name, actorID)
	return args.Error(0)
}
```

`internal/middleware/middleware_test.go:119-121`:

```go
func (s *stubVaultService) DeleteVault(context.Context, string, uuid.UUID) error  { return nil }
func (s *stubVaultService) RecoverVault(context.Context, string, uuid.UUID) error { return nil }
func (s *stubVaultService) PurgeVault(context.Context, string, uuid.UUID) error   { return nil }
```

In `cmd/vaults/vaults_test.go:132` and `cmd/vaults/vaults_more_test.go` lines 53, 69, 87, 103, 318 and 492, add `tc.TestUserID` as the third `On` argument, for example `tc.MockVaultService.On("DeleteVault", mock.Anything, "my-vault", tc.TestUserID).Return(nil)`. This is the CLI actor assertion: the mock matches only when the command passes the caller. At lines 422, 440 and 481 add a third `mock.Anything` to `AssertNotCalled`, which otherwise passes vacuously against a three-argument call.

Rewrite the service-level and container test calls with:

```bash
perl -pi -e 's/\.(DeleteVault|RecoverVault|PurgeVault)\(((?:ctx|context\.Background\(\))), ([^()]+?)\)/.$1($2, $3, uuid.New())/g' \
  internal/services/vaults/vault_service_test.go \
  internal/services/vaults/vault_service_edge_test.go \
  internal/services/vaults/vault_service_role_assignment_cleanup_test.go \
  internal/services/vaults/vault_service_tx_integration_test.go \
  internal/services/vaults/vault_service_webhook_cleanup_test.go \
  internal/services/vaults/vault_cache_test.go \
  internal/container/container_test.go
```

- [ ] **Step 8: Run the tests**

Run: `go build ./... && go vet ./... && go test ./internal/services/vaults/ ./internal/services/softdelete/ ./api/ ./cmd/vaults/ ./internal/middleware/ ./internal/container/ -count=1`
Expected: `ok` for every package.

- [ ] **Step 9: Commit**

Invoke the `dev-workflow-skills:1-git-commit` skill via the Skill tool for every file changed in this task (GPG signed, key 61D246B30285ED35).

### Task 10: Audit access-policy create, update and delete

**Files:**
- Modify: `internal/services/authorization/access_policy_service.go:3-12` (imports), `:44-50` (interface), `:53-60` (struct and constructor), `:113-141` (methods)
- Modify: `internal/container/service_container.go:521`
- Modify: `api/access_policies.go:122`, `:187`, `:208`
- Modify test doubles listed in the table above for `CreatePolicy`/`UpdatePolicy`/`DeletePolicy`
- Test: `internal/services/authorization/access_policy_service_test.go`, `api/access_policies_test.go:254-261, 389, 413, 553, 575, 612, 631`

**Interfaces:**
- Consumes: `logtest.NewLogger()` (Task 8); `callerIdentity(c)`.
- Produces: `NewAccessPolicyService(repo repositories.AccessPolicyRepositoryInterface, log *logging.Logger) AccessPolicyService`; `CreatePolicy(ctx, policy *model.AccessPolicy, actorID uuid.UUID) error`; `UpdatePolicy(ctx, policy *model.AccessPolicy, actorID uuid.UUID) error`; `DeletePolicy(ctx, id, actorID uuid.UUID) error`. Audit actions `create_access_policy`, `update_access_policy`, `delete_access_policy`.

- [ ] **Step 1: Write the failing service test**

Append to `internal/services/authorization/access_policy_service_test.go` (add `"rocketvault/internal/logging/logtest"` to its imports):

```go
// TestAccessPolicyMutations_AreAudited is the B81 regression: explicit-deny
// overrides could change with no trail. Each mutation now records the actor
// and what the policy did.
func TestAccessPolicyMutations_AreAudited(t *testing.T) {
	repo := &mockPolicyRepo{}
	logger, rec := logtest.NewLogger()
	svc := authorization.NewAccessPolicyService(repo, logger)
	ctx := context.Background()
	actor := uuid.New()

	policy := &model.AccessPolicy{
		ID:            uuid.New(),
		PrincipalID:   uuid.New(),
		PrincipalType: model.PrincipalTypeUser,
		ResourceType:  model.PolicyResourceKeys,
		Operation:     model.OpDecrypt,
		Effect:        model.PolicyEffectDeny,
	}
	stored := *policy
	repo.On("Create", ctx, policy).Return(nil)
	repo.On("GetByID", ctx, policy.ID).Return(&stored, nil)
	repo.On("Update", ctx, policy).Return(nil)
	repo.On("Delete", ctx, policy.ID).Return(nil)

	require.NoError(t, svc.CreatePolicy(ctx, policy, actor))
	policy.Effect = model.PolicyEffectAllow
	require.NoError(t, svc.UpdatePolicy(ctx, policy, actor))
	require.NoError(t, svc.DeletePolicy(ctx, policy.ID, actor))

	created, ok := rec.Find("create_access_policy", "success")
	require.True(t, ok)
	assert.Equal(t, actor.String(), created.UserID)
	assert.Contains(t, created.Details, "operation=decrypt effect=deny scope=global")

	updated, ok := rec.Find("update_access_policy", "success")
	require.True(t, ok)
	assert.Equal(t, actor.String(), updated.UserID)
	assert.Contains(t, updated.Details, "effect deny -> allow")

	deleted, ok := rec.Find("delete_access_policy", "success")
	require.True(t, ok)
	assert.Equal(t, actor.String(), deleted.UserID)
}
```

- [ ] **Step 2: Run it and see it fail**

Run: `go test ./internal/services/authorization/ -run TestAccessPolicyMutations_AreAudited -count=1`
Expected: build failure, `too many arguments in call to authorization.NewAccessPolicyService`.

- [ ] **Step 3: Implement audited mutations**

In `internal/services/authorization/access_policy_service.go`, add `"rocketvault/internal/logging"` to the imports. Replace the three interface lines with:

```go
	// CreatePolicy, UpdatePolicy and DeletePolicy write an audit row naming
	// actorID and the policy's principal, resource, operation, effect and
	// scope, because an explicit deny overrides every role grant.
	CreatePolicy(ctx context.Context, policy *model.AccessPolicy, actorID uuid.UUID) error
	GetPolicy(ctx context.Context, id uuid.UUID) (*model.AccessPolicy, error)
	ListPolicies(ctx context.Context) ([]*model.AccessPolicy, error)
	ListByPrincipal(ctx context.Context, principalID uuid.UUID) ([]*model.AccessPolicy, error)
	UpdatePolicy(ctx context.Context, policy *model.AccessPolicy, actorID uuid.UUID) error
	DeletePolicy(ctx context.Context, id, actorID uuid.UUID) error
```

Replace the struct and constructor with:

```go
type accessPolicyService struct {
	repo repositories.AccessPolicyRepositoryInterface
	log  *logging.Logger
}

// NewAccessPolicyService creates a new AccessPolicyService backed by repo. The
// logger may be nil, in which case mutations are not audited.
func NewAccessPolicyService(repo repositories.AccessPolicyRepositoryInterface, log *logging.Logger) AccessPolicyService {
	return &accessPolicyService{repo: repo, log: log}
}
```

Replace `CreatePolicy`, `UpdatePolicy` and `DeletePolicy` with:

```go
func (s *accessPolicyService) CreatePolicy(ctx context.Context, policy *model.AccessPolicy, actorID uuid.UUID) error {
	if policy.ID == uuid.Nil {
		policy.ID = uuid.New()
	}
	if policy.CreatedAt.IsZero() {
		policy.CreatedAt = time.Now()
	}
	if err := s.repo.Create(ctx, policy); err != nil {
		return err
	}
	s.audit(actorID, "create_access_policy",
		fmt.Sprintf("Access policy %s created: %s", policy.ID, describePolicy(policy)))
	return nil
}

func (s *accessPolicyService) UpdatePolicy(ctx context.Context, policy *model.AccessPolicy, actorID uuid.UUID) error {
	// Read the stored row first so the audit row records the old effect. A
	// failed read loses only the old value; it never blocks the update.
	previous := "unknown"
	if old, err := s.repo.GetByID(ctx, policy.ID); err == nil && old != nil {
		previous = string(old.Effect)
	}
	if err := s.repo.Update(ctx, policy); err != nil {
		return err
	}
	s.audit(actorID, "update_access_policy",
		fmt.Sprintf("Access policy %s updated: effect %s -> %s (%s)", policy.ID, previous, policy.Effect, describePolicy(policy)))
	return nil
}

func (s *accessPolicyService) DeletePolicy(ctx context.Context, id, actorID uuid.UUID) error {
	// Read the row first so the audit row says what the deleted policy did.
	detail := "policy row not readable before delete"
	if old, err := s.repo.GetByID(ctx, id); err == nil && old != nil {
		detail = describePolicy(old)
	}
	if err := s.repo.Delete(ctx, id); err != nil {
		return err
	}
	s.audit(actorID, "delete_access_policy", fmt.Sprintf("Access policy %s deleted: %s", id, detail))
	return nil
}

// describePolicy renders the fields an auditor needs to see what a policy did.
func describePolicy(p *model.AccessPolicy) string {
	scope := "global"
	if p.VaultID != nil {
		scope = "vault " + p.VaultID.String()
	}
	return fmt.Sprintf("principal=%s (%s) resource=%s operation=%s effect=%s scope=%s",
		p.PrincipalID, p.PrincipalType, p.ResourceType, p.Operation, p.Effect, scope)
}

// audit writes one success row when a logger is configured.
func (s *accessPolicyService) audit(actorID uuid.UUID, operation, message string) {
	if s.log != nil {
		s.log.LogAuditInfo(actorID.String(), operation, "success", message)
	}
}
```

`internal/container/service_container.go:521`:

```go
	c.accessPolicyService = authzServices.NewAccessPolicyService(c.accessPolicyRepository, c.logger)
```

Update the other constructor calls and the existing create test:

```bash
perl -pi -e 's/authorization\.NewAccessPolicyService\(repo\)/authorization.NewAccessPolicyService(repo, nil)/g; s/svc\.CreatePolicy\(ctx, policy\)\)/svc.CreatePolicy(ctx, policy, uuid.New()))/g' internal/services/authorization/access_policy_service_test.go
```

- [ ] **Step 4: Update the handlers**

In `api/access_policies.go`, after `requireAccessPolicyAdmin` succeeds in each of `createAccessPolicy`, `updateAccessPolicy` and `deleteAccessPolicy`, read the actor:

```go
	_, actorID, callerOK := callerIdentity(c)
	if !callerOK {
		c.SetInternalError(nil)
		return
	}
```

(All three handlers already declare `ok` later, from `decodeBody` or `resourceID`, so name this one `callerOK` and test `!callerOK`.) Then pass it: line 122 `svc.CreatePolicy(r.Context(), policy, actorID)`, line 187 `svc.UpdatePolicy(r.Context(), policy, actorID)`, line 208 `svc.DeletePolicy(r.Context(), id, actorID)`.

- [ ] **Step 5: Update the test doubles and handler tests**

For the testify mocks (`internal/middleware/middleware_test.go:948-985`, `api/access_policies_test.go:60-97`, `cmd/testutils/test_utils.go:756-793`) use:

```go
func (m *MockAccessPolicyService) CreatePolicy(ctx context.Context, policy *model.AccessPolicy, actorID uuid.UUID) error {
	args := m.Called(ctx, policy, actorID)
	return args.Error(0)
}

func (m *MockAccessPolicyService) UpdatePolicy(ctx context.Context, policy *model.AccessPolicy, actorID uuid.UUID) error {
	args := m.Called(ctx, policy, actorID)
	return args.Error(0)
}

func (m *MockAccessPolicyService) DeletePolicy(ctx context.Context, id, actorID uuid.UUID) error {
	args := m.Called(ctx, id, actorID)
	return args.Error(0)
}
```

(receiver `mockAccessPolicyService` in `api/access_policies_test.go`). For the no-op fakes run:

```bash
perl -pi -e 's/CreatePolicy\(context\.Context, \*model\.AccessPolicy\) error/CreatePolicy(context.Context, *model.AccessPolicy, uuid.UUID) error/; s/UpdatePolicy\(context\.Context, \*model\.AccessPolicy\) error/UpdatePolicy(context.Context, *model.AccessPolicy, uuid.UUID) error/; s/DeletePolicy\(context\.Context, uuid\.UUID\) error/DeletePolicy(context.Context, uuid.UUID, uuid.UUID) error/' \
  internal/services/authorization/vault_authz_test.go \
  cmd/vault-webhook/authz_test.go \
  cmd/vaults/vaults_test.go \
  cmd/vault-access/authz_test.go
```

In `api/access_policies_test.go`, give `newPolicyCtx` a principal so `callerIdentity` succeeds:

```go
		Claims: RequestClaims{
			UserID: "00000000-0000-0000-0000-0000000000ad",
			Roles:  []string{"secrets_manager", string(model.RoleAdmin)},
		},
```

and add a third `mock.Anything` to the `On` calls at lines 389, 413, 553 and 575 (`svc.On("CreatePolicy", mock.Anything, mock.Anything, mock.Anything)`, likewise `UpdatePolicy`), and change lines 612 and 631 to `svc.On("DeletePolicy", mock.Anything, policyID, uuid.MustParse("00000000-0000-0000-0000-0000000000ad"))`.

- [ ] **Step 6: Run the tests**

Run: `go build ./... && go vet ./... && go test ./internal/services/authorization/ ./api/ ./cmd/... ./internal/middleware/ ./internal/container/ -count=1`
Expected: `ok` for every package.

- [ ] **Step 7: Commit**

Invoke the `dev-workflow-skills:1-git-commit` skill via the Skill tool for every file changed in this task (GPG signed, key 61D246B30285ED35).

### Task 11: Audit handler-level and CLI-level refusals

**Files:**
- Modify: `api/context.go:113-116` (add `auditDenied` after `SetPermissionError`)
- Modify: `api/vault.go:84, 105, 202, 240, 297`, `api/role_assignments.go:71, 106, 138, 176, 217, 231`, `api/access_policies.go:33`, `api/vault_webhook.go:60`
- Modify: `cmd/vaults/authz.go` (all four `require*` helpers), `cmd/vault-access/authz.go:22-31`, `cmd/vault-access/grant.go:106`, `cmd/vault-access/revoke.go:75`, `cmd/vault-access/list.go:69`
- Create: `api/denial_audit_test.go`
- Test: `cmd/vaults/vaults_more_test.go` (`TestVaultsDelete_ForbiddenWithoutGrant`), `cmd/vault-access/authz_test.go` (`TestVaultAccessGrant_DeniedWithoutGrant`)

**Interfaces:**
- Consumes: `logtest.NewLogger()`, `logtest.Recorder` (Task 8); `requireCanManageVault(...) (uuid.UUID, error)` (Task 9).
- Produces: `func (c *Context) auditDenied(operation, permission string)`; `requireCanManageRoleAssignments(ctx, sc, vaultID uuid.UUID, write bool, operation string) error`. Denied rows use status `denied` and the operation names `create_vault`, `get_vault`, `update_vault`, `delete_vault`, `recover_vault`, `purge_vault`, `manage_vault_webhook`, `assign_role`, `revoke_role_assignment`, `list_role_assignments`, `get_role_assignment`, `manage_access_policy`.

- [ ] **Step 1: Write the failing HTTP tests**

Create `api/denial_audit_test.go`:

```go
// Package api — handler-level refusals are audited (B81).
package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"rocketvault/app"
	"rocketvault/common"
	"rocketvault/internal/logging/logtest"
	authzServices "rocketvault/internal/services/authorization"
	"rocketvault/internal/testutils"
	"rocketvault/model"
)

// TestDeleteVault_RefusalIsAudited proves a vault 403 leaves a denied row.
func TestDeleteVault_RefusalIsAudited(t *testing.T) {
	policySvc := &mockAccessPolicyService{}
	policySvc.On("CheckAccess", mock.Anything, mock.Anything, model.PolicyResourceVaults, model.OpManage, mock.Anything).
		Return(authzServices.AccessFallback, nil)
	policySvc.On("CheckVaultScopedAccess", mock.Anything, mock.Anything, model.PolicyResourceVaults, model.OpManage, mock.Anything).
		Return(authzServices.AccessFallback, nil)
	api, _ := buildAuthzVaultAPI(policySvc)
	logger, rec := logtest.NewLogger()
	api.App.Logger = logger

	w := doVaultRequestAs(api, string(model.RoleUser), http.MethodDelete, "/api/v1/vaults/prod", nil)
	require.Equal(t, http.StatusForbidden, w.Code)

	row, ok := rec.Find("delete_vault", "denied")
	require.True(t, ok, "a refused vault delete must be audited")
	assert.Equal(t, vaultTestUserID, row.UserID)
}

// TestCreateRoleAssignment_RefusalIsAudited proves a refused grant leaves a
// denied row naming the caller.
func TestCreateRoleAssignment_RefusalIsAudited(t *testing.T) {
	policySvc := &mockAccessPolicyService{}
	policySvc.On("CheckAccess", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).
		Return(authzServices.AccessFallback, nil)
	policySvc.On("CheckVaultScopedAccess", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).
		Return(authzServices.AccessFallback, nil)

	c := newRoleAssignmentCtx("user", policySvc)
	logger, rec := logtest.NewLogger()
	c.Logger = logger
	w := httptest.NewRecorder()
	body := []byte(`{"principal":"alice","role":"Key Vault Administrator"}`)
	r := httptest.NewRequest(http.MethodPost, "/api/v1/vaults/prod/role-assignments", bytes.NewReader(body))

	createRoleAssignment(c, w, r)
	require.NotNil(t, c.Err)

	row, ok := rec.Find("assign_role", "denied")
	require.True(t, ok, "a refused grant must be audited")
	assert.Equal(t, c.Claims.UserID, row.UserID)
}

// TestDeleteRoleAssignment_NotGrantableRefusalIsAudited covers the second
// refusal point on revoke: the service's ErrRoleNotGrantable.
func TestDeleteRoleAssignment_NotGrantableRefusalIsAudited(t *testing.T) {
	vaultID := uuid.New()
	assignmentID := uuid.New()
	callerID := uuid.MustParse("00000000-0000-0000-0000-000000000001")

	// The api tests use internal/testutils.MockServiceContainer, whose
	// GetAccessPolicyService always returns nil. CanManageRoleAssignments
	// tolerates a nil policy service and falls through to HasDataAction, so
	// the first gate passes and the handler reaches ErrRoleNotGrantable.
	roleSvc := &mockRoleAssignmentService{}
	roleSvc.On("HasDataAction", mock.Anything, callerID, vaultID, model.ActionRoleAssignmentsDelete).Return(true, nil)
	roleSvc.On("RevokeAssignment", mock.Anything, assignmentID, vaultID, callerID, false).
		Return(authzServices.ErrRoleNotGrantable)

	mc := &testutils.MockServiceContainer{}
	mc.On("GetRoleAssignmentService").Return(roleSvc)
	logger, rec := logtest.NewLogger()
	c := &Context{
		App:    &app.App{ServiceContainer: mc},
		Claims: RequestClaims{UserID: callerID.String(), Roles: []string{"user"}},
		Params: &ApiParams{VaultName: "prod", AssignmentID: assignmentID.String(), PerPage: 60},
		Logger: logger,
	}
	r := httptest.NewRequest(http.MethodDelete, "/api/v1/vaults/prod/role-assignments/"+assignmentID.String(), nil)
	r = r.WithContext(context.WithValue(r.Context(), common.VaultIDKey, vaultID.String()))

	deleteRoleAssignment(c, httptest.NewRecorder(), r)
	require.NotNil(t, c.Err)
	// Guard against a vacuous pass at the first gate: the service must be reached.
	roleSvc.AssertCalled(t, "RevokeAssignment", mock.Anything, assignmentID, vaultID, callerID, false)

	row, ok := rec.Find("revoke_role_assignment", "denied")
	require.True(t, ok, "a refused revoke must be audited")
	assert.Equal(t, callerID.String(), row.UserID)
}

// TestCreateAccessPolicy_NonAdminRefusalIsAudited proves an attempt to write
// an explicit deny without the admin role leaves a trail.
func TestCreateAccessPolicy_NonAdminRefusalIsAudited(t *testing.T) {
	c := newNonAdminPolicyCtx(nil)
	c.Claims.UserID = "00000000-0000-0000-0000-0000000000bb"
	logger, rec := logtest.NewLogger()
	c.Logger = logger
	body, _ := json.Marshal(map[string]string{"principal_id": uuid.New().String()})
	r := httptest.NewRequest(http.MethodPost, "/access-policies", bytes.NewReader(body))

	createAccessPolicy(c, httptest.NewRecorder(), r)
	require.NotNil(t, c.Err)

	row, ok := rec.Find("manage_access_policy", "denied")
	require.True(t, ok)
	assert.Equal(t, "00000000-0000-0000-0000-0000000000bb", row.UserID)
}
```

- [ ] **Step 2: Run them and see them fail**

Run: `go test ./api/ -run 'RefusalIsAudited' -count=1`
Expected: FAIL in all four tests with `a refused ... must be audited` (no denied row is written).

- [ ] **Step 3: Implement the HTTP helper and use it**

In `api/context.go`, after `SetPermissionError`, add:

```go
// auditDenied records a handler-level authorization refusal, then sets the
// 403 response. Middleware refusals were already audited; handler refusals
// were not, so a refused grant, revoke or vault change left no trace (B81).
func (c *Context) auditDenied(operation, permission string) {
	if c.Logger != nil {
		c.Logger.LogAuditError(c.Claims.UserID, operation, "denied",
			"Insufficient permissions: "+permission, nil)
	}
	c.SetPermissionError(permission)
}
```

Replace these `c.SetPermissionError(X)` calls with `c.auditDenied(OP, X)`, keeping each message `X` unchanged:

| File:line | OP |
|---|---|
| `api/vault.go:84` | `"create_vault"` |
| `api/vault.go:105` | `"create_vault"` |
| `api/vault.go:202` | `"get_vault"` |
| `api/vault.go:240` | `"update_vault"` |
| `api/vault.go:297` | `"delete_vault"` |
| `api/vault_webhook.go:60` | `"manage_vault_webhook"` |
| `api/role_assignments.go:71` | `"assign_role"` |
| `api/role_assignments.go:106` | `"assign_role"` |
| `api/role_assignments.go:138` | `"list_role_assignments"` |
| `api/role_assignments.go:176` | `"get_role_assignment"` |
| `api/role_assignments.go:217` | `"revoke_role_assignment"` |
| `api/role_assignments.go:231` | `"revoke_role_assignment"` |
| `api/access_policies.go:33` | `"manage_access_policy"` |

- [ ] **Step 4: Run them and see them pass**

Run: `go test ./api/ -count=1`
Expected: `ok  	rocketvault/api`.

- [ ] **Step 5: Write the failing CLI tests**

In `cmd/vaults/vaults_more_test.go`, add `"rocketvault/internal/logging/logtest"` to the imports and append to `TestVaultsDelete_ForbiddenWithoutGrant`, before `err := cmd.Execute()`:

```go
	rec := &logtest.Recorder{}
	tc.MockContainer.GetLogger().SetAuditPersister(rec)
```

and after the existing assertions:

```go
	row, ok := rec.Find("delete_vault", "denied")
	require.True(t, ok, "a refused CLI vault delete must be audited")
	assert.Equal(t, tc.TestUserID.String(), row.UserID)
```

In `cmd/vault-access/authz_test.go`, add the same import and, in `TestVaultAccessGrant_DeniedWithoutGrant`, before `err := cmd.Execute()`:

```go
	rec := &logtest.Recorder{}
	tc.MockContainer.GetLogger().SetAuditPersister(rec)
```

and after the existing assertions:

```go
	row, ok := rec.Find("assign_role", "denied")
	require.True(t, ok, "a refused CLI grant must be audited")
	assert.Equal(t, tc.TestUserID.String(), row.UserID)
```

Run: `go test ./cmd/vaults/ ./cmd/vault-access/ -run 'ForbiddenWithoutGrant|DeniedWithoutGrant' -count=1`
Expected: FAIL with `a refused CLI vault delete must be audited` and `a refused CLI grant must be audited`.

- [ ] **Step 6: Implement the CLI audit**

In `cmd/vaults/authz.go`, add:

```go
// auditDenied records a CLI refusal with the same operation name and status
// the HTTP handler writes for the same refusal (B81).
func auditDenied(sc container.ServiceContainerInterface, principalID uuid.UUID, operation, message string) {
	if logger := sc.GetLogger(); logger != nil {
		logger.LogAuditError(principalID.String(), operation, "denied", message, nil)
	}
}
```

Give `requireCanManageVault` a fourth parameter `operation string`, and in its refusal branch, and in the refusal branches of `requireCanPurgeVault` and `requireCanCreateVault`, build the error once and audit it:

```go
	if !authz.CanManageVault(ctx, roles, sc.GetAccessPolicyService(), principalID, vaultID) {
		err := fmt.Errorf("permission denied: admin or vaults/manage required for vault %q", vaultName)
		auditDenied(sc, principalID, operation, err.Error())
		return uuid.Nil, err
	}
```

```go
	if !authz.CanPurgeVault(ctx, roles, sc.GetRoleAssignmentService(), principalID, vaultID) {
		err := fmt.Errorf("permission denied: admin or Key Vault Purge Operator required for vault %q", vaultName)
		auditDenied(sc, principalID, "purge_vault", err.Error())
		return uuid.Nil, err
	}
```

```go
	if right == authz.CreateRightNone {
		err := fmt.Errorf("permission denied: admin, a global vaults/manage grant, or a vault provisioning grant required to create a vault")
		auditDenied(sc, principalID, "create_vault", err.Error())
		return authz.CreateRightNone, err
	}
```

Pass the operation at each caller: `cmd/vaults/delete.go` `"delete_vault"`, `recover.go` `"recover_vault"`, `get.go` `"get_vault"`, `update.go` `"update_vault"`.

In `cmd/vault-access/authz.go`, replace the function with:

```go
// requireCanManageRoleAssignments authorizes granting (write=true) or revoking
// (write=false) a role assignment in vaultID, using the same shared primitive
// as the HTTP handlers so CLI and API cannot drift apart. A refusal is
// audited under operation, matching the HTTP handler's row.
func requireCanManageRoleAssignments(ctx context.Context, sc container.ServiceContainerInterface, vaultID uuid.UUID, write bool, operation string) error {
	roles, principalID, err := vaultcli.CallerIdentity(ctx)
	if err != nil {
		return err
	}
	if !authz.CanManageRoleAssignments(ctx, roles, sc.GetAccessPolicyService(), sc.GetRoleAssignmentService(), principalID, vaultID, write) {
		err := fmt.Errorf("permission denied: admin, vaults/manage, or Key Vault Data Access Administrator required for this vault")
		if logger := sc.GetLogger(); logger != nil {
			logger.LogAuditError(principalID.String(), operation, "denied", err.Error(), nil)
		}
		return err
	}
	return nil
}
```

and pass `"assign_role"` at `grant.go:106`, `"revoke_role_assignment"` at `revoke.go:75`, `"list_role_assignments"` at `list.go:69`.

- [ ] **Step 7: Run the tests**

Run: `go build ./... && go vet ./... && go test ./api/ ./cmd/... -count=1`
Expected: `ok` for every package.

- [ ] **Step 8: Commit**

Invoke the `dev-workflow-skills:1-git-commit` skill via the Skill tool for every file changed in this task (GPG signed, key 61D246B30285ED35).

### Task 12: Floor for audit retention_days

Floor chosen: **90 days**. PCI DSS v4.0 requirement 10.5.1 keeps audit history for twelve months with the most recent three months immediately available, and 90 days is also the shortest observation window over which the SOC 2 report this product generates (`GET /audit/reports/soc2`) says anything useful. It is well under the 365-day default, so a deployment that never changed the setting is unaffected. The floor matters because retention is itself a way to destroy evidence: an admin credential (or a stolen admin token) could set `retention_days` to 1 and let the next daily purge erase the trail of whatever it just did. The floor is enforced in the service (both entry points), validated early in the handler and the CLI for a clear message, and applied as a clamp when a stored value is below it, so a value of 1 saved before this change cannot delete recent rows.

**Files:**
- Modify: `internal/services/audit/compliance_report_service.go:210-232`
- Modify: `api/audit.go:236-239` (`patchAuditConfig` validation)
- Modify: `cmd/audit/config.go:1-10` (imports), `:44-49`
- Modify: `docs/api-specification.yaml:5459-5462` (`minimum`)
- Test: `internal/services/audit/compliance_report_service_test.go:127-143`, `api/coverage_boost_test.go:288-305`, `cmd/audit/audit_cmds_test.go:464-490`

**Interfaces:**
- Produces: `const auditSvc.MinRetentionDays = 90`, `var auditSvc.ErrRetentionBelowFloor error`; `GetRetentionDays` never returns less than `MinRetentionDays` (except on its existing error path, which returns 365).

- [ ] **Step 1: Write the failing tests**

In `internal/services/audit/compliance_report_service_test.go`, replace `TestComplianceReportService_PurgeExpiredLogs` with:

```go
func TestComplianceReportService_PurgeExpiredLogs(t *testing.T) {
	db := openTestDB(t)
	repo := repositories.NewAuditRepository(rvdb.NewConn(db, rvdb.SQLite))
	require.NoError(t, repo.SetAuditConfig(context.Background(), "retention_days", "90"))

	old := time.Now().UTC().AddDate(0, 0, -92)
	recent := time.Now().UTC()
	require.NoError(t, repo.InsertAuditLog(context.Background(), repositories.AuditLog{ID: uuid.New().String(), Action: "old", Timestamp: old}))
	require.NoError(t, repo.InsertAuditLog(context.Background(), repositories.AuditLog{ID: uuid.New().String(), Action: "recent", Timestamp: recent}))

	svc := auditSvc.NewComplianceReportService(repo)
	deleted, err := svc.PurgeExpiredLogs(context.Background())
	require.NoError(t, err)
	assert.Equal(t, int64(1), deleted)
}

// TestComplianceReportService_StoredRetentionBelowFloorIsClamped pins that a
// value of 1 saved before the floor existed cannot purge recent rows (B81).
func TestComplianceReportService_StoredRetentionBelowFloorIsClamped(t *testing.T) {
	db := openTestDB(t)
	repo := repositories.NewAuditRepository(rvdb.NewConn(db, rvdb.SQLite))
	require.NoError(t, repo.SetAuditConfig(context.Background(), "retention_days", "1"))

	twoDaysOld := time.Now().UTC().Add(-48 * time.Hour)
	require.NoError(t, repo.InsertAuditLog(context.Background(), repositories.AuditLog{ID: uuid.New().String(), Action: "recent-ish", Timestamp: twoDaysOld}))

	svc := auditSvc.NewComplianceReportService(repo)
	days, err := svc.GetRetentionDays(context.Background())
	require.NoError(t, err)
	assert.Equal(t, auditSvc.MinRetentionDays, days)

	deleted, err := svc.PurgeExpiredLogs(context.Background())
	require.NoError(t, err)
	assert.Equal(t, int64(0), deleted)
}

// TestComplianceReportService_SetRetentionBelowFloorIsRefused pins the floor
// on the write path shared by HTTP and the CLI.
func TestComplianceReportService_SetRetentionBelowFloorIsRefused(t *testing.T) {
	db := openTestDB(t)
	repo := repositories.NewAuditRepository(rvdb.NewConn(db, rvdb.SQLite))
	svc := auditSvc.NewComplianceReportService(repo)

	err := svc.SetRetentionDays(context.Background(), 89)
	require.ErrorIs(t, err, auditSvc.ErrRetentionBelowFloor)
	require.NoError(t, svc.SetRetentionDays(context.Background(), 90))
}
```

In `api/coverage_boost_test.go`, change `TestPatchAuditConfig_ServiceError_Returns500` to use `120` in both the mock (`mockCRS.On("SetRetentionDays", mock.Anything, 120)`) and the body (`{"retention_days":120}`), and append:

```go
// TestPatchAuditConfig_BelowFloor_Returns400 pins the 90-day floor (B81).
func TestPatchAuditConfig_BelowFloor_Returns400(t *testing.T) {
	mc := &testutils.MockServiceContainer{}
	mc.On("GetComplianceReportService").Return(&testutils.MockComplianceReportService{})

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPatch, "/audit/config", strings.NewReader(`{"retention_days":1}`))
	c := auditAdminCtx(mc)

	patchAuditConfig(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusBadRequest, w.Code)
}
```

In `cmd/audit/audit_cmds_test.go`, change `TestConfigCmd_SetRetentionDays_Success` to use `120` (mock and `--retention-days=120`) and `TestConfigCmd_SetRetentionDays_Error` to use `100`, and append:

```go
// TestConfigCmd_SetRetentionDays_BelowFloor pins the 90-day floor on the CLI
// before the service is reached (B81).
func TestConfigCmd_SetRetentionDays_BelowFloor(t *testing.T) {
	tc := testutils.NewTestContext(t)
	mockSvc := &MockComplianceReportService{}
	tc.MockContainer.On("GetComplianceReportService").Return(mockSvc)

	cmd, _ := newConfigCmd()
	cmd.SetContext(tc.Ctx)
	cmd.SetArgs([]string{"--retention-days=30"})
	err := cmd.Execute()
	assert.ErrorContains(t, err, "at least 90")
	mockSvc.AssertNotCalled(t, "SetRetentionDays", mock.Anything, mock.Anything)
}
```

- [ ] **Step 2: Run them and see them fail**

Run: `go test ./internal/services/audit/ ./api/ ./cmd/audit/ -run 'Retention|AuditConfig|ConfigCmd' -count=1`
Expected: build failure, `undefined: auditSvc.MinRetentionDays` and `undefined: auditSvc.ErrRetentionBelowFloor`.

- [ ] **Step 3: Implement the floor**

In `internal/services/audit/compliance_report_service.go` (add `"errors"` to its imports if absent), add above `GetRetentionDays`:

```go
// MinRetentionDays is the shortest audit retention the service accepts. It
// keeps the three months of immediately available history PCI DSS 10.5.1
// asks for, and stops an admin credential from shrinking retention to erase
// its own trail at the next purge.
const MinRetentionDays = 90

// ErrRetentionBelowFloor is returned when retention_days is below MinRetentionDays.
var ErrRetentionBelowFloor = errors.New("retention_days below the minimum")
```

In `GetRetentionDays`, replace the final `return days, nil` with:

```go
	// A value stored before the floor existed is clamped, so it cannot
	// purge recent rows.
	if days < MinRetentionDays {
		return MinRetentionDays, nil
	}
	return days, nil
```

Replace the body of `SetRetentionDays` with:

```go
	if days < MinRetentionDays {
		return fmt.Errorf("%w: %d (minimum %d)", ErrRetentionBelowFloor, days, MinRetentionDays)
	}
	return s.repo.SetAuditConfig(ctx, "retention_days", strconv.Itoa(days))
```

In `api/audit.go`, replace the `body.RetentionDays <= 0` check (lines 236-239) with:

```go
	if body.RetentionDays < auditSvc.MinRetentionDays {
		c.SetInvalidParam("retention_days: must be at least " + strconv.Itoa(auditSvc.MinRetentionDays))
		return
	}
```

In `cmd/audit/config.go`, add `auditSvc "rocketvault/internal/services/audit"` to the imports and insert before `svc := sc.GetComplianceReportService()`:

```go
		if retentionDays > 0 && retentionDays < auditSvc.MinRetentionDays {
			return fmt.Errorf("--retention-days must be at least %d", auditSvc.MinRetentionDays)
		}
```

In `docs/api-specification.yaml:5461`, change `minimum: 1` to `minimum: 90`.

- [ ] **Step 4: Run them and see them pass**

Run: `go test ./internal/services/audit/ ./api/ ./cmd/audit/ -count=1`
Expected: `ok` for all three packages. `TestPatchAuditConfig_ZeroRetention_Returns400` keeps passing because 0 is below the floor.

- [ ] **Step 5: Commit**

Invoke the `dev-workflow-skills:1-git-commit` skill via the Skill tool for every file changed in this task (GPG signed, key 61D246B30285ED35).

### Task 13: B81 entry, B58 superseded, release note, and full verification

**Files:**
- Modify: `.claude/known-bugs.md` (B81 after B80; B58 status line at 3436)
- Create: `docs/release-notes/v4.7.0-authorization-policy-and-audit.md`
- Modify: `scripts/docsgen/docs.go:45` (add the release note after the v4.6.0 entry)

**Interfaces:**
- Consumes: every change from Tasks 1-12.
- Produces: documentation only.

- [ ] **Step 1: Mark B58 superseded**

In `.claude/known-bugs.md`, replace the B58 line `**Status**: Open, found 2026-09-04` with:

```markdown
**Status**: Superseded by B81 (fixed 2026-09-30, GitHub #49; closes #18). The
fix recipe below was followed, with one correction: `cmd/vaults/delete.go`
did not have `principalID` in scope, because `requireCanManageVault` returned
only an error; it now returns the principal.
```

- [ ] **Step 2: Add the B81 entry**

Insert after B80:

```markdown
### B81 — Security-relevant changes were unattributed or unaudited

**Status**: Fixed 2026-09-30 (GitHub #49, supersedes B58 and #18)
**Severity**: Medium — accountability gap. Authorization was unaffected, but
the audit log could not say who revoked a role, deleted, recovered or purged
a vault, or created, changed or removed an explicit-deny policy, and it
recorded no trace of refused grants, revokes or vault changes.
**Files**: `internal/services/authorization/role_assignment_service.go`,
`internal/services/vaults/vault_service.go`,
`internal/services/authorization/access_policy_service.go`,
`internal/services/softdelete/purge_scheduler.go`, `api/context.go`,
`api/vault.go`, `api/role_assignments.go`, `api/access_policies.go`,
`api/vault_webhook.go`, `api/audit.go`, `cmd/vaults/*.go`,
`cmd/vault-access/*.go`, `cmd/audit/config.go`,
`internal/services/audit/compliance_report_service.go`

**Symptom**: `revoke_role_assignment`, `delete_vault`, `recover_vault` and
`purge_vault` rows carried an empty `user_id`. Access-policy create, update
and delete wrote no audit row at all. A handler-level 403 on a grant, revoke
or vault operation wrote nothing. `PATCH /audit/config` accepted
`retention_days: 1`.

**Root cause**: the four destructive service methods had no actor parameter
(B58), the access-policy service had no logger, handler refusals called only
`SetPermissionError`, and retention was validated only as positive.

**What was fixed**: `RevokeAssignment`, `DeleteVault`, `RecoverVault` and
`PurgeVault` take an `actorID`, and every HTTP and CLI caller passes the
session principal; the purge scheduler passes `uuid.Nil`, recorded as
`system`. The access-policy service audits each mutation with the actor and
the policy's principal, resource, operation, effect and scope, including the
old effect on update. Handler and CLI refusals write a `denied` row under the
same operation name on both paths. Audit retention has a 90-day floor on
write, and a stored value below it is clamped on read.

---
```

- [ ] **Step 3: Write the release note**

Create `docs/release-notes/v4.7.0-authorization-policy-and-audit.md`:

```markdown
# v4.7.0 — Explicit-deny coverage, route authorization, and audit attribution

This release fixes three findings from the 2026-09-30 static audit of `api/`:
GitHub #42 (`.claude/known-bugs.md` § B79), #50 (§ B80) and #49 (§ B81, which
supersedes § B58).

## Behavior changes for existing deployments

### Access policies: five operations now have their own names

`POST .../keys/{id}/encrypt`, `/decrypt`, `/wrap`, `/unwrap` and
`POST .../{secrets|keys|certificates}/{id}/backup` used to be evaluated
against the `create` operation. They now resolve to `encrypt`, `decrypt`,
`wrap`, `unwrap` and `backup`. `wrap` and `unwrap` are new operation values.
The CLI `keys wrap` and `keys unwrap` commands changed the same way, so both
entry points agree.

What this means for you:

1. A deny naming `encrypt`, `decrypt` or `backup` now takes effect over HTTP.
   Before, it was silently ignored there.
2. A deny on `(keys, create)` no longer blocks the five operations above, and
   a deny on `(secrets, create)` or `(certificates, create)` no longer blocks
   item backup. If you relied on that, add denies naming the operations.

Find policies that may need a companion deny:

    GET /api/v1/access-policies

and look for rows with `"operation": "create"` and `"effect": "deny"`.

### Public endpoints are matched exactly

Only these paths skip authentication: `/api/v1/health`,
`/api/v1/health/ready`, `/api/v1/health/live`, `/api/v1/users/login`,
`/api/v1/users/refresh`, `/api/v1/oauth2/token`, `/api/v1/oidc/login` and
`/api/v1/oidc/callback`. Before, any path ending in `/login`, `/refresh`,
`/register` or `/health` skipped it, which made a vault with one of those
names impossible to manage over HTTP. Such vaults are manageable again with
no action.

### Reserved vault names

New vaults may not be named `login`, `health`, `refresh` or `register`.
**Existing vaults with these names keep working** everywhere, including the
MCP server; nothing is renamed and no migration runs. After such a vault is
purged, its name cannot be reused.

### Startup refuses an unclassified route

The server now refuses to start if any registered route is neither a mapped
vault data-plane route nor on the non-data-plane allow-list in
`api/route_authorization.go`. This affects only builds that add routes; a
stock build always passes.

### Audit trail

- `revoke_role_assignment`, `delete_vault`, `recover_vault` and
  `purge_vault` rows now name the acting principal. Automatic vault purges by
  the soft-delete scheduler are recorded as `system`.
- Access-policy changes write `create_access_policy`,
  `update_access_policy` and `delete_access_policy` rows.
- Refused vault, role-assignment and access-policy operations write a row
  with status `denied`, on HTTP and the CLI alike.

### Audit retention floor: 90 days

`PATCH /api/v1/audit/config` and `rocketvault audit config --retention-days`
refuse values below 90. A value below 90 saved by an earlier version is
treated as 90, and `GET /api/v1/audit/config` reports 90 for it. The default
stays 365.

## Upgrade procedure

1. Review explicit-deny policies on `create` as described above.
2. Deploy. No schema change runs.
3. Optionally, re-save audit retention if it was below 90:

       rocketvault audit config --retention-days 90
```

Add this line to `scripts/docsgen/docs.go` after the v4.6.0 entry at line 45:

```go
	{"docs/release-notes/v4.7.0-authorization-policy-and-audit.md", "docs/release-notes/v4.7.0-authorization-policy-and-audit.html"},
```

Run: `./scripts/docs.sh build`
Expected: exits 0 and writes `docs/release-notes/v4.7.0-authorization-policy-and-audit.html`.

- [ ] **Step 4: Full verification**

Run: `go build ./... && go vet ./... && go test ./... -count=1`
Expected: all packages `ok`. Then run `go test ./api/ -run TestGenerateRouteInventory -count=1`; it must pass unchanged, because this plan adds no route. `golangci-lint` must be run in CI or on a fixed toolchain, since it fails in this environment.

- [ ] **Step 5: Commit**

Invoke the `dev-workflow-skills:1-git-commit` skill via the Skill tool for `.claude/known-bugs.md`, `docs/release-notes/v4.7.0-authorization-policy-and-audit.md`, the generated `.html`, and `scripts/docsgen/docs.go`, with the footers `Fixes #49` and `Fixes #18` (GPG signed, key 61D246B30285ED35).

---

## Self-Review

**Spec coverage.**
- #42: CLI operations established per verb (table above); HTTP and CLI agree for sign, verify, encrypt, decrypt, wrap, unwrap and backup (Tasks 1-2); per-operation explicit-deny tests through `PolicyMiddleware` (Task 1) and a real-router walk (Task 3); decision on new versus existing operations recorded (new `OpWrap`/`OpUnwrap`, existing `OpEncrypt`/`OpDecrypt`/`OpBackup`).
- #50: every registered route checked against the data-plane map or an explicit allow-list at test time and startup (Tasks 6-7); exact public-path matching (Task 4); reserved names with a migration note (Task 5, release note); base path asserted at startup (already in `bootstrap.validateAuthorizationBasePath`, now also in `VerifyRouteAuthorization`).
- #49: revoke actor (Task 8); vault delete, recover and purge actor, superseding B58 (Task 9); access-policy audit (Task 10); refused grants, revokes and vault 403s audited on HTTP and CLI (Task 11); retention floor chosen and justified (Task 12). Every caller, interface and test double is listed in the B81 table.

**Placeholder scan.** No step says "add validation", "handle errors" or "similar to Task N" without code. The two regex rewrites are exact commands over named files. Known-bugs statuses carry the fix date and issue number rather than commit hashes, which do not exist yet.

**Type consistency.** `OpWrap`/`OpUnwrap` are `model.PolicyOperation` (Tasks 1-3). `middleware.IsPublicPath(string) bool` and `middleware.PublicPaths() []string` (Task 4) are consumed by `VerifyRouteAuthorization(*mux.Router, string) error` (Tasks 6-7). `RevokeAssignment(ctx, assignmentID, vaultID, actorID uuid.UUID, callerIsGlobalAdmin bool) error` puts the new `uuid.UUID` before the `bool`, so every stale call site is a compile error rather than a silent reorder. `DeleteVault`/`RecoverVault`/`PurgeVault(ctx, name string, actorID uuid.UUID) error` match `softdelete.VaultPurger`. `requireCanManageVault` returns `(uuid.UUID, error)` from Task 9 and gains an `operation string` parameter in Task 11; `requireCanManageRoleAssignments` gains `operation string` in Task 11. `logtest.Recorder.Find(action, status string) (Record, bool)` is used identically in Tasks 8-11.

**Deviations from the brief.** The vault-name reservation lives in a new `ValidateNewVaultName`, not in `ValidateVaultName`, because the latter also validates lookups in `internal/mcpserver/gating.go:95` and would lock out existing vaults. Non-data-plane routes are made fail-closed by a startup allow-list rather than by making `PolicyMiddleware` default-deny, for the reason given at the top of the B80 section.

**Open question.** `POST /{resource}/restore` (restore from a backup blob) still resolves to `OpRecover`, the same defect class as #42, because its suffix collides with the soft-delete restore route. It is recorded under "Not fixed here" in B79 and left for a separate issue.
