# OIDC JIT Policy Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let an admin control who may be provisioned or may log in through OIDC, and close the PKCE, `email_verified`, email-storage, lookup-error and state-compare gaps.

**Architecture:** A pure `ExternalUserPolicy` (new file in `internal/services/users`) is built from `oidc.*` config at startup and injected into `userService`. `FindOrCreateExternalUser` evaluates it on every login. Transport fixes (PKCE, constant-time state, extra identity fields) live in `internal/services/auth/oidc_service.go` and `api/oidc.go`. Email is stored in a new nullable `users.email` column.

**Tech Stack:** Go 1.24.2, `coreos/go-oidc/v3`, `golang.org/x/oauth2`, viper, testify, SQLite/Postgres.

**Spec:** `docs/superpowers/specs/2026-11-06-oidc-jit-policy-design.md` (intent: `docs/superpowers/intents/2026-11-06-oidc-jit-policy.md`).

## Global Constraints

- JIT is off by default: `oidc.jit_enabled` defaults to `false`; a nil or zero `ExternalUserPolicy` means JIT off.
- Config keys: `oidc.jit_enabled`, `oidc.allowed_email_domains`, `oidc.require_email_verified`, `oidc.required_claims`, `oidc.default_role` (default `user`, any other value fails startup), `oidc.enforce_on_existing` (default `true`).
- Denial returns `ErrExternalUserNotAllowed`, mapped to a generic 403 body `access denied`. The denial reason appears only in the audit event, never in the response. Lookup or create errors give 500. Token-exchange failure stays 401.
- Identities link only by `(provider, subject)`. Never match or link by email.
- PKCE is S256, always on, with no config key. Verifier is 32 random bytes, base64url, in an `oidc_pkce` cookie.
- Audit events use the existing `LogAudit*` calls: `oidc_login_denied` (subject, provider, reason code in `jit_disabled|domain|email_unverified|claim`; never claim values) and `oidc_user_provisioned` (user ID, role).
- Plan clarification of the spec: `email` and `email_verified` come from the same source. If the ID token has no `email` and userinfo supplies one, `email_verified` is taken from userinfo too. `Claims` always holds the ID token's claims.
- New code comments are short full sentences ending in a period. Follow `service-layer-conventions`: policy and flow in the service, SQL only in the repository, HTTP concerns only in `api/`.
- Commit each task with the `dev-workflow-skills:1-git-commit` skill, never a freeform `git commit -m`. Before finishing, `go build ./... && go test ./... && golangci-lint run` must be clean.

## Review Focus

- `email_verified` sent as the string `"true"` (any case) must count as verified; any other string or a number must not.
- Email with uppercase letters or several `@` signs: the domain is the part after the last `@`, compared case-insensitively.
- `required_claims` against an array claim holding non-strings, or a claim of another type: no match, no panic.
- A failing email refresh for an existing user must not deny or fail the login; it is logged.
- Any callback failure path (state mismatch, missing PKCE cookie, exchange error) still clears the state, nonce, PKCE and CLI cookies.

---

### Task 1: Store email on users

**Files:**
- Modify: `internal/db/db.go` (CREATE TABLE `users` at ~341; migrations list at ~1027)
- Modify: `model/user.go` (add `Email string` with tag `json:"email,omitempty"`)
- Modify: `internal/repositories/user_repository.go` (interface at 23; `Create` ~129; SELECTs at ~170, 441, 479, 526 and the Scan at ~547)
- Modify: `internal/services/retry/retry_user_repository_wrapper.go`, `internal/services/users/user_service_test.go` (mock at ~56), `internal/services/secrets/coverage_boost_test.go` (mock at ~124): add `UpdateEmail`.
- Modify: every hand-written test `users` table that user-repository queries run against (`grep -rln "CREATE TABLE.*users" --include='*_test.go' .`; includes `internal/repositories/missing_coverage_test.go:49`, `internal/services/auth/totp_replay_test.go`, `internal/health/health_test.go`, `internal/services/secrets/rotation_roundtrip_test.go`, `internal/services/secrets/import_overwrite_roundtrip_test.go`): add `email TEXT`.
- Test: `internal/db/upgrade_path_test.go`, new `internal/repositories/user_repository_email_test.go` (package `repositories_test`, helpers `setupUserDB`, `newUser`, `newLogger`).

**Interfaces:**
- Produces: `model.User.Email string`; `UserRepositoryInterface.UpdateEmail(ctx context.Context, id uuid.UUID, email string) error` (returns `ErrNotFound`-wrapped error for an unknown ID).

- [ ] **Step 1: Write failing tests.** In `user_repository_email_test.go`: `TestUserRepository_CreateStoresEmail` (create with `Email: "a@example.com"`, `ReadByExternalSubject` returns it), `TestUserRepository_NoEmailReadsEmpty` (create without email, read back `""`), `TestUserRepository_UpdateEmail` (changes it; unknown ID returns `repositories.ErrNotFound`). Extend `upgrade_path_test.go` with `require.True(t, columnExists(t, conn, "users", "email"))` after the migration pass, and assert the pre-existing row reads a NULL email.
- [ ] **Step 2: Run to verify failure.** Run: `go test ./internal/repositories/ ./internal/db/ -run 'Email|Upgrade' -v`. Expected: FAIL (column and method missing).
- [ ] **Step 3: Implement.** Add `email TEXT` to the `users` CREATE TABLE and `"ALTER TABLE users ADD COLUMN email TEXT"` after the `totp_last_step` migration line. `Create` inserts `nil` when `Email == ""`, else the value. Every SELECT reads `COALESCE(email, '')` into `&user.Email`. `UpdateEmail` is a single `UPDATE users SET email = ? WHERE id = ?` using the same dialect rebind and metrics wrapper as neighbouring methods, returning `ErrNotFound` when no row changes. Add the retry-wrapper method in the existing `retried(...)` style and the two mock methods.
- [ ] **Step 4: Fix test schemas.** Add `email TEXT` to the hand-written `users` tables listed above.
- [ ] **Step 5: Verify.** Run: `go build ./... && go test ./internal/repositories/ ./internal/db/ ./internal/services/... ./internal/health/ -count=1`. Expected: PASS.
- [ ] **Step 6: Commit** with the `1-git-commit` skill.

---

### Task 2: External user policy

**Files:**
- Create: `internal/services/users/external_user_policy.go`
- Test: `internal/services/users/external_user_policy_test.go`

**Interfaces:**
- Produces:
  - `var ErrExternalUserNotAllowed error`. The concrete type implements `ClientFault() bool` returning `true`, so the database circuit breaker ignores it (see `internal/retry/retry.go:515`).
  - `type NotAllowedError struct{ Reason string }` with `Error()`, `ClientFault() bool` and `Is(target error) bool` (true for `ErrExternalUserNotAllowed`). Reasons: `jit_disabled`, `domain`, `email_unverified`, `claim`.
  - `type ExternalUserPolicyConfig struct { JITEnabled bool; AllowedEmailDomains []string; RequireEmailVerified bool; RequiredClaims map[string]string; DefaultRole string; EnforceOnExisting bool }`.
  - `type ExternalIdentity struct { Email string; EmailVerified bool; Claims map[string]any }`.
  - `func NewExternalUserPolicy(cfg ExternalUserPolicyConfig) (*ExternalUserPolicy, error)`. It lowercases domains, rejects a domain that is empty or contains `@` or whitespace, rejects an empty `required_claims` key, and rejects a `DefaultRole` other than `model.RoleUser` (an empty value becomes `model.RoleUser`).
  - `func (p *ExternalUserPolicy) Evaluate(id ExternalIdentity, isNew bool) error` and `func (p *ExternalUserPolicy) DefaultRole() string`. A nil receiver behaves as JIT off with `enforce_on_existing` true and no other checks.

- [ ] **Step 1: Write failing table tests** in `external_user_policy_test.go`: `TestEvaluate` cases for new user with JIT off (reason `jit_disabled`); JIT on with no restrictions allows; domain match, mismatch, case difference (`USER@Example.COM`), several `@`, missing email (reason `domain`); `require_email_verified` with unverified (reason `email_unverified`); domains set with `EmailVerified=false` (reason `email_unverified`); required claim scalar match, mismatch, array membership, array of non-strings, absent claim, claim of another type (reason `claim`); existing user with `EnforceOnExisting` true re-checked and with false skipped; nil policy. `TestNewExternalUserPolicy_Invalid` covers bad domain, empty claim key and `DefaultRole: "admin"`. `TestNotAllowedError` asserts `errors.Is(err, ErrExternalUserNotAllowed)` and `ClientFault()`.
- [ ] **Step 2: Run to verify failure.** Run: `go test ./internal/services/users/ -run 'Evaluate|ExternalUserPolicy|NotAllowed' -v`. Expected: FAIL (undefined).
- [ ] **Step 3: Implement** the types above in `external_user_policy.go`. Check order in `Evaluate`: `isNew && !JITEnabled`; then, when `isNew || EnforceOnExisting`, the domain, verified and claim checks.
- [ ] **Step 4: Verify.** Run: `go test ./internal/services/users/ -run 'Evaluate|ExternalUserPolicy|NotAllowed' -v`. Expected: PASS.
- [ ] **Step 5: Commit** with the `1-git-commit` skill.

---

### Task 3: OIDC transport (identity fields, PKCE, state compare)

**Files:**
- Modify: `internal/services/auth/oidc_service.go` (identity struct ~15-34; `AuthCodeURL` ~122 and ~219; `HandleCallback` ~226-300)
- Modify: `api/oidc.go` (cookie constants ~16; login handler ~84; callback state compare ~121 and cookie handling)
- Test: `internal/services/auth/oidc_service_test.go` (existing tests at 275 and 382-479 use the old signatures), `api/oidc_test.go` (mock at 47-58)

**Interfaces:**
- Produces:
  - `OIDCIdentity` gains `EmailVerified bool` and `Claims map[string]any`.
  - `OIDCService.AuthCodeURL(state, nonce, verifier string) string` and `OIDCService.HandleCallback(ctx, code, expectedNonce, verifier string) (*OIDCIdentity, error)`.
  - const `oidcPKCECookie = "oidc_pkce"` in `api/oidc.go`.

- [ ] **Step 1: Write failing tests.** In `oidc_service_test.go`: `TestOIDCService_AuthCodeURL_IncludesS256Challenge` (URL has `code_challenge_method=S256` and `code_challenge` equal to `oauth2.S256ChallengeFromVerifier(v)`); `TestHandleCallback_SendsCodeVerifier` (the fake token endpoint receives `code_verifier`); `TestHandleCallback_ParsesEmailVerified` (bool `true`, string `"true"`, string `"TRUE"`, string `"false"`, number `1` giving false, absent giving false); `TestHandleCallback_EmailFromUserInfoUsesUserInfoVerified`; `TestHandleCallback_ReturnsRawClaims`. In `api/oidc_test.go`: `TestOIDCCallback_MissingPKCECookie_400`, `TestOIDCCallback_PassesVerifierToService`, `TestOIDCLogin_SetsPKCECookie`, `TestOIDCCallback_StateMismatch_ClearsAllCookies`. Update the mock signatures and existing call sites.
- [ ] **Step 2: Run to verify failure.** Run: `go test ./internal/services/auth/ ./api/ -run 'OIDC|HandleCallback' -v`. Expected: FAIL.
- [ ] **Step 3: Implement.** `AuthCodeURL` adds `oauth2.S256ChallengeOption(verifier)`. `HandleCallback` calls `Exchange(ctx, code, oauth2.VerifierOption(verifier))` and stays a single, unretried call. Decode the ID-token claims into a `map[string]any` once as well as into `oidcClaims`; add `EmailVerified any` to `oidcClaims` and a helper `parseEmailVerified(v any) bool`. Login handler: `oauth2.GenerateVerifier()` stored with `setOIDCCookie`. Callback: missing PKCE cookie gives 400 like the nonce cookie; state compared with `subtle.ConstantTimeCompare`; a deferred helper clears the state, nonce, PKCE and CLI cookies on every return path (same attributes as `setOIDCCookie`, `MaxAge: -1`).
- [ ] **Step 4: Verify.** Run: `go build ./... && go test ./internal/services/auth/ ./api/ -count=1`. Expected: PASS.
- [ ] **Step 5: Commit** with the `1-git-commit` skill.

---

### Task 4: Policy-aware `FindOrCreateExternalUser`

**Files:**
- Modify: `internal/services/users/user_service.go` (request struct ~34; `userService` and `UserServiceConfig` ~148-170; `FindOrCreateExternalUser` ~273-309)
- Test: `internal/services/users/user_service_test.go` (tests at ~1035-1115)

**Interfaces:**
- Consumes: Task 1 `UserRepositoryInterface.UpdateEmail`, `model.User.Email`; Task 2 `ExternalUserPolicy`, `ExternalIdentity`, `ErrExternalUserNotAllowed`, `NotAllowedError`.
- Produces: `FindOrCreateExternalUserRequest` gains `Email string`, `EmailVerified bool`, `Claims map[string]any`. `UserServiceConfig` gains `ExternalUserPolicy *ExternalUserPolicy`.

- [ ] **Step 1: Write failing tests** (and fix the existing ones): `ReadByExternalSubject` not-found mocks must now return `fmt.Errorf("user not found: %w", repositories.ErrNotFound)`, and the creating tests pass a policy with `JITEnabled: true`. New tests: `TestFindOrCreateExternalUser_LookupDBError_CreatesNothing` (error is returned, `Create` never called); `TestFindOrCreateExternalUser_JITOff_NewUserDenied` (sentinel, no `Create`, `oidc_login_denied` logged); `TestFindOrCreateExternalUser_NilPolicy_DeniesNew`; `TestFindOrCreateExternalUser_ExistingUser_DeniedWhenEnforced`; `TestFindOrCreateExternalUser_ExistingUser_NotChecked_WhenEnforceOff`; `TestFindOrCreateExternalUser_ExistingUser_RefreshesEmail` (`UpdateEmail` called only when the email changed); `TestFindOrCreateExternalUser_EmailRefreshFailure_DoesNotFailLogin`; `TestFindOrCreateExternalUser_NewUser_StoresEmailAndDefaultRole`.
- [ ] **Step 2: Run to verify failure.** Run: `go test ./internal/services/users/ -run FindOrCreateExternalUser -v`. Expected: FAIL.
- [ ] **Step 3: Implement** the spec's flow: found then (if enforcing) `Evaluate(..., false)` then refresh email; `errors.Is(err, repositories.ErrNotFound)` then `Evaluate(..., true)` then create with `policy.DefaultRole()` and the email, keeping the username-collision retry; any other lookup error returns wrapped. On denial log `oidc_login_denied` with the `NotAllowedError.Reason`; on creation log `oidc_user_provisioned`. A nil policy uses the zero behaviour from Task 2.
- [ ] **Step 4: Verify.** Run: `go build ./... && go test ./internal/services/users/ ./internal/services/retry/ -count=1`. Expected: PASS.
- [ ] **Step 5: Commit** with the `1-git-commit` skill.

---

### Task 5: Handler wiring and error mapping

**Files:**
- Modify: `api/oidc.go` (`FindOrCreateExternalUser` call ~144-153)
- Test: `api/oidc_test.go`

**Interfaces:**
- Consumes: Task 3 `OIDCIdentity` fields; Task 4 request fields; Task 2 `userServices.ErrExternalUserNotAllowed`.

- [ ] **Step 1: Write failing tests:** `TestOIDCCallback_PolicyDenied_403` (mock returns `userServices.ErrExternalUserNotAllowed`; response is 403 with body `access denied` and no session issued); `TestOIDCCallback_LookupError_500`; `TestOIDCCallback_PassesEmailAndClaims` (request carries `Email`, `EmailVerified` and `Claims` from the identity).
- [ ] **Step 2: Run to verify failure.** Run: `go test ./api/ -run OIDCCallback -v`. Expected: FAIL.
- [ ] **Step 3: Implement.** Pass the new fields. On `errors.Is(err, userServices.ErrExternalUserNotAllowed)` write 403 `access denied` (log with `logBypassError`); other errors keep 500.
- [ ] **Step 4: Verify.** Run: `go test ./api/ -count=1`. Expected: PASS.
- [ ] **Step 5: Commit** with the `1-git-commit` skill.

---

### Task 6: Config, startup validation and docs

**Files:**
- Modify: `internal/container/service_container.go` (`initializeServices`, before `baseUserService` at ~589)
- Modify: `.rocketvault.yaml.example` (`oidc:` block at ~306)
- Modify: `docs/contributing/configuration.md` (add an OIDC section)
- Test: `internal/container/` (new `oidc_policy_config_test.go`)

**Interfaces:**
- Consumes: Task 2 `NewExternalUserPolicy`, `ExternalUserPolicyConfig`; Task 4 `UserServiceConfig.ExternalUserPolicy`.
- Produces: `func buildExternalUserPolicy(v *viper.Viper) (*userServices.ExternalUserPolicy, error)` in the container package.

- [ ] **Step 1: Write failing tests** in `oidc_policy_config_test.go`: defaults (`jit_enabled` false, `enforce_on_existing` true, role `user`); all keys read; `default_role: admin` returns an error; malformed domain returns an error; OIDC disabled returns a nil policy and no error even with junk keys.
- [ ] **Step 2: Run to verify failure.** Run: `go test ./internal/container/ -run OIDCPolicy -v`. Expected: FAIL.
- [ ] **Step 3: Implement** `buildExternalUserPolicy` (viper defaults set with `SetDefault` only for `enforce_on_existing`; `required_claims` read with `GetStringMapString`). Call it in `initializeServices` when `oidc.enabled` is true, return its error (this fails startup, unlike the existing warn-only OIDC discovery failure), and pass the result in `UserServiceConfig`.
- [ ] **Step 4: Document.** Add the six keys with comments to `.rocketvault.yaml.example` (JIT off by default, no real values). Add an OIDC policy section to `docs/contributing/configuration.md` with the table from the spec, a note that identities link by subject only, and the upgrade warning that new OIDC identities are denied until `jit_enabled: true`.
- [ ] **Step 5: Verify.** Run: `go build ./... && go test ./... -count=1 && golangci-lint run`. Expected: all clean.
- [ ] **Step 6: Commit** with the `1-git-commit` skill.

---

### Task 7: Tracking and release notes

**Files:**
- Modify: `docs/known-bugs.md` (new entries after the last `B<N>` entry; use the next free numbers)
- Create: `docs/release-notes/<next-version>-oidc-jit-policy.md` (match the style of `docs/release-notes/v4.9.0-login-rate-limiting.md`; pick the version with the user)

- [ ] **Step 1: Add two `known-bugs.md` entries with status Fixed** (commit hashes from Tasks 3 to 5): "OIDC flow has no PKCE" and "OIDC ignores `email_verified` and provisions on any lookup error". Use the Severity/Files/Symptom/Root cause format of neighbouring entries.
- [ ] **Step 2: File two GitHub issues** with `gh issue create` (title `B<N>: <summary>`, label `bug`, body with the same detail plus `Full detail: docs/known-bugs.md § B<N>`), then close them with a reference to the fixing commits.
- [ ] **Step 3: Write the release note.** It must state that JIT is now off by default, which keys to set to keep auto-provisioning, that PKCE is always on, and that `users.email` is added by migration.
- [ ] **Step 4: Verify.** Run: `grep -n "B<N>" docs/known-bugs.md` for both entries and `gh issue list --label bug --limit 5`. Expected: both present.
- [ ] **Step 5: Commit** with the `1-git-commit` skill.
