# Known Bugs and Deferred Refactors

This file tracks open bugs and intentionally deferred items with root-cause analysis
and fix recipes for each entry.

**Convention**: every new entry here also gets a matching GitHub issue (title
`B<N>: <summary>`, `bug` label), with the issue body carrying the same
Severity/Files/Symptom/Root cause detail as the entry itself (see any issue
from B52 onward, e.g. #17, for the format) plus a `Full detail:
.claude/known-bugs.md § B<N>` pointer. When an entry's status moves to
Fixed, close its issue (a PR's `Fixes #<N>` footer does this automatically
on merge).

---

## Open Bugs

### B1 — secrets table missing columns

**Status**: Fixed in commit `b46000b` (2026-03-08)
**Severity**: Resolved
**File**: `internal/db/db.go`

**What was fixed**: The `createOptimizedSchema` function's `CREATE TABLE secrets`
statement now includes both `deleted_at TIMESTAMP NULL` and
`purge_protection BOOLEAN NOT NULL DEFAULT FALSE` (lines 377-378). Corresponding
`ALTER TABLE secrets ADD COLUMN deleted_at ...` and
`ALTER TABLE secrets ADD COLUMN purge_protection ...` statements were also added to
`migrateSchema()` (lines 694-695) so existing databases are patched on startup.

See `.claude/database-init-patterns.md` for the `migrateSchema` pattern.

---

### B2 — Service-account JWT revocation gap

**Status**: Fixed in commit `229d982`
**Severity**: Resolved
**File**: `internal/services/oauth2/oauth2_service.go`, `internal/services/auth/authentication_service.go`

**What was fixed**: `IssueToken` now uses `client.ID` (not `uuid.Nil`) as the JWT jti.
`ValidateSession` branches on `claims.Role == model.RoleServiceAccount` and calls
`oauth2ClientRepo.GetByID(ctx, sessionID)`. If the client is not found (deleted),
disabled, or expired, the request is rejected immediately.

**Remaining limitation (by design)**: `RotateSecret` does not invalidate live tokens —
tokens remain valid until their JWT TTL expires after a secret rotation. This is standard
OAuth2 behavior: rotating a secret prevents *new* token issuance but not existing tokens.
The `jwt.expiry` lifetime bounds the exposure window — **up to 1 hour**, since the key is
optional and `internal/container/service_container.go:366-369` falls back to `time.Hour`,
which is also what both committed configs set. (Corrected 2026-09-04: this line said 15m,
understating the post-rotation exposure window fourfold. An operator who needs a tighter
bound after rotating a service-account secret must lower `jwt.expiry` explicitly.)

---

### B4 — `serve` initialized its DB connection and ServiceContainer twice

**Status**: Fixed in commit `1495e4b`
**Severity**: Resolved — was a startup-cost/correctness issue, not data loss
**File**: `cmd/root.go`, `cmd/serve.go`, `bootstrap/bootstrap.go`, `app/app.go`

**Root cause**: `persistentPreRun` (`cmd/root.go`) runs before every CLI command and
unconditionally opens a DB connection (`db.NewRepository(...).InitializeDB()`) and
builds a full `container.ServiceContainer` — which eagerly loads the JWT signing key,
initializes the OIDC service (a real discovery HTTP call to the issuer), and
initializes the software/HSM key provider — *before* it checks whether the command
is in the `systemCmds` allowlist. `serve` is in that allowlist (no auth required),
but that check only skips authentication, not the DB/container construction that
already happened. `serve()` then calls `bootstrap.Boot`, which independently builds
its own DB connection and `ServiceContainer` from scratch — the one actually wired
into the running server. Net effect: two DB connections opened and migrated, two
JWT-signing-key keychain reads, two OIDC discovery calls, and two key-provider inits
on every `rocketvault serve` startup, with the first of each pair immediately
discarded. Also caused a cosmetic "Rotation scheduler started" double-log: one line
logged inside `schedulerService.Start` (`internal/services/secrets/scheduler_service.go`),
a second, redundant one logged by its caller in `app.StartServer` (`app/app.go`) on
the same successful call — not a second scheduler, verified no second `.Start()` call
exists anywhere.

**Fix**: `serveCmd` now sets its own `PersistentPreRunE` (`servePreRun` in
`cmd/serve.go`), following the same pattern `cmd/vaults/preview_migration.go`
already uses for the same reason (skip the root pre-run's DB/container setup).
`servePreRun` installs only the logger on the context — `bootstrap.Boot` remains
the single place that builds the real DB connection and `ServiceContainer`.
Verified via full-repo grep that nothing on `serve`'s execution path (bootstrap,
app, server, api packages) reads any other context key `persistentPreRun` used to
set; `persistentPostRun`'s `common.DBClassKey` lookup already no-ops gracefully
when absent (covered by `TestPersistentPostRun_NoDBInContext`). Also removed the
redundant success-path log line in `app.StartServer`, since `scheduler.Start`
already logs the same message with the same `interval` field internally.
Bonus: this also fixes a latent staleness bug — the discarded pre-run container was
built from config *before* bootstrap injects vault secrets into Viper, so it was
never even representative of the real runtime config.

**Regression test**: `TestServeCmd_OverridesRootPersistentPreRun` and
`TestServePreRun_SetsLoggerInContext` in `cmd/cmd_test.go` assert `serveCmd` keeps
its own `PersistentPreRunE` so a future refactor can't silently re-inherit the
root's DB-initializing pre-run.

---

### B3 — Pre-upgrade JWTs rejected after v4.0.0 session-revocation fix

**Status**: Expected operational behavior — documented in
`docs/release-notes/v4.0.0-azure-rbac.md` § "Breaking changes" item 5
**Severity**: Low — self-resolving within one JWT lifetime (up to 1h; `jwt.expiry`
defaults to `time.Hour`, corrected 2026-09-04 from a stated 15m). Still Low: it
resolves without intervention and exposes no data, but the window is four times
what this entry claimed, so plan the upgrade accordingly.
**File**: `internal/services/auth/authentication_service.go`,
`internal/services/oauth2/oauth2_service.go`

**Root cause**: Two distinct mechanisms, both introduced the same day across
commits `b68e787`, `67d52e2`, and `229d982` — not a single unified fix:

- **User sessions** (`b68e787`): prior to the fix, JWTs had a random UUID as the
  jti with no link to `user_sessions`. After the upgrade, `ValidateSession`
  parses jti as a session ID and calls `sessionRepo.IsSessionRevoked`, which
  internally catches `sql.ErrNoRows` for a missing row and returns
  `(revoked=true, err=nil)` — `ValidateSession` then rejects with
  `"session revoked"` → 401.
- **Service accounts** (`229d982`, superseding an intermediate `uuid.Nil`
  scheme from `67d52e2`): `ValidateSession` never calls `IsSessionRevoked` for
  `RoleServiceAccount` claims — it takes a separate branch that resolves jti as
  a client ID via `oauth2ClientRepo.GetByID`. A pre-upgrade token's random jti
  matches no `oauth2_clients` row, `GetByID` hits `sql.ErrNoRows` directly, and
  `ValidateSession` rejects with `"service account not found or revoked"` → 401.

**Impact**: All users logged in at the time of a v4.0.0 deploy will receive a 401
on their next request. They must re-authenticate. Service-account tokens issued
before the upgrade are similarly invalidated, via the separate client-lookup
path above — no credential rotation needed, just a fresh token.

**Mitigation**: Deploy during low-traffic hours. The 401 is safe and self-resolving.
No data is lost. Users and service accounts simply need to re-authenticate.

---

### B5 — CircuitBreaker Open→HalfOpen admission race and half-open wedge

**Status**: Fixed in commits `40b865b` (admission race) and `455461b` (half-open
wedge follow-up; `29f3c41` adds the deterministic repro test for the latter)
**Severity**: Resolved
**File**: `internal/retry/retry.go`

**What was fixed**: `Execute` previously read `state` under `RLock`, released
the lock, then acted on it unlocked — including an entirely unlocked read of
`lastFailure` — so concurrent callers could all observe a stale `Open` state,
each independently transition to `HalfOpen`, and each be admitted into the
half-open trial with no cap; `HalfOpenRequests` was only ever checked after a
successful call, never as an admission gate before `fn()` ran. `admit()` now
performs the state check, `Open`→`HalfOpen` transition, and half-open slot
reservation as one locked critical section, capping concurrent/total
half-open admission at `HalfOpenRequests` (`40b865b`).

A follow-up review caught a second, related defect this introduced:
`finishHalfOpen`'s failure branch delegated to `recordFailure`, which only
flips state back to `Open` once `cb.failures` reaches `FailureThreshold`. With
half-open admission now capped at `HalfOpenRequests` (well below
`FailureThreshold` in every shipped config), a half-open trial could fail
without ever reopening the breaker — permanently wedging it in `HalfOpen`
with no path back to `Open` or forward to `Closed`. `finishHalfOpen` now
reopens the breaker unconditionally on any half-open trial failure, matching
standard circuit-breaker semantics; `recordFailure` itself is untouched —
`executeClosed`'s failure path still uses it as before (`455461b`).
`40b865b` adds `TestCircuitBreaker_HalfOpenAdmissionIsCapped` to pin down the
admission-race fix, and `455461b` adds
`TestCircuitBreaker_HalfOpenFailureReopensImmediately` to exercise the
half-open reopen path under a production-shaped config. Neither test alone
actually reaches the specific state the wedge fix protects against —
`recordFailure()` only sets `state=Open` once `cb.failures` is already at or
above `FailureThreshold`, which happens to already hold by the time a
sequential trip reaches `Open`, so both tests still pass even against a
version of `finishHalfOpen` that delegates to `recordFailure`. `29f3c41`
closes that gap with a third test,
`TestCircuitBreaker_LateSuccessDoesNotCausePermanentHalfOpenWedge`, which
reproduces the real reachable path deterministically: a closed-state call
admitted before the trip completes successfully after the trip and calls
the unexported `recordSuccess()` directly (reachable since the test is in
package `retry`), zeroing `cb.failures` while `state` is already `Open` with
no check on `cb.state` — from there, `HalfOpenRequests` failed half-open
trials are never enough to re-cross `FailureThreshold` under the old
delegating-to-`recordFailure` logic. This test was verified to fail against
the pre-`455461b` `finishHalfOpen` and pass against the current fix.

---

### B6 — `SetRetryDefaults` retryable_errors defaults drifted from policy source of truth

**Status**: Fixed in commit `d13db0c`
**Severity**: Resolved
**File**: `internal/retry/config_loader.go`

**What was fixed**: `SetRetryDefaults` hand-duplicated the `database` and
`external_services` `retryable_errors` lists as inline string slices instead
of referencing `DatabasePolicy()`/`ExternalServicePolicy()`, the actual source
of truth. The `external_services` list had fallen out of sync — missing the
5xx-reason-phrase entries already present in `ExternalServicePolicy()` — which
silently disabled 5xx retry for any deployment that didn't explicitly
override `retry.external_services.retryable_errors` in its own config.
`SetRetryDefaults` now sets both defaults directly from
`DatabasePolicy().RetryableErrors`/`ExternalServicePolicy().RetryableErrors`,
so the two can no longer drift apart. `TestSetRetryDefaults` was extended to
assert both defaults equal their source `Policy` function's list exactly.

---

### B7 — OIDC login retried the non-idempotent OAuth2 authorization-code exchange

**Status**: Fixed in commit `10fce4e`
**Severity**: Resolved
**File**: `internal/services/auth/oidc_service.go`

**What was fixed**: `HandleCallback`'s call to `s.oauth2Config.Exchange`
redeems a single-use authorization code, but it was wrapped in the same
`withRetry`/`ExternalServicePolicy` retry policy used for idempotent calls
(`Verify`, `UserInfo`). If the exchange actually succeeded at the IdP but the
response was lost (e.g. a timeout), the retry replayed the already-consumed
code, which the IdP correctly rejects as `invalid_grant` — turning a
successful login into a failed one. `Exchange` now runs exactly once,
unwrapped; a failure surfaces immediately and the user restarts the login
flow to obtain a fresh code. `TestHandleCallback_ExchangeIsNeverRetried`
pins this down, accounting for `golang.org/x/oauth2`'s own internal
auth-style-probing retry (which is independent of, and not to be confused
with, this codebase's retry wrapper).

---

### B8 — OIDC callback's Verify/UserInfo retries could exceed a typical reverse-proxy timeout

**Status**: Fixed in commits `6f5e768` (new `interactive` retry tier, plumbing
only) and `257ff16` (wires `HandleCallback`'s `Verify`/`UserInfo` calls to it)
**Severity**: Resolved
**File**: `internal/retry/config.go`, `internal/retry/retry.go`,
`internal/services/retry/retry_service.go`, `internal/services/auth/oidc_service.go`

**What was fixed**: `HandleCallback`'s `Verify` and `UserInfo` calls were
retried under `ExternalServicePolicy`, whose worst-case backoff (5 attempts,
1s–30s) can sum to roughly 19.5s per call. Stacked across `HandleCallback`'s
synchronous, user-facing request path, this risked exceeding a typical 30s
reverse-proxy/browser timeout well before the retry budget was exhausted,
turning a slow-but-eventually-successful IdP call into a hard failure for the
end user. `6f5e768` adds a fourth retry tier, `retry.InteractivePolicy()`
(`Config.Interactive`, `RetryService.ExecuteInteractiveOperation`/
`GetInteractivePolicy`), with deliberately short defaults (2 attempts,
250ms–2s backoff) for synchronous request paths that can't risk exceeding a
proxy/browser timeout — plumbing only, not itself consumed by any caller.
`257ff16` routes `HandleCallback`'s `Verify` and `UserInfo` calls through the
new tier via a widened local `RetryExecutor` interface and a new
`withInteractiveRetry` helper; `Discovery` (a startup-time, not per-request,
call) is unchanged. `TestHandleCallback_VerifyAndUserInfoUseInteractivePolicy`
asserts both calls go through the interactive tier and not
`ExecuteExternalServiceOperation`.

---

### B9 — JWT forgery via the HS256 "migration window" fallback

**Status**: Fixed 2026-08-16 — see
`docs/superpowers/plans/2026-08-16-remove-hs256-jwt-fallback.md`
**Severity**: Resolved — was High (full administrative takeover, confirmed by
live exploitation in `.claude/pentest-report-2026-08-16.md` § H1)
**File**: `internal/services/auth/jwt_service.go`,
`internal/container/service_container.go`

**Root cause**: `jwtService.ValidateToken` fell back to HMAC-SHA256
verification for any token whose header carried no `kid`, via
`validateHS256Fallback`. Three things made that fatal rather than merely
legacy:

1. The HMAC key was `JWTConfig.SecretKey`, read from `viper.GetString("jwt_secret")`
   — a static value committed to `.rocketvault.yaml` and present throughout git
   history. With HS256 the verification key *is* the signing key, so a public
   verification key means anyone can mint tokens.
2. `NewJWTServiceWithProvider` computed `migrationDeadline = time.Now().Add(config.MigrationWindow)`
   **at service construction**, so `jwt.migration_window: "24h"` restarted on
   every process boot. The window never closed.
3. `ValidateSession` only checks that the token's `jti` maps to a non-revoked
   session, and trusts the `role` claim inside the token — so an attacker could
   log in normally as a low-privilege user, reuse that real session id, and set
   `role: admin` in a forged token.

**Evidence**: a forged token (no `kid`, `role: admin`, real `jti` from a
`role=user` login, correct issuer/audience, signed with the committed
`jwt_secret`) was accepted by `GET /api/v1/users/` → HTTP 200 with the
admin-only user list. A random `jti` → 401 and a wrong secret → 401, confirming
the only missing control was the secrecy of the HMAC key.

**What was fixed**: the HS256 verification path is gone, not repaired. A token
without a `kid` header is rejected outright (`invalid JWT token: missing kid
header`); `legacyJWTService`/`NewJWTService` — the only code able to *mint* an
HS256 token — were deleted along with `JWTConfig.SecretKey` and
`JWTConfig.MigrationWindow`; and the container now treats a
`signing.NewProvider` failure as a fatal startup error instead of degrading to
symmetric signing. Repair was rejected because this branch has never shipped a
tagged release, so there was no population of legacy HS256 tokens to migrate —
the path protected zero real migrations while providing one complete
authentication bypass.
`TestJWTService_Provider_KidlessHS256Token_Rejected` pins the fix by replaying
the exploit with the leaked secret.

**Remaining, tracked separately**:
- Rotating `jwt_secret` and removing it from tracked config and git history is
  pentest finding **H4**.
- `ValidateSession` still trusts the JWT's `role` claim rather than re-reading
  the role from the database. With HS256 gone this requires compromise of the
  asymmetric private key to exploit, so it is defence-in-depth rather than a
  live hole; fixing it means a DB read per authenticated request and a decision
  about role-change propagation latency.

---

### B10 — Live secrets committed to git, recurrence of a fixed incident

**Status**: Fixed 2026-08-16 (structural fix; all four secrets rotated,
including `master_key` — see item 6 below, executed 2026-08-16 against the
real dev database with a full change log at
`.claude/master-key-rotation-log-2026-08-16.md`) — see
`docs/superpowers/plans/2026-08-16-secrets-in-git-remediation.md`. Git-history
purge ran 2026-08-17 (see item 9 below) — the "remaining, tracked separately"
gap this note used to describe is closed. One recurrence happened in between
(also item 9): a separate session re-tracked `.rocketvault.yaml` directly on
`v-4.0.0` and pushed it before the structural fix had merged there.
**Severity**: Resolved — was High (full offline decryption of every stored
secret, admin-token forgery via the paired H1 finding, and first-admin-bootstrap
takeover, confirmed by live git-history inspection in
`.claude/pentest-report-2026-08-16.md` § H4)
**File**: `.gitignore`, `.rocketvault.yaml`, `.rocketvault.yaml.example`,
`.github/workflows/go.yml`, plus 9 tracked docs/scripts/tests that duplicated
the same values

**Root cause**: `.claude/security-incident-2026-03-07.md` (2026-03-07) already
fixed this exact class of leak once — `git rm --cached` on the then-named
`.password-manager*.yaml` files, plus a `.gitignore` entry for that name
pattern. The very next commit touching this area, one day later, renamed the
project to RocketVault and introduced a brand-new `.rocketvault.yaml` — under a
name the old `.gitignore` pattern didn't cover. It has been tracked and
unrotated ever since. A second, unrelated `.gitignore` line
(`rocketvault-*`, under "Application binaries") looks like it might have been
meant to catch this too; it never could, because it requires no leading dot and
a trailing dash, and `.rocketvault.yaml` has neither. Nothing ever tested that
either pattern actually matched the file it needed to match — that is the
literal, specific root cause, verified with `git check-ignore -v
.rocketvault.yaml` (no output, exit 1, before this fix).

The same four secret values (`master_key`, `jwt_secret`, `bootstrap_token`,
`hsm.pin`) were also duplicated, in whole or in part, across 9 other tracked
files (docs, a test fixture, a capture script) — including one,
`scripts/README.md`, still quoting an even older, already-`git rm`'d secret
generation from `.password-manager-test.yaml` (removed from the working tree in
commit `cb93bc9`, but never purged from history, and apparently copy-pasted
into a doc before that removal).

**What was fixed**:
1. `.gitignore` — new block matching `.rocketvault.yaml`, `.rocketvault-*.yaml`,
   and `.rocketvault.yaml.local`, with a negation for the new
   `.rocketvault.yaml.example` template. Verified with `git check-ignore -v`
   against all four names.
2. `.rocketvault.yaml.example` — committed template with instructional
   placeholders, mirroring the existing `.env`/`.env.example` pattern. The real
   `.rocketvault.yaml` is `git rm --cached`'d (working tree untouched).
3. Two new CI steps in `.github/workflows/go.yml`'s `security` job: a
   structural check that no `.rocketvault*.yaml` variant is ever tracked again,
   and a denylist check for the exact secret bytes already known to be
   compromised. A gitleaks-based alternative was evaluated and rejected after
   producing 50 findings locally, nearly all false positives on test fixtures —
   see the design doc.
4. `bootstrap_token` rotated to a freshly generated value; the old one
   (`***SECRET-REMOVED-2026-08-17***`) is permanently compromised,
   never to be reused.
5. `jwt_secret`/`jwt.migration_window` deleted from `.rocketvault.yaml` outright
   rather than rotated — H1 (`docs/superpowers/plans/2026-08-16-remove-hs256-jwt-fallback.md`)
   made both keys fully unread by any Go code, so rotating a value nothing
   reads would be motion without effect.
6. `master_key` — **rotated**, 2026-08-16, with explicit human sign-off. Used
   H3's `rocketvault master-key rotate` tool
   (`docs/superpowers/plans/2026-08-16-master-key-rotation.md`, see § B12)
   against the real dev database: backed up `dev-rocketvault.db` first, dry-run
   verified (3 rows: 2 `secrets`, 1 `keys`; 1 HSM-backed key correctly skipped),
   real run matched the dry run exactly with no errors, `.rocketvault.yaml`
   updated to the new key, server restarted on the existing (pre-this-branch)
   binary to confirm rotation doesn't require the new code to be deployed.
   Verified at the database level (ciphertext for both `secrets` rows
   genuinely changed vs. the pre-rotation backup); a live decrypt-via-API
   round-trip was attempted but blocked by an unrelated, pre-existing CLI
   session/refresh-token issue — not chased further, and **still worth an
   operator double-check** (`docs/runbooks/master-key-rotation.md` step 7).
   Full step-by-step log: `.claude/master-key-rotation-log-2026-08-16.md`. The
   old placeholder key (`***SECRET-REMOVED-2026-08-17***`, base64
   for `0123456789abcdef0123456789abcdef`) is retired and treated as
   permanently compromised; the pre-rotation database backup
   (`dev-rocketvault.db.pre-rotation-2026-08-16`) remains sealed under it.
7. `hsm.pin` — documented as a manual `softhsm2-util --pin ... --new-pin ...`
   runbook (`docs/runbooks/hsm-pin-rotation.md`), not automated: it is real,
   shared PKCS#11 token state, not a config value.
8. Nine other tracked files with duplicated literal values fixed to placeholders
   or config-driven reads.
9. **Recurrence + git-history purge, 2026-08-17.** Before this branch's fix
   (item 1-2 above) had merged into `v-4.0.0`, a separate Claude Code session
   working directly on the main checkout ran its own master_key rotation and
   committed the result — including `.rocketvault.yaml`, still git-tracked on
   `v-4.0.0` at that point — in commit `79d3598` ("chore: rotate dev
   master_key, update compose healthcheck path"), which was pushed to
   `origin/v-4.0.0` before being noticed. This put a second `master_key` value
   live in public git history (repo confirmed public; confirmed not used in
   production) alongside the four original values. Response: (a) merged this
   branch's fix into `v-4.0.0` so the file stays untracked going forward; (b)
   ran a full `git-filter-repo` purge against a fresh mirror clone — removed
   every historical `.rocketvault*.yaml`/`.password-manager*.yaml` file
   entirely and scrubbed all 7 known secret literals (the original 6 plus the
   `79d3598` value) from every remaining blob, across all 1027 commits, 6
   branches, 7 tags; verified clean via a full object-level sweep (9401
   objects, zero matches) before force-pushing the rewritten history (no other
   clones/forks existed, confirmed by the human operator, so no collaborator
   coordination was needed); (c) rotated `master_key` a third time so the live
   value was never exposed anywhere in history. Full detail:
   `.claude/master-key-rotation-log-2026-08-16.md` (§ "Third rotation —
   2026-08-17"). **Residual risk**: any clone/fork/cache made before
   2026-08-17, outside the operator's knowledge, still has the pre-purge
   history — accepted, same as the four original values' pre-rotation
   exposure.

**Regression tests**: none in the traditional sense (no Go logic changed beyond
one test-fixture swap) — the "tests" for this fix are the CI gate itself
(Task 6) and the verification gate in the design doc, both grep-based against
the real repository content, run and confirmed clean before this entry was
written.

**Remaining, tracked separately**:
- `master_key` rotation: **executed** 2026-08-16 against the live database,
  see item 6 above and `.claude/master-key-rotation-log-2026-08-16.md` for the
  full step-by-step record. A live decrypt-via-API verification is still
  recommended as a final operator sanity check.
- the git history itself still contains every value listed above, recoverable
  by anyone who has ever cloned this repository —
  `docs/superpowers/plans/2026-08-16-git-history-secret-purge-followup.md` is the
  deferred `git filter-repo` + coordinated force-push procedure to actually purge
  it. Until that runs, treat every value named in this entry as permanently
  public, rotation notwithstanding.

---

### B11 — Cross-vault authorization bypass on flat data-plane routes

**Status**: Fixed in commit `b4fc132`
**Severity**: High — broken access control; per-vault revocation was not enforced
**Files**: `api/context.go`, `api/keys.go`

**Root cause**: `scopeFromRequest` (`api/context.go`) branched on route shape: a
vault scope for `/api/v1/vaults/{vault_name}/...`, an owner scope for the legacy
flat routes (`/api/v1/secrets/{id}`, `/keys/{id}`, `/certificates/{id}` and their
sub-routes). An owner scope's repository predicate is `user_id = ?` with no
`vault_id` term at all (`internal/repositories/scope_predicate.go`), and
`model/scope.go` had already flagged `ScopeOwner` as "P1 only; retired in P2".
Meanwhile `PolicyMiddleware` authorized every flat-route request against the
**default** vault, because `VaultResolutionMiddleware` resolves
`model.DefaultVaultName` for any route with no `vault_name` variable. So the
authorization decision and the data lookup disagreed about which vault the
request targeted: a caller holding any data-plane grant on the default vault
could keep reading — and, with a set/create grant, writing — resources they had
created in **any other vault**, including one where their role assignment had
been explicitly revoked. Confirmed by live exploitation during the 2026-08-16
pentest (`.claude/pentest-report-2026-08-16.md` § H2): after
`DELETE .../role-assignments/{id}` returned 200, the vault-scoped route returned
403 for the secret while `GET /api/v1/secrets/{id}` still returned its value.

Secrets and certificates were affected on every flat read and write. Keys were
affected on get/list/update/versions only: `KeyService.DeleteKey`,
`KeyService.RotateKey` and `cryptoService.loadAndAuthorize` each carry an in-Go
"B6 conjunction" that re-applies the vault term when the scope is owner-scoped.
`deleteSecret` and `deleteCertificate` were already immune — both build
`model.NewVaultScope` by hand instead of calling the helper — which is why the
bug survived: the pattern was known and applied to two handlers out of 35 call
sites.

**Fix**: `scopeFromRequest` now returns `model.NewVaultScope(vaultID, userID)`
for every route shape. The vault id needed no change — `vaultIDFromRequest`
already resolved the default vault for flat routes, which is the same vault
`PolicyMiddleware` checks. `createKey`'s response read-back (`api/keys.go`), the
only other owner-scope construction on the request path, changed with it, so
`grep -rn "NewOwnerScope" api/` is now empty. `deleteSecret`/`deleteCertificate`
keep their hand-built scopes as belt-and-braces; only their comments changed.
Regression coverage is in `api/flat_route_vault_scope_test.go`: real SQLite
repositories behind the real router, seeding a caller-owned resource in another
vault and asserting 404 on the flat route, each paired with a positive control
in the resolved vault.

**Known behavior change**: flat-route listing (`GET /secrets`, `/keys`,
`/certificates`, `POST /secrets/export`, the deleted-item lists) now returns
every row in the default vault rather than only the caller's own rows across
every vault — the Azure-parity "vault members see all" semantic already in force
on the vault-scoped routes. See
`docs/release-notes/v4.1.0-role-parity-and-authz-fix.md`.

**Deliberately not fixed here** (bounded fix, see
`docs/superpowers/specs/2026-08-16-flat-route-vault-scope-fix-design.md`
§ "Not in scope"): `ScopeOwner` still exists in `model/scope.go` and the
repository predicate; `cmd/version.go` still builds
`model.NewOwnerScope(uuid.Nil, userID)` on the CLI path, which needs its own
`vaultcli.ResolveVaultID` + `RequireDataAction` treatment; and the three B6
conjunctions in the key services are now unreachable from HTTP but were left in
place, along with their comments claiming flat routes still reach them.

---

### B12 — All secrets and software key PEMs sealed with a predictable, git-committed master key

**Status**: Fixed on branch `v-4.0.0` (2026-08-16) — tool and startup guard landed; the
rotation itself against the real dev/prod databases is tracked separately as H4
**Severity**: High — confirmed by live exploitation during the 2026-08-16 penetration test
**File**: `common/encrypt.go`, `common/masterkey.go`, `bootstrap/bootstrap.go`,
`internal/rekey/`, `cmd/master_key.go`, `.rocketvault.yaml`

**Root cause**: Secret values, software (non-HSM) key PEMs, and certificate private keys are all
sealed with AES-256-GCM under a single key read from `viper.GetString("master_key")`. The AES-GCM
construction is correct (fresh random 12-byte nonce per seal, prepended, real AEAD). The defect was
the key *value*: the committed `.rocketvault.yaml` shipped
`master_key: "***SECRET-REMOVED-2026-08-17***"`, which base64-decodes to the ASCII
string `0123456789abcdef0123456789abcdef` — a placeholder, in git, identical in every deployment
that never changed it. Anyone holding a copy of the database (stolen backup, snapshot,
decommissioned disk, or the repository itself) decrypted every secret offline. Nothing in the
codebase checked key quality, and the two length checks even disagreed: `EncryptSecret` accepted
`len(key) >= 32` while `DecryptSecret` required `== 32`.

Rotating the key was not a one-line config change either: with no re-encryption path anywhere in
the codebase, changing `master_key` made every existing row permanently undecryptable. That is why
the fix is a migration tool, not just a guard.

**Blast radius** (every column sealed with this key, established by mapping all nine callers of
`common.EncryptSecret`/`DecryptSecret` to the columns they write): `secrets.value`,
`secret_versions.value`, `keys.value`, `key_versions.value`, `certificates.private_key`. The
`keys` entry includes `internal/signing.SelfPKIProvider`'s JWT signing key, which is stored as an
ordinary `keys` row. PKCS#11/HSM key rows (`pkcs11:` prefix) hold token handles, not ciphertext,
and are unaffected. User passwords and OAuth2 client secrets are bcrypt hashes; TOTP secrets are
stored in plaintext (a separate issue) — none of those are touched by rotation.

**Fix**:
1. `common.EncryptWithKey`/`DecryptWithKey`/`ParseMasterKey` — key-parameterized AES-256-GCM
   primitives, so one process can open under the old key and seal under the new one.
   `EncryptSecret`/`DecryptSecret` keep their signatures and now agree on requiring exactly 32
   bytes.
2. `common.ValidateMasterKey` — rejects a missing/malformed/wrong-length key, the known-compromised
   committed default (constant-time compare), all-printable-ASCII keys, and keys with fewer than 16
   distinct byte values.
3. `bootstrap.ConfigurationValidator.ValidateMasterKey`, called as `setup` Step 1c (after Step 1b
   injects vault-sourced secrets into Viper, since that injection can supply `master_key` itself) —
   the server now refuses to start on a weak key, with no override flag.
4. `internal/rekey` — plan-then-apply re-encryption over the five columns above using raw
   dialect-aware SQL (repositories are scope- and soft-delete-filtered and would re-encrypt on the
   way through, so they are the wrong layer). Each row is classified by trying the **new** key
   first, which makes an interrupted run safe to resume without double-encrypting; `pkcs11:` rows
   are skipped; updates run in batched transactions guarded by `AND <column> = <old ciphertext>`
   with `RowsAffected() == 1` asserted, so a still-running server causes a loud abort instead of
   silent data loss.
5. `rocketvault master-key rotate --new-key-env NEW_MASTER_KEY [--old-key-env ...] [--dry-run]` —
   admin-only CLI driving the engine. Keys are passed by environment-variable *name*, never in
   argv; the new key must pass `ValidateMasterKey`; neither key nor any plaintext is ever logged.

**Regression tests**: `common/masterkey_test.go` (weak-key rejection, including the exact committed
value), `common/encrypt_key_test.go` (key-parameterized round-trip, wrong-key failure),
`internal/rekey/classify_test.go` and `internal/rekey/rekey_test.go` (dry-run writes nothing,
full re-encryption round-trips under the new key, second run is a no-op, partial migration resumes,
`pkcs11:` rows untouched, wrong old key aborts with no writes), `bootstrap/bootstrap_test.go`
(startup guard), `cmd/master_key_test.go` (admin gate, key resolution).

**Operational note**: after this landed, the server refuses to boot against the repository's
working-tree `.rocketvault.yaml` (no longer git-tracked, but its value is still recoverable from
git history) until the key is rotated — intended. The procedure is
`docs/runbooks/master-key-rotation.md`. Backups taken before a rotation remain encrypted with the
old key and need the old key to restore.

**Related**: H4 (removing the committed key from `.rocketvault.yaml` and moving custody to the
environment/secret store) invokes this tool to perform the actual rotation. Envelope encryption
(per-secret data keys wrapped by a KEK, making future rotations O(1) instead of O(rows)) was
considered and deliberately deferred — it is a storage-format change touching every read path.

---

### B13 — CLI `audit logs`/`audit report`/`audit config` bypassed the admin-only restriction enforced by their HTTP equivalents

**Status**: Fixed in commits `46e3686` (helper), `eaaaedf` (logs), `0013f91`
(report), `466d76c` (config)
**Severity**: High — confirmed by a live pentest run 2026-08-16
**File**: `cmd/audit/authz.go`, `cmd/audit/logs.go`, `cmd/audit/report.go`,
`cmd/audit/config.go`

**Root cause**: `api/audit.go`'s five HTTP handlers (`getAuditLogs`,
`getSOC2Report`, `getGDPRReport`, `getAuditConfig`, `patchAuditConfig`) each
correctly gate on `claims.Role != model.RoleAdmin` before touching
`ComplianceReportService`. CLI commands bypass the HTTP middleware chain
entirely and are individually responsible for reproducing the equivalent
check (`CLAUDE.md` § "CLI Authorization") — the three CLI equivalents under
`cmd/audit/` never did. Each `RunE` only checked that a service container was
present in context, then called straight into `sc.GetComplianceReportService()`.
A plain `role=user` account with no admin or audit grant could run `rocketvault
audit logs` or `rocketvault audit report --type soc2 ...` and get the full
cross-vault audit trail and a complete SOC2 report covering every user
including the admin — confirmed live before the fix.

**What was fixed**: Added `requireAuditAdmin(cmd *cobra.Command)
(*model.Claims, error)` (`cmd/audit/authz.go`), modeled directly on
`cmd/backup.go`'s pre-existing `requireBackupAdmin` — same category of check
(global admin gate, no vault to scope to). Called from the top of
`logsCmd.RunE`, `reportCmd.RunE`, and `configCmd.RunE`, immediately after
each command's existing service-container guard and before any flag parsing
or service call. `TestLogsCmd_NonAdmin_Forbidden`,
`TestReportCmd_NonAdmin_Forbidden`, and `TestConfigCmd_NonAdmin_Forbidden`
(`cmd/audit/audit_cmds_test.go`) each assert both the `forbidden` error and,
via `AssertNotCalled`, that the underlying `ComplianceReportService` method
was never invoked.

**Spec/plan**: `docs/superpowers/specs/2026-08-16-cli-audit-authz-fix-design.md`,
`docs/superpowers/plans/2026-08-16-cli-audit-authz-fix.md`.

---

### B14 — CLI `vaults get`/`vaults list` performed zero authorization checks

**Status**: Fixed in commit `93339d1`
**Severity**: High — any authenticated CLI user, including a plain `user` role
with no vault grants, could enumerate every vault's metadata instance-wide
**File**: `cmd/vaults/authz.go`, `cmd/vaults/get.go`, `cmd/vaults/list.go`

**Root cause**: Same bug class as B11/B13 — `cmd/vaults/get.go` and
`cmd/vaults/list.go` bypass the HTTP middleware chain entirely and never
reproduced the `CanManageVault` check their HTTP equivalents (`api/vault.go`'s
`getVault`/`listVaults`) both require.

**What was fixed**: Added `requireCanListVaults` (`cmd/vaults/authz.go`,
checked against `uuid.Nil` since list has no single target vault, mirroring
`listVaults`) and wired the pre-existing `requireCanManageVault` into
`get.go`. `TestVaultsGet_ForbiddenWithoutGrant`/
`TestVaultsList_ForbiddenWithoutGlobalGrant` (`cmd/vaults/vaults_more_test.go`)
pin the fix.

**Spec/plan**: `docs/plans/2026-08-18-azure-keyvault-parity-audit.md` (Critical
Finding #1/F2), `docs/superpowers/plans/2026-08-18-security-short-term-fixes.md`
(Task 1).

---

### B15 — `RestoreSecret`/`RestoreKey`/`RestoreCertificate` wrote the blob's embedded vault, not the caller's authorized vault

**Status**: Fixed in commit `c5bf97d`
**Severity**: High — a caller with restore permission in one vault could
silently write a restored secret/key/certificate into any vault the backup
blob happened to reference
**File**: `internal/backup/item_backup.go`, `api/backup_item.go`

**Root cause**: `ItemBackupService.RestoreSecret`/`RestoreKey`/
`RestoreCertificate` decoded the backup blob and persisted the item using the
`vault_id` embedded inside that blob, instead of the vault the HTTP request
was actually authorized against. The audit only named the `RestoreSecret`
instance, but `RestoreKey`/`RestoreCertificate` shared the identical bug.

**What was fixed**: All three methods gained a `vaultID` parameter — the
vault resolved from the authorized request (`vaultIDFromRequest`) — and now
write that value onto the restored item's `VaultID`, never the blob's.
`TestRestoreSecretWritesAuthorizedVaultNotBlobVault`
(`internal/backup/item_backup_test.go`) and the HTTP-level regression test in
`api/backup_item_test.go` pin the fix.

**Spec/plan**: `docs/plans/2026-08-18-azure-keyvault-parity-audit.md`
(Secrets findings, High), `docs/superpowers/plans/2026-08-18-security-short-term-fixes.md`
(Task 2).

---

### B16 — Role-assignment grant/revoke never audit-logged the success path

**Status**: Fixed in commit `62c4b7b`
**Severity**: High — the single most security-sensitive action in the RBAC
system (granting/revoking a per-vault Azure role) left no forensic trail;
`RevokeAssignment` had zero audit calls on any path
**File**: `internal/services/authorization/role_assignment_service.go`

**Root cause**: `RoleAssignmentService.AssignRole` only logged on failure
paths; `RevokeAssignment` didn't call `LogAuditInfo`/`LogAuditError` at all.
A malicious admin who self-granted excess privilege then revoked it was
invisible to `GET /audit/logs`.

**What was fixed**: Added `s.log.LogAuditInfo(...)` success-path calls to
both methods (`"assign_role"`/`"revoke_role_assignment"`, matching the
existing sentinel-error/`LogAuditInfo` convention).
`TestAssignRole_LogsSuccessAudit`/`TestRevokeAssignment_LogsSuccessAudit`
(`internal/services/authorization/role_assignment_service_test.go`) pin the
fix.

**Spec/plan**: `docs/plans/2026-08-18-azure-keyvault-parity-audit.md`
(Critical Finding #6), `docs/superpowers/plans/2026-08-18-security-short-term-fixes.md`
(Task 3).

---

### B17 — Recover/purge success was never audit-logged for secrets, keys, or certificates

**Status**: Fixed in commit `51d8bae`
**Severity**: High — an irreversible purge of vault material produced zero
audit record of who did it or when; vaults were the only domain that logged
this correctly
**File**: `internal/services/secrets/secret_service.go`,
`internal/services/keys/key_service.go`,
`internal/services/certificates/certificate_service.go`

**Root cause**: `RecoverSecret`/`PurgeSecret`/`RecoverKey`/`PurgeKey`/
`RecoverCertificate`/`PurgeCertificate` only logged the "not found" guard
failure, never a success-path audit row, unlike `vault_service.go`'s
`DeleteVault`/`RecoverVault`/`PurgeVault`.

**What was fixed**: Added `s.logger.LogAuditInfo(scope.ActorID().String(),
"<recover|purge>_<secret|key|certificate>", "success", ...)` to all six
methods' success paths, matching the existing `vault_service.go` pattern.
Six new tests (`*_LogsSuccessAudit`) across
`internal/services/secrets/secret_scope_service_test.go`,
`internal/services/keys/key_soft_delete_test.go`, and
`internal/services/certificates/cert_soft_delete_test.go` pin the fix.

**Spec/plan**: `docs/plans/2026-08-18-azure-keyvault-parity-audit.md`
(Critical Finding #7), `docs/superpowers/plans/2026-08-18-security-short-term-fixes.md`
(Task 4).

---

### B18 — SOC2 report's `AuthSuccesses`/`AuthFailures` counters were silently wrong in production

**Status**: Fixed in commit `4e50061`
**Severity**: High — a SOC 2 compliance report generated from real production
data showed a 100% authentication failure rate regardless of reality
**File**: `internal/services/auth/authentication_service.go`,
`internal/container/service_container.go`

**Root cause**: The real `AuthenticateUser`/`issueSession` write path only
called `s.logger.LogAuditInfo`/`LogAuditError` (a lossy legacy shim that
never populates `AuditLog.Outcome`), never `AuditService.RecordEvent` (the
rich path HTTP middleware already uses). Every real login, success or
failure, persisted `Outcome = ""`, which `ComplianceReportService`'s SOC2
report counts as neither a success nor a failure it can attribute correctly.
The existing unit test masked this by seeding `Outcome` directly into the
repo, bypassing the real write path entirely.

**What was fixed**: `AuthenticationConfig`/`authenticationService` gained an
optional `AuditService auditServices.AuditServiceInterface` field, wired in
`internal/container/service_container.go`. `AuthenticateUser`'s four failure
branches and `issueSession`'s success log now route through
`AuditService.RecordEvent` (falling back to the old `LogAuditInfo` path only
when `AuditService` is nil, e.g. in tests that don't set it up).
`TestAuthenticateUser_RecordsRichAuditOutcomeOnSuccessAndFailure`
(`internal/services/auth/authentication_service_test.go`) exercises the real
write path end-to-end and asserts a persisted `Outcome` of `"success"`/
`"failure"`, not the seeded-row shortcut the old test used.

**Spec/plan**: `docs/plans/2026-08-18-azure-keyvault-parity-audit.md`
(Critical Finding #8), `docs/superpowers/plans/2026-08-18-security-short-term-fixes.md`
(Task 5).

---

### B19 — Any Key Vault Data Access Administrator could grant itself, Purge Operator, or Certificate User

**Status**: Fixed in commit `ccdcb3d`; `4b4d0d1` fixed a follow-up where the
new `ErrRoleNotGrantable` rejection surfaced as HTTP 500 instead of 403 in
`createRoleAssignment` (the handler didn't map the sentinel, so it fell
through to `SetInternalError`)
**Severity**: High — Data Access Administrator exists specifically to
delegate role management *without* also granting data-plane access or the
ability to escalate to it; without this restriction a holder could grant
themselves Purge Operator/Certificate User or grant another principal a
second Data Access Administrator, defeating the role's entire purpose
**File**: `internal/services/authorization/role_assignment_service.go`,
`api/role_assignments.go`, `cmd/vault-access/grant.go`

**Root cause**: `RoleAssignmentService.AssignRole` applied the same
authorization check regardless of *which* role was being granted or by whom
— any caller who passed `CanManageRoleAssignments` (global admin, or Data
Access Administrator in that vault) could grant any role, including
`Key Vault Data Access Administrator`, `Key Vault Purge Operator`, and
`Key Vault Certificate User`. Azure's real ABAC restricts Data Access
Administrator from granting those three roles; RocketVault had no equivalent
restriction.

**What was fixed**: `AssignRoleInput` gained `CallerIsGlobalAdmin bool`, set
by both call sites (`api/role_assignments.go`'s `createRoleAssignment`,
`cmd/vault-access/grant.go`) from the same `common.HasRequiredRole(role,
string(model.RoleAdmin))` check `CanManageRoleAssignments` already performs.
`AssignRole` now rejects granting any role outside the
`nonAdminGrantableRoles` allow-list — which deliberately excludes
`RoleKeyVaultDataAccessAdministrator`, `RoleKeyVaultPurgeOperator`, and
`RoleKeyVaultCertificateUser` — with the new sentinel `ErrRoleNotGrantable`,
unless `CallerIsGlobalAdmin` is true. Five new tests in
`internal/services/authorization/role_assignment_service_test.go` pin both
the restriction and the global-admin bypass.

**Known residual gap**: the restriction is enforced by `AssignRole` only —
`RevokeAssignment` has no equivalent `CallerIsGlobalAdmin`-style check, so a
non-global-admin Data Access Administrator can *revoke* a Purge
Operator/Certificate User/Data Access Administrator assignment even though
they cannot *grant* one. Tracked separately as B21 below; deliberately
deferred, not an oversight (see the comment on `nonAdminGrantableRoles`).

**Spec/plan**: `docs/plans/2026-08-18-azure-keyvault-parity-audit.md` (Access
control finding F1), `docs/superpowers/plans/2026-08-18-security-short-term-fixes.md`
(Task 6).

---

### B20 — Per-item purge protection was dead code for secrets, keys, and certificates

**Status**: Fixed in commits `1e24095` (secrets), `986fc07` (keys), `d9a6136`
(certificates), plus three follow-ups from the same-day final review:
`16c1fa8` (the retry layer wrapped inner errors with `%v`, severing the
`errors.Is` chain, so a purge blocked by `ErrSecretPurgeProtected` surfaced
as HTTP 500 instead of 403 whenever `retry.database.enabled` — the default
— was true; changed to `%w`, and the vault-protection read now fails closed,
i.e. blocks the purge, if the read itself errors), and `68a52d8` (restoring a
secret/key/certificate via `Restore*` dropped its `purge_protection` flag —
repository `Create` doesn't write that column — so a backup taken while
protected restored unprotected; each `Restore*` now re-applies the decoded
entity's flag via `SetPurgeProtection` after create; also reworded the three
sentinel messages and hand-copied HTTP 403 literals in
`api/errors_{secret,key,certificate}.go`, which read as item-only despite
covering both item- and vault-level blocks).
**Severity**: High — an operator who enabled purge protection, expecting
Azure's guarantee that no contained object can be purged early, got no actual
protection for any secret, key, or certificate; a false sense of security for
exactly the compliance/data-loss-prevention scenario purge protection exists
for
**File**: `internal/repositories/{secret,key,certificate}_repository.go`,
`internal/services/{secrets,keys,certificates}/*_service.go`,
`model/{secret,key,certificate}.go`,
`api/{secrets,keys,certificates}.go`, `api/errors_{secret,key,certificate}.go`,
`cmd/{secrets,keys,certificates}/{create,update}.go`,
`internal/container/service_container.go`

**Root cause**: The `purge_protection` DB column, each repository's
`SetPurgeProtection` method, and the enforcement check inside
`PurgeSecret`/`PurgeKey`/`PurgeCertificate` all existed, but no API field,
service method, or CLI flag ever set the flag to `true` — it was unreachable
plumbing. Even where enforcement existed, only the background auto-purge
scheduler honored it; the manual `DELETE .../purge` path never checked it for
keys/certificates, and secrets didn't have the check wired for manual purge
at all. Vault-level purge protection also did not cascade to protect
contained items, only the vault itself.
`.claude/azure-keyvault-parity.md:177` stated "✅ (per-key + per-vault)",
which was true for per-vault but false for per-key.

**What was fixed**: For each resource type — `PurgeProtection *bool` added
to the service-layer create/update DTOs and the HTTP DTOs
(`purge_protection` JSON field, `nil` = no explicit value, matching the
existing `Enabled *bool` convention); a `--purge-protection` CLI flag on
`create`/`update`, gated by `cmd.Flags().Changed(...)`; each repository's
`Purge*` protection check now returns a shared sentinel
(`repositories.ErrSecretPurgeProtected`/`ErrKeyPurgeProtected`/
`ErrCertPurgeProtected`, `internal/repositories/purge_protection_errors.go`)
instead of a bare error, mapped to HTTP 403 in each `api/errors_*.go`; and
each service's `Purge*` method gained a vault-level cascade check via an
optional `VaultRepository` — if the containing vault has `PurgeProtection`
enabled, the purge is refused even if the item itself doesn't have the flag
set. New tests per resource type cover both the create/update wiring and the
vault-level cascade block.

**Spec/plan**: `docs/plans/2026-08-18-azure-keyvault-parity-audit.md`
(Critical Finding #2), `docs/superpowers/plans/2026-08-18-security-short-term-fixes.md`
(Tasks 7–9).

---

### B21 — `RevokeAssignment` does not enforce the Data Access Administrator grant restriction

**Status**: Fixed in commit `662781e`
**Severity**: Medium — narrower than B19: exploiting it requires the caller
to already hold Data Access Administrator in the vault (itself a
sensitive, deliberately-restricted grant), and the effect is revoking an
assignment rather than escalating privilege via a new grant
**File**: `internal/services/authorization/role_assignment_service.go`,
`api/role_assignments.go`, `cmd/vault-access/revoke.go`

**Root cause**: B19's fix restricted which roles `AssignRole` will grant for
a non-global-admin caller via `nonAdminGrantableRoles` and
`AssignRoleInput.CallerIsGlobalAdmin`. `RevokeAssignment`'s signature carried
no equivalent caller-authority flag, so it did not consult that allow-list.
A non-global-admin Data Access Administrator could grant only the allow-listed
roles, but could revoke *any* role assignment in their vault — including
another principal's `Key Vault Data Access Administrator`, `Key Vault Purge
Operator`, or `Key Vault Certificate User` grant.

**What was fixed**: `RevokeAssignment` gained a `callerIsGlobalAdmin bool`
parameter, mirroring `AssignRoleInput.CallerIsGlobalAdmin`, and now applies
the same `nonAdminGrantableRoles` allow-list to the assignment being revoked
— same shape as the `AssignRole` check, applied to the role being revoked
rather than the role being granted. Both call sites compute the flag the
same way `AssignRole`'s callers already do
(`common.HasRequiredRole(role, string(model.RoleAdmin))`):
`api/role_assignments.go`'s `deleteRoleAssignment` (which now also maps
`ErrRoleNotGrantable` to HTTP 403, mirroring the grant path) and
`cmd/vault-access/revoke.go` (which previously didn't even fetch the
caller's account role). Six `RoleAssignmentService` test doubles across the
authorization/middleware/api/cmd test suites were updated to the new 4-arg
signature. New tests: `TestRevokeAssignment_NonAdminCannotRevoke{DataAccessAdministrator,PurgeOperator,CertificateUser}`,
`TestRevokeAssignment_NonAdminCanRevokeOrdinaryRole`,
`TestRevokeAssignment_GlobalAdminCanRevokeAnyRole`
(`internal/services/authorization`), `TestRoleAssignments_RevokeDeniedRoleNotGrantable_Returns403`
(`api/role_assignments_test.go`), and `TestVaultAccessRevoke_PassesNonAdminCallerFlag`
(`cmd/vault-access/authz_test.go`).

**Spec/plan**: `docs/plans/2026-08-18-azure-keyvault-parity-audit.md` (Access
control finding F1 — this residual is called out under B19 above, not a
separate audit finding), `internal/services/authorization/role_assignment_service.go`'s
own comment on `nonAdminGrantableRoles`.

---

### B22 — `PurgeVault`'s bulk cascade-delete ignores per-item purge protection

**Status**: Fixed in commit `74dfab8`
**Severity**: High — before B20, this gap was inert because `purge_protection`
could never be set to `true` on any secret/key/certificate; B20 made the flag
real and settable, which made this a live, reachable bypass: purging a vault
silently destroyed every contained item regardless of its individual
purge-protection flag, the exact guarantee B20 just added for the
single-item purge path
**File**: `internal/repositories/secret_repository.go`'s `PurgeVaultContents`
(and the equivalent `key_repository.go`/`certificate_repository.go` methods),
`internal/services/vaults/cascade_adapter.go`, `internal/services/vaults/vault_service.go`,
`api/vault.go`

**Root cause**: `VaultService.PurgeVault` cascades to
`cascadeAdapter.PurgeVaultContents`, which calls each resource repository's
`PurgeVaultContents(ctx, vaultID)`. Those methods run an unconditional
`DELETE FROM secrets/keys/certificates WHERE vault_id = ?` with no
`purge_protection` check at all — by design, per the method's own comment,
to avoid stranding orphaned rows once the containing vault is gone. That
design predates B20; it was never revisited once per-item purge protection
became settable.

**What was fixed**: Took fix-sketch option (a) — `PurgeVault` now refuses to
purge a vault that still contains any item with `purge_protection = true`,
mirroring Azure's "cannot purge while it still contains protected items"
semantics; the caller must purge or wait out those items individually
first. Added `CascadeRepository.HasProtectedContent(ctx, vaultID) (bool,
error)`, backed by a `HasProtectedContent` method on each of
`SecretRepository`/`KeyRepository`/`CertificateRepository` — following the
existing `PurgeVaultContents` convention, added only to the concrete types,
not their exported `*RepositoryInterface`, to avoid rippling to every mock
across the codebase. `PurgeVault` calls it after the vault's own
`PurgeProtection` check and before `s.repo.Purge`, and **fails closed**: if
the check itself errors, the purge is refused rather than risking a bypass
because an item's status couldn't be read (same posture as B20's
`16c1fa8` follow-up). The new sentinel `ErrVaultContentsPurgeProtected` is
mapped to HTTP 400 in `api/vault.go` alongside the existing
`ErrVaultPurgeProtected`/`ErrDefaultVaultProtected` cases. New tests:
`TestSecretRepository_HasProtectedContent`/`TestKeyRepository_HasProtectedContent`/
`TestCertificateRepository_HasProtectedContent`,
`TestPurgeVault_RefusesWhenContentsProtected`/
`TestPurgeVault_ContentsProtectionCheckError_FailsClosed`
(`internal/services/vaults`), and `TestPurgeVault_RefusesWhenContentsProtected`
(`api/vault_test.go`).

**Spec/plan**: `docs/plans/2026-08-18-azure-keyvault-parity-audit.md`
(Critical Finding #2 row and "Remediation Update — Short-term Fixes
(2026-08-18)" section).

---

### B23 — Upgrading an existing database with a pre-`vault_id` `key_rotation_policies`/`rotation_policies` table crashed on startup

**Status**: Fixed in commit `f1d3d41`
**Severity**: High — any real, already-deployed database created before commit
`57bfa2b` (2026-08-17) could never start again after upgrading past it, and
the resulting failure mode was a nil-pointer panic on the first DB query of
any command (e.g. `users login`), not a clean error
**File**: `internal/db/db.go` (`createOptimizedSchema`), `cmd/root.go`
(`persistentPreRun`)

**Root cause (two independent bugs compounding)**:
1. Commit `57bfa2b` ("feat(db): add vault_id to rotation_policies and
   key_rotation_policies") added `vault_id` to both tables in two places:
   correctly in `migrateSchema` (`ALTER TABLE ... ADD COLUMN`, then
   `CREATE INDEX` *after* the ALTER — idempotent, safe on upgrade), and also
   in `createOptimizedSchema`, the fresh-install schema that runs *before*
   `migrateSchema` inside `SetupSchema`. There, `CREATE TABLE IF NOT EXISTS`
   is a safe no-op against a pre-existing old-shaped table, but the
   `CREATE INDEX ... (vault_id)` immediately following it in the same batch
   is not a no-op — it fails with `no such column: vault_id` against exactly
   that table shape. Since `createOptimizedSchema` runs first and its error
   aborts `SetupSchema`, `migrateSchema`'s correct fix for this never got a
   chance to run. This is the identical failure class already identified and
   avoided for `audit_logs`'s enriched-column indexes (see the comment at the
   end of `createOptimizedSchema`'s SQL block) — just not applied
   consistently to `key_rotation_policies`/`rotation_policies` when they got
   the same treatment. The regression test added in the same commit
   (`rotation_vault_scope_migration_test.go`) tested `migrateSchema` in
   isolation and `SetupSchema` only against a *fresh* database — never the
   real call path (`SetupSchema`) against an *old-shaped* one, so it couldn't
   catch this.
2. `cmd/root.go`'s `persistentPreRun` discarded `InitializeDB()`'s error
   (`//nolint:errcheck,gosec`). With the DB-init error above, execution
   continued with `database.GetDB()` returning `nil`, which
   `container.NewServiceContainer` threaded into every repository as a nil
   `*db.Conn` (its nil-guard was written assuming this only happens on the
   unit-test path). Any command reached deep into a DB call before crashing
   with a nil-pointer `SIGSEGV`, not a clean error — e.g. `users login`
   authenticates, logs "Starting user authentication," then panics inside
   `UserRepository.ReadByUsername`.

**What was fixed**:
1. Removed the two unsafe `CREATE INDEX ... (vault_id)` statements from
   `createOptimizedSchema` for `key_rotation_policies` and
   `rotation_policies` — both indexes are already correctly created in
   `migrateSchema`, after the ALTER TABLE, for both fresh and upgraded
   databases. New test `TestSetupSchema_UpgradesOldShapeRotationPolicies-
   WithoutError` (`internal/db/rotation_vault_scope_migration_test.go`)
   exercises the real `SetupSchema` call path against an old-shaped database
   and pins that this can't regress; confirmed it fails with the exact
   reported error (`no such column: vault_id`) against the pre-fix code.
2. `persistentPreRun` now checks `InitializeDB()`'s error and aborts with
   `fmt.Errorf("database initialization failed: %w", err)` for any command
   that isn't in the `context`/cobra-builtin exemption already used by the
   adjacent remote-target guard (those are documented no-DB/local-only paths
   and must keep working with no database configured at all, e.g.
   `rocketvault context list` before `.rocketvault.yaml` exists). New test
   `TestPersistentPreRun_DatabaseInitFailure_NonExemptCommand_ReturnsClean-
   Error` (`cmd/root_test.go`) pins that a DB-needing command now fails
   cleanly instead of reaching a later nil-pointer panic.

**Effect for existing (real, not test) databases**: with fix 1 alone, a
database in the pre-`vault_id` shape now upgrades in place on next startup —
no data loss, no manual intervention. Fix 2 is defense in depth so any
*future* DB-init failure (a different stale-schema case, a permissions
issue, a full disk) surfaces as a clean error instead of the same class of
panic.

**Reported by**: a real user hitting this on `users login` against an
existing local database, not discovered via review — see conversation
history for the original panic output.

---

### B24 — `POST /keys` rejected the P-256K curve despite full support elsewhere

**Status**: Fixed
**Severity**: Medium — a real, working capability was unreachable through the
only HTTP-facing way to create keys; the CLI and service layer already
supported it, so this was a REST-API-specific regression, not a missing
feature
**File**: `internal/validation/key_validation.go`

**Root cause**: `ValidateKeyCreate`'s curve field used
`validation.In("P-256", "P-384", "P-521")` — an allowlist that predated
P-256K support and was never updated when it was added elsewhere.
`api/keys.go`'s `createKey` handler calls this validator (line 282) *before*
its own, already-correct four-curve check at line 358
(`req.Curve != "P-256" && ... && req.Curve != "P-256K"`), so the validator's
`400 Curve: must be a valid value.` fired first and the handler's own check
never got a chance to run. `KeyService.CreateECDSAKey` (the service layer)
also independently allowed P-256K, and the CLI (`rocketvault keys create
--curve P-256K`) worked because it calls `KeyService` directly and never
goes through this HTTP validator at all — so the bug was specific to the
`POST /keys` REST path. Found during the 2026-08-19 Azure parity audit
against `.claude/azure-keyvault-parity.md` §3, while re-verifying EC curve
support against the actual API surface rather than the service layer alone.

**What was fixed**: Added `"P-256K"` to the `validation.In(...)` allowlist in
`key_validation.go` (one line), plus its doc comment. Added a regression test
at the API layer (`TestCreateKey_ECDSA_P256K_Success_Returns201`,
`api/keys_crud_test.go`) asserting `POST /keys` with `curve: "P-256K"`
returns 201 — a unit test on the validator alone would not have caught the
original bug, since it's an interaction between two independent checks in
two different files. Added a unit case to `TestValidateKeyCreate`
(`internal/validation/validation_test.go`) for direct coverage of the
allowlist itself. Also updated the CLI's `--curve` flag help text
(`cmd/keys/create.go`), which listed only three curves despite the fourth
already working.

**Scope check performed, no other call site affected**: `ValidateKeyCreate`
has exactly one caller (`api/keys.go:282`). `ValidateKeyUpdate` has no
`Curve` field — key updates never change curve, so the update path was never
affected. Key rotation reuses the existing key's stored curve
(`KeyService.RotateKey`), not user input, so it was never affected either.

---

### B25 — `POST /keys` with `curve: "P-256K"` leaked an uncaught 500 on HSM-enabled instances

**Status**: Fixed
**Severity**: Medium — an information-disclosure-adjacent error-handling gap
(a raw internal error string reached the client) rather than a capability
gap; HSM-backed P-256K key creation was never actually supported and still
isn't — only the failure mode was wrong
**File**: `api/keys.go`, `api/errors_key.go`

**Root cause**: A direct follow-up to B24. Once `ValidateKeyCreate` allowed
`P-256K` through (B24's fix), `POST /keys {"curve":"P-256K"}` on an
HSM-enabled instance (`hsm.enabled: true`, this repo's own configured
default) reached `KeyService.CreateECDSAKey` → `PKCS11KeyProvider
.GenerateECDSAKey`, which correctly returns `crypto.ErrUnsupportedCurve`
(`internal/crypto/pkcs11_provider.go`'s `ecOID` map has no P-256K entry — no
PKCS#11 mechanism exists for it). But `createKey`'s error switch
(`api/keys.go`) only special-cased `crypto.ErrOctKeysRequireHSM` into a
clean 400 — every other error, including this one, fell through to
`c.SetInternalError(err)`, an uncaught HTTP 500 with the raw Go error text
(`"failed to generate ECDSA key: curve not supported by PKCS#11 provider:
P-256K"`) in the response body. The same `GenerateECDSAKey` call exists in
`KeyService.RotateKey` for `ES256K` keys, reached via the shared
`writeKeyError` helper (`api/errors_key.go`), which had the identical gap —
currently unreachable in practice (an HSM instance can never create the
P-256K key it would need to rotate), but the shared helper needed the same
fix for correctness. Found via live end-to-end verification while following
up on B24 against `.claude/azure-keyvault-parity.md` §3 — a unit test on the
validator alone (B24's fix) would not have caught this, since it's a
downstream error-mapping gap in a completely different file.

**What was fixed**: Added a case for `crypto.ErrUnsupportedCurve` to both
`createKey`'s error switch (`api/keys.go`) and the shared `writeKeyError`
(`api/errors_key.go`), mapping it to a clean 400 with the message `curve: `
plus the underlying error text — mirroring the existing
`crypto.ErrOctKeysRequireHSM` precedent exactly. Added two regression tests:
`TestCreateKey_ECDSA_P256K_NoHSMMechanism_Returns400` and
`TestRotateKey_P256K_NoHSMMechanism_Returns400` (`api/keys_crud_test.go`),
both reproducing the exact error value and wrapping the real service layer
produces. HSM-backed P-256K key creation itself remains unsupported by
design (no PKCS#11 mechanism exists) — this fix corrects only the failure
mode, not the underlying capability gap.

**Scope check performed**: grepped every `GenerateECDSAKey` call site (two:
`CreateECDSAKey` and `RotateKey`, both in `KeyService`) and every consumer of
their errors (`createKey`'s inline switch and `writeKeyError`, respectively)
— both are now covered. `crypto.ErrUnsupportedAlgorithm`, a sibling PKCS#11
sentinel for algorithm (not curve) mismatches, was checked separately and
found to already be properly wrapped into a service-level
`keyservices.ErrUnsupportedAlgorithm` and mapped to 400 in six handlers — no
gap there.

---

### B26 — Rotating a key permanently stranded every pre-rotation ciphertext and signature

**Status**: Fixed
**Severity**: High — silent, permanent data loss: any secret encrypted, any
signature produced, or any key wrapped before a rotation became
undecryptable/unverifiable/unwrappable forever, with no error at rotation
time to warn the caller
**Files**: `internal/repositories/key_repository.go`,
`internal/services/keys/crypto_service.go`, `internal/services/keys/key_service.go`,
`api/keys.go`, `api/errors_key.go`, `internal/backup/item_backup.go`, `model/key.go`

**Root cause**: `KeyService.RotateKey` (`internal/services/keys/key_service.go`)
always archived the pre-rotation key material into `key_versions.value` before
overwriting `keys.value` with the newly generated material — the write path
was correct and had been since `key_versions` was introduced. But nothing on
the read side ever used it: `model.KeyVersion` had no `Value` field,
`KeyRepository.ListVersions` deliberately selected only `version, created_at`
("Raw key material (value) is not returned" per its own doc comment), and none
of the six crypto operations — `Sign`/`Verify`/`Encrypt`/`Decrypt`/`WrapKey`/
`UnwrapKey` in `internal/services/keys/crypto_service.go` — had any way to
request a version; every one of them always resolved to `key.Value`, the
*current* row, unconditionally. The archived material was sitting in the
database, correctly encrypted, and permanently unreachable. Practical impact:
rotate a key once, and every ciphertext, wrapped key, or signature produced
before that rotation could never be decrypted, unwrapped, or verified again —
a real, silent data-loss bug with no error raised at rotation time to warn
the caller it was about to happen. Found via `.claude/azure-keyvault-parity.md`
§2 gap analysis against Azure Key Vault, which keeps every key version
independently addressable and usable indefinitely.

**Bundled bug found during design, fixed in the same pass**:
`resolveKeyMaterial` (`internal/services/keys/crypto_service.go`) cached
decrypted PEM material keyed on `(key.ID, 0)` — the version component of the
cache key was hardcoded to `0`, not derived from the material actually being
resolved, even though `internal/keycache`'s `Get`/`Set` already took a real
`version int` parameter that nothing ever populated correctly. Harmless
before this fix, since only one version (the current one) was ever resolved
per key. Had the version-addressing fix below shipped without also fixing
this, a second version's material would have been served from the first
version's stale cache entry (or vice versa) on any two-versions-in-a-row
lookup — a silent wrong-plaintext / wrong-signature bug, worse than the
original gap because it would fail without even raising a not-found error.

**What was fixed** (plan:
`docs/superpowers/plans/2026-08-19-key-version-addressability.md`, design:
`docs/superpowers/specs/2026-08-19-key-version-addressability-design.md`,
commits `78ad152..f03957a`):
- `KeyRepository` gained `ReadVersionValue`/`GetVersion`/`ListVersionRecords`
  to read archived `key_versions` rows (material and metadata), authorized
  against the key's owner, matching the existing `ListVersions` idiom exactly.
  A new `model.KeyVersionRecord` internal-only type carries material for
  backup use; the existing HTTP-facing `model.KeyVersion` still never gains a
  `Value` field, so API responses can't leak material even by future mistake.
- All six crypto service request/result types
  (`SignRequest`/`VerifyRequest`/`EncryptRequest`/`DecryptRequest`/
  `WrapKeyRequest`/`UnwrapKeyRequest` and their `*Result` counterparts) gained
  an optional `Version int` — `0`/omitted resolves to the current version,
  unchanged from prior behavior; any other value resolves via the new
  repository methods. Same addition on the six HTTP request/response types in
  `api/keys.go`, as a `"version"` JSON field (`omitempty` on the request,
  always present on the response so a caller who omitted it can discover what
  "current" resolved to).
- `resolveKeyMaterial`'s cache key changed from the hardcoded `(key.ID, 0)` to
  `(key.ID, resolvedVersion)` — the fix for the bundled cache bug above.
- New `GET /keys/{key_id}/versions/{version}` route (flat + vault-scoped),
  backed by a new `KeyService.GetKeyVersion`, mirroring the existing
  `ListKeyVersions` authorization shape — closes the read-side asymmetry
  against secrets, which already had `GET /secrets/{id}/versions/{version}`.
  `repositories.ErrKeyVersionNotFound` (new sentinel) maps to a clean 404 in
  both the six crypto handlers' inline error switches and the shared
  `writeKeyError` helper.
- `internal/backup/item_backup.go`'s shared `backupEnvelope` gained an
  additive `Versions []model.KeyVersionRecord` field (`omitempty`), populated
  by `BackupKey` via `ListVersionRecords` and replayed by `RestoreKey` via
  `CreateVersion` under the restored key's new ID. Purely additive to the
  envelope — a pre-fix backup blob (no `versions` field) still decodes and
  restores exactly as before, just without version history, so this is
  backward compatible with every backup taken before this fix. Without this
  half of the fix, a rotated key's version history would have silently been
  lost on any backup/restore cycle, reintroducing the exact bug this fix
  closes via a different path than rotation.
- OCT (symmetric, HSM-only) keys are unaffected: `RotateKey` has no case for
  `model.KeyTypeOCT` and OCT keys cannot be rotated at all, so there is no
  multi-version OCT case to fix.

**Two follow-ups from the whole-branch review, fixed in the same body of
work**:
- `KeyService.ListKeyVersions` now synthesizes the implicit version-1 entry
  when `key_versions` is empty, so `GET /keys/{id}/versions` no longer reports
  an empty history for a never-rotated key whose version 1 both
  `GET /keys/{id}/versions/1` and every crypto operation happily resolve. The
  synthesized entry is timestamped by the key's own `CreatedAt`, matching
  `ReadVersionValue`/`GetVersion`'s existing fallback. `RotateKey` deliberately
  still calls the raw `KeyRepository.ListVersions`, since its version-numbering
  math needs the true zero-row count.
- New `KeyRepository.CurrentVersion` — a single `COALESCE(MAX(version), 1)`
  aggregate over `key_versions` — replaces the full `ListVersions` row scan
  that `cryptoService.currentVersionNumber` was running on *every* crypto
  operation just to compute one number.

  **Correction (2026-08-20)**: this paragraph used to describe the query as an
  aggregate over a `LEFT JOIN` from `keys`, and claimed that join direction was
  load-bearing — that "an INNER JOIN from `key_versions` returns zero rows for a
  never-rotated key rather than a row with a NULL aggregate, which would defeat
  the `COALESCE` fallback to 1." **That claim is false.** An aggregate with no
  `GROUP BY` always returns exactly one row even when nothing matches: `MAX`
  yields NULL, and `COALESCE` turns it into 1. Verified empirically against
  SQLite — the left-join, inner-join, and join-free forms all return 1 for a
  never-rotated key. F2 dropped the join entirely on that basis; the current
  query is join-free (`internal/repositories/key_repository.go:893-905`).

**Left open, tracked as a fast-follow, not a regression**: all four crypto CLI
commands — `rocketvault keys sign` (`cmd/keys/sign.go`), `keys verify`
(`cmd/keys/verify.go`), `keys wrap` (`cmd/keys/wrap.go`), and `keys unwrap`
(`cmd/keys/unwrap.go`) — still call their `CryptoService` method with
`Version` left unset (always current), and none exposes a `--version` flag.
REST is the only way to address an archived version today. (There are no
`keys encrypt`/`keys decrypt` CLI commands at all, so those four are the
complete set.) Flagged explicitly in the design's "Not in scope" section
rather than silently deferred. Also noted but not fixed, as pre-existing and
unrelated gaps in the purge path: `KeyRepository.PurgeKey` never destroys
PKCS#11 HSM token objects for the current or any archived version on purge;
and it deletes only the `keys` row, relying on `ON DELETE CASCADE` to remove
the matching `key_versions` rows — but this project runs SQLite with
`foreign_keys` left off (`internal/db/db.go` never issues
`PRAGMA foreign_keys = ON`), so on SQLite deployments a purged key leaves its
archived `key_versions` rows, encrypted material and all, orphaned in the
database. Both are candidates for their own future entries here if they need
to be addressed.

### B27 — Rotation policy's `expiry_days` lifetime action was stored but never acted on

**Status**: Partially fixed
**Severity**: Low — a documented, non-functioning policy field, not a
security or data-loss issue; an operator configuring `expiry_days` got no
error, just silent non-enforcement
**Files**: `internal/services/keys/key_service.go`,
`internal/services/keys/keys_edge_test.go`

**Root cause**: `UpsertKeyRotationPolicy` (`api/key_rotation_policy.go` →
`internal/services/keys/key_service.go`) persisted and echoed back both
`expiry_days` and `notify_before_expiry_days`, but `RotateKey` never read
either — `Key.ExpiresAt` was left exactly as it was before rotation, forever,
regardless of what a policy's `expiry_days` said. Azure's Notify lifetime
action has two halves: stamping an expiration on the rotated version, and
sending a near-expiry notification. Neither had any implementation behind it.
Found via `.claude/azure-keyvault-parity.md` §2's "Get/Set rotation policy" row.

**What was fixed** (commit `1161fa5`): `RotateKey` now looks up the key's
rotation policy via the already-injected `policyRepo` and, if the policy is
`Enabled` with `ExpiryDays > 0`, stamps `existing.ExpiresAt = now +
ExpiryDays` before the existing `KeyRepository.Update` call — no new
repository method needed, since `Update`'s SQL already writes `expires_at`
(`UpdateKey` already lets callers set it directly). Applies uniformly to
every rotation, scheduled or manual, since both paths go through the same
`RotateKey`. `policyRepo` is nil-guarded (most `keyService` test instances,
and any future minimally-constructed caller, don't set it — matches the
existing `vaultRepo` optional-dependency convention already used in
`PurgeKey`), and a key with no policy configured — the common case — rotates
exactly as before. A genuine repository error during the policy lookup (not
"no policy configured", which is `sql.ErrNoRows` and expected) fails the
whole rotation rather than silently skipping the stamp.

**Deliberately not fixed — a separate, larger effort**:
`notify_before_expiry_days` (the actual near-expiry *notification*) is
untouched. RocketVault has no notification delivery mechanism anywhere in the
codebase — `internal/services/secrets/scheduler_service.go`'s `sendReminder`
is a logging-only placeholder (its own comment: "In a real implementation,
this would send email/SMS notifications"), and
`internal/services/secrets/expiration_service.go`'s `ExpirationService` is
unwired, unreachable dead code (`NewExpirationService` is never called from
`internal/container/` or any `cmd/` bootstrap). Building real delivery (at
minimum a generic webhook) is RocketVault's own roadmap item — see
`.claude/roadmap-azure-parity-and-beyond.md`'s Phase 3 "native
webhook/notification system" entry — and was explicitly scoped out of the
original rotation-scheduler work for the same reason
(`docs/superpowers/specs/2026-08-18-rotation-policy-scheduler-design.md`
§11). Tracked as its own future design/plan, not a follow-up here.

**Also out of scope**: secrets. `model.RotationPolicy` (the secrets-side
policy) has no `expiry_days` field at all — only `ReminderDays`/`AutoRotate`,
an entirely separate, non-shared schema from keys' `KeyRotationPolicy`.
Adding secret-side expiry stamping would be a schema change and its own
decision, not implied by this fix.

**2026-08-20 update — storage/configuration layer shipped, B27 stays open**:
A per-vault webhook *storage and configuration* layer now exists on
`feat/vault-webhook-config` (`docs/superpowers/specs/2026-08-19-vault-webhook-config-design.md`):
table `vault_webhook_configs` (`internal/db/db.go`), `model.VaultWebhookConfig`
(`model/vault_webhook.go`), `internal/repositories/vault_webhook_repository.go`,
`internal/services/vaults/webhook_service.go`
(`VaultWebhookService`/`UpsertWebhookRequest`), the HTTP routes
`PUT`/`GET`/`DELETE /vaults/{name}/webhook` (`api/vault_webhook.go`,
`api/vault.go`), and a `rocketvault vault-webhook set|get|delete` CLI
(`cmd/vault-webhook/`). The signing secret is server-generated, encrypted at
rest, and returned in plaintext exactly once — on create or rotate via `set`
— never again afterwards (`GET`'s response schema has no `signing_secret`
field at all).

This is configuration only. **B27 remains open.** Nothing sends a
notification yet — this sub-project deliberately built no delivery mechanism
of any kind: no outbound HTTP call, no sender, no payload schema. The
paragraph above this one, stating RocketVault "has no notification delivery
mechanism anywhere in the codebase," is still accurate about *delivery* —
what changed is that a notification now has somewhere to be configured to go
*to*, not a way to get there. `notify_before_expiry_days` still has no
effect. The remaining work is split into its own sub-projects, not follow-up
tasks here: the delivery primitive (which will make the first real outbound
HTTP call and own the payload schema), keys' near-expiry sweep (reading
`notify_before_expiry_days` off `KeyRotationPolicy` and firing the delivery
primitive), secrets' `sendReminder` wiring (replacing the logging-only
placeholder in `internal/services/secrets/scheduler_service.go`),
certificates' expiry-warning wiring, and user-facing docs
(`docs/usage-guide.md`, deferred until the chain is usable end-to-end).

---

### B28 — Item backup gated on ownership, and unscoped underneath it

**Status**: Fixed 2026-08-19
**Severity**: High — the visible half refused every legitimately-authorized
non-owner, a real Azure parity gap; the hidden half meant the ownership check
was the *only* thing stopping a caller from backing up an item they owned in
a vault other than the one their request was authorized against
**Files**: `internal/backup/item_backup.go`, `api/backup_item.go`

**Root cause**: `ItemBackupService.BackupKey` read the target key via
`model.NewAdminScope(userID)` — a scope with no predicate at all — and then
separately compared `key.UserID == caller`, returning `ErrForbidden` (→ HTTP
403) for anyone else; the method's own comment said as much: "The read itself
is unchecked (admin scope); the explicit ownership check below is the actual
gate." Azure's Crypto User role grants `keys/backup/action` with no ownership
concept whatsoever, so this refused every non-owner who legitimately held
`ActionKeysBackup` — a real parity gap. `BackupSecret` and `BackupCertificate`
carried the identical gate. Before this fix none of the three methods even
took a `vaultID` parameter, so the ownership comparison was the *only* code
confirming the named item belonged to the caller at all — nothing tied the
read to the vault the caller's request was authorized against. A caller who
owned a key in vault A could back it up via a request authorized only for
vault B, since the admin-scoped read would find the key by ID regardless of
vault and the ownership check passed independently of which vault was in
play. Deleting the ownership check to close the parity gap — the obvious
fix — would, on its own, have left that cross-vault read open.

**What was fixed** (plan:
`docs/superpowers/plans/2026-08-19-item-backup-vault-scoped-authz.md`): all
three `Backup*` methods now take the request's authorized `vaultID`
(resolved by `vaultIDFromRequest`, the same rule the three `Restore*` methods
already followed per B15) and read with `model.NewVaultScope(vaultID,
userID)` instead of an admin-scoped read plus an ownership comparison — the
repository's scope predicate is now the sole enforcement point, and an
out-of-scope ID reports 404, matching every other scoped resource route.
`BackupKey` also switched `ListVersionRecords`'s second argument from the
caller's ID to `key.UserID` (the key it just read): that query joins
`k.user_id`, so passing the caller's ID was safe only while caller-equals-
owner was guaranteed, and once a non-owner can legitimately back up a key it
would have returned zero rows and silently dropped the key's rotation
history from the blob — reintroducing the exact loss B26 closed, through a
different path. `backup.ErrForbidden` and the three now-unreachable
`errors.Is(err, backup.ErrForbidden)` branches in the restore handlers
(`api/backup_item.go`) were also deleted; the three backup handlers had
already lost theirs in the same body of work, and no `Restore*` method had
ever produced the sentinel in the first place.
`TestBackupKeyNonOwnerInSameVaultSucceeds`, `TestBackupKeyReadsWithVaultScope`,
`TestBackupSecretNonOwnerInSameVaultSucceeds`, and
`TestBackupCertificateNonOwnerInSameVaultSucceeds`
(`internal/backup/backup_edge_test.go`, `internal/backup/item_backup_test.go`)
pin the fix.

**Superseded by**: F2 (below) — the `user_id` parameter itself was removed
from `ListVersionRecords` and its four sibling version methods on 2026-08-20.

---

### B29 — Secret backup silently discarded every archived version

**Status**: Fixed 2026-08-20
**Severity**: High — silent, permanent data loss: a secret with ten
historical versions backed up and restored as one, with no error and no
warning to the caller.
**Files**: `internal/backup/item_backup.go`, `model/secret.go`,
`internal/backup/item_backup_test.go`

**Root cause**: `ItemBackupService.BackupSecret` ended
`return encodeBlob("secret", id.String(), secret, nil)`. The `nil` was the
versions argument. `model.Secret` carries a `Version` *number*, which made
the blob look complete, but the historical values live in the separate
`secret_versions` table the blob never read.

**Why it survived**: the identical defect on the key path was found and
fixed on 2026-08-19 (§ B26), but that fix was scoped to keys; `BackupSecret`'s
`nil` was left in place and only became conspicuous once `BackupKey` was
explicit about carrying history. Nothing tested for the absence.

**What was fixed** (commits `34ffee1`, `284a60b`, `8327ab7`):
- `34ffee1` generalized the backup blob envelope from a keys-only
  `[]model.KeyVersionRecord` parameter to a `blobVersions{Key, Secret}`
  struct, adding a new additive `secret_versions` JSON field (`omitempty`)
  alongside the existing `versions` field.
- `284a60b` injected `SecretVersionRepositoryInterface` into
  `ItemBackupService`; `BackupSecret` now calls `GetVersions` and puts the
  result in the blob's `Secret` field. `model.SecretVersion` gained the same
  sensitivity-warning comment `model.KeyVersionRecord` already carried.
- `8327ab7` made `RestoreSecret` replay those versions under the new
  secret's ID: each row gets a fresh `uuid.New()` primary key
  (`secret_versions.id` is a PRIMARY KEY, and the source secret usually
  still exists, so reusing the blob's IDs would collide) and the restoring
  caller's `UserID` (`secret_versions.user_id` is a real FK to `users`,
  enforced on PostgreSQL, so carrying the blob's original owner could
  reference a user absent from the target deployment).

**Security note**: a secret backup blob now carries every historical secret
value, so it is exactly as sensitive as a key backup blob — the response
body is a merely base64url-encoded, not encrypted, JSON envelope.

**Back-compat**: the new field is `omitempty` and additive, so blobs taken
before this change decode with a nil slice and restore unchanged — pinned by
`TestRestoreSecret_OldFormatBlob_NoVersionsField`.

**Pinned by**: `TestBackupSecret_CarriesVersionHistory`,
`TestBackupRestoreSecret_CarriesVersionHistory`,
`TestRestoreSecret_OldFormatBlob_NoVersionsField`
(`internal/backup/item_backup_test.go`).

---

### B30 — A Key Vault Reader can dump every historical plaintext value of every secret in a vault

**Status**: Fixed 2026-08-20 (commit `764a75e`)
**Severity**: High — a role documented and tested as "metadata only" instead
grants full plaintext secret-value disclosure, for every archived version of
every secret in a vault the role is assigned in
**Files**: `internal/services/authorization/data_actions.go`,
`api/secrets.go`, `internal/services/secrets/versioning_service.go`,
`model/azure_roles.go`, `internal/services/authorization/authorization_matrix_test.go`,
`model/secret.go`

**Root cause**: `mapSecretAction` maps `GET /secrets/{id}/versions` to
`model.ActionSecretsReadMetadata` (`internal/services/authorization/data_actions.go:129-131`),
with the comment "Listing versions exposes metadata only." That premise is
false: `listSecretVersionsHandler` (`api/secrets.go:100-106`) calls
`secretService.GetSecretVersions` and JSON-encodes the result directly, and
`versioningService.GetVersions` (`internal/services/secrets/versioning_service.go:172-183`)
decrypts every version's value before returning it — the handler ships
plaintext, not metadata. `RoleKeyVaultReader` holds
`ActionSecretsReadMetadata` (`model/azure_roles.go:168-171`, i.e. the block
is one line later than initially estimated at 167-171), and
`authorization_matrix_test.go:123-124` asserts Reader is *supposed* to be
allowed `secrets.listVersions` — so this is the intended, tested
authorization outcome, not an oversight in the test.

**Net effect**: any principal holding only `Key Vault Reader` — the
least-privileged built-in role, granted no plaintext read of the current
secret value (`ActionSecretsGet` is absent from its list) — can call
`GET /secrets/{id}/versions` and receive the plaintext value of every
historical version of that secret. This is distinct from the 2026-08-14
retraction in this file's history: that one cleared `GET /secrets/{id}`
(`ActionSecretsGet`, which Reader does not hold) as safe; this is a
different route, gated by a different, Reader-held action.

**Why this branch surfaced it**: `model.SecretVersion`'s doc comment
(`model/secret.go:89-97`) was added by this branch and claims the same
sensitivity handling as `model.KeyVersionRecord`. But `KeyVersionRecord`'s
safety is structural, not a policy choice: `model.KeyVersion` (the type
actually returned by key version-list/version-get handlers) has no `Value`
field at all (`model/key.go:64-72`), so those handlers cannot leak key
material even by future mistake — only the internal-only
`KeyVersionRecord` carries `Value`, and it is never marshaled into an HTTP
response. Secrets have no equivalent split: `model.SecretVersion` is both
the backup-blob payload type *and* the type `listSecretVersionsHandler`
marshals into its response body, so there is no structural barrier — only
the data-action mapping — between "list versions" and "read every
historical plaintext value."

**Candidate fixes (not chosen; this entry is record-only)**:
1. Split the type the way keys do: introduce a metadata-only
   `SecretVersionMetadata` (no `Value`) for the versions-list API response,
   keeping `model.SecretVersion` (with `Value`) as the internal/backup-only
   type.
2. Re-map `GET /secrets/{id}/versions` to a data action Reader does not
   hold (e.g. `ActionSecretsGet`), accepting that this narrows what
   "metadata only" routes Reader retains.

Fixing this was out of scope for the secret-backup-version-history work that
surfaced it; it got its own design pass on 2026-08-20.

**What was fixed** (commit `764a75e`): candidate fix 1 above, chosen because
it matches Azure — a Reader may enumerate versions, and reads a value through
`GET /secrets/{id}/versions/{n}`, which requires `ActionSecretsGet`. Candidate
2 would have closed the leak by *diverging* from Azure and would have left the
response carrying plaintext, so the next mismapping would leak again.

New `model.SecretVersionMetadata` has no `Value` field, so a handler cannot
serialize one — the same structural guarantee `model.KeyVersion` already gives
key-version listing. `listSecretVersionsHandler` now calls a new
`GetSecretVersionsMetadata` path that **never calls `DecryptSecret`**: returning
a values-free type alone would still pull every historical plaintext into
process memory and would leave the guarantee resting on the caller's choice of
return type, which is exactly how this bug happened. Not obtaining the
plaintext is the guarantee.

**The authorization mapping was never wrong and is unchanged.** Only its
comment was — "Listing versions exposes metadata only" was a false statement
about the handler, not a mistaken action choice. `authorization_matrix_test.go`
still correctly asserts Reader may list versions.

**Scope check**: `GET /secrets` was audited for the same defect and is clean —
`listSecrets` (`api/secrets.go`) builds its response without values
deliberately, which makes the versions route an outlier rather than a pattern.
Keys are structurally safe already (`model.KeyVersion` has no `Value`, and its
"metadata only" mapping is truthful). Certificates have no versions at all.

**Bundled fix — see B31 below**, a distinct defect in the same code path found
while fixing this one.

---

### B31 — The `secrets version` CLI commands had no authorization check at all

**Status**: Fixed 2026-08-20 (commit `764a75e`, same commit as B30)
**Severity**: Medium — no authorization enforcement on a plaintext-returning
path, plus a scope that survives revocation. Narrower than B30 because the
owner scope limited results to secrets the caller created
**Files**: `cmd/version.go`

**Root cause**: none of `secrets version list`, `get`, or `latest` called
`vaultcli.RequireDataAction`, unlike every sibling command in `cmd/secrets/`.
The CLI bypasses `PolicyMiddleware` entirely, so — per CLAUDE.md's "CLI
Authorization" section — that check is the only enforcement point on the path,
and there was none. All three also used `model.NewOwnerScope(uuid.Nil, userID)`,
the pattern the B11 flat-route fix removed elsewhere, which **survives
revocation**: a user who created a secret in a vault could still read its full
version history after losing access to that vault. `list` additionally printed
a `VALUE` column, so it was B30's leak on a second surface.

**What was fixed**: `list` now requires `ActionSecretsReadMetadata` and prints
no `VALUE` column; `get` and `latest` require `ActionSecretsGet`, since they
legitimately return one value; all three resolve a vault scope. A `--vault`
flag was added to each, matching the other resource commands.

**Note on the test suite**: a test named
`TestVersionListCommand_ReturnsDecryptedVersions` had encoded the leak as a
requirement, asserting the plaintext appeared in the command's output. It was
inverted and renamed rather than deleted, so the file records that the old
behaviour was intended and is now forbidden. Every new guard in both B30 and
B31 was verified to fail before the fix.

---

### B32 — Certificate creation authorizes its signing key by ownership, not by vault

**Status**: Fixed 2026-08-20, same day it was found
**Severity**: Medium — breaks vault isolation, but only for a key the caller
already owns. It is not a path to using someone else's key
**Files**: `internal/services/certificates/certificate_service.go`

**What it is**: `ValidateKeyOwnership` (`:826-847`) reads the signing key with
`model.NewAdminScope(userID)` — an admin scope carries no vault predicate — and
then applies a single check, `key.UserID != userID`. Vault membership is never
consulted.

So a user who owns a key in vault A can create a certificate in vault B signed
by that key, with no role assignment relating the two vaults. The vault
boundary, which is the security boundary everywhere else in the system, does
not apply here. `ValidateCertificateAccess` (`:792-822`) has the identical
shape for the CA certificate on the CA-signed path.

This is the ownership-based authorization that P2 retired across the data
plane, surviving in a corner the `scope-gate` CI job does not cover: the job
bans `NewOwnerScope`, and this code reaches the same outcome using
`NewAdminScope` plus a hand-written owner comparison.

**Two things that make it easy to misread as safe**:

- Both functions open with `if role == model.RoleAdmin { return nil }`, which
  reads like a deliberate privilege tier. It is inert — all three call sites
  pass `""` (`:203`, `:334`, `:339`, `:719`), so the branch never fires.
- Three call sites carry a comment of the form "Ownership was already verified
  by ValidateKeyOwnership above, so an admin scope is safe here" (`:208`,
  `:345`, `:360`). The premise is true and the conclusion does not follow:
  ownership was verified, vault authorization was not, so the admin-scoped
  re-read that pulls the private key inherits the same gap.

**The fix**: both functions now take a `model.Scope` in place of
`userID`+`role`, and read through it, so the repository's vault predicate does
the work. The three admin-scoped re-reads that pulled the private key and CA
certificate afterwards were changed to the same scope — they had quietly
reintroduced the gap the validator had just closed — and the three comments
claiming an admin scope was "safe here" are gone with them.

The owner comparison was deliberately **kept**. Dropping it would match how the
rest of the data plane works, where a scoped read is the whole gate, but it
would also let any vault member sign with another member's key: strictly more
access than before. A security fix should not widen permissions on the way
past, so that remains a separate decision.

No request-type plumbing was needed after all. `CreateCertificateRequest`
already carried `VaultID`, and `RenewCertificate` already took a `model.Scope`
— an earlier estimate in this entry said otherwise and was wrong.

**Pinned by**: `TestValidateKeyOwnership_IsVaultScoped` and
`TestValidateCertificateAccess_IsVaultScoped`, each asserting both halves. The
same-vault half is the one that fails against the old code — a cross-vault
assertion on its own would pass either way, since the old code also errors,
just for the wrong reason. Both were verified failing before the fix landed.

**Note on the test suite**: four tests encoded the defect as a requirement.
`TestValidateCertificateAccess_AdminBypassesCheck` and
`TestValidateKeyOwnership_AdminBypasses` asserted that the dead admin branch
short-circuited the repository read, and nineteen `.On("Read", …,
model.NewAdminScope(userID))` expectations pinned the unscoped read. The admin
tests were replaced by `TestValidateCertificateAccess_HasNoAdminBypass`, which
asserts the opposite, and the expectations now use a `certVaultScope` matcher
that an admin scope fails.

**Not reachable by the case that prompted the audit**: `user14` owns no keys.

---

### B33 — CLI and HTTP disagree on the policy operation for key sign and verify

**Status**: Fixed 2026-08-20, same day it was found
**Severity**: Low — affects only explicit-deny access policies, not the
deny-by-default role check. No effect on deployments that write no deny rules
**Files**: `internal/middleware/middleware.go`, `cmd/keys/sign.go`,
`cmd/keys/verify.go`

**What it is**: `resolvePolicy` (`:407-430`) special-cases the `/purge`,
`/restore`, `/rotate`, `/import` and `/renew` suffixes, then falls through to
the plain HTTP method. `/sign` and `/verify` have no case, so both resolve to
`OpCreate` on their `POST`. The CLI passes `model.OpSign` (`cmd/keys/sign.go:95`)
and `model.OpVerify` (`cmd/keys/verify.go:107`).

Stage 1 of the check — the explicit-deny `access_policies` override — matches
on `(principalID, resourceType, operation, vaultID)`. A deny rule written
against `(keys, sign)` therefore fires on the CLI and does not fire over HTTP,
where the request is looking for `(keys, create)`. The API is the way around a
deny rule that the CLI honours.

Stage 2, the deny-by-default role-assignment check, keys off the data action
(`ActionKeysSign`/`ActionKeysVerify`) and is unaffected — a principal with no
qualifying role assignment is still denied on both paths. That is what keeps
this Low rather than a bypass.

`wrap` and `unwrap` are consistent: their CLI commands pass `OpCreate`
(`cmd/keys/wrap.go:90`, `cmd/keys/unwrap.go:90`), matching what HTTP resolves.

**The fix**: `/sign` and `/verify` suffix cases were added to `resolvePolicy`,
so HTTP now produces `OpSign`/`OpVerify` and matches the CLI. Changing the CLI
to send `OpCreate` would also have made the two agree, but it would leave a
deny rule unable to name the operation it wants to deny.

**Pinned by**: `TestResolvePolicy_SignAndVerifyResolveToTheirOwnOperations`,
which covers both the flat and vault-scoped route shapes and also asserts that
`wrap`, `unwrap` and `rotate` are unchanged — the new cases must not widen.

---

### B34 — JWK public components silently empty on every key response

**Status**: Fixed 2026-08-20
**Severity**: Low — a missing response field, not a security or data defect.
Nothing was exposed that should not have been; an advertised capability simply
never worked
**Files**: `api/keys.go`, `internal/services/keys/key_service.go`, `model/key.go`

**Symptom**: `GET /keys/{id}`, `POST /keys`, `PUT /keys/{id}` and
`POST /keys/{id}/rotate` all declared `n`/`e`/`x`/`y` on `api.KeyResponse` and
never populated them for any software-backed key. All four carry `omitempty`,
so the fields simply vanished from the JSON and no client could tell "this key
has no public material" — the genuine HSM result — from "extraction failed".

**Root cause**: `buildKeyResponse` called
`crypto.ExtractPublicComponents(key.Value, key.Type)`. `key.Value` is the value
as *stored*, and every software key is stored master-key-encrypted
(`CreateKey` runs `common.EncryptSecret` before `keyRepo.Create`).
`ExtractPublicComponents` opens with `pem.Decode`, which returns a nil block
for base64 ciphertext, so the function returned four empty strings and
`failed to decode PEM block`. **That error was assigned to `_`.**

**Why it survived review**: the discarded error made the failure
indistinguishable from the legitimate HSM path, which also returns four empty
strings — but with a nil error. No test asserted a non-empty `n` at the handler
level, and `internal/crypto/key_crypto_test.go` only exercised
`ExtractPublicComponents` with plaintext PEM, where it works correctly. The
unit under test was fine; the caller was passing it the wrong bytes.

**Fix**: extraction moved to `KeyService.GetPublicJWK`, which decrypts with
`common.DecryptSecret` before parsing and propagates both failures.
`buildKeyResponse` now *receives* the components instead of deriving them, so a
handler cannot reintroduce the bug by passing the wrong value — the encrypted
material is no longer in reach at that layer. The same method resolves an
archived version's material through `KeyRepository.ReadVersionValue`, which is
what let `GET /keys/{id}/versions/{version}` gain a real public JWK, matching
Azure's `GET /keys/{name}/{version}`.

Deliberate choices worth keeping:

- **A JWK failure does not fail the request.** `keyJWK` (`api/keys.go`) logs and
  omits the components. The primary content of the response is already in hand,
  and a key created moments ago should not 500 because its public components
  could not be derived.
- **`listKeys` passes `nil`.** Fetching a JWK per row would be an N-way decrypt
  on a list endpoint, and Azure's own list response carries identifiers and
  attributes only.
- **HSM keys return an empty JWK with a nil error**, never a 500 — the material
  never left the token, which is a normal answer rather than a failure.
- **`model.KeyVersion` is unchanged.** The version route returns a new
  `api.KeyVersionResponse` that embeds it and adds the four public fields, so
  that type's no-material guarantee still holds.

**Pinned by**: `TestGetPublicJWK_*` (`internal/services/keys/key_jwk_test.go`)
at the service layer and `TestGetKey_EmitsPublicJWKComponents`,
`TestGetKey_JWKFailureDoesNotFailTheRequest`,
`TestGetKeyVersion_EmitsThatVersionsJWK` (`api/keys_jwk_test.go`) at the
handler. The handler tests matter independently: the service tests would pass
against a handler that still extracted from the encrypted value itself, which
is exactly the bug. Verified by reinstating the original
`ExtractPublicComponents(key.Value, …)` call and watching
`TestGetKey_EmitsPublicJWKComponents` fail.

**Note on the plan**: this was planned on 2026-08-19 as bug `B28`, which was
taken by the item-backup entry before the plan ran. Renumbered to B34 on
execution.

---

### B35 — `secrets rotation rotate` writes a corrupted value that never decrypts again

**Status**: Fixed 2026-08-21, commits `1dcf07f..1043a4c`
**Severity**: Resolved — was Critical (re-rated from High during design:
`schedulerService.performAutomaticRotation` delegated to the same function, so
every policy with `AutoRotate: true` destroyed its secrets unattended)
**Files**: `internal/services/secrets/rotation_service.go`,
`internal/services/secrets/scheduler_service.go`, `cmd/rotation.go`

**Symptom**: after `rocketvault secrets rotation rotate`, a subsequent
`secrets get` on that secret cannot decrypt it. The rotation itself reports
success.

**Root cause**: `PerformManualRotation` does

```go
newValue := s.generateNewSecretValue(secret.Value)
secret.Value = newValue
err = s.secretRepo.Update(ctx, secret, model.NewOwnerScope(...))
```

with no encryption step. `generateNewSecretValue` is a placeholder returning
`fmt.Sprintf("%s_rotated_%d", currentValue, time.Now().Unix())`. Per the
repository contract, `secret.Value` as loaded is the *master-key ciphertext*,
so the suffix is appended to ciphertext and stored. `common.DecryptSecret` can
never recover it.

`cryptoSvc CryptographyService` is injected into `rotationService` and never
used — it appears exactly three times in the file: field declaration (l.100),
constructor parameter (l.115), assignment (l.126). The dependency needed to fix
this is already wired in and simply not called.

**Also**: the manual path never archives the prior value. Only the scheduler's
`performAutomaticRotation` calls `versioningSvc.CreateVersion` first, so there
is no version row to recover the pre-rotation value from.

**Fix sketch**: generate a real replacement value (or require the caller to
supply one), encrypt via `cryptoSvc` before `Update`, and call
`versioningSvc.CreateVersion` on the old value first, matching
`performAutomaticRotation`. A regression test should rotate then `GetSecret`
and assert the plaintext round-trips.

**Why it survived**: no test performs a manual rotation followed by a read. The
CLI help previously said only "rotate a secret according to its assigned
policy", which described the intent rather than the placeholder implementation.

**What was fixed**: `PerformManualRotation` now resolves its replacement value
from the request (`NewValue`, or `Generate` with `pwgen.Options`) and fails
with `ErrRotationValueRequired` rather than inventing one; archives the
pre-rotation plaintext through `versioningSvc.CreateVersion` before writing,
which is fatal on failure; and encrypts through `cryptoSvc.EncryptSecret`
before `secretRepo.Update`. `generateNewSecretValue` is deleted. The scheduler
sets `Generate: true` and no longer calls `CreateVersion` itself, which used to
write a second, doubly encrypted row. The CLI gained `--value`/`--generate`.
The regression test is
`TestPerformManualRotation_ExplicitValue_RoundTripsThroughGetSecret` in
`internal/services/secrets/rotation_roundtrip_test.go`.

**Upgrade note**: the rotation scheduler is enabled by default
(`rotation.secrets.enabled: true`, 1h interval — see `config/config.go` and
`.rocketvault.yaml.example`). Any deployment upgrading to this fix with
`auto_rotate = true` policies that are already overdue will have those
secrets rotated to a freshly generated value within the scheduler's next
tick (default 1h) after deploy — this is correct per the fix, not a
regression, but it is a real behavior change: the old value is archived as a
version, not lost, but the live value changes to something the operator did
not choose, and nothing outside RocketVault is updated to match. Operators
who rely on those secrets matching an external system's value should check
for overdue `auto_rotate` policies before upgrading, or disable auto-rotate
on them first, rotate manually with an explicit `--value`, then re-enable.

**Recovery for data corrupted before this fix**: values rotated by the
scheduler survive in `secret_versions`, but doubly encrypted — a normal
`secrets version get` returns the inner ciphertext, and recovering the
plaintext means decrypting that output once more with the master key. Values
rotated manually are **not recoverable**: the manual path never versioned, and
it overwrote the stored ciphertext in place. The only recovery for those is an
out-of-band copy (a database backup or `rocketvault backup` archive predating
the rotation, or the value as known to the system the secret belongs to). No
repair tooling was built; this was an explicit non-goal.

Detecting affected secrets: a corrupted value has a `_rotated_<digits>`
suffix on an otherwise base64 body, and fails to decrypt. Operators can find
candidates with
`SELECT id, name FROM secrets WHERE value LIKE '%\_rotated\_%' ESCAPE '\';`
and cross-check `secret_rotation_history` to tell the two recovery cases
apart. Its `triggered_by` column does not help here — both the scheduler and
the CLI go through `PerformManualRotation`, which hardcodes
`TriggeredBy: model.TriggerManual` regardless of caller, so every row reads
`'manual'`. Use `notes` instead: a row with
`notes = 'Automatic rotation by scheduler'` is the doubly-encrypted,
recoverable case above; any other row, or no row at all, is the manual,
unrecoverable case.

---

### B36 — `secrets export` writes plaintext while `--encrypt` (default true) claims otherwise

**Status**: Fixed 2026-08-21, across commits `457c0c5..5840391` — the fix
spans the service layer (`457c0c5` seals exports under a passphrase),
the CLI wiring (`8d02ec8`), import detection and refusal (`e9e2f12`,
`a10654b`), the API's dead `encrypt` field (`e0252cd`), and the audit-record
and release-note follow-ups (`179dd45`, `5840391`); no single commit covers
the whole fix.
**Severity**: Resolved
**Files**: `cmd/secrets/export.go`, `cmd/secrets/import.go`,
`internal/services/secrets/secret_service.go`

**Symptom**: `rocketvault secrets export --file backup.json` produces a file
containing plaintext secret values. The flag `--encrypt`/`-e` defaults to
`true` and is described as "Encrypt the export file", so the default
invocation actively misinforms.

**Corrected 2026-08-21** (this entry originally cited the wrong flag and line):
the output flag is `--file`/`-o` (`export.go:141`, with
`MarkFlagRequired("file")`), not `--output` — `--output` is a root persistent
flag selecting table/json/yaml rendering. `exportEncrypt` binds at
`export.go:142`, not 129.

**The HTTP path has the same defect.** `model.ExportSecretsRequest.Encrypt`
(`model/secret.go:228`) also has no reader anywhere in the tree, so
`POST /secrets/export` with `{"encrypt": true}` returns plaintext too. This was
missed when the entry was first filed; fixing only the CLI would leave the API
making the same false claim.

**Root cause**: `exportEncrypt` is declared (`export.go:43`) and bound
(`export.go:142`) and **never read anywhere in the repository**.
`ExportSecretsRequest` has no encryption field at all — only `Scope`, `Format`,
`FilterTags`, `IncludeTags` — and `ExportSecrets` serialises
`Value string \`json:"value"\`` directly. `importEncrypted`
(`import.go:42,122`, "File is encrypted") is dead in exactly the same way.

**Fix taken**: export encryption is implemented, not deleted.
`ExportSecretsRequest` gained `Encrypt`/`Passphrase`; `ExportSecrets` seals the
formatted bytes with `common.SealExport` (argon2id over the existing
AES-256-GCM primitives) and errors rather than returning plaintext when
encryption was requested without a passphrase. The CLI resolves the passphrase
from `--passphrase-file`, `ROCKETVAULT_EXPORT_PASSPHRASE` or a prompt, after the
authorization check and before any write. Import detects the envelope by content
and opens it; `--encrypted` is deprecated rather than removed. The API's dead
`encrypt` field is now a 400.

**Follow-up (2026-08-22): the API-side 400 was itself reversed.** The "API's
dead `encrypt` field is now a 400" decision above was not the only one on the
table when it was made — a design-spec commit (`a428298`) recorded a
different decision 12 minutes after the implementation plan was written
("the API accepts a passphrase in the request body"), but the plan's earlier,
opposite approach is what actually shipped, and the spec text was never
reconciled with the code. That contradiction was found and resolved on this
date: `POST /secrets/export` and `POST /secrets/import` now accept a
`passphrase` (request body field / multipart form value respectively) and
can produce and consume encrypted exports directly, implementing the design
spec's original decision. See
`docs/superpowers/specs/2026-08-21-cli-bug-fixes-b35-b41-design.md`'s
"Decision (2026-08-21)" note (itself annotated on this date to say so) and
`docs/release-notes/v4.3.0-api-secrets-passphrase.md`. The paragraph above is
left as written because it was correct for the commits it describes; it no
longer describes current behavior.

**Breaking**: a scripted export with no passphrase source now fails instead of
writing plaintext. See `docs/release-notes/v4.2.0-ca-certificates.md`.

**Authorization**: `cmd/secrets/export.go`'s `RunE` requires the admin or
secrets_manager role (`common.HasRequiredRole`), then
`vaultcli.RequireDataAction` re-runs the same access-policy-then-role-grant
check HTTP gets, scoped to the target vault and
`ActionSecretsGet`. There was never an access-control hole here — the defect
was purely the false encryption assurance.

---

### B37 — `certificates renew` silently converts a CA-signed certificate to self-signed

**Status**: Fixed 2026-08-21, commits `bba1735..52af5f1`, plus `a9bcbad`
(gate renewal on the CA's own signability)
**Severity**: High — breaks trust chains without warning
**Files**: `internal/services/certificates/certificate_service.go`,
`internal/repositories/certificate_repository.go`, `internal/crypto/x509_helper.go`,
`internal/crypto/key_crypto.go`, `internal/db/db.go`, `model/certificate.go`,
`cmd/certificates/renew.go`

**Symptom**: renewing a certificate originally issued against a CA returns a
self-signed certificate. Relying parties that pinned or validated the chain
reject it, with nothing in the CLI output indicating the issuer changed.

**Root cause**: `RenewCertificate` always self-signs. It calls
`crypto.CreateSelfSignedCertificatePEM(privateKeyPEM, key.Type,
crypto.CertificateTemplate{... IsCA: isCA})` on every path: there is no
CA-signing branch in the renew path and the original `CACertID` is never
consulted.

The `IsCA` argument used to be a hardcoded `true`, which was B44; it is now
derived from the stored certificate by `inspectCertificateCA`, which
distinguishes a leaf, a working CA, and a pre-fix certificate that asserts
`CA:TRUE` without `keyCertSign`.

> **Do not revert that `IsCA` handling to a hardcoded value when fixing this
> bug.** Passing `IsCA: true` again reintroduces B44, and post-B43 it is
> strictly worse than the original: the template now adds `keyCertSign`
> wherever `IsCA` is set, so a hardcoded `true` turns every renewed
> certificate into a fully working CA. Passing a hardcoded `false` is the
> mirror-image bug — it strips the CA bit off real CAs. Keep the derivation
> and the demotion of pre-fix certificates exactly as they are; see
> `docs/superpowers/plans/2026-08-21-08-b43-ca-keyusage.md` and § B44 below
> for why.

**Related**: `CreateCASignedCertificate` hardcodes the CA key type as `"RSA"`
(l.396-397, comment: "assume CA uses RSA for simplicity"), so an ECDSA CA is
sent down the RSA path.

**Fix**: the CA link had nowhere to live — `CreateCertificateRequest.CACertID`
was consumed at creation and discarded, and neither `model.Certificate` nor the
`certificates` table had a column for it. The fix therefore spans the storage
path as well as the branch:

- `certificates.ca_cert_id` added to the fresh-install schema and to
  `migrateSchema`; `model.Certificate.CACertID *uuid.UUID` added.
  `CertificateRepository.Update` deliberately does **not** write the column —
  renewal writes through it, and touching it there would erase the issuer.
- `CreateCASignedCertificate` records the link and derives the CA key type
  from the CA private key via the new `crypto.DetectPrivateKeyType`, replacing
  the hardcoded `"RSA"`.
- `RenewCertificate` branches on the link. A CA that is deleted, out of scope,
  disabled or expired refuses the renewal instead of silently self-signing —
  stricter than creation, deliberately.
- `crypto.CreateX509Template` now adds `KeyUsageCertSign|KeyUsageCRLSign` to
  CA templates. Without it neither `CheckSignatureFrom` nor a pool `Verify`
  accepted any chain this system issued, so the headline regression test could
  not have been written.
- `crypto.CreateCASignedCertificatePEM` now errors on an unsupported CA key
  type instead of returning a PEM block wrapping zero bytes with a nil error.

**Not repaired by the fix, two carry-overs:**

1. Certificates created before this change have a NULL `ca_cert_id`. If such a
   certificate is genuinely CA-signed, renewal now **refuses** it with
   "signed by a CA this installation no longer records"; re-create it against
   its CA. Refusing is deliberate — silently self-signing is the bug.
2. CA certificates issued before this change lack `KeyUsageCertSign`, so
   chains under them still fail Go's verifier. Renewing such a CA does not
   repair it: `inspectCertificateCA` reports it as `caStatusUnsignableCA`, and
   the self-signed branch's `isCA := status == caStatusCA` evaluates false for
   that status, so renewal demotes it to an ordinary leaf instead. Existing
   CAs stay unusable until reissued with `--is-ca`; see the reissue procedure
   in `docs/release-notes/v4.2.0-ca-certificates.md`.

**Follow-ups filed, not done here:**

- `CreateCASignedCertificate` will still sign with an expired CA
  (`certRepo.Read` with no lifecycle gate) while renewal now refuses to.
  Aligning create is a behavior change outside B37.
- (Resolved before this plan landed.) `CreateSelfSignedCertificate` used to set
  `IsCA: true` on every self-signed certificate, leaf or not. That was filed as
  B44 and fixed by
  `docs/superpowers/plans/2026-08-21-08-b43-ca-keyusage.md`: the CA flag is now
  opt-in, and renewal carries over whatever the stored certificate says.

---

### B38 — `secrets import --overwrite` is a no-op

**Status**: Fixed 2026-08-21
**Severity**: Resolved — was Medium (documented behavior that did not exist;
imports intended to replace existing secrets silently did not)
**Files**: `internal/services/secrets/secret_service.go`,
`internal/repositories/secret_repository.go`, `cmd/secrets/import.go`

`importOverwrite` is plumbed correctly into `ImportSecretsRequest.Overwrite`,
but `ImportSecrets` only emits it as a log field. The import loop calls
`s.CreateSecret(ctx, createReq)` unconditionally with no existence check, and
`CreateSecret` never looks for an existing name. The previous CLI example
"Import and overwrite existing secrets" documented behavior with no
implementation behind it.

**What was fixed** (commits `548cd6b..fcfede3`): `FindByName` was added to
`SecretRepositoryInterface` as a scoped, name-keyed lookup. The import loop
now looks up each record by name before deciding create vs. overwrite vs.
skip: a name that does not exist is created at version 1, an existing name is
updated (versioning the previous value) only when `--overwrite` is set, and
otherwise it is skipped. `ImportResult.FailedCount` was added to distinguish
records that were attempted and errored from records intentionally skipped
(`SkippedCount`), and the CLI now prints all three counters. A real
in-memory-SQLite round-trip test
(`internal/services/secrets/import_overwrite_roundtrip_test.go`) proves the
create/overwrite/skip sequence against real crypto and the real
`idx_secrets_vault_name` unique index, not mocks.

**Related**: this fix briefly widened the blast radius of §B42 (CSV
export/import corrupts any value containing a quote or newline) — a
mis-parsed CSV record hitting an existing name used to be refused outright by
the unique-name constraint, and a working `--overwrite` would instead have
let it replace a correct secret with garbage. B42 has since been fixed, and a
malformed CSV row is now reported in `ImportResult.Errors` rather than parsed
into a value at all, so that combination is no longer a concern.

---

### B39 — `migrate:to` a lower version is a silent no-op, not a rollback

**Status**: Fixed 2026-08-21
**Severity**: Resolved — was Medium (an operator could believe they rolled
back when nothing happened)
**Files**: `internal/db/migrations/migration_runner.go`

`MigrateToVersion` only ever applies forward: it `break`s once a migration's
version exceeds the target and `continue`s past already-applied ones
(l.225-230). No down-migration path exists anywhere in the runner. Targeting a
version below the current one therefore succeeds while doing nothing.

**What was fixed** (commits `70a9cae..61cc088`, i.e. `70a9cae`, `440a667`,
`6a1048e`, `61cc088`):
`MigrateToVersion` now refuses outright when the target's version magnitude
is lower than the current schema version's, with a clear error naming both
versions and stating that down-migrations are not supported. The refusal is
a pure magnitude comparison against the current version, independent of
whether the target names a real migration file — an operator cannot dodge it
by guessing an arbitrary small number. The forward-apply loop's own
break-condition comparator was fixed alongside it, since it shared the same
underlying defect (comparing version strings instead of their numeric
value). A final code review then caught that `GetCurrentVersion` itself —
which the new refusal check depends on to learn what "current" means — still
determined the current version via SQL's lexicographic `MAX(version)`
instead of numeric magnitude, defeating the fix in the one case where
applied versions have different digit widths; that was fixed in the same
follow-up wave so the whole comparison chain (current version, target,
forward-apply) is numeric end to end.

---

### B40 — `backup list` shows nothing for default (encrypted) backups

**Status**: Fixed 2026-08-21, commits `e5b8fd8`, `6e18215` and `dedcaf5`
(behavior), `b6eeaaf` and `7a58926` (comment and help text)
**Severity**: Resolved — was Medium (the command reported an empty backup
directory that was not empty)
**Files**: `internal/backup/backup.go`, `cmd/backup.go`

`getBackupMetadata` rejected any file whose contents did not begin with `{`,
and `ListBackups` logged a warning and skipped it. Since `backup create`
encrypts by default, a directory of default backups listed as empty.

Separately, the `FILE` column was synthesized from each backup's timestamp
rather than read from disk, so it could disagree with the actual filename.

**What was fixed**: `getBackupMetadata` is now content-based and never
decryption-based — it never touches the master key. A file that does not
parse as plaintext backup JSON is no longer an error: it returns the
filesystem-derived fields (`Filename`, `Size`, `ModTime`) with `Readable`
false and `Encrypted` true, so an encrypted or corrupt backup still lists as
a row. Only a genuine filesystem failure (cannot open, stat or read) returns
an error, and `ListBackups` still logs that skip as a warning. Three shapes
take the unreadable path: contents not starting with `{`, contents that
start with `{` but fail to unmarshal, and — added by `dedcaf5` — contents
that unmarshal cleanly but carry an empty `Metadata.Version`, which is the
same minimum-viability check `validateBackupData` uses to refuse a restore,
so `{}` is reported as unreadable rather than as a fabricated all-zero
backup row. `cmd/backup.go`'s rendering was extracted into `backupListRow`,
which prints `-` for the four payload-derived columns (timestamp, version,
tables, records) whenever `Readable` is false rather than guessing them, and
takes `FILE`, `SIZE` and `MODIFIED` from the filesystem fields, so the
filename column is the real filename.

---

### B41 — Cluster of misleading CLI output and help strings

**Status**: Fixed 2026-08-21 (except the deferred `vault-access list`
permission tier — see below)
**Severity**: Low — cosmetic or documentation-only; grouped to avoid diluting
the list above
**Files**: various under `cmd/`, `internal/services/`

- ~~`certificates renew` prints "Old Certificate ID" and "New Certificate ID",
  always the same UUID~~ — fixed 2026-08-21 as part of B37; one ID is printed.
- ~~`keys rotate` prints "New Key: ID=…" though `RotateKey` reuses the same
  UUID.~~ — fixed 2026-08-21, commit `59ea36e`; output now reads "Key rotated
  successfully: ID=…" with no "New Key" claim.
- ~~`keys create --bits` help says "(2048 or 4096)"; `CreateRSAKey` also
  accepts 3072.~~ — fixed 2026-08-21, commit `9353568`; help text now lists
  all three accepted sizes.
- ~~`cmd/vault-webhook/delete.go` has an unreachable
  `errors.Is(err, ErrWebhookNotFound)` branch; `Delete` never returns that
  sentinel and deleting an absent webhook is a silent success.~~ — fixed
  2026-08-21, commit `cd9eb52`; the dead branch was removed.
- ~~`secrets create --purge-protection=false` is inert — `CreateSecret` writes
  the column only when the value is `true`, while `UpdateSecret` honors both
  directions.~~ — fixed 2026-08-21, commits `2381eae` (behavior) and
  `3471964` (help text); `create` now honors both directions like `update`.
- ~~`secrets generate-password` requires a session despite being pure local
  RNG that stores nothing; it is absent from `persistentPreRun`'s
  `systemCmds` map.~~ — fixed 2026-08-21, commits `edea96d` (behavior) and
  `3f84a8c` (docs); the command is now exempt from the session requirement.
- `vault-access list` passes `write=false` to `requireCanManageRoleAssignments`
  — the same value `revoke` passes — so listing assignments requires
  revoke-level permission. Fail-closed, so not a hole, but stricter than the
  parameter name suggests. **Deferred**, not fixed — see below.

**`vault-access list`'s permission tier is a deferred product decision, not
a bug fix.** `cmd/vault-access/list.go`'s `Long` text (as of commit
`dd5fb83`) already documents the current behavior accurately: listing
requires the same permission as `vault-access revoke`. The spec for this
cluster (`docs/superpowers/specs/2026-08-21-cli-bug-fixes-b35-b41-design.md`,
§ B41) marks "add a narrower read tier vs. keep the shared check" as
"resolve before implementing" rather than a mechanical fix, so B41's plan
(`docs/superpowers/plans/2026-08-21-07-b41-cleanup-cluster.md`) deliberately
left the authorization check untouched. Whoever owns the product call
should update this note when a decision is made.

**Provenance for B35–B41**: all found during the 2026-08-21 CLI help-text sweep
(`.claude/cli-help-conventions.md`), while reading every `RunE` to describe it
accurately. Each was verified against the source before filing. The help text
now documents actual behavior in each case, so the shipped help and this list
agree.

---

### B42 — CSV export/import corrupts any value containing a quote or newline

**Status**: Fixed 2026-08-21, commits `f2efdc5` (export) and `f1650c0`
(import), plus `e2d95e2` from the final-review wave
**Severity**: Medium — silent data corruption on a round trip, independent of
B36's encryption defect
**Files**: `internal/services/secrets/secret_service.go`

**Symptom**: export a secret whose value contains a `"` or a newline with
`--format csv`, then import it back. The value that returns is not the value
that left.

**Root cause**: neither side uses `encoding/csv`.

Export builds rows by string concatenation with no escaping:

```go
csvData += fmt.Sprintf(`"%s","%s",%s`+"\n", secret.Name, secret.Value, tags)
```

An embedded `"` therefore closes the field early, and an embedded newline ends
the record early.

Import's `parseCSVLine` (l.863) toggles `inQuotes` on *every* quote character
with no handling for the doubled-quote escape the CSV convention uses, and
operates on input already split by line, so a quoted newline can never be
parsed correctly.

**Fix sketch**: use `encoding/csv`'s `Writer` and `Reader` on both sides. They
handle quoting, doubling and embedded newlines correctly, and `Reader` with
`FieldsPerRecord` also gives real malformed-row detection, which the current
hand-rolled parser lacks. Delete `parseCSVLine`.

**What was fixed**: `ExportSecrets`'s CSV branch now writes with
`encoding/csv.Writer` and `ImportSecrets`'s CSV branch reads with
`encoding/csv.Reader`, with `FieldsPerRecord` locked to the header row's own
column count so a malformed row is reported in `ImportResult.Errors` instead
of silently mis-parsed. Tags are packed into their column through a second,
nested `csv.Writer`/`csv.Reader` pair (`csvEncodeTags`/`csvDecodeTags`) so a
tag containing a comma round-trips too. `parseCSVLine` is deleted.

**Backward compatibility**: a CSV export written before this fix still
imports correctly when no field contains a quote, comma, or newline — the
common case, verified by
`TestImportSecretsCSV_ParsesOldPreFixExportForCommonCase`. An export whose
value already contained a quote was already corrupted at write time; that
row is now reported as a parse error on import instead of being silently
misread (`TestImportSecretsCSV_OldFormatWithEmbeddedQuote_FailsLoudlyNotSilently`).
Nothing repairs an already-corrupted historical export — there is no data to
recover from a row that was mis-written before this fix existed.

One residual limitation remains, not a regression: `encoding/csv.Reader`
normalizes any embedded `\r\n` to `\n`, including inside a quoted field, with
no option to disable it, so a value or tag containing a literal `\r\n` does
not round-trip byte-for-byte through CSV. Before this fix *any* embedded
newline (`\r\n` or `\n`) destroyed the record outright; now only `\r\n`
specifically is silently altered. See B49. `--format json` is unaffected and
is the recommended format when byte-exactness matters.

**Test**: round-trip a value containing `"`, `,`, and `\n` and assert equality.

**Found**: while planning B36, which seals the formatted bytes and so does not
touch this. The two are independent; B36 does not fix or worsen it.

---

### B43 — CA certificates omit KeyUsageCertSign, so no issued chain verifies

**Status**: Fixed 2026-08-21, commit `820e4c0` (landed after B44's `8bed005`
and `5d4399b`; see the ordering note below)
**Severity**: High — the CA-signed certificate feature does not produce usable
certificates. Every chain this system has ever issued fails standard
verification
**Files**: `internal/crypto/x509_helper.go`

**Symptom**: a certificate issued via `CreateCASignedCertificate` cannot be
validated against its own CA by Go's verifier, OpenSSL, or a browser.

**Root cause**: `CreateX509Template` (`x509_helper.go:61`) sets

```go
KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
BasicConstraintsValid: true,
IsCA:                  params.IsCA,
```

The same template serves leaves and CAs, so a CA is marked `IsCA: true` with
`BasicConstraintsValid: true` but **without `KeyUsageCertSign`**. RFC 5280
requires a CA that asserts a key-usage extension to include `keyCertSign`, and
Go's verifier enforces it: a parent with a non-zero `KeyUsage` lacking
`CertSign` is rejected as a signer.

**Evidence** (reproduced 2026-08-21 in a scratch module using this template
verbatim, with a control):

```
CA KeyUsage bits: 00000101  (CertSign bit set: false)
CheckSignatureFrom: FAILED -> x509: invalid signature: parent certificate
                              cannot sign this kind of certificate
chain Verify:       FAILED -> x509: certificate signed by unknown authority
CONTROL (+CertSign):OK
```

The control differs only by `KeyUsage |= CertSign | CRLSign` and verifies
cleanly, isolating the cause.

**What was fixed**: `CreateX509Template` now computes `KeyUsage` as a variable
and adds `x509.KeyUsageCertSign | x509.KeyUsageCRLSign` when `params.IsCA` is
set; leaf templates are unchanged. Implemented by
`docs/superpowers/plans/2026-08-21-08-b43-ca-keyusage.md`, which took the work
over from Task 1 of `docs/superpowers/plans/2026-08-21-03-b37-ca-renewal.md` —
B37's chain-verification tests could not pass until this landed, so plan 08
lands first. That plan fixed B44 in the same change and **landed B44's `IsCA`
default first**, so this fix never gave a certificate signing authority nobody
had asked for.

The regression tests are in `internal/crypto/x509_ca_keyusage_test.go`: a CA
chain is built and verified end to end with both `CheckSignatureFrom` and a
cert-pool `Verify`, for an RSA and an ECDSA CA, plus a negative test pinning
that a leaf never gains `CertSign`. Asserting on the usage bits alone would
have accepted a blanket change.

**Carry-over that cannot be repaired in place**: a CA certificate already
issued keeps its bad `KeyUsage` — the extension is inside the signed body.
Existing CAs stay unusable until reissued, and every certificate under them
must then be reissued too. Documented, with the reissue procedure, in
`docs/release-notes/v4.2.0-ca-certificates.md`.

**Why it survived**: no test ever verified a chain. The certificate tests assert
that issuance returns a PEM and that fields round-trip, never that the result
validates. An assertion as small as `leaf.CheckSignatureFrom(ca)` would have
caught it at the first CA-signed certificate.

**Related**: B37 (renewal drops the CA signature) is a separate defect in the
same feature. B37 makes renewal preserve the issuer; B43 makes the issuer's
signature acceptable in the first place. Neither alone gives a working chain.

**Shipped with B44, in that order.** Every self-signed certificate used to be
marked `IsCA: true` (B44), so adding `CertSign` on the strength of that flag
would have turned every self-signed leaf into a working CA. Plan 08 landed
B44's `IsCA` default and its `--is-ca` opt-in first, then this fix. The
ordering is recorded in that plan's "Task ordering is a security property"
section, and pinned by
`TestCreateSelfSignedCertificate_LeafGetsNoCertSign`.

---

### B44 — Every self-signed certificate is issued as a Certificate Authority

**Status**: Fixed 2026-08-21, commits `8bed005` and `5d4399b`, plus
`d6a524c` (renew a pre-fix pseudo-CA as a leaf)
**Severity**: High — a compromised leaf key becomes a signing CA. Also gates
B43, whose fix would otherwise make this exploitable rather than merely wrong
**Files**: `internal/services/certificates/certificate_service.go`

**Symptom**: request an ordinary self-signed certificate — a TLS server
certificate, say — and the certificate you get back has
`BasicConstraints: CA:TRUE`. Verify with:

```bash
openssl x509 -in cert.pem -noout -text | grep -A1 "Basic Constraints"
```

**Root cause**: both self-signed call sites hardcode the flag.

```go
// certificate_service.go:227 (creation) and :743 (renewal)
crypto.CreateSelfSignedCertificatePEM(privateKeyPEM, key.Type, crypto.CertificateTemplate{
    CommonName:   req.Name,
    ValidityDays: req.ValidityDays,
    IsCA:         true,
})
```

There is no code path that produces a self-signed certificate with
`IsCA: false`. The API and CLI expose no way to ask for one.

**Why this matters on its own**: a certificate asserting `CA:TRUE` is, to any
relying party that trusts it, an issuer. If its private key leaks, the holder
can mint certificates for arbitrary names that chain to it. An ordinary leaf
certificate should assert `CA:FALSE` so that a key compromise stays scoped to
that one identity.

**Why it gates B43**: today these certificates carry `IsCA: true` but no
`keyCertSign`, so verifiers refuse to treat them as signers — the B43 defect is
accidentally the only thing preventing them from working as CAs. B43's fix adds
`CertSign` **conditioned on `IsCA`**, so applying it while B44 stands would
promote every self-signed certificate from a broken CA to a fully functional
one. That is a security regression introduced by a security fix, which is why
the two must be sequenced together.

**What was fixed**: `CreateCertificateRequest` gained an `IsCA bool` that
defaults to false, surfaced as `--is-ca` on `rocketvault certificate create`
and `is_ca` in the `POST /certificates` body. `CreateSelfSignedCertificate`
passes it through; `CreateCASignedCertificate` rejects it, because an
intermediate CA is a separate feature and quietly issuing a leaf when a CA was
asked for is the same silent wrongness as the bug itself. `RenewCertificate`
no longer forces a value at all: `inspectCertificateCA` reads the status out of
the certificate being replaced, so a leaf renews as a leaf and a working CA
renews as a CA. The one status it does not preserve is a pre-fix certificate —
`CA:TRUE` with no `keyCertSign` — which is demoted to a leaf; see the
carry-over paragraph below. Implemented by
`docs/superpowers/plans/2026-08-21-08-b43-ca-keyusage.md`, ahead of B43 in the
same change.

The flag is `--is-ca`, not the `--ca` this entry originally sketched: every
other flag on that command is named for the JSON field it fills
(`--ca-cert-id`/`ca_cert_id`, `--auto-renew`/`auto_renew`), and `--ca` would
have sat one character from `--ca-cert-id` and from the root command's
`--ca-cert`, which takes a path.

**Regression tests**: `internal/services/certificates/ca_opt_in_test.go` —
an ordinary self-signed certificate parses back with `IsCA == false` and no
`CertSign`; the opt-in parses back with `IsCA == true` and `CertSign`; the
CA-signed path refuses the opt-in; renewal preserves the stored value in both
directions (`TestRenewCertificate_PreservesNonCA`,
`TestRenewCertificate_PreservesCA`); and a pre-fix certificate renews as a
leaf with the demotion audit-logged
(`TestRenewCertificate_DemotesPreFixPseudoCAToLeaf`,
`TestRenewCertificate_DemotionIsAuditLogged`).

**Carry-over that cannot be repaired in place**: the CA flag is inside the
signed body, so every certificate issued before this fix keeps asserting
`CA:TRUE` until it is replaced. Upgrading does not narrow an existing
certificate.

What renewal does with such a certificate: it **demotes it to an ordinary
leaf** and records the demotion in the audit log under the `renew_certificate`
operation with status `ca_demoted`. Renewal is not refused, because refusing
would break auto-renew across the whole existing fleet, and nothing is lost —
a pre-fix certificate carries no `keyCertSign`, so nothing it ever signed
verified in the first place. A certificate that was genuinely meant to be a CA
must be reissued with `--is-ca`; renewal will not restore its authority.

**Operators who renewed during an earlier upgrade window must check.** Before
this correction landed, renewal preserved the bare `IsCA` flag while the fixed
template added `keyCertSign` to anything carrying it — so renewing a pre-fix
certificate armed it as a **fully working CA**, unattended via the auto-renew
scheduler and with nothing in the output saying its authority had changed. Any
certificate renewed in that window should be inspected with `openssl x509
-noout -text` for `CA:TRUE` together with `Certificate Sign`, and reissued as
a leaf if it was never meant to be an authority. Documented in
`docs/release-notes/v4.2.0-ca-certificates.md`.

**Found**: while planning B43, which surfaced that its fix keys off this flag.

---

### B45 — `POST /secrets/generate` uses a modulo-biased password generator

**Status**: Fixed 2026-08-22
**Severity**: Medium — weakens generated secrets measurably; not catastrophic,
but it is a security primitive reachable over HTTP
**Files**: `internal/services/secrets/secret_service.go`,
`internal/services/secrets/secret_service_test.go`

**Symptom**: passwords minted by `GenerateSecret` (reached from
`api/secrets.go:697`) are not uniformly distributed over their character set.

**Root cause**: `generateRandomPassword` (l.552) selects each character as

```go
randomIndex := make([]byte, 1)
rand.Read(randomIndex)
password[i] = charset[int(randomIndex[0])%len(charset)]
```

A single byte spans 0-255. With all four character sets enabled the charset is
88 characters, and `256 mod 88 == 80`, so indices 0-79 are produced three times
per 256 draws while indices 80-87 are produced twice — a 1.5x bias toward the
first 80 characters. Any charset length that does not divide 256 is biased; only
lengths that are powers of two are safe.

It is also weaker than the CLI's generator in two further ways: it guarantees no
character from each enabled set, and it has no rule against runs of identical
characters.

**Why this is now worth fixing**: `internal/pwgen` exists as of 2026-08-21 and
does all three things correctly — rejection-free selection via
`rand.Int(rand.Reader, big.NewInt(n))`, guaranteed per-set characters, and no
three identical characters in a row. Now that B35 has landed, `internal/services/secrets`
already imports `pwgen`, so `secrets generate-password` and rotation
`--generate` produce strong values while `POST /secrets/generate` keeps
producing biased ones from the same package.

**Fix sketch**: replace `generateRandomPassword`'s body with a call to
`pwgen.Generate`, mapping `GenerateSecretRequest`'s flags onto `pwgen.Options`.
Delete `generateRandomPassword`. Note the flag names differ in order
(`useSymbols, useNumbers, useUppercase, useLowercase` vs `pwgen.Options`), so
map them by name, not position.

**Test**: generate a large sample over a charset whose length does not divide
256 and assert the distribution is within tolerance; assert one character from
each enabled set is present.

**Found**: by the whole-plan review of the shared-foundations plan, which
noticed the extracted generator was about to sit beside a weaker duplicate in
the very package it was extracted for. Deliberately not fixed there — that plan's
constraint was "fix the defect and nothing else".

**What was fixed**: `generateRandomPassword` deleted outright.
`GenerateSecret` now calls `pwgen.Generate` directly, mapping
`GenerateSecretRequest`'s flags onto `pwgen.Options` **by name** (the two
structs order their booleans differently — `UseSymbols→Special`,
`UseNumbers→Numbers`, `UseUppercase→Upper`, `UseLowercase→Lower`). The now-
unused `crypto/rand` import was removed. Error handling and the pre-existing
length/charset validation in `GenerateSecret` were untouched.

**Test**: `TestGenerateSecret_UniformCharacterDistribution` generates 2000
passwords of length 64 (128,000 characters total) through `GenerateSecret`
with all four charset flags enabled (88-char set, `256 mod 88 != 0`) and
asserts every character's observed frequency is within 20% of the expected
uniform frequency. Verified to actually discriminate the bug — not just
pass by construction — by temporarily reverting `secret_service.go` alone
back to the old modulo-biased implementation and confirming the test fails
reliably (5/5 runs) against it, then confirming it passes reliably (10/10
runs) against the real fix. An earlier draft of this test (400 samples,
50% tolerance) passed even against the unfixed biased code — too loose to
catch the ~31% deviation the bug actually produces on the charset's tail
characters — and was tightened before being accepted.
`TestGenerateSecret_GuaranteesAllCharsetTypes` asserts 100 length-128
passwords each contain at least one uppercase, lowercase, digit, and symbol
character (length 128 chosen over the service's stated minimum of 8 — see
B53 below for why).

---

### B46 — `RollbackToVersion` has B35's exact defect (double-encrypt + plaintext write), currently unreachable

**Status**: Fixed 2026-08-22
**Severity**: Low today (unreachable), would have been Critical if ever wired
up unfixed — same defect class as B35, which was rated Critical for the
equivalent scheduler path
**Files**: `internal/services/secrets/versioning_service.go`
(`RollbackToVersion`), `internal/services/secrets/versioning_rollback_roundtrip_test.go`
(new), `internal/services/secrets/coverage_boost_test.go`,
`internal/services/secrets/direct_write_invalidation_test.go`

**Symptom**: none yet in production. `RollbackToVersion` has no caller
outside its own tests — no CLI command under `cmd/secrets` and no API route
invoke it, and the only production reference to `RollbackRequest` is the
interface declaration on `VersioningServiceInterface` (l.39) plus its
generated mocks. If a future CLI command or API route calls it, every
rollback will corrupt both the secret being rolled back and the version
archived on the way in.

**Root cause**: `RollbackToVersion` reads `secret` via `secretRepo.Read`
(l.345), so `secret.Value` is master-key ciphertext, exactly as it is
throughout the B35 codepaths. It then makes both of B35's mistakes at once:

1. **Archives ciphertext through `CreateVersion`, which encrypts it again.**
   At l.372-380 it builds a `CreateVersionRequest{..., Value: secret.Value,
   ...}` and calls `s.CreateVersion(ctx, currentVersionReq)`. `CreateVersion`
   unconditionally encrypts whatever it is given
   (`s.cryptoSvc.EncryptSecret(req.Value)`, l.128) before storing it, so the
   backup row written here is `secret.Value` encrypted a second time — the
   same double-encryption B35 diagnosed in the pre-fix scheduler path.
2. **Writes decrypted plaintext into `secrets.value`.** At l.364 it decrypts
   the *target* version's value into `decryptedValue`, then at l.388 does
   `secret.Value = decryptedValue` and passes that straight to
   `secretRepo.Update` (l.391) with no re-encryption step. The repository
   contract expects `secret.Value` to already be ciphertext, so this writes
   plaintext into a column every other code path treats as ciphertext — a
   subsequent `GetSecret`'s decrypt attempt on that row fails, the same
   symptom B35 fixed for `PerformManualRotation`.

Both halves fire on every call: there is no conditional or flag that skips
either step, so a single rollback both corrupts the current version's backup
row and breaks the secret's own decryptability going forward.

**Originally filed instead of fixed**: found during the B35 final review. The
reviewer confirmed it was presently unreachable — fixing unreachable code was
unplanned, unreviewed work outside that plan's scope — so it was tracked here
for whoever wired a rollback command or route up next, with an explicit
warning not to treat "unreachable" as "safe to ignore indefinitely."

**What was fixed**: mirrors B35's fix exactly, applying the same pattern
already established in `PerformManualRotation`
(`internal/services/secrets/rotation_service.go`). Before archiving the
pre-rollback state, `secret.Value` (ciphertext) is decrypted into
`currentPlaintext` via `s.cryptoSvc.DecryptSecret`, and that plaintext — not
the raw ciphertext — is what `CreateVersionRequest.Value` carries, so
`CreateVersion`'s own encryption is the only encryption step. Before writing
the target version into `secrets.value`, the already-decrypted
`decryptedValue` is re-encrypted via `s.cryptoSvc.EncryptSecret` into
`encryptedValue`, and `secret.Value = encryptedValue` is what `secretRepo.Update`
receives — never raw plaintext. A third gap surfaced during review of the
fix itself (not present in the original filing): the function's final
`return secret, nil` still held ciphertext in `secret.Value`, inconsistent
with `CreateSecret`'s established "Return plaintext to the caller" convention
in the same file. Fixed by restoring `secret.Value = decryptedValue`
(reusing the already-decrypted target-version plaintext, no re-decryption)
immediately before the final return, after the repository write and cache
invalidation complete — so it cannot affect what gets persisted.

**Test**: `internal/services/secrets/versioning_rollback_roundtrip_test.go`
(new, real SQLite + real crypto service, reusing `rotation_roundtrip_test.go`'s
fixture schema — a mocked-crypto test cannot prove a round trip).
`TestRollbackToVersion_RoundTripsThroughGetSecret` rolls back then reads the
secret back through the normal (decrypting) read path and asserts it equals
the target version's original plaintext. `TestRollbackToVersion_ArchivesThePreRollbackValue`
asserts the freshly-archived pre-rollback version decrypts in one pass, not
double-encrypted garbage. `TestRollbackToVersion_LeavesTheSecretWritable`
proves a later `UpdateSecret` can still decrypt the stored value (i.e. the
column genuinely holds ciphertext, not stranded plaintext). All three
independently verified to fail with the fix reverted and pass with it
applied. A separate assertion (added during the "return plaintext" fix
round) checks the `*model.Secret` returned directly by `RollbackToVersion`
holds plaintext, using a raw `SELECT value FROM secrets` to independently
confirm the DB column itself holds ciphertext — a two-sided check that
cannot pass if either half of the fix is missing.

---

### B47 — `rocketvault migrate` fails on any freshly-initialized database with a duplicate-column error

**Status**: Fixed 2026-09-25
**Severity**: Medium — the explicit `rocketvault migrate` CLI command is
unusable against a normally-bootstrapped database; the app itself still
starts and serves traffic fine, since its own boot-time schema setup never
hits this path
**Files**: `internal/db/db.go` (`createOptimizedSchema`, l.330 — the `secrets`
table's `CREATE TABLE IF NOT EXISTS` at l.369-385 already declares `deleted_at
TIMESTAMP NULL` at l.377), `internal/db/migrations/20241025000001_add_soft_delete.sql`
(l.5 — `ALTER TABLE secrets ADD COLUMN deleted_at TIMESTAMP DEFAULT NULL;`),
`internal/db/migrations/migration_runner.go` (`ApplyMigration`, fixed here),
`internal/db/migrations/migration_runner_test.go` (new regression test)

**Symptom**: on a database that was bootstrapped the normal way (`serve`'s
startup path, which calls `InitializeDB` → `SetupSchema` →
`createOptimizedSchema`), running the standalone `rocketvault migrate` CLI
command fails with an error of the shape `migration failed: failed to apply
migration 20241025000001: failed to execute migration 20241025000001:
duplicate column name: deleted_at`. Reproduced live against a fresh in-memory
SQLite database seeded via `DBRepository.SetupSchema` followed by
`migrations.NewMigrationRunner(...).MigrateUp(ctx)`.

**Root cause**: RocketVault has two independent, non-communicating schema
mechanisms that both believe they own the `secrets.deleted_at` column:

1. `internal/db/db.go`'s `createOptimizedSchema` (called by `SetupSchema`,
   which every normal boot runs via `InitializeDB`) creates the `secrets`
   table fresh with `deleted_at TIMESTAMP NULL` already in its `CREATE TABLE
   IF NOT EXISTS` statement (l.377). Its sibling `migrateSchema` (l.741) also
   issues `ALTER TABLE secrets ADD COLUMN deleted_at TIMESTAMP NULL` (l.744)
   for upgrading pre-existing databases, but that call site is guarded:
   `SetupSchema`'s doc comment and the loop at l.925-931 explicitly swallow
   `isDuplicateColumnError` results, so this half of the codebase is already
   idempotent against a column that's already there. Neither of these two
   functions ever writes a row to `schema_migrations`.
2. `internal/db/migrations/20241025000001_add_soft_delete.sql`, run through
   `MigrationRunner.ApplyMigration` (`internal/db/migrations/migration_runner.go`),
   does the same `ALTER TABLE secrets ADD COLUMN deleted_at` (l.5) but with no
   such guard — `ApplyMigration` runs the raw SQL in a transaction and treats
   any error, including SQLite's `duplicate column name`, as fatal.

Because a normal boot never populates `schema_migrations`, `MigrationRunner`
has no record that `deleted_at` was already handled by
`createOptimizedSchema`, so the first time anyone runs `rocketvault migrate`
against a normally-bootstrapped database, migration `001` (a no-op
placeholder — see its own comment, "The production schema is managed in
internal/db/db.go") applies fine, and then `20241025000001` fails outright on
the column collision. `rocketvault migrate` is effectively unusable on any
database this project's own normal boot path created.

**Not the same as**: B39 (a schema-initialization mechanism conflict, not a
version-comparison bug), and reproduces on any fresh database, not just ones
affected by B39.

**Broader than originally filed**: the same collision isn't unique to
`secrets.deleted_at`. `createOptimizedSchema` also pre-declares `keys` and
`certificates`' `deleted_at`/`purge_protection` (both added again by the same
`20241025000001` migration) and their `scheduled_purge_at`
(re-added by `20260308000001_add_soft_delete_keys_certs.sql`), plus most other
`ALTER TABLE ... ADD COLUMN` migrations in `internal/db/migrations/` target a
column `createOptimizedSchema`'s `CREATE TABLE` already declares for a fresh
install (e.g. `secrets.expires_at`/`not_before`/`enabled`,
`vaults.tags`/`updated_at`/`updated_by`, `secrets/keys/certificates.vault_id`,
`access_policies.vault_id`/`assignment_id`). Any of these would have hit the
same fatal error on the first pending migration after `deleted_at`, so a
migration-specific guard (e.g. only on `20241025000001`) would not have been
a real fix — the fix had to be in `ApplyMigration` itself.

**What was fixed**: `MigrationRunner.ApplyMigration`
(`internal/db/migrations/migration_runner.go`) now splits each migration
file's SQL into individual statements (a new `splitStatements` helper that
tracks `--` line comments and `'...'` string literals so an embedded `;`
doesn't split a statement in two — one migration's own comment prose
contains a semicolon) and executes them one at a time inside the transaction
instead of one `Exec` call for the whole file. A statement that fails with
`db.SQLite.IsDuplicateColumnErr` (the same dialect-agnostic check
`migrateSchema` already used to stay idempotent, reused here rather than
duplicated) is logged and skipped instead of aborting the migration; any
other error still fails it. `schema_migrations` still gets a row for the
migration either way, so a real upgrade of a pre-existing database (where the
columns are genuinely missing) is unaffected — every `ALTER TABLE` actually
runs there, exactly as before. Regression test:
`TestMigrateUp_NormallyBootstrappedDatabase` in
`internal/db/migrations/migration_runner_test.go`, which reproduces the
exact repro above (`SetupSchema` then `MigrateUp`) and asserts every real
migration ends up recorded as applied.

---

### B48 — `backup create --output <path>` fails outright: local flag shadowed by root's persistent `--output`

**Status**: Fixed 2026-08-22
**Severity**: Medium — `backup create --output <path>` could not be run at
all; the command exited with a format-validation error instead of writing a
backup
**Files**: `cmd/root.go` (unchanged, root's persistent flag was always
correct), `cmd/backup.go`, `cmd/backup_test.go` (new tests), `README.md`,
`docs/cli-guide.md`, `docs/usage-guide.md`, `docs/usage-guide.html`

**Symptom**: running `rocketvault backup create --output /path/to/file.backup`
fails immediately with an error of the shape `Error: invalid --output value
"/path/to/file.backup": must be table, json, or yaml` — the file path the
user passed is rejected as if it were a display-format selector, and no
backup is written.

**Root cause**: two different flags share the name `output`, and pflag's
local-flag-wins merge behavior picks the wrong one at the point it's read.

- `cmd/root.go:117` registers a **persistent** flag on the root command:
  `rootCmd.PersistentFlags().String("output", "table", "Output format: table,
  json, yaml")` — this is the global display-format selector (table/json/yaml)
  inherited by every subcommand.
- `cmd/root.go:415-418`, inside `PersistentPreRunE` (which runs before every
  command's `RunE`, including `backup create`'s), reads it back with
  `cmd.Flags().GetString("output")` and passes the result to
  `formatter.New(formatter.Format(outputFlag))`; a value that isn't
  `table`/`json`/`yaml` makes this call fail and `PersistentPreRunE` return
  the error above, so `RunE` never runs.
- `cmd/backup.go:207` separately registers a **local** flag on
  `backupCreateCmd` with the same name: `backupCreateCmd.Flags().StringVarP(
  &backupOutput, "output", "o", "", "Output file path for backup
  (required)")` — this is meant to be the destination file path, marked
  required at `cmd/backup.go:209`.

Cobra/pflag merges a command's local flag set with its inherited persistent
flags before `PersistentPreRunE` runs, and when both define a flag with the
same name, the command's own local flag takes precedence in the merged set.
So `cmd.Flags().GetString("output")` at `cmd/root.go:415` — intended to read
the global display-format flag — actually reads whatever the user passed to
`backup create`'s local `-o/--output` flag, i.e. the file path. Since a file
path is never `table`, `json`, or `yaml`, the format validation in
`PersistentPreRunE` always rejects it, and `backup create --output <path>`
cannot succeed regardless of the path given. (Neither the long form
`--output` nor the short form `-o` avoids the collision — pflag's flag-set
merge is keyed on name and skips registering root's persistent `output` flag
entirely on this command once the local `output` flag is registered,
regardless of which form a user types.)

**Originally not fixed alongside its discovery**: found incidentally while
implementing the B40 fix (`backup list`'s encrypted/corrupt-file bug); that
bug was about `backup create`, was pre-existing, and was unrelated to B40's
change, so it was filed separately rather than fixed opportunistically.

**What was fixed**: renamed `backupCreateCmd`'s local flag from `--output`/
`-o` to `--file`/`-f`, matching the sibling `backupRestoreCmd`'s
already-established convention for the identical concept (a backup file
path) — `backup create` and `backup restore` now name their file-path flag
consistently, and root's persistent `--output` (the format selector) is no
longer shadowed on `backup create`. The Go variable backing the flag
(`backupOutput`) was left unrenamed — only the flag's CLI name, shorthand,
and help text changed — to avoid unnecessary churn outside this bug's scope.
`backupCreateCmd`'s `Long`/`Example` text, the parent `backupCmd`'s Example
line referencing it, and every hand-written doc example found across the
repo (`README.md`, `docs/cli-guide.md`, `docs/usage-guide.md`,
`docs/usage-guide.html`) were updated to `--file` to match. `cmd/root.go`
itself needed no change — its persistent `--output` flag registration and
`PersistentPreRunE`'s read of it were always correct; the bug was entirely
in `backupCreateCmd`'s own registration colliding with it.

**Test**: `cmd/backup_test.go` gained two tests.
`TestBackupCreateCmd_FileFlagRegistered` asserts `--file`/`-f` is registered
and required, that `backup create` no longer registers its own local
`--output` flag, and that `--output` still resolves on the command but only
via inheritance from root's persistent flag (confirmed by its default value
being `"table"`, the format selector's default, not the empty string a
required path flag would have). `TestBackupCreateCmd_FileAndOutputFlagsParseIndependently`
parses `--file <path> --output json` together and asserts each flag
independently captures its own value with no collision — the scenario that
was previously impossible to express at all.

**Not touched**: `docs/usage-guide.html` was hand-edited to match rather
than regenerated via `./scripts/docs.sh build`, since a full regeneration
would have pulled in an unrelated, pre-existing doc-drift issue from B40 —
flagged for a future pass, not fixed here as it's outside this bug's scope.

---

### B49 — CSV export/import normalizes embedded CRLF to LF in values and tags

**Status**: Fixed 2026-08-22
**Severity**: Low — a documented limitation of a stdlib API, not silent
corruption beyond byte-normalization; `--format json` was unaffected and
remained available as a workaround throughout
**Files**: `internal/services/secrets/secret_service.go`,
`internal/services/secrets/secret_service_test.go`,
`internal/services/secrets/csv_cr_escape_test.go`

**Symptom** (pre-fix): export a secret whose value or a tag contains a
literal `\r\n` (e.g. Windows-authored text, some PEM/config blobs) with
`--format csv`, then import it back. The `\r\n` returned as `\n` — the round
trip was not byte-exact.

**Root cause**: `encoding/csv.Reader` (Go stdlib) unconditionally converts
`\r\n` to `\n` wherever it appears, including inside a quoted multi-line
field, with no option to disable this.

**Not a regression**: before B42's fix, *any* embedded newline (`\r\n` or
`\n`) destroyed the CSV record entirely. After B42's fix, `\n` round-tripped
exactly and only `\r\n` specifically was silently altered — a narrower,
lower-severity residual case.

**What was fixed**: since `encoding/csv` itself has no lever to preserve a
literal CR, `escapeCR`/`unescapeCR` (`secret_service.go`) transparently hide
it from the CSV layer instead. `escapeCR` replaces every literal `\r` with a
two-byte escape (a sentinel `\x00` byte followed by `'r'`), and escapes any
literal `\x00` already present the same way (doubled), so the transform is
bijective even on input that already contains the sentinel byte — not just
the common case. `unescapeCR` reverses it exactly. Applied to `Name`/`Value`
before the outer `csv.Writer.Write`/after the outer `csv.Reader.Read` in
`ExportSecrets`/`ImportSecrets`, and to each tag inside `csvEncodeTags`/
`csvDecodeTags` (the nested tags-column writer/reader has the identical
CR-normalization problem, since it is also `encoding/csv`). A plain `\n`
still needs no escaping — encoding/csv already preserves it correctly, which
is why the fast path (`strings.ContainsAny` check) skips the escape entirely
for the common case of no `\r`/`\x00` in the field.

**Backward compatibility**: a CSV file exported before this fix, whose value
or tag contained a literal CR, still degrades to `\n` on import under the
new code — exactly as it did under the pre-fix (but post-B42) code, since
there is nothing in that old file to un-escape (no sentinel byte present).
Nothing is retroactively repaired; only exports written after this fix
preserve CR going forward.

**Test**: `TestEscapeCR_RoundTrips`, `TestEscapeCR_NoOpFastPathForOrdinaryInput`,
`TestUnescapeCR_MalformedEscapePreservesBytesRatherThanDroppingData`,
`TestUnescapeCR_TrailingEscapeByteWithNoFollowingByte`
(`csv_cr_escape_test.go`, package-internal since they exercise unexported
functions); `TestExportImportCSV_RoundTripsCRLFValueAndTag`
(`secret_service_test.go`), an end-to-end `ExportSecrets`→`ImportSecrets`
round trip asserting the literal CR bytes in both the value and a tag
survive exactly.

**Found**: during final review of the B42 CSV round-trip fix.

---

### B50 — A soft-deleted certificate's name is not freed for reuse

**Status**: Fixed 2026-08-22
**Severity**: Low-Medium — blocked a documented operational procedure
(v4.2.0's CA reissue), with a workaround; no data loss and nothing failed
silently
**Files**: `internal/db/db.go` (`finalizeVaultIndexes`),
`internal/db/vault_collision.go` (`ResolveNameCollisions`),
`internal/db/vault_partial_unique_index_test.go` (new),
`internal/db/vault_collision_test.go`, `internal/db/db_edge_test.go`,
`internal/services/secrets/import_overwrite_roundtrip_test.go`,
`internal/repositories/name_taken_errors.go` (new),
`internal/repositories/secret_repository.go`,
`internal/repositories/key_repository.go`,
`internal/repositories/certificate_repository.go`,
`internal/repositories/secret_repository_test.go`,
`internal/repositories/key_soft_delete_test.go`,
`internal/repositories/certificate_soft_delete_test.go`

**Symptom (pre-fix)**: delete a certificate, then create a replacement under
the same name in the same vault. The create failed on a raw `UNIQUE
constraint failed: certificates.vault_id, certificates.name` from the
driver — no service-layer error wrapped it, so the operator saw a database
error rather than "that name is still taken by a deleted certificate".

**Root cause**: `finalizeVaultIndexes` created
`CREATE UNIQUE INDEX idx_certificates_vault_name ON certificates(vault_id, name)`
with no `WHERE deleted_at IS NULL` predicate, and `SoftDelete` only stamps
`deleted_at` — the row, and its name, stayed in the table. Only
`PurgeCertificate` (a real `DELETE FROM certificates`) freed the name, and
purge has no CLI subcommand: it is reachable solely over
`DELETE /api/v1/vaults/{vault}/deleted/certificates/{id}/purge`.
`idx_secrets_vault_name` and `idx_keys_vault_name` were built the same way in
the same function, so secrets and keys had the same shape; certificates were
where it was noticed because of the reissue procedure below.

**What was fixed — the index**: all three indexes are now partial
(`WHERE deleted_at IS NULL`), so a soft-deleted row is invisible to the
constraint and its name is immediately reusable, with no purge required.
Since `CREATE UNIQUE INDEX IF NOT EXISTS` matches on the index *name*, not
its definition, an already-upgraded database's pre-fix, non-partial index
would have been a silent no-op under `IF NOT EXISTS` alone and the old
definition would have survived this fix forever — `finalizeVaultIndexes` now
unconditionally `DROP INDEX IF EXISTS`s each of the three indexes before
recreating them, every boot, rather than attempting dialect-specific
introspection of the existing definition. `DROP INDEX IF EXISTS` and partial
indexes are spelled identically in SQLite and PostgreSQL, so no dialect
branching was needed. Neither `finalizeVaultIndexes` nor its caller
(`SetupSchema`) runs inside a transaction, so the brief window between the
DROP and the CREATE where the constraint is absent matches the pre-existing
risk profile of the boot sequence, not a new one.

**What was fixed — the collision resolver**: `ResolveNameCollisions`, which
runs before `finalizeVaultIndexes` and renames colliding
`(vault_id, name)` rows so the unique index can be created, used to scan
*all* rows including soft-deleted ones. Once the index only constrains
active rows, a soft-deleted row sharing a name with an active (or another
soft-deleted) row is no longer a real collision — renaming it would be pure
churn and could misleadingly rename a row that was never going to violate
the new constraint. Its `SELECT` now filters `WHERE deleted_at IS NULL`.

**What was fixed — the error message**: a genuine remaining collision
(two *active* resources sharing a name in one vault, still correctly
rejected) used to surface the raw, unwrapped driver error. `SecretRepository.create`,
`KeyRepository.insertKeyAndTags`, and `CertificateRepository.insertCertAndTags`
now detect a constraint violation via the existing, already-used
`db.Dialect.IsConstraintErr` helper (dialect-agnostic: SQLite's
`sqlite3.ErrConstraint` and Postgres's `23505` code) and wrap it as the new
`repositories.ErrNameTaken` sentinel, using Go's multi-`%w` support so both
`errors.Is(err, ErrNameTaken)` and the original driver error stay reachable —
a deliberate improvement over the fix sketch's single-`%w` suggestion, which
would have discarded the underlying driver error entirely.

**Symptom in the docs, still accurate**: `docs/release-notes/v4.2.0-ca-certificates.md`'s
reissue procedure was reworked on 2026-08-22 (before this fix landed) to give
the replacement CA a new name, with the delete-then-purge route documented
as the only way to reuse the exact name. That reasoning still holds after
this fix — the reissue procedure's problem was retiring the old CA *after*
trying to recreate it under the same name, which this fix does not change
the ordering requirements of, since a soft-delete only frees the name once
the create attempt runs after the delete, not before.

**Test**: `internal/db/vault_partial_unique_index_test.go` (new, real SQLite,
covering all three resource types) proves the actual fix (a soft-deleted
name is reusable), that active duplicates are still rejected, that
cross-vault names are unaffected, and — the case this bug class has broken
on four times before in this codebase — that an already-upgraded database
carrying the old, non-partial index gets it replaced correctly, not silently
skipped. `internal/db/vault_collision_test.go` gained soft-delete-aware
cases; its four pre-existing tests still pass unmodified in intent (given a
`deleted_at` column fixtures now need). `internal/repositories/*_test.go`
gained one real-database test per resource type proving `errors.Is(err,
repositories.ErrNameTaken)` on a genuine collision, and that a normal create
still succeeds.

**Found**: during the whole-branch review of `fix/b35-b44`, while checking
that v4.2.0's CA reissue procedure was executable as written.

---

### B51 — Docs still show `"encrypt": true` on `POST /secrets/export`, which now 400s

**Status**: Fixed 2026-08-22
**Severity**: Low — copy-pasting a documented example now fails with a 400
instead of doing something unsafe; no security or data-loss impact
**Files**: `docs/api-developer-guide.md`, `docs/api-developer-guide.html`,
`docs/integration-examples.md`

**Symptom**: `fix/b35-b44` (commit `e0252cd`) made the export endpoint reject
`"encrypt": true` outright — encrypted export is CLI-only (see
`docs/api-specification.yaml`'s `ExportRequest.encrypt`, updated on this same
branch). Three other docs still show request bodies or example scripts
sending `"encrypt": true` against `POST /secrets/export`, which would now
fail: `docs/api-developer-guide.md` (a request-body example plus two JS
snippets), its rendered `docs/api-developer-guide.html` (two of the same
spots), and `docs/integration-examples.md` (a copy-pasteable backup `curl`
example plus two more references).

**Root cause**: this branch changed export's API behavior (B36) without
sweeping the hand-written developer-guide and integration-example docs that
predate it — only the OpenAPI spec (`docs/api-specification.yaml`) was
updated, in this same whole-branch review's fix wave.

**Fix sketch**: remove `"encrypt": true` from the affected examples (six
spots across the three files) or replace them with a note that encrypted
export is CLI-only, matching the spec's new field description. The `.html`
file is generated by `scripts/docs.sh build` from Markdown sources — verify
whether it should be hand-edited or regenerated per this repo's normal docs
workflow before editing it directly.

**Found**: during the scoped re-review of the whole-branch review's own fix
wave for `fix/b35-b44`, while independently verifying item 5 (the OpenAPI
spec fix) against the rest of the documentation set.

**Closed (2026-08-22)**: rather than scrubbing `"encrypt": true` from these
examples (this entry's original "Fix sketch"), the underlying API behavior
was changed instead — `POST /secrets/export`/`POST /secrets/import` now
accept a `passphrase` field/form value (see B36's follow-up note above), so
the examples this bug flagged are correct again once a `passphrase` is added
alongside `encrypt: true`. All three originally-named files were updated,
plus `docs/integration-examples.html`, which this entry's original "Files"
list omitted despite carrying the same three stale spots as its `.md` source
(`docs/integration-examples.md`) — a gap in the original filing, corrected
during the fix rather than left for a future bug report.

---

### B52 — `docs/usage-guide.html` is stale relative to `docs/usage-guide.md` for a B40 passage

**Status**: Open, found 2026-08-22
**Severity**: Low — the generated `.html` doc shows outdated prose in one
passage; the source-of-truth `.md` file is correct, no code behavior is
affected
**Files**: `docs/usage-guide.html`, `docs/usage-guide.md`

**Symptom**: `docs/usage-guide.html` is normally generated from
`docs/usage-guide.md` via `scripts/docs.sh build`. Running that build
locally (to check an unrelated fix) revealed the checked-in `.html` had
already drifted from the `.md`: a passage about `backup list`'s behavior
with encrypted/corrupt backups (B40, fixed 2026-08-21) was updated in
`usage-guide.md` at the time, but the corresponding `.html` was never
regenerated to match, so it still shows pre-B40 prose.

**Root cause**: whoever landed B40's `usage-guide.md` correction did not
also run `./scripts/docs.sh build` (or did, but didn't commit the result)
to regenerate `usage-guide.html` from it. The two files are meant to stay
in sync via that build step; nothing enforces it automatically.

**Not fixed here**: found incidentally while fixing B48 (a `backup create`
flag-name doc update touched three lines of `usage-guide.md`/`.html`).
Running a full `scripts/docs.sh build` to fix this properly also
regenerates every other doc in `scripts/docsgen/docs.go`'s list and
materializes two previously-ungenerated `docs/release-notes/*.html` files —
a much larger, unreviewed diff than B48's own scope. B48's fix hand-edited
only its own three affected lines in `usage-guide.html` and left this
pre-existing drift untouched.

**Fix sketch**: run `./scripts/docs.sh build` and review/commit the full
regenerated output (including the two currently-uncommitted
`docs/release-notes/*.html` files, if they're meant to be tracked) as its
own, separately-reviewed change — not bundled into an unrelated bug fix.

**Found**: while fixing B48 (2026-08-22).

---

### B53 — `pwgen.Generate`'s "guaranteed per-set character" injection can silently overwrite another set's guarantee, especially at short lengths

**Status**: Open, found 2026-08-22
**Severity**: Medium — undermines a documented guarantee of a shared security
primitive used by HTTP secret generation, CLI password generation, and
credential rotation; most likely to bite at short lengths, which is exactly
where a caller is most likely to still want every requested character class
represented
**Files**: `internal/pwgen/pwgen.go`

**Symptom**: `pwgen.Generate`'s doc comment promises "when Length is at
least as large as the number of enabled character sets, it also guarantees
at least one character from every enabled set." That guarantee does not
hold in practice once more than one set is enabled, well above the
documented breakdown point (`Length < number of enabled sets`).

**Root cause**: the `injectGuaranteed` closure (l.89-115) is called once per
enabled charset (Upper, Lower, Numbers, Special, in that order), and each
call independently picks a **random position** in the password to overwrite
with a character from its own set — with no tracking of which positions
earlier calls already claimed. A later set's injection can land on the exact
position an earlier set just guaranteed, silently erasing that guarantee
without the function ever noticing.

Measured failure rate (all four sets enabled, `crypto/rand`-backed, real
runs against current code):

| Length | Guarantee violated |
|---|---|
| 8 (the secrets-service minimum) | ~15% of samples |
| 16 | ~1.6% |
| 32 | ~0.08% |
| 128 (the secrets-service maximum) | unmeasured in 20,000 samples |

**Impact**: any caller requesting a short password with multiple character
classes enabled can receive one missing a class it explicitly asked for,
despite the function's contract. Current callers: `POST /secrets/generate`
(default length 16, but caller-settable down to 8 — see B45, just fixed to
call this function), `secrets generate-password` CLI (`cmd/secrets/generate.go`),
and credential rotation's `--generate` path (`internal/services/secrets/rotation_service.go`).
None of them currently retry or validate the guarantee after the call, so a
violation ships silently as a generated secret/password that is one
character class short of what was requested.

**Fix sketch**: track claimed positions across all `injectGuaranteed` calls
(e.g. a `map[int]bool` or a shuffled position list consumed one index per
call) so a later set's injection never lands on a position an earlier set
already claimed. That also removes the need for `injectGuaranteed`'s
own run-of-3 retry-on-collision loop to double as an implicit (and
insufficient) way of avoiding overwrites.

**Found**: by the B45 implementer, while writing a test asserting
`pwgen.Generate`'s guaranteed-per-set-character property at length 8 (B45's
service minimum) — the test failed intermittently, not from B45's own
change, but from this pre-existing defect in the shared `pwgen` package.
B45's own test was changed to use length 128 instead of 8 to avoid the
flakiness while still exercising the real guarantee; fixing this bug is
tracked separately since `pwgen` is shared by callers outside B45's scope
and touching it wasn't part of that fix.

---

### B54 — No way to log in to a remote server: `users login` is blocked by the remote-target guard, so a remote session can only be created as a side effect of a `secrets` command

**Status**: Fixed in commit `3cf4d89` (2026-09-04), found 2026-09-03
**Severity**: Medium — remote mode is reachable but its front door is not.
A user with an active context who has no cached session (or whose refresh
token has aged out) cannot authenticate by the documented command; they must
know to pass credentials to an unrelated resource command instead. No data
is at risk and no workaround is destructive, but the discoverability failure
is total: the error names the wrong remedy.
**Files**: `cmd/root.go` (`isRemoteCapableCommand` l.235-240, the guard
l.593-598, `resolveRemoteAuthentication` l.411-491), `cmd/users/login.go`,
`cmd/users/login_oidc.go`, `cmd/users/logout.go`, `common/session.go:263-265`,
`internal/vaultapi/login.go`

**Symptom**: with a context active, the obvious command fails:

```
$ rocketvault users login --username admin --password <pw> --totp-code <code>
Error: remote mode (--server/ROCKETVAULT_ADDR/context "https://numericlabs.lxd")
is not yet supported for "rocketvault users login"; unset it to run against the
local instance
```

The error's advice — "unset it to run against the local instance" — is
actively misleading here. Unsetting the context logs the user into the
*local* instance, which is not what they asked for and leaves them no closer
to a remote session.

**Root cause**: `isRemoteCapableCommand` (`cmd/root.go:235-240`) admits only
the seven `secrets` subcommands. `users login` is in `isSystemCommand` — which
exempts it from *authentication*, not from the remote-target guard — and is
neither `isContextGroup`, `isCobraBuiltinCommand`, nor `isLocalOnlyCommand`,
so it falls through to the blanket refusal at `cmd/root.go:593-598`.

Remote authentication does exist, but only inside
`resolveRemoteAuthentication` (`cmd/root.go:421-438`), which calls
`cliclient.LoginRemote` when `--username` and `--password` are present. That
function runs in `remotePersistentPreRun`, which is reached only by a
remote-capable command. So the only way to create a remote session today is:

```bash
rocketvault secrets list --username admin --password <pw> --totp-code <code>
```

Asking for a secret list is how you log in. The session it caches
(`srv_<host>__<user>.json`) is then reused by later bare commands.

**Fix**: planned as
`docs/superpowers/plans/2026-09-03-cli-remote-vaultapi-02b-remote-login.md`,
a dedicated three-task plan sequenced right after `02a` rewrites the code
this touches. The shape:
widen the remote-capable allowlist beyond `secrets` to admit `users
login`/`users logout`, and give `remotePersistentPreRun` an unauthenticated
branch for them — `login` cannot require a token before it starts, since
producing one is its whole job.

The adapter is thinner than the rest of the group but not free.
`vaultapi.Login` (`internal/vaultapi/login.go`) already targets the correct
route, but it returns only a `TokenSource` and a `LoginIdentity` — neither
exposes the access or refresh token — and it seeds the source through
`NewSessionSourceFromCache`, whose `SaveSession` defaults to a no-op by
design (`sessionsource.go:98-101`, so the MCP server's in-chat login stays
memory-only). No caller can persist the session it just created. The task
therefore replaces `Login`'s trailing `expiry` parameter with a
`LoginOptions{Expiry, SaveSession}` struct; the one production caller,
`internal/mcpserver/tools_login.go:44`, keeps its behaviour by passing no
hook.

**Related defect found while designing the fix**: `logout` is broken in the
same scenario, for a different reason. `runLogout` (`cmd/users/logout.go:58`)
calls `common.DeleteSession(username)`, hardcoded to `LocalServerKey`
(`common/session.go:263-265`), and its no-username path takes whatever
`LoadCurrentSession` returns with no server check. Exempting it from the
guard without more would make it delete the **local** session while a remote
context is active — the wrong file, silently — and leave the remote session
it was asked to clear in place. It needs `DeleteSessionForServer` plus the
server-key guard `resolveRemoteAuthentication` already applies
(`cmd/root.go:446-448`). Same task.

One partial relief is already planned and does not close this: Task 1 of the
same plan adds `--client-id`/`--client-secret`, giving CI a remote identity
with no login step. That helps service accounts, not humans.

**What actually shipped** (2026-09-04, plan `02b`): `remoteCapableCommands`
replaced the secrets-shaped `remoteCapableSecretsCommands` map and admits
`users login`/`users logout`; `remotePersistentPreRun` grew an
unauthenticated branch, selected by `isRemoteUnauthenticatedCommand`, that
builds a `vaultapi.Client` with `unauthenticatedSource{}` so `login` reaches
its `RunE` with no session on disk. `runRemoteLogin` (`cmd/users/login.go`)
calls `vaultapi.Login` with `SaveSession: common.SaveSession`; `Login`
stamps `ServerKey` from the client's base URL, so a remote login lands in
`srv_<host>__<user>.json` and never overwrites the local session.

The related `logout` defect is fixed in the same commit: `runLogout` takes a
`serverKey` first argument, deletes through `DeleteSessionForServer`, and
its no-username path now refuses a current-session pointer belonging to a
different server.

Two things done beyond the original entry: `--oidc` follows the remote
target too and uses the CA-aware HTTP client rather than
`http.DefaultClient`, and the JWT is no longer printed on successful login
in either mode — the session is cached, so a bearer token on stdout only
leaked into shell history and CI logs.

**Not verified end to end.** The fix is covered by unit tests
(`cmd/users/login_remote_test.go`, `cmd/root_test.go`), but the plan's
manual walkthrough against a running server — log in, run a bare command,
log out, confirm the local session survives — was not performed, as it
needs a live instance and a current TOTP code.

The `users` *resource* commands (CRUD, bootstrap admin) stay deferred to the
`users` spec named under "Non-goals" in
`docs/superpowers/specs/2026-09-03-cli-remote-vaultapi-consolidation-design.md`.
`vaultapi` has no coverage for them at all. Only the authentication pair
moves.

**Found**: manually, while verifying the B-adjacent refresh-path fix
(`0924ba5`). The refresh itself worked; the failure surfaced only because
the suggested recovery step — re-authenticating with `users login` — turned
out to be impossible while a context was active.

---

### B55 — A duplicate resource name returns HTTP 500 with the SQL constraint in the response body, for secrets, keys and certificates alike

**Status**: Open, found 2026-09-03
**Severity**: Medium — a plain client error is reported as a server fault, and
the response leaks the table and column names of the violated unique index.
No data is at risk and the write is correctly rejected, but callers cannot
distinguish "you chose a taken name" from "the vault is broken" by status
code, and any client retrying on 5xx will retry forever. The information
disclosure is the same class B24/B25 closed for PKCS#11 errors, in a path
those fixes did not cover.
**Files**: `internal/repositories/name_taken_errors.go:9`,
`internal/repositories/secret_repository.go:199`,
`internal/repositories/key_repository.go:391`,
`internal/repositories/certificate_repository.go:444`,
`api/errors_key.go:60-62` (the `default` arm)

**Symptom**: reproduced live 2026-09-03 against a scratch instance by
importing a key whose name already existed in the vault:

```json
{"detailed_error":"failed to store imported key: key \"imported-rsa\": a resource with this name already exists in this vault: UNIQUE constraint failed: keys.vault_id, keys.name",
 "id":"Internal server error","message":"Internal server error","request_id":"req-91efe9c9","status_code":500}
```

**Root cause**: the sentinel exists and is raised correctly —
`repositories.ErrNameTaken` is wrapped by all three repositories on a unique
violation, alongside the driver's own error. Nothing maps it. `grep -rn
ErrNameTaken api/ internal/services/` returns no hits at all, so
`writeKeyError`'s switch (`api/errors_key.go`) never matches it and falls
through to `default: c.SetInternalError(err)`, which serialises the whole
wrapped chain — including the driver's `UNIQUE constraint failed: ...` — into
`detailed_error`.

This is **not** import-specific. The same sentinel is raised by
`SecretRepository.Create`, `KeyRepository.Create` and
`CertificateRepository.Create`, so every create/import path that can collide
on a name has the same 500. Import is simply where it was noticed.

**Fix recipe**: add a case ahead of the `default` arm in `api/errors_key.go`:

```go
case errors.Is(err, repositories.ErrNameTaken):
    c.SetConflict("a resource with this name already exists in this vault")
```

returning `409`, and make the equivalent mapping wherever secrets and
certificates render their errors. The response must carry the sentinel's own
message and **not** the wrapped driver error — the point is to stop
serialising the chain, so re-wrapping it into a 409 would fix the status code
and keep the leak. Pin with a test per resource type that asserts both the
status and the absence of the substring `UNIQUE constraint` in the body.

**Found**: manually, while capturing the §8.1 key-import worked example for
`.claude/manual-testing-plan.md`. Not reachable from the existing test suite,
which never creates two resources with the same name in one vault.

---

### B56 — The per-vault rate limiter charges requests it then rejects with 403, so an unauthorized caller can drain a vault's budget

**Status**: Open, found 2026-09-03
**Severity**: Medium — a principal with **no** access to a vault can exhaust
that vault's per-minute allowance and deny service to callers who do have
access. It needs a valid session (the limiter runs after authentication), so
this is not anonymous, but any authenticated user on the instance can do it to
any vault whose name they can guess, without holding a single role in it.
Whether that is acceptable is a deployment question; that nothing records it
is the defect.
**Files**: `internal/middleware/vault_rate_limit.go`, `api/api.go:83-88`
(chain order)

**Symptom**: reproduced live 2026-09-03 with `rate_limit.per_vault: 5`, as an
admin holding no role assignment in the `default` vault:

```
req 1: 403     req 5: 403
req 2: 403     req 6: 429
req 3: 403     req 7: 429
req 4: 403     req 8: 429
```

Five refusals consumed the entire budget. The caller never read anything.

**Root cause**: chain order, and it is the correct order. `api/api.go:83-88`
runs `VaultResolutionMiddleware` → `VaultRateLimitMiddleware` →
`PolicyMiddleware`. The limiter must follow vault resolution (the vault is
unknown before it) and therefore necessarily precedes authorization, so the
token is spent before the request's authorization outcome exists. There is no
ordering that both knows the vault and knows the verdict.

**Fix recipe**: not a reordering. Options, in rough order of preference:

1. Refund the token when the handler's outcome is a 403 — the limiter would
   need to observe the response status, e.g. via a `ResponseWriter` wrapper,
   and return the token to the bucket. Keeps one bucket and the current
   ordering.
2. Charge unauthorized requests against a separate, much smaller
   per-principal bucket, so abuse costs the abuser rather than the vault.
   This overlaps with the per-principal rate limiting already on the roadmap
   (`.claude/roadmap-azure-parity-and-beyond.md`, Phase 3).
3. Accept and document it, on the grounds that the caller is authenticated
   and therefore attributable in the audit log.

Whichever is chosen, the behaviour belongs in the docs either way — it is
currently written down only in `.claude/manual-testing-plan.md` §11.1's worked
example.

**Found**: manually, while capturing the §11.1 per-vault rate-limit worked
example. Invisible to the unit tests, which exercise the limiter against
authorized requests only.

---

### B57 — `secrets create/update/delete/import/export` gate on a legacy global role, contradicting a vault's own role assignments

**Status**: Open, found 2026-09-04
**Severity**: Medium — this is not an access-control hole; it fails closed,
never open (see Authorization note below). The defect is that it silently
overrides a real, vault-scoped role assignment for every CLI user of these
five commands, including the new self-service vault-provisioning feature's
headline case: a vault's creator, freshly granted `Key Vault Administrator`
in that vault, cannot write a secret into it over the CLI. It is also a
CLI/HTTP behavioural divergence, which this project otherwise treats as a
defect to fix rather than a variance to document — see CLAUDE.md's "CLI
Authorization" section.
**Files**: `cmd/secrets/create.go:95-96`, `cmd/secrets/update.go:95-96`,
`cmd/secrets/delete.go:83-84`, `cmd/secrets/import.go:111-112`,
`cmd/secrets/export.go:119-120`

**Symptom**: reproduced live 2026-09-04 while capturing the self-service
provisioning worked example (`.claude/manual-testing-plan.md`'s "Worked
example: self-service provisioning, quotas, and what a soft-delete costs
you"). `msp-bot`, holding only the global account role `user`, created vault
`acme-prod` under a provisioning grant; vault creation automatically wrote it
a `Key Vault Administrator` role assignment scoped to `acme-prod`. Writing a
secret into that vault as the same principal:

```
$ rocketvault secrets create example-secret hello-acme --vault acme-prod
Error: forbidden: requires admin or secrets_manager role
```

The identical write over HTTP, same principal, same vault:

```
$ curl -s -X POST $BASE/vaults/acme-prod/secrets -H "Authorization: Bearer $BOT_TOKEN" \
  -H 'Content-Type: application/json' -d '{"name":"example-secret","value":"hello-acme"}'
{"id":"d590bb30-8507-4953-9b8e-697345fd7b1a","name":"example-secret","version":1,"created_at":"2026-09-04T18:28:32+05:30","enabled":true}
```

`201`. The vault-scoped role assignment is genuinely honored — just not by
the CLI command.

**Root cause**: each of the five commands runs two authorization checks in
sequence, as an AND, where only the second is meant to be authoritative.
First, a legacy check against the caller's global account role:

```go
if !common.HasAnyRole(claims.Roles, model.RoleAdmin, model.RoleSecretsManager) {
    return fmt.Errorf("forbidden: requires admin or secrets_manager role")
}
```

(`create.go:95-96`; the same two lines, same message, appear at
`update.go:95-96`, `delete.go:83-84`, `import.go:111-112`, and
`export.go:119-120`). Only after that gate passes does the command reach the
real, vault-scoped check:

```go
vaultID, err := vaultcli.RequireDataAction(ctx, cmd, serviceContainer, userID, model.ActionSecretsSet, model.OpCreate)
```

(`create.go:105`; `update.go:106`, `delete.go:96`, `import.go:131`,
`export.go:130` for the other four, against their own actions/ops).
`RequireDataAction` is the check CLAUDE.md's "CLI Authorization" section
describes as reproducing what HTTP gets for free from `PolicyMiddleware` —
explicit-deny override, then deny-by-default role-assignment lookup. A
principal with no global `admin`/`secrets_manager` role but a valid
vault-scoped grant (exactly what `Key Vault Administrator` from
self-service provisioning is) satisfies `RequireDataAction` but never reaches
it, because the first gate already returned.

`secrets get` (`cmd/secrets/get.go`) has no such first gate — only the
`RequireDataAction` call at `get.go:93`, and its help text at `get.go:53-56`
says so explicitly ("No global role is checked here"). That makes the family
asymmetric: reads honor a vault-scoped role assignment on their own; the five
writes require the caller to *also* hold the legacy global role, which
self-service-provisioned principals such as `msp-bot` do not have and have no
way to acquire without an admin separately granting it — defeating the point
of self-service.

**Cross-reference**: `.claude/known-bugs.md` § B36's "Authorization" note
describes this same gate on `export.go` and concludes "There was never an
access-control hole here — the defect was purely the false encryption
assurance." That conclusion is about permissiveness and is still correct; it
is not in tension with this entry, which is about over-restriction on a
different axis. B36 did not fix, and was not about, the gate itself. See also
`docs/release-notes/v4.5.0-vault-provisioning.md` (the feature whose headline
promise this defect undercuts) and the worked example in
`.claude/manual-testing-plan.md` cited above, which is where this was found
and first written down.

**Fix recipe**: delete the five `HasAnyRole` gates outright, leaving
`RequireDataAction` as the single enforcement point for these commands — this
is the recommended fix. It matches `secrets get`'s existing pattern, matches
HTTP exactly (closing the divergence CLAUDE.md flags as the thing to avoid),
and needs no new logic: `RequireDataAction` already covers everything the
legacy gate was trying to express, since the global `admin` role also carries
data-plane access via role assignments (or the access-policy path), and
`secrets_manager` was itself the legacy stand-in for what per-vault role
assignments now do properly. The alternative — turn the AND into an OR, so
either the global role or the vault-scoped grant suffices — is not
recommended: it keeps a permanent second code path to maintain, keeps the
CLI/HTTP divergence alive at half-strength, and adds nothing that
`RequireDataAction` doesn't already grant an admin.

Either way, this is **not a silent fix**: deleting the gate changes behavior
for any existing deployment whose operators rely on the global
`secrets_manager` role rather than per-vault role assignments to authorize
secret writes over the CLI — those principals keep working (an actual
`secrets_manager` grant almost always also satisfies `RequireDataAction`
today, since the two checks have overlapped in practice), but a principal
that held `secrets_manager` *without* a matching vault-scoped role
assignment would newly need one. This belongs in a release note alongside
the fix, not folded quietly into a patch release.

**Found**: manually, while capturing the self-service-provisioning worked
example for `.claude/manual-testing-plan.md`. Not reachable from the existing
test suite, which does not exercise a principal holding a vault-scoped role
assignment without also holding the matching global account role.

---

### B58 — Vault delete, recover, and purge audit as an unattributed actor

**Status**: Open, found 2026-09-04
**Severity**: Medium. This is not an access-control hole — authorization is
unaffected; a refused delete/recover/purge is still refused, and the
boundary tests around each all pass. It is an accountability gap: the three
most destructive vault operations are exactly the ones the audit log cannot
attribute to anyone, while the benign create and update operations are
attributed correctly. For a self-hosted secrets manager, whose audit log is
the only record of who removed a vault and everything in it, "who did this?"
being unanswerable for a destructive action is a real compliance failure,
not a cosmetic logging gap.
**Files**: `internal/services/vaults/vault_service.go:638` (`delete_vault`),
`:690` (`recover_vault`), `:770` (`purge_vault`);
`internal/services/authorization/role_assignment_service.go:203`
(`revoke_role_assignment`, same pattern, found via the grep below)

**Symptom**: verified both in source and live against the scratch database
at `/tmp/rv-prov/rv.db`. An admin performing `vaults delete` and
`vaults purge` on its own vault produces rows with an empty `user_id`:

```
$ sqlite3 /tmp/rv-prov/rv.db \
  "select action, user_id, outcome from audit_logs where action in ('create_vault','delete_vault','purge_vault') order by timestamp;"
create_vault|a10eee1d-f25f-432c-9b20-bd9abf416e5a|
create_vault|a10eee1d-f25f-432c-9b20-bd9abf416e5a|
delete_vault||
create_vault|a10eee1d-f25f-432c-9b20-bd9abf416e5a|
purge_vault||
```

Every `create_vault` row carries the real principal UUID; every
`delete_vault` and `purge_vault` row carries an empty `user_id`. Reproduced with
a global admin acting on a vault it owns, so this is not specific to a
non-admin, to the CLI, or to the self-service provisioning feature — it is
below where the CLI and HTTP paths converge, so it affects both equally and
every actor, including admins.

**Root cause**: three of the five audit calls in
`internal/services/vaults/vault_service.go` hardcode an empty actor string
instead of passing the acting principal:

```go
s.log.LogAuditInfo("", "delete_vault", "success", fmt.Sprintf("Vault deleted: %s", name))   // :638
s.log.LogAuditInfo("", "recover_vault", "success", fmt.Sprintf("Vault recovered: %s", name)) // :690
s.log.LogAuditInfo("", "purge_vault", "success", fmt.Sprintf("Vault purged: %s", name))      // :770
```

The sibling calls in the same file do it correctly, passing the real
principal:

```go
s.log.LogAuditInfo(createdBy.String(), "create_vault", "success", ...)  // :334, and :448 (provisioned path)
s.log.LogAuditInfo(updatedBy.String(), "update_vault", "success", ...)  // :571
```

The underlying reason the three destructive calls hardcode `""` is that
**`DeleteVault`, `RecoverVault`, and `PurgeVault` do not receive the acting
principal in their current signatures at all**:

```go
DeleteVault(ctx context.Context, name string) error
RecoverVault(ctx context.Context, name string) error
PurgeVault(ctx context.Context, name string) error
```

By contrast, `CreateVault`/`CreateVaultProvisioned` take `createdBy
uuid.UUID` and `UpdateVault` takes `updatedBy uuid.UUID` — there is simply no
parameter to pass at the three destructive call sites. This is a signature
gap, not a call site that forgot an argument it already had.

A grep for `LogAuditInfo("` across `internal/services/` turns up one further
call site with the identical shape:
`internal/services/authorization/role_assignment_service.go:203`, in
`RevokeAssignment`:

```go
s.log.LogAuditInfo("", "revoke_role_assignment", "success", ...)
```

whose sibling, `AssignRole`, passes `in.CreatedBy.String()` at line 179. Like
the vault trio, `RevokeAssignment`'s signature —
`RevokeAssignment(ctx context.Context, assignmentID, vaultID uuid.UUID, callerIsGlobalAdmin bool) error`
— has no principal parameter to pass; `callerIsGlobalAdmin` is a bool, not
an identity. Revoking a role assignment is itself a destructive,
security-relevant action, so this is the same defect, not a coincidence.

The two remaining `LogAuditInfo("system", ...)` calls in
`internal/services/secrets/expiration_service.go:64,81` are unrelated: they
attribute background-scheduler actions to a literal `"system"` actor on
purpose, not an omitted caller, and are not part of this defect.

**Total call sites with the defect**: four —
`vault_service.go:638/690/770` plus
`role_assignment_service.go:203`. The original report named only
`delete_vault` and `purge_vault`; `recover_vault` (`:690`) and
`revoke_role_assignment` (`:203`) were both missed and are included here.

**Fix recipe**: thread the acting principal into all four methods the same
way `CreateVault`/`UpdateVault` already do, then pass it to `LogAuditInfo`
instead of `""`. Because none of the four methods currently accepts a
principal parameter, this is a signature change with callers to update, not
a one-line fix:

- `VaultService.DeleteVault(ctx, name string) error` →
  `DeleteVault(ctx, name string, actorID uuid.UUID) error`. Callers:
  `cmd/vaults/delete.go:43` (has `principalID` in scope already, from
  `requireCanManageVault`'s `callerIdentity(ctx)` call in
  `cmd/vaults/authz.go:108`) and `api/vault.go:300` (has `userID` in scope
  already, from `callerIdentity(c)` at `api/vault.go:290`).
- `VaultService.RecoverVault(ctx, name string) error` →
  add `actorID uuid.UUID`. Only caller: `cmd/vaults/recover.go:42`, which
  resolves `principalID` via `requireCanManageVault` the same way `delete.go`
  does. There is currently no HTTP route for vault recovery (confirmed by
  grep — `RecoverVault` appears nowhere under `api/`), so only the CLI
  caller needs updating.
- `VaultService.PurgeVault(ctx, name string) error` →
  add `actorID uuid.UUID`. Callers: `cmd/vaults/purge.go:49` (has
  `principalID` in scope from `requireCanPurgeVault`,
  `cmd/vaults/authz.go:125`) and `api/vault.go:337`, whose `purgeVault`
  handler does not currently call `callerIdentity(c)` at all (it relies on
  `PolicyMiddleware` for authorization and never extracts the identity for
  its own use) — that call needs adding, not just threading through an
  existing variable.
- `RoleAssignmentService.RevokeAssignment(ctx, assignmentID, vaultID
  uuid.UUID, callerIsGlobalAdmin bool) error` → add `actorID uuid.UUID`.
  Callers: `cmd/vault-access/revoke.go:55` and `api/role_assignments.go:233`.

Every call site above already resolves the caller's identity for its own
authorization check before calling the service method, so the principal is
available at each one — this is a mechanical signature change plus four
call-site updates (five, counting `RevokeAssignment`), not a design problem.
Update the mock/test doubles in `cmd/testutils/test_utils.go` (`MockVaultService.DeleteVault/RecoverVault/PurgeVault`,
`MockRoleAssignmentService.RevokeAssignment`) to match the new signatures.

**Found**: manually, while capturing the self-service-provisioning worked
example for `.claude/manual-testing-plan.md`, and confirmed independently
against `/tmp/rv-prov/rv.db`. Not caught by the existing test suite, which
asserts on the returned error/success of these operations but does not
assert on the actor recorded in the resulting audit log entry.

---

### B59 — A provisioning grantee can set `purge_protection` via `vaults update`, one command after being refused it at create

**Status**: Open, found 2026-09-05 (release 2 code review)
**Severity**: Medium — not an authorization bypass in the access-control
sense (`UpdateVault`'s `CanManageVault` check is honored correctly for the
vault in question); the defect is that the *quota-pinning* protection
`ErrPurgeProtectionNotPermitted` exists to provide is only enforced on one of
the two paths that can set the flag, so the restriction it advertises is
trivially bypassable by any provisioning grantee, not just a theoretical one.
**Files**: `internal/services/vaults/vault_service.go:372-373` (the
create-time guard), `:567-569` (`UpdateVault`, no equivalent guard),
`:714-739` (`PurgeVault`, refuses a protected vault for every caller
including admin); `cmd/vaults/update.go:43` and `api/vault.go:239` (both
gate the update path on `CanManageVault` against the concrete vault, not on
`quotaBounded`)

**Symptom**: a provisioning grantee refused `purge_protection` at `vaults
create` can set it one command later:

```
$ rocketvault vaults create acme-pinned --purge-protection
Error: failed to create vault: purge protection may only be set on a create
that is not quota-bounded -- a quota-bounded provisioning grant cannot set
--purge-protection; an admin or a global vaults:manage holder can

$ rocketvault vaults create acme-pinned
<succeeds -- purge_protection defaults to false>

$ rocketvault vaults update acme-pinned --purge-protection=true
<succeeds -- CanManageVault is satisfied by the vault-scoped vaults:manage
 policy the create path just wrote for this grantee>

$ rocketvault vaults delete acme-pinned
<succeeds -- soft-delete, still counts toward quota>

$ rocketvault vaults purge acme-pinned
Error: vault "acme-pinned" is protected from purge
```

The vault is now permanently soft-deleted, permanently occupies a quota
slot, and cannot be purged by anyone, including an admin —
`PurgeVault`'s `v.PurgeProtection` check (`vault_service.go:737-739`) applies
uniformly to every caller, with no override. This is not permanent data
pollution, though: an admin has a recovery path —
`vaults recover` → `vaults update --purge-protection=false` → `vaults delete`
→ `vaults purge` — since `RecoverVault` and `UpdateVault` are not subject to
the same guard, so the slot can still be freed manually. It is a recoverable
quota nuisance requiring an admin's intervention, not a permanently stuck
vault.

**Root cause**: the create-time guard
(`if quotaBounded && req.PurgeProtection != nil && *req.PurgeProtection`,
`vault_service.go:372`) exists on exactly one of the two write paths for
`purge_protection`. `UpdateVault` applies `req.PurgeProtection` unconditionally
whenever it is non-nil (`vault_service.go:567-569`) — there is no
`quotaBounded` parameter on `UpdateVault` at all, and no analogous check of
any kind. Both `cmd/vaults/update.go` and the HTTP `updateVault` handler
(`api/vault.go`) gate the call on `CanManageVault(ctx, roles, policies,
principalID, target.ID)` — an ordinary vault-scoped authorization check, not
a quota-awareness check. A provisioning grantee holds a genuine, correctly
vault-scoped `vaults:manage` access policy over the vault it created (written
by the very creator-grant transaction release 2 added — `vault_service.go:433-443`),
so `CanManageVault` legitimately returns true for it there. The check that
refuses the grantee at create time has no counterpart asking the same
question at update time.

**Cross-reference**: this predates and is independent of release 2's
narrowing of `CanManageVault`/`CanManageRoleAssignments`
(`docs/release-notes/v4.6.0-narrow-global-vault-manage.md`) — it was
reachable exactly the same way under release 1, since a provisioning
grantee's creator grant (vault-scoped `vaults:manage`) already existed then.
It was found during release 2's code review because that release's own
purge-protection wording fix (`ErrPurgeProtectionNotPermitted`) prompted a
closer look at what the guard actually covers.

**Fix recipe**: give `UpdateVault` the same quota-awareness `CreateVaultProvisioned`
has. The caller already knows whether the principal is quota-bounded
(`authz.CreateRight` is computed at every call site for create; the
equivalent read-only classification — "does this principal hold a
provisioning grant" — is not currently computed for update/delete, and would
need to be, probably via the same `GrantReader` this package already has).
Concretely: thread a `quotaBounded bool` (or the full `CreateRight`) into
`UpdateVault`, and refuse `req.PurgeProtection != nil && *req.PurgeProtection`
with `ErrPurgeProtectionNotPermitted` when `quotaBounded` is true, mirroring
the create-path guard exactly. **Do not** widen the guard to "non-admin" —
that was explicitly ruled out during release 2's review, since it would
incorrectly refuse a global-policy holder (who has no quota to pin and is
not part of this defect) while still needing the precise `quotaBounded`
predicate to close the actual hole.
**Not implemented in release 2**: the branch narrows a global grant's
vault-scoped authority; widening its scope to also patch an unrelated,
pre-existing create/update-path asymmetry would make an already-breaking
release harder to review. Filed here instead, per that release's own note.

**Found**: manually, during code review of release 2
(`docs/release-notes/v4.6.0-narrow-global-vault-manage.md`), while checking
whether "provisioning grantee: refused, always" was actually true of
`purge_protection` — it is true only at create time.

---

### B60 — `SelfPKIProvider`'s JWT signing key can never be stored under Postgres

**Status**: Fixed 2026-09-06, same day it was found (fix recipe option 1: a
real seeded system user). `model.SystemUserID`/`SystemUsername`/`RoleSystem`
added; `db.seedSystemUser` seeds the row idempotently in `SetupSchema`;
`UserRepository.ValidateBootstrapToken` and `.List()` both exclude it
(the bootstrap-token gate counting this row would have permanently blocked
first-admin creation on every fresh install — caught before it shipped).
Verified against a real Postgres container: `rocketvault-rocketvault-1`
starts healthy, `SelfPKIProvider: loaded existing JWT signing key` logs
clean, and `rocketvault users admin --bootstrap-token=...` still succeeds
with the system user row already present.
**Found**: 2026-09-06, while bringing up the docker-compose
`--profile metrics` stack against a fresh Postgres volume
**Severity**: High for the docker-compose/Fly.io/Railway-with-Postgres
deployment path specifically: a completely fresh Postgres-backed instance
with `jwt.key_source: self_pki` cannot start at all. Not reachable on SQLite.
**Files**: `internal/signing/self_pki.go:129,210` (`UserID: uuid.Nil`),
`internal/db/db.go` (every `FOREIGN KEY (user_id) REFERENCES users(id)` on
the `keys` table, no exception for a system-owned key),
`.rocketvault.docker.yaml.tmpl:23-30` (hardcodes `key_source: "self_pki"`
for containers, with a comment stating this is deliberate for *both*
SQLite and Postgres)

**What it is**: `SelfPKIProvider` generates and stores RocketVault's own JWT
signing key as a regular row in the `keys` table, owned by nobody —
`UserID: uuid.Nil` — since it isn't a user-created key. The `keys` table's
schema has no case for that: `user_id` is a plain `FOREIGN KEY ... REFERENCES
users(id)`, so inserting a row with `uuid.Nil` requires a `users` row with
that id to already exist, and none ever does.

On SQLite this insert succeeds anyway — foreign keys aren't enforced by
default in this codebase's SQLite connections, so the dangling reference is
silently accepted. Postgres enforces foreign keys unconditionally, so the
identical code path fails outright:

```
error: pq: insert or update on table "keys" violates foreign key constraint "keys_user_id_fkey"
Error: service container initialization failed: failed to initialize
services: JWT signing provider initialisation failed: SelfPKIProvider init:
store generated key: failed to insert key: pq: insert or update on table
"keys" violates foreign key constraint "keys_user_id_fkey"
```

The container never becomes healthy — the process exits before the HTTP
server ever starts, on the very first boot against an empty Postgres
database, before any user (and so before any real `KeyService`/JWT config
exists to catch this earlier).

**Impact**: any brand-new docker-compose (or Fly.io/Railway with
`RV_DB_DRIVER=postgres`) deployment fails to start, unconditionally, with no
workaround short of switching `jwt.key_source` away from the template's own
documented default. SQLite deployments (the default for a plain `docker run`
and for Railway) are unaffected, which is presumably why this was never
caught before — this is likely the first time a genuinely fresh Postgres
volume was exercised end-to-end with `self_pki` in place.

**Fix recipe**: give system-owned keys a real home instead of a dangling
`uuid.Nil` reference. Two shapes, either works, both dialect-safe:

1. Seed a real "system" user row (fixed id `uuid.Nil` or a dedicated
   sentinel UUID) during `migrateSchema`, with no login credentials and a
   role that can never authenticate — `SelfPKIProvider` then owns a real
   user, no schema change needed.
2. Make `keys.user_id` nullable and drop the FK's `NOT NULL`, giving
   `SelfPKIProvider` a `NULL` user_id for its own key and updating whatever
   `KeyRepository` queries currently assume `user_id` is always present.

Option 1 is smaller and touches no query code; option 2 is more honest about
what a system key actually is. Either way, both SQLite and Postgres dialects
in `internal/db/dialect.go` need the same fix applied identically — this bug
existing at all is exactly the class of dialect-divergence risk the
Postgres-support work was supposed to guard against.

**Implemented**: option 1. `model.SystemUserID` (`"00000000-0000-0000-0000-000000000000"`,
the same value `uuid.Nil` already produces), `model.SystemUsername`
(`"__rocketvault_system__"`) and `model.RoleSystem` (`"system"`, deliberately
excluded from `ValidRoles`) added in `model/user.go`. `db.seedSystemUser`
(`internal/db/db.go`) inserts that row idempotently in `SetupSchema`, right
after `migrateSchema` — a real users-table row, password_hash set to a
syntactically-invalid bcrypt string so no password can ever authenticate it,
same SELECT-then-INSERT idempotency pattern as `seedBootstrapToken`/
`seedDefaultVault`.

The one place this needed a companion fix, not just a seed: `UserRepository.
ValidateBootstrapToken` (`internal/repositories/user_repository.go`) counted
`SELECT COUNT(*) FROM users` to decide whether bootstrap ("no admin exists
yet") is allowed. Seeding a permanent row would have made that count always
≥ 1, permanently disabling first-admin creation on every fresh install —
caught before it shipped, fixed by excluding `model.SystemUserID` from that
count. `UserRepository.List()` excludes it too, so it never appears in a
`users list`. (`internal/health/health.go`'s own `COUNT(*) FROM users` is
purely a diagnostic number in a health payload, never gated on — left as is
rather than plumbing a dialect through `HealthCollector` for cosmetics.)

Verified against a real Postgres container from a clean volume: the
dockerized `rocketvault` service starts healthy, and
`rocketvault users admin --bootstrap-token=...` still succeeds with the
system user row already present.

---

### B63 — `getDeletedKey` lists an entire vault to serve one id

**Status**: Open (deferred 2026-09-06)
**Severity**: Low — performance only, no correctness or authorization defect
**Files**: `api/soft_delete.go` (lines 326-366),
`internal/repositories/key_repository.go`, `internal/services/keys/key_service.go`

`api/soft_delete.go`'s `getDeletedKey` calls `KeyService.ListDeletedKeys` for
the whole vault and linear-scans the result for one key id. It is O(n) in the
vault's soft-deleted key count for a single-item GET.

Root cause: no scoped by-id read of a soft-deleted key exists.
`KeyRepository.Read` filters `deleted_at IS NULL`.

`KeyRepository.ReadDeletedScoped(ctx, id, scope)` (built on `ScopedGet[T]`) now
exists — added 2026-09-25 fixing B64 below. What remains for this ticket:
expose it as `KeyService.GetDeletedKey` and rewire the handler. Still deferred
because the `KeyService` interface fan-out exceeds five files (unchanged by
the B64 fix, which only touched `KeyRepositoryInterface`).

That audit of the unscoped `ReadDeleted` was done on 2026-09-06 and is filed
as B64: the one production caller is safe, but the method still authorizes
nothing on its own.

The measured fan-out, for whoever picks this up: seven files declare or stub a
`ListDeletedKeys` method and would each need a `GetDeletedKey` pass-through —
`internal/services/keys/key_service.go` (interface and implementation),
`internal/services/retry/retry_key_service.go`,
`internal/services/keys/mocks/mock_KeyService.go`, and four hand-rolled test
doubles in `api/keys_crud_test.go`, `api/vault_scoped_keys_certs_test.go`,
`cmd/keys/keys_cmd_test.go` and `cmd/keys/update_test.go`. The four hand-rolled
doubles are the real cost: each must be edited by hand, and a missed one is a
compile break rather than a silent bug.

---

### B64 — `KeyRepository.ReadDeleted` takes no `model.Scope`, so it authorizes nothing

**Status**: Fixed 2026-09-25 (GitHub issue #23)
**Severity**: Low today, High if a second caller appears
**Files**: `internal/repositories/key_repository.go` (lines 41-43, 411-422),
`internal/services/keys/key_service.go` (line 940)

`ReadDeleted(ctx, id)` reads a key by id regardless of soft-deletion state and
takes no `model.Scope`. Scope is the authorization predicate everywhere else in
this codebase — every sibling read (`Read`, `List`) takes one — so this method
returns any key in any vault to any caller that holds its id.

This is the audit B63's entry asked for, now done. There is exactly one
production caller, and it is **safe**: `keyService.DeleteKey` calls the scoped
`keyRepo.Read(ctx, keyID, scope)` first and returns `ErrKeyNotFound` if that
fails, then soft-deletes, then calls `ReadDeleted` on the same already-authorized
id purely to re-read the row's post-delete metadata for its return value. The
unscoped read is covered by the scoped read that precedes it.

Root cause: the method was written as an internal re-read helper for one
call site, but it is exported on `KeyRepositoryInterface`, so nothing stops a
future caller from reaching it without a preceding scoped read. The signature
carries no hint that the caller owes an authorization check.

Why it matters despite being latent: B63's fix recipe proposes a scoped by-id
read of a soft-deleted key. Anyone implementing that who reaches for the
existing `ReadDeleted` instead of adding `ReadDeletedScoped` turns this into a
live cross-vault read on a `GET` handler.

Fix recipe: add `ReadDeletedScoped(ctx, id, scope)` built on `ScopedGet[T]`
(the same one B63 needs), point `DeleteKey` at it, and unexport or delete
`ReadDeleted` so no unscoped path remains. Doing this alongside B63 shares the
work, since both need the same new repository method.

**Fix**: `ReadDeletedScoped(ctx, id, scope)` added to `KeyRepositoryInterface`
and `KeyRepository`, built on `ScopedGet[T]` exactly as the recipe proposed —
same query, scope predicate appended, same "key not found"/"key not found or
access denied" ambiguity `Read` uses for a row outside scope. `DeleteKey`
(`internal/services/keys/key_service.go:940`) now calls it with the same
`scope` it already threads through the preceding `Read`. The old unscoped
`ReadDeleted` was deleted outright (not unexported — it had no in-package
callers left once `DeleteKey` moved off it), so `KeyRepositoryInterface` no
longer exposes any unscoped read path. Updated every implementer: the
mockery-generated `internal/repositories/mocks/mock_KeyRepositoryInterface.go`
(regenerated by hand — this environment's `golangci-lint`/`mockery` combo hits
an unrelated `go1.27.1`/`math/rand/v2` stdlib incompatibility, pre-existing and
not caused by this change) plus six hand-rolled test doubles
(`internal/signing/signing_test.go`, `internal/services/keys/key_soft_delete_test.go`,
`internal/services/certificates/cert_soft_delete_test.go`,
`internal/backup/item_backup_test.go`, `api/backup_item_test.go`,
`internal/services/keys/key_service_extended_test.go`). Added
`TestKeyRepository_ReadDeletedScoped_WrongVaultDenied` to
`internal/repositories/repositories_test.go` to actually exercise the new
cross-vault denial, since B63/B64's analysis was latent and no prior test
covered it. `go build ./...`, `go vet ./...`, and `go test ./...` all pass.
B63 above still needs its own `KeyService`/handler wiring; this fix only
closes the repository-layer gap.

---

### B61 — `vault-webhook delete` reports "deleted" even when nothing was configured

**Status**: Open, found 2026-09-06
**Severity**: Cosmetic — `Delete` is correctly idempotent (returns success,
no error) when a vault has no webhook configured, matching its documented
contract. The defect is purely in the message text, not the behavior.
**Files**: `cmd/vault-webhook/delete.go`

**Symptom**: reproduced live against a scratch instance —
`rocketvault vault-webhook delete --vault webhook-happy`, run a second time
immediately after a first successful delete (config already gone), still
prints:
```
webhook configuration deleted for vault "webhook-happy"
```
An operator re-running the command, or scripting it defensively, has no way
to tell from the output whether it actually removed a config or found
nothing to remove.

**Fix recipe**: have `VaultWebhookService.Delete` report whether a row
existed (e.g. return a `bool` alongside the error, or a typed
`ErrWebhookNotFound`-vs-nil distinction the CLI already imports for `get`),
and have `delete.go` print a different message for the no-op case, e.g. "no
webhook was configured for vault %q" vs. today's single message for both
cases. Mirrors the `get` command's existing `errors.Is(err,
vaultServices.ErrWebhookNotFound)` handling — `delete.go` doesn't do the
equivalent check today because `Delete` doesn't surface the distinction.

**Found**: manual CLI test pass of `vault-webhook set/get/delete`, step 14 of
the happy-path scenario (idempotent double-delete check).

---

### B62 — `vault-webhook get`/`set`/`delete` against an unknown vault name double-wraps the "not found" error

**Status**: Open, found 2026-09-06
**Severity**: Cosmetic — the caller still gets a clear, non-crashing error;
the defect is redundant wording, not a wrong or misleading outcome.
**Files**: `internal/services/vaults/vault_service.go:517` (`getByName`),
`cmd/vaultcli/vault.go:31` (`ResolveVaultID`) — two layers each add their own
"vault %q ... not found" wording around the same error.

**Symptom**: reproduced live —
`rocketvault vault-webhook get --vault does-not-exist-xyz`:
```
Error: vault "does-not-exist-xyz" not found: vault "does-not-exist-xyz": vault not found
```
The vault name and "not found" both appear twice, once from each wrapping
layer.

**Root cause**: `vaultService.getByName` already produces a fully-formed,
name-bearing message — `fmt.Errorf("vault %q: %w", name, ErrVaultNotFound)`,
i.e. `vault "X": vault not found`
(`internal/services/vaults/vault_service.go:517`). `cmd/vaultcli.ResolveVaultID`
then wraps that error a second time with its own name-bearing prefix —
`fmt.Errorf("vault %q not found: %w", name, err)`
(`cmd/vaultcli/vault.go:31`) — without knowing the inner error already said
the same thing. This is shared plumbing every vault-scoped CLI command goes
through, not something specific to `vault-webhook`, which just happened to
be the command under test when this was noticed.

**Fix recipe**: pick one layer to own the message. Either have
`ResolveVaultID` wrap with a generic, name-free prefix (e.g. `"resolve
vault: %w"`, since the inner error already names the vault), or have it
special-case `errors.Is(err, vaultServices.ErrVaultNotFound)` and pass the
inner error through unwrapped. Since this is shared plumbing
(`vaultcli.ResolveVaultID`), the fix is one place, not three.

**Found**: manual CLI test pass of `vault-webhook set/get/delete`, step 15
of the happy-path scenario (`get` against a nonexistent vault name).

---

### B65 — Swallowed scan errors truncated result sets silently

**Status**: Fixed in commits `7032545`, `1873418`
**Severity**: High — silent wrong answers, no error surfaced, security-visible
in the session case
**Files**: `internal/repositories/rotation_repository.go`,
`internal/repositories/session_repository.go`

**Symptom**: four `for rows.Next()` loops responded to a failed `rows.Scan`
with `log.Error(...)` followed by `continue`, and never called `rows.Err()`
afterwards. A driver failure partway through iteration returned a short
result list with a **nil** error, so a caller could not distinguish a
truncated listing from a complete one. `session_repository.go`'s
`GetActiveSessionsByUserID` was the security-visible instance: a user
auditing where their account is signed in could be shown fewer sessions than
actually existed.

**Root cause**: the same swallow-and-continue pattern already fixed once in
`versioning_repository.go` by commit `6cd6d52` ("no longer swallows scan
errors") was never applied to `rotation_repository.go`'s three loops (lines
269, 318, 430 at the time of the audit) or to `session_repository.go`'s one.

**What was fixed**: each loop now returns the scan error immediately instead
of logging and continuing, and each checks `rows.Err()` after the loop exits.
See `docs/superpowers/specs/2026-09-07-repository-layer-hardening-design.md`
§ F1 for the full analysis.

**Commit note**: `398f56b` does **not** belong on this list — it is a pure
F6 fix (B66), touching only `scanRotationPolicyRow`'s single-row scan and
`List`'s scan closure, neither of which is a `continue`-on-failure loop.
Plans 01 and 02 split this package's fixes by *file*, not by finding,
because F1 and F6 occur in the same loop bodies — so `7032545` (rotation)
and `1873418` (session) each mix F1's `rows.Err()`/error-return fix with
some F6 parse-error fixes in the same hunks, and a reader tracing one
finding to one commit will not find a clean one-to-one correspondence.

---

### B66 — Discarded `uuid.Parse` errors silently yielded `uuid.Nil`

**Status**: Fixed in commits `398f56b`, `7032545`, `acd10c6`, `7fa2e16`, `e4fde67`
**Severity**: Medium-high — silent substitution of a privileged sentinel
value for corrupt data
**Files**: `internal/repositories/rotation_repository.go` (21 sites),
`internal/repositories/versioning_repository.go` (9 sites),
`internal/repositories/certificate_policy_repository.go` (6 sites)

**Symptom**: 36 sites across the three files assigned a parsed UUID while
discarding the parse error, e.g. `policy.VaultID, _ = uuid.Parse(vaultID)`. A
malformed or empty UUID column therefore produced `uuid.Nil` rather than an
error, with no indication anything had gone wrong. (21 + 9 + 6 = 36; the
design doc's prose originally said "35," an arithmetic error against its own
correct per-file breakdown, corrected there and here.)

**Root cause**: `uuid.Nil` is not an inert value in this codebase — it is the
`auditActor` constant for key and certificate lifecycle operations, and
`model.NewAdminScope(uuid.Nil)` is a real, privileged scope. Every other
scanner in the package (`scanKeyRow`, `scanCertificateRow`, `scanSecretRow`,
`parseRoleAssignmentIDs`) already returned a wrapped parse error; these three
files were the outliers.

**What was fixed**: all 36 sites now return a wrapped parse error instead of
discarding it. See the design doc's § F6 for the full site list; note this
is the one fix in this effort that changes behavior on data that exists
today — a deployed database with a malformed UUID in one of these columns
now surfaces an error on read where it previously produced a silent
`uuid.Nil`, which is the intended outcome of the fix.

**Commit note**: `1873418`'s commit message says "Closes the last of the 35
discarded-uuid.Parse sites" — that count was wrong at the time (see above);
the commit itself is not being amended for a message-only number, since a
landed commit's history is not worth rewriting for this. `398f56b` and
`7032545` each mix this finding's fixes with F1 fixes (B65) in the same
loop bodies, per that entry's note — this package's plans were split by
file, not by finding.

---

### B67 — `CertificateRepository.ListAll`'s duplicated SELECT list panicked on a malformed UUID

**Status**: Fixed in commits `213a751`, `d1fad5a`
**Severity**: Medium-high — a live panic vector plus the structural cause of
a bug this codebase had already been bitten by once
**Files**: `internal/repositories/certificate_repository.go`

**Symptom**: `ListAll` (used by the certificate renewal scheduler) scanned
rows with `uuid.MustParse` for `id`, `user_id`, and `key_id`. A malformed
UUID in any of those columns panicked the renewal scheduler's goroutine
rather than returning an error.

**Root cause**: `ListAll` carried a second, hand-written column list parallel
to the canonical `certificateColumns` const, rather than reusing the shared
`scanCertificateRow`. That hand-written list also omitted `vault_id`,
`deleted_at`, and `purge_protection` — the same shape of defect previously
documented as the cause of an earlier bug where `keyColumns` and
`certificateColumns` omitted `deleted_at`/`purge_protection` and made every
`List()` return both fields zero-valued.

The missing `vault_id` was **latent, not live**: `CheckAndRenewCertificates`
(`renewal_service.go:86`) passes `model.NewAdminScope(cert.UserID)`, which
applies no vault predicate, so the zero-valued `VaultID` never reached a
query. The live defect was strictly the `uuid.MustParse` panic.

**What was fixed**: `ListAll` now routes through the same shared column list
and `scanCertificateRow` every other certificate read uses, so it returns a
wrapped parse error instead of panicking and no longer omits any column.
`d1fad5a` adds a guard test against a second column list reappearing. See the
design doc's § F2.

---

### B68 — Error identity by string comparison, and bare errors missing the `ErrNotFound` sentinel

**Status**: Fixed in commits `5b1f54a`, `3107a85`, `c574c42`
**Severity**: Medium — no misbehavior at the time, but a sharp edge that
turns an innocuous edit into a silent behavior change
**Files**: `internal/repositories/role_assignment_repository.go`,
`internal/repositories/user_repository.go`,
`internal/repositories/access_policy_repository.go`,
`internal/repositories/oauth2_client_repository.go`

**Symptom**: `role_assignment_repository.go`'s `FindByTuple` identified "no
such assignment" by comparing `err.Error()` to the literal string `"role
assignment not found"` — rewording the message in `scanRoleAssignment` would
silently flip `FindByTuple` from `(nil, nil)` to an error, on an
authorization-adjacent path. Several sites (the consequential one being
`user_repository.go`'s `ReadByExternalSubject`, which OIDC's
`FindOrCreateExternalUser` needs to distinguish "no such user, create one"
from "the database is broken") returned a bare `fmt.Errorf("... not
found")` without wrapping `ErrNotFound`, so `errors.Is` could never work
against them. Three sites (`access_policy_repository.go:198`,
`oauth2_client_repository.go:110`, `role_assignment_repository.go:149`)
compared `err == sql.ErrNoRows` directly rather than `errors.Is`, which only
worked because nothing wrapped the error yet.

**Root cause**: `errors.go`'s `ErrNotFound` sentinel existed but was not
consistently used — see that file's own (now-corrected) comment, which
pointed at `FindByTuple` as the standing example of the pattern it exists to
replace.

**What was fixed**: `FindByTuple` and the other bare-error sites now wrap
`ErrNotFound` (message text preserved as a prefix, per the design doc's
"error messages are extended, never replaced" rule, so existing
`assert.Contains` service-layer tests keep passing), and the three
`== sql.ErrNoRows` comparisons became `errors.Is`. `internal/repositories/errors.go`'s
comment was corrected to stop citing `FindByTuple` as a still-open example
(this task). See the design doc's § F3.

---

### B69 — `executeWithMetrics` copy-pasted five times, ignoring the configured slow-query threshold

**Status**: Fixed in commits `9461d81`, `5aa1df2`, `897610f`
**Severity**: Medium — observability that misleads under exactly the
conditions it was configured to help with
**Files**: `internal/repositories/key_repository.go`,
`internal/repositories/certificate_repository.go`,
`internal/repositories/secret_repository.go`,
`internal/repositories/user_repository.go`,
`internal/repositories/session_repository.go`, `internal/repositories/metrics.go`
(new), `internal/db/db.go`

**Symptom**: five separate `executeWithMetrics` definitions each hardcoded
`100 * time.Millisecond` as the slow-query cutoff, while
`db.RecordQueryExecution` — which every one of them also called — applied
the *configured* `monitoring.slow_query_threshold`. Once an operator tuned
that setting away from its 100ms default, the `SlowQueryCount` metric and
the "slow query" log warnings disagreed about which queries were slow.
Separately, `SecretRepository.Update` and `SecretRepository.Delete` were not
wrapped in metrics at all, while their key and certificate equivalents were.

**Correction to the original finding**: an earlier draft of the design
assumed all five copies were identical; they were not.
`SessionRepository`'s diverged in three ways — it never called
`db.RecordQueryExecution` at all (so session queries had never been counted
in `QueryCount`/`TotalQueryTime`/`SlowQueryCount`), it logged through the
injected `r.logger` rather than the package-level `logrus` the other four
used, and it emitted a different message plus a `"threshold": 100` field.

**What was fixed**: a single package-level `withMetrics(table, operation,
fn)` helper in the new `internal/repositories/metrics.go`, taking its
threshold from a new exported `db.SlowQueryThreshold()` accessor (wrapping
the existing unexported `getSlowQueryThreshold`) so the metric and the log
warnings agree at any configured value. All five `executeWithMetrics`
methods became one-line delegations to it, and `SecretRepository.Update`/
`Delete` were instrumented for the first time (`897610f`).

**Accepted behavior change**: consolidating the session copy means session
queries are now counted in the shared `QueryCount`/`SlowQueryCount` metrics
for the first time — a step change in those numbers on deployment, and the
correct outcome, since their prior absence was under-reporting. Session's
distinct log message and `"threshold": 100` field are gone, replaced by the
shared `"Slow database query detected"` message; a log-based alert matching
the old string stops matching. Session's slow-query warning now also routes
through the unconfigured global `logrus` (stderr, no rotation) rather than
the configured, rotated injected logger `r.logger` used to write to — a
known limitation accepted rather than plumbing a logger through the
package-level helper, which the design deliberately keeps free of
per-repository state (see the design doc's "shared metrics helper is
package-level, not a struct field" note). See § F4 for the full analysis.

---

### B70 — Tag rows orphaned on purge and on secret delete

**Status**: Fixed in commits `947fdc4`, `1442c2d`
**Severity**: Medium — unbounded row growth and a stale-data path; not a
disclosure risk, since orphaned tags are only reachable by an item ID that no
longer resolves
**Files**: `internal/repositories/item_lifecycle.go`,
`internal/repositories/secret_repository.go`,
`internal/repositories/key_repository.go`,
`internal/repositories/certificate_repository.go`

**Symptom**: `secret_tags`, `key_tags`, and `certificate_tags` each declare
`FOREIGN KEY (...) REFERENCES ... ON DELETE CASCADE`
(`internal/db/db.go` lines 437-443, 479-485, 589-595), but SQLite runs with
the `foreign_keys` pragma off project-wide, so the declared cascade never
fires. `item_lifecycle.go`'s `purgeItem` and `purgeVaultContents` issued a
bare `DELETE FROM <table> WHERE id = ?`, stranding every tag row of the
purged item(s) — for secrets, keys, and certificates alike.
`SecretRepository.Delete` deleted the secret row without touching
`secret_tags` at all, unlike `KeyRepository.Delete` and
`CertificateRepository.Delete`, which already deleted their tag rows
explicitly inside a transaction. Because tag primary keys are `(item_id,
tag)`, a purged-then-recreated item that reused an ID would also inherit the
dead tags.

**Root cause**: this is the same class of defect the existing
`RoleAssignmentRepository.DeleteByVault`/`AccessPolicyRepository.DeleteByVault`/
webhook cleaner exist to work around — SQLite's `foreign_keys` pragma being
off means every `ON DELETE CASCADE` in the schema is decorative and each
dependent table needs its own explicit cleanup.

**What was fixed**: `itemLifecycleConfig` (`947fdc4`) learned the tag table
and its foreign-key column, so `purgeItem` and `purgeVaultContents` now
delete tag rows before the item/vault-contents row. `1442c2d` then collapsed
`KeyRepository.Delete` and `CertificateRepository.Delete` — which differed
only in table names and log labels — into a shared `deleteItemWithTags`, and
`SecretRepository.Delete` adopted the same helper, gaining the tag cleanup
it was missing. See § F5.

**Update (2026-09-07 final review)**: the "known limitation" originally
recorded here rested on a false premise — that `purgeItem` "cannot know
whether it already holds a transaction" because it receives `ex db.DBTX`.
Verified false: all three call sites (`key_repository.go:547`,
`secret_repository.go:404`, `certificate_repository.go:618`) pass `r.db`, a
plain connection; no `PurgeKeyTx`/`PurgeSecretTx`/`PurgeCertificateTx` exists
or ever did. `purgeItem` now takes `conn db.DB` instead of `ex db.DBTX` and
opens its own transaction (`conn.BeginTx` / `defer tx.Rollback()` /
`tx.Commit()`) around the tag delete and the item delete, mirroring
`deleteItemWithTags` in the same file. The status checks (`deletedAt == nil`,
`purgeProtection`) still run against `conn` before any write. `purgeItem` is
transactional; the limitation below no longer applies.

---

### B71 — Repository-layer hardening: recorded non-goals and other accepted limitations

**Status**: Not bugs — deliberately out of scope or accepted as-is, recorded
2026-09-07 so they are not rediscovered from scratch
**Severity**: N/A
**Files**: `internal/repositories/secret_repository.go`,
`internal/repositories/rotation_repository.go` (`RemoveFromSecret`),
`internal/repositories/tag_orphan_test.go`

Found during the repository-layer hardening effort
(`docs/superpowers/specs/2026-09-07-repository-layer-hardening-design.md`)
but excluded from it. Each non-goal below needs an exported-interface
change, which that effort's scope decision ruled out entirely (see the
design doc's "Scope decision" line):

- Five dead stubs on `SecretRepositoryInterface` (`ExportSecrets`,
  `ImportSecrets`, `GetVersions`, `GetVersion`, `GetLatestVersion`) return
  "moved to X service" errors and exist only to satisfy the interface.
- `SecretFilter.Tags` is accepted by `List` and silently ignored, while
  `KeyFilter.Tags` and `CertificateFilter.Tags` are honored.
- `SecretFilter` is still declared in `internal/repositories` while
  `KeyFilter`, `CertificateFilter`, and `AuditFilter` moved to
  `model/filters.go`.
- `SecretRepository.List` does not load tags; the key and certificate
  equivalents batch-load them.

**F4's "related inconsistency" was only half-closed (2026-09-07 final
review).** The design spec's F4 section noted `SecretRepository.Update` and
`SecretRepository.Delete` were both uninstrumented while their key/certificate
equivalents were wrapped in metrics. Commit `897610f` instrumented `Update`.
`Delete` then adopted `deleteItemWithTags` (`1442c2d`), whose `cfg.wrap` for
secret is `passthroughWrap` — so `Delete` is still uninstrumented. The old
divergence (secret vs key/cert) has been replaced by a new one *inside*
`SecretRepository` itself: `Update` records query metrics, `Delete` does not.
Closing this properly means changing secret's `crud()` to pass
`r.executeWithMetrics` instead of `passthroughWrap` — but that also
instruments secret's `SoftDelete`, `Recover`, `PurgeSecret`, and the
vault-cascade operations, all of which currently share the same `cfg.wrap`.
That is a wider behavior change than this review authorized, so it is
recorded here rather than applied.

One further item was accepted as-is rather than fixed, noted in its own B69
entry above and repeated here for a single point of reference: session's
slow-query warning logs through the unconfigured global `logrus` instead of
the rotated injected logger (B69).

`purgeItem`'s tags-then-item write pair was listed here as accepted-as-is
non-atomicity; it no longer is. The premise behind accepting it was false
(see B70's "Update" paragraph) and the fix landed in the 2026-09-07 final
review — `purgeItem` is transactional.

One item found during the sweep but outside every plan's file list:
`rotation_repository.go`'s `RemoveFromSecret` still returns a bare
`"policy assignment not found"` without the `ErrNotFound` sentinel B68 added
elsewhere in the package.

Test coverage note: `tag_orphan_test.go` (added by `947fdc4`) covers keys
only; secret and certificate tag-foreign-key correctness is exercised only
incidentally, by pre-existing purge tests that would fail with "no such
column" if a column name were wrong, not by a dedicated orphan-row
assertion for those two types.

---

## Deferred Refactors

Both items formerly tracked here (H3, M2) were re-investigated on 2026-08-14 and
found to be much smaller in scope than originally estimated — see git history for
each item's exact commit. Neither was actually large enough to warrant deferral;
both are now fixed. Kept below for history.

### H3 — Unexported global `globalDB *sql.DB` in `internal/db/db.go` — FIXED

**Tracked since**: 2026-04-30
**Status**: Fixed in commit `484a4ff`
**Severity**: Low (architectural) — not a runtime bug; no data loss risk

**Original claim vs. reality**: The original entry described an *exported*
`var DB *sql.DB` needing "20+ call sites across the codebase" threaded through
DI. Re-investigation found the actual variable, `globalDB`, was already
unexported and had exactly 3 readers, all inside `internal/db/db.go` itself
(`GetPerformanceMetrics`, `GetConnectionPoolStats`, `HealthCheck`) — every
external consumer already went through `DBRepository.GetDB()`/`d.db` via proper
DI. The "20+" figure didn't correspond to anything in the codebase.

**Fix applied**:
1. `GetConnectionPoolStats` and `HealthCheck` became methods on `*DBRepository`,
   reading `d.db` instead of the global.
2. `GetPerformanceMetrics` took a `conn *sql.DB` parameter instead of reading the
   global, so its (previously unused-in-most-callers) `ConnectionStats` field is
   now supplied explicitly by each caller — `hc.db` in `internal/health/health.go`,
   and `database.GetDB()` in `bootstrap/bootstrap.go`'s `dbPerformanceSnapshot`
   (which now returns a closure over the repository instead of being a bare
   package function, since it feeds the `rocketvault_db_*` Prometheus gauges via
   `metrics.MetricsScheduler` and genuinely needs live connection-pool stats).
3. `globalDB` and its assignment in `InitializeDB()` were deleted.
4. All ~30 test references to `globalDB` (across `db_test.go`, `db_edge_test.go`,
   `db_more_test.go`, `tags_test.go`) were updated to use the already-initialized
   repository instance in scope instead.

---

### M2 — `Context.Claims` was `jwt.MapClaims` instead of a typed struct — FIXED

**Tracked since**: 2026-04-30
**Status**: Fixed in commit `9898477`
**Severity**: Low (code quality) — no runtime bug found; see below

**Original claim vs. reality**: The original entry said this "produces obscure
panics when the JWT is malformed or a field is missing." Re-investigation found
no reachable path that panics: `Claims` is populated with all three keys, always,
inside `ApiSessionRequired`; `ApiHandler` (public routes) never touches it; and
invalid JWTs 401 before `Context` is even built. The fix recipe's proposed
`internal/domain/user.go`/`JWTClaims` also didn't match the codebase — no
`internal/domain` package exists, and `model.Claims` (the actual typed
upstream struct) has `UserID uuid.UUID`, not a string, so reusing it directly
would have required a wider type change than the untyped map warranted.

**Fix applied**: Added a purpose-built value type in `api/context.go`:
```go
type RequestClaims struct {
    UserID   string
    Username string
    Role     string
}
```
Value type (not a pointer), so a zero-value `Context` — as `ApiHandler` leaves it
for public routes — still yields safe empty-string reads instead of a
nil-pointer panic. `Context.Claims` changed from `jwt.MapClaims` to
`RequestClaims`; `ApiSessionRequired` now assigns the struct literal directly.
All ~37 call sites across 11 `api/*.go` files were converted from
`c.Claims["user_id"].(string)`/`c.Claims["role"].(string)` type assertions
(with their `ok`/`_` boilerplate) to plain `c.Claims.UserID`/`c.Claims.Role`
field access, and ~20 test files that built `Context{Claims: jwt.MapClaims{...}}`
were converted to `RequestClaims{...}` (including two test-only helper functions,
`newUserCtx`/`newCertCtx`, whose parameter types changed accordingly).

One genuine, intentional behavior change fell out of this: the old map-based
`ok` check let a handful of sites distinguish "claim key absent" (500 internal
error) from "claim present but invalid" (400 bad param) — a distinction that
was already unreachable in production per the investigation above. With a
plain string field there's no "absent" state to distinguish, so
`getUserID` (`api/backup_item.go`), `listUserSessions`, and `revokeAllSessions`
(`api/users.go`) now return 400 uniformly via `uuid.Parse` for both cases. Three
tests were updated to match (`TestGetUserID_MissingClaim_SetsErr`,
`TestListUserSessions_MissingUserIDInClaims_Returns400`,
`TestRevokeAllSessions_MissingUserID_Returns400`).

---

### F1 — api/context.go bypasses the service layer with three repository accessors

**Status**: Resolved (Plan A Tasks 1-6, committed 2026-08-14/2026-08-15)
**Severity**: Low (architectural) — no runtime bug; DDD pattern violation

**What was fixed**: `api/context.go` originally exposed three raw repository accessor methods:
- `sessionRepo()` → routed through `AuthenticationService.ListActiveSessions` (Task 1-2)
- `certPolicyRepo()` → routed through `CertificateService` policy methods (Task 3-4)
- `keyRotationPolicyRepo()` → routed through `KeyService` policy methods (Task 5-6)

The three accessors this plan targeted (`sessionRepo()`, `certPolicyRepo()`, `keyRotationPolicyRepo()`) are gone from `api/context.go`. `api/`'s remaining `internal/repositories` imports are filter value types passed to service methods (`api/audit.go`, `api/keys.go`, `api/certificates.go`), not repository access. Two direct container-repository reads remain outside this plan's scope: `api/keys.go:620` and `api/role_assignments.go:32` — not regressions, just not targeted by this plan.

**Plan reference**: `.claude/context-followup-cleanup-plan.md`, Plan A Tasks 1-6.

---

### I1 — `retry.service_operations` is intentionally unwired

**Status**: Not a bug — intentional design decision (investigated 2026-08-14)
**Severity**: N/A — architectural intention, not an issue
**Files**: `internal/services/retry/retry_service.go`, `config.go`, `CLAUDE.md`

**Root cause of confusion**: Earlier documentation incorrectly labeled
`retry.service_operations` as a "dead stub... not yet read by code." This was
inaccurate — `retry.service_operations` is fully parsed, has complete test
coverage, and provides a real API surface (`RetryService.ExecuteServiceOperation`
and `GetServiceOperationsPolicy`). It simply has no production callers at this time.

**Investigation findings**:
1. **HSM/PKCS#11 key operations**: Investigated as a candidate for service-operation
   retry (connection timeouts, transient remote-call failures). Ruled out: this
   codebase only supports SoftHSM2, a local shared library, so connection-refused
   and timeout failure modes don't realistically apply to the cryptographic tier.
2. **Background schedulers**: Investigated certificate renewal, soft-delete purge,
   and secret rotation as candidates. Ruled out: all are pure local DB/SQL work with
   zero network calls, so they fit `database` retry instead.

**Decision**: Keep `retry.service_operations` as intentional forward-looking
scaffolding for a hypothetical future feature (e.g., a cloud HSM backend, ACME-based
certificate issuer, or remote KMS) that would genuinely need a distinct retry tier
with different failure modes. The API exists, is tested, and is ready to be wired if
such a feature lands. No technical debt or risk — harmless and deliberate.

**Notes**:
- `ExecuteServiceOperation` and `GetServiceOperationsPolicy` in `retry_service.go`
  have accurate doc comments (no changes needed).
- `CLAUDE.md`'s "Configuration" section incorrectly listed this as a dead stub;
  corrected 2026-08-15 to remove `retry.service_operations` from the dead-stub list
  and added a clarifying note about intentional unwiring.

---

### F2 — Key-version repository queries carried a `user_id` filter that authorized nothing

**Status**: Fixed 2026-08-20 (commits `746bf91`, `44334b5`).
**Severity**: Low (architectural) — no runtime bug; the predicate could
never fail, but its presence as an apparent authorization check enabled the
ambiguity behind B28.
**Files**: `internal/repositories/key_repository.go`,
`internal/repositories/key_versions_test.go`,
`internal/services/keys/key_service.go`,
`internal/services/keys/crypto_service.go`,
`internal/backup/item_backup.go`.

**What it was**: `KeyRepository`'s five version methods — `ListVersions`,
`ReadVersionValue`, `GetVersion`, `ListVersionRecords`, `CurrentVersion` —
each took a `userID uuid.UUID` and filtered on a joined `keys.user_id`.
`ReadVersionValue` and `GetVersion` each additionally fell back to a second,
implicit-version-1 query directly against `keys` (for a never-rotated key
with zero `key_versions` rows), and that fallback query carried the same
`user_id` predicate.

**Why it authorized nothing**: all five methods are reachable only after
the caller has already read the parent key through a scoped `Read` (which
applies the real vault predicate), and every call site then passed *that
key's own owner ID* back in — never the caller's own. The predicate was
therefore satisfied by construction on every code path and could not fail,
while still reading like an access control.

**Why it was worth removing**: a parameter that looks like an authorization
control but is really "pass back the owner ID you just read" gives no
signal when it is passed the wrong value. B28 is exactly that bug:
`ItemBackupService.BackupKey` passed the *caller's* ID into
`ListVersionRecords`, which was correct only while an upstream ownership
check guaranteed caller == owner. Once that ownership check was slated for
removal to close a real Azure-parity gap, the argument would have silently
become wrong, and a non-owning caller's backup would have returned zero
version rows — dropping a rotated key's history with no error. B28's fix
(2026-08-19) worked around this by switching that one call site to pass
`key.UserID` instead; this refactor removes the parameter (and the
ambiguity) everywhere.

**Fix**: the `userID` parameter and its `user_id` predicate were dropped
from all five methods (`746bf91` for `ReadVersionValue`/
`ListVersionRecords`, `44334b5` for `ListVersions`/`GetVersion`/
`CurrentVersion`, the latter also fixing a third `ListVersions` call site in
`KeyService.RotateKey` that the plan's caller table had missed).
`CurrentVersion` also dropped its `LEFT JOIN keys k` entirely (corrected
during final review, 2026-08-20): the join was never load-bearing — an
ungrouped aggregate query always returns exactly one row regardless of join
type or how many rows match, so `COALESCE(MAX(version), 1)` against
`key_versions` alone already supplies the never-rotated fallback of `1`
without any join. The new contract matches the pre-existing
`SecretVersionRepositoryInterface`
(`internal/repositories/versioning_repository.go:18-28`), which has never
taken a user or scope parameter on any method, for the same reason: the
caller's scoped read of the parent secret is the only enforcement point.
`TestKeyVersions_ReadVersionValue_WrongOwner`, which asserted the retired
filter, was deleted — the argument it exercised no longer exists.

**Pinned by**: `TestVersionQueries_NotFilteredByOwner`,
`TestVersionMetadataQueries_NotFilteredByOwner`,
`TestCurrentVersion_NeverRotatedKeyStillReturnsOne`
(`internal/repositories/key_versions_test.go`).

---

### F3 — Item restore is non-atomic across its parent write, purge-protection write, and version replay — FIXED

**Status**: Fixed 2026-08-22
**Severity**: Low — a failure partway left a partial restore, not corrupt
data; the caller got an error rather than a false success, and the residue
was cleanable on all three paths. (It was *not* cleanable for keys until
2026-08-20; see the ordering table below.)
**Files**: `internal/backup/item_backup.go`,
`internal/repositories/secret_repository.go`,
`internal/repositories/versioning_repository.go`,
`internal/repositories/key_repository.go`,
`internal/repositories/certificate_repository.go`,
`internal/container/service_container.go`,
`internal/backup/item_backup_atomicity_test.go`

**What it is**: `RestoreKey`, `RestoreSecret`, and `RestoreCertificate` each
perform their work as separate, unwrapped repository calls, with no
transaction spanning them. A failure partway through — for example, the
parent row is created but the third of five version replays fails — leaves a
partial restore under the newly minted ID, with no automatic cleanup.

The write order differs per path, and the difference decides whether the
residue is cleanable (verified against `internal/backup/item_backup.go`,
2026-08-20):

| Path | Write order | Residue after a failed replay |
|---|---|---|
| `RestoreSecret` | `Create` → `CreateVersion`×N → `SetPurgeProtection` | partial row, not purge-protected — deletable |
| `RestoreKey` | `Create` → `CreateVersion`×N → `SetPurgeProtection` | partial row, not purge-protected — deletable |
| `RestoreCertificate` | `Create` → `SetPurgeProtection` (no version replay) | one write after `Create`; narrow window |

Versions-before-protection is the deliberate order on both replaying paths. F7
of the 2026-08-20 secret-backup-version-history pass established it for
`RestoreSecret`, so a failed replay could not strand a purge-protected row.

**`RestoreKey` was fixed the same way on 2026-08-20**, having been missed by
F7. Before that swap, a failed `CreateVersion` left the key row already
purge-protected, and `KeyRepository.PurgeKey` refuses to delete a protected key
(`ErrKeyPurgeProtected`, `internal/repositories/key_repository.go:634-637`) —
so the partial restore could not be cleaned up until someone cleared purge
protection by hand. Pinned by
`TestRestoreKey_FailedVersionReplayLeavesNoPurgeProtectedOrphan`.

That fix also exposed a stub-fidelity gap worth remembering: `stubKeyRepo.Create`
persisted the caller's `PurgeProtection` flag, while the real
`KeyRepository.Create` omits `purge_protection` from its INSERT column list
entirely. A restored key looked protected either way, so the stub could not
have caught this class of ordering bug. The stub now mirrors the INSERT, and
fixtures apply protection through `SetPurgeProtection`, as production does.

**What was fixed**: a unit of work is now threaded through the repository
layer, exactly as this entry's own "why it is deferred" reasoning called for.
`SecretRepository`, `KeyRepository`, `CertificateRepository`, and
`secretVersionRepository`'s `Create`/`CreateVersion`/`SetPurgeProtection`
methods were each split into a private `ex db.DBTX`-parameterized helper,
their existing public method (unchanged behavior, passes its own `r.db`),
and a new `*Tx`-suffixed exported method (`CreateTx`, `CreateVersionTx`,
`SetPurgeProtectionTx`) that runs against a caller-supplied executor
instead — mirroring the `ReadByIDTx`/`SoftDeleteTx`/`RecoverTx` pattern
`VaultService`/`VaultRepository` already established for the same problem
(see `internal/services/vaults/vault_service.go`'s `txCapableVaultRepo`).
The Tx-scoped methods live only on the concrete repository structs, not on
the exported `*RepositoryInterface` types, so adding them did not ripple to
any existing mock or test double implementing those interfaces.

`ItemBackupService` gained the identical `TxBeginner`/`SetTxBeginner`/
`withTx` shape `VaultService` already uses, plus `txCapableSecretRepo`/
`txCapableSecretVersionRepo`/`txCapableKeyRepo`/`txCapableCertRepo` type-
assertion interfaces to detect the capability. `RestoreSecret`/`RestoreKey`/
`RestoreCertificate` each try the transactional path first (when a
`TxBeginner` is set and the injected repos support it) and fall back to the
original non-transactional sequence otherwise — so a caller that never
wires up a `TxBeginner` (every pre-existing test in this package, until the
new atomicity tests) keeps exercising the exact old behavior, unchanged.
`internal/container/service_container.go` wires the real
`ItemBackupService.SetTxBeginner(c.conn)`, mirroring
`vaultService.SetTxBeginner(c.conn)` immediately above it — this is the only
change on the production code path that matters: the DI container now hands
`ItemBackupService` a real transaction beginner, same as it already did for
`VaultService`.

The versions-before-purge-protection write order inside each `Restore*` is
unchanged — it no longer matters for correctness on the transactional path
(a version-replay failure now rolls back the `Create` too), but was kept
identical on purpose so the two paths stay trivially comparable, and so the
non-transactional fallback's already-established, already-tested guarantee
(a failed replay leaves an unprotected, purgeable partial row, never a
stranded protected orphan) is preserved exactly for any caller that still
takes that path.

**Test**: `TestRestoreSecret_TxBeginnerSet_FailurePartwayRollsBackEverything`
proves, against a real in-memory SQLite database (not a mock), that a
version-replay failure on the transactional path leaves zero rows behind —
neither the secret nor the one version that succeeded before the injected
failure. `TestRestoreSecret_NoTxBeginner_FailurePartwayLeavesDocumentedPartialRestore`
proves the non-transactional fallback still leaves exactly the documented
partial restore (one secret row, one version row) with the identical failure
injected, unchanged by the transactional path's existence.
`TestRestoreSecret_TxBeginnerSet_SuccessCommitsSecretAndAllVersions` proves
the happy path still commits everything correctly under the new wiring, not
just that failures roll back. All three
(`internal/backup/item_backup_atomicity_test.go`) use a `failingVersionRepo`
wrapper around the *real* `secretVersionRepository` — deterministically
failing on a chosen call while delegating every other call to the real
repository — rather than a hand-written stub, so a genuine wiring bug in the
Tx-scoped methods could not hide behind a stub that never exercised them.

**Verified**: `db.DB` does expose `BeginTx` (`internal/db/conn.go:14`), and
several repositories already use it for their own atomic multi-statement
writes (e.g. `internal/repositories/key_repository.go:321`,
`internal/repositories/certificate_repository.go:134`,
`internal/repositories/user_repository.go:238`, `internal/db/tags.go:50`).
`KeyRepository.Create`/`CertificateRepository.Create` already opened their
own inner transaction for the row+tags pair before this fix; their new
`CreateTx` variants do NOT open a second, nested one — they execute directly
against the caller-supplied `ex` (already a transaction the outer
`ItemBackupService.withTx` owns), since `database/sql` has no nested-
transaction primitive and none is needed once the outer transaction already
covers the whole sequence. The full-database restore
(`internal/backup/backup.go`, `Manager.RestoreBackup`) remains a separate,
already-transactional code path (a raw `*sql.DB` and stdlib `Begin()`, not
`db.DB.BeginTx()`) — untouched by this fix and not conflated with it.

**Candidate fix (not implemented)**: give `ItemBackupService` a
transaction-scoped variant of the repository methods it needs — either a
`WithTx(*db.Tx)` factory on each repository interface, or a narrower
unit-of-work abstraction passed into `RestoreSecret`/`RestoreKey` — so the
three (or more) writes per restore commit or roll back together.

## MCP Server: Known Deferrals

Two items decided deliberately during the `feat/mcp-server` branch (2026-08-24)
and recorded here rather than left implicit. Neither is a defect in that work.

### D-MCP1: No CLI command to create a service account

`cmd/` has no `service-accounts` group; the capability exists only as
`POST /api/v1/service-accounts` (`api/oauth2.go`). The MCP server's
recommended production posture requires a service account, so setting it up
runs through `curl` — documented that way in `docs/mcp-server.md`.

**Impact**: friction on the recommended path, not a security gap.
**Fix**: add a `rocketvault service-accounts create` command.
**Deferred because**: out of scope for the MCP work, which deliberately added
no new API surface.

### D-MCP2: `query_audit_log` requires a global admin principal

`GET /api/v1/audit/logs` gates on the global admin role (`api/audit.go:68`),
not a data action, so no per-vault grant unlocks it. An MCP server running as
a least-privilege service account gets 403 from that tool every time.

**Impact**: audit querying and least privilege are mutually exclusive through
MCP. Both the tool's error and the runbook say so.
**Fix**: a `Microsoft.KeyVault/vaults/audit/read` data action would let this be
granted per vault.
**Deferred because**: changing the audit route's authorization is a server
change with its own security review, well beyond this branch.
