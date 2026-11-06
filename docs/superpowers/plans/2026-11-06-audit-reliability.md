# Audit Reliability Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Critical operations never succeed without an audit record, and the audit hash chain never resets or forks across replicas.

**Architecture:** One `AppendChained` repository call locks an `audit_chain_head` row, reads DB time, lets the service build a hashed row for the next `seq`, inserts it and advances the head in one transaction. `RecordCritical` returns that error; `RecordEvent` swallows and counts it. Critical call sites run through a `WithCritical` wrapper that writes an `attempt` row first and aborts if that write fails.

**Tech Stack:** Go 1.24, `database/sql` via `internal/db` (`Conn`, `Tx`, `Dialect`), SQLite and Postgres, testify, Prometheus (`internal/metrics`), testcontainers for Postgres integration tests.

**Spec:** `docs/superpowers/specs/2026-11-06-audit-reliability-design.md` (intent: `docs/superpowers/intents/2026-11-06-audit-reliability.md`).

## Global Constraints

- Failed critical write returns a generic 5xx with body text `audit unavailable`; the cause stays in server logs only.
- Hash chain column stays named `prev_hash` (it stores the row's own hash). No rename.
- `seq BIGINT` on `audit_logs` with a unique index created in `migrateSchema` after the `ALTER`; old rows keep `seq NULL`.
- `audit_chain_head (id INT PRIMARY KEY CHECK (id = 1), last_seq BIGINT NOT NULL, last_hash TEXT NOT NULL)`, seeded with `INSERT ... ON CONFLICT DO NOTHING` from the newest legacy row by `(timestamp, id)`, else `last_seq = 0`, `last_hash = ""`.
- Break reasons are exactly `gap` and `hash_mismatch`. `DeleteBefore` pruning a prefix is never a break.
- Metric: counter `audit_write_failures_total` with label `action`, registered with the `rocketvault_` prefix used by the other metrics in `internal/metrics` (full name `rocketvault_audit_write_failures_total`).
- No `""` hash fallback anywhere; `GetLastHash` is removed.
- Repositories do CRUD only; hashing stays in the service. Follow the `service-layer-conventions` skill.
- Code comments are short, full sentences ending with a punctuation mark.
- Every commit goes through the `dev-workflow-skills:1-git-commit` skill. Before the final merge, `go build ./... && go test ./... && golangci-lint run` must be clean.

## Review Focus

- Timestamp precision: Postgres stores microseconds, so a hash computed on a nanosecond time fails verification after a round trip. Time is truncated to microseconds (Task 3, Task 4).
- SQLite writers contending on the head lock must not surface `database is locked` as a failed write (Task 5).
- A failed insert must not consume a `seq`: the next write gets the next contiguous number (Task 2).
- Re-running the migration on a populated database must not reset the head (Task 1).
- A failing audit write on a critical path must block the mutation and must not leak the cause in the response (Tasks 6-8).

## File Structure

- `internal/db/db.go`: schema, migration, head seed (Task 1).
- `model/audit.go`: add `Seq *int64` to `AuditLog` (Task 1).
- `internal/repositories/audit_repository.go`: `AppendChained`, query ordering and `seq` scan, drop `GetLastHash` (Task 2).
- `internal/metrics/audit_metrics.go` (new): failure counter (Task 3).
- `internal/services/audit/audit_service.go`: write path, `RecordCritical`, hashing (Task 3).
- `internal/services/audit/critical.go` (new): `ErrAuditUnavailable`, `WithCritical` (Task 3).
- `internal/services/audit/compliance_report_service.go`: verification by `seq` (Task 4).
- `internal/vaultapi/audit.go`, `internal/mcpserver/tools_audit.go`, `internal/testutils/mocks.go`: plumb the integrity result and mock the new methods (Tasks 3-4).
- Call sites: see Tasks 6-8.

---

### Task 1: Schema, migration and head seed

**Files:**
- Modify: `internal/db/db.go` (`CREATE TABLE audit_logs` near line 577; `migrateSchema` near line 974; `seedAuditConfig` near line 1437)
- Modify: `model/audit.go`
- Test: `internal/db/audit_chain_migration_test.go` (new)

**Interfaces:**
- Produces: `model.AuditLog.Seq *int64`; tables/columns above. Later tasks rely on `audit_chain_head` existing with exactly one row after `SetupSchema`.

- [ ] **Step 1: Write failing tests** in `audit_chain_migration_test.go` using the existing `SetupSchema(db, dialect)` on a file-backed SQLite database:
  - `TestAuditChainMigration_EmptyTable_SeedsZeroHead`: head row has `last_seq = 0`, `last_hash = ""`.
  - `TestAuditChainMigration_LegacyRows_SeedsFromNewest`: before `SetupSchema`'s audit step, insert two legacy rows with different timestamps and `prev_hash` values `h1`, `h2` (newest `h2`); head `last_hash == "h2"`, `last_seq == 0`.
  - `TestAuditChainMigration_RerunKeepsHead`: set head to `(7, "x")`, call `SetupSchema` again; head is still `(7, "x")`.
  - `TestAuditChainMigration_SeqUnique`: inserting two rows with `seq = 1` fails with `Dialect.IsConstraintErr`; two rows with `seq NULL` succeed.
- [ ] **Step 2: Run** `go test ./internal/db/ -run TestAuditChainMigration -v`. Expected: FAIL (no `seq` column).
- [ ] **Step 3: Implement** in `db.go`: add `seq BIGINT` to the `audit_logs` `CREATE TABLE`; `ALTER TABLE audit_logs ADD COLUMN seq BIGINT` and `CREATE UNIQUE INDEX IF NOT EXISTS idx_audit_logs_seq ON audit_logs(seq)` in `migrateSchema` after the other enriched-column `ALTER`s; `CREATE TABLE IF NOT EXISTS audit_chain_head (...)` as in Global Constraints; new `seedAuditChainHead(db *sql.DB) error` called next to `seedAuditConfig`, using `d.dialect.UpsertIgnore`. Add `Seq *int64` to `model.AuditLog`.
- [ ] **Step 4: Run** the same command. Expected: PASS. Also run `go test ./internal/db/...` for regressions.
- [ ] **Step 5: Commit** via the `1-git-commit` skill.

### Task 2: Repository `AppendChained`

**Files:**
- Modify: `internal/repositories/audit_repository.go`
- Test: `internal/repositories/audit_repository_test.go`, `internal/repositories/pg_integration_test.go` (build tag `integration`)

**Interfaces:**
- Produces on `AuditRepositoryExtended`:
  `AppendChained(ctx context.Context, build func(nextSeq int64, prevHash string, now time.Time) AuditLog) error`
  Removes `GetLastHash`. `QueryAuditLogs` now selects and scans `seq`.
- Contract: inside one transaction the repo (1) locks the head with `UPDATE audit_chain_head SET last_seq = last_seq WHERE id = 1` (takes the write lock on both engines), (2) reads `last_seq`, `last_hash`, (3) reads DB time (`SELECT clock_timestamp()` on Postgres, `time.Now().UTC()` on SQLite) truncated to microseconds, (4) calls `build(last_seq+1, last_hash, now)`, (5) inserts the returned row with `Seq = last_seq+1` and `Timestamp = now`, (6) sets the head to `(seq, entry.PrevHash)`, (7) commits. Any error rolls back.

- [ ] **Step 1: Write failing tests** (extend the test schema helper to create `seq` and `audit_chain_head`, seeded `(0, "")`):
  - `TestAppendChained_AssignsContiguousSeq`: three appends give `seq` 1, 2, 3 and `build` receives the previous row's hash each time.
  - `TestAppendChained_BuildErrorRollsBack`: use a `build` that returns a row with a duplicate `ID`; the call errors, the head is unchanged, and the next append gets `seq` 1 (no gap).
  - `TestAppendChained_TimestampMicrosecondPrecision`: the `now` passed to `build` has `Nanosecond() % 1000 == 0`.
  - `TestQueryAuditLogs_OrdersChainedBeforeLegacy`: with one legacy row and two chained rows, newest-first order is seq 2, seq 1, legacy (order by `COALESCE(seq, 0) DESC, timestamp DESC, id DESC`).
  - Postgres (`integration`): `TestPG_AppendChained_Concurrent` runs 20 goroutines of one append each; `seq` is exactly 1..20 with no gaps.
- [ ] **Step 2: Run** `go test ./internal/repositories/ -run 'AppendChained|OrdersChained' -v`. Expected: FAIL (undefined).
- [ ] **Step 3: Implement** `AppendChained` in `AuditRepository` using `r.db.BeginTx`, `Dialect().Rebind` and a `Dialect() == db.Postgres` branch only for the time read. Update the interface and the `QueryAuditLogs` select, scan and `ORDER BY`. Delete `GetLastHash`.
- [ ] **Step 4: Run** the step 2 command, then `go test -tags=integration ./internal/repositories/ -run TestPG_AppendChained -v` (needs Docker). Expected: PASS.
- [ ] **Step 5: Commit** via the `1-git-commit` skill.

### Task 3: Service write path, metric and `WithCritical`

**Files:**
- Create: `internal/metrics/audit_metrics.go`, `internal/services/audit/critical.go`
- Modify: `internal/services/audit/audit_service.go`, `internal/testutils/mocks.go`, `internal/container/service_container.go` (only if constructor args change)
- Test: `internal/services/audit/audit_service_test.go`, `internal/services/audit/critical_test.go` (new)

**Interfaces:**
- Consumes: Task 2 `AppendChained`.
- Produces:
  - `AuditServiceInterface` gains `RecordCritical(ctx context.Context, event AuditEvent) error`; `RecordEvent` returns the real error.
  - `computeChainHash(prevHash string, seq int64, ts time.Time, e AuditEvent) string` using the existing field order with `seq` after `prevHash`. `computeHash` stays for legacy verification.
  - `var ErrAuditUnavailable = errors.New("audit unavailable")`.
  - `func WithCritical(ctx context.Context, svc AuditServiceInterface, ev AuditEvent, op func(context.Context) error) error`: records `ev` with `Outcome: "attempt"` via `RecordCritical`; on error returns `ErrAuditUnavailable` wrapping the cause and does not call `op`; otherwise runs `op`, records the same event with `Outcome` `success` or `failure` via `RecordEvent`, and returns `op`'s error.
  - `metrics.AuditWriteFailures` with `Inc(action string)`; a no-op default so unit tests need no registry.

- [ ] **Step 1: Write failing tests** (fake repo implementing `AuditRepositoryExtended` where needed):
  - `TestRecordCritical_ReturnsRepoError`: repo `AppendChained` fails; `RecordCritical` returns that error.
  - `TestRecordEvent_SwallowsErrorAndCounts`: same failure; `RecordEvent` returns the error (fire-and-forget callers ignore it) and the counter for that action increments by exactly 1.
  - `TestRecordEvent_ChainsHashWithSeq`: two events on a real SQLite repo; row 2's stored hash equals `computeChainHash(row1.PrevHash, 2, row2.Timestamp, event)` (use an exported test hook or recompute through the package-internal test file).
  - `TestPersistAudit_SetsSourceAndOutcome`: `PersistAudit("u", "login", "operation=login status=success message=ok")` stores `Source == "system"` and `Outcome == "success"`; a `status=failure` or `status=error` string stores `"failure"`; any other status stores `"warning"`. (Fixes B98.)
  - `TestWithCritical_AuditFailureBlocksOp`: `op` is never called; error `errors.Is(err, ErrAuditUnavailable)`; `err.Error()` of the unwrapped public message is `audit unavailable`.
  - `TestWithCritical_RecordsAttemptThenResult`: success path writes `attempt` then `success`; `op` error path writes `attempt` then `failure` and returns the op error.
- [ ] **Step 2: Run** `go test ./internal/services/audit/ -run 'RecordCritical|RecordEvent|PersistAudit|WithCritical' -v`. Expected: FAIL.
- [ ] **Step 3: Implement** `appendChained` (private) as a call to `repo.AppendChained` whose `build` closure returns an `AuditLog` with `PrevHash = computeChainHash(...)`. Remove the mutex and the `GetLastHash` call. `RecordEvent` calls `appendChained`, logs with `log.Printf` and increments the counter on error, and returns the error. `RecordCritical` increments the counter and returns the error. Add `RecordCritical` to `MockAuditService`. Add the counter in `audit_metrics.go` following `vault_rate_limit_metrics.go`; wire it through a package-level setter called from the container next to `NewAuditService`. Leave `logging.go` unchanged: its persist path calls `PersistAudit`, which goes through `RecordEvent`, so persist failures are already counted once.
- [ ] **Step 4: Run** the step 2 command plus `go build ./...`. Expected: PASS. Fix any other `AuditServiceInterface` implementers the compiler reports.
- [ ] **Step 5: Commit** via the `1-git-commit` skill.

### Task 4: Verification by `seq`

**Files:**
- Modify: `internal/services/audit/compliance_report_service.go` (`verifyChain`, `QueryLogs`), `internal/vaultapi/audit.go`, `internal/mcpserver/tools_audit.go`, `internal/testutils/mocks.go`
- Test: `internal/services/audit/compliance_report_service_test.go`, `internal/vaultapi/audit_test.go`

**Interfaces:**
- Produces:
  `type IntegrityResult struct { OK bool; BreakSeq *int64; BreakReason string }`
  `func verifyChain(logs []repositories.AuditLog) IntegrityResult` (logs newest-first)
  `QueryLogs(ctx, filter) ([]repositories.AuditLog, int64, IntegrityResult, error)`
  JSON keeps `integrity_ok` and adds `integrity_break_seq` and `integrity_break_reason`, both `omitempty`.
- Rules: for a row with `Seq != nil` and an older row in the page: if the older row has a `Seq`, require `newer.Seq == older.Seq+1` else `gap`; if the older row is legacy, require `newer.Seq == 1` else `gap`; then require `newer.PrevHash == computeChainHash(older.PrevHash, *newer.Seq, newer.Timestamp, event)` else `hash_mismatch`. A chained row with no older row in the page is not checked. Legacy rows (`Seq == nil`) keep the current check. The result reports the first break found walking newest to oldest.

- [ ] **Step 1: Write failing tests** `TestVerifyChain_*`: valid chained page; `gap` (seq 5 follows 3, break seq 5); `hash_mismatch` (tampered details, break seq reported); legacy-to-chained boundary valid (seq 1 over a legacy row); boundary `gap` (seq 2 over a legacy row); pruned prefix (page ends at seq 40 with nothing older: OK); all-legacy page behaves as before. Plus `TestAuditHandler_IntegrityBreakFields` in `internal/vaultapi/audit_test.go` asserting the JSON carries `integrity_break_seq` and `integrity_break_reason` when broken and omits them when OK.
- [ ] **Step 2: Run** `go test ./internal/services/audit/ ./internal/vaultapi/ -run 'VerifyChain|IntegrityBreak' -v`. Expected: FAIL.
- [ ] **Step 3: Implement** as specified, then fix compile errors in callers (`vaultapi/audit.go`, `mcpserver/tools_audit.go`, mocks, existing tests asserting `IntegrityOK`).
- [ ] **Step 4: Run** `go test ./internal/services/audit/ ./internal/vaultapi/ ./internal/mcpserver/ -v`. Expected: PASS.
- [ ] **Step 5: Commit** via the `1-git-commit` skill.

### Task 5: Concurrency, fork and end-to-end chain tests

**Files:**
- Test: `internal/services/audit/audit_chain_concurrency_test.go` (new), `internal/repositories/pg_integration_test.go`
- Modify (only if the test shows lock errors): the SQLite DSN where `internal/db` opens the connection.

- [ ] **Step 1: Write tests** on a file-backed SQLite DB in `t.TempDir()` (not `:memory:`, which gives each connection its own database):
  - `TestAuditChain_ConcurrentWriters`: 20 goroutines each call `RecordEvent` once; no errors; `seq` is exactly 1..20; `verifyChain` over all rows returns `OK`.
  - `TestAuditChain_TwoServicesOneDB`: two `AuditService` instances over two `Conn`s to the same file, 10 writes each, interleaved; `seq` 1..20 and `OK` (simulates two replicas).
  - Postgres (`integration`): the same two-service test against the testcontainer.
- [ ] **Step 2: Run** `go test ./internal/services/audit/ -run AuditChain -race -count=3 -v`. Expected: PASS. If a `database is locked` error appears, add `_busy_timeout=5000` to the SQLite DSN in `internal/db` and rerun; commit that change with this task.
- [ ] **Step 3: Run** `go test -tags=integration ./internal/services/audit/ -run AuditChain -v` (needs Docker). Expected: PASS.
- [ ] **Step 4: Commit** via the `1-git-commit` skill.

### Task 6: Convert group 1 - auth, tokens, JWKS

**Files:**
- Modify: `internal/services/auth/authentication_service.go` (RecordEvent sites at lines 192, 213, 233, 250, 262, 328, 339, 394), `api/oauth2.go` (lines 149, 199), `api/jwks.go` (line 88)
- Test: the matching `_test.go` files; add `internal/services/auth/authentication_service_audit_test.go` if none fits.

**Interfaces:**
- Consumes: `audit.WithCritical`, `audit.ErrAuditUnavailable`, `RecordCritical`.
- Rule: a site that gates an operation (login success, token issue, signing-key use) goes through `WithCritical` or `RecordCritical` before the effect. Failure-outcome events (bad password, locked account) stay `RecordEvent`; they record a denial and block nothing. `middleware.go:460` is a request-level audit and is not converted.
- Handlers map `ErrAuditUnavailable` to 5xx with body `audit unavailable` using each package's existing error-response helper.

- [ ] **Step 1: Write failing tests**: with a `MockAuditService` whose `RecordCritical` returns an error, (a) login with correct credentials returns an error and no token, (b) the OAuth2 token endpoint returns 5xx with body containing `audit unavailable` and no `access_token`, (c) the response body never contains the underlying error text.
- [ ] **Step 2: Run** `go test ./internal/services/auth/ ./api/ -run Audit -v`. Expected: FAIL.
- [ ] **Step 3: Implement** the conversions per the rule above.
- [ ] **Step 4: Run** `go test ./internal/services/auth/ ./api/ -v`. Expected: PASS.
- [ ] **Step 5: Commit** via the `1-git-commit` skill.

### Task 7: Convert group 2 - exports, purges, user and vault delete

**Files:**
- Modify: `internal/services/exportaudit/exportaudit.go` (line 150), `internal/services/certificates/certificate_export.go`, `internal/services/keys/key_export.go`, the purge paths in `internal/services/secrets/secret_service.go`, `internal/services/keys/key_service.go`, `internal/services/certificates/certificate_service.go`, the vault purge and delete service, `internal/services/users/user_service.go` (delete)
- Test: the matching `_test.go` files.

**Interfaces:**
- Consumes: Task 3 and Task 6 conventions. Services in this group that only hold a logger receive `AuditServiceInterface` through their constructors, wired in `internal/container/service_container.go`.
- `exportaudit` records the export attempt with `RecordCritical` before key or certificate material is produced, so a failed audit write returns the R6 error body and no material.

- [ ] **Step 1: Write failing tests**: with a failing critical audit, (a) key export and certificate export return an error and the response has no key material, (b) secret, key and certificate purge leave the item in the soft-deleted state, (c) user delete and vault delete leave the row in place.
- [ ] **Step 2: Run** `go test ./internal/services/... -run 'Audit|Critical' -v`. Expected: FAIL.
- [ ] **Step 3: Implement** the conversions and constructor injection; run `go build ./...` to find every constructor call site.
- [ ] **Step 4: Run** `go test ./internal/services/... ./api/... ./cmd/... -v`. Expected: PASS.
- [ ] **Step 5: Commit** via the `1-git-commit` skill (split by service if the diff is large).

### Task 8: Convert group 3 - key lifecycle and role assignments

**Files:**
- Modify: `internal/services/keys/key_service.go` (create, import, rotate, delete, wrap, unwrap), `internal/services/secrets/rotation_service.go` (rotate), the role assignment service in `internal/services/authorization/`, and the signing-key operations in `internal/signing/` / the JWKS service.
- Test: the matching `_test.go` files.

**Interfaces:**
- Same rule and wiring as Task 7. Role assignment grant and revoke use `WithCritical` so a failed audit write leaves the grants unchanged.

- [ ] **Step 1: Write failing tests**: with a failing critical audit, (a) key create, import, rotate, delete, wrap and unwrap each return an error and change nothing, (b) a role assignment is not created or removed, (c) secret rotation does not write a new version.
- [ ] **Step 2: Run** `go test ./internal/services/keys/ ./internal/services/authorization/ ./internal/services/secrets/ -run 'Audit|Critical' -v`. Expected: FAIL.
- [ ] **Step 3: Implement** the conversions.
- [ ] **Step 4: Run** `go build ./... && go test ./... && golangci-lint run`. Expected: all clean.
- [ ] **Step 5: Commit** via the `1-git-commit` skill.

### Task 9: Bug tracking and operations notes

**Files:**
- Modify: `docs/known-bugs.md`, `docs/internal/saas-roadmap/phase-0-hardening.md` (section 3 status), the admin or operations doc that lists metrics (find with `grep -rn rocketvault_vault_rate_limit docs/`).

- [ ] **Step 1:** Mark B98 fixed in `docs/known-bugs.md`. Add entries for the two new audit findings (`GetLastHash` failure resets the chain; chain forks with more than one replica) as fixed, each with a matching GitHub issue (`gh issue create`, full details, per the project convention).
- [ ] **Step 2:** Document `rocketvault_audit_write_failures_total` and a suggested alert (`increase(...[5m]) > 0`) next to the existing metric docs, and the new `integrity_break_seq` and `integrity_break_reason` fields in the audit API docs.
- [ ] **Step 3: Run** `go build ./...`. Expected: no output.
- [ ] **Step 4: Commit** via the `1-git-commit` skill.
