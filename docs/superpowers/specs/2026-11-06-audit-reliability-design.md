# Audit reliability design

Intent: [2026-11-06-audit-reliability.md](../intents/2026-11-06-audit-reliability.md).
Source: Phase 0 section 3 of the SaaS roadmap.

## Goal

Critical operations never succeed without an audit record. The hash chain never
resets, never forks across replicas, and a verification failure names the break.

## Decisions

- **Fail-closed model: audit first, then mutate.** A critical call writes an
  `attempt` row before the operation and aborts if that write fails. The result
  is recorded afterwards with a best-effort event (`success` or `failure`). No
  service-level transaction refactor.
- **Old rows: legacy boundary.** Existing rows keep `seq NULL` and are not
  rewritten. New rows chain from the newest legacy row's hash.
- **Chain locking: `audit_chain_head` row.** One row holds `last_seq` and
  `last_hash`. Every write locks it, so replicas serialize on the database.

## Write path

`AuditService` (`internal/services/audit/audit_service.go`):

- `RecordCritical(ctx, ev) error` returns any failure to the caller.
- `RecordEvent(ctx, ev) error` returns the real error. Fire-and-forget callers
  ignore it; the service logs it and increments
  `audit_write_failures_total{action}`.
- Both call `appendChained`, which runs one transaction:
  1. Lock the head row (`SELECT ... FOR UPDATE` on Postgres, `BEGIN IMMEDIATE`
     on SQLite).
  2. Read the time from the database (`clock_timestamp()` on Postgres; the app
     clock on SQLite, which has one writer).
  3. Compute the hash from `last_hash`, `seq`, the time and the event fields.
  4. Insert the row with `seq = last_seq + 1`.
  5. Update the head. Commit.
- A failure rolls back, so `seq` is not consumed. There is no `""` fallback and
  `GetLastHash` is removed.
- The in-process mutex is removed.
- `PersistAudit` (the logger hook) sets `Source: "system"` and derives `Outcome`
  from the status text. This fixes B98. A persist failure also increments the
  metric (`logging.go:177,195`).

The `prev_hash` column stores each row's own hash. The name is kept to avoid a
risky rename.

## Schema and migration

Added to `internal/db/db.go` using the dual-write pattern (`CREATE TABLE` plus
`ALTER` in `migrateSchema`):

- `ALTER TABLE audit_logs ADD COLUMN seq BIGINT`.
- A unique index on `seq`, created in `migrateSchema` after the column exists.
  NULLs do not collide on either database.
- `audit_chain_head (id INT PRIMARY KEY CHECK (id = 1), last_seq BIGINT NOT NULL,
  last_hash TEXT NOT NULL)`.
- Seed with `INSERT ... ON CONFLICT DO NOTHING`: `last_seq = 0` and `last_hash`
  equal to the hash of the newest legacy row by `(timestamp, id)`, or `""` for
  an empty table.

## Verification

`compliance_report_service.go:252`:

- Legacy segment (`seq NULL`): checked by timestamp as today.
- Chained segment: walk by `seq`. `seq` must be contiguous and each hash must
  equal `computeHash(previous stored hash, ...)`.
- The first chained row is checked against the legacy tip. If the legacy rows
  were pruned, it is accepted as the start.
- `DeleteBefore` prunes a prefix only. Verification starts at the first
  remaining row and trusts its predecessor link, so pruning is not a break.
- The result is `{ok, break_seq, break_reason}` with reason `gap` or
  `hash_mismatch`, replacing the bare boolean.

## Critical sites

Converted to audit-first `RecordCritical`: login and token issue, exports,
purges, role assignment changes, key create/import/rotate/delete/export/wrap/
unwrap, user and vault delete, and signing-key operations (JWKS). OIDC
provisioning and denial are named critical here and emitted by the OIDC JIT
sub-project.

Most sites use `LogAudit*` today. Services that need `RecordCritical` receive
`AuditServiceInterface` through the container. Conversion is staged: auth and
tokens, then exports and purges, then keys and roles. The plan enumerates the
exact sites.

## Errors

A failed critical write returns a generic 5xx (`audit unavailable`), the
operation does not run, and the cause stays in server logs.

## Testing

- Unit: hash and `seq` progression; `RecordCritical` returns the repo error;
  `RecordEvent` swallows it and increments the metric; `PersistAudit` sets
  outcome and source.
- Integration on SQLite and Postgres: N concurrent writers give contiguous
  `seq` and a valid chain.
- Fork test: two `AuditService` instances on one database.
- Verification: gap, hash mismatch, legacy-to-chained boundary, pruned prefix.
- Migration: an old database with legacy rows seeds the head correctly.
- Per converted group: a failing audit repo blocks the mutation.

## Out of scope

As in the intent: non-global-admin audit reads (D-MCP2), auditing successful
secret reads, converting the roughly 479 non-critical `LogAudit*` sites, audit
export and external shipping, and the OIDC events themselves.
