# Audit reliability

## What

Make the audit trail trustworthy enough to host: audit writes report failures,
critical events fail closed, and the hash chain stays intact with more than one
replica. This is Phase 0 section 3 of the SaaS roadmap.

## Why

`RecordEvent` never returns an error, so an insert failure is logged with
`log.Printf` and dropped. A `GetLastHash` error resets the chain to `""`, which
the compliance report later shows as a false integrity break. The in-process
mutex does not serialize two replicas, so they fork the chain. Today a login,
export, purge or key operation can succeed with no audit record and nobody
knows.

## Scope

- `RecordCritical(ctx, ev) error`, fail-closed, for the critical events listed
  in the roadmap, in the same transaction as the mutation where practical.
- `RecordEvent` stays fail-open and counts failures in
  `audit_write_failures_total{action}`.
- A `GetLastHash` error fails the write. The chain never restarts from `""`.
- Chain integrity: `seq` column with a unique index, DB-side timestamp,
  dialect-specific locking (Postgres and SQLite), verification by `seq` that
  reports the break position.
- Fix B98 (outcome and source never set by `PersistAudit`).
- Convert critical call sites to `RecordCritical`.

## Out of scope

- Reading audit data for non-global admins (D-MCP2, Phase 2).
- Auditing successful secret reads (separate Phase 0 bug).
- Converting the roughly 479 non-critical `LogAudit*` sites.
- Audit export, retention changes and external log shipping.
- OIDC audit events beyond naming them as critical (the OIDC JIT sub-project
  emits them).
