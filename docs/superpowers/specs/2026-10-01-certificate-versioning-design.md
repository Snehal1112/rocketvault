# Certificate Versioning — Design

**Date**: 2026-10-01
**Status**: Proposed
**Branch target**: v-4.0.0
**Intent**: [2026-10-01-certificate-versioning.md](../intents/2026-10-01-certificate-versioning.md)
**Followed by**: certificate and key export, which takes an optional `version`
(see [2026-10-01-certificate-and-key-export.md](../intents/2026-10-01-certificate-and-key-export.md)).

**Scope**: `model/certificate.go`, `internal/db/db.go`,
`internal/repositories/certificate_repository.go` (and a new version
repository), `internal/repositories/item_lifecycle.go`,
`internal/services/certificates/` (service, renewal), `internal/certcache/`,
`internal/backup/item_backup.go`, `internal/backup/table_order.go`,
`internal/rekey/targets.go`, `internal/services/authorization/data_actions.go`,
`api/certificates.go` (+ new `api/certificates_versions.go`),
`cmd/certificates/`, `internal/vaultapi/`, `internal/mcpserver/`, and the docs
listed under Documentation.

---

## Problem

`RenewCertificate` (`certificate_service.go:879`) renews in place: the row keeps
its id, but `certificate`, `private_key`, `created_at` and `expires_at` are
overwritten, so the previous certificate and its key are lost. Azure Key Vault
certificates are versioned; RocketVault keys and secrets already are. There is
no history, no rollback, and nothing to pin an export to.
`.claude/known-bugs.md` (B30/B31 note) records "certificates have no versions at
all". The parity doc has no row for it.

## Goals

- Every create and every renewal yields a numbered version; the certificate id
  and name stay stable.
- List, get and update per version; renewal over HTTP.
- Per-version lifecycle: `enabled`, `expires_at`, `not_before`.
- Version-aware backup, restore, soft-delete, recover and purge.
- No regression for existing readers of the certificate row.

## Non-goals

- Azure's 32-hex version ids. Versions are sequential integers, like keys and
  secrets. This is a documented parity divergence.
- Deleting a single version (Azure has no such call either).
- Fixing orphaned `key_versions`/`secret_versions` rows on SQLite (B26). Only
  the new table is handled correctly here.
- Export, import and CSR merge (separate specs).

## Design

### 1. Storage

The parent `certificates` row is always the **current** version (the secrets
convention, not the keys convention, which keeps the current version in both
places and needs an implicit-v1 fallback). This leaves `certificateColumns`,
`certcache`, CA signing reads and the scheduler unchanged.

- `certificates` gains `version INTEGER NOT NULL DEFAULT 1`.
- New table `certificate_versions`: `certificate_id TEXT NOT NULL`,
  `version INTEGER NOT NULL`, `certificate TEXT NOT NULL`,
  `private_key TEXT NOT NULL` (master-key encrypted), `key_id TEXT`,
  `created_at`, `expires_at`, `not_before`, `enabled BOOLEAN NOT NULL`.
  Primary key `(certificate_id, version)`; index on `certificate_id`.
- Both are added in `createOptimizedSchema` **and** `migrateSchema` (dual-write;
  duplicate-column errors ignored as for existing ALTERs).
- Existing rows become version 1 with no archived rows. Nothing is backfilled.
- Versions are integers starting at 1. The list response is the archived rows
  plus the current one.

Model: `model.Certificate.Version int` (`json:"version"`); new
`model.CertificateVersion` (metadata, no PEM, no key) and an internal
`CertificateVersionRecord` carrying material for backup only, mirroring
`KeyVersion`/`KeyVersionRecord`.

### 2. Renewal

`RenewCertificate` runs its existing guards first (CA-signing check, preserved
`ca_cert_id`, B37). Only then, in **one transaction** (`db.WithTx` / a `*Tx`
repository method, not the non-transactional shape of `RotateKey`):

1. Insert the current body, encrypted key and attributes into
   `certificate_versions` under the current number.
2. Update the parent with the new certificate, `version + 1`, fresh
   `created_at`, `expires_at`, `not_before`; `enabled` is true (renewal already
   requires an enabled certificate, see the lifecycle gate below).

A guard failure writes no version. Two concurrent renewals collide on the
primary key; the loser returns 409 and may retry. The scheduler and the new
route share this path. Validity for auto-renew is still computed from the
current `created_at`.

### 3. Per-version lifecycle

Each version carries `enabled`, `expires_at`, `not_before`. The current
version's live on the parent; archived ones in their rows. A new version starts
enabled with dates from its certificate. `PUT .../versions/{n}` updates them
for any version; updating the current version is the same as updating the
certificate. A disabled or expired version is unusable (later: not
exportable); a disabled parent gates every version. Validation: `not_before`
must not be after `expires_at` (400).

### 4. API

Routes, on both the flat and vault-scoped routers
(`registerCertificateRoutes`):

- `GET .../certificates/{id}/versions`: list, metadata only.
- `GET .../certificates/{id}/versions/{n}`: one version's metadata.
- `PUT .../certificates/{id}/versions/{n}`: update lifecycle attributes.
- `POST .../certificates/{id}/renew`: body `{"validity_days": optional}`;
  returns the new version's metadata.

No PEM or key in any response, as with the existing certificate responses.
`CertificateResponse` gains `version`. There is no delete-version route.

Errors use the existing helpers and flat body: 404 unknown, soft-deleted or
out-of-vault certificate or version; 400 bad version, bad attributes; 409
renewal race, or `ErrCertLifecycleDenied` (renewal goes through
`GetCertificate`, which already denies a disabled certificate or one outside
its valid time window, `certificate_service.go:539`); a soft-deleted
certificate is a 404. Internal errors return a generic message.

### 5. Authorization

No new data actions or roles. `mapCertificateAction` and `mapDeletedAction`
(`data_actions.go`) gain the new routes: list and get map to
`ActionCertificatesRead`, `PUT versions/{n}` to `ActionCertificatesUpdate`,
`POST renew` to `ActionCertificatesCreate` (the mapping already anticipates it,
`data_actions.go:252`). Unmapped paths still fail closed.

### 6. Backup, restore, purge

- The certificate blob gains an additive `certificate_versions` field
  (`backupEnvelope`, `blobVersions` get a certificate slot; never rename or
  retype, per the existing comment). A blob without it restores unchanged.
- Amended 2026-10-03 (B76): blobs are now sealed. A pre-versioning inner envelope still restores once sealed, but a blob taken before the seal no longer restores at all.
- `restoreCertificateWith` creates the certificate, replays versions under the
  same numbers, then applies purge protection, in one transaction.
- `purgeItem`, `purgeVaultContents` and `deleteItemWithTags`
  (`item_lifecycle.go`) explicitly delete `certificate_versions` rows, because
  SQLite runs with foreign keys off. Soft-delete and recover leave versions
  alone; they are unreachable while the parent is deleted.
- `certificate_versions` is added to `table_order.go` (after `certificates`)
  and to `rekey/targets.go` (`private_key`, key columns `certificate_id`,
  `version`), so master-key rotation re-encrypts archived keys.

### 7. Other readers

- `certcache`: invalidate on renewal and on current-version updates as today;
  archived versions are not cached.
- Vault client, MCP server, CLI: list, get and renew, metadata only.
- Key rotation never touches an archived certificate key copy; a version keeps
  the key it was issued with.

### 8. Parity

| Aspect | Azure | RocketVault |
|---|---|---|
| Stable identity, new version on issue | yes | yes |
| List and get by version | yes | yes |
| Policy at certificate level | yes | yes |
| Per-version enabled, expires, not_before | yes | yes |
| Version id | 32-hex | integer (divergence) |
| New versions via create/import/merge | yes | renew (import/merge unbuilt) |

## Testing

Test-first, per layer:

- **Migration**: fresh and upgraded databases; existing rows read as version 1
  with nothing archived.
- **Repository**: archive-and-bump is atomic (failure in either half rolls
  back both); duplicate `(certificate_id, version)` rejected; list, get, update
  by version; `TestCertificateSelectListIsNotDuplicated` still passes.
- **Service**: renewal archives under the old number and bumps the parent; a
  guard failure writes no version; concurrent renewals give one winner and one
  409; attribute validation; current-version update equals certificate update;
  renewal after key rotation leaves the archived key copy unchanged.
- **Cleanup**: purge, vault purge and delete-with-tags leave no version rows on
  SQLite; soft-delete and recover keep them.
- **Backup and restore**: round trip with versions, a pre-change blob restores
  unchanged, a failed replay rolls back the restore.
- **Master-key rotation**: archived keys re-encrypt and still decrypt;
  drift-guard tests for `table_order.go` and `rekey/targets.go`.
- **API**: every route and status on both route shapes; route and authorization
  matrix tests; no response carries PEM or key material;
  `openapi_drift_test` passes.
- **Scheduler**: auto-renew creates a version; validity is computed correctly.

## Documentation

`docs/api-specification.yaml` and `docs/api-routes.generated.txt` (both route
shapes), `docs/api-developer-guide.md`, `docs/integration-examples.md`,
`.claude/azure-keyvault-parity.md` (new §4 certificate version rows; correct
the backup/restore row; update the §4 tally), `CLAUDE.md` if certificate
operations are enumerated there, and a `.claude/known-bugs.md` note that the
"certificates have no versions" statement (B30/B31) is superseded.

## Delivery

One branch off `v-4.0.0`; commits through the `1-git-commit` skill; build,
`go vet` and the linter clean before any report.
