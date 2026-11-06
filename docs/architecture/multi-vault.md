# Multi-Vault Architecture

RocketVault is now a multi-vault system with Azure Key Vault parity. A vault is a
named namespace and security boundary that contains secrets, keys, and
certificates, governed by per-vault access policies.

Spec: `docs/superpowers/specs/2026-05-29-multi-vault-design.md`
Plan: `docs/superpowers/plans/2026-05-29-multi-vault-support.md`

## Model (Approach A — vault as a routing + context-scoping layer)

A vault is resolved per request and its ID is injected into the request context,
exactly as `user_id` is. Handlers and services read `vault_id` from context;
repositories scope queries by `vault_id`. Resources are vault-scoped; the former
`user_id` column is retained as **created_by** audit metadata, not an access scope.

- **Vault addressing:** path-based `/api/v1/vaults/{vault_name}/secrets/...`, plus
  legacy flat routes `/api/v1/secrets/...` that resolve to the `default` vault.
- **Resource uniqueness:** `UNIQUE (vault_id, name)`.
- **Visibility model:** any caller authorized for a vault sees all items in it.
  Access is governed by vault access policies + RBAC, NOT per-user object
  ownership. This applies uniformly to secrets, keys, and certificates.

## Key components

- `model/vault.go` — `Vault` type, DTOs, `ValidateVaultName`, `DefaultVaultID`
  (`00000000-0000-0000-0000-00000000efa1`) and `DefaultVaultName` ("default").
- `internal/repositories/vault_repository.go` — vault CRUD.
- `internal/services/vaults/` — `vault_service.go` (lifecycle), `cascade_adapter.go`
  (fans soft-delete/recover out to secret/key/cert repos). `ErrVaultNotFound`
  sentinel is returned for missing vaults so the API maps them to 404.
- `internal/middleware/middleware.go` — `VaultResolutionMiddleware` resolves the
  vault (path var → default), injects `common.VaultIDKey`. Positioned in the chain
  AFTER authentication, BEFORE policy. `PolicyMiddleware` is vault-aware.
- `internal/db/db.go` — `vaults` table + `vault_id` columns in
  `createOptimizedSchema` (fresh DBs) and `migrateSchema` (existing DBs);
  `seedDefaultVault` + `finalizeVaultIndexes` wired into `InitializeDB`.
- `internal/db/vault_collision.go` — `ResolveNameCollisions` renames duplicate
  `(vault_id, name)` rows before the unique index is built (migration safety).
- `api/vault.go` — vault management endpoints (create/get/list/update/delete).
- `cmd/vaults/` — `vaults` CLI command group. `common.ResolveVaultName` is the
  single source of truth for the `--vault` precedence: flag > `ROCKETVAULT_VAULT`
  env > viper `vault` key > `default`.

## Access policies

Access policies gained a nullable `vault_id`. NULL = global (applies in every
vault); a set `vault_id` applies only in that vault. Lookup uses
`(vault_id = ? OR vault_id IS NULL)`. Deny-overrides-allow precedence is preserved
across mixed global/vault-specific rows. A `vaults` resource type with a `manage`
operation supports per-vault admin grants.

## Migration

On startup, `migrateSchema` adds the `vaults` table and `vault_id` columns to
existing databases; `seedDefaultVault` creates the `default` vault; existing rows
default to the default vault. Name collisions across users that would violate the
new `(vault_id, name)` uniqueness are auto-renamed to `{name}-{short-id}` and
logged. The `migrate` CLI path uses
`internal/db/migrations/20260529000001_add_vaults.sql`.

## Vault-scope inconsistency fixes (2026-07-26)

An audit found that several routes registered under `/vaults/{name}/...` were
silently ignoring the resolved vault and falling back to owner-scoped
(per-user) behavior instead of vault-wide "members see all" — violating the
codebase's own stated rule (see the deleted-flow bullet below) that a
vault-scoped route must never silently ignore its vault. Fixed in
`docs/superpowers/plans/2026-07-26-vault-scope-inconsistency-fixes.md`
(5 tasks, all reviewed): **secrets UPDATE**, **secret versions** (list/get/
latest), **secrets export/import**, **keys UPDATE**, and **certificate
policy** (GET/PUT/DELETE) are now genuinely vault-scoped on the explicit
`/vaults/{name}/...` path — any vault member can act on any resource in the
vault, matching the existing list/get/delete behavior. Legacy flat routes are
byte-for-byte unchanged (verified by dedicated regression tests per fix).

**B6 resolved (2026-08-02, commit `da6fb9b`).** This section previously said key
delete and all crypto operations (sign/verify/encrypt/decrypt/wrap/unwrap)
were deliberately left owner-gated even on a vault-scoped route. That's no
longer true: `da6fb9b` ("feat(api)!: gate crypto operations, key delete and
rotate by vault role") made every key operation follow `scopeFromRequest`
(`api/context.go`) like the rest of the vault-scoped surface. As of 2026-08-16
`scopeFromRequest` yields `ScopeVault` on **both** route shapes — the flat
routes carry the default vault — because the owner scope there was a cross-vault
authorization bypass (see `docs/known-bugs.md` § B11). The
`ownerScoped`-branch code paths that used to enforce the old behavior
(`key_service.go` delete/rotate, `crypto_service.go`'s `loadAndAuthorize`)
still exist but are now unreachable from any HTTP route; they were left in
place deliberately rather than removed with the security fix. Verified
end-to-end against current source 2026-08-11; do not reintroduce this as a
known limitation without re-checking `git log -- internal/services/keys
api/keys.go` first.

## Known deferrals (intentional, not bugs)

These continue to work via the default vault; they were scoped out to keep
each change reviewable:

- **Secondary subsystems still user-scoped:** rotation and scheduler still key
  off `user_id`, constructing `model.NewOwnerScope(uuid.Nil, userID)` directly
  (`internal/services/secrets/rotation_service.go`, `scheduler_service.go`,
  `versioning_service.go`) rather than a vault scope. This is a choice of
  which `model.Scope` they build, not a separate code path — the P1
  `model.Scope` refactor (`docs/superpowers/plans/2026-07-26-p1-scope-value-object-refactor.md`)
  collapsed every repository onto scope-aware `Read`/`Update`/`List`, so the
  `ReadByOwner`/`ListByUser` method-level distinction this bullet used to cite
  no longer exists. Secrets versioning, secrets/keys UPDATE, and secrets
  export/import were vault-scoped by the 2026-07-26 fix above; item backup
  (`internal/backup/item_backup.go`) was vault-scoped separately on
  2026-08-19 (`model.NewVaultScope`) and is no longer in this category either.
- ~~**Keys/certs CLI `--vault` wiring**~~ — RESOLVED (shipped 2026-08-11–13).
  `rootCmd` registers a global `--vault` persistent flag (`cmd/root.go`,
  bound to `ROCKETVAULT_VAULT`/`vault:` config), inherited by every
  subcommand. `cmd/keys/*.go` and `cmd/certificates/*.go` resolve it via
  `vaultcli.ResolveVaultID`/`RequireDataAction` and build
  `model.NewVaultScope(vaultID, claims.UserID)`, not `NewOwnerScope`. On the
  backend, certificate **UPDATE** (`api/certificates.go`'s `updateCertificate`)
  and **renew** (`CertificateService.RenewCertificate`) both take a real
  `scope model.Scope` now — neither is owner-only or scope-blind anymore.
- **Subdomain vault addressing:** designed but not implemented; path-based only.
- ~~**Keys/certs deleted flow not vault-scoped**~~ — RESOLVED (shipped
  2026-08-11–13). `api/soft_delete.go`'s `registerVaultScopedDeletedRoutes`
  registers vault-scoped list/restore/purge for secrets, keys, *and*
  certificates under `/vaults/{name}/deleted/...`, alongside the legacy flat
  `/deleted/...` routes for the default vault. All three resources' service
  methods (`ListDeletedKeys`/`RecoverKey`/`PurgeKey`,
  `ListDeletedCertificates`/`RecoverCertificate`/`PurgeCertificate`,
  `ListDeletedSecrets`/`RecoverSecret`/`PurgeSecret`) take a `model.Scope`.

All three routes this section used to track as scope-blind are now fixed.
`POST /vaults/{n}/keys/{id}/rotate` was fixed in P2 (2026-07-26): it builds a
genuine vault scope via `scopeFromRequest` and is gated by `Key Vault Crypto
Officer` at vault scope, verified end-to-end with real-repository tests.
`PUT /vaults/{n}/certificates/{id}` (`updateCertificate`, `api/certificates.go`)
and `GET /vaults/{n}/keys/{id}/versions` (`listKeyVersions`, `api/keys.go`)
both now call `scopeFromRequest` and pass the resulting scope through to their
service methods (`CertificateService.UpdateCertificate`,
`KeyService.ListKeyVersions`) instead of ignoring it.

## Pre-existing latent issue (predates multi-vault) — RESOLVED

`certificate_repository.go` used to filter `ListByUser`/`ListInVault` by a
`type` column that did not exist in the certificates schema, only triggered
when a non-empty `certType` was passed. Fixed as part of the P1
`model.Scope` refactor (`docs/superpowers/plans/2026-07-26-p1-scope-value-object-refactor.md`,
Task 3): no `type = ?` filter remains anywhere in `certificate_repository.go`,
and `certificateColumns` now includes `vault_id`, populated on every scanned
row. Regression coverage: `internal/repositories/certificate_vault_id_test.go`.
