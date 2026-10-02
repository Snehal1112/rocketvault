# Certificate and Key Export — Design

**Date**: 2026-10-01
**Status**: Implemented on v-4.0.0 (2026-10-02)
**Branch target**: v-4.0.0
**Intent**: [2026-10-01-certificate-and-key-export.md](../intents/2026-10-01-certificate-and-key-export.md)
**Depends on**: [2026-10-01-certificate-versioning-design.md](2026-10-01-certificate-versioning-design.md)
(certificate export takes an optional `version`; that spec is built first).
**Consumer**: Rocket (Tauri API client), which fetches an mTLS client identity at
send time with its service-account token and persists nothing.
**Amends**: [2026-08-25-key-export-decision-record.md](2026-08-25-key-export-decision-record.md)
(see Key export below). Does **not** implement the bulk passphrase-sealed
export of [2026-08-25-certificate-export-design.md](2026-08-25-certificate-export-design.md).

**Scope**: `model/certificate.go`, `model/key.go`, `model/azure_roles.go`,
`internal/db/db.go`, `internal/repositories/certificate_repository.go`,
`internal/repositories/key_repository.go`,
`internal/services/certificates/certificate_service.go`,
`internal/services/keys/key_service.go`, `internal/certcache/`,
`internal/services/retry/`, the generated mocks,
`internal/container/service_container.go`,
`internal/services/authorization/data_actions.go`, `internal/backup/item_backup.go`,
`api/certificates.go`, `api/keys.go`, `api/keys_types.go`, a new
`api/export.go`, the CLI create/import commands (`cmd/certificates/create.go`,
`cmd/keys/`), `internal/vaultapi/` and `internal/mcpserver/` create tools (the
`--exportable` flag and field only), `go.mod` (new dependency
`software.sslmate.com/src/go-pkcs12`, approved by the user on 2026-10-01), and
the docs listed under Documentation.

---

## Problem

No route returns usable private material. `POST /certificates/{id}/backup` is
master-key ciphertext, `GET` certificate is metadata only, keys are
non-extractable by decision, and the 2026-08-25 bulk export is sealed under a
human passphrase and gated by Officer-level roles. A Rocket service principal
cannot fetch a client certificate and key without being granted a role that can
export every private key in a vault.

## Goals

- Per-certificate export over HTTP: chain plus unencrypted PKCS#8 key as PEM, or
  a PKCS12 bundle, for one certificate (optionally one version).
- Per-key export over HTTP for software-backed keys: unencrypted PKCS#8 PEM.
- Opt-in and immutable: only items created or imported with `exportable: true`
  can ever be exported.
- Least privilege: two new narrow roles. Rocket's principal needs only the
  certificate one plus Secrets User.
- Every attempt audited; no material, password or key ever logged or cached.

## Non-goals

- Bulk export, CSV, the argon2id envelope, and the backup blob (see Amends).
- A way to make an existing item exportable. The flag is immutable by decision
  (strict option): existing certificates and keys stay permanently
  non-exportable, and a caller re-creates or re-imports to get an exportable one.
- Export of HSM-backed (`pkcs11:`) keys, symmetric `oct` keys, or ES256K keys
  (the standard library cannot encode ES256K as PKCS#8).
- The certificate-to-secret linkage, and certificate import or CSR merge. CLI
  export commands were a non-goal here; they were added by
  [2026-10-02-cli-certificate-and-key-export-design.md](2026-10-02-cli-certificate-and-key-export-design.md).

## Design

### 1. The `exportable` flag

- `model.Certificate.Exportable` and `model.Key.Exportable`, both
  `bool` with `json:"exportable"`. Both tables get
  `exportable BOOLEAN NOT NULL DEFAULT FALSE`, added to the `CREATE TABLE` and
  to a `migrateSchema` ALTER (dual-write; duplicate-column errors ignored).
  Existing rows become non-exportable.
- Set only at creation or import: an `exportable` field on `POST /certificates`,
  `POST /keys` and `POST /keys/import`. Repository `Update` never writes it
  (same pattern as `ca_cert_id`). A `PUT` carrying it is ignored like any
  unknown field.
- Every creation surface gets the field, not only HTTP, because otherwise an
  item created through it could never be exported: `--exportable` on the CLI
  `certificates create`, `keys create` and `keys import` commands, and the
  `exportable` field on the vault client (`internal/vaultapi`) and the MCP
  create tools (`create_certificate`, `create_key`). The CLI paths run their own
  authorization as today; setting the flag needs no extra permission beyond the
  create itself.
- Key rotation (`RotateKey`) updates the same key row, so it preserves
  `exportable`; a test pins this. A rotated key's older versions export through
  the same flag.
- Creation rules:
  - `exportable: true` on an HSM-backed or `oct` key is a 400.
  - An exportable certificate requires an exportable key. Creating one over a
    non-exportable key is a 409 whose message names the key's `exportable` flag,
    so a certificate cannot bypass its key's flag (a certificate stores its own
    copy of the key).
  - ES256K keys can be created exportable but export fails (see Non-goals).
- A certificate's versions (see the versioning spec) share the parent's flag;
  `certificate_versions` gets no `exportable` column.
- Backup and restore: `RestoreCertificate` and `RestoreKey` force
  `exportable=false`, even if an edited blob says otherwise (the blob is
  base64-encoded JSON, not authenticated). Documented: a restore loses
  exportability.

### 2. Certificate export

`CertificateService.ExportCertificate(ctx, scope, id, ExportCertificateRequest)`
where the request carries `Format` (`pem` or `pkcs12`), `Password *string`,
`Compat` (`modern` or `legacy`) and `Version int` (0 means latest).

1. Read the certificate in vault scope. Missing, soft-deleted or out of scope:
   404. The parent's lifecycle gate applies (disabled or outside its valid time
   window: 409 `certificate_disabled`, `ErrCertLifecycleDenied`).
2. Resolve the version: 0 or the current number uses the parent row; an archived
   number uses `certificate_versions` (404 if absent). The usability check is
   the one versioning already defines: `Certificate.VersionUsable(v)`, which is
   the parent being enabled AND that version being enabled and inside its own
   `not_before`/`expires_at` window (`CertificateVersion.IsAccessible`). The
   current version's `enabled` and dates live on the parent row. A failed check
   is a 409 `certificate_disabled`. This is the first consumer of the per-version
   `enabled` and dates that versioning added.
3. `exportable` false: 403 `certificate_not_exportable`, with a reason.
4. Decrypt the stored key copy for that version, parse it with
   `crypto.ParsePrivateKey`, and re-marshal with `x509.MarshalPKCS8PrivateKey`.
   Stored material is PKCS#1 (RSA) or SEC1 (EC); export always emits PKCS#8,
   starting exactly with `-----BEGIN PRIVATE KEY-----`, unencrypted, no
   preamble. A type the standard library cannot encode (ES256K): 403
   `certificate_not_exportable` with a reason.
5. Chain: leaf first, then intermediates found by walking `CACertID`, with a
   depth cap of 10, cycle detection, and a scoped read per hop. The root is
   excluded: a chain stops before the self-signed certificate. A self-signed
   leaf exports alone. Limit: each hop uses the CA certificate's current PEM, so
   if a CA was renewed after the leaf was issued the chain carries the CA's newer
   certificate. Renewal signs with the CA key's current value, so that
   certificate verifies only if the CA's key was not rotated before the CA's
   renewal. Export therefore checks `child.CheckSignatureFrom(ca)` at every
   hop, root included, and when a CA did not sign the certificate below it
   fails with `ErrCertificateChainUnavailable` (a generic 500) rather than
   shipping a chain that cannot verify; documented.
6. `pem`: return `certificate_pem` (the chain) and `private_key_pem`.
   `pkcs12`: the `password` field must be present (400 otherwise; an empty
   string is allowed). Encode with `go-pkcs12`: `modern` by default, and
   `compat: "legacy"` uses PBE-SHA1-3DES with a SHA-1 MAC.
7. Report `key_algorithm` (for example `RSA-2048`, `EC-P256`) computed from the
   leaf's public key, also when export is refused, so a client can show why.
8. A key rotation does not change an exported certificate: export reflects the
   certificate's own stored key copy until the certificate is renewed.
   Documented.

### 3. Key export

`KeyService.ExportKey(ctx, scope, id, version int)`, built beside `GetPublicJWK`:
read through `GetKey` (scope and lifecycle gate), reject `pkcs11:` and `oct`
keys, require `exportable`, resolve the version (0 or current uses the
current value; an older number uses `ReadVersionValue` after the scoped read),
decrypt, re-marshal to PKCS#8 PEM. ES256K and other unencodable types: 403
`key_not_exportable`. `version` for keys is an addition beyond Rocket's
requirements, made because keys already version; it can be dropped without
affecting Rocket.

Amendment to the 2026-08-25 decision record: its reasoning (an invisible,
deployment-dependent trust-model change) is answered by making exportability an
explicit, immutable, per-key flag visible in `GET key`, decided by the key's
creator. The record's status becomes "Superseded for software keys"; HSM keys
stay non-extractable (`CKA_EXTRACTABLE: false`).

### 4. Authorization

Two new data actions, named so they cannot collide with the unbuilt bulk-export
design's `ActionCertificatesExport`:

- `ActionCertificatesExportItem`
- `ActionKeysExport`

Two new built-in roles, added to `azureRoleDataActions`:

- `Key Vault Certificate Exporter`: the certificate action only.
- `Key Vault Key Exporter`: the key action only.

Administrator gets both. No other existing role gets either (not Reader, Secrets
User, Certificate User, Officer or Crypto roles). Role count goes from eleven to
thirteen and the hard-coded "eleven" mentions in comments and tests are updated.
Neither role is in `nonAdminGrantableRoles`, so only a global admin can grant
them. `Key Vault Administrator` stays a required, unchanged role and stays on
that list, so a delegated non-admin Data Access Administrator can still grant
it, and it now holds both export actions; the user accepted this on 2026-10-02
(delegation of Administrator is existing behavior, and removing it is out of
scope). It is documented as a caveat. `mapCertificateAction` and `mapKeyAction` map `POST .../export`; vault-scoped
role assignments apply. The legacy access-policy path classifies export as a
create, so a legacy deny-create policy also blocks export (fails closed).

### 5. API

Routes on both the flat and vault-scoped routers:

- `POST /api/v1/vaults/{vault_name}/certificates/{certificate_id}/export` and
  `POST /api/v1/certificates/{certificate_id}/export`
- `POST /api/v1/vaults/{vault_name}/keys/{key_id}/export` and
  `POST /api/v1/keys/{key_id}/export`

Request bodies: certificate `{"format","password","compat","version"}`; key
`{"format":"pem","version"}` (empty body allowed). Unknown `format` or `compat`:
400.

Responses (plain JSON, no `Content-Disposition`, under 64 KiB):

- Certificate PEM: `{id, name, version, format:"pem", certificate_pem, private_key_pem, not_before, expires_at, key_algorithm}`
- Certificate PKCS12: `{id, name, version, format:"pkcs12", pkcs12_base64, not_before, expires_at, key_algorithm}`
- Key: `{id, name, type, version, format:"pem", private_key_pem, key_algorithm}`

`CertificateResponse` and `KeyResponse` gain `exportable` and `key_algorithm`
(certificate's computed from the leaf public key, so the list does not query per
row). Every export response sets `Cache-Control: no-store` and
`Pragma: no-cache`.

The routes take the certificate or key UUID, like every other route. A client
that stores a name (Rocket's environment file stores a reference) resolves it to
the id from the list response, which carries `exportable` and `key_algorithm`
for exactly that purpose.

Errors on the export routes use `{"error":{"code","message"}}` through a local
helper (the rest of the API keeps its flat body):

| Status | Code | When |
|---|---|---|
| 400 | `bad_request` | bad body, invalid format/compat, `pkcs12` without `password`, bad version |
| 403 | `forbidden` | missing role |
| 403 | `certificate_not_exportable` / `key_not_exportable` | flag false, HSM, `oct`, ES256K |
| 404 | `not_found` | unknown, soft-deleted, out of vault, or unknown version |
| 409 | `certificate_disabled` / `key_disabled` | disabled, expired or outside its window |

The 401 and the missing-role 403 come from the existing session and policy
middleware, so their bodies keep their current shape (the role denial is
`text/plain`); clients read only the status. Messages and internal errors never
contain key material or the password; internal failures return a generic message.

### 6. Handling: no caching, no retry, no logging

- `certcache` and the retry wrapper pass `ExportCertificate` and `ExportKey`
  straight through: no cache fill, no cache hit, no retry of a failed call.
- Logs, audit records and errors never carry material or the password.
- Every attempt, allowed or denied, writes a structured `AuditService.RecordEvent`
  (principal, vault, resource type, id, name, version, format, outcome) with
  `ResourceID` set. Role denials are already logged by `PolicyMiddleware`.

### 7. Parity

Azure exposes neither per-item certificate key export (it uses the linked secret)
nor key export (keys are non-extractable on all tiers). Both are RocketVault
additions, marked with the parity doc's existing `➕` convention; the key-export
row at `.claude/azure-keyvault-parity.md:51` is rewritten to state software keys
are exportable only when created exportable.

## Testing

Test-first, per layer:

- **Migration and repositories**: the `exportable` column on fresh and upgraded
  databases (existing rows false); the flag round-trips on insert and read;
  `Update` never changes it.
- **Certificate service**: RSA and EC export as PEM (`BEGIN PRIVATE KEY`, exact
  prefix); chain order leaf then intermediates with no root; depth and cycle
  guards; PKCS12 modern and legacy round trips, including an empty password;
  refusals (not exportable, ES256K, disabled, missing password); `version`
  addressing an archived version; `key_algorithm`; the exportable-key creation
  rule returns a 409 naming the flag.
- **Key service**: software RSA and EC export; HSM, `oct`, non-exportable,
  disabled and expired keys refused; archived version.
- **Wrappers**: two exports in a row both reach decrypt; a cache dump holds
  neither the key nor the password; the retry wrapper never re-runs an export.
- **Authorization**: both roles in the matrix; only the exporter roles and
  Administrator can export; Reader, Secrets User, Certificate User, Officer and
  Crypto cannot; only a global admin can grant them.
- **API**: every route and status on both route shapes; R6 body; `no-store`
  headers; logs and audit events carry no material or password; a missing-role
  attempt writes an audit entry.
- **Restore**: a restored certificate and key are never exportable, even from an
  edited blob.
- **Creation surfaces**: `--exportable` on the CLI create and import commands
  and the `exportable` field on the vault client and MCP create tools reach the
  service; key rotation preserves the flag.
- **Version gating**: an archived version that is disabled, not yet valid or
  expired is a 409; an enabled one exports; the certificate being disabled
  blocks every version.
- **No logging of secrets**: a test drives an export with a PKCS12 password
  through the real middleware chain and asserts neither the password nor any key
  text appears in captured logs or audit events (the middleware does not log
  request bodies today, and the test keeps it that way).
- **End to end**: an exported identity drives a real TLS handshake against
  `openssl s_server -Verify 1`, PEM and PKCS12, RSA and EC.

## Regression safety

Export must not change the behavior of anything that exists today. This is a
requirement, not a hope, and each point below has a test or a delivery gate:

- **Existing data stays safe and unchanged.** The migration only adds a column
  with `DEFAULT FALSE`. Every existing certificate and key reads as
  non-exportable, and nothing is backfilled or rewritten. An upgrade test opens a
  database created by the pre-export build and checks that existing certificates,
  versions, keys, secrets and role assignments are all intact and readable.
- **Existing API responses only gain fields.** `CertificateResponse` and
  `KeyResponse` gain `exportable` and `key_algorithm`; no existing field is
  renamed, removed or retyped, and no existing status code or error body changes
  (the R6 body is used only on the new export routes). Golden-response tests for
  create, get, list and update pin this, and `openapi_drift_test` and the route
  contract tests pass.
- **No existing role gains export.** A role-matrix test asserts that the
  effective data actions of every pre-existing built-in role are exactly what they
  were before (only the two new roles and Administrator hold the new actions).
  Existing role assignments, the grant allow-list and global-admin behavior are
  unchanged. The role-count updates ("eleven" to thirteen) are the only edits to
  existing role code.
- **Existing creation and update paths behave the same.** A create without
  `exportable` produces exactly what it produced before (non-exportable); update,
  rotate, renew, versions, soft-delete, recover and purge behave as before, and
  the existing suites for them pass unmodified except where a count or a new
  field is asserted.
- **Backup, restore and rekey stay compatible.** Blobs written before this change
  restore unchanged (as non-exportable); a restore never grants exportability;
  master-key rotation and the backup table order are unaffected.
- **No new weakness in the old surfaces.** Caching, retry and logging behavior of
  existing methods is unchanged; the new methods are pass-through only, and the
  existing middleware and policy chain is not modified beyond the new route
  mappings (unmapped paths still fail closed).
- **Hard gates before reporting done:** `go build ./...`, `go vet ./...` and
  `go test ./... -count=1` pass with no failing package; the pre-existing tests
  are not weakened or deleted to make room; and a live smoke test on an isolated
  instance upgrades a database from the pre-export build and exercises the
  existing certificate, key, secret and role flows before the new export flows.

## Documentation

`docs/api-specification.yaml` and `docs/api-routes.generated.txt` (both route
shapes; `openapi_drift_test`), the role enum, `docs/api-developer-guide.md`,
`docs/integration-examples.md` (mTLS client identity example),
`.claude/azure-keyvault-parity.md` (key-export row, certificate rows, role table,
counts), the amended key-export decision record, rename of the bulk-export
design's action to avoid a clash, the "eleven roles" mentions, and `CLAUDE.md`.
Documented caveats: export reflects the certificate until renewal after a key
rotation, restore loses exportability, and existing items are permanently
non-exportable.

## Delivery

Built after certificate versioning, on `v-4.0.0`; commits through the
`1-git-commit` skill; build, `go vet` and the linter clean; the Regression
safety gates above all pass. The report to Rocket
carries the commit hashes, the final routes and bodies, how to start an isolated
local instance, and how to create a service principal with the exporter role plus
an exportable RSA certificate, an exportable EC certificate and a non-exportable
one.
