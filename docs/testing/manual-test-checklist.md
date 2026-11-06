# RocketVault Manual Testing Checklist

A practical, run-through checklist covering all 11 feature areas of RocketVault.
Check items off as you go. Use alongside:

- **[Administrator Manual](../admin-manual.html)** — canonical per-endpoint reference.
- **[Endpoint table](../../MANUAL_TESTING.md)** — full method/path/auth quick reference.
- **[.claude/e2e-manual-testing-guide.md](../internal/archive/e2e-manual-testing-guide.md)** — a prior deep-dive
  audit pass (2026-08-03) with ~50 findings (CLI-vs-REST auth divergence, IDOR, error-code
  mismatches, etc.). Skim its Findings sections for each area before you test it — several
  behaviors below are "known broken" there and you shouldn't re-report them as new.
- **[.claude/known-bugs.md](../known-bugs.md)** — authoritative fixed/open bug status; the e2e
  guide's findings are largely a separate, unreconciled list, so check both.

Environment assumed throughout: dev config (`.rocketvault.yaml`), server at
`http://localhost:8774`, SQLite at `./dev-rocketvault.db`, HSM enabled against a local
SoftHSM2 token labeled `rocketvault`, OIDC enabled against `exchange4all.local` (network
call — see §5).

---

## 0. Setup & Prerequisites

- [ ] Build: `go build -o build/rocketvault .` (the `./rocketvault` symlink already points here)
- [ ] Start server: `./rocketvault serve &` — watch `./logs/development.log` for startup errors
- [ ] Confirm liveness: `curl -s localhost:8774/api/v1/health/live`
- [ ] Bootstrap admin (**CLI-only** — `POST /api/v1/users/admin` does not exist over REST):
  ```bash
  ./rocketvault users admin --admin-username=admin --admin-password="<choose-a-password>" \
    --bootstrap-token="<bootstrap_token from .rocketvault.yaml>"
  ```
  Prints a TOTP secret as an `otpauth://` URL. Extract the base32 secret:
  ```bash
  SECRET=$(./rocketvault users admin ... 2>&1 | sed -n 's/.*secret=\([A-Z2-7]*\).*/\1/p')
  ```
- [ ] Log in, capture token:
  ```bash
  TOTP=$(oathtool --totp -b "$SECRET")
  TOKEN=$(curl -s -X POST localhost:8774/api/v1/users/login -H 'Content-Type: application/json' \
    -d "{\"username\":\"admin\",\"password\":\"<password>\",\"totp_code\":\"$TOTP\"}" | jq -r .token)
  ```
  TOTP codes are single-use, ~30s windows (with ±2-step skew) — regenerate for every
  subsequent CLI/curl call, don't reuse a stale code.
- [ ] `jq`, `oathtool` available (confirmed present on this box).

---

## 1. Multi-Vault Management

- [ ] Create a vault: `POST /api/v1/vaults {"name":"test-vault","purge_protection":false,"retention_days":10}` → 201
- [ ] List vaults: `GET /api/v1/vaults` → includes `default` + `test-vault`
- [ ] Get vault by name: `GET /api/v1/vaults/test-vault` → 200
- [ ] Update vault (`PATCH /api/v1/vaults/test-vault {"tags":{"env":"test"}}`) → 200, tags persisted
- [ ] Soft-delete vault: `DELETE /api/v1/vaults/test-vault` → 204
- [ ] Confirm `default` vault refuses deletion: `DELETE /api/v1/vaults/default` → error, not 204
- [ ] List with `?include_deleted=true` → shows soft-deleted `test-vault`
- [ ] Purge: `DELETE /api/v1/vaults/test-vault/purge` → verify purge-protection semantics if set
- [ ] Repeat create/list/get via CLI: `./rocketvault vaults create|list|get|delete|purge ...`
- [ ] Confirm legacy flat routes (`/api/v1/secrets`) resolve to `default` vault (create a secret flat, then check it's visible under `/vaults/default/secrets`)

## 2. Secrets

- [ ] Create (vault-scoped): `POST /vaults/test-vault/secrets {"name":"db-password","value":"<base64>"}` → 201
- [ ] Get: `GET /vaults/test-vault/secrets/db-password` → decodes correctly
- [ ] Update: `PUT .../secrets/{id}` → new version created
- [ ] List versions: `GET .../secrets/{id}/versions`, `/versions/{n}`, `/versions/latest`
- [ ] Tags + content-type set and round-trip on get
- [ ] Enable/disable + not-before/expiry attrs honored (disabled/expired secret 403s on get)
- [ ] Generate: `POST /secrets/generate` → random value returned
- [ ] Bulk export/import: `POST /secrets/export`, `POST /secrets/import`
- [ ] Backup/restore: `POST /secrets/{id}/backup`, `POST /secrets/restore`
- [ ] Soft-delete → list deleted → recover → purge, all vault-scoped
- [ ] Rotation policy CRUD (note: rotation execution is user-scoped, not vault-scoped — see multi-vault.md deferrals)
- [ ] CLI parity: `./rocketvault secrets create|get|list|update|delete --vault test-vault ...`
- [ ] **Known gotcha** (e2e guide Secrets §Finding 1): manual/auto rotation has historically corrupted ciphertext and 500'd `ListSecrets` for the whole vault — re-verify this is still broken or already fixed before relying on rotation in this environment.

## 3. Keys

- [ ] Create RSA key: `POST /vaults/test-vault/keys {"name":"signing-key","type":"RSA","bits":2048}` → 201
- [ ] Create EC key (P-256/P-256K/P-384/P-521)
- [ ] Create OCT (AES) key — **requires HSM**: `{"name":"aes-key","type":"OCT","bits":256}` → 201 (SoftHSM2 token `rocketvault` already initialized on this box); confirm it 4xxs cleanly if you disable `hsm.enabled` and retry
- [ ] Get/list/list-versions
- [ ] Update attributes, delete (soft)
- [ ] Rotate: `POST .../keys/{id}/rotate` → new version
- [ ] Sign/verify (`RS256`/`ES256`/etc.), encrypt/decrypt, wrap/unwrap — all base64 payloads
- [ ] Backup/restore
- [ ] Rotation policy get/set/delete (`/keys/{key_id}/rotationpolicy`)
- [ ] Soft-delete → list deleted → recover → purge
- [ ] CLI: `./rocketvault keys create|list|rotate ...` — **note**: keys/certificates CLI commands have no `--vault` flag yet (hardcode `default`); this is a documented CLI-only gap, not a backend bug (see multi-vault.md "Known deferrals")
- [ ] **Known gotcha** (e2e guide Keys §Finding 8): CLI `keys wrap`/`keys unwrap` were reported broken (missing required `Scope` field) — re-verify before relying on the CLI path for wrap/unwrap; use REST if it's still broken.

## 4. Certificates

- [ ] Create: `POST /vaults/test-vault/certificates {"name":"my-cert","subject":"CN=example.test","key_id":"<key-id>","validity_days":365}` → 201
- [ ] Get/list/update/delete (soft)
- [ ] Certificate policy get/set/delete (`/certificates/{id}/policy`)
- [ ] Auto-renewal: set `auto_renew`/`renewal_days`, confirm renewal scheduler picks it up (or trigger manually if there's a CLI hook)
- [ ] Backup/restore
- [ ] Soft-delete → list deleted → recover → purge
- [ ] Confirm self-signed only — no public-CA/ACME path exists to test
- [ ] **Known gotcha** (e2e guide Certificates §Finding 7 / §3): `certificate renew` was reported unconditionally broken (name collision on the `UNIQUE(vault_id,name)` constraint), and generated "CA" certs were reported missing `keyCertSign` (fails external validators like `openssl verify`) — check both before treating them as working.

## 5. Authentication & Authorization

- [ ] Local login: username + password + TOTP in one call, `POST /users/login`
- [ ] Wrong password / wrong TOTP / missing TOTP → distinct 403/400s, no user enumeration
- [ ] Refresh: `POST /users/refresh {"refresh_token":...}` → new token
- [ ] List sessions: `GET /users/sessions`; revoke one: `DELETE /users/sessions/{id}`; revoke all: `DELETE /users/sessions`
- [ ] OIDC (**network-dependent** — only if `exchange4all.local` is reachable): `GET /api/v1/oidc/login` → redirect to issuer → complete → `GET /api/v1/oidc/callback` → session issued; confirm `FindOrCreateExternalUser` provisions a least-privilege `user` role on first login
- [ ] CLI session cache: `rocketvault users login`, confirm `~/.rocketvault/sessions/<username>.json` written and `current` pointer set; run a bare command with no credential flags and confirm it reuses the cached session; `rocketvault users logout` clears it
- [ ] **Known gotcha** (e2e guide Auth §Findings 1, 6): self-service `GET/PUT /users/{own_id}` and `/users/sessions*` were reported completely unreachable over REST for non-admin roles (RBAC middleware blocks before the handler's own ownership check runs), and session revocation had no ownership check (any admin could revoke any user's session). Worth re-confirming current status with a non-admin test user.

## 6. RBAC (Azure Role Parity)

- [ ] List built-in roles (no auth needed): `./rocketvault vault-access roles` → all 11 bundles
- [ ] Grant a role: `POST /vaults/test-vault/role-assignments {"principal_id":"<uuid>","principal_type":"user","role":"Key Vault Secrets User"}`
- [ ] Confirm the granted principal can/can't perform the expected actions (e.g. Reader gets metadata but 403s on `GET secret value`; Secrets User gets values but 403s on write)
- [ ] Revoke: `DELETE /vaults/test-vault/role-assignments/{id}` → immediate effect, no caching delay
- [ ] Explicit-deny access policy overrides a role grant — create a deny policy against a role-holder, confirm it wins
- [ ] Confirm deny-by-default: a principal with zero role assignments 403s on every data-plane route, **including the global `admin` role** (admin has no implicit vault data-plane bypass)
- [ ] Confirm cross-vault isolation: a role grant in `test-vault` does not leak access into `default` or another vault
- [ ] `Key Vault Data Access Administrator` can manage role assignments without holding data-plane access itself
- [ ] **Known gotcha** (e2e guide RBAC §Finding 3, Critical): `rocketvault vault-access` (CLI) was reported to perform authentication but zero authorization — any authenticated user could self-grant `Key Vault Administrator` via CLI even with no REST access. This is the single most important item to re-verify before trusting RBAC in this environment; if still true, treat CLI access to the box as equivalent to global admin.

## 7. HSM Support

- [ ] Confirm SoftHSM2 token present: `softhsm2-util --show-slots` (already initialized here, label `rocketvault`)
- [ ] With `hsm.enabled: true` (current dev config), create RSA key → sign/verify, encrypt/decrypt via the key
- [ ] Create EC key on P-256/P-384/P-521 → sign/verify (HSM-backed); create P-256K → confirm it falls back to software (P-256K has no PKCS#11 mechanism per parity doc)
- [ ] Create OCT/AES key → generate + wrap/unwrap (HSM-only path, see §3)
- [ ] Confirm AES-CBC on software keys still works (HSM has no CBC mechanism, so this stays software-only even with HSM enabled)
- [ ] Flip `hsm.enabled: false`, restart, confirm software crypto path still works for RSA/EC and OCT key creation now correctly fails with `crypto.ErrOctKeysRequireHSM`

## 8. Soft-Delete / Purge Protection

- [ ] For each of secrets/keys/certificates: delete → appears in `GET /vaults/{v}/deleted/{type}` → restore → confirm live again → delete again → purge → confirm gone from both live and deleted lists
- [ ] Set `purge_protection: true` on an object/vault → confirm purge is refused before `retention_days` elapses
- [ ] Confirm retention window: object purges automatically (or via scheduler) once `retention_days` passes (can shortcut by setting a very short retention window in a throwaway vault)
- [ ] Vault-level purge/recover cascades correctly to its secrets/keys/certs (per `cascade_adapter.go`)

## 9. Audit & Compliance

- [ ] `GET /audit/logs?limit=50` → structured entries, each action you performed above should show up
- [ ] Confirm hash-chained tamper-evidence: check `integrity_ok` on an unfiltered query (note the e2e guide flagged **false positives on filtered/paginated queries** — don't treat a filtered-query integrity failure as a real tamper signal without checking JWKS §Finding 2)
- [ ] Compliance reports: `GET /audit/reports/soc2`, `GET /audit/reports/gdpr`
- [ ] Configure retention: `GET/PUT /audit/config`
- [ ] CLI: `./rocketvault audit logs`, `./rocketvault audit report --format json`
- [ ] **Known gotcha** (e2e guide Audit §Finding 1): CLI `audit logs`/`audit config` were reported to enforce authentication but no authorization — a non-admin could read the full audit trail and overwrite retention policy via CLI. Re-verify against current CLI authz (per CLAUDE.md, CLI commands now route through `vaultcli.RequireDataAction`/package-local authz helpers — confirm audit's CLI command actually calls one).

## 10. Monitoring & Ops

- [ ] Health: `GET /health/live`, `/health/ready`, `/health`, `/health/database`
- [ ] Metrics (gated by `monitoring.enable_metrics: true`): `GET /metrics` → Prometheus format, `rocketvault_db_*` gauges present and updating on the `metrics_interval` (60s in dev config)
- [ ] Rate limiting: hammer `/users/login` past `rate_limit.auth` (5/min in dev config) → 429s kick in
- [ ] Rate limiting: hammer any endpoint past `rate_limit.default` (300/min) → 429s kick in
- [ ] Whole-vault backup/restore: `./rocketvault backup create`, `./rocketvault backup restore` — confirm it now requires admin login (fixed 2026-08-13, [[bug-backup-command-unauthenticated]])
- [ ] **Known gotcha** (e2e guide Audit §Finding 2): `backup create --output/-o <path>` was reported to collide with the global `--output` format flag, silently writing to a file literally named `table`/`json`/`yaml` in the CWD instead of the intended path. Re-verify before relying on `-o` to target a specific backup file.

## 11. Interfaces (REST / CLI / vault-client library)

- [ ] REST: confirm every route you exercised above matches the [endpoint table](../../MANUAL_TESTING.md)
- [ ] CLI: for each resource, confirm `--vault` flag support matches what's documented — secrets: full support; keys/certs: no `--vault` flag yet (default only, see §3/§4)
- [ ] JWKS: `GET /jwks.json` → public keys present; trigger a signing-key rotation and confirm old key stays valid through `rotation_overlap` (1h in dev config)
- [ ] `examples/consumer-service`: run it against this RocketVault instance, confirm it fetches a secret via `internal/vaultclient` using an OAuth2 service-account (client-credentials grant) — this is the intended pattern for *other* apps consuming secrets, not RocketVault's own CLI/REST
- [ ] OAuth2 service accounts: create one, mint a token via `POST /oauth2/token` (Basic auth, client credentials), rotate its secret, delete it — confirm audit logging for each lifecycle step

---

## Wrap-up

- [ ] Note any behavior that contradicts this checklist or the linked docs — file it in `.claude/known-bugs.md` (with root cause if you find one) rather than leaving it only in test notes, so it doesn't get re-discovered from scratch next time.
- [ ] Clean up any throwaway vaults/users/keys created during this pass (or note that they're left behind for the next run).
