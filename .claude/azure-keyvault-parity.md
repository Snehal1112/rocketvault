# RocketVault ↔ Azure Key Vault — Feature Parity

Feature-by-feature comparison of RocketVault against Azure Key Vault (Standard/Premium
vaults). RocketVault columns are sourced from the codebase (`api/`, `internal/`,
`cmd/`, `model/`); Azure columns from Microsoft Learn (Key Vault overview and
`about-keys-details`, retrieved 2026-06-02).

**Legend:** ✅ full parity · 🟡 partial / with caveats · ❌ not supported ·
➕ RocketVault extra (no Azure equivalent)

> Scope note: RocketVault is a single self-hosted service. "Azure" here means the
> per-vault Key Vault resource, not Managed HSM. Cloud-platform features (geo-
> replication, Azure Monitor/Event Hubs, Entra ID, private endpoints) have no
> self-hosted equivalent by design — RocketVault substitutes local mechanisms.

---

## 1. Secrets management

| Capability | Azure Key Vault | RocketVault | Status |
|---|---|---|---|
| Store/retrieve secrets | ✅ | ✅ `POST/GET /api/v1/secrets` | ✅ |
| Update secret | ✅ | ✅ `PUT /secrets/{id}` | ✅ |
| Delete secret (soft) | ✅ | ✅ `DELETE /secrets/{id}` | ✅ |
| Secret versions (list/get/latest) | ✅ | ✅ `/secrets/{id}/versions[/{n}|/latest]` | ✅ |
| Content-type metadata | ✅ | ✅ `content_type` column | ✅ |
| Tags | ✅ (≤15) | ✅ tag service | ✅ |
| Enabled / nbf / exp lifecycle attrs | ✅ | ✅ `enabled`, `not_before`, `expires_at` | ✅ |
| Encryption at rest | ✅ HSM-backed | ✅ AES-256-GCM at rest | 🟡 (no HSM-sealed envelope) |
| Generate random secret | ❌ | ✅ `POST /secrets/generate` | ➕ |
| Bulk export / import | ❌ (per-secret only) | ✅ `POST /secrets/export`, `/import` | ➕ |
| Per-secret backup / restore | ✅ | ✅ `POST /secrets/{id}/backup`, `/secrets/restore` — the blob carries the secret's full `secret_versions` history and restore replays it under the new secret ID (2026-08-20), matching Azure's per-version backup semantics. Caveat: restore is not atomic across its parent write, purge-protection write and version replay (`.claude/known-bugs.md` § F3, deferred) — a mid-restore failure leaves a partial row. For secrets the residue is deletable; for **keys** the write order leaves a purge-protected orphan `PurgeKey` refuses to remove | ✅ capability parity; see F3 for the failure-path caveat |
| Rotation policy (auto-rotate) | ✅ | ✅ vault-scoped `rotation_policies` (`vault_id` + `model.Scope`-based repo/service, closed 2026-08-17 — see `.claude/known-bugs.md` § B23 for a follow-on upgrade-path fix) + CLI `secrets rotation ...` (`--vault`, `vaultcli.RequireDataAction`); scheduler auto-rotates due, enabled policies (`internal/services/secrets/scheduler_service.go`) — CLI-only, no HTTP route, matching today's design | ✅ |

## 2. Key management — operations

| Capability | Azure Key Vault | RocketVault | Status |
|---|---|---|---|
| Create key | ✅ | ✅ `POST /keys` | ✅ |
| Import key | ✅ (JWK) | ✅ `POST /keys/import` — accepts an RSA or ECDSA private-key JWK (`internal/signing.ParseJWK`; a public-only JWK is rejected), stores it exactly as a generated key would (encrypted PEM, or a non-extractable PKCS#11 object on an HSM-backed vault), gated by `ActionKeysImport` via `mapKeyAction`'s `case "import"` in `internal/services/authorization/data_actions.go`, granted to Crypto Officer/Administrator. CLI: `rocketvault keys import --name <name> --jwk-file <path>` (or `--jwk` inline), which additionally requires the caller's account to hold the global `admin` or `crypto_manager` role on top of the per-vault data-action check. Shipped 2026-08-25, closing `docs/superpowers/specs/2026-08-25-key-import-jwk-design.md` | ✅ |
| Get / List / List versions | ✅ (`GET /keys/{name}/{version}` returns the version's public JWK — `n`/`e` for RSA, `x`/`y`/`crv` for EC) | ✅ `GET /keys`, `/keys/{id}`, `/keys/{id}/versions`, and `/keys/{id}/versions/{version}`, which returns that version's public JWK components alongside its metadata (2026-08-20, § B34). Note the earlier claim here that the current-key `GET /keys/{id}` "does emit them via `buildKeyResponse`" was **false**: it advertised `n`/`e`/`x`/`y` and never populated them for any software key, because the handler parsed the master-key-encrypted stored value and discarded the resulting error. Both routes emit real components now. `GET /keys` stays JWK-free by design, as Azure's list response does | ✅ |
| Update (attributes) | ✅ | ✅ `PUT /keys/{id}` | ✅ |
| Delete (soft) | ✅ | ✅ `DELETE /keys/{id}` | ✅ |
| Rotate (new version) | ✅ | 🟡 `POST /keys/{id}/rotate` — `KeyService.RotateKey` still archives the old material into `key_versions` and overwrites `keys.value` in place (RSA/ECDSA/ES256K only; OCT has no branch), but old versions are no longer a dead end: all six crypto operations (`sign`/`verify`/`encrypt`/`decrypt`/`wrap`/`unwrap`) now accept an optional `version` field and resolve to the matching `key_versions` row, so data encrypted or signed before a rotation is usable again over REST (fixed 2026-08-19, `.claude/known-bugs.md` § B26). `GET /keys/{id}/versions/{version}` also now exists for reading one version's metadata. The CLI caught up on 2026-08-20: all four crypto commands (`rocketvault keys sign`/`verify`/`wrap`/`unwrap`) now take a `--version` flag, so an archived version is addressable from the CLI as well as REST. Omitting the flag sends `0`, which still means "current" | ✅ |
| Sign / Verify | ✅ | ✅ `POST /keys/{id}/sign`, `/verify` | ✅ |
| Encrypt / Decrypt | ✅ | ✅ `POST /keys/{id}/encrypt`, `/decrypt` | ✅ |
| Wrap / Unwrap key | ✅ | ✅ `POST /keys/{id}/wrap`, `/unwrap` | ✅ |
| Backup / Restore | ✅ | ✅ `POST /keys/{id}/backup`, `/keys/restore`, registered on both the flat and vault-scoped routers (`api/backup_item.go` `InitBackupItem`). Authorization is the RBAC data action in `PolicyMiddleware` plus a `model.NewVaultScope` read in `ItemBackupService` — a Crypto User with `ActionKeysBackup` can back up any key in a vault they are authorized for, and cannot name a key outside it. Key backups carry `key_versions` history, so a rotated key survives a backup/restore cycle with its archived versions intact | ✅ |
| Get/Set rotation policy | ✅ | 🟡 `GET/PUT/DELETE /keys/{key_id}/rotationpolicy`, mapped to `ActionKeysRotationPolicyRead`/`Write` in `MapRouteToDataAction` (`mapKeyAction`) and granted only to Crypto Officer + Administrator, matching Azure's `keyrotationpolicies/*`. `RotationScheduler` → `RotationExecutor.Check` (`rotation.keys.*` config, started in `bootstrap.go`) sweeps `KeyRotationPolicyRepository.GetDuePolicies` — enabled, `rotate_after_days > 0`, `next_rotation_at` passed — and calls `RotateKey`, so the rotate action genuinely executes. `expiry_days` is now acted on too (fixed 2026-08-19, `.claude/known-bugs.md` § B27): `RotateKey` stamps `ExpiresAt` on every rotation when the policy is enabled and `expiry_days > 0`. `notify_before_expiry_days` is still only persisted and echoed back — verified 2026-08-20, `NotifyBeforeExpiryDays` is read nowhere outside its own model and CRUD. Azure's Notify lifetime action remains half-implemented: the expiry half executes, the notify half does not. What changed on 2026-08-20 is one layer below parity — per-vault webhook **configuration** now exists (`vault_webhook_configs`, `PUT/GET/DELETE /vaults/{name}/webhook`, `rocketvault vault-webhook`), so a notification now has somewhere to be addressed *to*. Nothing sends: there is no outbound HTTP anywhere in the vault/secret/key service packages, and delivery is specced but unbuilt (`docs/superpowers/specs/2026-08-20-webhook-delivery-primitive-design.md`) | 🟡 |
| Release (confidential compute) | ✅ | ❌ no TEE attestation flow | ❌ |
| HSM keys non-extractable | ✅ | ✅ HSM-backed keys are created with `CKA_EXTRACTABLE: false` (`internal/crypto/pkcs11_provider.go`) and `KeyService.ExportKey` refuses every `pkcs11:` key, including an archived version, with 403 `key_not_exportable`. `buildKeyResponse` emits only JWK public components and `model.KeyVersion` omits `Value` | ✅ |
| Software key export (opt-in) | ❌ no plain export. A key may be marked exportable only together with a release policy, and it then leaves the vault only through secure key release to an attested environment (see the "Release (confidential compute)" row, still ❌ here) | ✅ `POST /keys/{key_id}/export` (both route shapes): unencrypted PKCS#8 PEM, optional `version`, only for software keys created or imported with `exportable: true` — an immutable, per-key flag visible in `GET key` and decided by the key's creator; existing keys stay non-exportable forever. Requires `Microsoft.KeyVault/vaults/keys/export/action` (Key Vault Key Exporter or Administrator). `oct` and ES256K keys are refused; a revoked, disabled, expired or not-yet-valid key gives 409 `key_disabled`. **Caveat:** this is an unattested plaintext PKCS#8 export gated only by RBAC (Key Vault Key Exporter or Administrator) and the immutable per-key flag. That is a different security model from Azure's attested release, not a pure extra; see the intentional divergences under §4. Amends `docs/superpowers/specs/2026-08-25-key-export-decision-record.md` (now "Superseded for software keys"); design: `docs/superpowers/specs/2026-10-01-certificate-and-key-export-design.md` | ➕ |

*Re-verified 2026-08-19 against `api/keys.go`, `api/key_rotation_policy.go`,
`api/backup_item.go`, `internal/services/keys/{key_service,crypto_service,
rotation_executor,rotation_scheduler}.go`, `internal/backup/item_backup.go`,
`internal/repositories/key_rotation_policy_repository.go`,
`internal/services/authorization/data_actions.go` and `model/azure_roles.go`.
Four rows moved ✅ → 🟡. The largest correction is **key versions are archival
only**: nothing in the API takes a version — no `/keys/{id}/{version}` route,
and no `Version` field on `SignRequest`/`EncryptRequest`/`DecryptRequest`/
`WrapKeyRequest`/`UnwrapKeyRequest` — so `RotateKey` overwriting `keys.value`
in place makes every pre-rotation ciphertext permanently undecryptable, where
Azure keeps old versions addressable and usable. The 2026-08-14 "full
rotation-execution parity" claim was half right: the scheduler really does
rotate due policies, but only the rotate lifetime action is implemented;
`expiry_days`/`notify_before_expiry_days` are inert columns. **Not a change:**
`rocketvault keys verify` (`cmd/keys/verify.go`, added 2026-08-18) calls
`CryptoService.Verify` directly — the same service `POST /keys/{id}/verify`
uses — so it is a CLI front end on an existing capability and moved no row.
Also confirmed unchanged: no attestation/release code exists anywhere in the
tree (Release stays ❌). Note for §1/§9 owners: `model.KeyRotationPolicy`
carries `vault_id` and its CRUD is `model.Scope`-scoped, but
`RotationExecutor.Check` sweeps under `model.NewAdminScope(uuid.Nil)` — the
policies are vault-scoped, the sweep is deliberately vault-agnostic.*

*Corrected 2026-08-19 (second pass, same day): the "Rotate (new version)" and
"Backup / Restore" rows above were re-verified against the just-landed key
version addressability fix (`docs/superpowers/plans/2026-08-19-key-version-
addressability.md`, design at `docs/superpowers/specs/2026-08-19-key-version-
addressability-design.md`, commits `78ad152..f03957a`). The core gap this
section flagged earlier today — "no crypto op takes a version... a prior
version can never be used again" — is fixed: `SignRequest`/`VerifyRequest`/
`EncryptRequest`/`DecryptRequest`/`WrapKeyRequest`/`UnwrapKeyRequest` all gained
an optional `Version` field (`internal/services/keys/crypto_service.go`), a new
`KeyRepository.ReadVersionValue` reads the archived `key_versions.value` a
prior rotation already wrote but nothing previously read back, and a new
`GET /keys/{id}/versions/{version}` route (`api/keys.go`) exposes one version's
metadata directly, closing the `Get / List / List versions` row's "not
addressable" caveat above too. Backup/restore was extended in the same body of
work so a rotated key's `key_versions` history survives a backup/restore cycle
(previously it silently reintroduced the exact bug this fix closes). See
`.claude/known-bugs.md` § B26 for the full root-cause writeup, including a
bundled latent cache-key bug (`resolveKeyMaterial` hardcoding its cache key's
version to `0`) found and fixed during design. That pass left no CLI `--version`
flag on any of the four crypto CLI commands — `rocketvault keys sign`,
`keys verify`, `keys wrap`, and `keys unwrap` all called their service method
with `Version` unset — flagged as a fast-follow in the design's
"Not in scope" section. That fast-follow landed 2026-08-20: each command now
has a `--version` flag bound to its own viper key (`sign-version` and
siblings), and omitting it sends `0`, unchanged from before.*

*Corrected 2026-08-19 (fifth pass): the "Backup / Restore" row above carried two
claims that were each wrong in a different direction. **(1)** Stale: it said
backup/restore was "registered on the flat routes only ... so
`/vaults/{name}/keys/{id}/backup` 404s". Commit `03badab` had already attached
all six routes to `BaseRoutes.VaultScoped`; `api/backup_item.go:21-27` shows the
registration. **(2)** Real, and now fixed: `BackupKey` gated on
`key.UserID == caller` on top of `ActionKeysBackup`, refusing a Crypto User who
legitimately held the action without owning the key — and the same gate existed
in `BackupSecret` and `BackupCertificate`, which the row never mentioned. All
three now read with `model.NewVaultScope(vaultID, userID)` instead of an
unscoped admin read plus an ownership comparison. That swap also closed a
latent cross-vault read the ownership check had been incidentally covering; see
`.claude/known-bugs.md` § B28.*

## 3. Key management — types & algorithms

| Capability | Azure Key Vault | RocketVault | Status |
|---|---|---|---|
| RSA key sizes | 2048 / 3072 / 4096 | 2048 / 3072 / 4096 | ✅ |
| EC curves | P-256, P-256K, P-384, P-521 | P-256 / P-384 / P-521 work over REST on both software and HSM-backed instances. P-256K now does too, end-to-end: both of its REST bugs were already fixed (the validator rejection, `.claude/known-bugs.md` § B24, and the follow-up uncaught 500 on HSM-enabled instances, § B25), and this plan closed the underlying capability gap those bugs' error paths existed to protect (2026-08-19, `docs/superpowers/specs/2026-08-19-hsm-secp256k1-aes-cbc-gcm-design.md`). `PKCS11KeyProvider.GenerateECDSAKey`'s `ecOID` map now includes secp256k1's OID (1.3.132.0.10) — `CKM_EC_KEY_PAIR_GEN` is curve-agnostic in the PKCS#11 spec, and SoftHSM2 accepts it. `POST /keys {"curve":"P-256K"}` now returns 201 on `hsm.enabled: false` (verified live against a running server — see the dated note below) and on `hsm.enabled: true` too (verified via live SoftHSM2 provider-level tests in `internal/crypto/pkcs11_provider_test.go`, not a running server), with working `sign`/`verify` on the resulting key either way. Only SoftHSM2 was available to verify against in this environment — secp256k1 isn't a NIST-approved curve, and real HSM vendor hardware may still reject it at the PKCS#11 level; `isHSMCapabilityError` (`internal/crypto/pkcs11_provider.go`) degrades that rejection to the existing clean `ErrUnsupportedCurve` 400 rather than an uncaught 500, so the failure mode is safe either way | 🟡 (RocketVault's own P-256K gap is fully closed on both software and SoftHSM2-backed instances; real-vendor-hardware secp256k1 support is unverified and genuinely uncertain, unlike the well-established P-256/P-384/P-521 curves) |
| Symmetric (oct/oct-HSM) keys | 🟡 oct-HSM 128/192/256 on **Premium vaults, public preview** (Managed HSM: GA) | ✅ `POST /keys` `"type": "OCT"` with `bits` 128/192/256 → `KeyService.CreateOctKey`; HSM-only by design (`SoftwareKeyProvider.GenerateAESKey` always returns `ErrOctKeysRequireHSM`), stored as a `pkcs11:` label so no key material enters the process. No CLI support (`keys create` takes RSA/ECDSA only) | ✅ (HSM-gating matches Azure's HSM-only rule; algorithm coverage differs — see the AES row) |
| Sign/Verify — RSA | RS256/384/512, PS256/384/512, RSNULL | RS256/384/512, PS256/384/512 | 🟡 (no RSNULL TLS edge case) |
| Sign/Verify — EC | ES256, ES256K, ES384, ES512 | ES256/384/512 in software and on HSM keys (`signMechanisms`, `CKM_ECDSA` with a Go-side pre-hash). ES256K (secp256k1, key type `ES256K`) now works the same way on both software and HSM-backed instances (2026-08-19, same plan as the EC curves row above). On a software-backed instance this was verified live: a REST-created P-256K key's `POST /keys/{id}/sign`/`verify` with `algorithm: ES256K` both work correctly (valid DER signature, correct accept/reject on tamper). On an HSM-backed instance the same operations are proven by live SoftHSM2 provider-level tests (`TestPKCS11Provider_SignVerify_ECDSA_ES256K`, `TestPKCS11Provider_Verify_ES256K_TamperedData_ReturnsFalse` in `internal/crypto/pkcs11_provider_test.go`), via the same generic `CKM_ECDSA` mechanism used for the other curves — not a REST/HTTP round-trip. This closes a RocketVault-side gap only — Azure's own secp256k1/ES256K support is unaffected by this change either way | 🟡 (fully working on software and SoftHSM2-backed instances; real-vendor HSM secp256k1 support unverified, same caveat as the EC curves row) |
| Sign/Verify — symmetric (HMAC) | HS256, HS384, HS512 (oct-HSM) | ❌ in practice: `CryptoOperations.Sign`/`Verify` implement HS256/384/512 for `oct` keys, but every oct key is PKCS#11-backed and `PKCS11KeyProvider`'s `signMechanisms` map has no HMAC entry | ❌ |
| Wrap/Encrypt — RSA | RSA-OAEP-256, RSA-OAEP, RSA1_5 | RSA-OAEP-256 and RSA-OAEP on both wrap/unwrap and encrypt/decrypt, software and HSM (`CKM_RSA_PKCS_OAEP` with SHA-256/SHA-1 params); RSA1_5 is implemented for encrypt/decrypt on software keys only (`AlgorithmRSA1_5`, no PKCS#11 mechanism) and deliberately excluded from the wrap/unwrap allowlist | 🟡 (RSA1_5 encrypt/decrypt only — Azure marks it "not recommended" anyway) |
| Wrap/Encrypt — AES (KW/CBC/GCM) | AES-KW, AES-GCM, AES-CBC on oct-HSM (Premium preview / Managed HSM) | A128/192/256 KW, A128/192/256 CBC, and AES256-GCM (256-bit only, matching RocketVault's pre-existing software identifier — Azure GCM key sizes beyond that aren't modeled) all now work end-to-end on HSM-backed AES keys (2026-08-19, `docs/superpowers/specs/2026-08-19-hsm-secp256k1-aes-cbc-gcm-design.md`). KW: `CKM_AES_KEY_WRAP` via `C_WrapKey`, with an algorithm↔`key.Bits` match check; requires 8-byte-aligned input (RFC 3394, matches Azure). CBC: **Encrypt/Decrypt only, never Wrap/Unwrap** — new `encryptAESCBC`/`decryptAESCBC` on `PKCS11KeyProvider` using the padded `CKM_AES_CBC_PAD` mechanism, reached through the plain `Encrypt`/`Decrypt` service path and its `POST /keys/{id}/encrypt` and `/decrypt` routes, which do round-trip the IV (`EncryptResult.Nonce` out, `DecryptRequest.Nonce` back in). `isHSMWrapAlgorithm` (`internal/services/keys/crypto_service.go`) deliberately still excludes `A128CBC`/`A192CBC`/`A256CBC`: the wrap/unwrap contract has no IV channel at all — `WrapKeyResult`, `UnwrapKeyRequest`, and their `api.WrapKeyResponse`/`api.UnwrapKeyRequest` counterparts carry only the wrapped bytes and the algorithm name, so a provider-generated CBC IV could never be returned to the caller nor supplied back on unwrap (`C_DecryptInit` with a nil IV returns `CKR_ARGUMENTS_BAD`, confirmed live against SoftHSM2). Verified at the PKCS#11 provider level (round-trip all 3 sizes, wrong-IV rejection, IV-length validation) and at the service-layer gate (`TestWrapKey_HSMKey_RejectsAES256CBC`/`TestUnwrapKey_HSMKey_RejectsAES256CBC`, `internal/services/keys/crypto_service_cache_test.go`). GCM: new `encryptAESGCM`/`decryptAESGCM` using `CKM_AES_GCM`/`NewGCMParams`, reached through the plain `Encrypt`/`Decrypt` service path (which never had a wrap-style algorithm allowlist to begin with) — verified at the PKCS#11 provider level (round-trip, tamper detection, wrong-nonce rejection); GCM stays Encrypt/Decrypt-only, never wrap/unwrap, matching Azure's own convention. Only SoftHSM2 was verified — these are standard NIST algorithms, so real-vendor rejection is far less likely than for P-256K, but genuinely unconfirmed beyond SoftHSM2 | ✅ (KW, CBC, and GCM all HSM-backed now, closely matching Azure's oct-HSM Premium-preview coverage; CBC and GCM are Encrypt/Decrypt-only, KW is the wrap/unwrap algorithm — see the *Scoped back* note below. Real-vendor-hardware confirmation is the only remaining implementation-side gap) |

*Corrected 2026-08-19 (third pass): both P-256K REST bugs are now fixed. The
validator rejection (`.claude/known-bugs.md` § B24) landed first; the follow-up —
an HSM-enabled instance (`hsm.enabled: true`, this repo's own configured default)
returning an uncaught HTTP 500 instead of a clean 400 for the same request, since
PKCS#11 has no P-256K mechanism and `crypto.ErrUnsupportedCurve` wasn't
special-cased in `api/keys.go`'s error switch — is now fixed too (§ B25). Both
fixes were re-verified: unit tests reproduce the exact real error values and
wrapping from `KeyService.CreateECDSAKey`/`RotateKey`, and the software-backed
(`hsm.enabled: false`) path was additionally confirmed live end-to-end against a
running server — `POST /keys {"curve":"P-256K"}` returns 201, and `sign`/`verify`
with `algorithm: ES256K` both work correctly on the resulting key. On an
HSM-enabled instance, the identical create request now returns a clean 400
(`curve: curve not supported by PKCS#11 provider: P-256K`) — HSM-backed P-256K
key creation remains genuinely unsupported (no PKCS#11 mechanism exists for it in
this provider), but the failure mode is now correct rather than leaking an
internal error. `RotateKey` hits the identical `GenerateECDSAKey` call for an
ES256K key and got the same fix via the shared `writeKeyError` helper in
`api/errors_key.go`, pinned by its own regression test even though at the time it
was unreachable in practice (an HSM instance could never create the P-256K key it
would need to rotate in the first place — **superseded by the *Closed* note below**:
HSM-backed P-256K key creation now works, so this rotation path is reachable
again). Also confirmed while testing this, but
unrelated to P-256K and **not fixed** — `POST /keys/{id}/encrypt` and `/wrap`
against *any* EC key (tested against both P-256 and P-256K) 500 with a leaked
internal parse error rather than a clean "not supported for EC keys" rejection;
Azure doesn't support encrypt/wrap on EC keys either, so this isn't a capability
gap, but the error handling is a pre-existing rough edge worth its own note if
RocketVault's error responses get audited for information leakage.*

*Closed 2026-08-19 (same day, separate plan,
`docs/superpowers/specs/2026-08-19-hsm-secp256k1-aes-cbc-gcm-design.md`): the three
implementation gaps the note above still left open — HSM-backed P-256K key
creation/sign/verify, and HSM-backed AES-CBC/AES-GCM — are now real, working code,
verified against a live SoftHSM2 token. `PKCS11KeyProvider.GenerateECDSAKey`'s
`ecOID` map gained secp256k1's OID (1.3.132.0.10); `CKM_EC_KEY_PAIR_GEN` is
curve-agnostic in the PKCS#11 spec and SoftHSM2 accepts it, so `POST /keys
{"curve":"P-256K"}` and `sign`/`verify` with `algorithm: ES256K` both now work
end-to-end on an HSM-enabled instance, not only a software-backed one. New
`encryptAESCBC`/`decryptAESCBC` (via the padded `CKM_AES_CBC_PAD` mechanism) and
`encryptAESGCM`/`decryptAESGCM` (via `CKM_AES_GCM`/`NewGCMParams`) methods on
`PKCS11KeyProvider` make AES-CBC and AES256-GCM real for HSM-backed AES keys, and
`isHSMWrapAlgorithm` (`internal/services/keys/crypto_service.go`) was extended to
let `A128CBC`/`A192CBC`/`A256CBC` through the wrap/unwrap gate that previously
blocked them (**reverted before merge — superseded by the *Scoped back* note
below**; CBC stayed Encrypt/Decrypt-only). A new `isHSMCapabilityError` helper
(`internal/crypto/pkcs11_provider.go`) translates a real HSM's rejection of any of
these three operations into the existing `ErrUnsupportedCurve`/
`ErrUnsupportedAlgorithm` sentinels — a clean 400 via the B24/B25 error-mapping
pipeline already in `api/keys.go`/`api/errors_key.go`, not an uncaught 500 — for
vendor hardware that doesn't accept them; no changes to those two files were
needed (**wrong for the algorithm case — corrected in the *Scoped back* note
below**; `crypto.ErrUnsupportedAlgorithm` was never mapped there and did need
wiring). Only SoftHSM2 was available to verify against in this environment:
secp256k1 isn't a NIST-approved curve and real HSM vendors may still reject it,
while AES-CBC/GCM are standard NIST algorithms far less likely to be rejected. See
the EC curves, Sign/Verify — EC, and Wrap/Encrypt — AES rows above, and §8 below,
for the resulting Status-glyph changes.*

*Scoped back 2026-08-19 (final whole-branch review of the same plan, before
merge): AES-CBC **wrap/unwrap** was briefly opened for HSM-backed keys during
that plan's development — `isHSMWrapAlgorithm` was extended to allow
`A128CBC`/`A192CBC`/`A256CBC` — and the final review found it could never have
worked. The wrap/unwrap contract has no IV channel: `WrapKeyResult` and
`UnwrapKeyRequest` (`internal/services/keys/crypto_service.go`), and the
`api.WrapKeyResponse`/`api.UnwrapKeyRequest` structs that mirror them, carry
only the wrapped bytes and the algorithm name. `WrapKey` therefore discarded
the IV `PKCS11KeyProvider.Encrypt` generates, and `UnwrapKey` passed `nil` for
the nonce — verified live against SoftHSM2, where `C_DecryptInit` with a nil IV
returns `CKR_ARGUMENTS_BAD`. In practice that meant `POST /keys/{id}/wrap` with
`A256CBC` returned 200 with an unrecoverable ciphertext and the matching
`/unwrap` 500'd. The gate was reverted to its pre-plan set (`RSA-OAEP`,
`RSA-OAEP-256`, `A128KW`, `A192KW`, `A256KW`) rather than plumbing an IV field
through both contracts, and regression tests now pin the rejection at the
service layer. Nothing that previously worked was lost: HSM-backed AES-CBC is
real and correct through `Encrypt`/`Decrypt`, which do carry the IV, and CBC
wrap was never reachable before this branch either (software `oct` keys cannot
be created at all — `ErrOctKeysRequireHSM`). Adding an IV field to the
wrap/unwrap contract is a genuine, identified architectural gap, deliberately
deferred, not an oversight. The same review also corrected the note above's
claim that "no changes to those two files were needed": `crypto.ErrUnsupportedAlgorithm`
is a different Go error value than `keyservices.ErrUnsupportedAlgorithm` and was
never mapped in `api/errors_key.go` or `api/keys.go`'s crypto-handler switches,
so an HSM rejecting AES-CBC/GCM would have produced exactly the uncaught 500
with a leaked PKCS#11 error that B24/B25 closed for the curve case. That mapping
is now wired, with a regression test.*

## 4. Certificate management

| Capability | Azure Key Vault | RocketVault | Status |
|---|---|---|---|
| Create / issue certificate | ✅ | ✅ `POST /certificates` (references a key_id) | ✅ |
| Get / List / Update / Delete | ✅ | ✅ full CRUD | ✅ |
| Certificate policy (get/set/delete) | ✅ | ✅ `/certificates/{id}/policy` GET/PUT/DELETE | ✅ |
| Auto-renewal | ✅ | ✅ `auto_renew`, `renewal_days`, renewal scheduler | ✅ |
| Versioned certificates (stable identity, new version on issue and renew; list and get by version) | ✅ | ✅ `GET /certificates/{id}/versions`, `GET /certificates/{id}/versions/{n}`, `POST /certificates/{id}/renew` (design: `docs/superpowers/specs/2026-10-01-certificate-versioning-design.md`) | ✅ |
| Per-version attributes (enabled, expires, not_before) | ✅ | ✅ `PUT /certificates/{id}/versions/{n}`; a disabled certificate gates every version | ✅ |
| Version identifier format | 32-hex | sequential integers, like keys and secrets; new versions come only from renew because import and merge are unbuilt | 🟡 |
| Backup / Restore | ✅ | ✅ `/certificates/{id}/backup`, `/certificates/restore` — the blob carries every archived version and restore replays them in one transaction; note this is an unencrypted, same-instance base64url blob (`internal/backup/item_backup.go`, `BackupCertificate`), not a portable export; see the passphrase-sealed Export row's design doc below for the distinction | ✅ |
| Per-certificate export with private key (PEM chain + PKCS#8, or PKCS12) | ❌ no export action. Azure delivers a certificate's private key through the certificate's linked secret, `GET /secrets/{name}`, which needs the secret get permission (held by Secrets User and, per §6, Certificate User) | ✅ `POST /certificates/{certificate_id}/export` (both route shapes), optional `version`; chain leaf first with intermediates, root excluded; PKCS12 `modern` or `legacy`. Only certificates created with `exportable: true` over an exportable key; requires `Microsoft.KeyVault/vaults/certificates/export/action` (Key Vault Certificate Exporter or Administrator); every attempt audited (the CLI records every attempt that reaches the command's own checks); `Cache-Control: no-store`. A restore yields a non-exportable certificate, and export reflects the certificate's own key copy until renewal. RocketVault intentionally does **not** mirror the linked-secret path: a certificate has no linked secret, and export is a dedicated action, so a Secrets User (or a Certificate User, which holds only `ActionCertificatesRead`) cannot pull the key; only Certificate Exporter or Administrator can | ➕ |
| Import certificate (PFX/PEM) | ✅ | ❌ no import route at all — not previously tracked in this table. Design specified, not yet built: `docs/superpowers/specs/2026-08-25-certificate-import-merge-design.md` | ❌ |
| Merge CSR (pending certificate) | ✅ (full pending-operation lifecycle: create CSR via the vault, get it signed externally, merge later with no resupplied state) | ❌ no merge route at all — not previously tracked in this table. Design specified, not yet built, and deliberately scoped to a single-call merge (caller resupplies the CSR + signed cert together; no persisted pending-operation state) rather than Azure's full lifecycle: `docs/superpowers/specs/2026-08-25-certificate-import-merge-design.md` § 2.1 | ❌ |
| Public-CA integration (DigiCert/GlobalSign) | ✅ | ❌ self-signed / internal only | ❌ |
| ACME / external CA enrollment | ✅ (partner CAs) | ❌ | ❌ |

*Bulk certificate export (passphrase-sealed, portable) has no Azure equivalent
and is not a row in this table — see `docs/superpowers/specs/
2026-08-25-certificate-export-design.md` (its action is now named
`ActionCertificatesBulkExport` so it cannot collide with the per-certificate
`ActionCertificatesExportItem`) and `.claude/roadmap-azure-parity-and-beyond.md`
Phase 3. Design specified, not yet built. Per-certificate export shipped
2026-10-01 (row above).*

**Intentional export divergences from Azure** (keys in §3 and certificates
above; verified against `api/export.go`, `api/keys_export.go`,
`internal/services/keys/key_export.go` and
`internal/services/certificates/certificate_export.go`):

- `exportable` is a flat top-level field on keys and certificates. Azure nests
  it in the key attributes and in the certificate policy's `key_props`, and
  RocketVault does not model `reuse_key`.
- `version` is an integer in the request body, where 0 or omitted means the
  current version; it is not a path segment. Versions are sequential
  integers, not 32-hex identifiers.
- Refusing a non-exportable item is 403 `key_not_exportable` or
  `certificate_not_exportable`. Azure reserves 403 for a missing permission.
  It is kept because the status has shipped and Rocket codes against it; a
  client tells the two 403s apart by the body.
- A disabled, expired, not-yet-valid or revoked key, and a disabled or
  out-of-window certificate or version, answer 409 `key_disabled` or
  `certificate_disabled`. Azure answers 403 Forbidden. This is not uniform
  inside RocketVault either: `writeKeyError` and `writeCertificateError`
  answer the same lifecycle denial with 403 on the other key and certificate
  routes, and only certificate renew also uses 409.
- Error codes are snake_case in the R6 body
  `{"error":{"code","message"}}`, used only by the two export routes. Azure
  uses CamelCase codes such as `KeyNotFound`.
- The CLI (`rocketvault certificates export`, `rocketvault keys export`)
  writes a passphrase-sealed file by default (argon2id and AES-256-GCM, the
  `secrets export` envelope), opened offline with `rocketvault export open`.
  Azure's CLI has no sealing step. Local mode only; design:
  `docs/superpowers/specs/2026-10-02-cli-certificate-and-key-export-design.md`.

## 5. Multi-vault / namespacing

| Capability | Azure Key Vault | RocketVault | Status |
|---|---|---|---|
| Multiple isolated vaults | ✅ (per-resource) | ✅ `POST /vaults`, path-scoped routes | ✅ |
| Per-vault resource isolation | ✅ | ✅ `idx_{secrets,keys,certificates}_vault_name` unique indexes on `(vault_id, name)`, vault_id scoping | ✅ |
| Default vault for legacy flat routes | n/a | ✅ `default` vault | ➕ |
| Vault-scoped secrets / keys / certs | ✅ | ✅ all three resource types | ✅ |
| Vault-scoped deleted/restore/purge | ✅ | ✅ all three resource types | ✅ |
| Per-vault purge protection + retention | ✅ | ✅ `purge_protection`, `retention_days` | ✅ |

*Closed 2026-08-13: `KeyService.ListDeletedKeys/RecoverKey/PurgeKey` and
`CertificateService.ListDeletedCertificates/RecoverCertificate/PurgeCertificate`
now mirror `SecretService`'s scope-aware soft-delete methods, and
`api/soft_delete.go`'s key/certificate handlers resolve `model.Scope` via
`scopeFromRequest`/`vaultIDFromRequest` instead of calling the repository
directly — see `docs/superpowers/plans/2026-08-13-vault-scoped-soft-delete-keys-certs.md`.
The dead `KeyRepositoryInterface`/`CertificateRepositoryInterface.ListSoftDeleted(ctx, userID)`
methods (superseded by the scope-aware `List(ctx, scope, Filter{OnlyDeleted: true})`)
were removed. That removal also surfaced and fixed a latent bug: `keyColumns`/
`certificateColumns` never selected `deleted_at`/`purge_protection`, so every
`List` call — not just the new deleted-listing path — silently returned zero
values for both fields.*

*Corrected 2026-08-18: this section's "Per-vault purge protection" row covers
the vault's own `PurgeProtection` flag, which always correctly blocked purging
the vault itself. But `.claude/known-bugs.md` § B20's same-day follow-up found
`VaultService.PurgeVault`'s cascade (`cascadeAdapter.PurgeVaultContents`) ran
an unconditional delete of every contained secret/key/certificate with no
check of *their* individual `purge_protection` flags — so purging an
unprotected vault silently destroyed protected items inside it, bypassing the
exact per-item guarantee B20's main fix had just made real. Fixed the same
day: `PurgeVault` now also calls the new `CascadeRepository.HasProtectedContent`
(`internal/services/vaults/cascade_adapter.go`) before purging and refuses,
fail-closed, if any contained item is protected — see `vault_service.go`'s
`PurgeVault` and `.claude/known-bugs.md` § B20 for the full history.*

## 6. Access control / authorization

*Re-verified 2026-07-25 against Microsoft Learn's "Azure built-in roles for Security"
(`dataActions` per role) and current `internal/services/authorization/roles.go` /
`access_policy_service.go`. Supersedes the 2026-06-02 pass below, which predates the
`feat/vault-scoped-users` merge (commit `5f16e75`) and didn't check role-by-role
`dataActions` precision.*

| Capability | Azure Key Vault | RocketVault | Status |
|---|---|---|---|
| Identity provider | Microsoft Entra ID | Local users + JWT (RS256/ES256) + TOTP MFA, **or** OIDC authorization-code flow (`GET /oidc/login`, `/oidc/callback`) against any standards-compliant IdP (Entra ID, Okta, Auth0, Keycloak, ...); both issue the same RocketVault session/JWT | ✅ (architecture matches: external IdP authenticates, RocketVault's existing vault-scoped role assignments still govern authorization) |
| Vault-scoped role assignment (Azure RBAC model) | ✅ role assignment scoped to vault resource, identity stays tenant-global | ✅ `role_assignments` table + `/vaults/{name}/role-assignments`; users stay tenant-global, no `vault_id` on `model.User` — confirmed against Microsoft Learn RBAC guide during design | ✅ architecture match |
| Access-policy engine (legacy model) | Separate, mutually-exclusive engine from RBAC (`enableRbacAuthorization` toggle picks one) | Two *layers*, not two interchangeable engines: `role_assignments` is the only allow path on the data plane (`HasDataAction` → `model.azureRoleDataActions`), and `access_policies` survives there purely as an explicit-deny override, evaluated first. `access_policies` is still an allow path for the non-data-plane `(vaults, manage)` grant (`CanManageVault`/`CanManageRoleAssignments`) | 🟡 simplified (reasonable for a single self-hosted product, but not a literal two-engine match) |
| Deny-overrides precedence | ✅ | ✅ confirmed in `access_policy_service.go`: "Explicit deny always wins. Falls back to RBAC when no matching policy exists." | ✅ |
| Machine identity (service principals) | ✅ | ✅ OAuth2 client-credentials service accounts | ✅ |
| MFA on human login | via Entra | ✅ TOTP enforced | ✅ |

*Corrected 2026-08-19, two items.* **(1)** The access-policy row above previously
read "Same underlying `access_policies` table for both manual grants and
role-assignment expansion — one engine, not two." That stopped being true on
2026-08-02 (`049f962`): `ExpandRole` (`roles.go`) returns `nil` for every Azure
built-in role, so a role grant materialises **no** `access_policies` row, and
`PolicyMiddleware`'s own comment now states "access_policies survives only as an
explicit-deny override and is evaluated FIRST, so a deny cannot be outvoted by a
role grant." Only the legacy vocabulary ever expanded, and it can no longer be
granted (see the closing paragraph of this section). **(2)** Route shape no longer
changes either the authorization scope or the data scope. `scopeFromRequest`
(`api/context.go`) used to hand legacy flat routes (`/api/v1/secrets/{id}`, …) an
*owner* scope — SQL predicate `user_id = ?` with no vault term — while
`PolicyMiddleware` authorized those same requests against the **default** vault,
so a caller could read and write their own resources in any other vault and
survive revocation there. Fixed 2026-08-16 in `1e16aa5`: every route shape now
yields `model.NewVaultScope` against the vault `PolicyMiddleware` checked. No cell
in §6 asserted the old behavior, so this is recorded rather than corrected — see
`.claude/known-bugs.md` § B11 and
`docs/superpowers/specs/2026-08-16-flat-route-vault-scope-fix-design.md`.

### Built-in role permission boundaries — role-by-role against real Azure `dataActions`

*Corrected 2026-08-13: the 2026-07-25 pass below compared Azure's roles against
`internal/services/authorization/roles.go`'s **legacy** role vocabulary
(`vault-reader`, `crypto-officer`, `crypto-user`, ...). That vocabulary is
authorization-inert today — `PolicyMiddleware` only ever grants a vault-data-plane
request through `RoleAssignmentService.HasDataAction`, which looks a role up in
`model.azureRoleDataActions` (`model/azure_roles.go`); a legacy-named
`role_assignments` row isn't in that map and so grants zero data actions, and
`RoleAssignmentService.AssignRole` has rejected new grants of any legacy name since
the `feat/vault-scoped-users` merge (`IsLegacyRole`, `roles.go:126-130`). The table
below re-verifies against the roles that actually govern access: the thirteen
`model/azure_roles.go` bundles.*

| Role | Azure grants (`dataActions`) | RocketVault grants (live `model/azure_roles.go`) | Status |
|---|---|---|---|
| Reader | `vaults/secrets/readMetadata` (metadata only — **not** the value), key/cert metadata + public material | `Key Vault Reader`: `ActionSecretsReadMetadata`, `ActionKeysRead`, `ActionCertificatesRead`. Bundle and effective boundary now agree: `GET /secrets/{id}` (requiring `ActionSecretsGet`) is denied, and as of 2026-08-20 `GET /secrets/{id}/versions` returns `model.SecretVersionMetadata`, which has no `Value` field, via a service path that never decrypts — so listing versions discloses no values. A value is read through `/versions/{n}`, which requires `ActionSecretsGet`, exactly as in Azure. Fixed in `764a75e`; see `.claude/known-bugs.md` §§ B30, B31 | ✅ |
| Secrets Officer | `vaults/secrets/*` (full CRUD + lifecycle) | `Key Vault Secrets Officer`: readMetadata/get/set/delete/backup/restore/recover/purge | ✅ |
| Secrets User | `getSecret` + `readMetadata` | `Key Vault Secrets User`: `ActionSecretsReadMetadata`, `ActionSecretsGet` | ✅ |
| Crypto Officer | `vaults/keys/*` — **superset of Crypto User**, includes sign/verify/encrypt/decrypt/wrap/unwrap **plus** management, and `keyrotationpolicies/*` | `Key Vault Crypto Officer`: read/create/update/delete/backup/restore/recover/purge/import/rotate/encrypt/decrypt/wrap/unwrap/sign/verify, plus `ActionKeysRotationPolicyRead`/`ActionKeysRotationPolicyWrite` — every Crypto User action plus management, written out as an explicit superset (not derived by union) | ✅ superset relationship matches |
| Crypto User | `keys/read,update,backup,encrypt,decrypt,wrap,unwrap,sign,verify` | `Key Vault Crypto User`: read/update/backup/encrypt/decrypt/wrap/unwrap/sign/verify — `update`/`backup` added 2026-08-17 to close the last gap from the 2026-07-25 pass (which checked the legacy `PolicyOperation` enum instead of this live bundle) | ✅ |
| Certificates Officer | `certificates/*`, `certificatecas/*`, `certificatecontacts/*` | `Key Vault Certificates Officer`: full cert CRUD + lifecycle; no CA or contacts sub-resources (those RocketVault features don't exist at all) | 🟡 matches what exists; CA/contacts out of scope |
| Administrator | `vaults/*` — full data-plane, all types, all ops including wrap/unwrap | `Key Vault Administrator`: every secrets/keys/certificates action written out explicitly, including wrap/unwrap — not a union of other roles, so it carries no derived gaps | ✅ |

Four more built-in roles were added 2026-08-11 (see
`docs/superpowers/specs/2026-08-11-azure-role-parity-and-vault-authz-fix-design.md`),
closing part of the gap between RocketVault's seven original roles and
Azure's full built-in set:

| Role | Azure grants (`dataActions`) | RocketVault grants | Status |
|---|---|---|---|
| Purge Operator | Purge a soft-deleted **vault** | `Key Vault Purge Operator`: `ActionVaultPurge` only | ✅ |
| Certificate User | Read a certificate **including its private-key portion** (Azure certs are a linked cert+key+secret object) | `Key Vault Certificate User`: `ActionCertificatesRead` only — RocketVault has no cert/key/secret linkage yet (P5), so this is currently identical to Reader's certificate slice | 🟡 placeholder parity — exists now, gains real meaning once P5 lands |
| Crypto Service Encryption User | Read key metadata + wrap/unwrap only (disk-encryption scenarios) | `Key Vault Crypto Service Encryption User`: `ActionKeysRead`, `ActionKeysWrap`, `ActionKeysUnwrap` | ✅ |
| Data Access Administrator | Manage role assignments, scoped to the vault, **for eight named roles only** — Administrator, Reader, Secrets User/Officer, Crypto User/Officer, Certificates Officer, Crypto Service Encryption User. Azure's ABAC condition bars it from granting itself, Purge Operator, or Certificate User | `Key Vault Data Access Administrator`: `ActionRoleAssignmentsWrite`, `ActionRoleAssignmentsDelete`, plus the same eight-role allow-list (`nonAdminGrantableRoles`, `role_assignment_service.go`) enforced on **both** grant (`AssignRole`) and revoke (`RevokeAssignment`) via `ErrRoleNotGrantable` → HTTP 403. A global admin bypasses the allow-list (`CallerIsGlobalAdmin`) | ✅ exact allow-list match — also closes the "role-assignment management is global-admin-only" known limitation from the v4.0.0 release notes |

Two RocketVault-only roles were added 2026-10-01 for per-item export
(`docs/superpowers/specs/2026-10-01-certificate-and-key-export-design.md`).
Azure has no counterpart, so they are extras, not parity rows. Neither is in
`nonAdminGrantableRoles`: only a global admin can grant them. Administrator
also holds both actions and, as before, remains grantable by a delegated
non-admin Data Access Administrator (accepted by the user on 2026-10-02), so
such a delegate can confer export through Administrator; no other built-in
role holds either action.

| Role | Azure grants | RocketVault grants | Status |
|---|---|---|---|
| Certificate Exporter | n/a | `Key Vault Certificate Exporter`: `ActionCertificatesExportItem` only | ➕ |
| Key Exporter | n/a | `Key Vault Key Exporter`: `ActionKeysExport` only | ➕ |

*Added 2026-08-19: the eight-role restriction is new — before 2026-08-18 any caller
who passed `CanManageRoleAssignments` could grant **any** role, so a Data Access
Administrator could grant itself Purge Operator or a second Data Access
Administrator, defeating the role's purpose. `ccdcb3d` closed the grant half,
`662781e` the revoke half (a non-global-admin could still revoke a role it could
not grant). RocketVault's allow-list is byte-for-byte Azure's documented Data
Access Administrator set. See `.claude/known-bugs.md` §§ B19, B21; pinned by
`TestAssignRole_NonAdminCannotGrant*` / `TestRevokeAssignment_NonAdminCannotRevoke*`
(`internal/services/authorization/role_assignment_service_test.go`),
`TestRoleAssignments_RevokeDeniedRoleNotGrantable_Returns403`
(`api/role_assignments_test.go`).*

**Not added:** `Key Vault Crypto Service Release User` (confidential-compute key release) — RocketVault has no TEE/attestation flow to gate at all (see §2's "Release (confidential compute)" row, still ❌). Adding the role name without a real capability behind it would repeat the exact anti-pattern the legacy vault-role vocabulary (`vault-reader`, `secrets-officer`, etc.) was retired for. **Not added either:** `Key Vault Contributor` — a control-plane role for Azure Resource Manager, not a data-plane concept RocketVault's self-hosted model has an equivalent for.

**Net:** the *architecture* (tenant-global identities + vault-scoped role assignments
evaluated directly against `model.azureRoleDataActions`, with an access-policy
explicit-deny override checked first) is a genuine, deliberate match to Azure's real
RBAC model. All eleven Azure *bundles* are byte-for-byte accurate against
`model/azure_roles.go`: Crypto Officer is a true superset of Crypto User including
wrap/unwrap, Administrator carries no derived gaps, and Data Access Administrator
carries Azure's own eight-role grant restriction. Crypto User's `update`/`backup` gap
(the last bundle gap from the 2026-08-13 pass) was closed 2026-08-17. (The two exporter roles added 2026-10-01 are RocketVault-only and have no Azure bundle to compare.)

*Corrected 2026-08-20 — and the correction is about method, not just a row.* This
paragraph previously concluded that "the *individual role boundaries* are now
byte-for-byte too," on the strength of an eleven-bundle line-by-line re-verification.
That inference does not hold. **A role's effective permission is its bundle composed
with the route→action map, and the bundle check cannot see the second half.** § B30 is
exactly that failure: the `Key Vault Reader` bundle is correct in isolation, while
`mapSecretAction` files `GET /secrets/{id}/versions` under `ActionSecretsReadMetadata`
on a false premise, so a Reader reads every historical plaintext secret value in the
vault. Verifying bundles against Azure's `dataActions` lists is necessary and was done
correctly; it is not sufficient, and no number of repeat passes over
`model/azure_roles.go` would ever have surfaced this. A future pass claiming role
parity must check both halves — for each role, which routes its actions actually
unlock, and what those routes return.

RocketVault also still ships a legacy, pre-Azure role vocabulary (`vault-reader`,
`crypto-officer`, `crypto-user`, etc., in
`internal/services/authorization/roles.go`) that is retained only for two purposes —
CLI display of not-yet-upgraded historical `role_assignments` rows, and the P2 upgrade
migration's translation of those rows to Azure role names
(`internal/db/role_backfill.go`) — and can no longer be granted going forward
(`IsLegacyRole`, rejected in `AssignRole`).

*Corrected 2026-08-19: this paragraph previously claimed the legacy vocabulary has
"no live authorization weight." Precisely, it has no live **data-plane** weight — a
legacy-named `role_assignments` row grants zero data actions, because
`RoleGrantsDataAction` knows only the thirteen built-in names (eleven Azure roles plus the two exporter roles). But a legacy grant made
before the `IsLegacyRole` rejection landed also materialised `access_policies` rows
via `ExpandRole`, and revoking the assignment is the only thing that deletes them.
For `vault-admin` specifically, that bundle includes `(vaults, manage)`, which
`CanManageVault` and `CanManageRoleAssignments` still honour — so a historical
`vault-admin` row can still confer vault-management and role-assignment-management
authority even though it confers no secret, key, or certificate access. New grants
cannot create this state; only pre-existing rows carry it. Out of scope for parity
comparison against Azure either way.*

## 7. Soft-delete, purge protection, recovery

| Capability | Azure Key Vault | RocketVault | Status |
|---|---|---|---|
| Soft-delete (all object types) | ✅ | ✅ secrets/keys/certs `deleted_at` | ✅ |
| List deleted / recover | ✅ | ✅ `/deleted/...` restore | ✅ |
| Purge (permanent delete) | ✅ | ✅ `/deleted/.../purge` | ✅ |
| Purge protection (block early purge) | ✅ | ✅ `purge_protection` (per-key + per-vault) | ✅ |
| Configurable retention window | ✅ (7–90 days) | ✅ `retention_days` + purge scheduler | ✅ |

*Corrected 2026-08-18: the 2026-08-18 Azure Key Vault parity audit (Critical
Finding #2, `docs/plans/2026-08-18-azure-keyvault-parity-audit.md`) found the
per-key half of this row was aspirational — the `purge_protection` DB column,
each repository's `SetPurgeProtection` method, and the enforcement check in
`PurgeSecret`/`PurgeKey`/`PurgeCertificate` all existed, but no API field,
service method, or CLI flag ever set the flag, and vault-level purge
protection didn't cascade to protect contained items. Fixed the same day: a
`--purge-protection` CLI flag and `purge_protection` API field on
create/update for all three resource types, plus a vault-level cascade check
in each `Purge*` service method — see `.claude/known-bugs.md` § B20 for the
full root cause and fix. The row's claim is now actually true, not
aspirational.*

*Extended 2026-08-18 (same day, commit `74dfab8`, `.claude/known-bugs.md` §
B22): closed the reverse-direction gap B20 left open. Bulk vault-level purge
(`VaultService.PurgeVault`'s cascade to `CascadeRepository.PurgeVaultContents`)
ran an unconditional `DELETE ... WHERE vault_id = ?` against secrets, keys,
and certificates with no `purge_protection` check at all, so purging a vault
silently destroyed every contained item regardless of its own protection
flag — the exact guarantee B20 had just made real for the single-item purge
path. `PurgeVault` now calls the new `CascadeRepository.HasProtectedContent`
(backed by a `HasProtectedContent` method on each of
`SecretRepository`/`KeyRepository`/`CertificateRepository`) after its own
vault-level `PurgeProtection` check and before `s.repo.Purge`, refusing with
`ErrVaultContentsPurgeProtected` if any contained item is still protected;
the check fails closed (refuses the purge) if the read itself errors, same
posture as B20's own cascade check.*

## 8. HSM & cryptographic protection

| Capability | Azure Key Vault | RocketVault | Status |
|---|---|---|---|
| Software crypto module | ✅ Standard (FIPS 140 L1) | ✅ Go crypto + AES-256-GCM | 🟡 (not FIPS-validated) |
| HSM-backed keys | ✅ Premium (FIPS 140-3 L3) | 🟡 PKCS#11 provider (`hsm.enabled`); RSA sign/verify/encrypt/decrypt, EC sign/verify (P-256/P-384/P-521 **and now P-256K**), and AES generate/wrap/unwrap (KW only) plus encrypt/decrypt (CBC, GCM) are all HSM-backed as of 2026-08-19 (`docs/superpowers/specs/2026-08-19-hsm-secp256k1-aes-cbc-gcm-design.md`; see §3 for the exact per-algorithm operation split) — every algorithm/curve gap that could be closed through code now is, verified against a live SoftHSM2 token (real-vendor-hardware confirmation for secp256k1 specifically remains outstanding, see §3's EC curves row). The one gap left is FIPS 140-3 L3 certification itself — a hardware/process certification, not achievable through code, that Azure's Premium tier holds and RocketVault's software-driven PKCS#11 integration never will; the same category of permanent, non-code-closable caveat the "Software crypto module" row above carries for FIPS 140 L1 | 🟡 (not FIPS 140-3 L3 certified — every other gap this row previously listed is now closed) |
| JWT signing key protection | n/a | ➕ OS keychain / self-PKI / external-PKI providers | ➕ |
| Keys non-extractable | ✅ | ✅ | ✅ |

## 9. Monitoring, audit & compliance

| Capability | Azure Key Vault | RocketVault | Status |
|---|---|---|---|
| Access/operation logging | ✅ (Azure Monitor) | ✅ structured audit logs (`/audit/logs`) | 🟡 (local, no cloud sink) |
| Tamper-evident audit chain | ❌ | ✅ `prev_hash` hash-chained audit rows | ➕ |
| Compliance reports | ❌ (raw logs only) | ✅ `/audit/reports/soc2`, `/audit/reports/gdpr` | ➕ |
| Configurable audit retention | via storage | ✅ `/audit/config` | ✅ |
| Stream to Event Hub / archive to storage | ✅ | ❌ no cloud sinks, and no push delivery of any kind. Per-vault webhook *configuration* landed 2026-08-20 (see §2's rotation-policy row) and is the roadmap's intended self-hosted answer here, but nothing is delivered yet — no row moves on config alone | ❌ |
| Health / readiness probes | platform-managed | ✅ `/health/live`, `/ready`, `/database` | ➕ |

## 10. Platform & operations

| Capability | Azure Key Vault | RocketVault | Status |
|---|---|---|---|
| REST API | ✅ | ✅ `/api/v1/...` | ✅ |
| CLI | ✅ (az keyvault) | ✅ Cobra CLI (`rocketvault ...`) | ✅ |
| JWKS endpoint for token verification | n/a | ➕ `/jwks.json` + key rotation | ➕ |
| Rate limiting | platform-managed | ✅ per-IP (global + stricter auth limits) | ➕ |
| Geo-replication / regional failover | ✅ automatic | ❌ single instance | ❌ |
| Self-hosted, no cloud dependency | ❌ | ✅ | ➕ |
| Backup / restore (whole instance) | ✅ (per-object) | ✅ `rocketvault backup create/restore`; dumps every table across *all* vaults in one file — no `--vault` scoping flag exists (`cmd/backup.go`'s `requireBackupAdmin` comment: "operates on the whole database across every vault -- there's no vault to scope this to") | ✅ broader than Azure's per-object model, not vault-scoped |

---

## Summary

### Scorecard (2026-08-20)

Counted from the status column of every capability row in §§1-10, including §6's
role-boundary tables. RocketVault extras (➕) are excluded from the denominator —
they are capabilities Azure lacks, not parity gaps.

| Section | ✅ | 🟡 | ❌ | ➕ |
|---|---:|---:|---:|---:|
| 1. Secrets management | 9 | 1 | 0 | 2 |
| 2. Key management — operations | 9 | 3 | 1 | 1 |
| 3. Key management — types & algorithms | 3 | 4 | 1 | 0 |
| 4. Certificate management | 7 | 1 | 4 | 1 |
| 5. Multi-vault / namespacing | 5 | 0 | 0 | 1 |
| 6. Access control / authorization | 14 | 3 | 0 | 2 |
| 7. Soft-delete, purge protection, recovery | 5 | 0 | 0 | 0 |
| 8. HSM & cryptographic protection | 1 | 2 | 0 | 1 |
| 9. Monitoring, audit & compliance | 1 | 1 | 1 | 3 |
| 10. Platform & operations | 3 | 0 | 1 | 3 |
| **Total** | **57** | **15** | **8** | **14** |

**71% full parity** (57/80 parity-comparable rows), 19% partial, 10% not supported.
Counting partial as usable-with-caveats, 90% of compared capabilities are present in
some form. (Two rows added 2026-08-25 — certificate import and CSR merge, both
❌, specified but not yet built — moved this from 72%/54/75 to 70%/54/77. Key
import closed the same day, moving it again to 71%/55/77; see
`docs/superpowers/specs/2026-08-25-certificate-import-merge-design.md` and
`docs/superpowers/specs/2026-08-25-key-import-jwk-design.md`.)
(Three §4 rows added 2026-10-01 for certificate versioning moved this from 55/77 to 57/80.)
(2026-10-01: export added four ➕ rows — software key export, per-certificate export and the two exporter roles — and split the key-export row; the parity percentages are unchanged.)

Read that number with three caveats. **Rows are not equally weighted** — "geo-
replication ❌" and "RSNULL 🟡" cost the same one row, though only one of them would
stop a deployment. **Four of the eight ❌ rows are structural, not backlog**:
geo-replication, cloud log sinks, public-CA/ACME enrollment and confidential-compute
key release are cloud-platform or third-party-integration features a single
self-hosted binary does not have an equivalent for by design. The genuinely closable
❌ rows are certificate import, CSR merge, HMAC-on-symmetric-keys, and ACME
enrollment — the first two now have designs specified (see §4 above) but not yet
built. And **the
percentage measures breadth, not correctness** — the row that moved this number from
71% to 72% (§ B30, fixed 2026-08-20) was a plaintext-disclosure defect, worth far more
than the one point it scored.

*Reconciled 2026-08-19 against a full section-by-section re-verification (see the
dated notes throughout §§1-3, 5-7, 10). Two rows moved out of Partial entirely
(rotation-policy vault-scoping, Crypto User's `update`/`backup` gap — both closed
before this pass and now confirmed live); several new Partial findings surfaced in
§2 and §3 that predate this pass but had never been rolled up here.*

*Further reconciled 2026-08-19 (same day, separate plan — HSM secp256k1 +
AES-CBC/GCM, `docs/superpowers/specs/2026-08-19-hsm-secp256k1-aes-cbc-gcm-design.md`):
§3's EC curves, Sign/Verify — EC, and Wrap/Encrypt — AES rows, and §8's HSM-backed
keys row, are updated below to reflect the capability that plan closed — see the
dated notes in §3 and §8 for the full detail.*

**Strong parity (✅):** secret lifecycle + versioning, rotation policies (now
vault-scoped with a working auto-rotate scheduler, closed 2026-08-17, see §1),
certificate CRUD + policy + auto-renewal, multi-vault isolation, per-vault purge
protection that correctly cascades to contained items (closed 2026-08-18, see §5,
§7), vault-scoped deleted/restore/purge across all three resource types (closed
2026-08-13, see §5), AES-KW wrap and AES-CBC/GCM encrypt on HSM-backed keys now
closely matching Azure's oct-HSM Premium-preview coverage (closed 2026-08-19, see §3), and
and RBAC *architecture*: vault-scoped role assignments evaluated against
`model.azureRoleDataActions` with an access-policy explicit-deny override checked
first, matching Azure's real RBAC model. All eleven Azure role **bundles** are byte-for-byte
accurate against `model/azure_roles.go` (Crypto Officer is a true superset of Crypto
User including wrap/unwrap, Administrator carries no derived gaps, Data Access
Administrator enforces Azure's own eight-role grant allow-list, closed 2026-08-18,
see §6).

Role **boundaries** were found broken on 2026-08-20 and fixed the same day (§§ B30,
B31, commit `764a75e`): `Key Vault Reader` had read every historical plaintext secret
value in its vault, because `GET /secrets/{id}/versions` was filed under
`ActionSecretsReadMetadata` on the false premise that listing versions returned
metadata. The mapping was right; the handler violated it. Bundles and effective
boundaries now agree — but note the method point in §6: a correct bundle composed with
a wrong route→action mapping still yields a wrong permission, so bundle verification
alone can never establish boundary parity.

**Partial (🟡):**
- **Key operations beyond CRUD** (see §2): fixed 2026-08-19 (§ B26) — key
  *versions* are still archival by nature (`RotateKey` still archives the old
  material into `key_versions` and overwrites `keys.value` in place), but they
  are no longer a dead end: all six crypto operations
  (sign/verify/encrypt/decrypt/wrap/unwrap) now accept an optional `version`
  field and can address any archived version — pre-rotation ciphertexts and
  signatures are usable again over REST, matching Azure's model. The new `GET
  /keys/{id}/versions/{version}` route closed the missing-route gap for
  reading a version back. It initially returned bookkeeping metadata only
  (`model.KeyVersion{KeyID, Version, CreatedAt}`); as of 2026-08-20 it also
  returns that version's public JWK components, matching Azure's real
  `GET /keys/{name}/{version}` (§ B34). The CLI gap that made this REST-only is closed as
  of 2026-08-20: all four crypto CLI commands take a `--version` flag.
  Key backup/restore is fully at parity: registered on both route shapes,
  authorized by the RBAC data action plus a vault scope rather than item
  ownership, and carrying `key_versions` history across a backup/restore
  cycle. Rotation-policy scheduling
  genuinely executes the rotate lifetime action, and `expiry_days` is acted on
  as of 2026-08-19; `notify_before_expiry_days` is still stored and never read,
  so Azure's Notify lifetime action remains half-implemented. Per-vault webhook
  configuration landed 2026-08-20 — a notification now has a destination to be
  addressed to — but nothing sends yet, so no row moves on that alone.
- **Key types & algorithms** (see §3): P-256K's two REST bugs are both fixed — the
  validator rejection (2026-08-19, § B24) and the follow-up uncaught 500 on
  HSM-enabled instances (2026-08-19, § B25) — and, as of the same day, the
  underlying capability gap those bugs' error paths existed to protect is closed
  too: P-256K key creation, sign, and verify all now work end-to-end on both
  software-backed and HSM-enabled instances — the software-backed path verified
  live against a running server (pre-existing evidence), the HSM-backed path
  verified via live SoftHSM2 provider-level tests (`internal/crypto/pkcs11_provider_test.go`),
  not a running server or HTTP round-trip. Real-vendor-hardware secp256k1 support beyond
  SoftHSM2 remains unverified and genuinely uncertain (not a NIST-approved curve),
  with `isHSMCapabilityError` degrading a real rejection to a clean 400 rather than
  a leaked 500 either way. RSA1_5 exists for encrypt/decrypt only, not wrap
  (matching Azure's own "not recommended" posture on that algorithm). AES-CBC and
  AES-GCM are also now real, HSM-backed capabilities (same date, same plan), for
  Encrypt/Decrypt only — wrap/unwrap on HSM-backed keys stays AES-KW (and the
  RSA-OAEP variants), because the wrap/unwrap contract carries no IV field; see
  §3's *Scoped back* note. Together this closely matches — without exceeding —
  Azure's Managed-HSM/Premium-preview AES-KW/CBC/GCM coverage.
- **HSM** (see §8): PKCS#11 path exists but is not the default; as of 2026-08-19 it
  covers RSA (sign/verify/encrypt/decrypt), EC P-256/P-384/P-521/P-256K
  (sign/verify), and AES generate/wrap/unwrap (KW only) plus encrypt/decrypt (CBC,
  GCM — CBC and GCM are Encrypt/Decrypt-only because wrap/unwrap has no IV
  channel, see §3's *Scoped back* note) — every algorithm/curve gap that could be
  closed through code now is. No FIPS 140-3 L3
  validation remains (a certification process, not achievable through code) — the
  one permanent, non-code-closable caveat left on this row.
- **Access-policy engine** (see §6): a genuine architectural match to Azure's
  deny-overrides model, but simplified to two layers under one table rather than
  Azure's two fully separate, switchable engines — reasonable for a single
  self-hosted product, not a literal match.
- **Certificate User role** (see §6): placeholder parity — `ActionCertificatesRead`
  only, identical to Reader's certificate slice today, because RocketVault has no
  cert/key/secret linkage yet (Azure's version also reads the linked private key).

*Reconciled 2026-08-20. Six commits had landed since the last pass (secret
backup version-history follow-ups, the webhook config fixes, and a design spec);
the webhook configuration feature itself merged just before that pass and was
never recorded. Changes: §6's Reader row moved ✅ → ❌ on § B30, and §6's "Net"
conclusion was corrected on method — bundle verification cannot establish role
boundaries. §2's rotation-policy row and §9's cloud-sink row were reconciled
against what webhook configuration actually is (storage only; nothing sends).
§1's per-secret backup row gained the § F3 non-atomic-restore caveat. A
scorecard was added. **Deliberately not added: a ➕ row for webhooks.** Per the
sub-project 1 spec's own decision, a parity claim for CRUD with nothing wired to
it would be premature; the row belongs here when something delivers. Also
re-verified and unchanged at the time: key import was still unroutable
(`ActionKeysImport` appeared only in `model/azure_roles.go`, never in
`data_actions.go`), and the PKCS#11 provider still has no HMAC mechanism — see
the 2026-08-26 correction below for the first of those two. `GET /secrets` was
checked for the same defect as § B30 and is clean: `listSecrets`
(`api/secrets.go:391`) builds its response without values deliberately, which
is what makes the versions route an outlier rather than a pattern.*

*Corrected 2026-08-26: the "key import still unroutable" claim above, and its
restatement in the "Not supported" list below, went stale five days after this
reconciliation pass was written and were never updated. Key import shipped
2026-08-25 (§2's own "Import key" row already said so) — `POST /keys/import`
is registered on both the flat and vault-scoped routers (`api/keys.go:304`,
`registerKeyRoutes`), `mapKeyAction`'s `case "import"` in
`internal/services/authorization/data_actions.go:155-159` maps it to
`model.ActionKeysImport`, and the CLI wraps it at `cmd/keys/import.go`
(commits `cdbb5b9`, `d4dab13`, `92f4ad7`, `e23ec73`, all 2026-08-25). The
scorecard was never wrong — §2's per-row text and the 71%/55/77 scorecard both
already reflected this; only these two prose paragraphs lagged. Re-verified
during a wider `az keyvault` CLI-parity audit (2026-08-26) that also confirmed
the HMAC-on-symmetric-keys ❌ is still accurate.*

**Not supported (❌):** key release to confidential compute (TEE), HMAC
sign/verify on symmetric keys (implemented in the crypto-operations layer but
unreachable in practice — every oct key is HSM-backed and the PKCS#11 provider
has no HMAC mechanism), public-CA / ACME certificate enrollment,
geo-replication, and cloud log sinks (Event Hub / Azure Monitor archive). RSNULL is
intentionally omitted (TLS edge case, deprecated).

**RocketVault extras (➕) beyond Azure vaults:** secret generate + bulk export/import,
whole-instance backup/restore spanning every vault in a single file (broader than,
not a like-for-like match with, Azure's per-object backup model — see §10), JWKS
endpoint with rotating signing keys (os_store / self_pki / external_pki), hash-chained
tamper-evident audit log, built-in SOC 2 / GDPR compliance reports, per-IP rate
limiting, health probes, and fully self-hosted operation with no cloud dependency.

---

*Sources: codebase (`api/`, `internal/services/keys`, `internal/crypto`, `model/`,
`cmd/`) and Microsoft Learn — Azure Key Vault Overview and "Key types, algorithms,
and operations" (`about-keys-details`), retrieved 2026-06-02.*
