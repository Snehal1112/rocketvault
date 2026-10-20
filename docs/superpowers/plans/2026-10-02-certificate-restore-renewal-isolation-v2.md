# Certificate Restore and Renewal Isolation Implementation Plan (v2)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Supersedes:** `docs/superpowers/plans/2026-09-30-certificate-restore-renewal-isolation.md` (v1). v1 was written against the tree of 2026-09-30 and must not be executed: it predates certificate versioning, certificate and key export, the HTTP renew route, B86 and the authorization plan, and several of its steps would now delete working code (see "Why v1 must not run" below). This plan was rewritten against HEAD `b654fad3` on branch `v-4.0.0`.

**Goal:** Stop a forged or cross-vault certificate backup from steering the auto-renew scheduler into other vaults, make certificate issuance and renewal respect the signing key's lifecycle and the `keys/sign` data action on every entry point (HTTP create, HTTP renew, CLI create, CLI renew, the scheduler), and fix two small certificate-creation error-mapping and input defects.

**Architecture:** Per-item backup blobs become sealed (AES-256-GCM through `common.EncryptWithKey`, under a key derived from the master key with HKDF-SHA256), wrapping the existing version-aware envelope unchanged, so only blobs this server produced restore. `RestoreCertificate` additionally drops `key_id`/`ca_cert_id` links, on the current row and on every archived version record, that do not resolve in the target vault. The scheduler renews under `model.NewVaultScope(cert.VaultID, cert.UserID)`, so `GetCertificate`, the key read and `ArchiveAndRenew`'s scoped `UPDATE` all carry the vault predicate. Key lifecycle is enforced in the certificate service (leaf key on create and renew, and the CA row's own linked key). The `keys/sign` requirement is enforced at every authorization entry point through one shared helper, `authorization.RequireDataPlaneAccess`, which the CLI's `vaultcli.RequireDataAction` also delegates to. Error mapping and a validity cap are additive edits in `api/` plus service-side guards so the CLI gets the same bound.

**Tech Stack:** Go 1.25 (`go.mod`; stdlib `crypto/hkdf`, `crypto/sha256`), Gorilla Mux, Cobra, testify, ozzo-validation, golangci-lint under the cached go1.25.7 toolchain.

**Spec and sources:**
- Unfiled High finding (filed as **B76** in Task 3): a forged or cross-vault certificate restore blob plants key and CA links that the auto-renew scheduler follows with an admin scope. Same class as `.claude/known-bugs.md` § B15 (restore wrote the blob's vault) and § B32 (creation authorized its key by ownership, not vault).
- GitHub issue #43, "Certificate create and renew ignore key lifecycle and do not require the sign action", tracked as **B77**.
- Two unfiled Low findings (filed as **B78** in Task 10): signing-key and CA refusals on certificate creation answer 500; `validity_days` has no upper bound.
- Related open entry: § B88 (secret restore trusts an unauthenticated blob). Sealing closes its forged-blob half; its validation half stays open (Task 11 updates the entry).
- Precedent: § B15, § B32, § B33 (CLI/HTTP policy-operation parity), § B37 (CA link is set at creation and never rewritten), § B43/§ B44 (CA keyCertSign), § B86 (`writeCertificateError` and the name-taken arm).
- Design docs this plan amends: `docs/superpowers/specs/2026-10-01-certificate-versioning-design.md` §6 ("a pre-change blob restores unchanged") and `docs/superpowers/specs/2026-10-01-certificate-and-key-export-design.md` ("Blobs written before this change restore unchanged"). Both promises end with sealing (Decision D1).

**Priority:** P1. **B-number range:** B76-B78 (Decision D3).

**Scratch verification:** every production and test change in Tasks 1-10 was applied to a scratch copy of HEAD `b654fad3` (`git archive`, outside the repository) and checked there: `go build ./...`, `go vet ./...` and `go test -p 2 ./... -count=1` all passed, and golangci-lint (go1.25.7) reported no finding on any new or changed line. Each task's "Expected" output is what that run printed. The repository itself was not modified.

---

## Prerequisites (all landed)

| Prerequisite | State at `b654fad3` | Evidence |
|---|---|---|
| Authorization policy and audit plan (B79-B81) | Landed, v4.10.0 | `RevokeAssignment(ctx, assignmentID, vaultID, actorID uuid.UUID, callerIsGlobalAdmin bool)` at `internal/services/authorization/role_assignment_service.go:93`; the test double at `internal/services/authorization/data_action_authz_test.go:33` already has that signature; `api.VerifyRouteAuthorization` at `api/route_authorization.go`; `Context.auditDenied` at `api/context.go:124` |
| Secrets and error responses plan (B82-B84) and B86 | Landed, v4.7.1 | `writeCertificateError` already has the `repositories.ErrNameTaken` arm (`api/errors_certificate.go:35-36`); `createCertificate` already routes service errors through `writeCertificateError` (`api/certificates.go:236-243`); `SetInternalError` no longer echoes error text (`api/context.go:171`) |
| Identity and login rate limiting plans | Landed, v4.8.0 and v4.9.0 | `docs/release-notes/v4.8.0-identity-sessions-hardening.md`, `v4.9.0-login-rate-limiting.md` |
| Certificate versioning | Landed | `certificate_versions` table, `CertificateVersionRepository.ArchiveAndRenew` (`internal/repositories/certificate_version_repository.go:74`), version-aware backup (`internal/backup/item_backup.go:380-401`, `:417-465`), HTTP renew route (`api/certificates_versions.go:150`) |
| Certificate and key export, CLI export | Landed | `exportable` flag, `ExportCertificate` (`internal/services/certificates/certificate_export.go`), exporter roles (`model/azure_roles.go:158-163`), restore forces `Exportable = false` (`internal/backup/item_backup.go:312`, `:437`) |

No other plan has to land first. The INDEX (`docs/superpowers/plans/2026-09-30-api-audit-fixes-INDEX.md`) still lists v1; update its row to point here when this plan is approved.

---

## What changed since v1, task by task

| v1 task | Verdict | Why (evidence at `b654fad3`) |
|---|---|---|
| 1 Scheduler vault scope | Keep, re-anchored | Still `model.NewAdminScope(cert.UserID)` at `internal/services/certificates/renewal_service.go:80`. Now also scopes `ArchiveAndRenew`'s `UPDATE` (`certificate_version_repository.go:92-98`), pinned by the existing `TestArchiveAndRenew_OutOfScopeWritesNothing`. |
| 2 Seal blobs | Rework | Envelope is now version-aware: `BackupCertificate` passes `blobVersions{Certificate: versions}` (`item_backup.go:400`); v1 would replace it with `blobVersions{}` and drop history. Five more test files hand-build blobs (`item_backup_cert_versions_test.go:123`, `:210`, `item_backup_exportable_test.go:26`, `:34`, `item_backup_test.go:923`); v1's sed misses two of the files, and `TestRestoreCertificate_RejectsInconsistentVersionNumbers` would pass vacuously on `ErrUnsealedBlob`. Container wiring anchor moved (`service_container.go:749-764`, `SetCertificateVersionRepository` now follows `SetTxBeginner`), and `rocketvault/common` is already imported. |
| 3 Drop foreign links at restore | Rework | Still open: `RestoreCertificate` overrides only ID, user, vault and `Exportable` (`item_backup.go:433-437`). Archived `CertificateVersionRecord`s carry their own `KeyID` (`model/certificate.go:169`) which v1 ignored. |
| 4 Shared data-plane helper | Keep, rework as an edit | `data_action_authz.go` has no `ErrDataPlaneDenied`/`RequireDataPlaneAccess`; the two-stage check is duplicated in `cmd/vaultcli/vault.go:55-66`. v1 replaced the file wholesale; this plan edits it. |
| 5 Signing-key lifecycle | Rework | `ValidateKeyOwnership` (`certificate_service.go:1292-1307`) still ignores `Revoked`/`Enabled`/window. `RenewCertificate` no longer calls it: it reads and owner-checks the key inline (`:993-1001`), so v1's "renew inherits the check" is false. Fixture list re-derived: 26 `model.Key` literals in 7 files. |
| 6 CA's own key | Keep, re-anchored, fixture list extended | Gates go after `:510-513` and `:906-909`. One more fixture test exists (`TestRenewCertificate_ResultReportsExportableAndKeyAlgorithm`, covered by the fixture edit). |
| 7 keys/sign on HTTP and CLI | Rework | v1 said "there is no HTTP renew route"; there is (`api/certificates_versions.go:150`), and the MCP `renew_certificate` tool reaches it. Its handler tests build `vaultSvcTestContainer`, whose policy getter panics (`api/vault_test.go:253-258`). |
| 8 Scheduler re-checks keys/sign | Keep | Plus `versioning_integration_test.go:178-182` now builds a scheduler and needs the authorizer. |
| 9 Error mapping | Shrink | B86 already routes create errors through `writeCertificateError`. Still open: `ValidateKeyOwnership`/`ValidateCertificateAccess` return plain strings (`:1255`, `:1260`, `:1298`, `:1303`), so those refusals reach `default:` and answer 500. v1's "bring the switch to the following" would delete five live arms. Additive arms only, plus a missing-CA sentinel v1 left as a limitation. |
| 10 Validity cap | Rework | No cap anywhere (`internal/validation/certificate_validation.go`). Also needed on the HTTP renew body (`api/certificates_versions.go:159`), and `CurrentValidityDays` must clamp or auto-renew of pre-cap certificates breaks. |
| 11 Release note | Rework | v4.8.0 is taken (identity); next free is v4.11.0. Docs list extended (journeys, journeybook, MCP guide, parity, admin manual). |

### Why v1 must not run

These v1 steps damage features that landed after it was written:

1. v1 lines 759-767 replace `return encodeBlob("certificate", id.String(), cert, blobVersions{})`. The current call passes `blobVersions{Certificate: versions}`; reproducing v1's replacement drops every archived version from every new certificate backup.
2. v1 lines 2730-2756 ("bring the `switch` in `writeCertificateError` to the following") list only the four pre-versioning arms. Applied, it deletes the `ErrCertificateVersionNotFound` (404), `ErrInvalidCertificateVersionAttributes` (400), `ErrCertificateVersionConflict` (409) and `ErrNameTaken` (409, B86) arms, breaking the versions API and B86.
3. v1 line 1971 ("There is no HTTP renew route ..., so renew is CLI-only") leaves `POST .../certificates/{id}/renew` and the MCP `renew_certificate` tool without `keys/sign`: a new HTTP/CLI divergence of exactly the B33 class.
4. v1 line 1507 ("RenewCertificate inherit[s] the check because [it] already call[s] ValidateKeyOwnership") leaves renewal with no lifecycle check.
5. v1 lines 402-409 (the sed over three backup test files) miss `item_backup_cert_versions_test.go` and `item_backup_exportable_test.go`; `TestRestoreCertificate_RejectsInconsistentVersionNumbers` would keep passing only because the seal refuses its blob, hiding any regression in version validation.
6. v1 line 879 adds `"rocketvault/common"` to the container imports; it is already there (duplicate import, build failure).
7. v1 Task 11 creates `v4.8.0-...`, a version already shipped by the identity plan.

---

## Decisions to make before execution

The plan is written for the recommended option of each. Where another option is chosen, the affected steps are named.

**D1. Seal blobs (recommended), authenticate only, or neither.**
- (a) **AES-256-GCM seal with an HKDF-derived key, pre-upgrade blobs refused (written here).** Closes the forged-link path (B76), the forged `pkcs11:` handle path for HSM keys, and the forged-blob half of B88; hides names, tags and IDs in a blob. Cost: every blob taken before the upgrade stops restoring, which breaks the "pre-change blob restores unchanged" promise of the versioning and export designs. A blob never survived a master-key rotation anyway (its values are master-key ciphertext).
- (b) HMAC-SHA256 tag, envelope stays readable base64url JSON. Same compatibility break, no confidentiality gain. Changes Task 2 only.
- (c) No seal; rely on Task 3's link dropping plus validation. Leaves HSM-handle forgery and B88 open. Drops Task 2.
- (d) Seal, plus a time-boxed opt-in (`backup.accept_unsealed_item_blobs`) for pre-upgrade blobs. Not recommended: an accepted unsealed blob is indistinguishable from a forged one, so the flag reopens the HSM-handle path for as long as it is on.

**D2. The Certificates Officer breaking change.**
- (a) **Require a `keys/sign` role grant plus no explicit deny on `(keys, sign)` (written here).** Evidence that the practical blast radius is small: issuance already requires the caller to *own* the key (`ValidateKeyOwnership`, B32), and Certificates Officer cannot create keys, so a Certificates-Officer-only principal can only issue over keys it created while it held a key-creating role, which is exactly the "lost key access but keeps signing" case #43 describes. The P2 role backfill already gave every key owner Crypto Officer (`internal/db/role_backfill.go:74`). Azure differs (a certificate there creates its own key), which is why this is a documented divergence, not parity.
- (b) Enforce only the explicit deny on `(keys, sign)` plus lifecycle, no role requirement. Non-breaking, and acceptable under #43's "sign data action **or** sign policy operation" wording, but a principal stripped of every key role keeps signing with keys it owns. Changes Tasks 7 and 8 (use only the policy half).
- The exporter roles do not change this: Key Vault Certificate Exporter and Key Vault Key Exporter grant only `certificates/export` and `keys/export` (`model/azure_roles.go:229-234`) and neither can issue; an exportable certificate still requires an exportable key at creation, unchanged.
- Side finding for the docs task: `docs/VAULT_USER_ACCESS_JOURNEYS_v3.md` Journey Q has Noor issue certificates over keys Sofia created. That already fails today on the B32 owner check, independent of this plan; Task 11 fixes the journey.

**D3. B-numbers.** B76, B77 and B78 are reserved by the INDEX and unused anywhere in `.claude/known-bugs.md`; the highest used number is B98. Recommended: keep B76-B78 (entries are not kept in numeric order; B86 already precedes B82). Alternative: B99-B101; replace the numbers throughout.

**D4. Status codes.** Recommended (written here): on create, a foreign key or CA is 403, an unusable key is 403 (matches `writeKeyError` for crypto lifecycle), a missing key or CA is 404, an over-long validity is 400. On the renew route, an unusable key and a missing signing CA are 409, matching that route's existing convention that a state the caller can fix is 409 (`api/errors_certificate.go:46-62`). Alternative: 403 for unusable keys on both routes; drop the renew-specific arm in Task 9.

**D5. Long-lived certificates and the cap.** Recommended (written here): `CurrentValidityDays` clamps to 36500, so a certificate issued before the cap with a longer period keeps auto-renewing, at the capped period. Alternative: no clamp; such certificates stop auto-renewing with `ErrInvalidValidityDays` until an operator renews them explicitly.

**D6. Restored CA certificates.** A CA restored into a vault where its key does not resolve loses its `key_id`, and Task 6 refuses a CA with no key link as a signer, so it can never sign again; re-issue it. Recommended: accept (every consequence of a dropped link is a refusal). There is no safe way to re-link by name.

**D7. Release version.** v4.11.0, provisional, as every recent note says.

---

## Breaking changes (all go in the release note, Task 12)

1. Per-item backup blobs are sealed; blobs taken before the upgrade, edited blobs and blobs sealed under another master key are refused with 400.
2. Issuing or renewing a certificate needs `Microsoft.KeyVault/vaults/keys/sign/action` in the vault, and an explicit deny on `(keys, sign)` blocks it: `POST .../certificates`, `POST .../certificates/{id}/renew`, the MCP `create_certificate` and `renew_certificate` tools, `rocketvault certificate create` and `rocketvault certificate renew`. Key Vault Certificates Officer alone is no longer enough.
3. Auto-renewal renews under the certificate's vault scope, skips rows with no vault, and stops for owners who no longer hold `keys/sign` there.
4. A revoked, disabled, expired or not-yet-active key cannot issue or renew a certificate, as a leaf key or as a CA's own key. A CA with no recorded key cannot sign.
5. A certificate restored into a vault where its key or signing CA does not exist loses those links (also on its archived versions) and will not renew there.
6. `validity_days` is capped at 36500 on create and renew (HTTP 400; CLI error). A renewal that keeps the current period is clamped to 36500.
7. Status codes: certificate creation answers 403 or 404 instead of 500 for foreign, unusable or missing keys and CAs; the renew route answers 409 instead of 500 for an unusable key or a missing signing CA.

---

## Global Constraints

- **Commits** go through the `dev-workflow-skills:1-git-commit` plugin skill (Skill tool), never a freeform `git commit -m`. Every commit and tag is GPG signed with key `61D246B30285ED35`.
- **Comments** are short full sentences ending with a punctuation mark. No emojis anywhere.
- **Lint base.** Before Task 1, record the starting commit once: `git rev-parse HEAD > .git/rv-cert-isolation-base`. Later steps read it with `BASE=$(cat .git/rv-cert-isolation-base)`. The file lives inside `.git`, so it is never committed.
- **Lint command.** `PATH="$HOME/go/pkg/mod/golang.org/toolchain@v0.0.1-go1.25.7.linux-amd64/bin:$PATH" GOTOOLCHAIN=local ~/go/bin/golangci-lint run --new-from-rev="$BASE" <packages>`. It must print `0 issues.`. New tests use `httptest.NewRequestWithContext(context.Background(), ...)`, never `httptest.NewRequest`, or `noctx` reports them. `api/certificates_test.go` already has an import-order gofmt finding at HEAD; leave it unless that file's imports change.
- **mockery.** No interface in this plan changes (`CertificateService`, `CertificateRenewalService`, `RoleAssignmentService` and `AccessPolicyService` keep their method sets), so mockery is not run. If a task ever needs it, regenerate from the repo root with `PATH="$HOME/go/pkg/mod/golang.org/toolchain@v0.0.1-go1.25.7.linux-amd64/bin:$PATH" GOTOOLCHAIN=local ~/go/bin/mockery`, and never run `~/go/bin/mockery --version` (it starts a full generation run).
- **Tests** run with `-p 2`; if the sandbox hits `newosproc`, prefix `GOMAXPROCS=1`.
- **Hard gates before any PR:** `go build ./...`, `go vet ./...`, `go test -p 2 ./... -count=1`, and the lint command above over every changed package, all clean.
- **CLI parity.** CLI commands call the service layer directly and bypass `PolicyMiddleware`, so every authorization change is tested on the HTTP path and on the CLI path.
- **Repositories stay pure CRUD.** No repository file, schema or `internal/db/db.go` change in this plan.
- **Additive switch edits only.** `writeCertificateError` and `writeCertificateRenewError` gain arms; no existing arm is removed, reordered past, or rewritten.
- **Version-aware backup is preserved.** The seal wraps `encodeBlob`'s output unchanged; `blobVersions{Secret: ...}`, `{Key: ...}` and `{Certificate: ...}` stay exactly as they are.
- **Exportability is never granted by restore.** `RestoreKey` and `RestoreCertificate` keep forcing `Exportable = false`, sealed blob or not.
- **Constants:** sealed blob prefix `rvb2.`; HKDF info `rocketvault item-backup blob seal v2`; derived key 32 bytes; `model.MaxCertificateValidityDays = 36500`.
- **The B32 owner comparison stays** in `ValidateKeyOwnership`, `ValidateCertificateAccess` and `RenewCertificate`; this plan does not widen it.
- **Known-bugs entries** follow the § B86 shape (Status, Severity, Files, Symptom, Root cause, What was fixed, decisions, Pinned by) and are inserted immediately before the line `## Deferred Refactors`. Every new entry gets a matching GitHub issue titled `B<N>: <summary>` with the `bug` label and a `Full detail: .claude/known-bugs.md § B<N>` pointer (convention at `.claude/known-bugs.md:6-12`). B77 reuses #43. Commits that close an issue carry a `Fixes #N` footer.
- **Documentation** goes under `.claude/` or `docs/`, never a new top-level file.

---

## Review Focus

1. **A forged or pre-upgrade blob must be refused and write nothing.** Pins: `TestRestoreCertificate_RejectsLegacyUnsealedBlob`, `TestRestoreKey_RejectsForgedHSMHandle` (Task 2, `internal/backup/item_backup_seal_test.go`), `TestRestoreCertificateHandler_LegacyUnsealedBlob_Returns400` (Task 2, `api/backup_item_seal_test.go`).
2. **Sealing must not drop or weaken version history.** Pins: `TestBackupCertificate_SealedBlobKeepsVersionHistory` (Task 2), the existing `TestCertificateBackupRestore_RoundTripsVersions` and `TestRestoreCertificate_FailedReplayRollsBackRestore` unmodified, and `TestRestoreCertificate_RejectsInconsistentVersionNumbers`, which now also asserts the refusal is not the seal's (Task 2).
3. **A tampered blob or one sealed under another master key is unauthenticated, and an unwired service fails closed.** Pins: `TestRestore_RejectsTamperedBlob`, `TestRestore_RejectsBlobSealedUnderAnotherMasterKey`, `TestItemBackup_FailsClosedWithoutSealKey` (Task 2), `TestItemBackupService_SealedWhenMasterKeyConfigured` (Task 2, container).
4. **A same-vault restore keeps every link and every version; a cross-vault restore keeps the history but no foreign link.** Pins: `TestRestoreCertificate_KeepsSameVaultReferences`, `TestRestoreCertificate_DropsCrossVaultReferences`, `TestRestoreCertificate_CrossVaultKeepsHistoryDropsVersionKeyLinks` (Task 3).
5. **The scheduler never renews under a broader scope or for an owner who lost `keys/sign`.** Pins: `TestCheckAndRenewCertificates_AutoRenew`, `TestCheckAndRenewCertificates_NilVaultSkipped` (Task 1), `TestCheckAndRenewCertificates_RefusesWhenOwnerCannotSign`, `TestCheckAndRenewCertificates_RefusesWithoutSignAuthorizer` (Task 8), and the existing `TestArchiveAndRenew_OutOfScopeWritesNothing`.
6. **Every issuing entry point requires `keys/sign`, including the HTTP renew route.** Pins: `TestCreateCertificate_RequiresKeySign`, `TestCreateCertificate_KeySignDenyPolicyRefuses`, `TestRenewCertificate_RequiresKeySign` (Task 7, `api/certificates_key_sign_test.go`), `TestCertCreateCmd_RequiresKeySign`, `TestCertRenewCmd_RequiresKeySign` (Task 7, `cmd/certificates/key_sign_test.go`).
7. **No live error arm disappears.** Pins: the existing `TestRenewCertificate_Statuses`, `TestUpdateCertificateVersion_Statuses`, `TestWriteErrors_NameTaken_Returns409WithoutDriverText` and `TestCertificateVersionRoutes_BothShapes`, all unmodified except the one-line `allowKeySignOn(api)` addition in the last (Task 7), plus `TestCreateCertificate_MapsSigningKeyErrors` and `TestRenewCertificate_MapsUnusableSigningMaterialTo409` (Task 9).
8. **Pre-cap certificates keep auto-renewing.** Pin: `TestCurrentValidityDays_ClampedToMaximum` (Task 10).

---

## File Structure

| File | Change |
|---|---|
| `internal/services/certificates/renewal_service.go` | Vault scope, nil-vault skip, `KeySignAuthorizer`, clamp in `CurrentValidityDays` (Tasks 1, 8, 10) |
| `internal/backup/blob_seal.go` (create) | `SetSealKey`, `sealBlob`, `openBlob`, three sentinels (Task 2) |
| `internal/backup/item_backup.go` | Seal and open in the six backup/restore methods; `dropForeignReferences` (Tasks 2, 3) |
| `internal/container/service_container.go` | Seal key wiring, renewal `SignAuthorizer` (Tasks 2, 8) |
| `internal/services/authorization/data_action_authz.go` | `ErrDataPlaneDenied`, `RequireDataPlaneAccess` (Task 4) |
| `cmd/vaultcli/vault.go`, `cmd/vaultcli/session.go` | Delegate to the shared check; `Session.RequireAlso` (Task 4) |
| `internal/services/certificates/certificate_service.go` | Sentinels, key lifecycle, CA-key gate, validity cap (Tasks 5, 6, 9, 10) |
| `api/certificates.go`, `api/certificates_versions.go` | `requireKeySign` on create and renew; validity bound on create and renew (Tasks 7, 10) |
| `api/errors_certificate.go` | Additive arms (Tasks 9, 10) |
| `cmd/certificates/create.go`, `cmd/certificates/renew.go` | `RequireAlso`, help text (Tasks 7, 10) |
| `internal/vaultapi/errors.go` | 403 hint names `keys/sign` for issuance (Task 7) |
| `internal/validation/certificate_validation.go`, `model/certificate.go` | Validity cap (Task 10) |
| Tests (create) | `internal/backup/seal_helpers_test.go`, `internal/backup/item_backup_seal_test.go`, `internal/backup/item_backup_cert_refs_test.go`, `api/backup_item_seal_test.go`, `internal/container/item_backup_seal_test.go`, `internal/services/authorization/data_plane_access_test.go`, `cmd/vaultcli/require_also_test.go`, `internal/services/certificates/signing_key_lifecycle_test.go`, `api/certificates_key_sign_test.go`, `api/certificates_error_mapping_test.go`, `cmd/certificates/key_sign_test.go` |
| Tests (modify) | listed per task |
| Docs (Tasks 11, 12) | `.claude/known-bugs.md`, `.claude/azure-keyvault-parity.md`, `CLAUDE.md`, `model/key.go`, `model/secret.go` comments, `docs/cli-guide.md`, `README.md`, `docs/mcp-server.md`, `docs/api-developer-guide.md`, `docs/admin-manual.html`, `docs/VAULT_USER_ACCESS_JOURNEYS_v3.md`, `journeybook/src/data/journeys-n-u.ts`, the two 2026-10-01 specs, `docs/release-notes/v4.11.0-certificate-restore-renewal-isolation.md` (create), `scripts/docsgen/docs.go` |

---

### Task 1: The scheduler renews under the certificate's vault scope (B76)

**Files:**
- Modify: `internal/services/certificates/renewal_service.go:6-13` (imports), `:76-80` (AutoRenew branch)
- Test: `internal/services/certificates/renewal_service_test.go:187-219` (`TestCheckAndRenewCertificates_AutoRenew`), new test after it
- Test: `internal/services/certificates/certificate_service_extended_test.go:1024-1056` (`TestCheckAndRenewCertificates_AutoRenewFailureSkipped`)
- Test: `internal/services/certificates/ca_renewal_scheduler_test.go:21-91` (`TestCheckAndRenewCertificates_CASignedKeepsIssuer`)

**Interfaces:**
- Consumes: `model.NewVaultScope(vaultID, actorID uuid.UUID) model.Scope`.
- Produces: no new API. `CheckAndRenewCertificates` calls `RenewCertificate(ctx, cert.ID, model.NewVaultScope(cert.VaultID, cert.UserID), validityDays)` and skips a row whose `VaultID == uuid.Nil`. Because `RenewCertificate` passes its scope to `versionRepo.ArchiveAndRenew`, the renewal's `UPDATE certificates ... WHERE id = ? AND version = ?` now also carries `AND vault_id = ?` (the existing `TestArchiveAndRenew_OutOfScopeWritesNothing` pins that predicate at repository level).

- [ ] **Step 0: Record the lint base (once, before any change)**

Run: `git rev-parse HEAD > .git/rv-cert-isolation-base && cat .git/rv-cert-isolation-base`
Expected: one commit hash (`b654fad3...` if nothing else landed). Skip this step if the file already exists.

- [ ] **Step 1: Write the failing tests**

In `internal/services/certificates/renewal_service_test.go`, replace the whole of `TestCheckAndRenewCertificates_AutoRenew` (lines 187-219) with:

```go
func TestCheckAndRenewCertificates_AutoRenew(t *testing.T) {
	expires := time.Now().Add(10 * 24 * time.Hour)
	certID := uuid.New()
	userID := uuid.New()
	vaultID := uuid.New()
	cert := model.Certificate{
		ID:          certID,
		UserID:      userID,
		VaultID:     vaultID,
		Name:        "test-cert",
		CreatedAt:   time.Now().Add(-365 * 24 * time.Hour),
		ExpiresAt:   &expires,
		AutoRenew:   true,
		RenewalDays: 30,
	}

	repo := &mockCertRepoForRenewal{}
	repo.On("ListAll", mock.Anything).Return([]model.Certificate{cert}, nil)

	// B76: the scheduler must renew inside the certificate's own vault. An
	// admin scope carries no vault predicate, so it let a restored row reach
	// keys and CA certificates in other vaults.
	certSvc := &mockCertSvcForRenewal{}
	certSvc.On("RenewCertificate", mock.Anything, certID, model.NewVaultScope(vaultID, userID), mock.AnythingOfType("int")).
		Return(&certificates.CreateCertificateResult{CertID: uuid.New()}, nil)

	svc := certificates.NewCertificateRenewalService(certificates.RenewalServiceConfig{
		CertRepository:     repo,
		CertificateService: certSvc,
		Logger:             newTestLogger(),
	})

	renewed, warned, err := svc.CheckAndRenewCertificates(context.Background())
	require.NoError(t, err)
	assert.Equal(t, 1, renewed)
	assert.Equal(t, 0, warned)
	certSvc.AssertExpectations(t)
}

// TestCheckAndRenewCertificates_NilVaultSkipped pins that a row with no vault
// is never renewed. There is no vault to scope the renewal to, and falling
// back to a broader scope is the B76 defect.
func TestCheckAndRenewCertificates_NilVaultSkipped(t *testing.T) {
	expires := time.Now().Add(10 * 24 * time.Hour)
	cert := model.Certificate{
		ID:          uuid.New(),
		UserID:      uuid.New(),
		Name:        "no-vault",
		CreatedAt:   time.Now().Add(-365 * 24 * time.Hour),
		ExpiresAt:   &expires,
		AutoRenew:   true,
		RenewalDays: 30,
	}

	repo := &mockCertRepoForRenewal{}
	repo.On("ListAll", mock.Anything).Return([]model.Certificate{cert}, nil)
	certSvc := &mockCertSvcForRenewal{}

	svc := certificates.NewCertificateRenewalService(certificates.RenewalServiceConfig{
		CertRepository:     repo,
		CertificateService: certSvc,
		Logger:             newTestLogger(),
	})

	renewed, warned, err := svc.CheckAndRenewCertificates(context.Background())
	require.NoError(t, err)
	assert.Equal(t, 0, renewed)
	assert.Equal(t, 0, warned)
	certSvc.AssertNotCalled(t, "RenewCertificate", mock.Anything, mock.Anything, mock.Anything, mock.Anything)
}
```

In `internal/services/certificates/certificate_service_extended_test.go`, inside `TestCheckAndRenewCertificates_AutoRenewFailureSkipped` only:
- after `userID := uuid.New()` (line 1027) add `vaultID := uuid.New()`;
- after `UserID:      userID,` (line 1033) add `VaultID:     vaultID,`;
- on line 1043 replace `model.NewAdminScope(userID)` with `model.NewVaultScope(vaultID, userID)`.

In `internal/services/certificates/ca_renewal_scheduler_test.go`:
- after `userID := uuid.New()` (line 24) add `vaultID := uuid.New()`;
- line 51: change `ID: certID, UserID: userID, KeyID: keyID, CACertID: &caCertID,` to `ID: certID, UserID: userID, VaultID: vaultID, KeyID: keyID, CACertID: &caCertID,`;
- line 57: change `ID: caCertID, UserID: userID, Name: "scheduler-ca",` to `ID: caCertID, UserID: userID, VaultID: vaultID, Name: "scheduler-ca",`;
- line 64: replace `adminScope := model.NewAdminScope(userID)` with `vaultScope := model.NewVaultScope(vaultID, userID)`, and rename the four later uses of `adminScope` (lines 66, 67, 68, 72) to `vaultScope`.

- [ ] **Step 2: Run the tests and confirm they fail**

Run: `go test ./internal/services/certificates/ -run 'TestCheckAndRenewCertificates' -count=1`
Expected: FAIL. `TestCheckAndRenewCertificates_CASignedKeepsIssuer` panics (`mock: I don't know what to return`, the scheduler still reads with an admin scope), which aborts the package run.

- [ ] **Step 3: Implement**

In `internal/services/certificates/renewal_service.go`, replace the import block (lines 6-13) with:

```go
import (
	"context"
	"time"

	"github.com/google/uuid"

	"rocketvault/internal/logging"
	"rocketvault/internal/repositories"
	"rocketvault/model"
)
```

Replace

```go
		if cert.AutoRenew {
			// Preserve the current version's validity period when renewing.
			validityDays := CurrentValidityDays(&cert)

			_, err := s.certSvc.RenewCertificate(ctx, cert.ID, model.NewAdminScope(cert.UserID), validityDays)
```

with

```go
		if cert.AutoRenew {
			// A row with no vault cannot be scoped to one, so it is never
			// renewed. Renewing under an admin scope is what let a restored
			// row reach keys and CA certificates in other vaults (B76).
			if cert.VaultID == uuid.Nil {
				s.logger.LogAuditError(cert.UserID.String(), "cert_auto_renew", "failed",
					"Auto-renewal skipped, certificate has no vault: "+cert.Name, nil)
				continue
			}

			// Preserve the current version's validity period when renewing.
			validityDays := CurrentValidityDays(&cert)

			// The renewal is scoped to the certificate's own vault, so its key
			// and CA links are only followed inside that vault, and
			// ArchiveAndRenew only updates a row in that vault (B76).
			_, err := s.certSvc.RenewCertificate(ctx, cert.ID, model.NewVaultScope(cert.VaultID, cert.UserID), validityDays)
```

- [ ] **Step 4: Run the tests and confirm they pass**

Run: `go test ./internal/services/certificates/ -count=1`
Expected: `ok  	rocketvault/internal/services/certificates`. (`TestCheckAndRenewCertificates_CreatesVersionWithPreservedValidity` in `versioning_integration_test.go` passes unchanged: its certificate is created with a vault.)

- [ ] **Step 5: Lint and commit**

Run: `BASE=$(cat .git/rv-cert-isolation-base); PATH="$HOME/go/pkg/mod/golang.org/toolchain@v0.0.1-go1.25.7.linux-amd64/bin:$PATH" GOTOOLCHAIN=local ~/go/bin/golangci-lint run --new-from-rev="$BASE" ./internal/services/certificates/`
Expected: `0 issues.`

Stage the four files of this task, then invoke the `dev-workflow-skills:1-git-commit` skill via the Skill tool. The subject should say the renewal scheduler now renews under the certificate's vault scope (B76). No `Fixes` footer yet.

---

### Task 2: Seal item-backup blobs under a master-key-derived key (B76)

**Files:**
- Create: `internal/backup/blob_seal.go`
- Modify: `internal/backup/item_backup.go:68-78` (struct), `:173` (`BackupSecret`), `:186-187` (`RestoreSecret`), `:296` (`BackupKey`), `:302-303` and `:310-311` (`RestoreKey`), `:400` (`BackupCertificate`), `:422-423` (`RestoreCertificate`)
- Modify: `internal/backup/export_test.go`
- Modify: `internal/container/service_container.go:763-766` (after `SetCertificateVersionRepository`)
- Create: `internal/backup/seal_helpers_test.go`, `internal/backup/item_backup_seal_test.go`, `api/backup_item_seal_test.go`, `internal/container/item_backup_seal_test.go`
- Modify (mechanical): `internal/backup/item_backup_test.go`, `internal/backup/backup_edge_test.go`, `internal/backup/item_backup_atomicity_test.go`, `internal/backup/item_backup_cert_versions_test.go`, `internal/backup/item_backup_exportable_test.go`, `api/backup_item_test.go`

**Interfaces:**
- Consumes: `common.EncryptWithKey(value string, key []byte) (string, error)`, `common.DecryptWithKey(encryptedValue string, key []byte) (string, error)`, `common.ParseMasterKey(encoded string) ([]byte, error)` (`common/encrypt.go:126`, `:154`, `:190`); `crypto/hkdf.Key[H hash.Hash](h func() H, secret, salt []byte, info string, keyLength int) ([]byte, error)`.
- Produces:
  - `func (s *ItemBackupService) SetSealKey(masterKey []byte) error`
  - `var ErrSealKeyUnset, ErrUnsealedBlob, ErrBlobAuthentication error` in package `backup`; `ErrUnsealedBlob` and `ErrBlobAuthentication` are always wrapped together with `ErrInvalidBlob`, so the existing restore handlers map them to 400 with no handler change.
  - unexported `sealBlob(inner string) (string, error)`, `openBlob(blob string) (string, error)`, const `sealedBlobPrefix = "rvb2."`
  - test-only: `backup.ExportedSealedBlobPrefix`, `(*ItemBackupService).ExportedSealBlob`, `(*ItemBackupService).ExportedOpenBlob`; `newTestItemBackupService(...)` and `sealForTest(t, svc, inner)` in `backup_test`; `newSealedItemBackupService(...)` in `api` tests.
- The envelope (`backupEnvelope`, `encodeBlob`, `decodeBlob`, `blobVersions`) is untouched: the seal wraps `encodeBlob`'s output, so every version field keeps working, including pre-versioning inner shapes sealed by a test.

Decisions recorded in § B76 (Task 3): pre-upgrade blobs are refused, with no opt-in (D1); a genuine HSM-key blob restored into another vault still points at the same HSM object, which is what backup plus restore means and is accepted; restore keeps forcing `Exportable = false`.

- [ ] **Step 1: Add the test helpers and the test-only exports**

Create `internal/backup/seal_helpers_test.go`:

```go
package backup_test

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/require"

	"rocketvault/internal/backup"
	"rocketvault/internal/repositories"
)

// testMasterKey is a fixed 32-byte master key used only by tests.
var testMasterKey = bytes.Repeat([]byte{0x42}, 32)

// newTestItemBackupService builds an ItemBackupService with its seal key set,
// so tests exercise the sealed blob format production uses.
func newTestItemBackupService(
	secretRepo repositories.SecretRepositoryInterface,
	keyRepo repositories.KeyRepositoryInterface,
	certRepo repositories.CertificateRepositoryInterface,
	versionRepo repositories.SecretVersionRepositoryInterface,
) *backup.ItemBackupService {
	svc := backup.NewItemBackupService(secretRepo, keyRepo, certRepo, versionRepo)
	if err := svc.SetSealKey(testMasterKey); err != nil {
		panic(err)
	}
	return svc
}

// sealForTest seals a hand-built inner envelope with svc's key. Tests that
// restore an inner shape no Backup call produces today use it.
func sealForTest(t *testing.T, svc *backup.ItemBackupService, inner string) string {
	t.Helper()
	blob, err := svc.ExportedSealBlob(inner)
	require.NoError(t, err)
	return blob
}
```

Replace the whole of `internal/backup/export_test.go` with:

```go
package backup

// Test-only aliases. This file is compiled only under `go test`, so these
// export nothing to production consumers.

type ExportedBlobVersions = blobVersions

var (
	ExportedEncodeBlob = encodeBlob
	ExportedDecodeBlob = decodeBlob
)

// ExportedSealedBlobPrefix is the sealed-format marker, for format tests.
const ExportedSealedBlobPrefix = sealedBlobPrefix

// ExportedSealBlob seals a hand-built inner envelope, so a test can restore
// an older or deliberately inconsistent inner shape through the real seal.
func (s *ItemBackupService) ExportedSealBlob(inner string) (string, error) {
	return s.sealBlob(inner)
}

// ExportedOpenBlob unseals a blob this service produced and returns its inner
// envelope, so a test can decode what a Backup method returned.
func (s *ItemBackupService) ExportedOpenBlob(blob string) (string, error) {
	return s.openBlob(blob)
}
```

Swap every existing test to a sealed service:

```bash
sed -i 's/backup\.NewItemBackupService(/newTestItemBackupService(/g' \
  internal/backup/item_backup_test.go \
  internal/backup/backup_edge_test.go \
  internal/backup/item_backup_atomicity_test.go \
  internal/backup/item_backup_cert_versions_test.go \
  internal/backup/item_backup_exportable_test.go
sed -i 's/backup\.NewItemBackupService(/newSealedItemBackupService(/g' api/backup_item_test.go
sed -i '/^\t"rocketvault\/internal\/backup"$/d' internal/backup/item_backup_atomicity_test.go
```

The third command removes the import that `item_backup_atomicity_test.go` no longer uses (line 19). Every other swapped file still uses another `backup.` identifier and keeps its import. In `api/backup_item_test.go` the sed also rewrites `buildValidSecretBlob`, `buildValidKeyBlob` and `buildValidCertBlob` (lines 483, 891, 1087), so every handler-test blob is sealed.

Five tests hand-build or decode a blob and need an edit, each because the format they construct no longer reaches `decodeBlob` unsealed.

(a) `internal/backup/item_backup_test.go`, `TestBackupSecret_CarriesVersionHistory`: replace

```go
	var restored model.Secret
	got, err := backup.ExportedDecodeBlob(blob, "secret", &restored)
	require.NoError(t, err)
	require.Len(t, got.Secret, 2, "both archived versions must reach the blob")
```

with

```go
	inner, err := svc.ExportedOpenBlob(blob)
	require.NoError(t, err)

	var restored model.Secret
	got, err := backup.ExportedDecodeBlob(inner, "secret", &restored)
	require.NoError(t, err)
	require.Len(t, got.Secret, 2, "both archived versions must reach the blob")
```

(b) `internal/backup/item_backup_test.go`, `TestRestoreSecret_OldFormatBlob_NoVersionsField`: replace

```go
	blob := base64.URLEncoding.EncodeToString(raw)

	repo := newStubSecretRepo()
	vr := newStubSecretVersionRepo()
	svc := newTestItemBackupService(repo, nil, nil, vr)
```

with

```go
	repo := newStubSecretRepo()
	vr := newStubSecretVersionRepo()
	svc := newTestItemBackupService(repo, nil, nil, vr)

	// The inner envelope keeps its pre-versions shape. Only the outer seal is
	// new, and every blob this server hands out carries it.
	blob := sealForTest(t, svc, base64.URLEncoding.EncodeToString(raw))
```

(c) `internal/backup/item_backup_cert_versions_test.go`, `TestRestoreCertificate_PreVersioningBlobRestoresAsVersionOne`: replace

```go
	blob, err := backup.ExportedEncodeBlob("certificate", id.String(), legacyCertificate{
		ID: id, UserID: f.userID, VaultID: f.vaultID, Name: "legacy", Certificate: "PEM",
		PrivateKey: "ENC", CreatedAt: time.Now().UTC(), Enabled: true,
	}, backup.ExportedBlobVersions{})
	require.NoError(t, err)
```

with

```go
	inner, err := backup.ExportedEncodeBlob("certificate", id.String(), legacyCertificate{
		ID: id, UserID: f.userID, VaultID: f.vaultID, Name: "legacy", Certificate: "PEM",
		PrivateKey: "ENC", CreatedAt: time.Now().UTC(), Enabled: true,
	}, backup.ExportedBlobVersions{})
	require.NoError(t, err)
	blob := sealForTest(t, f.svc, inner)
```

(d) `internal/backup/item_backup_cert_versions_test.go`, `TestRestoreCertificate_RejectsInconsistentVersionNumbers`: replace

```go
			blob, err := backup.ExportedEncodeBlob("certificate", id.String(), &model.Certificate{
				ID: id, Name: "forged", Certificate: "PEM", PrivateKey: "ENC", Enabled: true, Version: current,
			}, backup.ExportedBlobVersions{Certificate: records})
			require.NoError(t, err)

			newID := uuid.New()
			err = f.svc.RestoreCertificate(context.Background(), blob, f.userID, f.vaultID, newID)
			require.ErrorIs(t, err, backup.ErrInvalidBlob)
```

with

```go
			inner, err := backup.ExportedEncodeBlob("certificate", id.String(), &model.Certificate{
				ID: id, Name: "forged", Certificate: "PEM", PrivateKey: "ENC", Enabled: true, Version: current,
			}, backup.ExportedBlobVersions{Certificate: records})
			require.NoError(t, err)
			// Sealed, so the refusal below comes from the version check and
			// not from the seal.
			blob := sealForTest(t, f.svc, inner)

			newID := uuid.New()
			err = f.svc.RestoreCertificate(context.Background(), blob, f.userID, f.vaultID, newID)
			require.ErrorIs(t, err, backup.ErrInvalidBlob)
			require.NotErrorIs(t, err, backup.ErrUnsealedBlob)
			require.NotErrorIs(t, err, backup.ErrBlobAuthentication)
```

(e) `internal/backup/item_backup_exportable_test.go`, `TestRestore_ForcesExportableFalse`: replace its doc comment (lines 16-18) with

```go
// TestRestore_ForcesExportableFalse pins that a blob claiming exportable
// never restores an exportable item. The blob is sealed now, but the
// exportable decision belongs to the item's creator, so restore still forces
// it off.
```

then replace

```go
	keyBlob, err := backup.ExportedEncodeBlob("key", uuid.NewString(), &model.Key{
		Name: "k", Type: model.KeyTypeRSA, Value: "enc", Enabled: true, CreatedAt: time.Now(), Exportable: true,
	}, backup.ExportedBlobVersions{})
	require.NoError(t, err)
```

with

```go
	keyInner, err := backup.ExportedEncodeBlob("key", uuid.NewString(), &model.Key{
		Name: "k", Type: model.KeyTypeRSA, Value: "enc", Enabled: true, CreatedAt: time.Now(), Exportable: true,
	}, backup.ExportedBlobVersions{})
	require.NoError(t, err)
	keyBlob := sealForTest(t, svc, keyInner)
```

and replace

```go
	certBlob, err := backup.ExportedEncodeBlob("certificate", uuid.NewString(), &model.Certificate{
		Name: "c", Certificate: "pem", PrivateKey: "enc", Enabled: true, CreatedAt: time.Now(), Version: 1, Exportable: true,
	}, backup.ExportedBlobVersions{})
	require.NoError(t, err)
```

with

```go
	certInner, err := backup.ExportedEncodeBlob("certificate", uuid.NewString(), &model.Certificate{
		Name: "c", Certificate: "pem", PrivateKey: "enc", Enabled: true, CreatedAt: time.Now(), Version: 1, Exportable: true,
	}, backup.ExportedBlobVersions{})
	require.NoError(t, err)
	certBlob := sealForTest(t, svc, certInner)
```

Every other existing backup test is unaffected, checked by running them: `TestBlobEnvelope_*` encode and decode the inner envelope directly; the round-trip tests pass blobs between services that share `testMasterKey`; `TestRestoreKeyBlobError` and `TestRestoreCertificateBlobError` (`"!!!not-base64!!!"`, `"!!!bad!!!"`) and the API tests with `badBlob := "dGhpcyBpcyBub3QgYW4gZW52ZWxvcGU="` now fail in `openBlob` with `ErrUnsealedBlob` wrapped in `ErrInvalidBlob`, which still satisfies their assertions.

Create `api/backup_item_seal_test.go`:

```go
package api

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"

	"rocketvault/internal/backup"
	"rocketvault/internal/repositories"
	"rocketvault/model"
)

// apiTestSealKey is a fixed 32-byte master key used only by tests.
var apiTestSealKey = bytes.Repeat([]byte{0x42}, 32)

// newSealedItemBackupService builds an ItemBackupService with its seal key
// set, as the real container does.
func newSealedItemBackupService(
	secretRepo repositories.SecretRepositoryInterface,
	keyRepo repositories.KeyRepositoryInterface,
	certRepo repositories.CertificateRepositoryInterface,
	versionRepo repositories.SecretVersionRepositoryInterface,
) *backup.ItemBackupService {
	svc := backup.NewItemBackupService(secretRepo, keyRepo, certRepo, versionRepo)
	if err := svc.SetSealKey(apiTestSealKey); err != nil {
		panic(err)
	}
	return svc
}

// TestRestoreCertificateHandler_LegacyUnsealedBlob_Returns400 pins B76 on the
// HTTP path. A hand-written blob in the old base64url format names a key in
// another vault; it must be refused as a bad parameter and write nothing.
func TestRestoreCertificateHandler_LegacyUnsealedBlob_Returns400(t *testing.T) {
	raw, err := json.Marshal(map[string]any{
		"resource_type": "certificate",
		"resource_id":   uuid.New().String(),
		"data":          map[string]any{"name": "forged", "key_id": uuid.New().String(), "auto_renew": true},
	})
	if err != nil {
		t.Fatal(err)
	}
	legacy := base64.URLEncoding.EncodeToString(raw)

	created := false
	certRepo := &mockCertRepo{
		createFn: func(_ context.Context, _ *model.Certificate) error {
			created = true
			return nil
		},
	}
	c := newBackupCtxWithCert(certRepo)
	w := httptest.NewRecorder()
	body, _ := json.Marshal(map[string]string{"blob": legacy})
	r := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/certificates/restore", bytes.NewReader(body))

	restoreCertificateHandler(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.False(t, created, "a rejected blob must not reach the repository")
}
```

- [ ] **Step 2: Write the failing service tests**

Create `internal/backup/item_backup_seal_test.go`:

```go
package backup_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"rocketvault/internal/backup"
	"rocketvault/model"
)

// legacyBlob hand-builds a blob in the pre-sealing format: a bare base64url
// JSON envelope, which anyone can write.
func legacyBlob(t *testing.T, resourceType string, data any) string {
	t.Helper()
	raw, err := json.Marshal(data)
	require.NoError(t, err)
	env, err := json.Marshal(map[string]any{
		"resource_type": resourceType,
		"resource_id":   uuid.New().String(),
		"data":          json.RawMessage(raw),
	})
	require.NoError(t, err)
	return base64.URLEncoding.EncodeToString(env)
}

func TestBackupBlob_IsSealed(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	owner, vaultID := uuid.New(), uuid.New()
	repo := newStubCertRepo()
	cert := &model.Certificate{ID: uuid.New(), UserID: owner, VaultID: vaultID, Name: "sealed-cert"}
	require.NoError(t, repo.Create(ctx, cert))
	svc := newTestItemBackupService(nil, nil, repo, nil)

	blob, err := svc.BackupCertificate(ctx, cert.ID, owner, vaultID)
	require.NoError(t, err)
	assert.True(t, strings.HasPrefix(blob, backup.ExportedSealedBlobPrefix),
		"a new blob must carry the sealed-format marker")
	_, decodeErr := base64.URLEncoding.DecodeString(blob)
	assert.Error(t, decodeErr, "a sealed blob must not be a bare base64url envelope")
}

// TestBackupCertificate_SealedBlobKeepsVersionHistory guards the version-aware
// envelope: sealing wraps it, and must not drop certificate_versions.
func TestBackupCertificate_SealedBlobKeepsVersionHistory(t *testing.T) {
	f := newCertBackupFixture(t)
	cert := f.seedCertAtVersion3(t)

	blob, err := f.svc.BackupCertificate(context.Background(), cert.ID, f.userID, f.vaultID)
	require.NoError(t, err)
	inner, err := f.svc.ExportedOpenBlob(blob)
	require.NoError(t, err)

	var decoded model.Certificate
	versions, err := backup.ExportedDecodeBlob(inner, "certificate", &decoded)
	require.NoError(t, err)
	assert.Equal(t, 3, decoded.Version)
	require.Len(t, versions.Certificate, 2, "both archived versions must stay in the sealed blob")
}

// TestRestoreCertificate_RejectsLegacyUnsealedBlob is the B76 regression: a
// forged blob naming a key in another vault must be refused outright.
func TestRestoreCertificate_RejectsLegacyUnsealedBlob(t *testing.T) {
	t.Parallel()

	blob := legacyBlob(t, "certificate", &model.Certificate{
		ID: uuid.New(), Name: "forged", KeyID: uuid.New(), AutoRenew: true,
	})
	repo := newStubCertRepo()
	svc := newTestItemBackupService(nil, nil, repo, nil)

	err := svc.RestoreCertificate(context.Background(), blob, uuid.New(), uuid.New(), uuid.New())
	require.ErrorIs(t, err, backup.ErrInvalidBlob)
	require.ErrorIs(t, err, backup.ErrUnsealedBlob)
	assert.Empty(t, repo.certs, "a rejected blob must write nothing")
}

// TestRestoreKey_RejectsForgedHSMHandle pins the HSM half of B76: an HSM key
// blob stores a pkcs11 handle, so a forged blob could bind a new key row to
// any HSM object. Sealing makes that blob unrestorable.
func TestRestoreKey_RejectsForgedHSMHandle(t *testing.T) {
	t.Parallel()

	blob := legacyBlob(t, "key", &model.Key{
		ID: uuid.New(), Name: "hijack", Type: model.KeyTypeRSA,
		Value: "pkcs11:victim-vault-key", Enabled: true,
	})
	repo := newStubKeyRepo()
	svc := newTestItemBackupService(nil, repo, nil, nil)

	err := svc.RestoreKey(context.Background(), blob, uuid.New(), uuid.New(), uuid.New())
	require.ErrorIs(t, err, backup.ErrUnsealedBlob)
	assert.Empty(t, repo.keys, "a rejected blob must write nothing")
}

func TestRestore_RejectsTamperedBlob(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	owner, vaultID, secretID := uuid.New(), uuid.New(), uuid.New()
	repo := newStubSecretRepo()
	require.NoError(t, repo.Create(ctx, &model.Secret{
		ID: secretID, UserID: owner, VaultID: vaultID, Name: "s", Value: "v", Version: 1, Enabled: true,
	}))
	svc := newTestItemBackupService(repo, nil, nil, newStubSecretVersionRepo())

	blob, err := svc.BackupSecret(ctx, secretID, owner, vaultID)
	require.NoError(t, err)

	raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(blob, backup.ExportedSealedBlobPrefix))
	require.NoError(t, err)
	raw[len(raw)-1] ^= 0x01
	tampered := backup.ExportedSealedBlobPrefix + base64.StdEncoding.EncodeToString(raw)

	err = svc.RestoreSecret(ctx, tampered, owner, vaultID, uuid.New())
	require.ErrorIs(t, err, backup.ErrInvalidBlob)
	require.ErrorIs(t, err, backup.ErrBlobAuthentication)
}

// TestRestore_RejectsBlobSealedUnderAnotherMasterKey covers blobs taken
// before a master-key rotation. Their inner values are ciphertext under the
// old key anyway, so refusing them loses nothing that ever worked.
func TestRestore_RejectsBlobSealedUnderAnotherMasterKey(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	owner, vaultID, secretID := uuid.New(), uuid.New(), uuid.New()
	repo := newStubSecretRepo()
	require.NoError(t, repo.Create(ctx, &model.Secret{
		ID: secretID, UserID: owner, VaultID: vaultID, Name: "s", Value: "v", Version: 1, Enabled: true,
	}))
	svc := newTestItemBackupService(repo, nil, nil, newStubSecretVersionRepo())
	blob, err := svc.BackupSecret(ctx, secretID, owner, vaultID)
	require.NoError(t, err)

	other := backup.NewItemBackupService(repo, nil, nil, newStubSecretVersionRepo())
	require.NoError(t, other.SetSealKey(bytes.Repeat([]byte{0x43}, 32)))

	err = other.RestoreSecret(ctx, blob, owner, vaultID, uuid.New())
	require.ErrorIs(t, err, backup.ErrBlobAuthentication)
}

func TestItemBackup_FailsClosedWithoutSealKey(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	owner, vaultID, secretID := uuid.New(), uuid.New(), uuid.New()
	repo := newStubSecretRepo()
	require.NoError(t, repo.Create(ctx, &model.Secret{
		ID: secretID, UserID: owner, VaultID: vaultID, Name: "s", Value: "v", Version: 1, Enabled: true,
	}))
	svc := backup.NewItemBackupService(repo, nil, nil, newStubSecretVersionRepo())

	_, err := svc.BackupSecret(ctx, secretID, owner, vaultID)
	require.ErrorIs(t, err, backup.ErrSealKeyUnset)

	err = svc.RestoreSecret(ctx, "rvb2.anything", owner, vaultID, uuid.New())
	require.ErrorIs(t, err, backup.ErrSealKeyUnset)
}

func TestSetSealKey_RejectsWrongLength(t *testing.T) {
	t.Parallel()

	svc := backup.NewItemBackupService(nil, nil, nil, nil)
	require.Error(t, svc.SetSealKey(make([]byte, 16)))
}
```

- [ ] **Step 3: Run the tests and confirm they fail**

Run: `go test ./internal/backup/ ./api/ -count=1`
Expected: FAIL at build time: `svc.SetSealKey undefined`, `undefined: sealedBlobPrefix`, `undefined: backup.ErrUnsealedBlob` and similar.

- [ ] **Step 4: Implement the seal**

Create `internal/backup/blob_seal.go`:

```go
package backup

import (
	"crypto/hkdf"
	"crypto/sha256"
	"errors"
	"fmt"
	"strings"

	"rocketvault/common"
)

// sealedBlobPrefix marks a blob sealed under the item-backup key. It is also
// the format version: a blob without it predates sealing and is refused.
const sealedBlobPrefix = "rvb2."

// sealKeyInfo is the HKDF info string. It keeps the item-backup key distinct
// from the master key itself and from any other key derived from it.
const sealKeyInfo = "rocketvault item-backup blob seal v2"

// sealKeySize is the AES-256 key length in bytes.
const sealKeySize = 32

var (
	// ErrSealKeyUnset is returned when backup or restore runs before
	// SetSealKey. Both fail closed rather than fall back to the
	// unauthenticated format.
	ErrSealKeyUnset = errors.New("item backup seal key is not configured")

	// ErrUnsealedBlob marks a blob in the pre-sealing format. Such a blob was
	// either taken before the upgrade or written by hand, and the two cannot
	// be told apart, so both are refused.
	ErrUnsealedBlob = errors.New("blob is not sealed; take a new backup with this server")

	// ErrBlobAuthentication marks a sealed blob that failed its integrity
	// check: it was modified, or sealed under a different master key.
	ErrBlobAuthentication = errors.New("blob failed authentication")
)

// SetSealKey derives the blob-sealing key from the raw 32-byte master key.
// Every blob is then encrypted and authenticated, so restore accepts only
// blobs this server produced, unmodified (B76).
func (s *ItemBackupService) SetSealKey(masterKey []byte) error {
	if len(masterKey) != sealKeySize {
		return fmt.Errorf("item backup seal key: master key must be %d bytes, got %d", sealKeySize, len(masterKey))
	}
	key, err := hkdf.Key(sha256.New, masterKey, nil, sealKeyInfo, sealKeySize)
	if err != nil {
		return fmt.Errorf("item backup seal key: derive: %w", err)
	}
	s.sealKey = key
	return nil
}

// sealBlob encrypts and authenticates an encoded envelope with AES-256-GCM.
func (s *ItemBackupService) sealBlob(inner string) (string, error) {
	if s.sealKey == nil {
		return "", ErrSealKeyUnset
	}
	sealed, err := common.EncryptWithKey(inner, s.sealKey)
	if err != nil {
		return "", fmt.Errorf("seal backup blob: %w", err)
	}
	return sealedBlobPrefix + sealed, nil
}

// openBlob reverses sealBlob. Both refusals wrap ErrInvalidBlob, so the HTTP
// handlers report them as a bad parameter rather than a server fault.
func (s *ItemBackupService) openBlob(blob string) (string, error) {
	if s.sealKey == nil {
		return "", ErrSealKeyUnset
	}
	body, ok := strings.CutPrefix(blob, sealedBlobPrefix)
	if !ok {
		return "", fmt.Errorf("%w: %w", ErrInvalidBlob, ErrUnsealedBlob)
	}
	inner, err := common.DecryptWithKey(body, s.sealKey)
	if err != nil {
		return "", fmt.Errorf("%w: %w", ErrInvalidBlob, ErrBlobAuthentication)
	}
	return inner, nil
}
```

In `internal/backup/item_backup.go`, replace the struct doc and struct (lines 68-78) with:

```go
// ItemBackupService provides per-item backup and restore for secrets, keys,
// and certificates. Each backup is a JSON envelope, encrypted and
// authenticated under a key derived from the master key (see blob_seal.go),
// and is opaque to the caller.
type ItemBackupService struct {
	secretRepo      repositories.SecretRepositoryInterface
	keyRepo         repositories.KeyRepositoryInterface
	certRepo        repositories.CertificateRepositoryInterface
	versionRepo     repositories.SecretVersionRepositoryInterface
	certVersionRepo repositories.CertificateVersionRepositoryInterface
	txBeginner      TxBeginner
	// sealKey is set by SetSealKey. While it is nil, backup and restore fail
	// with ErrSealKeyUnset.
	sealKey []byte
}
```

In `BackupSecret` (line 173), replace `return encodeBlob("secret", id.String(), secret, blobVersions{Secret: versions})` with:

```go
	inner, err := encodeBlob("secret", id.String(), secret, blobVersions{Secret: versions})
	if err != nil {
		return "", err
	}
	return s.sealBlob(inner)
```

In `BackupKey` (line 296), replace `return encodeBlob("key", id.String(), key, blobVersions{Key: versions})` with:

```go
	inner, err := encodeBlob("key", id.String(), key, blobVersions{Key: versions})
	if err != nil {
		return "", err
	}
	return s.sealBlob(inner)
```

In `BackupCertificate` (line 400), replace `return encodeBlob("certificate", id.String(), cert, blobVersions{Certificate: versions})` with the following. Keep `blobVersions{Certificate: versions}` exactly; it carries the archived versions.

```go
	inner, err := encodeBlob("certificate", id.String(), cert, blobVersions{Certificate: versions})
	if err != nil {
		return "", err
	}
	return s.sealBlob(inner)
```

In `RestoreSecret` (lines 186-187), replace

```go
	var secret model.Secret
	versions, err := decodeBlob(blob, "secret", &secret)
```

with

```go
	inner, err := s.openBlob(blob)
	if err != nil {
		return err
	}
	var secret model.Secret
	versions, err := decodeBlob(inner, "secret", &secret)
```

In `RestoreKey` (lines 302-303), replace

```go
	var key model.Key
	versions, err := decodeBlob(blob, "key", &key)
```

with

```go
	inner, err := s.openBlob(blob)
	if err != nil {
		return err
	}
	var key model.Key
	versions, err := decodeBlob(inner, "key", &key)
```

and replace the comment above `key.Exportable = false` (lines 310-311)

```go
	// A restore never grants exportability: the blob is unauthenticated
	// base64 JSON, so its exportable value cannot be trusted.
```

with

```go
	// A restore never grants exportability. The blob is now sealed, but the
	// exportable decision belongs to the item's creator, and a restore may
	// land in a vault whose owners never made it.
```

In `RestoreCertificate` (lines 422-423), replace

```go
	var cert model.Certificate
	versions, err := decodeBlob(blob, "certificate", &cert)
```

with

```go
	inner, err := s.openBlob(blob)
	if err != nil {
		return err
	}
	var cert model.Certificate
	versions, err := decodeBlob(inner, "certificate", &cert)
```

Finally update the three doc comments that still describe the old format: in the comments above `BackupSecret` (line 155), `BackupKey` (line 276) and `BackupCertificate` (line 374), replace `creates a base64url-encoded backup blob` with `creates a sealed backup blob`.

- [ ] **Step 5: Run the service and handler tests and confirm they pass**

Run: `go vet ./internal/backup/ ./api/ && go test ./internal/backup/ ./api/ -count=1`
Expected: `ok  	rocketvault/internal/backup` and `ok  	rocketvault/api`.

- [ ] **Step 6: Write the failing container wiring test**

Create `internal/container/item_backup_seal_test.go`:

```go
package container

import (
	"bytes"
	"context"
	"encoding/base64"
	"testing"

	"github.com/google/uuid"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/require"

	"rocketvault/internal/backup"
)

// TestItemBackupService_SealedWhenMasterKeyConfigured pins the container
// wiring for B76. Only a service with its seal key set reports an unsealed
// blob as unsealed; an unwired one reports ErrSealKeyUnset instead.
func TestItemBackupService_SealedWhenMasterKeyConfigured(t *testing.T) {
	orig := viper.GetString("master_key")
	t.Cleanup(func() { viper.Set("master_key", orig) })
	viper.Set("master_key", base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x24}, 32)))

	c, err := NewServiceContainer(newMinimalConfig(t))
	require.NoError(t, err)
	t.Cleanup(func() { _ = c.Close() })

	err = c.GetItemBackupService().RestoreSecret(context.Background(), "not-a-sealed-blob", uuid.New(), uuid.New(), uuid.New())
	require.ErrorIs(t, err, backup.ErrUnsealedBlob)
}
```

Run: `go test ./internal/container/ -run TestItemBackupService_SealedWhenMasterKeyConfigured -count=1`
Expected: FAIL; the error is `item backup seal key is not configured`, not `ErrUnsealedBlob`.

- [ ] **Step 7: Wire the seal key in the container**

In `internal/container/service_container.go` (the import of `rocketvault/common` at line 14 already exists; add nothing), replace

```go
	c.itemBackupService.SetCertificateVersionRepository(c.certificateVersionRepository)

	return nil
}
```

with

```go
	c.itemBackupService.SetCertificateVersionRepository(c.certificateVersionRepository)
	// Seals every item-backup blob under a key derived from the master key,
	// so a forged or edited blob is refused at restore (B76). A missing or
	// malformed master key leaves the service unsealed, and backup and
	// restore then fail closed instead of using the unauthenticated format.
	// bootstrap.ValidateMasterKey already aborts server startup on a bad key.
	if masterKey, keyErr := common.ParseMasterKey(viper.GetString("master_key")); keyErr != nil {
		c.logger.WithError(keyErr).Warn("master key unavailable, item backup and restore are disabled")
	} else if err := c.itemBackupService.SetSealKey(masterKey); err != nil {
		return fmt.Errorf("failed to configure item backup sealing: %w", err)
	}

	return nil
}
```

The master key is read from the global viper, as `common.EncryptSecret` reads it, so the seal key always derives from the same key that encrypts the values inside the blob.

Run: `go test ./internal/container/ -count=1`
Expected: `ok  	rocketvault/internal/container`.

- [ ] **Step 8: Lint and commit**

Run: `go build ./... && go vet ./internal/backup/ ./internal/container/ ./api/`
Expected: no output.

Run: `BASE=$(cat .git/rv-cert-isolation-base); PATH="$HOME/go/pkg/mod/golang.org/toolchain@v0.0.1-go1.25.7.linux-amd64/bin:$PATH" GOTOOLCHAIN=local ~/go/bin/golangci-lint run --new-from-rev="$BASE" ./internal/backup/ ./internal/container/ ./api/`
Expected: `0 issues.`

Stage the created and modified files of this task, then invoke the `dev-workflow-skills:1-git-commit` skill via the Skill tool. The subject should say item-backup blobs are now sealed under a master-key-derived key and unsealed blobs are refused (B76). No `Fixes` footer yet.

---

### Task 3: Restore drops key and CA links that do not resolve in the target vault (B76)

**Files:**
- Modify: `internal/backup/item_backup.go` (`RestoreCertificate`, after `cert.Exportable = false`, line 437 at HEAD; new method `dropForeignReferences` before `// encodeBlob marshals data ...`, line 498 at HEAD)
- Create: `internal/backup/item_backup_cert_refs_test.go`
- Modify: `.claude/known-bugs.md` (new § B76 before `## Deferred Refactors`)

**Interfaces:**
- Consumes: `repositories.KeyRepositoryInterface.Read(ctx, id, scope) (*model.Key, error)`, `repositories.CertificateRepositoryInterface.Read(ctx, id, scope) (*model.Certificate, error)`; `model.CertificateVersionRecord.KeyID` (`model/certificate.go:169`; stored as `NULL` when `uuid.Nil`, `certificate_version_repository.go:141`).
- Produces: unexported `(s *ItemBackupService) dropForeignReferences(ctx context.Context, cert *model.Certificate, versions []model.CertificateVersionRecord, userID, vaultID uuid.UUID)`. A restored certificate keeps `KeyID`/`CACertID`, and each archived version keeps its `KeyID`, only when that link reads successfully under `model.NewVaultScope(vaultID, userID)`.

Decision recorded here and in § B76: clear, do not reject. Restoring into a different vault is supported (B15), and the body, private key copy and history are valid there; only the links point at objects the restoring caller was never authorized for. A cleared `KeyID` makes renewal refuse (`ErrRenewNotPossible`, "certificate has no associated key ID"); a cleared `CACertID` makes renewal refuse (`ErrRenewNotPossible`, "signed by a CA this installation no longer records"); Task 6 refuses a CA with no key as a signer; `ExportCertificate` is unaffected because a restored certificate is never exportable. Every consequence of clearing is a refusal, never a wider grant. Archived versions' `KeyID` is not followed by any code today, but it is cleared the same way so no foreign reference survives a restore. `RestoreSecret` and `RestoreKey` have no cross-object links; `RestoreKey`'s HSM handle is covered by the seal (Task 2).

- [ ] **Step 1: Write the failing tests**

Create `internal/backup/item_backup_cert_refs_test.go`:

```go
package backup_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"rocketvault/internal/backup"
	rvdb "rocketvault/internal/db"
	"rocketvault/internal/logging"
	"rocketvault/internal/repositories"
	"rocketvault/model"
)

// vaultCheckingKeyRepo applies the vault predicate the real KeyRepository
// applies in SQL, which stubKeyRepo deliberately ignores.
type vaultCheckingKeyRepo struct{ *stubKeyRepo }

func (r vaultCheckingKeyRepo) Read(ctx context.Context, id uuid.UUID, scope model.Scope) (*model.Key, error) {
	k, err := r.stubKeyRepo.Read(ctx, id, scope)
	if err != nil {
		return nil, err
	}
	if scope.Kind() != model.ScopeVault || k.VaultID != scope.VaultID() {
		return nil, fmt.Errorf("key not found or access denied")
	}
	return k, nil
}

// vaultCheckingCertRepo is vaultCheckingKeyRepo's certificate twin.
type vaultCheckingCertRepo struct{ *stubCertRepo }

func (r vaultCheckingCertRepo) Read(ctx context.Context, id uuid.UUID, scope model.Scope) (*model.Certificate, error) {
	c, err := r.stubCertRepo.Read(ctx, id, scope)
	if err != nil {
		return nil, err
	}
	if scope.Kind() != model.ScopeVault || c.VaultID != scope.VaultID() {
		return nil, fmt.Errorf("certificate not found or access denied")
	}
	return c, nil
}

// certRefFixture holds, in vault A, a signing key, a CA certificate and a
// leaf certificate linked to both, plus a sealed backup of the leaf.
type certRefFixture struct {
	keys     *stubKeyRepo
	certs    *stubCertRepo
	svc      *backup.ItemBackupService
	owner    uuid.UUID
	vaultA   uuid.UUID
	keyID    uuid.UUID
	caCertID uuid.UUID
	blob     string
}

func newCertRefFixture(t *testing.T) *certRefFixture {
	t.Helper()
	ctx := context.Background()
	owner, vaultA := uuid.New(), uuid.New()
	keyID, caCertID, leafID := uuid.New(), uuid.New(), uuid.New()

	keys := newStubKeyRepo()
	require.NoError(t, keys.Create(ctx, &model.Key{
		ID: keyID, UserID: owner, VaultID: vaultA, Name: "k", Value: "enc", Type: model.KeyTypeRSA, Enabled: true,
	}))
	certs := newStubCertRepo()
	require.NoError(t, certs.Create(ctx, &model.Certificate{ID: caCertID, UserID: owner, VaultID: vaultA, Name: "ca"}))
	require.NoError(t, certs.Create(ctx, &model.Certificate{
		ID: leafID, UserID: owner, VaultID: vaultA, Name: "leaf",
		KeyID: keyID, CACertID: &caCertID, AutoRenew: true,
	}))

	svc := newTestItemBackupService(nil, vaultCheckingKeyRepo{keys}, vaultCheckingCertRepo{certs}, nil)
	blob, err := svc.BackupCertificate(ctx, leafID, owner, vaultA)
	require.NoError(t, err)

	return &certRefFixture{
		keys: keys, certs: certs, svc: svc, owner: owner, vaultA: vaultA,
		keyID: keyID, caCertID: caCertID, blob: blob,
	}
}

// TestRestoreCertificate_DropsCrossVaultReferences is the B76 regression for
// a genuine blob restored into another vault: its links must not survive,
// or the scheduler would later follow them out of the restore vault.
func TestRestoreCertificate_DropsCrossVaultReferences(t *testing.T) {
	t.Parallel()

	f := newCertRefFixture(t)
	vaultB, newID := uuid.New(), uuid.New()
	require.NoError(t, f.svc.RestoreCertificate(context.Background(), f.blob, f.owner, vaultB, newID))

	restored := f.certs.certs[newID]
	require.NotNil(t, restored)
	assert.Equal(t, vaultB, restored.VaultID)
	assert.Equal(t, uuid.Nil, restored.KeyID, "a key in another vault must not stay linked")
	assert.Nil(t, restored.CACertID, "a CA certificate in another vault must not stay linked")
}

// TestRestoreCertificate_KeepsSameVaultReferences guards the common case: a
// restore into the vault the backup came from must keep auto-renew working.
func TestRestoreCertificate_KeepsSameVaultReferences(t *testing.T) {
	t.Parallel()

	f := newCertRefFixture(t)
	newID := uuid.New()
	require.NoError(t, f.svc.RestoreCertificate(context.Background(), f.blob, f.owner, f.vaultA, newID))

	restored := f.certs.certs[newID]
	require.NotNil(t, restored)
	assert.Equal(t, f.keyID, restored.KeyID)
	require.NotNil(t, restored.CACertID)
	assert.Equal(t, f.caCertID, *restored.CACertID)
}

// TestRestoreCertificate_NoKeyRepoDropsKeyReference pins the fail-closed
// branch: a link that cannot be checked is not kept.
func TestRestoreCertificate_NoKeyRepoDropsKeyReference(t *testing.T) {
	t.Parallel()

	f := newCertRefFixture(t)
	svc := newTestItemBackupService(nil, nil, vaultCheckingCertRepo{f.certs}, nil)
	newID := uuid.New()
	require.NoError(t, svc.RestoreCertificate(context.Background(), f.blob, f.owner, f.vaultA, newID))

	restored := f.certs.certs[newID]
	require.NotNil(t, restored)
	assert.Equal(t, uuid.Nil, restored.KeyID)
	require.NotNil(t, restored.CACertID, "the CA link still resolves and is kept")
}

// TestRestoreCertificate_CrossVaultKeepsHistoryDropsVersionKeyLinks runs on
// the real repositories. A versioned certificate restored into another vault
// keeps every archived version, but no version keeps a key link into the
// source vault. Restored into its own vault, every link survives.
func TestRestoreCertificate_CrossVaultKeepsHistoryDropsVersionKeyLinks(t *testing.T) {
	f := newCertBackupFixture(t)
	ctx := context.Background()
	conn := rvdb.NewConn(f.raw, rvdb.SQLite)
	keys := repositories.NewKeyRepository(conn, logging.InitLogger())

	cert := f.seedCertAtVersion3(t)
	require.NoError(t, keys.Create(ctx, &model.Key{
		ID: cert.KeyID, UserID: f.userID, VaultID: f.vaultID, Name: "signing-key",
		Type: model.KeyTypeRSA, Value: "enc", Enabled: true, CreatedAt: time.Now().UTC(),
	}))

	svc := newTestItemBackupService(nil, keys, f.certs, nil)
	svc.SetTxBeginner(conn)
	svc.SetCertificateVersionRepository(f.versions)

	blob, err := svc.BackupCertificate(ctx, cert.ID, f.userID, f.vaultID)
	require.NoError(t, err)

	otherVault, crossID := uuid.New(), uuid.New()
	require.NoError(t, svc.RestoreCertificate(ctx, blob, f.userID, otherVault, crossID))
	crossRow, err := f.certs.Read(ctx, crossID, model.NewVaultScope(otherVault, f.userID))
	require.NoError(t, err)
	assert.Equal(t, 3, crossRow.Version)
	assert.Equal(t, uuid.Nil, crossRow.KeyID)
	crossVersions, err := f.versions.ListVersionRecords(ctx, crossID)
	require.NoError(t, err)
	require.Len(t, crossVersions, 2, "history must survive a cross-vault restore")
	for _, v := range crossVersions {
		assert.Equal(t, uuid.Nil, v.KeyID, "version %d must not keep a key link into the source vault", v.Version)
	}

	require.NoError(t, f.certs.Delete(ctx, cert.ID))
	sameID := uuid.New()
	require.NoError(t, svc.RestoreCertificate(ctx, blob, f.userID, f.vaultID, sameID))
	sameRow, err := f.certs.Read(ctx, sameID, model.NewVaultScope(f.vaultID, f.userID))
	require.NoError(t, err)
	assert.Equal(t, cert.KeyID, sameRow.KeyID)
	sameVersions, err := f.versions.ListVersionRecords(ctx, sameID)
	require.NoError(t, err)
	require.Len(t, sameVersions, 2)
	for _, v := range sameVersions {
		assert.Equal(t, cert.KeyID, v.KeyID)
	}
}
```

- [ ] **Step 2: Run the tests and confirm they fail**

Run: `go test ./internal/backup/ -run 'TestRestoreCertificate_(DropsCrossVault|KeepsSameVault|NoKeyRepo|CrossVaultKeeps)' -count=1`
Expected: FAIL. `DropsCrossVaultReferences`, `NoKeyRepoDropsKeyReference` and `CrossVaultKeepsHistoryDropsVersionKeyLinks` report links that survived. `KeepsSameVaultReferences` already passes; it is the guard against over-clearing.

- [ ] **Step 3: Implement**

In `internal/backup/item_backup.go`, `RestoreCertificate`, replace

```go
	cert.ID = newID
	cert.UserID = userID
	cert.VaultID = vaultID
	// A restore never grants exportability; see RestoreKey.
	cert.Exportable = false
```

with

```go
	cert.ID = newID
	cert.UserID = userID
	cert.VaultID = vaultID
	// A restore never grants exportability; see RestoreKey.
	cert.Exportable = false
	// Links the target vault cannot resolve are dropped before anything is
	// written, on the current row and on every archived version (B76).
	s.dropForeignReferences(ctx, &cert, versions.Certificate, userID, vaultID)
```

`versions.Certificate` is the slice the transactional and plain write paths below replay, so clearing its elements in place is what reaches `certificate_versions`.

Immediately before the line `// encodeBlob marshals data into a JSON envelope and base64url-encodes it.`, add:

```go
// dropForeignReferences clears a restored certificate's signing-key and CA
// links unless each resolves inside vaultID, and clears the key link of every
// archived version the same way. A backup may be restored into a vault other
// than the one it came from (B15), and its links then name objects the
// restoring caller was never authorized for. Renewal follows those links, so
// a link that does not resolve here is dropped rather than kept (B76).
//
// Dropping only ever causes a refusal later: renewal refuses a certificate
// with no key, and refuses to re-sign one whose CA it no longer records. Any
// read error counts as "does not resolve", since keeping an unverified link
// is the one outcome this method exists to prevent.
func (s *ItemBackupService) dropForeignReferences(ctx context.Context, cert *model.Certificate, versions []model.CertificateVersionRecord, userID, vaultID uuid.UUID) {
	scope := model.NewVaultScope(vaultID, userID)

	// Each distinct key is read once, however many versions name it.
	resolved := make(map[uuid.UUID]bool)
	keyResolves := func(id uuid.UUID) bool {
		if ok, seen := resolved[id]; seen {
			return ok
		}
		ok := false
		if s.keyRepo != nil {
			_, err := s.keyRepo.Read(ctx, id, scope)
			ok = err == nil
		}
		resolved[id] = ok
		return ok
	}

	if cert.KeyID != uuid.Nil && !keyResolves(cert.KeyID) {
		cert.KeyID = uuid.Nil
	}
	for i := range versions {
		if versions[i].KeyID != uuid.Nil && !keyResolves(versions[i].KeyID) {
			versions[i].KeyID = uuid.Nil
		}
	}

	if cert.CACertID != nil {
		if _, err := s.certRepo.Read(ctx, *cert.CACertID, scope); err != nil {
			cert.CACertID = nil
		}
	}
}
```

- [ ] **Step 4: Run the tests and confirm they pass**

Run: `go test ./internal/backup/ ./api/ -count=1`
Expected: `ok  	rocketvault/internal/backup` and `ok  	rocketvault/api`. The existing `TestCertificateBackupRestore_RoundTripsVersions` still passes: it asserts body, key copy and version numbers, not links.

- [ ] **Step 5: File the GitHub issue and add the known-bugs entry**

```bash
gh issue create --label bug \
  --title "B76: A forged or cross-vault certificate restore blob planted key and CA links that auto-renew followed with an admin scope" \
  --body "$(cat <<'EOF'
**Severity**: High

**Files**: `internal/backup/item_backup.go` (`RestoreCertificate`, `encodeBlob`/`decodeBlob`), `internal/services/certificates/renewal_service.go` (`CheckAndRenewCertificates`), `internal/repositories/scope_predicate.go`

**Symptom**: A caller with `certificates/restore` in vault B could restore a certificate whose `key_id` and `ca_cert_id` named a key and a CA certificate in vault A. The blob was unauthenticated base64url JSON, so the links could also be written by hand. The auto-renew scheduler renewed that row with `model.NewAdminScope(cert.UserID)`, whose predicate matches every vault, so the renewal read the vault-A key, copied its private PEM into the vault-B row and wrote it through `ArchiveAndRenew` with no vault predicate. A restored CA body became a working CA in vault B signing with a vault-A key. Only the B32 owner comparison stood in the way, and it passes whenever the restorer owns the vault-A objects, including after losing access to vault A. The same blob format let a forged key blob bind a new key row to any `pkcs11:<label>` HSM handle.

**Root cause**: `RestoreCertificate` overrode only `ID`, `UserID`, `VaultID` and `Exportable`; `key_id`, `ca_cert_id` and every archived version's `key_id` came from the blob. The blob had no integrity protection. The scheduler used an admin scope, so the vault predicate never applied on the renewal path.

Full detail: .claude/known-bugs.md § B76
EOF
)"
```

Note the issue number the command prints; it is `<N>` below and in the commit footer.

In `.claude/known-bugs.md`, insert immediately before the line `## Deferred Refactors`:

```markdown
### B76 — A forged or cross-vault certificate restore blob planted key and CA links that auto-renew followed with an admin scope

**Status**: Fixed 2026-10-XX (GitHub issue #<N>)
**Severity**: High — key material from a vault the caller could not reach
ended up in a row in a vault they could, usable there as a CA signing key
**Files**: `internal/backup/item_backup.go`, `internal/backup/blob_seal.go`
(new), `internal/services/certificates/renewal_service.go`,
`internal/container/service_container.go`

**Symptom**: a caller holding `certificates/restore` in vault B could restore
a certificate whose `key_id` and `ca_cert_id` named a key and a CA
certificate in vault A. The auto-renew scheduler then renewed the row with
`model.NewAdminScope(cert.UserID)`, whose predicate matches every vault, so
the key read, the CA read and `ArchiveAndRenew`'s update all ignored the
vault, and the renewal copied the vault-A key's private PEM into the vault-B
row. When the restored body was a CA, the renewed row was a working CA in
vault B signed by a vault-A key. The owner comparison those reads keep (B32)
was the only barrier, and it passes whenever the restorer owns the vault-A
objects, including after their access to vault A was revoked. The blob was
unauthenticated base64url JSON, so the links did not need a real backup. The
same format let a forged key blob bind a new key row to any
`pkcs11:<label>` HSM handle.

**Root cause**: three layers, each enough to matter. `RestoreCertificate`
overrode only `ID`, `UserID`, `VaultID` and `Exportable` (B15 and the export
work), and `key_id`, `ca_cert_id` and each archived version's `key_id` were
inserted verbatim; no update path rewrites `ca_cert_id`, deliberately (B37).
The blob carried no integrity protection. The scheduler used an admin scope.

**What was fixed**:

- Blobs are sealed. `BackupSecret`, `BackupKey` and `BackupCertificate` return
  `rvb2.` followed by `common.EncryptWithKey` output under a key derived from
  the master key with HKDF-SHA256 (info `rocketvault item-backup blob seal
  v2`). The seal wraps the version-aware envelope unchanged. Restore refuses
  a blob with no prefix (`ErrUnsealedBlob`) or one that fails authentication
  (`ErrBlobAuthentication`), both wrapped in `ErrInvalidBlob` (HTTP 400), and
  does nothing while no seal key is set (`ErrSealKeyUnset`).
- `RestoreCertificate` keeps `key_id`, `ca_cert_id` and each archived
  version's `key_id` only when it reads under
  `model.NewVaultScope(targetVault, restorer)`; otherwise it clears it.
  Cleared, not rejected: cross-vault restore is supported (B15), and every
  consequence of a cleared link is a later refusal, never a grant.
- The scheduler renews with `model.NewVaultScope(cert.VaultID,
  cert.UserID)` and skips a row with no vault.

**Compatibility decision**: blobs taken before the upgrade are refused, with
no opt-in. An accepted unsealed blob is indistinguishable from a forged one.
A blob's values were always master-key ciphertext, so blobs never survived a
master-key rotation or moved between instances anyway. This ends the
"pre-change blob restores unchanged" promise of the 2026-10-01 versioning
and export designs. Operators re-take backups after upgrading.

**HSM-handle decision**: sealing closes the forged-handle case. A genuine
blob of an HSM key restored into another vault still points at the same HSM
object; that is what backup plus restore means (the caller held
`keys/backup` in the source vault) and is accepted.

**Accepted limitation**: a backup handler that hits `ErrSealKeyUnset`
reports it as 404, because the three backup handlers map every service error
to not-found. The container always sets the key when the master key parses,
and `bootstrap.ValidateMasterKey` refuses to start otherwise.

**Pinned by**: `TestRestoreCertificate_RejectsLegacyUnsealedBlob`,
`TestRestoreKey_RejectsForgedHSMHandle`, `TestRestore_RejectsTamperedBlob`,
`TestRestore_RejectsBlobSealedUnderAnotherMasterKey`,
`TestItemBackup_FailsClosedWithoutSealKey`,
`TestBackupCertificate_SealedBlobKeepsVersionHistory`
(`internal/backup/item_backup_seal_test.go`);
`TestRestoreCertificate_DropsCrossVaultReferences`,
`TestRestoreCertificate_KeepsSameVaultReferences`,
`TestRestoreCertificate_NoKeyRepoDropsKeyReference`,
`TestRestoreCertificate_CrossVaultKeepsHistoryDropsVersionKeyLinks`
(`internal/backup/item_backup_cert_refs_test.go`);
`TestRestoreCertificateHandler_LegacyUnsealedBlob_Returns400`
(`api/backup_item_seal_test.go`);
`TestItemBackupService_SealedWhenMasterKeyConfigured`
(`internal/container/item_backup_seal_test.go`);
`TestCheckAndRenewCertificates_AutoRenew`,
`TestCheckAndRenewCertificates_NilVaultSkipped`
(`internal/services/certificates/renewal_service_test.go`).

---
```

Replace `<N>` with the issue number, and `2026-10-XX` with the commit date.

- [ ] **Step 6: Lint and commit**

Run: `BASE=$(cat .git/rv-cert-isolation-base); PATH="$HOME/go/pkg/mod/golang.org/toolchain@v0.0.1-go1.25.7.linux-amd64/bin:$PATH" GOTOOLCHAIN=local ~/go/bin/golangci-lint run --new-from-rev="$BASE" ./internal/backup/`
Expected: `0 issues.`

Stage `internal/backup/item_backup.go`, `internal/backup/item_backup_cert_refs_test.go` and `.claude/known-bugs.md`, then invoke the `dev-workflow-skills:1-git-commit` skill via the Skill tool. The subject should say certificate restore drops key and CA links that do not resolve in the target vault (B76). Footer: `Fixes #<N>`.

---

### Task 4: One shared data-plane access check for HTTP handlers, the CLI and the scheduler (B77 groundwork)

**Files:**
- Modify: `internal/services/authorization/data_action_authz.go` (imports, new sentinel, doc comment, `RequireDataAction`'s refusal, new function)
- Create: `internal/services/authorization/data_plane_access_test.go`
- Modify: `cmd/vaultcli/vault.go:55-67` (`RequireDataAction` body)
- Modify: `cmd/vaultcli/session.go:11-15` (imports), new method `RequireAlso` before `Fail` (line 169)
- Create: `cmd/vaultcli/require_also_test.go`

**Interfaces:**
- Consumes: `AccessPolicyService.CheckAccess(ctx, principalID, resourceType, operation, vaultID) (AccessDecision, error)`, `RoleAssignmentService.HasDataAction(ctx, principalID, vaultID, action) (bool, error)`; the existing test doubles `fakeAccessPolicyService` (`vault_authz_test.go:18`) and `fakeRoleAssignmentService` (`data_action_authz_test.go:19`, already on the post-B81 `RevokeAssignment` signature).
- Produces:
  - `var ErrDataPlaneDenied = errors.New("forbidden")` in package `authorization`
  - `func RequireDataPlaneAccess(ctx context.Context, policies AccessPolicyService, roles RoleAssignmentService, principalID, vaultID uuid.UUID, resourceType model.PolicyResourceType, op model.PolicyOperation, action model.DataAction) error`
  - `func (s *Session) RequireAlso(action model.DataAction, op model.PolicyOperation) error` in package `vaultcli`
  - Unchanged messages: `forbidden: no role grants <action> in this vault` and `forbidden: access denied by an explicit access policy for <action>` keep their exact text, now wrapping `ErrDataPlaneDenied`. A lookup failure never wraps it. `CheckAccess` stays the collection-level call PolicyMiddleware uses for data-plane routes (`internal/middleware/middleware.go:696-697`), not `CheckVaultScopedAccess`.

- [ ] **Step 1: Write the failing tests**

Create `internal/services/authorization/data_plane_access_test.go`:

```go
package authorization

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"rocketvault/model"
)

func TestRequireDataPlaneAccess_ExplicitDenyWinsOverRoleGrant(t *testing.T) {
	policies := &fakeAccessPolicyService{decision: AccessDenied}
	roles := &fakeRoleAssignmentService{hasAction: true}

	err := RequireDataPlaneAccess(context.Background(), policies, roles, uuid.New(), uuid.New(),
		model.PolicyResourceKeys, model.OpSign, model.ActionKeysSign)
	require.ErrorIs(t, err, ErrDataPlaneDenied)
	require.Contains(t, err.Error(), "explicit access policy")
}

func TestRequireDataPlaneAccess_NoRoleGrantIsDenied(t *testing.T) {
	policies := &fakeAccessPolicyService{decision: AccessFallback}
	roles := &fakeRoleAssignmentService{hasAction: false}

	err := RequireDataPlaneAccess(context.Background(), policies, roles, uuid.New(), uuid.New(),
		model.PolicyResourceKeys, model.OpSign, model.ActionKeysSign)
	require.ErrorIs(t, err, ErrDataPlaneDenied)
	require.Contains(t, err.Error(), "forbidden: no role grants")
}

func TestRequireDataPlaneAccess_GrantPassesAndForwardsArguments(t *testing.T) {
	policies := &fakeAccessPolicyService{decision: AccessFallback}
	roles := &fakeRoleAssignmentService{hasAction: true}
	principalID, vaultID := uuid.New(), uuid.New()

	err := RequireDataPlaneAccess(context.Background(), policies, roles, principalID, vaultID,
		model.PolicyResourceKeys, model.OpSign, model.ActionKeysSign)
	require.NoError(t, err)
	require.Equal(t, principalID, roles.calledPrincipalID)
	require.Equal(t, vaultID, roles.calledVaultID)
	require.Equal(t, model.ActionKeysSign, roles.calledAction)
}

func TestRequireDataPlaneAccess_NilServicesFailClosed(t *testing.T) {
	err := RequireDataPlaneAccess(context.Background(), nil, nil, uuid.New(), uuid.New(),
		model.PolicyResourceKeys, model.OpSign, model.ActionKeysSign)
	require.ErrorIs(t, err, ErrDataPlaneDenied)
}

func TestRequireDataPlaneAccess_PolicyLookupErrorIsNotADenial(t *testing.T) {
	lookup := errors.New("db exploded")
	policies := &fakeAccessPolicyService{err: lookup}
	roles := &fakeRoleAssignmentService{hasAction: true}

	err := RequireDataPlaneAccess(context.Background(), policies, roles, uuid.New(), uuid.New(),
		model.PolicyResourceKeys, model.OpSign, model.ActionKeysSign)
	require.ErrorIs(t, err, lookup)
	require.NotErrorIs(t, err, ErrDataPlaneDenied, "a lookup failure is a server fault, not a 403")
}

func TestRequireDataAction_DenialWrapsSentinel(t *testing.T) {
	roles := &fakeRoleAssignmentService{hasAction: false}
	err := RequireDataAction(context.Background(), roles, uuid.New(), uuid.New(), model.ActionKeysSign)
	require.ErrorIs(t, err, ErrDataPlaneDenied)
	require.Equal(t, "forbidden: no role grants "+string(model.ActionKeysSign)+" in this vault", err.Error())
}
```

Create `cmd/vaultcli/require_also_test.go`:

```go
package vaultcli

import (
	"testing"

	"github.com/stretchr/testify/require"

	"rocketvault/model"
)

// TestRequireAlso_BeforeAuthorizeFailsClosed pins that the second check never
// runs against an unresolved vault.
func TestRequireAlso_BeforeAuthorizeFailsClosed(t *testing.T) {
	s := &Session{op: Op{Audit: "create_certificate", AuthzFailMsg: "failed to create certificate"}}

	err := s.RequireAlso(model.ActionKeysSign, model.OpSign)
	require.Error(t, err)
	require.Contains(t, err.Error(), "failed to create certificate")
	require.Contains(t, err.Error(), "before Authorize")
}
```

- [ ] **Step 2: Run the tests and confirm they fail**

Run: `go test ./internal/services/authorization/ ./cmd/vaultcli/ -count=1`
Expected: FAIL at build time: `undefined: RequireDataPlaneAccess`, `undefined: ErrDataPlaneDenied`, `s.RequireAlso undefined`.

- [ ] **Step 3: Implement the helper**

In `internal/services/authorization/data_action_authz.go`, add `"errors"` to the import block (between `"context"` and `"fmt"`). Immediately before the line `// RequireDataAction returns nil if principalID holds a role assignment in`, add:

```go
// ErrDataPlaneDenied marks a data-plane authorization refusal: an explicit
// deny policy, or no role granting the action. Its text is "forbidden", so
// every message built on it keeps the "forbidden: ..." shape callers and
// tests already match. A lookup failure never wraps it.
var ErrDataPlaneDenied = errors.New("forbidden")

```

In the doc comment of `RequireDataAction`, replace

```go
// needs AccessPolicyService, not RoleAssignmentService. cmd/vaultcli's
// RequireDataAction wraps both steps in the correct order; this function is
// deliberately only the second one. Do not call this function directly from
// a CLI command — call cmd/vaultcli.RequireDataAction instead.
```

with

```go
// needs AccessPolicyService, not RoleAssignmentService. RequireDataPlaneAccess
// wraps both steps in the correct order; this function is deliberately only
// the second one. Do not call this function directly from a CLI command or a
// handler; call RequireDataPlaneAccess or cmd/vaultcli.RequireDataAction.
```

Replace

```go
		return fmt.Errorf("forbidden: no role grants %s in this vault", action)
	}
	return nil
}
```

with

```go
		return fmt.Errorf("%w: no role grants %s in this vault", ErrDataPlaneDenied, action)
	}
	return nil
}

// RequireDataPlaneAccess runs PolicyMiddleware's full two-stage data-plane
// check for one action in one vault: first the access_policies explicit-deny
// override, then the deny-by-default role-assignment check. It is the single
// implementation behind the CLI (cmd/vaultcli), handlers that need a second
// action beyond the one their route maps to, and the renewal scheduler, so
// the three cannot drift apart. Nil services deny.
func RequireDataPlaneAccess(
	ctx context.Context,
	policies AccessPolicyService,
	roles RoleAssignmentService,
	principalID, vaultID uuid.UUID,
	resourceType model.PolicyResourceType,
	op model.PolicyOperation,
	action model.DataAction,
) error {
	if policies == nil || roles == nil {
		return fmt.Errorf("%w: authorization services are not available", ErrDataPlaneDenied)
	}

	decision, err := policies.CheckAccess(ctx, principalID, resourceType, op, vaultID)
	if err != nil {
		return fmt.Errorf("checking access policy: %w", err)
	}
	if decision == AccessDenied {
		return fmt.Errorf("%w: access denied by an explicit access policy for %s", ErrDataPlaneDenied, action)
	}

	return RequireDataAction(ctx, roles, principalID, vaultID, action)
}
```

- [ ] **Step 4: Route the CLI through the helper**

In `cmd/vaultcli/vault.go`, replace (lines 55-67)

```go
	resourceType := resourceTypeFromAction(action)
	decision, err := sc.GetAccessPolicyService().CheckAccess(ctx, principalID, resourceType, op, vaultID)
	if err != nil {
		return uuid.Nil, fmt.Errorf("checking access policy: %w", err)
	}
	if decision == authorization.AccessDenied {
		return uuid.Nil, fmt.Errorf("forbidden: access denied by an explicit access policy for %s", action)
	}

	if err := authorization.RequireDataAction(ctx, sc.GetRoleAssignmentService(), principalID, vaultID, action); err != nil {
		return uuid.Nil, err
	}
	return vaultID, nil
```

with

```go
	// One implementation for the CLI, HTTP handlers and the renewal
	// scheduler, so the two-stage order cannot drift between them.
	if err := authorization.RequireDataPlaneAccess(ctx, sc.GetAccessPolicyService(), sc.GetRoleAssignmentService(),
		principalID, vaultID, resourceTypeFromAction(action), op, action); err != nil {
		return uuid.Nil, err
	}
	return vaultID, nil
```

`fmt` stays imported (`ResolveVaultID` uses it).

In `cmd/vaultcli/session.go`, add `"rocketvault/internal/services/authorization"` to the import block between `"rocketvault/internal/logging"` and `"rocketvault/model"`. Immediately before the line `// Fail records an audit failure for the session's operation and returns the`, add:

```go
// RequireAlso runs Authorize's two-stage check for one more data action, in
// the vault Authorize already resolved. It is for commands that act on two
// object types at once, such as issuing a certificate with a key. Calling it
// before Authorize fails closed.
func (s *Session) RequireAlso(action model.DataAction, op model.PolicyOperation) error {
	msg := s.op.AuthzFailMsg
	if msg == "" {
		msg = "vault authorization failed"
	}
	if s.Container == nil || s.VaultID == uuid.Nil {
		return s.Fail(msg, fmt.Errorf("RequireAlso called before Authorize"))
	}

	if err := authorization.RequireDataPlaneAccess(s.Ctx, s.Container.GetAccessPolicyService(),
		s.Container.GetRoleAssignmentService(), s.Claims.UserID, s.VaultID,
		resourceTypeFromAction(action), op, action); err != nil {
		return s.Fail(msg, err)
	}
	return nil
}

```

- [ ] **Step 5: Run the tests and confirm they pass**

Run: `go vet ./internal/services/authorization/ ./cmd/vaultcli/ && go test ./internal/services/authorization/ ./cmd/... -count=1`
Expected: every package `ok`. Existing CLI denial tests still see the same `forbidden: ...` text.

- [ ] **Step 6: Lint and commit**

Run: `BASE=$(cat .git/rv-cert-isolation-base); PATH="$HOME/go/pkg/mod/golang.org/toolchain@v0.0.1-go1.25.7.linux-amd64/bin:$PATH" GOTOOLCHAIN=local ~/go/bin/golangci-lint run --new-from-rev="$BASE" ./internal/services/authorization/ ./cmd/vaultcli/`
Expected: `0 issues.`

Stage the files of this task, then invoke the `dev-workflow-skills:1-git-commit` skill via the Skill tool. The subject should say the data-plane two-stage check is extracted into `authorization.RequireDataPlaneAccess` and shared by the CLI. No footer.

---

### Task 5: Refuse revoked, disabled or out-of-window signing keys on create and renew (B77)

**Files:**
- Modify: `internal/services/certificates/certificate_service.go` (new sentinel after `ErrRenewNotPossible`, line 44; `RenewCertificate` after the owner check at `:998-1001`; `ValidateKeyOwnership` at `:1292-1307` and its doc comment at `:1279-1281`; new helper `requireUsableKey` after `ValidateKeyOwnership`)
- Create: `internal/services/certificates/signing_key_lifecycle_test.go`
- Modify (fixtures): the 26 `model.Key` literals without `Enabled` in `internal/services/certificates/*_test.go`

**Interfaces:**
- Consumes: `(*model.Key).IsAccessible() bool` (`model/key.go:41`), field `model.Key.Revoked`.
- Produces: `var ErrSigningKeyUnusable = errors.New("signing key is revoked, disabled or outside its valid time window")`; unexported `requireUsableKey(key *model.Key) error`. `ValidateKeyOwnership` (both create paths call it, `:307`, `:463`) and `RenewCertificate` (which reads its key inline at `:993`, not through `ValidateKeyOwnership`) refuse a revoked or inaccessible key with an error wrapping `ErrSigningKeyUnusable`. The checks run after the owner comparison, so the existing B32 and `ErrRenewKeyForbidden` behavior and messages are unchanged.

- [ ] **Step 1: Write the failing tests**

Create `internal/services/certificates/signing_key_lifecycle_test.go`:

```go
package certificates

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"rocketvault/model"
)

// TestValidateKeyOwnership_RefusesUnusableKey is the B77 regression. The key
// crypto path refuses these keys in loadAndAuthorize; issuing a certificate
// signs with the key, so it must refuse them too.
func TestValidateKeyOwnership_RefusesUnusableKey(t *testing.T) {
	t.Parallel()

	past := time.Now().Add(-time.Hour)
	future := time.Now().Add(time.Hour)
	cases := []struct {
		name string
		key  model.Key
	}{
		{"revoked", model.Key{Enabled: true, Revoked: true}},
		{"disabled", model.Key{Enabled: false}},
		{"expired", model.Key{Enabled: true, ExpiresAt: &past}},
		{"not yet active", model.Key{Enabled: true, NotBefore: &future}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			userID, keyID, vaultID := uuid.New(), uuid.New(), uuid.New()
			key := tc.key
			key.ID, key.UserID, key.VaultID = keyID, userID, vaultID
			keyRepo := &mockKeyRepo{}
			vaultScopedKeyRepo(keyRepo, keyID, vaultID, &key)

			svc := newCertSvc(&mockCertRepository{}, keyRepo)
			err := svc.ValidateKeyOwnership(context.Background(), keyID, model.NewVaultScope(vaultID, userID))
			require.ErrorIs(t, err, ErrSigningKeyUnusable)
		})
	}
}

func TestValidateKeyOwnership_AcceptsUsableKey(t *testing.T) {
	t.Parallel()

	future := time.Now().Add(time.Hour)
	userID, keyID, vaultID := uuid.New(), uuid.New(), uuid.New()
	keyRepo := &mockKeyRepo{}
	vaultScopedKeyRepo(keyRepo, keyID, vaultID, &model.Key{
		ID: keyID, UserID: userID, VaultID: vaultID, Enabled: true, ExpiresAt: &future,
	})

	svc := newCertSvc(&mockCertRepository{}, keyRepo)
	require.NoError(t, svc.ValidateKeyOwnership(context.Background(), keyID, model.NewVaultScope(vaultID, userID)))
}

func TestCreateSelfSignedCertificate_RefusesRevokedKey(t *testing.T) {
	t.Parallel()

	userID, keyID, vaultID := uuid.New(), uuid.New(), uuid.New()
	keyRepo := &mockKeyRepo{}
	vaultScopedKeyRepo(keyRepo, keyID, vaultID, &model.Key{
		ID: keyID, UserID: userID, VaultID: vaultID, Enabled: true, Revoked: true,
	})
	certRepo := &mockCertRepository{}

	svc := newCertSvc(certRepo, keyRepo)
	_, err := svc.CreateSelfSignedCertificate(context.Background(), CreateCertificateRequest{
		Name: "revoked-key-cert", KeyID: keyID, ValidityDays: 30, UserID: userID, VaultID: vaultID,
	})
	require.ErrorIs(t, err, ErrSigningKeyUnusable)
	certRepo.AssertNotCalled(t, "Create", mock.Anything, mock.Anything)
}

// TestRenewCertificate_RefusesDisabledKey covers the renewal path, which
// reads its key inline rather than through ValidateKeyOwnership.
func TestRenewCertificate_RefusesDisabledKey(t *testing.T) {
	t.Parallel()

	userID, keyID, vaultID, certID := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	scope := model.NewVaultScope(vaultID, userID)
	certRepo := &mockCertRepository{}
	certRepo.On("Read", mock.Anything, certID, scope).Return(&model.Certificate{
		ID: certID, UserID: userID, VaultID: vaultID, KeyID: keyID, Name: "c", Enabled: true,
	}, nil)
	keyRepo := &mockKeyRepo{}
	vaultScopedKeyRepo(keyRepo, keyID, vaultID, &model.Key{
		ID: keyID, UserID: userID, VaultID: vaultID, Enabled: false,
	})

	svc := newCertSvc(certRepo, keyRepo)
	_, err := svc.RenewCertificate(context.Background(), certID, scope, 30)
	require.ErrorIs(t, err, ErrSigningKeyUnusable)
	certRepo.AssertNotCalled(t, "Update", mock.Anything, mock.Anything, mock.Anything)
}
```

(`newCertSvc` routes `ArchiveAndRenew` to `certRepo.Update` through `fakeCertVersionRepo`, `version_repo_fake_test.go:30-40`, so "Update not called" means nothing was written.)

- [ ] **Step 2: Run the tests and confirm they fail**

Run: `go test ./internal/services/certificates/ -run 'RefusesUnusableKey|AcceptsUsableKey|RefusesRevokedKey|RefusesDisabledKey' -count=1`
Expected: FAIL at build time: `undefined: ErrSigningKeyUnusable`.

- [ ] **Step 3: Implement**

In `internal/services/certificates/certificate_service.go`, after the `ErrRenewNotPossible` declaration (line 44), add:

```go

// ErrSigningKeyUnusable is returned when a certificate's signing key, or the
// key linked to its signing CA, is revoked, disabled, or outside its validity
// window (B77).
var ErrSigningKeyUnusable = errors.New("signing key is revoked, disabled or outside its valid time window")
```

In `RenewCertificate`, replace

```go
	if key.UserID != userID {
		s.logger.LogAuditError(userID.String(), "renew_certificate", "failed", "forbidden: cannot use other users' keys", nil)
		return nil, ErrRenewKeyForbidden
	}
```

with

```go
	if key.UserID != userID {
		s.logger.LogAuditError(userID.String(), "renew_certificate", "failed", "forbidden: cannot use other users' keys", nil)
		return nil, ErrRenewKeyForbidden
	}
	// Renewal signs with the key, so it refuses the keys the key crypto path
	// refuses in loadAndAuthorize (B77).
	if err := requireUsableKey(key); err != nil {
		s.logger.LogAuditError(userID.String(), "renew_certificate", "failed", "signing key is unusable", nil)
		return nil, err
	}
```

In the doc comment above `ValidateKeyOwnership`, replace

```go
//     something a security fix should do on the way past; that call belongs in
//     its own change.
//
```

with

```go
//     something a security fix should do on the way past; that call belongs in
//     its own change.
//
// The key must also be usable: not revoked, enabled, and inside its validity
// window, matching loadAndAuthorize in the key crypto path (B77).
//
```

In `ValidateKeyOwnership`, replace

```go
	if key.UserID != actorID {
		s.logger.LogAuditError(actorID.String(), "validate_key_ownership", "failed", "forbidden: cannot use other users' keys", nil)
		return fmt.Errorf("forbidden: cannot use other users' keys")
	}

	return nil
}
```

with

```go
	if key.UserID != actorID {
		s.logger.LogAuditError(actorID.String(), "validate_key_ownership", "failed", "forbidden: cannot use other users' keys", nil)
		return fmt.Errorf("forbidden: cannot use other users' keys")
	}

	// Issuing a certificate signs with the key, so it refuses the keys the
	// key crypto path refuses in loadAndAuthorize (B77).
	if err := requireUsableKey(key); err != nil {
		s.logger.LogAuditError(actorID.String(), "validate_key_ownership", "failed", "signing key is unusable", nil)
		return err
	}

	return nil
}

// requireUsableKey refuses a key that is revoked, disabled, or outside its
// validity window, with an error wrapping ErrSigningKeyUnusable.
func requireUsableKey(key *model.Key) error {
	if key.Revoked || !key.IsAccessible() {
		return fmt.Errorf("%w: %s", ErrSigningKeyUnusable, key.ID)
	}
	return nil
}
```

- [ ] **Step 4: Fix the key fixtures the new gate now refuses**

Most fixtures build `model.Key` without `Enabled`, whose zero value is false. At HEAD there are 26 such literals: `ca_opt_in_test.go` lines 69, 209, 468; `ca_renewal_scheduler_test.go` 69; `ca_renewal_test.go` 104, 194, 381, 430; `cert_soft_delete_test.go` 299, 460, 513, 559; `certificate_service_extended_test.go` 593, 764, 1114, 1153, 1201, 1243, 1273, 1320, 1381, 1432, 1481, 1524; `certificate_versions_test.go` 66; `renew_sentinels_test.go` 35. Add `Enabled: true` to each with this script (it skips literals that already set `Enabled`, and the new `signing_key_lifecycle_test.go` is not in its file list):

```bash
cd internal/services/certificates && python3 - ca_opt_in_test.go ca_renewal_scheduler_test.go ca_renewal_test.go \
  cert_soft_delete_test.go certificate_service_extended_test.go certificate_versions_test.go renew_sentinels_test.go <<'EOF'
import re, sys
for path in sys.argv[1:]:
    src = open(path).read()
    out, pos, count = [], 0, 0
    for m in re.finditer(r'model\.Key\{', src):
        if m.start() < pos:
            continue
        i, depth = m.end(), 1
        while depth:
            depth += {'{': 1, '}': -1}.get(src[i], 0)
            i += 1
        close = i - 1
        body = src[m.end():close]
        if 'Enabled' in body or not body.strip():
            continue
        if '\n' in body:
            last = body.rstrip().split('\n')[-1]
            indent = re.match(r'\s*', last).group(0)
            head = body.rstrip()
            head += '' if head.endswith(',') else ','
            tail = re.search(r'\n(\s*)$', body).group(1)
            body = head + '\n' + indent + 'Enabled: true,\n' + tail
        else:
            body = body.rstrip().rstrip(',') + ', Enabled: true'
        out += [src[pos:m.end()], body]
        pos, count = close, count + 1
    out.append(src[pos:])
    open(path, 'w').write(''.join(out))
    print(path, count)
EOF
cd - && gofmt -w internal/services/certificates/*_test.go
```

Expected script output: `ca_opt_in_test.go 3`, `ca_renewal_scheduler_test.go 1`, `ca_renewal_test.go 4`, `cert_soft_delete_test.go 4`, `certificate_service_extended_test.go 12`, `certificate_versions_test.go 1`, `renew_sentinels_test.go 1`. `gofmt -w` only realigns the multi-line literals' field colons. The integration tests in `versioning_integration_test.go`, `certificate_export_test.go`, `certificate_exportable_test.go` and `export_tls_e2e_test.go` already create enabled keys.

- [ ] **Step 5: Run the tests and confirm they pass**

Run: `go vet ./internal/services/certificates/ && go test ./internal/services/certificates/ -count=1`
Expected: `ok  	rocketvault/internal/services/certificates`.

- [ ] **Step 6: Lint and commit**

Run: `BASE=$(cat .git/rv-cert-isolation-base); PATH="$HOME/go/pkg/mod/golang.org/toolchain@v0.0.1-go1.25.7.linux-amd64/bin:$PATH" GOTOOLCHAIN=local ~/go/bin/golangci-lint run --new-from-rev="$BASE" ./internal/services/certificates/`
Expected: `0 issues.`

Stage `certificate_service.go`, the new test file and the changed fixtures, then invoke the `dev-workflow-skills:1-git-commit` skill via the Skill tool. The subject should say certificate issuance and renewal refuse revoked, disabled or out-of-window keys (B77). No footer yet.

---

### Task 6: A CA certificate signs only while its own linked key is usable (B77, key-revocation decision)

**Files:**
- Modify: `internal/services/certificates/certificate_service.go` (new method `requireCAKeyUsable` before `requireUsableKey`; call sites in `CreateCASignedCertificate` after the `caStatus != caStatusCA` block, `:510-513` at HEAD, and in `renewCASignedBody` after its `caStatus != caStatusCA` block, `:906-909` at HEAD)
- Modify: `internal/services/certificates/signing_key_lifecycle_test.go` (imports, helper, tests)
- Modify: `internal/services/certificates/ca_renewal_test.go` (fixture `caRenewalFixture`/`newCARenewalFixture`, lines 21-123 at HEAD; new test)
- Modify (fixtures): `certificate_service_extended_test.go`, `cert_soft_delete_test.go`, `ca_renewal_scheduler_test.go`

**Interfaces:**
- Consumes: `ErrSigningKeyUnusable`, `requireUsableKey` (Task 5).
- Produces: unexported `(s *certificateService) requireCAKeyUsable(ctx context.Context, caCert *model.Certificate, scope model.Scope) error`; test helper `linkUsableCAKey(keyRepo *mockKeyRepo, caCert *model.Certificate, scope any)`; field `caRenewalFixture.caKey *model.Key`.

Decision recorded here and in § B77: a certificate row stores a copy of its key's private PEM, used only as a CA signing key (`caCert.PrivateKey` in `CreateCASignedCertificate` and `renewCASignedBody`) and, for an exportable certificate, by `ExportCertificate`. Revoking, disabling or expiring the key stops that CA from issuing or renewing anything. Certificates already issued are not revoked, disabled or deleted: that would be a destructive cross-object side effect of a key operation, Azure does not cascade either, and X.509 revocation is its own concern. The embedded copy is not erased, and export of an already-exportable certificate is unchanged (its export gates are the certificate's own lifecycle and the exporter role, `certificate_export.go:79-109`). A CA row with no key link is refused as a signer: every CA that passes `inspectCertificateCA` was issued after `certificates.key_id` existed (added 2026-05-23, commit `1c4048d3`; the keyCertSign fix, B43, came 2026-08-21), so such a row can only be one whose link was dropped at restore (Task 3).

- [ ] **Step 1: Write the failing tests**

In `internal/services/certificates/signing_key_lifecycle_test.go`, replace the import block with:

```go
import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"rocketvault/common"
	"rocketvault/internal/crypto"
	"rocketvault/model"
)
```

and append:

```go

// linkUsableCAKey gives a CA certificate fixture an enabled signing key and
// registers the key read the CA-key gate performs (B77).
func linkUsableCAKey(keyRepo *mockKeyRepo, caCert *model.Certificate, scope any) {
	caKeyID := uuid.New()
	caCert.KeyID = caKeyID
	keyRepo.On("Read", mock.Anything, caKeyID, scope).Return(&model.Key{
		ID: caKeyID, UserID: caCert.UserID, VaultID: caCert.VaultID, Enabled: true,
	}, nil)
}

func TestRequireCAKeyUsable(t *testing.T) {
	t.Parallel()

	userID, vaultID := uuid.New(), uuid.New()
	scope := model.NewVaultScope(vaultID, userID)
	past := time.Now().Add(-time.Hour)

	withKey := func(t *testing.T, key *model.Key, readErr error) error {
		t.Helper()
		keyRepo := &mockKeyRepo{}
		caKeyID := uuid.New()
		if readErr != nil {
			keyRepo.On("Read", mock.Anything, caKeyID, scope).Return(nil, readErr)
		} else {
			key.ID = caKeyID
			keyRepo.On("Read", mock.Anything, caKeyID, scope).Return(key, nil)
		}
		svc := newCertSvc(&mockCertRepository{}, keyRepo).(*certificateService)
		return svc.requireCAKeyUsable(context.Background(), &model.Certificate{ID: uuid.New(), KeyID: caKeyID}, scope)
	}

	t.Run("no key link is refused", func(t *testing.T) {
		svc := newCertSvc(&mockCertRepository{}, &mockKeyRepo{}).(*certificateService)
		err := svc.requireCAKeyUsable(context.Background(), &model.Certificate{ID: uuid.New()}, scope)
		require.ErrorIs(t, err, ErrSigningKeyUnusable)
	})
	t.Run("revoked key is refused", func(t *testing.T) {
		require.ErrorIs(t, withKey(t, &model.Key{Enabled: true, Revoked: true}, nil), ErrSigningKeyUnusable)
	})
	t.Run("expired key is refused", func(t *testing.T) {
		require.ErrorIs(t, withKey(t, &model.Key{Enabled: true, ExpiresAt: &past}, nil), ErrSigningKeyUnusable)
	})
	t.Run("key outside the vault is refused", func(t *testing.T) {
		require.ErrorIs(t, withKey(t, nil, errors.New("key not found or access denied")), ErrSigningKeyUnusable)
	})
	t.Run("usable key passes", func(t *testing.T) {
		require.NoError(t, withKey(t, &model.Key{Enabled: true}, nil))
	})
}

// TestCreateCASignedCertificate_RefusesCAWithRevokedKey is the creation half
// of the revocation decision: the CA row's embedded copy of a revoked key
// must not keep signing.
func TestCreateCASignedCertificate_RefusesCAWithRevokedKey(t *testing.T) {
	setupMasterKey()

	userID, keyID, caCertID, caKeyID := uuid.New(), uuid.New(), uuid.New(), uuid.New()

	entityKeyPEM, err := crypto.GenerateRSAKeyPEM(2048)
	require.NoError(t, err)
	caKeyPEM, err := crypto.GenerateRSAKeyPEM(2048)
	require.NoError(t, err)
	caCertPEM, err := crypto.CreateSelfSignedCertificatePEM(caKeyPEM, "RSA", crypto.CertificateTemplate{
		CommonName: "Revoked-key CA", ValidityDays: 3650, IsCA: true,
	})
	require.NoError(t, err)
	encEntity, err := common.EncryptSecret(entityKeyPEM)
	require.NoError(t, err)
	encCA, err := common.EncryptSecret(caKeyPEM)
	require.NoError(t, err)

	certRepo := &mockCertRepository{}
	keyRepo := &mockKeyRepo{}
	keyRepo.On("Read", mock.Anything, keyID, certVaultScope(userID)).
		Return(&model.Key{ID: keyID, UserID: userID, Type: model.KeyTypeRSA, Value: encEntity, Enabled: true}, nil)
	keyRepo.On("Read", mock.Anything, caKeyID, certVaultScope(userID)).
		Return(&model.Key{ID: caKeyID, UserID: userID, Type: model.KeyTypeRSA, Enabled: true, Revoked: true}, nil)
	certRepo.On("Read", mock.Anything, caCertID, certVaultScope(userID)).Return(&model.Certificate{
		ID: caCertID, UserID: userID, KeyID: caKeyID, Name: "revoked-key-ca",
		Certificate: caCertPEM, PrivateKey: encCA, Enabled: true,
	}, nil)
	// No Create stub: creation must stop before storing anything.

	svc := newCertSvc(certRepo, keyRepo)
	_, err = svc.CreateCASignedCertificate(context.Background(), CreateCertificateRequest{
		Name: "entity-cert", KeyID: keyID, ValidityDays: 365, UserID: userID, CACertID: &caCertID,
	})
	require.ErrorIs(t, err, ErrSigningKeyUnusable)
	certRepo.AssertNotCalled(t, "Create", mock.Anything, mock.Anything)
}
```

In `internal/services/certificates/ca_renewal_test.go`, change the fixture:
- in `caRenewalFixture`, after `updated  **model.Certificate` add:

```go
	// caKey is the CA's own linked key. A test sets Revoked or Enabled on it
	// to drive the CA-key gate (B77).
	caKey *model.Key
```

- in `newCARenewalFixture`, after `caCertID := uuid.New()` add `caKeyID := uuid.New()`;
- in its `caCert` literal, after `VaultID:     vaultID,` add `KeyID:       caKeyID,`;
- after the entity key's `keyRepo.On("Read", mock.Anything, keyID, scope).Return(...)` expectation add:

```go
	caKey := &model.Key{ID: caKeyID, UserID: userID, VaultID: vaultID, Type: caKeyType, Enabled: true}
	keyRepo.On("Read", mock.Anything, caKeyID, scope).Return(caKey, nil)
```

- in the returned `&caRenewalFixture{...}` literal, after `updated:  &updated,` add `caKey:    caKey,`.

Then append to `ca_renewal_test.go`:

```go

// The renewal half of the revocation decision (B77): once the CA's own key
// is revoked, its embedded copy must not re-sign anything.
func TestRenewCertificate_RevokedCAKeyRefusesRenewal(t *testing.T) {
	f := newCARenewalFixture(t, "RSA")
	f.caKey.Revoked = true

	_, err := f.svc.RenewCertificate(context.Background(), f.certID, f.scope, 365)
	require.ErrorIs(t, err, ErrSigningKeyUnusable)
	f.certRepo.AssertNotCalled(t, "Update", mock.Anything, mock.Anything, mock.Anything)
}
```

- [ ] **Step 2: Run the tests and confirm they fail**

Run: `go test ./internal/services/certificates/ -run 'TestRequireCAKeyUsable|RefusesCAWithRevokedKey|RevokedCAKeyRefusesRenewal' -count=1`
Expected: FAIL at build time: `svc.requireCAKeyUsable undefined`.

- [ ] **Step 3: Implement**

In `certificate_service.go`, immediately before the line `// requireUsableKey refuses a key that is revoked, disabled, or outside its` (added in Task 5), add:

```go
// requireCAKeyUsable refuses to sign through a CA certificate whose own
// linked key is revoked, disabled, outside its validity window, or no longer
// readable in scope. The CA row stores a copy of that key's private PEM, so
// without this check revoking the key would not stop the CA from issuing
// (B77). A CA row with no key link is refused too: every CA that passes
// inspectCertificateCA was issued after key_id existed, so a missing link
// means it was dropped at restore (B76) and the key cannot be checked.
func (s *certificateService) requireCAKeyUsable(ctx context.Context, caCert *model.Certificate, scope model.Scope) error {
	if caCert.KeyID == uuid.Nil {
		return fmt.Errorf("%w: CA certificate %s records no signing key", ErrSigningKeyUnusable, caCert.ID)
	}
	key, err := s.keyRepo.Read(ctx, caCert.KeyID, scope)
	if err != nil {
		return fmt.Errorf("%w: CA signing key %s is not readable: %w", ErrSigningKeyUnusable, caCert.KeyID, err)
	}
	return requireUsableKey(key)
}

```

In `CreateCASignedCertificate`, replace

```go
	if caStatus != caStatusCA {
		s.logger.LogAuditError(req.UserID.String(), "create_ca_signed_cert", "failed", "CA certificate cannot sign certificates", nil)
		return nil, fmt.Errorf("signing CA %s cannot sign certificates (asserts CA without keyCertSign, or is not a CA); reissue it with --is-ca", *req.CACertID)
	}
```

with

```go
	if caStatus != caStatusCA {
		s.logger.LogAuditError(req.UserID.String(), "create_ca_signed_cert", "failed", "CA certificate cannot sign certificates", nil)
		return nil, fmt.Errorf("signing CA %s cannot sign certificates (asserts CA without keyCertSign, or is not a CA); reissue it with --is-ca", *req.CACertID)
	}

	// The CA signs with its row's embedded copy of its key, so that key's
	// lifecycle decides whether it may still sign (B77).
	if err := s.requireCAKeyUsable(ctx, caCert, certScope); err != nil {
		s.logger.LogAuditError(req.UserID.String(), "create_ca_signed_cert", "failed", "CA signing key is unusable", err)
		return nil, fmt.Errorf("cannot issue a CA-signed certificate: %w", err)
	}
```

In `renewCASignedBody`, replace

```go
	if caStatus != caStatusCA {
		s.logger.LogAuditError(userID.String(), "renew_certificate", "failed", "signing CA certificate cannot sign certificates", nil)
		return "", fmt.Errorf("signing CA %s cannot sign certificates (asserts CA without keyCertSign, or is not a CA); reissue it with --is-ca", caCertID)
	}
```

with

```go
	if caStatus != caStatusCA {
		s.logger.LogAuditError(userID.String(), "renew_certificate", "failed", "signing CA certificate cannot sign certificates", nil)
		return "", fmt.Errorf("signing CA %s cannot sign certificates (asserts CA without keyCertSign, or is not a CA); reissue it with --is-ca", caCertID)
	}

	// See CreateCASignedCertificate: the CA's own key must still be usable.
	if err := s.requireCAKeyUsable(ctx, caCert, scope); err != nil {
		s.logger.LogAuditError(userID.String(), "renew_certificate", "failed", "signing CA key is unusable", err)
		return "", fmt.Errorf("cannot renew CA-signed certificate: %w", err)
	}
```

- [ ] **Step 4: Fix the CA fixtures the gate now refuses**

The gate sits after the `caStatus` refusal, so only tests that build a real CA and expect a successful CA-signed issue or renewal reach it. The three such tests built on `newCARenewalFixture` (`TestRenewCertificate_CASignedPreservesIssuerAndChain`, `_ECDSACAPreservesChain`, `_ResultReportsExportableAndKeyAlgorithm`) are already covered by the fixture edit in Step 1. Run `go test ./internal/services/certificates/ -count=1 2>&1 | grep -E '^--- FAIL'`; at this point it lists exactly seven tests: `TestCheckAndRenewCertificates_CASignedKeepsIssuer` and six `TestCreateCASignedCertificate_*` tests. Edit them as follows:

`certificate_service_extended_test.go`, three tests that already hold the CA in a `caCert` variable (`TestCreateCASignedCertificate_FullSuccess`, `_RepoCreateFails`, `_WithExplicitEnabledFalse`): each has exactly the line below; add the helper call above it in all three:

```go
	linkUsableCAKey(keyRepo, caCert, certVaultScope(userID))
	certRepo.On("Read", mock.Anything, caCertID, certVaultScope(userID)).Return(caCert, nil)
```

`certificate_service_extended_test.go`, `TestCreateCASignedCertificate_StoresCACertID`: replace

```go
	certRepo.On("Read", mock.Anything, caCertID, certVaultScope(userID)).
		Return(&model.Certificate{
			ID: caCertID, UserID: userID, Name: "test-ca",
			Certificate: caCertPEM, PrivateKey: encCA, Enabled: true,
		}, nil)
```

with

```go
	caCert := &model.Certificate{
		ID: caCertID, UserID: userID, Name: "test-ca",
		Certificate: caCertPEM, PrivateKey: encCA, Enabled: true,
	}
	linkUsableCAKey(keyRepo, caCert, certVaultScope(userID))
	certRepo.On("Read", mock.Anything, caCertID, certVaultScope(userID)).Return(caCert, nil)
```

`certificate_service_extended_test.go`, `TestCreateCASignedCertificate_ECDSACA`: the same replacement with `Name: "ecdsa-ca"`.

`cert_soft_delete_test.go`, `TestCreateCASignedCertificate_SetsPurgeProtectionWhenRequested`: replace

```go
	certRepo.On("Read", mock.Anything, caCertID, certVaultScope(userID)).Return(&model.Certificate{
		ID: caCertID, UserID: userID, Name: "test-ca", Certificate: caCertPEM, PrivateKey: encryptedCAKey,
	}, nil)
```

with

```go
	caCert := &model.Certificate{
		ID: caCertID, UserID: userID, Name: "test-ca", Certificate: caCertPEM, PrivateKey: encryptedCAKey,
	}
	linkUsableCAKey(keyRepo, caCert, certVaultScope(userID))
	certRepo.On("Read", mock.Anything, caCertID, certVaultScope(userID)).Return(caCert, nil)
```

`ca_renewal_scheduler_test.go`, `TestCheckAndRenewCertificates_CASignedKeepsIssuer` (`vaultScope` is the name Task 1 gave it): replace

```go
	certRepo.On("Read", mock.Anything, caCertID, vaultScope).Return(caCert, nil)
```

with

```go
	linkUsableCAKey(keyRepo, caCert, vaultScope)
	certRepo.On("Read", mock.Anything, caCertID, vaultScope).Return(caCert, nil)
```

Not affected, checked by running them: `ca_opt_in_test.go` (its CA-signed test is refused on `IsCA` before any read); the pseudo-CA and leaf-as-CA tests in `ca_renewal_test.go` (refused by `caStatus` first); `renew_sentinels_test.go` (refused before the CA is used); and the real-repository suites `certificate_export_test.go`, `export_tls_e2e_test.go` and `versioning_integration_test.go`, whose CAs are created through the service with an enabled key, so their `key_id` resolves.

- [ ] **Step 5: Run the tests and confirm they pass**

Run: `go vet ./internal/services/certificates/ && go test ./internal/services/certificates/ -count=1`
Expected: `ok  	rocketvault/internal/services/certificates`.

- [ ] **Step 6: Lint and commit**

Run: `BASE=$(cat .git/rv-cert-isolation-base); PATH="$HOME/go/pkg/mod/golang.org/toolchain@v0.0.1-go1.25.7.linux-amd64/bin:$PATH" GOTOOLCHAIN=local ~/go/bin/golangci-lint run --new-from-rev="$BASE" ./internal/services/certificates/`
Expected: `0 issues.`

Stage the files of this task, then invoke the `dev-workflow-skills:1-git-commit` skill via the Skill tool. The subject should say a CA certificate signs only while its linked key is usable (B77). No footer yet.

---

### Task 7: Issuing or renewing a certificate requires keys/sign on every entry point (B77)

**Files:**
- Modify: `api/certificates.go:24-38` (imports), `:158-160` (comment), after `:200-203` (`svc` lookup in `createCertificate`), new helper `requireKeySign` before `listCertificates` (line 271)
- Modify: `api/certificates_versions.go:147-149` (comment), after `:167-170` (`scopeFromRequest` in `renewCertificate`)
- Modify: `api/certificates_test.go:167-170` (`certSvcContainer` fields), `:235-240` (policy and role getters), new helper `allowAllDataPlane`
- Modify: `api/certificates_versions_test.go:272-309` (`TestCertificateVersionRoutes_BothShapes`, one line per subtest, plus helper `allowKeySignOn`)
- Create: `api/certificates_key_sign_test.go`
- Modify: `cmd/certificates/create.go:34-37` (Long), after `:101-103` (`s.Authorize()`)
- Modify: `cmd/certificates/renew.go:34-37` (Long), after `:75-77` (`s.Authorize()`)
- Modify: `cmd/certificates/certs_cmd_test.go:603-607` (`TestCertCreateCmd_Authorized`), `:1298-1302` (`TestCertRenewCmd_Authorized`)
- Create: `cmd/certificates/key_sign_test.go`
- Modify: `internal/vaultapi/errors.go:90-96` (hint), new helper `issuesCertificate` before `roleFor`'s doc comment (line 137); `internal/vaultapi/errors_test.go` (new test)

**Interfaces:**
- Consumes: `authorization.RequireDataPlaneAccess`, `authorization.ErrDataPlaneDenied`, `(*vaultcli.Session).RequireAlso` (Task 4); `(*Context).auditDenied(operation, permission string)` (`api/context.go:124`, B81).
- Produces: unexported `requireKeySign(c *Context, r *http.Request, userID, vaultID uuid.UUID, operation string) bool` in package `api`. `POST /certificates`, `POST /vaults/{name}/certificates`, `POST /certificates/{id}/renew` and `POST /vaults/{name}/certificates/{id}/renew` answer 403 (audited as `create_certificate`/`renew_certificate` `denied`) unless the caller holds `Microsoft.KeyVault/vaults/keys/sign/action` in the vault and no deny on `(keys, sign)` applies; a lookup failure is a 500. The MCP `create_certificate` and `renew_certificate` tools reach these routes through `internal/vaultapi`, so they inherit the check. `rocketvault certificate create` and `certificate renew` fail with `failed to create certificate: ...` / `failed to renew certificate: ...` under the same condition. No route is added, so `api.VerifyRouteAuthorization` and its allow-list are unaffected.

- [ ] **Step 1: Make the handler test doubles allow by default**

In `api/certificates_test.go`, replace

```go
type certSvcContainer struct {
	certSvc        certServices.CertificateService
	certPolicyRepo repositories.CertificatePolicyRepositoryInterface
}
```

with

```go
type certSvcContainer struct {
	certSvc        certServices.CertificateService
	certPolicyRepo repositories.CertificatePolicyRepositoryInterface
	// policySvc and roleSvc back the keys/sign check in createCertificate and
	// renewCertificate. Nil means allow, so tests that are not about that
	// check need no setup.
	policySvc authzServices.AccessPolicyService
	roleSvc   authzServices.RoleAssignmentService
}
```

and replace its two getters

```go
func (c *certSvcContainer) GetAccessPolicyService() authzServices.AccessPolicyService {
	panic("unexpected call: GetAccessPolicyService")
}
func (c *certSvcContainer) GetRoleAssignmentService() authzServices.RoleAssignmentService {
	return nil
}
```

with

```go
func (c *certSvcContainer) GetAccessPolicyService() authzServices.AccessPolicyService {
	if c.policySvc != nil {
		return c.policySvc
	}
	policies, _ := allowAllDataPlane()
	return policies
}
func (c *certSvcContainer) GetRoleAssignmentService() authzServices.RoleAssignmentService {
	if c.roleSvc != nil {
		return c.roleSvc
	}
	_, roles := allowAllDataPlane()
	return roles
}

// allowAllDataPlane returns policy and role services that pass every
// data-plane check, for handler tests that are not about authorization.
func allowAllDataPlane() (authzServices.AccessPolicyService, authzServices.RoleAssignmentService) {
	policies := &mockAccessPolicyService{}
	policies.On("CheckAccess", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).
		Return(authzServices.AccessFallback, nil)
	roles := &mockRoleAssignmentService{}
	roles.On("HasDataAction", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(true, nil)
	return policies, roles
}
```

(`mockAccessPolicyService` and `mockRoleAssignmentService` are the package's existing testify mocks, `api/access_policies_test.go:46`, `api/role_assignments_test.go:24`.)

In `api/certificates_versions_test.go`, immediately before `func TestCertificateVersionRoutes_BothShapes(t *testing.T) {`, add:

```go
// allowKeySignOn lets the renew route's keys/sign check pass on a test API
// built by newVaultScopedKeyCertTestAPI (B77).
func allowKeySignOn(api *API) {
	c := api.App.ServiceContainer.(*vaultSvcTestContainer)
	c.policySvc, c.roleSvc = allowAllDataPlane()
}

```

and inside that test add `allowKeySignOn(api)` on the line after each of the two `newVaultScopedKeyCertTestAPI(nil, rec, nil)` calls (the flat subtest's `api, _ := ...` and the vault-scoped subtest's `api, repo := ...`). `vaultSvcTestContainer` panics on an unset policy service (`api/vault_test.go:253-258`), which is why the renew subtests need it and the read-only ones do not mind.

- [ ] **Step 2: Write the failing HTTP tests**

Create `api/certificates_key_sign_test.go`:

```go
package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	authzServices "rocketvault/internal/services/authorization"
	"rocketvault/model"
)

// postCreateCertificate runs createCertificate for a minimal valid body.
func postCreateCertificate(c *Context) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	body, _ := json.Marshal(map[string]any{
		"name": "mycert", "key_id": uuid.New().String(), "validity_days": 365,
	})
	r := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/certificates", bytes.NewReader(body))
	createCertificate(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}
	return w
}

// TestCreateCertificate_RequiresKeySign pins B77 on the HTTP path. The route
// maps to certificates/create only, but issuing a certificate signs with the
// key, so keys/sign is required in the same vault.
func TestCreateCertificate_RequiresKeySign(t *testing.T) {
	svc := &mockCertService{}
	roles := &mockRoleAssignmentService{}
	roles.On("HasDataAction", mock.Anything, uuid.MustParse(certTestUserID),
		uuid.MustParse(model.DefaultVaultID), model.ActionKeysSign).Return(false, nil)

	c := newCertCtx(svc, certAdminClaims())
	c.App.ServiceContainer.(*certSvcContainer).roleSvc = roles

	w := postCreateCertificate(c)
	assert.Equal(t, http.StatusForbidden, w.Code)
	svc.AssertNotCalled(t, "CreateSelfSignedCertificate", mock.Anything, mock.Anything)
	roles.AssertExpectations(t)
}

// TestCreateCertificate_KeySignDenyPolicyRefuses pins the explicit-deny half:
// a deny on (keys, sign) blocks issuance even when a role would grant it.
func TestCreateCertificate_KeySignDenyPolicyRefuses(t *testing.T) {
	svc := &mockCertService{}
	policies := &mockAccessPolicyService{}
	policies.On("CheckAccess", mock.Anything, uuid.MustParse(certTestUserID), model.PolicyResourceKeys,
		model.OpSign, uuid.MustParse(model.DefaultVaultID)).Return(authzServices.AccessDenied, nil)

	c := newCertCtx(svc, certAdminClaims())
	c.App.ServiceContainer.(*certSvcContainer).policySvc = policies

	w := postCreateCertificate(c)
	assert.Equal(t, http.StatusForbidden, w.Code)
	svc.AssertNotCalled(t, "CreateSelfSignedCertificate", mock.Anything, mock.Anything)
}

// TestRenewCertificate_RequiresKeySign pins B77 on the HTTP renew route, which
// the MCP renew_certificate tool also uses. Renewal re-signs with the
// certificate's key, so keys/sign is required, exactly as for issuance.
func TestRenewCertificate_RequiresKeySign(t *testing.T) {
	svc := &mockCertService{}
	roles := &mockRoleAssignmentService{}
	roles.On("HasDataAction", mock.Anything, uuid.MustParse(certTestUserID),
		uuid.MustParse(model.DefaultVaultID), model.ActionKeysSign).Return(false, nil)

	c := newCertCtx(svc, certAdminClaims())
	c.App.ServiceContainer.(*certSvcContainer).roleSvc = roles
	c.Params.CertificateID = uuid.New().String()
	w := httptest.NewRecorder()
	r := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/certificates", bytes.NewBufferString(`{"validity_days":90}`))

	renewCertificate(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusForbidden, w.Code)
	svc.AssertNotCalled(t, "RenewCertificate", mock.Anything, mock.Anything, mock.Anything, mock.Anything)
	svc.AssertNotCalled(t, "GetCertificate", mock.Anything, mock.Anything, mock.Anything)
	roles.AssertExpectations(t)
}
```

Run: `go test ./api/ -run 'KeySign' -count=1`
Expected: FAIL. The handlers never consult the role or policy service and call the mocked service, which has no expectation, so testify panics with `mock: I don't know what to return`.

- [ ] **Step 3: Implement the HTTP check**

In `api/certificates.go`, add `authzServices "rocketvault/internal/services/authorization"` to the project imports, between `"rocketvault/internal/crypto"` and `certServices "rocketvault/internal/services/certificates"`.

Replace the opening comment of `createCertificate`

```go
	// Authorization happens in PolicyMiddleware: creating a certificate requires
	// the Microsoft.KeyVault/vaults/certificates/create data action, granted by
	// Key Vault Certificates Officer or Key Vault Administrator in this vault.
```

with

```go
	// Authorization is two checks. PolicyMiddleware requires the
	// Microsoft.KeyVault/vaults/certificates/create data action, and
	// requireKeySign below additionally requires keys/sign/action, because
	// issuing a certificate signs with the named key (B77).
```

Replace

```go
	certService, svcOK := svc(c, container.ServiceContainerInterface.GetCertificateService)
	if !svcOK {
		return
	}

	createReq := certServices.CreateCertificateRequest{
```

with

```go
	certService, svcOK := svc(c, container.ServiceContainerInterface.GetCertificateService)
	if !svcOK {
		return
	}
	if !requireKeySign(c, r, userID, vaultID, "create_certificate") {
		return
	}

	createReq := certServices.CreateCertificateRequest{
```

Immediately before the line `// listCertificates lists certificates. Legacy flat routes list the default`, add:

```go
// requireKeySign runs the full data-plane check for keys/sign in vaultID and
// reports whether the request may continue. Issuing or renewing a
// certificate signs with its key, but PolicyMiddleware only checked the
// route's certificates/create action, so a caller without keys/sign, or with
// an explicit deny on key sign, could still sign through the certificate
// routes (B77). The CLI runs the same check through vaultcli.Session.RequireAlso.
func requireKeySign(c *Context, r *http.Request, userID, vaultID uuid.UUID, operation string) bool {
	err := authzServices.RequireDataPlaneAccess(r.Context(),
		c.App.ServiceContainer.GetAccessPolicyService(), c.App.ServiceContainer.GetRoleAssignmentService(),
		userID, vaultID, model.PolicyResourceKeys, model.OpSign, model.ActionKeysSign)
	if err == nil {
		return true
	}
	if errors.Is(err, authzServices.ErrDataPlaneDenied) {
		c.auditDenied(operation, string(model.ActionKeysSign))
		return false
	}
	c.SetInternalError(err)
	return false
}

```

In `api/certificates_versions.go`, replace the comment above `renewCertificate`

```go
// renewCertificate issues a new version of a certificate and returns that
// version's metadata. Authorization happens in PolicyMiddleware: renewing
// requires the certificates/create data action (data_actions.go).
```

with

```go
// renewCertificate issues a new version of a certificate and returns that
// version's metadata. PolicyMiddleware requires the certificates/create data
// action (data_actions.go), and requireKeySign additionally requires
// keys/sign/action, because renewal re-signs with the certificate's key (B77).
```

and replace

```go
	scope, ok := scopeFromRequest(c, r)
	if !ok {
		return
	}

	var validityDays int
```

with

```go
	scope, ok := scopeFromRequest(c, r)
	if !ok {
		return
	}
	if !requireKeySign(c, r, scope.ActorID(), scope.VaultID(), "renew_certificate") {
		return
	}

	var validityDays int
```

The check runs before the default-validity `GetCertificate`, so a refused caller learns nothing about the certificate.

Run: `go vet ./api/ && go test ./api/ -count=1`
Expected: `ok  	rocketvault/api`.

- [ ] **Step 4: Write the failing CLI tests**

In `cmd/certificates/certs_cmd_test.go`, in both `TestCertCreateCmd_Authorized` and `TestCertRenewCmd_Authorized`, after the existing

```go
	roles.On("HasDataAction", mock.Anything, tc.TestUserID, tc.TestVaultID, model.ActionCertificatesCreate).
		Return(true, nil).Once()
```

add

```go
	roles.On("HasDataAction", mock.Anything, tc.TestUserID, tc.TestVaultID, model.ActionKeysSign).
		Return(true, nil).Once()
```

and after the existing `policies.On("CheckAccess", ..., model.PolicyResourceCertificates, model.OpCreate, ...)` (create) or `..., model.OpRenew, ...` (renew) expectation and its `.Return(authzServices.AccessAllowed, nil).Once()` line, add

```go
	policies.On("CheckAccess", mock.Anything, tc.TestUserID, model.PolicyResourceKeys, model.OpSign, tc.TestVaultID).
		Return(authzServices.AccessAllowed, nil).Once()
```

Create `cmd/certificates/key_sign_test.go`:

```go
package certificates

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	"rocketvault/cmd/testutils"
	"rocketvault/common"
	"rocketvault/model"
)

// TestCertCreateCmd_RequiresKeySign pins B77 on the CLI path:
// certificates/create alone is not enough, exactly as over HTTP.
func TestCertCreateCmd_RequiresKeySign(t *testing.T) {
	tc := testutils.NewTestContext(t)
	certSvc := &certCmdCertService{}
	keyID := uuid.New()

	roles := &testutils.MockRoleAssignmentService{}
	roles.On("HasDataAction", mock.Anything, tc.TestUserID, tc.TestVaultID, model.ActionCertificatesCreate).Return(true, nil)
	roles.On("HasDataAction", mock.Anything, tc.TestUserID, tc.TestVaultID, model.ActionKeysSign).Return(false, nil)
	tc.MockContainer.RoleAssignmentService = roles

	sc := &certsTestContainer{MockServiceContainer: tc.MockContainer, certSvc: certSvc}
	claims := &model.Claims{UserID: tc.TestUserID, Username: "admin", Roles: []string{model.RoleAdmin}}
	ctx := context.WithValue(context.Background(), common.ClaimsKey, claims)
	ctx = context.WithValue(ctx, common.LogKey, newCertLogger())
	ctx = context.WithValue(ctx, common.ServiceContainerKey, sc)
	ctx = context.WithValue(ctx, common.OutputFormatterKey, newCertFmtr())

	cmd, _ := newCertCmd(createCmd.RunE, nil)
	cmd.Flags().Bool("auto-renew", false, "")
	cmd.Flags().Int("renewal-days", 30, "")
	setFlags(cmd, map[string]any{"name": "mycert",
		"key-id":        keyID.String(),
		"validity-days": 365,
		"tags":          "",
		"ca-cert-id":    ""})
	cmd.SetContext(ctx)
	err := cmd.Execute()
	assert.ErrorContains(t, err, "failed to create certificate")
	assert.ErrorContains(t, err, string(model.ActionKeysSign))
	certSvc.AssertNotCalled(t, "CreateSelfSignedCertificate", mock.Anything, mock.Anything)
}

// TestCertRenewCmd_RequiresKeySign pins the same requirement for renewal.
func TestCertRenewCmd_RequiresKeySign(t *testing.T) {
	tc := testutils.NewTestContext(t)
	certSvc := &certCmdCertService{}
	certID := uuid.New()

	roles := &testutils.MockRoleAssignmentService{}
	roles.On("HasDataAction", mock.Anything, tc.TestUserID, tc.TestVaultID, model.ActionCertificatesCreate).Return(true, nil)
	roles.On("HasDataAction", mock.Anything, tc.TestUserID, tc.TestVaultID, model.ActionKeysSign).Return(false, nil)
	tc.MockContainer.RoleAssignmentService = roles

	sc := &certsTestContainer{MockServiceContainer: tc.MockContainer, certSvc: certSvc}
	claims := &model.Claims{UserID: tc.TestUserID, Roles: []string{model.RoleAdmin}}
	ctx := context.WithValue(context.Background(), common.ClaimsKey, claims)
	ctx = context.WithValue(ctx, common.LogKey, newCertLogger())
	ctx = context.WithValue(ctx, common.ServiceContainerKey, sc)

	cmd, _ := newCertCmd(renewCmd.RunE, []string{certID.String()})
	cmd.Args = cobra.ExactArgs(1)
	setFlags(cmd, map[string]any{"validity-days": 365})
	cmd.SetContext(ctx)
	err := cmd.Execute()
	assert.ErrorContains(t, err, "failed to renew certificate")
	assert.ErrorContains(t, err, string(model.ActionKeysSign))
	certSvc.AssertNotCalled(t, "RenewCertificate", mock.Anything, mock.Anything, mock.Anything, mock.Anything)
	certSvc.AssertNotCalled(t, "GetCertificate", mock.Anything, mock.Anything, mock.Anything)
}
```

Run: `go test ./cmd/certificates/ -run 'RequiresKeySign|Authorized' -count=1`
Expected: FAIL. The two `RequiresKeySign` tests reach the service; the two `Authorized` tests fail `roles.AssertExpectations` and `policies.AssertExpectations` because the keys/sign expectations were never used.

- [ ] **Step 5: Implement the CLI check**

In `cmd/certificates/create.go`, replace

```go
		if err := s.Authorize(); err != nil {
			return err
		}
		certService := s.Container.GetCertificateService()
```

with

```go
		if err := s.Authorize(); err != nil {
			return err
		}
		// Issuing a certificate signs with --key-id, so keys/sign is required
		// as well, exactly as the HTTP handler requires it (B77).
		if err := s.RequireAlso(model.ActionKeysSign, model.OpSign); err != nil {
			return err
		}
		certService := s.Container.GetCertificateService()
```

and in its `Long` text replace

```
Requires the admin or certificate_manager role, and the
Microsoft.KeyVault/vaults/certificates/create data action in the target
vault. The key named by --key-id must also be owned by the calling user, as
must the certificate named by --ca-cert-id.
```

with

```
Requires the admin or certificate_manager role, and both the
Microsoft.KeyVault/vaults/certificates/create and the
Microsoft.KeyVault/vaults/keys/sign/action data actions in the target
vault (for example Key Vault Certificates Officer plus Key Vault Crypto
User). The key named by --key-id must be owned by the calling user and be
enabled, not revoked, and inside its validity window. The certificate named
by --ca-cert-id must be owned by the calling user, and its own key must be
usable in the same way.
```

In `cmd/certificates/renew.go`, make the identical `s.Authorize()` replacement, with the comment

```go
		// Renewal re-signs with the certificate's key, so it needs keys/sign
		// like issuance does (B77).
```

and in its `Long` text replace

```
vault — not certificates/update. The certificate's key must still exist in
that vault and be owned by the calling user.
```

with

```
vault — not certificates/update. Renewal also needs the
Microsoft.KeyVault/vaults/keys/sign/action data action there, because it
signs with the certificate's key. That key must still exist in the vault,
be owned by the calling user, and be enabled, not revoked, and inside its
validity window. A CA's own key must be usable in the same way.
```

`TestRenewCmd_LongDescribesCAPreservation` (`renew_help_test.go:12`) enforces a 78-byte line limit and the phrase `Microsoft.KeyVault/vaults/certificates/create`; both still hold.

- [ ] **Step 6: Name keys/sign in the client-side 403 hint**

The vault client's 403 hint for a certificate POST names only Certificates Officer, which is now insufficient. In `internal/vaultapi/errors.go`, replace

```go
		resource, verb := resourceAndVerb(e.Method, e.Path)
		action := fmt.Sprintf("Microsoft.KeyVault/vaults/%s/%s", resource, verb)
		role := roleFor(resource, verb)
		vault := vaultFromPath(e.Path)
		if vault == "" {
			return fmt.Sprintf("principal lacks %s; grant e.g. %q", action, role)
		}
		return fmt.Sprintf("principal lacks %s in vault %q; grant e.g. %q", action, vault, role)
```

with

```go
		resource, verb := resourceAndVerb(e.Method, e.Path)
		action := fmt.Sprintf("Microsoft.KeyVault/vaults/%s/%s", resource, verb)
		role := roleFor(resource, verb)
		vault := vaultFromPath(e.Path)
		hint := fmt.Sprintf("principal lacks %s; grant e.g. %q", action, role)
		if vault != "" {
			hint = fmt.Sprintf("principal lacks %s in vault %q; grant e.g. %q", action, vault, role)
		}
		if issuesCertificate(e.Method, e.Path) {
			hint += "; issuing or renewing a certificate also needs Microsoft.KeyVault/vaults/keys/sign/action, e.g. \"Key Vault Crypto User\""
		}
		return hint
```

and immediately before the line `// roleFor names a built-in role that grants the given action. The names come`, add:

```go
// issuesCertificate reports whether a request issues or renews a
// certificate. Both sign with a key, so they need keys/sign as well as
// certificates/create (B77).
func issuesCertificate(method, path string) bool {
	if method != http.MethodPost {
		return false
	}
	return strings.HasSuffix(path, "/certificates") || strings.HasSuffix(path, "/renew")
}

```

Append to `internal/vaultapi/errors_test.go`:

```go

// TestAPIError_CertificateIssueHintNamesKeySign pins that a 403 on issuing or
// renewing a certificate points at the second action it needs (B77).
func TestAPIError_CertificateIssueHintNamesKeySign(t *testing.T) {
	for _, path := range []string{"/api/v1/vaults/prod/certificates", "/api/v1/vaults/prod/certificates/tls/renew"} {
		err := doAgainstStatus(t, http.StatusForbidden, `{}`, http.MethodPost, path)
		var apiErr *APIError
		require.ErrorAs(t, err, &apiErr)
		require.Contains(t, apiErr.Hint, "Key Vault Certificates Officer")
		require.Contains(t, apiErr.Hint, "keys/sign/action")
	}

	err := doAgainstStatus(t, http.StatusForbidden, `{}`, http.MethodGet, "/api/v1/vaults/prod/certificates")
	var readAPI *APIError
	require.ErrorAs(t, err, &readAPI)
	require.NotContains(t, readAPI.Hint, "keys/sign")
}
```

The existing `TestUpsertCertificatePolicy_ForbiddenSurfacesTheCertificatesOfficerHint` (a `PUT`) is unaffected.

- [ ] **Step 7: Run the tests and confirm they pass**

Run: `go vet ./api/ ./cmd/certificates/ ./internal/vaultapi/ && go test ./api/ ./cmd/certificates/ ./internal/vaultapi/ ./internal/mcpserver/ -count=1`
Expected: every package `ok` (`internal/vaultapi` takes about a minute).

- [ ] **Step 8: Lint and commit**

Run: `BASE=$(cat .git/rv-cert-isolation-base); PATH="$HOME/go/pkg/mod/golang.org/toolchain@v0.0.1-go1.25.7.linux-amd64/bin:$PATH" GOTOOLCHAIN=local ~/go/bin/golangci-lint run --new-from-rev="$BASE" ./api/ ./cmd/certificates/ ./internal/vaultapi/`
Expected: `0 issues.`

Stage the files of this task, then invoke the `dev-workflow-skills:1-git-commit` skill via the Skill tool. The subject should say certificate create and renew require keys/sign over HTTP, MCP and the CLI (B77). No footer yet.

---

### Task 8: The scheduler re-checks the owner's keys/sign before renewing (B77)

**Files:**
- Modify: `internal/services/certificates/renewal_service.go:20-40` (config, struct, constructor; new type `KeySignAuthorizer`), the AutoRenew branch (after Task 1's nil-vault check)
- Modify: `internal/container/service_container.go:6-41` (imports `github.com/google/uuid` and `rocketvault/model`, neither imported today), `:742-746` (renewal config)
- Modify: `internal/services/certificates/renewal_service_test.go` (imports, helpers, two tests, `SignAuthorizer` on `TestCheckAndRenewCertificates_AutoRenew`)
- Modify: `internal/services/certificates/signing_key_lifecycle_test.go` (helper `allowSign` for package `certificates`)
- Modify: `internal/services/certificates/certificate_service_extended_test.go` (`TestCheckAndRenewCertificates_AutoRenewFailureSkipped`), `ca_renewal_scheduler_test.go`, `versioning_integration_test.go:178-182`
- Modify: `.claude/known-bugs.md` (new § B77)

**Interfaces:**
- Consumes: `authorization.RequireDataPlaneAccess` (Task 4); the container's `c.accessPolicyService` and `c.roleAssignmentService`, both built before the renewal service (`service_container.go:538`, `:551`).
- Produces: `type KeySignAuthorizer func(ctx context.Context, principalID, vaultID uuid.UUID) error` and field `RenewalServiceConfig.SignAuthorizer` in package `certificates`. A nil authorizer refuses every renewal. `CertificateRenewalService`'s interface is unchanged, so no mock needs regenerating.

- [ ] **Step 1: Write the failing tests**

In `internal/services/certificates/renewal_service_test.go`, add `"errors"` to the stdlib imports, add `SignAuthorizer:     allowSign,` after `Logger:             newTestLogger(),` in the `RenewalServiceConfig` literal of `TestCheckAndRenewCertificates_AutoRenew` only, and append:

```go

// allowSign is a KeySignAuthorizer that grants every request.
func allowSign(context.Context, uuid.UUID, uuid.UUID) error { return nil }

// dueAutoRenewCert returns a certificate inside its renewal window with
// auto-renew on, in vaultID, owned by userID.
func dueAutoRenewCert(userID, vaultID uuid.UUID) model.Certificate {
	expires := time.Now().Add(10 * 24 * time.Hour)
	return model.Certificate{
		ID: uuid.New(), UserID: userID, VaultID: vaultID, Name: "due",
		CreatedAt: time.Now().Add(-365 * 24 * time.Hour), ExpiresAt: &expires,
		AutoRenew: true, RenewalDays: 30,
	}
}

// TestCheckAndRenewCertificates_RefusesWhenOwnerCannotSign is the scheduler
// half of B77: an owner who lost keys/sign in the vault gets no more
// unattended re-signing.
func TestCheckAndRenewCertificates_RefusesWhenOwnerCannotSign(t *testing.T) {
	userID, vaultID := uuid.New(), uuid.New()
	repo := &mockCertRepoForRenewal{}
	repo.On("ListAll", mock.Anything).Return([]model.Certificate{dueAutoRenewCert(userID, vaultID)}, nil)
	certSvc := &mockCertSvcForRenewal{}

	var gotPrincipal, gotVault uuid.UUID
	svc := certificates.NewCertificateRenewalService(certificates.RenewalServiceConfig{
		CertRepository:     repo,
		CertificateService: certSvc,
		Logger:             newTestLogger(),
		SignAuthorizer: func(_ context.Context, principalID, vaultID uuid.UUID) error {
			gotPrincipal, gotVault = principalID, vaultID
			return errors.New("forbidden: no role grants keys/sign in this vault")
		},
	})

	renewed, warned, err := svc.CheckAndRenewCertificates(context.Background())
	require.NoError(t, err)
	assert.Equal(t, 0, renewed)
	assert.Equal(t, 0, warned)
	assert.Equal(t, userID, gotPrincipal)
	assert.Equal(t, vaultID, gotVault)
	certSvc.AssertNotCalled(t, "RenewCertificate", mock.Anything, mock.Anything, mock.Anything, mock.Anything)
}

// TestCheckAndRenewCertificates_RefusesWithoutSignAuthorizer pins the
// fail-closed default: a scheduler wired without the check renews nothing.
func TestCheckAndRenewCertificates_RefusesWithoutSignAuthorizer(t *testing.T) {
	repo := &mockCertRepoForRenewal{}
	repo.On("ListAll", mock.Anything).Return([]model.Certificate{dueAutoRenewCert(uuid.New(), uuid.New())}, nil)
	certSvc := &mockCertSvcForRenewal{}

	svc := certificates.NewCertificateRenewalService(certificates.RenewalServiceConfig{
		CertRepository:     repo,
		CertificateService: certSvc,
		Logger:             newTestLogger(),
	})

	renewed, _, err := svc.CheckAndRenewCertificates(context.Background())
	require.NoError(t, err)
	assert.Equal(t, 0, renewed)
	certSvc.AssertNotCalled(t, "RenewCertificate", mock.Anything, mock.Anything, mock.Anything, mock.Anything)
}
```

In `internal/services/certificates/signing_key_lifecycle_test.go` (package `certificates`; `renewal_service_test.go` is package `certificates_test`, so the two helpers do not collide), append:

```go

// allowSign is a KeySignAuthorizer that grants every request.
func allowSign(context.Context, uuid.UUID, uuid.UUID) error { return nil }
```

Add `SignAuthorizer:     allowSign,` after the `Logger: ...` line of the `RenewalServiceConfig` literal in `TestCheckAndRenewCertificates_AutoRenewFailureSkipped` (`certificate_service_extended_test.go`), `TestCheckAndRenewCertificates_CASignedKeepsIssuer` (`ca_renewal_scheduler_test.go`) and `TestCheckAndRenewCertificates_CreatesVersionWithPreservedValidity` (`versioning_integration_test.go:178-182`).

- [ ] **Step 2: Run the tests and confirm they fail**

Run: `go test ./internal/services/certificates/ -run TestCheckAndRenewCertificates -count=1`
Expected: FAIL at build time: `unknown field SignAuthorizer in struct literal of type certificates.RenewalServiceConfig`.

- [ ] **Step 3: Implement**

In `internal/services/certificates/renewal_service.go`, replace

```go
// RenewalServiceConfig holds dependencies for the renewal service.
type RenewalServiceConfig struct {
	CertRepository     repositories.CertificateRepositoryInterface
	CertificateService CertificateService
	Logger             *logging.Logger
}

type certRenewalService struct {
	certRepo repositories.CertificateRepositoryInterface
	certSvc  CertificateService
	logger   *logging.Logger
}

// NewCertificateRenewalService constructs the renewal service with the given configuration.
func NewCertificateRenewalService(cfg RenewalServiceConfig) CertificateRenewalService {
	return &certRenewalService{
		certRepo: cfg.CertRepository,
		certSvc:  cfg.CertificateService,
		logger:   cfg.Logger,
	}
}
```

with

```go
// KeySignAuthorizer returns nil when principalID may sign with keys in
// vaultID, and an error otherwise.
type KeySignAuthorizer func(ctx context.Context, principalID, vaultID uuid.UUID) error

// RenewalServiceConfig holds dependencies for the renewal service.
type RenewalServiceConfig struct {
	CertRepository     repositories.CertificateRepositoryInterface
	CertificateService CertificateService
	Logger             *logging.Logger
	// SignAuthorizer re-checks, before every unattended renewal, that the
	// certificate's owner may still sign with keys in its vault (B77). Nil
	// refuses every renewal rather than skipping the check.
	SignAuthorizer KeySignAuthorizer
}

type certRenewalService struct {
	certRepo  repositories.CertificateRepositoryInterface
	certSvc   CertificateService
	logger    *logging.Logger
	signAuthz KeySignAuthorizer
}

// NewCertificateRenewalService constructs the renewal service with the given configuration.
func NewCertificateRenewalService(cfg RenewalServiceConfig) CertificateRenewalService {
	return &certRenewalService{
		certRepo:  cfg.CertRepository,
		certSvc:   cfg.CertificateService,
		logger:    cfg.Logger,
		signAuthz: cfg.SignAuthorizer,
	}
}
```

In `CheckAndRenewCertificates`, replace

```go
			// Preserve the current version's validity period when renewing.
			validityDays := CurrentValidityDays(&cert)
```

with

```go
			// Renewal re-signs with the certificate's key on its owner's
			// behalf, so the owner must still hold keys/sign in the vault
			// (B77). A scheduler wired without the check renews nothing.
			if s.signAuthz == nil {
				s.logger.LogAuditError(cert.UserID.String(), "cert_auto_renew", "failed",
					"Auto-renewal refused, no sign authorizer is configured: "+cert.Name, nil)
				continue
			}
			if authzErr := s.signAuthz(ctx, cert.UserID, cert.VaultID); authzErr != nil {
				s.logger.LogAuditError(cert.UserID.String(), "cert_auto_renew", "denied",
					"Auto-renewal refused, owner may not sign with keys in this vault: "+cert.Name, authzErr)
				continue
			}

			// Preserve the current version's validity period when renewing.
			validityDays := CurrentValidityDays(&cert)
```

In `internal/container/service_container.go`, add `"github.com/google/uuid"` to the third-party import group (before `"github.com/spf13/viper"`) and `"rocketvault/model"` after `"rocketvault/internal/vaultcache"`. Then replace

```go
	c.certRenewalService = certServices.NewCertificateRenewalService(certServices.RenewalServiceConfig{
		CertRepository:     c.certificateRepository,
		CertificateService: c.certificateService,
		Logger:             c.logger,
	})
```

with

```go
	c.certRenewalService = certServices.NewCertificateRenewalService(certServices.RenewalServiceConfig{
		CertRepository:     c.certificateRepository,
		CertificateService: c.certificateService,
		Logger:             c.logger,
		// The same two-stage check the CLI and HTTP handlers run for
		// keys/sign, applied to the certificate's owner (B77).
		SignAuthorizer: func(ctx context.Context, principalID, vaultID uuid.UUID) error {
			return authzServices.RequireDataPlaneAccess(ctx, c.accessPolicyService, c.roleAssignmentService,
				principalID, vaultID, model.PolicyResourceKeys, model.OpSign, model.ActionKeysSign)
		},
	})
```

- [ ] **Step 4: Run the tests and confirm they pass**

Run: `go build ./... && go vet ./internal/services/certificates/ ./internal/container/ && go test ./internal/services/certificates/ ./internal/container/ -count=1`
Expected: both packages `ok`.

- [ ] **Step 5: Add the known-bugs entry**

In `.claude/known-bugs.md`, insert immediately before the line `## Deferred Refactors`:

```markdown
### B77 — Certificate create and renew ignored key lifecycle and did not require the sign action

**Status**: Fixed 2026-10-XX (GitHub issue #43)
**Severity**: Medium — a revoked, disabled or expired key kept issuing and
renewing certificates, and `certificates/create` alone was enough to sign
with a key
**Files**: `internal/services/certificates/certificate_service.go`,
`internal/services/certificates/renewal_service.go`,
`internal/services/authorization/data_action_authz.go`,
`cmd/vaultcli/session.go`, `cmd/vaultcli/vault.go`, `api/certificates.go`,
`api/certificates_versions.go`, `cmd/certificates/create.go`,
`cmd/certificates/renew.go`, `internal/container/service_container.go`,
`internal/vaultapi/errors.go`

**Symptom**: `ValidateKeyOwnership` and `RenewCertificate`'s inline key read
never looked at `Revoked`, `Enabled` or the validity window, so a key the
crypto path refused (`loadAndAuthorize`) still minted and renewed
certificates. Issuing or renewing needed only `certificates/create` and
ownership of the key, over HTTP (create and the renew route, which the MCP
tools use) and the CLI; `keys/sign` was never required and a deny policy on
key sign was never consulted. The scheduler kept re-signing unattended,
under an admin scope (B76), for owners who had since lost access. A
certificate row stores a copy of its key's private PEM, used as the CA
signing key when that certificate is a CA, so revoking the key did not stop
the CA either.

**Root cause**: authorization for issuance lived only in the route's single
data action, and lifecycle lived only in the key crypto service.

**What was fixed**:

- `ValidateKeyOwnership` (both create paths) and `RenewCertificate` refuse a
  revoked or inaccessible key with `ErrSigningKeyUnusable`, after the B32
  owner comparison.
- `requireCAKeyUsable` refuses to sign through a CA whose linked key is
  unusable or unreadable in scope, or which records no key at all, on create
  and on renew.
- `authorization.RequireDataPlaneAccess` is the one two-stage check (deny
  policy, then role grant). `createCertificate` and `renewCertificate` call
  it for `(keys, sign, keys/sign/action)` through `requireKeySign`; the CLI
  `certificate create` and `certificate renew` call it through
  `vaultcli.Session.RequireAlso`; `vaultcli.RequireDataAction` delegates to
  it; the scheduler calls it for the certificate's owner through
  `RenewalServiceConfig.SignAuthorizer` and refuses everything when that is
  unset.

**Decision — what revoking a key does to certificates that embed it**: the
key can no longer issue or renew anything, as a leaf key or through a CA
row's embedded copy. Certificates already issued are left alone: not
revoked, disabled or deleted, since a key operation cascading into other
objects would be destructive and Azure does not do it either; X.509
revocation is its own concern. The embedded copy is not erased, and an
already exportable certificate still exports under its own gates. A CA row
with no key link is refused as a signer: every CA that passes
`inspectCertificateCA` was issued after `key_id` existed (B43 came later),
so such a row can only be one whose link was dropped at restore (B76).

**Accepted behavior change**: Key Vault Certificates Officer alone no longer
issues or renews certificates; the caller also needs a role granting
`keys/sign`, such as Key Vault Crypto User. Because issuance already
required owning the key (B32), and Certificates Officer cannot create keys,
this mostly affects principals who own keys but lost their key role, which
is the case this entry is about. Auto-renewal likewise stops for owners
without `keys/sign`.

**Pinned by**: `TestValidateKeyOwnership_RefusesUnusableKey`,
`TestCreateSelfSignedCertificate_RefusesRevokedKey`,
`TestRenewCertificate_RefusesDisabledKey`, `TestRequireCAKeyUsable`,
`TestCreateCASignedCertificate_RefusesCAWithRevokedKey`
(`internal/services/certificates/signing_key_lifecycle_test.go`);
`TestRenewCertificate_RevokedCAKeyRefusesRenewal` (`ca_renewal_test.go`);
`TestRequireDataPlaneAccess_*`
(`internal/services/authorization/data_plane_access_test.go`);
`TestCreateCertificate_RequiresKeySign`,
`TestCreateCertificate_KeySignDenyPolicyRefuses`,
`TestRenewCertificate_RequiresKeySign` (`api/certificates_key_sign_test.go`);
`TestCertCreateCmd_RequiresKeySign`, `TestCertRenewCmd_RequiresKeySign`
(`cmd/certificates/key_sign_test.go`);
`TestCheckAndRenewCertificates_RefusesWhenOwnerCannotSign`,
`TestCheckAndRenewCertificates_RefusesWithoutSignAuthorizer`
(`renewal_service_test.go`);
`TestAPIError_CertificateIssueHintNamesKeySign`
(`internal/vaultapi/errors_test.go`).

---
```

Replace `2026-10-XX` with the commit date.

- [ ] **Step 6: Lint and commit**

Run: `BASE=$(cat .git/rv-cert-isolation-base); PATH="$HOME/go/pkg/mod/golang.org/toolchain@v0.0.1-go1.25.7.linux-amd64/bin:$PATH" GOTOOLCHAIN=local ~/go/bin/golangci-lint run --new-from-rev="$BASE" ./internal/services/certificates/ ./internal/container/`
Expected: `0 issues.`

Stage the files of this task, then invoke the `dev-workflow-skills:1-git-commit` skill via the Skill tool. The subject should say the renewal scheduler re-checks the owner's keys/sign before renewing (B77). Footer: `Fixes #43`.

---

### Task 9: Signing-key and CA refusals map to 403/404/409 instead of 500 (B78)

**Files:**
- Modify: `internal/services/certificates/certificate_service.go` (four sentinels after `ErrSigningKeyUnusable`; `ValidateCertificateAccess` returns at `:1255`, `:1260`; `ValidateKeyOwnership` returns at `:1298`, `:1303`)
- Modify: `api/errors_certificate.go:35-39` (`writeCertificateError`, additive arms before `default:`), `:59-63` (`writeCertificateRenewError`, additive arms before the final fallthrough)
- Test: `internal/services/certificates/signing_key_lifecycle_test.go`; create `api/certificates_error_mapping_test.go`

**Interfaces:**
- Consumes: `ErrSigningKeyUnusable` (Task 5); `postCreateCertificate` (Task 7); `runCertVersionHandler`, `certLegacyVaultScope` (existing, `api/certificates_versions_test.go:24`, `api/certificates_test.go:336`).
- Produces in package `certificates`: `ErrSigningKeyForbidden` (text `forbidden: cannot use other users' keys`), `ErrSigningKeyNotFound` (text `key not found`), `ErrCACertForbidden` (text `forbidden: cannot access other users' certificates`), `ErrCACertNotFound` (text `certificate not found`). Every message callers see is unchanged; only identity is added. `ErrCACertNotFound` is deliberately distinct from `ErrCertNotFound`, so a missing CA is never reported as the certificate being acted on.
- What is already done and stays: `createCertificate` routes service errors through `writeCertificateError` (B86, `api/certificates.go:236-243`); the renew route has `ErrRenewKeyForbidden`/`ErrRenewKeyNotFound`/`ErrRenewNotPossible` arms (`api/errors_certificate.go:51-62`).

- [ ] **Step 1: Write the failing tests**

Append to `internal/services/certificates/signing_key_lifecycle_test.go`:

```go

// TestValidators_ReturnSentinels lets the HTTP layer map these refusals by
// identity instead of reporting them as server faults (B78). Each message is
// unchanged.
func TestValidators_ReturnSentinels(t *testing.T) {
	t.Parallel()

	ownerID, callerID, vaultID := uuid.New(), uuid.New(), uuid.New()
	scope := model.NewVaultScope(vaultID, callerID)

	keyID := uuid.New()
	keyRepo := &mockKeyRepo{}
	vaultScopedKeyRepo(keyRepo, keyID, vaultID, &model.Key{ID: keyID, UserID: ownerID, VaultID: vaultID, Enabled: true})
	svc := newCertSvc(&mockCertRepository{}, keyRepo)
	err := svc.ValidateKeyOwnership(context.Background(), keyID, scope)
	require.ErrorIs(t, err, ErrSigningKeyForbidden)
	require.Equal(t, "forbidden: cannot use other users' keys", err.Error())

	missing := uuid.New()
	missingRepo := &mockKeyRepo{}
	missingRepo.On("Read", mock.Anything, missing, scope).Return(nil, errors.New("key not found or access denied"))
	svc = newCertSvc(&mockCertRepository{}, missingRepo)
	err = svc.ValidateKeyOwnership(context.Background(), missing, scope)
	require.ErrorIs(t, err, ErrSigningKeyNotFound)
	require.Equal(t, "key not found: key not found or access denied", err.Error())

	caID := uuid.New()
	certRepo := &mockCertRepository{}
	certRepo.On("Read", mock.Anything, caID, scope).Return(&model.Certificate{ID: caID, UserID: ownerID, VaultID: vaultID}, nil)
	svc = newCertSvc(certRepo, &mockKeyRepo{})
	err = svc.ValidateCertificateAccess(context.Background(), caID, scope)
	require.ErrorIs(t, err, ErrCACertForbidden)
	require.Equal(t, "forbidden: cannot access other users' certificates", err.Error())

	missingCA := uuid.New()
	certRepo = &mockCertRepository{}
	certRepo.On("Read", mock.Anything, missingCA, scope).Return(nil, errors.New("certificate not found or access denied"))
	svc = newCertSvc(certRepo, &mockKeyRepo{})
	err = svc.ValidateCertificateAccess(context.Background(), missingCA, scope)
	require.ErrorIs(t, err, ErrCACertNotFound)
	require.NotErrorIs(t, err, ErrCertNotFound, "a missing CA is not the certificate being acted on")
}
```

Create `api/certificates_error_mapping_test.go`:

```go
package api

import (
	"errors"
	"fmt"
	"net/http"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	certServices "rocketvault/internal/services/certificates"
)

// TestCreateCertificate_MapsSigningKeyErrors pins B78: a refusal about the
// caller's key or CA is a client problem, not a 500, and the response never
// echoes the wrapped repository text.
func TestCreateCertificate_MapsSigningKeyErrors(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want int
	}{
		{"foreign key", certServices.ErrSigningKeyForbidden, http.StatusForbidden},
		{"foreign CA", fmt.Errorf("cannot access CA certificate: %w", certServices.ErrCACertForbidden), http.StatusForbidden},
		{"unusable key", fmt.Errorf("%w: %s", certServices.ErrSigningKeyUnusable, uuid.New()), http.StatusForbidden},
		{"missing key", fmt.Errorf("%w: %w", certServices.ErrSigningKeyNotFound, errors.New("sql: no rows wrapped")), http.StatusNotFound},
		{"missing CA", fmt.Errorf("cannot access CA certificate: %w", fmt.Errorf("%w: %w", certServices.ErrCACertNotFound, errors.New("sql: no rows wrapped"))), http.StatusNotFound},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			svc := &mockCertService{}
			svc.On("CreateSelfSignedCertificate", mock.Anything, mock.Anything).Return(nil, tc.err)

			w := postCreateCertificate(newCertCtx(svc, certAdminClaims()))
			assert.Equal(t, tc.want, w.Code)
			assert.NotContains(t, w.Body.String(), "sql:")
		})
	}
}

// TestRenewCertificate_MapsUnusableSigningMaterialTo409 pins the renew-route
// mapping: an unusable key or a missing signing CA is a state the caller
// fixes, reported like the route's other renewal refusals.
func TestRenewCertificate_MapsUnusableSigningMaterialTo409(t *testing.T) {
	certID := uuid.New()
	scope := certLegacyVaultScope()
	for name, err := range map[string]error{
		"unusable key": fmt.Errorf("%w: %s", certServices.ErrSigningKeyUnusable, uuid.New()),
		"missing CA":   fmt.Errorf("cannot renew CA-signed certificate: %w", fmt.Errorf("%w: %w", certServices.ErrCACertNotFound, errors.New("sql: no rows wrapped"))),
	} {
		t.Run(name, func(t *testing.T) {
			m := &mockCertService{}
			m.On("RenewCertificate", mock.Anything, certID, scope, 90).Return(nil, err)
			w := runCertVersionHandler(t, m, &ApiParams{CertificateID: certID.String()},
				http.MethodPost, `{"validity_days":90}`, renewCertificate)
			assert.Equal(t, http.StatusConflict, w.Code)
			assert.NotContains(t, w.Body.String(), "sql:")
		})
	}
}
```

- [ ] **Step 2: Run the tests and confirm they fail**

Run: `go test ./internal/services/certificates/ ./api/ -run 'ReturnSentinels|MapsSigningKeyErrors|MapsUnusableSigningMaterial' -count=1`
Expected: FAIL at build time: `undefined: ErrSigningKeyForbidden`, `undefined: certServices.ErrCACertNotFound` and similar.

- [ ] **Step 3: Implement**

In `certificate_service.go`, after the `ErrSigningKeyUnusable` declaration (Task 5), add:

```go

// ErrSigningKeyForbidden is returned when the signing key named at creation
// belongs to another user. Its text is the message this refusal always had.
var ErrSigningKeyForbidden = errors.New("forbidden: cannot use other users' keys")

// ErrSigningKeyNotFound is returned when the signing key named at creation
// does not resolve in the caller's vault scope.
var ErrSigningKeyNotFound = errors.New("key not found")

// ErrCACertForbidden is returned when the signing CA certificate belongs to
// another user. Its text is the message this refusal always had.
var ErrCACertForbidden = errors.New("forbidden: cannot access other users' certificates")

// ErrCACertNotFound is returned when the signing CA certificate does not
// resolve in the caller's vault scope.
var ErrCACertNotFound = errors.New("certificate not found")
```

In `ValidateCertificateAccess`, replace `return fmt.Errorf("certificate not found: %w", err)` with `return fmt.Errorf("%w: %w", ErrCACertNotFound, err)`, and `return fmt.Errorf("forbidden: cannot access other users' certificates")` with `return ErrCACertForbidden`.

In `ValidateKeyOwnership`, replace `return fmt.Errorf("key not found: %w", err)` with `return fmt.Errorf("%w: %w", ErrSigningKeyNotFound, err)`, and `return fmt.Errorf("forbidden: cannot use other users' keys")` with `return ErrSigningKeyForbidden`.

`RenewCertificate` is not touched here: its key refusals already carry `ErrRenewKeyForbidden`/`ErrRenewKeyNotFound`, and its CA refusals come through `ValidateCertificateAccess` and now carry the CA sentinels.

In `api/errors_certificate.go`, `writeCertificateError`, insert these arms between the existing `ErrNameTaken` arm and `default:`. Do not touch any existing arm:

```go
	// B78: refusals about the caller's signing key or CA are client problems.
	// Each uses a fixed message, so no wrapped repository text reaches the
	// response.
	case errors.Is(err, certServices.ErrSigningKeyForbidden):
		c.SetPermissionError("the signing key belongs to another user")
	case errors.Is(err, certServices.ErrCACertForbidden):
		c.SetPermissionError("the CA certificate belongs to another user")
	case errors.Is(err, certServices.ErrSigningKeyUnusable):
		c.SetPermissionError("signing key is revoked, disabled or outside its valid time window")
	case errors.Is(err, certServices.ErrSigningKeyNotFound):
		c.SetNotFound("key")
	case errors.Is(err, certServices.ErrCACertNotFound):
		c.SetNotFound("CA certificate")
```

The result, for review, is the existing eight arms (`ErrCertLifecycleDenied`, `ErrCertNotFound`, `ErrCertPurgeProtected`, `ErrGlobalPurgeProtectionEnabled`, `ErrCertificateVersionNotFound`, `ErrInvalidCertificateVersionAttributes`, `ErrCertificateVersionConflict`, `ErrNameTaken`, then these five), then `default:`.

In `writeCertificateRenewError`, replace

```go
	if errors.Is(err, certServices.ErrRenewNotPossible) {
		c.SetConflict("the certificate cannot be renewed in its current state")
		return
	}
	writeCertificateError(c, err)
```

with

```go
	if errors.Is(err, certServices.ErrRenewNotPossible) {
		c.SetConflict("the certificate cannot be renewed in its current state")
		return
	}
	// A key or signing CA that has become unusable is a state the caller can
	// fix, like the arms above, so renewal reports it as 409 (B77, B78).
	if errors.Is(err, certServices.ErrSigningKeyUnusable) {
		c.SetConflict("the certificate's signing key, or its CA's key, is revoked, disabled or outside its valid time window")
		return
	}
	if errors.Is(err, certServices.ErrCACertNotFound) {
		c.SetConflict("the certificate's signing CA is not available, so it cannot be renewed")
		return
	}
	writeCertificateError(c, err)
```

(Decision D4. For 403 on both routes instead, drop the `ErrSigningKeyUnusable` arm here and change that case of `TestRenewCertificate_MapsUnusableSigningMaterialTo409` to expect 403.)

- [ ] **Step 4: Run the tests and confirm they pass**

Run: `go vet ./internal/services/certificates/ ./api/ && go test ./internal/services/certificates/ ./api/ ./cmd/certificates/ -count=1`
Expected: every package `ok`. The existing `TestCreateCertificate_ServiceError_Returns500` still sees 500 (its plain error wraps no sentinel); `TestRenewCertificate_RoutineRefusals`, `TestRenewCertificate_Statuses`, `TestUpdateCertificateVersion_Statuses` and `TestWriteErrors_NameTaken_Returns409WithoutDriverText` are unchanged and pass.

- [ ] **Step 5: Lint and commit**

Run: `BASE=$(cat .git/rv-cert-isolation-base); PATH="$HOME/go/pkg/mod/golang.org/toolchain@v0.0.1-go1.25.7.linux-amd64/bin:$PATH" GOTOOLCHAIN=local ~/go/bin/golangci-lint run --new-from-rev="$BASE" ./internal/services/certificates/ ./api/`
Expected: `0 issues.`

Stage the files of this task, then invoke the `dev-workflow-skills:1-git-commit` skill via the Skill tool. The subject should say certificate signing-key and CA refusals map to client errors instead of 500 (B78). No footer yet.

---

### Task 10: Cap validity_days on create and renew (B78)

**Files:**
- Modify: `model/certificate.go` (constant after the `Certificate` struct, which ends at line 44)
- Modify: `internal/validation/certificate_validation.go` (whole file, 29 lines)
- Modify: `api/certificates.go:173-176` (`ValidateCertificateCreate` call)
- Modify: `api/certificates_versions.go:3-13` (imports), `:159-162` (renew body bound)
- Modify: `internal/services/certificates/certificate_service.go` (sentinel after `ErrCACertNotFound`; guards after the three `validity days must be positive` blocks, `:299-302`, `:445-448`, `:984-987` at HEAD)
- Modify: `internal/services/certificates/renewal_service.go:99-113` (`CurrentValidityDays` clamp)
- Modify: `api/errors_certificate.go` (one more arm)
- Modify: `cmd/certificates/create.go:39-43`, `cmd/certificates/renew.go:39-43` (help text)
- Test: `internal/validation/validation_test.go`, `internal/services/certificates/signing_key_lifecycle_test.go`, `api/certificates_error_mapping_test.go`
- Modify: `.claude/known-bugs.md` (new § B78)

**Interfaces:**
- Produces: `model.MaxCertificateValidityDays = 36500`; field `ValidityDays int` on `validation.CertificateCreateRequest`; `certificates.ErrInvalidValidityDays`. `CurrentValidityDays` never returns more than the cap (Decision D5), so the scheduler and the renew route's default period stay inside it. The MCP `create_certificate`/`renew_certificate` tools and `internal/vaultapi` need no change: the server enforces the bound.

- [ ] **Step 1: Write the failing tests**

Append to `internal/validation/validation_test.go` (it already imports `model` and `assert`):

```go

// TestValidateCertificateCreate_ValidityDaysUpperBound pins B78. Without a
// cap, a huge value pushes NotAfter past X.509's four-digit year and the
// request fails deep inside certificate generation as a 500.
func TestValidateCertificateCreate_ValidityDaysUpperBound(t *testing.T) {
	t.Parallel()

	ok := ValidateCertificateCreate(CertificateCreateRequest{Name: "cert", ValidityDays: model.MaxCertificateValidityDays})
	assert.NoError(t, ok, "the maximum itself is allowed")

	tooLong := ValidateCertificateCreate(CertificateCreateRequest{Name: "cert", ValidityDays: model.MaxCertificateValidityDays + 1})
	assert.Error(t, tooLong)
}
```

Append to `internal/services/certificates/signing_key_lifecycle_test.go`:

```go

// TestValidityDaysUpperBound_ServiceSide covers the CLI, which calls the
// service directly and never sees the HTTP validation (B78).
func TestValidityDaysUpperBound_ServiceSide(t *testing.T) {
	t.Parallel()

	userID, vaultID, certID := uuid.New(), uuid.New(), uuid.New()
	svc := newCertSvc(&mockCertRepository{}, &mockKeyRepo{})
	_, err := svc.CreateSelfSignedCertificate(context.Background(), CreateCertificateRequest{
		Name: "c", KeyID: uuid.New(), ValidityDays: model.MaxCertificateValidityDays + 1, UserID: userID, VaultID: vaultID,
	})
	require.ErrorIs(t, err, ErrInvalidValidityDays)

	caID := uuid.New()
	_, err = svc.CreateCASignedCertificate(context.Background(), CreateCertificateRequest{
		Name: "c", KeyID: uuid.New(), ValidityDays: model.MaxCertificateValidityDays + 1, UserID: userID, VaultID: vaultID, CACertID: &caID,
	})
	require.ErrorIs(t, err, ErrInvalidValidityDays)

	scope := model.NewVaultScope(vaultID, userID)
	certRepo := &mockCertRepository{}
	certRepo.On("Read", mock.Anything, certID, scope).Return(&model.Certificate{
		ID: certID, UserID: userID, VaultID: vaultID, KeyID: uuid.New(), Name: "c", Enabled: true,
	}, nil)
	svc = newCertSvc(certRepo, &mockKeyRepo{})
	_, err = svc.RenewCertificate(context.Background(), certID, scope, model.MaxCertificateValidityDays+1)
	require.ErrorIs(t, err, ErrInvalidValidityDays)
}

// TestCurrentValidityDays_ClampedToMaximum keeps auto-renewal working for a
// certificate issued with a longer period before the cap existed (B78).
func TestCurrentValidityDays_ClampedToMaximum(t *testing.T) {
	t.Parallel()

	created := time.Now().Add(-24 * time.Hour)
	expires := created.AddDate(0, 0, model.MaxCertificateValidityDays+500)
	require.Equal(t, model.MaxCertificateValidityDays,
		CurrentValidityDays(&model.Certificate{CreatedAt: created, ExpiresAt: &expires}))
}
```

In `api/certificates_error_mapping_test.go`, replace the import block with:

```go
import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	certServices "rocketvault/internal/services/certificates"
	"rocketvault/model"
)
```

and append:

```go

func TestCreateCertificate_ValidityAboveMaximum_Returns400(t *testing.T) {
	svc := &mockCertService{}
	c := newCertCtx(svc, certAdminClaims())
	w := httptest.NewRecorder()
	body, _ := json.Marshal(map[string]any{
		"name": "mycert", "key_id": uuid.New().String(), "validity_days": model.MaxCertificateValidityDays + 1,
	})
	r := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/certificates", bytes.NewReader(body))

	createCertificate(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusBadRequest, w.Code)
	svc.AssertNotCalled(t, "CreateSelfSignedCertificate", mock.Anything, mock.Anything)
}

func TestRenewCertificate_ValidityAboveMaximum_Returns400(t *testing.T) {
	svc := &mockCertService{}
	body := fmt.Sprintf(`{"validity_days":%d}`, model.MaxCertificateValidityDays+1)
	w := runCertVersionHandler(t, svc, &ApiParams{CertificateID: uuid.New().String()},
		http.MethodPost, body, renewCertificate)
	assert.Equal(t, http.StatusBadRequest, w.Code)
	svc.AssertNotCalled(t, "RenewCertificate", mock.Anything, mock.Anything, mock.Anything, mock.Anything)
}

// TestWriteCertificateError_InvalidValidityDaysIs400 covers the service-side
// sentinel, which the CLI path and any future caller reach.
func TestWriteCertificateError_InvalidValidityDaysIs400(t *testing.T) {
	c := newCertCtx(&mockCertService{}, certAdminClaims())
	writeCertificateError(c, fmt.Errorf("%w: must not exceed %d", certServices.ErrInvalidValidityDays, model.MaxCertificateValidityDays))
	w := httptest.NewRecorder()
	writeError(w, c)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}
```

- [ ] **Step 2: Run the tests and confirm they fail**

Run: `go test ./internal/validation/ ./internal/services/certificates/ ./api/ -run 'ValidityDaysUpperBound|ValidityAboveMaximum|ClampedToMaximum|InvalidValidityDaysIs400' -count=1`
Expected: FAIL at build time: `undefined: model.MaxCertificateValidityDays`, `unknown field ValidityDays`, `undefined: ErrInvalidValidityDays`.

- [ ] **Step 3: Implement**

In `model/certificate.go`, after the closing brace of the `Certificate` struct (line 44), add:

```go

// MaxCertificateValidityDays caps a certificate's validity period. It is 100
// years: longer than any real root CA, and short enough that NotAfter stays
// far inside X.509's four-digit-year GeneralizedTime range (B78).
const MaxCertificateValidityDays = 36500
```

Replace the whole of `internal/validation/certificate_validation.go` with:

```go
package validation

import (
	validation "github.com/go-ozzo/ozzo-validation/v4"

	"rocketvault/model"
)

// CertificateCreateRequest is the input for creating a certificate.
type CertificateCreateRequest struct {
	Name         string
	Tags         []string
	ValidityDays int
}

// ValidateCertificateCreate validates certificate creation input. A
// non-positive ValidityDays is rejected by the caller before this runs;
// validation.Max skips the zero value, so it only enforces the cap (B78).
func ValidateCertificateCreate(req CertificateCreateRequest) error {
	return validation.ValidateStruct(&req,
		validation.Field(&req.Name,
			validation.Required,
			validation.Length(1, 127),
			CertificateNameRule(),
		),
		validation.Field(&req.Tags,
			validation.Length(0, 15),
			validation.Each(validation.Length(1, 256)),
		),
		validation.Field(&req.ValidityDays,
			validation.Max(model.MaxCertificateValidityDays),
		),
	)
}

// CertificateNameRule validates certificate names.
func CertificateNameRule() validation.Rule {
	return validation.Match(CertificateNamePattern).Error("must contain only alphanumeric characters and hyphens, and start with a letter")
}
```

(`internal/validation` already imports `rocketvault/model` from `key_validation.go` and `secret_validation.go`, so no import cycle is introduced.)

In `api/certificates.go`, replace

```go
	if err := vvalidation.ValidateCertificateCreate(vvalidation.CertificateCreateRequest{
		Name: req.Name,
		Tags: req.Tags,
	}); err != nil {
```

with

```go
	if err := vvalidation.ValidateCertificateCreate(vvalidation.CertificateCreateRequest{
		Name:         req.Name,
		Tags:         req.Tags,
		ValidityDays: req.ValidityDays,
	}); err != nil {
```

In `api/certificates_versions.go`, add `"fmt"` to the stdlib imports (between `"errors"` and `"io"`), and replace

```go
	if req.ValidityDays != nil && *req.ValidityDays <= 0 {
		c.SetInvalidParam("validity_days: must be positive")
		return
	}
```

with

```go
	if req.ValidityDays != nil && (*req.ValidityDays <= 0 || *req.ValidityDays > model.MaxCertificateValidityDays) {
		c.SetInvalidParam(fmt.Sprintf("validity_days: must be between 1 and %d", model.MaxCertificateValidityDays))
		return
	}
```

In `certificate_service.go`, after the `ErrCACertNotFound` declaration (Task 9), add:

```go

// ErrInvalidValidityDays is returned when a validity period exceeds
// model.MaxCertificateValidityDays (B78).
var ErrInvalidValidityDays = errors.New("invalid validity days")
```

In `CreateSelfSignedCertificate`, replace

```go
		s.logger.LogAuditError(req.UserID.String(), "create_self_signed_cert", "failed", "validity days must be positive", nil)
		return nil, fmt.Errorf("validity days must be positive")
	}
```

with

```go
		s.logger.LogAuditError(req.UserID.String(), "create_self_signed_cert", "failed", "validity days must be positive", nil)
		return nil, fmt.Errorf("validity days must be positive")
	}
	if req.ValidityDays > model.MaxCertificateValidityDays {
		s.logger.LogAuditError(req.UserID.String(), "create_self_signed_cert", "failed", "validity days exceed the maximum", nil)
		return nil, fmt.Errorf("%w: must not exceed %d", ErrInvalidValidityDays, model.MaxCertificateValidityDays)
	}
```

In `CreateCASignedCertificate`, replace

```go
		s.logger.LogAuditError(req.UserID.String(), "create_ca_signed_cert", "failed", "validity days must be positive", nil)
		return nil, fmt.Errorf("validity days must be positive")
	}
```

with

```go
		s.logger.LogAuditError(req.UserID.String(), "create_ca_signed_cert", "failed", "validity days must be positive", nil)
		return nil, fmt.Errorf("validity days must be positive")
	}
	if req.ValidityDays > model.MaxCertificateValidityDays {
		s.logger.LogAuditError(req.UserID.String(), "create_ca_signed_cert", "failed", "validity days exceed the maximum", nil)
		return nil, fmt.Errorf("%w: must not exceed %d", ErrInvalidValidityDays, model.MaxCertificateValidityDays)
	}
```

In `RenewCertificate`, replace

```go
		s.logger.LogAuditError(userID.String(), "renew_certificate", "failed", "validity days must be positive", nil)
		return nil, fmt.Errorf("validity days must be positive")
	}
```

with

```go
		s.logger.LogAuditError(userID.String(), "renew_certificate", "failed", "validity days must be positive", nil)
		return nil, fmt.Errorf("validity days must be positive")
	}
	if validityDays > model.MaxCertificateValidityDays {
		s.logger.LogAuditError(userID.String(), "renew_certificate", "failed", "validity days exceed the maximum", nil)
		return nil, fmt.Errorf("%w: must not exceed %d", ErrInvalidValidityDays, model.MaxCertificateValidityDays)
	}
```

In `internal/services/certificates/renewal_service.go`, replace the doc comment of `CurrentValidityDays`

```go
// CurrentValidityDays returns the validity period of cert's current version
// in whole days: expires_at minus created_at. It falls back to 365 when
// either is missing or the difference is not positive. The auto-renew
// scheduler and the renew route both use it, so a renewal without an
// explicit validity keeps the period the certificate already had.
```

with

```go
// CurrentValidityDays returns the validity period of cert's current version
// in whole days: expires_at minus created_at. It falls back to 365 when
// either is missing or the difference is not positive, and is clamped to
// model.MaxCertificateValidityDays, so a certificate issued before the cap
// still renews (B78). The auto-renew scheduler and the renew route both use
// it, so a renewal without an explicit validity keeps the period the
// certificate already had.
```

and replace its final `return days` with `return min(days, model.MaxCertificateValidityDays)`.

In `api/errors_certificate.go`, `writeCertificateError`, insert after the `ErrCACertNotFound` arm (Task 9), before `default:`:

```go
	case errors.Is(err, certServices.ErrInvalidValidityDays):
		c.SetInvalidParam("validity_days")
```

In `cmd/certificates/create.go`'s `Long`, replace

```
Acts on the vault named by --vault, defaulting to "default". --name and
--key-id are required and --validity-days must be positive. --auto-renew and
--renewal-days only arm the background renewal scheduler for later; they
change nothing about the certificate being issued now. --purge-protection is
sent only when the flag is passed explicitly.
```

with

```
Acts on the vault named by --vault, defaulting to "default". --name and
--key-id are required and --validity-days must be between 1 and 36500.
--auto-renew and --renewal-days only arm the background renewal scheduler
for later; they change nothing about the certificate being issued now.
--purge-protection is sent only when the flag is passed explicitly.
```

In `cmd/certificates/renew.go`'s `Long`, replace

```
--validity-days must be positive; when omitted, the current version's
validity period is kept. A certificate that is disabled, not yet valid
or already expired reads as inaccessible and cannot be renewed, so renew
before it lapses rather than after.`,
```

with

```
--validity-days must be between 1 and 36500; when omitted, the current
version's validity period is kept, capped at 36500. A certificate that is
disabled, not yet valid or already expired reads as inaccessible and cannot
be renewed, so renew before it lapses rather than after.`,
```

The CLI needs no flag check of its own: the service returns `ErrInvalidValidityDays`, which the commands report as `failed to create certificate: ...` / `failed to renew certificate: ...`.

- [ ] **Step 4: Run the tests and confirm they pass**

Run: `go build ./... && go vet ./internal/validation/ ./internal/services/certificates/ ./api/ ./cmd/certificates/ && go test ./internal/validation/ ./internal/services/certificates/ ./api/ ./cmd/certificates/ -count=1`
Expected: every package `ok` (the renew help test still checks the 78-byte line limit).

- [ ] **Step 5: File the GitHub issue and add the known-bugs entry**

```bash
gh issue create --label bug \
  --title "B78: Certificate signing-key and CA refusals answer 500, and validity_days has no upper bound" \
  --body "$(cat <<'EOF'
**Severity**: Low

**Files**: `internal/services/certificates/certificate_service.go` (`ValidateKeyOwnership`, `ValidateCertificateAccess`, create and renew validity checks), `api/errors_certificate.go`, `api/certificates.go`, `api/certificates_versions.go`, `internal/validation/certificate_validation.go`

**Symptom**: Creating a certificate over a key or CA owned by someone else, or over a key or CA missing from the vault, answered 500, because the validators returned plain string errors that `writeCertificateError` could only send to its `default:` arm. A missing signing CA on renew also answered 500. `validity_days` had only a lower bound on create and renew, over HTTP and the CLI; a very large value pushed NotAfter past X.509's four-digit year and failed inside certificate generation, again as a 500.

**Root cause**: the validators carried no sentinels to map by identity, and no layer capped the validity period.

Full detail: .claude/known-bugs.md § B78
EOF
)"
```

Note the printed issue number as `<M>`. In `.claude/known-bugs.md`, insert immediately before the line `## Deferred Refactors`:

```markdown
### B78 — Certificate signing-key and CA refusals answered 500, and `validity_days` had no upper bound

**Status**: Fixed 2026-10-XX (GitHub issue #<M>)
**Severity**: Low — wrong status codes and a server fault for bad input; no
access was granted
**Files**: `internal/services/certificates/certificate_service.go`,
`internal/services/certificates/renewal_service.go`,
`api/errors_certificate.go`, `api/certificates.go`,
`api/certificates_versions.go`,
`internal/validation/certificate_validation.go`, `model/certificate.go`,
`cmd/certificates/create.go`, `cmd/certificates/renew.go`

**Symptom**: B86 had already routed `createCertificate`'s errors through
`writeCertificateError`, but `ValidateKeyOwnership` and
`ValidateCertificateAccess` returned plain strings, so a key or CA owned by
someone else, or missing from the vault, still reached `default:` and
answered 500, on create and (for the CA) on renew. `validity_days` had a
lower bound only; a very large value pushed NotAfter past X.509's four-digit
year and failed inside certificate generation as a 500. The CLI, which calls
the service directly, had no bound at all.

**Root cause**: nothing to map by identity, and nothing capped the period.

**What was fixed**: `ErrSigningKeyForbidden`, `ErrSigningKeyNotFound`,
`ErrCACertForbidden` and `ErrCACertNotFound` carry the exact messages those
refusals always had. `writeCertificateError` maps them, and
`ErrSigningKeyUnusable` (B77), to 403 or 404 with fixed text;
`writeCertificateRenewError` maps an unusable key and a missing signing CA
to 409, like the renew route's other state refusals.
`model.MaxCertificateValidityDays` (36500) is enforced by
`ValidateCertificateCreate` and the renew body check for HTTP, and by the
three service entry points for the CLI, as `ErrInvalidValidityDays`, mapped
to 400. `CurrentValidityDays` clamps to the cap, so a certificate issued
before it keeps auto-renewing at the capped period.

**Pinned by**: `TestValidators_ReturnSentinels`,
`TestValidityDaysUpperBound_ServiceSide`,
`TestCurrentValidityDays_ClampedToMaximum`
(`internal/services/certificates/signing_key_lifecycle_test.go`);
`TestCreateCertificate_MapsSigningKeyErrors`,
`TestRenewCertificate_MapsUnusableSigningMaterialTo409`,
`TestCreateCertificate_ValidityAboveMaximum_Returns400`,
`TestRenewCertificate_ValidityAboveMaximum_Returns400`,
`TestWriteCertificateError_InvalidValidityDaysIs400`
(`api/certificates_error_mapping_test.go`);
`TestValidateCertificateCreate_ValidityDaysUpperBound`
(`internal/validation/validation_test.go`).

---
```

Replace `<M>` and `2026-10-XX`.

- [ ] **Step 6: Lint and commit**

Run: `BASE=$(cat .git/rv-cert-isolation-base); PATH="$HOME/go/pkg/mod/golang.org/toolchain@v0.0.1-go1.25.7.linux-amd64/bin:$PATH" GOTOOLCHAIN=local ~/go/bin/golangci-lint run --new-from-rev="$BASE" ./model/ ./internal/validation/ ./internal/services/certificates/ ./api/ ./cmd/certificates/`
Expected: `0 issues.`

Stage only this task's files, then invoke the `dev-workflow-skills:1-git-commit` skill via the Skill tool. The subject should say certificate validity is capped at 36500 days on create and renew (B78). Footer: `Fixes #<M>`.

---

### Task 11: Documentation

**Files:**
- Modify: `model/key.go:99-103`, `model/secret.go:102-107` (comments)
- Modify: `.claude/known-bugs.md` (§ B88 status note)
- Modify: `.claude/azure-keyvault-parity.md:227`, `:367`
- Modify: `CLAUDE.md` (Certificate Management, CLI Authorization, Documentation History)
- Modify: `docs/cli-guide.md:452`, `README.md:103`, `docs/mcp-server.md:142`, `docs/api-developer-guide.md:422-424`, `docs/admin-manual.html:1779`
- Modify: `docs/VAULT_USER_ACCESS_JOURNEYS_v3.md` (Journey Q, lines 1095-1220) and `journeybook/src/data/journeys-n-u.ts` (its Journey Q cases)
- Modify: `docs/superpowers/specs/2026-10-01-certificate-versioning-design.md` (§6), `docs/superpowers/specs/2026-10-01-certificate-and-key-export-design.md` (Backup and restore bullets)

Documentation only; no code behavior changes.

- [ ] **Step 1: Code comments that describe the blob as unencrypted**

In `model/key.go`, replace

```go
// future mistake. It IS marshaled into a key backup blob, which
// POST /keys/{key_id}/backup returns in its response body as a merely
// base64url-encoded (not encrypted) JSON envelope, so a backup blob must be
// handled as key material. Value itself still carries the same
// master-key-encrypted form the database stores.
```

with

```go
// future mistake. It IS marshaled into a key backup blob, which
// POST /keys/{key_id}/backup returns sealed under a master-key-derived key
// (B76). A blob must still be handled as key material: anyone holding the
// master key can open it. Value itself carries the same master-key-encrypted
// form the database stores.
```

In `model/secret.go`, replace

```go
// This type IS marshaled into a secret backup blob, which
// POST /secrets/{id}/backup returns in its response body as a merely
// base64url-encoded (not encrypted) JSON envelope. A secret backup blob
// therefore contains every historical value of that secret and must be
// handled as secret material — the same warning model.KeyVersionRecord
// carries for keys.
```

with

```go
// This type IS marshaled into a secret backup blob, which
// POST /secrets/{id}/backup returns sealed under a master-key-derived key
// (B76). A secret backup blob contains every historical value of that secret
// and must still be handled as secret material — the same warning
// model.KeyVersionRecord carries for keys.
```

Run: `go build ./model/ && gofmt -l model/`
Expected: no output.

- [ ] **Step 2: Known-bugs and parity**

In `.claude/known-bugs.md` § B88, after its `**Status**` paragraph, add:

```markdown
**Update (B76)**: item-backup blobs are sealed under a master-key-derived
key, so a restore now accepts only a blob this server produced, unmodified.
That closes the "crafted blob" half of this entry. Running
`ValidateSecretCreate` on the decoded secret is still open.
```

In `.claude/azure-keyvault-parity.md` line 227, replace

`note this is an unencrypted, same-instance base64url blob (`internal/backup/item_backup.go`, `BackupCertificate`), not a portable export`

with

`the blob is AES-256-GCM sealed under a key derived from the master key (`internal/backup/blob_seal.go`, B76), so it restores only on an instance with the same master key and a modified blob is refused; a restore into another vault keeps the history but drops key and CA links that do not resolve there; it is not a portable export`

On line 367 (Certificates Officer), append to the RocketVault cell: ` Issuing or renewing additionally needs `keys/sign` (for example Key Vault Crypto User) in the same vault, because a RocketVault certificate is issued over an existing key rather than creating its own (B77); an intentional divergence.`

- [ ] **Step 3: CLAUDE.md**

Under `### Certificate Management`, after the bullet that begins `- Soft-delete (list/restore/purge) is vault-scoped`, add:

```markdown
- Issuing or renewing (HTTP create, HTTP renew, MCP, CLI, and the auto-renew scheduler for the owner) needs `keys/sign` in the vault as well as `certificates/create`, and refuses a revoked, disabled or out-of-window key, including a CA's own key (B77). Item-backup blobs are sealed (`rvb2.`, HKDF from the master key); a cross-vault restore drops key and CA links that do not resolve there (B76). See `docs/release-notes/v4.11.0-certificate-restore-renewal-isolation.md`.
```

Under `### CLI Authorization`, in the first bullet (per-vault data-plane operations), append: ` A command that also acts on a second object type adds `Session.RequireAlso` (for example certificate create and renew require `keys/sign`); both go through `authorization.RequireDataPlaneAccess`, the same function HTTP handlers and the scheduler use.`

Under `## Documentation History`, add as the first entry:

```markdown
- **2026-10-XX**: Certificate restore and renewal isolation (B76-B78) —
  sealed item-backup blobs, cross-vault restore link dropping, vault-scoped
  and `keys/sign`-checked auto-renewal, `keys/sign` on every certificate
  issue and renew entry point, signing-key lifecycle, and a 36500-day
  validity cap. Plan:
  `docs/superpowers/plans/2026-10-02-certificate-restore-renewal-isolation-v2.md`.
```

- [ ] **Step 4: User-facing docs**

- `docs/cli-guide.md:452`: replace the Certificates Officer description with `Full control of certificates — create, update, delete, back up, restore. Issuing or renewing also needs Key Vault Crypto User (keys/sign) in the same vault.`
- `README.md:103`: replace `Full certificate control` with `Full certificate control; issuing or renewing also needs a role with keys/sign, such as Key Vault Crypto User`.
- `docs/mcp-server.md:142`: replace the row with `| Manage certificates and their policies | `Key Vault Certificates Officer`, plus `Key Vault Crypto User` to issue or renew | read secrets |`.
- `docs/api-developer-guide.md:422-424`: replace `The body is optional; without `validity_days` the new version keeps the current version's validity period. Requires the `Microsoft.KeyVault/vaults/certificates/create` data action.` with `The body is optional; without `validity_days` the new version keeps the current version's validity period, capped at 36500 days. Requires the `Microsoft.KeyVault/vaults/certificates/create` and `Microsoft.KeyVault/vaults/keys/sign/action` data actions.` Make the same `keys/sign` addition wherever the guide describes `POST /certificates`.
- `docs/admin-manual.html:1779`: replace `per-item base64url-encoded (not encrypted) backup/restore blobs` with `per-item backup/restore blobs, sealed under a master-key-derived key (blobs from before v4.11.0 no longer restore),`.

- [ ] **Step 5: Journey Q and the journeybook**

`docs/VAULT_USER_ACCESS_JOURNEYS_v3.md` Journey Q has Noor issue certificates over keys Sofia created. That already fails today on the B32 owner check (`ValidateKeyOwnership` requires the caller to own the key), and after this plan Noor also needs `keys/sign`. Rewrite the journey so that:
- Priya grants Noor both `Key Vault Certificates Officer` and `Key Vault Crypto User` in `prod` (`rocketvault vault-access grant noor --role "Key Vault Crypto User" --vault prod`);
- the keys Noor issues over are keys Noor owns (Sofia cannot create them for her; state that the owner check is why, citing B32), for example by giving Noor `crypto_manager` plus `Key Vault Crypto Officer` for key creation, or by saying plainly that the CLI has no way for one user to issue over another user's key;
- a new "prove it" block shows `rocketvault certificate renew` failing with `failed to renew certificate: forbidden: no role grants Microsoft.KeyVault/vaults/keys/sign/action in this vault` for a principal holding only Certificates Officer;
- every command still comes from `cmd/`, per the document's own rule.

Mirror the same changes into the Journey Q cases of `journeybook/src/data/journeys-n-u.ts`, following `journeybook/.claude/authoring-cases.md`, then run `cd journeybook && bun run check:links`.
Expected: the link check passes.

- [ ] **Step 6: Amend the two 2026-10-01 designs**

In `docs/superpowers/specs/2026-10-01-certificate-versioning-design.md` §6, after the bullet `- The certificate blob gains an additive `certificate_versions` field ... A blob without it restores unchanged.`, add `- Amended 2026-10-XX (B76): blobs are now sealed. A pre-versioning inner envelope still restores once sealed, but a blob taken before the seal no longer restores at all.`

In `docs/superpowers/specs/2026-10-01-certificate-and-key-export-design.md`, after the "Backup, restore and rekey stay compatible" bullet, add `- Amended 2026-10-XX (B76): blobs are sealed, so blobs written before the seal no longer restore. Restore still forces exportable=false.`

- [ ] **Step 7: Build the docs and commit**

Run: `./scripts/docs.sh build`
Expected: exits 0.

Stage the files of this task (and any HTML `docs.sh build` regenerated for them), then invoke the `dev-workflow-skills:1-git-commit` skill via the Skill tool. The subject should say the docs describe sealed backups and the keys/sign requirement for certificates.

---

### Task 12: Release note and final verification

**Files:**
- Create: `docs/release-notes/v4.11.0-certificate-restore-renewal-isolation.md`
- Modify: `scripts/docsgen/docs.go:49` (add the note after the v4.10.0 line)

- [ ] **Step 1: Write the release note**

Create `docs/release-notes/v4.11.0-certificate-restore-renewal-isolation.md`:

```markdown
# v4.11.0 — Certificate restore and renewal isolation

> The version number is provisional and may change before tagging.

This release closes a High-severity cross-vault path through certificate
backup and auto-renewal (`.claude/known-bugs.md` § B76), makes certificate
issuance and renewal respect the signing key's lifecycle and the `keys/sign`
data action on every entry point (§ B77, GitHub #43), and fixes two
certificate status-code and input defects (§ B78). Implementation plan:
`docs/superpowers/plans/2026-10-02-certificate-restore-renewal-isolation-v2.md`.

## Breaking changes

1. **Per-item backup blobs are sealed, and old blobs no longer restore.**
   `POST .../secrets/{id}/backup`, `.../keys/{id}/backup` and
   `.../certificates/{id}/backup` now return a blob that starts with `rvb2.`
   and is AES-256-GCM encrypted and authenticated under a key derived from
   the master key. The blob still carries the item's full version history.
   `.../restore` refuses, with 400, any blob taken before this upgrade, any
   modified blob, and any blob sealed under a different master key. There is
   no switch to accept old blobs: an old blob and a hand-forged one look
   identical, and accepting either is the vulnerability this release closes.
   Blobs never survived a master-key rotation anyway, because the values
   inside them were already master-key ciphertext.
2. **Issuing or renewing a certificate needs `keys/sign`.** Besides
   `Microsoft.KeyVault/vaults/certificates/create`, the caller must hold
   `Microsoft.KeyVault/vaults/keys/sign/action` in the vault, and a deny
   policy on `(keys, sign)` now blocks it. This applies to
   `POST .../certificates`, `POST .../certificates/{id}/renew`, the MCP
   `create_certificate` and `renew_certificate` tools,
   `rocketvault certificate create` and `rocketvault certificate renew`.
   **Key Vault Certificates Officer alone is no longer enough**; pair it with
   Key Vault Crypto User (or use Key Vault Crypto Officer or Key Vault
   Administrator). Issuance already required owning the key, so this mostly
   affects principals who own keys but no longer hold a key role.
3. **Auto-renewal re-checks the owner and stays in the vault.** The
   scheduler renews a certificate only while its owner still holds
   `keys/sign` in the certificate's vault, renews under that vault's scope,
   and skips a certificate with no vault. Refusals log `cert_auto_renew`
   with status `denied` or `failed`.
4. **Unusable keys cannot sign.** A revoked, disabled, expired or
   not-yet-active key can no longer issue or renew a certificate. A CA
   certificate can no longer sign while its own linked key is in that state,
   or when it records no key at all. Certificates already issued are not
   touched, and an exportable certificate still exports under its own rules.
5. **Cross-vault restores lose foreign links.** A certificate restored into
   a vault where its key or signing CA does not exist keeps its body, key
   copy and full version history, but loses those links (also on its
   archived versions), so it will not renew there, and a restored CA cannot
   sign. Restores into the vault the backup came from are unaffected.
6. **`validity_days` is capped at 36500** on create and renew (HTTP 400; CLI
   error). A renewal that keeps the current period, including auto-renewal,
   uses at most 36500 days.
7. **Status codes.** Certificate creation now answers 403 for a key or CA
   owned by someone else or for an unusable key, and 404 for a key or CA that
   is not in the vault, instead of 500. The renew route answers 409 for an
   unusable key or a missing signing CA, instead of 500.

## Upgrade procedure

1. Before upgrading, note which items you rely on per-item backups for.
   After upgrading, take fresh backups of them; keep the old blobs only as a
   record, since they will not restore. Full-database backups
   (`rocketvault backup`) are unaffected.
2. List who issues certificates: `rocketvault vault-access list --vault <name>`.
   Grant every principal that issues or renews certificates and holds no
   role with `keys/sign` the Key Vault Crypto User role in the same vault:
   `rocketvault vault-access grant <user> --role "Key Vault Crypto User" --vault <name>`.
   Do the same for the owners of auto-renewing certificates.
3. After the first scheduler run, check the audit log for `cert_auto_renew`
   rows with status `denied` or `failed`; each names the certificate that
   stopped renewing and why.
4. A CA certificate that now refuses to sign with "records no signing key"
   was restored from another vault. Re-issue it with
   `rocketvault certificate create --is-ca` over a key in the same vault.

## What did not change

- Existing certificates, keys, secrets and their versions are not modified
  by the upgrade. No schema migration runs.
- The owner comparison on the signing key and CA certificate (B32) is
  unchanged.
- Restore still never grants exportability.
- Certificate and key export, and the exporter roles, are unchanged.
```

The two `vault-access` commands match `cmd/vault-access/grant.go` (`grant <principal> --role ... --vault ...`) and `cmd/vault-access/list.go` (`list --vault ...`).

In `scripts/docsgen/docs.go`, after the line for `v4.10.0-authorization-policy-and-audit.md` (line 49), add:

```go
	{"docs/release-notes/v4.11.0-certificate-restore-renewal-isolation.md", "docs/release-notes/v4.11.0-certificate-restore-renewal-isolation.html"},
```

- [ ] **Step 2: Build the docs**

Run: `./scripts/docs.sh build`
Expected: exits 0 and writes `docs/release-notes/v4.11.0-certificate-restore-renewal-isolation.html`.

- [ ] **Step 3: Full verification**

Run: `go build ./... && go vet ./... && go test -p 2 ./... -count=1`
Expected: every package `ok`.

Run: `BASE=$(cat .git/rv-cert-isolation-base); PATH="$HOME/go/pkg/mod/golang.org/toolchain@v0.0.1-go1.25.7.linux-amd64/bin:$PATH" GOTOOLCHAIN=local ~/go/bin/golangci-lint run --new-from-rev="$BASE" ./...`
Expected: `0 issues.`

Run: `grep -rn "NewAdminScope" internal/services/certificates/ --include='*.go' | grep -v _test`
Expected: no output.

Run: `grep -n "blobVersions{Certificate: versions}" internal/backup/item_backup.go`
Expected: one line, inside `BackupCertificate`.

Run: `grep -c "case errors.Is" api/errors_certificate.go`
Expected: `14` (the eight arms that existed before this plan plus six added by Tasks 9 and 10, all in `writeCertificateError`; `writeCertificateRenewError` uses `if` statements).

- [ ] **Step 4: Commit**

Stage the release note, its generated HTML and `scripts/docsgen/docs.go`, then invoke the `dev-workflow-skills:1-git-commit` skill via the Skill tool. The subject should say the release note for certificate restore and renewal isolation is added.

---

## Self-Review

**Spec coverage.**
- B76: sealing that wraps the version-aware envelope (Task 2), link dropping on the current row and every archived version with a clear-not-reject decision (Task 3), vault-scoped scheduler that also scopes `ArchiveAndRenew` (Task 1), the HSM-handle and pre-upgrade-blob decisions (Task 2, § B76, release note, D1).
- B77 / #43: lifecycle on create and on renew's inline key read (Task 5), the CA's own key (Task 6), `keys/sign` plus the sign deny on HTTP create, HTTP renew (and so MCP), CLI create and CLI renew through one helper (Tasks 4, 7), the scheduler re-check (Task 8), the revocation decision (Task 6, § B77).
- B78: sentinels and additive arms on create and renew (Task 9), the cap on create, renew and the default renewal period (Task 10).
- Interplay with landed work: version history preserved through the seal and the link drop (Review Focus 2, 4); exporter roles unaffected and restore still forces `exportable=false` (Global Constraints, D2); B86's `ErrNameTaken` arm and the versioning arms preserved (Review Focus 7); the B81 handler-denial audit reused for the new 403s (`auditDenied`); the B80 route allow-list untouched because no route is added.

**Placeholder scan.** `<N>` and `<M>` are GitHub issue numbers that exist only once `gh issue create` runs in the same step; `2026-10-XX` is the commit date. Task 11 Step 5 describes the journey rewrite rather than giving its full text, because that document's rules require commands verified against `cmd/` at the time of editing.

**Type consistency.**
- `ErrSigningKeyUnusable`, `ErrSigningKeyForbidden`, `ErrSigningKeyNotFound`, `ErrCACertForbidden`, `ErrCACertNotFound`, `ErrInvalidValidityDays` are `error` vars in package `certificates`, referenced as `certServices.X` in `api/`.
- `RequireDataPlaneAccess(ctx, policies AccessPolicyService, roles RoleAssignmentService, principalID, vaultID uuid.UUID, resourceType model.PolicyResourceType, op model.PolicyOperation, action model.DataAction) error` is called identically in `cmd/vaultcli/vault.go`, `cmd/vaultcli/session.go`, `api/certificates.go` and the container's `SignAuthorizer`.
- `KeySignAuthorizer func(ctx context.Context, principalID, vaultID uuid.UUID) error` matches both `allowSign` helpers and the container closure.
- `SetSealKey(masterKey []byte) error` receives `[]byte` from `common.ParseMasterKey` and from the test helpers.
- `dropForeignReferences` receives `versions.Certificate` (`[]model.CertificateVersionRecord`), the same slice both write paths replay.

**Scratch verification.** All of Tasks 1-10 (production code, every new and changed test, the fixture sweep, the help-text edits and the `vaultapi` hint) were applied to a `git archive` copy of `b654fad3` outside the repository. In that copy `go build ./...`, `go vet ./...` and `go test -p 2 ./... -count=1` passed, every "confirm they fail" step was checked against the pre-change code for Tasks 1 and 3, and golangci-lint (go1.25.7) reported no finding on new or changed lines once the new HTTP tests used `NewRequestWithContext`. Task 11 and 12 (docs, journeybook, release note, `docs.sh build`) were not run.
