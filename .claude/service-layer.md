# Service layer, authorization and CLI authorization

Moved verbatim out of the project CLAUDE.md on 2026-10-20 to keep it short. CLAUDE.md keeps only the invariants.

## Service Layer Architecture (NEW)

### Authentication Services (`internal/services/auth/`)
- **PasswordService**: Password hashing and validation only
- **TOTPService**: TOTP generation and validation only
- **JWTService**: JWT token creation and validation only. Asymmetric-only since 2026-08-16: tokens are signed RS256/ES256 through `internal/signing`'s `SigningKeyProvider`, always carry a `kid` header, and `ValidateToken` rejects any token without one. The legacy HS256 "migration window" fallback and the `legacyJWTService` implementation were deleted (pentest finding H1 — the fallback's HMAC key was the repo-committed `jwt_secret`, and its deadline was recomputed on every boot so the window never closed). A signing-provider failure now aborts startup instead of degrading to HS256 — see `docs/superpowers/specs/2026-08-16-remove-hs256-jwt-fallback-design.md`.
- **AuthenticationService**: Orchestrates complete auth workflow
- **OIDCService**: OIDC authorization-code-flow login, additive to local username/password/TOTP — never replaces it. Gated by `oidc.enabled` in `.rocketvault.yaml` — unset/`false` disables it entirely, and `GET /oidc/login`/`GET /oidc/callback` (`api/oidc.go`) return 503 rather than the server attempting a network call to the issuer at startup. A real developer's local `.rocketvault.yaml` (gitignored, not checked in — see the Configuration section above) may set this `true` against a real issuer; the committed `.rocketvault.yaml.example` template ships with `oidc.enabled: false`, so a fresh clone following this doc's setup steps does not make any OIDC network call at startup. On successful callback, `UserService.FindOrCreateExternalUser` looks up or creates a `model.User` (default role: least-privilege `user`), and `AuthenticationService.IssueSessionForUser` issues the same JWT/session pair local login uses — there is no separate OIDC token-issuance path to drift out of sync. That shared path is asymmetric-only, so the 2026-08-16 HS256 removal changed nothing about OIDC login.

### User Management (`internal/services/users/`)
- **UserService**: User creation, updates, and management workflows

### Secret Management (`internal/services/secrets/`)
- **SecretService**: Orchestrates secret operations
- **CryptographyService**: Encryption/decryption only
- **VersioningService**: Secret version management only
- **TagService**: Tag management only

### Key Management (`internal/services/keys/`) - NEW ✨
- **KeyService**: RSA/ECDSA key generation, access control, CRUD operations
- Symmetric AES (`oct`) keys are **HSM-only** by design, matching Azure (Managed HSM never allows symmetric key creation on Standard/Premium vaults, and RocketVault's software provider mirrors that restriction). `KeyService.CreateOctKey` → `crypto.KeyProvider.GenerateAESKey` always fails with `crypto.ErrOctKeysRequireHSM` unless `hsm.enabled: true`; the PKCS#11 provider implements AES-KW, AES-CBC, and AES-GCM wrap/encrypt for real (2026-08-19 — see `docs/superpowers/specs/2026-08-19-hsm-secp256k1-aes-cbc-gcm-design.md`). `POST /keys` accepts `"type": "OCT"` with `"bits"` of 128/192/256. The PKCS#11 provider also generates and signs/verifies secp256k1 (P-256K) EC keys as of the same date — real HSM vendors may still reject non-NIST curves like secp256k1 at the hardware level, which `isHSMCapabilityError` (`internal/crypto/pkcs11_provider.go`) degrades to a clean `ErrUnsupportedCurve`/`ErrUnsupportedAlgorithm` instead of a leaked error.
- Software keys created or imported with `exportable: true` can be exported as unencrypted PKCS#8 via `POST .../keys/{key_id}/export` (`KeyService.ExportKey`), with the Key Vault Key Exporter role. The flag is immutable (`KeyRepository.Update` never writes it, rotation keeps it, restore forces it false); HSM, `oct` and ES256K keys are never exportable; a revoked key gives 409 `key_disabled`. Design: `docs/superpowers/specs/2026-10-01-certificate-and-key-export-design.md`; the 2026-08-25 key-export decision record is superseded for software keys only.
- The CLI counterpart is `rocketvault keys export <id>` (`cmd/keys/export.go`), sealed by default under the `secrets export` envelope, with `rocketvault export open` (`cmd/export.go`) to decrypt it offline. Local mode only; never an MCP tool. Design: `docs/superpowers/specs/2026-10-02-cli-certificate-and-key-export-design.md`.

### Caching

All in-process domain caches (secrets, keys, vaults) are built on a shared
generic core, `internal/cachekit/` (TTL+LRU, `Cloneable`/`Zeroable`,
`sync.Map`-backed), wrapped by `internal/cache/` (secrets), `internal/keycache/`
(decrypted keys), and `internal/vaultcache/` (vault-by-name lookups — new,
caches what `VaultResolutionMiddleware` previously fetched from the database on
nearly every API request). Config for all three lives under one unified
`cache:` YAML section (`cache.secrets.*`, `cache.keys.*`, `cache.vaults.*`),
loaded via `config.LoadCacheConfig()`. The old standalone `key_cache.*` section
is gone — see `docs/release-notes/v4.1.0-role-parity-and-authz-fix.md` for the
breaking-change note. `cache.certificates.*`/`cache.users.*` are accepted in
config but reserved for future use; no cache is wired up for those domains yet.

An optional L2 (network) tier sits behind all four domain caches:
`cache.rocket_mem.*`, loaded via `config.LoadRocketMemConfig()` and backed by
`internal/rocketmemcache` (a thin client over an external, RESP-speaking
key-value store, "Rocket-mem") and `internal/cachekit.TieredCache`. It exists
for cache coherency across multiple RocketVault instances sharing one
Rocket-mem — an in-process-only cache can't do that. Opt-in and disabled by
default; a deployment with no `cache.rocket_mem` section (or `enabled: false`)
is unaffected, and each of the four `...WithL2` domain constructors falls back
to the plain in-process-only cache whenever *that domain's own* cache is
disabled, so `cache.<domain>.enabled: false` is never silently overridden by
`cache.rocket_mem.enabled: true`. `LoadRocketMemConfig` fails closed: enabling
it without both `tls: true` and a non-empty username/password aborts startup
outright (Rocket-mem defaults to a fully open ACL until a user is configured).
Only the system CA store is consulted for Rocket-mem's certificate today —
there is no CA-pinning/insecure-skip-verify config yet. See
`docs/superpowers/specs/2026-09-06-rocket-mem-tiered-cache-design.md` for the
full design.

### Certificate Management (`internal/services/certificates/`) - NEW ✨
- **CertificateService**: Certificate lifecycle management, CA validation
- Certificates are versioned (2026-10-01): the `certificates` row is always the current version and `certificate_versions` holds every earlier one. `RenewCertificate` archives and bumps in one `CertificateVersionRepository.ArchiveAndRenew` transaction guarded by the version number, so a lost race is a 409. `CertificateRepository.Update` writes metadata only; never write a certificate body or key through it. Design: `docs/superpowers/specs/2026-10-01-certificate-versioning-design.md`.
- Soft-delete (list/restore/purge) is vault-scoped for both keys and certificates, mirroring the pre-existing secrets soft-delete pattern (`internal/services/secrets/secret_service.go`'s `ListDeletedSecrets`/`RecoverSecret`/`PurgeSecret`) — see `KeyService.ListDeletedKeys`/`RecoverKey`/`PurgeKey` and the `CertificateService` equivalents.
- Issuing or renewing (HTTP create, HTTP renew, MCP, CLI, and the auto-renew scheduler for the owner) needs `keys/sign` in the vault as well as `certificates/create`, and refuses a revoked, disabled or out-of-window key, including a CA's own key (B77). Item-backup blobs are sealed (`rvb2.`, HKDF from the master key); a cross-vault restore drops key and CA links that do not resolve there (B76). Release note: `docs/release-notes/v4.11.0-certificate-restore-renewal-isolation.md`.
- Certificates created with `exportable: true` (which requires an exportable key, else 409) export as a leaf-first chain plus PKCS#8, or PKCS12, via `POST .../certificates/{certificate_id}/export` (`CertificateService.ExportCertificate`, reads the repository never `certcache`, never retried). The export routes alone use the R6 `{"error":{"code","message"}}` body (`api/export.go`), set `Cache-Control: no-store`, and audit every attempt through `AuditService.RecordEvent`.
- The CLI counterpart is `rocketvault certificates export <id>` (`cmd/certificates/export.go`, `--format pem|pkcs12`, PKCS12 password never a flag value). Both CLI export commands audit every attempt that reaches their own checks (a failed login or missing service container records nothing) through `internal/services/exportaudit`, the package the HTTP export handlers now share for their fixed reasons and event shape.

### Authorization (`internal/services/authorization/`)
- **RBACService**: global role permissions for vault and user management only
- **AccessPolicyService**: explicit-deny override, evaluated before role grants
- **RoleAssignmentService**: per-vault Azure role grants and the `HasDataAction` authorization decision
- A global (`vault_id NULL`) `vaults:manage` allow is **create-and-list only** as of v4.6.0 — it no longer confers get/update/delete/recover, vault-webhook configuration, or role-assignment management on any vault it holds no vault-scoped grant over, whether or not it created that vault (a global-policy holder that created a vault under v4.5.0 got no creator-grant row and loses management of it on upgrade; conversely a holder handed a scoped policy by an admin keeps management of a vault it never created). Vault-scoped decisions for a concrete vault go through `AccessPolicyService.CheckVaultScopedAccess`, where a `NULL`-scoped deny still matches every vault but a `NULL`-scoped allow matches none; the collection-level create/list decision still calls `CheckAccess`. See `docs/release-notes/v4.6.0-narrow-global-vault-manage.md`.
- Vault data-plane routes are deny-by-default: see `docs/release-notes/v4.0.0-azure-rbac.md`

### CLI Authorization

HTTP requests get their authorization check for free from middleware. CLI commands call the service layer directly and bypass that middleware entirely, so every resource command must reproduce the equivalent check itself — split along the same two tiers documented above:

- **Per-vault data-plane operations** (`secrets`, `keys`, `certificates`): call `cmd/vaultcli.RequireDataAction` (which re-runs the identical two-stage check HTTP gets — `AccessPolicyService`'s explicit-deny override, then the deny-by-default role-assignment check) after resolving the target vault via `vaultcli.ResolveVaultID`. A command that also acts on a second object type adds `Session.RequireAlso` (for example certificate create and renew require `keys/sign`); both go through `authorization.RequireDataPlaneAccess`, the same function HTTP handlers and the scheduler use.
- **Vault-management operations** (`vaults` lifecycle: create/update/delete/recover/purge; `vault-access` role-assignment grant/revoke): call their own package-local helpers (`cmd/vaults/authz.go`, `cmd/vault-access/authz.go`), built on the shared `CanManageVault`/`CanPurgeVault`/`CanManageRoleAssignments` checks in `internal/services/authorization`. `CanManageVault`/`CanManageRoleAssignments` consult the vault-scoped check (`CheckVaultScopedAccess`) for a concrete vault and `CheckAccess` only for the `uuid.Nil` create/list decision — see the Authorization section above.
- **Provisioning-grant management** (`vault-provisioning grant`/`revoke`/`list`): calls its own package-local helper, `cmd/vault-provisioning/authz.go`'s `requireGrantAdmin`. Unlike the `vaults` and `vault-access` helpers above, this one has no access-policy or role-assignment path at all — it checks only the global `admin` account role. This tier is admin-only and deliberately non-delegable: a principal able to amend its own provisioning grant could raise its own quota, and the bound the grant exists to impose would be decorative. See `docs/release-notes/v4.5.0-vault-provisioning.md`.

`certificates export` and `keys export` are per-vault data-plane operations (`ActionCertificatesExportItem` / `ActionKeysExport`, `OpCreate`) with no account-role gate, because the exporter roles are granted per vault to principals that typically hold only the `user` or `service_account` account role. `export open` decrypts a local file only; its group replaces the root pre-run, so it needs no session.

A new CLI command that skips its tier's check bypasses authorization entirely — there is no other enforcement point on the CLI path.

CLI commands no longer require `--username`/`--password`/`--totp-code` on every invocation. `rocketvault users login` (password/TOTP) or `rocketvault users login --oidc` (browser-based, for OIDC-provisioned users who have no local password) cache the resulting session under `~/.rocketvault/sessions/<username>.json`; a bare command with no credential flags reuses whichever session `~/.rocketvault/sessions/current` points at, refreshing it transparently via its refresh token if expired. `rocketvault users logout` clears the cache (client-side only — no server-side revocation). See `docs/superpowers/specs/2026-08-15-cli-oidc-login-design.md` for the full design.

### Azure Role Additions (since 2026-08-11)

Four built-in roles were added beyond the original seven: `Key Vault Purge Operator`, `Key Vault Certificate User`, `Key Vault Crypto Service Encryption User`, and `Key Vault Data Access Administrator` (`model/azure_roles.go`). `Key Vault Data Access Administrator` is the one role that can manage *other* role assignments — grant and revoke — without also holding data-plane access itself; every other role's permissions are described in `.claude/azure-keyvault-parity.md`. Vaults also gained a real purge endpoint, `DELETE /api/v1/vaults/{vault_name}/purge`. Unlike vault-management's `CanManageVault`/`CanPurgeVault` (which short-circuit for the global admin role — see CLI Authorization above), the HTTP route has no admin bypass: it's gated purely by the `RouteVaultData`/`ActionVaultPurge` role-assignment check in `PolicyMiddleware`, so even a global admin needs an explicit role grant (e.g. `Key Vault Purge Operator`) in that specific vault. The CLI's `vaults purge` command, via `CanPurgeVault`, does allow the admin bypass — the two paths genuinely diverge here.

Two RocketVault-only roles followed on 2026-10-01: `Key Vault Certificate Exporter` (`ActionCertificatesExportItem`) and `Key Vault Key Exporter` (`ActionKeysExport`). Administrator holds both actions, and stays grantable by a delegated Data Access Administrator (accepted 2026-10-02); no other role holds either, and neither exporter role is in `nonAdminGrantableRoles`, so only a global admin can grant them. That makes thirteen built-in roles.

### 🔐 Authorization Scope (`model/scope.go`)

Every repository and service operation carries a `model.Scope` describing how it
is authorized: `ScopeVault` (any vault member), `ScopeOwner` (the owner only;
retired in P2) or `ScopeAdmin` (no predicate, trusted internal callers). The zero
value is `ScopeInvalid`, so an uninitialised scope fails closed. Build scopes
with `NewVaultScope`, `NewOwnerScope` or `NewAdminScope`; composite literals are
banned outside `model/scope_test.go` and enforced by the `scope-gate` CI job.
