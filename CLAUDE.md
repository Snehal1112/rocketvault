# RocketVault - Claude Code Documentation

## Project Overview

**RocketVault** is a self-hosted, open-source alternative to [Microsoft Azure Key Vault](https://azure.microsoft.com/en-us/products/key-vault), built entirely in **Go**. It brings virtually all the capabilities of Azure Key Vault — secrets management, cryptographic key operations, X.509 certificate lifecycle management, and multi-vault RBAC — to your own infrastructure, with no cloud dependency required.

A single RocketVault instance hosts any number of named **vaults**, each an isolated security boundary with its own secrets, keys, certificates, and per-vault Azure-role-parity access grants — see [Multi-Vault Architecture](.claude/multi-vault.md) and [Azure Key Vault Feature Parity](.claude/azure-keyvault-parity.md). Every deployment ships with a `default` vault, so single-vault use needs no extra setup.

Whether you need to secure application secrets, manage RSA/ECDSA keys, rotate credentials automatically, or issue and renew TLS certificates, RocketVault provides a familiar, Azure Key Vault-compatible workflow through both a **REST API** and a full-featured **CLI**, making it easy to integrate into any environment or automation pipeline.

**Type**: Self-hosted Azure Key Vault alternative built in Go
**Architecture**: Domain-driven design with clean architecture, complete dependency injection, and multi-vault RBAC (Azure Key Vault role parity)
**Status**: Actively developed; latest tagged release [v0.2.1](https://github.com/Snehal1112/rocketvault/releases); this branch (`v-4.0.0`) adds multi-vault + Azure RBAC ahead of its own tag
**Last Updated**: 2026-08-14 — added CLI vault-authorization, new Azure roles, OIDC, HSM AES keys, vault-scoped soft-delete for keys/certs, and the docs.sh build pipeline (all shipped 2026-08-11–13, previously undocumented)

## Technology Stack

- **Language**: Go 1.24.2 with modern practices (generics, structured logging)
- **Framework**: Gorilla Mux router with custom middleware chain
- **Database**: SQLite (dev) / PostgreSQL (prod) with encrypted storage
- **Security**: JWT + TOTP MFA, RSA/ECDSA keys, X.509 certificates
- **CLI**: Cobra framework for command-line operations

## Architecture Overview

```
rocketvault/
├── cmd/                    # CLI commands (Cobra-based)
│   ├── vaults/             # Vault lifecycle commands (create, list, delete, ...)
│   ├── vault-access/       # Per-vault role assignment commands (grant, list, revoke, roles)
│   ├── vaultcli/           # Shared CLI authorization primitives (ResolveVaultID, RequireDataAction)
│   ├── certificates/       # Certificate management commands
│   ├── keys/                # Key management commands
│   ├── secrets/            # Secret management commands
│   ├── users/               # User management commands
│   └── audit/               # Audit log query commands
├── api/                    # HTTP API layer with service integration
├── app/                    # Application core and options
├── bootstrap/              # Application initialization (SRP-compliant)
├── common/                 # Shared CLI/API helpers: vault-flag resolution, auth context, encryption, i18n
├── examples/
│   └── consumer-service/  # Example service demonstrating vault-client secret consumption
├── model/                  # Pure domain types and constants (DDD)
│   ├── user.go            # User, Claims, Role constants
│   ├── secret.go          # Secret domain type
│   ├── key.go             # Key domain type
│   ├── certificate.go     # Certificate domain type
│   ├── vault.go           # Vault, DefaultVaultID, name/tag validation
│   ├── scope.go           # Scope authorization value object
│   └── azure_roles.go     # Azure Key Vault-parity built-in role definitions and data actions
├── internal/
│   ├── services/          # Business logic services (SRP-compliant)
│   │   ├── auth/          # Authentication services (password, TOTP, JWT, OIDC)
│   │   ├── users/         # User management services
│   │   ├── secrets/       # Secret management services (4 focused services)
│   │   ├── keys/          # Key management services
│   │   ├── certificates/  # Certificate management services
│   │   ├── vaults/        # Vault lifecycle and cascade soft-delete/recover
│   │   ├── authorization/ # RBAC, access-policy, and per-vault role-assignment services
│   │   ├── softdelete/    # Background scheduler that purges soft-deleted items past retention
│   │   ├── oauth2/        # OAuth2 client-credentials grant for service accounts
│   │   ├── audit/         # Audit log persistence and compliance reporting
│   │   └── retry/         # Retry-aware service wrappers
│   ├── repositories/      # Pure CRUD data access with interfaces
│   │   ├── user_repository.go         # UserRepositoryInterface + implementation
│   │   ├── secret_repository.go       # Secret data access
│   │   ├── key_repository.go          # Key data access
│   │   └── certificate_repository.go  # Certificate data access
│   ├── container/         # Dependency injection container
│   ├── middleware/        # HTTP middleware (SRP-compliant)
│   ├── backup/            # Backup and restore functionality
│   ├── cache/              # Secret caching layer, wraps cachekit
│   ├── cachekit/          # Generic TTL+LRU cache core (Cloneable/Zeroable, sync.Map-backed) shared by all domain caches
│   ├── keycache/          # In-process decrypted key cache for crypto operations, wraps cachekit
│   ├── vaultcache/        # In-process vault-by-name cache, wraps cachekit
│   ├── crypto/            # Cryptographic operations — software and PKCS#11/HSM key providers
│   ├── db/                # Database layer
│   ├── health/            # Health check endpoints
│   ├── logging/           # Structured logging
│   ├── metrics/           # Prometheus metrics
│   ├── retry/             # Retry logic and middleware
│   ├── signing/           # JWT asymmetric signing key storage (OS keychain)
│   ├── vaultclient/       # Client library for consuming secrets from a RocketVault instance
│   ├── vaultapi/          # Typed REST client for the RocketVault API (used by mcpserver; CLI remote mode next)
│   ├── mcpserver/         # Model Context Protocol server — tier-gated tool surface over vaultapi
│   └── validation/        # Input validation
├── scripts/
│   └── docsgen/            # Standalone Go module rendering the docs site (see Build and Run > Documentation)
└── config/                # Configuration management
```

## Complete Domain-Driven Architecture Transformation ✅

### Core Architectural Problems SOLVED
- **85% Code Duplication**: Between `auth.go` and `user_repository.go` → **ELIMINATED**
- **Mixed-Responsibility Package**: `auth.go` contained domain types + repository + helpers → **SEPARATED**
- **Repository Pattern Violations**: Mixed data access with business logic → **SOLVED**
- **Authentication Logic Scattered**: JWT, TOTP, password logic mixed throughout → **SOLVED**
- **Bootstrap Module Complexity**: Single setup method handled all concerns → **SOLVED**
- **Middleware Violations**: Authentication + authorization + HTTP in single method → **SOLVED**
- **API Integration Gap**: Services disconnected from API layer → **SOLVED**
- **Global State Dependencies**: Direct database access, logger globals → **SOLVED**

### Perfect Domain-Driven Design Implementation
- **`internal/auth/auth.go`**: **COMPLETELY ELIMINATED** 🎉
- **Domain Types**: Moved to `model/user.go` (User, Claims, Role constants)
- **Repository Interface**: Moved to `internal/repositories/user_repository.go`
- **Helper Functions**: Already existed in service layer (TOTPService, JWTService)
- **Zero Code Duplication**: Single source of truth for all domain concepts

### Complete Solutions Implemented
- **Service Layer Architecture**: 15+ focused services with single responsibilities
- **Dependency Injection Container**: Complete service lifecycle management with proper initialization
- **API Integration**: Full service container integration via `WithServiceContainer` option
- **Pure Repository Pattern**: Data access only, expects pre-processed data (encrypted, hashed, versioned)
- **Modular Bootstrap**: Specialized initializers (DatabaseInitializer, ServerStarter, ConfigurationValidator)
- **End-to-End Integration**: Complete flow from bootstrap → container → API → middleware → services

## Key Components Documentation

### 🧠 AI Knowledge Base (`~/data/rocket/Nl-knowledge-base/rocketvault/`)
- Local-machine, AI-maintained reference — not part of this repo, not committed, don't expect it on a fresh clone
- 10 topic pages (overview, architecture, dev-workflow, database, testing, security-auth, multi-vault, release-process, known-issues-gotchas, glossary), each re-verified against source, not just transcribed from docs — see its `README.md` for the one-line index and last-verified commit per page
- **Before implementing in a subsystem**, read that subsystem's page first (e.g. touching `internal/services/authorization/` → `security-auth.md`) — cheaper and more precise than re-deriving architecture from source each time
- **Before debugging**, check `known-issues-gotchas.md` first — it's a grep-first catalogue of past incidents and filed bugs with root cause and fix, and often the bug is already documented
- Refreshed via the `kb-refresh` skill (targeted diff since last verified commit, not a full rebuild) — if a page looks stale for the current HEAD, ask for a refresh rather than trusting it blindly

### 📘 [Administrator Manual](docs/admin-manual.html)
- Single authoritative, operationally-focused handbook covering every feature
- Getting started, identity & access, core resources, operations, integration
- Canonical entry point; older guides are linked as deep-dives

### 🏛️ [Multi-Vault Architecture](.claude/multi-vault.md)
- Vault as a routing + context-scoping layer (Azure Key Vault parity)
- Vault-scoped resources, per-vault access policies, default-vault migration
- Keys/certs CLI `--vault` wiring and vault-scoped soft-delete (list/restore/purge) shipped 2026-08-11–13; `.claude/multi-vault.md`'s "Known deferrals" section was refreshed to match on 2026-08-26

### 🔵 [Azure Key Vault Feature Parity](.claude/azure-keyvault-parity.md)
- Feature-by-feature comparison (secrets, keys, certs, RBAC, soft-delete, HSM, audit)
- Parity status per capability with code and Azure-doc sources
- RocketVault extras and intentional gaps vs Azure Key Vault

### 🐛 [Known Bugs](.claude/known-bugs.md)
- Open bugs, fixed bugs, and deferred refactors with root-cause analysis and fix recipes
- This is the living source of truth for bug status — don't duplicate bug entries elsewhere in this file, they will drift stale (see the "Open Bugs" note below)

### 🗺️ [Roadmap — Azure Parity & Beyond](.claude/roadmap-azure-parity-and-beyond.md)
- Phased plan built on `.claude/azure-keyvault-parity.md`'s gap analysis: close remaining Azure Key Vault gaps first (key import, rotation-policy scheduler, HSM P-256K/AES-CBC, ACME certs, one RBAC role fix), then platform maturity, then self-hosted-native differentiators beyond Azure
- README's `## Roadmap > Planned` section is a short checklist pointing here — this doc carries the rationale, non-goals, and phase grouping

### 🧪 [CLI Test Suite Implementation](doc/README_TESTS.md)
- Comprehensive test coverage for all CLI commands
- Mock infrastructure and service testing framework
- Security validation and authentication testing
- Performance and integration testing capabilities

### 👤 [Admin User Setup Guide](doc/README_ADMIN_SETUP.md)
- Bootstrap token configuration and management
- Initial admin user creation process
- MFA setup and TOTP configuration
- Authentication flow validation

> Nine previously-listed docs here (`current-architecture-state.md`, `service-layer-analysis.md`,
> `dependency-injection-guide.md`, `database-optimization.md`, `auth-elimination-guide.md`,
> `service-container-integration.md`, `retry-system-architecture.md`, `retry-integration-guide.md`,
> `retry-configuration-reference.md`, plus `database-init-patterns.md`,
> `repository-migration-status.md`, `repository-pattern-standardization.md`,
> `configuration-standardization.md`, `cmd-cleanup-report.md`) do not exist under `.claude/` and
> were removed 2026-08-11 — they described one-time refactors that already landed; the code itself
> and `.claude/known-bugs.md` are now the source of truth for that history. If you need one of
> these topics, check `git log` for the commit that did the work rather than looking for a doc.

## Additional Documentation

### Developer Resources
- **[API Developer Guide](docs/api-developer-guide.md)**: REST API reference, authentication, and SDK examples
- **[Testing Guide](docs/testing-guide.md)**: Comprehensive testing procedures and scenarios
- **[Integration Examples](docs/integration-examples.md)**: Integration patterns and examples
- **[CLI Usage Guide](docs/cli-guide.md)**: Step-by-step CLI walkthrough, first-time setup to everyday use
- **[Vault, User & Access Journeys](docs/VAULT_USER_ACCESS_JOURNEYS_v3.md)**: 21 end-to-end scenarios organized by actor and role rather than by command — onboarding, delegated access management, emergency explicit-deny, offboarding, vault retirement, multi-vault isolation. Its commands are taken from `cmd/`, never invented, and where a capability has no CLI equivalent the journey says so instead of showing a plausible-looking invocation; several journeys exist specifically to document CLI/HTTP behaviour divergences (e.g. the `vaults purge` admin-bypass split described under Azure Role Additions above). Useful when you need to know how a role behaves in practice, not what a command's flags are
- **[QA Journeybook](journeybook/README.md)**: The journeys document above, turned into a single-file offline HTML page (`journeybook/dist/journeybook.html`) that a QA engineer opens from disk and records a pass or fail against — 23 suites, 245 checks, each carrying its command, its verbatim expected output, and which of the three gates it exercises. Most checks also carry the mechanism behind the behaviour, how to settle a result the expected line leaves ambiguous, what the check leaves behind, and cross-references to the checks it depends on or contradicts — each claim citing the document section or `file.go:line` it came from, enforced by `bun run check:links`. Checks the sources do not explain carry no explanation, which is deliberate: an absent field is honest and an invented one would send a tester to file a defect against working software. Verdicts live in the tester's own browser and export as a plain-text summary. The cases are transcribed from `docs/VAULT_USER_ACCESS_JOURNEYS_v3.md` and go stale the moment the CLI changes without them — see `journeybook/.claude/authoring-cases.md` for the rules before editing them
- **[Setup Guide](doc/setup.md)**: Installation and initial configuration
- **[Intent Convention](.claude/intent-convention.md)**: Before brainstorming's architectural path starts designing, write a short `docs/superpowers/intents/YYYY-MM-DD-<topic>.md` first — what/why/scope/out-of-scope, a few sentences each
- **[v4.0.0 Azure RBAC Release Notes](docs/release-notes/v4.0.0-azure-rbac.md)**: Breaking changes, role table, and upgrade procedure
- **[MCP Server Guide](docs/mcp-server.md)**: Running `rocketvault mcp` for Claude Code and Claude Desktop, capability tiers, and service-account setup

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
- Soft-delete (list/restore/purge) is vault-scoped for both keys and certificates, mirroring the pre-existing secrets soft-delete pattern (`internal/services/secrets/secret_service.go`'s `ListDeletedSecrets`/`RecoverSecret`/`PurgeSecret`) — see `KeyService.ListDeletedKeys`/`RecoverKey`/`PurgeKey` and the `CertificateService` equivalents.

### Authorization (`internal/services/authorization/`)
- **RBACService**: global role permissions for vault and user management only
- **AccessPolicyService**: explicit-deny override, evaluated before role grants
- **RoleAssignmentService**: per-vault Azure role grants and the `HasDataAction` authorization decision
- A global (`vault_id NULL`) `vaults:manage` allow is **create-and-list only** as of v4.6.0 — it no longer confers get/update/delete/recover, vault-webhook configuration, or role-assignment management on any vault it holds no vault-scoped grant over, whether or not it created that vault (a global-policy holder that created a vault under v4.5.0 got no creator-grant row and loses management of it on upgrade; conversely a holder handed a scoped policy by an admin keeps management of a vault it never created). Vault-scoped decisions for a concrete vault go through `AccessPolicyService.CheckVaultScopedAccess`, where a `NULL`-scoped deny still matches every vault but a `NULL`-scoped allow matches none; the collection-level create/list decision still calls `CheckAccess`. See `docs/release-notes/v4.6.0-narrow-global-vault-manage.md`.
- Vault data-plane routes are deny-by-default: see `docs/release-notes/v4.0.0-azure-rbac.md`

### CLI Authorization

HTTP requests get their authorization check for free from middleware. CLI commands call the service layer directly and bypass that middleware entirely, so every resource command must reproduce the equivalent check itself — split along the same two tiers documented above:

- **Per-vault data-plane operations** (`secrets`, `keys`, `certificates`): call `cmd/vaultcli.RequireDataAction` (which re-runs the identical two-stage check HTTP gets — `AccessPolicyService`'s explicit-deny override, then the deny-by-default role-assignment check) after resolving the target vault via `vaultcli.ResolveVaultID`.
- **Vault-management operations** (`vaults` lifecycle: create/update/delete/recover/purge; `vault-access` role-assignment grant/revoke): call their own package-local helpers (`cmd/vaults/authz.go`, `cmd/vault-access/authz.go`), built on the shared `CanManageVault`/`CanPurgeVault`/`CanManageRoleAssignments` checks in `internal/services/authorization`. `CanManageVault`/`CanManageRoleAssignments` consult the vault-scoped check (`CheckVaultScopedAccess`) for a concrete vault and `CheckAccess` only for the `uuid.Nil` create/list decision — see the Authorization section above.
- **Provisioning-grant management** (`vault-provisioning grant`/`revoke`/`list`): calls its own package-local helper, `cmd/vault-provisioning/authz.go`'s `requireGrantAdmin`. Unlike the `vaults` and `vault-access` helpers above, this one has no access-policy or role-assignment path at all — it checks only the global `admin` account role. This tier is admin-only and deliberately non-delegable: a principal able to amend its own provisioning grant could raise its own quota, and the bound the grant exists to impose would be decorative. See `docs/release-notes/v4.5.0-vault-provisioning.md`.

A new CLI command that skips its tier's check bypasses authorization entirely — there is no other enforcement point on the CLI path.

CLI commands no longer require `--username`/`--password`/`--totp-code` on every invocation. `rocketvault users login` (password/TOTP) or `rocketvault users login --oidc` (browser-based, for OIDC-provisioned users who have no local password) cache the resulting session under `~/.rocketvault/sessions/<username>.json`; a bare command with no credential flags reuses whichever session `~/.rocketvault/sessions/current` points at, refreshing it transparently via its refresh token if expired. `rocketvault users logout` clears the cache (client-side only — no server-side revocation). See `docs/superpowers/specs/2026-08-15-cli-oidc-login-design.md` for the full design.

### Azure Role Additions (since 2026-08-11)

Four built-in roles were added beyond the original seven: `Key Vault Purge Operator`, `Key Vault Certificate User`, `Key Vault Crypto Service Encryption User`, and `Key Vault Data Access Administrator` (`model/azure_roles.go`). `Key Vault Data Access Administrator` is the one role that can manage *other* role assignments — grant and revoke — without also holding data-plane access itself; every other role's permissions are described in `.claude/azure-keyvault-parity.md`. Vaults also gained a real purge endpoint, `DELETE /api/v1/vaults/{vault_name}/purge`. Unlike vault-management's `CanManageVault`/`CanPurgeVault` (which short-circuit for the global admin role — see CLI Authorization above), the HTTP route has no admin bypass: it's gated purely by the `RouteVaultData`/`ActionVaultPurge` role-assignment check in `PolicyMiddleware`, so even a global admin needs an explicit role grant (e.g. `Key Vault Purge Operator`) in that specific vault. The CLI's `vaults purge` command, via `CanPurgeVault`, does allow the admin bypass — the two paths genuinely diverge here.

### 🔐 Authorization Scope (`model/scope.go`)

Every repository and service operation carries a `model.Scope` describing how it
is authorized: `ScopeVault` (any vault member), `ScopeOwner` (the owner only;
retired in P2) or `ScopeAdmin` (no predicate, trusted internal callers). The zero
value is `ScopeInvalid`, so an uninitialised scope fails closed. Build scopes
with `NewVaultScope`, `NewOwnerScope` or `NewAdminScope`; composite literals are
banned outside `model/scope_test.go` and enforced by the `scope-gate` CI job.

## Dependency Injection Container

**Location**: `internal/container/service_container.go`

**Purpose**: Manages all service dependencies and eliminates global state

**Key Features**:
- Configuration-driven service creation
- Proper service lifecycle management
- Eliminates global variables like `db.DB`
- Enables easy testing with mock services

## Development Patterns

### Service Layer Pattern
```go
// Services orchestrate business logic
type SecretService interface {
    CreateSecret(ctx context.Context, req CreateSecretRequest) (*Secret, error)
}

// Services delegate to repositories for data access
func (s *secretService) CreateSecret(ctx context.Context, req CreateSecretRequest) (*Secret, error) {
    // Business logic
    encryptedValue, err := s.cryptoService.EncryptSecret(req.Value)

    // Data access delegation
    return s.secretRepo.Create(ctx, secret)
}
```

### Repository Pattern (Refactored)
```go
// Repositories handle ONLY data access - no business logic
type SecretRepository interface {
    Create(ctx context.Context, secret *Secret) error  // Pre-encrypted data expected
    Read(ctx context.Context, id uuid.UUID) (*Secret, error)
    Update(ctx context.Context, secret *Secret) error
    Delete(ctx context.Context, id uuid.UUID) error
}
```

### Middleware Pattern (SRP-Compliant)
```go
// Focused middleware delegates to services
func (m *Middleware) AuthenticationMiddleware(next http.Handler) http.Handler {
    // HTTP concern: extract token
    token := extractToken(r)

    // Business logic: delegate to service
    claims, err := m.container.GetAuthenticationService().ValidateSession(ctx, token)

    // HTTP concern: handle response
    next.ServeHTTP(w, r.WithContext(ctx))
}
```

## Testing Strategy

### Testing Infrastructure ✅
- **CLI Test Suite**: All CLI commands tested with 50+ test cases
  - Mock infrastructure with testify/mock framework
  - Security, authentication, and RBAC validation
  - End-to-end workflow validation
  - ✅ Type assertion issue resolved with ServiceContainerInterface pattern
- **Middleware Testing**: Comprehensive test suite with 94.9% coverage
  - Authentication and authorization middleware
  - Logging and error handling middleware
  - Rate limiting and CORS middleware
- **Service Layer Testing**: Integration tests for all service components
- **Repository Testing**: Repository pattern validation and consistency tests

**CLI Type Safety Fix (October 22, 2025)**: Implemented `ServiceContainerInterface` in `internal/container` package. Updated 16 command files across all CLI packages to use interface type assertion instead of concrete type. This eliminates type assertion panics in tests while maintaining type safety in production code.

### Service Testing (NEW)
- Each service can be tested independently with mocks
- Clear boundaries reduce test complexity
- No global state dependencies in tests

### Integration Testing
- Service container enables easy integration testing
- Mock services can be injected for specific test scenarios

## Current Architecture Status

> The two subsections below are a snapshot from the October 2025 DDD refactor —
> the codebase has since grown substantially (multi-vault + Azure RBAC parity,
> see the Authorization section above). Treat specific percentages here as
> historical, not current measurements; re-run `go build ./...` / `go test ./...`
> to check current state rather than trusting a number written down a refactor
> ago.

### ✅ **Perfect Architecture Achieved** *(Oct 2025 refactor)*
- **Complete SRP Compliance**: Every component has a single, well-defined responsibility
- **Perfect Domain-Driven Design**: Domain types in `model/`, services in `services/`, repositories in `repositories/`
- **Zero Code Duplication**: Eliminated duplication between auth.go and user_repository.go (auth.go has since been removed entirely)
- **Full Dependency Injection**: End-to-end service container integration eliminates all global state
- **Clean API Integration**: Service container properly integrated with API, middleware, and handlers
- **Modern Go Architecture**: Interfaces, dependency injection, proper error handling, structured logging
- **Security-First Design**: Comprehensive auth with properly separated services (JWT + TOTP + RBAC), extended since by per-vault Azure role authorization
- **Pure Repository Pattern**: Data access expects pre-processed data, no business logic
- **Enterprise-Grade Performance**: Connection pooling, strategic indexing, performance monitoring
- **Modular Bootstrap**: Specialized initializers with clear separation of concerns
- **Testable Architecture**: Services can be tested independently with mocked dependencies

### ✅ **Major Architectural Achievements** *(Oct 2025 refactor)*
- **Auth.go Complete Elimination**: Mixed-responsibility package completely removed and reorganized
- **Domain Type Consolidation**: All user-related types in single `model/user.go` file
- **Repository Interface Separation**: Clean separation of interface from implementation
- **Service Layer Completion**: All authentication logic properly moved to service layer
- **Comprehensive CLI Test Suite**: grew from this refactor's starting point to 600+ test files project-wide today
- **Admin User Bootstrap**: Complete initial admin setup with MFA configuration
- **Service Container Integration**: CMD commands integrated with the service layer, including `KeyService` and `CertificateService`
- **Database Optimization**: Enterprise-grade connection pooling and performance monitoring

### ✅ **Recent Major Improvements (October 2025)**
- **CLI Type Safety (Oct 22)**: Implemented `ServiceContainerInterface` pattern
  - Updated 16 command files to use interface type assertion
  - Eliminated all type assertion panics in test infrastructure
  - Enhanced testability with mock-friendly interface design
- **Logging Infrastructure**: Extracted log rotation to `internal/logging` package with proper error handling
- **Middleware Testing**: Comprehensive test suite with 94.9% coverage achieved
- **Repository Pattern Standardization**: Complete documentation and migration status tracking
- **Service Container Integration**: Complete 95% compatibility achieved with all CMD commands
- **Database Optimization**: Enterprise-grade connection pooling and performance monitoring
- **Query Performance**: 90%+ improvement with strategic indexing and N+1 elimination
- **Production Monitoring**: Real-time database performance metrics and health checks

### ⚠️ **Open Bugs**
See `.claude/known-bugs.md` for the current list with root-cause analysis and fix
recipes — don't copy bug status into this file, it goes stale (the "secrets table
missing columns" bug previously listed here was already fixed on 2026-03-08, per
that file, and was left in this file as still-open for 5 months).

### 🎯 **Future Improvements**
1. **Caching Layer** - Redis integration for high-performance operation caching
2. **Enhanced CLI Features** - Additional command options and output formats
3. **API Testing Suite** - REST API comprehensive testing framework
4. **Observability Enhancement** - Prometheus metrics and distributed tracing

## Build and Run

### Development

First-time setup (once per clone):
```bash
cp .rocketvault.yaml.example .rocketvault.yaml
# Edit .rocketvault.yaml: replace the two "GENERATE_WITH" placeholders with
# real values — for both, that means:
openssl rand -base64 32
```

Then:
```bash
go run main.go serve
```

### Testing
```bash
# Run all tests
go test ./...

# Run CLI test suite specifically
go test ./cmd/... -v

# Run with coverage
go test ./cmd/... -coverprofile=coverage.out
go tool cover -html=coverage.out
```

### Documentation

`scripts/docs.sh` builds and serves the HTML docs site: renders the markdown docs listed in `scripts/docsgen/docs.go` into styled HTML siblings of the hand-written `docs/admin-manual.html` (via `scripts/docsgen`, its own Go module — no Python step, unlike before 2026-08-13).

```bash
./scripts/docs.sh build     # render markdown -> styled HTML
./scripts/docs.sh package   # build + tar.gz/zip with checksums
./scripts/docs.sh serve     # local preview server
```

### Linting
```bash
# Check if specific linting commands exist in project
npm run lint      # If available
npm run typecheck # If available
```

## Configuration

- **Main**: `.rocketvault.yaml` — the **only** config loaded at runtime. Not
  committed (see `.rocketvault.yaml.example`); every fresh clone starts with
  `cp .rocketvault.yaml.example .rocketvault.yaml` and generates its own
  `master_key`/`bootstrap_token`.
- **Test**: `test-config.yaml`
- **Docker**: `docker-compose.yml` (`.rocketvault.docker.yaml.tmpl`, rendered
  via `envsubst` from `.env` at container start — never holds a literal secret).
  The same template also serves Fly.io and Railway; `docker-entrypoint.sh`
  parametrizes the database driver via `RV_DB_DRIVER` (`sqlite3` by default,
  `postgres` set explicitly by `docker-compose.yml`/`fly.toml`) rather than
  keeping a separate template per driver.

### Config facts (2026-03-08)
- `initConfig()` in `cmd/root.go` hardcodes `.rocketvault.yaml` — no automatic env switching.
- Three redundant env-specific files were deleted (`-test`, `-staging`, `-production`).
- `jwt.expiry` is **optional**, not required: `internal/container/service_container.go:366-369` reads it via `viper.GetDuration("jwt.expiry")` and falls back to `time.Hour` when it is absent or zero. Nothing validates it at startup — only `master_key` (`bootstrap.ValidateMasterKey`) and the JWT signing provider abort. Both committed configs set `1h` (`.rocketvault.yaml.example:28`, `.rocketvault.docker.yaml.tmpl:33`). This entry previously claimed `"15m"` and "required"; both were wrong, and the same mistaken value had spread to `cmd/serve.go`'s help text and a comment in `internal/vaultapi/login.go` (corrected 2026-09-04).
- `jwt_secret` and `jwt.migration_window` are **no longer read by any Go code** (HS256 removal, 2026-08-16, pentest finding H1). Pentest finding H4 has since landed too: both keys are deleted from `.rocketvault.yaml` outright (not merely unread), and the file itself is no longer git-tracked — see `.claude/known-bugs.md` § B10. `jwt.key_source` (default `os_store`) is now mandatory — if its provider cannot be constructed, startup fails rather than falling back.
- Dead stubs (not yet read by code, kept as planned-feature markers): `health.*`, `development.*`. `monitoring.*` was wired up 2026-08-14: `enable_metrics` gates the `GET /metrics` Prometheus endpoint (`api/metrics.go`), `slow_query_threshold` drives the slow-query cutoff in `internal/db` and `internal/health` (default 100ms, via `config.LoadMonitoringConfig`), and `metrics_interval` controls how often `internal/metrics.MetricsScheduler` refreshes the `rocketvault_db_*` gauges — all wired from `bootstrap.go`.
- `rate_limit.per_vault` (default 600/min, added 2026-09-03) is the noisy-neighbour guard: a token bucket per *vault*, on top of the existing per-IP `rate_limit.default`/`rate_limit.auth` buckets. Enforced by `VaultRateLimitMiddleware` (`internal/middleware/vault_rate_limit.go`), which must stay after `VaultResolutionMiddleware` in `api/api.go`'s chain — the vault is unknown before that. Health probes are exempt (they skip vault resolution, so counting them would let a liveness probe drain the default vault's budget); routes that resolve no vault of their own count against the default vault. Rejections return 429, report `X-RateLimit-Vault-*` headers (deliberately distinct names so they cannot clobber the per-IP limiter's `X-RateLimit-*`), and increment `rocketvault_vault_rate_limit_exceeded_total{vault}` when `monitoring.enable_metrics` is on.
- `retry.service_operations` is intentionally unwired: fully parsed and tested, but no production caller yet. Reserved for a future feature (e.g., cloud HSM or ACME issuer) that needs a retry tier distinct from `database`/`external_services`. See `.claude/known-bugs.md` § I1 for investigation and rationale.
- For `bootstrap_token` seeding details, see `seedBootstrapToken()` in `internal/db/db.go`.
- `.rocketvault.yaml` is gitignored (fixed 2026-08-16 — see
  `.claude/known-bugs.md` § B10); `.rocketvault.yaml.example` is the committed
  template. Never add a real secret value to the `.example` file.

## Admin User Setup

### Initial Admin Creation
```bash
# Create first admin user (requires bootstrap token — see Configuration
# above; .rocketvault.yaml is generated per-clone, not committed)
./rocketvault users admin --admin-username=admin --admin-password=<your-password> --bootstrap-token="<value from your .rocketvault.yaml>"
```

### Admin Credentials (Example)
- **Username**: `admin` (or your choice, via `--admin-username`)
- **Password**: set via `--admin-password` at creation time
- **TOTP Secret**: Configure in authenticator app
- **Bootstrap Token**: no fixed value — each clone generates its own in
  `.rocketvault.yaml` (see Configuration); the file is gitignored and the
  token is rotated per `.claude/known-bugs.md` § B10, so there is no
  committed value to document here.

## Security Notes

✅ **PRODUCTION READY**: Configuration security addressed through secure storage and proper access controls. All security implementations (JWT+TOTP+RBAC) are production-grade.

## Performance and Production Readiness

### ✅ **Database Optimizations Implemented**
- **Connection Pooling**: Environment-specific pool configuration (dev/staging/prod)
- **Strategic Indexing**: 25+ indexes for optimal query performance
- **Performance Monitoring**: Real-time query execution tracking and slow query detection
- **Query Optimization**: N+1 elimination and batch operation improvements

### ✅ **Monitoring and Observability**
- **Health Checks**: Enhanced database health monitoring at `/health/database`
- **Performance Metrics**: Query execution time, connection pool utilization
- **Audit Logging**: Comprehensive security event tracking with structured logs

## Documentation History

- **2026-08-24**: Added the MCP server (`rocketvault mcp`) — a Model Context
  Protocol interface exposing the vault to Claude Code and Claude Desktop over
  stdio. Read-only by default (10 tools), with independently gated tiers for
  writes, destructive operations, crypto and secret values (28 tools fully
  enabled — verified live via `rocketvault mcp --check` on 2026-09-03; this
  line and the MCP plan docs previously said 27, which was off by one).
  Built on a new `internal/vaultapi` typed REST client, which the
  pending CLI remote-mode work is expected to reuse. Design:
  `docs/superpowers/specs/2026-08-21-mcp-server-design.md`; guide:
  `docs/mcp-server.md`.
- **2026-08-17**: Added `.claude/roadmap-azure-parity-and-beyond.md` — a phased
  roadmap built on the parity doc's gap analysis (close remaining Azure gaps,
  then platform maturity, then self-hosted-native differentiators). README's
  `## Roadmap > Planned` section was trimmed to a checklist linking to it.
- **2026-08-11**: README and this file corrected to document the multi-vault +
  Azure RBAC architecture (shipped ~May–Aug 2026); removed 13 dead `.claude/`
  doc links and two incorrect `cmd/README_*.md` paths (the files live under
  `doc/`); removed unverifiable grade/percentage claims.
- **2025-10-22**: `ServiceContainerInterface` pattern — 16 CLI command files
  updated to interface-based type assertions, eliminating type-assertion panics
  in tests.

## Retry System Implementation ✅

### **Phase 2: Retry Logic with Exponential Backoff - COMPLETED**

Comprehensive retry system with exponential backoff, circuit breakers, and configurable policies for enhanced reliability.

#### **Core Features**
- **Exponential Backoff**: Configurable delays with jitter to prevent thundering herd
- **Circuit Breaker**: Protection against cascading failures (foundation implemented)
- **Multiple Policies**: Separate retry strategies for database, external services, and internal operations
- **Context-Aware**: Proper cancellation handling and timeout support
- **Configurable**: YAML-based configuration with environment-specific defaults

#### **Service Integration**
- **Authentication Service**: Retry-aware user authentication and session management
- **User Service**: Retry logic for user CRUD operations
- **Secret Service**: Retry logic for secret management operations
- **Repository Wrappers**: Transparent retry logic for data access layer
- **HTTP Middleware**: Automatic retry of failed HTTP requests

#### **Configuration Example**
```yaml
retry:
  database:
    enabled: true
    max_attempts: 3
    initial_delay: "100ms"
    max_delay: "5s"
    backoff_multiplier: 2.0
    jitter_enabled: true
    retryable_errors:
      - "connection refused"
      - "database is locked"
      - "timeout"
  external_services:
    enabled: true
    max_attempts: 3
    initial_delay: "1s"
    max_delay: "30s"
    backoff_multiplier: 2.0
    jitter_enabled: true
```

#### **Usage Patterns**
```go
// Service layer automatically uses retry
user, err := container.GetUserService().GetUser(ctx, userID)

// Manual retry for custom operations
err := retryService.ExecuteDatabaseOperation(ctx, func() error {
    return db.Query("SELECT * FROM users WHERE id = ?", userID)
})
```

#### **Test Coverage**
- **Integration Tests**: 8 comprehensive test suites with 100% coverage
- **Mock-Based Testing**: testify/mock framework for reliable testing
- **Failure Simulation**: Tests for temporary failures, max attempts, context cancellation
- **Performance Benchmarks**: Included for optimization tracking

#### **Documentation**
No standalone retry docs exist; read `internal/retry/retry.go` (core policy/backoff
logic), `config.go` (YAML config loading), and `middleware.go` (HTTP retry wiring)
directly — they're the source of truth.

**Status**: Production-ready with comprehensive test coverage and enterprise-grade reliability.