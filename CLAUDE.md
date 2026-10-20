# RocketVault - Claude Code Documentation

Self-hosted, open-source alternative to Azure Key Vault, built in Go. One instance hosts any number of named **vaults** (isolated security boundaries with their own secrets, keys, certificates and per-vault Azure-role-parity grants). Every deployment ships with a `default` vault. Interfaces: REST API, Cobra CLI and an MCP server.

**Branch**: `v-4.0.0` (multi-vault + Azure RBAC, ahead of its own tag; latest tag v0.2.1).
**Stack**: Go 1.24.2, Gorilla Mux, SQLite (dev) / PostgreSQL (prod), JWT + TOTP MFA, Cobra.
**Architecture**: domain-driven, fully dependency-injected (`internal/container/service_container.go`). Domain types in `model/`, business logic in `internal/services/`, pure CRUD in `internal/repositories/`, HTTP in `api/` and `internal/middleware/`, CLI in `cmd/`.

## Before you start

- **Knowledge base** (`~/data/rocket/Nl-knowledge-base/rocketvault/`, local only, not in the repo): before implementing in a subsystem read its page (e.g. `internal/services/authorization/` -> `security-auth.md`); before debugging read `known-issues-gotchas.md`. If a page looks stale for HEAD, ask for a `kb-refresh`.
- **Bugs**: `.claude/known-bugs.md` is the only source of truth for bug status. Do not copy bug status here. Every new entry also gets a matching GitHub issue.
- **Design intent**: before brainstorming's architectural path, write `docs/superpowers/intents/YYYY-MM-DD-<topic>.md` (see `.claude/intent-convention.md`).
- **Layer rules**: see the `service-layer-conventions` skill. Services hold business logic, repositories hold data access only (they expect pre-encrypted, pre-hashed data), middleware only handles HTTP concerns and delegates to services.

## Build, test, run

```bash
cp .rocketvault.yaml.example .rocketvault.yaml   # once per clone; replace both GENERATE_WITH placeholders
openssl rand -base64 32                          # value for master_key and bootstrap_token
go run main.go serve                             # run the server
go build ./... && go test ./...                  # build and test (also run before any PR)
go test ./cmd/... -v                             # CLI suite
./scripts/docs.sh build|package|serve            # HTML docs site (scripts/docsgen is its own Go module)
./rocketvault users admin --admin-username=admin --admin-password=<pw> --bootstrap-token=<from .rocketvault.yaml>
```

Lint with `golangci-lint run`. Before any merge or pull request the code must build and lint clean.

## Configuration

- `.rocketvault.yaml` is the **only** config loaded at runtime. It is gitignored; `.rocketvault.yaml.example` is the committed template. Never put a real secret in the `.example` file.
- `master_key` is validated at startup. `jwt.key_source` (default `os_store`) is mandatory: if the signing provider cannot be built, startup fails. `jwt_secret` and `jwt.migration_window` are no longer read.
- JWT is asymmetric-only (RS256/ES256, always a `kid`). There is no HS256 fallback.
- OIDC login is additive and gated by `oidc.enabled` (default `false`, no network call at startup).
- Caches (secrets, keys, vaults) share `internal/cachekit` and the `cache:` config section. The optional L2 tier `cache.rocket_mem.*` fails closed unless TLS and credentials are set.
- `rate_limit.per_vault` is a per-vault token bucket and must stay after `VaultResolutionMiddleware` in `api/api.go`.
- Full config notes and admin setup: `.claude/configuration.md`.

## Authorization invariants

Three tiers. Get these wrong and a command or route silently bypasses authorization.

- **Account roles** (`admin`, `user`, `service_account`): global, used for vault and user management only (`RBACService`).
- **Explicit deny** (`AccessPolicyService`): evaluated before any grant. A global (`vault_id NULL`) `vaults:manage` allow is create-and-list only (v4.6.0). Concrete-vault decisions go through `CheckVaultScopedAccess`.
- **Per-vault Azure roles** (`RoleAssignmentService`, `HasDataAction`): data-plane routes are deny-by-default. Thirteen built-in roles live in `model/azure_roles.go`; only a global admin can grant the two exporter roles.
- **HTTP vault purge** (`DELETE /api/v1/vaults/{vault_name}/purge`) has no admin bypass. The CLI `vaults purge` does (via `CanPurgeVault`). The paths diverge on purpose.
- **Scope**: every repository and service call carries a `model.Scope` (`NewVaultScope`, `NewOwnerScope`, `NewAdminScope`). The zero value is `ScopeInvalid` and fails closed. Composite literals are banned outside `model/scope_test.go` (CI job `scope-gate`).

### CLI authorization

CLI commands call services directly and bypass HTTP middleware, so every command must run its own tier check:

- **Data-plane** (`secrets`, `keys`, `certificates`): `ResolveVaultID` then `vaultcli.RequireDataAction`; add `Session.RequireAlso` for a second object type (certificate create/renew also need `keys/sign`).
- **Vault management** (`vaults`, `vault-access`): package-local `authz.go` helpers on `CanManageVault` / `CanPurgeVault` / `CanManageRoleAssignments`.
- **Provisioning grants** (`vault-provisioning`): `requireGrantAdmin`, global `admin` only and deliberately non-delegable.
- `certificates export` / `keys export` are data-plane operations with no account-role gate. `export open` is a local file decrypt and needs no session.
- A new command that skips its tier's check has no other enforcement point.
- CLI sessions are cached under `~/.rocketvault/sessions/`; `users login` and `users login --oidc` create them.

Full detail, release-note links and the role history: `.claude/service-layer.md`.

## Key and certificate invariants

- Symmetric `oct` keys are HSM-only (`crypto.ErrOctKeysRequireHSM` unless `hsm.enabled: true`).
- `exportable` is immutable on keys and certificates. HSM, `oct` and ES256K keys are never exportable. Export routes use the R6 error body, `Cache-Control: no-store`, and audit every attempt through `exportaudit`.
- Certificates are versioned: `RenewCertificate` goes through `ArchiveAndRenew` in one transaction. `CertificateRepository.Update` writes metadata only, never a body or key.
- Issuing or renewing a certificate needs `keys/sign` as well as `certificates/create`, and refuses a revoked, disabled or out-of-window key.
- Item-backup blobs are sealed (`rvb2.`). A cross-vault restore drops key and CA links that do not resolve there.
- Soft-delete (list, restore, purge) is vault-scoped for secrets, keys and certificates.

## Documents (read on demand)

| Topic | File |
|---|---|
| Directory tree, DI container, code patterns, testing | `.claude/architecture.md` |
| Service layer, authorization, role history | `.claude/service-layer.md` |
| Multi-vault design | `.claude/multi-vault.md` |
| Azure Key Vault parity | `.claude/azure-keyvault-parity.md` |
| Roadmap | `.claude/roadmap-azure-parity-and-beyond.md` |
| Known bugs | `.claude/known-bugs.md` |
| Config and admin setup | `.claude/configuration.md` |
| All other docs (admin manual, API guide, CLI guide, journeys, QA journeybook, MCP, release notes) | `.claude/docs-index.md` |
| Historical sections (Oct 2025 refactor, retry system, doc history) | `.claude/claude-md-archive.md` |
