<img src="docs/assets/rocketvault-lockup.svg" alt="RocketVault" height="64"/>

**RocketVault** is a self-hosted, open-source alternative to [Microsoft Azure Key Vault](https://azure.microsoft.com/en-us/products/key-vault), built entirely in **Go**. It brings virtually all the capabilities of Azure Key Vault — secrets management, cryptographic key operations, X.509 certificate lifecycle management, and multi-vault RBAC — to your own infrastructure, with no cloud dependency required.

A single RocketVault instance hosts any number of named **vaults**, each an isolated security boundary with its own secrets, keys, certificates, and per-vault role assignments — mirroring how Azure Key Vault resources work, but self-hosted. Every deployment ships with a `default` vault so single-vault setups need no extra configuration.

Whether you need to secure application secrets, manage RSA/ECDSA keys, rotate credentials automatically, or issue and renew TLS certificates, RocketVault provides a familiar, Azure Key Vault-compatible workflow through both a **REST API** and a full-featured **CLI**, making it easy to integrate into any environment or automation pipeline.

### Why RocketVault?

| Capability | Azure Key Vault | RocketVault |
|---|---|---|
| Secrets management | ✅ | ✅ |
| Cryptographic keys (RSA, ECDSA, AES) | ✅ | ✅ |
| X.509 certificate management | ✅ | ✅ |
| Soft delete & purge protection | ✅ | ✅ |
| Secret versioning & rollback | ✅ | ✅ |
| Multiple named vaults per instance | ✅ | ✅ |
| Per-vault RBAC (built-in Azure roles) | ✅ | ✅ |
| MFA / TOTP authentication | ✅ | ✅ |
| REST API | ✅ | ✅ |
| CLI interface | ✅ | ✅ |
| HSM / PKCS#11 support | ✅ | ✅ |
| OAuth2 / service accounts | ✅ | ✅ |
| Secret rotation policies | ✅ | ✅ |
| Cloud dependency | ☁️ Required | ❌ None — fully self-hosted |
| Open source | ❌ | ✅ |

**Status**: Actively developed, production-ready core with a domain-driven, fully dependency-injected architecture and an extensive automated test suite (600+ test files).

## Table of Contents

- [Features](#features)
- [Architecture](#architecture)
- [Documentation](#documentation)
- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Building](#building)
- [Quick Start](#quick-start)
- [Usage](#usage)
- [API](#api)
- [Vault Client (Secret Consumption)](#vault-client-secret-consumption)
- [Testing](#testing)
- [Deployment](#deployment)
- [Contributing](#contributing)
- [License](#license)
- [Security](#security)
- [Roadmap](#roadmap)

## Features

### Core Capabilities

- **Secure Storage**: Encrypted storage of secrets, cryptographic keys, and X.509 certificates
- **Multi-Vault Architecture**: Any number of named vaults per instance, each an isolated security boundary; a `default` vault always exists so single-vault use needs no setup
- **Two-Tier RBAC**: JWT authentication with TOTP MFA support, split into global roles and per-vault data-plane roles

  Global roles (`internal/services/authorization/rbac_service.go`) govern user management, vault lifecycle management, and other system-wide actions — **not** secret/key/certificate access:

  | Role                    | Users | Vault mgmt | System |
  |-------------------------|-------|------------|--------|
  | `admin`                 | Full  | Full       | Full   |
  | `secrets_manager`, `crypto_manager`, `certificate_manager` | -     | -          | -      |
  | `user`                  | Read own | -       | -      |
  | `service_account`       | -     | -          | -      |

  Access to secrets, keys, and certificates is granted per vault via built-in Azure Key Vault-parity roles (see [Per-Vault RBAC](#per-vault-rbac-azure-key-vault-parity) below) — a principal with no role assignment in a vault is denied by default, regardless of their global role.
- **Secret Rotation**: Automated and manual secret rotation with customizable policies
- **Version Control**: Complete version history for secrets and keys with rollback capabilities
- **Soft Delete & Purge Protection**: Recoverable deletion with configurable retention and purge protection
- **Per-Item Backup & Restore**: Individual backup and restore for secrets, keys, and certificates
- **Backup & Recovery**: Encrypted database backups with restore functionality
- **Health Monitoring**: Comprehensive system health metrics and monitoring
- **REST API**: Full RESTful API with OpenAPI/Swagger documentation
- **CLI Interface**: Complete command-line interface for all operations
- **MCP server**: expose the vault to Claude Code or Claude Desktop with
  `rocketvault mcp`. Read-only by default, with independently gated tiers for
  writes, destructive operations, crypto and secret values. See
  [the MCP server guide](docs/mcp-server.md).
- **Multi-Database Support**: SQLite (development) and PostgreSQL (production)
- **Cryptographic Operations**: RSA (2048/3072/4096-bit), ECDSA, AES key generation and management
- **Key Crypto Operations**: Sign, verify, encrypt, decrypt, wrap, and unwrap via HTTP API
- **Certificate Policies**: Configurable renewal and issuance policies per certificate
- **Audit Logging**: Comprehensive audit trails persisted to database and log files
- **OAuth2 / Service Accounts**: Machine-to-machine authentication via client credentials grant
- **JWKS Endpoint**: Public key discovery at `/jwks.json` for JWT verification
- **HSM / PKCS#11 Support**: Optional hardware security module integration via SoftHSM2 or real HSM
- **Secret Consumption (Vault Client)**: Built-in client for consuming secrets from a RocketVault instance
- **Frontend Config Endpoint**: `GET /api/v1/config` exposes public configuration to frontend clients

### Per-Vault RBAC (Azure Key Vault Parity)

Data-plane access — reading or writing secrets, keys, and certificates — is authorized exclusively by role assignments scoped to a single vault, matching Azure Key Vault's built-in roles. There is no global "can read all secrets" role; a principal must be granted a role in each vault it needs to access. A newly created vault starts with **no** role assignments — even an admin must grant themselves access before using it.

| Role | Grants |
|---|---|
| `Key Vault Administrator` | All data-plane operations on all object types |
| `Key Vault Reader` | Metadata only — no secret values or key material |
| `Key Vault Secrets User` | Get and list secrets, including values |
| `Key Vault Secrets Officer` | Full secret control |
| `Key Vault Crypto User` | Use key material: encrypt, decrypt, sign, verify, wrap, unwrap — plus routine key maintenance: update and backup |
| `Key Vault Crypto Officer` | Full key control, including create, import, delete, and rotation |
| `Key Vault Certificates Officer` | Full certificate control; issuing or renewing also needs a role with keys/sign, such as Key Vault Crypto User |

Grant a role with the CLI:

```bash
rocketvault --username admin --password admin123 --totp-code <code> \
  vault-access grant alice --role "Key Vault Secrets User" --vault prod
```

or the API:

```bash
curl -X POST https://host/api/v1/vaults/prod/role-assignments \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"principal":"alice","role":"Key Vault Secrets User"}'
```

**Two behaviors worth knowing before you rely on this:**

- A caller who holds a role in a vault can see and act on **every** object in it — access is per vault, not per object owner. Anyone who created secrets under the pre-4.0.0 ownership model should review `rocketvault vaults preview-migration` before upgrading.
- Requesting an object outside the caller's authorized vault returns `404 Not Found`, not `403 Forbidden` — the two are indistinguishable by design so a 403 can't be used to probe for a resource's existence. `403` is reserved for an authenticated caller with no role granting the required action in that vault.

Full details, upgrade steps, and known limitations: [`docs/release-notes/v4.0.0-azure-rbac.md`](docs/release-notes/v4.0.0-azure-rbac.md) and [`.claude/multi-vault.md`](.claude/multi-vault.md).

### Enterprise-Grade Architecture

- **Domain-Driven Design**: Clean architecture with complete separation of concerns
- **Service Layer Pattern**: 15+ focused services with single responsibilities
- **Dependency Injection**: Complete service container with lifecycle management
- **Zero Code Duplication**: Eliminated through proper architectural patterns
- **Pure Repository Pattern**: Data access layer with no business logic
- **Performance Optimizations**: Connection pooling, strategic indexing (90%+ improvement)
- **Key Crypto Cache**: In-process decrypted key cache eliminates DB + AES-GCM + PEM-parse overhead on hot crypto paths
- **Prometheus Metrics**: `rocketvault_crypto_op_duration_seconds` histogram with `op`, `key_type`, and `cache_hit` labels for p50/p95/p99 observability
- **Comprehensive Testing**: 600+ test files covering CLI, API, services, repositories, and authorization; run `go test ./... -cover` for current coverage numbers
- **Graceful Error Handling**: Automatic directory creation, fallback mechanisms, no crashes on config issues
- **Retry System**: Exponential backoff with jitter, circuit breaker, and configurable policies

## Architecture

### Domain-Driven Design Structure

```
rocketvault/
├── cmd/                    # CLI commands (Cobra framework)
│   ├── vaults/             # Vault lifecycle commands (create, list, delete, ...)
│   ├── vault-access/       # Per-vault role assignment commands (grant, list, revoke, roles)
│   ├── certificates/       # Certificate management commands
│   ├── keys/                # Key management commands
│   ├── secrets/            # Secret management commands
│   └── users/               # User management commands
├── api/                    # HTTP API layer with service integration
├── app/                    # Application core and options
├── bootstrap/              # Application initialization (SRP-compliant)
├── model/                  # Pure domain types (DDD): user, secret, key, certificate, vault, scope, azure roles
├── examples/
│   └── consumer-service/  # Example app that fetches secrets from RocketVault
├── internal/
│   ├── services/          # Business logic (15+ services)
│   │   ├── auth/          # Authentication (JWT, TOTP, Password)
│   │   ├── users/         # User management
│   │   ├── secrets/       # Secret operations
│   │   ├── keys/          # Key management
│   │   ├── certificates/  # Certificate management
│   │   ├── vaults/        # Vault lifecycle and cascade soft-delete/recover
│   │   └── authorization/ # RBACService (global roles), AccessPolicyService (deny overrides),
│   │                      # RoleAssignmentService (per-vault Azure role grants + HasDataAction)
│   ├── repositories/      # Pure data access (no business logic)
│   ├── container/         # Dependency injection container
│   ├── middleware/        # HTTP middleware (SRP-compliant), incl. VaultResolutionMiddleware
│   ├── crypto/            # Cryptographic helpers (key_crypto, x509_helper)
│   ├── logging/           # Structured logging with audit persistence
│   └── retry/             # Retry logic with exponential backoff
└── config/                # Configuration management
```

### Service Layer Architecture

**Authentication Services** (`internal/services/auth/`):

- `PasswordService` — Password hashing and validation
- `TOTPService` — TOTP generation and validation
- `JWTService` — JWT token management (asymmetric signing, JWKS rotation)
- `AuthenticationService` — Complete auth workflow orchestration

**Secret Management** (`internal/services/secrets/`):

- `SecretService` — Secret operations orchestration
- `CryptographyService` — Encryption/decryption
- `VersioningService` — Version management
- `TagService` — Tag operations

**Key & Certificate Management**:

- `KeyService` — RSA/ECDSA key lifecycle, wrap/unwrap, sign/verify, encrypt/decrypt
- `CertificateService` — X.509 certificate management with policy support

**Vault Management** (`internal/services/vaults/`):

- `VaultService` — Vault lifecycle (create, update, soft-delete, purge, recover)

**User & Authorization** (`internal/services/authorization/`):

- `UserService` — User management workflows
- `RBACService` — Global roles for user and vault management only; does not gate secret/key/certificate access
- `AccessPolicyService` — Explicit-deny override, evaluated before role grants
- `RoleAssignmentService` — Per-vault Azure role grants and the `HasDataAction` authorization decision that gates every vault data-plane route

### Key Architectural Achievements

- Complete SRP compliance across all components
- Zero code duplication through proper patterns
- Full dependency injection (no global state)
- Pure repository pattern implementation
- Enterprise-grade performance optimizations

## Documentation

### Core Documentation

- [Getting Started — Pick Your Path](docs/getting-started.md) - Which of the 9 ways to use RocketVault fits your use case
- [Vault, User & Access Journeys](docs/VAULT_USER_ACCESS_JOURNEYS_v3.md) - 21 end-to-end scenarios by role, with the real CLI commands for each
- [API Specification (OpenAPI/Swagger)](docs/api-specification.yaml) - Complete OpenAPI 3.0 specification
- [API Developer Guide](docs/api-developer-guide.md) - Comprehensive guide for developers
- [Integration Examples](docs/integration-examples.md) - Real-world integration examples
- [CLI Documentation](doc/cli.markdown) - Command-line interface guide
- [Architecture Documentation](doc/architecture.markdown) - System architecture overview
- [Security Documentation](doc/security.markdown) - Security features and best practices
- [Configuration Guide](doc/configuration.markdown) - Configuration options and setup
- [Setup Guide](doc/setup.md) - Installation and setup instructions
- [Troubleshooting Guide](doc/troubleshooting.markdown) - Common issues and solutions
- [Testing Guide](docs/testing-guide.md) - Testing procedures and guidelines
- [HSM / SoftHSM2 Testing Guide](docs/hsm-softhsm2-testing.md) - HSM setup and testing with SoftHSM2
- [CLI Usage Guide](docs/cli-guide.md) - Step-by-step CLI walkthrough, first-time setup to everyday use

### Multi-Vault & Authorization Documentation

- [Multi-Vault Architecture](.claude/multi-vault.md) - Vault as a routing/context-scoping layer, migration, and known deferrals
- [Azure Key Vault RBAC Parity](.claude/azure-keyvault-parity.md) - Feature-by-feature parity comparison with Azure Key Vault
- [v4.0.0 Azure RBAC Release Notes](docs/release-notes/v4.0.0-azure-rbac.md) - Breaking changes, role table, and upgrade procedure
- [Vault-Scoped Users Manual Test Guide](.claude/manual-test-vault-scoped-users.md) - End-to-end manual verification steps
- [Vault, User & Access Journeys](docs/VAULT_USER_ACCESS_JOURNEYS_v3.md) - How the roles above behave in practice: onboarding, delegation, emergency deny, offboarding, and the CLI/HTTP divergences

### Additional Resources

- [API Documentation Validation](validate-api-docs.sh) - Documentation validation script
- [Known Bugs](.claude/known-bugs.md) - Open issues with root-cause analysis
- [Roadmap — Azure Parity & Beyond](.claude/roadmap-azure-parity-and-beyond.md) - Phased plan to close remaining Azure Key Vault gaps and build self-hosted-native differentiators

## Quick Install (Prebuilt Binary)

The fastest way to get `rocketvault` on Linux or macOS — installs to
`/usr/local/bin` by default:

```bash
curl -fsSL https://raw.githubusercontent.com/Snehal1112/rocketvault/v-4.0.0/install.sh | bash
```

> **macOS note:** downloading a release binary directly from the GitHub
> Releases page in a browser triggers Gatekeeper's "Apple could not verify
> ... is free of malware" warning — this is macOS quarantining any
> browser-downloaded, unsigned executable, not a problem with the binary
> itself. `install.sh` downloads via `curl` instead, which macOS does not
> quarantine, so the installed binary runs immediately with no extra steps.
> If you still hit the Gatekeeper dialog (e.g. you downloaded the archive
> manually), clear it with `xattr -d com.apple.quarantine <path-to-binary>`
> or System Settings → Privacy & Security → "Open Anyway".

Options:

```bash
curl -fsSL .../install.sh | VERSION=v0.2.5 bash            # install a specific tag
curl -fsSL .../install.sh | INSTALL_DIR=~/.local/bin bash  # install elsewhere
```

Run `./install.sh --help` (or `curl -fsSL .../install.sh | bash -s -- --help`)
for the full list of environment variables, flags, and examples.

Windows users: download the `.zip` asset for your platform from the
[Releases page](https://github.com/Snehal1112/rocketvault/releases).

## Prerequisites

- Go 1.25.0 or higher
- GCC / build-essential (required for CGO — SQLite3 and PKCS#11 bindings)
- SQLite 3 (for development) or PostgreSQL 13+ (for production)
- Git

### Optional: HSM / PKCS#11 Support

To use the HSM code path (software or hardware), install the PKCS#11 library before building:

```bash
# Ubuntu / Debian
sudo apt install softhsm2 opensc libsofthsm2

# Verify the library path
ls /usr/lib/softhsm/libsofthsm2.so
```

```bash
# macOS (Homebrew)
brew install softhsm opensc

# Locate the library path — Homebrew keeps the .so extension on macOS too
find "$(brew --prefix)/Cellar/softhsm" -name "libsofthsm2.so"
```

Then initialise a SoftHSM2 token (one-time setup):

```bash
mkdir -p ~/.config/softhsm2/tokens
cat > ~/.config/softhsm2/softhsm2.conf <<EOF
directories.tokendir = $HOME/.config/softhsm2/tokens/
objectstore.backend = file
log.level = INFO
EOF

echo 'export SOFTHSM2_CONF=~/.config/softhsm2/softhsm2.conf' >> ~/.zshrc
export SOFTHSM2_CONF=~/.config/softhsm2/softhsm2.conf

softhsm2-util --init-token --slot 0 --label rocketvault --so-pin 0000 --pin 1234
```

Enable HSM in `.rocketvault.yaml`, using the library path found above
(Ubuntu: `/usr/lib/softhsm/libsofthsm2.so`; macOS: the `Cellar` path from
`find` above, e.g. `/opt/homebrew/Cellar/softhsm/2.6.1/lib/softhsm/libsofthsm2.so`
on Apple Silicon or `/usr/local/Cellar/...` on Intel):

```yaml
hsm:
  enabled: true
  lib_path: /usr/lib/softhsm/libsofthsm2.so
  token_label: rocketvault
  pin: "1234"
```

See [HSM / SoftHSM2 Testing Guide](docs/hsm-softhsm2-testing.md) for the full walkthrough.

## Installation

1. Clone the repository:

   ```bash
   git clone https://github.com/Snehal1112/rocketvault.git
   cd rocketvault
   ```

2. Install system dependencies:

   ```bash
   # Ubuntu / Debian
   sudo apt install build-essential libsqlite3-dev

   # macOS
   xcode-select --install
   ```

3. Install Go dependencies:

   ```bash
   go mod tidy
   ```

4. Build the application:

   ```bash
   go build -o rocketvault .
   ```

## Building

The project includes a comprehensive build script following 2025 Go best practices.

### Quick Build

For development, use the build script for optimized binaries with embedded version information:

```bash
# Build for current platform
./build.sh

# Output: ./build/rocketvault
```

### Build Options

```bash
# Display build information
./build.sh --info

# Build for all platforms (cross-compilation)
./build.sh --all

# Create production release (tests + all platforms + checksums)
./build.sh --release

# Clean build artifacts
./build.sh --clean

# Run tests only
./build.sh --test

# Verify environment and dependencies
./build.sh --verify-only

# Skip tests during build
./build.sh --skip-tests
```

### Build Features

**Modern Go Optimizations**:

- **Version Injection**: Automatically embeds git version, commit hash, build time, and Go version
- **Binary Optimization**: Uses `-trimpath`, `-s`, and `-w` flags for smaller, reproducible builds
- **CGO Support**: Enabled for SQLite3 and PKCS#11 (miekg/pkcs11) compatibility
- **Race Detection**: Runs tests with `-race` flag for concurrency safety
- **Dependency Verification**: Validates `go.mod` integrity before building

**Cross-Platform Compilation**:
The build script supports 4 platform targets:

- Linux (amd64, arm64)
- macOS (arm64/Apple Silicon)
- Windows (amd64)

**Security & Verification**:

- SHA256 checksums for all binaries
- Automated dependency verification
- Test execution before release builds
- Archive creation (`.tar.gz` for Unix, `.zip` for Windows)

### Build Output

```
build/
└── rocketvault              # Current platform binary

dist/                             # Cross-platform builds (--all, --release)
├── rocketvault-v4.0.0-linux-amd64.tar.gz
├── rocketvault-v4.0.0-linux-amd64.tar.gz.sha256
├── rocketvault-v4.0.0-darwin-arm64.tar.gz
├── rocketvault-v4.0.0-darwin-arm64.tar.gz.sha256
├── rocketvault-v4.0.0-windows-amd64.zip
├── rocketvault-v4.0.0-windows-amd64.zip.sha256
└── RELEASE_NOTES.md              # Generated release documentation
```

### Environment Variables

Customize the build with environment variables:

```bash
# Override version
VERSION=v5.0.0 ./build.sh

# Custom commit hash
COMMIT_HASH=abc123 ./build.sh --release

# Combined
VERSION=v5.0.0 COMMIT_HASH=abc123 ./build.sh --all
```

### Manual Build

If you prefer building manually without the script:

```bash
# Basic build
go build -o rocketvault .

# Optimized build with version injection
go build \
  -trimpath \
  -ldflags="-s -w -X 'main.Version=v1.0.0' -X 'main.CommitHash=$(git rev-parse --short HEAD)'" \
  -o rocketvault \
  .
```

### Build Requirements

- **Go**: 1.25.0 or higher (verified automatically by build script)
- **Git**: For version tagging and commit hash extraction
- **GCC/Build Tools**: Required for CGO (SQLite3 and PKCS#11 support)
- **Disk Space**: ~50MB for single build, ~200MB for all platforms

### Troubleshooting Build Issues

**CGO Errors**:

```bash
# Install build essentials on Linux
sudo apt-get install build-essential libsqlite3-dev

# Install on macOS
xcode-select --install
```

**PKCS#11 linker errors** (miekg/pkcs11):

```bash
# Ensure libdl is available (usually bundled with libc on Linux)
sudo apt-get install libc6-dev
```

**Cross-Compilation Issues**:
Cross-compiling with CGO requires appropriate cross-compilers. For most use cases, build on the target platform or use the `--current` flag.

**Permission Errors**:

```bash
# Make script executable
chmod +x build.sh
```

## Quick Start

### 1. Create Initial Admin User

Create the first admin user using the bootstrap token:

```bash
# Initial admin setup (requires bootstrap token from config)
./rocketvault users admin --admin-username admin --admin-password admin123 --bootstrap-token <your-bootstrap-token>
```

The bootstrap token must be configured in your `.rocketvault.yaml` file.

### 2. Configure Your TOTP Authenticator

After creating an admin user, configure the TOTP secret in your authenticator app (Google Authenticator, Authy, etc.) using the secret provided during user creation.

### 3. Start the API Server

```bash
./rocketvault serve
```

By default the server listens on `:8774`. Override with `server.listen_addr` in `.rocketvault.yaml` or `--listen` flag.

### 4. Create Your First Secret

```bash
./rocketvault --username admin --password admin123 --totp-code <your-totp-code> \
  secrets create "database-password" "my-secret-password"
```

### 5. List Your Secrets

```bash
./rocketvault --username admin --password admin123 --totp-code <your-totp-code> \
  secrets list
```

## Usage

### Authentication

All commands require authentication with username, password, and TOTP code:

```bash
./rocketvault --username <username> --password <password> --totp-code <code> <command>
```

Every command exits `1` on failure and `0` on success, so it's safe to chain with `&&` or run under `set -e` in scripts and CI.

### Output Formats

All list and get commands support a global `--output` flag:

```bash
# Default human-readable table
./rocketvault --username admin --password admin123 --totp-code <code> secrets list

# JSON (suitable for scripting / jq)
./rocketvault --username admin --password admin123 --totp-code <code> --output json secrets list

# YAML
./rocketvault --username admin --password admin123 --totp-code <code> --output yaml keys list
```

### User Management

```bash
# Create a new user
./rocketvault --username admin --password admin123 --totp-code <code> \
  users create --new-username john --new-password pass123 --new-role secrets_manager

# Create a user with more than one role -- repeat --new-role for each one
./rocketvault --username admin --password admin123 --totp-code <code> \
  users create --new-username jane --new-password pass123 \
  --new-role admin --new-role secrets_manager

# List all users
./rocketvault --username admin --password admin123 --totp-code <code> \
  users list

# Update user (requires user ID as argument)
./rocketvault --username admin --password admin123 --totp-code <code> \
  # Valid roles: admin, secrets_manager, crypto_manager, certificate_manager, user
  users update <user-id> --new-username john2 --new-password newpass123 --new-role admin

# Get specific user
./rocketvault --username admin --password admin123 --totp-code <code> \
  users get <user-id>

# Delete user
./rocketvault --username admin --password admin123 --totp-code <code> \
  users delete <user-id>
```

### Vault Management

```bash
# Create a vault
./rocketvault --username admin --password admin123 --totp-code <code> \
  vaults create prod --purge-protection --retention-days 30

# List vaults (add --include-deleted to see soft-deleted ones)
./rocketvault --username admin --password admin123 --totp-code <code> \
  vaults list

# Get, update, or delete a vault
./rocketvault --username admin --password admin123 --totp-code <code> vaults get prod
./rocketvault --username admin --password admin123 --totp-code <code> vaults update prod --enabled=false
./rocketvault --username admin --password admin123 --totp-code <code> vaults delete prod

# Preview the one-time Azure-role backfill before upgrading from a pre-4.0.0 database
./rocketvault vaults preview-migration
```

### Vault Access (Role Assignments)

A vault has no data-plane role assignments when it's created — grant one before secrets, keys, or certificates in it are usable:

```bash
# Grant a built-in Azure role to a user in a vault
./rocketvault --username admin --password admin123 --totp-code <code> \
  vault-access grant alice --role "Key Vault Secrets Officer" --vault prod

# Grant a role to a service account instead of a user
./rocketvault --username admin --password admin123 --totp-code <code> \
  vault-access grant my-service-account --principal-type service_account --role "Key Vault Secrets User" --vault prod

# List role assignments in a vault
./rocketvault --username admin --password admin123 --totp-code <code> \
  vault-access list --vault prod

# Revoke a role assignment (by assignment ID)
./rocketvault --username admin --password admin123 --totp-code <code> \
  vault-access revoke <assignment-id> --vault prod

# List all available built-in roles and their data actions (no auth required)
./rocketvault vault-access roles
```

`--vault` resolves in this order: the flag, the `ROCKETVAULT_VAULT` environment variable, the `vault` key in `.rocketvault.yaml`, then falls back to `default`. See [Per-Vault RBAC](#per-vault-rbac-azure-key-vault-parity) for the full role list.

### Secret Management

`secrets create`, `list`, `get`, `delete`, `update`, `export`, and `import` accept `--vault <name>` (defaulting the same way as above) to target a specific vault. The `--vault` flag is defined globally, so it's accepted without error on `keys` and `certificates` commands too, but those still operate on the `default` vault only — the flag is silently ignored there today.

```bash
# Create a secret (name and value as positional arguments)
./rocketvault --username admin --password admin123 --totp-code <code> \
  secrets create "api-key" "secret-api-key-value"

# Create a secret with content type and tags
./rocketvault --username admin --password admin123 --totp-code <code> \
  secrets create "api-key" "secret-api-key-value" --content-type "text/plain" --tags "production,api"

# List secrets
./rocketvault --username admin --password admin123 --totp-code <code> \
  secrets list

# Get a specific secret (by secret ID)
./rocketvault --username admin --password admin123 --totp-code <code> \
  secrets get <secret-id>

# Delete a secret (by secret ID)
./rocketvault --username admin --password admin123 --totp-code <code> \
  secrets delete <secret-id>
```

### Key Management

```bash
# Generate an RSA key pair (2048, 3072, or 4096 bits)
./rocketvault --username admin --password admin123 --totp-code <code> \
  keys create --name "my-rsa-key" --type rsa --bits 2048

# Generate an ECDSA key pair
./rocketvault --username admin --password admin123 --totp-code <code> \
  keys create --name "my-ecdsa-key" --type ecdsa --curve P-256

# List keys
./rocketvault --username admin --password admin123 --totp-code <code> \
  keys list

# Get a specific key (by key ID) — response includes JWK public material
./rocketvault --username admin --password admin123 --totp-code <code> \
  keys get <key-id>

# Rotate a key (by key ID)
./rocketvault --username admin --password admin123 --totp-code <code> \
  keys rotate <key-id>

# Export an exportable key's private key to a sealed file
./rocketvault --username admin --password admin123 --totp-code <code> \
  keys export <key-id> --file signer.pem.sealed

# Delete a key (by key ID)
./rocketvault --username admin --password admin123 --totp-code <code> \
  keys delete <key-id>
```

### Certificate Management

```bash
# Create a self-signed certificate
./rocketvault --username admin --password admin123 --totp-code <code> \
  certificate create --name "my-cert" --key-id <key-id> --validity-days 365

# Export an exportable certificate and its key, then open the sealed file
./rocketvault --username admin --password admin123 --totp-code <code> \
  certificate export <certificate-id> --file client.pem.sealed
./rocketvault export open client.pem.sealed --file client.pem

# Get/update certificate policy (renewal rules)
# Use the REST API: GET/PUT /api/v1/certificates/{id}/policy
```

### Secret Rotation

```bash
# Create a rotation policy
./rocketvault --username admin --password admin123 --totp-code <code> \
  secrets rotation create --name "monthly-rotation" --interval 30 --reminder 7

# Assign policy to a secret
./rocketvault --username admin --password admin123 --totp-code <code> \
  secrets rotation assign --policy-id <policy-id> --secret-id <secret-id>

# Check rotation status
./rocketvault --username admin --password admin123 --totp-code <code> \
  secrets rotation status
```

### Backup and Restore

```bash
# Create an encrypted backup (default)
./rocketvault --username admin --password admin123 --totp-code <code> \
  backup create --file ./backup-2024.backup

# Create an unencrypted backup (use --encrypt=false)
./rocketvault --username admin --password admin123 --totp-code <code> \
  backup create --file ./backup-2024.backup --encrypt=false

# List available backups
./rocketvault --username admin --password admin123 --totp-code <code> \
  backup list --dir ./backups

# Restore from encrypted backup (default)
./rocketvault --username admin --password admin123 --totp-code <code> \
  backup restore --file ./backup-2024.backup

# Restore from unencrypted backup (use --decrypt=false)
./rocketvault --username admin --password admin123 --totp-code <code> \
  backup restore --file ./backup-2024.backup --decrypt=false
```

**Note**: Backups are encrypted by default. Use `--encrypt=false` (with equals sign) to create unencrypted backups. The `./backups` directory is automatically created if it doesn't exist.

### Master Key Rotation

Re-encrypts every secret, key, and certificate sealed under the current `master_key` onto a new one. CLI-only (no HTTP route), admin-only, and an **offline** maintenance operation — stop the server first and back up the database before running it for real. The new key is always supplied via an environment variable, never as a literal flag value.

```bash
# Preview what would change, write nothing
NEW_MASTER_KEY=$(openssl rand -base64 32) \
  ./rocketvault --username admin --password admin123 --totp-code <code> \
  master-key rotate --new-key-env NEW_MASTER_KEY --dry-run

# Perform the rotation (prompts for interactive "yes" confirmation)
NEW_MASTER_KEY=$(openssl rand -base64 32) \
  ./rocketvault --username admin --password admin123 --totp-code <code> \
  master-key rotate --new-key-env NEW_MASTER_KEY

# Non-interactive (e.g. scripted/CI), with a custom batch size
NEW_MASTER_KEY=$(openssl rand -base64 32) \
  ./rocketvault --username admin --password admin123 --totp-code <code> \
  master-key rotate --new-key-env NEW_MASTER_KEY --yes --batch-size 500
```

The rotation is resumable — already-migrated rows are skipped, so it's safe to re-run after an interruption. `--old-key-env` overrides which environment variable holds the *current* key (defaults to the `master_key` value from `.rocketvault.yaml`). Backups created under the old key are unaffected and remain restorable only with that old key. RocketVault also refuses to boot if `master_key` is invalid or matches a known-compromised default, so a stalled rotation can't leave the server running on a bad key. Full procedure: [`docs/runbooks/master-key-rotation.md`](docs/runbooks/master-key-rotation.md).

### System Health

```bash
# Check system health
./rocketvault health
```

This displays comprehensive metrics including memory usage, CPU statistics, database connections, and query performance.

### Version History

```bash
# List versions of a secret
./rocketvault --username admin --password admin123 --totp-code <code> \
  secrets version list --secret-id <secret-id>

# Get a specific version
./rocketvault --username admin --password admin123 --totp-code <code> \
  secrets version get --secret-id <secret-id> --version 2
```

## API

### Starting the API Server

```bash
./rocketvault serve
```

Default listen address is `:8774`. Configure in `.rocketvault.yaml` under `server.listen_addr`.

### Public Endpoints (no authentication required)

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/api/v1/oauth2/token` | OAuth2 client credentials token grant |
| `GET` | `/jwks.json` | JWKS public key set for JWT verification |
| `GET` | `/api/v1/config` | Frontend-facing public configuration |

### Health Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/v1/health` | Comprehensive system health metrics |
| `GET` | `/api/v1/health/ready` | Readiness check |
| `GET` | `/api/v1/health/live` | Liveness check |
| `GET` | `/api/v1/health/database` | Database performance metrics |

### Authenticated API Endpoints

All endpoints below require `Authorization: Bearer <jwt-token>`.

#### Vaults

All routes below (including `GET`) require the global `admin` role — there is currently no way for a non-admin to even list vaults via the API.

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/api/v1/vaults` | Create vault |
| `GET` | `/api/v1/vaults` | List vaults (`?include_deleted=true` to include soft-deleted) |
| `GET` | `/api/v1/vaults/{name}` | Get vault |
| `PATCH` | `/api/v1/vaults/{name}` | Update vault (enabled, purge protection, retention) |
| `DELETE` | `/api/v1/vaults/{name}` | Soft-delete vault |

`purge` and `recover` for vaults are CLI-only (`vaults purge` / `vaults recover`) — there is no HTTP route for them yet.

#### Vault Role Assignments

All routes below, including `GET`, currently require the global `admin` role too (see [known limitation](docs/release-notes/v4.0.0-azure-rbac.md#known-limitations) — a non-admin with only per-vault `vaults:manage` cannot yet manage or list a vault's role assignments through the API).

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/v1/vaults/{vault_name}/role-assignments` | List role assignments in a vault |
| `POST` | `/api/v1/vaults/{vault_name}/role-assignments` | Grant a built-in Azure role to a user or service account |
| `GET` | `/api/v1/vaults/{vault_name}/role-assignments/{id}` | Get a role assignment |
| `DELETE` | `/api/v1/vaults/{vault_name}/role-assignments/{id}` | Revoke a role assignment |

#### Secrets, Keys, and Certificates

Every route in the three tables below is registered twice: as shown (operating on the `default` vault), and again under `/api/v1/vaults/{vault_name}/...` (e.g. `/api/v1/vaults/prod/secrets`) operating on the named vault. Both forms call the identical handler — only the resolved vault differs. New integrations that need more than the default vault should address resources through the `/vaults/{vault_name}/...` form.

##### Secrets

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/v1/secrets` | List secrets |
| `POST` | `/api/v1/secrets` | Create secret |
| `GET` | `/api/v1/secrets/{id}` | Get secret |
| `PUT` | `/api/v1/secrets/{id}` | Update secret |
| `DELETE` | `/api/v1/secrets/{id}` | Soft-delete secret |
| `POST` | `/api/v1/secrets/generate` | Generate a random secret |
| `POST` | `/api/v1/secrets/export` | Export secrets |
| `POST` | `/api/v1/secrets/import` | Import secrets |
| `GET` | `/api/v1/secrets/{id}/versions` | List versions |
| `GET` | `/api/v1/secrets/{id}/versions/{n}` | Get specific version |
| `GET` | `/api/v1/secrets/{id}/versions/latest` | Get latest version |
| `POST` | `/api/v1/secrets/{id}/backup` | Per-item backup |
| `POST` | `/api/v1/secrets/restore` | Per-item restore |

##### Keys

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/v1/keys` | List keys |
| `POST` | `/api/v1/keys` | Create key |
| `GET` | `/api/v1/keys/{id}` | Get key (includes JWK public material) |
| `PUT` | `/api/v1/keys/{id}` | Update key |
| `DELETE` | `/api/v1/keys/{id}` | Soft-delete key |
| `POST` | `/api/v1/keys/{id}/rotate` | Rotate key |
| `GET` | `/api/v1/keys/{id}/versions` | List key versions |
| `POST` | `/api/v1/keys/{id}/wrap` | Wrap (encrypt) a key |
| `POST` | `/api/v1/keys/{id}/unwrap` | Unwrap (decrypt) a key |
| `POST` | `/api/v1/keys/{id}/sign` | Sign data |
| `POST` | `/api/v1/keys/{id}/verify` | Verify a signature |
| `POST` | `/api/v1/keys/{id}/encrypt` | Encrypt data |
| `POST` | `/api/v1/keys/{id}/decrypt` | Decrypt data |
| `POST` | `/api/v1/keys/{id}/backup` | Per-item backup |
| `POST` | `/api/v1/keys/restore` | Per-item restore |

##### Certificates

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/v1/certificates` | List certificates |
| `POST` | `/api/v1/certificates` | Create certificate |
| `GET` | `/api/v1/certificates/{id}` | Get certificate |
| `PUT` | `/api/v1/certificates/{id}` | Update certificate |
| `DELETE` | `/api/v1/certificates/{id}` | Soft-delete certificate |
| `GET` | `/api/v1/certificates/{id}/policy` | Get certificate policy |
| `PUT` | `/api/v1/certificates/{id}/policy` | Upsert certificate policy |
| `DELETE` | `/api/v1/certificates/{id}/policy` | Delete certificate policy |
| `POST` | `/api/v1/certificates/{id}/backup` | Per-item backup |
| `POST` | `/api/v1/certificates/restore` | Per-item restore |

#### Soft-Deleted Items

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/v1/deleted/secrets` | List deleted secrets |
| `POST` | `/api/v1/deleted/secrets/{id}/restore` | Recover deleted secret |
| `DELETE` | `/api/v1/deleted/secrets/{id}/purge` | Permanently purge secret |
| `GET` | `/api/v1/deleted/keys` | List deleted keys |
| `GET` | `/api/v1/deleted/keys/{id}` | Get a specific deleted key |
| `POST` | `/api/v1/deleted/keys/{id}/restore` | Recover deleted key |
| `DELETE` | `/api/v1/deleted/keys/{id}/purge` | Permanently purge key |
| `GET` | `/api/v1/deleted/certificates` | List deleted certificates |
| `POST` | `/api/v1/deleted/certificates/{id}/restore` | Recover deleted certificate |
| `DELETE` | `/api/v1/deleted/certificates/{id}/purge` | Permanently purge certificate |

Only the deleted-secrets routes (list, restore, purge) are also vault-scoped, at `/api/v1/vaults/{vault_name}/deleted/secrets[/{id}/restore|/purge]`. The deleted-keys and deleted-certificates routes above operate on the `default` vault only; they don't yet have a `/vaults/{vault_name}/...` equivalent.

#### Users & Sessions

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/api/v1/users/login` | Login (returns JWT) |
| `POST` | `/api/v1/users/refresh` | Refresh JWT token |
| `GET` | `/api/v1/users/sessions` | List active sessions |
| `DELETE` | `/api/v1/users/sessions/{id}` | Revoke a session |
| `DELETE` | `/api/v1/users/sessions` | Revoke all sessions |
| `GET` | `/api/v1/users` | List users |
| `POST` | `/api/v1/users` | Create user |
| `GET` | `/api/v1/users/{id}` | Get user |
| `PUT` | `/api/v1/users/{id}` | Update user |
| `DELETE` | `/api/v1/users/{id}` | Delete user |

#### Access Policies & Service Accounts

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/v1/access-policies` | List access policies |
| `POST` | `/api/v1/access-policies` | Create access policy |
| `GET` | `/api/v1/access-policies/{id}` | Get access policy |
| `PUT` | `/api/v1/access-policies/{id}` | Update access policy |
| `DELETE` | `/api/v1/access-policies/{id}` | Delete access policy |
| `GET` | `/api/v1/access-policies/principal/{id}` | List policies for a principal |
| `GET` | `/api/v1/service-accounts` | List service accounts |
| `POST` | `/api/v1/service-accounts` | Create service account |
| `GET` | `/api/v1/service-accounts/{id}` | Get service account |
| `DELETE` | `/api/v1/service-accounts/{id}` | Delete service account |
| `POST` | `/api/v1/service-accounts/{id}/rotate` | Rotate service account secret |

### Authentication

All protected API endpoints require JWT authentication:

```
Authorization: Bearer <your-jwt-token>
```

Tokens are obtained via `POST /api/v1/users/login` (human users) or `POST /api/v1/oauth2/token` (service accounts / machine-to-machine).

### API Documentation

Complete API documentation is available at:

- [OpenAPI Specification](docs/api-specification.yaml)
- [API Developer Guide](docs/api-developer-guide.md)

## Vault Client (Secret Consumption)

Other applications can fetch secrets from a running RocketVault instance using the built-in vault client or the example consumer service.

### Example Consumer Service

An example Go service is provided in `examples/consumer-service/`. It demonstrates how to authenticate as a service account, fetch secrets, and inject them into application config.

```bash
cd examples/consumer-service
# Configure vault URL and client_id in config.yaml, then:
VAULT_CLIENT_SECRET=<secret> go run .
```

### `vault_client` Configuration

Add the following to `.rocketvault.yaml` in the **consuming** application (not on the vault server itself):

```yaml
vault_client:
  url: "http://localhost:8774"
  client_id: "my-service-account"   # service account NAME, not UUID
  secrets:
    - name: DB_PASSWORD
      uuid: "0cfa58f7-a81e-4a68-acd7-b62f5f72e5b7"
      viper_key: "database.password"
```

Set the client secret via environment variable:

```bash
export VAULT_CLIENT_SECRET=<service-account-secret>
```

## Testing

### Unit Tests

```bash
# Run all tests
go test ./... -v

# Run with coverage report
go test ./... -v -cover

# Generate HTML coverage report
go test ./... -coverprofile=coverage.out
go tool cover -html=coverage.out
```

### CLI Test Suite

```bash
# Run CLI command tests
go test ./cmd/... -v

# Run specific command tests
go test ./cmd/secrets/... -v
go test ./cmd/users/... -v
go test ./cmd/keys/... -v
go test ./cmd/certificates/... -v
```

### Service Layer Tests

```bash
# Run service tests
go test ./internal/services/... -v

# Run with race detection
go test ./internal/services/... -v -race
```

### Integration Tests

```bash
# Run integration tests (requires test database)
go test ./... -v -tags=integration

# Legacy CLI tests
go test ./cmd -v -run TestCLI
```

### Performance Tests

```bash
# Database performance testing
./scripts/test_db_performance.sh

# Skip benchmarks during regular testing
go test ./... -v -cover -skip BenchmarkCreateSelfSigned
```

### API Validation

```bash
./validate-api-docs.sh
```

### Test Coverage Summary

**Current Status**:

- **CLI Commands**: extensive test coverage across every command group, including `vaults` and `vault-access`
- **Service Layer**: extensively tested with mocks; run `go test ./internal/services/... -cover` for current numbers
- **Authentication**: Complete JWT + TOTP + password validation
- **Authorization**: Global RBAC, per-vault Azure role assignment, and cross-vault denial tests (e.g. `api/vault_authz_test.go`, `api/vault_cross_denial_test.go`, `api/router_authorization_matrix_test.go`)
- **Performance**: Large dataset and concurrent operation tests
- **Error Handling**: Complete error scenario coverage

## Deployment

### Docker Deployment

1. Build the Docker image:

   ```bash
   docker build -t rocketvault .
   ```

2. Run with Docker Compose:

   ```bash
   docker-compose up -d
   ```

### Production Deployment

For production deployments, use PostgreSQL and configure proper environment variables:

```bash
export ROCKETVAULT_DATABASE_CONNECTION="host=localhost user=postgres password=secret dbname=rocketvault sslmode=require"
./rocketvault serve
```

### Railway Deployment

`railway.json` builds from the committed Dockerfile and defaults to SQLite on a mounted
volume (no PostgreSQL required). See [docs/deploy-railway.md](docs/deploy-railway.md) for
the full quick-start: attaching the volume, required variables, and bootstrapping the
first admin.

### Configuration

Create a `.rocketvault.yaml` configuration file:

```yaml
database:
  type: postgres
  connection: "host=localhost user=postgres password=secret dbname=rocketvault sslmode=require"
  max_open_conns: 100
  max_idle_conns: 25
  conn_max_lifetime: 1h

server:
  listen_addr: ":8774"
  read_timeout: "30s"
  write_timeout: "30s"

jwt:
  key_source: "os_store"     # os_store | self_pki | external_pki
  key_cn: "rocketvault"
  expiry: "1h"
  rotation_overlap: "1h"

logging:
  level: info
  file: ./logs/rocketvault.log
  max_size_mb: 10
  format: text
  rotation_method: lumberjack

bootstrap_token: "your-secure-bootstrap-token-here"

soft_delete:
  enabled: true
  retention_days: 90
  purge_protection: true

key_cache:
  enabled: true
  ttl: "60s"
  max_entries: 500
  cleanup_interval: "30s"

rate_limit:
  default: 300   # requests/min per IP
  auth: 5        # requests/min per IP for login/refresh
```

**Note**: Log directories (e.g., `./logs/`) are automatically created if they don't exist. If directory creation fails, logs fall back to stdout to prevent application crashes.

### Performance Tuning

#### Database Connection Pooling

**Development**:

```yaml
database:
  max_open_conns: 10
  max_idle_conns: 5
  conn_max_lifetime: 5m
```

**Staging**:

```yaml
database:
  max_open_conns: 50
  max_idle_conns: 15
  conn_max_lifetime: 30m
```

**Production**:

```yaml
database:
  max_open_conns: 100
  max_idle_conns: 25
  conn_max_lifetime: 1h
```

#### Performance Monitoring

Access database performance metrics at:

```bash
curl http://localhost:8774/api/v1/health/database
```

**Metrics include**:

- Connection pool utilization
- Query execution times
- Slow query detection
- Database health status

#### Key Crypto Cache

Every cryptographic operation (Sign, Verify, Encrypt, Decrypt, WrapKey, UnwrapKey) previously required a database read, an AES-GCM decrypt, and a PEM parse before the actual crypto work. Under load these three steps dominated p99 latency for software keys.

RocketVault now maintains an in-process decrypted key cache. On a cache hit the database round-trip and AES-GCM decrypt are skipped entirely. The cache is automatically invalidated whenever a key is rotated, updated, or deleted, so authorization and revocation semantics are always preserved.

Configure it in `.rocketvault.yaml`:

```yaml
key_cache:
  enabled: true          # set false to disable (falls back to no-op)
  ttl: "60s"             # how long a cached entry lives
  max_entries: 500       # maximum number of keys held in memory
  cleanup_interval: "30s"
```

HSM / PKCS#11 keys are never cached — the hardware token enforces isolation and the handle string is already cheap to access.

#### Prometheus Metrics

RocketVault exposes a Prometheus histogram for all key crypto operations:

```
rocketvault_crypto_op_duration_seconds
```

Labels:

| Label | Values |
|---|---|
| `op` | `sign`, `verify`, `encrypt`, `decrypt`, `wrap_key`, `unwrap_key` |
| `key_type` | `RSA`, `ECDSA`, `oct`, `pkcs11` |
| `cache_hit` | `true`, `false` |

Buckets (seconds): `0.001, 0.005, 0.010, 0.025, 0.050, 0.100, 0.250, 0.500`

The `cache_hit` label makes it straightforward to compare p99 latency between cache hits and misses and validate the cache is working as expected.

## Contributing

Contributions are welcome! This project follows enterprise-grade standards.

### Development Guidelines

1. **Architecture**: Follow domain-driven design principles
2. **Service Layer**: Maintain single responsibility per service
3. **Testing**: Maintain >90% test coverage for new code
4. **Documentation**: Update relevant documentation with changes
5. **Code Quality**: Run linters and tests before committing

Run `./scripts/install-hooks.sh` once after cloning to enable a local git hook that reminds you when `docs/usage-guide.md` may need refreshing after you touch source it documents. This is standard practice (similar to husky or pre-commit) — opting in means a repo-controlled shell script runs on your next commit.

### Contribution Process

1. Fork the repository
2. Create feature branch: `git checkout -b feature/amazing-feature`
3. Implement changes following DDD principles
4. Add comprehensive tests (unit + integration)
5. Update documentation as needed
6. Run full test suite: `go test ./... -v -cover`
7. Commit changes: `git commit -m 'Add amazing feature'`
8. Push to branch: `git push origin feature/amazing-feature`
9. Open Pull Request with detailed description

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE) for details.

## Security

This application implements industry-standard security practices:

- **Encryption**: All sensitive data is encrypted at rest
- **Authentication**: JWT tokens with TOTP MFA — asymmetric signing only (RS256/ES256 with mandatory `kid`, JWKS rotation); the server aborts startup rather than degrade to a weaker signing mode
- **Authorization**: Role-based access control + attribute-based access policies, enforced consistently on both the vault-scoped and legacy flat API routes
- **Master Key Rotation**: `master-key rotate` CLI re-encrypts every master-key-sealed secret, key, and certificate onto a new key (resumable, dry-run-capable); the server refuses to boot on an invalid or known-compromised master key
- **Audit Logging**: Comprehensive audit trails persisted to database and log files, with admin-gated access via both the API and CLI
- **Secure Defaults**: Conservative security defaults; CI guards against real secrets ever being committed to the repository
- **Rate Limiting**: Configurable per-endpoint rate limits to prevent brute force

For detailed security information, see the [Security Documentation](doc/security.markdown).

## Support

For questions or issues:

1. Check the [Troubleshooting Guide](doc/troubleshooting.markdown)
2. Search existing [GitHub Issues](https://github.com/Snehal1112/rocketvault/issues)
3. Open a new issue with detailed information

## Roadmap

### Shipped

*(Oct 2025)*

- [x] Complete domain-driven design architecture (A grade)
- [x] Service container integration (95% compatibility)
- [x] Database performance optimization (90%+ improvement)
- [x] Comprehensive testing suite (50+ test cases, 94.9% coverage)
- [x] Enterprise-grade connection pooling and monitoring
- [x] Production-ready deployment with performance tuning
- [x] Robust logging with automatic directory creation and graceful fallbacks
- [x] Backup encryption flag fix for proper unencrypted backup support

*(Feb–May 2026)*

- [x] Secret `content_type` field — domain, schema, repository, service validation, API and CLI
- [x] Key wrap/unwrap operations — CryptoService, HTTP endpoints, CLI subcommands
- [x] Key sign/verify/encrypt/decrypt — HTTP endpoints (`/sign`, `/verify`, `/encrypt`, `/decrypt`)
- [x] Key versioning — version list endpoint and `updated_at` timestamp
- [x] JWK public material in key responses
- [x] 3072-bit RSA key support in service layer and API
- [x] Certificate policies — GET/PUT/DELETE `/certificates/{id}/policy`
- [x] Certificate auto-renewal — ExpiresAt field, RenewalScheduler, HTTP API, CLI flags
- [x] Soft delete with purge protection — secrets, keys, and certificates
- [x] Per-item backup & restore — individual backup/restore for secrets, keys, and certificates
- [x] Access policies and service accounts — RBAC attribute-based policies, OAuth2 service accounts
- [x] Audit log DB persistence — AuditRepository writes to `audit_logs` table
- [x] Security hardening: crypto/rand enforcement, role self-promotion blocking, ownership enforcement on rotation
- [x] OS keychain JWT key storage — asymmetric signing keys stored in OS cert store
- [x] Rate limiting — configurable per-endpoint limits via gorilla/mux middleware
- [x] HSM / PKCS#11 support — SoftHSM2 and hardware HSM via miekg/pkcs11
- [x] Vault client / secret consumption — built-in client + example consumer service
- [x] GitHub Actions release workflow — matrix build for Linux/macOS/Windows, GitHub Release publish
- [x] git-cliff changelog generation — automatic grouped release notes via CI/CD
- [x] Signed releases — GPG-signed commits, tags, and release.sh bump script
- [x] First public release — v0.1.0 with verified tag and draft GitHub Release

*(May 2026 — continued)*

- [x] In-process key crypto cache — eliminates DB + AES-GCM + PEM-parse overhead on hot sign/verify/encrypt/decrypt paths
- [x] Prometheus histogram for key crypto operations — `rocketvault_crypto_op_duration_seconds` with `op`, `key_type`, `cache_hit` labels
- [x] PKCS#11 PSS mechanism parameters — correct `CK_RSA_PKCS_PSS_PARAMS` for PS256/PS384/PS512 algorithms
- [x] Race-free key material zeroing — `LoadAndDelete` pattern across all cache eviction paths
- [x] Advanced audit and compliance reporting (SOC 2, GDPR) — `internal/services/audit/compliance_report_service.go`
- [x] Enhanced CLI output formats — `--output table|json|yaml` global flag across all commands

*(May–Aug 2026 — Multi-vault architecture and Azure Key Vault RBAC parity)*

- [x] Vault as a routing/context-scoping layer — named vaults with `vault_id`-scoped secrets, keys, and certificates; `vaults` CLI and `/api/v1/vaults` management API
- [x] Vault-scoped resource routes — `/api/v1/vaults/{vault_name}/secrets|keys|certificates|...` alongside the legacy flat routes, which now resolve against the `default` vault
- [x] Seven built-in Azure Key Vault-parity roles (`Key Vault Administrator`, `Key Vault Reader`, `Key Vault Secrets User`, `Key Vault Secrets Officer`, `Key Vault Crypto User`, `Key Vault Crypto Officer`, `Key Vault Certificates Officer`) mapped to concrete data actions on every vault route
- [x] Per-vault role assignments — grant/list/revoke via CLI (`vault-access`) and API (`/api/v1/vaults/{vault}/role-assignments`)
- [x] Deny-by-default vault data-plane authorization — a caller needs an explicit role assignment in a vault; `access_policies` retained only as an explicit-deny override evaluated before the role decision
- [x] One-time migration backfill deriving Azure role assignments from prior object ownership, the global admin role, and legacy per-vault role names, plus `vaults preview-migration` to review it beforehand
- [x] Vault-scope inconsistency fixes (2026-07-26) — secrets update/versions/export/import, keys update, and certificate policy routes made genuinely vault-scoped instead of silently falling back to owner-only behavior
- [x] Key delete and all crypto operations (sign/verify/encrypt/decrypt/wrap/unwrap) gated by vault role instead of key ownership (2026-08-02) — the last key operations that were still owner-gated on a vault-scoped route now follow the same `Key Vault Crypto User`/`Key Vault Crypto Officer` role check as the rest of the vault-scoped surface
- [x] Extend `--vault` CLI support to `keys` (create/get/list/update/delete/rotate/wrap/unwrap) — pure CLI wiring, every one of these already had a vault-scoped HTTP path and vault-aware service method
- [x] Extend `--vault` CLI support to `certificates` `list`/`get`/`delete` — same as keys, backend was already vault-scoped
- [x] Certificate `update` and `renew` made genuinely vault-scoped (previously hardcoded owner-only at the API/service level) — `--vault` now works on every certificate command

*(2026-08-16 — Pentest hardening)*

- [x] Removed the legacy HS256 JWT fallback — signing is now asymmetric-only (RS256/ES256), every token requires a `kid`, and startup aborts on a bad signing provider instead of degrading
- [x] Fixed a cross-vault authorization bypass on legacy flat (non-vault-scoped) data-plane routes — `scopeFromRequest` now always resolves a vault-scoped predicate
- [x] Master key rotation — `internal/rekey` plan-then-apply re-encryption engine and the new `master-key rotate` CLI command (resumable, dry-run-capable), plus a startup guard refusing to boot on an invalid or known-compromised master key
- [x] Fixed the `.gitignore` gap that allowed `.rocketvault.yaml` to be tracked; shipped `.rocketvault.yaml.example`; rotated all previously-exposed secrets; added a CI guard against recurrence
- [x] Added an admin-only gate to the `audit` CLI commands, matching the existing HTTP API restriction
- [x] Fixed the CLI to exit non-zero on command failure — every command now exits `1` on error and `0` on success, safe for `&&` chains and `set -e` scripts
- [x] `Key Vault Crypto User` role: added missing `update`/`backup` data actions for exact Azure parity (2026-08-17)

*(2026-08-25)*

- [x] Key import (JWK) — `POST /keys/import` and `rocketvault keys import` accept an externally-generated RSA/ECDSA private-key JWK and store it exactly as a generated key would (encrypted PEM, or a non-extractable PKCS#11 object on an HSM-backed vault), gated by the new `ActionKeysImport` data action

### Planned

Full rationale, non-goals, and sequencing: [Roadmap — Azure Parity & Beyond](.claude/roadmap-azure-parity-and-beyond.md).

**Phase 1 — Close remaining Azure Key Vault gaps**

- [ ] Rotation-policy scheduler — actually execute the rotation policies that already exist (CRUD-only today); currently a silent no-op that could give a false sense of security, so this is the highest-priority item in this phase
- [ ] Certificate import (PFX/PEM) / CSR merge
- [ ] ACME / Let's Encrypt certificate enrollment — the open substitute for Azure's partner-CA-only integration (DigiCert/GlobalSign), which is not separately planned

Not planned, or needs a feasibility check first: confidential-compute key release (TEE attestation — no realistic self-hosted equivalent), FIPS 140-3 L3 certification (a hardware certification process — RocketVault instead supports FIPS-validated HSMs via PKCS#11), geo-replication identical to Azure's managed failover (see Phase 3 for an open, multi-primary alternative instead), and HSM coverage for the P-256K curve and AES-CBC wrap (niche demand — P-256K is mainly a blockchain-signing curve and AES-CBC wrap is superseded by AES-KW as the modern standard — and depends on PKCS#11 library/hardware support that may not exist, not purely a coding gap; revisit only if real user demand shows up).

**Phase 2 — Platform maturity**

- [ ] Vault-scope role-assignment management for non-admin `vaults:manage` holders (currently requires the global admin role — see [known limitations](docs/release-notes/v4.0.0-azure-rbac.md#known-limitations)) — highest priority here, since it's core to the multi-vault delegation model, not just a convenience gap
- [ ] Redis caching layer for distributed deployments — closes a real revocation-latency window: a key rotated on one replica can still be served from another replica's stale in-process cache until its TTL expires
- [ ] Official Helm chart + signed/scanned container images (cosign/sigstore) — moved up from the "beyond Azure" list as the natural prerequisite for the Kubernetes operator below
- [ ] Kubernetes operator for automated deployment — builds on the Helm chart above rather than starting from raw manifests
- [ ] Web-based administration interface — largest effort item in this phase; broadens adoption but doesn't unblock any existing functionality, so it's sequenced last

**Phase 3 — Beyond Azure**

- [ ] Multi-region / multi-primary replication — open design with conflict resolution, not a copy of Azure's managed regional failover
- [ ] GitOps / policy-as-code + Terraform provider for vaults, role assignments, and rotation policies
- [ ] WebAuthn / passkey login alongside TOTP MFA
- [ ] Native webhook/notification system for rotation failures, expiry warnings, and audit events
- [ ] Break-glass emergency access workflow with mandatory justification and audit trail
- [ ] Extended compliance report templates (PCI-DSS, HIPAA) alongside the existing SOC 2 / GDPR reports, with optional scheduled delivery (email/webhook) instead of pull-only
- [ ] Local dev secret injection — `direnv`-style `rocketvault run -- <command>`
- [ ] Format-aware bulk import/export — Kubernetes Secrets YAML, `.env`, Terraform tfvars, for easier migration in/out of other secret stores
- [ ] Externally-anchored tamper-evident audit log — sign and timestamp the hash-chain head (or publish it to a transparency log) so tampering is detectable even if the database itself is compromised
- [ ] Per-principal rate limiting alongside the existing per-IP limits
- [ ] Operation-aware health readiness — gate `/health/ready` during long-running operations like master-key rotation or purge runs

## Acknowledgments

Built with enterprise-grade architecture patterns:

- **Domain-Driven Design (DDD)**: Eric Evans' tactical patterns
- **Clean Architecture**: Robert C. Martin's architectural principles
- **Service Layer Pattern**: Martin Fowler's enterprise application architecture
- **Repository Pattern**: Data access abstraction and testability
- **Dependency Injection**: Loose coupling and high testability

**Technology Stack**:

- Go 1.25.0 with modern practices (generics, structured logging)
- Gorilla Mux for HTTP routing
- SQLite (dev) / PostgreSQL (prod) with encryption
- JWT + TOTP MFA for authentication (asymmetric, JWKS rotation)
- miekg/pkcs11 for HSM / PKCS#11 integration
- zalando/go-keyring for OS keychain JWT key storage
- Cobra framework for CLI
- Testify for comprehensive testing

**Status**: Actively developed | **Latest tagged release**: [v0.2.1](https://github.com/Snehal1112/rocketvault/releases) | This branch (`v-4.0.0`) adds multi-vault architecture and Azure Key Vault RBAC parity ahead of its own tag
