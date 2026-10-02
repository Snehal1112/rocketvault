# RocketVault Usage Guide

RocketVault is a self-hosted, open-source alternative to Azure Key Vault, written entirely in Go. It manages secrets, cryptographic keys, and X.509 certificates in your own infrastructure, with no cloud dependency — exposed through a REST API, a full-featured CLI, and a handful of integration surfaces.

This guide is the single entry point for **all nine ways to use RocketVault**, from a human typing commands in a terminal to a Kubernetes probe hitting a health endpoint. Each section follows the same shape: what the surface is, when to reach for it, what you need first, a worked example, and the gotchas that bite in practice.

Throughout this guide, `http://localhost:8774` is used as the server address. The effective bind address follows this precedence: the `serve --listen` flag, then `server.listen_addr` in `.rocketvault.yaml`, then a hardcoded `127.0.0.1:8774` fallback (`defaultListenAddr` in `cmd/serve.go`). The `server.listen_addr`-ignored init-ordering bug described in earlier revisions of this guide was fixed in commit `e630029` (2026-08-18) — `servePreRun` now applies it from config unless `--listen` was explicitly passed. Both the checked-in `.rocketvault.yaml` and `.rocketvault.yaml.example` set `server.listen_addr: ":8774"` (all interfaces), so `http://localhost:8774` still reaches it locally under the current default. All API paths are relative to the `/api/v1` base path unless stated otherwise.

## Known gaps in the surrounding documentation

An earlier audit of the other docs in this repo found a batch of inaccuracies; that audit has since been used to fix `docs/api-developer-guide.md`, `docs/admin-manual.html`, `README.md`, and `docs/consuming-secrets-guide.md`, so this callout no longer lists them. One item remains open, tracked in a project doc rather than in this guide:

| Document | Claim | Reality |
| --- | --- | --- |
| `CLAUDE.md` | "Open Bugs (as of 2026-03-08)" lists "secrets table missing columns" (`deleted_at` / `purge_protection`) as open | Stale — `.claude/known-bugs.md` (entry B1) already tracks this as fixed in commit `b46000b`, which added the columns to both `createOptimizedSchema` and `migrateSchema()`. `CLAUDE.md`'s "Open Bugs" section just hasn't been updated to match. |

## Table of contents

1. [CLI (human-driven)](#1-cli-human-driven)
2. [REST API (programmatic)](#2-rest-api-programmatic)
3. [OAuth2 / Service Accounts (machine-to-machine)](#3-oauth2--service-accounts-machine-to-machine)
4. [Vault Client library (embedded secret consumption)](#4-vault-client-library-embedded-secret-consumption)
5. [JWKS endpoint (token verification by external services)](#5-jwks-endpoint-token-verification-by-external-services)
6. [Backup / restore tooling](#6-backup--restore-tooling)
7. [Health / monitoring integration](#7-health--monitoring-integration)
8. [HSM-backed mode (PKCS#11)](#8-hsm-backed-mode-pkcs11)
9. [Deployment modes](#9-deployment-modes)

---

## 1. CLI (human-driven)

**What it is:** The `rocketvault` Cobra-based command-line binary. The same binary that runs the server (`rocketvault serve`) also exposes `secrets`, `keys`, `certificates` (aliased as `certificate`, the form used throughout this doc), `users`, and `vaults` subcommands that talk directly to the service layer — no HTTP hop. Authentication is now session-based rather than per-command: `rocketvault users login` (username/password/TOTP) or `rocketvault users login --oidc` (browser-based, for OIDC-provisioned users) authenticates once and caches the resulting session to `~/.rocketvault/sessions/`; every other command picks that cached session up automatically, falling back to `--username`/`--password`/`--totp-code` flags only if you pass them. Other registered top-level groups include `audit`, `vault-access`, `vault-webhook` (per-vault webhook configuration — `set`/`get`/`delete`), `rotation` (under `secrets`), `migrate`, `backup`, `health`, `mcp` (`rocketvault mcp`, a Model Context Protocol server over stdio), and `context` (local-only management of saved remote-server targets — see the remote-target gotcha below).

**Use it when:**

- You're an operator or admin sitting at a terminal doing one-off, interactive work: creating the first admin user, rotating a secret, inspecting a key, issuing a certificate.
- You want scriptable output (`--output json`) for shell pipelines without standing up an API client.
- You need to run system-level operations that don't require authentication (`serve`, `migrate`, `health`, `admin` bootstrap, `users login`/`logout`) or admin-only whole-database operations (`backup`).
- You're working against a local or self-hosted instance where you already have filesystem access to `.rocketvault.yaml`.

**Prerequisites:**

- A `.rocketvault.yaml` in the working directory (or `--config <path>`) — `initConfig()` in `cmd/root.go` looks for `./.rocketvault.yaml` by default and panics if it can't read it, unless you're targeting a remote server (`--server`/`ROCKETVAULT_ADDR`/an active `context`) or running the local-only `context` command group — neither needs a local config file.
- An existing user account for any non-system command: a local username + password + TOTP secret, or an OIDC-provisioned identity (see the OIDC note under Authentication Services in `CLAUDE.md`). Local accounts log in with `rocketvault users login`; OIDC accounts have no password and must use `rocketvault users login --oidc`, which requires `frontend.public_api_url` to be set in `.rocketvault.yaml` (`runOIDCLogin` in `cmd/users/login_oidc.go` errors out otherwise). For the very first user, you need the `bootstrap_token` config key (see `.rocketvault.yaml`) and `rocketvault users admin`.
- The compiled binary (`./rocketvault`, per `build.sh` / README) or `go run main.go` for development.

### Example

```bash
# One-time: create the first admin user using the bootstrap token from .rocketvault.yaml
./rocketvault users admin \
  --admin-username admin --admin-password admin123 \
  --bootstrap-token "<value from your .rocketvault.yaml>"

# Log in — this caches the session to ~/.rocketvault/sessions/local__admin.json
# (local-mode sessions are keyed "local__<username>.json") and points
# ~/.rocketvault/sessions/current at it
./rocketvault users login \
  --username admin --password admin123 --totp-code 847291

# ...or, for an OIDC-provisioned user with no local password, open a browser
# to the configured OIDC provider instead:
./rocketvault users login --oidc

# From here on, no --username/--password/--totp-code needed — commands pick
# up the cached session automatically (persistentPreRun -> resolveAuthentication
# in cmd/root.go), transparently refreshing it via its refresh token if expired.

# Create a secret with tags, in the default vault
./rocketvault secrets create my-secret my-value \
  --tags prod,db --content-type application/json

# Read it back as JSON
./rocketvault secrets get <secret-id> --output json

# List secrets filtered by tag, in a specific vault
./rocketvault secrets list --tags prod --vault payments-team

# Create an RSA key (requires admin or crypto_manager role)
./rocketvault keys create --name mykey --type RSA --bits 2048

# List certificates in a specific vault — keys and certificate subcommands
# all support --vault now, including certificate create
./rocketvault certificate list --vault payments-team

# Configure a vault's webhook (requires admin or vaults/manage) — the signing
# secret is printed once, on create or --rotate-secret, and never again
./rocketvault vault-webhook set --vault payments-team \
  --url https://hooks.example/rocketvault

# Log out when you're done — this only clears the local cache, it does not
# revoke the session server-side (the JWT just expires naturally)
./rocketvault users logout
```

The flag-based form still works on every command — pass `--username`/`--password`/`--totp-code` and it re-authenticates fresh instead of touching the cache (and still caches the result afterward), same as before this change:

```bash
./rocketvault secrets list --tags prod --vault payments-team \
  --username admin --password admin123 --totp-code 847291
```

Passing `--username` alone (no `--password`) loads that specific user's cached session instead of prompting for credentials — useful when you have more than one cached login and want to target a non-default one without a full re-login.

### Notes & gotchas

- **Sessions are cached, not re-authenticated per command.** `resolveAuthentication` in `cmd/root.go` tries, in order: fresh `--username`+`--password`(+`--totp-code`) login (cached to disk on success); `--username` alone loads that user's cached session; no flags at all loads whichever session `~/.rocketvault/sessions/current` points at. A cached session past its `ExpiresAt` is refreshed transparently via its refresh token before the command runs. This is a real behavior change from earlier versions, where every command re-authenticated from flags with no persistence.
- **`users login --oidc` and `users logout` are new.** `login --oidc` starts a local loopback listener, opens your browser to the server's `/oidc/login`, and exchanges the resulting one-time code for a session via `POST /oidc/cli/exchange` (`cmd/users/login_oidc.go`) — this is the only way to authenticate an OIDC-provisioned user from the CLI, since those accounts have no local password. `logout` (`cmd/users/logout.go`) deletes the cached session file for the current user, or for `--username <user>` if given; it's local-only, there is no server-side revocation call.
- **System commands skip auth entirely.** `health`, `serve`, `admin`, `migrate` / `migrate:status` / `migrate:to` / `migrate:create`, `roles`, `preview-migration` (i.e. `vaults preview-migration`), `login`, `logout`, `context`, `generate-password` (i.e. `secrets generate-password`), `help`, and `completion` (plus the hidden `__complete`/`__completeNoDesc` commands shell tab-completion invokes) are listed in `systemCmds` in `cmd/root.go` and run without a session or `--username`/`--password`. `backup` used to be in this list too (a real, unauthenticated-dump vulnerability) — it's since been removed and now requires an admin login like every other data-touching command; see the Backup / restore tooling section's gotchas.
- **`vault-webhook set|get|delete` configure, but do not deliver.** They manage a vault's webhook URL and signing secret only (`cmd/vault-webhook/`, backed by `VaultWebhookService`); RocketVault has no outbound notification delivery mechanism yet, so nothing actually calls the configured URL (see `.claude/known-bugs.md`'s webhook entry). `set --rotate-secret` (or a first-time `set`) prints the plaintext signing secret exactly once — it is not retrievable afterward and `get`'s output never includes it. All three subcommands require `--vault` (or the usual `--vault` precedence) and admin or `vaults/manage`-equivalent authorization via `CanManageVault`, checked client-side the same way `vaults`/`vault-access` commands are (see the two-stage role-check gotcha below for how this differs from `secrets`/`keys`/`certificate`'s per-vault-role check).
- **A remote-target guard still blocks most commands; the allowlist in `cmd/root.go` is the authority on which ones it doesn't.** `persistentPreRun` resolves a remote target via `cliclient.ResolveTarget`: `--server` flag > `ROCKETVAULT_ADDR` env > the active `rocketvault context` (saved with `context add`, selected with `context use`). A command with its own remote-mode adapter genuinely talks to `target.Server` over HTTP instead of the local service container; every other resource command is refused outright with `remote mode (...) is not yet supported for %q; unset it to run against the local instance`. **Read `remoteCapableCommands` in `cmd/root.go` for the current list rather than trusting prose here** — it is a map of command group to subcommands, it grows with every adapter phase, and the enumeration that used to live in this bullet went stale twice. At the time of writing it holds `secrets` (`create`, `get`, `list`, `update`, `delete`, `export`, `import`) and `users` (`login`, `logout`); `keys`, `certificate`, `vaults`, `vault-access`, `audit` and the `users` resource commands are still guarded. `users login`/`logout` take a separate unauthenticated pre-run branch (`isRemoteUnauthenticatedCommand`), since login is what produces a session and requiring one first would be circular. `context` itself, Cobra's own built-ins (`help`/`completion`), and the two commands that touch no server at all (`vault-access roles`, `secrets generate-password`) are exempt from the guard regardless. `--server`/`--ca-cert`/`--insecure-skip-verify` are registered as persistent flags on every command either way.
- **`--output` only accepts `table`, `json`, or `yaml`.** Anything else fails fast with `invalid --output value ...: must be table, json, or yaml` (`cmd/root.go`, `internal/formatter`). Default is `table`.
- **Vault targeting precedence:** `--vault` flag > `ROCKETVAULT_VAULT` env > config `vault` key > `"default"`, per `common.ResolveVaultName` (`common/vault_selector.go`) — the single source of truth every resolver (`vaultcli.ResolveVaultID`, and `cmd/vault_flag.go`'s test-only `resolveVault` wrapper) delegates to. The `--vault` persistent flag itself is registered on `rootCmd` in `cmd/root.go`'s `init()`, so it's available on every subcommand. A `--vault` wiring series has landed `--vault` support across every `secrets`/`keys`/`certificate` data-plane subcommand — create, get, list, update, delete, plus `keys rotate`/`wrap`/`unwrap` and `certificate renew`. `certificate create` was the last holdout (it silently ignored `--vault` and always provisioned into the default vault) but was wired up too; it now resolves the target vault the same way its sibling commands do.
- **Role checks now run in two stages, not just a client-side gate.** Commands first do a local role check — e.g. `keys create` calls `common.HasAnyRole(claims.Roles, model.RoleAdmin, model.RoleCryptoManager)` and fails fast with `forbidden: requires admin or crypto_manager role` before touching the service — then call `vaultcli.RequireDataAction`, which reproduces the HTTP `PolicyMiddleware`'s check against the resolved `--vault`: an access-policy explicit-deny override (`AccessPolicyService.CheckAccess`), then a per-vault role-assignment check (`RoleAssignmentService.HasDataAction`). A role that passes the local check can still be denied per-vault. `certificate create` used to skip this vault-authorization check entirely; that gap has since been closed, so it now goes through the same two-stage check as every other data-plane command. `keys create --curve` now also accepts `P-256K` (secp256k1) alongside `P-256`/`P-384`/`P-521`, for HSM-backed ECDSA keys.
- **In local mode, the CLI talks to the service container directly** (`internal/container.ServiceContainerInterface`), bypassing the HTTP API and its middleware chain — so the API-level `rate_limit` config in `.rocketvault.yaml` does not apply. This no longer holds for any command run against a remote target (see the remote-target gotcha above): a command with a remote adapter genuinely goes over HTTP to `target.Server` and is subject to that server's rate limits like any other API client.
- TOTP codes rotate every 30 seconds; an expired code is rejected by the authentication service. See the TOTP walkthrough in the deep-dive doc if you need a code without a phone.

**Deep dive:** [docs/cli-guide.md](cli-guide.md) — full walkthrough covering TOTP setup, first-time admin bootstrap, secrets/keys/certificates/users management, automatic rotation, backups, and health checks.

---

Everything the CLI does locally is also reachable over HTTP, which is the surface you'll use from application code.

## 2. REST API (programmatic)

**What it is:** A JWT-authenticated HTTP API (Gorilla Mux) exposing full CRUD for vaults, secrets, keys, certificates, users, access policies, role assignments, service accounts (OAuth2), audit, vault webhook configuration, and backup/restore — the same operations the CLI performs, callable from any HTTP client. Nearly everything lives under `/api/v1`; the two exceptions are `GET /jwks.json` and `GET /metrics`, which `api/api.go`'s `Init` registers directly on the root router with no base-path prefix (see sections 5 and 7).

**Use it when:**

- Integrating RocketVault into application code, CI/CD pipelines, or automation scripts instead of shelling out to the CLI.
- Building a custom UI, sidecar, or SDK on top of the vault.
- Using non-interactive machine identities (OAuth2 client-credentials service accounts) rather than human user logins.
- Scripting bulk operations (`/secrets/export`, `/secrets/import`) or programmatic session/token management.

**Prerequisites:**

- A running `rocketvault serve` instance. `server.listen_addr` in `.rocketvault.yaml` now determines the bind address: commit `e630029` ("fix(cmd): apply server.listen_addr from config on serve") moved the config read into `servePreRun` in `cmd/serve.go`, which runs after Viper has loaded the config file, so an unset `--listen` flag now picks up the config value instead of silently falling back to the hardcoded `defaultListenAddr = "127.0.0.1:8774"`. Both the checked-in `.rocketvault.yaml.example` and this repo's own `.rocketvault.yaml` set `server.listen_addr: ":8774"`, so the effective default bind today is `:8774` (all interfaces). `http://localhost:8774` still reaches it either way.
- An existing user account (created via bootstrap token — see section 1) with a username, password, and TOTP code; login requires all three.
- The API base path is `/api/v1` (`basePath = "/api/v1"` in `cmd/serve.go`, overridable via the `serve --api_base` flag or the `PASSWORD_MANAGER_BASE_API` env var).
- A valid JWT alone is not enough to touch secrets, keys, or certificates: the account must also hold a role assignment granting the relevant Azure data action in the target vault (see the deny-by-default note below). A bootstrap-created global admin gets this for free in every vault; any other user needs an explicit grant first (`vault-access grant` — section 1 — or `POST /api/v1/vaults/{vault_name}/role-assignments`).

### Example

Log in to get a JWT (`POST /api/v1/users/login` is public — no `Authorization` header needed):

```bash
curl -s -X POST http://localhost:8774/api/v1/users/login \
  -H "Content-Type: application/json" \
  -d '{
        "username": "admin",
        "password": "admin123",
        "totp_code": "123456"
      }'
```

This returns a JSON body with `token`, `refresh_token`, `user_id`, `username`, and `roles` (a string array, not a singular `role` — see `model.LoginResponse` in `model/user.go`). Use `token` as a Bearer credential on every other call:

```bash
TOKEN="<value of token from the login response>"

# Create a secret
curl -s -X POST http://localhost:8774/api/v1/secrets \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name": "db-password", "value": "s3cr3t", "tags": ["prod"]}'

# List secrets
curl -s http://localhost:8774/api/v1/secrets \
  -H "Authorization: Bearer $TOKEN"

# Get a specific secret
curl -s http://localhost:8774/api/v1/secrets/<secret_id> \
  -H "Authorization: Bearer $TOKEN"
```

When the access token expires, exchange the refresh token via the also-public `POST /api/v1/users/refresh` (body: `{"refresh_token": "..."}`, per `model.RefreshTokenRequest`) rather than logging in again.

### Notes & gotchas

- Every route except `POST /users/login`, `POST /users/refresh`, `POST /oauth2/token`, `GET /config`, `GET /jwks.json`, and the three public health routes (`GET /health`, `GET /health/ready`, `GET /health/live` — note that `GET /health/database` is *not* public) requires the `Authorization: Bearer <jwt>` header. `AuthenticationMiddleware`/`ApiSessionRequired` reject a missing or invalid session with `401`. `GET /oidc/login`, `GET /oidc/callback`, and `POST /oidc/cli/exchange` (`api/oidc.go`, `api/oidc_cli.go`) are also unauthenticated — a new browser-based login flow, additive to this section's username/password/TOTP flow, gated by `oidc.enabled` in `.rocketvault.yaml` and out of scope for the rest of this section.
- A valid bearer token is necessary but no longer sufficient for secrets, keys, and certificates. `PolicyMiddleware` (`internal/middleware/middleware.go`) is **deny-by-default** for vault data-plane routes: it maps the request to a single Azure data action and calls `RoleAssignmentService.HasDataAction` to check whether the caller holds a role assignment granting that action *in the resolved vault*. No matching assignment is a `403 Forbidden: no role assignment grants this operation in this vault`, regardless of how valid the token is. `access_policies` still exist but now act only as an explicit-deny override — `AccessPolicyService.CheckAccess` runs first, so an explicit deny always wins even where a role assignment would otherwise allow. `RBACService.ValidateEndpointAccess` (checked separately by `AuthorizationMiddleware`) still gates global-role permissions, but it explicitly defers on every vault data-plane and vault-management route (returns no error), so for `/secrets`, `/keys`, and `/certificates` it's the role-assignment check — not RBAC — that decides. A bootstrap-created global admin is auto-granted the Key Vault Administrator role in every vault (including `default`) by a startup migration backfill, which is why the `admin` example below works without any extra setup; every other principal needs an explicit grant via `vault-access grant` (section 1) or `POST /api/v1/vaults/{vault_name}/role-assignments` before it can touch data-plane resources.
- JWT access tokens expire based on `jwt.expiry` in `.rocketvault.yaml` (`1h` in the committed `.rocketvault.yaml.example` template; your own file is generated per-clone and may differ). Plan to use the refresh-token flow instead of re-authenticating with TOTP on every expiry.
- Rate limiting is enforced per-IP by `RateLimitMiddleware`: `rate_limit.auth` (5 req/min in `.rocketvault.yaml`) applies to `/users/login`, `/users/refresh`, and `/oauth2/token`, and `rate_limit.default` (300 req/min) applies to everything else. Responses include `X-RateLimit-Limit`, `X-RateLimit-Remaining`, and `X-RateLimit-Reset` headers. On top of that, `VaultRateLimitMiddleware` enforces a separate per-*vault* budget (`rate_limit.per_vault`, default 600 req/min, across every caller of that vault) — a noisy-neighbour guard distinct from the per-IP limiter above. It reports `X-RateLimit-Vault-Limit`, `X-RateLimit-Vault-Remaining`, and `X-RateLimit-Vault-Reset` headers (deliberately separate names so they can't clobber the per-IP headers) and rejects with `429 Vault rate limit exceeded` when exhausted. Health probes are exempt; routes that resolve no vault of their own (vault management, legacy flat routes) count against the `default` vault.
- Machine-to-machine access doesn't have to go through user login at all — `POST /api/v1/oauth2/token` (public, registered in `api/oauth2.go`) issues tokens for service accounts created via `POST /api/v1/service-accounts` (authenticated). See section 3.
- Most resource routes exist in two shapes: the legacy flat form (e.g. `/api/v1/secrets`) and a vault-scoped form (e.g. `/api/v1/vaults/{vault_name}/secrets`), registered by the same handlers (`api.registerSecretRoutes` in `api/secrets.go`). Both work, and both are gated by the same deny-by-default role-assignment check described above; a flat-route call resolves against the `default` vault, a vault-scoped call resolves — and is authorized — against the named vault instead. Per-item backup/restore (`POST /{secrets,keys,certificates}/{id}/backup`, `POST /{secrets,keys,certificates}/restore` — restore takes no ID in the path, since the target ID is embedded in the decoded backup blob) follows the same dual registration (`api/backup_item.go`). Vault webhook configuration is the exception: `PUT`/`GET`/`DELETE /api/v1/vaults/{name}/webhook` (`api/vault_webhook.go`) exists only in the vault-scoped form — there's no flat `/api/v1/webhook` — since it configures one named vault's outbound delivery settings directly, and it's authorized via `CanManageVault`, not the data-action role-assignment check.
- All IDs in path parameters (`secret_id`, `key_id`, `certificate_id`, `user_id`, `policy_id`, `service_account_id`, `assignment_id`) must match the hex/UUID pattern `[A-Fa-f0-9-]+` enforced by the Gorilla Mux route regex, or the router returns a 404 before your handler even runs.
- **Key crypto operations can target an archived version, not just the current one (fixed 2026-08-19).** `POST /keys/{id}/sign`, `/verify`, `/encrypt`, `/decrypt`, `/wrap`, and `/unwrap` all accept an optional `"version"` int field in the request body (`0` or omitted = current, unchanged from before); each response echoes back `"version"` so a caller that omitted it can see what "current" resolved to. Rotating a key with `POST /keys/{id}/rotate` no longer strands the pre-rotation material — pass the matching version to decrypt, unwrap, or verify something produced before a rotation. `GET /keys/{key_id}/versions/{version}` (flat + vault-scoped) is a new route returning one version's metadata (no key material — versions stay metadata-only, same as the existing `GET /keys/{id}/versions` list); a nonexistent or unauthorized version 404s. See `.claude/known-bugs.md` § B26 and `docs/api-specification.yaml` for the full request/response shapes.

**Deep dive:** [docs/api-developer-guide.md](api-developer-guide.html) — full endpoint reference, error format, and JavaScript/Python/Go SDK examples. Its one remaining discrepancy is its "Base URL" section, which shows a placeholder `https://api.rocketvault.local` domain rather than the real default `http://localhost:8774`.

---

Human logins are a poor fit for pipelines and long-running services. That's what service accounts are for.

## 3. OAuth2 / Service Accounts (machine-to-machine)

**What it is:** RocketVault issues short-lived JWTs to non-human callers via the RFC 6749 §4.4 client-credentials grant. A "service account" is an admin-managed principal with its own `client_id` (its name) and `client_secret`; an application exchanges that pair for a bearer token at `POST /api/v1/oauth2/token` instead of logging in with a human password + TOTP.

**Use it when:**

- A CI/CD pipeline needs to fetch a secret at build or deploy time.
- An application needs to read secrets, keys, or certificates at runtime without embedding a human's credentials.
- You want machine access that can be individually rotated, disabled, or deleted without touching any human user account.

**Prerequisites:**

- A running RocketVault server and an **admin** bearer JWT — creating, listing, rotating, and deleting service accounts requires the `admin` role (`api/oauth2.go`: `createServiceAccount`, `listServiceAccounts`, `getServiceAccount`, `deleteServiceAccount`, and `rotateServiceAccountSecret` all call `common.HasAnyRole(c.Claims.Roles, model.RoleAdmin)`).
- The `oauth2.token_expiry` (default `30m`) and `oauth2.issuer` config keys in `.rocketvault.yaml` (this repo's config currently sets `token_expiry: "30m"`, `issuer: "http://localhost:8774"` — since `.rocketvault.yaml` is gitignored and generated per clone, treat the specific `issuer` value as illustrative, not a shipped default). The container falls back to a 30-minute expiry if the key is unset (`internal/container/service_container.go`).
- Vault data-plane routes — secrets, keys, and certificates, both the flat `/api/v1/secrets/{id}` shape and the vault-scoped `/api/v1/vaults/{name}/secrets/{id}` shape — are **deny-by-default**: the caller needs a per-vault role assignment granting the mapped Azure data action (`internal/services/authorization/data_actions.go`, `PolicyMiddleware` in `internal/middleware/middleware.go`). A freshly created service account holds no role assignments, so every data-plane call 403s until an admin grants one via `POST /api/v1/vaults/{vault_name}/role-assignments` (see step 2 below). `access_policies` does not unlock this — it survives only as an explicit-deny override evaluated *before* the role-assignment check, and managing a policy (create/update/delete/list/get) itself now requires the `admin` role (`api/access_policies.go`: `requireAccessPolicyAdmin`).
- Once a role assignment grants access, the flat `/api/v1/secrets/{id}` route and its vault-scoped equivalent grant identical visibility — both resolve to a vault scope (`scopeFromRequest` in `api/context.go` returns `model.NewVaultScope` for every route shape), so any vault member with the matching role assignment can reach a secret regardless of who created it. This is a change from an earlier owner-scoped restriction on flat routes, retired 2026-08-16 as a security fix (`.claude/known-bugs.md` § B11) after it was found to let a caller keep reading/writing resources it had created in a *different* vault even once that vault's role assignment was revoked.

### Example

```bash
# 1. Create the service account (admin JWT required). client_secret is returned once.
curl -s -X POST http://localhost:8774/api/v1/service-accounts \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name":"my-app","description":"My application service account"}'
# → {"id":"<uuid>","name":"my-app","description":"...","enabled":true,
#    "created_at":"...","expires_at":null,"client_secret":"<64-hex, shown once>"}

SA_ID=<id from response>
CLIENT_SECRET=<client_secret from response>

# 2. Grant it a role in the vault (admin JWT required) so PolicyMiddleware's
# deny-by-default check lets it through. "Key Vault Secrets User" grants
# get/list on secrets only. `principal` must be the service account's UUID:
# resolvePrincipal only resolves a bare UUID or a human username, never a
# service-account name.
curl -s -X POST http://localhost:8774/api/v1/vaults/default/role-assignments \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d "{\"principal\":\"$SA_ID\",\"principal_type\":\"service_account\",\"role\":\"Key Vault Secrets User\"}"

# 3. Exchange client credentials for an access token (public endpoint, no admin JWT needed).
curl -s -X POST http://localhost:8774/api/v1/oauth2/token \
  -u "my-app:$CLIENT_SECRET" \
  -d "grant_type=client_credentials"
# → {"access_token":"<jwt>","token_type":"Bearer","expires_in":1800}

# 4. Use the token like any other bearer token. The flat route below and its
# vault-scoped equivalent grant identical, vault-member "see all" visibility
# — the role assignment from step 2 is what matters, not who created the
# secret, so this also returns an admin-created secret as long as the grant
# covers the secret's vault (the default vault here):
#   GET /api/v1/vaults/<vault_name>/secrets/<secret_id>
curl -s http://localhost:8774/api/v1/secrets/<secret_id> \
  -H "Authorization: Bearer <access_token>"

# Rotate or delete when needed (admin JWT required).
curl -s -X POST http://localhost:8774/api/v1/service-accounts/$SA_ID/rotate -H "Authorization: Bearer $TOKEN"
curl -s -X DELETE http://localhost:8774/api/v1/service-accounts/$SA_ID -H "Authorization: Bearer $TOKEN"
```

### Notes & gotchas

- `grant_type` must be exactly `client_credentials` (`400 unsupported_grant_type` otherwise), and the request body must have `Content-Type: application/x-www-form-urlencoded` — a different content type is rejected with `400 invalid_request` before the body is even parsed (`api/oauth2.go`, `tokenHandler`).
- `client_id` is the service account's **name** (e.g. `my-app`), not its UUID — `IssueToken` resolves the client with `FindByName`. The UUID (`service_account_id`) is only used on the management endpoints (`GET`/`DELETE /service-accounts/{id}`, `POST /service-accounts/{id}/rotate`).
- Credentials can be sent as HTTP Basic (`-u client_id:client_secret`) or as `client_id` / `client_secret` form fields. Basic auth is checked first and takes priority if both are present (`extractClientCredentials`).
- Invalid credentials, a disabled service account, and an expired service account all return the same generic `401 invalid_client` — this is intentional, to prevent credential enumeration (`internal/services/oauth2/oauth2_service.go`, `IssueToken`).
- Deleting or disabling a service account invalidates its outstanding tokens immediately: `ValidateSession` re-checks the client record on every request (using the JWT `jti`, which is set to the client's UUID at issuance), not just at token issuance (`internal/services/auth/authentication_service.go`).
- A service account gets exactly the data actions its role assignments grant — nothing implicit. `Key Vault Secrets User` (granted in step 2) covers `get`/`list` on secrets only, so a write attempt (`POST`/`PUT` on `/secrets`) is denied by `PolicyMiddleware`'s deny-by-default check — `HasDataAction` finds no assignment granting `secrets/setSecret/action` — before `AuthorizationMiddleware` is even reached. `AuthorizationMiddleware` no longer gates vault data-plane routes at all: `mapEndpointToPermission` (`internal/services/authorization/rbac_service.go`) returns `""` for every one of them, deferring entirely to the role-assignment check; the `service_account` role's `get`/`list` permission bundle in that file is legacy and has no effect on these routes. An explicit `deny` access policy for the principal, if one exists, is still evaluated first and would short-circuit with 403 regardless of the role assignment.
- The `/oauth2/token` route is registered on its own router with `CORSMiddleware` and `RateLimitMiddleware` attached (`api/api.go`, `InitOAuth2`). Unlike `/api/v1/service-accounts` and other authenticated routes, it does **not** go through `AuthenticationMiddleware`, `VaultResolutionMiddleware`, `PolicyMiddleware`, or `AuthorizationMiddleware`. `RateLimitMiddleware` special-cases the `/oauth2/token` path suffix to apply its stricter auth-endpoint limit, and — unlike the earlier state of this router — that middleware is now actually attached here, so the stricter limit is enforced; every request (success or failure) also writes an audit log entry.

**Deep dive:** [docs/consuming-secrets-guide.md](consuming-secrets-guide.html) and [Admin Manual — OAuth2 Service Accounts](admin-manual.html#service-accounts).

---

If the consuming application is itself written in Go, you don't have to hand-roll the token exchange — there's a client library for that.

## 4. Vault Client library (embedded secret consumption)

**What it is:** A Go package (`rocketvault/internal/vaultclient`) that authenticates to a running RocketVault server via OAuth2 client-credentials and fetches secret values by UUID, with token caching and automatic retry. It's designed to be embedded directly into a Go application's startup path — RocketVault itself uses it to bootstrap its own config, and `examples/consumer-service` shows an external consumer.

**Use it when:**

- You're writing a Go service that needs one or more RocketVault secrets injected at process startup (env-style, not per-request).
- You want the fetch to be retried on transient network errors but to fail fast on auth (401) or missing-secret (404) errors.
- You want secret values wired straight into Viper config keys instead of handled manually — the pattern `bootstrap/secrets_initializer.go` uses for RocketVault's own config.
- Direct HTTP or a shell helper isn't a good fit because you're already in Go and want typed config plus token caching for free.

**Prerequisites:**

- A running RocketVault server and its base URL (e.g. `http://localhost:8774`).
- A service account (OAuth2 client) already created **and granted a per-vault role assignment** (e.g. `Key Vault Secrets User`) carrying `get` / `list` on `secrets` in the target vault — a fresh service account holds no role assignments and every data-plane call 403s until one is granted via `POST /api/v1/vaults/{vault_name}/role-assignments` (see section 3, step 2). An access policy does not grant this on its own — it survives only as an explicit-deny override evaluated before the role-assignment check (see section 3) — service accounts are read-only consumers; only admins create secrets (see `docs/consuming-secrets-guide.md` Steps 1–2a).
- By default (`Config.Vault` / the `vault_client.vault` Viper key left unset), `vaultclient.Client.Get` calls the flat path `c.cfg.URL + "/api/v1/secrets/" + uuid` (`secretURL` in `internal/vaultclient/client.go`), which resolves to the `default` vault and is owner-scoped — the same 404-on-admin-owned-secret trap as the raw curl example in section 3. Set `Config.Vault` (or `vault_client.vault`) to the target vault's name and the client instead calls `c.cfg.URL + "/api/v1/vaults/{vault}/secrets/" + uuid`, which grants vault-member visibility with no per-owner filter — this is the way to fetch a secret the service account doesn't itself own (see `docs/consuming-secrets-guide.md` Step 3, Option A and its Troubleshooting section E).
- The service account's **name** (not UUID) as `client_id`.
- The service account's `client_secret` — best supplied via the `VAULT_CLIENT_SECRET` environment variable rather than committed to a config file, though `vaultclient.NewFromViper` will also read `vault_client.client_secret` from Viper if it's set there, falling back to the env var only when it's empty.
- The UUID of each secret you intend to fetch.

### Example

Config block (`vault_client` in `.rocketvault.yaml`, or an equivalent block in your own app's config — see `examples/consumer-service/config.yaml` for the consumer-side `vault:` shape):

```yaml
vault_client:
  url: "http://localhost:8774"
  client_id: ""   # service account NAME (not UUID) — leave empty on the vault server itself
  allow_insecure_http: false   # set true (or VAULT_ALLOW_INSECURE_HTTP=true) to use http:// against a non-loopback host
  vault: ""   # optional — target vault name; omit or leave blank to use the flat, default-vault, owner-scoped route
  secrets:
    - name: DB_PASSWORD
      uuid: "0cfa58f7-a81e-4a68-acd7-b62f5f72e5b7"
      viper_key: "database.password"
```

Building and using the client directly in Go:

```go
import (
    "context"
    "log"
    "os"

    "rocketvault/internal/vaultclient"
)

client, err := vaultclient.New(vaultclient.Config{
    URL:          "http://localhost:8774",
    ClientID:     "my-app",                          // service account name
    ClientSecret: os.Getenv("VAULT_CLIENT_SECRET"),   // env var only, never in config
    Vault:        "",                                 // optional — e.g. "prod-vault"; empty uses the flat, owner-scoped route
    Secrets: []vaultclient.SecretMapping{
        {Name: "DB_PASSWORD", UUID: "0cfa58f7-a81e-4a68-acd7-b62f5f72e5b7"},
    },
})
if err != nil {
    log.Fatalf("vault client: %v", err)
}

secrets, err := client.GetMany(context.Background(), []string{"DB_PASSWORD"})
if err != nil {
    log.Fatalf("vault fetch: %v", err)
}
dbPassword := secrets["DB_PASSWORD"]
```

Or build straight from Viper config (reads the `vault_client.*` keys shown above, falling back to `VAULT_CLIENT_SECRET` if `vault_client.client_secret` is unset):

```go
client, err := vaultclient.NewFromViper()
```

Or from environment variables only (`VAULT_URL`, `VAULT_CLIENT_ID`, `VAULT_CLIENT_SECRET`):

```go
client, err := vaultclient.NewFromEnv()
```

RocketVault's own bootstrap (`bootstrap/bootstrap.go`) uses this exact pattern to inject secrets into Viper before the service container reads any config: it builds a client with `vaultclient.NewFromViper()`, wraps it in `bootstrap.NewSecretsInitializerFromMappings(client, mappings)`, and calls `Initialize(ctx)`, which fetches each `vault_client.secrets[].name` and calls `viper.Set(viper_key, value)` for each configured `viper_key`. This step is skipped entirely if `vault_client.url`, `vault_client.client_id`, or the resolved client secret is empty.

### Notes & gotchas

- `vaultclient.New` requires `URL`, `ClientID`, and `ClientSecret` to all be non-empty — it returns an error immediately otherwise (`internal/vaultclient/client.go`).
- `vault_client.url` must be `https://`, unless the host is loopback (`localhost`, `127.0.0.1`, `::1`) or `allow_insecure_http` (`VAULT_ALLOW_INSECURE_HTTP` env var) is `true`; default is `false`. **Upgrade note:** an existing deployment with a non-loopback plain-`http://` `vault_client.url` must switch to `https://` or set `allow_insecure_http: true` before upgrading, or RocketVault will fail to start.
- Tokens are fetched from `POST {url}/api/v1/oauth2/token` (client-credentials grant) and cached in memory. The client re-authenticates about 60 s before expiry, with a 30 s minimum TTL floor so an `expires_in: 0` response can't cause a re-fetch storm.
- `Client.Get` retries network failures and every HTTP status other than 200, 401 and 404 (so 400, 403, 429 and 5xx are all retried) using `retry.ExternalServicePolicy()`; only 401 and 404 are terminal — no retry. A 401 also invalidates the cached token so the *next* call re-authenticates.
- Optional `Config.Logger` (an interface with a single `Warn(msg string, keysAndValues ...any)` method, not settable via YAML/Viper) receives a call on every retried failure and auth rejection, for observability into what would otherwise be silent retries. A nil `Logger` — the default — disables this logging; the client behaves identically either way.
- 401 responses surface as `vaultclient.ErrAuthFailed`; 404 responses surface as `vaultclient.ErrSecretNotFound` — both are terminal immediately, no retry. Once retries *are* exhausted, a transport-level failure (DNS, connection refused, timeout, TLS) surfaces as `vaultclient.ErrNetwork` and an unrecognized HTTP status as `vaultclient.ErrUnexpectedStatus` — those two are the ones actually retried. An undecodable 200 body surfaces as `vaultclient.ErrDecodeFailed` immediately, with no retry either, since a malformed body on a successful status is treated as a permanent incompatibility rather than a transient failure. Check any of these with `errors.Is`, as `examples/consumer-service/main.go` does for `ErrAuthFailed` — it treats that one as fatal (process exit) but a 404 or network error on an individual secret as non-fatal.
- `GetByName` / `GetMany` resolve names to UUIDs using the `Secrets []SecretMapping` you passed into `Config`; a name with no matching mapping errors out before any HTTP call is made.
- On RocketVault's own server, `vault_client.client_id` must stay `""` — the server must never call itself. `bootstrap.go` gates the entire secrets-injection step on `client_id`, `url`, and the client secret all being non-empty, so leaving `client_id` blank cleanly disables it.
- `client_secret` is deliberately absent from `SecretMapping` and the YAML example above — it must come from the `VAULT_CLIENT_SECRET` environment variable (or `vault_client.client_secret` in Viper, which `NewFromViper` prefers before falling back to the env var).
- Secret values are never logged by the client; only names are used in log and error messages.

**Deep dive:** [docs/consuming-secrets-guide.md](consuming-secrets-guide.html) — see "Option A — Go application using the `vaultclient` package", plus the full service-account creation and access-policy walkthrough and the Troubleshooting table.

---

Consuming secrets is one half of integration; the other half is letting *other* services validate the tokens RocketVault issues.

## 5. JWKS endpoint (token verification by external services)

**What it is:** `GET /jwks.json` serves an RFC 7517 JSON Web Key Set containing RocketVault's active JWT-signing public key(s), so other services can verify RocketVault-issued access tokens locally (offline) without calling back into RocketVault on every request.

**Use it when:**

- An API gateway, sidecar, or downstream microservice needs to validate a RocketVault-issued JWT's signature without a round-trip to RocketVault.
- You are integrating RocketVault as an OAuth2/OIDC-style token issuer (`oauth2.issuer`) into a broader auth ecosystem that expects a standard JWKS document.
- You run `jwt.key_source: self_pki` and need to rotate the signing key at runtime, having consumers pick up the new key automatically via JWKS polling.
- You need to confirm which algorithm (RS256, ES256, and so on) and `kid` a given RocketVault deployment is currently signing with.

**Prerequisites:**

- No authentication is required to fetch `GET /jwks.json` — it is registered directly on the root router and only has CORS and security-headers middleware applied (`mw.CORSMiddleware`, `mw.SecurityHeadersMiddleware`), bypassing the authentication/authorization chain used by `/api/v1/*` (`api/api.go`, `api/jwks.go`).
- `jwt.key_source` in `.rocketvault.yaml` (`os_store` | `self_pki` | `external_pki`) determines which signing algorithm shows up in the JWKS document (`internal/signing/provider.go`).
- To rotate keys via `POST /api/v1/jwks/rotate`, you need a valid bearer token for a user with the `admin` role — this route lives under `ApiRoot`, which runs `AuthenticationMiddleware`, and the handler itself rejects non-admin callers (`api/api.go`, `api/jwks.go`) — and it is only usable when `jwt.key_source: self_pki` is active.

### Example

Fetch the JWK Set (no auth needed):

```bash
curl http://localhost:8774/jwks.json
```

Example response shape (RSA key, `os_store` source):

```json
{
  "keys": [
    {
      "kty": "RSA",
      "use": "sig",
      "alg": "RS256",
      "kid": "3f9a1c2e7b804d11",
      "n": "...",
      "e": "AQAB"
    }
  ]
}
```

Example response shape (ECDSA key, `self_pki` source):

```json
{
  "keys": [
    {
      "kty": "EC",
      "use": "sig",
      "alg": "ES256",
      "kid": "9a02b7f31de44c88",
      "crv": "P-256",
      "x": "...",
      "y": "..."
    }
  ]
}
```

Rotate the signing key (`self_pki` only, requires an admin bearer token):

```bash
curl -X POST http://localhost:8774/api/v1/jwks/rotate \
  -H "Authorization: Bearer $TOKEN"
```

Response: `{"status":"ok","new_kid":"<new-kid>","overlap_until":"<RFC3339 timestamp>"}` (`api/jwks.go`).

### Notes & gotchas

- The algorithm in the JWKS document depends on `jwt.key_source` (`.rocketvault.yaml`, `internal/signing/provider.go`):
  - `os_store` — auto-generates or loads an RSA-2048 key from the OS keychain (falling back to a PEM file under `~/.local/share/rocketvault/` if the keychain is unavailable) → `RS256` (`internal/signing/os_store.go`).
  - `self_pki` — stores an ECDSA P-256 key in RocketVault's own encrypted key store → `ES256`, and supports runtime rotation (`internal/signing/self_pki.go`).
  - `external_pki` — loads a PEM private key from the `ROCKETVAULT_JWT_SIGNING_KEY` env var (base64-encoded) or the `jwt.signing_key_file` path; the algorithm is auto-detected (`RS256` for RSA, `ES256`/`ES384`/`ES512` for EC curves P-256/P-384/P-521). No runtime rotation — operators must replace the key file and restart (`internal/signing/external_pki.go`).
- `kid` is computed as the first 16 hex characters of the SHA-256 thumbprint of the DER-encoded public key (`internal/signing/external_pki.go`, `thumbprint`).
- The response sets `Cache-Control: public, max-age=3600`, so it is safe — and intended — for consumers to cache the JWKS document for up to an hour rather than fetching it on every token verification (`api/jwks.go`).
- If the signing provider failed to initialize, `GET /jwks.json` returns HTTP 503 with `{"error":"signing provider not available"}` instead of a JWK Set (`api/jwks.go`).
- `POST /api/v1/jwks/rotate` only works when the active provider implements rotation (currently only `self_pki`); calling it under `os_store` or `external_pki` returns HTTP 400 with `"key rotation is only supported for the self_pki key source"` (`api/jwks.go`).
- After a rotation, the *previous* key stays listed in `/jwks.json` alongside the new one for `jwt.rotation_overlap` (`.rocketvault.yaml`, default `1h` if unset or unparseable) so tokens signed just before rotation still verify. Plan JWKS polling and cache TTLs shorter than this overlap window (`internal/signing/self_pki.go`).
- `/jwks/rotate` has no route-specific entry in the RBAC endpoint map (`internal/services/authorization/rbac_service.go`, `mapEndpointToPermission`), so `AuthorizationMiddleware` itself does not gate this route by role — but the handler enforces admin-only directly: `rotateJWKS` checks `common.HasAnyRole(c.Claims.Roles, model.RoleAdmin)` and returns a permission error for any non-admin caller before rotating anything (`api/jwks.go`). A failed or successful rotation attempt is also recorded via the audit service (`recordJWKSRotateAudit`, `api/jwks.go`).
- Tokens issued by RocketVault carry `iss` set to the `oauth2.issuer` config value (currently `http://localhost:8774` in the committed `.rocketvault.yaml.example` — there is no code-level default; an unset `oauth2.issuer` means an empty `iss` claim) and `aud` hardcoded to `"PASSWORD_MANAGER"` (`internal/container/service_container.go`) — external verifiers should check both claims in addition to the signature.

**Deep dive:** [Admin Manual — JWT Signing & Key Sources](admin-manual.html#jwt-signing).

---

Beyond day-to-day access, RocketVault has operational surfaces too. The first is getting data safely in and out.

## 6. Backup / restore tooling

**What it is:** RocketVault ships two independent backup mechanisms: a CLI-driven **full database backup/restore** (`rocketvault backup create|list|restore`, in `cmd/backup.go` and `internal/backup/backup.go`), and a set of **per-item backup/restore API endpoints** for individual secrets, keys, and certificates (`api/backup_item.go`, `internal/backup/item_backup.go`).

**Use it when:**

- You need a full point-in-time snapshot of every table before an upgrade, migration, or risky bulk change.
- You want to disaster-recover an entire vault database from a `.backup` file.
- You need to export or import a *single* secret, key, or certificate — for example to hand a copy to another owner, or to duplicate an item under a new ID — without touching the rest of the database.
- You want to audit what backups exist in a directory before deciding which to restore.

**Prerequisites:**

- Full-database backup: an **admin** CLI login — either flags (`--username`/`--password`/`--totp-code`) on the command itself, or a cached session from a prior `rocketvault users login` / `rocketvault users login --oidc` (section 1) — plus a running database connection (the CLI reads `database.driver` from config to pick the SQL dialect — `sqlite3` or `postgres`) and, for encrypted backups (the default), a valid `master_key` in `.rocketvault.yaml` (`common.EncryptSecret` / `DecryptSecret` use `viper.GetString("master_key")`). `backup` isn't in `persistentPreRun`'s `systemCmds` map, so it goes through the same `resolveAuthentication` path as every other data-touching command — no special-casing.
- Per-item backup/restore: a valid JWT bearer token (`ApiSessionRequired` on every route). These routes are also deny-by-default vault data-plane routes as of the v4.0.0 Azure RBAC pass — `PolicyMiddleware` requires a role assignment granting the matching data action (`Microsoft.KeyVault/vaults/secrets/backup/action` / `.../restore/action`, and the keys/certificates equivalents; see `internal/services/authorization/data_actions.go`, `mapSecretAction`/`mapKeyAction`/`mapCertificateAction`). `InitBackupItem` registers each handler on both the legacy flat subrouters and the vault-scoped subrouter (`api/backup_item.go`, `registerBackupItemRoutes`), so both URL shapes resolve to the same handlers and that grant is checked against whichever vault `VaultResolutionMiddleware` resolves for the request — the **default vault** on a flat route, the named vault on a vault-scoped one — and a successful restore writes the item into that same resolved vault regardless of any `vault_id` embedded in the blob (see the restore gotcha below). On top of the RBAC check, `ItemBackupService` scopes its read to the vault the request was authorized against (`model.NewVaultScope`) — a caller can back up any item in that vault they hold the matching backup action for, whether or not they own it; naming an item in a different vault reports not-found rather than forbidden. Restore behaves the same way: any caller who holds the required role assignment can restore any blob it obtains, and the restored item is simply re-owned to that caller.

### Example

**Full database backup (CLI)**

```bash
# Every backup subcommand requires an admin login. The flags below authenticate
# inline; if you've already run `rocketvault users login` (or `--oidc` for an
# OIDC-provisioned admin), drop $AUTH entirely and the cached session is used.
AUTH="--username admin --password admin123 --totp-code 123456"

# Create an encrypted backup (default; --file/-f is required)
go run main.go backup create --file ./backups/backup-2026-07-25.backup $AUTH

# Create an unencrypted backup
go run main.go backup create --file ./backups/backup-plain.backup --encrypt=false $AUTH

# List backup files in a directory (defaults to ./backups)
go run main.go backup list --dir ./backups $AUTH

# Restore from an encrypted backup (destructive — replaces ALL existing data)
go run main.go backup restore --file ./backups/backup-2026-07-25.backup $AUTH
# Prompts: "Are you sure you want to continue? (type 'yes' to confirm):"

# Restore from an unencrypted backup, non-interactively
echo yes | go run main.go backup restore --file ./backups/backup-plain.backup --decrypt=false $AUTH
```

**Per-item backup/restore (API, one JSON blob per item)**

Both URL shapes work and resolve to the identical handlers — the legacy flat form and the vault-scoped form — per `InitBackupItem` in `api/backup_item.go`:

```bash
# Backup a single secret — returns {"blob": "rvb2.<sealed envelope>"}
curl -X POST http://localhost:8774/api/v1/secrets/<secret_id>/backup \
  -H "Authorization: Bearer <token>"

# Restore it — creates a NEW secret under a freshly generated ID
curl -X POST http://localhost:8774/api/v1/secrets/restore \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{"blob": "<blob-from-above>"}'

# Same pattern for keys and certificates:
#   POST http://localhost:8774/api/v1/keys/<key_id>/backup                  POST http://localhost:8774/api/v1/keys/restore
#   POST http://localhost:8774/api/v1/certificates/<certificate_id>/backup  POST http://localhost:8774/api/v1/certificates/restore

# The vault-scoped path shape works identically for all three resource types,
# scoped to a named vault instead of the default vault:
curl -X POST http://localhost:8774/api/v1/vaults/<vault_name>/secrets/<secret_id>/backup \
  -H "Authorization: Bearer <token>"
curl -X POST http://localhost:8774/api/v1/vaults/<vault_name>/secrets/restore \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{"blob": "<blob-from-above>"}'
#   POST http://localhost:8774/api/v1/vaults/<vault_name>/keys/<key_id>/backup                  POST http://localhost:8774/api/v1/vaults/<vault_name>/keys/restore
#   POST http://localhost:8774/api/v1/vaults/<vault_name>/certificates/<certificate_id>/backup  POST http://localhost:8774/api/v1/vaults/<vault_name>/certificates/restore
```

### Notes & gotchas

- **Full backups are all-or-nothing, and restore order is FK-dependency-aware, not alphabetical.** `backup restore` (`internal/backup/backup.go`, `RestoreBackup`) clears and reloads every table inside a single transaction: it deletes tables in reverse topological order (children before parents), then re-inserts them in topological order (parents before children), per the FK dependency map in `internal/backup/table_order.go` (`topologicalOrder`, `insertTableData`) — not the backup file's own table order. This matters most on Postgres, which enforces FK constraints mid-transaction; SQLite's `foreign_keys` pragma is off by default, so the same restore was silently safe there even before this ordering existed. It does not merge or skip tables, and it requires typing `yes` at the interactive confirmation prompt (or piping `yes` via stdin, as shown above).
- **`backup list` shows every backup file, including encrypted or corrupt ones, with honest gaps for what it can't determine.** `getBackupMetadata` only reads the payload (timestamp, version, table/record counts) when the file's content parses as plaintext backup JSON; a file that can't be read that way — a normal encrypted backup, or a genuinely corrupt file — still appears in the listing with its filesystem-derived metadata (filename, size, modified time), and `-` in place of the payload columns it can't determine without the master key.
- **Backup encryption reuses the same `master_key`** used for secret-value encryption elsewhere in the app — if `master_key` changes or is lost, previously encrypted backups can no longer be decrypted.
- **Full-backup table discovery is dialect-aware.** SQLite backups query `sqlite_master` / `PRAGMA table_info`, Postgres backups query `information_schema.tables` / `information_schema.columns`; the dialect is derived from `database.driver` in `.rocketvault.yaml`, not from a CLI flag.
- **Per-item backup blobs are sealed.** `sealBlob` / `openBlob` in `internal/backup/blob_seal.go` encrypt the base64url JSON envelope with AES-256-GCM under a key derived from the master key (HKDF-SHA256) and prefix the result with `rvb2.`. Restore accepts only a blob this server produced, unmodified, on an instance with the same master key; a blob without the prefix (taken before sealing, or written by hand), a modified blob, or one sealed under another master key is refused with 400. Anyone holding the master key can still open a blob, so treat it as sensitive data, not as a portable export format. A certificate restored into a vault where its key or signing CA does not resolve loses those links, and key and certificate restore still force `exportable` to false.
- **Per-item restore always allocates a new ID, and always targets the caller's authorized vault, not the blob's.** The API handlers call `svc.RestoreSecret` / `RestoreKey` / `RestoreCertificate` with a freshly generated `uuid.New()`, so restoring a blob never overwrites the original item — it creates a duplicate owned by the caller. All three methods also take the vault from `vaultIDFromRequest` (the request's authorized vault — the default vault on a flat route, or the named vault on a vault-scoped route) and write that onto the new item, ignoring any `vault_id` embedded in the blob; otherwise a caller with restore permission in one vault could use someone else's blob to write into any vault it happened to reference. Fixed by commit `c5bf97d`, tracked as `.claude/known-bugs.md` § B15.
- **Per-item backup/restore is registered on both the flat and vault-scoped routers, and is RBAC-gated with a vault-scoped read on the backup side.** `InitBackupItem` (`api/backup_item.go`) attaches the same handlers to `BaseRoutes.Secrets`/`Keys`/`Certificates` (flat) and to `BaseRoutes.VaultScoped` (`/vaults/{vault_name}/...`), so both URL shapes resolve identically for all three resource types. As of the v4.0.0 Azure RBAC pass, `PolicyMiddleware` deny-by-defaults these routes on the matching `ActionSecretsBackup`/`ActionSecretsRestore` (or keys/certificates equivalent) data action, checked against whichever vault is resolved for the request — the default vault on a flat route, the named vault on a vault-scoped route — so a caller first needs a role assignment granting that action in that vault. `ItemBackupService` additionally scopes its read to that same vault: a caller can back up any item in it they hold the backup action for, whether or not they own it, and an item in a different vault reports not-found rather than forbidden. Restore has the same shape — any caller who holds the required role assignment can restore any blob it obtains, and the item is simply re-owned to that caller. There is no separate ownership gate anymore: `backup.ErrForbidden` and the old owner-comparison check were removed once the scoped read took over as the authorization boundary (`internal/backup/item_backup.go`) — a non-owner who holds the matching backup/restore action in the vault is allowed, and naming an item in a vault the caller isn't authorized for reports not-found, never forbidden.
- **`backup create`/`list`/`restore` require an admin login.** This was previously a real gap — `backup` was listed in `persistentPreRun`'s `systemCmds` map in `cmd/root.go`, so none of the three subcommands required `--username`/`--password`/`--totp-code`, unlike every other data-touching CLI command. That's fixed: `backup` was removed from `systemCmds`, and each subcommand now calls `requireBackupAdmin` (`cmd/backup.go`), rejecting the request before touching the database unless the caller is logged in as the global `admin` role. There's no per-vault equivalent for this check — a full-database backup has no vault to scope it to, so `admin` is the only applicable gate, same as `users`/`vaults`/`migrate`. Because that fix routes `backup` through the normal (non-system) `persistentPreRun` path, it also picked up the CLI session cache and `--oidc` login for free when those landed later — an admin who ran `rocketvault users login` (password or OIDC) once doesn't need to repeat `--username`/`--password`/`--totp-code` on every `backup` invocation.
- Restoring a blob whose `resource_type` doesn't match the endpoint (for example, posting a key blob to `/api/v1/secrets/restore`) is rejected as an invalid-blob error, not silently coerced.
- **Key backups now carry version history (fixed 2026-08-19).** A key's backup blob previously carried only its current row, so backing up and restoring a rotated key silently dropped every archived `key_versions` entry — reintroducing the "old ciphertext unusable" bug tracked as `.claude/known-bugs.md` § B26, via the backup path instead of rotation. `BackupKey` now includes the key's full version history in the blob's envelope (a purely additive `versions` field), and `RestoreKey` replays it under the new key's ID, so a restored key keeps every version usable, matching the crypto-endpoint fix in section 2. Backward compatible: a blob taken before this change simply has no `versions` field and still restores exactly as before — just without version history. `RestoreKey` replays versions *before* applying purge protection (fixed 2026-08-20, commit `8225680`, matching the same order `RestoreSecret` uses below) — restores aren't transactional, so writing purge protection first and then hitting a failed version replay would have stranded the partial restore under an ID the caller never received, since `PurgeKey` refuses to delete a protected key.
- **Secret backups now carry version history (fixed 2026-08-20).** A secret's backup blob previously carried only its current row, so backing up and restoring a secret with archived versions silently dropped all of them, with no error — tracked as `.claude/known-bugs.md` § B29. `BackupSecret` now includes the secret's full version history in the blob's envelope (a purely additive `secret_versions` field), and `RestoreSecret` replays it under the new secret's ID, so a restored secret keeps every historical value. Backward compatible: a blob taken before this change simply has no `secret_versions` field and still restores exactly as before — just without version history. `RestoreSecret` also replays versions before applying purge protection, for the same reason as the key path above.

**Deep dive:** [Admin Manual — Backup & Restore](admin-manual.html#backup).

---

The second operational surface is telling your orchestrator and metrics stack whether the instance is healthy.

## 7. Health / monitoring integration

**What it is:** RocketVault exposes four HTTP health endpoints under `/api/v1/health` (liveness, readiness, detailed system metrics, and database health — three of them unauthenticated), plus an unversioned `GET /metrics` Prometheus scrape endpoint that exposes a `HistogramVec` of key-crypto operation latency, a set of `rocketvault_db_*` connection/query gauges, and a per-vault rate-limit rejection counter, so you can wire it into container orchestrators, load balancers, and metrics scrapers.

**Use it when:**

- Configuring Kubernetes or Docker liveness and readiness probes.
- Wiring a load balancer or uptime checker to detect a dead or degraded instance.
- Diagnosing connection-pool exhaustion or slow queries in production.
- Instrumenting p50/p95/p99 latency for `Sign` / `Verify` / `Encrypt` / `Decrypt` / `WrapKey` / `UnwrapKey`, and validating that the in-process key cache is actually reducing latency (via the `cache_hit` label).
- Scraping crypto-latency and database-performance gauges into Prometheus via `GET /metrics`.
- Alerting on noisy-neighbour vaults, via the `rocketvault_vault_rate_limit_exceeded_total{vault}` counter.

**Prerequisites:**

- A running RocketVault server (`go run main.go serve`). Bind-address precedence (fixed 2026-08-18, commit `e630029`): an explicit `--listen` flag wins, then `server.listen_addr` from `.rocketvault.yaml` (applied in `servePreRun`, `cmd/serve.go`), then the `PASSWORD_MANAGER_LISTEN` env var, then the hardcoded `defaultListenAddr` fallback `127.0.0.1:8774`. `.rocketvault.yaml` is gitignored and generated per clone from `.rocketvault.yaml.example`, which sets `server.listen_addr: ":8774"` — so unless you edited it, the effective default with no `--listen` flag is `:8774` (all interfaces), not the loopback-only hardcoded fallback. `http://localhost:8774` in the examples below reaches it either way. The server listens under base path `/api/v1` (hardcoded in `cmd/serve.go`, overridable with the `--api_base` flag or the `PASSWORD_MANAGER_BASE_API` env var).
- For `/api/v1/health/database`: a valid `Authorization: Bearer <jwt>` header from any authenticated user (no specific role or permission is required — see the gotchas below). For `/api/v1/health`, `/api/v1/health/ready`, and `/api/v1/health/live`: no token needed. `GET /metrics` needs no token either, since it bypasses the API's middleware chain entirely (see the gotchas).
- Nothing extra is required to *record* crypto-latency samples — the histogram is wired into `CryptoService`'s operations automatically via the service container (`internal/services/keys/crypto_service.go`). To *scrape* them over HTTP, `monitoring.enable_metrics` must be `true` (the built-in default, and what `.rocketvault.yaml.example` ships) — see the gotchas for exactly what `/metrics` exposes.

### Example

Liveness probe (always 200 if the process is up; no auth, no DB check):

```bash
curl -s http://localhost:8774/api/v1/health/live
# {"status":"alive"}
```

Readiness probe (200 if metrics can be collected, 503 with `{"status":"not ready", ...}` otherwise):

```bash
curl -s -o /dev/null -w '%{http_code}\n' http://localhost:8774/api/v1/health/ready
```

Comprehensive system health (memory, GC, goroutines, DB pool stats, query metrics):

```bash
curl -s http://localhost:8774/api/v1/health | jq .
```

Database-specific health check (connectivity ping, pool utilization, slow-query ratio, and a live `SELECT COUNT(*) FROM users` probe) — requires a bearer token:

```bash
TOKEN=$(curl -s -X POST http://localhost:8774/api/v1/users/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"admin123","totp_code":"123456"}' | jq -r .token)

curl -s -H "Authorization: Bearer $TOKEN" http://localhost:8774/api/v1/health/database | jq .
```

Kubernetes probe wiring (paths only — adjust port and scheme to your deployment):

```yaml
livenessProbe:
  httpGet:
    path: /api/v1/health/live
    port: 8774
readinessProbe:
  httpGet:
    path: /api/v1/health/ready
    port: 8774
```

Prometheus scrape endpoint (unversioned path, no auth, only mounted when `monitoring.enable_metrics` is `true`):

```bash
curl -s http://localhost:8774/metrics | grep '^rocketvault_'
```

Standing up Prometheus against it. Nothing needs installing on the RocketVault side — the exporter is compiled in — so this is just a scraper pointed at the endpoint. `prometheus.yml` at the repo root already targets `rocketvault:8774`, and `docker-compose.yml` carries a matching service behind the `metrics` profile, so it stays out of a plain `docker compose up`:

```bash
docker compose --profile metrics up --build
# then confirm the target reads UP:
open http://localhost:9090/targets
```

Outside compose, point `static_configs.targets` at `localhost:8774` instead and run Prometheus however you normally would:

```bash
docker run --rm -p 9090:9090 \
  -v "$PWD/prometheus.yml:/etc/prometheus/prometheus.yml:ro" \
  prom/prometheus:latest
```

Keep `scrape_interval` at or above `monitoring.metrics_interval` (60s by default). The `rocketvault_db_*` gauges only refresh on that internal ticker, so scraping faster just re-reads the same numbers.

### Notes & gotchas

- **Auth is asymmetric across the four `/api/v1/health/*` routes.** `AuthenticationMiddleware` and `AuthorizationMiddleware` in `internal/middleware/middleware.go` explicitly skip `/health`, `/health/ready`, and `/health/live` — those three are always public. `/health/database` is *not* in that skip list, so it requires a valid `Authorization: Bearer` token like any other API route. However, `RBACService.mapEndpointToPermission` has no mapping for `/health/*`, so once authenticated, any role (`admin` or `user`) is allowed through `AuthorizationMiddleware` — there's no dedicated "health-check" permission to grant or revoke.
- **`/api/v1/health/*` endpoints are still rate-limited; `/metrics` is not.** The four health routes hang off `ApiRoot`, which carries `RateLimitMiddleware` like every other route (the default limiter is `rate_limit.default: 300` requests/min per IP in `.rocketvault.yaml`) — aggressive external probing, e.g. multiple load balancers polling from the same NAT'd IP, can hit `429 Too Many Requests`, with no per-endpoint exemption for health checks. `GET /metrics`, by contrast, is registered directly on the root router (`api/api.go`: `r.Metrics = api.rootRouter.NewRoute().Subrouter()`), so it never passes through `ApiRoot`'s middleware chain at all — no CORS, no rate limiting, no authentication, regardless of role.
- **`/health/database` returns 503, not 200, on any degraded signal.** `api/health.go`'s `DatabaseCheck` maps a `status` of `"critical"`, `"degraded"`, or `"warning"` (computed in `internal/health.CheckDatabaseHealth`) to HTTP 503 — treat any non-200 as "needs attention", not just connection failures. Status-changing triggers are: a connection-pool wait count over 100 combined with wait duration over 100 ms (`warning`), slow queries exceeding 10% of total query count (`warning`), zero open connections (`critical`), a failed ping (`critical`), and a failing `SELECT COUNT(*) FROM users` probe (`degraded`). Ping latency over 50 ms only adds a `warnings` entry to the body — it does not change `status` and does not produce a 503.
- **`monitoring.*` keys are wired up; `health.*` keys are still dead stubs.** `config.LoadMonitoringConfig()` reads `monitoring.enable_metrics`, `monitoring.metrics_interval`, and `monitoring.slow_query_threshold`, and `bootstrap.Boot` applies all three: `enable_metrics` (default `true`; `true` in `.rocketvault.yaml.example`) gates whether `GET /metrics` is registered at all (`api/metrics.go`'s `InitMetrics`, called with `api.WithMetricsEnabled`) and whether the periodic DB-gauge collector starts; `metrics_interval` (default `60s`; `60s` in the example config) controls how often `internal/metrics.MetricsScheduler` refreshes the `rocketvault_db_*` gauges; `slow_query_threshold` (default `100ms`; `500ms` in the example config) is pushed into both `internal/db.SetSlowQueryThreshold` and `internal/health.SetDefaultSlowQueryThreshold`. `health.check_interval`, `health.database_timeout`, and `health.enable_detailed_metrics`, however, remain unread by any non-test code — the health handlers still always compute full metrics on every request, with no server-side polling interval or per-check timeout override.
- **`GET /metrics` exposes three independent instrument sets on Prometheus's default registry**, plus the standard `go_*` and `process_*` collectors that `promhttp.Handler()` picks up from that registry for free. `internal/metrics/crypto_metrics.go`'s `rocketvault_crypto_op_duration_seconds` `HistogramVec` (labels `op`, `key_type`, `cache_hit`; buckets `0.001`–`0.5`s) is populated in-process by `CryptoService.RecordOp` on every `Sign` / `Verify` / `Encrypt` / `Decrypt` / `WrapKey` / `UnwrapKey`. `internal/metrics/db_metrics.go`'s six `rocketvault_db_*` gauges (`query_count`, `slow_query_count`, `avg_query_time_ms`, `open_connections`, `connections_in_use`, `connections_idle`) are refreshed on a `monitoring.metrics_interval` ticker by `internal/metrics.MetricsScheduler`, started from `bootstrap.Boot` only when `monitoring.enable_metrics` is true. `internal/metrics/vault_rate_limit_metrics.go`'s `rocketvault_vault_rate_limit_exceeded_total` `CounterVec` (label `vault`) is incremented by `VaultRateLimitMiddleware` on every 429 from the per-vault token bucket. All three are absent from the response body when `monitoring.enable_metrics` is `false` (route unregistered, 404).
- **There are no HTTP-level metrics.** Nothing records request rate, request latency, or response status codes, so you cannot build a RED dashboard or alert on a 5xx spike from `/metrics` alone — the only request-shaped signal is the per-vault 429 counter. Derive availability from the `/api/v1/health/*` probes, or put request metrics on the reverse proxy in front.
- **`/metrics` leaks vault names.** `rocketvault_vault_rate_limit_exceeded_total`'s `vault` label carries real vault names, and the endpoint has no authentication of any kind. No secret material is exposed, but treat the endpoint as internal: bind it behind a firewall, an SSH tunnel, or a proxy that requires auth. `docker-compose.yml`'s optional `metrics` profile keeps its Prometheus on the internal `rocketvault_net` for exactly this reason.
- **`/health` (the base route) has no history or trend data.** Every field (`memory_usage`, `cpu_stats`, `database_stats`, `uptime`, `goroutines`, `query_metrics`, and so on, per `internal/health/health.go`'s `HealthMetrics` struct) is a point-in-time snapshot computed on each call. There's no built-in time series, so external polling and storage — Prometheus scraping `/metrics`, or a cron job hitting `/health` and logging the JSON — is required for trend analysis.
- **The `/health` response's top-level `query_metrics.slow_queries` is always `0` in production — it's a counter nothing increments.** That field is built from `HealthCollector.GetQueryMetrics()`, whose only writer is `HealthCollector.RecordQuery`; grepping the repo shows `RecordQuery` is called exclusively from `internal/health/health_test.go` — no repository, middleware, or handler in production code ever calls it. Don't use this field for real slow-query counts. The signal that's actually wired is `database_stats.slow_query_count` in that same `/health` response (mirrored as `performance.slow_query_count` in `/health/database`): it's fed by `internal/db.RecordQueryExecution`, called from every repository's `executeWithMetrics`/`queryWithMetrics` wrapper, and its slow-query cutoff *is* configurable — see the `monitoring.slow_query_threshold` bullet above.

**Deep dive:** [Admin Manual — Health & Monitoring](admin-manual.html#health).

---

For deployments where private key material must never touch process memory, RocketVault can hand key operations off to hardware.

## 8. HSM-backed mode (PKCS#11)

**What it is:** RocketVault can generate and operate RSA, ECDSA, and OCT (symmetric AES) keys through any PKCS#11-compliant hardware security module (or a software token such as SoftHSM2), so key material never enters Go process memory — it stays on the token, and only handles (labels) are stored in the database.

**Use it when:**

- Compliance requires keys to be non-extractable and hardware-backed (for example, FIPS-adjacent deployments).
- You want to test the HSM code path locally before rolling out real hardware, using SoftHSM2.
- You need RSA sign/verify/encrypt/decrypt, ECDSA sign/verify (including secp256k1/ES256K), or AES-KW/AES-CBC/AES-GCM operations backed by a token rather than the built-in AES-GCM-encrypted PEM storage.
- You need symmetric AES-KW key wrapping backed by a token: OCT (`type: "OCT"`) keys are HSM-only — the software provider rejects `CreateOctKey` outright with `crypto.ErrOctKeysRequireHSM` (mapped to a 400 by the API), so `hsm.enabled: true` is a hard prerequisite for this key type, not just an option.

**Prerequisites:**

- A PKCS#11 shared library reachable on disk — for example `/usr/lib/softhsm/libsofthsm2.so` for SoftHSM2 on Ubuntu, or the Homebrew Cellar path on macOS (Homebrew keeps the `.so` extension there too). See `docs/hsm-softhsm2-testing.md` for the full setup on both platforms.
- A token already initialized on that module with a known label and PIN. For SoftHSM2: `softhsm2-util --init-token --slot 0 --label rocketvault --pin 1234 --so-pin 0000`.
- The `hsm` block in `.rocketvault.yaml` configured with `enabled: true`:

  ```yaml
  hsm:
    enabled: true
    lib_path: /usr/lib/softhsm/libsofthsm2.so
    token_label: rocketvault
    pin: "1234"
    slot_id: 0   # 0 = auto-detect by token_label
  ```

- Authorization is unaffected by HSM mode: the caller still needs a role assignment granting the relevant Azure data action in the target vault — see the deny-by-default note in section 2. A bootstrap-created global admin has this in every vault for free (which is why the examples below work as shown); any other principal needs an explicit `vault-access grant` first.

### Example

The `hsm:` block is at the end of `.rocketvault.yaml`. This repo's checked-in dev config currently ships with `enabled: true` against a local SoftHSM2 token (`token_label: rocketvault`), so starting the server here does initialize the PKCS#11 provider and will fail at boot (`failed to initialise PKCS#11 key provider: ...`) if that token isn't present on the machine — set `enabled: false` first if you just want the software provider. Once the block is configured as you want it, start the server:

```bash
go run main.go serve
```

Check the startup log for confirmation that the PKCS#11 provider was selected:

```
PKCS#11 HSM key provider initialised
```

If `hsm.enabled` is `false` or unset, you'll see `Software key provider initialised (HSM disabled)` instead — the built-in Go crypto path.

Create an RSA key; it will be generated on the token instead of in software:

```bash
curl -s -X POST http://localhost:8774/api/v1/keys \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"name":"hsm-test","type":"RSA","bits":2048}' | jq
```

Sign data through the token (the same `/api/v1/keys/{id}/sign` route used in software mode):

```bash
curl -s -X POST http://localhost:8774/api/v1/keys/${KEY_ID}/sign \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"value":"aGVsbG8=","algorithm":"RS256"}' | jq
```

### Notes & gotchas

- The API surface is identical in HSM mode — `/api/v1/keys`, `/api/v1/keys/{id}/sign`, `/verify`, `/encrypt`, `/decrypt`, `/wrap`, and `/unwrap` all work the same whether keys live in software or on a token; only the storage and crypto backend changes. Like other resources, keys also exist in a vault-scoped route shape (`/api/v1/vaults/{vault_name}/keys/...`); the flat routes used in the example above resolve to the `default` vault — see section 2.
- Every crypto operation (`/sign`, `/verify`, `/encrypt`, `/decrypt`, `/wrap`, `/unwrap`) accepts an optional `"version"` field in the request body (`0` or omitted means the key's current version) and echoes back the `version` actually used in the response. This resolves the same way for HSM-backed keys as for software keys: a rotated key's older versions each keep their own `pkcs11:<uuid>` token handle, so you can address a prior version's material on a token exactly as you would a prior version's PEM.
- Internally, the key's stored `value` becomes `pkcs11:<uuid>` (the token's `CKA_LABEL`) instead of an encrypted PEM blob — the UUID is the handle looked up on the token for every operation.
- Keys are created non-extractable on the token (`CKA_EXTRACTABLE: false`, `CKA_SENSITIVE: true`) — this applies to RSA/ECDSA private keys and to OCT (AES) secret keys alike; none can be exported once generated on the token.
- Supported sign/verify algorithms (RSA/ECDSA keys): `RS256`, `RS384`, `RS512`, `PS256`, `PS384`, `PS512`, `ES256`, `ES384`, `ES512`, and `ES256K` (secp256k1/P-256K, signed via the same `CKM_ECDSA` mechanism as the NIST curves).
- Supported encrypt/decrypt: RSA keys support `RSA-OAEP` (SHA-1) and `RSA-OAEP-256` (SHA-256). OCT (AES) keys support `AES256-GCM` (128-bit tag, no AAD, matching the software provider's `cipher.NewGCM` defaults) and `A128CBC`/`A192CBC`/`A256CBC` (PKCS7-padded via `CKM_AES_CBC_PAD`, matching the software provider's padding semantics) — both round-trip the IV/nonce through the response's `nonce` field and the follow-up request's `nonce` field, same as software AES.
- ECDSA key generation supports curves `P-256`, `P-384`, `P-521`, and `P-256K` (secp256k1) — `CKM_EC_KEY_PAIR_GEN` is curve-agnostic in the PKCS#11 spec, so SoftHSM2 (which accepts a 112–521 bit key-size range for that mechanism) generates secp256k1 keys the same as any NIST curve. Real HSM vendors may still reject secp256k1 at the hardware level since it isn't NIST-approved: that specific rejection (`CKR_CURVE_NOT_SUPPORTED` and a few related capability codes) is caught and reported as a clean `curve not supported by PKCS#11 provider: <curve> (rejected by HSM)` (`ErrUnsupportedCurve`) instead of a leaked PKCS#11 error code. An unrecognized curve name fails the same way without ever reaching the token.
- `/wrap` and `/unwrap` support `RSA-OAEP`, `RSA-OAEP-256`, `A128KW`/`A192KW`/`A256KW`, and `A128CBC`/`A192CBC`/`A256CBC` for software-backed keys. An HSM-backed key supports `RSA-OAEP`, `RSA-OAEP-256`, and `A128KW`/`A192KW`/`A256KW` (the latter via `CKM_AES_KEY_WRAP` against the token's AES secret key) — only the `A128CBC`/`A192CBC`/`A256CBC` variants stay unsupported for `/wrap`/`/unwrap` specifically, because AES-CBC needs an IV and neither `WrapKeyResult` nor `UnwrapKeyRequest` has a field to carry one. Requesting an AES-CBC algorithm against an HSM key on `/wrap`/`/unwrap` fails with `algorithm "<alg>" is not supported for HSM-backed keys; use RSA-OAEP, RSA-OAEP-256, A128KW, A192KW, or A256KW` (`internal/services/keys/crypto_service.go`) — use `/encrypt`/`/decrypt` instead, which do carry the IV as `nonce`. AES-KW additionally requires the wrapping/unwrapping key's size to match the algorithm (`A128KW` needs a 128-bit key, `A192KW` 192-bit, `A256KW` 256-bit) — a mismatch fails with `algorithm "<alg>" requires a <N>-bit key, but key <key_id> is <M>-bit`.
- OCT (symmetric AES) keys can only be created when `hsm.enabled: true`; `POST /api/v1/keys` with `{"type":"OCT","bits":256}` against the software provider fails with a 400 (`type: OCT key creation requires an HSM-backed key provider (hsm.enabled: true)`). Valid OCT key sizes are 128, 192, or 256 bits. Use `/encrypt`/`/decrypt` for AES-GCM/AES-CBC, or `/wrap`/`/unwrap` for AES-KW (with an `A128KW`/`A192KW`/`A256KW` algorithm matching the key's bit size, per the bullet above); OCT keys have no PKCS#11 sign/verify mechanism, so `/sign` and `/verify` against one fail.
- `slot_id: 0` means "auto-detect by `token_label`"; set an explicit non-zero slot if you have multiple tokens with the same label, or if SoftHSM2 reassigns slots after `--init-token`.
- Switching `hsm.enabled` back to `false` reverts to the software provider on the next restart — no other config changes needed.

**Deep dive:** [docs/hsm-softhsm2-testing.md](hsm-softhsm2-testing.html) — full SoftHSM2 install and init walkthrough, verifying token contents with `pkcs11-tool`, and running the PKCS#11 integration test suite.

---

Finally, whichever of the surfaces above you use, the server itself has to run somewhere.

## 9. Deployment modes

**What it is:** RocketVault ships as a single self-contained Go binary and can run four ways: directly on a host (standalone binary against SQLite or PostgreSQL), inside Docker via `docker compose` (Postgres plus the app, with an optional Caddy TLS proxy), on Fly.io using the provided `fly.toml`, or on Railway using the same committed Dockerfile (`railway.json` plus `docs/deploy-railway.md`). All four run the exact same binary and config format — only `database.driver` / `database.connection` and how secrets are injected differ.

**Use it when:**

- You want a quick local or dev instance — build the binary and run it against the bundled SQLite file (this is what `.rocketvault.yaml` is preconfigured for out of the box).
- You're deploying to a VPS or bare server and want an isolated, reproducible container with a real Postgres backend — use `docker compose up`.
- You want a TLS-terminating reverse proxy in front of the container on a VPS — bring up the `caddy` service with the `proxy` profile.
- You're deploying to Fly.io — use `fly.toml` plus `fly secrets set` (Fly terminates TLS itself, so skip Caddy).
- You want a managed platform with no infra of your own to run — deploy to Railway with `railway up`; it builds from the same committed Dockerfile and defaults to SQLite on a mounted volume (no PostgreSQL required) — see `docs/deploy-railway.md`.
- You need to cross-compile release binaries for multiple platforms (`linux/amd64`, `linux/arm64`, `darwin/arm64`, `windows/amd64`) — use `./build.sh --all` or `./build.sh --release`.

**Prerequisites:**

- Go 1.25+ and a C toolchain (CGO must stay enabled — `go-sqlite3` is compiled into the binary even when the app talks to Postgres at runtime; see the comment at the top of `Dockerfile`).
- For standalone/SQLite: a `.rocketvault.yaml` with `database.driver: "sqlite3"` and `database.connection` pointing at a file path (the checked-in `.rocketvault.yaml` already does this: `connection: "./dev-rocketvault.db"`).
- For Postgres (Docker or Fly): `POSTGRES_USER`, `POSTGRES_PASSWORD`, `POSTGRES_DB`, `RV_MASTER_KEY`, and `RV_BOOTSTRAP_TOKEN` — all required, since `docker-entrypoint.sh` refuses to start the container if any is unset (each is guarded with a shell `:?` check) — plus `RV_ISSUER` and `RV_CORS_ORIGINS`, which `docker-entrypoint.sh` does *not* hard-require (no `:?` guard on those two); `docker-compose.yml` instead falls back to `http://localhost:8774` for both if they're unset in `.env`, so set them explicitly for a real deployment. There is no `RV_JWT_SECRET` — JWT signing is asymmetric-only and the Docker template's `jwt.key_source` is hardcoded to `self_pki`, so there is nothing to generate for it. `RV_DB_DRIVER` selects the driver `docker-entrypoint.sh` renders (`sqlite3` by default; `docker-compose.yml` and `fly.toml` both set it to `postgres` explicitly). `RV_HSM_ENABLED=true` (optional) has `docker-entrypoint.sh` initialize a SoftHSM2 token inside the container and set `hsm.enabled: true` in the rendered config directly — no manual template edits needed; once it's `true`, `RV_HSM_PIN` becomes required (its own `:?` guard fires only inside that branch) and `RV_HSM_SO_PIN` defaults to `RV_HSM_PIN` if left unset. Leave `RV_HSM_ENABLED` unset otherwise.
- Docker Compose: a `.env` file (copy `.env.example` to `.env` and fill in every value; secrets should be generated with `openssl rand -base64 32`).
- Railway: a persistent volume mounted at `/app/data` (`railway volume add --mount-path /app/data`) — without it, the SQLite database (which under `self_pki` also holds the JWT signing key) and logs are lost on every redeploy. Only `RV_MASTER_KEY` and `RV_BOOTSTRAP_TOKEN` are required; `RV_DB_DRIVER` defaults to `sqlite3` so it need not be set.

### Example

**Standalone binary (SQLite, dev):**

```bash
# Build
./build.sh                 # -> ./build/rocketvault (also symlinked to ./rocketvault)
# or, without the build script:
go build -o rocketvault .

# Run — reads ./.rocketvault.yaml (database.driver: sqlite3) from the cwd
./rocketvault serve
# or during development:
go run main.go serve

# Custom listen address (`--log-level` is currently a no-op flag; log level comes from `log.level` in `.rocketvault.yaml`)
./rocketvault serve --listen :9000
# To change the log level, edit .rocketvault.yaml instead:
#   log:
#     level: "debug"
```

**Standalone binary against PostgreSQL** (edit `.rocketvault.yaml`'s `database` block):

```yaml
database:
  driver: "postgres"
  connection: "postgres://user:password@localhost:5432/rocketvault?sslmode=require"
```

**Docker Compose (Postgres + app):**

```bash
cp .env.example .env       # fill in POSTGRES_PASSWORD, RV_MASTER_KEY, RV_BOOTSTRAP_TOKEN, RV_ISSUER, RV_CORS_ORIGINS
docker compose up --build

# Create the first admin user once the container is healthy
docker compose exec rocketvault /app/rocketvault users admin \
  --admin-username=admin --admin-password=<password> \
  --bootstrap-token=<RV_BOOTSTRAP_TOKEN from .env>

# Optional: TLS-terminating Caddy proxy (edit Caddyfile's domain first)
docker compose --profile proxy up --build
```

**Cross-platform release build:**

```bash
./build.sh --release       # go vet + tests + all 4 platform targets + checksums + RELEASE_NOTES.md
# artifacts land in ./dist/, e.g. rocketvault-v4.0.0-linux-amd64.tar.gz(.sha256)
```

**Fly.io** (see the header comment in `fly.toml` for the full walkthrough):

```bash
fly launch --no-deploy
fly postgres create
fly secrets set \
  RV_DB_DRIVER=postgres \
  POSTGRES_USER=rocketvault POSTGRES_PASSWORD="$(openssl rand -base64 24)" POSTGRES_DB=rocketvault \
  RV_MASTER_KEY="$(openssl rand -base64 32)" \
  RV_BOOTSTRAP_TOKEN="$(openssl rand -base64 32)" \
  RV_ISSUER="https://<your-app>.fly.dev" RV_CORS_ORIGINS="https://<your-app>.fly.dev"
fly deploy
```

**Railway** (see [docs/deploy-railway.md](deploy-railway.html) for the full walkthrough):

```bash
railway login
railway init                                          # builds from the committed Dockerfile
railway volume add --mount-path /app/data -s <service-name>
railway variable set RV_MASTER_KEY="$(openssl rand -base64 32)" -s <service-name>
railway variable set RV_BOOTSTRAP_TOKEN="$(openssl rand -base64 32)" -s <service-name>
railway up

# Create the first admin user once deployed (a one-off command, not an interactive shell)
railway ssh -s <service-name> -- \
  /app/rocketvault users admin --admin-username=admin --admin-password=<password> \
  --bootstrap-token=<RV_BOOTSTRAP_TOKEN from railway variables>
```

### Notes & gotchas

- The config key is `database.driver` (values `sqlite3` / `sqlite` or `postgres` / `postgresql`), **not** `database.type`. If `database.driver` is left blank, `internal/db/db.go`'s `sniffDriver()` infers Postgres from a `postgres://` / `postgresql://` prefix or a `host=...dbname=...` DSN, and falls back to SQLite otherwise — but setting it explicitly is recommended.
- CGO must stay `CGO_ENABLED=1` for every build target, including ones that will only ever talk to Postgres, because `go-sqlite3` is linked into the binary regardless (see the comment block at the top of `Dockerfile`). This is also why the runtime image is `debian:bookworm-slim` rather than `scratch`/distroless — the binary needs glibc at runtime.
- `docker-entrypoint.sh` renders `/app/.rocketvault.yaml` from `.rocketvault.docker.yaml.tmpl` via `envsubst` at container startup, substituting `RV_MASTER_KEY`, `RV_BOOTSTRAP_TOKEN`, `RV_CORS_ORIGINS`, `RV_ISSUER`, `RV_HSM_PIN`, and `RV_HSM_ENABLED` directly, plus three values the script derives itself rather than passing through from the caller — `RV_DATABASE_DRIVER`, `RV_DATABASE_CONNECTION` (built from `RV_DB_DRIVER` and, for Postgres, `POSTGRES_USER`/`POSTGRES_PASSWORD`/`POSTGRES_DB`), and `RV_LOG_FILE`. Viper does not expand `${VAR}` inside YAML values on its own, so this rendering step is required — don't expect a plain `docker run` with just env vars set and no entrypoint to pick up secrets into the YAML.
- There is no `RV_JWT_SECRET` anywhere in this path any more — not in `docker-entrypoint.sh`, `docker-compose.yml`, `.env.example`, or `fly.toml`. JWT signing has been asymmetric-only since the 2026-08-16 HS256 removal (pentest finding H1), and `.rocketvault.docker.yaml.tmpl`'s `jwt:` block hardcodes `key_source: "self_pki"` with no `jwt_secret` key at all (the checked-in `.rocketvault.yaml.example` dropped the same key). `self_pki` stores the signing key encrypted inside the database itself via `CryptoService`/`KeyRepository`, so it persists across redeploys with no separate key file, env var, or keychain to manage.
- `RV_HSM_ENABLED=true` is the one switch that turns HSM mode on for any of the container-based deployment modes: `docker-entrypoint.sh` initializes a SoftHSM2 token under `/app/data/softhsm` (or Railway's equivalent mounted volume) and substitutes `hsm.enabled: true` into the rendered config — no manual edits to `.rocketvault.docker.yaml.tmpl` needed. The runtime image bundles the `softhsm2` and `opensc` packages for this (see `Dockerfile`). `RV_HSM_PIN` is required only inside that branch, and `RV_HSM_SO_PIN` (used solely to initialize the token) defaults to `RV_HSM_PIN` if left unset.
- In `docker-compose.yml`, the app's `command` explicitly passes `--listen :8774`. This used to work around a real ordering bug in `cmd/serve.go`'s `init()`, which read `server.listen_addr` via `viper.GetString` at Go package-init time — before `cobra.OnInitialize(initConfig)` (registered in `cmd/root.go`'s `init()`) had a chance to load the config file, so the YAML value was silently ignored. **That bug was fixed 2026-08-18** (commit `e630029`, "fix(cmd): apply server.listen_addr from config on serve"): `servePreRun` (`serveCmd`'s `PersistentPreRunE`) now re-applies `server.listen_addr` from viper after `OnInitialize` has actually loaded it, and only when `--listen` wasn't explicitly passed. Precedence today is `--listen` flag > `server.listen_addr` in the config file > `PASSWORD_MANAGER_LISTEN` env var > the hardcoded `127.0.0.1:8774` default. The explicit `--listen :8774` in `docker-compose.yml` is therefore now redundant — the rendered `.rocketvault.yaml` already sets `server.listen_addr: ":8774"` — though it's harmless since both resolve to the same address. `docker-compose.yml`'s own inline comment on that `command` line still describes the bug as present and unfixed; it hasn't been updated to match.
- Both the Dockerfile `HEALTHCHECK` and the Compose `healthcheck` hit `GET http://127.0.0.1:8774/api/v1/health/live` (see section 7); the app container's healthcheck must pass before Compose considers it up (Caddy's `depends_on` waits on this).
- The `rocketvault` service in `docker-compose.yml` depends on `postgres` being healthy (`pg_isready`) before starting, and the Postgres DSN is templated as `postgres://${POSTGRES_USER}:${POSTGRES_PASSWORD}@postgres:5432/${POSTGRES_DB}?sslmode=disable` — `postgres` here is the Compose service name, resolved via Docker's internal DNS, not a real hostname.
- Schema migrations run at process startup with no distributed lock, so `fly.toml` deliberately pins `[[vm]]` to one machine (`min_machines_running = 1`, no horizontal replica count) — multiple replicas would race running `migrateSchema()` against the same database. This is a constraint on the Fly *instance* count, not on the (unrelated) multi-vault feature: a single instance already hosts any number of named vaults, each an isolated security boundary — see `.claude/multi-vault.md`. Scale vertically (bump `size` / `memory`), not horizontally.
- The `caddy` service only starts with `docker compose --profile proxy up` (not a plain `docker compose up`), and only makes sense for bare-VPS deployments — skip it entirely on Fly.io, which terminates TLS itself (`force_https = true` in `fly.toml`).
- `./build.sh --all` / `--release` cross-compiles with CGO enabled; if the matching C cross-compiler isn't installed for a target platform/arch, that target is skipped with a warning rather than failing the whole build (see `build_all` in `build.sh`).
- Never commit `.env` — `.env.example` documents every required variable and states it must differ between dev, staging, and prod, especially `RV_MASTER_KEY` (losing it makes all stored secrets permanently unrecoverable).

**Deep dive:** README.md's Installation, Building, and Deployment sections cover the standalone-binary and Docker basics in less depth; `fly.toml`, `docker-compose.yml`, and `.env.example` in the repo root are the canonical source for the Docker and Fly walkthroughs, and [docs/deploy-railway.md](deploy-railway.html) is the canonical source for Railway.
