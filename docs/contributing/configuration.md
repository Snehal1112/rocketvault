# Configuration and admin setup

Moved verbatim out of the project CLAUDE.md on 2026-10-20 to keep it short.

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
- `jwt_secret` and `jwt.migration_window` are **no longer read by any Go code** (HS256 removal, 2026-08-16, pentest finding H1). Pentest finding H4 has since landed too: both keys are deleted from `.rocketvault.yaml` outright (not merely unread), and the file itself is no longer git-tracked — see `docs/known-bugs.md` § B10. `jwt.key_source` (default `os_store`) is now mandatory — if its provider cannot be constructed, startup fails rather than falling back.
- Dead stubs (not yet read by code, kept as planned-feature markers): `health.*`, `development.*`. `monitoring.*` was wired up 2026-08-14: `enable_metrics` gates the `GET /metrics` Prometheus endpoint (`api/metrics.go`), `slow_query_threshold` drives the slow-query cutoff in `internal/db` and `internal/health` (default 100ms, via `config.LoadMonitoringConfig`), and `metrics_interval` controls how often `internal/metrics.MetricsScheduler` refreshes the `rocketvault_db_*` gauges — all wired from `bootstrap.go`.
- `rate_limit.per_vault` (default 600/min, added 2026-09-03) is the noisy-neighbour guard: a token bucket per *vault*, on top of the existing per-IP `rate_limit.default`/`rate_limit.auth` buckets. Enforced by `VaultRateLimitMiddleware` (`internal/middleware/vault_rate_limit.go`), which must stay after `VaultResolutionMiddleware` in `api/api.go`'s chain — the vault is unknown before that. Health probes are exempt (they skip vault resolution, so counting them would let a liveness probe drain the default vault's budget); routes that resolve no vault of their own count against the default vault. Rejections return 429, report `X-RateLimit-Vault-*` headers (deliberately distinct names so they cannot clobber the per-IP limiter's `X-RateLimit-*`), and increment `rocketvault_vault_rate_limit_exceeded_total{vault}` when `monitoring.enable_metrics` is on.
- `retry.service_operations` is intentionally unwired: fully parsed and tested, but no production caller yet. Reserved for a future feature (e.g., cloud HSM or ACME issuer) that needs a retry tier distinct from `database`/`external_services`. See `docs/known-bugs.md` § I1 for investigation and rationale.
- For `bootstrap_token` seeding details, see `seedBootstrapToken()` in `internal/db/db.go`.
- `.rocketvault.yaml` is gitignored (fixed 2026-08-16 — see
  `docs/known-bugs.md` § B10); `.rocketvault.yaml.example` is the committed
  template. Never add a real secret value to the `.example` file.

## OIDC login policy

OIDC login is gated by `oidc.enabled` (default `false`). When it is on, these
keys under `oidc:` control who may sign in. Invalid values (for example a
malformed domain or a `default_role` other than `user`) make startup fail.

| Key | Default | Rule |
|---|---|---|
| `jit_enabled` | `false` | A new OIDC identity is created only when `true`. |
| `allowed_email_domains` | `[]` | When set, the email domain must match one entry (case-insensitive), and the provider must send `email_verified: true`. A missing email is denied. |
| `require_email_verified` | `false` | The provider must report `email_verified` as true. |
| `required_claims` | `{}` | Each named claim must match the configured value. A claim that holds a list matches when it contains the value. Claims are read from the ID token only, never from userinfo. |
| `default_role` | `user` | Role of a newly created user. Only `user` is accepted. |
| `enforce_on_existing` | `true` | Also apply the domain, verified and claim checks to already-linked users. |

Evaluation order:

1. A new identity while `jit_enabled` is `false` is denied.
2. The domain, verified and required-claims checks always apply to new users.
   They apply to existing users only when `enforce_on_existing` is `true`.
3. A missing or empty email is denied when a domain list is set. A domain list
   also requires `email_verified` to be true, like `require_email_verified`.

The client sees a generic 403. The reason is recorded in the audit log only.

Notes:

- Identities link only by `(provider, subject)`, never by email.
- PKCE with S256 is always on for the login flow.
- Some providers, for example Microsoft Entra ID, do not send `email_verified`
  in ID tokens by default. With a domain list set, everyone is denied there
  until the claim is configured.
- Sessions and refresh tokens issued before a policy is tightened stay valid
  until they expire.
- **Upgrade warning**: JIT provisioning is now off by default. New OIDC
  identities are denied until you set `oidc.jit_enabled: true`. Users that are
  already linked keep logging in, unless `enforce_on_existing` is `true` and
  they fail the configured checks.

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
  token is rotated per `docs/known-bugs.md` § B10, so there is no
  committed value to document here.
