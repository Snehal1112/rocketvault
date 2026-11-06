# Consuming RocketVault Secrets in Your Application

This guide walks through the complete process of integrating your application with a
running RocketVault instance — from creating a service account to fetching secrets at
startup and verifying the integration works.

---

## Mental Model

```
┌─────────────────────────────┐        ┌──────────────────────────────┐
│   RocketVault Server        │        │   Your Application           │
│   :8774                     │        │   (Go service, CI script,    │
│                             │◄───────│    any HTTP client)          │
│   Stores secrets            │        │                              │
│   Issues OAuth2 tokens      │        │   1. Authenticate (OAuth2)   │
│   Enforces access policies  │        │   2. Fetch secrets by UUID   │
│                             │        │   3. Use values at runtime   │
└─────────────────────────────┘        └──────────────────────────────┘
```

**Key rules:**
- Service accounts default to **read-only** access — an admin creates the secret and then grants the
  service account a role (e.g. `Key Vault Secrets User`) scoped to the vault the secret lives in
  (Azure role-parity RBAC). A vault's `access-policies` endpoint still exists but today only acts as an
  explicit-**deny** override — it is not a grant mechanism, so an "allow" access policy alone does **not**
  give a service account access. Always use a role assignment to grant access.
- `client_id` in OAuth2 is the service account **name**, not its UUID.
- Secrets, and the roles granted on them, are **scoped to a vault**. Every RocketVault instance ships a
  `default` vault, but production setups commonly use named vaults (e.g. `prod-vault`) as isolated
  security boundaries — see [Using a Named Vault](#using-a-named-vault-eg-prod-vault) below.
- `VAULT_CLIENT_SECRET` must always come from an environment variable — never a config file.
- RocketVault's own `.rocketvault.yaml` must have `vault_client.client_id = ""` — the server never calls itself.

---

## Prerequisites

- RocketVault server running: `./rocketvault serve`
- Admin credentials configured (username `admin`, password `admin123`, TOTP set up)
- `curl` and `jq` installed

---

## Step 1: Create a Service Account

A service account is an OAuth2 client identity for your application. You create it once
and store the credentials securely.

### 1a. Get an admin JWT

```bash
# Replace <totp> with the current 6-digit code from your authenticator app
ADMIN_JWT=$(curl -s -X POST http://localhost:8774/api/v1/users/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"admin123","totp_code":"<totp>"}' \
  | jq -r '.token')

echo "JWT set: ${ADMIN_JWT:+yes}"
```

### 1b. Create the service account

```bash
SA=$(curl -s -X POST http://localhost:8774/api/v1/service-accounts \
  -H "Authorization: Bearer $ADMIN_JWT" \
  -H "Content-Type: application/json" \
  -d '{"name":"my-app","description":"My application service account"}')

SA_NAME=$(echo $SA | jq -r '.name')
SA_SECRET=$(echo $SA | jq -r '.client_secret')

echo "Service account name:   $SA_NAME"
echo "Service account secret: ${SA_SECRET:0:8}..."
```

> **Important:** The `client_secret` is shown **only once** at creation. Save it
> immediately. If you lose it, rotate it via `POST /api/v1/service-accounts/{id}/rotate`.

### 1c. Export the secret as an environment variable

```bash
export VAULT_CLIENT_SECRET="$SA_SECRET"
```

In production, inject this via your deployment platform (Docker env, Kubernetes Secret,
GitHub Actions secret, AWS Secrets Manager) — never write it to a file.

---

## Step 2: Create Secrets and Grant Access to the Service Account

Service accounts default to **read-only** access (Azure Key Vault model). An admin creates
the secrets and then grants the service account a role, scoped to the vault the secrets live in.

### 2a. Create secrets as admin

```bash
# Create DB_PASSWORD secret (using the admin JWT from Step 1a)
DB_UUID=$(curl -s -X POST http://localhost:8774/api/v1/secrets \
  -H "Authorization: Bearer $ADMIN_JWT" \
  -H "Content-Type: application/json" \
  -d '{"name":"DB_PASSWORD","value":"your-database-password"}' \
  | jq -r '.id')

echo "DB_PASSWORD UUID: $DB_UUID"

# Create API_KEY secret
API_UUID=$(curl -s -X POST http://localhost:8774/api/v1/secrets \
  -H "Authorization: Bearer $ADMIN_JWT" \
  -H "Content-Type: application/json" \
  -d '{"name":"API_KEY","value":"your-api-key"}' \
  | jq -r '.id')

echo "API_KEY UUID: $API_UUID"
```

### 2b. Grant the service account a role, scoped to the vault

Access is granted via a **per-vault role assignment**, not an access policy — `access-policies` is a
deny-only override in the current RBAC model (see Mental Model above). Grant the built-in
`Key Vault Secrets User` role (read-only: get + list secrets) on the `default` vault:

```bash
# Get the service account's UUID — the grant MUST use the UUID, not the name.
SA_ID=$(echo $SA | jq -r '.id')

curl -s -X POST http://localhost:8774/api/v1/vaults/default/role-assignments \
  -H "Authorization: Bearer $ADMIN_JWT" \
  -H "Content-Type: application/json" \
  -d "{\"principal\":\"$SA_ID\",\"principal_type\":\"service_account\",\"role\":\"Key Vault Secrets User\"}"
```

> **Important:** `principal` must be the service account's **UUID** (`$SA_ID`), never its `name`.
> Passing the name resolves against the users table and always returns `404 principal not found`.

### 2c. Get a service account token

```bash
SA_TOKEN=$(curl -s -X POST http://localhost:8774/api/v1/oauth2/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data-urlencode "grant_type=client_credentials" \
  --data-urlencode "client_id=my-app" \
  --data-urlencode "client_secret=$VAULT_CLIENT_SECRET" \
  | jq -r '.access_token')

echo "Token set: ${SA_TOKEN:+yes}"
```

> **Note the UUIDs** — you need them in your application config. The UUID is the stable
> identifier for the secret. The name is human-readable only.

---

## Step 3: Configure Your Application

### Option A — Go application using the `vaultclient` package

The `internal/vaultclient` package is part of the `rocketvault` module. If your app is
a separate module, copy the package or vendor it.

**Config file (`config.yaml`):**

```yaml
vault:
  url: "http://localhost:8774"
  client_id: "my-app"            # service account NAME (not UUID)
  # vault_name: "prod-vault"     # optional — target a named vault; omit for the `default` vault, or set VAULT_NAME env var
  secrets:
    - name: DB_PASSWORD
      uuid: "paste-uuid-from-step-2b-here"
    - name: API_KEY
      uuid: "paste-uuid-from-step-2b-here"

server:
  listen: ":9000"
```

**Environment variable (never in the config file):**

```bash
export VAULT_CLIENT_SECRET="<secret from step 1b>"
```

**Go code:**

```go
import "rocketvault/internal/vaultclient"

client, err := vaultclient.New(vaultclient.Config{
    URL:          "http://localhost:8774",
    ClientID:     "my-app",           // service account name
    ClientSecret: os.Getenv("VAULT_CLIENT_SECRET"),
    Vault:        "",                 // optional — e.g. "prod-vault"; empty targets the `default` vault
    Secrets: []vaultclient.SecretMapping{
        {Name: "DB_PASSWORD", UUID: "paste-uuid-here"},
        {Name: "API_KEY",     UUID: "paste-uuid-here"},
    },
})
if err != nil {
    log.Fatalf("vault client: %v", err)
}

// Fetch at startup
secrets, err := client.GetMany(ctx, []string{"DB_PASSWORD", "API_KEY"})
if err != nil {
    log.Fatalf("vault fetch: %v", err)
}

dbPassword := secrets["DB_PASSWORD"]
apiKey     := secrets["API_KEY"]
```

### Option B — Shell script (CI/CD, Docker entrypoints, any runtime)

```bash
export VAULT_URL="http://localhost:8774"
export VAULT_CLIENT_ID="my-app"
export VAULT_CLIENT_SECRET="<secret from step 1b>"
# export VAULT_NAME="prod-vault"    # optional — target a named vault; omit for the `default` vault

# Space-separated list of VAR_NAME=uuid pairs
export VAULT_SECRETS="DB_PASSWORD=<uuid> API_KEY=<uuid>"

# Source the script — exports secrets as env vars in the current shell
source scripts/rocketvault-fetch-secrets.sh

echo "DB_PASSWORD is set: ${DB_PASSWORD:+yes}"
```

To also write to a `.env` file:

```bash
export VAULT_ENV_FILE=".env"
source scripts/rocketvault-fetch-secrets.sh
# .env now contains: DB_PASSWORD="..." API_KEY="..."
```

### Option C — Direct HTTP (any language)

**Step 1: Get a token**

```bash
curl -X POST http://localhost:8774/api/v1/oauth2/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=client_credentials&client_id=my-app&client_secret=<secret>"
```

Response:
```json
{"access_token": "eyJ...", "token_type": "Bearer", "expires_in": 3600}
```

**Step 2: Fetch a secret**

```bash
curl http://localhost:8774/api/v1/secrets/<uuid> \
  -H "Authorization: Bearer <access_token>"
```

Response:
```json
{"id": "...", "name": "DB_PASSWORD", "value": "your-database-password", ...}
```

To fetch from a named vault instead of `default`, add the vault name to the path:
`GET /api/v1/vaults/<vault-name>/secrets/<uuid>` — see
[Using a Named Vault](#using-a-named-vault-eg-prod-vault) below.

---

## Step 4: Test with the Consumer Service

The `examples/consumer-service/` demo service provides a visual end-to-end proof.

```bash
# Terminal 1 — RocketVault
./rocketvault serve

# Terminal 2 — Consumer service
export VAULT_CLIENT_SECRET="<secret from step 1b>"
go run ./examples/consumer-service/

# Terminal 3 — Verify
curl -s http://localhost:9000/healthz | jq .
curl -s http://localhost:9000/status  | jq .
```

Expected `/status` response when everything is working:

```json
{
  "vault_url": "http://localhost:8774",
  "client_id": "my-app",
  "secrets": {
    "DB_PASSWORD": {"loaded": true,  "masked": "your***"},
    "API_KEY":     {"loaded": true,  "masked": "your***"}
  },
  "frontend_config": {
    "feature_flags": {},
    "public_api_url": "http://localhost:8774",
    "sentry_dsn": ""
  }
}
```

---

## Using a Named Vault (e.g. `prod-vault`)

Everything above targets the `default` vault, which every RocketVault instance ships with. Production
setups commonly isolate secrets in a dedicated named vault instead — each vault is its own security
boundary with its own secrets and its own role assignments. This section reuses the service account
created in Step 1 (`$ADMIN_JWT`, `$SA`, `$SA_NAME`, `$SA_SECRET`) and walks through granting it access to
a vault called `prod-vault`.

### A. Create the vault

```bash
curl -s -X POST http://localhost:8774/api/v1/vaults \
  -H "Authorization: Bearer $ADMIN_JWT" \
  -H "Content-Type: application/json" \
  -d '{"name":"prod-vault"}'
```

Requires the admin role (or a global `vaults/manage` grant) — creating a vault is a vault-*management*
operation, not a data-plane one, so it isn't gated by role assignments on the vault itself.

### B. Create a secret inside `prod-vault`

Same request body as Step 2a, just a vault-scoped path:

```bash
DB_UUID=$(curl -s -X POST http://localhost:8774/api/v1/vaults/prod-vault/secrets \
  -H "Authorization: Bearer $ADMIN_JWT" \
  -H "Content-Type: application/json" \
  -d '{"name":"DB_PASSWORD","value":"prod-database-password"}' \
  | jq -r '.id')

echo "DB_PASSWORD UUID in prod-vault: $DB_UUID"
```

### C. Grant the service account a role scoped to `prod-vault`

Same as Step 2b, but the role-assignment path names `prod-vault` instead of `default`:

```bash
SA_ID=$(echo $SA | jq -r '.id')

curl -s -X POST http://localhost:8774/api/v1/vaults/prod-vault/role-assignments \
  -H "Authorization: Bearer $ADMIN_JWT" \
  -H "Content-Type: application/json" \
  -d "{\"principal\":\"$SA_ID\",\"principal_type\":\"service_account\",\"role\":\"Key Vault Secrets User\"}"
```

This role grant is scoped to `prod-vault` only — the service account still has no access to `default`
or any other vault unless granted separately. A token issued for this service account has no notion of
"vault" baked in; authorization is checked per-request against whichever vault the request path names.

### D. Fetch the secret with the service account's token

```bash
SA_TOKEN=$(curl -s -X POST http://localhost:8774/api/v1/oauth2/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data-urlencode "grant_type=client_credentials" \
  --data-urlencode "client_id=$SA_NAME" \
  --data-urlencode "client_secret=$SA_SECRET" \
  | jq -r '.access_token')

curl -s http://localhost:8774/api/v1/vaults/prod-vault/secrets/$DB_UUID \
  -H "Authorization: Bearer $SA_TOKEN" | jq .
```

Fetching the same UUID via the legacy `/api/v1/secrets/$DB_UUID` path (no `prod-vault` in the path)
will **not** work — that path always resolves to the `default` vault regardless of which vault the
UUID actually belongs to, so it returns a not-found/access-denied error. The vault name must be in
the request path.

### E. Configure the `vaultclient` package or consumer-service example for `prod-vault`

**Go code:**

```go
client, err := vaultclient.New(vaultclient.Config{
    URL:          "http://localhost:8774",
    ClientID:     "my-app",
    ClientSecret: os.Getenv("VAULT_CLIENT_SECRET"),
    Vault:        "prod-vault",
    Secrets: []vaultclient.SecretMapping{
        {Name: "DB_PASSWORD", UUID: "paste-prod-vault-uuid-here"},
    },
})
```

**`examples/consumer-service/config.yaml`:**

```yaml
vault:
  url: "http://localhost:8774"
  client_id: "consumer-test"
  vault_name: "prod-vault"
  secrets:
    - name: DB_PASSWORD
      uuid: "paste-prod-vault-uuid-here"
```

Or without editing the file, override at runtime:

```bash
export VAULT_CLIENT_SECRET="$SA_SECRET"
export VAULT_NAME="prod-vault"
go run ./examples/consumer-service/
```

`GET /status` now reports `"vault": "prod-vault"` alongside the loaded secrets, confirming the fetch
went through the vault-scoped path.

**Shell script (Option B):**

```bash
export VAULT_URL="http://localhost:8774"
export VAULT_CLIENT_ID="$SA_NAME"
export VAULT_CLIENT_SECRET="$SA_SECRET"
export VAULT_NAME="prod-vault"
export VAULT_SECRETS="DB_PASSWORD=$DB_UUID"

source scripts/rocketvault-fetch-secrets.sh
echo "DB_PASSWORD is set: ${DB_PASSWORD:+yes}"
```

---

## Step 5: Fetch Frontend Config (Web Apps)

`GET /api/v1/config` is public — no authentication required. It returns non-sensitive
config values safe to expose to a browser.

```bash
curl -s http://localhost:8774/api/v1/config | jq .
```

Response:
```json
{
  "feature_flags": {},
  "public_api_url": "http://localhost:8774",
  "sentry_dsn": ""
}
```

Configure these values in `.rocketvault.yaml`:

```yaml
frontend:
  public_api_url: "https://api.yourapp.com"
  sentry_dsn: "https://your-sentry-dsn"
```

---

## Troubleshooting

| Error | Cause | Fix |
|---|---|---|
| `connect: connection refused` | RocketVault not running, or wrong URL/port | Start `./rocketvault serve`, check `vault.url` |
| `token endpoint returned 404` | Wrong OAuth2 path | Must be `/api/v1/oauth2/token`, not `/oauth2/token` |
| `authentication failed` | Wrong `client_id` or `client_secret` | `client_id` is the service account **name**, not UUID |
| `secret not found` fetching from a named vault | Used the legacy `/api/v1/secrets/{uuid}` path (or left `vault_name`/`Vault` unset) for a secret that lives in a non-default vault | Set `vault_name` (consumer-service config), `Config.Vault` (Go), or `VAULT_NAME` (shell script/env) to the vault the secret actually belongs to |
| `principal not found` granting a role assignment | Passed the service account's `name` as `principal` | `principal` must be the service account's **UUID** (`id` from `POST /service-accounts`), never its name |
| access policy "allow" entry has no effect | `access-policies` is a deny-only override in the current RBAC model | Grant access via `POST /api/v1/vaults/{vault}/role-assignments` instead (Step 2b) |
| `insufficient permissions` / `403` on a data-plane call | No role assignment for this service account on this vault, or the granted role lacks the needed data action | Grant `Key Vault Secrets User` (or another role, per `docs/architecture/azure-keyvault-parity.md`) scoped to the correct vault |
| `vault client init: Config.ClientSecret is required` | `VAULT_CLIENT_SECRET` env var not set | `export VAULT_CLIENT_SECRET="..."` |
| Server errors on `./rocketvault serve` | `vault_client.client_id` set in `.rocketvault.yaml` | Clear `client_id` — the server must not call itself |

---

## Security Checklist

- `VAULT_CLIENT_SECRET` is in env vars only — never in a config file or git
- `vault_client.client_id` is empty in `.rocketvault.yaml` on the RocketVault server
- Secrets and role assignments are created by an admin; each service account only ever holds the
  read-only role(s) it needs, scoped to the specific vault(s) it needs them in
- A service account granted a role on `prod-vault` has no access to `default` (or any other vault)
  unless separately granted there — role assignments do not cascade across vaults
- Each application has its own service account with the minimum required permissions
- Secret values are never logged (the `vaultclient` package logs names only)
- Rotate service account secrets periodically via `POST /api/v1/service-accounts/{id}/rotate`
