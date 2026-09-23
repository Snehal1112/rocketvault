# RocketVault API Collection

Bruno collection for testing the RocketVault REST API.

## Setup

1. Install [Bruno](https://www.usebruno.com/) (free, open-source API client)
2. Open Bruno → **Open Collection** → select this `docs/api/` directory
3. Select an environment from the top-right dropdown (Local / Staging / Production)

## First Request: Login

1. Open `auth/login`
2. Fill in `totp_code` in the environment variables (top-right → Manage Environments)
3. Send the request — the token is automatically saved to the `token` env var
4. All authenticated requests will now use this token

## Environment Variables

| Variable | Description |
|---|---|
| `base_url` | API base URL (e.g. `http://localhost:8080`) |
| `token` | JWT access token — auto-populated by the Login request |
| `username` | Login username |
| `password` | Login password |
| `totp_code` | TOTP code from your authenticator app — fill before login |

The following variables are used as path parameters — set them manually in the env or override per-request:

| Variable | Used in |
|---|---|
| `vault_name` | All vault-scoped resource routes (secrets, keys, certificates, access-policies, soft-delete) |
| `user_id` | users/get-user, update-user, delete-user |
| `secret_id` | secrets/get-secret, update-secret, delete-secret, versions |
| `key_id` | keys/get-key, update-key, delete-key, rotate, wrap, unwrap |
| `certificate_id` | certificates/get-certificate, update-certificate, delete-certificate |
| `policy_id` | access-policies/get-policy, update-policy, delete-policy |
| `principal_id` | access-policies/list-by-principal, vault-provisioning-grants/upsert-vault-provisioning-grant, vault-provisioning-grants/delete-vault-provisioning-grant |
| `assignment_id` | role-assignments/get-role-assignment, delete-role-assignment |
| `service_account_id` | service-accounts/get, delete, rotate service account |
| `ca_cert_id` | certificates/create-certificate-ca-signed |
| `session_id` | users/revoke-session |
| `version` | secrets/get-version |
| `client_id` | oauth2/token |
| `client_secret` | oauth2/token |

## Collection Structure

```
vaults/            Vault CRUD + recover, purge, list-deleted, webhook config
auth/              Login and token refresh
oidc/              OIDC login, callback, and CLI token exchange
users/             User CRUD + session management
secrets/           Secret CRUD + generate, export, import, versioning (vault-scoped)
keys/              Key CRUD + rotate, wrap, unwrap, import (vault-scoped)
certificates/      Certificate CRUD, self-signed and CA-signed (vault-scoped)
access-policies/   Policy CRUD + list by principal (vault-scoped)
role-assignments/  Per-vault Azure role assignments: grant, list, get, revoke (vault-scoped)
vault-provisioning-grants/  Issue, list, and revoke per-principal vault-creation quotas (admin)
soft-delete/       List, restore, purge for secrets/keys/certificates (vault-scoped)
backup/            Backup and restore for secrets, keys, certificates
service-accounts/  Service account CRUD + secret rotation
oauth2/            OAuth2 token endpoint (client_credentials grant)
health/            Health, readiness, and liveness checks
metrics/           Prometheus metrics endpoint (gated by monitoring.enable_metrics)
jwks/              JWKS public key set + rotation (admin)
audit/             Audit log queries + SOC2/GDPR compliance reports + config (admin)
config/            Public frontend configuration endpoint
```

## Running the server locally

```bash
go run main.go serve
```

The server starts on `http://127.0.0.1:8774` by default (`defaultListenAddr` in `cmd/serve.go`, and `server.listen_addr` in the checked-in `.rocketvault.yaml` sets the same `:8774`).
