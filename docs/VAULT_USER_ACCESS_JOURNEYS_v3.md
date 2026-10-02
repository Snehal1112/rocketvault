# RocketVault — Real-World Vault, User & Access Journeys (v3, with CLI)

> Every journey now carries the actual CLI commands. Flags and command names are taken from `cmd/` (`cmd/keys/*.go`, `cmd/keys/rotation_policy.go`, `cmd/users/*.go`, `cmd/vaults/*.go`, `cmd/vault-access/*.go`, `cmd/rotation.go`, `cmd/root.go`), not invented. Where a capability has no CLI command, that is called out explicitly rather than papered over with a plausible-looking invocation.

---

## New in v3 — two corrections that change the cast

### Correction 8 — The CLI enforces a **global role gate** the HTTP path does not

This is a bigger CLI/HTTP divergence than the purge one in Journey K, and v2 missed it entirely.

Every mutating `keys` CLI command begins with:

```go
if !common.HasAnyRole(claims.Roles, model.RoleAdmin, model.RoleCryptoManager) {
    return fmt.Errorf("forbidden: requires admin or crypto_manager role")
}
```

That check runs **before** the vault data-action check, and it has no HTTP equivalent — vault data-plane routes bypass global RBAC entirely (`mapEndpointToPermission`).

| Resource | CLI additionally requires (global role) | HTTP requires |
|---|---|---|
| `keys create/update/delete/rotate/sign/verify/wrap/unwrap` | `admin` **or** `crypto_manager` | vault data action only |
| `keys rotation-policy set/delete` | `admin` **or** `crypto_manager` | vault data action only |
| `keys get` / `keys list` / `keys rotation-policy get` | *(none — data action only)* | vault data action only |
| `secrets create/update/...` | `admin` **or** `secrets_manager` | vault data action only |
| `certificate create/update/...` | `admin` **or** `certificate_manager` | vault data action only |
| `secrets rotation *` | *(none — explicitly "No global role is checked")* | no HTTP route at all |
| `vaults *` | `CanManageVault` (admin or `(vaults, manage)` policy) | same |
| `vault-access *` | `CanManageRoleAssignments` | same |

**Consequence**: a user with global role `user` holding `Key Vault Crypto Officer` in `prod` can create a key over REST and gets `forbidden: requires admin or crypto_manager role` from the CLI. The cast below is corrected to give operators the matching global role.

### Correction 9 — Large parts of the key lifecycle have **no CLI command at all**

`cmd/keys.go` registers exactly: `create`, `delete`, `get`, `list`, `update`, `rotate`, `rotation-policy` (`get`/`set`/`delete`), `wrap`, `unwrap`, `sign`, `verify`.

| Capability | CLI | HTTP |
|---|---|---|
| Key soft-delete | ✅ `keys delete` | ✅ |
| Key **recover** | ❌ none | ✅ `/deleted/keys/{id}/restore` |
| Key **purge** | ❌ none | ✅ `/deleted/keys/{id}/purge` |
| Key **backup / restore** | ❌ none | ✅ `/keys/{id}/backup`, `/keys/restore` |
| Key **rotation policy** | ✅ `keys rotation-policy get/set/delete` (added 2026-08-25) | ✅ `GET/PUT/DELETE .../rotationpolicy` |
| **Secret** rotation policy | ✅ `secrets rotation *` | ❌ no HTTP route |
| OCT (AES) key creation | ❌ `--type` accepts RSA/ECDSA only | ✅ REST, HSM-only |

Key rotation policy used to be the odd one out — HTTP-only while secret rotation policy was CLI-only. As of 2026-08-25 both surfaces exist for keys too; `keys rotation-policy set` is a full replace (like the HTTP `PUT`), so `--rotate-after-days` and `--enabled` must both be supplied on every call.

*(Corrections 1–7 from v2 are retained at the end of this document.)*

---

## Global setup used by every journey

```bash
# Point at your scratch instance, never a shared dev DB.
BASE=http://numericlabs.lxd/api/v1
export CFG=/tmp/rv-test.yaml

# TOTP is mandatory on every login.
export ROCKETVAULT_TOTP_SECRET=<the secret printed at user creation>
TOTP_CODE=$(go run scripts/totp_generator.go -secret="$ROCKETVAULT_TOTP_SECRET" \
  2>&1 | grep -m1 -oP '(?<=--totp-code )\S+')

# Log in once — the session caches under ~/.rocketvault/sessions and every
# other CLI command picks it up. HTTP does NOT read this cache; curl needs
# its own token.
rocketvault users login --username priya --password '<pw>' --totp-code "$TOTP_CODE"

ADMIN_TOKEN=$(curl -s -X POST $BASE/users/login \
  -H "Content-Type: application/json" \
  -d "{\"username\":\"priya\",\"password\":\"<pw>\",\"totp_code\":\"$TOTP_CODE\"}" \
  | jq -r .token)
```

Global persistent flags available on every command: `--config`, `--username`, `--password`, `--totp-code`, `--output {table|json|yaml}`, `--vault`, `--server`, `--ca-cert`, `--insecure-skip-verify`.

---

## Corrected Cast

| Principal | Global role | Why that global role |
|---|---|---|
| `priya` | `admin` | Bootstrap, user creation, vault creation, access policies, audit |
| `wren` | `user` | Only ever grants/revokes role assignments — `vault-access` checks no global role |
| `sofia` | **`crypto_manager`** | Must run `keys create/rotate/sign` from the CLI (Correction 8) |
| `marcus` | **`secrets_manager`** | Must run `secrets create/update` from the CLI |
| `daeho` | `user` | Read-only via HTTP; `keys list`/`get` need no global role |
| `ops-oncall` | `admin` | Second admin for separation-of-duties purge |
| `ci-payments-svc` | service account | OAuth2 client, REST only — never uses the CLI |
| `checkout-api-svc` | service account | Same |
| `noor` | **`certificate_manager`** | Must run `certificates create/update/delete/renew` from the CLI (Correction 8) |
| `iris` | `user` | Platform automation. Holds a **global** (`vault_id` `NULL`) `(vaults, manage, allow)` access policy — not an account role. Journey W is entirely about what that does and no longer does |

---

## Journey A — Day Zero: the admin discovers she has no access

**Actor**: Priya (`admin`)

```bash
# 1. Bootstrap the first admin — one-time token from .rocketvault.yaml.
#    Requires no prior session. Prints the TOTP secret exactly once.
rocketvault users admin \
  --admin-username priya \
  --admin-password '<pw>' \
  --bootstrap-token '<token-from-config>'

# 2. Log in.
rocketvault users login --username priya --password '<pw>' --totp-code "$TOTP_CODE"

# 3. Create the vaults. Name is POSITIONAL — `vaults` commands have no --vault flag.
rocketvault vaults create dev
rocketvault vaults create staging
rocketvault vaults create prod --purge-protection --retention-days 30

rocketvault vaults list
rocketvault vaults get prod --output json

# Adjust attributes after creation — enabled, purge protection, retention —
# any subset; each flag is only applied when actually passed on the line.
rocketvault vaults update staging --retention-days 14
rocketvault vaults update staging --purge-protection
```

> **Upgrading an existing pre-P2 install?** `rocketvault vaults preview-migration` prints, without writing anything, the per-vault role assignments the deny-by-default authorization upgrade would derive from current object ownership (secret/key/cert owners → the matching Officer role in their vault; global admins → Administrator everywhere). It reads the local database file directly — it refuses to run against `--server` — so confirm every principal that needs access appears in its output *before* running the real migration, not after.

**Now the surprise.** Priya tries to use the vault she just created:

```bash
rocketvault keys list --vault prod
# Error: forbidden: no role grants Microsoft.KeyVault/vaults/keys/read in this vault

curl -s -o /dev/null -w '%{http_code}\n' $BASE/vaults/prod/secrets \
  -H "Authorization: Bearer $ADMIN_TOKEN"
# 403
```

`HasDataAction` has **no admin short-circuit, by design**. Creating a vault is a management operation; everything inside it is not. The fix is to self-grant:

```bash
rocketvault vault-access grant priya --role "Key Vault Administrator" --vault prod
rocketvault vault-access grant priya --role "Key Vault Administrator" --vault dev
rocketvault vault-access grant priya --role "Key Vault Administrator" --vault staging

rocketvault keys list --vault prod      # now works
```

Create the team, with the global roles Correction 8 requires:

```bash
rocketvault users create --new-username wren   --new-password '<pw>' --new-role user
rocketvault users create --new-username sofia  --new-password '<pw>' --new-role crypto_manager
rocketvault users create --new-username marcus --new-password '<pw>' --new-role secrets_manager
rocketvault users create --new-username daeho  --new-password '<pw>' --new-role user
rocketvault users create --new-username ops-oncall --new-password '<pw>' --new-role admin

rocketvault users list --output json
```

`--new-role` is **repeatable**, not comma-separated: `--new-role admin --new-role secrets_manager`. Each `users create` prints a TOTP secret once — capture it.

> **Runbook rule**: "self-grant `Key Vault Administrator` in every new vault" belongs in your vault provisioning steps, or the vault is unusable to its own creator.

---

## Journey B — Onboarding a Backend Engineer

**Actor**: Marcus (`secrets_manager`)

```bash
# Week 1 — metadata only.
rocketvault vault-access grant marcus --role "Key Vault Reader" --vault dev

# As Marcus:
rocketvault users login --username marcus --password '<pw>' --totp-code "$MARCUS_TOTP"
rocketvault secrets list --vault dev            # works — metadata
rocketvault secrets get <secret-id> --vault dev # Error: forbidden — Reader has no secrets/get
```

Confirm the § B30 regression is closed (Reader must not see values in the versions list):

```bash
MARCUS_TOKEN=$(curl -s -X POST $BASE/users/login -H "Content-Type: application/json" \
  -d '{"username":"marcus","password":"<pw>","totp_code":"'"$MARCUS_TOTP"'"}' | jq -r .token)

curl -s $BASE/vaults/dev/secrets/<secret-id>/versions \
  -H "Authorization: Bearer $MARCUS_TOKEN" | jq '[.versions[] | has("value")] | any'
# must print: false
```

```bash
# Week 2 — read values.
rocketvault vault-access revoke <reader-assignment-id> --vault dev
rocketvault vault-access grant marcus --role "Key Vault Secrets User" --vault dev

# As Marcus:
rocketvault secrets get <secret-id> --vault dev --output json   # now returns the value
rocketvault secrets create test-db-pass 's3cr3t' --vault dev     # Error: forbidden (no secrets/set)

# Month 3 — full secret ownership in dev.
rocketvault vault-access grant marcus --role "Key Vault Secrets Officer" --vault dev

# As Marcus:
rocketvault secrets create db-pass 's3cr3t-v1' --tags prod,db --vault dev
rocketvault secrets update <secret-id> 's3cr3t-v2' --vault dev
rocketvault secrets list --vault dev --tags prod --output json

# Still nothing in prod:
rocketvault secrets list --vault prod
# Error: forbidden: no role grants ... in this vault
```

> Re-running the same `vault-access grant` is harmless — `AssignRole` finds the existing `(principal, role, vault)` tuple and returns the original assignment rather than duplicating or erroring.

Marcus manages his own account — `users get`/`update` are owner-or-admin, with no vault scoping since user accounts are global:

```bash
rocketvault users get <marcus-user-id>            # his own record — allowed
rocketvault users update <marcus-user-id> --new-password 'new-Str0ng-pw'

# He cannot read or touch anyone else's account:
rocketvault users get <sofia-user-id>
# Error: forbidden: can only access your own profile or requires admin role

# Nor grant himself a new role, even on his own account:
rocketvault users update <marcus-user-id> --new-role admin
# Error: forbidden: only admins can change roles
```

---

## Journey C — Security Engineer Owns the Key Lifecycle

**Actor**: Sofia (`crypto_manager` — required for every CLI key mutation)

```bash
rocketvault vault-access grant sofia --role "Key Vault Crypto Officer" --vault prod

# As Sofia:
rocketvault users login --username sofia --password '<pw>' --totp-code "$SOFIA_TOTP"

rocketvault keys create --name payments-signing --type RSA --bits 4096 \
  --tags prod,jwt --purge-protection --vault prod

rocketvault keys create --name payments-ec --type ECDSA --curve P-384 \
  --tags prod --vault prod

rocketvault keys list --vault prod --output json
rocketvault keys get <key-id> --vault prod --output json
```

Sign / verify, with base64 data:

```bash
DATA=$(echo -n '{"sub":"txn-1"}' | base64)

SIG=$(rocketvault keys sign --key-id <key-id> --data "$DATA" \
        --algorithm RS256 --vault prod)

rocketvault keys verify --key-id <key-id> --data "$DATA" \
  --signature "$SIG" --algorithm RS256 --vault prod
# valid: true

TAMPERED=$(echo -n '{"sub":"attacker"}' | base64)
rocketvault keys verify --key-id <key-id> --data "$TAMPERED" \
  --signature "$SIG" --algorithm RS256 --vault prod
# valid: false
```

Update mutable attributes — name, tags, revocation, purge protection — without touching key material:

```bash
rocketvault keys update <key-id> --tags prod,jwt,q3-review --vault prod
# Key <key-id> updated successfully at 2026-08-25T...

# Revoking leaves metadata readable but breaks every crypto operation:
rocketvault keys update <key-id> --revoked --vault prod
rocketvault keys sign --key-id <key-id> --data "$DATA" --algorithm RS256 --vault prod
# Error: ... key is revoked

rocketvault keys update <key-id> --revoked=false --vault prod   # un-revoke

# At least one field is required:
rocketvault keys update <key-id> --vault prod
# Error: at least one update field (name, revoked, tags, purge-protection) must be provided
```

Rotate, and prove old versions stay usable:

```bash
rocketvault keys rotate <key-id> --vault prod

# --version 1 addresses the pre-rotation material.
rocketvault keys verify --key-id <key-id> --data "$DATA" \
  --signature "$SIG" --algorithm RS256 --version 1 --vault prod
# valid: true — the signature made before rotation still verifies
```

**Rotation policy**, via the CLI (added 2026-08-25 — `keys rotation-policy get/set/delete`, mirroring the pre-existing `GET/PUT/DELETE .../rotationpolicy` HTTP routes and requiring the same `admin`/`crypto_manager` global role as every other mutating `keys` command):

```bash
# Nothing set yet — reported, not an error.
rocketvault keys rotation-policy get <key-id> --vault prod
# No rotation policy set for key <key-id>

# --rotate-after-days and --enabled are BOTH required on every call: this is
# a full replace (like the HTTP PUT), not a partial update. An omitted flag
# is not "leave unchanged", it's a validation error.
rocketvault keys rotation-policy set <key-id> --vault prod
# Error: --rotate-after-days and --enabled are required: this replaces the
# whole policy, so every field must be supplied

# Azure parity: rotate-after-days must be >= 7 once the policy is enabled.
rocketvault keys rotation-policy set <key-id> --rotate-after-days 3 --enabled --vault prod
# Error: invalid rotation policy: RotateAfterDays: must be at least 7 when
# the policy is enabled.

rocketvault keys rotation-policy set <key-id> --vault prod \
  --rotate-after-days 90 --notify-before-expiry-days 14 --expiry-days 365 --enabled
# Rotation policy set for key <key-id>: next rotation at 2026-11-23T...

rocketvault keys rotation-policy get <key-id> --vault prod --output json
```

Equivalent HTTP, still fully supported (same underlying `KeyService` call, same validation):

```bash
SOFIA_TOKEN=$(curl -s -X POST $BASE/users/login -H "Content-Type: application/json" \
  -d '{"username":"sofia","password":"<pw>","totp_code":"'"$SOFIA_TOTP"'"}' | jq -r .token)

curl -s -X PUT $BASE/vaults/prod/keys/<key-id>/rotationpolicy \
  -H "Authorization: Bearer $SOFIA_TOKEN" -H "Content-Type: application/json" \
  -d '{"rotate_after_days":90,"notify_before_expiry_days":14,
       "expiry_days":365,"enabled":true}' | jq .
```

All four JSON fields are required over HTTP too — same full-replace contract; an omitted field silently zeroes itself rather than leaving the stored value unchanged.

Deleting the policy stops the scheduler touching this key; the key itself, and manual `keys rotate`, are unaffected:

```bash
rocketvault keys rotation-policy delete <key-id> --vault prod
# Rotation policy for key <key-id> deleted successfully

rocketvault keys rotation-policy delete <key-id> --vault prod
# Error: no rotation policy exists for key <key-id>
```

What actually executes on schedule:
- ✅ the rotation itself (`RotationExecutor.Check` sweeps due, enabled policies)
- ✅ `expiry_days` — `RotateKey` stamps `ExpiresAt` on every rotation
- ❌ `notify_before_expiry_days` — **stored and never read**. Per-vault webhook *config* exists (`rocketvault vault-webhook`), but nothing sends. There is no outbound HTTP anywhere in the vault/secret/key service packages.

> Do not build an operational process that depends on RocketVault warning you before expiry.

Key **import** does not exist:

```bash
rocketvault keys import ...
# Error: unknown command "import" for "rocketvault keys"
```
`ActionKeysImport` is in the Crypto Officer bundle but no route maps to it either.

---

## Journey D — CI/CD Service Account, Sign-Only

**Actor**: `ci-payments-svc` — REST only; service accounts never use the CLI session cache

```bash
# Wren grants the role (note --principal-type).
rocketvault vault-access grant ci-payments-svc --role "Key Vault Crypto User" \
  --principal-type service_account --vault prod

rocketvault vault-access list --vault prod
```

The pipeline itself:

```bash
SVC_TOKEN=$(curl -s -X POST $BASE/oauth2/token \
  -H "Content-Type: application/json" \
  -d '{"grant_type":"client_credentials",
       "client_id":"ci-payments-svc","client_secret":"'"$VAULT_CLIENT_SECRET"'"}' \
  | jq -r .access_token)

# Allowed:
curl -s -X POST $BASE/vaults/prod/keys/<key-id>/sign \
  -H "Authorization: Bearer $SVC_TOKEN" -H "Content-Type: application/json" \
  -d '{"value":"'"$DATA"'","algorithm":"RS256"}' | jq -r .value

# Denied — Crypto User has no keys/create:
curl -s -o /dev/null -w '%{http_code}\n' -X POST $BASE/vaults/prod/keys \
  -H "Authorization: Bearer $SVC_TOKEN" -H "Content-Type: application/json" \
  -d '{"name":"scratch","type":"RSA","bits":2048}'
# 403
```

A service account's grant runs the **same `HasDataAction` codepath** as a human's, with the same per-vault scoping.

> **Threat-model precision**: Crypto User *does* include `update` and `backup`. A backup blob is master-key-encrypted ciphertext, not plaintext PEM — but it is still key material.

---

## Journey E — Narrowest Possible Crypto Grant

**Actor**: `checkout-api-svc`

```bash
rocketvault vault-access grant checkout-api-svc \
  --role "Key Vault Crypto Service Encryption User" \
  --principal-type service_account --vault prod
```

Wrap/unwrap round-trip over the CLI (using an operator's session, to demonstrate the shape):

```bash
MATERIAL=$(openssl rand -base64 32)

WRAPPED=$(rocketvault keys wrap --key-id <rsa-key-id> \
            --key-material "$MATERIAL" --vault prod)

rocketvault keys unwrap --key-id <rsa-key-id> \
  --wrapped-key "$WRAPPED" --vault prod
# prints $MATERIAL back
```

> The CLI's wrap/unwrap **always requests RSA-OAEP** — there is no `--algorithm` flag on either command. AES key wrapping is REST-only.

The service's own calls, and the failure that matters:

```bash
# Allowed:
curl -s -X POST $BASE/vaults/prod/keys/<key-id>/wrap \
  -H "Authorization: Bearer $CHECKOUT_TOKEN" -H "Content-Type: application/json" \
  -d '{"plaintext_key":"'"$MATERIAL"'","algorithm":"RSA-OAEP"}' | jq -r .wrapped_key

# Denied — this role has no keys/encrypt. A bug that calls the wrong
# endpoint fails closed rather than silently doing different crypto:
curl -s -o /dev/null -w '%{http_code}\n' -X POST $BASE/vaults/prod/keys/<key-id>/encrypt \
  -H "Authorization: Bearer $CHECKOUT_TOKEN" -H "Content-Type: application/json" \
  -d '{"algorithm":"RSA-OAEP-256","value":"'"$DATA"'"}'
# 403
```

On HSM-backed keys, wrap/unwrap is limited to AES-KW and the RSA-OAEP variants. `A128CBC`/`A192CBC`/`A256CBC` are rejected on wrap because the wrap contract carries **no IV channel**; CBC and GCM are available through `encrypt`/`decrypt`, which do round-trip the IV.

---

## Journey F — Crypto User Hits the Rotation-Policy Wall

**Actor**: `cryptouser`, granted `Key Vault Crypto User` and nothing else

```bash
rocketvault vault-access grant cryptouser --role "Key Vault Crypto User" --vault prod
```

Allowed:

```bash
CU_TOKEN=$(curl -s -X POST $BASE/users/login -H "Content-Type: application/json" \
  -d '{"username":"cryptouser","password":"<pw>","totp_code":"<code>"}' | jq -r .token)

curl -s -X POST $BASE/vaults/prod/keys/<key-id>/encrypt \
  -H "Authorization: Bearer $CU_TOKEN" -H "Content-Type: application/json" \
  -d '{"algorithm":"RSA-OAEP-256","value":"'"$DATA"'"}'
# 200

curl -s -X PUT $BASE/vaults/prod/keys/<key-id> \
  -H "Authorization: Bearer $CU_TOKEN" -H "Content-Type: application/json" \
  -d '{"tags":["updated-by-cryptouser"]}'
# 200 — Crypto User gained `update` on 2026-08-18
```

Denied — all three methods:

```bash
for M in GET PUT DELETE; do
  curl -s -o /dev/null -w "$M %{http_code}\n" -X $M \
    $BASE/vaults/prod/keys/<key-id>/rotationpolicy \
    -H "Authorization: Bearer $CU_TOKEN"
done
# GET 403
# PUT 403
# DELETE 403
```

**The contrast check that proves these are real authorization denials**, not an endpoint quirk:

```bash
curl -s -o /dev/null -w '%{http_code}\n' \
  $BASE/vaults/prod/keys/<key-id>/rotationpolicy \
  -H "Authorization: Bearer $ADMIN_TOKEN"
# 404 rotation policy not found — a genuine "nothing set yet"
```

Same route, different principal, different failure mode. A test that only asserts "non-200" cannot tell these apart. The exclusion is deliberate: commit `cdd591c` added the rotation-policy actions to Crypto Officer and Administrator only, stating *"not Crypto User, matching Azure."*

---

## Journey G — Delegating Access Management Without Handing Over the Keys

**Actor**: Wren (global role `user` — `vault-access` checks no global role)

```bash
rocketvault vault-access grant wren --role "Key Vault Data Access Administrator" --vault prod

# As Wren:
rocketvault users login --username wren --password '<pw>' --totp-code "$WREN_TOTP"

# 1. She can grant other roles — this succeeds:
rocketvault vault-access grant marcus --role "Key Vault Secrets User" --vault prod
# granted Key Vault Secrets User to marcus in vault (assignment 8516e7fd-...)

rocketvault vault-access list --vault prod

# 2. She has zero data-plane access herself:
rocketvault secrets list --vault prod
# Error: forbidden: no role grants ... in this vault

curl -s -o /dev/null -w '%{http_code}\n' $BASE/vaults/prod/secrets \
  -H "Authorization: Bearer $WREN_TOKEN"
# 403

# 3. Self-escalation is blocked — the eight-role allow-list:
rocketvault vault-access grant wren --role "Key Vault Purge Operator" --vault prod
# Error: grant failed: role cannot be granted by a non-admin caller

rocketvault vault-access grant wren --role "Key Vault Data Access Administrator" --vault prod
# Error: grant failed: role cannot be granted by a non-admin caller

rocketvault vault-access grant wren --role "Key Vault Certificate User" --vault prod
# Error: grant failed: role cannot be granted by a non-admin caller

# 4. The same allow-list gates revoke, so she can't escape via the back door:
rocketvault vault-access revoke <purge-operator-assignment-id> --vault prod
# Error: role cannot be granted by a non-admin caller

# 5. Access policies are a different surface entirely — admin-only:
curl -s -o /dev/null -w '%{http_code}\n' $BASE/access-policies \
  -H "Authorization: Bearer $WREN_TOKEN"
# 403 Insufficient permissions: admin role required to manage access policies
```

She *can* grant any of the eight: Administrator, Reader, Secrets User, Secrets Officer, Crypto User, Crypto Officer, Certificates Officer, Crypto Service Encryption User.

Marcus, holding only Secrets User, cannot even list assignments:

```bash
rocketvault vault-access list --vault prod   # as marcus
# Error: permission denied: admin, vaults/manage, or Key Vault Data Access
#        Administrator required for this vault
```

Reference:

```bash
rocketvault vault-access roles     # no auth required; lists all 11 + deprecated legacy names
```

---

## Journey H — Emergency Lockout via Explicit Deny

**Actor**: Priya (admin — Wren cannot do this)

```bash
# Baseline: Marcus can read.
curl -s -o /dev/null -w '%{http_code}\n' $BASE/vaults/prod/secrets/<secret-id> \
  -H "Authorization: Bearer $MARCUS_TOKEN"
# 200

# Suspend one operation on one resource — no CLI command; HTTP only.
POLICY_ID=$(curl -s -X POST $BASE/access-policies \
  -H "Authorization: Bearer $ADMIN_TOKEN" -H "Content-Type: application/json" \
  -d '{"principal_id":"<marcus-user-id>","principal_type":"user",
       "resource_type":"secrets","operation":"get","effect":"deny",
       "vault_id":"<prod-vault-id>"}' | jq -r .id)

curl -s $BASE/vaults/prod/secrets/<secret-id> \
  -H "Authorization: Bearer $MARCUS_TOKEN"
# 403 Forbidden: access policy denied      <-- note the DIFFERENT string

curl -s $BASE/access-policies/principal/<marcus-user-id> \
  -H "Authorization: Bearer $ADMIN_TOKEN" | jq '.total'
# 1

# Marcus's role assignment is untouched:
rocketvault vault-access list --vault prod   # Marcus appears by principal id, not by name

# Investigation clears him — revert instantly, no restart, no cache flush.
curl -s -X DELETE $BASE/access-policies/$POLICY_ID -H "Authorization: Bearer $ADMIN_TOKEN"
curl -s -o /dev/null -w '%{http_code}\n' $BASE/vaults/prod/secrets/<secret-id> \
  -H "Authorization: Bearer $MARCUS_TOKEN"
# 200
```

Two different `403` strings, two different gates:
- `access policy denied` → Gate 2, rejected **before** the role check ran
- `no role assignment grants this operation in this vault` → Gate 3

---

## Journey I — Revoking a Compromised Service Account

**Actor**: Wren

```bash
# Capture the assignment ID first — you need it to revoke.
ASSIGNMENT_ID=$(rocketvault vault-access list --vault prod \
  | awk -v p="$SVC_CLIENT_ID" '$3 == p { print $1 }')

# Prove the token works right now, and record its claims.
curl -s -o /dev/null -w '%{http_code}\n' $BASE/vaults/prod/keys/<key-id> \
  -H "Authorization: Bearer $SVC_TOKEN"
# 200

echo "$SVC_TOKEN" | cut -d. -f2 | base64 -d 2>/dev/null | jq '{exp,jti,sub}'

# Revoke.
rocketvault vault-access revoke "$ASSIGNMENT_ID" --vault prod
# revoked assignment <id>

# SAME token, no new login, no reissue:
curl -s -o /dev/null -w '%{http_code}\n' $BASE/vaults/prod/keys/<key-id> \
  -H "Authorization: Bearer $SVC_TOKEN"
# 403

echo "$SVC_TOKEN" | cut -d. -f2 | base64 -d 2>/dev/null | jq '{exp,jti,sub}'
# byte-identical to before — exp still ~55 minutes out
```

Nothing about the token changed. Only the `role_assignments` row did. Both `PolicyMiddleware` (HTTP) and `RequireDataAction` (CLI) call the same live `HasDataAction` lookup per request — no cache, no JWT-embedded claim, no revocation lag.

Then rotate the key so any material the leaked credentials wrapped is invalidated going forward:

```bash
rocketvault keys rotate <key-id> --vault prod    # as sofia (crypto_manager)
```

---

## Journey J — Retiring a Vault (and the purge trap)

```bash
# Soft-delete cascades to contained secrets/keys/certs, stamping each
# with the vault's own deleted_at.
rocketvault vaults delete staging

rocketvault vaults list --include-deleted --output json

# Recovery cascades too — but ONLY restores children matching that exact
# deleted_at timestamp.
rocketvault vaults recover staging
```

> A secret that had been soft-deleted **individually, earlier** carries a different `deleted_at` and is excluded by the `WHERE vault_id = ? AND deleted_at = ?` clause. It needs its own explicit restore. Don't assume vault recovery brings everything back.

```bash
# Separation of duties: a different principal authorizes the permanent purge.
rocketvault vault-access grant ops-oncall --role "Key Vault Purge Operator" --vault staging

rocketvault vaults delete staging
rocketvault vaults purge staging      # as ops-oncall
```

`ActionVaultPurge` is granted by **no other role** — not Administrator's data-plane bundle, not Crypto Officer.

### ⚠️ The purge trap

`PurgeVault` deletes the vault row and its `access_policies` rows and **stops**. No cascade call. No FK forcing it either — `secrets`/`keys`/`certificates` carry a plain `vault_id TEXT NOT NULL` with **no** `REFERENCES vaults(id)`, unlike `role_assignments.vault_id`, which does have `ON DELETE CASCADE`.

```bash
# Verify the orphans directly — the API cannot show you them.
sqlite3 /tmp/rv-test.db \
  "SELECT id, name, vault_id, deleted_at FROM secrets WHERE vault_id='<purged-vault-id>';"
# rows still present, still soft-deleted, pointing at a vault that no longer exists
```

They are unreachable through any route (vault-scoped routes 404 because the name no longer resolves; flat routes only ever hit `default`) and are never swept by the purge scheduler, which only purges individually-deleted *items*.

**Purge a vault's contents item-by-item before purging the vault**, or accept permanently orphaned rows.

One guardrail does exist in the other direction:

```bash
# A vault containing any purge-protected item refuses bulk purge, fail-closed.
rocketvault vaults purge <vault-with-protected-contents>
# Error: ... purge protection enabled
```

---

## Journey K — The CLI/HTTP Purge Divergence

**Actor**: Priya, `admin`, with **no** Purge Operator grant in `dev`

```bash
rocketvault vaults delete dev

# HTTP — no admin bypass on this path:
curl -s -o /dev/null -w '%{http_code}\n' -X DELETE $BASE/vaults/dev/purge \
  -H "Authorization: Bearer $ADMIN_TOKEN"
# 403

# CLI — admin bypass in CanPurgeVault:
rocketvault vaults purge dev
# succeeds
```

| Caller | CLI `vaults purge` | `DELETE /vaults/{name}/purge` |
|---|---|---|
| Non-admin with **Key Vault Purge Operator** | ✅ | ✅ |
| **Admin** with no role grant | ✅ (admin bypass) | ❌ 403 |

Same person, same authority, same vault — two different answers depending on which door she walks through. Confirm explicitly rather than assuming parity. (Correction 8's global-role gate is the *other*, larger divergence.)

---

## Journey L — Compliance Auditor

**Actor**: Dae-Ho (global role `user`)

```bash
rocketvault vault-access grant daeho --role "Key Vault Reader" --vault prod
rocketvault vault-access grant daeho --role "Key Vault Reader" --vault staging

# As Dae-Ho — keys list/get need NO global role, only the data action:
rocketvault users login --username daeho --password '<pw>' --totp-code "$DAEHO_TOTP"
rocketvault keys list --vault prod --output json
rocketvault secrets list --vault prod --output json      # metadata only
rocketvault certificate get <cert-id> --vault prod

rocketvault secrets get <secret-id> --vault prod
# Error: forbidden — Reader holds readMetadata, not secrets/get
```

**Audit logs are admin-only and cut across all vaults** — his Reader grants are irrelevant:

```bash
rocketvault audit logs --limit 50
# Error: forbidden

curl -s -o /dev/null -w '%{http_code}\n' $BASE/audit/logs \
  -H "Authorization: Bearer $DAEHO_TOKEN"
# 403
```

Priya has to run them on his behalf:

```bash
rocketvault audit logs --from 2026-07-01 --to 2026-09-30 \
  --action create_key --outcome success --limit 100 --output json

rocketvault audit report --type soc2 --from 2026-07-01 --to 2026-09-30 --format csv
rocketvault audit report --type gdpr --from 2026-07-01 --to 2026-09-30 \
  --subject-id <daeho-user-id>

rocketvault audit config                        # omitted/0 --retention-days = view, not set
# Current audit log retention: 90 days

rocketvault audit config --retention-days 90    # set — a daily job then purges older entries
# Retention policy updated: 90 days
```

> **Friction point worth flagging to whoever designs your compliance process**: a vault-scoped read-only auditor cannot self-serve audit evidence.

Tear down the temporary grant:

```bash
rocketvault vault-access revoke <daeho-staging-assignment-id> --vault staging
```

---

## Journey M — Offboarding

```bash
# 1. Enumerate per vault — there is no "revoke everything" command.
for V in default dev staging prod; do
  echo "== $V"
  rocketvault vault-access list --vault "$V" \
    | awk -v p="$MARCUS_ID" '$3 == p { print $1, $2 }'
done

# 2. Revoke each. Takes effect on Marcus's very next request.
rocketvault vault-access revoke <assignment-id> --vault dev

# 3. Delete the account. His existing JWT should 401 immediately, not at TTL.
rocketvault users delete <marcus-user-id>

curl -s -o /dev/null -w '%{http_code}\n' $BASE/vaults/dev/secrets \
  -H "Authorization: Bearer $MARCUS_TOKEN"
# 401

# 4. Clean up any explicit-deny policies naming him — user deletion does NOT
#    remove these.
curl -s $BASE/access-policies/principal/<marcus-user-id> \
  -H "Authorization: Bearer $ADMIN_TOKEN" | jq -r '.policies[].id' \
  | xargs -I{} curl -s -X DELETE $BASE/access-policies/{} \
      -H "Authorization: Bearer $ADMIN_TOKEN"

# 5. Clear his cached CLI session on any shared machine (local only — this
#    does NOT revoke the token server-side).
rocketvault users logout
```

---

## Journey N — Multi-Vault Isolation Verification

```bash
# Two users, one vault each.
rocketvault vault-access grant alice --role "Key Vault Secrets Officer" --vault vault-a
rocketvault vault-access grant bob   --role "Key Vault Secrets Officer" --vault vault-b

# As alice, target vault-b's secret by its exact UUID:
rocketvault secrets get <vault-b-secret-id> --vault vault-b
# Error: forbidden: no role grants ... in this vault

curl -s -o /dev/null -w '%{http_code}\n' $BASE/vaults/vault-b/secrets/<id> \
  -H "Authorization: Bearer $ALICE_TOKEN"
# 403 — not a silent success, not a partial leak

# `default` behaves identically to a named vault, except it cannot be deleted:
rocketvault vaults delete default
# Error: the default vault cannot be deleted
```

**Cache check — security-relevant, not a perf check.** `vaultcache` sits directly in the authorization path:

```bash
# With cache.vaults.enabled: true and a live TTL window:
curl -s -X PATCH $BASE/vaults/vault-a \
  -H "Authorization: Bearer $ADMIN_TOKEN" -H "Content-Type: application/json" \
  -d '{"enabled":false}'

# Immediately resolve the same vault by name through a different path:
curl -s -o /dev/null -w '%{http_code}\n' $BASE/vaults/vault-a/secrets \
  -H "Authorization: Bearer $ALICE_TOKEN"
# Confirm this does not reflect a stale cached vault record in a way that
# produces an incorrect authorization decision.
```

---

## Journey O — Migrating a Secret Set to a New Vault, and Retiring the Original

**Actor**: Marcus (`secrets_manager`, continuing his Journey B ownership of `dev`)

Payments is being split into its own vault. Priya provisions it and grants Marcus the same role he already holds in `dev`:

```bash
rocketvault vaults create payments

rocketvault vault-access grant priya  --role "Key Vault Administrator" --vault payments
rocketvault vault-access grant marcus --role "Key Vault Secrets Officer" --vault payments
```

Marcus needs a fresh credential for the service account that will live in the new vault. `generate-password` runs entirely locally — no login, no vault, nothing stored:

```bash
rocketvault users login --username marcus --password '<pw>' --totp-code "$MARCUS_TOTP"

GENERATED_PW=$(rocketvault secrets generate-password --length 24 --special=true \
  | awk '{print $NF}')
# Generated password: <24 random chars>

rocketvault secrets create payments-db-pass "$GENERATED_PW" --tags prod,db --vault payments
```

> `generate-password` and the HTTP `POST /vaults/{name}/secrets/generate` route are **not** the same operation. The CLI command only prints a string — it never touches a vault. The HTTP route (`generateSecret` in `api/secrets.go`) takes a `name` and creates the secret in one step, storing the generated value directly. There is no CLI command that does what the HTTP route does, and no HTTP route that does what the CLI command does.

Now migrate the rest of the deprecated `payments-legacy`-tagged secrets out of `dev`. Export is encrypted by default — passphrase from the environment so the run is non-interactive:

```bash
export ROCKETVAULT_EXPORT_PASSPHRASE='correct-horse-battery-staple'

rocketvault secrets export --file /tmp/payments-legacy.json \
  --tags payments-legacy --vault dev
# Secrets exported successfully
# Format: json
# Encryption: passphrase (argon2id + AES-256-GCM)
# File: /tmp/payments-legacy.json
```

Import into the new vault — first, the wrong-usage case, with the passphrase deliberately unset:

```bash
unset ROCKETVAULT_EXPORT_PASSPHRASE

rocketvault secrets import --file /tmp/payments-legacy.json --vault payments
# Error: /tmp/payments-legacy.json is an encrypted export but no passphrase
# is available: pass --passphrase-file or set ROCKETVAULT_EXPORT_PASSPHRASE
```

Wrong passphrase fails differently — the file is real, the key derived from it just doesn't open the envelope:

```bash
echo 'not-the-real-passphrase' > /tmp/wrong-pass.txt
rocketvault secrets import --file /tmp/payments-legacy.json \
  --passphrase-file /tmp/wrong-pass.txt --vault payments
# Error: failed to decrypt /tmp/payments-legacy.json: wrong passphrase or corrupted file
```

Correct passphrase, correct target vault:

```bash
echo 'correct-horse-battery-staple' > /tmp/export-pass.txt
rocketvault secrets import --file /tmp/payments-legacy.json \
  --passphrase-file /tmp/export-pass.txt --vault payments
# Secrets imported successfully
# Imported: 6
# Skipped: 0
# Failed: 0

rocketvault secrets list --vault payments --tags payments-legacy --output json
```

> `--format` describes the payload inside the envelope, not the file on disk. A sealed CSV export is still a JSON envelope on the filesystem — it's read back with `--format csv`, never `--format json`, even though `file /tmp/whatever` would report it as JSON.

With the copies confirmed in `payments`, retire the originals in `dev` — soft-delete only, no CLI recover/purge:

```bash
rocketvault secrets delete <legacy-secret-id> --vault dev
```

> `secrets delete` has no `--force`/confirmation prompt and no equivalent "delete all matching tag" batch form — each of the six migrated secrets is deleted by its own UUID, one invocation per secret.

Equivalent HTTP for export/import — genuinely different request shapes, not just a different auth header. Export is a JSON body returning raw file bytes; import is `multipart/form-data`, matching what `cmd/secrets/export.go`/`import.go`'s remote-mode paths (`cliclient.ExportSecretsRemote`/`ImportSecretsRemote`) send under the hood:

```bash
MARCUS_TOKEN=$(curl -s -X POST $BASE/users/login -H "Content-Type: application/json" \
  -d '{"username":"marcus","password":"<pw>","totp_code":"'"$MARCUS_TOTP"'"}' | jq -r .token)

curl -s -X POST $BASE/vaults/dev/secrets/export \
  -H "Authorization: Bearer $MARCUS_TOKEN" -H "Content-Type: application/json" \
  -d '{"format":"json","tags":["payments-legacy"],"include_tags":true,
       "encrypt":true,"passphrase":"correct-horse-battery-staple"}' \
  -o /tmp/payments-legacy-http.json
# Content-Disposition: attachment; filename=secrets-export-<timestamp>.json

curl -s -X POST $BASE/vaults/payments/secrets/import \
  -H "Authorization: Bearer $MARCUS_TOKEN" \
  -F "file=@/tmp/payments-legacy-http.json" \
  -F "format=json" -F "overwrite=false" \
  -F "passphrase=correct-horse-battery-staple" | jq .
# {"success":true,"message":"Successfully imported 6/6 secrets", ...}
```

No CLI/HTTP authorization divergence here beyond Correction 8's usual gate: both `export` and `import` still require `admin` or `secrets_manager` globally on the CLI path (Marcus holds `secrets_manager`), on top of the same `ActionSecretsGet`/`ActionSecretsSet` vault role check HTTP enforces alone.

---

## Journey P — A `user`-Role Principal Runs the Entire Secret-Rotation Lifecycle

**Actor**: Wren (global role `user` — elsewhere in this doc she only ever grants/revokes role assignments, per Correction 8's table)

The platform team wants `prod-db-password` (a database credential secret Marcus created earlier under `Key Vault Secrets Officer`) rotated automatically every 30 days. They hand the on-call rotation duty to Wren. She has no `admin`, no `secrets_manager` — just `user` — so the first thing worth checking is whether that even matters for this feature.

```bash
rocketvault vault-access grant wren --role "Key Vault Secrets Officer" --vault prod
# granted Key Vault Secrets Officer to wren in vault (assignment ...)

# As Wren:
rocketvault users login --username wren --password '<pw>' --totp-code "$WREN_TOTP"
```

**The contrast that matters.** Try the thing Correction 8 already documents as gated, then the thing it documents as not:

```bash
rocketvault secrets create scratch-secret 'x' --vault prod
# Error: forbidden: requires admin or secrets_manager role

rocketvault secrets rotation create --name db-cred-30d --interval 30 \
  --reminder 7 --auto-rotate --vault prod
# Rotation policy created successfully
# Policy ID: <policy-id>
# Name: db-cred-30d
# Interval: 30 days
# Auto-rotate: true
```

Same principal, same vault, same `user` global role. One command is `forbidden` before it even looks at her vault grant; the other never asks the question. This is the divergence Correction 8 calls out but no journey had actually run until now.

Assign it to the real secret:

```bash
rocketvault secrets rotation assign --policy-id <policy-id> \
  --secret-id <secret-id> --vault prod
# Policy assigned to secret successfully.
```

> **Re-running `assign` for the same pair does not fail cleanly.** It bubbles a raw, triple-wrapped driver error instead of a friendly "already assigned":
> ```
> rocketvault secrets rotation assign --policy-id <policy-id> --secret-id <secret-id> --vault prod
> # Error: failed to assign policy to secret: failed to assign policy to secret: failed to
> # assign policy to secret: UNIQUE constraint failed: secret_policies.secret_id, secret_policies.policy_id
> ```
> The service wraps once, the CLI wraps again on top of `RunE`'s own `%w` — three layers of the same sentence around one SQLite constraint name. If you're scripting this, check for `UNIQUE constraint failed` in the output rather than matching a clean message.

```bash
rocketvault secrets rotation list --vault prod
# ID           NAME         INTERVAL  AUTO-ROTATE  ENABLED  CREATED
# --           ----         --------  -----------  -------  -------
# <policy-id>...  db-cred-30d  30 days   true         true     2026-08-25
#
# Found 1 rotation policies
```

**Thirty days pass.** The server has been running the whole time — `secret rotation scheduler started` at boot — but this policy's auto-rotate would only fire from inside that live `serve` process, silently, on its own schedule. Wren checks in instead of waiting to find out:

```bash
rocketvault secrets rotation status --vault prod
# Rotation Status
# ────────────────────────────────────────
# Secrets due for rotation:
#   - Secret <secret-id-abbrev>... (next: 2026-09-24)
#
# Active rotation policies:
#   - db-cred-30d: every 30 days (auto-rotate enabled)
```

An incident that week means the credential needs rotating right now, not on the scheduler's clock. `rotate` is the only CLI path to that, and it still needs a value source:

```bash
rocketvault secrets rotation rotate --secret-id <secret-id> --policy-id <policy-id> --vault prod
# Error: no new value: pass --value <value> to set one, or --generate to have one generated

rocketvault secrets rotation rotate --secret-id <secret-id> --policy-id <policy-id> \
  --generate --length 24 --vault prod
# Secret rotated successfully.

rocketvault secrets rotation history --secret-id <secret-id> --vault prod
# ROTATED_AT        TRIGGERED_BY  PREV_VERSION  NEW_VERSION  NOTES
# ----------        ------------  ------------  -----------  -----
# 2026-08-25 22:24  manual        1             2
#
# Found 1 rotation events
```

> `TRIGGERED_BY` reads `manual` here — and always will, even for a scheduler-driven rotation. `model.TriggerScheduled` exists in `model/rotation.go` but is never referenced by any code path; both the CLI's manual `rotate` and the background scheduler funnel through the same `PerformManualRotation`, which unconditionally hardcodes `TriggeredBy: model.TriggerManual`. The column exists but does not actually distinguish rotation sources. Nothing outside RocketVault was told about the new value either way — whatever consumes `prod-db-password` still needs updating by hand.

**Migration.** The service this credential belongs to is being decommissioned in favor of a managed database, so the rotation duty ends. Turn off auto-rotate first — it's a partial update, so only the flags actually passed change:

```bash
rocketvault secrets rotation update --id <policy-id> --auto-rotate=false --vault prod
# Rotation policy updated successfully.
```

Then take the secret out of rotation and remove the policy entirely:

```bash
rocketvault secrets rotation unassign --policy-id <policy-id> --secret-id <secret-id> --vault prod
# Policy removed from secret successfully.

rocketvault secrets rotation unassign --policy-id <policy-id> --secret-id <secret-id> --vault prod
# Error: failed to remove policy from secret: failed to remove policy from secret: policy assignment not found

rocketvault secrets rotation delete --id <policy-id> --vault prod
# Rotation policy deleted successfully.

rocketvault secrets rotation delete --id <policy-id> --vault prod
# Error: failed to delete rotation policy: failed to delete rotation policy: rotation policy not found
```

> Deleting the policy does not touch `prod-db-password` or its rotation history — `secrets rotation history --secret-id <secret-id> --vault prod` still shows the `manual` entry above, now with a `PolicyID` that no longer resolves to anything. Past events outlive the policy that caused them, by design.

**Confirming Correction 9's other half of the claim** — that this whole surface has no HTTP route at all, so a would-be REST client gets a plain 404, not a 403:

```bash
curl -s -o /dev/null -w '%{http_code}\n' $BASE/vaults/prod/secrets/rotation-policies \
  -H "Authorization: Bearer $WREN_TOKEN"
# 404

curl -s -o /dev/null -w '%{http_code}\n' $BASE/secrets/rotation \
  -H "Authorization: Bearer $WREN_TOKEN"
# 404
```

There is no authorization decision to make over HTTP for this feature — it isn't wired up, period.

| Caller (global role `user`, `Key Vault Secrets Officer` in `prod`) | `secrets rotation create/assign/rotate/update/delete/unassign/list/history/status` | `secrets create/update/delete` |
|---|---|---|
| CLI | ✅ — no global role checked | ❌ `forbidden: requires admin or secrets_manager role` |
| HTTP | 404 — no route exists | ✅ (same vault data action, no global-role concept on this path) |

Every other mutating resource in this codebase — `keys`, `certificate`, `secrets` itself — layers a CLI-only global-role gate on top of the vault check. `secrets rotation *` is the one command tree where a bare `user` global role, plus nothing but an ordinary vault role assignment, is sufficient to create policies, assign them to secrets, and rotate credentials on demand. Whether that is an oversight or a deliberate scope decision, it is not documented anywhere as intentional — it is simply what the code does.

---

## Journey Q — Certificate Manager Issues, Chains, and Retires a TLS Certificate

**Actor**: Noor (`certificate_manager` — required for every CLI certificate mutation, exactly like Sofia's `crypto_manager` requirement in Journey C; she also needs `crypto_manager`, `keys/sign` and her own keys to issue anything, see below)

```bash
# Priya creates the account with the global role Correction 8 requires.
rocketvault users create --new-username noor --new-password '<pw>' --new-role certificate_manager

# Grant the vault role. "Key Vault Certificates Officer" is full control —
# read/create/update/delete/backup/restore/recover/purge — and one of the
# eight roles Wren (Data Access Administrator) is allowed to grant.
rocketvault vault-access grant noor --role "Key Vault Certificates Officer" --vault prod
```

A certificate is always issued over an existing key, and key creation needs `crypto_manager`/`admin` — a role Noor's `certificate_manager` does **not** cover. She cannot self-serve the key:

```bash
rocketvault users login --username noor --password '<pw>' --totp-code "$NOOR_TOTP"

rocketvault keys create --name checkout-tls-leaf --type RSA --bits 2048 --vault prod
# Error: forbidden: requires admin or crypto_manager role
```

**Issuing a certificate signs with a key, so three things must all be true: two about the caller's grants and ownership, one about the key.** Noor satisfies none of them yet, since she holds only Certificates Officer and owns no key:

1. The caller holds `Microsoft.KeyVault/vaults/certificates/create` in the vault (Key Vault Certificates Officer) **and** `Microsoft.KeyVault/vaults/keys/sign/action` in the same vault. Of the built-in roles, Administrator, Crypto Officer and Crypto User hold `keys/sign` (`model/azure_roles.go`); Certificates Officer alone does not, so it is refused. An explicit deny policy on `(keys, sign)` refuses the call too. The same rule applies to `certificate renew`, to the REST create and renew routes, to the MCP `create_certificate` and `renew_certificate` tools, and to the background auto-renew scheduler, which checks it for the certificate's owner.
2. The caller **owns** the key (the B32 owner check): the key's creator must be the caller. A key Sofia created cannot be used by Noor, even with every role in the vault. No `cmd/keys` command changes a key's owner, so the CLI has no way for one user to issue over another user's key. Noor has to create her own keys.
3. The key is enabled, not revoked, and inside its validity window. The same holds for a CA certificate's own key when the certificate is signed by that CA.

So Priya gives Noor what she needs to make her own keys and to sign with them: the `crypto_manager` global role alongside `certificate_manager` (`--new-role` is repeatable, and the update replaces the role list, so both are passed), and `Key Vault Crypto Officer` in `prod`, which holds `keys/create` and `keys/sign`:

```bash
# As Priya:
rocketvault users update <noor-user-id> --new-role certificate_manager --new-role crypto_manager
rocketvault vault-access grant noor --role "Key Vault Crypto Officer" --vault prod

# As Noor, after logging in again (a role change ends the user's sessions):
rocketvault keys create --name checkout-ca-key --type RSA --bits 4096 --vault prod
rocketvault keys create --name checkout-tls-leaf --type ECDSA --curve P-384 --vault prod
```

Sofia (`crypto_manager`) also has a key in `prod`, but it is hers. Noor holds every role she needs and is still refused, by the owner check:

```bash
# As Sofia:
rocketvault keys create --name sofia-owned-key --type RSA --bits 2048 --vault prod

# As Noor:
rocketvault certificates create --name not-allowed \
  --key-id <sofia-owned-key-id> --validity-days 365 --vault prod
# Error: failed to create certificate: forbidden: cannot use other users' keys
```

**Self-signed certificate over an existing key** — the simple case, no CA involved:

```bash
# As Noor, over a key Noor created:
rocketvault certificates create --name checkout-tls-selfsigned \
  --key-id <checkout-tls-leaf-key-id> --validity-days 365 --tags prod,tls --vault prod
# ID    Name                       Created
# <id>  checkout-tls-selfsigned    2026-08-25T...
```

`--validity-days` must be between 1 and 36500, but the CLI itself only rejects a value of 0 or less. A larger value passes the flag check and the vault checks, and the service then refuses it (`Error: failed to create certificate: invalid validity days: must not exceed 36500`). Flag validation runs before the vault-scoped authorization checks and the key lookup — but **after** the global-role gate. `cmd/certificates/create.go` checks the global roles (`admin` or `certificate_manager`) in `vaultcli.Caller`, ahead of the `name`/`key-id`/`validity-days` check; only `s.Authorize()` (`certificates/create`) and `s.RequireAlso` (`keys/sign`) run after flag validation. Noor holds `certificate_manager`, so she reaches the missing-field error below. A caller without that global role who also omits a required flag gets the forbidden error instead, never this one:

```bash
rocketvault certificates create --key-id <checkout-tls-leaf-key-id> --validity-days 365 --vault prod
# Error: name, key-id, and validity-days are required
```

**CA-signed issuance** — first stand up a CA certificate (`--is-ca`, self-signed since it has no `--ca-cert-id` of its own), then issue the leaf against it:

```bash
rocketvault certificates create --name checkout-root-ca \
  --key-id <checkout-ca-key-id> --is-ca --validity-days 3650 --vault prod
# ID           Name              Created
# <ca-cert-id> checkout-root-ca  2026-08-25T...

rocketvault certificates create --name checkout-tls-chained \
  --key-id <checkout-tls-leaf-key-id> --ca-cert-id <ca-cert-id> \
  --validity-days 90 --tags prod,tls --auto-renew --renewal-days 30 --vault prod
```

`--is-ca` and `--ca-cert-id` are mutually exclusive by design — a certificate is either the CA or signed by one, never both in the same call:

```bash
rocketvault certificates create --name broken --key-id <checkout-tls-leaf-key-id> \
  --is-ca --ca-cert-id <ca-cert-id> --validity-days 90 --vault prod
# Error: failed to create certificate: cannot issue a CA-signed certificate as a CA: intermediate CA certificates are not supported
```

`--auto-renew`/`--renewal-days` only arm the background scheduler; nothing about `notify_before_expiry_days`-style delivery exists here either (Journey C's finding holds for certs too — check the scheduler ran, don't expect a notification).

List and inspect, `certificate` (singular) works everywhere as an alias for `certificates`:

```bash
rocketvault certificate list --vault prod --output json
rocketvault certificate get <ca-cert-id> --vault prod
# ID    Name              Tags  Expires        AutoRenew  Created
# <id>  checkout-root-ca        2036-08-23...  false      2026-08-25T...
```

`get`/`list` need no global role — only the vault data action, same as `keys get`/`list` in Correction 8's table. Daeho, holding only `Key Vault Reader` in `prod`, can run both against these certs without ever touching `certificate_manager`:

```bash
rocketvault certificate list --vault prod   # as daeho, works
```

**Update** — metadata only, never re-signs, and only the flags you actually pass take effect:

```bash
rocketvault certificate update <leaf-cert-id> --tags prod,tls,rotated-2026-08 --vault prod
# Certificate updated successfully: <leaf-cert-id>

rocketvault certificate get <leaf-cert-id> --vault prod --output json | jq .name
# unchanged — --name was not passed on this call
```

**Renew** — re-issues over the *same* key and ID as a new version (the previous one is archived), and, unlike every other mutating cert command, checks `certificates/create`, not `certificates/update`. Like issuance it also needs `keys/sign` in the vault, and the key must still exist, be owned by the caller, and be enabled, not revoked and inside its validity window. Without `--validity-days` the current version's period is kept, capped at 36500 days:

```bash
rocketvault certificate renew <leaf-cert-id> --validity-days 180 --vault prod
# Certificate renewed successfully!
# Certificate ID: <leaf-cert-id>
# Version: <previous version + 1>
# Validity: 180 days
```

Prove the divergence: grant a role with `update` but not `create`, and renew still fails even though update-only commands would succeed for that same principal:

```bash
rocketvault vault-access grant noor --role "Key Vault Certificate User" --vault staging
# As noor, in staging (Certificate User = read only, per model/azure_roles.go):
rocketvault certificate renew <staging-cert-id> --vault staging
# Error: failed to renew certificate: forbidden: no role grants Microsoft.KeyVault/vaults/certificates/create in this vault
```

**Certificates Officer alone is refused.** The `keys/sign` check runs right after the `certificates/create` check and before the certificate is looked up, so it fires whatever certificate ID is named. Priya grants Noor Certificates Officer in `dev` and nothing else there:

```bash
rocketvault vault-access grant noor --role "Key Vault Certificates Officer" --vault dev
# As noor, in dev (Certificates Officer holds certificates/create, not keys/sign):
rocketvault certificate renew <dev-cert-id> --vault dev
# Error: failed to renew certificate: forbidden: no role grants Microsoft.KeyVault/vaults/keys/sign/action in this vault
```

`certificate create` is refused the same way. Granting `Key Vault Crypto User` (or Crypto Officer) in `dev` clears it.

Over REST the same refusal is a `403` whose message is `Insufficient permissions: Microsoft.KeyVault/vaults/keys/sign/action`, on both `POST .../certificates` and `POST .../certificates/{certificate_id}/renew`. The two paths audit it differently: the HTTP handler writes an audit row with status `denied` (operation `create_certificate` or `renew_certificate`), while the CLI writes status `failed`. The HTTP row's text is the same whether an explicit deny policy or a missing role grant caused the refusal; the CLI's error text distinguishes them (`access denied by an explicit access policy for ...` versus `no role grants ... in this vault`).

A CA cert past its own validity window, or disabled, blocks renewal of anything it signed — the renewal is refused, never silently downgraded to self-signed.

**Delete** — soft-delete only; the CLI has no `recover`/`purge` for certificates (REST-only, mirroring Correction 9's key-lifecycle gaps):

```bash
rocketvault certificate delete <leaf-cert-id> --vault prod
# Certificate deleted successfully: <leaf-cert-id>

rocketvault certificate list --vault prod --output json | jq '[.[] | select(.id=="<leaf-cert-id>")]'
# []  -- gone from the listing, but still present as a soft-deleted row

rocketvault certificate get <leaf-cert-id> --vault prod
# Error: failed to get certificate: certificate not found: certificate not found or access denied
```

Recovering it needs REST, since the CLI has no equivalent subcommand:

```bash
curl -s -X POST $BASE/vaults/prod/deleted/certificates/<leaf-cert-id>/restore \
  -H "Authorization: Bearer $NOOR_OR_ADMIN_TOKEN"
```

---

## Journey R — Disaster Recovery: Scheduled Backups and a Post-Rotation Restore

**Actor**: Priya (`admin`) — per `backup --help`: *"Every subcommand requires the global admin role."* This is a pure global-role gate: `requireBackupAdmin` checks only the `admin` role, with no vault lookup at all. A `--vault` flag does exist (inherited from the root command on every subcommand), but `backup` never reads it — it has no vault-scoped form, and an operator with a role in only one vault cannot use these commands regardless of what they pass to `--vault`.

```bash
rocketvault backup list --dir /var/backups/rocketvault   # as marcus (secrets_manager)
# Error: forbidden: requires admin role
```

### Setting up the nightly job

RocketVault has no built-in backup scheduler — no `--schedule` flag, no daemon. "Scheduled" means an external cron/systemd timer invoking the CLI directly. The cached CLI session (see Global setup) refreshes itself transparently via its refresh token, so a non-interactive cron job keeps working as long as someone has logged in at least once and the refresh token hasn't itself expired:

```bash
# /etc/cron.d/rocketvault-backup
0 2 * * * root cd /opt/rocketvault && ./rocketvault backup create \
  --file /var/backups/rocketvault/nightly-$(date +\%F).backup \
  >> /var/log/rv-backup.log 2>&1
```

Priya runs the same command by hand first, to confirm the pipeline actually works before trusting it to cron:

```bash
rocketvault backup create --file /var/backups/rocketvault/nightly-2026-08-25.backup
# Backup created successfully.
# File: /var/backups/rocketvault/nightly-2026-08-25.backup
# Encrypted: true
```

> The file destination is `--file`/`-f`, not `--output`/`-o`. `backup create` briefly had its own local `--output` flag for the file path, which collided with root's persistent `--output` (the table/json/yaml format selector) and made `backup create --output <path>` fail outright with a format-validation error; fixed 2026-08-22 by renaming it to `--file`/`-f` (`.claude/known-bugs.md` § B48).

### Confirming what landed

```bash
rocketvault backup list --dir /var/backups/rocketvault
# TIMESTAMP  VERSION  TABLES  RECORDS  ENCRYPTED  FILE                          SIZE    MODIFIED
# ---------  -------  ------  -------  ---------  ----                          ----    --------
# -          -        -       -        true       nightly-2026-08-25.backup     482113  2026-08-25 02:00:01
#
# Found 1 backup files in /var/backups/rocketvault
```

The dashes are correct, not broken: `backup list` never touches the master key, so a default encrypted backup can't be parsed for its timestamp/version/table/record counts — only filename, size and mtime come from the filesystem. `backup create`'s own `Encrypted: true` line at write time is your real confirmation; `list` is for inventory, not verification.

### The incident

Wednesday: a bad migration corrupts the `secrets` table in `prod`. Priya decides to restore Monday night's backup rather than hand-repair rows.

```bash
# Stop the server first. Nothing in "backup restore" enforces this -- it's
# operator discipline, not a safety check the command performs.
sudo systemctl stop rocketvault

rocketvault backup restore --file /var/backups/rocketvault/nightly-2026-08-25.backup
# WARNING: This will replace all existing data in the database.
# Backup file: /var/backups/rocketvault/nightly-2026-08-25.backup
# Decrypt: true
# Are you sure you want to continue? (type 'yes' to confirm): yes
# Error: restore failed: failed to read backup file: failed to decrypt backup: failed to decrypt: cipher: message authentication failed
```

**The trap**: on Tuesday, between the backup and the incident, ops ran routine master-key hygiene:

```bash
rocketvault master-key rotate --new-key-env NEW_MASTER_KEY --yes
```

Both `secrets.value`-style column encryption *and* a backup file's own `--encrypt` wrapper are sealed with the exact same `master_key` from configuration (`common.EncryptSecret`/`DecryptSecret`, both reading `viper.GetString("master_key")`). `master-key rotate` re-encrypts every live row onto the new key, but — as its own `--help` states outright — *"Backup files made with 'rocketvault backup create' are not touched by this command and stay sealed under the old key, so keep that key if you may need to restore one."* Monday's backup is still wrapped in Monday's key; the server's config now holds Tuesday's. Same GCM auth-tag failure either layer, whichever fails first.

```bash
# Point this instance at the key that was active when the backup was taken,
# just for the restore -- not the current production key.
export MASTER_KEY="<the pre-rotation key, saved before Tuesday's rotation>"

rocketvault backup restore --file /var/backups/rocketvault/nightly-2026-08-25.backup
# WARNING: This will replace all existing data in the database.
# Backup file: /var/backups/rocketvault/nightly-2026-08-25.backup
# Decrypt: true
# Are you sure you want to continue? (type 'yes' to confirm): yes
# Database restored successfully from /var/backups/rocketvault/nightly-2026-08-25.backup
```

> **This is why `master-key rotate`'s own help says to "keep that key if you may need to restore one."** Losing the pre-rotation key permanently is not just an inconvenience here — every secret value, key PEM and certificate private key restored from that backup is column-level ciphertext sealed under the same lost key, independent of the file wrapper. There is no recovery path if it's gone.

Two more things worth knowing before declaring the incident closed:

- **The restore doesn't undo Tuesday's rotation.** The just-restored `secrets`/`keys`/`certificates` rows are back to being sealed under the *old* key, while `MASTER_KEY` is still pointed at it. Before pointing the running server back at the new key, either re-run `master-key rotate` onto the new key again, or leave the config on the old key — decide deliberately, don't let it default silently.
- **Restore only refills tables present in the file.** `RestoreBackup`'s `Long` text is explicit: *"Tables the backup does not contain are left alone."* A table added by a schema migration after Monday's backup was taken is untouched by the restore — for better or worse, restoring an old backup does not roll back your schema, only your data.

```bash
sudo systemctl start rocketvault
# Have Marcus and Sofia re-run "users login" -- the sessions table is one of
# the tables the backup covers, wiped and refilled like every other, so any
# server-side session state created after Monday's backup point is gone too.
```

---

**What a RocketVault backup is, precisely, for anyone planning a DR runbook around it**: one JSON file, whole-instance (every vault, no vault-scoped restriction — the inherited `--vault` flag is accepted but ignored), covering every table verbatim — including soft-deleted rows, users, role assignments, sessions and the audit log. Secret values and private keys inside it are exactly as sealed as they are in the live database, regardless of the file's own `--encrypt` flag; `--encrypt` only wraps the outer JSON blob, using whatever `master_key` was configured at that moment. There is no dry-run for restore and no partial/selective restore — it is whole-file, whole-transaction, or nothing.

---

## Journey S — Rotating the Master Key After an Infrastructure Departure

**Actor**: Priya (`admin` — `master-key rotate` checks the global admin role only; unlike the Correction 8 gate on `keys`/`secrets`, `crypto_manager` and `secrets_manager` do **not** get a pass here)

**Why**: An SRE who held root SSH access to the database host is leaving the team. Journey M's offboarding steps (revoke role assignments, delete the account) stop that person authenticating through the API or CLI ever again — but they did nothing about the master key. Anyone with filesystem access to the host could have copied `dev-rocketvault.db` (or a Postgres dump) alongside `.rocketvault.yaml`'s `master_key` before their access was cut. Every `secrets.value`, `secret_versions.value`, `keys.value`, `key_versions.value`, and `certificates.private_key` row is still decryptable with whatever key they walked out with. Revoking their `role_assignments` rows, as Journey I and M do, is irrelevant to this threat — it only gates authenticated requests through the running server. The only remedy for a key that has already left the building is `rocketvault master-key rotate`.

This is a different kind of operation from everything else in this document: not vault-scoped (`--vault` is accepted as a global flag but does not apply — the key protects every vault at once), not a role-assignment decision, and — per `docs/runbooks/master-key-rotation.md` — meant to run **offline**, in a maintenance window.

```bash
# Confirm the gate first — daeho (global role `user`) cannot even dry-run this.
rocketvault master-key rotate --new-key-env NEW_MASTER_KEY --dry-run
# Error: forbidden: requires admin role
```

### Step 1 — Generate the new key, and avoid the naming trap

```bash
export NEW_MASTER_KEY="$(openssl rand -base64 32)"
```

> Do not leave a stray `MASTER_KEY` exported in this shell. Viper resolves an exported `MASTER_KEY` before the config file, so `--old-key-env` (left unset here, defaulting to the config file) would silently pick up that leftover value instead of `.rocketvault.yaml`'s `master_key`. If it happens to equal the new key, the run refuses outright — and note the tool always labels the default source "config file (master_key)" in this error, even when an exported `MASTER_KEY` is what actually supplied the value:
> ```
> Error: the new master key is identical to the old one (old key source: config file
> (master_key)); note that an exported MASTER_KEY environment variable takes
> precedence over the config file
> ```
> Store `$NEW_MASTER_KEY` in a secret manager now — if it's lost after the real run, every row it just resealed is unrecoverable.

### ⚠️ Nothing in the code stops you from running this against a live server

The `--help` text and the runbook both say to stop the server first. That is advice, not an enforced precondition — `runMasterKeyRotate` never checks whether the server process is running, holds a lock, or has a PID file. The actual guard is narrower and comes later: every `UPDATE` in `rekey.go`'s `applyBatch` is qualified with `AND <column> = ?` bound to the exact ciphertext read during the earlier plan pass, so a row rewritten by a still-live server between plan and apply matches zero rows and the batch aborts:

```
Error: master key rotation failed: keys.value: row [<id>] changed while the rotation
was running (0 rows updated, expected 1) — stop the RocketVault server and re-run
```

That failure only kills the batch and target it happened in — targets are processed one table at a time (`secrets` → `secret_versions` → `keys` → `key_versions` → `certificates`), each fully read-then-written, and batches within a target commit independently at `--batch-size` (default 100). Run this against a live server and the realistic outcome isn't corruption, it's a **partially rotated instance**: `secrets` fully done, `keys` half-done, and an error telling you to stop the server and re-run. Re-running with the same key pair is safe — `classify()` recognizes rows already sealed under the new key and skips them — but "safe to resume" is not the same guarantee as "one atomic operation." Stop the server. The advice is load-bearing even though nothing enforces it.

### Step 2 — Back up first

```bash
cp dev-rocketvault.db dev-rocketvault.db.pre-rotation-2026-08-25   # SQLite
# pg_dump "$DATABASE_URL" > rocketvault-pre-rotation.sql           # Postgres
```

This backup plus the still-valid old key is the only rollback path — `master-key rotate` has no inverse command. (See Journey R for what happens if you rotate the key *before* verifying you can still restore an old backup with the key you're about to retire.)

### Step 3 — Dry run, and read the report before touching anything

```bash
rocketvault master-key rotate --new-key-env NEW_MASTER_KEY --dry-run
```

Verified output, run against a real dev instance:

```
Old master key source: config file (master_key)
New master key source: environment variable NEW_MASTER_KEY
Mode: DRY RUN (no rows will be written)

TABLE            COLUMN       ROWS  RE-ENCRYPTED  ALREADY NEW KEY  SKIPPED (HSM)
secrets          value        3     3             0                0
secret_versions  value        0     0             0                0
keys             value        1     0             0                1
key_versions     value        0     0             0                0
certificates     private_key  0     0             0                0

Total rows re-encrypted: 3

Dry run complete. No rows were modified.
```

`SKIPPED (HSM)` counts key rows whose `value` column is a `pkcs11:`-prefixed token label rather than sealed PEM — that key material never left the HSM in the first place, so there is nothing for this command to touch, and it is **not** covered by this rotation at all. A departing engineer's exposure to HSM-backed key material is a separate PKCS#11/PIN-rotation problem, not this one.

### Step 4 — Run it for real

```bash
rocketvault master-key rotate --new-key-env NEW_MASTER_KEY
```

```
This rewrites every master-key-encrypted row in the database.
Stop the RocketVault server and take a database backup before continuing.
Type 'yes' to continue:
```

> **Scripting trap**: typing anything other than the exact string `yes` — including a blank line — prints `Aborted.` and **exits 0**. A maintenance script that only checks the exit code will read an aborted, no-op rotation as a success. For unattended runs, pass `--yes` explicitly rather than piping an answer to the prompt.

On confirmation, the table reprints with the same counts as the dry run, followed by:

```
Rotation complete. Set the new key as master_key in the configuration (or as the
MASTER_KEY environment variable) and restart the server.
Reminder: existing database backup files were sealed under the old key and are not
affected by this rotation — they will not restore once the old key is retired.
```

### Step 5 — Finish the job by hand

Nothing is written back to the config file for you:

```bash
# .rocketvault.yaml
master_key: "<value of $NEW_MASTER_KEY>"
```

```bash
rocketvault serve
rocketvault secrets list --vault default    # doesn't just list — GetSecret-style
                                             # paths decrypt every value; a clean
                                             # read is real proof config and DB agree
```

> Don't use `certificates list` as your restart check — `ListCertificates`/`GetCertificate` never touch `private_key`, so a clean `certificates list` proves nothing about whether the rotation and the running config actually agree.

### The compromise-driven trade-off this journey exists for

Rotating the key stops the departed engineer's copy from decrypting *future* writes and any row this run touched. It does **not** retroactively protect anything if you keep the old key around — and you may need to, briefly, for restore purposes:

| Guarantee | Real behavior |
|---|---|
| A row is never clobbered by two concurrent writers | ✅ guarded `UPDATE ... AND value = <ciphertext read during plan>` |
| The whole run is one atomic transaction | ❌ commits per batch, per target — a crash mid-run leaves some tables rotated, others not |
| Server-stopped precondition is enforced | ❌ advisory only (help text + runbook); no lock, no PID check |
| Safe to re-run after an interruption | ✅ `classify()` skips rows already on the new key |
| Existing `backup create` archives get rotated too | ❌ never — they stay sealed under the retired key permanently (Journey R) |
| New key is written to `.rocketvault.yaml` for you | ❌ manual edit, always |

That last two rows are the actual bite of this journey: if the whole point is to invalidate a key someone else copied, keeping it around "just in case an old backup needs restoring" defeats the purpose, but destroying it immediately makes every pre-rotation backup permanently unrestorable. Decide which risk you're accepting — retire the old key on a delay long enough to cover your backup retention window, or take a fresh `backup create` immediately after rotating and delete the old backups outright — before you throw the old key away. `master-key rotate` will not remind you to make that call; the runbook (`docs/runbooks/master-key-rotation.md`, step 8) is the only place it's written down.

---

## Journey T — Working Across Prod, Staging, and Dev From One Laptop

**Actor**: Priya (`admin`) — the same `dev`/`staging`/`prod` vaults from Journey A, now reached from three separately-running RocketVault instances instead of one shared box.

```bash
# Each environment is its own RocketVault deployment (Journey A's vaults
# just happen to share names with these). --default-username and
# --default-vault are optional; --server is the only required flag.
rocketvault context add prod \
  --server https://vault.prod.internal \
  --default-username ops-oncall --default-vault prod

rocketvault context add staging \
  --server https://vault.staging.internal:8443 \
  --default-vault staging

rocketvault context add dev \
  --server http://localhost:8774 --default-vault dev

rocketvault context list
```
```
Name     Server                               Default Username  Default Vault  Current
-------  -----------------------------------  ----------------  -------------  -------
dev      http://localhost:8774                                  dev
prod     https://vault.prod.internal          ops-oncall        prod
staging  https://vault.staging.internal:8443                    staging
```

`context add` only ever writes to `~/.rocketvault/contexts.json` — it never dials the server, so an environment that's down still saves cleanly. It also stores no credentials. It does check the URL's *shape* before saving, though, so a missing scheme is caught here rather than surfacing later as an opaque transport error:

```bash
rocketvault context add prod --server vault.prod.internal
# Error: --server "vault.prod.internal" needs an http:// or https:// scheme (got "")
```

```bash
rocketvault context use prod
rocketvault context current
# prod -> https://vault.prod.internal

rocketvault context list --output json | jq '.[] | select(.current)'
```

### The mistake this journey is actually about

Priya finishes an incident call against `prod`, leaves the context switched to it, and goes back to normal `dev` work the next morning without running `context use dev` first. What actually happens depends entirely on *which* command she runs — and the answer is not uniform across the CLI today.

**For most resource groups, the CLI protects her — loudly, not silently:**

```bash
rocketvault keys list --vault dev
```
```
Error: remote mode (--server/ROCKETVAULT_ADDR/context "https://vault.prod.internal") is not yet supported for "rocketvault keys list"; unset it to run against the local instance
```

`keys`, `certificate`, `vaults`, `audit`, and the `users` *resource* commands have no remote adapter yet — `vault-access` no longer belongs on this list (see below). The authority on what does is the `remoteCapableCommands` map in `cmd/root.go` — read that rather than this list, which has gone stale before. As of 2026-09-04 it held `secrets` (all seven subcommands) and `users` (`login`, `logout`); `vault-access` (`grant`, `list`, `revoke`) has since joined them. `vault-access roles` has not, and is not going to — it reads compiled-in role definitions and never contacts a server, so it's handled separately by `isLocalOnlyCommand` rather than by this map. With any context active, `persistentPreRun`'s remote-target guard refuses everything else rather than guessing which instance she meant. This is real fail-closed behavior, not a documentation aspiration — confirmed against the built binary.

**For the groups that do have an adapter, there is no such guard — and the danger that creates is real, even if not literally silent:**

```bash
rocketvault secrets delete <secret-id>
```
```
Error: remote authentication failed - no cached session for server https://vault.prod.internal; run 'rocketvault users login' or pass --username/--password/--totp-code or --client-id/--client-secret
```

`secrets` commands authenticate per server: `common.SanitizeServerKey(target.Server)` (e.g. `srv_https_vault.prod.internal`) is baked into the session's filename inside the **same** `~/.rocketvault/sessions/` directory local sessions already use — there's no separate cache location. Critically, the "current session" pointer is a single global file shared between local and remote mode, so authenticating against a remote server can silently become the session a later bare command reuses.

That's exactly what happens next. Priya authenticates once to unblock the on-call task:

```bash
rocketvault users login --username ops-oncall --password '<prod-password>' --totp-code 482913
```
```
Login successful as ops-oncall.
```

This caches a session keyed to `srv_https_vault.prod.internal` and marks it "current." Nothing about that command's success mentions it also just became the default session for *any* future bare command, regardless of vault.

> **This front door is new (2026-09-04, § B54).** Until then `users login` was itself blocked by the guard, so the only way to create a remote session was as a *side effect* of an unrelated `secrets` command — `rocketvault secrets create ... --username ... --password ... --totp-code ...`. Asking for a secret write was how you logged in. That still works (credential flags on any remote-capable command re-authenticate), but it is no longer the only way in. Older notes describing the `secrets`-as-login workaround are describing the bug, not the design.

The session is written per server, so this does **not** disturb a local session for the same username: `srv_https_vault.prod.internal__ops-oncall.json` and `local__ops-oncall.json` are separate files.

**The trap.** The next morning, back at her desk:

```bash
# No --server, no --username, no confirmation prompt.
rocketvault secrets delete <secret-id>
```
```
time="…" level=info msg="Authenticated against remote server" command="Delete a secret by ID" server="https://vault.prod.internal" user=ops-oncall
Secret deleted successfully.
```

The cached session is reused with **no server-side revalidation** — the CLI only checks the session's local `expires_at`, it never re-checks the token against the server before firing the request. There is no interactive confirmation and no highlighted warning box, but it is not entirely silent either: both lines above are real `logrus` INFO-level output on stderr (default RocketVault CLI logging is unconfigured — stderr, Info level, text formatter), and both name the target server. An operator watching their terminal, rather than piping stdout elsewhere and ignoring stderr, would see `server=https://vault.prod.internal` printed twice. The danger is real but is "easy to miss," not "silent."

If `--vault` is omitted, the command falls back to the context's `--default-vault` (`prod`) rather than erroring — `cmd/secrets/delete.go` reads `target.Vault` only when the `--vault` flag was left empty.

> **Practical rule**: run `rocketvault context current` before any `secrets create/update/delete/import` you intend to be local, and actually read stderr rather than discarding it — it's the command group where a stale `context use` has a real blast radius. For every group still behind the guard, forgetting to switch back just produces the loud `remote mode ... is not yet supported` error above, which is annoying but safe.

### Logging out clears one server, not all of them

```bash
rocketvault users logout
```
```
Logged out ops-oncall.
```

`logout` is scoped to the active target: with the `prod` context current it deletes `srv_https_vault.prod.internal__ops-oncall.json` and leaves any local session for the same username alone. Run it with no context active and the reverse holds — it clears the local session and leaves the remote ones. With no `--username` it follows the current-session pointer, but only if that pointer belongs to *this* server; otherwise it reports `No cached session to log out of.` rather than deleting a file it was not asked to touch.

Logout is client-side only. It removes the cached file; it does not revoke anything server-side, so the underlying JWT stays valid until it expires on its own.

### Unattended auth: no session file at all

CI has no browser and no place to keep a TOTP secret. Service-account credentials skip the session cache entirely:

```bash
export ROCKETVAULT_CLIENT_ID=<client-id>
export ROCKETVAULT_CLIENT_SECRET=<client-secret>
rocketvault secrets list --vault prod
```

These take precedence over every other tier — over `--username/--password` and over any cached session — and authenticate through the OAuth2 client-credentials grant, writing nothing to `~/.rocketvault/sessions/`. `--client-id`/`--client-secret` work as flags too, but on a shared runner the environment keeps the secret out of the process list.

Half a pair is a usage error rather than a silent fallback to an interactive session:

```bash
ROCKETVAULT_CLIENT_ID=<client-id> rocketvault secrets list
# Error: remote authentication failed - --client-id given without --client-secret (or ROCKETVAULT_CLIENT_SECRET)
```

### `localhost` doesn't get you out of this

Pointing the `dev` context at `http://localhost:8774` does **not** put non-`secrets` commands back in local mode — it's still "a context is active," and the guard doesn't special-case loopback addresses:

```bash
rocketvault context use dev
rocketvault keys list --vault dev
# Error: remote mode (--server/ROCKETVAULT_ADDR/context "http://localhost:8774")
#        is not yet supported for "rocketvault keys list"; unset it to run
#        against the local instance
```

To go back to genuine local mode — direct database access, no HTTP hop, every command group available — the context has to be cleared, not merely pointed at localhost:

```bash
rocketvault context unset
rocketvault keys list --vault dev     # works again — no context, no --server, no ROCKETVAULT_ADDR
```

`context unset` clears only the "current" pointer; the saved `prod`/`staging`/`dev` entries are untouched and `context use <name>` switches back to any of them later. `context remove <name>` is the stronger operation — it deletes the saved context outright, and if it happened to be the active one, clears the current pointer as a side effect too (so a removed context can't be left dangling as "current").

```bash
rocketvault context remove staging
rocketvault context list
# staging is gone; if it had been current, `current` now reports local mode
```

### Precedence, for when more than one of these is in play

```bash
rocketvault context use prod
rocketvault secrets list --server https://vault.staging.internal:8443
# Targets staging, not prod — an explicit --server always wins.
```

`cliclient.ResolveTarget` checks, in order: the `--server` flag, then `ROCKETVAULT_ADDR`, then the active context. A context is the lowest-precedence, easiest-to-forget-about source of a target — which is exactly why it's the one that causes surprises days after it was set, not the one typed on the command line in front of you.

### `vault-access` works remotely too

Since `grant`, `list`, and `revoke` joined `remoteCapableCommands`, Priya can run
the exact commands she'd use locally against `prod`, once authenticated the
same way as any other remote command:

```bash
rocketvault context use prod
rocketvault users login --username ops-oncall --password '<prod-password>' --totp-code 482913

rocketvault vault-access grant daeho --role "Key Vault Reader" --vault prod
# granted Key Vault Reader to daeho in vault (assignment <assignment-id>)

rocketvault vault-access list --vault prod
# ASSIGNMENT-ID                         ROLE                 PRINCIPAL-ID
# <assignment-id>                       Key Vault Reader     <daeho-user-id>

rocketvault vault-access revoke <assignment-id> --vault prod
# revoked assignment <assignment-id>
```

Local and remote print through the same `Fprintf` format strings in
`cmd/vault-access/{grant,list,revoke}.go` — there is no separate remote
formatter, so this output is byte-identical to what the same commands print
in local mode. A denial from the server surfaces the same way for all three:

```
Error: failed to grant a role: no role assignment in this vault grants the required action
```

(substitute `list role assignments` or `revoke a role assignment` for the
other two.)

`vault-access roles` did **not** join the map — as noted above, it's routed
through `isLocalOnlyCommand` instead, because it only prints compiled-in role
definitions and never contacts a server. An active context, local or remote,
has no effect on it either way.

### The `ROCKETVAULT_VAULT` divergence: `vault-access` reads it, `secrets` doesn't

`vault-access grant/list/revoke` are the only three callers of
`cliclient.ResolveRemoteVault` (`internal/cliclient/vault.go`), whose
precedence is:

```
--vault flag (only when Flags().Changed) > ROCKETVAULT_VAULT >
context's default vault > config "vault" key > "default"
```

The `secrets` remote adapters (`cmd/secrets/list.go:138-141` and its
siblings) never call that function — they still resolve the vault the older
way:

```go
vault, _ := cmd.Flags().GetString("vault")
if vault == "" {
    vault = target.Vault
}
```

— flag, then the context's default vault, skipping `ROCKETVAULT_VAULT`
entirely. Priya can reproduce the gap in one shell, under one context:

```bash
rocketvault context use prod          # prod's default vault is "prod"
export ROCKETVAULT_VAULT=payments

rocketvault vault-access list
# acts on "payments" -- ResolveRemoteVault honors the env var

rocketvault secrets list
# acts on "prod" -- the secrets adapter never looks at ROCKETVAULT_VAULT,
# and falls straight back to the context's default vault
```

Same shell, same exported variable, same active context — two different
vaults, depending only on which command group she typed. It's worth QA
catching precisely because it's reproducible and quiet: neither command
errors, and neither prints which vault it resolved to.

One more wrinkle before relying on `--vault` to sidestep this:
`ResolveRemoteVault` checks `cmd.Flags().Changed("vault")`, not whether the
value is non-empty. A `--vault` left at a non-empty *default* is not a
deliberate choice on the caller's part and will not outrank an exported
`ROCKETVAULT_VAULT` — only a flag she actually typed does.

This resolves when plan 07 migrates the `secrets` remote adapters onto
`ResolveRemoteVault` too. Until then, treat `ROCKETVAULT_VAULT` as a
`vault-access`-only setting rather than a CLI-wide one.

---

## Journey U — Wiring (and Not Relying On) a Vault Webhook

**Actor**: Priya (`admin`) — webhook config is authorized by `CanManageVault`, the same vault-*management* tier as `vaults create/update/delete` (Correction 8's table), **not** a per-vault Azure data-plane role. Holding `Key Vault Administrator` or `Key Vault Crypto Officer` in a vault is not enough.

Journey C set a rotation policy on `payments-signing` with `--notify-before-expiry-days 14` and flagged that nothing reads that field. Priya goes looking for the obvious fix — point the vault at a webhook — and finds the gap one layer up.

```bash
# As Priya:
rocketvault vault-webhook set --vault prod --url https://hooks.example/rocketvault
# Webhook configured for vault "prod":
#   URL: https://hooks.example/rocketvault
#   Enabled: true
#
#   Signing Secret: XfUHEYSqLFk4IhYKn4Ilr3Q9EGMQGLKCpZWPgjB948c
#
# Store the signing secret now — it is not retrievable after this.
```

Verify, and confirm the secret really is show-once:

```bash
rocketvault vault-webhook get --vault prod
# Webhook for vault "prod":
#   URL: https://hooks.example/rocketvault
#   Enabled: true
#   Created: 2026-08-25T...
#   Updated: 2026-08-25T...
# (no Signing Secret field — get never emits it, on this call or any other)
```

The URL contract is enforced at set-time, not display-time — plain HTTP and embedded credentials are both rejected, and the rejection is careful not to echo a credential back into your terminal history or logs:

```bash
rocketvault vault-webhook set --vault prod --url http://hooks.example/rocketvault
# Error: set webhook failed: webhook url must be an absolute https URL: got scheme "http"

rocketvault vault-webhook set --vault prod --url https://user:pass@hooks.example/rocketvault
# Error: set webhook failed: webhook url must be an absolute https URL: must not embed
# credentials (user:password@); authenticate the receiver with this vault's webhook
# signing secret instead
```

**Sofia tries the same thing, holding `crypto_manager` globally and `Key Vault Crypto Officer` in `prod` — both denied**, proving this sits in the vault-management tier, not the data-plane role table:

```bash
# As Sofia:
rocketvault vault-webhook set --vault prod --url https://hooks.example/rocketvault
# Error: permission denied: managing webhook config for vault "prod" requires admin or vaults/manage

curl -s -o /dev/null -w '%{http_code}\n' -X PUT $BASE/vaults/prod/webhook \
  -H "Authorization: Bearer $SOFIA_TOKEN" -H "Content-Type: application/json" \
  -d '{"url":"https://hooks.example/rocketvault"}'
# 403
```

Unlike `vaults purge` (Journey K), there is **no CLI/HTTP divergence** here: `cmd/vault-webhook/authz.go`'s `requireCanManageVault` and `api/vault_webhook.go`'s `resolveAndAuthorizeVault` both call the identical `authz.CanManageVault`. Same door, same answer, from either side.

Equivalent HTTP, as Priya, for completeness:

```bash
curl -s -X PUT $BASE/vaults/prod/webhook \
  -H "Authorization: Bearer $ADMIN_TOKEN" -H "Content-Type: application/json" \
  -d '{"url":"https://hooks.example/rocketvault","rotate_secret":false}' | jq .
# {"url":"...", "enabled":true, "created_at":"...", "updated_at":"..."}
# — no signing_secret field on an update that didn't rotate one; it only
# appears in the response body the moment one is minted (create, or
# --rotate-secret / "rotate_secret":true)

curl -s $BASE/vaults/prod/webhook -H "Authorization: Bearer $ADMIN_TOKEN" | jq .
curl -s -X DELETE $BASE/vaults/prod/webhook -H "Authorization: Bearer $ADMIN_TOKEN"
```

`delete` is idempotent on both surfaces — deleting a vault with no webhook configured still succeeds:

```bash
rocketvault vault-webhook delete --vault prod
# webhook configuration deleted for vault "prod"

rocketvault vault-webhook delete --vault prod
# webhook configuration deleted for vault "prod"    <-- same message, not an error
```

> ### The config is real. Nothing sends.
>
> `rocketvault vault-webhook set/get/delete` genuinely creates, encrypts, and stores a webhook config with a real signing secret — this is not vaporware. But as of this writing it is **pure configuration with no consumer anywhere in the codebase**: nothing in RocketVault ever makes an outbound HTTP call to a configured webhook URL — there is no sender, dispatcher, or delivery worker. `docs/superpowers/specs/2026-08-20-webhook-delivery-primitive-design.md` (status: **Proposed**, sub-project 2 of a 6-part plan against `.claude/known-bugs.md` § B27) lays out how a sender, signature scheme, and SSRF-safe dialer *would* work — but as of 2026-08-25 that design has not been built. Sub-projects 3–5 (the actual publishers — key-expiry, secret-reminder, certificate-expiry) come after it.
>
> This is the **same gap Journey C already flagged from the other side**: `notify_before_expiry_days` on a key rotation policy is stored and echoed back by `keys rotation-policy get`, but nothing reads it to trigger a send — because there is nothing downstream, webhook or otherwise, that a trigger could call into yet.
>
> **Do not build an operational process that depends on this webhook actually firing.** Configuring it today buys you nothing operationally; it is safe to set up now only in the sense that flipping it on later (once a sender ships) will not require reconfiguring the URL or secret.

---

## Journey V — Delegating Vault *Creation* Without Delegating the Instance

**Actor**: Priya (`admin`) issues the grant; Wren (global role `user`) is the grantee

Journey G handed Wren the right to manage access *inside* one vault. This journey hands her something different: the right to create vaults of her own, up to a fixed count, with no authority whatsoever over a vault she did not create. The group's own help text (`cmd/vault_provisioning.go`) frames it exactly that way — "the delegated alternative to a global `vaults:manage` policy, which additionally confers authority over every vault that already exists." Journey W is that other option. Read the two as a pair.

### 1. Issue the grant — and note what comes back

```bash
# As Priya:
rocketvault vault-provisioning grant wren --quota 3
# Provisioning grant issued: principal=4f2c8a10-6f1b-4a53-9c2e-0d7b8e5a1c34 quota=3
```

The success line prints the **resolved principal UUID**, never the username you typed. `resolvePrincipal` parses the argument as a UUID first and falls back to a username lookup, and what is printed is the stored grant's `principal_id`. A QA case asserting the literal string `wren` in this output will fail on a correct build.

A raw UUID is accepted directly and takes precedence over a username lookup, because an OAuth2 service account is an `oauth2_clients` row with no username to look up:

```bash
rocketvault vault-provisioning grant 3b1e6c2a-9e4b-4f2d-8a2f-6b1c9d0e7f5a --quota 20
# Provisioning grant issued: principal=3b1e6c2a-9e4b-4f2d-8a2f-6b1c9d0e7f5a quota=20
```

Re-issuing for the same principal **changes the quota rather than stacking a second grant** — `principal_id` is `UNIQUE` and the repository upsert updates only the quota, leaving `id`, `created_by` and `created_at` as they were:

```bash
rocketvault vault-provisioning grant wren --quota 10
# Provisioning grant issued: principal=4f2c8a10-6f1b-4a53-9c2e-0d7b8e5a1c34 quota=10
```

### 2. A zero or negative quota is refused, with the reason stated

```bash
rocketvault vault-provisioning grant wren --quota 0
# Error: --quota must be a positive integer: a zero-quota grant is indistinguishable from no grant

rocketvault vault-provisioning grant wren --quota -1
# Error: --quota must be a positive integer: a zero-quota grant is indistinguishable from no grant
```

`--quota` is documented as required but is **not** registered with cobra's required-flag machinery — it is a plain `Int` flag defaulting to `0`. Omitting it entirely therefore produces the same message above, not cobra's `required flag(s) "quota" not set`.

Note the ordering: the admin check runs **before** the quota check. A non-admin who types `--quota 0` sees the permission error in step 3, never this one.

### 3. This tier is non-delegable — the point of the whole journey

Every other CLI authorization tier in RocketVault has a delegation path. The data plane falls through to `vaultcli.RequireDataAction`; `vaults` and `vault-access` fall through to an access policy or a role assignment. `cmd/vault-provisioning/authz.go` has **neither**. `requireGrantAdmin` reads the caller's account roles and checks one thing: `common.HasAnyRole(roles, model.RoleAdmin)`.

Wren holds `Key Vault Data Access Administrator` in `prod` — the one role that exists to delegate access management — and it buys her nothing here:

```bash
# As Wren:
rocketvault vault-provisioning grant marcus --quota 5
# Error: permission denied: managing vault provisioning grants requires the admin role

rocketvault vault-provisioning revoke marcus
# Error: permission denied: managing vault provisioning grants requires the admin role

rocketvault vault-provisioning list
# Error: permission denied: managing vault provisioning grants requires the admin role
```

Iris, holding a global `vaults:manage` access policy (Journey W), gets the identical three refusals. So does the grantee herself — a provisioning grant confers nothing over provisioning grants.

> The code states its own reason, and it is worth quoting to anyone who asks for an exception: *"a principal able to amend grants could raise its own quota, and the bound the grant exists to impose would be decorative."* The same sentence appears in `cmd/vault-provisioning/authz.go`'s `requireGrantAdmin` doc comment, in the group `Long` text, and in the `internal/services/provisioning` package comment. It is a deliberate design position, not an oversight to be patched.

### 4. `list` is instance-wide, not vault-scoped

```bash
# As Priya:
rocketvault vault-provisioning list
# PRINCIPAL-ID                           QUOTA    CREATED-AT
# 4f2c8a10-6f1b-4a53-9c2e-0d7b8e5a1c34   10       2026-09-05T11:04:22Z
# 3b1e6c2a-9e4b-4f2d-8a2f-6b1c9d0e7f5a   20       2026-09-05T11:07:51Z
```

A grant is a global right to create vaults, not a right inside one, so this lists every grant on the instance. `--vault` is a root-level persistent flag, so it parses here and is then **ignored** — `runList` never reads it:

```bash
rocketvault vault-provisioning list --vault prod
# identical output — same rows, no filtering
```

Two more shapes worth pinning in a test: the header row is emitted unconditionally, so a fresh instance with no grants prints the header and nothing else; and `--output json` is likewise ignored, because `runList` writes with `fmt.Fprintf` and never touches the output formatter. This is the opposite of `vaults list`, which does honour `--output`.

### 5. What the grant actually buys — and where it stops

```bash
# As Wren, with quota 3:
rocketvault vaults create tenant-a
rocketvault vaults create tenant-b
rocketvault vaults create tenant-c
# each prints the create table: ID  Name  Enabled  PurgeProtection  RetentionDays  Created

rocketvault vaults create tenant-d
# Error: failed to create vault: vault provisioning quota exceeded: 3 of 3 used -- soft-deleting
# a vault does not free a quota slot; a slot is released only when the vault is purged, which
# requires an administrator or a Key Vault Purge Operator grant. Ask an administrator to purge a
# vault or raise your quota
```

The quota check runs **inside** the insert transaction, so two concurrent creates cannot both pass a check-then-insert race.

A quota-bounded create may not set purge protection — because a grantee who could would soft-delete a protected vault and hold its slot forever:

```bash
rocketvault vaults create tenant-e --purge-protection
# Error: failed to create vault: purge protection may only be set on a create that is not
# quota-bounded -- a quota-bounded provisioning grant cannot set --purge-protection; an admin
# or a global vaults:manage holder can
```

The hint above is honest about the trap: Wren cannot free her own slot, because purge is gated on `CanPurgeVault`, and the creator grant she receives is `Key Vault Administrator`, which does not carry `ActionVaultPurge` (Journey J).

```bash
rocketvault vaults delete tenant-a       # succeeds — she manages what she created
rocketvault vaults purge tenant-a
# Error: permission denied: admin or Key Vault Purge Operator required for vault "tenant-a"

rocketvault vaults get prod
# Error: permission denied: admin or vaults/manage required for vault "prod"
```

### 6. Revoke stops future creates and cascades to nothing

```bash
# As Priya:
rocketvault vault-provisioning revoke wren
# Provisioning grant revoked: principal=4f2c8a10-6f1b-4a53-9c2e-0d7b8e5a1c34
```

Again a UUID, not `wren` — the same `resolvePrincipal` path as `grant`, and the same trap for a test asserting the typed argument.

Revocation **does not cascade**. `cmd/vault-provisioning/revoke.go`'s help states it outright: it "leaves every vault the principal already created, and that vault's own access grants, untouched. Removing access to existing vaults is a separate operator action." Verify both halves:

```bash
# As Wren, after revocation:
rocketvault vaults create tenant-f
# Error: permission denied: admin, a global vaults/manage grant, or a vault provisioning grant
#        required to create a vault

rocketvault vaults get tenant-b          # still succeeds
rocketvault secrets list --vault tenant-b   # still succeeds — Key Vault Administrator survives
```

That is the operationally important half. Revoking a grant is *not* offboarding. Offboarding means revoking the grant **and** removing the per-vault creator grants — the vault-scoped `vaults:manage` policy (HTTP only, see Journey W) and the `Key Vault Administrator` role assignment (`rocketvault vault-access revoke <assignment-id> --vault tenant-b`) — for every vault the principal created.

### 7. The trail

Both operations are logged with a named actor, taken from `requireGrantAdmin`'s return value — the CLI has no middleware to stamp one for it:

```bash
# As Priya:
rocketvault audit logs --action issue_provisioning_grant --limit 20 --output json
rocketvault audit logs --action revoke_provisioning_grant --limit 20 --output json
```

A create made under a grant is distinguishable from every other create in the same log: `Vault created under provisioning grant: <name>`, versus plain `Vault created: <name>` for an admin and `Vault created under global vaults:manage grant (creator rights granted): <name>` for Journey W's Iris.

---

## Journey W — The Global Grant That No Longer Means What It Used To

**Actor**: Iris (global role `user`, plus a global `vaults:manage` access policy)

As of v4.6.0 a global (`vault_id` `NULL`) `(vaults, manage, allow)` policy confers **create and list, and nothing else**. Its holder loses get, update, delete, recover, webhook configuration, and role-assignment management on every vault it does not hold a *vault-scoped* grant over. The whole journey turns on one contrast, and the two halves must not be run together: a vault Iris **created** stays reachable; a vault she **did not create** does not.

### 1. Setup is HTTP-only

There is no CLI command for access policies — the only mechanism is the admin-gated `POST /api/v1/access-policies` (`api/access_policies.go`, gated by `requireAccessPolicyAdmin`). This is the same constraint Journey I hit from the other direction.

```bash
# As Priya. Omitting vault_id is what makes the policy global — the field is a
# STRING in CreateAccessPolicyRequest, and "an empty vault_id leaves the policy
# global; a value scopes it to that vault".
POLICY_ID=$(curl -s -X POST $BASE/access-policies \
  -H "Authorization: Bearer $ADMIN_TOKEN" -H "Content-Type: application/json" \
  -d '{"principal_id":"<iris-user-id>","principal_type":"user",
       "resource_type":"vaults","operation":"manage","effect":"allow"}' | jq -r .id)

curl -s $BASE/access-policies/$POLICY_ID -H "Authorization: Bearer $ADMIN_TOKEN" | jq .
# no vault_id field in the response — VaultID is `omitempty` and nil means GLOBAL
```

> `rocketvault vault-access grant iris --role "Key Vault Administrator" --vault prod` is **not** a CLI substitute for this, however much it looks like one. `ExpandRole` returns `nil, nil` for every Azure built-in role, so a role grant writes `role_assignments` rows and nothing `CanManageVault` can see. It satisfies data-plane checks and restores none of the vault-management rights this journey is about.

### 2. Create and list still work

```bash
# As Iris:
rocketvault vaults create tenant-x
# ID  Name  Enabled  PurgeProtection  RetentionDays  Created

rocketvault vaults list
# every vault on the instance — dev, staging, prod, tenant-x, ...
```

The collection-level decision (`vaultID == uuid.Nil`) still calls `CheckAccess`, which a `NULL`-scoped allow satisfies. `vaults list` also treats her as an "all" lister, so she **sees** vaults she cannot touch. That asymmetry is the single most confusing thing about this release in practice, and it is intended: listing is not managing.

Unlike Journey V's grantee, she has no quota to pin, so purge protection is open to her:

```bash
rocketvault vaults create tenant-y --purge-protection    # succeeds
```

Three tiers exist on the create path, and only the middle one is refused: admin may set purge protection, a global-policy holder may set it, a provisioning grantee may not.

### 3. She can manage the vault she created — because creating it wrote her a scoped grant

```bash
# As Iris:
rocketvault vaults get tenant-x
rocketvault vaults update tenant-x --retention-days 14
rocketvault vault-webhook get --vault tenant-x
rocketvault vault-access list --vault tenant-x
# all succeed
```

None of that comes from the global policy. `cmd/vaults/create.go` passes `right != authz.CreateRightAdmin` as `grantCreatorRights`, and `CreateVaultProvisioned` writes, in the same transaction as the vault row, a vault-scoped `vaults:manage` access policy **and** a `Key Vault Administrator` role assignment for the creator. Confirm the policy really is scoped, not global:

```bash
# As Priya:
curl -s $BASE/access-policies/principal/<iris-user-id> \
  -H "Authorization: Bearer $ADMIN_TOKEN" | jq '.access_policies[] | {operation, effect, vault_id}'
# one row with no vault_id (the global allow) plus one row per vault she created,
# each carrying that vault's UUID
```

### 4. She cannot manage a vault she did not create — the actual breaking change

```bash
# As Iris, against prod, which Priya created in Journey A:
rocketvault vaults get prod
# Error: permission denied: admin or vaults/manage required for vault "prod"

rocketvault vaults update prod --retention-days 7
# Error: permission denied: admin or vaults/manage required for vault "prod"

rocketvault vaults delete prod
# Error: permission denied: admin or vaults/manage required for vault "prod"

rocketvault vault-webhook set --vault prod --url https://hooks.example/rocketvault
# Error: permission denied: managing webhook config for vault "prod" requires admin or vaults/manage

rocketvault vault-access grant iris --role "Key Vault Administrator" --vault prod
# Error: permission denied: admin, vaults/manage, or Key Vault Data Access Administrator
#        required for this vault
```

The mechanism is one function. A concrete vault ID routes `CanManageVault` and `CanManageRoleAssignments` to `CheckVaultScopedAccess` instead of `CheckAccess`; that method reuses the same `(vault_id = ? OR vault_id IS NULL)` lookup, then **discards `NULL`-scoped allow rows and keeps `NULL`-scoped deny rows**. Her global allow survives the query and is thrown away by the filter, so the decision falls through to `AccessFallback`, which is not `AccessAllowed`, and `CanManageVault` fails closed.

That last command is why both functions were narrowed together. Role-assignment management is by itself enough to self-award `Key Vault Administrator` anywhere; narrowing only `CanManageVault` would have left the escalation wide open.

### 5. The two things that did *not* change

A global **deny** still blocks everything, including vaults the denied principal created — the asymmetry between deny and allow is deliberate:

```bash
# As Priya, the same POST with effect "deny" and no vault_id:
curl -s -X POST $BASE/access-policies \
  -H "Authorization: Bearer $ADMIN_TOKEN" -H "Content-Type: application/json" \
  -d '{"principal_id":"<iris-user-id>","principal_type":"user",
       "resource_type":"vaults","operation":"manage","effect":"deny"}' | jq -r .id

# As Iris:
rocketvault vaults get tenant-x
# Error: permission denied: admin or vaults/manage required for vault "tenant-x"
#        <-- the vault she created, now unreachable
```

And the `admin` account role is untouched: it short-circuits both functions before any policy check runs. Priya's behaviour anywhere in this document is unaffected by this release.

### 6. Help text was corrected alongside the behaviour

Worth one grep during a QA pass, because stale help is how a narrowed permission gets re-widened in someone's head. `cmd/vaults/{delete,get,recover,update}.go` and `cmd/vault-webhook/{delete,get,set}.go` previously said the operation required an allow "scoped to this vault or granted globally"; all six now say "scoped to this vault":

```bash
rocketvault vaults get --help | grep -A1 'access-policy allow'
# Requires the admin account role, or an access-policy allow on (vaults,
# manage) scoped to this vault.
```

`cmd/vaults/list.go` still says "granted globally" — correctly, and it is the only one that should. `cmd/vaults/create.go` goes further and says the allow must be "scoped globally rather than to a specific vault (since the vault being created does not exist yet to scope the check to)", which is the same fact from the other side: a vault-scoped grant does not let you create.

### 7. If you are upgrading, not testing fresh

Run v4.5.0 once first and read the startup log for `warnGlobalVaultManageGrants` (`internal/db/db.go`). It names every principal holding a `NULL`-scoped `(vaults, manage, allow)` row, and every one of them loses everything in step 4 on upgrade. For each, either issue a bounded provisioning grant (Journey V) if it only ever needed to create and manage its *own future* vaults, or add explicit vault-scoped policies via the HTTP call in step 1 with a real `vault_id`. A provisioning grant does **not** retroactively repair vaults created under v4.5.0: those rows got no creator grants, because creator grants on the global-policy path are new in this release.

---

## CLI Quick Reference

### Command groups

```bash
rocketvault users        admin | create | get | list | update | delete | login | logout
rocketvault vaults       create | list | get | update | delete | recover | purge | preview-migration
rocketvault vault-access roles | grant | revoke | list
rocketvault vault-provisioning grant | revoke | list
rocketvault vault-webhook get | set | delete
rocketvault keys         create | get | list | update | delete | rotate | sign | verify | wrap | unwrap
rocketvault keys rotation-policy  get | set | delete
rocketvault secrets      create | get | list | update | delete | export | import | generate-password
rocketvault secrets rotation  create | list | update | delete | assign | unassign | rotate | history | status
rocketvault certificates create | list | get | update | delete | renew   ("certificate" also works, as an alias)
rocketvault audit        logs | report | config
rocketvault backup       create | list | restore
rocketvault context      add | list | use | current | remove | unset
rocketvault master-key   rotate
```

### Flag gotchas worth knowing

| Command | Gotcha |
|---|---|
| `vaults create/delete/recover/purge/update` | Vault name is **positional**; these have no `--vault` flag |
| `users create --new-role` | **Repeatable**, not comma-separated |
| `keys create --bits` | Help says "2048 or 4096" — **3072 is also valid**. Invalid sizes are rejected only after a full authenticated round trip, never at flag-parse time |
| `keys create --curve` | Help omits **P-256K**, which works. A P-256K key is stored with type `ES256K`, not `ECDSA` — tooling asserting `type == "ECDSA"` misses them silently |
| `keys create --type` | Accepts only `RSA`/`ECDSA`. `--type ES256K` is rejected; reach it via `--type ECDSA --curve P-256K` |
| `keys create` (name) | The CLI validates almost nothing about the name; HTTP enforces `^[a-zA-Z][a-zA-Z0-9-]{0,126}$`. A CLI-created key can violate a constraint HTTP would reject |
| `keys wrap/unwrap` | **No `--algorithm` flag** — always RSA-OAEP |
| `keys rotation-policy set` | `--rotate-after-days` and `--enabled` are **both required on every call** — it's a full replace (like the HTTP `PUT`), not a partial update |
| `keys sign/verify/wrap/unwrap --version` | `0` or omitted = current version |
| Duplicate key name | Rejected only *after* RSA generation runs, with a raw unwrapped driver error (`UNIQUE constraint failed: keys.vault_id, keys.name` on SQLite) |
| `secrets rotation --auto-rotate` | The scheduler **replaces the live value with a generated one**. Nothing outside RocketVault is told |
| `--server` / `ROCKETVAULT_ADDR` | Not supported by every subcommand; some are local-only and will tell you to unset it |
| `vault-provisioning grant --quota` | Documented as required but **not** registered required with cobra — it is a plain `Int` defaulting to `0`, so omitting it gives the positive-integer error, not `required flag(s) "quota" not set` |
| `vault-provisioning grant/revoke` | Print the **resolved principal UUID**, never the username you typed. A test asserting the literal argument fails on a correct build |
| `vault-provisioning list` | Ignores both `--vault` and `--output` — it writes with `fmt.Fprintf` and never reaches the output formatter, unlike `vaults list` |
| HTTP `-HSM` type suffix | `buildKeyResponse` appends `-HSM` for PKCS#11-backed keys. `keys list --output json` still prints plain `RSA`/`ECDSA` — the suffix is added by the HTTP handler only |

### Which gate produced your error

| Message | Gate |
|---|---|
| `forbidden: requires admin or crypto_manager role` | **CLI-only global role gate** (Correction 8) — no HTTP equivalent |
| `Forbidden: access policy denied` | Gate 2 — explicit deny, before the role check |
| `forbidden: no role grants <action> in this vault` / `Forbidden: no role assignment grants this operation in this vault` | Gate 3 — deny-by-default, applies to global admins too |
| `Insufficient permissions: admin role required to manage access policies` | Access-policy surface, admin-only |
| `permission denied: admin, vaults/manage, or Key Vault Data Access Administrator required for this vault` | Management-level check |
| `grant failed: role cannot be granted by a non-admin caller` | `ErrRoleNotGrantable` — eight-role allow-list |

---

## Corrections retained from v2

| # | v1 claimed | Actually true |
|---|---|---|
| 1 | Global `admin` bypasses all vault checks | **False.** `HasDataAction` has no admin short-circuit. Admins must self-grant a role in each vault |
| 2 | Cross-vault access returns 404 | Returns **403 deny-by-default** |
| 3 | Crypto User "can use a key, can't manage it" | Also has `update` and `backup` (added 2026-08-18) |
| 4 | Data Access Administrator manages access generally | Role assignments **only**; access policies are a separate admin-only surface |
| 5 | Revocation "immediate for new requests" | Confirmed precisely: same token, byte-identical claims, 200 → 403 |
| 6 | Purging a vault cleans it up | **Does not cascade** — permanently orphans children |
| 7 | Crypto Officer can import keys | `ActionKeysImport` is in the bundle but **no route maps to it** |
