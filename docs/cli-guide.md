# RocketVault — How to Use the CLI

RocketVault is a secure place to store passwords, API keys, and other sensitive information. This guide walks you through everything step by step, from first-time setup to everyday use.

> **What is the CLI?**
> A CLI (Command Line Interface) means you type commands into a terminal window instead of clicking buttons. Every example in this guide is a command you can copy, paste, and run.

---

## Before You Start

You need three things:

1. **The RocketVault program** — confirm it works by running:
   ```
   go run main.go --help
   ```
   You should see a list of available commands. If you get an error, ask your administrator to set up the program first.

2. **A config file** — a file called `.rocketvault.yaml` must exist in the same folder you run commands from. Your administrator provides this file.

3. **An authenticator app** — RocketVault uses two-factor authentication (like Google Authenticator or Authy). You will need one of these apps on your phone.

---

## Understanding the Login Code (TOTP)

Almost every command requires **three things to prove who you are**:

- Your **username**
- Your **password**
- A **6-digit code** from your authenticator app (called a TOTP code)

The 6-digit code changes every 30 seconds. When a command asks for `--totp-code 123456`, replace `123456` with the current code shown in your authenticator app at that moment.

**Example of how credentials look in every command:**
```
--username admin --password admin123 --totp-code 123456
```

---

## How to Get Your 6-Digit TOTP Code

The TOTP code comes from an **authenticator app on your phone**. You set it up once — after that, the app always shows your current code.

### Step 1 — Install an authenticator app

Install one of these free apps on your phone:

| App | Android | iPhone |
|-----|---------|--------|
| Google Authenticator | Google Play | App Store |
| Microsoft Authenticator | Google Play | App Store |
| Authy | Google Play | App Store |

Any of these works. Google Authenticator is the most common.

### Step 2 — Find your TOTP secret

Your TOTP secret is shown **once** when your account is first created. It looks like this:

```
TOTP Secret: otpauth://totp/PasswordManager:admin?algorithm=SHA1&digits=6&issuer=PasswordManager&period=30&secret=CZCBJ5TMFMCUULZS4R7ZHV5JZRIFA7TZ
```

The part you need is the value after `secret=` at the very end:

```
CZCBJ5TMFMCUULZS4R7ZHV5JZRIFA7TZ
```

Copy this and keep it somewhere safe — you will need it in Step 3.

> If you missed it during account creation, ask your administrator to reset your account so a new TOTP secret is generated.

### Step 3 — Add your account to the authenticator app

**Using Google Authenticator:**

1. Open Google Authenticator on your phone.
2. Tap the **+** button (bottom right).
3. Tap **Enter a setup key**.
4. Fill in the form:
   - **Account name**: type anything, e.g. `RocketVault`
   - **Your key**: paste the secret from Step 2 (e.g. `CZCBJ5TMFMCUULZS4R7ZHV5JZRIFA7TZ`)
   - **Type of key**: leave as **Time based**
5. Tap **Add**.

The app now shows a 6-digit code that refreshes every 30 seconds. That is your `--totp-code`.

**Using Microsoft Authenticator:**

1. Open the app and tap **+** → **Other account**.
2. Tap **OR ENTER CODE MANUALLY**.
3. Enter an account name (e.g. `RocketVault`) and paste the secret.
4. Tap the checkmark to save.

**Using Authy:**

1. Open Authy and tap **+**.
2. Tap **Enter key manually**.
3. Paste the secret into the **Account Key** field, give it a name, and tap **Add Account**.

### Step 4 — Use the code in a command

Open the authenticator app, find the RocketVault entry, and read the 6-digit number shown. Type it as `--totp-code` in your command:

```
go run main.go secrets list \
  --username admin \
  --password admin123 \
  --totp-code 847291
```

The code changes every 30 seconds. If you see a countdown timer nearly at zero, wait for it to refresh and use the new code — expired codes will be rejected.

> **Tip:** Most apps show a small circular countdown next to the code. If it is almost gone, wait 5 seconds for the next code before running your command.

---

## For Developers — Get TOTP Codes Without Your Phone

If you are running RocketVault locally for development, opening your phone every 30 seconds gets tedious. There is a script included in the project that generates TOTP codes directly in your terminal.

### One-time setup

Find your TOTP secret (the value after `secret=` shown when your account was created), then add it to your shell profile so you never have to type it again.

**For zsh (most Macs)** — open `~/.zshrc` in any text editor and add this line at the bottom:

```
export ROCKETVAULT_TOTP_SECRET="YOUR_SECRET_HERE"
```

**For bash (most Linux)** — open `~/.bashrc` and add the same line.

Replace `YOUR_SECRET_HERE` with your actual secret, for example:

```
export ROCKETVAULT_TOTP_SECRET="CZCBJ5TMFMCUULZS4R7ZHV5JZRIFA7TZ"
```

After saving the file, reload your shell:

```
source ~/.zshrc
# or
source ~/.bashrc
```

You only need to do this once. The secret is stored in your shell environment and never typed again.

### Get your current code

Run this from the RocketVault project folder:

```
go run scripts/totp_generator.go
```

Output:

```
RocketVault TOTP — user: admin
─────────────────────────────────
Current code : 933563
Valid for    : 24s  [████████████░░░]
Time         : 14:30:36

Ready to use:
  --totp-code 933563

Full example:
  go run main.go secrets list --username admin --password <password> --totp-code 933563
```

Copy the code next to `--totp-code` and paste it into your command.

The bar `[████████████░░░]` shows how much time is left on the current code. If the bar is nearly empty, wait a few seconds for a fresh code before running your command.

### Watch mode — auto-refresh in a second terminal

If you are running many commands in a row, keep watch mode open in a side terminal. It automatically shows a new code every 30 seconds:

```
go run scripts/totp_generator.go -watch
```

Leave it running. Glance at it whenever you need a code — no phone needed.

### Use a different username

```
go run scripts/totp_generator.go -username=alice
```

### Pass the secret directly without the env var

If you have not set up the env var yet:

```
go run scripts/totp_generator.go -secret="CZCBJ5TMFMCUULZS4R7ZHV5JZRIFA7TZ"
```

---

## Step 1 — First-Time Setup (Admins Only)

> Skip this section if someone else already set up the system. Jump to [Step 2 — Log In](#step-2--log-in).

### Start the server

Open a terminal and run:

```
go run main.go serve
```

Leave this terminal running. Open a second terminal for all other commands.

### Create the first admin account

You need the **bootstrap token** from the `.rocketvault.yaml` config file. Look for the line that says `bootstrap_token:` and copy its value.

```
go run main.go users admin \
  --admin-username admin \
  --admin-password admin123 \
  --bootstrap-token YOUR-BOOTSTRAP-TOKEN-HERE
```

Replace `YOUR-BOOTSTRAP-TOKEN-HERE` with the actual token from the config file.

**What you will see:**

```
Admin user admin created successfully with ID: 79ccfd7b-...
TOTP Secret: otpauth://totp/PasswordManager:admin?algorithm=SHA1&digits=6&issuer=PasswordManager&period=30&secret=CZCBJ5TMFMCUULZS4R7ZHV5JZRIFA7TZ
Configure the TOTP secret in your authenticator app for MFA.
```

**Important:** You must now add this account to your authenticator app before you can log in. See [How to Get Your 6-Digit TOTP Code](#how-to-get-your-6-digit-totp-code) for exact steps. The same section applies when any new user account is created.

---

## Step 2 — Log In

Run this to verify everything is working. Get the 6-digit code from your authenticator app first.

```
go run main.go users login \
  --username admin \
  --password admin123 \
  --totp-code 123456
```

If it works, you will see `Login successful` and a long token string. You are ready to use RocketVault.

---

## Managing Vaults

A **vault** is an isolated security boundary inside one RocketVault instance — its own secrets, keys, and certificates, completely separate from any other vault. Every RocketVault instance comes with a `default` vault that is used automatically whenever you don't specify one. Admins can create additional named vaults to keep different teams, applications, or environments (for example `prod`, `staging`, or `team-billing`) fully separate from each other.

### Choosing which vault a command applies to

Every resource command (`secrets`, `keys`, `certificate`, `vault-access`) accepts a `--vault` flag — with one exception: `certificate create` currently ignores it and always uses the `default` vault (see [Managing Certificates](#managing-certificates) below). If you leave `--vault` out elsewhere, RocketVault picks a vault in this order: the `--vault` flag, then the `ROCKETVAULT_VAULT` environment variable, then a `vault` key in your config file, and finally the `default` vault.

```
go run main.go secrets list \
  --username admin --password admin123 --totp-code 123456 \
  --vault prod
```

> If you only ever use the `default` vault, you can ignore `--vault` entirely — every other example in this guide already runs against it.

### Create a vault

Requires being an admin or holding a global `vaults:manage` grant.

```
go run main.go vaults create prod \
  --username admin --password admin123 --totp-code 123456
```

**With purge protection and a custom retention period:**

```
go run main.go vaults create prod \
  --username admin --password admin123 --totp-code 123456 \
  --purge-protection --retention-days 30
```

- `--purge-protection` — once set, the vault cannot be purged (permanently destroyed) by anyone, even an admin, until protection is turned off again.
- `--retention-days` — how many days a soft-deleted vault (and its contents) stays recoverable before it can be purged.

**What you will see:**

```
ID                                    NAME  ENABLED  PURGEPROTECTION  RETENTIONDAYS  CREATED
3fa11c9e-...                          prod  true     true             30             2026-08-12T10:15:00Z
```

### See all vaults

Just requires being logged in — no extra role needed to view the list.

```
go run main.go vaults list \
  --username admin --password admin123 --totp-code 123456
```

**Include soft-deleted vaults:**

```
go run main.go vaults list --include-deleted \
  --username admin --password admin123 --totp-code 123456
```

### Look up a specific vault

Also just requires being logged in.

```
go run main.go vaults get prod \
  --username admin --password admin123 --totp-code 123456
```

### Change a vault's settings

Requires admin or a `vaults:manage` grant scoped to that vault.

```
go run main.go vaults update prod --retention-days 60 \
  --username admin --password admin123 --totp-code 123456
```

**Disable a vault (blocks activity without deleting anything):**

```
go run main.go vaults update prod --enabled=false \
  --username admin --password admin123 --totp-code 123456
```

### Delete a vault

This is a **soft delete** — the vault and everything in it (secrets, keys, certificates) is marked deleted but kept around, recoverable with `vaults recover`, until someone purges it or its retention period runs out. Requires admin or `vaults:manage`.

```
go run main.go vaults delete prod \
  --username admin --password admin123 --totp-code 123456
```

> The `default` vault can never be deleted or purged — RocketVault refuses the request no matter who asks.

### Recover a deleted vault

Restores a soft-deleted vault and everything that was deleted along with it. Same permission as delete.

```
go run main.go vaults recover prod \
  --username admin --password admin123 --totp-code 123456
```

### Permanently purge a vault

> **This cannot be undone.** Purging removes the vault and its contents for good — unlike `delete`, there is no recovering from a purge. Requires admin or the **Key Vault Purge Operator** role (see [Vault Access & Roles](#vault-access--roles) below).

```
go run main.go vaults purge prod \
  --username admin --password admin123 --totp-code 123456
```

Purge is normally used on a vault you already soft-deleted, but if no soft-deleted vault by that name exists, RocketVault purges the currently active one instead — so double-check the name before running this. A vault created with `--purge-protection` refuses to be purged until protection is turned off with `vaults update prod --purge-protection=false`.

### Preview what an upgrade would grant (admins, before upgrading)

`vaults preview-migration` is a read-only command, usable without logging in, meant for administrators upgrading RocketVault to a version that introduces per-vault roles. It prints the role assignments the upgrade would automatically create from existing ownership (for example, "you own secrets in `prod`, so you'd get `Key Vault Secrets Officer` there") without changing anything. Run it before upgrading and confirm everyone who needs access appears in the output for the vaults they need.

```
go run main.go vaults preview-migration
```

---

## Vault Access & Roles

Having access to RocketVault at all — even being an **admin** — does not automatically give you access to what's stored *inside* a specific vault. Reading or writing a vault's secrets, keys, or certificates always requires an explicit role assignment in that vault. This keeps one team's vault private from another team's account unless someone deliberately grants access.

> This applies to the *data* inside a vault. Vault-management actions like creating, listing, or updating the vault itself remain available to global admins without a separate grant — see [Managing Vaults](#managing-vaults) above.

### Grant a role to someone

Requires being an admin, holding a global `vaults:manage` grant, or already holding **Key Vault Data Access Administrator** in that vault.

```
go run main.go vault-access grant alice --role "Key Vault Secrets User" --vault prod \
  --username admin --password admin123 --totp-code 123456
```

**Granting a role to a service account instead of a person:**

```
go run main.go vault-access grant my-svc --role "Key Vault Crypto User" --principal-type service_account --vault prod \
  --username admin --password admin123 --totp-code 123456
```

### See who has access to a vault

Same permission as granting.

```
go run main.go vault-access list --vault prod \
  --username admin --password admin123 --totp-code 123456
```

**Example output:**

```
ASSIGNMENT-ID                         ROLE                     PRINCIPAL-ID
7d2e1a4b-...                          Key Vault Secrets User    a1b2c3d4-...
```

### Take away someone's access

```
go run main.go vault-access revoke 7d2e1a4b-... --vault prod \
  --username admin --password admin123 --totp-code 123456
```

Replace the long ID with the `ASSIGNMENT-ID` shown by `vault-access list`.

### See what roles are available

No login required — this just lists the built-in roles and exactly what each one grants.

```
go run main.go vault-access roles
```

### Available roles

| Role | What it grants |
|---|---|
| Key Vault Administrator | Everything — full read/write access to secrets, keys, and certificates in the vault. |
| Key Vault Reader | Metadata only (names, tags, enabled state) — never secret values or key material. |
| Key Vault Secrets User | Read secrets, including their actual values. Cannot create, change, or delete them. |
| Key Vault Secrets Officer | Full control of secrets — create, read, update, delete, back up, restore. |
| Key Vault Crypto User | Use existing keys — encrypt, decrypt, sign, verify, wrap, unwrap. Cannot create or delete keys. |
| Key Vault Crypto Officer | Full control of keys — everything Crypto User can do, plus create, delete, and rotate. |
| Key Vault Certificates Officer | Full control of certificates — create, update, delete, back up, restore. |
| Key Vault Purge Operator | Permanently purge a soft-deleted vault. Nothing else. |
| Key Vault Certificate User | Read certificates. |
| Key Vault Crypto Service Encryption User | Read key metadata and wrap/unwrap with it — a narrower version of Crypto User. |
| Key Vault Data Access Administrator | Grant and revoke other people's roles in the vault. Gets no access to secrets, keys, or certificates itself. |

> `vault-access roles` may also list a few older role names (like `vault-reader` or `secrets-officer`) marked "deprecated." Those are left over from an earlier version of RocketVault and can no longer be granted — use the roles in the table above instead.

These roles are what actually gate access once you're in a vault — see [Managing Secrets](#managing-secrets), [Managing Cryptographic Keys](#managing-cryptographic-keys), and [Managing Certificates](#managing-certificates) below for how each command checks them.

---

## Vault Webhooks

Each vault can store one webhook configuration: an HTTPS URL and a signing secret. Think of it as somewhere to record *where* notifications about this vault should go.

> **These commands configure a webhook — they do not send anything.** RocketVault has no delivery mechanism yet, so nothing is posted to the URL today. Setting one now means the destination is already recorded when delivery ships.

Unlike secrets or keys, webhook configuration is a **vault-management** action, not a data action. You need to be an admin or hold a `vaults:manage` grant — no per-vault role assignment gets you here, and holding **Key Vault Secrets User** in the vault does not.

### Set (or update) a vault's webhook

```
go run main.go vault-webhook set --vault prod --url https://hooks.example.com/rocketvault \
  --username admin --password admin123 --totp-code 123456
```

**Example output:**

```
Webhook configured for vault "prod":
  URL: https://hooks.example.com/rocketvault
  Enabled: true
  Signing Secret: 9pQ2v...

Store the signing secret now — it is not retrievable after this.
```

**The signing secret is shown once and never again.** It is printed only when it is created, or when you ask for a new one with `--rotate-secret`. `get` will not show it, and there is no command that will. If you lose it, your only option is to rotate and update whatever was verifying signatures with the old one.

The URL must be an absolute **https** URL, and it must not embed credentials (`https://user:pass@host/...` is rejected). That second rule exists because the URL is stored unencrypted and `get` returns it verbatim — a password buried in the URL would leak into the response and into anything that logs it.

### Rotate the signing secret

```
go run main.go vault-webhook set --vault prod --rotate-secret \
  --username admin --password admin123 --totp-code 123456
```

Prints a fresh secret, once. The URL stays as it was unless you also pass `--url`.

### Turn a webhook off without deleting it

```
go run main.go vault-webhook set --vault prod --enabled=false \
  --username admin --password admin123 --totp-code 123456
```

Leave `--enabled` off entirely and the current value is kept — on a brand-new webhook, that means enabled.

### See a vault's webhook

```
go run main.go vault-webhook get --vault prod \
  --username admin --password admin123 --totp-code 123456
```

**Example output:**

```
Webhook for vault "prod":
  URL: https://hooks.example.com/rocketvault
  Enabled: true
  Created: 2026-08-19T10:22:04Z
  Updated: 2026-08-20T09:15:41Z
```

Note the absence of the signing secret — that is deliberate, not an omission in this guide.

### Delete a vault's webhook

```
go run main.go vault-webhook delete --vault prod \
  --username admin --password admin123 --totp-code 123456
```

Deleting the vault itself also removes its webhook configuration, but only on a **purge**. Soft-deleting a vault leaves the configuration in place, so recovering the vault brings its webhook back with it.

---

## Managing Secrets

A **secret** is any piece of sensitive information: a password, an API key, a database connection string, etc.

Secrets always live inside a vault. Every command below — `create`, `get`, `list`, `update`, `delete`, `export`, and `import` — defaults to the `default` vault unless you add `--vault <name>`, e.g. `--vault production`. You'll need a role assignment on that vault that grants the matching permission; a couple of examples below show the flag, and it works the same way on the rest. (`generate-password` just makes up a random string locally, so it doesn't take `--vault` at all.)

### Save a new secret

```
go run main.go secrets create my-database-password "MySecretValue123" \
  --username admin --password admin123 --totp-code 123456 --vault production
```

- `my-database-password` — a name you choose so you can find it later
- `"MySecretValue123"` — the actual secret value to store
- `--vault production` — optional; creates the secret in the `production` vault instead of `default`

**With labels (called tags) to help organise:**

```
go run main.go secrets create my-api-key "abc123xyz" \
  --username admin --password admin123 --totp-code 123456 \
  --tags production,api
```

Tags are optional keywords separated by commas. They make it easy to filter later.

### See all your secrets

```
go run main.go secrets list \
  --username admin --password admin123 --totp-code 123456
```

**Show only secrets with a specific tag:**

```
go run main.go secrets list \
  --username admin --password admin123 --totp-code 123456 \
  --tags production
```

### Look up a specific secret

Each secret has a unique ID (shown when you list them — looks like `9b8ead4b-7e88-430a-...`).

```
go run main.go secrets get 9b8ead4b-7e88-430a-982c-bec891eed705 \
  --username admin --password admin123 --totp-code 123456 --vault production
```

Replace the long ID with the actual ID of the secret you want, and make sure `--vault` matches the vault it was created in — the same ID won't be found under a different vault.

### Change a secret's value

```
go run main.go secrets update 9b8ead4b-7e88-430a-982c-bec891eed705 "NewSecretValue" \
  --username admin --password admin123 --totp-code 123456
```

### Delete a secret

```
go run main.go secrets delete 9b8ead4b-7e88-430a-982c-bec891eed705 \
  --username admin --password admin123 --totp-code 123456
```

### Declare the type of a secret (content type)

You can attach a media type to a secret so that any tool or service that reads it knows how to parse the value. This is optional — if you leave it out, the secret is stored without a declared type.

```
go run main.go secrets create my-pem-cert "-----BEGIN CERTIFICATE-----..." \
  --username admin --password admin123 --totp-code 123456 \
  --content-type application/x-pem-file
```

**Allowed content types:**

| Value | When to use |
|-------|-------------|
| `text/plain` | Plain text passwords, passphrases |
| `application/json` | JSON configuration blobs |
| `application/xml` | XML configuration |
| `application/x-pem-file` | PEM-encoded certificates or keys |
| `application/x-pkcs12` | PKCS#12 / .pfx certificate bundles |
| `application/octet-stream` | Binary data |

**Update the content type on an existing secret:**

```
go run main.go secrets update SECRET-ID-HERE \
  --username admin --password admin123 --totp-code 123456 \
  --content-type application/json
```

The content type is returned whenever you `get` or `list` a secret. RocketVault does not enforce that the value matches the declared type — it is purely informational for consumers.

### Generate a strong random password

Not sure what password to use? Let RocketVault create one for you:

```
go run main.go secrets generate-password \
  --username admin --password admin123 --totp-code 123456
```

**Custom length, no special characters:**

```
go run main.go secrets generate-password \
  --username admin --password admin123 --totp-code 123456 \
  --length 24 --special=false
```

### Back up all secrets to a file

```
go run main.go secrets export \
  --username admin --password admin123 --totp-code 123456 \
  --file ./my-secrets-backup.json
```

The file is encrypted automatically. Keep it somewhere safe.

**Export only secrets with a specific tag:**

```
go run main.go secrets export \
  --username admin --password admin123 --totp-code 123456 \
  --file ./production-secrets.json --tags production
```

### Restore secrets from a backup file

```
go run main.go secrets import \
  --username admin --password admin123 --totp-code 123456 \
  --file ./my-secrets-backup.json
```

---

## Automatic Secret Rotation

Secret rotation means automatically replacing a secret with a new value on a schedule — for example, changing a database password every 30 days. This reduces the risk if a secret is ever compromised.

### Create a rotation schedule (called a policy)

```
go run main.go secrets rotation create \
  --username admin --password admin123 --totp-code 123456 \
  --name "Monthly DB Password" \
  --interval 30 \
  --reminder 7 \
  --auto-rotate
```

- `--interval 30` — rotate every 30 days
- `--reminder 7` — warn you 7 days before rotation is due
- `--auto-rotate` — rotate automatically without manual action

### See all your rotation schedules

```
go run main.go secrets rotation list \
  --username admin --password admin123 --totp-code 123456
```

### Attach a rotation schedule to a secret

```
go run main.go secrets rotation assign \
  --username admin --password admin123 --totp-code 123456 \
  --policy-id POLICY-ID-HERE \
  --secret-id SECRET-ID-HERE
```

Replace `POLICY-ID-HERE` and `SECRET-ID-HERE` with the actual IDs shown when you list policies and secrets.

### Rotate a secret right now (manually)

```
go run main.go secrets rotation rotate \
  --username admin --password admin123 --totp-code 123456 \
  --secret-id SECRET-ID-HERE \
  --policy-id POLICY-ID-HERE
```

### Check what is due for rotation

```
go run main.go secrets rotation status \
  --username admin --password admin123 --totp-code 123456
```

### See the rotation history for a secret

```
go run main.go secrets rotation history \
  --username admin --password admin123 --totp-code 123456 \
  --secret-id SECRET-ID-HERE
```

---

## Managing Cryptographic Keys

> This section is for technical users who need to manage RSA or ECDSA keys. If you are not sure what these are, you likely do not need this section.

Every `keys` subcommand (`create`, `import`, `get`, `list`, `update`, `delete`, `rotate`, `wrap`, `unwrap`) checks your access against the target vault — you need a role assignment in that vault that grants the matching permission (for example, `Key Vault Crypto Officer` for create/import/update/delete/rotate, or `Key Vault Crypto User` for wrap/unwrap). **There is no admin bypass**: holding RocketVault's global admin role does not by itself grant access to keys in a vault — you still need an explicit per-vault role assignment. See "Vault Access & Roles" for how to grant these. `keys create` additionally requires your account to hold the global `admin` or `crypto_manager` role, and `keys import` the global `admin` or `crypto_manager` role, on top of the per-vault check.

All `keys` subcommands accept an optional `--vault <name>` flag to target a specific vault; if omitted, RocketVault uses the `default` vault.

### Create a key

**RSA key (most common):**

```
go run main.go keys create \
  --username admin --password admin123 --totp-code 123456 \
  --name my-rsa-key \
  --type RSA \
  --bits 2048 \
  --vault my-team-vault
```

**ECDSA key:**

```
go run main.go keys create \
  --username admin --password admin123 --totp-code 123456 \
  --name my-ecdsa-key \
  --type ECDSA \
  --curve P-256
```

### Import a key

Bring in an RSA or ECDSA private key generated somewhere else — a JWK containing private key material, from a file or inline — instead of having RocketVault generate one. It's stored exactly as a generated key would be (encrypted PEM, or a non-extractable PKCS#11 object on an HSM-backed vault). A JWK with no private key material (public-only) is rejected.

```
go run main.go keys import \
  --username admin --password admin123 --totp-code 123456 \
  --name imported-signing-key \
  --jwk-file ./key.jwk.json \
  --vault my-team-vault
```

Or supply the JWK inline instead of a file:

```
go run main.go keys import \
  --username admin --password admin123 --totp-code 123456 \
  --name imported-signing-key \
  --jwk '{"kty":"RSA","n":"...","e":"AQAB","d":"..."}'
```

`--name` and one of `--jwk-file`/`--jwk` (mutually exclusive) are required; `--tags` and `--purge-protection` are optional. `keys import` requires your account to hold the global `admin` or `crypto_manager` role, in addition to a per-vault role assignment granting the import permission (`Key Vault Crypto Officer` or `Key Vault Administrator`).

### See all keys

```
go run main.go keys list \
  --username admin --password admin123 --totp-code 123456 \
  --vault my-team-vault
```

### Replace a key with a new one (rotate)

The old key is revoked and a fresh one is created automatically.

```
go run main.go keys rotate KEY-ID-HERE \
  --username admin --password admin123 --totp-code 123456
```

### Delete a key

```
go run main.go keys delete KEY-ID-HERE \
  --username admin --password admin123 --totp-code 123456
```

### Wrap a key (envelope encryption)

Key wrapping lets you encrypt a data encryption key (DEK) using a vault RSA key (the KEK — key encryption key). This is the standard way to protect keys at rest without exposing the vault key itself.

**Step 1 — Wrap your DEK:**

```
go run main.go keys wrap \
  --username admin --password admin123 --totp-code 123456 \
  --key-id KEY-ID-HERE \
  --key-material BASE64-ENCODED-DEK
```

- `--key-id` — the UUID of the RSA vault key to use as the KEK
- `--key-material` — your DEK encoded in base64 (e.g. a 32-byte AES key)

The command prints the wrapped key as a base64 string. Store it safely — it cannot be read without the vault key.

**Generate a random DEK and wrap it in one step:**

```
DEK=$(openssl rand -base64 32)
go run main.go keys wrap \
  --username admin --password admin123 --totp-code 123456 \
  --key-id KEY-ID-HERE \
  --key-material "$DEK"
```

**Step 2 — Unwrap it when you need the DEK back:**

```
go run main.go keys unwrap \
  --username admin --password admin123 --totp-code 123456 \
  --key-id KEY-ID-HERE \
  --wrapped-key BASE64-WRAPPED-KEY
```

The command prints the original DEK in base64.

> Wrapping and unwrapping require a role assignment on the target vault that grants the wrap/unwrap permission — for example `Key Vault Crypto User` or `Key Vault Crypto Service Encryption User`. There is no owner or admin shortcut: even the key's creator or a global admin needs that role assignment to wrap or unwrap with it. The algorithm used is RSA-OAEP with SHA-256.

### Using an older version of a key

Rotating a key doesn't throw the old material away — it's archived, and the old version stays usable. Anything you signed or wrapped before a rotation still needs that older version to verify or unwrap.

`keys sign`, `keys verify`, `keys wrap`, and `keys unwrap` all take a `--version` flag for this:

```
# Unwrap something that was wrapped with version 2, before the key was rotated
go run main.go keys unwrap \
  --username admin --password admin123 --totp-code 123456 \
  --key-id KEY-ID-HERE \
  --wrapped-key BASE64-WRAPPED-KEY \
  --version 2
```

Leave `--version` off and the key's **current** version is used, which is what every command did before this flag existed. Passing `--version 0` means the same thing, so scripts that pass it explicitly aren't a special case.

To see which versions a key has, use the REST endpoint `GET /api/v1/keys/{id}/versions` — there is no CLI command for listing versions yet.

> Addressing an older version needs no extra permission. It's the same data action as using the current one, on a key you already have access to.

### Export a key

A key created or imported with `--exportable` can be exported as an unencrypted PKCS#8 private key in PEM. You need a role assignment that grants the key export permission — `Key Vault Key Exporter` (grantable only by a global admin) or `Key Vault Administrator` (which a delegated Data Access Administrator can also grant). No account role is needed. HSM-backed, `oct` and ES256K keys can never be exported.

```
go run main.go keys export KEY-ID-HERE --file ./signer.pem.sealed
```

The file is sealed by default, exactly like `secrets export`: the passphrase comes from `--passphrase-file`, then `ROCKETVAULT_EXPORT_PASSPHRASE`, then a prompt asked twice. Add `--version 2` for an older version, and `--vault <name>` for another vault. An existing file is never replaced unless you add `--force`. Turn the sealed file into the PEM file with `export open` (see "Open a sealed export file" below).

To write the PEM file directly, add `--encrypt=false`; the command prints a warning, because the file then holds the private key in the clear. Every attempt that reaches the export command's own checks, allowed or refused, is recorded in the audit log; a failed login or a missing service container records nothing. An explicit deny on the create operation blocks export, but a deny on get does not (known issue B95 in `.claude/known-bugs.md`).

For scripts, give the passphrase through `--passphrase-file` or `ROCKETVAULT_EXPORT_PASSPHRASE` so nothing prompts. See "How export files are written" below for the file-writing rules.

---

## Managing Certificates

> This section is for technical users who need to manage X.509 certificates (used for TLS/HTTPS). Requires admin or certificate_manager role.

Most certificate commands (`list`, `get`, `update`, `renew`, `delete`) accept an optional `--vault <name>` flag to target a specific vault; if omitted, RocketVault uses the `default` vault. You'll need the matching role assignment on that vault.

### Create a self-signed certificate

```
go run main.go certificate create \
  --username admin --password admin123 --totp-code 123456 \
  --name my-cert \
  --key-id KEY-ID-HERE \
  --validity-days 365
```

`--validity-days 365` means the certificate is valid for one year.

> **Note:** `certificate create` does not yet support `--vault` — it always creates the certificate in the `default` vault, regardless of any `--vault` flag you pass. This will be wired up in a future release.

### Create a certificate with automatic renewal

Add `--auto-renew` so RocketVault renews the certificate automatically before it expires. `--renewal-days` controls how many days before expiry the renewal triggers (default: 30).

```
go run main.go certificate create \
  --username admin --password admin123 --totp-code 123456 \
  --name my-tls-cert \
  --key-id KEY-ID-HERE \
  --validity-days 365 \
  --auto-renew \
  --renewal-days 30
```

**How auto-renewal works:**
- Every 24 hours, RocketVault checks all certificates in the vault.
- If a certificate's expiry is within the `--renewal-days` window and `--auto-renew` is on, a new certificate is created automatically with the same validity period.
- If `--auto-renew` is off (the default), RocketVault instead logs a `cert_expiry_warning` entry — you still get notified, but renewal is manual.
- No action is needed from you once auto-renewal is enabled. Check server logs to see renewal activity.

### Create a certificate signed by a CA

```
go run main.go certificate create \
  --username admin --password admin123 --totp-code 123456 \
  --name my-signed-cert \
  --key-id KEY-ID-HERE \
  --validity-days 90 \
  --ca-cert-id CA-CERT-ID-HERE
```

### See all certificates

```
go run main.go certificate list \
  --username admin --password admin123 --totp-code 123456 \
  --vault my-team-vault
```

The output includes `expires_at`, `auto_renew`, and `renewal_days` for each certificate.

### Enable or change auto-renewal on an existing certificate

```
go run main.go certificate update CERT-ID-HERE \
  --username admin --password admin123 --totp-code 123456 \
  --auto-renew \
  --renewal-days 14
```

**Disable auto-renewal (switch to warning-only mode):**

```
go run main.go certificate update CERT-ID-HERE \
  --username admin --password admin123 --totp-code 123456 \
  --auto-renew=false
```

### Renew a certificate manually

```
go run main.go certificate renew CERT-ID-HERE \
  --username admin --password admin123 --totp-code 123456 \
  --validity-days 365 \
  --vault my-team-vault
```

### Export a certificate and its private key

A certificate created with `--exportable` can be exported with its private key, as one PEM file (the certificate, any intermediate CA certificates, then the private key) or as a PKCS12 bundle. You need `Key Vault Certificate Exporter` (grantable only by a global admin) or `Key Vault Administrator` (which a delegated Data Access Administrator can also grant) on the vault; no account role is needed.

```
go run main.go certificates export CERT-ID-HERE --file ./client.pem.sealed
```

For PKCS12, add `--format pkcs12` and give the bundle's password through `--pkcs12-password-file`, the `ROCKETVAULT_PKCS12_PASSWORD` variable, or the prompt (asked twice). An empty password needs `--pkcs12-empty-password`; a password is never a flag value. Add `--compat legacy` for tools that cannot read the default AES-256 encoding:

```
go run main.go certificates export CERT-ID-HERE --format pkcs12 \
  --pkcs12-password-file ./p12-pass --file ./client.p12.sealed
```

The output is sealed by default, exactly like `secrets export`; `--encrypt=false` writes the PEM or PKCS12 file directly and prints a warning. `--version` exports an older version. A PEM export is one file; split it if a tool needs two:

```
openssl pkey -in client.pem -out client.key
sed -n '/BEGIN CERTIFICATE/,/END CERTIFICATE/p' client.pem > client.crt
```

An explicit deny on the create operation blocks export, but a deny on get does not (known issue B95 in `.claude/known-bugs.md`).

**Running without a terminal.** The export passphrase comes from `--passphrase-file` or `ROCKETVAULT_EXPORT_PASSPHRASE`; for PKCS12 the bundle password comes from `--pkcs12-password-file`, `ROCKETVAULT_PKCS12_PASSWORD` or `--pkcs12-empty-password`. A user at a terminal who sets none of these is asked twice for the passphrase and then, for PKCS12, twice for the PKCS12 password. Without a terminal and without a source, the command fails and writes no file.

### How export files are written

Both export commands, and `export open`, write the file the same way:

- The file has mode 0600 and missing parent directories are created with mode 0700.
- It is written to a temporary file named `.rocketvault-export-*` in the same directory, synced, then moved into place, so a failure normally leaves no partial output. If the process is killed (SIGINT or SIGKILL) during the write, that temporary file can survive. It is mode 0600 and, with `--encrypt=false`, holds plaintext, so delete any leftover `.rocketvault-export-*` file. The parent directory is not synced, so a power loss right after the command returns can still lose the file.
- An existing file is never replaced unless you add `--force`. Without `--force` the file is created with a hard link, so the output filesystem must support hard links. Otherwise the command fails with "the output filesystem does not support hard links; choose another location or use --force".
- `--file -` is refused: an export is only ever written to a file.
- Nothing secret is printed. Stdout carries only a status block: name, version, format, encryption mode and file path for the two export commands; kind, name, version, format and file path for `export open`.

### Open a sealed export file

`export open` turns a sealed certificate or key export back into the file it holds. It works offline, with no login, no config file, no database and no server, so you can run it on the machine that will use the key:

```
go run main.go export open ./client.pem.sealed --file ./client.pem
```

It asks for the passphrase (or reads `--passphrase-file` or `ROCKETVAULT_EXPORT_PASSPHRASE`), writes the file with owner-only permissions, and refuses to replace an existing file unless you add `--force`. A sealed secrets export is refused; open that with `secrets import` instead. A sealed file larger than 1 MiB is refused as not an export. The status block it prints strips control characters from the name and format stored in the file. Delete the opened file when you are done with it.

`rocketvault export open --help` works anywhere. `rocketvault help export` and shell completion for `export open` still need a config file, like the other command groups.

Export is local mode only: with a remote target configured, both export commands are refused.

### Delete a certificate

```
go run main.go certificate delete CERT-ID-HERE \
  --username admin --password admin123 --totp-code 123456
```

---

## Managing Users (Admins Only)

### Add a new user

```
go run main.go users create \
  --username admin --password admin123 --totp-code 123456 \
  --new-username alice \
  --new-password alicepassword \
  --new-role user
```

The output will include a `TOTP Secret` line for the new user. That person must add it to their authenticator app before they can log in. Share the secret with them securely and point them to [How to Get Your 6-Digit TOTP Code](#how-to-get-your-6-digit-totp-code).

Available roles and what they can do:

| Role                  | What they can access                          |
|-----------------------|-----------------------------------------------|
| `admin`               | Everything                                    |
| `secrets_manager`     | Create and manage secrets and keys            |
| `crypto_manager`      | Create and manage cryptographic keys          |
| `certificate_manager` | Create and manage certificates                |
| `user`                | Only their own secrets and account            |

### See all users

```
go run main.go users list \
  --username admin --password admin123 --totp-code 123456
```

### Change a user's password or role

```
go run main.go users update USER-ID-HERE \
  --username admin --password admin123 --totp-code 123456 \
  --new-password newpassword123
```

### Remove a user

```
go run main.go users delete USER-ID-HERE \
  --username admin --password admin123 --totp-code 123456
```

---

## Database Backups

Backup commands require an **admin** login — a backup covers the entire
database across every vault, so there's no per-vault role that makes sense
here; only a global admin can create, list, or restore one.

### Create a backup

```
go run main.go backup create --file ./backups/my-backup.backup \
  --username admin --password admin123 --totp-code 123456
```

The backup is encrypted by default. Store the file somewhere safe.

### See available backups

```
go run main.go backup list --dir ./backups \
  --username admin --password admin123 --totp-code 123456
```

### Restore from a backup

```
go run main.go backup restore --file ./backups/my-backup.backup \
  --username admin --password admin123 --totp-code 123456
```

You will be asked to type `yes` to confirm. This replaces all current data with the backup.

---

## Health Check

Check that the system is running correctly:

```
go run main.go health
```

No login required. Shows memory, database, and performance information.

---

## Common Questions

**Q: What is a UUID / ID?**
It is a long unique identifier that looks like `9b8ead4b-7e88-430a-982c-bec891eed705`. RocketVault assigns one to every secret, user, key, and certificate. Use `list` commands to find them.

**Q: Why does the command keep asking for `--totp-code`?**
The 6-digit code from your authenticator app changes every 30 seconds. You need to enter the current code each time you run a command.

**Q: I got "authentication failed" — what do I do?**
- Check your username and password are correct.
- Make sure the 6-digit code from your app is current (it expires every 30 seconds — try again with a fresh code).
- If your phone clock is wrong (even by a minute), the codes will not match. Check that your phone time is set to automatic/network time.

**Q: I lost or deleted my authenticator app entry — what do I do?**
The TOTP secret is only shown once at account creation and is not stored anywhere you can retrieve it. Ask your administrator to delete your account and create it again. You will get a new TOTP secret to set up.

**Q: I never set up the authenticator app and cannot log in — what do I do?**
Same answer as above — ask your administrator to recreate your account. This time, follow the steps in [How to Get Your 6-Digit TOTP Code](#how-to-get-your-6-digit-totp-code) immediately after the account is created.

**Q: What does the backslash `\` mean at the end of a line?**
It means the command continues on the next line. You can type the whole command on one line if you prefer, just remove the `\` characters.

**Q: I do not have an authenticator app — which should I use?**
Any TOTP-compatible app works: Google Authenticator, Microsoft Authenticator, or Authy are all free and easy to set up on iOS or Android.
