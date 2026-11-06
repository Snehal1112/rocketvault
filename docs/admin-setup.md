# RocketVault - Admin Setup Guide

## Overview

This guide covers everything needed to get the first admin user created and
authenticated in RocketVault. It reflects the current project structure,
binary name, configuration file layout, and CLI command signatures.

---

## Prerequisites

| Requirement | Details |
|---|---|
| Go 1.24+ | Required to build the binary and run scripts |
| `rocketvault` binary | Built with `go build -o rocketvault` |
| `.rocketvault.yaml` | Main config file, must exist in the project root |
| `sqlite3` (optional) | Useful for manual database inspection |

---

## Configuration File

The binary always loads `.rocketvault.yaml` from the current directory by
default. You may override this with `--config <path>` on any command.

Minimal working configuration:

```yaml
master_key: "GENERATE_WITH: openssl rand -base64 32"
jwt_secret: "***SECRET-REMOVED-2026-08-17***"  # unread since 2026-08-16; removal tracked separately
jwt:
  key_source: "os_store"
  key_cn: "rocketvault"
  expiry: "1h"
  rotation_overlap: "1h"
bootstrap_token: "GENERATE_WITH: openssl rand -base64 32"
environment: "development"
database:
  connection: "./dev-rocketvault.db"
  driver: "sqlite3"
log:
  level: "debug"
  file: "./logs/development.log"
server:
  listen_addr: ":8774"
```

The `bootstrap_token` field drives the initial admin creation flow. On every
startup the application reads this value and inserts it into the
`bootstrap_tokens` database table if it is not already present, so no manual
SQL is required.

---

## Step 1 — Build the Binary

```bash
go build -o rocketvault
```

Verify it is present:

```bash
./rocketvault --help
```

---

## Step 2 — Create the Initial Admin User

The `users admin` command is the only command that does not require prior
authentication. It accepts a bootstrap token (read from config or passed
directly) and registers the very first admin account. The command also
generates a TOTP secret and prints it to stdout.

### Option A — Using the Automated Script (Recommended)

`scripts/create_admin.sh` wraps the CLI command and handles auto-detection of
whether the database is empty (bootstrap mode) or already has users
(authenticated mode).

```bash
# Auto-detect mode (recommended for first run)
./scripts/create_admin.sh --username admin --password admin123

# Force bootstrap mode explicitly
./scripts/create_admin.sh --mode bootstrap --username admin --password admin123

# Override the bootstrap token at runtime
./scripts/create_admin.sh \
  --mode bootstrap \
  --username admin \
  --password admin123 \
  --bootstrap-token "your-custom-token"

# Generate TOTP codes immediately after creation
./scripts/create_admin.sh --username admin --password admin123 --generate-totp
```

The script reads the `bootstrap_token` from `.rocketvault.yaml` by default.
It prints the TOTP secret from the command output. There is no `.admin_totp_secret`
file written by the binary itself — only the script may write that as a
convenience, and you should delete it after configuring your authenticator.

### Option B — Direct CLI Command

```bash
./rocketvault users admin \
  --admin-username admin \
  --admin-password admin123 \
  --bootstrap-token "<value from your .rocketvault.yaml>"
```

Expected output:

```
Admin user admin created successfully with ID: <uuid>
TOTP Secret: <BASE32_SECRET>
Configure the TOTP secret in your authenticator app for MFA.
```

Copy the `TOTP Secret` value — you need it to log in and to generate codes
from the terminal.

---

## Step 3 — Configure Your Authenticator App

Open any TOTP-compatible authenticator (Google Authenticator, Authy, 1Password,
etc.) and add the secret printed in step 2. The issuer name to use is
`rocketvault`.

---

## Step 4 — Generate a TOTP Code from the Terminal

`scripts/totp_generator.go` can generate codes without your phone. It supports
a persistent environment variable so you never have to paste the secret again.

### One-time setup (recommended)

Add to `~/.bashrc` or `~/.zshrc`:

```bash
export ROCKETVAULT_TOTP_SECRET="<your_BASE32_secret_from_step_2>"
```

Reload your shell:

```bash
source ~/.zshrc   # or ~/.bashrc
```

### Generate the current code

```bash
go run scripts/totp_generator.go
```

Example output:

```
RocketVault TOTP — user: admin
─────────────────────────────────
Current code : 482931
Valid for    : 22s  [███████████░░░░]
Time         : 14:05:08

Ready to use:
  --totp-code 482931
```

### Pass the secret inline (no env var)

```bash
go run scripts/totp_generator.go -secret="<your_BASE32_secret>"
```

### Watch mode — auto-refreshes every 30 seconds

```bash
go run scripts/totp_generator.go -watch
```

### Show a code for a specific username in the example command

```bash
go run scripts/totp_generator.go -username alice
```

---

## Step 5 — Log In

All commands except `users admin`, `serve`, `health`, `backup`, and the
`migrate:*` family require authentication via persistent flags on the root
command.

```bash
./rocketvault \
  --username admin \
  --password admin123 \
  --totp-code <code_from_step_4> \
  users list
```

On success the request proceeds and the result is printed. On failure you will
see `Error: Authentication failed`.

### Dedicated login command (returns a JWT token)

If you need the raw JWT for use with the REST API or scripting, use the
`users login` sub-command:

```bash
./rocketvault users login \
  --username admin \
  --password admin123 \
  --totp-code <code>
```

Output:

```
Login successful as admin.
```

The JWT is not printed: the session is cached under `~/.rocketvault/sessions`
and reused automatically, so a bearer token on stdout would only leak into
shell history and CI logs.

---

## Step 6 — Create Additional Users

Once authenticated as admin you can create other users. Role must be `admin`
or `user`.

```bash
./rocketvault \
  --username admin \
  --password admin123 \
  --totp-code <code> \
  users create \
  --new-username devuser \
  --new-password SecurePass456 \
  --new-role user
```

To create a second admin account, use the authenticated mode of the script:

```bash
./scripts/create_admin.sh \
  --mode authenticated \
  --username admin2 \
  --password Admin2Pass \
  --auth-user admin \
  --auth-pass admin123 \
  --auth-totp-secret "$ROCKETVAULT_TOTP_SECRET"
```

---

## Full End-to-End Workflow

```bash
# 1. Build
go build -o rocketvault

# 2. Create initial admin (bootstrap)
./rocketvault users admin \
  --admin-username admin \
  --admin-password admin123 \
  --bootstrap-token "<value from your .rocketvault.yaml>"

# 3. Save the TOTP secret printed above
export ROCKETVAULT_TOTP_SECRET="<secret_from_output>"

# 4. Get a code
go run scripts/totp_generator.go

# 5. Test authentication
./rocketvault \
  --username admin \
  --password admin123 \
  --totp-code <code> \
  users list

# 6. Create a regular user
./rocketvault \
  --username admin \
  --password admin123 \
  --totp-code <code> \
  users create \
  --new-username alice \
  --new-password Alice123 \
  --new-role user
```

---

## Output Formats

All commands support `--output` with three values:

| Flag | Description |
|---|---|
| `--output table` | Human-readable table (default) |
| `--output json` | JSON — useful for scripting |
| `--output yaml` | YAML |

Example:

```bash
./rocketvault --username admin --password admin123 --totp-code <code> \
  users list --output json
```

---

## Troubleshooting

### "invalid or used bootstrap token"

The token has already been consumed or does not match the config. Options:

1. Check `bootstrap_token` in `.rocketvault.yaml` matches what you passed.
2. Inspect the database directly:

```bash
sqlite3 ./dev-rocketvault.db \
  "SELECT token, used FROM bootstrap_tokens;"
```

3. If the token is marked `used=1` and no users exist (edge case after a failed
   run), reset it:

```bash
sqlite3 ./dev-rocketvault.db \
  "UPDATE bootstrap_tokens SET used=0 WHERE token='<your-bootstrap-token>';"
```

### "authentication failed"

- Confirm username and password are correct.
- Confirm the TOTP code is current — codes are valid for 30 seconds. Run
  `go run scripts/totp_generator.go` and use the code immediately.
- If the code is about to expire (less than 5 seconds on the bar), the
  generator warns you and prints the next code.

### "service container not available in context"

The database failed to initialise. Check that `.rocketvault.yaml` is present
in the current directory and the `database.connection` path is writable.

### Check user table

```bash
sqlite3 ./dev-rocketvault.db "SELECT id, username, role FROM users;"
```

### Config not found

If you placed the config elsewhere, pass `--config` explicitly:

```bash
./rocketvault --config /etc/rocketvault/.rocketvault.yaml users admin \
  --admin-username admin \
  --admin-password admin123 \
  --bootstrap-token "<token>"
```

---

## Security Recommendations

1. Replace the `bootstrap_token` in `.rocketvault.yaml` with a randomly
   generated value before first use in any shared environment:

   ```bash
   openssl rand -base64 32
   ```

2. `.rocketvault.yaml` is gitignored and untracked as of 2026-08-16 (see
   `docs/known-bugs.md` § B10) — it is never committed. Copy
   `.rocketvault.yaml.example` to start a new one.

3. Delete any `.admin_totp_secret` files the script may have written after
   you have configured your authenticator app.

4. Unset `ROCKETVAULT_TOTP_SECRET` from your shell after testing if you are on
   a shared machine.

5. Rotate the bootstrap token after the initial admin is created — set
   `bootstrap_token: ""` in config or remove the line entirely, since the
   application only seeds it once.

---

## Related Files

| File | Purpose |
|---|---|
| `scripts/create_admin.sh` | Automated admin creation with mode auto-detection |
| `scripts/totp_generator.go` | Terminal TOTP code generator with watch mode |
| `cmd/users/admin.go` | `users admin` command implementation |
| `cmd/users/login.go` | `users login` command implementation |
| `cmd/users/create.go` | `users create` command implementation |
| `cmd/root.go` | Root command, config loading, and authentication pre-run |
| `internal/db/db.go` | Database init and bootstrap token seeding |
| `.rocketvault.yaml` | Runtime configuration (not committed) |
