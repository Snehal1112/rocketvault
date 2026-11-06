# CLI Help Conventions

House style for every `cobra.Command` under `cmd/`. This is the contract the
2026-08-21 help-text pass follows; new commands should follow it too.

Scope: the `Use`, `Short`, `Long` and `Example` fields only. Do not change flag
registration, command wiring, or `RunE` behavior to satisfy this document.

Supersedes `docs/superpowers/specs/2026-06-06-cli-examples-design.md`. That spec
required credential flags on every invocation, which the 2026-08-15 session-cache
migration made wrong, and explicitly declined to add a test guard. Both decisions
are reversed here.

## The template

```go
var createCmd = &cobra.Command{
	Use:   "create",
	Short: "Create a new key",
	Long: `Create an RSA or ECDSA key in the target vault.

Requires the admin or crypto_manager role, and the keys/create data action
in the target vault. --type accepts only RSA or ECDSA; any other value is
rejected before a key is generated.`,
	Example: `  # RSA key in the default vault
  rocketvault keys create --name <name> --type RSA --bits 2048

  # ECDSA key in a named vault, with tags
  rocketvault keys create --name <name> --type ECDSA \
    --curve P-256 --tags prod,secure --vault payments`,
}
```

> The example above is illustrative of *form*. Never copy its flags into another
> command without checking that command's own flag registration — an earlier
> draft of this section showed `--type OCT`, which `cmd/keys/create.go` rejects
> outright. Read the code; do not trust the template's specifics.

## Field rules

**`Use`** — leave alone unless it is wrong. Positional arguments are angle
bracketed and match the `Args` validator: `get <id>`, `add <name>`.

**`Short`** — one line, sentence case, no trailing period. It appears in the
parent's subcommand list, so keep it under about 60 characters.

**`Long`** — a real description, not a restatement of `Short`. Replace
placeholders like "Create a new key with the specified details." Cover, in this
order, only what applies:

1. What the command does, including anything non-obvious about its effect.
2. The role and/or data action required. Be specific: name the roles
   (`admin`, `crypto_manager`) and the data action where one is checked. Write
   the data action in full, exactly as declared in `model/azure_roles.go` —
   `Microsoft.KeyVault/vaults/keys/read`, not `keys/read`.
   Do not assume both apply: several commands check a data action with no role
   check at all (`keys get`, `keys list`), and saying otherwise is a lie about
   the security model. Read the `RunE` and report what is actually there.
3. Vault scoping — whether it acts on `--vault` and what the default is.
4. Hard constraints worth knowing before running it: HSM-only paths,
   irreversible operations, retention windows on soft delete.

Wrap at 78 columns. Blank line between paragraphs. Full sentences ending in a
period.

**`Example`** — see below.

## Example blocks

- Two-space indent on every line, including comment lines. Cobra does not
  re-indent, so the literal text is what the user sees.
- Each scenario gets a `#` comment above it, sentence case, no trailing period.
- Blank line between scenarios.
- Continue long invocations with a trailing `\` and indent the continuation
  four spaces.
- Two to four scenarios per leaf command. Cover the plain case first, then a
  vault-scoped or otherwise notable variant, then any genuinely different mode
  (a different key type, an alternate output format, a `--force` path).
- Placeholders are angle bracketed: `<id>`, `<name>`. Never invent realistic
  looking UUIDs or secrets.

## Authentication in examples

The CLI caches sessions. `resolveAuthentication` in `cmd/root.go` accepts
`--username` + `--password`, or `--username` alone against a cached session, or
no credential flags at all against the current session.

- **Leaf commands must not show `--username`, `--password` or `--totp-code`.**
  These examples assume an active session.
- **Parent/group commands** (`rocketvault keys`, `rocketvault secrets`, and the
  other group aggregators) carry the login line once, verbatim:

  ```
    # Log in once; the session is cached
    rocketvault users login --username admin
  ```

- `cmd/users/login.go` is the exception — it documents the credential flags
  because that is what the command is for.

## Global flags

Registered as persistent flags on `rootCmd`: `--config`, `--username`,
`--password`, `--totp-code`, `--output`, `--vault`, `--server`, `--ca-cert`,
`--insecure-skip-verify`.

- Show `--vault` on any command that is vault scoped, in at least one scenario.
- Show `--output json` only where the command prints structured data worth
  reshaping, and at most once per command.
- **Never show `--server`, `--ca-cert` or `--insecure-skip-verify` outside the
  `context` group.** The remote-target guard in `persistentPreRun` rejects
  remote mode for every other command with "remote mode ... is not yet
  supported", so an example using them documents an error path.

## Commands that need no session

`persistentPreRun` treats these as system commands, so their examples must not
imply a login: `health`, `serve`, `admin`, `migrate`, `migrate:status`,
`migrate:to`, `migrate:create`, `roles`, `preview-migration`, `login`,
`logout`, `secrets generate-password`, and the whole `context` group.

## Do not

- Do not repeat the login line in leaf commands.
- Do not invent flags. Every `--flag` in an example must be registered on that
  command or inherited from a parent; `cmd/help_examples_test.go` enforces this.
- Do not put real or realistic secret values in examples.
- Do not document behavior the code does not have. Read the `RunE` before
  describing what a command does.

## Verification

```bash
go build ./...
go test ./cmd/...
go test ./cmd/ -run TestExampleFlagsAreRegistered -v
```
