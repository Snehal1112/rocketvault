# CLI Certificate and Key Export

## What

Add `rocketvault certificates export <id>` and `rocketvault keys export <id>`,
the command-line counterparts of the per-item export routes built on
2026-10-01, plus a small `rocketvault export open <file>` that decrypts what
they write. They behave like `rocketvault secrets export` wherever that makes
sense: the same `--file`, `--encrypt` and `--passphrase-file` flags, the same
passphrase sources and order, the same argon2id and AES-256-GCM envelope, a
0600 file, and a loud warning when the caller writes plaintext on purpose.

## Why

Today an operator who holds the Key Vault Certificate Exporter or Key Vault
Key Exporter role can export only by scripting `curl` against the HTTP API:
log in, find the id, build a JSON body, decode `private_key_pem` or
`pkcs12_base64` with `jq` and `base64`, and remember to `chmod 600` the result.
Every one of those steps is a chance to leave a private key in a shell history,
a world-readable file or a terminal scrollback. The CLI already does this job
safely for secrets; certificates and keys should not be the exception. The
2026-10-01 spec listed CLI export commands as a non-goal; the user decided on
2026-10-02 to add them.

## Scope

- `certificates export <id>` with `--format pem|pkcs12`, `--compat
  modern|legacy`, `--version N`, and PKCS12 password handling that never takes
  the password as a command-line value.
- `keys export <id>` with `--version N` (PEM only, as on the API).
- Sealed output by default, `--encrypt=false` as a deliberate, warned opt-out,
  atomic 0600 writes that never leave a partial file, and no overwrite without
  `--force`.
- `export open <file>`, an offline command that opens a sealed certificate or
  key export.
- Authorization through the per-vault data-plane tier
  (`vaultcli.RequireDataAction` with the two exporter data actions), with the
  same explicit-deny override HTTP applies.
- One structured `AuditService.RecordEvent` per attempt, allowed or denied,
  sharing its fixed reasons with the HTTP handlers through a new
  `internal/services/exportaudit` package.
- `docs/cli-guide.md`, README, `CLAUDE.md`, the parity doc and the MCP guide.

## Out of scope

- Remote mode (`--server`, `ROCKETVAULT_ADDR`, a context): neither the
  `certificates` nor the `keys` group has a remote adapter, and the typed client
  has no export call; the existing remote-target guard keeps refusing.
- An MCP tool for export, at any tier.
- Bulk export of certificates or keys, and importing an export back.
- Any change to the service layer, the HTTP routes, their bodies or statuses,
  or the role definitions.
- Changing `secrets export`, including its account-role gate and its in-place
  overwrite.
