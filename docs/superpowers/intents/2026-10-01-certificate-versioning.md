# Certificate Versioning

## What

Give certificates an Azure-style version history. Each create and each renewal
produces a numbered version, the current one stays addressable by the
certificate id, and older versions can be listed and read by number. This
follows how keys and secrets already version.

## Why

Azure Key Vault certificates are versioned and RocketVault's are not: a
renewal replaces the certificate in place and the old one is lost. Without
history there is no rollback, no audit of what a certificate looked like
earlier, and no way to pin an export to a specific version. The certificate
and key export feature (see
[2026-10-01-certificate-and-key-export.md](2026-10-01-certificate-and-key-export.md))
wants an optional `version` on export, so it is sequenced after this work.

## Scope

- A certificate versions store and migration, written on create and on renewal.
- List-versions and get-by-version routes, with data actions and roles.
- Per-version lifecycle, matching what keys offer.
- Version-aware backup and restore, soft-delete, recover and purge.
- Keeping every reader of the certificate row consistent: cache, API, CLI,
  MCP server and the vault client.
- Docs and the Azure parity rows.

## Out of scope

- Certificate and key export, which is a separate spec and plan that follows.
- Certificate import and CSR merge, and the certificate-to-secret linkage.
- Changing how keys or secrets version.
