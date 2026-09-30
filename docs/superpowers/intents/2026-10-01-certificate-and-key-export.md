# Certificate and Key Export for Rocket mTLS

## What

Add per-item export of private material over the API: a certificate exports
as a chain plus an unencrypted PKCS#8 key (PEM) or a PKCS12 bundle, and a
software-backed key exports as unencrypted PKCS#8 PEM. Each is gated by a new
narrow role and data action, an immutable opt-in `exportable` flag, and an
audit entry for every attempt.

## Why

Rocket (the Tauri API client) wants to fetch an mTLS client identity from
RocketVault at send time, holding nothing on disk. Today no route returns usable
private material: backup is master-key ciphertext, `GET` returns metadata only,
and the 2026-08-25 bulk export is passphrase-sealed and Officer-gated. Without
this, Rocket users must copy key material into ordinary secrets by hand.

## Scope

- `POST .../certificates/{id}/export` (vault-scoped and flat), formats `pem`
  and `pkcs12` (modern default, `compat: "legacy"` option).
- `POST .../keys/{id}/export` for software-backed keys only, unencrypted
  PKCS#8 PEM. HSM (`pkcs11:`) keys are never exportable.
- `exportable` flag on certificates and keys, default false, set at creation
  or import and never changed after.
- `exportable` and `key_algorithm` on the certificate response, and
  `exportable` on the key response.
- New exporter data actions and a narrow exporter role, granted to
  Administrator only besides that role.
- The error contract, `Cache-Control: no-store`, per-attempt audit, and no
  material or password in logs.
- Updates to `docs/api-specification.yaml`, `docs/api-developer-guide.md`,
  `docs/integration-examples.md`, and the parity doc.

## Out of scope

- The bulk passphrase-sealed certificate export from the 2026-08-25 design.
- CSV export and the certificate-to-secret linkage (P5).
- CLI export commands, unless the spec adds them later.
- HSM key export, which the PKCS#11 token forbids.

The key-export half reverses the 2026-08-25 key-export decision record at the
user's direction. The spec must amend that record, not leave it contradicting
the code.
