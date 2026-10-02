# Certificate Export (passphrase-sealed) — Design

**Date**: 2026-08-25
**Status**: Proposed
**Scope**: `internal/services/certificates/certificate_service.go`,
`common/export_envelope.go` (reused, not modified), `api/certificates.go`,
`cmd/certificates/export.go` (new)
**Branch target**: v-4.0.0
**Source finding**: gap-audit review of the secrets/keys/certificates
import-export asymmetry — this gap is untracked (no row in
`.claude/azure-keyvault-parity.md` §4). The existing but unrelated
`POST /certificates/{id}/backup` (`api/backup_item.go:46-49`,
`internal/backup/item_backup.go:360-366`) is unencrypted and must not be
conflated with this feature — see Problem, below.

See also: [2026-08-25-certificate-import-merge-design.md](2026-08-25-certificate-import-merge-design.md),
which adds `CertificateService.ImportCertificate` — a **different** feature
(single-cert PFX/PEM ingestion) that happens to share the word "import" with
this doc's bulk restore-from-export path. Naming is kept deliberately distinct;
see Design §3.

---

## Problem

RocketVault already has `POST /certificates/{id}/backup` and
`POST /certificates/restore`. It is tempting to treat that as "certificate
export already exists" — it does not, and the distinction matters enough to
state precisely before designing anything new.

`BackupCertificate` (`internal/backup/item_backup.go:360-366`) reads the
certificate via `certRepo.Read`, then calls
`encodeBlob("certificate", id.String(), cert, blobVersions{})` on the bare
`*model.Certificate` — there is no `model.CertificateVersion` type; certificates
have no rotation-archive concept at all, unlike keys. `encodeBlob`
(`internal/backup/item_backup.go:425-441`) JSON-marshals that struct and
**base64url-encodes** the result — no additional encryption layer at the blob
level. Concretely:

- `model.Certificate.Certificate` (`model/certificate.go:22`) is already
  plaintext PEM (a certificate's public content is meant to be public).
- `model.Certificate.PrivateKey` (`model/certificate.go:23`) is already
  `common.EncryptSecret`-wrapped PEM — ciphertext under *this RocketVault
  instance's* master key.

So the backup blob is base64url(JSON(plaintext cert PEM, master-key-ciphertext
key PEM)). It is not encrypted for the recipient — base64 is trivially
reversible by anyone who has the blob — and the private-key portion is only
usable by an instance holding the *same* master key. This is a same-instance
disaster-recovery mechanism, not a portable, human-controlled export: it can't
be handed to a person or a different RocketVault deployment and opened with a
chosen passphrase.

## Goals

A genuinely separate feature, structurally mirroring the existing secrets
export/import (`cmd/secrets/export.go`, `internal/services/secrets/secret_service.go`
`ExportSecrets`/`ImportSecrets`):

- CLI: `rocketvault certificates export --format json --file <path> --encrypt
  (default true) --passphrase-file <path> --tags <tags>` — same flag set
  `InitSecretsExport` registers (`cmd/secrets/export.go:280`).
- Same passphrase channel: reuse the shared
  `exportPassphraseEnvVar = "ROCKETVAULT_EXPORT_PASSPHRASE"` constant
  (`cmd/secrets/export.go:55`) rather than declaring a certificate-specific
  environment variable — one env var, one UX, across every resource type that
  supports export.
- Sealing: reuse `common.SealExport`/`OpenExport`/`IsSealedExport`
  (`common/export_envelope.go`) exactly as-is. The envelope
  (`{Version, KDF: "argon2id", Params{Time,Memory,Threads}, Salt, Ciphertext}`,
  AES-256-GCM) is generic — not secrets-specific — and already validates
  untrusted argon2 params before deriving a key
  (`minParamMemory`/`maxParamMemory` bounds, `common/export_envelope.go:44-50`),
  so no modification is needed here.

## Non-goals

- Does not replace or rebrand `POST /certificates/{id}/backup`/`/restore` —
  both mechanisms coexist, clearly named apart: `backup` = unencrypted,
  same-instance, full internal representation; `export` = passphrase-sealed,
  portable, human-shareable, explicit export-shaped payload (see Design §3).
- Does not import PFX/PEM from arbitrary external sources — that's
  [2026-08-25-certificate-import-merge-design.md](2026-08-25-certificate-import-merge-design.md)'s
  job. This doc's counterpart to export, if built, only re-ingests its own
  sealed export format.
- No CSV support — see Design §1.

## Design

### 1. Format decision: JSON-only, no CSV

**This is the doc's central call, made explicitly**: `--format` accepts only
`json` for certificate export. CSV is not offered, in v1 or as a stated future
default.

Reasoning, citing `.claude/known-bugs.md` directly: § B49 established that even
after § B42 fixed secrets' hand-rolled CSV (switching to `encoding/csv`),
`encoding/csv` still unconditionally normalizes embedded `\r\n` → `\n` in field
values — this is documented stdlib behavior, not a bug in RocketVault's use of
it, and secrets' fix was a reversible CR-escaping sentinel-byte transform layered
on top. Certificate and CSR material — PEM blocks, and CSRs generated by
Windows tooling especially — is exactly the multi-line, line-ending-sensitive
text this bug class targets, and arguably a worse fit than secret values
generally are: a single flipped line ending inside a PEM block doesn't just
corrupt a value cosmetically, it can silently produce a certificate that no
longer parses. Porting the CR-escaping workaround over is possible, but doing
so here means treating a workaround as a feature requirement for data that
should never have been forced through CSV in the first place. JSON has no
equivalent risk — a `\r\n` inside a JSON string value round-trips exactly, byte
for byte, with no normalization step.

If a future need arises for spreadsheet-style bulk certificate metadata
(name, expiry, tags — no PEM/CSR content), that should be a separate,
metadata-only CSV export. Full-material certificate export must stay
JSON-only permanently — this constraint is intentional, not a v1 gap to close
later.

### 2. `CertificateService.ExportCertificates`

`CertificateService` (`certificate_service.go:91-123`) is greenfield for both
export and (per the sibling doc) import. Add:

```go
// ExportCertificates returns the vault's certificates (filtered by filter,
// authorized by scope) as a formatted, unsealed byte payload. Sealing under a
// passphrase happens one layer up (CLI or API handler), mirroring
// SecretService.ExportSecrets — this method never sees a passphrase.
ExportCertificates(ctx context.Context, scope model.Scope, filter model.CertificateFilter) ([]byte, error)
```

Kept symmetric with `SecretService.ExportSecrets`
(`internal/services/secrets/secret_service.go:605-`): format in the service
(here, JSON only via `json.MarshalIndent`), seal in CLI/API. The service takes
no passphrase parameter, so it can never accidentally write a "sealed" export
that wasn't actually sealed — the class of bug § B36 describes (an `--encrypt`
flag that was bound but never consulted) is structurally harder to reintroduce
when the seal step lives entirely outside the method that has no passphrase to
ignore.

Marshal an explicit export-shaped struct, not the raw `model.Certificate` —
decide and list which fields round-trip and which don't at implementation time
(e.g. `Name`, `Certificate`, decrypted `PrivateKey` PEM, `Tags`, `ExpiresAt`,
`AutoRenew`, `RenewalDays`, `Enabled` are natural candidates to keep;
`ID`/`UserID`/`VaultID`/`KeyID` are internal identifiers that get regenerated
on any future restore path, not preserved verbatim).

### 3. Naming — avoid collision with Section 1's `ImportCertificate`

[2026-08-25-certificate-import-merge-design.md](2026-08-25-certificate-import-merge-design.md)
adds a singular `CertificateService.ImportCertificate` for single-cert PFX/PEM
ingestion. This doc's bulk path must be named distinctly — recommend
`ExportCertificates`/`RestoreCertificatesFromExport` (plural, explicit
"from export") rather than reusing "import" for a completely different
operation (bulk re-ingestion of this doc's own sealed format vs. single-cert
ingestion of arbitrary external PFX/PEM). Keep this distinction visible in both
docs' text, not just in code — a reader of either doc alone should be able to
tell the two apart without cross-referencing.

### 4. Authorization

> **Renamed 2026-10-01.** This action was `ActionCertificatesExport` with
> `.../certificates/export/action`. The per-certificate export that shipped
> first (`docs/superpowers/specs/2026-10-01-certificate-and-key-export-design.md`)
> owns `ActionCertificatesExportItem` and the `.../certificates/export/action`
> string, so the bulk action takes a distinct name and string.

New constant — Azure has no bulk-export data action for certificates (there is
no Azure equivalent to score this against), so this is explicitly a
RocketVault-only addition, same category as the parity doc's other `➕` rows:

```go
// ActionCertificatesBulkExport permits exporting certificates as a
// passphrase-sealed, portable file. RocketVault-only — Azure Key Vault has no
// equivalent bulk-export operation for certificates.
ActionCertificatesBulkExport DataAction = "Microsoft.KeyVault/vaults/certificates/bulkExport/action"
```

Grant to the same roles as `ActionCertificatesBackup` — the closest existing
analog, since export is conceptually adjacent to backup even though the two
are functionally distinct (see Problem).

`mapCertificateAction` (`internal/services/authorization/data_actions.go:213`)
gets a new case, same collection-level shape as
[2026-08-25-certificate-import-merge-design.md](2026-08-25-certificate-import-merge-design.md)'s
`case "import"`:

```go
case "export":
	if method == http.MethodPost {
		return model.ActionCertificatesBulkExport, RouteVaultData
	}
	return "", RouteVaultData
```

### 5. API

New route in `registerCertificateRoutes` (`api/certificates.go:103-113`):

```go
c.Handle("/export", ApiSessionRequired(api.App, exportCertificates)).Methods("POST")
```

New `exportCertificates` handler, mirroring `api/secrets.go`'s `exportSecrets`
(`api/secrets.go:171-`): decode the request (format, tag filter, encrypt flag),
resolve scope, call `certService.ExportCertificates(...)`, seal via
`common.SealExport` if requested, write the sealed (or plain) bytes directly as
the HTTP response body with a `Content-Disposition: attachment;
filename=certificates-export-<timestamp>.json` header — raw bytes, not
JSON-wrapped, exactly like `exportSecrets` (`api/secrets.go:219-228`).

### 6. CLI — `cmd/certificates/export.go`

Structurally identical to `cmd/secrets/export.go`: same flags
(`--format`, `--file`, `--encrypt`, `--passphrase-file`, `--tags`), same
`common.ResolvePassphrase(common.PassphraseSource{File, EnvVar: exportPassphraseEnvVar,
Prompt, Confirm: true})` call, resolved **after** authorization and **before**
any write — matching the exact ordering `cmd/secrets/export.go` uses, which
exists so a caller without permission never gets prompted for a passphrase for
an export that was always going to be rejected.

### 7. Lessons applied

Each of the five known-bugs entries the secrets export/import feature
generated maps to an explicit mitigation here:

| Bug | Mitigation in this design |
|---|---|
| § B36 — `--encrypt` bound but never read, silently wrote plaintext | The service method takes no passphrase and does no sealing (§2) — sealing happens in exactly one place (CLI/API handler), where `encrypt=true` + empty passphrase is a hard error, never a silent no-op |
| § B38 — `--overwrite` plumbed but never checked, import silently behaved like create-or-skip | If a restore-from-export counterpart is ever built, its existence-check-then-overwrite/skip/fail-count semantics must be test-driven explicitly, not assumed from the flag's presence — flagged here for whoever builds that path next |
| § B42 — hand-rolled CSV corrupted quoted/multiline values | Moot for this feature — no CSV support at all (§1) |
| § B49 — even `encoding/csv` normalizes CRLF, corrupting PEM-like text | Moot for the same reason — this is in fact the reasoning that ruled CSV out (§1) |
| § B51 — hand-written docs drifted from the shipped request/response shape | Documentation section below includes an explicit sweep of both the guide and the examples doc, not just this new spec |

## Testing

Certificate-equivalent of the secrets export/import test suite:

- Round-trip: export → `OpenExport` → verify plaintext matches source
  certificates exactly.
- `encrypt=true` + empty passphrase is a hard error, no file/response written.
- Tag filtering narrows the exported set correctly.
- Wrong passphrase on open produces `common.ErrWrongPassphrase`, not a silent
  garbage decode.
- Malformed/tampered envelope rejected via `validateArgonParams`'s existing
  bounds checks (`common/export_envelope.go:44-50`) — this only needs a test
  confirming the service correctly delegates to `OpenExport`, not a re-test of
  argon2 bounds themselves, which are already covered at the `common` package
  level.
- API test for `POST /certificates/export` (authz, response headers, body is
  raw bytes not JSON-wrapped).
- CLI test for `certificates export` (flag parsing, passphrase resolution
  ordering).

## Documentation

1. `.claude/azure-keyvault-parity.md` §4 — add a new row, "Export
   (passphrase-sealed, RocketVault-only)", marked `➕` (matching the existing
   `➕` convention used elsewhere in the doc, e.g. the "Default vault for legacy
   flat routes" row at `.claude/azure-keyvault-parity.md:233`). Write the row's
   text to explicitly distinguish it from the existing "Backup / Restore" row
   (`.claude/azure-keyvault-parity.md:223`) so a reader doesn't conflate the
   two — cross-reference this doc.
2. `.claude/roadmap-azure-parity-and-beyond.md` — this is a RocketVault-only
   addition, not an Azure gap-close, so it likely belongs in whatever "beyond
   parity" section the roadmap doc has (its own filename suggests one exists)
   rather than Phase 1 — confirm the doc's structure at write time and place
   accordingly.
3. `README.md` roadmap checklist, if relevant.
4. `docs/cli-guide.md` — add `certificates export`, cross-referencing
   `secrets export`'s shared passphrase/env-var UX so a reader who already
   knows one recognizes the other immediately.
5. `docs/api-developer-guide.md` — add the new export endpoint's
   request/response shape.
6. `docs/integration-examples.md` — add a worked example. Per § B51, both this
   file and the guide doc drift independently — update both, not just one.
7. `CLAUDE.md` — if certificate operations are enumerated there, add export.
