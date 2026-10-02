# CLI Certificate and Key Export — Design

**Date**: 2026-10-02
**Status**: Implemented on v-4.0.0 (2026-10-02)
**Branch target**: v-4.0.0
**Intent**: [2026-10-02-cli-certificate-and-key-export.md](../intents/2026-10-02-cli-certificate-and-key-export.md)
**Amends**: [2026-10-01-certificate-and-key-export-design.md](2026-10-01-certificate-and-key-export-design.md),
whose Non-goals listed "CLI export commands". This spec adds them. Nothing else
in that spec changes: the services, routes, bodies, statuses, roles and the
`exportable` flag stay exactly as built.
**Builds on**: `CertificateService.ExportCertificate`
(`internal/services/certificates/certificate_export.go`), `KeyService.ExportKey`
(`internal/services/keys/key_export.go`), the HTTP handlers in `api/export.go`
and `api/keys_export.go`, and the `secrets export` command
(`cmd/secrets/export.go`, `common/export_envelope.go`, `common/passphrase.go`).

**Scope**: `common/item_export.go` (new), `common/private_file.go` (new),
`common/passphrase.go` (one additive field), `internal/services/exportaudit/`
(new), `api/export.go` (delegates to `exportaudit`, behavior unchanged),
`cmd/vaultcli/export.go` (new), `cmd/certificates/export.go` (new),
`cmd/keys/export.go` (new), `cmd/export.go` (new), `cmd/certificates.go` and
`cmd/keys.go` (registration and help text), `cmd/root.go` (help text and one
added condition in `initConfig`, see section 3), and the docs listed under
Documentation.

---

## Problem

The export routes exist, but the only way to use them from a shell is to
script `curl`: obtain a token, look up the id, build a JSON body, extract
`private_key_pem` or decode `pkcs12_base64`, and `chmod 600` the result by hand.
Each step can leave a private key in shell history, a world-readable file or
terminal scrollback. `rocketvault secrets export` already solves the same
problem for secrets with a sealed-by-default file. Certificates and keys have
no CLI equivalent.

## Goals

- `rocketvault certificates export <id>` and `rocketvault keys export <id>`,
  consistent with `secrets export` in flags, passphrase handling, envelope,
  file permissions and warnings.
- Every security rule of the HTTP export kept: the exporter data actions, the
  explicit-deny override, the service-side refusals, fixed error messages, one
  structured audit event per attempt, and no material or password in any log,
  error or audit record.
- A sealed export that a user can actually open, offline, with the same binary.
- No partial file on any failure, no silent overwrite, and nothing secret on
  stdout or stderr.

## Non-goals

- Remote mode (see section 7).
- An MCP tool for export (see section 9).
- Bulk export, CSV, or importing an export back into a vault.
- Any change to the services, the HTTP routes or bodies, the roles, or
  `secrets export` (its account-role gate and its in-place overwrite stay).
- Splitting a PEM export into separate certificate and key files. One file
  holds the chain then the key; section 2 shows how to split it.

## Design

### 1. Commands and flags

| | `certificates export <id>` | `keys export <id>` |
|---|---|---|
| Positional | certificate UUID | key UUID |
| `--file`, `-o` | required output path | required output path |
| `--encrypt`, `-e` | default `true` | default `true` |
| `--passphrase-file` | sealing passphrase file | sealing passphrase file |
| `--force` | replace an existing file | replace an existing file |
| `--format`, `-f` | `pem` (default) or `pkcs12` | none: PEM only, as on the API |
| `--compat` | `modern` (default) or `legacy`; pkcs12 only | none |
| `--version` | `0` (current) or a version number | `0` (current) or a version number |
| `--pkcs12-password-file` | PKCS12 password file; pkcs12 only | none |
| `--pkcs12-empty-password` | deliberate empty PKCS12 password; pkcs12 only | none |
| `--vault` | inherited root flag | inherited root flag |

`--format` and `--compat` are lowercased like `secrets export --format`. The id
is positional, like `certificates renew <id>` and `certificates versions list
<id>`. `--version` matches `keys sign --version`. `keys export` has no
`--format` flag: the API accepts only `pem` for keys, and a one-value flag is
noise that can be added later without breaking anything.

Both commands are built by a constructor (`newExportCmd`, `newKeyExportCmd`)
instead of a package-level variable, so every test gets fresh flags. The
existing tests' habit of sharing a package-level command's flag set leaks flag
values between tests.

### 2. Output protection

**Sealed by default.** `--encrypt` defaults to `true`, exactly as in
`secrets export`. The passphrase comes from `--passphrase-file` (first line,
trimmed), then `ROCKETVAULT_EXPORT_PASSPHRASE`, then a terminal prompt asked
twice, through the existing `common.ResolvePassphrase`. With none of them
available the command fails and writes no file. `--passphrase-file` together
with `--encrypt=false` is refused with the same message `secrets export` uses.
The passphrase is resolved only after authorization, so an unauthorized caller
is never prompted.

**Envelope.** The file is the existing `common.SealExport` envelope (argon2id,
AES-256-GCM, `{"rocketvault_export":1,...}`), unchanged. Its plaintext is a new
JSON payload, `common.ItemExportPayload`:

```json
{
  "rocketvault_item_export": 1,
  "kind": "certificate",
  "id": "<uuid>",
  "name": "client",
  "version": 2,
  "format": "pem",
  "key_algorithm": "RSA-2048",
  "content": "<base64 of the exact bytes --encrypt=false would write>"
}
```

`kind` is `certificate` or `key`. `content` is exactly the plaintext file: for a
certificate in PEM, the leaf, then the intermediates, then the PKCS#8 key; for
PKCS12, the DER bundle; for a key, the PKCS#8 PEM. So opening a sealed export
always yields byte-for-byte the file `--encrypt=false` would have written, and
there is one plaintext format to document, not two. The payload marker lets the
opener refuse a sealed `secrets export` file instead of misreading it, and a
newer payload version is refused rather than misparsed, mirroring
`OpenExport`'s own version check. `common.SealItemExport` and
`common.OpenItemExport` wrap `SealExport`/`OpenExport`.

**Plaintext opt-out.** `--encrypt=false` writes the content directly and first
prints one line to stderr:

- certificate PEM: `Warning: --encrypt=false — <file> will hold the certificate's private key unencrypted, in the clear.`
- certificate PKCS12: `Warning: --encrypt=false — <file> will hold the certificate's private key protected only by the PKCS12 password.`
- key: `Warning: --encrypt=false — <file> will hold the key's private key unencrypted, in the clear.`

A PEM export is one file. Tools that want two can split it:
`openssl pkey -in client.pem -out client.key` and
`sed -n '/BEGIN CERTIFICATE/,/END CERTIFICATE/p' client.pem > client.crt`. Go's
`tls.LoadX509KeyPair("client.pem", "client.pem")` and `curl --cert client.pem`
read it as is.

**Writing the file.** A new `common.WritePrivateFile(path, data, overwrite)`:

1. creates missing parent directories with mode 0700;
2. writes a temporary file in the same directory (`os.CreateTemp`), sets it to
   0600, writes, syncs and closes it;
3. without `--force`, hard-links it to the target with `os.Link`, which fails if
   anything (a file, a directory, a dangling symlink) is already there, so an
   existing path is never replaced and a symlink is never followed; with
   `--force`, renames it over the target, replacing the target itself (a symlink
   is replaced, not followed);
4. always removes the temporary name.

A failure at any step leaves the target as it was and no temporary file
behind. The command also checks for an existing target before authorizing, so
the common mistake fails before any material leaves the vault; the link in
step 3 closes the race.

Two deliberate differences from `secrets export`, which stays unchanged:
`secrets export` overwrites in place with `os.WriteFile`, and creates parent
directories 0755. Overwriting a private key file silently can destroy the only
copy of a different key, so the item exports refuse without `--force`.
Directories created only to hold private keys should not be listable by other
users, so they get 0700 (0755 would also trip gosec G301 in new code).

**Stdout and stderr.** On success stdout gets one status block and nothing
else:

```
Certificate exported successfully
Name: client
Version: 2
Format: pem
Encryption: passphrase (argon2id + AES-256-GCM)
File: client.pem.sealed
```

`--file -` is refused (`--file - is not supported: an export is only ever
written to a file`), so material never reaches a terminal or a pipe. Errors go
to stderr through cobra as usual and carry only fixed text (section 8).

### 3. Opening a sealed export: `rocketvault export open`

A sealed file nobody can open is useless, and `openssl` cannot read an argon2id
envelope. A new top-level group `export` holds one command:

```
rocketvault export open <sealed-file> --file <output> [--passphrase-file <path>] [--force]
```

It reads the sealed file (refusing anything over 1 MiB), resolves the
passphrase (`--passphrase-file`, then `ROCKETVAULT_EXPORT_PASSPHRASE`, then one
prompt), opens it with `common.OpenItemExport`, and writes `content` through
`WritePrivateFile` with the same no-overwrite rule. It prints a status block
(kind, name, version, format, file) to stdout and to stderr a warning that the
output now holds the private key unencrypted (PEM) or protected only by the
PKCS12 password.

- A wrong passphrase reports `wrong passphrase or corrupted export file`.
- A sealed `secrets export` file is refused with a pointer to
  `rocketvault secrets import`.
- A file that is not an envelope at all is refused.

It needs no session, no database and no server: it is pure local decryption,
so it works on the target machine that receives the sealed file. The `export`
group replaces the root `PersistentPreRunE` with a no-op, the pattern
`cmd/mcp.go` already uses. This is deliberately not done by adding a name to
`isSystemCommand` in `cmd/root.go`: that function matches by command name and
by parent name, so exempting `export` there would also exempt `secrets export`
from authentication. Because the group never reaches the remote-target guard,
`export open` also works with an active remote context.

Replacing the pre-run is not enough on its own. `cmd/root.go` registers
`initConfig` through `cobra.OnInitialize`, which runs before any pre-run, and
`initConfig` panics when no `.rocketvault.yaml` is found unless the command is
in the `context` group (`isContextCommandArgs`) or a remote target is set. So
`initConfig` gains one more exemption, `isExportGroupArgs(os.Args[1:])`,
defined in `cmd/export.go` beside the group. It resolves the arguments with
`rootCmd.Find` and compares command pointers with the `export` group, so
`secrets export`, `certificates export` and `keys export` never match. Verified
by building the binary and running `export open` from an empty directory.

Opening is not audited: it touches no vault and has no principal. The vault-side
record is the export itself.

Considered and rejected: a hidden `--open` flag on the export commands (mixes
an authenticated online command with an offline one, and would require a
session to decrypt a local file), and reusing `secrets import` (it writes into a
vault, which is the opposite of what is wanted).

### 4. PKCS12 password

`ExportCertificateRequest.Password` is a `*string` and pkcs12 requires it to be
present; an empty string is allowed. The CLI never takes the password as a
flag value. Sources, in order:

1. `--pkcs12-empty-password`: a deliberate empty password. This is the only
   way to get one.
2. `--pkcs12-password-file`: the first line, trimmed (the same reader as
   passphrase files, so an empty file is an error, not an empty password).
3. `ROCKETVAULT_PKCS12_PASSWORD`: an empty value counts as unset, so an unset
   shell variable expanded into it cannot silently produce an empty password.
4. A terminal prompt asked twice (`PKCS12 password: `, then
   `Confirm PKCS12 password: `). An empty answer is refused.

With none available the command fails with
`pkcs12 needs a password: pass --pkcs12-password-file, set ROCKETVAULT_PKCS12_PASSWORD, or pass --pkcs12-empty-password`
and writes nothing. `--pkcs12-password-file` and `--pkcs12-empty-password`
together are refused. `--compat`, `--pkcs12-password-file` and
`--pkcs12-empty-password` with `--format pem` are refused rather than ignored.

To support the second prompt's text, `common.PassphraseSource` gains an
optional `ConfirmPrompt` field defaulting to today's `Confirm passphrase: `, so
existing callers are unchanged.

Interplay with sealing: they are independent layers. The PKCS12 password is
what the consuming application will use; the passphrase protects the file in
transit and at rest until it is opened. A sealed PKCS12 export needs both, and
`export open` yields the PKCS12 file still protected by its own password. The
same value may be used for both; the CLI does not check.

The passphrase is resolved before the PKCS12 password, so a caller is asked for
the outer secret first.

### 5. Authorization

Per CLAUDE.md "CLI Authorization", certificates and keys are the per-vault
data-plane tier. Both commands go through `vaultcli.Caller` and then
`Session.Authorize`, the structure every newer certificate and key command
uses (`cmd/certificates/versions.go`, `cmd/certificates/create.go`), which calls
`vaultcli.RequireDataAction` and so runs the same two-stage check as
`PolicyMiddleware`:

| Command | `Op.Action` | `Op.Policy` | `Op.Audit` |
|---|---|---|---|
| `certificates export` | `model.ActionCertificatesExportItem` | `model.OpCreate` | `export_certificate` |
| `keys export` | `model.ActionKeysExport` | `model.OpCreate` | `export_key` |

`OpCreate` because `resolvePolicy` (`internal/middleware/middleware.go`) maps
the `POST .../export` routes to `OpCreate`, so a legacy deny-create access
policy blocks the CLI export exactly as it blocks the HTTP export, and the
explicit-deny override is evaluated with the same triple on both paths.

**No account-role gate.** `Op.Roles` stays empty. `secrets export` requires
`admin` or `secrets_manager`, and the mutating certificate and key commands
require `admin` plus `certificate_manager` or `crypto_manager`, but:

- the HTTP export routes apply no account role; `vaultcli.Session`'s own doc
  comment records the account-role gate as a pre-existing CLI-only divergence
  that is preserved, not a rule for new commands;
- the exporter roles are Azure data-plane roles granted per vault, by a global
  admin only, to principals that are typically plain `user` or
  `service_account` accounts; an account-role gate would make Key Vault
  Certificate Exporter and Key Vault Key Exporter useless on the CLI;
- the export data actions are already the narrowest gate in the system: only
  the two exporter roles and Key Vault Administrator hold them;
- the read-style certificate and key commands (`get`, `list`, `versions`)
  already run with no account role.

Authorization runs after input validation (so a malformed argument reports
itself, as in every other `Caller` command) and before any prompt or service
call. Unauthenticated callers fail in `vaultcli.Caller` as everywhere else.

### 6. Audit

The HTTP handlers write one structured `AuditService.RecordEvent` per attempt,
with fixed reasons from `exportFailureFor` and the event built in
`recordExportAudit`, both in package `api`. The CLI must produce the same event
and must not import `api`.

**Shared home: a new package `internal/services/exportaudit`.** It holds:

- `Kind` (`KindBadRequest`, `KindForbidden`, `KindNotExportable`,
  `KindNotFound`, `KindDisabled`, `KindInternal`) and `Failure{Kind, Code,
  Message, Reason, Name, KeyAlgorithm}`;
- `Classify(err, resource) Failure`: moved verbatim from `api.exportFailureFor`
  minus the HTTP status and the 500 cause;
- `BadRequest(msg)`, `Internal(reason)` and `Forbidden(reason)` constructors;
- `AuditableFormat(format)`: moved from `api.auditableExportFormat`;
- `Attempt` (the fields of `api.exportAudit` plus `UserID`, `IPAddress` and
  `Source`), `Event(Attempt) audit.AuditEvent` and `Record(ctx, svc, Attempt)`:
  moved from `api.recordExportAudit`, with the same `Details` keys (`vault_id`,
  `name`, `version`, `format`, `code`, `reason`), so the JSON is byte-identical.

It is a new package rather than part of `internal/services/audit` because the
classification needs the certificate and key service sentinels, and `audit` is
a leaf package that nothing service-specific should be pulled into. Nothing in
`exportaudit`'s imports imports it back, so there is no cycle.

**What moves out of `api/export.go`:** the body of `exportFailureFor` (now
`Classify` plus a local `exportStatus(kind)` table and the 500 cause), the body
of `auditableExportFormat` (now a call), and the body of `recordExportAudit`
(now builds an `Attempt` with `Source: "api"` and the client IP and calls
`Record`). The `api` types, helpers and every status, code, message, reason and
event field stay identical; the existing `api` export tests, unmodified, are
the proof.

**CLI side: `vaultcli.ExportAttempt`.** Created right after `Caller`, it holds an
`exportaudit.Attempt` with `Source: "cli"` and records exactly one event per
attempt whatever the outcome; a second outcome is ignored. Its methods:

- `Fail(f)`: validation failures, before or after authorization.
- `Denied(err)`: authorization failures; reason `vault authorization failed`,
  code `forbidden`. It re-resolves the vault so the event carries the vault id.
- `FailInput(reason, shown)`: a missing passphrase or PKCS12 password; reasons
  `export passphrase unavailable` and `pkcs12 password unavailable`.
- `FailService(err)`: `exportaudit.Classify`, so the same code and reason as
  HTTP.
- `FailOutput(err)`: the file could not be written after the service released
  the material; code `output_failed`, reason
  `the output file could not be written` (or `bad_request` for a target that
  appeared after the pre-check).
- `Succeed(name, version)`.

A failure before the vault is resolved records an empty `vault_id`. The raw id
argument reaches the event only when it parses as a UUID, and the format only
when it is a known export format (`invalid` otherwise), so arbitrary
command-line text never reaches the audit trail; the reason is always a fixed
phrase.

The command writes no legacy `Session.OK`/`Session.Fail` row of its own,
matching the HTTP handler. Two legacy rows still exist, as they do over HTTP:
the services' own `LogAuditInfo`/`LogAuditError` rows, and on an authorization
denial the row `Session.Authorize` writes (the CLI counterpart of the denial
`PolicyMiddleware` logs).

**No secrets in logs.** The passphrase and the PKCS12 password are never
logged, printed or put in an error. Material is never logged. An internal
service error's text goes only to the log file (as the HTTP handler's
`logExportFailure` does); the user sees
`internal error; see the RocketVault log for details`.

### 7. Remote mode: out of scope

`remoteCapableCommands` in `cmd/root.go` lists only `secrets`, `users` and
`vault-access` subcommands; the `keys` and `certificates` groups have no remote
adapter at all, and neither `internal/vaultapi` nor `internal/cliclient` has an
export call. Building one would mean a remote adapter for one subcommand of two
otherwise local-only groups, plus a new client call that carries private
material over the wire into the CLI, for no consumer that needs it (Rocket calls
the HTTP route directly). The existing guard already refuses both commands with
`remote mode (...) is not yet supported for "rocketvault certificates export"`
before touching a database; a test pins that. `export open` is local by nature
and unaffected by a remote target.

### 8. Order of operations and failure handling

Both commands run these steps in order; each failure records one audit event,
writes no file and returns an error:

1. `vaultcli.Caller`: claims and logger (no event: unauthenticated).
2. Validate: the id parses as a UUID; `--format`, `--compat` and `--version`
   are valid; the PKCS12 flags fit the format; `--file` is set and is not `-`;
   `--passphrase-file` is not combined with `--encrypt=false`; the target does
   not exist unless `--force`. Code `bad_request`, reason = the fixed message.
3. `Session.Authorize`: explicit deny, then the data action. Code `forbidden`.
4. Resolve the passphrase (if sealing), then the PKCS12 password (if pkcs12).
5. Call the service. Errors classified by `exportaudit.Classify`; the CLI shows
   `Failure.Message` (the service's refusal text for a not-exportable item, a
   fixed phrase otherwise) and never the raw error.
6. Build the payload; seal or warn; `WritePrivateFile`.
7. Record success, print the status block.

Error text is `failed to export certificate: <fixed message>` or
`failed to export key: <fixed message>`. For example a non-exportable
certificate yields
`failed to export certificate: certificate is not exportable: the certificate was not created with exportable: true`.

Exit codes: every failure exits 1 and success exits 0, through the existing
`cmd.run` (`cmd/root.go`), as for every other command. No command in this CLI
has distinct exit codes, and adding them for two commands would be
inconsistent.

The payload's `content` slice is cleared after writing. The PEM strings the
service returns are Go strings and cannot be zeroed; that limit is the same as
on the HTTP path.

### 9. MCP

Export is deliberately **not** exposed as an MCP tool, at any tier, now or as
part of this work. An MCP tool would hand an unencrypted private key to a
language model's context, which defeats every protection above. `docs/mcp-server.md`
says so explicitly.

## Decisions

| # | Decision | Reason |
|---|---|---|
| 1 | `certificates export <id>` and `keys export <id>`, positional id, `--file/-o` required, certificate `--format pem\|pkcs12` (default pem), `--compat modern\|legacy`, `--version N`; keys PEM only with `--version N`; `--vault` inherited | Matches `secrets export` flags and the newer `<id>`-positional certificate and key commands; keys have one format on the API. |
| 2 | Sealed by default, same passphrase sources and order as `secrets export`, same envelope | Consistency, and a private key should never land on disk in the clear by default. |
| 3 | The sealed payload is a versioned JSON object whose `content` is the exact plaintext file | One plaintext format, self-describing, refuses a secrets export, future-proof. |
| 4 | `rocketvault export open <file>` decrypts offline, no session or database | A sealed export nothing can open is useless; the receiving machine may have only the binary. |
| 5 | Atomic temp-file write, 0600, never overwrite without `--force`, parent directories 0700 | No partial files; overwriting a key file can destroy the only copy of another key. |
| 6 | PKCS12 password from a file, an environment variable or a double prompt, never a flag value; empty only via `--pkcs12-empty-password` | Command-line values leak through shell history and `ps`; an accidental empty password is a silent weakness. |
| 7 | Per-vault data-plane check with the exporter data actions and `OpCreate`; no account-role gate | Same triple and same explicit deny as HTTP; an account-role gate would block the exporter roles' intended holders. |
| 8 | Shared `internal/services/exportaudit` for classification and the audit event; `api` delegates | One set of fixed reasons and one event shape; the CLI must not import `api`. |
| 9 | Remote mode out of scope | No remote adapter for either group and no client export call; the guard already refuses. |
| 10 | Every failure exits 1 with a fixed message; stdout carries only a status block | Consistent with the whole CLI; no material on a terminal. |
| 11 | No MCP export tool | It would put an unencrypted private key into a model's context. |
| 12 | Commands built by constructors | Fresh flags per test; package-level commands leak flag state between tests. |

## Testing

Test-first, per layer, with the existing fakes (`testutils.NewTestContext`,
`certCmdCertService`, `keyCmdKeyService`, `certsTestContainer`,
`keysTestContainer`, `testutils.MockRoleAssignmentService`,
`testutils.MockAccessPolicyService`):

- **`common`**: item payload seal/open round trip; wrong passphrase; a sealed
  secrets export, a CSV and a marker-less object refused as not an item export;
  a newer payload version refused; `WritePrivateFile` creates 0600 and 0700,
  refuses an existing path and a dangling symlink without overwrite, replaces
  and tightens the mode with overwrite, and leaves no file or temporary file
  when the directory is not writable.
- **`exportaudit`**: `Classify` table over every sentinel the HTTP mapping
  handles, with raw error text never reaching `Message` or `Reason`; `Event`'s
  exact `Details` JSON; `Record` tolerates a nil service; `AuditableFormat`.
- **`api`**: the existing export tests pass unmodified; one new table test pins
  `exportStatus` for every `Kind`.
- **`vaultcli`**: one event per attempt even when two outcomes are reported;
  unparseable ids and formats never reach the event; internal causes go to the
  log only; refusal text shown; `Denied` returns the authorization error and
  records the vault; `FailOutput` codes; `ExportOutput.Check` messages;
  passphrase sources; sealed and plaintext writes with the exact warning;
  status block.
- **Command tests** (both commands): sealed round trip through
  `common.OpenItemExport`; plaintext content and the exact warning; file mode
  0600; `--force` replaces and an existing file is never replaced without it;
  every bad input rejected before authorization with the role mock never
  consulted; denial without the data action (and no passphrase prompt);
  explicit deny overriding a role grant; the exact action and `OpCreate`
  checked; the service's refusal text shown, nonzero, no file; not-found,
  disabled, invalid-request and internal errors shown only as fixed text;
  PKCS12 password from a file, the environment and the empty flag, missing
  password refused; one audit event with the right code and reason in every
  case; and no key text, certificate body, passphrase or PKCS12 password in
  stdout, stderr, the log or any audit event, sealed and plaintext.
- **`export open`**: round trip to the exact plaintext; wrong passphrase, a
  secrets export, a plain file and a missing passphrase all refused with no
  output; no overwrite without `--force`; an end-to-end run through
  `rootCmd` from a directory with no config file and no session, both in local
  mode and with `--server`; and `isExportGroupArgs` never matching the other
  `export` commands.
- **Remote mode**: `certificates export` and `keys export` through `rootCmd`
  with `--server` are refused by the guard and write nothing.

## Regression safety

- **No service, route, body, status, role or schema change.** `git diff` over
  `internal/services/certificates`, `internal/services/keys`,
  `internal/middleware`, `model`, `internal/db` and `api/keys_export.go` is
  empty.
- **`api/export.go` behaves identically.** Only three function bodies change,
  and the existing `api` export tests (statuses, R6 bodies, audit `Details`,
  no-secrets-in-logs through the real chain) pass without modification.
- **No existing command changes behavior.** `secrets export` and `secrets
  import` are untouched. `cmd/certificates.go` and `cmd/keys.go` change only by
  one registration line each and help text; `cmd/root.go` only by help text and
  the `isExportGroupArgs` condition in `initConfig`, which matches the new
  group alone. `common.PassphraseSource.ConfirmPrompt` is additive with the old
  default.
- **No existing test is modified.** New tests live in new files.
- **Remote guard unchanged.** `remoteCapableCommands` is not edited.
- **Hard gates:** `go build ./...`, `go vet ./...`,
  `go test -p 2 ./... -count=1`, and `golangci-lint run --new-from-rev=<base>`
  under the go1.25.7 toolchain, all clean; plus an isolated-instance smoke test
  that exports a real certificate and key, opens the sealed files and checks
  them with `openssl`. The smoke test sets `HOME` to a scratch directory:
  `users login` writes `~/.rocketvault/sessions/<server>__<user>.json` and
  `current`, and a smoke admin named `admin` would otherwise overwrite the
  developer's own cached session.

## Documentation

- `docs/cli-guide.md`: "Export a key", "Export a certificate and its private
  key" and "Open a sealed export file" sections.
- `README.md`: one example each in the key and certificate CLI blocks.
- `CLAUDE.md`: the CLI commands next to the existing export bullets, the CLI
  Authorization note that both use the data-plane tier with no account role,
  and a Documentation History entry.
- `.claude/azure-keyvault-parity.md`: one bullet under "Intentional export
  divergences" for the sealed CLI file.
- `docs/mcp-server.md`: export is never an MCP tool.
- The 2026-10-01 spec's Non-goals bullet points here; this spec's status
  becomes Implemented when the plan lands.
- `cmd/keys.go`'s group help no longer says private key material never leaves
  the vault.

## Delivery

On `v-4.0.0`, one commit per plan task through the
`dev-workflow-skills:1-git-commit` skill, GPG signed; the plan is
`docs/superpowers/plans/2026-10-02-cli-certificate-and-key-export.md`.

## Open questions

1. No account-role gate (section 5) makes the CLI export reachable by a plain
   `user` account holding an exporter role, unlike `secrets export`. That is
   the recommendation; confirm, or name the account roles to require.
2. `--force` and 0700 parent directories deliberately differ from
   `secrets export`. Confirm, or ask for exact parity (overwrite in place,
   0755).
