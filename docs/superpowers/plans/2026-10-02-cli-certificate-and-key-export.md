# CLI Certificate and Key Export Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add `rocketvault certificates export <id>` and `rocketvault keys export <id>`, consistent with `rocketvault secrets export` (same output flags, passphrase sources, envelope, 0600 file, plaintext warning), plus an offline `rocketvault export open <file>`, while keeping every rule of the HTTP export: the exporter data actions with the explicit-deny override, fixed error text, one structured audit event per attempt, and no material or password in any output.

**Architecture:** Two shared helpers land first. `common` gains a sealed item payload (`SealItemExport`/`OpenItemExport`, wrapping the existing `SealExport` envelope) and an atomic, no-clobber, 0600 file writer (`WritePrivateFile`). A new `internal/services/exportaudit` package takes over the HTTP handlers' error classification and audit-event construction, and `api/export.go` delegates to it with identical behavior. `cmd/vaultcli/export.go` adds `ExportAttempt` (one audit event per CLI attempt, `Source: "cli"`) and `ExportOutput` (the shared `--file`/`--encrypt`/`--passphrase-file`/`--force` flags, passphrase resolution, sealing, the warning and the status block). The two commands are thin `RunE`s over those, built with `vaultcli.Caller` then `Session.Authorize`. `export open` lives in package `cmd`, replaces the root pre-run with a no-op (as `cmd/mcp.go` does) and is exempted from `initConfig`'s missing-config panic.

**Tech Stack:** Go 1.25 (`go.mod`), Cobra v1.9.1, testify, `golang.org/x/crypto/argon2` (already used by `common/export_envelope.go`), OpenSSL 3 (manual smoke test only), golangci-lint under the cached go1.25.7 toolchain.

**Spec:** `docs/superpowers/specs/2026-10-02-cli-certificate-and-key-export-design.md` (intent: `docs/superpowers/intents/2026-10-02-cli-certificate-and-key-export.md`). It amends the CLI non-goal of `docs/superpowers/specs/2026-10-01-certificate-and-key-export-design.md`.

## Global Constraints

Binding requirements from the spec, one per line:

- `certificates export <id>` and `keys export <id>`; `--file/-o` required; `--encrypt/-e` default true; `--passphrase-file`; `--force`; certificates also `--format/-f pem|pkcs12` (default pem), `--compat modern|legacy`, `--version N`, `--pkcs12-password-file`, `--pkcs12-empty-password`; keys also `--version N`; `--vault` is the inherited root flag.
- Sealed by default with the existing `common.SealExport` envelope. Passphrase order: `--passphrase-file`, then `ROCKETVAULT_EXPORT_PASSPHRASE`, then a terminal prompt asked twice. No passphrase means failure and no file. `--passphrase-file` with `--encrypt=false` is refused.
- The sealed plaintext is `common.ItemExportPayload`, whose `content` is exactly the file `--encrypt=false` writes.
- `--encrypt=false` prints one stderr warning line before writing.
- Files are written through `common.WritePrivateFile`: temporary file in the same directory, mode 0600, sync, then `os.Link` (no overwrite, no symlink follow) or, with `--force`, `os.Rename`; parent directories 0700; no partial or temporary file ever survives.
- `--file -` is refused. Stdout carries only the status block; no key, certificate body, passphrase or PKCS12 password reaches stdout, stderr, a log, an error or an audit event.
- PKCS12 password: `--pkcs12-empty-password`, then `--pkcs12-password-file`, then `ROCKETVAULT_PKCS12_PASSWORD`, then a double prompt; never a flag value; empty only via `--pkcs12-empty-password`.
- Authorization: `vaultcli.Caller` then `Session.Authorize`, with `model.ActionCertificatesExportItem` or `model.ActionKeysExport` and `model.OpCreate`; no `Op.Roles`. Validation before authorization; prompts and the service call after it.
- Audit: exactly one `AuditService.RecordEvent` per attempt that passed `Caller`, built by `exportaudit.Event` with `Source: "cli"`; fixed reasons only; raw ids and formats reach the event only when valid.
- Service errors are shown only as `exportaudit.Classify`'s fixed message; internal causes go to the log file only.
- Every failure exits 1 through the existing `cmd.run`.
- `export open` needs no session, database, config file or server, and is not audited.
- Remote mode is out of scope; the existing guard keeps refusing both commands.
- Export is never an MCP tool.

Regression safety (binding):

- No change to `internal/services/certificates`, `internal/services/keys`, `internal/middleware`, `internal/db`, `model`, `api/keys_export.go`, `cmd/secrets`, `internal/mcpserver`, `internal/vaultapi` or `internal/cliclient`.
- `api/export.go` changes only three function bodies, and every pre-existing `api` test passes unmodified.
- No pre-existing test file is modified or deleted; new tests live in new files.
- `cmd/root.go` changes only by help text and one added condition in `initConfig`; `cmd/certificates.go` and `cmd/keys.go` only by one registration line each and help text.
- Hard gates: `go build ./...`, `go vet ./...`, `go test -p 2 ./... -count=1`, and golangci-lint (go1.25.7) with `--new-from-rev="$BASE"`, all clean.

Repository conventions for this plan:

- **Lint base.** Before Task 1, record the starting commit once: `git rev-parse HEAD > .git/rv-cli-export-base`. Every later step reads it with `BASE=$(cat .git/rv-cli-export-base)`. The file lives inside `.git`, so it is never committed.
- **Lint command.** `PATH="$HOME/go/pkg/mod/golang.org/toolchain@v0.0.1-go1.25.7.linux-amd64/bin:$PATH" GOTOOLCHAIN=local ~/go/bin/golangci-lint run --new-from-rev="$BASE" <packages>`. It must print `0 issues.`.
- **mockery.** No interface changes in this plan, so mockery is not run. If a task ever needs it, regenerate from the repo root with `PATH="$HOME/go/pkg/mod/golang.org/toolchain@v0.0.1-go1.25.7.linux-amd64/bin:$PATH" GOTOOLCHAIN=local ~/go/bin/mockery`, and never run `~/go/bin/mockery --version` (it starts a full generation run).
- **Tests** run with `-p 2`; if the sandbox hits `newosproc`, prefix `GOMAXPROCS=1`.
- **Commits** go through the `dev-workflow-skills:1-git-commit` plugin skill (Skill tool), never a freeform `git commit -m`, and are GPG signed (key 61D246B30285ED35).
- **Comments** are short full sentences ending with a punctuation mark. No emojis.
- **Package `cmd` tests never call `Execute` on a standalone command.** `cmd/root.go`'s `init` registers `cobra.OnInitialize(initConfig)` process-wide, and `initConfig` panics when no `.rocketvault.yaml` is found (see `cmd/rotation_test.go:163-170`). Standalone tests call `RunE` directly; end-to-end tests go through `rootCmd` from a temporary directory.
- **`testutils.MockServiceContainer.GetAuditService` is a testify call.** Any test that runs an export command must stub it: `tc.MockContainer.On("GetAuditService").Return(<recorder>)`.

## Review Focus

1. **Key material or a password reaching stdout, stderr, a log or an audit event.** Pins: `TestCertExport_NoMaterialOrSecretInAnyOutput`, `TestCertExport_PKCS12PasswordSources`, `TestKeyExport_NoMaterialOrSecretInAnyOutput`, `TestExportAttempt_FailServiceShowsOnlyFixedText` (Tasks 4-6).
2. **An unauthorized caller reaching a prompt or the service, or the explicit deny being skipped.** Pins: `TestCertExport_DeniedWithoutTheExportAction`, `TestCertExport_ExplicitDenyOverridesARoleGrant`, `TestCertExport_ChecksTheExportActionAndCreatePolicy` and the key equivalents (Tasks 5, 6).
3. **A partial file, a clobbered file or a followed symlink.** Pins: `TestWritePrivateFile_*` (Task 1), `TestCertExport_NeverReplacesAFileWithoutForce`, `TestKeyExport_NeverReplacesAFileWithoutForce`.
4. **The `api/export.go` refactor changing a status, code, reason or event field.** Pin: every pre-existing test in `api/export_test.go`, `api/keys_export_test.go` and `api/export_chain_test.go`, unmodified, plus `TestExportStatus_MapsEveryKind` (Task 3).
5. **`export open` exemptions leaking to other commands.** `isExportGroupArgs` and the group's no-op pre-run must never match `secrets export`, `certificates export` or `keys export`. Pins: `TestIsExportGroupArgs`, `TestItemExportCommands_RemoteModeIsRefused` (Task 7).

---

## File Structure

| File | Responsibility |
|---|---|
| `common/item_export.go` (create) | `ExportPassphraseEnvVar`, item kinds, `ItemExportPayload`, `SealItemExport`, `OpenItemExport`, `ErrNotItemExport` |
| `common/private_file.go` (create) | `WritePrivateFile`, `ErrOutputExists` |
| `common/passphrase.go` (modify) | additive `PassphraseSource.ConfirmPrompt` |
| `internal/services/exportaudit/exportaudit.go` (create) | `Kind`, `Failure`, `Classify`, `BadRequest`, `Internal`, `Forbidden`, `AuditableFormat`, `Attempt`, `Event`, `Record` |
| `api/export.go` (modify) | `exportFailureFor`, `auditableExportFormat` and `recordExportAudit` delegate to `exportaudit`; new `exportStatus` |
| `cmd/vaultcli/export.go` (create) | `ExportAttempt`, `BeginExportAttempt`, `ExportOutput`, `AddExportOutputFlags`, `ReadExportOutput` |
| `cmd/certificates/export.go` (create) | `certificates export` |
| `cmd/keys/export.go` (create) | `keys export` |
| `cmd/export.go` (create) | `export` group, `export open`, `isExportGroupArgs` |
| `cmd/certificates.go`, `cmd/keys.go`, `cmd/root.go` (modify) | registration, help text, the `initConfig` condition |
| `docs/cli-guide.md`, `README.md`, `CLAUDE.md`, `.claude/azure-keyvault-parity.md`, `docs/mcp-server.md`, the 2026-10-01 and 2026-10-02 specs (modify) | documentation |
| Tests (create): `common/item_export_test.go`, `common/private_file_test.go`, `internal/services/exportaudit/exportaudit_test.go`, `api/export_status_test.go`, `cmd/vaultcli/export_test.go`, `cmd/certificates/export_test.go`, `cmd/keys/export_test.go`, `cmd/export_test.go` | |

---

### Task 1: Sealed item payload, private file writer and the confirm prompt

**Files:**
- Create: `common/item_export.go`, `common/private_file.go`
- Modify: `common/passphrase.go`
- Test: `common/item_export_test.go`, `common/private_file_test.go` (create)

**Interfaces:**
- Consumes: `common.SealExport`, `common.OpenExport`, `common.ErrWrongPassphrase`, `common.ErrUnsupportedExportVersion`, `common.ErrPassphraseRequired`, `common.IsSealedExport` (all in `common/export_envelope.go`).
- Produces:
  - `const common.ExportPassphraseEnvVar = "ROCKETVAULT_EXPORT_PASSPHRASE"`
  - `const common.ItemExportKindCertificate = "certificate"`, `const common.ItemExportKindKey = "key"`
  - `type common.ItemExportPayload struct { PayloadVersion int; Kind, ID, Name string; Version int; Format, KeyAlgorithm string; Content []byte }`
  - `func common.SealItemExport(p ItemExportPayload, passphrase string) ([]byte, error)`
  - `func common.OpenItemExport(data []byte, passphrase string) (*ItemExportPayload, error)`
  - `var common.ErrNotItemExport`
  - `func common.WritePrivateFile(path string, data []byte, overwrite bool) error`, `var common.ErrOutputExists`
  - `common.PassphraseSource.ConfirmPrompt string`

- [ ] **Step 0: Record the lint base (once, before any change)**

Run: `git rev-parse HEAD > .git/rv-cli-export-base && cat .git/rv-cli-export-base`
Expected: one commit hash. Skip this step if the file already exists.

- [ ] **Step 1: Write the failing tests**

Create `common/item_export_test.go`:

```go
package common

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestItemExport_SealAndOpenRoundTrip(t *testing.T) {
	content := []byte("-----BEGIN CERTIFICATE-----\nLEAF\n-----END CERTIFICATE-----\n" +
		"-----BEGIN PRIVATE KEY-----\nKEY-MATERIAL\n-----END PRIVATE KEY-----\n")
	sealed, err := SealItemExport(ItemExportPayload{
		Kind: ItemExportKindCertificate, ID: "id-1", Name: "client", Version: 2,
		Format: "pem", KeyAlgorithm: "RSA-2048", Content: content,
	}, "correct horse")
	require.NoError(t, err)
	assert.True(t, IsSealedExport(sealed))
	assert.NotContains(t, string(sealed), "KEY-MATERIAL")
	assert.NotContains(t, string(sealed), "client")

	got, err := OpenItemExport(sealed, "correct horse")
	require.NoError(t, err)
	assert.Equal(t, 1, got.PayloadVersion)
	assert.Equal(t, ItemExportKindCertificate, got.Kind)
	assert.Equal(t, "id-1", got.ID)
	assert.Equal(t, "client", got.Name)
	assert.Equal(t, 2, got.Version)
	assert.Equal(t, "pem", got.Format)
	assert.Equal(t, "RSA-2048", got.KeyAlgorithm)
	assert.Equal(t, content, got.Content)
}

func TestItemExport_WrongPassphrase(t *testing.T) {
	sealed, err := SealItemExport(ItemExportPayload{Kind: ItemExportKindKey, Content: []byte("k")}, "right")
	require.NoError(t, err)
	_, err = OpenItemExport(sealed, "wrong")
	assert.ErrorIs(t, err, ErrWrongPassphrase)
}

func TestItemExport_RefusesOtherSealedPayloads(t *testing.T) {
	for name, plain := range map[string]string{
		"secrets json":          `[{"name":"db","value":"x"}]`,
		"secrets csv":           "name,value\ndb,x\n",
		"object without marker": `{"kind":"key","content":"eA=="}`,
		"unknown kind":          `{"rocketvault_item_export":1,"kind":"secret"}`,
	} {
		sealed, err := SealExport([]byte(plain), "p")
		require.NoError(t, err)
		_, err = OpenItemExport(sealed, "p")
		assert.ErrorIs(t, err, ErrNotItemExport, name)
	}
}

func TestItemExport_RefusesANewerPayloadVersion(t *testing.T) {
	sealed, err := SealExport([]byte(`{"rocketvault_item_export":2,"kind":"key"}`), "p")
	require.NoError(t, err)
	_, err = OpenItemExport(sealed, "p")
	assert.ErrorIs(t, err, ErrUnsupportedExportVersion)
}

func TestSealItemExport_RefusesUnknownKindAndEmptyPassphrase(t *testing.T) {
	_, err := SealItemExport(ItemExportPayload{Kind: "secret"}, "p")
	assert.EqualError(t, err, `unknown item export kind "secret"`)
	_, err = SealItemExport(ItemExportPayload{Kind: ItemExportKindKey}, "")
	assert.ErrorIs(t, err, ErrPassphraseRequired)
}
```

Create `common/private_file_test.go`:

```go
package common

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// assertNoTempFiles fails if WritePrivateFile left a temporary file in dir.
func assertNoTempFiles(t *testing.T, dir string) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	for _, e := range entries {
		assert.False(t, strings.HasPrefix(e.Name(), ".rocketvault-export-"), "temporary file left behind: %s", e.Name())
	}
}

func TestWritePrivateFile_CreatesFileAndDirectoriesPrivately(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nested", "out.pem")
	require.NoError(t, WritePrivateFile(path, []byte("data"), false))

	got, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.Equal(t, "data", string(got))
	info, err := os.Stat(path)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o600), info.Mode().Perm())
	dirInfo, err := os.Stat(filepath.Dir(path))
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o700), dirInfo.Mode().Perm())
	assertNoTempFiles(t, filepath.Dir(path))
}

func TestWritePrivateFile_NeverReplacesWithoutOverwrite(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "out.pem")
	require.NoError(t, os.WriteFile(path, []byte("original"), 0o644))

	assert.ErrorIs(t, WritePrivateFile(path, []byte("new"), false), ErrOutputExists)
	got, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.Equal(t, "original", string(got))
	assertNoTempFiles(t, dir)
}

func TestWritePrivateFile_OverwriteReplacesAndTightensTheMode(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "out.pem")
	require.NoError(t, os.WriteFile(path, []byte("original"), 0o644))

	require.NoError(t, WritePrivateFile(path, []byte("new"), true))
	got, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.Equal(t, "new", string(got))
	info, err := os.Stat(path)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o600), info.Mode().Perm())
	assertNoTempFiles(t, dir)
}

func TestWritePrivateFile_NeverFollowsASymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	require.NoError(t, os.WriteFile(target, []byte("keep"), 0o600))
	link := filepath.Join(dir, "link.pem")
	require.NoError(t, os.Symlink(target, link))

	assert.ErrorIs(t, WritePrivateFile(link, []byte("new"), false), ErrOutputExists)
	got, err := os.ReadFile(target)
	require.NoError(t, err)
	assert.Equal(t, "keep", string(got))
}

func TestWritePrivateFile_FailureLeavesNothingBehind(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root ignores directory permissions")
	}
	locked := filepath.Join(t.TempDir(), "locked")
	require.NoError(t, os.Mkdir(locked, 0o500))
	t.Cleanup(func() { _ = os.Chmod(locked, 0o700) })

	require.Error(t, WritePrivateFile(filepath.Join(locked, "out.pem"), []byte("data"), false))
	entries, err := os.ReadDir(locked)
	require.NoError(t, err)
	assert.Empty(t, entries)
}
```

- [ ] **Step 2: Run and expect FAIL**

Run: `go test -p 2 ./common -run 'ItemExport|WritePrivateFile' -count=1`
Expected: FAIL with a build error naming `undefined: SealItemExport`, `undefined: ItemExportPayload` and `undefined: WritePrivateFile`.

- [ ] **Step 3: Implement**

Create `common/item_export.go`:

```go
package common

import (
	"encoding/json"
	"errors"
	"fmt"
)

// ExportPassphraseEnvVar names the environment variable that supplies an
// export passphrase without a terminal. "secrets export" and "secrets
// import" read the same variable through their own constant.
const ExportPassphraseEnvVar = "ROCKETVAULT_EXPORT_PASSPHRASE"

// Item export kinds, as written into a sealed item export.
const (
	ItemExportKindCertificate = "certificate"
	ItemExportKindKey         = "key"
)

// itemExportPayloadVersion marks and versions a sealed item payload. Readers
// refuse a version they do not know rather than misparse it.
const itemExportPayloadVersion = 1

// ErrNotItemExport is returned when a sealed file opens but does not hold a
// certificate or key export, for example a sealed "secrets export" file.
var ErrNotItemExport = errors.New("not a RocketVault certificate or key export")

// ItemExportPayload is the plaintext a certificate or key export seals.
// Content is exactly the file the same export writes with --encrypt=false,
// so opening a sealed export yields that file byte for byte. It carries
// private material and must never be logged.
type ItemExportPayload struct {
	PayloadVersion int    `json:"rocketvault_item_export"`
	Kind           string `json:"kind"`
	ID             string `json:"id"`
	Name           string `json:"name"`
	Version        int    `json:"version"`
	Format         string `json:"format"`
	KeyAlgorithm   string `json:"key_algorithm"`
	Content        []byte `json:"content"`
}

// SealItemExport seals p under passphrase in the envelope SealExport writes.
// It sets the payload version itself.
func SealItemExport(p ItemExportPayload, passphrase string) ([]byte, error) {
	if p.Kind != ItemExportKindCertificate && p.Kind != ItemExportKindKey {
		return nil, fmt.Errorf("unknown item export kind %q", p.Kind)
	}
	p.PayloadVersion = itemExportPayloadVersion
	plain, err := json.Marshal(p)
	if err != nil {
		return nil, fmt.Errorf("failed to encode export payload: %w", err)
	}
	defer clear(plain)
	return SealExport(plain, passphrase)
}

// OpenItemExport reverses SealItemExport. A wrong passphrase returns
// ErrWrongPassphrase, and an envelope that holds anything other than a
// certificate or key export returns ErrNotItemExport.
func OpenItemExport(data []byte, passphrase string) (*ItemExportPayload, error) {
	plain, err := OpenExport(data, passphrase)
	if err != nil {
		return nil, err
	}
	defer clear(plain)

	var p ItemExportPayload
	if err := json.Unmarshal(plain, &p); err != nil {
		return nil, ErrNotItemExport
	}
	switch {
	case p.PayloadVersion == 0:
		return nil, ErrNotItemExport
	case p.PayloadVersion != itemExportPayloadVersion:
		return nil, fmt.Errorf("%w: item payload %d", ErrUnsupportedExportVersion, p.PayloadVersion)
	case p.Kind != ItemExportKindCertificate && p.Kind != ItemExportKindKey:
		return nil, ErrNotItemExport
	}
	return &p, nil
}
```

Create `common/private_file.go`:

```go
package common

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
)

// ErrOutputExists is returned by WritePrivateFile when something already
// exists at the path and overwrite is false.
var ErrOutputExists = errors.New("output file already exists")

// privateFileTempPattern names the temporary file WritePrivateFile writes
// next to its target.
const privateFileTempPattern = ".rocketvault-export-*"

// WritePrivateFile writes data to path with mode 0600, so that path either
// ends up holding all of data or is left as it was. It writes a temporary
// file in the same directory, syncs it and moves it into place. Without
// overwrite, an existing path is never replaced and a symlink is never
// followed, even if the path appears after the caller checked. With
// overwrite, the path itself is replaced. Missing parent directories are
// created with mode 0700.
func WritePrivateFile(path string, data []byte, overwrite bool) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("failed to create output directory: %w", err)
	}
	tmp, err := os.CreateTemp(dir, privateFileTempPattern)
	if err != nil {
		return fmt.Errorf("failed to create temporary file: %w", err)
	}
	tmpName := tmp.Name()
	// The temporary name never survives: on success it was renamed away or
	// is a second link to the output, and on failure it may be partial.
	defer func() { _ = os.Remove(tmpName) }()

	if err := writeAndSync(tmp, data); err != nil {
		return err
	}
	if overwrite {
		if err := os.Rename(tmpName, path); err != nil {
			return fmt.Errorf("failed to move the export file into place: %w", err)
		}
		return nil
	}
	if err := os.Link(tmpName, path); err != nil {
		if errors.Is(err, fs.ErrExist) {
			return ErrOutputExists
		}
		return fmt.Errorf("failed to move the export file into place: %w", err)
	}
	return nil
}

// writeAndSync sets f to mode 0600, writes data, syncs and closes it.
func writeAndSync(f *os.File, data []byte) error {
	if err := f.Chmod(0o600); err != nil {
		_ = f.Close()
		return fmt.Errorf("failed to set the export file mode: %w", err)
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return fmt.Errorf("failed to write the export file: %w", err)
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return fmt.Errorf("failed to write the export file: %w", err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("failed to write the export file: %w", err)
	}
	return nil
}
```

In `common/passphrase.go`, replace the struct

```go
type PassphraseSource struct {
	File    string
	EnvVar  string
	Prompt  string
	Confirm bool
}
```

with

```go
type PassphraseSource struct {
	File    string
	EnvVar  string
	Prompt  string
	Confirm bool
	// ConfirmPrompt is the second prompt when Confirm is set. Empty means
	// "Confirm passphrase: ".
	ConfirmPrompt string
}
```

and in `promptPassphrase` replace

```go
	if src.Confirm {
		fmt.Fprint(os.Stderr, "Confirm passphrase: ") //nolint:errcheck
```

with

```go
	if src.Confirm {
		confirmPrompt := src.ConfirmPrompt
		if confirmPrompt == "" {
			confirmPrompt = "Confirm passphrase: "
		}
		fmt.Fprint(os.Stderr, confirmPrompt) //nolint:errcheck
```

- [ ] **Step 4: Run and expect PASS**

Run: `go test -p 2 ./common -count=1`
Expected: `ok  	rocketvault/common`. The pre-existing passphrase and envelope tests pass unchanged. (`TestWritePrivateFile_FailureLeavesNothingBehind` skips when run as root.)

- [ ] **Step 5: Lint**

Run: `BASE=$(cat .git/rv-cli-export-base); PATH="$HOME/go/pkg/mod/golang.org/toolchain@v0.0.1-go1.25.7.linux-amd64/bin:$PATH" GOTOOLCHAIN=local ~/go/bin/golangci-lint run --new-from-rev="$BASE" ./common/...`
Expected: `0 issues.`

- [ ] **Step 6: Commit**

Commit via the `dev-workflow-skills:1-git-commit` skill. Stage: `common/item_export.go`, `common/item_export_test.go`, `common/private_file.go`, `common/private_file_test.go`, `common/passphrase.go`.

---

### Task 2: The `exportaudit` package

**Files:**
- Create: `internal/services/exportaudit/exportaudit.go`
- Test: `internal/services/exportaudit/exportaudit_test.go` (create)

**Interfaces:**
- Consumes: `model.ExportRefusedError`, `model.ErrInvalidExportRequest`, `model.ErrCertificateVersionNotFound`, `model.ErrKeyVersionNotFound`, `model.ExportFormatPEM`, `model.ExportFormatPKCS12`; `certificates.ErrCertNotFound`, `certificates.ErrCertLifecycleDenied`, `certificates.ErrCertificateChainUnavailable`, `certificates.ErrCertVersioningUnavailable`; `keys.ErrKeyNotFound`, `keys.ErrKeyLifecycleDenied`; `audit.AuditEvent`, `audit.AuditServiceInterface`.
- Produces:
  - `type exportaudit.Kind int` with `KindBadRequest`, `KindForbidden`, `KindNotExportable`, `KindNotFound`, `KindDisabled`, `KindInternal`
  - `type exportaudit.Failure struct { Kind Kind; Code, Message, Reason, Name, KeyAlgorithm string }`
  - `func Classify(err error, resource string) Failure`, `func BadRequest(message string) Failure`, `func Internal(reason string) Failure`, `func Forbidden(reason string) Failure`, `func AuditableFormat(format string) string`
  - `type exportaudit.Attempt struct { UserID, ResourceType, ResourceID, VaultID, Name string; Version int; Format, Outcome, Code, Reason, IPAddress, Source string }`
  - `func Event(a Attempt) audit.AuditEvent`, `func Record(ctx context.Context, svc audit.AuditServiceInterface, a Attempt)`

`Classify` is `api.exportFailureFor` (`api/export.go:98-127`) without the HTTP status and the 500 cause; `Event` builds exactly the event `api.recordExportAudit` (`api/export.go:190-211`) builds. Task 3 makes `api` delegate to them.

- [ ] **Step 1: Write the failing tests**

Create `internal/services/exportaudit/exportaudit_test.go`:

```go
package exportaudit_test

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	auditServices "rocketvault/internal/services/audit"
	certServices "rocketvault/internal/services/certificates"
	"rocketvault/internal/services/exportaudit"
	keyServices "rocketvault/internal/services/keys"
	"rocketvault/model"
)

func TestClassify_MapsEveryServiceErrorToAFixedReason(t *testing.T) {
	cases := []struct {
		name     string
		err      error
		resource string
		kind     exportaudit.Kind
		code     string
		message  string
		reason   string
	}{
		{"certificate refusal", &model.ExportRefusedError{Sentinel: model.ErrCertificateNotExportable, Reason: "flag is false", Name: "client", KeyAlgorithm: "RSA-2048"},
			"certificate", exportaudit.KindNotExportable, "certificate_not_exportable", "certificate is not exportable: flag is false", "flag is false"},
		{"key refusal", &model.ExportRefusedError{Sentinel: model.ErrKeyNotExportable, Reason: "HSM-backed keys never leave the token"},
			"key", exportaudit.KindNotExportable, "key_not_exportable", "key is not exportable: HSM-backed keys never leave the token", "HSM-backed keys never leave the token"},
		{"invalid request", fmt.Errorf("%w: format must be pem or pkcs12", model.ErrInvalidExportRequest),
			"certificate", exportaudit.KindBadRequest, "bad_request", "invalid export request: format must be pem or pkcs12", "invalid export request"},
		{"certificate not found", fmt.Errorf("%w: sql: raw-detail", certServices.ErrCertNotFound),
			"certificate", exportaudit.KindNotFound, "not_found", "certificate or version not found", "certificate or version not found"},
		{"certificate version not found", fmt.Errorf("%w: raw-detail", model.ErrCertificateVersionNotFound),
			"certificate", exportaudit.KindNotFound, "not_found", "certificate or version not found", "certificate or version not found"},
		{"key not found", fmt.Errorf("%w: raw-detail", keyServices.ErrKeyNotFound),
			"key", exportaudit.KindNotFound, "not_found", "key or version not found", "key or version not found"},
		{"key version not found", fmt.Errorf("%w: raw-detail", model.ErrKeyVersionNotFound),
			"key", exportaudit.KindNotFound, "not_found", "key or version not found", "key or version not found"},
		{"certificate disabled", certServices.ErrCertLifecycleDenied,
			"certificate", exportaudit.KindDisabled, "certificate_disabled", "the certificate or this version is disabled or outside its valid time window", "certificate or version disabled"},
		{"key disabled", fmt.Errorf("%w", keyServices.ErrKeyLifecycleDenied),
			"key", exportaudit.KindDisabled, "key_disabled", "the key is disabled or outside its valid time window", "key disabled"},
		{"chain unavailable", fmt.Errorf("%w: issuer raw-detail", certServices.ErrCertificateChainUnavailable),
			"certificate", exportaudit.KindInternal, "internal_error", "internal server error", "certificate chain unavailable"},
		{"versioning unavailable", certServices.ErrCertVersioningUnavailable,
			"certificate", exportaudit.KindInternal, "internal_error", "internal server error", "certificate versioning unavailable"},
		{"unknown", errors.New("decrypt certificate key: raw-detail"),
			"certificate", exportaudit.KindInternal, "internal_error", "internal server error", "internal failure"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := exportaudit.Classify(c.err, c.resource)
			assert.Equal(t, c.kind, f.Kind)
			assert.Equal(t, c.code, f.Code)
			assert.Equal(t, c.message, f.Message)
			assert.Equal(t, c.reason, f.Reason)
			assert.NotContains(t, f.Message+f.Reason, "raw-detail")
		})
	}

	refusal := exportaudit.Classify(cases[0].err, "certificate")
	assert.Equal(t, "client", refusal.Name)
	assert.Equal(t, "RSA-2048", refusal.KeyAlgorithm)
}

func TestConstructors(t *testing.T) {
	assert.Equal(t, exportaudit.Failure{Kind: exportaudit.KindBadRequest, Code: "bad_request", Message: "m", Reason: "m"}, exportaudit.BadRequest("m"))
	assert.Equal(t, exportaudit.Failure{Kind: exportaudit.KindInternal, Code: "internal_error", Message: "internal server error", Reason: "r"}, exportaudit.Internal("r"))
	assert.Equal(t, exportaudit.Failure{Kind: exportaudit.KindForbidden, Code: "forbidden", Message: "r", Reason: "r"}, exportaudit.Forbidden("r"))
}

func TestAuditableFormat(t *testing.T) {
	assert.Equal(t, "pem", exportaudit.AuditableFormat("pem"))
	assert.Equal(t, "pkcs12", exportaudit.AuditableFormat("pkcs12"))
	for _, raw := range []string{"", "PEM", "der", "hunter2"} {
		assert.Equal(t, "invalid", exportaudit.AuditableFormat(raw), raw)
	}
}

func TestEvent_CarriesOnlyFixedFields(t *testing.T) {
	ev := exportaudit.Event(exportaudit.Attempt{
		UserID: "u1", ResourceType: "certificate", ResourceID: "c1", VaultID: "v1", Name: "client", Version: 2,
		Format: "pem", Outcome: "failure", Code: "certificate_not_exportable", Reason: "flag is false",
		IPAddress: "10.0.0.1", Source: "cli",
	})
	assert.Equal(t, auditServices.AuditEvent{
		UserID:       "u1",
		Action:       "export_certificate",
		Details:      `{"code":"certificate_not_exportable","format":"pem","name":"client","reason":"flag is false","vault_id":"v1","version":2}`,
		ResourceType: "certificate",
		ResourceID:   "c1",
		IPAddress:    "10.0.0.1",
		Outcome:      "failure",
		Source:       "cli",
	}, ev)
}

// recorder captures audit events.
type recorder struct{ events []auditServices.AuditEvent }

func (r *recorder) RecordEvent(_ context.Context, e auditServices.AuditEvent) error {
	r.events = append(r.events, e)
	return nil
}

func (r *recorder) PersistAudit(string, string, string) error { return nil }

func TestRecord_WritesOneEventAndToleratesANilService(t *testing.T) {
	exportaudit.Record(context.Background(), nil, exportaudit.Attempt{ResourceType: "key"})

	rec := &recorder{}
	exportaudit.Record(context.Background(), rec, exportaudit.Attempt{ResourceType: "key", Outcome: "success", Source: "cli"})
	require.Len(t, rec.events, 1)
	assert.Equal(t, "export_key", rec.events[0].Action)
	assert.Equal(t, "success", rec.events[0].Outcome)
}
```

- [ ] **Step 2: Run and expect FAIL**

Run: `go test -p 2 ./internal/services/exportaudit -count=1`
Expected: FAIL: `no non-test Go files` or a build error naming `undefined: exportaudit.Classify`.

- [ ] **Step 3: Implement**

Create `internal/services/exportaudit/exportaudit.go`:

```go
// Package exportaudit classifies certificate and key export failures and
// records one structured audit event per export attempt. The HTTP export
// handlers and the CLI export commands both use it, so the two entry points
// share one set of fixed messages and reasons and one event shape.
package exportaudit

import (
	"context"
	"encoding/json"
	"errors"

	auditServices "rocketvault/internal/services/audit"
	certServices "rocketvault/internal/services/certificates"
	keyServices "rocketvault/internal/services/keys"
	"rocketvault/model"
)

// Kind is the transport-neutral class of an export failure. The API maps it
// onto an HTTP status; the CLI uses it to decide what to show.
type Kind int

// Export failure kinds.
const (
	KindBadRequest Kind = iota + 1
	KindForbidden
	KindNotExportable
	KindNotFound
	KindDisabled
	KindInternal
)

// Failure is one classified export failure. Message is safe to show the
// caller. Reason is a fixed phrase for the audit trail and never carries raw
// error text. Name and KeyAlgorithm are set only on a refusal.
type Failure struct {
	Kind         Kind
	Code         string
	Message      string
	Reason       string
	Name         string
	KeyAlgorithm string
}

// BadRequest is the failure for malformed input. message must be a fixed
// phrase that never includes a password; it is both shown and audited.
func BadRequest(message string) Failure {
	return Failure{Kind: KindBadRequest, Code: "bad_request", Message: message, Reason: message}
}

// Internal is the generic internal failure. reason goes to the audit trail;
// the caller only ever sees the fixed message.
func Internal(reason string) Failure {
	return Failure{Kind: KindInternal, Code: "internal_error", Message: "internal server error", Reason: reason}
}

// Forbidden is the failure for an authorization denial on a path without
// PolicyMiddleware, such as the CLI. reason must be a fixed phrase.
func Forbidden(reason string) Failure {
	return Failure{Kind: KindForbidden, Code: "forbidden", Message: reason, Reason: reason}
}

// Classify maps a certificate or key service error onto a Failure. resource
// is "certificate" or "key". Unknown errors become a generic internal
// failure. A chain failure is also internal, because its error text names a
// CA id that may belong to another vault.
func Classify(err error, resource string) Failure {
	var refusal *model.ExportRefusedError
	switch {
	case errors.As(err, &refusal):
		return Failure{Kind: KindNotExportable, Code: resource + "_not_exportable", Message: refusal.Error(),
			Reason: refusal.Reason, Name: refusal.Name, KeyAlgorithm: refusal.KeyAlgorithm}
	case errors.Is(err, model.ErrInvalidExportRequest):
		f := BadRequest(err.Error())
		f.Reason = "invalid export request"
		return f
	case errors.Is(err, certServices.ErrCertNotFound), errors.Is(err, model.ErrCertificateVersionNotFound):
		return Failure{Kind: KindNotFound, Code: "not_found", Message: "certificate or version not found",
			Reason: "certificate or version not found"}
	case errors.Is(err, keyServices.ErrKeyNotFound), errors.Is(err, model.ErrKeyVersionNotFound):
		return Failure{Kind: KindNotFound, Code: "not_found", Message: "key or version not found",
			Reason: "key or version not found"}
	case errors.Is(err, certServices.ErrCertLifecycleDenied):
		return Failure{Kind: KindDisabled, Code: "certificate_disabled",
			Message: "the certificate or this version is disabled or outside its valid time window",
			Reason:  "certificate or version disabled"}
	case errors.Is(err, keyServices.ErrKeyLifecycleDenied):
		return Failure{Kind: KindDisabled, Code: "key_disabled",
			Message: "the key is disabled or outside its valid time window", Reason: "key disabled"}
	case errors.Is(err, certServices.ErrCertificateChainUnavailable):
		return Internal("certificate chain unavailable")
	case errors.Is(err, certServices.ErrCertVersioningUnavailable):
		return Internal("certificate versioning unavailable")
	}
	return Internal("internal failure")
}

// AuditableFormat returns format when it is a known export format and
// "invalid" otherwise, so arbitrary caller text never reaches the audit trail.
func AuditableFormat(format string) string {
	switch format {
	case model.ExportFormatPEM, model.ExportFormatPKCS12:
		return format
	}
	return "invalid"
}

// Attempt is one export attempt as the audit trail records it. It holds no
// material and no password by construction. Reason is a fixed phrase from a
// Failure, never raw error text.
type Attempt struct {
	UserID       string
	ResourceType string // "certificate" or "key".
	ResourceID   string
	VaultID      string
	Name         string
	Version      int
	Format       string
	Outcome      string // "success" or "failure".
	Code         string
	Reason       string
	IPAddress    string
	Source       string // "api" or "cli".
}

// Event builds the audit event for a. Details carries only the fixed fields
// vault_id, name, version, format, code and reason.
func Event(a Attempt) auditServices.AuditEvent {
	details, _ := json.Marshal(map[string]any{
		"vault_id": a.VaultID, "name": a.Name, "version": a.Version, "format": a.Format, "code": a.Code, "reason": a.Reason,
	})
	return auditServices.AuditEvent{
		UserID:       a.UserID,
		Action:       "export_" + a.ResourceType,
		Details:      string(details),
		ResourceType: a.ResourceType,
		ResourceID:   a.ResourceID,
		IPAddress:    a.IPAddress,
		Outcome:      a.Outcome,
		Source:       a.Source,
	}
}

// Record writes one audit event for a. A nil service is tolerated, and an
// audit failure never blocks the caller.
func Record(ctx context.Context, svc auditServices.AuditServiceInterface, a Attempt) {
	if svc == nil {
		return
	}
	_ = svc.RecordEvent(ctx, Event(a))
}
```

- [ ] **Step 4: Run and expect PASS**

Run: `go vet ./internal/services/exportaudit && go test -p 2 ./internal/services/exportaudit -count=1`
Expected: `ok  	rocketvault/internal/services/exportaudit`.

- [ ] **Step 5: Lint**

Run: `BASE=$(cat .git/rv-cli-export-base); PATH="$HOME/go/pkg/mod/golang.org/toolchain@v0.0.1-go1.25.7.linux-amd64/bin:$PATH" GOTOOLCHAIN=local ~/go/bin/golangci-lint run --new-from-rev="$BASE" ./internal/services/exportaudit/...`
Expected: `0 issues.`

- [ ] **Step 6: Commit**

Commit via the `dev-workflow-skills:1-git-commit` skill. Stage: `internal/services/exportaudit/exportaudit.go`, `internal/services/exportaudit/exportaudit_test.go`.

---

### Task 3: `api/export.go` delegates to `exportaudit`

**Files:**
- Modify: `api/export.go`
- Test: `api/export_status_test.go` (create); every pre-existing `api` test, unmodified

**Interfaces:**
- Consumes: Task 2's `exportaudit.Classify`, `exportaudit.Kind*`, `exportaudit.AuditableFormat`, `exportaudit.Attempt`, `exportaudit.Record`.
- Produces: `func exportStatus(kind exportaudit.Kind) int` (package `api`, unexported). Every existing `api` symbol keeps its signature.

- [ ] **Step 1: Write the failing test**

Create `api/export_status_test.go`:

```go
package api

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"

	"rocketvault/internal/services/exportaudit"
)

// TestExportStatus_MapsEveryKind pins the HTTP status of every export
// failure kind, now that the classification lives in exportaudit.
func TestExportStatus_MapsEveryKind(t *testing.T) {
	for kind, want := range map[exportaudit.Kind]int{
		exportaudit.KindBadRequest:    http.StatusBadRequest,
		exportaudit.KindForbidden:     http.StatusForbidden,
		exportaudit.KindNotExportable: http.StatusForbidden,
		exportaudit.KindNotFound:      http.StatusNotFound,
		exportaudit.KindDisabled:      http.StatusConflict,
		exportaudit.KindInternal:      http.StatusInternalServerError,
	} {
		assert.Equal(t, want, exportStatus(kind), "kind %d", kind)
	}
}
```

- [ ] **Step 2: Run and expect FAIL**

Run: `go test -p 2 ./api -run TestExportStatus_MapsEveryKind -count=1`
Expected: FAIL with a build error naming `undefined: exportStatus`.

- [ ] **Step 3: Implement**

In `api/export.go`, replace the import block's

```go
	"rocketvault/internal/container"
	"rocketvault/internal/middleware"
	auditSvc "rocketvault/internal/services/audit"
	certServices "rocketvault/internal/services/certificates"
	keyservices "rocketvault/internal/services/keys"
	"rocketvault/model"
```

with

```go
	"rocketvault/internal/container"
	"rocketvault/internal/middleware"
	certServices "rocketvault/internal/services/certificates"
	"rocketvault/internal/services/exportaudit"
	"rocketvault/model"
```

Replace the whole `exportFailureFor` function and its doc comment (from `// exportFailureFor maps a certificate or key service error onto an export` down to the closing brace before `// decodeExportBody decodes`) with:

```go
// exportFailureFor maps a certificate or key service error onto an export
// failure. resource is "certificate" or "key". The classification, with its
// fixed messages and reasons, lives in exportaudit so the CLI export
// commands share it; this adds the HTTP status and keeps the cause of a 500
// for the server log.
func exportFailureFor(err error, resource string) exportFailure {
	f := exportaudit.Classify(err, resource)
	out := exportFailure{Status: exportStatus(f.Kind), Code: f.Code, Message: f.Message,
		KeyAlgorithm: f.KeyAlgorithm, Name: f.Name, Reason: f.Reason}
	if f.Kind == exportaudit.KindInternal {
		out.cause = err
	}
	return out
}

// exportStatus maps a classified export failure onto its HTTP status.
func exportStatus(kind exportaudit.Kind) int {
	switch kind {
	case exportaudit.KindBadRequest:
		return http.StatusBadRequest
	case exportaudit.KindForbidden, exportaudit.KindNotExportable:
		return http.StatusForbidden
	case exportaudit.KindNotFound:
		return http.StatusNotFound
	case exportaudit.KindDisabled:
		return http.StatusConflict
	default:
		return http.StatusInternalServerError
	}
}
```

Replace the body of `auditableExportFormat` so the function reads:

```go
func auditableExportFormat(format string) string {
	return exportaudit.AuditableFormat(format)
}
```

(keep its existing doc comment). Replace the whole `recordExportAudit` function and its doc comment (from `// recordExportAudit writes one structured audit event per export attempt.` down to the closing brace before `// ExportCertificateAPIRequest is the body`) with:

```go
// recordExportAudit writes one structured audit event per export attempt
// through exportaudit, which the CLI export commands share. A nil audit
// service is tolerated: audit failures never block the request.
func recordExportAudit(c *Context, r *http.Request, a exportAudit) {
	if c.App == nil || c.App.ServiceContainer == nil {
		return
	}
	exportaudit.Record(r.Context(), c.App.ServiceContainer.GetAuditService(), exportaudit.Attempt{
		UserID: c.Claims.UserID, ResourceType: a.ResourceType, ResourceID: a.ResourceID, VaultID: a.VaultID,
		Name: a.Name, Version: a.Version, Format: a.Format, Outcome: a.Outcome, Code: a.Code, Reason: a.Reason,
		IPAddress: middleware.ExtractClientIP(r), Source: "api",
	})
}
```

Nothing else in `api/export.go` changes: `exportFailure`, `exportAudit`, `badExportRequest`, `exportInternalFailure`, `logExportFailure` and both handlers stay as they are.

- [ ] **Step 4: Run and expect PASS, including every pre-existing export test unmodified**

Run: `go vet ./api && go test -p 2 ./api -count=1`
Expected: `ok  	rocketvault/api`. `git diff --stat -- api/` lists only `api/export.go` (modified) and `api/export_status_test.go` (new).

- [ ] **Step 5: Lint**

Run: `BASE=$(cat .git/rv-cli-export-base); PATH="$HOME/go/pkg/mod/golang.org/toolchain@v0.0.1-go1.25.7.linux-amd64/bin:$PATH" GOTOOLCHAIN=local ~/go/bin/golangci-lint run --new-from-rev="$BASE" ./api/...`
Expected: `0 issues.`

- [ ] **Step 6: Commit**

Commit via the `dev-workflow-skills:1-git-commit` skill. Stage: `api/export.go`, `api/export_status_test.go`.

---

### Task 4: `vaultcli.ExportAttempt` and `vaultcli.ExportOutput`

**Files:**
- Create: `cmd/vaultcli/export.go`
- Test: `cmd/vaultcli/export_test.go` (create)

**Interfaces:**
- Consumes: `vaultcli.Session` (fields `Ctx`, `Cmd`, `Claims`, `Container`, `Log`, `VaultID`), `vaultcli.CtxContainer`, `vaultcli.ResolveVaultID` (`cmd/vaultcli/session.go`, `context.go`, `vault.go`); Task 1's `common.SealItemExport`, `common.WritePrivateFile`, `common.ErrOutputExists`, `common.ExportPassphraseEnvVar`; `common.ResolvePassphrase`, `common.PassphraseSource`, `common.ErrNoPassphraseAvailable`; Task 2's `exportaudit`.
- Produces:
  - `type vaultcli.ExportAttempt`; `func BeginExportAttempt(s *Session, resourceType, rawID, format string, version int) *ExportAttempt`; methods `Fail(f exportaudit.Failure) error`, `FailService(err error) error`, `FailInput(reason string, shown error) error`, `FailOutput(err error) error`, `Denied(err error) error`, `Succeed(name string, version int)`
  - `type vaultcli.ExportOutput struct { File string; Encrypt bool; PassphraseFile string; Force bool }`; `func AddExportOutputFlags(cmd *cobra.Command)`; `func ReadExportOutput(cmd *cobra.Command) ExportOutput`; methods `Check() *exportaudit.Failure`, `Passphrase() (string, error)`, `Write(cmd *cobra.Command, p common.ItemExportPayload, passphrase, warning string) error`, `PrintStatus(cmd *cobra.Command, label, name string, version int, format string)`

- [ ] **Step 1: Write the failing tests**

Create `cmd/vaultcli/export_test.go`:

```go
package vaultcli

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"rocketvault/cmd/testutils"
	"rocketvault/common"
	"rocketvault/internal/logging"
	auditServices "rocketvault/internal/services/audit"
	"rocketvault/internal/services/exportaudit"
	"rocketvault/model"
)

// exportAuditRecorder captures structured audit events.
type exportAuditRecorder struct {
	mu     sync.Mutex
	events []auditServices.AuditEvent
}

func (r *exportAuditRecorder) RecordEvent(_ context.Context, e auditServices.AuditEvent) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.events = append(r.events, e)
	return nil
}

func (r *exportAuditRecorder) PersistAudit(string, string, string) error { return nil }

// exportSession builds an unauthorized Session whose context carries a
// container that hands out rec, and a logger that writes to logs.
func exportSession(t *testing.T, rec *exportAuditRecorder, logs *bytes.Buffer) (*Session, *testutils.TestContext) {
	t.Helper()
	tc := testutils.NewTestContext(t)
	tc.MockContainer.On("GetAuditService").Return(rec)
	l := logrus.New()
	l.SetOutput(logs)
	return &Session{Ctx: tc.Ctx, Claims: &model.Claims{UserID: tc.TestUserID}, Log: &logging.Logger{Logger: l}}, tc
}

func TestExportAttempt_RecordsExactlyOneEvent(t *testing.T) {
	rec := &exportAuditRecorder{}
	s, _ := exportSession(t, rec, &bytes.Buffer{})
	id := uuid.New()

	e := BeginExportAttempt(s, "certificate", id.String(), "pem", 3)
	err := e.Fail(exportaudit.BadRequest("--format must be pem or pkcs12"))
	assert.EqualError(t, err, "failed to export certificate: --format must be pem or pkcs12")
	e.Succeed("client", 3) // A second outcome is never recorded.

	require.Len(t, rec.events, 1)
	ev := rec.events[0]
	assert.Equal(t, "export_certificate", ev.Action)
	assert.Equal(t, "cli", ev.Source)
	assert.Equal(t, "failure", ev.Outcome)
	assert.Equal(t, id.String(), ev.ResourceID)
	assert.Equal(t, s.Claims.UserID.String(), ev.UserID)
	assert.Contains(t, ev.Details, `"reason":"--format must be pem or pkcs12"`)
	assert.Contains(t, ev.Details, `"code":"bad_request"`)
	assert.Contains(t, ev.Details, `"vault_id":""`)
	assert.Contains(t, ev.Details, `"version":3`)
}

func TestExportAttempt_SuccessCarriesVaultNameAndVersion(t *testing.T) {
	rec := &exportAuditRecorder{}
	s, tc := exportSession(t, rec, &bytes.Buffer{})
	s.VaultID = tc.TestVaultID

	BeginExportAttempt(s, "key", uuid.NewString(), "pem", 0).Succeed("signer", 4)

	require.Len(t, rec.events, 1)
	ev := rec.events[0]
	assert.Equal(t, "success", ev.Outcome)
	assert.Equal(t, "export_key", ev.Action)
	assert.Contains(t, ev.Details, `"vault_id":"`+tc.TestVaultID.String()+`"`)
	assert.Contains(t, ev.Details, `"name":"signer"`)
	assert.Contains(t, ev.Details, `"version":4`)
	assert.Contains(t, ev.Details, `"code":""`)
}

func TestExportAttempt_ArbitraryTextNeverReachesTheAuditTrail(t *testing.T) {
	rec := &exportAuditRecorder{}
	s, _ := exportSession(t, rec, &bytes.Buffer{})

	_ = BeginExportAttempt(s, "certificate", "not-a-uuid hunter2", "der hunter2", 0).
		Fail(exportaudit.BadRequest("certificate ID must be a UUID"))

	require.Len(t, rec.events, 1)
	assert.Empty(t, rec.events[0].ResourceID)
	assert.Contains(t, rec.events[0].Details, `"format":"invalid"`)
	assert.NotContains(t, rec.events[0].Details+rec.events[0].ResourceID, "hunter2")
}

func TestExportAttempt_FailServiceShowsOnlyFixedText(t *testing.T) {
	rec := &exportAuditRecorder{}
	logs := &bytes.Buffer{}
	s, _ := exportSession(t, rec, logs)

	err := BeginExportAttempt(s, "key", uuid.NewString(), "pem", 0).FailService(errors.New("decrypt key material: raw-detail"))
	assert.EqualError(t, err, "failed to export key: internal error; see the RocketVault log for details")
	assert.Contains(t, logs.String(), "raw-detail", "the cause goes to the log file only")
	require.Len(t, rec.events, 1)
	assert.Contains(t, rec.events[0].Details, `"reason":"internal failure"`)
	assert.NotContains(t, rec.events[0].Details, "raw-detail")
}

func TestExportAttempt_FailServiceShowsTheRefusalReason(t *testing.T) {
	rec := &exportAuditRecorder{}
	s, _ := exportSession(t, rec, &bytes.Buffer{})

	err := BeginExportAttempt(s, "key", uuid.NewString(), "pem", 0).FailService(&model.ExportRefusedError{
		Sentinel: model.ErrKeyNotExportable, Reason: "symmetric oct keys are not exportable", Name: "wrap",
	})
	assert.EqualError(t, err, "failed to export key: key is not exportable: symmetric oct keys are not exportable")
	require.Len(t, rec.events, 1)
	assert.Contains(t, rec.events[0].Details, `"name":"wrap"`)
	assert.Contains(t, rec.events[0].Details, `"code":"key_not_exportable"`)
}

func TestExportAttempt_DeniedReturnsTheAuthorizationErrorAndRecordsTheVault(t *testing.T) {
	rec := &exportAuditRecorder{}
	s, tc := exportSession(t, rec, &bytes.Buffer{})
	authzErr := errors.New("failed to export key: forbidden: no role grants it in this vault")

	err := BeginExportAttempt(s, "key", uuid.NewString(), "pem", 0).Denied(authzErr)
	assert.Equal(t, authzErr, err)
	require.Len(t, rec.events, 1)
	assert.Contains(t, rec.events[0].Details, `"code":"forbidden"`)
	assert.Contains(t, rec.events[0].Details, `"reason":"vault authorization failed"`)
	assert.Contains(t, rec.events[0].Details, `"vault_id":"`+tc.TestVaultID.String()+`"`)
}

func TestExportAttempt_FailOutput(t *testing.T) {
	t.Run("target appeared", func(t *testing.T) {
		rec := &exportAuditRecorder{}
		s, _ := exportSession(t, rec, &bytes.Buffer{})
		err := BeginExportAttempt(s, "key", uuid.NewString(), "pem", 0).FailOutput(common.ErrOutputExists)
		assert.EqualError(t, err, "failed to export key: the output file already exists: pass --force to replace it")
		require.Len(t, rec.events, 1)
		assert.Contains(t, rec.events[0].Details, `"code":"bad_request"`)
	})
	t.Run("write failed", func(t *testing.T) {
		rec := &exportAuditRecorder{}
		s, _ := exportSession(t, rec, &bytes.Buffer{})
		err := BeginExportAttempt(s, "key", uuid.NewString(), "pem", 0).FailOutput(errors.New("failed to write the export file: disk full"))
		assert.EqualError(t, err, "failed to export key: failed to write the export file: disk full")
		require.Len(t, rec.events, 1)
		assert.Contains(t, rec.events[0].Details, `"code":"output_failed"`)
		assert.Contains(t, rec.events[0].Details, `"reason":"the output file could not be written"`)
	})
}

func TestExportOutput_Check(t *testing.T) {
	dir := t.TempDir()
	existing := filepath.Join(dir, "exists.pem")
	require.NoError(t, os.WriteFile(existing, []byte("x"), 0o600))
	fresh := filepath.Join(dir, "new.pem")

	cases := []struct {
		name string
		o    ExportOutput
		want string
	}{
		{"usable", ExportOutput{File: fresh, Encrypt: true}, ""},
		{"no file", ExportOutput{Encrypt: true}, "--file is required"},
		{"stdout", ExportOutput{File: "-", Encrypt: true}, "--file - is not supported: an export is only ever written to a file"},
		{"plaintext with passphrase file", ExportOutput{File: fresh, PassphraseFile: "p"},
			"--passphrase-file was given with --encrypt=false: drop one, since a plaintext export has no passphrase"},
		{"existing without force", ExportOutput{File: existing, Encrypt: true}, "the output file already exists: pass --force to replace it"},
		{"existing with force", ExportOutput{File: existing, Encrypt: true, Force: true}, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := c.o.Check()
			if c.want == "" {
				assert.Nil(t, f)
				return
			}
			require.NotNil(t, f)
			assert.Equal(t, c.want, f.Message)
			assert.Equal(t, "bad_request", f.Code)
		})
	}
}

func TestExportOutput_Passphrase(t *testing.T) {
	t.Setenv(common.ExportPassphraseEnvVar, "")

	got, err := ExportOutput{Encrypt: false}.Passphrase()
	require.NoError(t, err)
	assert.Empty(t, got)

	// go test runs with stdin detached, so there is no terminal to prompt on.
	_, err = ExportOutput{Encrypt: true}.Passphrase()
	assert.ErrorContains(t, err, "no passphrase is available")

	t.Setenv(common.ExportPassphraseEnvVar, "from-env")
	got, err = ExportOutput{Encrypt: true}.Passphrase()
	require.NoError(t, err)
	assert.Equal(t, "from-env", got)

	file := filepath.Join(t.TempDir(), "pass")
	require.NoError(t, os.WriteFile(file, []byte("from-file\n"), 0o600))
	got, err = ExportOutput{Encrypt: true, PassphraseFile: file}.Passphrase()
	require.NoError(t, err)
	assert.Equal(t, "from-file", got, "the file comes before the environment")
}

func TestExportOutput_Write(t *testing.T) {
	payload := common.ItemExportPayload{
		Kind: common.ItemExportKindKey, ID: "id", Name: "signer", Version: 1, Format: "pem",
		Content: []byte("-----BEGIN PRIVATE KEY-----\nKEY-MATERIAL\n-----END PRIVATE KEY-----\n"),
	}

	t.Run("sealed", func(t *testing.T) {
		var stderr bytes.Buffer
		cmd := &cobra.Command{}
		cmd.SetErr(&stderr)
		o := ExportOutput{File: filepath.Join(t.TempDir(), "k.sealed"), Encrypt: true}

		require.NoError(t, o.Write(cmd, payload, "pass", "unused"))
		data, err := os.ReadFile(o.File)
		require.NoError(t, err)
		assert.NotContains(t, string(data), "KEY-MATERIAL")
		got, err := common.OpenItemExport(data, "pass")
		require.NoError(t, err)
		assert.Equal(t, payload.Content, got.Content)
		assert.Empty(t, stderr.String())
		info, err := os.Stat(o.File)
		require.NoError(t, err)
		assert.Equal(t, os.FileMode(0o600), info.Mode().Perm())
	})

	t.Run("plaintext", func(t *testing.T) {
		var stderr bytes.Buffer
		cmd := &cobra.Command{}
		cmd.SetErr(&stderr)
		o := ExportOutput{File: filepath.Join(t.TempDir(), "k.pem")}

		require.NoError(t, o.Write(cmd, payload, "", "will hold the key's private key unencrypted, in the clear."))
		data, err := os.ReadFile(o.File)
		require.NoError(t, err)
		assert.Equal(t, payload.Content, data)
		assert.Equal(t, "Warning: --encrypt=false — "+o.File+" will hold the key's private key unencrypted, in the clear.\n", stderr.String())
	})

	t.Run("existing target without force", func(t *testing.T) {
		cmd := &cobra.Command{}
		cmd.SetErr(&bytes.Buffer{})
		o := ExportOutput{File: filepath.Join(t.TempDir(), "k.pem")}
		require.NoError(t, os.WriteFile(o.File, []byte("original"), 0o600))
		assert.ErrorIs(t, o.Write(cmd, payload, "", "x"), common.ErrOutputExists)
	})
}

func TestExportOutput_PrintStatus(t *testing.T) {
	var stdout bytes.Buffer
	cmd := &cobra.Command{}
	cmd.SetOut(&stdout)
	ExportOutput{File: "k.sealed", Encrypt: true}.PrintStatus(cmd, "Key", "signer", 2, "pem")
	assert.Equal(t, "Key exported successfully\nName: signer\nVersion: 2\nFormat: pem\n"+
		"Encryption: passphrase (argon2id + AES-256-GCM)\nFile: k.sealed\n", stdout.String())
}

func TestAddExportOutputFlags(t *testing.T) {
	cmd := &cobra.Command{Use: "export"}
	AddExportOutputFlags(cmd)
	file := cmd.Flags().Lookup("file")
	require.NotNil(t, file)
	assert.Equal(t, "o", file.Shorthand)
	assert.Equal(t, []string{"true"}, file.Annotations[cobra.BashCompOneRequiredFlag])
	encrypt := cmd.Flags().Lookup("encrypt")
	require.NotNil(t, encrypt)
	assert.Equal(t, "e", encrypt.Shorthand)
	assert.Equal(t, "true", encrypt.DefValue)
	require.NotNil(t, cmd.Flags().Lookup("passphrase-file"))
	assert.Equal(t, "false", cmd.Flags().Lookup("force").DefValue)

	require.NoError(t, cmd.ParseFlags([]string{"-o", "x.pem", "--encrypt=false", "--force"}))
	assert.Equal(t, ExportOutput{File: "x.pem", Encrypt: false, Force: true}, ReadExportOutput(cmd))
}
```

- [ ] **Step 2: Run and expect FAIL**

Run: `go test -p 2 ./cmd/vaultcli -count=1`
Expected: FAIL with a build error naming `undefined: BeginExportAttempt` and `undefined: ExportOutput`.

- [ ] **Step 3: Implement**

Create `cmd/vaultcli/export.go`:

```go
package vaultcli

import (
	"errors"
	"fmt"
	"os"

	"github.com/google/uuid"
	"github.com/spf13/cobra"

	"rocketvault/common"
	"rocketvault/internal/services/exportaudit"
)

// outputExistsMessage is the fixed message for an output file that already
// exists when --force was not given.
const outputExistsMessage = "the output file already exists: pass --force to replace it"

// ExportAttempt is one CLI certificate or key export attempt. It records
// exactly one structured audit event through exportaudit, whatever the
// outcome: the same event the HTTP export handlers write, with Source "cli".
// The CLI has no PolicyMiddleware, so this event is also the audit record of
// a denied attempt.
type ExportAttempt struct {
	s        *Session
	attempt  exportaudit.Attempt
	recorded bool
}

// BeginExportAttempt starts an attempt to export resourceType ("certificate"
// or "key"). rawID is the command's argument; it reaches the audit trail
// only when it parses as a UUID. format reaches it only when it is a known
// export format, so arbitrary command-line text is never audited.
func BeginExportAttempt(s *Session, resourceType, rawID, format string, version int) *ExportAttempt {
	id := ""
	if parsed, err := uuid.Parse(rawID); err == nil {
		id = parsed.String()
	}
	return &ExportAttempt{s: s, attempt: exportaudit.Attempt{
		UserID: s.Claims.UserID.String(), ResourceType: resourceType, ResourceID: id,
		Version: version, Format: exportaudit.AuditableFormat(format), Outcome: "failure", Source: "cli",
	}}
}

// Fail records f and returns an error carrying only f's fixed message. An
// internal failure shows a generic message instead, as the API does.
func (e *ExportAttempt) Fail(f exportaudit.Failure) error {
	e.note(f)
	msg := f.Message
	if f.Kind == exportaudit.KindInternal {
		msg = "internal error; see the RocketVault log for details"
	}
	return fmt.Errorf("failed to export %s: %s", e.attempt.ResourceType, msg)
}

// FailService classifies a service error, records it and returns the fixed
// message. The service's own error text is never shown, because it can name
// repository detail; an internal failure's cause goes to the log file only.
func (e *ExportAttempt) FailService(err error) error {
	f := exportaudit.Classify(err, e.attempt.ResourceType)
	if f.Kind == exportaudit.KindInternal && e.s.Log != nil {
		e.s.Log.WithField("operation", "export_"+e.attempt.ResourceType).
			WithField("step", f.Reason).WithError(err).Error("export failed")
	}
	return e.Fail(f)
}

// FailInput records a local input problem under the fixed reason and returns
// shown. shown must be an error this command built, and it never holds a
// passphrase or password.
func (e *ExportAttempt) FailInput(reason string, shown error) error {
	e.note(exportaudit.BadRequest(reason))
	return fmt.Errorf("failed to export %s: %w", e.attempt.ResourceType, shown)
}

// FailOutput records that the output file could not be written. The service
// already released the material, but no file holds it, so the attempt is a
// failure.
func (e *ExportAttempt) FailOutput(err error) error {
	if errors.Is(err, common.ErrOutputExists) {
		return e.Fail(exportaudit.BadRequest(outputExistsMessage))
	}
	e.note(exportaudit.Failure{Kind: exportaudit.KindInternal, Code: "output_failed", Reason: "the output file could not be written"})
	return fmt.Errorf("failed to export %s: %w", e.attempt.ResourceType, err)
}

// Denied records an authorization failure and returns err, which
// Session.Authorize already shaped and logged. Authorize does not keep the
// vault it was refused in, so Denied resolves it again for the event.
func (e *ExportAttempt) Denied(err error) error {
	if sc, cerr := CtxContainer.From(e.s.Ctx); cerr == nil && sc != nil {
		if vaultID, verr := ResolveVaultID(e.s.Ctx, e.s.Cmd, sc); verr == nil {
			e.attempt.VaultID = vaultID.String()
		}
	}
	e.note(exportaudit.Forbidden("vault authorization failed"))
	return err
}

// Succeed records the successful export of name at version.
func (e *ExportAttempt) Succeed(name string, version int) {
	e.attempt.Outcome, e.attempt.Name, e.attempt.Version = "success", name, version
	e.attempt.Code, e.attempt.Reason = "", ""
	e.record()
}

// note records the failure f.
func (e *ExportAttempt) note(f exportaudit.Failure) {
	e.attempt.Code, e.attempt.Reason = f.Code, f.Reason
	if f.Name != "" {
		e.attempt.Name = f.Name
	}
	e.record()
}

// record writes the attempt's one audit event. Later calls do nothing, so an
// attempt is never audited twice. A failure before the vault is resolved
// records an empty vault id.
func (e *ExportAttempt) record() {
	if e.recorded {
		return
	}
	e.recorded = true
	if e.s.VaultID != uuid.Nil {
		e.attempt.VaultID = e.s.VaultID.String()
	}
	sc := e.s.Container
	if sc == nil {
		var err error
		if sc, err = CtxContainer.From(e.s.Ctx); err != nil || sc == nil {
			return
		}
	}
	exportaudit.Record(e.s.Ctx, sc.GetAuditService(), e.attempt)
}

// ExportOutput holds the output flags both item export commands share. The
// names, shorthands and defaults mirror "secrets export", plus --force.
type ExportOutput struct {
	File           string
	Encrypt        bool
	PassphraseFile string
	Force          bool
}

// AddExportOutputFlags registers --file/-o, --encrypt/-e, --passphrase-file
// and --force on cmd. --file is required.
func AddExportOutputFlags(cmd *cobra.Command) {
	cmd.Flags().StringP("file", "o", "", "Output file path (required)")
	cmd.Flags().BoolP("encrypt", "e", true, "Seal the file under a passphrase (argon2id + AES-256-GCM)")
	cmd.Flags().String("passphrase-file", "", "Read the export passphrase from the first line of this file")
	cmd.Flags().Bool("force", false, "Replace the output file if it already exists")
	cmd.MarkFlagRequired("file") //nolint:errcheck,gosec
}

// ReadExportOutput reads the flags AddExportOutputFlags registered.
func ReadExportOutput(cmd *cobra.Command) ExportOutput {
	file, _ := cmd.Flags().GetString("file")
	encrypt, _ := cmd.Flags().GetBool("encrypt")
	passphraseFile, _ := cmd.Flags().GetString("passphrase-file")
	force, _ := cmd.Flags().GetBool("force")
	return ExportOutput{File: file, Encrypt: encrypt, PassphraseFile: passphraseFile, Force: force}
}

// Check validates the output flags before anything is authorized or read.
// It returns nil when they are usable. Every message is a fixed phrase.
func (o ExportOutput) Check() *exportaudit.Failure {
	var msg string
	switch {
	case o.File == "":
		msg = "--file is required"
	case o.File == "-":
		msg = "--file - is not supported: an export is only ever written to a file"
	case !o.Encrypt && o.PassphraseFile != "":
		msg = "--passphrase-file was given with --encrypt=false: drop one, since a plaintext export has no passphrase"
	case !o.Force && pathExists(o.File):
		msg = outputExistsMessage
	default:
		return nil
	}
	f := exportaudit.BadRequest(msg)
	return &f
}

// pathExists reports whether anything, including a dangling symlink, is at
// path.
func pathExists(path string) bool {
	_, err := os.Lstat(path)
	return err == nil
}

// Passphrase resolves the sealing passphrase from --passphrase-file, then
// ROCKETVAULT_EXPORT_PASSPHRASE, then a terminal prompt asked twice, exactly
// as "secrets export" does. It returns "" when Encrypt is false. Call it only
// after authorization, so an unauthorized caller is never prompted.
func (o ExportOutput) Passphrase() (string, error) {
	if !o.Encrypt {
		return "", nil
	}
	passphrase, err := common.ResolvePassphrase(common.PassphraseSource{
		File:    o.PassphraseFile,
		EnvVar:  common.ExportPassphraseEnvVar,
		Prompt:  "Export passphrase: ",
		Confirm: true,
	})
	if errors.Is(err, common.ErrNoPassphraseAvailable) {
		return "", fmt.Errorf("export encryption is on but no passphrase is available: "+
			"pass --passphrase-file, set %s, or pass --encrypt=false to write plaintext deliberately",
			common.ExportPassphraseEnvVar)
	}
	if err != nil {
		return "", fmt.Errorf("failed to resolve export passphrase: %w", err)
	}
	return passphrase, nil
}

// Write seals p, or writes p.Content in the clear after printing warning to
// stderr, and moves the file into place atomically with mode 0600. warning
// completes the sentence "Warning: --encrypt=false — <file> ...".
func (o ExportOutput) Write(cmd *cobra.Command, p common.ItemExportPayload, passphrase, warning string) error {
	data := p.Content
	if o.Encrypt {
		sealed, err := common.SealItemExport(p, passphrase)
		if err != nil {
			return fmt.Errorf("failed to seal the export: %w", err)
		}
		data = sealed
	} else {
		fmt.Fprintf(cmd.ErrOrStderr(), "Warning: --encrypt=false — %s %s\n", o.File, warning) //nolint:errcheck
	}
	return common.WritePrivateFile(o.File, data, o.Force)
}

// PrintStatus writes the status block a successful export prints to stdout.
// It names the item and the file and never carries material.
func (o ExportOutput) PrintStatus(cmd *cobra.Command, label, name string, version int, format string) {
	encryption := "none (plaintext)"
	if o.Encrypt {
		encryption = "passphrase (argon2id + AES-256-GCM)"
	}
	fmt.Fprintf(cmd.OutOrStdout(), "%s exported successfully\nName: %s\nVersion: %d\nFormat: %s\nEncryption: %s\nFile: %s\n", //nolint:errcheck
		label, name, version, format, encryption, o.File)
}
```

- [ ] **Step 4: Run and expect PASS**

Run: `go vet ./cmd/vaultcli && go test -p 2 ./cmd/vaultcli -count=1`
Expected: `ok  	rocketvault/cmd/vaultcli`; the pre-existing `vault_test.go`, `context_test.go` and `render_test.go` pass unchanged.

- [ ] **Step 5: Lint**

Run: `BASE=$(cat .git/rv-cli-export-base); PATH="$HOME/go/pkg/mod/golang.org/toolchain@v0.0.1-go1.25.7.linux-amd64/bin:$PATH" GOTOOLCHAIN=local ~/go/bin/golangci-lint run --new-from-rev="$BASE" ./cmd/vaultcli/...`
Expected: `0 issues.`

- [ ] **Step 6: Commit**

Commit via the `dev-workflow-skills:1-git-commit` skill. Stage: `cmd/vaultcli/export.go`, `cmd/vaultcli/export_test.go`.

---

### Task 5: `rocketvault certificates export`

**Files:**
- Create: `cmd/certificates/export.go`
- Modify: `cmd/certificates.go` (one registration line, help text)
- Test: `cmd/certificates/export_test.go` (create)

**Interfaces:**
- Consumes: Task 4's `vaultcli` export helpers; `vaultcli.Caller`, `vaultcli.Op`, `Session.Authorize`; `CertificateService.ExportCertificate(ctx, scope, id, certServices.ExportCertificateRequest{Format, Password *string, Compat, Version})` returning `*certServices.ExportCertificateResult{ID, Name, Version, Format, CertificatePEM, PrivateKeyPEM, PKCS12, KeyAlgorithm, ...}` (`internal/services/certificates/certificate_export.go`); `model.ActionCertificatesExportItem`, `model.OpCreate`, `model.ExportFormat*`, `model.ExportCompat*`. Test fakes from `cmd/certificates/certs_cmd_test.go`: `certCmdCertService` (its `ExportCertificate` stub calls `m.Called(ctx, scope, id, req)`) and `certsTestContainer`.
- Produces: `func InitCertificatesExport(certificatesCmd *cobra.Command)`; package-private `newExportCmd`, `runCertificateExport`, `checkCertificateExportFlags`, `resolvePKCS12Password`, `certificateExportContent`, `certificatePlaintextWarning`, `pkcs12PasswordEnvVar`.

- [ ] **Step 1: Write the failing tests**

Create `cmd/certificates/export_test.go`:

```go
package certificates

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"rocketvault/cmd/testutils"
	"rocketvault/common"
	"rocketvault/internal/logging"
	auditServices "rocketvault/internal/services/audit"
	authzServices "rocketvault/internal/services/authorization"
	certServices "rocketvault/internal/services/certificates"
	"rocketvault/model"
)

// Test material is marked so that a leak is easy to search for.
const (
	exportTestLeaf       = "-----BEGIN CERTIFICATE-----\nTEST-LEAF-BODY\n-----END CERTIFICATE-----\n"
	exportTestKey        = "-----BEGIN PRIVATE KEY-----\nTEST-KEY-MATERIAL\n-----END PRIVATE KEY-----\n"
	exportTestPassphrase = "export-pass-1"
	exportTestP12        = "p12-secret-1"
)

// certExportAudit records every structured audit event.
type certExportAudit struct {
	mu     sync.Mutex
	events []auditServices.AuditEvent
}

func (a *certExportAudit) RecordEvent(_ context.Context, e auditServices.AuditEvent) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.events = append(a.events, e)
	return nil
}

func (a *certExportAudit) PersistAudit(string, string, string) error { return nil }

// only returns the single event an attempt must have recorded.
func (a *certExportAudit) only(t *testing.T) auditServices.AuditEvent {
	t.Helper()
	a.mu.Lock()
	defer a.mu.Unlock()
	require.Len(t, a.events, 1, "exactly one structured audit event per attempt")
	return a.events[0]
}

// certExportFixture is one export test's world: the mocks, the audit
// capture, a log buffer, a scratch directory and a certificate id.
type certExportFixture struct {
	tc    *testutils.TestContext
	svc   *certCmdCertService
	audit *certExportAudit
	logs  bytes.Buffer
	dir   string
	id    uuid.UUID
}

func newCertExportFixture(t *testing.T) *certExportFixture {
	t.Helper()
	f := &certExportFixture{
		tc: testutils.NewTestContext(t), svc: &certCmdCertService{}, audit: &certExportAudit{},
		dir: t.TempDir(), id: uuid.New(),
	}
	f.tc.MockContainer.On("GetAuditService").Return(f.audit)
	// Isolate every run from the developer's own environment.
	t.Setenv(common.ExportPassphraseEnvVar, "")
	t.Setenv(pkcs12PasswordEnvVar, "")
	return f
}

func (f *certExportFixture) scope() model.Scope {
	return model.NewVaultScope(f.tc.TestVaultID, f.tc.TestUserID)
}

func (f *certExportFixture) path(name string) string { return filepath.Join(f.dir, name) }

// run executes a fresh "certificates export" as a caller holding only the
// plain user account role, so a pass proves no account role is required.
func (f *certExportFixture) run(args ...string) (stdout, stderr string, err error) {
	cmd := newExportCmd()
	var out, errOut bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&errOut)
	cmd.SetArgs(args)
	l := logrus.New()
	l.SetOutput(&f.logs)
	claims := &model.Claims{UserID: f.tc.TestUserID, Username: "exporter", Roles: []string{model.RoleUser}}
	ctx := context.WithValue(context.Background(), common.ClaimsKey, claims)
	ctx = context.WithValue(ctx, common.LogKey, &logging.Logger{Logger: l})
	ctx = context.WithValue(ctx, common.ServiceContainerKey, &certsTestContainer{MockServiceContainer: f.tc.MockContainer, certSvc: f.svc})
	cmd.SetContext(ctx)
	err = cmd.Execute()
	return out.String(), errOut.String(), err
}

// everything returns every byte a run could have leaked through.
func (f *certExportFixture) everything(stdout, stderr string) string {
	f.audit.mu.Lock()
	defer f.audit.mu.Unlock()
	var b strings.Builder
	b.WriteString(stdout + stderr + f.logs.String())
	for _, e := range f.audit.events {
		b.WriteString(e.Details + e.ResourceID + e.Action)
	}
	return b.String()
}

func pemExport(id uuid.UUID) *certServices.ExportCertificateResult {
	return &certServices.ExportCertificateResult{
		ID: id, Name: "client", Version: 2, Format: model.ExportFormatPEM,
		CertificatePEM: exportTestLeaf, PrivateKeyPEM: exportTestKey, KeyAlgorithm: "RSA-2048",
	}
}

// assertNoFile fails if path exists or a temporary file was left beside it.
func assertNoFile(t *testing.T, path string) {
	t.Helper()
	_, err := os.Stat(path)
	assert.ErrorIs(t, err, fs.ErrNotExist, "no file may be written at %s", path)
	entries, err := os.ReadDir(filepath.Dir(path))
	require.NoError(t, err)
	for _, e := range entries {
		assert.False(t, strings.HasPrefix(e.Name(), ".rocketvault-export-"), "temporary file left behind: %s", e.Name())
	}
}

func assertMode0600(t *testing.T, path string) {
	t.Helper()
	info, err := os.Stat(path)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o600), info.Mode().Perm())
}

func TestCertExport_SealedByDefaultAndOpensBack(t *testing.T) {
	f := newCertExportFixture(t)
	t.Setenv(common.ExportPassphraseEnvVar, exportTestPassphrase)
	f.svc.On("ExportCertificate", mock.Anything, f.scope(), f.id, certServices.ExportCertificateRequest{
		Format: model.ExportFormatPEM, Compat: model.ExportCompatModern,
	}).Return(pemExport(f.id), nil).Once()

	out := f.path("client.pem.sealed")
	stdout, stderr, err := f.run(f.id.String(), "--file", out)
	require.NoError(t, err)
	f.svc.AssertExpectations(t)
	assert.Contains(t, stdout, "Certificate exported successfully")
	assert.Contains(t, stdout, "Encryption: passphrase (argon2id + AES-256-GCM)")
	assert.Empty(t, stderr)

	data, err := os.ReadFile(out)
	require.NoError(t, err)
	assert.NotContains(t, string(data), "TEST-KEY-MATERIAL")
	assertMode0600(t, out)

	p, err := common.OpenItemExport(data, exportTestPassphrase)
	require.NoError(t, err)
	assert.Equal(t, common.ItemExportKindCertificate, p.Kind)
	assert.Equal(t, f.id.String(), p.ID)
	assert.Equal(t, "client", p.Name)
	assert.Equal(t, 2, p.Version)
	assert.Equal(t, model.ExportFormatPEM, p.Format)
	assert.Equal(t, "RSA-2048", p.KeyAlgorithm)
	assert.Equal(t, exportTestLeaf+exportTestKey, string(p.Content))

	ev := f.audit.only(t)
	assert.Equal(t, "export_certificate", ev.Action)
	assert.Equal(t, "success", ev.Outcome)
	assert.Equal(t, "cli", ev.Source)
	assert.Equal(t, "certificate", ev.ResourceType)
	assert.Equal(t, f.id.String(), ev.ResourceID)
	assert.Equal(t, f.tc.TestUserID.String(), ev.UserID)
	assert.Contains(t, ev.Details, `"vault_id":"`+f.tc.TestVaultID.String()+`"`)
	assert.Contains(t, ev.Details, `"name":"client"`)
	assert.Contains(t, ev.Details, `"version":2`)
	assert.Contains(t, ev.Details, `"format":"pem"`)
}

func TestCertExport_PlaintextWritesThePEMAndWarns(t *testing.T) {
	f := newCertExportFixture(t)
	f.svc.On("ExportCertificate", mock.Anything, f.scope(), f.id, mock.Anything).Return(pemExport(f.id), nil).Once()

	out := f.path("client.pem")
	stdout, stderr, err := f.run(f.id.String(), "--file", out, "--encrypt=false")
	require.NoError(t, err)
	data, err := os.ReadFile(out)
	require.NoError(t, err)
	assert.Equal(t, exportTestLeaf+exportTestKey, string(data))
	assertMode0600(t, out)
	assert.Equal(t, "Warning: --encrypt=false — "+out+" will hold the certificate's private key unencrypted, in the clear.\n", stderr)
	assert.Contains(t, stdout, "Encryption: none (plaintext)")
	assert.NotContains(t, f.everything(stdout, stderr), "TEST-KEY-MATERIAL")
}

func TestCertExport_VersionReachesTheService(t *testing.T) {
	f := newCertExportFixture(t)
	f.svc.On("ExportCertificate", mock.Anything, f.scope(), f.id, certServices.ExportCertificateRequest{
		Format: model.ExportFormatPEM, Compat: model.ExportCompatModern, Version: 1,
	}).Return(pemExport(f.id), nil).Once()

	_, _, err := f.run(f.id.String(), "--file", f.path("v1.pem"), "--encrypt=false", "--version", "1")
	require.NoError(t, err)
	f.svc.AssertExpectations(t)
}

func TestCertExport_PKCS12PasswordSources(t *testing.T) {
	cases := []struct {
		name  string
		setup func(t *testing.T, f *certExportFixture) []string
		want  string
	}{
		{"file", func(t *testing.T, f *certExportFixture) []string {
			pw := f.path("p12-pass")
			require.NoError(t, os.WriteFile(pw, []byte(exportTestP12+"\n"), 0o600))
			return []string{"--pkcs12-password-file", pw}
		}, exportTestP12},
		{"environment", func(t *testing.T, _ *certExportFixture) []string {
			t.Setenv(pkcs12PasswordEnvVar, exportTestP12)
			return nil
		}, exportTestP12},
		{"explicit empty", func(_ *testing.T, _ *certExportFixture) []string {
			return []string{"--pkcs12-empty-password"}
		}, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := newCertExportFixture(t)
			extra := c.setup(t, f)
			want := c.want
			f.svc.On("ExportCertificate", mock.Anything, f.scope(), f.id, mock.MatchedBy(func(r certServices.ExportCertificateRequest) bool {
				return r.Format == model.ExportFormatPKCS12 && r.Compat == model.ExportCompatLegacy && r.Password != nil && *r.Password == want
			})).Return(&certServices.ExportCertificateResult{
				ID: f.id, Name: "client", Version: 1, Format: model.ExportFormatPKCS12, PKCS12: []byte("P12-BYTES"), KeyAlgorithm: "EC-P256",
			}, nil).Once()

			out := f.path("client.p12")
			args := append([]string{f.id.String(), "--format", "pkcs12", "--compat", "legacy", "--file", out, "--encrypt=false"}, extra...)
			stdout, stderr, err := f.run(args...)
			require.NoError(t, err)
			f.svc.AssertExpectations(t)
			data, err := os.ReadFile(out)
			require.NoError(t, err)
			assert.Equal(t, "P12-BYTES", string(data))
			assert.Contains(t, stderr, "protected only by the PKCS12 password")
			if want != "" {
				assert.NotContains(t, f.everything(stdout, stderr), want)
			}
		})
	}
}

func TestCertExport_PKCS12WithoutAPasswordWritesNothing(t *testing.T) {
	f := newCertExportFixture(t)
	out := f.path("client.p12")

	_, _, err := f.run(f.id.String(), "--format", "pkcs12", "--file", out, "--encrypt=false")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "pkcs12 needs a password")
	f.svc.AssertNotCalled(t, "ExportCertificate", mock.Anything, mock.Anything, mock.Anything, mock.Anything)
	assertNoFile(t, out)
	ev := f.audit.only(t)
	assert.Equal(t, "failure", ev.Outcome)
	assert.Contains(t, ev.Details, `"reason":"pkcs12 password unavailable"`)
}

func TestCertExport_NoPassphraseWritesNothing(t *testing.T) {
	f := newCertExportFixture(t)
	out := f.path("client.pem.sealed")

	_, _, err := f.run(f.id.String(), "--file", out)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no passphrase is available")
	f.svc.AssertNotCalled(t, "ExportCertificate", mock.Anything, mock.Anything, mock.Anything, mock.Anything)
	assertNoFile(t, out)
	assert.Contains(t, f.audit.only(t).Details, `"reason":"export passphrase unavailable"`)
}

func TestCertExport_RejectsBadInputBeforeAuthorization(t *testing.T) {
	cases := []struct {
		name string
		args func(f *certExportFixture) []string
		want string
	}{
		{"id is not a UUID", func(f *certExportFixture) []string { return []string{"not-a-uuid", "--file", f.path("o")} },
			"certificate ID must be a UUID"},
		{"unknown format", func(f *certExportFixture) []string {
			return []string{f.id.String(), "--file", f.path("o"), "--format", "der"}
		}, "--format must be pem or pkcs12"},
		{"unknown compat", func(f *certExportFixture) []string {
			return []string{f.id.String(), "--file", f.path("o"), "--format", "pkcs12", "--compat", "weak"}
		}, "--compat must be modern or legacy"},
		{"negative version", func(f *certExportFixture) []string {
			return []string{f.id.String(), "--file", f.path("o"), "--version=-1"}
		}, "--version must be 0 or a positive version number"},
		{"compat with pem", func(f *certExportFixture) []string {
			return []string{f.id.String(), "--file", f.path("o"), "--compat", "legacy"}
		}, "--compat, --pkcs12-password-file and --pkcs12-empty-password apply only to --format pkcs12"},
		{"empty password with pem", func(f *certExportFixture) []string {
			return []string{f.id.String(), "--file", f.path("o"), "--pkcs12-empty-password"}
		}, "--compat, --pkcs12-password-file and --pkcs12-empty-password apply only to --format pkcs12"},
		{"two password sources", func(f *certExportFixture) []string {
			return []string{f.id.String(), "--file", f.path("o"), "--format", "pkcs12",
				"--pkcs12-password-file", f.path("pw"), "--pkcs12-empty-password"}
		}, "pass --pkcs12-password-file or --pkcs12-empty-password, not both"},
		{"stdout", func(f *certExportFixture) []string { return []string{f.id.String(), "--file", "-"} },
			"--file - is not supported: an export is only ever written to a file"},
		{"plaintext with passphrase file", func(f *certExportFixture) []string {
			return []string{f.id.String(), "--file", f.path("o"), "--encrypt=false", "--passphrase-file", f.path("pw")}
		}, "--passphrase-file was given with --encrypt=false: drop one, since a plaintext export has no passphrase"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := newCertExportFixture(t)
			roles := &testutils.MockRoleAssignmentService{}
			f.tc.MockContainer.RoleAssignmentService = roles

			_, _, err := f.run(c.args(f)...)
			require.Error(t, err)
			assert.Equal(t, "failed to export certificate: "+c.want, err.Error())
			roles.AssertNotCalled(t, "HasDataAction", mock.Anything, mock.Anything, mock.Anything, mock.Anything)
			f.svc.AssertNotCalled(t, "ExportCertificate", mock.Anything, mock.Anything, mock.Anything, mock.Anything)
			assertNoFile(t, f.path("o"))
			ev := f.audit.only(t)
			assert.Equal(t, "failure", ev.Outcome)
			assert.Contains(t, ev.Details, `"code":"bad_request"`)
			assert.Contains(t, ev.Details, `"reason":"`+c.want+`"`)
		})
	}
}

func TestCertExport_NeverReplacesAFileWithoutForce(t *testing.T) {
	f := newCertExportFixture(t)
	out := f.path("client.pem")
	require.NoError(t, os.WriteFile(out, []byte("original"), 0o644))

	_, _, err := f.run(f.id.String(), "--file", out, "--encrypt=false")
	assert.EqualError(t, err, "failed to export certificate: the output file already exists: pass --force to replace it")
	f.svc.AssertNotCalled(t, "ExportCertificate", mock.Anything, mock.Anything, mock.Anything, mock.Anything)
	data, err := os.ReadFile(out)
	require.NoError(t, err)
	assert.Equal(t, "original", string(data))

	f.svc.On("ExportCertificate", mock.Anything, f.scope(), f.id, mock.Anything).Return(pemExport(f.id), nil).Once()
	_, _, err = f.run(f.id.String(), "--file", out, "--encrypt=false", "--force")
	require.NoError(t, err)
	data, err = os.ReadFile(out)
	require.NoError(t, err)
	assert.Equal(t, exportTestLeaf+exportTestKey, string(data))
	assertMode0600(t, out)
}

func TestCertExport_DeniedWithoutTheExportAction(t *testing.T) {
	f := newCertExportFixture(t)
	roles := &testutils.MockRoleAssignmentService{}
	roles.On("HasDataAction", mock.Anything, f.tc.TestUserID, f.tc.TestVaultID, model.ActionCertificatesExportItem).
		Return(false, nil).Once()
	f.tc.MockContainer.RoleAssignmentService = roles
	out := f.path("client.pem.sealed")

	_, _, err := f.run(f.id.String(), "--file", out)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to export certificate")
	assert.Contains(t, err.Error(), "forbidden")
	assert.NotContains(t, err.Error(), "passphrase", "an unauthorized caller is never asked for a passphrase")
	roles.AssertExpectations(t)
	f.svc.AssertNotCalled(t, "ExportCertificate", mock.Anything, mock.Anything, mock.Anything, mock.Anything)
	assertNoFile(t, out)
	ev := f.audit.only(t)
	assert.Equal(t, "failure", ev.Outcome)
	assert.Contains(t, ev.Details, `"code":"forbidden"`)
	assert.Contains(t, ev.Details, `"reason":"vault authorization failed"`)
	assert.Contains(t, ev.Details, `"vault_id":"`+f.tc.TestVaultID.String()+`"`)
}

func TestCertExport_ExplicitDenyOverridesARoleGrant(t *testing.T) {
	f := newCertExportFixture(t)
	policies := &testutils.MockAccessPolicyService{}
	policies.On("CheckAccess", mock.Anything, f.tc.TestUserID, model.PolicyResourceCertificates, model.OpCreate, f.tc.TestVaultID).
		Return(authzServices.AccessDenied, nil).Once()
	f.tc.MockContainer.AccessPolicyService = policies
	out := f.path("client.pem.sealed")

	_, _, err := f.run(f.id.String(), "--file", out)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "explicit access policy")
	policies.AssertExpectations(t)
	f.svc.AssertNotCalled(t, "ExportCertificate", mock.Anything, mock.Anything, mock.Anything, mock.Anything)
	assertNoFile(t, out)
	assert.Contains(t, f.audit.only(t).Details, `"code":"forbidden"`)
}

func TestCertExport_ChecksTheExportActionAndCreatePolicy(t *testing.T) {
	f := newCertExportFixture(t)
	t.Setenv(common.ExportPassphraseEnvVar, exportTestPassphrase)
	roles := &testutils.MockRoleAssignmentService{}
	roles.On("HasDataAction", mock.Anything, f.tc.TestUserID, f.tc.TestVaultID, model.ActionCertificatesExportItem).
		Return(true, nil).Once()
	policies := &testutils.MockAccessPolicyService{}
	policies.On("CheckAccess", mock.Anything, f.tc.TestUserID, model.PolicyResourceCertificates, model.OpCreate, f.tc.TestVaultID).
		Return(authzServices.AccessAllowed, nil).Once()
	f.tc.MockContainer.RoleAssignmentService = roles
	f.tc.MockContainer.AccessPolicyService = policies
	f.svc.On("ExportCertificate", mock.Anything, f.scope(), f.id, mock.Anything).Return(pemExport(f.id), nil).Once()

	_, _, err := f.run(f.id.String(), "--file", f.path("client.pem.sealed"))
	require.NoError(t, err)
	roles.AssertExpectations(t)
	policies.AssertExpectations(t)
	f.svc.AssertExpectations(t)
}

func TestCertExport_RefusalShowsTheFixedReasonAndWritesNothing(t *testing.T) {
	f := newCertExportFixture(t)
	t.Setenv(common.ExportPassphraseEnvVar, exportTestPassphrase)
	f.svc.On("ExportCertificate", mock.Anything, f.scope(), f.id, mock.Anything).Return(nil, &model.ExportRefusedError{
		Sentinel: model.ErrCertificateNotExportable, Reason: "the certificate was not created with exportable: true",
		Name: "client", KeyAlgorithm: "RSA-2048",
	}).Once()
	out := f.path("client.pem.sealed")

	_, _, err := f.run(f.id.String(), "--file", out)
	assert.EqualError(t, err, "failed to export certificate: certificate is not exportable: the certificate was not created with exportable: true")
	assertNoFile(t, out)
	ev := f.audit.only(t)
	assert.Equal(t, "failure", ev.Outcome)
	assert.Contains(t, ev.Details, `"code":"certificate_not_exportable"`)
	assert.Contains(t, ev.Details, `"reason":"the certificate was not created with exportable: true"`)
	assert.Contains(t, ev.Details, `"name":"client"`)
}

func TestCertExport_ServiceErrorsShowOnlyFixedMessages(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want string
	}{
		{"not found", fmt.Errorf("%w: sql: raw-detail", certServices.ErrCertNotFound),
			"failed to export certificate: certificate or version not found"},
		{"disabled", certServices.ErrCertLifecycleDenied,
			"failed to export certificate: the certificate or this version is disabled or outside its valid time window"},
		{"invalid request", fmt.Errorf("%w: version must be 0 or a positive version number", model.ErrInvalidExportRequest),
			"failed to export certificate: invalid export request: version must be 0 or a positive version number"},
		{"internal", errors.New("decrypt certificate key: raw-detail"),
			"failed to export certificate: internal error; see the RocketVault log for details"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := newCertExportFixture(t)
			t.Setenv(common.ExportPassphraseEnvVar, exportTestPassphrase)
			f.svc.On("ExportCertificate", mock.Anything, f.scope(), f.id, mock.Anything).Return(nil, c.err).Once()
			out := f.path("client.pem.sealed")

			_, _, err := f.run(f.id.String(), "--file", out)
			assert.EqualError(t, err, c.want)
			assertNoFile(t, out)
			assert.NotContains(t, f.audit.only(t).Details, "raw-detail")
		})
	}
}

func TestCertExport_NoMaterialOrSecretInAnyOutput(t *testing.T) {
	for _, encrypt := range []string{"--encrypt=true", "--encrypt=false"} {
		t.Run(encrypt, func(t *testing.T) {
			f := newCertExportFixture(t)
			t.Setenv(common.ExportPassphraseEnvVar, exportTestPassphrase)
			f.svc.On("ExportCertificate", mock.Anything, f.scope(), f.id, mock.Anything).Return(pemExport(f.id), nil).Once()

			stdout, stderr, err := f.run(f.id.String(), "--file", f.path("out"), encrypt)
			require.NoError(t, err)
			all := f.everything(stdout, stderr)
			for _, secret := range []string{"TEST-KEY-MATERIAL", "TEST-LEAF-BODY", exportTestPassphrase} {
				assert.NotContains(t, all, secret)
			}
		})
	}
}

func TestInitCertificatesExport_RegistersTheCommandAndFlags(t *testing.T) {
	parent := &cobra.Command{Use: "certificates"}
	InitCertificatesExport(parent)
	cmd, _, err := parent.Find([]string{"export"})
	require.NoError(t, err)
	assert.Equal(t, "export <id>", cmd.Use)
	for name, def := range map[string]string{
		"file": "", "encrypt": "true", "passphrase-file": "", "force": "false", "format": "pem",
		"compat": "modern", "version": "0", "pkcs12-password-file": "", "pkcs12-empty-password": "false",
	} {
		fl := cmd.Flags().Lookup(name)
		require.NotNil(t, fl, name)
		assert.Equal(t, def, fl.DefValue, name)
	}
	assert.Equal(t, "o", cmd.Flags().Lookup("file").Shorthand)
	assert.Equal(t, []string{"true"}, cmd.Flags().Lookup("file").Annotations[cobra.BashCompOneRequiredFlag])
	assert.Nil(t, cmd.Flags().Lookup("pkcs12-password"), "a password is never a command-line value")
}
```

- [ ] **Step 2: Run and expect FAIL**

Run: `go test -p 2 ./cmd/certificates -run 'CertExport|InitCertificatesExport' -count=1`
Expected: FAIL with a build error naming `undefined: newExportCmd`, `undefined: pkcs12PasswordEnvVar` and `undefined: InitCertificatesExport`.

- [ ] **Step 3: Implement**

Create `cmd/certificates/export.go`:

```go
/*
Copyright © 2025 Snehal Dangroshiya
*/

package certificates

import (
	"errors"
	"fmt"
	"strings"

	"github.com/google/uuid"
	"github.com/spf13/cobra"

	"rocketvault/cmd/vaultcli"
	"rocketvault/common"
	certServices "rocketvault/internal/services/certificates"
	"rocketvault/internal/services/exportaudit"
	"rocketvault/model"
)

// pkcs12PasswordEnvVar names the environment variable that supplies a PKCS12
// password without a terminal. An empty value counts as unset; an empty
// password needs --pkcs12-empty-password.
const pkcs12PasswordEnvVar = "ROCKETVAULT_PKCS12_PASSWORD" //nolint:gosec // G101: an environment variable name, not a credential.

// newExportCmd builds the "certificates export" command. It is a
// constructor rather than a package variable so every test gets fresh flags.
func newExportCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "export <id>",
		Short: "Export a certificate and its private key to a file",
		Long: `Export one version of a certificate and its private key to a file: as
PEM (the leaf certificate, then any intermediates, then the unencrypted
PKCS#8 private key, in one file) or as a PKCS12 bundle.

Only a certificate created with --exportable can be exported. A refusal
names the reason and writes no file.

Requires the Microsoft.KeyVault/vaults/certificates/export/action data
action in the target vault, held by the Key Vault Certificate Exporter and
Key Vault Administrator roles. No account role is required. Acts on the
vault named by --vault, defaulting to "default". Every attempt, allowed or
denied, is written to the audit log.

The file is sealed by default, as with "secrets export": --encrypt (default
true) seals it under a passphrase read from --passphrase-file, then the
ROCKETVAULT_EXPORT_PASSPHRASE environment variable, then a prompt asked
twice. If none of those yields a passphrase the command fails and writes no
file. Open a sealed file with "rocketvault export open". --encrypt=false
writes the PEM or PKCS12 file directly and prints a warning.

--format pkcs12 needs a PKCS12 password, read from --pkcs12-password-file,
then the ROCKETVAULT_PKCS12_PASSWORD environment variable, then a prompt
asked twice. An empty password is used only with --pkcs12-empty-password.
--compat legacy uses 3DES and SHA-1 for tools that cannot read the default
AES-256 encoding.

The file is written with 0600 permissions through a temporary file in the
same directory, so a failure leaves no partial file. An existing file is
never replaced unless --force is given. Missing parent directories are
created with 0700 permissions. Nothing secret is printed to the terminal.`,
		Example: `  # Export the current version as a sealed PEM file
  rocketvault certificates export <id> --file client.pem.sealed

  # Export version 2 as a sealed PKCS12 bundle from a named vault
  rocketvault certificates export <id> --format pkcs12 --version 2 \
    --file client.p12.sealed --passphrase-file /run/secrets/export-pass \
    --pkcs12-password-file /run/secrets/p12-pass --vault payments

  # Write a plaintext PEM file deliberately, accepting the warning
  rocketvault certificates export <id> --file client.pem --encrypt=false`,
		Args: cobra.ExactArgs(1),
		RunE: runCertificateExport,
	}
	vaultcli.AddExportOutputFlags(cmd)
	cmd.Flags().StringP("format", "f", model.ExportFormatPEM, "Output format: pem (chain plus PKCS#8 key) or pkcs12")
	cmd.Flags().String("compat", model.ExportCompatModern, "PKCS12 encoding: modern (AES-256) or legacy (3DES and SHA-1)")
	cmd.Flags().Int("version", 0, "Certificate version to export (0 or omitted = the current version)")
	cmd.Flags().String("pkcs12-password-file", "", "Read the PKCS12 password from the first line of this file")
	cmd.Flags().Bool("pkcs12-empty-password", false, "Encode the PKCS12 bundle with an empty password, deliberately")
	return cmd
}

// InitCertificatesExport registers the export command.
func InitCertificatesExport(certificatesCmd *cobra.Command) {
	certificatesCmd.AddCommand(newExportCmd())
}

// runCertificateExport is the export command's RunE.
func runCertificateExport(cmd *cobra.Command, args []string) error {
	s, err := vaultcli.Caller(cmd, vaultcli.Op{
		Audit: "export_certificate", Action: model.ActionCertificatesExportItem, Policy: model.OpCreate,
		AuthzFailMsg: "failed to export certificate",
	})
	if err != nil {
		return err
	}

	format, _ := cmd.Flags().GetString("format")
	format = strings.ToLower(format)
	compat, _ := cmd.Flags().GetString("compat")
	compat = strings.ToLower(compat)
	version, _ := cmd.Flags().GetInt("version")
	p12File, _ := cmd.Flags().GetString("pkcs12-password-file")
	p12Empty, _ := cmd.Flags().GetBool("pkcs12-empty-password")
	out := vaultcli.ReadExportOutput(cmd)
	e := vaultcli.BeginExportAttempt(s, "certificate", args[0], format, version)

	certID, err := uuid.Parse(args[0])
	if err != nil {
		return e.Fail(exportaudit.BadRequest("certificate ID must be a UUID"))
	}
	if msg := checkCertificateExportFlags(format, compat, version, cmd.Flags().Changed("compat"), p12File, p12Empty); msg != "" {
		return e.Fail(exportaudit.BadRequest(msg))
	}
	if f := out.Check(); f != nil {
		return e.Fail(*f)
	}

	// Authorize only after the input is known good, so a malformed argument
	// reports itself, and before any prompt, so an unauthorized caller is
	// never asked for a passphrase or a password.
	if err := s.Authorize(); err != nil {
		return e.Denied(err)
	}

	passphrase, err := out.Passphrase()
	if err != nil {
		return e.FailInput("export passphrase unavailable", err)
	}
	var password *string
	if format == model.ExportFormatPKCS12 {
		pw, pwErr := resolvePKCS12Password(p12File, p12Empty)
		if pwErr != nil {
			return e.FailInput("pkcs12 password unavailable", pwErr)
		}
		password = &pw
	}

	result, err := s.Container.GetCertificateService().ExportCertificate(s.Ctx, s.Scope, certID, certServices.ExportCertificateRequest{
		Format: format, Password: password, Compat: compat, Version: version,
	})
	if err != nil {
		return e.FailService(err)
	}

	payload := common.ItemExportPayload{
		Kind: common.ItemExportKindCertificate, ID: result.ID.String(), Name: result.Name, Version: result.Version,
		Format: result.Format, KeyAlgorithm: result.KeyAlgorithm, Content: certificateExportContent(result),
	}
	defer clear(payload.Content)
	if err := out.Write(cmd, payload, passphrase, certificatePlaintextWarning(result.Format)); err != nil {
		return e.FailOutput(err)
	}
	e.Succeed(result.Name, result.Version)
	out.PrintStatus(cmd, "Certificate", result.Name, result.Version, result.Format)
	return nil
}

// checkCertificateExportFlags validates the certificate-specific flags and
// returns a fixed message, or "" when they are usable.
func checkCertificateExportFlags(format, compat string, version int, compatSet bool, p12File string, p12Empty bool) string {
	switch {
	case format != model.ExportFormatPEM && format != model.ExportFormatPKCS12:
		return "--format must be pem or pkcs12"
	case compat != model.ExportCompatModern && compat != model.ExportCompatLegacy:
		return "--compat must be modern or legacy"
	case version < 0:
		return "--version must be 0 or a positive version number"
	case format == model.ExportFormatPEM && (compatSet || p12File != "" || p12Empty):
		return "--compat, --pkcs12-password-file and --pkcs12-empty-password apply only to --format pkcs12"
	case p12File != "" && p12Empty:
		return "pass --pkcs12-password-file or --pkcs12-empty-password, not both"
	}
	return ""
}

// resolvePKCS12Password returns the PKCS12 password from
// --pkcs12-empty-password, then --pkcs12-password-file, then
// ROCKETVAULT_PKCS12_PASSWORD, then a prompt asked twice. A password is never
// a command-line value, and only --pkcs12-empty-password yields an empty one.
func resolvePKCS12Password(file string, empty bool) (string, error) {
	if empty {
		return "", nil
	}
	password, err := common.ResolvePassphrase(common.PassphraseSource{
		File:          file,
		EnvVar:        pkcs12PasswordEnvVar,
		Prompt:        "PKCS12 password: ",
		Confirm:       true,
		ConfirmPrompt: "Confirm PKCS12 password: ",
	})
	if errors.Is(err, common.ErrNoPassphraseAvailable) {
		return "", fmt.Errorf("pkcs12 needs a password: pass --pkcs12-password-file, set %s, or pass --pkcs12-empty-password",
			pkcs12PasswordEnvVar)
	}
	if err != nil {
		return "", fmt.Errorf("failed to resolve pkcs12 password: %w", err)
	}
	return password, nil
}

// certificateExportContent returns the file an export writes in the clear:
// the PEM chain followed by the PKCS#8 key, or the PKCS12 bytes.
func certificateExportContent(r *certServices.ExportCertificateResult) []byte {
	if r.Format == model.ExportFormatPKCS12 {
		return r.PKCS12
	}
	return []byte(r.CertificatePEM + r.PrivateKeyPEM)
}

// certificatePlaintextWarning completes the --encrypt=false warning for
// format.
func certificatePlaintextWarning(format string) string {
	if format == model.ExportFormatPKCS12 {
		return "will hold the certificate's private key protected only by the PKCS12 password."
	}
	return "will hold the certificate's private key unencrypted, in the clear."
}
```

In `cmd/certificates.go`, add the registration after `certificates.InitCertificatesVersions(certificateCmd)`:

```go
	certificates.InitCertificatesVersions(certificateCmd)
	certificates.InitCertificatesExport(certificateCmd)
```

and in `certificateCmd.Long` replace the line

```
vault. get and list require only certificates/read. Vault access is
```

with the two lines

```
vault. get and list require only certificates/read, and export only
certificates/export/action, with no account role. Vault access is
```

- [ ] **Step 4: Run and expect PASS**

Run: `go vet ./cmd/... && go test -p 2 ./cmd/certificates ./cmd -count=1`
Expected: both `ok`. The `cmd` package includes `TestExampleFlagsAreRegistered`, `TestLeafExamplesDoNotShowCredentials` and `TestExamplesDoNotAdvertiseUnsupportedRemoteFlags`, which now also walk `certificates export`.

- [ ] **Step 5: Lint**

Run: `BASE=$(cat .git/rv-cli-export-base); PATH="$HOME/go/pkg/mod/golang.org/toolchain@v0.0.1-go1.25.7.linux-amd64/bin:$PATH" GOTOOLCHAIN=local ~/go/bin/golangci-lint run --new-from-rev="$BASE" ./cmd/...`
Expected: `0 issues.` (gosec G101 flags the constant `pkcs12PasswordEnvVar` because its name contains "password"; the `//nolint:gosec // G101: ...` comment on that line is deliberate.)

- [ ] **Step 6: Commit**

Commit via the `dev-workflow-skills:1-git-commit` skill. Stage: `cmd/certificates/export.go`, `cmd/certificates/export_test.go`, `cmd/certificates.go`.

---

### Task 6: `rocketvault keys export`

**Files:**
- Create: `cmd/keys/export.go`
- Modify: `cmd/keys.go` (one registration line, help text)
- Test: `cmd/keys/export_test.go` (create)

**Interfaces:**
- Consumes: Task 4's `vaultcli` export helpers; `KeyService.ExportKey(ctx, scope, id, version int)` returning `*keyServices.ExportKeyResult{ID, Name, Type, Version, Format, PrivateKeyPEM, KeyAlgorithm}` (`internal/services/keys/key_export.go`); `model.ActionKeysExport`, `model.OpCreate`. Test fakes from `cmd/keys/keys_cmd_test.go`: `keyCmdKeyService` (its `ExportKey` stub calls `m.Called(ctx, scope, id, version)`) and `keysTestContainer`.
- Produces: `func InitKeysExport(keysCmd *cobra.Command)`; package-private `newKeyExportCmd`, `runKeyExport`, `keyPlaintextWarning`.

- [ ] **Step 1: Write the failing tests**

Create `cmd/keys/export_test.go`:

```go
package keys

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"rocketvault/cmd/testutils"
	"rocketvault/common"
	"rocketvault/internal/logging"
	auditServices "rocketvault/internal/services/audit"
	authzServices "rocketvault/internal/services/authorization"
	keyServices "rocketvault/internal/services/keys"
	"rocketvault/model"
)

// Test material is marked so that a leak is easy to search for.
const (
	keyExportTestPEM        = "-----BEGIN PRIVATE KEY-----\nTEST-KEY-MATERIAL\n-----END PRIVATE KEY-----\n"
	keyExportTestPassphrase = "export-pass-2"
)

// keyExportAudit records every structured audit event.
type keyExportAudit struct {
	mu     sync.Mutex
	events []auditServices.AuditEvent
}

func (a *keyExportAudit) RecordEvent(_ context.Context, e auditServices.AuditEvent) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.events = append(a.events, e)
	return nil
}

func (a *keyExportAudit) PersistAudit(string, string, string) error { return nil }

// only returns the single event an attempt must have recorded.
func (a *keyExportAudit) only(t *testing.T) auditServices.AuditEvent {
	t.Helper()
	a.mu.Lock()
	defer a.mu.Unlock()
	require.Len(t, a.events, 1, "exactly one structured audit event per attempt")
	return a.events[0]
}

// keyExportFixture is one export test's world: the mocks, the audit
// capture, a log buffer, a scratch directory and a key id.
type keyExportFixture struct {
	tc    *testutils.TestContext
	svc   *keyCmdKeyService
	audit *keyExportAudit
	logs  bytes.Buffer
	dir   string
	id    uuid.UUID
}

func newKeyExportFixture(t *testing.T) *keyExportFixture {
	t.Helper()
	f := &keyExportFixture{
		tc: testutils.NewTestContext(t), svc: &keyCmdKeyService{}, audit: &keyExportAudit{},
		dir: t.TempDir(), id: uuid.New(),
	}
	f.tc.MockContainer.On("GetAuditService").Return(f.audit)
	// Isolate every run from the developer's own environment.
	t.Setenv(common.ExportPassphraseEnvVar, "")
	return f
}

func (f *keyExportFixture) scope() model.Scope {
	return model.NewVaultScope(f.tc.TestVaultID, f.tc.TestUserID)
}

func (f *keyExportFixture) path(name string) string { return filepath.Join(f.dir, name) }

// run executes a fresh "keys export" as a caller holding only the plain user
// account role, so a pass proves no account role is required.
func (f *keyExportFixture) run(args ...string) (stdout, stderr string, err error) {
	cmd := newKeyExportCmd()
	var out, errOut bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&errOut)
	cmd.SetArgs(args)
	l := logrus.New()
	l.SetOutput(&f.logs)
	claims := &model.Claims{UserID: f.tc.TestUserID, Username: "exporter", Roles: []string{model.RoleUser}}
	ctx := context.WithValue(context.Background(), common.ClaimsKey, claims)
	ctx = context.WithValue(ctx, common.LogKey, &logging.Logger{Logger: l})
	ctx = context.WithValue(ctx, common.ServiceContainerKey, &keysTestContainer{MockServiceContainer: f.tc.MockContainer, keySvc: f.svc})
	cmd.SetContext(ctx)
	err = cmd.Execute()
	return out.String(), errOut.String(), err
}

// everything returns every byte a run could have leaked through.
func (f *keyExportFixture) everything(stdout, stderr string) string {
	f.audit.mu.Lock()
	defer f.audit.mu.Unlock()
	var b strings.Builder
	b.WriteString(stdout + stderr + f.logs.String())
	for _, e := range f.audit.events {
		b.WriteString(e.Details + e.ResourceID + e.Action)
	}
	return b.String()
}

func keyExport(id uuid.UUID, version int) *keyServices.ExportKeyResult {
	return &keyServices.ExportKeyResult{
		ID: id, Name: "signer", Type: model.KeyTypeRSA, Version: version, Format: model.ExportFormatPEM,
		PrivateKeyPEM: keyExportTestPEM, KeyAlgorithm: "RSA-2048",
	}
}

// assertNoKeyFile fails if path exists or a temporary file was left beside it.
func assertNoKeyFile(t *testing.T, path string) {
	t.Helper()
	_, err := os.Stat(path)
	assert.ErrorIs(t, err, fs.ErrNotExist, "no file may be written at %s", path)
	entries, err := os.ReadDir(filepath.Dir(path))
	require.NoError(t, err)
	for _, e := range entries {
		assert.False(t, strings.HasPrefix(e.Name(), ".rocketvault-export-"), "temporary file left behind: %s", e.Name())
	}
}

func TestKeyExport_SealedByDefaultAndOpensBack(t *testing.T) {
	f := newKeyExportFixture(t)
	t.Setenv(common.ExportPassphraseEnvVar, keyExportTestPassphrase)
	f.svc.On("ExportKey", mock.Anything, f.scope(), f.id, 0).Return(keyExport(f.id, 3), nil).Once()

	out := f.path("signer.pem.sealed")
	stdout, stderr, err := f.run(f.id.String(), "--file", out)
	require.NoError(t, err)
	f.svc.AssertExpectations(t)
	assert.Contains(t, stdout, "Key exported successfully")
	assert.Contains(t, stdout, "Version: 3")
	assert.Empty(t, stderr)

	data, err := os.ReadFile(out)
	require.NoError(t, err)
	assert.NotContains(t, string(data), "TEST-KEY-MATERIAL")
	info, err := os.Stat(out)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o600), info.Mode().Perm())

	p, err := common.OpenItemExport(data, keyExportTestPassphrase)
	require.NoError(t, err)
	assert.Equal(t, common.ItemExportKindKey, p.Kind)
	assert.Equal(t, f.id.String(), p.ID)
	assert.Equal(t, "signer", p.Name)
	assert.Equal(t, 3, p.Version)
	assert.Equal(t, model.ExportFormatPEM, p.Format)
	assert.Equal(t, "RSA-2048", p.KeyAlgorithm)
	assert.Equal(t, keyExportTestPEM, string(p.Content))

	ev := f.audit.only(t)
	assert.Equal(t, "export_key", ev.Action)
	assert.Equal(t, "success", ev.Outcome)
	assert.Equal(t, "cli", ev.Source)
	assert.Equal(t, f.id.String(), ev.ResourceID)
	assert.Contains(t, ev.Details, `"vault_id":"`+f.tc.TestVaultID.String()+`"`)
	assert.Contains(t, ev.Details, `"name":"signer"`)
	assert.Contains(t, ev.Details, `"version":3`)
}

func TestKeyExport_PlaintextWritesThePEMAndWarns(t *testing.T) {
	f := newKeyExportFixture(t)
	f.svc.On("ExportKey", mock.Anything, f.scope(), f.id, 1).Return(keyExport(f.id, 1), nil).Once()

	out := f.path("signer.pem")
	stdout, stderr, err := f.run(f.id.String(), "--file", out, "--encrypt=false", "--version", "1")
	require.NoError(t, err)
	f.svc.AssertExpectations(t)
	data, err := os.ReadFile(out)
	require.NoError(t, err)
	assert.Equal(t, keyExportTestPEM, string(data))
	assert.Equal(t, "Warning: --encrypt=false — "+out+" will hold the key's private key unencrypted, in the clear.\n", stderr)
	assert.Contains(t, stdout, "Encryption: none (plaintext)")
	assert.NotContains(t, f.everything(stdout, stderr), "TEST-KEY-MATERIAL")
}

func TestKeyExport_RejectsBadInputBeforeAuthorization(t *testing.T) {
	cases := []struct {
		name string
		args func(f *keyExportFixture) []string
		want string
	}{
		{"id is not a UUID", func(f *keyExportFixture) []string { return []string{"not-a-uuid", "--file", f.path("o")} },
			"key ID must be a UUID"},
		{"negative version", func(f *keyExportFixture) []string {
			return []string{f.id.String(), "--file", f.path("o"), "--version=-1"}
		}, "--version must be 0 or a positive version number"},
		{"stdout", func(f *keyExportFixture) []string { return []string{f.id.String(), "--file", "-"} },
			"--file - is not supported: an export is only ever written to a file"},
		{"plaintext with passphrase file", func(f *keyExportFixture) []string {
			return []string{f.id.String(), "--file", f.path("o"), "--encrypt=false", "--passphrase-file", f.path("pw")}
		}, "--passphrase-file was given with --encrypt=false: drop one, since a plaintext export has no passphrase"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := newKeyExportFixture(t)
			roles := &testutils.MockRoleAssignmentService{}
			f.tc.MockContainer.RoleAssignmentService = roles

			_, _, err := f.run(c.args(f)...)
			require.Error(t, err)
			assert.Equal(t, "failed to export key: "+c.want, err.Error())
			roles.AssertNotCalled(t, "HasDataAction", mock.Anything, mock.Anything, mock.Anything, mock.Anything)
			f.svc.AssertNotCalled(t, "ExportKey", mock.Anything, mock.Anything, mock.Anything, mock.Anything)
			assertNoKeyFile(t, f.path("o"))
			ev := f.audit.only(t)
			assert.Contains(t, ev.Details, `"code":"bad_request"`)
			assert.Contains(t, ev.Details, `"reason":"`+c.want+`"`)
		})
	}
}

func TestKeyExport_NeverReplacesAFileWithoutForce(t *testing.T) {
	f := newKeyExportFixture(t)
	out := f.path("signer.pem")
	require.NoError(t, os.WriteFile(out, []byte("original"), 0o644))

	_, _, err := f.run(f.id.String(), "--file", out, "--encrypt=false")
	assert.EqualError(t, err, "failed to export key: the output file already exists: pass --force to replace it")
	f.svc.AssertNotCalled(t, "ExportKey", mock.Anything, mock.Anything, mock.Anything, mock.Anything)

	f.svc.On("ExportKey", mock.Anything, f.scope(), f.id, 0).Return(keyExport(f.id, 1), nil).Once()
	_, _, err = f.run(f.id.String(), "--file", out, "--encrypt=false", "--force")
	require.NoError(t, err)
	data, err := os.ReadFile(out)
	require.NoError(t, err)
	assert.Equal(t, keyExportTestPEM, string(data))
	info, err := os.Stat(out)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o600), info.Mode().Perm())
}

func TestKeyExport_DeniedWithoutTheExportAction(t *testing.T) {
	f := newKeyExportFixture(t)
	roles := &testutils.MockRoleAssignmentService{}
	roles.On("HasDataAction", mock.Anything, f.tc.TestUserID, f.tc.TestVaultID, model.ActionKeysExport).
		Return(false, nil).Once()
	f.tc.MockContainer.RoleAssignmentService = roles
	out := f.path("signer.pem.sealed")

	_, _, err := f.run(f.id.String(), "--file", out)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to export key")
	assert.Contains(t, err.Error(), "forbidden")
	assert.NotContains(t, err.Error(), "passphrase", "an unauthorized caller is never asked for a passphrase")
	roles.AssertExpectations(t)
	f.svc.AssertNotCalled(t, "ExportKey", mock.Anything, mock.Anything, mock.Anything, mock.Anything)
	assertNoKeyFile(t, out)
	ev := f.audit.only(t)
	assert.Contains(t, ev.Details, `"code":"forbidden"`)
	assert.Contains(t, ev.Details, `"vault_id":"`+f.tc.TestVaultID.String()+`"`)
}

func TestKeyExport_ExplicitDenyOverridesARoleGrant(t *testing.T) {
	f := newKeyExportFixture(t)
	policies := &testutils.MockAccessPolicyService{}
	policies.On("CheckAccess", mock.Anything, f.tc.TestUserID, model.PolicyResourceKeys, model.OpCreate, f.tc.TestVaultID).
		Return(authzServices.AccessDenied, nil).Once()
	f.tc.MockContainer.AccessPolicyService = policies
	out := f.path("signer.pem.sealed")

	_, _, err := f.run(f.id.String(), "--file", out)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "explicit access policy")
	policies.AssertExpectations(t)
	f.svc.AssertNotCalled(t, "ExportKey", mock.Anything, mock.Anything, mock.Anything, mock.Anything)
	assertNoKeyFile(t, out)
}

func TestKeyExport_ChecksTheExportActionAndCreatePolicy(t *testing.T) {
	f := newKeyExportFixture(t)
	t.Setenv(common.ExportPassphraseEnvVar, keyExportTestPassphrase)
	roles := &testutils.MockRoleAssignmentService{}
	roles.On("HasDataAction", mock.Anything, f.tc.TestUserID, f.tc.TestVaultID, model.ActionKeysExport).Return(true, nil).Once()
	policies := &testutils.MockAccessPolicyService{}
	policies.On("CheckAccess", mock.Anything, f.tc.TestUserID, model.PolicyResourceKeys, model.OpCreate, f.tc.TestVaultID).
		Return(authzServices.AccessAllowed, nil).Once()
	f.tc.MockContainer.RoleAssignmentService = roles
	f.tc.MockContainer.AccessPolicyService = policies
	f.svc.On("ExportKey", mock.Anything, f.scope(), f.id, 0).Return(keyExport(f.id, 1), nil).Once()

	_, _, err := f.run(f.id.String(), "--file", f.path("signer.pem.sealed"))
	require.NoError(t, err)
	roles.AssertExpectations(t)
	policies.AssertExpectations(t)
	f.svc.AssertExpectations(t)
}

func TestKeyExport_ServiceErrorsShowOnlyFixedMessages(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want string
		code string
	}{
		{"oct refusal", &model.ExportRefusedError{Sentinel: model.ErrKeyNotExportable, Reason: "symmetric oct keys are not exportable", Name: "wrap"},
			"failed to export key: key is not exportable: symmetric oct keys are not exportable", "key_not_exportable"},
		{"not exportable", &model.ExportRefusedError{Sentinel: model.ErrKeyNotExportable, Reason: "the key was not created with exportable: true", Name: "signer"},
			"failed to export key: key is not exportable: the key was not created with exportable: true", "key_not_exportable"},
		{"not found", fmt.Errorf("%w: sql: raw-detail", keyServices.ErrKeyNotFound), "failed to export key: key or version not found", "not_found"},
		{"version not found", fmt.Errorf("%w: key raw-detail has no version 9", model.ErrKeyVersionNotFound), "failed to export key: key or version not found", "not_found"},
		{"disabled", fmt.Errorf("%w", keyServices.ErrKeyLifecycleDenied), "failed to export key: the key is disabled or outside its valid time window", "key_disabled"},
		{"internal", errors.New("decrypt key material: raw-detail"), "failed to export key: internal error; see the RocketVault log for details", "internal_error"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := newKeyExportFixture(t)
			t.Setenv(common.ExportPassphraseEnvVar, keyExportTestPassphrase)
			f.svc.On("ExportKey", mock.Anything, f.scope(), f.id, 0).Return(nil, c.err).Once()
			out := f.path("signer.pem.sealed")

			_, _, err := f.run(f.id.String(), "--file", out)
			assert.EqualError(t, err, c.want)
			assertNoKeyFile(t, out)
			ev := f.audit.only(t)
			assert.Equal(t, "failure", ev.Outcome)
			assert.Contains(t, ev.Details, `"code":"`+c.code+`"`)
			assert.NotContains(t, ev.Details, "raw-detail")
		})
	}
}

func TestKeyExport_NoMaterialOrSecretInAnyOutput(t *testing.T) {
	for _, encrypt := range []string{"--encrypt=true", "--encrypt=false"} {
		t.Run(encrypt, func(t *testing.T) {
			f := newKeyExportFixture(t)
			t.Setenv(common.ExportPassphraseEnvVar, keyExportTestPassphrase)
			f.svc.On("ExportKey", mock.Anything, f.scope(), f.id, 0).Return(keyExport(f.id, 1), nil).Once()

			stdout, stderr, err := f.run(f.id.String(), "--file", f.path("out"), encrypt)
			require.NoError(t, err)
			all := f.everything(stdout, stderr)
			for _, secret := range []string{"TEST-KEY-MATERIAL", keyExportTestPassphrase} {
				assert.NotContains(t, all, secret)
			}
		})
	}
}

func TestInitKeysExport_RegistersTheCommandAndFlags(t *testing.T) {
	parent := &cobra.Command{Use: "keys"}
	InitKeysExport(parent)
	cmd, _, err := parent.Find([]string{"export"})
	require.NoError(t, err)
	assert.Equal(t, "export <id>", cmd.Use)
	for name, def := range map[string]string{
		"file": "", "encrypt": "true", "passphrase-file": "", "force": "false", "version": "0",
	} {
		fl := cmd.Flags().Lookup(name)
		require.NotNil(t, fl, name)
		assert.Equal(t, def, fl.DefValue, name)
	}
	assert.Nil(t, cmd.Flags().Lookup("format"), "keys export has one format, so no --format flag")
}
```

- [ ] **Step 2: Run and expect FAIL**

Run: `go test -p 2 ./cmd/keys -run 'KeyExport|InitKeysExport' -count=1`
Expected: FAIL with a build error naming `undefined: newKeyExportCmd` and `undefined: InitKeysExport`.

- [ ] **Step 3: Implement**

Create `cmd/keys/export.go`:

```go
/*
Copyright © 2025 Snehal Dangroshiya
*/

package keys

import (
	"github.com/google/uuid"
	"github.com/spf13/cobra"

	"rocketvault/cmd/vaultcli"
	"rocketvault/common"
	"rocketvault/internal/services/exportaudit"
	"rocketvault/model"
)

// keyPlaintextWarning completes the --encrypt=false warning for a key.
const keyPlaintextWarning = "will hold the key's private key unencrypted, in the clear."

// newKeyExportCmd builds the "keys export" command. It is a constructor
// rather than a package variable so every test gets fresh flags.
func newKeyExportCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "export <id>",
		Short: "Export a key's private key to a PEM file",
		Long: `Export one version of a software-backed key as an unencrypted PKCS#8
private key in PEM, written to a file.

Only a key created or imported with --exportable can be exported.
HSM-backed, symmetric oct and ES256K keys never can. A refusal names the
reason and writes no file.

Requires the Microsoft.KeyVault/vaults/keys/export/action data action in
the target vault, held by the Key Vault Key Exporter and Key Vault
Administrator roles. No account role is required. Acts on the vault named
by --vault, defaulting to "default". Every attempt, allowed or denied, is
written to the audit log.

The file is sealed by default, as with "secrets export": --encrypt (default
true) seals it under a passphrase read from --passphrase-file, then the
ROCKETVAULT_EXPORT_PASSPHRASE environment variable, then a prompt asked
twice. If none of those yields a passphrase the command fails and writes no
file. Open a sealed file with "rocketvault export open". --encrypt=false
writes the PEM file directly and prints a warning.

The file is written with 0600 permissions through a temporary file in the
same directory, so a failure leaves no partial file. An existing file is
never replaced unless --force is given. Missing parent directories are
created with 0700 permissions. Nothing secret is printed to the terminal.`,
		Example: `  # Export the current version as a sealed file
  rocketvault keys export <key-id> --file signer.pem.sealed

  # Export version 1 of a rotated key from a named vault, non-interactively
  rocketvault keys export <key-id> --version 1 --file signer-v1.pem.sealed \
    --passphrase-file /run/secrets/export-pass --vault payments

  # Write a plaintext PEM file deliberately, accepting the warning
  rocketvault keys export <key-id> --file signer.pem --encrypt=false`,
		Args: cobra.ExactArgs(1),
		RunE: runKeyExport,
	}
	vaultcli.AddExportOutputFlags(cmd)
	cmd.Flags().Int("version", 0, "Key version to export (0 or omitted = the key's current version)")
	return cmd
}

// InitKeysExport registers the export command.
func InitKeysExport(keysCmd *cobra.Command) {
	keysCmd.AddCommand(newKeyExportCmd())
}

// runKeyExport is the export command's RunE.
func runKeyExport(cmd *cobra.Command, args []string) error {
	s, err := vaultcli.Caller(cmd, vaultcli.Op{
		Audit: "export_key", Action: model.ActionKeysExport, Policy: model.OpCreate,
		AuthzFailMsg: "failed to export key",
	})
	if err != nil {
		return err
	}

	version, _ := cmd.Flags().GetInt("version")
	out := vaultcli.ReadExportOutput(cmd)
	e := vaultcli.BeginExportAttempt(s, "key", args[0], model.ExportFormatPEM, version)

	keyID, err := uuid.Parse(args[0])
	if err != nil {
		return e.Fail(exportaudit.BadRequest("key ID must be a UUID"))
	}
	if version < 0 {
		return e.Fail(exportaudit.BadRequest("--version must be 0 or a positive version number"))
	}
	if f := out.Check(); f != nil {
		return e.Fail(*f)
	}

	// Authorize only after the input is known good, so a malformed argument
	// reports itself, and before any prompt, so an unauthorized caller is
	// never asked for a passphrase.
	if err := s.Authorize(); err != nil {
		return e.Denied(err)
	}

	passphrase, err := out.Passphrase()
	if err != nil {
		return e.FailInput("export passphrase unavailable", err)
	}

	result, err := s.Container.GetKeyService().ExportKey(s.Ctx, s.Scope, keyID, version)
	if err != nil {
		return e.FailService(err)
	}

	payload := common.ItemExportPayload{
		Kind: common.ItemExportKindKey, ID: result.ID.String(), Name: result.Name, Version: result.Version,
		Format: result.Format, KeyAlgorithm: result.KeyAlgorithm, Content: []byte(result.PrivateKeyPEM),
	}
	defer clear(payload.Content)
	if err := out.Write(cmd, payload, passphrase, keyPlaintextWarning); err != nil {
		return e.FailOutput(err)
	}
	e.Succeed(result.Name, result.Version)
	out.PrintStatus(cmd, "Key", result.Name, result.Version, result.Format)
	return nil
}
```

In `cmd/keys.go`, add the registration after `keys.InitKeysVerify(keysCmd)`:

```go
	keys.InitKeysVerify(keysCmd)
	keys.InitKeysExport(keysCmd)
```

and in `keysCmd.Long` replace the two lines

```
use them to sign, verify, wrap, and unwrap. Private key material never leaves
the vault; crypto operations run inside it and return only the result.
```

with the three lines

```
use them to sign, verify, wrap, and unwrap. Crypto operations run inside the
vault and return only the result. Private key material leaves the vault only
through "keys export", and only for a key created with --exportable.
```

- [ ] **Step 4: Run and expect PASS**

Run: `go vet ./cmd/... && go test -p 2 ./cmd/keys ./cmd -count=1`
Expected: both `ok`.

- [ ] **Step 5: Lint**

Run: `BASE=$(cat .git/rv-cli-export-base); PATH="$HOME/go/pkg/mod/golang.org/toolchain@v0.0.1-go1.25.7.linux-amd64/bin:$PATH" GOTOOLCHAIN=local ~/go/bin/golangci-lint run --new-from-rev="$BASE" ./cmd/...`
Expected: `0 issues.`

- [ ] **Step 6: Commit**

Commit via the `dev-workflow-skills:1-git-commit` skill. Stage: `cmd/keys/export.go`, `cmd/keys/export_test.go`, `cmd/keys.go`.

---

### Task 7: `rocketvault export open`, the `initConfig` exemption and the remote-mode pin

**Files:**
- Create: `cmd/export.go`
- Modify: `cmd/root.go` (help text, one condition in `initConfig`)
- Test: `cmd/export_test.go` (create)

**Interfaces:**
- Consumes: Task 1's `common.OpenItemExport`, `common.ErrNotItemExport`, `common.WritePrivateFile`, `common.ErrOutputExists`, `common.ExportPassphraseEnvVar`; `common.IsSealedExport`, `common.ResolvePassphrase`, `common.SealExport`, `common.SessionBaseDir`; `rootCmd`, `isRemoteCapableCommand`, `isContextCommandArgs` (`cmd/root.go`); Tasks 5 and 6's registered commands (the remote-mode test runs them).
- Produces: `exportGroupCmd`, `newExportOpenCmd`, `runExportOpen`, `readSealedExport`, `isExportGroupArgs`, `maxSealedExportBytes`, `exportOutputExistsMessage` (package `cmd`, unexported).

Why `initConfig` changes: `cobra.OnInitialize(initConfig)` runs before any pre-run, and `initConfig` (`cmd/root.go`, the `viper.ReadInConfig()` branch) calls `log.Panicf` when no `.rocketvault.yaml` is found, unless the command is in the `context` group or a remote target is set. Without the new condition, `export open` would panic on a machine that has only the binary.

- [ ] **Step 1: Write the failing tests**

Create `cmd/export_test.go`:

```go
package cmd

import (
	"bytes"
	"context"
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/uuid"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"rocketvault/common"
)

const openTestContent = "-----BEGIN CERTIFICATE-----\nLEAF\n-----END CERTIFICATE-----\n" +
	"-----BEGIN PRIVATE KEY-----\nKEY-MATERIAL\n-----END PRIVATE KEY-----\n"

// sealedFixture writes a sealed export of p and a passphrase file into dir.
func sealedFixture(t *testing.T, dir string, p common.ItemExportPayload, passphrase string) (sealedPath, passFile string) {
	t.Helper()
	sealed, err := common.SealItemExport(p, passphrase)
	require.NoError(t, err)
	sealedPath = filepath.Join(dir, "export.sealed")
	require.NoError(t, os.WriteFile(sealedPath, sealed, 0o600))
	passFile = filepath.Join(dir, "pass")
	require.NoError(t, os.WriteFile(passFile, []byte(passphrase+"\n"), 0o600))
	return sealedPath, passFile
}

func certPayload() common.ItemExportPayload {
	return common.ItemExportPayload{
		Kind: common.ItemExportKindCertificate, ID: uuid.NewString(), Name: "client", Version: 2,
		Format: "pem", KeyAlgorithm: "RSA-2048", Content: []byte(openTestContent),
	}
}

// runOpen runs a fresh "export open" with args. It parses the flags and
// calls RunE directly: Execute would run root.go's process-wide
// cobra.OnInitialize hook, which loads a config file (see rotation_test.go).
// The end-to-end tests below go through rootCmd instead.
func runOpen(args ...string) (stdout, stderr string, err error) {
	cmd := newExportOpenCmd()
	var out, errOut bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&errOut)
	cmd.SetContext(context.Background())
	if err := cmd.ParseFlags(args); err != nil {
		return "", "", err
	}
	err = cmd.RunE(cmd, cmd.Flags().Args())
	return out.String(), errOut.String(), err
}

func TestExportOpen_WritesTheExactPlaintextFile(t *testing.T) {
	t.Setenv(common.ExportPassphraseEnvVar, "")
	dir := t.TempDir()
	sealed, pass := sealedFixture(t, dir, certPayload(), "open-pass")
	out := filepath.Join(dir, "client.pem")

	stdout, stderr, err := runOpen(sealed, "--file", out, "--passphrase-file", pass)
	require.NoError(t, err)
	data, err := os.ReadFile(out)
	require.NoError(t, err)
	assert.Equal(t, openTestContent, string(data))
	info, err := os.Stat(out)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o600), info.Mode().Perm())
	assert.Contains(t, stdout, "Kind: certificate")
	assert.Contains(t, stdout, "Name: client")
	assert.Contains(t, stdout, "Version: 2")
	assert.Equal(t, "Warning: "+out+" holds the certificate's private key unencrypted, in the clear. Delete it when you are done.\n", stderr)
	assert.NotContains(t, stdout+stderr, "KEY-MATERIAL")
	assert.NotContains(t, stdout+stderr, "open-pass")
}

func TestExportOpen_ReadsThePassphraseFromTheEnvironment(t *testing.T) {
	dir := t.TempDir()
	sealed, _ := sealedFixture(t, dir, certPayload(), "env-pass")
	t.Setenv(common.ExportPassphraseEnvVar, "env-pass")

	_, _, err := runOpen(sealed, "--file", filepath.Join(dir, "client.pem"))
	require.NoError(t, err)
}

func TestExportOpen_RefusalsWriteNothing(t *testing.T) {
	cases := []struct {
		name  string
		setup func(t *testing.T, dir, out string) []string
		want  string
	}{
		{"wrong passphrase", func(t *testing.T, dir, out string) []string {
			sealed, _ := sealedFixture(t, dir, certPayload(), "right")
			wrong := filepath.Join(dir, "wrong")
			require.NoError(t, os.WriteFile(wrong, []byte("wrong\n"), 0o600))
			return []string{sealed, "--passphrase-file", wrong, "--file", out}
		}, "failed to open export: wrong passphrase or corrupted export file"},
		{"a sealed secrets export", func(t *testing.T, dir, out string) []string {
			sealed, err := common.SealExport([]byte(`[{"name":"db","value":"x"}]`), "p")
			require.NoError(t, err)
			path := filepath.Join(dir, "secrets.json")
			require.NoError(t, os.WriteFile(path, sealed, 0o600))
			pass := filepath.Join(dir, "pass")
			require.NoError(t, os.WriteFile(pass, []byte("p\n"), 0o600))
			return []string{path, "--passphrase-file", pass, "--file", out}
		}, "this file is not a certificate or key export; read a sealed secrets export with rocketvault secrets import"},
		{"a plain PEM file", func(t *testing.T, dir, out string) []string {
			path := filepath.Join(dir, "plain.pem")
			require.NoError(t, os.WriteFile(path, []byte(openTestContent), 0o600))
			return []string{path, "--file", out}
		}, "not a sealed RocketVault export file"},
		{"no passphrase available", func(t *testing.T, dir, out string) []string {
			sealed, _ := sealedFixture(t, dir, certPayload(), "p")
			return []string{sealed, "--file", out}
		}, "no passphrase is available: pass --passphrase-file or set ROCKETVAULT_EXPORT_PASSPHRASE"},
		{"stdout", func(t *testing.T, dir, _ string) []string {
			sealed, pass := sealedFixture(t, dir, certPayload(), "p")
			return []string{sealed, "--passphrase-file", pass, "--file", "-"}
		}, "--file must name an output file: an opened export is only ever written to a file"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Setenv(common.ExportPassphraseEnvVar, "")
			dir := t.TempDir()
			out := filepath.Join(dir, "out.pem")

			_, _, err := runOpen(c.setup(t, dir, out)...)
			assert.EqualError(t, err, c.want)
			_, statErr := os.Stat(out)
			assert.ErrorIs(t, statErr, fs.ErrNotExist)
		})
	}
}

func TestExportOpen_NeverReplacesAFileWithoutForce(t *testing.T) {
	t.Setenv(common.ExportPassphraseEnvVar, "")
	dir := t.TempDir()
	sealed, pass := sealedFixture(t, dir, certPayload(), "p")
	out := filepath.Join(dir, "client.pem")
	require.NoError(t, os.WriteFile(out, []byte("original"), 0o644))

	_, _, err := runOpen(sealed, "--file", out, "--passphrase-file", pass)
	assert.EqualError(t, err, "the output file already exists: pass --force to replace it")
	data, err := os.ReadFile(out)
	require.NoError(t, err)
	assert.Equal(t, "original", string(data))

	_, _, err = runOpen(sealed, "--file", out, "--passphrase-file", pass, "--force")
	require.NoError(t, err)
	data, err = os.ReadFile(out)
	require.NoError(t, err)
	assert.Equal(t, openTestContent, string(data))
}

// isolateRootRun runs rootCmd with args from an empty directory, with no
// config file and no cached session, and restores the global state after.
func isolateRootRun(t *testing.T, args ...string) error {
	t.Helper()
	dir := t.TempDir()
	previousBase := common.SessionBaseDir
	common.SessionBaseDir = filepath.Join(dir, "sessions")
	t.Cleanup(func() { common.SessionBaseDir = previousBase })

	origWd, err := os.Getwd()
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.Chdir(origWd) })
	require.NoError(t, os.Chdir(dir))

	previousSettings := viper.AllSettings()
	viper.Reset()
	t.Cleanup(func() {
		viper.Reset()
		_ = viper.MergeConfigMap(previousSettings)
	})

	previousArgs := os.Args
	os.Args = append([]string{"rocketvault"}, args...)
	t.Cleanup(func() { os.Args = previousArgs })

	rootCmd.SetArgs(args)
	t.Cleanup(func() { rootCmd.SetArgs(nil) })
	return rootCmd.ExecuteContext(context.Background())
}

// TestExportOpen_NeedsNoConfigSessionDatabaseOrServer runs "export open"
// through the real root command from a directory with no config file and no
// cached session, once in local mode and once with a remote target set.
func TestExportOpen_NeedsNoConfigSessionDatabaseOrServer(t *testing.T) {
	for name, extra := range map[string][]string{
		"local":  nil,
		"remote": {"--server", "https://vault.example.com"},
	} {
		t.Run(name, func(t *testing.T) {
			t.Setenv(common.ExportPassphraseEnvVar, "")
			dir := t.TempDir()
			sealed, pass := sealedFixture(t, dir, certPayload(), "p")
			out := filepath.Join(dir, "client.pem")

			args := append([]string{"export", "open", sealed, "--file", out, "--passphrase-file", pass}, extra...)
			require.NoError(t, isolateRootRun(t, args...))
			data, err := os.ReadFile(out)
			require.NoError(t, err)
			assert.Equal(t, openTestContent, string(data))
		})
	}
}

func TestIsExportGroupArgs(t *testing.T) {
	assert.True(t, isExportGroupArgs([]string{"export", "open", "f"}))
	assert.True(t, isExportGroupArgs([]string{"export"}))
	assert.False(t, isExportGroupArgs([]string{"secrets", "export"}))
	assert.False(t, isExportGroupArgs([]string{"certificates", "export", "id"}))
	assert.False(t, isExportGroupArgs([]string{"keys", "export", "id"}))
}

// TestItemExportCommands_RemoteModeIsRefused pins that both export commands
// stay behind the remote-target guard: neither group has a remote adapter.
func TestItemExportCommands_RemoteModeIsRefused(t *testing.T) {
	for _, group := range []string{"certificates", "keys"} {
		t.Run(group, func(t *testing.T) {
			out := filepath.Join(t.TempDir(), "out.pem")
			err := isolateRootRun(t, group, "export", uuid.NewString(), "--file", out,
				"--server", "https://vault.example.com")
			require.Error(t, err)
			assert.Contains(t, err.Error(), "remote mode")
			assert.Contains(t, err.Error(), "is not yet supported for \"rocketvault "+group+" export\"")
			_, statErr := os.Stat(out)
			assert.ErrorIs(t, statErr, fs.ErrNotExist)
		})
	}

	for _, group := range []string{"certificates", "keys"} {
		parent := &cobra.Command{Use: group}
		export := &cobra.Command{Use: "export"}
		parent.AddCommand(export)
		assert.False(t, isRemoteCapableCommand(export), "%s export has no remote adapter", group)
	}
}

func TestExportGroup_IsRegisteredWithOpen(t *testing.T) {
	cmd, _, err := rootCmd.Find([]string{"export", "open"})
	require.NoError(t, err)
	assert.Equal(t, "open <sealed-file>", cmd.Use)
	assert.Contains(t, rootCmd.Long, "export\nopen")
}
```

- [ ] **Step 2: Run and expect FAIL**

Run: `go test -p 2 ./cmd -run 'ExportOpen|ItemExportCommands|ExportGroup|IsExportGroupArgs' -count=1`
Expected: FAIL with a build error naming `undefined: newExportOpenCmd` and `undefined: isExportGroupArgs`.

- [ ] **Step 3: Implement**

Create `cmd/export.go`:

```go
/*
Copyright © 2025 Snehal Dangroshiya
*/

package cmd

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"rocketvault/common"
	"rocketvault/model"
)

// maxSealedExportBytes bounds a sealed export read from disk. Real
// certificate and key exports are a few KiB; anything larger is not one.
const maxSealedExportBytes = 1 << 20

// exportOutputExistsMessage is the fixed message for an output file that
// already exists when --force was not given.
const exportOutputExistsMessage = "the output file already exists: pass --force to replace it"

// exportGroupCmd groups the commands that work on export files offline.
var exportGroupCmd = &cobra.Command{
	Use:   "export",
	Short: "Work with sealed certificate and key export files",
	Long: `Work with the sealed files that "certificates export" and "keys export"
write. These commands read only local files: they need no session, no
database and no server, so they work on a machine that has nothing but the
rocketvault binary.`,
	Example: `  # Open a sealed certificate export
  rocketvault export open client.pem.sealed --file client.pem`,
	// Replace the root PersistentPreRunE. Opening an export decrypts a local
	// file; it must not open a database, require a session or be refused by
	// the remote-target guard. cmd/mcp.go uses the same pattern. Adding
	// "export" to isSystemCommand instead would also exempt "secrets export",
	// because that function matches parent names too.
	PersistentPreRunE: func(_ *cobra.Command, _ []string) error { return nil },
	Run: func(cmd *cobra.Command, args []string) {
		cmd.Help() //nolint:errcheck,gosec
	},
}

// newExportOpenCmd builds "export open". It is a constructor rather than a
// package variable so every test gets fresh flags.
func newExportOpenCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "open <sealed-file>",
		Short: "Decrypt a sealed certificate or key export",
		Long: `Decrypt a file written by "certificates export" or "keys export" with
--encrypt (the default) and write the plaintext file it holds: a PEM chain
and private key, a PKCS12 bundle, or a PEM private key, exactly as the same
export with --encrypt=false would have written it.

The passphrase is read from --passphrase-file, then the
ROCKETVAULT_EXPORT_PASSPHRASE environment variable, then a prompt. A wrong
passphrase writes nothing. A sealed "secrets export" file is refused; read
it with "rocketvault secrets import".

The output is written with 0600 permissions through a temporary file in the
same directory, and an existing file is never replaced unless --force is
given. It holds a private key, so delete it when you are done. Opening is
not audited: it touches no vault. No session, database or server is needed.`,
		Example: `  # Open a sealed certificate export, prompting for the passphrase
  rocketvault export open client.pem.sealed --file client.pem

  # Open non-interactively, replacing an earlier output
  rocketvault export open signer.pem.sealed --file signer.pem \
    --passphrase-file /run/secrets/export-pass --force`,
		Args: cobra.ExactArgs(1),
		RunE: runExportOpen,
	}
	cmd.Flags().StringP("file", "o", "", "Output file path (required)")
	cmd.Flags().String("passphrase-file", "", "Read the export passphrase from the first line of this file")
	cmd.Flags().Bool("force", false, "Replace the output file if it already exists")
	cmd.MarkFlagRequired("file") //nolint:errcheck,gosec
	return cmd
}

// runExportOpen is "export open"'s RunE.
func runExportOpen(cmd *cobra.Command, args []string) error {
	out, _ := cmd.Flags().GetString("file")
	passphraseFile, _ := cmd.Flags().GetString("passphrase-file")
	force, _ := cmd.Flags().GetBool("force")

	if out == "" || out == "-" {
		return errors.New("--file must name an output file: an opened export is only ever written to a file")
	}
	if !force {
		if _, err := os.Lstat(out); err == nil {
			return errors.New(exportOutputExistsMessage)
		}
	}

	data, err := readSealedExport(args[0])
	if err != nil {
		return err
	}
	if !common.IsSealedExport(data) {
		return errors.New("not a sealed RocketVault export file")
	}

	passphrase, err := common.ResolvePassphrase(common.PassphraseSource{
		File:   passphraseFile,
		EnvVar: common.ExportPassphraseEnvVar,
		Prompt: "Export passphrase: ",
	})
	if errors.Is(err, common.ErrNoPassphraseAvailable) {
		return fmt.Errorf("no passphrase is available: pass --passphrase-file or set %s", common.ExportPassphraseEnvVar)
	}
	if err != nil {
		return fmt.Errorf("failed to resolve export passphrase: %w", err)
	}

	p, err := common.OpenItemExport(data, passphrase)
	if errors.Is(err, common.ErrNotItemExport) {
		return errors.New("this file is not a certificate or key export; read a sealed secrets export with rocketvault secrets import")
	}
	if err != nil {
		return fmt.Errorf("failed to open export: %w", err)
	}
	defer clear(p.Content)

	if err := common.WritePrivateFile(out, p.Content, force); err != nil {
		if errors.Is(err, common.ErrOutputExists) {
			return errors.New(exportOutputExistsMessage)
		}
		return err
	}

	protection := "unencrypted, in the clear"
	if p.Format == model.ExportFormatPKCS12 {
		protection = "protected only by its PKCS12 password"
	}
	fmt.Fprintf(cmd.ErrOrStderr(), "Warning: %s holds the %s's private key %s. Delete it when you are done.\n", //nolint:errcheck
		out, p.Kind, protection)
	fmt.Fprintf(cmd.OutOrStdout(), "Export opened\nKind: %s\nName: %s\nVersion: %d\nFormat: %s\nFile: %s\n", //nolint:errcheck
		p.Kind, p.Name, p.Version, p.Format, out)
	return nil
}

// readSealedExport reads at most maxSealedExportBytes from path.
func readSealedExport(path string) ([]byte, error) {
	f, err := os.Open(filepath.Clean(path)) //nolint:gosec // G304: the path is the caller's own argument.
	if err != nil {
		return nil, fmt.Errorf("failed to read export file: %w", err)
	}
	defer f.Close() //nolint:errcheck
	data, err := io.ReadAll(io.LimitReader(f, maxSealedExportBytes+1))
	if err != nil {
		return nil, fmt.Errorf("failed to read export file: %w", err)
	}
	if len(data) > maxSealedExportBytes {
		return nil, errors.New("not a sealed RocketVault export file: it is larger than 1 MiB")
	}
	return data, nil
}

// isExportGroupArgs reports whether args select the top-level "export" group
// or one of its commands. initConfig uses it to skip the config file, which
// these commands never read. It compares command pointers, not names, so
// "secrets export" never matches.
func isExportGroupArgs(args []string) bool {
	cmd, _, err := rootCmd.Find(args)
	if err != nil || cmd == nil {
		return false
	}
	return cmd == exportGroupCmd || cmd.Parent() == exportGroupCmd
}

func init() {
	rootCmd.AddCommand(exportGroupCmd)
	exportGroupCmd.AddCommand(newExportOpenCmd())
}
```

In `cmd/root.go`, in `rootCmd.Long`, replace

```
preview-migration, vault-access roles, secrets generate-password, and the
whole context group.
```

with

```
preview-migration, vault-access roles, secrets generate-password, export
open, and the whole context group.
```

In `initConfig`, replace

```go
	// only reads/writes ~/.rocketvault/contexts.json).
	if err := viper.ReadInConfig(); err != nil && !isContextCommandArgs(os.Args[1:]) {
```

with

```go
	// only reads/writes ~/.rocketvault/contexts.json), nor for the `export`
	// group, which only decrypts local files (see cmd/export.go).
	if err := viper.ReadInConfig(); err != nil && !isContextCommandArgs(os.Args[1:]) && !isExportGroupArgs(os.Args[1:]) {
```

Do not touch `isSystemCommand`, `isLocalOnlyCommand` or `remoteCapableCommands`: the group's no-op `PersistentPreRunE` already bypasses authentication, the database and the remote guard for `export open` alone, and adding `"export"` to `isSystemCommand`'s name map would also exempt `secrets export` from authentication.

- [ ] **Step 4: Run and expect PASS**

Run: `go vet ./cmd && go test -p 2 ./cmd -count=1`
Expected: `ok  	rocketvault/cmd`. The remote-mode test prints two `Error: remote mode (...) is not yet supported for "rocketvault ... export"` lines through cobra; that output is expected.

- [ ] **Step 5: Check the binary from an empty directory**

Run:

```bash
go build -o /tmp/rv-export-check . && (cd "$(mktemp -d)" && /tmp/rv-export-check export open missing.sealed --file out.pem; echo "exit=$?") ; rm -f /tmp/rv-export-check
```

Expected: `Error: failed to read export file: open missing.sealed: no such file or directory`, the usage text, and `exit=1`; no panic about a missing config file.

- [ ] **Step 6: Lint**

Run: `BASE=$(cat .git/rv-cli-export-base); PATH="$HOME/go/pkg/mod/golang.org/toolchain@v0.0.1-go1.25.7.linux-amd64/bin:$PATH" GOTOOLCHAIN=local ~/go/bin/golangci-lint run --new-from-rev="$BASE" ./cmd/...`
Expected: `0 issues.`

- [ ] **Step 7: Commit**

Commit via the `dev-workflow-skills:1-git-commit` skill. Stage: `cmd/export.go`, `cmd/export_test.go`, `cmd/root.go`.

---

### Task 8: Documentation

**Files:**
- Modify: `docs/cli-guide.md`, `README.md`, `CLAUDE.md`, `.claude/azure-keyvault-parity.md`, `docs/mcp-server.md`, `docs/superpowers/specs/2026-10-01-certificate-and-key-export-design.md`

**Interfaces:**
- Consumes: the commands, flags and messages from Tasks 5-7, exactly as built.
- Produces: no code.

- [ ] **Step 1: `docs/cli-guide.md`, keys**

After the line

```
> Addressing an older version needs no extra permission. It's the same data action as using the current one, on a key you already have access to.
```

insert:

````markdown

### Export a key

A key created or imported with `--exportable` can be exported as an unencrypted PKCS#8 private key in PEM. You need a role assignment that grants the key export permission — `Key Vault Key Exporter` or `Key Vault Administrator`, which only a global admin can grant. No account role is needed. HSM-backed, `oct` and ES256K keys can never be exported.

```
go run main.go keys export KEY-ID-HERE --file ./signer.pem.sealed
```

The file is sealed by default, exactly like `secrets export`: the passphrase comes from `--passphrase-file`, then `ROCKETVAULT_EXPORT_PASSPHRASE`, then a prompt asked twice. Add `--version 2` for an older version, and `--vault <name>` for another vault. An existing file is never replaced unless you add `--force`. Turn the sealed file into the PEM file with `export open` (see "Open a sealed export file" below).

To write the PEM file directly, add `--encrypt=false`; the command prints a warning, because the file then holds the private key in the clear. Every attempt, allowed or refused, is recorded in the audit log.
````

- [ ] **Step 2: `docs/cli-guide.md`, certificates**

Before the line `### Delete a certificate`, insert:

````markdown
### Export a certificate and its private key

A certificate created with `--exportable` can be exported with its private key, as one PEM file (the certificate, any intermediate CA certificates, then the private key) or as a PKCS12 bundle. You need `Key Vault Certificate Exporter` or `Key Vault Administrator` on the vault; no account role is needed.

```
go run main.go certificates export CERT-ID-HERE --file ./client.pem.sealed
```

For PKCS12, add `--format pkcs12` and give the bundle's password through `--pkcs12-password-file`, the `ROCKETVAULT_PKCS12_PASSWORD` variable, or the prompt. An empty password needs `--pkcs12-empty-password`. Add `--compat legacy` for tools that cannot read the default AES-256 encoding:

```
go run main.go certificates export CERT-ID-HERE --format pkcs12 \
  --pkcs12-password-file ./p12-pass --file ./client.p12.sealed
```

The output is sealed by default, exactly like `secrets export`; `--encrypt=false` writes the PEM or PKCS12 file directly and prints a warning. `--version` exports an older version. A PEM export is one file; split it if a tool needs two:

```
openssl pkey -in client.pem -out client.key
sed -n '/BEGIN CERTIFICATE/,/END CERTIFICATE/p' client.pem > client.crt
```

### Open a sealed export file

`export open` turns a sealed certificate or key export back into the file it holds. It works offline, with no login, no database and no server, so you can run it on the machine that will use the key:

```
go run main.go export open ./client.pem.sealed --file ./client.pem
```

It asks for the passphrase (or reads `--passphrase-file` or `ROCKETVAULT_EXPORT_PASSPHRASE`), writes the file with owner-only permissions, and refuses to replace an existing file unless you add `--force`. A sealed secrets export is opened with `secrets import` instead. Delete the opened file when you are done with it.

````

- [ ] **Step 3: `README.md`**

After the lines

```
./rocketvault --username admin --password admin123 --totp-code <code> \
  keys rotate <key-id>
```

insert:

```

# Export an exportable key's private key to a sealed file
./rocketvault --username admin --password admin123 --totp-code <code> \
  keys export <key-id> --file signer.pem.sealed
```

After the lines

```
./rocketvault --username admin --password admin123 --totp-code <code> \
  certificate create --name "my-cert" --key-id <key-id> --validity-days 365
```

insert:

```

# Export an exportable certificate and its key, then open the sealed file
./rocketvault --username admin --password admin123 --totp-code <code> \
  certificate export <certificate-id> --file client.pem.sealed
./rocketvault export open client.pem.sealed --file client.pem
```

- [ ] **Step 4: `CLAUDE.md`**

After the bullet that ends with `the 2026-08-25 key-export decision record is superseded for software keys only.` insert the bullet:

```markdown
- The CLI counterpart is `rocketvault keys export <id>` (`cmd/keys/export.go`), sealed by default under the `secrets export` envelope, with `rocketvault export open` (`cmd/export.go`) to decrypt it offline. Local mode only; never an MCP tool. Design: `docs/superpowers/specs/2026-10-02-cli-certificate-and-key-export-design.md`.
```

After the bullet that ends with `and audit every attempt through \`AuditService.RecordEvent\`.` insert the bullet:

```markdown
- The CLI counterpart is `rocketvault certificates export <id>` (`cmd/certificates/export.go`, `--format pem|pkcs12`, PKCS12 password never a flag value). Both CLI export commands audit every attempt through `internal/services/exportaudit`, the package the HTTP export handlers now share for their fixed reasons and event shape.
```

Before the line `A new CLI command that skips its tier's check bypasses authorization entirely — there is no other enforcement point on the CLI path.` insert the paragraph:

```markdown
`certificates export` and `keys export` are per-vault data-plane operations (`ActionCertificatesExportItem` / `ActionKeysExport`, `OpCreate`) with no account-role gate, because the exporter roles are granted per vault to principals that typically hold only the `user` or `service_account` account role. `export open` decrypts a local file only; its group replaces the root pre-run, so it needs no session.

```

Under `## Documentation History`, before the entry starting `- **2026-10-01**: Certificate and key export`, insert:

```markdown
- **2026-10-02**: CLI certificate and key export — `rocketvault certificates
  export`, `rocketvault keys export` and the offline `rocketvault export open`,
  sealed by default like `secrets export`; shared `internal/services/exportaudit`
  for the HTTP and CLI audit events. Plan:
  `docs/superpowers/plans/2026-10-02-cli-certificate-and-key-export.md`.
```

- [ ] **Step 5: `.claude/azure-keyvault-parity.md`**

After the lines

```
- Error codes are snake_case in the R6 body
  `{"error":{"code","message"}}`, used only by the two export routes. Azure
  uses CamelCase codes such as `KeyNotFound`.
```

insert:

```markdown
- The CLI (`rocketvault certificates export`, `rocketvault keys export`)
  writes a passphrase-sealed file by default (argon2id and AES-256-GCM, the
  `secrets export` envelope), opened offline with `rocketvault export open`.
  Azure's CLI has no sealing step. Local mode only; design:
  `docs/superpowers/specs/2026-10-02-cli-certificate-and-key-export-design.md`.
```

- [ ] **Step 6: `docs/mcp-server.md`**

Before the line `## Least privilege: which role to grant`, insert:

```markdown
### Never exposed: certificate and key export

No tier, flag or configuration exposes certificate or key export as an MCP
tool, and none is planned. An export returns an unencrypted private key, and a
tool result lands in the model's context. Use `rocketvault certificates
export` or `rocketvault keys export` from a terminal instead; both seal the
file by default.

```

- [ ] **Step 7: The 2026-10-01 spec's non-goal**

In `docs/superpowers/specs/2026-10-01-certificate-and-key-export-design.md`, replace

```
- The certificate-to-secret linkage, CLI export commands, and certificate import
  or CSR merge.
```

with

```
- The certificate-to-secret linkage, and certificate import or CSR merge. CLI
  export commands were a non-goal here; they were added by
  [2026-10-02-cli-certificate-and-key-export-design.md](2026-10-02-cli-certificate-and-key-export-design.md).
```

- [ ] **Step 8: Check the documented commands against the build**

Run:

```bash
go build -o /tmp/rv-doc-check .
FLAGS='--(file|encrypt|passphrase-file|force|format|compat|version|pkcs12-password-file|pkcs12-empty-password) '
/tmp/rv-doc-check certificates export --help | sed -n '/^Flags:/,/^Global Flags:/p' | grep -cE -- "$FLAGS"
/tmp/rv-doc-check keys export --help | sed -n '/^Flags:/,/^Global Flags:/p' | grep -cE -- "$FLAGS"
/tmp/rv-doc-check export open --help | sed -n '/^Flags:/,/^Global Flags:/p' | grep -cE -- "$FLAGS"
rm -f /tmp/rv-doc-check
```

Expected: `9`, `5` and `3`: every flag the docs name exists on its command. `--help` returns before cobra runs `initConfig`, so this works without a config file.

- [ ] **Step 9: Commit**

Commit via the `dev-workflow-skills:1-git-commit` skill. Stage: `docs/cli-guide.md`, `README.md`, `CLAUDE.md`, `.claude/azure-keyvault-parity.md`, `docs/mcp-server.md`, `docs/superpowers/specs/2026-10-01-certificate-and-key-export-design.md`.

---

### Task 9: Regression gate and isolated-instance smoke test

**Files:**
- Modify: `docs/superpowers/specs/2026-10-02-cli-certificate-and-key-export-design.md` (status line only, Step 6).

**Interfaces:**
- Consumes: Tasks 1-8.
- Produces: the evidence the spec's hard gates require.

- [ ] **Step 1: Build, vet and test everything**

Run: `go build ./... && go vet ./... && go test -p 2 ./... -count=1`
Expected: every package `ok` or `no test files`. A failing pre-existing test is fixed in the code under change, never by editing or deleting the test.

- [ ] **Step 2: Lint everything changed since the base**

Run: `BASE=$(cat .git/rv-cli-export-base); PATH="$HOME/go/pkg/mod/golang.org/toolchain@v0.0.1-go1.25.7.linux-amd64/bin:$PATH" GOTOOLCHAIN=local ~/go/bin/golangci-lint run --new-from-rev="$BASE" ./...`
Expected: `0 issues.`

- [ ] **Step 3: Confirm the untouched surfaces did not move**

Run:

```bash
BASE=$(cat .git/rv-cli-export-base)
git diff --stat "$BASE" -- internal/services/certificates internal/services/keys internal/middleware internal/db model \
  api/keys_export.go cmd/secrets internal/mcpserver internal/vaultapi internal/cliclient
git diff --diff-filter=MD --name-only "$BASE" -- '*_test.go'
git diff "$BASE" --stat -- cmd/root.go cmd/certificates.go cmd/keys.go api/export.go common/passphrase.go
grep -rn "ExportCertificate\|ExportKey\|export_certificate\|export_key" internal/mcpserver internal/vaultapi
```

Expected: the first two commands and the `grep` print nothing (no service, route, policy, schema, secrets-command, MCP or client change; no pre-existing test modified or deleted; no MCP export tool). The third shows small diffs only: `cmd/root.go` 5 insertions and 4 deletions, `cmd/certificates.go` 3 and 1, `cmd/keys.go` 4 and 2, `common/passphrase.go` 8 and 1, `api/export.go` 35 and 56 (the import block and the three function bodies).

- [ ] **Step 4: Smoke test on an isolated instance**

Never use `dev-rocketvault.db`, and keep `HOME` pointed at the scratch directory for every command: `users login` writes `~/.rocketvault/sessions/<server>__<user>.json` and `current`, and the smoke admin is named `admin`, so the real `HOME` would overwrite the developer's own cached session.

```bash
SMOKE=$(mktemp -d /tmp/rv-cli-export-smoke.XXXXXX); mkdir -p "$SMOKE/home"
go build -o "$SMOKE/rocketvault" .
cp .rocketvault.yaml.example "$SMOKE/smoke.yaml"
sed -i "s|^master_key:.*|master_key: \"$(openssl rand -base64 32)\"|; s|^bootstrap_token:.*|bootstrap_token: \"$(openssl rand -base64 32)\"|; s|connection: \"./dev-rocketvault.db\"|connection: \"$SMOKE/smoke.db\"|" "$SMOKE/smoke.yaml"
rv() { HOME="$SMOKE/home" "$SMOKE/rocketvault" --config "$SMOKE/smoke.yaml" "$@"; }
rv users admin --admin-username=admin --admin-password='Smoke-Test-1!' --bootstrap-token="$(sed -n 's/^bootstrap_token: "\(.*\)"/\1/p' "$SMOKE/smoke.yaml")"
# Use the printed secret: ROCKETVAULT_TOTP_SECRET=<secret> go run scripts/totp_generator.go
rv users login --username admin --password 'Smoke-Test-1!' --totp-code <code>
rv vault-access grant admin --role "Key Vault Administrator" --vault default
rv vault-access grant admin --role "Key Vault Key Exporter" --vault default
rv vault-access grant admin --role "Key Vault Certificate Exporter" --vault default
rv keys create --name exp-key --type RSA --bits 2048 --exportable --output json
rv keys create --name plain-key --type RSA --bits 2048 --output json
rv certificate create --name exp-cert --key-id <exp-key id> --validity-days 30 --exportable --output json
echo smoke-pass > "$SMOKE/pass"; chmod 600 "$SMOKE/pass"
```

Then:

```bash
rv keys export <exp-key id> --file "$SMOKE/out/k.pem.sealed" --passphrase-file "$SMOKE/pass"
rv export open "$SMOKE/out/k.pem.sealed" --file "$SMOKE/out/k.pem" --passphrase-file "$SMOKE/pass"
openssl pkey -in "$SMOKE/out/k.pem" -noout && head -1 "$SMOKE/out/k.pem"
rv certificates export <exp-cert id> --file "$SMOKE/out/c.pem" --encrypt=false
openssl x509 -in "$SMOKE/out/c.pem" -noout -subject && openssl pkey -in "$SMOKE/out/c.pem" -noout
ROCKETVAULT_EXPORT_PASSPHRASE=smoke-pass rv certificates export <exp-cert id> --format pkcs12 --pkcs12-empty-password --file "$SMOKE/out/c.p12.sealed"
rv export open "$SMOKE/out/c.p12.sealed" --file "$SMOKE/out/c.p12" --passphrase-file "$SMOKE/pass"
openssl pkcs12 -in "$SMOKE/out/c.p12" -info -nokeys -passin pass:
rv keys export <plain-key id> --file "$SMOKE/out/p.pem" --encrypt=false; echo "exit=$?"
rv certificates export <exp-cert id> --file "$SMOKE/out/r.pem" --server https://127.0.0.1:1; echo "exit=$?"
ls -la "$SMOKE/out"
sqlite3 "$SMOKE/smoke.db" "select source, outcome, details from audit_logs where action like 'export_%' order by timestamp"
sqlite3 "$SMOKE/smoke.db" "select count(*) from audit_logs where details like '%PRIVATE KEY%' or details like '%smoke-pass%'"
```

Expected, in order: `Key exported successfully` with `Encryption: passphrase (argon2id + AES-256-GCM)`; `Export opened` and a stderr warning; `openssl pkey` succeeds and the key starts with `-----BEGIN PRIVATE KEY-----`; the certificate warning and `Encryption: none (plaintext)`; `subject=CN = exp-cert` and the key parses; the PKCS12 export and open succeed and `openssl pkcs12 -info` shows `PBES2, PBKDF2, AES-256-CBC`; `failed to export key: key is not exportable: the key was not created with exportable: true` with `exit=1` and no `p.pem`; the remote-mode refusal with `exit=1` and no `r.pem`; every file in `out` is `-rw-------` and `out` itself `drwx------`; `cli` rows with fixed `details` (and `system` rows from the services' legacy log), and a count of `0`. `rocketvault audit logs --action ...` also works, but its "hash chain integrity check failed" warning on any filtered query is pre-existing and unrelated: `verifyChain` compares rows that are not chain neighbours once a filter is applied.

Finally `rm -rf "$SMOKE"` (it holds private keys).

- [ ] **Step 5: Report**

Record the outcome of Steps 1-4 in the hand-off report, with the commit hashes. Nothing to commit for Steps 1-4.

- [ ] **Step 6: Mark the spec implemented**

In `docs/superpowers/specs/2026-10-02-cli-certificate-and-key-export-design.md`, replace `**Status**: Proposed` with `**Status**: Implemented on v-4.0.0 (<today's date, YYYY-MM-DD>)`. Commit via the `dev-workflow-skills:1-git-commit` skill, staging only that file. If Steps 1-4 needed a fix, commit the fix first, staging only the fixed files.

---

## Self-Review

- **Spec coverage:** §1 commands and flags (Tasks 5, 6, flags pinned by `TestInitCertificatesExport_RegistersTheCommandAndFlags` and `TestInitKeysExport_RegistersTheCommandAndFlags`); §2 sealed default, passphrase order, envelope and payload, plaintext warning, atomic 0600 write, no clobber, 0700 directories, `--file -` refused, status block (Tasks 1, 4, 5, 6); §3 `export open`, offline, no-op pre-run, `initConfig` exemption, refusals (Task 7); §4 PKCS12 password sources, empty only by flag, flag conflicts, confirm prompt (Tasks 1, 5); §5 data-plane authorization with `OpCreate`, explicit deny, no account role, validation before authorization, prompts after it (Tasks 5, 6); §6 `exportaudit` with what moves out of `api`, `ExportAttempt` one event per attempt, fixed reasons, no secrets in logs (Tasks 2, 3, 4, 5, 6); §7 remote mode refused and pinned (Task 7); §8 order of operations, fixed messages, exit 1 (Tasks 4-6, smoke Step 4); §9 MCP (Task 8, gate Step 3); Testing list (Tasks 1-7); Regression safety (Task 9 Steps 1-3); Documentation (Task 8); smoke test with isolated `HOME` (Task 9 Step 4).
- **Verified against the repo at 68225fce** (HEAD when this plan was written; none of the files it touches differ from 510e032b): every new file and every edit in this plan was applied to a scratch copy of the committed tree, and `go build ./...`, `go vet ./...`, `go test -p 2 ./... -count=1` and golangci-lint (go1.25.7, the touched packages) passed there; the built binary ran the Task 9 smoke flow end to end. Cited symbols exist as used: `vaultcli.Caller`, `vaultcli.Op{Audit, Action, Policy, AuthzFailMsg}`, `Session.Authorize`, `vaultcli.CtxContainer`, `vaultcli.ResolveVaultID`, `common.ResolvePassphrase`, `common.ErrNoPassphraseAvailable`, `common.SealExport`, `common.OpenExport`, `common.IsSealedExport`, `common.SessionBaseDir`, `CertificateService.ExportCertificate`, `KeyService.ExportKey`, `model.ActionCertificatesExportItem`, `model.ActionKeysExport`, `model.OpCreate`, `model.PolicyResourceCertificates`, `model.PolicyResourceKeys`, `authorization.AccessDenied`, `testutils.NewTestContext`, `testutils.MockRoleAssignmentService`, `testutils.MockAccessPolicyService`, `certCmdCertService.ExportCertificate`, `keyCmdKeyService.ExportKey`, `certsTestContainer`, `keysTestContainer`, `rootCmd`, `isRemoteCapableCommand`, `isContextCommandArgs`.
- **Type consistency:** `ItemExportPayload{PayloadVersion, Kind, ID, Name, Version, Format, KeyAlgorithm, Content}`; `exportaudit.Failure{Kind, Code, Message, Reason, Name, KeyAlgorithm}`; `exportaudit.Attempt{UserID, ResourceType, ResourceID, VaultID, Name, Version, Format, Outcome, Code, Reason, IPAddress, Source}`; `ExportOutput{File, Encrypt, PassphraseFile, Force}`; `BeginExportAttempt(s, resourceType, rawID, format, version)`; `ExportOutput.Write(cmd, payload, passphrase, warning)`; `ExportOutput.PrintStatus(cmd, label, name, version, format)`.
- **Known limits, stated rather than hidden:** the terminal prompt paths (`promptPassphrase` with `ConfirmPrompt`, the PKCS12 prompt) are not unit-tested, as today, because `go test` runs without a terminal; Go strings returned by the services cannot be zeroed, only the payload slice is cleared; the services' own legacy `LogAuditInfo`/`LogAuditError` rows still exist beside the structured event, as on the HTTP path.
