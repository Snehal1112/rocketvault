# Key Export and Export Documentation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let a principal holding Key Vault Key Exporter fetch one exportable, software-backed key (optionally one version) as unencrypted PKCS#8 PEM over `POST .../keys/{key_id}/export` on both route shapes, then document the whole export feature (API, mTLS example, parity, the amended key-export decision record, the renamed bulk-export action, role counts, caveats) and run the final regression and upgrade-smoke gates.

**Architecture:** `KeyService.ExportKey` sits beside `GetPublicJWK`: it reads through `GetKey` (scope and lifecycle gate), refuses `pkcs11:`, `oct`, non-exportable and ES256K keys with `model.ExportRefusedError`, resolves the version through `CurrentVersion` and `ReadVersionValue`, decrypts and re-marshals with `crypto.MarshalPKCS8PrivateKeyPEM`. The handler reuses plan 2's export helpers in `api/export.go` (R6 errors, `no-store` headers, per-attempt audit); the retry wrapper passes `ExportKey` straight through and the decrypted-key cache is never touched.

**Tech Stack:** Go 1.25, SQLite, Gorilla Mux, testify, mockery v2.53.6, OpenSSL 3 (manual smoke test only).

**Spec:** `docs/superpowers/specs/2026-10-01-certificate-and-key-export-design.md` (intent: `docs/superpowers/intents/2026-10-01-certificate-and-key-export.md`).

**Plan series:** plan 3 of 3. It requires plans 1 and 2 to be fully landed and consumes exactly these symbols:
- From plan 1 (`docs/superpowers/plans/2026-10-01-export-flag-roles-creation.md`): `model.Key.Exportable`, `model.Key.KeyAlgorithm()`, `model.Certificate.Exportable`, `keys.CreateKeyRequest.Exportable`, `model.ActionKeysExport`, `model.ActionCertificatesExportItem`, `model.RoleKeyVaultKeyExporter`, `model.RoleKeyVaultCertificateExporter`, `model.ErrExportableKeyRequired`, `model.ErrExportableNotSupported`, and the `MapRouteToDataAction` mapping of `POST /keys/{id}/export`.
- From plan 2 (`docs/superpowers/plans/2026-10-01-certificate-export.md`): `model.ExportFormatPEM`, `model.ErrInvalidExportRequest`, `model.ErrKeyNotExportable`, `model.ExportRefusedError`, `crypto.MarshalPKCS8PrivateKeyPEM`, `crypto.ErrNotPKCS8Encodable`; in `api/export.go`: `setExportHeaders`, `writeExportError`, `exportFailure`, `exportFailureFor`, `badExportRequest`, `decodeExportBody`, `exportCaller`, `exportAudit`, `recordExportAudit`; in `api/export_test.go`/`api/export_chain_test.go`: `captureAudit`, `newExportCtx`, `decodeExportError`, `newExportChain`, `postExport`; in `internal/services/retry/retry_export_test.go`: `failingRetryService`; the routes `POST .../certificates/{certificate_id}/export`.

## Global Constraints

Binding requirements copied from the spec, one per line:

- `KeyService.ExportKey(ctx, scope, id, version int)`, built beside `GetPublicJWK`: read through `GetKey` (scope and lifecycle gate), reject `pkcs11:` and `oct` keys, require `exportable`, resolve the version (0 or current uses the current value; an older number uses `ReadVersionValue` after the scoped read), decrypt, re-marshal to PKCS#8 PEM.
- ES256K and other unencodable types: 403 `key_not_exportable`.
- Routes: `POST /api/v1/vaults/{vault_name}/keys/{key_id}/export` and `POST /api/v1/keys/{key_id}/export`.
- Key request body `{"format":"pem","version"}` (empty body allowed). Unknown `format`: 400.
- Key response `{id, name, type, version, format:"pem", private_key_pem, key_algorithm}`, plain JSON, no `Content-Disposition`, under 64 KiB, with `Cache-Control: no-store` and `Pragma: no-cache`.
- Errors use `{"error":{"code","message"}}` through the local helper: 400 `bad_request`, 403 `key_not_exportable`, 404 `not_found`, 409 `key_disabled`. The 401 and the missing-role 403 keep their middleware bodies. No key material or password in messages; internal failures return a generic message.
- `certcache` and the retry wrapper pass `ExportCertificate` and `ExportKey` straight through: no cache fill, no cache hit, no retry of a failed call.
- Every attempt, allowed or denied, writes a structured `AuditService.RecordEvent` with `ResourceID` set.
- Amend the 2026-08-25 key-export decision record: its status becomes "Superseded for software keys"; HSM keys stay non-extractable (`CKA_EXTRACTABLE: false`).
- Azure exposes neither per-item certificate key export nor key export. Both are RocketVault additions, marked with the parity doc's `➕` convention; the key-export row at `.claude/azure-keyvault-parity.md:51` is rewritten to state software keys are exportable only when created exportable.
- Documentation: `docs/api-specification.yaml` and `docs/api-routes.generated.txt` (both route shapes), the role enum, `docs/api-developer-guide.md`, `docs/integration-examples.md` (mTLS client identity example), `.claude/azure-keyvault-parity.md` (key-export row, certificate rows, role table, counts), the amended key-export decision record, rename of the bulk-export design's action to avoid a clash, the "eleven roles" mentions, and `CLAUDE.md`. Documented caveats: export reflects the certificate until renewal after a key rotation, restore loses exportability, and existing items are permanently non-exportable.

Regression safety (the spec's whole section, binding):

- **Existing data stays safe and unchanged.** The migration only adds a column with `DEFAULT FALSE`. Every existing certificate and key reads as non-exportable, and nothing is backfilled or rewritten. An upgrade test opens a database created by the pre-export build and checks that existing certificates, versions, keys, secrets and role assignments are all intact and readable.
- **Existing API responses only gain fields.** `CertificateResponse` and `KeyResponse` gain `exportable` and `key_algorithm`; no existing field is renamed, removed or retyped, and no existing status code or error body changes (the R6 body is used only on the new export routes). Golden-response tests for create, get, list and update pin this, and `openapi_drift_test` and the route contract tests pass.
- **No existing role gains export.** A role-matrix test asserts that the effective data actions of every pre-existing built-in role are exactly what they were before (only the two new roles and Administrator hold the new actions). Existing role assignments, the grant allow-list and global-admin behavior are unchanged. The role-count updates ("eleven" to thirteen) are the only edits to existing role code.
- **Existing creation and update paths behave the same.** A create without `exportable` produces exactly what it produced before (non-exportable); update, rotate, renew, versions, soft-delete, recover and purge behave as before, and the existing suites for them pass unmodified except where a count or a new field is asserted.
- **Backup, restore and rekey stay compatible.** Blobs written before this change restore unchanged (as non-exportable); a restore never grants exportability; master-key rotation and the backup table order are unaffected.
- **No new weakness in the old surfaces.** Caching, retry and logging behavior of existing methods is unchanged; the new methods are pass-through only, and the existing middleware and policy chain is not modified beyond the new route mappings (unmapped paths still fail closed).
- **Hard gates before reporting done:** `go build ./...`, `go vet ./...` and `go test ./... -count=1` pass with no failing package; the pre-existing tests are not weakened or deleted to make room; and a live smoke test on an isolated instance upgrades a database from the pre-export build and exercises the existing certificate, key, secret and role flows before the new export flows.

Repository conventions for this series:

- Schema changes are dual-written; this plan adds none.
- No new data actions beyond `ActionCertificatesExportItem` and `ActionKeysExport`. Unmapped paths still fail closed.
- Metadata responses never carry material; only the export success bodies do.
- Every new route is registered on both the flat and the vault-scoped router (`registerKeyRoutes`).
- `docs/api-specification.yaml` and `docs/api-routes.generated.txt` cover both route shapes; `TestOpenAPISpecCoversAllRoutes` and `TestGenerateRouteInventory` pass.
- Commits go through the `dev-workflow-skills:1-git-commit` plugin skill (Skill tool), never a freeform `git commit -m`. Commits are GPG signed (key 61D246B30285ED35).
- Code comments are short full sentences ending with a punctuation mark.
- mockery fails under the default go1.27 toolchain. Regenerate with `PATH="$HOME/go/pkg/mod/golang.org/toolchain@v0.0.1-go1.25.7.linux-amd64/bin:$PATH" GOTOOLCHAIN=local ~/go/bin/mockery` from the repo root (mockery v2.53.6 in `~/go/bin`; never run `mockery --version`, it starts a generation run).
- Run tests with `-p 2`; prefix `GOMAXPROCS=1` if the sandbox hits `newosproc`.
- `ExportKey` never reads or fills `keycache`; the cache holds decrypted material for crypto operations only.
- `Context.SetConflict` already exists; the export handlers never set `c.Err`.
- Do not edit `docs/superpowers/plans/2026-08-25-certificate-export.md` (the old bulk-export plan). The rename touches only the bulk-export design spec.

## Review Focus

1. **An HSM or oct key exported through an archived version.** A key's current value can be software while an older version is a `pkcs11:` handle, or the reverse. The refusal must check the resolved version's stored value, not only the row. Pin: `TestExportKey_ArchivedHSMVersionIsRefused` (Task 1).
2. **Export bypassing the lifecycle gate.** Reading through the repository instead of `GetKey` would export a disabled or expired key. Pin: `TestExportKey_Refusals` (Task 1).
3. **The decrypted-key cache filled by an export.** `GetPublicJWK`'s neighbours use `keyCache`; copying their pattern would leave plaintext in memory longer. Pin: `TestExportKey_NeverTouchesTheKeyCache` (Task 1).
4. **The key route answering in the flat error shape or without `no-store`.** Pin: `TestExportKeyHandler_ErrorBodiesAreR6` (Task 2).
5. **The docs claiming parity numbers that do not add up.** The scorecard counts rows by status; a ➕ row added in the wrong column silently shifts the percentages. Pin: Task 4 Step 6 recounts the table with `grep` and checks the totals line.

---

## File Structure

| File | Responsibility |
|---|---|
| `internal/services/keys/key_export.go` (create) | `ExportKeyResult`, `ExportKey` |
| `internal/services/keys/key_service.go` (modify) | interface method |
| `internal/services/retry/retry_key_service.go` (modify) | pass-through |
| `internal/services/keys/mocks/mock_KeyService.go` (regenerate) | mockery |
| key-service fakes (modify) | `ExportKey` stubs |
| `api/keys_export.go` (create) | `exportKey` handler and types |
| `api/keys.go` (modify) | route registration |
| `docs/api-specification.yaml`, `docs/api-routes.generated.txt` | key export paths |
| `docs/api-developer-guide.md`, `docs/integration-examples.md` | export reference, mTLS example |
| `.claude/azure-keyvault-parity.md` | rows, role table, counts |
| `docs/superpowers/specs/2026-08-25-key-export-decision-record.md` | amendment |
| `docs/superpowers/specs/2026-08-25-certificate-export-design.md` | action rename |
| `CLAUDE.md` | pointer and history |

---

### Task 1: `KeyService.ExportKey`, interface, retry pass-through, fakes and mock

**Files:**
- Create: `internal/services/keys/key_export.go`
- Modify: `internal/services/keys/key_service.go:116-180` (interface, after `GetPublicJWK`)
- Modify: `internal/services/retry/retry_key_service.go` (append after `GetPublicJWK`, `:172-176`)
- Regenerate: `internal/services/keys/mocks/mock_KeyService.go`
- Modify fakes: `api/vault_scoped_keys_certs_test.go` (`recordingKeyService`, `:29`), `api/keys_crud_test.go` (`mockKeyService`, `:51`), `cmd/keys/update_test.go` (`MockKeyServiceForUpdate`, `:19`), `cmd/keys/keys_cmd_test.go` (`keyCmdKeyService`, `:58`)
- Test: `internal/services/keys/key_export_test.go` (create), `internal/services/retry/retry_key_export_test.go` (create)

**Interfaces:**
- Consumes: `GetKey`, `pkcs11Prefix` (`crypto_service.go:188`), `keyRepo.CurrentVersion`, `keyRepo.ReadVersionValue`, `common.DecryptSecret`, `crypto.ParsePrivateKey`, `crypto.MarshalPKCS8PrivateKeyPEM`, `crypto.ErrNotPKCS8Encodable`, `model.ExportRefusedError`, `model.ErrKeyNotExportable`, `model.ErrInvalidExportRequest`, `setupKeyTestMasterKey`, `newKeyLogger`, `failingRetryService`.
- Produces:
  - `type ExportKeyResult struct { ID uuid.UUID; Name, Type string; Version int; Format string; PrivateKeyPEM string; KeyAlgorithm string }`
  - `KeyService.ExportKey(ctx context.Context, scope model.Scope, id uuid.UUID, version int) (*ExportKeyResult, error)`
  - Errors: `model.ErrInvalidExportRequest` (400), `ErrKeyNotFound`/`model.ErrKeyVersionNotFound` (404), `ErrKeyLifecycleDenied` (409), `*model.ExportRefusedError` wrapping `model.ErrKeyNotExportable` (403), anything else (500).

- [ ] **Step 1: Write the failing tests**

Create `internal/services/keys/key_export_test.go`:

```go
package keys

import (
	"context"
	"crypto/x509"
	"database/sql"
	"encoding/pem"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	_ "github.com/mattn/go-sqlite3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"rocketvault/internal/crypto"
	rvdb "rocketvault/internal/db"
	"rocketvault/internal/keycache"
	"rocketvault/internal/repositories"
	"rocketvault/model"
)

type keyExportHarness struct {
	raw   *sql.DB
	repo  repositories.KeyRepositoryInterface
	svc   KeyService
	scope model.Scope
	vault uuid.UUID
	user  uuid.UUID
}

func newKeyExportHarness(t *testing.T, cache keycache.Cache) *keyExportHarness {
	t.Helper()
	setupKeyTestMasterKey()
	raw, err := sql.Open("sqlite3", "file:keyexp_"+uuid.NewString()+"?mode=memory&cache=shared")
	require.NoError(t, err)
	t.Cleanup(func() { raw.Close() }) //nolint:errcheck,gosec
	require.NoError(t, rvdb.NewRepository(newKeyLogger()).SetupSchema(raw, rvdb.SQLite))
	repo := repositories.NewKeyRepository(rvdb.NewConn(raw, rvdb.SQLite), newKeyLogger())
	vault, user := uuid.New(), uuid.New()
	return &keyExportHarness{
		raw: raw, repo: repo, vault: vault, user: user, scope: model.NewVaultScope(vault, user),
		svc: NewKeyService(KeyServiceConfig{KeyRepository: repo, KeyProvider: crypto.NewSoftwareKeyProvider(), KeyCache: cache, Logger: newKeyLogger()}),
	}
}

func (h *keyExportHarness) create(t *testing.T, keyType, curve string, exportable bool) uuid.UUID {
	t.Helper()
	req := CreateKeyRequest{Name: "k-" + uuid.NewString()[:8], Type: keyType, UserID: h.user, VaultID: h.vault, Exportable: exportable}
	var res *CreateKeyResult
	var err error
	if keyType == "RSA" {
		req.Bits = 2048
		res, err = h.svc.CreateRSAKey(context.Background(), req)
	} else {
		req.Curve = curve
		res, err = h.svc.CreateECDSAKey(context.Background(), req)
	}
	require.NoError(t, err)
	return res.KeyID
}

func TestExportKey_SoftwareRSAAndEC(t *testing.T) {
	h := newKeyExportHarness(t, nil)
	for _, tc := range []struct{ keyType, curve, alg string }{{"RSA", "", "RSA-2048"}, {"ECDSA", "P-384", "EC-P384"}} {
		id := h.create(t, tc.keyType, tc.curve, true)
		res, err := h.svc.ExportKey(context.Background(), h.scope, id, 0)
		require.NoError(t, err)
		assert.True(t, strings.HasPrefix(res.PrivateKeyPEM, "-----BEGIN PRIVATE KEY-----\n"), "exact PKCS#8 prefix")
		assert.Equal(t, tc.alg, res.KeyAlgorithm)
		assert.Equal(t, 1, res.Version)
		assert.Equal(t, model.ExportFormatPEM, res.Format)

		block, _ := pem.Decode([]byte(res.PrivateKeyPEM))
		_, err = x509.ParsePKCS8PrivateKey(block.Bytes)
		require.NoError(t, err)

		jwk, err := h.svc.GetPublicJWK(context.Background(), id, 0, h.scope)
		require.NoError(t, err)
		assert.True(t, jwk.N != "" || jwk.X != "", "the exported key is the key the JWK describes")
	}
}

func TestExportKey_Refusals(t *testing.T) {
	h := newKeyExportHarness(t, nil)
	ctx := context.Background()
	refusedWith := func(err error, reason string) {
		t.Helper()
		var refusal *model.ExportRefusedError
		require.True(t, errors.As(err, &refusal), "%v", err)
		assert.ErrorIs(t, err, model.ErrKeyNotExportable)
		assert.Contains(t, refusal.Reason, reason)
		assert.NotEmpty(t, refusal.KeyAlgorithm)
	}

	plain := h.create(t, "RSA", "", false)
	_, err := h.svc.ExportKey(ctx, h.scope, plain, 0)
	refusedWith(err, "exportable")

	es := h.create(t, "ECDSA", "P-256K", true)
	_, err = h.svc.ExportKey(ctx, h.scope, es, 0)
	refusedWith(err, "ES256K")

	hsm := uuid.New()
	require.NoError(t, h.repo.Create(ctx, &model.Key{ID: hsm, UserID: h.user, VaultID: h.vault, Name: "hsm", Type: model.KeyTypeRSA,
		Value: "pkcs11:" + uuid.NewString(), Enabled: true, CreatedAt: time.Now(), Bits: 2048, Exportable: true}))
	_, err = h.svc.ExportKey(ctx, h.scope, hsm, 0)
	refusedWith(err, "HSM")

	oct := uuid.New()
	require.NoError(t, h.repo.Create(ctx, &model.Key{ID: oct, UserID: h.user, VaultID: h.vault, Name: "oct", Type: model.KeyTypeOct,
		Value: "pkcs11:" + uuid.NewString(), Enabled: true, CreatedAt: time.Now(), Bits: 256, Exportable: true}))
	_, err = h.svc.ExportKey(ctx, h.scope, oct, 0)
	refusedWith(err, "oct")

	disabled := h.create(t, "RSA", "", true)
	off := false
	require.NoError(t, h.svc.UpdateKey(ctx, UpdateKeyRequest{KeyID: disabled, Scope: h.scope, Enabled: &off}))
	_, err = h.svc.ExportKey(ctx, h.scope, disabled, 0)
	require.ErrorIs(t, err, ErrKeyLifecycleDenied)

	// Stored directly, so the test does not depend on what UpdateKey accepts
	// for a past expiry.
	expired := uuid.New()
	past := time.Now().Add(-time.Hour)
	require.NoError(t, h.repo.Create(ctx, &model.Key{ID: expired, UserID: h.user, VaultID: h.vault, Name: "expired", Type: model.KeyTypeRSA,
		Value: "enc", Enabled: true, CreatedAt: time.Now().Add(-2 * time.Hour), ExpiresAt: &past, Bits: 2048, Exportable: true}))
	_, err = h.svc.ExportKey(ctx, h.scope, expired, 0)
	require.ErrorIs(t, err, ErrKeyLifecycleDenied)

	_, err = h.svc.ExportKey(ctx, h.scope, uuid.New(), 0)
	require.ErrorIs(t, err, ErrKeyNotFound)
	ok := h.create(t, "RSA", "", true)
	_, err = h.svc.ExportKey(ctx, model.NewVaultScope(uuid.New(), h.user), ok, 0)
	require.ErrorIs(t, err, ErrKeyNotFound, "another vault sees nothing")

	_, err = h.svc.ExportKey(ctx, h.scope, ok, -1)
	require.ErrorIs(t, err, model.ErrInvalidExportRequest)
}

func TestExportKey_ArchivedVersion(t *testing.T) {
	h := newKeyExportHarness(t, nil)
	ctx := context.Background()
	id := h.create(t, "RSA", "", true)
	first, err := h.svc.ExportKey(ctx, h.scope, id, 0)
	require.NoError(t, err)

	_, err = h.svc.RotateKey(ctx, id, h.scope)
	require.NoError(t, err)

	v1, err := h.svc.ExportKey(ctx, h.scope, id, 1)
	require.NoError(t, err)
	assert.Equal(t, first.PrivateKeyPEM, v1.PrivateKeyPEM, "an archived version exports its own material")
	assert.Equal(t, 1, v1.Version)

	current, err := h.svc.ExportKey(ctx, h.scope, id, 0)
	require.NoError(t, err)
	assert.Equal(t, 2, current.Version)
	assert.NotEqual(t, first.PrivateKeyPEM, current.PrivateKeyPEM)

	explicit, err := h.svc.ExportKey(ctx, h.scope, id, 2)
	require.NoError(t, err)
	assert.Equal(t, current.PrivateKeyPEM, explicit.PrivateKeyPEM, "the current number equals 0")

	_, err = h.svc.ExportKey(ctx, h.scope, id, 3)
	require.ErrorIs(t, err, model.ErrKeyVersionNotFound)
}

// TestExportKey_ArchivedHSMVersionIsRefused pins Review Focus 1: the stored
// value of the resolved version decides, not only the row's current value.
func TestExportKey_ArchivedHSMVersionIsRefused(t *testing.T) {
	h := newKeyExportHarness(t, nil)
	ctx := context.Background()
	id := h.create(t, "RSA", "", true)
	_, err := h.svc.RotateKey(ctx, id, h.scope)
	require.NoError(t, err)
	_, err = h.raw.Exec("UPDATE key_versions SET value = ? WHERE key_id = ? AND version = 1", "pkcs11:"+uuid.NewString(), id.String())
	require.NoError(t, err)

	_, err = h.svc.ExportKey(ctx, h.scope, id, 1)
	require.ErrorIs(t, err, model.ErrKeyNotExportable)
}

// spyKeyCache records every use of the decrypted-key cache.
type spyKeyCache struct{ gets, sets int }

func (s *spyKeyCache) Get(uuid.UUID, int) (*keycache.Entry, bool) { s.gets++; return nil, false }
func (s *spyKeyCache) Set(uuid.UUID, int, *keycache.Entry)      { s.sets++ }
func (s *spyKeyCache) Invalidate(uuid.UUID)                      {}
func (s *spyKeyCache) InvalidateAll()                            {}
func (s *spyKeyCache) Stats() keycache.CacheStats                { return keycache.CacheStats{} }
func (s *spyKeyCache) Stop()                                     {}

func TestExportKey_NeverTouchesTheKeyCache(t *testing.T) {
	spy := &spyKeyCache{}
	h := newKeyExportHarness(t, spy)
	id := h.create(t, "RSA", "", true)
	for i := 0; i < 2; i++ {
		_, err := h.svc.ExportKey(context.Background(), h.scope, id, 0)
		require.NoError(t, err)
	}
	assert.Zero(t, spy.gets)
	assert.Zero(t, spy.sets)
}
```

If `keycache.Cache` has methods beyond the six at `internal/keycache/cache.go:78-91`, add no-op versions to `spyKeyCache`.

Create `internal/services/retry/retry_key_export_test.go`:

```go
package retry

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"rocketvault/internal/services/keys/mocks"
	"rocketvault/model"
)

func TestRetryExportKey_IsNotRetried(t *testing.T) {
	inner := mocks.NewMockKeyService(t)
	scope := model.NewVaultScope(uuid.New(), uuid.New())
	id := uuid.New()
	inner.On("ExportKey", mock.Anything, scope, id, 0).Return(nil, errors.New("database is locked")).Once()

	svc := NewRetryKeyService(inner, failingRetryService{})
	_, err := svc.ExportKey(context.Background(), scope, id, 0)
	require.Error(t, err)
	inner.AssertNumberOfCalls(t, "ExportKey", 1)
}
```

- [ ] **Step 2: Run and expect FAIL**

Run: `go test -p 2 ./internal/services/keys ./internal/services/retry -run 'ExportKey' -v`
Expected: FAIL (build error: `ExportKey` undefined).

- [ ] **Step 3: Implement**

Add to the `KeyService` interface after `GetPublicJWK`:

```go
	// ExportKey returns one version of an exportable, software-backed key as
	// unencrypted PKCS#8 PEM, authorized by scope through GetKey. version 0
	// means the current version. HSM, oct, ES256K and non-exportable keys are
	// refused with model.ExportRefusedError.
	ExportKey(ctx context.Context, scope model.Scope, id uuid.UUID, version int) (*ExportKeyResult, error)
```

Create `internal/services/keys/key_export.go`:

```go
package keys

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/google/uuid"

	"rocketvault/common"
	"rocketvault/internal/crypto"
	"rocketvault/model"
)

// ExportKeyResult is one exported key version. It carries private material
// and must never be logged, cached or stored.
type ExportKeyResult struct {
	ID            uuid.UUID
	Name          string
	Type          string
	Version       int
	Format        string // Always model.ExportFormatPEM.
	PrivateKeyPEM string // Unencrypted PKCS#8.
	KeyAlgorithm  string
}

// ExportKey implements KeyService.ExportKey. It sits beside GetPublicJWK and
// shares its version resolution, but it never touches keyCache: that cache
// is for crypto operations, and an export must not leave plaintext behind.
func (s *keyService) ExportKey(ctx context.Context, scope model.Scope, id uuid.UUID, version int) (*ExportKeyResult, error) {
	actor := scope.ActorID().String()
	if version < 0 {
		return nil, fmt.Errorf("%w: version must be 0 or a positive version number", model.ErrInvalidExportRequest)
	}

	// The scoped read and the lifecycle gate.
	key, err := s.GetKey(ctx, id, scope)
	if err != nil {
		return nil, err
	}
	refuse := func(reason string) error {
		s.logger.LogAuditError(actor, "export_key", "denied", fmt.Sprintf("Key %s not exportable: %s", id, reason), nil)
		return &model.ExportRefusedError{Sentinel: model.ErrKeyNotExportable, Reason: reason, Name: key.Name, KeyAlgorithm: key.KeyAlgorithm()}
	}
	if strings.HasPrefix(key.Value, pkcs11Prefix) {
		return nil, refuse("HSM-backed keys never leave the token")
	}
	if key.Type == model.KeyTypeOct {
		return nil, refuse("symmetric oct keys are not exportable")
	}
	if !key.Exportable {
		return nil, refuse("the key was not created with exportable: true")
	}

	// Resolve the version. The scoped read above authorizes the version row.
	current, err := s.keyRepo.CurrentVersion(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("resolve current version: %w", err)
	}
	if version == 0 {
		version = current
	}
	if version > current {
		return nil, fmt.Errorf("%w: key %s has no version %d", model.ErrKeyVersionNotFound, id, version)
	}
	stored := key.Value
	if version != current {
		stored, err = s.keyRepo.ReadVersionValue(ctx, id, version)
		if err != nil {
			return nil, err
		}
	}
	if strings.HasPrefix(stored, pkcs11Prefix) {
		return nil, refuse("HSM-backed keys never leave the token")
	}
	if key.Type == model.KeyTypeES256K {
		return nil, refuse("ES256K (secp256k1) keys cannot be encoded as PKCS#8")
	}

	keyPEM, err := common.DecryptSecret(stored)
	if err != nil {
		return nil, fmt.Errorf("decrypt key material: %w", err)
	}
	priv, err := crypto.ParsePrivateKey(keyPEM, key.Type)
	if err != nil {
		return nil, fmt.Errorf("parse key material: %w", err)
	}
	out, err := crypto.MarshalPKCS8PrivateKeyPEM(priv)
	if errors.Is(err, crypto.ErrNotPKCS8Encodable) {
		return nil, refuse("the key type cannot be encoded as PKCS#8")
	}
	if err != nil {
		return nil, fmt.Errorf("encode key material: %w", err)
	}

	s.logger.LogAuditInfo(actor, "export_key", "success", fmt.Sprintf("Key %s version %d exported", id, version))
	return &ExportKeyResult{
		ID: key.ID, Name: key.Name, Type: key.Type, Version: version, Format: model.ExportFormatPEM,
		PrivateKeyPEM: out, KeyAlgorithm: key.KeyAlgorithm(),
	}, nil
}
```

`ReadVersionValue` wraps `repositories.ErrKeyVersionNotFound`, which aliases `model.ErrKeyVersionNotFound` (the same sentinel `api/errors_key.go:58` matches).

Append to `internal/services/retry/retry_key_service.go`:

```go
// ExportKey is deliberately not retried. A failed export is reported once;
// replaying it would decrypt the key again for one request.
func (s *retryKeyService) ExportKey(ctx context.Context, scope model.Scope, id uuid.UUID, version int) (*keys.ExportKeyResult, error) {
	return s.baseService.ExportKey(ctx, scope, id, version)
}
```

- [ ] **Step 4: Add the method to every hand-written fake and regenerate the mock**

`api/keys_crud_test.go`, after `mockKeyService.GetPublicJWK`:

```go
func (m *mockKeyService) ExportKey(ctx context.Context, scope model.Scope, id uuid.UUID, version int) (*keyServices.ExportKeyResult, error) {
	args := m.Called(ctx, scope, id, version)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*keyServices.ExportKeyResult), args.Error(1)
}
```

`cmd/keys/keys_cmd_test.go` (`keyCmdKeyService`) and `cmd/keys/update_test.go` (`MockKeyServiceForUpdate`): the same body with their receivers.

`api/vault_scoped_keys_certs_test.go`: add a field `exportScope model.Scope` to `recordingKeyService` and the method:

```go
func (s *recordingKeyService) ExportKey(_ context.Context, scope model.Scope, id uuid.UUID, version int) (*keyServices.ExportKeyResult, error) {
	s.exportScope = scope
	return &keyServices.ExportKeyResult{ID: id, Name: "k", Type: "RSA", Version: 1, Format: "pem",
		PrivateKeyPEM: "key", KeyAlgorithm: "RSA-2048"}, nil
}
```

Use the alias each file already imports for the keys service package (`keyServices` or `keyservices`).

Run: `PATH="$HOME/go/pkg/mod/golang.org/toolchain@v0.0.1-go1.25.7.linux-amd64/bin:$PATH" GOTOOLCHAIN=local ~/go/bin/mockery && git status --short -- '*/mocks/*'`
Expected: only `internal/services/keys/mocks/mock_KeyService.go` is modified; revert any other with `git checkout -- <path>`.

- [ ] **Step 5: Run and expect PASS**

Run: `go build ./... && go test -p 2 ./internal/services/keys ./internal/services/retry ./api ./cmd/keys -count=1`
Expected: PASS.

- [ ] **Step 6: Commit**

Commit via the `dev-workflow-skills:1-git-commit` skill. Stage: `internal/services/keys/key_export.go`, `internal/services/keys/key_export_test.go`, `internal/services/keys/key_service.go`, `internal/services/keys/mocks/mock_KeyService.go`, `internal/services/retry/retry_key_service.go`, `internal/services/retry/retry_key_export_test.go`, `api/keys_crud_test.go`, `api/vault_scoped_keys_certs_test.go`, `cmd/keys/keys_cmd_test.go`, `cmd/keys/update_test.go`.

---

### Task 2: The key export route on both shapes, OpenAPI and route inventory

**Files:**
- Create: `api/keys_export.go`
- Modify: `api/keys.go:127-153` (`registerKeyRoutes`, after the `decrypt` route)
- Modify: `docs/api-specification.yaml` (paths after `/api/v1/keys/{key_id}/decrypt` at `:2786` and after `/api/v1/vaults/{vault_name}/keys/{key_id}/decrypt` at `:3351`; schemas), `docs/api-routes.generated.txt`
- Test: `api/keys_export_test.go` (create)

**Interfaces:**
- Consumes: Task 1; plan 2's export helpers and test helpers listed in the header; `mockKeyService`, `recordingKeyService`, `newVaultScopedKeyCertTestAPI`, `doVaultRequest`, `certLegacyVaultScope`, `certTestUserID`.
- Produces: `exportKey` handler; `ExportKeyAPIRequest`, `ExportKeyResponse`; routes `POST /api/v1/keys/{key_id}/export` and `POST /api/v1/vaults/{vault_name}/keys/{key_id}/export`.

- [ ] **Step 1: Write the failing tests**

Create `api/keys_export_test.go`:

```go
package api

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	keyServices "rocketvault/internal/services/keys"
	"rocketvault/model"
)

func runKeyExport(t *testing.T, svc keyServices.KeyService, audit *captureAudit, keyID, body string) *httptest.ResponseRecorder {
	t.Helper()
	c := newExportCtx(nil, svc, audit)
	c.Params.KeyID = keyID
	w := httptest.NewRecorder()
	var reqBody *bytes.Buffer
	if body == "" {
		reqBody = &bytes.Buffer{}
	} else {
		reqBody = bytes.NewBufferString(body)
	}
	exportKey(c, w, httptest.NewRequest(http.MethodPost, "/keys/"+keyID+"/export", reqBody))
	require.Nil(t, c.Err, "export handlers never set c.Err")
	return w
}

func TestExportKeyHandler_Success(t *testing.T) {
	keyID := uuid.New()
	keyText := "-----BEGIN PRIVATE KEY-----\nK\n-----END PRIVATE KEY-----\n"
	for _, body := range []string{``, `{}`, `{"format":"pem"}`, `{"format":"pem","version":1}`} {
		svc := &mockKeyService{}
		want := 0
		if body == `{"format":"pem","version":1}` {
			want = 1
		}
		svc.On("ExportKey", mock.Anything, certLegacyVaultScope(), keyID, want).
			Return(&keyServices.ExportKeyResult{ID: keyID, Name: "signer", Type: "RSA", Version: 1, Format: "pem", PrivateKeyPEM: keyText, KeyAlgorithm: "RSA-2048"}, nil)
		audit := &captureAudit{}

		w := runKeyExport(t, svc, audit, keyID.String(), body)
		require.Equal(t, http.StatusOK, w.Code, "body %q: %s", body, w.Body.String())
		assert.Equal(t, "no-store", w.Header().Get("Cache-Control"))
		assert.Equal(t, "no-cache", w.Header().Get("Pragma"))
		assert.Empty(t, w.Header().Get("Content-Disposition"))

		var resp map[string]any
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
		assert.Equal(t, "pem", resp["format"])
		assert.Equal(t, keyText, resp["private_key_pem"])
		assert.Equal(t, "RSA-2048", resp["key_algorithm"])
		assert.Equal(t, "RSA", resp["type"])

		require.Len(t, audit.events, 1)
		assert.Equal(t, "export_key", audit.events[0].Action)
		assert.Equal(t, "success", audit.events[0].Outcome)
		assert.Equal(t, "key", audit.events[0].ResourceType)
		assert.Equal(t, keyID.String(), audit.events[0].ResourceID)
		assert.NotContains(t, audit.dump(), "PRIVATE KEY")
	}
}

func TestExportKeyHandler_ErrorBodiesAreR6(t *testing.T) {
	keyID := uuid.New()
	cases := []struct {
		name, body string
		err        error
		status     int
		code       string
	}{
		{"bad json", `{"format":`, nil, http.StatusBadRequest, "bad_request"},
		{"unknown format", `{"format":"jwk"}`, nil, http.StatusBadRequest, "bad_request"},
		{"bad version", `{"version":-1}`, fmt.Errorf("%w: version", model.ErrInvalidExportRequest), http.StatusBadRequest, "bad_request"},
		{"not found", ``, fmt.Errorf("%w: x", keyServices.ErrKeyNotFound), http.StatusNotFound, "not_found"},
		{"no version", `{"version":7}`, fmt.Errorf("%w: x", model.ErrKeyVersionNotFound), http.StatusNotFound, "not_found"},
		{"disabled", ``, keyServices.ErrKeyLifecycleDenied, http.StatusConflict, "key_disabled"},
		{"refused", ``, &model.ExportRefusedError{Sentinel: model.ErrKeyNotExportable, Reason: "HSM-backed keys never leave the token", KeyAlgorithm: "RSA-2048"}, http.StatusForbidden, "key_not_exportable"},
		{"internal", ``, errors.New("decrypt key material: cipher: message authentication failed"), http.StatusInternalServerError, "internal_error"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			svc := &mockKeyService{}
			if tc.err != nil {
				svc.On("ExportKey", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(nil, tc.err)
			}
			audit := &captureAudit{}
			w := runKeyExport(t, svc, audit, keyID.String(), tc.body)
			require.Equal(t, tc.status, w.Code, w.Body.String())
			assert.Equal(t, "no-store", w.Header().Get("Cache-Control"))
			detail := decodeExportError(t, w.Body.Bytes())
			assert.Equal(t, tc.code, detail.Code)
			assert.NotContains(t, w.Body.String(), "authentication failed")
			if tc.code == "key_not_exportable" {
				assert.Equal(t, "RSA-2048", detail.KeyAlgorithm)
			}
			require.Len(t, audit.events, 1)
			assert.Equal(t, "failure", audit.events[0].Outcome)
		})
	}
}

func TestExportKeyRoutes_BothShapes(t *testing.T) {
	keyID := uuid.New().String()
	t.Run("flat", func(t *testing.T) {
		rec := &recordingKeyService{}
		api, _ := newVaultScopedKeyCertTestAPI(rec, nil, nil)
		w := doVaultRequest(api, http.MethodPost, "/api/v1/keys/"+keyID+"/export", nil)
		require.Equal(t, http.StatusOK, w.Code, w.Body.String())
		assert.Equal(t, uuid.MustParse(model.DefaultVaultID), rec.exportScope.VaultID())
	})
	t.Run("vault-scoped", func(t *testing.T) {
		rec := &recordingKeyService{}
		api, repo := newVaultScopedKeyCertTestAPI(rec, nil, nil)
		id := uuid.New()
		repo.byName["prod"] = &model.Vault{ID: id, Name: "prod", Enabled: true}
		repo.byID[id.String()] = repo.byName["prod"]
		w := doVaultRequest(api, http.MethodPost, "/api/v1/vaults/prod/keys/"+keyID+"/export", []byte(`{"format":"pem"}`))
		require.Equal(t, http.StatusOK, w.Code, w.Body.String())
		assert.Equal(t, id, rec.exportScope.VaultID())
	})
}

func TestExportKeyThroughRealChain_NoSecretsAndMissingRoleAudited(t *testing.T) {
	keyText := "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCleaked\n-----END PRIVATE KEY-----\n"
	keyID := uuid.New()
	svc := &mockKeyService{}
	svc.On("ExportKey", mock.Anything, mock.Anything, keyID, 0).
		Return(&keyServices.ExportKeyResult{ID: keyID, Name: "k", Type: "RSA", Version: 1, Format: "pem", PrivateKeyPEM: keyText, KeyAlgorithm: "RSA-2048"}, nil)

	router, audit, logs := newExportChain(t, nil, svc, "")
	w := postExport(router, "/api/v1/vaults/default/keys/"+keyID.String()+"/export", `{"format":"pem"}`)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	everything := logs.String() + audit.dump()
	assert.NotContains(t, everything, "BEGIN PRIVATE KEY")
	assert.NotContains(t, everything, "leaked")

	denied, deniedAudit, _ := newExportChain(t, nil, &mockKeyService{}, model.ActionKeysExport)
	w = postExport(denied, "/api/v1/keys/"+keyID.String()+"/export", ``)
	require.Equal(t, http.StatusForbidden, w.Code)
	assert.Contains(t, deniedAudit.dump(), string(model.ActionKeysExport))
}
```

- [ ] **Step 2: Run and expect FAIL**

Run: `go test -p 2 ./api -run 'ExportKey' -v`
Expected: FAIL (build error: `exportKey` undefined).

- [ ] **Step 3: Implement**

Create `api/keys_export.go`:

```go
package api

import (
	"fmt"
	"net/http"

	"github.com/google/uuid"

	"rocketvault/internal/container"
	"rocketvault/model"
)

// ExportKeyAPIRequest is the optional body of POST .../keys/{key_id}/export.
// An empty body exports the current version as PEM.
type ExportKeyAPIRequest struct {
	Format  string `json:"format,omitempty"`  // Only pem; empty means pem.
	Version int    `json:"version,omitempty"` // 0 or omitted means the current version.
}

// ExportKeyResponse is the key export success body.
type ExportKeyResponse struct {
	ID            uuid.UUID `json:"id"`
	Name          string    `json:"name"`
	Type          string    `json:"type"`
	Version       int       `json:"version"`
	Format        string    `json:"format"`
	PrivateKeyPEM string    `json:"private_key_pem"`
	KeyAlgorithm  string    `json:"key_algorithm"`
}

// exportKey handles POST .../keys/{key_id}/export. PolicyMiddleware has
// already required ActionKeysExport in the resolved vault. Like
// exportCertificate it never sets c.Err and audits every attempt once.
func exportKey(c *Context, w http.ResponseWriter, r *http.Request) {
	setExportHeaders(w)
	audit := exportAudit{ResourceType: "key", ResourceID: c.Params.KeyID, Outcome: "failure", Format: model.ExportFormatPEM}
	fail := func(f exportFailure) {
		audit.Code = f.Code
		if f.Name != "" {
			audit.Name = f.Name
		}
		recordExportAudit(c, r, audit)
		writeExportError(w, f)
	}

	scope, vaultID, ok := exportCaller(c, r)
	audit.VaultID = vaultID
	if !ok {
		fail(badExportRequest("the caller or vault could not be determined"))
		return
	}
	keyID, err := uuid.Parse(c.Params.KeyID)
	if err != nil {
		fail(badExportRequest("key_id must be a UUID"))
		return
	}
	var req ExportKeyAPIRequest
	if err := decodeExportBody(r, &req, true); err != nil {
		fail(badExportRequest(err.Error()))
		return
	}
	if req.Format != "" && req.Format != model.ExportFormatPEM {
		fail(badExportRequest("format must be pem"))
		return
	}
	audit.Version = req.Version

	keyService, svcOK := svc(c, container.ServiceContainerInterface.GetKeyService)
	if !svcOK {
		c.Err = nil
		fail(exportFailure{Status: http.StatusInternalServerError, Code: "internal_error", Message: "internal server error"})
		return
	}

	result, err := keyService.ExportKey(r.Context(), scope, keyID, req.Version)
	if err != nil {
		if c.Logger != nil {
			c.Logger.LogAuditError(c.Claims.UserID, "export_key", "failed", fmt.Sprintf("Key %s export failed", keyID), nil)
		}
		fail(exportFailureFor(err, "key"))
		return
	}

	audit.Outcome, audit.Name, audit.Version, audit.Code = "success", result.Name, result.Version, ""
	recordExportAudit(c, r, audit)
	writeJSON(w, ExportKeyResponse{
		ID: result.ID, Name: result.Name, Type: result.Type, Version: result.Version,
		Format: result.Format, PrivateKeyPEM: result.PrivateKeyPEM, KeyAlgorithm: result.KeyAlgorithm,
	})
}
```

In `registerKeyRoutes`, after the `decrypt` route add:

```go
	// Per-key export of an exportable software key. Requires ActionKeysExport;
	// see api/keys_export.go.
	k.Handle("/{key_id:[A-Fa-f0-9-]+}/export", ApiSessionRequired(api.App, exportKey)).Methods("POST")
```

- [ ] **Step 4: Document both route shapes in OpenAPI and regenerate the inventory**

In `docs/api-specification.yaml`, after the `/api/v1/keys/{key_id}/decrypt` path item add:

```yaml
  /api/v1/keys/{key_id}/export:
    parameters:
      - $ref: "#/components/parameters/KeyId"
    post:
      summary: Export a software key's private material
      description: |
        Returns one version of an exportable, software-backed key as
        unencrypted PKCS#8 PEM. Requires the
        `Microsoft.KeyVault/vaults/keys/export/action` data action (Key Vault
        Key Exporter or Administrator) and a key created or imported with
        `exportable: true`. HSM-backed (`pkcs11:`), `oct` and ES256K keys are
        never exportable (403 `key_not_exportable`). The body is optional.
        Every response carries `Cache-Control: no-store` and
        `Pragma: no-cache`; errors use the `ExportError` body except the 401
        and the missing-role 403, which come from the middleware.
      operationId: exportKey
      tags:
        - Keys
      requestBody:
        required: false
        content:
          application/json:
            schema:
              $ref: "#/components/schemas/ExportKeyRequest"
      responses:
        "200":
          description: The exported key
          content:
            application/json:
              schema:
                $ref: "#/components/schemas/ExportKeyResponse"
        "400":
          $ref: "#/components/responses/ExportBadRequest"
        "401":
          $ref: "#/components/responses/Unauthorized"
        "403":
          $ref: "#/components/responses/ExportForbidden"
        "404":
          $ref: "#/components/responses/ExportNotFound"
        "409":
          $ref: "#/components/responses/ExportConflict"
        "500":
          $ref: "#/components/responses/ExportInternalError"
```

Add the same item as `/api/v1/vaults/{vault_name}/keys/{key_id}/export` after the vault-scoped `decrypt` item, copying the exact `parameters` refs that item uses and with `operationId: exportKeyInVault`. Use the parameter ref name the existing `/api/v1/keys/{key_id}/decrypt` item uses for `key_id` if it is not `KeyId`.

Under `components.schemas` add:

```yaml
    ExportKeyRequest:
      type: object
      properties:
        format:
          type: string
          enum: [pem]
          default: pem
        version:
          type: integer
          minimum: 0
          description: 0 or omitted exports the current version.
    ExportKeyResponse:
      type: object
      required: [id, name, type, version, format, private_key_pem, key_algorithm]
      properties:
        id:
          type: string
          format: uuid
        name:
          type: string
        type:
          type: string
          example: "RSA"
        version:
          type: integer
        format:
          type: string
          enum: [pem]
        private_key_pem:
          type: string
          description: Unencrypted PKCS#8, starting with -----BEGIN PRIVATE KEY-----.
        key_algorithm:
          type: string
          example: "EC-P256"
```

Run: `go test ./api -run TestGenerateRouteInventory -update-route-inventory && git diff --stat docs/api-routes.generated.txt`
Expected: two added lines, the flat and vault-scoped `POST .../keys/{key_id...}/export`.

- [ ] **Step 5: Run and expect PASS**

Run: `go test -p 2 ./api ./internal/services/authorization -count=1`
Expected: PASS, including `TestOpenAPISpecCoversAllRoutes`, `TestGenerateRouteInventory` and `TestAuthorizationMatrixOpsAreRealRoutes`.

- [ ] **Step 6: Commit**

Commit via the `dev-workflow-skills:1-git-commit` skill. Stage: `api/keys_export.go`, `api/keys_export_test.go`, `api/keys.go`, `docs/api-specification.yaml`, `docs/api-routes.generated.txt`.

---

### Task 3: API developer guide and the mTLS integration example

**Files:**
- Modify: `docs/api-developer-guide.md` (Key Endpoints `:299-370`, Certificate Endpoints `:371-440`, status codes `:443-452`)
- Modify: `docs/integration-examples.md:5-13` (table of contents), before `## CI/CD Pipeline Integration` (`:625`)

**Interfaces:**
- Consumes: the routes, bodies, codes and roles from plans 1-2 and Task 2.
- Produces: documentation only.

- [ ] **Step 1: Developer guide**

At the end of `### Key Endpoints` (immediately before `### Certificate Endpoints`), add:

````markdown
#### Export a Key

```http
POST /api/v1/vaults/{vault_name}/keys/{key_id}/export
Authorization: Bearer <token>
Content-Type: application/json

{"format": "pem", "version": 0}
```

The body is optional; an empty body exports the current version as PEM.
Only a software-backed key created or imported with `"exportable": true`
can be exported, and only by a principal holding the Key Vault Key Exporter
role (or Administrator) in that vault. HSM-backed, `oct` and ES256K keys are
never exportable. The flat route `POST /api/v1/keys/{key_id}/export` acts on
the `default` vault.

**Response:** `200 OK` with `Cache-Control: no-store` and `Pragma: no-cache`:

```json
{
  "id": "6f1c...", "name": "signer", "type": "RSA", "version": 1,
  "format": "pem",
  "private_key_pem": "-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----\n",
  "key_algorithm": "RSA-2048"
}
```

````

At the end of `### Certificate Endpoints`, add:

````markdown
#### Export a Certificate with its Private Key

```http
POST /api/v1/vaults/{vault_name}/certificates/{certificate_id}/export
Authorization: Bearer <token>
Content-Type: application/json

{"format": "pem"}
```

or, for a PKCS12 bundle:

```json
{"format": "pkcs12", "password": "", "compat": "modern", "version": 0}
```

`format` is required (`pem` or `pkcs12`). For `pkcs12` the `password` field
must be present; an empty string is allowed. `compat: "legacy"` produces
PBE-SHA1-3DES with a SHA-1 MAC for old consumers; the default is modern
(AES-256, SHA-256 MAC). `version` 0 or omitted exports the current version;
an archived version must itself be enabled and inside its own validity
window, and a disabled certificate blocks every version.

Requires the Key Vault Certificate Exporter role (or Administrator) and a
certificate created with `"exportable": true`, which in turn requires a key
created with `"exportable": true`.

**PEM response** (`Cache-Control: no-store`, `Pragma: no-cache`):

```json
{
  "id": "550e8400-...", "name": "rocket-client", "version": 1, "format": "pem",
  "certificate_pem": "-----BEGIN CERTIFICATE-----\n(leaf)\n-----END CERTIFICATE-----\n-----BEGIN CERTIFICATE-----\n(intermediate)\n-----END CERTIFICATE-----\n",
  "private_key_pem": "-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----\n",
  "not_before": "2026-10-01T10:00:00Z", "expires_at": "2027-10-01T10:00:00Z",
  "key_algorithm": "EC-P256"
}
```

The chain is leaf first, then intermediates; the root is never included. A
PKCS12 response carries `pkcs12_base64` instead of the two PEM fields.

#### Export Errors

The two export routes use their own error body:

```json
{"error": {"code": "certificate_not_exportable", "message": "certificate is not exportable: the certificate was not created with exportable: true", "key_algorithm": "RSA-2048"}}
```

| Status | Code | When |
|---|---|---|
| 400 | `bad_request` | bad body, unknown `format`/`compat`, `pkcs12` without `password`, bad `version` |
| 403 | `certificate_not_exportable` / `key_not_exportable` | flag false, HSM, `oct`, ES256K |
| 404 | `not_found` | unknown, soft-deleted, out of vault, or unknown version |
| 409 | `certificate_disabled` / `key_disabled` | disabled, expired or outside its window |
| 500 | `internal_error` | anything else; the message is generic |

A 401 (no session) and a 403 for a missing role come from the middleware and
keep their usual bodies; read the status, not the body, for those.

#### Export Caveats

- **Existing items are permanently non-exportable.** `exportable` is set only
  at creation or import and can never be changed. Re-create or re-import to
  get an exportable item.
- **A restore loses exportability.** Restoring a certificate or key backup
  always produces a non-exportable item.
- **A key rotation does not change an exported certificate.** A certificate
  keeps its own copy of the key; export reflects that copy until the
  certificate is renewed.
- **Chains use each CA's current certificate.** If a CA was renewed after the
  leaf was issued, the chain carries the CA's newer certificate, which still
  verifies because renewal keeps the CA's key.
- Every export attempt is audited (`export_certificate` / `export_key`); no
  key, chain or password is ever logged.

````

In the HTTP status-code list, add after `409` (or after `404` if `409` is absent): `- \`403\` on an export route can also mean the item is not exportable; see Export Errors.`

- [ ] **Step 2: mTLS integration example**

In `docs/integration-examples.md`, add `- [mTLS Client Identity from an Exported Certificate](#mtls-client-identity-from-an-exported-certificate)` to the table of contents after the certificate-renewal entry, and immediately before `## CI/CD Pipeline Integration` add:

````markdown
## mTLS Client Identity from an Exported Certificate

A service principal fetches its client certificate and key at send time and
keeps nothing on disk. Setup, as an admin:

```bash
API="${ROCKETVAULT_URL:-http://127.0.0.1:8774}/api/v1/vaults/${VAULT:-default}"

# An exportable key and an exportable certificate issued over it.
KEY_ID=$(curl -sS -X POST "$API/keys" -H "Authorization: Bearer $ADMIN_JWT" \
  -H "Content-Type: application/json" \
  -d '{"name":"rocket-client-key","type":"ECDSA","curve":"P-256","exportable":true}' | jq -r .id)
CERT_ID=$(curl -sS -X POST "$API/certificates" -H "Authorization: Bearer $ADMIN_JWT" \
  -H "Content-Type: application/json" \
  -d "{\"name\":\"rocket-client\",\"key_id\":\"$KEY_ID\",\"validity_days\":365,\"exportable\":true}" | jq -r .id)

# Only a global admin can grant the exporter role.
curl -sS -X POST "$API/role-assignments" -H "Authorization: Bearer $ADMIN_JWT" \
  -H "Content-Type: application/json" \
  -d "{\"principal\":\"$SA_ID\",\"principal_type\":\"service_account\",\"role\":\"Key Vault Certificate Exporter\"}"
```

The same from the CLI: `rocketvault keys create --name rocket-client-key --type ECDSA --curve P-256 --exportable` and
`rocketvault certificate create --name rocket-client --key-id "$KEY_ID" --validity-days 365 --exportable`.

At send time, as the service principal (`$SA_TOKEN` from the OAuth2
client-credentials grant), fetch the identity and use it in memory only:

```bash
#!/usr/bin/env bash
# mtls_call.sh - fetch an exported client identity and make one mTLS call.
set -euo pipefail
API="${ROCKETVAULT_URL:-http://127.0.0.1:8774}/api/v1/vaults/${VAULT:-default}"

BODY=$(curl -sS -X POST "$API/certificates/$CERT_ID/export" \
  -H "Authorization: Bearer $SA_TOKEN" -H "Content-Type: application/json" \
  -d '{"format":"pem"}')

# Process substitution keeps the key off disk.
curl -sS https://mtls.example.internal/health \
  --cert <(jq -r .certificate_pem <<<"$BODY") \
  --key <(jq -r .private_key_pem <<<"$BODY")
```

In Go, build the identity straight from the response:

```go
pair, err := tls.X509KeyPair([]byte(resp.CertificatePEM), []byte(resp.PrivateKeyPEM))
if err != nil {
	return err
}
client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{
	Certificates: []tls.Certificate{pair},
	MinVersion:   tls.VersionTLS12,
}}}
```

A client that stores the certificate by name resolves it to the id from the
list response, which carries `exportable` and `key_algorithm` for exactly that
purpose. A certificate that is not exportable answers `403` with code
`certificate_not_exportable`; recreate it with `"exportable": true`.

````

- [ ] **Step 3: Verify the docs build**

Run: `./scripts/docs.sh build`
Expected: success, with `docs/api-developer-guide.html` and `docs/integration-examples.html` regenerated if those are in `scripts/docsgen/docs.go`'s list. Do not commit generated HTML unless it is already tracked (`git ls-files docs/*.html`).

- [ ] **Step 4: Commit**

Commit via the `dev-workflow-skills:1-git-commit` skill. Stage: `docs/api-developer-guide.md`, `docs/integration-examples.md`, and any tracked generated HTML that changed.

---

### Task 4: Parity doc, decision record, bulk-export rename, role counts and CLAUDE.md

**Files:**
- Modify: `.claude/azure-keyvault-parity.md:51` (key-export row), `§4` table (`:217-230`) and its footnote (`:232-236`), role tables (`:323`, after `:349`), `:365`, `:373`, `:396`, `:543`, scorecard (`:489`, `:491`, `:493`, `:498`)
- Modify: `docs/superpowers/specs/2026-08-25-key-export-decision-record.md:4` (status) and append an amendment section
- Modify: `docs/superpowers/specs/2026-08-25-certificate-export-design.md:166-169`, `:184` (action rename)
- Modify: `CLAUDE.md` (Key Management bullets, Certificate Management bullets, Azure Role Additions, Documentation History)

**Interfaces:**
- Consumes: everything from plans 1-3.
- Produces: documentation only.

- [ ] **Step 1: Parity rows**

Replace the row at `.claude/azure-keyvault-parity.md:51` (starting `| EXPORT blocked (keys non-extractable) |`) with two rows:

```markdown
| HSM keys non-extractable | ✅ | ✅ HSM-backed keys are created with `CKA_EXTRACTABLE: false` (`internal/crypto/pkcs11_provider.go`) and `KeyService.ExportKey` refuses every `pkcs11:` key, including an archived version, with 403 `key_not_exportable`. `buildKeyResponse` emits only JWK public components and `model.KeyVersion` omits `Value` | ✅ |
| Software key export (opt-in) | ❌ (keys are non-extractable on every tier) | ✅ `POST /keys/{key_id}/export` (both route shapes): unencrypted PKCS#8 PEM, optional `version`, only for software keys created or imported with `exportable: true` — an immutable, per-key flag visible in `GET key` and decided by the key's creator; existing keys stay non-exportable forever. Requires `Microsoft.KeyVault/vaults/keys/export/action` (Key Vault Key Exporter or Administrator). `oct` and ES256K keys are refused. Amends `docs/superpowers/specs/2026-08-25-key-export-decision-record.md` (now "Superseded for software keys"); design: `docs/superpowers/specs/2026-10-01-certificate-and-key-export-design.md` | ➕ |
```

In §4, after the `Backup / Restore` row add:

```markdown
| Per-certificate export with private key (PEM chain + PKCS#8, or PKCS12) | ❌ (Azure exports a certificate's key only through its linked secret) | ✅ `POST /certificates/{certificate_id}/export` (both route shapes), optional `version`; chain leaf first with intermediates, root excluded; PKCS12 `modern` or `legacy`. Only certificates created with `exportable: true` over an exportable key; requires `Microsoft.KeyVault/vaults/certificates/export/action` (Key Vault Certificate Exporter or Administrator); every attempt audited; `Cache-Control: no-store`. A restore yields a non-exportable certificate, and export reflects the certificate's own key copy until renewal | ➕ |
```

Replace the §4 footnote paragraph (`*Certificate export (passphrase-sealed, portable) has no Azure equivalent ...*`) with:

```markdown
*Bulk certificate export (passphrase-sealed, portable) has no Azure equivalent
and is not a row in this table — see `docs/superpowers/specs/
2026-08-25-certificate-export-design.md` (its action is now named
`ActionCertificatesBulkExport` so it cannot collide with the per-certificate
`ActionCertificatesExportItem`) and `.claude/roadmap-azure-parity-and-beyond.md`
Phase 3. Design specified, not yet built. Per-certificate export shipped
2026-10-01 (row above).*
```

- [ ] **Step 2: Role table and the "eleven" mentions**

At `:323`, change `the eleven` to `the thirteen`. After the four-role table that ends with the `Data Access Administrator` row (`:346`), add:

```markdown

Two RocketVault-only roles were added 2026-10-01 for per-item export
(`docs/superpowers/specs/2026-10-01-certificate-and-key-export-design.md`).
Azure has no counterpart, so they are extras, not parity rows. Neither is in
`nonAdminGrantableRoles`: only a global admin can grant them. Administrator
also holds both actions; no other built-in role holds either.

| Role | Azure grants | RocketVault grants | Status |
|---|---|---|---|
| Certificate Exporter | n/a | `Key Vault Certificate Exporter`: `ActionCertificatesExportItem` only | ➕ |
| Key Exporter | n/a | `Key Vault Key Exporter`: `ActionKeysExport` only | ➕ |
```

At `:365` replace `All eleven *bundles* are byte-for-byte accurate against` with `All eleven Azure *bundles* are byte-for-byte accurate against` and append to the end of that paragraph: `(The two exporter roles added 2026-10-01 are RocketVault-only and have no Azure bundle to compare.)`. Leave `:373` (a dated quotation of an earlier review) unchanged. At `:396` change `knows only the eleven Azure names` to `knows only the thirteen built-in names (eleven Azure roles plus the two exporter roles)`. At `:543` change `All eleven role **bundles** are byte-for-byte` to `All eleven Azure role **bundles** are byte-for-byte` and append `(plus two RocketVault-only exporter roles, 2026-10-01)` after that sentence.

- [ ] **Step 3: Scorecard**

The new rows are one ✅ (HSM keys non-extractable, replacing the old ✅ row in §2), one ➕ in §2, one ➕ in §4, and two ➕ in §6. ✅/🟡/❌ totals and the percentages do not change. Change:

- `| 2. Key management — operations | 9 | 3 | 1 | 0 |` to `| 2. Key management — operations | 9 | 3 | 1 | 1 |`
- `| 4. Certificate management | 7 | 1 | 4 | 0 |` to `| 4. Certificate management | 7 | 1 | 4 | 1 |`
- `| 6. Access control / authorization | 14 | 3 | 0 | 0 |` to `| 6. Access control / authorization | 14 | 3 | 0 | 2 |`
- `| **Total** | **57** | **15** | **8** | **10** |` to `| **Total** | **57** | **15** | **8** | **14** |`

and append to the paragraph after the scorecard: `(2026-10-01: export added four ➕ rows — software key export, per-certificate export and the two exporter roles — and split the key-export row; the parity percentages are unchanged.)`

- [ ] **Step 4: Amend the key-export decision record**

In `docs/superpowers/specs/2026-08-25-key-export-decision-record.md`, change `**Status**: Decided — will not implement` to:

```markdown
**Status**: Superseded for software keys (2026-10-01) — HSM keys stay non-extractable
```

Append at the end of the file:

```markdown
## Amendment (2026-10-01): superseded for software keys

[2026-10-01-certificate-and-key-export-design.md](2026-10-01-certificate-and-key-export-design.md)
adds `POST /keys/{key_id}/export` for software-backed keys. This record's
reasoning was that software-key export would be an invisible,
deployment-dependent change to the "keys never leave the vault" trust model.
The amendment answers that directly: exportability is an explicit, immutable,
per-key `exportable` flag, set only by the key's creator at creation or import,
visible in `GET key`, and false for every key that existed before the change.
Export further requires the narrow Key Vault Key Exporter role (or
Administrator), which only a global admin can grant, and every attempt is
audited.

What does not change: HSM-backed keys remain non-extractable
(`CKA_EXTRACTABLE: false`) and `ExportKey` refuses every `pkcs11:` key; `oct`
and ES256K keys are refused too. A key created without `exportable: true` can
never be exported.
```

- [ ] **Step 5: Rename the bulk-export design's action**

In `docs/superpowers/specs/2026-08-25-certificate-export-design.md`, replace the code block at `:166-169` with:

```go
// ActionCertificatesBulkExport permits exporting certificates as a
// passphrase-sealed, portable file. RocketVault-only — Azure Key Vault has no
// equivalent bulk-export operation for certificates.
ActionCertificatesBulkExport DataAction = "Microsoft.KeyVault/vaults/certificates/bulkExport/action"
```

and `return model.ActionCertificatesExport, RouteVaultData` at `:184` with `return model.ActionCertificatesBulkExport, RouteVaultData`. Then add, directly under the `### 4. Authorization` heading:

```markdown
> **Renamed 2026-10-01.** This action was `ActionCertificatesExport` with
> `.../certificates/export/action`. The per-certificate export that shipped
> first (`docs/superpowers/specs/2026-10-01-certificate-and-key-export-design.md`)
> owns `ActionCertificatesExportItem` and the `.../certificates/export/action`
> string, so the bulk action takes a distinct name and string.
```

Run: `grep -n "ActionCertificatesExport\b\|ActionCertificatesExport[^IB]" docs/superpowers/specs/2026-08-25-certificate-export-design.md`
Expected: no output. Do not edit `docs/superpowers/plans/2026-08-25-certificate-export.md`.

- [ ] **Step 6: Recount the scorecard**

Run: `grep -n '| ➕ |$' .claude/azure-keyvault-parity.md`
Expected: exactly fourteen lines: the ten that existed before (at today's `:30`, `:31`, `:244`, `:450`, `:458`, `:459`, `:462` and the three others the scorecard already counts) plus the four added in Steps 1-2, located in §2, §4 and §6 (twice). Then count the ✅, 🟡 and ❌ status cells of §2, §4 and §6 by hand and confirm they still match the edited scorecard rows; the split of the key-export row keeps §2 at nine ✅. Fix the table, never the count, if they disagree.

- [ ] **Step 7: CLAUDE.md**

Under `### Key Management (`internal/services/keys/`)`, append the bullet:

```markdown
- Software keys created or imported with `exportable: true` can be exported as unencrypted PKCS#8 via `POST .../keys/{key_id}/export` (`KeyService.ExportKey`), with the Key Vault Key Exporter role. The flag is immutable (`KeyRepository.Update` never writes it, rotation keeps it, restore forces it false); HSM, `oct` and ES256K keys are never exportable. Design: `docs/superpowers/specs/2026-10-01-certificate-and-key-export-design.md`; the 2026-08-25 key-export decision record is superseded for software keys only.
```

Under `### Certificate Management`, append:

```markdown
- Certificates created with `exportable: true` (which requires an exportable key, else 409) export as a leaf-first chain plus PKCS#8, or PKCS12, via `POST .../certificates/{certificate_id}/export` (`CertificateService.ExportCertificate`, reads the repository never `certcache`, never retried). The export routes alone use the R6 `{"error":{"code","message"}}` body (`api/export.go`), set `Cache-Control: no-store`, and audit every attempt through `AuditService.RecordEvent`.
```

In `### Azure Role Additions`, append: `Two RocketVault-only roles followed on 2026-10-01: \`Key Vault Certificate Exporter\` (\`ActionCertificatesExportItem\`) and \`Key Vault Key Exporter\` (\`ActionKeysExport\`). Administrator holds both actions; no other role does, and neither exporter role is in \`nonAdminGrantableRoles\`, so only a global admin can grant them. That makes thirteen built-in roles.`

Under `## Documentation History`, add above the `2026-10-01` versioning entry:

```markdown
- **2026-10-01**: Certificate and key export — `POST .../certificates/{id}/export`
  (PEM chain + PKCS#8 or PKCS12) and `POST .../keys/{id}/export` (software keys,
  PKCS#8) on both route shapes, the immutable `exportable` flag on every
  creation surface, `exportable`/`key_algorithm` on certificate and key
  responses, two exporter roles (thirteen built-in roles), and the new
  `software.sslmate.com/src/go-pkcs12` dependency. Plans:
  `docs/superpowers/plans/2026-10-01-export-flag-roles-creation.md`,
  `2026-10-01-certificate-export.md`, `2026-10-01-key-export-and-docs.md`.
```

- [ ] **Step 8: Commit**

Commit via the `dev-workflow-skills:1-git-commit` skill. Stage: `.claude/azure-keyvault-parity.md`, `docs/superpowers/specs/2026-08-25-key-export-decision-record.md`, `docs/superpowers/specs/2026-08-25-certificate-export-design.md`, `CLAUDE.md`.

---

### Task 5: Final regression gates and the isolated-instance upgrade smoke test

**Files:**
- No source changes. This task is a documented manual verification; record its outcome in the report to Rocket, not in a file.

**Interfaces:**
- Consumes: everything from plans 1-3.
- Produces: the evidence the spec's hard gates require.

- [ ] **Step 1: Automated gates**

Run: `go build ./... && go vet ./... && go test -p 2 ./... -count=1`
Expected: every package PASS, with no pre-existing test weakened or deleted. Then run the linter in CI (or on a fixed toolchain) and confirm it is clean.

Run: `git diff <commit before plan 1>..HEAD --stat -- '*_test.go'` and read every change to a pre-existing test file.
Expected: only the hand-written `exportable` schema column, the role counts and names, the new matrix rows, and the added fake methods. `<commit before plan 1>` is `35626511` unless other commits landed on the branch first; confirm with `git log --oneline` and use the parent of plan 1's first commit.

- [ ] **Step 2: Build the pre-export and the export binaries**

```bash
PRE=$(git log --format=%H -1 <commit before plan 1>)
SMOKE=$(mktemp -d /tmp/rv-export-smoke.XXXXXX)
git worktree add "$SMOKE/pre" "$PRE"
(cd "$SMOKE/pre" && go build -o "$SMOKE/rocketvault-pre" .)
go build -o "$SMOKE/rocketvault-new" .
```

Expected: both binaries build.

- [ ] **Step 3: Start an isolated pre-export instance and create existing data**

Never use `dev-rocketvault.db`. Create `"$SMOKE/smoke.yaml"` from `.rocketvault.yaml.example` with `database.connection: "$SMOKE/smoke.db"`, a fresh `master_key` and `bootstrap_token` (`openssl rand -base64 32` each), `server.listen_addr: "127.0.0.1:18774"`, and `oidc.enabled: false`. Then:

```bash
RV_PRE="$SMOKE/rocketvault-pre --config $SMOKE/smoke.yaml"
$RV_PRE serve & PRE_PID=$!
$RV_PRE users admin --admin-username=admin --admin-password='Smoke-Test-1!' --bootstrap-token="<token from smoke.yaml>"
$RV_PRE users login --username admin --password 'Smoke-Test-1!' --totp-code <code>
$RV_PRE keys create --name old-key --type RSA --bits 2048
$RV_PRE certificate create --name old-cert --key-id <old-key id> --validity-days 30
$RV_PRE certificate renew <old-cert id> --validity-days 30
$RV_PRE secrets create --name old-secret --value old-value
$RV_PRE vault-access grant admin --role "Key Vault Secrets User" --vault default
kill $PRE_PID
```

Use each command's `--help` for its exact flags if one differs. Expected: every command succeeds; `old-cert` is at version 2.

- [ ] **Step 4: Upgrade and exercise the existing flows first**

```bash
RV_NEW="$SMOKE/rocketvault-new --config $SMOKE/smoke.yaml"
$RV_NEW serve & NEW_PID=$!
$RV_NEW keys get <old-key id>
$RV_NEW certificate get <old-cert id>
$RV_NEW certificate versions list <old-cert id>
$RV_NEW secrets get <old-secret id>
$RV_NEW vault-access list --vault default
$RV_NEW keys rotate <old-key id>
$RV_NEW certificate renew <old-cert id> --validity-days 30
```

Expected: the upgrade starts without error; every existing item reads back unchanged; `GET` responses show `"exportable": false`; the certificate lists versions 1-2 and renews to 3; the secret value and role assignment are intact.

- [ ] **Step 5: Exercise the new export flows**

With an admin JWT (`ADMIN_JWT`) from `POST /api/v1/users/login` on `127.0.0.1:18774`:

1. Create a service account (`POST /api/v1/service-accounts`, keep `id` and `client_secret`), grant it `Key Vault Certificate Exporter` and `Key Vault Secrets User` on `default` (`POST /api/v1/vaults/default/role-assignments`, `principal` = the account UUID, `principal_type` = `service_account`), and get `SA_TOKEN` from `POST /api/v1/oauth2/token`.
2. Create an exportable RSA key and an exportable RSA certificate over it, an exportable EC (P-256) key and certificate, and one non-exportable certificate (`exportable` omitted).
3. As the service account: `POST /api/v1/vaults/default/certificates/<rsa cert>/export` with `{"format":"pem"}` and `{"format":"pkcs12","password":""}`; the same for the EC certificate; check `Cache-Control: no-store` with `curl -i`.
4. Check the PEM key: `jq -r .private_key_pem | head -1` prints exactly `-----BEGIN PRIVATE KEY-----`; `openssl x509 -noout -subject` on `certificate_pem` names the certificate; `base64 -d` of `pkcs12_base64` opens with `openssl pkcs12 -info -nokeys -passin pass:`.
5. Refusals: the non-exportable certificate answers 403 `certificate_not_exportable`; `old-cert` (pre-existing) answers 403 `certificate_not_exportable`; a key export by the service account answers the middleware 403 (it has no Key Exporter role); creating an exportable certificate over `old-key` answers 409 naming `exportable`.
6. `rocketvault audit` query (or `GET /api/v1/audit`) shows one `export_certificate` event per attempt, with no key text or password anywhere.

Expected: every step behaves as stated. Then `kill $NEW_PID && git worktree remove "$SMOKE/pre"` and delete `$SMOKE`.

- [ ] **Step 6: Report**

The report to Rocket carries the commit hashes of all three plans, the final routes and bodies (Task 3's developer-guide text), how to start an isolated instance (Steps 2-3), and how to create a service principal with the exporter role plus an exportable RSA certificate, an exportable EC certificate and a non-exportable one (Step 5). Nothing to commit.

---

## Self-Review

- **Spec coverage (plan 3's share):** §3 `ExportKey` beside `GetPublicJWK`, `GetKey` gate, `pkcs11:`/`oct`/non-exportable/ES256K refusals, version via `CurrentVersion`/`ReadVersionValue`, PKCS#8 (Task 1); §5 key routes on both shapes, optional body, 400 on unknown format, response shape, headers, R6 errors (Task 2); §6 no retry, no cache, no logging, per-attempt audit, middleware-logged role denial (Tasks 1, 2); §3 amendment and §7 parity (Task 4); Documentation section in full: OpenAPI and inventory (Task 2), role enum (plan 1 Task 6), developer guide and mTLS example with caveats (Task 3), parity rows/role table/counts, decision record, bulk-export rename, "eleven" mentions, CLAUDE.md (Task 4); Testing: key service list (Task 1), API both shapes and no-logging for keys (Task 2); Regression safety hard gates and the isolated upgrade smoke test (Task 5); Delivery report contents (Task 5 Step 6).
- **Type consistency:** `ExportKeyResult{ID, Name, Type, Version, Format, PrivateKeyPEM, KeyAlgorithm}`, `ExportKey(ctx, scope, id, version int)`, `ExportKeyAPIRequest{Format, Version}`, `ExportKeyResponse`; plan 2's helpers used with their exact signatures (`exportFailureFor(err, "key")`, `decodeExportBody(r, &req, true)`, `exportCaller(c, r)`, `recordExportAudit(c, r, audit)`, `newExportCtx(nil, svc, audit)`, `newExportChain(t, nil, svc, deny)`).
