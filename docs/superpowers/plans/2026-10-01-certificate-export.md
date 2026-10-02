# Certificate Export Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let a principal holding Key Vault Certificate Exporter fetch one exportable certificate (optionally one version) as a leaf-first chain plus an unencrypted PKCS#8 key in PEM, or as a PKCS12 bundle, over `POST .../certificates/{certificate_id}/export` on both route shapes, with `no-store` headers, an R6 error body, a structured audit event per attempt, and no material or password ever logged, cached or retried.

**Architecture:** `CertificateService.ExportCertificate` reads the parent through the repository (never the cache), applies the parent's lifecycle gate and `Certificate.VersionUsable`, refuses a non-exportable certificate, decrypts the stored key copy of the addressed version, re-marshals it to PKCS#8, and walks `CACertID` with scoped reads (depth 10, cycle guard, root excluded). The PEM and PKCS12 encoders live in `internal/crypto` (PKCS12 via `software.sslmate.com/src/go-pkcs12`). A new `api/export.go` holds the export-only R6 error helper, the header helper, the error mapping and the audit helper that the key export route in plan 3 reuses; the cache and retry wrappers pass `ExportCertificate` straight through.

**Tech Stack:** Go 1.25 (`go.mod`), `software.sslmate.com/src/go-pkcs12` v0.7.3 (new, approved by the user on 2026-10-01), `crypto/x509`, SQLite, Gorilla Mux, testify, mockery v2.53.6, OpenSSL 3 (end-to-end test only, skipped when absent).

**Spec:** `docs/superpowers/specs/2026-10-01-certificate-and-key-export-design.md` (intent: `docs/superpowers/intents/2026-10-01-certificate-and-key-export.md`).

**Plan series:** plan 2 of 3. It requires plan 1 (`docs/superpowers/plans/2026-10-01-export-flag-roles-creation.md`) to be fully landed and consumes exactly these symbols from it: `model.Certificate.Exportable`, `model.Key.Exportable`, `model.ActionCertificatesExportItem`, `model.ActionKeysExport`, `model.RoleKeyVaultCertificateExporter`, `model.RoleKeyVaultKeyExporter`, `crypto.KeyAlgorithmFromCertificatePEM`, `crypto.KeyAlgorithmFromPublicKey`, `certificates.CreateCertificateRequest.Exportable`, `keys.CreateKeyRequest.Exportable`, and the `MapRouteToDataAction` mapping of `POST .../export`. Plan 3 consumes the symbols this plan lists under "Produces".

## Global Constraints

Binding requirements copied from the spec, one per line:

- `CertificateService.ExportCertificate(ctx, scope, id, ExportCertificateRequest)` where the request carries `Format` (`pem` or `pkcs12`), `Password *string`, `Compat` (`modern` or `legacy`) and `Version int` (0 means latest).
- Read the certificate in vault scope. Missing, soft-deleted or out of scope: 404. The parent's lifecycle gate applies (disabled or outside its valid time window: 409 `certificate_disabled`, `ErrCertLifecycleDenied`).
- Resolve the version: 0 or the current number uses the parent row; an archived number uses `certificate_versions` (404 if absent). The usability check is `Certificate.VersionUsable(v)`. A failed check is a 409 `certificate_disabled`.
- `exportable` false: 403 `certificate_not_exportable`, with a reason.
- Decrypt the stored key copy for that version, parse it with `crypto.ParsePrivateKey`, and re-marshal with `x509.MarshalPKCS8PrivateKey`. Export always emits PKCS#8, starting exactly with `-----BEGIN PRIVATE KEY-----`, unencrypted, no preamble. A type the standard library cannot encode (ES256K): 403 `certificate_not_exportable` with a reason.
- Chain: leaf first, then intermediates found by walking `CACertID`, with a depth cap of 10, cycle detection, and a scoped read per hop. The root is excluded: a chain stops before the self-signed certificate. A self-signed leaf exports alone. Each hop uses the CA certificate's current PEM (documented limit).
- `pem`: return `certificate_pem` (the chain) and `private_key_pem`. `pkcs12`: the `password` field must be present (400 otherwise; an empty string is allowed). Encode with `go-pkcs12`: `modern` by default, and `compat: "legacy"` uses PBE-SHA1-3DES with a SHA-1 MAC.
- Report `key_algorithm` computed from the leaf's public key, also when export is refused.
- A key rotation does not change an exported certificate: export reflects the certificate's own stored key copy until the certificate is renewed.
- Routes: `POST /api/v1/vaults/{vault_name}/certificates/{certificate_id}/export` and `POST /api/v1/certificates/{certificate_id}/export`.
- Request body `{"format","password","compat","version"}`. Unknown `format` or `compat`: 400.
- Responses are plain JSON, no `Content-Disposition`, under 64 KiB. PEM: `{id, name, version, format:"pem", certificate_pem, private_key_pem, not_before, expires_at, key_algorithm}`; PKCS12: `{id, name, version, format:"pkcs12", pkcs12_base64, not_before, expires_at, key_algorithm}`.
- Every export response sets `Cache-Control: no-store` and `Pragma: no-cache`.
- Errors on the export routes use `{"error":{"code","message"}}` through a local helper; the rest of the API keeps its flat body. Codes: 400 `bad_request`, 403 `certificate_not_exportable`/`key_not_exportable`, 404 `not_found`, 409 `certificate_disabled`/`key_disabled`. The 401 and the missing-role 403 come from the existing middleware and keep their bodies. Messages and internal errors never contain key material or the password; internal failures return a generic message.
- `certcache` and the retry wrapper pass `ExportCertificate` and `ExportKey` straight through: no cache fill, no cache hit, no retry of a failed call.
- Logs, audit records and errors never carry material or the password.
- Every attempt, allowed or denied, writes a structured `AuditService.RecordEvent` (principal, vault, resource type, id, name, version, format, outcome) with `ResourceID` set. Role denials are already logged by `PolicyMiddleware`.
- End to end: an exported identity drives a real TLS handshake against `openssl s_server -Verify 1`, PEM and PKCS12, RSA and EC.

Regression safety (the spec's whole section, binding):

- **Existing data stays safe and unchanged.** The migration only adds a column with `DEFAULT FALSE`. Every existing certificate and key reads as non-exportable, and nothing is backfilled or rewritten. An upgrade test opens a database created by the pre-export build and checks that existing certificates, versions, keys, secrets and role assignments are all intact and readable.
- **Existing API responses only gain fields.** `CertificateResponse` and `KeyResponse` gain `exportable` and `key_algorithm`; no existing field is renamed, removed or retyped, and no existing status code or error body changes (the R6 body is used only on the new export routes). Golden-response tests for create, get, list and update pin this, and `openapi_drift_test` and the route contract tests pass.
- **No existing role gains export.** A role-matrix test asserts that the effective data actions of every pre-existing built-in role are exactly what they were before (only the two new roles and Administrator hold the new actions). Existing role assignments, the grant allow-list and global-admin behavior are unchanged. The role-count updates ("eleven" to thirteen) are the only edits to existing role code.
- **Existing creation and update paths behave the same.** A create without `exportable` produces exactly what it produced before (non-exportable); update, rotate, renew, versions, soft-delete, recover and purge behave as before, and the existing suites for them pass unmodified except where a count or a new field is asserted.
- **Backup, restore and rekey stay compatible.** Blobs written before this change restore unchanged (as non-exportable); a restore never grants exportability; master-key rotation and the backup table order are unaffected.
- **No new weakness in the old surfaces.** Caching, retry and logging behavior of existing methods is unchanged; the new methods are pass-through only, and the existing middleware and policy chain is not modified beyond the new route mappings (unmapped paths still fail closed).
- **Hard gates before reporting done:** `go build ./...`, `go vet ./...` and `go test ./... -count=1` pass with no failing package; the pre-existing tests are not weakened or deleted to make room; and a live smoke test on an isolated instance upgrades a database from the pre-export build and exercises the existing certificate, key, secret and role flows before the new export flows.

Repository conventions for this series:

- Schema changes are dual-written (`createOptimizedSchema` and `migrateSchema`). This plan adds no schema change.
- No new data actions beyond `ActionCertificatesExportItem` and `ActionKeysExport` (both from plan 1). Unmapped paths still fail closed.
- Metadata responses never carry material; only the export route's success body carries the chain and key.
- Every new route is registered on both the flat and the vault-scoped router through `registerCertificateRoutes`.
- `docs/api-specification.yaml` and `docs/api-routes.generated.txt` cover both route shapes; `TestOpenAPISpecCoversAllRoutes`, `TestGenerateRouteInventory` and `TestAuthorizationMatrixOpsAreRealRoutes` pass.
- Commits go through the `dev-workflow-skills:1-git-commit` plugin skill (Skill tool), never a freeform `git commit -m`. Commits are GPG signed (key 61D246B30285ED35).
- Code comments are short full sentences ending with a punctuation mark.
- mockery fails under the default go1.27 toolchain. Regenerate with the cached go1.25.7 toolchain from the repo root: `PATH="$HOME/go/pkg/mod/golang.org/toolchain@v0.0.1-go1.25.7.linux-amd64/bin:$PATH" GOTOOLCHAIN=local ~/go/bin/mockery` (mockery v2.53.6 is in `~/go/bin`). Never run `~/go/bin/mockery --version`: it starts a full generation run.
- Run tests with `-p 2`; if the sandbox still hits `newosproc`, prefix `GOMAXPROCS=1`.
- `ExportCertificate` reads from the repository, never from `certcache`. The instruction that motivated this said cached rows serialise an empty `private_key`; that is not accurate today (`internal/certcache/cache_l2_test.go:113-119` round-trips the ciphertext), but the rule stands: export must reflect the committed row and must never depend on cache freshness.
- `Context.SetConflict` already exists (`api/context.go:118-121`). The export handlers never set `c.Err` at all, because `writeError` would emit the flat body.

## Review Focus

1. **The export route falling back to the flat error body.** `ApiSessionRequired` calls `writeError` whenever `c.Err` is set, which emits the flat body and, for a 500, `detailed_error: err.Error()` that could carry a wrapped driver string. Pin: `TestExportCertificateHandler_ErrorBodiesAreR6AndGeneric` (Task 4).
2. **Key or password text reaching a log line or audit row.** The audit `Details` are hand-built and the service logs messages; one `%v` of the request or result would leak. Pin: `TestExportThroughRealChain_NoSecretsInLogsOrAudit` (Task 5).
3. **A chain walk escaping the caller's vault or looping.** `CACertID` is a raw id; an edited row could point at another vault's CA or form a cycle. Pin: `TestExportCertificate_ChainGuards` (Task 2).
4. **An archived version exported through a disabled parent, or a disabled archived version exported.** Pin: `TestExportCertificate_VersionGating` (Task 2).
5. **The cache or retry wrapper replaying or storing an export.** Pin: `TestCachedExportCertificate_NeverCaches` and `TestRetryExportCertificate_IsNotRetried` (Task 3).

---

## File Structure

| File | Responsibility |
|---|---|
| `go.mod`, `go.sum` (modify) | `software.sslmate.com/src/go-pkcs12 v0.7.3` |
| `model/export.go` (modify) | export vocabulary: formats, `ErrInvalidExportRequest`, `ErrCertificateNotExportable`, `ErrKeyNotExportable`, `ExportRefusedError` |
| `internal/crypto/export_encoding.go` (create) | `MarshalPKCS8PrivateKeyPEM`, `EncodePKCS12`, `ErrNotPKCS8Encodable` |
| `internal/services/certificates/certificate_export.go` (create) | `ExportCertificateRequest`, `ExportCertificateResult`, `ExportCertificate`, chain walk |
| `internal/services/certificates/certificate_service.go` (modify) | interface method |
| `internal/certcache/cache_integration.go`, `internal/services/retry/retry_certificate_service.go` (modify) | pass-through |
| `internal/services/certificates/mocks/mock_CertificateService.go` (regenerate) | mockery |
| test fakes (modify) | `ExportCertificate` stubs |
| `api/export.go` (create) | R6 helper, headers, body decode, error mapping, audit helper, certificate handler |
| `api/certificates.go` (modify) | route registration |
| `docs/api-specification.yaml`, `docs/api-routes.generated.txt` (modify) | both route shapes, schemas |

---

### Task 1: The go-pkcs12 dependency, the export vocabulary and the PKCS#8/PKCS12 encoders

**Files:**
- Modify: `go.mod`, `go.sum`
- Modify: `model/export.go` (created by plan 1)
- Create: `internal/crypto/export_encoding.go`
- Test: `internal/crypto/export_encoding_test.go` (create), `model/export_refusal_test.go` (create)

**Interfaces:**
- Consumes: `crypto.ParsePrivateKey`, `crypto.GenerateRSAKeyPEM`, `crypto.GenerateECDSAKeyPEM`, `crypto.CreateSelfSignedCertificatePEM`, `crypto.MarshalSecp256k1PrivateKeyPEM`.
- Produces (plan 3 consumes the starred ones):
  - `model.ExportFormatPEM = "pem"`*, `model.ExportFormatPKCS12 = "pkcs12"`, `model.ExportCompatModern = "modern"`, `model.ExportCompatLegacy = "legacy"`
  - `model.ErrInvalidExportRequest`*, `model.ErrCertificateNotExportable`, `model.ErrKeyNotExportable`*
  - `type model.ExportRefusedError struct { Sentinel error; Reason, Name, KeyAlgorithm string }`* with `Error() string` and `Unwrap() error`
  - `crypto.ErrNotPKCS8Encodable`*, `func crypto.MarshalPKCS8PrivateKeyPEM(priv any) (string, error)`*
  - `func crypto.EncodePKCS12(priv any, leaf *x509.Certificate, intermediates []*x509.Certificate, password string, legacy bool) ([]byte, error)`

- [ ] **Step 1: Add the dependency and read its API**

Run: `go get software.sslmate.com/src/go-pkcs12@v0.7.3 && go mod tidy`
Expected: `go.mod` gains `software.sslmate.com/src/go-pkcs12 v0.7.3`. The calls used below are, from `pkcs12.go` in that module: `var Modern = Modern2023` (PBES2, PBKDF2-HMAC-SHA-256, AES-256-CBC, HMAC-SHA-256 MAC), `var LegacyDES` (PBE-SHA1-3DES for keys and certificates, HMAC-SHA-1 MAC with one iteration), `func (enc *Encoder) Encode(privateKey interface{}, certificate *x509.Certificate, caCerts []*x509.Certificate, password string) ([]byte, error)`, and `func DecodeChain(pfxData []byte, password string) (privateKey interface{}, certificate *x509.Certificate, caCerts []*x509.Certificate, err error)`. Both encoders accept an empty password (verified with v0.7.3).

- [ ] **Step 2: Write the failing tests**

Create `model/export_refusal_test.go`:

```go
package model_test

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"

	"rocketvault/model"
)

func TestExportRefusedError_UnwrapsToItsSentinel(t *testing.T) {
	var err error = &model.ExportRefusedError{Sentinel: model.ErrCertificateNotExportable, Reason: "flag is false", KeyAlgorithm: "RSA-2048"}
	assert.True(t, errors.Is(err, model.ErrCertificateNotExportable))
	assert.False(t, errors.Is(err, model.ErrKeyNotExportable))
	assert.Equal(t, "certificate is not exportable: flag is false", err.Error())

	var refusal *model.ExportRefusedError
	assert.True(t, errors.As(err, &refusal))
	assert.Equal(t, "RSA-2048", refusal.KeyAlgorithm)
}
```

Create `internal/crypto/export_encoding_test.go`:

```go
package crypto

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"strings"
	"testing"

	secp256k1 "github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	pkcs12 "software.sslmate.com/src/go-pkcs12"
)

func TestMarshalPKCS8PrivateKeyPEM_RSAAndEC(t *testing.T) {
	for keyType, gen := range map[string]func() (string, error){
		"RSA":   func() (string, error) { return GenerateRSAKeyPEM(2048) },
		"ECDSA": func() (string, error) { return GenerateECDSAKeyPEM("P-256") },
	} {
		stored, err := gen()
		require.NoError(t, err)
		priv, err := ParsePrivateKey(stored, keyType)
		require.NoError(t, err)

		out, err := MarshalPKCS8PrivateKeyPEM(priv)
		require.NoError(t, err)
		assert.True(t, strings.HasPrefix(out, "-----BEGIN PRIVATE KEY-----\n"), "exact PKCS#8 prefix, no preamble")
		assert.NotContains(t, out, "RSA PRIVATE KEY")
		assert.NotContains(t, out, "EC PRIVATE KEY")

		block, _ := pem.Decode([]byte(out))
		require.NotNil(t, block)
		parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		require.NoError(t, err)
		switch keyType {
		case "RSA":
			assert.True(t, parsed.(*rsa.PrivateKey).Equal(priv))
		case "ECDSA":
			assert.True(t, parsed.(*ecdsa.PrivateKey).Equal(priv))
		}
	}
}

func TestMarshalPKCS8PrivateKeyPEM_ES256KIsRefused(t *testing.T) {
	k, err := secp256k1.GeneratePrivateKey()
	require.NoError(t, err)
	stored, err := MarshalSecp256k1PrivateKeyPEM(k)
	require.NoError(t, err)
	priv, err := ParsePrivateKey(stored, "ES256K")
	require.NoError(t, err)

	_, err = MarshalPKCS8PrivateKeyPEM(priv)
	require.True(t, errors.Is(err, ErrNotPKCS8Encodable))
}

func TestEncodePKCS12_ModernAndLegacyRoundTrip(t *testing.T) {
	stored, err := GenerateECDSAKeyPEM("P-256")
	require.NoError(t, err)
	certPEM, err := CreateSelfSignedCertificatePEM(stored, "ECDSA", CertificateTemplate{CommonName: "p12", ValidityDays: 1})
	require.NoError(t, err)
	priv, err := ParsePrivateKey(stored, "ECDSA")
	require.NoError(t, err)
	block, _ := pem.Decode([]byte(certPEM))
	leaf, err := x509.ParseCertificate(block.Bytes)
	require.NoError(t, err)

	for _, legacy := range []bool{false, true} {
		for _, password := range []string{"", "s3cret"} {
			pfx, err := EncodePKCS12(priv, leaf, nil, password, legacy)
			require.NoError(t, err)
			gotKey, gotLeaf, cas, err := pkcs12.DecodeChain(pfx, password)
			require.NoError(t, err, "legacy=%v password=%q", legacy, password)
			assert.True(t, gotKey.(*ecdsa.PrivateKey).Equal(priv))
			assert.Equal(t, leaf.Raw, gotLeaf.Raw)
			assert.Empty(t, cas)
		}
	}
}
```

- [ ] **Step 3: Run and expect FAIL**

Run: `go test -p 2 ./model ./internal/crypto -run 'ExportRefusedError|PKCS8|PKCS12' -v`
Expected: FAIL (build error: `ExportRefusedError`, `MarshalPKCS8PrivateKeyPEM`, `EncodePKCS12` undefined).

- [ ] **Step 4: Implement the vocabulary and encoders**

Append to `model/export.go`:

```go
// Export formats and PKCS12 compatibility modes accepted by the export routes.
const (
	ExportFormatPEM    = "pem"
	ExportFormatPKCS12 = "pkcs12"
	ExportCompatModern = "modern"
	ExportCompatLegacy = "legacy"
)

// ErrInvalidExportRequest is returned for a malformed export request: an
// unknown format or compat, pkcs12 without a password, or a negative
// version. Its wrapped message is safe to show: it never carries the
// password. The API maps it to 400 bad_request.
var ErrInvalidExportRequest = errors.New("invalid export request")

// ErrCertificateNotExportable is the sentinel behind every certificate
// export refusal. The API maps it to 403 certificate_not_exportable.
var ErrCertificateNotExportable = errors.New("certificate is not exportable")

// ErrKeyNotExportable is the sentinel behind every key export refusal. The
// API maps it to 403 key_not_exportable.
var ErrKeyNotExportable = errors.New("key is not exportable")

// ExportRefusedError explains why an item may not be exported. Reason is a
// fixed phrase chosen by the service, never derived from material. Name and
// KeyAlgorithm let a client and the audit trail show what was refused.
type ExportRefusedError struct {
	Sentinel     error
	Reason       string
	Name         string
	KeyAlgorithm string
}

// Error returns the sentinel's text followed by the reason.
func (e *ExportRefusedError) Error() string {
	return e.Sentinel.Error() + ": " + e.Reason
}

// Unwrap returns the sentinel, so errors.Is matches the refusal kind.
func (e *ExportRefusedError) Unwrap() error { return e.Sentinel }
```

Create `internal/crypto/export_encoding.go`:

```go
package crypto

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"

	pkcs12 "software.sslmate.com/src/go-pkcs12"
)

// ErrNotPKCS8Encodable is returned for a private key the standard library
// cannot encode as PKCS#8, such as a secp256k1 (ES256K) key.
var ErrNotPKCS8Encodable = errors.New("key type cannot be encoded as PKCS#8")

// MarshalPKCS8PrivateKeyPEM encodes priv as an unencrypted PKCS#8 PEM block.
// The result starts exactly with "-----BEGIN PRIVATE KEY-----" and carries
// no preamble. Stored keys are PKCS#1 or SEC1; export always emits PKCS#8.
func MarshalPKCS8PrivateKeyPEM(priv any) (string, error) {
	switch priv.(type) {
	case *rsa.PrivateKey, *ecdsa.PrivateKey, ed25519.PrivateKey:
	default:
		return "", ErrNotPKCS8Encodable
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return "", fmt.Errorf("%w: %w", ErrNotPKCS8Encodable, err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})), nil
}

// EncodePKCS12 builds a PKCS12 bundle of priv, leaf and the intermediates.
// The modern encoder is the default; legacy selects PBE-SHA1-3DES with a
// SHA-1 MAC for old consumers. An empty password is allowed.
func EncodePKCS12(priv any, leaf *x509.Certificate, intermediates []*x509.Certificate, password string, legacy bool) ([]byte, error) {
	enc := pkcs12.Modern
	if legacy {
		enc = pkcs12.LegacyDES
	}
	pfx, err := enc.Encode(priv, leaf, intermediates, password)
	if err != nil {
		return nil, fmt.Errorf("encode pkcs12: %w", err)
	}
	return pfx, nil
}
```

- [ ] **Step 5: Run and expect PASS**

Run: `go test -p 2 ./model ./internal/crypto -count=1`
Expected: PASS.

- [ ] **Step 6: Commit**

Commit via the `dev-workflow-skills:1-git-commit` skill. Stage: `go.mod`, `go.sum`, `model/export.go`, `model/export_refusal_test.go`, `internal/crypto/export_encoding.go`, `internal/crypto/export_encoding_test.go`.

---

### Task 2: `CertificateService.ExportCertificate`, interface, wrapper pass-throughs, fakes and mock

**Files:**
- Create: `internal/services/certificates/certificate_export.go`
- Modify: `internal/services/certificates/certificate_service.go:131-184` (interface, after `UpdateCertificateVersion`)
- Modify: `internal/certcache/cache_integration.go` (append), `internal/services/retry/retry_certificate_service.go` (append)
- Regenerate: `internal/services/certificates/mocks/mock_CertificateService.go`
- Modify fakes (add an `ExportCertificate` method): `internal/services/certificates/renewal_service_test.go` (`mockCertSvcForRenewal`, `:108`), `internal/services/certificates/certificate_service_extended_test.go` (`mockRenewalCertSvc`, `:888`), `api/vault_scoped_keys_certs_test.go` (`recordingCertService`, `:128`), `api/certificates_test.go` (`mockCertService`, `:49`), `cmd/certificates/certs_cmd_test.go` (`certCmdCertService`, `:45`)
- Test: `internal/services/certificates/certificate_export_test.go` (create)

**Interfaces:**
- Consumes: Task 1; `newVersioningHarness`, `addKey` (plan 1 Task 5, `certificate_exportable_test.go`), `isSelfSignedPEM`, `extractValidity`, `common.DecryptSecret`, `crypto.DetectPrivateKeyType`, `crypto.ParsePrivateKey`, `ErrCertNotFound`, `ErrCertLifecycleDenied`, `ErrCertVersioningUnavailable`, `CertificateVersionRepositoryInterface.ListVersionRecords`.
- Produces:
  - `type ExportCertificateRequest struct { Format string; Password *string; Compat string; Version int }`
  - `type ExportCertificateResult struct { ID uuid.UUID; Name string; Version int; Format string; CertificatePEM string; PrivateKeyPEM string; PKCS12 []byte; NotBefore *time.Time; ExpiresAt *time.Time; KeyAlgorithm string }`
  - `CertificateService.ExportCertificate(ctx context.Context, scope model.Scope, id uuid.UUID, req ExportCertificateRequest) (*ExportCertificateResult, error)`
  - `var ErrCertificateChainUnavailable` and `const maxExportChainDepth = 10`
  - Errors: `model.ErrInvalidExportRequest` (400), `ErrCertNotFound`/`model.ErrCertificateVersionNotFound` (404), `ErrCertLifecycleDenied` (409), `*model.ExportRefusedError` wrapping `model.ErrCertificateNotExportable` (403), anything else (500).

- [ ] **Step 1: Write the failing service tests**

Create `internal/services/certificates/certificate_export_test.go`:

```go
package certificates

import (
	"context"
	gocrypto "crypto"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	pkcs12 "software.sslmate.com/src/go-pkcs12"

	"rocketvault/common"
	"rocketvault/internal/crypto"
	"rocketvault/model"
)

func strPtr(s string) *string { return &s }

// createExportable issues a self-signed exportable certificate over a fresh
// exportable key of the given type ("RSA" or "ECDSA").
func createExportable(t *testing.T, h *versioningHarness, name, keyType string) uuid.UUID {
	t.Helper()
	keyID := uuid.New()
	var keyPEM string
	var err error
	if keyType == "RSA" {
		keyPEM, err = crypto.GenerateRSAKeyPEM(2048)
	} else {
		keyPEM, err = crypto.GenerateECDSAKeyPEM("P-256")
	}
	require.NoError(t, err)
	enc, err := common.EncryptSecret(keyPEM)
	require.NoError(t, err)
	k := &model.Key{ID: keyID, UserID: h.userID, VaultID: h.vaultID, Name: name + "-key", Type: model.KeyTypeRSA,
		Value: enc, Enabled: true, CreatedAt: time.Now(), Bits: 2048, Exportable: true}
	if keyType != "RSA" {
		k.Type, k.Bits, k.Curve = model.KeyTypeECDSA, 0, "P-256"
	}
	require.NoError(t, h.keyRepo.Create(context.Background(), k))
	res, err := h.svc.CreateSelfSignedCertificate(context.Background(), CreateCertificateRequest{
		Name: name, KeyID: keyID, ValidityDays: 30, UserID: h.userID, VaultID: h.vaultID, Exportable: true,
	})
	require.NoError(t, err)
	return res.CertID
}

// insertCert stores a certificate row directly, for chains the create paths
// cannot build (intermediate CAs) and for edited-row guards.
func insertCert(t *testing.T, h *versioningHarness, vaultID uuid.UUID, certPEM, keyPEM string, caID *uuid.UUID) uuid.UUID {
	t.Helper()
	enc, err := common.EncryptSecret(keyPEM)
	require.NoError(t, err)
	id := uuid.New()
	require.NoError(t, h.certRepo.Create(context.Background(), &model.Certificate{
		ID: id, UserID: h.userID, VaultID: vaultID, KeyID: uuid.New(), CACertID: caID, Name: "c-" + id.String()[:8],
		Certificate: certPEM, PrivateKey: enc, CreatedAt: time.Now(), Enabled: true, Version: 1, Exportable: true,
	}))
	return id
}

func parsePEMCerts(t *testing.T, chain string) []*x509.Certificate {
	t.Helper()
	var out []*x509.Certificate
	rest := []byte(chain)
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			return out
		}
		c, err := x509.ParseCertificate(block.Bytes)
		require.NoError(t, err)
		out = append(out, c)
	}
}

func TestExportCertificate_PEM_RSAAndEC(t *testing.T) {
	h := newVersioningHarness(t)
	for keyType, alg := range map[string]string{"RSA": "RSA-2048", "ECDSA": "EC-P256"} {
		id := createExportable(t, h, "pem-"+strings.ToLower(keyType), keyType)
		res, err := h.svc.ExportCertificate(context.Background(), h.scope(), id, ExportCertificateRequest{Format: model.ExportFormatPEM})
		require.NoError(t, err)

		assert.True(t, strings.HasPrefix(res.PrivateKeyPEM, "-----BEGIN PRIVATE KEY-----\n"), "exact PKCS#8 prefix")
		assert.Equal(t, alg, res.KeyAlgorithm)
		assert.Equal(t, 1, res.Version)
		assert.Equal(t, model.ExportFormatPEM, res.Format)
		require.NotNil(t, res.NotBefore)
		require.NotNil(t, res.ExpiresAt)
		assert.Nil(t, res.PKCS12)

		certs := parsePEMCerts(t, res.CertificatePEM)
		require.Len(t, certs, 1, "a self-signed leaf exports alone")
		block, _ := pem.Decode([]byte(res.PrivateKeyPEM))
		priv, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		require.NoError(t, err)
		leafPub := certs[0].PublicKey.(interface{ Equal(gocrypto.PublicKey) bool })
		assert.True(t, leafPub.Equal(priv.(gocrypto.Signer).Public()), "the key matches the leaf")
	}
}

func TestExportCertificate_PKCS12ModernLegacyAndEmptyPassword(t *testing.T) {
	h := newVersioningHarness(t)
	id := createExportable(t, h, "p12", "ECDSA")
	for _, compat := range []string{"", model.ExportCompatModern, model.ExportCompatLegacy} {
		for _, password := range []string{"", "s3cret"} {
			res, err := h.svc.ExportCertificate(context.Background(), h.scope(), id, ExportCertificateRequest{
				Format: model.ExportFormatPKCS12, Password: strPtr(password), Compat: compat,
			})
			require.NoError(t, err)
			assert.Empty(t, res.PrivateKeyPEM)
			_, leaf, cas, err := pkcs12.DecodeChain(res.PKCS12, password)
			require.NoError(t, err, "compat=%q password=%q", compat, password)
			assert.Equal(t, "p12", leaf.Subject.CommonName)
			assert.Empty(t, cas)
		}
	}
}

func TestExportCertificate_RequestValidation(t *testing.T) {
	h := newVersioningHarness(t)
	id := createExportable(t, h, "bad", "RSA")
	const password = "zz-validation-secret-zz"
	for name, req := range map[string]ExportCertificateRequest{
		"unknown format":     {Format: "der", Password: strPtr(password)},
		"missing format":     {},
		"unknown compat":     {Format: model.ExportFormatPKCS12, Password: strPtr(password), Compat: "ancient"},
		"pkcs12 no password": {Format: model.ExportFormatPKCS12},
		"negative version":   {Format: model.ExportFormatPEM, Password: strPtr(password), Version: -1},
	} {
		_, err := h.svc.ExportCertificate(context.Background(), h.scope(), id, req)
		require.ErrorIs(t, err, model.ErrInvalidExportRequest, name)
		assert.NotContains(t, err.Error(), password, "the password never reaches the message: "+name)
	}
}

func TestExportCertificate_Refusals(t *testing.T) {
	h := newVersioningHarness(t)
	ctx := context.Background()

	// Not exportable: created over a key without the flag.
	plain, err := h.svc.CreateSelfSignedCertificate(ctx, CreateCertificateRequest{
		Name: "plain", KeyID: h.keyID, ValidityDays: 30, UserID: h.userID, VaultID: h.vaultID,
	})
	require.NoError(t, err)
	_, err = h.svc.ExportCertificate(ctx, h.scope(), plain.CertID, ExportCertificateRequest{Format: model.ExportFormatPEM})
	var refusal *model.ExportRefusedError
	require.True(t, errors.As(err, &refusal))
	assert.ErrorIs(t, err, model.ErrCertificateNotExportable)
	assert.Equal(t, "RSA-2048", refusal.KeyAlgorithm, "key_algorithm is reported on refusal too")
	assert.Equal(t, "plain", refusal.Name)

	// ES256K: a stored secp256k1 key cannot be encoded as PKCS#8.
	rsaKeyPEM, err := crypto.GenerateRSAKeyPEM(2048)
	require.NoError(t, err)
	leafPEM, err := crypto.CreateSelfSignedCertificatePEM(rsaKeyPEM, "RSA", crypto.CertificateTemplate{CommonName: "k1", ValidityDays: 1})
	require.NoError(t, err)
	k1, err := crypto.GenerateECDSAKeyPEM("P-256K")
	require.NoError(t, err)
	es := insertCert(t, h, h.vaultID, leafPEM, k1, nil)
	_, err = h.svc.ExportCertificate(ctx, h.scope(), es, ExportCertificateRequest{Format: model.ExportFormatPEM})
	require.ErrorIs(t, err, model.ErrCertificateNotExportable)
	assert.Contains(t, err.Error(), "PKCS#8")

	// Disabled.
	disabledID := createExportable(t, h, "disabled", "RSA")
	off := false
	require.NoError(t, h.svc.UpdateCertificate(ctx, UpdateCertificateRequest{CertID: disabledID, Scope: h.scope(), Enabled: &off}))
	_, err = h.svc.ExportCertificate(ctx, h.scope(), disabledID, ExportCertificateRequest{Format: model.ExportFormatPEM})
	require.ErrorIs(t, err, ErrCertLifecycleDenied)

	// Unknown, out of vault, soft-deleted.
	_, err = h.svc.ExportCertificate(ctx, h.scope(), uuid.New(), ExportCertificateRequest{Format: model.ExportFormatPEM})
	require.ErrorIs(t, err, ErrCertNotFound)
	other := model.NewVaultScope(uuid.New(), h.userID)
	okID := createExportable(t, h, "elsewhere", "RSA")
	_, err = h.svc.ExportCertificate(ctx, other, okID, ExportCertificateRequest{Format: model.ExportFormatPEM})
	require.ErrorIs(t, err, ErrCertNotFound)
	require.NoError(t, h.svc.DeleteCertificate(ctx, okID, h.scope()))
	_, err = h.svc.ExportCertificate(ctx, h.scope(), okID, ExportCertificateRequest{Format: model.ExportFormatPEM})
	require.ErrorIs(t, err, ErrCertNotFound)
}

func TestExportCertificate_VersionGating(t *testing.T) {
	h := newVersioningHarness(t)
	ctx := context.Background()
	id := createExportable(t, h, "versions", "RSA")
	_, err := h.svc.RenewCertificate(ctx, id, h.scope(), 30)
	require.NoError(t, err)

	v1, err := h.svc.ExportCertificate(ctx, h.scope(), id, ExportCertificateRequest{Format: model.ExportFormatPEM, Version: 1})
	require.NoError(t, err, "an enabled archived version exports")
	v2, err := h.svc.ExportCertificate(ctx, h.scope(), id, ExportCertificateRequest{Format: model.ExportFormatPEM})
	require.NoError(t, err)
	assert.Equal(t, 1, v1.Version)
	assert.Equal(t, 2, v2.Version)
	assert.NotEqual(t, v1.CertificatePEM, v2.CertificatePEM, "the archived version exports its own body")

	_, err = h.svc.ExportCertificate(ctx, h.scope(), id, ExportCertificateRequest{Format: model.ExportFormatPEM, Version: 3})
	require.ErrorIs(t, err, model.ErrCertificateVersionNotFound)

	off := false
	_, err = h.svc.UpdateCertificateVersion(ctx, UpdateCertificateVersionRequest{CertID: id, Version: 1, Scope: h.scope(), Enabled: &off})
	require.NoError(t, err)
	_, err = h.svc.ExportCertificate(ctx, h.scope(), id, ExportCertificateRequest{Format: model.ExportFormatPEM, Version: 1})
	require.ErrorIs(t, err, ErrCertLifecycleDenied, "a disabled archived version is a 409")

	on := true
	future := time.Now().Add(time.Hour)
	_, err = h.svc.UpdateCertificateVersion(ctx, UpdateCertificateVersionRequest{CertID: id, Version: 1, Scope: h.scope(), Enabled: &on, NotBefore: &future})
	require.NoError(t, err)
	_, err = h.svc.ExportCertificate(ctx, h.scope(), id, ExportCertificateRequest{Format: model.ExportFormatPEM, Version: 1})
	require.ErrorIs(t, err, ErrCertLifecycleDenied, "a not-yet-valid archived version is a 409")

	past := time.Now().Add(-time.Hour)
	before := past.Add(-time.Hour)
	_, err = h.svc.UpdateCertificateVersion(ctx, UpdateCertificateVersionRequest{CertID: id, Version: 1, Scope: h.scope(), NotBefore: &before, ExpiresAt: &past})
	require.NoError(t, err)
	_, err = h.svc.ExportCertificate(ctx, h.scope(), id, ExportCertificateRequest{Format: model.ExportFormatPEM, Version: 1})
	require.ErrorIs(t, err, ErrCertLifecycleDenied, "an expired archived version is a 409")

	require.NoError(t, h.svc.UpdateCertificate(ctx, UpdateCertificateRequest{CertID: id, Scope: h.scope(), Enabled: &off}))
	_, err = h.svc.ExportCertificate(ctx, h.scope(), id, ExportCertificateRequest{Format: model.ExportFormatPEM})
	require.ErrorIs(t, err, ErrCertLifecycleDenied, "a disabled certificate blocks every version")
}

// TestExportCertificate_ChainLeafFirstNoRoot builds root -> intermediate ->
// leaf directly in the repository (the create path refuses intermediate CAs)
// and checks the chain is leaf then intermediate, with the root excluded.
func TestExportCertificate_ChainLeafFirstNoRoot(t *testing.T) {
	h := newVersioningHarness(t)
	rootKey, err := crypto.GenerateRSAKeyPEM(2048)
	require.NoError(t, err)
	rootPEM, err := crypto.CreateSelfSignedCertificatePEM(rootKey, "RSA", crypto.CertificateTemplate{CommonName: "root", ValidityDays: 30, IsCA: true})
	require.NoError(t, err)
	intKey, err := crypto.GenerateRSAKeyPEM(2048)
	require.NoError(t, err)
	intPEM, err := crypto.CreateCASignedCertificatePEM(intKey, "RSA", rootPEM, rootKey, "RSA", crypto.CertificateTemplate{CommonName: "intermediate", ValidityDays: 30, IsCA: true})
	require.NoError(t, err)
	leafKey, err := crypto.GenerateECDSAKeyPEM("P-256")
	require.NoError(t, err)
	leafPEM, err := crypto.CreateCASignedCertificatePEM(leafKey, "ECDSA", intPEM, intKey, "RSA", crypto.CertificateTemplate{CommonName: "leaf", ValidityDays: 30})
	require.NoError(t, err)

	rootID := insertCert(t, h, h.vaultID, rootPEM, rootKey, nil)
	intID := insertCert(t, h, h.vaultID, intPEM, intKey, &rootID)
	leafID := insertCert(t, h, h.vaultID, leafPEM, leafKey, &intID)

	res, err := h.svc.ExportCertificate(context.Background(), h.scope(), leafID, ExportCertificateRequest{Format: model.ExportFormatPEM})
	require.NoError(t, err)
	certs := parsePEMCerts(t, res.CertificatePEM)
	require.Len(t, certs, 2)
	assert.Equal(t, "leaf", certs[0].Subject.CommonName)
	assert.Equal(t, "intermediate", certs[1].Subject.CommonName)

	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM([]byte(rootPEM))
	inters := x509.NewCertPool()
	inters.AddCert(certs[1])
	_, err = certs[0].Verify(x509.VerifyOptions{Roots: roots, Intermediates: inters, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}})
	require.NoError(t, err, "the exported chain verifies against the root")

	p12, err := h.svc.ExportCertificate(context.Background(), h.scope(), leafID, ExportCertificateRequest{Format: model.ExportFormatPKCS12, Password: strPtr("")})
	require.NoError(t, err)
	_, _, cas, err := pkcs12.DecodeChain(p12.PKCS12, "")
	require.NoError(t, err)
	require.Len(t, cas, 1)
	assert.Equal(t, "intermediate", cas[0].Subject.CommonName)
}

func TestExportCertificate_ChainGuards(t *testing.T) {
	h := newVersioningHarness(t)
	ctx := context.Background()
	caKey, err := crypto.GenerateRSAKeyPEM(2048)
	require.NoError(t, err)
	caPEM, err := crypto.CreateSelfSignedCertificatePEM(caKey, "RSA", crypto.CertificateTemplate{CommonName: "ca", ValidityDays: 30, IsCA: true})
	require.NoError(t, err)
	// hopPEM is CA-signed, so the walk never treats a hop as the root.
	hopPEM, err := crypto.CreateCASignedCertificatePEM(caKey, "RSA", caPEM, caKey, "RSA", crypto.CertificateTemplate{CommonName: "hop", ValidityDays: 30, IsCA: true})
	require.NoError(t, err)

	// Depth: a leaf over a straight line of 11 non-root hops exceeds the cap.
	var next *uuid.UUID
	for i := 0; i < maxExportChainDepth+1; i++ {
		id := insertCert(t, h, h.vaultID, hopPEM, caKey, next)
		next = &id
	}
	deep := insertCert(t, h, h.vaultID, hopPEM, caKey, next)
	_, err = h.svc.ExportCertificate(ctx, h.scope(), deep, ExportCertificateRequest{Format: model.ExportFormatPEM})
	require.ErrorIs(t, err, ErrCertificateChainUnavailable)

	// Cycle: a and b name each other.
	a := insertCert(t, h, h.vaultID, hopPEM, caKey, nil)
	b := insertCert(t, h, h.vaultID, hopPEM, caKey, &a)
	_, err = h.raw.Exec("UPDATE certificates SET ca_cert_id = ? WHERE id = ?", b.String(), a.String())
	require.NoError(t, err)
	_, err = h.svc.ExportCertificate(ctx, h.scope(), a, ExportCertificateRequest{Format: model.ExportFormatPEM})
	require.ErrorIs(t, err, ErrCertificateChainUnavailable)

	// Scope: a hop in another vault is not readable, so the chain fails
	// closed rather than leaking that vault's certificate.
	foreign := insertCert(t, h, uuid.New(), hopPEM, caKey, nil)
	leaf := insertCert(t, h, h.vaultID, hopPEM, caKey, &foreign)
	_, err = h.svc.ExportCertificate(ctx, h.scope(), leaf, ExportCertificateRequest{Format: model.ExportFormatPEM})
	require.ErrorIs(t, err, ErrCertificateChainUnavailable)
}

// TestExportCertificate_ReflectsStoredKeyCopy pins the documented caveat: a
// key rotation does not change the exported certificate's key until the
// certificate is renewed.
func TestExportCertificate_ReflectsStoredKeyCopy(t *testing.T) {
	h := newVersioningHarness(t)
	ctx := context.Background()
	id := createExportable(t, h, "stable", "RSA")
	before, err := h.svc.ExportCertificate(ctx, h.scope(), id, ExportCertificateRequest{Format: model.ExportFormatPEM})
	require.NoError(t, err)

	cert, err := h.certRepo.Read(ctx, id, h.scope())
	require.NoError(t, err)
	newKey, err := crypto.GenerateRSAKeyPEM(2048)
	require.NoError(t, err)
	enc, err := common.EncryptSecret(newKey)
	require.NoError(t, err)
	_, err = h.raw.Exec("UPDATE keys SET value = ? WHERE id = ?", enc, cert.KeyID.String())
	require.NoError(t, err)

	after, err := h.svc.ExportCertificate(ctx, h.scope(), id, ExportCertificateRequest{Format: model.ExportFormatPEM})
	require.NoError(t, err)
	assert.Equal(t, before.PrivateKeyPEM, after.PrivateKeyPEM)
}
```

- [ ] **Step 2: Run and expect FAIL**

Run: `go test -p 2 ./internal/services/certificates -run 'TestExportCertificate_' -v`
Expected: FAIL (build error: `ExportCertificate`, `ExportCertificateRequest`, `maxExportChainDepth`, `ErrCertificateChainUnavailable` undefined).

- [ ] **Step 3: Implement the service method**

Add to the `CertificateService` interface after `UpdateCertificateVersion`:

```go
	// ExportCertificate returns one exportable certificate version as a
	// leaf-first chain plus an unencrypted PKCS#8 key, or as PKCS12,
	// authorized by scope. It always reads the repository, never a cache.
	ExportCertificate(ctx context.Context, scope model.Scope, id uuid.UUID, req ExportCertificateRequest) (*ExportCertificateResult, error)
```

Create `internal/services/certificates/certificate_export.go`:

```go
package certificates

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"

	"rocketvault/common"
	"rocketvault/internal/crypto"
	"rocketvault/model"
)

// maxExportChainDepth caps the CA walk, so an edited ca_cert_id cannot make
// an export loop or walk forever.
const maxExportChainDepth = 10

// ErrCertificateChainUnavailable is returned when the issuer chain cannot be
// built: a CA is missing, soft-deleted, outside the caller's vault, part of
// a cycle, or deeper than maxExportChainDepth. Nothing is exported.
var ErrCertificateChainUnavailable = errors.New("certificate chain cannot be built")

// ExportCertificateRequest selects what ExportCertificate returns. Password
// is a pointer so pkcs12 can tell "absent" from "empty"; an empty password is
// allowed.
type ExportCertificateRequest struct {
	Format   string  // model.ExportFormatPEM or model.ExportFormatPKCS12.
	Password *string // Required for pkcs12; ignored for pem.
	Compat   string  // "", model.ExportCompatModern or model.ExportCompatLegacy.
	Version  int     // 0 means the current version.
}

// ExportCertificateResult is one exported certificate version. It carries
// private material and must never be logged, cached or stored.
type ExportCertificateResult struct {
	ID             uuid.UUID
	Name           string
	Version        int
	Format         string
	CertificatePEM string // Leaf first, then intermediates; pem only.
	PrivateKeyPEM  string // Unencrypted PKCS#8; pem only.
	PKCS12         []byte // pkcs12 only.
	NotBefore      *time.Time
	ExpiresAt      *time.Time
	KeyAlgorithm   string
}

// validateExportRequest rejects a malformed request before anything is read.
// The messages are fixed phrases and never include the password.
func validateExportRequest(req ExportCertificateRequest) error {
	switch req.Format {
	case model.ExportFormatPEM, model.ExportFormatPKCS12:
	default:
		return fmt.Errorf("%w: format must be pem or pkcs12", model.ErrInvalidExportRequest)
	}
	switch req.Compat {
	case "", model.ExportCompatModern, model.ExportCompatLegacy:
	default:
		return fmt.Errorf("%w: compat must be modern or legacy", model.ErrInvalidExportRequest)
	}
	if req.Format == model.ExportFormatPKCS12 && req.Password == nil {
		return fmt.Errorf("%w: pkcs12 requires a password field (it may be empty)", model.ErrInvalidExportRequest)
	}
	if req.Version < 0 {
		return fmt.Errorf("%w: version must be 0 or a positive version number", model.ErrInvalidExportRequest)
	}
	return nil
}

// ExportCertificate implements CertificateService.ExportCertificate.
func (s *certificateService) ExportCertificate(ctx context.Context, scope model.Scope, id uuid.UUID, req ExportCertificateRequest) (*ExportCertificateResult, error) {
	actor := scope.ActorID().String()
	if err := validateExportRequest(req); err != nil {
		return nil, err
	}

	// 1. The scoped repository read is the vault gate; a cache is never used.
	parent, err := s.certRepo.Read(ctx, id, scope)
	if err != nil {
		s.logger.LogAuditError(actor, "export_certificate", "failed", fmt.Sprintf("Certificate not found: %s", id), nil)
		return nil, fmt.Errorf("%w: %s", ErrCertNotFound, err.Error())
	}
	if !parent.IsAccessible() {
		s.logger.LogAuditError(actor, "export_certificate", "denied", fmt.Sprintf("Certificate %s is disabled or outside its valid time window", id), nil)
		return nil, ErrCertLifecycleDenied
	}

	// 2. Resolve the version and apply the per-version gate.
	meta, certPEM, keyCipher, err := s.resolveExportVersion(ctx, parent, req.Version)
	if err != nil {
		return nil, err
	}
	if !parent.VersionUsable(meta) {
		s.logger.LogAuditError(actor, "export_certificate", "denied", fmt.Sprintf("Certificate %s version %d is disabled or outside its valid time window", id, meta.Version), nil)
		return nil, ErrCertLifecycleDenied
	}
	keyAlgorithm := crypto.KeyAlgorithmFromCertificatePEM(certPEM)
	refuse := func(reason string) error {
		s.logger.LogAuditError(actor, "export_certificate", "denied", fmt.Sprintf("Certificate %s not exportable: %s", id, reason), nil)
		return &model.ExportRefusedError{Sentinel: model.ErrCertificateNotExportable, Reason: reason, Name: parent.Name, KeyAlgorithm: keyAlgorithm}
	}

	// 3. The immutable flag.
	if !parent.Exportable {
		return nil, refuse("the certificate was not created with exportable: true")
	}

	// 4. Decrypt the version's own key copy and re-marshal it as PKCS#8.
	keyPEM, err := common.DecryptSecret(keyCipher)
	if err != nil {
		return nil, fmt.Errorf("decrypt certificate key: %w", err)
	}
	keyType, err := crypto.DetectPrivateKeyType(keyPEM)
	if err != nil {
		return nil, fmt.Errorf("classify certificate key: %w", err)
	}
	if keyType == model.KeyTypeES256K {
		return nil, refuse("ES256K (secp256k1) keys cannot be encoded as PKCS#8")
	}
	priv, err := crypto.ParsePrivateKey(keyPEM, keyType)
	if err != nil {
		return nil, fmt.Errorf("parse certificate key: %w", err)
	}
	pkcs8PEM, err := crypto.MarshalPKCS8PrivateKeyPEM(priv)
	if errors.Is(err, crypto.ErrNotPKCS8Encodable) {
		return nil, refuse("the key type cannot be encoded as PKCS#8")
	}
	if err != nil {
		return nil, fmt.Errorf("encode certificate key: %w", err)
	}

	// 5. Leaf first, then intermediates, root excluded.
	leaf, err := parseLeaf(certPEM)
	if err != nil {
		return nil, err
	}
	intermediates, err := s.exportChain(ctx, parent, leaf, scope)
	if err != nil {
		s.logger.LogAuditError(actor, "export_certificate", "failed", fmt.Sprintf("Certificate %s chain unavailable", id), nil)
		return nil, err
	}

	notBefore, notAfter := leaf.NotBefore, leaf.NotAfter
	result := &ExportCertificateResult{
		ID: parent.ID, Name: parent.Name, Version: meta.Version, Format: req.Format,
		NotBefore: &notBefore, ExpiresAt: &notAfter, KeyAlgorithm: keyAlgorithm,
	}

	// 6. Encode.
	if req.Format == model.ExportFormatPKCS12 {
		pfx, err := crypto.EncodePKCS12(priv, leaf, intermediates, *req.Password, req.Compat == model.ExportCompatLegacy)
		if err != nil {
			return nil, err
		}
		result.PKCS12 = pfx
	} else {
		var chain strings.Builder
		chain.Write(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leaf.Raw}))
		for _, c := range intermediates {
			chain.Write(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw}))
		}
		result.CertificatePEM = chain.String()
		result.PrivateKeyPEM = pkcs8PEM
	}

	s.logger.LogAuditInfo(actor, "export_certificate", "success",
		fmt.Sprintf("Certificate %s version %d exported as %s", id, meta.Version, req.Format))
	return result, nil
}

// resolveExportVersion returns the addressed version's metadata, body and
// encrypted key copy. 0 or the current number reads the parent row; an
// archived number reads certificate_versions, whose only gate is the scoped
// parent read the caller already made.
func (s *certificateService) resolveExportVersion(ctx context.Context, parent *model.Certificate, version int) (model.CertificateVersion, string, string, error) {
	current := parent.CurrentVersion()
	if version == 0 || version == current {
		return parent.VersionMetadata(), parent.Certificate, parent.PrivateKey, nil
	}
	if version > current {
		return model.CertificateVersion{}, "", "", fmt.Errorf("%w: certificate %s has no version %d", model.ErrCertificateVersionNotFound, parent.ID, version)
	}
	if s.versionRepo == nil {
		return model.CertificateVersion{}, "", "", ErrCertVersioningUnavailable
	}
	records, err := s.versionRepo.ListVersionRecords(ctx, parent.ID)
	if err != nil {
		return model.CertificateVersion{}, "", "", fmt.Errorf("read certificate versions: %w", err)
	}
	for _, rec := range records {
		if rec.Version == version {
			return rec.Metadata(), rec.Certificate, rec.PrivateKey, nil
		}
	}
	return model.CertificateVersion{}, "", "", fmt.Errorf("%w: certificate %s has no version %d", model.ErrCertificateVersionNotFound, parent.ID, version)
}

// parseLeaf decodes the first certificate in certPEM.
func parseLeaf(certPEM string) (*x509.Certificate, error) {
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		return nil, fmt.Errorf("decode stored certificate: no PEM block")
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse stored certificate: %w", err)
	}
	return leaf, nil
}

// exportChain walks CACertID from parent and returns the intermediates in
// order, stopping before the self-signed root. Every hop is a scoped read,
// so a CA outside the caller's vault is never read. A missing hop, a cycle
// or a walk past maxExportChainDepth fails with
// ErrCertificateChainUnavailable. Each hop uses the CA's current PEM.
func (s *certificateService) exportChain(ctx context.Context, parent *model.Certificate, leaf *x509.Certificate, scope model.Scope) ([]*x509.Certificate, error) {
	if self, err := isSelfSignedPEM(string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leaf.Raw}))); err == nil && self {
		return nil, nil
	}
	var chain []*x509.Certificate
	seen := map[uuid.UUID]bool{parent.ID: true}
	next := parent.CACertID
	for depth := 0; next != nil; depth++ {
		if depth >= maxExportChainDepth {
			return nil, fmt.Errorf("%w: deeper than %d", ErrCertificateChainUnavailable, maxExportChainDepth)
		}
		if seen[*next] {
			return nil, fmt.Errorf("%w: cycle at %s", ErrCertificateChainUnavailable, *next)
		}
		seen[*next] = true
		hop, err := s.certRepo.Read(ctx, *next, scope)
		if err != nil {
			return nil, fmt.Errorf("%w: issuer %s is not readable", ErrCertificateChainUnavailable, *next)
		}
		self, err := isSelfSignedPEM(hop.Certificate)
		if err != nil {
			return nil, fmt.Errorf("%w: issuer %s: %w", ErrCertificateChainUnavailable, *next, err)
		}
		if self {
			return chain, nil
		}
		cert, err := parseLeaf(hop.Certificate)
		if err != nil {
			return nil, fmt.Errorf("%w: issuer %s: %w", ErrCertificateChainUnavailable, *next, err)
		}
		chain = append(chain, cert)
		next = hop.CACertID
	}
	return chain, nil
}
```

`crypto.DetectPrivateKeyType` returns the same `"ES256K"` string as `model.KeyTypeES256K`.

- [ ] **Step 4: Pass-throughs in the wrappers**

Append to `internal/certcache/cache_integration.go`:

```go
// ExportCertificate passes straight through. An export is never served from
// or stored in the cache: the result carries a private key, and the export
// must reflect the committed row.
func (s *CachedCertificateService) ExportCertificate(ctx context.Context, scope model.Scope, id uuid.UUID, req certificates.ExportCertificateRequest) (*certificates.ExportCertificateResult, error) {
	return s.certificateService.ExportCertificate(ctx, scope, id, req)
}
```

Append to `internal/services/retry/retry_certificate_service.go`:

```go
// ExportCertificate is deliberately not retried. A failed export is reported
// once; replaying it would decrypt the key again and write a second audit
// trail for one request.
func (s *retryCertificateService) ExportCertificate(ctx context.Context, scope model.Scope, id uuid.UUID, req certificates.ExportCertificateRequest) (*certificates.ExportCertificateResult, error) {
	return s.baseService.ExportCertificate(ctx, scope, id, req)
}
```

- [ ] **Step 5: Add the method to every hand-written fake and regenerate the mock**

`internal/services/certificates/renewal_service_test.go`, after `mockCertSvcForRenewal`'s last method:

```go
func (m *mockCertSvcForRenewal) ExportCertificate(context.Context, model.Scope, uuid.UUID, certificates.ExportCertificateRequest) (*certificates.ExportCertificateResult, error) {
	panic("not called")
}
```

`internal/services/certificates/certificate_service_extended_test.go`, after `mockRenewalCertSvc`'s last method:

```go
func (m *mockRenewalCertSvc) ExportCertificate(context.Context, model.Scope, uuid.UUID, ExportCertificateRequest) (*ExportCertificateResult, error) {
	panic("not called")
}
```

`api/certificates_test.go`, after `mockCertService.ListCertificatesDueForRenewal`:

```go
func (m *mockCertService) ExportCertificate(ctx context.Context, scope model.Scope, id uuid.UUID, req certServices.ExportCertificateRequest) (*certServices.ExportCertificateResult, error) {
	args := m.Called(ctx, scope, id, req)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*certServices.ExportCertificateResult), args.Error(1)
}
```

`cmd/certificates/certs_cmd_test.go`, the same body on `certCmdCertService` (receiver `m *certCmdCertService`).

`api/vault_scoped_keys_certs_test.go`, after `recordingCertService.ListCertificatesDueForRenewal`:

```go
func (s *recordingCertService) ExportCertificate(_ context.Context, scope model.Scope, id uuid.UUID, req certServices.ExportCertificateRequest) (*certServices.ExportCertificateResult, error) {
	s.versionCalls = append(s.versionCalls, "export")
	s.versionScope = scope
	if s.getInVaultErr != nil {
		return nil, s.getInVaultErr
	}
	return &certServices.ExportCertificateResult{ID: id, Name: "c", Version: 1, Format: req.Format,
		CertificatePEM: "chain", PrivateKeyPEM: "key", KeyAlgorithm: "RSA-2048"}, nil
}
```

Regenerate the mock from the repo root:

Run: `PATH="$HOME/go/pkg/mod/golang.org/toolchain@v0.0.1-go1.25.7.linux-amd64/bin:$PATH" GOTOOLCHAIN=local ~/go/bin/mockery && git status --short -- '*/mocks/*'`
Expected: only `internal/services/certificates/mocks/mock_CertificateService.go` is modified. Revert any other regenerated mock with `git checkout -- <path>`.

- [ ] **Step 6: Run and expect PASS**

Run: `go build ./... && go test -p 2 ./internal/services/certificates ./internal/certcache ./internal/services/retry ./api ./cmd/certificates -count=1`
Expected: PASS.

- [ ] **Step 7: Commit**

Commit via the `dev-workflow-skills:1-git-commit` skill. Stage: `internal/services/certificates/certificate_export.go`, `internal/services/certificates/certificate_export_test.go`, `internal/services/certificates/certificate_service.go`, `internal/services/certificates/mocks/mock_CertificateService.go`, `internal/services/certificates/renewal_service_test.go`, `internal/services/certificates/certificate_service_extended_test.go`, `internal/certcache/cache_integration.go`, `internal/services/retry/retry_certificate_service.go`, `api/certificates_test.go`, `api/vault_scoped_keys_certs_test.go`, `cmd/certificates/certs_cmd_test.go`.

---

### Task 3: Wrapper behavior pins: no cache, no retry

**Files:**
- Test: `internal/certcache/cache_export_test.go` (create), `internal/services/retry/retry_export_test.go` (create)

**Interfaces:**
- Consumes: Task 2; `mocks.NewMockCertificateService`, `NewCachedCertificateService`, `NewCache`, `NewRetryCertificateService`, `RetryService` interface (`internal/services/retry/retry_service.go`).
- Produces: `failingRetryService` (test helper in package `retry`), reused by plan 3's key test.

- [ ] **Step 1: Write the tests**

Create `internal/certcache/cache_export_test.go`:

```go
package certcache

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"rocketvault/internal/cachekit"
	"rocketvault/internal/services/certificates"
	"rocketvault/internal/services/certificates/mocks"
	"rocketvault/model"
)

func TestCachedExportCertificate_NeverCaches(t *testing.T) {
	ctx := context.Background()
	c := NewCache(cachekit.Config{Enabled: true, TTL: time.Minute, CleanupInterval: time.Minute, MaxEntries: 10}, logrus.New())
	t.Cleanup(c.Stop)
	vaultID := uuid.New()
	scope := model.NewVaultScope(vaultID, uuid.New())
	certID := uuid.New()
	password := "never-cache-this-password"
	keyText := "-----BEGIN PRIVATE KEY-----\nMIIEexported\n-----END PRIVATE KEY-----\n"

	// A cached metadata row already exists; export must neither read nor
	// replace it.
	require.NoError(t, c.Set(ctx, &model.Certificate{ID: certID, VaultID: vaultID, Name: "c", Enabled: true}, scope))

	inner := mocks.NewMockCertificateService(t)
	req := certificates.ExportCertificateRequest{Format: model.ExportFormatPKCS12, Password: &password}
	inner.On("ExportCertificate", mock.Anything, scope, certID, req).
		Return(&certificates.ExportCertificateResult{ID: certID, PrivateKeyPEM: keyText, PKCS12: []byte("pfx")}, nil).Twice()
	svc := NewCachedCertificateService(inner, c, logrus.New())

	for i := 0; i < 2; i++ {
		_, err := svc.ExportCertificate(ctx, scope, certID, req)
		require.NoError(t, err)
	}
	inner.AssertNumberOfCalls(t, "ExportCertificate", 2) // Both exports reached the service.

	var dump strings.Builder
	c.core.Range(func(key string, v *model.Certificate) bool {
		dump.WriteString(key)
		dump.WriteString(v.Name + v.Certificate + v.PrivateKey)
		return true
	})
	assert.NotContains(t, dump.String(), password)
	assert.NotContains(t, dump.String(), "BEGIN PRIVATE KEY")
	assert.NotContains(t, dump.String(), "MIIEexported")
}
```

Create `internal/services/retry/retry_export_test.go`:

```go
package retry

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	internalRetry "rocketvault/internal/retry"
	"rocketvault/internal/services/certificates"
	"rocketvault/internal/services/certificates/mocks"
	"rocketvault/model"
)

// failingRetryService retries every operation three times, the way a real
// policy does on a retryable error. A method routed through it would run
// three times on failure; a pass-through method runs once.
type failingRetryService struct{}

func (failingRetryService) run(op func() error) error {
	var err error
	for i := 0; i < 3; i++ {
		if err = op(); err == nil {
			return nil
		}
	}
	return err
}
func (f failingRetryService) ExecuteDatabaseOperation(_ context.Context, op func() error) error {
	return f.run(op)
}
func (f failingRetryService) ExecuteExternalServiceOperation(_ context.Context, op func() error) error {
	return f.run(op)
}
func (f failingRetryService) ExecuteServiceOperation(_ context.Context, op func() error) error {
	return f.run(op)
}
func (f failingRetryService) ExecuteInteractiveOperation(_ context.Context, op func() error) error {
	return f.run(op)
}
func (failingRetryService) GetDatabasePolicy() internalRetry.Policy          { return internalRetry.Policy{} }
func (failingRetryService) GetExternalServicesPolicy() internalRetry.Policy  { return internalRetry.Policy{} }
func (failingRetryService) GetServiceOperationsPolicy() internalRetry.Policy { return internalRetry.Policy{} }
func (failingRetryService) GetInteractivePolicy() internalRetry.Policy       { return internalRetry.Policy{} }

func TestRetryExportCertificate_IsNotRetried(t *testing.T) {
	inner := mocks.NewMockCertificateService(t)
	scope := model.NewVaultScope(uuid.New(), uuid.New())
	id := uuid.New()
	req := certificates.ExportCertificateRequest{Format: model.ExportFormatPEM}
	inner.On("ExportCertificate", mock.Anything, scope, id, req).Return(nil, errors.New("database is locked")).Once()

	svc := NewRetryCertificateService(inner, failingRetryService{})
	_, err := svc.ExportCertificate(context.Background(), scope, id, req)
	require.Error(t, err)
	inner.AssertNumberOfCalls(t, "ExportCertificate", 1)
}
```

If `RetryService` has a method set different from the eight above (check `internal/services/retry/retry_service.go` and `noopRetryService` in `retry_wrappers_test.go:27-54`), make `failingRetryService` match `noopRetryService`'s method list exactly.

- [ ] **Step 2: Run and expect PASS**

Run: `go test -p 2 ./internal/certcache ./internal/services/retry -run 'Export' -v`
Expected: PASS (Task 2 wrote the behavior; these pin it). Temporarily routing the retry wrapper's `ExportCertificate` through `retried(...)` must make `TestRetryExportCertificate_IsNotRetried` fail with 3 calls; revert after checking.

- [ ] **Step 3: Commit**

Commit via the `dev-workflow-skills:1-git-commit` skill. Stage: `internal/certcache/cache_export_test.go`, `internal/services/retry/retry_export_test.go`.

---

### Task 4: The export route on both shapes, R6 errors, headers, audit, OpenAPI and route inventory

**Files:**
- Create: `api/export.go`
- Modify: `api/certificates.go:104-123` (`registerCertificateRoutes`, after the `renew` route)
- Modify: `docs/api-specification.yaml` (paths after `/api/v1/certificates/{certificate_id}/renew` at `:3796` and after `/api/v1/vaults/{vault_name}/certificates/{certificate_id}/renew` at `:4167`; schemas at the end of `components.schemas`), `docs/api-routes.generated.txt` (regenerated)
- Test: `api/export_test.go` (create)

**Interfaces:**
- Consumes: Task 2; `scopeFromRequest` is not used (it sets `c.Err`); `userIDFromClaims` is not used for the same reason; `vaultIDFromRequest`, `svc`, `container.ServiceContainerInterface`, `middleware.ExtractClientIP`, `auditSvc.AuditEvent`, `keyservices.ErrKeyNotFound`, `keyservices.ErrKeyLifecycleDenied`, `newCertCtx`, `certAdminClaims`, `certTestUserID`, `mockCertService`, `certSvcContainer`, `newVaultScopedKeyCertTestAPI`, `doVaultRequest`, `recordingCertService`.
- Produces (plan 3 consumes all of these from `api/export.go` and `api/export_test.go`):
  - `func setExportHeaders(w http.ResponseWriter)`
  - `type exportErrorBody struct { Error exportErrorDetail \`json:"error"\` }`, `type exportErrorDetail struct { Code, Message, KeyAlgorithm string }` (`json:"code"`, `json:"message"`, `json:"key_algorithm,omitempty"`)
  - `func writeExportError(w http.ResponseWriter, f exportFailure)`
  - `type exportFailure struct { Status int; Code, Message, KeyAlgorithm, Name string }`
  - `func exportFailureFor(err error, resource string) exportFailure` (`resource` is `"certificate"` or `"key"`)
  - `func badExportRequest(message string) exportFailure`
  - `func decodeExportBody(r *http.Request, dst any, allowEmpty bool) error`
  - `type exportAudit struct { ResourceType string; ResourceID string; VaultID string; Name string; Version int; Format string; Outcome string; Code string }`
  - `func recordExportAudit(c *Context, r *http.Request, a exportAudit)`
  - `func exportCaller(c *Context, r *http.Request) (model.Scope, string, bool)`
  - Test helpers in `api/export_test.go`: `type captureAudit`, `type exportTestContainer`, `func newExportCtx(certSvc certServices.CertificateService, keySvc keyservices.KeyService, audit *captureAudit) *Context`, `func decodeExportError(t *testing.T, body []byte) exportErrorDetail`
  - Routes `POST /api/v1/certificates/{certificate_id}/export` and `POST /api/v1/vaults/{vault_name}/certificates/{certificate_id}/export`.

- [ ] **Step 1: Write the failing handler tests**

Create `api/export_test.go`:

```go
package api

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"rocketvault/app"
	auditServices "rocketvault/internal/services/audit"
	certServices "rocketvault/internal/services/certificates"
	keyservices "rocketvault/internal/services/keys"
	"rocketvault/model"
)

// captureAudit records every audit write so tests can assert on content.
type captureAudit struct {
	mu        sync.Mutex
	events    []auditServices.AuditEvent
	persisted []string
}

func (a *captureAudit) RecordEvent(_ context.Context, e auditServices.AuditEvent) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.events = append(a.events, e)
	return nil
}

func (a *captureAudit) PersistAudit(userID, action, details string) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.persisted = append(a.persisted, userID+" "+action+" "+details)
	return nil
}

func (a *captureAudit) dump() string {
	a.mu.Lock()
	defer a.mu.Unlock()
	b, _ := json.Marshal(a.events)
	return string(b) + strings.Join(a.persisted, "\n")
}

// exportTestContainer serves the certificate and key services and an
// audit capture; everything else comes from certSvcContainer.
type exportTestContainer struct {
	*certSvcContainer
	keySvc keyservices.KeyService
	audit  *captureAudit
}

func (c *exportTestContainer) GetKeyService() keyservices.KeyService { return c.keySvc }
func (c *exportTestContainer) GetAuditService() auditServices.AuditServiceInterface {
	return c.audit
}

func newExportCtx(certSvc certServices.CertificateService, keySvc keyservices.KeyService, audit *captureAudit) *Context {
	a := &app.App{ServiceContainer: &exportTestContainer{certSvcContainer: &certSvcContainer{certSvc: certSvc}, keySvc: keySvc, audit: audit}}
	return &Context{App: a, Claims: certAdminClaims(), Params: &ApiParams{PerPage: 60}}
}

func decodeExportError(t *testing.T, body []byte) exportErrorDetail {
	t.Helper()
	var parsed exportErrorBody
	require.NoError(t, json.Unmarshal(body, &parsed), string(body))
	require.NotEmpty(t, parsed.Error.Code, string(body))
	return parsed.Error
}

func runCertExport(t *testing.T, svc certServices.CertificateService, audit *captureAudit, certID, body string) *httptest.ResponseRecorder {
	t.Helper()
	c := newExportCtx(svc, nil, audit)
	c.Params.CertificateID = certID
	w := httptest.NewRecorder()
	exportCertificate(c, w, httptest.NewRequest(http.MethodPost, "/certificates/"+certID+"/export", bytes.NewBufferString(body)))
	require.Nil(t, c.Err, "export handlers never set c.Err; they write the R6 body themselves")
	return w
}

func TestExportCertificateHandler_PEMSuccess(t *testing.T) {
	certID := uuid.New()
	svc := &mockCertService{}
	svc.On("ExportCertificate", mock.Anything, certLegacyVaultScope(), certID, certServices.ExportCertificateRequest{Format: "pem"}).
		Return(&certServices.ExportCertificateResult{ID: certID, Name: "client", Version: 2, Format: "pem",
			CertificatePEM: "CHAIN", PrivateKeyPEM: "-----BEGIN PRIVATE KEY-----\nK\n-----END PRIVATE KEY-----\n", KeyAlgorithm: "EC-P256"}, nil)
	audit := &captureAudit{}

	w := runCertExport(t, svc, audit, certID.String(), `{"format":"pem"}`)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	assert.Equal(t, "no-store", w.Header().Get("Cache-Control"))
	assert.Equal(t, "no-cache", w.Header().Get("Pragma"))
	assert.Empty(t, w.Header().Get("Content-Disposition"))
	assert.Less(t, w.Body.Len(), 64<<10)

	var body map[string]any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
	assert.Equal(t, "pem", body["format"])
	assert.Equal(t, "CHAIN", body["certificate_pem"])
	assert.Equal(t, "EC-P256", body["key_algorithm"])
	assert.EqualValues(t, 2, body["version"])
	assert.NotContains(t, body, "pkcs12_base64")

	require.Len(t, audit.events, 1)
	ev := audit.events[0]
	assert.Equal(t, "export_certificate", ev.Action)
	assert.Equal(t, "success", ev.Outcome)
	assert.Equal(t, "certificate", ev.ResourceType)
	assert.Equal(t, certID.String(), ev.ResourceID)
	assert.Equal(t, certTestUserID, ev.UserID)
	assert.Contains(t, ev.Details, `"format":"pem"`)
	assert.Contains(t, ev.Details, `"name":"client"`)
	assert.Contains(t, ev.Details, `"version":2`)
	assert.Contains(t, ev.Details, model.DefaultVaultID)
	assert.NotContains(t, audit.dump(), "PRIVATE KEY")
}

func TestExportCertificateHandler_PKCS12Success(t *testing.T) {
	certID := uuid.New()
	password := "hunter2-export"
	svc := &mockCertService{}
	svc.On("ExportCertificate", mock.Anything, certLegacyVaultScope(), certID,
		certServices.ExportCertificateRequest{Format: "pkcs12", Password: &password, Compat: "legacy"}).
		Return(&certServices.ExportCertificateResult{ID: certID, Name: "client", Version: 1, Format: "pkcs12", PKCS12: []byte{1, 2, 3}, KeyAlgorithm: "RSA-2048"}, nil)
	audit := &captureAudit{}

	w := runCertExport(t, svc, audit, certID.String(), `{"format":"pkcs12","password":"hunter2-export","compat":"legacy"}`)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	var body map[string]any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
	assert.Equal(t, base64.StdEncoding.EncodeToString([]byte{1, 2, 3}), body["pkcs12_base64"])
	assert.NotContains(t, body, "private_key_pem")
	assert.NotContains(t, audit.dump(), password)
}

// TestExportCertificateHandler_ErrorBodiesAreR6AndGeneric pins Review Focus
// 1: every failure uses the R6 body, and an internal failure exposes no
// detail.
func TestExportCertificateHandler_ErrorBodiesAreR6AndGeneric(t *testing.T) {
	certID := uuid.New()
	cases := []struct {
		name, body string
		err        error
		status     int
		code       string
	}{
		{"bad json", `{"format":`, nil, http.StatusBadRequest, "bad_request"},
		{"empty body", ``, nil, http.StatusBadRequest, "bad_request"},
		{"invalid request", `{"format":"der"}`, fmt.Errorf("%w: format must be pem or pkcs12", model.ErrInvalidExportRequest), http.StatusBadRequest, "bad_request"},
		{"not found", `{"format":"pem"}`, fmt.Errorf("%w: x", certServices.ErrCertNotFound), http.StatusNotFound, "not_found"},
		{"no version", `{"format":"pem","version":9}`, fmt.Errorf("%w: x", model.ErrCertificateVersionNotFound), http.StatusNotFound, "not_found"},
		{"disabled", `{"format":"pem"}`, certServices.ErrCertLifecycleDenied, http.StatusConflict, "certificate_disabled"},
		{"refused", `{"format":"pem"}`, &model.ExportRefusedError{Sentinel: model.ErrCertificateNotExportable, Reason: "flag is false", KeyAlgorithm: "RSA-2048"}, http.StatusForbidden, "certificate_not_exportable"},
		{"internal", `{"format":"pem"}`, errors.New("sql: database driver detail secret-ish"), http.StatusInternalServerError, "internal_error"},
		{"chain", `{"format":"pem"}`, fmt.Errorf("%w: cycle", certServices.ErrCertificateChainUnavailable), http.StatusInternalServerError, "internal_error"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			svc := &mockCertService{}
			if tc.err != nil {
				svc.On("ExportCertificate", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(nil, tc.err)
			}
			audit := &captureAudit{}
			w := runCertExport(t, svc, audit, certID.String(), tc.body)
			require.Equal(t, tc.status, w.Code, w.Body.String())
			assert.Equal(t, "no-store", w.Header().Get("Cache-Control"))
			detail := decodeExportError(t, w.Body.Bytes())
			assert.Equal(t, tc.code, detail.Code)
			assert.NotContains(t, w.Body.String(), "detailed_error")
			assert.NotContains(t, w.Body.String(), "driver detail")
			if tc.code == "certificate_not_exportable" {
				assert.Equal(t, "RSA-2048", detail.KeyAlgorithm)
				assert.Contains(t, detail.Message, "flag is false")
			}
			require.Len(t, audit.events, 1, "every attempt is audited")
			assert.Equal(t, "failure", audit.events[0].Outcome)
			assert.Equal(t, certID.String(), audit.events[0].ResourceID)
		})
	}
}

func TestExportCertificateHandler_BadIDIs400(t *testing.T) {
	audit := &captureAudit{}
	w := runCertExport(t, &mockCertService{}, audit, "not-a-uuid", `{"format":"pem"}`)
	require.Equal(t, http.StatusBadRequest, w.Code)
	assert.Equal(t, "bad_request", decodeExportError(t, w.Body.Bytes()).Code)
	require.Len(t, audit.events, 1)
}

func TestExportCertificateRoutes_BothShapes(t *testing.T) {
	certID := uuid.New().String()
	t.Run("flat", func(t *testing.T) {
		rec := &recordingCertService{}
		api, _ := newVaultScopedKeyCertTestAPI(nil, rec, nil)
		w := doVaultRequest(api, http.MethodPost, "/api/v1/certificates/"+certID+"/export", []byte(`{"format":"pem"}`))
		require.Equal(t, http.StatusOK, w.Code, w.Body.String())
		assert.Equal(t, uuid.MustParse(model.DefaultVaultID), rec.versionScope.VaultID())
		assert.Equal(t, "no-store", w.Header().Get("Cache-Control"))
	})
	t.Run("vault-scoped", func(t *testing.T) {
		rec := &recordingCertService{}
		api, repo := newVaultScopedKeyCertTestAPI(nil, rec, nil)
		id := uuid.New()
		repo.byName["prod"] = &model.Vault{ID: id, Name: "prod", Enabled: true}
		repo.byID[id.String()] = repo.byName["prod"]
		w := doVaultRequest(api, http.MethodPost, "/api/v1/vaults/prod/certificates/"+certID+"/export", []byte(`{"format":"pem"}`))
		require.Equal(t, http.StatusOK, w.Code, w.Body.String())
		assert.Equal(t, id, rec.versionScope.VaultID())
	})
}
```

`vaultSvcTestContainer.GetAuditService` returns nil; `recordExportAudit` must tolerate a nil audit service (the both-shapes test relies on it).

- [ ] **Step 2: Run and expect FAIL**

Run: `go test -p 2 ./api -run 'ExportCertificate' -v`
Expected: FAIL (build error: `exportCertificate`, `exportErrorBody`, `exportErrorDetail` undefined).

- [ ] **Step 3: Implement `api/export.go`**

```go
package api

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/google/uuid"

	"rocketvault/internal/container"
	"rocketvault/internal/middleware"
	auditSvc "rocketvault/internal/services/audit"
	certServices "rocketvault/internal/services/certificates"
	keyservices "rocketvault/internal/services/keys"
	"rocketvault/model"
)

// maxExportRequestBytes bounds an export request body. The body is a few
// short fields, so anything larger is malformed.
const maxExportRequestBytes = 16 << 10

// exportErrorBody is the R6 error shape used only by the export routes. The
// rest of the API keeps its flat body.
type exportErrorBody struct {
	Error exportErrorDetail `json:"error"`
}

// exportErrorDetail is the inner R6 object. KeyAlgorithm is set only on a
// not-exportable refusal, so a client can show why.
type exportErrorDetail struct {
	Code         string `json:"code"`
	Message      string `json:"message"`
	KeyAlgorithm string `json:"key_algorithm,omitempty"`
}

// exportFailure is one mapped export failure: the HTTP status, the R6 code
// and message, and what the audit event should record.
type exportFailure struct {
	Status       int
	Code         string
	Message      string
	KeyAlgorithm string
	Name         string
}

// setExportHeaders forbids every cache between the vault and the client.
// It must run before the first write.
func setExportHeaders(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
}

// writeExportError writes f as an R6 body.
func writeExportError(w http.ResponseWriter, f exportFailure) {
	writeJSONStatus(w, f.Status, exportErrorBody{Error: exportErrorDetail{Code: f.Code, Message: f.Message, KeyAlgorithm: f.KeyAlgorithm}})
}

// badExportRequest is the 400 for a malformed request. message must be a
// fixed phrase that never includes the password.
func badExportRequest(message string) exportFailure {
	return exportFailure{Status: http.StatusBadRequest, Code: "bad_request", Message: message}
}

// exportFailureFor maps a certificate or key service error onto an export
// failure. resource is "certificate" or "key". Unknown errors become a
// generic 500 whose message carries no detail.
func exportFailureFor(err error, resource string) exportFailure {
	var refusal *model.ExportRefusedError
	switch {
	case errors.As(err, &refusal):
		return exportFailure{Status: http.StatusForbidden, Code: resource + "_not_exportable",
			Message: refusal.Error(), KeyAlgorithm: refusal.KeyAlgorithm, Name: refusal.Name}
	case errors.Is(err, model.ErrInvalidExportRequest):
		return badExportRequest(err.Error())
	case errors.Is(err, certServices.ErrCertNotFound), errors.Is(err, model.ErrCertificateVersionNotFound):
		return exportFailure{Status: http.StatusNotFound, Code: "not_found", Message: "certificate or version not found"}
	case errors.Is(err, keyservices.ErrKeyNotFound), errors.Is(err, model.ErrKeyVersionNotFound):
		return exportFailure{Status: http.StatusNotFound, Code: "not_found", Message: "key or version not found"}
	case errors.Is(err, certServices.ErrCertLifecycleDenied):
		return exportFailure{Status: http.StatusConflict, Code: "certificate_disabled",
			Message: "the certificate or this version is disabled or outside its valid time window"}
	case errors.Is(err, keyservices.ErrKeyLifecycleDenied):
		return exportFailure{Status: http.StatusConflict, Code: "key_disabled",
			Message: "the key is disabled or outside its valid time window"}
	}
	return exportFailure{Status: http.StatusInternalServerError, Code: "internal_error", Message: "internal server error"}
}

// decodeExportBody decodes a bounded JSON body into dst. An empty body is an
// error unless allowEmpty, in which case dst keeps its zero value.
func decodeExportBody(r *http.Request, dst any, allowEmpty bool) error {
	if r.Body == nil {
		if allowEmpty {
			return nil
		}
		return errors.New("a JSON request body is required")
	}
	err := json.NewDecoder(io.LimitReader(r.Body, maxExportRequestBytes)).Decode(dst)
	if errors.Is(err, io.EOF) && allowEmpty {
		return nil
	}
	if err != nil {
		return errors.New("the request body must be a JSON object")
	}
	return nil
}

// exportCaller builds the vault scope without touching c.Err, because an
// export failure must be written as R6. It returns the vault id as a string
// for the audit event.
func exportCaller(c *Context, r *http.Request) (model.Scope, string, bool) {
	userID, err := uuid.Parse(c.Claims.UserID)
	if err != nil {
		return model.Scope{}, "", false
	}
	vaultID, err := vaultIDFromRequest(r)
	if err != nil {
		return model.Scope{}, "", false
	}
	return model.NewVaultScope(vaultID, userID), vaultID.String(), true
}

// exportAudit is one export attempt as the audit trail records it. It holds
// no material and no password by construction.
type exportAudit struct {
	ResourceType string
	ResourceID   string
	VaultID      string
	Name         string
	Version      int
	Format       string
	Outcome      string
	Code         string
}

// recordExportAudit writes one structured audit event per export attempt. A
// nil audit service is tolerated: audit failures never block the request.
func recordExportAudit(c *Context, r *http.Request, a exportAudit) {
	if c.App == nil || c.App.ServiceContainer == nil {
		return
	}
	svc := c.App.ServiceContainer.GetAuditService()
	if svc == nil {
		return
	}
	details, _ := json.Marshal(map[string]any{
		"vault_id": a.VaultID, "name": a.Name, "version": a.Version, "format": a.Format, "code": a.Code,
	})
	_ = svc.RecordEvent(r.Context(), auditSvc.AuditEvent{
		UserID:       c.Claims.UserID,
		Action:       "export_" + a.ResourceType,
		Details:      string(details),
		ResourceType: a.ResourceType,
		ResourceID:   a.ResourceID,
		IPAddress:    middleware.ExtractClientIP(r),
		Outcome:      a.Outcome,
		Source:       "api",
	})
}

// ExportCertificateAPIRequest is the body of POST .../certificates/{id}/export.
type ExportCertificateAPIRequest struct {
	Format   string  `json:"format"`             // pem or pkcs12.
	Password *string `json:"password,omitempty"` // Required for pkcs12; may be empty.
	Compat   string  `json:"compat,omitempty"`   // modern (default) or legacy.
	Version  int     `json:"version,omitempty"`  // 0 or omitted means the current version.
}

// ExportCertificateResponse is the export success body. Exactly one of the
// pem pair and pkcs12_base64 is set, matching format.
type ExportCertificateResponse struct {
	ID             uuid.UUID  `json:"id"`
	Name           string     `json:"name"`
	Version        int        `json:"version"`
	Format         string     `json:"format"`
	CertificatePEM string     `json:"certificate_pem,omitempty"`
	PrivateKeyPEM  string     `json:"private_key_pem,omitempty"`
	PKCS12Base64   string     `json:"pkcs12_base64,omitempty"`
	NotBefore      *time.Time `json:"not_before"`
	ExpiresAt      *time.Time `json:"expires_at"`
	KeyAlgorithm   string     `json:"key_algorithm"`
}

// exportCertificate handles POST .../certificates/{certificate_id}/export.
// PolicyMiddleware has already required ActionCertificatesExportItem in the
// resolved vault. It never sets c.Err: every outcome is written here, as R6
// on failure, and audited once.
func exportCertificate(c *Context, w http.ResponseWriter, r *http.Request) {
	setExportHeaders(w)
	audit := exportAudit{ResourceType: "certificate", ResourceID: c.Params.CertificateID, Outcome: "failure"}
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
	certID, err := uuid.Parse(c.Params.CertificateID)
	if err != nil {
		fail(badExportRequest("certificate_id must be a UUID"))
		return
	}
	var req ExportCertificateAPIRequest
	if err := decodeExportBody(r, &req, false); err != nil {
		fail(badExportRequest(err.Error()))
		return
	}
	audit.Format, audit.Version = req.Format, req.Version

	certService, svcOK := svc(c, container.ServiceContainerInterface.GetCertificateService)
	if !svcOK {
		c.Err = nil
		fail(exportFailure{Status: http.StatusInternalServerError, Code: "internal_error", Message: "internal server error"})
		return
	}

	result, err := certService.ExportCertificate(r.Context(), scope, certID, certServices.ExportCertificateRequest{
		Format: req.Format, Password: req.Password, Compat: req.Compat, Version: req.Version,
	})
	if err != nil {
		if c.Logger != nil {
			c.Logger.LogAuditError(c.Claims.UserID, "export_certificate", "failed", fmt.Sprintf("Certificate %s export failed", certID), nil)
		}
		fail(exportFailureFor(err, "certificate"))
		return
	}

	audit.Outcome, audit.Name, audit.Version, audit.Code = "success", result.Name, result.Version, ""
	recordExportAudit(c, r, audit)

	resp := ExportCertificateResponse{
		ID: result.ID, Name: result.Name, Version: result.Version, Format: result.Format,
		NotBefore: result.NotBefore, ExpiresAt: result.ExpiresAt, KeyAlgorithm: result.KeyAlgorithm,
	}
	if result.Format == model.ExportFormatPKCS12 {
		resp.PKCS12Base64 = base64.StdEncoding.EncodeToString(result.PKCS12)
	} else {
		resp.CertificatePEM, resp.PrivateKeyPEM = result.CertificatePEM, result.PrivateKeyPEM
	}
	writeJSON(w, resp)
}
```

The handler logs the failure with a nil error on purpose: the service error may wrap a decrypted-key parse error, so its text is never logged here.

- [ ] **Step 4: Register the route on both shapes**

In `registerCertificateRoutes`, after the `renew` route, add:

```go
	// Per-certificate export. Requires ActionCertificatesExportItem and an
	// exportable certificate; see api/export.go.
	c.Handle("/{certificate_id:[A-Fa-f0-9-]+}/export", ApiSessionRequired(api.App, exportCertificate)).Methods("POST")
```

- [ ] **Step 5: Document both route shapes in OpenAPI and regenerate the inventory**

In `docs/api-specification.yaml`, add after the `/api/v1/certificates/{certificate_id}/renew` path item:

```yaml
  /api/v1/certificates/{certificate_id}/export:
    parameters:
      - $ref: "#/components/parameters/CertificateId"
    post:
      summary: Export a certificate with its private key
      description: |
        Returns one exportable certificate version as a leaf-first chain
        (intermediates follow, the root is excluded) plus an unencrypted
        PKCS#8 private key (`format: pem`), or as a PKCS12 bundle
        (`format: pkcs12`, `password` required, may be empty; `compat:
        legacy` selects PBE-SHA1-3DES with a SHA-1 MAC). Requires the
        `Microsoft.KeyVault/vaults/certificates/export/action` data action
        (Key Vault Certificate Exporter or Administrator) and a certificate
        created with `exportable: true`. Every response carries
        `Cache-Control: no-store` and `Pragma: no-cache`. Errors use the
        `ExportError` body; the 401 and the missing-role 403 come from the
        session and policy middleware and keep their usual bodies. Export
        reflects the certificate's own key copy: after a key rotation it
        changes only once the certificate is renewed.
      operationId: exportCertificate
      tags:
        - Certificates
      requestBody:
        required: true
        content:
          application/json:
            schema:
              $ref: "#/components/schemas/ExportCertificateRequest"
      responses:
        "200":
          description: The exported certificate
          content:
            application/json:
              schema:
                $ref: "#/components/schemas/ExportCertificateResponse"
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

Add the same item under `/api/v1/vaults/{vault_name}/certificates/{certificate_id}/export` after the vault-scoped `renew` item, with `parameters` listing `- $ref: "#/components/parameters/VaultName"` before `CertificateId` (copy the exact parameter refs the vault-scoped `renew` item uses) and `operationId: exportCertificateInVault`.

Under `components.responses` add:

```yaml
    ExportBadRequest:
      description: Bad body, unknown format or compat, pkcs12 without password, or bad version
      content:
        application/json:
          schema:
            $ref: "#/components/schemas/ExportError"
    ExportForbidden:
      description: |
        `certificate_not_exportable` or `key_not_exportable` (ExportError
        body), or a missing role (plain-text body from the policy middleware)
      content:
        application/json:
          schema:
            $ref: "#/components/schemas/ExportError"
    ExportNotFound:
      description: Unknown, soft-deleted, out of vault, or unknown version
      content:
        application/json:
          schema:
            $ref: "#/components/schemas/ExportError"
    ExportConflict:
      description: Disabled, expired or outside its window (`certificate_disabled` or `key_disabled`)
      content:
        application/json:
          schema:
            $ref: "#/components/schemas/ExportError"
    ExportInternalError:
      description: Internal failure; the message is generic
      content:
        application/json:
          schema:
            $ref: "#/components/schemas/ExportError"
```

Under `components.schemas` add:

```yaml
    ExportError:
      type: object
      required: [error]
      properties:
        error:
          type: object
          required: [code, message]
          properties:
            code:
              type: string
              enum: [bad_request, forbidden, certificate_not_exportable, key_not_exportable, not_found, certificate_disabled, key_disabled, internal_error]
            message:
              type: string
            key_algorithm:
              type: string
              description: Set on a not-exportable refusal.
    ExportCertificateRequest:
      type: object
      required: [format]
      properties:
        format:
          type: string
          enum: [pem, pkcs12]
        password:
          type: string
          description: Required for pkcs12; an empty string is allowed. Never logged.
        compat:
          type: string
          enum: [modern, legacy]
          default: modern
        version:
          type: integer
          minimum: 0
          description: 0 or omitted exports the current version.
    ExportCertificateResponse:
      type: object
      required: [id, name, version, format, key_algorithm]
      properties:
        id:
          type: string
          format: uuid
        name:
          type: string
        version:
          type: integer
        format:
          type: string
          enum: [pem, pkcs12]
        certificate_pem:
          type: string
          description: pem only. Leaf first, then intermediates; no root.
        private_key_pem:
          type: string
          description: pem only. Unencrypted PKCS#8, starting with -----BEGIN PRIVATE KEY-----.
        pkcs12_base64:
          type: string
          description: pkcs12 only. Standard base64.
        not_before:
          type: string
          format: date-time
        expires_at:
          type: string
          format: date-time
        key_algorithm:
          type: string
          example: "EC-P256"
```

Regenerate the inventory:

Run: `go test ./api -run TestGenerateRouteInventory -update-route-inventory && git diff --stat docs/api-routes.generated.txt`
Expected: exactly two added lines, the flat and vault-scoped `POST .../certificates/{certificate_id...}/export`.

- [ ] **Step 6: Run and expect PASS**

Run: `go test -p 2 ./api ./internal/services/authorization -count=1`
Expected: PASS, including `TestOpenAPISpecCoversAllRoutes`, `TestGenerateRouteInventory`, `TestAuthorizationMatrixOpsAreRealRoutes` (the new route maps to `ActionCertificatesExportItem`) and every pre-existing handler test.

- [ ] **Step 7: Commit**

Commit via the `dev-workflow-skills:1-git-commit` skill. Stage: `api/export.go`, `api/export_test.go`, `api/certificates.go`, `docs/api-specification.yaml`, `docs/api-routes.generated.txt`.

---

### Task 5: No secrets in logs or audit through the real middleware chain, and the missing-role audit

**Files:**
- Test: `api/export_chain_test.go` (create)

**Interfaces:**
- Consumes: Task 4; `testutils.NewTestContext` (`cmd/testutils/test_utils.go:56`), `testutils.MockServiceContainer`, `authServices.JWTClaims`, `Init`, `WithAPP`, `WithRouter`, `WithBasePath`, `WithLogger`, `WithMetricsEnabled`, `captureAudit`, `mockCertService`.
- Produces: `func newExportChain(t *testing.T, certSvc certServices.CertificateService, keySvc keyservices.KeyService, deny model.DataAction) (*mux.Router, *captureAudit, *bytes.Buffer)` (plan 3 reuses it for keys).

- [ ] **Step 1: Write the tests**

Create `api/export_chain_test.go`:

```go
package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"rocketvault/app"
	"rocketvault/cmd/testutils"
	auditServices "rocketvault/internal/services/audit"
	authServices "rocketvault/internal/services/auth"
	certServices "rocketvault/internal/services/certificates"
	keyservices "rocketvault/internal/services/keys"
	"rocketvault/model"
)

// exportChainContainer is the cmd/testutils mock container with real
// certificate, key and audit services swapped in. Everything else keeps the
// stubs NewTestContext registers.
type exportChainContainer struct {
	*testutils.MockServiceContainer
	certSvc certServices.CertificateService
	keySvc  keyservices.KeyService
	audit   *captureAudit
}

func (c *exportChainContainer) GetCertificateService() certServices.CertificateService { return c.certSvc }
func (c *exportChainContainer) GetKeyService() keyservices.KeyService               { return c.keySvc }
func (c *exportChainContainer) GetAuditService() auditServices.AuditServiceInterface {
	return c.audit
}

// newExportChain serves the real router with the full production middleware
// chain. Every log line, from the app logger and the global logrus logger,
// lands in the returned buffer; every audit write lands in the capture.
// deny, when set, makes the role-assignment check refuse that action.
func newExportChain(t *testing.T, certSvc certServices.CertificateService, keySvc keyservices.KeyService, deny model.DataAction) (*mux.Router, *captureAudit, *bytes.Buffer) {
	t.Helper()
	for _, key := range []string{"rate_limit.default", "rate_limit.auth", "rate_limit.per_vault"} {
		previous := viper.Get(key)
		viper.Set(key, 1_000_000)
		t.Cleanup(func() { viper.Set(key, previous) })
	}

	tc := testutils.NewTestContext(t)
	logs := &bytes.Buffer{}
	tc.Logger.Logger.SetOutput(logs)
	tc.Logger.Logger.SetLevel(logrus.DebugLevel)
	previousOut := logrus.StandardLogger().Out
	logrus.SetOutput(logs)
	t.Cleanup(func() { logrus.SetOutput(previousOut) })

	audit := &captureAudit{}
	tc.Logger.SetAuditPersister(audit)

	tc.MockAuthService.On("ValidateSession", mock.Anything, mock.Anything).
		Return(&authServices.JWTClaims{UserID: tc.TestUserID, Username: "exporter", Roles: []string{model.RoleUser}}, nil).Maybe()
	tc.MockVaultService.On("GetVault", mock.Anything, mock.Anything).
		Return(&model.Vault{ID: tc.TestVaultID, Name: "default", Enabled: true}, nil).Maybe()
	tc.MockRBACService.On("ValidateEndpointAccess", mock.Anything, mock.Anything, mock.Anything).Return(nil).Maybe()
	if deny != "" {
		tc.MockRoleAssignmentService.ExpectedCalls = nil
		tc.MockRoleAssignmentService.On("HasDataAction", mock.Anything, mock.Anything, mock.Anything, deny).Return(false, nil).Maybe()
		tc.MockRoleAssignmentService.On("HasDataAction", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(true, nil).Maybe()
	}

	container := &exportChainContainer{MockServiceContainer: tc.MockContainer, certSvc: certSvc, keySvc: keySvc, audit: audit}
	router := mux.NewRouter()
	Init(
		WithAPP(&app.App{ServiceContainer: container, Logger: tc.Logger}),
		WithRouter(router),
		WithBasePath("/api/v1"),
		WithLogger(tc.Logger),
		WithMetricsEnabled(false),
	)
	return router, audit, logs
}

func postExport(router *mux.Router, path, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer chain-test-token")
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	return w
}

// TestExportThroughRealChain_NoSecretsInLogsOrAudit pins Review Focus 2.
func TestExportThroughRealChain_NoSecretsInLogsOrAudit(t *testing.T) {
	password := "pkcs12-password-must-not-leak"
	keyText := "-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgleaked\n-----END PRIVATE KEY-----\n"
	pfx := []byte("pfx-bytes-must-not-leak")
	certID := uuid.New()

	svc := &mockCertService{}
	svc.On("ExportCertificate", mock.Anything, mock.Anything, certID, mock.MatchedBy(func(r certServices.ExportCertificateRequest) bool {
		return r.Password != nil && *r.Password == password
	})).Return(&certServices.ExportCertificateResult{ID: certID, Name: "client", Version: 1, Format: "pkcs12",
		PKCS12: pfx, PrivateKeyPEM: keyText, KeyAlgorithm: "EC-P256"}, nil)
	svc.On("ExportCertificate", mock.Anything, mock.Anything, certID, mock.Anything).
		Return(&certServices.ExportCertificateResult{ID: certID, Name: "client", Version: 1, Format: "pem",
			CertificatePEM: "-----BEGIN CERTIFICATE-----\nX\n-----END CERTIFICATE-----\n", PrivateKeyPEM: keyText, KeyAlgorithm: "EC-P256"}, nil)

	router, audit, logs := newExportChain(t, svc, nil, "")
	body, _ := json.Marshal(map[string]any{"format": "pkcs12", "password": password})
	w := postExport(router, "/api/v1/certificates/"+certID.String()+"/export", string(body))
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	w = postExport(router, "/api/v1/vaults/default/certificates/"+certID.String()+"/export", `{"format":"pem"}`)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())

	everything := logs.String() + audit.dump()
	for _, secret := range []string{password, "BEGIN PRIVATE KEY", "MIGHAgEAMBMG", "leaked", string(pfx)} {
		assert.NotContains(t, everything, secret)
	}
	assert.Contains(t, audit.dump(), "export_certificate", "the attempt was audited")
}

// TestExportThroughRealChain_MissingRoleIsAudited pins that a principal
// without the exporter role gets the middleware's 403 and leaves a
// persisted audit record naming the export action.
func TestExportThroughRealChain_MissingRoleIsAudited(t *testing.T) {
	svc := &mockCertService{}
	router, audit, _ := newExportChain(t, svc, nil, model.ActionCertificatesExportItem)
	w := postExport(router, "/api/v1/certificates/"+uuid.NewString()+"/export", `{"format":"pem"}`)
	require.Equal(t, http.StatusForbidden, w.Code)
	assert.Contains(t, w.Body.String(), "no role assignment grants this operation")
	assert.Contains(t, audit.dump(), string(model.ActionCertificatesExportItem))
	svc.AssertNotCalled(t, "ExportCertificate", mock.Anything, mock.Anything, mock.Anything, mock.Anything)
}
```

If `testutils.MockServiceContainer` does not satisfy `container.ServiceContainerInterface` once embedded (it must, since `apitest.New` passes it to `api.Init`), the compiler reports the missing method; add only that override.

- [ ] **Step 2: Run and expect PASS**

Run: `go test -p 2 ./api -run 'ThroughRealChain' -v`
Expected: PASS. If the no-secrets test fails, a log or audit line is printing the request or the result; fix that line, never the test.

- [ ] **Step 3: Commit**

Commit via the `dev-workflow-skills:1-git-commit` skill. Stage: `api/export_chain_test.go`.

---

### Task 6: End-to-end mTLS handshake against `openssl s_server -Verify 1`

**Files:**
- Test: `internal/services/certificates/export_tls_e2e_test.go` (create)

**Interfaces:**
- Consumes: Task 2; `newVersioningHarness`, `addKey` from plan 1, `strPtr`.
- Produces: nothing exported.

- [ ] **Step 1: Write the test**

Create `internal/services/certificates/export_tls_e2e_test.go`:

```go
package certificates

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	pkcs12 "software.sslmate.com/src/go-pkcs12"

	"rocketvault/common"
	"rocketvault/internal/crypto"
	"rocketvault/model"
)

// startOpenSSLServer runs `openssl s_server -Verify 1` trusting caPEM for
// client certificates and returns its address and the server certificate.
func startOpenSSLServer(t *testing.T, caPEM string) (string, *x509.Certificate) {
	t.Helper()
	openssl, err := exec.LookPath("openssl")
	if err != nil {
		t.Skip("openssl not found on PATH; the TLS end-to-end export test needs `openssl s_server`")
	}
	dir := t.TempDir()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: "127.0.0.1"},
		NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour),
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	serverCert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	write := func(name string, block *pem.Block) string {
		p := filepath.Join(dir, name)
		require.NoError(t, os.WriteFile(p, pem.EncodeToMemory(block), 0o600))
		return p
	}
	certPath := write("server.pem", &pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPath := write("server.key", &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	caPath := filepath.Join(dir, "ca.pem")
	require.NoError(t, os.WriteFile(caPath, []byte(caPEM), 0o600))

	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	addr := l.Addr().String()
	require.NoError(t, l.Close())

	cmd := exec.Command(openssl, "s_server", "-accept", addr, "-cert", certPath, "-key", keyPath,
		"-CAfile", caPath, "-Verify", "1", "-verify_return_error", "-www", "-quiet")
	require.NoError(t, cmd.Start())
	t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })

	deadline := time.Now().Add(10 * time.Second)
	for {
		conn, err := net.DialTimeout("tcp", addr, 200*time.Millisecond)
		if err == nil {
			_ = conn.Close()
			break
		}
		require.True(t, time.Now().Before(deadline), "openssl s_server did not start")
		time.Sleep(100 * time.Millisecond)
	}
	return addr, serverCert
}

// handshake connects with identity and reports whether s_server answered
// with a page, which it only does after verifying the client certificate.
func handshake(t *testing.T, addr string, server *x509.Certificate, identity []tls.Certificate) bool {
	t.Helper()
	roots := x509.NewCertPool()
	roots.AddCert(server)
	conn, err := tls.Dial("tcp", addr, &tls.Config{RootCAs: roots, Certificates: identity, MinVersion: tls.VersionTLS12})
	if err != nil {
		return false
	}
	defer conn.Close() //nolint:errcheck
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn.Write([]byte("GET / HTTP/1.0\r\n\r\n")); err != nil {
		return false
	}
	line, err := bufio.NewReader(conn).ReadString('\n')
	return err == nil && strings.HasPrefix(line, "HTTP/1.0 200")
}

func TestExportCertificate_DrivesARealMutualTLSHandshake(t *testing.T) {
	for _, keyType := range []string{"RSA", "ECDSA"} {
		t.Run(keyType, func(t *testing.T) {
			h := newVersioningHarness(t)
			ctx := context.Background()

			ca, err := h.svc.CreateSelfSignedCertificate(ctx, CreateCertificateRequest{
				Name: "client-ca", KeyID: h.keyID, ValidityDays: 30, UserID: h.userID, VaultID: h.vaultID, IsCA: true,
			})
			require.NoError(t, err)
			caRow, err := h.certRepo.Read(ctx, ca.CertID, h.scope())
			require.NoError(t, err)

			leafKeyID := uuid.New()
			var leafKeyPEM string
			if keyType == "RSA" {
				leafKeyPEM, err = crypto.GenerateRSAKeyPEM(2048)
			} else {
				leafKeyPEM, err = crypto.GenerateECDSAKeyPEM("P-256")
			}
			require.NoError(t, err)
			enc, err := common.EncryptSecret(leafKeyPEM)
			require.NoError(t, err)
			k := &model.Key{ID: leafKeyID, UserID: h.userID, VaultID: h.vaultID, Name: "client-key", Type: model.KeyTypeRSA,
				Value: enc, Enabled: true, CreatedAt: time.Now(), Bits: 2048, Exportable: true}
			if keyType != "RSA" {
				k.Type, k.Bits, k.Curve = model.KeyTypeECDSA, 0, "P-256"
			}
			require.NoError(t, h.keyRepo.Create(ctx, k))
			leaf, err := h.svc.CreateCASignedCertificate(ctx, CreateCertificateRequest{
				Name: "client", KeyID: leafKeyID, CACertID: &ca.CertID, ValidityDays: 30, UserID: h.userID, VaultID: h.vaultID, Exportable: true,
			})
			require.NoError(t, err)

			addr, server := startOpenSSLServer(t, caRow.Certificate)
			require.False(t, handshake(t, addr, server, nil), "control: no client certificate is refused")

			pemRes, err := h.svc.ExportCertificate(ctx, h.scope(), leaf.CertID, ExportCertificateRequest{Format: model.ExportFormatPEM})
			require.NoError(t, err)
			pair, err := tls.X509KeyPair([]byte(pemRes.CertificatePEM), []byte(pemRes.PrivateKeyPEM))
			require.NoError(t, err)
			require.True(t, handshake(t, addr, server, []tls.Certificate{pair}), "PEM identity")

			p12Res, err := h.svc.ExportCertificate(ctx, h.scope(), leaf.CertID, ExportCertificateRequest{Format: model.ExportFormatPKCS12, Password: strPtr("pw")})
			require.NoError(t, err)
			priv, cert, cas, err := pkcs12.DecodeChain(p12Res.PKCS12, "pw")
			require.NoError(t, err)
			chain := [][]byte{cert.Raw}
			for _, c := range cas {
				chain = append(chain, c.Raw)
			}
			require.True(t, handshake(t, addr, server, []tls.Certificate{{Certificate: chain, PrivateKey: priv, Leaf: cert}}), "PKCS12 identity")
		})
	}
}
```

`-www` answers each request with an HTTP 200 page, and with `-Verify 1 -verify_return_error` it closes the connection before that page if the client sent no valid certificate. `newVersioningHarness`'s own key is RSA, so the CA is RSA for both subtests; the leaf key type varies.

- [ ] **Step 2: Run and expect PASS (or a clear SKIP)**

Run: `go test -p 2 ./internal/services/certificates -run TestExportCertificate_DrivesARealMutualTLSHandshake -v`
Expected: PASS for both subtests, or `SKIP: openssl not found on PATH ...` where OpenSSL is absent. OpenSSL 3.0.13 is at `/usr/bin/openssl` on the development machine.

- [ ] **Step 3: Commit**

Commit via the `dev-workflow-skills:1-git-commit` skill. Stage: `internal/services/certificates/export_tls_e2e_test.go`.

---

### Task 7: Plan 2 regression gate

**Files:**
- Test only: the whole module.

**Interfaces:**
- Consumes: Tasks 1-6.
- Produces: a green tree that plan 3 starts from.

- [ ] **Step 1: Build, vet and test**

Run: `go build ./... && go vet ./... && go test -p 2 ./... -count=1`
Expected: every package PASS. A failure in a pre-existing test is fixed in the code under change, never by weakening or deleting the test.

- [ ] **Step 2: Confirm the old surfaces did not move**

Run: `git diff HEAD~6 -- internal/middleware/ internal/certcache/cache.go internal/services/retry/retried.go api/context.go api/respond.go api/request.go`
Expected: no output. The middleware chain, the cache core, the retry helper and the shared API helpers are untouched.

- [ ] **Step 3: Commit**

Nothing to commit if Steps 1-2 needed no fix; otherwise commit the fix via the `dev-workflow-skills:1-git-commit` skill, staging only the fixed files.

---

## Self-Review

- **Spec coverage (plan 2's share):** §2 steps 1-8: scoped read and 404, parent lifecycle 409, version resolution and `VersionUsable` 409, not-exportable 403 with reason, decrypt and PKCS#8 with exact prefix, ES256K 403, chain leaf-first/no-root/depth 10/cycle/scoped hops, PEM and PKCS12 modern/legacy/empty password, `key_algorithm` on success and refusal, rotation caveat (Task 2). §5 routes on both shapes, request body, 400 on unknown format/compat, response shapes under 64 KiB, `no-store`/`no-cache`, R6 errors and codes, generic internal message (Task 4). §6 pass-through cache and retry with the cache-dump and no-retry tests (Tasks 2, 3), no material or password in logs/audit through the real chain, per-attempt `RecordEvent` with `ResourceID`, middleware-logged role denial (Tasks 4, 5). Testing: certificate service list (Task 2), wrappers (Task 3), API statuses/both shapes/R6/headers/audit (Task 4), no-logging and missing-role audit (Task 5), end to end (Task 6). Regression gates (Task 7).
- **Type consistency:** `ExportCertificateRequest{Format, Password *string, Compat, Version int}`, `ExportCertificateResult{ID, Name, Version, Format, CertificatePEM, PrivateKeyPEM, PKCS12 []byte, NotBefore, ExpiresAt *time.Time, KeyAlgorithm}`, `ExportCertificate(ctx, scope, id, req)`; `model.ExportRefusedError{Sentinel, Reason, Name, KeyAlgorithm}`; `exportFailure{Status, Code, Message, KeyAlgorithm, Name}`, `exportFailureFor(err, resource)`, `exportAudit`, `recordExportAudit`, `exportCaller`, `decodeExportBody`, `setExportHeaders`, `writeExportError`, `badExportRequest`; test helpers `captureAudit`, `exportTestContainer`, `newExportCtx`, `decodeExportError`, `newExportChain`, `postExport`.
