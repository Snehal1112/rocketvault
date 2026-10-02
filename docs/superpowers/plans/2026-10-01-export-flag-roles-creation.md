# Export Flag, Exporter Roles and Creation Surfaces Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Give certificates and keys an immutable, opt-in `exportable` flag that every creation surface can set, add the two exporter data actions and the two narrow exporter roles, route `POST .../export` to those actions (fail closed until the handlers land in the next plans), and report `exportable` and `key_algorithm` on every certificate and key response, without changing any existing behavior.

**Architecture:** `exportable` is a `BOOLEAN NOT NULL DEFAULT FALSE` column on `certificates` and `keys`, dual-written in `createOptimizedSchema` and `migrateSchema`; it is written only by the repository `INSERT` and read through the canonical select lists, so no update, rotation or renewal path can change it. The services enforce the creation rules (HSM and `oct` keys refuse `exportable: true`, an exportable certificate needs an exportable key) and backup restore forces the flag off. Authorization gains `ActionCertificatesExportItem` and `ActionKeysExport`, granted only by the two new exporter roles and Administrator, with `mapCertificateAction`/`mapKeyAction` mapping `POST {id}/export`.

**Tech Stack:** Go 1.25 (`go.mod`), `database/sql` over SQLite (`mattn/go-sqlite3` v1.14.28) and Postgres (`lib/pq`), Gorilla Mux, Cobra, testify, mockery v2.53.6 (`.mockery.yaml`), the MCP go-sdk.

**Spec:** `docs/superpowers/specs/2026-10-01-certificate-and-key-export-design.md` (intent: `docs/superpowers/intents/2026-10-01-certificate-and-key-export.md`; builds on `docs/superpowers/specs/2026-10-01-certificate-versioning-design.md`, already built on this branch).

**Plan series:** this is plan 1 of 3. Plan 2 (`docs/superpowers/plans/2026-10-01-certificate-export.md`) and plan 3 (`docs/superpowers/plans/2026-10-01-key-export-and-docs.md`) consume the symbols listed under "Produces" below; names and types must stay exactly as written here.

## Global Constraints

Binding requirements copied from the spec, one per line:

- `model.Certificate.Exportable` and `model.Key.Exportable`, both `bool` with `json:"exportable"`.
- Both tables get `exportable BOOLEAN NOT NULL DEFAULT FALSE`, added to the `CREATE TABLE` and to a `migrateSchema` ALTER (dual-write; duplicate-column errors ignored). Existing rows become non-exportable.
- Set only at creation or import: an `exportable` field on `POST /certificates`, `POST /keys` and `POST /keys/import`. Repository `Update` never writes it (same pattern as `ca_cert_id`). A `PUT` carrying it is ignored like any unknown field.
- Every creation surface gets the field: `--exportable` on the CLI `certificates create`, `keys create` and `keys import` commands, and the `exportable` field on the vault client (`internal/vaultapi`) and the MCP create tools (`create_certificate`, `create_key`). The CLI paths run their own authorization as today; setting the flag needs no extra permission beyond the create itself.
- Key rotation (`RotateKey`) updates the same key row, so it preserves `exportable`; a test pins this.
- `exportable: true` on an HSM-backed or `oct` key is a 400.
- An exportable certificate requires an exportable key. Creating one over a non-exportable key is a 409 whose message names the key's `exportable` flag.
- ES256K keys can be created exportable but export fails.
- A certificate's versions share the parent's flag; `certificate_versions` gets no `exportable` column.
- `RestoreCertificate` and `RestoreKey` force `exportable=false`, even if an edited blob says otherwise.
- Two new data actions, named so they cannot collide with the unbuilt bulk-export design's `ActionCertificatesExport`: `ActionCertificatesExportItem`, `ActionKeysExport`.
- Two new built-in roles in `azureRoleDataActions`: `Key Vault Certificate Exporter` (the certificate action only) and `Key Vault Key Exporter` (the key action only). Administrator gets both. No other existing role gets either.
- Role count goes from eleven to thirteen and the hard-coded "eleven" mentions in comments and tests are updated.
- Neither new role is in `nonAdminGrantableRoles`, so only a global admin can grant them.
- `mapCertificateAction` and `mapKeyAction` map `POST .../export`; vault-scoped role assignments apply. The legacy access-policy path classifies export as a create, so a legacy deny-create policy also blocks export (fails closed).
- `CertificateResponse` and `KeyResponse` gain `exportable` and `key_algorithm` (the certificate's computed from the leaf public key, so the list does not query per row).

Regression safety (the spec's whole section, binding):

- **Existing data stays safe and unchanged.** The migration only adds a column with `DEFAULT FALSE`. Every existing certificate and key reads as non-exportable, and nothing is backfilled or rewritten. An upgrade test opens a database created by the pre-export build and checks that existing certificates, versions, keys, secrets and role assignments are all intact and readable.
- **Existing API responses only gain fields.** `CertificateResponse` and `KeyResponse` gain `exportable` and `key_algorithm`; no existing field is renamed, removed or retyped, and no existing status code or error body changes (the R6 body is used only on the new export routes). Golden-response tests for create, get, list and update pin this, and `openapi_drift_test` and the route contract tests pass.
- **No existing role gains export.** A role-matrix test asserts that the effective data actions of every pre-existing built-in role are exactly what they were before (only the two new roles and Administrator hold the new actions). Existing role assignments, the grant allow-list and global-admin behavior are unchanged. The role-count updates ("eleven" to thirteen) are the only edits to existing role code.
- **Existing creation and update paths behave the same.** A create without `exportable` produces exactly what it produced before (non-exportable); update, rotate, renew, versions, soft-delete, recover and purge behave as before, and the existing suites for them pass unmodified except where a count or a new field is asserted.
- **Backup, restore and rekey stay compatible.** Blobs written before this change restore unchanged (as non-exportable); a restore never grants exportability; master-key rotation and the backup table order are unaffected.
- **No new weakness in the old surfaces.** Caching, retry and logging behavior of existing methods is unchanged; the new methods are pass-through only, and the existing middleware and policy chain is not modified beyond the new route mappings (unmapped paths still fail closed).
- **Hard gates before reporting done:** `go build ./...`, `go vet ./...` and `go test ./... -count=1` pass with no failing package; the pre-existing tests are not weakened or deleted to make room; and a live smoke test on an isolated instance upgrades a database from the pre-export build and exercises the existing certificate, key, secret and role flows before the new export flows.

Repository conventions for this series:

- Every schema change is dual-written: `createOptimizedSchema` and `migrateSchema` in `internal/db/db.go`; duplicate-column errors are ignored by the existing `isDuplicateColumnError` loop.
- No new data actions beyond `ActionCertificatesExportItem` and `ActionKeysExport`. Unmapped certificate and key paths still fail closed.
- Metadata-only responses: no PEM and no private key in any certificate or key metadata response. `exportable` and `key_algorithm` are metadata.
- Every new route is registered on both the flat and the vault-scoped router (`registerCertificateRoutes`, `registerKeyRoutes`). This plan adds no route; plans 2 and 3 do.
- `docs/api-specification.yaml` and `docs/api-routes.generated.txt` cover both route shapes; `TestOpenAPISpecCoversAllRoutes`, `TestGenerateRouteInventory` and `TestClientPathsAreRegistered` pass.
- Commits go through the `dev-workflow-skills:1-git-commit` plugin skill (Skill tool), never a freeform `git commit -m`. Commits are GPG signed (key 61D246B30285ED35).
- Code comments are short full sentences ending with a punctuation mark.
- mockery fails under the default go1.27 toolchain. Regenerate mocks with the cached go1.25.7 toolchain: `PATH="$HOME/go/pkg/mod/golang.org/toolchain@v0.0.1-go1.25.7.linux-amd64/bin:$PATH" GOTOOLCHAIN=local ~/go/bin/mockery` (mockery v2.53.6 is in `~/go/bin`). This plan changes no mocked interface method set, so it needs no regeneration.
- Run tests with `-p 2` (the sandbox caps OS threads; the default parallelism crashes the compiler). If a single `go run`/`go test` still hits `newosproc`, prefix `GOMAXPROCS=1`.
- Cached certificate rows must never be the source of export material: `ExportCertificate` (plan 2) reads from the repository, not `certcache`.
- `Context.SetConflict` already exists in `api/context.go:118-121`; do not add it again.
- CLI commands bypass HTTP middleware, so each creation rule is tested on the service the CLI calls as well as on the HTTP path.

## Review Focus

1. **A path that rewrites `exportable` after creation.** `KeyRepository.Update` already rewrites `value`, `created_at` and more on every rotation; if `exportable` slipped into its `SET` list, a rotation or a `PUT` could flip it. Pin: `TestKeyRepository_UpdateNeverWritesExportable` and `TestCertificateRepository_UpdateNeverWritesExportable` (Task 2), `TestRotateKey_PreservesExportable` (Task 4).
2. **A certificate bypassing its key's flag.** A certificate stores its own copy of the key, so an exportable certificate over a non-exportable key would leak a key its creator marked non-exportable. Pin: `TestCreateCertificate_ExportableRequiresExportableKey` (Task 5) and `TestCreateCertificateHandler_ExportableOverNonExportableKeyIs409` (Task 6).
3. **An edited backup blob granting exportability.** The blob is base64 JSON with no MAC. Pin: `TestRestore_ForcesExportableFalse` (Task 5).
4. **A pre-existing role silently gaining an export action.** Administrator's bundle is written out by hand and other roles might be edited by copy-paste. Pin: `TestPreExistingRoles_DataActionsUnchanged` (Task 3).
5. **An HSM key created exportable.** The HSM handle is only recognisable after generation, so the check must run both before (provider type) and after (handle shape). Pin: `TestCreateKey_HSMRejectsExportable` (Task 4).

---

## File Structure

| File | Responsibility |
|---|---|
| `model/certificate.go`, `model/key.go` (modify) | `Exportable` fields, `Key.KeyAlgorithm()` |
| `model/export.go` (create) | `ErrExportableKeyRequired`, `ErrExportableNotSupported` |
| `model/azure_roles.go` (modify) | two data actions, two roles, Administrator bundle, "thirteen" |
| `internal/crypto/key_algorithm.go` (create) | `KeyAlgorithmFromPublicKey`, `KeyAlgorithmFromCertificatePEM` |
| `internal/db/db.go` (modify) | `exportable` columns, both schema paths |
| `internal/repositories/certificate_repository.go`, `key_repository.go` (modify) | select list, scan, insert |
| `internal/repositories/*_test.go`, `internal/services/keys/*_test.go`, `api/vault_cross_denial_test.go` (modify) | hand-written schemas gain the column |
| `internal/services/authorization/data_actions.go`, `roles.go`, `role_assignment_service.go` (modify) | export mapping, "thirteen" comments |
| `internal/services/keys/key_service.go` (modify) | `Exportable` on create/import requests, HSM/oct refusal |
| `internal/services/certificates/certificate_service.go` (modify) | `Exportable` on create, 409 rule, result fields |
| `internal/backup/item_backup.go` (modify) | restore forces `Exportable=false` |
| `api/certificates.go`, `api/keys.go`, `api/keys_types.go`, `api/errors_key.go` (modify) | request/response fields, error mapping |
| `cmd/certificates/create.go`, `cmd/keys/create.go`, `cmd/keys/import.go` (modify) | `--exportable` |
| `internal/vaultapi/certificates_write.go`, `keys_write.go` (modify) | `Exportable` request field |
| `internal/mcpserver/tools_certificates_write.go`, `tools_keys_write.go` (modify) | `exportable` tool argument |
| `docs/api-specification.yaml` (modify) | request/response schema fields, role enum |

---

### Task 1: Model fields, sentinels, key-algorithm helpers and the schema migration

**Files:**
- Modify: `model/certificate.go:13-40` (`Certificate` struct, after `Version`)
- Modify: `model/key.go:12-31` (`Key` struct, after `UpdatedAt`), append `KeyAlgorithm` after `IsAccessible` (`:33-46`)
- Create: `model/export.go`, `internal/crypto/key_algorithm.go`
- Modify: `internal/db/db.go:412-431` (`keys` in `createOptimizedSchema`), `:455-475` (`certificates`), `migrateSchema` after the certificate-versions index (`:849`)
- Test: `model/export_test.go` (create), `internal/crypto/key_algorithm_test.go` (create), `internal/db/exportable_migration_test.go` (create)

**Interfaces:**
- Consumes: `cloneTimePtr` (`model/`), `isDuplicateColumnError` (`internal/db/db.go:1333`), `newSilentLogrus` (`internal/db/key_rotation_due_tracking_migration_test.go:22`).
- Produces:
  - `model.Certificate.Exportable bool` (`json:"exportable"`), `model.Key.Exportable bool` (`json:"exportable"`)
  - `func (k *Key) KeyAlgorithm() string` (`"RSA-2048"`, `"EC-P256"`, `"EC-P256K"`, `"oct-256"`; bare `"RSA"`/`"EC"` when the size is unknown)
  - `model.ErrExportableKeyRequired`, `model.ErrExportableNotSupported`
  - `func crypto.KeyAlgorithmFromPublicKey(pub any) string`, `func crypto.KeyAlgorithmFromCertificatePEM(certPEM string) string` (empty string when unparseable)
  - Columns `certificates.exportable`, `keys.exportable`, `BOOLEAN NOT NULL DEFAULT FALSE`.

- [ ] **Step 1: Write the failing model and helper tests**

Create `model/export_test.go`:

```go
package model_test

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"rocketvault/model"
)

func TestExportable_JSONTag(t *testing.T) {
	body, err := json.Marshal(model.Certificate{Exportable: true})
	require.NoError(t, err)
	assert.Contains(t, string(body), `"exportable":true`)

	body, err = json.Marshal(model.Key{Exportable: true})
	require.NoError(t, err)
	assert.Contains(t, string(body), `"exportable":true`)
}

func TestCertificateClone_CopiesExportable(t *testing.T) {
	c := &model.Certificate{Exportable: true}
	assert.True(t, c.Clone().Exportable, "the cache clones certificates, so the flag must survive Clone")
}

func TestKey_KeyAlgorithm(t *testing.T) {
	cases := map[string]model.Key{
		"RSA-2048": {Type: model.KeyTypeRSA, Bits: 2048},
		"RSA-4096": {Type: model.KeyTypeRSA, Bits: 4096},
		"RSA":      {Type: model.KeyTypeRSA},
		"EC-P256":  {Type: model.KeyTypeECDSA, Curve: "P-256"},
		"EC-P521":  {Type: model.KeyTypeECDSA, Curve: "P-521"},
		"EC":       {Type: model.KeyTypeECDSA},
		"EC-P256K": {Type: model.KeyTypeES256K, Curve: "P-256K"},
		"oct-256":  {Type: model.KeyTypeOct, Bits: 256},
	}
	for want, key := range cases {
		k := key
		assert.Equal(t, want, k.KeyAlgorithm())
	}
}

func TestExportSentinels_AreDistinct(t *testing.T) {
	assert.NotEqual(t, model.ErrExportableKeyRequired, model.ErrExportableNotSupported)
	assert.Contains(t, model.ErrExportableKeyRequired.Error(), "exportable")
}
```

Create `internal/crypto/key_algorithm_test.go`:

```go
package crypto

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestKeyAlgorithmFromPublicKey(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	assert.Equal(t, "RSA-2048", KeyAlgorithmFromPublicKey(&rsaKey.PublicKey))

	for curve, want := range map[elliptic.Curve]string{
		elliptic.P256(): "EC-P256", elliptic.P384(): "EC-P384", elliptic.P521(): "EC-P521",
	} {
		ecKey, err := ecdsa.GenerateKey(curve, rand.Reader)
		require.NoError(t, err)
		assert.Equal(t, want, KeyAlgorithmFromPublicKey(&ecKey.PublicKey))
	}
	assert.Equal(t, "", KeyAlgorithmFromPublicKey("not a key"))
}

func TestKeyAlgorithmFromCertificatePEM(t *testing.T) {
	keyPEM, err := GenerateECDSAKeyPEM("P-384")
	require.NoError(t, err)
	certPEM, err := CreateSelfSignedCertificatePEM(keyPEM, "ECDSA", CertificateTemplate{CommonName: "alg", ValidityDays: 1})
	require.NoError(t, err)
	assert.Equal(t, "EC-P384", KeyAlgorithmFromCertificatePEM(certPEM))
	assert.Equal(t, "", KeyAlgorithmFromCertificatePEM("garbage"))
}
```

- [ ] **Step 2: Run them and expect FAIL**

Run: `go test -p 2 ./model ./internal/crypto -run 'TestExportable_|TestCertificateClone_CopiesExportable|TestKey_KeyAlgorithm|TestExportSentinels|TestKeyAlgorithmFrom' -v`
Expected: FAIL (build error: `Exportable`, `KeyAlgorithm`, `ErrExportableKeyRequired`, `KeyAlgorithmFromPublicKey` undefined).

- [ ] **Step 3: Implement the model fields, sentinels and helpers**

In `model/certificate.go`, after the `Version int` field of `Certificate`, add:

```go
	// Exportable reports whether the certificate's private key may ever be
	// exported. It is set at creation only and no update path writes it, so
	// it is immutable. A certificate's archived versions share this flag.
	Exportable bool `json:"exportable"`
```

In `model/key.go`, add `"fmt"` and `"strings"` to the imports. After `UpdatedAt` in `Key`, add:

```go
	// Exportable reports whether the key's private material may ever be
	// exported. It is set at creation or import only; rotation keeps it
	// because rotation updates the same row. HSM and oct keys are never
	// exportable.
	Exportable bool `json:"exportable"`
```

After `IsAccessible` add:

```go
// KeyAlgorithm returns a short label for the key's algorithm and size, such
// as RSA-2048 or EC-P256. It reads only stored metadata, so it is safe on a
// list response and for HSM-backed keys. A size the row does not record
// yields the bare family name.
func (k *Key) KeyAlgorithm() string {
	switch k.Type {
	case KeyTypeRSA:
		if k.Bits > 0 {
			return fmt.Sprintf("RSA-%d", k.Bits)
		}
		return "RSA"
	case KeyTypeECDSA:
		if k.Curve != "" {
			return "EC-" + strings.ReplaceAll(k.Curve, "-", "")
		}
		return "EC"
	case KeyTypeES256K:
		return "EC-P256K"
	case KeyTypeOct:
		return fmt.Sprintf("oct-%d", k.Bits)
	}
	return k.Type
}
```

Create `model/export.go`:

```go
package model

import "errors"

// ErrExportableKeyRequired is returned when an exportable certificate is
// requested over a key whose exportable flag is false. A certificate keeps
// its own copy of the key, so allowing this would bypass the key's flag.
// The API maps it to 409.
var ErrExportableKeyRequired = errors.New("an exportable certificate requires a key whose exportable flag is true")

// ErrExportableNotSupported is returned when exportable is requested for a
// key that can never be exported: an HSM-backed key or a symmetric oct key.
// The API maps it to 400.
var ErrExportableNotSupported = errors.New("exportable is not supported for HSM-backed or oct keys")
```

Create `internal/crypto/key_algorithm.go`:

```go
package crypto

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"strings"
)

// KeyAlgorithmFromPublicKey returns a short label such as RSA-2048 or
// EC-P256 for a public key. An unknown type yields an empty string.
func KeyAlgorithmFromPublicKey(pub any) string {
	switch k := pub.(type) {
	case *rsa.PublicKey:
		return fmt.Sprintf("RSA-%d", k.N.BitLen())
	case *ecdsa.PublicKey:
		return "EC-" + strings.ReplaceAll(k.Curve.Params().Name, "-", "")
	case ed25519.PublicKey:
		return "Ed25519"
	}
	return ""
}

// KeyAlgorithmFromCertificatePEM returns the algorithm label of the public
// key in the first certificate of certPEM. It parses only; it never touches
// private material. An unparseable input yields an empty string.
func KeyAlgorithmFromCertificatePEM(certPEM string) string {
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		return ""
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return ""
	}
	return KeyAlgorithmFromPublicKey(cert.PublicKey)
}
```

- [ ] **Step 4: Run and expect PASS**

Run: `go test -p 2 ./model ./internal/crypto -run 'TestExportable_|TestCertificateClone_CopiesExportable|TestKey_KeyAlgorithm|TestExportSentinels|TestKeyAlgorithmFrom' -v`
Expected: PASS.

- [ ] **Step 5: Write the failing migration tests**

Create `internal/db/exportable_migration_test.go`:

```go
// Export adds certificates.exportable and keys.exportable. These tests prove
// a fresh database gets both with a false default, an upgraded database gets
// both with every existing row reading false and nothing rewritten, and a
// second migration run is a no-op.
package db

import (
	"database/sql"
	"testing"

	_ "github.com/mattn/go-sqlite3"
	"github.com/stretchr/testify/require"

	"rocketvault/internal/logging"
)

func TestSetupSchema_FreshDatabaseHasExportableColumns(t *testing.T) {
	conn, err := sql.Open("sqlite3", ":memory:")
	require.NoError(t, err)
	conn.SetMaxOpenConns(1)
	defer conn.Close() //nolint:errcheck

	repo := NewRepository(&logging.Logger{Logger: newSilentLogrus()})
	require.NoError(t, repo.SetupSchema(conn, SQLite))

	_, err = conn.Exec(`INSERT INTO certificates (id, user_id, name, certificate, private_key) VALUES ('c1', 'u1', 'c', 'pem', 'key')`)
	require.NoError(t, err)
	_, err = conn.Exec(`INSERT INTO keys (id, user_id, name, value, type) VALUES ('k1', 'u1', 'k', 'v', 'RSA')`)
	require.NoError(t, err)

	var certExportable, keyExportable bool
	require.NoError(t, conn.QueryRow(`SELECT exportable FROM certificates WHERE id = 'c1'`).Scan(&certExportable))
	require.NoError(t, conn.QueryRow(`SELECT exportable FROM keys WHERE id = 'k1'`).Scan(&keyExportable))
	require.False(t, certExportable, "a certificate created without the flag is not exportable")
	require.False(t, keyExportable, "a key created without the flag is not exportable")

	require.False(t, columnExists(t, conn, "certificate_versions", "exportable"),
		"versions share the parent's flag; certificate_versions has no exportable column")
}

func TestMigrateSchema_ExistingRowsBecomeNonExportable(t *testing.T) {
	conn, err := sql.Open("sqlite3", ":memory:")
	require.NoError(t, err)
	conn.SetMaxOpenConns(1)
	defer conn.Close() //nolint:errcheck

	// Minimal pre-feature schema, copied from the certificate-versions
	// migration test, with one existing certificate and one existing key.
	_, err = conn.Exec(`
		CREATE TABLE users (id TEXT PRIMARY KEY, username TEXT NOT NULL, role TEXT NOT NULL);
		CREATE TABLE secrets (id TEXT PRIMARY KEY, name TEXT NOT NULL);
		CREATE TABLE certificates (id TEXT PRIMARY KEY, name TEXT NOT NULL);
		CREATE TABLE access_policies (
			id TEXT PRIMARY KEY, principal_id TEXT NOT NULL, principal_type TEXT NOT NULL,
			resource_type TEXT NOT NULL, operation TEXT NOT NULL, effect TEXT NOT NULL,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		);
		CREATE TABLE audit_logs (id TEXT PRIMARY KEY);
		CREATE TABLE vaults (
			id TEXT PRIMARY KEY, name TEXT NOT NULL, enabled BOOLEAN NOT NULL DEFAULT TRUE,
			purge_protection BOOLEAN NOT NULL DEFAULT FALSE, retention_days INTEGER NOT NULL DEFAULT 90,
			created_by TEXT NOT NULL, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			deleted_at TIMESTAMP NULL, scheduled_purge_at TIMESTAMP NULL
		);
		CREATE TABLE keys (
			id TEXT PRIMARY KEY, name TEXT NOT NULL,
			vault_id TEXT NOT NULL DEFAULT '00000000-0000-0000-0000-00000000efa1',
			created_at TIMESTAMP NOT NULL
		);
		CREATE TABLE rotation_policies (
			id TEXT PRIMARY KEY, user_id TEXT NOT NULL,
			vault_id TEXT NOT NULL DEFAULT '00000000-0000-0000-0000-00000000efa1',
			name TEXT NOT NULL, description TEXT, interval_days INTEGER NOT NULL,
			enabled BOOLEAN NOT NULL DEFAULT TRUE, reminder_days INTEGER NOT NULL DEFAULT 7,
			auto_rotate BOOLEAN NOT NULL DEFAULT FALSE,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		);
		CREATE TABLE key_rotation_policies (
			id TEXT PRIMARY KEY, key_id TEXT NOT NULL UNIQUE, user_id TEXT NOT NULL,
			vault_id TEXT NOT NULL DEFAULT '00000000-0000-0000-0000-00000000efa1',
			rotate_after_days INTEGER NOT NULL DEFAULT 90,
			notify_before_expiry_days INTEGER NOT NULL DEFAULT 30,
			expiry_days INTEGER NOT NULL DEFAULT 365, enabled BOOLEAN NOT NULL DEFAULT TRUE,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		);
		INSERT INTO certificates (id, name) VALUES ('old-cert', 'issued-before-export');
		INSERT INTO keys (id, name, created_at) VALUES ('old-key', 'created-before-export', CURRENT_TIMESTAMP);
	`)
	require.NoError(t, err)

	repo := &DBRepository{dialect: SQLite}
	repo.log = &logging.Logger{Logger: newSilentLogrus()}
	require.NoError(t, repo.migrateSchema(conn))

	var certExportable, keyExportable bool
	require.NoError(t, conn.QueryRow(`SELECT exportable FROM certificates WHERE id = 'old-cert'`).Scan(&certExportable))
	require.NoError(t, conn.QueryRow(`SELECT exportable FROM keys WHERE id = 'old-key'`).Scan(&keyExportable))
	require.False(t, certExportable)
	require.False(t, keyExportable)

	var name string
	require.NoError(t, conn.QueryRow(`SELECT name FROM certificates WHERE id = 'old-cert'`).Scan(&name))
	require.Equal(t, "issued-before-export", name, "nothing is rewritten")

	require.NoError(t, repo.migrateSchema(conn), "a second run must ignore the duplicate columns")
}
```

`columnExists` is the existing helper in `internal/db/upgrade_path_test.go`.

- [ ] **Step 6: Run and expect FAIL**

Run: `go test -p 2 ./internal/db -run 'Exportable' -v`
Expected: FAIL with `no such column: exportable`.

- [ ] **Step 7: Add the columns on both schema paths**

In `internal/db/db.go` `createOptimizedSchema`, in the `keys` table after `updated_at TIMESTAMP NULL,` add:

```sql
			exportable BOOLEAN NOT NULL DEFAULT FALSE,
```

In the `certificates` table after `version INTEGER NOT NULL DEFAULT 1,` add:

```sql
			exportable BOOLEAN NOT NULL DEFAULT FALSE,
```

In `migrateSchema`, immediately after `"CREATE INDEX IF NOT EXISTS idx_certificate_versions_certificate_id ON certificate_versions(certificate_id)",` add:

```go
		// Export: an immutable opt-in flag set only at creation. Existing
		// rows become non-exportable and nothing is backfilled.
		// certificate_versions gets no column: versions share the parent's flag.
		"ALTER TABLE certificates ADD COLUMN exportable BOOLEAN NOT NULL DEFAULT FALSE",
		"ALTER TABLE keys ADD COLUMN exportable BOOLEAN NOT NULL DEFAULT FALSE",
```

- [ ] **Step 8: Run and expect PASS**

Run: `go test -p 2 ./internal/db ./model ./internal/crypto -count=1`
Expected: PASS (every existing `internal/db` migration test still passes; the backup FK drift guard is unaffected because no table was added).

- [ ] **Step 9: Commit**

Commit via the `dev-workflow-skills:1-git-commit` skill. Stage: `model/certificate.go`, `model/key.go`, `model/export.go`, `model/export_test.go`, `internal/crypto/key_algorithm.go`, `internal/crypto/key_algorithm_test.go`, `internal/db/db.go`, `internal/db/exportable_migration_test.go`.

---

### Task 2: Repositories read and insert the flag, never update it, and the upgrade test

**Files:**
- Modify: `internal/repositories/certificate_repository.go:72` (`certificateColumns`), `:75-111` (`scanCertificateRow`), `:438-460` (`insertCertAndTags`)
- Modify: `internal/repositories/key_repository.go:91` (`keyColumns`), `:94-116` (`scanKeyRow`), `:372-381` (`insertKeyAndTags`)
- Modify hand-written test schemas (add `exportable BOOLEAN NOT NULL DEFAULT FALSE` to every `certificates` table that has `version INTEGER NOT NULL DEFAULT 1` and every `keys` table that has `updated_at TIMESTAMP NULL`): `internal/repositories/repositories_test.go:65` and `:97`, `certificate_renewal_repo_test.go:33`, `certificate_listall_test.go:39`, `certificate_ca_cert_id_test.go:33`, `internal_coverage_test.go:~91` (`makeKeysTable`) and `:122`, `certificate_lifecycle_test.go:32`, `certificate_scope_test.go:34`, `certificate_soft_delete_test.go:41`, `certificate_key_id_test.go:36`, `key_soft_delete_test.go:57`, `tag_orphan_test.go:~52`, `key_scope_test.go:44`; `internal/services/keys/crypto_vault_scope_test.go:88`, `rotation_integration_test.go:69`, `key_service_update_test.go:152`; `api/vault_cross_denial_test.go:160`, `:241` and `:353`
- Test: `internal/repositories/exportable_repo_test.go` (create), `internal/repositories/export_upgrade_test.go` (create), `internal/certcache/cache_exportable_test.go` (create)

**Interfaces:**
- Consumes: Task 1 columns and fields; `rvdb.NewRepository`, `rvdb.NewConn`, `NewCertificateRepository`, `NewKeyRepository`, `NewCertificateVersionRepository`, `NewSecretRepository`, `NewRoleAssignmentRepository`, `certcache.NewCacheWithL2`.
- Produces: `exportable` in `certificateColumns`/`keyColumns`, read by every scoped read and list; written only by `insertCertAndTags`/`insertKeyAndTags`.

- [ ] **Step 1: Write the failing repository tests**

Create `internal/repositories/exportable_repo_test.go`:

```go
package repositories

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/google/uuid"
	_ "github.com/mattn/go-sqlite3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	rvdb "rocketvault/internal/db"
	"rocketvault/internal/logging"
	"rocketvault/model"
)

func newExportableDB(t *testing.T) (*sql.DB, rvdb.DB) {
	t.Helper()
	raw, err := sql.Open("sqlite3", "file:exportable_"+uuid.NewString()+"?mode=memory&cache=shared")
	require.NoError(t, err)
	t.Cleanup(func() { raw.Close() }) //nolint:errcheck,gosec
	require.NoError(t, rvdb.NewRepository(logging.InitLogger()).SetupSchema(raw, rvdb.SQLite))
	return raw, rvdb.NewConn(raw, rvdb.SQLite)
}

func TestKeyRepository_ExportableRoundTrips(t *testing.T) {
	_, conn := newExportableDB(t)
	repo := NewKeyRepository(conn, logging.InitLogger())
	ctx := context.Background()
	vaultID, userID := uuid.New(), uuid.New()
	scope := model.NewVaultScope(vaultID, userID)

	on := &model.Key{ID: uuid.New(), UserID: userID, VaultID: vaultID, Name: "on", Type: model.KeyTypeRSA,
		Value: "enc", Enabled: true, CreatedAt: time.Now(), Bits: 2048, Exportable: true}
	off := &model.Key{ID: uuid.New(), UserID: userID, VaultID: vaultID, Name: "off", Type: model.KeyTypeRSA,
		Value: "enc", Enabled: true, CreatedAt: time.Now(), Bits: 2048}
	require.NoError(t, repo.Create(ctx, on))
	require.NoError(t, repo.Create(ctx, off))

	got, err := repo.Read(ctx, on.ID, scope)
	require.NoError(t, err)
	assert.True(t, got.Exportable)
	got, err = repo.Read(ctx, off.ID, scope)
	require.NoError(t, err)
	assert.False(t, got.Exportable)

	list, err := repo.List(ctx, scope, KeyFilter{})
	require.NoError(t, err)
	byName := map[string]bool{}
	for _, k := range list {
		byName[k.Name] = k.Exportable
	}
	assert.Equal(t, map[string]bool{"on": true, "off": false}, byName)
}

func TestKeyRepository_UpdateNeverWritesExportable(t *testing.T) {
	_, conn := newExportableDB(t)
	repo := NewKeyRepository(conn, logging.InitLogger())
	ctx := context.Background()
	vaultID, userID := uuid.New(), uuid.New()
	scope := model.NewVaultScope(vaultID, userID)

	key := &model.Key{ID: uuid.New(), UserID: userID, VaultID: vaultID, Name: "k", Type: model.KeyTypeRSA,
		Value: "enc", Enabled: true, CreatedAt: time.Now(), Exportable: false}
	require.NoError(t, repo.Create(ctx, key))

	key.Exportable = true
	key.Value = "rotated"
	require.NoError(t, repo.Update(ctx, key, scope))

	got, err := repo.Read(ctx, key.ID, scope)
	require.NoError(t, err)
	assert.Equal(t, "rotated", got.Value, "the update itself applied")
	assert.False(t, got.Exportable, "Update must never write exportable")
}

func TestCertificateRepository_ExportableRoundTripsAndUpdateNeverWritesIt(t *testing.T) {
	_, conn := newExportableDB(t)
	repo := NewCertificateRepository(conn, logging.InitLogger())
	ctx := context.Background()
	vaultID, userID := uuid.New(), uuid.New()
	scope := model.NewVaultScope(vaultID, userID)

	cert := &model.Certificate{ID: uuid.New(), UserID: userID, VaultID: vaultID, KeyID: uuid.New(), Name: "c",
		Certificate: "pem", PrivateKey: "enc", CreatedAt: time.Now(), Enabled: true, Version: 1, Exportable: true}
	require.NoError(t, repo.Create(ctx, cert))

	got, err := repo.Read(ctx, cert.ID, scope)
	require.NoError(t, err)
	assert.True(t, got.Exportable)

	got.Exportable = false
	got.Name = "renamed"
	require.NoError(t, repo.Update(ctx, got, scope))
	again, err := repo.Read(ctx, cert.ID, scope)
	require.NoError(t, err)
	assert.Equal(t, "renamed", again.Name)
	assert.True(t, again.Exportable, "Update must never write exportable")

	list, err := repo.List(ctx, scope, CertificateFilter{})
	require.NoError(t, err)
	require.Len(t, list, 1)
	assert.True(t, list[0].Exportable)
}

func TestCertificateRepository_UpdateNeverWritesExportable(t *testing.T) {
	_, conn := newExportableDB(t)
	repo := NewCertificateRepository(conn, logging.InitLogger())
	ctx := context.Background()
	vaultID, userID := uuid.New(), uuid.New()
	scope := model.NewVaultScope(vaultID, userID)

	cert := &model.Certificate{ID: uuid.New(), UserID: userID, VaultID: vaultID, KeyID: uuid.New(), Name: "c",
		Certificate: "pem", PrivateKey: "enc", CreatedAt: time.Now(), Enabled: true, Version: 1}
	require.NoError(t, repo.Create(ctx, cert))
	cert.Exportable = true
	require.NoError(t, repo.Update(ctx, cert, scope))
	got, err := repo.Read(ctx, cert.ID, scope)
	require.NoError(t, err)
	assert.False(t, got.Exportable)
}
```

Create `internal/repositories/export_upgrade_test.go`:

```go
package repositories

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	rvdb "rocketvault/internal/db"
	"rocketvault/internal/logging"
	"rocketvault/model"
)

// TestUpgrade_PreExportDatabaseStaysIntact builds a database with the full
// current schema, populates certificates (with an archived version), keys,
// secrets and role assignments, then drops the exportable columns so it has
// exactly the pre-export shape. Re-running the real schema setup must add the
// columns back as false and leave every existing row intact and readable.
func TestUpgrade_PreExportDatabaseStaysIntact(t *testing.T) {
	path := filepath.Join(t.TempDir(), "pre-export.db")
	raw, err := sql.Open("sqlite3", path)
	require.NoError(t, err)
	raw.SetMaxOpenConns(1)
	t.Cleanup(func() { raw.Close() }) //nolint:errcheck,gosec

	setup := rvdb.NewRepository(logging.InitLogger())
	require.NoError(t, setup.SetupSchema(raw, rvdb.SQLite))
	conn := rvdb.NewConn(raw, rvdb.SQLite)
	log := logging.InitLogger()
	ctx := context.Background()

	vaultID, userID := uuid.MustParse(model.DefaultVaultID), uuid.New()
	scope := model.NewVaultScope(vaultID, userID)
	keys := NewKeyRepository(conn, log)
	certs := NewCertificateRepository(conn, log)
	versions := NewCertificateVersionRepository(conn, log)
	secrets := NewSecretRepository(conn, log)
	roles := NewRoleAssignmentRepository(conn)

	key := &model.Key{ID: uuid.New(), UserID: userID, VaultID: vaultID, Name: "old-key", Type: model.KeyTypeRSA,
		Value: "enc", Enabled: true, CreatedAt: time.Now(), Bits: 2048}
	require.NoError(t, keys.Create(ctx, key))
	cert := &model.Certificate{ID: uuid.New(), UserID: userID, VaultID: vaultID, KeyID: key.ID, Name: "old-cert",
		Certificate: "pem-v2", PrivateKey: "enc-v2", CreatedAt: time.Now(), Enabled: true, Version: 2}
	require.NoError(t, certs.Create(ctx, cert))
	require.NoError(t, versions.CreateVersion(ctx, &model.CertificateVersionRecord{
		CertificateID: cert.ID, Version: 1, Certificate: "pem-v1", PrivateKey: "enc-v1", KeyID: key.ID,
		CreatedAt: time.Now().Add(-time.Hour), Enabled: true,
	}))
	secret := &model.Secret{ID: uuid.New(), UserID: userID, VaultID: vaultID, Name: "old-secret", Value: "enc-s",
		Version: 1, CreatedAt: time.Now(), Enabled: true}
	require.NoError(t, secrets.Create(ctx, secret))
	assignment := &model.RoleAssignment{ID: uuid.New(), PrincipalID: userID, PrincipalType: model.PrincipalTypeUser,
		Role: model.RoleKeyVaultSecretsUser, VaultID: vaultID, CreatedBy: userID}
	require.NoError(t, roles.Create(ctx, assignment))

	// Turn this into a pre-export database.
	_, err = raw.Exec(`ALTER TABLE certificates DROP COLUMN exportable`)
	require.NoError(t, err)
	_, err = raw.Exec(`ALTER TABLE keys DROP COLUMN exportable`)
	require.NoError(t, err)

	// The upgrade: the same setup production runs on every start.
	require.NoError(t, setup.SetupSchema(raw, rvdb.SQLite))

	gotKey, err := keys.Read(ctx, key.ID, scope)
	require.NoError(t, err)
	assert.Equal(t, "old-key", gotKey.Name)
	assert.Equal(t, "enc", gotKey.Value)
	assert.False(t, gotKey.Exportable)

	gotCert, err := certs.Read(ctx, cert.ID, scope)
	require.NoError(t, err)
	assert.Equal(t, "pem-v2", gotCert.Certificate)
	assert.Equal(t, 2, gotCert.Version)
	assert.False(t, gotCert.Exportable)

	records, err := versions.ListVersionRecords(ctx, cert.ID)
	require.NoError(t, err)
	require.Len(t, records, 1)
	assert.Equal(t, "enc-v1", records[0].PrivateKey)

	gotSecret, err := secrets.Read(ctx, secret.ID, scope)
	require.NoError(t, err)
	assert.Equal(t, "old-secret", gotSecret.Name)

	listed, err := roles.ListByVault(ctx, vaultID)
	require.NoError(t, err)
	require.Len(t, listed, 1)
	assert.Equal(t, model.RoleKeyVaultSecretsUser, listed[0].Role)
}
```

If `model.Secret` has no `Enabled` field, drop that field from the literal; the compiler will say so.

Create `internal/certcache/cache_exportable_test.go`:

```go
package certcache

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"rocketvault/internal/cachekit"
	"rocketvault/model"
)

// TestCache_ExportableSurvivesClone pins that a cached certificate keeps its
// flag: the list and get responses read exportable off whatever the cache
// returns.
func TestCache_ExportableSurvivesClone(t *testing.T) {
	c := NewCache(cachekit.Config{Enabled: true, TTL: time.Minute, CleanupInterval: time.Minute, MaxEntries: 10}, logrus.New())
	t.Cleanup(c.Stop)
	ctx := context.Background()
	vaultID := uuid.New()
	scope := model.NewVaultScope(vaultID, uuid.New())
	cert := &model.Certificate{ID: uuid.New(), VaultID: vaultID, Name: "c", Enabled: true, Exportable: true}
	require.NoError(t, c.Set(ctx, cert, scope))

	got, ok := c.Get(ctx, cert.ID, scope)
	require.True(t, ok)
	assert.True(t, got.Exportable)
}
```

- [ ] **Step 2: Run and expect FAIL**

Run: `go test -p 2 ./internal/repositories -run 'Exportable|TestUpgrade_PreExportDatabaseStaysIntact' -v`
Expected: FAIL. The round-trip tests read `Exportable` back as false for the `on` key and certificate, because neither the insert nor the select list carries the column yet. The upgrade test already passes at this point (it only reads names, values and versions, and the flag reads false), so it is a regression guard that must stay green after Step 3.

- [ ] **Step 3: Add the column to the canonical select lists, scans and inserts**

In `internal/repositories/certificate_repository.go`, change `certificateColumns` to end with `..., purge_protection, version, exportable"` and in `scanCertificateRow` change the scan tail from `&cert.PurgeProtection, &cert.Version); err != nil {` to `&cert.PurgeProtection, &cert.Version, &cert.Exportable); err != nil {`.

In `insertCertAndTags`, replace the INSERT with:

```go
	// exportable is written here and nowhere else: Update never touches it,
	// so the flag is immutable after creation.
	_, err := ex.ExecContext(
		ctx,
		"INSERT INTO certificates (id, user_id, vault_id, name, certificate, private_key, created_at, expires_at, auto_renew, renewal_days, key_id, ca_cert_id, enabled, not_before, version, exportable) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
		cert.ID.String(), cert.UserID.String(), cert.VaultID.String(), cert.Name, cert.Certificate, cert.PrivateKey, cert.CreatedAt,
		cert.ExpiresAt, cert.AutoRenew, cert.RenewalDays, cert.KeyID.String(), caCertID, cert.Enabled, cert.NotBefore, cert.CurrentVersion(),
		cert.Exportable,
	)
```

In `internal/repositories/key_repository.go`, change `keyColumns` to end with `..., deleted_at, purge_protection, exportable"` and the `scanKeyRow` scan tail to `&key.DeletedAt, &key.PurgeProtection, &key.Exportable); err != nil {`. In `insertKeyAndTags` replace the INSERT with:

```go
	// exportable is written here and nowhere else: Update never touches it,
	// so rotation and PUT keep the flag the key was created with.
	_, err := ex.ExecContext(
		ctx,
		"INSERT INTO keys (id, user_id, vault_id, name, value, type, revoked, created_at, enabled, expires_at, not_before, bits, curve, exportable) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
		key.ID.String(), key.UserID.String(), key.VaultID.String(), key.Name, key.Value, key.Type, key.Revoked, key.CreatedAt,
		key.Enabled, key.ExpiresAt, key.NotBefore, key.Bits, key.Curve, key.Exportable,
	)
```

Leave both `Update` methods and `ReadDeletedScoped` unchanged.

- [ ] **Step 4: Add the column to the hand-written test schemas**

In each file listed under **Files** above, add the line `exportable BOOLEAN NOT NULL DEFAULT FALSE,` to the `certificates` table directly after `version INTEGER NOT NULL DEFAULT 1,` and to the `keys` table directly after `updated_at TIMESTAMP NULL` (add a comma to the `updated_at` line when it was the last column). Then confirm nothing was missed:

Run: `grep -rln "CREATE TABLE\( IF NOT EXISTS\)\? \(keys\|certificates\) (" --include='*_test.go' internal/repositories internal/services api cmd internal/backup | xargs grep -L "exportable"`
Expected: only files whose hand-written tables never pass through `KeyRepository`/`CertificateRepository` reads (for example `key_rotation_policy_repository_test.go`); confirm each by running its package tests in Step 5.

- [ ] **Step 5: Run and expect PASS**

Run: `go test -p 2 ./internal/repositories ./internal/certcache ./internal/services/keys ./internal/services/certificates ./internal/backup ./api -count=1`
Expected: PASS. Any `no such column: exportable` failure names a hand-written schema missed in Step 4; add the column there.

- [ ] **Step 6: Commit**

Commit via the `dev-workflow-skills:1-git-commit` skill. Stage: `internal/repositories/certificate_repository.go`, `internal/repositories/key_repository.go`, `internal/repositories/exportable_repo_test.go`, `internal/repositories/export_upgrade_test.go`, `internal/certcache/cache_exportable_test.go`, and every test file edited in Step 4.

---

### Task 3: Export data actions, exporter roles, route mapping and the role-matrix regression test

**Files:**
- Modify: `model/azure_roles.go:76-97` (certificate actions), `:32-74` (key actions), `:111-149` (role names), `:154-167` (Administrator bundle), append the two roles after `RoleKeyVaultDataAccessAdministrator` in `azureRoleDataActions` (`:210-212`), `:215` and `:225` (comments)
- Modify: `internal/services/authorization/data_actions.go:139-213` (`mapKeyAction`), `:218-279` (`mapCertificateAction`)
- Modify (comments only, "eleven" to "thirteen"): `internal/services/authorization/roles.go:61`, `:93`, `:111`; `internal/services/authorization/role_assignment_service.go:121`; `internal/db/role_backfill.go:46`
- Modify tests: `model/azure_roles_test.go:10-25`, `:27`, `:79-92`, `:215-220`; `internal/services/authorization/authorization_matrix_test.go:31-97`, `:120-161`, `:164`, `:195`, `:211-214`; `internal/services/authorization/roles_test.go:113`, `:165`; `internal/services/authorization/role_assignment_service_test.go:134`, `:210`
- Test: `model/export_roles_test.go` (create), `internal/services/authorization/export_mapping_test.go` (create), `internal/services/authorization/export_grant_test.go` (create), `internal/middleware/export_policy_test.go` (create)

**Interfaces:**
- Consumes: `MapRouteToDataAction`, `RoleGrantsDataAction`, `AzureRoleDataActions`, `nonAdminGrantableRoles`, `resolvePolicy` (`internal/middleware/middleware.go:413`).
- Produces (plans 2 and 3 rely on these exact names):
  - `model.ActionCertificatesExportItem DataAction = "Microsoft.KeyVault/vaults/certificates/export/action"`
  - `model.ActionKeysExport DataAction = "Microsoft.KeyVault/vaults/keys/export/action"`
  - `model.RoleKeyVaultCertificateExporter = "Key Vault Certificate Exporter"`
  - `model.RoleKeyVaultKeyExporter = "Key Vault Key Exporter"`
  - `MapRouteToDataAction("POST", ".../certificates/{id}/export")` returns `(model.ActionCertificatesExportItem, RouteVaultData)`; `MapRouteToDataAction("POST", ".../keys/{id}/export")` returns `(model.ActionKeysExport, RouteVaultData)`; any other method on those paths returns `("", RouteVaultData)`.

The action strings reuse `.../export/action`, which the unbuilt bulk-export design (`docs/superpowers/specs/2026-08-25-certificate-export-design.md:166-169`) also planned for its `ActionCertificatesExport`. Plan 3 renames that design's action to `ActionCertificatesBulkExport` with `.../certificates/bulkExport/action`, as the spec's Documentation section requires.

- [ ] **Step 1: Write the failing tests**

Create `model/export_roles_test.go`:

```go
package model

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestExportActions_Strings(t *testing.T) {
	assert.Equal(t, DataAction("Microsoft.KeyVault/vaults/certificates/export/action"), ActionCertificatesExportItem)
	assert.Equal(t, DataAction("Microsoft.KeyVault/vaults/keys/export/action"), ActionKeysExport)
}

func TestExporterRoles_GrantOnlyTheirAction(t *testing.T) {
	assert.Equal(t, []DataAction{ActionCertificatesExportItem}, AzureRoleDataActions(RoleKeyVaultCertificateExporter))
	assert.Equal(t, []DataAction{ActionKeysExport}, AzureRoleDataActions(RoleKeyVaultKeyExporter))
	assert.True(t, IsAzureRole(RoleKeyVaultCertificateExporter))
	assert.True(t, IsAzureRole(RoleKeyVaultKeyExporter))
}

func TestAdministrator_GrantsBothExportActions(t *testing.T) {
	assert.True(t, RoleGrantsDataAction(RoleKeyVaultAdministrator, ActionCertificatesExportItem))
	assert.True(t, RoleGrantsDataAction(RoleKeyVaultAdministrator, ActionKeysExport))
}

// preExportBundles is every pre-existing role's bundle exactly as it was
// before export. Only Administrator may differ, and only by the two export
// actions.
var preExportBundles = map[string][]DataAction{
	RoleKeyVaultReader:      {ActionSecretsReadMetadata, ActionKeysRead, ActionCertificatesRead},
	RoleKeyVaultSecretsUser: {ActionSecretsReadMetadata, ActionSecretsGet},
	RoleKeyVaultSecretsOfficer: {ActionSecretsReadMetadata, ActionSecretsGet, ActionSecretsSet,
		ActionSecretsDelete, ActionSecretsBackup, ActionSecretsRestore, ActionSecretsRecover, ActionSecretsPurge},
	RoleKeyVaultCryptoUser: {ActionKeysRead, ActionKeysUpdate, ActionKeysEncrypt, ActionKeysDecrypt,
		ActionKeysWrap, ActionKeysUnwrap, ActionKeysSign, ActionKeysVerify, ActionKeysBackup},
	RoleKeyVaultCryptoOfficer: {ActionKeysRead, ActionKeysCreate, ActionKeysUpdate, ActionKeysDelete,
		ActionKeysBackup, ActionKeysRestore, ActionKeysRecover, ActionKeysPurge, ActionKeysImport, ActionKeysRotate,
		ActionKeysEncrypt, ActionKeysDecrypt, ActionKeysWrap, ActionKeysUnwrap, ActionKeysSign, ActionKeysVerify,
		ActionKeysRotationPolicyRead, ActionKeysRotationPolicyWrite},
	RoleKeyVaultCertificatesOfficer: {ActionCertificatesRead, ActionCertificatesCreate, ActionCertificatesUpdate,
		ActionCertificatesDelete, ActionCertificatesBackup, ActionCertificatesRestore, ActionCertificatesRecover,
		ActionCertificatesPurge},
	RoleKeyVaultPurgeOperator:               {ActionVaultPurge},
	RoleKeyVaultCertificateUser:             {ActionCertificatesRead},
	RoleKeyVaultCryptoServiceEncryptionUser: {ActionKeysRead, ActionKeysWrap, ActionKeysUnwrap},
	RoleKeyVaultDataAccessAdministrator:     {ActionRoleAssignmentsWrite, ActionRoleAssignmentsDelete},
}

// TestPreExistingRoles_DataActionsUnchanged is the regression gate: no role
// that existed before export gains any action, and only Administrator gains
// the two export actions.
func TestPreExistingRoles_DataActionsUnchanged(t *testing.T) {
	for role, want := range preExportBundles {
		assert.ElementsMatch(t, want, AzureRoleDataActions(role), "role %q changed", role)
		assert.False(t, RoleGrantsDataAction(role, ActionCertificatesExportItem), "role %q must not export certificates", role)
		assert.False(t, RoleGrantsDataAction(role, ActionKeysExport), "role %q must not export keys", role)
	}
	admin := AzureRoleDataActions(RoleKeyVaultAdministrator)
	assert.Len(t, admin, 36, "34 pre-existing actions plus the two export actions")
}
```

Create `internal/services/authorization/export_mapping_test.go`:

```go
package authorization

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"

	"rocketvault/model"
)

func TestMapRouteToDataAction_Export(t *testing.T) {
	cases := []struct {
		method, path string
		want         model.DataAction
	}{
		{http.MethodPost, "/api/v1/certificates/abc/export", model.ActionCertificatesExportItem},
		{http.MethodPost, "/api/v1/vaults/prod/certificates/abc/export", model.ActionCertificatesExportItem},
		{http.MethodPost, "/api/v1/keys/abc/export", model.ActionKeysExport},
		{http.MethodPost, "/api/v1/vaults/prod/keys/abc/export", model.ActionKeysExport},
		// Every other method on an export path fails closed.
		{http.MethodGet, "/api/v1/certificates/abc/export", ""},
		{http.MethodPut, "/api/v1/vaults/prod/keys/abc/export", ""},
		{http.MethodDelete, "/api/v1/keys/abc/export", ""},
	}
	for _, tc := range cases {
		action, kind := MapRouteToDataAction(tc.method, tc.path)
		assert.Equal(t, RouteVaultData, kind, "%s %s", tc.method, tc.path)
		assert.Equal(t, tc.want, action, "%s %s", tc.method, tc.path)
	}
}

// TestMapRouteToDataAction_ExportDoesNotShadowCollectionRoutes pins that the
// unbuilt bulk route POST /certificates/export stays unmapped (fail closed),
// and POST /keys/import keeps its own action.
func TestMapRouteToDataAction_ExportDoesNotShadowCollectionRoutes(t *testing.T) {
	// rest is "export", one segment, and the one-segment switch has no POST
	// arm, so the unbuilt bulk route stays unmapped and fails closed.
	action, kind := MapRouteToDataAction(http.MethodPost, "/api/v1/certificates/export")
	assert.Equal(t, RouteVaultData, kind)
	assert.Equal(t, model.DataAction(""), action)
	action, _ = MapRouteToDataAction(http.MethodPost, "/api/v1/keys/import")
	assert.Equal(t, model.ActionKeysImport, action)
}
```

Create `internal/services/authorization/export_grant_test.go`:

```go
package authorization

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"rocketvault/model"
)

func TestExporterRoles_OnlyGlobalAdminCanGrantOrRevoke(t *testing.T) {
	for _, role := range []string{model.RoleKeyVaultCertificateExporter, model.RoleKeyVaultKeyExporter} {
		rr, pr := newFakeRoleRepo(), newFakePolicyRepo()
		ul := &fakeUserLookup{users: map[string]model.User{"alice": {ID: uuid.New(), Username: "alice"}}}
		svc := newSvc(rr, pr, ul)
		vaultID := uuid.New()

		_, err := svc.AssignRole(context.Background(), AssignRoleInput{
			Principal: "alice", PrincipalType: model.PrincipalTypeUser, Role: role,
			VaultID: vaultID, CreatedBy: uuid.New(), CallerIsGlobalAdmin: false,
		})
		require.ErrorIs(t, err, ErrRoleNotGrantable, role)

		granted, err := svc.AssignRole(context.Background(), AssignRoleInput{
			Principal: "alice", PrincipalType: model.PrincipalTypeUser, Role: role,
			VaultID: vaultID, CreatedBy: uuid.New(), CallerIsGlobalAdmin: true,
		})
		require.NoError(t, err, role)

		err = svc.RevokeAssignment(context.Background(), granted.ID, vaultID, false)
		require.ErrorIs(t, err, ErrRoleNotGrantable, role)
		require.NoError(t, svc.RevokeAssignment(context.Background(), granted.ID, vaultID, true), role)
	}
}
```

Create `internal/middleware/export_policy_test.go`:

```go
package middleware

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"

	"rocketvault/model"
)

// TestResolvePolicy_ExportIsACreate pins the fail-closed legacy path: an
// explicit deny-create access policy also blocks export on both shapes.
func TestResolvePolicy_ExportIsACreate(t *testing.T) {
	for path, resource := range map[string]model.PolicyResourceType{
		"/api/v1/certificates/abc/export":             model.PolicyResourceCertificates,
		"/api/v1/vaults/prod/certificates/abc/export": model.PolicyResourceCertificates,
		"/api/v1/keys/abc/export":                     model.PolicyResourceKeys,
		"/api/v1/vaults/prod/keys/abc/export":         model.PolicyResourceKeys,
	} {
		gotResource, op := resolvePolicy(http.MethodPost, path)
		assert.Equal(t, resource, gotResource, path)
		assert.Equal(t, model.OpCreate, op, path)
	}
}
```

- [ ] **Step 2: Run and expect FAIL**

Run: `go test -p 2 ./model ./internal/services/authorization ./internal/middleware -run 'Export|PreExistingRoles' -v`
Expected: FAIL (build error: `ActionCertificatesExportItem`, `RoleKeyVaultCertificateExporter` undefined). `TestResolvePolicy_ExportIsACreate` already passes once the build succeeds; it pins today's behavior.

- [ ] **Step 3: Add the actions and roles**

In `model/azure_roles.go`, at the end of the key action block add:

```go
	// ActionKeysExport permits exporting one software-backed, exportable key
	// as unencrypted PKCS#8. RocketVault-only: Azure keys are non-extractable.
	// Granted by Key Vault Key Exporter and Administrator only.
	ActionKeysExport DataAction = "Microsoft.KeyVault/vaults/keys/export/action"
```

At the end of the certificate action block add:

```go
	// ActionCertificatesExportItem permits exporting one exportable
	// certificate with its private key, as PEM or PKCS12. RocketVault-only.
	// Named so it cannot collide with the unbuilt bulk export. Granted by Key
	// Vault Certificate Exporter and Administrator only.
	ActionCertificatesExportItem DataAction = "Microsoft.KeyVault/vaults/certificates/export/action"
```

At the end of the role-name const block add:

```go
	// RoleKeyVaultCertificateExporter grants per-certificate export of
	// exportable certificates only. Only a global admin can grant it.
	RoleKeyVaultCertificateExporter = "Key Vault Certificate Exporter"
	// RoleKeyVaultKeyExporter grants per-key export of exportable software
	// keys only. Only a global admin can grant it.
	RoleKeyVaultKeyExporter = "Key Vault Key Exporter"
```

In the Administrator bundle, append after `ActionCertificatesRecover, ActionCertificatesPurge,`:

```go
		ActionCertificatesExportItem, ActionKeysExport,
```

After the `RoleKeyVaultDataAccessAdministrator` entry add:

```go
	RoleKeyVaultCertificateExporter: {
		ActionCertificatesExportItem,
	},
	RoleKeyVaultKeyExporter: {
		ActionKeysExport,
	},
```

Change the two comments `the eleven built-in role names` and `one of the eleven built-in roles` to `thirteen`.

- [ ] **Step 4: Map the routes**

In `internal/services/authorization/data_actions.go` `mapKeyAction`, inside `if method == http.MethodPost { switch seg[1] {`, add after `case "decrypt":`:

```go
			case "export":
				return model.ActionKeysExport, RouteVaultData
```

In `mapCertificateAction`, inside `if len(seg) == 2 { switch seg[1] {`, add after the `renew` case:

```go
		case "export":
			if method == http.MethodPost {
				return model.ActionCertificatesExportItem, RouteVaultData
			}
```

- [ ] **Step 5: Update the role-count comments and existing tests**

Change "eleven" to "thirteen" in the comments at `internal/services/authorization/roles.go:61`, `:93`, `:111`, `role_assignment_service.go:121`, `internal/db/role_backfill.go:46`, `internal/services/authorization/roles_test.go:113`, `role_assignment_service_test.go:134`, `:210`, `model/azure_roles_test.go:10`, `:27`. Do not touch `nonAdminGrantableRoles`.

In `model/azure_roles_test.go`:
- `TestAzureRoleNames`: the expected sorted list becomes the eleven names plus `"Key Vault Certificate Exporter"` (between `"Key Vault Administrator"` and `"Key Vault Certificate User"`) and `"Key Vault Key Exporter"` (between `"Key Vault Data Access Administrator"` and `"Key Vault Purge Operator"`).
- In the Administrator-superset test, add `RoleKeyVaultCertificateExporter` and `RoleKeyVaultKeyExporter` to nothing (they are covered by Administrator), and change `assert.Len(t, admin, 34, "administrator must grant all 34 data actions")` to `assert.Len(t, admin, 36, "administrator must grant all 36 data actions")` and the comment's `34` to `36`.
- Rename `TestAzureRoleNames_IncludesAllElevenGrantableRoles` to `TestAzureRoleNames_IncludesAllThirteenGrantableRoles` and change `11` to `13` in both places.

In `internal/services/authorization/roles_test.go:165`, change `18` to `20` and the message to `(7 legacy + 13 Azure)`.

In `internal/services/authorization/authorization_matrix_test.go`:
- Append to `matrixOps` after the `certs.purge` row:

```go
	{"certs.export", http.MethodPost, "/api/v1/vaults/prod/certificates/abc/export"},
	{"keys.export", http.MethodPost, "/api/v1/vaults/prod/keys/abc/export"},
```

- Do not add either to `allCertOps` or `allKeyOps` (the officer roles must not gain them). Change the Administrator entry to:

```go
	model.RoleKeyVaultAdministrator: append(append(append(append([]string{},
		allSecretOps...), allKeyOps...), allCertOps...), "certs.export", "keys.export"),
```

- Add the two roles:

```go
	model.RoleKeyVaultCertificateExporter: {"certs.export"},
	model.RoleKeyVaultKeyExporter:         {"keys.export"},
```

- Change `require.Len(t, matrixAllowed, 11, "all eleven Azure roles must appear in the matrix")` to `require.Len(t, matrixAllowed, 13, "all thirteen Azure roles must appear in the matrix")`, `assert.Len(t, matrixOps, 51)` to `53`, and both `51`s in `TestAuthorizationMatrixNoRoleGrantsEverythingButAdministrator` to `53`.

- [ ] **Step 6: Run and expect PASS**

Run: `go test -p 2 ./model ./internal/services/authorization ./internal/middleware ./internal/db ./api -count=1`
Expected: PASS. `TestAuthorizationMatrixOpsAreRealRoutes` still passes: no export route is registered yet, and the mapping is pure.

- [ ] **Step 7: Commit**

Commit via the `dev-workflow-skills:1-git-commit` skill. Stage: `model/azure_roles.go`, `model/azure_roles_test.go`, `model/export_roles_test.go`, `internal/services/authorization/data_actions.go`, `internal/services/authorization/roles.go`, `internal/services/authorization/roles_test.go`, `internal/services/authorization/role_assignment_service.go`, `internal/services/authorization/role_assignment_service_test.go`, `internal/services/authorization/authorization_matrix_test.go`, `internal/services/authorization/export_mapping_test.go`, `internal/services/authorization/export_grant_test.go`, `internal/middleware/export_policy_test.go`, `internal/db/role_backfill.go`.

---

### Task 4: Key creation rules (HSM and oct refuse, rotation preserves)

**Files:**
- Modify: `internal/services/keys/key_service.go:51-66` (`CreateKeyRequest`), `:69-79` (`ImportKeyRequest`), `CreateRSAKey` (`:267-354`), `CreateECDSAKey` (`:361-445`), `CreateOctKey` (`:450-512`), `ImportKey` (`:517-620`), append `providerIsHSM` after `isPKCS11Handle` (`:1214`)
- Test: `internal/services/keys/key_exportable_test.go` (create)

**Interfaces:**
- Consumes: `model.ErrExportableNotSupported`, `isPKCS11Handle`, `crypto.PKCS11KeyProvider`, `mockKeyProviderForService` and `mockKeyRepository` (`key_service_extended_test.go`), `setupKeyTestMasterKey`.
- Produces: `keys.CreateKeyRequest.Exportable bool`, `keys.ImportKeyRequest.Exportable bool`; every create path stores `model.Key.Exportable`; `exportable: true` on an HSM or oct key returns an error wrapping `model.ErrExportableNotSupported`.

- [ ] **Step 1: Write the failing tests**

Create `internal/services/keys/key_exportable_test.go`:

```go
package keys

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/google/uuid"
	_ "github.com/mattn/go-sqlite3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"rocketvault/internal/crypto"
	rvdb "rocketvault/internal/db"
	"rocketvault/internal/repositories"
	"rocketvault/model"
)

func TestCreateKey_ExportableIsStored(t *testing.T) {
	setupKeyTestMasterKey()
	repo := &mockKeyRepository{}
	var stored *model.Key
	repo.On("Create", mock.Anything, mock.AnythingOfType("*model.Key")).
		Run(func(args mock.Arguments) { stored = args.Get(1).(*model.Key) }).Return(nil)
	svc := NewKeyService(KeyServiceConfig{KeyRepository: repo, KeyProvider: crypto.NewSoftwareKeyProvider(), Logger: newKeyLogger()})

	_, err := svc.CreateRSAKey(context.Background(), CreateKeyRequest{Name: "k", Type: "RSA", Bits: 2048, UserID: uuid.New(), Exportable: true})
	require.NoError(t, err)
	require.NotNil(t, stored)
	assert.True(t, stored.Exportable)

	_, err = svc.CreateECDSAKey(context.Background(), CreateKeyRequest{Name: "e", Type: "ECDSA", Curve: "P-256", UserID: uuid.New()})
	require.NoError(t, err)
	assert.False(t, stored.Exportable, "a create without the field stays non-exportable")
}

func TestCreateKey_ES256KMayBeCreatedExportable(t *testing.T) {
	setupKeyTestMasterKey()
	repo := &mockKeyRepository{}
	var stored *model.Key
	repo.On("Create", mock.Anything, mock.AnythingOfType("*model.Key")).
		Run(func(args mock.Arguments) { stored = args.Get(1).(*model.Key) }).Return(nil)
	svc := NewKeyService(KeyServiceConfig{KeyRepository: repo, KeyProvider: crypto.NewSoftwareKeyProvider(), Logger: newKeyLogger()})

	_, err := svc.CreateECDSAKey(context.Background(), CreateKeyRequest{Name: "k1", Type: "ECDSA", Curve: "P-256K", UserID: uuid.New(), Exportable: true})
	require.NoError(t, err)
	assert.True(t, stored.Exportable, "the refusal for ES256K happens at export, not at creation")
}

func TestCreateKey_HSMRejectsExportable(t *testing.T) {
	repo := &mockKeyRepository{}
	provider := &mockKeyProviderForService{}
	hsmHandle := uuid.NewString()
	provider.On("GenerateRSAKey", 2048).Return(hsmHandle, nil)
	provider.On("GenerateECDSAKey", "P-256").Return(hsmHandle, nil)
	svc := NewKeyService(KeyServiceConfig{KeyRepository: repo, KeyProvider: provider, Logger: newKeyLogger()})

	_, err := svc.CreateRSAKey(context.Background(), CreateKeyRequest{Name: "k", Type: "RSA", Bits: 2048, UserID: uuid.New(), Exportable: true})
	require.ErrorIs(t, err, model.ErrExportableNotSupported)
	_, err = svc.CreateECDSAKey(context.Background(), CreateKeyRequest{Name: "e", Type: "ECDSA", Curve: "P-256", UserID: uuid.New(), Exportable: true})
	require.ErrorIs(t, err, model.ErrExportableNotSupported)
	repo.AssertNotCalled(t, "Create", mock.Anything, mock.Anything)
}

func TestCreateOctKey_RejectsExportableBeforeTheProvider(t *testing.T) {
	provider := &mockKeyProviderForService{}
	svc := NewKeyService(KeyServiceConfig{KeyRepository: &mockKeyRepository{}, KeyProvider: provider, Logger: newKeyLogger()})

	_, err := svc.CreateOctKey(context.Background(), CreateKeyRequest{Name: "o", Type: "OCT", Bits: 256, UserID: uuid.New(), Exportable: true})
	require.ErrorIs(t, err, model.ErrExportableNotSupported)
	provider.AssertNotCalled(t, "GenerateAESKey", mock.Anything)
}

func TestImportKey_ExportableIsStoredAndHSMRejects(t *testing.T) {
	setupKeyTestMasterKey()
	jwk := `{"kty":"EC","crv":"P-256","x":"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU","y":"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0","d":"jpsQnnGQmL-YBIffH1136cspYG6-0iY7X1fCE9-E9LI"}`

	repo := &mockKeyRepository{}
	var stored *model.Key
	repo.On("Create", mock.Anything, mock.AnythingOfType("*model.Key")).
		Run(func(args mock.Arguments) { stored = args.Get(1).(*model.Key) }).Return(nil)
	svc := NewKeyService(KeyServiceConfig{KeyRepository: repo, KeyProvider: crypto.NewSoftwareKeyProvider(), Logger: newKeyLogger()})
	_, err := svc.ImportKey(context.Background(), ImportKeyRequest{Name: "imp", JWK: []byte(jwk), UserID: uuid.New(), Exportable: true})
	require.NoError(t, err)
	assert.True(t, stored.Exportable)

	provider := &mockKeyProviderForService{}
	provider.On("ImportKey", "ECDSA", mock.Anything).Return(uuid.NewString(), nil)
	hsmRepo := &mockKeyRepository{}
	hsm := NewKeyService(KeyServiceConfig{KeyRepository: hsmRepo, KeyProvider: provider, Logger: newKeyLogger()})
	_, err = hsm.ImportKey(context.Background(), ImportKeyRequest{Name: "imp", JWK: []byte(jwk), UserID: uuid.New(), Exportable: true})
	require.ErrorIs(t, err, model.ErrExportableNotSupported)
	hsmRepo.AssertNotCalled(t, "Create", mock.Anything, mock.Anything)
}

// TestRotateKey_PreservesExportable runs a real rotation over the real
// repository: rotation updates the same row, and the flag must survive it.
func TestRotateKey_PreservesExportable(t *testing.T) {
	setupKeyTestMasterKey()
	raw, err := sql.Open("sqlite3", "file:rotexp_"+uuid.NewString()+"?mode=memory&cache=shared")
	require.NoError(t, err)
	t.Cleanup(func() { raw.Close() }) //nolint:errcheck,gosec
	require.NoError(t, rvdb.NewRepository(newKeyLogger()).SetupSchema(raw, rvdb.SQLite))
	repo := repositories.NewKeyRepository(rvdb.NewConn(raw, rvdb.SQLite), newKeyLogger())
	svc := NewKeyService(KeyServiceConfig{KeyRepository: repo, KeyProvider: crypto.NewSoftwareKeyProvider(), Logger: newKeyLogger()})

	ctx := context.Background()
	vaultID, userID := uuid.New(), uuid.New()
	scope := model.NewVaultScope(vaultID, userID)
	created, err := svc.CreateRSAKey(ctx, CreateKeyRequest{Name: "rot", Type: "RSA", Bits: 2048, UserID: userID, VaultID: vaultID, Exportable: true})
	require.NoError(t, err)

	_, err = svc.RotateKey(ctx, created.KeyID, scope)
	require.NoError(t, err)

	got, err := svc.GetKey(ctx, created.KeyID, scope)
	require.NoError(t, err)
	assert.True(t, got.Exportable, "rotation keeps the flag")
	assert.WithinDuration(t, time.Now(), *got.UpdatedAt, time.Minute)
}
```

The JWK is the RFC 7517 Appendix A.2 P-256 example key.

- [ ] **Step 2: Run and expect FAIL**

Run: `go test -p 2 ./internal/services/keys -run 'Exportable|TestRotateKey_PreservesExportable' -v`
Expected: FAIL (build error: unknown field `Exportable` in `CreateKeyRequest`/`ImportKeyRequest`).

- [ ] **Step 3: Implement**

In `CreateKeyRequest` and `ImportKeyRequest` add, after `PurgeProtection`:

```go
	// Exportable requests an exportable key. It is set at creation only.
	// HSM-backed and oct keys refuse it with model.ErrExportableNotSupported.
	Exportable bool
```

After `isPKCS11Handle` add:

```go
// providerIsHSM reports whether keys from p live on a PKCS#11 token. It lets
// a create refuse exportable before anything is generated on the token.
func providerIsHSM(p crypto.KeyProvider) bool {
	_, ok := p.(*crypto.PKCS11KeyProvider)
	return ok
}

// refuseExportableHSM returns model.ErrExportableNotSupported when an
// exportable key was requested from an HSM provider, or when the handle the
// provider returned is a PKCS#11 label. The second check covers providers
// that only reveal their backend through the handle.
func (s *keyService) refuseExportableHSM(exportable bool, handle string, userID uuid.UUID, action string) error {
	if !exportable {
		return nil
	}
	if providerIsHSM(s.keyProvider) || (handle != "" && isPKCS11Handle(handle)) {
		s.logger.LogAuditError(userID.String(), action, "failed", "exportable requested for an HSM-backed key", nil)
		return fmt.Errorf("%w: the key would be HSM-backed", model.ErrExportableNotSupported)
	}
	return nil
}
```

In `CreateRSAKey`, after the bits validation and before `s.keyProvider.GenerateRSAKey`, add:

```go
	if err := s.refuseExportableHSM(req.Exportable, "", req.UserID, "create_rsa_key"); err != nil {
		return nil, err
	}
```

and directly after the `GenerateRSAKey` error check add:

```go
	if err := s.refuseExportableHSM(req.Exportable, handle, req.UserID, "create_rsa_key"); err != nil {
		return nil, err
	}
```

Do the same in `CreateECDSAKey` (action `"create_ecdsa_key"`) around `GenerateECDSAKey`, and in `ImportKey` (action `"import_key"`) before and after `s.keyProvider.ImportKey`. In `CreateOctKey`, after the bits validation and before `GenerateAESKey`, add:

```go
	// oct keys are HSM-only and never exportable.
	if req.Exportable {
		s.logger.LogAuditError(req.UserID.String(), "create_oct_key", "failed", "exportable requested for an oct key", nil)
		return nil, fmt.Errorf("%w: oct keys are HSM-only", model.ErrExportableNotSupported)
	}
```

In the `model.Key` literals of `CreateRSAKey`, `CreateECDSAKey` and `ImportKey` add `Exportable: req.Exportable,`. Leave `CreateOctKey`'s literal without it (always false). Leave `RotateKey` unchanged.

- [ ] **Step 4: Run and expect PASS**

Run: `go test -p 2 ./internal/services/keys -count=1`
Expected: PASS, including every pre-existing key-service test.

- [ ] **Step 5: Commit**

Commit via the `dev-workflow-skills:1-git-commit` skill. Stage: `internal/services/keys/key_service.go`, `internal/services/keys/key_exportable_test.go`.

---

### Task 5: Certificate creation rule (exportable needs an exportable key) and restore forcing false

**Files:**
- Modify: `internal/services/certificates/certificate_service.go:62-81` (`CreateCertificateRequest`), `:94-101` (`CreateCertificateResult`), `CreateSelfSignedCertificate` (`:268-390`), `CreateCASignedCertificate` (`:402-581`)
- Modify: `internal/backup/item_backup.go:301-309` (`RestoreKey`), `:418-433` (`RestoreCertificate`)
- Test: `internal/services/certificates/certificate_exportable_test.go` (create), `internal/backup/item_backup_exportable_test.go` (create)

**Interfaces:**
- Consumes: `newVersioningHarness` and its fields (`versioning_integration_test.go:36-77`), `model.ErrExportableKeyRequired`, `crypto.KeyAlgorithmFromCertificatePEM`, `encodeBlob`, `newStubKeyRepo`, `newStubCertRepo`, `newStubSecretRepo`.
- Produces:
  - `certificates.CreateCertificateRequest.Exportable bool`
  - `certificates.CreateCertificateResult.Exportable bool` and `.KeyAlgorithm string`
  - Creating an exportable certificate over a non-exportable key returns an error wrapping `model.ErrExportableKeyRequired` and writes nothing.
  - `RestoreKey` and `RestoreCertificate` always restore with `Exportable == false`.

- [ ] **Step 1: Write the failing tests**

Create `internal/services/certificates/certificate_exportable_test.go`:

```go
package certificates

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"rocketvault/common"
	"rocketvault/internal/crypto"
	"rocketvault/model"
)

// addKey stores an RSA key owned by the harness user with the given flag.
func addKey(t *testing.T, h *versioningHarness, exportable bool) uuid.UUID {
	t.Helper()
	keyPEM, err := crypto.GenerateRSAKeyPEM(2048)
	require.NoError(t, err)
	enc, err := common.EncryptSecret(keyPEM)
	require.NoError(t, err)
	id := uuid.New()
	require.NoError(t, h.keyRepo.Create(context.Background(), &model.Key{
		ID: id, UserID: h.userID, VaultID: h.vaultID, Name: "k-" + id.String()[:8],
		Type: model.KeyTypeRSA, Value: enc, Enabled: true, CreatedAt: time.Now(), Bits: 2048, Exportable: exportable,
	}))
	return id
}

func TestCreateCertificate_ExportableRequiresExportableKey(t *testing.T) {
	h := newVersioningHarness(t)
	ctx := context.Background()

	// h.keyID was created without the flag.
	_, err := h.svc.CreateSelfSignedCertificate(ctx, CreateCertificateRequest{
		Name: "refused", KeyID: h.keyID, ValidityDays: 30, UserID: h.userID, VaultID: h.vaultID, Exportable: true,
	})
	require.ErrorIs(t, err, model.ErrExportableKeyRequired)
	assert.Contains(t, err.Error(), "exportable")

	list, err := h.svc.ListCertificates(ctx, h.scope(), model.CertificateFilter{})
	require.NoError(t, err)
	assert.Empty(t, list, "a refused create writes nothing")

	exportableKey := addKey(t, h, true)
	res, err := h.svc.CreateSelfSignedCertificate(ctx, CreateCertificateRequest{
		Name: "allowed", KeyID: exportableKey, ValidityDays: 30, UserID: h.userID, VaultID: h.vaultID, Exportable: true,
	})
	require.NoError(t, err)
	assert.True(t, res.Exportable)
	assert.Equal(t, "RSA-2048", res.KeyAlgorithm)

	stored, err := h.certRepo.Read(ctx, res.CertID, h.scope())
	require.NoError(t, err)
	assert.True(t, stored.Exportable)
}

func TestCreateCertificate_NonExportableOverExportableKeyIsAllowed(t *testing.T) {
	h := newVersioningHarness(t)
	key := addKey(t, h, true)
	res, err := h.svc.CreateSelfSignedCertificate(context.Background(), CreateCertificateRequest{
		Name: "plain", KeyID: key, ValidityDays: 30, UserID: h.userID, VaultID: h.vaultID,
	})
	require.NoError(t, err)
	assert.False(t, res.Exportable, "a create without the field stays non-exportable")
}

func TestCreateCASignedCertificate_ExportableRequiresExportableKey(t *testing.T) {
	h := newVersioningHarness(t)
	ctx := context.Background()
	ca, err := h.svc.CreateSelfSignedCertificate(ctx, CreateCertificateRequest{
		Name: "ca", KeyID: h.keyID, ValidityDays: 365, UserID: h.userID, VaultID: h.vaultID, IsCA: true,
	})
	require.NoError(t, err)

	leafKey := addKey(t, h, false)
	_, err = h.svc.CreateCASignedCertificate(ctx, CreateCertificateRequest{
		Name: "leaf", KeyID: leafKey, CACertID: &ca.CertID, ValidityDays: 30, UserID: h.userID, VaultID: h.vaultID, Exportable: true,
	})
	require.ErrorIs(t, err, model.ErrExportableKeyRequired)

	exportableLeafKey := addKey(t, h, true)
	res, err := h.svc.CreateCASignedCertificate(ctx, CreateCertificateRequest{
		Name: "leaf2", KeyID: exportableLeafKey, CACertID: &ca.CertID, ValidityDays: 30, UserID: h.userID, VaultID: h.vaultID, Exportable: true,
	})
	require.NoError(t, err)
	assert.True(t, res.Exportable)
}

func TestRenewCertificate_PreservesExportable(t *testing.T) {
	h := newVersioningHarness(t)
	ctx := context.Background()
	key := addKey(t, h, true)
	res, err := h.svc.CreateSelfSignedCertificate(ctx, CreateCertificateRequest{
		Name: "renewed", KeyID: key, ValidityDays: 30, UserID: h.userID, VaultID: h.vaultID, Exportable: true,
	})
	require.NoError(t, err)
	_, err = h.svc.RenewCertificate(ctx, res.CertID, h.scope(), 30)
	require.NoError(t, err)
	got, err := h.certRepo.Read(ctx, res.CertID, h.scope())
	require.NoError(t, err)
	assert.Equal(t, 2, got.Version)
	assert.True(t, got.Exportable, "renewal updates the same row and keeps the flag")
}
```

Create `internal/backup/item_backup_exportable_test.go`:

```go
package backup

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"rocketvault/model"
)

// TestRestore_ForcesExportableFalse pins that a blob claiming exportable,
// whether genuine or edited (the blob is unauthenticated base64 JSON), never
// restores an exportable item.
func TestRestore_ForcesExportableFalse(t *testing.T) {
	ctx := context.Background()
	keys := newStubKeyRepo()
	certs := newStubCertRepo()
	svc := NewItemBackupService(newStubSecretRepo(), keys, certs, nil)
	userID, vaultID := uuid.New(), uuid.New()

	keyBlob, err := encodeBlob("key", uuid.NewString(), &model.Key{
		Name: "k", Type: model.KeyTypeRSA, Value: "enc", Enabled: true, CreatedAt: time.Now(), Exportable: true,
	}, blobVersions{})
	require.NoError(t, err)
	newKeyID := uuid.New()
	require.NoError(t, svc.RestoreKey(ctx, keyBlob, userID, vaultID, newKeyID))
	assert.False(t, keys.keys[newKeyID].Exportable)

	certBlob, err := encodeBlob("certificate", uuid.NewString(), &model.Certificate{
		Name: "c", Certificate: "pem", PrivateKey: "enc", Enabled: true, CreatedAt: time.Now(), Version: 1, Exportable: true,
	}, blobVersions{})
	require.NoError(t, err)
	newCertID := uuid.New()
	require.NoError(t, svc.RestoreCertificate(ctx, certBlob, userID, vaultID, newCertID))
	assert.False(t, certs.certs[newCertID].Exportable)
}
```

- [ ] **Step 2: Run and expect FAIL**

Run: `go test -p 2 ./internal/services/certificates ./internal/backup -run 'Exportable|TestRestore_ForcesExportableFalse' -v`
Expected: FAIL (build error: unknown field `Exportable` in `CreateCertificateRequest`; `KeyAlgorithm` undefined on the result; the restore test fails with `Exportable` true).

- [ ] **Step 3: Implement the creation rule and result fields**

In `CreateCertificateRequest`, after `PurgeProtection`, add:

```go
	// Exportable requests an exportable certificate. It requires a key whose
	// own exportable flag is true, because the certificate keeps a copy of
	// that key; otherwise the create fails with model.ErrExportableKeyRequired.
	Exportable bool
```

In `CreateCertificateResult`, after `Version`, add:

```go
	Exportable   bool   // The immutable exportable flag the certificate was created with.
	KeyAlgorithm string // The leaf public key's algorithm, such as RSA-2048.
```

Add this helper after `resolveVaultID`:

```go
// requireExportableKey refuses an exportable certificate over a key whose
// exportable flag is false, so a certificate cannot carry out a key its
// creator marked non-exportable.
func (s *certificateService) requireExportableKey(req CreateCertificateRequest, key *model.Key, action string) error {
	if !req.Exportable || key.Exportable {
		return nil
	}
	s.logger.LogAuditError(req.UserID.String(), action, "failed", "exportable certificate requested over a non-exportable key", nil)
	return fmt.Errorf("%w: key %s has exportable=false", model.ErrExportableKeyRequired, req.KeyID)
}
```

In `CreateSelfSignedCertificate`, directly after the `s.keyRepo.Read` error check, add:

```go
	if err := s.requireExportableKey(req, key, "create_self_signed_cert"); err != nil {
		return nil, err
	}
```

In `CreateCASignedCertificate`, directly after its `s.keyRepo.Read` error check, add the same call with action `"create_ca_signed_cert"`.

In both `model.Certificate` literals add `Exportable: req.Exportable,`. In both returned `CreateCertificateResult` literals add:

```go
		Exportable:   cert.Exportable,
		KeyAlgorithm: crypto.KeyAlgorithmFromCertificatePEM(certPEM),
```

- [ ] **Step 4: Force the flag off on restore**

In `internal/backup/item_backup.go` `RestoreKey`, after `key.VaultID = vaultID` add:

```go
	// A restore never grants exportability: the blob is unauthenticated
	// base64 JSON, so its exportable value cannot be trusted.
	key.Exportable = false
```

In `RestoreCertificate`, after `cert.VaultID = vaultID` add:

```go
	// A restore never grants exportability; see RestoreKey.
	cert.Exportable = false
```

- [ ] **Step 5: Run and expect PASS**

Run: `go test -p 2 ./internal/services/certificates ./internal/backup -count=1`
Expected: PASS, including every pre-existing backup and certificate test.

- [ ] **Step 6: Commit**

Commit via the `dev-workflow-skills:1-git-commit` skill. Stage: `internal/services/certificates/certificate_service.go`, `internal/services/certificates/certificate_exportable_test.go`, `internal/backup/item_backup.go`, `internal/backup/item_backup_exportable_test.go`.

---

### Task 6: HTTP create bodies, `exportable` and `key_algorithm` on responses, error mapping, golden responses and OpenAPI schemas

**Files:**
- Modify: `api/certificates.go:39-53` (`CreateCertificateAPIRequest`), `:68-80` (`CertificateResponse`), `:126-140` (`certToDomainResponse`), `:143-247` (`createCertificate`)
- Modify: `api/keys_types.go:35-46` (`CreateKeyRequest`), `:50-59` (`ImportKeyRequest`), `:74-93` (`KeyResponse`)
- Modify: `api/keys.go:74-107` (`buildKeyResponse`), `:219-229` (`createKey` request build), `:332-342` (`importKey` request build)
- Modify: `api/errors_key.go:20-63` (`writeKeyError`)
- Modify: `docs/api-specification.yaml:6354` (`CreateKeyRequest`), `:6389` (`ImportKeyRequest`), `:6436` (`KeyResponse`), `:6822` (`CreateCertificateRequest`), `:6890` (`CertificateResponse`), `:6055-6066` (role enum)
- Test: `api/export_fields_test.go` (create)

**Interfaces:**
- Consumes: Tasks 1-5; `newCertCtx`, `certAdminClaims`, `mockCertService` (`api/certificates_test.go`), `newKeyCtx`/`mockKeyService` (`api/keys_crud_test.go`; read that file for the exact helper name before writing the key test and use it), `writeError`.
- Produces (plans 2 and 3 rely on these):
  - `api.CertificateResponse.Exportable bool` (`json:"exportable"`), `.KeyAlgorithm string` (`json:"key_algorithm"`)
  - `api.KeyResponse.Exportable bool` (`json:"exportable"`), `.KeyAlgorithm string` (`json:"key_algorithm"`)
  - `CreateCertificateAPIRequest.Exportable`, `CreateKeyRequest.Exportable`, `ImportKeyRequest.Exportable` (all `bool`, `json:"exportable,omitempty"`)
  - `model.ErrExportableKeyRequired` maps to 409 on `POST /certificates`; `model.ErrExportableNotSupported` maps to 400 on `POST /keys` and `POST /keys/import`.

- [ ] **Step 1: Write the failing tests**

Create `api/export_fields_test.go`:

```go
package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sort"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"rocketvault/internal/crypto"
	certServices "rocketvault/internal/services/certificates"
	"rocketvault/model"
)

func jsonKeys(t *testing.T, v any) []string {
	t.Helper()
	body, err := json.Marshal(v)
	require.NoError(t, err)
	var m map[string]any
	require.NoError(t, json.Unmarshal(body, &m))
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// TestCertificateResponse_GoldenFields pins that the response only gained
// exportable and key_algorithm: every pre-existing field keeps its name.
func TestCertificateResponse_GoldenFields(t *testing.T) {
	keyPEM, err := crypto.GenerateECDSAKeyPEM("P-256")
	require.NoError(t, err)
	certPEM, err := crypto.CreateSelfSignedCertificatePEM(keyPEM, "ECDSA", crypto.CertificateTemplate{CommonName: "g", ValidityDays: 1})
	require.NoError(t, err)
	exp, nb := time.Now(), time.Now()
	resp := certToDomainResponse(&model.Certificate{ID: uuid.New(), Name: "g", Certificate: certPEM, PrivateKey: "enc",
		ExpiresAt: &exp, NotBefore: &nb, Enabled: true, Version: 1, Exportable: true})

	assert.Equal(t, []string{"auto_renew", "created_at", "enabled", "expires_at", "exportable", "id", "key_algorithm",
		"name", "not_before", "renewal_days", "tags", "user_id", "version"}, jsonKeys(t, resp))
	assert.True(t, resp.Exportable)
	assert.Equal(t, "EC-P256", resp.KeyAlgorithm)
}

func TestKeyResponse_GoldenFields(t *testing.T) {
	exp, nb, upd := time.Now(), time.Now(), time.Now()
	resp := buildKeyResponse(&model.Key{ID: uuid.New(), Name: "k", Type: model.KeyTypeRSA, Bits: 2048, Curve: "",
		ExpiresAt: &exp, NotBefore: &nb, UpdatedAt: &upd, Enabled: true, Exportable: true},
		&model.PublicJWK{N: "n", E: "e"})
	assert.Equal(t, []string{"bits", "created_at", "e", "enabled", "expires_at", "exportable", "id", "key_algorithm",
		"n", "name", "not_before", "revoked", "tags", "type", "updated_at", "user_id"}, jsonKeys(t, resp))
	assert.Equal(t, "RSA-2048", resp.KeyAlgorithm)
	assert.True(t, resp.Exportable)
}

func TestCreateCertificateHandler_PassesExportable(t *testing.T) {
	svc := &mockCertService{}
	svc.On("CreateSelfSignedCertificate", mock.Anything, mock.MatchedBy(func(r certServices.CreateCertificateRequest) bool {
		return r.Exportable
	})).Return(&certServices.CreateCertificateResult{CertID: uuid.New(), Name: "c", Version: 1, Exportable: true, KeyAlgorithm: "RSA-2048"}, nil)

	c := newCertCtx(svc, certAdminClaims())
	w := httptest.NewRecorder()
	body := fmt.Sprintf(`{"name":"c","key_id":"%s","validity_days":30,"exportable":true}`, uuid.New())
	createCertificate(c, w, httptest.NewRequest(http.MethodPost, "/certificates", bytes.NewBufferString(body)))
	require.Nil(t, c.Err)
	require.Equal(t, http.StatusCreated, w.Code)

	var resp CertificateResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.True(t, resp.Exportable)
	assert.Equal(t, "RSA-2048", resp.KeyAlgorithm)
	svc.AssertExpectations(t)
}

func TestCreateCertificateHandler_ExportableOverNonExportableKeyIs409(t *testing.T) {
	svc := &mockCertService{}
	svc.On("CreateSelfSignedCertificate", mock.Anything, mock.Anything).
		Return(nil, fmt.Errorf("%w: key x has exportable=false", model.ErrExportableKeyRequired))

	c := newCertCtx(svc, certAdminClaims())
	w := httptest.NewRecorder()
	body := fmt.Sprintf(`{"name":"c","key_id":"%s","validity_days":30,"exportable":true}`, uuid.New())
	createCertificate(c, w, httptest.NewRequest(http.MethodPost, "/certificates", bytes.NewBufferString(body)))
	require.NotNil(t, c.Err)
	writeError(w, c)
	assert.Equal(t, http.StatusConflict, w.Code)
	assert.Contains(t, w.Body.String(), "exportable")
}

func TestCreateCertificateHandler_OtherErrorsKeepTheir500(t *testing.T) {
	svc := &mockCertService{}
	svc.On("CreateSelfSignedCertificate", mock.Anything, mock.Anything).Return(nil, fmt.Errorf("boom"))
	c := newCertCtx(svc, certAdminClaims())
	w := httptest.NewRecorder()
	body := fmt.Sprintf(`{"name":"c","key_id":"%s","validity_days":30}`, uuid.New())
	createCertificate(c, w, httptest.NewRequest(http.MethodPost, "/certificates", bytes.NewBufferString(body)))
	require.NotNil(t, c.Err)
	assert.Equal(t, http.StatusInternalServerError, c.Err.StatusCode, "no existing status changes")
}

func TestWriteKeyError_ExportableNotSupportedIs400(t *testing.T) {
	c := &Context{}
	writeKeyError(c, fmt.Errorf("%w: the key would be HSM-backed", model.ErrExportableNotSupported))
	require.NotNil(t, c.Err)
	assert.Equal(t, http.StatusBadRequest, c.Err.StatusCode)
	assert.Contains(t, c.Err.Message, "exportable")
}
```

Append to the same file (add `keyServices "rocketvault/internal/services/keys"` to its imports; `newKeyCtx` and `mockKeyService` are the existing helpers in `api/keys_crud_test.go:51` and `:361`):

```go
func TestCreateAndImportKeyHandlers_PassExportable(t *testing.T) {
	keyID := uuid.New()
	stored := &model.Key{ID: keyID, Name: "k", Type: model.KeyTypeRSA, Bits: 2048, Enabled: true, Exportable: true}
	wantsExportable := func(exportable bool) bool { return exportable }

	for name, run := range map[string]func(svc *mockKeyService, c *Context, w *httptest.ResponseRecorder){
		"create": func(svc *mockKeyService, c *Context, w *httptest.ResponseRecorder) {
			svc.On("CreateRSAKey", mock.Anything, mock.MatchedBy(func(r keyServices.CreateKeyRequest) bool { return wantsExportable(r.Exportable) })).
				Return(&keyServices.CreateKeyResult{KeyID: keyID, Name: "k", Type: "RSA"}, nil)
			createKey(c, w, httptest.NewRequest(http.MethodPost, "/keys",
				bytes.NewBufferString(`{"name":"k","type":"RSA","bits":2048,"exportable":true}`)))
		},
		"import": func(svc *mockKeyService, c *Context, w *httptest.ResponseRecorder) {
			svc.On("ImportKey", mock.Anything, mock.MatchedBy(func(r keyServices.ImportKeyRequest) bool { return wantsExportable(r.Exportable) })).
				Return(&keyServices.CreateKeyResult{KeyID: keyID, Name: "k", Type: "RSA"}, nil)
			importKey(c, w, httptest.NewRequest(http.MethodPost, "/keys/import",
				bytes.NewBufferString(`{"name":"k","jwk":{"kty":"RSA"},"exportable":true}`)))
		},
	} {
		t.Run(name, func(t *testing.T) {
			svc := &mockKeyService{}
			svc.On("GetKey", mock.Anything, keyID, mock.Anything).Return(stored, nil)
			svc.On("GetPublicJWK", mock.Anything, keyID, 0, mock.Anything).Return(&model.PublicJWK{}, nil)
			c := newKeyCtx(svc)
			w := httptest.NewRecorder()
			run(svc, c, w)
			require.Nil(t, c.Err)
			require.Equal(t, http.StatusCreated, w.Code, w.Body.String())
			assert.Contains(t, w.Body.String(), `"exportable":true`)
			assert.Contains(t, w.Body.String(), `"key_algorithm":"RSA-2048"`)
			svc.AssertExpectations(t)
		})
	}
}
```

- [ ] **Step 2: Run and expect FAIL**

Run: `go test -p 2 ./api -run 'GoldenFields|Exportable|TestCreateCertificateHandler_|TestWriteKeyError_ExportableNotSupportedIs400' -v`
Expected: FAIL (build error: `Exportable`/`KeyAlgorithm` undefined on the API types).

- [ ] **Step 3: Implement the request and response fields**

In `CreateCertificateAPIRequest`, after `PurgeProtection`, add:

```go
	// Exportable requests an exportable certificate; immutable after creation.
	Exportable bool `json:"exportable,omitempty"`
```

In `CertificateResponse`, after `Version`, add:

```go
	Exportable   bool   `json:"exportable"`    // Whether the certificate can be exported. Immutable.
	KeyAlgorithm string `json:"key_algorithm"` // The leaf public key's algorithm, such as RSA-2048.
```

In `certToDomainResponse` add `Exportable: cert.Exportable,` and `KeyAlgorithm: crypto.KeyAlgorithmFromCertificatePEM(cert.Certificate),` (import `"rocketvault/internal/crypto"`). Parsing the PEM in memory adds no query per row.

In `createCertificate`, add `Exportable: req.Exportable,` to `createReq`, replace

```go
	if err != nil {
		c.SetInternalError(err)
		return
	}
```

(the one after the two create calls) with

```go
	if err != nil {
		if errors.Is(err, model.ErrExportableKeyRequired) {
			c.SetConflict("exportable: the key's exportable flag is false; an exportable certificate requires a key created with exportable: true")
			return
		}
		c.SetInternalError(err)
		return
	}
```

(import `"errors"`), and add to the `CertificateResponse` literal:

```go
		Exportable:   result.Exportable,
		KeyAlgorithm: result.KeyAlgorithm,
```

In `api/keys_types.go`, add to `CreateKeyRequest` and `ImportKeyRequest`:

```go
	// Exportable requests an exportable key; immutable after creation. HSM
	// and OCT keys refuse it with 400.
	Exportable bool `json:"exportable,omitempty"`
```

and to `KeyResponse`, after `Curve`:

```go
	Exportable   bool   `json:"exportable"`    // Whether the key can be exported. Immutable.
	KeyAlgorithm string `json:"key_algorithm"` // Algorithm and size, such as RSA-2048 or EC-P256.
```

In `buildKeyResponse` add `Exportable: key.Exportable,` and `KeyAlgorithm: key.KeyAlgorithm(),`. In `createKey`'s `createReq` and in `importKey`'s `keyservices.ImportKeyRequest` literal add `Exportable: req.Exportable,`.

In `writeKeyError`, add before the `default` case:

```go
	case errors.Is(err, model.ErrExportableNotSupported):
		c.SetInvalidParam("exportable: HSM-backed and OCT keys can never be exportable")
```

`UpdateCertificateAPIRequest` and `UpdateKeyRequest` get no field, so a `PUT` carrying `exportable` is ignored like any unknown field.

- [ ] **Step 4: Update the OpenAPI schemas**

In `docs/api-specification.yaml`:

- Under `CreateCertificateRequest.properties`, `CreateKeyRequest.properties` and `ImportKeyRequest.properties` add:

```yaml
        exportable:
          type: boolean
          default: false
          description: |
            Opt in to export. Set only at creation and never changed after.
            An exportable certificate requires a key created exportable (409
            otherwise); HSM-backed and OCT keys refuse it (400). Restoring a
            backup always yields a non-exportable item.
```

- Under `CertificateResponse.properties` and `KeyResponse.properties` add:

```yaml
        exportable:
          type: boolean
          description: Whether the item can be exported. Immutable.
        key_algorithm:
          type: string
          description: The key's algorithm and size, such as RSA-2048 or EC-P256.
          example: "RSA-2048"
```

- Append to the role `enum` after `"Key Vault Data Access Administrator"`:

```yaml
            - "Key Vault Certificate Exporter"
            - "Key Vault Key Exporter"
```

- [ ] **Step 5: Run and expect PASS**

Run: `go test -p 2 ./api -count=1`
Expected: PASS, including `TestOpenAPISpecCoversAllRoutes`, `TestGenerateRouteInventory`, `TestClientPathsAreRegistered` and every pre-existing handler test.

- [ ] **Step 6: Commit**

Commit via the `dev-workflow-skills:1-git-commit` skill. Stage: `api/certificates.go`, `api/keys.go`, `api/keys_types.go`, `api/errors_key.go`, `api/export_fields_test.go`, `docs/api-specification.yaml`.

---

### Task 7: CLI `--exportable` on `certificates create`, `keys create` and `keys import`

**Files:**
- Modify: `cmd/certificates/create.go:24-43` (Long), `:101-117` (request), `:144-156` (flags)
- Modify: `cmd/keys/create.go:40-54` (Long), `:103-116` (request), `:147-156` (flags)
- Modify: `cmd/keys/import.go:38-50` (Long), `:105-115` (request), `:121-130` (flags)
- Test: `cmd/certificates/create_exportable_test.go` (create), `cmd/keys/exportable_flag_test.go` (create)

**Interfaces:**
- Consumes: `newCertCmd`, `setFlags`, `newCertLogger`, `newCertFmtr`, `certCmdCertService`, `certsTestContainer` (`cmd/certificates/certs_cmd_test.go`); `newTestCmd`, `setFlags`, `newAllowedContainer`, `newLogger`, `newTestFmtr`, `keyCmdKeyService` (`cmd/keys/keys_cmd_test.go`); `testutils.NewTestContext`.
- Produces: `--exportable` boolean flag on the three commands, forwarded as `Exportable` on the service request. No extra authorization beyond the create itself.

- [ ] **Step 1: Write the failing tests**

Create `cmd/certificates/create_exportable_test.go`:

```go
package certificates

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"rocketvault/cmd/testutils"
	"rocketvault/common"
	certServices "rocketvault/internal/services/certificates"
	"rocketvault/model"
)

func TestCertCreateCmd_ExportableReachesTheService(t *testing.T) {
	tc := testutils.NewTestContext(t)
	certSvc := &certCmdCertService{}
	keyID := uuid.New()
	certSvc.On("CreateSelfSignedCertificate", mock.Anything, mock.MatchedBy(func(r certServices.CreateCertificateRequest) bool {
		return r.KeyID == keyID && r.Exportable
	})).Return(&certServices.CreateCertificateResult{CertID: uuid.New(), Name: "c", CreatedAt: time.Now()}, nil)

	sc := &certsTestContainer{MockServiceContainer: tc.MockContainer, certSvc: certSvc}
	claims := &model.Claims{UserID: tc.TestUserID, Username: "admin", Roles: []string{model.RoleAdmin}}
	ctx := context.WithValue(context.Background(), common.ClaimsKey, claims)
	ctx = context.WithValue(ctx, common.LogKey, newCertLogger())
	ctx = context.WithValue(ctx, common.ServiceContainerKey, sc)
	ctx = context.WithValue(ctx, common.OutputFormatterKey, newCertFmtr())

	cmd, _ := newCertCmd(createCmd.RunE, nil)
	cmd.Flags().Bool("auto-renew", false, "")
	cmd.Flags().Int("renewal-days", 30, "")
	setFlags(cmd, map[string]any{"name": "c", "key-id": keyID.String(), "validity-days": 365, "ca-cert-id": "", "exportable": true})
	cmd.SetContext(ctx)
	require.NoError(t, cmd.Execute())
	certSvc.AssertExpectations(t)
}

func TestCertCreateCmd_RegistersExportableFlag(t *testing.T) {
	f := createCmd.Flags().Lookup("exportable")
	require.NotNil(t, f)
	assert.Equal(t, "false", f.DefValue)
}
```

Create `cmd/keys/exportable_flag_test.go`:

```go
package keys

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"rocketvault/common"
	keyServices "rocketvault/internal/services/keys"
	"rocketvault/model"
)

func keyCmdCtx(sc any) context.Context {
	claims := &model.Claims{UserID: uuid.New(), Roles: []string{model.RoleAdmin}}
	ctx := context.WithValue(context.Background(), common.ClaimsKey, claims)
	ctx = context.WithValue(ctx, common.LogKey, newLogger())
	ctx = context.WithValue(ctx, common.ServiceContainerKey, sc)
	return context.WithValue(ctx, common.OutputFormatterKey, newTestFmtr())
}

func TestCreateCmd_ExportableReachesTheService(t *testing.T) {
	keySvc := &keyCmdKeyService{}
	sc, _ := newAllowedContainer(keySvc, nil)
	keySvc.On("CreateRSAKey", mock.Anything, mock.MatchedBy(func(r keyServices.CreateKeyRequest) bool { return r.Exportable })).
		Return(&keyServices.CreateKeyResult{KeyID: uuid.New(), Name: "k", Type: "RSA", CreatedAt: time.Now()}, nil)

	cmd, _ := newTestCmd(createCmd.RunE, nil)
	setFlags(cmd, map[string]any{"name": "k", "type": "RSA", "bits": 2048, "curve": "P-256", "tags": "", "exportable": true})
	cmd.SetContext(keyCmdCtx(sc))
	require.NoError(t, cmd.Execute())
	keySvc.AssertExpectations(t)
}

func TestImportCmd_ExportableReachesTheService(t *testing.T) {
	keySvc := &keyCmdKeyService{}
	sc, _ := newAllowedContainer(keySvc, nil)
	keySvc.On("ImportKey", mock.Anything, mock.MatchedBy(func(r keyServices.ImportKeyRequest) bool { return r.Exportable })).
		Return(&keyServices.CreateKeyResult{KeyID: uuid.New(), Name: "i", Type: "RSA", CreatedAt: time.Now()}, nil)

	cmd, _ := newTestCmd(importCmd.RunE, nil)
	setFlags(cmd, map[string]any{"name": "i", "jwk": `{"kty":"RSA"}`, "tags": "", "exportable": true})
	cmd.SetContext(keyCmdCtx(sc))
	require.NoError(t, cmd.Execute())
	keySvc.AssertExpectations(t)
}

func TestKeyCommands_RegisterExportableFlag(t *testing.T) {
	// The Init functions register flags on the shared command values; run
	// them once if no other test in this binary already has.
	if createCmd.Flags().Lookup("name") == nil {
		InitKeysCreate(&cobra.Command{})
	}
	if importCmd.Flags().Lookup("name") == nil {
		InitKeysImport(&cobra.Command{})
	}
	require.NotNil(t, createCmd.Flags().Lookup("exportable"))
	require.NotNil(t, importCmd.Flags().Lookup("exportable"))
	assert.Equal(t, "false", createCmd.Flags().Lookup("exportable").DefValue)
	assert.Equal(t, "false", importCmd.Flags().Lookup("exportable").DefValue)
}
```

Add `"github.com/spf13/cobra"` to this file's imports. Apply the same guard (`if createCmd.Flags().Lookup("name") == nil { InitCertificatesCreate(&cobra.Command{}) }`) at the top of `TestCertCreateCmd_RegistersExportableFlag` and import cobra there too.

- [ ] **Step 2: Run and expect FAIL**

Run: `go test -p 2 ./cmd/certificates ./cmd/keys -run 'Exportable' -v`
Expected: FAIL (the matchers see `Exportable == false`; the flag lookups return nil).

- [ ] **Step 3: Implement**

In `cmd/certificates/create.go`, read the flag with the others:

```go
		exportable, _ := cmd.Flags().GetBool("exportable")
```

add `Exportable: exportable,` to `req`, register the flag in `InitCertificatesCreate`:

```go
	createCmd.Flags().Bool("exportable", false, "Allow this certificate and its private key to be exported later; requires a key created with --exportable; cannot be changed after creation")
```

and append to `Long` before the closing backquote:

```
--exportable marks the certificate exportable. It can only be set here, never
later, and needs a key that was itself created with --exportable (otherwise
the create is refused). Exporting still requires the Key Vault Certificate
Exporter role.
```

In `cmd/keys/create.go` and `cmd/keys/import.go`, read `exportable, _ := cmd.Flags().GetBool("exportable")`, add `Exportable: exportable,` to the request, register:

```go
	createCmd.Flags().Bool("exportable", false, "Allow this key's private material to be exported later; refused for HSM-backed keys; cannot be changed after creation")
```

(and the same text on `importCmd`), and append to each `Long`:

```
--exportable marks the key exportable. It can only be set at creation or
import, never later, and an HSM-backed key refuses it. Exporting still
requires the Key Vault Key Exporter role.
```

- [ ] **Step 4: Run and expect PASS**

Run: `go test -p 2 ./cmd/... -count=1`
Expected: PASS, including every pre-existing CLI test (they never register `exportable`, so `GetBool` returns false and their requests are unchanged).

- [ ] **Step 5: Commit**

Commit via the `dev-workflow-skills:1-git-commit` skill. Stage: `cmd/certificates/create.go`, `cmd/certificates/create_exportable_test.go`, `cmd/keys/create.go`, `cmd/keys/import.go`, `cmd/keys/exportable_flag_test.go`.

---

### Task 8: Vault client and MCP create tools carry `exportable`

**Files:**
- Modify: `internal/vaultapi/certificates_write.go:18-30` (`CreateCertificateRequest`), `:34-45` (`createCertificateBody`), `:70-79` (body build)
- Modify: `internal/vaultapi/keys_write.go:17-26` (`CreateKeyRequest`)
- Modify: `internal/mcpserver/tools_certificates_write.go:12-22` (`createCertificateArgs`), `:120-129` (client call)
- Modify: `internal/mcpserver/tools_keys_write.go:12-19` (`createKeyArgs`), `:105-111` (client call)
- Test: `internal/vaultapi/exportable_write_test.go` (create), `internal/mcpserver/tools_exportable_test.go` (create)

**Interfaces:**
- Consumes: `certWriteServer`, `vaultWriteServer`, `newClientForTest`, `keysForCertBody`, `tlsCertID`, `rsaKeyID` (`internal/vaultapi` tests); `newFakeVault`, `writeConfig`, `callTool`, `structured`, `signKeyUUID`, `tlsCertUUID` (`internal/mcpserver` tests).
- Produces: `vaultapi.CreateCertificateRequest.Exportable bool`, `vaultapi.CreateKeyRequest.Exportable bool` (`json:"exportable,omitempty"`); MCP argument `exportable` on `create_certificate` and `create_key`.

- [ ] **Step 1: Write the failing tests**

Create `internal/vaultapi/exportable_write_test.go`:

```go
package vaultapi

import (
	"context"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCreateCertificate_SendsExportable(t *testing.T) {
	srv, probe := certWriteServer(t, keysForCertBody, http.StatusCreated, `{"id":"`+tlsCertID+`","name":"tls-cert"}`)
	c := newClientForTest(t, srv)
	_, err := c.CreateCertificate(context.Background(), "prod", CreateCertificateRequest{
		Name: "tls-cert", KeyName: "tls-key", ValidityDays: 30, Exportable: true,
	})
	require.NoError(t, err)
	require.Equal(t, true, probe.body["exportable"])
}

func TestCreateCertificate_OmitsExportableWhenFalse(t *testing.T) {
	srv, probe := certWriteServer(t, keysForCertBody, http.StatusCreated, `{"id":"`+tlsCertID+`","name":"tls-cert"}`)
	c := newClientForTest(t, srv)
	_, err := c.CreateCertificate(context.Background(), "prod", CreateCertificateRequest{Name: "tls-cert", KeyName: "tls-key", ValidityDays: 30})
	require.NoError(t, err)
	_, present := probe.body["exportable"]
	require.False(t, present, "an unset flag leaves the request body exactly as before")
}

func TestCreateKey_SendsExportable(t *testing.T) {
	srv, probe := vaultWriteServer(t, http.StatusCreated, `{"id":"`+rsaKeyID+`","name":"k","type":"RSA"}`)
	c := newClientForTest(t, srv)
	_, err := c.CreateKey(context.Background(), "prod", CreateKeyRequest{Name: "k", Type: "RSA", Bits: 2048, Exportable: true})
	require.NoError(t, err)
	require.Equal(t, true, probe.body["exportable"])
}
```

Create `internal/mcpserver/tools_exportable_test.go`:

```go
package mcpserver

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCreateCertificateTool_ForwardsExportable(t *testing.T) {
	f := newFakeVault(t, map[string]string{
		"/api/v1/vaults/default/keys": `{"keys":[{"id":"` + signKeyUUID + `","name":"tls-key"}]}`,
	})
	f.writeResponse = `{"id":"` + tlsCertUUID + `","name":"tls-cert"}`
	s := f.server(t, writeConfig())
	registerCertificatesWriteTools(s)

	var got createCertificateResult
	structured(t, callTool(t, s, "create_certificate", map[string]any{
		"name": "tls-cert", "key_name": "tls-key", "validity_days": 30, "exportable": true,
	}), &got)
	require.Equal(t, true, f.lastWriteBody["exportable"])
}

func TestCreateKeyTool_ForwardsExportable(t *testing.T) {
	f := newFakeVault(t, map[string]string{})
	f.writeResponse = `{"id":"` + signKeyUUID + `","name":"k","type":"RSA","bits":2048}`
	s := f.server(t, writeConfig())
	registerKeysWriteTools(s)

	var got createKeyResult
	structured(t, callTool(t, s, "create_key", map[string]any{
		"name": "k", "type": "RSA", "bits": 2048, "exportable": true,
	}), &got)
	require.Equal(t, true, f.lastWriteBody["exportable"])
}
```

- [ ] **Step 2: Run and expect FAIL**

Run: `go test -p 2 ./internal/vaultapi ./internal/mcpserver -run 'Exportable' -v`
Expected: FAIL (build error: unknown field `Exportable`; the MCP calls reject or drop the unknown argument).

- [ ] **Step 3: Implement**

In `internal/vaultapi/certificates_write.go`, add to `CreateCertificateRequest` after `NotBefore`:

```go
	// Exportable requests an exportable certificate. It needs a key created
	// exportable and can never be changed later.
	Exportable bool
```

to `createCertificateBody`:

```go
	Exportable   bool       `json:"exportable,omitempty"`
```

and `Exportable: req.Exportable,` to the `body` literal. In `internal/vaultapi/keys_write.go` `CreateKeyRequest` add:

```go
	// Exportable requests an exportable key. The server refuses it for HSM
	// and OCT keys, and it can never be changed later.
	Exportable bool `json:"exportable,omitempty"`
```

In `internal/mcpserver/tools_certificates_write.go` `createCertificateArgs`, add before `Vault`:

```go
	Exportable   bool     `json:"exportable,omitempty" jsonschema:"allow the certificate to be exported later; needs a key created exportable; cannot be changed after creation"`
```

and `Exportable: args.Exportable,` to the `vaultapi.CreateCertificateRequest` literal. In `tools_keys_write.go` `createKeyArgs` add before `Vault`:

```go
	Exportable bool     `json:"exportable,omitempty" jsonschema:"allow the key to be exported later; refused for HSM and OCT keys; cannot be changed after creation"`
```

and `Exportable: args.Exportable,` to the `vaultapi.CreateKeyRequest` literal. The tool results keep no field for material.

- [ ] **Step 4: Run and expect PASS**

Run: `go test -p 2 ./internal/vaultapi ./internal/mcpserver ./api -count=1`
Expected: PASS, including the MCP leak sweep and `TestClientPathsAreRegistered` (no new client path).

- [ ] **Step 5: Commit**

Commit via the `dev-workflow-skills:1-git-commit` skill. Stage: `internal/vaultapi/certificates_write.go`, `internal/vaultapi/keys_write.go`, `internal/vaultapi/exportable_write_test.go`, `internal/mcpserver/tools_certificates_write.go`, `internal/mcpserver/tools_keys_write.go`, `internal/mcpserver/tools_exportable_test.go`.

---

### Task 9: Plan 1 regression gate

**Files:**
- Test only: the whole module.

**Interfaces:**
- Consumes: Tasks 1-8.
- Produces: a green tree that plan 2 starts from.

- [ ] **Step 1: Build, vet and test**

Run: `go build ./... && go vet ./... && go test -p 2 ./... -count=1`
Expected: every package PASS. A failure in a pre-existing test is fixed in the code under change, never by weakening or deleting the test; the only permitted edits to existing tests are the role counts (Task 3) and the hand-written schema column (Task 2).

- [ ] **Step 2: Confirm no pre-existing behavior changed**

Run: `git diff --stat HEAD~8 -- '*_test.go' | tail -1` and read the diff of every modified pre-existing test file.
Expected: the only changes to pre-existing test files are the `exportable` schema line, the "eleven" to "thirteen" comments, the role-name list, and the matrix counts and rows.

- [ ] **Step 3: Commit**

Nothing to commit if Steps 1-2 needed no fix. If a fix was needed, commit it via the `dev-workflow-skills:1-git-commit` skill, staging only the fixed files.

---

## Self-Review

- **Spec coverage (plan 1's share):** §1 flag, columns, dual-write, `Update` never writes it (Tasks 1, 2); every creation surface (Tasks 6, 7, 8); rotation preserves it (Task 4); HSM/oct 400 and ES256K allowed at creation (Task 4); exportable-certificate-needs-exportable-key 409 naming the flag (Tasks 5, 6); versions share the flag, no column (Task 1); restore forces false (Task 5). §4 two actions, two roles, Administrator, no other role, "eleven" to thirteen, not non-admin grantable, route mapping, legacy deny-create (Task 3). §5 `exportable` and `key_algorithm` on both responses (Task 6). Testing: migration and repositories (Tasks 1, 2), authorization matrix and grants (Task 3), restore (Task 5), creation surfaces and rotation (Tasks 4, 7, 8). Regression safety: upgrade test (Task 2), golden responses (Task 6), role-matrix regression (Task 3), unchanged create paths (Tasks 4, 5, 6, 7), restore compatibility (Task 5), hard gates (Task 9).
- **Type consistency:** `Exportable bool` on `model.Certificate`, `model.Key`, both service requests, `CreateCertificateResult`, all API requests and responses, `vaultapi` requests and MCP args; `KeyAlgorithm string` on `CreateCertificateResult`, `CertificateResponse`, `KeyResponse`; `Key.KeyAlgorithm()`, `crypto.KeyAlgorithmFromCertificatePEM`, `crypto.KeyAlgorithmFromPublicKey`; `model.ErrExportableKeyRequired`, `model.ErrExportableNotSupported`; `model.ActionCertificatesExportItem`, `model.ActionKeysExport`, `model.RoleKeyVaultCertificateExporter`, `model.RoleKeyVaultKeyExporter`.
