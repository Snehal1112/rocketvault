# Certificate Versioning Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Give certificates an Azure-style numbered version history: every create and every renewal yields a version, the certificate id and name stay stable, and versions can be listed, read, updated (lifecycle attributes only), backed up, restored, purged and re-encrypted.

**Architecture:** The `certificates` row is always the current version (the secrets convention) and gains a `version` column; every earlier version lives in a new `certificate_versions` table owned by a new `CertificateVersionRepository`. `RenewCertificate` runs its existing guards, then archives the current version and bumps the parent in one repository transaction guarded by `WHERE version = ?`, so a lost race writes nothing and surfaces as `model.ErrCertificateVersionConflict` (HTTP 409). Version reads and writes are authorized only through a scoped read of the parent, because `certificate_versions` has no vault column.

**Tech Stack:** Go 1.24 (`go.mod`), `database/sql` over SQLite (`mattn/go-sqlite3`) and Postgres (`lib/pq`), Gorilla Mux, Cobra, testify, mockery v2.53.6 (`.mockery.yaml`), the MCP go-sdk.

**Spec:** `docs/superpowers/specs/2026-10-01-certificate-versioning-design.md` (intent: `docs/superpowers/intents/2026-10-01-certificate-versioning.md`).

## Global Constraints

- Every schema change is dual-written: `createOptimizedSchema` and `migrateSchema` in `internal/db/db.go`; duplicate-column errors are ignored as for the existing ALTERs.
- Existing rows become version 1 with no archived rows. Nothing is backfilled.
- Versions are sequential integers starting at 1 (documented parity divergence from Azure's 32-hex ids). There is no delete-version route.
- SQLite runs with `foreign_keys` off, so purge, vault purge and delete-with-tags delete `certificate_versions` rows explicitly. Soft-delete and recover leave versions alone.
- Renewal archives and bumps in one transaction, after the existing guards (CA-signing check, preserved `ca_cert_id`, B37). A guard failure writes no version. A lost race is a 409.
- Metadata-only responses: no PEM and no private key in any certificate or certificate-version response. `model.CertificateVersion` has no material field and none may be added.
- Every new route is registered on both the flat and the vault-scoped routers through `registerCertificateRoutes`.
- `docs/api-specification.yaml` and `docs/api-routes.generated.txt` cover both route shapes; `TestOpenAPISpecCoversAllRoutes` and `TestGenerateRouteInventory` pass.
- No new data actions or roles. Unmapped certificate paths still fail closed.
- `certificate_versions` is in `internal/backup/table_order.go` and `internal/rekey/targets.go` (`private_key`, key columns `certificate_id`, `version`).
- Commits go through the `dev-workflow-skills:1-git-commit` plugin skill (Skill tool), never a freeform `git commit -m`. Commits and tags are GPG signed (key 61D246B30285ED35).
- Code comments are short full sentences ending with a punctuation mark.
- Before any PR: `go build ./...`, `go vet ./...` and `go test ./...` pass, and the linter is clean (golangci-lint fails locally on the snap Go toolchain, so run it in CI or on a fixed toolchain).
- CLI commands bypass HTTP middleware, so every behavior is tested on the HTTP path and on the service or command the CLI calls.
- Merge notes: `docs/superpowers/plans/2026-09-30-secrets-and-error-responses.md` also adds `Context.SetConflict` with the same signature (Task 8 adds it only if absent), and `docs/superpowers/plans/2026-09-30-certificate-restore-renewal-isolation.md` also edits `RestoreCertificate`, `encodeBlob`/`decodeBlob` (sealed blobs) and the scheduler's `RenewCertificate` call. Whichever lands second merges additively; never replace the other plan's lines wholesale.

## Review Focus

These are the failure modes the spec implies but its test list does not exercise. Each has a pinning test in the owning task.

1. **A stale `UpdateCertificate` clobbering a renewal.** `CertificateRepository.Update` currently rewrites `certificate`, `private_key`, `created_at` and `expires_at` from a read taken before the write. After versioning, a PUT that read version N and wrote after a renewal committed N+1 would put the old body under the new version number. Task 2 narrows `Update` to metadata. Pin: `TestCertificateUpdate_NeverRewritesRenewedMaterial` (Task 2).
2. **Version routes reaching a certificate outside the caller's vault, or a soft-deleted one.** `certificate_versions` has no `vault_id`, so the parent's scoped read is the only gate. Pin: `TestCertificateVersions_OutOfScopeOrDeletedParentIsNotFound` (Task 4).
3. **A current-version lifecycle update racing a renewal.** `PUT .../versions/{n}` for the current `n` must not land on version `n+1` if a renewal commits in between. Pin: `TestUpdateCurrentLifecycle_StaleVersionConflicts` (Task 2).
4. **A forged or corrupt backup blob with inconsistent version numbers** (an archived version equal to or above the parent's, a duplicate, or below 1). It must be refused as `ErrInvalidBlob` and write nothing. Pin: `TestRestoreCertificate_RejectsInconsistentVersionNumbers` (Task 6).
5. **History silently dropped by a backup when the version repository is not wired.** A certificate above version 1 must fail closed rather than produce a blob without its history. Pin: `TestBackupCertificate_HistoryWithoutVersionRepoFailsClosed` (Task 6).

---

## File Structure

| File | Responsibility |
|---|---|
| `model/certificate.go` (modify) | `Certificate.Version`, `CertificateVersion`, `CertificateVersionRecord`, `CertificateVersionAttributes`, helpers |
| `model/filters.go` (modify) | `ErrCertificateVersionNotFound`, `ErrCertificateVersionConflict`, `ErrInvalidCertificateVersionAttributes` |
| `internal/db/db.go` (modify) | `certificates.version`, `certificate_versions` table, both schema paths |
| `internal/backup/table_order.go` (modify) | FK ordering entry |
| `internal/repositories/certificate_repository.go` (modify) | `version` column in the canonical select, scan and insert; metadata-only `Update` |
| `internal/repositories/certificate_version_repository.go` (create) | archive-and-bump, list, get, lifecycle updates, records |
| `internal/repositories/certificate_version_errors.go` (create) | sentinel aliases |
| `internal/repositories/item_lifecycle.go` (modify) | explicit version-row deletes |
| `internal/services/certificates/certificate_service.go` (modify) | transactional renewal, version methods |
| `internal/services/certificates/renewal_service.go` (modify) | `CurrentValidityDays` shared by scheduler and route |
| `internal/certcache/cache_integration.go` (modify) | pass-through and invalidation |
| `internal/services/retry/retry_certificate_service.go` (modify) | retry pass-through |
| `internal/services/certificates/mocks/mock_CertificateService.go` (regenerate) | mockery |
| `internal/container/service_container.go` (modify) | wiring |
| `internal/backup/item_backup.go` (modify) | versions in the blob, replay on restore |
| `internal/rekey/targets.go` (modify) | re-encrypt archived keys |
| `internal/services/authorization/data_actions.go` (modify) | route to action mapping |
| `api/context.go` (modify) | `SetConflict` |
| `api/errors_certificate.go` (modify) | version error mapping, renew mapping |
| `api/certificates.go` (modify) | routes, `version` in responses |
| `api/certificates_versions.go` (create) | four handlers |
| `internal/vaultapi/certificates.go`, `certificates_write.go` (modify) | client calls |
| `internal/mcpserver/tools_certificates.go`, `tools_certificates_write.go` (modify) | versions in `get_certificate`, `renew_certificate` tool |
| `cmd/certificates/versions.go` (create), `renew.go`, `columns.go`, `cmd/certificates.go` (modify) | CLI |
| `docs/…`, `.claude/…`, `CLAUDE.md` | documentation |

---

### Task 1: Model types, sentinels and schema migration

**Files:**
- Modify: `model/certificate.go:3-9` (imports), `:12-34` (`Certificate` struct), append after `IsAccessible` (`:58-70`)
- Modify: `model/filters.go` (append after `ErrKeyVersionNotFound`, `:72`)
- Modify: `internal/db/db.go:455-474` (`certificates` in `createOptimizedSchema`), after `:485` (`certificate_tags` index), after `:812` (`ca_cert_id` ALTER in `migrateSchema`)
- Modify: `internal/backup/table_order.go:40`
- Test: `model/certificate_version_test.go` (create), `internal/db/certificate_versions_migration_test.go` (create)

**Interfaces:**
- Consumes: `cloneTimePtr` (`model/`), `isDuplicateColumnError` (`internal/db/db.go:1297`).
- Produces:
  - `Certificate.Version int` (`json:"version"`)
  - `func (c *Certificate) CurrentVersion() int`
  - `func (c *Certificate) VersionMetadata() CertificateVersion`
  - `func (c *Certificate) ArchiveRecord() CertificateVersionRecord`
  - `func (c *Certificate) VersionUsable(v CertificateVersion) bool`
  - `type CertificateVersion struct { CertificateID uuid.UUID; Version int; Current bool; CreatedAt time.Time; ExpiresAt, NotBefore *time.Time; Enabled bool }` and `func (v CertificateVersion) IsAccessible() bool`
  - `type CertificateVersionRecord struct { CertificateID uuid.UUID; Version int; Certificate, PrivateKey string; KeyID uuid.UUID; CreatedAt time.Time; ExpiresAt, NotBefore *time.Time; Enabled bool }` and `func (r CertificateVersionRecord) Metadata() CertificateVersion`
  - `type CertificateVersionAttributes struct { Enabled bool; ExpiresAt, NotBefore *time.Time }`
  - `func ValidateCertificateVersionWindow(notBefore, expiresAt *time.Time) error`
  - `model.ErrCertificateVersionNotFound`, `model.ErrCertificateVersionConflict`, `model.ErrInvalidCertificateVersionAttributes`
  - Table `certificate_versions(certificate_id, version, certificate, private_key, key_id, created_at, expires_at, not_before, enabled)`, PK `(certificate_id, version)`, FK to `certificates(id)`.

- [ ] **Step 1: Write the failing model test**

Create `model/certificate_version_test.go`:

```go
package model_test

import (
	"encoding/json"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"rocketvault/model"
)

func TestCertificate_CurrentVersionDefaultsToOne(t *testing.T) {
	assert.Equal(t, 1, (&model.Certificate{}).CurrentVersion(), "a row that predates versioning is version 1")
	assert.Equal(t, 4, (&model.Certificate{Version: 4}).CurrentVersion())
}

func TestCertificate_ArchiveRecordSnapshotsMaterialAndLifecycle(t *testing.T) {
	expires := time.Now().Add(time.Hour)
	notBefore := time.Now().Add(-time.Hour)
	cert := &model.Certificate{
		ID: uuid.New(), KeyID: uuid.New(), Certificate: "PEM", PrivateKey: "ENC",
		CreatedAt: time.Now(), ExpiresAt: &expires, NotBefore: &notBefore, Enabled: true, Version: 3,
	}

	rec := cert.ArchiveRecord()
	assert.Equal(t, cert.ID, rec.CertificateID)
	assert.Equal(t, 3, rec.Version)
	assert.Equal(t, "PEM", rec.Certificate)
	assert.Equal(t, "ENC", rec.PrivateKey)
	assert.Equal(t, cert.KeyID, rec.KeyID)
	assert.True(t, rec.Enabled)

	// The snapshot must not share time pointers with the live row.
	*cert.ExpiresAt = expires.Add(time.Hour)
	assert.Equal(t, expires, *rec.ExpiresAt)

	meta := rec.Metadata()
	assert.False(t, meta.Current)
	assert.Equal(t, 3, meta.Version)
}

func TestCertificate_VersionMetadataIsCurrent(t *testing.T) {
	cert := &model.Certificate{ID: uuid.New(), Enabled: true, Version: 2}
	meta := cert.VersionMetadata()
	assert.True(t, meta.Current)
	assert.Equal(t, 2, meta.Version)
	assert.Equal(t, cert.ID, meta.CertificateID)
}

// TestCertificateVersion_HasNoMaterialFields pins the rule that the metadata
// type can never carry a PEM or a key, because handlers encode it directly.
func TestCertificateVersion_HasNoMaterialFields(t *testing.T) {
	typ := reflect.TypeOf(model.CertificateVersion{})
	for i := 0; i < typ.NumField(); i++ {
		assert.NotContains(t, []string{"Certificate", "PrivateKey", "PEM", "Value"}, typ.Field(i).Name)
	}
	body, err := json.Marshal(model.CertificateVersion{Version: 1, Enabled: true})
	require.NoError(t, err)
	assert.NotContains(t, string(body), "private_key")
	assert.NotContains(t, string(body), `"certificate"`)
}

func TestValidateCertificateVersionWindow(t *testing.T) {
	early := time.Now()
	late := early.Add(time.Hour)

	assert.NoError(t, model.ValidateCertificateVersionWindow(nil, nil))
	assert.NoError(t, model.ValidateCertificateVersionWindow(&early, nil))
	assert.NoError(t, model.ValidateCertificateVersionWindow(nil, &late))
	assert.NoError(t, model.ValidateCertificateVersionWindow(&early, &late))

	err := model.ValidateCertificateVersionWindow(&late, &early)
	require.Error(t, err)
	assert.True(t, errors.Is(err, model.ErrInvalidCertificateVersionAttributes))
}

func TestCertificate_VersionUsable_DisabledParentGatesEveryVersion(t *testing.T) {
	v := model.CertificateVersion{Version: 1, Enabled: true}
	assert.True(t, (&model.Certificate{Enabled: true}).VersionUsable(v))
	assert.False(t, (&model.Certificate{Enabled: false}).VersionUsable(v))

	past := time.Now().Add(-time.Hour)
	expired := model.CertificateVersion{Version: 1, Enabled: true, ExpiresAt: &past}
	assert.False(t, (&model.Certificate{Enabled: true}).VersionUsable(expired))
}
```

- [ ] **Step 2: Run it and expect FAIL**

Run: `go test ./model -run 'TestCertificate_|TestCertificateVersion_|TestValidateCertificateVersionWindow' -v`
Expected: FAIL (build error: `CurrentVersion`, `CertificateVersion`, `ValidateCertificateVersionWindow` undefined).

- [ ] **Step 3: Implement the model**

In `model/certificate.go`, add `"fmt"` to the import block. In the `Certificate` struct, after the `NotBefore` field, add:

```go
	// Version is the number of the version this row holds. The row is
	// always the current version; earlier ones live in certificate_versions.
	// Zero is a row that predates versioning and reads as version 1, see
	// CurrentVersion.
	Version int `json:"version"`
```

After `IsAccessible` add:

```go
// CurrentVersion returns the version number the certificate row holds. A
// zero Version, from a caller or a backup blob that predates versioning, is
// version 1: every certificate has at least one version.
func (c *Certificate) CurrentVersion() int {
	if c.Version < 1 {
		return 1
	}
	return c.Version
}

// VersionMetadata returns the current version's metadata, read off the
// certificate row itself.
func (c *Certificate) VersionMetadata() CertificateVersion {
	return CertificateVersion{
		CertificateID: c.ID,
		Version:       c.CurrentVersion(),
		Current:       true,
		CreatedAt:     c.CreatedAt,
		ExpiresAt:     cloneTimePtr(c.ExpiresAt),
		NotBefore:     cloneTimePtr(c.NotBefore),
		Enabled:       c.Enabled,
	}
}

// ArchiveRecord snapshots the current version, material included, so a
// renewal can move it into certificate_versions under its own number.
func (c *Certificate) ArchiveRecord() CertificateVersionRecord {
	return CertificateVersionRecord{
		CertificateID: c.ID,
		Version:       c.CurrentVersion(),
		Certificate:   c.Certificate,
		PrivateKey:    c.PrivateKey,
		KeyID:         c.KeyID,
		CreatedAt:     c.CreatedAt,
		ExpiresAt:     cloneTimePtr(c.ExpiresAt),
		NotBefore:     cloneTimePtr(c.NotBefore),
		Enabled:       c.Enabled,
	}
}

// VersionUsable reports whether version v of this certificate may be used.
// A disabled certificate gates every one of its versions; otherwise the
// version's own lifecycle decides.
func (c *Certificate) VersionUsable(v CertificateVersion) bool {
	return c.Enabled && v.IsAccessible()
}

// CertificateVersion is one version of a certificate. It is metadata only:
// there is deliberately no PEM and no private key field here, and none may
// be added, because the versions handlers encode it straight onto the
// response. CertificateVersionRecord carries the material, for backup only.
type CertificateVersion struct {
	CertificateID uuid.UUID  `json:"certificate_id"`
	Version       int        `json:"version"`
	Current       bool       `json:"current"`
	CreatedAt     time.Time  `json:"created_at"`
	ExpiresAt     *time.Time `json:"expires_at,omitempty"`
	NotBefore     *time.Time `json:"not_before,omitempty"`
	Enabled       bool       `json:"enabled"`
}

// IsAccessible reports whether the version is enabled and inside its own
// validity window.
func (v CertificateVersion) IsAccessible() bool {
	if !v.Enabled {
		return false
	}
	now := time.Now()
	if v.NotBefore != nil && now.Before(*v.NotBefore) {
		return false
	}
	if v.ExpiresAt != nil && now.After(*v.ExpiresAt) {
		return false
	}
	return true
}

// CertificateVersionRecord carries one archived version's material for
// internal use: the repository and the backup service. It is never encoded
// into an API response. PrivateKey holds the same master-key-encrypted form
// the database stores, so a backup blob carrying records is key material.
type CertificateVersionRecord struct {
	CertificateID uuid.UUID  `json:"certificate_id"`
	Version       int        `json:"version"`
	Certificate   string     `json:"certificate"`
	PrivateKey    string     `json:"private_key"`
	KeyID         uuid.UUID  `json:"key_id"`
	CreatedAt     time.Time  `json:"created_at"`
	ExpiresAt     *time.Time `json:"expires_at,omitempty"`
	NotBefore     *time.Time `json:"not_before,omitempty"`
	Enabled       bool       `json:"enabled"`
}

// Metadata returns the metadata of this archived version.
func (r CertificateVersionRecord) Metadata() CertificateVersion {
	return CertificateVersion{
		CertificateID: r.CertificateID,
		Version:       r.Version,
		Current:       false,
		CreatedAt:     r.CreatedAt,
		ExpiresAt:     cloneTimePtr(r.ExpiresAt),
		NotBefore:     cloneTimePtr(r.NotBefore),
		Enabled:       r.Enabled,
	}
}

// CertificateVersionAttributes are the lifecycle attributes every version
// carries and PUT .../versions/{version} may change.
type CertificateVersionAttributes struct {
	Enabled   bool
	ExpiresAt *time.Time
	NotBefore *time.Time
}

// ValidateCertificateVersionWindow rejects a not_before that falls after
// expires_at. Either may be unset.
func ValidateCertificateVersionWindow(notBefore, expiresAt *time.Time) error {
	if notBefore != nil && expiresAt != nil && notBefore.After(*expiresAt) {
		return fmt.Errorf("%w: not_before %s is after expires_at %s", ErrInvalidCertificateVersionAttributes,
			notBefore.Format(time.RFC3339), expiresAt.Format(time.RFC3339))
	}
	return nil
}
```

In `model/filters.go`, after `ErrKeyVersionNotFound`, add:

```go
// ErrCertificateVersionNotFound is returned when a certificate has no
// version with the requested number, or the number is below 1.
var ErrCertificateVersionNotFound = errors.New("certificate version not found")

// ErrCertificateVersionConflict is returned when a renewal or a
// current-version update loses a race: the version it read is no longer the
// current one. The caller may re-read and retry.
var ErrCertificateVersionConflict = errors.New("certificate version changed concurrently")

// ErrInvalidCertificateVersionAttributes is returned when a version update
// carries no attribute, or sets not_before after expires_at.
var ErrInvalidCertificateVersionAttributes = errors.New("invalid certificate version attributes")
```

- [ ] **Step 4: Run the model test and expect PASS**

Run: `go test ./model -run 'TestCertificate_|TestCertificateVersion_|TestValidateCertificateVersionWindow' -v`
Expected: PASS.

- [ ] **Step 5: Write the failing migration tests**

Create `internal/db/certificate_versions_migration_test.go`:

```go
// Certificate versioning adds certificates.version and the
// certificate_versions table. These tests prove a fresh database gets both,
// an upgraded one gets both with every existing row reading as version 1 and
// nothing archived, and that a second migration run is a no-op.
package db

import (
	"database/sql"
	"testing"

	_ "github.com/mattn/go-sqlite3"
	"github.com/stretchr/testify/require"

	"rocketvault/internal/logging"
)

func TestSetupSchema_FreshDatabaseHasCertificateVersions(t *testing.T) {
	conn, err := sql.Open("sqlite3", ":memory:")
	require.NoError(t, err)
	conn.SetMaxOpenConns(1)
	defer conn.Close() //nolint:errcheck

	repo := NewRepository(&logging.Logger{Logger: newSilentLogrus()})
	require.NoError(t, repo.SetupSchema(conn, SQLite))

	_, err = conn.Exec(`INSERT INTO certificates (id, user_id, name, certificate, private_key)
		VALUES ('c1', 'u1', 'fresh', 'pem', 'key')`)
	require.NoError(t, err)

	var version int
	require.NoError(t, conn.QueryRow(`SELECT version FROM certificates WHERE id = 'c1'`).Scan(&version))
	require.Equal(t, 1, version, "a certificate created without a version is version 1")

	_, err = conn.Exec(`INSERT INTO certificate_versions (certificate_id, version, certificate, private_key, enabled)
		VALUES ('c1', 1, 'pem', 'key', TRUE)`)
	require.NoError(t, err)

	_, err = conn.Exec(`INSERT INTO certificate_versions (certificate_id, version, certificate, private_key, enabled)
		VALUES ('c1', 1, 'pem', 'key', TRUE)`)
	require.Error(t, err, "(certificate_id, version) is the primary key")
}

func TestMigrateSchema_ExistingCertificatesBecomeVersionOne(t *testing.T) {
	conn, err := sql.Open("sqlite3", ":memory:")
	require.NoError(t, err)
	conn.SetMaxOpenConns(1)
	defer conn.Close() //nolint:errcheck

	// Minimal pre-feature schema: the tables migrateSchema ALTERs, in shapes
	// that predate this column. Copied from the B37 migration test.
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
		INSERT INTO certificates (id, name) VALUES ('existing', 'issued-before-versioning');
	`)
	require.NoError(t, err)

	repo := &DBRepository{dialect: SQLite}
	repo.log = &logging.Logger{Logger: newSilentLogrus()}
	require.NoError(t, repo.migrateSchema(conn))

	var version int
	require.NoError(t, conn.QueryRow(`SELECT version FROM certificates WHERE id = 'existing'`).Scan(&version))
	require.Equal(t, 1, version, "an existing certificate becomes version 1")

	var archived int
	require.NoError(t, conn.QueryRow(`SELECT COUNT(*) FROM certificate_versions`).Scan(&archived))
	require.Zero(t, archived, "nothing is backfilled")

	// A second run must not error on the now-existing column and table.
	require.NoError(t, repo.migrateSchema(conn))
}
```

- [ ] **Step 6: Run them and expect FAIL**

Run: `go test ./internal/db -run 'CertificateVersions|BecomeVersionOne' -v`
Expected: FAIL (`no such column: version` / `no such table: certificate_versions`).

- [ ] **Step 7: Implement the schema**

In `createOptimizedSchema`'s `certificates` table, after `not_before TIMESTAMP NULL,` add `version INTEGER NOT NULL DEFAULT 1,` (before the `FOREIGN KEY` line). After `CREATE INDEX IF NOT EXISTS idx_certificate_tags_tag ON certificate_tags(tag);` add:

```sql
		CREATE TABLE IF NOT EXISTS certificate_versions (
			certificate_id TEXT NOT NULL,
			version        INTEGER NOT NULL,
			certificate    TEXT NOT NULL,
			private_key    TEXT NOT NULL,
			key_id         TEXT NULL,
			created_at     TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			expires_at     TIMESTAMP NULL,
			not_before     TIMESTAMP NULL,
			enabled        BOOLEAN NOT NULL DEFAULT TRUE,
			PRIMARY KEY (certificate_id, version),
			FOREIGN KEY (certificate_id) REFERENCES certificates(id) ON DELETE CASCADE
		);
		CREATE INDEX IF NOT EXISTS idx_certificate_versions_certificate_id ON certificate_versions(certificate_id);
```

In `migrateSchema`, immediately after `"ALTER TABLE certificates ADD COLUMN ca_cert_id TEXT NULL",` add:

```go
		// Certificate versioning: the certificates row is always the current
		// version, and every earlier one is archived in certificate_versions.
		// Existing rows become version 1; nothing is backfilled. The ON DELETE
		// CASCADE only fires on Postgres; SQLite deletes these rows explicitly
		// in item_lifecycle.go.
		"ALTER TABLE certificates ADD COLUMN version INTEGER NOT NULL DEFAULT 1",
		`CREATE TABLE IF NOT EXISTS certificate_versions (
			certificate_id TEXT NOT NULL,
			version        INTEGER NOT NULL,
			certificate    TEXT NOT NULL,
			private_key    TEXT NOT NULL,
			key_id         TEXT NULL,
			created_at     TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			expires_at     TIMESTAMP NULL,
			not_before     TIMESTAMP NULL,
			enabled        BOOLEAN NOT NULL DEFAULT TRUE,
			PRIMARY KEY (certificate_id, version),
			FOREIGN KEY (certificate_id) REFERENCES certificates(id) ON DELETE CASCADE
		)`,
		"CREATE INDEX IF NOT EXISTS idx_certificate_versions_certificate_id ON certificate_versions(certificate_id)",
```

- [ ] **Step 8: Run the migration tests and expect PASS, then the FK drift guard and expect FAIL**

Run: `go test ./internal/db -run 'CertificateVersions|BecomeVersionOne|TestMigrateSchema|TestUpgradePath' -v`
Expected: PASS.

Run: `go test ./internal/backup -run TestTableDependencies_MatchesLiveSchema -v`
Expected: FAIL with `table "certificate_versions" exists in the live schema but has no entry in tableDependencies`.

- [ ] **Step 9: Update the FK ordering map**

In `internal/backup/table_order.go`, after `"certificate_tags":          {"certificates"},` add:

```go
	"certificate_versions":      {"certificates"},
```

- [ ] **Step 10: Run and expect PASS**

Run: `go test ./internal/backup -run 'TestTableDependencies|TestTopological' -v && go test ./internal/db ./model`
Expected: PASS.

- [ ] **Step 11: Commit**

Commit via the `dev-workflow-skills:1-git-commit` skill. Stage: `model/certificate.go`, `model/filters.go`, `model/certificate_version_test.go`, `internal/db/db.go`, `internal/db/certificate_versions_migration_test.go`, `internal/backup/table_order.go`.

---

### Task 2: Certificate version repository and the certificate repository's version column

**Files:**
- Modify: `internal/repositories/certificate_repository.go:72` (`certificateColumns`), `:75-111` (`scanCertificateRow`), `:147-210` (`Update`), `:421-466` (`insertCertAndTags`)
- Create: `internal/repositories/certificate_version_repository.go`, `internal/repositories/certificate_version_errors.go`
- Modify tests (add the `version` column to hand-written schemas): `internal/repositories/certificate_ca_cert_id_test.go:32` and `:147-150` (`TestCertificateRepository_CACertID_SurvivesUpdate`), `certificate_listall_test.go:38`, `certificate_renewal_repo_test.go:32`, `repositories_test.go:96`, `certificate_lifecycle_test.go:31`, `certificate_key_id_test.go:35`, `certificate_soft_delete_test.go:40`, `certificate_scope_test.go:33`, `internal_coverage_test.go:121`, `api/vault_cross_denial_test.go:240` and `:335`
- Test: `internal/repositories/certificate_version_repository_test.go` (create)

**Interfaces:**
- Consumes: Task 1 model types and sentinels; `ScopedExec` (`scoped_crud.go:29`); `withMetrics` (`metrics.go:23`); `db.DB`, `db.DBTX`, `Dialect.IsConstraintErr`.
- Produces:
  - `type CertificateVersionRepositoryInterface interface` with
    - `ArchiveAndRenew(ctx context.Context, archived model.CertificateVersionRecord, renewed *model.Certificate, scope model.Scope) error`
    - `CreateVersion(ctx context.Context, rec *model.CertificateVersionRecord) error`
    - `ListVersions(ctx context.Context, certID uuid.UUID) ([]model.CertificateVersion, error)`
    - `GetVersion(ctx context.Context, certID uuid.UUID, version int) (*model.CertificateVersion, error)`
    - `ListVersionRecords(ctx context.Context, certID uuid.UUID) ([]model.CertificateVersionRecord, error)`
    - `UpdateVersionLifecycle(ctx context.Context, certID uuid.UUID, version int, attrs model.CertificateVersionAttributes) error`
    - `UpdateCurrentLifecycle(ctx context.Context, certID uuid.UUID, version int, attrs model.CertificateVersionAttributes, scope model.Scope) error`
  - `func NewCertificateVersionRepository(conn db.DB, log *logging.Logger) CertificateVersionRepositoryInterface`
  - `func (r *CertificateVersionRepository) CreateVersionTx(ctx context.Context, ex db.DBTX, rec *model.CertificateVersionRecord) error` (concrete type only, for restore)
  - `repositories.ErrCertificateVersionNotFound`, `repositories.ErrCertificateVersionConflict` (aliases of the model sentinels)
  - Behavior change: `CertificateRepository.Update` writes only `name`, `auto_renew`, `renewal_days`, `enabled`, `not_before` (and tags).

- [ ] **Step 1: Write the failing repository tests**

Create `internal/repositories/certificate_version_repository_test.go`:

```go
package repositories_test

import (
	"context"
	"database/sql"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	rvdb "rocketvault/internal/db"
	"rocketvault/internal/logging"
	"rocketvault/internal/repositories"
	"rocketvault/model"
)

// newCertVersionFixture builds both repositories over the real schema, so
// these tests exercise the same DDL production runs.
func newCertVersionFixture(t *testing.T) (repositories.CertificateRepositoryInterface, repositories.CertificateVersionRepositoryInterface, *sql.DB) {
	t.Helper()
	raw := newSharedCacheDB(t, "cert_versions_"+uuid.NewString())
	require.NoError(t, rvdb.NewRepository(logging.InitLogger()).SetupSchema(raw, rvdb.SQLite))
	conn := rvdb.NewConn(raw, rvdb.SQLite)
	log := logging.InitLogger()
	return repositories.NewCertificateRepository(conn, log), repositories.NewCertificateVersionRepository(conn, log), raw
}

// seedVersionedCert stores a version-1 certificate in vaultID.
func seedVersionedCert(t *testing.T, certs repositories.CertificateRepositoryInterface, vaultID uuid.UUID) *model.Certificate {
	t.Helper()
	expires := time.Now().Add(30 * 24 * time.Hour).UTC()
	caID := uuid.New()
	cert := &model.Certificate{
		ID: uuid.New(), UserID: uuid.New(), VaultID: vaultID, KeyID: uuid.New(), CACertID: &caID,
		Name: "versioned-" + uuid.NewString()[:8], Certificate: "PEM-v1", PrivateKey: "ENC-v1",
		CreatedAt: time.Now().UTC(), ExpiresAt: &expires, Enabled: true, RenewalDays: 30, Version: 1,
	}
	require.NoError(t, certs.Create(context.Background(), cert))
	return cert
}

// renewedFrom builds the row a renewal of cert would write.
func renewedFrom(cert *model.Certificate, body string) *model.Certificate {
	next := *cert
	next.Certificate = body
	next.PrivateKey = "ENC-" + body
	next.Version = cert.CurrentVersion() + 1
	next.CreatedAt = time.Now().UTC()
	expires := time.Now().Add(365 * 24 * time.Hour).UTC()
	next.ExpiresAt = &expires
	notBefore := time.Now().UTC()
	next.NotBefore = &notBefore
	next.Enabled = true
	return &next
}

func countCertVersions(t *testing.T, raw *sql.DB, certID uuid.UUID) int {
	t.Helper()
	var n int
	require.NoError(t, raw.QueryRow("SELECT COUNT(*) FROM certificate_versions WHERE certificate_id = ?", certID.String()).Scan(&n))
	return n
}

func TestCertificateRepository_ReadsVersionColumn(t *testing.T) {
	certs, _, _ := newCertVersionFixture(t)
	vaultID := uuid.New()
	cert := seedVersionedCert(t, certs, vaultID)

	got, err := certs.Read(context.Background(), cert.ID, model.NewVaultScope(vaultID, cert.UserID))
	require.NoError(t, err)
	assert.Equal(t, 1, got.Version)

	unversioned := *cert
	unversioned.ID = uuid.New()
	unversioned.Name = "zero-version"
	unversioned.Version = 0
	require.NoError(t, certs.Create(context.Background(), &unversioned))
	got, err = certs.Read(context.Background(), unversioned.ID, model.NewVaultScope(vaultID, cert.UserID))
	require.NoError(t, err)
	assert.Equal(t, 1, got.Version, "a zero Version is stored as version 1")
}

func TestArchiveAndRenew_ArchivesCurrentAndBumpsParent(t *testing.T) {
	certs, versions, raw := newCertVersionFixture(t)
	ctx := context.Background()
	vaultID := uuid.New()
	cert := seedVersionedCert(t, certs, vaultID)
	scope := model.NewVaultScope(vaultID, cert.UserID)

	require.NoError(t, versions.ArchiveAndRenew(ctx, cert.ArchiveRecord(), renewedFrom(cert, "PEM-v2"), scope))

	got, err := certs.Read(ctx, cert.ID, scope)
	require.NoError(t, err)
	assert.Equal(t, 2, got.Version)
	assert.Equal(t, "PEM-v2", got.Certificate)
	assert.Equal(t, "ENC-PEM-v2", got.PrivateKey)
	require.NotNil(t, got.CACertID, "renewal must leave ca_cert_id alone (B37)")
	assert.Equal(t, *cert.CACertID, *got.CACertID)

	records, err := versions.ListVersionRecords(ctx, cert.ID)
	require.NoError(t, err)
	require.Len(t, records, 1)
	assert.Equal(t, 1, records[0].Version)
	assert.Equal(t, "PEM-v1", records[0].Certificate)
	assert.Equal(t, "ENC-v1", records[0].PrivateKey)
	assert.Equal(t, cert.KeyID, records[0].KeyID)
	assert.Equal(t, 1, countCertVersions(t, raw, cert.ID))
}

func TestArchiveAndRenew_InsertFailureRollsBackParent(t *testing.T) {
	certs, versions, _ := newCertVersionFixture(t)
	ctx := context.Background()
	vaultID := uuid.New()
	cert := seedVersionedCert(t, certs, vaultID)
	scope := model.NewVaultScope(vaultID, cert.UserID)

	// A row already archived under the current number makes the insert half fail.
	pre := cert.ArchiveRecord()
	require.NoError(t, versions.CreateVersion(ctx, &pre))

	err := versions.ArchiveAndRenew(ctx, cert.ArchiveRecord(), renewedFrom(cert, "PEM-v2"), scope)
	require.Error(t, err)
	assert.True(t, errors.Is(err, repositories.ErrCertificateVersionConflict))

	got, err := certs.Read(ctx, cert.ID, scope)
	require.NoError(t, err)
	assert.Equal(t, 1, got.Version, "the parent must be untouched when the archive insert fails")
	assert.Equal(t, "PEM-v1", got.Certificate)
}

func TestArchiveAndRenew_UpdateFailureRollsBackArchive(t *testing.T) {
	certs, versions, raw := newCertVersionFixture(t)
	ctx := context.Background()
	vaultID := uuid.New()
	cert := seedVersionedCert(t, certs, vaultID)
	scope := model.NewVaultScope(vaultID, cert.UserID)

	// The insert half succeeds (no row at 5), the update half matches nothing
	// (the row is at 1, not 5), so the insert must be rolled back.
	archived := cert.ArchiveRecord()
	archived.Version = 5
	renewed := renewedFrom(cert, "PEM-v6")
	renewed.Version = 6

	err := versions.ArchiveAndRenew(ctx, archived, renewed, scope)
	require.Error(t, err)
	assert.True(t, errors.Is(err, repositories.ErrCertificateVersionConflict))
	assert.Zero(t, countCertVersions(t, raw, cert.ID), "the archive row must roll back with the failed update")
}

func TestArchiveAndRenew_ConcurrentRenewalsHaveOneWinner(t *testing.T) {
	certs, versions, raw := newCertVersionFixture(t)
	ctx := context.Background()
	vaultID := uuid.New()
	cert := seedVersionedCert(t, certs, vaultID)
	scope := model.NewVaultScope(vaultID, cert.UserID)

	// Both renewals read version 1 before either wrote.
	first := renewedFrom(cert, "PEM-first")
	second := renewedFrom(cert, "PEM-second")

	require.NoError(t, versions.ArchiveAndRenew(ctx, cert.ArchiveRecord(), first, scope))
	err := versions.ArchiveAndRenew(ctx, cert.ArchiveRecord(), second, scope)
	require.Error(t, err)
	assert.True(t, errors.Is(err, repositories.ErrCertificateVersionConflict))

	got, err := certs.Read(ctx, cert.ID, scope)
	require.NoError(t, err)
	assert.Equal(t, "PEM-first", got.Certificate)
	assert.Equal(t, 2, got.Version)
	assert.Equal(t, 1, countCertVersions(t, raw, cert.ID))
}

func TestArchiveAndRenew_RejectsNonSequentialVersion(t *testing.T) {
	certs, versions, _ := newCertVersionFixture(t)
	vaultID := uuid.New()
	cert := seedVersionedCert(t, certs, vaultID)
	renewed := renewedFrom(cert, "PEM-v3")
	renewed.Version = 3

	err := versions.ArchiveAndRenew(context.Background(), cert.ArchiveRecord(), renewed, model.NewVaultScope(vaultID, cert.UserID))
	require.Error(t, err)
}

func TestArchiveAndRenew_OutOfScopeWritesNothing(t *testing.T) {
	certs, versions, raw := newCertVersionFixture(t)
	ctx := context.Background()
	cert := seedVersionedCert(t, certs, uuid.New())

	err := versions.ArchiveAndRenew(ctx, cert.ArchiveRecord(), renewedFrom(cert, "PEM-v2"), model.NewVaultScope(uuid.New(), cert.UserID))
	require.Error(t, err)
	assert.Zero(t, countCertVersions(t, raw, cert.ID))
}

func TestCertificateVersions_ListGetAndUpdateArchived(t *testing.T) {
	certs, versions, _ := newCertVersionFixture(t)
	ctx := context.Background()
	vaultID := uuid.New()
	cert := seedVersionedCert(t, certs, vaultID)
	scope := model.NewVaultScope(vaultID, cert.UserID)

	v2 := renewedFrom(cert, "PEM-v2")
	require.NoError(t, versions.ArchiveAndRenew(ctx, cert.ArchiveRecord(), v2, scope))
	require.NoError(t, versions.ArchiveAndRenew(ctx, v2.ArchiveRecord(), renewedFrom(v2, "PEM-v3"), scope))

	list, err := versions.ListVersions(ctx, cert.ID)
	require.NoError(t, err)
	require.Len(t, list, 2)
	assert.Equal(t, []int{1, 2}, []int{list[0].Version, list[1].Version})
	assert.False(t, list[0].Current)

	one, err := versions.GetVersion(ctx, cert.ID, 1)
	require.NoError(t, err)
	assert.True(t, one.Enabled)

	for _, missing := range []int{0, 3, 9} {
		_, err := versions.GetVersion(ctx, cert.ID, missing)
		assert.True(t, errors.Is(err, repositories.ErrCertificateVersionNotFound), "version %d", missing)
	}

	require.NoError(t, versions.UpdateVersionLifecycle(ctx, cert.ID, 1, model.CertificateVersionAttributes{Enabled: false}))
	one, err = versions.GetVersion(ctx, cert.ID, 1)
	require.NoError(t, err)
	assert.False(t, one.Enabled)

	err = versions.UpdateVersionLifecycle(ctx, cert.ID, 9, model.CertificateVersionAttributes{Enabled: true})
	assert.True(t, errors.Is(err, repositories.ErrCertificateVersionNotFound))
}

func TestCreateVersion_DuplicateRejected(t *testing.T) {
	certs, versions, _ := newCertVersionFixture(t)
	cert := seedVersionedCert(t, certs, uuid.New())
	rec := cert.ArchiveRecord()

	require.NoError(t, versions.CreateVersion(context.Background(), &rec))
	err := versions.CreateVersion(context.Background(), &rec)
	assert.True(t, errors.Is(err, repositories.ErrCertificateVersionConflict))
}

func TestUpdateCurrentLifecycle_WritesParent(t *testing.T) {
	certs, versions, _ := newCertVersionFixture(t)
	ctx := context.Background()
	vaultID := uuid.New()
	cert := seedVersionedCert(t, certs, vaultID)
	scope := model.NewVaultScope(vaultID, cert.UserID)

	notBefore := time.Now().Add(-time.Hour).UTC()
	require.NoError(t, versions.UpdateCurrentLifecycle(ctx, cert.ID, 1,
		model.CertificateVersionAttributes{Enabled: false, ExpiresAt: cert.ExpiresAt, NotBefore: &notBefore}, scope))

	got, err := certs.Read(ctx, cert.ID, scope)
	require.NoError(t, err)
	assert.False(t, got.Enabled)
	require.NotNil(t, got.NotBefore)
	assert.WithinDuration(t, notBefore, *got.NotBefore, time.Second)
}

// TestUpdateCurrentLifecycle_StaleVersionConflicts pins Review Focus 3: a
// current-version update that read version 1 must not land on version 2
// after a renewal committed in between.
func TestUpdateCurrentLifecycle_StaleVersionConflicts(t *testing.T) {
	certs, versions, _ := newCertVersionFixture(t)
	ctx := context.Background()
	vaultID := uuid.New()
	cert := seedVersionedCert(t, certs, vaultID)
	scope := model.NewVaultScope(vaultID, cert.UserID)

	require.NoError(t, versions.ArchiveAndRenew(ctx, cert.ArchiveRecord(), renewedFrom(cert, "PEM-v2"), scope))

	err := versions.UpdateCurrentLifecycle(ctx, cert.ID, 1, model.CertificateVersionAttributes{Enabled: false}, scope)
	require.Error(t, err)
	assert.True(t, errors.Is(err, repositories.ErrCertificateVersionConflict))

	got, err := certs.Read(ctx, cert.ID, scope)
	require.NoError(t, err)
	assert.True(t, got.Enabled, "version 2 must be untouched by an update aimed at version 1")
}

// TestCertificateUpdate_NeverRewritesRenewedMaterial pins Review Focus 1: a
// metadata update built from a read taken before a renewal must not put the
// old body, key or expiry back over the new version.
func TestCertificateUpdate_NeverRewritesRenewedMaterial(t *testing.T) {
	certs, versions, _ := newCertVersionFixture(t)
	ctx := context.Background()
	vaultID := uuid.New()
	cert := seedVersionedCert(t, certs, vaultID)
	scope := model.NewVaultScope(vaultID, cert.UserID)

	stale, err := certs.Read(ctx, cert.ID, scope)
	require.NoError(t, err)

	renewed := renewedFrom(cert, "PEM-v2")
	require.NoError(t, versions.ArchiveAndRenew(ctx, cert.ArchiveRecord(), renewed, scope))

	stale.Name = "renamed-after-renewal"
	require.NoError(t, certs.Update(ctx, stale, scope))

	got, err := certs.Read(ctx, cert.ID, scope)
	require.NoError(t, err)
	assert.Equal(t, "renamed-after-renewal", got.Name)
	assert.Equal(t, "PEM-v2", got.Certificate)
	assert.Equal(t, "ENC-PEM-v2", got.PrivateKey)
	assert.Equal(t, 2, got.Version)
	require.NotNil(t, got.ExpiresAt)
	assert.WithinDuration(t, *renewed.ExpiresAt, *got.ExpiresAt, time.Second)
}
```

- [ ] **Step 2: Run and expect FAIL**

Run: `go test ./internal/repositories -run 'TestCertificateRepository_ReadsVersionColumn|TestArchiveAndRenew|TestCertificateVersions_|TestCreateVersion_|TestUpdateCurrentLifecycle|TestCertificateUpdate_NeverRewrites' -v`
Expected: FAIL (build error: `NewCertificateVersionRepository`, `ErrCertificateVersionConflict` undefined).

- [ ] **Step 3: Add the version column to the certificate repository**

In `internal/repositories/certificate_repository.go`:

Replace the `certificateColumns` value with:

```go
const certificateColumns = "id, user_id, vault_id, name, certificate, private_key, created_at, expires_at, auto_renew, renewal_days, key_id, ca_cert_id, enabled, not_before, deleted_at, purge_protection, version"
```

In `scanCertificateRow`, append `&cert.Version` as the last scan destination:

```go
	if err := scan(&idStr, &userIDStr, &vaultIDStr, &cert.Name, &cert.Certificate, &cert.PrivateKey,
		&cert.CreatedAt, &cert.ExpiresAt, &cert.AutoRenew, &cert.RenewalDays, &keyIDStr, &caCertIDStr,
		&cert.Enabled, &cert.NotBefore, &cert.DeletedAt, &cert.PurgeProtection, &cert.Version); err != nil {
		return cert, err
	}
```

In `insertCertAndTags`, replace the insert with:

```go
	// Insert certificate with pre-encrypted private key and renewal metadata.
	// version is the row's current version: 1 on create, the blob's own
	// number on restore.
	_, err := ex.ExecContext(
		ctx,
		"INSERT INTO certificates (id, user_id, vault_id, name, certificate, private_key, created_at, expires_at, auto_renew, renewal_days, key_id, ca_cert_id, enabled, not_before, version) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
		cert.ID.String(), cert.UserID.String(), cert.VaultID.String(), cert.Name, cert.Certificate, cert.PrivateKey, cert.CreatedAt,
		cert.ExpiresAt, cert.AutoRenew, cert.RenewalDays, cert.KeyID.String(), caCertID, cert.Enabled, cert.NotBefore, cert.CurrentVersion(),
	)
```

In `Update`, replace the comment above `query` and the `query`/`execArgs` pair with:

```go
		// Only metadata is written here. The body, the private key and the
		// issuance dates belong to a version, and only a renewal changes them,
		// through CertificateVersionRepository.ArchiveAndRenew under a version
		// guard. Writing them here from a read taken before a concurrent
		// renewal would put the old body back under the new version number.
		// ca_cert_id is deliberately absent too: the CA link is set at
		// creation and immutable afterwards (B37).
		query := "UPDATE certificates SET name = ?, auto_renew = ?, renewal_days = ?, enabled = ?, not_before = ? WHERE id = ?"
		execArgs := []any{
			cert.Name, cert.AutoRenew, cert.RenewalDays, cert.Enabled, cert.NotBefore, cert.ID.String(),
		}
```

- [ ] **Step 4: Create the sentinel aliases**

Create `internal/repositories/certificate_version_errors.go`:

```go
package repositories

import "rocketvault/model"

// ErrCertificateVersionNotFound and ErrCertificateVersionConflict alias the
// model sentinels, so api/ and cmd/ can check them without importing this
// package. Same pattern as ErrKeyVersionNotFound.
var (
	ErrCertificateVersionNotFound = model.ErrCertificateVersionNotFound
	ErrCertificateVersionConflict = model.ErrCertificateVersionConflict
)
```

- [ ] **Step 5: Create the version repository**

Create `internal/repositories/certificate_version_repository.go`:

```go
package repositories

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/google/uuid"

	"rocketvault/internal/db"
	"rocketvault/internal/logging"
	"rocketvault/model"
)

// CertificateVersionRepositoryInterface is the data access contract for
// archived certificate versions. The certificates row is always the current
// version; this repository owns the rows that hold every earlier one.
//
// Only ArchiveAndRenew and UpdateCurrentLifecycle take a scope, because they
// write the certificates row. Every other method performs no authorization:
// the caller MUST have authorized the parent certificate with a scoped read
// first. certificate_versions has no vault_id column, so its rows are
// reachable only through a parent the caller has proved access to. This is
// the same contract as KeyRepository.ReadVersionValue (B28).
type CertificateVersionRepositoryInterface interface {
	// ArchiveAndRenew inserts archived into certificate_versions and replaces
	// the certificates row with renewed, in one transaction. renewed.Version
	// must be archived.Version + 1, and the row must still be at
	// archived.Version; otherwise nothing is written and the error wraps
	// ErrCertificateVersionConflict.
	ArchiveAndRenew(ctx context.Context, archived model.CertificateVersionRecord, renewed *model.Certificate, scope model.Scope) error
	// CreateVersion inserts one archived version. Restore uses it.
	CreateVersion(ctx context.Context, rec *model.CertificateVersionRecord) error
	// ListVersions returns the archived versions' metadata, oldest first.
	ListVersions(ctx context.Context, certID uuid.UUID) ([]model.CertificateVersion, error)
	// GetVersion returns one archived version's metadata.
	GetVersion(ctx context.Context, certID uuid.UUID, version int) (*model.CertificateVersion, error)
	// ListVersionRecords returns the archived versions with their material,
	// oldest first. Internal use only: the backup service.
	ListVersionRecords(ctx context.Context, certID uuid.UUID) ([]model.CertificateVersionRecord, error)
	// UpdateVersionLifecycle sets one archived version's lifecycle attributes.
	UpdateVersionLifecycle(ctx context.Context, certID uuid.UUID, version int, attrs model.CertificateVersionAttributes) error
	// UpdateCurrentLifecycle sets the lifecycle attributes on the
	// certificates row, only while that row is still at version.
	UpdateCurrentLifecycle(ctx context.Context, certID uuid.UUID, version int, attrs model.CertificateVersionAttributes, scope model.Scope) error
}

// certificateVersionMetadataColumns is the SELECT list for metadata reads.
const certificateVersionMetadataColumns = "version, created_at, expires_at, not_before, enabled"

// certificateVersionRecordColumns is the SELECT list for material reads.
const certificateVersionRecordColumns = "version, certificate, private_key, key_id, created_at, expires_at, not_before, enabled"

// CertificateVersionRepository implements CertificateVersionRepositoryInterface.
type CertificateVersionRepository struct {
	db  db.DB
	log *logging.Logger
}

var _ CertificateVersionRepositoryInterface = (*CertificateVersionRepository)(nil)

// NewCertificateVersionRepository creates a CertificateVersionRepository.
func NewCertificateVersionRepository(conn db.DB, log *logging.Logger) CertificateVersionRepositoryInterface {
	return &CertificateVersionRepository{db: conn, log: log}
}

func (r *CertificateVersionRepository) executeWithMetrics(operation string, fn func() error) error {
	return withMetrics("certificate_versions", operation, fn)
}

// ArchiveAndRenew archives the current version and moves the certificates
// row to the renewed one, in a single transaction.
func (r *CertificateVersionRepository) ArchiveAndRenew(ctx context.Context, archived model.CertificateVersionRecord, renewed *model.Certificate, scope model.Scope) error {
	if renewed.Version != archived.Version+1 {
		return fmt.Errorf("renewed version %d must directly follow archived version %d", renewed.Version, archived.Version)
	}
	return r.executeWithMetrics("archive_and_renew", func() error {
		tx, err := r.db.BeginTx(ctx, nil)
		if err != nil {
			return fmt.Errorf("failed to begin transaction: %w", err)
		}
		defer tx.Rollback() //nolint:errcheck

		if err := r.insertVersion(ctx, tx, &archived); err != nil {
			return err
		}

		// The version guard is what makes a lost race a conflict: a renewal
		// that read version N cannot overwrite a row another renewal has
		// already moved to N+1.
		result, err := ScopedExec(ctx, tx,
			"UPDATE certificates SET certificate = ?, private_key = ?, version = ?, created_at = ?, expires_at = ?, not_before = ?, enabled = ? WHERE id = ? AND version = ? AND deleted_at IS NULL",
			[]any{
				renewed.Certificate, renewed.PrivateKey, renewed.Version, renewed.CreatedAt,
				renewed.ExpiresAt, renewed.NotBefore, renewed.Enabled, renewed.ID.String(), archived.Version,
			},
			scope)
		if err != nil {
			if errors.Is(err, ErrInvalidScope) {
				return err
			}
			return fmt.Errorf("failed to update renewed certificate: %w", err)
		}
		affected, err := result.RowsAffected()
		if err != nil {
			return fmt.Errorf("failed to get rows affected: %w", err)
		}
		if affected == 0 {
			return fmt.Errorf("certificate %s is no longer at version %d: %w", renewed.ID, archived.Version, ErrCertificateVersionConflict)
		}

		if err := tx.Commit(); err != nil {
			return fmt.Errorf("failed to commit transaction: %w", err)
		}
		return nil
	})
}

// CreateVersion inserts one archived version.
func (r *CertificateVersionRepository) CreateVersion(ctx context.Context, rec *model.CertificateVersionRecord) error {
	return r.executeWithMetrics("create_certificate_version", func() error {
		return r.insertVersion(ctx, r.db, rec)
	})
}

// CreateVersionTx is CreateVersion inside a transaction the caller owns.
// ItemBackupService uses it for an atomic restore.
func (r *CertificateVersionRepository) CreateVersionTx(ctx context.Context, ex db.DBTX, rec *model.CertificateVersionRecord) error {
	return r.executeWithMetrics("create_certificate_version", func() error {
		return r.insertVersion(ctx, ex, rec)
	})
}

// insertVersion writes one certificate_versions row against ex.
func (r *CertificateVersionRepository) insertVersion(ctx context.Context, ex db.DBTX, rec *model.CertificateVersionRecord) error {
	if rec.Version < 1 {
		return fmt.Errorf("certificate version must be >= 1, got %d", rec.Version)
	}
	var keyID any
	if rec.KeyID != uuid.Nil {
		keyID = rec.KeyID.String()
	}
	_, err := ex.ExecContext(ctx,
		"INSERT INTO certificate_versions (certificate_id, version, certificate, private_key, key_id, created_at, expires_at, not_before, enabled) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
		rec.CertificateID.String(), rec.Version, rec.Certificate, rec.PrivateKey, keyID,
		rec.CreatedAt, rec.ExpiresAt, rec.NotBefore, rec.Enabled,
	)
	if err != nil {
		if r.db.Dialect().IsConstraintErr(err) {
			return fmt.Errorf("certificate %s version %d is already archived: %w", rec.CertificateID, rec.Version, ErrCertificateVersionConflict)
		}
		return fmt.Errorf("failed to insert certificate version: %w", err)
	}
	return nil
}

// scanCertificateVersion scans one row of certificateVersionMetadataColumns.
func scanCertificateVersion(certID uuid.UUID, scan func(dest ...any) error) (model.CertificateVersion, error) {
	v := model.CertificateVersion{CertificateID: certID}
	err := scan(&v.Version, &v.CreatedAt, &v.ExpiresAt, &v.NotBefore, &v.Enabled)
	return v, err
}

// ListVersions returns the archived versions' metadata, oldest first.
func (r *CertificateVersionRepository) ListVersions(ctx context.Context, certID uuid.UUID) ([]model.CertificateVersion, error) {
	var versions []model.CertificateVersion
	err := r.executeWithMetrics("list_certificate_versions", func() error {
		rows, err := r.db.QueryContext(ctx,
			"SELECT "+certificateVersionMetadataColumns+" FROM certificate_versions WHERE certificate_id = ? ORDER BY version ASC",
			certID.String())
		if err != nil {
			return fmt.Errorf("failed to query certificate versions: %w", err)
		}
		defer rows.Close() //nolint:errcheck

		for rows.Next() {
			v, scanErr := scanCertificateVersion(certID, rows.Scan)
			if scanErr != nil {
				return fmt.Errorf("failed to scan certificate version: %w", scanErr)
			}
			versions = append(versions, v)
		}
		return rows.Err()
	})
	return versions, err
}

// GetVersion returns one archived version's metadata.
func (r *CertificateVersionRepository) GetVersion(ctx context.Context, certID uuid.UUID, version int) (*model.CertificateVersion, error) {
	if version < 1 {
		return nil, fmt.Errorf("%w: version must be >= 1", ErrCertificateVersionNotFound)
	}
	var out *model.CertificateVersion
	err := r.executeWithMetrics("get_certificate_version", func() error {
		row := r.db.QueryRowContext(ctx,
			"SELECT "+certificateVersionMetadataColumns+" FROM certificate_versions WHERE certificate_id = ? AND version = ?",
			certID.String(), version)
		v, scanErr := scanCertificateVersion(certID, row.Scan)
		if errors.Is(scanErr, sql.ErrNoRows) {
			return fmt.Errorf("%w: certificate %s has no archived version %d", ErrCertificateVersionNotFound, certID, version)
		}
		if scanErr != nil {
			return fmt.Errorf("failed to query certificate version: %w", scanErr)
		}
		out = &v
		return nil
	})
	return out, err
}

// ListVersionRecords returns the archived versions with material, oldest first.
func (r *CertificateVersionRepository) ListVersionRecords(ctx context.Context, certID uuid.UUID) ([]model.CertificateVersionRecord, error) {
	var records []model.CertificateVersionRecord
	err := r.executeWithMetrics("list_certificate_version_records", func() error {
		rows, err := r.db.QueryContext(ctx,
			"SELECT "+certificateVersionRecordColumns+" FROM certificate_versions WHERE certificate_id = ? ORDER BY version ASC",
			certID.String())
		if err != nil {
			return fmt.Errorf("failed to query certificate version records: %w", err)
		}
		defer rows.Close() //nolint:errcheck

		for rows.Next() {
			rec := model.CertificateVersionRecord{CertificateID: certID}
			var keyID sql.NullString
			if err := rows.Scan(&rec.Version, &rec.Certificate, &rec.PrivateKey, &keyID,
				&rec.CreatedAt, &rec.ExpiresAt, &rec.NotBefore, &rec.Enabled); err != nil {
				return fmt.Errorf("failed to scan certificate version record: %w", err)
			}
			if keyID.Valid && keyID.String != "" {
				parsed, parseErr := uuid.Parse(keyID.String)
				if parseErr != nil {
					return fmt.Errorf("failed to parse certificate version key ID: %w", parseErr)
				}
				rec.KeyID = parsed
			}
			records = append(records, rec)
		}
		return rows.Err()
	})
	return records, err
}

// UpdateVersionLifecycle sets one archived version's lifecycle attributes.
func (r *CertificateVersionRepository) UpdateVersionLifecycle(ctx context.Context, certID uuid.UUID, version int, attrs model.CertificateVersionAttributes) error {
	return r.executeWithMetrics("update_certificate_version", func() error {
		result, err := r.db.ExecContext(ctx,
			"UPDATE certificate_versions SET enabled = ?, expires_at = ?, not_before = ? WHERE certificate_id = ? AND version = ?",
			attrs.Enabled, attrs.ExpiresAt, attrs.NotBefore, certID.String(), version)
		if err != nil {
			return fmt.Errorf("failed to update certificate version: %w", err)
		}
		affected, err := result.RowsAffected()
		if err != nil {
			return fmt.Errorf("failed to get rows affected: %w", err)
		}
		if affected == 0 {
			return fmt.Errorf("%w: certificate %s has no archived version %d", ErrCertificateVersionNotFound, certID, version)
		}
		return nil
	})
}

// UpdateCurrentLifecycle sets the lifecycle attributes on the certificates
// row while it is still at version. A renewal that committed in between
// moves the row on, and the update then matches nothing and conflicts.
func (r *CertificateVersionRepository) UpdateCurrentLifecycle(ctx context.Context, certID uuid.UUID, version int, attrs model.CertificateVersionAttributes, scope model.Scope) error {
	return r.executeWithMetrics("update_current_certificate_version", func() error {
		result, err := ScopedExec(ctx, r.db,
			"UPDATE certificates SET enabled = ?, expires_at = ?, not_before = ? WHERE id = ? AND version = ? AND deleted_at IS NULL",
			[]any{attrs.Enabled, attrs.ExpiresAt, attrs.NotBefore, certID.String(), version},
			scope)
		if err != nil {
			if errors.Is(err, ErrInvalidScope) {
				return err
			}
			return fmt.Errorf("failed to update certificate lifecycle: %w", err)
		}
		affected, err := result.RowsAffected()
		if err != nil {
			return fmt.Errorf("failed to get rows affected: %w", err)
		}
		if affected == 0 {
			return fmt.Errorf("certificate %s is no longer at version %d: %w", certID, version, ErrCertificateVersionConflict)
		}
		return nil
	})
}
```

- [ ] **Step 6: Update the hand-written test schemas and the B37 Update test**

`certificateColumns` now selects `version` and `insertCertAndTags` writes it, so every hand-written `certificates` table used by a `CertificateRepository` needs the column. In each file below, inside the `CREATE TABLE ... certificates (` statement, add this line immediately after the `private_key ... TEXT NOT NULL,` line (match the file's column alignment):

```sql
version INTEGER NOT NULL DEFAULT 1,
```

Files: `internal/repositories/certificate_ca_cert_id_test.go` (line 32), `certificate_listall_test.go` (38), `certificate_renewal_repo_test.go` (32), `repositories_test.go` (96, in `setupFullCertDB`), `certificate_lifecycle_test.go` (31), `certificate_key_id_test.go` (35), `certificate_soft_delete_test.go` (40), `certificate_scope_test.go` (33), `internal_coverage_test.go` (121), `api/vault_cross_denial_test.go` (240 in `newCrossVaultCertsTestAPI`, 335 in `newCrossVaultCertPolicyTestAPI`). Leave `certificate_policy_repository_test.go` alone: its minimal table is never read through `CertificateRepository`.

In `internal/repositories/certificate_ca_cert_id_test.go`, `TestCertificateRepository_CACertID_SurvivesUpdate`, replace

```go
	require.Equal(t, "renewed-pem", got.Certificate)
```

with

```go
	require.Equal(t, "cert-pem", got.Certificate,
		"Update writes metadata only; a renewal writes the body through ArchiveAndRenew")
```

- [ ] **Step 7: Run and expect PASS**

Run: `go test ./internal/repositories -run 'TestCertificateRepository_ReadsVersionColumn|TestArchiveAndRenew|TestCertificateVersions_|TestCreateVersion_|TestUpdateCurrentLifecycle|TestCertificateUpdate_NeverRewrites' -v`
Expected: PASS.

Run: `go test ./internal/repositories ./api -run 'Certificate|Cert' && go test ./internal/repositories -run TestCertificateSelectListIsNotDuplicated -v`
Expected: PASS.

- [ ] **Step 8: Commit**

Commit via the `dev-workflow-skills:1-git-commit` skill. Stage: `internal/repositories/certificate_repository.go`, `internal/repositories/certificate_version_repository.go`, `internal/repositories/certificate_version_errors.go`, `internal/repositories/certificate_version_repository_test.go`, the ten modified `internal/repositories/*_test.go` files listed in Step 6, `api/vault_cross_denial_test.go`.

---

### Task 3: Explicit version-row cleanup on purge, vault purge and hard delete

**Files:**
- Modify: `internal/repositories/item_lifecycle.go:35-46` (`itemLifecycleConfig`), `:124-195` (`purgeItem`), `:267-290` (`purgeVaultContents`), `:301-345` (`deleteItemWithTags`)
- Modify: `internal/repositories/certificate_repository.go:322-337` (`crud`)
- Create: `internal/repositories/certificate_versions_schema_test.go` (package `repositories_test`), `internal/repositories/certificate_versions_schema_internal_test.go` (package `repositories`)
- Modify tests: the setup functions of `certificate_ca_cert_id_test.go`, `certificate_listall_test.go`, `certificate_renewal_repo_test.go`, `repositories_test.go` (`setupFullCertDB`), `certificate_lifecycle_test.go`, `certificate_key_id_test.go`, `certificate_soft_delete_test.go`, `certificate_scope_test.go` (`newScopeTestCertRepo`), `internal_coverage_test.go`, `api/vault_cross_denial_test.go` (`newCrossVaultCertsTestAPI`)
- Test: `internal/repositories/certificate_version_cleanup_test.go` (create)

**Interfaces:**
- Consumes: `newCertVersionFixture`, `seedVersionedCert`, `countCertVersions` (Task 2 test helpers, same package).
- Produces: `itemLifecycleConfig.versionTable`, `itemLifecycleConfig.versionFK`; `func deleteItemVersions(ctx context.Context, ex db.DBTX, cfg itemLifecycleConfig, id uuid.UUID) error`; test helper `createCertificateVersionsTable(t *testing.T, db *sql.DB)` in both test packages.

- [ ] **Step 1: Write the failing cleanup tests**

Create `internal/repositories/certificate_version_cleanup_test.go`:

```go
package repositories_test

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"rocketvault/model"
)

// archiveOneVersion renews cert once, so it has one archived row.
func archiveOneVersion(t *testing.T, cert *model.Certificate, archive func(model.CertificateVersionRecord, *model.Certificate, model.Scope) error) {
	t.Helper()
	require.NoError(t, archive(cert.ArchiveRecord(), renewedFrom(cert, "PEM-v2"), model.NewVaultScope(cert.VaultID, cert.UserID)))
}

func TestCertificatePurge_RemovesVersionRows(t *testing.T) {
	certs, versions, raw := newCertVersionFixture(t)
	ctx := context.Background()
	cert := seedVersionedCert(t, certs, uuid.New())
	archiveOneVersion(t, cert, func(a model.CertificateVersionRecord, r *model.Certificate, s model.Scope) error {
		return versions.ArchiveAndRenew(ctx, a, r, s)
	})

	require.NoError(t, certs.SoftDelete(ctx, cert.ID))
	require.NoError(t, certs.PurgeCertificate(ctx, cert.ID))
	assert.Zero(t, countCertVersions(t, raw, cert.ID), "SQLite does not cascade; purge must delete version rows itself")
}

func TestCertificateDelete_RemovesVersionRows(t *testing.T) {
	certs, versions, raw := newCertVersionFixture(t)
	ctx := context.Background()
	cert := seedVersionedCert(t, certs, uuid.New())
	archiveOneVersion(t, cert, func(a model.CertificateVersionRecord, r *model.Certificate, s model.Scope) error {
		return versions.ArchiveAndRenew(ctx, a, r, s)
	})

	require.NoError(t, certs.Delete(ctx, cert.ID))
	assert.Zero(t, countCertVersions(t, raw, cert.ID))
}

func TestCertificatePurgeVaultContents_RemovesOnlyThatVaultsVersionRows(t *testing.T) {
	certs, versions, raw := newCertVersionFixture(t)
	ctx := context.Background()
	purged := seedVersionedCert(t, certs, uuid.New())
	kept := seedVersionedCert(t, certs, uuid.New())
	for _, c := range []*model.Certificate{purged, kept} {
		archiveOneVersion(t, c, func(a model.CertificateVersionRecord, r *model.Certificate, s model.Scope) error {
			return versions.ArchiveAndRenew(ctx, a, r, s)
		})
	}

	purger, ok := certs.(interface {
		PurgeVaultContents(ctx context.Context, vaultID uuid.UUID) error
	})
	require.True(t, ok, "the real certificate repository purges vault contents")
	require.NoError(t, purger.PurgeVaultContents(ctx, purged.VaultID))

	assert.Zero(t, countCertVersions(t, raw, purged.ID))
	assert.Equal(t, 1, countCertVersions(t, raw, kept.ID), "another vault's history must survive")
}

func TestCertificateSoftDeleteAndRecover_KeepVersionRows(t *testing.T) {
	certs, versions, raw := newCertVersionFixture(t)
	ctx := context.Background()
	cert := seedVersionedCert(t, certs, uuid.New())
	archiveOneVersion(t, cert, func(a model.CertificateVersionRecord, r *model.Certificate, s model.Scope) error {
		return versions.ArchiveAndRenew(ctx, a, r, s)
	})

	require.NoError(t, certs.SoftDelete(ctx, cert.ID))
	assert.Equal(t, 1, countCertVersions(t, raw, cert.ID))
	require.NoError(t, certs.RecoverCertificate(ctx, cert.ID))
	assert.Equal(t, 1, countCertVersions(t, raw, cert.ID))
}
```

- [ ] **Step 2: Run and expect FAIL**

Run: `go test ./internal/repositories -run 'TestCertificatePurge_RemovesVersionRows|TestCertificateDelete_RemovesVersionRows|TestCertificatePurgeVaultContents_|TestCertificateSoftDeleteAndRecover_' -v`
Expected: FAIL on the purge, delete and vault-purge tests (version rows remain: `expected 0, got 1`). The soft-delete test passes already.

- [ ] **Step 3: Implement the explicit deletes**

In `itemLifecycleConfig`, after the `tagFK` field add:

```go
	// versionTable/versionFK name the item's archived-version table when the
	// purge and delete paths must clear it explicitly. Only certificates set
	// them. The same SQLite cascade caveat applies to key_versions and
	// secret_versions, but those are tracked separately as B26.
	versionTable string
	versionFK    string
```

After `passthroughWrap`, add:

```go
// deleteItemVersions removes id's archived-version rows when cfg names a
// version table. See itemLifecycleConfig.versionTable.
func deleteItemVersions(ctx context.Context, ex db.DBTX, cfg itemLifecycleConfig, id uuid.UUID) error {
	if cfg.versionTable == "" {
		return nil
	}
	if _, err := ex.ExecContext(ctx,
		"DELETE FROM "+cfg.versionTable+" WHERE "+cfg.versionFK+" = ?", id.String()); err != nil {
		return fmt.Errorf("failed to delete %s versions: %w", cfg.item, err)
	}
	return nil
}
```

In `purgeItem`, immediately after the tag-delete block (the `if _, tagErr := tx.ExecContext(...)` that ends with `return fmt.Errorf("failed to purge %s tags: %w", cfg.item, tagErr)` and its closing brace), add:

```go
		if verErr := deleteItemVersions(ctx, tx, cfg, id); verErr != nil {
			cfg.log.LogAuditError(cfg.auditActor, op, "failed", "Failed to purge "+cfg.item+" versions", verErr)
			return verErr
		}
```

In `deleteItemWithTags`, immediately after the tag-delete block (ending `return fmt.Errorf("failed to delete tags: %w", err)` and its closing brace), add:

```go
		if verErr := deleteItemVersions(ctx, tx, cfg, id); verErr != nil {
			cfg.log.LogAuditError(cfg.auditActor, op, "failed", "Failed to delete "+cfg.item+" versions", verErr)
			return verErr
		}
```

In `purgeVaultContents`, immediately after the tag-delete block (ending `return fmt.Errorf("failed to purge vault %s: %w", cfg.tagTable, tagErr)` and its closing brace), add:

```go
		// Same cascade caveat for archived versions, through the same subquery.
		if cfg.versionTable != "" {
			if _, verErr := ex.ExecContext(ctx,
				"DELETE FROM "+cfg.versionTable+" WHERE "+cfg.versionFK+
					" IN (SELECT id FROM "+cfg.table+" WHERE vault_id = ?)", vaultID.String()); verErr != nil {
				cfg.log.LogAuditError(vaultID.String(), op, "failed", "Failed to purge vault "+cfg.versionTable, verErr)
				return fmt.Errorf("failed to purge vault %s: %w", cfg.versionTable, verErr)
			}
		}
```

In `CertificateRepository.crud()`, after `tagFK: "certificate_id",` add:

```go
		versionTable:       "certificate_versions",
		versionFK:          "certificate_id",
```

- [ ] **Step 4: Give the hand-written schemas the version table**

Create `internal/repositories/certificate_versions_schema_test.go`:

```go
package repositories_test

import (
	"database/sql"
	"testing"

	"github.com/stretchr/testify/require"
)

// createCertificateVersionsTable adds certificate_versions to a hand-written
// test schema. The purge and delete paths now delete from it explicitly.
func createCertificateVersionsTable(t *testing.T, db *sql.DB) {
	t.Helper()
	_, err := db.Exec(`CREATE TABLE IF NOT EXISTS certificate_versions (
		certificate_id TEXT NOT NULL,
		version        INTEGER NOT NULL,
		certificate    TEXT NOT NULL,
		private_key    TEXT NOT NULL,
		key_id         TEXT NULL,
		created_at     TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		expires_at     TIMESTAMP NULL,
		not_before     TIMESTAMP NULL,
		enabled        BOOLEAN NOT NULL DEFAULT TRUE,
		PRIMARY KEY (certificate_id, version)
	)`)
	require.NoError(t, err)
}
```

Create `internal/repositories/certificate_versions_schema_internal_test.go` for the internal test package (`certificate_scope_test.go` and `internal_coverage_test.go` are `package repositories`):

```go
package repositories

import (
	"database/sql"
	"testing"

	"github.com/stretchr/testify/require"
)

// createCertificateVersionsTable adds certificate_versions to a hand-written
// test schema. The purge and delete paths now delete from it explicitly.
func createCertificateVersionsTable(t *testing.T, db *sql.DB) {
	t.Helper()
	_, err := db.Exec(`CREATE TABLE IF NOT EXISTS certificate_versions (
		certificate_id TEXT NOT NULL,
		version        INTEGER NOT NULL,
		certificate    TEXT NOT NULL,
		private_key    TEXT NOT NULL,
		key_id         TEXT NULL,
		created_at     TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		expires_at     TIMESTAMP NULL,
		not_before     TIMESTAMP NULL,
		enabled        BOOLEAN NOT NULL DEFAULT TRUE,
		PRIMARY KEY (certificate_id, version)
	)`)
	require.NoError(t, err)
}
```

Then, in each setup function below, add `createCertificateVersionsTable(t, <db>)` immediately after the error check that follows the statement creating `certificate_tags`:

| File | Setup function | `<db>` |
|---|---|---|
| `certificate_ca_cert_id_test.go` | `setupCertCACertIDTestDB` | `db` |
| `certificate_listall_test.go` | `setupCertListAllTestDB` | `raw` |
| `certificate_renewal_repo_test.go` | `setupCertRenewalTestDB` | `db` |
| `repositories_test.go` | `setupFullCertDB` | `db` |
| `certificate_lifecycle_test.go` | `setupCertLifecycleTestDB` | `db` |
| `certificate_key_id_test.go` | `setupCertKeyIDTestDB` | `db` |
| `certificate_soft_delete_test.go` | `setupCertTestDB` | `db` |
| `certificate_scope_test.go` | `newScopeTestCertRepo` | `db` |
| `internal_coverage_test.go` | the function that creates `certificate_tags` at line 134 | `db` |

In `api/vault_cross_denial_test.go`, `newCrossVaultCertsTestAPI`, after the `certificate_tags` creation's `if err != nil { t.Fatalf(...) }` block, add:

```go
	_, err = sqlDB.Exec(`CREATE TABLE IF NOT EXISTS certificate_versions (
		certificate_id TEXT NOT NULL,
		version        INTEGER NOT NULL,
		certificate    TEXT NOT NULL,
		private_key    TEXT NOT NULL,
		key_id         TEXT NULL,
		created_at     TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		expires_at     TIMESTAMP NULL,
		not_before     TIMESTAMP NULL,
		enabled        BOOLEAN NOT NULL DEFAULT TRUE,
		PRIMARY KEY (certificate_id, version)
	)`)
	if err != nil {
		t.Fatalf("create certificate_versions schema: %v", err)
	}
```

- [ ] **Step 5: Run and expect PASS**

Run: `go test ./internal/repositories -run 'TestCertificatePurge_RemovesVersionRows|TestCertificateDelete_RemovesVersionRows|TestCertificatePurgeVaultContents_|TestCertificateSoftDeleteAndRecover_' -v`
Expected: PASS.

Run: `go test ./internal/repositories ./api ./internal/services/vaults ./internal/services/softdelete`
Expected: PASS.

- [ ] **Step 6: Commit**

Commit via the `dev-workflow-skills:1-git-commit` skill. Stage: `internal/repositories/item_lifecycle.go`, `internal/repositories/certificate_repository.go`, `internal/repositories/certificate_version_cleanup_test.go`, `internal/repositories/certificate_versions_schema_test.go`, `internal/repositories/certificate_versions_schema_internal_test.go`, the nine modified `internal/repositories/*_test.go` files, `api/vault_cross_denial_test.go`.

---

### Task 4: Transactional renewal and version methods in the certificate service

**Files:**
- Modify: `internal/services/certificates/certificate_service.go:27-31` (sentinels), `:66-72` (`CreateCertificateResult`), after `:87` (new request type), `:91-135` (interface), `:139-152` (struct), `:154-167` (config), `:177-186` (constructor), `:293-308` and `:479-495` (create entities set `Version: 1`), `:328-334` and `:516-522` (create results), `:969-1015` (tail of `RenewCertificate`), after `:1107` (`extractValidity`)
- Modify: `internal/certcache/cache_integration.go` (append three methods), `internal/services/retry/retry_certificate_service.go` (append three methods)
- Regenerate: `internal/services/certificates/mocks/mock_CertificateService.go`
- Modify: `internal/container/service_container.go:164` (field), `:369` (construct), `:699-706` (config)
- Modify test doubles: `internal/services/certificates/certificate_service_extended_test.go:36-42` (`newCertSvc`) and `mockRenewalCertSvc` (`:892-…`), `internal/services/certificates/renewal_service_test.go` (`mockCertSvcForRenewal`, `:108-…`), `internal/services/certificates/ca_opt_in_test.go:225-229`, `internal/services/certificates/cert_soft_delete_test.go:331-335`, `api/certificates_test.go` (`mockCertService`), `api/vault_scoped_keys_certs_test.go` (`recordingCertService`), `cmd/certificates/certs_cmd_test.go` (`certCmdCertService`), `internal/container/container_test.go:257-…`
- Create tests: `internal/services/certificates/version_repo_fake_test.go`, `internal/services/certificates/certificate_versions_test.go`, `internal/services/certificates/versioning_integration_test.go`

**Interfaces:**
- Consumes: `repositories.CertificateVersionRepositoryInterface`, `repositories.NewCertificateVersionRepository` (Task 2); model types (Task 1).
- Produces:
  - `var ErrCertVersioningUnavailable = errors.New("certificate versioning is not configured")`
  - `CreateCertificateResult.Version int`
  - `type UpdateCertificateVersionRequest struct { CertID uuid.UUID; Version int; Scope model.Scope; Enabled *bool; ExpiresAt *time.Time; NotBefore *time.Time }`
  - `CertificateServiceConfig.VersionRepository repositories.CertificateVersionRepositoryInterface`
  - Interface methods:
    - `ListCertificateVersions(ctx context.Context, certID uuid.UUID, scope model.Scope) ([]model.CertificateVersion, error)`
    - `GetCertificateVersion(ctx context.Context, certID uuid.UUID, version int, scope model.Scope) (*model.CertificateVersion, error)`
    - `UpdateCertificateVersion(ctx context.Context, req UpdateCertificateVersionRequest) (*model.CertificateVersion, error)`
  - Test helpers in package `certificates`: `fakeCertVersionRepo`, `newCertSvcWithVersions`, `newSelfSignedRenewalFixture`, `versioningHarness`, `newVersioningHarness`, `(*versioningHarness).scope`, `(*versioningHarness).createCert`.

- [ ] **Step 1: Add the fake version repository and rewire `newCertSvc`**

Create `internal/services/certificates/version_repo_fake_test.go`:

```go
package certificates

import (
	"context"
	"fmt"

	"github.com/google/uuid"

	"rocketvault/internal/repositories"
	"rocketvault/model"
)

// fakeCertVersionRepo is an in-memory CertificateVersionRepositoryInterface.
// When certRepo is set, ArchiveAndRenew forwards the renewed row to
// certRepo.Update, so fixtures written before versioning, which capture the
// renewed certificate from an Update stub, keep working unchanged.
type fakeCertVersionRepo struct {
	certRepo *mockCertRepository

	archived []model.CertificateVersionRecord
	renewed  *model.Certificate
	stored   []model.CertificateVersion

	archiveErr error
	currentErr error

	currentUpdates  []model.CertificateVersionAttributes
	archivedUpdates map[int]model.CertificateVersionAttributes
}

func (f *fakeCertVersionRepo) ArchiveAndRenew(ctx context.Context, archived model.CertificateVersionRecord, renewed *model.Certificate, scope model.Scope) error {
	if f.archiveErr != nil {
		return f.archiveErr
	}
	f.archived = append(f.archived, archived)
	f.renewed = renewed
	if f.certRepo != nil {
		return f.certRepo.Update(ctx, renewed, scope)
	}
	return nil
}

func (f *fakeCertVersionRepo) CreateVersion(_ context.Context, rec *model.CertificateVersionRecord) error {
	f.archived = append(f.archived, *rec)
	return nil
}

func (f *fakeCertVersionRepo) ListVersions(_ context.Context, _ uuid.UUID) ([]model.CertificateVersion, error) {
	return append([]model.CertificateVersion(nil), f.stored...), nil
}

func (f *fakeCertVersionRepo) GetVersion(_ context.Context, certID uuid.UUID, version int) (*model.CertificateVersion, error) {
	for _, v := range f.stored {
		if v.Version == version {
			found := v
			return &found, nil
		}
	}
	return nil, fmt.Errorf("%w: certificate %s has no archived version %d", repositories.ErrCertificateVersionNotFound, certID, version)
}

func (f *fakeCertVersionRepo) ListVersionRecords(_ context.Context, _ uuid.UUID) ([]model.CertificateVersionRecord, error) {
	return f.archived, nil
}

func (f *fakeCertVersionRepo) UpdateVersionLifecycle(_ context.Context, certID uuid.UUID, version int, attrs model.CertificateVersionAttributes) error {
	for _, v := range f.stored {
		if v.Version == version {
			if f.archivedUpdates == nil {
				f.archivedUpdates = map[int]model.CertificateVersionAttributes{}
			}
			f.archivedUpdates[version] = attrs
			return nil
		}
	}
	return fmt.Errorf("%w: certificate %s has no archived version %d", repositories.ErrCertificateVersionNotFound, certID, version)
}

func (f *fakeCertVersionRepo) UpdateCurrentLifecycle(_ context.Context, _ uuid.UUID, _ int, attrs model.CertificateVersionAttributes, _ model.Scope) error {
	if f.currentErr != nil {
		return f.currentErr
	}
	f.currentUpdates = append(f.currentUpdates, attrs)
	return nil
}

// newCertSvcWithVersions builds the service with an explicit version fake.
func newCertSvcWithVersions(certRepo *mockCertRepository, keyRepo *mockKeyRepo, versions *fakeCertVersionRepo) CertificateService {
	return NewCertificateService(CertificateServiceConfig{
		CertificateRepository: certRepo,
		KeyRepository:         keyRepo,
		VersionRepository:     versions,
		Logger:                newTestCertLogger(),
	})
}
```

In `certificate_service_extended_test.go`, replace `newCertSvc` with:

```go
func newCertSvc(certRepo *mockCertRepository, keyRepo *mockKeyRepo) CertificateService {
	return newCertSvcWithVersions(certRepo, keyRepo, &fakeCertVersionRepo{certRepo: certRepo})
}
```

In `ca_opt_in_test.go` (`NewCertificateService(CertificateServiceConfig{` at line 225) and `cert_soft_delete_test.go` (line 331), add to the config literal:

```go
		VersionRepository:     &fakeCertVersionRepo{certRepo: certRepo},
```

- [ ] **Step 2: Write the failing service tests**

Create `internal/services/certificates/certificate_versions_test.go`:

```go
package certificates

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"rocketvault/common"
	"rocketvault/internal/crypto"
	"rocketvault/internal/repositories"
	"rocketvault/model"
)

// selfSignedRenewalFixture is a self-signed certificate at a chosen version,
// wired to mocks and a fake version repository that records every write.
type selfSignedRenewalFixture struct {
	svc      CertificateService
	certRepo *mockCertRepository
	keyRepo  *mockKeyRepo
	versions *fakeCertVersionRepo
	scope    model.Scope
	original *model.Certificate
}

// newSelfSignedRenewalFixture issues the stored body with one key. When
// currentKeyPEM is non-empty the key row holds that PEM instead, which is
// what the certificate's key looks like after a key rotation.
func newSelfSignedRenewalFixture(t *testing.T, version int, currentKeyPEM string) *selfSignedRenewalFixture {
	t.Helper()
	setupMasterKey()

	userID, vaultID, certID, keyID := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	issuedKeyPEM, err := crypto.GenerateRSAKeyPEM(2048)
	require.NoError(t, err)
	body, err := crypto.CreateSelfSignedCertificatePEM(issuedKeyPEM, "RSA", crypto.CertificateTemplate{
		CommonName: "versioned-cert", ValidityDays: 365,
	})
	require.NoError(t, err)
	issuedEnc, err := common.EncryptSecret(issuedKeyPEM)
	require.NoError(t, err)
	if currentKeyPEM == "" {
		currentKeyPEM = issuedKeyPEM
	}
	currentEnc, err := common.EncryptSecret(currentKeyPEM)
	require.NoError(t, err)

	scope := model.NewVaultScope(vaultID, userID)
	expires := time.Now().Add(20 * 24 * time.Hour)
	original := &model.Certificate{
		ID: certID, UserID: userID, VaultID: vaultID, KeyID: keyID, Name: "versioned-cert",
		Certificate: body, PrivateKey: issuedEnc, CreatedAt: time.Now().Add(-345 * 24 * time.Hour),
		ExpiresAt: &expires, Enabled: true, RenewalDays: 30, Version: version,
	}

	certRepo := &mockCertRepository{}
	keyRepo := &mockKeyRepo{}
	certRepo.On("Read", mock.Anything, certID, scope).Return(original, nil)
	keyRepo.On("Read", mock.Anything, keyID, scope).
		Return(&model.Key{ID: keyID, UserID: userID, Type: model.KeyTypeRSA, Value: currentEnc}, nil)

	versions := &fakeCertVersionRepo{}
	return &selfSignedRenewalFixture{
		svc:      newCertSvcWithVersions(certRepo, keyRepo, versions),
		certRepo: certRepo,
		keyRepo:  keyRepo,
		versions: versions,
		scope:    scope,
		original: original,
	}
}

func TestRenewCertificate_ArchivesCurrentVersionAndBumpsParent(t *testing.T) {
	f := newSelfSignedRenewalFixture(t, 3, "")
	originalBody := f.original.Certificate
	originalKey := f.original.PrivateKey
	originalExpiry := *f.original.ExpiresAt

	result, err := f.svc.RenewCertificate(context.Background(), f.original.ID, f.scope, 90)
	require.NoError(t, err)

	require.Len(t, f.versions.archived, 1)
	archived := f.versions.archived[0]
	assert.Equal(t, 3, archived.Version)
	assert.Equal(t, originalBody, archived.Certificate)
	assert.Equal(t, originalKey, archived.PrivateKey)
	assert.Equal(t, f.original.KeyID, archived.KeyID)
	require.NotNil(t, archived.ExpiresAt)
	assert.Equal(t, originalExpiry, *archived.ExpiresAt)

	renewed := f.versions.renewed
	require.NotNil(t, renewed)
	assert.Equal(t, 4, renewed.Version)
	assert.NotEqual(t, originalBody, renewed.Certificate)
	assert.True(t, renewed.Enabled)
	require.NotNil(t, renewed.NotBefore, "a new version takes not_before from its certificate")
	require.NotNil(t, renewed.ExpiresAt)
	assert.WithinDuration(t, time.Now().AddDate(0, 0, 90), *renewed.ExpiresAt, 24*time.Hour)
	assert.Equal(t, 4, result.Version)
}

func TestRenewCertificate_PreVersioningRowArchivesAsVersionOne(t *testing.T) {
	f := newSelfSignedRenewalFixture(t, 0, "")

	result, err := f.svc.RenewCertificate(context.Background(), f.original.ID, f.scope, 90)
	require.NoError(t, err)
	require.Len(t, f.versions.archived, 1)
	assert.Equal(t, 1, f.versions.archived[0].Version)
	assert.Equal(t, 2, result.Version)
}

func TestRenewCertificate_GuardFailureWritesNoVersion(t *testing.T) {
	cases := []struct {
		name      string
		mutate    func(*model.Certificate)
		validity  int
		wantIsErr error
	}{
		{"disabled certificate", func(c *model.Certificate) { c.Enabled = false }, 90, ErrCertLifecycleDenied},
		{"no key", func(c *model.Certificate) { c.KeyID = uuid.Nil }, 90, nil},
		{"non-positive validity", func(*model.Certificate) {}, 0, nil},
		{"legacy CA-signed row with no link", func(c *model.Certificate) { c.Certificate = foreignIssuerPEM(t) }, 90, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newSelfSignedRenewalFixture(t, 2, "")
			tc.mutate(f.original)

			_, err := f.svc.RenewCertificate(context.Background(), f.original.ID, f.scope, tc.validity)
			require.Error(t, err)
			if tc.wantIsErr != nil {
				assert.True(t, errors.Is(err, tc.wantIsErr))
			}
			assert.Empty(t, f.versions.archived, "a guard failure must write no version")
			assert.Nil(t, f.versions.renewed)
		})
	}
}

// foreignIssuerPEM returns a leaf signed by a separate CA, so it is not
// self-signed and carries no ca_cert_id link.
func foreignIssuerPEM(t *testing.T) string {
	t.Helper()
	caKeyPEM, err := crypto.GenerateRSAKeyPEM(2048)
	require.NoError(t, err)
	caPEM, err := crypto.CreateSelfSignedCertificatePEM(caKeyPEM, "RSA", crypto.CertificateTemplate{
		CommonName: "Foreign CA", ValidityDays: 3650, IsCA: true,
	})
	require.NoError(t, err)
	leafKeyPEM, err := crypto.GenerateRSAKeyPEM(2048)
	require.NoError(t, err)
	leafPEM, err := crypto.CreateCASignedCertificatePEM(leafKeyPEM, "RSA", caPEM, caKeyPEM, "RSA", crypto.CertificateTemplate{
		CommonName: "versioned-cert", ValidityDays: 365,
	})
	require.NoError(t, err)
	return leafPEM
}

func TestRenewCertificate_VersionConflictKeepsSentinel(t *testing.T) {
	f := newSelfSignedRenewalFixture(t, 2, "")
	f.versions.archiveErr = fmt.Errorf("lost the race: %w", repositories.ErrCertificateVersionConflict)

	_, err := f.svc.RenewCertificate(context.Background(), f.original.ID, f.scope, 90)
	require.Error(t, err)
	assert.True(t, errors.Is(err, model.ErrCertificateVersionConflict), "the API maps this sentinel to 409")
}

func TestRenewCertificate_AfterKeyRotationKeepsArchivedKeyCopy(t *testing.T) {
	rotatedPEM, err := crypto.GenerateRSAKeyPEM(2048)
	require.NoError(t, err)
	f := newSelfSignedRenewalFixture(t, 1, rotatedPEM)
	issuedKey := f.original.PrivateKey

	_, err = f.svc.RenewCertificate(context.Background(), f.original.ID, f.scope, 90)
	require.NoError(t, err)

	require.Len(t, f.versions.archived, 1)
	assert.Equal(t, issuedKey, f.versions.archived[0].PrivateKey,
		"a version keeps the key it was issued with")
	renewedKey, err := common.DecryptSecret(f.versions.renewed.PrivateKey)
	require.NoError(t, err)
	assert.Equal(t, rotatedPEM, renewedKey, "the new version is issued over the rotated key")
}

func TestRenewCertificate_WithoutVersionRepositoryFailsClosed(t *testing.T) {
	f := newSelfSignedRenewalFixture(t, 1, "")
	svc := NewCertificateService(CertificateServiceConfig{
		CertificateRepository: f.certRepo,
		KeyRepository:         f.keyRepo,
		Logger:                newTestCertLogger(),
	})

	_, err := svc.RenewCertificate(context.Background(), f.original.ID, f.scope, 90)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrCertVersioningUnavailable))
	f.certRepo.AssertNotCalled(t, "Update", mock.Anything, mock.Anything, mock.Anything)
}

func TestListCertificateVersions_ArchivedThenCurrent(t *testing.T) {
	f := newSelfSignedRenewalFixture(t, 3, "")
	f.versions.stored = []model.CertificateVersion{
		{CertificateID: f.original.ID, Version: 1, Enabled: true},
		{CertificateID: f.original.ID, Version: 2, Enabled: false},
	}

	list, err := f.svc.ListCertificateVersions(context.Background(), f.original.ID, f.scope)
	require.NoError(t, err)
	require.Len(t, list, 3)
	assert.Equal(t, []int{1, 2, 3}, []int{list[0].Version, list[1].Version, list[2].Version})
	assert.True(t, list[2].Current)
	assert.False(t, list[0].Current)
}

func TestGetCertificateVersion(t *testing.T) {
	f := newSelfSignedRenewalFixture(t, 3, "")
	f.versions.stored = []model.CertificateVersion{{CertificateID: f.original.ID, Version: 2, Enabled: true}}
	ctx := context.Background()

	current, err := f.svc.GetCertificateVersion(ctx, f.original.ID, 3, f.scope)
	require.NoError(t, err)
	assert.True(t, current.Current)

	archived, err := f.svc.GetCertificateVersion(ctx, f.original.ID, 2, f.scope)
	require.NoError(t, err)
	assert.False(t, archived.Current)

	for _, missing := range []int{0, 4} {
		_, err := f.svc.GetCertificateVersion(ctx, f.original.ID, missing, f.scope)
		assert.True(t, errors.Is(err, model.ErrCertificateVersionNotFound), "version %d", missing)
	}
}

func TestUpdateCertificateVersion_RejectsNotBeforeAfterExpiry(t *testing.T) {
	f := newSelfSignedRenewalFixture(t, 1, "")
	early := time.Now()
	late := early.Add(time.Hour)

	_, err := f.svc.UpdateCertificateVersion(context.Background(), UpdateCertificateVersionRequest{
		CertID: f.original.ID, Version: 1, Scope: f.scope, NotBefore: &late, ExpiresAt: &early,
	})
	require.Error(t, err)
	assert.True(t, errors.Is(err, model.ErrInvalidCertificateVersionAttributes))
	assert.Empty(t, f.versions.currentUpdates)
}

func TestUpdateCertificateVersion_NoAttributesRejected(t *testing.T) {
	f := newSelfSignedRenewalFixture(t, 1, "")

	_, err := f.svc.UpdateCertificateVersion(context.Background(), UpdateCertificateVersionRequest{
		CertID: f.original.ID, Version: 1, Scope: f.scope,
	})
	assert.True(t, errors.Is(err, model.ErrInvalidCertificateVersionAttributes))
}

func TestUpdateCertificateVersion_RoutesCurrentAndArchived(t *testing.T) {
	f := newSelfSignedRenewalFixture(t, 3, "")
	f.versions.stored = []model.CertificateVersion{{CertificateID: f.original.ID, Version: 2, Enabled: true}}
	disabled := false
	ctx := context.Background()

	current, err := f.svc.UpdateCertificateVersion(ctx, UpdateCertificateVersionRequest{
		CertID: f.original.ID, Version: 3, Scope: f.scope, Enabled: &disabled,
	})
	require.NoError(t, err)
	assert.True(t, current.Current)
	assert.False(t, current.Enabled)
	require.Len(t, f.versions.currentUpdates, 1)
	assert.False(t, f.versions.currentUpdates[0].Enabled)
	assert.Equal(t, f.original.ExpiresAt, f.versions.currentUpdates[0].ExpiresAt, "untouched attributes are kept")

	archived, err := f.svc.UpdateCertificateVersion(ctx, UpdateCertificateVersionRequest{
		CertID: f.original.ID, Version: 2, Scope: f.scope, Enabled: &disabled,
	})
	require.NoError(t, err)
	assert.False(t, archived.Current)
	assert.False(t, f.versions.archivedUpdates[2].Enabled)
}

func TestCertificateVersionMethods_UnknownParentIsNotFound(t *testing.T) {
	f := newSelfSignedRenewalFixture(t, 1, "")
	other := uuid.New()
	f.certRepo.On("Read", mock.Anything, other, f.scope).Return(nil, errors.New("certificate not found or access denied"))

	_, err := f.svc.ListCertificateVersions(context.Background(), other, f.scope)
	assert.True(t, errors.Is(err, ErrCertNotFound))
}
```

Create `internal/services/certificates/versioning_integration_test.go`:

```go
package certificates

import (
	"context"
	"database/sql"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	_ "github.com/mattn/go-sqlite3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"rocketvault/common"
	"rocketvault/internal/crypto"
	rvdb "rocketvault/internal/db"
	"rocketvault/internal/repositories"
	"rocketvault/model"
)

// versioningHarness runs the real certificate service over the real
// repositories and the real schema, so a renewal really archives and really
// commits.
type versioningHarness struct {
	raw      *sql.DB
	certRepo repositories.CertificateRepositoryInterface
	keyRepo  repositories.KeyRepositoryInterface
	versions repositories.CertificateVersionRepositoryInterface
	svc      CertificateService
	userID   uuid.UUID
	vaultID  uuid.UUID
	keyID    uuid.UUID
}

func newVersioningHarness(t *testing.T) *versioningHarness {
	t.Helper()
	setupMasterKey()

	raw, err := sql.Open("sqlite3", "file:certver_"+uuid.NewString()+"?mode=memory&cache=shared")
	require.NoError(t, err)
	t.Cleanup(func() { raw.Close() }) //nolint:errcheck,gosec

	logger := newTestCertLogger()
	require.NoError(t, rvdb.NewRepository(logger).SetupSchema(raw, rvdb.SQLite))
	conn := rvdb.NewConn(raw, rvdb.SQLite)

	h := &versioningHarness{
		raw:      raw,
		certRepo: repositories.NewCertificateRepository(conn, logger),
		keyRepo:  repositories.NewKeyRepository(conn, logger),
		versions: repositories.NewCertificateVersionRepository(conn, logger),
		userID:   uuid.New(),
		vaultID:  uuid.New(),
		keyID:    uuid.New(),
	}
	h.svc = NewCertificateService(CertificateServiceConfig{
		CertificateRepository: h.certRepo,
		KeyRepository:         h.keyRepo,
		VersionRepository:     h.versions,
		Logger:                logger,
	})

	keyPEM, err := crypto.GenerateRSAKeyPEM(2048)
	require.NoError(t, err)
	enc, err := common.EncryptSecret(keyPEM)
	require.NoError(t, err)
	require.NoError(t, h.keyRepo.Create(context.Background(), &model.Key{
		ID: h.keyID, UserID: h.userID, VaultID: h.vaultID, Name: "versioning-key",
		Type: model.KeyTypeRSA, Value: enc, Enabled: true, CreatedAt: time.Now(),
	}))
	return h
}

func (h *versioningHarness) scope() model.Scope { return model.NewVaultScope(h.vaultID, h.userID) }

func (h *versioningHarness) createCert(t *testing.T, name string) uuid.UUID {
	t.Helper()
	result, err := h.svc.CreateSelfSignedCertificate(context.Background(), CreateCertificateRequest{
		Name: name, KeyID: h.keyID, ValidityDays: 365, UserID: h.userID, VaultID: h.vaultID,
	})
	require.NoError(t, err)
	require.Equal(t, 1, result.Version)
	return result.CertID
}

func TestVersioning_RenewTwiceThroughRealRepositories(t *testing.T) {
	h := newVersioningHarness(t)
	ctx := context.Background()
	certID := h.createCert(t, "renew-twice")

	first, err := h.svc.RenewCertificate(ctx, certID, h.scope(), 30)
	require.NoError(t, err)
	assert.Equal(t, 2, first.Version)
	second, err := h.svc.RenewCertificate(ctx, certID, h.scope(), 30)
	require.NoError(t, err)
	assert.Equal(t, 3, second.Version)

	list, err := h.svc.ListCertificateVersions(ctx, certID, h.scope())
	require.NoError(t, err)
	require.Len(t, list, 3)
	assert.Equal(t, []int{1, 2, 3}, []int{list[0].Version, list[1].Version, list[2].Version})
	assert.True(t, list[2].Current)

	cert, err := h.svc.GetCertificate(ctx, certID, h.scope())
	require.NoError(t, err)
	assert.Equal(t, 3, cert.Version)
}

func TestVersioning_CurrentVersionUpdateEqualsCertificateUpdate(t *testing.T) {
	h := newVersioningHarness(t)
	ctx := context.Background()
	viaCert := h.createCert(t, "via-certificate-update")
	viaVersion := h.createCert(t, "via-version-update")

	disabled := false
	notBefore := time.Now().Add(-time.Hour).UTC().Truncate(time.Second)
	require.NoError(t, h.svc.UpdateCertificate(ctx, UpdateCertificateRequest{
		CertID: viaCert, Scope: h.scope(), Enabled: &disabled, NotBefore: &notBefore,
	}))
	_, err := h.svc.UpdateCertificateVersion(ctx, UpdateCertificateVersionRequest{
		CertID: viaVersion, Version: 1, Scope: h.scope(), Enabled: &disabled, NotBefore: &notBefore,
	})
	require.NoError(t, err)

	a, err := h.certRepo.Read(ctx, viaCert, h.scope())
	require.NoError(t, err)
	b, err := h.certRepo.Read(ctx, viaVersion, h.scope())
	require.NoError(t, err)
	assert.Equal(t, a.Enabled, b.Enabled)
	require.NotNil(t, a.NotBefore)
	require.NotNil(t, b.NotBefore)
	assert.True(t, a.NotBefore.Equal(*b.NotBefore))
	assert.Equal(t, a.Version, b.Version)
}

// TestCertificateVersions_OutOfScopeOrDeletedParentIsNotFound pins Review
// Focus 2: certificate_versions has no vault column, so the parent's scoped
// read is the only gate, and a soft-deleted parent hides its history.
func TestCertificateVersions_OutOfScopeOrDeletedParentIsNotFound(t *testing.T) {
	h := newVersioningHarness(t)
	ctx := context.Background()
	certID := h.createCert(t, "scoped-history")
	_, err := h.svc.RenewCertificate(ctx, certID, h.scope(), 30)
	require.NoError(t, err)

	otherVault := model.NewVaultScope(uuid.New(), h.userID)
	enabled := true
	_, err = h.svc.ListCertificateVersions(ctx, certID, otherVault)
	assert.True(t, errors.Is(err, ErrCertNotFound), "list")
	_, err = h.svc.GetCertificateVersion(ctx, certID, 1, otherVault)
	assert.True(t, errors.Is(err, ErrCertNotFound), "get")
	_, err = h.svc.UpdateCertificateVersion(ctx, UpdateCertificateVersionRequest{
		CertID: certID, Version: 1, Scope: otherVault, Enabled: &enabled,
	})
	assert.True(t, errors.Is(err, ErrCertNotFound), "update")
	_, err = h.svc.RenewCertificate(ctx, certID, otherVault, 30)
	assert.True(t, errors.Is(err, ErrCertNotFound), "renew")

	require.NoError(t, h.svc.DeleteCertificate(ctx, certID, h.scope()))
	_, err = h.svc.ListCertificateVersions(ctx, certID, h.scope())
	assert.True(t, errors.Is(err, ErrCertNotFound), "a soft-deleted parent is a 404")
}
```

- [ ] **Step 3: Run and expect FAIL**

Run: `go test ./internal/services/certificates -run 'TestRenewCertificate_|TestListCertificateVersions_|TestGetCertificateVersion|TestUpdateCertificateVersion_|TestCertificateVersionMethods_|TestVersioning_|TestCertificateVersions_' -v`
Expected: FAIL (build errors: `VersionRepository`, `ErrCertVersioningUnavailable`, `UpdateCertificateVersionRequest`, `Version` on `CreateCertificateResult` undefined).

- [ ] **Step 4: Implement the service**

In `certificate_service.go`:

After `ErrCertLifecycleDenied` add:

```go
// ErrCertVersioningUnavailable is returned when the service was built
// without a version repository. Renewal and the version operations fail
// closed rather than overwrite a certificate with no history kept.
var ErrCertVersioningUnavailable = errors.New("certificate versioning is not configured")
```

In `CreateCertificateResult`, after `ExpiresAt` add:

```go
	Version   int // The certificate's current version number.
```

After `UpdateCertificateRequest` add:

```go
// UpdateCertificateVersionRequest changes one version's lifecycle
// attributes. Nil fields are left as they are; at least one must be set.
type UpdateCertificateVersionRequest struct {
	CertID    uuid.UUID
	Version   int
	Scope     model.Scope // Authorization scope, checked against the parent certificate.
	Enabled   *bool
	ExpiresAt *time.Time
	NotBefore *time.Time
}
```

In the `CertificateService` interface, after `RenewCertificate`, add:

```go
	// ListCertificateVersions returns certID's versions, oldest first with
	// the current one last, authorized by scope against the parent.
	ListCertificateVersions(ctx context.Context, certID uuid.UUID, scope model.Scope) ([]model.CertificateVersion, error)
	// GetCertificateVersion returns one version's metadata, authorized by
	// scope against the parent.
	GetCertificateVersion(ctx context.Context, certID uuid.UUID, version int, scope model.Scope) (*model.CertificateVersion, error)
	// UpdateCertificateVersion changes one version's lifecycle attributes,
	// authorized by req.Scope against the parent.
	UpdateCertificateVersion(ctx context.Context, req UpdateCertificateVersionRequest) (*model.CertificateVersion, error)
```

In `certificateService`, after `policyRepo` add `versionRepo repositories.CertificateVersionRepositoryInterface`. In `CertificateServiceConfig`, after `PolicyRepository` add:

```go
	// VersionRepository stores archived versions. Renewal and the version
	// operations fail closed with ErrCertVersioningUnavailable without it.
	VersionRepository repositories.CertificateVersionRepositoryInterface
```

In `NewCertificateService`, add `versionRepo: config.VersionRepository,`.

In both create paths, add `Version: 1,` to the `model.Certificate` literal (after `NotBefore: req.NotBefore,`) and `Version: 1,` to the returned `CreateCertificateResult` literal.

In `RenewCertificate`, replace everything from `expiresAt, err := extractExpiresAt(certPEM)` down to the end of the function with:

```go
	notBefore, notAfter, err := extractValidity(certPEM)
	if err != nil {
		s.logger.LogAuditError(userID.String(), "renew_certificate", "failed", "failed to parse certificate validity", err)
		return nil, fmt.Errorf("failed to determine certificate validity: %w", err)
	}

	encryptedKey, err := common.EncryptSecret(privateKeyPEM)
	if err != nil {
		s.logger.LogAuditError(userID.String(), "renew_certificate", "failed", "failed to encrypt private key", err)
		return nil, fmt.Errorf("failed to encrypt private key: %w", err)
	}

	if s.versionRepo == nil {
		s.logger.LogAuditError(userID.String(), "renew_certificate", "failed", "certificate version repository is not configured", nil)
		return nil, ErrCertVersioningUnavailable
	}

	// Every guard above has passed, so only now is anything written. The
	// current version is archived under its own number and the row moves to
	// the next one, in one repository transaction guarded by the version the
	// row was read at. A concurrent renewal that committed first makes this
	// one a conflict and writes nothing.
	archived := original.ArchiveRecord()
	renewed := *original
	renewed.Certificate = certPEM
	renewed.PrivateKey = encryptedKey
	renewed.Version = archived.Version + 1
	renewed.CreatedAt = time.Now()
	renewed.ExpiresAt = &notAfter
	renewed.NotBefore = &notBefore
	renewed.Enabled = true

	if err := s.versionRepo.ArchiveAndRenew(ctx, archived, &renewed, scope); err != nil {
		s.logger.LogAuditError(userID.String(), "renew_certificate", "failed", "failed to store renewed certificate", err)
		return nil, fmt.Errorf("failed to store renewed certificate: %w", err)
	}

	// The demotion is logged only once the renewed certificate is actually
	// stored, so the audit trail never claims a change that did not land.
	if demoted {
		s.logger.LogAuditInfo(userID.String(), "renew_certificate", "ca_demoted",
			fmt.Sprintf("certificate %s (ID: %s) asserted CA:TRUE without keyCertSign and was renewed as a non-CA leaf; reissue it with --is-ca if it is genuinely a certificate authority",
				renewed.Name, renewed.ID))
	}

	s.logger.LogAuditInfo(userID.String(), "renew_certificate", "success",
		fmt.Sprintf("certificate renewed: %s, ID: %s, version %d archived, now version %d", renewed.Name, renewed.ID, archived.Version, renewed.Version))

	return &CreateCertificateResult{
		CertID:    renewed.ID,
		Name:      renewed.Name,
		Tags:      renewed.Tags,
		CreatedAt: renewed.CreatedAt,
		ExpiresAt: renewed.ExpiresAt,
		Version:   renewed.Version,
	}, nil
}

// readVersionedParent authorizes a version operation against the parent
// certificate. The scoped read is the whole gate: certificate_versions has no
// vault column, so a version is reachable only through a parent the caller
// can read. It is deliberately not lifecycle-gated, so a disabled
// certificate's history can still be inspected and re-enabled, the same way
// UpdateCertificate reads a disabled certificate.
func (s *certificateService) readVersionedParent(ctx context.Context, certID uuid.UUID, scope model.Scope, action string) (*model.Certificate, error) {
	actor := scope.ActorID().String()
	if s.versionRepo == nil {
		s.logger.LogAuditError(actor, action, "failed", "certificate version repository is not configured", nil)
		return nil, ErrCertVersioningUnavailable
	}
	cert, err := s.certRepo.Read(ctx, certID, scope)
	if err != nil {
		s.logger.LogAuditError(actor, action, "failed", "Certificate not found", err)
		return nil, fmt.Errorf("%w: %s", ErrCertNotFound, err.Error())
	}
	return cert, nil
}

// ListCertificateVersions returns certID's versions, oldest first, with the
// current one, read off the certificate row, last.
func (s *certificateService) ListCertificateVersions(ctx context.Context, certID uuid.UUID, scope model.Scope) ([]model.CertificateVersion, error) {
	parent, err := s.readVersionedParent(ctx, certID, scope, "list_certificate_versions")
	if err != nil {
		return nil, err
	}
	archived, err := s.versionRepo.ListVersions(ctx, certID)
	if err != nil {
		return nil, fmt.Errorf("failed to list certificate versions: %w", err)
	}
	return append(archived, parent.VersionMetadata()), nil
}

// GetCertificateVersion returns one version's metadata. The current version
// comes from the certificate row; earlier ones from certificate_versions.
func (s *certificateService) GetCertificateVersion(ctx context.Context, certID uuid.UUID, version int, scope model.Scope) (*model.CertificateVersion, error) {
	if version < 1 {
		return nil, fmt.Errorf("%w: version must be >= 1", model.ErrCertificateVersionNotFound)
	}
	parent, err := s.readVersionedParent(ctx, certID, scope, "get_certificate_version")
	if err != nil {
		return nil, err
	}
	current := parent.CurrentVersion()
	switch {
	case version == current:
		meta := parent.VersionMetadata()
		return &meta, nil
	case version > current:
		return nil, fmt.Errorf("%w: certificate %s has no version %d", model.ErrCertificateVersionNotFound, certID, version)
	}
	return s.versionRepo.GetVersion(ctx, certID, version)
}

// UpdateCertificateVersion changes one version's lifecycle attributes.
// Updating the current version writes the certificate row, exactly as a
// certificate update of the same attributes would; the write is guarded by
// the version number, so a renewal in between turns it into a conflict.
func (s *certificateService) UpdateCertificateVersion(ctx context.Context, req UpdateCertificateVersionRequest) (*model.CertificateVersion, error) {
	actor := req.Scope.ActorID().String()
	if req.Enabled == nil && req.ExpiresAt == nil && req.NotBefore == nil {
		return nil, fmt.Errorf("%w: at least one of enabled, expires_at or not_before is required", model.ErrInvalidCertificateVersionAttributes)
	}

	target, err := s.GetCertificateVersion(ctx, req.CertID, req.Version, req.Scope)
	if err != nil {
		s.logger.LogAuditError(actor, "update_certificate_version", "failed", "Certificate version not found", err)
		return nil, err
	}

	attrs := model.CertificateVersionAttributes{Enabled: target.Enabled, ExpiresAt: target.ExpiresAt, NotBefore: target.NotBefore}
	if req.Enabled != nil {
		attrs.Enabled = *req.Enabled
	}
	if req.ExpiresAt != nil {
		attrs.ExpiresAt = req.ExpiresAt
	}
	if req.NotBefore != nil {
		attrs.NotBefore = req.NotBefore
	}
	if err := model.ValidateCertificateVersionWindow(attrs.NotBefore, attrs.ExpiresAt); err != nil {
		s.logger.LogAuditError(actor, "update_certificate_version", "failed", "invalid version attributes", err)
		return nil, err
	}

	if target.Current {
		err = s.versionRepo.UpdateCurrentLifecycle(ctx, req.CertID, target.Version, attrs, req.Scope)
	} else {
		err = s.versionRepo.UpdateVersionLifecycle(ctx, req.CertID, target.Version, attrs)
	}
	if err != nil {
		s.logger.LogAuditError(actor, "update_certificate_version", "failed", "Failed to update certificate version", err)
		return nil, fmt.Errorf("failed to update certificate version: %w", err)
	}

	updated := *target
	updated.Enabled = attrs.Enabled
	updated.ExpiresAt = attrs.ExpiresAt
	updated.NotBefore = attrs.NotBefore
	s.logger.LogAuditInfo(actor, "update_certificate_version", "success",
		fmt.Sprintf("Certificate %s version %d updated", req.CertID, target.Version))
	return &updated, nil
}
```

After `extractExpiresAt`, add:

```go
// extractValidity returns the NotBefore and NotAfter of a PEM-encoded X.509
// certificate. A new version takes both dates from its certificate.
func extractValidity(certPEM string) (time.Time, time.Time, error) {
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		return time.Time{}, time.Time{}, fmt.Errorf("failed to decode PEM block from certificate")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return time.Time{}, time.Time{}, fmt.Errorf("failed to parse certificate: %w", err)
	}
	return cert.NotBefore, cert.NotAfter, nil
}
```

If `extractExpiresAt` has no remaining caller after this edit (the create paths still use it), leave it; if `go vet` reports it unused, delete it.

- [ ] **Step 5: Keep every `CertificateService` implementation compiling**

Append to `internal/certcache/cache_integration.go`:

```go
// ListCertificateVersions lists a certificate's versions (not cached).
func (s *CachedCertificateService) ListCertificateVersions(ctx context.Context, certID uuid.UUID, scope model.Scope) ([]model.CertificateVersion, error) {
	return s.certificateService.ListCertificateVersions(ctx, certID, scope)
}

// GetCertificateVersion reads one version (not cached; archived versions
// never are).
func (s *CachedCertificateService) GetCertificateVersion(ctx context.Context, certID uuid.UUID, version int, scope model.Scope) (*model.CertificateVersion, error) {
	return s.certificateService.GetCertificateVersion(ctx, certID, version, scope)
}

// UpdateCertificateVersion updates one version and evicts the cached
// certificate when the version was the current one, whose attributes live on
// the cached row. Archived versions are not cached, so updating one leaves
// the cache alone.
func (s *CachedCertificateService) UpdateCertificateVersion(ctx context.Context, req certificates.UpdateCertificateVersionRequest) (*model.CertificateVersion, error) {
	updated, err := s.certificateService.UpdateCertificateVersion(ctx, req)
	if err != nil {
		return nil, err
	}
	if updated.Current {
		if err := s.cache.DeleteByID(ctx, req.CertID); err != nil {
			s.logger.WithError(err).Warn("Failed to invalidate cached certificate after version update")
		}
	}
	return updated, nil
}
```

Append to `internal/services/retry/retry_certificate_service.go`:

```go
// ListCertificateVersions lists versions with retry logic for database operations.
func (s *retryCertificateService) ListCertificateVersions(ctx context.Context, certID uuid.UUID, scope model.Scope) ([]model.CertificateVersion, error) {
	return retried(ctx, s.retryService, func() ([]model.CertificateVersion, error) {
		return s.baseService.ListCertificateVersions(ctx, certID, scope)
	})
}

// GetCertificateVersion reads one version with retry logic for database operations.
func (s *retryCertificateService) GetCertificateVersion(ctx context.Context, certID uuid.UUID, version int, scope model.Scope) (*model.CertificateVersion, error) {
	return retried(ctx, s.retryService, func() (*model.CertificateVersion, error) {
		return s.baseService.GetCertificateVersion(ctx, certID, version, scope)
	})
}

// UpdateCertificateVersion updates one version with retry logic for database operations.
func (s *retryCertificateService) UpdateCertificateVersion(ctx context.Context, req certificates.UpdateCertificateVersionRequest) (*model.CertificateVersion, error) {
	return retried(ctx, s.retryService, func() (*model.CertificateVersion, error) {
		return s.baseService.UpdateCertificateVersion(ctx, req)
	})
}
```

Regenerate the mockery mock from the repo root, then confirm only the certificate service mock changed:

```bash
mockery
git status --short internal/services/*/mocks internal/repositories/mocks
```

Expected: only `internal/services/certificates/mocks/mock_CertificateService.go` is modified. Restore any other changed mock with `git checkout -- <path>`.

Append to `mockCertSvcForRenewal` in `internal/services/certificates/renewal_service_test.go`:

```go
func (m *mockCertSvcForRenewal) ListCertificateVersions(ctx context.Context, certID uuid.UUID, scope model.Scope) ([]model.CertificateVersion, error) {
	panic("not called")
}

func (m *mockCertSvcForRenewal) GetCertificateVersion(ctx context.Context, certID uuid.UUID, version int, scope model.Scope) (*model.CertificateVersion, error) {
	panic("not called")
}

func (m *mockCertSvcForRenewal) UpdateCertificateVersion(ctx context.Context, req certificates.UpdateCertificateVersionRequest) (*model.CertificateVersion, error) {
	panic("not called")
}
```

Append to `mockRenewalCertSvc` in `certificate_service_extended_test.go` (package `certificates`, so the request type is unqualified):

```go
func (m *mockRenewalCertSvc) ListCertificateVersions(ctx context.Context, certID uuid.UUID, scope model.Scope) ([]model.CertificateVersion, error) {
	panic("not called")
}
func (m *mockRenewalCertSvc) GetCertificateVersion(ctx context.Context, certID uuid.UUID, version int, scope model.Scope) (*model.CertificateVersion, error) {
	panic("not called")
}
func (m *mockRenewalCertSvc) UpdateCertificateVersion(ctx context.Context, req UpdateCertificateVersionRequest) (*model.CertificateVersion, error) {
	panic("not called")
}
```

Append to `mockCertService` in `api/certificates_test.go`:

```go
func (m *mockCertService) ListCertificateVersions(ctx context.Context, certID uuid.UUID, scope model.Scope) ([]model.CertificateVersion, error) {
	args := m.Called(ctx, certID, scope)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]model.CertificateVersion), args.Error(1)
}

func (m *mockCertService) GetCertificateVersion(ctx context.Context, certID uuid.UUID, version int, scope model.Scope) (*model.CertificateVersion, error) {
	args := m.Called(ctx, certID, version, scope)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*model.CertificateVersion), args.Error(1)
}

func (m *mockCertService) UpdateCertificateVersion(ctx context.Context, req certServices.UpdateCertificateVersionRequest) (*model.CertificateVersion, error) {
	args := m.Called(ctx, req)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*model.CertificateVersion), args.Error(1)
}
```

Append to `certCmdCertService` in `cmd/certificates/certs_cmd_test.go`:

```go
func (m *certCmdCertService) ListCertificateVersions(ctx context.Context, certID uuid.UUID, scope model.Scope) ([]model.CertificateVersion, error) {
	args := m.Called(ctx, certID, scope)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]model.CertificateVersion), args.Error(1)
}

func (m *certCmdCertService) GetCertificateVersion(ctx context.Context, certID uuid.UUID, version int, scope model.Scope) (*model.CertificateVersion, error) {
	args := m.Called(ctx, certID, version, scope)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*model.CertificateVersion), args.Error(1)
}

func (m *certCmdCertService) UpdateCertificateVersion(ctx context.Context, req certServices.UpdateCertificateVersionRequest) (*model.CertificateVersion, error) {
	args := m.Called(ctx, req)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*model.CertificateVersion), args.Error(1)
}
```

In `api/vault_scoped_keys_certs_test.go`, add two fields to `recordingCertService` after `policyRepo`:

```go
	// versionCalls and versionScope record the version operations and the
	// scope they were dispatched with, for the route-shape tests.
	versionCalls []string
	versionScope model.Scope
```

and append:

```go
func (s *recordingCertService) ListCertificateVersions(_ context.Context, certID uuid.UUID, scope model.Scope) ([]model.CertificateVersion, error) {
	s.versionCalls = append(s.versionCalls, "list")
	s.versionScope = scope
	if s.getInVaultErr != nil {
		return nil, s.getInVaultErr
	}
	return []model.CertificateVersion{{CertificateID: certID, Version: 1, Current: true, Enabled: true}}, nil
}
func (s *recordingCertService) GetCertificateVersion(_ context.Context, certID uuid.UUID, version int, scope model.Scope) (*model.CertificateVersion, error) {
	s.versionCalls = append(s.versionCalls, "get")
	s.versionScope = scope
	if s.getInVaultErr != nil {
		return nil, s.getInVaultErr
	}
	return &model.CertificateVersion{CertificateID: certID, Version: version, Current: true, Enabled: true}, nil
}
func (s *recordingCertService) UpdateCertificateVersion(_ context.Context, req certServices.UpdateCertificateVersionRequest) (*model.CertificateVersion, error) {
	s.versionCalls = append(s.versionCalls, "update")
	s.versionScope = req.Scope
	if s.getInVaultErr != nil {
		return nil, s.getInVaultErr
	}
	return &model.CertificateVersion{CertificateID: req.CertID, Version: req.Version, Current: true, Enabled: true}, nil
}
```

- [ ] **Step 6: Wire the container**

In `internal/container/service_container.go`: after the `certificateRepository` field add `certificateVersionRepository repositories.CertificateVersionRepositoryInterface`; after `c.certificateRepository = repositories.NewCertificateRepository(c.conn, c.logger)` add `c.certificateVersionRepository = repositories.NewCertificateVersionRepository(c.conn, c.logger)`; in the `certServices.CertificateServiceConfig` literal add `VersionRepository:     c.certificateVersionRepository,`.

In `internal/container/container_test.go`, `TestNewServiceContainer_Success_CacheDisabled`, after the `GetCertificatePolicyRepository` assertion add:

```go
	assert.NotNil(t, container.certificateVersionRepository, "certificateVersionRepository must be wired, or renewal fails closed")
```

- [ ] **Step 7: Run and expect PASS**

Run: `go test ./internal/services/certificates -run 'TestRenewCertificate_|TestListCertificateVersions_|TestGetCertificateVersion|TestUpdateCertificateVersion_|TestCertificateVersionMethods_|TestVersioning_|TestCertificateVersions_' -v`
Expected: PASS.

Run: `go build ./... && go vet ./... && go test ./internal/services/... ./internal/certcache ./internal/container ./api ./cmd/...`
Expected: PASS.

- [ ] **Step 8: Commit**

Commit via the `dev-workflow-skills:1-git-commit` skill. Stage: `internal/services/certificates/certificate_service.go`, `internal/services/certificates/version_repo_fake_test.go`, `internal/services/certificates/certificate_versions_test.go`, `internal/services/certificates/versioning_integration_test.go`, `internal/services/certificates/certificate_service_extended_test.go`, `internal/services/certificates/ca_opt_in_test.go`, `internal/services/certificates/cert_soft_delete_test.go`, `internal/services/certificates/renewal_service_test.go`, `internal/services/certificates/mocks/mock_CertificateService.go`, `internal/certcache/cache_integration.go`, `internal/services/retry/retry_certificate_service.go`, `internal/container/service_container.go`, `internal/container/container_test.go`, `api/certificates_test.go`, `api/vault_scoped_keys_certs_test.go`, `cmd/certificates/certs_cmd_test.go`.

---

### Task 5: Cache and retry behavior, and the auto-renew scheduler

**Files:**
- Modify: `internal/services/certificates/renewal_service.go:78-84` (validity computation), append `CurrentValidityDays`
- Test: `internal/certcache/cache_versions_test.go` (create), `internal/services/retry/retry_certificate_versions_test.go` (create), `internal/services/certificates/validity_days_test.go` (create), `internal/services/certificates/versioning_integration_test.go` (append)

**Interfaces:**
- Consumes: `mocks.NewMockCertificateService` (Task 4 regeneration), `versioningHarness` (Task 4), `noopRetryService` (`retry_wrappers_test.go`).
- Produces: `func CurrentValidityDays(cert *model.Certificate) int` in package `certificates`.

- [ ] **Step 1: Write the failing tests**

Create `internal/certcache/cache_versions_test.go`:

```go
package certcache

import (
	"context"
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

func newVersionTestCache(t *testing.T) *Cache {
	t.Helper()
	c := NewCache(cachekit.Config{Enabled: true, TTL: 5 * time.Minute, CleanupInterval: time.Minute, MaxEntries: 100}, logrus.New())
	t.Cleanup(c.Stop)
	return c
}

func TestCachedUpdateCertificateVersion_EvictsOnlyForCurrentVersion(t *testing.T) {
	ctx := context.Background()
	c := newVersionTestCache(t)
	vaultID := uuid.New()
	scope := model.NewVaultScope(vaultID, uuid.New())
	cert := &model.Certificate{ID: uuid.New(), VaultID: vaultID, Name: "c", Enabled: true, Version: 3}
	require.NoError(t, c.Set(ctx, cert, scope))

	inner := mocks.NewMockCertificateService(t)
	svc := NewCachedCertificateService(inner, c, logrus.New())

	archivedReq := certificates.UpdateCertificateVersionRequest{CertID: cert.ID, Version: 2, Scope: scope}
	inner.On("UpdateCertificateVersion", mock.Anything, archivedReq).
		Return(&model.CertificateVersion{CertificateID: cert.ID, Version: 2}, nil)
	_, err := svc.UpdateCertificateVersion(ctx, archivedReq)
	require.NoError(t, err)
	_, found := c.Get(ctx, cert.ID, scope)
	assert.True(t, found, "archived versions are not cached, so the entry stays")

	currentReq := certificates.UpdateCertificateVersionRequest{CertID: cert.ID, Version: 3, Scope: scope}
	inner.On("UpdateCertificateVersion", mock.Anything, currentReq).
		Return(&model.CertificateVersion{CertificateID: cert.ID, Version: 3, Current: true}, nil)
	_, err = svc.UpdateCertificateVersion(ctx, currentReq)
	require.NoError(t, err)
	_, found = c.Get(ctx, cert.ID, scope)
	assert.False(t, found, "the current version's attributes live on the cached row")
}

func TestCachedRenewCertificate_Evicts(t *testing.T) {
	ctx := context.Background()
	c := newVersionTestCache(t)
	vaultID := uuid.New()
	scope := model.NewVaultScope(vaultID, uuid.New())
	cert := &model.Certificate{ID: uuid.New(), VaultID: vaultID, Name: "c", Enabled: true, Version: 1}
	require.NoError(t, c.Set(ctx, cert, scope))

	inner := mocks.NewMockCertificateService(t)
	inner.On("RenewCertificate", mock.Anything, cert.ID, scope, 30).
		Return(&certificates.CreateCertificateResult{CertID: cert.ID, Version: 2}, nil)
	svc := NewCachedCertificateService(inner, c, logrus.New())

	_, err := svc.RenewCertificate(ctx, cert.ID, scope, 30)
	require.NoError(t, err)
	_, found := c.Get(ctx, cert.ID, scope)
	assert.False(t, found)
}
```

Create `internal/services/retry/retry_certificate_versions_test.go`:

```go
package retry

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"rocketvault/internal/services/certificates"
	"rocketvault/internal/services/certificates/mocks"
	"rocketvault/model"
)

func TestRetryCertificateService_VersionMethodsDelegate(t *testing.T) {
	ctx := context.Background()
	inner := mocks.NewMockCertificateService(t)
	certID := uuid.New()
	scope := model.NewVaultScope(uuid.New(), uuid.New())
	req := certificates.UpdateCertificateVersionRequest{CertID: certID, Version: 1, Scope: scope}

	inner.On("ListCertificateVersions", mock.Anything, certID, scope).
		Return([]model.CertificateVersion{{Version: 1, Current: true}}, nil)
	inner.On("GetCertificateVersion", mock.Anything, certID, 1, scope).
		Return(&model.CertificateVersion{Version: 1, Current: true}, nil)
	inner.On("UpdateCertificateVersion", mock.Anything, req).
		Return(&model.CertificateVersion{Version: 1, Current: true}, nil)

	svc := NewRetryCertificateService(inner, &noopRetryService{})

	list, err := svc.ListCertificateVersions(ctx, certID, scope)
	require.NoError(t, err)
	assert.Len(t, list, 1)
	one, err := svc.GetCertificateVersion(ctx, certID, 1, scope)
	require.NoError(t, err)
	assert.True(t, one.Current)
	updated, err := svc.UpdateCertificateVersion(ctx, req)
	require.NoError(t, err)
	assert.Equal(t, 1, updated.Version)
}
```

Create `internal/services/certificates/validity_days_test.go`:

```go
package certificates

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"rocketvault/model"
)

func TestCurrentValidityDays(t *testing.T) {
	now := time.Now()
	in90 := now.Add(90 * 24 * time.Hour)
	past := now.Add(-time.Hour)

	assert.Equal(t, 90, CurrentValidityDays(&model.Certificate{CreatedAt: now, ExpiresAt: &in90}))
	assert.Equal(t, 365, CurrentValidityDays(&model.Certificate{CreatedAt: now}), "no expiry falls back to 365")
	assert.Equal(t, 365, CurrentValidityDays(&model.Certificate{ExpiresAt: &in90}), "no creation time falls back to 365")
	assert.Equal(t, 365, CurrentValidityDays(&model.Certificate{CreatedAt: now, ExpiresAt: &past}), "a non-positive period falls back to 365")
	assert.Equal(t, 365, CurrentValidityDays(nil))
}
```

Append to `internal/services/certificates/versioning_integration_test.go`:

```go
func TestCheckAndRenewCertificates_CreatesVersionWithPreservedValidity(t *testing.T) {
	h := newVersioningHarness(t)
	ctx := context.Background()
	certID := h.createCert(t, "auto-renewed")

	// Move the certificate into its renewal window, with a 365-day validity.
	now := time.Now().UTC()
	created := now.Add(-355 * 24 * time.Hour)
	expires := now.Add(10 * 24 * time.Hour)
	_, err := h.raw.Exec("UPDATE certificates SET created_at = ?, expires_at = ?, auto_renew = ?, renewal_days = ? WHERE id = ?",
		created, expires, true, 30, certID.String())
	require.NoError(t, err)

	scheduler := NewCertificateRenewalService(RenewalServiceConfig{
		CertRepository:     h.certRepo,
		CertificateService: h.svc,
		Logger:             newTestCertLogger(),
	})
	renewed, warned, err := scheduler.CheckAndRenewCertificates(ctx)
	require.NoError(t, err)
	assert.Equal(t, 1, renewed)
	assert.Zero(t, warned)

	versions, err := h.svc.ListCertificateVersions(ctx, certID, h.scope())
	require.NoError(t, err)
	require.Len(t, versions, 2)
	assert.Equal(t, 1, versions[0].Version)
	assert.False(t, versions[0].Current)
	require.NotNil(t, versions[0].ExpiresAt)
	assert.WithinDuration(t, expires, *versions[0].ExpiresAt, time.Second)

	assert.Equal(t, 2, versions[1].Version)
	assert.True(t, versions[1].Current)
	require.NotNil(t, versions[1].ExpiresAt)
	assert.WithinDuration(t, time.Now().AddDate(0, 0, 365), *versions[1].ExpiresAt, 24*time.Hour,
		"validity is computed from the current version's created_at and expires_at")
}
```

- [ ] **Step 2: Run and expect FAIL**

Run: `go test ./internal/services/certificates -run 'TestCurrentValidityDays|TestCheckAndRenewCertificates_CreatesVersion' -v`
Expected: FAIL (build error: `CurrentValidityDays` undefined).

Run: `go test ./internal/certcache ./internal/services/retry -run 'Version|TestCachedRenewCertificate_Evicts' -v`
Expected: PASS already (Task 4 wrote the behavior); these pin it.

- [ ] **Step 3: Implement `CurrentValidityDays` and use it in the scheduler**

Append to `internal/services/certificates/renewal_service.go`:

```go
// CurrentValidityDays returns the validity period of cert's current version
// in whole days: expires_at minus created_at. It falls back to 365 when
// either is missing or the difference is not positive. The auto-renew
// scheduler and the renew route both use it, so a renewal without an
// explicit validity keeps the period the certificate already had.
func CurrentValidityDays(cert *model.Certificate) int {
	if cert == nil || cert.CreatedAt.IsZero() || cert.ExpiresAt == nil {
		return 365
	}
	days := int(cert.ExpiresAt.Sub(cert.CreatedAt).Hours() / 24)
	if days <= 0 {
		return 365
	}
	return days
}
```

In `CheckAndRenewCertificates`, replace

```go
			// Preserve original validity period when renewing.
			validityDays := 365
			if !cert.CreatedAt.IsZero() && cert.ExpiresAt != nil {
				validityDays = int(cert.ExpiresAt.Sub(cert.CreatedAt).Hours() / 24)
			}
			if validityDays <= 0 {
				validityDays = 365
			}
```

with

```go
			// Preserve the current version's validity period when renewing.
			validityDays := CurrentValidityDays(&cert)
```

- [ ] **Step 4: Run and expect PASS**

Run: `go test ./internal/services/certificates ./internal/certcache ./internal/services/retry -v -run 'Version|Validity|CheckAndRenew|TestCachedRenewCertificate_Evicts'`
Expected: PASS.

- [ ] **Step 5: Commit**

Commit via the `dev-workflow-skills:1-git-commit` skill. Stage: `internal/services/certificates/renewal_service.go`, `internal/services/certificates/validity_days_test.go`, `internal/services/certificates/versioning_integration_test.go`, `internal/certcache/cache_versions_test.go`, `internal/services/retry/retry_certificate_versions_test.go`.

---

### Task 6: Version-aware certificate backup and restore

**Files:**
- Modify: `internal/backup/item_backup.go:55-59` (tx interfaces), `:64-70` (service struct), after `:92` (setter), `:112-115` (`blobVersions`), `:122-128` (`backupEnvelope`), `:353-420` (`BackupCertificate`, `RestoreCertificate`, `restoreCertificateWith`), `:422-465` (`encodeBlob`, `decodeBlob`)
- Modify: `internal/container/service_container.go:730-741` (backup wiring)
- Test: `internal/backup/item_backup_cert_versions_test.go` (create)

**Interfaces:**
- Consumes: `repositories.CertificateVersionRepositoryInterface`, `CreateVersionTx` (Task 2); `backup.ExportedEncodeBlob`, `backup.ExportedBlobVersions` (`export_test.go`).
- Produces: `func (s *ItemBackupService) SetCertificateVersionRepository(repo repositories.CertificateVersionRepositoryInterface)`; `blobVersions.Certificate []model.CertificateVersionRecord`; envelope field `certificate_versions`; `func validateCertificateVersions(current int, versions []model.CertificateVersionRecord) error`.

- [ ] **Step 1: Write the failing tests**

Create `internal/backup/item_backup_cert_versions_test.go`:

```go
package backup_test

import (
	"context"
	"database/sql"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	_ "github.com/mattn/go-sqlite3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"rocketvault/internal/backup"
	rvdb "rocketvault/internal/db"
	"rocketvault/internal/logging"
	"rocketvault/internal/repositories"
	"rocketvault/model"
)

type certBackupFixture struct {
	raw      *sql.DB
	certs    repositories.CertificateRepositoryInterface
	versions repositories.CertificateVersionRepositoryInterface
	svc      *backup.ItemBackupService
	userID   uuid.UUID
	vaultID  uuid.UUID
}

func newCertBackupFixture(t *testing.T) *certBackupFixture {
	t.Helper()
	raw, err := sql.Open("sqlite3", "file:certbackup_"+uuid.NewString()+"?mode=memory&cache=shared")
	require.NoError(t, err)
	t.Cleanup(func() { raw.Close() }) //nolint:errcheck,gosec
	require.NoError(t, rvdb.NewRepository(logging.InitLogger()).SetupSchema(raw, rvdb.SQLite))

	conn := rvdb.NewConn(raw, rvdb.SQLite)
	log := logging.InitLogger()
	f := &certBackupFixture{
		raw:      raw,
		certs:    repositories.NewCertificateRepository(conn, log),
		versions: repositories.NewCertificateVersionRepository(conn, log),
		userID:   uuid.New(),
		vaultID:  uuid.New(),
	}
	f.svc = backup.NewItemBackupService(nil, nil, f.certs, nil)
	f.svc.SetTxBeginner(conn)
	f.svc.SetCertificateVersionRepository(f.versions)
	return f
}

// seedCertAtVersion3 stores a certificate whose history is versions 1 and 2.
func (f *certBackupFixture) seedCertAtVersion3(t *testing.T) *model.Certificate {
	t.Helper()
	ctx := context.Background()
	cert := &model.Certificate{
		ID: uuid.New(), UserID: f.userID, VaultID: f.vaultID, KeyID: uuid.New(),
		Name: "backed-up-" + uuid.NewString()[:8], Certificate: "PEM-v3", PrivateKey: "ENC-v3",
		CreatedAt: time.Now().UTC(), Enabled: true, RenewalDays: 30, Version: 3,
	}
	require.NoError(t, f.certs.Create(ctx, cert))
	for _, n := range []int{1, 2} {
		rec := &model.CertificateVersionRecord{
			CertificateID: cert.ID, Version: n, Certificate: "PEM-v" + string(rune('0'+n)),
			PrivateKey: "ENC-v" + string(rune('0'+n)), KeyID: cert.KeyID, CreatedAt: time.Now().UTC(), Enabled: true,
		}
		require.NoError(t, f.versions.CreateVersion(ctx, rec))
	}
	return cert
}

func (f *certBackupFixture) countRows(t *testing.T, query string, id uuid.UUID) int {
	t.Helper()
	var n int
	require.NoError(t, f.raw.QueryRow(query, id.String()).Scan(&n))
	return n
}

func TestCertificateBackupRestore_RoundTripsVersions(t *testing.T) {
	f := newCertBackupFixture(t)
	ctx := context.Background()
	cert := f.seedCertAtVersion3(t)

	blob, err := f.svc.BackupCertificate(ctx, cert.ID, f.userID, f.vaultID)
	require.NoError(t, err)

	// Restore under a new name so the unique (vault, name) index allows it.
	require.NoError(t, f.certs.Delete(ctx, cert.ID))
	newID := uuid.New()
	require.NoError(t, f.svc.RestoreCertificate(ctx, blob, f.userID, f.vaultID, newID))

	restored, err := f.certs.Read(ctx, newID, model.NewVaultScope(f.vaultID, f.userID))
	require.NoError(t, err)
	assert.Equal(t, 3, restored.Version)
	assert.Equal(t, "PEM-v3", restored.Certificate)

	records, err := f.versions.ListVersionRecords(ctx, newID)
	require.NoError(t, err)
	require.Len(t, records, 2)
	assert.Equal(t, []int{1, 2}, []int{records[0].Version, records[1].Version})
	assert.Equal(t, "PEM-v1", records[0].Certificate)
	assert.Equal(t, "ENC-v2", records[1].PrivateKey)
}

// legacyCertificate is the certificate shape a blob written before
// versioning carries: no version field at all.
type legacyCertificate struct {
	ID          uuid.UUID `json:"id"`
	UserID      uuid.UUID `json:"user_id"`
	VaultID     uuid.UUID `json:"vault_id"`
	Name        string    `json:"name"`
	Certificate string    `json:"certificate"`
	PrivateKey  string    `json:"private_key"`
	CreatedAt   time.Time `json:"created_at"`
	Enabled     bool      `json:"enabled"`
}

func TestRestoreCertificate_PreVersioningBlobRestoresAsVersionOne(t *testing.T) {
	f := newCertBackupFixture(t)
	ctx := context.Background()
	id := uuid.New()
	blob, err := backup.ExportedEncodeBlob("certificate", id.String(), legacyCertificate{
		ID: id, UserID: f.userID, VaultID: f.vaultID, Name: "legacy", Certificate: "PEM",
		PrivateKey: "ENC", CreatedAt: time.Now().UTC(), Enabled: true,
	}, backup.ExportedBlobVersions{})
	require.NoError(t, err)

	newID := uuid.New()
	require.NoError(t, f.svc.RestoreCertificate(ctx, blob, f.userID, f.vaultID, newID))

	restored, err := f.certs.Read(ctx, newID, model.NewVaultScope(f.vaultID, f.userID))
	require.NoError(t, err)
	assert.Equal(t, 1, restored.Version)
	assert.Zero(t, f.countRows(t, "SELECT COUNT(*) FROM certificate_versions WHERE certificate_id = ?", newID))
}

// failingCertVersionRepo fails the second archived-version insert, on
// whichever path the restore takes.
type failingCertVersionRepo struct {
	repositories.CertificateVersionRepositoryInterface
	real interface {
		CreateVersionTx(ctx context.Context, ex rvdb.DBTX, rec *model.CertificateVersionRecord) error
	}
	calls int
}

var errInjectedCertVersionFailure = errors.New("injected failure: second archived certificate version")

func (f *failingCertVersionRepo) CreateVersion(ctx context.Context, rec *model.CertificateVersionRecord) error {
	f.calls++
	if f.calls == 2 {
		return errInjectedCertVersionFailure
	}
	return f.CertificateVersionRepositoryInterface.CreateVersion(ctx, rec)
}

func (f *failingCertVersionRepo) CreateVersionTx(ctx context.Context, ex rvdb.DBTX, rec *model.CertificateVersionRecord) error {
	f.calls++
	if f.calls == 2 {
		return errInjectedCertVersionFailure
	}
	return f.real.CreateVersionTx(ctx, ex, rec)
}

func TestRestoreCertificate_FailedReplayRollsBackRestore(t *testing.T) {
	f := newCertBackupFixture(t)
	ctx := context.Background()
	cert := f.seedCertAtVersion3(t)
	blob, err := f.svc.BackupCertificate(ctx, cert.ID, f.userID, f.vaultID)
	require.NoError(t, err)
	require.NoError(t, f.certs.Delete(ctx, cert.ID))

	real, ok := f.versions.(interface {
		CreateVersionTx(ctx context.Context, ex rvdb.DBTX, rec *model.CertificateVersionRecord) error
	})
	require.True(t, ok, "the real version repository is Tx-capable")
	f.svc.SetCertificateVersionRepository(&failingCertVersionRepo{CertificateVersionRepositoryInterface: f.versions, real: real})

	newID := uuid.New()
	err = f.svc.RestoreCertificate(ctx, blob, f.userID, f.vaultID, newID)
	require.ErrorIs(t, err, errInjectedCertVersionFailure)
	assert.Zero(t, f.countRows(t, "SELECT COUNT(*) FROM certificates WHERE id = ?", newID), "the certificate row must roll back")
	assert.Zero(t, f.countRows(t, "SELECT COUNT(*) FROM certificate_versions WHERE certificate_id = ?", newID))
}

// TestRestoreCertificate_RejectsInconsistentVersionNumbers pins Review Focus
// 4: a forged or corrupt blob whose history does not sit strictly below the
// current version is refused before anything is written.
func TestRestoreCertificate_RejectsInconsistentVersionNumbers(t *testing.T) {
	cases := map[string][]int{
		"equal to current": {1, 2},
		"above current":    {3},
		"duplicate":        {1, 1},
		"below one":        {0},
	}
	for name, numbers := range cases {
		t.Run(name, func(t *testing.T) {
			f := newCertBackupFixture(t)
			id := uuid.New()
			var records []model.CertificateVersionRecord
			for _, n := range numbers {
				records = append(records, model.CertificateVersionRecord{CertificateID: id, Version: n, Certificate: "PEM", PrivateKey: "ENC"})
			}
			current := 2
			if name == "above current" {
				current = 3
				records[0].Version = 4
			}
			blob, err := backup.ExportedEncodeBlob("certificate", id.String(), &model.Certificate{
				ID: id, Name: "forged", Certificate: "PEM", PrivateKey: "ENC", Enabled: true, Version: current,
			}, backup.ExportedBlobVersions{Certificate: records})
			require.NoError(t, err)

			newID := uuid.New()
			err = f.svc.RestoreCertificate(context.Background(), blob, f.userID, f.vaultID, newID)
			require.ErrorIs(t, err, backup.ErrInvalidBlob)
			assert.Zero(t, f.countRows(t, "SELECT COUNT(*) FROM certificates WHERE id = ?", newID))
		})
	}
}

// TestBackupCertificate_HistoryWithoutVersionRepoFailsClosed pins Review
// Focus 5: a certificate with history must not be backed up without it.
func TestBackupCertificate_HistoryWithoutVersionRepoFailsClosed(t *testing.T) {
	f := newCertBackupFixture(t)
	cert := f.seedCertAtVersion3(t)
	unwired := backup.NewItemBackupService(nil, nil, f.certs, nil)

	_, err := unwired.BackupCertificate(context.Background(), cert.ID, f.userID, f.vaultID)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no version repository")
}
```

The "equal to current" case uses current 2 with versions `{1, 2}`: version 2 collides with the parent. "above current" uses current 3 with version 4. "duplicate" uses current 2 with `{1, 1}`. "below one" uses current 2 with `{0}`.

- [ ] **Step 2: Run and expect FAIL**

Run: `go test ./internal/backup -run 'TestCertificateBackupRestore_|TestRestoreCertificate_|TestBackupCertificate_History' -v`
Expected: FAIL (build error: `SetCertificateVersionRepository` undefined, `ExportedBlobVersions` has no field `Certificate`).

- [ ] **Step 3: Implement**

In `item_backup.go`, after `txCapableCertRepo` add:

```go
// txCapableCertVersionRepo is CertificateVersionRepositoryInterface's
// Tx-scoped counterpart. See txCapableSecretRepo.
type txCapableCertVersionRepo interface {
	CreateVersionTx(ctx context.Context, ex db.DBTX, rec *model.CertificateVersionRecord) error
}
```

In `ItemBackupService`, after `versionRepo` add `certVersionRepo repositories.CertificateVersionRepositoryInterface`. After `SetTxBeginner` add:

```go
// SetCertificateVersionRepository attaches the certificate version store.
// Without it, BackupCertificate refuses a certificate that has history and
// RestoreCertificate refuses a blob that carries history, rather than
// silently dropping either.
func (s *ItemBackupService) SetCertificateVersionRepository(repo repositories.CertificateVersionRepositoryInterface) {
	s.certVersionRepo = repo
}
```

Replace `blobVersions` and `backupEnvelope` with:

```go
// blobVersions carries whatever version history a resource type has. Every
// field is optional: a key blob populates Key, a secret blob Secret, and a
// certificate blob Certificate.
type blobVersions struct {
	Key         []model.KeyVersionRecord
	Secret      []model.SecretVersion
	Certificate []model.CertificateVersionRecord
}

// backupEnvelope is the internal structure stored inside the opaque blob.
//
// Every version field is omitempty and additive: a blob written before a
// given field existed simply decodes it as nil. That is what lets pre-2026-08
// key blobs, pre-2026-08-20 secret blobs and pre-2026-10-01 certificate blobs
// still restore. Never rename or retype an existing field here, it is a wire
// format.
type backupEnvelope struct {
	ResourceType        string                           `json:"resource_type"`
	ResourceID          string                           `json:"resource_id"`
	Data                json.RawMessage                  `json:"data"`
	Versions            []model.KeyVersionRecord         `json:"versions,omitempty"`             // keys only
	SecretVersions      []model.SecretVersion            `json:"secret_versions,omitempty"`      // secrets only
	CertificateVersions []model.CertificateVersionRecord `json:"certificate_versions,omitempty"` // certificates only
}
```

In `encodeBlob`, add `CertificateVersions: versions.Certificate,` to the envelope literal. In `decodeBlob`, change the final return to:

```go
	return blobVersions{Key: envelope.Versions, Secret: envelope.SecretVersions, Certificate: envelope.CertificateVersions}, nil
```

Replace `BackupCertificate`, `RestoreCertificate` and `restoreCertificateWith` with:

```go
// BackupCertificate creates a base64url-encoded backup blob for the given
// certificate, archived versions included.
//
// vaultID is the vault the caller's request was authorized against. See
// BackupKey for why the scoped read replaces the previous unscoped read plus
// ownership comparison.
func (s *ItemBackupService) BackupCertificate(ctx context.Context, id, userID, vaultID uuid.UUID) (string, error) {
	cert, err := s.certRepo.Read(ctx, id, model.NewVaultScope(vaultID, userID))
	if err != nil {
		return "", fmt.Errorf("backup certificate: %w", err)
	}

	// Version rows are fetched by certificate ID; the scoped read above is
	// their authorization. A certificate with history and no version store
	// fails closed: a blob without its history would restore a single
	// version and silently discard the rest (the loss B26 closed for keys).
	var versions []model.CertificateVersionRecord
	switch {
	case s.certVersionRepo != nil:
		versions, err = s.certVersionRepo.ListVersionRecords(ctx, id)
		if err != nil {
			return "", fmt.Errorf("backup certificate: list versions: %w", err)
		}
	case cert.CurrentVersion() > 1:
		return "", fmt.Errorf("backup certificate: %s is at version %d but no version repository is configured", id, cert.CurrentVersion())
	}
	return encodeBlob("certificate", id.String(), cert, blobVersions{Certificate: versions})
}

// validateCertificateVersions refuses a blob whose archived versions do not
// sit strictly below the current one, or repeat a number. A forged or
// corrupt blob is rejected before anything is written.
func validateCertificateVersions(current int, versions []model.CertificateVersionRecord) error {
	seen := make(map[int]bool, len(versions))
	for _, v := range versions {
		if v.Version < 1 || v.Version >= current || seen[v.Version] {
			return fmt.Errorf("%w: certificate version %d is inconsistent with current version %d", ErrInvalidBlob, v.Version, current)
		}
		seen[v.Version] = true
	}
	return nil
}

// RestoreCertificate decodes blob and re-inserts it as newID, owned by
// userID, into vaultID, the vault authorized by the caller's request. The
// blob's archived versions are replayed under their own numbers. See
// RestoreSecret.
func (s *ItemBackupService) RestoreCertificate(ctx context.Context, blob string, userID, vaultID, newID uuid.UUID) error {
	var cert model.Certificate
	versions, err := decodeBlob(blob, "certificate", &cert)
	if err != nil {
		return err
	}
	if err := validateCertificateVersions(cert.CurrentVersion(), versions.Certificate); err != nil {
		return err
	}
	if len(versions.Certificate) > 0 && s.certVersionRepo == nil {
		return fmt.Errorf("restore certificate: blob carries %d versions but no version repository is configured", len(versions.Certificate))
	}
	cert.ID = newID
	cert.UserID = userID
	cert.VaultID = vaultID

	if txCertRepo, repoOK := s.certRepo.(txCapableCertRepo); repoOK && s.txBeginner != nil {
		txVersionRepo, versionOK := s.certVersionRepo.(txCapableCertVersionRepo)
		if len(versions.Certificate) == 0 || versionOK {
			return s.withTx(ctx, func(tx *db.Tx) error {
				return s.restoreCertificateWith(ctx, &cert, versions.Certificate, newID,
					func(ctx context.Context, c *model.Certificate) error { return txCertRepo.CreateTx(ctx, tx, c) },
					func(ctx context.Context, rec *model.CertificateVersionRecord) error {
						return txVersionRepo.CreateVersionTx(ctx, tx, rec)
					},
					func(ctx context.Context, id uuid.UUID, enabled bool) error {
						return txCertRepo.SetPurgeProtectionTx(ctx, tx, id, enabled)
					},
				)
			})
		}
	}
	// See RestoreSecret for why these are closures, not bare method values.
	return s.restoreCertificateWith(ctx, &cert, versions.Certificate, newID,
		func(ctx context.Context, c *model.Certificate) error { return s.certRepo.Create(ctx, c) },
		func(ctx context.Context, rec *model.CertificateVersionRecord) error {
			return s.certVersionRepo.CreateVersion(ctx, rec)
		},
		func(ctx context.Context, id uuid.UUID, enabled bool) error {
			return s.certRepo.SetPurgeProtection(ctx, id, enabled)
		},
	)
}

// restoreCertificateWith is RestoreCertificate's write sequence: create,
// replay versions, re-apply purge protection, parameterized the same way
// restoreSecretWith is. See restoreSecretWith for why this shape exists and
// why versions are replayed before purge protection.
func (s *ItemBackupService) restoreCertificateWith(
	ctx context.Context,
	cert *model.Certificate,
	versions []model.CertificateVersionRecord,
	newID uuid.UUID,
	create func(context.Context, *model.Certificate) error,
	createVersion func(context.Context, *model.CertificateVersionRecord) error,
	setPurgeProtection func(context.Context, uuid.UUID, bool) error,
) error {
	if err := create(ctx, cert); err != nil {
		return err
	}
	for _, v := range versions {
		v.CertificateID = newID
		if err := createVersion(ctx, &v); err != nil {
			return fmt.Errorf("restore certificate: create version %d: %w", v.Version, err)
		}
	}
	// See restoreSecretWith: Create does not write purge_protection.
	if cert.PurgeProtection {
		if err := setPurgeProtection(ctx, newID, true); err != nil {
			return fmt.Errorf("restore certificate: set purge protection: %w", err)
		}
	}
	return nil
}
```

In `internal/container/service_container.go`, after `c.itemBackupService.SetTxBeginner(c.conn)` add:

```go
	// Certificate backups carry their archived versions, and restores
	// replay them in the same transaction.
	c.itemBackupService.SetCertificateVersionRepository(c.certificateVersionRepository)
```

- [ ] **Step 4: Run and expect PASS**

Run: `go test ./internal/backup -run 'TestCertificateBackupRestore_|TestRestoreCertificate_|TestBackupCertificate_History' -v`
Expected: PASS.

Run: `go test ./internal/backup ./api -run 'Backup|Restore'`
Expected: PASS.

- [ ] **Step 5: Commit**

Commit via the `dev-workflow-skills:1-git-commit` skill. Stage: `internal/backup/item_backup.go`, `internal/backup/item_backup_cert_versions_test.go`, `internal/container/service_container.go`.

---

### Task 7: Master-key rotation re-encrypts archived certificate keys

**Files:**
- Modify: `internal/rekey/targets.go:52-60` (`Targets`)
- Modify tests: `internal/rekey/rekey_test.go:28-41` (`newTestDB`), `:74-81` (`seedAllTargets`), `:91-92`, `:96-102`, `:123`; `internal/rekey/classify_test.go:94-107`
- Test: `internal/rekey/targets_schema_test.go` (create)

**Interfaces:**
- Consumes: `rvdb.NewRepository(...).SetupSchema` (live schema).
- Produces: a sixth `Target{Table: "certificate_versions", Column: "private_key", KeyColumns: []string{"certificate_id", "version"}}`.

- [ ] **Step 1: Write the failing drift guard**

Create `internal/rekey/targets_schema_test.go`:

```go
package rekey

import (
	"database/sql"
	"strings"
	"testing"

	_ "github.com/mattn/go-sqlite3"
	"github.com/stretchr/testify/require"

	rvdb "rocketvault/internal/db"
	"rocketvault/internal/logging"
)

// TestTargets_MatchLiveSchema is the drift guard for Targets. Every target
// must name a real table and columns, and every "<singular>_versions" table
// whose parent is a target must itself be a target: archived version rows
// hold the same sealed material as their parent, and a missed one stays
// sealed under a retired master key.
func TestTargets_MatchLiveSchema(t *testing.T) {
	raw, err := sql.Open("sqlite3", ":memory:")
	require.NoError(t, err)
	raw.SetMaxOpenConns(1)
	defer raw.Close() //nolint:errcheck
	require.NoError(t, rvdb.NewRepository(logging.InitLogger()).SetupSchema(raw, rvdb.SQLite))

	columns := func(table string) map[string]bool {
		rows, err := raw.Query("SELECT name FROM pragma_table_info(?)", table)
		require.NoError(t, err)
		defer rows.Close() //nolint:errcheck
		out := map[string]bool{}
		for rows.Next() {
			var name string
			require.NoError(t, rows.Scan(&name))
			out[name] = true
		}
		require.NoError(t, rows.Err())
		return out
	}

	targeted := map[string]bool{}
	for _, target := range Targets() {
		cols := columns(target.Table)
		require.NotEmpty(t, cols, "target table %q does not exist", target.Table)
		require.True(t, cols[target.Column], "target %s has no column %s", target.Table, target.Column)
		for _, key := range target.KeyColumns {
			require.True(t, cols[key], "target %s has no key column %s", target.Table, key)
		}
		targeted[target.Table] = true
	}

	for table := range targeted {
		versions := strings.TrimSuffix(table, "s") + "_versions"
		if len(columns(versions)) > 0 {
			require.True(t, targeted[versions], "%s holds %s's archived material and must be a rekey target", versions, table)
		}
	}
}
```

- [ ] **Step 2: Run and expect FAIL**

Run: `go test ./internal/rekey -run TestTargets_MatchLiveSchema -v`
Expected: FAIL with `certificate_versions holds certificates's archived material and must be a rekey target`.

- [ ] **Step 3: Implement and update the fixtures**

In `Targets()`, after the `certificates` entry add:

```go
		{Table: "certificate_versions", Column: "private_key", KeyColumns: []string{"certificate_id", "version"}},
```

Update its doc comment's list to read "secrets and their version history, software (non-HSM) key PEMs and their version history, and certificate private-key PEMs and their version history."

In `rekey_test.go`, `newTestDB`, after `CREATE TABLE certificates (id TEXT PRIMARY KEY, private_key TEXT NOT NULL);` add:

```sql
		CREATE TABLE certificate_versions (
			certificate_id TEXT NOT NULL,
			version        INTEGER NOT NULL,
			private_key    TEXT NOT NULL,
			PRIMARY KEY (certificate_id, version)
		);
```

and change its comment from "the five master-key-encrypted tables" to "the six master-key-encrypted tables". In `seedAllTargets` add:

```go
	exec(t, conn, "INSERT INTO certificate_versions (certificate_id, version, private_key) VALUES (?, ?, ?)", "c1", 1, seal(t, "cert-pem-v1", key))
```

In `TestRun_ReEncryptsEveryTarget` change `5` to `6` on both assertions and add to the query map:

```go
		"SELECT private_key FROM certificate_versions WHERE certificate_id = 'c1' AND version = 1": "cert-pem-v1",
```

In `TestRun_DryRunReportsWithoutWriting` (line 123) change `5` to `6`. Leave `TestRun_BatchSizeSmallerThanRowCount` (five secrets) at `5`.

In `classify_test.go`, `TestTargets_CoverEveryMasterKeyColumn`, add `"certificate_versions": "private_key",` to the expected map.

- [ ] **Step 4: Run and expect PASS**

Run: `go test ./internal/rekey -v`
Expected: PASS.

- [ ] **Step 5: Commit**

Commit via the `dev-workflow-skills:1-git-commit` skill. Stage: `internal/rekey/targets.go`, `internal/rekey/targets_schema_test.go`, `internal/rekey/rekey_test.go`, `internal/rekey/classify_test.go`.

---

### Task 8: Authorization mapping, HTTP routes, error mapping and the OpenAPI spec

**Files:**
- Modify: `internal/services/authorization/data_actions.go:247-266` (`mapCertificateAction`)
- Modify: `api/context.go` (after `SetNotFound`, `:119-122`), `api/errors_certificate.go:19-33`, `api/certificates.go:68-79` (`CertificateResponse`), `:103-115` (`registerCertificateRoutes`), `:117-131` (`certToDomainResponse`), `:214-225` (create response)
- Create: `api/certificates_versions.go`
- Modify: `docs/api-specification.yaml` (paths before `:3707` and `:3952`, responses after `NotFound` `:4631`, schemas before `CertificateListResponse` `:6671`, `CertificateResponse` `:6632-6669`), regenerate `docs/api-routes.generated.txt`
- Modify tests: `internal/services/authorization/data_actions_test.go:66-78` and `:146-153`, `api/certificates_test.go` (`TestCertToDomainResponse_PopulatesFields`), `api/vault_scoped_keys_certs_test.go` (`recordingCertService.RenewCertificate`)
- Test: `api/certificates_versions_test.go` (create)

**Interfaces:**
- Consumes: service methods and `UpdateCertificateVersionRequest` (Task 4), `certServices.CurrentValidityDays` (Task 5), sentinels (Task 1).
- Produces: `func (c *Context) SetConflict(message string)`; `func writeCertificateRenewError(c *Context, err error)`; handlers `listCertificateVersions`, `getCertificateVersion`, `updateCertificateVersion`, `renewCertificate`; `UpdateCertificateVersionAPIRequest`, `RenewCertificateAPIRequest`, `CertificateVersionListResponse`; `CertificateResponse.Version int` (`json:"version"`); routes `GET …/versions`, `GET|PUT …/versions/{version}`, `POST …/renew` on both shapes. Response bodies: list `{"versions":[CertificateVersion...]}`, get, put and renew a single `CertificateVersion`.

- [ ] **Step 1: Write the failing mapping test cases**

In `data_actions_test.go`, `TestMapRouteToDataAction`, after the `purge certificate` case add:

```go
		{"list certificate versions", http.MethodGet, "/api/v1/certificates/abc/versions", model.ActionCertificatesRead, RouteVaultData},
		{"get certificate version", http.MethodGet, "/api/v1/certificates/abc/versions/2", model.ActionCertificatesRead, RouteVaultData},
		{"update certificate version", http.MethodPut, "/api/v1/certificates/abc/versions/2", model.ActionCertificatesUpdate, RouteVaultData},
		{"renew certificate", http.MethodPost, "/api/v1/certificates/abc/renew", model.ActionCertificatesCreate, RouteVaultData},
```

In `TestMapRouteToDataActionUnmappedMethodFailsClosed`, add to `cases`:

```go
		{http.MethodDelete, "/api/v1/certificates/abc/versions/2"},
		{http.MethodPost, "/api/v1/certificates/abc/versions"},
		{http.MethodGet, "/api/v1/certificates/abc/renew"},
		{http.MethodGet, "/api/v1/certificates/abc/versions/2/extra"},
```

- [ ] **Step 2: Write the failing handler and route tests**

Create `api/certificates_versions_test.go`:

```go
package api

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	certServices "rocketvault/internal/services/certificates"
	"rocketvault/model"
)

// runCertVersionHandler calls handler directly with the given params and body.
func runCertVersionHandler(t *testing.T, svc *mockCertService, params *ApiParams, method, body string,
	handler func(*Context, http.ResponseWriter, *http.Request)) *httptest.ResponseRecorder {
	t.Helper()
	c := newCertCtx(svc, certAdminClaims())
	params.PerPage = 60
	c.Params = params
	w := httptest.NewRecorder()
	var r *http.Request
	if body == "" {
		r = httptest.NewRequest(method, "/certificates", nil)
	} else {
		r = httptest.NewRequest(method, "/certificates", bytes.NewBufferString(body))
	}
	handler(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}
	return w
}

func TestListCertificateVersions_Statuses(t *testing.T) {
	certID := uuid.New()

	ok := &mockCertService{}
	ok.On("ListCertificateVersions", mock.Anything, certID, certLegacyVaultScope()).Return([]model.CertificateVersion{
		{CertificateID: certID, Version: 1}, {CertificateID: certID, Version: 2, Current: true},
	}, nil)
	w := runCertVersionHandler(t, ok, &ApiParams{CertificateID: certID.String()}, http.MethodGet, "", listCertificateVersions)
	require.Equal(t, http.StatusOK, w.Code)
	var body CertificateVersionListResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
	assert.Len(t, body.Versions, 2)

	missing := &mockCertService{}
	missing.On("ListCertificateVersions", mock.Anything, certID, certLegacyVaultScope()).Return(nil, certServices.ErrCertNotFound)
	w = runCertVersionHandler(t, missing, &ApiParams{CertificateID: certID.String()}, http.MethodGet, "", listCertificateVersions)
	assert.Equal(t, http.StatusNotFound, w.Code)

	w = runCertVersionHandler(t, &mockCertService{}, &ApiParams{CertificateID: "bad"}, http.MethodGet, "", listCertificateVersions)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestGetCertificateVersion_Statuses(t *testing.T) {
	certID := uuid.New()

	w := runCertVersionHandler(t, &mockCertService{}, &ApiParams{CertificateID: certID.String(), Version: 0},
		http.MethodGet, "", getCertificateVersion)
	assert.Equal(t, http.StatusBadRequest, w.Code, "version 0 is a bad version")

	missing := &mockCertService{}
	missing.On("GetCertificateVersion", mock.Anything, certID, 7, certLegacyVaultScope()).
		Return(nil, fmt.Errorf("%w: no version 7", model.ErrCertificateVersionNotFound))
	w = runCertVersionHandler(t, missing, &ApiParams{CertificateID: certID.String(), Version: 7}, http.MethodGet, "", getCertificateVersion)
	assert.Equal(t, http.StatusNotFound, w.Code)

	ok := &mockCertService{}
	ok.On("GetCertificateVersion", mock.Anything, certID, 2, certLegacyVaultScope()).
		Return(&model.CertificateVersion{CertificateID: certID, Version: 2, Enabled: true}, nil)
	w = runCertVersionHandler(t, ok, &ApiParams{CertificateID: certID.String(), Version: 2}, http.MethodGet, "", getCertificateVersion)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestUpdateCertificateVersion_Statuses(t *testing.T) {
	certID := uuid.New()

	w := runCertVersionHandler(t, &mockCertService{}, &ApiParams{CertificateID: certID.String(), Version: 1},
		http.MethodPut, `{}`, updateCertificateVersion)
	assert.Equal(t, http.StatusBadRequest, w.Code, "an update with no attribute is refused")

	w = runCertVersionHandler(t, &mockCertService{}, &ApiParams{CertificateID: certID.String(), Version: 1},
		http.MethodPut, `{not json`, updateCertificateVersion)
	assert.Equal(t, http.StatusBadRequest, w.Code)

	invalid := &mockCertService{}
	invalid.On("UpdateCertificateVersion", mock.Anything, mock.Anything).
		Return(nil, fmt.Errorf("%w: not_before after expires_at", model.ErrInvalidCertificateVersionAttributes))
	w = runCertVersionHandler(t, invalid, &ApiParams{CertificateID: certID.String(), Version: 1},
		http.MethodPut, `{"not_before":"2030-01-02T00:00:00Z","expires_at":"2030-01-01T00:00:00Z"}`, updateCertificateVersion)
	assert.Equal(t, http.StatusBadRequest, w.Code)

	raced := &mockCertService{}
	raced.On("UpdateCertificateVersion", mock.Anything, mock.Anything).
		Return(nil, fmt.Errorf("lost: %w", model.ErrCertificateVersionConflict))
	w = runCertVersionHandler(t, raced, &ApiParams{CertificateID: certID.String(), Version: 1},
		http.MethodPut, `{"enabled":false}`, updateCertificateVersion)
	assert.Equal(t, http.StatusConflict, w.Code)

	disabled := false
	ok := &mockCertService{}
	ok.On("UpdateCertificateVersion", mock.Anything, certServices.UpdateCertificateVersionRequest{
		CertID: certID, Version: 1, Scope: certLegacyVaultScope(), Enabled: &disabled,
	}).Return(&model.CertificateVersion{CertificateID: certID, Version: 1, Current: true}, nil)
	w = runCertVersionHandler(t, ok, &ApiParams{CertificateID: certID.String(), Version: 1},
		http.MethodPut, `{"enabled":false}`, updateCertificateVersion)
	assert.Equal(t, http.StatusOK, w.Code)
	ok.AssertExpectations(t)
}

func TestRenewCertificate_Statuses(t *testing.T) {
	certID := uuid.New()
	scope := certLegacyVaultScope()

	w := runCertVersionHandler(t, &mockCertService{}, &ApiParams{CertificateID: certID.String()},
		http.MethodPost, `{"validity_days":0}`, renewCertificate)
	assert.Equal(t, http.StatusBadRequest, w.Code)

	w = runCertVersionHandler(t, &mockCertService{}, &ApiParams{CertificateID: certID.String()},
		http.MethodPost, `{not json`, renewCertificate)
	assert.Equal(t, http.StatusBadRequest, w.Code)

	denied := &mockCertService{}
	denied.On("RenewCertificate", mock.Anything, certID, scope, 90).Return(nil, certServices.ErrCertLifecycleDenied)
	w = runCertVersionHandler(t, denied, &ApiParams{CertificateID: certID.String()},
		http.MethodPost, `{"validity_days":90}`, renewCertificate)
	assert.Equal(t, http.StatusConflict, w.Code, "the spec maps a lifecycle denial on renew to 409")

	raced := &mockCertService{}
	raced.On("RenewCertificate", mock.Anything, certID, scope, 90).
		Return(nil, fmt.Errorf("lost: %w", model.ErrCertificateVersionConflict))
	w = runCertVersionHandler(t, raced, &ApiParams{CertificateID: certID.String()},
		http.MethodPost, `{"validity_days":90}`, renewCertificate)
	assert.Equal(t, http.StatusConflict, w.Code)

	missing := &mockCertService{}
	missing.On("RenewCertificate", mock.Anything, certID, scope, 90).Return(nil, certServices.ErrCertNotFound)
	w = runCertVersionHandler(t, missing, &ApiParams{CertificateID: certID.String()},
		http.MethodPost, `{"validity_days":90}`, renewCertificate)
	assert.Equal(t, http.StatusNotFound, w.Code)

	internal := &mockCertService{}
	internal.On("RenewCertificate", mock.Anything, certID, scope, 90).Return(nil, errors.New("sql: connection reset by peer"))
	w = runCertVersionHandler(t, internal, &ApiParams{CertificateID: certID.String()},
		http.MethodPost, `{"validity_days":90}`, renewCertificate)
	assert.Equal(t, http.StatusInternalServerError, w.Code)
	// The message is generic ("Internal server error"), but writeError still
	// serializes err.Error() into detailed_error today. Scrubbing that is
	// docs/superpowers/plans/2026-09-30-secrets-and-error-responses.md Task 1;
	// once it lands, add: assert.NotContains(t, w.Body.String(), "connection reset").
	assert.Contains(t, w.Body.String(), "Internal server error")
}

func TestRenewCertificate_DefaultsToCurrentValidity(t *testing.T) {
	certID := uuid.New()
	scope := certLegacyVaultScope()
	created := time.Now().Add(-10 * 24 * time.Hour)
	expires := created.Add(120 * 24 * time.Hour)

	svc := &mockCertService{}
	svc.On("GetCertificate", mock.Anything, certID, scope).
		Return(&model.Certificate{ID: certID, CreatedAt: created, ExpiresAt: &expires, Enabled: true}, nil)
	svc.On("RenewCertificate", mock.Anything, certID, scope, 120).
		Return(&certServices.CreateCertificateResult{CertID: certID, Version: 2}, nil)
	svc.On("GetCertificateVersion", mock.Anything, certID, 2, scope).
		Return(&model.CertificateVersion{CertificateID: certID, Version: 2, Current: true, Enabled: true}, nil)

	w := runCertVersionHandler(t, svc, &ApiParams{CertificateID: certID.String()}, http.MethodPost, "", renewCertificate)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	var got model.CertificateVersion
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &got))
	assert.Equal(t, 2, got.Version)
	svc.AssertExpectations(t)
}

// TestCertificateVersionResponses_CarryNoKeyMaterial pins that no version
// response can carry a PEM or a private key.
func TestCertificateVersionResponses_CarryNoKeyMaterial(t *testing.T) {
	certID := uuid.New()
	scope := certLegacyVaultScope()
	svc := &mockCertService{}
	svc.On("ListCertificateVersions", mock.Anything, certID, scope).
		Return([]model.CertificateVersion{{CertificateID: certID, Version: 1, Current: true}}, nil)
	svc.On("GetCertificateVersion", mock.Anything, certID, 1, scope).
		Return(&model.CertificateVersion{CertificateID: certID, Version: 1, Current: true}, nil)
	svc.On("RenewCertificate", mock.Anything, certID, scope, 30).
		Return(&certServices.CreateCertificateResult{CertID: certID, Version: 1}, nil)

	for name, run := range map[string]func() *httptest.ResponseRecorder{
		"list": func() *httptest.ResponseRecorder {
			return runCertVersionHandler(t, svc, &ApiParams{CertificateID: certID.String()}, http.MethodGet, "", listCertificateVersions)
		},
		"get": func() *httptest.ResponseRecorder {
			return runCertVersionHandler(t, svc, &ApiParams{CertificateID: certID.String(), Version: 1}, http.MethodGet, "", getCertificateVersion)
		},
		"renew": func() *httptest.ResponseRecorder {
			return runCertVersionHandler(t, svc, &ApiParams{CertificateID: certID.String()}, http.MethodPost, `{"validity_days":30}`, renewCertificate)
		},
	} {
		body := strings.ToLower(run().Body.String())
		assert.NotContains(t, body, "private_key", name)
		assert.NotContains(t, body, `"certificate":`, name)
		assert.NotContains(t, body, "begin", name)
	}
}

// TestCertificateVersionRoutes_BothShapes dispatches every new route on the
// flat and the vault-scoped router, and checks the vault each one scoped to.
func TestCertificateVersionRoutes_BothShapes(t *testing.T) {
	certID := uuid.New().String()
	cases := []struct {
		method, suffix, body string
	}{
		{http.MethodGet, "/versions", ""},
		{http.MethodGet, "/versions/1", ""},
		{http.MethodPut, "/versions/1", `{"enabled":true}`},
		{http.MethodPost, "/renew", `{"validity_days":30}`},
	}
	for _, tc := range cases {
		t.Run("flat "+tc.method+tc.suffix, func(t *testing.T) {
			rec := &recordingCertService{}
			api, _ := newVaultScopedKeyCertTestAPI(nil, rec, nil)
			var body []byte
			if tc.body != "" {
				body = []byte(tc.body)
			}
			w := doVaultRequest(api, tc.method, "/api/v1/certificates/"+certID+tc.suffix, body)
			require.Equal(t, http.StatusOK, w.Code, w.Body.String())
			assert.Equal(t, uuid.MustParse(model.DefaultVaultID), rec.versionScope.VaultID())
		})
		t.Run("vault-scoped "+tc.method+tc.suffix, func(t *testing.T) {
			rec := &recordingCertService{}
			api, repo := newVaultScopedKeyCertTestAPI(nil, rec, nil)
			id := uuid.New()
			repo.byName["prod"] = &model.Vault{ID: id, Name: "prod", Enabled: true}
			repo.byID[id.String()] = repo.byName["prod"]
			var body []byte
			if tc.body != "" {
				body = []byte(tc.body)
			}
			w := doVaultRequest(api, tc.method, "/api/v1/vaults/prod/certificates/"+certID+tc.suffix, body)
			require.Equal(t, http.StatusOK, w.Code, w.Body.String())
			assert.Equal(t, id, rec.versionScope.VaultID())
		})
	}
}
```

In `api/vault_scoped_keys_certs_test.go`, replace `recordingCertService.RenewCertificate` (currently `panic("unexpected")`) with:

```go
func (s *recordingCertService) RenewCertificate(_ context.Context, certID uuid.UUID, scope model.Scope, _ int) (*certServices.CreateCertificateResult, error) {
	s.versionCalls = append(s.versionCalls, "renew")
	s.versionScope = scope
	if s.getInVaultErr != nil {
		return nil, s.getInVaultErr
	}
	return &certServices.CreateCertificateResult{CertID: certID, Version: 2}, nil
}
```

In `api/certificates_test.go`, `TestCertToDomainResponse_PopulatesFields`, set `Version: 3` on the input certificate and add `assert.Equal(t, 3, resp.Version)` (use the response variable name that test already uses).

- [ ] **Step 3: Run and expect FAIL**

Run: `go test ./internal/services/authorization -run 'TestMapRouteToDataAction' -v`
Expected: FAIL for `list certificate versions`, `get certificate version`, `update certificate version` (empty action).

Run: `go test ./api -run 'CertificateVersion|RenewCertificate|TestCertToDomainResponse' -v`
Expected: FAIL (build errors: handlers and `CertificateVersionListResponse` undefined).

- [ ] **Step 4: Implement the mapping**

In `mapCertificateAction`, in the `len(seg) == 2` switch, add a case before `case "renew":`:

```go
		case "versions":
			if method == http.MethodGet {
				return model.ActionCertificatesRead, RouteVaultData
			}
```

After the `len(seg) == 2` block and before the final `return "", RouteVaultData`, add:

```go
	if len(seg) == 3 && seg[1] == "versions" {
		switch method {
		case http.MethodGet:
			return model.ActionCertificatesRead, RouteVaultData
		case http.MethodPut:
			return model.ActionCertificatesUpdate, RouteVaultData
		}
	}
```

- [ ] **Step 5: Implement the handlers, error mapping and routes**

In `api/context.go`, after `SetNotFound` add (skip if `docs/superpowers/plans/2026-09-30-secrets-and-error-responses.md` already landed it):

```go
// SetConflict sets a 409 error for a request that collides with existing state.
func (c *Context) SetConflict(message string) {
	c.Err = common.NewAppError("api.context.set_conflict", message, nil, "", http.StatusConflict)
}
```

In `api/errors_certificate.go`, add these cases before `default:`:

```go
	case errors.Is(err, model.ErrCertificateVersionNotFound):
		c.SetNotFound("certificate version")
	case errors.Is(err, model.ErrInvalidCertificateVersionAttributes):
		c.SetInvalidParam("version attributes: at least one of enabled, expires_at or not_before is required, and not_before must not be after expires_at")
	case errors.Is(err, model.ErrCertificateVersionConflict):
		c.SetConflict("certificate was renewed or updated concurrently; re-read it and retry")
```

and append:

```go
// writeCertificateRenewError maps a renewal error. It differs from
// writeCertificateError in one arm: renewal goes through GetCertificate, so a
// disabled certificate, or one outside its valid time window, is refused with
// ErrCertLifecycleDenied, which the design maps to 409 for this route.
func writeCertificateRenewError(c *Context, err error) {
	if errors.Is(err, certServices.ErrCertLifecycleDenied) {
		c.SetConflict("certificate is disabled or outside its valid time window and cannot be renewed")
		return
	}
	writeCertificateError(c, err)
}
```

In `api/certificates.go`: add to `CertificateResponse` after `NotBefore`:

```go
	Version     int        `json:"version"` // The current version number.
```

In `certToDomainResponse` add `Version: cert.CurrentVersion(),`. In `createCertificate`'s `response` literal add `Version: result.Version,`. In `registerCertificateRoutes`, after the policy routes add:

```go
	// Versions sub-resource and renewal. Renewal creates a new version.
	c.Handle("/{certificate_id:[A-Fa-f0-9-]+}/versions", ApiSessionRequired(api.App, listCertificateVersions)).Methods("GET")
	c.Handle("/{certificate_id:[A-Fa-f0-9-]+}/versions/{version:[0-9]+}", ApiSessionRequired(api.App, getCertificateVersion)).Methods("GET")
	c.Handle("/{certificate_id:[A-Fa-f0-9-]+}/versions/{version:[0-9]+}", ApiSessionRequired(api.App, updateCertificateVersion)).Methods("PUT")
	c.Handle("/{certificate_id:[A-Fa-f0-9-]+}/renew", ApiSessionRequired(api.App, renewCertificate)).Methods("POST")
```

Create `api/certificates_versions.go`:

```go
package api

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"time"

	"rocketvault/internal/container"
	certServices "rocketvault/internal/services/certificates"
	"rocketvault/model"
)

// UpdateCertificateVersionAPIRequest is the body for
// PUT /certificates/{certificate_id}/versions/{version}. Nil fields are left
// as they are; at least one is required.
type UpdateCertificateVersionAPIRequest struct {
	Enabled   *bool      `json:"enabled,omitempty"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
	NotBefore *time.Time `json:"not_before,omitempty"`
}

// RenewCertificateAPIRequest is the optional body for
// POST /certificates/{certificate_id}/renew. An omitted validity_days keeps
// the current version's validity period.
type RenewCertificateAPIRequest struct {
	ValidityDays *int `json:"validity_days,omitempty"`
}

// CertificateVersionListResponse is the body for GET .../versions. Every
// entry is metadata only; model.CertificateVersion has no material field.
type CertificateVersionListResponse struct {
	Versions []model.CertificateVersion `json:"versions"`
}

// listCertificateVersions returns a certificate's versions, oldest first,
// with the current one last.
func listCertificateVersions(c *Context, w http.ResponseWriter, r *http.Request) {
	certID, certOK := resourceID(c, c.Params.CertificateID, "certificate_id")
	if !certOK {
		return
	}
	certService, svcOK := svc(c, container.ServiceContainerInterface.GetCertificateService)
	if !svcOK {
		return
	}
	scope, ok := scopeFromRequest(c, r)
	if !ok {
		return
	}

	versions, err := certService.ListCertificateVersions(r.Context(), certID, scope)
	if err != nil {
		writeCertificateError(c, err)
		return
	}
	if versions == nil {
		versions = []model.CertificateVersion{}
	}
	writeJSON(w, CertificateVersionListResponse{Versions: versions})
}

// getCertificateVersion returns one version's metadata.
func getCertificateVersion(c *Context, w http.ResponseWriter, r *http.Request) {
	certID, certOK := resourceID(c, c.Params.CertificateID, "certificate_id")
	if !certOK {
		return
	}
	if c.Params.Version < 1 {
		c.SetInvalidParam("version")
		return
	}
	certService, svcOK := svc(c, container.ServiceContainerInterface.GetCertificateService)
	if !svcOK {
		return
	}
	scope, ok := scopeFromRequest(c, r)
	if !ok {
		return
	}

	version, err := certService.GetCertificateVersion(r.Context(), certID, c.Params.Version, scope)
	if err != nil {
		writeCertificateError(c, err)
		return
	}
	writeJSON(w, version)
}

// updateCertificateVersion changes one version's lifecycle attributes.
func updateCertificateVersion(c *Context, w http.ResponseWriter, r *http.Request) {
	certID, certOK := resourceID(c, c.Params.CertificateID, "certificate_id")
	if !certOK {
		return
	}
	if c.Params.Version < 1 {
		c.SetInvalidParam("version")
		return
	}
	req, bodyOK := decodeBody[UpdateCertificateVersionAPIRequest](c, r)
	if !bodyOK {
		return
	}
	if req.Enabled == nil && req.ExpiresAt == nil && req.NotBefore == nil {
		c.SetInvalidParam("at least one of enabled, expires_at or not_before must be provided")
		return
	}
	certService, svcOK := svc(c, container.ServiceContainerInterface.GetCertificateService)
	if !svcOK {
		return
	}
	scope, ok := scopeFromRequest(c, r)
	if !ok {
		return
	}

	updated, err := certService.UpdateCertificateVersion(r.Context(), certServices.UpdateCertificateVersionRequest{
		CertID:    certID,
		Version:   c.Params.Version,
		Scope:     scope,
		Enabled:   req.Enabled,
		ExpiresAt: req.ExpiresAt,
		NotBefore: req.NotBefore,
	})
	if err != nil {
		writeCertificateError(c, err)
		return
	}
	writeJSON(w, updated)
}

// decodeRenewBody decodes the optional renew body. An empty body is valid
// and means every default.
func decodeRenewBody(c *Context, r *http.Request) (RenewCertificateAPIRequest, bool) {
	var req RenewCertificateAPIRequest
	if r.Body == nil {
		return req, true
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil && !errors.Is(err, io.EOF) {
		c.SetInvalidParam("request body")
		return req, false
	}
	return req, true
}

// renewCertificate issues a new version of a certificate and returns that
// version's metadata. Authorization happens in PolicyMiddleware: renewing
// requires the certificates/create data action (data_actions.go).
func renewCertificate(c *Context, w http.ResponseWriter, r *http.Request) {
	certID, certOK := resourceID(c, c.Params.CertificateID, "certificate_id")
	if !certOK {
		return
	}
	req, bodyOK := decodeRenewBody(c, r)
	if !bodyOK {
		return
	}
	if req.ValidityDays != nil && *req.ValidityDays <= 0 {
		c.SetInvalidParam("validity_days: must be positive")
		return
	}
	certService, svcOK := svc(c, container.ServiceContainerInterface.GetCertificateService)
	if !svcOK {
		return
	}
	scope, ok := scopeFromRequest(c, r)
	if !ok {
		return
	}

	var validityDays int
	if req.ValidityDays != nil {
		validityDays = *req.ValidityDays
	} else {
		current, err := certService.GetCertificate(r.Context(), certID, scope)
		if err != nil {
			writeCertificateRenewError(c, err)
			return
		}
		validityDays = certServices.CurrentValidityDays(current)
	}

	result, err := certService.RenewCertificate(r.Context(), certID, scope, validityDays)
	if err != nil {
		writeCertificateRenewError(c, err)
		return
	}

	version, err := certService.GetCertificateVersion(r.Context(), certID, result.Version, scope)
	if err != nil {
		writeCertificateError(c, err)
		return
	}
	writeJSON(w, version)
}
```

- [ ] **Step 6: Run and expect PASS; then run the drift tests and expect FAIL**

Run: `go test ./internal/services/authorization -run TestMapRouteToDataAction -v && go test ./api -run 'CertificateVersion|RenewCertificate|TestCertToDomainResponse' -v`
Expected: PASS.

Run: `go test ./api -run 'TestOpenAPISpecCoversAllRoutes|TestGenerateRouteInventory' -v`
Expected: FAIL, listing the eight new method+path pairs as undocumented and the inventory as out of date.

- [ ] **Step 7: Document the routes in OpenAPI and regenerate the inventory**

In `docs/api-specification.yaml`, insert immediately before the line `  /api/v1/certificates/{certificate_id}/backup:`:

```yaml
  /api/v1/certificates/{certificate_id}/versions:
    parameters:
      - $ref: "#/components/parameters/CertificateId"
    get:
      summary: List certificate versions
      description: |
        Returns every version of the certificate, oldest first, with the
        current version last and marked `current: true`. Metadata only: no
        certificate body and no private key. A certificate created before
        versioning reports a single version 1. Versions are sequential
        integers, not Azure's 32-hex identifiers.
      operationId: listCertificateVersions
      tags:
        - Certificates
      responses:
        "200":
          description: Certificate versions retrieved successfully
          content:
            application/json:
              schema:
                $ref: "#/components/schemas/CertificateVersionListResponse"
        "400":
          $ref: "#/components/responses/BadRequest"
        "401":
          $ref: "#/components/responses/Unauthorized"
        "403":
          $ref: "#/components/responses/Forbidden"
        "404":
          $ref: "#/components/responses/NotFound"

  /api/v1/certificates/{certificate_id}/versions/{version}:
    parameters:
      - $ref: "#/components/parameters/CertificateId"
      - $ref: "#/components/parameters/Version"
    get:
      summary: Get a certificate version
      description: Returns one version's metadata. No certificate body and no private key.
      operationId: getCertificateVersion
      tags:
        - Certificates
      responses:
        "200":
          description: Certificate version retrieved successfully
          content:
            application/json:
              schema:
                $ref: "#/components/schemas/CertificateVersion"
        "400":
          $ref: "#/components/responses/BadRequest"
        "401":
          $ref: "#/components/responses/Unauthorized"
        "403":
          $ref: "#/components/responses/Forbidden"
        "404":
          $ref: "#/components/responses/NotFound"
    put:
      summary: Update a certificate version's lifecycle attributes
      description: |
        Changes `enabled`, `expires_at` and `not_before` on one version.
        Updating the current version is the same as updating the
        certificate's own attributes. A disabled or expired version is
        unusable, and a disabled certificate gates every version.
      operationId: updateCertificateVersion
      tags:
        - Certificates
      requestBody:
        required: true
        content:
          application/json:
            schema:
              $ref: "#/components/schemas/UpdateCertificateVersionRequest"
      responses:
        "200":
          description: Certificate version updated successfully
          content:
            application/json:
              schema:
                $ref: "#/components/schemas/CertificateVersion"
        "400":
          $ref: "#/components/responses/BadRequest"
        "401":
          $ref: "#/components/responses/Unauthorized"
        "403":
          $ref: "#/components/responses/Forbidden"
        "404":
          $ref: "#/components/responses/NotFound"
        "409":
          $ref: "#/components/responses/Conflict"

  /api/v1/certificates/{certificate_id}/renew:
    parameters:
      - $ref: "#/components/parameters/CertificateId"
    post:
      summary: Renew a certificate
      description: |
        Re-issues the certificate over its key and makes the result the new
        current version. The previous version is archived under its own
        number. Requires the certificates/create data action. A disabled
        certificate, one outside its validity window, or a concurrent renewal
        returns 409.
      operationId: renewCertificate
      tags:
        - Certificates
      requestBody:
        required: false
        content:
          application/json:
            schema:
              $ref: "#/components/schemas/RenewCertificateRequest"
      responses:
        "200":
          description: Certificate renewed; the new version's metadata
          content:
            application/json:
              schema:
                $ref: "#/components/schemas/CertificateVersion"
        "400":
          $ref: "#/components/responses/BadRequest"
        "401":
          $ref: "#/components/responses/Unauthorized"
        "403":
          $ref: "#/components/responses/Forbidden"
        "404":
          $ref: "#/components/responses/NotFound"
        "409":
          $ref: "#/components/responses/Conflict"
        "500":
          $ref: "#/components/responses/InternalError"

```

Insert immediately before the line `  /api/v1/vaults/{vault_name}/certificates/{certificate_id}/backup:`:

```yaml
  /api/v1/vaults/{vault_name}/certificates/{certificate_id}/versions:
    parameters:
      - $ref: "#/components/parameters/VaultName"
      - $ref: "#/components/parameters/CertificateId"
    get:
      summary: List certificate versions in a vault
      description: |
        Returns every version of a certificate held in the named vault,
        oldest first, with the current version last and marked
        `current: true`. Metadata only, matching the flat route.
      operationId: listCertificateVersionsInVault
      tags:
        - Certificates
      responses:
        "200":
          description: Certificate versions retrieved successfully
          content:
            application/json:
              schema:
                $ref: "#/components/schemas/CertificateVersionListResponse"
        "400":
          $ref: "#/components/responses/BadRequest"
        "401":
          $ref: "#/components/responses/Unauthorized"
        "403":
          $ref: "#/components/responses/Forbidden"
        "404":
          $ref: "#/components/responses/NotFound"

  /api/v1/vaults/{vault_name}/certificates/{certificate_id}/versions/{version}:
    parameters:
      - $ref: "#/components/parameters/VaultName"
      - $ref: "#/components/parameters/CertificateId"
      - $ref: "#/components/parameters/Version"
    get:
      summary: Get a certificate version in a vault
      description: Returns one version's metadata for a certificate held in the named vault.
      operationId: getCertificateVersionInVault
      tags:
        - Certificates
      responses:
        "200":
          description: Certificate version retrieved successfully
          content:
            application/json:
              schema:
                $ref: "#/components/schemas/CertificateVersion"
        "400":
          $ref: "#/components/responses/BadRequest"
        "401":
          $ref: "#/components/responses/Unauthorized"
        "403":
          $ref: "#/components/responses/Forbidden"
        "404":
          $ref: "#/components/responses/NotFound"
    put:
      summary: Update a certificate version's lifecycle attributes in a vault
      description: Changes `enabled`, `expires_at` and `not_before` on one version, matching the flat route.
      operationId: updateCertificateVersionInVault
      tags:
        - Certificates
      requestBody:
        required: true
        content:
          application/json:
            schema:
              $ref: "#/components/schemas/UpdateCertificateVersionRequest"
      responses:
        "200":
          description: Certificate version updated successfully
          content:
            application/json:
              schema:
                $ref: "#/components/schemas/CertificateVersion"
        "400":
          $ref: "#/components/responses/BadRequest"
        "401":
          $ref: "#/components/responses/Unauthorized"
        "403":
          $ref: "#/components/responses/Forbidden"
        "404":
          $ref: "#/components/responses/NotFound"
        "409":
          $ref: "#/components/responses/Conflict"

  /api/v1/vaults/{vault_name}/certificates/{certificate_id}/renew:
    parameters:
      - $ref: "#/components/parameters/VaultName"
      - $ref: "#/components/parameters/CertificateId"
    post:
      summary: Renew a certificate in a vault
      description: Re-issues a certificate held in the named vault as a new current version, matching the flat route.
      operationId: renewCertificateInVault
      tags:
        - Certificates
      requestBody:
        required: false
        content:
          application/json:
            schema:
              $ref: "#/components/schemas/RenewCertificateRequest"
      responses:
        "200":
          description: Certificate renewed; the new version's metadata
          content:
            application/json:
              schema:
                $ref: "#/components/schemas/CertificateVersion"
        "400":
          $ref: "#/components/responses/BadRequest"
        "401":
          $ref: "#/components/responses/Unauthorized"
        "403":
          $ref: "#/components/responses/Forbidden"
        "404":
          $ref: "#/components/responses/NotFound"
        "409":
          $ref: "#/components/responses/Conflict"
        "500":
          $ref: "#/components/responses/InternalError"

```

Under `components.responses`, immediately after the `NotFound` response, add:

```yaml
    Conflict:
      description: The request conflicts with the resource's current state
      content:
        application/json:
          schema:
            $ref: "#/components/schemas/ErrorResponse"
```

Under `components.schemas`, immediately before `    CertificateListResponse:`, add:

```yaml
    CertificateVersion:
      type: object
      description: One certificate version. Metadata only; there is no certificate body and no private key.
      required:
        - certificate_id
        - version
        - current
        - created_at
        - enabled
      properties:
        certificate_id:
          type: string
          format: uuid
        version:
          type: integer
          minimum: 1
        current:
          type: boolean
          description: True for the certificate's current version.
        created_at:
          type: string
          format: date-time
        expires_at:
          type: string
          format: date-time
        not_before:
          type: string
          format: date-time
        enabled:
          type: boolean

    CertificateVersionListResponse:
      type: object
      required:
        - versions
      properties:
        versions:
          type: array
          items:
            $ref: "#/components/schemas/CertificateVersion"

    UpdateCertificateVersionRequest:
      type: object
      description: At least one field is required. not_before must not be after expires_at.
      properties:
        enabled:
          type: boolean
        expires_at:
          type: string
          format: date-time
        not_before:
          type: string
          format: date-time

    RenewCertificateRequest:
      type: object
      properties:
        validity_days:
          type: integer
          minimum: 1
          description: Validity of the new version in days. Omitted means the current version's validity period.

```

In `CertificateResponse`, add `- version` to `required` and add the property:

```yaml
        version:
          type: integer
          minimum: 1
          description: The certificate's current version number.
```

Regenerate the inventory:

```bash
go test ./api/... -run TestGenerateRouteInventory -update-route-inventory
```

- [ ] **Step 8: Run and expect PASS**

Run: `go test ./api -run 'TestOpenAPISpecCoversAllRoutes|TestGenerateRouteInventory|TestClientPathsAreRegistered' -v && go test ./api ./internal/services/authorization ./internal/middleware`
Expected: PASS. `git diff docs/api-routes.generated.txt` shows exactly eight added lines (four flat, four vault-scoped).

- [ ] **Step 9: Commit**

Commit via the `dev-workflow-skills:1-git-commit` skill. Stage: `internal/services/authorization/data_actions.go`, `internal/services/authorization/data_actions_test.go`, `api/context.go`, `api/errors_certificate.go`, `api/certificates.go`, `api/certificates_versions.go`, `api/certificates_versions_test.go`, `api/certificates_test.go`, `api/vault_scoped_keys_certs_test.go`, `docs/api-specification.yaml`, `docs/api-routes.generated.txt`.

---

### Task 9: Vault client and MCP server

**Files:**
- Modify: `internal/vaultapi/certificates.go:17-65` (`CertificateSummary`, `certificateWire`, `summary`), append `CertificateVersion` and `GetCertificateVersions`
- Modify: `internal/vaultapi/certificates_write.go` (append `RenewCertificate`)
- Modify: `api/route_contract_test.go:22-29` (`clientCalledRoutes`)
- Modify: `internal/mcpserver/tools_certificates.go:56-67` (`getCertificateResult`), `:128-161` (`handleGetCertificate`)
- Modify: `internal/mcpserver/tools_certificates_write.go:68-83` (registration), append the renew tool
- Modify tests: `internal/mcpserver/gating_table_test.go:24-28` and `:119-124`, `internal/mcpserver/leak_sweep_test.go` (`leakRoutes`)
- Modify docs: `docs/mcp-server.md:76`
- Test: `internal/vaultapi/certificates_versions_test.go` (create), `internal/mcpserver/tools_certificates_versions_test.go` (create)

**Interfaces:**
- Consumes: routes and response shapes from Task 8.
- Produces:
  - `CertificateSummary.Version int`
  - `type CertificateVersion struct { CertificateID uuid.UUID; Version int; Current, Enabled bool; CreatedAt time.Time; ExpiresAt, NotBefore *time.Time }`
  - `func (c *Client) GetCertificateVersions(ctx context.Context, vault, name string) ([]CertificateVersion, error)`
  - `func (c *Client) RenewCertificate(ctx context.Context, vault, name string, validityDays int) (*CertificateVersion, error)`
  - MCP tool `renew_certificate` (write tier); `getCertificateResult.Version`, `getCertificateResult.Versions []certificateVersionResult`.

- [ ] **Step 1: Write the failing client tests**

Create `internal/vaultapi/certificates_versions_test.go`:

```go
package vaultapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
)

const certListForVersions = `{"certificates":[{"id":"` + tlsCertID + `","name":"tls-cert"}]}`

func TestGetCertificateVersions_ResolvesAndDecodesWrapper(t *testing.T) {
	var paths []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/api/v1/vaults/prod/certificates" {
			_, _ = w.Write([]byte(certListForVersions))
			return
		}
		_, _ = w.Write([]byte(`{"versions":[
			{"certificate_id":"` + tlsCertID + `","version":1,"current":false,"enabled":true,"created_at":"2026-08-01T00:00:00Z"},
			{"certificate_id":"` + tlsCertID + `","version":2,"current":true,"enabled":true,"created_at":"2026-09-01T00:00:00Z"}
		]}`))
	}))
	defer srv.Close()

	got, err := newClientForTest(t, srv).GetCertificateVersions(context.Background(), "prod", "tls-cert")
	require.NoError(t, err)
	require.Contains(t, paths, "/api/v1/vaults/prod/certificates/"+tlsCertID+"/versions")
	require.Len(t, got, 2)
	require.Equal(t, 2, got[1].Version)
	require.True(t, got[1].Current)
}

func TestRenewCertificate_PostsValidityAndDecodesVersion(t *testing.T) {
	var body map[string]any
	var renewPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method == http.MethodGet {
			_, _ = w.Write([]byte(certListForVersions))
			return
		}
		renewPath = r.URL.Path
		_ = json.NewDecoder(r.Body).Decode(&body)
		_, _ = w.Write([]byte(`{"certificate_id":"` + tlsCertID + `","version":3,"current":true,"enabled":true,
			"created_at":"2026-10-01T00:00:00Z","expires_at":"2027-10-01T00:00:00Z"}`))
	}))
	defer srv.Close()

	got, err := newClientForTest(t, srv).RenewCertificate(context.Background(), "prod", "tls-cert", 90)
	require.NoError(t, err)
	require.Equal(t, "/api/v1/vaults/prod/certificates/"+tlsCertID+"/renew", renewPath)
	require.Equal(t, float64(90), body["validity_days"])
	require.Equal(t, 3, got.Version)
	require.NotNil(t, got.ExpiresAt)
}

func TestRenewCertificate_OmitsValidityWhenZero(t *testing.T) {
	var body map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method == http.MethodGet {
			_, _ = w.Write([]byte(certListForVersions))
			return
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		_, _ = w.Write([]byte(`{"certificate_id":"` + tlsCertID + `","version":2,"current":true}`))
	}))
	defer srv.Close()

	_, err := newClientForTest(t, srv).RenewCertificate(context.Background(), "prod", "tls-cert", 0)
	require.NoError(t, err)
	require.NotContains(t, body, "validity_days", "zero means keep the current validity period")
}

func TestRenewCertificate_RequiresVaultAndName(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()
	client := newClientForTest(t, srv)

	_, err := client.RenewCertificate(context.Background(), "", "tls-cert", 30)
	require.ErrorContains(t, err, "vault is required")
	_, err = client.RenewCertificate(context.Background(), "prod", "", 30)
	require.ErrorContains(t, err, "name is required")
	_, err = client.RenewCertificate(context.Background(), "prod", "tls-cert", -1)
	require.ErrorContains(t, err, "validity_days")
}
```

- [ ] **Step 2: Run and expect FAIL**

Run: `go test ./internal/vaultapi -run 'CertificateVersions|RenewCertificate' -v`
Expected: FAIL (build error: `GetCertificateVersions`, `RenewCertificate` undefined).

- [ ] **Step 3: Implement the client**

In `internal/vaultapi/certificates.go`, add `Version int \`json:"version"\`` to `CertificateSummary` (after `NotBefore`) and to `certificateWire` (after `NotBefore`), and `Version: w.Version,` to the `summary()` literal. Append:

```go
// CertificateVersion is one entry of a certificate's version history. Like
// the API type it mirrors, it has no field for a PEM or a private key.
type CertificateVersion struct {
	CertificateID uuid.UUID  `json:"certificate_id"`
	Version       int        `json:"version"`
	Current       bool       `json:"current"`
	Enabled       bool       `json:"enabled"`
	CreatedAt     time.Time  `json:"created_at"`
	ExpiresAt     *time.Time `json:"expires_at,omitempty"`
	NotBefore     *time.Time `json:"not_before,omitempty"`
}

type certificateVersionsResponse struct {
	Versions []CertificateVersion `json:"versions"`
}

// GetCertificateVersions returns a certificate's versions, oldest first,
// with the current one last.
func (c *Client) GetCertificateVersions(ctx context.Context, vault, name string) ([]CertificateVersion, error) {
	if vault == "" {
		return nil, fmt.Errorf("vaultapi: vault is required to list certificate versions")
	}
	id, err := c.Resolver().Resolve(ctx, vault, KindCertificates, name)
	if err != nil {
		return nil, err
	}

	var response certificateVersionsResponse
	path := fmt.Sprintf("/api/v1/vaults/%s/certificates/%s/versions", vault, id)
	if err := c.Do(ctx, http.MethodGet, path, nil, &response); err != nil {
		return nil, err
	}
	return response.Versions, nil
}
```

Append to `internal/vaultapi/certificates_write.go`:

```go
// renewCertificateBody is the renew route's optional body. A zero
// ValidityDays is omitted, which keeps the current validity period.
type renewCertificateBody struct {
	ValidityDays int `json:"validity_days,omitempty"`
}

// RenewCertificate issues a new version of a certificate and returns that
// version's metadata. validityDays of zero keeps the current period.
func (c *Client) RenewCertificate(ctx context.Context, vault, name string, validityDays int) (*CertificateVersion, error) {
	if vault == "" {
		return nil, fmt.Errorf("vaultapi: vault is required to renew a certificate")
	}
	if name == "" {
		return nil, fmt.Errorf("vaultapi: certificate name is required to renew a certificate")
	}
	if validityDays < 0 {
		return nil, fmt.Errorf("vaultapi: validity_days must not be negative, got %d", validityDays)
	}

	id, err := c.Resolver().Resolve(ctx, vault, KindCertificates, name)
	if err != nil {
		return nil, err
	}

	var version CertificateVersion
	path := fmt.Sprintf("/api/v1/vaults/%s/certificates/%s/renew", vault, id)
	if err := c.Do(ctx, http.MethodPost, path, renewCertificateBody{ValidityDays: validityDays}, &version); err != nil {
		return nil, err
	}
	return &version, nil
}
```

In `api/route_contract_test.go`, add to `clientCalledRoutes`:

```go
	{"GET", "/api/v1/vaults/{vault_name}/certificates/{certificate_id}/versions", "vaultapi.GetCertificateVersions"},
	{"POST", "/api/v1/vaults/{vault_name}/certificates/{certificate_id}/renew", "vaultapi.RenewCertificate"},
```

- [ ] **Step 4: Run and expect PASS**

Run: `go test ./internal/vaultapi -run 'CertificateVersions|RenewCertificate|Certificate' -v && go test ./api -run TestClientPathsAreRegistered -v`
Expected: PASS.

- [ ] **Step 5: Write the failing MCP tests**

Create `internal/mcpserver/tools_certificates_versions_test.go`:

```go
package mcpserver

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestGetCertificate_IncludesVersionHistory(t *testing.T) {
	routes := certRoutes()
	routes["/api/v1/vaults/default/certificates/"+tlsCertUUID+"/versions"] = `{"versions":[
		{"certificate_id":"` + tlsCertUUID + `","version":1,"current":false,"enabled":true,"created_at":"2026-08-01T00:00:00Z"},
		{"certificate_id":"` + tlsCertUUID + `","version":2,"current":true,"enabled":true,"created_at":"2026-09-01T00:00:00Z"}]}`
	f := newFakeVault(t, routes)
	s := f.server(t, testConfig())
	registerCertificatesReadTools(s)

	var got getCertificateResult
	structured(t, callTool(t, s, "get_certificate", map[string]any{"name": "tls-cert"}), &got)
	require.Len(t, got.Versions, 2)
	require.True(t, got.Versions[1].Current)
	require.Equal(t, 2, got.Versions[1].Version)
}

func TestRenewCertificate_IsAbsentWithoutAllowWrite(t *testing.T) {
	f := newFakeVault(t, certRoutes())
	s := f.server(t, testConfig())
	registerCertificatesWriteTools(s)
	require.NotContains(t, s.RegisteredTools(), "renew_certificate")
}

func TestRenewCertificate_PostsAndReportsTheNewVersion(t *testing.T) {
	f := newFakeVault(t, certRoutes())
	f.writeResponse = `{"certificate_id":"` + tlsCertUUID + `","version":2,"current":true,"enabled":true,
		"created_at":"2026-10-01T00:00:00Z","expires_at":"2027-10-01T00:00:00Z"}`
	s := f.server(t, writeConfig())
	registerCertificatesWriteTools(s)

	var got renewCertificateResult
	structured(t, callTool(t, s, "renew_certificate", map[string]any{"name": "tls-cert", "validity_days": 90}), &got)
	require.Equal(t, 2, got.Version)
	require.NotEmpty(t, got.ExpiresAt)
	require.True(t, f.hit("/api/v1/vaults/default/certificates/"+tlsCertUUID+"/renew"))
	require.Equal(t, float64(90), f.lastWriteBody["validity_days"])
}

func TestRenewCertificate_RequiresName(t *testing.T) {
	f := newFakeVault(t, certRoutes())
	s := f.server(t, writeConfig())
	registerCertificatesWriteTools(s)
	require.True(t, callTool(t, s, "renew_certificate", map[string]any{}).IsError)
}
```

In `gating_table_test.go`, add `"renew_certificate"` to `writeTools` (keep it sorted: after `"recover_deleted"`), and change the counts `{true, false, false, false, 19}` to `20`, `{true, true, false, false, 23}` to `24`, `{true, true, true, false, 26}` to `27`, `{true, true, true, true, 27}` to `28`.

In `leak_sweep_test.go`, `leakRoutes`, add:

```go
		"/api/v1/vaults/default/certificates/" + tlsCertUUID + "/versions": `{"versions":[{"version":1,"current":true,
			"private_key":"` + leakMarker + `","certificate":"` + leakMarker + `"}]}`,
```

- [ ] **Step 6: Run and expect FAIL**

Run: `go test ./internal/mcpserver -run 'TestGetCertificate_IncludesVersionHistory|TestRenewCertificate_|TestGatingTable' -v`
Expected: FAIL (build error: `renewCertificateResult` undefined; `Versions` field missing).

- [ ] **Step 7: Implement the MCP tools**

In `tools_certificates.go`, add after `certificatePolicyResult`:

```go
// certificateVersionResult is one version in a certificate's history. It
// has no field for a PEM or a private key.
type certificateVersionResult struct {
	Version   int    `json:"version"`
	Current   bool   `json:"current"`
	Enabled   bool   `json:"enabled"`
	CreatedAt string `json:"created_at,omitempty"`
	ExpiresAt string `json:"expires_at,omitempty"`
}
```

In `getCertificateResult`, after `RenewalDays` add:

```go
	Version     int                        `json:"version"`
	Versions    []certificateVersionResult `json:"versions,omitempty"`
```

Change the `get_certificate` description to `"Get a certificate's metadata, version history and issuance policy, including subject, SANs and renewal settings."`. In `handleGetCertificate`, add `Version: certificate.Version,` to the `result` literal, and before the policy fetch add:

```go
	// The version history is supplementary, like the policy below.
	if versions, err := s.client.GetCertificateVersions(ctx, vault, args.Name); err == nil {
		for _, v := range versions {
			entry := certificateVersionResult{
				Version:   v.Version,
				Current:   v.Current,
				Enabled:   v.Enabled,
				CreatedAt: v.CreatedAt.Format(time.RFC3339),
			}
			if v.ExpiresAt != nil {
				entry.ExpiresAt = v.ExpiresAt.Format(time.RFC3339)
			}
			result.Versions = append(result.Versions, entry)
		}
	}
```

In `tools_certificates_write.go`, add the types:

```go
type renewCertificateArgs struct {
	Name         string `json:"name" jsonschema:"the certificate's name, or its id"`
	ValidityDays int    `json:"validity_days,omitempty" jsonschema:"days the new version is valid for; omitted keeps the current version's validity period"`
	Vault        string `json:"vault,omitempty" jsonschema:"the vault holding the certificate; defaults to the server's configured vault"`
}

// renewCertificateResult describes the new version. It has no field for a
// PEM or a private key.
type renewCertificateResult struct {
	Vault     string `json:"vault"`
	Name      string `json:"name"`
	Version   int    `json:"version"`
	Enabled   bool   `json:"enabled"`
	ExpiresAt string `json:"expires_at,omitempty"`
}
```

In `registerCertificatesWriteTools`, after `create_certificate`, add:

```go
	registerIf(s, TierWrite, "renew_certificate",
		"Renew a certificate: re-issue it over its key as a new version. The previous version is kept in the "+
			"certificate's history. Never returns private key material.",
		// Not idempotent: each call creates another version.
		Annotations{ReadOnly: false, Idempotent: false, Destructive: false},
		s.handleRenewCertificate)
```

and append:

```go
func (s *Server) handleRenewCertificate(ctx context.Context, _ *mcp.CallToolRequest, args renewCertificateArgs) (*mcp.CallToolResult, renewCertificateResult, error) {
	if args.Name == "" {
		return errorResult("renew_certificate requires a name"), renewCertificateResult{}, nil
	}
	if args.ValidityDays < 0 {
		return errorResult("renew_certificate requires a positive validity_days, or none"), renewCertificateResult{}, nil
	}
	vault, err := s.ResolveVault(args.Vault)
	if err != nil {
		return errorResult("%s", err), renewCertificateResult{}, nil
	}

	version, err := s.client.RenewCertificate(ctx, vault, args.Name, args.ValidityDays)
	if err != nil {
		return errorResult("could not renew certificate %q in vault %q: %s", args.Name, vault, err), renewCertificateResult{}, nil
	}

	result := renewCertificateResult{
		Vault:   vault,
		Name:    args.Name,
		Version: version.Version,
		Enabled: version.Enabled,
	}
	if version.ExpiresAt != nil {
		result.ExpiresAt = version.ExpiresAt.Format(time.RFC3339)
	}
	return nil, result, nil
}
```

In `docs/mcp-server.md`, change the `allow_write` row's tool count from `9` to `10`.

- [ ] **Step 8: Run and expect PASS**

Run: `go test ./internal/mcpserver ./internal/vaultapi -v -run 'Certificate|Gating|Leak'`
Expected: PASS.

- [ ] **Step 9: Commit**

Commit via the `dev-workflow-skills:1-git-commit` skill. Stage: `internal/vaultapi/certificates.go`, `internal/vaultapi/certificates_write.go`, `internal/vaultapi/certificates_versions_test.go`, `api/route_contract_test.go`, `internal/mcpserver/tools_certificates.go`, `internal/mcpserver/tools_certificates_write.go`, `internal/mcpserver/tools_certificates_versions_test.go`, `internal/mcpserver/gating_table_test.go`, `internal/mcpserver/leak_sweep_test.go`, `docs/mcp-server.md`.

---

### Task 10: CLI version commands and renewal output

**Files:**
- Create: `cmd/certificates/versions.go`
- Modify: `cmd/certificates/renew.go:18-88` (help and output), `cmd/certificates/columns.go:11-18` (`certColumns`, new `certVersionColumns`), `cmd/certificates.go:77` (wiring)
- Modify tests: `cmd/certificates/renew_help_test.go`
- Test: `cmd/certificates/versions_test.go` (create)

**Interfaces:**
- Consumes: `ListCertificateVersions`, `GetCertificateVersion`, `CreateCertificateResult.Version` (Task 4); `certCmdCertService` versions methods (Task 4).
- Produces: `func InitCertificatesVersions(certificatesCmd *cobra.Command)`; commands `certificate versions list <id>` and `certificate versions get <id> <version>`; `certVersionColumns`.

- [ ] **Step 1: Write the failing tests**

Create `cmd/certificates/versions_test.go`:

```go
package certificates

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"rocketvault/cmd/testutils"
	"rocketvault/common"
	certServices "rocketvault/internal/services/certificates"
	"rocketvault/model"
)

func versionsTestCtx(tc *testutils.TestContext, svc *certCmdCertService) context.Context {
	sc := &certsTestContainer{MockServiceContainer: tc.MockContainer, certSvc: svc}
	claims := &model.Claims{UserID: tc.TestUserID, Roles: []string{model.RoleAdmin}}
	ctx := context.WithValue(context.Background(), common.ClaimsKey, claims)
	ctx = context.WithValue(ctx, common.LogKey, newCertLogger())
	ctx = context.WithValue(ctx, common.ServiceContainerKey, sc)
	return context.WithValue(ctx, common.OutputFormatterKey, newCertFmtr())
}

func TestCertVersionsListCmd_PrintsEveryVersion(t *testing.T) {
	tc := testutils.NewTestContext(t)
	svc := &certCmdCertService{}
	certID := uuid.New()
	svc.On("ListCertificateVersions", mock.Anything, certID, model.NewVaultScope(tc.TestVaultID, tc.TestUserID)).
		Return([]model.CertificateVersion{
			{CertificateID: certID, Version: 1, Enabled: true, CreatedAt: time.Now()},
			{CertificateID: certID, Version: 2, Current: true, Enabled: true, CreatedAt: time.Now()},
		}, nil)

	cmd, buf := newCertCmd(versionsListCmd.RunE, []string{certID.String()})
	cmd.Args = cobra.ExactArgs(1)
	cmd.SetContext(versionsTestCtx(tc, svc))
	require.NoError(t, cmd.Execute())

	out := buf.String()
	assert.Contains(t, out, "Version")
	assert.Contains(t, out, "Current")
	assert.NotContains(t, out, "BEGIN", "versions output never carries a PEM")
	svc.AssertExpectations(t)
}

func TestCertVersionsGetCmd_RejectsBadVersion(t *testing.T) {
	tc := testutils.NewTestContext(t)
	// "-1" is not listed: cobra reads it as a shorthand flag before RunE runs.
	for _, bad := range []string{"0", "abc", "99999999999999999999"} {
		cmd, _ := newCertCmd(versionsGetCmd.RunE, []string{uuid.New().String(), bad})
		cmd.Args = cobra.ExactArgs(2)
		cmd.SetContext(versionsTestCtx(tc, &certCmdCertService{}))
		assert.ErrorContains(t, cmd.Execute(), "invalid version", bad)
	}
}

func TestCertVersionsGetCmd_PrintsOneVersion(t *testing.T) {
	tc := testutils.NewTestContext(t)
	svc := &certCmdCertService{}
	certID := uuid.New()
	svc.On("GetCertificateVersion", mock.Anything, certID, 2, model.NewVaultScope(tc.TestVaultID, tc.TestUserID)).
		Return(&model.CertificateVersion{CertificateID: certID, Version: 2, Current: true, Enabled: true}, nil)

	cmd, buf := newCertCmd(versionsGetCmd.RunE, []string{certID.String(), "2"})
	cmd.Args = cobra.ExactArgs(2)
	cmd.SetContext(versionsTestCtx(tc, svc))
	require.NoError(t, cmd.Execute())
	assert.Contains(t, buf.String(), "2")
	svc.AssertExpectations(t)
}

func TestCertVersionsGetCmd_ServiceError(t *testing.T) {
	tc := testutils.NewTestContext(t)
	svc := &certCmdCertService{}
	certID := uuid.New()
	svc.On("GetCertificateVersion", mock.Anything, certID, 9, model.NewVaultScope(tc.TestVaultID, tc.TestUserID)).
		Return(nil, fmt.Errorf("%w: none", model.ErrCertificateVersionNotFound))

	cmd, _ := newCertCmd(versionsGetCmd.RunE, []string{certID.String(), "9"})
	cmd.Args = cobra.ExactArgs(2)
	cmd.SetContext(versionsTestCtx(tc, svc))
	assert.ErrorContains(t, cmd.Execute(), "failed to get certificate version")
}

func TestCertRenewCmd_PrintsNewVersion(t *testing.T) {
	tc := testutils.NewTestContext(t)
	svc := &certCmdCertService{}
	certID := uuid.New()
	svc.On("RenewCertificate", mock.Anything, certID, model.NewVaultScope(tc.TestVaultID, tc.TestUserID), 365).
		Return(&certServices.CreateCertificateResult{CertID: certID, Version: 4}, nil)

	cmd, buf := newCertCmd(renewCmd.RunE, []string{certID.String()})
	cmd.Args = cobra.ExactArgs(1)
	setFlags(cmd, map[string]any{"validity-days": 365})
	cmd.SetContext(versionsTestCtx(tc, svc))
	require.NoError(t, cmd.Execute())
	assert.Contains(t, buf.String(), "Version: 4")
}
```

In `renew_help_test.go`, append:

```go
// Renewal adds a version and keeps the old one, and the help must say so.
func TestRenewCmd_LongDescribesVersioning(t *testing.T) {
	require.Contains(t, renewCmd.Long, "new version")
	require.Contains(t, renewCmd.Long, "certificate versions list")
	require.NotContains(t, renewCmd.Long, "written in place")
}
```

- [ ] **Step 2: Run and expect FAIL**

Run: `go test ./cmd/certificates -run 'TestCertVersions|TestCertRenewCmd_PrintsNewVersion|TestRenewCmd_' -v`
Expected: FAIL (build error: `versionsListCmd`, `versionsGetCmd` undefined).

- [ ] **Step 3: Implement**

In `cmd/certificates/columns.go`, add to `certColumns` after the `Name` column:

```go
	vaultcli.Col("Version", func(c model.Certificate) string { return vaultcli.CellInt(c.CurrentVersion()) }),
```

and append:

```go
// certVersionColumns is how a certificate version is printed. There is no
// column for a PEM or a key: model.CertificateVersion carries neither.
var certVersionColumns = []vaultcli.Column[model.CertificateVersion]{
	vaultcli.Col("Version", func(v model.CertificateVersion) string { return vaultcli.CellInt(v.Version) }),
	vaultcli.Col("Current", func(v model.CertificateVersion) string { return vaultcli.CellBool(v.Current) }),
	vaultcli.Col("Enabled", func(v model.CertificateVersion) string { return vaultcli.CellBool(v.Enabled) }),
	vaultcli.Col("Not-Before", func(v model.CertificateVersion) string { return vaultcli.CellOptTime(v.NotBefore) }),
	vaultcli.Col("Expires", func(v model.CertificateVersion) string { return vaultcli.CellOptTime(v.ExpiresAt) }),
	vaultcli.Col("Created", func(v model.CertificateVersion) string { return vaultcli.CellTime(v.CreatedAt) }),
}
```

Create `cmd/certificates/versions.go`:

```go
/*
Copyright © 2025 Snehal Dangroshiya
*/

package certificates

import (
	"fmt"
	"strconv"

	"github.com/google/uuid"
	"github.com/spf13/cobra"

	"rocketvault/cmd/vaultcli"
	"rocketvault/model"
)

// versionsCmd groups the certificate version commands.
var versionsCmd = &cobra.Command{
	Use:   "versions",
	Short: "List or inspect a certificate's versions",
	Long: `Every create and every renewal gives a certificate a numbered version.
The certificate keeps its ID; the highest number is the current version.
These commands print metadata only: never a PEM or a private key.`,
	Run: func(cmd *cobra.Command, args []string) {
		cmd.Help() //nolint:errcheck,gosec
	},
}

// versionsListCmd lists a certificate's versions.
var versionsListCmd = &cobra.Command{
	Use:   "list <id>",
	Short: "List a certificate's versions",
	Long: `Print every version of a certificate, oldest first, with the current
version last.

Requires the Microsoft.KeyVault/vaults/certificates/read data action in the
target vault. Acts on the vault named by --vault, defaulting to "default".
A disabled certificate's versions are still listed.`,
	Example: `  rocketvault certificate versions list <id>
  rocketvault certificate versions list <id> --vault payments --output json`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		s, err := vaultcli.Caller(cmd, vaultcli.Op{
			Audit: "list_certificate_versions", Action: model.ActionCertificatesRead, Policy: model.OpGet,
			AuthzFailMsg: "failed to list certificate versions",
		})
		if err != nil {
			return err
		}
		certID, err := uuid.Parse(args[0])
		if err != nil {
			return s.Fail("invalid certificate ID", err)
		}
		if err := s.Authorize(); err != nil {
			return err
		}

		versions, err := s.Container.GetCertificateService().ListCertificateVersions(s.Ctx, certID, s.Scope)
		if err != nil {
			return s.Fail("failed to list certificate versions", err)
		}
		s.OK(fmt.Sprintf("certificate versions listed: %s", certID))
		return vaultcli.Print(s, certVersionColumns, versions...)
	},
}

// versionsGetCmd prints one certificate version.
var versionsGetCmd = &cobra.Command{
	Use:   "get <id> <version>",
	Short: "Show one certificate version",
	Long: `Print one version of a certificate by number.

Requires the Microsoft.KeyVault/vaults/certificates/read data action in the
target vault. Acts on the vault named by --vault, defaulting to "default".`,
	Example: `  rocketvault certificate versions get <id> 2`,
	Args:    cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		s, err := vaultcli.Caller(cmd, vaultcli.Op{
			Audit: "get_certificate_version", Action: model.ActionCertificatesRead, Policy: model.OpGet,
			AuthzFailMsg: "failed to get certificate version",
		})
		if err != nil {
			return err
		}
		certID, err := uuid.Parse(args[0])
		if err != nil {
			return s.Fail("invalid certificate ID", err)
		}
		number, err := strconv.Atoi(args[1])
		if err != nil || number < 1 {
			return s.Fail("invalid version: must be a positive integer", err)
		}
		if err := s.Authorize(); err != nil {
			return err
		}

		version, err := s.Container.GetCertificateService().GetCertificateVersion(s.Ctx, certID, number, s.Scope)
		if err != nil {
			return s.Fail("failed to get certificate version", err)
		}
		s.OK(fmt.Sprintf("certificate version retrieved: %s v%d", certID, number))
		return vaultcli.Print(s, certVersionColumns, *version)
	},
}

// InitCertificatesVersions registers the versions command group.
func InitCertificatesVersions(certificatesCmd *cobra.Command) {
	versionsCmd.AddCommand(versionsListCmd, versionsGetCmd)
	certificatesCmd.AddCommand(versionsCmd)
}
```

If `s.Fail` does not accept a nil error for the `number < 1` branch, keep the call as written: `TestCertRenewCmd_InvalidValidityDays` already calls `s.Fail(msg, nil)`.

In `cmd/certificates.go`, after `certificates.InitCertificatesRenew(certificateCmd)` add `certificates.InitCertificatesVersions(certificateCmd)`.

In `cmd/certificates/renew.go`, replace the first paragraph of `Long` with:

```
Re-issue an X.509 certificate over its existing key with a fresh validity
period counted from now. The certificate keeps its ID, name, tags and
vault. There is no new certificate ID to record: the renewal adds a new
version instead, and the body it replaces is kept as the previous version.
List them with 'rocketvault certificate versions list <id>'.
```

Keep the other paragraphs unchanged and every line within 78 columns. Replace the success output with:

```go
		s.OK(fmt.Sprintf("certificate renewed: %s, now version %d", result.CertID, result.Version))
		// Renewal adds a version under the same ID, so there is one ID to print.
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Certificate renewed successfully!\nCertificate ID: %s\nVersion: %d\nValidity: %d days\n",
			result.CertID, result.Version, validityDays)
```

- [ ] **Step 4: Run and expect PASS**

Run: `go test ./cmd/certificates -v -run 'TestCertVersions|TestCertRenewCmd|TestRenewCmd_' && go test ./cmd/...`
Expected: PASS.

- [ ] **Step 5: Commit**

Commit via the `dev-workflow-skills:1-git-commit` skill. Stage: `cmd/certificates/versions.go`, `cmd/certificates/versions_test.go`, `cmd/certificates/renew.go`, `cmd/certificates/renew_help_test.go`, `cmd/certificates/columns.go`, `cmd/certificates.go`.

---

### Task 11: Documentation

**Files:**
- Modify: `docs/api-developer-guide.md:373-380` (status codes), before `:371` (`## Error Handling`)
- Modify: `docs/integration-examples.md:7-12` (table of contents), before `## CI/CD Pipeline Integration` (`:585`)
- Modify: `.claude/azure-keyvault-parity.md:215-236` (§4), `:488` (tally row), `:495` (total row), `:497` (percentages)
- Modify: `.claude/known-bugs.md:1546`
- Modify: `CLAUDE.md:242` (CertificateService bullet), Documentation History (`:526`)

**Interfaces:**
- Consumes: routes, statuses, CLI commands and MCP tool from Tasks 8-10.
- Produces: documentation only.

- [ ] **Step 1: Developer guide**

In `docs/api-developer-guide.md`, add `- \`409\`: Conflict (the resource changed concurrently, or is in a state that refuses the operation)` to the status-code list after `404`. Immediately before `## Error Handling`, add:

````markdown
### Certificate Endpoints

Certificates are versioned. Every create and every renewal produces a new
numbered version; the certificate's ID and name never change. Version numbers
are sequential integers starting at 1 (Azure Key Vault uses 32-hex version
IDs; this is a deliberate divergence). Every route below also exists under
`/api/v1/vaults/{vault_name}/certificates/...`. No response ever carries a PEM
or a private key.

#### Renew a Certificate

```http
POST /api/v1/certificates/{certificate_id}/renew
Authorization: Bearer <token>
Content-Type: application/json

{"validity_days": 90}
```

The body is optional; without `validity_days` the new version keeps the
current version's validity period. Requires the
`Microsoft.KeyVault/vaults/certificates/create` data action.

**Response:** `200 OK`, the new version's metadata:

```json
{
  "certificate_id": "550e8400-e29b-41d4-a716-446655440000",
  "version": 3,
  "current": true,
  "created_at": "2026-10-01T10:30:00Z",
  "expires_at": "2026-12-30T10:30:00Z",
  "not_before": "2026-10-01T10:30:00Z",
  "enabled": true
}
```

`409` means the certificate is disabled or outside its validity window, or a
concurrent renewal won; re-read and retry.

#### List and Read Versions

```http
GET /api/v1/certificates/{certificate_id}/versions
GET /api/v1/certificates/{certificate_id}/versions/{version}
```

The list is `{"versions": [...]}`, oldest first, with the current version last
and marked `"current": true`. Both require the
`Microsoft.KeyVault/vaults/certificates/read` data action.

#### Update a Version's Lifecycle

```http
PUT /api/v1/certificates/{certificate_id}/versions/{version}
Content-Type: application/json

{"enabled": false}
```

Accepts `enabled`, `expires_at` and `not_before`; at least one is required and
`not_before` must not be after `expires_at` (otherwise `400`). Updating the
current version is the same as updating the certificate's own attributes. A
disabled or expired version is unusable, and a disabled certificate gates every
version. Requires `Microsoft.KeyVault/vaults/certificates/update`. There is no
route to delete a single version.

````

- [ ] **Step 2: Integration examples**

In `docs/integration-examples.md`, add `- [Certificate Renewal and Version History](#certificate-renewal-and-version-history)` to the table of contents after the rotation entry, and immediately before `## CI/CD Pipeline Integration` add:

````markdown
## Certificate Renewal and Version History

Renew a certificate, then confirm the previous version was kept:

```bash
#!/usr/bin/env bash
# renew_cert.sh - renew a certificate and show its version history.
set -euo pipefail

API="${ROCKETVAULT_URL:-http://127.0.0.1:8774}/api/v1/vaults/${VAULT:-default}"
CERT_ID="$1"

curl -sS -X POST "$API/certificates/$CERT_ID/renew" \
  -H "Authorization: Bearer $ROCKETVAULT_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"validity_days": 90}' | jq '{version, expires_at}'

curl -sS "$API/certificates/$CERT_ID/versions" \
  -H "Authorization: Bearer $ROCKETVAULT_TOKEN" | jq '.versions[] | {version, current, enabled, expires_at}'
```

The same from the CLI:

```bash
rocketvault certificate renew "$CERT_ID" --validity-days 90 --vault "$VAULT"
rocketvault certificate versions list "$CERT_ID" --vault "$VAULT"
```

To retire an old version without deleting it, disable it:

```bash
curl -sS -X PUT "$API/certificates/$CERT_ID/versions/1" \
  -H "Authorization: Bearer $ROCKETVAULT_TOKEN" \
  -H "Content-Type: application/json" -d '{"enabled": false}'
```

````

- [ ] **Step 3: Parity doc**

In `.claude/azure-keyvault-parity.md` §4, after the `Auto-renewal` row add:

```markdown
| Versioned certificates (stable identity, new version on issue and renew; list and get by version) | ✅ | ✅ `GET /certificates/{id}/versions`, `GET /certificates/{id}/versions/{n}`, `POST /certificates/{id}/renew` (design: `docs/superpowers/specs/2026-10-01-certificate-versioning-design.md`) | ✅ |
| Per-version attributes (enabled, expires, not_before) | ✅ | ✅ `PUT /certificates/{id}/versions/{n}`; a disabled certificate gates every version | ✅ |
| Version identifier format | 32-hex | sequential integers, like keys and secrets; new versions come only from renew because import and merge are unbuilt | 🟡 |
```

In the `Backup / Restore` row, replace `note this is an unencrypted, same-instance base64url blob (\`internal/backup/item_backup.go:360-366\`)` with `the blob carries every archived version and restore replays them in one transaction; note this is an unencrypted, same-instance base64url blob (\`internal/backup/item_backup.go\`, \`BackupCertificate\`)`.

In the scorecard, change `| 4. Certificate management | 5 | 0 | 4 | 0 |` to `| 4. Certificate management | 7 | 1 | 4 | 0 |` and `| **Total** | **55** | **14** | **8** | **10** |` to `| **Total** | **57** | **15** | **8** | **10** |`. Change `**71% full parity** (55/77 parity-comparable rows), 18% partial, 10% not supported.` to `**71% full parity** (57/80 parity-comparable rows), 19% partial, 10% not supported.` (72 of 80 present in some form is still 90%, so the next sentence stands). Append to that paragraph: `(Three §4 rows added 2026-10-01 for certificate versioning moved this from 55/77 to 57/80.)`

- [ ] **Step 4: Known bugs and CLAUDE.md**

In `.claude/known-bugs.md`, replace `Certificates have no versions at all.` with `Certificates had no versions at all when this was written; superseded 2026-10-01 by certificate versioning, whose \`model.CertificateVersion\` is metadata-only by the same rule as \`model.KeyVersion\`.`

In `CLAUDE.md`, replace `- **CertificateService**: Certificate lifecycle management, CA validation` with:

```markdown
- **CertificateService**: Certificate lifecycle management, CA validation
- Certificates are versioned (2026-10-01): the `certificates` row is always the current version and `certificate_versions` holds every earlier one. `RenewCertificate` archives and bumps in one `CertificateVersionRepository.ArchiveAndRenew` transaction guarded by the version number, so a lost race is a 409. `CertificateRepository.Update` writes metadata only; never write a certificate body or key through it. Design: `docs/superpowers/specs/2026-10-01-certificate-versioning-design.md`.
```

Under `## Documentation History`, add above the `2026-08-24` entry:

```markdown
- **2026-10-01**: Certificate versioning — `GET .../versions`, `GET|PUT .../versions/{n}`
  and `POST .../renew` on both route shapes, version-aware backup, purge and
  master-key rotation, `rocketvault certificate versions list|get`, and the
  `renew_certificate` MCP write tool (29 tools fully enabled, 20 with only
  `allow_write`). Plan: `docs/superpowers/plans/2026-10-01-certificate-versioning.md`.
```

- [ ] **Step 5: Verify the whole change**

Run: `go build ./... && go vet ./... && go test ./...`
Expected: PASS. Then run the linter in CI (or on a fixed toolchain) and confirm it is clean. Run `./scripts/docs.sh build` and confirm it succeeds.

- [ ] **Step 6: Commit**

Commit via the `dev-workflow-skills:1-git-commit` skill. Stage: `docs/api-developer-guide.md`, `docs/integration-examples.md`, `.claude/azure-keyvault-parity.md`, `.claude/known-bugs.md`, `CLAUDE.md`.

---

## Self-Review

- **Spec coverage:** §1 storage and model (Task 1), repository and select list (Task 2); §2 transactional renewal, guards first, 409 on a race, shared scheduler path (Tasks 2, 4, 5); §3 per-version lifecycle and validation (Tasks 1, 2, 4); §4 API on both shapes, metadata only, `version` in `CertificateResponse`, error statuses (Task 8); §5 data actions (Task 8); §6 backup blob, restore replay, explicit deletes, `table_order.go`, `rekey/targets.go` (Tasks 1, 3, 6, 7); §7 cache, vault client, MCP, CLI, archived key copy survives key rotation (Tasks 4, 5, 9, 10); §8 parity rows (Task 11). Testing: migration fresh and upgraded (Task 1); atomic archive-and-bump, duplicate rejection, list/get/update, select-list guard (Task 2); renewal, guard failure, race, validation, current-equals-certificate update, key rotation (Task 4); cleanup (Task 3); backup round trip, pre-change blob, failed replay (Task 6); master-key rotation and drift guards (Tasks 1, 7); API statuses, both shapes, authorization matrix, no material, OpenAPI drift (Task 8); scheduler (Task 5). Documentation list (Task 11).
- **Type consistency:** `CertificateVersionRepositoryInterface` method set and `UpdateCertificateVersionRequest` fields are identical wherever used; `CreateCertificateResult.Version`, `CurrentValidityDays`, `SetCertificateVersionRepository`, `SetConflict`, `writeCertificateRenewError`, `CertificateVersionListResponse` and the MCP `renewCertificateResult` are defined once and consumed with the same names.
- **Judgment calls to confirm:** version list/get/update read the parent without the lifecycle gate (so a disabled certificate's history can be inspected and re-enabled), while renewal keeps the gate; renew returns `200` like `rotateKey`; `CertificateRepository.Update` is narrowed to metadata (Review Focus 1).
