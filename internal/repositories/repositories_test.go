// Package repositories_test contains additional unit tests targeting the
// uncovered paths in key_repository.go, certificate_repository.go,
// access_policy_repository.go, audit_repository.go, and rotation_repository.go.
//
// Every test uses an in-memory SQLite database so no disk I/O or external
// services are required.
package repositories_test

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
	"rocketvault/internal/repositories"
	"rocketvault/model"
)

// ---------------------------------------------------------------------------
// Shared test database helpers
// ---------------------------------------------------------------------------

// newSharedCacheDB opens a named, shared-cache in-memory SQLite database so
// multiple connection-pool connections within one *sql.DB all share the same
// data. (In-memory SQLite databases are connection-local by default.)
func newSharedCacheDB(t *testing.T, name string) *sql.DB {
	t.Helper()
	dsn := "file:" + name + "?mode=memory&cache=shared"
	db, err := sql.Open("sqlite3", dsn)
	require.NoError(t, err)
	t.Cleanup(func() { db.Close() }) //nolint:errcheck,gosec
	return db
}

// setupFullKeyDB creates a shared-cache in-memory SQLite database with the
// full keys, key_tags and key_versions schema needed by KeyRepository.
func setupFullKeyDB(t *testing.T) *sql.DB {
	t.Helper()
	db := newSharedCacheDB(t, "full_key_"+uuid.NewString())
	_, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS keys (
			id TEXT PRIMARY KEY,
			user_id TEXT NOT NULL,
			vault_id TEXT NOT NULL DEFAULT '00000000-0000-0000-0000-00000000efa1',
			name TEXT NOT NULL,
			value TEXT NOT NULL,
			type TEXT NOT NULL,
			revoked BOOLEAN NOT NULL DEFAULT FALSE,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			deleted_at TIMESTAMP DEFAULT NULL,
			purge_protection BOOLEAN NOT NULL DEFAULT FALSE,
			scheduled_purge_at TIMESTAMP DEFAULT NULL,
			enabled BOOLEAN NOT NULL DEFAULT TRUE,
			expires_at TIMESTAMP NULL,
			not_before TIMESTAMP NULL,
			bits INTEGER NOT NULL DEFAULT 0,
			curve TEXT NOT NULL DEFAULT '',
			updated_at TIMESTAMP NULL
		);
		CREATE TABLE IF NOT EXISTS key_tags (
			key_id TEXT NOT NULL,
			tag TEXT NOT NULL,
			PRIMARY KEY (key_id, tag)
		);
		CREATE TABLE IF NOT EXISTS key_versions (
			key_id     TEXT NOT NULL,
			version    INTEGER NOT NULL,
			value      TEXT NOT NULL,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			PRIMARY KEY (key_id, version)
		);
	`)
	require.NoError(t, err)
	return db
}

// setupFullCertDB creates a shared-cache in-memory SQLite database with the
// full certificates, certificate_tags and crl schema.
func setupFullCertDB(t *testing.T) *sql.DB {
	t.Helper()
	db := newSharedCacheDB(t, "full_cert_"+uuid.NewString())
	_, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS certificates (
			id TEXT PRIMARY KEY,
			user_id TEXT NOT NULL,
			vault_id TEXT NOT NULL DEFAULT '00000000-0000-0000-0000-00000000efa1',
			name TEXT NOT NULL,
			certificate TEXT NOT NULL,
			private_key TEXT NOT NULL,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			deleted_at TIMESTAMP DEFAULT NULL,
			purge_protection BOOLEAN NOT NULL DEFAULT FALSE,
			scheduled_purge_at TIMESTAMP DEFAULT NULL,
			expires_at DATETIME,
			auto_renew BOOLEAN NOT NULL DEFAULT FALSE,
			renewal_days INTEGER NOT NULL DEFAULT 30,
			key_id TEXT NOT NULL DEFAULT '',
			ca_cert_id TEXT NULL,
			enabled BOOLEAN NOT NULL DEFAULT TRUE,
			not_before TIMESTAMP NULL
		);
		CREATE TABLE IF NOT EXISTS certificate_tags (
			certificate_id TEXT NOT NULL,
			tag TEXT NOT NULL,
			PRIMARY KEY (certificate_id, tag)
		);
		CREATE TABLE IF NOT EXISTS crl (
			id TEXT PRIMARY KEY,
			user_id TEXT NOT NULL,
			serial_number TEXT NOT NULL,
			name TEXT NOT NULL,
			revoked_at TIMESTAMP NOT NULL
		);
	`)
	require.NoError(t, err)
	return db
}

// setupRotationDB creates a shared-cache in-memory SQLite database with the
// rotation_policies, secret_policies, secret_rotation_history and
// rotation_reminders tables required by RotationPolicyRepository.
func setupRotationDB(t *testing.T) *sql.DB {
	t.Helper()
	db := newSharedCacheDB(t, "rotation_"+uuid.NewString())
	_, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS rotation_policies (
			id TEXT PRIMARY KEY,
			user_id TEXT NOT NULL,
			vault_id TEXT NOT NULL,
			name TEXT NOT NULL,
			description TEXT,
			interval_days INTEGER NOT NULL,
			enabled BOOLEAN NOT NULL DEFAULT TRUE,
			reminder_days INTEGER NOT NULL DEFAULT 7,
			auto_rotate BOOLEAN NOT NULL DEFAULT FALSE,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		);
		CREATE TABLE IF NOT EXISTS secret_policies (
			secret_id TEXT NOT NULL,
			policy_id TEXT NOT NULL,
			assigned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			last_rotated_at TIMESTAMP,
			next_rotation_at TIMESTAMP,
			PRIMARY KEY (secret_id, policy_id)
		);
		CREATE TABLE IF NOT EXISTS secret_rotation_history (
			id TEXT PRIMARY KEY,
			secret_id TEXT NOT NULL,
			policy_id TEXT,
			rotated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			previous_version INTEGER,
			new_version INTEGER,
			triggered_by TEXT NOT NULL,
			notes TEXT
		);
		CREATE TABLE IF NOT EXISTS rotation_reminders (
			id TEXT PRIMARY KEY,
			secret_id TEXT NOT NULL,
			policy_id TEXT NOT NULL,
			reminder_type TEXT NOT NULL,
			sent_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			next_reminder_at TIMESTAMP,
			acknowledged BOOLEAN NOT NULL DEFAULT FALSE
		);
	`)
	require.NoError(t, err)
	return db
}

// newKey returns a minimal Key ready for insertion.
func newKey(userID, vaultID uuid.UUID, name string) *model.Key {
	return &model.Key{
		ID:        uuid.New(),
		UserID:    userID,
		VaultID:   vaultID,
		Name:      name,
		Type:      model.KeyTypeRSA,
		Value:     "encrypted-key-material",
		CreatedAt: time.Now(),
		Enabled:   true,
	}
}

// newCert returns a minimal Certificate ready for insertion.
func newCert(userID, vaultID uuid.UUID, name string) *model.Certificate {
	return &model.Certificate{
		ID:          uuid.New(),
		UserID:      userID,
		VaultID:     vaultID,
		Name:        name,
		Certificate: "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----",
		PrivateKey:  "encrypted-key",
		CreatedAt:   time.Now(),
		Enabled:     true,
	}
}

// ---------------------------------------------------------------------------
// KeyRepository – uncovered paths
// ---------------------------------------------------------------------------

func TestKeyRepository_Delete_RemovesKey(t *testing.T) {
	t.Parallel()
	db := setupFullKeyDB(t)
	log := logging.InitLogger()
	repo := repositories.NewKeyRepository(rvdb.NewConn(db, rvdb.SQLite), log)
	ctx := context.Background()

	userID := uuid.New()
	k := newKey(userID, uuid.New(), "delete-me")
	require.NoError(t, repo.Create(ctx, k))

	require.NoError(t, repo.Delete(ctx, k.ID))

	_, err := repo.Read(ctx, k.ID, model.NewAdminScope(uuid.Nil))
	assert.Error(t, err, "deleted key must not be readable")
}

func TestKeyRepository_Delete_NotFound(t *testing.T) {
	t.Parallel()
	db := setupFullKeyDB(t)
	log := logging.InitLogger()
	repo := repositories.NewKeyRepository(rvdb.NewConn(db, rvdb.SQLite), log)
	ctx := context.Background()

	err := repo.Delete(ctx, uuid.New())
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

func TestKeyRepository_ListByUser_FiltersCorrectly(t *testing.T) {
	t.Parallel()
	db := setupFullKeyDB(t)
	log := logging.InitLogger()
	repo := repositories.NewKeyRepository(rvdb.NewConn(db, rvdb.SQLite), log)
	ctx := context.Background()

	userA := uuid.New()
	userB := uuid.New()
	vault := uuid.New()

	kA1 := newKey(userA, vault, "rsa-key-1")
	kA1.Type = model.KeyTypeRSA
	kA2 := newKey(userA, vault, "ecdsa-key-1")
	kA2.Type = model.KeyTypeECDSA
	kB := newKey(userB, vault, "rsa-key-b")

	require.NoError(t, repo.Create(ctx, kA1))
	require.NoError(t, repo.Create(ctx, kA2))
	require.NoError(t, repo.Create(ctx, kB))

	// List all for userA
	all, err := repo.List(ctx, model.NewOwnerScope(uuid.Nil, userA), repositories.KeyFilter{})
	require.NoError(t, err)
	assert.Len(t, all, 2)

	// Filter by type
	rsaOnly, err := repo.List(ctx, model.NewOwnerScope(uuid.Nil, userA), repositories.KeyFilter{Type: model.KeyTypeRSA})
	require.NoError(t, err)
	assert.Len(t, rsaOnly, 1)
	assert.Equal(t, model.KeyTypeRSA, rsaOnly[0].Type)

	// admin scope = all users
	allUsers, err := repo.List(ctx, model.NewAdminScope(uuid.Nil), repositories.KeyFilter{})
	require.NoError(t, err)
	assert.Len(t, allUsers, 3)
}

func TestKeyRepository_ListByUser_FiltersByTag(t *testing.T) {
	t.Parallel()
	db := setupFullKeyDB(t)
	log := logging.InitLogger()
	repo := repositories.NewKeyRepository(rvdb.NewConn(db, rvdb.SQLite), log)
	ctx := context.Background()

	userID := uuid.New()
	vault := uuid.New()

	k1 := newKey(userID, vault, "tagged-key")
	k1.Tags = []string{"env:prod", "tier:premium"}
	k2 := newKey(userID, vault, "plain-key")

	require.NoError(t, repo.Create(ctx, k1))
	require.NoError(t, repo.Create(ctx, k2))

	tagged, err := repo.List(ctx, model.NewOwnerScope(uuid.Nil, userID), repositories.KeyFilter{Tags: []string{"env:prod"}})
	require.NoError(t, err)
	assert.Len(t, tagged, 1)
	assert.Equal(t, k1.ID, tagged[0].ID)
}

func TestKeyRepository_UpdateRevocationStatus(t *testing.T) {
	t.Parallel()
	db := setupFullKeyDB(t)
	log := logging.InitLogger()
	repo := repositories.NewKeyRepository(rvdb.NewConn(db, rvdb.SQLite), log)
	ctx := context.Background()

	k := newKey(uuid.New(), uuid.New(), "revoke-me")
	require.NoError(t, repo.Create(ctx, k))

	require.NoError(t, repo.UpdateRevocationStatus(ctx, k.ID, true))

	var revoked bool
	require.NoError(t, db.QueryRowContext(ctx, "SELECT revoked FROM keys WHERE id = ?", k.ID.String()).Scan(&revoked))
	assert.True(t, revoked)
}

func TestKeyRepository_UpdateRevocationStatus_NotFound(t *testing.T) {
	t.Parallel()
	db := setupFullKeyDB(t)
	log := logging.InitLogger()
	repo := repositories.NewKeyRepository(rvdb.NewConn(db, rvdb.SQLite), log)
	ctx := context.Background()

	err := repo.UpdateRevocationStatus(ctx, uuid.New(), true)
	assert.Error(t, err)
}

func TestKeyRepository_RecoverKey(t *testing.T) {
	t.Parallel()
	db := setupFullKeyDB(t)
	log := logging.InitLogger()
	repo := repositories.NewKeyRepository(rvdb.NewConn(db, rvdb.SQLite), log)
	ctx := context.Background()

	userID := uuid.New()
	k := newKey(userID, uuid.New(), "recover-me")
	require.NoError(t, repo.Create(ctx, k))
	require.NoError(t, repo.SoftDelete(ctx, k.ID))

	// Should be hidden from normal reads
	_, err := repo.Read(ctx, k.ID, model.NewAdminScope(uuid.Nil))
	require.Error(t, err)

	// Recover it
	require.NoError(t, repo.RecoverKey(ctx, k.ID))

	// Now visible again
	got, err := repo.Read(ctx, k.ID, model.NewAdminScope(uuid.Nil))
	require.NoError(t, err)
	assert.Equal(t, k.ID, got.ID)
}

func TestKeyRepository_RecoverKey_NotDeleted(t *testing.T) {
	t.Parallel()
	db := setupFullKeyDB(t)
	log := logging.InitLogger()
	repo := repositories.NewKeyRepository(rvdb.NewConn(db, rvdb.SQLite), log)
	ctx := context.Background()

	k := newKey(uuid.New(), uuid.New(), "live-key")
	require.NoError(t, repo.Create(ctx, k))

	// Recovering a non-deleted key should fail
	err := repo.RecoverKey(ctx, k.ID)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not found in deleted state")
}

func TestKeyRepository_ReadDeletedScoped(t *testing.T) {
	t.Parallel()
	db := setupFullKeyDB(t)
	log := logging.InitLogger()
	repo := repositories.NewKeyRepository(rvdb.NewConn(db, rvdb.SQLite), log)
	ctx := context.Background()

	k := newKey(uuid.New(), uuid.New(), "read-deleted-key")
	require.NoError(t, repo.Create(ctx, k))
	require.NoError(t, repo.SoftDelete(ctx, k.ID))

	got, err := repo.ReadDeletedScoped(ctx, k.ID, model.NewAdminScope(uuid.Nil))
	require.NoError(t, err)
	assert.Equal(t, k.ID, got.ID)
	assert.NotNil(t, got.DeletedAt)
}

func TestKeyRepository_ReadDeletedScoped_NotFound(t *testing.T) {
	t.Parallel()
	db := setupFullKeyDB(t)
	log := logging.InitLogger()
	repo := repositories.NewKeyRepository(rvdb.NewConn(db, rvdb.SQLite), log)
	ctx := context.Background()

	_, err := repo.ReadDeletedScoped(ctx, uuid.New(), model.NewAdminScope(uuid.Nil))
	assert.Error(t, err)
}

func TestKeyRepository_ReadDeletedScoped_WrongVaultDenied(t *testing.T) {
	t.Parallel()
	db := setupFullKeyDB(t)
	log := logging.InitLogger()
	repo := repositories.NewKeyRepository(rvdb.NewConn(db, rvdb.SQLite), log)
	ctx := context.Background()

	k := newKey(uuid.New(), uuid.New(), "cross-vault-deleted-key")
	require.NoError(t, repo.Create(ctx, k))
	require.NoError(t, repo.SoftDelete(ctx, k.ID))

	_, err := repo.ReadDeletedScoped(ctx, k.ID, model.NewVaultScope(uuid.New(), uuid.Nil))
	assert.Error(t, err, "a key outside the scoped vault must not be readable")
}

func TestKeyRepository_SoftDeleteVaultContents(t *testing.T) {
	t.Parallel()
	db := setupFullKeyDB(t)
	log := logging.InitLogger()
	repo := repositories.NewKeyRepository(rvdb.NewConn(db, rvdb.SQLite), log)
	ctx := context.Background()

	vaultID := uuid.New()
	userID := uuid.New()

	k1 := newKey(userID, vaultID, "vault-key-1")
	k2 := newKey(userID, vaultID, "vault-key-2")
	k3 := newKey(userID, uuid.New(), "other-vault-key")

	require.NoError(t, repo.Create(ctx, k1))
	require.NoError(t, repo.Create(ctx, k2))
	require.NoError(t, repo.Create(ctx, k3))

	deletedAt := time.Now()
	require.NoError(t, repo.SoftDeleteVaultContents(ctx, vaultID, deletedAt))

	// Keys in vault should be hidden
	inVault, err := repo.List(ctx, model.NewVaultScope(vaultID, uuid.Nil), repositories.KeyFilter{})
	require.NoError(t, err)
	assert.Empty(t, inVault)

	// Key in other vault should still be visible
	_, err = repo.Read(ctx, k3.ID, model.NewAdminScope(uuid.Nil))
	require.NoError(t, err)
}

// TestKeyRepository_PurgeVaultContents_RemovesAllRows verifies purging a
// vault's key contents removes every key it ever held -- active or already
// soft-deleted -- rather than leaving orphaned rows behind.
func TestKeyRepository_PurgeVaultContents_RemovesAllRows(t *testing.T) {
	t.Parallel()
	db := setupFullKeyDB(t)
	log := logging.InitLogger()
	// PurgeVaultContents is intentionally not part of KeyRepositoryInterface
	// (see internal/repositories/key_repository.go); assert to the concrete
	// type to reach it, the way the vault cascade adapter does at runtime.
	repo := repositories.NewKeyRepository(rvdb.NewConn(db, rvdb.SQLite), log).(*repositories.KeyRepository)
	ctx := context.Background()

	vaultA := uuid.New()
	vaultB := uuid.New()
	userID := uuid.New()

	active := newKey(userID, vaultA, "active-key")
	deleted := newKey(userID, vaultA, "deleted-key")
	other := newKey(userID, vaultB, "other-vault-key")
	require.NoError(t, repo.Create(ctx, active))
	require.NoError(t, repo.Create(ctx, deleted))
	require.NoError(t, repo.Create(ctx, other))
	require.NoError(t, repo.SoftDelete(ctx, deleted.ID))

	require.NoError(t, repo.PurgeVaultContents(ctx, vaultA))

	all, err := repo.List(ctx, model.NewVaultScope(vaultA, uuid.Nil), repositories.KeyFilter{IncludeDeleted: true})
	require.NoError(t, err)
	assert.Empty(t, all, "purge must remove every key in the vault, active or soft-deleted")

	_, err = repo.Read(ctx, other.ID, model.NewAdminScope(uuid.Nil))
	require.NoError(t, err, "a key in a different vault must be untouched")
}

func TestKeyRepository_HasProtectedContent(t *testing.T) {
	t.Parallel()
	db := setupFullKeyDB(t)
	log := logging.InitLogger()
	repo := repositories.NewKeyRepository(rvdb.NewConn(db, rvdb.SQLite), log).(*repositories.KeyRepository)
	ctx := context.Background()

	vaultA := uuid.New()
	vaultB := uuid.New()
	userID := uuid.New()

	unprotected := newKey(userID, vaultA, "unprotected-key")
	require.NoError(t, repo.Create(ctx, unprotected))
	other := newKey(userID, vaultB, "other-vault-key")
	require.NoError(t, repo.Create(ctx, other))

	protected, err := repo.HasProtectedContent(ctx, vaultA)
	require.NoError(t, err)
	assert.False(t, protected, "no key in the vault has purge_protection set yet")

	require.NoError(t, repo.SetPurgeProtection(ctx, unprotected.ID, true))

	protected, err = repo.HasProtectedContent(ctx, vaultA)
	require.NoError(t, err)
	assert.True(t, protected, "a protected key exists in the vault")

	protected, err = repo.HasProtectedContent(ctx, vaultB)
	require.NoError(t, err)
	assert.False(t, protected, "vault B has no protected content of its own")
}

func TestKeyRepository_RecoverVaultContents(t *testing.T) {
	t.Parallel()
	db := setupFullKeyDB(t)
	log := logging.InitLogger()
	repo := repositories.NewKeyRepository(rvdb.NewConn(db, rvdb.SQLite), log)
	ctx := context.Background()

	vaultID := uuid.New()
	userID := uuid.New()

	k1 := newKey(userID, vaultID, "vault-key-a")
	k2 := newKey(userID, vaultID, "vault-key-b")
	require.NoError(t, repo.Create(ctx, k1))
	require.NoError(t, repo.Create(ctx, k2))

	deletedAt := time.Now().Truncate(time.Second)
	require.NoError(t, repo.SoftDeleteVaultContents(ctx, vaultID, deletedAt))

	// Verify they're gone
	inVault, err := repo.List(ctx, model.NewVaultScope(vaultID, uuid.Nil), repositories.KeyFilter{})
	require.NoError(t, err)
	assert.Empty(t, inVault)

	// Recover them
	require.NoError(t, repo.RecoverVaultContents(ctx, vaultID, deletedAt))

	// Verify they're back
	inVault, err = repo.List(ctx, model.NewVaultScope(vaultID, uuid.Nil), repositories.KeyFilter{})
	require.NoError(t, err)
	assert.Len(t, inVault, 2)
}

func TestKeyRepository_Update_NotFound(t *testing.T) {
	t.Parallel()
	db := setupFullKeyDB(t)
	log := logging.InitLogger()
	repo := repositories.NewKeyRepository(rvdb.NewConn(db, rvdb.SQLite), log)
	ctx := context.Background()

	k := newKey(uuid.New(), uuid.New(), "ghost")
	// Don't insert – just try to update
	err := repo.Update(ctx, k, model.NewAdminScope(uuid.Nil))
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

// TestKeyRepository_Update_VaultScope_NoOpWhenVaultMismatch mirrors
// TestSecretRepository_Update_VaultScope_NoOpWhenVaultMismatch: a scoped
// Update against the wrong vault must be rejected and leave the row
// untouched, proving the ScopedExec retrofit didn't relax cross-vault
// enforcement.
func TestKeyRepository_Update_VaultScope_NoOpWhenVaultMismatch(t *testing.T) {
	t.Parallel()
	db := setupFullKeyDB(t)
	log := logging.InitLogger()
	repo := repositories.NewKeyRepository(rvdb.NewConn(db, rvdb.SQLite), log)
	ctx := context.Background()

	realVault := uuid.New()
	k := newKey(uuid.New(), realVault, "k1")
	require.NoError(t, repo.Create(ctx, k))

	k.Name = "should-not-apply"
	err := repo.Update(ctx, k, model.NewVaultScope(uuid.New(), uuid.Nil)) // wrong vault
	require.Error(t, err)

	got, err := repo.Read(ctx, k.ID, model.NewVaultScope(realVault, uuid.Nil))
	require.NoError(t, err)
	assert.Equal(t, "k1", got.Name) // unchanged
}

func TestKeyRepository_ListByUser_ExcludesSoftDeleted(t *testing.T) {
	t.Parallel()
	db := setupFullKeyDB(t)
	log := logging.InitLogger()
	repo := repositories.NewKeyRepository(rvdb.NewConn(db, rvdb.SQLite), log)
	ctx := context.Background()

	userID := uuid.New()
	vault := uuid.New()

	k := newKey(userID, vault, "will-be-deleted")
	require.NoError(t, repo.Create(ctx, k))
	require.NoError(t, repo.SoftDelete(ctx, k.ID))

	list, err := repo.List(ctx, model.NewOwnerScope(uuid.Nil, userID), repositories.KeyFilter{})
	require.NoError(t, err)
	assert.Empty(t, list)
}

// ---------------------------------------------------------------------------
// CertificateRepository – uncovered paths
// ---------------------------------------------------------------------------

func TestCertificateRepository_Update(t *testing.T) {
	t.Parallel()
	db := setupFullCertDB(t)
	log := logging.InitLogger()
	repo := repositories.NewCertificateRepository(rvdb.NewConn(db, rvdb.SQLite), log)
	ctx := context.Background()

	userID := uuid.New()
	cert := newCert(userID, uuid.New(), "update-cert")
	require.NoError(t, repo.Create(ctx, cert))

	cert.Name = "updated-cert-name"
	cert.AutoRenew = true
	cert.RenewalDays = 45
	require.NoError(t, repo.Update(ctx, cert, model.NewAdminScope(uuid.Nil)))

	got, err := repo.Read(ctx, cert.ID, model.NewAdminScope(uuid.Nil))
	require.NoError(t, err)
	assert.Equal(t, "updated-cert-name", got.Name)
	assert.True(t, got.AutoRenew)
	assert.Equal(t, 45, got.RenewalDays)
}

func TestCertificateRepository_Update_NotFound(t *testing.T) {
	t.Parallel()
	db := setupFullCertDB(t)
	log := logging.InitLogger()
	repo := repositories.NewCertificateRepository(rvdb.NewConn(db, rvdb.SQLite), log)
	ctx := context.Background()

	cert := newCert(uuid.New(), uuid.New(), "ghost-cert")
	err := repo.Update(ctx, cert, model.NewAdminScope(uuid.Nil))
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

// TestCertificateRepository_Update_VaultScope_NoOpWhenVaultMismatch mirrors
// TestSecretRepository_Update_VaultScope_NoOpWhenVaultMismatch: a scoped
// Update against the wrong vault must be rejected and leave the row (and its
// tags) untouched, proving the ScopedExec retrofit didn't relax cross-vault
// enforcement even though certificate Update runs inside a manual
// transaction.
func TestCertificateRepository_Update_VaultScope_NoOpWhenVaultMismatch(t *testing.T) {
	t.Parallel()
	db := setupFullCertDB(t)
	log := logging.InitLogger()
	repo := repositories.NewCertificateRepository(rvdb.NewConn(db, rvdb.SQLite), log)
	ctx := context.Background()

	realVault := uuid.New()
	cert := newCert(uuid.New(), realVault, "c1")
	require.NoError(t, repo.Create(ctx, cert))

	cert.Name = "should-not-apply"
	err := repo.Update(ctx, cert, model.NewVaultScope(uuid.New(), uuid.Nil)) // wrong vault
	require.Error(t, err)

	got, err := repo.Read(ctx, cert.ID, model.NewVaultScope(realVault, uuid.Nil))
	require.NoError(t, err)
	assert.Equal(t, "c1", got.Name) // unchanged
}

func TestCertificateRepository_Delete(t *testing.T) {
	t.Parallel()
	db := setupFullCertDB(t)
	log := logging.InitLogger()
	repo := repositories.NewCertificateRepository(rvdb.NewConn(db, rvdb.SQLite), log)
	ctx := context.Background()

	cert := newCert(uuid.New(), uuid.New(), "delete-cert")
	require.NoError(t, repo.Create(ctx, cert))

	require.NoError(t, repo.Delete(ctx, cert.ID))

	_, err := repo.Read(ctx, cert.ID, model.NewAdminScope(uuid.Nil))
	assert.Error(t, err)
}

func TestCertificateRepository_Delete_NotFound(t *testing.T) {
	t.Parallel()
	db := setupFullCertDB(t)
	log := logging.InitLogger()
	repo := repositories.NewCertificateRepository(rvdb.NewConn(db, rvdb.SQLite), log)
	ctx := context.Background()

	err := repo.Delete(ctx, uuid.New())
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

func TestCertificateRepository_ListByUser(t *testing.T) {
	t.Parallel()
	db := setupFullCertDB(t)
	log := logging.InitLogger()
	repo := repositories.NewCertificateRepository(rvdb.NewConn(db, rvdb.SQLite), log)
	ctx := context.Background()

	userA := uuid.New()
	userB := uuid.New()
	vaultID := uuid.New()

	c1 := newCert(userA, vaultID, "cert-a1")
	c2 := newCert(userA, vaultID, "cert-a2")
	c3 := newCert(userB, vaultID, "cert-b1")

	require.NoError(t, repo.Create(ctx, c1))
	require.NoError(t, repo.Create(ctx, c2))
	require.NoError(t, repo.Create(ctx, c3))

	listA, err := repo.List(ctx, model.NewOwnerScope(uuid.Nil, userA), repositories.CertificateFilter{})
	require.NoError(t, err)
	assert.Len(t, listA, 2)

	listB, err := repo.List(ctx, model.NewOwnerScope(uuid.Nil, userB), repositories.CertificateFilter{})
	require.NoError(t, err)
	assert.Len(t, listB, 1)
}

func TestCertificateRepository_ListByUser_FiltersByTag(t *testing.T) {
	t.Parallel()
	db := setupFullCertDB(t)
	log := logging.InitLogger()
	repo := repositories.NewCertificateRepository(rvdb.NewConn(db, rvdb.SQLite), log)
	ctx := context.Background()

	userID := uuid.New()
	vaultID := uuid.New()

	c1 := newCert(userID, vaultID, "tagged-cert")
	c1.Tags = []string{"env:staging"}
	c2 := newCert(userID, vaultID, "plain-cert")

	require.NoError(t, repo.Create(ctx, c1))
	require.NoError(t, repo.Create(ctx, c2))

	tagged, err := repo.List(ctx, model.NewOwnerScope(uuid.Nil, userID), repositories.CertificateFilter{Tags: []string{"env:staging"}})
	require.NoError(t, err)
	assert.Len(t, tagged, 1)
	assert.Equal(t, c1.ID, tagged[0].ID)
}

func TestCertificateRepository_Revoke(t *testing.T) {
	t.Parallel()
	db := setupFullCertDB(t)
	log := logging.InitLogger()
	repo := repositories.NewCertificateRepository(rvdb.NewConn(db, rvdb.SQLite), log)
	ctx := context.Background()

	cert := newCert(uuid.New(), uuid.New(), "revoke-cert")
	require.NoError(t, repo.Create(ctx, cert))

	require.NoError(t, repo.Revoke(ctx, cert.ID, "SN-001", "revoke-cert"))

	revoked, err := repo.ListRevoked(ctx, cert.UserID)
	require.NoError(t, err)
	require.Len(t, revoked, 1)
	assert.Equal(t, "SN-001", revoked[0].SerialNumber)
}

func TestCertificateRepository_ListRevoked_Empty(t *testing.T) {
	t.Parallel()
	db := setupFullCertDB(t)
	log := logging.InitLogger()
	repo := repositories.NewCertificateRepository(rvdb.NewConn(db, rvdb.SQLite), log)
	ctx := context.Background()

	revoked, err := repo.ListRevoked(ctx, uuid.New())
	require.NoError(t, err)
	assert.Empty(t, revoked)
}

func TestCertificateRepository_RecoverCertificate(t *testing.T) {
	t.Parallel()
	db := setupFullCertDB(t)
	log := logging.InitLogger()
	repo := repositories.NewCertificateRepository(rvdb.NewConn(db, rvdb.SQLite), log)
	ctx := context.Background()

	cert := newCert(uuid.New(), uuid.New(), "recover-cert")
	require.NoError(t, repo.Create(ctx, cert))
	require.NoError(t, repo.SoftDelete(ctx, cert.ID))

	// Should be hidden
	_, err := repo.Read(ctx, cert.ID, model.NewAdminScope(uuid.Nil))
	require.Error(t, err)

	// Recover
	require.NoError(t, repo.RecoverCertificate(ctx, cert.ID))

	// Now visible
	got, err := repo.Read(ctx, cert.ID, model.NewAdminScope(uuid.Nil))
	require.NoError(t, err)
	assert.Equal(t, cert.ID, got.ID)
}

func TestCertificateRepository_RecoverCertificate_NotDeleted(t *testing.T) {
	t.Parallel()
	db := setupFullCertDB(t)
	log := logging.InitLogger()
	repo := repositories.NewCertificateRepository(rvdb.NewConn(db, rvdb.SQLite), log)
	ctx := context.Background()

	cert := newCert(uuid.New(), uuid.New(), "live-cert")
	require.NoError(t, repo.Create(ctx, cert))

	err := repo.RecoverCertificate(ctx, cert.ID)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not found in deleted state")
}

func TestCertificateRepository_SoftDeleteVaultContents(t *testing.T) {
	t.Parallel()
	db := setupFullCertDB(t)
	log := logging.InitLogger()
	repo := repositories.NewCertificateRepository(rvdb.NewConn(db, rvdb.SQLite), log)
	ctx := context.Background()

	vaultID := uuid.New()
	userID := uuid.New()

	c1 := newCert(userID, vaultID, "vault-cert-1")
	c2 := newCert(userID, vaultID, "vault-cert-2")
	c3 := newCert(userID, uuid.New(), "other-vault-cert")

	require.NoError(t, repo.Create(ctx, c1))
	require.NoError(t, repo.Create(ctx, c2))
	require.NoError(t, repo.Create(ctx, c3))

	deletedAt := time.Now()
	require.NoError(t, repo.SoftDeleteVaultContents(ctx, vaultID, deletedAt))

	inVault, err := repo.List(ctx, model.NewVaultScope(vaultID, uuid.Nil), repositories.CertificateFilter{})
	require.NoError(t, err)
	assert.Empty(t, inVault)

	// Other vault cert unaffected
	_, err = repo.Read(ctx, c3.ID, model.NewAdminScope(uuid.Nil))
	require.NoError(t, err)
}

// TestCertificateRepository_PurgeVaultContents_RemovesAllRows verifies
// purging a vault's certificate contents removes every certificate it ever
// held -- active or already soft-deleted -- rather than leaving orphaned
// rows behind.
func TestCertificateRepository_PurgeVaultContents_RemovesAllRows(t *testing.T) {
	t.Parallel()
	db := setupFullCertDB(t)
	log := logging.InitLogger()
	// PurgeVaultContents is intentionally not part of
	// CertificateRepositoryInterface (see internal/repositories/
	// certificate_repository.go); assert to the concrete type to reach it,
	// the way the vault cascade adapter does at runtime.
	repo := repositories.NewCertificateRepository(rvdb.NewConn(db, rvdb.SQLite), log).(*repositories.CertificateRepository)
	ctx := context.Background()

	vaultA := uuid.New()
	vaultB := uuid.New()
	userID := uuid.New()

	active := newCert(userID, vaultA, "active-cert")
	deleted := newCert(userID, vaultA, "deleted-cert")
	other := newCert(userID, vaultB, "other-vault-cert")
	require.NoError(t, repo.Create(ctx, active))
	require.NoError(t, repo.Create(ctx, deleted))
	require.NoError(t, repo.Create(ctx, other))
	require.NoError(t, repo.SoftDelete(ctx, deleted.ID))

	require.NoError(t, repo.PurgeVaultContents(ctx, vaultA))

	all, err := repo.List(ctx, model.NewVaultScope(vaultA, uuid.Nil), repositories.CertificateFilter{IncludeDeleted: true})
	require.NoError(t, err)
	assert.Empty(t, all, "purge must remove every certificate in the vault, active or soft-deleted")

	_, err = repo.Read(ctx, other.ID, model.NewAdminScope(uuid.Nil))
	require.NoError(t, err, "a certificate in a different vault must be untouched")
}

func TestCertificateRepository_HasProtectedContent(t *testing.T) {
	t.Parallel()
	db := setupFullCertDB(t)
	log := logging.InitLogger()
	repo := repositories.NewCertificateRepository(rvdb.NewConn(db, rvdb.SQLite), log).(*repositories.CertificateRepository)
	ctx := context.Background()

	vaultA := uuid.New()
	vaultB := uuid.New()
	userID := uuid.New()

	unprotected := newCert(userID, vaultA, "unprotected-cert")
	require.NoError(t, repo.Create(ctx, unprotected))
	other := newCert(userID, vaultB, "other-vault-cert")
	require.NoError(t, repo.Create(ctx, other))

	protected, err := repo.HasProtectedContent(ctx, vaultA)
	require.NoError(t, err)
	assert.False(t, protected, "no certificate in the vault has purge_protection set yet")

	require.NoError(t, repo.SetPurgeProtection(ctx, unprotected.ID, true))

	protected, err = repo.HasProtectedContent(ctx, vaultA)
	require.NoError(t, err)
	assert.True(t, protected, "a protected certificate exists in the vault")

	protected, err = repo.HasProtectedContent(ctx, vaultB)
	require.NoError(t, err)
	assert.False(t, protected, "vault B has no protected content of its own")
}

func TestCertificateRepository_RecoverVaultContents(t *testing.T) {
	t.Parallel()
	db := setupFullCertDB(t)
	log := logging.InitLogger()
	repo := repositories.NewCertificateRepository(rvdb.NewConn(db, rvdb.SQLite), log)
	ctx := context.Background()

	vaultID := uuid.New()
	userID := uuid.New()

	c1 := newCert(userID, vaultID, "vault-cert-x")
	c2 := newCert(userID, vaultID, "vault-cert-y")
	require.NoError(t, repo.Create(ctx, c1))
	require.NoError(t, repo.Create(ctx, c2))

	deletedAt := time.Now().Truncate(time.Second)
	require.NoError(t, repo.SoftDeleteVaultContents(ctx, vaultID, deletedAt))

	inVault, err := repo.List(ctx, model.NewVaultScope(vaultID, uuid.Nil), repositories.CertificateFilter{})
	require.NoError(t, err)
	assert.Empty(t, inVault)

	require.NoError(t, repo.RecoverVaultContents(ctx, vaultID, deletedAt))

	inVault, err = repo.List(ctx, model.NewVaultScope(vaultID, uuid.Nil), repositories.CertificateFilter{})
	require.NoError(t, err)
	assert.Len(t, inVault, 2)
}

func TestCertificateRepository_ListAll(t *testing.T) {
	t.Parallel()
	db := setupFullCertDB(t)
	log := logging.InitLogger()
	repo := repositories.NewCertificateRepository(rvdb.NewConn(db, rvdb.SQLite), log)
	ctx := context.Background()

	userID := uuid.New()
	vaultID := uuid.New()

	c1 := newCert(userID, vaultID, "all-cert-1")
	c2 := newCert(userID, vaultID, "all-cert-2")
	cDeleted := newCert(userID, vaultID, "deleted-cert")

	require.NoError(t, repo.Create(ctx, c1))
	require.NoError(t, repo.Create(ctx, c2))
	require.NoError(t, repo.Create(ctx, cDeleted))
	require.NoError(t, repo.SoftDelete(ctx, cDeleted.ID))

	all, err := repo.ListAll(ctx)
	require.NoError(t, err)
	assert.Len(t, all, 2, "ListAll should exclude soft-deleted certificates")
}

func TestCertificateRepository_ListInVault_ReturnsAll(t *testing.T) {
	t.Parallel()
	db := setupFullCertDB(t)
	log := logging.InitLogger()
	repo := repositories.NewCertificateRepository(rvdb.NewConn(db, rvdb.SQLite), log)
	ctx := context.Background()

	vaultID := uuid.New()
	userID := uuid.New()

	c1 := newCert(userID, vaultID, "cert-v1")
	c2 := newCert(userID, vaultID, "cert-v2")
	require.NoError(t, repo.Create(ctx, c1))
	require.NoError(t, repo.Create(ctx, c2))

	// No type filter returns all
	all, err := repo.List(ctx, model.NewVaultScope(vaultID, uuid.Nil), repositories.CertificateFilter{})
	require.NoError(t, err)
	assert.Len(t, all, 2)
}

func TestCertificateRepository_ReadInVault_WrongVault(t *testing.T) {
	t.Parallel()
	db := setupFullCertDB(t)
	log := logging.InitLogger()
	repo := repositories.NewCertificateRepository(rvdb.NewConn(db, rvdb.SQLite), log)
	ctx := context.Background()

	vaultA := uuid.New()
	vaultB := uuid.New()

	cert := newCert(uuid.New(), vaultA, "cert-in-a")
	require.NoError(t, repo.Create(ctx, cert))

	_, err := repo.Read(ctx, cert.ID, model.NewVaultScope(vaultB, uuid.Nil))
	assert.Error(t, err, "Read with the wrong vault scope must return error")
}

// ---------------------------------------------------------------------------
// AccessPolicyRepository – List (0% covered)
// ---------------------------------------------------------------------------

func TestAccessPolicyRepository_List(t *testing.T) {
	t.Parallel()
	db := setupAccessPolicyTestDB(t)
	repo := repositories.NewAccessPolicyRepository(rvdb.NewConn(db, rvdb.SQLite))
	ctx := context.Background()

	// Ensure list on empty table works
	empty, err := repo.List(ctx)
	require.NoError(t, err)
	assert.Empty(t, empty)

	// Insert two policies for different principals
	p1 := &model.AccessPolicy{
		ID:            uuid.New(),
		PrincipalID:   uuid.New(),
		PrincipalType: model.PrincipalTypeUser,
		ResourceType:  model.PolicyResourceSecrets,
		Operation:     model.OpGet,
		Effect:        model.PolicyEffectAllow,
	}
	p2 := &model.AccessPolicy{
		ID:            uuid.New(),
		PrincipalID:   uuid.New(),
		PrincipalType: model.PrincipalTypeUser,
		ResourceType:  model.PolicyResourceKeys,
		Operation:     model.OpList,
		Effect:        model.PolicyEffectDeny,
	}
	require.NoError(t, repo.Create(ctx, p1))
	require.NoError(t, repo.Create(ctx, p2))

	all, err := repo.List(ctx)
	require.NoError(t, err)
	assert.Len(t, all, 2)
}

func TestAccessPolicyRepository_List_WithVaultScoped(t *testing.T) {
	t.Parallel()
	db := setupAccessPolicyTestDB(t)
	repo := repositories.NewAccessPolicyRepository(rvdb.NewConn(db, rvdb.SQLite))
	ctx := context.Background()

	vaultID := uuid.New()
	p := &model.AccessPolicy{
		ID:            uuid.New(),
		PrincipalID:   uuid.New(),
		PrincipalType: model.PrincipalTypeUser,
		ResourceType:  model.PolicyResourceCertificates,
		Operation:     model.OpCreate,
		Effect:        model.PolicyEffectAllow,
		VaultID:       &vaultID,
	}
	require.NoError(t, repo.Create(ctx, p))

	all, err := repo.List(ctx)
	require.NoError(t, err)
	require.Len(t, all, 1)
	require.NotNil(t, all[0].VaultID)
	assert.Equal(t, vaultID, *all[0].VaultID)
}

// ---------------------------------------------------------------------------
// AuditRepository – additional uncovered paths
// (Note: TestAuditRepository_PersistAudit, TestAuditRepository_GetLastHash_EmptyTable,
// TestAuditRepository_DeleteBefore and TestAuditRepository_AuditConfig_RoundTrip are
// already covered in audit_repository_test.go — these tests cover different filter
// combinations and edge cases not yet exercised.)
// ---------------------------------------------------------------------------

// setupAuditDBFull creates a fresh full-schema audit DB for tests not relying
// on openAuditTestDBFull (which is already declared in audit_repository_test.go).
func setupAuditDBFull(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite3", ":memory:")
	require.NoError(t, err)
	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS audit_logs (
			id TEXT PRIMARY KEY,
			user_id TEXT,
			action TEXT NOT NULL,
			details TEXT,
			timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			resource_type TEXT,
			resource_id TEXT,
			ip_address TEXT,
			outcome TEXT,
			source TEXT,
			prev_hash TEXT
		);
		CREATE TABLE IF NOT EXISTS audit_config (
			key   TEXT PRIMARY KEY,
			value TEXT NOT NULL
		);
	`)
	require.NoError(t, err)
	t.Cleanup(func() { db.Close() }) //nolint:errcheck,gosec
	return db
}

func TestAuditRepository_InsertAuditLog_FullEntry(t *testing.T) {
	t.Parallel()
	db := setupAuditDBFull(t)
	repo := repositories.NewAuditRepository(rvdb.NewConn(db, rvdb.SQLite))
	ctx := context.Background()

	entry := repositories.AuditLog{
		UserID:       uuid.New().String(),
		Action:       "create_secret",
		Details:      "created secret foo",
		ResourceType: "secret",
		ResourceID:   uuid.New().String(),
		IPAddress:    "192.168.1.1",
		Outcome:      "success",
		Source:       "api",
		PrevHash:     "abc123",
	}
	require.NoError(t, repo.InsertAuditLog(ctx, entry))

	logs, total, err := repo.QueryAuditLogs(ctx, repositories.AuditFilter{})
	require.NoError(t, err)
	assert.Equal(t, int64(1), total)
	assert.Len(t, logs, 1)
	assert.Equal(t, "create_secret", logs[0].Action)
	assert.Equal(t, "success", logs[0].Outcome)
	assert.Equal(t, "192.168.1.1", logs[0].IPAddress)
}

func TestAuditRepository_InsertAuditLog_PreservesProvidedID(t *testing.T) {
	t.Parallel()
	db := setupAuditDBFull(t)
	repo := repositories.NewAuditRepository(rvdb.NewConn(db, rvdb.SQLite))
	ctx := context.Background()

	id := uuid.New().String()
	entry := repositories.AuditLog{
		ID:     id,
		Action: "test-action",
	}
	require.NoError(t, repo.InsertAuditLog(ctx, entry))

	logs, _, err := repo.QueryAuditLogs(ctx, repositories.AuditFilter{})
	require.NoError(t, err)
	require.Len(t, logs, 1)
	assert.Equal(t, id, logs[0].ID)
}

func TestAuditRepository_GetLastHash_ReturnsLatest(t *testing.T) {
	t.Parallel()
	db := setupAuditDBFull(t)
	repo := repositories.NewAuditRepository(rvdb.NewConn(db, rvdb.SQLite))
	ctx := context.Background()

	require.NoError(t, repo.InsertAuditLog(ctx, repositories.AuditLog{Action: "a1", PrevHash: "hash1"}))
	require.NoError(t, repo.InsertAuditLog(ctx, repositories.AuditLog{Action: "a2", PrevHash: "hash2"}))

	hash, err := repo.GetLastHash(ctx)
	require.NoError(t, err)
	// The last-inserted row's prev_hash is returned
	assert.NotEmpty(t, hash)
}

func TestAuditRepository_QueryAuditLogs_AllFilters(t *testing.T) {
	t.Parallel()
	db := setupAuditDBFull(t)
	repo := repositories.NewAuditRepository(rvdb.NewConn(db, rvdb.SQLite))
	ctx := context.Background()

	userID := uuid.New().String()
	now := time.Now().UTC()
	from := now.Add(-time.Hour)
	to := now.Add(time.Hour)
	action := "read_secret"
	outcome := "success"
	resourceType := "secret"
	resourceID := uuid.New().String()
	source := "cli"

	require.NoError(t, repo.InsertAuditLog(ctx, repositories.AuditLog{
		UserID:       userID,
		Action:       action,
		Outcome:      outcome,
		ResourceType: resourceType,
		ResourceID:   resourceID,
		Source:       source,
	}))

	// Insert a non-matching entry
	require.NoError(t, repo.InsertAuditLog(ctx, repositories.AuditLog{
		UserID: uuid.New().String(),
		Action: "other_action",
	}))

	filter := repositories.AuditFilter{
		From:         &from,
		To:           &to,
		UserID:       &userID,
		Action:       &action,
		Outcome:      &outcome,
		ResourceType: &resourceType,
		ResourceID:   &resourceID,
		Source:       &source,
		Limit:        10,
	}
	logs, total, err := repo.QueryAuditLogs(ctx, filter)
	require.NoError(t, err)
	assert.Equal(t, int64(1), total)
	assert.Len(t, logs, 1)
	assert.Equal(t, action, logs[0].Action)
}

func TestAuditRepository_DeleteBefore_MultipleOld(t *testing.T) {
	t.Parallel()
	db := setupAuditDBFull(t)
	repo := repositories.NewAuditRepository(rvdb.NewConn(db, rvdb.SQLite))
	ctx := context.Background()

	base := time.Now().UTC()
	// Three entries with explicit timestamps so SQLite compares them predictably.
	oldEntry1 := repositories.AuditLog{
		Action:    "old1",
		Timestamp: base.Add(-48 * time.Hour),
	}
	oldEntry2 := repositories.AuditLog{
		Action:    "old2",
		Timestamp: base.Add(-24 * time.Hour),
	}
	// New entry is clearly in the future; using an explicit timestamp avoids
	// relying on CURRENT_TIMESTAMP string-comparison semantics in SQLite.
	newEntry := repositories.AuditLog{
		Action:    "new",
		Timestamp: base.Add(24 * time.Hour),
	}

	require.NoError(t, repo.InsertAuditLog(ctx, oldEntry1))
	require.NoError(t, repo.InsertAuditLog(ctx, oldEntry2))
	require.NoError(t, repo.InsertAuditLog(ctx, newEntry))

	// Cutoff sits between old (-24h) and new (+24h), so only 2 rows get deleted.
	cutoff := base.Add(-time.Hour)
	deleted, err := repo.DeleteBefore(ctx, cutoff)
	require.NoError(t, err)
	assert.Equal(t, int64(2), deleted)

	logs, total, err := repo.QueryAuditLogs(ctx, repositories.AuditFilter{})
	require.NoError(t, err)
	assert.Equal(t, int64(1), total)
	require.Len(t, logs, 1)
	assert.Equal(t, "new", logs[0].Action)
}

func TestAuditRepository_SetAndGetConfig(t *testing.T) {
	t.Parallel()
	db := setupAuditDBFull(t)
	repo := repositories.NewAuditRepository(rvdb.NewConn(db, rvdb.SQLite))
	ctx := context.Background()

	require.NoError(t, repo.SetAuditConfig(ctx, "retention_days", "90"))

	val, err := repo.GetAuditConfig(ctx, "retention_days")
	require.NoError(t, err)
	assert.Equal(t, "90", val)

	// Upsert
	require.NoError(t, repo.SetAuditConfig(ctx, "retention_days", "180"))
	val, err = repo.GetAuditConfig(ctx, "retention_days")
	require.NoError(t, err)
	assert.Equal(t, "180", val)
}

func TestAuditRepository_GetConfig_Missing(t *testing.T) {
	t.Parallel()
	db := setupAuditDBFull(t)
	repo := repositories.NewAuditRepository(rvdb.NewConn(db, rvdb.SQLite))
	ctx := context.Background()

	val, err := repo.GetAuditConfig(ctx, "nonexistent_key")
	require.NoError(t, err)
	assert.Equal(t, "", val)
}

func TestAuditRepository_QueryAuditLogs_LimitCap(t *testing.T) {
	t.Parallel()
	db := setupAuditDBFull(t)
	repo := repositories.NewAuditRepository(rvdb.NewConn(db, rvdb.SQLite))
	ctx := context.Background()

	// Requesting > 1000 should be capped at 1000 (no panic)
	_, _, err := repo.QueryAuditLogs(ctx, repositories.AuditFilter{Limit: 5000})
	require.NoError(t, err)
}

// ---------------------------------------------------------------------------
// RotationPolicyRepository – uncovered paths (0%)
// ---------------------------------------------------------------------------

func TestRotationPolicyRepository_CRUD(t *testing.T) {
	t.Parallel()
	db := setupRotationDB(t)
	log := logging.InitLogger()
	repo := repositories.NewRotationPolicyRepository(rvdb.NewConn(db, rvdb.SQLite), log)
	ctx := context.Background()

	userID := uuid.New()
	vaultID := uuid.New()
	now := time.Now()

	policy := &model.RotationPolicy{
		ID:           uuid.New(),
		UserID:       userID,
		VaultID:      vaultID,
		Name:         "30-day-rotation",
		Description:  "Rotate every 30 days",
		IntervalDays: 30,
		Enabled:      true,
		ReminderDays: 7,
		AutoRotate:   false,
		CreatedAt:    now,
		UpdatedAt:    now,
	}
	require.NoError(t, repo.Create(ctx, policy))

	// Read
	got, err := repo.Read(ctx, policy.ID, model.NewVaultScope(vaultID, uuid.New()))
	require.NoError(t, err)
	assert.Equal(t, policy.ID, got.ID)
	assert.Equal(t, "30-day-rotation", got.Name)
	assert.Equal(t, 30, got.IntervalDays)

	// Update
	policy.Name = "60-day-rotation"
	policy.IntervalDays = 60
	policy.UpdatedAt = time.Now()
	require.NoError(t, repo.Update(ctx, policy, model.NewVaultScope(vaultID, uuid.New())))

	updated, err := repo.Read(ctx, policy.ID, model.NewVaultScope(vaultID, uuid.New()))
	require.NoError(t, err)
	assert.Equal(t, "60-day-rotation", updated.Name)
	assert.Equal(t, 60, updated.IntervalDays)

	// Delete
	require.NoError(t, repo.Delete(ctx, policy.ID, model.NewVaultScope(vaultID, uuid.New())))
	_, err = repo.Read(ctx, policy.ID, model.NewAdminScope(uuid.New()))
	assert.Error(t, err)
}

func TestRotationPolicyRepository_Read_NotFound(t *testing.T) {
	t.Parallel()
	db := setupRotationDB(t)
	log := logging.InitLogger()
	repo := repositories.NewRotationPolicyRepository(rvdb.NewConn(db, rvdb.SQLite), log)
	ctx := context.Background()

	_, err := repo.Read(ctx, uuid.New(), model.NewAdminScope(uuid.New()))
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

func TestRotationPolicyRepository_Update_NotFound(t *testing.T) {
	t.Parallel()
	db := setupRotationDB(t)
	log := logging.InitLogger()
	repo := repositories.NewRotationPolicyRepository(rvdb.NewConn(db, rvdb.SQLite), log)
	ctx := context.Background()

	policy := &model.RotationPolicy{
		ID:           uuid.New(),
		UserID:       uuid.New(),
		VaultID:      uuid.New(),
		Name:         "ghost",
		IntervalDays: 1,
		UpdatedAt:    time.Now(),
	}
	err := repo.Update(ctx, policy, model.NewAdminScope(uuid.New()))
	assert.Error(t, err)
}

func TestRotationPolicyRepository_Delete_NotFound(t *testing.T) {
	t.Parallel()
	db := setupRotationDB(t)
	log := logging.InitLogger()
	repo := repositories.NewRotationPolicyRepository(rvdb.NewConn(db, rvdb.SQLite), log)
	ctx := context.Background()

	err := repo.Delete(ctx, uuid.New(), model.NewAdminScope(uuid.New()))
	assert.Error(t, err)
}

func TestRotationPolicyRepository_List(t *testing.T) {
	t.Parallel()
	db := setupRotationDB(t)
	log := logging.InitLogger()
	repo := repositories.NewRotationPolicyRepository(rvdb.NewConn(db, rvdb.SQLite), log)
	ctx := context.Background()

	vaultA := uuid.New()
	vaultB := uuid.New()
	now := time.Now()

	p1 := &model.RotationPolicy{ID: uuid.New(), UserID: uuid.New(), VaultID: vaultA, Name: "p1", IntervalDays: 7, CreatedAt: now, UpdatedAt: now}
	p2 := &model.RotationPolicy{ID: uuid.New(), UserID: uuid.New(), VaultID: vaultA, Name: "p2", IntervalDays: 14, CreatedAt: now, UpdatedAt: now}
	p3 := &model.RotationPolicy{ID: uuid.New(), UserID: uuid.New(), VaultID: vaultB, Name: "p3", IntervalDays: 30, CreatedAt: now, UpdatedAt: now}

	require.NoError(t, repo.Create(ctx, p1))
	require.NoError(t, repo.Create(ctx, p2))
	require.NoError(t, repo.Create(ctx, p3))

	listA, err := repo.List(ctx, model.NewVaultScope(vaultA, uuid.New()))
	require.NoError(t, err)
	assert.Len(t, listA, 2)

	listB, err := repo.List(ctx, model.NewVaultScope(vaultB, uuid.New()))
	require.NoError(t, err)
	assert.Len(t, listB, 1)

	listAll, err := repo.List(ctx, model.NewAdminScope(uuid.New()))
	require.NoError(t, err)
	assert.Len(t, listAll, 3)
}

func TestRotationPolicyRepository_AssignAndRemoveFromSecret(t *testing.T) {
	t.Parallel()
	db := setupRotationDB(t)
	log := logging.InitLogger()
	repo := repositories.NewRotationPolicyRepository(rvdb.NewConn(db, rvdb.SQLite), log)
	ctx := context.Background()

	now := time.Now()
	userID := uuid.New()

	// Create a policy first
	policy := &model.RotationPolicy{
		ID:           uuid.New(),
		UserID:       userID,
		VaultID:      uuid.New(),
		Name:         "assign-test",
		IntervalDays: 30,
		CreatedAt:    now,
		UpdatedAt:    now,
	}
	require.NoError(t, repo.Create(ctx, policy))

	secretID := uuid.New()
	nextRotation := now.Add(30 * 24 * time.Hour)

	require.NoError(t, repo.AssignToSecret(ctx, secretID, policy.ID, now, nextRotation))

	// GetSecretPolicies
	sps, err := repo.GetSecretPolicies(ctx, secretID)
	require.NoError(t, err)
	require.Len(t, sps, 1)
	assert.Equal(t, secretID, sps[0].SecretID)
	assert.Equal(t, policy.ID, sps[0].PolicyID)

	// GetPoliciesForSecret
	policies, err := repo.GetPoliciesForSecret(ctx, secretID)
	require.NoError(t, err)
	require.Len(t, policies, 1)
	assert.Equal(t, policy.ID, policies[0].ID)

	// UpdateSecretPolicyRotation
	lastRotated := now
	nextRotation2 := now.Add(60 * 24 * time.Hour)
	require.NoError(t, repo.UpdateSecretPolicyRotation(ctx, secretID, policy.ID, lastRotated, nextRotation2))

	// RemoveFromSecret
	require.NoError(t, repo.RemoveFromSecret(ctx, secretID, policy.ID))

	spsAfter, err := repo.GetSecretPolicies(ctx, secretID)
	require.NoError(t, err)
	assert.Empty(t, spsAfter)
}

func TestRotationPolicyRepository_RecordAndGetHistory(t *testing.T) {
	t.Parallel()
	db := setupRotationDB(t)
	log := logging.InitLogger()
	repo := repositories.NewRotationPolicyRepository(rvdb.NewConn(db, rvdb.SQLite), log)
	ctx := context.Background()

	secretID := uuid.New()
	history := &model.RotationHistory{
		ID:              uuid.New(),
		SecretID:        secretID,
		RotatedAt:       time.Now(),
		PreviousVersion: 1,
		NewVersion:      2,
		TriggeredBy:     "manual",
		Notes:           "manual rotation test",
	}

	require.NoError(t, repo.RecordRotation(ctx, history))

	got, err := repo.GetRotationHistory(ctx, secretID)
	require.NoError(t, err)
	require.Len(t, got, 1)
	assert.Equal(t, history.ID, got[0].ID)
	assert.Equal(t, "manual", got[0].TriggeredBy)
}

func TestRotationPolicyRepository_CreateAndGetReminder(t *testing.T) {
	t.Parallel()
	db := setupRotationDB(t)
	log := logging.InitLogger()
	repo := repositories.NewRotationPolicyRepository(rvdb.NewConn(db, rvdb.SQLite), log)
	ctx := context.Background()

	now := time.Now()
	userID := uuid.New()

	// We need a real policy row for the JOIN in GetUpcomingReminders
	policy := &model.RotationPolicy{
		ID:           uuid.New(),
		UserID:       userID,
		VaultID:      uuid.New(),
		Name:         "reminder-test",
		IntervalDays: 30,
		Enabled:      true,
		CreatedAt:    now,
		UpdatedAt:    now,
	}
	require.NoError(t, repo.Create(ctx, policy))

	secretID := uuid.New()
	nextReminder := now.Add(-time.Minute) // in the past so GetUpcomingReminders picks it up

	reminder := &model.RotationReminder{
		ID:             uuid.New(),
		SecretID:       secretID,
		PolicyID:       policy.ID,
		ReminderType:   "upcoming",
		SentAt:         now,
		NextReminderAt: &nextReminder,
		Acknowledged:   false,
	}
	require.NoError(t, repo.CreateReminder(ctx, reminder))

	// GetReminderBySecret
	got, err := repo.GetReminderBySecret(ctx, secretID, policy.ID, "upcoming")
	require.NoError(t, err)
	require.NotNil(t, got)
	assert.Equal(t, reminder.ID, got.ID)

	// UpdateReminder (acknowledge it)
	got.Acknowledged = true
	require.NoError(t, repo.UpdateReminder(ctx, got))

	// After acknowledgement, GetReminderBySecret should return nil (filters acknowledged=FALSE)
	gone, err := repo.GetReminderBySecret(ctx, secretID, policy.ID, "upcoming")
	require.NoError(t, err)
	assert.Nil(t, gone)

	// GetUpcomingReminders should also be empty since we acknowledged
	upcoming, err := repo.GetUpcomingReminders(ctx, model.NewAdminScope(userID))
	require.NoError(t, err)
	assert.Empty(t, upcoming)
}

func TestRotationPolicyRepository_GetDueRotations(t *testing.T) {
	t.Parallel()
	db := setupRotationDB(t)
	log := logging.InitLogger()
	repo := repositories.NewRotationPolicyRepository(rvdb.NewConn(db, rvdb.SQLite), log)
	ctx := context.Background()

	now := time.Now()
	userID := uuid.New()

	policy := &model.RotationPolicy{
		ID:           uuid.New(),
		UserID:       userID,
		VaultID:      uuid.New(),
		Name:         "due-test",
		IntervalDays: 30,
		Enabled:      true,
		CreatedAt:    now,
		UpdatedAt:    now,
	}
	require.NoError(t, repo.Create(ctx, policy))

	secretID := uuid.New()
	// next_rotation_at in the past → due now
	pastRotation := now.Add(-time.Minute)
	require.NoError(t, repo.AssignToSecret(ctx, secretID, policy.ID, now, pastRotation))

	due, err := repo.GetDueRotations(ctx, model.NewAdminScope(userID))
	require.NoError(t, err)
	assert.Len(t, due, 1)
	assert.Equal(t, secretID, due[0].SecretID)
}

func TestRotationPolicyRepository_Read_CrossVaultDenied(t *testing.T) {
	t.Parallel()
	db := setupRotationDB(t)
	log := logging.InitLogger()
	repo := repositories.NewRotationPolicyRepository(rvdb.NewConn(db, rvdb.SQLite), log)
	ctx := context.Background()

	vaultA, vaultB := uuid.New(), uuid.New()
	now := time.Now()
	policy := &model.RotationPolicy{ID: uuid.New(), UserID: uuid.New(), VaultID: vaultA, Name: "p", IntervalDays: 30, CreatedAt: now, UpdatedAt: now}
	require.NoError(t, repo.Create(ctx, policy))

	got, err := repo.Read(ctx, policy.ID, model.NewVaultScope(vaultA, uuid.New()))
	require.NoError(t, err)
	assert.Equal(t, policy.Name, got.Name)

	_, err = repo.Read(ctx, policy.ID, model.NewVaultScope(vaultB, uuid.New()))
	assert.Error(t, err, "a policy in vault A must not be readable under vault B's scope")
}

func TestRotationPolicyRepository_Update_CrossVaultDenied(t *testing.T) {
	t.Parallel()
	db := setupRotationDB(t)
	log := logging.InitLogger()
	repo := repositories.NewRotationPolicyRepository(rvdb.NewConn(db, rvdb.SQLite), log)
	ctx := context.Background()

	vaultA, vaultB := uuid.New(), uuid.New()
	now := time.Now()
	policy := &model.RotationPolicy{ID: uuid.New(), UserID: uuid.New(), VaultID: vaultA, Name: "p", IntervalDays: 30, CreatedAt: now, UpdatedAt: now}
	require.NoError(t, repo.Create(ctx, policy))

	policy.Name = "renamed"
	assert.Error(t, repo.Update(ctx, policy, model.NewVaultScope(vaultB, uuid.New())), "update scoped to the wrong vault must fail")
	require.NoError(t, repo.Update(ctx, policy, model.NewVaultScope(vaultA, uuid.New())))

	got, err := repo.Read(ctx, policy.ID, model.NewVaultScope(vaultA, uuid.New()))
	require.NoError(t, err)
	assert.Equal(t, "renamed", got.Name)
}

func TestRotationPolicyRepository_Delete_CrossVaultDenied(t *testing.T) {
	t.Parallel()
	db := setupRotationDB(t)
	log := logging.InitLogger()
	repo := repositories.NewRotationPolicyRepository(rvdb.NewConn(db, rvdb.SQLite), log)
	ctx := context.Background()

	vaultA, vaultB := uuid.New(), uuid.New()
	now := time.Now()
	policy := &model.RotationPolicy{ID: uuid.New(), UserID: uuid.New(), VaultID: vaultA, Name: "p", IntervalDays: 30, CreatedAt: now, UpdatedAt: now}
	require.NoError(t, repo.Create(ctx, policy))

	assert.Error(t, repo.Delete(ctx, policy.ID, model.NewVaultScope(vaultB, uuid.New())))
	require.NoError(t, repo.Delete(ctx, policy.ID, model.NewVaultScope(vaultA, uuid.New())))
	_, err := repo.Read(ctx, policy.ID, model.NewAdminScope(uuid.New()))
	assert.Error(t, err)
}

func TestRotationPolicyRepository_GetDueRotations_FiltersByVault(t *testing.T) {
	t.Parallel()
	db := setupRotationDB(t)
	log := logging.InitLogger()
	repo := repositories.NewRotationPolicyRepository(rvdb.NewConn(db, rvdb.SQLite), log)
	ctx := context.Background()

	vaultA, vaultB := uuid.New(), uuid.New()
	now := time.Now()
	policyA := &model.RotationPolicy{ID: uuid.New(), UserID: uuid.New(), VaultID: vaultA, Name: "pa", IntervalDays: 30, Enabled: true, CreatedAt: now, UpdatedAt: now}
	policyB := &model.RotationPolicy{ID: uuid.New(), UserID: uuid.New(), VaultID: vaultB, Name: "pb", IntervalDays: 30, Enabled: true, CreatedAt: now, UpdatedAt: now}
	require.NoError(t, repo.Create(ctx, policyA))
	require.NoError(t, repo.Create(ctx, policyB))

	secretA, secretB := uuid.New(), uuid.New()
	past := now.Add(-time.Hour)
	require.NoError(t, repo.AssignToSecret(ctx, secretA, policyA.ID, now, past))
	require.NoError(t, repo.AssignToSecret(ctx, secretB, policyB.ID, now, past))

	dueA, err := repo.GetDueRotations(ctx, model.NewVaultScope(vaultA, uuid.New()))
	require.NoError(t, err)
	require.Len(t, dueA, 1)
	assert.Equal(t, secretA, dueA[0].SecretID)

	dueAll, err := repo.GetDueRotations(ctx, model.NewAdminScope(uuid.New()))
	require.NoError(t, err)
	assert.Len(t, dueAll, 2)
}

// ---------------------------------------------------------------------------
// KeyRepository / CertificateRepository -- vault-cascade Tx-scoped methods
// ---------------------------------------------------------------------------

func TestKeyRepository_SoftDeleteVaultContentsTx_CommitsWithSharedTx(t *testing.T) {
	t.Parallel()
	db := setupFullKeyDB(t)
	log := logging.InitLogger()
	conn := rvdb.NewConn(db, rvdb.SQLite)
	// SoftDeleteVaultContentsTx is intentionally not part of KeyRepositoryInterface
	// (see internal/repositories/key_repository.go); assert to the concrete type
	// to reach it, the way a same-package cascade caller would.
	repo := repositories.NewKeyRepository(conn, log).(*repositories.KeyRepository)
	ctx := context.Background()

	vaultID := uuid.New()
	k := newKey(uuid.New(), vaultID, "tx-key")
	require.NoError(t, repo.Create(ctx, k))

	tx, err := conn.BeginTx(ctx, nil)
	require.NoError(t, err)
	require.NoError(t, repo.SoftDeleteVaultContentsTx(ctx, tx, vaultID, time.Now().UTC()))
	require.NoError(t, tx.Commit())

	_, err = repo.Read(ctx, k.ID, model.NewAdminScope(uuid.Nil))
	assert.Error(t, err, "key must be hidden after the transaction commits")
}

func TestKeyRepository_SoftDeleteVaultContentsTx_RollsBackWithSharedTx(t *testing.T) {
	t.Parallel()
	db := setupFullKeyDB(t)
	log := logging.InitLogger()
	conn := rvdb.NewConn(db, rvdb.SQLite)
	// SoftDeleteVaultContentsTx is intentionally not part of KeyRepositoryInterface
	// (see internal/repositories/key_repository.go); assert to the concrete type
	// to reach it, the way a same-package cascade caller would.
	repo := repositories.NewKeyRepository(conn, log).(*repositories.KeyRepository)
	ctx := context.Background()

	vaultID := uuid.New()
	k := newKey(uuid.New(), vaultID, "tx-key-rb")
	require.NoError(t, repo.Create(ctx, k))

	tx, err := conn.BeginTx(ctx, nil)
	require.NoError(t, err)
	require.NoError(t, repo.SoftDeleteVaultContentsTx(ctx, tx, vaultID, time.Now().UTC()))
	require.NoError(t, tx.Rollback())

	_, err = repo.Read(ctx, k.ID, model.NewAdminScope(uuid.Nil))
	require.NoError(t, err, "key must still be active after rollback")
}

func TestCertificateRepository_SoftDeleteVaultContentsTx_CommitsWithSharedTx(t *testing.T) {
	t.Parallel()
	db := setupFullCertDB(t)
	log := logging.InitLogger()
	conn := rvdb.NewConn(db, rvdb.SQLite)
	// SoftDeleteVaultContentsTx is intentionally not part of CertificateRepositoryInterface
	// (see internal/repositories/certificate_repository.go); assert to the concrete type
	// to reach it, the way a same-package cascade caller would.
	repo := repositories.NewCertificateRepository(conn, log).(*repositories.CertificateRepository)
	ctx := context.Background()

	vaultID := uuid.New()
	c := newCert(uuid.New(), vaultID, "tx-cert")
	require.NoError(t, repo.Create(ctx, c))

	tx, err := conn.BeginTx(ctx, nil)
	require.NoError(t, err)
	require.NoError(t, repo.SoftDeleteVaultContentsTx(ctx, tx, vaultID, time.Now().UTC()))
	require.NoError(t, tx.Commit())

	_, err = repo.Read(ctx, c.ID, model.NewAdminScope(uuid.Nil))
	assert.Error(t, err, "certificate must be hidden after the transaction commits")
}

func TestCertificateRepository_SoftDeleteVaultContentsTx_RollsBackWithSharedTx(t *testing.T) {
	t.Parallel()
	db := setupFullCertDB(t)
	log := logging.InitLogger()
	conn := rvdb.NewConn(db, rvdb.SQLite)
	// SoftDeleteVaultContentsTx is intentionally not part of CertificateRepositoryInterface
	// (see internal/repositories/certificate_repository.go); assert to the concrete type
	// to reach it, the way a same-package cascade caller would.
	repo := repositories.NewCertificateRepository(conn, log).(*repositories.CertificateRepository)
	ctx := context.Background()

	vaultID := uuid.New()
	c := newCert(uuid.New(), vaultID, "tx-cert-rb")
	require.NoError(t, repo.Create(ctx, c))

	tx, err := conn.BeginTx(ctx, nil)
	require.NoError(t, err)
	require.NoError(t, repo.SoftDeleteVaultContentsTx(ctx, tx, vaultID, time.Now().UTC()))
	require.NoError(t, tx.Rollback())

	_, err = repo.Read(ctx, c.ID, model.NewAdminScope(uuid.Nil))
	require.NoError(t, err, "certificate must still be active after rollback")
}
