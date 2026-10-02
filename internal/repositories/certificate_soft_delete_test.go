package repositories_test

import (
	"context"
	"database/sql"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	sqlite3 "github.com/mattn/go-sqlite3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	rvdb "rocketvault/internal/db"
	"rocketvault/internal/logging"
	"rocketvault/internal/repositories"
	"rocketvault/model"
)

// setupCertTestDB creates an in-memory SQLite database with the certificates table.
// The table includes the soft-delete columns required by the repository.
func setupCertTestDB(t *testing.T) *sql.DB {
	t.Helper()

	// Use a shared-cache in-memory database so every pooled connection sees the
	// same schema. List() reads tags via a second connection, which would
	// otherwise hit a fresh, empty in-memory database.
	dsn := "file:certtest_" + uuid.NewString() + "?mode=memory&cache=shared"
	db, err := sql.Open("sqlite3", dsn)
	require.NoError(t, err, "failed to open in-memory database")

	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS certificates (
			id TEXT PRIMARY KEY,
			user_id TEXT NOT NULL,
			vault_id TEXT NOT NULL DEFAULT '00000000-0000-0000-0000-00000000efa1',
			name TEXT NOT NULL,
			certificate TEXT NOT NULL,
			private_key TEXT NOT NULL,
			version INTEGER NOT NULL DEFAULT 1,
			exportable BOOLEAN NOT NULL DEFAULT FALSE,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			deleted_at TIMESTAMP DEFAULT NULL,
			purge_protection BOOLEAN NOT NULL DEFAULT FALSE,
			scheduled_purge_at TIMESTAMP DEFAULT NULL,
			expires_at TIMESTAMP,
			auto_renew BOOLEAN NOT NULL DEFAULT FALSE,
			renewal_days INTEGER NOT NULL DEFAULT 30,
			key_id TEXT,
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
	require.NoError(t, err, "failed to create certificate test schema")
	createCertificateVersionsTable(t, db)

	t.Cleanup(func() { db.Close() }) //nolint:errcheck,gosec

	return db
}

// newTestCert builds a minimal Certificate suitable for insertion via Create.
func newTestCert(userID uuid.UUID, name string) *model.Certificate {
	return &model.Certificate{
		ID:          uuid.New(),
		UserID:      userID,
		Name:        name,
		Certificate: "-----BEGIN CERTIFICATE-----\nMIItest\n-----END CERTIFICATE-----",
		PrivateKey:  "encrypted-private-key",
		CreatedAt:   time.Now(),
	}
}

// TestCertificateSoftDelete verifies that SoftDelete hides the certificate from Read
// while making it visible through List with OnlyDeleted.
func TestCertificateSoftDelete(t *testing.T) {
	t.Parallel()
	db := setupCertTestDB(t)
	log := logging.InitLogger()
	repo := repositories.NewCertificateRepository(rvdb.NewConn(db, rvdb.SQLite), log)
	ctx := context.Background()
	userID := uuid.New()

	cert := newTestCert(userID, "soft-delete-cert")
	require.NoError(t, repo.Create(ctx, cert))

	// SoftDelete sets deleted_at, leaves the row in the table.
	require.NoError(t, repo.SoftDelete(ctx, cert.ID))

	// Normal Read should return an error because the cert is now soft-deleted.
	_, err := repo.Read(ctx, cert.ID, model.NewAdminScope(uuid.Nil))
	assert.Error(t, err, "Read should fail for a soft-deleted certificate")

	// List with OnlyDeleted should include the certificate.
	deleted, err := repo.List(ctx, model.NewOwnerScope(uuid.Nil, userID), repositories.CertificateFilter{OnlyDeleted: true})
	require.NoError(t, err)
	require.Len(t, deleted, 1)
	assert.Equal(t, cert.ID, deleted[0].ID)
	assert.NotNil(t, deleted[0].DeletedAt)
}

// TestCertificatePurge verifies that PurgeCertificate permanently removes a soft-deleted certificate.
func TestCertificatePurge(t *testing.T) {
	t.Parallel()
	db := setupCertTestDB(t)
	log := logging.InitLogger()
	repo := repositories.NewCertificateRepository(rvdb.NewConn(db, rvdb.SQLite), log)
	ctx := context.Background()
	userID := uuid.New()

	cert := newTestCert(userID, "purge-cert")
	require.NoError(t, repo.Create(ctx, cert))
	require.NoError(t, repo.SoftDelete(ctx, cert.ID))

	// PurgeCertificate should permanently remove the row.
	require.NoError(t, repo.PurgeCertificate(ctx, cert.ID))

	deleted, err := repo.List(ctx, model.NewOwnerScope(uuid.Nil, userID), repositories.CertificateFilter{OnlyDeleted: true})
	require.NoError(t, err)
	assert.Empty(t, deleted, "certificate should be permanently removed after purge")
}

// TestCertificatePurgeProtection verifies that PurgeCertificate fails when purge protection is enabled.
func TestCertificatePurgeProtection(t *testing.T) {
	t.Parallel()
	db := setupCertTestDB(t)
	log := logging.InitLogger()
	repo := repositories.NewCertificateRepository(rvdb.NewConn(db, rvdb.SQLite), log)
	ctx := context.Background()
	userID := uuid.New()

	cert := newTestCert(userID, "protected-cert")
	require.NoError(t, repo.Create(ctx, cert))
	require.NoError(t, repo.SoftDelete(ctx, cert.ID))
	require.NoError(t, repo.SetPurgeProtection(ctx, cert.ID, true))

	// Purge must fail while purge_protection is true.
	err := repo.PurgeCertificate(ctx, cert.ID)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "purge protection")
}

// TestCertificateSoftDelete_PreservesPurgeProtection verifies that SoftDelete does not
// overwrite a pre-existing purge_protection = TRUE on a certificate.
func TestCertificateSoftDelete_PreservesPurgeProtection(t *testing.T) {
	t.Parallel()
	db := setupCertTestDB(t)
	log := logging.InitLogger()
	repo := repositories.NewCertificateRepository(rvdb.NewConn(db, rvdb.SQLite), log)
	ctx := context.Background()
	userID := uuid.New()

	cert := newTestCert(userID, "pp-cert")
	require.NoError(t, repo.Create(ctx, cert))

	// Enable purge protection before soft-deleting.
	require.NoError(t, repo.SetPurgeProtection(ctx, cert.ID, true))

	// SoftDelete must not reset purge_protection to FALSE.
	require.NoError(t, repo.SoftDelete(ctx, cert.ID))

	var pp bool
	err := db.QueryRowContext(ctx,
		"SELECT purge_protection FROM certificates WHERE id = ?", cert.ID.String()).Scan(&pp)
	require.NoError(t, err)
	assert.True(t, pp, "SoftDelete must not overwrite purge_protection")
}

// TestCertificateRepository_Create_NameCollision_ReturnsErrNameTaken is the
// B50 secondary fix: creating a certificate whose name collides with an
// ACTIVE certificate in the same vault must surface repositories.ErrNameTaken,
// not the raw driver error. This uses a real SQLite database with the same
// partial unique index finalizeVaultIndexes installs in production, so the
// constraint violation is a genuine driver error, not a mock.
func TestCertificateRepository_Create_NameCollision_ReturnsErrNameTaken(t *testing.T) {
	t.Parallel()
	db := setupCertTestDB(t)
	_, err := db.Exec(`CREATE UNIQUE INDEX idx_certificates_vault_name ON certificates(vault_id, name) WHERE deleted_at IS NULL`)
	require.NoError(t, err)

	log := logging.InitLogger()
	repo := repositories.NewCertificateRepository(rvdb.NewConn(db, rvdb.SQLite), log)
	ctx := context.Background()
	userID := uuid.New()
	vaultID := uuid.New()

	first := newTestCert(userID, "taken-cert")
	first.VaultID = vaultID
	require.NoError(t, repo.Create(ctx, first))

	// A second, active certificate with the same name in the same vault must
	// be rejected as a name collision.
	second := newTestCert(userID, "taken-cert")
	second.VaultID = vaultID
	err = repo.Create(ctx, second)
	require.Error(t, err)
	assert.ErrorIs(t, err, repositories.ErrNameTaken, "collision must be reported as ErrNameTaken, got: %v", err)

	// The original driver error must still be reachable through %w, proving
	// this wraps the real constraint error rather than replacing it outright.
	var sqliteErr sqlite3.Error
	assert.True(t, errors.As(err, &sqliteErr), "original sqlite3.Error must still be reachable via errors.As, got: %v", err)

	// A non-colliding create in the same vault must still succeed.
	third := newTestCert(userID, "different-cert")
	third.VaultID = vaultID
	assert.NoError(t, repo.Create(ctx, third), "a non-colliding create must still succeed")
}
