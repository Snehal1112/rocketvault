package repositories_test

import (
	"context"
	"database/sql"
	"testing"
	"time"

	_ "github.com/mattn/go-sqlite3"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	rvdb "rocketvault/internal/db"
	"rocketvault/internal/logging"
	"rocketvault/internal/repositories"
	"rocketvault/model"
)

// setupCertLifecycleTestDB creates an in-memory SQLite DB with lifecycle columns.
func setupCertLifecycleTestDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite3", ":memory:")
	require.NoError(t, err)
	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS certificates (
		id TEXT PRIMARY KEY,
		user_id TEXT NOT NULL,
		vault_id TEXT NOT NULL DEFAULT '00000000-0000-0000-0000-00000000efa1',
		name TEXT NOT NULL,
		certificate TEXT NOT NULL,
		private_key TEXT NOT NULL,
		version INTEGER NOT NULL DEFAULT 1,
		exportable BOOLEAN NOT NULL DEFAULT FALSE,
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		deleted_at TIMESTAMP NULL,
		purge_protection BOOLEAN NOT NULL DEFAULT FALSE,
		scheduled_purge_at TIMESTAMP NULL,
		expires_at DATETIME,
		auto_renew BOOLEAN NOT NULL DEFAULT FALSE,
		renewal_days INTEGER NOT NULL DEFAULT 30,
		key_id TEXT,
		ca_cert_id TEXT NULL,
		enabled BOOLEAN NOT NULL DEFAULT TRUE,
		not_before TIMESTAMP NULL
	)`)
	require.NoError(t, err)
	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS certificate_tags (
		certificate_id TEXT NOT NULL, tag TEXT NOT NULL,
		PRIMARY KEY (certificate_id, tag))`)
	require.NoError(t, err)
	createCertificateVersionsTable(t, db)
	t.Cleanup(func() { db.Close() }) //nolint:errcheck,gosec
	return db
}

// TestCertLifecycleAttributes_PersistAndLoad verifies that enabled and not_before are
// persisted to the database and correctly read back.
func TestCertLifecycleAttributes_PersistAndLoad(t *testing.T) {
	t.Parallel()
	db := setupCertLifecycleTestDB(t)
	log := logging.InitLogger()
	repo := repositories.NewCertificateRepository(rvdb.NewConn(db, rvdb.SQLite), log)

	now := time.Now().UTC().Truncate(time.Second)
	nbf := now.Add(-1 * time.Hour)

	cert := &model.Certificate{
		ID:          uuid.New(),
		UserID:      uuid.New(),
		Name:        "test-cert",
		Certificate: "cert-data",
		PrivateKey:  "key-data",
		CreatedAt:   now,
		Enabled:     true,
		NotBefore:   &nbf,
	}
	require.NoError(t, repo.Create(context.Background(), cert))

	loaded, err := repo.Read(context.Background(), cert.ID, model.NewAdminScope(uuid.Nil))
	require.NoError(t, err)
	require.True(t, loaded.Enabled)
	require.NotNil(t, loaded.NotBefore)
	require.WithinDuration(t, nbf, *loaded.NotBefore, time.Second)
}

// TestCertLifecycleAttributes_DisabledCertNotAccessible verifies that a disabled
// certificate is reported as inaccessible by IsAccessible.
func TestCertLifecycleAttributes_DisabledCertNotAccessible(t *testing.T) {
	t.Parallel()
	cert := &model.Certificate{
		Enabled: false,
	}
	require.False(t, cert.IsAccessible())
}

// TestCertLifecycleAttributes_EnabledCertWithFutureNBF verifies that a certificate
// whose not_before is in the future is reported as inaccessible.
func TestCertLifecycleAttributes_EnabledCertWithFutureNBF(t *testing.T) {
	t.Parallel()
	future := time.Now().Add(1 * time.Hour)
	cert := &model.Certificate{
		Enabled:   true,
		NotBefore: &future,
	}
	require.False(t, cert.IsAccessible())
}

// TestCertLifecycleAttributes_EnabledCertAccessible verifies that an enabled certificate
// with a past not_before is reported as accessible.
func TestCertLifecycleAttributes_EnabledCertAccessible(t *testing.T) {
	t.Parallel()
	past := time.Now().Add(-1 * time.Hour)
	cert := &model.Certificate{
		Enabled:   true,
		NotBefore: &past,
	}
	require.True(t, cert.IsAccessible())
}
