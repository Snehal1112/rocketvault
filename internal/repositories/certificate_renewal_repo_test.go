package repositories_test

import (
	"context"
	"database/sql"
	"testing"
	"time"

	_ "github.com/mattn/go-sqlite3"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	rvdb "rocketvault/internal/db"
	"rocketvault/internal/logging"
	"rocketvault/internal/repositories"
	"rocketvault/model"
)

// setupCertRenewalTestDB creates an in-memory SQLite DB with the renewal columns.
func setupCertRenewalTestDB(t *testing.T) *sql.DB {
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

// TestCertificateRepositoryRenewalFields verifies that renewal fields are persisted and read back correctly.
func TestCertificateRepositoryRenewalFields(t *testing.T) {
	db := setupCertRenewalTestDB(t)
	log := logging.InitLogger()
	repo := repositories.NewCertificateRepository(rvdb.NewConn(db, rvdb.SQLite), log)

	expires := time.Now().Add(90 * 24 * time.Hour).UTC().Truncate(time.Second)
	cert := &model.Certificate{
		ID:          uuid.New(),
		UserID:      uuid.New(),
		Name:        "test-cert",
		Certificate: "PEM",
		PrivateKey:  "ENCRYPTED",
		CreatedAt:   time.Now().UTC(),
		ExpiresAt:   &expires,
		AutoRenew:   true,
		RenewalDays: 14,
	}

	err := repo.Create(context.Background(), cert)
	require.NoError(t, err)

	got, err := repo.Read(context.Background(), cert.ID, model.NewAdminScope(uuid.Nil))
	require.NoError(t, err)
	assert.True(t, got.AutoRenew)
	assert.Equal(t, 14, got.RenewalDays)
	require.NotNil(t, got.ExpiresAt)
	assert.WithinDuration(t, expires, *got.ExpiresAt, time.Second)
}

// TestCertificateRepositoryListAll verifies that ListAll returns all non-deleted certificates.
func TestCertificateRepositoryListAll(t *testing.T) {
	db := setupCertRenewalTestDB(t)
	log := logging.InitLogger()
	repo := repositories.NewCertificateRepository(rvdb.NewConn(db, rvdb.SQLite), log)

	cert := &model.Certificate{
		ID:          uuid.New(),
		UserID:      uuid.New(),
		Name:        "list-all-cert",
		Certificate: "PEM",
		PrivateKey:  "ENCRYPTED",
		CreatedAt:   time.Now().UTC(),
		AutoRenew:   false,
		RenewalDays: 30,
	}
	require.NoError(t, repo.Create(context.Background(), cert))

	all, err := repo.ListAll(context.Background())
	require.NoError(t, err)
	assert.Len(t, all, 1)
	assert.Equal(t, cert.ID, all[0].ID)
}
