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

func setupCertKeyIDTestDB(t *testing.T) *sql.DB {
	t.Helper()
	// Use a shared-cache in-memory database so every pooled connection sees the
	// same schema. Listing certificates reads tags on a second connection while
	// rows are open, which would otherwise hit a fresh, empty in-memory database.
	dsn := "file:certkeyidtest_" + uuid.NewString() + "?mode=memory&cache=shared"
	db, err := sql.Open("sqlite3", dsn)
	require.NoError(t, err)
	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS certificates (
		id TEXT PRIMARY KEY,
		user_id TEXT NOT NULL,
		vault_id TEXT NOT NULL DEFAULT '00000000-0000-0000-0000-00000000efa1',
		name TEXT NOT NULL,
		certificate TEXT NOT NULL,
		private_key TEXT NOT NULL,
		version INTEGER NOT NULL DEFAULT 1,
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

// TestCertificateRepository_KeyID_Persisted verifies that a non-nil KeyID round-trips
// through Create and Read without corruption.
func TestCertificateRepository_KeyID_Persisted(t *testing.T) {
	db := setupCertKeyIDTestDB(t)
	log := logging.InitLogger()
	repo := repositories.NewCertificateRepository(rvdb.NewConn(db, rvdb.SQLite), log)

	keyID := uuid.New()
	cert := &model.Certificate{
		ID:          uuid.New(),
		UserID:      uuid.New(),
		KeyID:       keyID,
		Name:        "key-id-test-cert",
		Certificate: "-----BEGIN CERTIFICATE-----\nMIItest\n-----END CERTIFICATE-----",
		PrivateKey:  "encrypted-private-key",
		CreatedAt:   time.Now().UTC().Truncate(time.Second),
		AutoRenew:   false,
		RenewalDays: 30,
	}

	err := repo.Create(context.Background(), cert)
	require.NoError(t, err)

	got, err := repo.Read(context.Background(), cert.ID, model.NewAdminScope(uuid.Nil))
	require.NoError(t, err)
	assert.Equal(t, keyID, got.KeyID, "KeyID should round-trip through Create/Read")
}

// TestCertificateRepository_KeyID_NilUUID verifies that a zero-value KeyID (uuid.Nil) is
// stored as a valid UUID string and reads back as uuid.Nil.
func TestCertificateRepository_KeyID_NilUUID(t *testing.T) {
	db := setupCertKeyIDTestDB(t)
	log := logging.InitLogger()
	repo := repositories.NewCertificateRepository(rvdb.NewConn(db, rvdb.SQLite), log)

	cert := &model.Certificate{
		ID:          uuid.New(),
		UserID:      uuid.New(),
		KeyID:       uuid.Nil, // zero value
		Name:        "nil-key-id-cert",
		Certificate: "PEM",
		PrivateKey:  "ENCRYPTED",
		CreatedAt:   time.Now().UTC(),
		AutoRenew:   false,
		RenewalDays: 30,
	}

	err := repo.Create(context.Background(), cert)
	require.NoError(t, err)

	got, err := repo.Read(context.Background(), cert.ID, model.NewAdminScope(uuid.Nil))
	require.NoError(t, err)
	// uuid.Nil.String() == "00000000-0000-0000-0000-000000000000", which is valid — parses back to uuid.Nil
	assert.Equal(t, uuid.Nil, got.KeyID)
}

// TestCertificateRepository_ListInVault_ScopesByVault verifies that ListInVault
// returns only certificates belonging to the requested vault.
func TestCertificateRepository_ListInVault_ScopesByVault(t *testing.T) {
	db := setupCertKeyIDTestDB(t)
	log := logging.InitLogger()
	repo := repositories.NewCertificateRepository(rvdb.NewConn(db, rvdb.SQLite), log)
	ctx := context.Background()
	vaultA, vaultB := uuid.New(), uuid.New()

	mk := func(name string, v uuid.UUID) *model.Certificate {
		return &model.Certificate{
			ID:          uuid.New(),
			UserID:      uuid.New(),
			VaultID:     v,
			Name:        name,
			Certificate: "cert-pem",
			PrivateKey:  "encrypted",
			CreatedAt:   time.Now(),
			RenewalDays: 30,
			Enabled:     true,
		}
	}
	require.NoError(t, repo.Create(ctx, mk("a", vaultA)))
	require.NoError(t, repo.Create(ctx, mk("b", vaultA)))
	require.NoError(t, repo.Create(ctx, mk("c", vaultB)))

	gotA, err := repo.List(ctx, model.NewVaultScope(vaultA, uuid.Nil), repositories.CertificateFilter{})
	require.NoError(t, err)
	require.Len(t, gotA, 2)
	gotB, err := repo.List(ctx, model.NewVaultScope(vaultB, uuid.Nil), repositories.CertificateFilter{})
	require.NoError(t, err)
	require.Len(t, gotB, 1)
}

// TestCertificateRepository_ReadInVault_PopulatesVaultID verifies that ReadInVault
// and ListInVault set VaultID on returned certificates to the queried vault.
func TestCertificateRepository_ReadInVault_PopulatesVaultID(t *testing.T) {
	db := setupCertKeyIDTestDB(t)
	log := logging.InitLogger()
	repo := repositories.NewCertificateRepository(rvdb.NewConn(db, rvdb.SQLite), log)
	ctx := context.Background()
	vaultA := uuid.New()

	cert := &model.Certificate{
		ID:          uuid.New(),
		UserID:      uuid.New(),
		VaultID:     vaultA,
		Name:        "vault-id-cert",
		Certificate: "cert-pem",
		PrivateKey:  "encrypted",
		CreatedAt:   time.Now(),
		RenewalDays: 30,
		Enabled:     true,
	}
	require.NoError(t, repo.Create(ctx, cert))

	read, err := repo.Read(ctx, cert.ID, model.NewVaultScope(vaultA, uuid.Nil))
	require.NoError(t, err)
	assert.Equal(t, vaultA, read.VaultID, "Read with a vault scope must populate VaultID on returned certificate")

	listed, err := repo.List(ctx, model.NewVaultScope(vaultA, uuid.Nil), repositories.CertificateFilter{})
	require.NoError(t, err)
	require.Len(t, listed, 1)
	assert.Equal(t, vaultA, listed[0].VaultID, "List with a vault scope must populate VaultID on returned certificates")
}
