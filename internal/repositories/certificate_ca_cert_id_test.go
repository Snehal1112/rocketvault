package repositories_test

import (
	"context"
	"database/sql"
	"testing"

	"github.com/google/uuid"
	_ "github.com/mattn/go-sqlite3"
	"github.com/stretchr/testify/require"

	rvdb "rocketvault/internal/db"
	"rocketvault/internal/logging"
	"rocketvault/internal/repositories"
	"rocketvault/model"
)

func setupCertCACertIDTestDB(t *testing.T) *sql.DB {
	t.Helper()

	dsn := "file:certcacerttest_" + uuid.NewString() + "?mode=memory&cache=shared"
	db, err := sql.Open("sqlite3", dsn)
	require.NoError(t, err)

	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS certificates (
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
			key_id TEXT NOT NULL DEFAULT '',
			ca_cert_id TEXT NULL,
			enabled BOOLEAN NOT NULL DEFAULT TRUE,
			not_before TIMESTAMP NULL
		);
		CREATE TABLE IF NOT EXISTS certificate_tags (
			certificate_id TEXT NOT NULL, tag TEXT NOT NULL,
			PRIMARY KEY (certificate_id, tag)
		);
	`)
	require.NoError(t, err)

	t.Cleanup(func() { db.Close() }) //nolint:errcheck,gosec
	return db
}

// A CA-signed certificate must remember its issuer across a write and a read,
// or renewal has nothing to branch on (B37).
func TestCertificateRepository_CACertID_RoundTrips(t *testing.T) {
	db := setupCertCACertIDTestDB(t)
	repo := repositories.NewCertificateRepository(rvdb.NewConn(db, rvdb.SQLite), logging.InitLogger())
	ctx := context.Background()

	userID := uuid.New()
	vaultID := uuid.MustParse(model.DefaultVaultID)
	caCertID := uuid.New()

	cert := &model.Certificate{
		ID:          uuid.New(),
		UserID:      userID,
		VaultID:     vaultID,
		KeyID:       uuid.New(),
		CACertID:    &caCertID,
		Name:        "ca-signed",
		Certificate: "cert-pem",
		PrivateKey:  "encrypted-key",
		Enabled:     true,
		RenewalDays: 30,
	}
	require.NoError(t, repo.Create(ctx, cert))

	scope := model.NewVaultScope(vaultID, userID)
	got, err := repo.Read(ctx, cert.ID, scope)
	require.NoError(t, err)
	require.NotNil(t, got.CACertID, "a CA-signed certificate must read back with its CA link")
	require.Equal(t, caCertID, *got.CACertID)
}

// A self-signed certificate must read back with no CA link, not a zero UUID.
func TestCertificateRepository_CACertID_NilForSelfSigned(t *testing.T) {
	db := setupCertCACertIDTestDB(t)
	repo := repositories.NewCertificateRepository(rvdb.NewConn(db, rvdb.SQLite), logging.InitLogger())
	ctx := context.Background()

	userID := uuid.New()
	vaultID := uuid.MustParse(model.DefaultVaultID)

	cert := &model.Certificate{
		ID:          uuid.New(),
		UserID:      userID,
		VaultID:     vaultID,
		KeyID:       uuid.New(),
		Name:        "self-signed",
		Certificate: "cert-pem",
		PrivateKey:  "encrypted-key",
		Enabled:     true,
		RenewalDays: 30,
	}
	require.NoError(t, repo.Create(ctx, cert))

	scope := model.NewVaultScope(vaultID, userID)
	got, err := repo.Read(ctx, cert.ID, scope)
	require.NoError(t, err)
	require.Nil(t, got.CACertID)
}

// Update must not disturb the CA link. Renewal writes through Update, so a
// column touched there would erase the issuer on the first renewal.
func TestCertificateRepository_CACertID_SurvivesUpdate(t *testing.T) {
	db := setupCertCACertIDTestDB(t)
	repo := repositories.NewCertificateRepository(rvdb.NewConn(db, rvdb.SQLite), logging.InitLogger())
	ctx := context.Background()

	userID := uuid.New()
	vaultID := uuid.MustParse(model.DefaultVaultID)
	caCertID := uuid.New()

	cert := &model.Certificate{
		ID:          uuid.New(),
		UserID:      userID,
		VaultID:     vaultID,
		KeyID:       uuid.New(),
		CACertID:    &caCertID,
		Name:        "ca-signed",
		Certificate: "cert-pem",
		PrivateKey:  "encrypted-key",
		Enabled:     true,
		RenewalDays: 30,
	}
	require.NoError(t, repo.Create(ctx, cert))

	scope := model.NewVaultScope(vaultID, userID)
	updated := *cert
	updated.Certificate = "renewed-pem"
	updated.CACertID = nil // Even an explicit nil must not clear the column.
	require.NoError(t, repo.Update(ctx, &updated, scope))

	got, err := repo.Read(ctx, cert.ID, scope)
	require.NoError(t, err)
	require.Equal(t, "cert-pem", got.Certificate,
		"Update writes metadata only; a renewal writes the body through ArchiveAndRenew")
	require.NotNil(t, got.CACertID, "Update must leave ca_cert_id alone")
	require.Equal(t, caCertID, *got.CACertID)
}

// The renewal scheduler reads certificates through ListAll, so it needs the
// CA link too or auto-renewal regresses to self-signing.
func TestCertificateRepository_CACertID_InListAll(t *testing.T) {
	db := setupCertCACertIDTestDB(t)
	repo := repositories.NewCertificateRepository(rvdb.NewConn(db, rvdb.SQLite), logging.InitLogger())
	ctx := context.Background()

	caCertID := uuid.New()
	cert := &model.Certificate{
		ID:          uuid.New(),
		UserID:      uuid.New(),
		VaultID:     uuid.MustParse(model.DefaultVaultID),
		KeyID:       uuid.New(),
		CACertID:    &caCertID,
		Name:        "ca-signed",
		Certificate: "cert-pem",
		PrivateKey:  "encrypted-key",
		Enabled:     true,
		RenewalDays: 30,
	}
	require.NoError(t, repo.Create(ctx, cert))

	all, err := repo.ListAll(ctx)
	require.NoError(t, err)
	require.Len(t, all, 1)
	require.NotNil(t, all[0].CACertID)
	require.Equal(t, caCertID, *all[0].CACertID)
}
