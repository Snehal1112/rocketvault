package vaults_test

import (
	"context"
	"database/sql"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	_ "github.com/mattn/go-sqlite3"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"

	rvdb "rocketvault/internal/db"
	"rocketvault/internal/logging"
	"rocketvault/internal/repositories"
	vaultServices "rocketvault/internal/services/vaults"
	"rocketvault/model"
)

func newTxTestLogger(t *testing.T) *logging.Logger {
	t.Helper()
	l := logrus.New()
	l.SetLevel(logrus.DebugLevel)
	return &logging.Logger{Logger: l}
}

// newTxTestDB creates an in-memory SQLite database with just enough schema
// (vaults + secrets) to prove a transaction shared between VaultRepository
// and SecretRepository rolls back or commits both tables together.
func newTxTestDB(t *testing.T) *sql.DB {
	t.Helper()
	sqlDB, err := sql.Open("sqlite3", ":memory:")
	require.NoError(t, err)
	_, err = sqlDB.Exec(`
		CREATE TABLE vaults (
			id TEXT PRIMARY KEY, name TEXT UNIQUE NOT NULL,
			enabled BOOLEAN NOT NULL DEFAULT 1,
			purge_protection BOOLEAN NOT NULL DEFAULT 0,
			retention_days INTEGER NOT NULL DEFAULT 90,
			created_by TEXT NOT NULL,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			deleted_at TIMESTAMP NULL,
			scheduled_purge_at TIMESTAMP NULL,
			tags TEXT NOT NULL DEFAULT '{}',
			updated_at TIMESTAMP NULL,
			updated_by TEXT NULL
		);
		CREATE TABLE secrets (
			id               TEXT PRIMARY KEY,
			user_id          TEXT NOT NULL,
			vault_id         TEXT NOT NULL DEFAULT '00000000-0000-0000-0000-00000000efa1',
			name             TEXT NOT NULL,
			value            TEXT NOT NULL,
			version          INTEGER NOT NULL,
			created_at       TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			deleted_at       TIMESTAMP NULL,
			purge_protection BOOLEAN NOT NULL DEFAULT FALSE,
			scheduled_purge_at TIMESTAMP NULL,
			content_type     TEXT NOT NULL DEFAULT '',
			enabled          BOOLEAN NOT NULL DEFAULT TRUE,
			expires_at       TIMESTAMP NULL,
			not_before       TIMESTAMP NULL
		);`)
	require.NoError(t, err)
	t.Cleanup(func() { sqlDB.Close() }) //nolint:errcheck,gosec
	return sqlDB
}

// explodingContentRepo stands in for a cascade participant (e.g.
// certificates) that fails mid-cascade, proving the transaction rolls back
// every repo's writes, not just its own.
type explodingContentRepo struct{ err error }

func (e *explodingContentRepo) SoftDeleteVaultContents(context.Context, uuid.UUID, time.Time) error {
	return e.err
}
func (e *explodingContentRepo) RecoverVaultContents(context.Context, uuid.UUID, time.Time) error {
	return e.err
}
func (e *explodingContentRepo) SoftDeleteVaultContentsTx(context.Context, rvdb.DBTX, uuid.UUID, time.Time) error {
	return e.err
}
func (e *explodingContentRepo) RecoverVaultContentsTx(context.Context, rvdb.DBTX, uuid.UUID, time.Time) error {
	return e.err
}

func deletedAtColumn(t *testing.T, sqlDB *sql.DB, table string, id uuid.UUID) *time.Time {
	t.Helper()
	var deletedAt sql.NullTime
	require.NoError(t, sqlDB.QueryRow("SELECT deleted_at FROM "+table+" WHERE id = ?", id.String()).Scan(&deletedAt))
	if !deletedAt.Valid {
		return nil
	}
	return &deletedAt.Time
}

func TestDeleteVault_CascadeFailureRollsBackEverything(t *testing.T) {
	sqlDB := newTxTestDB(t)
	conn := rvdb.NewConn(sqlDB, rvdb.SQLite)
	log := newTxTestLogger(t)
	ctx := context.Background()

	vaultRepo := repositories.NewVaultRepository(conn, log)
	secretRepo := repositories.NewSecretRepository(conn, log)

	vaultID := uuid.New()
	require.NoError(t, vaultRepo.Create(ctx, &model.Vault{
		ID: vaultID, Name: "prod", Enabled: true, RetentionDays: 90, CreatedBy: uuid.New(),
	}))
	secretID := uuid.New()
	require.NoError(t, secretRepo.Create(ctx, &model.Secret{
		ID: secretID, UserID: uuid.New(), VaultID: vaultID, Name: "s1", Value: "enc",
		Version: 1, CreatedAt: time.Now().UTC(), Enabled: true,
	}))

	boom := errors.New("cert cascade boom")
	cascade := vaultServices.NewCascadeAdapter(secretRepo, &explodingContentRepo{err: boom})
	svc := vaultServices.NewVaultService(vaultRepo, cascade, log)
	svc.SetTxBeginner(conn)

	err := svc.DeleteVault(ctx, "prod", uuid.New())
	require.Error(t, err)
	require.ErrorIs(t, err, boom)

	require.Nil(t, deletedAtColumn(t, sqlDB, "vaults", vaultID), "vault soft-delete must have rolled back")
	require.Nil(t, deletedAtColumn(t, sqlDB, "secrets", secretID), "secret soft-delete must have rolled back with it")
}

// TestRecoverVault_CascadeFailureRollsBackEverything proves RecoverVault's
// transactional path -- structurally identical to DeleteVault's (RecoverTx +
// RecoverVaultContentsTx inside one withTx) -- rolls back the vault row's
// recovery when the cascade fails, against a real SQLite database. Unlike the
// delete tests, the fixture starts from an ALREADY soft-deleted vault and
// secret sharing the same deleted_at, mirroring what DeleteVault's own
// cascade would have produced in production.
func TestRecoverVault_CascadeFailureRollsBackEverything(t *testing.T) {
	sqlDB := newTxTestDB(t)
	conn := rvdb.NewConn(sqlDB, rvdb.SQLite)
	log := newTxTestLogger(t)
	ctx := context.Background()

	vaultRepo := repositories.NewVaultRepository(conn, log)
	secretRepo := repositories.NewSecretRepository(conn, log)

	vaultID := uuid.New()
	require.NoError(t, vaultRepo.Create(ctx, &model.Vault{
		ID: vaultID, Name: "prod", Enabled: true, RetentionDays: 90, CreatedBy: uuid.New(),
	}))
	secretID := uuid.New()
	require.NoError(t, secretRepo.Create(ctx, &model.Secret{
		ID: secretID, UserID: uuid.New(), VaultID: vaultID, Name: "s1", Value: "enc",
		Version: 1, CreatedAt: time.Now().UTC(), Enabled: true,
	}))

	// Soft-delete the vault, then stamp the secret with the EXACT same
	// deleted_at the vault ended up with -- exactly what DeleteVault's own
	// cascade does in production -- so RecoverVault's cascade query (which
	// matches on that timestamp) picks the secret back up too.
	require.NoError(t, vaultRepo.SoftDelete(ctx, vaultID))
	deletedAt := deletedAtColumn(t, sqlDB, "vaults", vaultID)
	require.NotNil(t, deletedAt, "vault must be soft-deleted before the recover test begins")
	require.NoError(t, secretRepo.SoftDeleteVaultContents(ctx, vaultID, *deletedAt))
	require.NotNil(t, deletedAtColumn(t, sqlDB, "secrets", secretID), "secret must be soft-deleted before the recover test begins")

	boom := errors.New("cert recover cascade boom")
	cascade := vaultServices.NewCascadeAdapter(secretRepo, &explodingContentRepo{err: boom})
	svc := vaultServices.NewVaultService(vaultRepo, cascade, log)
	svc.SetTxBeginner(conn)

	err := svc.RecoverVault(ctx, "prod", uuid.New())
	require.Error(t, err)
	require.ErrorIs(t, err, boom)

	require.NotNil(t, deletedAtColumn(t, sqlDB, "vaults", vaultID), "vault recovery must have rolled back, leaving it soft-deleted")
	require.NotNil(t, deletedAtColumn(t, sqlDB, "secrets", secretID), "secret recovery must have rolled back with it, leaving it soft-deleted")
}

func TestDeleteVault_CascadeSuccessCommitsEverything(t *testing.T) {
	sqlDB := newTxTestDB(t)
	conn := rvdb.NewConn(sqlDB, rvdb.SQLite)
	log := newTxTestLogger(t)
	ctx := context.Background()

	vaultRepo := repositories.NewVaultRepository(conn, log)
	secretRepo := repositories.NewSecretRepository(conn, log)

	vaultID := uuid.New()
	require.NoError(t, vaultRepo.Create(ctx, &model.Vault{
		ID: vaultID, Name: "prod", Enabled: true, RetentionDays: 90, CreatedBy: uuid.New(),
	}))
	secretID := uuid.New()
	require.NoError(t, secretRepo.Create(ctx, &model.Secret{
		ID: secretID, UserID: uuid.New(), VaultID: vaultID, Name: "s1", Value: "enc",
		Version: 1, CreatedAt: time.Now().UTC(), Enabled: true,
	}))

	cascade := vaultServices.NewCascadeAdapter(secretRepo)
	svc := vaultServices.NewVaultService(vaultRepo, cascade, log)
	svc.SetTxBeginner(conn)

	require.NoError(t, svc.DeleteVault(ctx, "prod", uuid.New()))

	require.NotNil(t, deletedAtColumn(t, sqlDB, "vaults", vaultID), "vault must be soft-deleted after commit")
	require.NotNil(t, deletedAtColumn(t, sqlDB, "secrets", secretID), "secret must be soft-deleted after commit")
}
