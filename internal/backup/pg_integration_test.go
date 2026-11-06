//go:build integration

// Package backup integration suite proves a full backup-then-restore
// round-trip succeeds against a live PostgreSQL database, which -- unlike
// this package's default SQLite-backed tests -- genuinely enforces foreign
// key constraints. Run with:
//
//	go test -tags=integration ./internal/backup/...
//
// It requires Docker. The default `go test ./...` run skips this file.
package backup

import (
	"context"
	"database/sql"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	_ "github.com/lib/pq"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	tcpostgres "github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"

	rvdb "rocketvault/internal/db"
	"rocketvault/internal/logging"
)

func newBackupPostgresDB(t *testing.T) (*sql.DB, rvdb.Dialect, func()) {
	t.Helper()
	ctx := context.Background()

	container, err := tcpostgres.Run(ctx,
		"postgres:16-alpine",
		tcpostgres.WithDatabase("rocketvault"),
		tcpostgres.WithUsername("rv"),
		tcpostgres.WithPassword("rv-secret"),
		tcpostgres.BasicWaitStrategies(),
		tcpostgres.WithSQLDriver("postgres"),
		testcontainers.WithAdditionalWaitStrategy(
			wait.ForLog("database system is ready to accept connections").
				WithOccurrence(2).
				WithStartupTimeout(60*time.Second),
		),
	)
	require.NoError(t, err, "start postgres container")

	dsn, err := container.ConnectionString(ctx, "sslmode=disable")
	require.NoError(t, err)

	sqlDB, err := sql.Open("postgres", dsn)
	require.NoError(t, err)

	require.Eventually(t, func() bool {
		return sqlDB.PingContext(ctx) == nil
	}, 60*time.Second, 500*time.Millisecond, "postgres did not become ready")

	repo := rvdb.NewRepository(logging.InitLogger())
	require.NoError(t, repo.SetupSchema(sqlDB, rvdb.Postgres), "setup schema on postgres")

	cleanup := func() {
		sqlDB.Close()
		_ = container.Terminate(ctx)
	}
	return sqlDB, rvdb.Postgres, cleanup
}

// TestPostgres_BackupRestore_RoundTrip proves CreateBackup + RestoreBackup
// succeed end-to-end against real Postgres FK enforcement. Before Task 2's
// fix, this would fail with a foreign key violation partway through the
// restore transaction (whichever child table's alphabetical position came
// before its parent's) -- this test is what Critical Finding #9 asked for:
// a Postgres-backed backup/restore test that didn't exist anywhere before
// this plan.
func TestPostgres_BackupRestore_RoundTrip(t *testing.T) {
	sqlDB, dialect, cleanup := newBackupPostgresDB(t)
	defer cleanup()

	userID := uuid.New()
	vaultID := uuid.MustParse("00000000-0000-0000-0000-00000000efa1") // model.DefaultVaultID
	secretID := uuid.New()
	keyID := uuid.New()

	// Seed data spanning multiple dependency levels: users (root),
	// secrets/keys (depend on users), secret_tags/key_tags (depend on
	// secrets/keys) -- exercising a real multi-level FK chain, not just a
	// single parent-child pair.
	_, err := sqlDB.Exec(`INSERT INTO users (id, username, password_hash, role) VALUES ($1, $2, $3, $4)`,
		userID.String(), "backup-test-user", "hash", "user")
	require.NoError(t, err)
	_, err = sqlDB.Exec(`INSERT INTO secrets (id, user_id, vault_id, name, value, version) VALUES ($1, $2, $3, $4, $5, $6)`,
		secretID.String(), userID.String(), vaultID.String(), "test-secret", "encrypted-value", 1)
	require.NoError(t, err)
	_, err = sqlDB.Exec(`INSERT INTO secret_tags (secret_id, tag) VALUES ($1, $2)`,
		secretID.String(), "env")
	require.NoError(t, err)
	_, err = sqlDB.Exec(`INSERT INTO keys (id, user_id, vault_id, name, value, type, created_at) VALUES ($1, $2, $3, $4, $5, $6, NOW())`,
		keyID.String(), userID.String(), vaultID.String(), "test-key", "encrypted-key-material", "RSA")
	require.NoError(t, err)

	mgr := NewManager(sqlDB, dialect, logging.InitLogger())

	backupPath := t.TempDir() + "/pg-roundtrip.backup"
	require.NoError(t, mgr.CreateBackup(backupPath, false))

	// Mutate the live DB before restoring, so the restore's effect is
	// actually observable (otherwise a no-op restore would also "pass").
	_, err = sqlDB.Exec(`DELETE FROM secret_tags WHERE secret_id = $1`, secretID.String())
	require.NoError(t, err)
	_, err = sqlDB.Exec(`UPDATE secrets SET name = $1 WHERE id = $2`, "mutated-name", secretID.String())
	require.NoError(t, err)

	// The real assertion: this must not return an FK-violation error.
	require.NoError(t, mgr.RestoreBackup(backupPath, false))

	var restoredName string
	require.NoError(t, sqlDB.QueryRow(`SELECT name FROM secrets WHERE id = $1`, secretID.String()).Scan(&restoredName))
	require.Equal(t, "test-secret", restoredName, "restore must have reverted the pre-restore mutation")

	var tagCount int
	require.NoError(t, sqlDB.QueryRow(`SELECT COUNT(*) FROM secret_tags WHERE secret_id = $1`, secretID.String()).Scan(&tagCount))
	require.Equal(t, 1, tagCount, "restore must have brought the deleted tag back")

	require.NoError(t, os.Remove(backupPath))
}

// TestPostgres_Restore_RecomputesAuditChainHead runs the chain head restore
// scenarios against Postgres. Each scenario starts from an empty trail.
func TestPostgres_Restore_RecomputesAuditChainHead(t *testing.T) {
	sqlDB, dialect, cleanup := newBackupPostgresDB(t)
	defer cleanup()

	scenarios := map[string]func(*testing.T, *auditChainFixture){
		"lagging_head":    scenarioRestoreLaggingHead,
		"pre_v412_legacy": scenarioRestorePreV412Legacy,
		"pre_v412_empty":  scenarioRestorePreV412Empty,
		"round_trip_head": scenarioRoundTripWithHead,
	}
	for name, run := range scenarios {
		t.Run(name, func(t *testing.T) {
			_, err := sqlDB.Exec(`DELETE FROM audit_logs`)
			require.NoError(t, err)
			_, err = sqlDB.Exec(`UPDATE audit_chain_head SET last_seq = 0, last_hash = '' WHERE id = 1`)
			require.NoError(t, err)
			run(t, newAuditChainFixture(sqlDB, dialect))
		})
	}

	// The startup reconcile advances a lagging head and never moves it back.
	t.Run("startup_reconcile", func(t *testing.T) {
		_, err := sqlDB.Exec(`DELETE FROM audit_logs`)
		require.NoError(t, err)
		_, err = sqlDB.Exec(`UPDATE audit_chain_head SET last_seq = 0, last_hash = '' WHERE id = 1`)
		require.NoError(t, err)
		f := newAuditChainFixture(sqlDB, dialect)
		f.record(t, 4)
		f.setHead(t, 2, f.hashOfSeq(t, 2))

		repo := rvdb.NewRepository(logging.InitLogger())
		require.NoError(t, repo.SetupSchema(sqlDB, rvdb.Postgres))
		seq, hash := f.head(t)
		require.Equal(t, int64(4), seq)
		require.Equal(t, f.hashOfSeq(t, 4), hash)

		f.setHead(t, 9, "ahead")
		require.NoError(t, repo.SetupSchema(sqlDB, rvdb.Postgres))
		seq, hash = f.head(t)
		require.Equal(t, int64(9), seq)
		require.Equal(t, "ahead", hash)
	})
}
