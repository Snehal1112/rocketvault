package repositories_test

import (
	"context"
	"database/sql"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/uuid"
	_ "github.com/mattn/go-sqlite3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	rvdb "rocketvault/internal/db"
	"rocketvault/internal/repositories"
)

func openAuditTestDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite3", ":memory:")
	require.NoError(t, err)
	t.Cleanup(func() { db.Close() }) //nolint:errcheck,gosec
	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS audit_logs (
		id      TEXT PRIMARY KEY,
		user_id TEXT,
		action  TEXT NOT NULL,
		details TEXT,
		timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
	)`)
	require.NoError(t, err)
	return db
}

func TestAuditRepository_PersistAudit(t *testing.T) {
	db := openAuditTestDB(t)
	repo := repositories.NewAuditRepository(rvdb.NewConn(db, rvdb.SQLite))

	err := repo.PersistAudit("user-1", "create_secret", "status=success message=done")
	require.NoError(t, err)

	var count int
	err = db.QueryRowContext(context.Background(),
		"SELECT COUNT(*) FROM audit_logs WHERE user_id = ? AND action = ?",
		"user-1", "create_secret",
	).Scan(&count)
	require.NoError(t, err)
	assert.Equal(t, 1, count)

	// Verify the stored field values, not just the count.
	var storedUserID, storedAction, storedDetails string
	err = db.QueryRowContext(context.Background(),
		"SELECT user_id, action, details FROM audit_logs WHERE user_id = ? AND action = ?",
		"user-1", "create_secret",
	).Scan(&storedUserID, &storedAction, &storedDetails)
	require.NoError(t, err)
	assert.Equal(t, "user-1", storedUserID)
	assert.Equal(t, "create_secret", storedAction)
	assert.Equal(t, "status=success message=done", storedDetails)
}

func TestAuditRepository_PersistAudit_EmptyUserID(t *testing.T) {
	db := openAuditTestDB(t)
	repo := repositories.NewAuditRepository(rvdb.NewConn(db, rvdb.SQLite))

	// Empty user_id is valid (unauthenticated events like auth failures).
	err := repo.PersistAudit("", "auth", "status=failed message=missing token")
	require.NoError(t, err)

	var count int
	err = db.QueryRowContext(context.Background(),
		"SELECT COUNT(*) FROM audit_logs WHERE user_id IS NULL OR user_id = ''",
	).Scan(&count)
	require.NoError(t, err)
	assert.Equal(t, 1, count)
}

func TestAuditRepository_PersistAudit_MultipleRecords(t *testing.T) {
	db := openAuditTestDB(t)
	repo := repositories.NewAuditRepository(rvdb.NewConn(db, rvdb.SQLite))

	for i := 0; i < 5; i++ {
		err := repo.PersistAudit("user-2", "get_key", "status=success")
		require.NoError(t, err)
	}

	var count int
	err := db.QueryRowContext(context.Background(),
		"SELECT COUNT(*) FROM audit_logs WHERE user_id = ?", "user-2",
	).Scan(&count)
	require.NoError(t, err)
	assert.Equal(t, 5, count)
}

// openAuditTestDBFull creates a file-backed DB with the full enriched audit_logs schema.
func openAuditTestDBFull(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite3", filepath.Join(t.TempDir(), "audit.db"))
	require.NoError(t, err)
	t.Cleanup(func() { db.Close() }) //nolint:errcheck,gosec
	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS audit_logs (
		id            TEXT PRIMARY KEY,
		user_id       TEXT,
		action        TEXT NOT NULL,
		details       TEXT,
		timestamp     TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		resource_type TEXT,
		resource_id   TEXT,
		ip_address    TEXT,
		outcome       TEXT,
		source        TEXT,
		prev_hash     TEXT,
		seq           BIGINT
	)`)
	require.NoError(t, err)
	_, err = db.Exec(`CREATE UNIQUE INDEX IF NOT EXISTS idx_audit_logs_seq ON audit_logs(seq)`)
	require.NoError(t, err)
	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS audit_chain_head (
		id INT PRIMARY KEY CHECK (id = 1), last_seq BIGINT NOT NULL, last_hash TEXT NOT NULL)`)
	require.NoError(t, err)
	_, err = db.Exec(`INSERT INTO audit_chain_head (id, last_seq, last_hash) VALUES (1, 0, '')`)
	require.NoError(t, err)
	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS audit_config (key TEXT PRIMARY KEY, value TEXT NOT NULL)`)
	require.NoError(t, err)
	return db
}

func TestAuditRepository_GetLastHash_EmptyTable(t *testing.T) {
	db := openAuditTestDBFull(t)
	repo := repositories.NewAuditRepository(rvdb.NewConn(db, rvdb.SQLite))
	hash, err := repo.GetLastHash(context.Background())
	require.NoError(t, err)
	assert.Equal(t, "", hash)
}

func TestAuditRepository_QueryAuditLogs_FilterByOutcome(t *testing.T) {
	db := openAuditTestDBFull(t)
	repo := repositories.NewAuditRepository(rvdb.NewConn(db, rvdb.SQLite))

	require.NoError(t, repo.InsertAuditLog(context.Background(), repositories.AuditLog{
		ID: uuid.New().String(), UserID: "u1", Action: "login",
		Outcome: "success", Source: "api", Timestamp: time.Now().UTC(),
	}))
	require.NoError(t, repo.InsertAuditLog(context.Background(), repositories.AuditLog{
		ID: uuid.New().String(), UserID: "u2", Action: "login",
		Outcome: "failure", Source: "api", Timestamp: time.Now().UTC(),
	}))

	outcome := "success"
	logs, total, err := repo.QueryAuditLogs(context.Background(), repositories.AuditFilter{Outcome: &outcome, Limit: 10})
	require.NoError(t, err)
	assert.Equal(t, int64(1), total)
	assert.Len(t, logs, 1)
	assert.Equal(t, "success", logs[0].Outcome)
}

func TestAuditRepository_DeleteBefore(t *testing.T) {
	db := openAuditTestDBFull(t)
	repo := repositories.NewAuditRepository(rvdb.NewConn(db, rvdb.SQLite))

	old := time.Now().UTC().Add(-48 * time.Hour)
	recent := time.Now().UTC()
	require.NoError(t, repo.InsertAuditLog(context.Background(), repositories.AuditLog{
		ID: uuid.New().String(), UserID: "u1", Action: "old_action",
		Timestamp: old,
	}))
	require.NoError(t, repo.InsertAuditLog(context.Background(), repositories.AuditLog{
		ID: uuid.New().String(), UserID: "u1", Action: "recent_action",
		Timestamp: recent,
	}))

	cutoff := time.Now().UTC().Add(-24 * time.Hour)
	deleted, err := repo.DeleteBefore(context.Background(), cutoff)
	require.NoError(t, err)
	assert.Equal(t, int64(1), deleted)
}

func TestAuditRepository_AuditConfig_RoundTrip(t *testing.T) {
	db := openAuditTestDBFull(t)
	repo := repositories.NewAuditRepository(rvdb.NewConn(db, rvdb.SQLite))

	// Key that doesn't exist returns "".
	val, err := repo.GetAuditConfig(context.Background(), "retention_days")
	require.NoError(t, err)
	assert.Equal(t, "", val)

	// Set then get.
	require.NoError(t, repo.SetAuditConfig(context.Background(), "retention_days", "90"))
	val, err = repo.GetAuditConfig(context.Background(), "retention_days")
	require.NoError(t, err)
	assert.Equal(t, "90", val)

	// Upsert (set same key again).
	require.NoError(t, repo.SetAuditConfig(context.Background(), "retention_days", "180"))
	val, err = repo.GetAuditConfig(context.Background(), "retention_days")
	require.NoError(t, err)
	assert.Equal(t, "180", val)
}

func TestAppendChained_AssignsContiguousSeq(t *testing.T) {
	db := openAuditTestDBFull(t)
	repo := repositories.NewAuditRepository(rvdb.NewConn(db, rvdb.SQLite))
	ctx := context.Background()

	prev := ""
	for i := int64(1); i <= 3; i++ {
		hash := fmt.Sprintf("hash-%d", i)
		err := repo.AppendChained(ctx, func(nextSeq int64, prevHash string, now time.Time) repositories.AuditLog {
			assert.Equal(t, i, nextSeq)
			assert.Equal(t, prev, prevHash)
			return repositories.AuditLog{ID: uuid.New().String(), UserID: "u", Action: "a", PrevHash: hash}
		})
		require.NoError(t, err)
		prev = hash
	}

	rows, err := db.Query(`SELECT seq FROM audit_logs ORDER BY seq`)
	require.NoError(t, err)
	defer rows.Close() //nolint:errcheck
	var got []int64
	for rows.Next() {
		var s int64
		require.NoError(t, rows.Scan(&s))
		got = append(got, s)
	}
	assert.Equal(t, []int64{1, 2, 3}, got)

	var lastSeq int64
	var lastHash string
	require.NoError(t, db.QueryRow(`SELECT last_seq, last_hash FROM audit_chain_head WHERE id = 1`).Scan(&lastSeq, &lastHash))
	assert.Equal(t, int64(3), lastSeq)
	assert.Equal(t, "hash-3", lastHash)
}

func TestAppendChained_BuildErrorRollsBack(t *testing.T) {
	db := openAuditTestDBFull(t)
	repo := repositories.NewAuditRepository(rvdb.NewConn(db, rvdb.SQLite))
	ctx := context.Background()

	_, err := db.Exec(`INSERT INTO audit_logs (id, action) VALUES ('dup', 'x')`)
	require.NoError(t, err)

	err = repo.AppendChained(ctx, func(int64, string, time.Time) repositories.AuditLog {
		return repositories.AuditLog{ID: "dup", Action: "a", PrevHash: "h"}
	})
	require.Error(t, err)

	var lastSeq int64
	var lastHash string
	require.NoError(t, db.QueryRow(`SELECT last_seq, last_hash FROM audit_chain_head WHERE id = 1`).Scan(&lastSeq, &lastHash))
	assert.Equal(t, int64(0), lastSeq)
	assert.Equal(t, "", lastHash)

	var seq int64
	err = repo.AppendChained(ctx, func(nextSeq int64, _ string, _ time.Time) repositories.AuditLog {
		seq = nextSeq
		return repositories.AuditLog{ID: uuid.New().String(), Action: "a", PrevHash: "h2"}
	})
	require.NoError(t, err)
	assert.Equal(t, int64(1), seq)
}

func TestAppendChained_TimestampMicrosecondPrecision(t *testing.T) {
	db := openAuditTestDBFull(t)
	repo := repositories.NewAuditRepository(rvdb.NewConn(db, rvdb.SQLite))

	var seen time.Time
	err := repo.AppendChained(context.Background(), func(_ int64, _ string, now time.Time) repositories.AuditLog {
		seen = now
		return repositories.AuditLog{ID: uuid.New().String(), Action: "a", PrevHash: "h"}
	})
	require.NoError(t, err)
	assert.Equal(t, 0, seen.Nanosecond()%1000)
	assert.Equal(t, time.UTC, seen.Location())
}

func TestQueryAuditLogs_OrdersChainedBeforeLegacy(t *testing.T) {
	db := openAuditTestDBFull(t)
	repo := repositories.NewAuditRepository(rvdb.NewConn(db, rvdb.SQLite))
	ctx := context.Background()

	require.NoError(t, repo.InsertAuditLog(ctx, repositories.AuditLog{
		ID: "legacy", Action: "a", Timestamp: time.Now().UTC().Add(time.Hour),
	}))
	for _, id := range []string{"c1", "c2"} {
		require.NoError(t, repo.AppendChained(ctx, func(int64, string, time.Time) repositories.AuditLog {
			return repositories.AuditLog{ID: id, Action: "a", PrevHash: "h" + id}
		}))
	}

	logs, _, err := repo.QueryAuditLogs(ctx, repositories.AuditFilter{})
	require.NoError(t, err)
	require.Len(t, logs, 3)
	assert.Equal(t, "c2", logs[0].ID)
	assert.Equal(t, "c1", logs[1].ID)
	assert.Equal(t, "legacy", logs[2].ID)
	require.NotNil(t, logs[0].Seq)
	assert.Equal(t, int64(2), *logs[0].Seq)
	assert.Nil(t, logs[2].Seq)
}
