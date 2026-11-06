// The audit hash chain needs a unique seq column and a single audit_chain_head
// row. These tests prove SetupSchema creates and seeds both, and that a rerun
// never resets the head.
package db

import (
	"context"
	"database/sql"
	"fmt"
	"path/filepath"
	"testing"

	_ "github.com/mattn/go-sqlite3"
	"github.com/stretchr/testify/require"

	"rocketvault/internal/logging"
)

func openAuditChainDB(t *testing.T) (*sql.DB, *DBRepository) {
	t.Helper()
	conn, err := sql.Open("sqlite3", filepath.Join(t.TempDir(), "audit.db"))
	require.NoError(t, err)
	conn.SetMaxOpenConns(1)
	t.Cleanup(func() { _ = conn.Close() })
	repo := NewRepository(&logging.Logger{Logger: newSilentLogrus()})
	return conn, repo
}

func readHead(t *testing.T, conn *sql.DB) (int64, string) {
	t.Helper()
	var n int
	require.NoError(t, conn.QueryRow(`SELECT COUNT(*) FROM audit_chain_head`).Scan(&n))
	require.Equal(t, 1, n, "exactly one head row")
	var seq int64
	var hash string
	require.NoError(t, conn.QueryRow(`SELECT last_seq, last_hash FROM audit_chain_head WHERE id = 1`).Scan(&seq, &hash))
	return seq, hash
}

func TestAuditChainMigration_EmptyTable_SeedsZeroHead(t *testing.T) {
	conn, repo := openAuditChainDB(t)
	require.NoError(t, repo.SetupSchema(conn, SQLite))
	seq, hash := readHead(t, conn)
	require.Equal(t, int64(0), seq)
	require.Equal(t, "", hash)
}

func TestAuditChainMigration_LegacyRows_SeedsFromNewest(t *testing.T) {
	conn, repo := openAuditChainDB(t)
	require.NoError(t, repo.SetupSchema(conn, SQLite))
	// Simulate an upgrade: legacy rows exist and no head row yet.
	_, err := conn.Exec(`DELETE FROM audit_chain_head`)
	require.NoError(t, err)
	_, err = conn.Exec(`INSERT INTO audit_logs (id, action, timestamp, prev_hash) VALUES
		('a1', 'x', '2026-01-01 00:00:00', 'h1'),
		('a2', 'x', '2026-01-02 00:00:00', 'h2')`)
	require.NoError(t, err)

	require.NoError(t, repo.SetupSchema(conn, SQLite))
	seq, hash := readHead(t, conn)
	require.Equal(t, int64(0), seq)
	require.Equal(t, "h2", hash)
}

func TestAuditChainMigration_RerunKeepsHead(t *testing.T) {
	conn, repo := openAuditChainDB(t)
	require.NoError(t, repo.SetupSchema(conn, SQLite))
	_, err := conn.Exec(`UPDATE audit_chain_head SET last_seq = 7, last_hash = 'x' WHERE id = 1`)
	require.NoError(t, err)

	require.NoError(t, repo.SetupSchema(conn, SQLite))
	seq, hash := readHead(t, conn)
	require.Equal(t, int64(7), seq)
	require.Equal(t, "x", hash)
}

func TestAuditChainMigration_SeqUnique(t *testing.T) {
	conn, repo := openAuditChainDB(t)
	require.NoError(t, repo.SetupSchema(conn, SQLite))

	_, err := conn.Exec(`INSERT INTO audit_logs (id, action, seq) VALUES ('s1', 'x', 1)`)
	require.NoError(t, err)
	_, err = conn.Exec(`INSERT INTO audit_logs (id, action, seq) VALUES ('s2', 'x', 1)`)
	require.Error(t, err)
	require.True(t, SQLite.IsConstraintErr(err), "duplicate seq is a constraint error")

	_, err = conn.Exec(`INSERT INTO audit_logs (id, action) VALUES ('n1', 'x')`)
	require.NoError(t, err)
	_, err = conn.Exec(`INSERT INTO audit_logs (id, action) VALUES ('n2', 'x')`)
	require.NoError(t, err, "NULL seq values do not collide")
}

// insertChainedRows inserts chained rows with seq 1..n and hash "h<seq>".
func insertChainedRows(t *testing.T, conn *sql.DB, n int) {
	t.Helper()
	for i := 1; i <= n; i++ {
		_, err := conn.Exec(
			`INSERT INTO audit_logs (id, action, timestamp, prev_hash, seq) VALUES (?, 'x', '2026-01-01 00:00:00', ?, ?)`,
			fmt.Sprintf("c%d", i), fmt.Sprintf("h%d", i), i,
		)
		require.NoError(t, err)
	}
}

func TestAuditChainMigration_ReconcileAdvancesLaggingHead(t *testing.T) {
	conn, repo := openAuditChainDB(t)
	require.NoError(t, repo.SetupSchema(conn, SQLite))
	insertChainedRows(t, conn, 5)
	_, err := conn.Exec(`UPDATE audit_chain_head SET last_seq = 3, last_hash = 'h3' WHERE id = 1`)
	require.NoError(t, err)

	require.NoError(t, repo.SetupSchema(conn, SQLite))
	seq, hash := readHead(t, conn)
	require.Equal(t, int64(5), seq)
	require.Equal(t, "h5", hash)
}

func TestAuditChainMigration_ReconcileNeverMovesBackwards(t *testing.T) {
	conn, repo := openAuditChainDB(t)
	require.NoError(t, repo.SetupSchema(conn, SQLite))
	insertChainedRows(t, conn, 5)
	_, err := conn.Exec(`UPDATE audit_chain_head SET last_seq = 9, last_hash = 'h9' WHERE id = 1`)
	require.NoError(t, err)

	require.NoError(t, repo.SetupSchema(conn, SQLite))
	seq, hash := readHead(t, conn)
	require.Equal(t, int64(9), seq)
	require.Equal(t, "h9", hash)
}

func TestAuditChainMigration_ReconcileNoOpOnHealthyHead(t *testing.T) {
	conn, repo := openAuditChainDB(t)
	require.NoError(t, repo.SetupSchema(conn, SQLite))
	insertChainedRows(t, conn, 5)
	_, err := conn.Exec(`UPDATE audit_chain_head SET last_seq = 5, last_hash = 'h5' WHERE id = 1`)
	require.NoError(t, err)

	require.NoError(t, repo.SetupSchema(conn, SQLite))
	require.NoError(t, repo.SetupSchema(conn, SQLite))
	seq, hash := readHead(t, conn)
	require.Equal(t, int64(5), seq)
	require.Equal(t, "h5", hash)
}

func TestAuditChainMigration_SeedUsesHighestSeq(t *testing.T) {
	conn, repo := openAuditChainDB(t)
	require.NoError(t, repo.SetupSchema(conn, SQLite))
	insertChainedRows(t, conn, 4)
	_, err := conn.Exec(`DELETE FROM audit_chain_head`)
	require.NoError(t, err)

	require.NoError(t, repo.SetupSchema(conn, SQLite))
	seq, hash := readHead(t, conn)
	require.Equal(t, int64(4), seq)
	require.Equal(t, "h4", hash)
}

func TestResetAuditChainHead_MovesBackToLegacyTip(t *testing.T) {
	conn, repo := openAuditChainDB(t)
	require.NoError(t, repo.SetupSchema(conn, SQLite))
	_, err := conn.Exec(`INSERT INTO audit_logs (id, action, timestamp, prev_hash) VALUES
		('a1', 'x', '2026-01-01 00:00:00', 'l1'),
		('a2', 'x', '2026-01-02 00:00:00', 'l2')`)
	require.NoError(t, err)
	_, err = conn.Exec(`UPDATE audit_chain_head SET last_seq = 40, last_hash = 'h40' WHERE id = 1`)
	require.NoError(t, err)

	require.NoError(t, ResetAuditChainHead(context.Background(), conn, SQLite))
	seq, hash := readHead(t, conn)
	require.Equal(t, int64(0), seq)
	require.Equal(t, "l2", hash)
}

func TestResetAuditChainHead_CreatesMissingRow(t *testing.T) {
	conn, repo := openAuditChainDB(t)
	require.NoError(t, repo.SetupSchema(conn, SQLite))
	insertChainedRows(t, conn, 2)
	_, err := conn.Exec(`DELETE FROM audit_chain_head`)
	require.NoError(t, err)

	require.NoError(t, ResetAuditChainHead(context.Background(), conn, SQLite))
	seq, hash := readHead(t, conn)
	require.Equal(t, int64(2), seq)
	require.Equal(t, "h2", hash)
}
