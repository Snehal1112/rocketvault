// The audit hash chain needs a unique seq column and a single audit_chain_head
// row. These tests prove SetupSchema creates and seeds both, and that a rerun
// never resets the head.
package db

import (
	"database/sql"
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
