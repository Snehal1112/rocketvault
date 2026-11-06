// A restore replaces audit_logs, so it must also recompute audit_chain_head.
// Otherwise the next chained write reuses an existing seq (head behind the
// rows) or chains onto rows that are gone (head ahead of the rows). These
// scenarios run on SQLite here and on Postgres in pg_integration_test.go.
package backup

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	rvdb "rocketvault/internal/db"
	"rocketvault/internal/logging"
	"rocketvault/internal/repositories"
	auditSvc "rocketvault/internal/services/audit"
)

// auditChainFixture bundles a full-schema database and the audit services.
type auditChainFixture struct {
	db      *sql.DB
	dialect rvdb.Dialect
	mgr     *Manager
	audit   auditSvc.AuditServiceInterface
	reports auditSvc.ComplianceReportServiceInterface
}

func newAuditChainFixture(sqlDB *sql.DB, dialect rvdb.Dialect) *auditChainFixture {
	repo := repositories.NewAuditRepository(rvdb.NewConn(sqlDB, dialect))
	return &auditChainFixture{
		db:      sqlDB,
		dialect: dialect,
		mgr:     NewManager(sqlDB, dialect, logging.InitLogger()),
		audit:   auditSvc.NewAuditService(repo),
		reports: auditSvc.NewComplianceReportService(repo, nil),
	}
}

// newSQLiteAuditChainFixture opens a file-backed SQLite database with the full schema.
func newSQLiteAuditChainFixture(t *testing.T) *auditChainFixture {
	t.Helper()
	sqlDB, err := sql.Open("sqlite3", filepath.Join(t.TempDir(), "chain.db"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = sqlDB.Close() })
	require.NoError(t, rvdb.NewRepository(logging.InitLogger()).SetupSchema(sqlDB, rvdb.SQLite))
	return newAuditChainFixture(sqlDB, rvdb.SQLite)
}

func (f *auditChainFixture) record(t *testing.T, n int) {
	t.Helper()
	for i := 0; i < n; i++ {
		require.NoError(t, f.audit.RecordCritical(context.Background(), auditSvc.AuditEvent{
			UserID: "u1", Action: fmt.Sprintf("act_%d", i), Details: "d", Outcome: "success", Source: "api",
		}))
	}
}

func (f *auditChainFixture) head(t *testing.T) (int64, string) {
	t.Helper()
	var seq int64
	var hash string
	require.NoError(t, f.db.QueryRow(`SELECT last_seq, last_hash FROM audit_chain_head WHERE id = 1`).Scan(&seq, &hash))
	return seq, hash
}

func (f *auditChainFixture) hashOfSeq(t *testing.T, seq int64) string {
	t.Helper()
	var hash string
	require.NoError(t, f.db.QueryRow(f.dialect.Rebind(`SELECT prev_hash FROM audit_logs WHERE seq = ?`), seq).Scan(&hash))
	return hash
}

func (f *auditChainFixture) setHead(t *testing.T, seq int64, hash string) {
	t.Helper()
	_, err := f.db.Exec(f.dialect.Rebind(`UPDATE audit_chain_head SET last_seq = ?, last_hash = ? WHERE id = 1`), seq, hash)
	require.NoError(t, err)
}

func (f *auditChainFixture) maxSeq(t *testing.T) int64 {
	t.Helper()
	var seq sql.NullInt64
	require.NoError(t, f.db.QueryRow(`SELECT MAX(seq) FROM audit_logs`).Scan(&seq))
	return seq.Int64
}

// requireIntegrityOK asserts that an unfiltered audit query verifies.
func (f *auditChainFixture) requireIntegrityOK(t *testing.T) {
	t.Helper()
	_, _, integrity, err := f.reports.QueryLogs(context.Background(), repositories.AuditFilter{Limit: 100})
	require.NoError(t, err)
	require.True(t, integrity.OK, "chain must verify, got break %q", integrity.BreakReason)
}

// rewriteAsPreV412 removes audit_chain_head and the seq column from a plain
// backup file, the shape a pre-v4.12 build wrote.
func rewriteAsPreV412(t *testing.T, path string) {
	t.Helper()
	raw, err := os.ReadFile(path)
	require.NoError(t, err)
	var data BackupData
	require.NoError(t, json.Unmarshal(raw, &data))
	kept := data.Tables[:0]
	for _, tbl := range data.Tables {
		if tbl.Name == "audit_chain_head" {
			continue
		}
		if tbl.Name == "audit_logs" {
			cols := tbl.Columns[:0]
			for _, c := range tbl.Columns {
				if c != "seq" {
					cols = append(cols, c)
				}
			}
			tbl.Columns = cols
			for _, row := range tbl.Rows {
				delete(row, "seq")
			}
		}
		kept = append(kept, tbl)
	}
	data.Tables = kept
	data.Metadata.TableCount = len(kept)
	out, err := json.Marshal(data)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(path, out, 0600))
}

// scenarioRestoreLaggingHead restores a backup whose head lags its rows.
func scenarioRestoreLaggingHead(t *testing.T, f *auditChainFixture) {
	f.record(t, 5)
	f.setHead(t, 3, f.hashOfSeq(t, 3))
	path := filepath.Join(t.TempDir(), "lag.backup")
	require.NoError(t, f.mgr.CreateBackup(path, false))

	// Writes after the backup move the live head past the backup.
	f.setHead(t, 5, f.hashOfSeq(t, 5))
	f.record(t, 2)

	require.NoError(t, f.mgr.RestoreBackup(path, false))
	seq, hash := f.head(t)
	require.Equal(t, int64(5), seq)
	require.Equal(t, f.hashOfSeq(t, 5), hash)

	f.record(t, 1)
	require.Equal(t, int64(6), f.maxSeq(t))
	f.requireIntegrityOK(t)
}

// scenarioRestorePreV412Legacy restores a pre-v4.12 backup with one legacy row
// over a database whose head is at seq 40.
func scenarioRestorePreV412Legacy(t *testing.T, f *auditChainFixture) {
	_, err := f.db.Exec(f.dialect.Rebind(
		`INSERT INTO audit_logs (id, user_id, action, details, timestamp, outcome, prev_hash) VALUES (?, ?, ?, ?, ?, ?, ?)`),
		"legacy-1", "u1", "legacy", "d", "2026-01-01 00:00:00", "success", "legacy-tip")
	require.NoError(t, err)
	path := filepath.Join(t.TempDir(), "pre412.backup")
	require.NoError(t, f.mgr.CreateBackup(path, false))
	rewriteAsPreV412(t, path)

	_, err = f.db.Exec(f.dialect.Rebind(`DELETE FROM audit_logs WHERE id = ?`), "legacy-1")
	require.NoError(t, err)
	f.record(t, 40)
	seq, _ := f.head(t)
	require.Equal(t, int64(40), seq)

	require.NoError(t, f.mgr.RestoreBackup(path, false))
	seq, hash := f.head(t)
	require.Equal(t, int64(0), seq)
	require.Equal(t, "legacy-tip", hash)

	f.record(t, 1)
	require.Equal(t, int64(1), f.maxSeq(t))
	f.requireIntegrityOK(t)
}

// scenarioRestorePreV412Empty restores a pre-v4.12 backup with no audit rows.
func scenarioRestorePreV412Empty(t *testing.T, f *auditChainFixture) {
	path := filepath.Join(t.TempDir(), "empty.backup")
	require.NoError(t, f.mgr.CreateBackup(path, false))
	rewriteAsPreV412(t, path)
	f.record(t, 40)

	require.NoError(t, f.mgr.RestoreBackup(path, false))
	seq, hash := f.head(t)
	require.Equal(t, int64(0), seq)
	require.Equal(t, "", hash)

	f.record(t, 2)
	require.Equal(t, int64(2), f.maxSeq(t))
	f.requireIntegrityOK(t)
}

// scenarioRoundTripWithHead backs up a healthy chain and restores it.
func scenarioRoundTripWithHead(t *testing.T, f *auditChainFixture) {
	f.record(t, 3)
	path := filepath.Join(t.TempDir(), "rt.backup")
	require.NoError(t, f.mgr.CreateBackup(path, false))

	raw, err := os.ReadFile(path)
	require.NoError(t, err)
	var data BackupData
	require.NoError(t, json.Unmarshal(raw, &data))
	found := false
	for _, tbl := range data.Tables {
		if tbl.Name == "audit_chain_head" {
			found = true
			require.Equal(t, 1, tbl.RowCount)
		}
	}
	require.True(t, found, "backup must contain audit_chain_head")

	f.record(t, 4)
	require.NoError(t, f.mgr.RestoreBackup(path, false))
	seq, hash := f.head(t)
	require.Equal(t, int64(3), seq)
	require.Equal(t, f.hashOfSeq(t, 3), hash)

	f.record(t, 1)
	require.Equal(t, int64(4), f.maxSeq(t))
	f.requireIntegrityOK(t)
}

func TestRestore_LaggingHead_RecomputesHead(t *testing.T) {
	scenarioRestoreLaggingHead(t, newSQLiteAuditChainFixture(t))
}

func TestRestore_PreV412LegacyBackup_ResetsHead(t *testing.T) {
	scenarioRestorePreV412Legacy(t, newSQLiteAuditChainFixture(t))
}

func TestRestore_PreV412EmptyBackup_ResetsHead(t *testing.T) {
	scenarioRestorePreV412Empty(t, newSQLiteAuditChainFixture(t))
}

func TestRestore_RoundTripWithChainHead(t *testing.T) {
	scenarioRoundTripWithHead(t, newSQLiteAuditChainFixture(t))
}
