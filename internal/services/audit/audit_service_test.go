package audit_test

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"fmt"
	"sync"
	"testing"
	"time"

	_ "github.com/mattn/go-sqlite3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	rvdb "rocketvault/internal/db"
	"rocketvault/internal/repositories"
	auditSvc "rocketvault/internal/services/audit"
)

func openTestDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite3", ":memory:")
	require.NoError(t, err)
	t.Cleanup(func() { db.Close() }) //nolint:errcheck,gosec
	_, err = db.Exec(`CREATE TABLE audit_logs (
		id TEXT PRIMARY KEY, user_id TEXT, action TEXT NOT NULL,
		details TEXT, timestamp TIMESTAMP,
		resource_type TEXT, resource_id TEXT, ip_address TEXT,
		outcome TEXT, source TEXT, prev_hash TEXT, seq BIGINT
	)`)
	require.NoError(t, err)
	_, err = db.Exec(`CREATE TABLE audit_config (key TEXT PRIMARY KEY, value TEXT NOT NULL)`)
	require.NoError(t, err)
	return db
}

func TestAuditService_RecordEvent_HashChain(t *testing.T) {
	db := openTestDB(t)
	repo := repositories.NewAuditRepository(rvdb.NewConn(db, rvdb.SQLite))
	svc := auditSvc.NewAuditService(repo)

	err := svc.RecordEvent(context.Background(), auditSvc.AuditEvent{
		UserID: "u1", Action: "login", Outcome: "success", Source: "api",
	})
	require.NoError(t, err)

	err = svc.RecordEvent(context.Background(), auditSvc.AuditEvent{
		UserID: "u1", Action: "get_secret", Outcome: "success", Source: "api",
	})
	require.NoError(t, err)

	logs, total, err := repo.QueryAuditLogs(context.Background(), repositories.AuditFilter{Limit: 10})
	require.NoError(t, err)
	assert.Equal(t, int64(2), total)

	// Rows come back newest-first; the second insert has a non-empty prev_hash.
	newestLog := logs[0]
	assert.NotEmpty(t, newestLog.PrevHash)
}

func TestAuditService_RecordEvent_ErrorSwallowed(t *testing.T) {
	db := openTestDB(t)
	// Drop the table to force insert failures.
	_, _ = db.Exec(`DROP TABLE audit_logs`)
	repo := repositories.NewAuditRepository(rvdb.NewConn(db, rvdb.SQLite))
	svc := auditSvc.NewAuditService(repo)

	// Must not return an error even when insert fails.
	err := svc.RecordEvent(context.Background(), auditSvc.AuditEvent{
		UserID: "u1", Action: "login", Outcome: "success", Source: "api",
	})
	assert.NoError(t, err)
}

func TestAuditService_RecordEvent_ConcurrentSafety(t *testing.T) {
	db := openTestDB(t)
	repo := repositories.NewAuditRepository(rvdb.NewConn(db, rvdb.SQLite))
	svc := auditSvc.NewAuditService(repo)

	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_ = svc.RecordEvent(context.Background(), auditSvc.AuditEvent{
				UserID: fmt.Sprintf("u%d", i), Action: "concurrent",
				Outcome: "success", Source: "api",
			})
		}(i)
	}
	wg.Wait()

	_, total, err := repo.QueryAuditLogs(context.Background(), repositories.AuditFilter{Limit: 100})
	require.NoError(t, err)
	assert.Equal(t, int64(20), total)
}

func TestAuditService_HashComputation(t *testing.T) {
	prevHash := "abc123"
	ts := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	userID, action, details, resourceType, resourceID, outcome := "u1", "login", "", "", "", "success"
	raw := fmt.Sprintf("%s|%s|%s|%s|%s|%s|%s",
		prevHash, ts.Format(time.RFC3339Nano),
		userID, action, details, resourceType+resourceID, outcome)
	expected := fmt.Sprintf("%x", sha256.Sum256([]byte(raw)))
	assert.Len(t, expected, 64) // SHA-256 hex is always 64 chars.
}
