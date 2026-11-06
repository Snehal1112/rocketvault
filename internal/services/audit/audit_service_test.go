package audit_test

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"errors"
	"fmt"
	"path/filepath"
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

// createAuditSchema builds the chained audit schema and seeds the chain head.
func createAuditSchema(t *testing.T, db *sql.DB) {
	t.Helper()
	_, err := db.Exec(`CREATE TABLE audit_logs (
		id TEXT PRIMARY KEY, user_id TEXT, action TEXT NOT NULL,
		details TEXT, timestamp TIMESTAMP,
		resource_type TEXT, resource_id TEXT, ip_address TEXT,
		outcome TEXT, source TEXT, prev_hash TEXT, seq BIGINT
	)`)
	require.NoError(t, err)
	_, err = db.Exec(`CREATE UNIQUE INDEX idx_audit_logs_seq ON audit_logs(seq)`)
	require.NoError(t, err)
	_, err = db.Exec(`CREATE TABLE audit_chain_head (
		id INT PRIMARY KEY CHECK (id = 1), last_seq BIGINT NOT NULL, last_hash TEXT NOT NULL)`)
	require.NoError(t, err)
	_, err = db.Exec(`INSERT INTO audit_chain_head (id, last_seq, last_hash) VALUES (1, 0, '')`)
	require.NoError(t, err)
	_, err = db.Exec(`CREATE TABLE audit_config (key TEXT PRIMARY KEY, value TEXT NOT NULL)`)
	require.NoError(t, err)
}

// openTestDB creates a file-backed SQLite DB with the chained audit schema.
func openTestDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite3", filepath.Join(t.TempDir(), "audit.db"))
	require.NoError(t, err)
	// One connection serialises writers, so SQLite never reports a busy lock here.
	db.SetMaxOpenConns(1)
	t.Cleanup(func() { db.Close() }) //nolint:errcheck,gosec
	createAuditSchema(t, db)
	return db
}

// failingRepo is an audit repository whose chained append always fails.
type failingRepo struct {
	repositories.AuditRepositoryExtended
	err error
}

func (f *failingRepo) AppendChained(context.Context, func(int64, string, time.Time) repositories.AuditLog) error {
	return f.err
}

// countingRecorder counts write failures per action.
type countingRecorder struct {
	mu     sync.Mutex
	counts map[string]int
}

func (c *countingRecorder) Inc(action string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.counts == nil {
		c.counts = map[string]int{}
	}
	c.counts[action]++
}

func (c *countingRecorder) get(action string) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.counts[action]
}

// useRecorder installs rec for the test and restores the no-op default after.
func useRecorder(t *testing.T) *countingRecorder {
	t.Helper()
	rec := &countingRecorder{}
	auditSvc.SetWriteFailureRecorder(rec)
	t.Cleanup(func() { auditSvc.SetWriteFailureRecorder(nil) })
	return rec
}

func TestRecordCritical_ReturnsRepoError(t *testing.T) {
	rec := useRecorder(t)
	repoErr := errors.New("disk full")
	svc := auditSvc.NewAuditService(&failingRepo{err: repoErr})

	err := svc.RecordCritical(context.Background(), auditSvc.AuditEvent{Action: "grant_role"})
	require.ErrorIs(t, err, repoErr)
	assert.Equal(t, 1, rec.get("grant_role"))
}

func TestRecordEvent_SwallowsErrorAndCounts(t *testing.T) {
	rec := useRecorder(t)
	repoErr := errors.New("disk full")
	svc := auditSvc.NewAuditService(&failingRepo{err: repoErr})

	err := svc.RecordEvent(context.Background(), auditSvc.AuditEvent{Action: "login"})
	require.ErrorIs(t, err, repoErr)
	assert.Equal(t, 1, rec.get("login"))
	assert.Equal(t, 0, rec.get("other"))
}

func TestRecordEvent_ChainsHashWithSeq(t *testing.T) {
	db := openTestDB(t)
	repo := repositories.NewAuditRepository(rvdb.NewConn(db, rvdb.SQLite))
	svc := auditSvc.NewAuditService(repo)
	ctx := context.Background()

	ev1 := auditSvc.AuditEvent{UserID: "u1", Action: "login", Outcome: "success", Source: "api"}
	ev2 := auditSvc.AuditEvent{
		UserID: "u1", Action: "get_secret", Details: "d", ResourceType: "secret",
		ResourceID: "s1", Outcome: "success", Source: "api",
	}
	require.NoError(t, svc.RecordEvent(ctx, ev1))
	require.NoError(t, svc.RecordEvent(ctx, ev2))

	logs, _, err := repo.QueryAuditLogs(ctx, repositories.AuditFilter{Limit: 10})
	require.NoError(t, err)
	require.Len(t, logs, 2)
	row2, row1 := logs[0], logs[1]
	require.NotNil(t, row1.Seq)
	require.NotNil(t, row2.Seq)
	assert.Equal(t, int64(1), *row1.Seq)
	assert.Equal(t, int64(2), *row2.Seq)

	assert.Equal(t, auditSvc.ComputeChainHash("", 1, row1.Timestamp, ev1), row1.PrevHash)
	assert.Equal(t, auditSvc.ComputeChainHash(row1.PrevHash, 2, row2.Timestamp, ev2), row2.PrevHash)
}

func TestPersistAudit_SetsSourceAndOutcome(t *testing.T) {
	cases := []struct {
		status  string
		outcome string
	}{
		{"success", "success"},
		{"failure", "failure"},
		{"error", "failure"},
		{"failed", "failure"},
		{"denied", "warning"},
		{"info", "warning"},
	}
	for _, tc := range cases {
		t.Run(tc.status, func(t *testing.T) {
			db := openTestDB(t)
			repo := repositories.NewAuditRepository(rvdb.NewConn(db, rvdb.SQLite))
			svc := auditSvc.NewAuditService(repo)

			details := fmt.Sprintf("operation=login status=%s message=ok", tc.status)
			require.NoError(t, svc.PersistAudit("u", "login", details))

			logs, _, err := repo.QueryAuditLogs(context.Background(), repositories.AuditFilter{Limit: 10})
			require.NoError(t, err)
			require.Len(t, logs, 1)
			assert.Equal(t, "system", logs[0].Source)
			assert.Equal(t, tc.outcome, logs[0].Outcome)
			assert.Equal(t, details, logs[0].Details)
		})
	}
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

func TestAuditService_RecordEvent_ConcurrentSafety(t *testing.T) {
	db := openTestDB(t)
	repo := repositories.NewAuditRepository(rvdb.NewConn(db, rvdb.SQLite))
	svc := auditSvc.NewAuditService(repo)

	var wg sync.WaitGroup
	errs := make(chan error, 20)
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			errs <- svc.RecordEvent(context.Background(), auditSvc.AuditEvent{
				UserID: fmt.Sprintf("u%d", i), Action: "concurrent",
				Outcome: "success", Source: "api",
			})
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		require.NoError(t, err)
	}

	_, total, err := repo.QueryAuditLogs(context.Background(), repositories.AuditFilter{Limit: 100})
	require.NoError(t, err)
	assert.Equal(t, int64(20), total)
}

func TestAuditService_HashComputation(t *testing.T) {
	prevHash := "abc123"
	ts := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	userID, action, details, resourceType, resourceID, outcome := "u1", "login", "", "", "", "success"
	raw := fmt.Sprintf("%s|%d|%s|%s|%s|%s|%s|%s",
		prevHash, int64(7), ts.Format(time.RFC3339Nano),
		userID, action, details, resourceType+resourceID, outcome)
	expected := fmt.Sprintf("%x", sha256.Sum256([]byte(raw)))
	got := auditSvc.ComputeChainHash(prevHash, 7, ts, auditSvc.AuditEvent{
		UserID: userID, Action: action, Outcome: outcome,
	})
	assert.Equal(t, expected, got)
}
