package audit_test

import (
	"context"
	"database/sql"
	"fmt"
	"path/filepath"
	"strconv"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"

	rvdb "rocketvault/internal/db"
	"rocketvault/internal/repositories"
	auditSvc "rocketvault/internal/services/audit"
)

// openPoolDB opens a multi-connection SQLite pool on path, like production does.
func openPoolDB(t *testing.T, path string) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite3", path)
	require.NoError(t, err)
	db.SetMaxOpenConns(10)
	t.Cleanup(func() { db.Close() }) //nolint:errcheck,gosec
	return db
}

// runWriters runs perSvc concurrent RecordEvent calls per service and returns every error.
func runWriters(svcs []auditSvc.AuditServiceInterface, perSvc int) []error {
	var wg sync.WaitGroup
	errs := make(chan error, len(svcs)*perSvc)
	for si, svc := range svcs {
		for i := 0; i < perSvc; i++ {
			wg.Add(1)
			go func(svc auditSvc.AuditServiceInterface, si, i int) {
				defer wg.Done()
				errs <- svc.RecordEvent(context.Background(), auditSvc.AuditEvent{
					UserID: fmt.Sprintf("s%d-u%d", si, i), Action: "concurrent",
					Details: fmt.Sprintf("n%d-%d", si, i), Outcome: "success", Source: "api",
				})
			}(svc, si, i)
		}
	}
	wg.Wait()
	close(errs)
	var out []error
	for err := range errs {
		out = append(out, err)
	}
	return out
}

// assertChainIntact checks seq 1..want, the stored hash linkage and the verifier.
func assertChainIntact(t *testing.T, repo repositories.AuditRepositoryExtended, want int) {
	t.Helper()
	comp := auditSvc.NewComplianceReportService(repo, nil)
	logs, total, res, err := comp.QueryLogs(context.Background(), repositories.AuditFilter{Limit: 1000})
	require.NoError(t, err)
	require.Equal(t, int64(want), total)
	require.Len(t, logs, want)
	if !res.OK {
		breakSeq := "none"
		if res.BreakSeq != nil {
			breakSeq = strconv.FormatInt(*res.BreakSeq, 10)
		}
		t.Errorf("chain break at seq %s: %s", breakSeq, res.BreakReason)
	}

	// Rows come back newest-first, so walk them from the oldest.
	prev := ""
	for i := range logs {
		l := logs[len(logs)-1-i]
		require.NotNil(t, l.Seq)
		require.Equal(t, int64(i+1), *l.Seq)
		ev := auditSvc.AuditEvent{
			UserID: l.UserID, Action: l.Action, Details: l.Details,
			ResourceType: l.ResourceType, ResourceID: l.ResourceID, Outcome: l.Outcome,
		}
		require.Equal(t, auditSvc.ComputeChainHash(prev, *l.Seq, l.Timestamp, ev), l.PrevHash,
			"hash linkage broken at seq %d", *l.Seq)
		prev = l.PrevHash
	}
}

func TestAuditChain_ConcurrentWriters(t *testing.T) {
	db := openPoolDB(t, filepath.Join(t.TempDir(), "audit.db"))
	createAuditSchema(t, db)
	repo := repositories.NewAuditRepository(rvdb.NewConn(db, rvdb.SQLite))
	svc := auditSvc.NewAuditService(repo)

	for _, err := range runWriters([]auditSvc.AuditServiceInterface{svc}, 20) {
		require.NoError(t, err)
	}
	assertChainIntact(t, repo, 20)
}

func TestAuditChain_TwoServicesOneDB(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.db")
	dbA := openPoolDB(t, path)
	createAuditSchema(t, dbA)
	dbB := openPoolDB(t, path)
	repoA := repositories.NewAuditRepository(rvdb.NewConn(dbA, rvdb.SQLite))
	repoB := repositories.NewAuditRepository(rvdb.NewConn(dbB, rvdb.SQLite))
	svcs := []auditSvc.AuditServiceInterface{auditSvc.NewAuditService(repoA), auditSvc.NewAuditService(repoB)}

	for _, err := range runWriters(svcs, 10) {
		require.NoError(t, err)
	}
	// Either repo sees the same single chain.
	assertChainIntact(t, repoA, 20)
	assertChainIntact(t, repoB, 20)
}
