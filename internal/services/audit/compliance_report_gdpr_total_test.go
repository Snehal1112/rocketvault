package audit_test

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	rvdb "rocketvault/internal/db"
	"rocketvault/internal/repositories"
	auditSvc "rocketvault/internal/services/audit"
)

func TestComplianceReportService_GDPRReport_TotalExcludesAttemptsBeyondPage(t *testing.T) {
	db := openTestDB(t)
	repo := repositories.NewAuditRepository(rvdb.NewConn(db, rvdb.SQLite))
	now := time.Now().UTC()
	// 600 attempt rows are older than 1200 result rows, so the 1000-row page
	// holds results only and the attempt rows fall outside it.
	for i := 0; i < 1800; i++ {
		outcome, ts := "success", now
		if i < 600 {
			outcome, ts = "attempt", now.Add(-time.Hour)
		}
		require.NoError(t, repo.InsertAuditLog(context.Background(), repositories.AuditLog{
			ID: uuid.New().String(), UserID: "ub", Action: "get_secret", Outcome: outcome,
			Source: "system", ResourceType: "secret", Timestamp: ts,
		}))
	}
	svc := auditSvc.NewComplianceReportService(repo, nil)

	report, err := svc.GenerateGDPRReport(context.Background(),
		now.Add(-2*time.Hour), now.Add(time.Hour), "ub")
	require.NoError(t, err)
	assert.Equal(t, int64(1200), report.TotalEvents)
	assert.Len(t, report.Events, 1000)
}
