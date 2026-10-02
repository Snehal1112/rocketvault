package audit_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	rvdb "rocketvault/internal/db"
	"rocketvault/internal/repositories"
	auditSvc "rocketvault/internal/services/audit"
)

func seedLogs(t *testing.T, repo repositories.AuditRepositoryExtended) {
	t.Helper()
	now := time.Now().UTC()
	entries := []repositories.AuditLog{
		{ID: uuid.New().String(), UserID: "u1", Action: "authenticate_user", Outcome: "success", Source: "api", ResourceType: "user", Timestamp: now},
		{ID: uuid.New().String(), UserID: "u1", Action: "authenticate_user", Outcome: "failure", Source: "api", ResourceType: "user", Timestamp: now},
		{ID: uuid.New().String(), UserID: "u2", Action: "get_secret", Outcome: "success", Source: "api", ResourceType: "secret", Timestamp: now},
		{ID: uuid.New().String(), UserID: "u1", Action: "create_key", Outcome: "success", Source: "api", ResourceType: "key", Timestamp: now},
		{ID: uuid.New().String(), UserID: "u3", Action: "delete_secret", Outcome: "success", Source: "cli", ResourceType: "secret", Timestamp: now},
	}
	for _, e := range entries {
		require.NoError(t, repo.InsertAuditLog(context.Background(), e))
	}
}

func TestComplianceReportService_SOC2Report(t *testing.T) {
	db := openTestDB(t)
	repo := repositories.NewAuditRepository(rvdb.NewConn(db, rvdb.SQLite))
	seedLogs(t, repo)
	svc := auditSvc.NewComplianceReportService(repo)

	from := time.Now().UTC().Add(-1 * time.Hour)
	to := time.Now().UTC().Add(1 * time.Hour)
	report, err := svc.GenerateSOC2Report(context.Background(), from, to)
	require.NoError(t, err)
	assert.Equal(t, int64(5), report.TotalEvents)
	assert.Equal(t, int64(3), report.UniqueUsers)
	assert.Equal(t, int64(1), report.AuthFailures)
	assert.Equal(t, int64(1), report.AuthSuccesses)
	assert.Equal(t, int64(1), report.KeyOperations)
}

// TestComplianceReportService_SOC2Report_CountsRealAuthenticateUserOutcomes
// exercises the real AuditService.RecordEvent write path (rather than
// seeding rows directly via InsertAuditLog) to document the correct end
// state: an authenticate_user event recorded with an explicit Outcome must
// be counted as success/failure in the SOC2 report, not silently miscounted
// as a failure because Outcome was left as the Go zero value.
func TestComplianceReportService_SOC2Report_CountsRealAuthenticateUserOutcomes(t *testing.T) {
	db := openTestDB(t)
	repo := repositories.NewAuditRepository(rvdb.NewConn(db, rvdb.SQLite))
	auditSvcInst := auditSvc.NewAuditService(repo)

	require.NoError(t, auditSvcInst.RecordEvent(context.Background(), auditSvc.AuditEvent{
		UserID: "u1", Action: "authenticate_user", Outcome: "success", Source: "system", ResourceType: "user",
	}))
	require.NoError(t, auditSvcInst.RecordEvent(context.Background(), auditSvc.AuditEvent{
		UserID: "u2", Action: "authenticate_user", Outcome: "failure", Source: "system", ResourceType: "user",
	}))

	reportSvc := auditSvc.NewComplianceReportService(repo)
	from := time.Now().UTC().Add(-time.Hour)
	to := time.Now().UTC().Add(time.Hour)
	report, err := reportSvc.GenerateSOC2Report(context.Background(), from, to)
	require.NoError(t, err)

	assert.Equal(t, int64(1), report.AuthSuccesses)
	assert.Equal(t, int64(1), report.AuthFailures)
}

func TestComplianceReportService_GDPRReport(t *testing.T) {
	db := openTestDB(t)
	repo := repositories.NewAuditRepository(rvdb.NewConn(db, rvdb.SQLite))
	seedLogs(t, repo)
	svc := auditSvc.NewComplianceReportService(repo)

	from := time.Now().UTC().Add(-1 * time.Hour)
	to := time.Now().UTC().Add(1 * time.Hour)
	report, err := svc.GenerateGDPRReport(context.Background(), from, to, "u1")
	require.NoError(t, err)
	assert.Equal(t, "u1", report.SubjectID)
	assert.Equal(t, int64(3), report.TotalEvents) // u1 has 3 events.
}

func TestComplianceReportService_SOC2CSV(t *testing.T) {
	db := openTestDB(t)
	repo := repositories.NewAuditRepository(rvdb.NewConn(db, rvdb.SQLite))
	seedLogs(t, repo)
	svc := auditSvc.NewComplianceReportService(repo)

	from := time.Now().UTC().Add(-1 * time.Hour)
	to := time.Now().UTC().Add(1 * time.Hour)
	csv, err := svc.GenerateSOC2CSV(context.Background(), from, to)
	require.NoError(t, err)
	assert.True(t, strings.Contains(csv, "total_events"))
	assert.True(t, strings.Contains(csv, "5"))
}

func TestComplianceReportService_QueryLogs_IntegrityCheck(t *testing.T) {
	db := openTestDB(t)
	repo := repositories.NewAuditRepository(rvdb.NewConn(db, rvdb.SQLite))
	svc := auditSvc.NewAuditService(repo)
	compSvc := auditSvc.NewComplianceReportService(repo)

	// Record two events through AuditService to build a valid chain.
	require.NoError(t, svc.RecordEvent(context.Background(), auditSvc.AuditEvent{
		UserID: "u1", Action: "login", Outcome: "success", Source: "api",
	}))
	require.NoError(t, svc.RecordEvent(context.Background(), auditSvc.AuditEvent{
		UserID: "u1", Action: "get_secret", Outcome: "success", Source: "api",
	}))

	from := time.Now().UTC().Add(-1 * time.Hour)
	to := time.Now().UTC().Add(1 * time.Hour)
	_, _, integrityOK, err := compSvc.QueryLogs(context.Background(), repositories.AuditFilter{From: &from, To: &to, Limit: 10})
	require.NoError(t, err)
	assert.True(t, integrityOK, "hash chain should be valid for events recorded by AuditService")
}

func TestComplianceReportService_PurgeExpiredLogs(t *testing.T) {
	db := openTestDB(t)
	repo := repositories.NewAuditRepository(rvdb.NewConn(db, rvdb.SQLite))
	require.NoError(t, repo.SetAuditConfig(context.Background(), "retention_days", "90"))

	// Insert one old and one recent log.
	old := time.Now().UTC().AddDate(0, 0, -92)
	recent := time.Now().UTC()
	require.NoError(t, repo.InsertAuditLog(context.Background(), repositories.AuditLog{ID: uuid.New().String(), Action: "old", Timestamp: old}))
	require.NoError(t, repo.InsertAuditLog(context.Background(), repositories.AuditLog{ID: uuid.New().String(), Action: "recent", Timestamp: recent}))

	svc := auditSvc.NewComplianceReportService(repo)
	deleted, err := svc.PurgeExpiredLogs(context.Background())
	require.NoError(t, err)
	assert.Equal(t, int64(1), deleted)
}

// TestComplianceReportService_StoredRetentionBelowFloorIsClamped pins that a
// value of 1 saved before the floor existed cannot purge recent rows (B81).
func TestComplianceReportService_StoredRetentionBelowFloorIsClamped(t *testing.T) {
	db := openTestDB(t)
	repo := repositories.NewAuditRepository(rvdb.NewConn(db, rvdb.SQLite))
	require.NoError(t, repo.SetAuditConfig(context.Background(), "retention_days", "1"))

	twoDaysOld := time.Now().UTC().Add(-48 * time.Hour)
	require.NoError(t, repo.InsertAuditLog(context.Background(), repositories.AuditLog{ID: uuid.New().String(), Action: "recent-ish", Timestamp: twoDaysOld}))

	svc := auditSvc.NewComplianceReportService(repo)
	days, err := svc.GetRetentionDays(context.Background())
	require.NoError(t, err)
	assert.Equal(t, auditSvc.MinRetentionDays, days)

	deleted, err := svc.PurgeExpiredLogs(context.Background())
	require.NoError(t, err)
	assert.Equal(t, int64(0), deleted)
}

// TestComplianceReportService_SetRetentionBelowFloorIsRefused pins the floor
// on the write path shared by HTTP and the CLI.
func TestComplianceReportService_SetRetentionBelowFloorIsRefused(t *testing.T) {
	db := openTestDB(t)
	repo := repositories.NewAuditRepository(rvdb.NewConn(db, rvdb.SQLite))
	svc := auditSvc.NewComplianceReportService(repo)

	err := svc.SetRetentionDays(context.Background(), 89)
	require.ErrorIs(t, err, auditSvc.ErrRetentionBelowFloor)
	require.NoError(t, svc.SetRetentionDays(context.Background(), 90))
}
