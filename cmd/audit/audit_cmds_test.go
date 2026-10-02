package audit

// Tests that exercise the actual logsCmd, reportCmd, and configCmd RunE closures.
// The existing audit_test.go tests use inline cobra commands (not the package-level
// command vars), so those RunE bodies have zero statement coverage. These tests fix it.

import (
	"bytes"
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	"rocketvault/cmd/testutils"
	"rocketvault/common"
	"rocketvault/internal/formatter"
	"rocketvault/internal/repositories"
	auditServices "rocketvault/internal/services/audit"
	"rocketvault/model"
)

// --------------------------------------------------------------------------
// helpers
// --------------------------------------------------------------------------

// buildAuditCtx returns a context that carries the mock service container and
// a table formatter so the formatter assertion inside logsCmd passes.
func buildAuditCtx(tc *testutils.TestContext) context.Context {
	fmtr, _ := formatter.New(formatter.FormatTable)
	ctx := context.WithValue(tc.Ctx, common.OutputFormatterKey, fmtr)
	return ctx
}

// newLogsCmd returns a fresh cobra.Command wired to the real logsCmd.RunE and
// the same flags that init() registered on the package-level logsCmd.
func newLogsCmd() (*cobra.Command, *bytes.Buffer) {
	cmd := &cobra.Command{Use: "logs", Args: cobra.NoArgs, RunE: logsCmd.RunE}
	cmd.Flags().String("from", "", "")
	cmd.Flags().String("to", "", "")
	cmd.Flags().String("user-id", "", "")
	cmd.Flags().String("action", "", "")
	cmd.Flags().String("outcome", "", "")
	cmd.Flags().String("resource-type", "", "")
	cmd.Flags().Int("limit", 100, "")
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	return cmd, &buf
}

// newReportCmd returns a fresh cobra.Command wired to reportCmd.RunE.
func newReportCmd() (*cobra.Command, *bytes.Buffer) {
	cmd := &cobra.Command{Use: "report", Args: cobra.NoArgs, RunE: reportCmd.RunE}
	cmd.Flags().String("type", "", "")
	cmd.Flags().String("from", "", "")
	cmd.Flags().String("to", "", "")
	cmd.Flags().String("subject-id", "", "")
	cmd.Flags().String("format", "json", "")
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	return cmd, &buf
}

// newConfigCmd returns a fresh cobra.Command wired to configCmd.RunE.
func newConfigCmd() (*cobra.Command, *bytes.Buffer) {
	cmd := &cobra.Command{Use: "config", Args: cobra.NoArgs, RunE: configCmd.RunE}
	cmd.Flags().Int("retention-days", 0, "")
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	return cmd, &buf
}

// --------------------------------------------------------------------------
// logsCmd.RunE tests
// --------------------------------------------------------------------------

func TestLogsCmd_NoServiceContainer(t *testing.T) {
	cmd, _ := newLogsCmd()
	cmd.SetContext(context.Background())
	err := cmd.Execute()
	assert.ErrorContains(t, err, "service container not available")
}

func TestLogsCmd_QueryLogsError(t *testing.T) {
	tc := testutils.NewTestContext(t)
	mockSvc := &MockComplianceReportService{}
	mockSvc.On("QueryLogs", mock.Anything, mock.Anything).
		Return(nil, int64(0), true, fmt.Errorf("db error"))
	tc.MockContainer.On("GetComplianceReportService").Return(mockSvc)

	cmd, _ := newLogsCmd()
	cmd.SetContext(buildAuditCtx(tc))
	err := cmd.Execute()
	assert.ErrorContains(t, err, "failed to query audit logs")
}

func TestLogsCmd_Success_EmptyResult(t *testing.T) {
	tc := testutils.NewTestContext(t)
	mockSvc := &MockComplianceReportService{}
	mockSvc.On("QueryLogs", mock.Anything, mock.MatchedBy(func(f repositories.AuditFilter) bool {
		return f.Limit == 100
	})).Return([]repositories.AuditLog{}, int64(0), true, nil)
	tc.MockContainer.On("GetComplianceReportService").Return(mockSvc)

	cmd, buf := newLogsCmd()
	cmd.SetContext(buildAuditCtx(tc))
	err := cmd.Execute()
	assert.NoError(t, err)
	assert.Contains(t, buf.String(), "Total matching: 0")
	mockSvc.AssertExpectations(t)
}

func TestLogsCmd_Success_WithLogs(t *testing.T) {
	tc := testutils.NewTestContext(t)
	mockSvc := &MockComplianceReportService{}
	logs := []repositories.AuditLog{
		{ID: "1", Timestamp: time.Now(), UserID: "u1", Action: "login", Outcome: "success"},
	}
	mockSvc.On("QueryLogs", mock.Anything, mock.Anything).
		Return(logs, int64(1), true, nil)
	tc.MockContainer.On("GetComplianceReportService").Return(mockSvc)

	cmd, buf := newLogsCmd()
	cmd.SetContext(buildAuditCtx(tc))
	err := cmd.Execute()
	assert.NoError(t, err)
	assert.Contains(t, buf.String(), "Total matching: 1")
	mockSvc.AssertExpectations(t)
}

func TestLogsCmd_IntegrityWarning(t *testing.T) {
	tc := testutils.NewTestContext(t)
	mockSvc := &MockComplianceReportService{}
	mockSvc.On("QueryLogs", mock.Anything, mock.Anything).
		Return([]repositories.AuditLog{}, int64(0), false /* integrityOK=false */, nil)
	tc.MockContainer.On("GetComplianceReportService").Return(mockSvc)

	cmd, buf := newLogsCmd()
	cmd.SetContext(buildAuditCtx(tc))
	err := cmd.Execute()
	assert.NoError(t, err)
	assert.Contains(t, buf.String(), "WARNING")
	mockSvc.AssertExpectations(t)
}

func TestLogsCmd_WithFilters(t *testing.T) {
	tc := testutils.NewTestContext(t)
	mockSvc := &MockComplianceReportService{}
	mockSvc.On("QueryLogs", mock.Anything, mock.MatchedBy(func(f repositories.AuditFilter) bool {
		return f.Action != nil && *f.Action == "authenticate" &&
			f.Outcome != nil && *f.Outcome == "failure" &&
			f.UserID != nil && *f.UserID == "user123"
	})).Return([]repositories.AuditLog{}, int64(0), true, nil)
	tc.MockContainer.On("GetComplianceReportService").Return(mockSvc)

	cmd, _ := newLogsCmd()
	cmd.SetContext(buildAuditCtx(tc))
	cmd.SetArgs([]string{
		"--action=authenticate", "--outcome=failure",
		"--user-id=user123", "--resource-type=secret",
	})
	err := cmd.Execute()
	assert.NoError(t, err)
	mockSvc.AssertExpectations(t)
}

func TestLogsCmd_InvalidFrom(t *testing.T) {
	tc := testutils.NewTestContext(t)
	mockSvc := &MockComplianceReportService{}
	tc.MockContainer.On("GetComplianceReportService").Return(mockSvc)

	cmd, _ := newLogsCmd()
	cmd.SetContext(buildAuditCtx(tc))
	cmd.SetArgs([]string{"--from=not-a-date"})
	err := cmd.Execute()
	assert.ErrorContains(t, err, "invalid --from value")
}

func TestLogsCmd_InvalidTo(t *testing.T) {
	tc := testutils.NewTestContext(t)
	mockSvc := &MockComplianceReportService{}
	mockSvc.On("QueryLogs", mock.Anything, mock.Anything).
		Return([]repositories.AuditLog{}, int64(0), true, nil).Maybe()
	tc.MockContainer.On("GetComplianceReportService").Return(mockSvc)

	cmd, _ := newLogsCmd()
	cmd.SetContext(buildAuditCtx(tc))
	cmd.SetArgs([]string{"--from=2026-01-01", "--to=bad"})
	err := cmd.Execute()
	assert.ErrorContains(t, err, "invalid --to value")
}

func TestLogsCmd_NoFormatter(t *testing.T) {
	tc := testutils.NewTestContext(t)
	mockSvc := &MockComplianceReportService{}
	mockSvc.On("QueryLogs", mock.Anything, mock.Anything).
		Return([]repositories.AuditLog{}, int64(0), true, nil)
	tc.MockContainer.On("GetComplianceReportService").Return(mockSvc)

	// Context WITHOUT OutputFormatterKey.
	ctx := context.WithValue(tc.Ctx, common.ServiceContainerKey, tc.MockContainer)

	cmd, _ := newLogsCmd()
	cmd.SetContext(ctx)
	err := cmd.Execute()
	assert.ErrorContains(t, err, "output formatter not available")
}

// --------------------------------------------------------------------------
// reportCmd.RunE tests
// --------------------------------------------------------------------------

func TestReportCmd_NoServiceContainer(t *testing.T) {
	cmd, _ := newReportCmd()
	cmd.SetContext(context.Background())
	cmd.SetArgs([]string{"--type=soc2", "--from=2026-01-01", "--to=2026-12-31"})
	err := cmd.Execute()
	assert.ErrorContains(t, err, "service container not available")
}

func TestReportCmd_MissingType(t *testing.T) {
	tc := testutils.NewTestContext(t)
	tc.MockContainer.On("GetComplianceReportService").Return(&MockComplianceReportService{}).Maybe()
	cmd, _ := newReportCmd()
	cmd.SetContext(tc.Ctx)
	err := cmd.Execute()
	assert.ErrorContains(t, err, "--type is required")
}

func TestReportCmd_MissingFrom(t *testing.T) {
	tc := testutils.NewTestContext(t)
	tc.MockContainer.On("GetComplianceReportService").Return(&MockComplianceReportService{}).Maybe()
	cmd, _ := newReportCmd()
	cmd.SetContext(tc.Ctx)
	cmd.SetArgs([]string{"--type=soc2"})
	err := cmd.Execute()
	assert.ErrorContains(t, err, "--from is required")
}

func TestReportCmd_MissingTo(t *testing.T) {
	tc := testutils.NewTestContext(t)
	tc.MockContainer.On("GetComplianceReportService").Return(&MockComplianceReportService{}).Maybe()
	cmd, _ := newReportCmd()
	cmd.SetContext(tc.Ctx)
	cmd.SetArgs([]string{"--type=soc2", "--from=2026-01-01"})
	err := cmd.Execute()
	assert.ErrorContains(t, err, "--to is required")
}

func TestReportCmd_InvalidFrom(t *testing.T) {
	tc := testutils.NewTestContext(t)
	tc.MockContainer.On("GetComplianceReportService").Return(&MockComplianceReportService{}).Maybe()
	cmd, _ := newReportCmd()
	cmd.SetContext(tc.Ctx)
	cmd.SetArgs([]string{"--type=soc2", "--from=bad", "--to=2026-12-31"})
	err := cmd.Execute()
	assert.ErrorContains(t, err, "invalid --from value")
}

func TestReportCmd_InvalidTo(t *testing.T) {
	tc := testutils.NewTestContext(t)
	tc.MockContainer.On("GetComplianceReportService").Return(&MockComplianceReportService{}).Maybe()
	cmd, _ := newReportCmd()
	cmd.SetContext(tc.Ctx)
	cmd.SetArgs([]string{"--type=soc2", "--from=2026-01-01", "--to=bad"})
	err := cmd.Execute()
	assert.ErrorContains(t, err, "invalid --to value")
}

func TestReportCmd_SOC2_Success(t *testing.T) {
	tc := testutils.NewTestContext(t)
	mockSvc := &MockComplianceReportService{}
	from := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	to := time.Date(2026, 12, 31, 0, 0, 0, 0, time.UTC)
	mockSvc.On("GenerateSOC2Report", mock.Anything, from, to).Return(&auditServices.SOC2Report{
		From: from, To: to, TotalEvents: 100, UniqueUsers: 5, AuthSuccesses: 90, AuthFailures: 10,
		TopActions: []auditServices.ActionCount{{Action: "login", Count: 50}},
	}, nil)
	_ = from
	tc.MockContainer.On("GetComplianceReportService").Return(mockSvc)

	cmd, buf := newReportCmd()
	cmd.SetContext(tc.Ctx)
	cmd.SetArgs([]string{"--type=soc2", "--from=2026-01-01", "--to=2026-12-31"})
	err := cmd.Execute()
	assert.NoError(t, err)
	assert.Contains(t, buf.String(), "SOC 2 Report")
	mockSvc.AssertExpectations(t)
}

func TestReportCmd_SOC2_Error(t *testing.T) {
	tc := testutils.NewTestContext(t)
	mockSvc := &MockComplianceReportService{}
	mockSvc.On("GenerateSOC2Report", mock.Anything, mock.Anything, mock.Anything).
		Return(nil, fmt.Errorf("report gen error"))
	tc.MockContainer.On("GetComplianceReportService").Return(mockSvc)

	cmd, _ := newReportCmd()
	cmd.SetContext(tc.Ctx)
	cmd.SetArgs([]string{"--type=soc2", "--from=2026-01-01", "--to=2026-12-31"})
	err := cmd.Execute()
	assert.ErrorContains(t, err, "failed to generate SOC 2 report")
}

func TestReportCmd_SOC2_CSV(t *testing.T) {
	tc := testutils.NewTestContext(t)
	mockSvc := &MockComplianceReportService{}
	mockSvc.On("GenerateSOC2CSV", mock.Anything, mock.Anything, mock.Anything).
		Return("id,timestamp,action\n", nil)
	tc.MockContainer.On("GetComplianceReportService").Return(mockSvc)

	cmd, buf := newReportCmd()
	cmd.SetContext(tc.Ctx)
	cmd.SetArgs([]string{"--type=soc2", "--from=2026-01-01", "--to=2026-12-31", "--format=csv"})
	err := cmd.Execute()
	assert.NoError(t, err)
	assert.Contains(t, buf.String(), "id,timestamp")
	mockSvc.AssertExpectations(t)
}

func TestReportCmd_SOC2_CSV_Error(t *testing.T) {
	tc := testutils.NewTestContext(t)
	mockSvc := &MockComplianceReportService{}
	mockSvc.On("GenerateSOC2CSV", mock.Anything, mock.Anything, mock.Anything).
		Return("", fmt.Errorf("csv error"))
	tc.MockContainer.On("GetComplianceReportService").Return(mockSvc)

	cmd, _ := newReportCmd()
	cmd.SetContext(tc.Ctx)
	cmd.SetArgs([]string{"--type=soc2", "--from=2026-01-01", "--to=2026-12-31", "--format=csv"})
	err := cmd.Execute()
	assert.ErrorContains(t, err, "failed to generate SOC 2 CSV")
}

func TestReportCmd_GDPR_MissingSubjectID(t *testing.T) {
	tc := testutils.NewTestContext(t)
	mockSvc := &MockComplianceReportService{}
	tc.MockContainer.On("GetComplianceReportService").Return(mockSvc)

	cmd, _ := newReportCmd()
	cmd.SetContext(tc.Ctx)
	cmd.SetArgs([]string{"--type=gdpr", "--from=2026-01-01", "--to=2026-12-31"})
	err := cmd.Execute()
	assert.ErrorContains(t, err, "--subject-id is required")
}

func TestReportCmd_GDPR_Success(t *testing.T) {
	tc := testutils.NewTestContext(t)
	mockSvc := &MockComplianceReportService{}
	mockSvc.On("GenerateGDPRReport", mock.Anything, mock.Anything, mock.Anything, "user123").
		Return(&auditServices.GDPRReport{
			SubjectID: "user123", TotalEvents: 5, DataAccess: 3, Deletions: 1, AuthEvents: 1,
		}, nil)
	tc.MockContainer.On("GetComplianceReportService").Return(mockSvc)

	cmd, buf := newReportCmd()
	cmd.SetContext(tc.Ctx)
	cmd.SetArgs([]string{"--type=gdpr", "--from=2026-01-01", "--to=2026-12-31", "--subject-id=user123"})
	err := cmd.Execute()
	assert.NoError(t, err)
	assert.Contains(t, buf.String(), "GDPR Report")
	mockSvc.AssertExpectations(t)
}

func TestReportCmd_GDPR_Error(t *testing.T) {
	tc := testutils.NewTestContext(t)
	mockSvc := &MockComplianceReportService{}
	mockSvc.On("GenerateGDPRReport", mock.Anything, mock.Anything, mock.Anything, "user123").
		Return(nil, fmt.Errorf("gdpr error"))
	tc.MockContainer.On("GetComplianceReportService").Return(mockSvc)

	cmd, _ := newReportCmd()
	cmd.SetContext(tc.Ctx)
	cmd.SetArgs([]string{"--type=gdpr", "--from=2026-01-01", "--to=2026-12-31", "--subject-id=user123"})
	err := cmd.Execute()
	assert.ErrorContains(t, err, "failed to generate GDPR report")
}

func TestReportCmd_GDPR_CSV(t *testing.T) {
	tc := testutils.NewTestContext(t)
	mockSvc := &MockComplianceReportService{}
	mockSvc.On("GenerateGDPRCSV", mock.Anything, mock.Anything, mock.Anything, "user123").
		Return("id,action\n", nil)
	tc.MockContainer.On("GetComplianceReportService").Return(mockSvc)

	cmd, buf := newReportCmd()
	cmd.SetContext(tc.Ctx)
	cmd.SetArgs([]string{"--type=gdpr", "--from=2026-01-01", "--to=2026-12-31", "--subject-id=user123", "--format=csv"})
	err := cmd.Execute()
	assert.NoError(t, err)
	assert.Contains(t, buf.String(), "id,action")
	mockSvc.AssertExpectations(t)
}

func TestReportCmd_GDPR_CSV_Error(t *testing.T) {
	tc := testutils.NewTestContext(t)
	mockSvc := &MockComplianceReportService{}
	mockSvc.On("GenerateGDPRCSV", mock.Anything, mock.Anything, mock.Anything, "user123").
		Return("", fmt.Errorf("csv gen err"))
	tc.MockContainer.On("GetComplianceReportService").Return(mockSvc)

	cmd, _ := newReportCmd()
	cmd.SetContext(tc.Ctx)
	cmd.SetArgs([]string{"--type=gdpr", "--from=2026-01-01", "--to=2026-12-31", "--subject-id=user123", "--format=csv"})
	err := cmd.Execute()
	assert.ErrorContains(t, err, "failed to generate GDPR CSV")
}

func TestReportCmd_UnknownType(t *testing.T) {
	tc := testutils.NewTestContext(t)
	mockSvc := &MockComplianceReportService{}
	tc.MockContainer.On("GetComplianceReportService").Return(mockSvc)

	cmd, _ := newReportCmd()
	cmd.SetContext(tc.Ctx)
	cmd.SetArgs([]string{"--type=unknown", "--from=2026-01-01", "--to=2026-12-31"})
	err := cmd.Execute()
	assert.ErrorContains(t, err, "unknown report type")
}

// --------------------------------------------------------------------------
// configCmd.RunE tests
// --------------------------------------------------------------------------

func TestConfigCmd_NoServiceContainer(t *testing.T) {
	cmd, _ := newConfigCmd()
	cmd.SetContext(context.Background())
	err := cmd.Execute()
	assert.ErrorContains(t, err, "service container not available")
}

func TestConfigCmd_GetRetentionDays_Success(t *testing.T) {
	tc := testutils.NewTestContext(t)
	mockSvc := &MockComplianceReportService{}
	mockSvc.On("GetRetentionDays", mock.Anything).Return(90, nil)
	tc.MockContainer.On("GetComplianceReportService").Return(mockSvc)

	cmd, buf := newConfigCmd()
	cmd.SetContext(tc.Ctx)
	// No --retention-days → GetRetentionDays path.
	err := cmd.Execute()
	assert.NoError(t, err)
	assert.Contains(t, buf.String(), "90 days")
	mockSvc.AssertExpectations(t)
}

func TestConfigCmd_GetRetentionDays_Error(t *testing.T) {
	tc := testutils.NewTestContext(t)
	mockSvc := &MockComplianceReportService{}
	mockSvc.On("GetRetentionDays", mock.Anything).Return(0, fmt.Errorf("db error"))
	tc.MockContainer.On("GetComplianceReportService").Return(mockSvc)

	cmd, _ := newConfigCmd()
	cmd.SetContext(tc.Ctx)
	err := cmd.Execute()
	assert.ErrorContains(t, err, "failed to get retention policy")
}

func TestConfigCmd_SetRetentionDays_Success(t *testing.T) {
	tc := testutils.NewTestContext(t)
	mockSvc := &MockComplianceReportService{}
	mockSvc.On("SetRetentionDays", mock.Anything, 120).Return(nil)
	tc.MockContainer.On("GetComplianceReportService").Return(mockSvc)

	cmd, buf := newConfigCmd()
	cmd.SetContext(tc.Ctx)
	cmd.SetArgs([]string{"--retention-days=120"})
	err := cmd.Execute()
	assert.NoError(t, err)
	assert.Contains(t, buf.String(), "updated")
	mockSvc.AssertExpectations(t)
}

func TestConfigCmd_SetRetentionDays_Error(t *testing.T) {
	tc := testutils.NewTestContext(t)
	mockSvc := &MockComplianceReportService{}
	mockSvc.On("SetRetentionDays", mock.Anything, 100).Return(fmt.Errorf("write error"))
	tc.MockContainer.On("GetComplianceReportService").Return(mockSvc)

	cmd, _ := newConfigCmd()
	cmd.SetContext(tc.Ctx)
	cmd.SetArgs([]string{"--retention-days=100"})
	err := cmd.Execute()
	assert.ErrorContains(t, err, "failed to update retention policy")
}

// TestConfigCmd_SetRetentionDays_BelowFloor pins the 90-day floor on the CLI
// before the service is reached (B81).
func TestConfigCmd_SetRetentionDays_BelowFloor(t *testing.T) {
	tc := testutils.NewTestContext(t)
	mockSvc := &MockComplianceReportService{}
	tc.MockContainer.On("GetComplianceReportService").Return(mockSvc)

	cmd, _ := newConfigCmd()
	cmd.SetContext(tc.Ctx)
	cmd.SetArgs([]string{"--retention-days=30"})
	err := cmd.Execute()
	assert.ErrorContains(t, err, "at least 90")
	mockSvc.AssertNotCalled(t, "SetRetentionDays", mock.Anything, mock.Anything)
}

// TestConfigCmd_NonAdmin_Forbidden proves a non-admin caller is rejected
// before GetRetentionDays/SetRetentionDays is ever called.
func TestConfigCmd_NonAdmin_Forbidden(t *testing.T) {
	tc := testutils.NewTestContext(t)
	mockSvc := &MockComplianceReportService{}
	tc.MockContainer.On("GetComplianceReportService").Return(mockSvc).Maybe()

	ctx := context.WithValue(tc.Ctx, common.ClaimsKey, &model.Claims{Roles: []string{model.RoleUser}})

	cmd, _ := newConfigCmd()
	cmd.SetContext(ctx)
	err := cmd.Execute()

	assert.ErrorContains(t, err, "forbidden: requires admin role")
	mockSvc.AssertNotCalled(t, "GetRetentionDays", mock.Anything)
	mockSvc.AssertNotCalled(t, "SetRetentionDays", mock.Anything, mock.Anything)
}

// TestConfigCmd_Admin_Allowed proves an admin caller still reaches
// GetRetentionDays after the gate is added.
func TestConfigCmd_Admin_Allowed(t *testing.T) {
	tc := testutils.NewTestContext(t)
	mockSvc := &MockComplianceReportService{}
	mockSvc.On("GetRetentionDays", mock.Anything).Return(90, nil)
	tc.MockContainer.On("GetComplianceReportService").Return(mockSvc)

	cmd, buf := newConfigCmd()
	cmd.SetContext(tc.Ctx)
	err := cmd.Execute()

	assert.NoError(t, err)
	assert.Contains(t, buf.String(), "90 days")
	mockSvc.AssertExpectations(t)
}

// --------------------------------------------------------------------------
// parseDate coverage (missing the error branch)
// --------------------------------------------------------------------------

func TestParseDate_RFC3339(t *testing.T) {
	ts := "2026-06-01T12:00:00Z"
	got, err := parseDate(ts)
	assert.NoError(t, err)
	assert.Equal(t, 2026, got.Year())
}

func TestParseDate_YYYYMMDD(t *testing.T) {
	got, err := parseDate("2026-01-15")
	assert.NoError(t, err)
	assert.Equal(t, 15, got.Day())
}

func TestParseDate_Invalid(t *testing.T) {
	_, err := parseDate("not-a-date")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "expected RFC3339 or YYYY-MM-DD")
}

// TestReportCmd_NonAdmin_Forbidden proves a non-admin caller is rejected
// before any report-generation method is called.
func TestReportCmd_NonAdmin_Forbidden(t *testing.T) {
	tc := testutils.NewTestContext(t)
	mockSvc := &MockComplianceReportService{}
	tc.MockContainer.On("GetComplianceReportService").Return(mockSvc).Maybe()

	ctx := context.WithValue(tc.Ctx, common.ClaimsKey, &model.Claims{Roles: []string{model.RoleUser}})

	cmd, _ := newReportCmd()
	cmd.SetContext(ctx)
	cmd.SetArgs([]string{"--type=soc2", "--from=2026-01-01", "--to=2026-12-31"})
	err := cmd.Execute()

	assert.ErrorContains(t, err, "forbidden: requires admin role")
	mockSvc.AssertNotCalled(t, "GenerateSOC2Report", mock.Anything, mock.Anything, mock.Anything)
}

// TestReportCmd_Admin_Allowed proves an admin caller still reaches
// GenerateSOC2Report after the gate is added.
func TestReportCmd_Admin_Allowed(t *testing.T) {
	tc := testutils.NewTestContext(t)
	mockSvc := &MockComplianceReportService{}
	from := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	to := time.Date(2026, 12, 31, 0, 0, 0, 0, time.UTC)
	mockSvc.On("GenerateSOC2Report", mock.Anything, from, to).
		Return(&auditServices.SOC2Report{From: from, To: to, TotalEvents: 1}, nil)
	tc.MockContainer.On("GetComplianceReportService").Return(mockSvc)

	cmd, buf := newReportCmd()
	cmd.SetContext(tc.Ctx)
	cmd.SetArgs([]string{"--type=soc2", "--from=2026-01-01", "--to=2026-12-31"})
	err := cmd.Execute()

	assert.NoError(t, err)
	assert.Contains(t, buf.String(), "SOC 2 Report")
	mockSvc.AssertExpectations(t)
}

// TestLogsCmd_NonAdmin_Forbidden proves a non-admin caller is rejected before
// QueryLogs is ever called.
func TestLogsCmd_NonAdmin_Forbidden(t *testing.T) {
	tc := testutils.NewTestContext(t)
	mockSvc := &MockComplianceReportService{}
	tc.MockContainer.On("GetComplianceReportService").Return(mockSvc).Maybe()

	ctx := context.WithValue(tc.Ctx, common.ClaimsKey, &model.Claims{Roles: []string{model.RoleUser}})

	cmd, _ := newLogsCmd()
	cmd.SetContext(ctx)
	err := cmd.Execute()

	assert.ErrorContains(t, err, "forbidden: requires admin role")
	mockSvc.AssertNotCalled(t, "QueryLogs", mock.Anything, mock.Anything)
}

// TestLogsCmd_Admin_Allowed proves an admin caller still reaches QueryLogs
// after the gate is added (regression guard for the fix in this task).
func TestLogsCmd_Admin_Allowed(t *testing.T) {
	tc := testutils.NewTestContext(t)
	mockSvc := &MockComplianceReportService{}
	mockSvc.On("QueryLogs", mock.Anything, mock.Anything).
		Return([]repositories.AuditLog{}, int64(0), true, nil)
	tc.MockContainer.On("GetComplianceReportService").Return(mockSvc)

	cmd, buf := newLogsCmd()
	cmd.SetContext(buildAuditCtx(tc))
	err := cmd.Execute()

	assert.NoError(t, err)
	assert.Contains(t, buf.String(), "Total matching: 0")
	mockSvc.AssertExpectations(t)
}

// TestLogsCmd_MultiRoleWithAdmin_Allowed proves a caller holding multiple
// roles, admin among them but not first, still reaches QueryLogs.
func TestLogsCmd_MultiRoleWithAdmin_Allowed(t *testing.T) {
	tc := testutils.NewTestContext(t)
	mockSvc := &MockComplianceReportService{}
	mockSvc.On("QueryLogs", mock.Anything, mock.Anything).
		Return([]repositories.AuditLog{}, int64(0), true, nil)
	tc.MockContainer.On("GetComplianceReportService").Return(mockSvc)

	ctx := context.WithValue(buildAuditCtx(tc), common.ClaimsKey, &model.Claims{Roles: []string{model.RoleSecretsManager, model.RoleAdmin}})

	cmd, buf := newLogsCmd()
	cmd.SetContext(ctx)
	err := cmd.Execute()

	assert.NoError(t, err)
	assert.Contains(t, buf.String(), "Total matching: 0")
	mockSvc.AssertExpectations(t)
}
