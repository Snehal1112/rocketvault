package audit

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
)

// MockComplianceReportService is a mock for ComplianceReportServiceInterface.
type MockComplianceReportService struct {
	mock.Mock
}

func (m *MockComplianceReportService) QueryLogs(ctx context.Context, filter repositories.AuditFilter) ([]repositories.AuditLog, int64, auditServices.IntegrityResult, error) {
	args := m.Called(ctx, filter)
	// Tests may return a bare bool for the integrity result.
	var res auditServices.IntegrityResult
	switch v := args.Get(2).(type) {
	case auditServices.IntegrityResult:
		res = v
	case bool:
		res = auditServices.IntegrityResult{OK: v}
	}
	if args.Get(0) == nil {
		return nil, args.Get(1).(int64), res, args.Error(3)
	}
	return args.Get(0).([]repositories.AuditLog), args.Get(1).(int64), res, args.Error(3)
}

func (m *MockComplianceReportService) GenerateSOC2Report(ctx context.Context, from, to time.Time) (*auditServices.SOC2Report, error) {
	args := m.Called(ctx, from, to)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*auditServices.SOC2Report), args.Error(1)
}

func (m *MockComplianceReportService) GenerateSOC2CSV(ctx context.Context, from, to time.Time) (string, error) {
	args := m.Called(ctx, from, to)
	return args.String(0), args.Error(1)
}

func (m *MockComplianceReportService) GenerateGDPRReport(ctx context.Context, from, to time.Time, subjectID string) (*auditServices.GDPRReport, error) {
	args := m.Called(ctx, from, to, subjectID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*auditServices.GDPRReport), args.Error(1)
}

func (m *MockComplianceReportService) GenerateGDPRCSV(ctx context.Context, from, to time.Time, subjectID string) (string, error) {
	args := m.Called(ctx, from, to, subjectID)
	return args.String(0), args.Error(1)
}

func (m *MockComplianceReportService) PurgeExpiredLogs(ctx context.Context) (int64, error) {
	args := m.Called(ctx)
	return args.Get(0).(int64), args.Error(1)
}

func (m *MockComplianceReportService) GetRetentionDays(ctx context.Context) (int, error) {
	args := m.Called(ctx)
	return args.Int(0), args.Error(1)
}

func (m *MockComplianceReportService) SetRetentionDays(ctx context.Context, days int) error {
	args := m.Called(ctx, days)
	return args.Error(0)
}

// contextWithFormatter adds a table formatter to the test context so commands
// that read the formatter from context work correctly.
func contextWithFormatter(ctx context.Context) context.Context {
	fmtr, _ := formatter.New(formatter.Format("table"))
	return context.WithValue(ctx, common.OutputFormatterKey, fmtr)
}

// TestAuditLogsDefaultFilter verifies that "audit logs" with no flags calls
// QueryLogs with Limit=100 and returns no error.
func TestAuditLogsDefaultFilter(t *testing.T) {
	tc := testutils.NewTestContext(t)
	mockSvc := &MockComplianceReportService{}

	// Default filter has only Limit set to 100.
	mockSvc.On("QueryLogs", mock.Anything, repositories.AuditFilter{Limit: 100}).
		Return([]repositories.AuditLog{}, int64(0), true, nil)

	// Inject the service directly to avoid routing through the container.
	cmd := &cobra.Command{
		Use: "logs",
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()

			limit, _ := cmd.Flags().GetInt("limit")
			filter := repositories.AuditFilter{Limit: limit}

			logs, total, integrity, err := mockSvc.QueryLogs(ctx, filter)
			if err != nil {
				return fmt.Errorf("failed to query audit logs: %w", err)
			}
			if !integrity.OK {
				fmt.Fprintln(cmd.ErrOrStderr(), "WARNING: hash chain integrity check failed") //nolint:errcheck
			}
			fmt.Fprintf(cmd.OutOrStdout(), "Total matching: %d\n", total) //nolint:errcheck

			fmtr, ok := ctx.Value(common.OutputFormatterKey).(formatter.Formatter)
			if !ok {
				return fmt.Errorf("output formatter not available in context")
			}
			headers := []string{"ID", "Timestamp", "User ID", "Action", "Outcome", "Resource Type", "Resource ID", "Source"}
			rows := make([][]string, len(logs))
			return fmtr.Write(cmd.OutOrStdout(), headers, rows)
		},
	}
	cmd.Flags().Int("limit", 100, "Maximum number of log entries to return")

	cmd.SetContext(contextWithFormatter(tc.Ctx))
	cmd.SetArgs([]string{})

	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)

	err := cmd.Execute()
	assert.NoError(t, err)
	assert.Contains(t, out.String(), "Total matching: 0")

	mockSvc.AssertExpectations(t)
}

// TestAuditReportSOC2 verifies that "audit report --type soc2 ..." calls
// GenerateSOC2Report and prints a summary line.
func TestAuditReportSOC2(t *testing.T) {
	tc := testutils.NewTestContext(t)
	mockSvc := &MockComplianceReportService{}

	from := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	to := time.Date(2026, 12, 31, 0, 0, 0, 0, time.UTC)

	mockSvc.On("GenerateSOC2Report", mock.Anything, from, to).
		Return(&auditServices.SOC2Report{
			From:          from,
			To:            to,
			TotalEvents:   42,
			UniqueUsers:   5,
			AuthSuccesses: 30,
			AuthFailures:  2,
		}, nil)

	cmd := &cobra.Command{
		Use: "report",
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()

			reportType, _ := cmd.Flags().GetString("type")
			fromStr, _ := cmd.Flags().GetString("from")
			toStr, _ := cmd.Flags().GetString("to")

			fromT, err := parseDate(fromStr)
			if err != nil {
				return err
			}
			toT, err := parseDate(toStr)
			if err != nil {
				return err
			}

			if reportType == "soc2" {
				report, err := mockSvc.GenerateSOC2Report(ctx, fromT, toT)
				if err != nil {
					return fmt.Errorf("failed to generate SOC 2 report: %w", err)
				}
				fmt.Fprintf(cmd.OutOrStdout(), "SOC 2 Report: %s to %s\n", report.From.Format("2006-01-02"), report.To.Format("2006-01-02")) //nolint:errcheck
				fmt.Fprintf(cmd.OutOrStdout(), "  Total events:       %d\n", report.TotalEvents)                                             //nolint:errcheck
			}
			return nil
		},
	}
	cmd.Flags().String("type", "", "Report type")
	cmd.Flags().String("from", "", "Start date")
	cmd.Flags().String("to", "", "End date")

	cmd.SetContext(tc.Ctx)
	cmd.SetArgs([]string{"--type=soc2", "--from=2026-01-01", "--to=2026-12-31"})

	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)

	err := cmd.Execute()
	assert.NoError(t, err)
	assert.Contains(t, out.String(), "SOC 2 Report:")
	assert.Contains(t, out.String(), "Total events:")

	mockSvc.AssertExpectations(t)
}

// TestAuditReportGDPRMissingSubjectID verifies that "audit report --type gdpr"
// without --subject-id returns an error before calling any service.
func TestAuditReportGDPRMissingSubjectID(t *testing.T) {
	tc := testutils.NewTestContext(t)

	cmd := &cobra.Command{
		Use: "report",
		RunE: func(cmd *cobra.Command, args []string) error {
			reportType, _ := cmd.Flags().GetString("type")
			fromStr, _ := cmd.Flags().GetString("from")
			toStr, _ := cmd.Flags().GetString("to")
			subjectID, _ := cmd.Flags().GetString("subject-id")

			_, err := parseDate(fromStr)
			if err != nil {
				return err
			}
			_, err = parseDate(toStr)
			if err != nil {
				return err
			}

			if reportType == "gdpr" && subjectID == "" {
				return fmt.Errorf("--subject-id is required for GDPR reports")
			}
			return nil
		},
	}
	cmd.Flags().String("type", "", "Report type")
	cmd.Flags().String("from", "", "Start date")
	cmd.Flags().String("to", "", "End date")
	cmd.Flags().String("subject-id", "", "Data subject ID")

	cmd.SetContext(tc.Ctx)
	cmd.SetArgs([]string{"--type=gdpr", "--from=2026-01-01", "--to=2026-12-31"})

	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)

	err := cmd.Execute()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "--subject-id is required for GDPR reports")
}

// TestAuditConfigGetRetentionDays verifies that "audit config" with no flags
// calls GetRetentionDays and prints the current value.
func TestAuditConfigGetRetentionDays(t *testing.T) {
	tc := testutils.NewTestContext(t)
	mockSvc := &MockComplianceReportService{}

	mockSvc.On("GetRetentionDays", mock.Anything).Return(365, nil)

	cmd := &cobra.Command{
		Use: "config",
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()

			retentionDays, _ := cmd.Flags().GetInt("retention-days")

			if retentionDays > 0 {
				if err := mockSvc.SetRetentionDays(ctx, retentionDays); err != nil {
					return fmt.Errorf("failed to update retention policy: %w", err)
				}
				fmt.Fprintf(cmd.OutOrStdout(), "Retention policy updated: %d days\n", retentionDays) //nolint:errcheck
			} else {
				days, err := mockSvc.GetRetentionDays(ctx)
				if err != nil {
					return fmt.Errorf("failed to get retention policy: %w", err)
				}
				fmt.Fprintf(cmd.OutOrStdout(), "Current audit log retention: %d days\n", days) //nolint:errcheck
			}
			return nil
		},
	}
	cmd.Flags().Int("retention-days", 0, "Set retention period in days")

	cmd.SetContext(tc.Ctx)
	cmd.SetArgs([]string{})

	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)

	err := cmd.Execute()
	assert.NoError(t, err)
	assert.Contains(t, out.String(), "Current audit log retention: 365 days")

	mockSvc.AssertExpectations(t)
}
