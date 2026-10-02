package audit

import (
	"context"
	"encoding/csv"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"rocketvault/internal/repositories"
	"rocketvault/model"
)

// SOC2Report contains aggregated data for a SOC 2 access-events report.
type SOC2Report struct {
	From             time.Time
	To               time.Time
	TotalEvents      int64
	UniqueUsers      int64
	AuthSuccesses    int64
	AuthFailures     int64
	DataAccessEvents int64
	AdminActions     int64
	KeyOperations    int64
	TopActions       []ActionCount
}

// ActionCount pairs an action name with its frequency.
type ActionCount struct {
	Action string
	Count  int64
}

// GDPRReport contains all events touching a specific data subject.
type GDPRReport struct {
	SubjectID   string
	From        time.Time
	To          time.Time
	TotalEvents int64
	DataAccess  int64
	Deletions   int64
	AuthEvents  int64
	Events      []repositories.AuditLog
}

// ComplianceReportServiceInterface is the read-path contract.
type ComplianceReportServiceInterface interface {
	QueryLogs(ctx context.Context, filter model.AuditFilter) ([]repositories.AuditLog, int64, bool, error)
	GenerateSOC2Report(ctx context.Context, from, to time.Time) (*SOC2Report, error)
	GenerateSOC2CSV(ctx context.Context, from, to time.Time) (string, error)
	GenerateGDPRReport(ctx context.Context, from, to time.Time, subjectID string) (*GDPRReport, error)
	GenerateGDPRCSV(ctx context.Context, from, to time.Time, subjectID string) (string, error)
	PurgeExpiredLogs(ctx context.Context) (int64, error)
	GetRetentionDays(ctx context.Context) (int, error)
	SetRetentionDays(ctx context.Context, days int) error
}

// ComplianceReportService implements ComplianceReportServiceInterface.
type ComplianceReportService struct {
	repo repositories.AuditRepositoryExtended
}

// NewComplianceReportService creates a ComplianceReportService.
func NewComplianceReportService(repo repositories.AuditRepositoryExtended) ComplianceReportServiceInterface {
	return &ComplianceReportService{repo: repo}
}

// QueryLogs returns paginated audit logs and an integrity flag.
// integrityOK is false if any hash chain break is detected in the returned page.
func (s *ComplianceReportService) QueryLogs(ctx context.Context, filter model.AuditFilter) ([]repositories.AuditLog, int64, bool, error) {
	logs, total, err := s.repo.QueryAuditLogs(ctx, filter)
	if err != nil {
		return nil, 0, false, err
	}
	integrityOK := verifyChain(logs)
	return logs, total, integrityOK, nil
}

// GenerateSOC2Report builds aggregated SOC 2 metrics for the given time range.
func (s *ComplianceReportService) GenerateSOC2Report(ctx context.Context, from, to time.Time) (*SOC2Report, error) {
	logs, _, err := s.repo.QueryAuditLogs(ctx, repositories.AuditFilter{From: &from, To: &to, Limit: 1000})
	if err != nil {
		return nil, fmt.Errorf("soc2 report query: %w", err)
	}

	report := &SOC2Report{From: from, To: to}
	actionCounts := map[string]int64{}
	userSet := map[string]struct{}{}

	for _, l := range logs {
		report.TotalEvents++
		if l.UserID != "" {
			userSet[l.UserID] = struct{}{}
		}
		actionCounts[l.Action]++

		switch {
		case strings.HasPrefix(l.Action, "authenticate") || l.Action == "validate_session":
			if l.Outcome == "success" {
				report.AuthSuccesses++
			} else {
				report.AuthFailures++
			}
		case l.ResourceType == "secret":
			report.DataAccessEvents++
		case l.ResourceType == "key":
			report.KeyOperations++
		case strings.HasPrefix(l.Action, "create_user") || strings.HasPrefix(l.Action, "delete_user") ||
			strings.HasPrefix(l.Action, "update_user"):
			report.AdminActions++
		}
	}
	report.UniqueUsers = int64(len(userSet))

	for action, count := range actionCounts {
		report.TopActions = append(report.TopActions, ActionCount{Action: action, Count: count})
	}
	return report, nil
}

// GenerateSOC2CSV renders a SOC 2 report as CSV.
func (s *ComplianceReportService) GenerateSOC2CSV(ctx context.Context, from, to time.Time) (string, error) {
	report, err := s.GenerateSOC2Report(ctx, from, to)
	if err != nil {
		return "", err
	}
	var sb strings.Builder
	w := csv.NewWriter(&sb)
	_ = w.Write([]string{"metric", "value"})
	_ = w.Write([]string{"total_events", strconv.FormatInt(report.TotalEvents, 10)})
	_ = w.Write([]string{"unique_users", strconv.FormatInt(report.UniqueUsers, 10)})
	_ = w.Write([]string{"auth_successes", strconv.FormatInt(report.AuthSuccesses, 10)})
	_ = w.Write([]string{"auth_failures", strconv.FormatInt(report.AuthFailures, 10)})
	_ = w.Write([]string{"data_access_events", strconv.FormatInt(report.DataAccessEvents, 10)})
	_ = w.Write([]string{"admin_actions", strconv.FormatInt(report.AdminActions, 10)})
	_ = w.Write([]string{"key_operations", strconv.FormatInt(report.KeyOperations, 10)})
	for _, ac := range report.TopActions {
		_ = w.Write([]string{"action:" + ac.Action, strconv.FormatInt(ac.Count, 10)})
	}
	w.Flush()
	return sb.String(), nil
}

// GenerateGDPRReport returns all events for a specific data subject.
func (s *ComplianceReportService) GenerateGDPRReport(ctx context.Context, from, to time.Time, subjectID string) (*GDPRReport, error) {
	logs, total, err := s.repo.QueryAuditLogs(ctx, repositories.AuditFilter{
		From: &from, To: &to, UserID: &subjectID, Limit: 1000,
	})
	if err != nil {
		return nil, fmt.Errorf("gdpr report query: %w", err)
	}

	report := &GDPRReport{SubjectID: subjectID, From: from, To: to, TotalEvents: total, Events: logs}
	for _, l := range logs {
		switch {
		case l.ResourceType == "secret" && (l.Action == "get_secret" || l.Action == "list_secrets"):
			report.DataAccess++
		case strings.HasPrefix(l.Action, "delete"):
			report.Deletions++
		case strings.HasPrefix(l.Action, "authenticate") || l.Action == "validate_session":
			report.AuthEvents++
		}
	}
	return report, nil
}

// GenerateGDPRCSV renders a GDPR report as CSV.
func (s *ComplianceReportService) GenerateGDPRCSV(ctx context.Context, from, to time.Time, subjectID string) (string, error) {
	report, err := s.GenerateGDPRReport(ctx, from, to, subjectID)
	if err != nil {
		return "", err
	}
	var sb strings.Builder
	w := csv.NewWriter(&sb)
	_ = w.Write([]string{"timestamp", "action", "outcome", "resource_type", "resource_id", "source", "details"})
	for _, l := range report.Events {
		_ = w.Write([]string{
			l.Timestamp.Format(time.RFC3339),
			l.Action, l.Outcome, l.ResourceType, l.ResourceID, l.Source, l.Details,
		})
	}
	w.Flush()
	return sb.String(), nil
}

// PurgeExpiredLogs deletes logs older than the configured retention_days.
// Returns the number of rows deleted.
func (s *ComplianceReportService) PurgeExpiredLogs(ctx context.Context) (int64, error) {
	days, err := s.GetRetentionDays(ctx)
	if err != nil {
		return 0, err
	}
	cutoff := time.Now().UTC().AddDate(0, 0, -days)
	deleted, err := s.repo.DeleteBefore(ctx, cutoff)
	if err != nil {
		return 0, err
	}
	if deleted > 0 {
		_ = s.repo.InsertAuditLog(ctx, repositories.AuditLog{
			Action:  "audit_purge",
			Source:  "system",
			Outcome: "success",
			Details: fmt.Sprintf("rows_deleted=%d retention_days=%d", deleted, days),
		})
	}
	return deleted, nil
}

// MinRetentionDays is the shortest audit retention the service accepts. It
// keeps the three months of immediately available history PCI DSS 10.5.1
// asks for, and stops an admin credential from shrinking retention to erase
// its own trail at the next purge.
const MinRetentionDays = 90

// ErrRetentionBelowFloor is returned when retention_days is below MinRetentionDays.
var ErrRetentionBelowFloor = errors.New("retention_days below the minimum")

// GetRetentionDays reads retention_days from audit_config (default 365).
// A stored value below MinRetentionDays is clamped up to the floor.
func (s *ComplianceReportService) GetRetentionDays(ctx context.Context) (int, error) {
	val, err := s.repo.GetAuditConfig(ctx, "retention_days")
	if err != nil {
		return 365, err
	}
	if val == "" {
		return 365, nil
	}
	days, err := strconv.Atoi(val)
	if err != nil {
		return 365, fmt.Errorf("invalid retention_days value %q: %w", val, err)
	}
	// A value stored before the floor existed is clamped, so it cannot
	// purge recent rows.
	if days < MinRetentionDays {
		return MinRetentionDays, nil
	}
	return days, nil
}

// SetRetentionDays persists a new retention_days value of at least MinRetentionDays.
func (s *ComplianceReportService) SetRetentionDays(ctx context.Context, days int) error {
	if days < MinRetentionDays {
		return fmt.Errorf("%w: %d (minimum %d)", ErrRetentionBelowFloor, days, MinRetentionDays)
	}
	return s.repo.SetAuditConfig(ctx, "retention_days", strconv.Itoa(days))
}

// verifyChain walks logs (newest-first) and verifies the hash chain.
// Returns false if a chain break is detected. Rows with empty PrevHash are skipped.
func verifyChain(logs []repositories.AuditLog) bool {
	for i := 0; i < len(logs)-1; i++ {
		newer := logs[i]
		older := logs[i+1]
		if newer.PrevHash == "" {
			// Pre-dates hash chaining — skip.
			continue
		}
		// newer.PrevHash should equal computeHash(older.PrevHash, newer.Timestamp, event from newer).
		expected := computeHash(older.PrevHash, newer.Timestamp, AuditEvent{
			UserID:       newer.UserID,
			Action:       newer.Action,
			Details:      newer.Details,
			ResourceType: newer.ResourceType,
			ResourceID:   newer.ResourceID,
			Outcome:      newer.Outcome,
		})
		if newer.PrevHash != expected {
			return false
		}
	}
	return true
}
