package audit

import (
	"fmt"
	"time"

	"github.com/spf13/cobra"

	"rocketvault/common"
	"rocketvault/internal/container"
	"rocketvault/internal/formatter"
	"rocketvault/model"
)

// logsCmd queries and displays audit log entries.
var logsCmd = &cobra.Command{
	Use:   "logs",
	Short: "Query audit log entries",
	Long: `Query audit log entries, filtered by time range, user, action, outcome, or
resource type. Prints a running total of matching entries, then the
entries themselves; if the log's hash chain fails an integrity check, a
tampering warning is printed to stderr first.

--from and --to accept RFC3339 timestamps or YYYY-MM-DD dates. --limit
caps the number of entries returned (default 100).

Requires the global admin role. Audit data spans every vault, so there is
no --vault scoping.`,
	Example: `  # View recent audit logs
  rocketvault audit logs

  # Filter by date range and action
  rocketvault audit logs --from 2026-01-01 --to 2026-01-31 \
    --action authenticate --outcome failure

  # Filter by user and resource type, as JSON
  rocketvault audit logs --user-id <user-id> --resource-type secret \
    --limit 50 --output json`,
	Args: cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := cmd.Context()

		sc, ok := ctx.Value(common.ServiceContainerKey).(container.ServiceContainerInterface)
		if !ok || sc == nil {
			return fmt.Errorf("service container not available in context")
		}

		if _, err := requireAuditAdmin(cmd); err != nil {
			return err
		}

		// Parse time range flags.
		fromStr, _ := cmd.Flags().GetString("from")
		toStr, _ := cmd.Flags().GetString("to")
		userID, _ := cmd.Flags().GetString("user-id")
		action, _ := cmd.Flags().GetString("action")
		outcome, _ := cmd.Flags().GetString("outcome")
		resourceType, _ := cmd.Flags().GetString("resource-type")
		limit, _ := cmd.Flags().GetInt("limit")

		filter := model.AuditFilter{Limit: limit}

		if fromStr != "" {
			t, err := parseDate(fromStr)
			if err != nil {
				return fmt.Errorf("invalid --from value %q: %w", fromStr, err)
			}
			filter.From = &t
		}
		if toStr != "" {
			t, err := parseDate(toStr)
			if err != nil {
				return fmt.Errorf("invalid --to value %q: %w", toStr, err)
			}
			filter.To = &t
		}
		if userID != "" {
			filter.UserID = &userID
		}
		if action != "" {
			filter.Action = &action
		}
		if outcome != "" {
			filter.Outcome = &outcome
		}
		if resourceType != "" {
			filter.ResourceType = &resourceType
		}

		svc := sc.GetComplianceReportService()
		logs, total, integrity, err := svc.QueryLogs(ctx, filter)
		if err != nil {
			return fmt.Errorf("failed to query audit logs: %w", err)
		}

		if !integrity.OK {
			fmt.Fprintf(cmd.ErrOrStderr(), "WARNING: hash chain integrity check failed (%s) — audit log may have been tampered with\n", integrity.BreakReason) //nolint:errcheck
		}

		fmt.Fprintf(cmd.OutOrStdout(), "Total matching: %d\n", total) //nolint:errcheck

		fmtr, ok := ctx.Value(common.OutputFormatterKey).(formatter.Formatter)
		if !ok {
			return fmt.Errorf("output formatter not available in context")
		}

		headers := []string{"ID", "Timestamp", "User ID", "Action", "Outcome", "Resource Type", "Resource ID", "Source"}
		rows := make([][]string, len(logs))
		for i, l := range logs {
			rows[i] = []string{
				l.ID,
				l.Timestamp.Format(time.RFC3339),
				l.UserID,
				l.Action,
				l.Outcome,
				l.ResourceType,
				l.ResourceID,
				l.Source,
			}
		}
		return fmtr.Write(cmd.OutOrStdout(), headers, rows)
	},
}

func init() {
	logsCmd.Flags().String("from", "", "Start of time range (RFC3339 or YYYY-MM-DD)")
	logsCmd.Flags().String("to", "", "End of time range (RFC3339 or YYYY-MM-DD)")
	logsCmd.Flags().String("user-id", "", "Filter by user ID")
	logsCmd.Flags().String("action", "", "Filter by action name")
	logsCmd.Flags().String("outcome", "", "Filter by outcome (success|failure|warning|denied|attempt)")
	logsCmd.Flags().String("resource-type", "", "Filter by resource type (secret|key|certificate)")
	logsCmd.Flags().Int("limit", 100, "Maximum number of log entries to return")
}

// parseDate tries RFC3339 first, then YYYY-MM-DD.
func parseDate(s string) (time.Time, error) {
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t, nil
	}
	t, err := time.Parse("2006-01-02", s)
	if err != nil {
		return time.Time{}, fmt.Errorf("expected RFC3339 or YYYY-MM-DD, got %q", s)
	}
	return t, nil
}
