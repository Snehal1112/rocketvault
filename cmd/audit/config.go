package audit

import (
	"fmt"

	"github.com/spf13/cobra"

	"rocketvault/common"
	"rocketvault/internal/container"
	auditSvc "rocketvault/internal/services/audit"
)

// configCmd manages audit log configuration settings.
var configCmd = &cobra.Command{
	Use:   "config",
	Short: "View or update audit log configuration",
	Long: `Show or update the audit log retention policy: how many days audit log
entries are kept before a daily background job purges older entries.

Pass --retention-days (minimum 90) to set a new value; omit it, or pass 0, to print the
current value instead.

Requires the global admin role. Audit data spans every vault, so there is
no --vault scoping.`,
	Example: `  # Show current audit log retention policy
  rocketvault audit config

  # Update audit log retention to 90 days
  rocketvault audit config --retention-days 90`,
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

		retentionDays, _ := cmd.Flags().GetInt("retention-days")
		if retentionDays > 0 && retentionDays < auditSvc.MinRetentionDays {
			return fmt.Errorf("--retention-days must be at least %d", auditSvc.MinRetentionDays)
		}
		svc := sc.GetComplianceReportService()

		if retentionDays > 0 {
			if err := svc.SetRetentionDays(ctx, retentionDays); err != nil {
				return fmt.Errorf("failed to update retention policy: %w", err)
			}
			fmt.Fprintf(cmd.OutOrStdout(), "Retention policy updated: %d days\n", retentionDays) //nolint:errcheck
		} else {
			days, err := svc.GetRetentionDays(ctx)
			if err != nil {
				return fmt.Errorf("failed to get retention policy: %w", err)
			}
			fmt.Fprintf(cmd.OutOrStdout(), "Current audit log retention: %d days\n", days) //nolint:errcheck
		}

		return nil
	},
}

func init() {
	configCmd.Flags().Int("retention-days", 0, "Set retention period in days (0 = show current value)")
}
