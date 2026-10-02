package vaults

import (
	"fmt"
	"strconv"
	"time"

	"github.com/spf13/cobra"

	"rocketvault/common"
	"rocketvault/internal/container"
	"rocketvault/internal/formatter"
)

// getCmd represents the vaults get command.
var getCmd = &cobra.Command{
	Use:   "get <name>",
	Short: "Retrieve a vault by name",
	Long: `Retrieve a single vault's details by name: ID, enabled state, purge
protection, retention period, and creation time.

Requires the admin account role, or an access-policy allow on (vaults,
manage) scoped to this vault.

The vault name is the positional argument; this command has no --vault
flag.`,
	Example: `  # Get a vault by name
  rocketvault vaults get <name>

  # Machine-readable output
  rocketvault vaults get <name> --output json`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		name := args[0]

		ctx := cmd.Context()
		serviceContainer, ok := ctx.Value(common.ServiceContainerKey).(container.ServiceContainerInterface)
		if !ok || serviceContainer == nil {
			return fmt.Errorf("service container not available in context")
		}
		if _, err := requireCanManageVault(ctx, serviceContainer, name, "get_vault"); err != nil {
			return err
		}
		vaultService := serviceContainer.GetVaultService()

		vault, err := vaultService.GetVault(ctx, name)
		if err != nil {
			return fmt.Errorf("failed to retrieve vault %q: %w", name, err)
		}

		fmtr, ok := ctx.Value(common.OutputFormatterKey).(formatter.Formatter)
		if !ok {
			return fmt.Errorf("output formatter not available in context")
		}
		headers := []string{"ID", "Name", "Enabled", "PurgeProtection", "RetentionDays", "Created"}
		row := []string{
			vault.ID.String(),
			vault.Name,
			strconv.FormatBool(vault.Enabled),
			strconv.FormatBool(vault.PurgeProtection),
			strconv.Itoa(vault.RetentionDays),
			vault.CreatedAt.Format(time.RFC3339),
		}
		return fmtr.Write(cmd.OutOrStdout(), headers, [][]string{row})
	},
}

// InitVaultsGet registers the get command under the vaults command group.
func InitVaultsGet(vaultsCmd *cobra.Command) {
	vaultsCmd.AddCommand(getCmd)
}
