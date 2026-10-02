package vaults

import (
	"fmt"
	"strconv"
	"time"

	"github.com/spf13/cobra"

	"rocketvault/cmd/vaultcli"
	"rocketvault/common"
	"rocketvault/internal/container"
	"rocketvault/internal/formatter"
	"rocketvault/model"
)

// updateCmd represents the vaults update command.
var updateCmd = &cobra.Command{
	Use:   "update <name>",
	Short: "Update a vault",
	Long: `Update an existing vault's settings. Only flags explicitly passed on
the command line are applied; --enabled defaults to true but is only used
when --enabled is actually set.

Requires the admin account role, or an access-policy allow on (vaults,
manage) scoped to this vault.

The vault name is the positional argument; this command has no --vault
flag.`,
	Example: `  # Disable a vault
  rocketvault vaults update <name> --enabled=false

  # Update purge protection and retention
  rocketvault vaults update <name> --purge-protection --retention-days 60`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		name := args[0]

		ctx := cmd.Context()
		serviceContainer, ok := ctx.Value(common.ServiceContainerKey).(container.ServiceContainerInterface)
		if !ok || serviceContainer == nil {
			return fmt.Errorf("service container not available in context")
		}
		if _, err := requireCanManageVault(ctx, serviceContainer, name); err != nil {
			return err
		}
		_, callerID, err := vaultcli.CallerIdentity(ctx)
		if err != nil {
			return err
		}
		vaultService := serviceContainer.GetVaultService()

		var req model.UpdateVaultRequest
		if cmd.Flags().Changed("enabled") {
			en, _ := cmd.Flags().GetBool("enabled")
			req.Enabled = &en
		}
		if cmd.Flags().Changed("purge-protection") {
			pp, _ := cmd.Flags().GetBool("purge-protection")
			req.PurgeProtection = &pp
		}
		if cmd.Flags().Changed("retention-days") {
			rd, _ := cmd.Flags().GetInt("retention-days")
			req.RetentionDays = &rd
		}

		vault, err := vaultService.UpdateVault(ctx, name, req, callerID)
		if err != nil {
			return fmt.Errorf("failed to update vault %q: %w", name, err)
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

// InitVaultsUpdate registers the update command under the vaults command group.
func InitVaultsUpdate(vaultsCmd *cobra.Command) {
	vaultsCmd.AddCommand(updateCmd)

	updateCmd.Flags().Bool("enabled", true, "Enable or disable the vault")
	updateCmd.Flags().Bool("purge-protection", false, "Protect the vault from being purged")
	updateCmd.Flags().Int("retention-days", 0, "Soft-delete retention period in days")
}
