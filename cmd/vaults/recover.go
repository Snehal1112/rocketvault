package vaults

import (
	"fmt"

	"github.com/spf13/cobra"

	"rocketvault/common"
	"rocketvault/internal/container"
)

// recoverCmd represents the vaults recover command.
var recoverCmd = &cobra.Command{
	Use:   "recover <name>",
	Short: "Recover a soft-deleted vault by name",
	Long: `Recover a soft-deleted vault by name, restoring it and cascading the
recovery to the secrets, keys, and certificates that were soft-deleted along
with it. Items that were deleted individually, at a different time, are left
untouched.

Requires the admin account role, or an access-policy allow on (vaults,
manage) scoped to this vault.

The vault name is the positional argument; this command has no --vault
flag.`,
	Example: `  # Recover a soft-deleted vault
  rocketvault vaults recover <name>`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		name := args[0]

		ctx := cmd.Context()
		serviceContainer, ok := ctx.Value(common.ServiceContainerKey).(container.ServiceContainerInterface)
		if !ok || serviceContainer == nil {
			return fmt.Errorf("service container not available in context")
		}
		actorID, err := requireCanManageVault(ctx, serviceContainer, name, "recover_vault")
		if err != nil {
			return err
		}
		vaultService := serviceContainer.GetVaultService()

		if err := vaultService.RecoverVault(ctx, name, actorID); err != nil {
			return fmt.Errorf("failed to recover vault %q: %w", name, err)
		}

		fmt.Fprintf(cmd.OutOrStdout(), "Vault %q recovered successfully\n", name) //nolint:errcheck
		return nil
	},
}

// InitVaultsRecover registers the recover command under the vaults command group.
func InitVaultsRecover(vaultsCmd *cobra.Command) {
	vaultsCmd.AddCommand(recoverCmd)
}
