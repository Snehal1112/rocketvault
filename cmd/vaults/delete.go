package vaults

import (
	"fmt"

	"github.com/spf13/cobra"

	"rocketvault/common"
	"rocketvault/internal/container"
)

// deleteCmd represents the vaults delete command.
var deleteCmd = &cobra.Command{
	Use:   "delete <name>",
	Short: "Soft-delete a vault by name",
	Long: `Soft-delete a vault by name, cascading the soft delete to every secret,
key, and certificate it contains. The vault and its contents can be restored
with vaults recover until they are purged.

Requires the admin account role, or an access-policy allow on (vaults,
manage) scoped to this vault.

The vault name is the positional argument; this command has no --vault
flag.

The default vault cannot be deleted.`,
	Example: `  # Soft-delete a vault
  rocketvault vaults delete <name>`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		name := args[0]

		ctx := cmd.Context()
		serviceContainer, ok := ctx.Value(common.ServiceContainerKey).(container.ServiceContainerInterface)
		if !ok || serviceContainer == nil {
			return fmt.Errorf("service container not available in context")
		}
		actorID, err := requireCanManageVault(ctx, serviceContainer, name, "delete_vault")
		if err != nil {
			return err
		}
		vaultService := serviceContainer.GetVaultService()

		if err := vaultService.DeleteVault(ctx, name, actorID); err != nil {
			return fmt.Errorf("failed to delete vault %q: %w", name, err)
		}

		fmt.Fprintf(cmd.OutOrStdout(), "Vault %q deleted successfully\n", name) //nolint:errcheck
		return nil
	},
}

// InitVaultsDelete registers the delete command under the vaults command group.
func InitVaultsDelete(vaultsCmd *cobra.Command) {
	vaultsCmd.AddCommand(deleteCmd)
}
