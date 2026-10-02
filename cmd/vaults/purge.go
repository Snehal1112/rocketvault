package vaults

import (
	"fmt"

	"github.com/spf13/cobra"

	"rocketvault/common"
	"rocketvault/internal/container"
)

// purgeCmd represents the vaults purge command.
var purgeCmd = &cobra.Command{
	Use:   "purge <name>",
	Short: "Permanently purge a vault by name",
	Long: `Permanently remove a vault and everything in it: secrets, keys,
certificates, and access policies. This cannot be undone.

Requires the admin account role, or a Key Vault Purge Operator role
assignment in this vault (the Microsoft.KeyVault/vaults/purge/action data
action) — a different authorization tier from the other vaults commands,
which check the (vaults, manage) access policy instead. The admin bypass
applies only here, on the CLI: the HTTP purge route has no admin
short-circuit and always requires an explicit role grant.

The vault name is the positional argument; this command has no --vault
flag.

Refuses to run if the vault, or anything inside it, has purge protection
enabled, and always refuses the default vault. A soft-deleted vault is the
normal target, but an active vault that was never soft-deleted is purged
too if it matches by name.`,
	Example: `  # Permanently purge a soft-deleted vault
  rocketvault vaults purge <name>`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		name := args[0]

		ctx := cmd.Context()
		serviceContainer, ok := ctx.Value(common.ServiceContainerKey).(container.ServiceContainerInterface)
		if !ok || serviceContainer == nil {
			return fmt.Errorf("service container not available in context")
		}
		actorID, err := requireCanPurgeVault(ctx, serviceContainer, name)
		if err != nil {
			return err
		}
		vaultService := serviceContainer.GetVaultService()

		if err := vaultService.PurgeVault(ctx, name, actorID); err != nil {
			return fmt.Errorf("failed to purge vault %q: %w", name, err)
		}

		fmt.Fprintf(cmd.OutOrStdout(), "Vault %q purged successfully\n", name) //nolint:errcheck
		return nil
	},
}

// InitVaultsPurge registers the purge command under the vaults command group.
func InitVaultsPurge(vaultsCmd *cobra.Command) {
	vaultsCmd.AddCommand(purgeCmd)
}
