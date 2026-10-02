package vaultaccess

import (
	"fmt"

	"github.com/spf13/cobra"

	"rocketvault/cmd/vaultcli"
	"rocketvault/common"
	"rocketvault/internal/cliclient"
	"rocketvault/internal/container"
	"rocketvault/internal/vaultapi"
)

// runListRemote lists role assignments from a remote server, printing the
// same columns the local path prints.
func runListRemote(cmd *cobra.Command, client *vaultapi.Client, target *cliclient.Target) error {
	vault := cliclient.ResolveRemoteVault(cmd, target)

	list, _, err := client.ListRoleAssignments(cmd.Context(), vault, 0)
	if err != nil {
		return cliclient.CLIError("list role assignments", err)
	}

	out := cmd.OutOrStdout()
	fmt.Fprintf(out, "%-38s %-20s %s\n", "ASSIGNMENT-ID", "ROLE", "PRINCIPAL-ID") //nolint:errcheck
	for i := range list {
		ra := cliclient.RoleAssignmentFromAPI(&list[i])
		fmt.Fprintf(out, "%-38s %-20s %s\n", ra.ID, ra.Role, ra.PrincipalID) //nolint:errcheck
	}
	return nil
}

// InitVaultAccessList registers the list command, which lists role assignments in a vault.
func InitVaultAccessList(parent *cobra.Command) {
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List role assignments in a vault",
		Long: `List every role assignment in a vault: assignment ID, role name, and
principal ID.

Requires the admin account role, an access-policy allow on (vaults, manage)
for this vault, or a Key Vault Data Access Administrator role assignment
holding Microsoft.Authorization/roleAssignments/delete in this vault. That
is the same check vault-access revoke uses — there is no separate,
narrower permission tier for listing.

Vault scoped via --vault; defaults to the ROCKETVAULT_VAULT environment
variable, then config, then "default" if none of those is set.`,
		Example: `  # List role assignments in a vault
  rocketvault vault-access list --vault prod

  # List role assignments in the default vault
  rocketvault vault-access list`,
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			if client, ok := ctx.Value(common.RemoteClientKey).(*vaultapi.Client); ok && client != nil {
				target, _ := ctx.Value(common.RemoteTargetKey).(*cliclient.Target)
				return runListRemote(cmd, client, target)
			}
			sc, ok := ctx.Value(common.ServiceContainerKey).(container.ServiceContainerInterface)
			if !ok || sc == nil {
				return fmt.Errorf("service container not available in context")
			}
			vaultID, err := vaultcli.ResolveVaultID(ctx, cmd, sc)
			if err != nil {
				return err
			}
			if err := requireCanManageRoleAssignments(ctx, sc, vaultID, false, "list_role_assignments"); err != nil {
				return err
			}
			list, err := sc.GetRoleAssignmentService().ListAssignments(ctx, vaultID)
			if err != nil {
				return fmt.Errorf("list failed: %w", err)
			}
			out := cmd.OutOrStdout()
			fmt.Fprintf(out, "%-38s %-20s %s\n", "ASSIGNMENT-ID", "ROLE", "PRINCIPAL-ID") //nolint:errcheck
			for _, ra := range list {
				fmt.Fprintf(out, "%-38s %-20s %s\n", ra.ID, ra.Role, ra.PrincipalID) //nolint:errcheck
			}
			return nil
		},
	}
	vaultcli.AddVaultFlag(cmd)
	parent.AddCommand(cmd)
}
