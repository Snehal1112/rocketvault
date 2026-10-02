package vaultaccess

import (
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/spf13/cobra"

	"rocketvault/cmd/vaultcli"
	"rocketvault/common"
	"rocketvault/internal/cliclient"
	"rocketvault/internal/container"
	authz "rocketvault/internal/services/authorization"
	"rocketvault/internal/vaultapi"
	"rocketvault/model"
)

// runRevokeRemote revokes one role assignment on a remote server.
// DeleteRoleAssignment rejects a non-UUID argument before issuing a request,
// since one principal can hold several roles in a vault and a name is
// ambiguous.
func runRevokeRemote(
	cmd *cobra.Command,
	client *vaultapi.Client,
	target *cliclient.Target,
	assignmentID string,
) error {
	vault := cliclient.ResolveRemoteVault(cmd, target)

	if err := client.DeleteRoleAssignment(cmd.Context(), vault, assignmentID); err != nil {
		return cliclient.CLIError("revoke a role assignment", err)
	}
	fmt.Fprintf(cmd.OutOrStdout(), "revoked assignment %s\n", assignmentID) //nolint:errcheck
	return nil
}

// InitVaultAccessRevoke registers the revoke command, which removes a role assignment.
func InitVaultAccessRevoke(parent *cobra.Command) {
	cmd := &cobra.Command{
		Use:   "revoke <assignment-id>",
		Short: "Revoke a role assignment in a vault",
		Long: `Revoke a role assignment by its assignment ID, removing that principal's
access under the granted role in the vault.

Requires the admin account role, an access-policy allow on (vaults, manage)
for this vault, or a Key Vault Data Access Administrator role assignment
holding Microsoft.Authorization/roleAssignments/delete in this vault.

Vault scoped via --vault; defaults to the ROCKETVAULT_VAULT environment
variable, then config, then "default" if none of those is set. The
assignment must belong to the resolved vault, or the revoke fails as if the
assignment did not exist.`,
		Example: `  # Revoke a role assignment by id
  rocketvault vault-access revoke <assignment-id> --vault prod`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			id, err := uuid.Parse(args[0])
			if err != nil {
				return fmt.Errorf("invalid assignment id: %w", err)
			}
			ctx := cmd.Context()
			// After the parse above, so the local "invalid assignment id"
			// check also guards remote input.
			if client, ok := ctx.Value(common.RemoteClientKey).(*vaultapi.Client); ok && client != nil {
				target, _ := ctx.Value(common.RemoteTargetKey).(*cliclient.Target)
				return runRevokeRemote(cmd, client, target, id.String())
			}
			sc, ok := ctx.Value(common.ServiceContainerKey).(container.ServiceContainerInterface)
			if !ok || sc == nil {
				return fmt.Errorf("service container not available in context")
			}
			vaultID, err := vaultcli.ResolveVaultID(ctx, cmd, sc)
			if err != nil {
				return err
			}
			if err := requireCanManageRoleAssignments(ctx, sc, vaultID, false, "revoke_role_assignment"); err != nil {
				return err
			}
			callerRoles, callerID, err := vaultcli.CallerIdentity(ctx)
			if err != nil {
				return err
			}
			isGlobalAdmin := common.HasAnyRole(callerRoles, string(model.RoleAdmin))
			if err := sc.GetRoleAssignmentService().RevokeAssignment(ctx, id, vaultID, callerID, isGlobalAdmin); err != nil {
				if errors.Is(err, authz.ErrRoleNotGrantable) {
					auditDeniedRefusal(sc, callerID, "revoke_role_assignment", err)
				}
				return fmt.Errorf("revoke failed: %w", err)
			}
			fmt.Fprintf(cmd.OutOrStdout(), "revoked assignment %s\n", id) //nolint:errcheck
			return nil
		},
	}
	vaultcli.AddVaultFlag(cmd)
	parent.AddCommand(cmd)
}
