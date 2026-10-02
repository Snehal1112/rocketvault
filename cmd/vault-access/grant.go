package vaultaccess

import (
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

// runGrantRemote grants a role against a remote server. Remote mode runs no
// client-side authorization check: the server owns that decision, and its
// 403 is mapped into readable text rather than pre-empted here.
//
// This is the canonical remote-adapter shape: take (cmd, client, target) as a
// fixed prefix so the function is testable without assembling a context, then
// the command's own input. cmd/secrets/*.go still uses the older form, which
// takes a ctx and pulls TokenKey and RemoteHTTPClientKey out of it -- those
// migrate to this shape in plan 08. Copy this one, not those.
//
// New adapters should pass their input as a request struct rather than
// positionally: keys create has six flags, and the positional form would give
// it nine parameters with four adjacent strings. See the Post-Execution Review
// in docs/superpowers/plans/2026-09-03-cli-remote-vaultapi-03b-vault-access-adapter.md.
func runGrantRemote(
	cmd *cobra.Command,
	client *vaultapi.Client,
	target *cliclient.Target,
	principal, role, ptype string,
) error {
	vault := cliclient.ResolveRemoteVault(cmd, target)

	ra, err := client.CreateRoleAssignment(cmd.Context(), vault, vaultapi.GrantRoleRequest{
		Principal:     principal,
		PrincipalType: ptype,
		Role:          role,
	})
	if err != nil {
		return cliclient.CLIError("grant a role", err)
	}

	resp := cliclient.RoleAssignmentFromAPI(ra)
	fmt.Fprintf(cmd.OutOrStdout(), "granted %s to %s in vault (assignment %s)\n", //nolint:errcheck
		resp.Role, principal, resp.ID)
	return nil
}

// InitVaultAccessGrant registers the grant command, which assigns a built-in role to a principal.
func InitVaultAccessGrant(parent *cobra.Command) {
	cmd := &cobra.Command{
		Use:   "grant <principal>",
		Short: "Grant a built-in role to a principal in a vault",
		Long: `Grant a built-in Azure Key Vault role to a principal (user or service
account) in a vault, creating a role assignment that governs its data-plane
access there.

Requires the admin account role, an access-policy allow on (vaults, manage)
for this vault, or a Key Vault Data Access Administrator role assignment
holding Microsoft.Authorization/roleAssignments/write in this vault.

Vault scoped via --vault; defaults to the ROCKETVAULT_VAULT environment
variable, then config, then "default" if none of those is set.

--role must be one of the built-in role names listed by vault-access roles.
--principal-type defaults to "user"; the only other accepted value is
"service_account".`,
		Example: `  # Grant a built-in role to a user in a vault
  rocketvault vault-access grant alice --role "Key Vault Secrets User" \
    --vault prod

  # Grant a role to a service account
  rocketvault vault-access grant my-svc --role "Key Vault Crypto User" \
    --principal-type service_account --vault prod`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			principal := args[0]
			role, _ := cmd.Flags().GetString("role")
			if role == "" {
				return fmt.Errorf("--role is required")
			}
			ptype, _ := cmd.Flags().GetString("principal-type")
			if ptype == "" {
				ptype = string(model.PrincipalTypeUser)
			}
			ctx := cmd.Context()
			if client, ok := ctx.Value(common.RemoteClientKey).(*vaultapi.Client); ok && client != nil {
				target, _ := ctx.Value(common.RemoteTargetKey).(*cliclient.Target)
				return runGrantRemote(cmd, client, target, principal, role, ptype)
			}
			callerID, _ := ctx.Value(common.UserIDKey).(uuid.UUID)
			sc, ok := ctx.Value(common.ServiceContainerKey).(container.ServiceContainerInterface)
			if !ok || sc == nil {
				return fmt.Errorf("service container not available in context")
			}
			vaultID, err := vaultcli.ResolveVaultID(ctx, cmd, sc)
			if err != nil {
				return err
			}
			if err := requireCanManageRoleAssignments(ctx, sc, vaultID, true, "assign_role"); err != nil {
				return err
			}
			callerRoles, _, err := vaultcli.CallerIdentity(ctx)
			if err != nil {
				return err
			}
			isGlobalAdmin := common.HasAnyRole(callerRoles, string(model.RoleAdmin))
			ra, err := sc.GetRoleAssignmentService().AssignRole(ctx, authz.AssignRoleInput{
				Principal:           principal,
				PrincipalType:       model.PrincipalType(ptype),
				Role:                role,
				VaultID:             vaultID,
				CreatedBy:           callerID,
				CallerIsGlobalAdmin: isGlobalAdmin,
			})
			if err != nil {
				return fmt.Errorf("grant failed: %w", err)
			}
			fmt.Fprintf(cmd.OutOrStdout(), "granted %s to %s in vault (assignment %s)\n", role, principal, ra.ID) //nolint:errcheck
			return nil
		},
	}
	cmd.Flags().String("role", "", "built-in role (see `vault-access roles`)")
	cmd.Flags().String("principal-type", "user", "principal type: user or service_account")
	vaultcli.AddVaultFlag(cmd)
	parent.AddCommand(cmd)
}
