// Package vaultaccess — authz.go provides the authorization check for the CLI
// role-assignment commands (grant/revoke), closing a privilege-escalation gap:
// these commands previously called RoleAssignmentService directly with no
// authorization check at all, so any authenticated principal could grant
// themselves any role in any vault. It mirrors cmd/vaults/authz.go.
package vaultaccess

import (
	"context"
	"fmt"

	"github.com/google/uuid"

	"rocketvault/cmd/vaultcli"
	"rocketvault/internal/container"
	authz "rocketvault/internal/services/authorization"
)

// requireCanManageRoleAssignments authorizes granting (write=true) or revoking
// (write=false) a role assignment in vaultID, using the same shared primitive
// as the HTTP handlers so CLI and API cannot drift apart. A refusal is
// audited under operation, matching the HTTP handler's row.
func requireCanManageRoleAssignments(ctx context.Context, sc container.ServiceContainerInterface, vaultID uuid.UUID, write bool, operation string) error {
	roles, principalID, err := vaultcli.CallerIdentity(ctx)
	if err != nil {
		return err
	}
	if !authz.CanManageRoleAssignments(ctx, roles, sc.GetAccessPolicyService(), sc.GetRoleAssignmentService(), principalID, vaultID, write) {
		err := fmt.Errorf("permission denied: admin, vaults/manage, or Key Vault Data Access Administrator required for this vault")
		if logger := sc.GetLogger(); logger != nil {
			logger.LogAuditError(principalID.String(), operation, "denied", err.Error(), nil)
		}
		return err
	}
	return nil
}
