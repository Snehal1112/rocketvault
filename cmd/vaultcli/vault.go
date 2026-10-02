package vaultcli

import (
	"context"
	"fmt"
	"strings"

	"github.com/google/uuid"
	"github.com/spf13/cobra"

	"rocketvault/common"
	"rocketvault/internal/container"
	"rocketvault/internal/services/authorization"
	"rocketvault/model"
)

// ResolveVaultID resolves the --vault selection to a vault id via the service container.
func ResolveVaultID(ctx context.Context, cmd *cobra.Command, sc container.ServiceContainerInterface) (uuid.UUID, error) {
	// A container wired without a vault service is a construction bug, but it
	// must surface as an error on the authorization path rather than a nil
	// dereference -- this call is the first thing every data-plane command
	// does, so a panic here is the least legible place for one.
	svc := sc.GetVaultService()
	if svc == nil {
		return uuid.Nil, fmt.Errorf("vault service not available")
	}

	name := common.ResolveVaultName(cmd)
	v, err := svc.GetVault(ctx, name)
	if err != nil {
		return uuid.Nil, fmt.Errorf("vault %q not found: %w", name, err)
	}
	return v.ID, nil
}

// RequireDataAction resolves the vault, then reproduces PolicyMiddleware's
// full two-stage check in order: (1) the access_policies explicit-deny
// override via AccessPolicyService.CheckAccess, (2) the deny-by-default
// role-assignment check via authorization.RequireDataAction. Returns the
// resolved vault ID on success so callers don't have to resolve twice.
//
// op is the model.PolicyOperation that a real HTTP request for this same
// logical command would resolve to via internal/middleware/middleware.go's
// resolvePolicy(method, path). It cannot be derived from action alone:
// several DataActions are deliberately coarser than PolicyOperation
// (ActionSecretsSet covers both create's OpCreate and update's OpSet), so
// callers must supply it explicitly. resourceType, unlike op, has no such
// ambiguity — it's derived internally from action's own string prefix.
func RequireDataAction(ctx context.Context, cmd *cobra.Command, sc container.ServiceContainerInterface, principalID uuid.UUID, action model.DataAction, op model.PolicyOperation) (uuid.UUID, error) {
	vaultID, err := ResolveVaultID(ctx, cmd, sc)
	if err != nil {
		return uuid.Nil, err
	}

	// One implementation for the CLI, HTTP handlers and the renewal
	// scheduler, so the two-stage order cannot drift between them.
	if err := authorization.RequireDataPlaneAccess(ctx, sc.GetAccessPolicyService(), sc.GetRoleAssignmentService(),
		principalID, vaultID, resourceTypeFromAction(action), op, action); err != nil {
		return uuid.Nil, err
	}
	return vaultID, nil
}

// resourceTypeFromAction derives the model.PolicyResourceType from action's
// own Microsoft.KeyVault/vaults/{secrets|keys|certificates}/... string
// content, mirroring internal/middleware/middleware.go's resolvePolicy path
// matching so the same (principal, resourceType, op, vault) triple is
// evaluated on both entry points.
func resourceTypeFromAction(action model.DataAction) model.PolicyResourceType {
	s := string(action)
	switch {
	case strings.Contains(s, "/secrets"):
		return model.PolicyResourceSecrets
	case strings.Contains(s, "/keys"):
		return model.PolicyResourceKeys
	case strings.Contains(s, "/certificates"):
		return model.PolicyResourceCertificates
	default:
		return ""
	}
}

// AddVaultFlag adds the --vault selection flag to a command. Commands under a
// group that does not inherit the root persistent flag need their own.
func AddVaultFlag(cmd *cobra.Command) {
	cmd.Flags().String("vault", "", "vault name (default: ROCKETVAULT_VAULT env, config, or \"default\")")
}
