// Package vaults — authz.go provides shared authorization checks for the CLI
// vault-management commands (create/update/delete/recover/purge), closing a
// pre-existing gap: these commands previously called the service layer
// directly with no authorization check at all. See
// docs/superpowers/specs/2026-08-11-azure-role-parity-and-vault-authz-fix-design.md
// §7.
package vaults

import (
	"context"
	"fmt"

	"github.com/google/uuid"

	"rocketvault/cmd/vaultcli"
	"rocketvault/internal/container"
	authz "rocketvault/internal/services/authorization"
	vaultServices "rocketvault/internal/services/vaults"
)

// resolveTargetVaultID finds the ID of the vault named name, whether active
// or soft-deleted. VaultService.GetVault only returns active vaults, and
// recover/purge commonly target a soft-deleted one, so ListVaults(true) is
// used uniformly by every command in this file.
func resolveTargetVaultID(ctx context.Context, svc vaultServices.VaultService, name string) (uuid.UUID, error) {
	vaults, err := svc.ListVaults(ctx, true)
	if err != nil {
		return uuid.Nil, err
	}
	for _, v := range vaults {
		if v.Name == name {
			return v.ID, nil
		}
	}
	return uuid.Nil, vaultServices.ErrVaultNotFound
}

// requireCanCreateVault checks the three-way create decision: the global
// admin role, a global (not vault-specific) vaults:manage grant, or a bounded
// provisioning grant. There is no target vault to resolve yet when creating
// one, so this mirrors the HTTP createVault handler's use of CanCreateVault
// rather than a scoped check.
//
// The CLI bypasses PolicyMiddleware entirely, so this is the only
// authorization enforcement point on this path.
//
// The returned CreateRight is not incidental -- the caller MUST use it to
// decide whether the create is quota-bounded (CreateRightProvisioningGrant is
// the only bounded right; CreateRightAdmin and CreateRightGlobalPolicy are
// not) and pass that decision to VaultService.CreateVaultProvisioned. An
// earlier version of this function returned only an error, and its caller
// discarded the right entirely, always calling the unbounded CreateVault --
// letting a provisioning-grant holder create unlimited vaults, set
// purge_protection, and receive none of the creator's grants. Do not repeat
// that mistake: a caller that checks only "err == nil" and calls the
// unbounded path regardless reopens the same bypass.
func requireCanCreateVault(ctx context.Context, sc container.ServiceContainerInterface) (authz.CreateRight, error) {
	roles, principalID, err := vaultcli.CallerIdentity(ctx)
	if err != nil {
		return authz.CreateRightNone, err
	}
	right := authz.CanCreateVault(ctx, roles, sc.GetAccessPolicyService(), sc.GetGrantService(), principalID)
	if right == authz.CreateRightNone {
		return authz.CreateRightNone, fmt.Errorf("permission denied: admin, a global vaults/manage grant, or a vault provisioning grant required to create a vault")
	}
	return right, nil
}

// requireCanListVaults reports whether the caller may list vaults, and
// whether it may list them all. A global grant or the admin role lists
// everything; any other principal lists only vaults it holds scoped
// management over. Mirrors HTTP listVaults.
//
// The CLI bypasses PolicyMiddleware entirely, so this is the only
// authorization enforcement point on this path.
//
// Listing is no longer refused outright: a principal with no reachable vault
// gets an empty list, which is the same information a 403 would leak minus
// the confirmation that vaults exist.
func requireCanListVaults(ctx context.Context, sc container.ServiceContainerInterface) (bool, error) {
	roles, principalID, err := vaultcli.CallerIdentity(ctx)
	if err != nil {
		return false, err
	}
	if authz.CanManageVault(ctx, roles, sc.GetAccessPolicyService(), principalID, uuid.Nil) {
		return true, nil
	}
	return false, nil
}

// requireCanManageVault resolves vaultName to an ID, checks CanManageVault
// against it, and returns the caller's principal for audit attribution.
func requireCanManageVault(ctx context.Context, sc container.ServiceContainerInterface, vaultName string) (uuid.UUID, error) {
	roles, principalID, err := vaultcli.CallerIdentity(ctx)
	if err != nil {
		return uuid.Nil, err
	}
	vaultID, err := resolveTargetVaultID(ctx, sc.GetVaultService(), vaultName)
	if err != nil {
		return uuid.Nil, fmt.Errorf("resolve vault %q: %w", vaultName, err)
	}
	if !authz.CanManageVault(ctx, roles, sc.GetAccessPolicyService(), principalID, vaultID) {
		return uuid.Nil, fmt.Errorf("permission denied: admin or vaults/manage required for vault %q", vaultName)
	}
	return principalID, nil
}

// requireCanPurgeVault resolves vaultName to an ID, checks CanPurgeVault
// against it, and returns the caller's principal for audit attribution.
func requireCanPurgeVault(ctx context.Context, sc container.ServiceContainerInterface, vaultName string) (uuid.UUID, error) {
	roles, principalID, err := vaultcli.CallerIdentity(ctx)
	if err != nil {
		return uuid.Nil, err
	}
	vaultID, err := resolveTargetVaultID(ctx, sc.GetVaultService(), vaultName)
	if err != nil {
		return uuid.Nil, fmt.Errorf("resolve vault %q: %w", vaultName, err)
	}
	if !authz.CanPurgeVault(ctx, roles, sc.GetRoleAssignmentService(), principalID, vaultID) {
		return uuid.Nil, fmt.Errorf("permission denied: admin or Key Vault Purge Operator required for vault %q", vaultName)
	}
	return principalID, nil
}
