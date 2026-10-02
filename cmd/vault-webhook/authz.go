// Package vaultwebhook — authz.go provides the authorization check for the
// CLI vault-webhook commands (set/get/delete). The CLI calls the service
// layer directly and bypasses PolicyMiddleware entirely, so this is the only
// authorization enforcement point on this path -- a command that skips it
// bypasses authorization completely. It mirrors cmd/vault-access/authz.go,
// whose header comment records the privilege-escalation gap that arose from
// omitting exactly this check.
package vaultwebhook

import (
	"context"
	"fmt"

	"github.com/google/uuid"

	"rocketvault/cmd/vaultcli"
	"rocketvault/internal/container"
	authz "rocketvault/internal/services/authorization"
)

// requireCanManageVault authorizes a webhook-config operation on vaultID with
// the same primitive the HTTP handlers use, so CLI and API cannot drift.
//
// The CLI calls the service layer directly and bypasses PolicyMiddleware
// entirely, so this is the only authorization enforcement point on this path
// -- a command that skips it bypasses authorization completely.
//
// It returns the authorized principal's id so the caller can attribute the
// change in the audit trail. The CLI has no middleware to stamp an actor for
// it, so a command that discards this value produces an audit record naming
// nobody.
func requireCanManageVault(ctx context.Context, sc container.ServiceContainerInterface, vaultID uuid.UUID, vaultName string) (uuid.UUID, error) {
	roles, principalID, err := vaultcli.CallerIdentity(ctx)
	if err != nil {
		return uuid.Nil, err
	}
	if !authz.CanManageVault(ctx, roles, sc.GetAccessPolicyService(), principalID, vaultID) {
		err := fmt.Errorf("permission denied: managing webhook config for vault %q requires admin or vaults/manage", vaultName)
		// Audit the refusal under the same operation name the HTTP handler uses (B81).
		if logger := sc.GetLogger(); logger != nil {
			logger.LogAuditError(principalID.String(), "manage_vault_webhook", "denied", err.Error(), nil)
		}
		return uuid.Nil, err
	}
	return principalID, nil
}
