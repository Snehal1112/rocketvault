package authorization

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"

	"rocketvault/model"
)

// ErrDataPlaneDenied marks a data-plane authorization refusal: an explicit
// deny policy, or no role granting the action. Its text is "forbidden", so
// every message built on it keeps the "forbidden: ..." shape callers and
// tests already match. A lookup failure never wraps it.
var ErrDataPlaneDenied = errors.New("forbidden")

// ErrDataPlaneMisuse marks a data-plane check called with an empty resource
// type, operation or action, or a nil principal or vault. It is a caller bug,
// not a refusal, so it never wraps ErrDataPlaneDenied. The check still fails
// closed.
var ErrDataPlaneMisuse = errors.New("data-plane check called with incomplete arguments")

// ErrAuthorizationUnavailable marks a data-plane check that has no access
// policy or role assignment service to consult. It is a wiring bug, not a
// refusal, so it never wraps ErrDataPlaneDenied. The check still fails closed.
var ErrAuthorizationUnavailable = errors.New("authorization services are not available")

// RequireDataAction returns nil if principalID holds a role assignment in
// vaultID granting action, and an error otherwise. It is the CLI-callable
// equivalent of the role-assignment half of PolicyMiddleware's check (its
// "2. Deny-by-default for vault data-plane routes" step) and must stay
// behaviorally identical to it: no admin short-circuit. Data-plane access
// has none today, even over HTTP (unlike vault-management's CanManageVault/
// CanPurgeVault, which do short-circuit for the global admin role) — copying
// that idiom here would grant the CLI a bypass the HTTP API doesn't have.
//
// This function alone is NOT full parity with PolicyMiddleware: it doesn't
// check the access_policies explicit-deny override (PolicyMiddleware's
// step "1"), because that check needs a *policy operation*, a different unit
// than the *data action* this function's callers already have on hand, and
// needs AccessPolicyService, not RoleAssignmentService. RequireDataPlaneAccess
// wraps both steps in the correct order; this function is deliberately only
// the second one. Do not call this function directly from a CLI command or a
// handler; call RequireDataPlaneAccess or cmd/vaultcli.RequireDataAction.
func RequireDataAction(ctx context.Context, roles RoleAssignmentService, principalID, vaultID uuid.UUID, action model.DataAction) error {
	ok, err := roles.HasDataAction(ctx, principalID, vaultID, action)
	if err != nil {
		return fmt.Errorf("checking vault authorization: %w", err)
	}
	if !ok {
		return fmt.Errorf("%w: no role grants %s in this vault", ErrDataPlaneDenied, action)
	}
	return nil
}

// RequireDataPlaneAccess runs PolicyMiddleware's full two-stage data-plane
// check for one action in one vault: first the access_policies explicit-deny
// override, then the deny-by-default role-assignment check. It is the single
// implementation behind the CLI (cmd/vaultcli), handlers that need a second
// action beyond the one their route maps to, and the renewal scheduler, so
// the three cannot drift apart.
//
// It returns nil only when access is granted. Every other outcome is an
// error in one of four classes:
//   - A refusal (explicit deny, or no role grant) wraps ErrDataPlaneDenied.
//   - Incomplete arguments return ErrDataPlaneMisuse before any lookup.
//   - Nil services return ErrAuthorizationUnavailable before any lookup.
//   - A policy or role lookup failure is wrapped as is.
//
// Only the first class is a refusal; callers map the others to a server
// fault.
func RequireDataPlaneAccess(
	ctx context.Context,
	policies AccessPolicyService,
	roles RoleAssignmentService,
	principalID, vaultID uuid.UUID,
	resourceType model.PolicyResourceType,
	op model.PolicyOperation,
	action model.DataAction,
) error {
	if resourceType == "" || op == "" || action == "" || principalID == uuid.Nil || vaultID == uuid.Nil {
		return fmt.Errorf("%w: resource=%q op=%q action=%q principal=%s vault=%s",
			ErrDataPlaneMisuse, resourceType, op, action, principalID, vaultID)
	}
	if policies == nil || roles == nil {
		return ErrAuthorizationUnavailable
	}

	decision, err := policies.CheckAccess(ctx, principalID, resourceType, op, vaultID)
	if err != nil {
		return fmt.Errorf("checking access policy: %w", err)
	}
	if decision == AccessDenied {
		return fmt.Errorf("%w: access denied by an explicit access policy for %s", ErrDataPlaneDenied, action)
	}

	return RequireDataAction(ctx, roles, principalID, vaultID, action)
}
