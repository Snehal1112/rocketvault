package authorization

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"rocketvault/model"
)

func TestRequireDataPlaneAccess_ExplicitDenyWinsOverRoleGrant(t *testing.T) {
	policies := &fakeAccessPolicyService{decision: AccessDenied}
	roles := &fakeRoleAssignmentService{hasAction: true}

	err := RequireDataPlaneAccess(context.Background(), policies, roles, uuid.New(), uuid.New(),
		model.PolicyResourceKeys, model.OpSign, model.ActionKeysSign)
	require.ErrorIs(t, err, ErrDataPlaneDenied)
	require.Contains(t, err.Error(), "explicit access policy")
	require.Equal(t, "forbidden: access denied by an explicit access policy for "+string(model.ActionKeysSign), err.Error())
	require.Empty(t, roles.calledAction, "an explicit deny must short-circuit the role check")
}

func TestRequireDataPlaneAccess_NoRoleGrantIsDenied(t *testing.T) {
	policies := &fakeAccessPolicyService{decision: AccessFallback}
	roles := &fakeRoleAssignmentService{hasAction: false}

	err := RequireDataPlaneAccess(context.Background(), policies, roles, uuid.New(), uuid.New(),
		model.PolicyResourceKeys, model.OpSign, model.ActionKeysSign)
	require.ErrorIs(t, err, ErrDataPlaneDenied)
	require.Contains(t, err.Error(), "forbidden: no role grants")
}

// TestRequireDataPlaneAccess_PolicyAllowDoesNotGrant pins that an access
// policy allow is not a grant: the role check still decides.
func TestRequireDataPlaneAccess_PolicyAllowDoesNotGrant(t *testing.T) {
	policies := &fakeAccessPolicyService{decision: AccessAllowed}
	roles := &fakeRoleAssignmentService{hasAction: false}

	err := RequireDataPlaneAccess(context.Background(), policies, roles, uuid.New(), uuid.New(),
		model.PolicyResourceKeys, model.OpSign, model.ActionKeysSign)
	require.ErrorIs(t, err, ErrDataPlaneDenied)
}

func TestRequireDataPlaneAccess_GrantPassesAndForwardsArguments(t *testing.T) {
	policies := &fakeAccessPolicyService{decision: AccessFallback}
	roles := &fakeRoleAssignmentService{hasAction: true}
	principalID, vaultID := uuid.New(), uuid.New()

	err := RequireDataPlaneAccess(context.Background(), policies, roles, principalID, vaultID,
		model.PolicyResourceKeys, model.OpSign, model.ActionKeysSign)
	require.NoError(t, err)
	require.Equal(t, principalID, roles.calledPrincipalID)
	require.Equal(t, vaultID, roles.calledVaultID)
	require.Equal(t, model.ActionKeysSign, roles.calledAction)
}

func TestRequireDataPlaneAccess_NilServicesFailClosed(t *testing.T) {
	err := RequireDataPlaneAccess(context.Background(), nil, nil, uuid.New(), uuid.New(),
		model.PolicyResourceKeys, model.OpSign, model.ActionKeysSign)
	require.ErrorIs(t, err, ErrDataPlaneDenied)

	err = RequireDataPlaneAccess(context.Background(), &fakeAccessPolicyService{decision: AccessFallback}, nil,
		uuid.New(), uuid.New(), model.PolicyResourceKeys, model.OpSign, model.ActionKeysSign)
	require.ErrorIs(t, err, ErrDataPlaneDenied)

	err = RequireDataPlaneAccess(context.Background(), nil, &fakeRoleAssignmentService{hasAction: true},
		uuid.New(), uuid.New(), model.PolicyResourceKeys, model.OpSign, model.ActionKeysSign)
	require.ErrorIs(t, err, ErrDataPlaneDenied)
}

func TestRequireDataPlaneAccess_PolicyLookupErrorIsNotADenial(t *testing.T) {
	lookup := errors.New("db exploded")
	policies := &fakeAccessPolicyService{err: lookup}
	roles := &fakeRoleAssignmentService{hasAction: true}

	err := RequireDataPlaneAccess(context.Background(), policies, roles, uuid.New(), uuid.New(),
		model.PolicyResourceKeys, model.OpSign, model.ActionKeysSign)
	require.ErrorIs(t, err, lookup)
	require.NotErrorIs(t, err, ErrDataPlaneDenied, "a lookup failure is a server fault, not a 403")
	require.Empty(t, roles.calledAction, "a policy lookup failure must not fall through to the role check")
}

// TestRequireDataPlaneAccess_RoleLookupErrorIsNotADenial pins that a role
// lookup failure is neither an allow nor a refusal, even when the lookup
// also reports the action as granted.
func TestRequireDataPlaneAccess_RoleLookupErrorIsNotADenial(t *testing.T) {
	lookup := errors.New("role table exploded")
	policies := &fakeAccessPolicyService{decision: AccessFallback}
	roles := &fakeRoleAssignmentService{hasAction: true, err: lookup}

	err := RequireDataPlaneAccess(context.Background(), policies, roles, uuid.New(), uuid.New(),
		model.PolicyResourceKeys, model.OpSign, model.ActionKeysSign)
	require.ErrorIs(t, err, lookup)
	require.NotErrorIs(t, err, ErrDataPlaneDenied, "a lookup failure is a server fault, not a 403")
}

func TestRequireDataAction_DenialWrapsSentinel(t *testing.T) {
	roles := &fakeRoleAssignmentService{hasAction: false}
	err := RequireDataAction(context.Background(), roles, uuid.New(), uuid.New(), model.ActionKeysSign)
	require.ErrorIs(t, err, ErrDataPlaneDenied)
	require.Equal(t, "forbidden: no role grants "+string(model.ActionKeysSign)+" in this vault", err.Error())
}
