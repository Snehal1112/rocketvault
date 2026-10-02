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

// TestRequireDataPlaneAccess_NilServicesFailClosed pins that a missing
// service fails closed as a wiring fault, not as a refusal.
func TestRequireDataPlaneAccess_NilServicesFailClosed(t *testing.T) {
	cases := []struct {
		name     string
		policies AccessPolicyService
		roles    RoleAssignmentService
	}{
		{"both nil", nil, nil},
		{"nil roles", &fakeAccessPolicyService{decision: AccessFallback}, nil},
		{"nil policies", nil, &fakeRoleAssignmentService{hasAction: true}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := RequireDataPlaneAccess(context.Background(), tc.policies, tc.roles, uuid.New(), uuid.New(),
				model.PolicyResourceKeys, model.OpSign, model.ActionKeysSign)
			require.ErrorIs(t, err, ErrAuthorizationUnavailable)
			require.NotErrorIs(t, err, ErrDataPlaneDenied, "a wiring fault is not a refusal")
		})
	}
}

// countingPolicyService records whether CheckAccess ran.
type countingPolicyService struct {
	fakeAccessPolicyService
	calls int
}

func (c *countingPolicyService) CheckAccess(ctx context.Context, p uuid.UUID, r model.PolicyResourceType, o model.PolicyOperation, v uuid.UUID) (AccessDecision, error) {
	c.calls++
	return c.fakeAccessPolicyService.CheckAccess(ctx, p, r, o, v)
}

// TestRequireDataPlaneAccess_IncompleteArgumentsFailClosed pins that every
// empty or nil argument is refused as misuse before any service is called.
func TestRequireDataPlaneAccess_IncompleteArgumentsFailClosed(t *testing.T) {
	type args struct {
		principalID, vaultID uuid.UUID
		resourceType         model.PolicyResourceType
		op                   model.PolicyOperation
		action               model.DataAction
	}
	valid := func() args {
		return args{uuid.New(), uuid.New(), model.PolicyResourceKeys, model.OpSign, model.ActionKeysSign}
	}
	cases := map[string]func(*args){
		"empty resource type": func(a *args) { a.resourceType = "" },
		"empty op":            func(a *args) { a.op = "" },
		"empty action":        func(a *args) { a.action = "" },
		"nil principal":       func(a *args) { a.principalID = uuid.Nil },
		"nil vault":           func(a *args) { a.vaultID = uuid.Nil },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			a := valid()
			mutate(&a)
			policies := &countingPolicyService{fakeAccessPolicyService: fakeAccessPolicyService{decision: AccessFallback}}
			roles := &fakeRoleAssignmentService{hasAction: true}

			err := RequireDataPlaneAccess(context.Background(), policies, roles, a.principalID, a.vaultID,
				a.resourceType, a.op, a.action)
			require.ErrorIs(t, err, ErrDataPlaneMisuse)
			require.NotErrorIs(t, err, ErrDataPlaneDenied, "a caller bug is not a refusal")
			require.Zero(t, policies.calls, "no policy lookup may run")
			require.Empty(t, roles.calledAction, "no role lookup may run")
		})
	}

	// Misuse is reported even when the services are missing too.
	err := RequireDataPlaneAccess(context.Background(), nil, nil, uuid.Nil, uuid.Nil, "", "", "")
	require.ErrorIs(t, err, ErrDataPlaneMisuse)
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
