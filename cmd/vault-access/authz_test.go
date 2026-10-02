package vaultaccess

import (
	"bytes"
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"rocketvault/cmd/testutils"
	"rocketvault/common"
	"rocketvault/internal/logging/logtest"
	authzServices "rocketvault/internal/services/authorization"
	"rocketvault/model"
)

// fakePolicySvc is a minimal AccessPolicyService returning a fixed decision.
type fakePolicySvc struct {
	decision authzServices.AccessDecision
}

func (f *fakePolicySvc) CheckAccess(context.Context, uuid.UUID, model.PolicyResourceType, model.PolicyOperation, uuid.UUID) (authzServices.AccessDecision, error) {
	return f.decision, nil
}
func (f *fakePolicySvc) CheckVaultScopedAccess(context.Context, uuid.UUID, model.PolicyResourceType, model.PolicyOperation, uuid.UUID) (authzServices.AccessDecision, error) {
	return f.decision, nil
}
func (f *fakePolicySvc) CreatePolicy(context.Context, *model.AccessPolicy, uuid.UUID) error {
	return nil
}
func (f *fakePolicySvc) GetPolicy(context.Context, uuid.UUID) (*model.AccessPolicy, error) {
	return nil, nil
}
func (f *fakePolicySvc) ListPolicies(context.Context) ([]*model.AccessPolicy, error) {
	return nil, nil
}
func (f *fakePolicySvc) ListByPrincipal(context.Context, uuid.UUID) ([]*model.AccessPolicy, error) {
	return nil, nil
}
func (f *fakePolicySvc) UpdatePolicy(context.Context, *model.AccessPolicy, uuid.UUID) error {
	return nil
}
func (f *fakePolicySvc) DeletePolicy(context.Context, uuid.UUID, uuid.UUID) error { return nil }

// fakeRoleSvc is a minimal RoleAssignmentService that reports whether the
// mutating calls were reached, so a denial test can prove the gate ran first.
type fakeRoleSvc struct {
	hasAction                 bool
	assignCalled              bool
	revokeCalled              bool
	listCalled                bool
	actionsAsked              []model.DataAction
	assignedInput             authzServices.AssignRoleInput
	revokeCallerIsGlobalAdmin bool
	revokeActor               uuid.UUID
	assignErr                 error
	revokeErr                 error
}

func (f *fakeRoleSvc) AssignRole(_ context.Context, in authzServices.AssignRoleInput) (*model.RoleAssignment, error) {
	f.assignCalled = true
	f.assignedInput = in
	if f.assignErr != nil {
		return nil, f.assignErr
	}
	return &model.RoleAssignment{ID: uuid.New(), VaultID: in.VaultID, Role: in.Role}, nil
}

func (f *fakeRoleSvc) RevokeAssignment(_ context.Context, _, _ uuid.UUID, actorID uuid.UUID, callerIsGlobalAdmin bool) error {
	f.revokeCalled = true
	f.revokeActor = actorID
	f.revokeCallerIsGlobalAdmin = callerIsGlobalAdmin
	return f.revokeErr
}

func (f *fakeRoleSvc) ListAssignments(context.Context, uuid.UUID) ([]*model.RoleAssignment, error) {
	f.listCalled = true
	return nil, nil
}

func (f *fakeRoleSvc) HasDataAction(_ context.Context, _, _ uuid.UUID, action model.DataAction) (bool, error) {
	f.actionsAsked = append(f.actionsAsked, action)
	return f.hasAction, nil
}

// newVaultAccessCmd wires grant and revoke onto a fresh parent command bound to
// ctx, and returns the parent plus its captured output buffer.
func newVaultAccessCmd(ctx context.Context) (*cobra.Command, *bytes.Buffer) {
	parent := &cobra.Command{Use: "vault-access"}
	InitVaultAccessGrant(parent)
	InitVaultAccessRevoke(parent)
	InitVaultAccessList(parent)
	parent.SetContext(ctx)
	var out bytes.Buffer
	parent.SetOut(&out)
	parent.SetErr(&out)
	return parent, &out
}

// nonAdminCtx returns the test context with the caller downgraded to a plain
// user holding the given policy/role services.
func nonAdminCtx(tc *testutils.TestContext, policySvc authzServices.AccessPolicyService, roleSvc authzServices.RoleAssignmentService) context.Context {
	tc.MockContainer.AccessPolicyService = policySvc
	tc.MockContainer.RoleAssignmentService = roleSvc
	return context.WithValue(tc.Ctx, common.ClaimsKey,
		&model.Claims{UserID: tc.TestUserID, Roles: []string{model.RoleUser}})
}

// TestVaultAccessGrant_DeniedWithoutGrant is the privilege-escalation
// regression: before this fix, `vault-access grant` called AssignRole with no
// authorization check at all, so any authenticated user could grant themselves
// Key Vault Administrator in any vault.
func TestVaultAccessGrant_DeniedWithoutGrant(t *testing.T) {
	tc := testutils.NewTestContext(t)
	roleSvc := &fakeRoleSvc{hasAction: false}
	ctx := nonAdminCtx(tc, &fakePolicySvc{decision: authzServices.AccessFallback}, roleSvc)

	cmd, _ := newVaultAccessCmd(ctx)
	cmd.SetArgs([]string{"grant", "alice", "--role", model.RoleKeyVaultAdministrator})
	rec := &logtest.Recorder{}
	tc.MockContainer.GetLogger().SetAuditPersister(rec)

	err := cmd.Execute()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "permission denied")
	assert.False(t, roleSvc.assignCalled, "AssignRole must not be reached when the caller is denied")
	assert.Contains(t, roleSvc.actionsAsked, model.ActionRoleAssignmentsWrite)
	row, ok := rec.Find("assign_role", "denied")
	require.True(t, ok, "a refused CLI grant must be audited")
	assert.Equal(t, tc.TestUserID.String(), row.UserID)
}

// TestVaultAccessRevoke_DeniedWithoutGrant mirrors the grant case: revoking
// another principal's role is equally a privileged operation.
func TestVaultAccessRevoke_DeniedWithoutGrant(t *testing.T) {
	tc := testutils.NewTestContext(t)
	roleSvc := &fakeRoleSvc{hasAction: false}
	ctx := nonAdminCtx(tc, &fakePolicySvc{decision: authzServices.AccessFallback}, roleSvc)

	cmd, _ := newVaultAccessCmd(ctx)
	cmd.SetArgs([]string{"revoke", uuid.New().String()})

	err := cmd.Execute()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "permission denied")
	assert.False(t, roleSvc.revokeCalled, "RevokeAssignment must not be reached when the caller is denied")
	assert.Contains(t, roleSvc.actionsAsked, model.ActionRoleAssignmentsDelete)
}

// TestVaultAccessGrant_NotGrantableRefusalIsAudited covers the service-level
// refusal: the HTTP handler audits it, so the CLI must too.
func TestVaultAccessGrant_NotGrantableRefusalIsAudited(t *testing.T) {
	tc := testutils.NewTestContext(t)
	roleSvc := &fakeRoleSvc{hasAction: true, assignErr: authzServices.ErrRoleNotGrantable}
	ctx := nonAdminCtx(tc, &fakePolicySvc{decision: authzServices.AccessFallback}, roleSvc)
	rec := &logtest.Recorder{}
	tc.MockContainer.GetLogger().SetAuditPersister(rec)

	cmd, _ := newVaultAccessCmd(ctx)
	cmd.SetArgs([]string{"grant", "alice", "--role", model.RoleKeyVaultAdministrator})

	err := cmd.Execute()
	require.ErrorIs(t, err, authzServices.ErrRoleNotGrantable)
	assert.Contains(t, err.Error(), "grant failed")
	row, ok := rec.Find("assign_role", "denied")
	require.True(t, ok, "a not-grantable CLI grant must be audited")
	assert.Equal(t, tc.TestUserID.String(), row.UserID)
}

// TestVaultAccessRevoke_NotGrantableRefusalIsAudited mirrors the grant case.
func TestVaultAccessRevoke_NotGrantableRefusalIsAudited(t *testing.T) {
	tc := testutils.NewTestContext(t)
	roleSvc := &fakeRoleSvc{hasAction: true, revokeErr: authzServices.ErrRoleNotGrantable}
	ctx := nonAdminCtx(tc, &fakePolicySvc{decision: authzServices.AccessFallback}, roleSvc)
	rec := &logtest.Recorder{}
	tc.MockContainer.GetLogger().SetAuditPersister(rec)

	cmd, _ := newVaultAccessCmd(ctx)
	cmd.SetArgs([]string{"revoke", uuid.New().String()})

	err := cmd.Execute()
	require.ErrorIs(t, err, authzServices.ErrRoleNotGrantable)
	assert.Contains(t, err.Error(), "revoke failed")
	row, ok := rec.Find("revoke_role_assignment", "denied")
	require.True(t, ok, "a not-revocable CLI revoke must be audited")
	assert.Equal(t, tc.TestUserID.String(), row.UserID)
}

// TestVaultAccessGrant_AllowedForDataAccessAdministrator proves the gate is
// not blanket-deny: a non-admin holding Key Vault Data Access Administrator in
// the target vault can still grant roles there.
func TestVaultAccessGrant_AllowedForDataAccessAdministrator(t *testing.T) {
	tc := testutils.NewTestContext(t)
	roleSvc := &fakeRoleSvc{hasAction: true}
	ctx := nonAdminCtx(tc, &fakePolicySvc{decision: authzServices.AccessFallback}, roleSvc)

	cmd, out := newVaultAccessCmd(ctx)
	cmd.SetArgs([]string{"grant", "alice", "--role", model.RoleKeyVaultSecretsUser})

	require.NoError(t, cmd.Execute())
	assert.True(t, roleSvc.assignCalled)
	assert.Equal(t, "alice", roleSvc.assignedInput.Principal)
	assert.Contains(t, out.String(), "granted")
}

// TestVaultAccessRevoke_AllowedForDataAccessAdministrator mirrors the grant
// case for revocation.
func TestVaultAccessRevoke_AllowedForDataAccessAdministrator(t *testing.T) {
	tc := testutils.NewTestContext(t)
	roleSvc := &fakeRoleSvc{hasAction: true}
	ctx := nonAdminCtx(tc, &fakePolicySvc{decision: authzServices.AccessFallback}, roleSvc)

	cmd, out := newVaultAccessCmd(ctx)
	cmd.SetArgs([]string{"revoke", uuid.New().String()})

	require.NoError(t, cmd.Execute())
	assert.True(t, roleSvc.revokeCalled)
	assert.Contains(t, out.String(), "revoked assignment")
}

// TestVaultAccessRevoke_PassesNonAdminCallerFlag proves `vault-access revoke`
// computes callerIsGlobalAdmin from the CLI session's account role and passes
// it through to RevokeAssignment (B21), the same signal grant.go already
// passes as AssignRoleInput.CallerIsGlobalAdmin -- the enforcement itself is
// tested at the service layer (role_assignment_service_test.go); this proves
// the CLI wiring reaches it.
func TestVaultAccessRevoke_PassesNonAdminCallerFlag(t *testing.T) {
	tc := testutils.NewTestContext(t)
	roleSvc := &fakeRoleSvc{hasAction: true}
	ctx := nonAdminCtx(tc, &fakePolicySvc{decision: authzServices.AccessFallback}, roleSvc)

	cmd, _ := newVaultAccessCmd(ctx)
	cmd.SetArgs([]string{"revoke", uuid.New().String()})

	require.NoError(t, cmd.Execute())
	require.True(t, roleSvc.revokeCalled)
	assert.False(t, roleSvc.revokeCallerIsGlobalAdmin, "a plain user's revoke must not carry the global-admin bypass")
	assert.Equal(t, tc.TestUserID, roleSvc.revokeActor, "the CLI must pass the caller as the audit actor")
}

// TestVaultAccessList_DeniedWithoutGrant is the CLI twin of the HTTP
// listRoleAssignments regression: before this fix, `vault-access list` called
// ListAssignments with no authorization check at all, so any authenticated
// user could enumerate who holds which role in any vault.
func TestVaultAccessList_DeniedWithoutGrant(t *testing.T) {
	tc := testutils.NewTestContext(t)
	roleSvc := &fakeRoleSvc{hasAction: false}
	ctx := nonAdminCtx(tc, &fakePolicySvc{decision: authzServices.AccessFallback}, roleSvc)

	cmd, _ := newVaultAccessCmd(ctx)
	cmd.SetArgs([]string{"list"})

	err := cmd.Execute()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "permission denied")
	assert.False(t, roleSvc.listCalled, "ListAssignments must not be reached when the caller is denied")
	assert.Contains(t, roleSvc.actionsAsked, model.ActionRoleAssignmentsDelete)
}

// TestVaultAccessList_AllowedForDataAccessAdministrator mirrors the grant/revoke
// allow case: a non-admin holding Key Vault Data Access Administrator in the
// target vault can still list its role assignments.
func TestVaultAccessList_AllowedForDataAccessAdministrator(t *testing.T) {
	tc := testutils.NewTestContext(t)
	roleSvc := &fakeRoleSvc{hasAction: true}
	ctx := nonAdminCtx(tc, &fakePolicySvc{decision: authzServices.AccessFallback}, roleSvc)

	cmd, out := newVaultAccessCmd(ctx)
	cmd.SetArgs([]string{"list"})

	require.NoError(t, cmd.Execute())
	assert.True(t, roleSvc.listCalled)
	assert.Contains(t, out.String(), "ASSIGNMENT-ID")
}

// TestVaultAccessGrant_ExplicitDenyBeatsRoleGrant proves the deny-wins rule
// reaches the CLI too: an explicit deny access-policy is not outvoted by a
// Data Access Administrator role assignment.
func TestVaultAccessGrant_ExplicitDenyBeatsRoleGrant(t *testing.T) {
	tc := testutils.NewTestContext(t)
	roleSvc := &fakeRoleSvc{hasAction: true}
	ctx := nonAdminCtx(tc, &fakePolicySvc{decision: authzServices.AccessDenied}, roleSvc)

	cmd, _ := newVaultAccessCmd(ctx)
	cmd.SetArgs([]string{"grant", "alice", "--role", model.RoleKeyVaultSecretsUser})

	err := cmd.Execute()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "permission denied")
	assert.False(t, roleSvc.assignCalled)
}
