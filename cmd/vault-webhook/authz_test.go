package vaultwebhook

import (
	"context"
	"testing"

	"github.com/google/uuid"
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

// nonAdminCtx returns the test context with the caller downgraded to a plain
// user holding the given access-policy service.
func nonAdminCtx(tc *testutils.TestContext, policySvc authzServices.AccessPolicyService) context.Context {
	tc.MockContainer.AccessPolicyService = policySvc
	return context.WithValue(tc.Ctx, common.ClaimsKey,
		&model.Claims{UserID: tc.TestUserID, Roles: []string{model.RoleUser}})
}

// TestRequireCanManageVault_DeniedWithoutGrant proves a non-admin with no
// vaults/manage policy is denied, and the denial message names the vault.
func TestRequireCanManageVault_DeniedWithoutGrant(t *testing.T) {
	tc := testutils.NewTestContext(t)
	ctx := nonAdminCtx(tc, &fakePolicySvc{decision: authzServices.AccessFallback})
	rec := &logtest.Recorder{}
	tc.MockContainer.GetLogger().SetAuditPersister(rec)

	principal, err := requireCanManageVault(ctx, tc.MockContainer, tc.TestVaultID, "prod")
	require.Error(t, err)
	row, ok := rec.Find("manage_vault_webhook", "denied")
	require.True(t, ok, "a refused CLI webhook change must be audited")
	assert.Equal(t, tc.TestUserID.String(), row.UserID)
	assert.Equal(t, uuid.Nil, principal, "a denied call must not hand back a principal to attribute")
	assert.Contains(t, err.Error(), "permission denied")
	assert.Contains(t, err.Error(), `"prod"`, "denial message must name the vault")
}

// TestRequireCanManageVault_AllowsAdmin proves the admin account role is
// always allowed, regardless of access-policy state.
func TestRequireCanManageVault_AllowsAdmin(t *testing.T) {
	tc := testutils.NewTestContext(t)
	// tc's default context already carries an admin-role claim.
	principal, err := requireCanManageVault(tc.Ctx, tc.MockContainer, tc.TestVaultID, "prod")
	require.NoError(t, err)
	// The returned principal is what the command attributes the change to in
	// the audit trail; uuid.Nil here would produce a record naming nobody.
	assert.NotEqual(t, uuid.Nil, principal, "an allowed call must return the acting principal")
}

// TestRequireCanManageVault_NoClaimsInContext proves a context with no claims
// returns an error, not a silent allow.
func TestRequireCanManageVault_NoClaimsInContext(t *testing.T) {
	tc := testutils.NewTestContext(t)
	ctx := context.Background() // no ClaimsKey set at all.

	principal, err := requireCanManageVault(ctx, tc.MockContainer, tc.TestVaultID, "prod")
	require.Error(t, err)
	assert.Equal(t, uuid.Nil, principal)
	assert.Contains(t, err.Error(), "authenticated claims not available")
}
