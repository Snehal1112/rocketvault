package vaults

import (
	"bytes"
	"context"
	"fmt"
	"testing"

	"github.com/google/uuid"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"rocketvault/cmd/testutils"
	"rocketvault/common"
	"rocketvault/internal/formatter"
	authzServices "rocketvault/internal/services/authorization"
	vaultServices "rocketvault/internal/services/vaults"
	"rocketvault/model"
)

// ctxWithFormatter adds a table formatter to the test context so commands that
// write tabular output do not fail with "output formatter not available".
func ctxWithFormatter(ctx context.Context) context.Context {
	fmtr, _ := formatter.New(formatter.FormatTable)
	return context.WithValue(ctx, common.OutputFormatterKey, fmtr)
}

func TestVaultsCreateRequiresName(t *testing.T) {
	tc := testutils.NewTestContext(t)

	cmd := &cobra.Command{Use: "create", Args: createCmd.Args, RunE: createCmd.RunE}
	cmd.Flags().Bool("purge-protection", false, "")
	cmd.Flags().Int("retention-days", 0, "")

	cmd.SetContext(ctxWithFormatter(tc.Ctx))
	cmd.SetArgs([]string{})

	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)

	err := cmd.Execute()
	require.Error(t, err)
}

func TestVaultsCreate(t *testing.T) {
	tc := testutils.NewTestContext(t)

	created := &model.Vault{
		ID:            uuid.New(),
		Name:          "my-vault",
		Enabled:       true,
		RetentionDays: 90,
	}
	tc.MockVaultService.On("CreateVaultProvisioned", mock.Anything, mock.MatchedBy(func(r model.CreateVaultRequest) bool {
		return r.Name == "my-vault"
	}), tc.TestUserID, false, false).Return(created, nil)

	cmd := &cobra.Command{Use: "create", RunE: createCmd.RunE}
	cmd.Flags().Bool("purge-protection", false, "")
	cmd.Flags().Int("retention-days", 0, "")

	cmd.SetContext(ctxWithFormatter(tc.Ctx))
	cmd.SetArgs([]string{"my-vault"})

	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)

	err := cmd.Execute()
	require.NoError(t, err)
	assert.Contains(t, out.String(), "my-vault")
	tc.MockVaultService.AssertExpectations(t)
}

func TestVaultsList(t *testing.T) {
	tc := testutils.NewTestContext(t)

	seeded := []model.Vault{
		{ID: uuid.New(), Name: "default", Enabled: true, RetentionDays: 90},
		{ID: uuid.New(), Name: "my-vault", Enabled: true, RetentionDays: 30},
	}
	tc.MockVaultService.On("ListVaultsScoped", mock.Anything, tc.TestUserID, false, true).Return(seeded, nil)

	cmd := &cobra.Command{Use: "list", RunE: listCmd.RunE}
	cmd.Flags().Bool("include-deleted", false, "")

	cmd.SetContext(ctxWithFormatter(tc.Ctx))
	cmd.SetArgs([]string{})

	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)

	err := cmd.Execute()
	require.NoError(t, err)
	output := out.String()
	assert.Contains(t, output, "my-vault")
	assert.Contains(t, output, "default")
	tc.MockVaultService.AssertExpectations(t)
}

func TestVaultsGet(t *testing.T) {
	tc := testutils.NewTestContext(t)

	tc.MockVaultService.On("ListVaults", mock.Anything, true).
		Return([]model.Vault{{ID: uuid.New(), Name: "my-vault"}}, nil)
	v := &model.Vault{ID: uuid.New(), Name: "my-vault", Enabled: true, RetentionDays: 90}
	tc.MockVaultService.On("GetVault", mock.Anything, "my-vault").Return(v, nil)

	cmd := &cobra.Command{Use: "get", Args: cobra.ExactArgs(1), RunE: getCmd.RunE}
	cmd.SetContext(ctxWithFormatter(tc.Ctx))
	cmd.SetArgs([]string{"my-vault"})

	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)

	err := cmd.Execute()
	require.NoError(t, err)
	assert.Contains(t, out.String(), "my-vault")
	tc.MockVaultService.AssertExpectations(t)
}

func TestVaultsDelete(t *testing.T) {
	tc := testutils.NewTestContext(t)

	tc.MockVaultService.On("ListVaults", mock.Anything, true).
		Return([]model.Vault{{ID: uuid.New(), Name: "my-vault"}}, nil)
	tc.MockVaultService.On("DeleteVault", mock.Anything, "my-vault").Return(nil)

	cmd := &cobra.Command{Use: "delete", Args: cobra.ExactArgs(1), RunE: deleteCmd.RunE}
	cmd.SetContext(tc.Ctx)
	cmd.SetArgs([]string{"my-vault"})

	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)

	err := cmd.Execute()
	require.NoError(t, err)
	assert.Contains(t, out.String(), "deleted successfully")
	tc.MockVaultService.AssertExpectations(t)
}

func TestVaultsUpdate(t *testing.T) {
	tc := testutils.NewTestContext(t)

	tc.MockVaultService.On("ListVaults", mock.Anything, true).
		Return([]model.Vault{{ID: uuid.New(), Name: "my-vault"}}, nil)
	updated := &model.Vault{ID: uuid.New(), Name: "my-vault", Enabled: false, RetentionDays: 90}
	tc.MockVaultService.On("UpdateVault", mock.Anything, "my-vault", mock.MatchedBy(func(r model.UpdateVaultRequest) bool {
		return r.Enabled != nil && !*r.Enabled
	}), tc.TestUserID).Return(updated, nil)

	cmd := &cobra.Command{Use: "update", Args: updateCmd.Args, RunE: updateCmd.RunE}
	cmd.Flags().Bool("enabled", true, "")
	cmd.Flags().Bool("purge-protection", false, "")
	cmd.Flags().Int("retention-days", 0, "")

	cmd.SetContext(ctxWithFormatter(tc.Ctx))
	cmd.SetArgs([]string{"my-vault", "--enabled=false"})

	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)

	err := cmd.Execute()
	require.NoError(t, err)
	assert.Contains(t, out.String(), "my-vault")
	tc.MockVaultService.AssertExpectations(t)
}

// mockAccessPolicyService is a minimal test double for authzServices.AccessPolicyService.
type mockAccessPolicyService struct {
	decision authzServices.AccessDecision
}

func (m *mockAccessPolicyService) CheckAccess(context.Context, uuid.UUID, model.PolicyResourceType, model.PolicyOperation, uuid.UUID) (authzServices.AccessDecision, error) {
	return m.decision, nil
}
func (m *mockAccessPolicyService) CheckVaultScopedAccess(context.Context, uuid.UUID, model.PolicyResourceType, model.PolicyOperation, uuid.UUID) (authzServices.AccessDecision, error) {
	return m.decision, nil
}
func (m *mockAccessPolicyService) CreatePolicy(context.Context, *model.AccessPolicy) error {
	return nil
}
func (m *mockAccessPolicyService) GetPolicy(context.Context, uuid.UUID) (*model.AccessPolicy, error) {
	return nil, nil
}
func (m *mockAccessPolicyService) ListPolicies(context.Context) ([]*model.AccessPolicy, error) {
	return nil, nil
}
func (m *mockAccessPolicyService) ListByPrincipal(context.Context, uuid.UUID) ([]*model.AccessPolicy, error) {
	return nil, nil
}
func (m *mockAccessPolicyService) UpdatePolicy(context.Context, *model.AccessPolicy) error {
	return nil
}
func (m *mockAccessPolicyService) DeletePolicy(context.Context, uuid.UUID) error { return nil }

// TestVaultsCreate_ForbiddenWithoutGlobalGrant proves a non-admin with no
// global vaults:manage policy cannot create a vault via the CLI.
func TestVaultsCreate_ForbiddenWithoutGlobalGrant(t *testing.T) {
	tc := testutils.NewTestContext(t)
	nonAdminCtx := context.WithValue(tc.Ctx, common.ClaimsKey, &model.Claims{UserID: tc.TestUserID, Roles: []string{model.RoleUser}})

	policySvc := &mockAccessPolicyService{decision: authzServices.AccessFallback}
	tc.MockContainer.AccessPolicyService = policySvc

	cmd := &cobra.Command{Use: "create", Args: createCmd.Args, RunE: createCmd.RunE}
	cmd.Flags().Bool("purge-protection", false, "")
	cmd.Flags().Int("retention-days", 0, "")
	cmd.SetContext(ctxWithFormatter(nonAdminCtx))
	cmd.SetArgs([]string{"newvault"})

	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)

	err := cmd.Execute()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "permission denied")
	tc.MockVaultService.AssertNotCalled(t, "CreateVaultProvisioned", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything)
}

// TestVaultsCreate_QuotaExceededRefusesGrantHolder proves the CLI actually
// bounds a provisioning-grant holder's create by their quota. Before this
// fix, requireCanCreateVault computed the CreateRight and its only caller
// (createCmd) discarded it, always calling the unbounded CreateVault -- so a
// grant holder's create never reached the quota-bounded path at all, no
// matter what the service would have returned. Asserting the mock is called
// with quotaBounded=true (the 4th argument) is the CLI-side proof that
// bypass is closed: if createCmd still called CreateVault (or called
// CreateVaultProvisioned with quotaBounded=false), this mock expectation
// would go unmatched and testify would panic on the unexpected call,
// failing the test. The quota-enforcement logic itself (the actual row-lock
// count check) is proven against a real database in
// internal/services/vaults/vault_provisioned_create_test.go -- this test is
// only about the CLI wiring the right through correctly.
func TestVaultsCreate_QuotaExceededRefusesGrantHolder(t *testing.T) {
	tc := testutils.NewTestContext(t)
	nonAdminCtx := context.WithValue(tc.Ctx, common.ClaimsKey,
		&model.Claims{UserID: tc.TestUserID, Roles: []string{model.RoleUser}})

	policySvc := &mockAccessPolicyService{decision: authzServices.AccessFallback}
	tc.MockContainer.AccessPolicyService = policySvc
	tc.MockContainer.GrantService = &fakeGrantService{
		grant: &model.VaultProvisioningGrant{ID: uuid.New(), PrincipalID: tc.TestUserID, Quota: 1},
	}

	tc.MockVaultService.On("CreateVaultProvisioned", mock.Anything, mock.Anything, tc.TestUserID, true, true).
		Return(nil, fmt.Errorf("%w: 1 of 1 used", vaultServices.ErrVaultQuotaExceeded))

	cmd := &cobra.Command{Use: "create", Args: createCmd.Args, RunE: createCmd.RunE}
	cmd.Flags().Bool("purge-protection", false, "")
	cmd.Flags().Int("retention-days", 0, "")
	cmd.SetContext(ctxWithFormatter(nonAdminCtx))
	cmd.SetArgs([]string{"one-too-many"})

	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)

	err := cmd.Execute()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "quota")
	tc.MockVaultService.AssertExpectations(t)
}

// TestVaultsCreate_PurgeProtectionRefusedForGrantHolder proves a
// provisioning-grant holder cannot set --purge-protection via the CLI --
// mirroring the HTTP handler's ErrPurgeProtectionNotPermitted mapping. A
// grantee who could pin purge_protection could soft-delete the vault and
// hold the quota slot forever, since PurgeVault refuses a protected vault.
// Like the quota test above, the mock only accepts quotaBounded=true, so
// this also proves createCmd threads the right through rather than
// discarding it.
func TestVaultsCreate_PurgeProtectionRefusedForGrantHolder(t *testing.T) {
	tc := testutils.NewTestContext(t)
	nonAdminCtx := context.WithValue(tc.Ctx, common.ClaimsKey,
		&model.Claims{UserID: tc.TestUserID, Roles: []string{model.RoleUser}})

	policySvc := &mockAccessPolicyService{decision: authzServices.AccessFallback}
	tc.MockContainer.AccessPolicyService = policySvc
	tc.MockContainer.GrantService = &fakeGrantService{
		grant: &model.VaultProvisioningGrant{ID: uuid.New(), PrincipalID: tc.TestUserID, Quota: 5},
	}

	tc.MockVaultService.On("CreateVaultProvisioned", mock.Anything, mock.Anything, tc.TestUserID, true, true).
		Return(nil, vaultServices.ErrPurgeProtectionNotPermitted)

	cmd := &cobra.Command{Use: "create", Args: createCmd.Args, RunE: createCmd.RunE}
	cmd.Flags().Bool("purge-protection", false, "")
	cmd.Flags().Int("retention-days", 0, "")
	cmd.SetContext(ctxWithFormatter(nonAdminCtx))
	cmd.SetArgs([]string{"pinned", "--purge-protection=true"})

	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)

	err := cmd.Execute()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "purge protection")
	tc.MockVaultService.AssertExpectations(t)
}

// TestVaultsCreate_ReservedNameSurfacesError proves the CLI reports the
// service's reserved-name refusal instead of swallowing it (B80).
func TestVaultsCreate_ReservedNameSurfacesError(t *testing.T) {
	tc := testutils.NewTestContext(t)

	tc.MockVaultService.On("CreateVaultProvisioned", mock.Anything, mock.MatchedBy(func(r model.CreateVaultRequest) bool {
		return r.Name == "login"
	}), tc.TestUserID, false, false).Return(nil, fmt.Errorf("%w: %q is reserved", model.ErrReservedVaultName, "login"))

	cmd := &cobra.Command{Use: "create", RunE: createCmd.RunE}
	cmd.Flags().Bool("purge-protection", false, "")
	cmd.Flags().Int("retention-days", 0, "")
	cmd.SetContext(ctxWithFormatter(tc.Ctx))
	cmd.SetArgs([]string{"login"})
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)

	err := cmd.Execute()
	require.ErrorIs(t, err, model.ErrReservedVaultName)
}
