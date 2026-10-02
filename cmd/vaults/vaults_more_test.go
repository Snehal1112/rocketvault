package vaults

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"testing"

	"github.com/google/uuid"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"rocketvault/cmd/testutils"
	"rocketvault/common"
	"rocketvault/internal/logging/logtest"
	authzServices "rocketvault/internal/services/authorization"
	"rocketvault/model"
)

// TestMain registers all Init* functions once to cover their registration
// statements, then delegates to the standard test runner.
func TestMain(m *testing.M) {
	parent := &cobra.Command{Use: "vaults"}
	InitVaultsCreate(parent)
	InitVaultsDelete(parent)
	InitVaultsGet(parent)
	InitVaultsList(parent)
	InitVaultsPurge(parent)
	InitVaultsRecover(parent)
	InitVaultsUpdate(parent)
	os.Exit(m.Run())
}

// ---- helpers ----

func newVltCmd(runE func(*cobra.Command, []string) error, args []string) (*cobra.Command, *bytes.Buffer) {
	cmd := &cobra.Command{Use: "test", RunE: runE}
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	cmd.SetArgs(args)
	return cmd, &buf
}

// ---- purgeCmd tests ----

func TestPurgeCmd_Success(t *testing.T) {
	tc := testutils.NewTestContext(t)
	tc.MockVaultService.On("ListVaults", mock.Anything, true).
		Return([]model.Vault{{ID: uuid.New(), Name: "my-vault"}}, nil)
	tc.MockVaultService.On("PurgeVault", mock.Anything, "my-vault", tc.TestUserID).Return(nil)

	cmd, buf := newVltCmd(purgeCmd.RunE, []string{"my-vault"})
	cmd.Args = cobra.ExactArgs(1)
	cmd.SetContext(ctxWithFormatter(tc.Ctx))

	err := cmd.Execute()
	require.NoError(t, err)
	assert.Contains(t, buf.String(), "purged successfully")
	tc.MockVaultService.AssertExpectations(t)
}

func TestPurgeCmd_ServiceError(t *testing.T) {
	tc := testutils.NewTestContext(t)
	tc.MockVaultService.On("ListVaults", mock.Anything, true).
		Return([]model.Vault{{ID: uuid.New(), Name: "my-vault"}}, nil)
	tc.MockVaultService.On("PurgeVault", mock.Anything, "my-vault", tc.TestUserID).
		Return(fmt.Errorf("cannot purge"))

	cmd, _ := newVltCmd(purgeCmd.RunE, []string{"my-vault"})
	cmd.Args = cobra.ExactArgs(1)
	cmd.SetContext(ctxWithFormatter(tc.Ctx))

	err := cmd.Execute()
	assert.ErrorContains(t, err, "failed to purge vault")
	tc.MockVaultService.AssertExpectations(t)
}

// ---- recoverCmd tests ----

func TestRecoverCmd_Success(t *testing.T) {
	tc := testutils.NewTestContext(t)
	tc.MockVaultService.On("ListVaults", mock.Anything, true).
		Return([]model.Vault{{ID: uuid.New(), Name: "my-vault"}}, nil)
	tc.MockVaultService.On("RecoverVault", mock.Anything, "my-vault", tc.TestUserID).Return(nil)

	cmd, buf := newVltCmd(recoverCmd.RunE, []string{"my-vault"})
	cmd.Args = cobra.ExactArgs(1)
	cmd.SetContext(ctxWithFormatter(tc.Ctx))

	err := cmd.Execute()
	require.NoError(t, err)
	assert.Contains(t, buf.String(), "recovered successfully")
	tc.MockVaultService.AssertExpectations(t)
}

func TestRecoverCmd_ServiceError(t *testing.T) {
	tc := testutils.NewTestContext(t)
	tc.MockVaultService.On("ListVaults", mock.Anything, true).
		Return([]model.Vault{{ID: uuid.New(), Name: "broken-vault"}}, nil)
	tc.MockVaultService.On("RecoverVault", mock.Anything, "broken-vault", tc.TestUserID).
		Return(fmt.Errorf("vault not found"))

	cmd, _ := newVltCmd(recoverCmd.RunE, []string{"broken-vault"})
	cmd.Args = cobra.ExactArgs(1)
	cmd.SetContext(ctxWithFormatter(tc.Ctx))

	err := cmd.Execute()
	assert.ErrorContains(t, err, "failed to recover vault")
	tc.MockVaultService.AssertExpectations(t)
}

// ---- createCmd additional error paths ----

func TestVaultsCreate_ServiceError(t *testing.T) {
	tc := testutils.NewTestContext(t)
	tc.MockVaultService.On("CreateVaultProvisioned", mock.Anything, mock.Anything, tc.TestUserID, false, false).
		Return(nil, fmt.Errorf("vault creation failed"))

	cmd := &cobra.Command{Use: "create", RunE: createCmd.RunE}
	cmd.Flags().Bool("purge-protection", false, "")
	cmd.Flags().Int("retention-days", 0, "")
	cmd.SetContext(ctxWithFormatter(tc.Ctx))
	cmd.SetArgs([]string{"bad-vault"})

	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)

	err := cmd.Execute()
	assert.ErrorContains(t, err, "failed to create vault")
	tc.MockVaultService.AssertExpectations(t)
}

func TestVaultsCreate_NoFormatter(t *testing.T) {
	tc := testutils.NewTestContext(t)
	created := &model.Vault{
		ID:            uuid.New(),
		Name:          "nofmt-vault",
		Enabled:       true,
		RetentionDays: 90,
	}
	tc.MockVaultService.On("CreateVaultProvisioned", mock.Anything, mock.Anything, tc.TestUserID, false, false).Return(created, nil)

	cmd := &cobra.Command{Use: "create", RunE: createCmd.RunE}
	cmd.Flags().Bool("purge-protection", false, "")
	cmd.Flags().Int("retention-days", 0, "")
	// Context without formatter.
	cmd.SetContext(tc.Ctx)
	cmd.SetArgs([]string{"nofmt-vault"})

	err := cmd.Execute()
	assert.ErrorContains(t, err, "output formatter not available")
	tc.MockVaultService.AssertExpectations(t)
}

func TestVaultsCreate_WithPurgeProtection(t *testing.T) {
	tc := testutils.NewTestContext(t)
	created := &model.Vault{
		ID:              uuid.New(),
		Name:            "protected-vault",
		Enabled:         true,
		PurgeProtection: true,
		RetentionDays:   30,
	}
	tc.MockVaultService.On("CreateVaultProvisioned", mock.Anything,
		mock.MatchedBy(func(r model.CreateVaultRequest) bool {
			return r.Name == "protected-vault" &&
				r.PurgeProtection != nil && *r.PurgeProtection
		}), tc.TestUserID, false, false).Return(created, nil)

	cmd := &cobra.Command{Use: "create", RunE: createCmd.RunE}
	cmd.Flags().Bool("purge-protection", false, "")
	cmd.Flags().Int("retention-days", 0, "")
	cmd.SetContext(ctxWithFormatter(tc.Ctx))
	cmd.SetArgs([]string{"protected-vault", "--purge-protection=true"})

	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)

	err := cmd.Execute()
	require.NoError(t, err)
	assert.Contains(t, out.String(), "protected-vault")
	tc.MockVaultService.AssertExpectations(t)
}

func TestVaultsCreate_WithRetentionDays(t *testing.T) {
	tc := testutils.NewTestContext(t)
	created := &model.Vault{
		ID:            uuid.New(),
		Name:          "retention-vault",
		Enabled:       true,
		RetentionDays: 60,
	}
	tc.MockVaultService.On("CreateVaultProvisioned", mock.Anything,
		mock.MatchedBy(func(r model.CreateVaultRequest) bool {
			return r.Name == "retention-vault" &&
				r.RetentionDays != nil && *r.RetentionDays == 60
		}), tc.TestUserID, false, false).Return(created, nil)

	cmd := &cobra.Command{Use: "create", RunE: createCmd.RunE}
	cmd.Flags().Bool("purge-protection", false, "")
	cmd.Flags().Int("retention-days", 0, "")
	cmd.SetContext(ctxWithFormatter(tc.Ctx))
	cmd.SetArgs([]string{"retention-vault", "--retention-days=60"})

	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)

	err := cmd.Execute()
	require.NoError(t, err)
	assert.Contains(t, out.String(), "retention-vault")
	tc.MockVaultService.AssertExpectations(t)
}

// ---- getCmd additional error paths ----

func TestVaultsGet_ServiceError(t *testing.T) {
	tc := testutils.NewTestContext(t)
	tc.MockVaultService.On("ListVaults", mock.Anything, true).
		Return([]model.Vault{{ID: uuid.New(), Name: "missing-vault"}}, nil)
	tc.MockVaultService.On("GetVault", mock.Anything, "missing-vault").
		Return(nil, fmt.Errorf("not found"))

	cmd := &cobra.Command{Use: "get", Args: cobra.ExactArgs(1), RunE: getCmd.RunE}
	cmd.SetContext(ctxWithFormatter(tc.Ctx))
	cmd.SetArgs([]string{"missing-vault"})

	err := cmd.Execute()
	assert.ErrorContains(t, err, "failed to retrieve vault")
	tc.MockVaultService.AssertExpectations(t)
}

func TestVaultsGet_NoFormatter(t *testing.T) {
	tc := testutils.NewTestContext(t)
	tc.MockVaultService.On("ListVaults", mock.Anything, true).
		Return([]model.Vault{{ID: uuid.New(), Name: "nofmt-vault"}}, nil)
	v := &model.Vault{ID: uuid.New(), Name: "nofmt-vault", Enabled: true, RetentionDays: 90}
	tc.MockVaultService.On("GetVault", mock.Anything, "nofmt-vault").Return(v, nil)

	cmd := &cobra.Command{Use: "get", Args: cobra.ExactArgs(1), RunE: getCmd.RunE}
	// No formatter in context.
	cmd.SetContext(tc.Ctx)
	cmd.SetArgs([]string{"nofmt-vault"})

	err := cmd.Execute()
	assert.ErrorContains(t, err, "output formatter not available")
	tc.MockVaultService.AssertExpectations(t)
}

// ---- listCmd additional error paths ----

func TestVaultsList_ServiceError(t *testing.T) {
	tc := testutils.NewTestContext(t)
	tc.MockVaultService.On("ListVaultsScoped", mock.Anything, tc.TestUserID, false, true).
		Return(nil, fmt.Errorf("db error"))

	cmd := &cobra.Command{Use: "list", RunE: listCmd.RunE}
	cmd.Flags().Bool("include-deleted", false, "")
	cmd.SetContext(ctxWithFormatter(tc.Ctx))
	cmd.SetArgs([]string{})

	err := cmd.Execute()
	assert.ErrorContains(t, err, "failed to list vaults")
	tc.MockVaultService.AssertExpectations(t)
}

func TestVaultsList_NoFormatter(t *testing.T) {
	tc := testutils.NewTestContext(t)
	tc.MockVaultService.On("ListVaultsScoped", mock.Anything, tc.TestUserID, false, true).
		Return([]model.Vault{}, nil)

	cmd := &cobra.Command{Use: "list", RunE: listCmd.RunE}
	cmd.Flags().Bool("include-deleted", false, "")
	// No formatter.
	cmd.SetContext(tc.Ctx)
	cmd.SetArgs([]string{})

	err := cmd.Execute()
	assert.ErrorContains(t, err, "output formatter not available")
	tc.MockVaultService.AssertExpectations(t)
}

func TestVaultsList_IncludeDeleted(t *testing.T) {
	tc := testutils.NewTestContext(t)
	tc.MockVaultService.On("ListVaultsScoped", mock.Anything, tc.TestUserID, true, true).
		Return([]model.Vault{
			{ID: uuid.New(), Name: "active-vault", Enabled: true},
			{ID: uuid.New(), Name: "deleted-vault", Enabled: false},
		}, nil)

	cmd := &cobra.Command{Use: "list", RunE: listCmd.RunE}
	cmd.Flags().Bool("include-deleted", false, "")
	cmd.SetContext(ctxWithFormatter(tc.Ctx))
	cmd.SetArgs([]string{"--include-deleted=true"})

	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)

	err := cmd.Execute()
	require.NoError(t, err)
	assert.Contains(t, out.String(), "active-vault")
	assert.Contains(t, out.String(), "deleted-vault")
	tc.MockVaultService.AssertExpectations(t)
}

// ---- deleteCmd additional error paths ----

func TestVaultsDelete_ServiceError(t *testing.T) {
	tc := testutils.NewTestContext(t)
	tc.MockVaultService.On("ListVaults", mock.Anything, true).
		Return([]model.Vault{{ID: uuid.New(), Name: "locked-vault"}}, nil)
	tc.MockVaultService.On("DeleteVault", mock.Anything, "locked-vault", tc.TestUserID).
		Return(fmt.Errorf("vault is protected"))

	cmd := &cobra.Command{Use: "delete", Args: cobra.ExactArgs(1), RunE: deleteCmd.RunE}
	cmd.SetContext(tc.Ctx)
	cmd.SetArgs([]string{"locked-vault"})

	err := cmd.Execute()
	assert.ErrorContains(t, err, "failed to delete vault")
	tc.MockVaultService.AssertExpectations(t)
}

// ---- updateCmd additional error paths ----

func TestVaultsUpdate_ServiceError(t *testing.T) {
	tc := testutils.NewTestContext(t)
	tc.MockVaultService.On("ListVaults", mock.Anything, true).
		Return([]model.Vault{{ID: uuid.New(), Name: "error-vault"}}, nil)
	tc.MockVaultService.On("UpdateVault", mock.Anything, "error-vault", mock.Anything, tc.TestUserID).
		Return(nil, fmt.Errorf("update rejected"))

	cmd := &cobra.Command{Use: "update", Args: updateCmd.Args, RunE: updateCmd.RunE}
	cmd.Flags().Bool("enabled", true, "")
	cmd.Flags().Bool("purge-protection", false, "")
	cmd.Flags().Int("retention-days", 0, "")
	cmd.SetContext(ctxWithFormatter(tc.Ctx))
	cmd.SetArgs([]string{"error-vault", "--enabled=false"})

	err := cmd.Execute()
	assert.ErrorContains(t, err, "failed to update vault")
	tc.MockVaultService.AssertExpectations(t)
}

func TestVaultsUpdate_NoFormatter(t *testing.T) {
	tc := testutils.NewTestContext(t)
	tc.MockVaultService.On("ListVaults", mock.Anything, true).
		Return([]model.Vault{{ID: uuid.New(), Name: "nofmt-vault"}}, nil)
	updated := &model.Vault{ID: uuid.New(), Name: "nofmt-vault", Enabled: false}
	tc.MockVaultService.On("UpdateVault", mock.Anything, "nofmt-vault", mock.Anything, tc.TestUserID).
		Return(updated, nil)

	cmd := &cobra.Command{Use: "update", Args: updateCmd.Args, RunE: updateCmd.RunE}
	cmd.Flags().Bool("enabled", true, "")
	cmd.Flags().Bool("purge-protection", false, "")
	cmd.Flags().Int("retention-days", 0, "")
	// No formatter in context.
	cmd.SetContext(tc.Ctx)
	cmd.SetArgs([]string{"nofmt-vault", "--enabled=false"})

	err := cmd.Execute()
	assert.ErrorContains(t, err, "output formatter not available")
	tc.MockVaultService.AssertExpectations(t)
}

func TestVaultsUpdate_WithPurgeAndRetention(t *testing.T) {
	tc := testutils.NewTestContext(t)
	updated := &model.Vault{
		ID:              uuid.New(),
		Name:            "full-update-vault",
		Enabled:         true,
		PurgeProtection: true,
		RetentionDays:   45,
	}
	tc.MockVaultService.On("ListVaults", mock.Anything, true).
		Return([]model.Vault{{ID: uuid.New(), Name: "full-update-vault"}}, nil)
	tc.MockVaultService.On("UpdateVault", mock.Anything, "full-update-vault",
		mock.MatchedBy(func(r model.UpdateVaultRequest) bool {
			return r.PurgeProtection != nil && *r.PurgeProtection &&
				r.RetentionDays != nil && *r.RetentionDays == 45
		}), tc.TestUserID).Return(updated, nil)

	cmd := &cobra.Command{Use: "update", Args: updateCmd.Args, RunE: updateCmd.RunE}
	cmd.Flags().Bool("enabled", true, "")
	cmd.Flags().Bool("purge-protection", false, "")
	cmd.Flags().Int("retention-days", 0, "")
	cmd.SetContext(ctxWithFormatter(tc.Ctx))
	cmd.SetArgs([]string{"full-update-vault", "--purge-protection=true", "--retention-days=45"})

	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)

	err := cmd.Execute()
	require.NoError(t, err)
	assert.Contains(t, out.String(), "full-update-vault")
	tc.MockVaultService.AssertExpectations(t)
}

// TestVaultsDelete_ForbiddenWithoutGrant proves a non-admin with no
// vaults:manage policy on the target vault cannot delete it via the CLI.
func TestVaultsDelete_ForbiddenWithoutGrant(t *testing.T) {
	tc := testutils.NewTestContext(t)
	nonAdminCtx := context.WithValue(tc.Ctx, common.ClaimsKey, &model.Claims{UserID: tc.TestUserID, Roles: []string{model.RoleUser}})
	tc.MockContainer.AccessPolicyService = &mockAccessPolicyService{decision: authzServices.AccessFallback}
	tc.MockVaultService.On("ListVaults", mock.Anything, true).
		Return([]model.Vault{{ID: uuid.New(), Name: "guarded-vault"}}, nil)

	cmd := &cobra.Command{Use: "delete", Args: cobra.ExactArgs(1), RunE: deleteCmd.RunE}
	cmd.SetContext(nonAdminCtx)
	cmd.SetArgs([]string{"guarded-vault"})
	rec := &logtest.Recorder{}
	tc.MockContainer.GetLogger().SetAuditPersister(rec)

	err := cmd.Execute()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "permission denied")
	tc.MockVaultService.AssertNotCalled(t, "DeleteVault", mock.Anything, mock.Anything, mock.Anything)
	row, ok := rec.Find("delete_vault", "denied")
	require.True(t, ok, "a refused CLI vault delete must be audited")
	assert.Equal(t, tc.TestUserID.String(), row.UserID)
}

// TestVaultsRecover_ForbiddenWithoutGrant mirrors the delete case for recover.
func TestVaultsRecover_ForbiddenWithoutGrant(t *testing.T) {
	tc := testutils.NewTestContext(t)
	nonAdminCtx := context.WithValue(tc.Ctx, common.ClaimsKey, &model.Claims{UserID: tc.TestUserID, Roles: []string{model.RoleUser}})
	tc.MockContainer.AccessPolicyService = &mockAccessPolicyService{decision: authzServices.AccessFallback}
	tc.MockVaultService.On("ListVaults", mock.Anything, true).
		Return([]model.Vault{{ID: uuid.New(), Name: "guarded-vault"}}, nil)

	cmd := &cobra.Command{Use: "recover", Args: cobra.ExactArgs(1), RunE: recoverCmd.RunE}
	cmd.SetContext(nonAdminCtx)
	cmd.SetArgs([]string{"guarded-vault"})

	err := cmd.Execute()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "permission denied")
	tc.MockVaultService.AssertNotCalled(t, "RecoverVault", mock.Anything, mock.Anything, mock.Anything)
}

// stubRoleAssignmentService is a minimal RoleAssignmentService test double
// whose HasDataAction result is fixed at construction — enough to prove
// CanPurgeVault's positive path from the CLI without a full mock.
type stubRoleAssignmentService struct {
	allowed bool
}

func (s *stubRoleAssignmentService) AssignRole(context.Context, authzServices.AssignRoleInput) (*model.RoleAssignment, error) {
	return nil, fmt.Errorf("not implemented in stub")
}
func (s *stubRoleAssignmentService) RevokeAssignment(context.Context, uuid.UUID, uuid.UUID, uuid.UUID, bool) error {
	return fmt.Errorf("not implemented in stub")
}
func (s *stubRoleAssignmentService) ListAssignments(context.Context, uuid.UUID) ([]*model.RoleAssignment, error) {
	return nil, fmt.Errorf("not implemented in stub")
}
func (s *stubRoleAssignmentService) HasDataAction(context.Context, uuid.UUID, uuid.UUID, model.DataAction) (bool, error) {
	return s.allowed, nil
}

// TestVaultsPurge_ForbiddenWithoutGrant proves a non-admin with no Purge
// Operator role assignment cannot purge a vault via the CLI. This is the
// concrete regression for the pre-existing gap: before this task, purge had
// no authorization check of any kind.
func TestVaultsPurge_ForbiddenWithoutGrant(t *testing.T) {
	tc := testutils.NewTestContext(t)
	nonAdminCtx := context.WithValue(tc.Ctx, common.ClaimsKey, &model.Claims{UserID: tc.TestUserID, Roles: []string{model.RoleUser}})
	tc.MockContainer.RoleAssignmentService = &stubRoleAssignmentService{allowed: false}
	tc.MockVaultService.On("ListVaults", mock.Anything, true).
		Return([]model.Vault{{ID: uuid.New(), Name: "guarded-vault"}}, nil)

	cmd, _ := newVltCmd(purgeCmd.RunE, []string{"guarded-vault"})
	cmd.Args = cobra.ExactArgs(1)
	cmd.SetContext(nonAdminCtx)

	err := cmd.Execute()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "permission denied")
	tc.MockVaultService.AssertNotCalled(t, "PurgeVault", mock.Anything, mock.Anything, mock.Anything)
}

// TestVaultsPurge_AllowedWithPurgeOperatorGrant proves a non-admin holding
// Key Vault Purge Operator in the target vault CAN purge it via the CLI.
func TestVaultsPurge_AllowedWithPurgeOperatorGrant(t *testing.T) {
	tc := testutils.NewTestContext(t)
	nonAdminCtx := context.WithValue(tc.Ctx, common.ClaimsKey, &model.Claims{UserID: tc.TestUserID, Roles: []string{model.RoleUser}})
	tc.MockContainer.RoleAssignmentService = &stubRoleAssignmentService{allowed: true}
	tc.MockVaultService.On("ListVaults", mock.Anything, true).
		Return([]model.Vault{{ID: uuid.New(), Name: "my-vault"}}, nil)
	tc.MockVaultService.On("PurgeVault", mock.Anything, "my-vault", tc.TestUserID).Return(nil)

	cmd, buf := newVltCmd(purgeCmd.RunE, []string{"my-vault"})
	cmd.Args = cobra.ExactArgs(1)
	cmd.SetContext(nonAdminCtx)

	err := cmd.Execute()
	require.NoError(t, err)
	assert.Contains(t, buf.String(), "purged successfully")
	tc.MockVaultService.AssertExpectations(t)
}

func TestVaultsGet_ForbiddenWithoutGrant(t *testing.T) {
	tc := testutils.NewTestContext(t)
	nonAdminCtx := context.WithValue(tc.Ctx, common.ClaimsKey, &model.Claims{UserID: tc.TestUserID, Roles: []string{model.RoleUser}})
	tc.MockContainer.AccessPolicyService = &mockAccessPolicyService{decision: authzServices.AccessFallback}
	tc.MockVaultService.On("ListVaults", mock.Anything, true).
		Return([]model.Vault{{ID: uuid.New(), Name: "guarded-vault"}}, nil)

	cmd := &cobra.Command{Use: "get", Args: cobra.ExactArgs(1), RunE: getCmd.RunE}
	cmd.SetContext(ctxWithFormatter(nonAdminCtx))
	cmd.SetArgs([]string{"guarded-vault"})

	err := cmd.Execute()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "permission denied")
	tc.MockVaultService.AssertNotCalled(t, "GetVault", mock.Anything, mock.Anything)
}

// TestVaultsList_ScopedWithoutGlobalGrant proves list is no longer a
// global-grant-or-denial decision for the CLI either: a non-admin caller
// with no global vaults:manage grant still succeeds, requesting the
// non-instance-wide (all=false) listing rather than being refused outright.
func TestVaultsList_ScopedWithoutGlobalGrant(t *testing.T) {
	tc := testutils.NewTestContext(t)
	nonAdminCtx := context.WithValue(tc.Ctx, common.ClaimsKey, &model.Claims{UserID: tc.TestUserID, Roles: []string{model.RoleUser}})
	tc.MockContainer.AccessPolicyService = &mockAccessPolicyService{decision: authzServices.AccessFallback}
	tc.MockVaultService.On("ListVaultsScoped", mock.Anything, tc.TestUserID, false, false).
		Return([]model.Vault{{ID: uuid.New(), Name: "own-vault"}}, nil)

	cmd := &cobra.Command{Use: "list", RunE: listCmd.RunE}
	cmd.SetContext(ctxWithFormatter(nonAdminCtx))

	err := cmd.Execute()
	require.NoError(t, err)
	tc.MockVaultService.AssertExpectations(t)
}
