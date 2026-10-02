package keys

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	"rocketvault/cmd/testutils"
	"rocketvault/internal/repositories"
	authzServices "rocketvault/internal/services/authorization"
	keyServices "rocketvault/internal/services/keys"
	"rocketvault/model"
)

type MockKeyServiceForUpdate struct{ mock.Mock }

func (m *MockKeyServiceForUpdate) UpdateKey(ctx context.Context, req keyServices.UpdateKeyRequest) error {
	args := m.Called(ctx, req)
	return args.Error(0)
}
func (m *MockKeyServiceForUpdate) CreateRSAKey(ctx context.Context, req keyServices.CreateKeyRequest) (*keyServices.CreateKeyResult, error) {
	return nil, nil
}
func (m *MockKeyServiceForUpdate) CreateECDSAKey(ctx context.Context, req keyServices.CreateKeyRequest) (*keyServices.CreateKeyResult, error) {
	return nil, nil
}
func (m *MockKeyServiceForUpdate) CreateOctKey(ctx context.Context, req keyServices.CreateKeyRequest) (*keyServices.CreateKeyResult, error) {
	return nil, nil
}
func (m *MockKeyServiceForUpdate) ImportKey(ctx context.Context, req keyServices.ImportKeyRequest) (*keyServices.CreateKeyResult, error) {
	return nil, nil
}
func (m *MockKeyServiceForUpdate) GetKey(ctx context.Context, keyID uuid.UUID, scope model.Scope) (*model.Key, error) {
	return nil, nil
}
func (m *MockKeyServiceForUpdate) ListKeys(ctx context.Context, scope model.Scope, filter repositories.KeyFilter) ([]model.Key, error) {
	return nil, nil
}
func (m *MockKeyServiceForUpdate) DeleteKey(ctx context.Context, keyID uuid.UUID, scope model.Scope) (*model.Key, error) {
	return nil, nil
}
func (m *MockKeyServiceForUpdate) RotateKey(ctx context.Context, keyID uuid.UUID, scope model.Scope) (*keyServices.CreateKeyResult, error) {
	return nil, nil
}
func (m *MockKeyServiceForUpdate) ValidateKeyAccess(ctx context.Context, keyID, userID uuid.UUID, role string) error {
	return nil
}
func (m *MockKeyServiceForUpdate) ListDeletedKeys(ctx context.Context, scope model.Scope) ([]model.Key, error) {
	return nil, nil
}
func (m *MockKeyServiceForUpdate) RecoverKey(ctx context.Context, keyID uuid.UUID, scope model.Scope) error {
	return nil
}
func (m *MockKeyServiceForUpdate) PurgeKey(ctx context.Context, keyID uuid.UUID, scope model.Scope) error {
	return nil
}
func (m *MockKeyServiceForUpdate) GetKeyRotationPolicy(ctx context.Context, keyID uuid.UUID, scope model.Scope) (*model.KeyRotationPolicy, error) {
	return nil, nil
}
func (m *MockKeyServiceForUpdate) UpsertKeyRotationPolicy(ctx context.Context, keyID uuid.UUID, scope model.Scope, req model.UpsertKeyRotationPolicyRequest) (*model.KeyRotationPolicy, error) {
	return nil, nil
}
func (m *MockKeyServiceForUpdate) DeleteKeyRotationPolicy(ctx context.Context, keyID uuid.UUID, scope model.Scope) error {
	return nil
}
func (m *MockKeyServiceForUpdate) ListKeyRotationPolicies(ctx context.Context, scope model.Scope) ([]model.KeyRotationPolicyWithKeyName, error) {
	return nil, nil
}
func (m *MockKeyServiceForUpdate) ListDueKeyRotationPolicies(ctx context.Context, scope model.Scope) ([]model.KeyRotationPolicy, error) {
	return nil, nil
}
func (m *MockKeyServiceForUpdate) ListKeyVersions(ctx context.Context, keyID uuid.UUID, scope model.Scope) ([]model.KeyVersion, error) {
	return nil, nil
}
func (m *MockKeyServiceForUpdate) GetKeyVersion(ctx context.Context, keyID uuid.UUID, version int, scope model.Scope) (*model.KeyVersion, error) {
	args := m.Called(ctx, keyID, version, scope)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*model.KeyVersion), args.Error(1)
}

func (m *MockKeyServiceForUpdate) GetPublicJWK(ctx context.Context, keyID uuid.UUID, version int, scope model.Scope) (*model.PublicJWK, error) {
	// Plain stub: this test asserts the update call, not response bodies.
	return &model.PublicJWK{}, nil
}

func (m *MockKeyServiceForUpdate) ExportKey(ctx context.Context, scope model.Scope, id uuid.UUID, version int) (*keyServices.ExportKeyResult, error) {
	args := m.Called(ctx, scope, id, version)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*keyServices.ExportKeyResult), args.Error(1)
}

func TestUpdateKeyCommand_CallsServiceUpdate(t *testing.T) {
	tc := testutils.NewTestContext(t)
	mockKeySvc := &MockKeyServiceForUpdate{}
	keyID := uuid.New()

	mockKeySvc.On("UpdateKey", mock.Anything, mock.MatchedBy(func(r keyServices.UpdateKeyRequest) bool {
		return r.KeyID == keyID &&
			r.Scope == model.NewVaultScope(tc.TestVaultID, tc.TestUserID) &&
			r.Name != nil && *r.Name == "new-name"
	})).Return(nil)
	tc.MockContainer.On("GetKeyService").Return(mockKeySvc)

	cmd := &cobra.Command{
		Use:  "update <id>",
		Args: cobra.ExactArgs(1),
		RunE: updateCmd.RunE,
	}
	cmd.Flags().String("name", "", "")
	cmd.Flags().Bool("revoked", false, "")
	cmd.Flags().String("tags", "", "")
	cmd.SetArgs([]string{keyID.String(), "--name=new-name"})
	cmd.SetContext(tc.Ctx)

	err := cmd.Execute()
	assert.NoError(t, err)
	mockKeySvc.AssertExpectations(t)
}

func TestUpdateKeyCommand_Denied(t *testing.T) {
	tc := testutils.NewTestContext(t)
	mockKeySvc := &MockKeyServiceForUpdate{}
	keyID := uuid.New()

	denyRoles := &testutils.MockRoleAssignmentService{}
	denyRoles.On("HasDataAction", mock.Anything, mock.Anything, mock.Anything, mock.Anything).
		Return(false, nil).Maybe()
	tc.MockContainer.RoleAssignmentService = denyRoles
	tc.MockContainer.On("GetKeyService").Return(mockKeySvc)

	cmd := &cobra.Command{
		Use:  "update <id>",
		Args: cobra.ExactArgs(1),
		RunE: updateCmd.RunE,
	}
	cmd.Flags().String("name", "", "")
	cmd.Flags().Bool("revoked", false, "")
	cmd.Flags().String("tags", "", "")
	cmd.SetArgs([]string{keyID.String(), "--name=new-name"})
	cmd.SetContext(tc.Ctx)

	err := cmd.Execute()
	assert.ErrorContains(t, err, "forbidden")
	mockKeySvc.AssertNotCalled(t, "UpdateKey", mock.Anything, mock.Anything)
}

func TestUpdateKeyCommand_Authorized(t *testing.T) {
	tc := testutils.NewTestContext(t)
	mockKeySvc := &MockKeyServiceForUpdate{}
	keyID := uuid.New()

	roles := &testutils.MockRoleAssignmentService{}
	roles.On("HasDataAction", mock.Anything, tc.TestUserID, tc.TestVaultID, model.ActionKeysUpdate).
		Return(true, nil).Once()
	policies := &testutils.MockAccessPolicyService{}
	policies.On("CheckAccess", mock.Anything, tc.TestUserID, model.PolicyResourceKeys, model.OpSet, tc.TestVaultID).
		Return(authzServices.AccessAllowed, nil).Once()
	tc.MockContainer.RoleAssignmentService = roles
	tc.MockContainer.AccessPolicyService = policies

	mockKeySvc.On("UpdateKey", mock.Anything, mock.MatchedBy(func(r keyServices.UpdateKeyRequest) bool {
		return r.KeyID == keyID &&
			r.Scope == model.NewVaultScope(tc.TestVaultID, tc.TestUserID) &&
			r.Name != nil && *r.Name == "new-name"
	})).Return(nil)
	tc.MockContainer.On("GetKeyService").Return(mockKeySvc)

	cmd := &cobra.Command{
		Use:  "update <id>",
		Args: cobra.ExactArgs(1),
		RunE: updateCmd.RunE,
	}
	cmd.Flags().String("name", "", "")
	cmd.Flags().Bool("revoked", false, "")
	cmd.Flags().String("tags", "", "")
	cmd.SetArgs([]string{keyID.String(), "--name=new-name"})
	cmd.SetContext(tc.Ctx)

	err := cmd.Execute()
	assert.NoError(t, err)
	mockKeySvc.AssertExpectations(t)
	roles.AssertExpectations(t)
	policies.AssertExpectations(t)
}

func TestUpdateKeyCommand_SetsRevoked(t *testing.T) {
	tc := testutils.NewTestContext(t)
	mockKeySvc := &MockKeyServiceForUpdate{}
	keyID := uuid.New()

	mockKeySvc.On("UpdateKey", mock.Anything, mock.MatchedBy(func(r keyServices.UpdateKeyRequest) bool {
		return r.Revoked != nil && *r.Revoked == true &&
			r.Scope == model.NewVaultScope(tc.TestVaultID, tc.TestUserID)
	})).Return(nil)
	tc.MockContainer.On("GetKeyService").Return(mockKeySvc)

	cmd := &cobra.Command{
		Use:  "update <id>",
		Args: cobra.ExactArgs(1),
		RunE: updateCmd.RunE,
	}
	cmd.Flags().String("name", "", "")
	cmd.Flags().Bool("revoked", false, "")
	cmd.Flags().String("tags", "", "")
	cmd.SetArgs([]string{keyID.String(), "--revoked=true"})
	cmd.SetContext(tc.Ctx)

	err := cmd.Execute()
	assert.NoError(t, err)
	mockKeySvc.AssertExpectations(t)
}

func TestUpdateKeyCommand_NoFieldsProvided(t *testing.T) {
	tc := testutils.NewTestContext(t)
	keyID := uuid.New()

	cmd := &cobra.Command{
		Use:  "update <id>",
		Args: cobra.ExactArgs(1),
		RunE: updateCmd.RunE,
	}
	cmd.Flags().String("name", "", "")
	cmd.Flags().Bool("revoked", false, "")
	cmd.Flags().String("tags", "", "")
	cmd.SetArgs([]string{keyID.String()})
	cmd.SetContext(tc.Ctx)

	err := cmd.Execute()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "at least one update field")
}
