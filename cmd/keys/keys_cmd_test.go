package keys

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"rocketvault/cmd/testutils"
	"rocketvault/common"
	"rocketvault/internal/crypto"
	"rocketvault/internal/formatter"
	"rocketvault/internal/logging"
	"rocketvault/internal/repositories"
	authzServices "rocketvault/internal/services/authorization"
	keyServices "rocketvault/internal/services/keys"
	"rocketvault/model"
)

// TestMain registers all Init functions exactly once, covering those
// registration statements, then runs all tests.
func TestMain(m *testing.M) {
	parent := &cobra.Command{Use: "keys"}
	InitKeysCreate(parent)
	InitKeysImport(parent)
	InitKeysList(parent)
	InitKeysGet(parent)
	InitKeysDelete(parent)
	InitKeysRotate(parent)
	InitKeysWrap(parent)
	InitKeysUnwrap(parent)
	InitKeysUpdate(parent)
	InitKeysRotationPolicy(parent)
	InitKeysSign(parent)
	InitKeysVerify(parent)
	_ = NewWrapCmd()
	_ = NewUnwrapCmd()
	_ = NewSignCmd()
	_ = NewVerifyCmd()
	os.Exit(m.Run())
}

// ---- mocks ----

// keyCmdKeyService is a full mock for keyServices.KeyService.
type keyCmdKeyService struct{ mock.Mock }

func (m *keyCmdKeyService) CreateRSAKey(ctx context.Context, req keyServices.CreateKeyRequest) (*keyServices.CreateKeyResult, error) {
	args := m.Called(ctx, req)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*keyServices.CreateKeyResult), args.Error(1)
}
func (m *keyCmdKeyService) CreateECDSAKey(ctx context.Context, req keyServices.CreateKeyRequest) (*keyServices.CreateKeyResult, error) {
	args := m.Called(ctx, req)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*keyServices.CreateKeyResult), args.Error(1)
}
func (m *keyCmdKeyService) CreateOctKey(ctx context.Context, req keyServices.CreateKeyRequest) (*keyServices.CreateKeyResult, error) {
	args := m.Called(ctx, req)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*keyServices.CreateKeyResult), args.Error(1)
}
func (m *keyCmdKeyService) ImportKey(ctx context.Context, req keyServices.ImportKeyRequest) (*keyServices.CreateKeyResult, error) {
	args := m.Called(ctx, req)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*keyServices.CreateKeyResult), args.Error(1)
}
func (m *keyCmdKeyService) GetKey(ctx context.Context, keyID uuid.UUID, scope model.Scope) (*model.Key, error) {
	args := m.Called(ctx, keyID, scope)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*model.Key), args.Error(1)
}
func (m *keyCmdKeyService) ListKeys(ctx context.Context, scope model.Scope, filter repositories.KeyFilter) ([]model.Key, error) {
	args := m.Called(ctx, scope, filter)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]model.Key), args.Error(1)
}
func (m *keyCmdKeyService) UpdateKey(ctx context.Context, req keyServices.UpdateKeyRequest) error {
	args := m.Called(ctx, req)
	return args.Error(0)
}
func (m *keyCmdKeyService) DeleteKey(ctx context.Context, keyID uuid.UUID, scope model.Scope) (*model.Key, error) {
	args := m.Called(ctx, keyID, scope)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*model.Key), args.Error(1)
}
func (m *keyCmdKeyService) RotateKey(ctx context.Context, keyID uuid.UUID, scope model.Scope) (*keyServices.CreateKeyResult, error) {
	args := m.Called(ctx, keyID, scope)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*keyServices.CreateKeyResult), args.Error(1)
}
func (m *keyCmdKeyService) ValidateKeyAccess(ctx context.Context, keyID, userID uuid.UUID, role string) error {
	return nil
}
func (m *keyCmdKeyService) ListDeletedKeys(ctx context.Context, scope model.Scope) ([]model.Key, error) {
	args := m.Called(ctx, scope)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]model.Key), args.Error(1)
}
func (m *keyCmdKeyService) RecoverKey(ctx context.Context, keyID uuid.UUID, scope model.Scope) error {
	return m.Called(ctx, keyID, scope).Error(0)
}
func (m *keyCmdKeyService) PurgeKey(ctx context.Context, keyID uuid.UUID, scope model.Scope) error {
	return m.Called(ctx, keyID, scope).Error(0)
}
func (m *keyCmdKeyService) GetKeyRotationPolicy(ctx context.Context, keyID uuid.UUID, scope model.Scope) (*model.KeyRotationPolicy, error) {
	args := m.Called(ctx, keyID, scope)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*model.KeyRotationPolicy), args.Error(1)
}
func (m *keyCmdKeyService) UpsertKeyRotationPolicy(ctx context.Context, keyID uuid.UUID, scope model.Scope, req model.UpsertKeyRotationPolicyRequest) (*model.KeyRotationPolicy, error) {
	args := m.Called(ctx, keyID, scope, req)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*model.KeyRotationPolicy), args.Error(1)
}
func (m *keyCmdKeyService) DeleteKeyRotationPolicy(ctx context.Context, keyID uuid.UUID, scope model.Scope) error {
	return m.Called(ctx, keyID, scope).Error(0)
}
func (m *keyCmdKeyService) ListKeyRotationPolicies(ctx context.Context, scope model.Scope) ([]model.KeyRotationPolicyWithKeyName, error) {
	args := m.Called(ctx, scope)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]model.KeyRotationPolicyWithKeyName), args.Error(1)
}
func (m *keyCmdKeyService) ListDueKeyRotationPolicies(ctx context.Context, scope model.Scope) ([]model.KeyRotationPolicy, error) {
	args := m.Called(ctx, scope)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]model.KeyRotationPolicy), args.Error(1)
}
func (m *keyCmdKeyService) ListKeyVersions(ctx context.Context, keyID uuid.UUID, scope model.Scope) ([]model.KeyVersion, error) {
	args := m.Called(ctx, keyID, scope)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]model.KeyVersion), args.Error(1)
}
func (m *keyCmdKeyService) GetKeyVersion(ctx context.Context, keyID uuid.UUID, version int, scope model.Scope) (*model.KeyVersion, error) {
	args := m.Called(ctx, keyID, version, scope)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*model.KeyVersion), args.Error(1)
}

func (m *keyCmdKeyService) GetPublicJWK(ctx context.Context, keyID uuid.UUID, version int, scope model.Scope) (*model.PublicJWK, error) {
	// A plain stub, not m.Called: these tests set no JWK expectation, and the
	// component values are covered by key_jwk_test.go at the service layer and
	// by the dedicated handler test below.
	return &model.PublicJWK{}, nil
}

func (m *keyCmdKeyService) ExportKey(ctx context.Context, scope model.Scope, id uuid.UUID, version int) (*keyServices.ExportKeyResult, error) {
	args := m.Called(ctx, scope, id, version)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*keyServices.ExportKeyResult), args.Error(1)
}

// keyCmdCryptoService is a full mock for keyServices.CryptoService.
type keyCmdCryptoService struct{ mock.Mock }

func (m *keyCmdCryptoService) Sign(ctx context.Context, req keyServices.SignRequest) (*keyServices.SignResult, error) {
	args := m.Called(ctx, req)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*keyServices.SignResult), args.Error(1)
}
func (m *keyCmdCryptoService) Verify(ctx context.Context, req keyServices.VerifyRequest) (*keyServices.VerifyResult, error) {
	args := m.Called(ctx, req)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*keyServices.VerifyResult), args.Error(1)
}
func (m *keyCmdCryptoService) Encrypt(ctx context.Context, req keyServices.EncryptRequest) (*keyServices.EncryptResult, error) {
	return nil, nil
}
func (m *keyCmdCryptoService) Decrypt(ctx context.Context, req keyServices.DecryptRequest) (*keyServices.DecryptResult, error) {
	return nil, nil
}
func (m *keyCmdCryptoService) WrapKey(ctx context.Context, req keyServices.WrapKeyRequest) (*keyServices.WrapKeyResult, error) {
	args := m.Called(ctx, req)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*keyServices.WrapKeyResult), args.Error(1)
}
func (m *keyCmdCryptoService) UnwrapKey(ctx context.Context, req keyServices.UnwrapKeyRequest) (*keyServices.UnwrapKeyResult, error) {
	args := m.Called(ctx, req)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*keyServices.UnwrapKeyResult), args.Error(1)
}

// keysTestContainer wraps MockServiceContainer and allows overriding
// GetKeyService and GetCryptoService per test.
type keysTestContainer struct {
	*testutils.MockServiceContainer
	keySvc    keyServices.KeyService
	cryptoSvc keyServices.CryptoService
}

func (c *keysTestContainer) GetKeyService() keyServices.KeyService       { return c.keySvc }
func (c *keysTestContainer) GetCryptoService() keyServices.CryptoService { return c.cryptoSvc }

// newAllowedContainer returns a keysTestContainer pre-wired with a
// default-allow vault resolution (the "default" vault) and a default-allow
// role-assignment mock, mirroring testutils.NewTestContext's wiring. Tests
// in this file build their service container by hand instead of using
// testutils.NewTestContext, so this helper gives them the same defaults.
// Returns the container and the id of the resolved default vault, for
// scope/VaultID assertions.
func newAllowedContainer(keySvc keyServices.KeyService, cryptoSvc keyServices.CryptoService) (*keysTestContainer, uuid.UUID) {
	vaultID := uuid.MustParse(model.DefaultVaultID)

	mockVaultSvc := &testutils.MockVaultService{}
	mockVaultSvc.On("GetVault", mock.Anything, model.DefaultVaultName).
		Return(&model.Vault{ID: vaultID, Name: model.DefaultVaultName, Enabled: true}, nil).Maybe()

	mockRoleSvc := &testutils.MockRoleAssignmentService{}
	mockRoleSvc.On("HasDataAction", mock.Anything, mock.Anything, mock.Anything, mock.Anything).
		Return(true, nil).Maybe()

	// vaultcli.RequireDataAction checks AccessPolicyService.CheckAccess before
	// RoleAssignmentService.HasDataAction, so a default-allow mock is required
	// here too, or the call panics on a nil interface. Mirrors
	// testutils.NewTestContext's wiring.
	mockPolicySvc := &testutils.MockAccessPolicyService{}
	mockPolicySvc.On("CheckAccess", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).
		Return(authzServices.AccessAllowed, nil).Maybe()

	base := &testutils.MockServiceContainer{}
	base.VaultService = mockVaultSvc
	base.RoleAssignmentService = mockRoleSvc
	base.AccessPolicyService = mockPolicySvc

	return &keysTestContainer{
		MockServiceContainer: base,
		keySvc:               keySvc,
		cryptoSvc:            cryptoSvc,
	}, vaultID
}

// newDeniedContainer is identical to newAllowedContainer except the
// role-assignment mock denies every HasDataAction call, simulating a caller
// with no role assignment in the resolved vault. The access-policy mock
// still default-allows, so denial is attributable to the role-assignment
// check alone.
func newDeniedContainer(keySvc keyServices.KeyService, cryptoSvc keyServices.CryptoService) *keysTestContainer {
	vaultID := uuid.MustParse(model.DefaultVaultID)

	mockVaultSvc := &testutils.MockVaultService{}
	mockVaultSvc.On("GetVault", mock.Anything, model.DefaultVaultName).
		Return(&model.Vault{ID: vaultID, Name: model.DefaultVaultName, Enabled: true}, nil).Maybe()

	mockRoleSvc := &testutils.MockRoleAssignmentService{}
	mockRoleSvc.On("HasDataAction", mock.Anything, mock.Anything, mock.Anything, mock.Anything).
		Return(false, nil).Maybe()

	mockPolicySvc := &testutils.MockAccessPolicyService{}
	mockPolicySvc.On("CheckAccess", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).
		Return(authzServices.AccessAllowed, nil).Maybe()

	base := &testutils.MockServiceContainer{}
	base.VaultService = mockVaultSvc
	base.RoleAssignmentService = mockRoleSvc
	base.AccessPolicyService = mockPolicySvc

	return &keysTestContainer{
		MockServiceContainer: base,
		keySvc:               keySvc,
		cryptoSvc:            cryptoSvc,
	}
}

// ---- context helpers ----

func newLogger() *logging.Logger {
	return &logging.Logger{Logger: logrus.New()}
}

func newTestFmtr() formatter.Formatter {
	f, _ := formatter.New(formatter.FormatTable)
	return f
}

// buildAdminCtx builds a context with admin claims, logger, the given container, and formatter.
func buildAdminCtx(sc any) context.Context {
	userID := uuid.New()
	claims := &model.Claims{UserID: userID, Username: "admin", Roles: []string{model.RoleAdmin}}
	ctx := context.Background()
	ctx = context.WithValue(ctx, common.ClaimsKey, claims)
	ctx = context.WithValue(ctx, common.LogKey, newLogger())
	ctx = context.WithValue(ctx, common.ServiceContainerKey, sc)
	ctx = context.WithValue(ctx, common.OutputFormatterKey, newTestFmtr())
	return ctx
}

// buildUserCtx builds a context with non-admin (secrets_manager) claims.
func buildUserCtx(sc any, role string) context.Context {
	userID := uuid.New()
	claims := &model.Claims{UserID: userID, Username: "user", Roles: []string{role}}
	ctx := context.Background()
	ctx = context.WithValue(ctx, common.ClaimsKey, claims)
	ctx = context.WithValue(ctx, common.LogKey, newLogger())
	ctx = context.WithValue(ctx, common.ServiceContainerKey, sc)
	ctx = context.WithValue(ctx, common.OutputFormatterKey, newTestFmtr())
	return ctx
}

// noopContainer is a minimal container that returns nil for everything.
// Used for "no service container" tests by setting a non-container value.

func newTestCmd(runE func(*cobra.Command, []string) error, args []string) (*cobra.Command, *bytes.Buffer) {
	cmd := &cobra.Command{Use: "test", RunE: runE}
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	cmd.SetArgs(args)
	return cmd, &buf
}

// setFlags registers each key as a flag on cmd (if not already registered)
// and sets its value. Commands read their inputs from their own flag set,
// never from global viper: two commands binding the same viper key overwrite
// each other process-wide, which is what silently disabled `keys list --tags`.
func setFlags(cmd *cobra.Command, kvs map[string]any) {
	for k, v := range kvs {
		switch val := v.(type) {
		case string:
			if cmd.Flags().Lookup(k) == nil {
				cmd.Flags().String(k, val, "")
				continue
			}
			_ = cmd.Flags().Set(k, val)
		case int:
			if cmd.Flags().Lookup(k) == nil {
				cmd.Flags().Int(k, val, "")
				continue
			}
			_ = cmd.Flags().Set(k, strconv.Itoa(val))
		case bool:
			if cmd.Flags().Lookup(k) == nil {
				cmd.Flags().Bool(k, val, "")
				continue
			}
			_ = cmd.Flags().Set(k, strconv.FormatBool(val))
		default:
			panic("setFlags: unsupported flag type for " + k)
		}
	}
}

// ========== createCmd tests ==========

func TestCreateCmd_NoClaims(t *testing.T) {
	ctx := context.Background()
	cmd, _ := newTestCmd(createCmd.RunE, nil)
	cmd.SetContext(ctx)
	err := cmd.Execute()
	assert.ErrorContains(t, err, "unauthorized")
}

func TestCreateCmd_ForbiddenRole(t *testing.T) {
	sc := &testutils.MockServiceContainer{}
	ctx := buildUserCtx(sc, model.RoleUser)
	cmd, _ := newTestCmd(createCmd.RunE, nil)
	setFlags(cmd, map[string]any{"name": "k", "type": "RSA"})
	cmd.SetContext(ctx)
	err := cmd.Execute()
	assert.ErrorContains(t, err, "forbidden")
}

func TestCreateCmd_NoServiceContainer(t *testing.T) {
	ctx := context.Background()
	claims := &model.Claims{UserID: uuid.New(), Roles: []string{model.RoleAdmin}}
	ctx = context.WithValue(ctx, common.ClaimsKey, claims)
	ctx = context.WithValue(ctx, common.LogKey, newLogger())
	// No ServiceContainerKey in context.
	cmd, _ := newTestCmd(createCmd.RunE, nil)
	setFlags(cmd, map[string]any{"name": "mykey", "type": "RSA", "bits": 2048})
	cmd.SetContext(ctx)
	err := cmd.Execute()
	assert.ErrorContains(t, err, "service container not available")
}

func TestCreateCmd_MissingName(t *testing.T) {
	sc := &keysTestContainer{
		MockServiceContainer: &testutils.MockServiceContainer{},
	}
	ctx := buildAdminCtx(sc)
	cmd, _ := newTestCmd(createCmd.RunE, nil)
	setFlags(cmd, map[string]any{"name": "", "type": "RSA"})
	cmd.SetContext(ctx)
	err := cmd.Execute()
	assert.ErrorContains(t, err, "name and type are required")
}

func TestCreateCmd_MissingType(t *testing.T) {
	sc := &keysTestContainer{
		MockServiceContainer: &testutils.MockServiceContainer{},
	}
	ctx := buildAdminCtx(sc)
	cmd, _ := newTestCmd(createCmd.RunE, nil)
	setFlags(cmd, map[string]any{"name": "mykey", "type": ""})
	cmd.SetContext(ctx)
	err := cmd.Execute()
	assert.ErrorContains(t, err, "name and type are required")
}

func TestCreateCmd_InvalidType(t *testing.T) {
	sc := &keysTestContainer{
		MockServiceContainer: &testutils.MockServiceContainer{},
	}
	ctx := buildAdminCtx(sc)
	cmd, _ := newTestCmd(createCmd.RunE, nil)
	setFlags(cmd, map[string]any{"name": "mykey", "type": "INVALID"})
	cmd.SetContext(ctx)
	err := cmd.Execute()
	assert.ErrorContains(t, err, "invalid key type")
}

func TestCreateCmd_RSASuccess(t *testing.T) {
	keySvc := &keyCmdKeyService{}
	userID := uuid.New()
	sc, vaultID := newAllowedContainer(keySvc, nil)
	result := &keyServices.CreateKeyResult{
		KeyID: uuid.New(), Name: "mykey", Type: "RSA", CreatedAt: time.Now(),
	}
	keySvc.On("CreateRSAKey", mock.Anything, mock.MatchedBy(func(r keyServices.CreateKeyRequest) bool {
		return r.Name == "mykey" && r.Type == "RSA" && r.Bits == 2048 && r.VaultID == vaultID
	})).Return(result, nil)

	claims := &model.Claims{UserID: userID, Roles: []string{model.RoleAdmin}}
	ctx := context.WithValue(context.Background(), common.ClaimsKey, claims)
	ctx = context.WithValue(ctx, common.LogKey, newLogger())
	ctx = context.WithValue(ctx, common.ServiceContainerKey, sc)
	ctx = context.WithValue(ctx, common.OutputFormatterKey, newTestFmtr())

	cmd, buf := newTestCmd(createCmd.RunE, nil)
	setFlags(cmd, map[string]any{"name": "mykey", "type": "RSA", "bits": 2048, "curve": "P-256", "tags": ""})
	cmd.SetContext(ctx)
	err := cmd.Execute()
	assert.NoError(t, err)
	assert.NotEmpty(t, buf.String())
	keySvc.AssertExpectations(t)
}

// ========== importCmd tests ==========

func TestImportCmd_MissingName(t *testing.T) {
	sc := &keysTestContainer{
		MockServiceContainer: &testutils.MockServiceContainer{},
	}
	ctx := buildAdminCtx(sc)
	cmd, _ := newTestCmd(importCmd.RunE, nil)
	setFlags(cmd, map[string]any{"name": "", "jwk": `{"kty":"RSA"}`})
	cmd.SetContext(ctx)
	err := cmd.Execute()
	assert.ErrorContains(t, err, "name is required")
}

func TestImportCmd_MissingJWK(t *testing.T) {
	sc := &keysTestContainer{
		MockServiceContainer: &testutils.MockServiceContainer{},
	}
	ctx := buildAdminCtx(sc)
	cmd, _ := newTestCmd(importCmd.RunE, nil)
	setFlags(cmd, map[string]any{"name": "imported-key", "jwk": "", "jwk-file": ""})
	cmd.SetContext(ctx)
	err := cmd.Execute()
	assert.ErrorContains(t, err, "--jwk or --jwk-file is required")
}

func TestImportCmd_BothJWKFlags_MutuallyExclusive(t *testing.T) {
	sc := &keysTestContainer{
		MockServiceContainer: &testutils.MockServiceContainer{},
	}
	ctx := buildAdminCtx(sc)
	cmd, _ := newTestCmd(importCmd.RunE, nil)
	setFlags(cmd, map[string]any{"name": "imported-key", "jwk": `{"kty":"RSA"}`, "jwk-file": "/tmp/x.json"})
	cmd.SetContext(ctx)
	err := cmd.Execute()
	assert.ErrorContains(t, err, "mutually exclusive")
}

func TestImportCmd_Success(t *testing.T) {
	keySvc := &keyCmdKeyService{}
	userID := uuid.New()
	sc, vaultID := newAllowedContainer(keySvc, nil)
	result := &keyServices.CreateKeyResult{
		KeyID: uuid.New(), Name: "imported-key", Type: "RSA", CreatedAt: time.Now(),
	}
	keySvc.On("ImportKey", mock.Anything, mock.MatchedBy(func(r keyServices.ImportKeyRequest) bool {
		return r.Name == "imported-key" && r.VaultID == vaultID && len(r.JWK) > 0
	})).Return(result, nil)

	claims := &model.Claims{UserID: userID, Roles: []string{model.RoleAdmin}}
	ctx := context.WithValue(context.Background(), common.ClaimsKey, claims)
	ctx = context.WithValue(ctx, common.LogKey, newLogger())
	ctx = context.WithValue(ctx, common.ServiceContainerKey, sc)
	ctx = context.WithValue(ctx, common.OutputFormatterKey, newTestFmtr())

	cmd, buf := newTestCmd(importCmd.RunE, nil)
	setFlags(cmd, map[string]any{"name": "imported-key", "jwk": `{"kty":"RSA","n":"...","e":"AQAB","d":"..."}`, "tags": ""})
	cmd.SetContext(ctx)
	err := cmd.Execute()
	assert.NoError(t, err)
	assert.NotEmpty(t, buf.String())
	keySvc.AssertExpectations(t)
}

func TestImportCmd_JWKFile(t *testing.T) {
	tmpFile, err := os.CreateTemp(t.TempDir(), "test-*.jwk.json")
	require.NoError(t, err)
	_, err = tmpFile.WriteString(`{"kty":"RSA","n":"...","e":"AQAB","d":"..."}`)
	require.NoError(t, err)
	require.NoError(t, tmpFile.Close())

	keySvc := &keyCmdKeyService{}
	sc, _ := newAllowedContainer(keySvc, nil)
	result := &keyServices.CreateKeyResult{KeyID: uuid.New(), Name: "from-file", Type: "RSA", CreatedAt: time.Now()}
	keySvc.On("ImportKey", mock.Anything, mock.Anything).Return(result, nil)

	ctx := buildAdminCtx(sc)

	cmd, buf := newTestCmd(importCmd.RunE, nil)
	setFlags(cmd, map[string]any{"name": "from-file", "jwk-file": tmpFile.Name(), "jwk": ""})
	cmd.SetContext(ctx)
	err = cmd.Execute()
	assert.NoError(t, err)
	assert.NotEmpty(t, buf.String())
	keySvc.AssertExpectations(t)
}

func TestKeysCreateBitsFlagDocumentsAllAcceptedSizes(t *testing.T) {
	flag := createCmd.Flags().Lookup("bits")
	if flag == nil {
		t.Fatal("--bits flag not registered on keys create")
	}
	assert.Equal(t, "RSA key size in bits (2048, 3072 or 4096)", flag.Usage)
}

func TestCreateCmd_Denied(t *testing.T) {
	keySvc := &keyCmdKeyService{}
	userID := uuid.New()
	sc := newDeniedContainer(keySvc, nil)

	claims := &model.Claims{UserID: userID, Roles: []string{model.RoleAdmin}}
	ctx := context.WithValue(context.Background(), common.ClaimsKey, claims)
	ctx = context.WithValue(ctx, common.LogKey, newLogger())
	ctx = context.WithValue(ctx, common.ServiceContainerKey, sc)
	ctx = context.WithValue(ctx, common.OutputFormatterKey, newTestFmtr())

	cmd, _ := newTestCmd(createCmd.RunE, nil)
	setFlags(cmd, map[string]any{"name": "mykey", "type": "RSA", "bits": 2048, "curve": "P-256", "tags": ""})
	cmd.SetContext(ctx)
	err := cmd.Execute()
	assert.ErrorContains(t, err, "forbidden")
	keySvc.AssertNotCalled(t, "CreateRSAKey", mock.Anything, mock.Anything)
	keySvc.AssertNotCalled(t, "CreateECDSAKey", mock.Anything, mock.Anything)
}

func TestCreateCmd_Authorized(t *testing.T) {
	keySvc := &keyCmdKeyService{}
	userID := uuid.New()
	sc, vaultID := newAllowedContainer(keySvc, nil)

	roles := &testutils.MockRoleAssignmentService{}
	roles.On("HasDataAction", mock.Anything, userID, vaultID, model.ActionKeysCreate).
		Return(true, nil).Once()
	policies := &testutils.MockAccessPolicyService{}
	policies.On("CheckAccess", mock.Anything, userID, model.PolicyResourceKeys, model.OpCreate, vaultID).
		Return(authzServices.AccessAllowed, nil).Once()
	sc.RoleAssignmentService = roles
	sc.AccessPolicyService = policies

	result := &keyServices.CreateKeyResult{
		KeyID: uuid.New(), Name: "mykey", Type: "RSA", CreatedAt: time.Now(),
	}
	keySvc.On("CreateRSAKey", mock.Anything, mock.MatchedBy(func(r keyServices.CreateKeyRequest) bool {
		return r.Name == "mykey" && r.Type == "RSA" && r.Bits == 2048 && r.VaultID == vaultID
	})).Return(result, nil)

	claims := &model.Claims{UserID: userID, Roles: []string{model.RoleAdmin}}
	ctx := context.WithValue(context.Background(), common.ClaimsKey, claims)
	ctx = context.WithValue(ctx, common.LogKey, newLogger())
	ctx = context.WithValue(ctx, common.ServiceContainerKey, sc)
	ctx = context.WithValue(ctx, common.OutputFormatterKey, newTestFmtr())

	cmd, _ := newTestCmd(createCmd.RunE, nil)
	setFlags(cmd, map[string]any{"name": "mykey", "type": "RSA", "bits": 2048, "curve": "P-256", "tags": ""})
	cmd.SetContext(ctx)
	err := cmd.Execute()
	assert.NoError(t, err)
	keySvc.AssertExpectations(t)
	roles.AssertExpectations(t)
	policies.AssertExpectations(t)
}

func TestCreateCmd_MultiRoleCaller_PrivilegedRoleNotFirst_Allowed(t *testing.T) {
	keySvc := &keyCmdKeyService{}
	userID := uuid.New()
	sc, vaultID := newAllowedContainer(keySvc, nil)
	result := &keyServices.CreateKeyResult{
		KeyID: uuid.New(), Name: "mykey", Type: "RSA", CreatedAt: time.Now(),
	}
	keySvc.On("CreateRSAKey", mock.Anything, mock.MatchedBy(func(r keyServices.CreateKeyRequest) bool {
		return r.Name == "mykey" && r.Type == "RSA" && r.Bits == 2048 && r.VaultID == vaultID
	})).Return(result, nil)

	// The privileged role (crypto_manager) is second in Roles, not first, to
	// prove common.HasAnyRole is used at this call site rather than only
	// checking claims.Roles[0].
	claims := &model.Claims{UserID: userID, Roles: []string{model.RoleUser, model.RoleCryptoManager}}
	ctx := context.WithValue(context.Background(), common.ClaimsKey, claims)
	ctx = context.WithValue(ctx, common.LogKey, newLogger())
	ctx = context.WithValue(ctx, common.ServiceContainerKey, sc)
	ctx = context.WithValue(ctx, common.OutputFormatterKey, newTestFmtr())

	cmd, _ := newTestCmd(createCmd.RunE, nil)
	setFlags(cmd, map[string]any{"name": "mykey", "type": "RSA", "bits": 2048, "curve": "P-256", "tags": ""})
	cmd.SetContext(ctx)
	err := cmd.Execute()
	assert.NoError(t, err)
	keySvc.AssertExpectations(t)
}

func TestCreateCmd_RSAWithTags(t *testing.T) {
	keySvc := &keyCmdKeyService{}
	userID := uuid.New()
	sc, vaultID := newAllowedContainer(keySvc, nil)
	result := &keyServices.CreateKeyResult{
		KeyID: uuid.New(), Name: "tagged-key", Type: "RSA", Tags: []string{"prod", "infra"}, CreatedAt: time.Now(),
	}
	keySvc.On("CreateRSAKey", mock.Anything, mock.MatchedBy(func(r keyServices.CreateKeyRequest) bool {
		return r.Name == "tagged-key" && len(r.Tags) == 2 && r.VaultID == vaultID
	})).Return(result, nil)

	claims := &model.Claims{UserID: userID, Roles: []string{model.RoleAdmin}}
	ctx := context.WithValue(context.Background(), common.ClaimsKey, claims)
	ctx = context.WithValue(ctx, common.LogKey, newLogger())
	ctx = context.WithValue(ctx, common.ServiceContainerKey, sc)
	ctx = context.WithValue(ctx, common.OutputFormatterKey, newTestFmtr())

	cmd, _ := newTestCmd(createCmd.RunE, nil)
	setFlags(cmd, map[string]any{"name": "tagged-key", "type": "rsa", "bits": 2048, "curve": "P-256", "tags": "prod,infra"})
	cmd.SetContext(ctx)
	err := cmd.Execute()
	assert.NoError(t, err)
	keySvc.AssertExpectations(t)
}

func TestCreateCmd_ECDSASuccess(t *testing.T) {
	keySvc := &keyCmdKeyService{}
	userID := uuid.New()
	sc, vaultID := newAllowedContainer(keySvc, nil)
	result := &keyServices.CreateKeyResult{
		KeyID: uuid.New(), Name: "eckey", Type: "ECDSA", CreatedAt: time.Now(),
	}
	keySvc.On("CreateECDSAKey", mock.Anything, mock.MatchedBy(func(r keyServices.CreateKeyRequest) bool {
		return r.Name == "eckey" && r.Type == "ECDSA" && r.Curve == "P-256" && r.VaultID == vaultID
	})).Return(result, nil)

	claims := &model.Claims{UserID: userID, Roles: []string{model.RoleCryptoManager}}
	ctx := context.WithValue(context.Background(), common.ClaimsKey, claims)
	ctx = context.WithValue(ctx, common.LogKey, newLogger())
	ctx = context.WithValue(ctx, common.ServiceContainerKey, sc)
	ctx = context.WithValue(ctx, common.OutputFormatterKey, newTestFmtr())

	cmd, _ := newTestCmd(createCmd.RunE, nil)
	setFlags(cmd, map[string]any{"name": "eckey", "type": "ECDSA", "bits": 2048, "curve": "P-256", "tags": ""})
	cmd.SetContext(ctx)
	err := cmd.Execute()
	assert.NoError(t, err)
	keySvc.AssertExpectations(t)
}

func TestCreateCmd_ServiceError(t *testing.T) {
	keySvc := &keyCmdKeyService{}
	userID := uuid.New()
	sc, _ := newAllowedContainer(keySvc, nil)
	keySvc.On("CreateRSAKey", mock.Anything, mock.Anything).Return(nil, fmt.Errorf("db error"))

	claims := &model.Claims{UserID: userID, Roles: []string{model.RoleAdmin}}
	ctx := context.WithValue(context.Background(), common.ClaimsKey, claims)
	ctx = context.WithValue(ctx, common.LogKey, newLogger())
	ctx = context.WithValue(ctx, common.ServiceContainerKey, sc)
	ctx = context.WithValue(ctx, common.OutputFormatterKey, newTestFmtr())

	cmd, _ := newTestCmd(createCmd.RunE, nil)
	setFlags(cmd, map[string]any{"name": "failkey", "type": "RSA", "bits": 2048, "curve": "", "tags": ""})
	cmd.SetContext(ctx)
	err := cmd.Execute()
	assert.ErrorContains(t, err, "failed to create key")
}

func TestCreateCmd_NoFormatter(t *testing.T) {
	keySvc := &keyCmdKeyService{}
	userID := uuid.New()
	sc, _ := newAllowedContainer(keySvc, nil)
	result := &keyServices.CreateKeyResult{KeyID: uuid.New(), Name: "k", Type: "RSA", CreatedAt: time.Now()}
	keySvc.On("CreateRSAKey", mock.Anything, mock.Anything).Return(result, nil)

	claims := &model.Claims{UserID: userID, Roles: []string{model.RoleAdmin}}
	ctx := context.WithValue(context.Background(), common.ClaimsKey, claims)
	ctx = context.WithValue(ctx, common.LogKey, newLogger())
	ctx = context.WithValue(ctx, common.ServiceContainerKey, sc)
	// No OutputFormatterKey.

	cmd, _ := newTestCmd(createCmd.RunE, nil)
	setFlags(cmd, map[string]any{"name": "k", "type": "RSA", "bits": 2048, "curve": "", "tags": ""})
	cmd.SetContext(ctx)
	err := cmd.Execute()
	assert.ErrorContains(t, err, "output formatter not available")
}

// ========== listCmd tests ==========

func TestListCmd_NoClaims(t *testing.T) {
	ctx := context.Background()
	cmd, _ := newTestCmd(listCmd.RunE, nil)
	cmd.SetContext(ctx)
	err := cmd.Execute()
	assert.ErrorContains(t, err, "unauthorized")
}

func TestListCmd_NoServiceContainer(t *testing.T) {
	claims := &model.Claims{UserID: uuid.New(), Roles: []string{model.RoleAdmin}}
	ctx := context.WithValue(context.Background(), common.ClaimsKey, claims)
	ctx = context.WithValue(ctx, common.LogKey, newLogger())
	cmd, _ := newTestCmd(listCmd.RunE, nil)
	cmd.SetContext(ctx)
	err := cmd.Execute()
	assert.ErrorContains(t, err, "service container not available")
}

func TestListCmd_NonAdminSuccess(t *testing.T) {
	keySvc := &keyCmdKeyService{}
	userID := uuid.New()
	sc, vaultID := newAllowedContainer(keySvc, nil)
	keys := []model.Key{
		{ID: uuid.New(), UserID: userID, Name: "k1", Type: "RSA"},
		{ID: uuid.New(), UserID: userID, Name: "k2", Type: "ECDSA"},
	}
	keySvc.On("ListKeys", mock.Anything, model.NewVaultScope(vaultID, userID), repositories.KeyFilter{Type: "", Tags: nil}).
		Return(keys, nil)

	claims := &model.Claims{UserID: userID, Roles: []string{model.RoleSecretsManager}}
	ctx := context.WithValue(context.Background(), common.ClaimsKey, claims)
	ctx = context.WithValue(ctx, common.LogKey, newLogger())
	ctx = context.WithValue(ctx, common.ServiceContainerKey, sc)
	ctx = context.WithValue(ctx, common.OutputFormatterKey, newTestFmtr())

	cmd, buf := newTestCmd(listCmd.RunE, nil)
	setFlags(cmd, map[string]any{"type": "", "tags": ""})
	cmd.SetContext(ctx)
	err := cmd.Execute()
	assert.NoError(t, err)
	assert.NotEmpty(t, buf.String())
	keySvc.AssertExpectations(t)
}

func TestListCmd_Denied(t *testing.T) {
	keySvc := &keyCmdKeyService{}
	userID := uuid.New()
	sc := newDeniedContainer(keySvc, nil)

	claims := &model.Claims{UserID: userID, Roles: []string{model.RoleSecretsManager}}
	ctx := context.WithValue(context.Background(), common.ClaimsKey, claims)
	ctx = context.WithValue(ctx, common.LogKey, newLogger())
	ctx = context.WithValue(ctx, common.ServiceContainerKey, sc)
	ctx = context.WithValue(ctx, common.OutputFormatterKey, newTestFmtr())

	cmd, _ := newTestCmd(listCmd.RunE, nil)
	setFlags(cmd, map[string]any{"type": "", "tags": ""})
	cmd.SetContext(ctx)
	err := cmd.Execute()
	assert.ErrorContains(t, err, "forbidden")
	keySvc.AssertNotCalled(t, "ListKeys", mock.Anything, mock.Anything, mock.Anything)
}

func TestListCmd_Authorized(t *testing.T) {
	keySvc := &keyCmdKeyService{}
	userID := uuid.New()
	sc, vaultID := newAllowedContainer(keySvc, nil)

	roles := &testutils.MockRoleAssignmentService{}
	roles.On("HasDataAction", mock.Anything, userID, vaultID, model.ActionKeysRead).
		Return(true, nil).Once()
	policies := &testutils.MockAccessPolicyService{}
	policies.On("CheckAccess", mock.Anything, userID, model.PolicyResourceKeys, model.OpGet, vaultID).
		Return(authzServices.AccessAllowed, nil).Once()
	sc.RoleAssignmentService = roles
	sc.AccessPolicyService = policies

	keys := []model.Key{
		{ID: uuid.New(), UserID: userID, Name: "k1", Type: "RSA"},
	}
	keySvc.On("ListKeys", mock.Anything, model.NewVaultScope(vaultID, userID), repositories.KeyFilter{Type: "", Tags: nil}).
		Return(keys, nil)

	claims := &model.Claims{UserID: userID, Roles: []string{model.RoleSecretsManager}}
	ctx := context.WithValue(context.Background(), common.ClaimsKey, claims)
	ctx = context.WithValue(ctx, common.LogKey, newLogger())
	ctx = context.WithValue(ctx, common.ServiceContainerKey, sc)
	ctx = context.WithValue(ctx, common.OutputFormatterKey, newTestFmtr())

	cmd, _ := newTestCmd(listCmd.RunE, nil)
	setFlags(cmd, map[string]any{"type": "", "tags": ""})
	cmd.SetContext(ctx)
	err := cmd.Execute()
	assert.NoError(t, err)
	keySvc.AssertExpectations(t)
	roles.AssertExpectations(t)
	policies.AssertExpectations(t)
}

func TestListCmd_NonAdminWithTags(t *testing.T) {
	keySvc := &keyCmdKeyService{}
	userID := uuid.New()
	sc, vaultID := newAllowedContainer(keySvc, nil)
	keySvc.On("ListKeys", mock.Anything, model.NewVaultScope(vaultID, userID), repositories.KeyFilter{Type: "RSA", Tags: []string{"prod", "secure"}}).
		Return([]model.Key{}, nil)

	claims := &model.Claims{UserID: userID, Roles: []string{model.RoleUser}}
	ctx := context.WithValue(context.Background(), common.ClaimsKey, claims)
	ctx = context.WithValue(ctx, common.LogKey, newLogger())
	ctx = context.WithValue(ctx, common.ServiceContainerKey, sc)
	ctx = context.WithValue(ctx, common.OutputFormatterKey, newTestFmtr())

	cmd, _ := newTestCmd(listCmd.RunE, nil)
	setFlags(cmd, map[string]any{"type": "RSA", "tags": "prod,secure"})
	cmd.SetContext(ctx)
	err := cmd.Execute()
	assert.NoError(t, err)
	keySvc.AssertExpectations(t)
}

func TestListCmd_AdminRoleAloneDoesNotBypassVaultAuthorization(t *testing.T) {
	keySvc := &keyCmdKeyService{}
	userID := uuid.New()
	// A global admin role with NO vault role assignment: the legacy
	// list.go admin bypass (model.NewAdminScope) has been removed, so this
	// must be denied exactly like TestListCmd_Denied, matching HTTP's
	// GET /keys (scopeFromRequest has no role-based special case).
	sc := newDeniedContainer(keySvc, nil)

	claims := &model.Claims{UserID: userID, Roles: []string{model.RoleAdmin}}
	ctx := context.WithValue(context.Background(), common.ClaimsKey, claims)
	ctx = context.WithValue(ctx, common.LogKey, newLogger())
	ctx = context.WithValue(ctx, common.ServiceContainerKey, sc)
	ctx = context.WithValue(ctx, common.OutputFormatterKey, newTestFmtr())

	cmd, _ := newTestCmd(listCmd.RunE, nil)
	setFlags(cmd, map[string]any{"type": "", "tags": ""})
	cmd.SetContext(ctx)
	err := cmd.Execute()
	assert.ErrorContains(t, err, "forbidden")
	keySvc.AssertNotCalled(t, "ListKeys", mock.Anything, mock.Anything, mock.Anything)
	// In particular, ListKeys must never be called with model.NewAdminScope:
	// that call pattern must not exist anywhere in list.go anymore.
	keySvc.AssertNotCalled(t, "ListKeys", mock.Anything, model.NewAdminScope(userID), mock.Anything)
}

func TestListCmd_ServiceError(t *testing.T) {
	keySvc := &keyCmdKeyService{}
	userID := uuid.New()
	sc, vaultID := newAllowedContainer(keySvc, nil)
	keySvc.On("ListKeys", mock.Anything, model.NewVaultScope(vaultID, userID), repositories.KeyFilter{Type: "", Tags: nil}).
		Return(nil, fmt.Errorf("db error"))

	claims := &model.Claims{UserID: userID, Roles: []string{model.RoleSecretsManager}}
	ctx := context.WithValue(context.Background(), common.ClaimsKey, claims)
	ctx = context.WithValue(ctx, common.LogKey, newLogger())
	ctx = context.WithValue(ctx, common.ServiceContainerKey, sc)
	ctx = context.WithValue(ctx, common.OutputFormatterKey, newTestFmtr())

	cmd, _ := newTestCmd(listCmd.RunE, nil)
	setFlags(cmd, map[string]any{"type": "", "tags": ""})
	cmd.SetContext(ctx)
	err := cmd.Execute()
	assert.ErrorContains(t, err, "failed to list keys")
}

func TestListCmd_NoFormatter(t *testing.T) {
	keySvc := &keyCmdKeyService{}
	userID := uuid.New()
	sc, vaultID := newAllowedContainer(keySvc, nil)
	keySvc.On("ListKeys", mock.Anything, model.NewVaultScope(vaultID, userID), repositories.KeyFilter{Type: "", Tags: nil}).
		Return([]model.Key{}, nil)

	claims := &model.Claims{UserID: userID, Roles: []string{model.RoleUser}}
	ctx := context.WithValue(context.Background(), common.ClaimsKey, claims)
	ctx = context.WithValue(ctx, common.LogKey, newLogger())
	ctx = context.WithValue(ctx, common.ServiceContainerKey, sc)
	// No OutputFormatterKey.

	cmd, _ := newTestCmd(listCmd.RunE, nil)
	setFlags(cmd, map[string]any{"type": "", "tags": ""})
	cmd.SetContext(ctx)
	err := cmd.Execute()
	assert.ErrorContains(t, err, "output formatter not available")
}

// ========== getCmd tests ==========

func TestGetCmd_NoClaims(t *testing.T) {
	ctx := context.Background()
	cmd, _ := newTestCmd(getCmd.RunE, []string{uuid.New().String()})
	cmd.Args = cobra.ExactArgs(1)
	cmd.SetContext(ctx)
	err := cmd.Execute()
	assert.ErrorContains(t, err, "unauthorized")
}

func TestGetCmd_InvalidUUID(t *testing.T) {
	claims := &model.Claims{UserID: uuid.New(), Roles: []string{model.RoleAdmin}}
	ctx := context.WithValue(context.Background(), common.ClaimsKey, claims)
	ctx = context.WithValue(ctx, common.LogKey, newLogger())
	cmd, _ := newTestCmd(getCmd.RunE, []string{"not-a-uuid"})
	cmd.Args = cobra.ExactArgs(1)
	cmd.SetContext(ctx)
	err := cmd.Execute()
	assert.ErrorContains(t, err, "invalid key ID")
}

func TestGetCmd_NoServiceContainer(t *testing.T) {
	claims := &model.Claims{UserID: uuid.New(), Roles: []string{model.RoleAdmin}}
	ctx := context.WithValue(context.Background(), common.ClaimsKey, claims)
	ctx = context.WithValue(ctx, common.LogKey, newLogger())
	cmd, _ := newTestCmd(getCmd.RunE, []string{uuid.New().String()})
	cmd.Args = cobra.ExactArgs(1)
	cmd.SetContext(ctx)
	err := cmd.Execute()
	assert.ErrorContains(t, err, "service container not available")
}

func TestGetCmd_Success(t *testing.T) {
	keySvc := &keyCmdKeyService{}
	userID := uuid.New()
	keyID := uuid.New()
	sc, vaultID := newAllowedContainer(keySvc, nil)
	key := &model.Key{ID: keyID, UserID: userID, Name: "my-key", Type: "RSA", CreatedAt: time.Now()}
	keySvc.On("GetKey", mock.Anything, keyID, model.NewVaultScope(vaultID, userID)).Return(key, nil)

	claims := &model.Claims{UserID: userID, Roles: []string{model.RoleAdmin}}
	ctx := context.WithValue(context.Background(), common.ClaimsKey, claims)
	ctx = context.WithValue(ctx, common.LogKey, newLogger())
	ctx = context.WithValue(ctx, common.ServiceContainerKey, sc)
	ctx = context.WithValue(ctx, common.OutputFormatterKey, newTestFmtr())

	cmd, buf := newTestCmd(getCmd.RunE, []string{keyID.String()})
	cmd.Args = cobra.ExactArgs(1)
	cmd.SetContext(ctx)
	err := cmd.Execute()
	assert.NoError(t, err)
	assert.NotEmpty(t, buf.String())
	keySvc.AssertExpectations(t)
}

func TestGetCmd_Denied(t *testing.T) {
	keySvc := &keyCmdKeyService{}
	userID := uuid.New()
	keyID := uuid.New()
	sc := newDeniedContainer(keySvc, nil)

	claims := &model.Claims{UserID: userID, Roles: []string{model.RoleAdmin}}
	ctx := context.WithValue(context.Background(), common.ClaimsKey, claims)
	ctx = context.WithValue(ctx, common.LogKey, newLogger())
	ctx = context.WithValue(ctx, common.ServiceContainerKey, sc)
	ctx = context.WithValue(ctx, common.OutputFormatterKey, newTestFmtr())

	cmd, _ := newTestCmd(getCmd.RunE, []string{keyID.String()})
	cmd.Args = cobra.ExactArgs(1)
	cmd.SetContext(ctx)
	err := cmd.Execute()
	assert.ErrorContains(t, err, "forbidden")
	keySvc.AssertNotCalled(t, "GetKey", mock.Anything, mock.Anything, mock.Anything)
}

func TestGetCmd_Authorized(t *testing.T) {
	keySvc := &keyCmdKeyService{}
	userID := uuid.New()
	keyID := uuid.New()
	sc, vaultID := newAllowedContainer(keySvc, nil)

	roles := &testutils.MockRoleAssignmentService{}
	roles.On("HasDataAction", mock.Anything, userID, vaultID, model.ActionKeysRead).
		Return(true, nil).Once()
	policies := &testutils.MockAccessPolicyService{}
	policies.On("CheckAccess", mock.Anything, userID, model.PolicyResourceKeys, model.OpGet, vaultID).
		Return(authzServices.AccessAllowed, nil).Once()
	sc.RoleAssignmentService = roles
	sc.AccessPolicyService = policies

	key := &model.Key{ID: keyID, UserID: userID, Name: "my-key", Type: "RSA", CreatedAt: time.Now()}
	keySvc.On("GetKey", mock.Anything, keyID, model.NewVaultScope(vaultID, userID)).Return(key, nil)

	claims := &model.Claims{UserID: userID, Roles: []string{model.RoleAdmin}}
	ctx := context.WithValue(context.Background(), common.ClaimsKey, claims)
	ctx = context.WithValue(ctx, common.LogKey, newLogger())
	ctx = context.WithValue(ctx, common.ServiceContainerKey, sc)
	ctx = context.WithValue(ctx, common.OutputFormatterKey, newTestFmtr())

	cmd, _ := newTestCmd(getCmd.RunE, []string{keyID.String()})
	cmd.Args = cobra.ExactArgs(1)
	cmd.SetContext(ctx)
	err := cmd.Execute()
	assert.NoError(t, err)
	keySvc.AssertExpectations(t)
	roles.AssertExpectations(t)
	policies.AssertExpectations(t)
}

func TestGetCmd_ServiceError(t *testing.T) {
	keySvc := &keyCmdKeyService{}
	userID := uuid.New()
	keyID := uuid.New()
	sc, vaultID := newAllowedContainer(keySvc, nil)
	keySvc.On("GetKey", mock.Anything, keyID, model.NewVaultScope(vaultID, userID)).Return(nil, fmt.Errorf("not found"))

	claims := &model.Claims{UserID: userID, Roles: []string{model.RoleAdmin}}
	ctx := context.WithValue(context.Background(), common.ClaimsKey, claims)
	ctx = context.WithValue(ctx, common.LogKey, newLogger())
	ctx = context.WithValue(ctx, common.ServiceContainerKey, sc)
	ctx = context.WithValue(ctx, common.OutputFormatterKey, newTestFmtr())

	cmd, _ := newTestCmd(getCmd.RunE, []string{keyID.String()})
	cmd.Args = cobra.ExactArgs(1)
	cmd.SetContext(ctx)
	err := cmd.Execute()
	assert.ErrorContains(t, err, "failed to get key")
}

func TestGetCmd_NoFormatter(t *testing.T) {
	keySvc := &keyCmdKeyService{}
	userID := uuid.New()
	keyID := uuid.New()
	sc, vaultID := newAllowedContainer(keySvc, nil)
	key := &model.Key{ID: keyID, UserID: userID, Name: "k", Type: "RSA", CreatedAt: time.Now()}
	keySvc.On("GetKey", mock.Anything, keyID, model.NewVaultScope(vaultID, userID)).Return(key, nil)

	claims := &model.Claims{UserID: userID, Roles: []string{model.RoleAdmin}}
	ctx := context.WithValue(context.Background(), common.ClaimsKey, claims)
	ctx = context.WithValue(ctx, common.LogKey, newLogger())
	ctx = context.WithValue(ctx, common.ServiceContainerKey, sc)
	// No formatter.

	cmd, _ := newTestCmd(getCmd.RunE, []string{keyID.String()})
	cmd.Args = cobra.ExactArgs(1)
	cmd.SetContext(ctx)
	err := cmd.Execute()
	assert.ErrorContains(t, err, "output formatter not available")
}

// ========== deleteCmd tests ==========

func TestDeleteCmd_NoClaims(t *testing.T) {
	ctx := context.Background()
	cmd, _ := newTestCmd(deleteCmd.RunE, []string{uuid.New().String()})
	cmd.Args = cobra.ExactArgs(1)
	cmd.SetContext(ctx)
	err := cmd.Execute()
	assert.ErrorContains(t, err, "unauthorized")
}

func TestDeleteCmd_InvalidUUID(t *testing.T) {
	claims := &model.Claims{UserID: uuid.New(), Roles: []string{model.RoleAdmin}}
	ctx := context.WithValue(context.Background(), common.ClaimsKey, claims)
	ctx = context.WithValue(ctx, common.LogKey, newLogger())
	cmd, _ := newTestCmd(deleteCmd.RunE, []string{"bad-uuid"})
	cmd.Args = cobra.ExactArgs(1)
	cmd.SetContext(ctx)
	err := cmd.Execute()
	assert.ErrorContains(t, err, "invalid key ID")
}

func TestDeleteCmd_NoServiceContainer(t *testing.T) {
	claims := &model.Claims{UserID: uuid.New(), Roles: []string{model.RoleAdmin}}
	ctx := context.WithValue(context.Background(), common.ClaimsKey, claims)
	ctx = context.WithValue(ctx, common.LogKey, newLogger())
	cmd, _ := newTestCmd(deleteCmd.RunE, []string{uuid.New().String()})
	cmd.Args = cobra.ExactArgs(1)
	cmd.SetContext(ctx)
	err := cmd.Execute()
	assert.ErrorContains(t, err, "service container not available")
}

func TestDeleteCmd_Success(t *testing.T) {
	keySvc := &keyCmdKeyService{}
	userID := uuid.New()
	keyID := uuid.New()
	sc, vaultID := newAllowedContainer(keySvc, nil)
	keySvc.On("DeleteKey", mock.Anything, keyID, model.NewVaultScope(vaultID, userID)).Return(nil, nil)

	claims := &model.Claims{UserID: userID, Roles: []string{model.RoleAdmin}}
	ctx := context.WithValue(context.Background(), common.ClaimsKey, claims)
	ctx = context.WithValue(ctx, common.LogKey, newLogger())
	ctx = context.WithValue(ctx, common.ServiceContainerKey, sc)

	cmd, _ := newTestCmd(deleteCmd.RunE, []string{keyID.String()})
	cmd.Args = cobra.ExactArgs(1)
	cmd.SetContext(ctx)
	err := cmd.Execute()
	assert.NoError(t, err)
	keySvc.AssertExpectations(t)
}

func TestDeleteCmd_Denied(t *testing.T) {
	keySvc := &keyCmdKeyService{}
	userID := uuid.New()
	keyID := uuid.New()
	sc := newDeniedContainer(keySvc, nil)

	claims := &model.Claims{UserID: userID, Roles: []string{model.RoleAdmin}}
	ctx := context.WithValue(context.Background(), common.ClaimsKey, claims)
	ctx = context.WithValue(ctx, common.LogKey, newLogger())
	ctx = context.WithValue(ctx, common.ServiceContainerKey, sc)

	cmd, _ := newTestCmd(deleteCmd.RunE, []string{keyID.String()})
	cmd.Args = cobra.ExactArgs(1)
	cmd.SetContext(ctx)
	err := cmd.Execute()
	assert.ErrorContains(t, err, "forbidden")
	keySvc.AssertNotCalled(t, "DeleteKey", mock.Anything, mock.Anything, mock.Anything)
}

func TestDeleteCmd_Authorized(t *testing.T) {
	keySvc := &keyCmdKeyService{}
	userID := uuid.New()
	keyID := uuid.New()
	sc, vaultID := newAllowedContainer(keySvc, nil)

	roles := &testutils.MockRoleAssignmentService{}
	roles.On("HasDataAction", mock.Anything, userID, vaultID, model.ActionKeysDelete).
		Return(true, nil).Once()
	policies := &testutils.MockAccessPolicyService{}
	policies.On("CheckAccess", mock.Anything, userID, model.PolicyResourceKeys, model.OpDelete, vaultID).
		Return(authzServices.AccessAllowed, nil).Once()
	sc.RoleAssignmentService = roles
	sc.AccessPolicyService = policies

	keySvc.On("DeleteKey", mock.Anything, keyID, model.NewVaultScope(vaultID, userID)).Return(nil, nil)

	claims := &model.Claims{UserID: userID, Roles: []string{model.RoleAdmin}}
	ctx := context.WithValue(context.Background(), common.ClaimsKey, claims)
	ctx = context.WithValue(ctx, common.LogKey, newLogger())
	ctx = context.WithValue(ctx, common.ServiceContainerKey, sc)

	cmd, _ := newTestCmd(deleteCmd.RunE, []string{keyID.String()})
	cmd.Args = cobra.ExactArgs(1)
	cmd.SetContext(ctx)
	err := cmd.Execute()
	assert.NoError(t, err)
	keySvc.AssertExpectations(t)
	roles.AssertExpectations(t)
	policies.AssertExpectations(t)
}

func TestDeleteCmd_ServiceError(t *testing.T) {
	keySvc := &keyCmdKeyService{}
	userID := uuid.New()
	keyID := uuid.New()
	sc, vaultID := newAllowedContainer(keySvc, nil)
	keySvc.On("DeleteKey", mock.Anything, keyID, model.NewVaultScope(vaultID, userID)).Return(nil, fmt.Errorf("delete failed"))

	claims := &model.Claims{UserID: userID, Roles: []string{model.RoleAdmin}}
	ctx := context.WithValue(context.Background(), common.ClaimsKey, claims)
	ctx = context.WithValue(ctx, common.LogKey, newLogger())
	ctx = context.WithValue(ctx, common.ServiceContainerKey, sc)

	cmd, _ := newTestCmd(deleteCmd.RunE, []string{keyID.String()})
	cmd.Args = cobra.ExactArgs(1)
	cmd.SetContext(ctx)
	err := cmd.Execute()
	assert.ErrorContains(t, err, "failed to delete key")
}

// ========== rotateCmd tests ==========

func TestRotateCmd_NoClaims(t *testing.T) {
	ctx := context.Background()
	cmd, _ := newTestCmd(rotateCmd.RunE, []string{uuid.New().String()})
	cmd.Args = cobra.ExactArgs(1)
	cmd.SetContext(ctx)
	err := cmd.Execute()
	assert.ErrorContains(t, err, "unauthorized")
}

func TestRotateCmd_InvalidUUID(t *testing.T) {
	claims := &model.Claims{UserID: uuid.New(), Roles: []string{model.RoleAdmin}}
	ctx := context.WithValue(context.Background(), common.ClaimsKey, claims)
	ctx = context.WithValue(ctx, common.LogKey, newLogger())
	cmd, _ := newTestCmd(rotateCmd.RunE, []string{"not-uuid"})
	cmd.Args = cobra.ExactArgs(1)
	cmd.SetContext(ctx)
	err := cmd.Execute()
	assert.ErrorContains(t, err, "invalid key ID")
}

func TestRotateCmd_NoServiceContainer(t *testing.T) {
	claims := &model.Claims{UserID: uuid.New(), Roles: []string{model.RoleAdmin}}
	ctx := context.WithValue(context.Background(), common.ClaimsKey, claims)
	ctx = context.WithValue(ctx, common.LogKey, newLogger())
	cmd, _ := newTestCmd(rotateCmd.RunE, []string{uuid.New().String()})
	cmd.Args = cobra.ExactArgs(1)
	cmd.SetContext(ctx)
	err := cmd.Execute()
	assert.ErrorContains(t, err, "service container not available")
}

func TestRotateCmd_Success(t *testing.T) {
	keySvc := &keyCmdKeyService{}
	userID := uuid.New()
	keyID := uuid.New()
	sc, vaultID := newAllowedContainer(keySvc, nil)
	result := &keyServices.CreateKeyResult{
		KeyID: keyID, Name: "rotated", Type: "RSA", CreatedAt: time.Now(),
	}
	keySvc.On("RotateKey", mock.Anything, keyID, model.NewVaultScope(vaultID, userID)).Return(result, nil)

	claims := &model.Claims{UserID: userID, Roles: []string{model.RoleAdmin}}
	ctx := context.WithValue(context.Background(), common.ClaimsKey, claims)
	ctx = context.WithValue(ctx, common.LogKey, newLogger())
	ctx = context.WithValue(ctx, common.ServiceContainerKey, sc)

	cmd, buf := newTestCmd(rotateCmd.RunE, []string{keyID.String()})
	cmd.Args = cobra.ExactArgs(1)
	cmd.SetContext(ctx)
	err := cmd.Execute()
	assert.NoError(t, err)
	keySvc.AssertExpectations(t)
	assert.Contains(t, buf.String(), "Key rotated successfully: ID="+keyID.String())
	assert.NotContains(t, buf.String(), "New Key", "the rotated key keeps its UUID; the output must not imply a new one")
}

func TestRotateCmd_Denied(t *testing.T) {
	keySvc := &keyCmdKeyService{}
	userID := uuid.New()
	keyID := uuid.New()
	sc := newDeniedContainer(keySvc, nil)

	claims := &model.Claims{UserID: userID, Roles: []string{model.RoleAdmin}}
	ctx := context.WithValue(context.Background(), common.ClaimsKey, claims)
	ctx = context.WithValue(ctx, common.LogKey, newLogger())
	ctx = context.WithValue(ctx, common.ServiceContainerKey, sc)

	cmd, _ := newTestCmd(rotateCmd.RunE, []string{keyID.String()})
	cmd.Args = cobra.ExactArgs(1)
	cmd.SetContext(ctx)
	err := cmd.Execute()
	assert.ErrorContains(t, err, "forbidden")
	keySvc.AssertNotCalled(t, "RotateKey", mock.Anything, mock.Anything, mock.Anything)
}

func TestRotateCmd_Authorized(t *testing.T) {
	keySvc := &keyCmdKeyService{}
	userID := uuid.New()
	keyID := uuid.New()
	sc, vaultID := newAllowedContainer(keySvc, nil)

	roles := &testutils.MockRoleAssignmentService{}
	roles.On("HasDataAction", mock.Anything, userID, vaultID, model.ActionKeysRotate).
		Return(true, nil).Once()
	policies := &testutils.MockAccessPolicyService{}
	policies.On("CheckAccess", mock.Anything, userID, model.PolicyResourceKeys, model.OpRotate, vaultID).
		Return(authzServices.AccessAllowed, nil).Once()
	sc.RoleAssignmentService = roles
	sc.AccessPolicyService = policies

	result := &keyServices.CreateKeyResult{
		KeyID: uuid.New(), Name: "rotated", Type: "RSA", CreatedAt: time.Now(),
	}
	keySvc.On("RotateKey", mock.Anything, keyID, model.NewVaultScope(vaultID, userID)).Return(result, nil)

	claims := &model.Claims{UserID: userID, Roles: []string{model.RoleAdmin}}
	ctx := context.WithValue(context.Background(), common.ClaimsKey, claims)
	ctx = context.WithValue(ctx, common.LogKey, newLogger())
	ctx = context.WithValue(ctx, common.ServiceContainerKey, sc)

	cmd, _ := newTestCmd(rotateCmd.RunE, []string{keyID.String()})
	cmd.Args = cobra.ExactArgs(1)
	cmd.SetContext(ctx)
	err := cmd.Execute()
	assert.NoError(t, err)
	keySvc.AssertExpectations(t)
	roles.AssertExpectations(t)
	policies.AssertExpectations(t)
}

func TestRotateCmd_ServiceError(t *testing.T) {
	keySvc := &keyCmdKeyService{}
	userID := uuid.New()
	keyID := uuid.New()
	sc, vaultID := newAllowedContainer(keySvc, nil)
	keySvc.On("RotateKey", mock.Anything, keyID, model.NewVaultScope(vaultID, userID)).Return(nil, fmt.Errorf("rotation failed"))

	claims := &model.Claims{UserID: userID, Roles: []string{model.RoleAdmin}}
	ctx := context.WithValue(context.Background(), common.ClaimsKey, claims)
	ctx = context.WithValue(ctx, common.LogKey, newLogger())
	ctx = context.WithValue(ctx, common.ServiceContainerKey, sc)

	cmd, _ := newTestCmd(rotateCmd.RunE, []string{keyID.String()})
	cmd.Args = cobra.ExactArgs(1)
	cmd.SetContext(ctx)
	err := cmd.Execute()
	assert.ErrorContains(t, err, "failed to rotate key")
}

// ========== wrapCmd tests ==========

func TestWrapCmd_NoClaims(t *testing.T) {
	ctx := context.Background()
	cmd, _ := newTestCmd(wrapCmd.RunE, nil)
	setFlags(cmd, map[string]any{"key-id": uuid.New().String(), "key-material": "dGVzdA=="})
	cmd.SetContext(ctx)
	err := cmd.Execute()
	assert.ErrorContains(t, err, "unauthorized")
}

func TestWrapCmd_MissingKeyID(t *testing.T) {
	claims := &model.Claims{UserID: uuid.New(), Roles: []string{model.RoleAdmin}}
	ctx := context.WithValue(context.Background(), common.ClaimsKey, claims)
	ctx = context.WithValue(ctx, common.LogKey, newLogger())
	cmd, _ := newTestCmd(wrapCmd.RunE, nil)
	setFlags(cmd, map[string]any{"key-id": "", "key-material": "dGVzdA=="})
	cmd.SetContext(ctx)
	err := cmd.Execute()
	assert.ErrorContains(t, err, "--key-id and --key-material are required")
}

func TestWrapCmd_MissingKeyMaterial(t *testing.T) {
	claims := &model.Claims{UserID: uuid.New(), Roles: []string{model.RoleAdmin}}
	ctx := context.WithValue(context.Background(), common.ClaimsKey, claims)
	ctx = context.WithValue(ctx, common.LogKey, newLogger())
	cmd, _ := newTestCmd(wrapCmd.RunE, nil)
	setFlags(cmd, map[string]any{"key-id": uuid.New().String(), "key-material": ""})
	cmd.SetContext(ctx)
	err := cmd.Execute()
	assert.ErrorContains(t, err, "--key-id and --key-material are required")
}

func TestWrapCmd_InvalidKeyID(t *testing.T) {
	claims := &model.Claims{UserID: uuid.New(), Roles: []string{model.RoleAdmin}}
	ctx := context.WithValue(context.Background(), common.ClaimsKey, claims)
	ctx = context.WithValue(ctx, common.LogKey, newLogger())
	cmd, _ := newTestCmd(wrapCmd.RunE, nil)
	setFlags(cmd, map[string]any{"key-id": "not-a-uuid", "key-material": "dGVzdA=="})
	cmd.SetContext(ctx)
	err := cmd.Execute()
	assert.ErrorContains(t, err, "invalid key ID")
}

func TestWrapCmd_InvalidBase64(t *testing.T) {
	claims := &model.Claims{UserID: uuid.New(), Roles: []string{model.RoleAdmin}}
	ctx := context.WithValue(context.Background(), common.ClaimsKey, claims)
	ctx = context.WithValue(ctx, common.LogKey, newLogger())
	cmd, _ := newTestCmd(wrapCmd.RunE, nil)
	setFlags(cmd, map[string]any{"key-id": uuid.New().String(), "key-material": "not!!valid@@base64"})
	cmd.SetContext(ctx)
	err := cmd.Execute()
	assert.ErrorContains(t, err, "failed to decode --key-material")
}

func TestWrapCmd_NoServiceContainer(t *testing.T) {
	keyID := uuid.New()
	claims := &model.Claims{UserID: uuid.New(), Roles: []string{model.RoleAdmin}}
	ctx := context.WithValue(context.Background(), common.ClaimsKey, claims)
	ctx = context.WithValue(ctx, common.LogKey, newLogger())
	// No service container.
	cmd, _ := newTestCmd(wrapCmd.RunE, nil)
	setFlags(cmd, map[string]any{"key-id": keyID.String(), "key-material": "dGVzdA=="})
	cmd.SetContext(ctx)
	err := cmd.Execute()
	assert.ErrorContains(t, err, "service container not available")
}

func TestWrapCmd_Success(t *testing.T) {
	cryptoSvc := &keyCmdCryptoService{}
	userID := uuid.New()
	keyID := uuid.New()
	plaintext := []byte("my-secret-key-material")
	wrapped := []byte("wrapped-bytes")
	sc, vaultID := newAllowedContainer(nil, cryptoSvc)
	cryptoSvc.On("WrapKey", mock.Anything, mock.MatchedBy(func(r keyServices.WrapKeyRequest) bool {
		return r.KeyID == keyID && r.UserID == userID &&
			r.VaultID == vaultID && r.Scope == model.NewVaultScope(vaultID, userID)
	})).Return(&keyServices.WrapKeyResult{WrappedKey: wrapped}, nil)

	claims := &model.Claims{UserID: userID, Roles: []string{model.RoleAdmin}}
	ctx := context.WithValue(context.Background(), common.ClaimsKey, claims)
	ctx = context.WithValue(ctx, common.LogKey, newLogger())
	ctx = context.WithValue(ctx, common.ServiceContainerKey, sc)

	// wrapCmd uses fmt.Println (writes to os.Stdout), not cmd.OutOrStdout().
	cmd, _ := newTestCmd(wrapCmd.RunE, nil)
	setFlags(cmd, map[string]any{"key-id": keyID.String(),
		"key-material": base64.StdEncoding.EncodeToString(plaintext)})
	cmd.SetContext(ctx)
	err := cmd.Execute()
	assert.NoError(t, err)
	cryptoSvc.AssertExpectations(t)
}

func TestWrapCmd_Denied(t *testing.T) {
	cryptoSvc := &keyCmdCryptoService{}
	userID := uuid.New()
	keyID := uuid.New()
	sc := newDeniedContainer(nil, cryptoSvc)

	claims := &model.Claims{UserID: userID, Roles: []string{model.RoleAdmin}}
	ctx := context.WithValue(context.Background(), common.ClaimsKey, claims)
	ctx = context.WithValue(ctx, common.LogKey, newLogger())
	ctx = context.WithValue(ctx, common.ServiceContainerKey, sc)

	cmd, _ := newTestCmd(wrapCmd.RunE, nil)
	setFlags(cmd, map[string]any{"key-id": keyID.String(),
		"key-material": base64.StdEncoding.EncodeToString([]byte("plaintext"))})
	cmd.SetContext(ctx)
	err := cmd.Execute()
	assert.ErrorContains(t, err, "forbidden")
	cryptoSvc.AssertNotCalled(t, "WrapKey", mock.Anything, mock.Anything)
}

func TestWrapCmd_Authorized(t *testing.T) {
	cryptoSvc := &keyCmdCryptoService{}
	userID := uuid.New()
	keyID := uuid.New()
	plaintext := []byte("my-secret-key-material")
	wrapped := []byte("wrapped-bytes")
	sc, vaultID := newAllowedContainer(nil, cryptoSvc)

	roles := &testutils.MockRoleAssignmentService{}
	roles.On("HasDataAction", mock.Anything, userID, vaultID, model.ActionKeysWrap).
		Return(true, nil).Once()
	policies := &testutils.MockAccessPolicyService{}
	policies.On("CheckAccess", mock.Anything, userID, model.PolicyResourceKeys, model.OpCreate, vaultID).
		Return(authzServices.AccessAllowed, nil).Once()
	sc.RoleAssignmentService = roles
	sc.AccessPolicyService = policies

	cryptoSvc.On("WrapKey", mock.Anything, mock.MatchedBy(func(r keyServices.WrapKeyRequest) bool {
		return r.KeyID == keyID && r.UserID == userID &&
			r.VaultID == vaultID && r.Scope == model.NewVaultScope(vaultID, userID)
	})).Return(&keyServices.WrapKeyResult{WrappedKey: wrapped}, nil)

	claims := &model.Claims{UserID: userID, Roles: []string{model.RoleAdmin}}
	ctx := context.WithValue(context.Background(), common.ClaimsKey, claims)
	ctx = context.WithValue(ctx, common.LogKey, newLogger())
	ctx = context.WithValue(ctx, common.ServiceContainerKey, sc)

	cmd, _ := newTestCmd(wrapCmd.RunE, nil)
	setFlags(cmd, map[string]any{"key-id": keyID.String(),
		"key-material": base64.StdEncoding.EncodeToString(plaintext)})
	cmd.SetContext(ctx)
	err := cmd.Execute()
	assert.NoError(t, err)
	cryptoSvc.AssertExpectations(t)
	roles.AssertExpectations(t)
	policies.AssertExpectations(t)
}

func TestWrapCmd_ServiceError(t *testing.T) {
	cryptoSvc := &keyCmdCryptoService{}
	userID := uuid.New()
	keyID := uuid.New()
	sc, _ := newAllowedContainer(nil, cryptoSvc)
	cryptoSvc.On("WrapKey", mock.Anything, mock.Anything).Return(nil, fmt.Errorf("wrap error"))

	claims := &model.Claims{UserID: userID, Roles: []string{model.RoleAdmin}}
	ctx := context.WithValue(context.Background(), common.ClaimsKey, claims)
	ctx = context.WithValue(ctx, common.LogKey, newLogger())
	ctx = context.WithValue(ctx, common.ServiceContainerKey, sc)

	cmd, _ := newTestCmd(wrapCmd.RunE, nil)
	setFlags(cmd, map[string]any{"key-id": keyID.String(),
		"key-material": base64.StdEncoding.EncodeToString([]byte("plaintext"))})
	cmd.SetContext(ctx)
	err := cmd.Execute()
	assert.ErrorContains(t, err, "wrap failed")
}

// ========== unwrapCmd tests ==========

func TestUnwrapCmd_NoClaims(t *testing.T) {
	ctx := context.Background()
	cmd, _ := newTestCmd(unwrapCmd.RunE, nil)
	setFlags(cmd, map[string]any{"key-id": uuid.New().String(), "wrapped-key": "dGVzdA=="})
	cmd.SetContext(ctx)
	err := cmd.Execute()
	assert.ErrorContains(t, err, "unauthorized")
}

func TestUnwrapCmd_MissingKeyID(t *testing.T) {
	claims := &model.Claims{UserID: uuid.New(), Roles: []string{model.RoleAdmin}}
	ctx := context.WithValue(context.Background(), common.ClaimsKey, claims)
	ctx = context.WithValue(ctx, common.LogKey, newLogger())
	cmd, _ := newTestCmd(unwrapCmd.RunE, nil)
	setFlags(cmd, map[string]any{"key-id": "", "wrapped-key": "dGVzdA=="})
	cmd.SetContext(ctx)
	err := cmd.Execute()
	assert.ErrorContains(t, err, "--key-id and --wrapped-key are required")
}

func TestUnwrapCmd_MissingWrappedKey(t *testing.T) {
	claims := &model.Claims{UserID: uuid.New(), Roles: []string{model.RoleAdmin}}
	ctx := context.WithValue(context.Background(), common.ClaimsKey, claims)
	ctx = context.WithValue(ctx, common.LogKey, newLogger())
	cmd, _ := newTestCmd(unwrapCmd.RunE, nil)
	setFlags(cmd, map[string]any{"key-id": uuid.New().String(), "wrapped-key": ""})
	cmd.SetContext(ctx)
	err := cmd.Execute()
	assert.ErrorContains(t, err, "--key-id and --wrapped-key are required")
}

func TestUnwrapCmd_InvalidKeyID(t *testing.T) {
	claims := &model.Claims{UserID: uuid.New(), Roles: []string{model.RoleAdmin}}
	ctx := context.WithValue(context.Background(), common.ClaimsKey, claims)
	ctx = context.WithValue(ctx, common.LogKey, newLogger())
	cmd, _ := newTestCmd(unwrapCmd.RunE, nil)
	setFlags(cmd, map[string]any{"key-id": "bad-uuid", "wrapped-key": "dGVzdA=="})
	cmd.SetContext(ctx)
	err := cmd.Execute()
	assert.ErrorContains(t, err, "invalid key ID")
}

func TestUnwrapCmd_InvalidBase64(t *testing.T) {
	claims := &model.Claims{UserID: uuid.New(), Roles: []string{model.RoleAdmin}}
	ctx := context.WithValue(context.Background(), common.ClaimsKey, claims)
	ctx = context.WithValue(ctx, common.LogKey, newLogger())
	cmd, _ := newTestCmd(unwrapCmd.RunE, nil)
	setFlags(cmd, map[string]any{"key-id": uuid.New().String(), "wrapped-key": "not!!base64"})
	cmd.SetContext(ctx)
	err := cmd.Execute()
	assert.ErrorContains(t, err, "failed to decode --wrapped-key")
}

func TestUnwrapCmd_NoServiceContainer(t *testing.T) {
	keyID := uuid.New()
	claims := &model.Claims{UserID: uuid.New(), Roles: []string{model.RoleAdmin}}
	ctx := context.WithValue(context.Background(), common.ClaimsKey, claims)
	ctx = context.WithValue(ctx, common.LogKey, newLogger())
	cmd, _ := newTestCmd(unwrapCmd.RunE, nil)
	setFlags(cmd, map[string]any{"key-id": keyID.String(), "wrapped-key": "dGVzdA=="})
	cmd.SetContext(ctx)
	err := cmd.Execute()
	assert.ErrorContains(t, err, "service container not available")
}

func TestUnwrapCmd_Success(t *testing.T) {
	cryptoSvc := &keyCmdCryptoService{}
	userID := uuid.New()
	keyID := uuid.New()
	wrappedBytes := []byte("wrapped-material")
	plaintext := []byte("recovered-key")
	sc, vaultID := newAllowedContainer(nil, cryptoSvc)
	cryptoSvc.On("UnwrapKey", mock.Anything, mock.MatchedBy(func(r keyServices.UnwrapKeyRequest) bool {
		return r.KeyID == keyID && r.UserID == userID &&
			r.VaultID == vaultID && r.Scope == model.NewVaultScope(vaultID, userID)
	})).Return(&keyServices.UnwrapKeyResult{PlaintextKey: plaintext}, nil)

	claims := &model.Claims{UserID: userID, Roles: []string{model.RoleAdmin}}
	ctx := context.WithValue(context.Background(), common.ClaimsKey, claims)
	ctx = context.WithValue(ctx, common.LogKey, newLogger())
	ctx = context.WithValue(ctx, common.ServiceContainerKey, sc)

	// unwrapCmd uses fmt.Println (writes to os.Stdout), not cmd.OutOrStdout().
	cmd, _ := newTestCmd(unwrapCmd.RunE, nil)
	setFlags(cmd, map[string]any{"key-id": keyID.String(),
		"wrapped-key": base64.StdEncoding.EncodeToString(wrappedBytes)})
	cmd.SetContext(ctx)
	err := cmd.Execute()
	assert.NoError(t, err)
	cryptoSvc.AssertExpectations(t)
}

func TestUnwrapCmd_Denied(t *testing.T) {
	cryptoSvc := &keyCmdCryptoService{}
	userID := uuid.New()
	keyID := uuid.New()
	sc := newDeniedContainer(nil, cryptoSvc)

	claims := &model.Claims{UserID: userID, Roles: []string{model.RoleAdmin}}
	ctx := context.WithValue(context.Background(), common.ClaimsKey, claims)
	ctx = context.WithValue(ctx, common.LogKey, newLogger())
	ctx = context.WithValue(ctx, common.ServiceContainerKey, sc)

	cmd, _ := newTestCmd(unwrapCmd.RunE, nil)
	setFlags(cmd, map[string]any{"key-id": keyID.String(),
		"wrapped-key": base64.StdEncoding.EncodeToString([]byte("wrapped"))})
	cmd.SetContext(ctx)
	err := cmd.Execute()
	assert.ErrorContains(t, err, "forbidden")
	cryptoSvc.AssertNotCalled(t, "UnwrapKey", mock.Anything, mock.Anything)
}

func TestUnwrapCmd_Authorized(t *testing.T) {
	cryptoSvc := &keyCmdCryptoService{}
	userID := uuid.New()
	keyID := uuid.New()
	wrappedBytes := []byte("wrapped-material")
	plaintext := []byte("recovered-key")
	sc, vaultID := newAllowedContainer(nil, cryptoSvc)

	roles := &testutils.MockRoleAssignmentService{}
	roles.On("HasDataAction", mock.Anything, userID, vaultID, model.ActionKeysUnwrap).
		Return(true, nil).Once()
	policies := &testutils.MockAccessPolicyService{}
	policies.On("CheckAccess", mock.Anything, userID, model.PolicyResourceKeys, model.OpCreate, vaultID).
		Return(authzServices.AccessAllowed, nil).Once()
	sc.RoleAssignmentService = roles
	sc.AccessPolicyService = policies

	cryptoSvc.On("UnwrapKey", mock.Anything, mock.MatchedBy(func(r keyServices.UnwrapKeyRequest) bool {
		return r.KeyID == keyID && r.UserID == userID &&
			r.VaultID == vaultID && r.Scope == model.NewVaultScope(vaultID, userID)
	})).Return(&keyServices.UnwrapKeyResult{PlaintextKey: plaintext}, nil)

	claims := &model.Claims{UserID: userID, Roles: []string{model.RoleAdmin}}
	ctx := context.WithValue(context.Background(), common.ClaimsKey, claims)
	ctx = context.WithValue(ctx, common.LogKey, newLogger())
	ctx = context.WithValue(ctx, common.ServiceContainerKey, sc)

	cmd, _ := newTestCmd(unwrapCmd.RunE, nil)
	setFlags(cmd, map[string]any{"key-id": keyID.String(),
		"wrapped-key": base64.StdEncoding.EncodeToString(wrappedBytes)})
	cmd.SetContext(ctx)
	err := cmd.Execute()
	assert.NoError(t, err)
	cryptoSvc.AssertExpectations(t)
	roles.AssertExpectations(t)
	policies.AssertExpectations(t)
}

func TestUnwrapCmd_ServiceError(t *testing.T) {
	cryptoSvc := &keyCmdCryptoService{}
	userID := uuid.New()
	keyID := uuid.New()
	sc, _ := newAllowedContainer(nil, cryptoSvc)
	cryptoSvc.On("UnwrapKey", mock.Anything, mock.Anything).Return(nil, fmt.Errorf("unwrap error"))

	claims := &model.Claims{UserID: userID, Roles: []string{model.RoleAdmin}}
	ctx := context.WithValue(context.Background(), common.ClaimsKey, claims)
	ctx = context.WithValue(ctx, common.LogKey, newLogger())
	ctx = context.WithValue(ctx, common.ServiceContainerKey, sc)

	cmd, _ := newTestCmd(unwrapCmd.RunE, nil)
	setFlags(cmd, map[string]any{"key-id": keyID.String(),
		"wrapped-key": base64.StdEncoding.EncodeToString([]byte("wrapped"))})
	cmd.SetContext(ctx)
	err := cmd.Execute()
	assert.ErrorContains(t, err, "unwrap failed")
}

func TestWrapCmd_SetsResolvedVaultID(t *testing.T) {
	cryptoSvc := &keyCmdCryptoService{}
	userID := uuid.New()
	keyID := uuid.New()
	plaintext := []byte("my-secret-key-material")
	wrapped := []byte("wrapped-bytes")
	sc, vaultID := newAllowedContainer(nil, cryptoSvc)
	cryptoSvc.On("WrapKey", mock.Anything, mock.MatchedBy(func(r keyServices.WrapKeyRequest) bool {
		return r.VaultID == vaultID && r.VaultID == uuid.MustParse(model.DefaultVaultID)
	})).Return(&keyServices.WrapKeyResult{WrappedKey: wrapped}, nil)

	claims := &model.Claims{UserID: userID, Roles: []string{model.RoleAdmin}}
	ctx := context.WithValue(context.Background(), common.ClaimsKey, claims)
	ctx = context.WithValue(ctx, common.LogKey, newLogger())
	ctx = context.WithValue(ctx, common.ServiceContainerKey, sc)

	cmd, _ := newTestCmd(wrapCmd.RunE, nil)
	setFlags(cmd, map[string]any{"key-id": keyID.String(),
		"key-material": base64.StdEncoding.EncodeToString(plaintext)})
	cmd.SetContext(ctx)
	err := cmd.Execute()
	assert.NoError(t, err)
	cryptoSvc.AssertExpectations(t)
}

func TestUnwrapCmd_SetsResolvedVaultID(t *testing.T) {
	cryptoSvc := &keyCmdCryptoService{}
	userID := uuid.New()
	keyID := uuid.New()
	wrapped := []byte("wrapped-bytes")
	plaintext := []byte("recovered-key-material")
	sc, vaultID := newAllowedContainer(nil, cryptoSvc)
	cryptoSvc.On("UnwrapKey", mock.Anything, mock.MatchedBy(func(r keyServices.UnwrapKeyRequest) bool {
		return r.VaultID == vaultID && r.VaultID == uuid.MustParse(model.DefaultVaultID)
	})).Return(&keyServices.UnwrapKeyResult{PlaintextKey: plaintext}, nil)

	claims := &model.Claims{UserID: userID, Roles: []string{model.RoleAdmin}}
	ctx := context.WithValue(context.Background(), common.ClaimsKey, claims)
	ctx = context.WithValue(ctx, common.LogKey, newLogger())
	ctx = context.WithValue(ctx, common.ServiceContainerKey, sc)

	cmd, _ := newTestCmd(unwrapCmd.RunE, nil)
	setFlags(cmd, map[string]any{"key-id": keyID.String(),
		"wrapped-key": base64.StdEncoding.EncodeToString(wrapped)})
	cmd.SetContext(ctx)
	err := cmd.Execute()
	assert.NoError(t, err)
	cryptoSvc.AssertExpectations(t)
}

// ========== signCmd tests ==========

func TestSignCmd_NoClaims(t *testing.T) {
	ctx := context.Background()
	cmd, _ := newTestCmd(signCmd.RunE, nil)
	setFlags(cmd, map[string]any{"key-id": uuid.New().String(), "data": "dGVzdA==", "algorithm": "RS256"})
	cmd.SetContext(ctx)
	err := cmd.Execute()
	assert.ErrorContains(t, err, "unauthorized")
}

func TestSignCmd_MissingKeyIDOrData(t *testing.T) {
	claims := &model.Claims{UserID: uuid.New(), Roles: []string{model.RoleAdmin}}
	ctx := context.WithValue(context.Background(), common.ClaimsKey, claims)
	ctx = context.WithValue(ctx, common.LogKey, newLogger())
	cmd, _ := newTestCmd(signCmd.RunE, nil)
	setFlags(cmd, map[string]any{"key-id": "", "data": "", "algorithm": "RS256"})
	cmd.SetContext(ctx)
	err := cmd.Execute()
	assert.ErrorContains(t, err, "--key-id and --data are required")
}

func TestSignCmd_InvalidKeyID(t *testing.T) {
	claims := &model.Claims{UserID: uuid.New(), Roles: []string{model.RoleAdmin}}
	ctx := context.WithValue(context.Background(), common.ClaimsKey, claims)
	ctx = context.WithValue(ctx, common.LogKey, newLogger())
	cmd, _ := newTestCmd(signCmd.RunE, nil)
	setFlags(cmd, map[string]any{"key-id": "not-a-uuid", "data": "dGVzdA==", "algorithm": "RS256"})
	cmd.SetContext(ctx)
	err := cmd.Execute()
	assert.ErrorContains(t, err, "invalid key ID")
}

func TestSignCmd_InvalidBase64(t *testing.T) {
	claims := &model.Claims{UserID: uuid.New(), Roles: []string{model.RoleAdmin}}
	ctx := context.WithValue(context.Background(), common.ClaimsKey, claims)
	ctx = context.WithValue(ctx, common.LogKey, newLogger())
	cmd, _ := newTestCmd(signCmd.RunE, nil)
	setFlags(cmd, map[string]any{"key-id": uuid.New().String(), "data": "not!!valid@@base64", "algorithm": "RS256"})
	cmd.SetContext(ctx)
	err := cmd.Execute()
	assert.ErrorContains(t, err, "failed to decode --data")
}

func TestSignCmd_NoServiceContainer(t *testing.T) {
	keyID := uuid.New()
	claims := &model.Claims{UserID: uuid.New(), Roles: []string{model.RoleAdmin}}
	ctx := context.WithValue(context.Background(), common.ClaimsKey, claims)
	ctx = context.WithValue(ctx, common.LogKey, newLogger())
	// No service container.
	cmd, _ := newTestCmd(signCmd.RunE, nil)
	setFlags(cmd, map[string]any{"key-id": keyID.String(), "data": "dGVzdA==", "algorithm": "RS256"})
	cmd.SetContext(ctx)
	err := cmd.Execute()
	assert.ErrorContains(t, err, "service container not available")
}

func TestSignCmd_DefaultsAlgorithmToRS256(t *testing.T) {
	cryptoSvc := &keyCmdCryptoService{}
	userID := uuid.New()
	keyID := uuid.New()
	data := []byte("data-to-sign")
	signature := []byte("signature-bytes")
	sc, vaultID := newAllowedContainer(nil, cryptoSvc)
	cryptoSvc.On("Sign", mock.Anything, mock.MatchedBy(func(r keyServices.SignRequest) bool {
		return r.KeyID == keyID && r.UserID == userID && r.VaultID == vaultID &&
			r.Scope == model.NewVaultScope(vaultID, userID) &&
			r.Algorithm == crypto.SignatureAlgorithm("RS256")
	})).Return(&keyServices.SignResult{Signature: signature}, nil)

	claims := &model.Claims{UserID: userID, Roles: []string{model.RoleAdmin}}
	ctx := context.WithValue(context.Background(), common.ClaimsKey, claims)
	ctx = context.WithValue(ctx, common.LogKey, newLogger())
	ctx = context.WithValue(ctx, common.ServiceContainerKey, sc)

	cmd, _ := newTestCmd(signCmd.RunE, nil)
	setFlags(cmd, map[string]any{"key-id": keyID.String(),
		"data":      base64.StdEncoding.EncodeToString(data),
		"algorithm": ""})
	cmd.SetContext(ctx)
	err := cmd.Execute()
	assert.NoError(t, err)
	cryptoSvc.AssertExpectations(t)
}

func TestSignCmd_Success(t *testing.T) {
	cryptoSvc := &keyCmdCryptoService{}
	userID := uuid.New()
	keyID := uuid.New()
	data := []byte("data-to-sign")
	signature := []byte("signature-bytes")
	sc, vaultID := newAllowedContainer(nil, cryptoSvc)
	cryptoSvc.On("Sign", mock.Anything, mock.MatchedBy(func(r keyServices.SignRequest) bool {
		return r.KeyID == keyID && r.UserID == userID && r.VaultID == vaultID &&
			r.Scope == model.NewVaultScope(vaultID, userID) &&
			r.Algorithm == crypto.SignatureAlgorithm("ES256")
	})).Return(&keyServices.SignResult{Signature: signature}, nil)

	claims := &model.Claims{UserID: userID, Roles: []string{model.RoleAdmin}}
	ctx := context.WithValue(context.Background(), common.ClaimsKey, claims)
	ctx = context.WithValue(ctx, common.LogKey, newLogger())
	ctx = context.WithValue(ctx, common.ServiceContainerKey, sc)

	cmd, _ := newTestCmd(signCmd.RunE, nil)
	setFlags(cmd, map[string]any{"key-id": keyID.String(),
		"data":      base64.StdEncoding.EncodeToString(data),
		"algorithm": "ES256"})
	cmd.SetContext(ctx)
	err := cmd.Execute()
	assert.NoError(t, err)
	cryptoSvc.AssertExpectations(t)
}

func TestSignCmd_Denied(t *testing.T) {
	cryptoSvc := &keyCmdCryptoService{}
	userID := uuid.New()
	keyID := uuid.New()
	sc := newDeniedContainer(nil, cryptoSvc)

	claims := &model.Claims{UserID: userID, Roles: []string{model.RoleAdmin}}
	ctx := context.WithValue(context.Background(), common.ClaimsKey, claims)
	ctx = context.WithValue(ctx, common.LogKey, newLogger())
	ctx = context.WithValue(ctx, common.ServiceContainerKey, sc)

	cmd, _ := newTestCmd(signCmd.RunE, nil)
	setFlags(cmd, map[string]any{"key-id": keyID.String(),
		"data":      base64.StdEncoding.EncodeToString([]byte("data")),
		"algorithm": "RS256"})
	cmd.SetContext(ctx)
	err := cmd.Execute()
	assert.ErrorContains(t, err, "forbidden")
	cryptoSvc.AssertNotCalled(t, "Sign", mock.Anything, mock.Anything)
}

func TestSignCmd_Authorized(t *testing.T) {
	cryptoSvc := &keyCmdCryptoService{}
	userID := uuid.New()
	keyID := uuid.New()
	data := []byte("data-to-sign")
	signature := []byte("signature-bytes")
	sc, vaultID := newAllowedContainer(nil, cryptoSvc)

	roles := &testutils.MockRoleAssignmentService{}
	roles.On("HasDataAction", mock.Anything, userID, vaultID, model.ActionKeysSign).
		Return(true, nil).Once()
	policies := &testutils.MockAccessPolicyService{}
	policies.On("CheckAccess", mock.Anything, userID, model.PolicyResourceKeys, model.OpSign, vaultID).
		Return(authzServices.AccessAllowed, nil).Once()
	sc.RoleAssignmentService = roles
	sc.AccessPolicyService = policies

	cryptoSvc.On("Sign", mock.Anything, mock.MatchedBy(func(r keyServices.SignRequest) bool {
		return r.KeyID == keyID && r.UserID == userID &&
			r.VaultID == vaultID && r.Scope == model.NewVaultScope(vaultID, userID)
	})).Return(&keyServices.SignResult{Signature: signature}, nil)

	claims := &model.Claims{UserID: userID, Roles: []string{model.RoleAdmin}}
	ctx := context.WithValue(context.Background(), common.ClaimsKey, claims)
	ctx = context.WithValue(ctx, common.LogKey, newLogger())
	ctx = context.WithValue(ctx, common.ServiceContainerKey, sc)

	cmd, _ := newTestCmd(signCmd.RunE, nil)
	setFlags(cmd, map[string]any{"key-id": keyID.String(),
		"data":      base64.StdEncoding.EncodeToString(data),
		"algorithm": "RS256"})
	cmd.SetContext(ctx)
	err := cmd.Execute()
	assert.NoError(t, err)
	cryptoSvc.AssertExpectations(t)
	roles.AssertExpectations(t)
	policies.AssertExpectations(t)
}

func TestSignCmd_ServiceError(t *testing.T) {
	cryptoSvc := &keyCmdCryptoService{}
	userID := uuid.New()
	keyID := uuid.New()
	sc, _ := newAllowedContainer(nil, cryptoSvc)
	cryptoSvc.On("Sign", mock.Anything, mock.Anything).Return(nil, fmt.Errorf("sign error"))

	claims := &model.Claims{UserID: userID, Roles: []string{model.RoleAdmin}}
	ctx := context.WithValue(context.Background(), common.ClaimsKey, claims)
	ctx = context.WithValue(ctx, common.LogKey, newLogger())
	ctx = context.WithValue(ctx, common.ServiceContainerKey, sc)

	cmd, _ := newTestCmd(signCmd.RunE, nil)
	setFlags(cmd, map[string]any{"key-id": keyID.String(),
		"data":      base64.StdEncoding.EncodeToString([]byte("data")),
		"algorithm": "RS256"})
	cmd.SetContext(ctx)
	err := cmd.Execute()
	assert.ErrorContains(t, err, "sign failed")
}

func TestSignCmd_SetsResolvedVaultID(t *testing.T) {
	cryptoSvc := &keyCmdCryptoService{}
	userID := uuid.New()
	keyID := uuid.New()
	signature := []byte("signature-bytes")
	sc, vaultID := newAllowedContainer(nil, cryptoSvc)
	cryptoSvc.On("Sign", mock.Anything, mock.MatchedBy(func(r keyServices.SignRequest) bool {
		return r.VaultID == vaultID && r.VaultID == uuid.MustParse(model.DefaultVaultID)
	})).Return(&keyServices.SignResult{Signature: signature}, nil)

	claims := &model.Claims{UserID: userID, Roles: []string{model.RoleAdmin}}
	ctx := context.WithValue(context.Background(), common.ClaimsKey, claims)
	ctx = context.WithValue(ctx, common.LogKey, newLogger())
	ctx = context.WithValue(ctx, common.ServiceContainerKey, sc)

	cmd, _ := newTestCmd(signCmd.RunE, nil)
	setFlags(cmd, map[string]any{"key-id": keyID.String(),
		"data":      base64.StdEncoding.EncodeToString([]byte("data")),
		"algorithm": "RS256"})
	cmd.SetContext(ctx)
	err := cmd.Execute()
	assert.NoError(t, err)
	cryptoSvc.AssertExpectations(t)
}

// ========== verifyCmd tests ==========

func TestVerifyCmd_NoClaims(t *testing.T) {
	ctx := context.Background()
	cmd, _ := newTestCmd(verifyCmd.RunE, nil)
	setFlags(cmd, map[string]any{"key-id": uuid.New().String(), "data": "dGVzdA==",
		"signature": "c2ln", "algorithm": "RS256"})
	cmd.SetContext(ctx)
	err := cmd.Execute()
	assert.ErrorContains(t, err, "unauthorized")
}

func TestVerifyCmd_MissingRequiredFlags(t *testing.T) {
	cases := []struct {
		name      string
		keyID     string
		data      string
		signature string
	}{
		{"missing key-id", "", "dGVzdA==", "c2ln"},
		{"missing data", uuid.New().String(), "", "c2ln"},
		{"missing signature", uuid.New().String(), "dGVzdA==", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			claims := &model.Claims{UserID: uuid.New(), Roles: []string{model.RoleAdmin}}
			ctx := context.WithValue(context.Background(), common.ClaimsKey, claims)
			ctx = context.WithValue(ctx, common.LogKey, newLogger())
			cmd, _ := newTestCmd(verifyCmd.RunE, nil)
			setFlags(cmd, map[string]any{
				"key-id": tc.keyID, "data": tc.data,
				"signature": tc.signature, "algorithm": "RS256",
			})
			cmd.SetContext(ctx)
			err := cmd.Execute()
			assert.ErrorContains(t, err, "--key-id, --data, and --signature are required")
		})
	}
}

func TestVerifyCmd_InvalidKeyID(t *testing.T) {
	claims := &model.Claims{UserID: uuid.New(), Roles: []string{model.RoleAdmin}}
	ctx := context.WithValue(context.Background(), common.ClaimsKey, claims)
	ctx = context.WithValue(ctx, common.LogKey, newLogger())
	cmd, _ := newTestCmd(verifyCmd.RunE, nil)
	setFlags(cmd, map[string]any{"key-id": "not-a-uuid", "data": "dGVzdA==",
		"signature": "c2ln", "algorithm": "RS256"})
	cmd.SetContext(ctx)
	err := cmd.Execute()
	assert.ErrorContains(t, err, "invalid key ID")
}

func TestVerifyCmd_InvalidDataBase64(t *testing.T) {
	claims := &model.Claims{UserID: uuid.New(), Roles: []string{model.RoleAdmin}}
	ctx := context.WithValue(context.Background(), common.ClaimsKey, claims)
	ctx = context.WithValue(ctx, common.LogKey, newLogger())
	cmd, _ := newTestCmd(verifyCmd.RunE, nil)
	setFlags(cmd, map[string]any{"key-id": uuid.New().String(), "data": "not!!valid@@base64",
		"signature": "c2ln", "algorithm": "RS256"})
	cmd.SetContext(ctx)
	err := cmd.Execute()
	assert.ErrorContains(t, err, "failed to decode --data")
}

func TestVerifyCmd_InvalidSignatureBase64(t *testing.T) {
	claims := &model.Claims{UserID: uuid.New(), Roles: []string{model.RoleAdmin}}
	ctx := context.WithValue(context.Background(), common.ClaimsKey, claims)
	ctx = context.WithValue(ctx, common.LogKey, newLogger())
	cmd, _ := newTestCmd(verifyCmd.RunE, nil)
	setFlags(cmd, map[string]any{"key-id": uuid.New().String(), "data": "dGVzdA==",
		"signature": "not!!valid@@base64", "algorithm": "RS256"})
	cmd.SetContext(ctx)
	err := cmd.Execute()
	assert.ErrorContains(t, err, "failed to decode --signature")
}

func TestVerifyCmd_NoServiceContainer(t *testing.T) {
	keyID := uuid.New()
	claims := &model.Claims{UserID: uuid.New(), Roles: []string{model.RoleAdmin}}
	ctx := context.WithValue(context.Background(), common.ClaimsKey, claims)
	ctx = context.WithValue(ctx, common.LogKey, newLogger())
	cmd, _ := newTestCmd(verifyCmd.RunE, nil)
	setFlags(cmd, map[string]any{"key-id": keyID.String(), "data": "dGVzdA==",
		"signature": "c2ln", "algorithm": "RS256"})
	cmd.SetContext(ctx)
	err := cmd.Execute()
	assert.ErrorContains(t, err, "service container not available")
}

func TestVerifyCmd_Denied(t *testing.T) {
	cryptoSvc := &keyCmdCryptoService{}
	userID := uuid.New()
	keyID := uuid.New()
	sc := newDeniedContainer(nil, cryptoSvc)

	claims := &model.Claims{UserID: userID, Roles: []string{model.RoleAdmin}}
	ctx := context.WithValue(context.Background(), common.ClaimsKey, claims)
	ctx = context.WithValue(ctx, common.LogKey, newLogger())
	ctx = context.WithValue(ctx, common.ServiceContainerKey, sc)

	cmd, _ := newTestCmd(verifyCmd.RunE, nil)
	setFlags(cmd, map[string]any{"key-id": keyID.String(), "data": base64.StdEncoding.EncodeToString([]byte("data")),
		"signature": base64.StdEncoding.EncodeToString([]byte("sig")), "algorithm": "RS256"})
	cmd.SetContext(ctx)
	err := cmd.Execute()
	assert.ErrorContains(t, err, "forbidden")
	cryptoSvc.AssertNotCalled(t, "Verify", mock.Anything, mock.Anything)
}

func TestVerifyCmd_Authorized_ValidSignature(t *testing.T) {
	cryptoSvc := &keyCmdCryptoService{}
	userID := uuid.New()
	keyID := uuid.New()
	data := []byte("data-to-verify")
	signature := []byte("signature-bytes")
	sc, vaultID := newAllowedContainer(nil, cryptoSvc)

	roles := &testutils.MockRoleAssignmentService{}
	roles.On("HasDataAction", mock.Anything, userID, vaultID, model.ActionKeysVerify).
		Return(true, nil).Once()
	policies := &testutils.MockAccessPolicyService{}
	policies.On("CheckAccess", mock.Anything, userID, model.PolicyResourceKeys, model.OpVerify, vaultID).
		Return(authzServices.AccessAllowed, nil).Once()
	sc.RoleAssignmentService = roles
	sc.AccessPolicyService = policies

	cryptoSvc.On("Verify", mock.Anything, mock.MatchedBy(func(r keyServices.VerifyRequest) bool {
		return r.KeyID == keyID && r.UserID == userID && r.VaultID == vaultID &&
			r.Scope == model.NewVaultScope(vaultID, userID) &&
			r.Algorithm == crypto.SignatureAlgorithm("RS256")
	})).Return(&keyServices.VerifyResult{KeyID: keyID, Algorithm: crypto.SignatureAlgorithm("RS256"), Valid: true}, nil)

	claims := &model.Claims{UserID: userID, Roles: []string{model.RoleAdmin}}
	ctx := buildAdminCtx(sc)
	ctx = context.WithValue(ctx, common.ClaimsKey, claims)

	cmd, out := newTestCmd(verifyCmd.RunE, nil)
	setFlags(cmd, map[string]any{"key-id": keyID.String(), "data": base64.StdEncoding.EncodeToString(data),
		"signature": base64.StdEncoding.EncodeToString(signature), "algorithm": "RS256"})
	cmd.SetContext(ctx)
	err := cmd.Execute()
	assert.NoError(t, err, "a valid signature must exit 0")
	assert.Contains(t, out.String(), "true")
	cryptoSvc.AssertExpectations(t)
	roles.AssertExpectations(t)
	policies.AssertExpectations(t)
}

func TestVerifyCmd_InvalidSignature_ExitsNonZeroButPrintsResult(t *testing.T) {
	cryptoSvc := &keyCmdCryptoService{}
	userID := uuid.New()
	keyID := uuid.New()
	sc, _ := newAllowedContainer(nil, cryptoSvc)
	cryptoSvc.On("Verify", mock.Anything, mock.Anything).
		Return(&keyServices.VerifyResult{KeyID: keyID, Algorithm: crypto.SignatureAlgorithm("RS256"), Valid: false}, nil)

	claims := &model.Claims{UserID: userID, Roles: []string{model.RoleAdmin}}
	ctx := buildAdminCtx(sc)
	ctx = context.WithValue(ctx, common.ClaimsKey, claims)

	cmd, out := newTestCmd(verifyCmd.RunE, nil)
	setFlags(cmd, map[string]any{"key-id": keyID.String(), "data": base64.StdEncoding.EncodeToString([]byte("data")),
		"signature": base64.StdEncoding.EncodeToString([]byte("bad-sig")), "algorithm": "RS256"})
	cmd.SetContext(ctx)
	err := cmd.Execute()
	assert.Error(t, err, "an invalid signature must exit non-zero")
	assert.ErrorContains(t, err, "signature verification failed")
	assert.Contains(t, out.String(), "false", "the result row must still be printed even though the command fails")
}

func TestVerifyCmd_ServiceError(t *testing.T) {
	cryptoSvc := &keyCmdCryptoService{}
	userID := uuid.New()
	keyID := uuid.New()
	sc, _ := newAllowedContainer(nil, cryptoSvc)
	cryptoSvc.On("Verify", mock.Anything, mock.Anything).Return(nil, fmt.Errorf("verify error"))

	claims := &model.Claims{UserID: userID, Roles: []string{model.RoleAdmin}}
	ctx := context.WithValue(context.Background(), common.ClaimsKey, claims)
	ctx = context.WithValue(ctx, common.LogKey, newLogger())
	ctx = context.WithValue(ctx, common.ServiceContainerKey, sc)

	cmd, _ := newTestCmd(verifyCmd.RunE, nil)
	setFlags(cmd, map[string]any{"key-id": keyID.String(), "data": base64.StdEncoding.EncodeToString([]byte("data")),
		"signature": base64.StdEncoding.EncodeToString([]byte("sig")), "algorithm": "RS256"})
	cmd.SetContext(ctx)
	err := cmd.Execute()
	assert.ErrorContains(t, err, "verify failed")
}

func TestVerifyCmd_SetsResolvedVaultID(t *testing.T) {
	cryptoSvc := &keyCmdCryptoService{}
	userID := uuid.New()
	keyID := uuid.New()
	sc, vaultID := newAllowedContainer(nil, cryptoSvc)
	cryptoSvc.On("Verify", mock.Anything, mock.MatchedBy(func(r keyServices.VerifyRequest) bool {
		return r.VaultID == vaultID && r.VaultID == uuid.MustParse(model.DefaultVaultID)
	})).Return(&keyServices.VerifyResult{KeyID: keyID, Algorithm: crypto.SignatureAlgorithm("RS256"), Valid: true}, nil)

	claims := &model.Claims{UserID: userID, Roles: []string{model.RoleAdmin}}
	ctx := buildAdminCtx(sc)
	ctx = context.WithValue(ctx, common.ClaimsKey, claims)

	cmd, _ := newTestCmd(verifyCmd.RunE, nil)
	setFlags(cmd, map[string]any{"key-id": keyID.String(), "data": base64.StdEncoding.EncodeToString([]byte("data")),
		"signature": base64.StdEncoding.EncodeToString([]byte("sig")), "algorithm": "RS256"})
	cmd.SetContext(ctx)
	err := cmd.Execute()
	assert.NoError(t, err)
	cryptoSvc.AssertExpectations(t)
}

// ---- verify unused imports are gone ----
var _ io.Writer = (*bytes.Buffer)(nil)

// ========== --version flag tests ==========
//
// The service layer has accepted a Version on every crypto request since the
// 2026-08-19 key-version-addressability work, but the four CLI commands never
// set it, so the CLI could only ever operate on a key's current version while
// REST could address an archived one. Each test below pins that the flag now
// reaches the service, and that omitting it still sends 0 -- the "current
// version" sentinel resolveVersionValue special-cases -- so existing scripted
// invocations are unaffected.

func TestSignCmd_PassesVersionToService(t *testing.T) {
	cryptoSvc := &keyCmdCryptoService{}
	userID := uuid.New()
	keyID := uuid.New()
	sc, _ := newAllowedContainer(nil, cryptoSvc)
	cryptoSvc.On("Sign", mock.Anything, mock.MatchedBy(func(r keyServices.SignRequest) bool {
		return r.KeyID == keyID && r.Version == 2
	})).Return(&keyServices.SignResult{Signature: []byte("sig")}, nil)

	claims := &model.Claims{UserID: userID, Roles: []string{model.RoleAdmin}}
	ctx := context.WithValue(context.Background(), common.ClaimsKey, claims)
	ctx = context.WithValue(ctx, common.LogKey, newLogger())
	ctx = context.WithValue(ctx, common.ServiceContainerKey, sc)

	cmd, _ := newTestCmd(signCmd.RunE, nil)
	setFlags(cmd, map[string]any{"key-id": keyID.String(),
		"data":      base64.StdEncoding.EncodeToString([]byte("data")),
		"algorithm": "RS256",
		"version":   2})
	cmd.SetContext(ctx)
	assert.NoError(t, cmd.Execute())
	cryptoSvc.AssertExpectations(t)
}

func TestSignCmd_OmittedVersionSendsZero(t *testing.T) {
	cryptoSvc := &keyCmdCryptoService{}
	userID := uuid.New()
	keyID := uuid.New()
	sc, _ := newAllowedContainer(nil, cryptoSvc)
	cryptoSvc.On("Sign", mock.Anything, mock.MatchedBy(func(r keyServices.SignRequest) bool {
		return r.Version == 0
	})).Return(&keyServices.SignResult{Signature: []byte("sig")}, nil)

	claims := &model.Claims{UserID: userID, Roles: []string{model.RoleAdmin}}
	ctx := context.WithValue(context.Background(), common.ClaimsKey, claims)
	ctx = context.WithValue(ctx, common.LogKey, newLogger())
	ctx = context.WithValue(ctx, common.ServiceContainerKey, sc)

	cmd, _ := newTestCmd(signCmd.RunE, nil)
	setFlags(cmd, map[string]any{"key-id": keyID.String(),
		"data":      base64.StdEncoding.EncodeToString([]byte("data")),
		"algorithm": "RS256"})
	cmd.SetContext(ctx)
	assert.NoError(t, cmd.Execute())
	cryptoSvc.AssertExpectations(t)
}

func TestVerifyCmd_PassesVersionToService(t *testing.T) {
	cryptoSvc := &keyCmdCryptoService{}
	userID := uuid.New()
	keyID := uuid.New()
	sc, _ := newAllowedContainer(nil, cryptoSvc)
	cryptoSvc.On("Verify", mock.Anything, mock.MatchedBy(func(r keyServices.VerifyRequest) bool {
		return r.KeyID == keyID && r.Version == 3
	})).Return(&keyServices.VerifyResult{Valid: true, KeyID: keyID}, nil)

	claims := &model.Claims{UserID: userID, Roles: []string{model.RoleAdmin}}
	ctx := context.WithValue(context.Background(), common.ClaimsKey, claims)
	ctx = context.WithValue(ctx, common.LogKey, newLogger())
	ctx = context.WithValue(ctx, common.ServiceContainerKey, sc)
	// verify prints through the output formatter; the other three write a bare
	// base64 line, so only this command needs one in context.
	ctx = context.WithValue(ctx, common.OutputFormatterKey, newTestFmtr())

	cmd, _ := newTestCmd(verifyCmd.RunE, nil)
	setFlags(cmd, map[string]any{"key-id": keyID.String(),
		"data":      base64.StdEncoding.EncodeToString([]byte("data")),
		"signature": base64.StdEncoding.EncodeToString([]byte("sig")),
		"algorithm": "RS256",
		"version":   3})
	cmd.SetContext(ctx)
	assert.NoError(t, cmd.Execute())
	cryptoSvc.AssertExpectations(t)
}

func TestWrapCmd_PassesVersionToService(t *testing.T) {
	cryptoSvc := &keyCmdCryptoService{}
	userID := uuid.New()
	keyID := uuid.New()
	sc, _ := newAllowedContainer(nil, cryptoSvc)
	cryptoSvc.On("WrapKey", mock.Anything, mock.MatchedBy(func(r keyServices.WrapKeyRequest) bool {
		return r.KeyID == keyID && r.Version == 4
	})).Return(&keyServices.WrapKeyResult{WrappedKey: []byte("wrapped")}, nil)

	claims := &model.Claims{UserID: userID, Roles: []string{model.RoleAdmin}}
	ctx := context.WithValue(context.Background(), common.ClaimsKey, claims)
	ctx = context.WithValue(ctx, common.LogKey, newLogger())
	ctx = context.WithValue(ctx, common.ServiceContainerKey, sc)

	cmd, _ := newTestCmd(wrapCmd.RunE, nil)
	setFlags(cmd, map[string]any{"key-id": keyID.String(),
		"key-material": base64.StdEncoding.EncodeToString([]byte("material")),
		"version":      4})
	cmd.SetContext(ctx)
	assert.NoError(t, cmd.Execute())
	cryptoSvc.AssertExpectations(t)
}

func TestUnwrapCmd_PassesVersionToService(t *testing.T) {
	cryptoSvc := &keyCmdCryptoService{}
	userID := uuid.New()
	keyID := uuid.New()
	sc, _ := newAllowedContainer(nil, cryptoSvc)
	cryptoSvc.On("UnwrapKey", mock.Anything, mock.MatchedBy(func(r keyServices.UnwrapKeyRequest) bool {
		return r.KeyID == keyID && r.Version == 5
	})).Return(&keyServices.UnwrapKeyResult{PlaintextKey: []byte("plain")}, nil)

	claims := &model.Claims{UserID: userID, Roles: []string{model.RoleAdmin}}
	ctx := context.WithValue(context.Background(), common.ClaimsKey, claims)
	ctx = context.WithValue(ctx, common.LogKey, newLogger())
	ctx = context.WithValue(ctx, common.ServiceContainerKey, sc)

	cmd, _ := newTestCmd(unwrapCmd.RunE, nil)
	setFlags(cmd, map[string]any{"key-id": keyID.String(),
		"wrapped-key": base64.StdEncoding.EncodeToString([]byte("wrapped")),
		"version":     5})
	cmd.SetContext(ctx)
	assert.NoError(t, cmd.Execute())
	cryptoSvc.AssertExpectations(t)
}
