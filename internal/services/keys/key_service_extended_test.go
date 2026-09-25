package keys

// Extended tests for KeyService covering CreateRSAKey, CreateECDSAKey,
// ListKeys, ValidateKeyAccess, and resolveVaultID.
//
// These tests run in the same package so they can reuse the
// mockKeyRepository defined in key_soft_delete_test.go.

import (
	"context"
	gocrypto "crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"errors"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"rocketvault/common"
	"rocketvault/internal/crypto"
	"rocketvault/internal/logging"
	"rocketvault/internal/repositories"
	"rocketvault/internal/signing"
	"rocketvault/model"
)

// ─── helpers ─────────────────────────────────────────────────────────────────

func setupKeyTestMasterKey() {
	k := make([]byte, 32)
	for i := range k {
		k[i] = byte(i + 1)
	}
	viper.Set("master_key", base64.StdEncoding.EncodeToString(k))
}

func newKeyLogger() *logging.Logger {
	return &logging.Logger{Logger: logrus.New()}
}

// mockKeyProviderForService is a minimal mock of crypto.KeyProvider for key
// service tests. Only GenerateRSAKey and GenerateECDSAKey are exercised here.
type mockKeyProviderForService struct {
	mock.Mock
}

func (m *mockKeyProviderForService) GenerateRSAKey(_ context.Context, bits int) (string, error) {
	args := m.Called(bits)
	return args.String(0), args.Error(1)
}

func (m *mockKeyProviderForService) GenerateECDSAKey(_ context.Context, curve string) (string, error) {
	args := m.Called(curve)
	return args.String(0), args.Error(1)
}

func (m *mockKeyProviderForService) GenerateAESKey(_ context.Context, bits int) (string, error) {
	args := m.Called(bits)
	return args.String(0), args.Error(1)
}

func (m *mockKeyProviderForService) Sign(_ context.Context, handle, _ string, _ []byte, _ crypto.SignatureAlgorithm) ([]byte, error) {
	return nil, errors.New("not implemented")
}

func (m *mockKeyProviderForService) Verify(_ context.Context, handle, _ string, _, _ []byte, _ crypto.SignatureAlgorithm) (bool, error) {
	return false, errors.New("not implemented")
}

func (m *mockKeyProviderForService) Encrypt(_ context.Context, handle string, _ []byte, _ crypto.EncryptionAlgorithm) ([]byte, []byte, error) {
	return nil, nil, errors.New("not implemented")
}

func (m *mockKeyProviderForService) Decrypt(_ context.Context, handle string, _ []byte, _ []byte, _ crypto.EncryptionAlgorithm) ([]byte, error) {
	return nil, errors.New("not implemented")
}

func (m *mockKeyProviderForService) Close() error { return nil }

func (m *mockKeyProviderForService) ImportKey(_ context.Context, keyType string, privateKey gocrypto.PrivateKey) (string, error) {
	args := m.Called(keyType, privateKey)
	return args.String(0), args.Error(1)
}

func accessibleKey(userID, keyID uuid.UUID) *model.Key {
	return &model.Key{ID: keyID, UserID: userID, Name: "key", Type: model.KeyTypeRSA, Enabled: true}
}

// ─── resolveVaultID ───────────────────────────────────────────────────────────

func TestResolveVaultID_NilFallsBack(t *testing.T) {
	got := resolveVaultID(uuid.Nil)
	assert.Equal(t, uuid.MustParse(model.DefaultVaultID), got)
}

func TestResolveVaultID_Preserved(t *testing.T) {
	v := uuid.New()
	assert.Equal(t, v, resolveVaultID(v))
}

// ─── CreateRSAKey ─────────────────────────────────────────────────────────────

func TestCreateRSAKey_InvalidBits(t *testing.T) {
	repo := &mockKeyRepository{}
	provider := &mockKeyProviderForService{}
	svc := NewKeyService(KeyServiceConfig{
		KeyRepository: repo,
		KeyProvider:   provider,
		Logger:        newKeyLogger(),
	})

	_, err := svc.CreateRSAKey(context.Background(), CreateKeyRequest{
		Name:   "bad-bits",
		Bits:   1024, // invalid
		UserID: uuid.New(),
		Type:   "RSA",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid RSA key size")
}

func TestCreateRSAKey_ProviderError(t *testing.T) {
	repo := &mockKeyRepository{}
	provider := &mockKeyProviderForService{}
	provider.On("GenerateRSAKey", 2048).Return("", errors.New("generate error"))

	svc := NewKeyService(KeyServiceConfig{
		KeyRepository: repo,
		KeyProvider:   provider,
		Logger:        newKeyLogger(),
	})

	_, err := svc.CreateRSAKey(context.Background(), CreateKeyRequest{
		Name:   "key",
		Bits:   2048,
		UserID: uuid.New(),
		Type:   "RSA",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to generate RSA key")
}

func TestCreateRSAKey_SuccessWithSoftwareKey(t *testing.T) {
	setupKeyTestMasterKey()

	// SoftwareKeyProvider returns a PEM handle which must be encrypted.
	softwareProvider := crypto.NewSoftwareKeyProvider()

	repo := &mockKeyRepository{}
	repo.On("Create", mock.Anything, mock.AnythingOfType("*model.Key")).Return(nil)

	userID := uuid.New()
	svc := NewKeyService(KeyServiceConfig{
		KeyRepository: repo,
		KeyProvider:   softwareProvider,
		Logger:        newKeyLogger(),
	})

	result, err := svc.CreateRSAKey(context.Background(), CreateKeyRequest{
		Name:   "rsa-key",
		Bits:   2048,
		UserID: userID,
		Type:   "RSA",
		Tags:   []string{"env:test"},
	})
	require.NoError(t, err)
	assert.NotNil(t, result)
	assert.Equal(t, "rsa-key", result.Name)
	assert.Equal(t, model.KeyTypeRSA, result.Type)
	repo.AssertExpectations(t)
}

func TestCreateRSAKey_SuccessWithExplicitDisabled(t *testing.T) {
	setupKeyTestMasterKey()

	softwareProvider := crypto.NewSoftwareKeyProvider()

	repo := &mockKeyRepository{}
	var createdKey *model.Key
	repo.On("Create", mock.Anything, mock.AnythingOfType("*model.Key")).
		Run(func(args mock.Arguments) { createdKey = args.Get(1).(*model.Key) }).
		Return(nil)

	disabled := false
	userID := uuid.New()
	svc := NewKeyService(KeyServiceConfig{
		KeyRepository: repo,
		KeyProvider:   softwareProvider,
		Logger:        newKeyLogger(),
	})

	result, err := svc.CreateRSAKey(context.Background(), CreateKeyRequest{
		Name:    "rsa-disabled",
		Bits:    2048,
		UserID:  userID,
		Type:    "RSA",
		Enabled: &disabled,
	})
	require.NoError(t, err)
	assert.NotNil(t, result)
	require.NotNil(t, createdKey)
	assert.False(t, createdKey.Enabled)
}

func TestCreateRSAKey_RepoCreateFails(t *testing.T) {
	setupKeyTestMasterKey()

	softwareProvider := crypto.NewSoftwareKeyProvider()

	repo := &mockKeyRepository{}
	repo.On("Create", mock.Anything, mock.AnythingOfType("*model.Key")).
		Return(errors.New("db error"))

	svc := NewKeyService(KeyServiceConfig{
		KeyRepository: repo,
		KeyProvider:   softwareProvider,
		Logger:        newKeyLogger(),
	})

	_, err := svc.CreateRSAKey(context.Background(), CreateKeyRequest{
		Name:   "rsa-fail",
		Bits:   2048,
		UserID: uuid.New(),
		Type:   "RSA",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to store RSA key")
}

func TestCreateRSAKey_WithVaultID(t *testing.T) {
	setupKeyTestMasterKey()

	softwareProvider := crypto.NewSoftwareKeyProvider()

	repo := &mockKeyRepository{}
	var createdKey *model.Key
	repo.On("Create", mock.Anything, mock.AnythingOfType("*model.Key")).
		Run(func(args mock.Arguments) { createdKey = args.Get(1).(*model.Key) }).
		Return(nil)

	vaultID := uuid.New()
	svc := NewKeyService(KeyServiceConfig{
		KeyRepository: repo,
		KeyProvider:   softwareProvider,
		Logger:        newKeyLogger(),
	})

	_, err := svc.CreateRSAKey(context.Background(), CreateKeyRequest{
		Name:    "vaulted-key",
		Bits:    2048,
		UserID:  uuid.New(),
		Type:    "RSA",
		VaultID: vaultID,
	})
	require.NoError(t, err)
	require.NotNil(t, createdKey)
	assert.Equal(t, vaultID, createdKey.VaultID)
}

func TestCreateRSAKey_WithPKCS11Handle(t *testing.T) {
	// A PKCS11 handle is a UUID-format string; verify it is stored with "pkcs11:" prefix.
	pkcs11UUID := uuid.New().String() // "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" = 36 chars

	provider := &mockKeyProviderForService{}
	provider.On("GenerateRSAKey", 2048).Return(pkcs11UUID, nil)

	repo := &mockKeyRepository{}
	var createdKey *model.Key
	repo.On("Create", mock.Anything, mock.AnythingOfType("*model.Key")).
		Run(func(args mock.Arguments) { createdKey = args.Get(1).(*model.Key) }).
		Return(nil)

	svc := NewKeyService(KeyServiceConfig{
		KeyRepository: repo,
		KeyProvider:   provider,
		Logger:        newKeyLogger(),
	})

	result, err := svc.CreateRSAKey(context.Background(), CreateKeyRequest{
		Name:   "hsm-key",
		Bits:   2048,
		UserID: uuid.New(),
		Type:   "RSA",
	})
	require.NoError(t, err)
	assert.NotNil(t, result)
	require.NotNil(t, createdKey)
	assert.Equal(t, "pkcs11:"+pkcs11UUID, createdKey.Value)
}

// ─── CreateECDSAKey ───────────────────────────────────────────────────────────

func TestCreateECDSAKey_InvalidCurve(t *testing.T) {
	repo := &mockKeyRepository{}
	provider := &mockKeyProviderForService{}

	svc := NewKeyService(KeyServiceConfig{
		KeyRepository: repo,
		KeyProvider:   provider,
		Logger:        newKeyLogger(),
	})

	_, err := svc.CreateECDSAKey(context.Background(), CreateKeyRequest{
		Name:   "bad-curve",
		Curve:  "P-192", // unsupported
		UserID: uuid.New(),
		Type:   "ECDSA",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid ECDSA curve")
}

func TestCreateECDSAKey_ProviderError(t *testing.T) {
	repo := &mockKeyRepository{}
	provider := &mockKeyProviderForService{}
	provider.On("GenerateECDSAKey", "P-256").Return("", errors.New("generate error"))

	svc := NewKeyService(KeyServiceConfig{
		KeyRepository: repo,
		KeyProvider:   provider,
		Logger:        newKeyLogger(),
	})

	_, err := svc.CreateECDSAKey(context.Background(), CreateKeyRequest{
		Name:   "key",
		Curve:  "P-256",
		UserID: uuid.New(),
		Type:   "ECDSA",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to generate ECDSA key")
}

func TestCreateECDSAKey_SuccessP256(t *testing.T) {
	setupKeyTestMasterKey()

	softwareProvider := crypto.NewSoftwareKeyProvider()

	repo := &mockKeyRepository{}
	repo.On("Create", mock.Anything, mock.AnythingOfType("*model.Key")).Return(nil)

	userID := uuid.New()
	svc := NewKeyService(KeyServiceConfig{
		KeyRepository: repo,
		KeyProvider:   softwareProvider,
		Logger:        newKeyLogger(),
	})

	result, err := svc.CreateECDSAKey(context.Background(), CreateKeyRequest{
		Name:   "ec-key",
		Curve:  "P-256",
		UserID: userID,
		Type:   "ECDSA",
	})
	require.NoError(t, err)
	assert.NotNil(t, result)
	assert.Equal(t, "ec-key", result.Name)
	assert.Equal(t, model.KeyTypeECDSA, result.Type)
	repo.AssertExpectations(t)
}

func TestCreateECDSAKey_SuccessP256K(t *testing.T) {
	setupKeyTestMasterKey()

	softwareProvider := crypto.NewSoftwareKeyProvider()

	repo := &mockKeyRepository{}
	var createdKey *model.Key
	repo.On("Create", mock.Anything, mock.AnythingOfType("*model.Key")).
		Run(func(args mock.Arguments) { createdKey = args.Get(1).(*model.Key) }).
		Return(nil)

	svc := NewKeyService(KeyServiceConfig{
		KeyRepository: repo,
		KeyProvider:   softwareProvider,
		Logger:        newKeyLogger(),
	})

	result, err := svc.CreateECDSAKey(context.Background(), CreateKeyRequest{
		Name:   "secp256k1-key",
		Curve:  "P-256K",
		UserID: uuid.New(),
		Type:   "ECDSA",
	})
	require.NoError(t, err)
	assert.NotNil(t, result)
	require.NotNil(t, createdKey)
	// P-256K keys get type ES256K.
	assert.Equal(t, model.KeyTypeES256K, createdKey.Type)
}

func TestCreateECDSAKey_WithExplicitDisabled(t *testing.T) {
	setupKeyTestMasterKey()

	softwareProvider := crypto.NewSoftwareKeyProvider()

	repo := &mockKeyRepository{}
	var createdKey *model.Key
	repo.On("Create", mock.Anything, mock.AnythingOfType("*model.Key")).
		Run(func(args mock.Arguments) { createdKey = args.Get(1).(*model.Key) }).
		Return(nil)

	disabled := false
	svc := NewKeyService(KeyServiceConfig{
		KeyRepository: repo,
		KeyProvider:   softwareProvider,
		Logger:        newKeyLogger(),
	})

	_, err := svc.CreateECDSAKey(context.Background(), CreateKeyRequest{
		Name:    "ec-disabled",
		Curve:   "P-384",
		UserID:  uuid.New(),
		Enabled: &disabled,
	})
	require.NoError(t, err)
	require.NotNil(t, createdKey)
	assert.False(t, createdKey.Enabled)
}

func TestCreateECDSAKey_RepoCreateFails(t *testing.T) {
	setupKeyTestMasterKey()

	softwareProvider := crypto.NewSoftwareKeyProvider()

	repo := &mockKeyRepository{}
	repo.On("Create", mock.Anything, mock.AnythingOfType("*model.Key")).
		Return(errors.New("db error"))

	svc := NewKeyService(KeyServiceConfig{
		KeyRepository: repo,
		KeyProvider:   softwareProvider,
		Logger:        newKeyLogger(),
	})

	_, err := svc.CreateECDSAKey(context.Background(), CreateKeyRequest{
		Name:   "ec-fail",
		Curve:  "P-521",
		UserID: uuid.New(),
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to store ECDSA key")
}

func TestCreateECDSAKey_WithPKCS11Handle(t *testing.T) {
	pkcs11UUID := uuid.New().String()

	provider := &mockKeyProviderForService{}
	provider.On("GenerateECDSAKey", "P-256").Return(pkcs11UUID, nil)

	repo := &mockKeyRepository{}
	var createdKey *model.Key
	repo.On("Create", mock.Anything, mock.AnythingOfType("*model.Key")).
		Run(func(args mock.Arguments) { createdKey = args.Get(1).(*model.Key) }).
		Return(nil)

	svc := NewKeyService(KeyServiceConfig{
		KeyRepository: repo,
		KeyProvider:   provider,
		Logger:        newKeyLogger(),
	})

	_, err := svc.CreateECDSAKey(context.Background(), CreateKeyRequest{
		Name:   "hsm-ec",
		Curve:  "P-256",
		UserID: uuid.New(),
	})
	require.NoError(t, err)
	require.NotNil(t, createdKey)
	assert.Equal(t, "pkcs11:"+pkcs11UUID, createdKey.Value)
}

// ─── CreateOctKey ─────────────────────────────────────────────────────────────

func TestCreateOctKey_Success(t *testing.T) {
	userID := uuid.New()
	repo := &mockKeyRepository{}
	repo.On("Create", mock.Anything, mock.MatchedBy(func(k *model.Key) bool {
		return k.Type == model.KeyTypeOct && k.Bits == 256
	})).Return(nil)

	provider := &mockKeyProviderForService{}
	provider.On("GenerateAESKey", 256).Return("aes-label", nil)

	svc := NewKeyService(KeyServiceConfig{KeyRepository: repo, KeyProvider: provider, Logger: newKeyLogger()})

	result, err := svc.CreateOctKey(context.Background(), CreateKeyRequest{
		Name: "my-aes-key", Bits: 256, UserID: userID,
	})
	require.NoError(t, err)
	assert.Equal(t, model.KeyTypeOct, result.Type)
	repo.AssertExpectations(t)
	provider.AssertExpectations(t)
}

func TestCreateOctKey_InvalidBits_ReturnsError(t *testing.T) {
	svc := NewKeyService(KeyServiceConfig{KeyRepository: &mockKeyRepository{}, KeyProvider: &mockKeyProviderForService{}, Logger: newKeyLogger()})

	_, err := svc.CreateOctKey(context.Background(), CreateKeyRequest{
		Name: "bad", Bits: 100, UserID: uuid.New(),
	})
	assert.Error(t, err)
}

func TestCreateOctKey_SoftwareProvider_ReturnsError(t *testing.T) {
	repo := &mockKeyRepository{}
	provider := &mockKeyProviderForService{}
	provider.On("GenerateAESKey", 256).Return("", crypto.ErrOctKeysRequireHSM)

	svc := NewKeyService(KeyServiceConfig{KeyRepository: repo, KeyProvider: provider, Logger: newKeyLogger()})

	_, err := svc.CreateOctKey(context.Background(), CreateKeyRequest{
		Name: "my-aes-key", Bits: 256, UserID: uuid.New(),
	})
	require.ErrorIs(t, err, crypto.ErrOctKeysRequireHSM)
	repo.AssertNotCalled(t, "Create", mock.Anything, mock.Anything)
}

// ─── ListKeys ─────────────────────────────────────────────────────────────────

func TestListKeys_Success(t *testing.T) {
	userID := uuid.New()
	repo := &mockKeyRepository{}
	expected := []model.Key{{ID: uuid.New(), UserID: userID, Name: "k1", Enabled: true}}
	repo.On("List", mock.Anything, model.NewOwnerScope(uuid.Nil, userID), repositories.KeyFilter{}).Return(expected, nil)

	svc := NewKeyService(KeyServiceConfig{KeyRepository: repo, Logger: newKeyLogger()})
	got, err := svc.ListKeys(context.Background(), model.NewOwnerScope(uuid.Nil, userID), repositories.KeyFilter{})
	require.NoError(t, err)
	assert.Equal(t, expected, got)
	repo.AssertExpectations(t)
}

func TestListKeys_RepositoryError(t *testing.T) {
	userID := uuid.New()
	repo := &mockKeyRepository{}
	repo.On("List", mock.Anything, model.NewOwnerScope(uuid.Nil, userID), repositories.KeyFilter{}).Return(nil, errors.New("db error"))

	svc := NewKeyService(KeyServiceConfig{KeyRepository: repo, Logger: newKeyLogger()})
	_, err := svc.ListKeys(context.Background(), model.NewOwnerScope(uuid.Nil, userID), repositories.KeyFilter{})
	assert.Error(t, err)
}

// ─── ValidateKeyAccess ────────────────────────────────────────────────────────

func TestValidateKeyAccess_AdminBypasses(t *testing.T) {
	keyID := uuid.New()
	userID := uuid.New()
	repo := &mockKeyRepository{}

	svc := NewKeyService(KeyServiceConfig{KeyRepository: repo, Logger: newKeyLogger()})
	err := svc.ValidateKeyAccess(context.Background(), keyID, userID, model.RoleAdmin)
	require.NoError(t, err)
	repo.AssertNotCalled(t, "Read", mock.Anything, mock.Anything)
}

func TestValidateKeyAccess_OwnerGranted(t *testing.T) {
	userID := uuid.New()
	keyID := uuid.New()
	repo := &mockKeyRepository{}
	repo.On("Read", mock.Anything, keyID, model.NewAdminScope(userID)).Return(accessibleKey(userID, keyID), nil)

	svc := NewKeyService(KeyServiceConfig{KeyRepository: repo, Logger: newKeyLogger()})
	err := svc.ValidateKeyAccess(context.Background(), keyID, userID, "")
	require.NoError(t, err)
}

func TestValidateKeyAccess_ForbiddenForOtherUser(t *testing.T) {
	ownerID := uuid.New()
	callerID := uuid.New()
	keyID := uuid.New()
	repo := &mockKeyRepository{}
	repo.On("Read", mock.Anything, keyID, model.NewAdminScope(callerID)).Return(accessibleKey(ownerID, keyID), nil)

	svc := NewKeyService(KeyServiceConfig{KeyRepository: repo, Logger: newKeyLogger()})
	err := svc.ValidateKeyAccess(context.Background(), keyID, callerID, "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "forbidden")
}

func TestValidateKeyAccess_KeyNotFound(t *testing.T) {
	keyID := uuid.New()
	userID := uuid.New()
	repo := &mockKeyRepository{}
	repo.On("Read", mock.Anything, keyID, model.NewAdminScope(userID)).Return(nil, errors.New("not found"))

	svc := NewKeyService(KeyServiceConfig{KeyRepository: repo, Logger: newKeyLogger()})
	err := svc.ValidateKeyAccess(context.Background(), keyID, userID, "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "key not found")
}

// ─── GetKey – additional branches ────────────────────────────────────────────

func TestGetKey_WrongOwner(t *testing.T) {
	callerID := uuid.New()
	keyID := uuid.New()
	repo := &mockKeyRepository{}
	// A non-owner's scoped read finds no matching row, same as the SQL
	// predicate excluding it; the access check happens at the scoped read,
	// not via a separate Go-level ownership comparison.
	repo.On("Read", mock.Anything, keyID, model.NewOwnerScope(uuid.Nil, callerID)).
		Return(nil, errors.New("key not found or access denied"))

	svc := NewKeyService(KeyServiceConfig{KeyRepository: repo, Logger: newKeyLogger()})
	_, err := svc.GetKey(context.Background(), keyID, model.NewOwnerScope(uuid.Nil, callerID))
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrKeyNotFound)
}

func TestGetKey_LifecycleDenied(t *testing.T) {
	userID := uuid.New()
	keyID := uuid.New()
	repo := &mockKeyRepository{}
	repo.On("Read", mock.Anything, keyID, model.NewOwnerScope(uuid.Nil, userID)).Return(&model.Key{
		ID:      keyID,
		UserID:  userID,
		Enabled: false,
	}, nil)

	svc := NewKeyService(KeyServiceConfig{KeyRepository: repo, Logger: newKeyLogger()})
	_, err := svc.GetKey(context.Background(), keyID, model.NewOwnerScope(uuid.Nil, userID))
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrKeyLifecycleDenied)
}

// ─── isPKCS11Handle ───────────────────────────────────────────────────────────

func TestIsPKCS11Handle_ValidUUID(t *testing.T) {
	assert.True(t, isPKCS11Handle(uuid.New().String()))
}

func TestIsPKCS11Handle_PEM(t *testing.T) {
	assert.False(t, isPKCS11Handle("-----BEGIN RSA PRIVATE KEY-----\n..."))
}

func TestIsPKCS11Handle_TooShort(t *testing.T) {
	assert.False(t, isPKCS11Handle("short"))
}

// ─── CryptoService – Verify / Encrypt / Decrypt / resolveKeyHandle ────────────

// The CryptoService tests use real RSA key material and a real common.EncryptSecret
// so they exercise the software path (not PKCS#11).

func TestCryptoService_Verify_Success(t *testing.T) {
	setupKeyTestMasterKey()

	softwareProvider := crypto.NewSoftwareKeyProvider()

	privateKeyPEM, err := crypto.GenerateRSAKeyPEM(2048)
	require.NoError(t, err)

	encryptedPEM, err := common.EncryptSecret(privateKeyPEM)
	require.NoError(t, err)

	userID := uuid.New()
	keyID := uuid.New()
	key := &model.Key{ID: keyID, UserID: userID, Type: model.KeyTypeRSA, Value: encryptedPEM, Enabled: true}

	repo := &mockKeyRepoForExtendedCrypto{}
	repo.On("Read", mock.Anything, keyID, model.NewOwnerScope(uuid.Nil, userID)).Return(key, nil)

	svc := NewCryptoService(CryptoServiceConfig{
		KeyRepository: repo,
		KeyProvider:   softwareProvider,
		Logger:        newKeyLogger(),
	})

	// First sign some data.
	data := []byte("verify me")
	signResult, err := svc.Sign(context.Background(), SignRequest{
		KeyID:     keyID,
		UserID:    userID,
		Scope:     model.NewOwnerScope(uuid.Nil, userID),
		Data:      data,
		Algorithm: crypto.AlgorithmRS256,
	})
	require.NoError(t, err)

	// Then verify the signature.
	verifyResult, err := svc.Verify(context.Background(), VerifyRequest{
		KeyID:     keyID,
		UserID:    userID,
		Scope:     model.NewOwnerScope(uuid.Nil, userID),
		Data:      data,
		Signature: signResult.Signature,
		Algorithm: crypto.AlgorithmRS256,
	})
	require.NoError(t, err)
	assert.True(t, verifyResult.Valid)

	// Verify tampered data returns valid=false.
	verifyResult2, err := svc.Verify(context.Background(), VerifyRequest{
		KeyID:     keyID,
		UserID:    userID,
		Scope:     model.NewOwnerScope(uuid.Nil, userID),
		Data:      []byte("tampered"),
		Signature: signResult.Signature,
		Algorithm: crypto.AlgorithmRS256,
	})
	require.NoError(t, err)
	assert.False(t, verifyResult2.Valid)
}

func TestCryptoService_Verify_KeyNotFound(t *testing.T) {
	repo := &mockKeyRepoForExtendedCrypto{}
	keyID := uuid.New()
	userID := uuid.New()
	repo.On("Read", mock.Anything, keyID, model.NewOwnerScope(uuid.Nil, userID)).Return(nil, errors.New("not found"))

	svc := NewCryptoService(CryptoServiceConfig{
		KeyRepository: repo,
		Logger:        newKeyLogger(),
	})
	_, err := svc.Verify(context.Background(), VerifyRequest{
		KeyID:     keyID,
		UserID:    userID,
		Scope:     model.NewOwnerScope(uuid.Nil, userID),
		Data:      []byte("data"),
		Signature: []byte("sig"),
		Algorithm: crypto.AlgorithmRS256,
	})
	require.Error(t, err)
}

func TestCryptoService_Encrypt_Success(t *testing.T) {
	setupKeyTestMasterKey()

	softwareProvider := crypto.NewSoftwareKeyProvider()

	privateKeyPEM, err := crypto.GenerateRSAKeyPEM(2048)
	require.NoError(t, err)

	encryptedPEM, err := common.EncryptSecret(privateKeyPEM)
	require.NoError(t, err)

	userID := uuid.New()
	keyID := uuid.New()
	key := &model.Key{ID: keyID, UserID: userID, Type: model.KeyTypeRSA, Value: encryptedPEM, Enabled: true}

	repo := &mockKeyRepoForExtendedCrypto{}
	repo.On("Read", mock.Anything, keyID, model.NewOwnerScope(uuid.Nil, userID)).Return(key, nil)

	svc := NewCryptoService(CryptoServiceConfig{
		KeyRepository: repo,
		KeyProvider:   softwareProvider,
		Logger:        newKeyLogger(),
	})

	encResult, err := svc.Encrypt(context.Background(), EncryptRequest{
		KeyID:     keyID,
		UserID:    userID,
		Scope:     model.NewOwnerScope(uuid.Nil, userID),
		Data:      []byte("sensitive data"),
		Algorithm: crypto.AlgorithmRSAOAEP,
	})
	require.NoError(t, err)
	assert.NotEmpty(t, encResult.Ciphertext)
	assert.Equal(t, crypto.AlgorithmRSAOAEP, encResult.Algorithm)
}

func TestCryptoService_Decrypt_Success(t *testing.T) {
	setupKeyTestMasterKey()

	softwareProvider := crypto.NewSoftwareKeyProvider()

	privateKeyPEM, err := crypto.GenerateRSAKeyPEM(2048)
	require.NoError(t, err)

	encryptedPEM, err := common.EncryptSecret(privateKeyPEM)
	require.NoError(t, err)

	userID := uuid.New()
	keyID := uuid.New()
	key := &model.Key{ID: keyID, UserID: userID, Type: model.KeyTypeRSA, Value: encryptedPEM, Enabled: true}

	repo := &mockKeyRepoForExtendedCrypto{}
	repo.On("Read", mock.Anything, keyID, model.NewOwnerScope(uuid.Nil, userID)).Return(key, nil)

	svc := NewCryptoService(CryptoServiceConfig{
		KeyRepository: repo,
		KeyProvider:   softwareProvider,
		Logger:        newKeyLogger(),
	})

	plaintext := []byte("sensitive payload")

	// Encrypt first.
	encResult, err := svc.Encrypt(context.Background(), EncryptRequest{
		KeyID:     keyID,
		UserID:    userID,
		Scope:     model.NewOwnerScope(uuid.Nil, userID),
		Data:      plaintext,
		Algorithm: crypto.AlgorithmRSAOAEP,
	})
	require.NoError(t, err)

	// Now decrypt.
	decResult, err := svc.Decrypt(context.Background(), DecryptRequest{
		KeyID:      keyID,
		UserID:     userID,
		Scope:      model.NewOwnerScope(uuid.Nil, userID),
		Ciphertext: encResult.Ciphertext,
		Algorithm:  crypto.AlgorithmRSAOAEP,
	})
	require.NoError(t, err)
	assert.Equal(t, plaintext, decResult.Plaintext)
}

func TestCryptoService_Encrypt_KeyNotFound(t *testing.T) {
	repo := &mockKeyRepoForExtendedCrypto{}
	keyID := uuid.New()
	userID := uuid.New()
	repo.On("Read", mock.Anything, keyID, model.NewOwnerScope(uuid.Nil, userID)).Return(nil, errors.New("not found"))

	svc := NewCryptoService(CryptoServiceConfig{
		KeyRepository: repo,
		Logger:        newKeyLogger(),
	})
	_, err := svc.Encrypt(context.Background(), EncryptRequest{
		KeyID: keyID, UserID: userID, Scope: model.NewOwnerScope(uuid.Nil, userID),
		Data: []byte("data"), Algorithm: crypto.AlgorithmRSAOAEP,
	})
	require.Error(t, err)
}

func TestCryptoService_Decrypt_KeyNotFound(t *testing.T) {
	repo := &mockKeyRepoForExtendedCrypto{}
	keyID := uuid.New()
	userID := uuid.New()
	repo.On("Read", mock.Anything, keyID, model.NewOwnerScope(uuid.Nil, userID)).Return(nil, errors.New("not found"))

	svc := NewCryptoService(CryptoServiceConfig{
		KeyRepository: repo,
		Logger:        newKeyLogger(),
	})
	_, err := svc.Decrypt(context.Background(), DecryptRequest{
		KeyID: keyID, UserID: userID, Scope: model.NewOwnerScope(uuid.Nil, userID),
		Ciphertext: []byte("data"), Algorithm: crypto.AlgorithmRSAOAEP,
	})
	require.Error(t, err)
}

// ─── wrapAlgorithmToEncryption ────────────────────────────────────────────────

func TestWrapAlgorithmToEncryption_AllCases(t *testing.T) {
	cases := map[string]crypto.EncryptionAlgorithm{
		"RSA-OAEP-256": crypto.AlgorithmRSAOAEP256,
		"RSA-OAEP":     crypto.AlgorithmRSAOAEP,
		"A128KW":       crypto.AlgorithmA128KW,
		"A192KW":       crypto.AlgorithmA192KW,
		"A256KW":       crypto.AlgorithmA256KW,
		"A128CBC":      crypto.AlgorithmA128CBC,
		"A192CBC":      crypto.AlgorithmA192CBC,
		"A256CBC":      crypto.AlgorithmA256CBC,
	}
	for input, expected := range cases {
		got, err := wrapAlgorithmToEncryption(input)
		require.NoError(t, err)
		assert.Equal(t, expected, got, "algorithm: "+input)
	}
}

// ─── resolveKeyHandle ─────────────────────────────────────────────────────────

func TestResolveKeyHandle_PKCS11(t *testing.T) {
	label := uuid.New().String()
	handle, isPKCS11, err := resolveKeyHandle("pkcs11:" + label)
	require.NoError(t, err)
	assert.True(t, isPKCS11)
	assert.Equal(t, label, handle)
}

func TestResolveKeyHandle_SoftwareKey(t *testing.T) {
	setupKeyTestMasterKey()

	pem := "-----BEGIN RSA PRIVATE KEY-----\nsomepemdata\n-----END RSA PRIVATE KEY-----"
	encrypted, err := common.EncryptSecret(pem)
	require.NoError(t, err)

	handle, isPKCS11, err := resolveKeyHandle(encrypted)
	require.NoError(t, err)
	assert.False(t, isPKCS11)
	assert.Equal(t, pem, handle)
}

func TestResolveKeyHandle_InvalidEncrypted(t *testing.T) {
	setupKeyTestMasterKey()
	_, _, err := resolveKeyHandle("not-encrypted-data")
	require.Error(t, err)
}

// ─── LoadAndAuthorize – revoked and inaccessible branches ─────────────────────

func TestCryptoService_Sign_RevokedKey(t *testing.T) {
	repo := &mockKeyRepoForExtendedCrypto{}
	keyID := uuid.New()
	userID := uuid.New()
	repo.On("Read", mock.Anything, keyID, model.NewOwnerScope(uuid.Nil, userID)).Return(&model.Key{
		ID: keyID, UserID: userID, Revoked: true, Enabled: true,
	}, nil)

	svc := NewCryptoService(CryptoServiceConfig{
		KeyRepository: repo,
		Logger:        newKeyLogger(),
	})
	_, err := svc.Sign(context.Background(), SignRequest{
		KeyID: keyID, UserID: userID, Scope: model.NewOwnerScope(uuid.Nil, userID),
		Data: []byte("data"), Algorithm: crypto.AlgorithmRS256,
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "revoked")
}

func TestCryptoService_Sign_InaccessibleKey(t *testing.T) {
	repo := &mockKeyRepoForExtendedCrypto{}
	keyID := uuid.New()
	userID := uuid.New()
	repo.On("Read", mock.Anything, keyID, model.NewOwnerScope(uuid.Nil, userID)).Return(&model.Key{
		ID: keyID, UserID: userID, Revoked: false, Enabled: false,
	}, nil)

	svc := NewCryptoService(CryptoServiceConfig{
		KeyRepository: repo,
		Logger:        newKeyLogger(),
	})
	_, err := svc.Sign(context.Background(), SignRequest{
		KeyID: keyID, UserID: userID, Scope: model.NewOwnerScope(uuid.Nil, userID),
		Data: []byte("data"), Algorithm: crypto.AlgorithmRS256,
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "disabled or outside its valid time window")
}

// ─── mockKeyRepoForExtendedCrypto ─────────────────────────────────────────────

// Reuse fields from mockKeyRepository defined in key_soft_delete_test.go.
// We need a separate mock here because crypto_service_cache_test.go is in a
// different package (keys_test) and mockKeyRepoForWrap is not accessible from
// this package-level test file.

type mockKeyRepoForExtendedCrypto struct{ mock.Mock }

func (m *mockKeyRepoForExtendedCrypto) Create(ctx context.Context, k *model.Key) error { return nil }
func (m *mockKeyRepoForExtendedCrypto) Delete(ctx context.Context, id uuid.UUID) error { return nil }
func (m *mockKeyRepoForExtendedCrypto) UpdateRevocationStatus(ctx context.Context, id uuid.UUID, revoked bool) error {
	return nil
}
func (m *mockKeyRepoForExtendedCrypto) SoftDelete(ctx context.Context, id uuid.UUID) error {
	return nil
}
func (m *mockKeyRepoForExtendedCrypto) RecoverKey(ctx context.Context, id uuid.UUID) error {
	return nil
}
func (m *mockKeyRepoForExtendedCrypto) PurgeKey(ctx context.Context, id uuid.UUID) error { return nil }
func (m *mockKeyRepoForExtendedCrypto) SetPurgeProtection(ctx context.Context, id uuid.UUID, enabled bool) error {
	return nil
}
func (m *mockKeyRepoForExtendedCrypto) ReadDeletedScoped(ctx context.Context, id uuid.UUID, scope model.Scope) (*model.Key, error) {
	return nil, nil
}
func (m *mockKeyRepoForExtendedCrypto) CreateVersion(ctx context.Context, keyID uuid.UUID, version int, value string) error {
	return nil
}
func (m *mockKeyRepoForExtendedCrypto) ListVersions(ctx context.Context, keyID uuid.UUID) ([]model.KeyVersion, error) {
	return nil, nil
}
func (m *mockKeyRepoForExtendedCrypto) CurrentVersion(ctx context.Context, keyID uuid.UUID) (int, error) {
	return 1, nil
}
func (m *mockKeyRepoForExtendedCrypto) ReadVersionValue(ctx context.Context, keyID uuid.UUID, version int) (string, error) {
	return "", nil
}
func (m *mockKeyRepoForExtendedCrypto) GetVersion(ctx context.Context, keyID uuid.UUID, version int) (*model.KeyVersion, error) {
	return nil, nil
}
func (m *mockKeyRepoForExtendedCrypto) ListVersionRecords(ctx context.Context, keyID uuid.UUID) ([]model.KeyVersionRecord, error) {
	return nil, nil
}
func (m *mockKeyRepoForExtendedCrypto) SoftDeleteVaultContents(ctx context.Context, vaultID uuid.UUID, deletedAt time.Time) error {
	return nil
}
func (m *mockKeyRepoForExtendedCrypto) RecoverVaultContents(ctx context.Context, vaultID uuid.UUID, deletedAt time.Time) error {
	return nil
}
func (m *mockKeyRepoForExtendedCrypto) Read(ctx context.Context, id uuid.UUID, scope model.Scope) (*model.Key, error) {
	args := m.Called(ctx, id, scope)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*model.Key), args.Error(1)
}
func (m *mockKeyRepoForExtendedCrypto) Update(ctx context.Context, key *model.Key, scope model.Scope) error {
	return nil
}
func (m *mockKeyRepoForExtendedCrypto) List(ctx context.Context, scope model.Scope, filter repositories.KeyFilter) ([]model.Key, error) {
	return nil, nil
}

// ─── ImportKey ────────────────────────────────────────────────────────────────

func TestImportKey_SuccessWithSoftwareKey_RSA(t *testing.T) {
	setupKeyTestMasterKey()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	jwk := jose.JSONWebKey{Key: priv}
	jwkJSON, err := jwk.MarshalJSON()
	require.NoError(t, err)

	repo := &mockKeyRepository{}
	var createdKey *model.Key
	repo.On("Create", mock.Anything, mock.Anything).
		Run(func(args mock.Arguments) { createdKey = args.Get(1).(*model.Key) }).
		Return(nil)

	svc := NewKeyService(KeyServiceConfig{
		KeyRepository: repo,
		KeyProvider:   crypto.NewSoftwareKeyProvider(),
		Logger:        newKeyLogger(),
	})

	userID := uuid.New()
	result, err := svc.ImportKey(context.Background(), ImportKeyRequest{
		Name:   "imported-rsa",
		JWK:    jwkJSON,
		UserID: userID,
	})
	require.NoError(t, err)
	assert.Equal(t, "imported-rsa", result.Name)
	assert.Equal(t, model.KeyTypeRSA, result.Type)

	require.NotNil(t, createdKey)
	assert.Equal(t, model.KeyTypeRSA, createdKey.Type)
	assert.NotEmpty(t, createdKey.Value)
	// Value is common.EncryptSecret-encrypted PEM, not the raw handle.
	assert.NotContains(t, createdKey.Value, "PRIVATE KEY")
	repo.AssertExpectations(t)
}

func TestImportKey_SuccessWithSoftwareKey_ECDSA(t *testing.T) {
	setupKeyTestMasterKey()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	jwk := jose.JSONWebKey{Key: priv}
	jwkJSON, err := jwk.MarshalJSON()
	require.NoError(t, err)

	repo := &mockKeyRepository{}
	repo.On("Create", mock.Anything, mock.Anything).Return(nil)

	svc := NewKeyService(KeyServiceConfig{
		KeyRepository: repo,
		KeyProvider:   crypto.NewSoftwareKeyProvider(),
		Logger:        newKeyLogger(),
	})

	result, err := svc.ImportKey(context.Background(), ImportKeyRequest{
		Name:   "imported-ecdsa",
		JWK:    jwkJSON,
		UserID: uuid.New(),
	})
	require.NoError(t, err)
	assert.Equal(t, model.KeyTypeECDSA, result.Type)
	repo.AssertExpectations(t)
}

func TestImportKey_MalformedJWK_Rejected(t *testing.T) {
	svc := NewKeyService(KeyServiceConfig{
		KeyRepository: &mockKeyRepository{},
		KeyProvider:   &mockKeyProviderForService{},
		Logger:        newKeyLogger(),
	})

	_, err := svc.ImportKey(context.Background(), ImportKeyRequest{
		Name:   "bad",
		JWK:    []byte("not json"),
		UserID: uuid.New(),
	})
	require.Error(t, err)
}

func TestImportKey_PublicOnlyJWK_Rejected(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	jwk := jose.JSONWebKey{Key: &priv.PublicKey}
	jwkJSON, err := jwk.MarshalJSON()
	require.NoError(t, err)

	svc := NewKeyService(KeyServiceConfig{
		KeyRepository: &mockKeyRepository{},
		KeyProvider:   &mockKeyProviderForService{},
		Logger:        newKeyLogger(),
	})

	_, err = svc.ImportKey(context.Background(), ImportKeyRequest{
		Name:   "public-only",
		JWK:    jwkJSON,
		UserID: uuid.New(),
	})
	require.ErrorIs(t, err, signing.ErrJWKNoPrivateKey)
}

func TestImportKey_ProviderStoresPKCS11Handle_NotEncrypted(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	jwk := jose.JSONWebKey{Key: priv}
	jwkJSON, err := jwk.MarshalJSON()
	require.NoError(t, err)

	provider := &mockKeyProviderForService{}
	// A PKCS#11 handle is a 36-char UUID label, per isPKCS11Handle.
	provider.On("ImportKey", "RSA", mock.Anything).Return("11111111-2222-3333-4444-555555555555", nil)

	repo := &mockKeyRepository{}
	var createdKey *model.Key
	repo.On("Create", mock.Anything, mock.Anything).
		Run(func(args mock.Arguments) { createdKey = args.Get(1).(*model.Key) }).
		Return(nil)

	svc := NewKeyService(KeyServiceConfig{
		KeyRepository: repo,
		KeyProvider:   provider,
		Logger:        newKeyLogger(),
	})

	_, err = svc.ImportKey(context.Background(), ImportKeyRequest{
		Name:   "hsm-imported",
		JWK:    jwkJSON,
		UserID: uuid.New(),
	})
	require.NoError(t, err)
	require.NotNil(t, createdKey)
	assert.Equal(t, "pkcs11:11111111-2222-3333-4444-555555555555", createdKey.Value)
}

// TestImportKey_StoresBitsAndCurve pins the fix for the "silent key
// downgrade on rotation" bug: ImportKey's model.Key literal previously
// omitted Bits/Curve entirely, so RotateKey's zero-value fallback (2048 /
// P-256) silently replaced a stronger imported key on its first rotation.
func TestImportKey_StoresBitsAndCurve_RSA(t *testing.T) {
	setupKeyTestMasterKey()
	priv, err := rsa.GenerateKey(rand.Reader, 4096)
	require.NoError(t, err)
	jwk := jose.JSONWebKey{Key: priv}
	jwkJSON, err := jwk.MarshalJSON()
	require.NoError(t, err)

	repo := &mockKeyRepository{}
	var createdKey *model.Key
	repo.On("Create", mock.Anything, mock.Anything).
		Run(func(args mock.Arguments) { createdKey = args.Get(1).(*model.Key) }).
		Return(nil)

	svc := NewKeyService(KeyServiceConfig{
		KeyRepository: repo,
		KeyProvider:   crypto.NewSoftwareKeyProvider(),
		Logger:        newKeyLogger(),
	})

	_, err = svc.ImportKey(context.Background(), ImportKeyRequest{
		Name:   "imported-rsa-4096",
		JWK:    jwkJSON,
		UserID: uuid.New(),
	})
	require.NoError(t, err)
	require.NotNil(t, createdKey)
	assert.Equal(t, 4096, createdKey.Bits)
	assert.Empty(t, createdKey.Curve)
}

func TestImportKey_StoresBitsAndCurve_ECDSA(t *testing.T) {
	setupKeyTestMasterKey()
	priv, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	require.NoError(t, err)
	jwk := jose.JSONWebKey{Key: priv}
	jwkJSON, err := jwk.MarshalJSON()
	require.NoError(t, err)

	repo := &mockKeyRepository{}
	var createdKey *model.Key
	repo.On("Create", mock.Anything, mock.Anything).
		Run(func(args mock.Arguments) { createdKey = args.Get(1).(*model.Key) }).
		Return(nil)

	svc := NewKeyService(KeyServiceConfig{
		KeyRepository: repo,
		KeyProvider:   crypto.NewSoftwareKeyProvider(),
		Logger:        newKeyLogger(),
	})

	_, err = svc.ImportKey(context.Background(), ImportKeyRequest{
		Name:   "imported-ecdsa-p521",
		JWK:    jwkJSON,
		UserID: uuid.New(),
	})
	require.NoError(t, err)
	require.NotNil(t, createdKey)
	assert.Equal(t, "P-521", createdKey.Curve)
	assert.Zero(t, createdKey.Bits)
}

// TestImportKey_ThenRotate_PreservesOriginalStrength is the regression guard
// for the exact downgrade bug: import a key stronger than RotateKey's
// hardcoded fallback (4096-bit RSA vs. the 2048 fallback), then rotate it,
// and assert the rotated key is generated at the ORIGINAL strength rather
// than silently downgraded. Against the pre-fix code (Bits/Curve omitted
// from ImportKey's model.Key literal) this test fails: RotateKey would read
// back Bits == 0, fall back to 2048, and generate a 2048-bit replacement.
func TestImportKey_ThenRotate_PreservesOriginalStrength_RSA(t *testing.T) {
	setupKeyTestMasterKey()
	priv, err := rsa.GenerateKey(rand.Reader, 4096)
	require.NoError(t, err)
	jwk := jose.JSONWebKey{Key: priv}
	jwkJSON, err := jwk.MarshalJSON()
	require.NoError(t, err)

	repo := &mockKeyRepository{}
	var importedKey *model.Key
	repo.On("Create", mock.Anything, mock.Anything).
		Run(func(args mock.Arguments) { importedKey = args.Get(1).(*model.Key) }).
		Return(nil)

	provider := crypto.NewSoftwareKeyProvider()
	svc := NewKeyService(KeyServiceConfig{
		KeyRepository: repo,
		KeyProvider:   provider,
		Logger:        newKeyLogger(),
	})

	ownerID := uuid.New()
	_, err = svc.ImportKey(context.Background(), ImportKeyRequest{
		Name:   "imported-rsa-4096",
		JWK:    jwkJSON,
		UserID: ownerID,
	})
	require.NoError(t, err)
	require.NotNil(t, importedKey)
	require.Equal(t, 4096, importedKey.Bits)

	// Now rotate the key that was just imported. Read returns exactly what
	// ImportKey persisted (Bits included), matching how the real repository
	// round-trips the row.
	scope := model.NewOwnerScope(uuid.Nil, ownerID)
	repo.On("Read", mock.Anything, importedKey.ID, scope).Return(importedKey, nil)
	repo.On("ListVersions", mock.Anything, importedKey.ID).Return([]model.KeyVersion{}, nil)
	repo.On("CreateVersion", mock.Anything, importedKey.ID, mock.AnythingOfType("int"), mock.AnythingOfType("string")).Return(nil)

	var rotatedKey *model.Key
	repo.On("Update", mock.Anything, mock.AnythingOfType("*model.Key"), scope).
		Run(func(args mock.Arguments) { rotatedKey = args.Get(1).(*model.Key) }).
		Return(nil)

	_, err = svc.RotateKey(context.Background(), importedKey.ID, scope)
	require.NoError(t, err)
	require.NotNil(t, rotatedKey)
	assert.Equal(t, 4096, rotatedKey.Bits, "rotation must preserve the imported key's original strength, not fall back to the 2048 default")
}

func TestImportKey_ThenRotate_PreservesOriginalStrength_ECDSA(t *testing.T) {
	setupKeyTestMasterKey()
	priv, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	require.NoError(t, err)
	jwk := jose.JSONWebKey{Key: priv}
	jwkJSON, err := jwk.MarshalJSON()
	require.NoError(t, err)

	repo := &mockKeyRepository{}
	var importedKey *model.Key
	repo.On("Create", mock.Anything, mock.Anything).
		Run(func(args mock.Arguments) { importedKey = args.Get(1).(*model.Key) }).
		Return(nil)

	provider := crypto.NewSoftwareKeyProvider()
	svc := NewKeyService(KeyServiceConfig{
		KeyRepository: repo,
		KeyProvider:   provider,
		Logger:        newKeyLogger(),
	})

	ownerID := uuid.New()
	_, err = svc.ImportKey(context.Background(), ImportKeyRequest{
		Name:   "imported-ecdsa-p521",
		JWK:    jwkJSON,
		UserID: ownerID,
	})
	require.NoError(t, err)
	require.NotNil(t, importedKey)
	require.Equal(t, "P-521", importedKey.Curve)

	scope := model.NewOwnerScope(uuid.Nil, ownerID)
	repo.On("Read", mock.Anything, importedKey.ID, scope).Return(importedKey, nil)
	repo.On("ListVersions", mock.Anything, importedKey.ID).Return([]model.KeyVersion{}, nil)
	repo.On("CreateVersion", mock.Anything, importedKey.ID, mock.AnythingOfType("int"), mock.AnythingOfType("string")).Return(nil)

	var rotatedKey *model.Key
	repo.On("Update", mock.Anything, mock.AnythingOfType("*model.Key"), scope).
		Run(func(args mock.Arguments) { rotatedKey = args.Get(1).(*model.Key) }).
		Return(nil)

	_, err = svc.RotateKey(context.Background(), importedKey.ID, scope)
	require.NoError(t, err)
	require.NotNil(t, rotatedKey)
	assert.Equal(t, "P-521", rotatedKey.Curve, "rotation must preserve the imported key's original curve, not fall back to the P-256 default")
}

// ─── ImportKey: minimum RSA key size ───────────────────────────────────────

// TestImportKey_RSATooSmall_Rejected pins the minimum-RSA-size enforcement
// added to ImportKey: go-jose validates mathematical correctness but not
// size, so without this check a sub-2048-bit RSA JWK would be importable
// even though CreateRSAKey rejects the same size at generation time.
func TestImportKey_RSATooSmall_Rejected(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 1024)
	require.NoError(t, err)
	jwk := jose.JSONWebKey{Key: priv}
	jwkJSON, err := jwk.MarshalJSON()
	require.NoError(t, err)

	provider := &mockKeyProviderForService{}
	repo := &mockKeyRepository{}

	svc := NewKeyService(KeyServiceConfig{
		KeyRepository: repo,
		KeyProvider:   provider,
		Logger:        newKeyLogger(),
	})

	_, err = svc.ImportKey(context.Background(), ImportKeyRequest{
		Name:   "too-small",
		JWK:    jwkJSON,
		UserID: uuid.New(),
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "too small")

	provider.AssertNotCalled(t, "ImportKey", mock.Anything, mock.Anything)
	repo.AssertNotCalled(t, "Create", mock.Anything, mock.Anything)
}
