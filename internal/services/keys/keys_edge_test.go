// Edge tests for UpdateKey, DeleteKey, RotateKey, and Crypto Service error paths.
package keys

import (
	"context"
	"database/sql"
	"encoding/base64"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"rocketvault/common"
	"rocketvault/internal/crypto"
	"rocketvault/internal/keycache"
	"rocketvault/internal/logging"
	"rocketvault/model"
)

func testLogger() *logging.Logger {
	return &logging.Logger{Logger: logrus.New()}
}

func setupMasterKey(t *testing.T) {
	k := make([]byte, 32)
	for i := range k {
		k[i] = byte(i + 1)
	}
	viper.Set("master_key", base64.StdEncoding.EncodeToString(k))
	t.Cleanup(viper.Reset)
}

// ─── UpdateKey ───────────────────────────────────────────────────────────────

func TestUpdateKey_KeyNotFound(t *testing.T) {
	repo := &mockKeyRepository{}
	keyID := uuid.New()
	userID := uuid.New()
	repo.On("Read", mock.Anything, keyID, model.NewOwnerScope(uuid.Nil, userID)).Return(nil, errors.New("not found"))

	svc := &keyService{keyRepo: repo, logger: testLogger()}
	err := svc.UpdateKey(context.Background(), UpdateKeyRequest{KeyID: keyID, Scope: model.NewOwnerScope(uuid.Nil, userID)})
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrKeyNotFound)
}

// TestUpdateKey_WrongOwner asserts that a non-owner's scoped read finds no
// matching row, same as the SQL predicate excluding it. The access check
// happens at the scoped read, not via a separate Go-level ownership
// comparison, so the caller sees not-found rather than forbidden.
func TestUpdateKey_WrongOwner(t *testing.T) {
	repo := &mockKeyRepository{}
	keyID := uuid.New()
	callerID := uuid.New()
	repo.On("Read", mock.Anything, keyID, model.NewOwnerScope(uuid.Nil, callerID)).
		Return(nil, errors.New("key not found or access denied"))

	svc := &keyService{keyRepo: repo, logger: testLogger()}
	err := svc.UpdateKey(context.Background(), UpdateKeyRequest{KeyID: keyID, Scope: model.NewOwnerScope(uuid.Nil, callerID)})
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrKeyNotFound)
}

func TestUpdateKey_RepoUpdateError(t *testing.T) {
	repo := &mockKeyRepository{}
	keyID := uuid.New()
	ownerID := uuid.New()
	scope := model.NewOwnerScope(uuid.Nil, ownerID)
	repo.On("Read", mock.Anything, keyID, scope).Return(
		&model.Key{ID: keyID, UserID: ownerID, Enabled: true}, nil,
	)
	repo.On("Update", mock.Anything, mock.AnythingOfType("*model.Key"), scope).
		Return(errors.New("db error"))

	svc := &keyService{keyRepo: repo, logger: testLogger()}
	err := svc.UpdateKey(context.Background(), UpdateKeyRequest{KeyID: keyID, Scope: scope})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to update key")
}

func TestUpdateKey_WithCacheInvalidation(t *testing.T) {
	repo := &mockKeyRepository{}
	keyID := uuid.New()
	ownerID := uuid.New()
	scope := model.NewOwnerScope(uuid.Nil, ownerID)
	repo.On("Read", mock.Anything, keyID, scope).Return(
		&model.Key{ID: keyID, UserID: ownerID, Enabled: true}, nil,
	)
	repo.On("Update", mock.Anything, mock.AnythingOfType("*model.Key"), scope).Return(nil)

	// Use a real NopCache so Invalidate is exercised.
	cache := &testKeyCache{}
	svc := &keyService{keyRepo: repo, logger: testLogger(), keyCache: cache}
	err := svc.UpdateKey(context.Background(), UpdateKeyRequest{KeyID: keyID, Scope: scope})
	require.NoError(t, err)
	assert.Equal(t, keyID, cache.lastInvalidated)
}

// ─── DeleteKey ───────────────────────────────────────────────────────────────

func TestDeleteKey_SoftDeleteFails(t *testing.T) {
	repo := &mockKeyRepository{}
	keyID := uuid.New()
	ownerID := uuid.New()
	repo.On("Read", mock.Anything, keyID, model.NewOwnerScope(uuid.Nil, ownerID)).Return(
		&model.Key{ID: keyID, UserID: ownerID, Enabled: true}, nil,
	)
	repo.On("SoftDelete", mock.Anything, keyID).Return(errors.New("db error"))

	svc := &keyService{keyRepo: repo, logger: testLogger()}
	_, err := svc.DeleteKey(context.Background(), keyID, model.NewOwnerScope(uuid.Nil, ownerID))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to delete key")
}

func TestDeleteKey_ReadDeletedFails_ReturnsSnapshot(t *testing.T) {
	repo := &mockKeyRepository{}
	keyID := uuid.New()
	ownerID := uuid.New()
	repo.On("Read", mock.Anything, keyID, model.NewOwnerScope(uuid.Nil, ownerID)).Return(
		&model.Key{ID: keyID, UserID: ownerID, Enabled: true}, nil,
	)
	repo.On("SoftDelete", mock.Anything, keyID).Return(nil)
	repo.On("ReadDeletedScoped", mock.Anything, keyID, model.NewOwnerScope(uuid.Nil, ownerID)).Return(nil, errors.New("metadata unavailable"))

	svc := &keyService{keyRepo: repo, logger: testLogger()}
	got, err := svc.DeleteKey(context.Background(), keyID, model.NewOwnerScope(uuid.Nil, ownerID))
	require.NoError(t, err)
	assert.Equal(t, keyID, got.ID)
}

func TestDeleteKey_CacheInvalidated(t *testing.T) {
	repo := &mockKeyRepository{}
	keyID := uuid.New()
	ownerID := uuid.New()
	now := time.Now()
	repo.On("Read", mock.Anything, keyID, model.NewOwnerScope(uuid.Nil, ownerID)).Return(
		&model.Key{ID: keyID, UserID: ownerID, Enabled: true}, nil,
	)
	repo.On("SoftDelete", mock.Anything, keyID).Return(nil)
	repo.On("ReadDeletedScoped", mock.Anything, keyID, model.NewOwnerScope(uuid.Nil, ownerID)).Return(
		&model.Key{ID: keyID, DeletedAt: &now}, nil,
	)

	cache := &testKeyCache{}
	svc := &keyService{keyRepo: repo, logger: testLogger(), keyCache: cache}
	_, err := svc.DeleteKey(context.Background(), keyID, model.NewOwnerScope(uuid.Nil, ownerID))
	require.NoError(t, err)
	assert.Equal(t, keyID, cache.lastInvalidated)
}

// ─── RotateKey ───────────────────────────────────────────────────────────────

func TestRotateKey_KeyNotFound(t *testing.T) {
	repo := &mockKeyRepository{}
	keyID := uuid.New()
	userID := uuid.New()
	repo.On("Read", mock.Anything, keyID, model.NewOwnerScope(uuid.Nil, userID)).Return(nil, errors.New("not found"))

	svc := &keyService{keyRepo: repo, logger: testLogger()}
	_, err := svc.RotateKey(context.Background(), keyID, model.NewOwnerScope(uuid.Nil, userID))
	require.Error(t, err)
}

// TestRotateKey_ScopedReadIsTheCheck pins that rotation is authorized by the
// scope alone: a caller who is not the owner never gets a row back from the
// owner-scoped read, so there is no in-Go ownership comparison left to bypass.
func TestRotateKey_ScopedReadIsTheCheck(t *testing.T) {
	repo := &mockKeyRepository{}
	keyID := uuid.New()
	callerID := uuid.New()
	callerScope := model.NewOwnerScope(uuid.Nil, callerID)
	// The real repository's owner predicate excludes another user's key, so
	// the read is what fails — the rotation never reaches key generation.
	repo.On("Read", mock.Anything, keyID, callerScope).Return(nil, errors.New("key not found or access denied"))

	svc := &keyService{keyRepo: repo, logger: testLogger()}
	_, err := svc.RotateKey(context.Background(), keyID, callerScope)
	require.Error(t, err)
	repo.AssertNotCalled(t, "Update", mock.Anything, mock.Anything, mock.Anything)
}

// TestRotateKey_WrongVaultIsDenied pins the B6 conjunction: an owner scope
// carrying an advisory vault id must not rotate a key that lives in another
// vault. Before the scope migration rotate ignored the vault entirely, so a
// vault-scoped rotate route acted on keys outside that vault.
func TestRotateKey_WrongVaultIsDenied(t *testing.T) {
	repo := &mockKeyRepository{}
	keyID := uuid.New()
	ownerID := uuid.New()
	requestedVault := uuid.New()
	scope := model.NewOwnerScope(requestedVault, ownerID)
	repo.On("Read", mock.Anything, keyID, scope).Return(
		&model.Key{ID: keyID, UserID: ownerID, VaultID: uuid.New(), Type: model.KeyTypeRSA, Bits: 2048}, nil,
	)

	svc := &keyService{keyRepo: repo, logger: testLogger()}
	_, err := svc.RotateKey(context.Background(), keyID, scope)
	require.ErrorIs(t, err, ErrKeyNotFound)
	assert.Contains(t, err.Error(), "does not belong to the requested vault")
	repo.AssertNotCalled(t, "Update", mock.Anything, mock.Anything, mock.Anything)
}

func TestRotateKey_UnsupportedKeyType(t *testing.T) {
	repo := &mockKeyRepository{}
	keyID := uuid.New()
	ownerID := uuid.New()
	repo.On("Read", mock.Anything, keyID, model.NewOwnerScope(uuid.Nil, ownerID)).Return(
		&model.Key{ID: keyID, UserID: ownerID, Type: "UNKNOWN"}, nil,
	)

	provider := &mockKeyProviderForService{}
	svc := &keyService{keyRepo: repo, logger: testLogger(), keyProvider: provider}
	_, err := svc.RotateKey(context.Background(), keyID, model.NewOwnerScope(uuid.Nil, ownerID))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported key type")
}

func TestRotateKey_GenerationError(t *testing.T) {
	repo := &mockKeyRepository{}
	keyID := uuid.New()
	ownerID := uuid.New()
	repo.On("Read", mock.Anything, keyID, model.NewOwnerScope(uuid.Nil, ownerID)).Return(
		&model.Key{ID: keyID, UserID: ownerID, Type: model.KeyTypeRSA, Bits: 2048}, nil,
	)

	provider := &mockKeyProviderForService{}
	provider.On("GenerateRSAKey", 2048).Return("", errors.New("HSM offline"))

	svc := &keyService{keyRepo: repo, logger: testLogger(), keyProvider: provider}
	_, err := svc.RotateKey(context.Background(), keyID, model.NewOwnerScope(uuid.Nil, ownerID))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "key generation failed")
}

func TestRotateKey_ListVersionsError(t *testing.T) {
	setupMasterKey(t)

	repo := &mockKeyRepository{}
	keyID := uuid.New()
	ownerID := uuid.New()
	repo.On("Read", mock.Anything, keyID, model.NewOwnerScope(uuid.Nil, ownerID)).Return(
		&model.Key{ID: keyID, UserID: ownerID, Type: model.KeyTypeRSA, Bits: 2048}, nil,
	)
	repo.On("ListVersions", mock.Anything, keyID).Return(nil, errors.New("db error"))

	softwareProvider := crypto.NewSoftwareKeyProvider()
	svc := &keyService{keyRepo: repo, logger: testLogger(), keyProvider: softwareProvider}
	_, err := svc.RotateKey(context.Background(), keyID, model.NewOwnerScope(uuid.Nil, ownerID))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "list versions")
}

func TestRotateKey_SuccessWithVersionArchive(t *testing.T) {
	setupMasterKey(t)

	repo := &mockKeyRepository{}
	keyID := uuid.New()
	ownerID := uuid.New()

	existingEncrypted, _ := common.EncryptSecret("-----BEGIN RSA PRIVATE KEY-----\noriginal\n-----END RSA PRIVATE KEY-----")

	repo.On("Read", mock.Anything, keyID, model.NewOwnerScope(uuid.Nil, ownerID)).Return(
		&model.Key{ID: keyID, UserID: ownerID, Type: model.KeyTypeRSA, Bits: 2048,
			Value: existingEncrypted, Name: "rsa-key"},
		nil,
	)
	// No existing versions — RotateKey must archive the original as v1 first.
	repo.On("ListVersions", mock.Anything, keyID).Return([]model.KeyVersion{}, nil)
	repo.On("CreateVersion", mock.Anything, keyID, 1, existingEncrypted).Return(nil)
	repo.On("CreateVersion", mock.Anything, keyID, 2, mock.AnythingOfType("string")).Return(nil)
	repo.On("Update", mock.Anything, mock.AnythingOfType("*model.Key"), model.NewOwnerScope(uuid.Nil, ownerID)).Return(nil)

	softwareProvider := crypto.NewSoftwareKeyProvider()
	svc := &keyService{keyRepo: repo, logger: testLogger(), keyProvider: softwareProvider}
	result, err := svc.RotateKey(context.Background(), keyID, model.NewOwnerScope(uuid.Nil, ownerID))
	require.NoError(t, err)
	assert.Equal(t, keyID, result.KeyID)
	repo.AssertExpectations(t)
}

func TestRotateKey_ECDSAKey(t *testing.T) {
	setupMasterKey(t)

	repo := &mockKeyRepository{}
	keyID := uuid.New()
	ownerID := uuid.New()

	existingEncrypted, _ := common.EncryptSecret("ec-key-material")

	repo.On("Read", mock.Anything, keyID, model.NewOwnerScope(uuid.Nil, ownerID)).Return(
		&model.Key{ID: keyID, UserID: ownerID, Type: model.KeyTypeECDSA, Curve: "P-256",
			Value: existingEncrypted, Name: "ec-key"},
		nil,
	)
	repo.On("ListVersions", mock.Anything, keyID).Return([]model.KeyVersion{}, nil)
	repo.On("CreateVersion", mock.Anything, keyID, mock.AnythingOfType("int"), mock.AnythingOfType("string")).Return(nil)
	repo.On("Update", mock.Anything, mock.AnythingOfType("*model.Key"), model.NewOwnerScope(uuid.Nil, ownerID)).Return(nil)

	softwareProvider := crypto.NewSoftwareKeyProvider()
	svc := &keyService{keyRepo: repo, logger: testLogger(), keyProvider: softwareProvider}
	result, err := svc.RotateKey(context.Background(), keyID, model.NewOwnerScope(uuid.Nil, ownerID))
	require.NoError(t, err)
	assert.Equal(t, keyID, result.KeyID)
}

func TestRotateKey_ES256KKey(t *testing.T) {
	setupMasterKey(t)

	repo := &mockKeyRepository{}
	keyID := uuid.New()
	ownerID := uuid.New()

	existingEncrypted, _ := common.EncryptSecret("es256k-key-material")

	repo.On("Read", mock.Anything, keyID, model.NewOwnerScope(uuid.Nil, ownerID)).Return(
		&model.Key{ID: keyID, UserID: ownerID, Type: model.KeyTypeES256K,
			Value: existingEncrypted, Name: "es256k-key"},
		nil,
	)
	repo.On("ListVersions", mock.Anything, keyID).Return([]model.KeyVersion{}, nil)
	repo.On("CreateVersion", mock.Anything, keyID, mock.AnythingOfType("int"), mock.AnythingOfType("string")).Return(nil)
	repo.On("Update", mock.Anything, mock.AnythingOfType("*model.Key"), model.NewOwnerScope(uuid.Nil, ownerID)).Return(nil)

	softwareProvider := crypto.NewSoftwareKeyProvider()
	svc := &keyService{keyRepo: repo, logger: testLogger(), keyProvider: softwareProvider}
	result, err := svc.RotateKey(context.Background(), keyID, model.NewOwnerScope(uuid.Nil, ownerID))
	require.NoError(t, err)
	assert.Equal(t, keyID, result.KeyID)
}

// ─── RotateKey — expiry_days stamping ───────────────────────────────────────

// TestRotateKey_StampsExpiryFromPolicy verifies that an enabled policy with
// ExpiryDays > 0 stamps ExpiresAt on the key at rotation time.
func TestRotateKey_StampsExpiryFromPolicy(t *testing.T) {
	setupMasterKey(t)

	repo := &mockKeyRepository{}
	policyRepo := new(mockKeyPolicyRepo)
	keyID := uuid.New()
	ownerID := uuid.New()
	scope := model.NewOwnerScope(uuid.Nil, ownerID)

	existingEncrypted, _ := common.EncryptSecret("rsa-key-material")
	repo.On("Read", mock.Anything, keyID, scope).Return(
		&model.Key{ID: keyID, UserID: ownerID, Type: model.KeyTypeRSA, Bits: 2048, Value: existingEncrypted, Name: "rsa-key"},
		nil,
	)
	repo.On("ListVersions", mock.Anything, keyID).Return([]model.KeyVersion{}, nil)
	repo.On("CreateVersion", mock.Anything, keyID, 1, existingEncrypted).Return(nil)
	repo.On("CreateVersion", mock.Anything, keyID, 2, mock.AnythingOfType("string")).Return(nil)

	policyRepo.On("GetByKeyID", mock.Anything, keyID, scope).Return(
		&model.KeyRotationPolicy{KeyID: keyID, Enabled: true, ExpiryDays: 30}, nil,
	)

	before := time.Now().UTC()
	var captured *model.Key
	repo.On("Update", mock.Anything, mock.MatchedBy(func(k *model.Key) bool {
		captured = k
		return k.ExpiresAt != nil
	}), scope).Return(nil)

	softwareProvider := crypto.NewSoftwareKeyProvider()
	svc := &keyService{keyRepo: repo, policyRepo: policyRepo, logger: testLogger(), keyProvider: softwareProvider}
	_, err := svc.RotateKey(context.Background(), keyID, scope)
	require.NoError(t, err)
	repo.AssertExpectations(t)
	policyRepo.AssertExpectations(t)

	require.NotNil(t, captured)
	require.NotNil(t, captured.ExpiresAt)
	wantMin := before.AddDate(0, 0, 30)
	wantMax := time.Now().UTC().AddDate(0, 0, 30)
	assert.False(t, captured.ExpiresAt.Before(wantMin), "ExpiresAt too early")
	assert.False(t, captured.ExpiresAt.After(wantMax), "ExpiresAt too late")
}

// TestRotateKey_NoPolicyDoesNotStampExpiry verifies that a key with no
// rotation policy configured (the common case) rotates exactly as before —
// ExpiresAt is left untouched.
func TestRotateKey_NoPolicyDoesNotStampExpiry(t *testing.T) {
	setupMasterKey(t)

	repo := &mockKeyRepository{}
	policyRepo := new(mockKeyPolicyRepo)
	keyID := uuid.New()
	ownerID := uuid.New()
	scope := model.NewOwnerScope(uuid.Nil, ownerID)

	existingEncrypted, _ := common.EncryptSecret("rsa-key-material")
	repo.On("Read", mock.Anything, keyID, scope).Return(
		&model.Key{ID: keyID, UserID: ownerID, Type: model.KeyTypeRSA, Bits: 2048, Value: existingEncrypted, Name: "rsa-key"},
		nil,
	)
	repo.On("ListVersions", mock.Anything, keyID).Return([]model.KeyVersion{}, nil)
	repo.On("CreateVersion", mock.Anything, keyID, 1, existingEncrypted).Return(nil)
	repo.On("CreateVersion", mock.Anything, keyID, 2, mock.AnythingOfType("string")).Return(nil)

	policyRepo.On("GetByKeyID", mock.Anything, keyID, scope).Return(nil, sql.ErrNoRows)

	repo.On("Update", mock.Anything, mock.MatchedBy(func(k *model.Key) bool {
		return k.ExpiresAt == nil
	}), scope).Return(nil)

	softwareProvider := crypto.NewSoftwareKeyProvider()
	svc := &keyService{keyRepo: repo, policyRepo: policyRepo, logger: testLogger(), keyProvider: softwareProvider}
	_, err := svc.RotateKey(context.Background(), keyID, scope)
	require.NoError(t, err)
	repo.AssertExpectations(t)
	policyRepo.AssertExpectations(t)
}

// TestRotateKey_DisabledPolicyDoesNotStamp verifies that a disabled policy's
// ExpiryDays is not applied.
func TestRotateKey_DisabledPolicyDoesNotStamp(t *testing.T) {
	setupMasterKey(t)

	repo := &mockKeyRepository{}
	policyRepo := new(mockKeyPolicyRepo)
	keyID := uuid.New()
	ownerID := uuid.New()
	scope := model.NewOwnerScope(uuid.Nil, ownerID)

	existingEncrypted, _ := common.EncryptSecret("rsa-key-material")
	repo.On("Read", mock.Anything, keyID, scope).Return(
		&model.Key{ID: keyID, UserID: ownerID, Type: model.KeyTypeRSA, Bits: 2048, Value: existingEncrypted, Name: "rsa-key"},
		nil,
	)
	repo.On("ListVersions", mock.Anything, keyID).Return([]model.KeyVersion{}, nil)
	repo.On("CreateVersion", mock.Anything, keyID, 1, existingEncrypted).Return(nil)
	repo.On("CreateVersion", mock.Anything, keyID, 2, mock.AnythingOfType("string")).Return(nil)

	policyRepo.On("GetByKeyID", mock.Anything, keyID, scope).Return(
		&model.KeyRotationPolicy{KeyID: keyID, Enabled: false, ExpiryDays: 30}, nil,
	)

	repo.On("Update", mock.Anything, mock.MatchedBy(func(k *model.Key) bool {
		return k.ExpiresAt == nil
	}), scope).Return(nil)

	softwareProvider := crypto.NewSoftwareKeyProvider()
	svc := &keyService{keyRepo: repo, policyRepo: policyRepo, logger: testLogger(), keyProvider: softwareProvider}
	_, err := svc.RotateKey(context.Background(), keyID, scope)
	require.NoError(t, err)
	repo.AssertExpectations(t)
	policyRepo.AssertExpectations(t)
}

// TestRotateKey_ZeroExpiryDaysDoesNotStamp verifies that an enabled policy
// with ExpiryDays == 0 (no expiry lifetime action configured) does not stamp.
func TestRotateKey_ZeroExpiryDaysDoesNotStamp(t *testing.T) {
	setupMasterKey(t)

	repo := &mockKeyRepository{}
	policyRepo := new(mockKeyPolicyRepo)
	keyID := uuid.New()
	ownerID := uuid.New()
	scope := model.NewOwnerScope(uuid.Nil, ownerID)

	existingEncrypted, _ := common.EncryptSecret("rsa-key-material")
	repo.On("Read", mock.Anything, keyID, scope).Return(
		&model.Key{ID: keyID, UserID: ownerID, Type: model.KeyTypeRSA, Bits: 2048, Value: existingEncrypted, Name: "rsa-key"},
		nil,
	)
	repo.On("ListVersions", mock.Anything, keyID).Return([]model.KeyVersion{}, nil)
	repo.On("CreateVersion", mock.Anything, keyID, 1, existingEncrypted).Return(nil)
	repo.On("CreateVersion", mock.Anything, keyID, 2, mock.AnythingOfType("string")).Return(nil)

	policyRepo.On("GetByKeyID", mock.Anything, keyID, scope).Return(
		&model.KeyRotationPolicy{KeyID: keyID, Enabled: true, ExpiryDays: 0, RotateAfterDays: 90}, nil,
	)

	repo.On("Update", mock.Anything, mock.MatchedBy(func(k *model.Key) bool {
		return k.ExpiresAt == nil
	}), scope).Return(nil)

	softwareProvider := crypto.NewSoftwareKeyProvider()
	svc := &keyService{keyRepo: repo, policyRepo: policyRepo, logger: testLogger(), keyProvider: softwareProvider}
	_, err := svc.RotateKey(context.Background(), keyID, scope)
	require.NoError(t, err)
	repo.AssertExpectations(t)
	policyRepo.AssertExpectations(t)
}

// TestRotateKey_PolicyLookupErrorFailsRotation verifies that a genuine
// repository error during policy lookup (not "no policy configured") aborts
// the rotation rather than silently skipping the stamp.
func TestRotateKey_PolicyLookupErrorFailsRotation(t *testing.T) {
	setupMasterKey(t)

	repo := &mockKeyRepository{}
	policyRepo := new(mockKeyPolicyRepo)
	keyID := uuid.New()
	ownerID := uuid.New()
	scope := model.NewOwnerScope(uuid.Nil, ownerID)

	existingEncrypted, _ := common.EncryptSecret("rsa-key-material")
	repo.On("Read", mock.Anything, keyID, scope).Return(
		&model.Key{ID: keyID, UserID: ownerID, Type: model.KeyTypeRSA, Bits: 2048, Value: existingEncrypted, Name: "rsa-key"},
		nil,
	)
	repo.On("ListVersions", mock.Anything, keyID).Return([]model.KeyVersion{}, nil)
	repo.On("CreateVersion", mock.Anything, keyID, 1, existingEncrypted).Return(nil)
	repo.On("CreateVersion", mock.Anything, keyID, 2, mock.AnythingOfType("string")).Return(nil)

	policyRepo.On("GetByKeyID", mock.Anything, keyID, scope).Return(nil, errors.New("db connection lost"))

	softwareProvider := crypto.NewSoftwareKeyProvider()
	svc := &keyService{keyRepo: repo, policyRepo: policyRepo, logger: testLogger(), keyProvider: softwareProvider}
	_, err := svc.RotateKey(context.Background(), keyID, scope)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "rotation policy")
	repo.AssertNotCalled(t, "Update", mock.Anything, mock.Anything, mock.Anything)
	policyRepo.AssertExpectations(t)
}

// TestRotateKey_NilPolicyRepoDoesNotStamp verifies that a keyService
// constructed without a policyRepo (as most existing tests in this file do)
// rotates successfully without attempting a lookup — matching the existing
// optional-dependency convention already used for vaultRepo in PurgeKey.
func TestRotateKey_NilPolicyRepoDoesNotStamp(t *testing.T) {
	setupMasterKey(t)

	repo := &mockKeyRepository{}
	keyID := uuid.New()
	ownerID := uuid.New()
	scope := model.NewOwnerScope(uuid.Nil, ownerID)

	existingEncrypted, _ := common.EncryptSecret("rsa-key-material")
	repo.On("Read", mock.Anything, keyID, scope).Return(
		&model.Key{ID: keyID, UserID: ownerID, Type: model.KeyTypeRSA, Bits: 2048, Value: existingEncrypted, Name: "rsa-key"},
		nil,
	)
	repo.On("ListVersions", mock.Anything, keyID).Return([]model.KeyVersion{}, nil)
	repo.On("CreateVersion", mock.Anything, keyID, 1, existingEncrypted).Return(nil)
	repo.On("CreateVersion", mock.Anything, keyID, 2, mock.AnythingOfType("string")).Return(nil)
	repo.On("Update", mock.Anything, mock.MatchedBy(func(k *model.Key) bool {
		return k.ExpiresAt == nil
	}), scope).Return(nil)

	softwareProvider := crypto.NewSoftwareKeyProvider()
	svc := &keyService{keyRepo: repo, logger: testLogger(), keyProvider: softwareProvider}
	_, err := svc.RotateKey(context.Background(), keyID, scope)
	require.NoError(t, err)
	repo.AssertExpectations(t)
}

// ─── CryptoService error paths ───────────────────────────────────────────────

func TestCryptoService_Sign_ResolveKeyMaterialError(t *testing.T) {
	setupMasterKey(t)

	repo := &mockKeyRepoForExtendedCrypto{}
	keyID := uuid.New()
	userID := uuid.New()
	// Value is not a valid encrypted string or PKCS11 handle.
	repo.On("Read", mock.Anything, keyID, model.NewOwnerScope(uuid.Nil, userID)).Return(&model.Key{
		ID: keyID, UserID: userID, Type: model.KeyTypeRSA, Value: "bad-value", Enabled: true,
	}, nil)

	svc := NewCryptoService(CryptoServiceConfig{
		KeyRepository: repo,
		Logger:        testLogger(),
	})
	_, err := svc.Sign(context.Background(), SignRequest{
		KeyID: keyID, UserID: userID, Scope: model.NewOwnerScope(uuid.Nil, userID), Data: []byte("d"), Algorithm: crypto.AlgorithmRS256,
	})
	require.Error(t, err)
}

func TestCryptoService_Verify_ResolveKeyMaterialError(t *testing.T) {
	setupMasterKey(t)

	repo := &mockKeyRepoForExtendedCrypto{}
	keyID := uuid.New()
	userID := uuid.New()
	repo.On("Read", mock.Anything, keyID, model.NewOwnerScope(uuid.Nil, userID)).Return(&model.Key{
		ID: keyID, UserID: userID, Type: model.KeyTypeRSA, Value: "bad-value", Enabled: true,
	}, nil)

	svc := NewCryptoService(CryptoServiceConfig{
		KeyRepository: repo,
		Logger:        testLogger(),
	})
	_, err := svc.Verify(context.Background(), VerifyRequest{
		KeyID: keyID, UserID: userID, Scope: model.NewOwnerScope(uuid.Nil, userID), Data: []byte("d"), Signature: []byte("s"), Algorithm: crypto.AlgorithmRS256,
	})
	require.Error(t, err)
}

func TestCryptoService_Encrypt_ResolveKeyMaterialError(t *testing.T) {
	setupMasterKey(t)

	repo := &mockKeyRepoForExtendedCrypto{}
	keyID := uuid.New()
	userID := uuid.New()
	repo.On("Read", mock.Anything, keyID, model.NewOwnerScope(uuid.Nil, userID)).Return(&model.Key{
		ID: keyID, UserID: userID, Type: model.KeyTypeRSA, Value: "bad-value", Enabled: true,
	}, nil)

	svc := NewCryptoService(CryptoServiceConfig{
		KeyRepository: repo,
		Logger:        testLogger(),
	})
	_, err := svc.Encrypt(context.Background(), EncryptRequest{
		KeyID: keyID, UserID: userID, Scope: model.NewOwnerScope(uuid.Nil, userID), Data: []byte("d"), Algorithm: crypto.AlgorithmRSAOAEP,
	})
	require.Error(t, err)
}

func TestCryptoService_Decrypt_ResolveKeyMaterialError(t *testing.T) {
	setupMasterKey(t)

	repo := &mockKeyRepoForExtendedCrypto{}
	keyID := uuid.New()
	userID := uuid.New()
	repo.On("Read", mock.Anything, keyID, model.NewOwnerScope(uuid.Nil, userID)).Return(&model.Key{
		ID: keyID, UserID: userID, Type: model.KeyTypeRSA, Value: "bad-value", Enabled: true,
	}, nil)

	svc := NewCryptoService(CryptoServiceConfig{
		KeyRepository: repo,
		Logger:        testLogger(),
	})
	_, err := svc.Decrypt(context.Background(), DecryptRequest{
		KeyID: keyID, UserID: userID, Scope: model.NewOwnerScope(uuid.Nil, userID), Ciphertext: []byte("c"), Algorithm: crypto.AlgorithmRSAOAEP,
	})
	require.Error(t, err)
}

func TestCryptoService_WrapKey_InvalidAlgorithm(t *testing.T) {
	repo := &mockKeyRepoForExtendedCrypto{}
	svc := NewCryptoService(CryptoServiceConfig{KeyRepository: repo, Logger: testLogger()})
	_, err := svc.WrapKey(context.Background(), WrapKeyRequest{
		KeyID: uuid.New(), UserID: uuid.New(), Algorithm: "INVALID",
	})
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrUnsupportedAlgorithm)
}

func TestCryptoService_UnwrapKey_InvalidAlgorithm(t *testing.T) {
	repo := &mockKeyRepoForExtendedCrypto{}
	svc := NewCryptoService(CryptoServiceConfig{KeyRepository: repo, Logger: testLogger()})
	_, err := svc.UnwrapKey(context.Background(), UnwrapKeyRequest{
		KeyID: uuid.New(), UserID: uuid.New(), Algorithm: "INVALID",
	})
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrUnsupportedAlgorithm)
}

func TestCryptoService_WrapKey_KeyNotFound(t *testing.T) {
	repo := &mockKeyRepoForExtendedCrypto{}
	keyID := uuid.New()
	userID := uuid.New()
	repo.On("Read", mock.Anything, keyID, model.NewOwnerScope(uuid.Nil, userID)).Return(nil, errors.New("not found"))

	svc := NewCryptoService(CryptoServiceConfig{KeyRepository: repo, Logger: testLogger()})
	_, err := svc.WrapKey(context.Background(), WrapKeyRequest{
		KeyID: keyID, UserID: userID, Scope: model.NewOwnerScope(uuid.Nil, userID), Algorithm: "RSA-OAEP",
	})
	require.Error(t, err)
}

func TestCryptoService_UnwrapKey_KeyNotFound(t *testing.T) {
	repo := &mockKeyRepoForExtendedCrypto{}
	keyID := uuid.New()
	userID := uuid.New()
	repo.On("Read", mock.Anything, keyID, model.NewOwnerScope(uuid.Nil, userID)).Return(nil, errors.New("not found"))

	svc := NewCryptoService(CryptoServiceConfig{KeyRepository: repo, Logger: testLogger()})
	_, err := svc.UnwrapKey(context.Background(), UnwrapKeyRequest{
		KeyID: keyID, UserID: userID, Scope: model.NewOwnerScope(uuid.Nil, userID), Algorithm: "RSA-OAEP",
	})
	require.Error(t, err)
}

func TestCryptoService_WrapKey_OperationFails(t *testing.T) {
	setupMasterKey(t)

	repo := &mockKeyRepoForExtendedCrypto{}
	keyID := uuid.New()
	userID := uuid.New()
	repo.On("Read", mock.Anything, keyID, model.NewOwnerScope(uuid.Nil, userID)).Return(&model.Key{
		ID: keyID, UserID: userID, Type: model.KeyTypeRSA, Value: "bad-value", Enabled: true,
	}, nil)

	svc := NewCryptoService(CryptoServiceConfig{KeyRepository: repo, Logger: testLogger()})
	_, err := svc.WrapKey(context.Background(), WrapKeyRequest{
		KeyID: keyID, UserID: userID, Scope: model.NewOwnerScope(uuid.Nil, userID), Algorithm: "RSA-OAEP", PlaintextKey: []byte("key"),
	})
	require.Error(t, err)
}

func TestCryptoService_UnwrapKey_OperationFails(t *testing.T) {
	setupMasterKey(t)

	repo := &mockKeyRepoForExtendedCrypto{}
	keyID := uuid.New()
	userID := uuid.New()
	repo.On("Read", mock.Anything, keyID, model.NewOwnerScope(uuid.Nil, userID)).Return(&model.Key{
		ID: keyID, UserID: userID, Type: model.KeyTypeRSA, Value: "bad-value", Enabled: true,
	}, nil)

	svc := NewCryptoService(CryptoServiceConfig{KeyRepository: repo, Logger: testLogger()})
	_, err := svc.UnwrapKey(context.Background(), UnwrapKeyRequest{
		KeyID: keyID, UserID: userID, Scope: model.NewOwnerScope(uuid.Nil, userID), Algorithm: "RSA-OAEP", WrappedKey: []byte("wrapped"),
	})
	require.Error(t, err)
}

// ─── testKeyCache – minimal keycache.Cache for invalidation tests ────────────

type testKeyCache struct {
	lastInvalidated uuid.UUID
}

func (c *testKeyCache) Get(_ uuid.UUID, _ int) (*keycache.Entry, bool) { return nil, false }
func (c *testKeyCache) Set(_ uuid.UUID, _ int, _ *keycache.Entry)      {}
func (c *testKeyCache) Invalidate(id uuid.UUID)                        { c.lastInvalidated = id }
func (c *testKeyCache) InvalidateAll()                                 {}
func (c *testKeyCache) Stats() keycache.CacheStats                     { return keycache.CacheStats{} }
func (c *testKeyCache) Stop()                                          {}
