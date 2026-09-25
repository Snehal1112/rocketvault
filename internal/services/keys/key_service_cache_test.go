package keys

import (
	"context"
	gocrypto "crypto"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	"rocketvault/internal/crypto"
	"rocketvault/internal/keycache"
	"rocketvault/internal/logging"
	"rocketvault/model"
)

// mockCacheForKeyService is a testify mock of keycache.Cache used to assert
// Invalidate is called after successful key mutations.
type mockCacheForKeyService struct {
	mock.Mock
}

func (m *mockCacheForKeyService) Get(keyID uuid.UUID, version int) (*keycache.Entry, bool) {
	args := m.Called(keyID, version)
	if args.Get(0) == nil {
		return nil, args.Bool(1)
	}
	return args.Get(0).(*keycache.Entry), args.Bool(1)
}

func (m *mockCacheForKeyService) Set(keyID uuid.UUID, version int, entry *keycache.Entry) {
	m.Called(keyID, version, entry)
}

func (m *mockCacheForKeyService) Invalidate(keyID uuid.UUID) {
	m.Called(keyID)
}

func (m *mockCacheForKeyService) InvalidateAll() {
	m.Called()
}

func (m *mockCacheForKeyService) Stats() keycache.CacheStats {
	args := m.Called()
	return args.Get(0).(keycache.CacheStats)
}

func (m *mockCacheForKeyService) Stop() {
	m.Called()
}

// TestKeyService_DeleteKey_InvalidatesCache verifies that a successful DeleteKey
// call evicts the key from the cache exactly once.
func TestKeyService_DeleteKey_InvalidatesCache(t *testing.T) {
	userID := uuid.New()
	keyID := uuid.New()

	now := time.Now()
	existingKey := &model.Key{
		ID:        keyID,
		UserID:    userID,
		Name:      "test-key",
		Type:      model.KeyTypeRSA,
		CreatedAt: now,
		Enabled:   true,
	}
	deletedKey := &model.Key{
		ID:        keyID,
		UserID:    userID,
		Name:      "test-key",
		Type:      model.KeyTypeRSA,
		CreatedAt: now,
		Enabled:   true,
		DeletedAt: &now,
	}

	repo := &mockKeyRepository{}
	repo.On("Read", mock.Anything, keyID, model.NewOwnerScope(uuid.Nil, userID)).Return(existingKey, nil)
	repo.On("SoftDelete", mock.Anything, keyID).Return(nil)
	repo.On("ReadDeletedScoped", mock.Anything, keyID, model.NewOwnerScope(uuid.Nil, userID)).Return(deletedKey, nil)

	cache := &mockCacheForKeyService{}
	cache.On("Invalidate", keyID).Return()

	logger := &logging.Logger{Logger: logrus.New()}
	svc := NewKeyService(KeyServiceConfig{
		KeyRepository: repo,
		KeyCache:      cache,
		Logger:        logger,
	})

	result, err := svc.DeleteKey(context.Background(), keyID, model.NewOwnerScope(uuid.Nil, userID))
	assert.NoError(t, err)
	assert.NotNil(t, result)

	// Invalidate must be called exactly once with the correct key ID.
	cache.AssertCalled(t, "Invalidate", keyID)
	cache.AssertNumberOfCalls(t, "Invalidate", 1)
	cache.AssertExpectations(t)
	repo.AssertExpectations(t)
}

// TestKeyService_UpdateKey_InvalidatesCache verifies that a successful UpdateKey
// call evicts the key from the cache exactly once.
func TestKeyService_UpdateKey_InvalidatesCache(t *testing.T) {
	userID := uuid.New()
	keyID := uuid.New()

	existing := &model.Key{
		ID:      keyID,
		UserID:  userID,
		Name:    "my-key",
		Type:    model.KeyTypeRSA,
		Enabled: true,
	}

	repo := &mockKeyRepository{}
	repo.On("Read", mock.Anything, keyID, model.NewOwnerScope(uuid.Nil, userID)).Return(existing, nil)
	repo.On("Update", mock.Anything, mock.MatchedBy(func(k *model.Key) bool {
		return k.ID == keyID && k.Revoked
	}), model.NewOwnerScope(uuid.Nil, userID)).Return(nil)

	cache := &mockCacheForKeyService{}
	cache.On("Invalidate", keyID).Return()

	logger := &logging.Logger{Logger: logrus.New()}
	svc := NewKeyService(KeyServiceConfig{
		KeyRepository: repo,
		KeyCache:      cache,
		Logger:        logger,
	})

	err := svc.UpdateKey(context.Background(), UpdateKeyRequest{
		KeyID:   keyID,
		Scope:   model.NewOwnerScope(uuid.Nil, userID),
		Revoked: boolPtr(true),
	})
	assert.NoError(t, err)

	cache.AssertCalled(t, "Invalidate", keyID)
	cache.AssertNumberOfCalls(t, "Invalidate", 1)
	cache.AssertExpectations(t)
	repo.AssertExpectations(t)
}

// TestKeyService_RotateKey_InvalidatesCache verifies that a successful RotateKey
// call evicts the key from the cache exactly once.
func TestKeyService_RotateKey_InvalidatesCache(t *testing.T) {
	userID := uuid.New()
	keyID := uuid.New()
	rotateScope := model.NewOwnerScope(uuid.Nil, userID)

	// Use a real encrypted PEM value so the encrypt path does not fail.
	// RotateKey calls keyProvider.GenerateRSAKey; we use a mockKeyProvider that
	// returns a PKCS#11 UUID handle so no actual RSA generation is needed.
	hsmHandle := "a1b2c3d4-e5f6-7890-abcd-ef1234567890" // valid UUID format

	existing := &model.Key{
		ID:      keyID,
		UserID:  userID,
		Name:    "rotate-key",
		Type:    model.KeyTypeRSA,
		Bits:    2048,
		Enabled: true,
		Value:   "pkcs11:old-handle-uuid-1234",
	}

	repo := &mockKeyRepository{}
	repo.On("Read", mock.Anything, keyID, rotateScope).Return(existing, nil)
	repo.On("ListVersions", mock.Anything, keyID).Return([]model.KeyVersion{}, nil)
	// Archive original as version 1 (first rotation).
	repo.On("CreateVersion", mock.Anything, keyID, 1, existing.Value).Return(nil)
	// Archive new material as version 2.
	repo.On("CreateVersion", mock.Anything, keyID, 2, "pkcs11:"+hsmHandle).Return(nil)
	repo.On("Update", mock.Anything, mock.MatchedBy(func(k *model.Key) bool {
		return k.ID == keyID
	}), rotateScope).Return(nil)

	// Mock provider returns a PKCS#11 UUID handle so no encryption is needed.
	provider := &mockKeyProviderForRotate{handle: hsmHandle}

	cache := &mockCacheForKeyService{}
	cache.On("Invalidate", keyID).Return()

	logger := &logging.Logger{Logger: logrus.New()}
	svc := NewKeyService(KeyServiceConfig{
		KeyRepository: repo,
		KeyProvider:   provider,
		KeyCache:      cache,
		Logger:        logger,
	})

	result, err := svc.RotateKey(context.Background(), keyID, rotateScope)
	assert.NoError(t, err)
	assert.NotNil(t, result)

	cache.AssertCalled(t, "Invalidate", keyID)
	cache.AssertNumberOfCalls(t, "Invalidate", 1)
	cache.AssertExpectations(t)
	repo.AssertExpectations(t)
}

// mockKeyProviderForRotate is a minimal KeyProvider that returns a fixed PKCS#11
// UUID handle from GenerateRSAKey so RotateKey tests avoid real RSA generation.
type mockKeyProviderForRotate struct {
	handle string
}

func (m *mockKeyProviderForRotate) GenerateRSAKey(_ context.Context, _ int) (string, error) {
	return m.handle, nil
}

func (m *mockKeyProviderForRotate) GenerateECDSAKey(_ context.Context, _ string) (string, error) {
	return m.handle, nil
}

func (m *mockKeyProviderForRotate) GenerateAESKey(_ context.Context, _ int) (string, error) {
	return m.handle, nil
}

func (m *mockKeyProviderForRotate) Sign(_ context.Context, _, _ string, _ []byte, _ crypto.SignatureAlgorithm) ([]byte, error) {
	return nil, nil
}

func (m *mockKeyProviderForRotate) Verify(_ context.Context, _, _ string, _, _ []byte, _ crypto.SignatureAlgorithm) (bool, error) {
	return false, nil
}

func (m *mockKeyProviderForRotate) Encrypt(_ context.Context, _ string, _ []byte, _ crypto.EncryptionAlgorithm) ([]byte, []byte, error) {
	return nil, nil, nil
}

func (m *mockKeyProviderForRotate) Decrypt(_ context.Context, _ string, _ []byte, _ []byte, _ crypto.EncryptionAlgorithm) ([]byte, error) {
	return nil, nil
}

func (m *mockKeyProviderForRotate) Close() error { return nil }

func (m *mockKeyProviderForRotate) ImportKey(_ context.Context, _ string, _ gocrypto.PrivateKey) (string, error) {
	return m.handle, nil
}
