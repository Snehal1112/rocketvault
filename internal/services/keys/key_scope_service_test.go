package keys

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"rocketvault/internal/logging"
	"rocketvault/internal/repositories"
	"rocketvault/model"
)

// newKeyScopeFixture builds a keyService over a mock repository.
func newKeyScopeFixture(t *testing.T) (*mockKeyRepository, *keyService) {
	t.Helper()
	repo := new(mockKeyRepository)
	l := logrus.New()
	l.SetLevel(logrus.PanicLevel)
	return repo, &keyService{
		keyRepo:  repo,
		keyCache: nil,
		logger:   &logging.Logger{Logger: l},
	}
}

func TestGetKeyPassesTheScopeToTheRepository(t *testing.T) {
	repo, svc := newKeyScopeFixture(t)
	ctx := context.Background()

	keyID, vaultID := uuid.New(), uuid.New()
	scope := model.NewVaultScope(vaultID, uuid.New())
	repo.On("Read", ctx, keyID, scope).
		Return(&model.Key{ID: keyID, VaultID: vaultID, Enabled: true}, nil).Once()

	got, err := svc.GetKey(ctx, keyID, scope)
	require.NoError(t, err)
	assert.Equal(t, keyID, got.ID)
	repo.AssertExpectations(t)
}

func TestGetKeyEnforcesLifecycle(t *testing.T) {
	repo, svc := newKeyScopeFixture(t)
	ctx := context.Background()

	keyID := uuid.New()
	scope := model.NewVaultScope(uuid.New(), uuid.New())
	repo.On("Read", ctx, keyID, scope).
		Return(&model.Key{ID: keyID, Enabled: false}, nil).Once()

	_, err := svc.GetKey(ctx, keyID, scope)
	assert.ErrorIs(t, err, ErrKeyLifecycleDenied)
}

func TestListKeysForwardsTheFilter(t *testing.T) {
	repo, svc := newKeyScopeFixture(t)
	ctx := context.Background()

	scope := model.NewVaultScope(uuid.New(), uuid.New())
	filter := repositories.KeyFilter{Type: model.KeyTypeRSA, Tags: []string{"prod"}}
	repo.On("List", ctx, scope, filter).Return([]model.Key{{ID: uuid.New()}}, nil).Once()

	got, err := svc.ListKeys(ctx, scope, filter)
	require.NoError(t, err)
	assert.Len(t, got, 1)
	repo.AssertExpectations(t)
}

func TestUpdateKeyUsesTheSameScopeForReadAndWrite(t *testing.T) {
	repo, svc := newKeyScopeFixture(t)
	ctx := context.Background()

	keyID, vaultID := uuid.New(), uuid.New()
	scope := model.NewVaultScope(vaultID, uuid.New())
	name := "renamed"

	repo.On("Read", ctx, keyID, scope).
		Return(&model.Key{ID: keyID, VaultID: vaultID, Name: "original", Enabled: true}, nil).Once()
	repo.On("Update", ctx, mock.MatchedBy(func(k *model.Key) bool {
		return k.Name == "renamed"
	}), scope).Return(nil).Once()

	require.NoError(t, svc.UpdateKey(ctx, UpdateKeyRequest{KeyID: keyID, Scope: scope, Name: &name}))
	repo.AssertExpectations(t)
}

func TestDeleteKeyKeepsTheB6VaultConjunction(t *testing.T) {
	repo, svc := newKeyScopeFixture(t)
	ctx := context.Background()

	keyID := uuid.New()
	ownerID := uuid.New()
	requestedVault, actualVault := uuid.New(), uuid.New()
	scope := model.NewOwnerScope(requestedVault, ownerID)

	// The owner predicate matches, but the key lives in another vault.
	repo.On("Read", ctx, keyID, scope).
		Return(&model.Key{ID: keyID, UserID: ownerID, VaultID: actualVault, Enabled: true}, nil).Once()

	_, err := svc.DeleteKey(ctx, keyID, scope)
	assert.ErrorIs(t, err, ErrKeyNotFound)
	repo.AssertNotCalled(t, "SoftDelete", mock.Anything, mock.Anything)
}

func TestDeleteKeySoftDeletesInScope(t *testing.T) {
	repo, svc := newKeyScopeFixture(t)
	ctx := context.Background()

	keyID, vaultID := uuid.New(), uuid.New()
	scope := model.NewVaultScope(vaultID, uuid.New())

	repo.On("Read", ctx, keyID, scope).
		Return(&model.Key{ID: keyID, VaultID: vaultID, Enabled: true}, nil).Once()
	repo.On("SoftDelete", ctx, keyID).Return(nil).Once()
	repo.On("ReadDeletedScoped", ctx, keyID, scope).Return(&model.Key{ID: keyID}, nil).Once()

	deleted, err := svc.DeleteKey(ctx, keyID, scope)
	require.NoError(t, err)
	assert.Equal(t, keyID, deleted.ID)
	repo.AssertExpectations(t)
}
