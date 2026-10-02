package secrets

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"rocketvault/model"
)

func lifecycleParents(secretID uuid.UUID) map[string]*model.Secret {
	past := time.Now().Add(-time.Hour)
	return map[string]*model.Secret{
		"disabled": {ID: secretID, Enabled: false},
		"expired":  {ID: secretID, Enabled: true, ExpiresAt: &past},
	}
}

func TestVersionReads_DeniedForInaccessibleParent(t *testing.T) {
	for name, parent := range lifecycleParents(uuid.New()) {
		t.Run(name, func(t *testing.T) {
			secretRepo, versionRepo, svc := newVersioningScopeFixture(t)
			ctx := context.Background()
			scope := model.NewVaultScope(uuid.New(), uuid.New())
			secretRepo.On("Read", ctx, parent.ID, scope).Return(parent, nil)

			_, err := svc.GetVersion(ctx, parent.ID, 1, scope)
			require.ErrorIs(t, err, ErrSecretLifecycleDenied)
			_, err = svc.GetLatestVersion(ctx, parent.ID, scope)
			require.ErrorIs(t, err, ErrSecretLifecycleDenied)
			_, err = svc.GetVersions(ctx, parent.ID, scope)
			require.ErrorIs(t, err, ErrSecretLifecycleDenied)

			versionRepo.AssertNotCalled(t, "GetVersion", mock.Anything, mock.Anything, mock.Anything)
			versionRepo.AssertNotCalled(t, "GetLatestVersion", mock.Anything, mock.Anything)
			versionRepo.AssertNotCalled(t, "GetVersions", mock.Anything, mock.Anything)
		})
	}
}

// Metadata carries no plaintext, so a disabled parent may still be enumerated.
func TestGetVersionsMetadata_AllowedForDisabledParent(t *testing.T) {
	secretRepo, versionRepo, svc := newVersioningScopeFixture(t)
	ctx := context.Background()
	secretID := uuid.New()
	scope := model.NewVaultScope(uuid.New(), uuid.New())
	secretRepo.On("Read", ctx, secretID, scope).Return(&model.Secret{ID: secretID, Enabled: false}, nil).Once()
	versionRepo.On("GetVersions", ctx, secretID).Return([]model.SecretVersion{{SecretID: secretID, Version: 1}}, nil).Once()

	got, err := svc.GetVersionsMetadata(ctx, secretID, scope)
	require.NoError(t, err)
	assert.Len(t, got, 1)
}
