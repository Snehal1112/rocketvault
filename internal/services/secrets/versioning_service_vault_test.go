package secrets_test

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"rocketvault/internal/services/secrets"
	"rocketvault/internal/testutils"
	"rocketvault/model"
)

func TestGetVersions_VaultScope_HappyPath(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	secretID := uuid.New()
	vaultID := uuid.New()

	userRepo := &testutils.MockUserRepository{}
	secretRepo := &testutils.MockSecretRepository{}
	versionRepo := &testutils.MockSecretVersionRepository{}
	crypto := &testutils.MockCryptographyService{}

	scope := model.NewVaultScope(vaultID, uuid.Nil)
	secretRepo.On("Read", ctx, secretID, scope).Return(
		&model.Secret{ID: secretID, VaultID: vaultID, Enabled: true}, nil,
	)
	versionRepo.On("GetVersions", ctx, secretID).Return(
		[]model.SecretVersion{{ID: uuid.New(), SecretID: secretID, Value: "enc-v1", Version: 1}}, nil,
	)
	crypto.On("DecryptSecret", "enc-v1").Return("plain-v1", nil)

	svc := secrets.NewVersioningService(versionRepo, secretRepo, userRepo, crypto, testutils.NewTestLogger(t), nil)
	versions, err := svc.GetVersions(ctx, secretID, scope)

	require.NoError(t, err)
	require.Len(t, versions, 1)
	require.Equal(t, "plain-v1", versions[0].Value)
}

func TestGetVersions_VaultScope_WrongVault(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	secretID := uuid.New()
	vaultID := uuid.New()

	userRepo := &testutils.MockUserRepository{}
	secretRepo := &testutils.MockSecretRepository{}
	versionRepo := &testutils.MockSecretVersionRepository{}
	crypto := &testutils.MockCryptographyService{}

	scope := model.NewVaultScope(vaultID, uuid.Nil)
	secretRepo.On("Read", ctx, secretID, scope).Return(nil, errors.New("secret not found or access denied"))

	svc := secrets.NewVersioningService(versionRepo, secretRepo, userRepo, crypto, testutils.NewTestLogger(t), nil)
	_, err := svc.GetVersions(ctx, secretID, scope)

	require.Error(t, err)
}
