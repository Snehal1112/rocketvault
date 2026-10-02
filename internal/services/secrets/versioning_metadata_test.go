package secrets

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"rocketvault/model"
)

// exposingCrypto fails loudly if anything asks it to decrypt. The metadata
// path's guarantee is that plaintext never enters memory at all -- not that a
// handler politely declines to serialize it. A crypto double that returns a
// value would let the old "decrypt everything, then drop the field" shape pass
// this test, which is exactly the shape B30 came from.
type exposingCrypto struct{ decryptCalls int }

func (c *exposingCrypto) EncryptSecret(v string) (string, error) { return "ENC(" + v + ")", nil }
func (c *exposingCrypto) DecryptSecret(string) (string, error) {
	c.decryptCalls++
	return "", errors.New("DecryptSecret must not be called on the metadata path")
}

func newMetadataFixture(t *testing.T) (*MockSecretRepository, *MockSecretVersionRepository, *exposingCrypto, *versioningService) {
	t.Helper()
	secretRepo := new(MockSecretRepository)
	versionRepo := new(MockSecretVersionRepository)
	crypto := &exposingCrypto{}
	return secretRepo, versionRepo, crypto, &versioningService{
		versionRepo: versionRepo,
		secretRepo:  secretRepo,
		userRepo:    new(MockUserRepository),
		cryptoSvc:   crypto,
		log:         newTestLogger(t),
	}
}

// TestGetVersionsMetadata_NeverDecrypts is the structural half of the B30 fix.
// A Key Vault Reader holds ActionSecretsReadMetadata and may list versions;
// the leak was that listing decrypted and returned every historical value. The
// fix is a path that cannot leak because it never obtains plaintext.
func TestGetVersionsMetadata_NeverDecrypts(t *testing.T) {
	secretRepo, versionRepo, crypto, svc := newMetadataFixture(t)
	ctx := context.Background()

	secretID := uuid.New()
	scope := model.NewVaultScope(uuid.New(), uuid.New())
	secretRepo.On("Read", ctx, secretID, scope).Return(&model.Secret{ID: secretID}, nil).Once()
	versionRepo.On("GetVersions", ctx, secretID).Return([]model.SecretVersion{
		{ID: uuid.New(), SecretID: secretID, Name: "db-password", Version: 1, Value: "ENC(hunter2)", CreatedAt: time.Now().UTC()},
		{ID: uuid.New(), SecretID: secretID, Name: "db-password", Version: 2, Value: "ENC(hunter3)", CreatedAt: time.Now().UTC()},
	}, nil).Once()

	versions, err := svc.GetVersionsMetadata(ctx, secretID, scope)
	require.NoError(t, err)
	require.Len(t, versions, 2)

	assert.Zero(t, crypto.decryptCalls,
		"the metadata path must never decrypt: plaintext must not enter memory at all")

	// The returned type has no Value field, so this is a compile-time
	// guarantee as much as a runtime one -- these assertions document the
	// shape a caller actually receives.
	assert.Equal(t, 1, versions[0].Version)
	assert.Equal(t, "db-password", versions[0].Name)
	assert.Equal(t, secretID, versions[0].SecretID)
}

// TestGetVersionsMetadata_DeniesOutOfScope keeps the scope check that
// GetVersions already performs -- the metadata path must not become a way to
// enumerate a secret the caller cannot read.
func TestGetVersionsMetadata_DeniesOutOfScope(t *testing.T) {
	secretRepo, versionRepo, _, svc := newMetadataFixture(t)
	ctx := context.Background()

	secretID := uuid.New()
	scope := model.NewVaultScope(uuid.New(), uuid.New())
	secretRepo.On("Read", ctx, secretID, scope).Return(nil, assert.AnError).Once()

	_, err := svc.GetVersionsMetadata(ctx, secretID, scope)
	require.Error(t, err)
	versionRepo.AssertNotCalled(t, "GetVersions", mock.Anything, mock.Anything)
}

// TestGetVersions_StillDecrypts pins that the fix did not over-correct: backup
// and restore genuinely need version plaintext, and that path is unchanged.
func TestGetVersions_StillDecrypts(t *testing.T) {
	secretRepo, versionRepo, _, svc := newMetadataFixture(t)
	svc.cryptoSvc = fakeCrypto{}
	ctx := context.Background()

	secretID := uuid.New()
	scope := model.NewVaultScope(uuid.New(), uuid.New())
	secretRepo.On("Read", ctx, secretID, scope).Return(&model.Secret{ID: secretID, Enabled: true}, nil).Once()
	versionRepo.On("GetVersions", ctx, secretID).Return([]model.SecretVersion{
		{ID: uuid.New(), SecretID: secretID, Version: 1, Value: "ENC(hunter2)"},
	}, nil).Once()

	versions, err := svc.GetVersions(ctx, secretID, scope)
	require.NoError(t, err)
	require.Len(t, versions, 1)
	assert.Equal(t, "hunter2", versions[0].Value)
}
