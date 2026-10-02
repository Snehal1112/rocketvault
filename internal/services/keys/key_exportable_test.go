package keys

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/google/uuid"
	_ "github.com/mattn/go-sqlite3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"rocketvault/internal/crypto"
	rvdb "rocketvault/internal/db"
	"rocketvault/internal/repositories"
	"rocketvault/model"
)

func TestCreateKey_ExportableIsStored(t *testing.T) {
	setupKeyTestMasterKey()
	repo := &mockKeyRepository{}
	var stored *model.Key
	repo.On("Create", mock.Anything, mock.AnythingOfType("*model.Key")).
		Run(func(args mock.Arguments) { stored = args.Get(1).(*model.Key) }).Return(nil)
	svc := NewKeyService(KeyServiceConfig{KeyRepository: repo, KeyProvider: crypto.NewSoftwareKeyProvider(), Logger: newKeyLogger()})

	_, err := svc.CreateRSAKey(context.Background(), CreateKeyRequest{Name: "k", Type: "RSA", Bits: 2048, UserID: uuid.New(), Exportable: true})
	require.NoError(t, err)
	require.NotNil(t, stored)
	assert.True(t, stored.Exportable)

	_, err = svc.CreateECDSAKey(context.Background(), CreateKeyRequest{Name: "e", Type: "ECDSA", Curve: "P-256", UserID: uuid.New()})
	require.NoError(t, err)
	assert.False(t, stored.Exportable, "a create without the field stays non-exportable")
}

func TestCreateKey_ES256KMayBeCreatedExportable(t *testing.T) {
	setupKeyTestMasterKey()
	repo := &mockKeyRepository{}
	var stored *model.Key
	repo.On("Create", mock.Anything, mock.AnythingOfType("*model.Key")).
		Run(func(args mock.Arguments) { stored = args.Get(1).(*model.Key) }).Return(nil)
	svc := NewKeyService(KeyServiceConfig{KeyRepository: repo, KeyProvider: crypto.NewSoftwareKeyProvider(), Logger: newKeyLogger()})

	_, err := svc.CreateECDSAKey(context.Background(), CreateKeyRequest{Name: "k1", Type: "ECDSA", Curve: "P-256K", UserID: uuid.New(), Exportable: true})
	require.NoError(t, err)
	assert.True(t, stored.Exportable, "the refusal for ES256K happens at export, not at creation")
}

func TestCreateKey_HSMRejectsExportable(t *testing.T) {
	repo := &mockKeyRepository{}
	provider := &mockKeyProviderForService{}
	hsmHandle := uuid.NewString()
	provider.On("GenerateRSAKey", 2048).Return(hsmHandle, nil)
	provider.On("GenerateECDSAKey", "P-256").Return(hsmHandle, nil)
	svc := NewKeyService(KeyServiceConfig{KeyRepository: repo, KeyProvider: provider, Logger: newKeyLogger()})

	_, err := svc.CreateRSAKey(context.Background(), CreateKeyRequest{Name: "k", Type: "RSA", Bits: 2048, UserID: uuid.New(), Exportable: true})
	require.ErrorIs(t, err, model.ErrExportableNotSupported)
	_, err = svc.CreateECDSAKey(context.Background(), CreateKeyRequest{Name: "e", Type: "ECDSA", Curve: "P-256", UserID: uuid.New(), Exportable: true})
	require.ErrorIs(t, err, model.ErrExportableNotSupported)
	repo.AssertNotCalled(t, "Create", mock.Anything, mock.Anything)
}

func TestCreateOctKey_RejectsExportableBeforeTheProvider(t *testing.T) {
	provider := &mockKeyProviderForService{}
	svc := NewKeyService(KeyServiceConfig{KeyRepository: &mockKeyRepository{}, KeyProvider: provider, Logger: newKeyLogger()})

	_, err := svc.CreateOctKey(context.Background(), CreateKeyRequest{Name: "o", Type: "OCT", Bits: 256, UserID: uuid.New(), Exportable: true})
	require.ErrorIs(t, err, model.ErrExportableNotSupported)
	provider.AssertNotCalled(t, "GenerateAESKey", mock.Anything)
}

func TestImportKey_ExportableIsStoredAndHSMRejects(t *testing.T) {
	setupKeyTestMasterKey()
	jwk := `{"kty":"EC","crv":"P-256","x":"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU","y":"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0","d":"jpsQnnGQmL-YBIffH1136cspYG6-0iY7X1fCE9-E9LI"}`

	repo := &mockKeyRepository{}
	var stored *model.Key
	repo.On("Create", mock.Anything, mock.AnythingOfType("*model.Key")).
		Run(func(args mock.Arguments) { stored = args.Get(1).(*model.Key) }).Return(nil)
	svc := NewKeyService(KeyServiceConfig{KeyRepository: repo, KeyProvider: crypto.NewSoftwareKeyProvider(), Logger: newKeyLogger()})
	_, err := svc.ImportKey(context.Background(), ImportKeyRequest{Name: "imp", JWK: []byte(jwk), UserID: uuid.New(), Exportable: true})
	require.NoError(t, err)
	assert.True(t, stored.Exportable)

	provider := &mockKeyProviderForService{}
	provider.On("ImportKey", "ECDSA", mock.Anything).Return(uuid.NewString(), nil)
	hsmRepo := &mockKeyRepository{}
	hsm := NewKeyService(KeyServiceConfig{KeyRepository: hsmRepo, KeyProvider: provider, Logger: newKeyLogger()})
	_, err = hsm.ImportKey(context.Background(), ImportKeyRequest{Name: "imp", JWK: []byte(jwk), UserID: uuid.New(), Exportable: true})
	require.ErrorIs(t, err, model.ErrExportableNotSupported)
	hsmRepo.AssertNotCalled(t, "Create", mock.Anything, mock.Anything)
}

// TestRotateKey_PreservesExportable runs a real rotation over the real
// repository: rotation updates the same row, and the flag must survive it.
func TestRotateKey_PreservesExportable(t *testing.T) {
	setupKeyTestMasterKey()
	raw, err := sql.Open("sqlite3", "file:rotexp_"+uuid.NewString()+"?mode=memory&cache=shared")
	require.NoError(t, err)
	t.Cleanup(func() { raw.Close() }) //nolint:errcheck,gosec
	require.NoError(t, rvdb.NewRepository(newKeyLogger()).SetupSchema(raw, rvdb.SQLite))
	repo := repositories.NewKeyRepository(rvdb.NewConn(raw, rvdb.SQLite), newKeyLogger())
	svc := NewKeyService(KeyServiceConfig{KeyRepository: repo, KeyProvider: crypto.NewSoftwareKeyProvider(), Logger: newKeyLogger()})

	ctx := context.Background()
	vaultID, userID := uuid.New(), uuid.New()
	scope := model.NewVaultScope(vaultID, userID)
	created, err := svc.CreateRSAKey(ctx, CreateKeyRequest{Name: "rot", Type: "RSA", Bits: 2048, UserID: userID, VaultID: vaultID, Exportable: true})
	require.NoError(t, err)

	_, err = svc.RotateKey(ctx, created.KeyID, scope)
	require.NoError(t, err)

	got, err := svc.GetKey(ctx, created.KeyID, scope)
	require.NoError(t, err)
	assert.True(t, got.Exportable, "rotation keeps the flag")
	assert.WithinDuration(t, time.Now(), *got.UpdatedAt, time.Minute)
}
