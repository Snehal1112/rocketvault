package repositories

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/google/uuid"
	_ "github.com/mattn/go-sqlite3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	rvdb "rocketvault/internal/db"
	"rocketvault/internal/logging"
	"rocketvault/model"
)

func newExportableDB(t *testing.T) (*sql.DB, rvdb.DB) {
	t.Helper()
	raw, err := sql.Open("sqlite3", "file:exportable_"+uuid.NewString()+"?mode=memory&cache=shared")
	require.NoError(t, err)
	t.Cleanup(func() { raw.Close() }) //nolint:errcheck,gosec
	require.NoError(t, rvdb.NewRepository(logging.InitLogger()).SetupSchema(raw, rvdb.SQLite))
	return raw, rvdb.NewConn(raw, rvdb.SQLite)
}

func TestKeyRepository_ExportableRoundTrips(t *testing.T) {
	_, conn := newExportableDB(t)
	repo := NewKeyRepository(conn, logging.InitLogger())
	ctx := context.Background()
	vaultID, userID := uuid.New(), uuid.New()
	scope := model.NewVaultScope(vaultID, userID)

	on := &model.Key{ID: uuid.New(), UserID: userID, VaultID: vaultID, Name: "on", Type: model.KeyTypeRSA,
		Value: "enc", Enabled: true, CreatedAt: time.Now(), Bits: 2048, Exportable: true}
	off := &model.Key{ID: uuid.New(), UserID: userID, VaultID: vaultID, Name: "off", Type: model.KeyTypeRSA,
		Value: "enc", Enabled: true, CreatedAt: time.Now(), Bits: 2048}
	require.NoError(t, repo.Create(ctx, on))
	require.NoError(t, repo.Create(ctx, off))

	got, err := repo.Read(ctx, on.ID, scope)
	require.NoError(t, err)
	assert.True(t, got.Exportable)
	got, err = repo.Read(ctx, off.ID, scope)
	require.NoError(t, err)
	assert.False(t, got.Exportable)

	list, err := repo.List(ctx, scope, KeyFilter{})
	require.NoError(t, err)
	byName := map[string]bool{}
	for _, k := range list {
		byName[k.Name] = k.Exportable
	}
	assert.Equal(t, map[string]bool{"on": true, "off": false}, byName)
}

func TestKeyRepository_UpdateNeverWritesExportable(t *testing.T) {
	_, conn := newExportableDB(t)
	repo := NewKeyRepository(conn, logging.InitLogger())
	ctx := context.Background()
	vaultID, userID := uuid.New(), uuid.New()
	scope := model.NewVaultScope(vaultID, userID)

	key := &model.Key{ID: uuid.New(), UserID: userID, VaultID: vaultID, Name: "k", Type: model.KeyTypeRSA,
		Value: "enc", Enabled: true, CreatedAt: time.Now(), Exportable: false}
	require.NoError(t, repo.Create(ctx, key))

	key.Exportable = true
	key.Value = "rotated"
	require.NoError(t, repo.Update(ctx, key, scope))

	got, err := repo.Read(ctx, key.ID, scope)
	require.NoError(t, err)
	assert.Equal(t, "rotated", got.Value, "the update itself applied")
	assert.False(t, got.Exportable, "Update must never write exportable")
}

func TestCertificateRepository_ExportableRoundTripsAndUpdateNeverWritesIt(t *testing.T) {
	_, conn := newExportableDB(t)
	repo := NewCertificateRepository(conn, logging.InitLogger())
	ctx := context.Background()
	vaultID, userID := uuid.New(), uuid.New()
	scope := model.NewVaultScope(vaultID, userID)

	cert := &model.Certificate{ID: uuid.New(), UserID: userID, VaultID: vaultID, KeyID: uuid.New(), Name: "c",
		Certificate: "pem", PrivateKey: "enc", CreatedAt: time.Now(), Enabled: true, Version: 1, Exportable: true}
	require.NoError(t, repo.Create(ctx, cert))

	got, err := repo.Read(ctx, cert.ID, scope)
	require.NoError(t, err)
	assert.True(t, got.Exportable)

	got.Exportable = false
	got.Name = "renamed"
	require.NoError(t, repo.Update(ctx, got, scope))
	again, err := repo.Read(ctx, cert.ID, scope)
	require.NoError(t, err)
	assert.Equal(t, "renamed", again.Name)
	assert.True(t, again.Exportable, "Update must never write exportable")

	list, err := repo.List(ctx, scope, CertificateFilter{})
	require.NoError(t, err)
	require.Len(t, list, 1)
	assert.True(t, list[0].Exportable)
}

func TestCertificateRepository_UpdateNeverWritesExportable(t *testing.T) {
	_, conn := newExportableDB(t)
	repo := NewCertificateRepository(conn, logging.InitLogger())
	ctx := context.Background()
	vaultID, userID := uuid.New(), uuid.New()
	scope := model.NewVaultScope(vaultID, userID)

	cert := &model.Certificate{ID: uuid.New(), UserID: userID, VaultID: vaultID, KeyID: uuid.New(), Name: "c",
		Certificate: "pem", PrivateKey: "enc", CreatedAt: time.Now(), Enabled: true, Version: 1}
	require.NoError(t, repo.Create(ctx, cert))
	cert.Exportable = true
	require.NoError(t, repo.Update(ctx, cert, scope))
	got, err := repo.Read(ctx, cert.ID, scope)
	require.NoError(t, err)
	assert.False(t, got.Exportable)
}
