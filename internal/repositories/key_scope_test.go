package repositories

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/google/uuid"
	_ "github.com/mattn/go-sqlite3"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	rvdb "rocketvault/internal/db"
	"rocketvault/internal/logging"
	"rocketvault/model"
)

func newScopeTestKeyRepo(t *testing.T) *KeyRepository {
	t.Helper()
	dsn := "file:keyscope_" + uuid.NewString() + "?mode=memory&cache=shared"
	db, err := sql.Open("sqlite3", dsn)
	require.NoError(t, err)
	t.Cleanup(func() { db.Close() }) //nolint:errcheck,gosec

	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS keys (
		id TEXT PRIMARY KEY,
		user_id TEXT NOT NULL,
		vault_id TEXT NOT NULL DEFAULT '00000000-0000-0000-0000-00000000efa1',
		name TEXT NOT NULL,
		value TEXT NOT NULL,
		type TEXT NOT NULL,
		revoked BOOLEAN NOT NULL DEFAULT FALSE,
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		deleted_at TIMESTAMP DEFAULT NULL,
		purge_protection BOOLEAN NOT NULL DEFAULT FALSE,
		scheduled_purge_at TIMESTAMP DEFAULT NULL,
		enabled BOOLEAN NOT NULL DEFAULT TRUE,
		expires_at TIMESTAMP NULL,
		not_before TIMESTAMP NULL,
		bits INTEGER NOT NULL DEFAULT 0,
		curve TEXT NOT NULL DEFAULT '',
		updated_at TIMESTAMP NULL,
		exportable BOOLEAN NOT NULL DEFAULT FALSE
	);
	CREATE TABLE IF NOT EXISTS key_tags (
		key_id TEXT NOT NULL,
		tag TEXT NOT NULL,
		PRIMARY KEY (key_id, tag)
	)`)
	require.NoError(t, err)

	l := logrus.New()
	l.SetLevel(logrus.PanicLevel)
	return &KeyRepository{db: rvdb.NewConn(db, rvdb.SQLite), log: &logging.Logger{Logger: l}}
}

func seedScopeKey(t *testing.T, repo *KeyRepository, ownerID, vaultID uuid.UUID, name, keyType string) *model.Key {
	t.Helper()
	k := &model.Key{
		ID:        uuid.New(),
		UserID:    ownerID,
		VaultID:   vaultID,
		Name:      name,
		Type:      keyType,
		Value:     "encrypted-" + name,
		CreatedAt: time.Now().UTC(),
		Enabled:   true,
		Bits:      2048,
	}
	require.NoError(t, repo.Create(context.Background(), k))
	return k
}

func TestKeyRead(t *testing.T) {
	repo := newScopeTestKeyRepo(t)
	ctx := context.Background()

	ownerID, otherUser := uuid.New(), uuid.New()
	vaultA, vaultB := uuid.New(), uuid.New()
	key := seedScopeKey(t, repo, ownerID, vaultA, "rsa-a", model.KeyTypeRSA)

	got, err := repo.Read(ctx, key.ID, model.NewVaultScope(vaultA, otherUser))
	require.NoError(t, err)
	assert.Equal(t, key.ID, got.ID)
	assert.Equal(t, vaultA, got.VaultID)

	_, err = repo.Read(ctx, key.ID, model.NewVaultScope(vaultB, otherUser))
	assert.Error(t, err)

	_, err = repo.Read(ctx, key.ID, model.NewOwnerScope(vaultA, otherUser))
	assert.Error(t, err)

	got, err = repo.Read(ctx, key.ID, model.NewAdminScope(otherUser))
	require.NoError(t, err)
	assert.Equal(t, key.ID, got.ID)
}

func TestKeyUpdate(t *testing.T) {
	repo := newScopeTestKeyRepo(t)
	ctx := context.Background()

	ownerID, otherUser := uuid.New(), uuid.New()
	vaultA, vaultB := uuid.New(), uuid.New()
	key := seedScopeKey(t, repo, ownerID, vaultA, "rsa-b", model.KeyTypeRSA)

	updated := *key
	updated.Name = "rsa-b-renamed"
	require.NoError(t, repo.Update(ctx, &updated, model.NewVaultScope(vaultA, otherUser)))

	got, err := repo.Read(ctx, key.ID, model.NewAdminScope(uuid.Nil))
	require.NoError(t, err)
	assert.Equal(t, "rsa-b-renamed", got.Name)

	blocked := *key
	blocked.Name = "should-not-land"
	assert.Error(t, repo.Update(ctx, &blocked, model.NewVaultScope(vaultB, otherUser)))
}

func TestKeyList(t *testing.T) {
	repo := newScopeTestKeyRepo(t)
	ctx := context.Background()

	ownerA, ownerB := uuid.New(), uuid.New()
	vaultA, vaultB := uuid.New(), uuid.New()
	seedScopeKey(t, repo, ownerA, vaultA, "rsa-1", model.KeyTypeRSA)
	seedScopeKey(t, repo, ownerA, vaultA, "ec-1", model.KeyTypeECDSA)
	seedScopeKey(t, repo, ownerB, vaultB, "rsa-2", model.KeyTypeRSA)

	inVault, err := repo.List(ctx, model.NewVaultScope(vaultA, ownerB), KeyFilter{})
	require.NoError(t, err)
	assert.Len(t, inVault, 2)

	typed, err := repo.List(ctx, model.NewVaultScope(vaultA, ownerB), KeyFilter{Type: model.KeyTypeRSA})
	require.NoError(t, err)
	require.Len(t, typed, 1)
	assert.Equal(t, model.KeyTypeRSA, typed[0].Type)

	byOwner, err := repo.List(ctx, model.NewOwnerScope(vaultB, ownerA), KeyFilter{})
	require.NoError(t, err)
	assert.Len(t, byOwner, 2, "owner scope must not constrain vault_id")

	all, err := repo.List(ctx, model.NewAdminScope(uuid.Nil), KeyFilter{})
	require.NoError(t, err)
	assert.Len(t, all, 3)
}
