package repositories_test

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
	"rocketvault/internal/repositories"
	"rocketvault/model"
)

func setupOAuth2TestDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite3", ":memory:")
	require.NoError(t, err)
	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS oauth2_clients (
id            TEXT PRIMARY KEY,
name          TEXT NOT NULL UNIQUE,
client_secret TEXT NOT NULL,
description   TEXT DEFAULT '',
enabled       BOOLEAN DEFAULT TRUE,
created_at    TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
expires_at    TIMESTAMP NULL
)
	`)
	require.NoError(t, err)
	createPrincipalGrantTables(t, db)
	t.Cleanup(func() { db.Close() }) //nolint:errcheck,gosec
	return db
}

func TestOAuth2ClientRepository_CreateAndGetByID(t *testing.T) {
	t.Parallel()
	db := setupOAuth2TestDB(t)
	repo := repositories.NewOAuth2ClientRepository(rvdb.NewConn(db, rvdb.SQLite))
	ctx := context.Background()

	client := &model.OAuth2Client{
		ID:           uuid.New(),
		Name:         "my-service",
		ClientSecret: "hashed-secret",
		Description:  "test client",
		Enabled:      true,
		CreatedAt:    time.Now().UTC(),
	}

	err := repo.Create(ctx, client)
	require.NoError(t, err)

	got, err := repo.GetByID(ctx, client.ID)
	require.NoError(t, err)
	assert.Equal(t, client.ID, got.ID)
	assert.Equal(t, client.Name, got.Name)
	assert.Equal(t, client.ClientSecret, got.ClientSecret)
	assert.Equal(t, client.Enabled, got.Enabled)
}

func TestOAuth2ClientRepository_FindByName(t *testing.T) {
	t.Parallel()
	db := setupOAuth2TestDB(t)
	repo := repositories.NewOAuth2ClientRepository(rvdb.NewConn(db, rvdb.SQLite))
	ctx := context.Background()

	client := &model.OAuth2Client{
		ID:           uuid.New(),
		Name:         "find-by-name-client",
		ClientSecret: "hash",
		Enabled:      true,
		CreatedAt:    time.Now().UTC(),
	}
	require.NoError(t, repo.Create(ctx, client))

	got, err := repo.FindByName(ctx, "find-by-name-client")
	require.NoError(t, err)
	assert.Equal(t, client.ID, got.ID)
	assert.Equal(t, "find-by-name-client", got.Name)
}

func TestOAuth2ClientRepository_List(t *testing.T) {
	t.Parallel()
	db := setupOAuth2TestDB(t)
	repo := repositories.NewOAuth2ClientRepository(rvdb.NewConn(db, rvdb.SQLite))
	ctx := context.Background()

	for _, name := range []string{"svc-a", "svc-b", "svc-c"} {
		require.NoError(t, repo.Create(ctx, &model.OAuth2Client{
			ID:           uuid.New(),
			Name:         name,
			ClientSecret: "h",
			Enabled:      true,
			CreatedAt:    time.Now().UTC(),
		}))
	}

	clients, err := repo.List(ctx)
	require.NoError(t, err)
	assert.Len(t, clients, 3)
}

func TestOAuth2ClientRepository_Update(t *testing.T) {
	t.Parallel()
	db := setupOAuth2TestDB(t)
	repo := repositories.NewOAuth2ClientRepository(rvdb.NewConn(db, rvdb.SQLite))
	ctx := context.Background()

	client := &model.OAuth2Client{
		ID:           uuid.New(),
		Name:         "update-me",
		ClientSecret: "old-hash",
		Enabled:      true,
		CreatedAt:    time.Now().UTC(),
	}
	require.NoError(t, repo.Create(ctx, client))

	client.ClientSecret = "new-hash"
	client.Enabled = false
	require.NoError(t, repo.Update(ctx, client))

	got, err := repo.GetByID(ctx, client.ID)
	require.NoError(t, err)
	assert.Equal(t, "new-hash", got.ClientSecret)
	assert.False(t, got.Enabled)
}

func TestOAuth2ClientRepository_Delete(t *testing.T) {
	t.Parallel()
	db := setupOAuth2TestDB(t)
	repo := repositories.NewOAuth2ClientRepository(rvdb.NewConn(db, rvdb.SQLite))
	ctx := context.Background()

	client := &model.OAuth2Client{
		ID:           uuid.New(),
		Name:         "delete-me",
		ClientSecret: "h",
		Enabled:      true,
		CreatedAt:    time.Now().UTC(),
	}
	require.NoError(t, repo.Create(ctx, client))
	require.NoError(t, repo.Delete(ctx, client.ID))

	_, err := repo.GetByID(ctx, client.ID)
	assert.Error(t, err)
}
