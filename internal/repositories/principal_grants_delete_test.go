package repositories_test

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	rvdb "rocketvault/internal/db"
	"rocketvault/internal/repositories"
	"rocketvault/model"
)

// principalGrantTables lists every table keyed by a principal that has no
// foreign key to the principal's own row.
var principalGrantTables = []string{"role_assignments", "access_policies", "vault_provisioning_grants"}

// createPrincipalGrantTables adds the columns the delete paths touch, so a
// test does not depend on the columns the delete paths ignore.
func createPrincipalGrantTables(t *testing.T, db *sql.DB) {
	t.Helper()
	for _, table := range principalGrantTables {
		_, err := db.ExecContext(context.Background(), `CREATE TABLE `+table+` (id TEXT PRIMARY KEY, principal_id TEXT NOT NULL)`)
		require.NoError(t, err)
	}
}

// seedPrincipalGrants inserts one row per grant table for principalID.
func seedPrincipalGrants(t *testing.T, db *sql.DB, principalID uuid.UUID) {
	t.Helper()
	for _, table := range principalGrantTables {
		_, err := db.ExecContext(context.Background(), `INSERT INTO `+table+` (id, principal_id) VALUES (?, ?)`, uuid.NewString(), principalID.String())
		require.NoError(t, err)
	}
}

// assertPrincipalGrantCount checks every grant table holds want rows for principalID.
func assertPrincipalGrantCount(t *testing.T, db *sql.DB, principalID uuid.UUID, want int) {
	t.Helper()
	for _, table := range principalGrantTables {
		var got int
		require.NoError(t, db.QueryRowContext(context.Background(), `SELECT COUNT(*) FROM `+table+` WHERE principal_id = ?`, principalID.String()).Scan(&got))
		assert.Equal(t, want, got, table)
	}
}

func newDeleteTestClient(name string) *model.OAuth2Client {
	return &model.OAuth2Client{
		ID:           uuid.New(),
		Name:         name,
		ClientSecret: "h",
		Enabled:      true,
		CreatedAt:    time.Now().UTC(),
	}
}

// B99: a deleted user keeps no grants, and other principals keep theirs.
func TestUserRepository_Delete_RemovesPrincipalGrants(t *testing.T) {
	t.Parallel()
	db := setupUserDB(t)
	repo := repositories.NewUserRepository(rvdb.NewConn(db, rvdb.SQLite), newLogger())
	ctx := context.Background()

	u := newUser("departing", model.RoleUser)
	require.NoError(t, repo.Create(ctx, u))
	other := uuid.New()
	seedPrincipalGrants(t, db, u.ID)
	seedPrincipalGrants(t, db, other)

	require.NoError(t, repo.Delete(ctx, u.ID))

	assertPrincipalGrantCount(t, db, u.ID, 0)
	assertPrincipalGrantCount(t, db, other, 1)
}

// B99: the user and its grants go together, so a failed cleanup keeps the user.
func TestUserRepository_Delete_KeepsUserWhenGrantCleanupFails(t *testing.T) {
	t.Parallel()
	db := setupUserDB(t)
	repo := repositories.NewUserRepository(rvdb.NewConn(db, rvdb.SQLite), newLogger())
	ctx := context.Background()

	u := newUser("stays", model.RoleUser)
	require.NoError(t, repo.Create(ctx, u))
	_, err := db.ExecContext(context.Background(), `DROP TABLE vault_provisioning_grants`)
	require.NoError(t, err)

	require.Error(t, repo.Delete(ctx, u.ID))

	_, err = repo.Read(ctx, u.ID)
	assert.NoError(t, err)
}

// B99: a deleted service account keeps no grants, and other principals keep theirs.
func TestOAuth2ClientRepository_Delete_RemovesPrincipalGrants(t *testing.T) {
	t.Parallel()
	db := setupOAuth2TestDB(t)
	repo := repositories.NewOAuth2ClientRepository(rvdb.NewConn(db, rvdb.SQLite))
	ctx := context.Background()

	client := newDeleteTestClient("departing-sa")
	require.NoError(t, repo.Create(ctx, client))
	other := uuid.New()
	seedPrincipalGrants(t, db, client.ID)
	seedPrincipalGrants(t, db, other)

	require.NoError(t, repo.Delete(ctx, client.ID))

	assertPrincipalGrantCount(t, db, client.ID, 0)
	assertPrincipalGrantCount(t, db, other, 1)
}

// B99: the client and its grants go together, so a failed cleanup keeps the client.
func TestOAuth2ClientRepository_Delete_KeepsClientWhenGrantCleanupFails(t *testing.T) {
	t.Parallel()
	db := setupOAuth2TestDB(t)
	repo := repositories.NewOAuth2ClientRepository(rvdb.NewConn(db, rvdb.SQLite))
	ctx := context.Background()

	client := newDeleteTestClient("stays-sa")
	require.NoError(t, repo.Create(ctx, client))
	_, err := db.ExecContext(context.Background(), `DROP TABLE vault_provisioning_grants`)
	require.NoError(t, err)

	require.Error(t, repo.Delete(ctx, client.ID))

	_, err = repo.GetByID(ctx, client.ID)
	assert.NoError(t, err)
}
