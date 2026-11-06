package repositories_test

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	rvdb "rocketvault/internal/db"
	"rocketvault/internal/repositories"
	"rocketvault/model"
)

func TestUserRepository_CreateStoresEmail(t *testing.T) {
	repo := repositories.NewUserRepository(rvdb.NewConn(setupUserDB(t), rvdb.SQLite), newLogger())
	ctx := context.Background()

	u := newUser("email-user", model.RoleUser)
	u.AuthProvider = "oidc"
	u.ExternalIDPSubject = "sub-1"
	u.Email = "a@example.com"
	require.NoError(t, repo.Create(ctx, u))

	got, err := repo.ReadByExternalSubject(ctx, "oidc", "sub-1")
	require.NoError(t, err)
	require.Equal(t, "a@example.com", got.Email)
}

func TestUserRepository_NoEmailReadsEmpty(t *testing.T) {
	repo := repositories.NewUserRepository(rvdb.NewConn(setupUserDB(t), rvdb.SQLite), newLogger())
	ctx := context.Background()

	u := newUser("no-email-user", model.RoleUser)
	require.NoError(t, repo.Create(ctx, u))

	got, err := repo.Read(ctx, u.ID)
	require.NoError(t, err)
	require.Equal(t, "", got.Email)
}

func TestUserRepository_UpdateEmail(t *testing.T) {
	repo := repositories.NewUserRepository(rvdb.NewConn(setupUserDB(t), rvdb.SQLite), newLogger())
	ctx := context.Background()

	u := newUser("update-email-user", model.RoleUser)
	require.NoError(t, repo.Create(ctx, u))

	require.NoError(t, repo.UpdateEmail(ctx, u.ID, "new@example.com"))
	got, err := repo.ReadByUsername(ctx, "update-email-user")
	require.NoError(t, err)
	require.Equal(t, "new@example.com", got.Email)

	err = repo.UpdateEmail(ctx, uuid.New(), "x@example.com")
	require.ErrorIs(t, err, repositories.ErrNotFound)
}
