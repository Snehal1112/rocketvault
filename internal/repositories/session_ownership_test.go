package repositories_test

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	rvdb "rocketvault/internal/db"
	"rocketvault/internal/repositories"
)

// A session may only be revoked through RevokeUserSession by its owner.
func TestSessionRepository_RevokeUserSession_OwnerOnly(t *testing.T) {
	t.Parallel()
	db := setupSessionDB(t)
	repo := repositories.NewSessionRepository(repositories.SessionRepositoryConfig{DB: rvdb.NewConn(db, rvdb.SQLite), Logger: newLogger()})
	ctx := context.Background()

	owner := uuid.New()
	other := uuid.New()
	sess := newSession(owner)
	require.NoError(t, repo.CreateSession(ctx, sess))

	err := repo.RevokeUserSession(ctx, sess.ID, other, "cross-user")
	require.ErrorIs(t, err, repositories.ErrNotFound)

	revoked, err := repo.IsSessionRevoked(ctx, sess.ID)
	require.NoError(t, err)
	assert.False(t, revoked, "a non-owner must not revoke the session")

	require.NoError(t, repo.RevokeUserSession(ctx, sess.ID, owner, "self"))

	revoked, err = repo.IsSessionRevoked(ctx, sess.ID)
	require.NoError(t, err)
	assert.True(t, revoked)
}

func TestSessionRepository_RevokeUserSession_AlreadyRevoked(t *testing.T) {
	t.Parallel()
	db := setupSessionDB(t)
	repo := repositories.NewSessionRepository(repositories.SessionRepositoryConfig{DB: rvdb.NewConn(db, rvdb.SQLite), Logger: newLogger()})
	ctx := context.Background()

	owner := uuid.New()
	sess := newSession(owner)
	require.NoError(t, repo.CreateSession(ctx, sess))
	require.NoError(t, repo.RevokeUserSession(ctx, sess.ID, owner, "first"))

	err := repo.RevokeUserSession(ctx, sess.ID, owner, "second")
	require.ErrorIs(t, err, repositories.ErrNotFound)
}
