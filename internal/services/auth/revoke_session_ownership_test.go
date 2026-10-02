package auth

// End-to-end ownership tests for RevokeSession against a real SQLite session
// table. The HTTP handler is the only caller today; the service is the single
// enforcement point, so any future CLI or MCP caller inherits this behavior.

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
	"rocketvault/internal/repositories"
	"rocketvault/model"
)

// newRevokeFixture returns a service backed by an in-memory session table.
func newRevokeFixture(t *testing.T) (AuthenticationService, repositories.SessionRepositoryInterface) {
	t.Helper()
	db, err := sql.Open("sqlite3", ":memory:")
	require.NoError(t, err)
	// One connection keeps every query on the same in-memory database.
	db.SetMaxOpenConns(1)
	t.Cleanup(func() { _ = db.Close() })
	_, err = db.ExecContext(context.Background(), `
		CREATE TABLE user_sessions (
			id                 TEXT PRIMARY KEY,
			user_id            TEXT NOT NULL,
			refresh_token_hash TEXT NOT NULL,
			device_info        TEXT NOT NULL DEFAULT '',
			ip_address         TEXT NOT NULL DEFAULT '',
			user_agent         TEXT NOT NULL DEFAULT '',
			expires_at         TIMESTAMP NOT NULL,
			last_used_at       TIMESTAMP NOT NULL,
			created_at         TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			revoked            BOOLEAN NOT NULL DEFAULT FALSE,
			revoked_at         TIMESTAMP NULL,
			revoked_reason     TEXT NOT NULL DEFAULT ''
		);
	`)
	require.NoError(t, err)

	logger := logging.InitLogger()
	repo := repositories.NewSessionRepository(repositories.SessionRepositoryConfig{
		DB:     rvdb.NewConn(db, rvdb.SQLite),
		Logger: logger,
	})
	svc := NewAuthenticationService(AuthenticationConfig{SessionRepository: repo, Logger: logger})
	return svc, repo
}

// seedSession inserts an active session owned by userID.
func seedSession(t *testing.T, repo repositories.SessionRepositoryInterface, userID uuid.UUID) uuid.UUID {
	t.Helper()
	sess := &model.Session{
		ID:               uuid.New(),
		UserID:           userID,
		RefreshTokenHash: uuid.NewString(),
		ExpiresAt:        time.Now().Add(time.Hour),
		LastUsedAt:       time.Now(),
		CreatedAt:        time.Now(),
	}
	require.NoError(t, repo.CreateSession(context.Background(), sess))
	return sess.ID
}

func TestRevokeSession_RealRepo_NonOwnerCannotRevoke(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	svc, repo := newRevokeFixture(t)
	owner := uuid.New()
	sessionID := seedSession(t, repo, owner)

	err := svc.RevokeSession(ctx, RevokeSessionRequest{
		SessionID: sessionID.String(), CallerID: uuid.New(), CallerRoles: []string{model.RoleUser}, Reason: "cross-user",
	})
	require.ErrorIs(t, err, ErrSessionNotFound)

	revoked, err := repo.IsSessionRevoked(ctx, sessionID)
	require.NoError(t, err)
	assert.False(t, revoked, "a non-owner must not revoke the session")

	// A missing session gives the same error, so the two cases are indistinguishable.
	err = svc.RevokeSession(ctx, RevokeSessionRequest{
		SessionID: uuid.NewString(), CallerID: uuid.New(), CallerRoles: []string{model.RoleUser}, Reason: "missing",
	})
	require.ErrorIs(t, err, ErrSessionNotFound)
}

func TestRevokeSession_RealRepo_OwnerRevokes(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	svc, repo := newRevokeFixture(t)
	owner := uuid.New()
	sessionID := seedSession(t, repo, owner)

	require.NoError(t, svc.RevokeSession(ctx, RevokeSessionRequest{
		SessionID: sessionID.String(), CallerID: owner, CallerRoles: []string{model.RoleUser}, Reason: "self",
	}))

	revoked, err := repo.IsSessionRevoked(ctx, sessionID)
	require.NoError(t, err)
	assert.True(t, revoked)
}

func TestRevokeSession_RealRepo_AdminRevokesAnySession(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	svc, repo := newRevokeFixture(t)
	sessionID := seedSession(t, repo, uuid.New())

	require.NoError(t, svc.RevokeSession(ctx, RevokeSessionRequest{
		SessionID: sessionID.String(), CallerID: uuid.New(), CallerRoles: []string{model.RoleAdmin}, Reason: "admin action",
	}))

	revoked, err := repo.IsSessionRevoked(ctx, sessionID)
	require.NoError(t, err)
	assert.True(t, revoked)
}
