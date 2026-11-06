package repositories_test

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	rvdb "rocketvault/internal/db"
	"rocketvault/internal/repositories"
)

func TestAuditRepository_QueryAuditLogs_ExcludeOutcome(t *testing.T) {
	db := openAuditTestDBFull(t)
	repo := repositories.NewAuditRepository(rvdb.NewConn(db, rvdb.SQLite))
	ctx := context.Background()
	now := time.Now().UTC()
	add := func(user, outcome string) {
		require.NoError(t, repo.InsertAuditLog(ctx, repositories.AuditLog{
			ID: uuid.New().String(), UserID: user, Action: "a",
			Outcome: outcome, Source: "api", Timestamp: now,
		}))
	}
	add("u1", "attempt")
	add("u1", "attempt")
	add("u1", "success")
	add("u1", "failure")
	add("u1", "") // Stored as NULL.
	add("u2", "attempt")
	add("u2", "success")

	attempt := "attempt"
	u1 := "u1"

	_, total, err := repo.QueryAuditLogs(ctx, repositories.AuditFilter{ExcludeOutcome: &attempt, Limit: 100})
	require.NoError(t, err)
	assert.Equal(t, int64(4), total, "attempt rows excluded, NULL and other outcomes kept")

	logs, total, err := repo.QueryAuditLogs(ctx, repositories.AuditFilter{UserID: &u1, ExcludeOutcome: &attempt, Limit: 1})
	require.NoError(t, err)
	assert.Equal(t, int64(3), total, "total ignores the page limit")
	assert.Len(t, logs, 1)

	success := "success"
	_, total, err = repo.QueryAuditLogs(ctx, repositories.AuditFilter{UserID: &u1, Outcome: &success, ExcludeOutcome: &attempt})
	require.NoError(t, err)
	assert.Equal(t, int64(1), total, "combines with the outcome filter")

	_, total, err = repo.QueryAuditLogs(ctx, repositories.AuditFilter{UserID: &u1})
	require.NoError(t, err)
	assert.Equal(t, int64(5), total, "unset leaves attempt rows in")
}
