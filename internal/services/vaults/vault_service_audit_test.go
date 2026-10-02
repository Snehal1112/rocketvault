package vaults

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"rocketvault/internal/logging/logtest"
	"rocketvault/model"
)

// TestVaultDestructiveOps_AuditTheActor is the B81 regression that supersedes
// B58: delete, recover and purge each record the acting principal.
func TestVaultDestructiveOps_AuditTheActor(t *testing.T) {
	logger, rec := logtest.NewLogger()
	repo := newFakeRepo()
	id := uuid.New()
	repo.byName["stg"] = &model.Vault{ID: id, Name: "stg", Enabled: true}
	repo.byID[id.String()] = repo.byName["stg"]
	svc := NewVaultService(repo, &noopCascade{}, logger)
	actor := uuid.New()

	require.NoError(t, svc.DeleteVault(context.Background(), "stg", actor))
	require.NoError(t, svc.RecoverVault(context.Background(), "stg", actor))
	require.NoError(t, svc.DeleteVault(context.Background(), "stg", actor))
	require.NoError(t, svc.PurgeVault(context.Background(), "stg", actor))

	for _, action := range []string{"delete_vault", "recover_vault", "purge_vault"} {
		row, ok := rec.Find(action, "success")
		require.True(t, ok, "%s must emit a success audit row", action)
		assert.Equal(t, actor.String(), row.UserID, "%s must name the actor", action)
	}
}

// TestPurgeVault_SchedulerActorIsRecordedAsSystem pins the one legitimate
// uuid.Nil caller, the background purge scheduler.
func TestPurgeVault_SchedulerActorIsRecordedAsSystem(t *testing.T) {
	logger, rec := logtest.NewLogger()
	repo := newFakeRepo()
	id := uuid.New()
	now := nowForTest()
	repo.byName["old"] = &model.Vault{ID: id, Name: "old", DeletedAt: &now}
	repo.byID[id.String()] = repo.byName["old"]
	svc := NewVaultService(repo, &noopCascade{}, logger)

	require.NoError(t, svc.PurgeVault(context.Background(), "old", uuid.Nil))

	row, ok := rec.Find("purge_vault", "success")
	require.True(t, ok)
	assert.Equal(t, "system", row.UserID)
}
