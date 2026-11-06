package vaults

// Audit-first tests: a vault delete or purge must not run unless the critical
// audit row was written first.

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"rocketvault/internal/logging/logtest"
	auditServices "rocketvault/internal/services/audit"
	"rocketvault/model"
)

// fakeVaultAudit records calls in order and can fail critical writes.
type fakeVaultAudit struct {
	criticalErr error
	calls       []string
	critical    []auditServices.AuditEvent
}

func (f *fakeVaultAudit) RecordEvent(_ context.Context, ev auditServices.AuditEvent) error {
	f.calls = append(f.calls, "event:"+ev.Outcome)
	return nil
}

func (f *fakeVaultAudit) RecordCritical(_ context.Context, ev auditServices.AuditEvent) error {
	f.calls = append(f.calls, "critical:"+ev.Outcome)
	f.critical = append(f.critical, ev)
	return f.criticalErr
}

func (f *fakeVaultAudit) PersistAudit(_, _, _ string) error { return nil }

// auditedVaultFixture returns a service holding vault "stg", with audit wired.
func auditedVaultFixture(audit auditServices.AuditServiceInterface, deleted bool) (VaultService, *fakeVaultRepo, *noopCascade, uuid.UUID) {
	logger, _ := logtest.NewLogger()
	repo := newFakeRepo()
	id := uuid.New()
	v := &model.Vault{ID: id, Name: "stg", Enabled: true}
	if deleted {
		now := nowForTest()
		v.DeletedAt = &now
	}
	repo.byName["stg"] = v
	repo.byID[id.String()] = v
	cascade := &noopCascade{}
	svc := NewVaultService(repo, cascade, logger)
	svc.SetAuditService(audit)
	return svc, repo, cascade, id
}

func requireVaultAuditUnavailable(t *testing.T, err error) {
	t.Helper()
	require.Error(t, err)
	assert.True(t, errors.Is(err, auditServices.ErrAuditUnavailable), "%v", err)
	assert.Equal(t, "audit unavailable", err.Error())
}

func TestDeleteVault_AuditFailureLeavesVaultInPlace(t *testing.T) {
	audit := &fakeVaultAudit{criticalErr: errors.New("pq: disk full on audit_logs")}
	svc, repo, cascade, id := auditedVaultFixture(audit, false)

	err := svc.DeleteVault(context.Background(), "stg", uuid.New())

	requireVaultAuditUnavailable(t, err)
	assert.Nil(t, repo.byID[id.String()].DeletedAt, "the vault must stay active")
	assert.Zero(t, cascade.soft)
}

func TestDeleteVault_WritesAttemptBeforeDelete(t *testing.T) {
	audit := &fakeVaultAudit{}
	svc, repo, _, id := auditedVaultFixture(audit, false)
	actor := uuid.New()

	require.NoError(t, svc.DeleteVault(context.Background(), "stg", actor))

	assert.NotNil(t, repo.byID[id.String()].DeletedAt)
	assert.Equal(t, []string{"critical:attempt", "event:success"}, audit.calls)
	assert.Equal(t, "delete_vault", audit.critical[0].Action)
	assert.Equal(t, id.String(), audit.critical[0].ResourceID)
	assert.Equal(t, actor.String(), audit.critical[0].UserID)
}

func TestPurgeVault_AuditFailureLeavesVaultInPlace(t *testing.T) {
	audit := &fakeVaultAudit{criticalErr: errors.New("down")}
	svc, repo, cascade, id := auditedVaultFixture(audit, true)

	err := svc.PurgeVault(context.Background(), "stg", uuid.New())

	requireVaultAuditUnavailable(t, err)
	assert.Contains(t, repo.byID, id.String(), "the vault row must stay")
	assert.Zero(t, cascade.purge)
}

func TestPurgeVault_WritesAttemptBeforePurge(t *testing.T) {
	audit := &fakeVaultAudit{}
	svc, repo, _, id := auditedVaultFixture(audit, true)

	require.NoError(t, svc.PurgeVault(context.Background(), "stg", uuid.Nil))

	assert.NotContains(t, repo.byID, id.String())
	assert.Equal(t, []string{"critical:attempt", "event:success"}, audit.calls)
	assert.Equal(t, "purge_vault", audit.critical[0].Action)
	assert.Equal(t, "system", audit.critical[0].UserID, "the scheduler is recorded as system")
}

// TestPurgeVault_RefusalIsNotCritical pins that a purge-protection refusal
// is answered as before, even with audit down.
func TestPurgeVault_RefusalIsNotCritical(t *testing.T) {
	audit := &fakeVaultAudit{criticalErr: errors.New("down")}
	svc, repo, _, id := auditedVaultFixture(audit, true)
	repo.byID[id.String()].PurgeProtection = true

	err := svc.PurgeVault(context.Background(), "stg", uuid.New())

	assert.ErrorIs(t, err, ErrVaultPurgeProtected)
	assert.Empty(t, audit.critical)
}
