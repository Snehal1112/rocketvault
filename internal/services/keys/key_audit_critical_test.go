package keys

// Audit-first tests: an export must not release material and a purge must not
// remove a key unless the critical audit row was written first.

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"rocketvault/internal/crypto"
	"rocketvault/internal/logging"
	"rocketvault/internal/repositories"
	auditServices "rocketvault/internal/services/audit"
	"rocketvault/model"
)

// fakeKeyAudit records calls in order and can fail critical writes.
// internal/testutils cannot be used here because it imports this package.
type fakeKeyAudit struct {
	mu          sync.Mutex
	criticalErr error
	calls       []string
	critical    []auditServices.AuditEvent
	events      []auditServices.AuditEvent
}

func (f *fakeKeyAudit) RecordEvent(_ context.Context, ev auditServices.AuditEvent) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, "event:"+ev.Outcome)
	f.events = append(f.events, ev)
	return nil
}

func (f *fakeKeyAudit) RecordCritical(_ context.Context, ev auditServices.AuditEvent) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, "critical:"+ev.Outcome)
	f.critical = append(f.critical, ev)
	return f.criticalErr
}

func (f *fakeKeyAudit) PersistAudit(_, _, _ string) error { return nil }

func (f *fakeKeyAudit) note(call string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, call)
}

// requireAuditUnavailable checks the public error shape of a refused operation.
func requireAuditUnavailable(t *testing.T, err error) {
	t.Helper()
	require.Error(t, err)
	assert.True(t, errors.Is(err, auditServices.ErrAuditUnavailable), "%v", err)
	assert.Equal(t, "audit unavailable", err.Error(), "the cause must not reach the caller")
}

// auditedKeyService builds a key service over h's repository with audit wired.
func auditedKeyService(h *keyExportHarness, audit auditServices.AuditServiceInterface) KeyService {
	return NewKeyService(KeyServiceConfig{KeyRepository: h.repo, KeyProvider: crypto.NewSoftwareKeyProvider(),
		Logger: newKeyLogger(), AuditService: audit})
}

func TestExportKey_AuditFailureReleasesNoMaterial(t *testing.T) {
	h := newKeyExportHarness(t, nil)
	id := h.create(t, "RSA", "", true)
	audit := &fakeKeyAudit{criticalErr: errors.New("pq: disk full on audit_logs")}

	res, err := auditedKeyService(h, audit).ExportKey(context.Background(), h.scope, id, 0)

	requireAuditUnavailable(t, err)
	assert.Nil(t, res, "no key material may be returned")
	require.Len(t, audit.critical, 1)
	assert.Equal(t, "export_key", audit.critical[0].Action)
	assert.Equal(t, "attempt", audit.critical[0].Outcome)
	assert.Equal(t, id.String(), audit.critical[0].ResourceID)
}

func TestExportKey_WritesAttemptBeforeRelease(t *testing.T) {
	h := newKeyExportHarness(t, nil)
	id := h.create(t, "RSA", "", true)
	audit := &fakeKeyAudit{}

	res, err := auditedKeyService(h, audit).ExportKey(context.Background(), h.scope, id, 0)

	require.NoError(t, err)
	require.NotNil(t, res)
	assert.NotEmpty(t, res.PrivateKeyPEM)
	assert.Equal(t, []string{"critical:attempt"}, audit.calls, "the result row is exportaudit's job")
	assert.Equal(t, "key", audit.critical[0].ResourceType)
	assert.Contains(t, audit.critical[0].Details, h.vault.String())
}

// TestExportKey_RefusalIsNotCritical pins that a not-exportable denial is
// answered as before, even with audit down, and writes no critical row.
func TestExportKey_RefusalIsNotCritical(t *testing.T) {
	h := newKeyExportHarness(t, nil)
	id := h.create(t, "RSA", "", false)
	audit := &fakeKeyAudit{criticalErr: errors.New("down")}

	_, err := auditedKeyService(h, audit).ExportKey(context.Background(), h.scope, id, 0)

	assert.ErrorIs(t, err, model.ErrKeyNotExportable)
	assert.Empty(t, audit.critical)
}

// purgeableKeyRepo returns a mock repository holding keyID as soft-deleted in scope.
func purgeableKeyRepo(scope model.Scope, keyID uuid.UUID) *mockKeyRepository {
	now := time.Now()
	repo := &mockKeyRepository{}
	repo.On("List", mock.Anything, scope, repositories.KeyFilter{OnlyDeleted: true}).
		Return([]model.Key{{ID: keyID, Name: "k", Type: model.KeyTypeRSA, DeletedAt: &now}}, nil)
	return repo
}

func TestPurgeKey_AuditFailureLeavesKeySoftDeleted(t *testing.T) {
	scope := model.NewVaultScope(uuid.New(), uuid.New())
	keyID := uuid.New()
	repo := purgeableKeyRepo(scope, keyID)
	audit := &fakeKeyAudit{criticalErr: errors.New("down")}
	svc := NewKeyService(KeyServiceConfig{KeyRepository: repo, Logger: &logging.Logger{Logger: logrus.New()}, AuditService: audit})

	err := svc.PurgeKey(context.Background(), keyID, scope)

	requireAuditUnavailable(t, err)
	repo.AssertNotCalled(t, "PurgeKey", mock.Anything, mock.Anything)
}

func TestPurgeKey_WritesAttemptBeforePurge(t *testing.T) {
	scope := model.NewVaultScope(uuid.New(), uuid.New())
	keyID := uuid.New()
	repo := purgeableKeyRepo(scope, keyID)
	audit := &fakeKeyAudit{}
	repo.On("PurgeKey", mock.Anything, keyID).Run(func(mock.Arguments) { audit.note("purge") }).Return(nil)
	svc := NewKeyService(KeyServiceConfig{KeyRepository: repo, Logger: &logging.Logger{Logger: logrus.New()}, AuditService: audit})

	require.NoError(t, svc.PurgeKey(context.Background(), keyID, scope))

	assert.Equal(t, []string{"critical:attempt", "purge", "event:success"}, audit.calls)
	assert.Equal(t, "purge_key", audit.critical[0].Action)
	assert.Equal(t, keyID.String(), audit.critical[0].ResourceID)
	assert.Equal(t, scope.ActorID().String(), audit.critical[0].UserID)
}
