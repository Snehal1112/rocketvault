package signing

// Audit-first tests: the self_pki provider must not store a newly generated
// JWT signing key unless its critical attempt row was written first.

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	auditServices "rocketvault/internal/services/audit"
)

// fakeSigningAudit records calls in order and can fail critical writes.
type fakeSigningAudit struct {
	mu          sync.Mutex
	criticalErr error
	repo        *mockKeyRepo
	calls       []string
	critical    []auditServices.AuditEvent
}

func (f *fakeSigningAudit) RecordEvent(_ context.Context, ev auditServices.AuditEvent) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, "event:"+ev.Outcome)
	return nil
}

func (f *fakeSigningAudit) RecordCritical(_ context.Context, ev auditServices.AuditEvent) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.repo != nil && len(f.repo.created) > 0 {
		f.calls = append(f.calls, "stored-before-attempt")
	}
	f.calls = append(f.calls, "critical:"+ev.Outcome)
	f.critical = append(f.critical, ev)
	return f.criticalErr
}

func (f *fakeSigningAudit) PersistAudit(_, _, _ string) error { return nil }

func TestSelfPKI_GenerateAuditFailureStoresNoKey(t *testing.T) {
	repo := &mockKeyRepo{}
	audit := &fakeSigningAudit{criticalErr: errors.New("pq: disk full on audit_logs")}

	p, err := NewSelfPKIProvider(&mockCryptoService{}, repo, "", audit)

	require.Error(t, err)
	assert.Nil(t, p, "startup fails rather than run on an unaudited key")
	assert.ErrorIs(t, err, auditServices.ErrAuditUnavailable)
	assert.NotContains(t, err.Error(), "disk full")
	assert.Empty(t, repo.created, "no signing key may be stored")
	require.Len(t, audit.critical, 1)
	ev := audit.critical[0]
	assert.Equal(t, "signing_key_generate", ev.Action)
	assert.Equal(t, "attempt", ev.Outcome)
	assert.Equal(t, "system", ev.UserID)
	assert.Equal(t, "signing_key", ev.ResourceType)
	assert.NotEmpty(t, ev.ResourceID, "the row names the new kid")
}

func TestSelfPKI_GenerateWritesAttemptBeforeStore(t *testing.T) {
	repo := &mockKeyRepo{}
	audit := &fakeSigningAudit{repo: repo}

	p, err := NewSelfPKIProvider(&mockCryptoService{}, repo, "", audit)

	require.NoError(t, err)
	assert.Equal(t, []string{"critical:attempt", "event:success"}, audit.calls)
	require.Len(t, repo.created, 1)
	assert.Equal(t, p.KeyID(), audit.critical[0].ResourceID)
}

// TestSelfPKI_LoadWritesNoCriticalRow pins that loading an existing key is
// not a mutation and starts even with audit down.
func TestSelfPKI_LoadWritesNoCriticalRow(t *testing.T) {
	crypto := &mockCryptoService{}
	seed := &mockKeyRepo{}
	_, err := NewSelfPKIProvider(crypto, seed, "", nil)
	require.NoError(t, err)
	repo := &mockKeyRepo{keys: seed.created}
	audit := &fakeSigningAudit{criticalErr: errors.New("down")}

	_, err = NewSelfPKIProvider(crypto, repo, "", audit)

	require.NoError(t, err)
	assert.Empty(t, audit.critical)
	assert.Empty(t, repo.created)
}
