package audit_test

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	auditSvc "rocketvault/internal/services/audit"
)

// fakeAuditService records the events it receives and can fail critical writes.
type fakeAuditService struct {
	criticalErr error
	critical    []auditSvc.AuditEvent
	events      []auditSvc.AuditEvent
}

func (f *fakeAuditService) RecordEvent(_ context.Context, ev auditSvc.AuditEvent) error {
	f.events = append(f.events, ev)
	return nil
}

func (f *fakeAuditService) RecordCritical(_ context.Context, ev auditSvc.AuditEvent) error {
	f.critical = append(f.critical, ev)
	return f.criticalErr
}

func (f *fakeAuditService) PersistAudit(string, string, string) error { return nil }

func TestWithCritical_AuditFailureBlocksOp(t *testing.T) {
	cause := errors.New("db down")
	svc := &fakeAuditService{criticalErr: cause}
	called := false

	err := auditSvc.WithCritical(context.Background(), svc, auditSvc.AuditEvent{Action: "grant_role"},
		func(context.Context) error {
			called = true
			return nil
		})

	require.Error(t, err)
	assert.False(t, called)
	assert.True(t, errors.Is(err, auditSvc.ErrAuditUnavailable))
	assert.True(t, errors.Is(err, cause))
	assert.Equal(t, "audit unavailable", auditSvc.ErrAuditUnavailable.Error())
	assert.Empty(t, svc.events)
}

func TestWithCritical_RecordsAttemptThenResult(t *testing.T) {
	ev := auditSvc.AuditEvent{UserID: "u", Action: "grant_role", ResourceID: "r1", Source: "api"}

	t.Run("success", func(t *testing.T) {
		svc := &fakeAuditService{}
		called := false
		err := auditSvc.WithCritical(context.Background(), svc, ev, func(context.Context) error {
			called = true
			require.Len(t, svc.critical, 1, "attempt must be written before the op runs")
			return nil
		})
		require.NoError(t, err)
		assert.True(t, called)
		require.Len(t, svc.critical, 1)
		assert.Equal(t, "attempt", svc.critical[0].Outcome)
		assert.Equal(t, "grant_role", svc.critical[0].Action)
		require.Len(t, svc.events, 1)
		assert.Equal(t, "success", svc.events[0].Outcome)
		assert.Equal(t, "r1", svc.events[0].ResourceID)
	})

	t.Run("op failure", func(t *testing.T) {
		svc := &fakeAuditService{}
		opErr := errors.New("grant failed")
		err := auditSvc.WithCritical(context.Background(), svc, ev, func(context.Context) error {
			return opErr
		})
		require.ErrorIs(t, err, opErr)
		assert.False(t, errors.Is(err, auditSvc.ErrAuditUnavailable))
		require.Len(t, svc.critical, 1)
		assert.Equal(t, "attempt", svc.critical[0].Outcome)
		require.Len(t, svc.events, 1)
		assert.Equal(t, "failure", svc.events[0].Outcome)
	})
}
