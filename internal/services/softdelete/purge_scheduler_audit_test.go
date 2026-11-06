package softdelete

// Audit-first tests: the scheduler must not purge a table's expired rows
// unless the critical attempt row for that table was written first.

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	auditServices "rocketvault/internal/services/audit"
)

// fakeSchedulerAudit records calls in order. onCritical, when set, runs
// before each critical write so a test can look at the database then.
type fakeSchedulerAudit struct {
	criticalErr error
	onCritical  func(ev auditServices.AuditEvent)
	calls       []string
	critical    []auditServices.AuditEvent
	events      []auditServices.AuditEvent
}

func (f *fakeSchedulerAudit) RecordEvent(_ context.Context, ev auditServices.AuditEvent) error {
	f.calls = append(f.calls, ev.Action+":"+ev.Outcome)
	f.events = append(f.events, ev)
	return nil
}

func (f *fakeSchedulerAudit) RecordCritical(_ context.Context, ev auditServices.AuditEvent) error {
	if f.onCritical != nil {
		f.onCritical(ev)
	}
	f.calls = append(f.calls, ev.Action+":"+ev.Outcome)
	f.critical = append(f.critical, ev)
	return f.criticalErr
}

func (f *fakeSchedulerAudit) PersistAudit(_, _, _ string) error { return nil }

// seedExpired inserts one expired, unprotected row into each named table.
func seedExpired(t *testing.T, db *sql.DB, tables ...string) {
	t.Helper()
	expired := time.Now().AddDate(0, 0, -60).Format("2006-01-02 15:04:05")
	for _, table := range tables {
		_, err := db.Exec(fmt.Sprintf(`INSERT INTO %s (id, deleted_at, purge_protection) VALUES (?, ?, ?)`, table),
			"expired-"+table, expired, false)
		require.NoError(t, err)
	}
}

func rowCount(t *testing.T, db *sql.DB, table string) int {
	t.Helper()
	var n int
	require.NoError(t, db.QueryRow(fmt.Sprintf(`SELECT COUNT(*) FROM %s`, table)).Scan(&n))
	return n
}

func TestPurgeExpired_AuditDownDeletesNothing(t *testing.T) {
	rawDB := newTestDB(t)
	createPurgeTables(rawDB)
	seedExpired(t, rawDB, "secrets", "keys", "certificates")
	audit := &fakeSchedulerAudit{criticalErr: errors.New("pq: disk full on audit_logs")}
	s := NewPurgeScheduler(newTestConn(t, rawDB), testConfig(), testLogger(), nil, audit)

	s.purgeExpired(context.Background())

	for _, table := range []string{"secrets", "keys", "certificates"} {
		assert.Equal(t, 1, rowCount(t, rawDB, table), "%s rows must stay soft-deleted", table)
	}
	assert.Len(t, audit.critical, 3, "every table is still tried")
	assert.Empty(t, audit.events, "no result row for a skipped table")
}

func TestPurgeExpired_WritesAttemptBeforeDelete(t *testing.T) {
	rawDB := newTestDB(t)
	createPurgeTables(rawDB)
	seedExpired(t, rawDB, "keys")
	audit := &fakeSchedulerAudit{}
	audit.onCritical = func(ev auditServices.AuditEvent) {
		assert.Equal(t, 1, rowCount(t, rawDB, ev.ResourceType), "the attempt must precede the delete")
	}
	s := NewPurgeScheduler(newTestConn(t, rawDB), testConfig(), testLogger(), nil, audit)

	s.purgeExpired(context.Background())

	assert.Equal(t, 0, rowCount(t, rawDB, "keys"))
	assert.Equal(t, []string{"auto_purge_keys:attempt", "auto_purge_keys:success"}, audit.calls,
		"tables with nothing eligible write no audit rows")
	attempt := audit.critical[0]
	assert.Equal(t, "system", attempt.UserID)
	assert.Equal(t, "keys", attempt.ResourceType)
	assert.Equal(t, "system", attempt.Source)
	assert.Contains(t, attempt.Details, "cutoff=")
	assert.Contains(t, audit.events[0].Details, "rows_deleted=1")
}

func TestPurgeExpired_NothingEligibleWritesNoAudit(t *testing.T) {
	rawDB := newTestDB(t)
	createPurgeTables(rawDB)
	// A recent soft-delete and a protected expired row are both ineligible.
	recent := time.Now().AddDate(0, 0, -5).Format("2006-01-02 15:04:05")
	expired := time.Now().AddDate(0, 0, -60).Format("2006-01-02 15:04:05")
	_, err := rawDB.Exec(`INSERT INTO secrets (id, deleted_at, purge_protection) VALUES ('r', ?, FALSE), ('p', ?, TRUE)`, recent, expired)
	require.NoError(t, err)
	audit := &fakeSchedulerAudit{}
	s := NewPurgeScheduler(newTestConn(t, rawDB), testConfig(), testLogger(), nil, audit)

	s.purgeExpired(context.Background())

	assert.Empty(t, audit.calls)
	assert.Equal(t, 2, rowCount(t, rawDB, "secrets"))
}
