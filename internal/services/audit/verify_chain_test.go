package audit_test

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	rvdb "rocketvault/internal/db"
	"rocketvault/internal/repositories"
	auditSvc "rocketvault/internal/services/audit"
)

var verifyBase = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

func verifyEvent() auditSvc.AuditEvent {
	return auditSvc.AuditEvent{UserID: "u", Action: "act", Details: "d", Outcome: "success", ResourceType: "secret", ResourceID: "r"}
}

func toLog(e auditSvc.AuditEvent, ts time.Time, hash string) repositories.AuditLog {
	return repositories.AuditLog{
		UserID: e.UserID, Action: e.Action, Details: e.Details, ResourceType: e.ResourceType,
		ResourceID: e.ResourceID, Outcome: e.Outcome, Timestamp: ts, PrevHash: hash,
	}
}

// legacyRow builds a legacy row (no seq) chained after prev.
func legacyRow(i int, prev string) repositories.AuditLog {
	ts := verifyBase.Add(time.Duration(i) * time.Second)
	e := verifyEvent()
	return toLog(e, ts, auditSvc.ComputeHash(prev, ts, e))
}

// chainedRow builds a chained row with the given seq after prev.
func chainedRow(i int, seq int64, prev string) repositories.AuditLog {
	ts := verifyBase.Add(time.Duration(i) * time.Second)
	e := verifyEvent()
	l := toLog(e, ts, auditSvc.ComputeChainHash(prev, seq, ts, e))
	l.Seq = &seq
	return l
}

// newestFirst reverses an oldest-first slice, as QueryAuditLogs returns rows.
func newestFirst(in ...repositories.AuditLog) []repositories.AuditLog {
	out := make([]repositories.AuditLog, len(in))
	for i, l := range in {
		out[len(in)-1-i] = l
	}
	return out
}

func int64p(v int64) *int64 { return &v }

func TestVerifyChain_ValidChainedPage(t *testing.T) {
	r1 := chainedRow(1, 1, "")
	r2 := chainedRow(2, 2, r1.PrevHash)
	r3 := chainedRow(3, 3, r2.PrevHash)
	res := auditSvc.VerifyChain(newestFirst(r1, r2, r3))
	assert.True(t, res.OK)
	assert.Nil(t, res.BreakSeq)
	assert.Empty(t, res.BreakReason)
}

func TestVerifyChain_Gap(t *testing.T) {
	r3 := chainedRow(3, 3, "")
	r5 := chainedRow(5, 5, r3.PrevHash)
	res := auditSvc.VerifyChain(newestFirst(r3, r5))
	assert.False(t, res.OK)
	assert.Equal(t, int64p(5), res.BreakSeq)
	assert.Equal(t, "gap", res.BreakReason)
}

func TestVerifyChain_HashMismatch(t *testing.T) {
	r1 := chainedRow(1, 1, "")
	r2 := chainedRow(2, 2, r1.PrevHash)
	r3 := chainedRow(3, 3, r2.PrevHash)
	r2.Details = "tampered"
	res := auditSvc.VerifyChain(newestFirst(r1, r2, r3))
	assert.False(t, res.OK)
	assert.Equal(t, int64p(2), res.BreakSeq)
	assert.Equal(t, "hash_mismatch", res.BreakReason)
}

func TestVerifyChain_LegacyToChainedBoundaryValid(t *testing.T) {
	l1 := legacyRow(1, "")
	l2 := legacyRow(2, l1.PrevHash)
	c1 := chainedRow(3, 1, l2.PrevHash)
	c2 := chainedRow(4, 2, c1.PrevHash)
	res := auditSvc.VerifyChain(newestFirst(l1, l2, c1, c2))
	assert.True(t, res.OK)
}

func TestVerifyChain_BoundaryGap(t *testing.T) {
	l1 := legacyRow(1, "")
	c2 := chainedRow(2, 2, l1.PrevHash)
	res := auditSvc.VerifyChain(newestFirst(l1, c2))
	assert.False(t, res.OK)
	assert.Equal(t, int64p(2), res.BreakSeq)
	assert.Equal(t, "gap", res.BreakReason)
}

func TestVerifyChain_PrunedPrefixOK(t *testing.T) {
	r40 := chainedRow(40, 40, "pruned-older-hash")
	r41 := chainedRow(41, 41, r40.PrevHash)
	res := auditSvc.VerifyChain(newestFirst(r40, r41))
	assert.True(t, res.OK)
}

func TestVerifyChain_AllLegacy(t *testing.T) {
	l1 := legacyRow(1, "")
	l2 := legacyRow(2, l1.PrevHash)
	l3 := legacyRow(3, l2.PrevHash)
	assert.True(t, auditSvc.VerifyChain(newestFirst(l1, l2, l3)).OK)

	l2.Details = "tampered"
	res := auditSvc.VerifyChain(newestFirst(l1, l2, l3))
	assert.False(t, res.OK)
	assert.Nil(t, res.BreakSeq)
	assert.Equal(t, "hash_mismatch", res.BreakReason)
}

func TestComplianceReportService_QueryLogs_ChainedRoundTrip(t *testing.T) {
	db := openTestDB(t)
	repo := repositories.NewAuditRepository(rvdb.NewConn(db, rvdb.SQLite))
	svc := auditSvc.NewAuditService(repo)
	compSvc := auditSvc.NewComplianceReportService(repo, nil)

	for _, a := range []string{"a", "b", "c"} {
		require.NoError(t, svc.RecordEvent(context.Background(), auditSvc.AuditEvent{
			UserID: "u1", Action: a, Outcome: "success", Source: "api",
		}))
	}
	logs, _, res, err := compSvc.QueryLogs(context.Background(), repositories.AuditFilter{Limit: 10})
	require.NoError(t, err)
	require.Len(t, logs, 3)
	assert.True(t, res.OK, "break: %v %s", res.BreakSeq, res.BreakReason)
}
