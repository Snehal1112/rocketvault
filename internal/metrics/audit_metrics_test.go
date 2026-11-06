package metrics

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
)

// TestPrometheusAuditWriteFailures_CountsPerAction verifies each action gets
// its own counter, so an operator can tell which writes are being lost.
func TestPrometheusAuditWriteFailures_CountsPerAction(t *testing.T) {
	m := NewPrometheusAuditWriteFailures()

	m.Inc("login")
	m.Inc("login")
	m.Inc("grant_role")

	assert.Equal(t, float64(2), testutil.ToFloat64(m.FailureCounter().WithLabelValues("login")))
	assert.Equal(t, float64(1), testutil.ToFloat64(m.FailureCounter().WithLabelValues("grant_role")))
}

// TestNopAuditWriteFailures_DoesNothing pins that the no-op recorder is safe
// to use when metrics are disabled.
func TestNopAuditWriteFailures_DoesNothing(t *testing.T) {
	NewNopAuditWriteFailures().Inc("login")
	// Reaching here without a panic is the assertion.
}
