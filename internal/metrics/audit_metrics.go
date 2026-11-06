package metrics

import "github.com/prometheus/client_golang/prometheus"

// AuditWriteFailures counts audit rows that could not be written, by action.
type AuditWriteFailures interface {
	// Inc counts one failed audit write for action.
	Inc(action string)
}

// auditWriteFailuresOpts is the single definition of the counter descriptor.
var auditWriteFailuresOpts = prometheus.CounterOpts{
	Name: "rocketvault_audit_write_failures_total",
	Help: "Audit events that could not be persisted, by action.",
}

// auditWriteFailuresLabels are the label names for the counter.
var auditWriteFailuresLabels = []string{"action"}

// PrometheusAuditWriteFailures counts failures in a Prometheus CounterVec.
type PrometheusAuditWriteFailures struct {
	failures *prometheus.CounterVec
}

// NewPrometheusAuditWriteFailures creates a recorder on a new (non-default)
// Prometheus registry so tests do not conflict.
func NewPrometheusAuditWriteFailures() *PrometheusAuditWriteFailures {
	reg := prometheus.NewRegistry()
	c := prometheus.NewCounterVec(auditWriteFailuresOpts, auditWriteFailuresLabels)
	reg.MustRegister(c)
	return &PrometheusAuditWriteFailures{failures: c}
}

// NewDefaultPrometheusAuditWriteFailures registers the counter on the default
// Prometheus registry, so it is exported by the /metrics endpoint. Safe to call
// more than once: it returns the existing collector if already registered.
func NewDefaultPrometheusAuditWriteFailures() *PrometheusAuditWriteFailures {
	c := prometheus.NewCounterVec(auditWriteFailuresOpts, auditWriteFailuresLabels)
	if err := prometheus.Register(c); err != nil {
		if are, ok := err.(prometheus.AlreadyRegisteredError); ok {
			c = are.ExistingCollector.(*prometheus.CounterVec)
		} else {
			panic(err)
		}
	}
	return &PrometheusAuditWriteFailures{failures: c}
}

// Inc increments the counter for action.
func (p *PrometheusAuditWriteFailures) Inc(action string) {
	p.failures.WithLabelValues(action).Inc()
}

// FailureCounter exposes the counter for assertions in tests.
func (p *PrometheusAuditWriteFailures) FailureCounter() *prometheus.CounterVec {
	return p.failures
}

// NopAuditWriteFailures is a no-op recorder used when metrics are disabled.
type NopAuditWriteFailures struct{}

// NewNopAuditWriteFailures returns a NopAuditWriteFailures.
func NewNopAuditWriteFailures() AuditWriteFailures { return &NopAuditWriteFailures{} }

// Inc does nothing.
func (n *NopAuditWriteFailures) Inc(_ string) {}
