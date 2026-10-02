// Package logtest provides an in-memory audit recorder for tests that assert
// who an audit entry was attributed to. It imports only internal/logging, so
// any test package can use it without an import cycle.
package logtest

import (
	"strings"
	"sync"

	"github.com/sirupsen/logrus"

	"rocketvault/internal/logging"
)

// Record is one audit row captured by Recorder.
type Record struct {
	UserID  string
	Action  string
	Details string
}

// Recorder is a logging.AuditPersister that keeps every row in memory.
type Recorder struct {
	mu      sync.Mutex
	records []Record
}

// PersistAudit implements logging.AuditPersister.
func (r *Recorder) PersistAudit(userID, action, details string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.records = append(r.records, Record{UserID: userID, Action: action, Details: details})
	return nil
}

// Find returns the first row for action whose details carry status=<status>.
func (r *Recorder) Find(action, status string) (Record, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, rec := range r.records {
		if rec.Action == action && strings.Contains(rec.Details, "status="+status) {
			return rec, true
		}
	}
	return Record{}, false
}

// NewLogger returns a quiet logger whose audit rows go to a new Recorder.
func NewLogger() (*logging.Logger, *Recorder) {
	l := logrus.New()
	l.SetLevel(logrus.PanicLevel)
	logger := logging.WrapLogrus(l)
	rec := &Recorder{}
	logger.SetAuditPersister(rec)
	return logger, rec
}
