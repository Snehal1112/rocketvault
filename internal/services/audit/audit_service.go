// Package audit provides the write and read paths for the compliance audit trail.
package audit

import (
	"context"
	"crypto/sha256"
	"fmt"
	"log"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"

	"rocketvault/internal/metrics"
	"rocketvault/internal/repositories"
)

// AuditEvent is the input to RecordEvent.
type AuditEvent struct {
	UserID       string
	Action       string
	Details      string
	ResourceType string
	ResourceID   string
	IPAddress    string
	Outcome      string // "success" | "failure" | "denied" | "warning" | "attempt"
	Source       string // "api" | "cli" | "system"
}

// AuditServiceInterface is the write-path contract for audit events.
// It replaces logging.AuditPersister across the codebase.
type AuditServiceInterface interface {
	// RecordEvent persists one audit event and returns the real error.
	// Fire-and-forget callers ignore it; the service logs and counts it.
	RecordEvent(ctx context.Context, event AuditEvent) error

	// RecordCritical persists one audit event for a critical operation.
	// The caller must not run the operation if it returns an error.
	RecordCritical(ctx context.Context, event AuditEvent) error

	// PersistAudit satisfies logging.AuditPersister for legacy callers.
	PersistAudit(userID, action, details string) error
}

// failureRecorder counts failed audit writes. It defaults to a no-op so
// tests need no Prometheus registry.
var (
	failureMu       sync.RWMutex
	failureRecorder metrics.AuditWriteFailures = metrics.NewNopAuditWriteFailures()
)

// SetWriteFailureRecorder installs the recorder for failed audit writes.
// A nil recorder restores the no-op default.
func SetWriteFailureRecorder(r metrics.AuditWriteFailures) {
	if r == nil {
		r = metrics.NewNopAuditWriteFailures()
	}
	failureMu.Lock()
	defer failureMu.Unlock()
	failureRecorder = r
}

// countFailure records one failed audit write for action.
func countFailure(action string) {
	failureMu.RLock()
	r := failureRecorder
	failureMu.RUnlock()
	r.Inc(action)
}

// AuditService implements AuditServiceInterface with hash-chained writes.
type AuditService struct {
	repo repositories.AuditRepositoryExtended
}

// NewAuditService creates an AuditService backed by repo.
func NewAuditService(repo repositories.AuditRepositoryExtended) AuditServiceInterface {
	return &AuditService{repo: repo}
}

// RecordEvent appends the event to the hash chain. A failure is logged and
// counted, then returned so that callers who care can see it.
func (s *AuditService) RecordEvent(ctx context.Context, event AuditEvent) error {
	if err := s.appendChained(ctx, event); err != nil {
		// Use standard log to avoid a circular dependency with the logging package.
		log.Printf("audit write failed: action=%s: %v", event.Action, err)
		countFailure(event.Action)
		return err
	}
	return nil
}

// RecordCritical appends the event to the hash chain and returns any failure.
func (s *AuditService) RecordCritical(ctx context.Context, event AuditEvent) error {
	if err := s.appendChained(ctx, event); err != nil {
		// The cause stays in server logs; callers return a generic error.
		log.Printf("critical audit write failed: action=%s: %v", event.Action, err)
		countFailure(event.Action)
		return err
	}
	return nil
}

// appendChained writes one row whose hash covers the previous hash, the
// sequence number, the database time and the event fields.
func (s *AuditService) appendChained(ctx context.Context, event AuditEvent) error {
	return s.repo.AppendChained(ctx, func(nextSeq int64, prevHash string, now time.Time) repositories.AuditLog {
		return repositories.AuditLog{
			ID:           uuid.New().String(),
			UserID:       event.UserID,
			Action:       event.Action,
			Details:      event.Details,
			ResourceType: event.ResourceType,
			ResourceID:   event.ResourceID,
			IPAddress:    event.IPAddress,
			Outcome:      event.Outcome,
			Source:       event.Source,
			PrevHash:     computeChainHash(prevHash, nextSeq, now, event),
		}
	})
}

// PersistAudit satisfies logging.AuditPersister for legacy callers. It takes
// the outcome from the status token in details.
func (s *AuditService) PersistAudit(userID, action, details string) error {
	return s.RecordEvent(context.Background(), AuditEvent{
		UserID:  userID,
		Action:  action,
		Details: details,
		Outcome: outcomeFromDetails(details),
		Source:  "system",
	})
}

// outcomeFromDetails maps the logger's status=<value> token to an outcome.
func outcomeFromDetails(details string) string {
	for _, field := range strings.Fields(details) {
		status, ok := strings.CutPrefix(field, "status=")
		if !ok {
			continue
		}
		switch status {
		case "success":
			return "success"
		case "failure", "failed", "error":
			return "failure"
		case "denied":
			return "denied"
		default:
			return "warning"
		}
	}
	return "warning"
}

// computeChainHash returns
// SHA-256(prevHash|seq|timestamp|userID|action|details|resourceType+resourceID|outcome).
func computeChainHash(prevHash string, seq int64, ts time.Time, e AuditEvent) string {
	raw := fmt.Sprintf("%s|%d|%s|%s|%s|%s|%s|%s",
		prevHash, seq, ts.Format(time.RFC3339Nano),
		e.UserID, e.Action, e.Details,
		e.ResourceType+e.ResourceID, e.Outcome)
	sum := sha256.Sum256([]byte(raw))
	return fmt.Sprintf("%x", sum)
}

// computeHash is the legacy formula without seq, kept to verify old rows.
// It returns SHA-256(prevHash|timestamp|userID|action|details|resourceType+resourceID|outcome).
func computeHash(prevHash string, ts time.Time, e AuditEvent) string {
	raw := fmt.Sprintf("%s|%s|%s|%s|%s|%s|%s",
		prevHash, ts.Format(time.RFC3339Nano),
		e.UserID, e.Action, e.Details,
		e.ResourceType+e.ResourceID, e.Outcome)
	sum := sha256.Sum256([]byte(raw))
	return fmt.Sprintf("%x", sum)
}
