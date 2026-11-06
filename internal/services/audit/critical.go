package audit

import (
	"context"
	"errors"
)

// ErrAuditUnavailable is returned when a critical operation is refused
// because its audit record could not be written.
var ErrAuditUnavailable = errors.New("audit unavailable")

// auditUnavailableError matches both ErrAuditUnavailable and its cause, but
// its message never includes the cause, so handlers can echo it safely.
type auditUnavailableError struct {
	cause error
}

// Error returns the public message only.
func (e *auditUnavailableError) Error() string { return ErrAuditUnavailable.Error() }

// Unwrap exposes both the sentinel and the cause to errors.Is and errors.As.
func (e *auditUnavailableError) Unwrap() []error { return []error{ErrAuditUnavailable, e.cause} }

// WithCritical writes an attempt row for ev, runs op only if that write
// succeeded, then records the result as success or failure. It returns an
// error matching ErrAuditUnavailable (and the cause) when the attempt cannot
// be written, and op's error otherwise.
func WithCritical(ctx context.Context, svc AuditServiceInterface, ev AuditEvent, op func(context.Context) error) error {
	attempt := ev
	attempt.Outcome = "attempt"
	if err := svc.RecordCritical(ctx, attempt); err != nil {
		return &auditUnavailableError{cause: err}
	}

	opErr := op(ctx)

	result := ev
	result.Outcome = "success"
	if opErr != nil {
		result.Outcome = "failure"
	}
	// The result row is best effort; RecordEvent already logs and counts a failure.
	// It must survive a client that disconnects after op has committed.
	_ = svc.RecordEvent(context.WithoutCancel(ctx), result)
	return opErr
}
