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

// RecordAttempt writes only the attempt row for ev, for a caller whose result
// row is written elsewhere. It returns an error matching ErrAuditUnavailable
// (and the cause) when the write fails; the caller must then not proceed.
func RecordAttempt(ctx context.Context, svc AuditServiceInterface, ev AuditEvent) error {
	ev.Outcome = "attempt"
	if err := svc.RecordCritical(ctx, ev); err != nil {
		return &auditUnavailableError{cause: err}
	}
	return nil
}

// WithCritical writes an attempt row for ev, runs op only if that write
// succeeded, then records the result as success or failure. It returns an
// error matching ErrAuditUnavailable (and the cause) when the attempt cannot
// be written, and op's error otherwise.
func WithCritical(ctx context.Context, svc AuditServiceInterface, ev AuditEvent, op func(context.Context) error) error {
	if err := RecordAttempt(ctx, svc, ev); err != nil {
		return err
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
