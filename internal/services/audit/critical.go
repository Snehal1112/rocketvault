package audit

import (
	"context"
	"errors"
	"fmt"
)

// ErrAuditUnavailable is returned when a critical operation is refused
// because its audit record could not be written.
var ErrAuditUnavailable = errors.New("audit unavailable")

// WithCritical writes an attempt row for ev, runs op only if that write
// succeeded, then records the result as success or failure. It returns
// ErrAuditUnavailable (wrapping the cause) when the attempt cannot be
// written, and op's error otherwise.
func WithCritical(ctx context.Context, svc AuditServiceInterface, ev AuditEvent, op func(context.Context) error) error {
	attempt := ev
	attempt.Outcome = "attempt"
	if err := svc.RecordCritical(ctx, attempt); err != nil {
		return fmt.Errorf("%w: %w", ErrAuditUnavailable, err)
	}

	opErr := op(ctx)

	result := ev
	result.Outcome = "success"
	if opErr != nil {
		result.Outcome = "failure"
	}
	// The result row is best effort; RecordEvent already logs and counts a failure.
	_ = svc.RecordEvent(ctx, result)
	return opErr
}
