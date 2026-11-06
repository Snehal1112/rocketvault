package keys

import (
	"context"
	"encoding/json"

	"github.com/google/uuid"

	"rocketvault/internal/logging"
	auditServices "rocketvault/internal/services/audit"
)

// systemActor names the actor of a key operation with no acting principal,
// such as a scheduled rotation.
const systemActor = "system"

// keyAuditActor returns the audit actor for actorID, or systemActor for uuid.Nil.
func keyAuditActor(actorID uuid.UUID) string {
	if actorID == uuid.Nil {
		return systemActor
	}
	return actorID.String()
}

// keyCriticalEvent builds the critical audit event for action on keyID by
// actorID. Details, when given, are stored as JSON.
func keyCriticalEvent(actorID uuid.UUID, action string, keyID uuid.UUID, details map[string]any) auditServices.AuditEvent {
	ev := auditServices.AuditEvent{
		UserID: keyAuditActor(actorID), Action: action,
		ResourceType: "key", ResourceID: keyID.String(), Source: "system",
	}
	if len(details) > 0 {
		if b, err := json.Marshal(details); err == nil {
			ev.Details = string(b)
		}
	}
	return ev
}

// runKeyCritical runs op after a critical attempt row for ev, and records its
// result. With no audit service wired (tests only) it runs op directly. A
// failed attempt write returns audit.ErrAuditUnavailable and op does not run.
func runKeyCritical(ctx context.Context, svc auditServices.AuditServiceInterface, ev auditServices.AuditEvent, op func(context.Context) error) error {
	if svc == nil {
		return op(ctx)
	}
	return auditServices.WithCritical(ctx, svc, ev, op)
}

// logLegacySuccess writes the legacy success log row when no audit service is
// wired. With one wired, the WithCritical result row replaces it.
func logLegacySuccess(svc auditServices.AuditServiceInterface, log *logging.Logger, actor, action, message string) {
	if svc == nil && log != nil {
		log.LogAuditInfo(actor, action, "success", message)
	}
}
