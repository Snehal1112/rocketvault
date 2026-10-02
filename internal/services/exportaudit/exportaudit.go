// Package exportaudit classifies certificate and key export failures and
// records one structured audit event per export attempt. The HTTP export
// handlers and the CLI export commands both use it, so the two entry points
// share one set of fixed messages and reasons and one event shape.
package exportaudit

import (
	"context"
	"encoding/json"
	"errors"

	auditServices "rocketvault/internal/services/audit"
	certServices "rocketvault/internal/services/certificates"
	keyServices "rocketvault/internal/services/keys"
	"rocketvault/model"
)

// Kind is the transport-neutral class of an export failure. The API maps it
// onto an HTTP status; the CLI uses it to decide what to show.
type Kind int

// Export failure kinds.
const (
	KindBadRequest Kind = iota + 1
	KindForbidden
	KindNotExportable
	KindNotFound
	KindDisabled
	KindInternal
)

// Failure is one classified export failure. Message is safe to show the
// caller. Reason is a fixed phrase for the audit trail and never carries raw
// error text. Name and KeyAlgorithm are set only on a refusal.
type Failure struct {
	Kind         Kind
	Code         string
	Message      string
	Reason       string
	Name         string
	KeyAlgorithm string
}

// BadRequest is the failure for malformed input. message must be a fixed
// phrase that never includes a password; it is both shown and audited.
func BadRequest(message string) Failure {
	return Failure{Kind: KindBadRequest, Code: "bad_request", Message: message, Reason: message}
}

// Internal is the generic internal failure. reason goes to the audit trail;
// the caller only ever sees the fixed message.
func Internal(reason string) Failure {
	return Failure{Kind: KindInternal, Code: "internal_error", Message: "internal server error", Reason: reason}
}

// Forbidden is the failure for an authorization denial on a path without
// PolicyMiddleware, such as the CLI. reason must be a fixed phrase.
func Forbidden(reason string) Failure {
	return Failure{Kind: KindForbidden, Code: "forbidden", Message: reason, Reason: reason}
}

// Classify maps a certificate or key service error onto a Failure. resource
// is "certificate" or "key". Unknown errors become a generic internal
// failure. A chain failure is also internal, because its error text names a
// CA id that may belong to another vault.
func Classify(err error, resource string) Failure {
	var refusal *model.ExportRefusedError
	switch {
	case errors.As(err, &refusal):
		return Failure{Kind: KindNotExportable, Code: resource + "_not_exportable", Message: refusal.Error(),
			Reason: refusal.Reason, Name: refusal.Name, KeyAlgorithm: refusal.KeyAlgorithm}
	case errors.Is(err, model.ErrInvalidExportRequest):
		f := BadRequest(err.Error())
		f.Reason = "invalid export request"
		return f
	case errors.Is(err, certServices.ErrCertNotFound), errors.Is(err, model.ErrCertificateVersionNotFound):
		return Failure{Kind: KindNotFound, Code: "not_found", Message: "certificate or version not found",
			Reason: "certificate or version not found"}
	case errors.Is(err, keyServices.ErrKeyNotFound), errors.Is(err, model.ErrKeyVersionNotFound):
		return Failure{Kind: KindNotFound, Code: "not_found", Message: "key or version not found",
			Reason: "key or version not found"}
	case errors.Is(err, certServices.ErrCertLifecycleDenied):
		return Failure{Kind: KindDisabled, Code: "certificate_disabled",
			Message: "the certificate or this version is disabled or outside its valid time window",
			Reason:  "certificate or version disabled"}
	case errors.Is(err, keyServices.ErrKeyLifecycleDenied):
		return Failure{Kind: KindDisabled, Code: "key_disabled",
			Message: "the key is disabled or outside its valid time window", Reason: "key disabled"}
	case errors.Is(err, certServices.ErrCertificateChainUnavailable):
		return Internal("certificate chain unavailable")
	case errors.Is(err, certServices.ErrCertVersioningUnavailable):
		return Internal("certificate versioning unavailable")
	}
	return Internal("internal failure")
}

// AuditableFormat returns format when it is a known export format and
// "invalid" otherwise, so arbitrary caller text never reaches the audit trail.
func AuditableFormat(format string) string {
	switch format {
	case model.ExportFormatPEM, model.ExportFormatPKCS12:
		return format
	}
	return "invalid"
}

// Attempt is one export attempt as the audit trail records it. It holds no
// material and no password by construction. Reason is a fixed phrase from a
// Failure, never raw error text.
type Attempt struct {
	UserID       string
	ResourceType string // "certificate" or "key".
	ResourceID   string
	VaultID      string
	Name         string
	Version      int
	Format       string
	Outcome      string // "success" or "failure".
	Code         string
	Reason       string
	IPAddress    string
	Source       string // "api" or "cli".
}

// Event builds the audit event for a. Details carries only the fixed fields
// vault_id, name, version, format, code and reason.
func Event(a Attempt) auditServices.AuditEvent {
	details, _ := json.Marshal(map[string]any{
		"vault_id": a.VaultID, "name": a.Name, "version": a.Version, "format": a.Format, "code": a.Code, "reason": a.Reason,
	})
	return auditServices.AuditEvent{
		UserID:       a.UserID,
		Action:       "export_" + a.ResourceType,
		Details:      string(details),
		ResourceType: a.ResourceType,
		ResourceID:   a.ResourceID,
		IPAddress:    a.IPAddress,
		Outcome:      a.Outcome,
		Source:       a.Source,
	}
}

// Record writes one audit event for a. A nil service is tolerated, and an
// audit failure never blocks the caller.
func Record(ctx context.Context, svc auditServices.AuditServiceInterface, a Attempt) {
	if svc == nil {
		return
	}
	_ = svc.RecordEvent(ctx, Event(a))
}
