package api

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"time"

	"github.com/google/uuid"

	"rocketvault/internal/container"
	"rocketvault/internal/middleware"
	auditSvc "rocketvault/internal/services/audit"
	certServices "rocketvault/internal/services/certificates"
	keyservices "rocketvault/internal/services/keys"
	"rocketvault/model"
)

// maxExportRequestBytes bounds an export request body. The body is a few
// short fields, so anything larger is malformed.
const maxExportRequestBytes = 16 << 10

// exportErrorBody is the R6 error shape used only by the export routes. The
// rest of the API keeps its flat body.
type exportErrorBody struct {
	Error exportErrorDetail `json:"error"`
}

// exportErrorDetail is the inner R6 object. KeyAlgorithm is set only on a
// not-exportable refusal, so a client can show why.
type exportErrorDetail struct {
	Code         string `json:"code"`
	Message      string `json:"message"`
	KeyAlgorithm string `json:"key_algorithm,omitempty"`
}

// exportFailure is one mapped export failure: the HTTP status, the R6 code
// and message, and what the audit event should record. Reason is a fixed
// phrase for the audit trail; it never carries raw error text. cause is the
// underlying error of a 500; it goes to the server log only.
type exportFailure struct {
	Status       int
	Code         string
	Message      string
	KeyAlgorithm string
	Name         string
	Reason       string
	cause        error
}

// logExportFailure writes the cause of an export 500 to the server log, so
// an operator can diagnose it. It logs only the fixed reason and the error
// text, never the request body or any exported material. Other statuses are
// not logged here, because the audit event already explains them.
func logExportFailure(c *Context, resource string, f exportFailure) {
	if f.Status != http.StatusInternalServerError || c == nil || c.Logger == nil {
		return
	}
	entry := c.Logger.WithField("operation", "export_"+resource).WithField("step", f.Reason)
	if f.cause != nil {
		entry = entry.WithError(f.cause)
	}
	entry.Error("export failed")
}

// setExportHeaders forbids every cache between the vault and the client.
// It must run before the first write.
func setExportHeaders(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
}

// writeExportError writes f as an R6 body.
func writeExportError(w http.ResponseWriter, f exportFailure) {
	writeJSONStatus(w, f.Status, exportErrorBody{Error: exportErrorDetail{Code: f.Code, Message: f.Message, KeyAlgorithm: f.KeyAlgorithm}})
}

// badExportRequest is the 400 for a malformed request. message must be a
// fixed phrase that never includes the password.
func badExportRequest(message string) exportFailure {
	return exportFailure{Status: http.StatusBadRequest, Code: "bad_request", Message: message, Reason: message}
}

// exportInternalFailure is the generic 500. reason goes to the audit trail
// and the server log, cause to the server log only; the client always sees
// the same fixed message.
func exportInternalFailure(reason string, cause error) exportFailure {
	return exportFailure{Status: http.StatusInternalServerError, Code: "internal_error", Message: "internal server error", Reason: reason, cause: cause}
}

// exportFailureFor maps a certificate or key service error onto an export
// failure. resource is "certificate" or "key". Unknown errors become a
// generic 500 whose message carries no detail. A chain failure is also a
// generic 500, because its error text names a CA id that may belong to
// another vault.
func exportFailureFor(err error, resource string) exportFailure {
	var refusal *model.ExportRefusedError
	switch {
	case errors.As(err, &refusal):
		return exportFailure{Status: http.StatusForbidden, Code: resource + "_not_exportable",
			Message: refusal.Error(), KeyAlgorithm: refusal.KeyAlgorithm, Name: refusal.Name, Reason: refusal.Reason}
	case errors.Is(err, model.ErrInvalidExportRequest):
		f := badExportRequest(err.Error())
		f.Reason = "invalid export request"
		return f
	case errors.Is(err, certServices.ErrCertNotFound), errors.Is(err, model.ErrCertificateVersionNotFound):
		return exportFailure{Status: http.StatusNotFound, Code: "not_found", Message: "certificate or version not found",
			Reason: "certificate or version not found"}
	case errors.Is(err, keyservices.ErrKeyNotFound), errors.Is(err, model.ErrKeyVersionNotFound):
		return exportFailure{Status: http.StatusNotFound, Code: "not_found", Message: "key or version not found",
			Reason: "key or version not found"}
	case errors.Is(err, certServices.ErrCertLifecycleDenied):
		return exportFailure{Status: http.StatusConflict, Code: "certificate_disabled",
			Message: "the certificate or this version is disabled or outside its valid time window",
			Reason:  "certificate or version disabled"}
	case errors.Is(err, keyservices.ErrKeyLifecycleDenied):
		return exportFailure{Status: http.StatusConflict, Code: "key_disabled",
			Message: "the key is disabled or outside its valid time window", Reason: "key disabled"}
	case errors.Is(err, certServices.ErrCertificateChainUnavailable):
		return exportInternalFailure("certificate chain unavailable", err)
	case errors.Is(err, certServices.ErrCertVersioningUnavailable):
		return exportInternalFailure("certificate versioning unavailable", err)
	}
	return exportInternalFailure("internal failure", err)
}

// decodeExportBody decodes a bounded JSON body into dst. An empty body is an
// error unless allowEmpty, in which case dst keeps its zero value.
func decodeExportBody(r *http.Request, dst any, allowEmpty bool) error {
	if r.Body == nil {
		if allowEmpty {
			return nil
		}
		return errors.New("a JSON request body is required")
	}
	err := json.NewDecoder(io.LimitReader(r.Body, maxExportRequestBytes)).Decode(dst)
	if errors.Is(err, io.EOF) && allowEmpty {
		return nil
	}
	if err != nil {
		return errors.New("the request body must be a JSON object")
	}
	return nil
}

// exportCaller builds the vault scope without touching c.Err, because an
// export failure must be written as R6. It returns the vault id as a string
// for the audit event.
func exportCaller(c *Context, r *http.Request) (model.Scope, string, bool) {
	userID, err := uuid.Parse(c.Claims.UserID)
	if err != nil {
		return model.Scope{}, "", false
	}
	vaultID, err := vaultIDFromRequest(r)
	if err != nil {
		return model.Scope{}, "", false
	}
	return model.NewVaultScope(vaultID, userID), vaultID.String(), true
}

// auditableExportFormat returns format when it is a known export format and
// "invalid" otherwise, so arbitrary client text never reaches the audit trail.
func auditableExportFormat(format string) string {
	switch format {
	case model.ExportFormatPEM, model.ExportFormatPKCS12:
		return format
	}
	return "invalid"
}

// exportAudit is one export attempt as the audit trail records it. It holds
// no material and no password by construction. Reason is a fixed phrase from
// exportFailure, never raw error text.
type exportAudit struct {
	ResourceType string
	ResourceID   string
	VaultID      string
	Name         string
	Version      int
	Format       string
	Outcome      string
	Code         string
	Reason       string
}

// recordExportAudit writes one structured audit event per export attempt. A
// nil audit service is tolerated: audit failures never block the request.
func recordExportAudit(c *Context, r *http.Request, a exportAudit) {
	if c.App == nil || c.App.ServiceContainer == nil {
		return
	}
	svc := c.App.ServiceContainer.GetAuditService()
	if svc == nil {
		return
	}
	details, _ := json.Marshal(map[string]any{
		"vault_id": a.VaultID, "name": a.Name, "version": a.Version, "format": a.Format, "code": a.Code, "reason": a.Reason,
	})
	_ = svc.RecordEvent(r.Context(), auditSvc.AuditEvent{
		UserID:       c.Claims.UserID,
		Action:       "export_" + a.ResourceType,
		Details:      string(details),
		ResourceType: a.ResourceType,
		ResourceID:   a.ResourceID,
		IPAddress:    middleware.ExtractClientIP(r),
		Outcome:      a.Outcome,
		Source:       "api",
	})
}

// ExportCertificateAPIRequest is the body of POST .../certificates/{id}/export.
type ExportCertificateAPIRequest struct {
	Format   string  `json:"format"`             // pem or pkcs12.
	Password *string `json:"password,omitempty"` // Required for pkcs12; may be empty.
	Compat   string  `json:"compat,omitempty"`   // modern (default) or legacy.
	Version  int     `json:"version,omitempty"`  // 0 or omitted means the current version.
}

// ExportCertificateResponse is the export success body. Exactly one of the
// pem pair and pkcs12_base64 is set, matching format.
type ExportCertificateResponse struct {
	ID             uuid.UUID  `json:"id"`
	Name           string     `json:"name"`
	Version        int        `json:"version"`
	Format         string     `json:"format"`
	CertificatePEM string     `json:"certificate_pem,omitempty"`
	PrivateKeyPEM  string     `json:"private_key_pem,omitempty"`
	PKCS12Base64   string     `json:"pkcs12_base64,omitempty"`
	NotBefore      *time.Time `json:"not_before"`
	ExpiresAt      *time.Time `json:"expires_at"`
	KeyAlgorithm   string     `json:"key_algorithm"`
}

// exportCertificate handles POST .../certificates/{certificate_id}/export.
// PolicyMiddleware has already required ActionCertificatesExportItem in the
// resolved vault. It never sets c.Err: every outcome is written here, as R6
// on failure, and audited once. That one structured event is the audit
// record for the attempt, so the handler writes no legacy log row of its own.
func exportCertificate(c *Context, w http.ResponseWriter, r *http.Request) {
	setExportHeaders(w)
	audit := exportAudit{ResourceType: "certificate", ResourceID: c.Params.CertificateID, Outcome: "failure"}
	fail := func(f exportFailure) {
		audit.Code, audit.Reason = f.Code, f.Reason
		if f.Name != "" {
			audit.Name = f.Name
		}
		recordExportAudit(c, r, audit)
		logExportFailure(c, "certificate", f)
		writeExportError(w, f)
	}

	scope, vaultID, ok := exportCaller(c, r)
	audit.VaultID = vaultID
	if !ok {
		fail(badExportRequest("the caller or vault could not be determined"))
		return
	}
	certID, err := uuid.Parse(c.Params.CertificateID)
	if err != nil {
		fail(badExportRequest("certificate_id must be a UUID"))
		return
	}
	var req ExportCertificateAPIRequest
	if err := decodeExportBody(r, &req, false); err != nil {
		fail(badExportRequest(err.Error()))
		return
	}
	audit.Format, audit.Version = auditableExportFormat(req.Format), req.Version

	certService, svcOK := svc(c, container.ServiceContainerInterface.GetCertificateService)
	if !svcOK {
		c.Err = nil
		fail(exportInternalFailure("certificate service unavailable", nil))
		return
	}

	result, err := certService.ExportCertificate(r.Context(), scope, certID, certServices.ExportCertificateRequest{
		Format: req.Format, Password: req.Password, Compat: req.Compat, Version: req.Version,
	})
	if err != nil {
		fail(exportFailureFor(err, "certificate"))
		return
	}

	audit.Outcome, audit.Name, audit.Version, audit.Code, audit.Reason = "success", result.Name, result.Version, "", ""
	recordExportAudit(c, r, audit)

	resp := ExportCertificateResponse{
		ID: result.ID, Name: result.Name, Version: result.Version, Format: result.Format,
		NotBefore: result.NotBefore, ExpiresAt: result.ExpiresAt, KeyAlgorithm: result.KeyAlgorithm,
	}
	if result.Format == model.ExportFormatPKCS12 {
		resp.PKCS12Base64 = base64.StdEncoding.EncodeToString(result.PKCS12)
	} else {
		resp.CertificatePEM, resp.PrivateKeyPEM = result.CertificatePEM, result.PrivateKeyPEM
	}
	writeJSON(w, resp)
}
