package api

import (
	"net/http"

	"github.com/google/uuid"

	"rocketvault/internal/container"
	"rocketvault/model"
)

// ExportKeyAPIRequest is the optional body of POST .../keys/{key_id}/export.
// An empty body exports the current version as PEM.
type ExportKeyAPIRequest struct {
	Format  string `json:"format,omitempty"`  // Only pem; empty means pem.
	Version int    `json:"version,omitempty"` // 0 or omitted means the current version.
}

// ExportKeyResponse is the key export success body.
type ExportKeyResponse struct {
	ID            uuid.UUID `json:"id"`
	Name          string    `json:"name"`
	Type          string    `json:"type"`
	Version       int       `json:"version"`
	Format        string    `json:"format"`
	PrivateKeyPEM string    `json:"private_key_pem"`
	KeyAlgorithm  string    `json:"key_algorithm"`
}

// auditableKeyExportFormat returns pem for an empty or pem format and
// "invalid" otherwise, so arbitrary client text never reaches the audit trail.
func auditableKeyExportFormat(format string) string {
	if format == "" || format == model.ExportFormatPEM {
		return model.ExportFormatPEM
	}
	return "invalid"
}

// exportKey handles POST .../keys/{key_id}/export. PolicyMiddleware has
// already required ActionKeysExport in the resolved vault. Like
// exportCertificate it never sets c.Err: every outcome is written here, as R6
// on failure, and audited once. The key service's own error text names the
// key id and repository detail, so it is never echoed; exportFailureFor maps
// each error onto a fixed message.
func exportKey(c *Context, w http.ResponseWriter, r *http.Request) {
	setExportHeaders(w)
	audit := exportAudit{ResourceType: "key", ResourceID: c.Params.KeyID, Outcome: "failure", Format: model.ExportFormatPEM}
	fail := func(f exportFailure) {
		audit.Code, audit.Reason = f.Code, f.Reason
		if f.Name != "" {
			audit.Name = f.Name
		}
		recordExportAudit(c, r, audit)
		logExportFailure(c, "key", f)
		writeExportError(w, f)
	}

	scope, vaultID, ok := exportCaller(c, r)
	audit.VaultID = vaultID
	if !ok {
		fail(badExportRequest("the caller or vault could not be determined"))
		return
	}
	keyID, err := uuid.Parse(c.Params.KeyID)
	if err != nil {
		fail(badExportRequest("key_id must be a UUID"))
		return
	}
	var req ExportKeyAPIRequest
	if err := decodeExportBody(r, &req, true); err != nil {
		fail(badExportRequest(err.Error()))
		return
	}
	audit.Format, audit.Version = auditableKeyExportFormat(req.Format), req.Version
	if audit.Format != model.ExportFormatPEM {
		fail(badExportRequest("format must be pem"))
		return
	}

	keyService, svcOK := svc(c, container.ServiceContainerInterface.GetKeyService)
	if !svcOK {
		c.Err = nil
		fail(exportInternalFailure("key service unavailable", nil))
		return
	}

	result, err := keyService.ExportKey(r.Context(), scope, keyID, req.Version)
	if err != nil {
		fail(exportFailureFor(err, "key"))
		return
	}

	audit.Outcome, audit.Name, audit.Version, audit.Code, audit.Reason = "success", result.Name, result.Version, "", ""
	recordExportAudit(c, r, audit)
	writeJSON(w, ExportKeyResponse{
		ID: result.ID, Name: result.Name, Type: result.Type, Version: result.Version,
		Format: result.Format, PrivateKeyPEM: result.PrivateKeyPEM, KeyAlgorithm: result.KeyAlgorithm,
	})
}
