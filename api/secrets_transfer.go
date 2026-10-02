/*
Copyright © 2025 Snehal Dangroshiya

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
*/

package api

import (
	"fmt"
	"io"
	"net/http"
	"strconv"
	"time"

	"rocketvault/common"
	"rocketvault/internal/container"
	"rocketvault/internal/services/secrets"
	"rocketvault/model"
)

// exportSecrets handles the export of secrets to encrypted files.
// Supports JSON and CSV formats with optional encryption.
func exportSecrets(c *Context, w http.ResponseWriter, r *http.Request) {
	// Parse request body using model type.
	exportReq, err := model.ExportSecretsRequestFromJson(r.Body)
	if err != nil {
		c.SetInvalidParam("request body")
		return
	}

	// Validate format.
	if exportReq.Format != "json" && exportReq.Format != "csv" {
		c.SetInvalidParam("format: must be 'json' or 'csv'")
		return
	}

	secretService, svcOK := svc(c, container.ServiceContainerInterface.GetSecretService)
	if !svcOK {
		return
	}

	scope, ok := scopeFromRequest(c, r)
	if !ok {
		return
	}

	// Use service layer for export.
	serviceReq := secrets.ExportSecretsRequest{
		Scope:       scope,
		Format:      exportReq.Format,
		FilterTags:  exportReq.Tags,
		IncludeTags: exportReq.IncludeTags,
		Encrypt:     exportReq.Encrypt,
		Passphrase:  exportReq.Passphrase,
	}

	data, err := secretService.ExportSecrets(r.Context(), serviceReq)
	if err != nil {
		writeSecretError(c, err)
		return
	}

	// Set response headers.
	contentType := "application/json"
	if exportReq.Format == "csv" {
		contentType = "text/csv"
	}

	filename := fmt.Sprintf("secrets-export-%s.%s", time.Now().Format("20060102-150405"), exportReq.Format)
	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%s", filename))
	w.Header().Set("Content-Length", strconv.Itoa(len(data)))

	// Write raw file bytes.
	w.WriteHeader(http.StatusOK)
	w.Write(data) //nolint:errcheck,gosec

	c.Logger.Printf("User %s exported secrets in %s format", c.Claims.UserID, exportReq.Format)
}

// importSecrets handles the import of secrets from encrypted files.
// Accepts multipart form data with file, format, and options.
func importSecrets(c *Context, w http.ResponseWriter, r *http.Request) {
	// Parse multipart form.
	if err := r.ParseMultipartForm(10 << 20); err != nil { // 10 MB max.
		c.SetInvalidParam("request body: failed to parse multipart form")
		return
	}

	// Get file from form.
	file, _, err := r.FormFile("file")
	if err != nil {
		c.SetInvalidParam("file: missing or invalid")
		return
	}
	defer file.Close() //nolint:errcheck

	// Read file data.
	data, err := io.ReadAll(file)
	if err != nil {
		c.SetInvalidParam("file: failed to read")
		return
	}

	// Get form parameters.
	format := r.FormValue("format")
	if format != "json" && format != "csv" {
		c.SetInvalidParam("format: must be 'json' or 'csv'")
		return
	}

	overwrite := r.FormValue("overwrite") == "true"

	// A sealed export must be opened here, in the handler, not in the
	// service: this is the only layer with a passphrase channel (the
	// "passphrase" form field). ImportSecrets refuses sealed data outright
	// by design (see secret_service.go's ImportSecrets) — plaintext must
	// reach it. This mirrors cmd/secrets/import.go's own detect-then-open
	// sequence exactly. The passphrase form value is used only for this
	// OpenExport call; it is never logged and never reaches the service.
	if common.IsSealedExport(data) {
		opened, openErr := common.OpenExport(data, r.FormValue("passphrase"))
		if openErr != nil {
			writeSecretError(c, openErr)
			return
		}
		data = opened
	}

	secretService, svcOK := svc(c, container.ServiceContainerInterface.GetSecretService)
	if !svcOK {
		return
	}

	scope, ok := scopeFromRequest(c, r)
	if !ok {
		return
	}

	// Use service layer for import.
	serviceReq := secrets.ImportSecretsRequest{
		Scope:     scope,
		Data:      data,
		Format:    format,
		Overwrite: overwrite,
	}

	result, err := secretService.ImportSecrets(r.Context(), serviceReq)
	if err != nil {
		writeSecretError(c, err)
		return
	}

	// Prepare response using model type.
	message := fmt.Sprintf("Successfully imported %d/%d secrets", result.ImportedCount, result.TotalCount)
	if result.FailedCount > 0 {
		message = fmt.Sprintf("Imported %d/%d secrets, %d failed", result.ImportedCount, result.TotalCount, result.FailedCount)
	}
	response := model.ImportResponse{
		Success:       result.FailedCount == 0,
		Message:       message,
		ImportedCount: result.ImportedCount,
		SkippedCount:  result.SkippedCount,
		FailedCount:   result.FailedCount,
		TotalCount:    result.TotalCount,
		Format:        format,
		ImportedAt:    time.Now().Format(time.RFC3339),
		Errors:        result.Errors,
	}

	// Send response.
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(response.ToJson())) //nolint:errcheck,gosec

	c.Logger.Printf("User %s imported %d/%d secrets from %s format",
		c.Claims.UserID, result.ImportedCount, result.TotalCount, format)
}
