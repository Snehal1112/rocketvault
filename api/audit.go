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
	"net/http"
	"strconv"
	"time"

	"rocketvault/common"
	auditSvc "rocketvault/internal/services/audit"
	"rocketvault/model"
)

// InitAudit registers the audit log and compliance-report routes.
// Routes:
//
//	GET   /audit/logs          — paginated audit log query
//	GET   /audit/reports/soc2  — SOC 2 report (JSON or CSV via Accept)
//	GET   /audit/reports/gdpr  — GDPR data-subject report (JSON or CSV via Accept)
//	GET   /audit/config        — get retention configuration
//	PATCH /audit/config        — update retention configuration
func (api *API) InitAudit() {
	a := api.BaseRoutes.Audit

	a.Handle("/logs", ApiSessionRequired(api.App, getAuditLogs)).Methods("GET")
	a.Handle("/reports/soc2", ApiSessionRequired(api.App, getSOC2Report)).Methods("GET")
	a.Handle("/reports/gdpr", ApiSessionRequired(api.App, getGDPRReport)).Methods("GET")
	a.Handle("/config", ApiSessionRequired(api.App, getAuditConfig)).Methods("GET")
	a.Handle("/config", ApiSessionRequired(api.App, patchAuditConfig)).Methods("PATCH")
}

// complianceSvc is a helper that retrieves the ComplianceReportService from the container.
func (c *Context) complianceSvc() auditSvc.ComplianceReportServiceInterface {
	if c.App == nil || c.App.ServiceContainer == nil {
		c.SetInternalError(nil)
		return nil
	}
	return c.App.ServiceContainer.GetComplianceReportService()
}

// getAuditLogs handles GET /audit/logs.
// It parses AuditFilter query params and returns a page of logs with an integrity flag.
func getAuditLogs(c *Context, w http.ResponseWriter, r *http.Request) {
	// Restrict to admin role.
	roles := c.Claims.Roles
	if !common.HasAnyRole(roles, model.RoleAdmin) {
		c.SetPermissionError("admin role required")
		return
	}

	svc := c.complianceSvc()
	if svc == nil {
		return
	}

	filter := parseAuditFilter(r)

	logs, total, integrityOK, err := svc.QueryLogs(r.Context(), filter)
	if err != nil {
		c.SetInternalError(err)
		return
	}

	writeJSON(w, auditLogsResponse{
		IntegrityOK: integrityOK,
		Logs:        logs,
		NextCursor:  "",
		Total:       total,
	})
}

// auditLogsResponse is the GET /audit/logs envelope.
//
// Fields are declared in the alphabetical order the map[string]any this
// replaces encoded them in, so the JSON byte order is unchanged. No field is
// omitempty: the map always emitted all four keys, and next_cursor in
// particular is always the empty string today.
type auditLogsResponse struct {
	IntegrityOK bool             `json:"integrity_ok"`
	Logs        []model.AuditLog `json:"logs"`
	NextCursor  string           `json:"next_cursor"`
	Total       int64            `json:"total"`
}

// getSOC2Report handles GET /audit/reports/soc2.
// Returns JSON by default; returns CSV when Accept: text/csv is set.
func getSOC2Report(c *Context, w http.ResponseWriter, r *http.Request) {
	// Restrict to admin role.
	roles := c.Claims.Roles
	if !common.HasAnyRole(roles, model.RoleAdmin) {
		c.SetPermissionError("admin role required")
		return
	}

	svc := c.complianceSvc()
	if svc == nil {
		return
	}

	from, to, ok := parseReportDateRange(c, r)
	if !ok {
		return
	}

	// Return CSV when the client requests it explicitly.
	if r.Header.Get("Accept") == "text/csv" {
		csvData, err := svc.GenerateSOC2CSV(r.Context(), from, to)
		if err != nil {
			c.SetInternalError(err)
			return
		}
		w.Header().Set("Content-Type", "text/csv")
		w.Header().Set("Content-Disposition", "attachment; filename=soc2-report.csv")
		w.Write([]byte(csvData)) //nolint:errcheck,gosec
		return
	}

	report, err := svc.GenerateSOC2Report(r.Context(), from, to)
	if err != nil {
		c.SetInternalError(err)
		return
	}

	writeJSON(w, report)
}

// getGDPRReport handles GET /audit/reports/gdpr.
// Requires the subject_id query parameter.
// Returns JSON by default; returns CSV when Accept: text/csv is set.
func getGDPRReport(c *Context, w http.ResponseWriter, r *http.Request) {
	// Restrict to admin role.
	roles := c.Claims.Roles
	if !common.HasAnyRole(roles, model.RoleAdmin) {
		c.SetPermissionError("admin role required")
		return
	}

	subjectID := r.URL.Query().Get("subject_id")
	if subjectID == "" {
		c.SetInvalidParam("subject_id")
		return
	}

	svc := c.complianceSvc()
	if svc == nil {
		return
	}

	from, to, ok := parseReportDateRange(c, r)
	if !ok {
		return
	}

	// Return CSV when the client requests it explicitly.
	if r.Header.Get("Accept") == "text/csv" {
		csvData, err := svc.GenerateGDPRCSV(r.Context(), from, to, subjectID)
		if err != nil {
			c.SetInternalError(err)
			return
		}
		w.Header().Set("Content-Type", "text/csv")
		w.Header().Set("Content-Disposition", "attachment; filename=gdpr-report.csv")
		w.Write([]byte(csvData)) //nolint:errcheck,gosec
		return
	}

	report, err := svc.GenerateGDPRReport(r.Context(), from, to, subjectID)
	if err != nil {
		c.SetInternalError(err)
		return
	}

	writeJSON(w, report)
}

// getAuditConfig handles GET /audit/config and returns the current retention_days.
func getAuditConfig(c *Context, w http.ResponseWriter, r *http.Request) {
	// Restrict to admin role.
	roles := c.Claims.Roles
	if !common.HasAnyRole(roles, model.RoleAdmin) {
		c.SetPermissionError("admin role required")
		return
	}

	svc := c.complianceSvc()
	if svc == nil {
		return
	}

	days, err := svc.GetRetentionDays(r.Context())
	if err != nil {
		c.SetInternalError(err)
		return
	}

	writeJSON(w, map[string]int{"retention_days": days})
}

// patchAuditConfig handles PATCH /audit/config and updates retention_days.
func patchAuditConfig(c *Context, w http.ResponseWriter, r *http.Request) {
	// Restrict to admin role.
	roles := c.Claims.Roles
	if !common.HasAnyRole(roles, model.RoleAdmin) {
		c.SetPermissionError("admin role required")
		return
	}

	body, ok := decodeBody[struct {
		RetentionDays int `json:"retention_days"`
	}](c, r)
	if !ok {
		return
	}
	if body.RetentionDays < auditSvc.MinRetentionDays {
		c.SetInvalidParam("retention_days: must be at least " + strconv.Itoa(auditSvc.MinRetentionDays))
		return
	}

	svc := c.complianceSvc()
	if svc == nil {
		return
	}

	if err := svc.SetRetentionDays(r.Context(), body.RetentionDays); err != nil {
		c.SetInternalError(err)
		return
	}

	writeJSON(w, map[string]int{"retention_days": body.RetentionDays})
}

// parseAuditFilter builds an AuditFilter from URL query parameters.
// All fields are optional; absent params leave the pointer nil (no filter).
func parseAuditFilter(r *http.Request) model.AuditFilter {
	q := r.URL.Query()
	f := model.AuditFilter{}

	if v := q.Get("from"); v != "" {
		if t, err := time.Parse(time.RFC3339, v); err == nil {
			f.From = &t
		}
	}
	if v := q.Get("to"); v != "" {
		if t, err := time.Parse(time.RFC3339, v); err == nil {
			f.To = &t
		}
	}
	if v := q.Get("user_id"); v != "" {
		f.UserID = &v
	}
	if v := q.Get("action"); v != "" {
		f.Action = &v
	}
	if v := q.Get("outcome"); v != "" {
		f.Outcome = &v
	}
	if v := q.Get("resource_type"); v != "" {
		f.ResourceType = &v
	}
	if v := q.Get("resource_id"); v != "" {
		f.ResourceID = &v
	}
	if v := q.Get("source"); v != "" {
		f.Source = &v
	}

	// Default to 100 entries; cap at 1000.
	f.Limit = 100
	if v := q.Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			if n > 1000 {
				n = 1000
			}
			f.Limit = n
		}
	}

	return f
}

// parseReportDateRange parses the "from" and "to" RFC3339 query parameters.
// Returns false and sets c.Err when either parameter is absent or malformed.
func parseReportDateRange(c *Context, r *http.Request) (from, to time.Time, ok bool) {
	fromStr := r.URL.Query().Get("from")
	toStr := r.URL.Query().Get("to")

	if fromStr == "" {
		c.SetInvalidParam("from")
		return
	}
	if toStr == "" {
		c.SetInvalidParam("to")
		return
	}

	var err error
	from, err = time.Parse(time.RFC3339, fromStr)
	if err != nil {
		c.SetInvalidParam("from: must be RFC3339")
		return
	}
	to, err = time.Parse(time.RFC3339, toStr)
	if err != nil {
		c.SetInvalidParam("to: must be RFC3339")
		return
	}

	ok = true
	return
}
