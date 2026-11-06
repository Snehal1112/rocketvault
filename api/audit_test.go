// Package api — internal tests for audit log and compliance-report handlers.
package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"rocketvault/app"
	"rocketvault/internal/repositories"
	auditSvc "rocketvault/internal/services/audit"
	"rocketvault/internal/testutils"
	"rocketvault/model"
)

// adminClaims returns a RequestClaims with a multi-role set where admin is
// present but not the sole or first role, verifying the gate checks
// membership rather than a single primary role.
func adminClaims() RequestClaims {
	return RequestClaims{Roles: []string{"secrets_manager", string(model.RoleAdmin)}}
}

// TestGetAuditLogs_Returns200 verifies that a valid query returns 200 with integrity_ok.
func TestGetAuditLogs_Returns200(t *testing.T) {
	mockCRS := &testutils.MockComplianceReportService{}
	mockContainer := &testutils.MockServiceContainer{}
	mockContainer.On("GetComplianceReportService").Return(mockCRS)
	mockCRS.On("QueryLogs", mock.Anything, mock.Anything).Return(
		[]repositories.AuditLog{{ID: "id1", Action: "login", Outcome: "success"}},
		int64(1), true, nil,
	)

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/api/v1/audit/logs", nil)
	c := &Context{App: &app.App{ServiceContainer: mockContainer}, Claims: adminClaims()}

	getAuditLogs(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}
	assert.Equal(t, http.StatusOK, w.Code)

	var resp map[string]interface{}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, true, resp["integrity_ok"])
}

// TestGetAuditLogs_IntegrityBreakFields verifies the break seq and reason reach the JSON.
func TestGetAuditLogs_IntegrityBreakFields(t *testing.T) {
	seq := int64(7)
	mockCRS := &testutils.MockComplianceReportService{}
	mockContainer := &testutils.MockServiceContainer{}
	mockContainer.On("GetComplianceReportService").Return(mockCRS)
	mockCRS.On("QueryLogs", mock.Anything, mock.Anything).Return(
		[]repositories.AuditLog{}, int64(0),
		auditSvc.IntegrityResult{BreakSeq: &seq, BreakReason: "gap"}, nil,
	)

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/api/v1/audit/logs", nil)
	c := &Context{App: &app.App{ServiceContainer: mockContainer}, Claims: adminClaims()}

	getAuditLogs(c, w, r)
	assert.Equal(t, http.StatusOK, w.Code)

	var resp map[string]interface{}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, false, resp["integrity_ok"])
	assert.Equal(t, float64(7), resp["integrity_break_seq"])
	assert.Equal(t, "gap", resp["integrity_break_reason"])
}

// TestGetSOC2Report_Returns200 verifies that SOC2 report generation returns 200.
func TestGetSOC2Report_Returns200(t *testing.T) {
	mockCRS := &testutils.MockComplianceReportService{}
	mockContainer := &testutils.MockServiceContainer{}
	mockContainer.On("GetComplianceReportService").Return(mockCRS)
	mockCRS.On("GenerateSOC2Report", mock.Anything, mock.Anything, mock.Anything).Return(
		&auditSvc.SOC2Report{TotalEvents: 10, UniqueUsers: 3}, nil,
	)

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/api/v1/audit/reports/soc2?from=2026-01-01T00:00:00Z&to=2026-12-31T23:59:59Z", nil)
	c := &Context{App: &app.App{ServiceContainer: mockContainer}, Claims: adminClaims()}

	getSOC2Report(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}
	assert.Equal(t, http.StatusOK, w.Code)
}

// TestPatchAuditConfig_Returns200 verifies that updating retention_days returns 200.
func TestPatchAuditConfig_Returns200(t *testing.T) {
	mockCRS := &testutils.MockComplianceReportService{}
	mockContainer := &testutils.MockServiceContainer{}
	mockContainer.On("GetComplianceReportService").Return(mockCRS)
	mockCRS.On("SetRetentionDays", mock.Anything, 90).Return(nil)

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPatch, "/api/v1/audit/config",
		strings.NewReader(`{"retention_days":90}`))
	c := &Context{App: &app.App{ServiceContainer: mockContainer}, Claims: adminClaims()}

	patchAuditConfig(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}
	assert.Equal(t, http.StatusOK, w.Code)
}

// TestGetGDPRReport_MissingSubjectID_Returns400 verifies that subject_id is required.
func TestGetGDPRReport_MissingSubjectID_Returns400(t *testing.T) {
	mockCRS := &testutils.MockComplianceReportService{}
	mockContainer := &testutils.MockServiceContainer{}
	mockContainer.On("GetComplianceReportService").Return(mockCRS)

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/api/v1/audit/reports/gdpr?from=2026-01-01T00:00:00Z&to=2026-12-31T23:59:59Z", nil)
	c := &Context{App: &app.App{ServiceContainer: mockContainer}, Claims: adminClaims()}

	getGDPRReport(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestGetAuditConfig_Returns200 verifies that the config endpoint returns retention_days.
func TestGetAuditConfig_Returns200(t *testing.T) {
	mockCRS := &testutils.MockComplianceReportService{}
	mockContainer := &testutils.MockServiceContainer{}
	mockContainer.On("GetComplianceReportService").Return(mockCRS)
	mockCRS.On("GetRetentionDays", mock.Anything).Return(365, nil)

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/api/v1/audit/config", nil)
	c := &Context{App: &app.App{ServiceContainer: mockContainer}, Claims: adminClaims()}

	getAuditConfig(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}
	assert.Equal(t, http.StatusOK, w.Code)

	var resp map[string]interface{}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, float64(365), resp["retention_days"])
}
