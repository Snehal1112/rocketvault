// Package api — supplemental tests to push statement coverage above 80%.
package api

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"rocketvault/app"
	"rocketvault/internal/crypto"
	"rocketvault/internal/logging"
	auditSvc "rocketvault/internal/services/audit"
	keyServices "rocketvault/internal/services/keys"
	"rocketvault/internal/testutils"
	"rocketvault/model"
)

// ============================================================
// options.go — WithAPP, WithBasePath, WithRouter, WithLogger
// ============================================================

func TestWithAPP_SetsAppField(t *testing.T) {
	a := &app.App{}
	api := &API{}
	WithAPP(a)(api)
	assert.Equal(t, a, api.App)
}

func TestWithBasePath_SetsBasePathField(t *testing.T) {
	api := &API{}
	WithBasePath("/api/v1")(api)
	assert.Equal(t, "/api/v1", api.basePath)
}

func TestWithRouter_SetsRootRouterField(t *testing.T) {
	router := mux.NewRouter()
	api := &API{}
	WithRouter(router)(api)
	assert.Equal(t, router, api.rootRouter)
}

func TestWithLogger_SetsLoggerField(t *testing.T) {
	l := logrus.New()
	logger := &logging.Logger{Logger: l}
	api := &API{}
	WithLogger(logger)(api)
	assert.Equal(t, logger, api.Logger)
}

// ============================================================
// audit.go — missing branches
// ============================================================

// auditAdminCtx creates a Context backed by the MockServiceContainer for audit tests.
func auditAdminCtx(mc *testutils.MockServiceContainer) *Context {
	return &Context{
		App:    &app.App{ServiceContainer: mc},
		Claims: RequestClaims{Roles: []string{model.RoleAdmin}},
		Params: &ApiParams{PerPage: 60},
	}
}

// TestGetAuditLogs_NonAdmin_Returns403 ensures non-admin users are rejected.
func TestGetAuditLogs_NonAdmin_Returns403(t *testing.T) {
	c := &Context{
		App:    &app.App{},
		Claims: RequestClaims{Roles: []string{"viewer"}},
		Params: &ApiParams{},
	}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/audit/logs", nil)

	getAuditLogs(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusForbidden, w.Code)
}

// TestGetSOC2Report_CSVAcceptHeader_Returns200 exercises the CSV branch.
func TestGetSOC2Report_CSVAcceptHeader_Returns200(t *testing.T) {
	mockCRS := &testutils.MockComplianceReportService{}
	mc := &testutils.MockServiceContainer{}
	mc.On("GetComplianceReportService").Return(mockCRS)
	mockCRS.On("GenerateSOC2CSV", mock.Anything, mock.Anything, mock.Anything).Return("col1,col2\nval1,val2", nil)

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/audit/reports/soc2?from=2026-01-01T00:00:00Z&to=2026-12-31T23:59:59Z", nil)
	r.Header.Set("Accept", "text/csv")
	c := auditAdminCtx(mc)

	getSOC2Report(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "text/csv", w.Header().Get("Content-Type"))
}

// TestGetSOC2Report_MissingFromParam_Returns400 verifies from is required.
func TestGetSOC2Report_MissingFromParam_Returns400(t *testing.T) {
	mc := &testutils.MockServiceContainer{}
	mc.On("GetComplianceReportService").Return(&testutils.MockComplianceReportService{})

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/audit/reports/soc2?to=2026-12-31T23:59:59Z", nil)
	c := auditAdminCtx(mc)

	getSOC2Report(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestGetSOC2Report_ServiceError_Returns500 tests that service errors are propagated.
func TestGetSOC2Report_ServiceError_Returns500(t *testing.T) {
	mockCRS := &testutils.MockComplianceReportService{}
	mc := &testutils.MockServiceContainer{}
	mc.On("GetComplianceReportService").Return(mockCRS)
	mockCRS.On("GenerateSOC2Report", mock.Anything, mock.Anything, mock.Anything).Return((*auditSvc.SOC2Report)(nil), errors.New("db error"))

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/audit/reports/soc2?from=2026-01-01T00:00:00Z&to=2026-12-31T23:59:59Z", nil)
	c := auditAdminCtx(mc)

	getSOC2Report(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

// TestGetSOC2Report_CSVError_Returns500 tests CSV generation error.
func TestGetSOC2Report_CSVError_Returns500(t *testing.T) {
	mockCRS := &testutils.MockComplianceReportService{}
	mc := &testutils.MockServiceContainer{}
	mc.On("GetComplianceReportService").Return(mockCRS)
	mockCRS.On("GenerateSOC2CSV", mock.Anything, mock.Anything, mock.Anything).Return("", errors.New("csv error"))

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/audit/reports/soc2?from=2026-01-01T00:00:00Z&to=2026-12-31T23:59:59Z", nil)
	r.Header.Set("Accept", "text/csv")
	c := auditAdminCtx(mc)

	getSOC2Report(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

// TestGetGDPRReport_JSON_Returns200 verifies the happy-path JSON branch.
func TestGetGDPRReport_JSON_Returns200(t *testing.T) {
	mockCRS := &testutils.MockComplianceReportService{}
	mc := &testutils.MockServiceContainer{}
	mc.On("GetComplianceReportService").Return(mockCRS)
	mockCRS.On("GenerateGDPRReport", mock.Anything, mock.Anything, mock.Anything, "user123").Return(
		&auditSvc.GDPRReport{SubjectID: "user123"}, nil,
	)

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/audit/reports/gdpr?from=2026-01-01T00:00:00Z&to=2026-12-31T23:59:59Z&subject_id=user123", nil)
	c := auditAdminCtx(mc)

	getGDPRReport(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusOK, w.Code)
}

// TestGetGDPRReport_CSV_Returns200 exercises the CSV Accept header branch.
func TestGetGDPRReport_CSV_Returns200(t *testing.T) {
	mockCRS := &testutils.MockComplianceReportService{}
	mc := &testutils.MockServiceContainer{}
	mc.On("GetComplianceReportService").Return(mockCRS)
	mockCRS.On("GenerateGDPRCSV", mock.Anything, mock.Anything, mock.Anything, "user123").Return("col1\nval1", nil)

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/audit/reports/gdpr?from=2026-01-01T00:00:00Z&to=2026-12-31T23:59:59Z&subject_id=user123", nil)
	r.Header.Set("Accept", "text/csv")
	c := auditAdminCtx(mc)

	getGDPRReport(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "text/csv", w.Header().Get("Content-Type"))
}

// TestGetGDPRReport_ServiceError_Returns500 ensures service errors are forwarded.
func TestGetGDPRReport_ServiceError_Returns500(t *testing.T) {
	mockCRS := &testutils.MockComplianceReportService{}
	mc := &testutils.MockServiceContainer{}
	mc.On("GetComplianceReportService").Return(mockCRS)
	mockCRS.On("GenerateGDPRReport", mock.Anything, mock.Anything, mock.Anything, "u1").Return((*auditSvc.GDPRReport)(nil), errors.New("err"))

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/audit/reports/gdpr?from=2026-01-01T00:00:00Z&to=2026-12-31T23:59:59Z&subject_id=u1", nil)
	c := auditAdminCtx(mc)

	getGDPRReport(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

// TestGetGDPRReport_CSVError_Returns500 tests CSV generation error for GDPR report.
func TestGetGDPRReport_CSVError_Returns500(t *testing.T) {
	mockCRS := &testutils.MockComplianceReportService{}
	mc := &testutils.MockServiceContainer{}
	mc.On("GetComplianceReportService").Return(mockCRS)
	mockCRS.On("GenerateGDPRCSV", mock.Anything, mock.Anything, mock.Anything, "u1").Return("", errors.New("csv error"))

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/audit/reports/gdpr?from=2026-01-01T00:00:00Z&to=2026-12-31T23:59:59Z&subject_id=u1", nil)
	r.Header.Set("Accept", "text/csv")
	c := auditAdminCtx(mc)

	getGDPRReport(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

// TestPatchAuditConfig_InvalidBody_Returns400 ensures bad JSON is rejected.
func TestPatchAuditConfig_InvalidBody_Returns400(t *testing.T) {
	mc := &testutils.MockServiceContainer{}
	mc.On("GetComplianceReportService").Return(&testutils.MockComplianceReportService{})

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPatch, "/audit/config", strings.NewReader("{bad json}"))
	c := auditAdminCtx(mc)

	patchAuditConfig(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestPatchAuditConfig_ZeroRetention_Returns400 ensures retention_days must be positive.
func TestPatchAuditConfig_ZeroRetention_Returns400(t *testing.T) {
	mc := &testutils.MockServiceContainer{}
	mc.On("GetComplianceReportService").Return(&testutils.MockComplianceReportService{})

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPatch, "/audit/config", strings.NewReader(`{"retention_days":0}`))
	c := auditAdminCtx(mc)

	patchAuditConfig(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestPatchAuditConfig_ServiceError_Returns500 tests SetRetentionDays error path.
func TestPatchAuditConfig_ServiceError_Returns500(t *testing.T) {
	mockCRS := &testutils.MockComplianceReportService{}
	mc := &testutils.MockServiceContainer{}
	mc.On("GetComplianceReportService").Return(mockCRS)
	mockCRS.On("SetRetentionDays", mock.Anything, 30).Return(errors.New("db error"))

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPatch, "/audit/config", strings.NewReader(`{"retention_days":30}`))
	c := auditAdminCtx(mc)

	patchAuditConfig(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

// TestGetAuditConfig_ServiceError_Returns500 covers the error path.
func TestGetAuditConfig_ServiceError_Returns500(t *testing.T) {
	mockCRS := &testutils.MockComplianceReportService{}
	mc := &testutils.MockServiceContainer{}
	mc.On("GetComplianceReportService").Return(mockCRS)
	mockCRS.On("GetRetentionDays", mock.Anything).Return(0, errors.New("db error"))

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/audit/config", nil)
	c := auditAdminCtx(mc)

	getAuditConfig(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

// TestGetAuditLogs_ServiceError_Returns500 covers the QueryLogs error path.
func TestGetAuditLogs_ServiceError_Returns500(t *testing.T) {
	mockCRS := &testutils.MockComplianceReportService{}
	mc := &testutils.MockServiceContainer{}
	mc.On("GetComplianceReportService").Return(mockCRS)
	mockCRS.On("QueryLogs", mock.Anything, mock.Anything).Return(nil, int64(0), false, errors.New("db error"))

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/audit/logs", nil)
	c := auditAdminCtx(mc)

	getAuditLogs(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

// ============================================================
// audit.go — parseAuditFilter comprehensive branch coverage
// ============================================================

// TestParseAuditFilter_AllParams verifies all optional fields are parsed.
func TestParseAuditFilter_AllParams(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/audit/logs?from=2026-01-01T00:00:00Z&to=2026-12-31T23:59:59Z&user_id=u1&action=login&outcome=success&resource_type=secret&resource_id=r1&source=api&limit=50", nil)
	f := parseAuditFilter(r)

	require.NotNil(t, f.From)
	require.NotNil(t, f.To)
	require.NotNil(t, f.UserID)
	assert.Equal(t, "u1", *f.UserID)
	require.NotNil(t, f.Action)
	assert.Equal(t, "login", *f.Action)
	require.NotNil(t, f.Outcome)
	assert.Equal(t, "success", *f.Outcome)
	require.NotNil(t, f.ResourceType)
	assert.Equal(t, "secret", *f.ResourceType)
	require.NotNil(t, f.ResourceID)
	assert.Equal(t, "r1", *f.ResourceID)
	require.NotNil(t, f.Source)
	assert.Equal(t, "api", *f.Source)
	assert.Equal(t, 50, f.Limit)
}

// TestParseAuditFilter_DefaultLimit verifies the default limit is 100.
func TestParseAuditFilter_DefaultLimit(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/audit/logs", nil)
	f := parseAuditFilter(r)
	assert.Equal(t, 100, f.Limit)
}

// TestParseAuditFilter_LimitCappedAt1000 verifies the 1000-entry cap.
func TestParseAuditFilter_LimitCappedAt1000(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/audit/logs?limit=9999", nil)
	f := parseAuditFilter(r)
	assert.Equal(t, 1000, f.Limit)
}

// TestParseAuditFilter_InvalidFromIgnored verifies that invalid RFC3339 from is silently ignored.
func TestParseAuditFilter_InvalidFromIgnored(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/audit/logs?from=not-a-date", nil)
	f := parseAuditFilter(r)
	assert.Nil(t, f.From)
}

// ============================================================
// audit.go — parseReportDateRange
// ============================================================

// TestParseReportDateRange_MissingTo_Returns400 ensures to is required.
func TestParseReportDateRange_MissingTo_Returns400(t *testing.T) {
	c := &Context{Params: &ApiParams{}}
	r := httptest.NewRequest(http.MethodGet, "/?from=2026-01-01T00:00:00Z", nil)
	_, _, ok := parseReportDateRange(c, r)
	assert.False(t, ok)
	assert.NotNil(t, c.Err)
	assert.Equal(t, http.StatusBadRequest, c.Err.StatusCode)
}

// TestParseReportDateRange_InvalidFrom_Returns400 verifies bad from format.
func TestParseReportDateRange_InvalidFrom_Returns400(t *testing.T) {
	c := &Context{Params: &ApiParams{}}
	r := httptest.NewRequest(http.MethodGet, "/?from=bad-date&to=2026-12-31T23:59:59Z", nil)
	_, _, ok := parseReportDateRange(c, r)
	assert.False(t, ok)
	assert.NotNil(t, c.Err)
}

// TestParseReportDateRange_InvalidTo_Returns400 verifies bad to format.
func TestParseReportDateRange_InvalidTo_Returns400(t *testing.T) {
	c := &Context{Params: &ApiParams{}}
	r := httptest.NewRequest(http.MethodGet, "/?from=2026-01-01T00:00:00Z&to=bad-date", nil)
	_, _, ok := parseReportDateRange(c, r)
	assert.False(t, ok)
	assert.NotNil(t, c.Err)
}

// TestParseReportDateRange_Valid_ReturnsOK verifies the happy path.
func TestParseReportDateRange_Valid_ReturnsOK(t *testing.T) {
	c := &Context{Params: &ApiParams{}}
	r := httptest.NewRequest(http.MethodGet, "/?from=2026-01-01T00:00:00Z&to=2026-12-31T23:59:59Z", nil)
	from, to, ok := parseReportDateRange(c, r)
	assert.True(t, ok)
	assert.Nil(t, c.Err)
	assert.Equal(t, 2026, from.Year())
	assert.Equal(t, time.December, to.Month())
}

// ============================================================
// soft_delete.go — getDeletedKey
// ============================================================

// TestGetDeletedKey_InvalidKeyID_Returns400 verifies that a bad key_id returns 400.
func TestGetDeletedKey_InvalidKeyID_Returns400(t *testing.T) {
	c := newGetDeletedKeyContext(&mockKeyService{})
	c.Params = &ApiParams{KeyID: "bad-id"}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/keys/deleted/bad-id", nil)

	getDeletedKey(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestGetDeletedKey_RepoError_Returns500 verifies service errors are handled.
func TestGetDeletedKey_RepoError_Returns500(t *testing.T) {
	svc := &mockKeyService{}
	svc.On("ListDeletedKeys", mock.Anything, mock.Anything).Return(nil, errors.New("db error"))

	c := newGetDeletedKeyContext(svc)
	c.Params = &ApiParams{KeyID: uuid.New().String(), PerPage: 60}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/keys/deleted/"+c.Params.KeyID, nil)

	getDeletedKey(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusInternalServerError, w.Code)
	svc.AssertExpectations(t)
}

// ============================================================
// secrets.go — updateSecret missing branches
// ============================================================

// buildUpdateSecretCtx creates a Context with the given secret service and a logger.
func buildUpdateSecretCtx(svc *mockSecretService, secretIDStr string) *Context {
	a := &app.App{ServiceContainer: &secretSvcTestContainer{secretSvc: svc}}
	l := logrus.New()
	return &Context{
		App:    a,
		Claims: RequestClaims{UserID: secretHTestUserID},
		Params: &ApiParams{SecretID: secretIDStr, PerPage: 60},
		Logger: &logging.Logger{Logger: l},
	}
}

// TestUpdateSecret_NoChangesProvided_Returns400 verifies that an empty update is rejected.
func TestUpdateSecret_NoChangesProvided_Returns400(t *testing.T) {
	secretID := uuid.New()
	svc := &mockSecretService{}
	// No mock expectations: an empty body is rejected before any service call.

	c := buildUpdateSecretCtx(svc, secretID.String())
	w := httptest.NewRecorder()
	// Empty body — no fields changed.
	body, _ := json.Marshal(map[string]any{})
	r := httptest.NewRequest(http.MethodPut, "/secrets/"+secretID.String(), bytes.NewReader(body))

	updateSecret(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestUpdateSecret_UpdateServiceError_Returns500 verifies service errors are handled.
func TestUpdateSecret_UpdateServiceError_Returns500(t *testing.T) {
	secretID := uuid.New()
	svc := &mockSecretService{}
	svc.On("UpdateSecret", mock.Anything, mock.Anything).Return(errors.New("db error"))

	c := buildUpdateSecretCtx(svc, secretID.String())
	w := httptest.NewRecorder()
	body, _ := json.Marshal(map[string]any{"name": "new-name"})
	r := httptest.NewRequest(http.MethodPut, "/secrets/"+secretID.String(), bytes.NewReader(body))

	updateSecret(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

// TestUpdateSecret_NameChange_Returns200 verifies that updating the name succeeds.
func TestUpdateSecret_NameChange_Returns200(t *testing.T) {
	secretID := uuid.New()
	svc := &mockSecretService{}
	existing := makeSecretModel(secretID)
	svc.On("GetSecret", mock.Anything, secretID, mock.Anything).Return(existing, nil)
	svc.On("UpdateSecret", mock.Anything, mock.Anything).Return(nil)

	c := buildUpdateSecretCtx(svc, secretID.String())
	w := httptest.NewRecorder()
	body, _ := json.Marshal(map[string]any{"name": "new-name"})
	r := httptest.NewRequest(http.MethodPut, "/secrets/"+secretID.String(), bytes.NewReader(body))

	updateSecret(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusOK, w.Code)
}

// ============================================================
// secrets.go — importSecrets (0% → increase coverage)
// ============================================================

// TestImportSecrets_NoMultipartForm_Returns400 verifies that a non-multipart body is rejected.
func TestImportSecrets_NoMultipartForm_Returns400(t *testing.T) {
	c := &Context{
		App:    &app.App{},
		Claims: RequestClaims{UserID: secretHTestUserID},
		Params: &ApiParams{PerPage: 60},
	}
	w := httptest.NewRecorder()
	// Plain JSON body — not multipart.
	r := httptest.NewRequest(http.MethodPost, "/secrets/import", strings.NewReader(`{"format":"json"}`))

	importSecrets(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ============================================================
// context.go — ApiHandler additional coverage
// ============================================================

// TestApiHandler_SetsRequestMetadata verifies that ApiHandler populates ctx fields.
func TestApiHandler_SetsRequestMetadata(t *testing.T) {
	a := &app.App{}
	handler := ApiHandler(a, func(c *Context, w http.ResponseWriter, _ *http.Request) {
		assert.NotEmpty(t, c.RequestID)
		assert.NotEmpty(t, c.IPAddress)
		assert.NotEmpty(t, c.Path)
		w.WriteHeader(http.StatusOK)
	})

	r := httptest.NewRequest(http.MethodGet, "/test", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)

	assert.Equal(t, http.StatusOK, w.Code)
}

// TestApiHandler_HandlerSetsError_WritesJSONError verifies that errors set by the
// handler are written as structured JSON.
func TestApiHandler_HandlerSetsError_WritesJSONError(t *testing.T) {
	a := &app.App{}
	handler := ApiHandler(a, func(c *Context, _ http.ResponseWriter, _ *http.Request) {
		c.SetInvalidParam("test_param")
	})

	r := httptest.NewRequest(http.MethodGet, "/test", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	var body map[string]any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
	assert.NotEmpty(t, body["message"])
}

// ============================================================
// context.go — complianceSvc nil guards
// ============================================================

// TestComplianceSvc_NilApp_SetsError verifies error path when App is nil.
func TestComplianceSvc_NilApp_SetsError(t *testing.T) {
	c := &Context{App: nil, Params: &ApiParams{}}
	svc := c.complianceSvc()
	assert.Nil(t, svc)
	assert.NotNil(t, c.Err)
	assert.Equal(t, http.StatusInternalServerError, c.Err.StatusCode)
}

// TestComplianceSvc_NilContainer_SetsError verifies error path when ServiceContainer is nil.
func TestComplianceSvc_NilContainer_SetsError(t *testing.T) {
	c := &Context{App: &app.App{ServiceContainer: nil}, Params: &ApiParams{}}
	svc := c.complianceSvc()
	assert.Nil(t, svc)
	assert.NotNil(t, c.Err)
}

// ============================================================
// keys.go — wrapKey and unwrapKey missing branches
// ============================================================

// TestWrapKey_MissingPlaintextKey_Returns400 verifies validation of plaintext_key.
func TestWrapKey_MissingPlaintextKey_Returns400(t *testing.T) {
	c := newCryptoContext(&stubCryptoSvc{})
	w := httptest.NewRecorder()
	body, _ := json.Marshal(map[string]any{"algorithm": "RSA-OAEP"})
	r := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(body))

	wrapKey(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestWrapKey_InvalidBase64PlaintextKey_Returns400 verifies base64 validation.
func TestWrapKey_InvalidBase64PlaintextKey_Returns400(t *testing.T) {
	c := newCryptoContext(&stubCryptoSvc{})
	w := httptest.NewRecorder()
	body, _ := json.Marshal(map[string]any{"plaintext_key": "not-valid-base64!!!", "algorithm": "RSA-OAEP"})
	r := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(body))

	wrapKey(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestUnwrapKey_MissingWrappedKeyField_Returns400 verifies validation of wrapped_key.
func TestUnwrapKey_MissingWrappedKeyField_Returns400(t *testing.T) {
	c := newCryptoContext(&stubCryptoSvc{})
	w := httptest.NewRecorder()
	body, _ := json.Marshal(map[string]any{"algorithm": "RSA-OAEP"})
	r := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(body))

	unwrapKey(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestUnwrapKey_InvalidBase64WrappedKeyField_Returns400 verifies base64 validation.
func TestUnwrapKey_InvalidBase64WrappedKeyField_Returns400(t *testing.T) {
	c := newCryptoContext(&stubCryptoSvc{})
	w := httptest.NewRecorder()
	body, _ := json.Marshal(map[string]any{"wrapped_key": "not-valid-base64!!!", "algorithm": "RSA-OAEP"})
	r := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(body))

	unwrapKey(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestWrapKey_ServiceForbidden_Returns403 verifies the forbidden error path in wrapKey.
func TestWrapKey_ServiceForbidden_Returns403(t *testing.T) {
	svc := &stubCryptoSvc{
		// WrapKey is overridden in keys_crypto_test.go to return "not implemented".
		// We need a svc that returns "forbidden" from WrapKey — use a custom stub.
	}
	_ = svc

	customSvc := &forbiddenWrapCryptoSvc{}
	c := newCryptoContext(customSvc)
	w := httptest.NewRecorder()
	body, _ := json.Marshal(map[string]any{
		"plaintext_key": base64.StdEncoding.EncodeToString([]byte("hello")),
		"algorithm":     "RSA-OAEP",
	})
	r := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(body))

	wrapKey(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusForbidden, w.Code)
}

// TestWrapKey_ServiceNotFound_Returns404 verifies the not-found error path in wrapKey.
func TestWrapKey_ServiceNotFound_Returns404(t *testing.T) {
	customSvc := &notFoundWrapCryptoSvc{}
	c := newCryptoContext(customSvc)
	w := httptest.NewRecorder()
	body, _ := json.Marshal(map[string]any{
		"plaintext_key": base64.StdEncoding.EncodeToString([]byte("hello")),
		"algorithm":     "RSA-OAEP",
	})
	r := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(body))

	wrapKey(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusNotFound, w.Code)
}

// TestWrapKey_ServiceUnsupportedAlgorithm_Returns400 verifies the algorithm error path.
func TestWrapKey_ServiceUnsupportedAlgorithm_Returns400(t *testing.T) {
	customSvc := &unsupportedAlgWrapCryptoSvc{}
	c := newCryptoContext(customSvc)
	w := httptest.NewRecorder()
	body, _ := json.Marshal(map[string]any{
		"plaintext_key": base64.StdEncoding.EncodeToString([]byte("hello")),
		"algorithm":     "BADALGXYZ",
	})
	r := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(body))

	wrapKey(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestWrapKey_ServiceSuccess_Returns200 verifies the happy path for wrapKey.
func TestWrapKey_ServiceSuccess_Returns200(t *testing.T) {
	customSvc := &successWrapCryptoSvc{}
	c := newCryptoContext(customSvc)
	w := httptest.NewRecorder()
	body, _ := json.Marshal(map[string]any{
		"plaintext_key": base64.StdEncoding.EncodeToString([]byte("hello")),
	})
	r := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(body))

	wrapKey(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusOK, w.Code)
}

// TestUnwrapKey_ServiceForbidden_Returns403 verifies the forbidden error path in unwrapKey.
func TestUnwrapKey_ServiceForbidden_Returns403(t *testing.T) {
	customSvc := &forbiddenUnwrapCryptoSvc{}
	c := newCryptoContext(customSvc)
	w := httptest.NewRecorder()
	body, _ := json.Marshal(map[string]any{
		"wrapped_key": base64.StdEncoding.EncodeToString([]byte("wrapped")),
		"algorithm":   "RSA-OAEP",
	})
	r := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(body))

	unwrapKey(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusForbidden, w.Code)
}

// TestUnwrapKey_ServiceSuccess_Returns200 verifies the happy path for unwrapKey.
func TestUnwrapKey_ServiceSuccess_Returns200(t *testing.T) {
	customSvc := &successUnwrapCryptoSvc{}
	c := newCryptoContext(customSvc)
	w := httptest.NewRecorder()
	body, _ := json.Marshal(map[string]any{
		"wrapped_key": base64.StdEncoding.EncodeToString([]byte("wrapped")),
	})
	r := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(body))

	unwrapKey(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusOK, w.Code)
}

// ============================================================
// keys.go — verifyKey missing error branches
// ============================================================

// TestVerifyKey_Forbidden_Returns403 verifies the forbidden error path.
func TestVerifyKey_Forbidden_Returns403(t *testing.T) {
	svc := &stubCryptoSvc{
		verifyFn: func(_ context.Context, _ keyServices.VerifyRequest) (*keyServices.VerifyResult, error) {
			return nil, fmt.Errorf("%w: key access denied", keyServices.ErrKeyForbidden)
		},
	}
	c := newCryptoContext(svc)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/", jsonBody(t, map[string]any{
		"value":     base64.StdEncoding.EncodeToString([]byte("data")),
		"signature": base64.StdEncoding.EncodeToString([]byte("sig")),
	}))

	verifyKey(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusForbidden, w.Code)
}

// TestVerifyKey_ServiceError_Returns500 verifies the generic error path.
func TestVerifyKey_ServiceError_Returns500(t *testing.T) {
	svc := &stubCryptoSvc{
		verifyFn: func(_ context.Context, _ keyServices.VerifyRequest) (*keyServices.VerifyResult, error) {
			return nil, errors.New("internal crypto failure")
		},
	}
	c := newCryptoContext(svc)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/", jsonBody(t, map[string]any{
		"value":     base64.StdEncoding.EncodeToString([]byte("data")),
		"signature": base64.StdEncoding.EncodeToString([]byte("sig")),
	}))

	verifyKey(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

// TestVerifyKey_InvalidValueBase64_Returns400 verifies value base64 validation.
func TestVerifyKey_InvalidValueBase64_Returns400(t *testing.T) {
	c := newCryptoContext(nil)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/", jsonBody(t, map[string]any{
		"value":     "not-base64!!!",
		"signature": base64.StdEncoding.EncodeToString([]byte("sig")),
	}))

	verifyKey(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ============================================================
// keys.go — encryptKey missing error branches
// ============================================================

// TestEncryptKey_Forbidden_Returns403 verifies the forbidden error path.
func TestEncryptKey_Forbidden_Returns403(t *testing.T) {
	svc := &stubCryptoSvc{
		encryptFn: func(_ context.Context, _ keyServices.EncryptRequest) (*keyServices.EncryptResult, error) {
			return nil, fmt.Errorf("%w: cannot encrypt with revoked key", keyServices.ErrKeyForbidden)
		},
	}
	c := newCryptoContext(svc)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/", jsonBody(t, map[string]any{
		"value": base64.StdEncoding.EncodeToString([]byte("plaintext")),
	}))

	encryptKey(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusForbidden, w.Code)
}

// TestEncryptKey_NotFound_Returns404 verifies the not-found error path.
func TestEncryptKey_NotFound_Returns404(t *testing.T) {
	svc := &stubCryptoSvc{
		encryptFn: func(_ context.Context, _ keyServices.EncryptRequest) (*keyServices.EncryptResult, error) {
			return nil, fmt.Errorf("%w: no rows in result set", keyServices.ErrKeyNotFound)
		},
	}
	c := newCryptoContext(svc)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/", jsonBody(t, map[string]any{
		"value": base64.StdEncoding.EncodeToString([]byte("plaintext")),
	}))

	encryptKey(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusNotFound, w.Code)
}

// TestEncryptKey_InvalidValueBase64_Returns400 verifies value base64 validation.
func TestEncryptKey_InvalidValueBase64_Returns400(t *testing.T) {
	c := newCryptoContext(nil)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/", jsonBody(t, map[string]any{
		"value": "not-valid-base64!!!",
	}))

	encryptKey(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ============================================================
// keys.go — decryptKey missing error branches
// ============================================================

// TestDecryptKey_InvalidValueBase64_Returns400 verifies value base64 validation.
func TestDecryptKey_InvalidValueBase64_Returns400(t *testing.T) {
	c := newCryptoContext(nil)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/", jsonBody(t, map[string]any{
		"value": "not-valid-base64!!!",
	}))

	decryptKey(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestDecryptKey_UnsupportedAlgorithm_Returns400 verifies unsupported algorithm path.
func TestDecryptKey_UnsupportedAlgorithm_Returns400(t *testing.T) {
	svc := &stubCryptoSvc{
		decryptFn: func(_ context.Context, _ keyServices.DecryptRequest) (*keyServices.DecryptResult, error) {
			return nil, fmt.Errorf("%w: FOOBAR", keyServices.ErrUnsupportedAlgorithm)
		},
	}
	c := newCryptoContext(svc)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/", jsonBody(t, map[string]any{
		"value":     base64.StdEncoding.EncodeToString([]byte("ct")),
		"algorithm": "FOOBAR",
	}))

	decryptKey(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ============================================================
// Stub crypto service types for wrapKey / unwrapKey tests
// ============================================================

// forbiddenWrapCryptoSvc returns "forbidden" from WrapKey.
type forbiddenWrapCryptoSvc struct{ stubCryptoSvc }

func (s *forbiddenWrapCryptoSvc) WrapKey(_ context.Context, _ keyServices.WrapKeyRequest) (*keyServices.WrapKeyResult, error) {
	return nil, fmt.Errorf("%w: key access denied", keyServices.ErrKeyForbidden)
}

// notFoundWrapCryptoSvc returns "not found" from WrapKey.
type notFoundWrapCryptoSvc struct{ stubCryptoSvc }

func (s *notFoundWrapCryptoSvc) WrapKey(_ context.Context, _ keyServices.WrapKeyRequest) (*keyServices.WrapKeyResult, error) {
	return nil, fmt.Errorf("%w: no rows", keyServices.ErrKeyNotFound)
}

// unsupportedAlgWrapCryptoSvc returns "unsupported algorithm" from WrapKey.
type unsupportedAlgWrapCryptoSvc struct{ stubCryptoSvc }

func (s *unsupportedAlgWrapCryptoSvc) WrapKey(_ context.Context, _ keyServices.WrapKeyRequest) (*keyServices.WrapKeyResult, error) {
	return nil, fmt.Errorf("%w: BADALGXYZ", keyServices.ErrUnsupportedAlgorithm)
}

// successWrapCryptoSvc returns a valid result from WrapKey.
type successWrapCryptoSvc struct{ stubCryptoSvc }

func (s *successWrapCryptoSvc) WrapKey(_ context.Context, req keyServices.WrapKeyRequest) (*keyServices.WrapKeyResult, error) {
	return &keyServices.WrapKeyResult{
		WrappedKey: []byte("wrapped-key-bytes"),
		Algorithm:  req.Algorithm,
	}, nil
}

// forbiddenUnwrapCryptoSvc returns "forbidden" from UnwrapKey.
type forbiddenUnwrapCryptoSvc struct{ stubCryptoSvc }

func (s *forbiddenUnwrapCryptoSvc) UnwrapKey(_ context.Context, _ keyServices.UnwrapKeyRequest) (*keyServices.UnwrapKeyResult, error) {
	return nil, fmt.Errorf("%w: key access revoked", keyServices.ErrKeyForbidden)
}

// successUnwrapCryptoSvc returns a valid result from UnwrapKey.
type successUnwrapCryptoSvc struct{ stubCryptoSvc }

func (s *successUnwrapCryptoSvc) UnwrapKey(_ context.Context, req keyServices.UnwrapKeyRequest) (*keyServices.UnwrapKeyResult, error) {
	return &keyServices.UnwrapKeyResult{
		PlaintextKey: []byte("plaintext-key"),
		Algorithm:    req.Algorithm,
	}, nil
}

// ============================================================
// Ensure unused crypto import is used
// ============================================================

// ============================================================
// keys.go — getKey admin path
// ============================================================

// TestGetKey_AdminPath_GetKeyError_Returns404 exercises the legacy flat route
// where a failed per-user lookup makes the handler return 404.
func TestGetKey_AdminPath_GetKeyFailsValidationFails_Returns404(t *testing.T) {
	keyID := uuid.New()

	svc := &mockKeyService{}
	// Legacy flat route (no vault_name) uses default-vault visibility via GetKey;
	// the not-found sentinel makes the handler return 404.
	svc.On("GetKey", mock.Anything, keyID, keyLegacyVaultScope()).Return((*model.Key)(nil), keyServices.ErrKeyNotFound)

	c := newKeyCtx(svc)
	c.Params = &ApiParams{KeyID: keyID.String(), PerPage: 60}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/keys/"+keyID.String(), nil)

	getKey(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusNotFound, w.Code)
	svc.AssertExpectations(t)
}

// TestGetKey_AdminPath_RetryGetKeyFails_Returns404 verifies that the legacy flat
// route still returns 404 when the per-user lookup fails.
func TestGetKey_AdminPath_RetryGetKeyFails_Returns404(t *testing.T) {
	keyID := uuid.New()

	svc := &mockKeyService{}
	// Legacy flat route (no vault_name) uses default-vault visibility via GetKey;
	// the not-found sentinel maps to 404.
	svc.On("GetKey", mock.Anything, keyID, keyLegacyVaultScope()).Return((*model.Key)(nil), keyServices.ErrKeyNotFound)

	c := newKeyCtx(svc)
	c.Params = &ApiParams{KeyID: keyID.String(), PerPage: 60}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/keys/"+keyID.String(), nil)

	getKey(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusNotFound, w.Code)
	svc.AssertExpectations(t)
}

// ============================================================
// secrets.go — updateSecret with value/tags change
// ============================================================

// TestUpdateSecret_ValueChange_Returns200 verifies that updating the value succeeds.
func TestUpdateSecret_ValueChange_Returns200(t *testing.T) {
	secretID := uuid.New()
	svc := &mockSecretService{}
	existing := makeSecretModel(secretID)
	svc.On("GetSecret", mock.Anything, secretID, mock.Anything).Return(existing, nil)
	svc.On("UpdateSecret", mock.Anything, mock.Anything).Return(nil)

	c := buildUpdateSecretCtx(svc, secretID.String())
	w := httptest.NewRecorder()
	body, _ := json.Marshal(map[string]any{"value": "new-value"})
	r := httptest.NewRequest(http.MethodPut, "/secrets/"+secretID.String(), bytes.NewReader(body))

	updateSecret(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusOK, w.Code)
}

// TestUpdateSecret_TagsChange_Returns200 verifies that updating tags succeeds.
func TestUpdateSecret_TagsChange_Returns200(t *testing.T) {
	secretID := uuid.New()
	svc := &mockSecretService{}
	existing := makeSecretModel(secretID)
	svc.On("GetSecret", mock.Anything, secretID, mock.Anything).Return(existing, nil)
	svc.On("UpdateSecret", mock.Anything, mock.Anything).Return(nil)

	c := buildUpdateSecretCtx(svc, secretID.String())
	w := httptest.NewRecorder()
	body, _ := json.Marshal(map[string]any{"tags": []string{"env:prod", "team:backend"}})
	r := httptest.NewRequest(http.MethodPut, "/secrets/"+secretID.String(), bytes.NewReader(body))

	updateSecret(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusOK, w.Code)
}

// ============================================================
// audit.go — non-admin checks for config endpoints
// ============================================================

// TestGetAuditConfig_NonAdmin_Returns403 verifies the non-admin path.
func TestGetAuditConfig_NonAdmin_Returns403(t *testing.T) {
	c := &Context{
		App:    &app.App{},
		Claims: RequestClaims{Roles: []string{"viewer"}},
		Params: &ApiParams{},
	}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/audit/config", nil)

	getAuditConfig(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusForbidden, w.Code)
}

// TestPatchAuditConfig_NonAdmin_Returns403 verifies the non-admin path.
func TestPatchAuditConfig_NonAdmin_Returns403(t *testing.T) {
	c := &Context{
		App:    &app.App{},
		Claims: RequestClaims{Roles: []string{"viewer"}},
		Params: &ApiParams{},
	}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPatch, "/audit/config", strings.NewReader(`{"retention_days":90}`))

	patchAuditConfig(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusForbidden, w.Code)
}

// TestGetSOC2Report_NonAdmin_Returns403 verifies the non-admin path.
func TestGetSOC2Report_NonAdmin_Returns403(t *testing.T) {
	c := &Context{
		App:    &app.App{},
		Claims: RequestClaims{Roles: []string{"viewer"}},
		Params: &ApiParams{},
	}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/audit/reports/soc2?from=2026-01-01T00:00:00Z&to=2026-12-31T23:59:59Z", nil)

	getSOC2Report(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusForbidden, w.Code)
}

// TestGetGDPRReport_NonAdmin_Returns403 verifies the non-admin path.
func TestGetGDPRReport_NonAdmin_Returns403(t *testing.T) {
	c := &Context{
		App:    &app.App{},
		Claims: RequestClaims{Roles: []string{"viewer"}},
		Params: &ApiParams{},
	}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/audit/reports/gdpr?subject_id=u1&from=2026-01-01T00:00:00Z&to=2026-12-31T23:59:59Z", nil)

	getGDPRReport(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusForbidden, w.Code)
}

// ============================================================
// Ensure unused crypto import is used
// ============================================================

var _ = crypto.SignatureAlgorithm("")
