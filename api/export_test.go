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
	"sync"
	"testing"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"rocketvault/app"
	"rocketvault/internal/logging"
	auditServices "rocketvault/internal/services/audit"
	authzServices "rocketvault/internal/services/authorization"
	certServices "rocketvault/internal/services/certificates"
	keyservices "rocketvault/internal/services/keys"
	"rocketvault/model"
)

// captureAudit records every audit write so tests can assert on content.
type captureAudit struct {
	mu        sync.Mutex
	events    []auditServices.AuditEvent
	persisted []string
}

func (a *captureAudit) RecordEvent(_ context.Context, e auditServices.AuditEvent) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.events = append(a.events, e)
	return nil
}

func (a *captureAudit) PersistAudit(userID, action, details string) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.persisted = append(a.persisted, userID+" "+action+" "+details)
	return nil
}

func (a *captureAudit) dump() string {
	a.mu.Lock()
	defer a.mu.Unlock()
	b, _ := json.Marshal(a.events)
	return string(b) + strings.Join(a.persisted, "\n")
}

// exportTestContainer serves the certificate and key services and an
// audit capture; everything else comes from certSvcContainer.
type exportTestContainer struct {
	*certSvcContainer
	keySvc keyservices.KeyService
	audit  *captureAudit
}

func (c *exportTestContainer) GetKeyService() keyservices.KeyService { return c.keySvc }
func (c *exportTestContainer) GetAuditService() auditServices.AuditServiceInterface {
	return c.audit
}

// newExportCtx builds a handler context whose logger writes to a buffer and
// persists legacy audit rows into audit, so a test can assert that the
// handler writes no legacy row and can read what it logged.
func newExportCtx(certSvc certServices.CertificateService, keySvc keyservices.KeyService, audit *captureAudit) *Context {
	a := &app.App{ServiceContainer: &exportTestContainer{certSvcContainer: &certSvcContainer{certSvc: certSvc}, keySvc: keySvc, audit: audit}}
	l := logrus.New()
	l.SetOutput(&bytes.Buffer{})
	l.SetLevel(logrus.DebugLevel)
	logger := logging.WrapLogrus(l)
	if audit != nil {
		logger.SetAuditPersister(audit)
	}
	return &Context{App: a, Claims: certAdminClaims(), Params: &ApiParams{PerPage: 60}, Logger: logger}
}

// exportLogs returns everything the handler logged through c.Logger.
func exportLogs(t *testing.T, c *Context) string {
	t.Helper()
	buf, ok := c.Logger.Out.(*bytes.Buffer)
	require.True(t, ok, "newExportCtx logs to a buffer")
	return buf.String()
}

func decodeExportError(t *testing.T, body []byte) exportErrorDetail {
	t.Helper()
	var parsed exportErrorBody
	require.NoError(t, json.Unmarshal(body, &parsed), string(body))
	require.NotEmpty(t, parsed.Error.Code, string(body))
	return parsed.Error
}

func runCertExport(t *testing.T, svc certServices.CertificateService, audit *captureAudit, certID, body string) *httptest.ResponseRecorder {
	t.Helper()
	c := newExportCtx(svc, nil, audit)
	c.Params.CertificateID = certID
	w := httptest.NewRecorder()
	exportCertificate(c, w, httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/certificates/"+certID+"/export", bytes.NewBufferString(body)))
	require.Nil(t, c.Err, "export handlers never set c.Err; they write the R6 body themselves")
	return w
}

func TestExportCertificateHandler_PEMSuccess(t *testing.T) {
	certID := uuid.New()
	svc := &mockCertService{}
	svc.On("ExportCertificate", mock.Anything, certLegacyVaultScope(), certID, certServices.ExportCertificateRequest{Format: "pem"}).
		Return(&certServices.ExportCertificateResult{ID: certID, Name: "client", Version: 2, Format: "pem",
			CertificatePEM: "CHAIN", PrivateKeyPEM: "-----BEGIN PRIVATE KEY-----\nK\n-----END PRIVATE KEY-----\n", KeyAlgorithm: "EC-P256"}, nil)
	audit := &captureAudit{}

	w := runCertExport(t, svc, audit, certID.String(), `{"format":"pem"}`)
	require.Equal(t, http.StatusOK, w.Code, "the export succeeds; the body is not printed because it holds key material")
	assert.Equal(t, "no-store", w.Header().Get("Cache-Control"))
	assert.Equal(t, "no-cache", w.Header().Get("Pragma"))
	assert.Empty(t, w.Header().Get("Content-Disposition"))
	assert.Less(t, w.Body.Len(), 64<<10)

	var body map[string]any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
	assert.Equal(t, "pem", body["format"])
	assert.Equal(t, "CHAIN", body["certificate_pem"])
	assert.Equal(t, "EC-P256", body["key_algorithm"])
	assert.EqualValues(t, 2, body["version"])
	_, hasPKCS12 := body["pkcs12_base64"]
	assert.False(t, hasPKCS12, "a pem export has no pkcs12_base64 field")

	require.Len(t, audit.events, 1)
	ev := audit.events[0]
	assert.Equal(t, "export_certificate", ev.Action)
	assert.Equal(t, "success", ev.Outcome)
	assert.Equal(t, "certificate", ev.ResourceType)
	assert.Equal(t, certID.String(), ev.ResourceID)
	assert.Equal(t, certTestUserID, ev.UserID)
	assert.Contains(t, ev.Details, `"format":"pem"`)
	assert.Contains(t, ev.Details, `"name":"client"`)
	assert.Contains(t, ev.Details, `"version":2`)
	assert.Contains(t, ev.Details, model.DefaultVaultID)
	assert.False(t, strings.Contains(audit.dump(), "PRIVATE KEY"), "key material reached the audit trail")
}

func TestExportCertificateHandler_PKCS12Success(t *testing.T) {
	certID := uuid.New()
	password := "hunter2-export"
	svc := &mockCertService{}
	svc.On("ExportCertificate", mock.Anything, certLegacyVaultScope(), certID,
		certServices.ExportCertificateRequest{Format: "pkcs12", Password: &password, Compat: "legacy"}).
		Return(&certServices.ExportCertificateResult{ID: certID, Name: "client", Version: 1, Format: "pkcs12", PKCS12: []byte{1, 2, 3}, KeyAlgorithm: "RSA-2048"}, nil)
	audit := &captureAudit{}

	w := runCertExport(t, svc, audit, certID.String(), `{"format":"pkcs12","password":"hunter2-export","compat":"legacy"}`)
	require.Equal(t, http.StatusOK, w.Code, "the export succeeds; the body is not printed because it holds key material")
	var body map[string]any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body), "the success body is JSON")
	assert.True(t, body["pkcs12_base64"] == base64.StdEncoding.EncodeToString([]byte{1, 2, 3}), "pkcs12_base64 carries the service's bytes")
	_, hasKey := body["private_key_pem"]
	assert.False(t, hasKey, "a pkcs12 export has no private_key_pem field")
	assert.False(t, strings.Contains(audit.dump(), password), "the pkcs12 password reached the audit trail")
}

// TestExportCertificateHandler_ErrorBodiesAreR6AndGeneric pins Review Focus
// 1: every failure uses the R6 body, and an internal failure exposes no
// detail.
func TestExportCertificateHandler_ErrorBodiesAreR6AndGeneric(t *testing.T) {
	certID := uuid.New()
	cases := []struct {
		name, body string
		err        error
		status     int
		code       string
	}{
		{"bad json", `{"format":`, nil, http.StatusBadRequest, "bad_request"},
		{"empty body", ``, nil, http.StatusBadRequest, "bad_request"},
		{"invalid request", `{"format":"der"}`, fmt.Errorf("%w: format must be pem or pkcs12", model.ErrInvalidExportRequest), http.StatusBadRequest, "bad_request"},
		{"not found", `{"format":"pem"}`, fmt.Errorf("%w: x", certServices.ErrCertNotFound), http.StatusNotFound, "not_found"},
		{"no version", `{"format":"pem","version":9}`, fmt.Errorf("%w: x", model.ErrCertificateVersionNotFound), http.StatusNotFound, "not_found"},
		{"disabled", `{"format":"pem"}`, certServices.ErrCertLifecycleDenied, http.StatusConflict, "certificate_disabled"},
		{"refused", `{"format":"pem"}`, &model.ExportRefusedError{Sentinel: model.ErrCertificateNotExportable, Reason: "flag is false", KeyAlgorithm: "RSA-2048"}, http.StatusForbidden, "certificate_not_exportable"},
		{"internal", `{"format":"pem"}`, errors.New("sql: database driver detail secret-ish"), http.StatusInternalServerError, "internal_error"},
		{"chain", `{"format":"pem"}`, fmt.Errorf("%w: cycle", certServices.ErrCertificateChainUnavailable), http.StatusInternalServerError, "internal_error"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			svc := &mockCertService{}
			if tc.err != nil {
				svc.On("ExportCertificate", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(nil, tc.err)
			}
			audit := &captureAudit{}
			w := runCertExport(t, svc, audit, certID.String(), tc.body)
			require.Equal(t, tc.status, w.Code, w.Body.String())
			assert.Equal(t, "no-store", w.Header().Get("Cache-Control"))
			detail := decodeExportError(t, w.Body.Bytes())
			assert.Equal(t, tc.code, detail.Code)
			assert.NotContains(t, w.Body.String(), "detailed_error")
			assert.NotContains(t, w.Body.String(), "driver detail")
			if tc.code == "certificate_not_exportable" {
				assert.Equal(t, "RSA-2048", detail.KeyAlgorithm)
				assert.Contains(t, detail.Message, "flag is false")
			}
			require.Len(t, audit.events, 1, "every attempt is audited")
			assert.Equal(t, "failure", audit.events[0].Outcome)
			assert.Equal(t, certID.String(), audit.events[0].ResourceID)
		})
	}
}

func TestExportCertificateHandler_BadIDIs400(t *testing.T) {
	audit := &captureAudit{}
	w := runCertExport(t, &mockCertService{}, audit, "not-a-uuid", `{"format":"pem"}`)
	require.Equal(t, http.StatusBadRequest, w.Code)
	assert.Equal(t, "bad_request", decodeExportError(t, w.Body.Bytes()).Code)
	require.Len(t, audit.events, 1)
}

func TestExportCertificateRoutes_BothShapes(t *testing.T) {
	certID := uuid.New().String()
	t.Run("flat", func(t *testing.T) {
		rec := &recordingCertService{}
		api, _ := newVaultScopedKeyCertTestAPI(nil, rec, nil)
		w := doVaultRequest(api, http.MethodPost, "/api/v1/certificates/"+certID+"/export", []byte(`{"format":"pem"}`))
		require.Equal(t, http.StatusOK, w.Code, "the export succeeds; the body is not printed because it holds key material")
		assert.Equal(t, uuid.MustParse(model.DefaultVaultID), rec.versionScope.VaultID())
		assert.Equal(t, "no-store", w.Header().Get("Cache-Control"))
	})
	t.Run("vault-scoped", func(t *testing.T) {
		rec := &recordingCertService{}
		api, repo := newVaultScopedKeyCertTestAPI(nil, rec, nil)
		id := uuid.New()
		repo.byName["prod"] = &model.Vault{ID: id, Name: "prod", Enabled: true}
		repo.byID[id.String()] = repo.byName["prod"]
		w := doVaultRequest(api, http.MethodPost, "/api/v1/vaults/prod/certificates/"+certID+"/export", []byte(`{"format":"pem"}`))
		require.Equal(t, http.StatusOK, w.Code, "the export succeeds; the body is not printed because it holds key material")
		assert.Equal(t, id, rec.versionScope.VaultID())
	})
}

// TestExportCertificateHandler_EveryFailureAuditedOnceWithReason pins the
// Task 2 carry-over: failure paths the service does not audit itself
// (versioning unavailable, decrypt, classify, parse, PKCS12 encode, chain)
// still produce exactly one structured audit event, with a fixed reason and
// none of the raw error text.
func TestExportCertificateHandler_EveryFailureAuditedOnceWithReason(t *testing.T) {
	certID := uuid.New()
	foreignCA := uuid.New().String()
	cases := []struct {
		name   string
		err    error
		status int
		code   string
		reason string
	}{
		{"versioning unavailable", certServices.ErrCertVersioningUnavailable, http.StatusInternalServerError, "internal_error", "certificate versioning unavailable"},
		{"decrypt", fmt.Errorf("decrypt certificate key: %w", errors.New("cipher: message authentication failed")), http.StatusInternalServerError, "internal_error", "internal failure"},
		{"classify", fmt.Errorf("classify certificate key: %w", errors.New("unknown PEM block raw-detail")), http.StatusInternalServerError, "internal_error", "internal failure"},
		{"parse", fmt.Errorf("parse certificate key: %w", errors.New("asn1: structure error raw-detail")), http.StatusInternalServerError, "internal_error", "internal failure"},
		{"pkcs12 encode", fmt.Errorf("pkcs12: encode raw-detail"), http.StatusInternalServerError, "internal_error", "internal failure"},
		{"chain cycle", fmt.Errorf("%w: cycle at %s", certServices.ErrCertificateChainUnavailable, foreignCA), http.StatusInternalServerError, "internal_error", "certificate chain unavailable"},
		{"chain foreign issuer", fmt.Errorf("%w: issuer %s is not readable", certServices.ErrCertificateChainUnavailable, foreignCA), http.StatusInternalServerError, "internal_error", "certificate chain unavailable"},
		{"version not found", fmt.Errorf("%w: certificate %s has no version 9", model.ErrCertificateVersionNotFound, certID), http.StatusNotFound, "not_found", "certificate or version not found"},
		{"negative version", fmt.Errorf("%w: version must be 0 or a positive version number", model.ErrInvalidExportRequest), http.StatusBadRequest, "bad_request", "invalid export request"},
		{"pkcs12 without password", fmt.Errorf("%w: pkcs12 requires a password field (it may be empty)", model.ErrInvalidExportRequest), http.StatusBadRequest, "bad_request", "invalid export request"},
		{"bad compat", fmt.Errorf("%w: compat must be modern or legacy", model.ErrInvalidExportRequest), http.StatusBadRequest, "bad_request", "invalid export request"},
		{"disabled", certServices.ErrCertLifecycleDenied, http.StatusConflict, "certificate_disabled", "certificate or version disabled"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			svc := &mockCertService{}
			svc.On("ExportCertificate", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(nil, tc.err)
			audit := &captureAudit{}
			w := runCertExport(t, svc, audit, certID.String(), `{"format":"pem","version":3}`)
			require.Equal(t, tc.status, w.Code, w.Body.String())
			detail := decodeExportError(t, w.Body.Bytes())
			assert.Equal(t, tc.code, detail.Code)
			if tc.status == http.StatusInternalServerError {
				assert.Equal(t, "internal server error", detail.Message, "a 500 never echoes the error")
			}
			assert.NotContains(t, w.Body.String(), "raw-detail")
			assert.NotContains(t, w.Body.String(), foreignCA, "a CA id from another vault never reaches the client")
			assert.NotContains(t, w.Body.String(), "cipher:")

			require.Len(t, audit.events, 1, "exactly one structured event per attempt")
			assert.Empty(t, audit.persisted, "the handler writes no second, legacy audit row")
			ev := audit.events[0]
			assert.Equal(t, "failure", ev.Outcome)
			assert.Equal(t, "export_certificate", ev.Action)
			assert.Equal(t, "certificate", ev.ResourceType)
			assert.Equal(t, certID.String(), ev.ResourceID)
			assert.Equal(t, certTestUserID, ev.UserID)
			assert.Contains(t, ev.Details, `"reason":"`+tc.reason+`"`)
			assert.Contains(t, ev.Details, `"code":"`+tc.code+`"`)
			assert.Contains(t, ev.Details, `"format":"pem"`)
			assert.Contains(t, ev.Details, `"version":3`)
			assert.Contains(t, ev.Details, model.DefaultVaultID)
			assert.NotContains(t, ev.Details, "raw-detail")
			assert.NotContains(t, ev.Details, foreignCA)
			assert.NotContains(t, ev.Details, "cipher:")
		})
	}
}

// TestExportCertificateHandler_RefusalAuditCarriesNameAndReason pins that a
// not-exportable refusal audits the certificate name and the fixed reason.
func TestExportCertificateHandler_RefusalAuditCarriesNameAndReason(t *testing.T) {
	certID := uuid.New()
	svc := &mockCertService{}
	svc.On("ExportCertificate", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(nil,
		&model.ExportRefusedError{Sentinel: model.ErrCertificateNotExportable, Reason: "the certificate was not created with exportable: true", Name: "web", KeyAlgorithm: "EC-P256"})
	audit := &captureAudit{}
	w := runCertExport(t, svc, audit, certID.String(), `{"format":"pem"}`)
	require.Equal(t, http.StatusForbidden, w.Code)
	detail := decodeExportError(t, w.Body.Bytes())
	assert.Equal(t, "EC-P256", detail.KeyAlgorithm)
	require.Len(t, audit.events, 1)
	assert.Contains(t, audit.events[0].Details, `"name":"web"`)
	assert.Contains(t, audit.events[0].Details, `"reason":"the certificate was not created with exportable: true"`)
	assert.Contains(t, audit.events[0].Details, `"code":"certificate_not_exportable"`)
}

// TestExportCertificateHandler_PasswordNeverInFailureAudit pins that a
// pkcs12 password survives neither the error body nor the audit on failure.
func TestExportCertificateHandler_PasswordNeverInFailureAudit(t *testing.T) {
	certID := uuid.New()
	svc := &mockCertService{}
	svc.On("ExportCertificate", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(nil, errors.New("boom"))
	audit := &captureAudit{}
	w := runCertExport(t, svc, audit, certID.String(), `{"format":"pkcs12","password":"s3cret-pass-xyz"}`)
	require.Equal(t, http.StatusInternalServerError, w.Code)
	assert.False(t, strings.Contains(w.Body.String(), "s3cret-pass-xyz"), "the pkcs12 password reached the error body")
	assert.False(t, strings.Contains(audit.dump(), "s3cret-pass-xyz"), "the pkcs12 password reached the audit trail")
	require.Len(t, audit.events, 1)
}

// TestExportCertificateRoutes_MapToExportAction walks the real router and
// pins that both registered export routes require the certificate export
// data action, not a broader or weaker one.
func TestExportCertificateRoutes_MapToExportAction(t *testing.T) {
	container := &routerWalkContainer{policyContainer: &policyContainer{}, logger: userTestLog()}
	a := &app.App{ServiceContainer: container, Logger: userTestLog()}
	router := mux.NewRouter()
	require.NotNil(t, Init(WithAPP(a), WithRouter(router), WithBasePath("/api/v1"), WithLogger(userTestLog())))

	found := 0
	require.NoError(t, router.Walk(func(route *mux.Route, _ *mux.Router, _ []*mux.Route) error {
		tmpl, err := route.GetPathTemplate()
		if err != nil || !strings.HasSuffix(tmpl, "/export") || !strings.Contains(tmpl, "/certificates/") {
			return nil
		}
		methods, _ := route.GetMethods()
		assert.Equal(t, []string{http.MethodPost}, methods, tmpl)
		action, kind := authzServices.MapRouteToDataAction(http.MethodPost, tmpl)
		assert.Equal(t, authzServices.RouteVaultData, kind, tmpl)
		assert.Equal(t, model.ActionCertificatesExportItem, action, tmpl)
		found++
		return nil
	}))
	assert.Equal(t, 2, found, "the export route is registered on the flat and vault-scoped shapes")
}

// TestExportCertificateHandler_UnknownFormatIsNotCopiedToAudit pins that a
// client-chosen format string never reaches the audit trail verbatim.
func TestExportCertificateHandler_UnknownFormatIsNotCopiedToAudit(t *testing.T) {
	svc := &mockCertService{}
	svc.On("ExportCertificate", mock.Anything, mock.Anything, mock.Anything, mock.Anything).
		Return(nil, fmt.Errorf("%w: format must be pem or pkcs12", model.ErrInvalidExportRequest))
	audit := &captureAudit{}
	w := runCertExport(t, svc, audit, uuid.New().String(), `{"format":"hunter2-pasted-here"}`)
	require.Equal(t, http.StatusBadRequest, w.Code)
	require.Len(t, audit.events, 1)
	assert.False(t, strings.Contains(audit.dump(), "hunter2-pasted-here"), "client format text reached the audit trail")
	assert.Contains(t, audit.events[0].Details, `"format":"invalid"`)
}

// TestExportHandlers_Log500CauseServerSideOnly pins that an export 500
// leaves the underlying error and a fixed step label in the server log,
// while the client body stays generic and a 4xx logs nothing. The pkcs12
// password and key material never reach the log.
func TestExportHandlers_Log500CauseServerSideOnly(t *testing.T) {
	password := "s3cret-pass-in-500"
	t.Run("certificate 500", func(t *testing.T) {
		svc := &mockCertService{}
		svc.On("ExportCertificate", mock.Anything, mock.Anything, mock.Anything, mock.Anything).
			Return(nil, fmt.Errorf("%w: issuer x did not sign the certificate below it", certServices.ErrCertificateChainUnavailable))
		c := newExportCtx(svc, nil, &captureAudit{})
		c.Params.CertificateID = uuid.NewString()
		w := httptest.NewRecorder()
		exportCertificate(c, w, httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/export",
			bytes.NewBufferString(`{"format":"pkcs12","password":"`+password+`"}`)))
		require.Equal(t, http.StatusInternalServerError, w.Code)
		assert.Equal(t, "internal server error", decodeExportError(t, w.Body.Bytes()).Message)
		logs := exportLogs(t, c)
		assert.Contains(t, logs, "export_certificate")
		assert.Contains(t, logs, "certificate chain unavailable", "the fixed step label is logged")
		assert.Contains(t, logs, "did not sign the certificate below it", "the cause is logged")
		assert.False(t, strings.Contains(logs, password), "the pkcs12 password reached the log")
	})
	t.Run("key 500", func(t *testing.T) {
		svc := &mockKeyService{}
		svc.On("ExportKey", mock.Anything, mock.Anything, mock.Anything, mock.Anything).
			Return(nil, errors.New("decrypt key material: cipher: message authentication failed"))
		c := newExportCtx(nil, svc, &captureAudit{})
		c.Params.KeyID = uuid.NewString()
		w := httptest.NewRecorder()
		exportKey(c, w, httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/export", &bytes.Buffer{}))
		require.Equal(t, http.StatusInternalServerError, w.Code)
		logs := exportLogs(t, c)
		assert.Contains(t, logs, "export_key")
		assert.Contains(t, logs, "internal failure")
		assert.Contains(t, logs, "message authentication failed")
		assert.False(t, strings.Contains(logs, "PRIVATE KEY"), "key material reached the log")
	})
	t.Run("4xx is not logged", func(t *testing.T) {
		svc := &mockCertService{}
		svc.On("ExportCertificate", mock.Anything, mock.Anything, mock.Anything, mock.Anything).
			Return(nil, fmt.Errorf("%w: x", certServices.ErrCertNotFound))
		c := newExportCtx(svc, nil, &captureAudit{})
		c.Params.CertificateID = uuid.NewString()
		w := httptest.NewRecorder()
		exportCertificate(c, w, httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/export", bytes.NewBufferString(`{"format":"pem"}`)))
		require.Equal(t, http.StatusNotFound, w.Code)
		assert.NotContains(t, exportLogs(t, c), "export failed")
	})
	t.Run("nil logger is tolerated", func(t *testing.T) {
		svc := &mockCertService{}
		svc.On("ExportCertificate", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(nil, errors.New("boom"))
		c := newExportCtx(svc, nil, &captureAudit{})
		c.Logger = nil
		c.Params.CertificateID = uuid.NewString()
		w := httptest.NewRecorder()
		exportCertificate(c, w, httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/export", bytes.NewBufferString(`{"format":"pem"}`)))
		require.Equal(t, http.StatusInternalServerError, w.Code)
	})
}
