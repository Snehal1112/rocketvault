package api

// Audit-first handler tests for exports, purges and deletes: when the service
// refuses because its critical audit row could not be written, the handler
// answers 503 with exactly "audit unavailable" and nothing else.

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"rocketvault/model"
)

// assertExportAuditUnavailable checks the R6 503 an export answers.
func assertExportAuditUnavailable(t *testing.T, w *httptest.ResponseRecorder) {
	t.Helper()
	require.Equal(t, http.StatusServiceUnavailable, w.Code, w.Body.String())
	assert.Equal(t, "no-store", w.Header().Get("Cache-Control"))
	detail := decodeExportError(t, w.Body.Bytes())
	assert.Equal(t, "audit_unavailable", detail.Code)
	assert.Equal(t, "audit unavailable", detail.Message)
	assert.NotContains(t, w.Body.String(), handlerAuditCause)
	assert.NotContains(t, w.Body.String(), "private_key_pem")
	assert.NotContains(t, w.Body.String(), "pkcs12_base64")
}

// assertFlatAuditUnavailable checks the flat 503 body every other route answers.
func assertFlatAuditUnavailable(t *testing.T, w *httptest.ResponseRecorder) {
	t.Helper()
	require.Equal(t, http.StatusServiceUnavailable, w.Code, w.Body.String())
	var body map[string]any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
	assert.Equal(t, "audit unavailable", body["message"])
	assert.Empty(t, body["detailed_error"])
	assert.NotContains(t, w.Body.String(), handlerAuditCause)
}

func TestExportKeyHandler_AuditUnavailable_Returns503R6(t *testing.T) {
	keyID := uuid.New()
	svc := &mockKeyService{}
	svc.On("ExportKey", mock.Anything, mock.Anything, keyID, 0).Return(nil, realAuditUnavailableErr(t))
	audit := &captureAudit{}

	w := runKeyExport(t, svc, audit, keyID.String(), "")

	assertExportAuditUnavailable(t, w)
	require.Len(t, audit.events, 1, "the failure is still offered to exportaudit")
	assert.Equal(t, "failure", audit.events[0].Outcome)
}

func TestExportCertificateHandler_AuditUnavailable_Returns503R6(t *testing.T) {
	certID := uuid.New()
	svc := &mockCertService{}
	svc.On("ExportCertificate", mock.Anything, mock.Anything, certID, mock.Anything).Return(nil, realAuditUnavailableErr(t))

	w := runCertExport(t, svc, &captureAudit{}, certID.String(), `{"format":"pem"}`)

	assertExportAuditUnavailable(t, w)
}

func TestPurgeSecret_AuditUnavailable_Returns503(t *testing.T) {
	secretID := uuid.New()
	svc := &mockSecretService{}
	svc.On("PurgeSecret", mock.Anything, secretID, mock.Anything).Return(realAuditUnavailableErr(t))
	c := newSecretCtx(svc)
	c.Params = &ApiParams{SecretID: secretID.String(), PerPage: 60}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodDelete, "/deleted/secrets/"+secretID.String()+"/purge", nil)

	purgeSecret(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assertFlatAuditUnavailable(t, w)
}

func TestDeleteUser_AuditUnavailable_Returns503(t *testing.T) {
	svc := &mockUserService{}
	targetID := uuid.New()
	svc.On("GetUser", mock.Anything, targetID).Return(&model.User{ID: targetID, Username: "target", CreatedAt: time.Now()}, nil)
	svc.On("DeleteUser", mock.Anything, targetID, mock.Anything).Return(realAuditUnavailableErr(t))
	c := newUserCtx(svc, nil, uAdminClaims(uuid.NewString()))
	c.Params = &ApiParams{UserID: targetID.String(), PerPage: 60}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodDelete, "/users/"+targetID.String(), nil)

	deleteUser(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assertFlatAuditUnavailable(t, w)
}
