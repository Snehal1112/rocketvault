package api

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"rocketvault/app"
	authzServices "rocketvault/internal/services/authorization"
	keyServices "rocketvault/internal/services/keys"
	"rocketvault/model"
)

// These tests never compare key material with assert.Equal or NotContains on
// a body that holds it, because a failure would print the material. They
// compare digests or use booleans with a static message instead.

func runKeyExport(t *testing.T, svc keyServices.KeyService, audit *captureAudit, keyID, body string) *httptest.ResponseRecorder {
	t.Helper()
	c := newExportCtx(nil, svc, audit)
	c.Params.KeyID = keyID
	w := httptest.NewRecorder()
	var reqBody *bytes.Buffer
	if body == "" {
		reqBody = &bytes.Buffer{}
	} else {
		reqBody = bytes.NewBufferString(body)
	}
	exportKey(c, w, httptest.NewRequest(http.MethodPost, "/keys/"+keyID+"/export", reqBody))
	require.Nil(t, c.Err, "export handlers never set c.Err")
	return w
}

func TestExportKeyHandler_Success(t *testing.T) {
	keyID := uuid.New()
	keyText := "-----BEGIN PRIVATE KEY-----\nK\n-----END PRIVATE KEY-----\n"
	for _, body := range []string{``, `{}`, `{"format":"pem"}`, `{"format":"pem","version":1}`} {
		svc := &mockKeyService{}
		want := 0
		if body == `{"format":"pem","version":1}` {
			want = 1
		}
		svc.On("ExportKey", mock.Anything, certLegacyVaultScope(), keyID, want).
			Return(&keyServices.ExportKeyResult{ID: keyID, Name: "signer", Type: "RSA", Version: 1, Format: "pem", PrivateKeyPEM: keyText, KeyAlgorithm: "RSA-2048"}, nil)
		audit := &captureAudit{}

		w := runKeyExport(t, svc, audit, keyID.String(), body)
		require.Equal(t, http.StatusOK, w.Code, "body %q", body)
		assert.Equal(t, "no-store", w.Header().Get("Cache-Control"))
		assert.Equal(t, "no-cache", w.Header().Get("Pragma"))
		assert.Empty(t, w.Header().Get("Content-Disposition"))
		assert.Less(t, w.Body.Len(), 64<<10)

		var resp map[string]any
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
		assert.Equal(t, keyID.String(), resp["id"])
		assert.Equal(t, "signer", resp["name"])
		assert.EqualValues(t, 1, resp["version"])
		assert.Equal(t, "pem", resp["format"])
		gotPEM, _ := resp["private_key_pem"].(string)
		assert.Equal(t, sha256.Sum256([]byte(keyText)), sha256.Sum256([]byte(gotPEM)), "private_key_pem round-trips unchanged")
		assert.Equal(t, "RSA-2048", resp["key_algorithm"])
		assert.Equal(t, "RSA", resp["type"])
		assert.Len(t, resp, 7, "the success body has exactly the documented fields")

		require.Len(t, audit.events, 1)
		ev := audit.events[0]
		assert.Equal(t, "export_key", ev.Action)
		assert.Equal(t, "success", ev.Outcome)
		assert.Equal(t, "key", ev.ResourceType)
		assert.Equal(t, keyID.String(), ev.ResourceID)
		assert.Equal(t, certTestUserID, ev.UserID)
		assert.Contains(t, ev.Details, `"format":"pem"`)
		assert.Contains(t, ev.Details, `"name":"signer"`)
		assert.Contains(t, ev.Details, `"version":1`)
		assert.Contains(t, ev.Details, model.DefaultVaultID)
		assert.Empty(t, audit.persisted, "the handler writes no second, legacy audit row")
		assert.False(t, strings.Contains(audit.dump(), "PRIVATE KEY"), "key material reached the audit trail")
		svc.AssertExpectations(t)
	}
}

// TestExportKeyHandler_ErrorBodiesAreR6 pins Review Focus 4: every failure
// is an R6 body with no-store headers, exactly one audit event with a fixed
// reason, and no raw error text.
func TestExportKeyHandler_ErrorBodiesAreR6(t *testing.T) {
	keyID := uuid.New()
	cases := []struct {
		name, body string
		err        error
		status     int
		code       string
		reason     string
		message    string
	}{
		{"bad json", `{"format":`, nil, http.StatusBadRequest, "bad_request", "the request body must be a JSON object", ""},
		{"unknown format", `{"format":"jwk"}`, nil, http.StatusBadRequest, "bad_request", "format must be pem", "format must be pem"},
		{"pkcs12 format", `{"format":"pkcs12"}`, nil, http.StatusBadRequest, "bad_request", "format must be pem", "format must be pem"},
		{"bad version", `{"version":-1}`, fmt.Errorf("%w: version must be 0 or a positive version number", model.ErrInvalidExportRequest), http.StatusBadRequest, "bad_request", "invalid export request", ""},
		{"not found", ``, fmt.Errorf("%w: key %s raw-detail", keyServices.ErrKeyNotFound, keyID), http.StatusNotFound, "not_found", "key or version not found", "key or version not found"},
		{"no version", `{"version":7}`, fmt.Errorf("%w: key %s has no version 7 raw-detail", model.ErrKeyVersionNotFound, keyID), http.StatusNotFound, "not_found", "key or version not found", "key or version not found"},
		{"disabled", ``, fmt.Errorf("%w: key %s raw-detail", keyServices.ErrKeyLifecycleDenied, keyID), http.StatusConflict, "key_disabled", "key disabled", "the key is disabled or outside its valid time window"},
		{"revoked", ``, fmt.Errorf("%w", keyServices.ErrKeyLifecycleDenied), http.StatusConflict, "key_disabled", "key disabled", "the key is disabled or outside its valid time window"},
		{"refused", ``, &model.ExportRefusedError{Sentinel: model.ErrKeyNotExportable, Reason: "HSM-backed keys never leave the token", Name: "signer", KeyAlgorithm: "RSA-2048"}, http.StatusForbidden, "key_not_exportable", "HSM-backed keys never leave the token", ""},
		{"internal", ``, errors.New("decrypt key material: cipher: message authentication failed raw-detail"), http.StatusInternalServerError, "internal_error", "internal failure", "internal server error"},
		{"repository", ``, fmt.Errorf("read key %s version 3: sql: no rows raw-detail", keyID), http.StatusInternalServerError, "internal_error", "internal failure", "internal server error"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			svc := &mockKeyService{}
			if tc.err != nil {
				svc.On("ExportKey", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(nil, tc.err)
			}
			audit := &captureAudit{}
			w := runKeyExport(t, svc, audit, keyID.String(), tc.body)
			require.Equal(t, tc.status, w.Code, w.Body.String())
			assert.Equal(t, "no-store", w.Header().Get("Cache-Control"))
			assert.Equal(t, "no-cache", w.Header().Get("Pragma"))
			detail := decodeExportError(t, w.Body.Bytes())
			assert.Equal(t, tc.code, detail.Code)
			if tc.message != "" {
				assert.Equal(t, tc.message, detail.Message)
			}
			assert.NotContains(t, w.Body.String(), "authentication failed")
			assert.NotContains(t, w.Body.String(), "raw-detail")
			if tc.status != http.StatusBadRequest {
				assert.NotContains(t, w.Body.String(), keyID.String(), "the key id from the error text is never echoed")
			}
			if tc.code == "key_not_exportable" {
				assert.Equal(t, "RSA-2048", detail.KeyAlgorithm)
				assert.Contains(t, detail.Message, "HSM-backed keys never leave the token")
			}
			if tc.err == nil {
				svc.AssertNotCalled(t, "ExportKey", mock.Anything, mock.Anything, mock.Anything, mock.Anything)
			}

			require.Len(t, audit.events, 1, "exactly one structured event per attempt")
			assert.Empty(t, audit.persisted, "the handler writes no second, legacy audit row")
			ev := audit.events[0]
			assert.Equal(t, "failure", ev.Outcome)
			assert.Equal(t, "export_key", ev.Action)
			assert.Equal(t, "key", ev.ResourceType)
			assert.Equal(t, keyID.String(), ev.ResourceID)
			assert.Equal(t, certTestUserID, ev.UserID)
			assert.Contains(t, ev.Details, `"reason":"`+tc.reason+`"`)
			assert.Contains(t, ev.Details, `"code":"`+tc.code+`"`)
			assert.Contains(t, ev.Details, model.DefaultVaultID)
			assert.NotContains(t, ev.Details, "raw-detail")
			assert.NotContains(t, ev.Details, "cipher:")
		})
	}
}

func TestExportKeyHandler_BadIDIs400(t *testing.T) {
	svc := &mockKeyService{}
	audit := &captureAudit{}
	w := runKeyExport(t, svc, audit, "not-a-uuid", ``)
	require.Equal(t, http.StatusBadRequest, w.Code)
	assert.Equal(t, "bad_request", decodeExportError(t, w.Body.Bytes()).Code)
	assert.Equal(t, "no-store", w.Header().Get("Cache-Control"))
	require.Len(t, audit.events, 1)
	assert.Equal(t, "not-a-uuid", audit.events[0].ResourceID)
	assert.Contains(t, audit.events[0].Details, `"reason":"key_id must be a UUID"`)
	svc.AssertNotCalled(t, "ExportKey", mock.Anything, mock.Anything, mock.Anything, mock.Anything)
}

// TestExportKeyHandler_UnknownFormatIsNotCopiedToAudit pins that a
// client-chosen format string never reaches the audit trail verbatim.
func TestExportKeyHandler_UnknownFormatIsNotCopiedToAudit(t *testing.T) {
	audit := &captureAudit{}
	w := runKeyExport(t, &mockKeyService{}, audit, uuid.NewString(), `{"format":"hunter2-pasted-here"}`)
	require.Equal(t, http.StatusBadRequest, w.Code)
	assert.NotContains(t, w.Body.String(), "hunter2-pasted-here")
	require.Len(t, audit.events, 1)
	assert.NotContains(t, audit.dump(), "hunter2-pasted-here")
	assert.Contains(t, audit.events[0].Details, `"format":"invalid"`)
}

// TestExportKeyHandler_RefusalAuditCarriesNameAndReason pins that a
// not-exportable refusal audits the key name and the fixed reason.
func TestExportKeyHandler_RefusalAuditCarriesNameAndReason(t *testing.T) {
	svc := &mockKeyService{}
	svc.On("ExportKey", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(nil,
		&model.ExportRefusedError{Sentinel: model.ErrKeyNotExportable, Reason: "the key was not created with exportable: true", Name: "signer", KeyAlgorithm: "EC-P256"})
	audit := &captureAudit{}
	w := runKeyExport(t, svc, audit, uuid.NewString(), `{"version":2}`)
	require.Equal(t, http.StatusForbidden, w.Code)
	assert.Equal(t, "EC-P256", decodeExportError(t, w.Body.Bytes()).KeyAlgorithm)
	require.Len(t, audit.events, 1)
	assert.Contains(t, audit.events[0].Details, `"name":"signer"`)
	assert.Contains(t, audit.events[0].Details, `"version":2`)
	assert.Contains(t, audit.events[0].Details, `"reason":"the key was not created with exportable: true"`)
	assert.Contains(t, audit.events[0].Details, `"code":"key_not_exportable"`)
}

func TestExportKeyRoutes_BothShapes(t *testing.T) {
	keyID := uuid.New().String()
	t.Run("flat", func(t *testing.T) {
		rec := &recordingKeyService{}
		api, _ := newVaultScopedKeyCertTestAPI(rec, nil, nil)
		w := doVaultRequest(api, http.MethodPost, "/api/v1/keys/"+keyID+"/export", nil)
		require.Equal(t, http.StatusOK, w.Code, w.Body.String())
		assert.Equal(t, uuid.MustParse(model.DefaultVaultID), rec.exportScope.VaultID())
		assert.Equal(t, "no-store", w.Header().Get("Cache-Control"))
	})
	t.Run("vault-scoped", func(t *testing.T) {
		rec := &recordingKeyService{}
		api, repo := newVaultScopedKeyCertTestAPI(rec, nil, nil)
		id := uuid.New()
		repo.byName["prod"] = &model.Vault{ID: id, Name: "prod", Enabled: true}
		repo.byID[id.String()] = repo.byName["prod"]
		w := doVaultRequest(api, http.MethodPost, "/api/v1/vaults/prod/keys/"+keyID+"/export", []byte(`{"format":"pem"}`))
		require.Equal(t, http.StatusOK, w.Code, w.Body.String())
		assert.Equal(t, id, rec.exportScope.VaultID())
	})
}

// TestExportKeyRoutes_MapToExportAction walks the real router and pins that
// both registered key export routes require the key export data action.
func TestExportKeyRoutes_MapToExportAction(t *testing.T) {
	container := &routerWalkContainer{policyContainer: &policyContainer{}, logger: userTestLog()}
	a := &app.App{ServiceContainer: container, Logger: userTestLog()}
	router := mux.NewRouter()
	require.NotNil(t, Init(WithAPP(a), WithRouter(router), WithBasePath("/api/v1"), WithLogger(userTestLog())))

	found := 0
	require.NoError(t, router.Walk(func(route *mux.Route, _ *mux.Router, _ []*mux.Route) error {
		tmpl, err := route.GetPathTemplate()
		if err != nil || !strings.HasSuffix(tmpl, "/export") || !strings.Contains(tmpl, "/keys/") {
			return nil
		}
		methods, _ := route.GetMethods()
		assert.Equal(t, []string{http.MethodPost}, methods, tmpl)
		action, kind := authzServices.MapRouteToDataAction(http.MethodPost, tmpl)
		assert.Equal(t, authzServices.RouteVaultData, kind, tmpl)
		assert.Equal(t, model.ActionKeysExport, action, tmpl)
		found++
		return nil
	}))
	assert.Equal(t, 2, found, "the key export route is registered on the flat and vault-scoped shapes")
}

func TestExportKeyThroughRealChain_NoSecretsAndMissingRoleAudited(t *testing.T) {
	keyText := "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCleaked\n-----END PRIVATE KEY-----\n"
	keyID := uuid.New()
	svc := &mockKeyService{}
	svc.On("ExportKey", mock.Anything, mock.Anything, keyID, 0).
		Return(&keyServices.ExportKeyResult{ID: keyID, Name: "k", Type: "RSA", Version: 1, Format: "pem", PrivateKeyPEM: keyText, KeyAlgorithm: "RSA-2048"}, nil)

	router, audit, logs := newExportChain(t, nil, svc, "")
	w := postExport(router, "/api/v1/vaults/default/keys/"+keyID.String()+"/export", `{"format":"pem"}`)
	require.Equal(t, http.StatusOK, w.Code, "status %d", w.Code)
	assert.Equal(t, "no-store", w.Header().Get("Cache-Control"))
	w = postExport(router, "/api/v1/keys/"+keyID.String()+"/export", ``)
	require.Equal(t, http.StatusOK, w.Code, "status %d", w.Code)

	everything := logs.String() + audit.dump()
	for _, secret := range []string{"BEGIN PRIVATE KEY", "MIIEvQIBADANBg", "leaked"} {
		assert.False(t, strings.Contains(everything, secret), "key material reached the logs or audit trail")
	}
	exportEvents := 0
	for _, e := range audit.events {
		if e.Action == "export_key" {
			exportEvents++
		}
	}
	assert.Equal(t, 2, exportEvents, "one structured event per attempt")
	for _, row := range audit.persisted {
		fields := strings.SplitN(row, " ", 3)
		require.Len(t, fields, 3)
		assert.NotEqual(t, "export_key", fields[1], "no legacy audit row from the handler")
	}

	denied := &mockKeyService{}
	deniedRouter, deniedAudit, _ := newExportChain(t, nil, denied, model.ActionKeysExport)
	w = postExport(deniedRouter, "/api/v1/keys/"+keyID.String()+"/export", ``)
	require.Equal(t, http.StatusForbidden, w.Code)
	assert.Contains(t, w.Body.String(), "no role assignment grants this operation")
	assert.Contains(t, deniedAudit.dump(), string(model.ActionKeysExport))
	denied.AssertNotCalled(t, "ExportKey", mock.Anything, mock.Anything, mock.Anything, mock.Anything)
}
