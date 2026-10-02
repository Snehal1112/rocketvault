package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sort"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"rocketvault/internal/crypto"
	certServices "rocketvault/internal/services/certificates"
	keyServices "rocketvault/internal/services/keys"
	"rocketvault/model"
)

func jsonKeys(t *testing.T, v any) []string {
	t.Helper()
	body, err := json.Marshal(v)
	require.NoError(t, err)
	var m map[string]any
	require.NoError(t, json.Unmarshal(body, &m))
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// TestCertificateResponse_GoldenFields pins that the response only gained
// exportable and key_algorithm: every pre-existing field keeps its name.
func TestCertificateResponse_GoldenFields(t *testing.T) {
	keyPEM, err := crypto.GenerateECDSAKeyPEM("P-256")
	require.NoError(t, err)
	certPEM, err := crypto.CreateSelfSignedCertificatePEM(keyPEM, "ECDSA", crypto.CertificateTemplate{CommonName: "g", ValidityDays: 1})
	require.NoError(t, err)
	exp, nb := time.Now(), time.Now()
	resp := certToDomainResponse(&model.Certificate{ID: uuid.New(), Name: "g", Certificate: certPEM, PrivateKey: "enc",
		ExpiresAt: &exp, NotBefore: &nb, Enabled: true, Version: 1, Exportable: true})

	assert.Equal(t, []string{"auto_renew", "created_at", "enabled", "expires_at", "exportable", "id", "key_algorithm",
		"name", "not_before", "renewal_days", "tags", "user_id", "version"}, jsonKeys(t, resp))
	assert.True(t, resp.Exportable)
	assert.Equal(t, "EC-P256", resp.KeyAlgorithm)
}

func TestKeyResponse_GoldenFields(t *testing.T) {
	exp, nb, upd := time.Now(), time.Now(), time.Now()
	resp := buildKeyResponse(&model.Key{ID: uuid.New(), Name: "k", Type: model.KeyTypeRSA, Bits: 2048, Curve: "",
		ExpiresAt: &exp, NotBefore: &nb, UpdatedAt: &upd, Enabled: true, Exportable: true},
		&model.PublicJWK{N: "n", E: "e"})
	assert.Equal(t, []string{"bits", "created_at", "e", "enabled", "expires_at", "exportable", "id", "key_algorithm",
		"n", "name", "not_before", "revoked", "tags", "type", "updated_at", "user_id"}, jsonKeys(t, resp))
	assert.Equal(t, "RSA-2048", resp.KeyAlgorithm)
	assert.True(t, resp.Exportable)
}

func TestCreateCertificateHandler_PassesExportable(t *testing.T) {
	svc := &mockCertService{}
	svc.On("CreateSelfSignedCertificate", mock.Anything, mock.MatchedBy(func(r certServices.CreateCertificateRequest) bool {
		return r.Exportable
	})).Return(&certServices.CreateCertificateResult{CertID: uuid.New(), Name: "c", Version: 1, Exportable: true, KeyAlgorithm: "RSA-2048"}, nil)

	c := newCertCtx(svc, certAdminClaims())
	w := httptest.NewRecorder()
	body := fmt.Sprintf(`{"name":"c","key_id":"%s","validity_days":30,"exportable":true}`, uuid.New())
	createCertificate(c, w, httptest.NewRequest(http.MethodPost, "/certificates", bytes.NewBufferString(body)))
	require.Nil(t, c.Err)
	require.Equal(t, http.StatusCreated, w.Code)

	var resp CertificateResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.True(t, resp.Exportable)
	assert.Equal(t, "RSA-2048", resp.KeyAlgorithm)
	svc.AssertExpectations(t)
}

func TestCreateCertificateHandler_ExportableOverNonExportableKeyIs409(t *testing.T) {
	svc := &mockCertService{}
	svc.On("CreateSelfSignedCertificate", mock.Anything, mock.Anything).
		Return(nil, fmt.Errorf("%w: key x has exportable=false", model.ErrExportableKeyRequired))

	c := newCertCtx(svc, certAdminClaims())
	w := httptest.NewRecorder()
	body := fmt.Sprintf(`{"name":"c","key_id":"%s","validity_days":30,"exportable":true}`, uuid.New())
	createCertificate(c, w, httptest.NewRequest(http.MethodPost, "/certificates", bytes.NewBufferString(body)))
	require.NotNil(t, c.Err)
	writeError(w, c)
	assert.Equal(t, http.StatusConflict, w.Code)
	assert.Contains(t, w.Body.String(), "exportable")
}

func TestCreateCertificateHandler_OtherErrorsKeepTheir500(t *testing.T) {
	svc := &mockCertService{}
	svc.On("CreateSelfSignedCertificate", mock.Anything, mock.Anything).Return(nil, fmt.Errorf("boom"))
	c := newCertCtx(svc, certAdminClaims())
	w := httptest.NewRecorder()
	body := fmt.Sprintf(`{"name":"c","key_id":"%s","validity_days":30}`, uuid.New())
	createCertificate(c, w, httptest.NewRequest(http.MethodPost, "/certificates", bytes.NewBufferString(body)))
	require.NotNil(t, c.Err)
	assert.Equal(t, http.StatusInternalServerError, c.Err.StatusCode, "no existing status changes")
}

func TestWriteKeyError_ExportableNotSupportedIs400(t *testing.T) {
	c := &Context{}
	writeKeyError(c, fmt.Errorf("%w: the key would be HSM-backed", model.ErrExportableNotSupported))
	require.NotNil(t, c.Err)
	assert.Equal(t, http.StatusBadRequest, c.Err.StatusCode)
	assert.Contains(t, c.Err.Message, "exportable")
}

func TestCreateAndImportKeyHandlers_PassExportable(t *testing.T) {
	keyID := uuid.New()
	stored := &model.Key{ID: keyID, Name: "k", Type: model.KeyTypeRSA, Bits: 2048, Enabled: true, Exportable: true}
	wantsExportable := func(exportable bool) bool { return exportable }

	for name, run := range map[string]func(svc *mockKeyService, c *Context, w *httptest.ResponseRecorder){
		"create": func(svc *mockKeyService, c *Context, w *httptest.ResponseRecorder) {
			svc.On("CreateRSAKey", mock.Anything, mock.MatchedBy(func(r keyServices.CreateKeyRequest) bool { return wantsExportable(r.Exportable) })).
				Return(&keyServices.CreateKeyResult{KeyID: keyID, Name: "k", Type: "RSA"}, nil)
			createKey(c, w, httptest.NewRequest(http.MethodPost, "/keys",
				bytes.NewBufferString(`{"name":"k","type":"RSA","bits":2048,"exportable":true}`)))
		},
		"import": func(svc *mockKeyService, c *Context, w *httptest.ResponseRecorder) {
			svc.On("ImportKey", mock.Anything, mock.MatchedBy(func(r keyServices.ImportKeyRequest) bool { return wantsExportable(r.Exportable) })).
				Return(&keyServices.CreateKeyResult{KeyID: keyID, Name: "k", Type: "RSA"}, nil)
			importKey(c, w, httptest.NewRequest(http.MethodPost, "/keys/import",
				bytes.NewBufferString(`{"name":"k","jwk":{"kty":"RSA"},"exportable":true}`)))
		},
	} {
		t.Run(name, func(t *testing.T) {
			svc := &mockKeyService{}
			svc.On("GetKey", mock.Anything, keyID, mock.Anything).Return(stored, nil)
			c := newKeyCtx(svc)
			w := httptest.NewRecorder()
			run(svc, c, w)
			require.Nil(t, c.Err)
			require.Equal(t, http.StatusCreated, w.Code, w.Body.String())
			assert.Contains(t, w.Body.String(), `"exportable":true`)
			assert.Contains(t, w.Body.String(), `"key_algorithm":"RSA-2048"`)
			svc.AssertExpectations(t)
		})
	}
}
