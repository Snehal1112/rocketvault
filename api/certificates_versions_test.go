package api

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	certServices "rocketvault/internal/services/certificates"
	"rocketvault/model"
)

// runCertVersionHandler calls handler directly with the given params and body.
func runCertVersionHandler(t *testing.T, svc *mockCertService, params *ApiParams, method, body string,
	handler func(*Context, http.ResponseWriter, *http.Request)) *httptest.ResponseRecorder {
	t.Helper()
	c := newCertCtx(svc, certAdminClaims())
	params.PerPage = 60
	c.Params = params
	w := httptest.NewRecorder()
	var r *http.Request
	if body == "" {
		r = httptest.NewRequest(method, "/certificates", nil)
	} else {
		r = httptest.NewRequest(method, "/certificates", bytes.NewBufferString(body))
	}
	handler(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}
	return w
}

func TestListCertificateVersions_Statuses(t *testing.T) {
	certID := uuid.New()

	ok := &mockCertService{}
	ok.On("ListCertificateVersions", mock.Anything, certID, certLegacyVaultScope()).Return([]model.CertificateVersion{
		{CertificateID: certID, Version: 1}, {CertificateID: certID, Version: 2, Current: true},
	}, nil)
	w := runCertVersionHandler(t, ok, &ApiParams{CertificateID: certID.String()}, http.MethodGet, "", listCertificateVersions)
	require.Equal(t, http.StatusOK, w.Code)
	var body CertificateVersionListResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
	assert.Len(t, body.Versions, 2)

	missing := &mockCertService{}
	missing.On("ListCertificateVersions", mock.Anything, certID, certLegacyVaultScope()).Return(nil, certServices.ErrCertNotFound)
	w = runCertVersionHandler(t, missing, &ApiParams{CertificateID: certID.String()}, http.MethodGet, "", listCertificateVersions)
	assert.Equal(t, http.StatusNotFound, w.Code)

	w = runCertVersionHandler(t, &mockCertService{}, &ApiParams{CertificateID: "bad"}, http.MethodGet, "", listCertificateVersions)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestGetCertificateVersion_Statuses(t *testing.T) {
	certID := uuid.New()

	w := runCertVersionHandler(t, &mockCertService{}, &ApiParams{CertificateID: certID.String(), Version: 0},
		http.MethodGet, "", getCertificateVersion)
	assert.Equal(t, http.StatusBadRequest, w.Code, "version 0 is a bad version")

	missing := &mockCertService{}
	missing.On("GetCertificateVersion", mock.Anything, certID, 7, certLegacyVaultScope()).
		Return(nil, fmt.Errorf("%w: no version 7", model.ErrCertificateVersionNotFound))
	w = runCertVersionHandler(t, missing, &ApiParams{CertificateID: certID.String(), Version: 7}, http.MethodGet, "", getCertificateVersion)
	assert.Equal(t, http.StatusNotFound, w.Code)

	ok := &mockCertService{}
	ok.On("GetCertificateVersion", mock.Anything, certID, 2, certLegacyVaultScope()).
		Return(&model.CertificateVersion{CertificateID: certID, Version: 2, Enabled: true}, nil)
	w = runCertVersionHandler(t, ok, &ApiParams{CertificateID: certID.String(), Version: 2}, http.MethodGet, "", getCertificateVersion)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestUpdateCertificateVersion_Statuses(t *testing.T) {
	certID := uuid.New()

	w := runCertVersionHandler(t, &mockCertService{}, &ApiParams{CertificateID: certID.String(), Version: 1},
		http.MethodPut, `{}`, updateCertificateVersion)
	assert.Equal(t, http.StatusBadRequest, w.Code, "an update with no attribute is refused")

	w = runCertVersionHandler(t, &mockCertService{}, &ApiParams{CertificateID: certID.String(), Version: 1},
		http.MethodPut, `{not json`, updateCertificateVersion)
	assert.Equal(t, http.StatusBadRequest, w.Code)

	invalid := &mockCertService{}
	invalid.On("UpdateCertificateVersion", mock.Anything, mock.Anything).
		Return(nil, fmt.Errorf("%w: not_before after expires_at", model.ErrInvalidCertificateVersionAttributes))
	w = runCertVersionHandler(t, invalid, &ApiParams{CertificateID: certID.String(), Version: 1},
		http.MethodPut, `{"not_before":"2030-01-02T00:00:00Z","expires_at":"2030-01-01T00:00:00Z"}`, updateCertificateVersion)
	assert.Equal(t, http.StatusBadRequest, w.Code)

	raced := &mockCertService{}
	raced.On("UpdateCertificateVersion", mock.Anything, mock.Anything).
		Return(nil, fmt.Errorf("lost: %w", model.ErrCertificateVersionConflict))
	w = runCertVersionHandler(t, raced, &ApiParams{CertificateID: certID.String(), Version: 1},
		http.MethodPut, `{"enabled":false}`, updateCertificateVersion)
	assert.Equal(t, http.StatusConflict, w.Code)

	disabled := false
	ok := &mockCertService{}
	ok.On("UpdateCertificateVersion", mock.Anything, certServices.UpdateCertificateVersionRequest{
		CertID: certID, Version: 1, Scope: certLegacyVaultScope(), Enabled: &disabled,
	}).Return(&model.CertificateVersion{CertificateID: certID, Version: 1, Current: true}, nil)
	w = runCertVersionHandler(t, ok, &ApiParams{CertificateID: certID.String(), Version: 1},
		http.MethodPut, `{"enabled":false}`, updateCertificateVersion)
	assert.Equal(t, http.StatusOK, w.Code)
	ok.AssertExpectations(t)
}

func TestRenewCertificate_Statuses(t *testing.T) {
	certID := uuid.New()
	scope := certLegacyVaultScope()

	w := runCertVersionHandler(t, &mockCertService{}, &ApiParams{CertificateID: certID.String()},
		http.MethodPost, `{"validity_days":0}`, renewCertificate)
	assert.Equal(t, http.StatusBadRequest, w.Code)

	w = runCertVersionHandler(t, &mockCertService{}, &ApiParams{CertificateID: certID.String()},
		http.MethodPost, `{not json`, renewCertificate)
	assert.Equal(t, http.StatusBadRequest, w.Code)

	denied := &mockCertService{}
	denied.On("RenewCertificate", mock.Anything, certID, scope, 90).Return(nil, certServices.ErrCertLifecycleDenied)
	w = runCertVersionHandler(t, denied, &ApiParams{CertificateID: certID.String()},
		http.MethodPost, `{"validity_days":90}`, renewCertificate)
	assert.Equal(t, http.StatusConflict, w.Code, "the spec maps a lifecycle denial on renew to 409")

	raced := &mockCertService{}
	raced.On("RenewCertificate", mock.Anything, certID, scope, 90).
		Return(nil, fmt.Errorf("lost: %w", model.ErrCertificateVersionConflict))
	w = runCertVersionHandler(t, raced, &ApiParams{CertificateID: certID.String()},
		http.MethodPost, `{"validity_days":90}`, renewCertificate)
	assert.Equal(t, http.StatusConflict, w.Code)

	missing := &mockCertService{}
	missing.On("RenewCertificate", mock.Anything, certID, scope, 90).Return(nil, certServices.ErrCertNotFound)
	w = runCertVersionHandler(t, missing, &ApiParams{CertificateID: certID.String()},
		http.MethodPost, `{"validity_days":90}`, renewCertificate)
	assert.Equal(t, http.StatusNotFound, w.Code)

	internal := &mockCertService{}
	internal.On("RenewCertificate", mock.Anything, certID, scope, 90).Return(nil, errors.New("sql: connection reset by peer"))
	w = runCertVersionHandler(t, internal, &ApiParams{CertificateID: certID.String()},
		http.MethodPost, `{"validity_days":90}`, renewCertificate)
	assert.Equal(t, http.StatusInternalServerError, w.Code)
	// The message is generic ("Internal server error"), but writeError still
	// serializes err.Error() into detailed_error today. Scrubbing that is
	// docs/superpowers/plans/2026-09-30-secrets-and-error-responses.md Task 1;
	// once it lands, add: assert.NotContains(t, w.Body.String(), "connection reset").
	assert.Contains(t, w.Body.String(), "Internal server error")
}

func TestRenewCertificate_RoutineRefusals(t *testing.T) {
	certID := uuid.New()
	scope := certLegacyVaultScope()
	cases := []struct {
		name string
		err  error
		code int
	}{
		{"foreign key", fmt.Errorf("wrapped: %w", certServices.ErrRenewKeyForbidden), http.StatusForbidden},
		{"key missing", fmt.Errorf("wrapped: %w", certServices.ErrRenewKeyNotFound), http.StatusConflict},
		{"not possible", fmt.Errorf("wrapped: %w", certServices.ErrRenewNotPossible), http.StatusConflict},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := &mockCertService{}
			m.On("RenewCertificate", mock.Anything, certID, scope, 90).Return(nil, tc.err)
			w := runCertVersionHandler(t, m, &ApiParams{CertificateID: certID.String()},
				http.MethodPost, `{"validity_days":90}`, renewCertificate)
			assert.Equal(t, tc.code, w.Code)
			assert.NotContains(t, w.Body.String(), "wrapped", "internal text must not be echoed")
		})
	}
}

func TestRenewCertificate_DefaultsToCurrentValidity(t *testing.T) {
	certID := uuid.New()
	scope := certLegacyVaultScope()
	created := time.Now().Add(-10 * 24 * time.Hour)
	expires := created.Add(120 * 24 * time.Hour)

	svc := &mockCertService{}
	svc.On("GetCertificate", mock.Anything, certID, scope).
		Return(&model.Certificate{ID: certID, CreatedAt: created, ExpiresAt: &expires, Enabled: true}, nil)
	svc.On("RenewCertificate", mock.Anything, certID, scope, 120).
		Return(&certServices.CreateCertificateResult{CertID: certID, Version: 2}, nil)
	svc.On("GetCertificateVersion", mock.Anything, certID, 2, scope).
		Return(&model.CertificateVersion{CertificateID: certID, Version: 2, Current: true, Enabled: true}, nil)

	w := runCertVersionHandler(t, svc, &ApiParams{CertificateID: certID.String()}, http.MethodPost, "", renewCertificate)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	var got model.CertificateVersion
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &got))
	assert.Equal(t, 2, got.Version)
	svc.AssertExpectations(t)
}

// A failed metadata read-back after a committed renewal must not turn the
// request into an error: the new version exists.
func TestRenewCertificate_ReadBackFailureFallsBackToResult(t *testing.T) {
	certID := uuid.New()
	scope := certLegacyVaultScope()
	created := time.Now().UTC().Truncate(time.Second)
	expires := created.Add(90 * 24 * time.Hour)

	svc := &mockCertService{}
	svc.On("RenewCertificate", mock.Anything, certID, scope, 90).
		Return(&certServices.CreateCertificateResult{CertID: certID, Version: 3, CreatedAt: created, ExpiresAt: &expires}, nil)
	svc.On("GetCertificateVersion", mock.Anything, certID, 3, scope).
		Return(nil, errors.New("sql: connection reset by peer"))

	w := runCertVersionHandler(t, svc, &ApiParams{CertificateID: certID.String()},
		http.MethodPost, `{"validity_days":90}`, renewCertificate)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	var got model.CertificateVersion
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &got))
	assert.Equal(t, certID, got.CertificateID)
	assert.Equal(t, 3, got.Version)
	assert.True(t, got.Current)
	assert.True(t, got.Enabled)
	assert.True(t, got.CreatedAt.Equal(created))
	require.NotNil(t, got.ExpiresAt)
	assert.True(t, got.ExpiresAt.Equal(expires))
}

// TestCertificateVersionResponses_CarryNoKeyMaterial pins that no version
// response can carry a PEM or a private key.
func TestCertificateVersionResponses_CarryNoKeyMaterial(t *testing.T) {
	certID := uuid.New()
	scope := certLegacyVaultScope()
	svc := &mockCertService{}
	svc.On("ListCertificateVersions", mock.Anything, certID, scope).
		Return([]model.CertificateVersion{{CertificateID: certID, Version: 1, Current: true}}, nil)
	svc.On("GetCertificateVersion", mock.Anything, certID, 1, scope).
		Return(&model.CertificateVersion{CertificateID: certID, Version: 1, Current: true}, nil)
	svc.On("RenewCertificate", mock.Anything, certID, scope, 30).
		Return(&certServices.CreateCertificateResult{CertID: certID, Version: 1}, nil)

	for name, run := range map[string]func() *httptest.ResponseRecorder{
		"list": func() *httptest.ResponseRecorder {
			return runCertVersionHandler(t, svc, &ApiParams{CertificateID: certID.String()}, http.MethodGet, "", listCertificateVersions)
		},
		"get": func() *httptest.ResponseRecorder {
			return runCertVersionHandler(t, svc, &ApiParams{CertificateID: certID.String(), Version: 1}, http.MethodGet, "", getCertificateVersion)
		},
		"renew": func() *httptest.ResponseRecorder {
			return runCertVersionHandler(t, svc, &ApiParams{CertificateID: certID.String()}, http.MethodPost, `{"validity_days":30}`, renewCertificate)
		},
	} {
		body := strings.ToLower(run().Body.String())
		assert.NotContains(t, body, "private_key", name)
		assert.NotContains(t, body, `"certificate":`, name)
		assert.NotContains(t, body, "begin", name)
	}
}

// allowKeySignOn lets the renew route's keys/sign check pass on a test API
// built by newVaultScopedKeyCertTestAPI (B77).
func allowKeySignOn(api *API) {
	c := api.App.ServiceContainer.(*vaultSvcTestContainer)
	c.policySvc, c.roleSvc = allowAllDataPlane()
}

// TestCertificateVersionRoutes_BothShapes dispatches every new route on the
// flat and the vault-scoped router, and checks the vault each one scoped to.
func TestCertificateVersionRoutes_BothShapes(t *testing.T) {
	certID := uuid.New().String()
	cases := []struct {
		method, suffix, body string
	}{
		{http.MethodGet, "/versions", ""},
		{http.MethodGet, "/versions/1", ""},
		{http.MethodPut, "/versions/1", `{"enabled":true}`},
		{http.MethodPost, "/renew", `{"validity_days":30}`},
	}
	for _, tc := range cases {
		t.Run("flat "+tc.method+tc.suffix, func(t *testing.T) {
			rec := &recordingCertService{}
			api, _ := newVaultScopedKeyCertTestAPI(nil, rec, nil)
			allowKeySignOn(api)
			var body []byte
			if tc.body != "" {
				body = []byte(tc.body)
			}
			w := doVaultRequest(api, tc.method, "/api/v1/certificates/"+certID+tc.suffix, body)
			require.Equal(t, http.StatusOK, w.Code, w.Body.String())
			assert.Equal(t, uuid.MustParse(model.DefaultVaultID), rec.versionScope.VaultID())
		})
		t.Run("vault-scoped "+tc.method+tc.suffix, func(t *testing.T) {
			rec := &recordingCertService{}
			api, repo := newVaultScopedKeyCertTestAPI(nil, rec, nil)
			allowKeySignOn(api)
			id := uuid.New()
			repo.byName["prod"] = &model.Vault{ID: id, Name: "prod", Enabled: true}
			repo.byID[id.String()] = repo.byName["prod"]
			var body []byte
			if tc.body != "" {
				body = []byte(tc.body)
			}
			w := doVaultRequest(api, tc.method, "/api/v1/vaults/prod/certificates/"+certID+tc.suffix, body)
			require.Equal(t, http.StatusOK, w.Code, w.Body.String())
			assert.Equal(t, id, rec.versionScope.VaultID())
		})
	}
}
