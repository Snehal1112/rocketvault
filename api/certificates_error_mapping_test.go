package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	certServices "rocketvault/internal/services/certificates"
	"rocketvault/model"
)

// leakedKeyID is wrapped into the service errors below. No response may echo
// it, nor the wrapped repository text.
var leakedKeyID = uuid.New()

// TestCreateCertificate_MapsSigningKeyErrors pins B78: a refusal about the
// caller's key or CA is a client problem, not a 500, and the response never
// echoes the wrapped repository text.
func TestCreateCertificate_MapsSigningKeyErrors(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want int
	}{
		{"foreign key", certServices.ErrSigningKeyForbidden, http.StatusForbidden},
		{"foreign CA", fmt.Errorf("cannot access CA certificate: %w", certServices.ErrCACertForbidden), http.StatusForbidden},
		{"unusable key", fmt.Errorf("%w: %s", certServices.ErrSigningKeyUnusable, leakedKeyID), http.StatusForbidden},
		{"missing key", fmt.Errorf("%w: %w", certServices.ErrSigningKeyNotFound, errors.New("sql: no rows wrapped")), http.StatusNotFound},
		{"missing CA", fmt.Errorf("cannot access CA certificate: %w", fmt.Errorf("%w: %w", certServices.ErrCACertNotFound, errors.New("sql: no rows wrapped"))), http.StatusNotFound},
		{"read fault", fmt.Errorf("failed to read key: %w", errors.New("sql: database is closed")), http.StatusInternalServerError},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			svc := &mockCertService{}
			svc.On("CreateSelfSignedCertificate", mock.Anything, mock.Anything).Return(nil, tc.err)

			w := postCreateCertificate(newCertCtx(svc, certAdminClaims()))
			assert.Equal(t, tc.want, w.Code)
			assert.NotContains(t, w.Body.String(), "sql:")
			assert.NotContains(t, w.Body.String(), leakedKeyID.String())
		})
	}
}

// TestRenewCertificate_MapsUnusableSigningMaterialTo409 pins the renew-route
// mapping: an unusable key or a missing signing CA is a state the caller
// fixes, reported like the route's other renewal refusals.
func TestRenewCertificate_MapsUnusableSigningMaterialTo409(t *testing.T) {
	certID := uuid.New()
	scope := certLegacyVaultScope()
	for name, err := range map[string]error{
		"unusable key": fmt.Errorf("%w: %s", certServices.ErrSigningKeyUnusable, leakedKeyID),
		"missing CA":   fmt.Errorf("cannot renew CA-signed certificate: %w", fmt.Errorf("%w: %w", certServices.ErrCACertNotFound, errors.New("sql: no rows wrapped"))),
	} {
		t.Run(name, func(t *testing.T) {
			m := &mockCertService{}
			m.On("RenewCertificate", mock.Anything, certID, scope, 90).Return(nil, err)
			w := runCertVersionHandler(t, m, &ApiParams{CertificateID: certID.String()},
				http.MethodPost, `{"validity_days":90}`, renewCertificate)
			assert.Equal(t, http.StatusConflict, w.Code)
			assert.NotContains(t, w.Body.String(), "sql:")
			assert.NotContains(t, w.Body.String(), leakedKeyID.String())
		})
	}
}

// TestSigningKeyUnusable_NotA500OnBothRouteShapes dispatches create and renew
// through the real router, flat and vault-scoped, and checks an unusable key
// answers 403 on create and 409 on renew rather than falling to 500 (B78).
func TestSigningKeyUnusable_NotA500OnBothRouteShapes(t *testing.T) {
	unusable := fmt.Errorf("%w: %s", certServices.ErrSigningKeyUnusable, leakedKeyID)
	createBody := []byte(fmt.Sprintf(`{"name":"mycert","key_id":%q,"validity_days":365}`, uuid.New()))
	certID := uuid.New().String()

	for _, shape := range []string{"flat", "vault-scoped"} {
		t.Run(shape, func(t *testing.T) {
			svc := &mockCertService{}
			svc.On("CreateSelfSignedCertificate", mock.Anything, mock.Anything).Return(nil, unusable)
			svc.On("RenewCertificate", mock.Anything, mock.Anything, mock.Anything, 30).Return(nil, unusable)
			api, repo := newVaultScopedKeyCertTestAPI(nil, svc, nil)
			allowKeySignOn(api)

			prefix := "/api/v1/certificates"
			if shape == "vault-scoped" {
				id := uuid.New()
				repo.byName["prod"] = &model.Vault{ID: id, Name: "prod", Enabled: true}
				repo.byID[id.String()] = repo.byName["prod"]
				prefix = "/api/v1/vaults/prod/certificates"
			}

			w := doVaultRequest(api, http.MethodPost, prefix, createBody)
			require.Equal(t, http.StatusForbidden, w.Code, w.Body.String())
			assert.NotContains(t, w.Body.String(), leakedKeyID.String())
			// The sentinel also comes from the CA's own key, which may be
			// missing, so the fixed text names both keys and that case.
			assert.Contains(t, w.Body.String(), signingKeyUnusableMessage)

			w = doVaultRequest(api, http.MethodPost, prefix+"/"+certID+"/renew", []byte(`{"validity_days":30}`))
			require.Equal(t, http.StatusConflict, w.Code, w.Body.String())
			assert.NotContains(t, w.Body.String(), leakedKeyID.String())
			assert.Contains(t, w.Body.String(), signingKeyUnusableMessage)

			svc.AssertCalled(t, "CreateSelfSignedCertificate", mock.Anything, mock.Anything)
			svc.AssertCalled(t, "RenewCertificate", mock.Anything, mock.Anything, mock.Anything, 30)
		})
	}
}

// TestRenewCertificate_ForeignCAIs403OnBothRouteShapes pins that a signing CA
// owned by another user, which renewal reaches through
// ValidateCertificateAccess, falls through writeCertificateRenewError to the
// 403 arm of writeCertificateError rather than to 500 (B78).
func TestRenewCertificate_ForeignCAIs403OnBothRouteShapes(t *testing.T) {
	foreignCA := fmt.Errorf("cannot renew CA-signed certificate: signing CA %s is not accessible: %w",
		leakedKeyID, certServices.ErrCACertForbidden)
	certID := uuid.New().String()

	for _, shape := range []string{"flat", "vault-scoped"} {
		t.Run(shape, func(t *testing.T) {
			svc := &mockCertService{}
			svc.On("RenewCertificate", mock.Anything, mock.Anything, mock.Anything, 30).Return(nil, foreignCA)
			api, repo := newVaultScopedKeyCertTestAPI(nil, svc, nil)
			allowKeySignOn(api)

			prefix := "/api/v1/certificates"
			if shape == "vault-scoped" {
				id := uuid.New()
				repo.byName["prod"] = &model.Vault{ID: id, Name: "prod", Enabled: true}
				repo.byID[id.String()] = repo.byName["prod"]
				prefix = "/api/v1/vaults/prod/certificates"
			}

			w := doVaultRequest(api, http.MethodPost, prefix+"/"+certID+"/renew", []byte(`{"validity_days":30}`))
			require.Equal(t, http.StatusForbidden, w.Code, w.Body.String())
			assert.Contains(t, w.Body.String(), "the CA certificate belongs to another user")
			assert.NotContains(t, w.Body.String(), leakedKeyID.String())
			svc.AssertCalled(t, "RenewCertificate", mock.Anything, mock.Anything, mock.Anything, 30)
		})
	}
}

func TestCreateCertificate_ValidityAboveMaximum_Returns400(t *testing.T) {
	svc := &mockCertService{}
	c := newCertCtx(svc, certAdminClaims())
	w := httptest.NewRecorder()
	body, _ := json.Marshal(map[string]any{
		"name": "mycert", "key_id": uuid.New().String(), "validity_days": model.MaxCertificateValidityDays + 1,
	})
	r := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/certificates", bytes.NewReader(body))

	createCertificate(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusBadRequest, w.Code)
	svc.AssertNotCalled(t, "CreateSelfSignedCertificate", mock.Anything, mock.Anything)
}

// TestCreateCertificate_ValidityBoundaries runs the create route over the
// boundary values (B78). Refused values never reach the service; accepted
// ones reach it unchanged.
func TestCreateCertificate_ValidityBoundaries(t *testing.T) {
	cases := []struct {
		raw    string
		accept int
	}{
		{raw: "0"}, {raw: "-1"}, {raw: "36501"},
		{raw: fmt.Sprint(math.MaxInt64)},
		// Beyond int64 the JSON decoder itself refuses the body.
		{raw: "99999999999999999999"},
		{raw: "1", accept: 1},
		{raw: "36500", accept: model.MaxCertificateValidityDays},
	}
	for _, tc := range cases {
		t.Run(tc.raw, func(t *testing.T) {
			svc := &mockCertService{}
			if tc.accept != 0 {
				svc.On("CreateSelfSignedCertificate", mock.Anything, mock.MatchedBy(func(req certServices.CreateCertificateRequest) bool {
					return req.ValidityDays == tc.accept
				})).Return(nil, certServices.ErrSigningKeyNotFound)
			}
			c := newCertCtx(svc, certAdminClaims())
			w := httptest.NewRecorder()
			body := fmt.Sprintf(`{"name":"mycert","key_id":%q,"validity_days":%s}`, uuid.New().String(), tc.raw)
			r := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/certificates", bytes.NewBufferString(body))

			createCertificate(c, w, r)
			if c.Err != nil {
				writeError(w, c)
			}

			if tc.accept == 0 {
				assert.Equal(t, http.StatusBadRequest, w.Code)
				svc.AssertNotCalled(t, "CreateSelfSignedCertificate", mock.Anything, mock.Anything)
				return
			}
			// The stubbed service refuses the key, so reaching it reads as 404.
			assert.Equal(t, http.StatusNotFound, w.Code)
			svc.AssertExpectations(t)
		})
	}
}

func TestRenewCertificate_ValidityAboveMaximum_Returns400(t *testing.T) {
	svc := &mockCertService{}
	body := fmt.Sprintf(`{"validity_days":%d}`, model.MaxCertificateValidityDays+1)
	w := runCertVersionHandler(t, svc, &ApiParams{CertificateID: uuid.New().String()},
		http.MethodPost, body, renewCertificate)
	assert.Equal(t, http.StatusBadRequest, w.Code)
	svc.AssertNotCalled(t, "RenewCertificate", mock.Anything, mock.Anything, mock.Anything, mock.Anything)
}

// TestRenewCertificate_ValidityBoundaries runs the renew route over the
// boundary values (B78).
func TestRenewCertificate_ValidityBoundaries(t *testing.T) {
	certID := uuid.New()
	scope := certLegacyVaultScope()
	cases := []struct {
		raw    string
		accept int
	}{
		{raw: "0"}, {raw: "-1"}, {raw: "36501"},
		{raw: fmt.Sprint(math.MaxInt64)},
		{raw: "99999999999999999999"},
		{raw: "1", accept: 1},
		{raw: "36500", accept: model.MaxCertificateValidityDays},
	}
	for _, tc := range cases {
		t.Run(tc.raw, func(t *testing.T) {
			svc := &mockCertService{}
			if tc.accept != 0 {
				svc.On("RenewCertificate", mock.Anything, certID, scope, tc.accept).
					Return(nil, certServices.ErrRenewNotPossible)
			}
			w := runCertVersionHandler(t, svc, &ApiParams{CertificateID: certID.String()},
				http.MethodPost, `{"validity_days":`+tc.raw+`}`, renewCertificate)
			if tc.accept == 0 {
				assert.Equal(t, http.StatusBadRequest, w.Code)
				svc.AssertNotCalled(t, "RenewCertificate", mock.Anything, mock.Anything, mock.Anything, mock.Anything)
				return
			}
			// The stubbed service refuses the renewal, so reaching it reads as 409.
			assert.Equal(t, http.StatusConflict, w.Code)
			svc.AssertExpectations(t)
		})
	}
}

// TestRenewCertificate_DefaultValidityClampedToMaximum pins Decision D5 on
// the renew route: without validity_days, a certificate issued before the
// cap with a longer period renews at the capped period, not a 400.
func TestRenewCertificate_DefaultValidityClampedToMaximum(t *testing.T) {
	certID := uuid.New()
	scope := certLegacyVaultScope()
	created := time.Now().Add(-24 * time.Hour)
	expires := created.AddDate(0, 0, model.MaxCertificateValidityDays+1000)

	svc := &mockCertService{}
	svc.On("GetCertificate", mock.Anything, certID, scope).
		Return(&model.Certificate{ID: certID, CreatedAt: created, ExpiresAt: &expires}, nil)
	svc.On("RenewCertificate", mock.Anything, certID, scope, model.MaxCertificateValidityDays).
		Return(nil, certServices.ErrRenewNotPossible)

	w := runCertVersionHandler(t, svc, &ApiParams{CertificateID: certID.String()},
		http.MethodPost, `{}`, renewCertificate)
	assert.Equal(t, http.StatusConflict, w.Code)
	svc.AssertExpectations(t)
}

// TestWriteCertificateError_InvalidValidityDaysIs400 covers the service-side
// sentinel, which the CLI path and any future caller reach.
func TestWriteCertificateError_InvalidValidityDaysIs400(t *testing.T) {
	c := newCertCtx(&mockCertService{}, certAdminClaims())
	writeCertificateError(c, fmt.Errorf("%w: must not exceed %d", certServices.ErrInvalidValidityDays, model.MaxCertificateValidityDays))
	w := httptest.NewRecorder()
	writeError(w, c)
	assert.Equal(t, http.StatusBadRequest, w.Code)

	// The renew route falls through to the same arm.
	c = newCertCtx(&mockCertService{}, certAdminClaims())
	writeCertificateRenewError(c, fmt.Errorf("%w: must not exceed %d", certServices.ErrInvalidValidityDays, model.MaxCertificateValidityDays))
	w = httptest.NewRecorder()
	writeError(w, c)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}
