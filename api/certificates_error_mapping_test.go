package api

import (
	"errors"
	"fmt"
	"net/http"
	"testing"

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

			w = doVaultRequest(api, http.MethodPost, prefix+"/"+certID+"/renew", []byte(`{"validity_days":30}`))
			require.Equal(t, http.StatusConflict, w.Code, w.Body.String())
			assert.NotContains(t, w.Body.String(), leakedKeyID.String())

			svc.AssertCalled(t, "CreateSelfSignedCertificate", mock.Anything, mock.Anything)
			svc.AssertCalled(t, "RenewCertificate", mock.Anything, mock.Anything, mock.Anything, 30)
		})
	}
}
