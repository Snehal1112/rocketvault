package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"rocketvault/internal/logging/logtest"
	authzServices "rocketvault/internal/services/authorization"
	"rocketvault/model"
)

// postCreateCertificate runs createCertificate for a minimal valid body.
func postCreateCertificate(c *Context) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	body, _ := json.Marshal(map[string]any{
		"name": "mycert", "key_id": uuid.New().String(), "validity_days": 365,
	})
	r := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/certificates", bytes.NewReader(body))
	createCertificate(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}
	return w
}

// postRenewCertificate runs renewCertificate with an explicit validity.
func postRenewCertificate(c *Context) *httptest.ResponseRecorder {
	c.Params.CertificateID = uuid.New().String()
	w := httptest.NewRecorder()
	r := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/certificates", bytes.NewBufferString(`{"validity_days":90}`))
	renewCertificate(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}
	return w
}

// TestCreateCertificate_RequiresKeySign pins B77 on the HTTP path. The route
// maps to certificates/create only, but issuing a certificate signs with the
// key, so keys/sign is required in the same vault.
func TestCreateCertificate_RequiresKeySign(t *testing.T) {
	svc := &mockCertService{}
	roles := &mockRoleAssignmentService{}
	roles.On("HasDataAction", mock.Anything, uuid.MustParse(certTestUserID),
		uuid.MustParse(model.DefaultVaultID), model.ActionKeysSign).Return(false, nil)

	c := newCertCtx(svc, certAdminClaims())
	c.App.ServiceContainer.(*certSvcContainer).roleSvc = roles

	w := postCreateCertificate(c)
	assert.Equal(t, http.StatusForbidden, w.Code)
	svc.AssertNotCalled(t, "CreateSelfSignedCertificate", mock.Anything, mock.Anything)
	roles.AssertExpectations(t)
}

// TestCreateCertificate_KeySignDenyPolicyRefuses pins the explicit-deny half:
// a deny on (keys, sign) blocks issuance even when a role would grant it.
func TestCreateCertificate_KeySignDenyPolicyRefuses(t *testing.T) {
	svc := &mockCertService{}
	policies := &mockAccessPolicyService{}
	policies.On("CheckAccess", mock.Anything, uuid.MustParse(certTestUserID), model.PolicyResourceKeys,
		model.OpSign, uuid.MustParse(model.DefaultVaultID)).Return(authzServices.AccessDenied, nil)

	c := newCertCtx(svc, certAdminClaims())
	c.App.ServiceContainer.(*certSvcContainer).policySvc = policies

	w := postCreateCertificate(c)
	assert.Equal(t, http.StatusForbidden, w.Code)
	svc.AssertNotCalled(t, "CreateSelfSignedCertificate", mock.Anything, mock.Anything)
	policies.AssertExpectations(t)
}

// TestRenewCertificate_RequiresKeySign pins B77 on the HTTP renew route, which
// the MCP renew_certificate tool also uses. Renewal re-signs with the
// certificate's key, so keys/sign is required, exactly as for issuance.
func TestRenewCertificate_RequiresKeySign(t *testing.T) {
	svc := &mockCertService{}
	roles := &mockRoleAssignmentService{}
	roles.On("HasDataAction", mock.Anything, uuid.MustParse(certTestUserID),
		uuid.MustParse(model.DefaultVaultID), model.ActionKeysSign).Return(false, nil)

	c := newCertCtx(svc, certAdminClaims())
	c.App.ServiceContainer.(*certSvcContainer).roleSvc = roles

	w := postRenewCertificate(c)
	assert.Equal(t, http.StatusForbidden, w.Code)
	svc.AssertNotCalled(t, "RenewCertificate", mock.Anything, mock.Anything, mock.Anything, mock.Anything)
	svc.AssertNotCalled(t, "GetCertificate", mock.Anything, mock.Anything, mock.Anything)
	roles.AssertExpectations(t)
}

// TestRenewCertificate_KeySignDenyPolicyRefuses pins the explicit-deny half on
// the renew route.
func TestRenewCertificate_KeySignDenyPolicyRefuses(t *testing.T) {
	svc := &mockCertService{}
	policies := &mockAccessPolicyService{}
	policies.On("CheckAccess", mock.Anything, uuid.MustParse(certTestUserID), model.PolicyResourceKeys,
		model.OpSign, uuid.MustParse(model.DefaultVaultID)).Return(authzServices.AccessDenied, nil)

	c := newCertCtx(svc, certAdminClaims())
	c.App.ServiceContainer.(*certSvcContainer).policySvc = policies

	w := postRenewCertificate(c)
	assert.Equal(t, http.StatusForbidden, w.Code)
	svc.AssertNotCalled(t, "RenewCertificate", mock.Anything, mock.Anything, mock.Anything, mock.Anything)
	policies.AssertExpectations(t)
}

// TestKeySign_LookupFailureIs500 pins that a failed policy or role lookup is
// a server fault, never a refusal and never a pass, on both handlers.
func TestKeySign_LookupFailureIs500(t *testing.T) {
	lookupErr := errors.New("db down: secret-detail")
	type setup func(c *certSvcContainer)
	failures := map[string]setup{
		"policy lookup": func(c *certSvcContainer) {
			policies := &mockAccessPolicyService{}
			policies.On("CheckAccess", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).
				Return(authzServices.AccessFallback, lookupErr)
			c.policySvc = policies
		},
		"role lookup": func(c *certSvcContainer) {
			roles := &mockRoleAssignmentService{}
			roles.On("HasDataAction", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(false, lookupErr)
			c.roleSvc = roles
		},
	}
	handlers := map[string]func(*Context) *httptest.ResponseRecorder{
		"create": postCreateCertificate,
		"renew":  postRenewCertificate,
	}
	for fName, fail := range failures {
		for hName, run := range handlers {
			t.Run(hName+" "+fName, func(t *testing.T) {
				svc := &mockCertService{}
				c := newCertCtx(svc, certAdminClaims())
				fail(c.App.ServiceContainer.(*certSvcContainer))

				w := run(c)
				assert.Equal(t, http.StatusInternalServerError, w.Code)
				assert.NotContains(t, w.Body.String(), "secret-detail")
				assert.Empty(t, svc.Calls, "no certificate service call after a failed check")
			})
		}
	}
}

// newKeySignRouterAPI builds the routed test API with explicit policy and
// role services, so a test drives the real flat and vault-scoped routes.
func newKeySignRouterAPI(t *testing.T, svc *mockCertService, policies authzServices.AccessPolicyService,
	roles authzServices.RoleAssignmentService) (*API, uuid.UUID, *logtest.Recorder) {
	t.Helper()
	api, repo := newVaultScopedKeyCertTestAPI(nil, svc, nil)
	c := api.App.ServiceContainer.(*vaultSvcTestContainer)
	c.policySvc, c.roleSvc = policies, roles
	logger, rec := logtest.NewLogger()
	api.App.Logger = logger
	prodID := uuid.New()
	repo.byName["prod"] = &model.Vault{ID: prodID, Name: "prod", Enabled: true}
	repo.byID[prodID.String()] = repo.byName["prod"]
	return api, prodID, rec
}

// TestKeySign_BothRouteShapes drives create and renew through the flat and
// the vault-scoped routes. The check must run against the vault the route
// resolved, as the authenticated caller, and a refusal must be audited and
// reach no service method.
func TestKeySign_BothRouteShapes(t *testing.T) {
	certID := uuid.New().String()
	createBody := []byte(`{"name":"mycert","key_id":"` + uuid.New().String() + `","validity_days":365,"vault_id":"` + uuid.New().String() + `"}`)
	renewBody := []byte(`{"validity_days":90}`)
	cases := []struct {
		name, path, operation string
		body                  []byte
		vaultScoped           bool
	}{
		{"flat create", "/api/v1/certificates", "create_certificate", createBody, false},
		{"vault-scoped create", "/api/v1/vaults/prod/certificates", "create_certificate", createBody, true},
		{"flat renew", "/api/v1/certificates/" + certID + "/renew", "renew_certificate", renewBody, false},
		{"vault-scoped renew", "/api/v1/vaults/prod/certificates/" + certID + "/renew", "renew_certificate", renewBody, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			svc := &mockCertService{}
			policies := &mockAccessPolicyService{}
			roles := &mockRoleAssignmentService{}
			api, prodID, rec := newKeySignRouterAPI(t, svc, policies, roles)
			vaultID := uuid.MustParse(model.DefaultVaultID)
			if tc.vaultScoped {
				vaultID = prodID
			}
			callerID := uuid.MustParse(vaultTestUserID)
			policies.On("CheckAccess", mock.Anything, callerID, model.PolicyResourceKeys, model.OpSign, vaultID).
				Return(authzServices.AccessFallback, nil).Once()
			roles.On("HasDataAction", mock.Anything, callerID, vaultID, model.ActionKeysSign).Return(false, nil).Once()

			w := doVaultRequest(api, http.MethodPost, tc.path, tc.body)

			require.Equal(t, http.StatusForbidden, w.Code, w.Body.String())
			assert.Contains(t, w.Body.String(), string(model.ActionKeysSign))
			policies.AssertExpectations(t)
			roles.AssertExpectations(t)
			assert.Empty(t, svc.Calls, "a refused caller reaches no certificate service method")
			row, ok := rec.Find(tc.operation, "denied")
			require.True(t, ok, "a keys/sign refusal must be audited")
			assert.Equal(t, vaultTestUserID, row.UserID)
		})
	}
}

// TestKeySign_UnwiredAuthorizationFailsClosed pins that a container which
// returns no role service answers 500 rather than letting the request
// through. Production wiring always constructs both services; this guards
// against a future wiring regression.
func TestKeySign_UnwiredAuthorizationFailsClosed(t *testing.T) {
	certID := uuid.New().String()
	for _, tc := range []struct{ path, body string }{
		{"/api/v1/vaults/prod/certificates", `{"name":"mycert","key_id":"` + uuid.New().String() + `","validity_days":365}`},
		{"/api/v1/vaults/prod/certificates/" + certID + "/renew", `{"validity_days":90}`},
	} {
		t.Run(tc.path, func(t *testing.T) {
			svc := &mockCertService{}
			policies := &mockAccessPolicyService{}
			policies.On("CheckAccess", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).
				Return(authzServices.AccessFallback, nil).Maybe()
			// The vaultSvcTestContainer returns nil for an unset role service.
			api, _, _ := newKeySignRouterAPI(t, svc, policies, nil)

			w := doVaultRequest(api, http.MethodPost, tc.path, []byte(tc.body))

			assert.Equal(t, http.StatusInternalServerError, w.Code, w.Body.String())
			assert.Empty(t, svc.Calls)
		})
	}
}
