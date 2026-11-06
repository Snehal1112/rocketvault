package api

// Audit-first handler tests for the key lifecycle, wrap and unwrap, role
// assignments, and the purges and deletes converted earlier: when the service
// refuses because its critical audit row could not be written, the handler
// answers 503 with exactly "audit unavailable" and nothing else.

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"rocketvault/app"
	"rocketvault/common"
	authzServices "rocketvault/internal/services/authorization"
	keyServices "rocketvault/internal/services/keys"
	"rocketvault/internal/testutils"
	"rocketvault/model"
)

// TestKeyRoutes_AuditUnavailable_Returns503 covers every key route whose
// service call is audit-first and goes through writeKeyError.
func TestKeyRoutes_AuditUnavailable_Returns503(t *testing.T) {
	keyID := uuid.New()
	jsonReq := func(method, path string, body any) *http.Request {
		b, _ := json.Marshal(body)
		return httptest.NewRequest(method, path, bytes.NewReader(b))
	}
	cases := []struct {
		name    string
		method  string
		args    []any
		handler func(*Context, http.ResponseWriter, *http.Request)
		req     *http.Request
	}{
		{"create RSA", "CreateRSAKey", []any{mock.Anything, mock.Anything}, createKey,
			jsonReq(http.MethodPost, "/keys", map[string]any{"name": "k", "type": "RSA", "bits": 2048})},
		{"create ECDSA", "CreateECDSAKey", []any{mock.Anything, mock.Anything}, createKey,
			jsonReq(http.MethodPost, "/keys", map[string]any{"name": "k", "type": "ECDSA", "curve": "P-256"})},
		{"create oct", "CreateOctKey", []any{mock.Anything, mock.Anything}, createKey,
			jsonReq(http.MethodPost, "/keys", map[string]any{"name": "k", "type": "OCT", "bits": 256})},
		{"import", "ImportKey", []any{mock.Anything, mock.Anything}, importKey,
			jsonReq(http.MethodPost, "/keys/import", map[string]any{"name": "k", "jwk": json.RawMessage(`{"kty":"EC"}`)})},
		{"rotate", "RotateKey", []any{mock.Anything, keyID, mock.Anything}, rotateKey,
			httptest.NewRequest(http.MethodPost, "/keys/"+keyID.String()+"/rotate", nil)},
		{"delete", "DeleteKey", []any{mock.Anything, keyID, mock.Anything}, deleteKey,
			httptest.NewRequest(http.MethodDelete, "/keys/"+keyID.String(), nil)},
		{"purge", "PurgeKey", []any{mock.Anything, keyID, mock.Anything}, purgeKey,
			httptest.NewRequest(http.MethodDelete, "/deleted/keys/"+keyID.String()+"/purge", nil)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			svc := &mockKeyService{}
			call := svc.On(tc.method, tc.args...)
			if tc.method == "PurgeKey" {
				call.Return(realAuditUnavailableErr(t))
			} else {
				call.Return(nil, realAuditUnavailableErr(t))
			}
			c := newKeyCtx(svc)
			c.Params = &ApiParams{KeyID: keyID.String(), PerPage: 60}
			w := httptest.NewRecorder()

			tc.handler(c, w, tc.req)
			if c.Err != nil {
				writeError(w, c)
			}

			assertFlatAuditUnavailable(t, w)
			svc.AssertExpectations(t)
			svc.AssertNotCalled(t, "GetKey", mock.Anything, mock.Anything, mock.Anything)
		})
	}
}

func TestWrapUnwrap_AuditUnavailable_Returns503(t *testing.T) {
	cases := []struct {
		name    string
		svc     *stubCryptoSvc
		body    map[string]any
		handler func(*Context, http.ResponseWriter, *http.Request)
	}{
		{"wrap", &stubCryptoSvc{wrapFn: func(context.Context, keyServices.WrapKeyRequest) (*keyServices.WrapKeyResult, error) {
			return nil, realAuditUnavailableErr(t)
		}}, map[string]any{"plaintext_key": base64.StdEncoding.EncodeToString([]byte("dek"))}, wrapKey},
		{"unwrap", &stubCryptoSvc{unwrapFn: func(context.Context, keyServices.UnwrapKeyRequest) (*keyServices.UnwrapKeyResult, error) {
			return nil, realAuditUnavailableErr(t)
		}}, map[string]any{"wrapped_key": base64.StdEncoding.EncodeToString([]byte("blob"))}, unwrapKey},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := newCryptoContext(tc.svc)
			w := httptest.NewRecorder()
			r := httptest.NewRequest(http.MethodPost, "/", jsonBody(t, tc.body))

			tc.handler(c, w, r)
			if c.Err != nil {
				writeError(w, c)
			}

			assertFlatAuditUnavailable(t, w)
			assert.NotContains(t, w.Body.String(), "plaintext_key")
			assert.NotContains(t, w.Body.String(), "wrapped_key")
		})
	}
}

// roleAssignmentAdminCtx builds a Context for a global admin managing role
// assignments in vaultID through roleSvc.
func roleAssignmentAdminCtx(roleSvc authzServices.RoleAssignmentService, callerID uuid.UUID, assignmentID string) *Context {
	mc := &testutils.MockServiceContainer{}
	mc.On("GetAccessPolicyService").Return(&mockAccessPolicyService{})
	mc.On("GetRoleAssignmentService").Return(roleSvc)
	return &Context{
		App:    &app.App{ServiceContainer: mc},
		Claims: RequestClaims{UserID: callerID.String(), Roles: []string{model.RoleAdmin}},
		Params: &ApiParams{VaultName: "prod", AssignmentID: assignmentID, PerPage: 60},
	}
}

func TestRoleAssignments_AuditUnavailable_Returns503(t *testing.T) {
	vaultID := uuid.New()
	callerID := uuid.New()
	assignmentID := uuid.New()
	withVault := func(r *http.Request) *http.Request {
		return r.WithContext(context.WithValue(r.Context(), common.VaultIDKey, vaultID.String()))
	}

	t.Run("grant", func(t *testing.T) {
		roleSvc := &mockRoleAssignmentService{}
		roleSvc.On("AssignRole", mock.Anything, mock.MatchedBy(func(in authzServices.AssignRoleInput) bool {
			return in.CreatedBy == callerID && in.VaultID == vaultID
		})).Return(nil, realAuditUnavailableErr(t))
		c := roleAssignmentAdminCtx(roleSvc, callerID, "")
		body := []byte(`{"principal":"alice","role":"Key Vault Reader"}`)
		r := withVault(httptest.NewRequest(http.MethodPost, "/api/v1/vaults/prod/role-assignments", bytes.NewReader(body)))
		w := httptest.NewRecorder()

		createRoleAssignment(c, w, r)
		if c.Err != nil {
			writeError(w, c)
		}

		assertFlatAuditUnavailable(t, w)
		roleSvc.AssertExpectations(t)
	})

	t.Run("revoke", func(t *testing.T) {
		roleSvc := &mockRoleAssignmentService{}
		roleSvc.On("RevokeAssignment", mock.Anything, assignmentID, vaultID, callerID, true).Return(realAuditUnavailableErr(t))
		c := roleAssignmentAdminCtx(roleSvc, callerID, assignmentID.String())
		r := withVault(httptest.NewRequest(http.MethodDelete, "/api/v1/vaults/prod/role-assignments/"+assignmentID.String(), nil))
		w := httptest.NewRecorder()

		deleteRoleAssignment(c, w, r)
		if c.Err != nil {
			writeError(w, c)
		}

		assertFlatAuditUnavailable(t, w)
		roleSvc.AssertExpectations(t)
	})
}

func TestPurgeCertificate_AuditUnavailable_Returns503(t *testing.T) {
	certID := uuid.New()
	svc := &mockCertService{}
	svc.On("PurgeCertificate", mock.Anything, certID, mock.Anything).Return(realAuditUnavailableErr(t))
	c := newCertCtx(svc, certAdminClaims())
	c.Params = &ApiParams{CertificateID: certID.String(), PerPage: 60}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodDelete, "/deleted/certificates/"+certID.String()+"/purge", nil)

	purgeCertificate(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assertFlatAuditUnavailable(t, w)
}

// TestVaultDeleteAndPurge_AuditUnavailable_Returns503 runs the real vault
// service through the router with a failing audit service, and checks the
// vault is left as it was.
func TestVaultDeleteAndPurge_AuditUnavailable_Returns503(t *testing.T) {
	t.Run("delete", func(t *testing.T) {
		api, repo := newVaultTestAPI()
		api.App.ServiceContainer.(*vaultSvcTestContainer).vaultSvc.SetAuditService(failingCriticalAudit())
		id := uuid.New()
		repo.byName["stg"] = &model.Vault{ID: id, Name: "stg", Enabled: true}
		repo.byID[id.String()] = repo.byName["stg"]

		w := doVaultRequest(api, http.MethodDelete, "/api/v1/vaults/stg", nil)

		assertFlatAuditUnavailable(t, w)
		v, err := repo.ReadByID(context.Background(), id)
		require.NoError(t, err)
		assert.Nil(t, v.DeletedAt, "the vault must stay live")
	})

	t.Run("purge", func(t *testing.T) {
		api, repo := newVaultTestAPI()
		api.App.ServiceContainer.(*vaultSvcTestContainer).vaultSvc.SetAuditService(failingCriticalAudit())
		id := uuid.New()
		deletedAt := time.Now()
		repo.byName["stg"] = &model.Vault{ID: id, Name: "stg", Enabled: true, DeletedAt: &deletedAt}
		repo.byID[id.String()] = repo.byName["stg"]

		w := doVaultRequest(api, http.MethodDelete, "/api/v1/vaults/stg/purge", nil)

		assertFlatAuditUnavailable(t, w)
		_, err := repo.ReadByID(context.Background(), id)
		assert.NoError(t, err, "the vault must not be purged")
	})
}
