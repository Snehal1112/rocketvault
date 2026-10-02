// Package api — internal tests for access policy handlers.
package api

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	"rocketvault/app"
	rvconfig "rocketvault/config"
	"rocketvault/internal/backup"
	"rocketvault/internal/cache"
	"rocketvault/internal/crypto"
	"rocketvault/internal/keycache"
	"rocketvault/internal/logging"
	"rocketvault/internal/metrics"
	"rocketvault/internal/repositories"
	auditServices "rocketvault/internal/services/audit"
	authServices "rocketvault/internal/services/auth"
	authzServices "rocketvault/internal/services/authorization"
	certServices "rocketvault/internal/services/certificates"
	keyServices "rocketvault/internal/services/keys"
	oauth2Services "rocketvault/internal/services/oauth2"
	"rocketvault/internal/services/provisioning"
	retryServices "rocketvault/internal/services/retry"
	secretServices "rocketvault/internal/services/secrets"
	userServices "rocketvault/internal/services/users"
	vaultServices "rocketvault/internal/services/vaults"
	"rocketvault/internal/signing"
	"rocketvault/internal/certcache"
	"rocketvault/internal/vaultcache"
	"rocketvault/model"
)

// --- mock AccessPolicyService ---

type mockAccessPolicyService struct {
	mock.Mock
}

func (m *mockAccessPolicyService) CheckAccess(ctx context.Context, principalID uuid.UUID, resourceType model.PolicyResourceType, operation model.PolicyOperation, vaultID uuid.UUID) (authzServices.AccessDecision, error) {
	args := m.Called(ctx, principalID, resourceType, operation, vaultID)
	return args.Get(0).(authzServices.AccessDecision), args.Error(1)
}

func (m *mockAccessPolicyService) CheckVaultScopedAccess(ctx context.Context, principalID uuid.UUID, resourceType model.PolicyResourceType, operation model.PolicyOperation, vaultID uuid.UUID) (authzServices.AccessDecision, error) {
	args := m.Called(ctx, principalID, resourceType, operation, vaultID)
	return args.Get(0).(authzServices.AccessDecision), args.Error(1)
}

func (m *mockAccessPolicyService) CreatePolicy(ctx context.Context, policy *model.AccessPolicy, actorID uuid.UUID) error {
	args := m.Called(ctx, policy, actorID)
	return args.Error(0)
}

func (m *mockAccessPolicyService) GetPolicy(ctx context.Context, id uuid.UUID) (*model.AccessPolicy, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*model.AccessPolicy), args.Error(1)
}

func (m *mockAccessPolicyService) ListPolicies(ctx context.Context) ([]*model.AccessPolicy, error) {
	args := m.Called(ctx)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*model.AccessPolicy), args.Error(1)
}

func (m *mockAccessPolicyService) ListByPrincipal(ctx context.Context, principalID uuid.UUID) ([]*model.AccessPolicy, error) {
	args := m.Called(ctx, principalID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*model.AccessPolicy), args.Error(1)
}

func (m *mockAccessPolicyService) UpdatePolicy(ctx context.Context, policy *model.AccessPolicy, actorID uuid.UUID) error {
	args := m.Called(ctx, policy, actorID)
	return args.Error(0)
}

func (m *mockAccessPolicyService) DeletePolicy(ctx context.Context, id, actorID uuid.UUID) error {
	args := m.Called(ctx, id, actorID)
	return args.Error(0)
}

// --- policyContainer: a container stub that provides AccessPolicyService ---

// policyContainer satisfies ServiceContainerInterface for access policy handler tests.
// All methods except GetAccessPolicyService panic to surface accidental calls.
type policyContainer struct {
	policySvc authzServices.AccessPolicyService
}

func (c *policyContainer) GetAccessPolicyService() authzServices.AccessPolicyService {
	return c.policySvc
}
func (c *policyContainer) GetRoleAssignmentService() authzServices.RoleAssignmentService {
	return nil
}
func (c *policyContainer) GetGrantService() provisioning.GrantService {
	return nil
}
func (c *policyContainer) GetRBACService() authzServices.RBACService {
	panic("unexpected call: GetRBACService")
}
func (c *policyContainer) GetUserRepository() repositories.UserRepositoryInterface {
	panic("unexpected call: GetUserRepository")
}
func (c *policyContainer) GetSecretRepository() repositories.SecretRepositoryInterface {
	panic("unexpected call: GetSecretRepository")
}
func (c *policyContainer) GetRotationRepository() repositories.RotationPolicyRepositoryInterface {
	panic("unexpected call: GetRotationRepository")
}
func (c *policyContainer) GetVersionRepository() repositories.SecretVersionRepositoryInterface {
	panic("unexpected call: GetVersionRepository")
}
func (c *policyContainer) GetKeyRepository() repositories.KeyRepositoryInterface {
	panic("unexpected call: GetKeyRepository")
}
func (c *policyContainer) GetCertificateRepository() repositories.CertificateRepositoryInterface {
	panic("unexpected call: GetCertificateRepository")
}
func (c *policyContainer) GetKeyRotationPolicyRepository() repositories.KeyRotationPolicyRepositoryInterface {
	panic("unexpected call: GetKeyRotationPolicyRepository")
}
func (c *policyContainer) GetCertificatePolicyRepository() repositories.CertificatePolicyRepositoryInterface {
	panic("unexpected call: GetCertificatePolicyRepository")
}
func (c *policyContainer) GetSessionRepository() repositories.SessionRepositoryInterface {
	panic("unexpected call: GetSessionRepository")
}
func (c *policyContainer) GetVaultRepository() repositories.VaultRepositoryInterface {
	panic("unexpected call: GetVaultRepository")
}
func (c *policyContainer) GetVaultService() vaultServices.VaultService {
	panic("unexpected call: GetVaultService")
}
func (c *policyContainer) GetVaultWebhookService() vaultServices.VaultWebhookService {
	panic("unexpected call: GetVaultWebhookService")
}
func (c *policyContainer) GetPasswordService() authServices.PasswordService {
	panic("unexpected call: GetPasswordService")
}
func (c *policyContainer) GetTOTPService() authServices.TOTPService {
	panic("unexpected call: GetTOTPService")
}
func (c *policyContainer) GetJWTService() authServices.JWTService {
	panic("unexpected call: GetJWTService")
}
func (c *policyContainer) GetAuthenticationService() authServices.AuthenticationService {
	panic("unexpected call: GetAuthenticationService")
}
func (c *policyContainer) GetOIDCService() authServices.OIDCService {
	panic("unexpected call: GetOIDCService")
}
func (c *policyContainer) GetAccessPolicyRepository() repositories.AccessPolicyRepositoryInterface {
	panic("unexpected call: GetAccessPolicyRepository")
}
func (c *policyContainer) GetOAuth2ClientRepository() repositories.OAuth2ClientRepositoryInterface {
	panic("unexpected call: GetOAuth2ClientRepository")
}
func (c *policyContainer) GetOAuth2Service() oauth2Services.OAuth2Service {
	panic("unexpected call: GetOAuth2Service")
}
func (c *policyContainer) GetUserService() userServices.UserService {
	panic("unexpected call: GetUserService")
}
func (c *policyContainer) GetSecretService() secretServices.SecretService {
	panic("unexpected call: GetSecretService")
}
func (c *policyContainer) GetKeyService() keyServices.KeyService {
	panic("unexpected call: GetKeyService")
}
func (c *policyContainer) GetCertificateService() certServices.CertificateService {
	panic("unexpected call: GetCertificateService")
}
func (c *policyContainer) GetCertificateRenewalService() certServices.CertificateRenewalService {
	panic("unexpected call: GetCertificateRenewalService")
}
func (c *policyContainer) GetCryptoService() keyServices.CryptoService {
	panic("unexpected call: GetCryptoService")
}
func (c *policyContainer) GetCryptographyService() secretServices.CryptographyService {
	panic("unexpected call: GetCryptographyService")
}
func (c *policyContainer) GetVersioningService() secretServices.VersioningServiceInterface {
	panic("unexpected call: GetVersioningService")
}
func (c *policyContainer) GetTagService() secretServices.TagService {
	panic("unexpected call: GetTagService")
}
func (c *policyContainer) GetRotationService() secretServices.RotationServiceInterface {
	panic("unexpected call: GetRotationService")
}
func (c *policyContainer) GetSchedulerService() secretServices.SchedulerServiceInterface {
	panic("unexpected call: GetSchedulerService")
}
func (c *policyContainer) GetDatabase() *sql.DB       { panic("unexpected call: GetDatabase") }
func (c *policyContainer) GetLogger() *logging.Logger { panic("unexpected call: GetLogger") }
func (c *policyContainer) GetSecretCache() *cache.SecretCache {
	panic("unexpected call: GetSecretCache")
}
func (c *policyContainer) GetCacheConfig() rvconfig.CacheConfig {
	panic("unexpected call: GetCacheConfig")
}

func (c *policyContainer) GetVaultCache() *vaultcache.Cache {
	panic("unexpected call: GetVaultCache")
}
func (c *policyContainer) GetCertificateCache() *certcache.Cache {
	panic("unexpected call: GetCertificateCache")
}
func (c *policyContainer) GetCachedSecretService() secretServices.SecretService {
	panic("unexpected call: GetCachedSecretService")
}
func (c *policyContainer) GetRetryService() retryServices.RetryService {
	panic("unexpected call: GetRetryService")
}
func (c *policyContainer) GetKeyProvider() crypto.KeyProvider             { return nil }
func (c *policyContainer) GetSigningProvider() signing.SigningKeyProvider { return nil }
func (c *policyContainer) GetItemBackupService() *backup.ItemBackupService {
	return nil
}
func (c *policyContainer) GetKeyCache() keycache.Cache             { return nil }
func (c *policyContainer) GetCryptoMetrics() metrics.CryptoMetrics { return nil }
func (c *policyContainer) GetAuditService() auditServices.AuditServiceInterface {
	return nil
}
func (c *policyContainer) GetComplianceReportService() auditServices.ComplianceReportServiceInterface {
	return nil
}
func (c *policyContainer) Close() error { return nil }

// newPolicyCtx builds a Context backed by the given AccessPolicyService mock,
// authenticated as an admin. Access-policy handlers are admin-gated (an access
// policy can override the deny-by-default vault decision or grant access
// across every vault), so every existing success-path test in this file
// needs an admin claim to keep exercising the handler body instead of being
// turned away at the gate.
func newPolicyCtx(svc authzServices.AccessPolicyService) *Context {
	a := &app.App{ServiceContainer: &policyContainer{policySvc: svc}}
	return &Context{
		App:    a,
		Params: &ApiParams{PerPage: 60},
		Claims: RequestClaims{
			UserID: "00000000-0000-0000-0000-0000000000ad",
			Roles:  []string{"secrets_manager", string(model.RoleAdmin)},
		},
	}
}

// newNonAdminPolicyCtx builds a Context identical to newPolicyCtx but
// authenticated as an ordinary user, for asserting the admin gate itself.
func newNonAdminPolicyCtx(svc authzServices.AccessPolicyService) *Context {
	a := &app.App{ServiceContainer: &policyContainer{policySvc: svc}}
	return &Context{
		App:    a,
		Params: &ApiParams{PerPage: 60},
		Claims: RequestClaims{Roles: []string{string(model.RoleUser)}},
	}
}

// ============================================================
// listAccessPolicies
// ============================================================

func TestListAccessPolicies_Success_Returns200(t *testing.T) {
	svc := &mockAccessPolicyService{}
	policies := []*model.AccessPolicy{
		{ID: uuid.New(), PrincipalType: model.PrincipalTypeUser, Effect: model.PolicyEffectAllow},
	}
	svc.On("ListPolicies", mock.Anything).Return(policies, nil)

	c := newPolicyCtx(svc)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/access-policies", nil)

	listAccessPolicies(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusOK, w.Code)
	svc.AssertExpectations(t)
}

func TestListAccessPolicies_NilList_Returns200Empty(t *testing.T) {
	svc := &mockAccessPolicyService{}
	// Service returning nil; handler should convert to empty slice.
	svc.On("ListPolicies", mock.Anything).Return([]*model.AccessPolicy(nil), nil)

	c := newPolicyCtx(svc)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/access-policies", nil)

	listAccessPolicies(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusOK, w.Code)
	svc.AssertExpectations(t)
}

func TestListAccessPolicies_ServiceError_Returns500(t *testing.T) {
	svc := &mockAccessPolicyService{}
	svc.On("ListPolicies", mock.Anything).Return([]*model.AccessPolicy(nil), errors.New("db error"))

	c := newPolicyCtx(svc)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/access-policies", nil)

	listAccessPolicies(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusInternalServerError, w.Code)
	svc.AssertExpectations(t)
}

// ============================================================
// createAccessPolicy
// ============================================================

func TestCreateAccessPolicy_InvalidJSON_Returns400(t *testing.T) {
	c := newPolicyCtx(nil)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/access-policies", bytes.NewReader([]byte("{invalid json")))

	createAccessPolicy(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestCreateAccessPolicy_InvalidPrincipalID_Returns400(t *testing.T) {
	c := newPolicyCtx(nil)
	w := httptest.NewRecorder()
	body, _ := json.Marshal(map[string]string{
		"principal_id":   "not-a-uuid",
		"principal_type": "user",
		"resource_type":  "secrets",
		"operation":      "get",
		"effect":         "allow",
	})
	r := httptest.NewRequest(http.MethodPost, "/access-policies", bytes.NewReader(body))

	createAccessPolicy(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestCreateAccessPolicy_MissingRequiredFields_Returns400(t *testing.T) {
	c := newPolicyCtx(nil)
	w := httptest.NewRecorder()
	// Missing effect, resource_type, operation and principal_type.
	body, _ := json.Marshal(map[string]string{
		"principal_id": uuid.New().String(),
	})
	r := httptest.NewRequest(http.MethodPost, "/access-policies", bytes.NewReader(body))

	createAccessPolicy(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestCreateAccessPolicy_ServiceError_Returns500(t *testing.T) {
	svc := &mockAccessPolicyService{}
	svc.On("CreatePolicy", mock.Anything, mock.Anything, mock.Anything).Return(errors.New("db error"))

	c := newPolicyCtx(svc)
	w := httptest.NewRecorder()
	body, _ := json.Marshal(map[string]string{
		"principal_id":   uuid.New().String(),
		"principal_type": "user",
		"resource_type":  "secrets",
		"operation":      "get",
		"effect":         "allow",
	})
	r := httptest.NewRequest(http.MethodPost, "/access-policies", bytes.NewReader(body))

	createAccessPolicy(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusInternalServerError, w.Code)
	svc.AssertExpectations(t)
}

func TestCreateAccessPolicy_Success_Returns201(t *testing.T) {
	svc := &mockAccessPolicyService{}
	svc.On("CreatePolicy", mock.Anything, mock.Anything, mock.Anything).Return(nil)

	c := newPolicyCtx(svc)
	w := httptest.NewRecorder()
	body, _ := json.Marshal(map[string]string{
		"principal_id":   uuid.New().String(),
		"principal_type": "user",
		"resource_type":  "secrets",
		"operation":      "get",
		"effect":         "allow",
	})
	r := httptest.NewRequest(http.MethodPost, "/access-policies", bytes.NewReader(body))

	createAccessPolicy(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusCreated, w.Code)
	svc.AssertExpectations(t)
}

// ============================================================
// getAccessPolicy
// ============================================================

func TestGetAccessPolicy_InvalidPolicyID_Returns400(t *testing.T) {
	c := newPolicyCtx(nil)
	c.Params = &ApiParams{PolicyID: "not-a-uuid", PerPage: 60}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/access-policies/not-a-uuid", nil)

	getAccessPolicy(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestGetAccessPolicy_NotFound_Returns404(t *testing.T) {
	svc := &mockAccessPolicyService{}
	policyID := uuid.New()
	svc.On("GetPolicy", mock.Anything, policyID).Return(nil, errors.New("not found"))

	c := newPolicyCtx(svc)
	c.Params = &ApiParams{PolicyID: policyID.String(), PerPage: 60}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/access-policies/"+policyID.String(), nil)

	getAccessPolicy(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusNotFound, w.Code)
	svc.AssertExpectations(t)
}

func TestGetAccessPolicy_Success_Returns200(t *testing.T) {
	svc := &mockAccessPolicyService{}
	policyID := uuid.New()
	svc.On("GetPolicy", mock.Anything, policyID).Return(&model.AccessPolicy{
		ID:     policyID,
		Effect: model.PolicyEffectAllow,
	}, nil)

	c := newPolicyCtx(svc)
	c.Params = &ApiParams{PolicyID: policyID.String(), PerPage: 60}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/access-policies/"+policyID.String(), nil)

	getAccessPolicy(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusOK, w.Code)
	svc.AssertExpectations(t)
}

// ============================================================
// updateAccessPolicy
// ============================================================

func TestUpdateAccessPolicy_InvalidPolicyID_Returns400(t *testing.T) {
	c := newPolicyCtx(nil)
	c.Params = &ApiParams{PolicyID: "bad", PerPage: 60}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPut, "/access-policies/bad", bytes.NewReader([]byte(`{"effect":"allow"}`)))

	updateAccessPolicy(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestUpdateAccessPolicy_MissingEffect_Returns400(t *testing.T) {
	policyID := uuid.New()
	c := newPolicyCtx(nil)
	c.Params = &ApiParams{PolicyID: policyID.String(), PerPage: 60}
	w := httptest.NewRecorder()
	// Empty effect.
	r := httptest.NewRequest(http.MethodPut, "/access-policies/"+policyID.String(), bytes.NewReader([]byte(`{"effect":""}`)))

	updateAccessPolicy(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestUpdateAccessPolicy_NotFound_Returns404(t *testing.T) {
	svc := &mockAccessPolicyService{}
	policyID := uuid.New()
	svc.On("GetPolicy", mock.Anything, policyID).Return(nil, errors.New("not found"))

	c := newPolicyCtx(svc)
	c.Params = &ApiParams{PolicyID: policyID.String(), PerPage: 60}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPut, "/access-policies/"+policyID.String(), bytes.NewReader([]byte(`{"effect":"deny"}`)))

	updateAccessPolicy(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusNotFound, w.Code)
	svc.AssertExpectations(t)
}

func TestUpdateAccessPolicy_ServiceError_Returns500(t *testing.T) {
	svc := &mockAccessPolicyService{}
	policyID := uuid.New()
	svc.On("GetPolicy", mock.Anything, policyID).Return(&model.AccessPolicy{
		ID: policyID, Effect: model.PolicyEffectAllow,
	}, nil)
	svc.On("UpdatePolicy", mock.Anything, mock.Anything, mock.Anything).Return(errors.New("db error"))

	c := newPolicyCtx(svc)
	c.Params = &ApiParams{PolicyID: policyID.String(), PerPage: 60}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPut, "/access-policies/"+policyID.String(), bytes.NewReader([]byte(`{"effect":"deny"}`)))

	updateAccessPolicy(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusInternalServerError, w.Code)
	svc.AssertExpectations(t)
}

func TestUpdateAccessPolicy_Success_Returns200(t *testing.T) {
	svc := &mockAccessPolicyService{}
	policyID := uuid.New()
	svc.On("GetPolicy", mock.Anything, policyID).Return(&model.AccessPolicy{
		ID: policyID, Effect: model.PolicyEffectAllow,
	}, nil)
	svc.On("UpdatePolicy", mock.Anything, mock.Anything, mock.Anything).Return(nil)

	c := newPolicyCtx(svc)
	c.Params = &ApiParams{PolicyID: policyID.String(), PerPage: 60}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPut, "/access-policies/"+policyID.String(), bytes.NewReader([]byte(`{"effect":"deny"}`)))

	updateAccessPolicy(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusOK, w.Code)
	svc.AssertExpectations(t)
}

// ============================================================
// deleteAccessPolicy
// ============================================================

func TestDeleteAccessPolicy_InvalidPolicyID_Returns400(t *testing.T) {
	c := newPolicyCtx(nil)
	c.Params = &ApiParams{PolicyID: "bad", PerPage: 60}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodDelete, "/access-policies/bad", nil)

	deleteAccessPolicy(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestDeleteAccessPolicy_ServiceError_Returns500(t *testing.T) {
	svc := &mockAccessPolicyService{}
	policyID := uuid.New()
	svc.On("DeletePolicy", mock.Anything, policyID, uuid.MustParse("00000000-0000-0000-0000-0000000000ad")).Return(errors.New("db error"))

	c := newPolicyCtx(svc)
	c.Params = &ApiParams{PolicyID: policyID.String(), PerPage: 60}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodDelete, "/access-policies/"+policyID.String(), nil)

	deleteAccessPolicy(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusInternalServerError, w.Code)
	svc.AssertExpectations(t)
}

func TestDeleteAccessPolicy_Success_Returns200(t *testing.T) {
	svc := &mockAccessPolicyService{}
	policyID := uuid.New()
	svc.On("DeletePolicy", mock.Anything, policyID, uuid.MustParse("00000000-0000-0000-0000-0000000000ad")).Return(nil)

	c := newPolicyCtx(svc)
	c.Params = &ApiParams{PolicyID: policyID.String(), PerPage: 60}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodDelete, "/access-policies/"+policyID.String(), nil)

	deleteAccessPolicy(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusOK, w.Code)
	svc.AssertExpectations(t)
}

// ============================================================
// listAccessPoliciesByPrincipal
// ============================================================

func TestListAccessPoliciesByPrincipal_InvalidPrincipalID_Returns400(t *testing.T) {
	c := newPolicyCtx(nil)
	c.Params = &ApiParams{PrincipalID: "bad-id", PerPage: 60}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/access-policies/principal/bad-id", nil)

	listAccessPoliciesByPrincipal(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestListAccessPoliciesByPrincipal_Success_Returns200(t *testing.T) {
	svc := &mockAccessPolicyService{}
	principalID := uuid.New()
	svc.On("ListByPrincipal", mock.Anything, principalID).Return([]*model.AccessPolicy{
		{ID: uuid.New(), PrincipalID: principalID, Effect: model.PolicyEffectAllow},
	}, nil)

	c := newPolicyCtx(svc)
	c.Params = &ApiParams{PrincipalID: principalID.String(), PerPage: 60}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/access-policies/principal/"+principalID.String(), nil)

	listAccessPoliciesByPrincipal(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusOK, w.Code)
	svc.AssertExpectations(t)
}

func TestListAccessPoliciesByPrincipal_NilResult_Returns200Empty(t *testing.T) {
	svc := &mockAccessPolicyService{}
	principalID := uuid.New()
	svc.On("ListByPrincipal", mock.Anything, principalID).Return([]*model.AccessPolicy(nil), nil)

	c := newPolicyCtx(svc)
	c.Params = &ApiParams{PrincipalID: principalID.String(), PerPage: 60}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/access-policies/principal/"+principalID.String(), nil)

	listAccessPoliciesByPrincipal(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusOK, w.Code)
	svc.AssertExpectations(t)
}

// ============================================================
// Admin gate — a non-admin must be refused on every mutating (and
// enumerating) endpoint. Regression for the finding that any authenticated
// principal, including an OAuth2 service account, could delete or flip its
// own deny policy or create a deny policy against an admin.
// ============================================================

func TestCreateAccessPolicy_NonAdmin_Returns403(t *testing.T) {
	c := newNonAdminPolicyCtx(nil)
	w := httptest.NewRecorder()
	body, _ := json.Marshal(map[string]string{
		"principal_id":   uuid.New().String(),
		"principal_type": "user",
		"resource_type":  "secrets",
		"operation":      "get",
		"effect":         "allow",
	})
	r := httptest.NewRequest(http.MethodPost, "/access-policies", bytes.NewReader(body))

	createAccessPolicy(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusForbidden, w.Code)
}

func TestUpdateAccessPolicy_NonAdmin_Returns403(t *testing.T) {
	policyID := uuid.New()
	c := newNonAdminPolicyCtx(nil)
	c.Params = &ApiParams{PolicyID: policyID.String(), PerPage: 60}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPut, "/access-policies/"+policyID.String(), bytes.NewReader([]byte(`{"effect":"deny"}`)))

	updateAccessPolicy(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusForbidden, w.Code)
}

func TestDeleteAccessPolicy_NonAdmin_Returns403(t *testing.T) {
	policyID := uuid.New()
	c := newNonAdminPolicyCtx(nil)
	c.Params = &ApiParams{PolicyID: policyID.String(), PerPage: 60}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodDelete, "/access-policies/"+policyID.String(), nil)

	deleteAccessPolicy(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusForbidden, w.Code)
}

func TestListAccessPolicies_NonAdmin_Returns403(t *testing.T) {
	c := newNonAdminPolicyCtx(nil)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/access-policies", nil)

	listAccessPolicies(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusForbidden, w.Code)
}

func TestGetAccessPolicy_NonAdmin_Returns403(t *testing.T) {
	policyID := uuid.New()
	c := newNonAdminPolicyCtx(nil)
	c.Params = &ApiParams{PolicyID: policyID.String(), PerPage: 60}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/access-policies/"+policyID.String(), nil)

	getAccessPolicy(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusForbidden, w.Code)
}

func TestListAccessPoliciesByPrincipal_NonAdmin_Returns403(t *testing.T) {
	principalID := uuid.New()
	c := newNonAdminPolicyCtx(nil)
	c.Params = &ApiParams{PrincipalID: principalID.String(), PerPage: 60}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/access-policies/principal/"+principalID.String(), nil)

	listAccessPoliciesByPrincipal(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusForbidden, w.Code)
}

// ============================================================
// Enum validation — resource_type, operation, effect, and principal_type
// must be rejected with 400 when they hold a value outside the known enum,
// not merely when empty.
// ============================================================

func TestCreateAccessPolicy_InvalidPrincipalType_Returns400(t *testing.T) {
	c := newPolicyCtx(nil)
	w := httptest.NewRecorder()
	body, _ := json.Marshal(map[string]string{
		"principal_id":   uuid.New().String(),
		"principal_type": "garbage",
		"resource_type":  "secrets",
		"operation":      "get",
		"effect":         "allow",
	})
	r := httptest.NewRequest(http.MethodPost, "/access-policies", bytes.NewReader(body))

	createAccessPolicy(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestCreateAccessPolicy_InvalidResourceType_Returns400(t *testing.T) {
	c := newPolicyCtx(nil)
	w := httptest.NewRecorder()
	body, _ := json.Marshal(map[string]string{
		"principal_id":   uuid.New().String(),
		"principal_type": "user",
		"resource_type":  "garbage",
		"operation":      "get",
		"effect":         "allow",
	})
	r := httptest.NewRequest(http.MethodPost, "/access-policies", bytes.NewReader(body))

	createAccessPolicy(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestCreateAccessPolicy_InvalidOperation_Returns400(t *testing.T) {
	c := newPolicyCtx(nil)
	w := httptest.NewRecorder()
	body, _ := json.Marshal(map[string]string{
		"principal_id":   uuid.New().String(),
		"principal_type": "user",
		"resource_type":  "secrets",
		"operation":      "garbage",
		"effect":         "allow",
	})
	r := httptest.NewRequest(http.MethodPost, "/access-policies", bytes.NewReader(body))

	createAccessPolicy(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestCreateAccessPolicy_InvalidEffect_Returns400(t *testing.T) {
	c := newPolicyCtx(nil)
	w := httptest.NewRecorder()
	body, _ := json.Marshal(map[string]string{
		"principal_id":   uuid.New().String(),
		"principal_type": "user",
		"resource_type":  "secrets",
		"operation":      "get",
		"effect":         "garbage",
	})
	r := httptest.NewRequest(http.MethodPost, "/access-policies", bytes.NewReader(body))

	createAccessPolicy(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestUpdateAccessPolicy_InvalidEffect_Returns400(t *testing.T) {
	policyID := uuid.New()
	c := newPolicyCtx(nil)
	c.Params = &ApiParams{PolicyID: policyID.String(), PerPage: 60}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPut, "/access-policies/"+policyID.String(), bytes.NewReader([]byte(`{"effect":"garbage"}`)))

	updateAccessPolicy(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusBadRequest, w.Code)
}
