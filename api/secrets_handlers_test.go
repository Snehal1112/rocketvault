// Package api — internal tests for secret CRUD and version handlers.
package api

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"mime/multipart"
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

// --- mock SecretService ---

type mockSecretService struct {
	mock.Mock
}

func (m *mockSecretService) CreateSecret(ctx context.Context, req secretServices.CreateSecretRequest) (*model.Secret, error) {
	args := m.Called(ctx, req)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*model.Secret), args.Error(1)
}

func (m *mockSecretService) UpdateSecret(ctx context.Context, req secretServices.UpdateSecretRequest) error {
	args := m.Called(ctx, req)
	return args.Error(0)
}

func (m *mockSecretService) GetSecret(ctx context.Context, secretID uuid.UUID, scope model.Scope) (*model.Secret, error) {
	args := m.Called(ctx, secretID, scope)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*model.Secret), args.Error(1)
}

func (m *mockSecretService) ListSecrets(ctx context.Context, scope model.Scope, tags []string, limit, offset int) ([]model.Secret, error) {
	args := m.Called(ctx, scope, tags, limit, offset)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]model.Secret), args.Error(1)
}

func (m *mockSecretService) DeleteSecret(ctx context.Context, secretID uuid.UUID, scope model.Scope) error {
	args := m.Called(ctx, secretID, scope)
	return args.Error(0)
}

func (m *mockSecretService) ListDeletedSecrets(ctx context.Context, scope model.Scope) ([]model.Secret, error) {
	args := m.Called(ctx, scope)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]model.Secret), args.Error(1)
}

func (m *mockSecretService) GenerateSecret(ctx context.Context, req secretServices.GenerateSecretRequest) (*model.Secret, error) {
	args := m.Called(ctx, req)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*model.Secret), args.Error(1)
}

func (m *mockSecretService) ExportSecrets(ctx context.Context, req secretServices.ExportSecretsRequest) ([]byte, error) {
	args := m.Called(ctx, req)
	return args.Get(0).([]byte), args.Error(1)
}

func (m *mockSecretService) ImportSecrets(ctx context.Context, req secretServices.ImportSecretsRequest) (*secretServices.ImportResult, error) {
	args := m.Called(ctx, req)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*secretServices.ImportResult), args.Error(1)
}

func (m *mockSecretService) GetSecretVersions(ctx context.Context, secretID uuid.UUID, scope model.Scope) ([]model.SecretVersion, error) {
	args := m.Called(ctx, secretID, scope)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]model.SecretVersion), args.Error(1)
}

func (m *mockSecretService) GetSecretVersionsMetadata(ctx context.Context, secretID uuid.UUID, scope model.Scope) ([]model.SecretVersionMetadata, error) {
	args := m.Called(ctx, secretID, scope)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]model.SecretVersionMetadata), args.Error(1)
}

func (m *mockSecretService) GetSecretVersion(ctx context.Context, secretID uuid.UUID, version int, scope model.Scope) (*model.SecretVersion, error) {
	args := m.Called(ctx, secretID, version, scope)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*model.SecretVersion), args.Error(1)
}

func (m *mockSecretService) GetLatestSecretVersion(ctx context.Context, secretID uuid.UUID, scope model.Scope) (*model.SecretVersion, error) {
	args := m.Called(ctx, secretID, scope)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*model.SecretVersion), args.Error(1)
}

func (m *mockSecretService) RecoverSecret(ctx context.Context, secretID uuid.UUID, scope model.Scope) error {
	args := m.Called(ctx, secretID, scope)
	return args.Error(0)
}

func (m *mockSecretService) PurgeSecret(ctx context.Context, secretID uuid.UUID, scope model.Scope) error {
	args := m.Called(ctx, secretID, scope)
	return args.Error(0)
}

// --- secretSvcTestContainer ---

type secretSvcTestContainer struct {
	secretSvc secretServices.SecretService
}

func (c *secretSvcTestContainer) GetSecretService() secretServices.SecretService { return c.secretSvc }
func (c *secretSvcTestContainer) GetRBACService() authzServices.RBACService {
	panic("unexpected call: GetRBACService")
}
func (c *secretSvcTestContainer) GetUserRepository() repositories.UserRepositoryInterface {
	panic("unexpected call: GetUserRepository")
}
func (c *secretSvcTestContainer) GetSecretRepository() repositories.SecretRepositoryInterface {
	panic("unexpected call: GetSecretRepository")
}
func (c *secretSvcTestContainer) GetRotationRepository() repositories.RotationPolicyRepositoryInterface {
	panic("unexpected call: GetRotationRepository")
}
func (c *secretSvcTestContainer) GetVersionRepository() repositories.SecretVersionRepositoryInterface {
	panic("unexpected call: GetVersionRepository")
}
func (c *secretSvcTestContainer) GetKeyRepository() repositories.KeyRepositoryInterface {
	panic("unexpected call: GetKeyRepository")
}
func (c *secretSvcTestContainer) GetCertificateRepository() repositories.CertificateRepositoryInterface {
	panic("unexpected call: GetCertificateRepository")
}
func (c *secretSvcTestContainer) GetKeyRotationPolicyRepository() repositories.KeyRotationPolicyRepositoryInterface {
	panic("unexpected call: GetKeyRotationPolicyRepository")
}
func (c *secretSvcTestContainer) GetCertificatePolicyRepository() repositories.CertificatePolicyRepositoryInterface {
	panic("unexpected call: GetCertificatePolicyRepository")
}
func (c *secretSvcTestContainer) GetSessionRepository() repositories.SessionRepositoryInterface {
	panic("unexpected call: GetSessionRepository")
}
func (c *secretSvcTestContainer) GetVaultRepository() repositories.VaultRepositoryInterface {
	panic("unexpected call: GetVaultRepository")
}
func (c *secretSvcTestContainer) GetVaultService() vaultServices.VaultService {
	panic("unexpected call: GetVaultService")
}
func (c *secretSvcTestContainer) GetVaultWebhookService() vaultServices.VaultWebhookService {
	panic("unexpected call: GetVaultWebhookService")
}
func (c *secretSvcTestContainer) GetPasswordService() authServices.PasswordService {
	panic("unexpected call: GetPasswordService")
}
func (c *secretSvcTestContainer) GetTOTPService() authServices.TOTPService {
	panic("unexpected call: GetTOTPService")
}
func (c *secretSvcTestContainer) GetJWTService() authServices.JWTService {
	panic("unexpected call: GetJWTService")
}
func (c *secretSvcTestContainer) GetAuthenticationService() authServices.AuthenticationService {
	panic("unexpected call: GetAuthenticationService")
}
func (c *secretSvcTestContainer) GetOIDCService() authServices.OIDCService {
	panic("unexpected call: GetOIDCService")
}
func (c *secretSvcTestContainer) GetAccessPolicyRepository() repositories.AccessPolicyRepositoryInterface {
	panic("unexpected call: GetAccessPolicyRepository")
}
func (c *secretSvcTestContainer) GetAccessPolicyService() authzServices.AccessPolicyService {
	panic("unexpected call: GetAccessPolicyService")
}
func (c *secretSvcTestContainer) GetRoleAssignmentService() authzServices.RoleAssignmentService {
	return nil
}
func (c *secretSvcTestContainer) GetGrantService() provisioning.GrantService {
	return nil
}
func (c *secretSvcTestContainer) GetOAuth2ClientRepository() repositories.OAuth2ClientRepositoryInterface {
	panic("unexpected call: GetOAuth2ClientRepository")
}
func (c *secretSvcTestContainer) GetOAuth2Service() oauth2Services.OAuth2Service {
	panic("unexpected call: GetOAuth2Service")
}
func (c *secretSvcTestContainer) GetUserService() userServices.UserService {
	panic("unexpected call: GetUserService")
}
func (c *secretSvcTestContainer) GetKeyService() keyServices.KeyService {
	panic("unexpected call: GetKeyService")
}
func (c *secretSvcTestContainer) GetCertificateService() certServices.CertificateService {
	panic("unexpected call: GetCertificateService")
}
func (c *secretSvcTestContainer) GetCertificateRenewalService() certServices.CertificateRenewalService {
	panic("unexpected call: GetCertificateRenewalService")
}
func (c *secretSvcTestContainer) GetCryptoService() keyServices.CryptoService {
	panic("unexpected call: GetCryptoService")
}
func (c *secretSvcTestContainer) GetCryptographyService() secretServices.CryptographyService {
	panic("unexpected call: GetCryptographyService")
}
func (c *secretSvcTestContainer) GetVersioningService() secretServices.VersioningServiceInterface {
	panic("unexpected call: GetVersioningService")
}
func (c *secretSvcTestContainer) GetTagService() secretServices.TagService {
	panic("unexpected call: GetTagService")
}
func (c *secretSvcTestContainer) GetRotationService() secretServices.RotationServiceInterface {
	panic("unexpected call: GetRotationService")
}
func (c *secretSvcTestContainer) GetSchedulerService() secretServices.SchedulerServiceInterface {
	panic("unexpected call: GetSchedulerService")
}
func (c *secretSvcTestContainer) GetDatabase() *sql.DB { panic("unexpected call: GetDatabase") }
func (c *secretSvcTestContainer) GetLogger() *logging.Logger {
	panic("unexpected call: GetLogger")
}
func (c *secretSvcTestContainer) GetSecretCache() *cache.SecretCache {
	panic("unexpected call: GetSecretCache")
}
func (c *secretSvcTestContainer) GetCacheConfig() rvconfig.CacheConfig {
	panic("unexpected call: GetCacheConfig")
}

func (c *secretSvcTestContainer) GetVaultCache() *vaultcache.Cache {
	panic("unexpected call: GetVaultCache")
}
func (c *secretSvcTestContainer) GetCertificateCache() *certcache.Cache {
	panic("unexpected call: GetCertificateCache")
}
func (c *secretSvcTestContainer) GetCachedSecretService() secretServices.SecretService {
	panic("unexpected call: GetCachedSecretService")
}
func (c *secretSvcTestContainer) GetRetryService() retryServices.RetryService {
	panic("unexpected call: GetRetryService")
}
func (c *secretSvcTestContainer) GetKeyProvider() crypto.KeyProvider             { return nil }
func (c *secretSvcTestContainer) GetSigningProvider() signing.SigningKeyProvider { return nil }
func (c *secretSvcTestContainer) GetItemBackupService() *backup.ItemBackupService {
	return nil
}
func (c *secretSvcTestContainer) GetKeyCache() keycache.Cache             { return nil }
func (c *secretSvcTestContainer) GetCryptoMetrics() metrics.CryptoMetrics { return nil }
func (c *secretSvcTestContainer) GetAuditService() auditServices.AuditServiceInterface {
	return nil
}
func (c *secretSvcTestContainer) GetComplianceReportService() auditServices.ComplianceReportServiceInterface {
	return nil
}
func (c *secretSvcTestContainer) Close() error { return nil }

const secretHTestUserID = "a1b2c3d4-e5f6-7890-abcd-ef1234567890"

// newSecretCtx builds a Context backed by the given SecretService mock.
func newSecretCtx(svc secretServices.SecretService) *Context {
	a := &app.App{ServiceContainer: &secretSvcTestContainer{secretSvc: svc}}
	return &Context{
		App:    a,
		Claims: RequestClaims{UserID: secretHTestUserID},
		Params: &ApiParams{PerPage: 60},
		Logger: userTestLog(),
	}
}

// makeSecretModel returns a minimal valid *model.Secret for test use.
func makeSecretModel(secretID uuid.UUID) *model.Secret {
	return &model.Secret{
		ID:        secretID,
		Name:      "test-secret",
		Value:     "secret-value",
		UserID:    uuid.MustParse(secretHTestUserID),
		Version:   1,
		CreatedAt: time.Now(),
		Enabled:   true,
	}
}

// ============================================================
// createSecret
// ============================================================

func TestCreateSecret_MissingName_Returns400(t *testing.T) {
	c := newSecretCtx(nil)
	w := httptest.NewRecorder()
	body, _ := json.Marshal(map[string]any{"value": "val"})
	r := httptest.NewRequest(http.MethodPost, "/secrets", bytes.NewReader(body))

	createSecret(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestCreateSecret_MissingValue_Returns400(t *testing.T) {
	c := newSecretCtx(nil)
	w := httptest.NewRecorder()
	body, _ := json.Marshal(map[string]any{"name": "mysecret"})
	r := httptest.NewRequest(http.MethodPost, "/secrets", bytes.NewReader(body))

	createSecret(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestCreateSecret_ServiceError_Returns500(t *testing.T) {
	svc := &mockSecretService{}
	svc.On("CreateSecret", mock.Anything, mock.Anything).Return(nil, errors.New("db error"))

	c := newSecretCtx(svc)
	w := httptest.NewRecorder()
	body, _ := json.Marshal(map[string]any{"name": "mysecret", "value": "myvalue"})
	r := httptest.NewRequest(http.MethodPost, "/secrets", bytes.NewReader(body))

	createSecret(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusInternalServerError, w.Code)
	svc.AssertExpectations(t)
}

func TestCreateSecret_Success_Returns201(t *testing.T) {
	secretID := uuid.New()
	svc := &mockSecretService{}
	svc.On("CreateSecret", mock.Anything, mock.Anything).Return(makeSecretModel(secretID), nil)

	c := newSecretCtx(svc)
	w := httptest.NewRecorder()
	body, _ := json.Marshal(map[string]any{"name": "mysecret", "value": "myvalue"})
	r := httptest.NewRequest(http.MethodPost, "/secrets", bytes.NewReader(body))

	createSecret(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusCreated, w.Code)
	svc.AssertExpectations(t)
}

// ============================================================
// listSecrets
// ============================================================

// TestListSecrets_Pagination_ComputesLimitAndOffsetFromPageParams pins the
// Page*PerPage offset math: a swapped limit/offset or a dropped multiply
// would still pass every other listSecrets test, since they all use the
// zero-value Page (offset 0).
func TestListSecrets_Pagination_ComputesLimitAndOffsetFromPageParams(t *testing.T) {
	svc := &mockSecretService{}
	svc.On("ListSecrets", mock.Anything, mock.Anything, mock.Anything, 10, 20).
		Return([]model.Secret{}, nil)

	c := newSecretCtx(svc)
	c.Params.Page = 2
	c.Params.PerPage = 10
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/secrets?page=2&per_page=10", nil)

	listSecrets(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusOK, w.Code)
	svc.AssertExpectations(t)
}

func TestListSecrets_ServiceError_Returns500(t *testing.T) {
	svc := &mockSecretService{}
	// Legacy flat route (no vault_name) yields a default-vault scope via ListSecrets.
	svc.On("ListSecrets", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return([]model.Secret{}, errors.New("db error"))

	c := newSecretCtx(svc)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/secrets", nil)

	listSecrets(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusInternalServerError, w.Code)
	svc.AssertExpectations(t)
}

func TestListSecrets_Success_Returns200(t *testing.T) {
	secretID := uuid.New()
	svc := &mockSecretService{}
	// Legacy flat route (no vault_name) yields a default-vault scope via ListSecrets.
	svc.On("ListSecrets", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return([]model.Secret{*makeSecretModel(secretID)}, nil)

	c := newSecretCtx(svc)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/secrets", nil)

	listSecrets(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusOK, w.Code)
	svc.AssertExpectations(t)
}

// ============================================================
// getSecret
// ============================================================

func TestGetSecret_InvalidSecretID_Returns400(t *testing.T) {
	c := newSecretCtx(nil)
	c.Params = &ApiParams{SecretID: "bad", PerPage: 60}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/secrets/bad", nil)

	getSecret(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestGetSecret_NotFound_Returns404(t *testing.T) {
	secretID := uuid.New()
	svc := &mockSecretService{}
	// Legacy flat route (no vault_name) yields a default-vault scope via GetSecret.
	// The service returns the not-found sentinel, which maps to 404.
	svc.On("GetSecret", mock.Anything, secretID, mock.Anything).Return(nil, secretServices.ErrSecretNotFound)

	c := newSecretCtx(svc)
	c.Params = &ApiParams{SecretID: secretID.String(), PerPage: 60}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/secrets/"+secretID.String(), nil)

	getSecret(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusNotFound, w.Code)
	svc.AssertExpectations(t)
}

func TestGetSecret_Success_Returns200(t *testing.T) {
	secretID := uuid.New()
	svc := &mockSecretService{}
	// Legacy flat route (no vault_name) yields a default-vault scope via GetSecret.
	svc.On("GetSecret", mock.Anything, secretID, mock.Anything).Return(makeSecretModel(secretID), nil)

	c := newSecretCtx(svc)
	c.Params = &ApiParams{SecretID: secretID.String(), PerPage: 60}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/secrets/"+secretID.String(), nil)

	getSecret(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusOK, w.Code)
	svc.AssertExpectations(t)
}

// ============================================================
// updateSecret
// ============================================================

func TestUpdateSecret_InvalidSecretID_Returns400(t *testing.T) {
	c := newSecretCtx(nil)
	c.Params = &ApiParams{SecretID: "bad", PerPage: 60}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPut, "/secrets/bad", bytes.NewReader([]byte(`{"name":"new"}`)))

	updateSecret(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestUpdateSecret_NoChanges_Returns400(t *testing.T) {
	secretID := uuid.New()
	svc := &mockSecretService{}
	// No mock expectations: an empty body is rejected before any service call.

	c := newSecretCtx(svc)
	c.Params = &ApiParams{SecretID: secretID.String(), PerPage: 60}
	w := httptest.NewRecorder()
	body, _ := json.Marshal(map[string]any{})
	r := httptest.NewRequest(http.MethodPut, "/secrets/"+secretID.String(), bytes.NewReader(body))

	updateSecret(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusBadRequest, w.Code)
	svc.AssertExpectations(t)
}

func TestUpdateSecret_ServiceError_Returns500(t *testing.T) {
	secretID := uuid.New()
	svc := &mockSecretService{}
	svc.On("UpdateSecret", mock.Anything, mock.Anything).Return(errors.New("db error"))

	c := newSecretCtx(svc)
	c.Params = &ApiParams{SecretID: secretID.String(), PerPage: 60}
	w := httptest.NewRecorder()
	body, _ := json.Marshal(map[string]any{"name": "new-name"})
	r := httptest.NewRequest(http.MethodPut, "/secrets/"+secretID.String(), bytes.NewReader(body))

	updateSecret(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusInternalServerError, w.Code)
	svc.AssertExpectations(t)
}

func TestUpdateSecret_NotFound_Returns404(t *testing.T) {
	secretID := uuid.New()
	svc := &mockSecretService{}
	svc.On("UpdateSecret", mock.Anything, mock.Anything).
		Return(secretServices.ErrSecretNotFound)

	c := newSecretCtx(svc)
	c.Params = &ApiParams{SecretID: secretID.String(), PerPage: 60}
	w := httptest.NewRecorder()
	body, _ := json.Marshal(map[string]any{"name": "new-name"})
	r := httptest.NewRequest(http.MethodPut, "/secrets/"+secretID.String(), bytes.NewReader(body))

	updateSecret(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusNotFound, w.Code)
	svc.AssertExpectations(t)
}

// The real service never returns this error from UpdateSecret; this only pins the error-to-403 mapping.
func TestUpdateSecret_LifecycleDeniedErrorMapping_Returns403(t *testing.T) {
	secretID := uuid.New()
	svc := &mockSecretService{}
	svc.On("UpdateSecret", mock.Anything, mock.Anything).
		Return(secretServices.ErrSecretLifecycleDenied)

	c := newSecretCtx(svc)
	c.Params = &ApiParams{SecretID: secretID.String(), PerPage: 60}
	w := httptest.NewRecorder()
	body, _ := json.Marshal(map[string]any{"name": "new-name"})
	r := httptest.NewRequest(http.MethodPut, "/secrets/"+secretID.String(), bytes.NewReader(body))

	updateSecret(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusForbidden, w.Code)
	svc.AssertExpectations(t)
}

func TestUpdateSecret_GetSecretError_Returns500(t *testing.T) {
	secretID := uuid.New()
	svc := &mockSecretService{}
	svc.On("UpdateSecret", mock.Anything, mock.Anything).Return(nil)
	svc.On("GetSecret", mock.Anything, secretID, mock.Anything).
		Return(nil, errors.New("disk I/O"))

	c := newSecretCtx(svc)
	c.Params = &ApiParams{SecretID: secretID.String(), PerPage: 60}
	w := httptest.NewRecorder()
	body, _ := json.Marshal(map[string]any{"name": "new-name"})
	r := httptest.NewRequest(http.MethodPut, "/secrets/"+secretID.String(), bytes.NewReader(body))

	updateSecret(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusInternalServerError, w.Code)
	svc.AssertExpectations(t)
}

func TestUpdateSecret_Success_Returns200(t *testing.T) {
	secretID := uuid.New()
	svc := &mockSecretService{}
	original := makeSecretModel(secretID)
	svc.On("GetSecret", mock.Anything, secretID, mock.Anything).Return(original, nil)
	svc.On("UpdateSecret", mock.Anything, mock.Anything).Return(nil)

	c := newSecretCtx(svc)
	c.Params = &ApiParams{SecretID: secretID.String(), PerPage: 60}
	w := httptest.NewRecorder()
	body, _ := json.Marshal(map[string]any{"name": "new-name"})
	r := httptest.NewRequest(http.MethodPut, "/secrets/"+secretID.String(), bytes.NewReader(body))

	updateSecret(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusOK, w.Code)
	svc.AssertExpectations(t)
}

// ============================================================
// deleteSecret
// ============================================================

func TestDeleteSecret_InvalidSecretID_Returns400(t *testing.T) {
	c := newSecretCtx(nil)
	c.Params = &ApiParams{SecretID: "bad", PerPage: 60}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodDelete, "/secrets/bad", nil)

	deleteSecret(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestDeleteSecret_ServiceError_Returns500(t *testing.T) {
	secretID := uuid.New()
	svc := &mockSecretService{}
	svc.On("DeleteSecret", mock.Anything, secretID, mock.Anything).Return(errors.New("db error"))

	c := newSecretCtx(svc)
	c.Params = &ApiParams{SecretID: secretID.String(), PerPage: 60}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodDelete, "/secrets/"+secretID.String(), nil)

	deleteSecret(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusInternalServerError, w.Code)
	svc.AssertExpectations(t)
}

func TestDeleteSecret_Success_Returns200(t *testing.T) {
	secretID := uuid.New()
	svc := &mockSecretService{}
	svc.On("DeleteSecret", mock.Anything, secretID, mock.Anything).Return(nil)

	c := newSecretCtx(svc)
	c.Params = &ApiParams{SecretID: secretID.String(), PerPage: 60}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodDelete, "/secrets/"+secretID.String(), nil)

	deleteSecret(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusOK, w.Code)
	svc.AssertExpectations(t)
}

// TestDeleteSecret_MissingUserIDClaim_Returns400 verifies the missing user_id
// claim path. deleteSecret builds its scope via userIDFromClaims, which fails
// closed with SetInvalidParam (400) rather than the ad hoc SetInternalError
// (500) the handler used before the scope refactor.
func TestDeleteSecret_MissingUserIDClaim_Returns400(t *testing.T) {
	secretID := uuid.New()
	// A valid service container, so the assertion below exercises the
	// missing-claim path itself rather than the unrelated nil-container guard.
	c := newSecretCtx(&mockSecretService{})
	c.Claims = RequestClaims{}
	c.Params = &ApiParams{SecretID: secretID.String(), PerPage: 60}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodDelete, "/secrets/"+secretID.String(), nil)

	deleteSecret(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestListSecrets_MissingUserIDClaim_Returns400 verifies the missing user_id
// claim path. listSecrets builds its scope via scopeFromRequest, which fails
// closed with SetInvalidParam (400) rather than the ad hoc SetInternalError
// (500) the handler used before the scope refactor.
func TestListSecrets_MissingUserIDClaim_Returns400(t *testing.T) {
	// A valid service container, so the assertion below exercises the
	// missing-claim path itself rather than the unrelated nil-container guard.
	c := newSecretCtx(&mockSecretService{})
	c.Claims = RequestClaims{}
	c.Params = &ApiParams{PerPage: 60}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/secrets", nil)

	listSecrets(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ============================================================
// generateSecret
// ============================================================

func TestGenerateSecret_MissingName_Returns400(t *testing.T) {
	c := newSecretCtx(nil)
	w := httptest.NewRecorder()
	body, _ := json.Marshal(map[string]any{"length": 16})
	r := httptest.NewRequest(http.MethodPost, "/secrets/generate", bytes.NewReader(body))

	generateSecret(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestGenerateSecret_InvalidLength_Returns400(t *testing.T) {
	c := newSecretCtx(nil)
	w := httptest.NewRecorder()
	body, _ := json.Marshal(map[string]any{"name": "gen", "length": 4})
	r := httptest.NewRequest(http.MethodPost, "/secrets/generate", bytes.NewReader(body))

	generateSecret(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestGenerateSecret_ServiceError_Returns500(t *testing.T) {
	svc := &mockSecretService{}
	svc.On("GenerateSecret", mock.Anything, mock.Anything).Return(nil, errors.New("generation failed"))

	c := newSecretCtx(svc)
	w := httptest.NewRecorder()
	body, _ := json.Marshal(map[string]any{"name": "gen", "length": 16})
	r := httptest.NewRequest(http.MethodPost, "/secrets/generate", bytes.NewReader(body))

	generateSecret(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusInternalServerError, w.Code)
	svc.AssertExpectations(t)
}

func TestGenerateSecret_Success_Returns201(t *testing.T) {
	secretID := uuid.New()
	svc := &mockSecretService{}
	svc.On("GenerateSecret", mock.Anything, mock.Anything).Return(makeSecretModel(secretID), nil)

	c := newSecretCtx(svc)
	w := httptest.NewRecorder()
	body, _ := json.Marshal(map[string]any{"name": "gen", "length": 16})
	r := httptest.NewRequest(http.MethodPost, "/secrets/generate", bytes.NewReader(body))

	generateSecret(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusCreated, w.Code)
	svc.AssertExpectations(t)
}

// ============================================================
// listSecretVersionsHandler
// ============================================================

func TestListSecretVersionsHandler_InvalidSecretID_Returns400(t *testing.T) {
	c := newSecretCtx(nil)
	c.Params = &ApiParams{SecretID: "bad", PerPage: 60}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/secrets/bad/versions", nil)

	listSecretVersionsHandler(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestListSecretVersionsHandler_ServiceError_Returns500(t *testing.T) {
	secretID := uuid.New()
	svc := &mockSecretService{}
	svc.On("GetSecretVersionsMetadata", mock.Anything, secretID, mock.Anything).Return([]model.SecretVersionMetadata{}, errors.New("db error"))

	c := newSecretCtx(svc)
	c.Params = &ApiParams{SecretID: secretID.String(), PerPage: 60}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/secrets/"+secretID.String()+"/versions", nil)

	listSecretVersionsHandler(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusInternalServerError, w.Code)
	svc.AssertExpectations(t)
}

func TestListSecretVersionsHandler_Success_Returns200(t *testing.T) {
	secretID := uuid.New()
	svc := &mockSecretService{}
	svc.On("GetSecretVersionsMetadata", mock.Anything, secretID, mock.Anything).Return([]model.SecretVersionMetadata{
		{SecretID: secretID, Version: 1},
	}, nil)

	c := newSecretCtx(svc)
	c.Params = &ApiParams{SecretID: secretID.String(), PerPage: 60}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/secrets/"+secretID.String()+"/versions", nil)

	listSecretVersionsHandler(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusOK, w.Code)
	svc.AssertExpectations(t)
}

// ============================================================
// getSecretVersionHandler
// ============================================================

func TestGetSecretVersionHandler_InvalidSecretID_Returns400(t *testing.T) {
	c := newSecretCtx(nil)
	c.Params = &ApiParams{SecretID: "bad", PerPage: 60}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/secrets/bad/versions/1", nil)

	getSecretVersionHandler(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestGetSecretVersionHandler_NotFound_Returns404(t *testing.T) {
	secretID := uuid.New()
	svc := &mockSecretService{}
	// writeSecretError only maps the not-found sentinel to 404; a generic
	// error now maps to 500 (see TestListSecretVersionsWrongVaultReturns404's
	// sibling coverage in secrets_scope_test.go for the unified mapping).
	svc.On("GetSecretVersion", mock.Anything, secretID, 1, mock.Anything).Return(nil, secretServices.ErrSecretNotFound)

	c := newSecretCtx(svc)
	c.Params = &ApiParams{SecretID: secretID.String(), Version: 1, PerPage: 60}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/secrets/"+secretID.String()+"/versions/1", nil)

	getSecretVersionHandler(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusNotFound, w.Code)
	svc.AssertExpectations(t)
}

func TestGetSecretVersionHandler_Success_Returns200(t *testing.T) {
	secretID := uuid.New()
	svc := &mockSecretService{}
	svc.On("GetSecretVersion", mock.Anything, secretID, 1, mock.Anything).Return(&model.SecretVersion{
		SecretID: secretID, Version: 1, Value: "val",
	}, nil)

	c := newSecretCtx(svc)
	c.Params = &ApiParams{SecretID: secretID.String(), Version: 1, PerPage: 60}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/secrets/"+secretID.String()+"/versions/1", nil)

	getSecretVersionHandler(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusOK, w.Code)
	svc.AssertExpectations(t)
}

// ============================================================
// getLatestSecretVersionHandler
// ============================================================

func TestGetLatestSecretVersionHandler_InvalidSecretID_Returns400(t *testing.T) {
	c := newSecretCtx(nil)
	c.Params = &ApiParams{SecretID: "bad", PerPage: 60}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/secrets/bad/versions/latest", nil)

	getLatestSecretVersionHandler(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestGetLatestSecretVersionHandler_NotFound_Returns404(t *testing.T) {
	secretID := uuid.New()
	svc := &mockSecretService{}
	// writeSecretError only maps the not-found sentinel to 404.
	svc.On("GetLatestSecretVersion", mock.Anything, secretID, mock.Anything).Return(nil, secretServices.ErrSecretNotFound)

	c := newSecretCtx(svc)
	c.Params = &ApiParams{SecretID: secretID.String(), PerPage: 60}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/secrets/"+secretID.String()+"/versions/latest", nil)

	getLatestSecretVersionHandler(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusNotFound, w.Code)
	svc.AssertExpectations(t)
}

func TestGetLatestSecretVersionHandler_Success_Returns200(t *testing.T) {
	secretID := uuid.New()
	svc := &mockSecretService{}
	svc.On("GetLatestSecretVersion", mock.Anything, secretID, mock.Anything).Return(&model.SecretVersion{
		SecretID: secretID, Version: 2, Value: "latest",
	}, nil)

	c := newSecretCtx(svc)
	c.Params = &ApiParams{SecretID: secretID.String(), PerPage: 60}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/secrets/"+secretID.String()+"/versions/latest", nil)

	getLatestSecretVersionHandler(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusOK, w.Code)
	svc.AssertExpectations(t)
}

// ============================================================
// exportSecrets
// ============================================================

func TestExportSecrets_InvalidFormat_Returns400(t *testing.T) {
	c := newSecretCtx(nil)
	w := httptest.NewRecorder()
	body, _ := json.Marshal(map[string]any{"format": "xml"})
	r := httptest.NewRequest(http.MethodPost, "/secrets/export", bytes.NewReader(body))

	exportSecrets(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// Requesting encryption without a passphrase is refused with 400. This used
// to be a hard "CLI only" rejection of any encrypt:true (B36's original API
// fix); it is not anymore — the API now has a passphrase channel (the
// request body's "passphrase" field) and ExportSecrets itself refuses to
// seal without one (secrets.ErrExportPassphraseRequired), mapped to 400 by
// writeSecretError. It still never returns plaintext under "encrypt": true.
func TestExportSecrets_EncryptRequested_Returns400(t *testing.T) {
	svc := &mockSecretService{}
	svc.On("ExportSecrets", mock.Anything, mock.Anything).
		Return([]byte(nil), secretServices.ErrExportPassphraseRequired)

	c := newSecretCtx(svc)
	w := httptest.NewRecorder()
	body, _ := json.Marshal(map[string]any{"format": "json", "encrypt": true})
	r := httptest.NewRequest(http.MethodPost, "/secrets/export", bytes.NewReader(body))

	exportSecrets(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusBadRequest, w.Code)
	svc.AssertExpectations(t)
}

func TestExportSecrets_EncryptWithPassphrase_Success_Returns200(t *testing.T) {
	svc := &mockSecretService{}
	svc.On("ExportSecrets", mock.Anything, mock.MatchedBy(func(req secretServices.ExportSecretsRequest) bool {
		return req.Encrypt && req.Passphrase == "correct horse battery staple" && req.Format == "json"
	})).Return([]byte(`{"rocketvault_export":1}`), nil)

	c := newSecretCtx(svc)
	w := httptest.NewRecorder()
	body, _ := json.Marshal(map[string]any{
		"format": "json", "encrypt": true, "passphrase": "correct horse battery staple",
	})
	r := httptest.NewRequest(http.MethodPost, "/secrets/export", bytes.NewReader(body))

	exportSecrets(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusOK, w.Code)
	svc.AssertExpectations(t)
}

func TestExportSecrets_PassphraseWithoutEncryptFlag_StillThreadsThrough(t *testing.T) {
	svc := &mockSecretService{}
	svc.On("ExportSecrets", mock.Anything, mock.MatchedBy(func(req secretServices.ExportSecretsRequest) bool {
		return !req.Encrypt && req.Passphrase == "pw"
	})).Return([]byte(`{"rocketvault_export":1}`), nil)

	c := newSecretCtx(svc)
	w := httptest.NewRecorder()
	body, _ := json.Marshal(map[string]any{"format": "json", "passphrase": "pw"}) // encrypt omitted
	r := httptest.NewRequest(http.MethodPost, "/secrets/export", bytes.NewReader(body))

	exportSecrets(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusOK, w.Code)
	svc.AssertExpectations(t)
}

func TestExportSecrets_ServiceError_Returns500(t *testing.T) {
	svc := &mockSecretService{}
	svc.On("ExportSecrets", mock.Anything, mock.Anything).Return([]byte{}, errors.New("export failed"))

	c := newSecretCtx(svc)
	w := httptest.NewRecorder()
	body, _ := json.Marshal(map[string]any{"format": "json"})
	r := httptest.NewRequest(http.MethodPost, "/secrets/export", bytes.NewReader(body))

	exportSecrets(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusInternalServerError, w.Code)
	svc.AssertExpectations(t)
}

func TestExportSecrets_JSON_Success_Returns200(t *testing.T) {
	svc := &mockSecretService{}
	svc.On("ExportSecrets", mock.Anything, mock.Anything).Return([]byte(`[]`), nil)

	c := newSecretCtx(svc)
	w := httptest.NewRecorder()
	body, _ := json.Marshal(map[string]any{"format": "json"})
	r := httptest.NewRequest(http.MethodPost, "/secrets/export", bytes.NewReader(body))

	exportSecrets(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusOK, w.Code)
	svc.AssertExpectations(t)
}

// ============================================================
// importSecrets — passphrase handling
// ============================================================

// newImportRequest builds a multipart import request, optionally carrying an
// overwrite and a passphrase form field.
func newImportRequest(t *testing.T, fileBytes []byte, format, overwrite, passphrase string) *http.Request {
	t.Helper()
	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)
	fw, err := w.CreateFormFile("file", "export.json")
	require.NoError(t, err)
	_, err = fw.Write(fileBytes)
	require.NoError(t, err)
	require.NoError(t, w.WriteField("format", format))
	if overwrite != "" {
		require.NoError(t, w.WriteField("overwrite", overwrite))
	}
	if passphrase != "" {
		require.NoError(t, w.WriteField("passphrase", passphrase))
	}
	require.NoError(t, w.Close())

	r := httptest.NewRequest(http.MethodPost, "/secrets/import", &buf)
	r.Header.Set("Content-Type", w.FormDataContentType())
	return r
}

func TestImportSecrets_SealedUpload_CorrectPassphrase_Returns200(t *testing.T) {
	plaintext := []byte(`[{"name":"n1","value":"v1"}]`)
	sealed, err := common.SealExport(plaintext, "correct-pass")
	require.NoError(t, err)

	svc := &mockSecretService{}
	svc.On("ImportSecrets", mock.Anything, mock.MatchedBy(func(req secretServices.ImportSecretsRequest) bool {
		return bytes.Equal(req.Data, plaintext) && req.Format == "json"
	})).Return(&secretServices.ImportResult{ImportedCount: 1, TotalCount: 1}, nil)

	c := newSecretCtx(svc)
	w := httptest.NewRecorder()
	r := newImportRequest(t, sealed, "json", "", "correct-pass")

	importSecrets(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusOK, w.Code)
	svc.AssertExpectations(t)
}

func TestImportSecrets_SealedUpload_WrongPassphrase_Returns400(t *testing.T) {
	sealed, err := common.SealExport([]byte(`[{"name":"n1","value":"v1"}]`), "correct-pass")
	require.NoError(t, err)

	svc := &mockSecretService{} // ImportSecrets must never be called

	c := newSecretCtx(svc)
	w := httptest.NewRecorder()
	r := newImportRequest(t, sealed, "json", "", "wrong-pass")

	importSecrets(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusBadRequest, w.Code)
	svc.AssertNotCalled(t, "ImportSecrets", mock.Anything, mock.Anything)
}

func TestImportSecrets_SealedUpload_MissingPassphrase_Returns400(t *testing.T) {
	sealed, err := common.SealExport([]byte(`[{"name":"n1","value":"v1"}]`), "correct-pass")
	require.NoError(t, err)

	svc := &mockSecretService{}

	c := newSecretCtx(svc)
	w := httptest.NewRecorder()
	r := newImportRequest(t, sealed, "json", "", "") // no passphrase field at all

	importSecrets(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusBadRequest, w.Code)
	svc.AssertNotCalled(t, "ImportSecrets", mock.Anything, mock.Anything)
}

func TestImportSecrets_PlaintextUpload_PassphraseFieldIgnored_Returns200(t *testing.T) {
	plaintext := []byte(`[{"name":"n1","value":"v1"}]`)

	svc := &mockSecretService{}
	svc.On("ImportSecrets", mock.Anything, mock.MatchedBy(func(req secretServices.ImportSecretsRequest) bool {
		return bytes.Equal(req.Data, plaintext)
	})).Return(&secretServices.ImportResult{ImportedCount: 1, TotalCount: 1}, nil)

	c := newSecretCtx(svc)
	w := httptest.NewRecorder()
	r := newImportRequest(t, plaintext, "json", "", "some-passphrase-nobody-needed")

	importSecrets(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusOK, w.Code)
	svc.AssertExpectations(t)
}

func TestImportSecrets_PlaintextUpload_NoPassphrase_Returns200(t *testing.T) {
	plaintext := []byte(`[{"name":"n1","value":"v1"}]`)

	svc := &mockSecretService{}
	svc.On("ImportSecrets", mock.Anything, mock.MatchedBy(func(req secretServices.ImportSecretsRequest) bool {
		return bytes.Equal(req.Data, plaintext)
	})).Return(&secretServices.ImportResult{ImportedCount: 1, TotalCount: 1}, nil)

	c := newSecretCtx(svc)
	w := httptest.NewRecorder()
	r := newImportRequest(t, plaintext, "json", "", "")

	importSecrets(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusOK, w.Code)
	svc.AssertExpectations(t)
}

// ============================================================
// Status-code distinction for DELETE (Issue 8) and GET (Issue 9)
// ============================================================

// TestDeleteSecret_NotFound_Returns404 verifies that a not-found sentinel from
// the service maps to 404 rather than 500.
func TestDeleteSecret_NotFound_Returns404(t *testing.T) {
	secretID := uuid.New()
	svc := &mockSecretService{}
	svc.On("DeleteSecret", mock.Anything, secretID, mock.Anything).
		Return(secretServices.ErrSecretNotFound)

	c := newSecretCtx(svc)
	c.Params = &ApiParams{SecretID: secretID.String(), PerPage: 60}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodDelete, "/secrets/"+secretID.String(), nil)

	deleteSecret(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusNotFound, w.Code)
	svc.AssertExpectations(t)
}

// TestGetSecret_LifecycleDenied_Returns403 verifies that a disabled/expired
// secret yields 403 rather than 404.
func TestGetSecret_LifecycleDenied_Returns403(t *testing.T) {
	secretID := uuid.New()
	svc := &mockSecretService{}
	svc.On("GetSecret", mock.Anything, secretID, mock.Anything).
		Return(nil, secretServices.ErrSecretLifecycleDenied)

	c := newSecretCtx(svc)
	c.Params = &ApiParams{SecretID: secretID.String(), PerPage: 60}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/secrets/"+secretID.String(), nil)

	getSecret(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusForbidden, w.Code)
	svc.AssertExpectations(t)
}

// TestGetSecret_DecryptError_Returns500 verifies that a genuine server fault
// (e.g. decrypt failure) yields 500 rather than 404.
func TestGetSecret_DecryptError_Returns500(t *testing.T) {
	secretID := uuid.New()
	svc := &mockSecretService{}
	svc.On("GetSecret", mock.Anything, secretID, mock.Anything).
		Return(nil, errors.New("disk I/O"))

	c := newSecretCtx(svc)
	c.Params = &ApiParams{SecretID: secretID.String(), PerPage: 60}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/secrets/"+secretID.String(), nil)

	getSecret(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusInternalServerError, w.Code)
	svc.AssertExpectations(t)
}

// TestGetSecret_NotFoundSentinel_Returns404 verifies the not-found sentinel
// still yields 404.
func TestGetSecret_NotFoundSentinel_Returns404(t *testing.T) {
	secretID := uuid.New()
	svc := &mockSecretService{}
	svc.On("GetSecret", mock.Anything, secretID, mock.Anything).
		Return(nil, secretServices.ErrSecretNotFound)

	c := newSecretCtx(svc)
	c.Params = &ApiParams{SecretID: secretID.String(), PerPage: 60}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/secrets/"+secretID.String(), nil)

	getSecret(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusNotFound, w.Code)
	svc.AssertExpectations(t)
}

// TestListSecretVersionsHandler_NeverEmitsValues is the API-side regression
// guard for § B30.
//
// GET /secrets/{id}/versions is authorized by ActionSecretsReadMetadata, which
// Key Vault Reader holds. It used to call GetSecretVersions, which decrypts
// every version, so the least-privileged built-in role could read every
// historical plaintext value of every secret in its vault.
//
// Two assertions, because either alone is weak: the response carries no
// "value" key, AND the value-bearing service method is never reached. The
// second is what makes this a real guard -- with model.SecretVersionMetadata
// having no Value field, the first would pass even if the handler decrypted
// everything and then discarded it.
func TestListSecretVersionsHandler_NeverEmitsValues(t *testing.T) {
	secretID := uuid.New()
	svc := &mockSecretService{}
	svc.On("GetSecretVersionsMetadata", mock.Anything, secretID, mock.Anything).
		Return([]model.SecretVersionMetadata{
			{SecretID: secretID, Name: "db-password", Version: 1},
			{SecretID: secretID, Name: "db-password", Version: 2},
		}, nil)

	c := newSecretCtx(svc)
	c.Params = &ApiParams{SecretID: secretID.String(), PerPage: 60}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/secrets/"+secretID.String()+"/versions", nil)

	listSecretVersionsHandler(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusOK, w.Code)
	assert.NotContains(t, w.Body.String(), `"value"`,
		"the versions list must not carry a value field")
	svc.AssertNotCalled(t, "GetSecretVersions", mock.Anything, mock.Anything, mock.Anything)
	svc.AssertExpectations(t)
}
