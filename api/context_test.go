package api_test

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"rocketvault/api"
	"rocketvault/app"
	"rocketvault/common"
	rvconfig "rocketvault/config"
	"rocketvault/internal/backup"
	"rocketvault/internal/cache"
	"rocketvault/internal/certcache"
	"rocketvault/internal/crypto"
	"rocketvault/internal/keycache"
	"rocketvault/internal/logging"
	"rocketvault/internal/metrics"
	"rocketvault/internal/repositories"
	"rocketvault/internal/retry"
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
	"rocketvault/internal/vaultcache"
)

// testLogger returns a minimal logger for use in tests.
func testLogger() *logging.Logger {
	l := logrus.New()
	l.SetLevel(logrus.DebugLevel)
	return &logging.Logger{Logger: l}
}

// --- mockRBACService ---

// mockRBACService is a minimal mock of authzServices.RBACService.
type mockRBACService struct {
	mock.Mock
}

func (m *mockRBACService) HasPermission(role string, permission authzServices.Permission) bool {
	args := m.Called(role, permission)
	return args.Bool(0)
}

func (m *mockRBACService) GetRolePermissions(role string) []authzServices.Permission {
	args := m.Called(role)
	return args.Get(0).([]authzServices.Permission)
}

func (m *mockRBACService) ValidateEndpointAccess(roles []string, method, path string) error {
	args := m.Called(roles, method, path)
	return args.Error(0)
}

// --- mockServiceContainer ---

// mockServiceContainer satisfies container.ServiceContainerInterface for tests.
// Only GetRBACService is expected to be called during SessionRequired.
// All other methods panic to surface accidental calls.
type mockServiceContainer struct {
	rbac authzServices.RBACService
}

func (m *mockServiceContainer) GetRBACService() authzServices.RBACService { return m.rbac }

// The remaining methods satisfy the interface but are not exercised by SessionRequired.
func (m *mockServiceContainer) GetUserRepository() repositories.UserRepositoryInterface {
	panic("unexpected call: GetUserRepository")
}
func (m *mockServiceContainer) GetSecretRepository() repositories.SecretRepositoryInterface {
	panic("unexpected call: GetSecretRepository")
}
func (m *mockServiceContainer) GetRotationRepository() repositories.RotationPolicyRepositoryInterface {
	panic("unexpected call: GetRotationRepository")
}
func (m *mockServiceContainer) GetVersionRepository() repositories.SecretVersionRepositoryInterface {
	panic("unexpected call: GetVersionRepository")
}
func (m *mockServiceContainer) GetKeyRepository() repositories.KeyRepositoryInterface {
	panic("unexpected call: GetKeyRepository")
}
func (m *mockServiceContainer) GetCertificateRepository() repositories.CertificateRepositoryInterface {
	panic("unexpected call: GetCertificateRepository")
}
func (m *mockServiceContainer) GetCertificatePolicyRepository() repositories.CertificatePolicyRepositoryInterface {
	panic("unexpected call: GetCertificatePolicyRepository")
}
func (m *mockServiceContainer) GetKeyRotationPolicyRepository() repositories.KeyRotationPolicyRepositoryInterface {
	panic("unexpected call: GetKeyRotationPolicyRepository")
}
func (m *mockServiceContainer) GetSessionRepository() repositories.SessionRepositoryInterface {
	panic("unexpected call: GetSessionRepository")
}
func (m *mockServiceContainer) GetVaultRepository() repositories.VaultRepositoryInterface {
	panic("unexpected call: GetVaultRepository")
}
func (m *mockServiceContainer) GetVaultService() vaultServices.VaultService {
	panic("unexpected call: GetVaultService")
}
func (m *mockServiceContainer) GetVaultWebhookService() vaultServices.VaultWebhookService {
	panic("unexpected call: GetVaultWebhookService")
}
func (m *mockServiceContainer) GetPasswordService() authServices.PasswordService {
	panic("unexpected call: GetPasswordService")
}
func (m *mockServiceContainer) GetTOTPService() authServices.TOTPService {
	panic("unexpected call: GetTOTPService")
}
func (m *mockServiceContainer) GetJWTService() authServices.JWTService {
	panic("unexpected call: GetJWTService")
}
func (m *mockServiceContainer) GetAuthenticationService() authServices.AuthenticationService {
	panic("unexpected call: GetAuthenticationService")
}
func (m *mockServiceContainer) GetOIDCService() authServices.OIDCService {
	panic("unexpected call: GetOIDCService")
}
func (m *mockServiceContainer) GetAccessPolicyRepository() repositories.AccessPolicyRepositoryInterface {
	panic("unexpected call: GetAccessPolicyRepository")
}
func (m *mockServiceContainer) GetAccessPolicyService() authzServices.AccessPolicyService {
	panic("unexpected call: GetAccessPolicyService")
}
func (m *mockServiceContainer) GetRoleAssignmentService() authzServices.RoleAssignmentService {
	return nil
}
func (m *mockServiceContainer) GetGrantService() provisioning.GrantService {
	return nil
}
func (m *mockServiceContainer) GetOAuth2ClientRepository() repositories.OAuth2ClientRepositoryInterface {
	panic("unexpected call: GetOAuth2ClientRepository")
}
func (m *mockServiceContainer) GetOAuth2Service() oauth2Services.OAuth2Service {
	panic("unexpected call: GetOAuth2Service")
}
func (m *mockServiceContainer) GetUserService() userServices.UserService {
	panic("unexpected call: GetUserService")
}
func (m *mockServiceContainer) GetSecretService() secretServices.SecretService {
	panic("unexpected call: GetSecretService")
}
func (m *mockServiceContainer) GetKeyService() keyServices.KeyService {
	panic("unexpected call: GetKeyService")
}
func (m *mockServiceContainer) GetCertificateService() certServices.CertificateService {
	panic("unexpected call: GetCertificateService")
}
func (m *mockServiceContainer) GetCertificateRenewalService() certServices.CertificateRenewalService {
	panic("unexpected call: GetCertificateRenewalService")
}
func (m *mockServiceContainer) GetCryptoService() keyServices.CryptoService {
	panic("unexpected call: GetCryptoService")
}
func (m *mockServiceContainer) GetCryptographyService() secretServices.CryptographyService {
	panic("unexpected call: GetCryptographyService")
}
func (m *mockServiceContainer) GetVersioningService() secretServices.VersioningServiceInterface {
	panic("unexpected call: GetVersioningService")
}
func (m *mockServiceContainer) GetTagService() secretServices.TagService {
	panic("unexpected call: GetTagService")
}
func (m *mockServiceContainer) GetRotationService() secretServices.RotationServiceInterface {
	panic("unexpected call: GetRotationService")
}
func (m *mockServiceContainer) GetSchedulerService() secretServices.SchedulerServiceInterface {
	panic("unexpected call: GetSchedulerService")
}
func (m *mockServiceContainer) GetDatabase() *sql.DB {
	panic("unexpected call: GetDatabase")
}
func (m *mockServiceContainer) GetLogger() *logging.Logger {
	panic("unexpected call: GetLogger")
}
func (m *mockServiceContainer) GetSecretCache() *cache.SecretCache {
	panic("unexpected call: GetSecretCache")
}
func (m *mockServiceContainer) GetCacheConfig() rvconfig.CacheConfig {
	panic("unexpected call: GetCacheConfig")
}

func (m *mockServiceContainer) GetVaultCache() *vaultcache.Cache {
	panic("unexpected call: GetVaultCache")
}
func (m *mockServiceContainer) GetCertificateCache() *certcache.Cache {
	panic("unexpected call: GetCertificateCache")
}
func (m *mockServiceContainer) GetCachedSecretService() secretServices.SecretService {
	panic("unexpected call: GetCachedSecretService")
}
func (m *mockServiceContainer) GetRetryService() retryServices.RetryService {
	panic("unexpected call: GetRetryService")
}
func (m *mockServiceContainer) GetKeyProvider() crypto.KeyProvider {
	return nil
}
func (m *mockServiceContainer) GetSigningProvider() signing.SigningKeyProvider {
	return nil
}
func (m *mockServiceContainer) GetItemBackupService() *backup.ItemBackupService {
	return nil
}
func (m *mockServiceContainer) GetKeyCache() keycache.Cache {
	return nil
}
func (m *mockServiceContainer) GetCryptoMetrics() metrics.CryptoMetrics {
	return nil
}
func (m *mockServiceContainer) GetAuditService() auditServices.AuditServiceInterface {
	return nil
}
func (m *mockServiceContainer) GetComplianceReportService() auditServices.ComplianceReportServiceInterface {
	return nil
}
func (m *mockServiceContainer) Close() error {
	panic("unexpected call: Close")
}

// --- Tests ---

// TestSessionRequired_ReadsFromContext verifies that SessionRequired accepts
// a request that carries identity in r.Context() and does NOT require an
// Authorization header — i.e. it trusts AuthenticationMiddleware's output.
func TestSessionRequired_ReadsFromContext(t *testing.T) {
	rbac := &mockRBACService{}
	rbac.On("ValidateEndpointAccess", []string{"admin"}, http.MethodGet, "/api/secrets").Return(nil)

	testApp := &app.App{}
	testApp.ServiceContainer = &mockServiceContainer{rbac: rbac}
	testApp.Logger = testLogger()

	handlerCalled := false
	handler := api.SessionRequired(testApp, func(c *api.Context, w http.ResponseWriter, r *http.Request) {
		handlerCalled = true
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/api/secrets", nil)
	// Populate context as AuthenticationMiddleware would — no Authorization header.
	ctx := context.WithValue(req.Context(), common.UserIDKey, "a1b2c3d4-e5f6-7890-abcd-ef1234567890")
	ctx = context.WithValue(ctx, common.UsernameKey, "alice")
	ctx = context.WithValue(ctx, common.RoleKey, []string{"admin"})
	req = req.WithContext(ctx)

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	assert.True(t, handlerCalled, "inner handler must be invoked")
	assert.Equal(t, http.StatusOK, rr.Code)
	rbac.AssertExpectations(t)
}

// TestSessionRequired_MissingUserID_Returns401 verifies that requests missing
// the user ID in context are rejected with 401, even if an Authorization
// header is present.
func TestSessionRequired_MissingUserID_Returns401(t *testing.T) {
	testApp := &app.App{}
	// ServiceContainer is nil; the missing user ID should short-circuit before RBAC.

	handler := api.SessionRequired(testApp, func(c *api.Context, w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/api/secrets", nil)
	// Deliberately include an Authorization header to show it is ignored.
	req.Header.Set("Authorization", "Bearer some.jwt.token")
	// No identity values in context.

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusUnauthorized, rr.Code)
}

// TestSessionRequired_RBACDenied_Returns403 verifies that when RBAC rejects the
// role for the requested endpoint, SessionRequired returns 403.
func TestSessionRequired_RBACDenied_Returns403(t *testing.T) {
	rbac := &mockRBACService{}
	rbac.On("ValidateEndpointAccess", []string{"viewer"}, http.MethodDelete, "/api/secrets/123").
		Return(errors.New("insufficient permissions"))

	testApp := &app.App{}
	testApp.ServiceContainer = &mockServiceContainer{rbac: rbac}
	testApp.Logger = testLogger()

	handlerCalled := false
	handler := api.SessionRequired(testApp, func(c *api.Context, w http.ResponseWriter, r *http.Request) {
		handlerCalled = true
	})

	req := httptest.NewRequest(http.MethodDelete, "/api/secrets/123", nil)
	ctx := context.WithValue(req.Context(), common.UserIDKey, "a1b2c3d4-e5f6-7890-abcd-ef1234567890")
	ctx = context.WithValue(ctx, common.UsernameKey, "bob")
	ctx = context.WithValue(ctx, common.RoleKey, []string{"viewer"})
	req = req.WithContext(ctx)

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	assert.False(t, handlerCalled, "inner handler must NOT be invoked on RBAC denial")
	assert.Equal(t, http.StatusForbidden, rr.Code)
	rbac.AssertExpectations(t)
}

// TestSetInternalError_CircuitBreakerOpen_Returns503WithoutLeakingChain
// verifies that a retry.ErrCircuitBreakerOpen error (wrapped, as
// retry.WithExponentialBackoff and the CircuitBreaker return it in
// production) maps to 503 with a Retry-After hint, and that the response
// carries a fixed generic message rather than the wrapped error chain —
// which could otherwise reach down to a raw driver error string.
func TestSetInternalError_CircuitBreakerOpen_Returns503WithoutLeakingChain(t *testing.T) {
	wrapped := fmt.Errorf("some operation: %w", retry.ErrCircuitBreakerOpen)

	testApp := &app.App{}
	handler := api.ApiHandler(testApp, func(c *api.Context, w http.ResponseWriter, r *http.Request) {
		c.SetInternalError(wrapped)
	})

	req := httptest.NewRequest(http.MethodGet, "/api/secrets", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusServiceUnavailable, rr.Code)
	assert.Equal(t, "5", rr.Header().Get("Retry-After"))
	assert.NotContains(t, rr.Body.String(), retry.ErrCircuitBreakerOpen.Error(),
		"the wrapped circuit-breaker error text must not reach the response body")
}

// TestSetInternalError_MaxRetriesExceeded_Returns503WithoutLeakingChain covers
// the other retry-exhaustion sentinel WithExponentialBackoff returns, wrapping
// a driver-shaped error the way a real database failure would.
func TestSetInternalError_MaxRetriesExceeded_Returns503WithoutLeakingChain(t *testing.T) {
	driverErr := errors.New("database is locked: file is locked")
	wrapped := fmt.Errorf("%w: %w", retry.ErrMaxRetriesExceeded, driverErr)

	testApp := &app.App{}
	handler := api.ApiHandler(testApp, func(c *api.Context, w http.ResponseWriter, r *http.Request) {
		c.SetInternalError(wrapped)
	})

	req := httptest.NewRequest(http.MethodGet, "/api/secrets", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusServiceUnavailable, rr.Code)
	assert.Equal(t, "5", rr.Header().Get("Retry-After"))
	assert.NotContains(t, rr.Body.String(), driverErr.Error(),
		"the wrapped driver error text must not reach the response body")
}

// TestSetInternalError_OrdinaryError_Returns500WithFixedDetail verifies that an
// unrelated error is still a 500 but its text never reaches the response body.
func TestSetInternalError_OrdinaryError_Returns500WithFixedDetail(t *testing.T) {
	plain := errors.New("pq: relation \"secrets\" does not exist at /var/lib/rv/db")

	testApp := &app.App{}
	handler := api.ApiHandler(testApp, func(c *api.Context, w http.ResponseWriter, r *http.Request) {
		c.SetInternalError(plain)
	})

	req := httptest.NewRequest(http.MethodGet, "/api/secrets", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusInternalServerError, rr.Code)
	assert.Empty(t, rr.Header().Get("Retry-After"))
	assert.NotContains(t, rr.Body.String(), "secrets")
	assert.NotContains(t, rr.Body.String(), "/var/lib/rv/db")

	var body map[string]any
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &body))
	assert.Equal(t, "An internal error occurred. Quote the request_id when contacting support.", body["detailed_error"])
	assert.NotEmpty(t, body["request_id"])
}

// TestSetInternalError_LogsErrorWithRequestID verifies the detail is not lost:
// the real error goes to the server log keyed by the same request id.
func TestSetInternalError_LogsErrorWithRequestID(t *testing.T) {
	var buf bytes.Buffer
	l := logrus.New()
	l.SetOutput(&buf)
	testApp := &app.App{Logger: &logging.Logger{Logger: l}}

	handler := api.ApiHandler(testApp, func(c *api.Context, w http.ResponseWriter, r *http.Request) {
		c.SetInternalError(errors.New("driver exploded"))
	})
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/api/secrets", nil))

	var body map[string]any
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &body))
	assert.Contains(t, buf.String(), "driver exploded")
	assert.Contains(t, buf.String(), body["request_id"].(string))
}
