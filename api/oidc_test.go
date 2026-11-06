// Package api — tests for the OIDC login/callback handlers.
package api

import (
	"errors"
	"context"
	"database/sql"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

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

type mockOIDCService struct {
	mock.Mock
}

func (m *mockOIDCService) AuthCodeURL(state, nonce, verifier string) string {
	args := m.Called(state, nonce, verifier)
	return args.String(0)
}

func (m *mockOIDCService) HandleCallback(ctx context.Context, code, expectedNonce, verifier string) (*authServices.OIDCIdentity, error) {
	args := m.Called(ctx, code, expectedNonce, verifier)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*authServices.OIDCIdentity), args.Error(1)
}

type mockUserServiceForOIDC struct {
	mock.Mock
	userServices.UserService
}

func (m *mockUserServiceForOIDC) FindOrCreateExternalUser(ctx context.Context, req userServices.FindOrCreateExternalUserRequest) (*model.User, error) {
	args := m.Called(ctx, req)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*model.User), args.Error(1)
}

type mockAuthServiceForOIDC struct {
	mock.Mock
	authServices.AuthenticationService
}

func (m *mockAuthServiceForOIDC) IssueSessionForUser(ctx context.Context, user *model.User) (*authServices.AuthenticationResult, error) {
	args := m.Called(ctx, user)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*authServices.AuthenticationResult), args.Error(1)
}

// oidcHTestContainer satisfies container.ServiceContainerInterface for
// oidcLoginHandler/oidcCallbackHandler tests. Every method other than
// GetOIDCService/GetUserService/GetAuthenticationService panics.
type oidcHTestContainer struct {
	oidcSvc authServices.OIDCService
	userSvc userServices.UserService
	authSvc authServices.AuthenticationService
}

func (c *oidcHTestContainer) GetOIDCService() authServices.OIDCService { return c.oidcSvc }
func (c *oidcHTestContainer) GetUserService() userServices.UserService { return c.userSvc }
func (c *oidcHTestContainer) GetAuthenticationService() authServices.AuthenticationService {
	return c.authSvc
}
func (c *oidcHTestContainer) GetRBACService() authzServices.RBACService {
	panic("unexpected call: GetRBACService")
}
func (c *oidcHTestContainer) GetUserRepository() repositories.UserRepositoryInterface {
	panic("unexpected call: GetUserRepository")
}
func (c *oidcHTestContainer) GetSecretRepository() repositories.SecretRepositoryInterface {
	panic("unexpected call: GetSecretRepository")
}
func (c *oidcHTestContainer) GetRotationRepository() repositories.RotationPolicyRepositoryInterface {
	panic("unexpected call: GetRotationRepository")
}
func (c *oidcHTestContainer) GetVersionRepository() repositories.SecretVersionRepositoryInterface {
	panic("unexpected call: GetVersionRepository")
}
func (c *oidcHTestContainer) GetKeyRepository() repositories.KeyRepositoryInterface {
	panic("unexpected call: GetKeyRepository")
}
func (c *oidcHTestContainer) GetCertificateRepository() repositories.CertificateRepositoryInterface {
	panic("unexpected call: GetCertificateRepository")
}
func (c *oidcHTestContainer) GetKeyRotationPolicyRepository() repositories.KeyRotationPolicyRepositoryInterface {
	panic("unexpected call: GetKeyRotationPolicyRepository")
}
func (c *oidcHTestContainer) GetCertificatePolicyRepository() repositories.CertificatePolicyRepositoryInterface {
	panic("unexpected call: GetCertificatePolicyRepository")
}
func (c *oidcHTestContainer) GetSessionRepository() repositories.SessionRepositoryInterface {
	panic("unexpected call: GetSessionRepository")
}
func (c *oidcHTestContainer) GetVaultRepository() repositories.VaultRepositoryInterface {
	panic("unexpected call: GetVaultRepository")
}
func (c *oidcHTestContainer) GetVaultService() vaultServices.VaultService {
	panic("unexpected call: GetVaultService")
}
func (c *oidcHTestContainer) GetVaultWebhookService() vaultServices.VaultWebhookService {
	panic("unexpected call: GetVaultWebhookService")
}
func (c *oidcHTestContainer) GetPasswordService() authServices.PasswordService {
	panic("unexpected call: GetPasswordService")
}
func (c *oidcHTestContainer) GetTOTPService() authServices.TOTPService {
	panic("unexpected call: GetTOTPService")
}
func (c *oidcHTestContainer) GetJWTService() authServices.JWTService {
	panic("unexpected call: GetJWTService")
}
func (c *oidcHTestContainer) GetAccessPolicyRepository() repositories.AccessPolicyRepositoryInterface {
	panic("unexpected call: GetAccessPolicyRepository")
}
func (c *oidcHTestContainer) GetAccessPolicyService() authzServices.AccessPolicyService {
	panic("unexpected call: GetAccessPolicyService")
}
func (c *oidcHTestContainer) GetRoleAssignmentService() authzServices.RoleAssignmentService {
	return nil
}
func (c *oidcHTestContainer) GetGrantService() provisioning.GrantService {
	return nil
}
func (c *oidcHTestContainer) GetOAuth2ClientRepository() repositories.OAuth2ClientRepositoryInterface {
	panic("unexpected call: GetOAuth2ClientRepository")
}
func (c *oidcHTestContainer) GetOAuth2Service() oauth2Services.OAuth2Service {
	panic("unexpected call: GetOAuth2Service")
}
func (c *oidcHTestContainer) GetSecretService() secretServices.SecretService {
	panic("unexpected call: GetSecretService")
}
func (c *oidcHTestContainer) GetKeyService() keyServices.KeyService {
	panic("unexpected call: GetKeyService")
}
func (c *oidcHTestContainer) GetCertificateService() certServices.CertificateService {
	panic("unexpected call: GetCertificateService")
}
func (c *oidcHTestContainer) GetCertificateRenewalService() certServices.CertificateRenewalService {
	panic("unexpected call: GetCertificateRenewalService")
}
func (c *oidcHTestContainer) GetCryptoService() keyServices.CryptoService {
	panic("unexpected call: GetCryptoService")
}
func (c *oidcHTestContainer) GetCryptographyService() secretServices.CryptographyService {
	panic("unexpected call: GetCryptographyService")
}
func (c *oidcHTestContainer) GetVersioningService() secretServices.VersioningServiceInterface {
	panic("unexpected call: GetVersioningService")
}
func (c *oidcHTestContainer) GetTagService() secretServices.TagService {
	panic("unexpected call: GetTagService")
}
func (c *oidcHTestContainer) GetRotationService() secretServices.RotationServiceInterface {
	panic("unexpected call: GetRotationService")
}
func (c *oidcHTestContainer) GetSchedulerService() secretServices.SchedulerServiceInterface {
	panic("unexpected call: GetSchedulerService")
}
func (c *oidcHTestContainer) GetDatabase() *sql.DB { panic("unexpected call: GetDatabase") }
func (c *oidcHTestContainer) GetLogger() *logging.Logger {
	panic("unexpected call: GetLogger")
}
func (c *oidcHTestContainer) GetSecretCache() *cache.SecretCache {
	panic("unexpected call: GetSecretCache")
}
func (c *oidcHTestContainer) GetCacheConfig() rvconfig.CacheConfig {
	panic("unexpected call: GetCacheConfig")
}

func (c *oidcHTestContainer) GetVaultCache() *vaultcache.Cache {
	panic("unexpected call: GetVaultCache")
}
func (c *oidcHTestContainer) GetCertificateCache() *certcache.Cache {
	panic("unexpected call: GetCertificateCache")
}
func (c *oidcHTestContainer) GetCachedSecretService() secretServices.SecretService {
	panic("unexpected call: GetCachedSecretService")
}
func (c *oidcHTestContainer) GetRetryService() retryServices.RetryService {
	panic("unexpected call: GetRetryService")
}
func (c *oidcHTestContainer) GetKeyProvider() crypto.KeyProvider             { return nil }
func (c *oidcHTestContainer) GetSigningProvider() signing.SigningKeyProvider { return nil }
func (c *oidcHTestContainer) GetItemBackupService() *backup.ItemBackupService {
	return nil
}
func (c *oidcHTestContainer) GetKeyCache() keycache.Cache             { return nil }
func (c *oidcHTestContainer) GetCryptoMetrics() metrics.CryptoMetrics { return nil }
func (c *oidcHTestContainer) GetAuditService() auditServices.AuditServiceInterface {
	return nil
}
func (c *oidcHTestContainer) GetComplianceReportService() auditServices.ComplianceReportServiceInterface {
	return nil
}
func (c *oidcHTestContainer) Close() error { return nil }

// newOIDCHAPI builds an API instance for oidcLoginHandler/oidcCallbackHandler
// tests.
func newOIDCHAPI(oidcSvc authServices.OIDCService, userSvc userServices.UserService, authSvc authServices.AuthenticationService) *API {
	a := &app.App{ServiceContainer: &oidcHTestContainer{oidcSvc: oidcSvc, userSvc: userSvc, authSvc: authSvc}}
	return &API{App: a, Logger: userTestLog(), cliExchange: newCLIExchangeStore()}
}

func TestOIDCLogin_ServiceUnavailable_Returns503(t *testing.T) {
	api := newOIDCHAPI(nil, nil, nil) // no OIDCService configured
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/oidc/login", nil)

	api.oidcLoginHandler(w, r)

	assert.Equal(t, http.StatusServiceUnavailable, w.Code)
}

func TestOIDCLogin_SetsStateAndNonceCookiesAndRedirects(t *testing.T) {
	oidcSvc := &mockOIDCService{}
	oidcSvc.On("AuthCodeURL", mock.AnythingOfType("string"), mock.AnythingOfType("string"), mock.AnythingOfType("string")).
		Return("https://idp.example.com/authorize?state=x")

	api := newOIDCHAPI(oidcSvc, nil, nil)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/oidc/login", nil)

	api.oidcLoginHandler(w, r)

	assert.Equal(t, http.StatusFound, w.Code)
	assert.Equal(t, "https://idp.example.com/authorize?state=x", w.Header().Get("Location"))
	cookies := w.Result().Cookies()
	var sawState, sawNonce bool
	for _, ck := range cookies {
		if ck.Name == "oidc_state" {
			sawState = true
		}
		if ck.Name == "oidc_nonce" {
			sawNonce = true
		}
	}
	assert.True(t, sawState, "oidc_state cookie must be set")
	assert.True(t, sawNonce, "oidc_nonce cookie must be set")
}

func TestOIDCCallback_MissingStateCookie_Returns400(t *testing.T) {
	oidcSvc := &mockOIDCService{}
	api := newOIDCHAPI(oidcSvc, nil, nil)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/oidc/callback?state=x&code=y", nil)

	api.oidcCallbackHandler(w, r)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestOIDCCallback_StateMismatch_Returns400(t *testing.T) {
	oidcSvc := &mockOIDCService{}
	api := newOIDCHAPI(oidcSvc, nil, nil)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/oidc/callback?state=wrong&code=y", nil)
	r.AddCookie(&http.Cookie{Name: "oidc_state", Value: "expected"})
	r.AddCookie(&http.Cookie{Name: "oidc_nonce", Value: "nonce-1"})
	r.AddCookie(&http.Cookie{Name: "oidc_pkce", Value: "verifier-1"})

	api.oidcCallbackHandler(w, r)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	oidcSvc.AssertNotCalled(t, "HandleCallback", mock.Anything, mock.Anything, mock.Anything, mock.Anything)
}

func TestOIDCCallback_Success_ReturnsLoginResponse(t *testing.T) {
	identity := &authServices.OIDCIdentity{Subject: "sub-1", PreferredUsername: "jdoe", Email: "jdoe@example.com"}
	oidcSvc := &mockOIDCService{}
	oidcSvc.On("HandleCallback", mock.Anything, "auth-code", "nonce-1", "verifier-1").Return(identity, nil)

	userSvc := &mockUserServiceForOIDC{}
	user := &model.User{ID: uuid.New(), Username: "jdoe", Roles: []string{model.RoleUser}}
	userSvc.On("FindOrCreateExternalUser", mock.Anything, mock.Anything).Return(user, nil)

	authSvc := &mockAuthServiceForOIDC{}
	authSvc.On("IssueSessionForUser", mock.Anything, user).Return(&authServices.AuthenticationResult{
		Token: "access-token", RefreshToken: "refresh-token", UserID: user.ID, Username: user.Username, Roles: user.Roles,
	}, nil)

	api := newOIDCHAPI(oidcSvc, userSvc, authSvc)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/oidc/callback?state=expected&code=auth-code", nil)
	r.AddCookie(&http.Cookie{Name: "oidc_state", Value: "expected"})
	r.AddCookie(&http.Cookie{Name: "oidc_nonce", Value: "nonce-1"})
	r.AddCookie(&http.Cookie{Name: "oidc_pkce", Value: "verifier-1"})

	api.oidcCallbackHandler(w, r)

	assert.Equal(t, http.StatusOK, w.Code)
	oidcSvc.AssertExpectations(t)
	userSvc.AssertExpectations(t)
	authSvc.AssertExpectations(t)
}

func TestOIDCLogin_InvalidCLIRedirectURI_Returns400(t *testing.T) {
	oidcSvc := &mockOIDCService{}
	api := newOIDCHAPI(oidcSvc, nil, nil)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/oidc/login?cli_redirect_uri=https://evil.example.com/callback", nil)

	api.oidcLoginHandler(w, r)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	oidcSvc.AssertNotCalled(t, "AuthCodeURL", mock.Anything, mock.Anything, mock.Anything)
}

func TestOIDCLogin_ValidCLIRedirectURI_SetsCookie(t *testing.T) {
	oidcSvc := &mockOIDCService{}
	oidcSvc.On("AuthCodeURL", mock.AnythingOfType("string"), mock.AnythingOfType("string"), mock.AnythingOfType("string")).
		Return("https://idp.example.com/authorize?state=x")
	api := newOIDCHAPI(oidcSvc, nil, nil)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/oidc/login?cli_redirect_uri=http://127.0.0.1:54321/callback", nil)

	api.oidcLoginHandler(w, r)

	assert.Equal(t, http.StatusFound, w.Code)
	var sawCLIRedirect bool
	for _, ck := range w.Result().Cookies() {
		if ck.Name == "oidc_cli_redirect" {
			sawCLIRedirect = true
			assert.Equal(t, "http://127.0.0.1:54321/callback", ck.Value)
		}
	}
	assert.True(t, sawCLIRedirect, "oidc_cli_redirect cookie must be set")
}

func TestOIDCCallback_WithCLIRedirect_RedirectsWithExchangeCode(t *testing.T) {
	identity := &authServices.OIDCIdentity{Subject: "sub-1", PreferredUsername: "jdoe"}
	oidcSvc := &mockOIDCService{}
	oidcSvc.On("HandleCallback", mock.Anything, "auth-code", "nonce-1", "verifier-1").Return(identity, nil)

	userSvc := &mockUserServiceForOIDC{}
	user := &model.User{ID: uuid.New(), Username: "jdoe", Roles: []string{model.RoleUser}}
	userSvc.On("FindOrCreateExternalUser", mock.Anything, mock.Anything).Return(user, nil)

	authSvc := &mockAuthServiceForOIDC{}
	authSvc.On("IssueSessionForUser", mock.Anything, user).Return(&authServices.AuthenticationResult{
		Token: "access-token", RefreshToken: "refresh-token", UserID: user.ID, Username: user.Username, Roles: user.Roles,
	}, nil)

	api := newOIDCHAPI(oidcSvc, userSvc, authSvc)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/oidc/callback?state=expected&code=auth-code", nil)
	r.AddCookie(&http.Cookie{Name: "oidc_state", Value: "expected"})
	r.AddCookie(&http.Cookie{Name: "oidc_nonce", Value: "nonce-1"})
	r.AddCookie(&http.Cookie{Name: "oidc_pkce", Value: "verifier-1"})
	r.AddCookie(&http.Cookie{Name: "oidc_cli_redirect", Value: "http://127.0.0.1:54321/callback"})

	api.oidcCallbackHandler(w, r)

	require.Equal(t, http.StatusFound, w.Code)
	location := w.Header().Get("Location")
	assert.Contains(t, location, "http://127.0.0.1:54321/callback?code=")

	code := strings.TrimPrefix(location, "http://127.0.0.1:54321/callback?code=")
	got, ok := api.cliExchange.consume(code)
	require.True(t, ok)
	assert.Equal(t, "access-token", got.Token)
	assert.Equal(t, user.ID.String(), got.UserID)
}

func TestOIDCCallback_InvalidCLIRedirectCookie_Returns400(t *testing.T) {
	oidcSvc := &mockOIDCService{}
	oidcSvc.On("HandleCallback", mock.Anything, "auth-code", "nonce-1", "verifier-1").
		Return(&authServices.OIDCIdentity{Subject: "sub-1"}, nil)
	api := newOIDCHAPI(oidcSvc, nil, nil)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/oidc/callback?state=expected&code=auth-code", nil)
	r.AddCookie(&http.Cookie{Name: "oidc_state", Value: "expected"})
	r.AddCookie(&http.Cookie{Name: "oidc_nonce", Value: "nonce-1"})
	r.AddCookie(&http.Cookie{Name: "oidc_pkce", Value: "verifier-1"})
	r.AddCookie(&http.Cookie{Name: "oidc_cli_redirect", Value: "https://evil.example.com/callback"})

	api.oidcCallbackHandler(w, r)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestOIDCLogin_SetsPKCECookie(t *testing.T) {
	oidcSvc := &mockOIDCService{}
	oidcSvc.On("AuthCodeURL", mock.Anything, mock.Anything, mock.AnythingOfType("string")).
		Return("https://idp.example.com/authorize")
	api := newOIDCHAPI(oidcSvc, nil, nil)
	w := httptest.NewRecorder()

	api.oidcLoginHandler(w, httptest.NewRequest(http.MethodGet, "/oidc/login", nil))

	var verifier string
	for _, ck := range w.Result().Cookies() {
		if ck.Name == "oidc_pkce" {
			verifier = ck.Value
			assert.True(t, ck.HttpOnly)
			assert.True(t, ck.Secure)
		}
	}
	require.NotEmpty(t, verifier, "oidc_pkce cookie must be set")
	oidcSvc.AssertCalled(t, "AuthCodeURL", mock.Anything, mock.Anything, verifier)
}

func TestOIDCCallback_MissingPKCECookie_400(t *testing.T) {
	oidcSvc := &mockOIDCService{}
	api := newOIDCHAPI(oidcSvc, nil, nil)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/oidc/callback?state=expected&code=y", nil)
	r.AddCookie(&http.Cookie{Name: "oidc_state", Value: "expected"})
	r.AddCookie(&http.Cookie{Name: "oidc_nonce", Value: "nonce-1"})

	api.oidcCallbackHandler(w, r)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	oidcSvc.AssertNotCalled(t, "HandleCallback", mock.Anything, mock.Anything, mock.Anything, mock.Anything)
}

func TestOIDCCallback_PassesVerifierToService(t *testing.T) {
	oidcSvc := &mockOIDCService{}
	oidcSvc.On("HandleCallback", mock.Anything, "auth-code", "nonce-1", "verifier-1").
		Return(nil, errors.New("boom"))
	api := newOIDCHAPI(oidcSvc, nil, nil)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/oidc/callback?state=expected&code=auth-code", nil)
	r.AddCookie(&http.Cookie{Name: "oidc_state", Value: "expected"})
	r.AddCookie(&http.Cookie{Name: "oidc_nonce", Value: "nonce-1"})
	r.AddCookie(&http.Cookie{Name: "oidc_pkce", Value: "verifier-1"})

	api.oidcCallbackHandler(w, r)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
	oidcSvc.AssertExpectations(t)
}

func TestOIDCCallback_StateMismatch_ClearsAllCookies(t *testing.T) {
	api := newOIDCHAPI(&mockOIDCService{}, nil, nil)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/oidc/callback?state=wrong&code=y", nil)
	r.AddCookie(&http.Cookie{Name: "oidc_state", Value: "expected"})
	r.AddCookie(&http.Cookie{Name: "oidc_nonce", Value: "nonce-1"})
	r.AddCookie(&http.Cookie{Name: "oidc_pkce", Value: "verifier-1"})

	api.oidcCallbackHandler(w, r)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	cleared := map[string]bool{}
	for _, ck := range w.Result().Cookies() {
		if ck.MaxAge < 0 {
			cleared[ck.Name] = true
		}
	}
	for _, name := range []string{"oidc_state", "oidc_nonce", "oidc_pkce", "oidc_cli_redirect"} {
		assert.True(t, cleared[name], "%s must be cleared", name)
	}
}
