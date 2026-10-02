// Package api — additional tests for OAuth2 handlers covering token endpoint and service account CRUD.
package api

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
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
	"rocketvault/internal/testutils"
	"rocketvault/internal/certcache"
	"rocketvault/internal/vaultcache"
	"rocketvault/model"
)

// --- mock OAuth2Service ---

type mockOAuth2Svc struct {
	mock.Mock
}

func (m *mockOAuth2Svc) IssueToken(ctx context.Context, clientName, clientSecret string) (*oauth2Services.TokenResponse, error) {
	args := m.Called(ctx, clientName, clientSecret)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*oauth2Services.TokenResponse), args.Error(1)
}

func (m *mockOAuth2Svc) CreateClient(ctx context.Context, name, description string, expiresAt *time.Time) (*model.OAuth2Client, string, error) {
	args := m.Called(ctx, name, description, expiresAt)
	if args.Get(0) == nil {
		return nil, args.String(1), args.Error(2)
	}
	return args.Get(0).(*model.OAuth2Client), args.String(1), args.Error(2)
}

func (m *mockOAuth2Svc) GetClient(ctx context.Context, id uuid.UUID) (*model.OAuth2Client, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*model.OAuth2Client), args.Error(1)
}

func (m *mockOAuth2Svc) ListClients(ctx context.Context) ([]*model.OAuth2Client, error) {
	args := m.Called(ctx)
	return args.Get(0).([]*model.OAuth2Client), args.Error(1)
}

func (m *mockOAuth2Svc) RotateSecret(ctx context.Context, id uuid.UUID) (string, error) {
	args := m.Called(ctx, id)
	return args.String(0), args.Error(1)
}

func (m *mockOAuth2Svc) DeleteClient(ctx context.Context, id uuid.UUID) error {
	args := m.Called(ctx, id)
	return args.Error(0)
}

// --- oauth2HTestContainer ---

type oauth2HTestContainer struct {
	svc      oauth2Services.OAuth2Service
	auditSvc auditServices.AuditServiceInterface
}

func (c *oauth2HTestContainer) GetOAuth2Service() oauth2Services.OAuth2Service { return c.svc }
func (c *oauth2HTestContainer) GetRBACService() authzServices.RBACService {
	panic("unexpected call: GetRBACService")
}
func (c *oauth2HTestContainer) GetUserRepository() repositories.UserRepositoryInterface {
	panic("unexpected call: GetUserRepository")
}
func (c *oauth2HTestContainer) GetSecretRepository() repositories.SecretRepositoryInterface {
	panic("unexpected call: GetSecretRepository")
}
func (c *oauth2HTestContainer) GetRotationRepository() repositories.RotationPolicyRepositoryInterface {
	panic("unexpected call: GetRotationRepository")
}
func (c *oauth2HTestContainer) GetVersionRepository() repositories.SecretVersionRepositoryInterface {
	panic("unexpected call: GetVersionRepository")
}
func (c *oauth2HTestContainer) GetKeyRepository() repositories.KeyRepositoryInterface {
	panic("unexpected call: GetKeyRepository")
}
func (c *oauth2HTestContainer) GetCertificateRepository() repositories.CertificateRepositoryInterface {
	panic("unexpected call: GetCertificateRepository")
}
func (c *oauth2HTestContainer) GetKeyRotationPolicyRepository() repositories.KeyRotationPolicyRepositoryInterface {
	panic("unexpected call: GetKeyRotationPolicyRepository")
}
func (c *oauth2HTestContainer) GetCertificatePolicyRepository() repositories.CertificatePolicyRepositoryInterface {
	panic("unexpected call: GetCertificatePolicyRepository")
}
func (c *oauth2HTestContainer) GetSessionRepository() repositories.SessionRepositoryInterface {
	panic("unexpected call: GetSessionRepository")
}
func (c *oauth2HTestContainer) GetVaultRepository() repositories.VaultRepositoryInterface {
	panic("unexpected call: GetVaultRepository")
}
func (c *oauth2HTestContainer) GetVaultService() vaultServices.VaultService {
	panic("unexpected call: GetVaultService")
}
func (c *oauth2HTestContainer) GetVaultWebhookService() vaultServices.VaultWebhookService {
	panic("unexpected call: GetVaultWebhookService")
}
func (c *oauth2HTestContainer) GetPasswordService() authServices.PasswordService {
	panic("unexpected call: GetPasswordService")
}
func (c *oauth2HTestContainer) GetTOTPService() authServices.TOTPService {
	panic("unexpected call: GetTOTPService")
}
func (c *oauth2HTestContainer) GetJWTService() authServices.JWTService {
	panic("unexpected call: GetJWTService")
}
func (c *oauth2HTestContainer) GetAuthenticationService() authServices.AuthenticationService {
	panic("unexpected call: GetAuthenticationService")
}
func (c *oauth2HTestContainer) GetOIDCService() authServices.OIDCService {
	panic("unexpected call: GetOIDCService")
}
func (c *oauth2HTestContainer) GetAccessPolicyRepository() repositories.AccessPolicyRepositoryInterface {
	panic("unexpected call: GetAccessPolicyRepository")
}
func (c *oauth2HTestContainer) GetAccessPolicyService() authzServices.AccessPolicyService {
	panic("unexpected call: GetAccessPolicyService")
}
func (c *oauth2HTestContainer) GetRoleAssignmentService() authzServices.RoleAssignmentService {
	return nil
}
func (c *oauth2HTestContainer) GetGrantService() provisioning.GrantService {
	return nil
}
func (c *oauth2HTestContainer) GetOAuth2ClientRepository() repositories.OAuth2ClientRepositoryInterface {
	panic("unexpected call: GetOAuth2ClientRepository")
}
func (c *oauth2HTestContainer) GetUserService() userServices.UserService {
	panic("unexpected call: GetUserService")
}
func (c *oauth2HTestContainer) GetSecretService() secretServices.SecretService {
	panic("unexpected call: GetSecretService")
}
func (c *oauth2HTestContainer) GetKeyService() keyServices.KeyService {
	panic("unexpected call: GetKeyService")
}
func (c *oauth2HTestContainer) GetCertificateService() certServices.CertificateService {
	panic("unexpected call: GetCertificateService")
}
func (c *oauth2HTestContainer) GetCertificateRenewalService() certServices.CertificateRenewalService {
	panic("unexpected call: GetCertificateRenewalService")
}
func (c *oauth2HTestContainer) GetCryptoService() keyServices.CryptoService {
	panic("unexpected call: GetCryptoService")
}
func (c *oauth2HTestContainer) GetCryptographyService() secretServices.CryptographyService {
	panic("unexpected call: GetCryptographyService")
}
func (c *oauth2HTestContainer) GetVersioningService() secretServices.VersioningServiceInterface {
	panic("unexpected call: GetVersioningService")
}
func (c *oauth2HTestContainer) GetTagService() secretServices.TagService {
	panic("unexpected call: GetTagService")
}
func (c *oauth2HTestContainer) GetRotationService() secretServices.RotationServiceInterface {
	panic("unexpected call: GetRotationService")
}
func (c *oauth2HTestContainer) GetSchedulerService() secretServices.SchedulerServiceInterface {
	panic("unexpected call: GetSchedulerService")
}
func (c *oauth2HTestContainer) GetDatabase() *sql.DB { panic("unexpected call: GetDatabase") }
func (c *oauth2HTestContainer) GetLogger() *logging.Logger {
	panic("unexpected call: GetLogger")
}
func (c *oauth2HTestContainer) GetSecretCache() *cache.SecretCache {
	panic("unexpected call: GetSecretCache")
}
func (c *oauth2HTestContainer) GetCacheConfig() rvconfig.CacheConfig {
	panic("unexpected call: GetCacheConfig")
}

func (c *oauth2HTestContainer) GetVaultCache() *vaultcache.Cache {
	panic("unexpected call: GetVaultCache")
}
func (c *oauth2HTestContainer) GetCertificateCache() *certcache.Cache {
	panic("unexpected call: GetCertificateCache")
}
func (c *oauth2HTestContainer) GetCachedSecretService() secretServices.SecretService {
	panic("unexpected call: GetCachedSecretService")
}
func (c *oauth2HTestContainer) GetRetryService() retryServices.RetryService {
	panic("unexpected call: GetRetryService")
}
func (c *oauth2HTestContainer) GetKeyProvider() crypto.KeyProvider             { return nil }
func (c *oauth2HTestContainer) GetSigningProvider() signing.SigningKeyProvider { return nil }
func (c *oauth2HTestContainer) GetItemBackupService() *backup.ItemBackupService {
	return nil
}
func (c *oauth2HTestContainer) GetKeyCache() keycache.Cache             { return nil }
func (c *oauth2HTestContainer) GetCryptoMetrics() metrics.CryptoMetrics { return nil }
func (c *oauth2HTestContainer) GetAuditService() auditServices.AuditServiceInterface {
	return c.auditSvc
}
func (c *oauth2HTestContainer) GetComplianceReportService() auditServices.ComplianceReportServiceInterface {
	return nil
}
func (c *oauth2HTestContainer) Close() error { return nil }

// newOAuth2HCtx builds a Context backed by the given OAuth2Service mock.
func newOAuth2HCtx(svc oauth2Services.OAuth2Service) *Context {
	a := &app.App{ServiceContainer: &oauth2HTestContainer{svc: svc}}
	return &Context{
		App:    a,
		Claims: RequestClaims{Roles: []string{"secrets_manager", string(model.RoleAdmin)}},
		Params: &ApiParams{PerPage: 60},
	}
}

// newOAuth2HAPI builds an API instance for tokenHandler tests.
func newOAuth2HAPI(svc oauth2Services.OAuth2Service) *API {
	a := &app.App{ServiceContainer: &oauth2HTestContainer{svc: svc}}
	return &API{App: a, Logger: userTestLog()}
}

// ============================================================
// extractClientCredentials
// ============================================================

func TestExtractClientCredentials_BasicAuth_OK(t *testing.T) {
	creds := base64.StdEncoding.EncodeToString([]byte("myclient:mysecret"))
	r := httptest.NewRequest(http.MethodPost, "/oauth2/token", nil)
	r.Header.Set("Authorization", "Basic "+creds)
	r.ParseForm() //nolint:errcheck,gosec

	id, secret, ok := extractClientCredentials(r)
	assert.True(t, ok)
	assert.Equal(t, "myclient", id)
	assert.Equal(t, "mysecret", secret)
}

func TestExtractClientCredentials_InvalidBase64_Fails(t *testing.T) {
	r := httptest.NewRequest(http.MethodPost, "/oauth2/token", nil)
	r.Header.Set("Authorization", "Basic !!!not-base64!!!")
	r.ParseForm() //nolint:errcheck,gosec

	_, _, ok := extractClientCredentials(r)
	assert.False(t, ok)
}

func TestExtractClientCredentials_BasicNoColon_Fails(t *testing.T) {
	creds := base64.StdEncoding.EncodeToString([]byte("nocolon"))
	r := httptest.NewRequest(http.MethodPost, "/oauth2/token", nil)
	r.Header.Set("Authorization", "Basic "+creds)
	r.ParseForm() //nolint:errcheck,gosec

	_, _, ok := extractClientCredentials(r)
	assert.False(t, ok)
}

func TestExtractClientCredentials_FormBody_OK(t *testing.T) {
	body := strings.NewReader("client_id=myid&client_secret=mysec&grant_type=client_credentials")
	r := httptest.NewRequest(http.MethodPost, "/oauth2/token", body)
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.ParseForm() //nolint:errcheck,gosec

	id, secret, ok := extractClientCredentials(r)
	assert.True(t, ok)
	assert.Equal(t, "myid", id)
	assert.Equal(t, "mysec", secret)
}

// ============================================================
// writeTokenError
// ============================================================

func TestWriteTokenError_RFC6749Format(t *testing.T) {
	w := httptest.NewRecorder()
	writeTokenError(w, http.StatusUnauthorized, "invalid_client", "bad creds")

	assert.Equal(t, http.StatusUnauthorized, w.Code)
	var body map[string]string
	require.NoError(t, json.NewDecoder(w.Body).Decode(&body))
	assert.Equal(t, "invalid_client", body["error"])
	assert.Equal(t, "bad creds", body["error_description"])
}

// ============================================================
// tokenHandler
// ============================================================

func TestTokenHandler_WrongCT_Returns400(t *testing.T) {
	api := newOAuth2HAPI(nil)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/oauth2/token", bytes.NewReader([]byte("grant_type=client_credentials")))
	r.Header.Set("Content-Type", "application/json")

	api.tokenHandler(w, r)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestTokenHandler_WrongGrant_Returns400(t *testing.T) {
	api := newOAuth2HAPI(nil)
	w := httptest.NewRecorder()
	body := strings.NewReader("grant_type=password&client_id=x&client_secret=y")
	r := httptest.NewRequest(http.MethodPost, "/oauth2/token", body)
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	api.tokenHandler(w, r)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestTokenHandler_MissingCreds_Returns401(t *testing.T) {
	api := newOAuth2HAPI(nil)
	w := httptest.NewRecorder()
	body := strings.NewReader("grant_type=client_credentials")
	r := httptest.NewRequest(http.MethodPost, "/oauth2/token", body)
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	api.tokenHandler(w, r)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestTokenHandler_InvalidCreds_Returns401(t *testing.T) {
	svc := &mockOAuth2Svc{}
	svc.On("IssueToken", mock.Anything, "bad_client", "bad_sec").Return(nil, errors.New("invalid"))

	api := newOAuth2HAPI(svc)
	w := httptest.NewRecorder()
	body := strings.NewReader("grant_type=client_credentials&client_id=bad_client&client_secret=bad_sec")
	r := httptest.NewRequest(http.MethodPost, "/oauth2/token", body)
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	api.tokenHandler(w, r)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
	svc.AssertExpectations(t)
}

func TestTokenHandler_Success_Returns200(t *testing.T) {
	svc := &mockOAuth2Svc{}
	svc.On("IssueToken", mock.Anything, "good_client", "good_sec").Return(&oauth2Services.TokenResponse{
		AccessToken: "tok", TokenType: "Bearer", ExpiresIn: 3600,
	}, nil)

	api := newOAuth2HAPI(svc)
	w := httptest.NewRecorder()
	body := strings.NewReader("grant_type=client_credentials&client_id=good_client&client_secret=good_sec")
	r := httptest.NewRequest(http.MethodPost, "/oauth2/token", body)
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	api.tokenHandler(w, r)
	assert.Equal(t, http.StatusOK, w.Code)
	svc.AssertExpectations(t)
}

func TestTokenHandler_Success_RecordsAuditEvent(t *testing.T) {
	svc := &mockOAuth2Svc{}
	svc.On("IssueToken", mock.Anything, "good_client", "good_sec").Return(&oauth2Services.TokenResponse{
		AccessToken: "tok", TokenType: "Bearer", ExpiresIn: 3600,
	}, nil)
	mockAudit := &testutils.MockAuditService{}
	mockAudit.On("RecordEvent", mock.Anything, mock.MatchedBy(func(e auditServices.AuditEvent) bool {
		return e.Action == "oauth2_token_issue" && e.Outcome == "success" && e.ResourceID == "good_client"
	})).Return(nil)

	a := &app.App{ServiceContainer: &oauth2HTestContainer{svc: svc, auditSvc: mockAudit}}
	api := &API{App: a, Logger: userTestLog()}
	w := httptest.NewRecorder()
	body := strings.NewReader("grant_type=client_credentials&client_id=good_client&client_secret=good_sec")
	r := httptest.NewRequest(http.MethodPost, "/oauth2/token", body)
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	api.tokenHandler(w, r)

	assert.Equal(t, http.StatusOK, w.Code)
	svc.AssertExpectations(t)
	mockAudit.AssertExpectations(t)
}

func TestTokenHandler_InvalidCreds_RecordsFailureAuditEvent(t *testing.T) {
	svc := &mockOAuth2Svc{}
	svc.On("IssueToken", mock.Anything, "bad_client", "bad_sec").Return(nil, errors.New("invalid"))
	mockAudit := &testutils.MockAuditService{}
	mockAudit.On("RecordEvent", mock.Anything, mock.MatchedBy(func(e auditServices.AuditEvent) bool {
		return e.Action == "oauth2_token_issue" && e.Outcome == "failure" && e.ResourceID == "bad_client"
	})).Return(nil)

	a := &app.App{ServiceContainer: &oauth2HTestContainer{svc: svc, auditSvc: mockAudit}}
	api := &API{App: a, Logger: userTestLog()}
	w := httptest.NewRecorder()
	body := strings.NewReader("grant_type=client_credentials&client_id=bad_client&client_secret=bad_sec")
	r := httptest.NewRequest(http.MethodPost, "/oauth2/token", body)
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	api.tokenHandler(w, r)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
	svc.AssertExpectations(t)
	mockAudit.AssertExpectations(t)
}

func TestTokenHandler_OversizedClientID_TruncatedInAuditEvent(t *testing.T) {
	oversized := strings.Repeat("a", 300)
	truncated := oversized[:maxAuditClientIDLen]

	svc := &mockOAuth2Svc{}
	svc.On("IssueToken", mock.Anything, oversized, "bad_sec").Return(nil, errors.New("invalid"))
	mockAudit := &testutils.MockAuditService{}
	mockAudit.On("RecordEvent", mock.Anything, mock.MatchedBy(func(e auditServices.AuditEvent) bool {
		return e.UserID == truncated && e.ResourceID == truncated &&
			len(e.UserID) == maxAuditClientIDLen && len(e.ResourceID) == maxAuditClientIDLen
	})).Return(nil)

	a := &app.App{ServiceContainer: &oauth2HTestContainer{svc: svc, auditSvc: mockAudit}}
	api := &API{App: a, Logger: userTestLog()}
	w := httptest.NewRecorder()
	body := strings.NewReader("grant_type=client_credentials&client_id=" + oversized + "&client_secret=bad_sec")
	r := httptest.NewRequest(http.MethodPost, "/oauth2/token", body)
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	api.tokenHandler(w, r)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
	svc.AssertExpectations(t)
	mockAudit.AssertExpectations(t)
}

// ============================================================
// tokenHandler: credentials come from the body or Basic auth only
// ============================================================

func TestTokenHandler_SecretInQueryStringIsIgnored(t *testing.T) {
	svc := &mockOAuth2Svc{} // IssueToken must never be called.
	api := newOAuth2HAPI(svc)
	w := httptest.NewRecorder()
	r := httptest.NewRequestWithContext(context.Background(), http.MethodPost,
		"/oauth2/token?client_id=app&client_secret=leaked", strings.NewReader("grant_type=client_credentials"))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	api.tokenHandler(w, r)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
	svc.AssertNotCalled(t, "IssueToken", mock.Anything, mock.Anything, mock.Anything)
}

func TestTokenHandler_GrantTypeInQueryStringIsIgnored(t *testing.T) {
	api := newOAuth2HAPI(nil)
	w := httptest.NewRecorder()
	r := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/oauth2/token?grant_type=client_credentials", strings.NewReader(""))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	api.tokenHandler(w, r)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// A body client_id must not be completed by a secret taken from the URL, and
// the response must be the same one a request with no secret at all gets.
func TestTokenHandler_QuerySecretDoesNotCompleteBodyClientID(t *testing.T) {
	missing := httptest.NewRecorder()
	r := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/oauth2/token", strings.NewReader("grant_type=client_credentials&client_id=app"))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	newOAuth2HAPI(nil).tokenHandler(missing, r)

	svc := &mockOAuth2Svc{} // IssueToken must never be called.
	w := httptest.NewRecorder()
	r = httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/oauth2/token?client_secret=leaked",
		strings.NewReader("grant_type=client_credentials&client_id=app"))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	newOAuth2HAPI(svc).tokenHandler(w, r)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
	assert.Equal(t, missing.Body.String(), w.Body.String(), "the query secret changes nothing in the response")
	assert.Equal(t, missing.Header().Get("WWW-Authenticate"), w.Header().Get("WWW-Authenticate"))
	assert.NotContains(t, w.Body.String(), "leaked")
	svc.AssertNotCalled(t, "IssueToken", mock.Anything, mock.Anything, mock.Anything)
}

func TestTokenHandler_BodyCredentialsIgnoreQueryValues(t *testing.T) {
	svc := &mockOAuth2Svc{}
	svc.On("IssueToken", mock.Anything, "good_client", "good_sec").Return(&oauth2Services.TokenResponse{
		AccessToken: "tok", TokenType: "Bearer", ExpiresIn: 3600,
	}, nil)

	w := httptest.NewRecorder()
	r := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/oauth2/token?client_id=other&client_secret=other_sec",
		strings.NewReader("grant_type=client_credentials&client_id=good_client&client_secret=good_sec"))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	newOAuth2HAPI(svc).tokenHandler(w, r)

	assert.Equal(t, http.StatusOK, w.Code)
	svc.AssertExpectations(t)
}

func TestTokenHandler_BasicAuthStillWorks(t *testing.T) {
	svc := &mockOAuth2Svc{}
	svc.On("IssueToken", mock.Anything, "basic_client", "basic_sec").Return(&oauth2Services.TokenResponse{
		AccessToken: "tok", TokenType: "Bearer", ExpiresIn: 3600,
	}, nil)

	w := httptest.NewRecorder()
	r := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/oauth2/token?client_secret=leaked",
		strings.NewReader("grant_type=client_credentials"))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.SetBasicAuth("basic_client", "basic_sec")
	newOAuth2HAPI(svc).tokenHandler(w, r)

	assert.Equal(t, http.StatusOK, w.Code)
	svc.AssertExpectations(t)
}

func TestExtractClientCredentials_QueryStringIgnored(t *testing.T) {
	r := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/oauth2/token?client_id=qid&client_secret=qsec",
		strings.NewReader("grant_type=client_credentials"))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	require.NoError(t, r.ParseForm())

	id, secret, ok := extractClientCredentials(r)
	assert.True(t, ok)
	assert.Empty(t, id)
	assert.Empty(t, secret)
}

// ============================================================
// createServiceAccount (additional paths)
// ============================================================

func TestCreateSA_MissingName_Returns400(t *testing.T) {
	c := newOAuth2HCtx(nil)
	w := httptest.NewRecorder()
	body, _ := json.Marshal(map[string]any{"description": "desc"})
	r := httptest.NewRequest(http.MethodPost, "/service-accounts", bytes.NewReader(body))

	createServiceAccount(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestCreateSA_ServiceError_Returns500(t *testing.T) {
	svc := &mockOAuth2Svc{}
	svc.On("CreateClient", mock.Anything, "svcname", "", (*time.Time)(nil)).Return(nil, "", errors.New("db error"))

	c := newOAuth2HCtx(svc)
	w := httptest.NewRecorder()
	body, _ := json.Marshal(map[string]any{"name": "svcname"})
	r := httptest.NewRequest(http.MethodPost, "/service-accounts", bytes.NewReader(body))

	createServiceAccount(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusInternalServerError, w.Code)
	svc.AssertExpectations(t)
}

func TestCreateSA_Success_Returns201(t *testing.T) {
	svc := &mockOAuth2Svc{}
	clientID := uuid.New()
	now := time.Now()
	svc.On("CreateClient", mock.Anything, "svcname", "", (*time.Time)(nil)).Return(&model.OAuth2Client{
		ID: clientID, Name: "svcname", Enabled: true, CreatedAt: now,
	}, "plain-secret", nil)

	c := newOAuth2HCtx(svc)
	w := httptest.NewRecorder()
	body, _ := json.Marshal(map[string]any{"name": "svcname"})
	r := httptest.NewRequest(http.MethodPost, "/service-accounts", bytes.NewReader(body))

	createServiceAccount(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusCreated, w.Code)
	svc.AssertExpectations(t)
}

func TestCreateSA_Success_RecordsAuditEvent(t *testing.T) {
	svc := &mockOAuth2Svc{}
	clientID := uuid.New()
	now := time.Now()
	svc.On("CreateClient", mock.Anything, "svcname", "", (*time.Time)(nil)).Return(&model.OAuth2Client{
		ID: clientID, Name: "svcname", Enabled: true, CreatedAt: now,
	}, "plain-secret", nil)
	mockAudit := &testutils.MockAuditService{}
	mockAudit.On("RecordEvent", mock.Anything, mock.MatchedBy(func(e auditServices.AuditEvent) bool {
		return e.Action == "service_account_create" && e.Outcome == "success" && e.ResourceID == clientID.String()
	})).Return(nil)

	c := newOAuth2HCtx(svc)
	c.App.ServiceContainer.(*oauth2HTestContainer).auditSvc = mockAudit
	w := httptest.NewRecorder()
	body, _ := json.Marshal(map[string]any{"name": "svcname"})
	r := httptest.NewRequest(http.MethodPost, "/service-accounts", bytes.NewReader(body))

	createServiceAccount(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusCreated, w.Code)
	svc.AssertExpectations(t)
	mockAudit.AssertExpectations(t)
}

// ============================================================
// listServiceAccounts (additional paths)
// ============================================================

func TestListSA_ServiceError_Returns500(t *testing.T) {
	svc := &mockOAuth2Svc{}
	svc.On("ListClients", mock.Anything).Return([]*model.OAuth2Client{}, errors.New("db error"))

	c := newOAuth2HCtx(svc)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/service-accounts", nil)

	listServiceAccounts(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusInternalServerError, w.Code)
	svc.AssertExpectations(t)
}

func TestListSA_Success_Returns200(t *testing.T) {
	svc := &mockOAuth2Svc{}
	svc.On("ListClients", mock.Anything).Return([]*model.OAuth2Client{{ID: uuid.New(), Name: "svc1"}}, nil)

	c := newOAuth2HCtx(svc)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/service-accounts", nil)

	listServiceAccounts(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusOK, w.Code)
	svc.AssertExpectations(t)
}

// ============================================================
// getServiceAccount (additional paths)
// ============================================================

func TestGetSA_InvalidID_Returns400(t *testing.T) {
	c := newOAuth2HCtx(nil)
	c.Params = &ApiParams{ServiceAccountID: "bad"}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/service-accounts/bad", nil)

	getServiceAccount(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestGetSA_NotFound_Returns404(t *testing.T) {
	saID := uuid.New()
	svc := &mockOAuth2Svc{}
	svc.On("GetClient", mock.Anything, saID).Return(nil, errors.New("not found"))

	c := newOAuth2HCtx(svc)
	c.Params = &ApiParams{ServiceAccountID: saID.String()}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/service-accounts/"+saID.String(), nil)

	getServiceAccount(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusNotFound, w.Code)
	svc.AssertExpectations(t)
}

func TestGetSA_Success_Returns200(t *testing.T) {
	saID := uuid.New()
	svc := &mockOAuth2Svc{}
	svc.On("GetClient", mock.Anything, saID).Return(&model.OAuth2Client{ID: saID, Name: "sa"}, nil)

	c := newOAuth2HCtx(svc)
	c.Params = &ApiParams{ServiceAccountID: saID.String()}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/service-accounts/"+saID.String(), nil)

	getServiceAccount(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusOK, w.Code)
	svc.AssertExpectations(t)
}

// ============================================================
// deleteServiceAccount (additional paths)
// ============================================================

func TestDeleteSA_InvalidID_Returns400(t *testing.T) {
	c := newOAuth2HCtx(nil)
	c.Params = &ApiParams{ServiceAccountID: "bad"}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodDelete, "/service-accounts/bad", nil)

	deleteServiceAccount(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestDeleteSA_ServiceError_Returns500(t *testing.T) {
	saID := uuid.New()
	svc := &mockOAuth2Svc{}
	svc.On("DeleteClient", mock.Anything, saID).Return(errors.New("db error"))

	c := newOAuth2HCtx(svc)
	c.Params = &ApiParams{ServiceAccountID: saID.String()}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodDelete, "/service-accounts/"+saID.String(), nil)

	deleteServiceAccount(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusInternalServerError, w.Code)
	svc.AssertExpectations(t)
}

func TestDeleteSA_Success_Returns200(t *testing.T) {
	saID := uuid.New()
	svc := &mockOAuth2Svc{}
	svc.On("DeleteClient", mock.Anything, saID).Return(nil)

	c := newOAuth2HCtx(svc)
	c.Params = &ApiParams{ServiceAccountID: saID.String()}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodDelete, "/service-accounts/"+saID.String(), nil)

	deleteServiceAccount(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusOK, w.Code)
	svc.AssertExpectations(t)
}

func TestDeleteSA_Success_RecordsAuditEvent(t *testing.T) {
	saID := uuid.New()
	svc := &mockOAuth2Svc{}
	svc.On("DeleteClient", mock.Anything, saID).Return(nil)
	mockAudit := &testutils.MockAuditService{}
	mockAudit.On("RecordEvent", mock.Anything, mock.MatchedBy(func(e auditServices.AuditEvent) bool {
		return e.Action == "service_account_delete" && e.Outcome == "success" && e.ResourceID == saID.String()
	})).Return(nil)

	c := newOAuth2HCtx(svc)
	c.App.ServiceContainer.(*oauth2HTestContainer).auditSvc = mockAudit
	c.Params = &ApiParams{ServiceAccountID: saID.String()}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodDelete, "/service-accounts/"+saID.String(), nil)

	deleteServiceAccount(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusOK, w.Code)
	svc.AssertExpectations(t)
	mockAudit.AssertExpectations(t)
}

// ============================================================
// rotateServiceAccountSecret (additional paths)
// ============================================================

func TestRotateSA_InvalidID_Returns400(t *testing.T) {
	c := newOAuth2HCtx(nil)
	c.Params = &ApiParams{ServiceAccountID: "bad"}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/service-accounts/bad/rotate", nil)

	rotateServiceAccountSecret(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestRotateSA_ServiceError_Returns500(t *testing.T) {
	saID := uuid.New()
	svc := &mockOAuth2Svc{}
	svc.On("RotateSecret", mock.Anything, saID).Return("", errors.New("rotate failed"))

	c := newOAuth2HCtx(svc)
	c.Params = &ApiParams{ServiceAccountID: saID.String()}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/service-accounts/"+saID.String()+"/rotate", nil)

	rotateServiceAccountSecret(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusInternalServerError, w.Code)
	svc.AssertExpectations(t)
}

func TestRotateSA_Success_Returns200(t *testing.T) {
	saID := uuid.New()
	svc := &mockOAuth2Svc{}
	svc.On("RotateSecret", mock.Anything, saID).Return("new-secret", nil)

	c := newOAuth2HCtx(svc)
	c.Params = &ApiParams{ServiceAccountID: saID.String()}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/service-accounts/"+saID.String()+"/rotate", nil)

	rotateServiceAccountSecret(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusOK, w.Code)
	svc.AssertExpectations(t)
}

func TestRotateSA_Success_RecordsAuditEvent(t *testing.T) {
	saID := uuid.New()
	svc := &mockOAuth2Svc{}
	svc.On("RotateSecret", mock.Anything, saID).Return("new-secret", nil)
	mockAudit := &testutils.MockAuditService{}
	mockAudit.On("RecordEvent", mock.Anything, mock.MatchedBy(func(e auditServices.AuditEvent) bool {
		return e.Action == "service_account_rotate_secret" && e.Outcome == "success" && e.ResourceID == saID.String()
	})).Return(nil)

	c := newOAuth2HCtx(svc)
	c.App.ServiceContainer.(*oauth2HTestContainer).auditSvc = mockAudit
	c.Params = &ApiParams{ServiceAccountID: saID.String()}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/service-accounts/"+saID.String()+"/rotate", nil)

	rotateServiceAccountSecret(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusOK, w.Code)
	svc.AssertExpectations(t)
	mockAudit.AssertExpectations(t)
}

// ============================================================
// sanitizeAuditClientID
// ============================================================

func TestSanitizeAuditClientID(t *testing.T) {
	assert.Equal(t, "my-app_1", sanitizeAuditClientID("my-app_1"))
	assert.Equal(t, "evilfake", sanitizeAuditClientID("evil\r\n\x00fake"))
	assert.Equal(t, "ab", sanitizeAuditClientID("a\xffb"), "invalid UTF-8 is dropped")
	assert.Equal(t, "a[31mb", sanitizeAuditClientID("a\x1b[31mb"), "ESC is dropped")
	assert.Equal(t, "", sanitizeAuditClientID("\n\t"))
	assert.Equal(t, "", sanitizeAuditClientID(""))

	long := strings.Repeat("é", 200) // 400 bytes.
	got := sanitizeAuditClientID(long)
	assert.LessOrEqual(t, len(got), maxAuditClientIDLen)
	assert.True(t, utf8.ValidString(got), "truncation must not split a rune")
	assert.Equal(t, strings.Repeat("é", 127), got, "254 bytes, the last whole rune that fits")

	assert.Len(t, sanitizeAuditClientID(strings.Repeat("a", 1000)), maxAuditClientIDLen)
}

func TestTokenHandler_ControlCharsInClientIDAreStrippedFromAuditEvent(t *testing.T) {
	svc := &mockOAuth2Svc{}
	// The lookup still receives the original value.
	svc.On("IssueToken", mock.Anything, "evil\nname", "s").Return(nil, errors.New("invalid"))
	mockAudit := &testutils.MockAuditService{}
	mockAudit.On("RecordEvent", mock.Anything, mock.MatchedBy(func(e auditServices.AuditEvent) bool {
		return e.UserID == "evilname" && e.ResourceID == "evilname"
	})).Return(nil)

	a := &app.App{ServiceContainer: &oauth2HTestContainer{svc: svc, auditSvc: mockAudit}}
	api := &API{App: a, Logger: userTestLog()}
	router := mux.NewRouter()
	router.HandleFunc("/oauth2/token", api.tokenHandler).Methods(http.MethodPost)

	w := httptest.NewRecorder()
	body := strings.NewReader("grant_type=client_credentials&client_id=evil%0Aname&client_secret=s")
	r := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/oauth2/token", body)
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	router.ServeHTTP(w, r)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
	assert.NotContains(t, w.Body.String(), "evil", "the response must not echo the client_id")
	svc.AssertExpectations(t)
	mockAudit.AssertExpectations(t)
}
