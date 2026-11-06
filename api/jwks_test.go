// Package api — internal tests for JWKS handlers.
package api

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"rocketvault/app"
	rvconfig "rocketvault/config"
	"rocketvault/internal/backup"
	"rocketvault/internal/cache"
	cryptoPkg "rocketvault/internal/crypto"
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

// --- stub signing providers ---

// stubSigningProvider is a minimal SigningKeyProvider with configurable keys.
type stubSigningProvider struct {
	keys      []signing.PublicKeyInfo
	algorithm string
	keyID     string
}

func (s *stubSigningProvider) PrivateKey() crypto.Signer           { return nil }
func (s *stubSigningProvider) PublicKeys() []signing.PublicKeyInfo { return s.keys }
func (s *stubSigningProvider) Algorithm() string                   { return s.algorithm }
func (s *stubSigningProvider) KeyID() string                       { return s.keyID }

// rotatableStubProvider also implements signing.RotatableProvider.
type rotatableStubProvider struct {
	stubSigningProvider
	rotateKID   string
	rotateUntil string
	rotateErr   error
	rotateCalls int
}

func (r *rotatableStubProvider) Rotate() (string, string, error) {
	r.rotateCalls++
	return r.rotateKID, r.rotateUntil, r.rotateErr
}

// --- jwkContainerBase: full ServiceContainerInterface with configurable signing provider ---

// jwkContainerBase satisfies ServiceContainerInterface for JWKS handler tests.
// Only GetSigningProvider returns a real value; everything else panics.
type jwkContainerBase struct {
	signingProvider signing.SigningKeyProvider
	auditSvc        auditServices.AuditServiceInterface
}

func (c *jwkContainerBase) GetSigningProvider() signing.SigningKeyProvider { return c.signingProvider }
func (c *jwkContainerBase) GetRBACService() authzServices.RBACService {
	panic("unexpected call: GetRBACService")
}
func (c *jwkContainerBase) GetUserRepository() repositories.UserRepositoryInterface {
	panic("unexpected call: GetUserRepository")
}
func (c *jwkContainerBase) GetSecretRepository() repositories.SecretRepositoryInterface {
	panic("unexpected call: GetSecretRepository")
}
func (c *jwkContainerBase) GetRotationRepository() repositories.RotationPolicyRepositoryInterface {
	panic("unexpected call: GetRotationRepository")
}
func (c *jwkContainerBase) GetVersionRepository() repositories.SecretVersionRepositoryInterface {
	panic("unexpected call: GetVersionRepository")
}
func (c *jwkContainerBase) GetKeyRepository() repositories.KeyRepositoryInterface {
	panic("unexpected call: GetKeyRepository")
}
func (c *jwkContainerBase) GetCertificateRepository() repositories.CertificateRepositoryInterface {
	panic("unexpected call: GetCertificateRepository")
}
func (c *jwkContainerBase) GetKeyRotationPolicyRepository() repositories.KeyRotationPolicyRepositoryInterface {
	panic("unexpected call: GetKeyRotationPolicyRepository")
}
func (c *jwkContainerBase) GetCertificatePolicyRepository() repositories.CertificatePolicyRepositoryInterface {
	panic("unexpected call: GetCertificatePolicyRepository")
}
func (c *jwkContainerBase) GetSessionRepository() repositories.SessionRepositoryInterface {
	panic("unexpected call: GetSessionRepository")
}
func (c *jwkContainerBase) GetVaultRepository() repositories.VaultRepositoryInterface {
	panic("unexpected call: GetVaultRepository")
}
func (c *jwkContainerBase) GetVaultService() vaultServices.VaultService {
	panic("unexpected call: GetVaultService")
}
func (c *jwkContainerBase) GetVaultWebhookService() vaultServices.VaultWebhookService {
	panic("unexpected call: GetVaultWebhookService")
}
func (c *jwkContainerBase) GetPasswordService() authServices.PasswordService {
	panic("unexpected call: GetPasswordService")
}
func (c *jwkContainerBase) GetTOTPService() authServices.TOTPService {
	panic("unexpected call: GetTOTPService")
}
func (c *jwkContainerBase) GetJWTService() authServices.JWTService {
	panic("unexpected call: GetJWTService")
}
func (c *jwkContainerBase) GetAuthenticationService() authServices.AuthenticationService {
	panic("unexpected call: GetAuthenticationService")
}
func (c *jwkContainerBase) GetOIDCService() authServices.OIDCService {
	panic("unexpected call: GetOIDCService")
}
func (c *jwkContainerBase) GetAccessPolicyRepository() repositories.AccessPolicyRepositoryInterface {
	panic("unexpected call: GetAccessPolicyRepository")
}
func (c *jwkContainerBase) GetAccessPolicyService() authzServices.AccessPolicyService {
	panic("unexpected call: GetAccessPolicyService")
}
func (c *jwkContainerBase) GetRoleAssignmentService() authzServices.RoleAssignmentService {
	return nil
}
func (c *jwkContainerBase) GetGrantService() provisioning.GrantService {
	return nil
}
func (c *jwkContainerBase) GetOAuth2ClientRepository() repositories.OAuth2ClientRepositoryInterface {
	panic("unexpected call: GetOAuth2ClientRepository")
}
func (c *jwkContainerBase) GetOAuth2Service() oauth2Services.OAuth2Service {
	panic("unexpected call: GetOAuth2Service")
}
func (c *jwkContainerBase) GetUserService() userServices.UserService {
	panic("unexpected call: GetUserService")
}
func (c *jwkContainerBase) GetSecretService() secretServices.SecretService {
	panic("unexpected call: GetSecretService")
}
func (c *jwkContainerBase) GetKeyService() keyServices.KeyService {
	panic("unexpected call: GetKeyService")
}
func (c *jwkContainerBase) GetCertificateService() certServices.CertificateService {
	panic("unexpected call: GetCertificateService")
}
func (c *jwkContainerBase) GetCertificateRenewalService() certServices.CertificateRenewalService {
	panic("unexpected call: GetCertificateRenewalService")
}
func (c *jwkContainerBase) GetCryptoService() keyServices.CryptoService {
	panic("unexpected call: GetCryptoService")
}
func (c *jwkContainerBase) GetCryptographyService() secretServices.CryptographyService {
	panic("unexpected call: GetCryptographyService")
}
func (c *jwkContainerBase) GetVersioningService() secretServices.VersioningServiceInterface {
	panic("unexpected call: GetVersioningService")
}
func (c *jwkContainerBase) GetTagService() secretServices.TagService {
	panic("unexpected call: GetTagService")
}
func (c *jwkContainerBase) GetRotationService() secretServices.RotationServiceInterface {
	panic("unexpected call: GetRotationService")
}
func (c *jwkContainerBase) GetSchedulerService() secretServices.SchedulerServiceInterface {
	panic("unexpected call: GetSchedulerService")
}
func (c *jwkContainerBase) GetDatabase() *sql.DB {
	panic("unexpected call: GetDatabase")
}
func (c *jwkContainerBase) GetLogger() *logging.Logger {
	panic("unexpected call: GetLogger")
}
func (c *jwkContainerBase) GetSecretCache() *cache.SecretCache {
	panic("unexpected call: GetSecretCache")
}
func (c *jwkContainerBase) GetCacheConfig() rvconfig.CacheConfig {
	panic("unexpected call: GetCacheConfig")
}

func (c *jwkContainerBase) GetVaultCache() *vaultcache.Cache {
	panic("unexpected call: GetVaultCache")
}
func (c *jwkContainerBase) GetCertificateCache() *certcache.Cache {
	panic("unexpected call: GetCertificateCache")
}
func (c *jwkContainerBase) GetCachedSecretService() secretServices.SecretService {
	panic("unexpected call: GetCachedSecretService")
}
func (c *jwkContainerBase) GetRetryService() retryServices.RetryService {
	panic("unexpected call: GetRetryService")
}
func (c *jwkContainerBase) GetKeyProvider() cryptoPkg.KeyProvider { return nil }
func (c *jwkContainerBase) GetItemBackupService() *backup.ItemBackupService {
	return nil
}
func (c *jwkContainerBase) GetKeyCache() keycache.Cache             { return nil }
func (c *jwkContainerBase) GetCryptoMetrics() metrics.CryptoMetrics { return nil }
func (c *jwkContainerBase) GetAuditService() auditServices.AuditServiceInterface {
	return c.auditSvc
}
func (c *jwkContainerBase) GetComplianceReportService() auditServices.ComplianceReportServiceInterface {
	return nil
}
func (c *jwkContainerBase) Close() error { return nil }

// newJWKSCtx builds a Context backed by the given signing provider.
func newJWKSCtx(provider signing.SigningKeyProvider) *Context {
	a := &app.App{ServiceContainer: &jwkContainerBase{signingProvider: provider}}
	return &Context{
		App:    a,
		Params: &ApiParams{PerPage: 60},
	}
}

// newJWKSAdminCtx builds a Context with a multi-role claim where admin is
// present but not the sole or first role, for handlers gated to admins.
func newJWKSAdminCtx(provider signing.SigningKeyProvider) *Context {
	c := newJWKSCtx(provider)
	c.Claims = RequestClaims{Roles: []string{"secrets_manager", string(model.RoleAdmin)}, UserID: "00000000-0000-0000-0000-000000000001"}
	return c
}

// ============================================================
// getJWKS
// ============================================================

// TestGetJWKS_NilProvider_Returns503 verifies that when the signing provider is nil
// the handler returns 503 Service Unavailable without setting c.Err.
func TestGetJWKS_NilProvider_Returns503(t *testing.T) {
	c := newJWKSCtx(nil)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/jwks.json", nil)

	getJWKS(c, w, r)

	assert.Equal(t, http.StatusServiceUnavailable, w.Code)
}

// TestGetJWKS_EmptyKeys_Returns200 verifies that when the provider has no keys
// the handler still returns 200 with an empty keys array.
func TestGetJWKS_EmptyKeys_Returns200(t *testing.T) {
	provider := &stubSigningProvider{keys: []signing.PublicKeyInfo{}, algorithm: "RS256"}
	c := newJWKSCtx(provider)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/jwks.json", nil)

	getJWKS(c, w, r)

	assert.Equal(t, http.StatusOK, w.Code)
	var body map[string]any
	require.NoError(t, json.NewDecoder(w.Body).Decode(&body))
	assert.NotNil(t, body["keys"])
}

// TestGetJWKS_WithRSAKey_Returns200AndJWK verifies that an RSA signing key
// is serialised into the JWK Set with the expected fields.
func TestGetJWKS_WithRSAKey_Returns200AndJWK(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	provider := &stubSigningProvider{
		algorithm: "RS256",
		keyID:     "test-kid",
		keys: []signing.PublicKeyInfo{
			{KeyID: "test-kid", Algorithm: "RS256", PublicKey: &rsaKey.PublicKey},
		},
	}
	c := newJWKSCtx(provider)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/jwks.json", nil)

	getJWKS(c, w, r)

	assert.Equal(t, http.StatusOK, w.Code)
	var body map[string]any
	require.NoError(t, json.NewDecoder(w.Body).Decode(&body))
	keys, ok := body["keys"].([]any)
	require.True(t, ok)
	require.Len(t, keys, 1)
	keyMap := keys[0].(map[string]any)
	assert.Equal(t, "RSA", keyMap["kty"])
	assert.Equal(t, "test-kid", keyMap["kid"])
}

// ============================================================
// rotateJWKS
// ============================================================

// TestRotateJWKS_NilProvider_SetsErrWith503 verifies that when the provider is nil
// the handler sets c.Err with StatusServiceUnavailable.
func TestRotateJWKS_NilProvider_SetsErrWith503(t *testing.T) {
	c := newJWKSAdminCtx(nil)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/api/v1/jwks/rotate", nil)

	rotateJWKS(c, w, r)

	require.NotNil(t, c.Err)
	assert.Equal(t, http.StatusServiceUnavailable, c.Err.StatusCode)
}

// TestRotateJWKS_NonRotatableProvider_SetsErrWith400 verifies that when the provider
// does not implement RotatableProvider the handler returns 400.
func TestRotateJWKS_NonRotatableProvider_SetsErrWith400(t *testing.T) {
	provider := &stubSigningProvider{algorithm: "RS256"}
	c := newJWKSAdminCtx(provider)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/api/v1/jwks/rotate", nil)

	rotateJWKS(c, w, r)

	require.NotNil(t, c.Err)
	assert.Equal(t, http.StatusBadRequest, c.Err.StatusCode)
}

// TestRotateJWKS_Success_Returns200 verifies that a rotatable provider produces
// a 200 response with the new key ID and status fields.
func TestRotateJWKS_Success_Returns200(t *testing.T) {
	provider := &rotatableStubProvider{
		rotateKID:   "new-kid",
		rotateUntil: "2026-01-01T00:00:00Z",
		rotateErr:   nil,
	}
	c := newJWKSAdminCtx(provider)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/api/v1/jwks/rotate", nil)

	rotateJWKS(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Nil(t, c.Err)
	assert.Equal(t, http.StatusOK, w.Code)
	var body map[string]any
	require.NoError(t, json.NewDecoder(w.Body).Decode(&body))
	assert.Equal(t, "new-kid", body["new_kid"])
	assert.Equal(t, "ok", body["status"])
}

// TestRotateJWKS_NonAdmin_Returns403 verifies a non-admin caller cannot rotate signing keys.
func TestRotateJWKS_NonAdmin_Returns403(t *testing.T) {
	provider := &rotatableStubProvider{rotateKID: "new-kid", rotateUntil: "2026-01-01T00:00:00Z"}
	c := newJWKSCtx(provider)
	c.Claims = RequestClaims{Roles: []string{"user"}}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/api/v1/jwks/rotate", nil)

	rotateJWKS(c, w, r)

	require.NotNil(t, c.Err)
	assert.Equal(t, http.StatusForbidden, c.Err.StatusCode)
}

// TestRotateJWKS_Success_RecordsAuditEvent verifies a successful rotation writes
// a "jwks_rotate"/"success" audit event tagged with the new key ID.
func TestRotateJWKS_Success_RecordsAuditEvent(t *testing.T) {
	provider := &rotatableStubProvider{rotateKID: "new-kid", rotateUntil: "2026-01-01T00:00:00Z"}
	mockAudit := &testutils.MockAuditService{}
	// The handler may write a critical attempt row first.
	mockAudit.On("RecordCritical", mock.Anything, mock.Anything).Return(nil).Maybe()
	mockAudit.On("RecordEvent", mock.Anything, mock.MatchedBy(func(e auditServices.AuditEvent) bool {
		return e.Action == "jwks_rotate" && e.Outcome == "success" && e.ResourceID == "new-kid"
	})).Return(nil)

	a := &app.App{ServiceContainer: &jwkContainerBase{signingProvider: provider, auditSvc: mockAudit}}
	c := &Context{
		App:    a,
		Claims: RequestClaims{Roles: []string{string(model.RoleAdmin)}, UserID: "00000000-0000-0000-0000-000000000001"},
		Params: &ApiParams{PerPage: 60},
	}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/api/v1/jwks/rotate", nil)

	rotateJWKS(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusOK, w.Code)
	mockAudit.AssertExpectations(t)
}

// ============================================================
// buildJWKSet
// ============================================================

// TestBuildJWKSet_Empty_ReturnsEmptyKeys verifies that an empty key list produces
// an empty "keys" slice.
func TestBuildJWKSet_Empty_ReturnsEmptyKeys(t *testing.T) {
	result, err := buildJWKSet([]signing.PublicKeyInfo{})
	require.NoError(t, err)
	keys, ok := result["keys"].([]map[string]any)
	require.True(t, ok)
	assert.Len(t, keys, 0)
}

// TestBuildJWKSet_RSAKey_ReturnsCorrectStructure verifies that an RSA key is
// correctly serialised with kty="RSA" and the expected fields.
func TestBuildJWKSet_RSAKey_ReturnsCorrectStructure(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	keys := []signing.PublicKeyInfo{
		{KeyID: "kid1", Algorithm: "RS256", PublicKey: &rsaKey.PublicKey},
	}
	result, err := buildJWKSet(keys)
	require.NoError(t, err)

	jwkList, ok := result["keys"].([]map[string]any)
	require.True(t, ok)
	require.Len(t, jwkList, 1)
	assert.Equal(t, "RSA", jwkList[0]["kty"])
	assert.Equal(t, "kid1", jwkList[0]["kid"])
	assert.Equal(t, "RS256", jwkList[0]["alg"])
}

// TestRotateJWKS_RotateError_Returns500 verifies that a rotation failure
// sets an internal error on the context.
func TestRotateJWKS_RotateError_Returns500(t *testing.T) {
	provider := &rotatableStubProvider{
		rotateErr: errors.New("rotate failed"),
	}
	c := newJWKSAdminCtx(provider)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/api/v1/jwks/rotate", nil)

	rotateJWKS(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	require.NotNil(t, c.Err)
	assert.Equal(t, http.StatusInternalServerError, c.Err.StatusCode)
}

// TestGetJWKS_BuildError_Returns500 verifies that when buildJWKSet fails
// (unsupported key type) the handler returns 500.
func TestGetJWKS_BuildError_Returns500(t *testing.T) {
	// An ed25519 public key or unsupported key type would cause buildJWKSet to fail.
	// We supply a key with a nil PublicKey to trigger PublicKeyInfoToJWK error.
	provider := &stubSigningProvider{
		algorithm: "EdDSA",
		keyID:     "edkey",
		keys: []signing.PublicKeyInfo{
			{KeyID: "edkey", Algorithm: "EdDSA", PublicKey: nil},
		},
	}
	c := newJWKSCtx(provider)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/jwks.json", nil)

	getJWKS(c, w, r)

	// buildJWKSet returns an error for an unsupported key type; the handler writes 500.
	assert.Equal(t, http.StatusInternalServerError, w.Code)
}
