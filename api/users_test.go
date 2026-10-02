// Package api — internal tests for user handlers.
package api

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
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"github.com/sirupsen/logrus"
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

// userTestLog returns a minimal logger for user handler tests.
func userTestLog() *logging.Logger {
	l := logrus.New()
	l.SetLevel(logrus.DebugLevel)
	return &logging.Logger{Logger: l}
}

// --- mock UserService ---

type mockUserService struct {
	mock.Mock
}

func (m *mockUserService) CreateUser(ctx context.Context, req userServices.CreateUserRequest) (*userServices.CreateUserResult, error) {
	args := m.Called(ctx, req)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*userServices.CreateUserResult), args.Error(1)
}

func (m *mockUserService) UpdateUser(ctx context.Context, req userServices.UpdateUserRequest) (*userServices.UpdateUserResult, error) {
	args := m.Called(ctx, req)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*userServices.UpdateUserResult), args.Error(1)
}

func (m *mockUserService) GetUser(ctx context.Context, userID uuid.UUID) (*model.User, error) {
	args := m.Called(ctx, userID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*model.User), args.Error(1)
}

func (m *mockUserService) GetUserByUsername(ctx context.Context, username string) (*model.User, error) {
	args := m.Called(ctx, username)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*model.User), args.Error(1)
}

func (m *mockUserService) FindOrCreateExternalUser(ctx context.Context, req userServices.FindOrCreateExternalUserRequest) (*model.User, error) {
	args := m.Called(ctx, req)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*model.User), args.Error(1)
}

func (m *mockUserService) ListUsers(ctx context.Context) ([]model.User, error) {
	args := m.Called(ctx)
	return args.Get(0).([]model.User), args.Error(1)
}

func (m *mockUserService) DeleteUser(ctx context.Context, userID uuid.UUID) error {
	args := m.Called(ctx, userID)
	return args.Error(0)
}

func (m *mockUserService) ValidateBootstrapToken(ctx context.Context, token string) (bool, error) {
	args := m.Called(ctx, token)
	return args.Bool(0), args.Error(1)
}

func (m *mockUserService) InvalidateBootstrapToken(ctx context.Context, token string) error {
	args := m.Called(ctx, token)
	return args.Error(0)
}

// --- mock AuthenticationService ---

type mockAuthService struct {
	mock.Mock
}

func (m *mockAuthService) AuthenticateUser(ctx context.Context, username, password, totpCode string) (*authServices.AuthenticationResult, error) {
	args := m.Called(ctx, username, password, totpCode)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*authServices.AuthenticationResult), args.Error(1)
}

func (m *mockAuthService) IssueSessionForUser(ctx context.Context, user *model.User) (*authServices.AuthenticationResult, error) {
	args := m.Called(ctx, user)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*authServices.AuthenticationResult), args.Error(1)
}

func (m *mockAuthService) ValidateSession(ctx context.Context, token string) (*authServices.JWTClaims, error) {
	args := m.Called(ctx, token)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*authServices.JWTClaims), args.Error(1)
}

func (m *mockAuthService) RefreshAccessToken(ctx context.Context, refreshToken string) (*authServices.RefreshTokenResult, error) {
	args := m.Called(ctx, refreshToken)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*authServices.RefreshTokenResult), args.Error(1)
}

func (m *mockAuthService) RevokeSession(ctx context.Context, req authServices.RevokeSessionRequest) error {
	args := m.Called(ctx, req)
	return args.Error(0)
}

func (m *mockAuthService) RevokeAllUserSessions(ctx context.Context, userID uuid.UUID, reason string) error {
	args := m.Called(ctx, userID, reason)
	return args.Error(0)
}

func (m *mockAuthService) ListActiveSessions(ctx context.Context, userID uuid.UUID) ([]*model.Session, error) {
	args := m.Called(ctx, userID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*model.Session), args.Error(1)
}

// --- userSvcContainer: a container that provides UserService and AuthService ---

// userSvcContainer is a minimal container stub for user handler tests.
// It provides UserService and AuthenticationService; all other methods panic.
type userSvcContainer struct {
	userSvc userServices.UserService
	authSvc authServices.AuthenticationService
}

func (c *userSvcContainer) GetUserService() userServices.UserService { return c.userSvc }
func (c *userSvcContainer) GetAuthenticationService() authServices.AuthenticationService {
	return c.authSvc
}
func (c *userSvcContainer) GetOIDCService() authServices.OIDCService {
	panic("unexpected call: GetOIDCService")
}
func (c *userSvcContainer) GetSessionRepository() repositories.SessionRepositoryInterface {
	panic("unexpected call: GetSessionRepository")
}
func (c *userSvcContainer) GetVaultRepository() repositories.VaultRepositoryInterface {
	panic("unexpected call: GetVaultRepository")
}
func (c *userSvcContainer) GetVaultService() vaultServices.VaultService {
	panic("unexpected call: GetVaultService")
}
func (c *userSvcContainer) GetVaultWebhookService() vaultServices.VaultWebhookService {
	panic("unexpected call: GetVaultWebhookService")
}
func (c *userSvcContainer) GetRBACService() authzServices.RBACService {
	panic("unexpected call: GetRBACService")
}
func (c *userSvcContainer) GetUserRepository() repositories.UserRepositoryInterface {
	panic("unexpected call: GetUserRepository")
}
func (c *userSvcContainer) GetSecretRepository() repositories.SecretRepositoryInterface {
	panic("unexpected call: GetSecretRepository")
}
func (c *userSvcContainer) GetRotationRepository() repositories.RotationPolicyRepositoryInterface {
	panic("unexpected call: GetRotationRepository")
}
func (c *userSvcContainer) GetVersionRepository() repositories.SecretVersionRepositoryInterface {
	panic("unexpected call: GetVersionRepository")
}
func (c *userSvcContainer) GetKeyRepository() repositories.KeyRepositoryInterface {
	panic("unexpected call: GetKeyRepository")
}
func (c *userSvcContainer) GetCertificateRepository() repositories.CertificateRepositoryInterface {
	panic("unexpected call: GetCertificateRepository")
}
func (c *userSvcContainer) GetKeyRotationPolicyRepository() repositories.KeyRotationPolicyRepositoryInterface {
	panic("unexpected call: GetKeyRotationPolicyRepository")
}
func (c *userSvcContainer) GetCertificatePolicyRepository() repositories.CertificatePolicyRepositoryInterface {
	panic("unexpected call: GetCertificatePolicyRepository")
}
func (c *userSvcContainer) GetPasswordService() authServices.PasswordService {
	panic("unexpected call: GetPasswordService")
}
func (c *userSvcContainer) GetTOTPService() authServices.TOTPService {
	panic("unexpected call: GetTOTPService")
}
func (c *userSvcContainer) GetJWTService() authServices.JWTService {
	panic("unexpected call: GetJWTService")
}
func (c *userSvcContainer) GetAccessPolicyRepository() repositories.AccessPolicyRepositoryInterface {
	panic("unexpected call: GetAccessPolicyRepository")
}
func (c *userSvcContainer) GetAccessPolicyService() authzServices.AccessPolicyService {
	panic("unexpected call: GetAccessPolicyService")
}
func (c *userSvcContainer) GetRoleAssignmentService() authzServices.RoleAssignmentService {
	return nil
}
func (c *userSvcContainer) GetGrantService() provisioning.GrantService {
	return nil
}
func (c *userSvcContainer) GetOAuth2ClientRepository() repositories.OAuth2ClientRepositoryInterface {
	panic("unexpected call: GetOAuth2ClientRepository")
}
func (c *userSvcContainer) GetOAuth2Service() oauth2Services.OAuth2Service {
	panic("unexpected call: GetOAuth2Service")
}
func (c *userSvcContainer) GetSecretService() secretServices.SecretService {
	panic("unexpected call: GetSecretService")
}
func (c *userSvcContainer) GetKeyService() keyServices.KeyService {
	panic("unexpected call: GetKeyService")
}
func (c *userSvcContainer) GetCertificateService() certServices.CertificateService {
	panic("unexpected call: GetCertificateService")
}
func (c *userSvcContainer) GetCertificateRenewalService() certServices.CertificateRenewalService {
	panic("unexpected call: GetCertificateRenewalService")
}
func (c *userSvcContainer) GetCryptoService() keyServices.CryptoService {
	panic("unexpected call: GetCryptoService")
}
func (c *userSvcContainer) GetCryptographyService() secretServices.CryptographyService {
	panic("unexpected call: GetCryptographyService")
}
func (c *userSvcContainer) GetVersioningService() secretServices.VersioningServiceInterface {
	panic("unexpected call: GetVersioningService")
}
func (c *userSvcContainer) GetTagService() secretServices.TagService {
	panic("unexpected call: GetTagService")
}
func (c *userSvcContainer) GetRotationService() secretServices.RotationServiceInterface {
	panic("unexpected call: GetRotationService")
}
func (c *userSvcContainer) GetSchedulerService() secretServices.SchedulerServiceInterface {
	panic("unexpected call: GetSchedulerService")
}
func (c *userSvcContainer) GetDatabase() *sql.DB {
	panic("unexpected call: GetDatabase")
}
func (c *userSvcContainer) GetLogger() *logging.Logger {
	panic("unexpected call: GetLogger")
}
func (c *userSvcContainer) GetSecretCache() *cache.SecretCache {
	panic("unexpected call: GetSecretCache")
}
func (c *userSvcContainer) GetCacheConfig() rvconfig.CacheConfig {
	panic("unexpected call: GetCacheConfig")
}

func (c *userSvcContainer) GetVaultCache() *vaultcache.Cache {
	panic("unexpected call: GetVaultCache")
}
func (c *userSvcContainer) GetCertificateCache() *certcache.Cache {
	panic("unexpected call: GetCertificateCache")
}
func (c *userSvcContainer) GetCachedSecretService() secretServices.SecretService {
	panic("unexpected call: GetCachedSecretService")
}
func (c *userSvcContainer) GetRetryService() retryServices.RetryService {
	panic("unexpected call: GetRetryService")
}
func (c *userSvcContainer) GetKeyProvider() crypto.KeyProvider             { return nil }
func (c *userSvcContainer) GetSigningProvider() signing.SigningKeyProvider { return nil }
func (c *userSvcContainer) GetItemBackupService() *backup.ItemBackupService {
	return nil
}
func (c *userSvcContainer) GetKeyCache() keycache.Cache             { return nil }
func (c *userSvcContainer) GetCryptoMetrics() metrics.CryptoMetrics { return nil }
func (c *userSvcContainer) GetAuditService() auditServices.AuditServiceInterface {
	return nil
}
func (c *userSvcContainer) GetComplianceReportService() auditServices.ComplianceReportServiceInterface {
	return nil
}
func (c *userSvcContainer) Close() error { return nil }

// --- helpers ---

// newUserCtx builds a Context with the given claims wired to a userSvcContainer.
func newUserCtx(userSvc userServices.UserService, authSvc authServices.AuthenticationService, claims RequestClaims) *Context {
	a := &app.App{
		ServiceContainer: &userSvcContainer{userSvc: userSvc, authSvc: authSvc},
		Logger:           userTestLog(),
	}
	return &Context{
		App:    a,
		Claims: claims,
		Params: &ApiParams{PerPage: 60},
		Logger: a.Logger,
	}
}

// uAdminClaims returns claims for an admin caller with the given user_id.
func uAdminClaims(userID string) RequestClaims {
	return RequestClaims{
		Roles:  []string{model.RoleAdmin},
		UserID: userID,
	}
}

// uViewerClaims returns claims for a non-admin caller.
func uViewerClaims(userID string) RequestClaims {
	return RequestClaims{
		Roles:  []string{model.RoleUser},
		UserID: userID,
	}
}

// encodeBody marshals v to JSON and returns a bytes.Reader.
func encodeBody(v any) *bytes.Reader {
	b, _ := json.Marshal(v)
	return bytes.NewReader(b)
}

// ============================================================
// createUser
// ============================================================

func TestCreateUser_NonAdmin_Returns403(t *testing.T) {
	c := newUserCtx(nil, nil, uViewerClaims("aaa"))
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/users", encodeBody(map[string]any{
		"username": "bob", "password": "password123", "roles": []string{model.RoleUser},
	}))

	createUser(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusForbidden, w.Code)
}

func TestCreateUser_InvalidUsername_Returns400(t *testing.T) {
	c := newUserCtx(nil, nil, uAdminClaims("aaa"))
	w := httptest.NewRecorder()
	// Username shorter than 3 chars.
	r := httptest.NewRequest(http.MethodPost, "/users", encodeBody(map[string]any{
		"username": "ab", "password": "password123", "roles": []string{model.RoleUser},
	}))

	createUser(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestCreateUser_InvalidPassword_Returns400(t *testing.T) {
	c := newUserCtx(nil, nil, uAdminClaims("aaa"))
	w := httptest.NewRecorder()
	// Password shorter than 8 chars.
	r := httptest.NewRequest(http.MethodPost, "/users", encodeBody(map[string]any{
		"username": "validuser", "password": "short", "roles": []string{model.RoleUser},
	}))

	createUser(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestCreateUser_InvalidRole_Returns400(t *testing.T) {
	// Role validation now happens entirely in UserService; the handler must
	// classify the service's "invalid role" error as a 400, not a 500.
	svc := &mockUserService{}
	svc.On("CreateUser", mock.Anything, mock.Anything).
		Return(nil, errors.New("invalid role: superadmin"))

	c := newUserCtx(svc, nil, uAdminClaims("aaa"))
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/users", encodeBody(map[string]any{
		"username": "validuser", "password": "password123", "roles": []string{"superadmin"},
	}))

	createUser(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusBadRequest, w.Code)
	svc.AssertExpectations(t)
}

func TestCreateUser_NilServiceContainer_Returns500(t *testing.T) {
	// App has no service container so userSvc() returns nil.
	c := &Context{
		App:    &app.App{ServiceContainer: nil},
		Claims: uAdminClaims("aaa"),
		Params: &ApiParams{PerPage: 60},
		Logger: userTestLog(),
	}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/users", encodeBody(map[string]any{
		"username": "validuser", "password": "password123", "roles": []string{model.RoleUser},
	}))

	createUser(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestCreateUser_ServiceError_Returns500(t *testing.T) {
	svc := &mockUserService{}
	svc.On("CreateUser", mock.Anything, mock.Anything).Return(nil, errors.New("db error"))

	c := newUserCtx(svc, nil, uAdminClaims("aaa"))
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/users", encodeBody(map[string]any{
		"username": "newuser", "password": "password123", "roles": []string{model.RoleUser},
	}))

	createUser(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusInternalServerError, w.Code)
	svc.AssertExpectations(t)
}

func TestCreateUser_Success_Returns201(t *testing.T) {
	svc := &mockUserService{}
	svc.On("CreateUser", mock.Anything, mock.Anything).Return(&userServices.CreateUserResult{
		UserID:     uuid.New(),
		Username:   "newuser",
		Roles:      []string{model.RoleUser},
		TOTPSecret: "otpauth://totp/...",
		CreatedAt:  time.Now(),
	}, nil)

	c := newUserCtx(svc, nil, uAdminClaims("aaa"))
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/users", encodeBody(map[string]any{
		"username": "newuser", "password": "password123", "roles": []string{model.RoleUser},
	}))

	createUser(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusCreated, w.Code)
	svc.AssertExpectations(t)
}

func TestCreateUser_MultipleRolesInRequestBody_Accepted(t *testing.T) {
	svc := &mockUserService{}
	svc.On("CreateUser", mock.Anything, userServices.CreateUserRequest{
		Username:    "newuser",
		Password:    "pw12345678",
		Roles:       []string{"secrets_manager", "crypto_manager"},
		CallerRoles: []string{model.RoleAdmin},
	}).Return(&userServices.CreateUserResult{
		UserID:     uuid.New(),
		Username:   "newuser",
		Roles:      []string{"secrets_manager", "crypto_manager"},
		TOTPSecret: "otpauth://totp/...",
		CreatedAt:  time.Now(),
	}, nil)

	c := newUserCtx(svc, nil, uAdminClaims("aaa"))
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/users", encodeBody(map[string]any{
		"username": "newuser", "password": "pw12345678", "roles": []string{"secrets_manager", "crypto_manager"},
	}))

	createUser(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusCreated, w.Code)
	var body map[string]any
	require.NoError(t, json.NewDecoder(w.Body).Decode(&body))
	roles, ok := body["roles"].([]any)
	require.True(t, ok)
	assert.ElementsMatch(t, []any{"secrets_manager", "crypto_manager"}, roles)
	svc.AssertExpectations(t)
}

func TestCreateUser_EmptyRolesArray_Rejected(t *testing.T) {
	// An explicit "roles": [] decodes to a non-nil empty slice; UserService
	// rejects it (no role is not a valid state), and the handler must
	// surface that as a client error rather than a 500.
	svc := &mockUserService{}
	svc.On("CreateUser", mock.Anything, mock.Anything).
		Return(nil, errors.New("invalid role: at least one role is required"))

	c := newUserCtx(svc, nil, uAdminClaims("aaa"))
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/users", encodeBody(map[string]any{
		"username": "newuser", "password": "pw12345678", "roles": []string{},
	}))

	createUser(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusBadRequest, w.Code)
	svc.AssertExpectations(t)
}

func TestCreateUser_DeprecatedRoleField_Rejected(t *testing.T) {
	// The old "role" string field must be rejected outright, not silently
	// ignored -- there is no dual-field transition period for this API.
	svc := &mockUserService{}

	c := newUserCtx(svc, nil, uAdminClaims("aaa"))
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/users", encodeBody(map[string]any{
		"username": "x", "password": "password123", "role": "admin",
	}))

	createUser(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, c.Err.Message, "roles")
	svc.AssertNotCalled(t, "CreateUser", mock.Anything, mock.Anything)
}

// ============================================================
// listUsers
// ============================================================

func TestListUsers_NonAdmin_Returns403(t *testing.T) {
	c := newUserCtx(nil, nil, uViewerClaims("aaa"))
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/users", nil)

	listUsers(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusForbidden, w.Code)
}

func TestListUsers_NilServiceContainer_Returns500(t *testing.T) {
	c := &Context{
		App:    &app.App{ServiceContainer: nil},
		Claims: uAdminClaims("aaa"),
		Params: &ApiParams{PerPage: 60},
		Logger: userTestLog(),
	}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/users", nil)

	listUsers(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestListUsers_ServiceError_Returns500(t *testing.T) {
	svc := &mockUserService{}
	svc.On("ListUsers", mock.Anything).Return([]model.User{}, errors.New("db error"))

	c := newUserCtx(svc, nil, uAdminClaims("aaa"))
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/users", nil)

	listUsers(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusInternalServerError, w.Code)
	svc.AssertExpectations(t)
}

func TestListUsers_Success_Returns200(t *testing.T) {
	svc := &mockUserService{}
	users := []model.User{
		{ID: uuid.New(), Username: "alice", Roles: []string{model.RoleAdmin}, CreatedAt: time.Now()},
		{ID: uuid.New(), Username: "bob", Roles: []string{model.RoleUser}, CreatedAt: time.Now()},
	}
	svc.On("ListUsers", mock.Anything).Return(users, nil)

	c := newUserCtx(svc, nil, uAdminClaims("aaa"))
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/users", nil)

	listUsers(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusOK, w.Code)
	var body map[string]any
	require.NoError(t, json.NewDecoder(w.Body).Decode(&body))
	assert.Equal(t, float64(2), body["total"])
	svc.AssertExpectations(t)
}

// TestListUsers_MultiRoleAdmin_Allowed verifies a caller holding admin
// alongside other roles still passes the admin gate -- the exact regression
// class the whole feature exists to fix (a multi-role admin silently losing
// access under the old strict-equality check).
func TestListUsers_MultiRoleAdmin_Allowed(t *testing.T) {
	svc := &mockUserService{}
	users := []model.User{
		{ID: uuid.New(), Username: "alice", Roles: []string{model.RoleAdmin}, CreatedAt: time.Now()},
	}
	svc.On("ListUsers", mock.Anything).Return(users, nil)

	c := newUserCtx(svc, nil, RequestClaims{
		UserID: "aaa",
		Roles:  []string{"secrets_manager", model.RoleAdmin},
	})
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/users", nil)

	listUsers(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusOK, w.Code)
	svc.AssertExpectations(t)
}

func TestListUsers_PaginationBeyondEnd_Returns200EmptyPage(t *testing.T) {
	svc := &mockUserService{}
	users := []model.User{
		{ID: uuid.New(), Username: "alice", Roles: []string{model.RoleAdmin}, CreatedAt: time.Now()},
	}
	svc.On("ListUsers", mock.Anything).Return(users, nil)

	c := newUserCtx(svc, nil, uAdminClaims("aaa"))
	// Request page 10 when only 1 user exists — offset will exceed total.
	c.Params = &ApiParams{Page: 10, PerPage: 60}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/users?page=10", nil)

	listUsers(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusOK, w.Code)
	var body map[string]any
	require.NoError(t, json.NewDecoder(w.Body).Decode(&body))
	// Total reflects the full count, not the empty page.
	assert.Equal(t, float64(1), body["total"])
	svc.AssertExpectations(t)
}

// ============================================================
// getUser
// ============================================================

func TestGetUser_InvalidUserID_Returns400(t *testing.T) {
	c := newUserCtx(nil, nil, uAdminClaims("aaa"))
	c.Params = &ApiParams{UserID: "not-a-uuid", PerPage: 60}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/users/not-a-uuid", nil)

	getUser(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestGetUser_NonAdminAccessingOtherUser_Returns403(t *testing.T) {
	targetID := uuid.New()
	c := newUserCtx(nil, nil, uViewerClaims("different-id"))
	c.Params = &ApiParams{UserID: targetID.String(), PerPage: 60}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/users/"+targetID.String(), nil)

	getUser(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusForbidden, w.Code)
}

// TestGetUser_MultiRoleNonAdmin_CanOnlyAccessOwnProfile verifies a caller
// holding several non-admin roles is still denied access to another user's
// profile -- multi-role support must not accidentally widen non-admin access.
func TestGetUser_MultiRoleNonAdmin_CanOnlyAccessOwnProfile(t *testing.T) {
	targetID := uuid.New()
	c := newUserCtx(nil, nil, RequestClaims{
		UserID: "different-id",
		Roles:  []string{"secrets_manager", "crypto_manager"},
	})
	c.Params = &ApiParams{UserID: targetID.String(), PerPage: 60}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/users/"+targetID.String(), nil)

	getUser(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusForbidden, w.Code)
}

func TestGetUser_NotFound_Returns404(t *testing.T) {
	svc := &mockUserService{}
	targetID := uuid.New()
	svc.On("GetUser", mock.Anything, targetID).Return(nil, errors.New("not found"))

	c := newUserCtx(svc, nil, uAdminClaims("aaa"))
	c.Params = &ApiParams{UserID: targetID.String(), PerPage: 60}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/users/"+targetID.String(), nil)

	getUser(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusNotFound, w.Code)
	svc.AssertExpectations(t)
}

func TestGetUser_Success_Returns200(t *testing.T) {
	svc := &mockUserService{}
	targetID := uuid.New()
	svc.On("GetUser", mock.Anything, targetID).Return(&model.User{
		ID: targetID, Username: "alice", Roles: []string{model.RoleAdmin}, CreatedAt: time.Now(),
	}, nil)

	c := newUserCtx(svc, nil, uAdminClaims("aaa"))
	c.Params = &ApiParams{UserID: targetID.String(), PerPage: 60}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/users/"+targetID.String(), nil)

	getUser(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusOK, w.Code)
	svc.AssertExpectations(t)
}

// ============================================================
// updateUser
// ============================================================

func TestUpdateUser_InvalidUserID_Returns400(t *testing.T) {
	c := newUserCtx(nil, nil, uAdminClaims("aaa"))
	c.Params = &ApiParams{UserID: "bad", PerPage: 60}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPut, "/users/bad", encodeBody(map[string]string{"username": "newname"}))

	updateUser(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestUpdateUser_ShortUsername_Returns400(t *testing.T) {
	targetID := uuid.New()
	c := newUserCtx(nil, nil, uAdminClaims("aaa"))
	c.Params = &ApiParams{UserID: targetID.String(), PerPage: 60}
	w := httptest.NewRecorder()
	// Only 2 chars — below the 3-char minimum.
	r := httptest.NewRequest(http.MethodPut, "/users/"+targetID.String(), encodeBody(map[string]string{"username": "ab"}))

	updateUser(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestUpdateUser_ShortPassword_Returns400(t *testing.T) {
	targetID := uuid.New()
	c := newUserCtx(nil, nil, uAdminClaims("aaa"))
	c.Params = &ApiParams{UserID: targetID.String(), PerPage: 60}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPut, "/users/"+targetID.String(), encodeBody(map[string]string{"password": "short"}))

	updateUser(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestUpdateUser_NonAdminChangingRole_Returns403(t *testing.T) {
	targetID := uuid.New()
	// Non-admin targeting their own account but trying to change role.
	c := newUserCtx(nil, nil, uViewerClaims(targetID.String()))
	c.Params = &ApiParams{UserID: targetID.String(), PerPage: 60}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPut, "/users/"+targetID.String(), encodeBody(map[string]any{"roles": []string{model.RoleAdmin}}))

	updateUser(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusForbidden, w.Code)
}

func TestUpdateUser_NonAdminUpdatingOtherUser_Returns403(t *testing.T) {
	targetID := uuid.New()
	// Non-admin targeting a different user's account.
	c := newUserCtx(nil, nil, uViewerClaims("different-caller-id"))
	c.Params = &ApiParams{UserID: targetID.String(), PerPage: 60}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPut, "/users/"+targetID.String(), encodeBody(map[string]string{"username": "newname"}))

	updateUser(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusForbidden, w.Code)
}

func TestUpdateUser_ServiceError_Returns500(t *testing.T) {
	svc := &mockUserService{}
	targetID := uuid.New()
	svc.On("UpdateUser", mock.Anything, mock.Anything).Return(nil, errors.New("db error"))

	c := newUserCtx(svc, nil, uAdminClaims("aaa"))
	c.Params = &ApiParams{UserID: targetID.String(), PerPage: 60}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPut, "/users/"+targetID.String(), encodeBody(map[string]string{"username": "newname"}))

	updateUser(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusInternalServerError, w.Code)
	svc.AssertExpectations(t)
}

func TestUpdateUser_Success_Returns200(t *testing.T) {
	svc := &mockUserService{}
	targetID := uuid.New()
	svc.On("UpdateUser", mock.Anything, mock.Anything).Return(&userServices.UpdateUserResult{}, nil)
	svc.On("GetUser", mock.Anything, targetID).Return(&model.User{
		ID: targetID, Username: "newname", Roles: []string{model.RoleAdmin}, CreatedAt: time.Now(),
	}, nil)

	c := newUserCtx(svc, nil, uAdminClaims("aaa"))
	c.Params = &ApiParams{UserID: targetID.String(), PerPage: 60}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPut, "/users/"+targetID.String(), encodeBody(map[string]string{"username": "newname"}))

	updateUser(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusOK, w.Code)
	svc.AssertExpectations(t)
}

// A password set that enrolls TOTP must hand the otpauth URL back once.
func TestUpdateUser_PasswordEnrollment_ReturnsTOTPURL(t *testing.T) {
	svc := &mockUserService{}
	targetID := uuid.New()
	enrollURL := "otpauth://totp/PasswordManager:alice?secret=ABC"
	svc.On("UpdateUser", mock.Anything, mock.MatchedBy(func(req userServices.UpdateUserRequest) bool {
		return req.Password != nil && *req.Password == "newpass123"
	})).Return(&userServices.UpdateUserResult{TOTPEnrollmentURL: enrollURL}, nil)
	svc.On("GetUser", mock.Anything, targetID).Return(&model.User{
		ID: targetID, Username: "alice", Roles: []string{model.RoleUser}, CreatedAt: time.Now(),
	}, nil)

	c := newUserCtx(svc, nil, uViewerClaims(targetID.String()))
	c.Params = &ApiParams{UserID: targetID.String(), PerPage: 60}
	w := httptest.NewRecorder()
	r := httptest.NewRequestWithContext(context.Background(), http.MethodPut, "/users/"+targetID.String(), encodeBody(map[string]string{"password": "newpass123"}))

	updateUser(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	require.Equal(t, http.StatusOK, w.Code)
	// The body carries a TOTP secret, so no cache may keep it.
	assert.Equal(t, "no-store", w.Header().Get("Cache-Control"))
	var body model.UserResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
	assert.Equal(t, enrollURL, body.TOTPSecret)
}

// An update that enrolls nothing must not carry a totp_secret field at all.
func TestUpdateUser_NoEnrollment_OmitsTOTPSecret(t *testing.T) {
	svc := &mockUserService{}
	targetID := uuid.New()
	svc.On("UpdateUser", mock.Anything, mock.Anything).Return(&userServices.UpdateUserResult{}, nil)
	svc.On("GetUser", mock.Anything, targetID).Return(&model.User{
		ID: targetID, Username: "alice", Roles: []string{model.RoleUser}, TOTPSecret: "STOREDSECRET", CreatedAt: time.Now(),
	}, nil)

	c := newUserCtx(svc, nil, uViewerClaims(targetID.String()))
	c.Params = &ApiParams{UserID: targetID.String(), PerPage: 60}
	w := httptest.NewRecorder()
	r := httptest.NewRequestWithContext(context.Background(), http.MethodPut, "/users/"+targetID.String(), encodeBody(map[string]string{"password": "newpass123"}))

	updateUser(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	require.Equal(t, http.StatusOK, w.Code)
	assert.NotContains(t, w.Body.String(), "totp_secret")
	assert.NotContains(t, w.Body.String(), "STOREDSECRET")
}

// enrollRouteContainer allows every endpoint, so the real route and its
// ApiSessionRequired wrapper can be exercised end to end.
type enrollRouteContainer struct {
	userSvcContainer
}

func (c *enrollRouteContainer) GetRBACService() authzServices.RBACService {
	return permissiveRBAC{}
}

// The enrollment response must be marked no-store on the real
// PUT /api/v1/users/{id} route, not only when the handler is called directly.
// The container uses permissiveRBAC, so this role:user caller reaches the
// handler. Production RBAC maps PUT /users/* to users:update, which only the
// admin role holds, so a non-admin is denied before the handler runs; see
// TestUpdateUserRoute_PasswordEnrollment_RealRBAC for both cases.
func TestUpdateUserRoute_PasswordEnrollment_NoStore(t *testing.T) {
	svc := &mockUserService{}
	targetID := uuid.New()
	enrollURL := "otpauth://totp/PasswordManager:alice?secret=ABC"
	svc.On("UpdateUser", mock.Anything, mock.Anything).
		Return(&userServices.UpdateUserResult{TOTPEnrollmentURL: enrollURL}, nil)
	svc.On("GetUser", mock.Anything, targetID).Return(&model.User{
		ID: targetID, Username: "alice", Roles: []string{model.RoleUser}, CreatedAt: time.Now(),
	}, nil)

	application := &app.App{
		ServiceContainer: &enrollRouteContainer{userSvcContainer{userSvc: svc}},
		Logger:           userTestLog(),
	}
	router := mux.NewRouter()
	a := &API{App: application, BaseRoutes: &Routes{Users: router.PathPrefix("/api/v1/users").Subrouter()}}
	a.InitUsers()

	ctx := context.WithValue(context.Background(), common.UserIDKey, targetID.String())
	ctx = context.WithValue(ctx, common.RoleKey, []string{model.RoleUser})
	r := httptest.NewRequestWithContext(ctx, http.MethodPut, "/api/v1/users/"+targetID.String(),
		encodeBody(map[string]string{"password": "newpass123"}))
	w := httptest.NewRecorder()
	router.ServeHTTP(w, r)

	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	assert.Equal(t, "no-store", w.Header().Get("Cache-Control"))
	var body model.UserResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
	assert.Equal(t, enrollURL, body.TOTPSecret)
	svc.AssertExpectations(t)
}

// realRBACRouteContainer uses the production role-permission map.
type realRBACRouteContainer struct {
	userSvcContainer
}

func (c *realRBACRouteContainer) GetRBACService() authzServices.RBACService {
	return authzServices.NewRBACService(userTestLog())
}

// With production RBAC an admin setting another user's password gets the
// enrollment URL with no-store, and a role:user caller never reaches the handler.
func TestUpdateUserRoute_PasswordEnrollment_RealRBAC(t *testing.T) {
	enrollURL := "otpauth://totp/PasswordManager:alice?secret=ABC"

	cases := []struct {
		name       string
		roles      []string
		wantStatus int
	}{
		{name: "admin", roles: []string{model.RoleAdmin}, wantStatus: http.StatusOK},
		{name: "user", roles: []string{model.RoleUser}, wantStatus: http.StatusForbidden},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			svc := &mockUserService{}
			targetID := uuid.New()
			svc.On("UpdateUser", mock.Anything, mock.Anything).
				Return(&userServices.UpdateUserResult{TOTPEnrollmentURL: enrollURL}, nil)
			svc.On("GetUser", mock.Anything, targetID).Return(&model.User{
				ID: targetID, Username: "alice", Roles: []string{model.RoleUser}, CreatedAt: time.Now(),
			}, nil)

			application := &app.App{
				ServiceContainer: &realRBACRouteContainer{userSvcContainer{userSvc: svc}},
				Logger:           userTestLog(),
			}
			router := mux.NewRouter()
			a := &API{App: application, BaseRoutes: &Routes{Users: router.PathPrefix("/api/v1/users").Subrouter()}}
			a.InitUsers()

			// The admin updates someone else; the user updates their own account.
			callerID := targetID.String()
			if tc.name == "admin" {
				callerID = uuid.New().String()
			}
			ctx := context.WithValue(context.Background(), common.UserIDKey, callerID)
			ctx = context.WithValue(ctx, common.RoleKey, tc.roles)
			r := httptest.NewRequestWithContext(ctx, http.MethodPut, "/api/v1/users/"+targetID.String(),
				encodeBody(map[string]string{"password": "newpass123"}))
			w := httptest.NewRecorder()
			router.ServeHTTP(w, r)

			require.Equal(t, tc.wantStatus, w.Code, w.Body.String())
			if tc.wantStatus != http.StatusOK {
				svc.AssertNotCalled(t, "UpdateUser", mock.Anything, mock.Anything)
				return
			}
			assert.Equal(t, "no-store", w.Header().Get("Cache-Control"))
			var body model.UserResponse
			require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
			assert.Equal(t, enrollURL, body.TOTPSecret)
		})
	}
}

// When the update enrolled TOTP but the read-back fails, the one-time URL must
// still reach the caller. The body is built from the request instead, and the
// URL never appears in the log.
func TestUpdateUser_PasswordEnrollment_GetUserFails_StillReturnsURL(t *testing.T) {
	svc := &mockUserService{}
	targetID := uuid.New()
	enrollURL := "otpauth://totp/PasswordManager:alice?secret=ABC"
	svc.On("UpdateUser", mock.Anything, mock.Anything).
		Return(&userServices.UpdateUserResult{TOTPEnrollmentURL: enrollURL}, nil)
	svc.On("GetUser", mock.Anything, targetID).Return(nil, errors.New("database is locked"))

	c := newUserCtx(svc, nil, uViewerClaims(targetID.String()))
	c.Params = &ApiParams{UserID: targetID.String(), PerPage: 60}
	var logBuf bytes.Buffer
	c.Logger.SetOutput(&logBuf)
	w := httptest.NewRecorder()
	r := httptest.NewRequestWithContext(context.Background(), http.MethodPut, "/users/"+targetID.String(),
		encodeBody(map[string]string{"password": "newpass123"}))

	updateUser(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	assert.Equal(t, "no-store", w.Header().Get("Cache-Control"))
	var body model.UserResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
	assert.Equal(t, enrollURL, body.TOTPSecret)
	assert.Equal(t, targetID.String(), body.ID)
	assert.NotContains(t, w.Body.String(), "database is locked")
	// The read failure is logged server-side, and the secret is not.
	assert.Contains(t, logBuf.String(), "database is locked")
	assert.NotContains(t, logBuf.String(), "secret=ABC")
}

// Without an enrollment URL a failed read-back stays a plain 500.
func TestUpdateUser_NoEnrollment_GetUserFails_Returns500(t *testing.T) {
	svc := &mockUserService{}
	targetID := uuid.New()
	svc.On("UpdateUser", mock.Anything, mock.Anything).Return(&userServices.UpdateUserResult{}, nil)
	svc.On("GetUser", mock.Anything, targetID).Return(nil, errors.New("database is locked"))

	c := newUserCtx(svc, nil, uViewerClaims(targetID.String()))
	c.Params = &ApiParams{UserID: targetID.String(), PerPage: 60}
	w := httptest.NewRecorder()
	r := httptest.NewRequestWithContext(context.Background(), http.MethodPut, "/users/"+targetID.String(),
		encodeBody(map[string]string{"password": "newpass123"}))

	updateUser(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusInternalServerError, w.Code)
	assert.NotContains(t, w.Body.String(), "database is locked")
}

func TestUpdateUser_DeprecatedRoleField_Rejected(t *testing.T) {
	// The old "role" string field must be rejected outright, not silently
	// ignored -- there is no dual-field transition period for this API.
	targetID := uuid.New()
	svc := &mockUserService{}

	c := newUserCtx(svc, nil, uAdminClaims("aaa"))
	c.Params = &ApiParams{UserID: targetID.String(), PerPage: 60}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPut, "/users/"+targetID.String(), encodeBody(map[string]any{"role": "admin"}))

	updateUser(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, c.Err.Message, "roles")
	svc.AssertNotCalled(t, "UpdateUser", mock.Anything, mock.Anything)
}

// ============================================================
// deleteUser
// ============================================================

func TestDeleteUser_NonAdmin_Returns403(t *testing.T) {
	c := newUserCtx(nil, nil, uViewerClaims("aaa"))
	c.Params = &ApiParams{UserID: uuid.New().String(), PerPage: 60}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodDelete, "/users/"+uuid.New().String(), nil)

	deleteUser(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusForbidden, w.Code)
}

func TestDeleteUser_InvalidUserID_Returns400(t *testing.T) {
	c := newUserCtx(nil, nil, uAdminClaims("aaa"))
	c.Params = &ApiParams{UserID: "not-a-uuid", PerPage: 60}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodDelete, "/users/not-a-uuid", nil)

	deleteUser(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestDeleteUser_SelfDeletion_Returns400(t *testing.T) {
	selfID := uuid.New().String()
	c := newUserCtx(nil, nil, uAdminClaims(selfID))
	c.Params = &ApiParams{UserID: selfID, PerPage: 60}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodDelete, "/users/"+selfID, nil)

	deleteUser(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestDeleteUser_UserNotFound_Returns404(t *testing.T) {
	svc := &mockUserService{}
	targetID := uuid.New()
	svc.On("GetUser", mock.Anything, targetID).Return(nil, errors.New("not found"))

	c := newUserCtx(svc, nil, uAdminClaims("aaa"))
	c.Params = &ApiParams{UserID: targetID.String(), PerPage: 60}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodDelete, "/users/"+targetID.String(), nil)

	deleteUser(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusNotFound, w.Code)
	svc.AssertExpectations(t)
}

func TestDeleteUser_DeleteError_Returns500(t *testing.T) {
	svc := &mockUserService{}
	targetID := uuid.New()
	svc.On("GetUser", mock.Anything, targetID).Return(&model.User{
		ID: targetID, Username: "target", CreatedAt: time.Now(),
	}, nil)
	svc.On("DeleteUser", mock.Anything, targetID).Return(errors.New("db error"))

	c := newUserCtx(svc, nil, uAdminClaims("aaa"))
	c.Params = &ApiParams{UserID: targetID.String(), PerPage: 60}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodDelete, "/users/"+targetID.String(), nil)

	deleteUser(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusInternalServerError, w.Code)
	svc.AssertExpectations(t)
}

func TestDeleteUser_Success_Returns200(t *testing.T) {
	svc := &mockUserService{}
	targetID := uuid.New()
	svc.On("GetUser", mock.Anything, targetID).Return(&model.User{
		ID: targetID, Username: "target", CreatedAt: time.Now(),
	}, nil)
	svc.On("DeleteUser", mock.Anything, targetID).Return(nil)

	c := newUserCtx(svc, nil, uAdminClaims("aaa"))
	c.Params = &ApiParams{UserID: targetID.String(), PerPage: 60}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodDelete, "/users/"+targetID.String(), nil)

	deleteUser(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusOK, w.Code)
	svc.AssertExpectations(t)
}

// ============================================================
// loginUser
// ============================================================

func TestLoginUser_MissingFields_Returns400(t *testing.T) {
	c := newUserCtx(nil, nil, RequestClaims{})
	w := httptest.NewRecorder()
	// Missing totp_code field.
	r := httptest.NewRequest(http.MethodPost, "/users/login", encodeBody(map[string]string{
		"username": "alice", "password": "pass1234",
	}))

	loginUser(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestLoginUser_AuthFailure_Returns403(t *testing.T) {
	authSvc := &mockAuthService{}
	authSvc.On("AuthenticateUser", mock.Anything, "alice", "wrong", "123456").
		Return(nil, errors.New("invalid credentials"))

	c := newUserCtx(nil, authSvc, RequestClaims{})
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/users/login", encodeBody(map[string]string{
		"username": "alice", "password": "wrong", "totp_code": "123456",
	}))

	loginUser(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusForbidden, w.Code)
	authSvc.AssertExpectations(t)
}

func TestLoginUser_Success_Returns200(t *testing.T) {
	authSvc := &mockAuthService{}
	authSvc.On("AuthenticateUser", mock.Anything, "alice", "goodpass", "123456").
		Return(&authServices.AuthenticationResult{
			Token:        "tok",
			RefreshToken: "rtok",
			UserID:       uuid.New(),
			Username:     "alice",
			Roles:        []string{model.RoleAdmin},
		}, nil)

	c := newUserCtx(nil, authSvc, RequestClaims{})
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/users/login", encodeBody(map[string]string{
		"username": "alice", "password": "goodpass", "totp_code": "123456",
	}))

	loginUser(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusOK, w.Code)
	// The body carries tokens, so no cache may keep it.
	assert.Equal(t, "no-store", w.Header().Get("Cache-Control"))
	var body map[string]any
	require.NoError(t, json.NewDecoder(w.Body).Decode(&body))
	assert.Equal(t, "tok", body["token"])
	authSvc.AssertExpectations(t)
}

// ============================================================
// refreshToken
// ============================================================

func TestRefreshToken_MissingToken_Returns400(t *testing.T) {
	c := newUserCtx(nil, nil, RequestClaims{})
	w := httptest.NewRecorder()
	// refresh_token is empty string.
	r := httptest.NewRequest(http.MethodPost, "/users/refresh", encodeBody(map[string]string{}))

	refreshToken(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestRefreshToken_RefreshFailure_Returns403(t *testing.T) {
	authSvc := &mockAuthService{}
	authSvc.On("RefreshAccessToken", mock.Anything, "badtoken").
		Return(nil, errors.New("token invalid"))

	c := newUserCtx(nil, authSvc, RequestClaims{})
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/users/refresh", encodeBody(map[string]string{
		"refresh_token": "badtoken",
	}))

	refreshToken(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusForbidden, w.Code)
	authSvc.AssertExpectations(t)
}

func TestRefreshToken_Success_Returns200(t *testing.T) {
	authSvc := &mockAuthService{}
	authSvc.On("RefreshAccessToken", mock.Anything, "validtoken").
		Return(&authServices.RefreshTokenResult{
			Token:        "newtok",
			RefreshToken: "newrtok",
			UserID:       uuid.New(),
			Username:     "alice",
			Roles:        []string{model.RoleAdmin},
			ExpiresAt:    time.Now().Add(time.Hour),
		}, nil)

	c := newUserCtx(nil, authSvc, RequestClaims{})
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/users/refresh", encodeBody(map[string]string{
		"refresh_token": "validtoken",
	}))

	refreshToken(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusOK, w.Code)
	// The body carries tokens, so no cache may keep it.
	assert.Equal(t, "no-store", w.Header().Get("Cache-Control"))
	authSvc.AssertExpectations(t)
}

// ============================================================
// listUserSessions
// ============================================================

func TestListUserSessions_MissingUserIDInClaims_Returns400(t *testing.T) {
	// A zero-value RequestClaims has UserID == "", which fails uuid.Parse the
	// same way an invalid UUID does — there is no separate "missing" state.
	c := newUserCtx(nil, nil, RequestClaims{})
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/users/sessions", nil)

	listUserSessions(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestListUserSessions_InvalidUUIDInClaims_Returns400(t *testing.T) {
	c := newUserCtx(nil, nil, RequestClaims{UserID: "not-a-uuid"})
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/users/sessions", nil)

	listUserSessions(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestListUserSessions_Success_Returns200(t *testing.T) {
	authSvc := &mockAuthService{}
	userID := uuid.New()
	authSvc.On("ListActiveSessions", mock.Anything, userID).Return([]*model.Session{}, nil)

	c := newUserCtx(nil, authSvc, RequestClaims{UserID: userID.String()})
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/users/sessions", nil)

	listUserSessions(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusOK, w.Code)
	authSvc.AssertExpectations(t)
}

// ============================================================
// revokeSession
// ============================================================

func TestRevokeSession_Success_Returns200(t *testing.T) {
	authSvc := &mockAuthService{}
	sessionID := uuid.New().String()
	callerID := uuid.New()
	authSvc.On("RevokeSession", mock.Anything, authServices.RevokeSessionRequest{
		SessionID: sessionID, CallerID: callerID, CallerRoles: []string{model.RoleUser}, Reason: "User requested revocation",
	}).Return(nil)

	c := newUserCtx(nil, authSvc, uViewerClaims(callerID.String()))
	c.Params = &ApiParams{SessionID: sessionID, PerPage: 60}
	w := httptest.NewRecorder()
	r := httptest.NewRequestWithContext(context.Background(), http.MethodDelete, "/users/sessions/"+sessionID, nil)

	revokeSession(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusOK, w.Code)
	authSvc.AssertExpectations(t)
}

// An admin caller's roles reach the service so it can apply the admin bypass.
func TestRevokeSession_Admin_PassesRoles(t *testing.T) {
	authSvc := &mockAuthService{}
	sessionID := uuid.New().String()
	callerID := uuid.New()
	authSvc.On("RevokeSession", mock.Anything, authServices.RevokeSessionRequest{
		SessionID: sessionID, CallerID: callerID, CallerRoles: []string{model.RoleAdmin}, Reason: "User requested revocation",
	}).Return(nil)

	c := newUserCtx(nil, authSvc, RequestClaims{UserID: callerID.String(), Roles: []string{model.RoleAdmin}})
	c.Params = &ApiParams{SessionID: sessionID, PerPage: 60}
	w := httptest.NewRecorder()
	r := httptest.NewRequestWithContext(context.Background(), http.MethodDelete, "/users/sessions/"+sessionID, nil)

	revokeSession(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusOK, w.Code)
	authSvc.AssertExpectations(t)
}

// Revoking another user's session must look exactly like revoking a missing one.
func TestRevokeSession_OtherUsersSession_Returns404(t *testing.T) {
	authSvc := &mockAuthService{}
	sessionID := uuid.New().String()
	callerID := uuid.New()
	authSvc.On("RevokeSession", mock.Anything, mock.Anything).
		Return(fmt.Errorf("revoke session %s: %w", sessionID, authServices.ErrSessionNotFound))

	c := newUserCtx(nil, authSvc, uViewerClaims(callerID.String()))
	c.Params = &ApiParams{SessionID: sessionID, PerPage: 60}
	w := httptest.NewRecorder()
	r := httptest.NewRequestWithContext(context.Background(), http.MethodDelete, "/users/sessions/"+sessionID, nil)

	revokeSession(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusNotFound, w.Code)
	authSvc.AssertExpectations(t)
}

func TestRevokeSession_InvalidCallerID_Returns400(t *testing.T) {
	authSvc := &mockAuthService{}
	sessionID := uuid.New().String()

	c := newUserCtx(nil, authSvc, RequestClaims{UserID: "not-a-uuid"})
	c.Params = &ApiParams{SessionID: sessionID, PerPage: 60}
	w := httptest.NewRecorder()
	r := httptest.NewRequestWithContext(context.Background(), http.MethodDelete, "/users/sessions/"+sessionID, nil)

	revokeSession(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusBadRequest, w.Code)
	authSvc.AssertNotCalled(t, "RevokeSession", mock.Anything, mock.Anything)
}

func TestRevokeSession_Error_Returns500(t *testing.T) {
	authSvc := &mockAuthService{}
	sessionID := uuid.New().String()
	authSvc.On("RevokeSession", mock.Anything, mock.Anything).Return(errors.New("db error"))

	c := newUserCtx(nil, authSvc, uViewerClaims(uuid.New().String()))
	c.Params = &ApiParams{SessionID: sessionID, PerPage: 60}
	w := httptest.NewRecorder()
	r := httptest.NewRequestWithContext(context.Background(), http.MethodDelete, "/users/sessions/"+sessionID, nil)

	revokeSession(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusInternalServerError, w.Code)
	authSvc.AssertExpectations(t)
}

// ============================================================
// revokeAllSessions
// ============================================================

func TestRevokeAllSessions_MissingUserID_Returns400(t *testing.T) {
	// A zero-value RequestClaims has UserID == "", which fails uuid.Parse the
	// same way an invalid UUID does — there is no separate "missing" state.
	c := newUserCtx(nil, nil, RequestClaims{})
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodDelete, "/users/sessions", nil)

	revokeAllSessions(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestRevokeAllSessions_RevokeError_Returns500(t *testing.T) {
	authSvc := &mockAuthService{}
	userID := uuid.New()
	authSvc.On("RevokeAllUserSessions", mock.Anything, userID, "User requested revocation of all sessions").
		Return(errors.New("db error"))

	c := newUserCtx(nil, authSvc, RequestClaims{UserID: userID.String()})
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodDelete, "/users/sessions", nil)

	revokeAllSessions(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusInternalServerError, w.Code)
	authSvc.AssertExpectations(t)
}

func TestRevokeAllSessions_Success_Returns200(t *testing.T) {
	authSvc := &mockAuthService{}
	userID := uuid.New()
	authSvc.On("RevokeAllUserSessions", mock.Anything, userID, "User requested revocation of all sessions").
		Return(nil)

	c := newUserCtx(nil, authSvc, RequestClaims{UserID: userID.String()})
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodDelete, "/users/sessions", nil)

	revokeAllSessions(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusOK, w.Code)
	authSvc.AssertExpectations(t)
}
