package testutils

import (
	"context"
	"database/sql"
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/mock"

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
	"rocketvault/model"
)

// TestContext holds common test utilities and mocks
type TestContext struct {
	Ctx                       context.Context
	MockContainer             *MockServiceContainer
	MockUserService           *MockUserService
	MockSecretService         *MockSecretService
	MockAuthService           *MockAuthenticationService
	MockRBACService           *MockRBACService
	MockVaultService          *MockVaultService
	MockRoleAssignmentService *MockRoleAssignmentService
	MockAccessPolicyService   *MockAccessPolicyService
	TestUserID                uuid.UUID
	TestVaultID               uuid.UUID
	Logger                    *logging.Logger
}

// NewTestContext creates a new test context with mocks
func NewTestContext(t *testing.T) *TestContext {
	testUserID := uuid.New()
	logger := &logging.Logger{Logger: logrus.New()}

	// Create mocks
	mockContainer := &MockServiceContainer{}
	mockUserService := &MockUserService{}
	mockSecretService := &MockSecretService{}
	mockAuthService := &MockAuthenticationService{}
	mockRBACService := &MockRBACService{}
	mockVaultService := &MockVaultService{}

	// The default vault resolves so vault-aware resource commands work in tests.
	testVaultID := uuid.MustParse(model.DefaultVaultID)
	defaultVault := &model.Vault{
		ID:      testVaultID,
		Name:    model.DefaultVaultName,
		Enabled: true,
	}
	mockVaultService.On("GetVault", mock.Anything, model.DefaultVaultName).
		Return(defaultVault, nil).Maybe()

	// Default to allowing every data action, so vault-authorization checks
	// added to CLI commands don't break every pre-existing test that doesn't
	// care about them. Tests exercising the deny path replace this field with
	// a fresh instance.
	mockRoleAssignmentService := &MockRoleAssignmentService{}
	mockRoleAssignmentService.On("HasDataAction", mock.Anything, mock.Anything, mock.Anything, mock.Anything).
		Return(true, nil).Maybe()

	// Default to allowing every access-policy check, so vault-authorization
	// checks added to CLI commands don't break every pre-existing test that
	// doesn't care about them. Tests exercising the deny path replace this
	// field with a fresh instance.
	mockAccessPolicyService := &MockAccessPolicyService{}
	mockAccessPolicyService.On("CheckAccess", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).
		Return(authzServices.AccessAllowed, nil).Maybe()

	// Setup mock container to return mock services
	mockContainer.On("GetUserService").Return(mockUserService)
	mockContainer.On("GetSecretService").Return(mockSecretService)
	mockContainer.On("GetAuthenticationService").Return(mockAuthService)
	mockContainer.On("GetRBACService").Return(mockRBACService)
	mockContainer.On("GetLogger").Return(logger)
	mockContainer.On("Close").Return(nil)
	mockContainer.VaultService = mockVaultService
	mockContainer.RoleAssignmentService = mockRoleAssignmentService
	mockContainer.AccessPolicyService = mockAccessPolicyService

	// Create test claims for authentication
	testClaims := &model.Claims{
		UserID:   testUserID,
		Username: "testuser",
		Roles:    []string{model.RoleAdmin},
	}

	// Create context with service container and authentication
	ctx := context.Background()
	ctx = context.WithValue(ctx, common.ServiceContainerKey, mockContainer)
	ctx = context.WithValue(ctx, common.UserIDKey, testUserID)
	ctx = context.WithValue(ctx, common.ClaimsKey, testClaims)
	ctx = context.WithValue(ctx, common.LogKey, logger)

	return &TestContext{
		Ctx:                       ctx,
		MockContainer:             mockContainer,
		MockUserService:           mockUserService,
		MockSecretService:         mockSecretService,
		MockAuthService:           mockAuthService,
		MockRBACService:           mockRBACService,
		MockVaultService:          mockVaultService,
		MockRoleAssignmentService: mockRoleAssignmentService,
		MockAccessPolicyService:   mockAccessPolicyService,
		TestUserID:                testUserID,
		TestVaultID:               testVaultID,
		Logger:                    logger,
	}
}

// CreateTestCommand creates a command with test context
func (tc *TestContext) CreateTestCommand(cmd *cobra.Command) *cobra.Command {
	cmd.SetContext(tc.Ctx)
	return cmd
}

// Mock Service Container implements ServiceContainerInterface for testing
type MockServiceContainer struct {
	mock.Mock
	// VaultService is returned by GetVaultService. It defaults to a MockVaultService
	// that resolves the "default" vault so vault-aware resource commands work in tests.
	VaultService vaultServices.VaultService
	// VaultWebhookService is returned by GetVaultWebhookService, nil by default.
	VaultWebhookService vaultServices.VaultWebhookService
	// AccessPolicyService is returned by GetAccessPolicyService, nil by default.
	AccessPolicyService authzServices.AccessPolicyService
	// RoleAssignmentService is returned by GetRoleAssignmentService. It defaults to a
	// MockRoleAssignmentService that allows every action, so vault-authorization checks
	// added to CLI commands don't break every pre-existing test that doesn't care about
	// them. Tests exercising the deny path replace this field with a fresh instance.
	RoleAssignmentService authzServices.RoleAssignmentService
	// GrantService is returned by GetGrantService, nil by default.
	GrantService provisioning.GrantService
}

// Repository getters - return nil for unused repositories
func (m *MockServiceContainer) GetUserRepository() repositories.UserRepositoryInterface {
	return nil
}

func (m *MockServiceContainer) GetSecretRepository() repositories.SecretRepositoryInterface {
	return nil
}

func (m *MockServiceContainer) GetRotationRepository() repositories.RotationPolicyRepositoryInterface {
	return nil
}

func (m *MockServiceContainer) GetVersionRepository() repositories.SecretVersionRepositoryInterface {
	return nil
}

func (m *MockServiceContainer) GetKeyRepository() repositories.KeyRepositoryInterface {
	return nil
}

func (m *MockServiceContainer) GetCertificateRepository() repositories.CertificateRepositoryInterface {
	return nil
}

func (m *MockServiceContainer) GetCertificatePolicyRepository() repositories.CertificatePolicyRepositoryInterface {
	return nil
}

func (m *MockServiceContainer) GetKeyRotationPolicyRepository() repositories.KeyRotationPolicyRepositoryInterface {
	return nil
}

func (m *MockServiceContainer) GetSessionRepository() repositories.SessionRepositoryInterface {
	return nil
}

func (m *MockServiceContainer) GetVaultRepository() repositories.VaultRepositoryInterface {
	return nil
}

func (m *MockServiceContainer) GetVaultService() vaultServices.VaultService {
	return m.VaultService
}

func (m *MockServiceContainer) GetVaultWebhookService() vaultServices.VaultWebhookService {
	return m.VaultWebhookService
}

// Authentication service getters - return nil for unused services
func (m *MockServiceContainer) GetPasswordService() authServices.PasswordService {
	return nil
}

func (m *MockServiceContainer) GetTOTPService() authServices.TOTPService {
	return nil
}

func (m *MockServiceContainer) GetJWTService() authServices.JWTService {
	return nil
}

func (m *MockServiceContainer) GetAuthenticationService() authServices.AuthenticationService {
	args := m.Called()
	return args.Get(0).(authServices.AuthenticationService)
}

func (m *MockServiceContainer) GetOIDCService() authServices.OIDCService {
	return nil
}

// Authorization service getters
func (m *MockServiceContainer) GetRBACService() authzServices.RBACService {
	args := m.Called()
	return args.Get(0).(authzServices.RBACService)
}

func (m *MockServiceContainer) GetAccessPolicyRepository() repositories.AccessPolicyRepositoryInterface {
	return nil
}

func (m *MockServiceContainer) GetAccessPolicyService() authzServices.AccessPolicyService {
	return m.AccessPolicyService
}

func (m *MockServiceContainer) GetRoleAssignmentService() authzServices.RoleAssignmentService {
	return m.RoleAssignmentService
}

func (m *MockServiceContainer) GetGrantService() provisioning.GrantService {
	return m.GrantService
}

func (m *MockServiceContainer) GetOAuth2ClientRepository() repositories.OAuth2ClientRepositoryInterface {
	return nil
}

func (m *MockServiceContainer) GetOAuth2Service() oauth2Services.OAuth2Service {
	return nil
}

// Business service getters
func (m *MockServiceContainer) GetUserService() userServices.UserService {
	args := m.Called()
	return args.Get(0).(userServices.UserService)
}

func (m *MockServiceContainer) GetSecretService() secretServices.SecretService {
	args := m.Called()
	return args.Get(0).(secretServices.SecretService)
}

func (m *MockServiceContainer) GetCachedSecretService() secretServices.SecretService {
	// For testing, return the same mock service as GetSecretService
	args := m.Called()
	if len(args) == 0 {
		// Fallback to GetSecretService if not explicitly mocked
		return m.GetSecretService()
	}
	return args.Get(0).(secretServices.SecretService)
}

func (m *MockServiceContainer) GetKeyService() keyServices.KeyService {
	args := m.Called()
	if len(args) == 0 || args.Get(0) == nil {
		return nil
	}
	return args.Get(0).(keyServices.KeyService)
}

func (m *MockServiceContainer) GetCertificateService() certServices.CertificateService {
	return nil
}

func (m *MockServiceContainer) GetCertificateRenewalService() certServices.CertificateRenewalService {
	return nil
}

func (m *MockServiceContainer) GetCryptoService() keyServices.CryptoService {
	return nil
}

// Secret component service getters - return nil for unused services
func (m *MockServiceContainer) GetCryptographyService() secretServices.CryptographyService {
	return nil
}

func (m *MockServiceContainer) GetVersioningService() secretServices.VersioningServiceInterface {
	args := m.Called()
	if len(args) == 0 {
		return nil
	}
	return args.Get(0).(secretServices.VersioningServiceInterface)
}

func (m *MockServiceContainer) GetTagService() secretServices.TagService {
	return nil
}

func (m *MockServiceContainer) GetRotationService() secretServices.RotationServiceInterface {
	args := m.Called()
	if len(args) == 0 || args.Get(0) == nil {
		return nil
	}
	return args.Get(0).(secretServices.RotationServiceInterface)
}

func (m *MockServiceContainer) GetSchedulerService() secretServices.SchedulerServiceInterface {
	args := m.Called()
	if len(args) == 0 {
		return nil
	}
	return args.Get(0).(secretServices.SchedulerServiceInterface)
}

// Infrastructure getters
func (m *MockServiceContainer) GetDatabase() *sql.DB {
	return nil
}

func (m *MockServiceContainer) GetLogger() *logging.Logger {
	args := m.Called()
	if len(args) == 0 || args.Get(0) == nil {
		return nil
	}
	return args.Get(0).(*logging.Logger)
}

// Cache getters
func (m *MockServiceContainer) GetSecretCache() *cache.SecretCache {
	return nil
}

func (m *MockServiceContainer) GetCacheConfig() rvconfig.CacheConfig {
	return rvconfig.CacheConfig{}
}

func (m *MockServiceContainer) GetVaultCache() *vaultcache.Cache {
	return nil
}

func (m *MockServiceContainer) GetCertificateCache() *certcache.Cache {
	return nil
}

// Retry service getter
func (m *MockServiceContainer) GetRetryService() retryServices.RetryService {
	return nil
}

// GetSigningProvider returns nil — signing provider is not used in CLI tests.
func (m *MockServiceContainer) GetSigningProvider() signing.SigningKeyProvider {
	return nil
}

// GetItemBackupService returns nil — backup service is not used in CLI tests.
func (m *MockServiceContainer) GetItemBackupService() *backup.ItemBackupService {
	return nil
}

// GetKeyProvider returns nil — key provider is not used in CLI tests.
func (m *MockServiceContainer) GetKeyProvider() crypto.KeyProvider {
	return nil
}

// GetKeyCache returns nil — key cache is not used in CLI tests.
func (m *MockServiceContainer) GetKeyCache() keycache.Cache {
	return nil
}

// GetCryptoMetrics returns nil — crypto metrics are not used in CLI tests.
func (m *MockServiceContainer) GetCryptoMetrics() metrics.CryptoMetrics {
	return nil
}

// GetAuditService returns the audit write-path mock.
func (m *MockServiceContainer) GetAuditService() auditServices.AuditServiceInterface {
	args := m.Called()
	if args.Get(0) == nil {
		return nil
	}
	return args.Get(0).(auditServices.AuditServiceInterface)
}

// GetComplianceReportService returns the compliance report read-path mock.
func (m *MockServiceContainer) GetComplianceReportService() auditServices.ComplianceReportServiceInterface {
	args := m.Called()
	if args.Get(0) == nil {
		return nil
	}
	return args.Get(0).(auditServices.ComplianceReportServiceInterface)
}

// Lifecycle management
func (m *MockServiceContainer) Close() error {
	args := m.Called()
	return args.Error(0)
}

// Mock User Service
type MockUserService struct {
	mock.Mock
}

func (m *MockUserService) CreateUser(ctx context.Context, req userServices.CreateUserRequest) (*userServices.CreateUserResult, error) {
	args := m.Called(ctx, req)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*userServices.CreateUserResult), args.Error(1)
}

func (m *MockUserService) GetUser(ctx context.Context, userID uuid.UUID) (*model.User, error) {
	args := m.Called(ctx, userID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*model.User), args.Error(1)
}

func (m *MockUserService) UpdateUser(ctx context.Context, req userServices.UpdateUserRequest) error {
	args := m.Called(ctx, req)
	return args.Error(0)
}

func (m *MockUserService) DeleteUser(ctx context.Context, userID uuid.UUID) error {
	args := m.Called(ctx, userID)
	return args.Error(0)
}

func (m *MockUserService) GetUserByUsername(ctx context.Context, username string) (*model.User, error) {
	args := m.Called(ctx, username)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*model.User), args.Error(1)
}

func (m *MockUserService) FindOrCreateExternalUser(ctx context.Context, req userServices.FindOrCreateExternalUserRequest) (*model.User, error) {
	args := m.Called(ctx, req)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*model.User), args.Error(1)
}

func (m *MockUserService) ListUsers(ctx context.Context) ([]model.User, error) {
	args := m.Called(ctx)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]model.User), args.Error(1)
}

func (m *MockUserService) ValidateBootstrapToken(ctx context.Context, token string) (bool, error) {
	args := m.Called(ctx, token)
	return args.Bool(0), args.Error(1)
}

func (m *MockUserService) InvalidateBootstrapToken(ctx context.Context, token string) error {
	args := m.Called(ctx, token)
	return args.Error(0)
}

// Mock Secret Service
type MockSecretService struct {
	mock.Mock
}

func (m *MockSecretService) CreateSecret(ctx context.Context, req secretServices.CreateSecretRequest) (*model.Secret, error) {
	args := m.Called(ctx, req)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*model.Secret), args.Error(1)
}

func (m *MockSecretService) GetSecret(ctx context.Context, secretID uuid.UUID, scope model.Scope) (*model.Secret, error) {
	args := m.Called(ctx, secretID, scope)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*model.Secret), args.Error(1)
}

func (m *MockSecretService) ListSecrets(ctx context.Context, scope model.Scope, tags []string, limit, offset int) ([]model.Secret, error) {
	args := m.Called(ctx, scope, tags, limit, offset)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]model.Secret), args.Error(1)
}

func (m *MockSecretService) DeleteSecret(ctx context.Context, secretID uuid.UUID, scope model.Scope) error {
	args := m.Called(ctx, secretID, scope)
	return args.Error(0)
}

func (m *MockSecretService) ListDeletedSecrets(ctx context.Context, scope model.Scope) ([]model.Secret, error) {
	args := m.Called(ctx, scope)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]model.Secret), args.Error(1)
}

func (m *MockSecretService) UpdateSecret(ctx context.Context, req secretServices.UpdateSecretRequest) error {
	args := m.Called(ctx, req)
	return args.Error(0)
}

func (m *MockSecretService) GetSecretVersions(ctx context.Context, secretID uuid.UUID, scope model.Scope) ([]model.SecretVersion, error) {
	args := m.Called(ctx, secretID, scope)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]model.SecretVersion), args.Error(1)
}

func (m *MockSecretService) GetSecretVersionsMetadata(ctx context.Context, secretID uuid.UUID, scope model.Scope) ([]model.SecretVersionMetadata, error) {
	args := m.Called(ctx, secretID, scope)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]model.SecretVersionMetadata), args.Error(1)
}

func (m *MockSecretService) GetSecretVersion(ctx context.Context, secretID uuid.UUID, version int, scope model.Scope) (*model.SecretVersion, error) {
	args := m.Called(ctx, secretID, version, scope)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*model.SecretVersion), args.Error(1)
}

func (m *MockSecretService) GetLatestSecretVersion(ctx context.Context, secretID uuid.UUID, scope model.Scope) (*model.SecretVersion, error) {
	args := m.Called(ctx, secretID, scope)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*model.SecretVersion), args.Error(1)
}

func (m *MockSecretService) GenerateSecret(ctx context.Context, req secretServices.GenerateSecretRequest) (*model.Secret, error) {
	args := m.Called(ctx, req)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*model.Secret), args.Error(1)
}

func (m *MockSecretService) ExportSecrets(ctx context.Context, req secretServices.ExportSecretsRequest) ([]byte, error) {
	args := m.Called(ctx, req)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]byte), args.Error(1)
}

func (m *MockSecretService) ImportSecrets(ctx context.Context, req secretServices.ImportSecretsRequest) (*secretServices.ImportResult, error) {
	args := m.Called(ctx, req)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*secretServices.ImportResult), args.Error(1)
}

func (m *MockSecretService) RecoverSecret(ctx context.Context, secretID uuid.UUID, scope model.Scope) error {
	args := m.Called(ctx, secretID, scope)
	return args.Error(0)
}

func (m *MockSecretService) PurgeSecret(ctx context.Context, secretID uuid.UUID, scope model.Scope) error {
	args := m.Called(ctx, secretID, scope)
	return args.Error(0)
}

// MockVaultService implements vaultServices.VaultService for testing.
type MockVaultService struct {
	mock.Mock
}

func (m *MockVaultService) CreateVault(ctx context.Context, req model.CreateVaultRequest, createdBy uuid.UUID) (*model.Vault, error) {
	args := m.Called(ctx, req, createdBy)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*model.Vault), args.Error(1)
}

func (m *MockVaultService) CreateVaultProvisioned(ctx context.Context, req model.CreateVaultRequest, createdBy uuid.UUID, quotaBounded, grantCreatorRights bool) (*model.Vault, error) {
	args := m.Called(ctx, req, createdBy, quotaBounded, grantCreatorRights)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*model.Vault), args.Error(1)
}

func (m *MockVaultService) GetVault(ctx context.Context, name string) (*model.Vault, error) {
	args := m.Called(ctx, name)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*model.Vault), args.Error(1)
}

func (m *MockVaultService) ListVaults(ctx context.Context, includeDeleted bool) ([]model.Vault, error) {
	args := m.Called(ctx, includeDeleted)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]model.Vault), args.Error(1)
}

func (m *MockVaultService) ListVaultsScoped(ctx context.Context, principalID uuid.UUID, includeDeleted, all bool) ([]model.Vault, error) {
	args := m.Called(ctx, principalID, includeDeleted, all)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]model.Vault), args.Error(1)
}

func (m *MockVaultService) UpdateVault(ctx context.Context, name string, req model.UpdateVaultRequest, updatedBy uuid.UUID) (*model.Vault, error) {
	args := m.Called(ctx, name, req, updatedBy)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*model.Vault), args.Error(1)
}

func (m *MockVaultService) DeleteVault(ctx context.Context, name string) error {
	args := m.Called(ctx, name)
	return args.Error(0)
}

func (m *MockVaultService) RecoverVault(ctx context.Context, name string) error {
	args := m.Called(ctx, name)
	return args.Error(0)
}

func (m *MockVaultService) PurgeVault(ctx context.Context, name string) error {
	args := m.Called(ctx, name)
	return args.Error(0)
}

func (m *MockVaultService) SetPolicyCleaner(p vaultServices.PolicyCleaner) {
	m.Called(p)
}

func (m *MockVaultService) SetRoleAssignmentCleaner(c vaultServices.RoleAssignmentCleaner) {
	m.Called(c)
}

func (m *MockVaultService) SetWebhookCleaner(c vaultServices.WebhookCleaner) {
	m.Called(c)
}

func (m *MockVaultService) SetTxBeginner(tb vaultServices.TxBeginner) {
	m.Called(tb)
}

func (m *MockVaultService) SetSecretCacheFlusher(f vaultServices.SecretCacheFlusher) {
	m.Called(f)
}

func (m *MockVaultService) SetVaultCache(c vaultServices.VaultCacheInterface) {
	m.Called(c)
}

func (m *MockVaultService) SetGlobalPurgeProtection(protected bool) {
	m.Called(protected)
}

func (m *MockVaultService) SetGrantLocker(l vaultServices.GrantLocker) {
	m.Called(l)
}

func (m *MockVaultService) SetCreatorGranter(g vaultServices.CreatorGranter) {
	m.Called(g)
}

func (m *MockVaultService) SetPolicyVaultLister(l vaultServices.PolicyVaultLister) {
	m.Called(l)
}

// ErrVaultNotFoundForTest is returned by test doubles standing in for a
// vault-lookup failure; production code never checks for this sentinel.
var ErrVaultNotFoundForTest = errors.New("test: vault not found")

// MockRoleAssignmentService implements authzServices.RoleAssignmentService for testing.
type MockRoleAssignmentService struct {
	mock.Mock
}

func (m *MockRoleAssignmentService) AssignRole(ctx context.Context, in authzServices.AssignRoleInput) (*model.RoleAssignment, error) {
	args := m.Called(ctx, in)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*model.RoleAssignment), args.Error(1)
}

func (m *MockRoleAssignmentService) RevokeAssignment(ctx context.Context, assignmentID, vaultID uuid.UUID, callerIsGlobalAdmin bool) error {
	args := m.Called(ctx, assignmentID, vaultID, callerIsGlobalAdmin)
	return args.Error(0)
}

func (m *MockRoleAssignmentService) ListAssignments(ctx context.Context, vaultID uuid.UUID) ([]*model.RoleAssignment, error) {
	args := m.Called(ctx, vaultID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*model.RoleAssignment), args.Error(1)
}

func (m *MockRoleAssignmentService) HasDataAction(ctx context.Context, principalID, vaultID uuid.UUID, action model.DataAction) (bool, error) {
	args := m.Called(ctx, principalID, vaultID, action)
	return args.Bool(0), args.Error(1)
}

// MockAccessPolicyService implements authzServices.AccessPolicyService for testing.
type MockAccessPolicyService struct {
	mock.Mock
}

func (m *MockAccessPolicyService) CheckAccess(ctx context.Context, principalID uuid.UUID, resourceType model.PolicyResourceType, operation model.PolicyOperation, vaultID uuid.UUID) (authzServices.AccessDecision, error) {
	args := m.Called(ctx, principalID, resourceType, operation, vaultID)
	return args.Get(0).(authzServices.AccessDecision), args.Error(1)
}

func (m *MockAccessPolicyService) CheckVaultScopedAccess(ctx context.Context, principalID uuid.UUID, resourceType model.PolicyResourceType, operation model.PolicyOperation, vaultID uuid.UUID) (authzServices.AccessDecision, error) {
	args := m.Called(ctx, principalID, resourceType, operation, vaultID)
	return args.Get(0).(authzServices.AccessDecision), args.Error(1)
}

func (m *MockAccessPolicyService) CreatePolicy(ctx context.Context, policy *model.AccessPolicy) error {
	args := m.Called(ctx, policy)
	return args.Error(0)
}

func (m *MockAccessPolicyService) GetPolicy(ctx context.Context, id uuid.UUID) (*model.AccessPolicy, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*model.AccessPolicy), args.Error(1)
}

func (m *MockAccessPolicyService) ListPolicies(ctx context.Context) ([]*model.AccessPolicy, error) {
	args := m.Called(ctx)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*model.AccessPolicy), args.Error(1)
}

func (m *MockAccessPolicyService) ListByPrincipal(ctx context.Context, principalID uuid.UUID) ([]*model.AccessPolicy, error) {
	args := m.Called(ctx, principalID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*model.AccessPolicy), args.Error(1)
}

func (m *MockAccessPolicyService) UpdatePolicy(ctx context.Context, policy *model.AccessPolicy) error {
	args := m.Called(ctx, policy)
	return args.Error(0)
}

func (m *MockAccessPolicyService) DeletePolicy(ctx context.Context, id uuid.UUID) error {
	args := m.Called(ctx, id)
	return args.Error(0)
}

// Mock Authentication Service
type MockAuthenticationService struct {
	mock.Mock
}

func (m *MockAuthenticationService) AuthenticateUser(ctx context.Context, username, password, totpCode string) (*authServices.AuthenticationResult, error) {
	args := m.Called(ctx, username, password, totpCode)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*authServices.AuthenticationResult), args.Error(1)
}

func (m *MockAuthenticationService) IssueSessionForUser(ctx context.Context, user *model.User) (*authServices.AuthenticationResult, error) {
	args := m.Called(ctx, user)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*authServices.AuthenticationResult), args.Error(1)
}

func (m *MockAuthenticationService) ValidateSession(ctx context.Context, token string) (*authServices.JWTClaims, error) {
	args := m.Called(ctx, token)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*authServices.JWTClaims), args.Error(1)
}

func (m *MockAuthenticationService) RefreshAccessToken(ctx context.Context, refreshToken string) (*authServices.RefreshTokenResult, error) {
	args := m.Called(ctx, refreshToken)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*authServices.RefreshTokenResult), args.Error(1)
}

func (m *MockAuthenticationService) RevokeSession(ctx context.Context, req authServices.RevokeSessionRequest) error {
	args := m.Called(ctx, req)
	return args.Error(0)
}

func (m *MockAuthenticationService) RevokeAllUserSessions(ctx context.Context, userID uuid.UUID, reason string) error {
	args := m.Called(ctx, userID, reason)
	return args.Error(0)
}

func (m *MockAuthenticationService) ListActiveSessions(ctx context.Context, userID uuid.UUID) ([]*model.Session, error) {
	args := m.Called(ctx, userID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*model.Session), args.Error(1)
}

// Mock RBAC Service
type MockRBACService struct {
	mock.Mock
}

func (m *MockRBACService) HasPermission(role string, permission authzServices.Permission) bool {
	args := m.Called(role, permission)
	return args.Bool(0)
}

func (m *MockRBACService) GetRolePermissions(role string) []authzServices.Permission {
	args := m.Called(role)
	return args.Get(0).([]authzServices.Permission)
}

func (m *MockRBACService) ValidateEndpointAccess(roles []string, method, path string) error {
	args := m.Called(roles, method, path)
	return args.Error(0)
}

// Test Data Factory
func CreateTestUser() *model.User {
	return &model.User{
		ID:           uuid.New(),
		Username:     "testuser",
		PasswordHash: "$2a$10$test.hash",
		Roles:        []string{model.RoleUser},
		TOTPSecret:   "testsecret",
	}
}

func CreateTestSecret() *model.Secret {
	return &model.Secret{
		ID:      uuid.New(),
		UserID:  uuid.New(),
		Name:    "test-secret",
		Value:   "secret-value",
		Version: 1,
		Tags:    []string{"test", "sample"},
	}
}
