// Package testutils provides shared mock implementations for internal service tests.
package testutils

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/mock"

	rvconfig "rocketvault/config"
	"rocketvault/internal/backup"
	"rocketvault/internal/cache"
	"rocketvault/internal/certcache"
	"rocketvault/internal/crypto"
	"rocketvault/internal/keycache"
	"rocketvault/internal/logging"
	"rocketvault/internal/metrics"
	"rocketvault/internal/repositories"
	auditSvc "rocketvault/internal/services/audit"
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

// NewTestLogger returns a logger suitable for use in tests.
func NewTestLogger(t *testing.T) *logging.Logger {
	t.Helper()
	l := logrus.New()
	l.SetLevel(logrus.DebugLevel)
	return &logging.Logger{Logger: l}
}

// --- MockAuthenticationService ---

// MockAuthenticationService mocks authServices.AuthenticationService.
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

// --- MockRBACService ---

// MockRBACService mocks authzServices.RBACService.
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

// --- MockSecretRepository ---

// MockSecretRepository mocks repositories.SecretRepositoryInterface.
type MockSecretRepository struct {
	mock.Mock
}

func (m *MockSecretRepository) Create(ctx context.Context, secret *model.Secret) error {
	args := m.Called(ctx, secret)
	return args.Error(0)
}

func (m *MockSecretRepository) Read(ctx context.Context, id uuid.UUID, scope model.Scope) (*model.Secret, error) {
	args := m.Called(ctx, id, scope)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*model.Secret), args.Error(1)
}

func (m *MockSecretRepository) FindByName(ctx context.Context, name string, scope model.Scope) (*model.Secret, error) {
	args := m.Called(ctx, name, scope)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*model.Secret), args.Error(1)
}

func (m *MockSecretRepository) Update(ctx context.Context, secret *model.Secret, scope model.Scope) error {
	args := m.Called(ctx, secret, scope)
	return args.Error(0)
}

func (m *MockSecretRepository) List(ctx context.Context, scope model.Scope, filter repositories.SecretFilter) ([]model.Secret, error) {
	args := m.Called(ctx, scope, filter)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]model.Secret), args.Error(1)
}

func (m *MockSecretRepository) Delete(ctx context.Context, id uuid.UUID) error {
	args := m.Called(ctx, id)
	return args.Error(0)
}

func (m *MockSecretRepository) SoftDelete(ctx context.Context, id uuid.UUID) error {
	args := m.Called(ctx, id)
	return args.Error(0)
}

func (m *MockSecretRepository) ExportSecrets(ctx context.Context, options model.ExportOptions) ([]byte, error) {
	args := m.Called(ctx, options)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]byte), args.Error(1)
}

func (m *MockSecretRepository) ImportSecrets(ctx context.Context, data []byte, options model.ImportOptions) (int, error) {
	args := m.Called(ctx, data, options)
	return args.Int(0), args.Error(1)
}

func (m *MockSecretRepository) GetVersions(ctx context.Context, secretID uuid.UUID) ([]model.SecretVersion, error) {
	args := m.Called(ctx, secretID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]model.SecretVersion), args.Error(1)
}

func (m *MockSecretRepository) GetVersion(ctx context.Context, secretID uuid.UUID, version int) (*model.SecretVersion, error) {
	args := m.Called(ctx, secretID, version)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*model.SecretVersion), args.Error(1)
}

func (m *MockSecretRepository) GetLatestVersion(ctx context.Context, secretID uuid.UUID) (*model.SecretVersion, error) {
	args := m.Called(ctx, secretID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*model.SecretVersion), args.Error(1)
}

func (m *MockSecretRepository) RecoverSecret(ctx context.Context, id uuid.UUID) error {
	args := m.Called(ctx, id)
	return args.Error(0)
}

func (m *MockSecretRepository) PurgeSecret(ctx context.Context, id uuid.UUID) error {
	args := m.Called(ctx, id)
	return args.Error(0)
}

func (m *MockSecretRepository) SetPurgeProtection(ctx context.Context, id uuid.UUID, enabled bool) error {
	args := m.Called(ctx, id, enabled)
	return args.Error(0)
}

func (m *MockSecretRepository) SoftDeleteVaultContents(ctx context.Context, vaultID uuid.UUID, deletedAt time.Time) error {
	args := m.Called(ctx, vaultID, deletedAt)
	return args.Error(0)
}

func (m *MockSecretRepository) RecoverVaultContents(ctx context.Context, vaultID uuid.UUID, deletedAt time.Time) error {
	args := m.Called(ctx, vaultID, deletedAt)
	return args.Error(0)
}

// --- MockCryptographyService ---

// MockCryptographyService mocks secretServices.CryptographyService.
type MockCryptographyService struct {
	mock.Mock
}

func (m *MockCryptographyService) EncryptSecret(plaintext string) (string, error) {
	args := m.Called(plaintext)
	return args.String(0), args.Error(1)
}

func (m *MockCryptographyService) DecryptSecret(ciphertext string) (string, error) {
	args := m.Called(ciphertext)
	return args.String(0), args.Error(1)
}

// --- MockVersioningService ---

// MockVersioningService mocks secretServices.VersioningServiceInterface.
type MockVersioningService struct {
	mock.Mock
}

func (m *MockVersioningService) CreateVersion(ctx context.Context, req secretServices.CreateVersionRequest) (*model.SecretVersion, error) {
	args := m.Called(ctx, req)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*model.SecretVersion), args.Error(1)
}

func (m *MockVersioningService) GetVersions(ctx context.Context, secretID uuid.UUID, scope model.Scope) ([]model.SecretVersion, error) {
	args := m.Called(ctx, secretID, scope)
	if v := args.Get(0); v != nil {
		return v.([]model.SecretVersion), args.Error(1)
	}
	return nil, args.Error(1)
}

func (m *MockVersioningService) GetVersionsMetadata(ctx context.Context, secretID uuid.UUID, scope model.Scope) ([]model.SecretVersionMetadata, error) {
	args := m.Called(ctx, secretID, scope)
	if v := args.Get(0); v != nil {
		return v.([]model.SecretVersionMetadata), args.Error(1)
	}
	return nil, args.Error(1)
}

func (m *MockVersioningService) GetVersion(ctx context.Context, secretID uuid.UUID, version int, scope model.Scope) (*model.SecretVersion, error) {
	args := m.Called(ctx, secretID, version, scope)
	if v := args.Get(0); v != nil {
		return v.(*model.SecretVersion), args.Error(1)
	}
	return nil, args.Error(1)
}

func (m *MockVersioningService) GetLatestVersion(ctx context.Context, secretID uuid.UUID, scope model.Scope) (*model.SecretVersion, error) {
	args := m.Called(ctx, secretID, scope)
	if v := args.Get(0); v != nil {
		return v.(*model.SecretVersion), args.Error(1)
	}
	return nil, args.Error(1)
}

func (m *MockVersioningService) DeleteVersions(ctx context.Context, secretID, userID uuid.UUID) error {
	args := m.Called(ctx, secretID, userID)
	return args.Error(0)
}

func (m *MockVersioningService) DeleteSpecificVersion(ctx context.Context, secretID uuid.UUID, version int, userID uuid.UUID) error {
	args := m.Called(ctx, secretID, version, userID)
	return args.Error(0)
}

func (m *MockVersioningService) RollbackToVersion(ctx context.Context, req secretServices.RollbackRequest) (*model.Secret, error) {
	args := m.Called(ctx, req)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*model.Secret), args.Error(1)
}

// --- MockUserRepository ---

// MockUserRepository mocks repositories.UserRepositoryInterface.
type MockUserRepository struct {
	mock.Mock
}

func (m *MockUserRepository) Create(ctx context.Context, user *model.User) error {
	args := m.Called(ctx, user)
	return args.Error(0)
}

func (m *MockUserRepository) Read(ctx context.Context, id uuid.UUID) (*model.User, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*model.User), args.Error(1)
}

func (m *MockUserRepository) Update(ctx context.Context, user *model.User) error {
	args := m.Called(ctx, user)
	return args.Error(0)
}

func (m *MockUserRepository) Delete(ctx context.Context, id uuid.UUID) error {
	args := m.Called(ctx, id)
	return args.Error(0)
}

func (m *MockUserRepository) ReadByUsername(ctx context.Context, username string) (model.User, error) {
	args := m.Called(ctx, username)
	if args.Get(0) == nil {
		return model.User{}, args.Error(1)
	}
	return args.Get(0).(model.User), args.Error(1)
}

func (m *MockUserRepository) ReadByExternalSubject(ctx context.Context, provider, subject string) (*model.User, error) {
	args := m.Called(ctx, provider, subject)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*model.User), args.Error(1)
}

func (m *MockUserRepository) List(ctx context.Context) ([]model.User, error) {
	args := m.Called(ctx)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]model.User), args.Error(1)
}

func (m *MockUserRepository) ValidateBootstrapToken(ctx context.Context, token string) (bool, error) {
	args := m.Called(ctx, token)
	return args.Bool(0), args.Error(1)
}

func (m *MockUserRepository) InvalidateBootstrapToken(ctx context.Context, token string) error {
	args := m.Called(ctx, token)
	return args.Error(0)
}

// --- MockSecretVersionRepository ---

// MockSecretVersionRepository mocks repositories.SecretVersionRepositoryInterface.
type MockSecretVersionRepository struct {
	mock.Mock
}

func (m *MockSecretVersionRepository) CreateVersion(ctx context.Context, version *model.SecretVersion) error {
	args := m.Called(ctx, version)
	return args.Error(0)
}

func (m *MockSecretVersionRepository) GetVersions(ctx context.Context, secretID uuid.UUID) ([]model.SecretVersion, error) {
	args := m.Called(ctx, secretID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]model.SecretVersion), args.Error(1)
}

func (m *MockSecretVersionRepository) GetVersion(ctx context.Context, secretID uuid.UUID, version int) (*model.SecretVersion, error) {
	args := m.Called(ctx, secretID, version)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*model.SecretVersion), args.Error(1)
}

func (m *MockSecretVersionRepository) GetLatestVersion(ctx context.Context, secretID uuid.UUID) (*model.SecretVersion, error) {
	args := m.Called(ctx, secretID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*model.SecretVersion), args.Error(1)
}

func (m *MockSecretVersionRepository) DeleteVersions(ctx context.Context, secretID uuid.UUID) error {
	args := m.Called(ctx, secretID)
	return args.Error(0)
}

func (m *MockSecretVersionRepository) DeleteSpecificVersion(ctx context.Context, secretID uuid.UUID, version int) error {
	args := m.Called(ctx, secretID, version)
	return args.Error(0)
}

// --- MockTagService ---

// MockTagService mocks secretServices.TagService.
type MockTagService struct {
	mock.Mock
}

func (m *MockTagService) AddTags(ctx context.Context, secretID uuid.UUID, tags []string) error {
	args := m.Called(ctx, secretID, tags)
	return args.Error(0)
}

func (m *MockTagService) RemoveTags(ctx context.Context, secretID uuid.UUID, tags []string) error {
	args := m.Called(ctx, secretID, tags)
	return args.Error(0)
}

func (m *MockTagService) RemoveAllTags(ctx context.Context, secretID uuid.UUID) error {
	args := m.Called(ctx, secretID)
	return args.Error(0)
}

func (m *MockTagService) GetTags(ctx context.Context, secretID uuid.UUID) ([]string, error) {
	args := m.Called(ctx, secretID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]string), args.Error(1)
}

func (m *MockTagService) FindSecretsByTags(ctx context.Context, userID uuid.UUID, tags []string) ([]uuid.UUID, error) {
	args := m.Called(ctx, userID, tags)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]uuid.UUID), args.Error(1)
}

// --- MockAuditService ---

// MockAuditService is a testify mock for auditSvc.AuditServiceInterface.
type MockAuditService struct {
	mock.Mock
}

func (m *MockAuditService) RecordEvent(ctx context.Context, event auditSvc.AuditEvent) error {
	args := m.Called(ctx, event)
	return args.Error(0)
}

func (m *MockAuditService) PersistAudit(userID, action, details string) error {
	args := m.Called(userID, action, details)
	return args.Error(0)
}

// --- MockComplianceReportService ---

// MockComplianceReportService is a testify mock for auditSvc.ComplianceReportServiceInterface.
type MockComplianceReportService struct {
	mock.Mock
}

func (m *MockComplianceReportService) QueryLogs(ctx context.Context, filter repositories.AuditFilter) ([]repositories.AuditLog, int64, bool, error) {
	args := m.Called(ctx, filter)
	if args.Get(0) == nil {
		return nil, args.Get(1).(int64), args.Bool(2), args.Error(3)
	}
	return args.Get(0).([]repositories.AuditLog), args.Get(1).(int64), args.Bool(2), args.Error(3)
}

func (m *MockComplianceReportService) GenerateSOC2Report(ctx context.Context, from, to time.Time) (*auditSvc.SOC2Report, error) {
	args := m.Called(ctx, from, to)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*auditSvc.SOC2Report), args.Error(1)
}

func (m *MockComplianceReportService) GenerateSOC2CSV(ctx context.Context, from, to time.Time) (string, error) {
	args := m.Called(ctx, from, to)
	return args.String(0), args.Error(1)
}

func (m *MockComplianceReportService) GenerateGDPRReport(ctx context.Context, from, to time.Time, subjectID string) (*auditSvc.GDPRReport, error) {
	args := m.Called(ctx, from, to, subjectID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*auditSvc.GDPRReport), args.Error(1)
}

func (m *MockComplianceReportService) GenerateGDPRCSV(ctx context.Context, from, to time.Time, subjectID string) (string, error) {
	args := m.Called(ctx, from, to, subjectID)
	return args.String(0), args.Error(1)
}

func (m *MockComplianceReportService) PurgeExpiredLogs(ctx context.Context) (int64, error) {
	args := m.Called(ctx)
	return args.Get(0).(int64), args.Error(1)
}

func (m *MockComplianceReportService) GetRetentionDays(ctx context.Context) (int, error) {
	args := m.Called(ctx)
	return args.Int(0), args.Error(1)
}

func (m *MockComplianceReportService) SetRetentionDays(ctx context.Context, days int) error {
	args := m.Called(ctx, days)
	return args.Error(0)
}

// --- MockServiceContainer ---

// MockServiceContainer is a testify mock for container.ServiceContainerInterface.
// It is used in api package tests where the full container interface is required.
type MockServiceContainer struct {
	mock.Mock
}

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
	return nil
}

func (m *MockServiceContainer) GetVaultWebhookService() vaultServices.VaultWebhookService {
	return nil
}

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
	if args.Get(0) == nil {
		return nil
	}
	return args.Get(0).(authServices.AuthenticationService)
}

func (m *MockServiceContainer) GetOIDCService() authServices.OIDCService {
	return nil
}

func (m *MockServiceContainer) GetRBACService() authzServices.RBACService {
	args := m.Called()
	if args.Get(0) == nil {
		return nil
	}
	return args.Get(0).(authzServices.RBACService)
}

func (m *MockServiceContainer) GetAccessPolicyRepository() repositories.AccessPolicyRepositoryInterface {
	return nil
}

func (m *MockServiceContainer) GetAccessPolicyService() authzServices.AccessPolicyService {
	return nil
}

// GetRoleAssignmentService returns the mocked role assignment service.
func (m *MockServiceContainer) GetRoleAssignmentService() authzServices.RoleAssignmentService {
	args := m.Called()
	if v, ok := args.Get(0).(authzServices.RoleAssignmentService); ok {
		return v
	}
	return nil
}

// GetGrantService returns the mocked provisioning grant service, nil unless a
// test sets it up.
func (m *MockServiceContainer) GetGrantService() provisioning.GrantService {
	return nil
}

func (m *MockServiceContainer) GetOAuth2ClientRepository() repositories.OAuth2ClientRepositoryInterface {
	return nil
}

func (m *MockServiceContainer) GetOAuth2Service() oauth2Services.OAuth2Service {
	return nil
}

func (m *MockServiceContainer) GetUserService() userServices.UserService {
	return nil
}

func (m *MockServiceContainer) GetSecretService() secretServices.SecretService {
	return nil
}

func (m *MockServiceContainer) GetKeyService() keyServices.KeyService {
	return nil
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

func (m *MockServiceContainer) GetCryptographyService() secretServices.CryptographyService {
	return nil
}

func (m *MockServiceContainer) GetVersioningService() secretServices.VersioningServiceInterface {
	return nil
}

func (m *MockServiceContainer) GetTagService() secretServices.TagService {
	return nil
}

func (m *MockServiceContainer) GetRotationService() secretServices.RotationServiceInterface {
	return nil
}

func (m *MockServiceContainer) GetSchedulerService() secretServices.SchedulerServiceInterface {
	return nil
}

func (m *MockServiceContainer) GetDatabase() *sql.DB {
	return nil
}

func (m *MockServiceContainer) GetLogger() *logging.Logger {
	return nil
}

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

func (m *MockServiceContainer) GetCachedSecretService() secretServices.SecretService {
	return nil
}

func (m *MockServiceContainer) GetRetryService() retryServices.RetryService {
	return nil
}

func (m *MockServiceContainer) GetSigningProvider() signing.SigningKeyProvider {
	return nil
}

func (m *MockServiceContainer) GetItemBackupService() *backup.ItemBackupService {
	return nil
}

func (m *MockServiceContainer) GetKeyProvider() crypto.KeyProvider {
	return nil
}

func (m *MockServiceContainer) GetKeyCache() keycache.Cache {
	return nil
}

func (m *MockServiceContainer) GetCryptoMetrics() metrics.CryptoMetrics {
	return nil
}

// GetAuditService returns the audit write-path mock.
func (m *MockServiceContainer) GetAuditService() auditSvc.AuditServiceInterface {
	args := m.Called()
	if args.Get(0) == nil {
		return nil
	}
	return args.Get(0).(auditSvc.AuditServiceInterface)
}

// GetComplianceReportService returns the compliance report read-path mock.
func (m *MockServiceContainer) GetComplianceReportService() auditSvc.ComplianceReportServiceInterface {
	args := m.Called()
	if args.Get(0) == nil {
		return nil
	}
	return args.Get(0).(auditSvc.ComplianceReportServiceInterface)
}

func (m *MockServiceContainer) Close() error {
	return nil
}

// --- Test data factories ---

// NewSecret returns a minimal Secret for use in tests.
func NewSecret(userID uuid.UUID) *model.Secret {
	return &model.Secret{
		ID:      uuid.New(),
		UserID:  userID,
		Name:    "test-secret",
		Value:   "plaintext-value",
		Version: 1,
		Tags:    []string{},
	}
}
