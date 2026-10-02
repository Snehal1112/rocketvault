package retry

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	"rocketvault/internal/repositories"
	internalRetry "rocketvault/internal/retry"
	"rocketvault/internal/services/auth"
	"rocketvault/internal/services/secrets"
	"rocketvault/internal/services/users"
	"rocketvault/model"
)

// ---------------------------------------------------------------------------
// noopRetryService — executes the operation exactly once, no real retry.
// ---------------------------------------------------------------------------

type noopRetryService struct{}

func (n *noopRetryService) ExecuteDatabaseOperation(_ context.Context, op func() error) error {
	return op()
}

func (n *noopRetryService) ExecuteExternalServiceOperation(_ context.Context, op func() error) error {
	return op()
}

func (n *noopRetryService) ExecuteServiceOperation(_ context.Context, op func() error) error {
	return op()
}

func (n *noopRetryService) ExecuteInteractiveOperation(_ context.Context, op func() error) error {
	return op()
}

func (n *noopRetryService) GetDatabasePolicy() internalRetry.Policy { return internalRetry.Policy{} }
func (n *noopRetryService) GetExternalServicesPolicy() internalRetry.Policy {
	return internalRetry.Policy{}
}
func (n *noopRetryService) GetServiceOperationsPolicy() internalRetry.Policy {
	return internalRetry.Policy{}
}
func (n *noopRetryService) GetInteractivePolicy() internalRetry.Policy {
	return internalRetry.Policy{}
}

// ---------------------------------------------------------------------------
// MockAuthService
// ---------------------------------------------------------------------------

type MockAuthService struct {
	mock.Mock
}

func (m *MockAuthService) AuthenticateUser(ctx context.Context, username, password, totpCode string) (*auth.AuthenticationResult, error) {
	args := m.Called(ctx, username, password, totpCode)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*auth.AuthenticationResult), args.Error(1)
}

func (m *MockAuthService) IssueSessionForUser(ctx context.Context, user *model.User) (*auth.AuthenticationResult, error) {
	args := m.Called(ctx, user)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*auth.AuthenticationResult), args.Error(1)
}

func (m *MockAuthService) ValidateSession(ctx context.Context, token string) (*auth.JWTClaims, error) {
	args := m.Called(ctx, token)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*auth.JWTClaims), args.Error(1)
}

func (m *MockAuthService) RefreshAccessToken(ctx context.Context, refreshToken string) (*auth.RefreshTokenResult, error) {
	args := m.Called(ctx, refreshToken)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*auth.RefreshTokenResult), args.Error(1)
}

func (m *MockAuthService) RevokeSession(ctx context.Context, req auth.RevokeSessionRequest) error {
	args := m.Called(ctx, req)
	return args.Error(0)
}

func (m *MockAuthService) RevokeAllUserSessions(ctx context.Context, userID uuid.UUID, reason string) error {
	args := m.Called(ctx, userID, reason)
	return args.Error(0)
}

func (m *MockAuthService) ListActiveSessions(ctx context.Context, userID uuid.UUID) ([]*model.Session, error) {
	args := m.Called(ctx, userID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*model.Session), args.Error(1)
}

// ---------------------------------------------------------------------------
// MockUserService
// ---------------------------------------------------------------------------

type MockUserService struct {
	mock.Mock
}

func (m *MockUserService) CreateUser(ctx context.Context, req users.CreateUserRequest) (*users.CreateUserResult, error) {
	args := m.Called(ctx, req)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*users.CreateUserResult), args.Error(1)
}

func (m *MockUserService) UpdateUser(ctx context.Context, req users.UpdateUserRequest) error {
	args := m.Called(ctx, req)
	return args.Error(0)
}

func (m *MockUserService) GetUser(ctx context.Context, userID uuid.UUID) (*model.User, error) {
	args := m.Called(ctx, userID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*model.User), args.Error(1)
}

func (m *MockUserService) GetUserByUsername(ctx context.Context, username string) (*model.User, error) {
	args := m.Called(ctx, username)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*model.User), args.Error(1)
}

func (m *MockUserService) FindOrCreateExternalUser(ctx context.Context, req users.FindOrCreateExternalUserRequest) (*model.User, error) {
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

func (m *MockUserService) DeleteUser(ctx context.Context, userID uuid.UUID) error {
	args := m.Called(ctx, userID)
	return args.Error(0)
}

func (m *MockUserService) ValidateBootstrapToken(ctx context.Context, token string) (bool, error) {
	args := m.Called(ctx, token)
	return args.Bool(0), args.Error(1)
}

func (m *MockUserService) InvalidateBootstrapToken(ctx context.Context, token string) error {
	args := m.Called(ctx, token)
	return args.Error(0)
}

// ---------------------------------------------------------------------------
// MockSecretService
// ---------------------------------------------------------------------------

type MockSecretService struct {
	mock.Mock
}

func (m *MockSecretService) CreateSecret(ctx context.Context, req secrets.CreateSecretRequest) (*model.Secret, error) {
	args := m.Called(ctx, req)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*model.Secret), args.Error(1)
}

func (m *MockSecretService) UpdateSecret(ctx context.Context, req secrets.UpdateSecretRequest) error {
	args := m.Called(ctx, req)
	return args.Error(0)
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

func (m *MockSecretService) GenerateSecret(ctx context.Context, req secrets.GenerateSecretRequest) (*model.Secret, error) {
	args := m.Called(ctx, req)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*model.Secret), args.Error(1)
}

func (m *MockSecretService) ExportSecrets(ctx context.Context, req secrets.ExportSecretsRequest) ([]byte, error) {
	args := m.Called(ctx, req)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]byte), args.Error(1)
}

func (m *MockSecretService) ImportSecrets(ctx context.Context, req secrets.ImportSecretsRequest) (*secrets.ImportResult, error) {
	args := m.Called(ctx, req)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*secrets.ImportResult), args.Error(1)
}

func (m *MockSecretService) RecoverSecret(ctx context.Context, secretID uuid.UUID, scope model.Scope) error {
	args := m.Called(ctx, secretID, scope)
	return args.Error(0)
}

func (m *MockSecretService) PurgeSecret(ctx context.Context, secretID uuid.UUID, scope model.Scope) error {
	args := m.Called(ctx, secretID, scope)
	return args.Error(0)
}

// ---------------------------------------------------------------------------
// MockSecretRepo (repositories.SecretRepositoryInterface)
// ---------------------------------------------------------------------------

type MockSecretRepo struct {
	mock.Mock
}

func (m *MockSecretRepo) Create(ctx context.Context, secret *model.Secret) error {
	args := m.Called(ctx, secret)
	return args.Error(0)
}

func (m *MockSecretRepo) Read(ctx context.Context, id uuid.UUID, scope model.Scope) (*model.Secret, error) {
	args := m.Called(ctx, id, scope)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*model.Secret), args.Error(1)
}

func (m *MockSecretRepo) FindByName(ctx context.Context, name string, scope model.Scope) (*model.Secret, error) {
	args := m.Called(ctx, name, scope)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*model.Secret), args.Error(1)
}

func (m *MockSecretRepo) Update(ctx context.Context, secret *model.Secret, scope model.Scope) error {
	args := m.Called(ctx, secret, scope)
	return args.Error(0)
}

func (m *MockSecretRepo) List(ctx context.Context, scope model.Scope, filter repositories.SecretFilter) ([]model.Secret, error) {
	args := m.Called(ctx, scope, filter)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]model.Secret), args.Error(1)
}

func (m *MockSecretRepo) Delete(ctx context.Context, id uuid.UUID) error {
	args := m.Called(ctx, id)
	return args.Error(0)
}

func (m *MockSecretRepo) SoftDelete(ctx context.Context, id uuid.UUID) error {
	args := m.Called(ctx, id)
	return args.Error(0)
}

func (m *MockSecretRepo) RecoverSecret(ctx context.Context, id uuid.UUID) error {
	args := m.Called(ctx, id)
	return args.Error(0)
}

func (m *MockSecretRepo) SoftDeleteVaultContents(ctx context.Context, vaultID uuid.UUID, deletedAt time.Time) error {
	args := m.Called(ctx, vaultID, deletedAt)
	return args.Error(0)
}

func (m *MockSecretRepo) RecoverVaultContents(ctx context.Context, vaultID uuid.UUID, deletedAt time.Time) error {
	args := m.Called(ctx, vaultID, deletedAt)
	return args.Error(0)
}

func (m *MockSecretRepo) ExportSecrets(ctx context.Context, options model.ExportOptions) ([]byte, error) {
	args := m.Called(ctx, options)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]byte), args.Error(1)
}

func (m *MockSecretRepo) ImportSecrets(ctx context.Context, data []byte, options model.ImportOptions) (int, error) {
	args := m.Called(ctx, data, options)
	return args.Int(0), args.Error(1)
}

func (m *MockSecretRepo) GetVersions(ctx context.Context, secretID uuid.UUID) ([]model.SecretVersion, error) {
	args := m.Called(ctx, secretID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]model.SecretVersion), args.Error(1)
}

func (m *MockSecretRepo) GetVersion(ctx context.Context, secretID uuid.UUID, version int) (*model.SecretVersion, error) {
	args := m.Called(ctx, secretID, version)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*model.SecretVersion), args.Error(1)
}

func (m *MockSecretRepo) GetLatestVersion(ctx context.Context, secretID uuid.UUID) (*model.SecretVersion, error) {
	args := m.Called(ctx, secretID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*model.SecretVersion), args.Error(1)
}

func (m *MockSecretRepo) PurgeSecret(ctx context.Context, id uuid.UUID) error {
	args := m.Called(ctx, id)
	return args.Error(0)
}

func (m *MockSecretRepo) SetPurgeProtection(ctx context.Context, id uuid.UUID, enabled bool) error {
	args := m.Called(ctx, id, enabled)
	return args.Error(0)
}

// Compile-time check that MockSecretRepo satisfies the interface.
var _ repositories.SecretRepositoryInterface = (*MockSecretRepo)(nil)

// ---------------------------------------------------------------------------
// MockUserRepo (repositories.UserRepositoryInterface)
// ---------------------------------------------------------------------------

type MockUserRepo struct {
	mock.Mock
}

func (m *MockUserRepo) Create(ctx context.Context, user *model.User) error {
	args := m.Called(ctx, user)
	return args.Error(0)
}

func (m *MockUserRepo) Read(ctx context.Context, id uuid.UUID) (*model.User, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*model.User), args.Error(1)
}

func (m *MockUserRepo) Update(ctx context.Context, user *model.User) error {
	args := m.Called(ctx, user)
	return args.Error(0)
}

func (m *MockUserRepo) Delete(ctx context.Context, id uuid.UUID) error {
	args := m.Called(ctx, id)
	return args.Error(0)
}

func (m *MockUserRepo) ReadByUsername(ctx context.Context, username string) (model.User, error) {
	args := m.Called(ctx, username)
	return args.Get(0).(model.User), args.Error(1)
}

func (m *MockUserRepo) ReadByExternalSubject(ctx context.Context, provider, subject string) (*model.User, error) {
	args := m.Called(ctx, provider, subject)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*model.User), args.Error(1)
}

func (m *MockUserRepo) List(ctx context.Context) ([]model.User, error) {
	args := m.Called(ctx)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]model.User), args.Error(1)
}

func (m *MockUserRepo) ValidateBootstrapToken(ctx context.Context, token string) (bool, error) {
	args := m.Called(ctx, token)
	return args.Bool(0), args.Error(1)
}

func (m *MockUserRepo) InvalidateBootstrapToken(ctx context.Context, token string) error {
	args := m.Called(ctx, token)
	return args.Error(0)
}

// Compile-time check that MockUserRepo satisfies the interface.
var _ repositories.UserRepositoryInterface = (*MockUserRepo)(nil)

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

var ctx = context.Background()

func newNoop() RetryService { return &noopRetryService{} }

// ---------------------------------------------------------------------------
// RetryService (retry_service.go) tests
// ---------------------------------------------------------------------------

func TestNewRetryService_DefaultConfig(t *testing.T) {
	v := viper.New()
	svc, err := NewRetryService(v)
	assert.NoError(t, err)
	assert.NotNil(t, svc)
}

func TestRetryService_GetPolicies(t *testing.T) {
	v := viper.New()
	svc, err := NewRetryService(v)
	assert.NoError(t, err)

	// Policies must be non-zero structs (default config populates them).
	dbPol := svc.GetDatabasePolicy()
	assert.True(t, dbPol.MaxAttempts > 0 || !dbPol.Enabled, "database policy is initialized")

	extPol := svc.GetExternalServicesPolicy()
	assert.True(t, extPol.MaxAttempts > 0 || !extPol.Enabled, "external services policy is initialized")

	svcPol := svc.GetServiceOperationsPolicy()
	assert.True(t, svcPol.MaxAttempts > 0 || !svcPol.Enabled, "service operations policy is initialized")
}

func TestRetryService_ExecuteDatabaseOperation_Success(t *testing.T) {
	v := viper.New()
	// Use minimal delays so the test is fast even if retry fires.
	v.Set("retry.database.enabled", true)
	v.Set("retry.database.max_attempts", 1)
	v.Set("retry.database.initial_delay", "1ms")
	v.Set("retry.database.max_delay", "1ms")
	v.Set("retry.database.backoff_multiplier", 1.0)
	v.Set("retry.circuit_breaker.failure_threshold", 5)
	v.Set("retry.circuit_breaker.timeout", "60s")
	v.Set("retry.circuit_breaker.half_open_requests", 3)

	svc, err := NewRetryService(v)
	assert.NoError(t, err)

	called := false
	execErr := svc.ExecuteDatabaseOperation(ctx, func() error {
		called = true
		return nil
	})
	assert.NoError(t, execErr)
	assert.True(t, called)
}

func TestRetryService_ExecuteDatabaseOperation_Error(t *testing.T) {
	v := viper.New()
	v.Set("retry.database.enabled", true)
	v.Set("retry.database.max_attempts", 1)
	v.Set("retry.database.initial_delay", "1ms")
	v.Set("retry.database.max_delay", "1ms")
	v.Set("retry.database.backoff_multiplier", 1.0)
	v.Set("retry.circuit_breaker.failure_threshold", 5)
	v.Set("retry.circuit_breaker.timeout", "60s")
	v.Set("retry.circuit_breaker.half_open_requests", 3)

	svc, err := NewRetryService(v)
	assert.NoError(t, err)

	sentinel := fmt.Errorf("db error")
	execErr := svc.ExecuteDatabaseOperation(ctx, func() error {
		return sentinel
	})
	assert.Error(t, execErr)
}

func TestRetryService_ExecuteExternalServiceOperation_Success(t *testing.T) {
	v := viper.New()
	v.Set("retry.external_services.enabled", true)
	v.Set("retry.external_services.max_attempts", 1)
	v.Set("retry.external_services.initial_delay", "1ms")
	v.Set("retry.external_services.max_delay", "1ms")
	v.Set("retry.external_services.backoff_multiplier", 1.0)
	v.Set("retry.circuit_breaker.failure_threshold", 5)
	v.Set("retry.circuit_breaker.timeout", "60s")
	v.Set("retry.circuit_breaker.half_open_requests", 3)

	svc, err := NewRetryService(v)
	assert.NoError(t, err)

	called := false
	execErr := svc.ExecuteExternalServiceOperation(ctx, func() error {
		called = true
		return nil
	})
	assert.NoError(t, execErr)
	assert.True(t, called)
}

func TestRetryService_ExecuteExternalServiceOperation_Error(t *testing.T) {
	v := viper.New()
	v.Set("retry.external_services.enabled", true)
	v.Set("retry.external_services.max_attempts", 1)
	v.Set("retry.external_services.initial_delay", "1ms")
	v.Set("retry.external_services.max_delay", "1ms")
	v.Set("retry.external_services.backoff_multiplier", 1.0)
	v.Set("retry.circuit_breaker.failure_threshold", 5)
	v.Set("retry.circuit_breaker.timeout", "60s")
	v.Set("retry.circuit_breaker.half_open_requests", 3)

	svc, err := NewRetryService(v)
	assert.NoError(t, err)

	sentinel := fmt.Errorf("external error")
	execErr := svc.ExecuteExternalServiceOperation(ctx, func() error {
		return sentinel
	})
	assert.Error(t, execErr)
}

func TestRetryService_ExecuteServiceOperation_Success(t *testing.T) {
	v := viper.New()
	v.Set("retry.service_operations.enabled", true)
	v.Set("retry.service_operations.max_attempts", 1)
	v.Set("retry.service_operations.initial_delay", "1ms")
	v.Set("retry.service_operations.max_delay", "1ms")
	v.Set("retry.service_operations.backoff_multiplier", 1.0)
	v.Set("retry.circuit_breaker.failure_threshold", 5)
	v.Set("retry.circuit_breaker.timeout", "60s")
	v.Set("retry.circuit_breaker.half_open_requests", 3)

	svc, err := NewRetryService(v)
	assert.NoError(t, err)

	called := false
	execErr := svc.ExecuteServiceOperation(ctx, func() error {
		called = true
		return nil
	})
	assert.NoError(t, execErr)
	assert.True(t, called)
}

func TestRetryService_ExecuteServiceOperation_Error(t *testing.T) {
	v := viper.New()
	v.Set("retry.service_operations.enabled", true)
	v.Set("retry.service_operations.max_attempts", 1)
	v.Set("retry.service_operations.initial_delay", "1ms")
	v.Set("retry.service_operations.max_delay", "1ms")
	v.Set("retry.service_operations.backoff_multiplier", 1.0)
	v.Set("retry.circuit_breaker.failure_threshold", 5)
	v.Set("retry.circuit_breaker.timeout", "60s")
	v.Set("retry.circuit_breaker.half_open_requests", 3)

	svc, err := NewRetryService(v)
	assert.NoError(t, err)

	sentinel := fmt.Errorf("service error")
	execErr := svc.ExecuteServiceOperation(ctx, func() error {
		return sentinel
	})
	assert.Error(t, execErr)
}

func TestRetryService_ExecuteInteractiveOperation_Success(t *testing.T) {
	v := viper.New()
	v.Set("retry.interactive.max_attempts", 1)
	v.Set("retry.interactive.initial_delay", "1ms")
	v.Set("retry.interactive.max_delay", "1ms")
	v.Set("retry.interactive.backoff_multiplier", 2.0)
	v.Set("retry.interactive.enabled", true)

	svc, err := NewRetryService(v)
	if err != nil {
		t.Fatalf("NewRetryService failed: %v", err)
	}

	calls := 0
	err = svc.ExecuteInteractiveOperation(context.Background(), func() error {
		calls++
		return nil
	})
	if err != nil {
		t.Errorf("expected success, got error: %v", err)
	}
	if calls != 1 {
		t.Errorf("expected 1 call, got %d", calls)
	}
}

func TestRetryService_ExecuteInteractiveOperation_Error(t *testing.T) {
	v := viper.New()
	v.Set("retry.interactive.max_attempts", 1)
	v.Set("retry.interactive.initial_delay", "1ms")
	v.Set("retry.interactive.max_delay", "1ms")
	v.Set("retry.interactive.backoff_multiplier", 2.0)
	v.Set("retry.interactive.enabled", true)
	v.Set("retry.interactive.retryable_errors", []string{"boom"})

	svc, err := NewRetryService(v)
	if err != nil {
		t.Fatalf("NewRetryService failed: %v", err)
	}

	err = svc.ExecuteInteractiveOperation(context.Background(), func() error {
		return errors.New("boom")
	})
	if err == nil {
		t.Error("expected error, got nil")
	}
}

func TestRetryService_GetInteractivePolicy(t *testing.T) {
	svc, err := NewRetryService(viper.New())
	if err != nil {
		t.Fatalf("NewRetryService failed: %v", err)
	}

	policy := svc.GetInteractivePolicy()
	if policy.MaxAttempts <= 0 && policy.Enabled {
		t.Error("expected interactive policy to be initialized")
	}
}

// ---------------------------------------------------------------------------
// RetryAuthenticationService (retry_auth_service.go) tests
// ---------------------------------------------------------------------------

func TestNewRetryAuthenticationService(t *testing.T) {
	base := &MockAuthService{}
	svc := NewRetryAuthenticationService(base, newNoop())
	assert.NotNil(t, svc)
}

func TestRetryAuth_AuthenticateUser_Success(t *testing.T) {
	base := &MockAuthService{}
	expected := &auth.AuthenticationResult{Token: "tok", UserID: uuid.New(), Username: "alice", Roles: []string{"admin"}}
	base.On("AuthenticateUser", mock.Anything, "alice", "pass", "123456").Return(expected, nil)

	svc := NewRetryAuthenticationService(base, newNoop())
	result, err := svc.AuthenticateUser(ctx, "alice", "pass", "123456")
	assert.NoError(t, err)
	assert.Equal(t, expected, result)
	base.AssertExpectations(t)
}

func TestRetryAuth_AuthenticateUser_Error(t *testing.T) {
	base := &MockAuthService{}
	base.On("AuthenticateUser", mock.Anything, "alice", "badpass", "123456").Return(nil, fmt.Errorf("invalid credentials"))

	svc := NewRetryAuthenticationService(base, newNoop())
	result, err := svc.AuthenticateUser(ctx, "alice", "badpass", "123456")
	assert.Nil(t, result)
	assert.Error(t, err)
	base.AssertExpectations(t)
}

func TestRetryAuth_IssueSessionForUser_Success(t *testing.T) {
	base := &MockAuthService{}
	user := &model.User{ID: uuid.New(), Username: "alice", Roles: []string{"admin"}}
	expected := &auth.AuthenticationResult{Token: "tok", UserID: user.ID, Username: "alice", Roles: []string{"admin"}}
	base.On("IssueSessionForUser", mock.Anything, user).Return(expected, nil)

	svc := NewRetryAuthenticationService(base, newNoop())
	result, err := svc.IssueSessionForUser(ctx, user)
	assert.NoError(t, err)
	assert.Equal(t, expected, result)
	base.AssertExpectations(t)
}

func TestRetryAuth_IssueSessionForUser_Error(t *testing.T) {
	base := &MockAuthService{}
	user := &model.User{ID: uuid.New(), Username: "alice", Roles: []string{"admin"}}
	base.On("IssueSessionForUser", mock.Anything, user).Return(nil, fmt.Errorf("session creation failed"))

	svc := NewRetryAuthenticationService(base, newNoop())
	result, err := svc.IssueSessionForUser(ctx, user)
	assert.Nil(t, result)
	assert.Error(t, err)
	base.AssertExpectations(t)
}

func TestRetryAuth_ValidateSession_Success(t *testing.T) {
	base := &MockAuthService{}
	expected := &auth.JWTClaims{Username: "alice", Roles: []string{"admin"}}
	base.On("ValidateSession", mock.Anything, "mytoken").Return(expected, nil)

	svc := NewRetryAuthenticationService(base, newNoop())
	result, err := svc.ValidateSession(ctx, "mytoken")
	assert.NoError(t, err)
	assert.Equal(t, expected, result)
	base.AssertExpectations(t)
}

func TestRetryAuth_ValidateSession_Error(t *testing.T) {
	base := &MockAuthService{}
	base.On("ValidateSession", mock.Anything, "badtoken").Return(nil, fmt.Errorf("invalid token"))

	svc := NewRetryAuthenticationService(base, newNoop())
	result, err := svc.ValidateSession(ctx, "badtoken")
	assert.Nil(t, result)
	assert.Error(t, err)
	base.AssertExpectations(t)
}

func TestRetryAuth_RefreshAccessToken_Success(t *testing.T) {
	base := &MockAuthService{}
	expected := &auth.RefreshTokenResult{Token: "newtok", UserID: uuid.New()}
	base.On("RefreshAccessToken", mock.Anything, "refresh").Return(expected, nil)

	svc := NewRetryAuthenticationService(base, newNoop())
	result, err := svc.RefreshAccessToken(ctx, "refresh")
	assert.NoError(t, err)
	assert.Equal(t, expected, result)
	base.AssertExpectations(t)
}

func TestRetryAuth_RefreshAccessToken_Error(t *testing.T) {
	base := &MockAuthService{}
	base.On("RefreshAccessToken", mock.Anything, "badrefresh").Return(nil, fmt.Errorf("invalid refresh token"))

	svc := NewRetryAuthenticationService(base, newNoop())
	result, err := svc.RefreshAccessToken(ctx, "badrefresh")
	assert.Nil(t, result)
	assert.Error(t, err)
	base.AssertExpectations(t)
}

func TestRetryAuth_RevokeSession_Success(t *testing.T) {
	base := &MockAuthService{}
	req := auth.RevokeSessionRequest{SessionID: "sess-1", CallerID: uuid.New(), Reason: "logout"}
	base.On("RevokeSession", mock.Anything, req).Return(nil)

	svc := NewRetryAuthenticationService(base, newNoop())
	err := svc.RevokeSession(ctx, req)
	assert.NoError(t, err)
	base.AssertExpectations(t)
}

func TestRetryAuth_RevokeSession_Error(t *testing.T) {
	base := &MockAuthService{}
	req := auth.RevokeSessionRequest{SessionID: "sess-1", CallerID: uuid.New(), Reason: "logout"}
	base.On("RevokeSession", mock.Anything, req).Return(fmt.Errorf("revoke failed"))

	svc := NewRetryAuthenticationService(base, newNoop())
	err := svc.RevokeSession(ctx, req)
	assert.Error(t, err)
	base.AssertExpectations(t)
}

func TestRetryAuth_RevokeAllUserSessions_Success(t *testing.T) {
	base := &MockAuthService{}
	userID := uuid.New()
	base.On("RevokeAllUserSessions", mock.Anything, userID, "admin").Return(nil)

	svc := NewRetryAuthenticationService(base, newNoop())
	err := svc.RevokeAllUserSessions(ctx, userID, "admin")
	assert.NoError(t, err)
	base.AssertExpectations(t)
}

func TestRetryAuth_RevokeAllUserSessions_Error(t *testing.T) {
	base := &MockAuthService{}
	userID := uuid.New()
	base.On("RevokeAllUserSessions", mock.Anything, userID, "admin").Return(fmt.Errorf("revoke all failed"))

	svc := NewRetryAuthenticationService(base, newNoop())
	err := svc.RevokeAllUserSessions(ctx, userID, "admin")
	assert.Error(t, err)
	base.AssertExpectations(t)
}

// ---------------------------------------------------------------------------
// RetryUserService (retry_user_service.go) tests
// ---------------------------------------------------------------------------

func TestNewRetryUserService(t *testing.T) {
	base := &MockUserService{}
	svc := NewRetryUserService(base, newNoop())
	assert.NotNil(t, svc)
}

func TestRetryUser_CreateUser_Success(t *testing.T) {
	base := &MockUserService{}
	req := users.CreateUserRequest{Username: "alice", Password: "secret", Roles: []string{"admin"}, CallerRoles: []string{"admin"}}
	expected := &users.CreateUserResult{UserID: uuid.New(), Username: "alice"}
	base.On("CreateUser", mock.Anything, req).Return(expected, nil)

	svc := NewRetryUserService(base, newNoop())
	result, err := svc.CreateUser(ctx, req)
	assert.NoError(t, err)
	assert.Equal(t, expected, result)
	base.AssertExpectations(t)
}

func TestRetryUser_CreateUser_Error(t *testing.T) {
	base := &MockUserService{}
	req := users.CreateUserRequest{Username: "alice", Password: "secret", Roles: []string{"admin"}, CallerRoles: []string{"admin"}}
	base.On("CreateUser", mock.Anything, req).Return(nil, fmt.Errorf("create failed"))

	svc := NewRetryUserService(base, newNoop())
	result, err := svc.CreateUser(ctx, req)
	assert.Nil(t, result)
	assert.Error(t, err)
	base.AssertExpectations(t)
}

func TestRetryUser_UpdateUser_Success(t *testing.T) {
	base := &MockUserService{}
	req := users.UpdateUserRequest{UserID: uuid.New()}
	base.On("UpdateUser", mock.Anything, req).Return(nil)

	svc := NewRetryUserService(base, newNoop())
	err := svc.UpdateUser(ctx, req)
	assert.NoError(t, err)
	base.AssertExpectations(t)
}

func TestRetryUser_UpdateUser_Error(t *testing.T) {
	base := &MockUserService{}
	req := users.UpdateUserRequest{UserID: uuid.New()}
	base.On("UpdateUser", mock.Anything, req).Return(fmt.Errorf("update failed"))

	svc := NewRetryUserService(base, newNoop())
	err := svc.UpdateUser(ctx, req)
	assert.Error(t, err)
	base.AssertExpectations(t)
}

func TestRetryUser_GetUser_Success(t *testing.T) {
	base := &MockUserService{}
	userID := uuid.New()
	expected := &model.User{ID: userID, Username: "alice"}
	base.On("GetUser", mock.Anything, userID).Return(expected, nil)

	svc := NewRetryUserService(base, newNoop())
	result, err := svc.GetUser(ctx, userID)
	assert.NoError(t, err)
	assert.Equal(t, expected, result)
	base.AssertExpectations(t)
}

func TestRetryUser_GetUser_Error(t *testing.T) {
	base := &MockUserService{}
	userID := uuid.New()
	base.On("GetUser", mock.Anything, userID).Return(nil, fmt.Errorf("not found"))

	svc := NewRetryUserService(base, newNoop())
	result, err := svc.GetUser(ctx, userID)
	assert.Nil(t, result)
	assert.Error(t, err)
	base.AssertExpectations(t)
}

func TestRetryUser_GetUserByUsername_Success(t *testing.T) {
	base := &MockUserService{}
	expected := &model.User{Username: "alice"}
	base.On("GetUserByUsername", mock.Anything, "alice").Return(expected, nil)

	svc := NewRetryUserService(base, newNoop())
	result, err := svc.GetUserByUsername(ctx, "alice")
	assert.NoError(t, err)
	assert.Equal(t, expected, result)
	base.AssertExpectations(t)
}

func TestRetryUser_GetUserByUsername_Error(t *testing.T) {
	base := &MockUserService{}
	base.On("GetUserByUsername", mock.Anything, "nobody").Return(nil, fmt.Errorf("not found"))

	svc := NewRetryUserService(base, newNoop())
	result, err := svc.GetUserByUsername(ctx, "nobody")
	assert.Nil(t, result)
	assert.Error(t, err)
	base.AssertExpectations(t)
}

func TestRetryUser_ListUsers_Success(t *testing.T) {
	base := &MockUserService{}
	expected := []model.User{{Username: "alice"}, {Username: "bob"}}
	base.On("ListUsers", mock.Anything).Return(expected, nil)

	svc := NewRetryUserService(base, newNoop())
	result, err := svc.ListUsers(ctx)
	assert.NoError(t, err)
	assert.Equal(t, expected, result)
	base.AssertExpectations(t)
}

func TestRetryUser_ListUsers_Error(t *testing.T) {
	base := &MockUserService{}
	base.On("ListUsers", mock.Anything).Return(nil, fmt.Errorf("list failed"))

	svc := NewRetryUserService(base, newNoop())
	result, err := svc.ListUsers(ctx)
	assert.Nil(t, result)
	assert.Error(t, err)
	base.AssertExpectations(t)
}

func TestRetryUser_DeleteUser_Success(t *testing.T) {
	base := &MockUserService{}
	userID := uuid.New()
	base.On("DeleteUser", mock.Anything, userID).Return(nil)

	svc := NewRetryUserService(base, newNoop())
	err := svc.DeleteUser(ctx, userID)
	assert.NoError(t, err)
	base.AssertExpectations(t)
}

func TestRetryUser_DeleteUser_Error(t *testing.T) {
	base := &MockUserService{}
	userID := uuid.New()
	base.On("DeleteUser", mock.Anything, userID).Return(fmt.Errorf("delete failed"))

	svc := NewRetryUserService(base, newNoop())
	err := svc.DeleteUser(ctx, userID)
	assert.Error(t, err)
	base.AssertExpectations(t)
}

func TestRetryUser_ValidateBootstrapToken_Success(t *testing.T) {
	base := &MockUserService{}
	base.On("ValidateBootstrapToken", mock.Anything, "mytoken").Return(true, nil)

	svc := NewRetryUserService(base, newNoop())
	ok, err := svc.ValidateBootstrapToken(ctx, "mytoken")
	assert.NoError(t, err)
	assert.True(t, ok)
	base.AssertExpectations(t)
}

func TestRetryUser_ValidateBootstrapToken_Error(t *testing.T) {
	base := &MockUserService{}
	base.On("ValidateBootstrapToken", mock.Anything, "badtoken").Return(false, fmt.Errorf("validation failed"))

	svc := NewRetryUserService(base, newNoop())
	ok, err := svc.ValidateBootstrapToken(ctx, "badtoken")
	assert.False(t, ok)
	assert.Error(t, err)
	base.AssertExpectations(t)
}

func TestRetryUser_InvalidateBootstrapToken_Success(t *testing.T) {
	base := &MockUserService{}
	base.On("InvalidateBootstrapToken", mock.Anything, "mytoken").Return(nil)

	svc := NewRetryUserService(base, newNoop())
	err := svc.InvalidateBootstrapToken(ctx, "mytoken")
	assert.NoError(t, err)
	base.AssertExpectations(t)
}

func TestRetryUser_InvalidateBootstrapToken_Error(t *testing.T) {
	base := &MockUserService{}
	base.On("InvalidateBootstrapToken", mock.Anything, "mytoken").Return(fmt.Errorf("invalidate failed"))

	svc := NewRetryUserService(base, newNoop())
	err := svc.InvalidateBootstrapToken(ctx, "mytoken")
	assert.Error(t, err)
	base.AssertExpectations(t)
}

// ---------------------------------------------------------------------------
// RetrySecretService (retry_secret_service.go) tests
// ---------------------------------------------------------------------------

func TestNewRetrySecretService(t *testing.T) {
	base := &MockSecretService{}
	svc := NewRetrySecretService(base, newNoop())
	assert.NotNil(t, svc)
}

func TestRetrySecret_CreateSecret_Success(t *testing.T) {
	base := &MockSecretService{}
	req := secrets.CreateSecretRequest{Name: "my-secret", Value: "s3cr3t", UserID: uuid.New()}
	expected := &model.Secret{ID: uuid.New(), Name: "my-secret"}
	base.On("CreateSecret", mock.Anything, req).Return(expected, nil)

	svc := NewRetrySecretService(base, newNoop())
	result, err := svc.CreateSecret(ctx, req)
	assert.NoError(t, err)
	assert.Equal(t, expected, result)
	base.AssertExpectations(t)
}

func TestRetrySecret_CreateSecret_Error(t *testing.T) {
	base := &MockSecretService{}
	req := secrets.CreateSecretRequest{Name: "my-secret", Value: "s3cr3t", UserID: uuid.New()}
	base.On("CreateSecret", mock.Anything, req).Return(nil, fmt.Errorf("create failed"))

	svc := NewRetrySecretService(base, newNoop())
	result, err := svc.CreateSecret(ctx, req)
	assert.Nil(t, result)
	assert.Error(t, err)
	base.AssertExpectations(t)
}

func TestRetrySecret_UpdateSecret_Success(t *testing.T) {
	base := &MockSecretService{}
	req := secrets.UpdateSecretRequest{SecretID: uuid.New(), Scope: model.NewOwnerScope(uuid.Nil, uuid.New())}
	base.On("UpdateSecret", mock.Anything, req).Return(nil)

	svc := NewRetrySecretService(base, newNoop())
	err := svc.UpdateSecret(ctx, req)
	assert.NoError(t, err)
	base.AssertExpectations(t)
}

func TestRetrySecret_UpdateSecret_Error(t *testing.T) {
	base := &MockSecretService{}
	req := secrets.UpdateSecretRequest{SecretID: uuid.New(), Scope: model.NewOwnerScope(uuid.Nil, uuid.New())}
	base.On("UpdateSecret", mock.Anything, req).Return(fmt.Errorf("update failed"))

	svc := NewRetrySecretService(base, newNoop())
	err := svc.UpdateSecret(ctx, req)
	assert.Error(t, err)
	base.AssertExpectations(t)
}

func TestRetrySecret_GetSecret_Success(t *testing.T) {
	base := &MockSecretService{}
	secretID := uuid.New()
	scope := model.NewOwnerScope(uuid.Nil, uuid.New())
	expected := &model.Secret{ID: secretID, Name: "my-secret"}
	base.On("GetSecret", mock.Anything, secretID, scope).Return(expected, nil)

	svc := NewRetrySecretService(base, newNoop())
	result, err := svc.GetSecret(ctx, secretID, scope)
	assert.NoError(t, err)
	assert.Equal(t, expected, result)
	base.AssertExpectations(t)
}

func TestRetrySecret_GetSecret_Error(t *testing.T) {
	base := &MockSecretService{}
	secretID := uuid.New()
	scope := model.NewOwnerScope(uuid.Nil, uuid.New())
	base.On("GetSecret", mock.Anything, secretID, scope).Return(nil, fmt.Errorf("not found"))

	svc := NewRetrySecretService(base, newNoop())
	result, err := svc.GetSecret(ctx, secretID, scope)
	assert.Nil(t, result)
	assert.Error(t, err)
	base.AssertExpectations(t)
}

func TestRetrySecret_ListSecrets_Success(t *testing.T) {
	base := &MockSecretService{}
	scope := model.NewOwnerScope(uuid.Nil, uuid.New())
	expected := []model.Secret{{Name: "sec1"}, {Name: "sec2"}}
	base.On("ListSecrets", mock.Anything, scope, []string{"tag1"}, 0, 0).Return(expected, nil)

	svc := NewRetrySecretService(base, newNoop())
	result, err := svc.ListSecrets(ctx, scope, []string{"tag1"}, 0, 0)
	assert.NoError(t, err)
	assert.Equal(t, expected, result)
	base.AssertExpectations(t)
}

func TestRetrySecret_ListSecrets_Error(t *testing.T) {
	base := &MockSecretService{}
	scope := model.NewOwnerScope(uuid.Nil, uuid.New())
	base.On("ListSecrets", mock.Anything, scope, []string(nil), 0, 0).Return(nil, fmt.Errorf("list failed"))

	svc := NewRetrySecretService(base, newNoop())
	result, err := svc.ListSecrets(ctx, scope, nil, 0, 0)
	assert.Nil(t, result)
	assert.Error(t, err)
	base.AssertExpectations(t)
}

func TestRetrySecret_DeleteSecret_Success(t *testing.T) {
	base := &MockSecretService{}
	secretID := uuid.New()
	scope := model.NewOwnerScope(uuid.Nil, uuid.New())
	base.On("DeleteSecret", mock.Anything, secretID, scope).Return(nil)

	svc := NewRetrySecretService(base, newNoop())
	err := svc.DeleteSecret(ctx, secretID, scope)
	assert.NoError(t, err)
	base.AssertExpectations(t)
}

func TestRetrySecret_DeleteSecret_Error(t *testing.T) {
	base := &MockSecretService{}
	secretID := uuid.New()
	scope := model.NewOwnerScope(uuid.Nil, uuid.New())
	base.On("DeleteSecret", mock.Anything, secretID, scope).Return(fmt.Errorf("delete failed"))

	svc := NewRetrySecretService(base, newNoop())
	err := svc.DeleteSecret(ctx, secretID, scope)
	assert.Error(t, err)
	base.AssertExpectations(t)
}

func TestRetrySecret_GetSecretVersions_Success(t *testing.T) {
	base := &MockSecretService{}
	secretID := uuid.New()
	scope := model.NewOwnerScope(uuid.Nil, uuid.New())
	expected := []model.SecretVersion{{Version: 1}, {Version: 2}}
	base.On("GetSecretVersions", mock.Anything, secretID, scope).Return(expected, nil)

	svc := NewRetrySecretService(base, newNoop())
	result, err := svc.GetSecretVersions(ctx, secretID, scope)
	assert.NoError(t, err)
	assert.Equal(t, expected, result)
	base.AssertExpectations(t)
}

func TestRetrySecret_GetSecretVersions_Error(t *testing.T) {
	base := &MockSecretService{}
	secretID := uuid.New()
	scope := model.NewOwnerScope(uuid.Nil, uuid.New())
	base.On("GetSecretVersions", mock.Anything, secretID, scope).Return(nil, fmt.Errorf("versions failed"))

	svc := NewRetrySecretService(base, newNoop())
	result, err := svc.GetSecretVersions(ctx, secretID, scope)
	assert.Nil(t, result)
	assert.Error(t, err)
	base.AssertExpectations(t)
}

func TestRetrySecret_GetSecretVersion_Success(t *testing.T) {
	base := &MockSecretService{}
	secretID := uuid.New()
	scope := model.NewOwnerScope(uuid.Nil, uuid.New())
	expected := &model.SecretVersion{Version: 3}
	base.On("GetSecretVersion", mock.Anything, secretID, 3, scope).Return(expected, nil)

	svc := NewRetrySecretService(base, newNoop())
	result, err := svc.GetSecretVersion(ctx, secretID, 3, scope)
	assert.NoError(t, err)
	assert.Equal(t, expected, result)
	base.AssertExpectations(t)
}

func TestRetrySecret_GetSecretVersion_Error(t *testing.T) {
	base := &MockSecretService{}
	secretID := uuid.New()
	scope := model.NewOwnerScope(uuid.Nil, uuid.New())
	base.On("GetSecretVersion", mock.Anything, secretID, 99, scope).Return(nil, fmt.Errorf("version not found"))

	svc := NewRetrySecretService(base, newNoop())
	result, err := svc.GetSecretVersion(ctx, secretID, 99, scope)
	assert.Nil(t, result)
	assert.Error(t, err)
	base.AssertExpectations(t)
}

func TestRetrySecret_GetLatestSecretVersion_Success(t *testing.T) {
	base := &MockSecretService{}
	secretID := uuid.New()
	scope := model.NewOwnerScope(uuid.Nil, uuid.New())
	expected := &model.SecretVersion{Version: 5}
	base.On("GetLatestSecretVersion", mock.Anything, secretID, scope).Return(expected, nil)

	svc := NewRetrySecretService(base, newNoop())
	result, err := svc.GetLatestSecretVersion(ctx, secretID, scope)
	assert.NoError(t, err)
	assert.Equal(t, expected, result)
	base.AssertExpectations(t)
}

func TestRetrySecret_GetLatestSecretVersion_Error(t *testing.T) {
	base := &MockSecretService{}
	secretID := uuid.New()
	scope := model.NewOwnerScope(uuid.Nil, uuid.New())
	base.On("GetLatestSecretVersion", mock.Anything, secretID, scope).Return(nil, fmt.Errorf("no versions"))

	svc := NewRetrySecretService(base, newNoop())
	result, err := svc.GetLatestSecretVersion(ctx, secretID, scope)
	assert.Nil(t, result)
	assert.Error(t, err)
	base.AssertExpectations(t)
}

func TestRetrySecret_GenerateSecret_Success(t *testing.T) {
	base := &MockSecretService{}
	req := secrets.GenerateSecretRequest{Name: "gen", Length: 16, UseNumbers: true, UserID: uuid.New()}
	expected := &model.Secret{Name: "gen"}
	base.On("GenerateSecret", mock.Anything, req).Return(expected, nil)

	svc := NewRetrySecretService(base, newNoop())
	result, err := svc.GenerateSecret(ctx, req)
	assert.NoError(t, err)
	assert.Equal(t, expected, result)
	base.AssertExpectations(t)
}

func TestRetrySecret_GenerateSecret_Error(t *testing.T) {
	base := &MockSecretService{}
	req := secrets.GenerateSecretRequest{Name: "gen", Length: 5, UserID: uuid.New()}
	base.On("GenerateSecret", mock.Anything, req).Return(nil, fmt.Errorf("invalid length"))

	svc := NewRetrySecretService(base, newNoop())
	result, err := svc.GenerateSecret(ctx, req)
	assert.Nil(t, result)
	assert.Error(t, err)
	base.AssertExpectations(t)
}

func TestRetrySecret_ExportSecrets_Success(t *testing.T) {
	base := &MockSecretService{}
	req := secrets.ExportSecretsRequest{Scope: model.NewOwnerScope(uuid.Nil, uuid.New()), Format: "json"}
	expected := []byte(`[{"name":"s1"}]`)
	base.On("ExportSecrets", mock.Anything, req).Return(expected, nil)

	svc := NewRetrySecretService(base, newNoop())
	result, err := svc.ExportSecrets(ctx, req)
	assert.NoError(t, err)
	assert.Equal(t, expected, result)
	base.AssertExpectations(t)
}

func TestRetrySecret_ExportSecrets_Error(t *testing.T) {
	base := &MockSecretService{}
	req := secrets.ExportSecretsRequest{Scope: model.NewOwnerScope(uuid.Nil, uuid.New()), Format: "bad"}
	base.On("ExportSecrets", mock.Anything, req).Return(nil, fmt.Errorf("invalid format"))

	svc := NewRetrySecretService(base, newNoop())
	result, err := svc.ExportSecrets(ctx, req)
	assert.Nil(t, result)
	assert.Error(t, err)
	base.AssertExpectations(t)
}

func TestRetrySecret_ImportSecrets_Success(t *testing.T) {
	base := &MockSecretService{}
	req := secrets.ImportSecretsRequest{Scope: model.NewOwnerScope(uuid.Nil, uuid.New()), Format: "json", Data: []byte(`[]`)}
	expected := &secrets.ImportResult{ImportedCount: 2}
	base.On("ImportSecrets", mock.Anything, req).Return(expected, nil)

	svc := NewRetrySecretService(base, newNoop())
	result, err := svc.ImportSecrets(ctx, req)
	assert.NoError(t, err)
	assert.Equal(t, expected, result)
	base.AssertExpectations(t)
}

func TestRetrySecret_ImportSecrets_Error(t *testing.T) {
	base := &MockSecretService{}
	req := secrets.ImportSecretsRequest{Scope: model.NewOwnerScope(uuid.Nil, uuid.New()), Format: "csv", Data: []byte(`bad`)}
	base.On("ImportSecrets", mock.Anything, req).Return(nil, fmt.Errorf("parse failed"))

	svc := NewRetrySecretService(base, newNoop())
	result, err := svc.ImportSecrets(ctx, req)
	assert.Nil(t, result)
	assert.Error(t, err)
	base.AssertExpectations(t)
}

// ---------------------------------------------------------------------------
// RetryRepositoryWrapper (retry_repository_wrapper.go) tests
// ---------------------------------------------------------------------------

func TestNewRetryRepositoryWrapper(t *testing.T) {
	base := &MockSecretRepo{}
	wrapper := NewRetryRepositoryWrapper(base, newNoop())
	assert.NotNil(t, wrapper)
}

func TestRetryRepo_Create_Success(t *testing.T) {
	base := &MockSecretRepo{}
	secret := &model.Secret{ID: uuid.New(), Name: "s1"}
	base.On("Create", mock.Anything, secret).Return(nil)

	w := NewRetryRepositoryWrapper(base, newNoop())
	err := w.Create(ctx, secret)
	assert.NoError(t, err)
	base.AssertExpectations(t)
}

func TestRetryRepo_Create_Error(t *testing.T) {
	base := &MockSecretRepo{}
	secret := &model.Secret{ID: uuid.New(), Name: "s1"}
	base.On("Create", mock.Anything, secret).Return(fmt.Errorf("db error"))

	w := NewRetryRepositoryWrapper(base, newNoop())
	err := w.Create(ctx, secret)
	assert.Error(t, err)
	base.AssertExpectations(t)
}

func TestRetryRepo_Read_Success(t *testing.T) {
	base := &MockSecretRepo{}
	id := uuid.New()
	scope := model.NewOwnerScope(uuid.Nil, uuid.New())
	expected := &model.Secret{ID: id}
	base.On("Read", mock.Anything, id, scope).Return(expected, nil)

	w := NewRetryRepositoryWrapper(base, newNoop())
	result, err := w.Read(ctx, id, scope)
	assert.NoError(t, err)
	assert.Equal(t, expected, result)
	base.AssertExpectations(t)
}

func TestRetryRepo_Read_Error(t *testing.T) {
	base := &MockSecretRepo{}
	id := uuid.New()
	scope := model.NewOwnerScope(uuid.Nil, uuid.New())
	base.On("Read", mock.Anything, id, scope).Return(nil, fmt.Errorf("not found"))

	w := NewRetryRepositoryWrapper(base, newNoop())
	result, err := w.Read(ctx, id, scope)
	assert.Nil(t, result)
	assert.Error(t, err)
	base.AssertExpectations(t)
}

func TestRetryRepo_Update_Success(t *testing.T) {
	base := &MockSecretRepo{}
	secret := &model.Secret{ID: uuid.New()}
	scope := model.NewOwnerScope(uuid.Nil, uuid.New())
	base.On("Update", mock.Anything, secret, scope).Return(nil)

	w := NewRetryRepositoryWrapper(base, newNoop())
	err := w.Update(ctx, secret, scope)
	assert.NoError(t, err)
	base.AssertExpectations(t)
}

func TestRetryRepo_Update_Error(t *testing.T) {
	base := &MockSecretRepo{}
	secret := &model.Secret{ID: uuid.New()}
	scope := model.NewOwnerScope(uuid.Nil, uuid.New())
	base.On("Update", mock.Anything, secret, scope).Return(fmt.Errorf("update error"))

	w := NewRetryRepositoryWrapper(base, newNoop())
	err := w.Update(ctx, secret, scope)
	assert.Error(t, err)
	base.AssertExpectations(t)
}

func TestRetryRepo_Delete_Success(t *testing.T) {
	base := &MockSecretRepo{}
	id := uuid.New()
	base.On("Delete", mock.Anything, id).Return(nil)

	w := NewRetryRepositoryWrapper(base, newNoop())
	err := w.Delete(ctx, id)
	assert.NoError(t, err)
	base.AssertExpectations(t)
}

func TestRetryRepo_Delete_Error(t *testing.T) {
	base := &MockSecretRepo{}
	id := uuid.New()
	base.On("Delete", mock.Anything, id).Return(fmt.Errorf("delete error"))

	w := NewRetryRepositoryWrapper(base, newNoop())
	err := w.Delete(ctx, id)
	assert.Error(t, err)
	base.AssertExpectations(t)
}

func TestRetryRepo_SoftDelete_Success(t *testing.T) {
	base := &MockSecretRepo{}
	id := uuid.New()
	base.On("SoftDelete", mock.Anything, id).Return(nil)

	w := NewRetryRepositoryWrapper(base, newNoop())
	err := w.SoftDelete(ctx, id)
	assert.NoError(t, err)
	base.AssertExpectations(t)
}

func TestRetryRepo_SoftDelete_Error(t *testing.T) {
	base := &MockSecretRepo{}
	id := uuid.New()
	base.On("SoftDelete", mock.Anything, id).Return(fmt.Errorf("soft delete error"))

	w := NewRetryRepositoryWrapper(base, newNoop())
	err := w.SoftDelete(ctx, id)
	assert.Error(t, err)
	base.AssertExpectations(t)
}

func TestRetryRepo_List_Success(t *testing.T) {
	base := &MockSecretRepo{}
	scope := model.NewOwnerScope(uuid.Nil, uuid.New())
	filter := repositories.SecretFilter{}
	expected := []model.Secret{{Name: "s1"}}
	base.On("List", mock.Anything, scope, filter).Return(expected, nil)

	w := NewRetryRepositoryWrapper(base, newNoop())
	result, err := w.List(ctx, scope, filter)
	assert.NoError(t, err)
	assert.Equal(t, expected, result)
	base.AssertExpectations(t)
}

func TestRetryRepo_List_Error(t *testing.T) {
	base := &MockSecretRepo{}
	scope := model.NewOwnerScope(uuid.Nil, uuid.New())
	filter := repositories.SecretFilter{}
	base.On("List", mock.Anything, scope, filter).Return(nil, fmt.Errorf("list error"))

	w := NewRetryRepositoryWrapper(base, newNoop())
	result, err := w.List(ctx, scope, filter)
	assert.Nil(t, result)
	assert.Error(t, err)
	base.AssertExpectations(t)
}

func TestRetryRepo_ExportSecrets_Success(t *testing.T) {
	base := &MockSecretRepo{}
	opts := model.ExportOptions{Format: "json"}
	expected := []byte(`[]`)
	base.On("ExportSecrets", mock.Anything, opts).Return(expected, nil)

	w := NewRetryRepositoryWrapper(base, newNoop())
	result, err := w.ExportSecrets(ctx, opts)
	assert.NoError(t, err)
	assert.Equal(t, expected, result)
	base.AssertExpectations(t)
}

func TestRetryRepo_ExportSecrets_Error(t *testing.T) {
	base := &MockSecretRepo{}
	opts := model.ExportOptions{Format: "csv"}
	base.On("ExportSecrets", mock.Anything, opts).Return(nil, fmt.Errorf("export error"))

	w := NewRetryRepositoryWrapper(base, newNoop())
	result, err := w.ExportSecrets(ctx, opts)
	assert.Nil(t, result)
	assert.Error(t, err)
	base.AssertExpectations(t)
}

func TestRetryRepo_ImportSecrets_Success(t *testing.T) {
	base := &MockSecretRepo{}
	data := []byte(`[]`)
	opts := model.ImportOptions{Format: "json"}
	base.On("ImportSecrets", mock.Anything, data, opts).Return(5, nil)

	w := NewRetryRepositoryWrapper(base, newNoop())
	count, err := w.ImportSecrets(ctx, data, opts)
	assert.NoError(t, err)
	assert.Equal(t, 5, count)
	base.AssertExpectations(t)
}

func TestRetryRepo_ImportSecrets_Error(t *testing.T) {
	base := &MockSecretRepo{}
	data := []byte(`bad`)
	opts := model.ImportOptions{Format: "json"}
	base.On("ImportSecrets", mock.Anything, data, opts).Return(0, fmt.Errorf("import error"))

	w := NewRetryRepositoryWrapper(base, newNoop())
	count, err := w.ImportSecrets(ctx, data, opts)
	assert.Equal(t, 0, count)
	assert.Error(t, err)
	base.AssertExpectations(t)
}

func TestRetryRepo_GetVersions_Success(t *testing.T) {
	base := &MockSecretRepo{}
	secretID := uuid.New()
	expected := []model.SecretVersion{{Version: 1}}
	base.On("GetVersions", mock.Anything, secretID).Return(expected, nil)

	w := NewRetryRepositoryWrapper(base, newNoop())
	result, err := w.GetVersions(ctx, secretID)
	assert.NoError(t, err)
	assert.Equal(t, expected, result)
	base.AssertExpectations(t)
}

func TestRetryRepo_GetVersions_Error(t *testing.T) {
	base := &MockSecretRepo{}
	secretID := uuid.New()
	base.On("GetVersions", mock.Anything, secretID).Return(nil, fmt.Errorf("versions error"))

	w := NewRetryRepositoryWrapper(base, newNoop())
	result, err := w.GetVersions(ctx, secretID)
	assert.Nil(t, result)
	assert.Error(t, err)
	base.AssertExpectations(t)
}

func TestRetryRepo_GetVersion_Success(t *testing.T) {
	base := &MockSecretRepo{}
	secretID := uuid.New()
	expected := &model.SecretVersion{Version: 2}
	base.On("GetVersion", mock.Anything, secretID, 2).Return(expected, nil)

	w := NewRetryRepositoryWrapper(base, newNoop())
	result, err := w.GetVersion(ctx, secretID, 2)
	assert.NoError(t, err)
	assert.Equal(t, expected, result)
	base.AssertExpectations(t)
}

func TestRetryRepo_GetVersion_Error(t *testing.T) {
	base := &MockSecretRepo{}
	secretID := uuid.New()
	base.On("GetVersion", mock.Anything, secretID, 99).Return(nil, fmt.Errorf("version not found"))

	w := NewRetryRepositoryWrapper(base, newNoop())
	result, err := w.GetVersion(ctx, secretID, 99)
	assert.Nil(t, result)
	assert.Error(t, err)
	base.AssertExpectations(t)
}

func TestRetryRepo_GetLatestVersion_Success(t *testing.T) {
	base := &MockSecretRepo{}
	secretID := uuid.New()
	expected := &model.SecretVersion{Version: 7}
	base.On("GetLatestVersion", mock.Anything, secretID).Return(expected, nil)

	w := NewRetryRepositoryWrapper(base, newNoop())
	result, err := w.GetLatestVersion(ctx, secretID)
	assert.NoError(t, err)
	assert.Equal(t, expected, result)
	base.AssertExpectations(t)
}

func TestRetryRepo_GetLatestVersion_Error(t *testing.T) {
	base := &MockSecretRepo{}
	secretID := uuid.New()
	base.On("GetLatestVersion", mock.Anything, secretID).Return(nil, fmt.Errorf("no versions"))

	w := NewRetryRepositoryWrapper(base, newNoop())
	result, err := w.GetLatestVersion(ctx, secretID)
	assert.Nil(t, result)
	assert.Error(t, err)
	base.AssertExpectations(t)
}

func TestRetryRepo_RecoverSecret_Success(t *testing.T) {
	base := &MockSecretRepo{}
	id := uuid.New()
	base.On("RecoverSecret", mock.Anything, id).Return(nil)

	w := NewRetryRepositoryWrapper(base, newNoop())
	err := w.RecoverSecret(ctx, id)
	assert.NoError(t, err)
	base.AssertExpectations(t)
}

func TestRetryRepo_RecoverSecret_Error(t *testing.T) {
	base := &MockSecretRepo{}
	id := uuid.New()
	base.On("RecoverSecret", mock.Anything, id).Return(fmt.Errorf("recover error"))

	w := NewRetryRepositoryWrapper(base, newNoop())
	err := w.RecoverSecret(ctx, id)
	assert.Error(t, err)
	base.AssertExpectations(t)
}

func TestRetryRepo_PurgeSecret_Success(t *testing.T) {
	base := &MockSecretRepo{}
	id := uuid.New()
	base.On("PurgeSecret", mock.Anything, id).Return(nil)

	w := NewRetryRepositoryWrapper(base, newNoop())
	err := w.PurgeSecret(ctx, id)
	assert.NoError(t, err)
	base.AssertExpectations(t)
}

func TestRetryRepo_PurgeSecret_Error(t *testing.T) {
	base := &MockSecretRepo{}
	id := uuid.New()
	base.On("PurgeSecret", mock.Anything, id).Return(fmt.Errorf("purge error"))

	w := NewRetryRepositoryWrapper(base, newNoop())
	err := w.PurgeSecret(ctx, id)
	assert.Error(t, err)
	base.AssertExpectations(t)
}

func TestRetryRepo_SoftDeleteVaultContents_Success(t *testing.T) {
	base := &MockSecretRepo{}
	vaultID := uuid.New()
	ts := time.Now()
	base.On("SoftDeleteVaultContents", mock.Anything, vaultID, ts).Return(nil)

	w := NewRetryRepositoryWrapper(base, newNoop())
	err := w.SoftDeleteVaultContents(ctx, vaultID, ts)
	assert.NoError(t, err)
	base.AssertExpectations(t)
}

func TestRetryRepo_SoftDeleteVaultContents_Error(t *testing.T) {
	base := &MockSecretRepo{}
	vaultID := uuid.New()
	ts := time.Now()
	base.On("SoftDeleteVaultContents", mock.Anything, vaultID, ts).Return(fmt.Errorf("soft delete vault error"))

	w := NewRetryRepositoryWrapper(base, newNoop())
	err := w.SoftDeleteVaultContents(ctx, vaultID, ts)
	assert.Error(t, err)
	base.AssertExpectations(t)
}

func TestRetryRepo_RecoverVaultContents_Success(t *testing.T) {
	base := &MockSecretRepo{}
	vaultID := uuid.New()
	ts := time.Now()
	base.On("RecoverVaultContents", mock.Anything, vaultID, ts).Return(nil)

	w := NewRetryRepositoryWrapper(base, newNoop())
	err := w.RecoverVaultContents(ctx, vaultID, ts)
	assert.NoError(t, err)
	base.AssertExpectations(t)
}

func TestRetryRepo_RecoverVaultContents_Error(t *testing.T) {
	base := &MockSecretRepo{}
	vaultID := uuid.New()
	ts := time.Now()
	base.On("RecoverVaultContents", mock.Anything, vaultID, ts).Return(fmt.Errorf("recover vault error"))

	w := NewRetryRepositoryWrapper(base, newNoop())
	err := w.RecoverVaultContents(ctx, vaultID, ts)
	assert.Error(t, err)
	base.AssertExpectations(t)
}

// ---------------------------------------------------------------------------
// RetryUserRepositoryWrapper (retry_user_repository_wrapper.go) tests
// ---------------------------------------------------------------------------

func TestNewRetryUserRepositoryWrapper(t *testing.T) {
	base := &MockUserRepo{}
	wrapper := NewRetryUserRepositoryWrapper(base, newNoop())
	assert.NotNil(t, wrapper)
}

func TestRetryUserRepo_Create_Success(t *testing.T) {
	base := &MockUserRepo{}
	user := &model.User{ID: uuid.New(), Username: "alice"}
	base.On("Create", mock.Anything, user).Return(nil)

	w := NewRetryUserRepositoryWrapper(base, newNoop())
	err := w.Create(ctx, user)
	assert.NoError(t, err)
	base.AssertExpectations(t)
}

func TestRetryUserRepo_Create_Error(t *testing.T) {
	base := &MockUserRepo{}
	user := &model.User{ID: uuid.New(), Username: "alice"}
	base.On("Create", mock.Anything, user).Return(fmt.Errorf("create error"))

	w := NewRetryUserRepositoryWrapper(base, newNoop())
	err := w.Create(ctx, user)
	assert.Error(t, err)
	base.AssertExpectations(t)
}

func TestRetryUserRepo_Read_Success(t *testing.T) {
	base := &MockUserRepo{}
	id := uuid.New()
	expected := &model.User{ID: id, Username: "alice"}
	base.On("Read", mock.Anything, id).Return(expected, nil)

	w := NewRetryUserRepositoryWrapper(base, newNoop())
	result, err := w.Read(ctx, id)
	assert.NoError(t, err)
	assert.Equal(t, expected, result)
	base.AssertExpectations(t)
}

func TestRetryUserRepo_Read_Error(t *testing.T) {
	base := &MockUserRepo{}
	id := uuid.New()
	base.On("Read", mock.Anything, id).Return(nil, fmt.Errorf("not found"))

	w := NewRetryUserRepositoryWrapper(base, newNoop())
	result, err := w.Read(ctx, id)
	assert.Nil(t, result)
	assert.Error(t, err)
	base.AssertExpectations(t)
}

func TestRetryUserRepo_Update_Success(t *testing.T) {
	base := &MockUserRepo{}
	user := &model.User{ID: uuid.New(), Username: "alice"}
	base.On("Update", mock.Anything, user).Return(nil)

	w := NewRetryUserRepositoryWrapper(base, newNoop())
	err := w.Update(ctx, user)
	assert.NoError(t, err)
	base.AssertExpectations(t)
}

func TestRetryUserRepo_Update_Error(t *testing.T) {
	base := &MockUserRepo{}
	user := &model.User{ID: uuid.New(), Username: "alice"}
	base.On("Update", mock.Anything, user).Return(fmt.Errorf("update error"))

	w := NewRetryUserRepositoryWrapper(base, newNoop())
	err := w.Update(ctx, user)
	assert.Error(t, err)
	base.AssertExpectations(t)
}

func TestRetryUserRepo_Delete_Success(t *testing.T) {
	base := &MockUserRepo{}
	id := uuid.New()
	base.On("Delete", mock.Anything, id).Return(nil)

	w := NewRetryUserRepositoryWrapper(base, newNoop())
	err := w.Delete(ctx, id)
	assert.NoError(t, err)
	base.AssertExpectations(t)
}

func TestRetryUserRepo_Delete_Error(t *testing.T) {
	base := &MockUserRepo{}
	id := uuid.New()
	base.On("Delete", mock.Anything, id).Return(fmt.Errorf("delete error"))

	w := NewRetryUserRepositoryWrapper(base, newNoop())
	err := w.Delete(ctx, id)
	assert.Error(t, err)
	base.AssertExpectations(t)
}

func TestRetryUserRepo_ReadByUsername_Success(t *testing.T) {
	base := &MockUserRepo{}
	expected := model.User{Username: "alice"}
	base.On("ReadByUsername", mock.Anything, "alice").Return(expected, nil)

	w := NewRetryUserRepositoryWrapper(base, newNoop())
	result, err := w.ReadByUsername(ctx, "alice")
	assert.NoError(t, err)
	assert.Equal(t, expected, result)
	base.AssertExpectations(t)
}

func TestRetryUserRepo_ReadByUsername_Error(t *testing.T) {
	base := &MockUserRepo{}
	base.On("ReadByUsername", mock.Anything, "nobody").Return(model.User{}, fmt.Errorf("not found"))

	w := NewRetryUserRepositoryWrapper(base, newNoop())
	result, err := w.ReadByUsername(ctx, "nobody")
	assert.Equal(t, model.User{}, result)
	assert.Error(t, err)
	base.AssertExpectations(t)
}

func TestRetryUserRepo_List_Success(t *testing.T) {
	base := &MockUserRepo{}
	expected := []model.User{{Username: "alice"}, {Username: "bob"}}
	base.On("List", mock.Anything).Return(expected, nil)

	w := NewRetryUserRepositoryWrapper(base, newNoop())
	result, err := w.List(ctx)
	assert.NoError(t, err)
	assert.Equal(t, expected, result)
	base.AssertExpectations(t)
}

func TestRetryUserRepo_List_Error(t *testing.T) {
	base := &MockUserRepo{}
	base.On("List", mock.Anything).Return(nil, fmt.Errorf("list error"))

	w := NewRetryUserRepositoryWrapper(base, newNoop())
	result, err := w.List(ctx)
	assert.Nil(t, result)
	assert.Error(t, err)
	base.AssertExpectations(t)
}

func TestRetryUserRepo_ValidateBootstrapToken_Success(t *testing.T) {
	base := &MockUserRepo{}
	base.On("ValidateBootstrapToken", mock.Anything, "tok").Return(true, nil)

	w := NewRetryUserRepositoryWrapper(base, newNoop())
	ok, err := w.ValidateBootstrapToken(ctx, "tok")
	assert.NoError(t, err)
	assert.True(t, ok)
	base.AssertExpectations(t)
}

func TestRetryUserRepo_ValidateBootstrapToken_Error(t *testing.T) {
	base := &MockUserRepo{}
	base.On("ValidateBootstrapToken", mock.Anything, "badtok").Return(false, fmt.Errorf("db error"))

	w := NewRetryUserRepositoryWrapper(base, newNoop())
	ok, err := w.ValidateBootstrapToken(ctx, "badtok")
	assert.False(t, ok)
	assert.Error(t, err)
	base.AssertExpectations(t)
}

func TestRetryUserRepo_InvalidateBootstrapToken_Success(t *testing.T) {
	base := &MockUserRepo{}
	base.On("InvalidateBootstrapToken", mock.Anything, "tok").Return(nil)

	w := NewRetryUserRepositoryWrapper(base, newNoop())
	err := w.InvalidateBootstrapToken(ctx, "tok")
	assert.NoError(t, err)
	base.AssertExpectations(t)
}

func TestRetryUserRepo_InvalidateBootstrapToken_Error(t *testing.T) {
	base := &MockUserRepo{}
	base.On("InvalidateBootstrapToken", mock.Anything, "tok").Return(fmt.Errorf("invalidate error"))

	w := NewRetryUserRepositoryWrapper(base, newNoop())
	err := w.InvalidateBootstrapToken(ctx, "tok")
	assert.Error(t, err)
	base.AssertExpectations(t)
}
