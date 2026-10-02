package secrets

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"rocketvault/internal/repositories"
	"rocketvault/model"
)

// MockSecretVersionRepository is a minimal test double for
// repositories.SecretVersionRepositoryInterface. See MockSecretRepository in
// secret_scope_service_test.go for why this is a local, package-scoped mock
// rather than a shared one from internal/testutils: this package's in-package
// test files cannot import internal/testutils without an import cycle.
type MockSecretVersionRepository struct {
	mock.Mock
	repositories.SecretVersionRepositoryInterface
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

// MockUserRepository is a minimal test double for
// repositories.UserRepositoryInterface. See MockSecretRepository in
// secret_scope_service_test.go for why this is a local, package-scoped mock.
// None of the tests in this file exercise it directly; it only needs to
// satisfy the versioningService struct's field type.
type MockUserRepository struct {
	mock.Mock
	repositories.UserRepositoryInterface
}

func newVersioningScopeFixture(t *testing.T) (*MockSecretRepository, *MockSecretVersionRepository, *versioningService) {
	t.Helper()
	secretRepo := new(MockSecretRepository)
	versionRepo := new(MockSecretVersionRepository)
	return secretRepo, versionRepo, &versioningService{
		versionRepo: versionRepo,
		secretRepo:  secretRepo,
		userRepo:    new(MockUserRepository),
		cryptoSvc:   fakeCrypto{},
		log:         newTestLogger(t),
	}
}

func TestGetVersionsDeniesOutOfScope(t *testing.T) {
	secretRepo, versionRepo, svc := newVersioningScopeFixture(t)
	ctx := context.Background()

	secretID := uuid.New()
	scope := model.NewVaultScope(uuid.New(), uuid.New())
	secretRepo.On("Read", ctx, secretID, scope).Return(nil, assert.AnError).Once()

	_, err := svc.GetVersions(ctx, secretID, scope)
	require.Error(t, err)
	versionRepo.AssertNotCalled(t, "GetVersions", mock.Anything, mock.Anything)
}

func TestGetVersionsDecryptsInScope(t *testing.T) {
	secretRepo, versionRepo, svc := newVersioningScopeFixture(t)
	ctx := context.Background()

	secretID := uuid.New()
	scope := model.NewVaultScope(uuid.New(), uuid.New())
	secretRepo.On("Read", ctx, secretID, scope).Return(&model.Secret{ID: secretID, Enabled: true}, nil).Once()
	versionRepo.On("GetVersions", ctx, secretID).Return([]model.SecretVersion{
		{ID: uuid.New(), SecretID: secretID, Version: 1, Value: "ENC(v1)", CreatedAt: time.Now().UTC()},
	}, nil).Once()

	versions, err := svc.GetVersions(ctx, secretID, scope)
	require.NoError(t, err)
	require.Len(t, versions, 1)
	assert.Equal(t, "v1", versions[0].Value)
}

func TestGetVersionAndLatestVersion(t *testing.T) {
	secretRepo, versionRepo, svc := newVersioningScopeFixture(t)
	ctx := context.Background()

	secretID := uuid.New()
	scope := model.NewOwnerScope(uuid.Nil, uuid.New())
	secretRepo.On("Read", ctx, secretID, scope).Return(&model.Secret{ID: secretID, Enabled: true}, nil).Twice()
	versionRepo.On("GetVersion", ctx, secretID, 2).
		Return(&model.SecretVersion{SecretID: secretID, Version: 2, Value: "ENC(v2)"}, nil).Once()
	versionRepo.On("GetLatestVersion", ctx, secretID).
		Return(&model.SecretVersion{SecretID: secretID, Version: 3, Value: "ENC(v3)"}, nil).Once()

	v, err := svc.GetVersion(ctx, secretID, 2, scope)
	require.NoError(t, err)
	assert.Equal(t, "v2", v.Value)

	latest, err := svc.GetLatestVersion(ctx, secretID, scope)
	require.NoError(t, err)
	assert.Equal(t, "v3", latest.Value)
	secretRepo.AssertExpectations(t)
}

// TestGetVersionMissingVersionMapsToErrSecretNotFound is a regression
// test for a gap found in code review: the parent secret is in scope (so
// Read succeeds), but the requested version number does not exist. The
// repository returns a wrapped repositories.ErrNotFound in that case, and
// GetVersion must translate it to secrets.ErrSecretNotFound so
// writeSecretError maps it to 404, not 500 — an entirely ordinary case (e.g.
// iterating version numbers, or after old versions were pruned).
func TestGetVersionMissingVersionMapsToErrSecretNotFound(t *testing.T) {
	secretRepo, versionRepo, svc := newVersioningScopeFixture(t)
	ctx := context.Background()

	secretID := uuid.New()
	scope := model.NewVaultScope(uuid.New(), uuid.New())
	secretRepo.On("Read", ctx, secretID, scope).Return(&model.Secret{ID: secretID, Enabled: true}, nil).Once()
	versionRepo.On("GetVersion", ctx, secretID, 99).
		Return(nil, fmt.Errorf("version %d not found for secret %s: %w", 99, secretID, repositories.ErrNotFound)).Once()

	_, err := svc.GetVersion(ctx, secretID, 99, scope)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrSecretNotFound), "missing version must map to ErrSecretNotFound, got: %v", err)
}

// TestGetVersionRealDBErrorStaysGeneric proves the fix does not
// overcorrect: a genuine repository failure (not a "no such version" case)
// must NOT be reported as ErrSecretNotFound, so it still maps to 500.
func TestGetVersionRealDBErrorStaysGeneric(t *testing.T) {
	secretRepo, versionRepo, svc := newVersioningScopeFixture(t)
	ctx := context.Background()

	secretID := uuid.New()
	scope := model.NewVaultScope(uuid.New(), uuid.New())
	secretRepo.On("Read", ctx, secretID, scope).Return(&model.Secret{ID: secretID, Enabled: true}, nil).Once()
	versionRepo.On("GetVersion", ctx, secretID, 1).
		Return(nil, fmt.Errorf("failed to query secret version: %w", assert.AnError)).Once()

	_, err := svc.GetVersion(ctx, secretID, 1, scope)
	require.Error(t, err)
	assert.False(t, errors.Is(err, ErrSecretNotFound), "a genuine DB error must not be reported as ErrSecretNotFound, got: %v", err)
}

// TestGetLatestVersionNoVersionsMapsToErrSecretNotFound mirrors
// TestGetVersionMissingVersionMapsToErrSecretNotFound for the "latest
// version" lookup: a secret in scope with zero versions must yield 404, not
// 500.
func TestGetLatestVersionNoVersionsMapsToErrSecretNotFound(t *testing.T) {
	secretRepo, versionRepo, svc := newVersioningScopeFixture(t)
	ctx := context.Background()

	secretID := uuid.New()
	scope := model.NewVaultScope(uuid.New(), uuid.New())
	secretRepo.On("Read", ctx, secretID, scope).Return(&model.Secret{ID: secretID, Enabled: true}, nil).Once()
	versionRepo.On("GetLatestVersion", ctx, secretID).
		Return(nil, fmt.Errorf("no versions found for secret %s: %w", secretID, repositories.ErrNotFound)).Once()

	_, err := svc.GetLatestVersion(ctx, secretID, scope)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrSecretNotFound), "no versions must map to ErrSecretNotFound, got: %v", err)
}

// TestGetLatestVersionRealDBErrorStaysGeneric mirrors
// TestGetVersionRealDBErrorStaysGeneric for the "latest version"
// lookup.
func TestGetLatestVersionRealDBErrorStaysGeneric(t *testing.T) {
	secretRepo, versionRepo, svc := newVersioningScopeFixture(t)
	ctx := context.Background()

	secretID := uuid.New()
	scope := model.NewVaultScope(uuid.New(), uuid.New())
	secretRepo.On("Read", ctx, secretID, scope).Return(&model.Secret{ID: secretID, Enabled: true}, nil).Once()
	versionRepo.On("GetLatestVersion", ctx, secretID).
		Return(nil, fmt.Errorf("failed to query latest secret version: %w", assert.AnError)).Once()

	_, err := svc.GetLatestVersion(ctx, secretID, scope)
	require.Error(t, err)
	assert.False(t, errors.Is(err, ErrSecretNotFound), "a genuine DB error must not be reported as ErrSecretNotFound, got: %v", err)
}
