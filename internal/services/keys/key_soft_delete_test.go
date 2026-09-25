package keys

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"rocketvault/internal/crypto"
	"rocketvault/internal/logging"
	"rocketvault/internal/repositories"
	"rocketvault/model"
)

// mockKeyRepository is a minimal testify mock for KeyRepositoryInterface.
type mockKeyRepository struct {
	mock.Mock
}

func (m *mockKeyRepository) Create(ctx context.Context, key *model.Key) error {
	return m.Called(ctx, key).Error(0)
}

func (m *mockKeyRepository) Delete(ctx context.Context, id uuid.UUID) error {
	return m.Called(ctx, id).Error(0)
}

func (m *mockKeyRepository) SoftDelete(ctx context.Context, id uuid.UUID) error {
	return m.Called(ctx, id).Error(0)
}

func (m *mockKeyRepository) PurgeKey(ctx context.Context, id uuid.UUID) error {
	return m.Called(ctx, id).Error(0)
}

func (m *mockKeyRepository) SetPurgeProtection(ctx context.Context, id uuid.UUID, enabled bool) error {
	return m.Called(ctx, id, enabled).Error(0)
}

func (m *mockKeyRepository) UpdateRevocationStatus(ctx context.Context, id uuid.UUID, revoked bool) error {
	return m.Called(ctx, id, revoked).Error(0)
}

func (m *mockKeyRepository) RecoverKey(ctx context.Context, id uuid.UUID) error {
	return m.Called(ctx, id).Error(0)
}

func (m *mockKeyRepository) ReadDeletedScoped(ctx context.Context, id uuid.UUID, scope model.Scope) (*model.Key, error) {
	args := m.Called(ctx, id, scope)
	if v := args.Get(0); v != nil {
		return v.(*model.Key), args.Error(1)
	}
	return nil, args.Error(1)
}

func (m *mockKeyRepository) CreateVersion(ctx context.Context, keyID uuid.UUID, version int, value string) error {
	return m.Called(ctx, keyID, version, value).Error(0)
}

func (m *mockKeyRepository) ListVersions(ctx context.Context, keyID uuid.UUID) ([]model.KeyVersion, error) {
	args := m.Called(ctx, keyID)
	if v := args.Get(0); v != nil {
		return v.([]model.KeyVersion), args.Error(1)
	}
	return nil, args.Error(1)
}

func (m *mockKeyRepository) CurrentVersion(ctx context.Context, keyID uuid.UUID) (int, error) {
	args := m.Called(ctx, keyID)
	return args.Int(0), args.Error(1)
}

func (m *mockKeyRepository) ReadVersionValue(ctx context.Context, keyID uuid.UUID, version int) (string, error) {
	args := m.Called(ctx, keyID, version)
	return args.String(0), args.Error(1)
}

func (m *mockKeyRepository) GetVersion(ctx context.Context, keyID uuid.UUID, version int) (*model.KeyVersion, error) {
	args := m.Called(ctx, keyID, version)
	if v := args.Get(0); v != nil {
		return v.(*model.KeyVersion), args.Error(1)
	}
	return nil, args.Error(1)
}

func (m *mockKeyRepository) ListVersionRecords(ctx context.Context, keyID uuid.UUID) ([]model.KeyVersionRecord, error) {
	args := m.Called(ctx, keyID)
	if v := args.Get(0); v != nil {
		return v.([]model.KeyVersionRecord), args.Error(1)
	}
	return nil, args.Error(1)
}

func (m *mockKeyRepository) SoftDeleteVaultContents(ctx context.Context, vaultID uuid.UUID, deletedAt time.Time) error {
	args := m.Called(ctx, vaultID, deletedAt)
	return args.Error(0)
}

func (m *mockKeyRepository) RecoverVaultContents(ctx context.Context, vaultID uuid.UUID, deletedAt time.Time) error {
	args := m.Called(ctx, vaultID, deletedAt)
	return args.Error(0)
}

func (m *mockKeyRepository) Read(ctx context.Context, id uuid.UUID, scope model.Scope) (*model.Key, error) {
	args := m.Called(ctx, id, scope)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*model.Key), args.Error(1)
}

func (m *mockKeyRepository) Update(ctx context.Context, key *model.Key, scope model.Scope) error {
	args := m.Called(ctx, key, scope)
	return args.Error(0)
}

func (m *mockKeyRepository) List(ctx context.Context, scope model.Scope, filter repositories.KeyFilter) ([]model.Key, error) {
	args := m.Called(ctx, scope, filter)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]model.Key), args.Error(1)
}

// mockVaultRepository is a minimal test double for
// repositories.VaultRepositoryInterface. Only ReadByID is exercised — the
// purge-protection cascade check is the sole reason the key service holds a
// vault repository at all, so the rest of the interface is embedded rather
// than implemented.
type mockVaultRepository struct {
	mock.Mock
	repositories.VaultRepositoryInterface
}

func (m *mockVaultRepository) ReadByID(ctx context.Context, id uuid.UUID) (*model.Vault, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*model.Vault), args.Error(1)
}

// TestDeleteKeySoftDeletes verifies that DeleteKey calls SoftDelete and not Delete.
func TestDeleteKeySoftDeletes(t *testing.T) {
	userID := uuid.New()
	keyID := uuid.New()

	now := time.Now()
	existingKey := &model.Key{
		ID:        keyID,
		UserID:    userID,
		Name:      "test-key",
		Type:      model.KeyTypeRSA,
		CreatedAt: now,
		Enabled:   true,
	}
	deletedKey := &model.Key{
		ID:        keyID,
		UserID:    userID,
		Name:      "test-key",
		Type:      model.KeyTypeRSA,
		CreatedAt: now,
		Enabled:   true,
		DeletedAt: &now,
	}

	repo := &mockKeyRepository{}

	// DeleteKey reads via the scoped read — return the key so access check passes.
	repo.On("Read", mock.Anything, keyID, model.NewOwnerScope(uuid.Nil, userID)).Return(existingKey, nil)

	// SoftDelete must be called once.
	repo.On("SoftDelete", mock.Anything, keyID).Return(nil)

	// ReadDeletedScoped is called after SoftDelete to fetch metadata.
	repo.On("ReadDeletedScoped", mock.Anything, keyID, model.NewOwnerScope(uuid.Nil, userID)).Return(deletedKey, nil)

	// Delete must NOT be called — we register no expectation, and AssertNotCalled
	// below will confirm this.

	logger := &logging.Logger{Logger: logrus.New()}
	svc := NewKeyService(KeyServiceConfig{
		KeyRepository: repo,
		Logger:        logger,
	})

	result, err := svc.DeleteKey(context.Background(), keyID, model.NewOwnerScope(uuid.Nil, userID))
	assert.NoError(t, err)
	assert.NotNil(t, result)

	repo.AssertCalled(t, "SoftDelete", mock.Anything, keyID)
	repo.AssertCalled(t, "ReadDeletedScoped", mock.Anything, keyID, model.NewOwnerScope(uuid.Nil, userID))
	repo.AssertNotCalled(t, "Delete", mock.Anything, mock.Anything)
	repo.AssertExpectations(t)
}

// TestDeleteKey_ReturnsDeletedRecord verifies that DeleteKey returns a non-nil
// *model.Key with DeletedAt populated after a successful soft-delete.
func TestDeleteKey_ReturnsDeletedRecord(t *testing.T) {
	userID := uuid.New()
	keyID := uuid.New()

	now := time.Now()
	existingKey := &model.Key{
		ID:        keyID,
		UserID:    userID,
		Name:      "my-key",
		Type:      model.KeyTypeRSA,
		CreatedAt: now,
		Enabled:   true,
	}
	deletedKey := &model.Key{
		ID:        keyID,
		UserID:    userID,
		Name:      "my-key",
		Type:      model.KeyTypeRSA,
		CreatedAt: now,
		Enabled:   true,
		DeletedAt: &now,
	}

	repo := &mockKeyRepository{}
	repo.On("Read", mock.Anything, keyID, model.NewOwnerScope(uuid.Nil, userID)).Return(existingKey, nil)
	repo.On("SoftDelete", mock.Anything, keyID).Return(nil)
	repo.On("ReadDeletedScoped", mock.Anything, keyID, model.NewOwnerScope(uuid.Nil, userID)).Return(deletedKey, nil)

	logger := &logging.Logger{Logger: logrus.New()}
	svc := NewKeyService(KeyServiceConfig{
		KeyRepository: repo,
		Logger:        logger,
	})

	result, err := svc.DeleteKey(context.Background(), keyID, model.NewOwnerScope(uuid.Nil, userID))
	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.NotNil(t, result.DeletedAt, "DeletedAt must be populated in the returned record")
	assert.Equal(t, keyID, result.ID)
	assert.Equal(t, "my-key", result.Name)

	repo.AssertExpectations(t)
}

// TestListDeletedKeys_FiltersInSQLNotInGo verifies ListDeletedKeys delegates
// straight to the scope-aware List with OnlyDeleted, mirroring
// secretService.ListDeletedSecrets.
func TestListDeletedKeys_FiltersInSQLNotInGo(t *testing.T) {
	scope := model.NewVaultScope(uuid.New(), uuid.New())
	now := time.Now()
	want := []model.Key{{ID: uuid.New(), Name: "k", Type: model.KeyTypeRSA, DeletedAt: &now}}

	repo := &mockKeyRepository{}
	repo.On("List", mock.Anything, scope, repositories.KeyFilter{OnlyDeleted: true}).Return(want, nil)

	logger := &logging.Logger{Logger: logrus.New()}
	svc := NewKeyService(KeyServiceConfig{KeyRepository: repo, Logger: logger})

	got, err := svc.ListDeletedKeys(context.Background(), scope)
	assert.NoError(t, err)
	assert.Equal(t, want, got)
	repo.AssertExpectations(t)
}

// TestRecoverKey_RequiresTheKeyToBeInScope verifies RecoverKey rejects a key
// ID that isn't in the scope's soft-deleted listing, without ever calling
// the repository's RecoverKey.
func TestRecoverKey_RequiresTheKeyToBeInScope(t *testing.T) {
	scope := model.NewVaultScope(uuid.New(), uuid.New())
	keyID := uuid.New()

	repo := &mockKeyRepository{}
	repo.On("List", mock.Anything, scope, repositories.KeyFilter{OnlyDeleted: true}).Return([]model.Key{}, nil)

	logger := &logging.Logger{Logger: logrus.New()}
	svc := NewKeyService(KeyServiceConfig{KeyRepository: repo, Logger: logger})

	err := svc.RecoverKey(context.Background(), keyID, scope)
	assert.ErrorIs(t, err, ErrKeyNotFound)
	repo.AssertNotCalled(t, "RecoverKey", mock.Anything, mock.Anything)
}

// TestRecoverKey_RecoversWhenInScope verifies RecoverKey calls the
// repository's RecoverKey once the key is confirmed in scope.
func TestRecoverKey_RecoversWhenInScope(t *testing.T) {
	scope := model.NewVaultScope(uuid.New(), uuid.New())
	keyID := uuid.New()
	now := time.Now()

	repo := &mockKeyRepository{}
	repo.On("List", mock.Anything, scope, repositories.KeyFilter{OnlyDeleted: true}).
		Return([]model.Key{{ID: keyID, Name: "k", Type: model.KeyTypeRSA, DeletedAt: &now}}, nil)
	repo.On("RecoverKey", mock.Anything, keyID).Return(nil)

	logger := &logging.Logger{Logger: logrus.New()}
	svc := NewKeyService(KeyServiceConfig{KeyRepository: repo, Logger: logger})

	err := svc.RecoverKey(context.Background(), keyID, scope)
	assert.NoError(t, err)
	repo.AssertExpectations(t)
}

// TestPurgeKey_RequiresTheKeyToBeInScope mirrors TestRecoverKey_RequiresTheKeyToBeInScope for purge.
func TestPurgeKey_RequiresTheKeyToBeInScope(t *testing.T) {
	scope := model.NewVaultScope(uuid.New(), uuid.New())
	keyID := uuid.New()

	repo := &mockKeyRepository{}
	repo.On("List", mock.Anything, scope, repositories.KeyFilter{OnlyDeleted: true}).Return([]model.Key{}, nil)

	logger := &logging.Logger{Logger: logrus.New()}
	svc := NewKeyService(KeyServiceConfig{KeyRepository: repo, Logger: logger})

	err := svc.PurgeKey(context.Background(), keyID, scope)
	assert.ErrorIs(t, err, ErrKeyNotFound)
	repo.AssertNotCalled(t, "PurgeKey", mock.Anything, mock.Anything)
}

// TestPurgeKey_PurgesWhenInScope mirrors TestRecoverKey_RecoversWhenInScope for purge.
func TestPurgeKey_PurgesWhenInScope(t *testing.T) {
	scope := model.NewVaultScope(uuid.New(), uuid.New())
	keyID := uuid.New()
	now := time.Now()

	repo := &mockKeyRepository{}
	repo.On("List", mock.Anything, scope, repositories.KeyFilter{OnlyDeleted: true}).
		Return([]model.Key{{ID: keyID, Name: "k", Type: model.KeyTypeRSA, DeletedAt: &now}}, nil)
	repo.On("PurgeKey", mock.Anything, keyID).Return(nil)

	logger := &logging.Logger{Logger: logrus.New()}
	svc := NewKeyService(KeyServiceConfig{KeyRepository: repo, Logger: logger})

	err := svc.PurgeKey(context.Background(), keyID, scope)
	assert.NoError(t, err)
	repo.AssertExpectations(t)
}

// TestCreateRSAKey_SetsPurgeProtectionWhenRequested verifies the create path
// actually persists the requested purge-protection flag, which was previously
// only settable by editing the database directly.
func TestCreateRSAKey_SetsPurgeProtectionWhenRequested(t *testing.T) {
	setupKeyTestMasterKey()

	repo := &mockKeyRepository{}
	var createdKey *model.Key
	repo.On("Create", mock.Anything, mock.AnythingOfType("*model.Key")).
		Run(func(args mock.Arguments) { createdKey = args.Get(1).(*model.Key) }).
		Return(nil)
	repo.On("SetPurgeProtection", mock.Anything, mock.AnythingOfType("uuid.UUID"), true).Return(nil)

	svc := NewKeyService(KeyServiceConfig{
		KeyRepository: repo,
		KeyProvider:   crypto.NewSoftwareKeyProvider(),
		Logger:        newKeyLogger(),
	})

	protect := true
	result, err := svc.CreateRSAKey(context.Background(), CreateKeyRequest{
		UserID: uuid.New(), Name: "k1", Type: "RSA", Bits: 2048, PurgeProtection: &protect,
	})
	require.NoError(t, err)
	require.NotNil(t, createdKey)
	repo.AssertCalled(t, "SetPurgeProtection", mock.Anything, result.KeyID, true)
	repo.AssertExpectations(t)
}

// TestCreateECDSAKey_SetsPurgeProtectionWhenRequested mirrors the RSA case for
// the ECDSA create path.
func TestCreateECDSAKey_SetsPurgeProtectionWhenRequested(t *testing.T) {
	setupKeyTestMasterKey()

	repo := &mockKeyRepository{}
	repo.On("Create", mock.Anything, mock.AnythingOfType("*model.Key")).Return(nil)
	repo.On("SetPurgeProtection", mock.Anything, mock.AnythingOfType("uuid.UUID"), true).Return(nil)

	svc := NewKeyService(KeyServiceConfig{
		KeyRepository: repo,
		KeyProvider:   crypto.NewSoftwareKeyProvider(),
		Logger:        newKeyLogger(),
	})

	protect := true
	result, err := svc.CreateECDSAKey(context.Background(), CreateKeyRequest{
		UserID: uuid.New(), Name: "k2", Type: "ECDSA", Curve: "P-256", PurgeProtection: &protect,
	})
	require.NoError(t, err)
	repo.AssertCalled(t, "SetPurgeProtection", mock.Anything, result.KeyID, true)
	repo.AssertExpectations(t)
}

// TestCreateRSAKey_LeavesPurgeProtectionAloneByDefault verifies the flag is
// only touched when the caller explicitly asks for it.
func TestCreateRSAKey_LeavesPurgeProtectionAloneByDefault(t *testing.T) {
	setupKeyTestMasterKey()

	repo := &mockKeyRepository{}
	repo.On("Create", mock.Anything, mock.AnythingOfType("*model.Key")).Return(nil)

	svc := NewKeyService(KeyServiceConfig{
		KeyRepository: repo,
		KeyProvider:   crypto.NewSoftwareKeyProvider(),
		Logger:        newKeyLogger(),
	})

	_, err := svc.CreateRSAKey(context.Background(), CreateKeyRequest{
		UserID: uuid.New(), Name: "k1", Type: "RSA", Bits: 2048,
	})
	require.NoError(t, err)
	repo.AssertNotCalled(t, "SetPurgeProtection", mock.Anything, mock.Anything, mock.Anything)
}

// TestUpdateKey_SetsPurgeProtectionWhenRequested verifies the update path
// forwards an explicit purge-protection change to the repository.
func TestUpdateKey_SetsPurgeProtectionWhenRequested(t *testing.T) {
	keyID := uuid.New()
	vaultID := uuid.New()
	scope := model.NewVaultScope(vaultID, uuid.New())

	repo := &mockKeyRepository{}
	repo.On("Read", mock.Anything, keyID, scope).
		Return(&model.Key{ID: keyID, VaultID: vaultID, Name: "k", Type: model.KeyTypeRSA, Enabled: true}, nil)
	repo.On("Update", mock.Anything, mock.AnythingOfType("*model.Key"), scope).Return(nil)
	repo.On("SetPurgeProtection", mock.Anything, keyID, true).Return(nil)

	svc := NewKeyService(KeyServiceConfig{KeyRepository: repo, Logger: newKeyLogger()})

	protect := true
	require.NoError(t, svc.UpdateKey(context.Background(), UpdateKeyRequest{
		KeyID: keyID, Scope: scope, PurgeProtection: &protect,
	}))
	repo.AssertExpectations(t)
}

// TestPurgeKey_BlockedWhenVaultIsPurgeProtected verifies vault-level purge
// protection cascades to the per-key purge path.
// TestPurgeKey_BlockedWhenGlobalPurgeProtectionEnabled pins the
// instance-wide soft_delete.purge_protection safety switch: it refuses the
// purge before any repository call, regardless of the key's or its vault's
// own purge_protection flag.
func TestPurgeKey_BlockedWhenGlobalPurgeProtectionEnabled(t *testing.T) {
	scope := model.NewVaultScope(uuid.New(), uuid.New())
	keyID := uuid.New()

	repo := &mockKeyRepository{}
	logger := &logging.Logger{Logger: logrus.New()}
	svc := NewKeyService(KeyServiceConfig{KeyRepository: repo, Logger: logger, GlobalPurgeProtection: true})

	err := svc.PurgeKey(context.Background(), keyID, scope)
	assert.ErrorIs(t, err, repositories.ErrGlobalPurgeProtectionEnabled)
	repo.AssertNotCalled(t, "List", mock.Anything, mock.Anything, mock.Anything)
	repo.AssertNotCalled(t, "PurgeKey", mock.Anything, mock.Anything)
}

func TestPurgeKey_BlockedWhenVaultIsPurgeProtected(t *testing.T) {
	vaultID := uuid.New()
	keyID := uuid.New()
	scope := model.NewVaultScope(vaultID, uuid.New())
	now := time.Now()

	repo := &mockKeyRepository{}
	repo.On("List", mock.Anything, scope, repositories.KeyFilter{OnlyDeleted: true}).
		Return([]model.Key{{ID: keyID, VaultID: vaultID, DeletedAt: &now}}, nil)

	vaultRepo := &mockVaultRepository{}
	vaultRepo.On("ReadByID", mock.Anything, vaultID).
		Return(&model.Vault{ID: vaultID, PurgeProtection: true}, nil)

	svc := NewKeyService(KeyServiceConfig{
		KeyRepository:   repo,
		VaultRepository: vaultRepo,
		Logger:          newKeyLogger(),
	})

	err := svc.PurgeKey(context.Background(), keyID, scope)
	require.ErrorIs(t, err, repositories.ErrKeyPurgeProtected)
	repo.AssertNotCalled(t, "PurgeKey", mock.Anything, mock.Anything)
	vaultRepo.AssertExpectations(t)
}

// TestPurgeKey_BlockedWhenVaultReadFails pins the fail-closed behaviour: a
// vault that cannot be read blocks the purge rather than silently skipping the
// only protection layer a key without its own flag has.
func TestPurgeKey_BlockedWhenVaultReadFails(t *testing.T) {
	vaultID := uuid.New()
	keyID := uuid.New()
	scope := model.NewVaultScope(vaultID, uuid.New())
	now := time.Now()

	repo := &mockKeyRepository{}
	repo.On("List", mock.Anything, scope, repositories.KeyFilter{OnlyDeleted: true}).
		Return([]model.Key{{ID: keyID, VaultID: vaultID, DeletedAt: &now}}, nil)

	readErr := errors.New("database is locked")
	vaultRepo := &mockVaultRepository{}
	vaultRepo.On("ReadByID", mock.Anything, vaultID).Return(nil, readErr)

	svc := NewKeyService(KeyServiceConfig{
		KeyRepository:   repo,
		VaultRepository: vaultRepo,
		Logger:          newKeyLogger(),
	})

	err := svc.PurgeKey(context.Background(), keyID, scope)
	require.Error(t, err)
	require.ErrorIs(t, err, readErr, "the vault-read failure must stay in the returned error chain")
	repo.AssertNotCalled(t, "PurgeKey", mock.Anything, mock.Anything)
	vaultRepo.AssertExpectations(t)
}

// TestPurgeKey_ProceedsWhenVaultIsNotPurgeProtected verifies the cascade check
// does not block an unprotected vault.
func TestPurgeKey_ProceedsWhenVaultIsNotPurgeProtected(t *testing.T) {
	vaultID := uuid.New()
	keyID := uuid.New()
	scope := model.NewVaultScope(vaultID, uuid.New())
	now := time.Now()

	repo := &mockKeyRepository{}
	repo.On("List", mock.Anything, scope, repositories.KeyFilter{OnlyDeleted: true}).
		Return([]model.Key{{ID: keyID, VaultID: vaultID, DeletedAt: &now}}, nil)
	repo.On("PurgeKey", mock.Anything, keyID).Return(nil)

	vaultRepo := &mockVaultRepository{}
	vaultRepo.On("ReadByID", mock.Anything, vaultID).Return(&model.Vault{ID: vaultID}, nil)

	svc := NewKeyService(KeyServiceConfig{
		KeyRepository:   repo,
		VaultRepository: vaultRepo,
		Logger:          newKeyLogger(),
	})

	require.NoError(t, svc.PurgeKey(context.Background(), keyID, scope))
	repo.AssertExpectations(t)
	vaultRepo.AssertExpectations(t)
}

// auditRecord is one persisted audit row.
type auditRecord struct {
	userID  string
	action  string
	details string
}

// recordingAuditPersister captures the audit rows a service emitted. Mirrors
// the helper defined in internal/services/secrets/direct_write_invalidation_test.go.
type recordingAuditPersister struct {
	mu      sync.Mutex
	records []auditRecord
}

func (p *recordingAuditPersister) PersistAudit(userID, action, details string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.records = append(p.records, auditRecord{userID, action, details})
	return nil
}

func (p *recordingAuditPersister) find(action, status string) (auditRecord, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, rec := range p.records {
		if rec.action == action && strings.Contains(rec.details, "status="+status) {
			return rec, true
		}
	}
	return auditRecord{}, false
}

// newAuditingLogger returns a quiet logger whose audit calls are captured.
func newAuditingLogger(t *testing.T) (*logging.Logger, *recordingAuditPersister) {
	t.Helper()
	l := logrus.New()
	l.SetLevel(logrus.PanicLevel)
	logger := logging.WrapLogrus(l)
	persister := &recordingAuditPersister{}
	logger.SetAuditPersister(persister)
	return logger, persister
}

// TestRecoverKey_LogsSuccessAudit verifies RecoverKey emits a success audit
// row attributed to the scope's actor.
func TestRecoverKey_LogsSuccessAudit(t *testing.T) {
	owner := uuid.New()
	vaultID := uuid.New()
	scope := model.NewVaultScope(vaultID, owner)
	keyID := uuid.New()
	now := time.Now()

	repo := &mockKeyRepository{}
	repo.On("List", mock.Anything, scope, repositories.KeyFilter{OnlyDeleted: true}).
		Return([]model.Key{{ID: keyID, Name: "k", Type: model.KeyTypeRSA, DeletedAt: &now}}, nil)
	repo.On("RecoverKey", mock.Anything, keyID).Return(nil)

	logger, audit := newAuditingLogger(t)
	svc := NewKeyService(KeyServiceConfig{KeyRepository: repo, Logger: logger})

	require.NoError(t, svc.RecoverKey(context.Background(), keyID, scope))

	rec, ok := audit.find("recover_key", "success")
	require.True(t, ok, "RecoverKey must emit a success audit row")
	assert.Equal(t, owner.String(), rec.userID)
}

// TestPurgeKey_LogsSuccessAudit mirrors TestRecoverKey_LogsSuccessAudit for purge.
func TestPurgeKey_LogsSuccessAudit(t *testing.T) {
	owner := uuid.New()
	vaultID := uuid.New()
	scope := model.NewVaultScope(vaultID, owner)
	keyID := uuid.New()
	now := time.Now()

	repo := &mockKeyRepository{}
	repo.On("List", mock.Anything, scope, repositories.KeyFilter{OnlyDeleted: true}).
		Return([]model.Key{{ID: keyID, Name: "k", Type: model.KeyTypeRSA, DeletedAt: &now}}, nil)
	repo.On("PurgeKey", mock.Anything, keyID).Return(nil)

	logger, audit := newAuditingLogger(t)
	svc := NewKeyService(KeyServiceConfig{KeyRepository: repo, Logger: logger})

	require.NoError(t, svc.PurgeKey(context.Background(), keyID, scope))

	rec, ok := audit.find("purge_key", "success")
	require.True(t, ok, "PurgeKey must emit a success audit row")
	assert.Equal(t, owner.String(), rec.userID)
}
