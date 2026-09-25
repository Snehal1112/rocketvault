// Package api — internal tests for backup item handlers.
package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"

	"rocketvault/app"
	"rocketvault/common"
	"rocketvault/internal/backup"
	"rocketvault/internal/repositories"
	"rocketvault/model"
)

// ============================================================
// itemBackupSvc (accessor helper)
// ============================================================

// TestItemBackupSvc_NilApp_SetsErr verifies that itemBackupSvc returns nil
// and sets an internal error when c.App is nil.
func TestItemBackupSvc_NilApp_SetsErr(t *testing.T) {
	c := &Context{App: nil, Params: &ApiParams{}}
	svc := itemBackupSvc(c)
	assert.Nil(t, svc)
	assert.NotNil(t, c.Err)
	assert.Equal(t, http.StatusInternalServerError, c.Err.StatusCode)
}

// TestItemBackupSvc_NilContainer_SetsErr verifies that itemBackupSvc returns nil
// and sets an internal error when the service container is nil.
func TestItemBackupSvc_NilContainer_SetsErr(t *testing.T) {
	c := &Context{App: &app.App{ServiceContainer: nil}, Params: &ApiParams{}}
	svc := itemBackupSvc(c)
	assert.Nil(t, svc)
	assert.NotNil(t, c.Err)
	assert.Equal(t, http.StatusInternalServerError, c.Err.StatusCode)
}

// ============================================================
// getUserID (backup_item helper)
// ============================================================

// TestGetUserID_MissingClaim_SetsErr verifies that getUserID returns false
// when user_id is absent from the claims. RequestClaims is a value type, so a
// zero-value Context has UserID == "", which fails uuid.Parse the same way an
// invalid UUID does — getUserID has no way to distinguish "absent" from
// "empty string", so this now surfaces as the same 400 as an invalid UUID.
func TestGetUserID_MissingClaim_SetsErr(t *testing.T) {
	c := &Context{Claims: RequestClaims{}, Params: &ApiParams{}}
	id, ok := getUserID(c)
	assert.False(t, ok)
	assert.Equal(t, uuid.Nil, id)
	assert.NotNil(t, c.Err)
	assert.Equal(t, http.StatusBadRequest, c.Err.StatusCode)
}

// TestGetUserID_InvalidUUID_SetsErr verifies that getUserID returns false
// when user_id cannot be parsed as a UUID.
func TestGetUserID_InvalidUUID_SetsErr(t *testing.T) {
	c := &Context{Claims: RequestClaims{UserID: "not-a-uuid"}, Params: &ApiParams{}}
	id, ok := getUserID(c)
	assert.False(t, ok)
	assert.Equal(t, uuid.Nil, id)
	assert.NotNil(t, c.Err)
	assert.Equal(t, http.StatusBadRequest, c.Err.StatusCode)
}

// TestGetUserID_ValidUUID_ReturnsID verifies that getUserID parses a valid UUID correctly.
func TestGetUserID_ValidUUID_ReturnsID(t *testing.T) {
	expected := uuid.New()
	c := &Context{Claims: RequestClaims{UserID: expected.String()}, Params: &ApiParams{}}
	id, ok := getUserID(c)
	assert.True(t, ok)
	assert.Equal(t, expected, id)
	assert.Nil(t, c.Err)
}

// ============================================================
// backupSecretHandler
// ============================================================

// TestBackupSecretHandler_InvalidSecretID_Returns400 verifies that a malformed
// secret_id path param is rejected before reaching the backup service.
func TestBackupSecretHandler_InvalidSecretID_Returns400(t *testing.T) {
	c := &Context{
		App:    &app.App{},
		Claims: RequestClaims{UserID: uuid.New().String()},
		Params: &ApiParams{SecretID: "not-a-uuid", PerPage: 60},
	}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/secrets/bad/backup", nil)

	backupSecretHandler(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestBackupSecretHandler_NilContainer_Returns500 verifies that a nil service
// container causes the handler to set an internal error via itemBackupSvc.
func TestBackupSecretHandler_NilContainer_Returns500(t *testing.T) {
	c := &Context{
		App:    &app.App{ServiceContainer: nil},
		Claims: RequestClaims{UserID: uuid.New().String()},
		Params: &ApiParams{SecretID: uuid.New().String(), PerPage: 60},
	}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/secrets/"+c.Params.SecretID+"/backup", nil)

	backupSecretHandler(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

// ============================================================
// restoreSecretHandler
// ============================================================

// TestRestoreSecretHandler_InvalidJSON_Returns400 verifies that a missing or
// empty blob field is rejected with 400.
func TestRestoreSecretHandler_InvalidJSON_Returns400(t *testing.T) {
	c := &Context{
		App:    &app.App{},
		Claims: RequestClaims{UserID: uuid.New().String()},
		Params: &ApiParams{PerPage: 60},
	}
	w := httptest.NewRecorder()
	// Blob field is empty.
	r := httptest.NewRequest(http.MethodPost, "/secrets/restore", bytes.NewReader([]byte(`{"blob":""}`)))

	restoreSecretHandler(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ============================================================
// backupKeyHandler
// ============================================================

func TestBackupKeyHandler_InvalidKeyID_Returns400(t *testing.T) {
	c := &Context{
		App:    &app.App{},
		Claims: RequestClaims{UserID: uuid.New().String()},
		Params: &ApiParams{KeyID: "bad", PerPage: 60},
	}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/keys/bad/backup", nil)

	backupKeyHandler(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestBackupKeyHandler_NilContainer_Returns500(t *testing.T) {
	c := &Context{
		App:    &app.App{ServiceContainer: nil},
		Claims: RequestClaims{UserID: uuid.New().String()},
		Params: &ApiParams{KeyID: uuid.New().String(), PerPage: 60},
	}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/keys/"+c.Params.KeyID+"/backup", nil)

	backupKeyHandler(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

// ============================================================
// restoreKeyHandler
// ============================================================

func TestRestoreKeyHandler_EmptyBlob_Returns400(t *testing.T) {
	c := &Context{
		App:    &app.App{},
		Claims: RequestClaims{UserID: uuid.New().String()},
		Params: &ApiParams{PerPage: 60},
	}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/keys/restore", bytes.NewReader([]byte(`{"blob":""}`)))

	restoreKeyHandler(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ============================================================
// backupCertificateHandler
// ============================================================

func TestBackupCertificateHandler_InvalidCertID_Returns400(t *testing.T) {
	c := &Context{
		App:    &app.App{},
		Claims: RequestClaims{UserID: uuid.New().String()},
		Params: &ApiParams{CertificateID: "bad", PerPage: 60},
	}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/certificates/bad/backup", nil)

	backupCertificateHandler(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestBackupCertificateHandler_NilContainer_Returns500(t *testing.T) {
	c := &Context{
		App:    &app.App{ServiceContainer: nil},
		Claims: RequestClaims{UserID: uuid.New().String()},
		Params: &ApiParams{CertificateID: uuid.New().String(), PerPage: 60},
	}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/certificates/"+c.Params.CertificateID+"/backup", nil)

	backupCertificateHandler(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

// ============================================================
// restoreCertificateHandler
// ============================================================

func TestRestoreCertificateHandler_EmptyBlob_Returns400(t *testing.T) {
	c := &Context{
		App:    &app.App{},
		Claims: RequestClaims{UserID: uuid.New().String()},
		Params: &ApiParams{PerPage: 60},
	}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/certificates/restore", bytes.NewReader([]byte(`{"blob":""}`)))

	restoreCertificateHandler(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ============================================================
// backupItemContainer — minimal container that exposes an ItemBackupService.
// ============================================================

// backupItemContainer is a minimal service-container stub that only
// implements GetItemBackupService() and delegates the RBAC call to a no-op.
type backupItemContainer struct {
	*secretSvcTestContainer
	backupSvc *backup.ItemBackupService
}

func (c *backupItemContainer) GetItemBackupService() *backup.ItemBackupService {
	return c.backupSvc
}

// ============================================================
// Minimal mock repositories for backup.ItemBackupService construction.
// ============================================================

// mockSecretRepo is a minimal SecretRepositoryInterface implementation for
// backup tests. Only Create and Read are expected to be called.
type mockSecretRepo struct {
	readFn    func(ctx context.Context, id uuid.UUID) (*model.Secret, error)
	createFn  func(ctx context.Context, secret *model.Secret) error
	lastScope model.Scope
}

func (m *mockSecretRepo) Create(ctx context.Context, secret *model.Secret) error {
	if m.createFn != nil {
		return m.createFn(ctx, secret)
	}
	return nil
}
func (m *mockSecretRepo) Read(ctx context.Context, id uuid.UUID, scope model.Scope) (*model.Secret, error) {
	m.lastScope = scope
	if m.readFn != nil {
		return m.readFn(ctx, id)
	}
	return nil, errors.New("not found")
}
func (m *mockSecretRepo) FindByName(_ context.Context, _ string, _ model.Scope) (*model.Secret, error) {
	return nil, errors.New("not implemented")
}
func (m *mockSecretRepo) Update(_ context.Context, _ *model.Secret, _ model.Scope) error {
	return errors.New("not implemented")
}
func (m *mockSecretRepo) List(_ context.Context, _ model.Scope, _ repositories.SecretFilter) ([]model.Secret, error) {
	return nil, nil
}
func (m *mockSecretRepo) Delete(_ context.Context, _ uuid.UUID) error { return nil }
func (m *mockSecretRepo) SoftDelete(_ context.Context, _ uuid.UUID) error {
	return errors.New("not implemented")
}
func (m *mockSecretRepo) RecoverSecret(_ context.Context, _ uuid.UUID) error {
	return errors.New("not implemented")
}
func (m *mockSecretRepo) ExportSecrets(_ context.Context, _ model.ExportOptions) ([]byte, error) {
	return nil, nil
}
func (m *mockSecretRepo) ImportSecrets(_ context.Context, _ []byte, _ model.ImportOptions) (int, error) {
	return 0, nil
}
func (m *mockSecretRepo) GetVersions(_ context.Context, _ uuid.UUID) ([]model.SecretVersion, error) {
	return nil, nil
}
func (m *mockSecretRepo) GetVersion(_ context.Context, _ uuid.UUID, _ int) (*model.SecretVersion, error) {
	return nil, nil
}
func (m *mockSecretRepo) GetLatestVersion(_ context.Context, _ uuid.UUID) (*model.SecretVersion, error) {
	return nil, nil
}
func (m *mockSecretRepo) PurgeSecret(_ context.Context, _ uuid.UUID) error { return nil }
func (m *mockSecretRepo) SetPurgeProtection(_ context.Context, _ uuid.UUID, _ bool) error {
	return nil
}
func (m *mockSecretRepo) SoftDeleteVaultContents(_ context.Context, _ uuid.UUID, _ time.Time) error {
	return nil
}
func (m *mockSecretRepo) RecoverVaultContents(_ context.Context, _ uuid.UUID, _ time.Time) error {
	return nil
}

// mockVersionRepo is a minimal SecretVersionRepositoryInterface for backup
// tests that exercise BackupSecret's success path. BackupSecret always calls
// GetVersions after a successful Read, so passing nil here would panic —
// unlike the key/cert-only test helpers, which never reach this repo.
type mockVersionRepo struct{}

func (m *mockVersionRepo) CreateVersion(_ context.Context, _ *model.SecretVersion) error {
	return nil
}
func (m *mockVersionRepo) GetVersions(_ context.Context, _ uuid.UUID) ([]model.SecretVersion, error) {
	return nil, nil
}
func (m *mockVersionRepo) GetVersion(_ context.Context, _ uuid.UUID, _ int) (*model.SecretVersion, error) {
	return nil, nil
}
func (m *mockVersionRepo) GetLatestVersion(_ context.Context, _ uuid.UUID) (*model.SecretVersion, error) {
	return nil, nil
}
func (m *mockVersionRepo) DeleteVersions(_ context.Context, _ uuid.UUID) error { return nil }
func (m *mockVersionRepo) DeleteSpecificVersion(_ context.Context, _ uuid.UUID, _ int) error {
	return nil
}

// newBackupCtxWithSecret creates a Context backed by a real ItemBackupService
// that uses a custom mockSecretRepo, allowing success-path testing.
func newBackupCtxWithSecret(secretRepo *mockSecretRepo) *Context {
	svc := backup.NewItemBackupService(secretRepo, nil, nil, &mockVersionRepo{})
	container := &backupItemContainer{
		secretSvcTestContainer: &secretSvcTestContainer{},
		backupSvc:              svc,
	}
	return &Context{
		App:    &app.App{ServiceContainer: container},
		Claims: RequestClaims{UserID: secretHTestUserID},
		Params: &ApiParams{PerPage: 60},
	}
}

// ============================================================
// backupSecretHandler — success and not-found paths
// ============================================================

// TestBackupSecretHandler_Success_Returns200 verifies the happy path returns the blob.
func TestBackupSecretHandler_Success_Returns200(t *testing.T) {
	secretID := uuid.New()
	userID := uuid.MustParse(secretHTestUserID)
	secretRepo := &mockSecretRepo{
		readFn: func(_ context.Context, id uuid.UUID) (*model.Secret, error) {
			return &model.Secret{ID: id, Name: "s", Value: "v", UserID: userID}, nil
		},
	}

	c := newBackupCtxWithSecret(secretRepo)
	c.Params = &ApiParams{SecretID: secretID.String(), PerPage: 60}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/secrets/"+secretID.String()+"/backup", nil)

	backupSecretHandler(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusOK, w.Code)
	var body map[string]any
	assert.NoError(t, json.NewDecoder(w.Body).Decode(&body))
	assert.NotEmpty(t, body["blob"])
}

// TestBackupSecretHandler_NotFound_Returns404 verifies that a repo error maps to 404.
func TestBackupSecretHandler_NotFound_Returns404(t *testing.T) {
	secretID := uuid.New()
	secretRepo := &mockSecretRepo{
		readFn: func(_ context.Context, _ uuid.UUID) (*model.Secret, error) {
			return nil, errors.New("not found")
		},
	}

	c := newBackupCtxWithSecret(secretRepo)
	c.Params = &ApiParams{SecretID: secretID.String(), PerPage: 60}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/secrets/"+secretID.String()+"/backup", nil)

	backupSecretHandler(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusNotFound, w.Code)
}

// TestBackupSecretHandler_ScopesReadToRequestVault verifies that the vault
// resolved from the request (vaultIDFromRequest, via common.VaultIDKey) is
// threaded through to the repository's Read call as the scope's vault, paired
// with the caller's user ID — not transposed, and not dropped in favor of
// uuid.Nil. mockSecretRepo.Read previously discarded its scope argument
// entirely, so a bug that swapped or zeroed backupSecretHandler's call to
// svc.BackupSecret(ctx, secretID, userID, vaultID) would compile and pass
// every other test in this file; this test pins the actual scope produced.
func TestBackupSecretHandler_ScopesReadToRequestVault(t *testing.T) {
	secretID := uuid.New()
	userID := uuid.MustParse(secretHTestUserID)
	vaultID := uuid.New()
	secretRepo := &mockSecretRepo{
		readFn: func(_ context.Context, id uuid.UUID) (*model.Secret, error) {
			return &model.Secret{ID: id, Name: "s", Value: "v", UserID: userID}, nil
		},
	}

	c := newBackupCtxWithSecret(secretRepo)
	c.Params = &ApiParams{SecretID: secretID.String(), PerPage: 60}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/secrets/"+secretID.String()+"/backup", nil)
	r = r.WithContext(context.WithValue(r.Context(), common.VaultIDKey, vaultID.String()))

	backupSecretHandler(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, model.NewVaultScope(vaultID, userID), secretRepo.lastScope)
}

// ============================================================
// restoreSecretHandler — error and success paths
// ============================================================

// buildValidSecretBlob creates a valid backup blob for a secret.
func buildValidSecretBlob(t *testing.T, secretID, userID uuid.UUID) string {
	t.Helper()
	secretRepo := &mockSecretRepo{
		readFn: func(_ context.Context, id uuid.UUID) (*model.Secret, error) {
			return &model.Secret{ID: id, Name: "s", Value: "v", UserID: userID}, nil
		},
	}
	svc := backup.NewItemBackupService(secretRepo, nil, nil, &mockVersionRepo{})
	blob, err := svc.BackupSecret(context.Background(), secretID, userID, uuid.Nil)
	if err != nil {
		t.Fatalf("buildValidSecretBlob: %v", err)
	}
	return blob
}

// TestRestoreSecretHandler_InvalidBlob_Returns400 verifies that ErrInvalidBlob maps to 400.
func TestRestoreSecretHandler_InvalidBlob_Returns400(t *testing.T) {
	secretRepo := &mockSecretRepo{}
	c := newBackupCtxWithSecret(secretRepo)
	w := httptest.NewRecorder()
	// Base64 string that decodes to invalid JSON.
	badBlob := "dGhpcyBpcyBub3QgYW4gZW52ZWxvcGU=" // "this is not an envelope"
	body, _ := json.Marshal(map[string]string{"blob": badBlob})
	r := httptest.NewRequest(http.MethodPost, "/secrets/restore", bytes.NewReader(body))

	restoreSecretHandler(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestRestoreSecretHandler_CreateError_Returns500 verifies that a generic repo error
// during restore maps to 500.
func TestRestoreSecretHandler_CreateError_Returns500(t *testing.T) {
	secretID := uuid.New()
	userID := uuid.MustParse(secretHTestUserID)
	blob := buildValidSecretBlob(t, secretID, userID)

	// The repo Create call returns a generic db error; RestoreSecret maps it to 500.
	secretRepo := &mockSecretRepo{
		readFn: func(_ context.Context, id uuid.UUID) (*model.Secret, error) {
			return &model.Secret{ID: id, Name: "s", Value: "v", UserID: userID}, nil
		},
		createFn: func(_ context.Context, _ *model.Secret) error {
			return errors.New("db error")
		},
	}

	c := newBackupCtxWithSecret(secretRepo)
	w := httptest.NewRecorder()
	body, _ := json.Marshal(map[string]string{"blob": blob})
	r := httptest.NewRequest(http.MethodPost, "/secrets/restore", bytes.NewReader(body))

	restoreSecretHandler(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

// TestRestoreSecretHandler_Success_Returns200 verifies the happy path.
func TestRestoreSecretHandler_Success_Returns200(t *testing.T) {
	secretID := uuid.New()
	userID := uuid.MustParse(secretHTestUserID)
	blob := buildValidSecretBlob(t, secretID, userID)

	secretRepo := &mockSecretRepo{
		readFn: func(_ context.Context, id uuid.UUID) (*model.Secret, error) {
			return &model.Secret{ID: id, Name: "s", Value: "v", UserID: userID}, nil
		},
		createFn: func(_ context.Context, _ *model.Secret) error {
			return nil
		},
	}

	c := newBackupCtxWithSecret(secretRepo)
	w := httptest.NewRecorder()
	body, _ := json.Marshal(map[string]string{"blob": blob})
	r := httptest.NewRequest(http.MethodPost, "/secrets/restore", bytes.NewReader(body))

	restoreSecretHandler(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusOK, w.Code)
}

// TestRestoreSecretHandler_WritesRequestVaultNotBlobVault verifies that the
// restore handler persists the vault ID resolved from the request (via
// vaultIDFromRequest), not the vault ID embedded in the backup blob. A user
// authorized in vaultB, restoring a blob whose embedded vault is vaultA,
// must land the restored secret in vaultB — not silently write into vaultA.
func TestRestoreSecretHandler_WritesRequestVaultNotBlobVault(t *testing.T) {
	vaultA := uuid.New()
	vaultB := uuid.New()
	secretID := uuid.New()
	userID := uuid.MustParse(secretHTestUserID)

	// Build a blob for a secret scoped to vaultA.
	blobSecretRepo := &mockSecretRepo{
		readFn: func(_ context.Context, id uuid.UUID) (*model.Secret, error) {
			return &model.Secret{ID: id, Name: "s", Value: "v", UserID: userID, VaultID: vaultA}, nil
		},
	}
	blobSvc := backup.NewItemBackupService(blobSecretRepo, nil, nil, &mockVersionRepo{})
	blob, err := blobSvc.BackupSecret(context.Background(), secretID, userID, uuid.Nil)
	if err != nil {
		t.Fatalf("failed to build blob: %v", err)
	}

	var createdVaultID uuid.UUID
	secretRepo := &mockSecretRepo{
		createFn: func(_ context.Context, secret *model.Secret) error {
			createdVaultID = secret.VaultID
			return nil
		},
	}

	c := newBackupCtxWithSecret(secretRepo)
	w := httptest.NewRecorder()
	body, _ := json.Marshal(map[string]string{"blob": blob})
	r := httptest.NewRequest(http.MethodPost, "/secrets/restore", bytes.NewReader(body))
	r = r.WithContext(context.WithValue(r.Context(), common.VaultIDKey, vaultB.String()))

	restoreSecretHandler(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, vaultB, createdVaultID, "restore must write the vault authorized by the request, not the blob's embedded vault")
	assert.NotEqual(t, vaultA, createdVaultID, "restore must not write the blob's embedded vault")
}

// TestRestoreSecretHandler_NilContainer_Returns500 verifies nil container handling.
func TestRestoreSecretHandler_NilContainer_Returns500(t *testing.T) {
	secretID := uuid.New()
	userID := uuid.MustParse(secretHTestUserID)
	blob := buildValidSecretBlob(t, secretID, userID)

	c := &Context{
		App:    &app.App{ServiceContainer: nil},
		Claims: RequestClaims{UserID: userID.String()},
		Params: &ApiParams{PerPage: 60},
	}
	w := httptest.NewRecorder()
	body, _ := json.Marshal(map[string]string{"blob": blob})
	r := httptest.NewRequest(http.MethodPost, "/secrets/restore", bytes.NewReader(body))

	restoreSecretHandler(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

// ============================================================
// Minimal key and certificate repo mocks
// ============================================================

// mockKeyRepo is a minimal KeyRepositoryInterface for backup tests.
type mockKeyRepo struct {
	readFn    func(ctx context.Context, id uuid.UUID) (*model.Key, error)
	createFn  func(ctx context.Context, key *model.Key) error
	lastScope model.Scope
}

func (m *mockKeyRepo) Create(ctx context.Context, key *model.Key) error {
	if m.createFn != nil {
		return m.createFn(ctx, key)
	}
	return nil
}
func (m *mockKeyRepo) Read(ctx context.Context, id uuid.UUID, scope model.Scope) (*model.Key, error) {
	m.lastScope = scope
	if m.readFn != nil {
		return m.readFn(ctx, id)
	}
	return nil, errors.New("not found")
}
func (m *mockKeyRepo) Update(_ context.Context, _ *model.Key, _ model.Scope) error {
	return errors.New("not implemented")
}
func (m *mockKeyRepo) List(_ context.Context, _ model.Scope, _ repositories.KeyFilter) ([]model.Key, error) {
	return nil, nil
}
func (m *mockKeyRepo) Delete(_ context.Context, _ uuid.UUID) error { return nil }
func (m *mockKeyRepo) UpdateRevocationStatus(_ context.Context, _ uuid.UUID, _ bool) error {
	return nil
}
func (m *mockKeyRepo) SoftDelete(_ context.Context, _ uuid.UUID) error                 { return nil }
func (m *mockKeyRepo) RecoverKey(_ context.Context, _ uuid.UUID) error                 { return nil }
func (m *mockKeyRepo) PurgeKey(_ context.Context, _ uuid.UUID) error                   { return nil }
func (m *mockKeyRepo) SetPurgeProtection(_ context.Context, _ uuid.UUID, _ bool) error { return nil }
func (m *mockKeyRepo) ReadDeletedScoped(_ context.Context, _ uuid.UUID, _ model.Scope) (*model.Key, error) {
	return nil, nil
}
func (m *mockKeyRepo) CreateVersion(_ context.Context, _ uuid.UUID, _ int, _ string) error {
	return nil
}
func (m *mockKeyRepo) ListVersions(_ context.Context, _ uuid.UUID) ([]model.KeyVersion, error) {
	return nil, nil
}
func (m *mockKeyRepo) CurrentVersion(_ context.Context, _ uuid.UUID) (int, error) {
	return 1, nil
}
func (m *mockKeyRepo) ReadVersionValue(_ context.Context, _ uuid.UUID, _ int) (string, error) {
	return "", nil
}
func (m *mockKeyRepo) GetVersion(_ context.Context, _ uuid.UUID, _ int) (*model.KeyVersion, error) {
	return nil, nil
}
func (m *mockKeyRepo) ListVersionRecords(_ context.Context, _ uuid.UUID) ([]model.KeyVersionRecord, error) {
	return nil, nil
}
func (m *mockKeyRepo) SoftDeleteVaultContents(_ context.Context, _ uuid.UUID, _ time.Time) error {
	return nil
}
func (m *mockKeyRepo) RecoverVaultContents(_ context.Context, _ uuid.UUID, _ time.Time) error {
	return nil
}

// mockCertRepo is a minimal CertificateRepositoryInterface for backup tests.
type mockCertRepo struct {
	readFn    func(ctx context.Context, id uuid.UUID) (*model.Certificate, error)
	createFn  func(ctx context.Context, cert *model.Certificate) error
	lastScope model.Scope
}

func (m *mockCertRepo) Create(ctx context.Context, cert *model.Certificate) error {
	if m.createFn != nil {
		return m.createFn(ctx, cert)
	}
	return nil
}
func (m *mockCertRepo) Read(ctx context.Context, id uuid.UUID, scope model.Scope) (*model.Certificate, error) {
	m.lastScope = scope
	if m.readFn != nil {
		return m.readFn(ctx, id)
	}
	return nil, errors.New("not found")
}
func (m *mockCertRepo) Update(_ context.Context, _ *model.Certificate, _ model.Scope) error {
	return errors.New("not implemented")
}
func (m *mockCertRepo) List(_ context.Context, _ model.Scope, _ repositories.CertificateFilter) ([]model.Certificate, error) {
	return nil, nil
}
func (m *mockCertRepo) ListDueForRenewal(_ context.Context, _ model.Scope) ([]model.Certificate, error) {
	return nil, nil
}
func (m *mockCertRepo) Delete(_ context.Context, _ uuid.UUID) error              { return nil }
func (m *mockCertRepo) Revoke(_ context.Context, _ uuid.UUID, _, _ string) error { return nil }
func (m *mockCertRepo) SoftDelete(_ context.Context, _ uuid.UUID) error          { return nil }
func (m *mockCertRepo) RecoverCertificate(_ context.Context, _ uuid.UUID) error  { return nil }
func (m *mockCertRepo) PurgeCertificate(_ context.Context, _ uuid.UUID) error    { return nil }
func (m *mockCertRepo) ListRevoked(_ context.Context, _ uuid.UUID) ([]model.RevokedCertificate, error) {
	return nil, nil
}
func (m *mockCertRepo) SetPurgeProtection(_ context.Context, _ uuid.UUID, _ bool) error { return nil }
func (m *mockCertRepo) ListAll(_ context.Context) ([]model.Certificate, error)          { return nil, nil }
func (m *mockCertRepo) SoftDeleteVaultContents(_ context.Context, _ uuid.UUID, _ time.Time) error {
	return nil
}
func (m *mockCertRepo) RecoverVaultContents(_ context.Context, _ uuid.UUID, _ time.Time) error {
	return nil
}

// backupItemContainerWithKey provides an ItemBackupService with a key repo.
type backupItemContainerWithKey struct {
	*secretSvcTestContainer
	backupSvc *backup.ItemBackupService
}

func (c *backupItemContainerWithKey) GetItemBackupService() *backup.ItemBackupService {
	return c.backupSvc
}

// newBackupCtxWithKey creates a Context backed by a real ItemBackupService with a key repo.
func newBackupCtxWithKey(keyRepo *mockKeyRepo) *Context {
	svc := backup.NewItemBackupService(nil, keyRepo, nil, nil)
	container := &backupItemContainerWithKey{
		secretSvcTestContainer: &secretSvcTestContainer{},
		backupSvc:              svc,
	}
	return &Context{
		App:    &app.App{ServiceContainer: container},
		Claims: RequestClaims{UserID: secretHTestUserID},
		Params: &ApiParams{PerPage: 60},
	}
}

// backupItemContainerWithCert provides an ItemBackupService with a certificate repo.
type backupItemContainerWithCert struct {
	*secretSvcTestContainer
	backupSvc *backup.ItemBackupService
}

func (c *backupItemContainerWithCert) GetItemBackupService() *backup.ItemBackupService {
	return c.backupSvc
}

// newBackupCtxWithCert creates a Context backed by a real ItemBackupService with a cert repo.
func newBackupCtxWithCert(certRepo *mockCertRepo) *Context {
	svc := backup.NewItemBackupService(nil, nil, certRepo, nil)
	container := &backupItemContainerWithCert{
		secretSvcTestContainer: &secretSvcTestContainer{},
		backupSvc:              svc,
	}
	return &Context{
		App:    &app.App{ServiceContainer: container},
		Claims: RequestClaims{UserID: secretHTestUserID},
		Params: &ApiParams{PerPage: 60},
	}
}

// ============================================================
// backupKeyHandler — success and error paths
// ============================================================

// TestBackupKeyHandler_Success_Returns200 verifies the happy path returns the blob.
func TestBackupKeyHandler_Success_Returns200(t *testing.T) {
	keyID := uuid.New()
	userID := uuid.MustParse(secretHTestUserID)
	keyRepo := &mockKeyRepo{
		readFn: func(_ context.Context, id uuid.UUID) (*model.Key, error) {
			return &model.Key{ID: id, Name: "k", Type: "RSA", UserID: userID}, nil
		},
	}

	c := newBackupCtxWithKey(keyRepo)
	c.Params = &ApiParams{KeyID: keyID.String(), PerPage: 60}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/keys/"+keyID.String()+"/backup", nil)

	backupKeyHandler(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusOK, w.Code)
	var body map[string]any
	assert.NoError(t, json.NewDecoder(w.Body).Decode(&body))
	assert.NotEmpty(t, body["blob"])
}

// TestBackupKeyHandler_NotFound_Returns404 verifies repo error maps to 404.
func TestBackupKeyHandler_NotFound_Returns404(t *testing.T) {
	keyID := uuid.New()
	keyRepo := &mockKeyRepo{
		readFn: func(_ context.Context, _ uuid.UUID) (*model.Key, error) {
			return nil, errors.New("not found")
		},
	}

	c := newBackupCtxWithKey(keyRepo)
	c.Params = &ApiParams{KeyID: keyID.String(), PerPage: 60}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/keys/"+keyID.String()+"/backup", nil)

	backupKeyHandler(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusNotFound, w.Code)
}

// TestBackupKeyHandler_ScopesReadToRequestVault verifies that the vault
// resolved from the request is threaded through to the repository's Read
// call as the scope's vault, paired with the caller's user ID — see
// TestBackupSecretHandler_ScopesReadToRequestVault for why this needs its own
// test rather than relying on the existing success/not-found cases.
func TestBackupKeyHandler_ScopesReadToRequestVault(t *testing.T) {
	keyID := uuid.New()
	userID := uuid.MustParse(secretHTestUserID)
	vaultID := uuid.New()
	keyRepo := &mockKeyRepo{
		readFn: func(_ context.Context, id uuid.UUID) (*model.Key, error) {
			return &model.Key{ID: id, Name: "k", Type: "RSA", UserID: userID}, nil
		},
	}

	c := newBackupCtxWithKey(keyRepo)
	c.Params = &ApiParams{KeyID: keyID.String(), PerPage: 60}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/keys/"+keyID.String()+"/backup", nil)
	r = r.WithContext(context.WithValue(r.Context(), common.VaultIDKey, vaultID.String()))

	backupKeyHandler(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, model.NewVaultScope(vaultID, userID), keyRepo.lastScope)
}

// ============================================================
// restoreKeyHandler — error and success paths
// ============================================================

// buildValidKeyBlob creates a valid backup blob for a key.
func buildValidKeyBlob(t *testing.T, keyID, userID uuid.UUID) string {
	t.Helper()
	keyRepo := &mockKeyRepo{
		readFn: func(_ context.Context, id uuid.UUID) (*model.Key, error) {
			return &model.Key{ID: id, Name: "k", Type: "RSA", UserID: userID}, nil
		},
	}
	svc := backup.NewItemBackupService(nil, keyRepo, nil, nil)
	blob, err := svc.BackupKey(context.Background(), keyID, userID, uuid.Nil)
	if err != nil {
		t.Fatalf("buildValidKeyBlob: %v", err)
	}
	return blob
}

// TestRestoreKeyHandler_Success_Returns200 verifies the happy path.
func TestRestoreKeyHandler_Success_Returns200(t *testing.T) {
	keyID := uuid.New()
	userID := uuid.MustParse(secretHTestUserID)
	blob := buildValidKeyBlob(t, keyID, userID)

	keyRepo := &mockKeyRepo{
		readFn: func(_ context.Context, id uuid.UUID) (*model.Key, error) {
			return &model.Key{ID: id, Name: "k", Type: "RSA", UserID: userID}, nil
		},
		createFn: func(_ context.Context, _ *model.Key) error { return nil },
	}

	c := newBackupCtxWithKey(keyRepo)
	w := httptest.NewRecorder()
	body, _ := json.Marshal(map[string]string{"blob": blob})
	r := httptest.NewRequest(http.MethodPost, "/keys/restore", bytes.NewReader(body))

	restoreKeyHandler(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusOK, w.Code)
}

// TestRestoreKeyHandler_InvalidBlob_Returns400 verifies bad blobs are rejected.
func TestRestoreKeyHandler_InvalidBlob_Returns400(t *testing.T) {
	keyRepo := &mockKeyRepo{}
	c := newBackupCtxWithKey(keyRepo)
	w := httptest.NewRecorder()
	badBlob := "dGhpcyBpcyBub3QgYW4gZW52ZWxvcGU=" // "this is not an envelope"
	body, _ := json.Marshal(map[string]string{"blob": badBlob})
	r := httptest.NewRequest(http.MethodPost, "/keys/restore", bytes.NewReader(body))

	restoreKeyHandler(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestRestoreKeyHandler_ServiceError_Returns500 verifies generic errors map to 500.
func TestRestoreKeyHandler_ServiceError_Returns500(t *testing.T) {
	keyID := uuid.New()
	userID := uuid.MustParse(secretHTestUserID)
	blob := buildValidKeyBlob(t, keyID, userID)

	keyRepo := &mockKeyRepo{
		readFn: func(_ context.Context, id uuid.UUID) (*model.Key, error) {
			return &model.Key{ID: id, Name: "k", Type: "RSA", UserID: userID}, nil
		},
		createFn: func(_ context.Context, _ *model.Key) error {
			return errors.New("db error")
		},
	}

	c := newBackupCtxWithKey(keyRepo)
	w := httptest.NewRecorder()
	body, _ := json.Marshal(map[string]string{"blob": blob})
	r := httptest.NewRequest(http.MethodPost, "/keys/restore", bytes.NewReader(body))

	restoreKeyHandler(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

// TestRestoreKeyHandler_NilContainer_Returns500 verifies nil container handling.
func TestRestoreKeyHandler_NilContainer_Returns500(t *testing.T) {
	keyID := uuid.New()
	userID := uuid.MustParse(secretHTestUserID)
	blob := buildValidKeyBlob(t, keyID, userID)

	c := &Context{
		App:    &app.App{ServiceContainer: nil},
		Claims: RequestClaims{UserID: userID.String()},
		Params: &ApiParams{PerPage: 60},
	}
	w := httptest.NewRecorder()
	body, _ := json.Marshal(map[string]string{"blob": blob})
	r := httptest.NewRequest(http.MethodPost, "/keys/restore", bytes.NewReader(body))

	restoreKeyHandler(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

// ============================================================
// backupCertificateHandler — success and error paths
// ============================================================

// TestBackupCertificateHandler_Success_Returns200 verifies the happy path.
func TestBackupCertificateHandler_Success_Returns200(t *testing.T) {
	certID := uuid.New()
	userID := uuid.MustParse(secretHTestUserID)
	certRepo := &mockCertRepo{
		readFn: func(_ context.Context, id uuid.UUID) (*model.Certificate, error) {
			return &model.Certificate{ID: id, Name: "c", UserID: userID}, nil
		},
	}

	c := newBackupCtxWithCert(certRepo)
	c.Params = &ApiParams{CertificateID: certID.String(), PerPage: 60}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/certificates/"+certID.String()+"/backup", nil)

	backupCertificateHandler(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusOK, w.Code)
	var body map[string]any
	assert.NoError(t, json.NewDecoder(w.Body).Decode(&body))
	assert.NotEmpty(t, body["blob"])
}

// TestBackupCertificateHandler_NotFound_Returns404 verifies repo errors map to 404.
func TestBackupCertificateHandler_NotFound_Returns404(t *testing.T) {
	certID := uuid.New()
	certRepo := &mockCertRepo{
		readFn: func(_ context.Context, _ uuid.UUID) (*model.Certificate, error) {
			return nil, errors.New("not found")
		},
	}

	c := newBackupCtxWithCert(certRepo)
	c.Params = &ApiParams{CertificateID: certID.String(), PerPage: 60}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/certificates/"+certID.String()+"/backup", nil)

	backupCertificateHandler(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusNotFound, w.Code)
}

// TestBackupCertificateHandler_ScopesReadToRequestVault verifies that the
// vault resolved from the request is threaded through to the repository's
// Read call as the scope's vault, paired with the caller's user ID — see
// TestBackupSecretHandler_ScopesReadToRequestVault for why this needs its own
// test rather than relying on the existing success/not-found cases.
func TestBackupCertificateHandler_ScopesReadToRequestVault(t *testing.T) {
	certID := uuid.New()
	userID := uuid.MustParse(secretHTestUserID)
	vaultID := uuid.New()
	certRepo := &mockCertRepo{
		readFn: func(_ context.Context, id uuid.UUID) (*model.Certificate, error) {
			return &model.Certificate{ID: id, Name: "c", UserID: userID}, nil
		},
	}

	c := newBackupCtxWithCert(certRepo)
	c.Params = &ApiParams{CertificateID: certID.String(), PerPage: 60}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/certificates/"+certID.String()+"/backup", nil)
	r = r.WithContext(context.WithValue(r.Context(), common.VaultIDKey, vaultID.String()))

	backupCertificateHandler(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, model.NewVaultScope(vaultID, userID), certRepo.lastScope)
}

// ============================================================
// restoreCertificateHandler — error and success paths
// ============================================================

// buildValidCertBlob creates a valid backup blob for a certificate.
func buildValidCertBlob(t *testing.T, certID, userID uuid.UUID) string {
	t.Helper()
	certRepo := &mockCertRepo{
		readFn: func(_ context.Context, id uuid.UUID) (*model.Certificate, error) {
			return &model.Certificate{ID: id, Name: "c", UserID: userID}, nil
		},
	}
	svc := backup.NewItemBackupService(nil, nil, certRepo, nil)
	blob, err := svc.BackupCertificate(context.Background(), certID, userID, uuid.Nil)
	if err != nil {
		t.Fatalf("buildValidCertBlob: %v", err)
	}
	return blob
}

// TestRestoreCertificateHandler_Success_Returns200 verifies the happy path.
func TestRestoreCertificateHandler_Success_Returns200(t *testing.T) {
	certID := uuid.New()
	userID := uuid.MustParse(secretHTestUserID)
	blob := buildValidCertBlob(t, certID, userID)

	certRepo := &mockCertRepo{
		readFn: func(_ context.Context, id uuid.UUID) (*model.Certificate, error) {
			return &model.Certificate{ID: id, Name: "c", UserID: userID}, nil
		},
		createFn: func(_ context.Context, _ *model.Certificate) error { return nil },
	}

	c := newBackupCtxWithCert(certRepo)
	w := httptest.NewRecorder()
	body, _ := json.Marshal(map[string]string{"blob": blob})
	r := httptest.NewRequest(http.MethodPost, "/certificates/restore", bytes.NewReader(body))

	restoreCertificateHandler(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusOK, w.Code)
}

// TestRestoreCertificateHandler_InvalidBlob_Returns400 verifies bad blobs are rejected.
func TestRestoreCertificateHandler_InvalidBlob_Returns400(t *testing.T) {
	certRepo := &mockCertRepo{}
	c := newBackupCtxWithCert(certRepo)
	w := httptest.NewRecorder()
	badBlob := "dGhpcyBpcyBub3QgYW4gZW52ZWxvcGU="
	body, _ := json.Marshal(map[string]string{"blob": badBlob})
	r := httptest.NewRequest(http.MethodPost, "/certificates/restore", bytes.NewReader(body))

	restoreCertificateHandler(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestRestoreCertificateHandler_ServiceError_Returns500 verifies generic errors map to 500.
func TestRestoreCertificateHandler_ServiceError_Returns500(t *testing.T) {
	certID := uuid.New()
	userID := uuid.MustParse(secretHTestUserID)
	blob := buildValidCertBlob(t, certID, userID)

	certRepo := &mockCertRepo{
		readFn: func(_ context.Context, id uuid.UUID) (*model.Certificate, error) {
			return &model.Certificate{ID: id, Name: "c", UserID: userID}, nil
		},
		createFn: func(_ context.Context, _ *model.Certificate) error {
			return errors.New("db error")
		},
	}

	c := newBackupCtxWithCert(certRepo)
	w := httptest.NewRecorder()
	body, _ := json.Marshal(map[string]string{"blob": blob})
	r := httptest.NewRequest(http.MethodPost, "/certificates/restore", bytes.NewReader(body))

	restoreCertificateHandler(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

// TestRestoreCertificateHandler_NilContainer_Returns500 verifies nil container handling.
func TestRestoreCertificateHandler_NilContainer_Returns500(t *testing.T) {
	certID := uuid.New()
	userID := uuid.MustParse(secretHTestUserID)
	blob := buildValidCertBlob(t, certID, userID)

	c := &Context{
		App:    &app.App{ServiceContainer: nil},
		Claims: RequestClaims{UserID: userID.String()},
		Params: &ApiParams{PerPage: 60},
	}
	w := httptest.NewRecorder()
	body, _ := json.Marshal(map[string]string{"blob": blob})
	r := httptest.NewRequest(http.MethodPost, "/certificates/restore", bytes.NewReader(body))

	restoreCertificateHandler(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

// ============================================================
// InitBackupItem — vault-scoped route registration
// ============================================================

// TestInitBackupItem_RegistersVaultScopedRoutes verifies that backup/restore
// for secrets, keys, and certificates resolve under the vault-scoped path
// shape (/vaults/{vault_name}/...), not just the legacy flat routes. Route
// matching only, no handler dispatch, so it needs no service container.
func TestInitBackupItem_RegistersVaultScopedRoutes(t *testing.T) {
	router := mux.NewRouter()
	testAPI := &API{
		BaseRoutes: &Routes{},
		basePath:   "/api/v1",
		rootRouter: router,
	}
	r := testAPI.BaseRoutes
	r.ApiRoot = router.PathPrefix("/api/v1").Subrouter()
	r.Vaults = r.ApiRoot.PathPrefix("/vaults").Subrouter()
	r.VaultScoped = r.Vaults.PathPrefix("/{vault_name:[a-z0-9-]+}").Subrouter()
	r.Secrets = r.ApiRoot.PathPrefix("/secrets").Subrouter()
	r.Keys = r.ApiRoot.PathPrefix("/keys").Subrouter()
	r.Certificates = r.ApiRoot.PathPrefix("/certificates").Subrouter()

	testAPI.InitBackupItem()

	cases := []struct {
		name   string
		method string
		path   string
	}{
		{"secret backup", http.MethodPost, "/api/v1/vaults/prod/secrets/" + uuid.New().String() + "/backup"},
		{"secret restore", http.MethodPost, "/api/v1/vaults/prod/secrets/restore"},
		{"key backup", http.MethodPost, "/api/v1/vaults/prod/keys/" + uuid.New().String() + "/backup"},
		{"key restore", http.MethodPost, "/api/v1/vaults/prod/keys/restore"},
		{"certificate backup", http.MethodPost, "/api/v1/vaults/prod/certificates/" + uuid.New().String() + "/backup"},
		{"certificate restore", http.MethodPost, "/api/v1/vaults/prod/certificates/restore"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(tc.method, tc.path, nil)
			var match mux.RouteMatch
			if !router.Match(req, &match) {
				t.Fatalf("no vault-scoped route matched %s %s", tc.method, tc.path)
			}
		})
	}
}

// TestInitBackupItem_LegacyFlatRoutesStillMatch verifies the pre-existing
// flat routes keep working once vault-scoped registration is added alongside
// them.
func TestInitBackupItem_LegacyFlatRoutesStillMatch(t *testing.T) {
	router := mux.NewRouter()
	testAPI := &API{
		BaseRoutes: &Routes{},
		basePath:   "/api/v1",
		rootRouter: router,
	}
	r := testAPI.BaseRoutes
	r.ApiRoot = router.PathPrefix("/api/v1").Subrouter()
	r.Vaults = r.ApiRoot.PathPrefix("/vaults").Subrouter()
	r.VaultScoped = r.Vaults.PathPrefix("/{vault_name:[a-z0-9-]+}").Subrouter()
	r.Secrets = r.ApiRoot.PathPrefix("/secrets").Subrouter()
	r.Keys = r.ApiRoot.PathPrefix("/keys").Subrouter()
	r.Certificates = r.ApiRoot.PathPrefix("/certificates").Subrouter()

	testAPI.InitBackupItem()

	cases := []struct {
		name   string
		method string
		path   string
	}{
		{"secret backup", http.MethodPost, "/api/v1/secrets/" + uuid.New().String() + "/backup"},
		{"secret restore", http.MethodPost, "/api/v1/secrets/restore"},
		{"key backup", http.MethodPost, "/api/v1/keys/" + uuid.New().String() + "/backup"},
		{"key restore", http.MethodPost, "/api/v1/keys/restore"},
		{"certificate backup", http.MethodPost, "/api/v1/certificates/" + uuid.New().String() + "/backup"},
		{"certificate restore", http.MethodPost, "/api/v1/certificates/restore"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(tc.method, tc.path, nil)
			var match mux.RouteMatch
			if !router.Match(req, &match) {
				t.Fatalf("no legacy flat route matched %s %s", tc.method, tc.path)
			}
		})
	}
}
