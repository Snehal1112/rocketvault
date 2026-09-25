package backup_test

import (
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"rocketvault/internal/backup"
	"rocketvault/internal/repositories"
	"rocketvault/model"
)

// stubSecretRepo is a minimal in-memory secret repository for testing.
type stubSecretRepo struct {
	secrets map[uuid.UUID]*model.Secret
	// LastReadScope records the scope of the most recent Read. The stub
	// itself ignores scope for its own gating (it applies scopeAuthorizes
	// directly against the in-memory map), but this lets tests assert the
	// exact scope the service passed — the real predicate lives in
	// SecretRepository's SQL.
	LastReadScope model.Scope
}

func newStubSecretRepo() *stubSecretRepo {
	return &stubSecretRepo{secrets: make(map[uuid.UUID]*model.Secret)}
}

func (r *stubSecretRepo) Create(_ context.Context, s *model.Secret) error {
	if _, exists := r.secrets[s.ID]; exists {
		return fmt.Errorf("secret already exists: %s", s.ID)
	}
	cp := *s
	r.secrets[s.ID] = &cp
	return nil
}

// scopeAuthorizes mirrors the real repository's scopePredicate: it decides
// whether a secret is reachable under the given scope.
func scopeAuthorizes(s *model.Secret, scope model.Scope) bool {
	switch scope.Kind() {
	case model.ScopeVault:
		return s.VaultID == scope.VaultID()
	case model.ScopeOwner:
		ownerID, ok := scope.OwnerID()
		return ok && s.UserID == ownerID
	case model.ScopeAdmin:
		return true
	default:
		return false
	}
}

func (r *stubSecretRepo) Read(_ context.Context, id uuid.UUID, scope model.Scope) (*model.Secret, error) {
	r.LastReadScope = scope
	s, ok := r.secrets[id]
	if !ok || !scopeAuthorizes(s, scope) {
		return nil, fmt.Errorf("secret not found or access denied")
	}
	cp := *s
	return &cp, nil
}

// FindByName looks up an active secret by name, mirroring the real
// repository's scoping rules via scopeAuthorizes.
func (r *stubSecretRepo) FindByName(_ context.Context, name string, scope model.Scope) (*model.Secret, error) {
	for _, s := range r.secrets {
		if s.Name == name && s.DeletedAt == nil && scopeAuthorizes(s, scope) {
			cp := *s
			return &cp, nil
		}
	}
	return nil, fmt.Errorf("secret %q: %w", name, repositories.ErrNotFound)
}

func (r *stubSecretRepo) Update(_ context.Context, s *model.Secret, scope model.Scope) error {
	existing, ok := r.secrets[s.ID]
	if !ok || !scopeAuthorizes(existing, scope) {
		return fmt.Errorf("secret not found or access denied")
	}
	cp := *s
	r.secrets[s.ID] = &cp
	return nil
}

func (r *stubSecretRepo) Delete(_ context.Context, id uuid.UUID) error {
	delete(r.secrets, id)
	return nil
}

func (r *stubSecretRepo) SoftDelete(_ context.Context, id uuid.UUID) error {
	s, ok := r.secrets[id]
	if !ok {
		return fmt.Errorf("secret not found")
	}
	now := time.Now()
	s.DeletedAt = &now
	return nil
}

func (r *stubSecretRepo) RecoverSecret(_ context.Context, id uuid.UUID) error {
	s, ok := r.secrets[id]
	if !ok {
		return fmt.Errorf("secret not found")
	}
	s.DeletedAt = nil
	return nil
}

func (r *stubSecretRepo) List(_ context.Context, scope model.Scope, filter repositories.SecretFilter) ([]model.Secret, error) {
	var out []model.Secret
	for _, s := range r.secrets {
		if !scopeAuthorizes(s, scope) {
			continue
		}
		switch {
		case filter.OnlyDeleted:
			if s.DeletedAt == nil {
				continue
			}
		case filter.IncludeDeleted:
			// No deleted_at constraint.
		default:
			if s.DeletedAt != nil {
				continue
			}
		}
		out = append(out, *s)
	}
	return out, nil
}

func (r *stubSecretRepo) ExportSecrets(_ context.Context, _ model.ExportOptions) ([]byte, error) {
	return nil, fmt.Errorf("not implemented")
}

func (r *stubSecretRepo) ImportSecrets(_ context.Context, _ []byte, _ model.ImportOptions) (int, error) {
	return 0, fmt.Errorf("not implemented")
}

func (r *stubSecretRepo) GetVersions(_ context.Context, _ uuid.UUID) ([]model.SecretVersion, error) {
	return nil, fmt.Errorf("not implemented")
}

func (r *stubSecretRepo) GetVersion(_ context.Context, _ uuid.UUID, _ int) (*model.SecretVersion, error) {
	return nil, fmt.Errorf("not implemented")
}

func (r *stubSecretRepo) GetLatestVersion(_ context.Context, _ uuid.UUID) (*model.SecretVersion, error) {
	return nil, fmt.Errorf("not implemented")
}

func (r *stubSecretRepo) PurgeSecret(_ context.Context, id uuid.UUID) error {
	delete(r.secrets, id)
	return nil
}

func (r *stubSecretRepo) SetPurgeProtection(_ context.Context, id uuid.UUID, enabled bool) error {
	if s, ok := r.secrets[id]; ok {
		s.PurgeProtection = enabled
	}
	return nil
}

func (r *stubSecretRepo) SoftDeleteVaultContents(_ context.Context, _ uuid.UUID, _ time.Time) error {
	return nil
}

func (r *stubSecretRepo) RecoverVaultContents(_ context.Context, _ uuid.UUID, _ time.Time) error {
	return nil
}

func TestBackupRestoreSecret(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	userID := uuid.New()
	secretID := uuid.New()

	repo := newStubSecretRepo()
	original := &model.Secret{
		ID:      secretID,
		UserID:  userID,
		Name:    "my-db-password",
		Value:   "s3cr3t",
		Version: 1,
		Tags:    []string{"db", "prod"},
		Enabled: true,
	}
	require.NoError(t, repo.Create(ctx, original))

	svc := backup.NewItemBackupService(repo, nil, nil, newStubSecretVersionRepo())

	// Backup the secret.
	blob, err := svc.BackupSecret(ctx, secretID, userID, uuid.Nil)
	require.NoError(t, err)
	require.NotEmpty(t, blob)

	// Remove the original so restore has a clean target.
	require.NoError(t, repo.Delete(ctx, secretID))

	// Restore using a new UUID so no collision.
	err = svc.RestoreSecret(ctx, blob, userID, uuid.New(), uuid.New())
	require.NoError(t, err)

	// Verify the restored secret matches the original data.
	restored, err := repo.List(ctx, model.NewOwnerScope(uuid.Nil, userID), repositories.SecretFilter{})
	require.NoError(t, err)
	require.Len(t, restored, 1)
	require.Equal(t, original.Name, restored[0].Name)
	require.Equal(t, original.Value, restored[0].Value)
	require.Equal(t, original.Version, restored[0].Version)
}

func TestBackupSecretNonOwnerInSameVaultSucceeds(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	ownerID := uuid.New()
	callerID := uuid.New()
	vaultID := uuid.New()
	secretID := uuid.New()

	repo := newStubSecretRepo()
	require.NoError(t, repo.Create(ctx, &model.Secret{
		ID:      secretID,
		UserID:  ownerID,
		VaultID: vaultID,
		Name:    "shared",
		Value:   "value",
		Version: 1,
		Enabled: true,
	}))

	svc := backup.NewItemBackupService(repo, nil, nil, newStubSecretVersionRepo())

	// A Secrets Officer authorized in this vault who does not own the secret
	// must be able to back it up.
	blob, err := svc.BackupSecret(ctx, secretID, callerID, vaultID)
	require.NoError(t, err)
	require.NotEmpty(t, blob)
	require.Equal(t, model.NewVaultScope(vaultID, callerID), repo.LastReadScope)
}

// stubKeyRepo is a minimal in-memory key repository for testing.
type stubKeyRepo struct {
	keys     map[uuid.UUID]*model.Key
	versions map[uuid.UUID]map[int]string
	// LastReadScope records the scope of the most recent Read. The stub itself
	// ignores scope (it is an in-memory map), so the scope the service passes
	// is asserted directly — the real predicate lives in KeyRepository's SQL.
	LastReadScope model.Scope
	// failCreateVersionAt makes the nth CreateVersion call (1-based) fail, so a
	// test can drive a version replay that dies partway through. Zero disables it.
	failCreateVersionAt int
	createVersionCalls  int
}

func newStubKeyRepo() *stubKeyRepo {
	return &stubKeyRepo{
		keys:     make(map[uuid.UUID]*model.Key),
		versions: make(map[uuid.UUID]map[int]string),
	}
}

func (r *stubKeyRepo) Create(_ context.Context, k *model.Key) error {
	if _, exists := r.keys[k.ID]; exists {
		return fmt.Errorf("key already exists: %s", k.ID)
	}
	cp := *k
	// Mirror the real INSERT, whose column list omits purge_protection: a
	// created key is always unprotected until SetPurgeProtection is called.
	// Persisting the caller's flag here would hide restore-ordering bugs,
	// since a partially restored key would look protected either way.
	cp.PurgeProtection = false
	r.keys[k.ID] = &cp
	return nil
}

// Read ignores scope for authorization purposes: it is an in-memory map with
// no SQL predicate to enforce. It still records the scope it was called with
// so tests can assert the service passed the correct one; the real predicate
// lives in KeyRepository's SQL.
func (r *stubKeyRepo) Read(_ context.Context, id uuid.UUID, scope model.Scope) (*model.Key, error) {
	r.LastReadScope = scope
	k, ok := r.keys[id]
	if !ok {
		return nil, fmt.Errorf("key not found")
	}
	cp := *k
	return &cp, nil
}

func (r *stubKeyRepo) Update(_ context.Context, k *model.Key, _ model.Scope) error {
	if _, ok := r.keys[k.ID]; !ok {
		return fmt.Errorf("key not found")
	}
	cp := *k
	r.keys[k.ID] = &cp
	return nil
}

func (r *stubKeyRepo) Delete(_ context.Context, id uuid.UUID) error {
	delete(r.keys, id)
	return nil
}

func (r *stubKeyRepo) UpdateRevocationStatus(_ context.Context, _ uuid.UUID, _ bool) error {
	return nil
}

func (r *stubKeyRepo) SoftDelete(_ context.Context, _ uuid.UUID) error { return nil }
func (r *stubKeyRepo) RecoverKey(_ context.Context, _ uuid.UUID) error { return nil }
func (r *stubKeyRepo) PurgeKey(_ context.Context, _ uuid.UUID) error   { return nil }
func (r *stubKeyRepo) SetPurgeProtection(_ context.Context, id uuid.UUID, enabled bool) error {
	if k, ok := r.keys[id]; ok {
		k.PurgeProtection = enabled
	}
	return nil
}

func (r *stubKeyRepo) ReadDeletedScoped(_ context.Context, _ uuid.UUID, _ model.Scope) (*model.Key, error) {
	return nil, nil
}

func (r *stubKeyRepo) CreateVersion(_ context.Context, keyID uuid.UUID, version int, value string) error {
	r.createVersionCalls++
	if r.failCreateVersionAt != 0 && r.createVersionCalls == r.failCreateVersionAt {
		return fmt.Errorf("simulated version write failure")
	}
	if r.versions[keyID] == nil {
		r.versions[keyID] = make(map[int]string)
	}
	r.versions[keyID][version] = value
	return nil
}

func (r *stubKeyRepo) ListVersions(_ context.Context, keyID uuid.UUID) ([]model.KeyVersion, error) {
	var out []model.KeyVersion
	for v := range r.versions[keyID] {
		out = append(out, model.KeyVersion{KeyID: keyID, Version: v})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Version < out[j].Version })
	return out, nil
}

// CurrentVersion mirrors the repository's aggregate: the highest stored
// version, or the implicit 1 when the key has never been rotated.
func (r *stubKeyRepo) CurrentVersion(_ context.Context, keyID uuid.UUID) (int, error) {
	current := 1
	for v := range r.versions[keyID] {
		if v > current {
			current = v
		}
	}
	return current, nil
}

func (r *stubKeyRepo) ReadVersionValue(_ context.Context, _ uuid.UUID, _ int) (string, error) {
	return "", nil
}

func (r *stubKeyRepo) GetVersion(_ context.Context, _ uuid.UUID, _ int) (*model.KeyVersion, error) {
	return nil, nil
}

func (r *stubKeyRepo) ListVersionRecords(_ context.Context, keyID uuid.UUID) ([]model.KeyVersionRecord, error) {
	var records []model.KeyVersionRecord
	for v, val := range r.versions[keyID] {
		records = append(records, model.KeyVersionRecord{KeyID: keyID, Version: v, Value: val})
	}
	sort.Slice(records, func(i, j int) bool { return records[i].Version < records[j].Version })
	return records, nil
}

func (r *stubKeyRepo) SoftDeleteVaultContents(_ context.Context, _ uuid.UUID, _ time.Time) error {
	return nil
}

func (r *stubKeyRepo) RecoverVaultContents(_ context.Context, _ uuid.UUID, _ time.Time) error {
	return nil
}

func (r *stubKeyRepo) List(_ context.Context, _ model.Scope, _ repositories.KeyFilter) ([]model.Key, error) {
	return nil, nil
}

func TestRestoreSecretBlobTypeMismatch(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	userID := uuid.New()
	keyID := uuid.New()

	// Build a key backup blob via the key path so it has resource_type="key".
	keyRepo := newStubKeyRepo()
	require.NoError(t, keyRepo.Create(ctx, &model.Key{
		ID:      keyID,
		UserID:  userID,
		Name:    "my-key",
		Value:   "key-value",
		Type:    model.KeyTypeRSA,
		Enabled: true,
	}))

	svc := backup.NewItemBackupService(newStubSecretRepo(), keyRepo, nil, nil)

	// Backup a key but try to restore it as a secret.
	blob, err := svc.BackupKey(ctx, keyID, userID, uuid.Nil)
	require.NoError(t, err)

	err = svc.RestoreSecret(ctx, blob, userID, uuid.New(), uuid.New())
	require.Error(t, err)
	require.True(t, errors.Is(err, backup.ErrInvalidBlob), "expected ErrInvalidBlob, got: %v", err)
}

// TestRestoreSecretWritesAuthorizedVaultNotBlobVault verifies that
// RestoreSecret writes the vault ID authorized by the caller's request, not
// the vault ID embedded in the backup blob. A user with restore permission
// in vault B, restoring a blob whose embedded vault is A, must land the
// restored secret in vault B — not silently write into vault A.
func TestRestoreSecretWritesAuthorizedVaultNotBlobVault(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	repo := newStubSecretRepo()
	svc := backup.NewItemBackupService(repo, nil, nil, newStubSecretVersionRepo())

	vaultA := uuid.New()
	vaultB := uuid.New()
	owner := uuid.New()

	original := &model.Secret{
		ID:      uuid.New(),
		UserID:  owner,
		VaultID: vaultA,
		Name:    "s1",
		Value:   "v1",
		Version: 1,
		Enabled: true,
	}
	require.NoError(t, repo.Create(ctx, original))

	blob, err := svc.BackupSecret(ctx, original.ID, owner, vaultA)
	require.NoError(t, err)

	newID := uuid.New()
	err = svc.RestoreSecret(ctx, blob, owner, vaultB, newID)
	require.NoError(t, err)

	restored, err := repo.Read(ctx, newID, model.NewVaultScope(vaultB, owner))
	require.NoError(t, err)
	assert.Equal(t, vaultB, restored.VaultID, "restore must write the authorized vault, not the blob's embedded vault")

	_, err = repo.Read(ctx, newID, model.NewVaultScope(vaultA, owner))
	require.Error(t, err, "the restored secret must not be readable under the blob's original vault scope")
}

// TestRestoreSecretPreservesPurgeProtection verifies that a secret backed up
// while purge-protected comes back protected. The repository's Create does
// not write purge_protection, so restore must re-apply the flag explicitly —
// otherwise a backup/restore round-trip silently strips the control.
func TestRestoreSecretPreservesPurgeProtection(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	repo := newStubSecretRepo()
	svc := backup.NewItemBackupService(repo, nil, nil, newStubSecretVersionRepo())

	owner := uuid.New()
	vaultID := uuid.New()
	original := &model.Secret{
		ID:              uuid.New(),
		UserID:          owner,
		VaultID:         vaultID,
		Name:            "protected",
		Value:           "v1",
		Version:         1,
		Enabled:         true,
		PurgeProtection: true,
	}
	require.NoError(t, repo.Create(ctx, original))

	blob, err := svc.BackupSecret(ctx, original.ID, owner, vaultID)
	require.NoError(t, err)

	newID := uuid.New()
	require.NoError(t, svc.RestoreSecret(ctx, blob, owner, vaultID, newID))

	restored, err := repo.Read(ctx, newID, model.NewVaultScope(vaultID, owner))
	require.NoError(t, err)
	assert.True(t, restored.PurgeProtection, "restore must preserve the backed-up secret's purge protection")
}

// TestRestoreKeyPreservesPurgeProtection is the key-side twin of
// TestRestoreSecretPreservesPurgeProtection.
func TestRestoreKeyPreservesPurgeProtection(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	repo := newStubKeyRepo()
	svc := backup.NewItemBackupService(nil, repo, nil, nil)

	owner := uuid.New()
	vaultID := uuid.New()
	original := &model.Key{
		ID:              uuid.New(),
		UserID:          owner,
		VaultID:         vaultID,
		Name:            "protected-key",
		Value:           "key-value",
		Type:            model.KeyTypeRSA,
		Enabled:         true,
		PurgeProtection: true,
	}
	require.NoError(t, repo.Create(ctx, original))
	// Create never persists purge_protection, in the stub or the real
	// repository -- production applies it as a separate write, so the fixture
	// must too.
	require.NoError(t, repo.SetPurgeProtection(ctx, original.ID, true))

	blob, err := svc.BackupKey(ctx, original.ID, owner, vaultID)
	require.NoError(t, err)

	newID := uuid.New()
	require.NoError(t, svc.RestoreKey(ctx, blob, owner, vaultID, newID))

	restored, err := repo.Read(ctx, newID, model.NewAdminScope(owner))
	require.NoError(t, err)
	assert.True(t, restored.PurgeProtection, "restore must preserve the backed-up key's purge protection")
}

// TestRestoreKey_FailedVersionReplayLeavesNoPurgeProtectedOrphan pins the write
// order inside RestoreKey: archived versions must be replayed before purge
// protection is applied.
//
// The order matters because a restore is not transactional (see
// .claude/known-bugs.md § F3). If purge protection went on first and a version
// replay then failed, the partial key would be left protected, and
// KeyRepository.PurgeKey refuses to delete a protected key
// (ErrKeyPurgeProtected) -- stranding a row under an ID the caller never
// received and cannot clean up. RestoreSecret was reordered for exactly this
// reason; this test is the key-side equivalent.
func TestRestoreKey_FailedVersionReplayLeavesNoPurgeProtectedOrphan(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	repo := newStubKeyRepo()
	svc := backup.NewItemBackupService(nil, repo, nil, nil)

	owner := uuid.New()
	vaultID := uuid.New()
	original := &model.Key{
		ID:              uuid.New(),
		UserID:          owner,
		VaultID:         vaultID,
		Name:            "protected-rotated-key",
		Value:           "current-value",
		Type:            model.KeyTypeRSA,
		Enabled:         true,
		PurgeProtection: true,
	}
	require.NoError(t, repo.Create(ctx, original))
	require.NoError(t, repo.SetPurgeProtection(ctx, original.ID, true))
	require.NoError(t, repo.CreateVersion(ctx, original.ID, 1, "v1-value"))
	require.NoError(t, repo.CreateVersion(ctx, original.ID, 2, "v2-value"))

	blob, err := svc.BackupKey(ctx, original.ID, owner, vaultID)
	require.NoError(t, err)

	// Fail the second replayed version, so the restore dies partway through
	// with the parent row already written.
	restoreRepo := newStubKeyRepo()
	restoreRepo.failCreateVersionAt = 2
	restoreSvc := backup.NewItemBackupService(nil, restoreRepo, nil, nil)

	newID := uuid.New()
	err = restoreSvc.RestoreKey(ctx, blob, owner, vaultID, newID)
	require.Error(t, err, "a failed version replay must surface as an error, not a silent partial restore")

	orphan, readErr := restoreRepo.Read(ctx, newID, model.NewAdminScope(owner))
	require.NoError(t, readErr, "the parent row is expected to survive; the point is that it stays cleanable")
	assert.False(t, orphan.PurgeProtection,
		"a partially restored key must not be purge-protected, or PurgeKey cannot clean it up")
}

// TestRestoreCertificatePreservesPurgeProtection is the certificate-side twin
// of TestRestoreSecretPreservesPurgeProtection.
func TestRestoreCertificatePreservesPurgeProtection(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	repo := newStubCertRepo()
	svc := backup.NewItemBackupService(nil, nil, repo, nil)

	owner := uuid.New()
	vaultID := uuid.New()
	original := &model.Certificate{
		ID:              uuid.New(),
		UserID:          owner,
		VaultID:         vaultID,
		Name:            "protected-cert",
		PurgeProtection: true,
	}
	require.NoError(t, repo.Create(ctx, original))

	blob, err := svc.BackupCertificate(ctx, original.ID, owner, vaultID)
	require.NoError(t, err)

	newID := uuid.New()
	require.NoError(t, svc.RestoreCertificate(ctx, blob, owner, vaultID, newID))

	restored, err := repo.Read(ctx, newID, model.NewAdminScope(owner))
	require.NoError(t, err)
	assert.True(t, restored.PurgeProtection, "restore must preserve the backed-up certificate's purge protection")
}

// TestBackupRestoreKey_CarriesVersionHistory verifies a rotated key's
// key_versions history survives a backup/restore round-trip, and that a
// crypto-relevant old version's material is still present afterward. The
// calling user is deliberately distinct from the key's owner: this is the
// direct regression pin for B28/F2 -- a non-owner backing up a key they
// don't own, but do hold ActionKeysBackup for in the same vault. Under the
// pre-fix code, ListVersionRecords' owner-ID filter would have been passed
// the caller's ID instead of the key's, matched no rows, and silently
// dropped the version history from the blob.
func TestBackupRestoreKey_CarriesVersionHistory(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	owner := uuid.New()
	caller := uuid.New()
	vaultID := uuid.New()
	keyID := uuid.New()

	repo := newStubKeyRepo()
	require.NoError(t, repo.Create(ctx, &model.Key{
		ID: keyID, UserID: owner, VaultID: vaultID, Name: "rotated-key",
		Value: "pem-v2", Type: model.KeyTypeRSA, Enabled: true,
	}))
	require.NoError(t, repo.CreateVersion(ctx, keyID, 1, "pem-v1"))
	require.NoError(t, repo.CreateVersion(ctx, keyID, 2, "pem-v2"))

	svc := backup.NewItemBackupService(nil, repo, nil, nil)

	blob, err := svc.BackupKey(ctx, keyID, caller, vaultID)
	require.NoError(t, err)

	newID := uuid.New()
	require.NoError(t, svc.RestoreKey(ctx, blob, caller, vaultID, newID))

	records, err := repo.ListVersionRecords(ctx, newID)
	require.NoError(t, err)
	require.Len(t, records, 2)
	assert.Equal(t, "pem-v1", records[0].Value)
	assert.Equal(t, "pem-v2", records[1].Value)
}

// TestRestoreKey_OldFormatBlob_NoVersionsField verifies a blob encoded
// before this change (no "versions" field on its envelope) still restores
// correctly, with no version history — not an error.
func TestRestoreKey_OldFormatBlob_NoVersionsField(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	owner := uuid.New()
	vaultID := uuid.New()
	keyID := uuid.New()

	repo := newStubKeyRepo()
	require.NoError(t, repo.Create(ctx, &model.Key{
		ID: keyID, UserID: owner, VaultID: vaultID, Name: "never-rotated",
		Value: "pem-v1", Type: model.KeyTypeRSA, Enabled: true,
	}))

	svc := backup.NewItemBackupService(nil, repo, nil, nil)

	// A key with zero key_versions rows produces a blob with an empty/absent
	// "versions" field today, which is exactly the old-format shape.
	blob, err := svc.BackupKey(ctx, keyID, owner, vaultID)
	require.NoError(t, err)

	newID := uuid.New()
	require.NoError(t, svc.RestoreKey(ctx, blob, owner, vaultID, newID))

	records, err := repo.ListVersionRecords(ctx, newID)
	require.NoError(t, err)
	assert.Empty(t, records)
}

// TestBlobEnvelope_SecretVersionsRoundTrip pins the new envelope field.
func TestBlobEnvelope_SecretVersionsRoundTrip(t *testing.T) {
	t.Parallel()

	secretID := uuid.New()
	versions := []model.SecretVersion{
		{ID: uuid.New(), SecretID: secretID, UserID: uuid.New(), Name: "s", Value: "enc-v1", Version: 1},
		{ID: uuid.New(), SecretID: secretID, UserID: uuid.New(), Name: "s", Value: "enc-v2", Version: 2},
	}

	blob, err := backup.ExportedEncodeBlob("secret", secretID.String(),
		&model.Secret{ID: secretID, Name: "s"},
		backup.ExportedBlobVersions{Secret: versions})
	require.NoError(t, err)

	var out model.Secret
	got, err := backup.ExportedDecodeBlob(blob, "secret", &out)
	require.NoError(t, err)
	require.Len(t, got.Secret, 2)
	require.Equal(t, "enc-v1", got.Secret[0].Value)
	require.Empty(t, got.Key, "a secret blob carries no key version records")
}

// TestBlobEnvelope_KeyVersionsUnaffected proves this refactor did not disturb
// the key path's existing field.
func TestBlobEnvelope_KeyVersionsUnaffected(t *testing.T) {
	t.Parallel()

	keyID := uuid.New()
	blob, err := backup.ExportedEncodeBlob("key", keyID.String(),
		&model.Key{ID: keyID, Name: "k"},
		backup.ExportedBlobVersions{Key: []model.KeyVersionRecord{{KeyID: keyID, Version: 1, Value: "enc"}}})
	require.NoError(t, err)

	var out model.Key
	got, err := backup.ExportedDecodeBlob(blob, "key", &out)
	require.NoError(t, err)
	require.Len(t, got.Key, 1)
	require.Empty(t, got.Secret)
}

// stubSecretVersionRepo is a minimal in-memory SecretVersionRepositoryInterface.
type stubSecretVersionRepo struct {
	versions map[uuid.UUID][]model.SecretVersion
}

func newStubSecretVersionRepo() *stubSecretVersionRepo {
	return &stubSecretVersionRepo{versions: make(map[uuid.UUID][]model.SecretVersion)}
}

func (r *stubSecretVersionRepo) CreateVersion(_ context.Context, v *model.SecretVersion) error {
	r.versions[v.SecretID] = append(r.versions[v.SecretID], *v)
	return nil
}

func (r *stubSecretVersionRepo) GetVersions(_ context.Context, secretID uuid.UUID) ([]model.SecretVersion, error) {
	return r.versions[secretID], nil
}

func (r *stubSecretVersionRepo) GetVersion(_ context.Context, secretID uuid.UUID, version int) (*model.SecretVersion, error) {
	for i := range r.versions[secretID] {
		if r.versions[secretID][i].Version == version {
			return &r.versions[secretID][i], nil
		}
	}
	return nil, sql.ErrNoRows
}

func (r *stubSecretVersionRepo) GetLatestVersion(_ context.Context, secretID uuid.UUID) (*model.SecretVersion, error) {
	list := r.versions[secretID]
	if len(list) == 0 {
		return nil, sql.ErrNoRows
	}
	return &list[len(list)-1], nil
}

func (r *stubSecretVersionRepo) DeleteVersions(_ context.Context, secretID uuid.UUID) error {
	delete(r.versions, secretID)
	return nil
}

func (r *stubSecretVersionRepo) DeleteSpecificVersion(_ context.Context, secretID uuid.UUID, version int) error {
	kept := r.versions[secretID][:0]
	for _, v := range r.versions[secretID] {
		if v.Version != version {
			kept = append(kept, v)
		}
	}
	r.versions[secretID] = kept
	return nil
}

// TestBackupSecret_CarriesVersionHistory verifies a secret's archived
// version history reaches the backup blob. The stub's GetVersions returns
// versions in insertion order, but the real secretVersionRepository orders
// version DESC (internal/repositories/versioning_repository.go) — so this
// asserts the set of values reached the blob, not their position. Task 3
// replays each row with its own Version number, making order irrelevant.
func TestBackupSecret_CarriesVersionHistory(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	ownerID := uuid.New()
	vaultID := uuid.New()
	secretID := uuid.New()

	repo := newStubSecretRepo()
	require.NoError(t, repo.Create(ctx, &model.Secret{
		ID: secretID, UserID: ownerID, VaultID: vaultID,
		Name: "db-password", Value: "enc-v3", Version: 3, Enabled: true,
	}))

	vr := newStubSecretVersionRepo()
	for i := 1; i <= 2; i++ {
		require.NoError(t, vr.CreateVersion(ctx, &model.SecretVersion{
			ID: uuid.New(), SecretID: secretID, UserID: ownerID,
			Name: "db-password", Value: fmt.Sprintf("enc-v%d", i), Version: i,
		}))
	}

	svc := backup.NewItemBackupService(repo, nil, nil, vr)

	blob, err := svc.BackupSecret(ctx, secretID, ownerID, vaultID)
	require.NoError(t, err)

	var restored model.Secret
	got, err := backup.ExportedDecodeBlob(blob, "secret", &restored)
	require.NoError(t, err)
	require.Len(t, got.Secret, 2, "both archived versions must reach the blob")

	values := []string{got.Secret[0].Value, got.Secret[1].Value}
	assert.ElementsMatch(t, []string{"enc-v1", "enc-v2"}, values)
}

// TestBackupRestoreSecret_CarriesVersionHistory verifies a secret's archived
// versions survive a full backup/restore round-trip: they must be replayed
// under the new secret's ID and the restoring caller's user ID, each with its
// own fresh primary key.
func TestBackupRestoreSecret_CarriesVersionHistory(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	ownerID := uuid.New()
	vaultID := uuid.New()
	secretID := uuid.New()

	repo := newStubSecretRepo()
	require.NoError(t, repo.Create(ctx, &model.Secret{
		ID: secretID, UserID: ownerID, VaultID: vaultID,
		Name: "db-password", Value: "enc-v3", Version: 3, Enabled: true,
	}))

	vr := newStubSecretVersionRepo()
	baseCreatedAt := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	for i := 1; i <= 2; i++ {
		require.NoError(t, vr.CreateVersion(ctx, &model.SecretVersion{
			ID: uuid.New(), SecretID: secretID, UserID: ownerID,
			Name: "db-password", Value: fmt.Sprintf("enc-v%d", i), Version: i,
			CreatedAt: baseCreatedAt.AddDate(0, 0, i),
		}))
	}

	svc := backup.NewItemBackupService(repo, nil, nil, vr)

	blob, err := svc.BackupSecret(ctx, secretID, ownerID, vaultID)
	require.NoError(t, err)

	newID := uuid.New()
	restorerID := uuid.New()
	newVaultID := uuid.New()
	require.NoError(t, svc.RestoreSecret(ctx, blob, restorerID, newVaultID, newID))

	restoredVersions, err := vr.GetVersions(ctx, newID)
	require.NoError(t, err)
	require.Len(t, restoredVersions, 2, "restore must replay the archived versions")

	for _, v := range restoredVersions {
		require.Equal(t, newID, v.SecretID, "versions must attach to the NEW secret")
		require.Equal(t, restorerID, v.UserID, "versions must belong to the restoring user")
		require.NotEqual(t, uuid.Nil, v.ID)
	}
	require.NotEqual(t, restoredVersions[0].ID, restoredVersions[1].ID,
		"each replayed version needs its own primary key")

	// The assertions above only check plumbing (IDs, ownership) -- none of
	// them would fail if the replay zeroed every Version or blanked every
	// Value. Assert the actual payload survived the round trip, order
	// agnostic: production orders "version DESC" while the stub returns
	// insertion order.
	type versionPair struct {
		Version int
		Value   string
	}
	wantPairs := []versionPair{
		{Version: 1, Value: "enc-v1"},
		{Version: 2, Value: "enc-v2"},
	}
	var gotPairs []versionPair
	for _, v := range restoredVersions {
		gotPairs = append(gotPairs, versionPair{Version: v.Version, Value: v.Value})
		assert.Equal(t, "db-password", v.Name, "version name must survive the round trip")
		assert.True(t, v.CreatedAt.Equal(baseCreatedAt.AddDate(0, 0, v.Version)),
			"version created_at must survive the round trip")
	}
	assert.ElementsMatch(t, wantPairs, gotPairs,
		"restored version {version, value} pairs must match what was backed up")
}

// TestRestoreSecret_OldFormatBlob_NoVersionsField proves back-compat: a blob
// written before the secret_versions field existed must still restore.
func TestRestoreSecret_OldFormatBlob_NoVersionsField(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	secretID := uuid.New()

	// Hand-built envelope with no secret_versions key at all.
	raw, err := json.Marshal(map[string]any{
		"resource_type": "secret",
		"resource_id":   secretID.String(),
		"data":          json.RawMessage(`{"id":"` + secretID.String() + `","name":"legacy","value":"enc","version":1}`),
	})
	require.NoError(t, err)
	blob := base64.URLEncoding.EncodeToString(raw)

	repo := newStubSecretRepo()
	vr := newStubSecretVersionRepo()
	svc := backup.NewItemBackupService(repo, nil, nil, vr)

	newID := uuid.New()
	require.NoError(t, svc.RestoreSecret(ctx, blob, uuid.New(), uuid.New(), newID),
		"a pre-versions blob must still restore")

	versions, err := vr.GetVersions(ctx, newID)
	require.NoError(t, err)
	require.Empty(t, versions)
}
