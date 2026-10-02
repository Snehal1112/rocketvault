package backup_test

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"rocketvault/internal/backup"
	"rocketvault/internal/repositories"
	"rocketvault/model"
)

// -- certificate stub -------------------------------------------------------

type stubCertRepo struct {
	certs map[uuid.UUID]*model.Certificate
	err   error
	// LastReadScope records the scope of the most recent Read. The stub itself
	// ignores scope (it is an in-memory map), so the scope the service passes
	// is asserted directly — the real predicate lives in
	// CertificateRepository's SQL.
	LastReadScope model.Scope
}

func newStubCertRepo() *stubCertRepo {
	return &stubCertRepo{certs: make(map[uuid.UUID]*model.Certificate)}
}

func (r *stubCertRepo) Create(_ context.Context, c *model.Certificate) error {
	if r.err != nil {
		return r.err
	}
	cp := *c
	r.certs[c.ID] = &cp
	return nil
}

// Read ignores scope for authorization purposes: it is an in-memory map with
// no SQL predicate to enforce. It still records the scope it was called with
// so tests can assert the service passed the correct one; the real predicate
// lives in CertificateRepository's SQL.
func (r *stubCertRepo) Read(_ context.Context, id uuid.UUID, scope model.Scope) (*model.Certificate, error) {
	r.LastReadScope = scope
	if r.err != nil {
		return nil, r.err
	}
	c, ok := r.certs[id]
	if !ok {
		return nil, fmt.Errorf("cert not found")
	}
	cp := *c
	return &cp, nil
}

func (r *stubCertRepo) Update(_ context.Context, _ *model.Certificate, _ model.Scope) error {
	return r.err
}

func (r *stubCertRepo) List(_ context.Context, _ model.Scope, _ repositories.CertificateFilter) ([]model.Certificate, error) {
	return nil, r.err
}

func (r *stubCertRepo) ListDueForRenewal(_ context.Context, _ model.Scope) ([]model.Certificate, error) {
	return nil, r.err
}

func (r *stubCertRepo) Delete(_ context.Context, _ uuid.UUID) error              { return r.err }
func (r *stubCertRepo) Revoke(_ context.Context, _ uuid.UUID, _, _ string) error { return r.err }
func (r *stubCertRepo) SoftDelete(_ context.Context, _ uuid.UUID) error          { return r.err }
func (r *stubCertRepo) RecoverCertificate(_ context.Context, _ uuid.UUID) error  { return r.err }
func (r *stubCertRepo) PurgeCertificate(_ context.Context, _ uuid.UUID) error    { return r.err }
func (r *stubCertRepo) SetPurgeProtection(_ context.Context, id uuid.UUID, enabled bool) error {
	if r.err != nil {
		return r.err
	}
	if c, ok := r.certs[id]; ok {
		c.PurgeProtection = enabled
	}
	return nil
}
func (r *stubCertRepo) ListRevoked(_ context.Context, _ uuid.UUID) ([]model.RevokedCertificate, error) {
	return nil, r.err
}
func (r *stubCertRepo) ListAll(_ context.Context) ([]model.Certificate, error) { return nil, r.err }
func (r *stubCertRepo) SoftDeleteVaultContents(_ context.Context, _ uuid.UUID, _ time.Time) error {
	return r.err
}
func (r *stubCertRepo) RecoverVaultContents(_ context.Context, _ uuid.UUID, _ time.Time) error {
	return r.err
}

// -- erroring stubs for secret/key repos ------------------------------------

type errSecretRepo struct{ *stubSecretRepo }

func newErrSecretRepo() *errSecretRepo { return &errSecretRepo{newStubSecretRepo()} }

func (r *errSecretRepo) Read(_ context.Context, _ uuid.UUID, _ model.Scope) (*model.Secret, error) {
	return nil, errors.New("db failure")
}

func (r *errSecretRepo) Create(_ context.Context, _ *model.Secret) error {
	return errors.New("create failure")
}

type errKeyRepo struct{ *stubKeyRepo }

func newErrKeyRepo() *errKeyRepo { return &errKeyRepo{newStubKeyRepo()} }

func (r *errKeyRepo) Read(_ context.Context, _ uuid.UUID, _ model.Scope) (*model.Key, error) {
	return nil, errors.New("db failure")
}

func (r *errKeyRepo) Create(_ context.Context, _ *model.Key) error {
	return errors.New("create failure")
}

// -- BackupKey / RestoreKey -------------------------------------------------

func TestBackupKeyNonOwnerInSameVaultSucceeds(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	ownerID := uuid.New()
	callerID := uuid.New()
	vaultID := uuid.New()
	keyID := uuid.New()

	kr := newStubKeyRepo()
	require.NoError(t, kr.Create(ctx, &model.Key{
		ID: keyID, UserID: ownerID, VaultID: vaultID,
		Name: "k", Value: "v", Type: model.KeyTypeRSA, Enabled: true,
	}))

	svc := newTestItemBackupService(nil, kr, nil, nil)

	// A Crypto User authorized in this vault who does not own the key must be
	// able to back it up. Authorization is the RBAC action check in
	// PolicyMiddleware plus the vault scope, not key ownership.
	blob, err := svc.BackupKey(ctx, keyID, callerID, vaultID)
	require.NoError(t, err)
	require.NotEmpty(t, blob)
}

func TestBackupKeyReadsWithVaultScope(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	ownerID := uuid.New()
	callerID := uuid.New()
	vaultID := uuid.New()
	keyID := uuid.New()

	kr := newStubKeyRepo()
	require.NoError(t, kr.Create(ctx, &model.Key{
		ID: keyID, UserID: ownerID, VaultID: vaultID,
		Name: "k", Value: "v", Type: model.KeyTypeRSA, Enabled: true,
	}))

	svc := newTestItemBackupService(nil, kr, nil, nil)

	_, err := svc.BackupKey(ctx, keyID, callerID, vaultID)
	require.NoError(t, err)

	// The scope is the whole gate now: an admin scope carries no predicate and
	// would let a caller name a key in any vault.
	require.Equal(t, model.NewVaultScope(vaultID, callerID), kr.LastReadScope)
}

func TestBackupKeyRepoError(t *testing.T) {
	t.Parallel()

	svc := newTestItemBackupService(nil, newErrKeyRepo(), nil, nil)
	_, err := svc.BackupKey(context.Background(), uuid.New(), uuid.New(), uuid.New())
	require.Error(t, err)
}

func TestRestoreKeySuccess(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	ownerID := uuid.New()
	keyID := uuid.New()

	kr := newStubKeyRepo()
	require.NoError(t, kr.Create(ctx, &model.Key{
		ID: keyID, UserID: ownerID, Name: "k", Value: "v", Type: model.KeyTypeRSA, Enabled: true,
	}))

	svc := newTestItemBackupService(nil, kr, nil, nil)

	blob, err := svc.BackupKey(ctx, keyID, ownerID, uuid.Nil)
	require.NoError(t, err)

	require.NoError(t, kr.Delete(ctx, keyID))

	newID := uuid.New()
	require.NoError(t, svc.RestoreKey(ctx, blob, ownerID, uuid.New(), newID))

	restored, err := kr.Read(ctx, newID, model.NewAdminScope(ownerID))
	require.NoError(t, err)
	require.Equal(t, "k", restored.Name)
}

func TestRestoreKeyBlobError(t *testing.T) {
	t.Parallel()

	svc := newTestItemBackupService(nil, newStubKeyRepo(), nil, nil)
	err := svc.RestoreKey(context.Background(), "!!!not-base64!!!", uuid.New(), uuid.New(), uuid.New())
	require.Error(t, err)
	require.True(t, errors.Is(err, backup.ErrInvalidBlob))
}

func TestRestoreKeyTypeMismatch(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	userID := uuid.New()
	secretID := uuid.New()

	sr := newStubSecretRepo()
	require.NoError(t, sr.Create(ctx, &model.Secret{
		ID: secretID, UserID: userID, Name: "s", Value: "v", Version: 1, Enabled: true,
	}))

	svc := newTestItemBackupService(sr, newStubKeyRepo(), nil, newStubSecretVersionRepo())

	// A secret blob must not restore as a key.
	blob, err := svc.BackupSecret(ctx, secretID, userID, uuid.Nil)
	require.NoError(t, err)

	err = svc.RestoreKey(ctx, blob, userID, uuid.New(), uuid.New())
	require.Error(t, err)
	require.True(t, errors.Is(err, backup.ErrInvalidBlob))
	// The blob is genuinely sealed, so the refusal must come from the type
	// check and not from the seal.
	require.NotErrorIs(t, err, backup.ErrUnsealedBlob)
	require.NotErrorIs(t, err, backup.ErrBlobAuthentication)
}

// -- BackupCertificate / RestoreCertificate ---------------------------------

func TestBackupCertificateSuccess(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	ownerID := uuid.New()
	certID := uuid.New()

	cr := newStubCertRepo()
	cr.certs[certID] = &model.Certificate{
		ID: certID, UserID: ownerID, Name: "my-cert",
	}

	svc := newTestItemBackupService(nil, nil, cr, nil)

	blob, err := svc.BackupCertificate(ctx, certID, ownerID, uuid.Nil)
	require.NoError(t, err)
	require.NotEmpty(t, blob)
}

// TestBackupCertificateNonOwnerInSameVaultSucceeds verifies that a
// Certificates Officer authorized in this vault who does not own the
// certificate can still back it up. Authorization is the RBAC action check
// in PolicyMiddleware plus the vault scope, not certificate ownership.
func TestBackupCertificateNonOwnerInSameVaultSucceeds(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	ownerID := uuid.New()
	callerID := uuid.New()
	vaultID := uuid.New()
	certID := uuid.New()

	// stubCertRepo has no Create; TestBackupCertificateSuccess above
	// populates its map directly, and this mirrors that.
	cr := newStubCertRepo()
	cr.certs[certID] = &model.Certificate{
		ID: certID, UserID: ownerID, VaultID: vaultID, Name: "my-cert",
	}

	svc := newTestItemBackupService(nil, nil, cr, nil)

	blob, err := svc.BackupCertificate(ctx, certID, callerID, vaultID)
	require.NoError(t, err)
	require.NotEmpty(t, blob)
	require.Equal(t, model.NewVaultScope(vaultID, callerID), cr.LastReadScope)
}

func TestBackupCertificateRepoError(t *testing.T) {
	t.Parallel()

	cr := newStubCertRepo()
	cr.err = errors.New("db failure")

	svc := newTestItemBackupService(nil, nil, cr, nil)
	_, err := svc.BackupCertificate(context.Background(), uuid.New(), uuid.New(), uuid.New())
	require.Error(t, err)
}

func TestRestoreCertificateSuccess(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	ownerID := uuid.New()
	certID := uuid.New()

	cr := newStubCertRepo()
	cr.certs[certID] = &model.Certificate{
		ID: certID, UserID: ownerID, Name: "my-cert",
	}

	svc := newTestItemBackupService(nil, nil, cr, nil)

	blob, err := svc.BackupCertificate(ctx, certID, ownerID, uuid.Nil)
	require.NoError(t, err)

	delete(cr.certs, certID)

	newID := uuid.New()
	require.NoError(t, svc.RestoreCertificate(ctx, blob, ownerID, uuid.New(), newID))

	restored, err := cr.Read(ctx, newID, model.NewAdminScope(ownerID))
	require.NoError(t, err)
	require.Equal(t, "my-cert", restored.Name)
}

func TestRestoreCertificateBlobError(t *testing.T) {
	t.Parallel()

	svc := newTestItemBackupService(nil, nil, newStubCertRepo(), nil)
	err := svc.RestoreCertificate(context.Background(), "!!!bad!!!", uuid.New(), uuid.New(), uuid.New())
	require.Error(t, err)
	require.True(t, errors.Is(err, backup.ErrInvalidBlob))
}

func TestRestoreCertificateTypeMismatch(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	userID := uuid.New()
	certID := uuid.New()

	cr := newStubCertRepo()
	cr.certs[certID] = &model.Certificate{
		ID: certID, UserID: userID, Name: "c",
	}

	svc := newTestItemBackupService(nil, nil, cr, nil)

	// Build a cert blob then attempt to restore it as a secret.
	blob, err := svc.BackupCertificate(ctx, certID, userID, uuid.Nil)
	require.NoError(t, err)

	err = svc.RestoreSecret(ctx, blob, userID, uuid.New(), uuid.New())
	require.Error(t, err)
	require.True(t, errors.Is(err, backup.ErrInvalidBlob))
	// The blob is genuinely sealed, so the refusal must come from the type
	// check and not from the seal.
	require.NotErrorIs(t, err, backup.ErrUnsealedBlob)
	require.NotErrorIs(t, err, backup.ErrBlobAuthentication)
}

// -- BackupSecret edge paths ------------------------------------------------

func TestBackupSecretReadError(t *testing.T) {
	t.Parallel()

	svc := newTestItemBackupService(newErrSecretRepo(), nil, nil, nil)
	_, err := svc.BackupSecret(context.Background(), uuid.New(), uuid.New(), uuid.New())
	require.Error(t, err)
}

func TestRestoreSecretCreateError(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	userID := uuid.New()
	secretID := uuid.New()

	// Build blob via a working repo.
	good := newStubSecretRepo()
	require.NoError(t, good.Create(ctx, &model.Secret{
		ID: secretID, UserID: userID, Name: "s", Value: "v", Version: 1, Enabled: true,
	}))

	goodSvc := newTestItemBackupService(good, nil, nil, newStubSecretVersionRepo())
	blob, err := goodSvc.BackupSecret(ctx, secretID, userID, uuid.Nil)
	require.NoError(t, err)

	// Restore into a failing repo.
	badSvc := newTestItemBackupService(newErrSecretRepo(), nil, nil, nil)
	err = badSvc.RestoreSecret(ctx, blob, userID, uuid.New(), uuid.New())
	require.Error(t, err)
}
