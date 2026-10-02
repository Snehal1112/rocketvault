package backup_test

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"rocketvault/internal/backup"
	rvdb "rocketvault/internal/db"
	"rocketvault/internal/logging"
	"rocketvault/internal/repositories"
	"rocketvault/model"
)

// vaultCheckingKeyRepo applies the vault predicate the real KeyRepository
// applies in SQL, which stubKeyRepo deliberately ignores.
type vaultCheckingKeyRepo struct{ *stubKeyRepo }

func (r vaultCheckingKeyRepo) Read(ctx context.Context, id uuid.UUID, scope model.Scope) (*model.Key, error) {
	k, err := r.stubKeyRepo.Read(ctx, id, scope)
	if err != nil {
		return nil, err
	}
	if scope.Kind() != model.ScopeVault || k.VaultID != scope.VaultID() {
		return nil, fmt.Errorf("key not found or access denied")
	}
	return k, nil
}

// vaultCheckingCertRepo is vaultCheckingKeyRepo's certificate twin.
type vaultCheckingCertRepo struct{ *stubCertRepo }

func (r vaultCheckingCertRepo) Read(ctx context.Context, id uuid.UUID, scope model.Scope) (*model.Certificate, error) {
	c, err := r.stubCertRepo.Read(ctx, id, scope)
	if err != nil {
		return nil, err
	}
	if scope.Kind() != model.ScopeVault || c.VaultID != scope.VaultID() {
		return nil, fmt.Errorf("certificate not found or access denied")
	}
	return c, nil
}

// certRefFixture holds, in vault A, a signing key, a CA certificate and a
// leaf certificate linked to both, plus a sealed backup of the leaf.
type certRefFixture struct {
	keys     *stubKeyRepo
	certs    *stubCertRepo
	svc      *backup.ItemBackupService
	owner    uuid.UUID
	vaultA   uuid.UUID
	keyID    uuid.UUID
	caCertID uuid.UUID
	blob     string
}

func newCertRefFixture(t *testing.T) *certRefFixture {
	t.Helper()
	ctx := context.Background()
	owner, vaultA := uuid.New(), uuid.New()
	keyID, caCertID, leafID := uuid.New(), uuid.New(), uuid.New()

	keys := newStubKeyRepo()
	require.NoError(t, keys.Create(ctx, &model.Key{
		ID: keyID, UserID: owner, VaultID: vaultA, Name: "k", Value: "enc", Type: model.KeyTypeRSA, Enabled: true,
	}))
	certs := newStubCertRepo()
	require.NoError(t, certs.Create(ctx, &model.Certificate{ID: caCertID, UserID: owner, VaultID: vaultA, Name: "ca"}))
	require.NoError(t, certs.Create(ctx, &model.Certificate{
		ID: leafID, UserID: owner, VaultID: vaultA, Name: "leaf",
		KeyID: keyID, CACertID: &caCertID, AutoRenew: true,
	}))

	svc := newTestItemBackupService(nil, vaultCheckingKeyRepo{keys}, vaultCheckingCertRepo{certs}, nil)
	blob, err := svc.BackupCertificate(ctx, leafID, owner, vaultA)
	require.NoError(t, err)

	return &certRefFixture{
		keys: keys, certs: certs, svc: svc, owner: owner, vaultA: vaultA,
		keyID: keyID, caCertID: caCertID, blob: blob,
	}
}

// TestRestoreCertificate_DropsCrossVaultReferences is the B76 regression for
// a genuine blob restored into another vault: its links must not survive,
// or the scheduler would later follow them out of the restore vault.
func TestRestoreCertificate_DropsCrossVaultReferences(t *testing.T) {
	t.Parallel()

	f := newCertRefFixture(t)
	vaultB, newID := uuid.New(), uuid.New()
	require.NoError(t, f.svc.RestoreCertificate(context.Background(), f.blob, f.owner, vaultB, newID))

	restored := f.certs.certs[newID]
	require.NotNil(t, restored)
	assert.Equal(t, vaultB, restored.VaultID)
	assert.Equal(t, uuid.Nil, restored.KeyID, "a key in another vault must not stay linked")
	assert.Nil(t, restored.CACertID, "a CA certificate in another vault must not stay linked")
}

// TestRestoreCertificate_KeepsSameVaultReferences guards the common case: a
// restore into the vault the backup came from must keep auto-renew working.
func TestRestoreCertificate_KeepsSameVaultReferences(t *testing.T) {
	t.Parallel()

	f := newCertRefFixture(t)
	newID := uuid.New()
	require.NoError(t, f.svc.RestoreCertificate(context.Background(), f.blob, f.owner, f.vaultA, newID))

	restored := f.certs.certs[newID]
	require.NotNil(t, restored)
	assert.Equal(t, f.keyID, restored.KeyID)
	require.NotNil(t, restored.CACertID)
	assert.Equal(t, f.caCertID, *restored.CACertID)
}

// TestRestoreCertificate_NoKeyRepoDropsKeyReference pins the fail-closed
// branch: a link that cannot be checked is not kept.
func TestRestoreCertificate_NoKeyRepoDropsKeyReference(t *testing.T) {
	t.Parallel()

	f := newCertRefFixture(t)
	svc := newTestItemBackupService(nil, nil, vaultCheckingCertRepo{f.certs}, nil)
	newID := uuid.New()
	require.NoError(t, svc.RestoreCertificate(context.Background(), f.blob, f.owner, f.vaultA, newID))

	restored := f.certs.certs[newID]
	require.NotNil(t, restored)
	assert.Equal(t, uuid.Nil, restored.KeyID)
	require.NotNil(t, restored.CACertID, "the CA link still resolves and is kept")
}

// scopeRecordingKeyRepo records every scope a Read is called with, on top of
// the vault predicate vaultCheckingKeyRepo applies.
type scopeRecordingKeyRepo struct {
	vaultCheckingKeyRepo
	scopes *[]model.Scope
}

func (r scopeRecordingKeyRepo) Read(ctx context.Context, id uuid.UUID, scope model.Scope) (*model.Key, error) {
	*r.scopes = append(*r.scopes, scope)
	return r.vaultCheckingKeyRepo.Read(ctx, id, scope)
}

// scopeRecordingCertRepo is scopeRecordingKeyRepo's certificate twin.
type scopeRecordingCertRepo struct {
	vaultCheckingCertRepo
	scopes *[]model.Scope
}

func (r scopeRecordingCertRepo) Read(ctx context.Context, id uuid.UUID, scope model.Scope) (*model.Certificate, error) {
	*r.scopes = append(*r.scopes, scope)
	return r.vaultCheckingCertRepo.Read(ctx, id, scope)
}

// TestRestoreCertificate_ForgedSealedBlobDropsForeignLinks pins the attack
// B76 describes: a blob that passes the seal but was built by hand to name a
// key and a CA in another vault. The restorer owns both objects, so only the
// vault check stands between the blob and the scheduler. Every read the
// restore makes must carry the target vault's scope, and nothing may be
// written outside the target vault.
func TestRestoreCertificate_ForgedSealedBlobDropsForeignLinks(t *testing.T) {
	t.Parallel()

	f := newCertRefFixture(t)
	var scopes []model.Scope
	svc := newTestItemBackupService(nil,
		scopeRecordingKeyRepo{vaultCheckingKeyRepo{f.keys}, &scopes},
		scopeRecordingCertRepo{vaultCheckingCertRepo{f.certs}, &scopes},
		nil)

	forgedID := uuid.New()
	caCertID := f.caCertID
	inner, err := backup.ExportedEncodeBlob("certificate", forgedID.String(), &model.Certificate{
		ID: forgedID, UserID: f.owner, VaultID: f.vaultA, Name: "forged",
		Certificate: "PEM", PrivateKey: "ENC", Enabled: true, AutoRenew: true,
		KeyID: f.keyID, CACertID: &caCertID,
	}, backup.ExportedBlobVersions{})
	require.NoError(t, err)
	blob := sealForTest(t, svc, inner)

	before := len(f.certs.certs)
	vaultB, newID := uuid.New(), uuid.New()
	require.NoError(t, svc.RestoreCertificate(context.Background(), blob, f.owner, vaultB, newID))

	restored := f.certs.certs[newID]
	require.NotNil(t, restored)
	assert.Equal(t, vaultB, restored.VaultID, "the blob's vault must never be written")
	assert.Equal(t, f.owner, restored.UserID)
	assert.Equal(t, uuid.Nil, restored.KeyID, "a forged link to a key in another vault must be dropped")
	assert.Nil(t, restored.CACertID, "a forged link to a CA in another vault must be dropped")
	assert.False(t, restored.Exportable)
	assert.Len(t, f.certs.certs, before+1, "the restore writes exactly one certificate row")

	require.Len(t, scopes, 2, "one key read and one CA read")
	want := model.NewVaultScope(vaultB, f.owner)
	for _, s := range scopes {
		assert.Equal(t, want, s, "every link check must read under the target vault's scope")
	}
}

// errReadUnavailable stands in for a repository failure that is not a
// not-found answer, such as a locked or unreachable database.
var errReadUnavailable = errors.New("database is locked")

// failingReadKeyRepo fails every Read with errReadUnavailable.
type failingReadKeyRepo struct{ *stubKeyRepo }

func (failingReadKeyRepo) Read(context.Context, uuid.UUID, model.Scope) (*model.Key, error) {
	return nil, errReadUnavailable
}

// failingReadCertRepo fails every Read with errReadUnavailable and leaves
// Create working, so the restore itself can still be written.
type failingReadCertRepo struct{ *stubCertRepo }

func (failingReadCertRepo) Read(context.Context, uuid.UUID, model.Scope) (*model.Certificate, error) {
	return nil, errReadUnavailable
}

// TestRestoreCertificate_ReadErrorDropsLinks pins the fail-closed choice for
// a repository error that is not a not-found answer: the link could not be
// verified, so it is dropped. Even a same-vault restore loses its links in
// that case; dropping a link only ever causes a later refusal.
func TestRestoreCertificate_ReadErrorDropsLinks(t *testing.T) {
	t.Parallel()

	f := newCertRefFixture(t)
	svc := newTestItemBackupService(nil, failingReadKeyRepo{f.keys}, failingReadCertRepo{f.certs}, nil)
	newID := uuid.New()
	require.NoError(t, svc.RestoreCertificate(context.Background(), f.blob, f.owner, f.vaultA, newID))

	restored := f.certs.certs[newID]
	require.NotNil(t, restored)
	assert.Equal(t, uuid.Nil, restored.KeyID, "an unverifiable key link must not be kept")
	assert.Nil(t, restored.CACertID, "an unverifiable CA link must not be kept")
}

// scopeIgnoringKeyRepo answers every Read whatever its scope, the way a
// misbehaving decorator might. The restore must not trust it.
type scopeIgnoringKeyRepo struct{ *stubKeyRepo }

// TestRestoreCertificate_ScopeIgnoringRepoStillDropsForeignKey pins the
// defence in depth in dropForeignReferences: a key that comes back from
// another vault is treated as not resolving.
func TestRestoreCertificate_ScopeIgnoringRepoStillDropsForeignKey(t *testing.T) {
	t.Parallel()

	f := newCertRefFixture(t)
	svc := newTestItemBackupService(nil, scopeIgnoringKeyRepo{f.keys}, vaultCheckingCertRepo{f.certs}, nil)
	vaultB, newID := uuid.New(), uuid.New()
	require.NoError(t, svc.RestoreCertificate(context.Background(), f.blob, f.owner, vaultB, newID))

	restored := f.certs.certs[newID]
	require.NotNil(t, restored)
	assert.Equal(t, uuid.Nil, restored.KeyID)
}

// TestRestoreCertificate_CrossVaultKeepsHistoryDropsVersionKeyLinks runs on
// the real repositories. A versioned certificate restored into another vault
// keeps every archived version, but no version keeps a key link into the
// source vault. Restored into its own vault, every link survives.
func TestRestoreCertificate_CrossVaultKeepsHistoryDropsVersionKeyLinks(t *testing.T) {
	f := newCertBackupFixture(t)
	ctx := context.Background()
	conn := rvdb.NewConn(f.raw, rvdb.SQLite)
	keys := repositories.NewKeyRepository(conn, logging.InitLogger())

	cert := f.seedCertAtVersion3(t)
	require.NoError(t, keys.Create(ctx, &model.Key{
		ID: cert.KeyID, UserID: f.userID, VaultID: f.vaultID, Name: "signing-key",
		Type: model.KeyTypeRSA, Value: "enc", Enabled: true, CreatedAt: time.Now().UTC(),
	}))

	svc := newTestItemBackupService(nil, keys, f.certs, nil)
	svc.SetTxBeginner(conn)
	svc.SetCertificateVersionRepository(f.versions)

	blob, err := svc.BackupCertificate(ctx, cert.ID, f.userID, f.vaultID)
	require.NoError(t, err)

	otherVault, crossID := uuid.New(), uuid.New()
	require.NoError(t, svc.RestoreCertificate(ctx, blob, f.userID, otherVault, crossID))
	crossRow, err := f.certs.Read(ctx, crossID, model.NewVaultScope(otherVault, f.userID))
	require.NoError(t, err)
	assert.Equal(t, 3, crossRow.Version)
	assert.Equal(t, uuid.Nil, crossRow.KeyID)
	crossVersions, err := f.versions.ListVersionRecords(ctx, crossID)
	require.NoError(t, err)
	require.Len(t, crossVersions, 2, "history must survive a cross-vault restore")
	for _, v := range crossVersions {
		assert.Equal(t, uuid.Nil, v.KeyID, "version %d must not keep a key link into the source vault", v.Version)
	}

	require.NoError(t, f.certs.Delete(ctx, cert.ID))
	sameID := uuid.New()
	require.NoError(t, svc.RestoreCertificate(ctx, blob, f.userID, f.vaultID, sameID))
	sameRow, err := f.certs.Read(ctx, sameID, model.NewVaultScope(f.vaultID, f.userID))
	require.NoError(t, err)
	assert.Equal(t, cert.KeyID, sameRow.KeyID)
	sameVersions, err := f.versions.ListVersionRecords(ctx, sameID)
	require.NoError(t, err)
	require.Len(t, sameVersions, 2)
	for _, v := range sameVersions {
		assert.Equal(t, cert.KeyID, v.KeyID)
	}
}

// TestRestoreCertificate_ForgedVersionsDropOnlyForeignKeyLinks runs a forged
// but validly sealed blob through the real repositories. Its current row and
// one archived version name a key in another vault, its CA lives in that
// vault too, and the other archived version names a key in the target vault.
// Each foreign link is dropped, the local one is kept, and the source vault
// gains no row.
func TestRestoreCertificate_ForgedVersionsDropOnlyForeignKeyLinks(t *testing.T) {
	f := newCertBackupFixture(t)
	ctx := context.Background()
	conn := rvdb.NewConn(f.raw, rvdb.SQLite)
	keys := repositories.NewKeyRepository(conn, logging.InitLogger())

	foreignVault := uuid.New()
	foreignKey, localKey, foreignCA := uuid.New(), uuid.New(), uuid.New()
	now := time.Now().UTC()
	require.NoError(t, keys.Create(ctx, &model.Key{
		ID: foreignKey, UserID: f.userID, VaultID: foreignVault, Name: "foreign-key",
		Type: model.KeyTypeRSA, Value: "enc", Enabled: true, CreatedAt: now,
	}))
	require.NoError(t, keys.Create(ctx, &model.Key{
		ID: localKey, UserID: f.userID, VaultID: f.vaultID, Name: "local-key",
		Type: model.KeyTypeRSA, Value: "enc", Enabled: true, CreatedAt: now,
	}))
	require.NoError(t, f.certs.Create(ctx, &model.Certificate{
		ID: foreignCA, UserID: f.userID, VaultID: foreignVault, Name: "foreign-ca",
		Certificate: "CA-PEM", PrivateKey: "CA-ENC", KeyID: foreignKey, CreatedAt: now, Enabled: true, Version: 1,
	}))

	svc := newTestItemBackupService(nil, keys, f.certs, nil)
	svc.SetTxBeginner(conn)
	svc.SetCertificateVersionRepository(f.versions)

	forgedID := uuid.New()
	inner, err := backup.ExportedEncodeBlob("certificate", forgedID.String(), &model.Certificate{
		ID: forgedID, UserID: f.userID, VaultID: foreignVault, Name: "forged",
		Certificate: "PEM-v3", PrivateKey: "ENC-v3", Enabled: true, AutoRenew: true, Version: 3,
		KeyID: foreignKey, CACertID: &foreignCA, CreatedAt: now,
	}, backup.ExportedBlobVersions{Certificate: []model.CertificateVersionRecord{
		{CertificateID: forgedID, Version: 1, Certificate: "PEM-v1", PrivateKey: "ENC-v1", KeyID: foreignKey, CreatedAt: now, Enabled: true},
		{CertificateID: forgedID, Version: 2, Certificate: "PEM-v2", PrivateKey: "ENC-v2", KeyID: localKey, CreatedAt: now, Enabled: true},
	}})
	require.NoError(t, err)
	blob := sealForTest(t, svc, inner)

	newID := uuid.New()
	require.NoError(t, svc.RestoreCertificate(ctx, blob, f.userID, f.vaultID, newID))

	row, err := f.certs.Read(ctx, newID, model.NewVaultScope(f.vaultID, f.userID))
	require.NoError(t, err)
	assert.Equal(t, f.vaultID, row.VaultID)
	assert.Equal(t, 3, row.Version)
	assert.Equal(t, uuid.Nil, row.KeyID, "the current row must not keep a key link into another vault")
	assert.Nil(t, row.CACertID, "the current row must not keep a CA link into another vault")

	records, err := f.versions.ListVersionRecords(ctx, newID)
	require.NoError(t, err)
	require.Len(t, records, 2)
	assert.Equal(t, uuid.Nil, records[0].KeyID, "version 1's foreign key link must be dropped")
	assert.Equal(t, localKey, records[1].KeyID, "version 2's same-vault key link must be kept")

	assert.Equal(t, 1, f.countRows(t, "SELECT COUNT(*) FROM certificates WHERE vault_id = ?", foreignVault),
		"the source vault must hold only its own CA")
	assert.Zero(t, f.countRows(t, "SELECT COUNT(*) FROM certificates WHERE id = ?", forgedID),
		"the blob's own ID must never be written")
}
