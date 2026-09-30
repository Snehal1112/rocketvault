package repositories_test

import (
	"context"
	"database/sql"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	rvdb "rocketvault/internal/db"
	"rocketvault/internal/logging"
	"rocketvault/internal/repositories"
	"rocketvault/model"
)

// newCertVersionFixture builds both repositories over the real schema, so
// these tests exercise the same DDL production runs.
func newCertVersionFixture(t *testing.T) (repositories.CertificateRepositoryInterface, repositories.CertificateVersionRepositoryInterface, *sql.DB) {
	t.Helper()
	raw := newSharedCacheDB(t, "cert_versions_"+uuid.NewString())
	require.NoError(t, rvdb.NewRepository(logging.InitLogger()).SetupSchema(raw, rvdb.SQLite))
	conn := rvdb.NewConn(raw, rvdb.SQLite)
	log := logging.InitLogger()
	return repositories.NewCertificateRepository(conn, log), repositories.NewCertificateVersionRepository(conn, log), raw
}

// seedVersionedCert stores a version-1 certificate in vaultID.
func seedVersionedCert(t *testing.T, certs repositories.CertificateRepositoryInterface, vaultID uuid.UUID) *model.Certificate {
	t.Helper()
	expires := time.Now().Add(30 * 24 * time.Hour).UTC()
	caID := uuid.New()
	cert := &model.Certificate{
		ID: uuid.New(), UserID: uuid.New(), VaultID: vaultID, KeyID: uuid.New(), CACertID: &caID,
		Name: "versioned-" + uuid.NewString()[:8], Certificate: "PEM-v1", PrivateKey: "ENC-v1",
		CreatedAt: time.Now().UTC(), ExpiresAt: &expires, Enabled: true, RenewalDays: 30, Version: 1,
	}
	require.NoError(t, certs.Create(context.Background(), cert))
	return cert
}

// renewedFrom builds the row a renewal of cert would write.
func renewedFrom(cert *model.Certificate, body string) *model.Certificate {
	next := *cert
	next.Certificate = body
	next.PrivateKey = "ENC-" + body
	next.Version = cert.CurrentVersion() + 1
	next.CreatedAt = time.Now().UTC()
	expires := time.Now().Add(365 * 24 * time.Hour).UTC()
	next.ExpiresAt = &expires
	notBefore := time.Now().UTC()
	next.NotBefore = &notBefore
	next.Enabled = true
	return &next
}

func countCertVersions(t *testing.T, raw *sql.DB, certID uuid.UUID) int {
	t.Helper()
	var n int
	require.NoError(t, raw.QueryRow("SELECT COUNT(*) FROM certificate_versions WHERE certificate_id = ?", certID.String()).Scan(&n))
	return n
}

func TestCertificateRepository_ReadsVersionColumn(t *testing.T) {
	certs, _, _ := newCertVersionFixture(t)
	vaultID := uuid.New()
	cert := seedVersionedCert(t, certs, vaultID)

	got, err := certs.Read(context.Background(), cert.ID, model.NewVaultScope(vaultID, cert.UserID))
	require.NoError(t, err)
	assert.Equal(t, 1, got.Version)

	unversioned := *cert
	unversioned.ID = uuid.New()
	unversioned.Name = "zero-version"
	unversioned.Version = 0
	require.NoError(t, certs.Create(context.Background(), &unversioned))
	got, err = certs.Read(context.Background(), unversioned.ID, model.NewVaultScope(vaultID, cert.UserID))
	require.NoError(t, err)
	assert.Equal(t, 1, got.Version, "a zero Version is stored as version 1")
}

func TestArchiveAndRenew_ArchivesCurrentAndBumpsParent(t *testing.T) {
	certs, versions, raw := newCertVersionFixture(t)
	ctx := context.Background()
	vaultID := uuid.New()
	cert := seedVersionedCert(t, certs, vaultID)
	scope := model.NewVaultScope(vaultID, cert.UserID)

	require.NoError(t, versions.ArchiveAndRenew(ctx, cert.ArchiveRecord(), renewedFrom(cert, "PEM-v2"), scope))

	got, err := certs.Read(ctx, cert.ID, scope)
	require.NoError(t, err)
	assert.Equal(t, 2, got.Version)
	assert.Equal(t, "PEM-v2", got.Certificate)
	assert.Equal(t, "ENC-PEM-v2", got.PrivateKey)
	require.NotNil(t, got.CACertID, "renewal must leave ca_cert_id alone (B37)")
	assert.Equal(t, *cert.CACertID, *got.CACertID)

	records, err := versions.ListVersionRecords(ctx, cert.ID)
	require.NoError(t, err)
	require.Len(t, records, 1)
	assert.Equal(t, 1, records[0].Version)
	assert.Equal(t, "PEM-v1", records[0].Certificate)
	assert.Equal(t, "ENC-v1", records[0].PrivateKey)
	assert.Equal(t, cert.KeyID, records[0].KeyID)
	assert.Equal(t, 1, countCertVersions(t, raw, cert.ID))
}

func TestArchiveAndRenew_InsertFailureRollsBackParent(t *testing.T) {
	certs, versions, _ := newCertVersionFixture(t)
	ctx := context.Background()
	vaultID := uuid.New()
	cert := seedVersionedCert(t, certs, vaultID)
	scope := model.NewVaultScope(vaultID, cert.UserID)

	// A row already archived under the current number makes the insert half fail.
	pre := cert.ArchiveRecord()
	require.NoError(t, versions.CreateVersion(ctx, &pre))

	err := versions.ArchiveAndRenew(ctx, cert.ArchiveRecord(), renewedFrom(cert, "PEM-v2"), scope)
	require.Error(t, err)
	assert.True(t, errors.Is(err, repositories.ErrCertificateVersionConflict))

	got, err := certs.Read(ctx, cert.ID, scope)
	require.NoError(t, err)
	assert.Equal(t, 1, got.Version, "the parent must be untouched when the archive insert fails")
	assert.Equal(t, "PEM-v1", got.Certificate)
}

func TestArchiveAndRenew_UpdateFailureRollsBackArchive(t *testing.T) {
	certs, versions, raw := newCertVersionFixture(t)
	ctx := context.Background()
	vaultID := uuid.New()
	cert := seedVersionedCert(t, certs, vaultID)
	scope := model.NewVaultScope(vaultID, cert.UserID)

	// The insert half succeeds (no row at 5), the update half matches nothing
	// (the row is at 1, not 5), so the insert must be rolled back.
	archived := cert.ArchiveRecord()
	archived.Version = 5
	renewed := renewedFrom(cert, "PEM-v6")
	renewed.Version = 6

	err := versions.ArchiveAndRenew(ctx, archived, renewed, scope)
	require.Error(t, err)
	assert.True(t, errors.Is(err, repositories.ErrCertificateVersionConflict))
	assert.Zero(t, countCertVersions(t, raw, cert.ID), "the archive row must roll back with the failed update")
}

func TestArchiveAndRenew_ConcurrentRenewalsHaveOneWinner(t *testing.T) {
	certs, versions, raw := newCertVersionFixture(t)
	ctx := context.Background()
	vaultID := uuid.New()
	cert := seedVersionedCert(t, certs, vaultID)
	scope := model.NewVaultScope(vaultID, cert.UserID)

	// Both renewals read version 1 before either wrote.
	first := renewedFrom(cert, "PEM-first")
	second := renewedFrom(cert, "PEM-second")

	require.NoError(t, versions.ArchiveAndRenew(ctx, cert.ArchiveRecord(), first, scope))
	err := versions.ArchiveAndRenew(ctx, cert.ArchiveRecord(), second, scope)
	require.Error(t, err)
	assert.True(t, errors.Is(err, repositories.ErrCertificateVersionConflict))

	got, err := certs.Read(ctx, cert.ID, scope)
	require.NoError(t, err)
	assert.Equal(t, "PEM-first", got.Certificate)
	assert.Equal(t, 2, got.Version)
	assert.Equal(t, 1, countCertVersions(t, raw, cert.ID))
}

func TestArchiveAndRenew_RejectsNonSequentialVersion(t *testing.T) {
	certs, versions, _ := newCertVersionFixture(t)
	vaultID := uuid.New()
	cert := seedVersionedCert(t, certs, vaultID)
	renewed := renewedFrom(cert, "PEM-v3")
	renewed.Version = 3

	err := versions.ArchiveAndRenew(context.Background(), cert.ArchiveRecord(), renewed, model.NewVaultScope(vaultID, cert.UserID))
	require.Error(t, err)
}

func TestArchiveAndRenew_OutOfScopeWritesNothing(t *testing.T) {
	certs, versions, raw := newCertVersionFixture(t)
	ctx := context.Background()
	cert := seedVersionedCert(t, certs, uuid.New())

	err := versions.ArchiveAndRenew(ctx, cert.ArchiveRecord(), renewedFrom(cert, "PEM-v2"), model.NewVaultScope(uuid.New(), cert.UserID))
	require.Error(t, err)
	assert.Zero(t, countCertVersions(t, raw, cert.ID))
}

func TestCertificateVersions_ListGetAndUpdateArchived(t *testing.T) {
	certs, versions, _ := newCertVersionFixture(t)
	ctx := context.Background()
	vaultID := uuid.New()
	cert := seedVersionedCert(t, certs, vaultID)
	scope := model.NewVaultScope(vaultID, cert.UserID)

	v2 := renewedFrom(cert, "PEM-v2")
	require.NoError(t, versions.ArchiveAndRenew(ctx, cert.ArchiveRecord(), v2, scope))
	require.NoError(t, versions.ArchiveAndRenew(ctx, v2.ArchiveRecord(), renewedFrom(v2, "PEM-v3"), scope))

	list, err := versions.ListVersions(ctx, cert.ID)
	require.NoError(t, err)
	require.Len(t, list, 2)
	assert.Equal(t, []int{1, 2}, []int{list[0].Version, list[1].Version})
	assert.False(t, list[0].Current)

	one, err := versions.GetVersion(ctx, cert.ID, 1)
	require.NoError(t, err)
	assert.True(t, one.Enabled)

	for _, missing := range []int{0, 3, 9} {
		_, err := versions.GetVersion(ctx, cert.ID, missing)
		assert.True(t, errors.Is(err, repositories.ErrCertificateVersionNotFound), "version %d", missing)
	}

	require.NoError(t, versions.UpdateVersionLifecycle(ctx, cert.ID, 1, model.CertificateVersionAttributes{Enabled: false}))
	one, err = versions.GetVersion(ctx, cert.ID, 1)
	require.NoError(t, err)
	assert.False(t, one.Enabled)

	err = versions.UpdateVersionLifecycle(ctx, cert.ID, 9, model.CertificateVersionAttributes{Enabled: true})
	assert.True(t, errors.Is(err, repositories.ErrCertificateVersionNotFound))
}

func TestCreateVersion_DuplicateRejected(t *testing.T) {
	certs, versions, _ := newCertVersionFixture(t)
	cert := seedVersionedCert(t, certs, uuid.New())
	rec := cert.ArchiveRecord()

	require.NoError(t, versions.CreateVersion(context.Background(), &rec))
	err := versions.CreateVersion(context.Background(), &rec)
	assert.True(t, errors.Is(err, repositories.ErrCertificateVersionConflict))
}

func TestUpdateCurrentLifecycle_WritesParent(t *testing.T) {
	certs, versions, _ := newCertVersionFixture(t)
	ctx := context.Background()
	vaultID := uuid.New()
	cert := seedVersionedCert(t, certs, vaultID)
	scope := model.NewVaultScope(vaultID, cert.UserID)

	notBefore := time.Now().Add(-time.Hour).UTC()
	require.NoError(t, versions.UpdateCurrentLifecycle(ctx, cert.ID, 1,
		model.CertificateVersionAttributes{Enabled: false, ExpiresAt: cert.ExpiresAt, NotBefore: &notBefore}, scope))

	got, err := certs.Read(ctx, cert.ID, scope)
	require.NoError(t, err)
	assert.False(t, got.Enabled)
	require.NotNil(t, got.NotBefore)
	assert.WithinDuration(t, notBefore, *got.NotBefore, time.Second)
}

// TestUpdateCurrentLifecycle_StaleVersionConflicts pins Review Focus 3: a
// current-version update that read version 1 must not land on version 2
// after a renewal committed in between.
func TestUpdateCurrentLifecycle_StaleVersionConflicts(t *testing.T) {
	certs, versions, _ := newCertVersionFixture(t)
	ctx := context.Background()
	vaultID := uuid.New()
	cert := seedVersionedCert(t, certs, vaultID)
	scope := model.NewVaultScope(vaultID, cert.UserID)

	require.NoError(t, versions.ArchiveAndRenew(ctx, cert.ArchiveRecord(), renewedFrom(cert, "PEM-v2"), scope))

	err := versions.UpdateCurrentLifecycle(ctx, cert.ID, 1, model.CertificateVersionAttributes{Enabled: false}, scope)
	require.Error(t, err)
	assert.True(t, errors.Is(err, repositories.ErrCertificateVersionConflict))

	got, err := certs.Read(ctx, cert.ID, scope)
	require.NoError(t, err)
	assert.True(t, got.Enabled, "version 2 must be untouched by an update aimed at version 1")
}

// TestCertificateUpdate_StaleReadConflicts pins Review Focus 1: a metadata
// update built from a read taken before a renewal must not put the old
// not_before or enabled back over the new version, nor touch the body, key or
// dates. It reports a version conflict instead.
func TestCertificateUpdate_StaleReadConflicts(t *testing.T) {
	certs, versions, _ := newCertVersionFixture(t)
	ctx := context.Background()
	vaultID := uuid.New()
	cert := seedVersionedCert(t, certs, vaultID)
	scope := model.NewVaultScope(vaultID, cert.UserID)

	// Give the seed an old not_before and enabled = true, then read it.
	oldNotBefore := time.Now().Add(-48 * time.Hour).UTC()
	cert.NotBefore = &oldNotBefore
	require.NoError(t, certs.Update(ctx, cert, scope))
	stale, err := certs.Read(ctx, cert.ID, scope)
	require.NoError(t, err)
	require.True(t, stale.Enabled)
	require.NotNil(t, stale.NotBefore)

	renewed := renewedFrom(stale, "PEM-v2")
	require.NoError(t, versions.ArchiveAndRenew(ctx, stale.ArchiveRecord(), renewed, scope))

	stale.Name = "renamed-after-renewal"
	stale.Enabled = false
	err = certs.Update(ctx, stale, scope)
	require.Error(t, err)
	assert.True(t, errors.Is(err, repositories.ErrCertificateVersionConflict))

	got, err := certs.Read(ctx, cert.ID, scope)
	require.NoError(t, err)
	assert.Equal(t, cert.Name, got.Name)
	assert.Equal(t, "PEM-v2", got.Certificate)
	assert.Equal(t, "ENC-PEM-v2", got.PrivateKey)
	assert.Equal(t, 2, got.Version)
	assert.True(t, got.Enabled)
	require.NotNil(t, got.NotBefore)
	assert.WithinDuration(t, *renewed.NotBefore, *got.NotBefore, time.Second)
	require.NotNil(t, got.ExpiresAt)
	assert.WithinDuration(t, *renewed.ExpiresAt, *got.ExpiresAt, time.Second)
	assert.WithinDuration(t, renewed.CreatedAt, got.CreatedAt, time.Second)
}

// TestCertificateUpdate_FreshReadSucceedsWithoutTouchingMaterial pins that an
// update built from a current read lands, and still writes metadata only.
func TestCertificateUpdate_FreshReadSucceedsWithoutTouchingMaterial(t *testing.T) {
	certs, versions, _ := newCertVersionFixture(t)
	ctx := context.Background()
	vaultID := uuid.New()
	cert := seedVersionedCert(t, certs, vaultID)
	scope := model.NewVaultScope(vaultID, cert.UserID)

	renewed := renewedFrom(cert, "PEM-v2")
	require.NoError(t, versions.ArchiveAndRenew(ctx, cert.ArchiveRecord(), renewed, scope))

	fresh, err := certs.Read(ctx, cert.ID, scope)
	require.NoError(t, err)
	fresh.Name = "renamed-after-renewal"
	fresh.Certificate = "TAMPERED"
	fresh.PrivateKey = "TAMPERED"
	require.NoError(t, certs.Update(ctx, fresh, scope))

	got, err := certs.Read(ctx, cert.ID, scope)
	require.NoError(t, err)
	assert.Equal(t, "renamed-after-renewal", got.Name)
	assert.Equal(t, "PEM-v2", got.Certificate)
	assert.Equal(t, "ENC-PEM-v2", got.PrivateKey)
	assert.Equal(t, 2, got.Version)
	require.NotNil(t, got.ExpiresAt)
	assert.WithinDuration(t, *renewed.ExpiresAt, *got.ExpiresAt, time.Second)
}
