package backup_test

import (
	"context"
	"database/sql"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	_ "github.com/mattn/go-sqlite3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"rocketvault/internal/backup"
	rvdb "rocketvault/internal/db"
	"rocketvault/internal/logging"
	"rocketvault/internal/repositories"
	"rocketvault/model"
)

type certBackupFixture struct {
	raw      *sql.DB
	certs    repositories.CertificateRepositoryInterface
	versions repositories.CertificateVersionRepositoryInterface
	svc      *backup.ItemBackupService
	userID   uuid.UUID
	vaultID  uuid.UUID
}

func newCertBackupFixture(t *testing.T) *certBackupFixture {
	t.Helper()
	raw, err := sql.Open("sqlite3", "file:certbackup_"+uuid.NewString()+"?mode=memory&cache=shared")
	require.NoError(t, err)
	t.Cleanup(func() { raw.Close() }) //nolint:errcheck,gosec
	require.NoError(t, rvdb.NewRepository(logging.InitLogger()).SetupSchema(raw, rvdb.SQLite))

	conn := rvdb.NewConn(raw, rvdb.SQLite)
	log := logging.InitLogger()
	f := &certBackupFixture{
		raw:      raw,
		certs:    repositories.NewCertificateRepository(conn, log),
		versions: repositories.NewCertificateVersionRepository(conn, log),
		userID:   uuid.New(),
		vaultID:  uuid.New(),
	}
	f.svc = backup.NewItemBackupService(nil, nil, f.certs, nil)
	f.svc.SetTxBeginner(conn)
	f.svc.SetCertificateVersionRepository(f.versions)
	return f
}

// seedCertAtVersion3 stores a certificate whose history is versions 1 and 2.
func (f *certBackupFixture) seedCertAtVersion3(t *testing.T) *model.Certificate {
	t.Helper()
	ctx := context.Background()
	cert := &model.Certificate{
		ID: uuid.New(), UserID: f.userID, VaultID: f.vaultID, KeyID: uuid.New(),
		Name: "backed-up-" + uuid.NewString()[:8], Certificate: "PEM-v3", PrivateKey: "ENC-v3",
		CreatedAt: time.Now().UTC(), Enabled: true, RenewalDays: 30, Version: 3,
	}
	require.NoError(t, f.certs.Create(ctx, cert))
	for _, n := range []int{1, 2} {
		rec := &model.CertificateVersionRecord{
			CertificateID: cert.ID, Version: n, Certificate: "PEM-v" + string(rune('0'+n)),
			PrivateKey: "ENC-v" + string(rune('0'+n)), KeyID: cert.KeyID, CreatedAt: time.Now().UTC(), Enabled: true,
		}
		require.NoError(t, f.versions.CreateVersion(ctx, rec))
	}
	return cert
}

func (f *certBackupFixture) countRows(t *testing.T, query string, id uuid.UUID) int {
	t.Helper()
	var n int
	require.NoError(t, f.raw.QueryRow(query, id.String()).Scan(&n))
	return n
}

func TestCertificateBackupRestore_RoundTripsVersions(t *testing.T) {
	f := newCertBackupFixture(t)
	ctx := context.Background()
	cert := f.seedCertAtVersion3(t)

	blob, err := f.svc.BackupCertificate(ctx, cert.ID, f.userID, f.vaultID)
	require.NoError(t, err)

	// Restore under a new name so the unique (vault, name) index allows it.
	require.NoError(t, f.certs.Delete(ctx, cert.ID))
	newID := uuid.New()
	require.NoError(t, f.svc.RestoreCertificate(ctx, blob, f.userID, f.vaultID, newID))

	restored, err := f.certs.Read(ctx, newID, model.NewVaultScope(f.vaultID, f.userID))
	require.NoError(t, err)
	assert.Equal(t, 3, restored.Version)
	assert.Equal(t, "PEM-v3", restored.Certificate)

	records, err := f.versions.ListVersionRecords(ctx, newID)
	require.NoError(t, err)
	require.Len(t, records, 2)
	assert.Equal(t, []int{1, 2}, []int{records[0].Version, records[1].Version})
	assert.Equal(t, "PEM-v1", records[0].Certificate)
	assert.Equal(t, "ENC-v2", records[1].PrivateKey)
}

// legacyCertificate is the certificate shape a blob written before
// versioning carries: no version field at all.
type legacyCertificate struct {
	ID          uuid.UUID `json:"id"`
	UserID      uuid.UUID `json:"user_id"`
	VaultID     uuid.UUID `json:"vault_id"`
	Name        string    `json:"name"`
	Certificate string    `json:"certificate"`
	PrivateKey  string    `json:"private_key"`
	CreatedAt   time.Time `json:"created_at"`
	Enabled     bool      `json:"enabled"`
}

func TestRestoreCertificate_PreVersioningBlobRestoresAsVersionOne(t *testing.T) {
	f := newCertBackupFixture(t)
	ctx := context.Background()
	id := uuid.New()
	blob, err := backup.ExportedEncodeBlob("certificate", id.String(), legacyCertificate{
		ID: id, UserID: f.userID, VaultID: f.vaultID, Name: "legacy", Certificate: "PEM",
		PrivateKey: "ENC", CreatedAt: time.Now().UTC(), Enabled: true,
	}, backup.ExportedBlobVersions{})
	require.NoError(t, err)

	newID := uuid.New()
	require.NoError(t, f.svc.RestoreCertificate(ctx, blob, f.userID, f.vaultID, newID))

	restored, err := f.certs.Read(ctx, newID, model.NewVaultScope(f.vaultID, f.userID))
	require.NoError(t, err)
	assert.Equal(t, 1, restored.Version)
	assert.Zero(t, f.countRows(t, "SELECT COUNT(*) FROM certificate_versions WHERE certificate_id = ?", newID))
}

// failingCertVersionRepo fails the second archived-version insert, on
// whichever path the restore takes.
type failingCertVersionRepo struct {
	repositories.CertificateVersionRepositoryInterface
	real interface {
		CreateVersionTx(ctx context.Context, ex rvdb.DBTX, rec *model.CertificateVersionRecord) error
	}
	calls int
}

var errInjectedCertVersionFailure = errors.New("injected failure: second archived certificate version")

func (f *failingCertVersionRepo) CreateVersion(ctx context.Context, rec *model.CertificateVersionRecord) error {
	f.calls++
	if f.calls == 2 {
		return errInjectedCertVersionFailure
	}
	return f.CertificateVersionRepositoryInterface.CreateVersion(ctx, rec)
}

func (f *failingCertVersionRepo) CreateVersionTx(ctx context.Context, ex rvdb.DBTX, rec *model.CertificateVersionRecord) error {
	f.calls++
	if f.calls == 2 {
		return errInjectedCertVersionFailure
	}
	return f.real.CreateVersionTx(ctx, ex, rec)
}

func TestRestoreCertificate_FailedReplayRollsBackRestore(t *testing.T) {
	f := newCertBackupFixture(t)
	ctx := context.Background()
	cert := f.seedCertAtVersion3(t)
	blob, err := f.svc.BackupCertificate(ctx, cert.ID, f.userID, f.vaultID)
	require.NoError(t, err)
	require.NoError(t, f.certs.Delete(ctx, cert.ID))

	real, ok := f.versions.(interface {
		CreateVersionTx(ctx context.Context, ex rvdb.DBTX, rec *model.CertificateVersionRecord) error
	})
	require.True(t, ok, "the real version repository is Tx-capable")
	f.svc.SetCertificateVersionRepository(&failingCertVersionRepo{CertificateVersionRepositoryInterface: f.versions, real: real})

	newID := uuid.New()
	err = f.svc.RestoreCertificate(ctx, blob, f.userID, f.vaultID, newID)
	require.ErrorIs(t, err, errInjectedCertVersionFailure)
	assert.Zero(t, f.countRows(t, "SELECT COUNT(*) FROM certificates WHERE id = ?", newID), "the certificate row must roll back")
	assert.Zero(t, f.countRows(t, "SELECT COUNT(*) FROM certificate_versions WHERE certificate_id = ?", newID))
}

// TestRestoreCertificate_RejectsInconsistentVersionNumbers pins Review Focus
// 4: a forged or corrupt blob whose history does not sit strictly below the
// current version is refused before anything is written.
func TestRestoreCertificate_RejectsInconsistentVersionNumbers(t *testing.T) {
	cases := map[string][]int{
		"equal to current": {1, 2},
		"above current":    {3},
		"duplicate":        {1, 1},
		"below one":        {0},
	}
	for name, numbers := range cases {
		t.Run(name, func(t *testing.T) {
			f := newCertBackupFixture(t)
			id := uuid.New()
			var records []model.CertificateVersionRecord
			for _, n := range numbers {
				records = append(records, model.CertificateVersionRecord{CertificateID: id, Version: n, Certificate: "PEM", PrivateKey: "ENC"})
			}
			current := 2
			if name == "above current" {
				current = 3
				records[0].Version = 4
			}
			blob, err := backup.ExportedEncodeBlob("certificate", id.String(), &model.Certificate{
				ID: id, Name: "forged", Certificate: "PEM", PrivateKey: "ENC", Enabled: true, Version: current,
			}, backup.ExportedBlobVersions{Certificate: records})
			require.NoError(t, err)

			newID := uuid.New()
			err = f.svc.RestoreCertificate(context.Background(), blob, f.userID, f.vaultID, newID)
			require.ErrorIs(t, err, backup.ErrInvalidBlob)
			assert.Zero(t, f.countRows(t, "SELECT COUNT(*) FROM certificates WHERE id = ?", newID))
		})
	}
}

// TestBackupCertificate_HistoryWithoutVersionRepoFailsClosed pins Review
// Focus 5: a certificate with history must not be backed up without it.
func TestBackupCertificate_HistoryWithoutVersionRepoFailsClosed(t *testing.T) {
	f := newCertBackupFixture(t)
	cert := f.seedCertAtVersion3(t)
	unwired := backup.NewItemBackupService(nil, nil, f.certs, nil)

	_, err := unwired.BackupCertificate(context.Background(), cert.ID, f.userID, f.vaultID)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no version repository")
}
