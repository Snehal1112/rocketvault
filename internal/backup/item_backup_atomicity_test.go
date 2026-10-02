package backup_test

// Real-database tests for F3: RestoreSecret must be atomic when a
// TxBeginner is wired up (the production DI path), and must preserve its
// pre-existing non-transactional behavior exactly when one is not (the
// path every other test in this package still exercises). A mocked
// repository cannot prove either claim — only a real transaction rolling
// back, or not, can.

import (
	"context"
	"database/sql"
	"testing"

	"github.com/google/uuid"
	_ "github.com/mattn/go-sqlite3"
	"github.com/stretchr/testify/require"

	rvdb "rocketvault/internal/db"
	"rocketvault/internal/repositories"
	"rocketvault/internal/testutils"
	"rocketvault/model"
)

// atomicityFixtureSchema mirrors internal/db/db.go's createOptimizedSchema
// for only the tables an item-backup restore touches.
const atomicityFixtureSchema = `
	CREATE TABLE secrets (
		id TEXT PRIMARY KEY,
		user_id TEXT NOT NULL,
		name TEXT NOT NULL,
		vault_id TEXT NOT NULL,
		value TEXT NOT NULL,
		version INTEGER NOT NULL,
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		deleted_at TIMESTAMP NULL,
		purge_protection BOOLEAN NOT NULL DEFAULT FALSE,
		content_type TEXT NOT NULL DEFAULT '',
		enabled BOOLEAN NOT NULL DEFAULT TRUE,
		expires_at TIMESTAMP NULL,
		not_before TIMESTAMP NULL
	);
	CREATE TABLE secret_tags (
		secret_id TEXT NOT NULL,
		tag TEXT NOT NULL,
		PRIMARY KEY (secret_id, tag)
	);
	CREATE TABLE secret_versions (
		id TEXT PRIMARY KEY,
		secret_id TEXT NOT NULL,
		user_id TEXT NOT NULL,
		name TEXT NOT NULL,
		value TEXT NOT NULL,
		version INTEGER NOT NULL,
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
	);
`

// atomicityFixture wires the real SecretRepository and secretVersionRepository
// against a real in-memory SQLite database, so a transaction really commits
// or really rolls back — nothing here is mocked.
type atomicityFixture struct {
	conn        *sql.DB
	dbConn      *rvdb.Conn
	secretRepo  repositories.SecretRepositoryInterface
	versionRepo repositories.SecretVersionRepositoryInterface
	userID      uuid.UUID
	vaultID     uuid.UUID
	secretID    uuid.UUID
}

func newAtomicityFixture(t *testing.T) *atomicityFixture {
	t.Helper()

	conn, err := sql.Open("sqlite3", ":memory:")
	require.NoError(t, err)
	t.Cleanup(func() { conn.Close() }) //nolint:errcheck,gosec

	_, err = conn.Exec(atomicityFixtureSchema)
	require.NoError(t, err)

	log := testutils.NewTestLogger(t)
	dbConn := rvdb.NewConn(conn, rvdb.SQLite)

	f := &atomicityFixture{
		conn:        conn,
		dbConn:      dbConn,
		secretRepo:  repositories.NewSecretRepository(dbConn, log),
		versionRepo: repositories.NewSecretVersionRepository(dbConn, log),
		userID:      uuid.New(),
		vaultID:     uuid.New(),
		secretID:    uuid.New(),
	}

	ctx := context.Background()
	require.NoError(t, f.secretRepo.Create(ctx, &model.Secret{
		ID:      f.secretID,
		UserID:  f.userID,
		VaultID: f.vaultID,
		Name:    "atomic-secret",
		Value:   "enc-original",
		Version: 1,
	}))

	return f
}

// scope returns the vault scope a caller authorized in this vault would use.
func (f *atomicityFixture) scope() model.Scope {
	return model.NewVaultScope(f.vaultID, f.userID)
}

// countSecretsByID returns how many rows in the secrets table have id = id —
// 0 or 1, since id is the primary key. Used to assert whether a restore's
// Create survived or was rolled back.
func (f *atomicityFixture) countSecretsByID(t *testing.T, id uuid.UUID) int {
	t.Helper()
	var n int
	require.NoError(t, f.conn.QueryRow("SELECT COUNT(*) FROM secrets WHERE id = ?", id.String()).Scan(&n))
	return n
}

// countVersionsBySecretID returns how many secret_versions rows reference
// secretID.
func (f *atomicityFixture) countVersionsBySecretID(t *testing.T, secretID uuid.UUID) int {
	t.Helper()
	var n int
	require.NoError(t, f.conn.QueryRow("SELECT COUNT(*) FROM secret_versions WHERE secret_id = ?", secretID.String()).Scan(&n))
	return n
}

// failingVersionRepo wraps a real, Tx-capable SecretVersionRepositoryInterface
// and fails deterministically on its failOn'th CreateVersion/CreateVersionTx
// call (1-indexed), regardless of which path the caller takes. This is what
// lets these tests force a mid-restore failure precisely on the second of
// two archived versions, using a REAL repository and REAL database for
// everything up to that point — not a hand-rolled stub that could hide a
// real wiring bug.
type failingVersionRepo struct {
	repositories.SecretVersionRepositoryInterface
	real      txCapableVersionRepo
	failOn    int
	callCount int
}

// txCapableVersionRepo is a structural (ad-hoc) interface matching
// secretVersionRepository's CreateVersionTx. It does not need to import that
// unexported type: Go interface satisfaction is structural, so any value
// whose dynamic type exports a CreateVersionTx method with this exact
// signature satisfies it, regardless of which package defined that type.
type txCapableVersionRepo interface {
	CreateVersionTx(ctx context.Context, ex rvdb.DBTX, version *model.SecretVersion) error
}

func newFailingVersionRepo(t *testing.T, real repositories.SecretVersionRepositoryInterface, failOn int) *failingVersionRepo {
	t.Helper()
	txReal, ok := real.(txCapableVersionRepo)
	require.True(t, ok, "the real secretVersionRepository must implement CreateVersionTx for this test to be meaningful")
	return &failingVersionRepo{SecretVersionRepositoryInterface: real, real: txReal, failOn: failOn}
}

func (f *failingVersionRepo) CreateVersion(ctx context.Context, version *model.SecretVersion) error {
	f.callCount++
	if f.callCount == f.failOn {
		return errInjectedVersionFailure
	}
	return f.SecretVersionRepositoryInterface.CreateVersion(ctx, version)
}

func (f *failingVersionRepo) CreateVersionTx(ctx context.Context, ex rvdb.DBTX, version *model.SecretVersion) error {
	f.callCount++
	if f.callCount == f.failOn {
		return errInjectedVersionFailure
	}
	return f.real.CreateVersionTx(ctx, ex, version)
}

var errInjectedVersionFailure = &injectedError{"injected failure: second archived version"}

type injectedError struct{ msg string }

func (e *injectedError) Error() string { return e.msg }

// seedTwoArchivedVersions writes two version rows for f.secretID directly
// (bypassing ItemBackupService), so BackupSecret's blob carries two versions
// to replay — the minimum needed to have a "first version succeeds, second
// fails" case.
func (f *atomicityFixture) seedTwoArchivedVersions(t *testing.T) {
	t.Helper()
	ctx := context.Background()
	require.NoError(t, f.versionRepo.CreateVersion(ctx, &model.SecretVersion{
		ID: uuid.New(), SecretID: f.secretID, UserID: f.userID, Name: "atomic-secret", Value: "enc-v1", Version: 1,
	}))
	require.NoError(t, f.versionRepo.CreateVersion(ctx, &model.SecretVersion{
		ID: uuid.New(), SecretID: f.secretID, UserID: f.userID, Name: "atomic-secret", Value: "enc-v2", Version: 2,
	}))
}

func TestRestoreSecret_TxBeginnerSet_FailurePartwayRollsBackEverything(t *testing.T) {
	f := newAtomicityFixture(t)
	f.seedTwoArchivedVersions(t)
	ctx := context.Background()

	backupSvc := newTestItemBackupService(f.secretRepo, nil, nil, f.versionRepo)
	blob, err := backupSvc.BackupSecret(ctx, f.secretID, f.userID, f.vaultID)
	require.NoError(t, err)

	failingVersions := newFailingVersionRepo(t, f.versionRepo, 2) // fail on the 2nd version
	restoreSvc := newTestItemBackupService(f.secretRepo, nil, nil, failingVersions)
	restoreSvc.SetTxBeginner(f.dbConn)

	newID := uuid.New()
	err = restoreSvc.RestoreSecret(ctx, blob, f.userID, f.vaultID, newID)
	require.Error(t, err, "the injected failure on the 2nd version must surface as an error")

	require.Equal(t, 0, f.countSecretsByID(t, newID),
		"F3: with a TxBeginner wired up, a version-replay failure must roll back the Create too — no partial secret row should exist")
	require.Equal(t, 0, f.countVersionsBySecretID(t, newID),
		"the one version that succeeded before the failure must also be rolled back, not left behind")
}

func TestRestoreSecret_NoTxBeginner_FailurePartwayLeavesDocumentedPartialRestore(t *testing.T) {
	f := newAtomicityFixture(t)
	f.seedTwoArchivedVersions(t)
	ctx := context.Background()

	backupSvc := newTestItemBackupService(f.secretRepo, nil, nil, f.versionRepo)
	blob, err := backupSvc.BackupSecret(ctx, f.secretID, f.userID, f.vaultID)
	require.NoError(t, err)

	failingVersions := newFailingVersionRepo(t, f.versionRepo, 2) // fail on the 2nd version
	restoreSvc := newTestItemBackupService(f.secretRepo, nil, nil, failingVersions)
	// No SetTxBeginner call: this is the pre-existing, still-supported
	// non-transactional path (e.g. a caller that never wires one up).

	newID := uuid.New()
	err = restoreSvc.RestoreSecret(ctx, blob, f.userID, f.vaultID, newID)
	require.Error(t, err, "the injected failure on the 2nd version must surface as an error")

	// This is the pre-F3, still-intentional behavior for the non-tx path:
	// the Create and the one version that succeeded before the failure are
	// left in place, unprotected (so an operator can still purge them) — see
	// restoreSecretWith's comment on why versions replay before purge
	// protection is applied.
	require.Equal(t, 1, f.countSecretsByID(t, newID),
		"the non-transactional path must still leave its documented partial restore behind, unchanged by F3's tx path existing")
	require.Equal(t, 1, f.countVersionsBySecretID(t, newID),
		"exactly the one version that succeeded before the injected failure should be present")
}

func TestRestoreSecret_TxBeginnerSet_SuccessCommitsSecretAndAllVersions(t *testing.T) {
	f := newAtomicityFixture(t)
	f.seedTwoArchivedVersions(t)
	ctx := context.Background()

	backupSvc := newTestItemBackupService(f.secretRepo, nil, nil, f.versionRepo)
	blob, err := backupSvc.BackupSecret(ctx, f.secretID, f.userID, f.vaultID)
	require.NoError(t, err)

	restoreSvc := newTestItemBackupService(f.secretRepo, nil, nil, f.versionRepo)
	restoreSvc.SetTxBeginner(f.dbConn)

	newID := uuid.New()
	require.NoError(t, restoreSvc.RestoreSecret(ctx, blob, f.userID, f.vaultID, newID))

	require.Equal(t, 1, f.countSecretsByID(t, newID), "a successful restore must still commit the secret row")
	require.Equal(t, 2, f.countVersionsBySecretID(t, newID), "a successful restore must still commit both archived versions")

	restored, err := f.secretRepo.Read(ctx, newID, f.scope())
	require.NoError(t, err)
	require.Equal(t, "atomic-secret", restored.Name)
	require.Equal(t, "enc-original", restored.Value)
}
