package secrets_test

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	_ "github.com/mattn/go-sqlite3"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	rvdb "rocketvault/internal/db"
	"rocketvault/internal/pwgen"
	"rocketvault/internal/repositories"
	"rocketvault/internal/services/secrets"
	"rocketvault/internal/testutils"
	"rocketvault/model"
)

// rotationFixtureSchema mirrors internal/db/db.go's createOptimizedSchema for
// only the tables rotation touches.
const rotationFixtureSchema = `
	CREATE TABLE users (
		id TEXT PRIMARY KEY,
		username TEXT UNIQUE NOT NULL,
		password_hash TEXT NOT NULL,
		totp_secret TEXT,
		role TEXT NOT NULL,
		auth_provider TEXT NOT NULL DEFAULT 'local',
		external_idp_subject TEXT,
		email TEXT,
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
	);
	CREATE TABLE user_roles (
		id         TEXT PRIMARY KEY,
		user_id    TEXT NOT NULL,
		role       TEXT NOT NULL,
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		UNIQUE (user_id, role),
		FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
	);
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
	CREATE TABLE rotation_policies (
		id TEXT PRIMARY KEY,
		user_id TEXT NOT NULL,
		vault_id TEXT NOT NULL,
		name TEXT NOT NULL,
		description TEXT,
		interval_days INTEGER NOT NULL,
		enabled BOOLEAN NOT NULL DEFAULT TRUE,
		reminder_days INTEGER NOT NULL DEFAULT 7,
		auto_rotate BOOLEAN NOT NULL DEFAULT FALSE,
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
	);
	CREATE TABLE secret_policies (
		secret_id TEXT NOT NULL,
		policy_id TEXT NOT NULL,
		assigned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		last_rotated_at TIMESTAMP,
		next_rotation_at TIMESTAMP,
		PRIMARY KEY (secret_id, policy_id)
	);
	CREATE TABLE secret_rotation_history (
		id TEXT PRIMARY KEY,
		secret_id TEXT NOT NULL,
		policy_id TEXT,
		rotated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		previous_version INTEGER,
		new_version INTEGER,
		triggered_by TEXT NOT NULL,
		notes TEXT
	);
	CREATE TABLE rotation_reminders (
		id TEXT PRIMARY KEY,
		secret_id TEXT NOT NULL,
		policy_id TEXT NOT NULL,
		reminder_type TEXT NOT NULL,
		sent_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		next_reminder_at TIMESTAMP,
		acknowledged BOOLEAN NOT NULL DEFAULT FALSE
	);
`

// rotationFixture wires the real repositories, the real cryptography service
// and a real database. Mocked crypto cannot prove a round trip, and a round
// trip is the whole point of these tests.
type rotationFixture struct {
	conn         *sql.DB
	crypto       secrets.CryptographyService
	rotationSvc  secrets.RotationServiceInterface
	secretSvc    secrets.SecretService
	schedulerSvc secrets.SchedulerServiceInterface
	versionRepo  repositories.SecretVersionRepositoryInterface
	userID       uuid.UUID
	vaultID      uuid.UUID
	secretID     uuid.UUID
	policyID     uuid.UUID
}

// scope returns the vault scope a CLI caller would use.
func (f *rotationFixture) scope() model.Scope {
	return model.NewVaultScope(f.vaultID, f.userID)
}

// newRotationFixture seeds one owner, one secret holding plaintext, and one
// auto-rotate policy already assigned to it with a next rotation in the past.
func newRotationFixture(t *testing.T, plaintext string) *rotationFixture {
	t.Helper()

	// The cryptography service reads master_key from the global viper
	// singleton, so these tests must not run in parallel.
	key := make([]byte, 32)
	_, err := rand.Read(key)
	require.NoError(t, err)
	previousKey := viper.GetString("master_key")
	viper.Set("master_key", base64.StdEncoding.EncodeToString(key))
	t.Cleanup(func() { viper.Set("master_key", previousKey) })

	conn, err := sql.Open("sqlite3", ":memory:")
	require.NoError(t, err)
	t.Cleanup(func() { conn.Close() }) //nolint:errcheck,gosec

	_, err = conn.Exec(rotationFixtureSchema)
	require.NoError(t, err)

	log := testutils.NewTestLogger(t)
	dbConn := rvdb.NewConn(conn, rvdb.SQLite)

	secretRepo := repositories.NewSecretRepository(dbConn, log)
	rotationRepo := repositories.NewRotationPolicyRepository(dbConn, log)
	versionRepo := repositories.NewSecretVersionRepository(dbConn, log)
	userRepo := repositories.NewUserRepository(dbConn, log)
	tagRepo := repositories.NewSecretTagRepository(dbConn)

	crypto := secrets.NewCryptographyService()
	versioningSvc := secrets.NewVersioningService(versionRepo, secretRepo, userRepo, crypto, log, nil)
	rotationSvc := secrets.NewRotationService(rotationRepo, secretRepo, userRepo, crypto, versioningSvc, log, nil)
	secretSvc := secrets.NewSecretService(secrets.SecretServiceConfig{
		SecretRepository: secretRepo,
		CryptoService:    crypto,
		VersionService:   versioningSvc,
		TagService:       secrets.NewTagService(tagRepo, log),
		Logger:           log,
	})
	schedulerSvc := secrets.NewSchedulerService(rotationSvc, versioningSvc, userRepo, secretRepo, rotationRepo, log)

	f := &rotationFixture{
		conn:         conn,
		crypto:       crypto,
		rotationSvc:  rotationSvc,
		secretSvc:    secretSvc,
		schedulerSvc: schedulerSvc,
		versionRepo:  versionRepo,
		userID:       uuid.New(),
		vaultID:      uuid.New(),
		secretID:     uuid.New(),
		policyID:     uuid.New(),
	}

	now := time.Now()
	_, err = conn.Exec(
		`INSERT INTO users (id, username, password_hash, totp_secret, role, auth_provider, created_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?)`,
		f.userID.String(), "alice", "hash", "", model.RoleUser, "local", now,
	)
	require.NoError(t, err)

	ciphertext, err := crypto.EncryptSecret(plaintext)
	require.NoError(t, err)
	_, err = conn.Exec(
		`INSERT INTO secrets (id, user_id, name, vault_id, value, version, created_at, content_type, enabled)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		f.secretID.String(), f.userID.String(), "db-password", f.vaultID.String(),
		ciphertext, 1, now, "", true,
	)
	require.NoError(t, err)

	ctx := context.Background()
	require.NoError(t, rotationRepo.Create(ctx, &model.RotationPolicy{
		ID:           f.policyID,
		UserID:       f.userID,
		VaultID:      f.vaultID,
		Name:         "monthly",
		IntervalDays: 30,
		Enabled:      true,
		ReminderDays: 0,
		AutoRotate:   true,
		CreatedAt:    now,
		UpdatedAt:    now,
	}))
	// The next rotation is backdated so the scheduler sees this pair as due.
	require.NoError(t, rotationRepo.AssignToSecret(ctx, f.secretID, f.policyID,
		now.AddDate(0, 0, -60), now.AddDate(0, 0, -30)))

	return f
}

// TestPerformManualRotation_ExplicitValue_RoundTripsThroughGetSecret is the
// test whose absence let B35 ship: nothing ever rotated a secret and then read
// it back.
func TestPerformManualRotation_ExplicitValue_RoundTripsThroughGetSecret(t *testing.T) {
	ctx := context.Background()
	f := newRotationFixture(t, "original-password")

	require.NoError(t, f.rotationSvc.PerformManualRotation(ctx, secrets.ManualRotationRequest{
		SecretID: f.secretID,
		PolicyID: f.policyID,
		Scope:    f.scope(),
		Notes:    "manual rotation",
		NewValue: "replacement-password",
	}))

	got, err := f.secretSvc.GetSecret(ctx, f.secretID, f.scope())
	require.NoError(t, err, "a rotated secret must still decrypt")
	assert.Equal(t, "replacement-password", got.Value)
	assert.Equal(t, 2, got.Version)

	history, err := f.rotationSvc.GetRotationHistory(ctx, f.secretID, f.scope())
	require.NoError(t, err)
	require.Len(t, history, 1, "rotation must record exactly one history row")
	assert.Equal(t, 1, history[0].PreviousVersion)
	assert.Equal(t, 2, history[0].NewVersion)
}

// TestPerformManualRotation_ArchivesThePreviousValue pins the second half of
// B35: the manual path used to overwrite the old value with no version row, so
// the pre-rotation value was gone for good.
func TestPerformManualRotation_ArchivesThePreviousValue(t *testing.T) {
	ctx := context.Background()
	f := newRotationFixture(t, "original-password")

	require.NoError(t, f.rotationSvc.PerformManualRotation(ctx, secrets.ManualRotationRequest{
		SecretID: f.secretID,
		PolicyID: f.policyID,
		Scope:    f.scope(),
		NewValue: "replacement-password",
	}))

	versions, err := f.versionRepo.GetVersions(ctx, f.secretID)
	require.NoError(t, err)
	require.Len(t, versions, 1, "manual rotation must archive exactly one version row")
	assert.Equal(t, 1, versions[0].Version)

	archived, err := f.crypto.DecryptSecret(versions[0].Value)
	require.NoError(t, err, "the archived version must be singly encrypted, not encrypted ciphertext")
	assert.Equal(t, "original-password", archived)
}

// TestPerformManualRotation_GeneratedValue_RoundTrips covers the opt-in
// generation path.
func TestPerformManualRotation_GeneratedValue_RoundTrips(t *testing.T) {
	ctx := context.Background()
	f := newRotationFixture(t, "original-password")

	require.NoError(t, f.rotationSvc.PerformManualRotation(ctx, secrets.ManualRotationRequest{
		SecretID: f.secretID,
		PolicyID: f.policyID,
		Scope:    f.scope(),
		Generate: true,
		GenerateOpts: pwgen.Options{
			Length: 24, Upper: true, Lower: true, Numbers: true, Special: true,
		},
	}))

	got, err := f.secretSvc.GetSecret(ctx, f.secretID, f.scope())
	require.NoError(t, err)
	assert.Len(t, got.Value, 24, "the generated value must honour GenerateOpts.Length")
	assert.NotEqual(t, "original-password", got.Value)
	assert.NotContains(t, got.Value, "_rotated_", "the placeholder generator must be gone")
}

// TestPerformManualRotation_RequiresAValueSource pins the "never invent a
// value" rule.
func TestPerformManualRotation_RequiresAValueSource(t *testing.T) {
	ctx := context.Background()
	f := newRotationFixture(t, "original-password")

	err := f.rotationSvc.PerformManualRotation(ctx, secrets.ManualRotationRequest{
		SecretID: f.secretID,
		PolicyID: f.policyID,
		Scope:    f.scope(),
	})
	require.Error(t, err)
	assert.True(t, errors.Is(err, secrets.ErrRotationValueRequired), "got %v", err)

	got, getErr := f.secretSvc.GetSecret(ctx, f.secretID, f.scope())
	require.NoError(t, getErr, "a rejected rotation must leave the secret untouched")
	assert.Equal(t, "original-password", got.Value)
	assert.Equal(t, 1, got.Version)
}

// TestPerformManualRotation_RejectsBothValueAndGenerate pins the ambiguous
// case: two value sources is a caller error, not a precedence rule.
func TestPerformManualRotation_RejectsBothValueAndGenerate(t *testing.T) {
	ctx := context.Background()
	f := newRotationFixture(t, "original-password")

	err := f.rotationSvc.PerformManualRotation(ctx, secrets.ManualRotationRequest{
		SecretID: f.secretID,
		PolicyID: f.policyID,
		Scope:    f.scope(),
		NewValue: "replacement-password",
		Generate: true,
	})
	require.Error(t, err)
	assert.True(t, errors.Is(err, secrets.ErrRotationValueConflict), "got %v", err)

	got, getErr := f.secretSvc.GetSecret(ctx, f.secretID, f.scope())
	require.NoError(t, getErr)
	assert.Equal(t, "original-password", got.Value)
}

// TestScheduler_AutomaticRotation_RoundTripsAndVersionsOnce covers the path
// that made B35 Critical: a policy with AutoRotate corrupts its secret on a
// timer, unattended. It also pins the single version row -- the scheduler used
// to write its own, on top of the one rotation now writes.
func TestScheduler_AutomaticRotation_RoundTripsAndVersionsOnce(t *testing.T) {
	ctx := context.Background()
	f := newRotationFixture(t, "original-password")

	require.NoError(t, f.schedulerSvc.ProcessUserRotations(ctx, f.userID))

	got, err := f.secretSvc.GetSecret(ctx, f.secretID, f.scope())
	require.NoError(t, err, "an automatically rotated secret must still decrypt")
	assert.NotEqual(t, "original-password", got.Value)
	assert.NotContains(t, got.Value, "_rotated_")
	assert.Equal(t, 2, got.Version)

	versions, err := f.versionRepo.GetVersions(ctx, f.secretID)
	require.NoError(t, err)
	require.Len(t, versions, 1, "automatic rotation must write exactly one version row")

	archived, err := f.crypto.DecryptSecret(versions[0].Value)
	require.NoError(t, err, "the archived version must be singly encrypted")
	assert.Equal(t, "original-password", archived)
}
