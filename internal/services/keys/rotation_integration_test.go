package keys

// TestRotationExecutor_Check_EndToEnd_RealRepositories is the I5 fix from the
// final review: every layer of the rotation-policy scheduler
// (schedulerkit, the due-policy repository query, the executor) is tested in
// isolation against mocks or an in-memory DB, but nothing before this test
// proved config -> scheduler -> executor -> real repository -> real
// RotateKey actually rotates a key end-to-end when a policy is due. This
// test wires a real KeyService and a real KeyRotationPolicyRepository, both
// backed by an in-memory SQLite DB (not mocks), and calls executor.Check
// directly -- it deliberately does not exercise schedulerkit's ticker
// (Start/Stop), which is already covered by internal/schedulerkit's own
// tests.
//
// This also incidentally exercises the I1 (never-recompute-past-due-dates)
// and I2 (deleted/OCT keys excluded from the sweep) fixes on the normal,
// happy-path case: a real due policy on a real, live RSA key must still be
// picked up and rotated.

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/google/uuid"
	_ "github.com/mattn/go-sqlite3"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"

	"rocketvault/common"
	rvcrypto "rocketvault/internal/crypto"
	rvdb "rocketvault/internal/db"
	"rocketvault/internal/logging"
	"rocketvault/internal/repositories"
	"rocketvault/model"
)

// setupRotationIntegrationDB creates an in-memory SQLite database with the
// keys/key_tags/key_versions/key_rotation_policies tables needed to wire a
// real KeyRepository and a real KeyRotationPolicyRepository -- the same
// shape as internal/db's createOptimizedSchema for these tables (including
// the due-tracking columns from Task 2 of the rotation-policy scheduler plan).
func setupRotationIntegrationDB(t *testing.T) *sql.DB {
	t.Helper()

	sqlDB, err := sql.Open("sqlite3", ":memory:")
	require.NoError(t, err)
	t.Cleanup(func() { sqlDB.Close() }) //nolint:errcheck,gosec

	_, err = sqlDB.Exec(`
		CREATE TABLE IF NOT EXISTS keys (
			id TEXT PRIMARY KEY,
			user_id TEXT NOT NULL,
			vault_id TEXT NOT NULL DEFAULT '00000000-0000-0000-0000-00000000efa1',
			name TEXT NOT NULL,
			value TEXT NOT NULL,
			type TEXT NOT NULL,
			revoked BOOLEAN NOT NULL DEFAULT FALSE,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			deleted_at TIMESTAMP DEFAULT NULL,
			purge_protection BOOLEAN NOT NULL DEFAULT FALSE,
			scheduled_purge_at TIMESTAMP DEFAULT NULL,
			enabled BOOLEAN NOT NULL DEFAULT TRUE,
			expires_at TIMESTAMP NULL,
			not_before TIMESTAMP NULL,
			bits INTEGER NOT NULL DEFAULT 0,
			curve TEXT NOT NULL DEFAULT '',
			updated_at TIMESTAMP NULL,
			exportable BOOLEAN NOT NULL DEFAULT FALSE
		);
		CREATE TABLE IF NOT EXISTS key_tags (
			key_id TEXT NOT NULL,
			tag TEXT NOT NULL,
			PRIMARY KEY (key_id, tag)
		);
		CREATE TABLE IF NOT EXISTS key_versions (
			key_id     TEXT NOT NULL,
			version    INTEGER NOT NULL,
			value      TEXT NOT NULL,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			PRIMARY KEY (key_id, version)
		);
		CREATE TABLE IF NOT EXISTS key_rotation_policies (
			id                         TEXT PRIMARY KEY,
			key_id                     TEXT NOT NULL UNIQUE,
			user_id                    TEXT NOT NULL,
			vault_id                   TEXT NOT NULL DEFAULT '00000000-0000-0000-0000-00000000efa1',
			rotate_after_days          INTEGER NOT NULL DEFAULT 90,
			notify_before_expiry_days  INTEGER NOT NULL DEFAULT 30,
			expiry_days                INTEGER NOT NULL DEFAULT 365,
			enabled                    BOOLEAN NOT NULL DEFAULT TRUE,
			last_rotated_at            TIMESTAMP NULL,
			next_rotation_at           TIMESTAMP NULL,
			created_at                 TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			updated_at                 TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		);
	`)
	require.NoError(t, err)

	return sqlDB
}

func TestRotationExecutor_Check_EndToEnd_RealRepositories(t *testing.T) {
	setupCryptoVaultScopeTestMasterKey() // Deterministic master key so common.EncryptSecret/DecryptSecret work.

	sqlDB := setupRotationIntegrationDB(t)
	logger := &logging.Logger{Logger: logrus.New()}

	keyRepo := repositories.NewKeyRepository(rvdb.NewConn(sqlDB, rvdb.SQLite), logger)
	policyRepo := repositories.NewKeyRotationPolicyRepository(rvdb.NewConn(sqlDB, rvdb.SQLite), logger)

	ctx := context.Background()
	keyID, userID, vaultID := uuid.New(), uuid.New(), uuid.New()
	adminScope := model.NewAdminScope(uuid.Nil)

	// Create a real, live RSA key.
	privateKeyPEM, err := rvcrypto.GenerateRSAKeyPEM(2048)
	require.NoError(t, err)
	encryptedPEM, err := common.EncryptSecret(privateKeyPEM)
	require.NoError(t, err)
	createdAt := time.Now().UTC().Add(-100 * 24 * time.Hour) // Old enough that any created_at-anchored recompute would also be overdue.
	require.NoError(t, keyRepo.Create(ctx, &model.Key{
		ID: keyID, UserID: userID, VaultID: vaultID, Name: "integration-key",
		Type: model.KeyTypeRSA, Value: encryptedPEM, Enabled: true, Bits: 2048, CreatedAt: createdAt,
	}))

	before, err := keyRepo.Read(ctx, keyID, adminScope)
	require.NoError(t, err)

	// A real, due, enabled rotation policy -- next_rotation_at in the past, UTC
	// (matching GetDuePolicies' UTC-normalized comparison, see M2).
	policy := &model.KeyRotationPolicy{
		ID: uuid.New(), KeyID: keyID, UserID: userID, VaultID: vaultID,
		RotateAfterDays: 90, NotifyBeforeExpiryDays: 30, ExpiryDays: 365, Enabled: true,
		NextRotationAt: time.Now().UTC().Add(-time.Hour),
		CreatedAt:      time.Now().UTC(), UpdatedAt: time.Now().UTC(),
	}
	require.NoError(t, policyRepo.Upsert(ctx, policy))

	keySvc := NewKeyService(KeyServiceConfig{
		KeyRepository:    keyRepo,
		KeyProvider:      rvcrypto.NewSoftwareKeyProvider(),
		PolicyRepository: policyRepo,
		Logger:           logger,
	})
	executor := NewRotationExecutor(keySvc, policyRepo, logger)

	require.NoError(t, executor.Check(ctx))

	// The key's material must have changed.
	after, err := keyRepo.Read(ctx, keyID, adminScope)
	require.NoError(t, err)
	require.NotEqual(t, before.Value, after.Value, "RotateKey must have replaced the key's stored material")

	versions, err := keyRepo.ListVersions(ctx, keyID)
	require.NoError(t, err)
	require.Len(t, versions, 2, "the original material and the newly rotated material must both be archived")

	// The policy's due-date must have advanced into the future.
	updatedPolicy, err := policyRepo.GetByKeyID(ctx, keyID, model.NewVaultScope(vaultID, uuid.New()))
	require.NoError(t, err)
	require.NotNil(t, updatedPolicy.LastRotatedAt, "MarkRotated must have stamped last_rotated_at")
	require.True(t, updatedPolicy.NextRotationAt.After(time.Now().UTC()), "next_rotation_at must have advanced into the future")

	// The now-not-due policy must no longer appear in a second sweep.
	due, err := policyRepo.GetDuePolicies(ctx, adminScope)
	require.NoError(t, err)
	require.Empty(t, due, "a freshly rotated policy must not still be due")
}
