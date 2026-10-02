//go:build integration

// Package repositories_test integration suite runs the real repositories
// against a live PostgreSQL container to prove dual-engine support. Run with:
//
//	go test -tags=integration ./internal/repositories/...
//
// It requires Docker. The default `go test ./...` run skips this file.
package repositories_test

import (
	"context"
	"database/sql"
	"encoding/base64"
	"testing"
	"time"

	"github.com/google/uuid"
	_ "github.com/lib/pq"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	tcpostgres "github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"

	rvdb "rocketvault/internal/db"
	"rocketvault/internal/logging"
	"rocketvault/internal/repositories"
	"rocketvault/model"
)

// newPostgresConn boots a postgres:16 container, runs the full schema setup,
// and returns a dialect-aware connection plus a cleanup func.
func newPostgresConn(t *testing.T) (*rvdb.Conn, func()) {
	t.Helper()
	ctx := context.Background()

	container, err := tcpostgres.Run(ctx,
		"postgres:16-alpine",
		tcpostgres.WithDatabase("rocketvault"),
		tcpostgres.WithUsername("rv"),
		tcpostgres.WithPassword("rv-secret"),
		tcpostgres.BasicWaitStrategies(),
		tcpostgres.WithSQLDriver("postgres"),
		// Belt-and-suspenders: also wait for the readiness log line.
		testcontainers.WithAdditionalWaitStrategy(
			wait.ForLog("database system is ready to accept connections").
				WithOccurrence(2).
				WithStartupTimeout(60*time.Second),
		),
	)
	require.NoError(t, err, "start postgres container")

	dsn, err := container.ConnectionString(ctx, "sslmode=disable")
	require.NoError(t, err)

	sqlDB, err := sql.Open("postgres", dsn)
	require.NoError(t, err)

	// Wait for the server to accept connections.
	require.Eventually(t, func() bool {
		return sqlDB.PingContext(ctx) == nil
	}, 60*time.Second, 500*time.Millisecond, "postgres did not become ready")

	// Run schema, migrations, and seeds against Postgres.
	repo := rvdb.NewRepository(logging.InitLogger())
	require.NoError(t, repo.SetupSchema(sqlDB, rvdb.Postgres), "setup schema on postgres")

	conn := rvdb.NewConn(sqlDB, rvdb.Postgres)

	cleanup := func() {
		sqlDB.Close()
		_ = container.Terminate(ctx)
	}
	return conn, cleanup
}

// seedUser inserts a user row so foreign-key-ish references resolve.
func seedUser(t *testing.T, conn *rvdb.Conn, id uuid.UUID) {
	t.Helper()
	_, err := conn.ExecContext(context.Background(),
		"INSERT INTO users (id, username, password_hash, role) VALUES (?, ?, ?, ?)",
		id.String(), "user-"+id.String()[:8], "hash", "user",
	)
	require.NoError(t, err)
}

func TestPostgres_SecretRoundTrip_BinaryValue(t *testing.T) {
	conn, cleanup := newPostgresConn(t)
	defer cleanup()
	ctx := context.Background()
	log := logging.InitLogger()

	userID := uuid.New()
	seedUser(t, conn, userID)

	repo := repositories.NewSecretRepository(conn, log)

	// A base64-encoded "encrypted" blob — the real storage format. This proves
	// the TEXT column round-trips non-trivial ASCII on Postgres.
	rawCipher := []byte{0x00, 0x01, 0xff, 0xfe, 0x10, 0x42, 0x7f}
	encoded := base64.StdEncoding.EncodeToString(rawCipher)

	secret := &model.Secret{
		ID:      uuid.New(),
		UserID:  userID,
		VaultID: uuid.MustParse(model.DefaultVaultID),
		Name:    "db-password",
		Value:   encoded,
		Version: 1,
		Enabled: true,
	}
	require.NoError(t, repo.Create(ctx, secret))

	got, err := repo.Read(ctx, secret.ID, model.NewOwnerScope(secret.VaultID, userID))
	require.NoError(t, err)
	require.Equal(t, encoded, got.Value, "base64 value must round-trip exactly")

	decoded, err := base64.StdEncoding.DecodeString(got.Value)
	require.NoError(t, err)
	require.Equal(t, rawCipher, decoded, "decoded bytes must match original")
}

func TestPostgres_KeyWithTags_RoundTrip(t *testing.T) {
	conn, cleanup := newPostgresConn(t)
	defer cleanup()
	ctx := context.Background()
	log := logging.InitLogger()

	userID := uuid.New()
	seedUser(t, conn, userID)

	repo := repositories.NewKeyRepository(conn, log)

	key := &model.Key{
		ID:        uuid.New(),
		UserID:    userID,
		VaultID:   uuid.MustParse(model.DefaultVaultID),
		Name:      "signing-key",
		Type:      "RSA",
		Value:     base64.StdEncoding.EncodeToString([]byte("pem-bytes")),
		Enabled:   true,
		CreatedAt: time.Now().UTC(),
		Bits:      2048,
		Tags:      []string{"prod", "signing"},
	}
	require.NoError(t, repo.Create(ctx, key))

	// Read exercises GetTags, which previously passed a raw uuid.UUID instead of
	// id.String() and would silently return no tags on Postgres.
	got, err := repo.Read(ctx, key.ID, model.NewOwnerScope(key.VaultID, userID))
	require.NoError(t, err)
	require.ElementsMatch(t, []string{"prod", "signing"}, got.Tags,
		"tags must round-trip on Postgres (guards the GetTags id.String fix)")
}

func TestPostgres_SecretTags_UpsertIgnore(t *testing.T) {
	conn, cleanup := newPostgresConn(t)
	defer cleanup()
	ctx := context.Background()
	log := logging.InitLogger()

	userID := uuid.New()
	seedUser(t, conn, userID)

	// Create a real secret first: Postgres enforces the secret_tags -> secrets
	// foreign key (SQLite leaves FKs off by default), so the parent row must exist.
	secretRepo := repositories.NewSecretRepository(conn, log)
	secret := &model.Secret{
		ID:      uuid.New(),
		UserID:  userID,
		VaultID: uuid.MustParse(model.DefaultVaultID),
		Name:    "tagged-secret",
		Value:   base64.StdEncoding.EncodeToString([]byte("v")),
		Version: 1,
		Enabled: true,
	}
	require.NoError(t, secretRepo.Create(ctx, secret))

	tagRepo := repositories.NewSecretTagRepository(conn)

	// Adding the same tag twice must not error — UpsertIgnore becomes
	// ON CONFLICT DO NOTHING on Postgres.
	require.NoError(t, tagRepo.AddTags(ctx, secret.ID, []string{"alpha", "beta"}))
	require.NoError(t, tagRepo.AddTags(ctx, secret.ID, []string{"alpha", "gamma"}),
		"re-adding an existing tag must be ignored, not error")

	tags, err := tagRepo.GetTags(ctx, secret.ID)
	require.NoError(t, err)
	require.ElementsMatch(t, []string{"alpha", "beta", "gamma"}, tags)
}

// TestPostgres_UserRolesBackfill_PreExistingUser proves the user_roles
// backfill's dialect-aware INSERT (Dialect.UpsertIgnore + Dialect.Rebind)
// actually works against real PostgreSQL, not just SQLite's "?" placeholder
// grammar. It seeds a legacy `users` row BEFORE SetupSchema (and therefore
// migrateSchema) ever runs, so migrateSchema's own backfill loop -- not test
// setup -- is what has to populate user_roles on Postgres.
func TestPostgres_UserRolesBackfill_PreExistingUser(t *testing.T) {
	ctx := context.Background()

	container, err := tcpostgres.Run(ctx,
		"postgres:16-alpine",
		tcpostgres.WithDatabase("rocketvault"),
		tcpostgres.WithUsername("rv"),
		tcpostgres.WithPassword("rv-secret"),
		tcpostgres.BasicWaitStrategies(),
		tcpostgres.WithSQLDriver("postgres"),
		testcontainers.WithAdditionalWaitStrategy(
			wait.ForLog("database system is ready to accept connections").
				WithOccurrence(2).
				WithStartupTimeout(60*time.Second),
		),
	)
	require.NoError(t, err, "start postgres container")
	defer func() { _ = container.Terminate(ctx) }()

	dsn, err := container.ConnectionString(ctx, "sslmode=disable")
	require.NoError(t, err)

	sqlDB, err := sql.Open("postgres", dsn)
	require.NoError(t, err)
	defer sqlDB.Close()

	require.Eventually(t, func() bool {
		return sqlDB.PingContext(ctx) == nil
	}, 60*time.Second, 500*time.Millisecond, "postgres did not become ready")

	// Hand-create a minimal legacy `users` table and seed a user directly --
	// before SetupSchema/createOptimizedSchema/migrateSchema have run at all.
	// createOptimizedSchema's "CREATE TABLE IF NOT EXISTS users" is then a
	// no-op against this pre-existing table, so this row is exactly what an
	// upgrading real deployment looks like: present before user_roles exists.
	_, err = sqlDB.Exec(`CREATE TABLE users (
		id            TEXT PRIMARY KEY,
		username      TEXT UNIQUE NOT NULL,
		password_hash TEXT NOT NULL,
		role          TEXT NOT NULL,
		created_at    TIMESTAMP DEFAULT CURRENT_TIMESTAMP
	)`)
	require.NoError(t, err)

	legacyUserID := uuid.New()
	_, err = sqlDB.Exec(
		"INSERT INTO users (id, username, password_hash, role) VALUES ($1, $2, $3, $4)",
		legacyUserID.String(), "legacy-pg-admin", "hash", "admin",
	)
	require.NoError(t, err)

	// SetupSchema runs createOptimizedSchema then migrateSchema -- the latter
	// is what creates user_roles and backfills the pre-existing row above via
	// the dialect-aware INSERT this test exists to prove.
	repo := rvdb.NewRepository(logging.InitLogger())
	require.NoError(t, repo.SetupSchema(sqlDB, rvdb.Postgres), "setup schema on postgres")

	var role string
	err = sqlDB.QueryRow(
		"SELECT role FROM user_roles WHERE user_id = $1", legacyUserID.String(),
	).Scan(&role)
	require.NoError(t, err, "migrateSchema's backfill must have written a user_roles row on Postgres")
	require.Equal(t, "admin", role)

	// Running SetupSchema a second time must not error and must not
	// duplicate the row -- proves ON CONFLICT DO NOTHING (this dialect's
	// UpsertIgnore) actually fires, not a SQLite-only "INSERT OR IGNORE"
	// that would have made this a hard Postgres syntax error instead.
	require.NoError(t, repo.SetupSchema(sqlDB, rvdb.Postgres))
	var count int
	err = sqlDB.QueryRow(
		"SELECT COUNT(*) FROM user_roles WHERE user_id = $1", legacyUserID.String(),
	).Scan(&count)
	require.NoError(t, err)
	require.Equal(t, 1, count, "a second SetupSchema run must not duplicate the backfilled row")
}

func TestPostgres_DefaultVaultSeeded(t *testing.T) {
	conn, cleanup := newPostgresConn(t)
	defer cleanup()
	ctx := context.Background()

	// The bootstrap seed path runs on the raw *sql.DB before the wrapper; this
	// confirms the rebound seed queries executed on Postgres.
	var count int
	err := conn.QueryRowContext(ctx,
		"SELECT COUNT(*) FROM vaults WHERE id = ?", model.DefaultVaultID,
	).Scan(&count)
	require.NoError(t, err)
	require.Equal(t, 1, count, "default vault must be seeded on Postgres")
}

// The claim must work on Postgres through placeholder rebinding and the real
// users.totp_last_step column.
func TestPostgres_TOTPStepClaim(t *testing.T) {
	conn, cleanup := newPostgresConn(t)
	defer cleanup()
	ctx := context.Background()

	userID := uuid.New()
	seedUser(t, conn, userID)
	steps := repositories.NewTOTPStepRepository(conn)

	// A realistic step: the Unix time divided by the 30 second period.
	step := time.Now().Unix() / 30

	claimed, err := steps.ClaimTOTPStep(ctx, userID, step)
	require.NoError(t, err)
	require.True(t, claimed, "the first use of a step must be accepted")

	claimed, err = steps.ClaimTOTPStep(ctx, userID, step)
	require.NoError(t, err)
	require.False(t, claimed, "the same step must not be accepted twice")

	claimed, err = steps.ClaimTOTPStep(ctx, userID, step-1)
	require.NoError(t, err)
	require.False(t, claimed, "an older step must be rejected")

	claimed, err = steps.ClaimTOTPStep(ctx, userID, step+1)
	require.NoError(t, err)
	require.True(t, claimed, "a newer step must be accepted")

	claimed, err = steps.ClaimTOTPStep(ctx, uuid.New(), step+2)
	require.NoError(t, err)
	require.False(t, claimed, "a missing user can never claim a step")

	// A step beyond 32 bits must fit the BIGINT column.
	big := int64(1) << 40
	claimed, err = steps.ClaimTOTPStep(ctx, userID, big)
	require.NoError(t, err)
	require.True(t, claimed, "a step beyond 32 bits must be accepted")

	claimed, err = steps.ClaimTOTPStep(ctx, userID, big-1)
	require.NoError(t, err)
	require.False(t, claimed, "a step below a large stored step must be rejected")
}
