package migrations

import (
	"context"
	"database/sql"
	"io"
	"testing"

	_ "github.com/mattn/go-sqlite3"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"rocketvault/internal/db"
	"rocketvault/internal/logging"
)

func TestParseVersionNumber_NumericNotLexicographic(t *testing.T) {
	t.Parallel()
	nine, err := parseVersionNumber("9")
	require.NoError(t, err)
	ten, err := parseVersionNumber("10")
	require.NoError(t, err)

	assert.Equal(t, int64(9), nine)
	assert.Equal(t, int64(10), ten)
	assert.Greater(t, ten, nine, "10 must sort after 9 numerically")
	assert.Less(t, "10", "9", "sanity check: lexicographic string comparison gets this backwards, which is exactly why MigrateToVersion must not compare version strings directly")
}

func TestParseVersionNumber_LeadingZeros(t *testing.T) {
	t.Parallel()
	n, err := parseVersionNumber("001")
	require.NoError(t, err)
	assert.Equal(t, int64(1), n)
}

func TestParseVersionNumber_Timestamp(t *testing.T) {
	t.Parallel()
	n, err := parseVersionNumber("20260606000001")
	require.NoError(t, err)
	assert.Equal(t, int64(20260606000001), n)
}

func TestParseVersionNumber_NonNumeric(t *testing.T) {
	t.Parallel()
	_, err := parseVersionNumber("not-a-version")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not-a-version")
}

// silentLogger returns a logrus.Logger that discards output, keeping test
// runs quiet.
func silentLogger() *logrus.Logger {
	l := logrus.New()
	l.SetOutput(io.Discard)
	return l
}

// newTestRunner opens an in-memory SQLite database, initializes the
// schema_migrations table, and returns a MigrationRunner against it along
// with the raw connection for seeding.
func newTestRunner(t *testing.T) (*MigrationRunner, *sql.DB) {
	t.Helper()
	conn, err := sql.Open("sqlite3", ":memory:")
	require.NoError(t, err)
	t.Cleanup(func() { conn.Close() }) //nolint:errcheck,gosec

	runner := NewMigrationRunner(conn, silentLogger())
	require.NoError(t, runner.Initialize(context.Background()))
	return runner, conn
}

// seedApplied marks the given versions as already applied, without running
// their migration SQL. MigrateToVersion's downward refusal is decided from
// the recorded version alone, before any migration SQL runs, so this is
// enough to establish a "current version" for these tests without depending
// on the real migration files' SQL succeeding against a bare in-memory
// database.
func seedApplied(t *testing.T, conn *sql.DB, versions ...string) {
	t.Helper()
	for _, v := range versions {
		_, err := conn.ExecContext(context.Background(), "INSERT INTO schema_migrations (version) VALUES (?)", v)
		require.NoError(t, err)
	}
}

// allRealVersions returns every version string in the real, embedded
// migration set (internal/db/migrations/*.sql), in file order.
func allRealVersions(t *testing.T, runner *MigrationRunner) []string {
	t.Helper()
	all, err := runner.LoadMigrations()
	require.NoError(t, err)
	require.NotEmpty(t, all, "the embedded migration set must not be empty for these tests to be meaningful")
	versions := make([]string, len(all))
	for i, m := range all {
		versions[i] = m.Version
	}
	return versions
}

// TestMigrateUp_NormallyBootstrappedDatabase is the headline B47 regression
// test: reproduces the exact repro from .claude/known-bugs.md § B47 by
// seeding an in-memory database through the same SetupSchema path a normal
// `serve` boot uses (which never populates schema_migrations), then running
// MigrateUp against it. Before the fix this failed on the first ALTER TABLE
// ... ADD COLUMN that collided with a column createOptimizedSchema's CREATE
// TABLE already declares (e.g. secrets.deleted_at).
func TestMigrateUp_NormallyBootstrappedDatabase(t *testing.T) {
	t.Parallel()
	conn, err := sql.Open("sqlite3", ":memory:")
	require.NoError(t, err)
	t.Cleanup(func() { conn.Close() }) //nolint:errcheck,gosec

	repo := db.NewRepository(logging.WrapLogrus(silentLogger()))
	require.NoError(t, repo.SetupSchema(conn, db.SQLite))

	runner := NewMigrationRunner(conn, silentLogger())
	err = runner.MigrateUp(context.Background())
	require.NoError(t, err, "migrate must succeed against a normally-bootstrapped database")

	applied, err := runner.GetAppliedMigrations(context.Background())
	require.NoError(t, err)
	for _, version := range allRealVersions(t, runner) {
		assert.True(t, applied[version], "migration %s must be recorded as applied", version)
	}
}

// TestMigrateToVersion_RefusesDownwardTarget is the headline B39 test: with
// the schema at a known version, targeting a lower one must fail and leave
// the applied set unchanged.
func TestMigrateToVersion_RefusesDownwardTarget(t *testing.T) {
	t.Parallel()
	runner, conn := newTestRunner(t)
	ctx := context.Background()

	// Seed the first 8 real versions as applied; the loop's break condition
	// (same digit width throughout this prefix) stops before reaching any
	// unapplied migration, so no real migration SQL runs even before the fix.
	seedApplied(t, conn,
		"001",
		"20241025000001",
		"20241026000001",
		"20241026000002",
		"20241026000003",
		"20241026000004",
		"20241026000005",
		"20260308000001",
	)

	before, err := runner.GetAppliedMigrations(ctx)
	require.NoError(t, err)

	err = runner.MigrateToVersion(ctx, "20241026000002")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "cannot migrate down")
	assert.Contains(t, err.Error(), "current schema is at version 20260308000001")
	assert.Contains(t, err.Error(), "target 20241026000002 is lower")
	assert.Contains(t, err.Error(), "Down-migrations are not supported.")

	after, err := runner.GetAppliedMigrations(ctx)
	require.NoError(t, err)
	assert.Equal(t, before, after, "a refused downward migration must leave the applied set unchanged")
}

// TestMigrateToVersion_RefusesDownwardTargetEvenWithNoExactFileMatch proves
// the refusal is a pure magnitude comparison against the current version,
// not conditioned on the target naming a real migration file -- otherwise an
// operator could dodge it by guessing an arbitrary small number.
func TestMigrateToVersion_RefusesDownwardTargetEvenWithNoExactFileMatch(t *testing.T) {
	t.Parallel()
	runner, conn := newTestRunner(t)
	ctx := context.Background()

	seedApplied(t, conn, allRealVersions(t, runner)...)

	before, err := runner.GetAppliedMigrations(ctx)
	require.NoError(t, err)

	err = runner.MigrateToVersion(ctx, "5")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "cannot migrate down")

	after, err := runner.GetAppliedMigrations(ctx)
	require.NoError(t, err)
	assert.Equal(t, before, after)
}

// TestMigrateToVersion_TargetEqualToCurrentSucceedsAsNoOp confirms equality
// is not treated as "downward" -- it must succeed and change nothing.
func TestMigrateToVersion_TargetEqualToCurrentSucceedsAsNoOp(t *testing.T) {
	t.Parallel()
	runner, conn := newTestRunner(t)
	ctx := context.Background()

	seedApplied(t, conn,
		"001",
		"20241025000001",
		"20241026000001",
		"20241026000002",
		"20241026000003",
		"20241026000004",
		"20241026000005",
		"20260308000001",
	)

	before, err := runner.GetAppliedMigrations(ctx)
	require.NoError(t, err)

	err = runner.MigrateToVersion(ctx, "20260308000001")
	require.NoError(t, err, "targeting the current version must succeed, not error")

	after, err := runner.GetAppliedMigrations(ctx)
	require.NoError(t, err)
	assert.Equal(t, before, after, "targeting the current version must not change the applied set")
}

// TestMigrateToVersion_TargetAboveCurrentWithNoExactMatchSucceeds confirms
// B39 does not add a "target must name a real migration" requirement --
// that is pre-existing, unrelated permissive behavior and stays as-is.
func TestMigrateToVersion_TargetAboveCurrentWithNoExactMatchSucceeds(t *testing.T) {
	t.Parallel()
	runner, conn := newTestRunner(t)
	ctx := context.Background()

	seedApplied(t, conn, allRealVersions(t, runner)...)

	before, err := runner.GetAppliedMigrations(ctx)
	require.NoError(t, err)

	err = runner.MigrateToVersion(ctx, "99999999999999")
	require.NoError(t, err, "a target above current that matches no file is permitted, as before this fix")

	after, err := runner.GetAppliedMigrations(ctx)
	require.NoError(t, err)
	assert.Equal(t, before, after, "every migration was already applied, so nothing should change")
}

// TestMigrateToVersion_RejectsNonNumericTarget confirms a target that
// cannot be compared to the current version is rejected rather than falling
// back to a string comparison.
func TestMigrateToVersion_RejectsNonNumericTarget(t *testing.T) {
	t.Parallel()
	runner, conn := newTestRunner(t)
	ctx := context.Background()

	seedApplied(t, conn, allRealVersions(t, runner)...)

	before, err := runner.GetAppliedMigrations(ctx)
	require.NoError(t, err)

	err = runner.MigrateToVersion(ctx, "not-a-version")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not-a-version")

	after, err := runner.GetAppliedMigrations(ctx)
	require.NoError(t, err)
	assert.Equal(t, before, after)
}

// TestMigrateToVersion_RejectsCorruptCurrentVersion is a defensive test: a
// non-numeric row in schema_migrations (only reachable through direct DB
// tampering) must fail closed, not panic or silently misorder.
func TestMigrateToVersion_RejectsCorruptCurrentVersion(t *testing.T) {
	t.Parallel()
	runner, conn := newTestRunner(t)
	ctx := context.Background()

	seedApplied(t, conn, allRealVersions(t, runner)...)
	seedApplied(t, conn, "corrupted-version")

	err := runner.MigrateToVersion(ctx, "20260308000001")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "cannot determine current schema version")
}

// TestGetCurrentVersion_EmptyTableReturnsZero locks in the pre-existing
// empty-table behavior: "0" with no error, unchanged by the numeric-magnitude
// fix below.
func TestGetCurrentVersion_EmptyTableReturnsZero(t *testing.T) {
	t.Parallel()
	runner, _ := newTestRunner(t)
	ctx := context.Background()

	version, err := runner.GetCurrentVersion(ctx)
	require.NoError(t, err)
	assert.Equal(t, "0", version)
}

// TestGetCurrentVersion_RealMigrationSetUnchanged locks in that, for the
// actual embedded migration files (all either the legacy "001" or a 14-digit
// timestamp), the numeric-magnitude fix returns the byte-for-byte same value
// the old lexicographic SQL MAX() did: the last file in version order.
func TestGetCurrentVersion_RealMigrationSetUnchanged(t *testing.T) {
	t.Parallel()
	runner, conn := newTestRunner(t)
	ctx := context.Background()

	versions := allRealVersions(t, runner)
	seedApplied(t, conn, versions...)

	got, err := runner.GetCurrentVersion(ctx)
	require.NoError(t, err)
	assert.Equal(t, versions[len(versions)-1], got,
		"the real migration set is uniform-width within each prefix (\"001\" then all 14-digit "+
			"timestamps), so the numerically highest version is also the lexicographically highest "+
			"one the old MAX() query would have picked")
}

// TestGetCurrentVersion_NumericNotLexicographic is the headline fix test:
// GetCurrentVersion must pick the numerically highest applied version, not
// the lexicographically highest one. A short, high-leading-digit version
// ("9") sorts after any 14-digit timestamp version lexicographically (SQL
// MAX() on the VARCHAR column) but is numerically far smaller.
func TestGetCurrentVersion_NumericNotLexicographic(t *testing.T) {
	t.Parallel()
	runner, conn := newTestRunner(t)
	ctx := context.Background()

	seedApplied(t, conn, "9", "20260308000001")

	got, err := runner.GetCurrentVersion(ctx)
	require.NoError(t, err)
	assert.Equal(t, "20260308000001", got,
		"lexicographic MAX() would incorrectly return \"9\" here, since \"9\" > \"20260308000001\" byte-wise")
}

// TestMigrateToVersion_ReviewerDemonstratedBypassIsFixed reproduces the
// live bypass a senior reviewer demonstrated against the pre-fix
// GetCurrentVersion: seeding a short, high-leading-digit version ("9")
// alongside the real, numerically-higher current version made
// MigrateToVersion's refusal check compare against the wrong "current"
// value, so a migrate:to targeting a real lower version silently succeeded
// instead of refusing -- B39's exact original symptom. With
// GetCurrentVersion fixed to compare numerically, the same seeded state must
// now correctly refuse.
func TestMigrateToVersion_ReviewerDemonstratedBypassIsFixed(t *testing.T) {
	t.Parallel()
	runner, conn := newTestRunner(t)
	ctx := context.Background()

	// "9" is lexicographically greater than every real 14-digit version, so
	// the old SQL MAX()-based GetCurrentVersion would have reported "9" as
	// current here instead of the true, numerically higher current version.
	seedApplied(t, conn,
		"001",
		"20241025000001",
		"20241026000001",
		"20241026000002",
		"20260308000001",
		"9",
	)

	before, err := runner.GetAppliedMigrations(ctx)
	require.NoError(t, err)

	// A real, lower target: below the true numeric current (20260308000001)
	// but above the lexicographically-wrong "current" ("9") the old code
	// would have reported. Under the pre-fix defect this target is treated
	// as "upward" relative to "9" and the migration silently no-ops instead
	// of refusing.
	err = runner.MigrateToVersion(ctx, "20241026000002")
	require.Error(t, err, "must refuse: the true current version (20260308000001) is numerically above the target")
	assert.Contains(t, err.Error(), "cannot migrate down")
	assert.Contains(t, err.Error(), "current schema is at version 20260308000001",
		"the refusal must cite the true numeric current version, not the lexicographically-wrong \"9\"")
	assert.Contains(t, err.Error(), "target 20241026000002 is lower")

	after, err := runner.GetAppliedMigrations(ctx)
	require.NoError(t, err)
	assert.Equal(t, before, after, "a refused downward migration must leave the applied set unchanged")
}
