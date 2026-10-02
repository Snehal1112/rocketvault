// Package db_test contains unit tests for the db package.
// It verifies database initialization, table creation, and connection management.
package db

import (
	"database/sql"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/lib/pq"
	_ "github.com/mattn/go-sqlite3"
	"github.com/sirupsen/logrus"
	"github.com/sirupsen/logrus/hooks/test"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"rocketvault/internal/logging"
)

// newLogCapturingDBRepository returns a DBRepository whose logger is backed
// by a logrus test hook, so tests can assert on warn-level output without a
// real log sink. Kept minimal rather than restructuring logging.Logger --
// the DBRepository just needs a *logging.Logger, which wraps any
// *logrus.Logger.
func newLogCapturingDBRepository(t *testing.T, conn *sql.DB) (*test.Hook, *DBRepository) {
	t.Helper()
	base, hook := test.NewNullLogger()
	base.SetLevel(logrus.DebugLevel)
	repo := NewRepository(logging.WrapLogrus(base))
	return hook, repo
}

// newTestDBRepository creates the minimal old-shape prerequisite tables that
// migrateSchema's ALTER TABLE statements need a target for (the same set the
// neighbouring migration tests in this package -- e.g.
// TestMigrate_CreatesRoleAssignmentsTable in migrate_assignment_test.go --
// already create by hand), then returns a *DBRepository ready to run
// migrateSchema against conn.
func newTestDBRepository(t *testing.T, conn *sql.DB) *DBRepository {
	t.Helper()
	_, err := conn.Exec(`
		CREATE TABLE users (
			id       TEXT PRIMARY KEY,
			username TEXT NOT NULL,
			role     TEXT NOT NULL
		);
		CREATE TABLE secrets (
			id   TEXT PRIMARY KEY,
			name TEXT NOT NULL
		);
		CREATE TABLE keys (
			id   TEXT PRIMARY KEY,
			name TEXT NOT NULL
		);
		CREATE TABLE certificates (
			id   TEXT PRIMARY KEY,
			name TEXT NOT NULL
		);
		CREATE TABLE audit_logs (
			id TEXT PRIMARY KEY
		);
		CREATE TABLE access_policies (
			id             TEXT PRIMARY KEY,
			principal_id   TEXT NOT NULL,
			principal_type TEXT NOT NULL,
			resource_type  TEXT NOT NULL,
			operation      TEXT NOT NULL,
			effect         TEXT NOT NULL,
			created_at     TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		);
	`)
	require.NoError(t, err)
	return NewRepository(logging.InitLogger())
}

// TestInitializeDB tests the InitializeDB function to ensure it opens a SQLite connection and creates tables.
func TestInitializeDB(t *testing.T) {
	// Set up test configuration.
	viper.Set("database.connection", "./test.db")
	defer os.Remove("./test.db") //nolint:errcheck // Clean up test database.
	log := logging.InitLogger()

	// Test happy path.
	db := NewRepository(log)
	err := db.InitializeDB()
	assert.NoError(t, err, "database initialization should succeed")
	assert.NotNil(t, db.GetDB(), "database connection should be initialized")

	// Verify table creation.
	rows, err := db.GetDB().Query("SELECT name FROM sqlite_master WHERE type='table' AND name='users'")
	assert.NoError(t, err, "query for users table should succeed")
	assert.True(t, rows.Next(), "users table should exist")
	rows.Close() //nolint:errcheck,gosec
}

// TestInitializeDBInvalidConfig tests InitializeDB with an invalid connection string.
func TestInitializeDBInvalidConfig(t *testing.T) {
	viper.Set("database.connection", "")
	log := logging.InitLogger()
	db := NewRepository(log)
	err := db.InitializeDB()
	assert.Error(t, err, "database initialization should fail with empty connection string")
	assert.Contains(t, err.Error(), "database connection string not configured")
}

// TestCloseDB tests the CloseDB function to ensure it closes the connection gracefully.
func TestCloseDB(t *testing.T) {
	viper.Set("database.connection", "./test.db")
	defer os.Remove("./test.db") //nolint:errcheck

	// Initialize database.
	log := logging.InitLogger()
	db := NewRepository(log)
	err := db.InitializeDB()
	assert.NoError(t, err, "database initialization should succeed")

	// Test closing.
	err = db.CloseDB()
	assert.NoError(t, err, "closing database should succeed")
}

// BenchmarkInitializeDB measures the performance of database initialization.
func BenchmarkInitializeDB(b *testing.B) {
	viper.Set("database.connection", "./test.db")
	defer os.Remove("./test.db") //nolint:errcheck
	log := logging.InitLogger()

	for i := 0; i < b.N; i++ {
		db := NewRepository(log)
		db.InitializeDB() //nolint:errcheck,gosec
		db.CloseDB()      //nolint:errcheck,gosec
	}
}

// TestIsDuplicateColumnError_SQLite tests duplicate column detection for SQLite.
func TestIsDuplicateColumnError_SQLite(t *testing.T) {
	err := fmt.Errorf("table secrets already has column deleted_at: duplicate column name: deleted_at")
	assert.True(t, isDuplicateColumnError(err), "SQLite duplicate column error should be detected")
}

// TestIsDuplicateColumnError_PostgreSQL_DuplicateColumn tests PostgreSQL error code 42701.
func TestIsDuplicateColumnError_PostgreSQL_DuplicateColumn(t *testing.T) {
	err := &pq.Error{Code: "42701", Message: "column deleted_at of relation secrets already exists"}
	assert.True(t, isDuplicateColumnError(err), "PostgreSQL duplicate column error (42701) should be detected")
}

// TestIsDuplicateColumnError_PostgreSQL_TableAlreadyExists tests that table-exists errors are NOT silenced.
func TestIsDuplicateColumnError_PostgreSQL_TableAlreadyExists(t *testing.T) {
	err := &pq.Error{Code: "42P07", Message: "relation secrets already exists"}
	assert.False(t, isDuplicateColumnError(err), "table already exists error (42P07) must not be silenced as duplicate column")
}

// TestIsDuplicateColumnError_Nil tests that nil errors are handled correctly.
func TestIsDuplicateColumnError_Nil(t *testing.T) {
	assert.False(t, isDuplicateColumnError(nil), "nil error should return false")
}

// TestIsDuplicateColumnError_GenericError tests that unrelated errors are not matched.
func TestIsDuplicateColumnError_GenericError(t *testing.T) {
	assert.False(t, isDuplicateColumnError(fmt.Errorf("connection refused")), "generic error should not match duplicate column")
}

// TestInitializeDB_SeedsDefaultVault verifies the default vault is seeded on startup.
func TestInitializeDB_SeedsDefaultVault(t *testing.T) {
	viper.Set("database.connection", "./test_vault_seed.db")
	defer os.Remove("./test_vault_seed.db") //nolint:errcheck
	log := logging.InitLogger()
	d := NewRepository(log)
	assert.NoError(t, d.InitializeDB())

	var name string
	err := d.GetDB().QueryRow("SELECT name FROM vaults WHERE id = ?", "00000000-0000-0000-0000-00000000efa1").Scan(&name)
	assert.NoError(t, err, "default vault should be seeded")
	assert.Equal(t, "default", name)
}

// TestMigrateSchema_CreatesVaultProvisioningGrants verifies that migrateSchema
// creates the vault_provisioning_grants table and its idx_vaults_created_by
// index on a pre-existing (old-shape) database.
func TestMigrateSchema_CreatesVaultProvisioningGrants(t *testing.T) {
	db, err := sql.Open("sqlite3", ":memory:")
	require.NoError(t, err)
	defer db.Close()

	repo := newTestDBRepository(t, db)
	require.NoError(t, repo.migrateSchema(db))

	var name string
	err = db.QueryRow(
		`SELECT name FROM sqlite_master WHERE type='table' AND name='vault_provisioning_grants'`,
	).Scan(&name)
	require.NoError(t, err, "migrateSchema must create vault_provisioning_grants")

	err = db.QueryRow(
		`SELECT name FROM sqlite_master WHERE type='index' AND name='idx_vaults_created_by'`,
	).Scan(&name)
	require.NoError(t, err, "migrateSchema must create idx_vaults_created_by")
}

// TestMigrateSchema_CreatesLoginFailures verifies that migrateSchema creates
// the login_failures table and its pruning index on a pre-existing database.
func TestMigrateSchema_CreatesLoginFailures(t *testing.T) {
	db, err := sql.Open("sqlite3", ":memory:")
	require.NoError(t, err)
	defer db.Close()

	repo := newTestDBRepository(t, db)
	require.NoError(t, repo.migrateSchema(db))

	var name string
	err = db.QueryRow(
		`SELECT name FROM sqlite_master WHERE type='table' AND name='login_failures'`,
	).Scan(&name)
	require.NoError(t, err, "migrateSchema must create login_failures")

	err = db.QueryRow(
		`SELECT name FROM sqlite_master WHERE type='index' AND name='idx_login_failures_last_failure_at'`,
	).Scan(&name)
	require.NoError(t, err, "migrateSchema must create idx_login_failures_last_failure_at")
}

// TestCreateOptimizedSchema_CreatesLoginFailures verifies that a fresh
// database gets the login_failures table from the initial schema block.
func TestCreateOptimizedSchema_CreatesLoginFailures(t *testing.T) {
	db, err := sql.Open("sqlite3", ":memory:")
	require.NoError(t, err)
	defer db.Close()
	db.SetMaxOpenConns(1)

	repo := NewRepository(logging.InitLogger())
	require.NoError(t, repo.createOptimizedSchema(db))

	var name string
	err = db.QueryRow(
		`SELECT name FROM sqlite_master WHERE type='table' AND name='login_failures'`,
	).Scan(&name)
	require.NoError(t, err, "createOptimizedSchema must create login_failures")

	err = db.QueryRow(
		`SELECT name FROM sqlite_master WHERE type='index' AND name='idx_login_failures_last_failure_at'`,
	).Scan(&name)
	require.NoError(t, err, "createOptimizedSchema must create idx_login_failures_last_failure_at")
}

// TestWarnGlobalVaultManageGrants_LogsEachHolder verifies that a global
// (vault_id IS NULL) vaults:manage allow is reported, and that a
// vault-scoped one is not -- the latter is unaffected by the coming
// narrowing and must not send operators chasing a grant that is not at risk.
func TestWarnGlobalVaultManageGrants_LogsEachHolder(t *testing.T) {
	database, err := sql.Open("sqlite3", ":memory:")
	require.NoError(t, err)
	defer database.Close()

	_, err = database.Exec(`
		CREATE TABLE access_policies (
			id TEXT PRIMARY KEY, principal_id TEXT NOT NULL, principal_type TEXT NOT NULL,
			resource_type TEXT NOT NULL, operation TEXT NOT NULL, effect TEXT NOT NULL,
			vault_id TEXT NULL, assignment_id TEXT NULL,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP);`)
	require.NoError(t, err)

	holder := uuid.New().String()
	// A global allow: must be reported.
	_, err = database.Exec(
		`INSERT INTO access_policies (id, principal_id, principal_type, resource_type, operation, effect, vault_id)
		 VALUES (?, ?, 'user', 'vaults', 'manage', 'allow', NULL)`, uuid.New().String(), holder)
	require.NoError(t, err)
	// A vault-scoped allow: must NOT be reported, it is unaffected by release 2.
	_, err = database.Exec(
		`INSERT INTO access_policies (id, principal_id, principal_type, resource_type, operation, effect, vault_id)
		 VALUES (?, ?, 'user', 'vaults', 'manage', 'allow', ?)`,
		uuid.New().String(), uuid.New().String(), uuid.New().String())
	require.NoError(t, err)

	hook, repo := newLogCapturingDBRepository(t, database)
	repo.warnGlobalVaultManageGrants(database)

	var messages []string
	for _, e := range hook.AllEntries() {
		messages = append(messages, e.Message+fmt.Sprint(e.Data))
	}
	joined := strings.Join(messages, "\n")
	require.Contains(t, joined, holder, "the global-grant holder must be named in the log")
	require.Equal(t, 1, strings.Count(joined, "global vaults:manage"),
		"only the global grant is reported; vault-scoped grants are unaffected by release 2")
}

// TestWarnGlobalVaultManageGrants_ContinuesAfterBadRow proves a row that
// fails to scan does not truncate the rest of the list. This diagnostic's
// entire purpose is to give an operator the COMPLETE set of principals
// affected by the coming narrowing; a `return` on the first bad row would
// silently drop everyone after it.
//
// The first row's principal_id is stored as SQL NULL against a schema that
// (unlike the real access_policies table) does not forbid it here, so
// Scan into the non-nullable `string` destination genuinely fails with
// "converting NULL to string is unsupported" -- a real database/sql Scan
// error, not a simulated one. The second row is an ordinary valid global
// grant and must still be reported.
func TestWarnGlobalVaultManageGrants_ContinuesAfterBadRow(t *testing.T) {
	database, err := sql.Open("sqlite3", ":memory:")
	require.NoError(t, err)
	defer database.Close()

	// principal_id intentionally has no NOT NULL constraint here (unlike the
	// real access_policies schema) so the first row below can carry a NULL
	// that triggers a genuine Scan error.
	_, err = database.Exec(`
		CREATE TABLE access_policies (
			id TEXT PRIMARY KEY, principal_id TEXT, principal_type TEXT NOT NULL,
			resource_type TEXT NOT NULL, operation TEXT NOT NULL, effect TEXT NOT NULL,
			vault_id TEXT NULL, assignment_id TEXT NULL,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP);`)
	require.NoError(t, err)

	// Row 1: a global allow whose principal_id is NULL -- Scan into `string`
	// fails on this row.
	_, err = database.Exec(
		`INSERT INTO access_policies (id, principal_id, principal_type, resource_type, operation, effect, vault_id)
		 VALUES (?, NULL, 'user', 'vaults', 'manage', 'allow', NULL)`, uuid.New().String())
	require.NoError(t, err)

	// Row 2: an ordinary valid global allow. Must still be reported even
	// though it is scanned after the bad row.
	secondHolder := uuid.New().String()
	_, err = database.Exec(
		`INSERT INTO access_policies (id, principal_id, principal_type, resource_type, operation, effect, vault_id)
		 VALUES (?, ?, 'user', 'vaults', 'manage', 'allow', NULL)`, uuid.New().String(), secondHolder)
	require.NoError(t, err)

	hook, repo := newLogCapturingDBRepository(t, database)
	repo.warnGlobalVaultManageGrants(database)

	var messages []string
	for _, e := range hook.AllEntries() {
		messages = append(messages, e.Message+fmt.Sprint(e.Data))
	}
	joined := strings.Join(messages, "\n")
	require.Contains(t, joined, secondHolder,
		"the row after the bad one must still be reported -- enumeration must not stop on a scan error")
	require.Equal(t, 1, strings.Count(joined, "Principal holds a global vaults:manage grant"),
		"exactly the one valid row is reported")
	require.Contains(t, joined, "Failed to scan a global vaults:manage grant",
		"the bad row is still logged, just not fatal to the scan")
}

// TestWarnGlobalVaultManageGrants_MissingTableDoesNotPanic pins the
// never-fail-startup posture: a query error against a partially-built
// schema (e.g. a migrateSchema-only test fixture with no access_policies
// table) must be logged and swallowed, never panic or propagate.
func TestWarnGlobalVaultManageGrants_MissingTableDoesNotPanic(t *testing.T) {
	database, err := sql.Open("sqlite3", ":memory:")
	require.NoError(t, err)
	defer database.Close()

	_, repo := newLogCapturingDBRepository(t, database)

	require.NotPanics(t, func() { repo.warnGlobalVaultManageGrants(database) },
		"a diagnostic must never fail startup on a partially-built schema")
}

// TestSeedDefaultVault_Idempotent verifies seedDefaultVault does not error or duplicate.
func TestSeedDefaultVault_Idempotent(t *testing.T) {
	viper.Set("database.connection", "./test_vault_idem.db")
	defer os.Remove("./test_vault_idem.db") //nolint:errcheck
	log := logging.InitLogger()
	d := NewRepository(log)
	assert.NoError(t, d.InitializeDB())
	// Calling seedDefaultVault again must not error or duplicate.
	assert.NoError(t, d.seedDefaultVault(d.GetDB()))
	var n int
	assert.NoError(t, d.GetDB().QueryRow("SELECT COUNT(*) FROM vaults WHERE name='default'").Scan(&n))
	assert.Equal(t, 1, n)
}
