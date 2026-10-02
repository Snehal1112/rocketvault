// Regression test for the access_policies.assignment_id index-ordering bug.
//
// createOptimizedSchema used to run
// `CREATE INDEX idx_access_policies_assignment ON access_policies(assignment_id)`
// in its big SQL block. On an EXISTING database whose access_policies table
// predates the assignment_id column, the `CREATE TABLE IF NOT EXISTS` is a
// no-op, so the index creation failed with "no such column: assignment_id" —
// and it ran BEFORE migrateSchema adds the column. The fix moved that index
// into migrateSchema, which runs after the ALTER that adds the column.
//
// This test reproduces the full InitializeDB ordering (createOptimizedSchema
// then migrateSchema) against a pre-feature, non-empty access_policies table,
// which the existing tests did not cover.
package db

import (
	"context"
	"database/sql"
	"testing"

	_ "github.com/mattn/go-sqlite3"
	"github.com/stretchr/testify/require"

	"rocketvault/internal/logging"
)

// TestUpgradePath_PreFeatureAccessPoliciesGetsAssignmentID runs the real init
// sequence on a database that already has an old-shape access_policies table.
func TestUpgradePath_PreFeatureAccessPoliciesGetsAssignmentID(t *testing.T) {
	conn, err := sql.Open("sqlite3", ":memory:")
	require.NoError(t, err)
	defer conn.Close() //nolint:errcheck

	// Pre-feature prerequisite tables in their old shape. These carry the
	// columns that createOptimizedSchema's CREATE INDEX statements reference
	// (user_id, name, created_at, etc.) so that those indexes succeed against a
	// pre-existing table — a real upgraded DB would already have had them. They
	// deliberately omit the newer columns that migrateSchema ALTERs in, so the
	// migration still has work to do. The access_policies table deliberately
	// omits assignment_id, which is the column at the center of this bug.
	_, err = conn.Exec(`
		CREATE TABLE secrets (
			id         TEXT PRIMARY KEY,
			user_id    TEXT NOT NULL,
			name       TEXT NOT NULL,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		);
		CREATE TABLE keys (
			id         TEXT PRIMARY KEY,
			user_id    TEXT NOT NULL,
			name       TEXT NOT NULL,
			type       TEXT NOT NULL DEFAULT '',
			revoked    BOOLEAN NOT NULL DEFAULT FALSE,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		);
		CREATE TABLE certificates (
			id         TEXT PRIMARY KEY,
			user_id    TEXT NOT NULL,
			name       TEXT NOT NULL,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		);
		CREATE TABLE audit_logs (
			id        TEXT PRIMARY KEY,
			user_id   TEXT,
			action    TEXT NOT NULL DEFAULT '',
			timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		);
		CREATE TABLE access_policies (
			id             TEXT PRIMARY KEY,
			principal_id   TEXT NOT NULL,
			principal_type TEXT NOT NULL,
			resource_type  TEXT NOT NULL,
			operation      TEXT NOT NULL,
			effect         TEXT NOT NULL,
			vault_id       TEXT,
			created_at     TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		);
		INSERT INTO access_policies (id, principal_id, principal_type, resource_type, operation, effect)
			VALUES ('p1','u1','user','secrets','get','allow');
	`)
	require.NoError(t, err)

	// Sanity check: the column must NOT exist before the upgrade runs.
	require.False(t, columnExists(t, conn, "access_policies", "assignment_id"),
		"assignment_id must not exist before the upgrade sequence runs")

	d := NewRepository(logging.InitLogger())

	// Real InitializeDB order: createOptimizedSchema THEN migrateSchema.
	// Before the fix, createOptimizedSchema errored here with
	// "no such column: assignment_id".
	require.NoError(t, d.createOptimizedSchema(conn), "createOptimizedSchema (upgrade) should succeed")
	require.NoError(t, d.migrateSchema(conn), "migrateSchema (upgrade) should succeed")

	// Idempotency: a second full pass must also succeed.
	require.NoError(t, d.createOptimizedSchema(conn), "createOptimizedSchema rerun should succeed")
	require.NoError(t, d.migrateSchema(conn), "migrateSchema rerun should succeed")

	// The assignment_id column must now exist on access_policies.
	var col string
	if err := conn.QueryRow(
		`SELECT name FROM pragma_table_info('access_policies') WHERE name='assignment_id'`).Scan(&col); err != nil {
		t.Fatalf("assignment_id column missing after upgrade: %v", err)
	}
	require.Equal(t, "assignment_id", col)

	// The index must exist.
	var idx string
	if err := conn.QueryRow(
		`SELECT name FROM sqlite_master WHERE type='index' AND name='idx_access_policies_assignment'`).Scan(&idx); err != nil {
		t.Fatalf("idx_access_policies_assignment missing after upgrade: %v", err)
	}
	require.Equal(t, "idx_access_policies_assignment", idx)

	// The pre-existing row must survive the upgrade.
	var n int
	if err := conn.QueryRow(`SELECT COUNT(*) FROM access_policies`).Scan(&n); err != nil {
		t.Fatalf("counting access_policies failed: %v", err)
	}
	require.Equal(t, 1, n, "pre-existing access_policies row must survive the upgrade")
}

// TestUpgradePath_PreFeatureUsersGetsAuthProvider is the same class of bug as
// TestUpgradePath_PreFeatureAccessPoliciesGetsAssignmentID, this time for the
// OIDC feature's auth_provider/external_idp_subject columns: createOptimizedSchema
// briefly contained `CREATE UNIQUE INDEX idx_users_external_idp ON
// users(auth_provider, external_idp_subject) ...` directly after the users
// CREATE TABLE. On an EXISTING database whose users table predates those
// columns, CREATE TABLE IF NOT EXISTS is a no-op, so the index creation failed
// with "no such column: auth_provider" — and it ran BEFORE migrateSchema adds
// the columns. The fix moved that index into migrateSchema only, which runs
// after the ALTER TABLE statements that add the columns.
func TestUpgradePath_PreFeatureUsersGetsAuthProvider(t *testing.T) {
	conn, err := sql.Open("sqlite3", ":memory:")
	require.NoError(t, err)
	defer conn.Close() //nolint:errcheck

	// Pre-feature prerequisite tables in their old shape, mirroring the sibling
	// test above. The users table deliberately omits auth_provider/
	// external_idp_subject, the columns at the center of this bug.
	_, err = conn.Exec(`
		CREATE TABLE users (
			id            TEXT PRIMARY KEY,
			username      TEXT UNIQUE NOT NULL,
			password_hash TEXT NOT NULL,
			totp_secret   TEXT,
			role          TEXT NOT NULL,
			created_at    TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		);
		CREATE TABLE secrets (
			id         TEXT PRIMARY KEY,
			user_id    TEXT NOT NULL,
			name       TEXT NOT NULL,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		);
		CREATE TABLE keys (
			id         TEXT PRIMARY KEY,
			user_id    TEXT NOT NULL,
			name       TEXT NOT NULL,
			type       TEXT NOT NULL DEFAULT '',
			revoked    BOOLEAN NOT NULL DEFAULT FALSE,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		);
		CREATE TABLE certificates (
			id         TEXT PRIMARY KEY,
			user_id    TEXT NOT NULL,
			name       TEXT NOT NULL,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		);
		CREATE TABLE audit_logs (
			id        TEXT PRIMARY KEY,
			user_id   TEXT,
			action    TEXT NOT NULL DEFAULT '',
			timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		);
		CREATE TABLE access_policies (
			id             TEXT PRIMARY KEY,
			principal_id   TEXT NOT NULL,
			principal_type TEXT NOT NULL,
			resource_type  TEXT NOT NULL,
			operation      TEXT NOT NULL,
			effect         TEXT NOT NULL,
			vault_id       TEXT,
			assignment_id  TEXT,
			created_at     TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		);
		INSERT INTO users (id, username, password_hash, role) VALUES ('u1', 'alice', 'hash', 'admin');
	`)
	require.NoError(t, err)

	// Sanity check: the column must NOT exist before the upgrade runs.
	require.False(t, columnExists(t, conn, "users", "auth_provider"),
		"auth_provider must not exist before the upgrade sequence runs")
	require.False(t, columnExists(t, conn, "users", "totp_last_step"),
		"totp_last_step must not exist before the upgrade sequence runs")

	d := NewRepository(logging.InitLogger())

	// Real InitializeDB order: createOptimizedSchema THEN migrateSchema.
	// Before the fix, createOptimizedSchema errored here with
	// "no such column: auth_provider".
	require.NoError(t, d.createOptimizedSchema(conn), "createOptimizedSchema (upgrade) should succeed")
	require.NoError(t, d.migrateSchema(conn), "migrateSchema (upgrade) should succeed")

	// Idempotency: a second full pass must also succeed.
	require.NoError(t, d.createOptimizedSchema(conn), "createOptimizedSchema rerun should succeed")
	require.NoError(t, d.migrateSchema(conn), "migrateSchema rerun should succeed")

	// The auth_provider column must now exist on users.
	var col string
	if err := conn.QueryRow(
		`SELECT name FROM pragma_table_info('users') WHERE name='auth_provider'`).Scan(&col); err != nil {
		t.Fatalf("auth_provider column missing after upgrade: %v", err)
	}
	require.Equal(t, "auth_provider", col)

	// The index must exist.
	var idx string
	if err := conn.QueryRow(
		`SELECT name FROM sqlite_master WHERE type='index' AND name='idx_users_external_idp'`).Scan(&idx); err != nil {
		t.Fatalf("idx_users_external_idp missing after upgrade: %v", err)
	}
	require.Equal(t, "idx_users_external_idp", idx)

	// The pre-existing row must survive the upgrade, defaulted to local auth.
	var authProvider string
	if err := conn.QueryRow(`SELECT auth_provider FROM users WHERE id = 'u1'`).Scan(&authProvider); err != nil {
		t.Fatalf("querying pre-existing user's auth_provider failed: %v", err)
	}
	require.Equal(t, "local", authProvider, "pre-existing users must default to local auth_provider")

	// The TOTP replay column must be added to the old table, defaulted to 0.
	var step int64
	if err := conn.QueryRowContext(context.Background(), `SELECT totp_last_step FROM users WHERE id = 'u1'`).Scan(&step); err != nil {
		t.Fatalf("querying pre-existing user's totp_last_step failed: %v", err)
	}
	require.Equal(t, int64(0), step, "pre-existing users must start with totp_last_step 0")
}
