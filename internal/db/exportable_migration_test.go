// Export adds certificates.exportable and keys.exportable. These tests prove
// a fresh database gets both with a false default, an upgraded database gets
// both with every existing row reading false and nothing rewritten, and a
// second migration run is a no-op.
package db

import (
	"context"
	"database/sql"
	"testing"

	_ "github.com/mattn/go-sqlite3"
	"github.com/stretchr/testify/require"

	"rocketvault/internal/logging"
)

func TestSetupSchema_FreshDatabaseHasExportableColumns(t *testing.T) {
	conn, err := sql.Open("sqlite3", ":memory:")
	require.NoError(t, err)
	conn.SetMaxOpenConns(1)
	defer conn.Close() //nolint:errcheck

	repo := NewRepository(&logging.Logger{Logger: newSilentLogrus()})
	require.NoError(t, repo.SetupSchema(conn, SQLite))

	_, err = conn.ExecContext(context.Background(), `INSERT INTO certificates (id, user_id, name, certificate, private_key) VALUES ('c1', 'u1', 'c', 'pem', 'key')`)
	require.NoError(t, err)
	_, err = conn.ExecContext(context.Background(), `INSERT INTO keys (id, user_id, name, value, type) VALUES ('k1', 'u1', 'k', 'v', 'RSA')`)
	require.NoError(t, err)

	var certExportable, keyExportable bool
	require.NoError(t, conn.QueryRowContext(context.Background(), `SELECT exportable FROM certificates WHERE id = 'c1'`).Scan(&certExportable))
	require.NoError(t, conn.QueryRowContext(context.Background(), `SELECT exportable FROM keys WHERE id = 'k1'`).Scan(&keyExportable))
	require.False(t, certExportable, "a certificate created without the flag is not exportable")
	require.False(t, keyExportable, "a key created without the flag is not exportable")

	require.False(t, columnExists(t, conn, "certificate_versions", "exportable"),
		"versions share the parent's flag; certificate_versions has no exportable column")
}

func TestMigrateSchema_ExistingRowsBecomeNonExportable(t *testing.T) {
	conn, err := sql.Open("sqlite3", ":memory:")
	require.NoError(t, err)
	conn.SetMaxOpenConns(1)
	defer conn.Close() //nolint:errcheck

	// Minimal pre-feature schema, copied from the certificate-versions
	// migration test, with one existing certificate and one existing key.
	_, err = conn.ExecContext(context.Background(), `
		CREATE TABLE users (id TEXT PRIMARY KEY, username TEXT NOT NULL, role TEXT NOT NULL);
		CREATE TABLE secrets (id TEXT PRIMARY KEY, name TEXT NOT NULL);
		CREATE TABLE certificates (id TEXT PRIMARY KEY, name TEXT NOT NULL);
		CREATE TABLE access_policies (
			id TEXT PRIMARY KEY, principal_id TEXT NOT NULL, principal_type TEXT NOT NULL,
			resource_type TEXT NOT NULL, operation TEXT NOT NULL, effect TEXT NOT NULL,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		);
		CREATE TABLE audit_logs (id TEXT PRIMARY KEY);
		CREATE TABLE vaults (
			id TEXT PRIMARY KEY, name TEXT NOT NULL, enabled BOOLEAN NOT NULL DEFAULT TRUE,
			purge_protection BOOLEAN NOT NULL DEFAULT FALSE, retention_days INTEGER NOT NULL DEFAULT 90,
			created_by TEXT NOT NULL, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			deleted_at TIMESTAMP NULL, scheduled_purge_at TIMESTAMP NULL
		);
		CREATE TABLE keys (
			id TEXT PRIMARY KEY, name TEXT NOT NULL,
			vault_id TEXT NOT NULL DEFAULT '00000000-0000-0000-0000-00000000efa1',
			created_at TIMESTAMP NOT NULL
		);
		CREATE TABLE rotation_policies (
			id TEXT PRIMARY KEY, user_id TEXT NOT NULL,
			vault_id TEXT NOT NULL DEFAULT '00000000-0000-0000-0000-00000000efa1',
			name TEXT NOT NULL, description TEXT, interval_days INTEGER NOT NULL,
			enabled BOOLEAN NOT NULL DEFAULT TRUE, reminder_days INTEGER NOT NULL DEFAULT 7,
			auto_rotate BOOLEAN NOT NULL DEFAULT FALSE,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		);
		CREATE TABLE key_rotation_policies (
			id TEXT PRIMARY KEY, key_id TEXT NOT NULL UNIQUE, user_id TEXT NOT NULL,
			vault_id TEXT NOT NULL DEFAULT '00000000-0000-0000-0000-00000000efa1',
			rotate_after_days INTEGER NOT NULL DEFAULT 90,
			notify_before_expiry_days INTEGER NOT NULL DEFAULT 30,
			expiry_days INTEGER NOT NULL DEFAULT 365, enabled BOOLEAN NOT NULL DEFAULT TRUE,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		);
		INSERT INTO certificates (id, name) VALUES ('old-cert', 'issued-before-export');
		INSERT INTO keys (id, name, created_at) VALUES ('old-key', 'created-before-export', CURRENT_TIMESTAMP);
	`)
	require.NoError(t, err)

	repo := &DBRepository{dialect: SQLite}
	repo.log = &logging.Logger{Logger: newSilentLogrus()}
	require.NoError(t, repo.migrateSchema(conn))

	var certExportable, keyExportable bool
	require.NoError(t, conn.QueryRowContext(context.Background(), `SELECT exportable FROM certificates WHERE id = 'old-cert'`).Scan(&certExportable))
	require.NoError(t, conn.QueryRowContext(context.Background(), `SELECT exportable FROM keys WHERE id = 'old-key'`).Scan(&keyExportable))
	require.False(t, certExportable)
	require.False(t, keyExportable)

	var name string
	require.NoError(t, conn.QueryRowContext(context.Background(), `SELECT name FROM certificates WHERE id = 'old-cert'`).Scan(&name))
	require.Equal(t, "issued-before-export", name, "nothing is rewritten")

	require.NoError(t, repo.migrateSchema(conn), "a second run must ignore the duplicate columns")
}
