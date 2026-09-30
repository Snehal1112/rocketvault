// Certificate versioning adds certificates.version and the
// certificate_versions table. These tests prove a fresh database gets both,
// an upgraded one gets both with every existing row reading as version 1 and
// nothing archived, and that a second migration run is a no-op.
package db

import (
	"database/sql"
	"testing"

	_ "github.com/mattn/go-sqlite3"
	"github.com/stretchr/testify/require"

	"rocketvault/internal/logging"
)

func TestSetupSchema_FreshDatabaseHasCertificateVersions(t *testing.T) {
	conn, err := sql.Open("sqlite3", ":memory:")
	require.NoError(t, err)
	conn.SetMaxOpenConns(1)
	defer conn.Close() //nolint:errcheck

	repo := NewRepository(&logging.Logger{Logger: newSilentLogrus()})
	require.NoError(t, repo.SetupSchema(conn, SQLite))

	_, err = conn.Exec(`INSERT INTO certificates (id, user_id, name, certificate, private_key)
		VALUES ('c1', 'u1', 'fresh', 'pem', 'key')`)
	require.NoError(t, err)

	var version int
	require.NoError(t, conn.QueryRow(`SELECT version FROM certificates WHERE id = 'c1'`).Scan(&version))
	require.Equal(t, 1, version, "a certificate created without a version is version 1")

	_, err = conn.Exec(`INSERT INTO certificate_versions (certificate_id, version, certificate, private_key, enabled)
		VALUES ('c1', 1, 'pem', 'key', TRUE)`)
	require.NoError(t, err)

	_, err = conn.Exec(`INSERT INTO certificate_versions (certificate_id, version, certificate, private_key, enabled)
		VALUES ('c1', 1, 'pem', 'key', TRUE)`)
	require.Error(t, err, "(certificate_id, version) is the primary key")
}

func TestMigrateSchema_ExistingCertificatesBecomeVersionOne(t *testing.T) {
	conn, err := sql.Open("sqlite3", ":memory:")
	require.NoError(t, err)
	conn.SetMaxOpenConns(1)
	defer conn.Close() //nolint:errcheck

	// Minimal pre-feature schema: the tables migrateSchema ALTERs, in shapes
	// that predate this column. Copied from the B37 migration test.
	_, err = conn.Exec(`
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
		INSERT INTO certificates (id, name) VALUES ('existing', 'issued-before-versioning');
	`)
	require.NoError(t, err)

	repo := &DBRepository{dialect: SQLite}
	repo.log = &logging.Logger{Logger: newSilentLogrus()}
	require.NoError(t, repo.migrateSchema(conn))

	var version int
	require.NoError(t, conn.QueryRow(`SELECT version FROM certificates WHERE id = 'existing'`).Scan(&version))
	require.Equal(t, 1, version, "an existing certificate becomes version 1")

	var archived int
	require.NoError(t, conn.QueryRow(`SELECT COUNT(*) FROM certificate_versions`).Scan(&archived))
	require.Zero(t, archived, "nothing is backfilled")

	// A second run must not error on the now-existing column and table.
	require.NoError(t, repo.migrateSchema(conn))
}
