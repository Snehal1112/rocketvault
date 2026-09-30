package repositories

import (
	"database/sql"
	"testing"

	"github.com/stretchr/testify/require"
)

// createCertificateVersionsTable adds certificate_versions to a hand-written
// test schema. The purge and delete paths now delete from it explicitly.
func createCertificateVersionsTable(t *testing.T, db *sql.DB) {
	t.Helper()
	_, err := db.Exec(`CREATE TABLE IF NOT EXISTS certificate_versions (
		certificate_id TEXT NOT NULL,
		version        INTEGER NOT NULL,
		certificate    TEXT NOT NULL,
		private_key    TEXT NOT NULL,
		key_id         TEXT NULL,
		created_at     TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		expires_at     TIMESTAMP NULL,
		not_before     TIMESTAMP NULL,
		enabled        BOOLEAN NOT NULL DEFAULT TRUE,
		PRIMARY KEY (certificate_id, version)
	)`)
	require.NoError(t, err)
}
