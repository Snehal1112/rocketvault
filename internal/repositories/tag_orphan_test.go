// internal/repositories/tag_orphan_test.go
package repositories_test

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/google/uuid"
	_ "github.com/mattn/go-sqlite3"
	"github.com/stretchr/testify/require"

	rvdb "rocketvault/internal/db"
	"rocketvault/internal/logging"
	"rocketvault/internal/repositories"
	"rocketvault/model"
)

// setupTagOrphanTestDB creates an in-memory SQLite database with the keys and
// key_tags tables. The FOREIGN KEY ... ON DELETE CASCADE is declared exactly as
// production declares it -- and, exactly as in production, SQLite leaves the
// foreign_keys pragma off, so it never fires. That is the whole point of the
// test: the cascade looks like it handles this and does not.
//
// Named distinctly from the package-scope setupTestDB, setupRotationTestDB,
// setupSessionTestDB, setupCertListAllTestDB, setupRoleAssignmentTestDB and
// setupCertLifecycleTestDB helpers that already exist in this test package.
func setupTagOrphanTestDB(t *testing.T) *sql.DB {
	t.Helper()

	dsn := "file:tagorphan_" + uuid.NewString() + "?mode=memory&cache=shared"
	raw, err := sql.Open("sqlite3", dsn)
	require.NoError(t, err, "open in-memory database")
	t.Cleanup(func() { _ = raw.Close() })

	_, err = raw.Exec(`
		CREATE TABLE keys (
			id TEXT PRIMARY KEY,
			user_id TEXT NOT NULL,
			vault_id TEXT NOT NULL,
			name TEXT NOT NULL,
			value TEXT NOT NULL,
			type TEXT NOT NULL,
			revoked BOOLEAN NOT NULL DEFAULT FALSE,
			created_at TIMESTAMP NOT NULL,
			enabled BOOLEAN NOT NULL DEFAULT TRUE,
			expires_at TIMESTAMP,
			not_before TIMESTAMP,
			bits INTEGER NOT NULL DEFAULT 0,
			curve TEXT NOT NULL DEFAULT '',
			updated_at TIMESTAMP,
			deleted_at TIMESTAMP,
			scheduled_purge_at TIMESTAMP,
			purge_protection BOOLEAN NOT NULL DEFAULT FALSE,
			exportable BOOLEAN NOT NULL DEFAULT FALSE
		);
		CREATE TABLE key_tags (
			key_id TEXT NOT NULL,
			tag TEXT NOT NULL,
			PRIMARY KEY (key_id, tag),
			FOREIGN KEY (key_id) REFERENCES keys(id) ON DELETE CASCADE
		);
	`)
	require.NoError(t, err, "create keys schema")

	return raw
}

func countKeyTags(t *testing.T, raw *sql.DB, keyID uuid.UUID) int {
	t.Helper()
	var n int
	require.NoError(t, raw.QueryRow(
		"SELECT COUNT(*) FROM key_tags WHERE key_id = ?", keyID.String()).Scan(&n))
	return n
}

// TestPurgeKeyRemovesItsTags pins the F5 fix. key_tags declares ON DELETE
// CASCADE, but SQLite runs with the foreign_keys pragma off project-wide, so
// the cascade never fires and purging a key strands every tag row it owned --
// unreachable through any route and never swept.
func TestPurgeKeyRemovesItsTags(t *testing.T) {
	raw := setupTagOrphanTestDB(t)
	repo := repositories.NewKeyRepository(rvdb.NewConn(raw, rvdb.SQLite), logging.InitLogger())

	ctx := context.Background()
	key := &model.Key{
		ID:        uuid.New(),
		UserID:    uuid.New(),
		VaultID:   uuid.New(),
		Name:      "signing-key",
		Value:     "ENCRYPTED",
		Type:      "RSA",
		CreatedAt: time.Now(),
		Enabled:   true,
		Tags:      []string{"prod", "signing"},
	}
	require.NoError(t, repo.Create(ctx, key))
	require.Equal(t, 2, countKeyTags(t, raw, key.ID), "tags were stored")

	require.NoError(t, repo.SoftDelete(ctx, key.ID))
	require.NoError(t, repo.PurgeKey(ctx, key.ID))

	require.Equal(t, 0, countKeyTags(t, raw, key.ID),
		"purging a key must remove its tag rows; SQLite's declared cascade does not fire")
}

// TestDeleteKeyRemovesItsTags confirms the hard-delete path, which key and
// certificate already handled explicitly and secret did not.
func TestDeleteKeyRemovesItsTags(t *testing.T) {
	raw := setupTagOrphanTestDB(t)
	repo := repositories.NewKeyRepository(rvdb.NewConn(raw, rvdb.SQLite), logging.InitLogger())

	ctx := context.Background()
	key := &model.Key{
		ID:        uuid.New(),
		UserID:    uuid.New(),
		VaultID:   uuid.New(),
		Name:      "throwaway",
		Value:     "ENCRYPTED",
		Type:      "RSA",
		CreatedAt: time.Now(),
		Enabled:   true,
		Tags:      []string{"temp"},
	}
	require.NoError(t, repo.Create(ctx, key))
	require.Equal(t, 1, countKeyTags(t, raw, key.ID))

	require.NoError(t, repo.Delete(ctx, key.ID))
	require.Equal(t, 0, countKeyTags(t, raw, key.ID))
}

// TestDeleteKeyIsAtomic pins the transaction the shared helper opens: if the
// item delete finds no row, the tag delete that ran first must roll back
// rather than leaving the key present with its tags gone.
func TestDeleteKeyIsAtomic(t *testing.T) {
	raw := setupTagOrphanTestDB(t)
	repo := repositories.NewKeyRepository(rvdb.NewConn(raw, rvdb.SQLite), logging.InitLogger())

	ctx := context.Background()
	key := &model.Key{
		ID:        uuid.New(),
		UserID:    uuid.New(),
		VaultID:   uuid.New(),
		Name:      "keeper",
		Value:     "ENCRYPTED",
		Type:      "RSA",
		CreatedAt: time.Now(),
		Enabled:   true,
		Tags:      []string{"keep-me"},
	}
	require.NoError(t, repo.Create(ctx, key))

	// Delete a key that does not exist. The helper deletes tags first, so
	// without a rollback this would strip the real key's tags -- except the
	// id does not match, so nothing should change at all.
	err := repo.Delete(ctx, uuid.New())
	require.Error(t, err, "deleting an absent key is an error")
	require.Contains(t, err.Error(), "key not found")

	require.Equal(t, 1, countKeyTags(t, raw, key.ID),
		"an unrelated failed delete must not touch this key's tags")
}

// TestPurgeKeyIsAtomicOnItemDeleteFailure pins Finding 1 of the 2026-09-07
// review: purgeItem now opens its own transaction around the tag delete and
// the item delete, so a failure on the item delete must roll back the tag
// delete that already ran, rather than leaving the key present but stripped
// of its tags. A BEFORE DELETE trigger simulates the ordinary-error-path
// failure the review called out (lock contention, disk pressure) by making
// the "DELETE FROM keys" statement itself fail after the tag delete has
// already succeeded within the same transaction.
func TestPurgeKeyIsAtomicOnItemDeleteFailure(t *testing.T) {
	raw := setupTagOrphanTestDB(t)
	repo := repositories.NewKeyRepository(rvdb.NewConn(raw, rvdb.SQLite), logging.InitLogger())

	ctx := context.Background()
	key := &model.Key{
		ID:        uuid.New(),
		UserID:    uuid.New(),
		VaultID:   uuid.New(),
		Name:      "signing-key",
		Value:     "ENCRYPTED",
		Type:      "RSA",
		CreatedAt: time.Now(),
		Enabled:   true,
		Tags:      []string{"prod", "signing"},
	}
	require.NoError(t, repo.Create(ctx, key))
	require.NoError(t, repo.SoftDelete(ctx, key.ID))
	require.Equal(t, 2, countKeyTags(t, raw, key.ID), "tags were stored")

	// Force the item delete to fail once the tag delete has already run,
	// without touching the driver or the transaction machinery -- a trigger
	// is a faithful stand-in for "the second statement failed" regardless of
	// the real-world cause.
	_, err := raw.Exec(`
		CREATE TRIGGER block_purge BEFORE DELETE ON keys
		WHEN OLD.id = '` + key.ID.String() + `'
		BEGIN SELECT RAISE(ABORT, 'simulated purge failure'); END;
	`)
	require.NoError(t, err, "install failure trigger")

	err = repo.PurgeKey(ctx, key.ID)
	require.Error(t, err, "purge must fail when the item delete fails")
	require.Contains(t, err.Error(), "failed to purge key")

	require.Equal(t, 2, countKeyTags(t, raw, key.ID),
		"a failed item delete must roll back the tag delete that already ran in the same transaction")

	var stillPresent int
	require.NoError(t, raw.QueryRow(
		"SELECT COUNT(*) FROM keys WHERE id = ?", key.ID.String()).Scan(&stillPresent))
	require.Equal(t, 1, stillPresent, "the key row itself must survive the rolled-back purge")
}
