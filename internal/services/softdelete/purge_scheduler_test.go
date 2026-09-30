package softdelete

import (
	"context"
	"database/sql"
	"fmt"
	"sync"
	"testing"
	"time"

	_ "github.com/mattn/go-sqlite3"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"rocketvault/config"
	rvdb "rocketvault/internal/db"
	"rocketvault/internal/logging"
	"rocketvault/model"
)

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func newTestDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite3", ":memory:")
	require.NoError(t, err)
	t.Cleanup(func() { db.Close() }) //nolint:errcheck,gosec
	return db
}

// newTestConn wraps a *sql.DB in a dialect-aware *rvdb.Conn. Tests always use
// SQLite so the SQLite dialect is used.
func newTestConn(t *testing.T, rawDB *sql.DB) *rvdb.Conn {
	t.Helper()
	return rvdb.NewConn(rawDB, rvdb.SQLite)
}

func createPurgeTables(db *sql.DB) {
	for _, table := range []string{"secrets", "keys", "certificates"} {
		_, _ = db.Exec(fmt.Sprintf(`CREATE TABLE %s (
			id TEXT PRIMARY KEY,
			deleted_at DATETIME,
			purge_protection BOOLEAN DEFAULT FALSE
		)`, table))
	}
	createVersionsTable(db)
}

func createVersionsTable(db *sql.DB) {
	_, _ = db.Exec(`CREATE TABLE certificate_versions (
		certificate_id TEXT NOT NULL,
		version INTEGER NOT NULL
	)`)
}

func testLogger() *logging.Logger {
	return &logging.Logger{Logger: logrus.New()}
}

func testConfig() config.SoftDeleteConfig {
	return config.SoftDeleteConfig{
		Enabled:       true,
		RetentionDays: 30,
	}
}

// fakeVaultPurger is a hand-rolled in-memory VaultPurger for tests.
type fakeVaultPurger struct {
	vaults []model.Vault
	mu     sync.Mutex
	purged []string
	err    error
}

func (f *fakeVaultPurger) ListVaults(_ context.Context, _ bool) ([]model.Vault, error) {
	if f.err != nil {
		return nil, f.err
	}
	return f.vaults, nil
}

func (f *fakeVaultPurger) PurgeVault(_ context.Context, name string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.purged = append(f.purged, name)
	return nil
}

func (f *fakeVaultPurger) purgedNames() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.purged...)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

// 1. NewPurgeScheduler sets all fields correctly.
func TestNewPurgeScheduler(t *testing.T) {
	rawDB := newTestDB(t)
	conn := newTestConn(t, rawDB)
	cfg := testConfig()
	log := testLogger()

	vaults := &fakeVaultPurger{}
	s := NewPurgeScheduler(conn, cfg, log, vaults)

	require.NotNil(t, s)
	assert.Equal(t, conn, s.db)
	assert.Equal(t, cfg, s.cfg)
	assert.Equal(t, log, s.log)
	assert.NotNil(t, s.done)
	assert.Equal(t, vaults, s.vaults)
}

// 2. Start then immediately Stop does not panic.
func TestStartStop(t *testing.T) {
	rawDB := newTestDB(t)
	createPurgeTables(rawDB)
	conn := newTestConn(t, rawDB)

	s := NewPurgeScheduler(conn, testConfig(), testLogger(), nil)

	assert.NotPanics(t, func() {
		s.Start(context.Background())
		// Give the goroutine a moment to start and call purgeExpired once.
		time.Sleep(10 * time.Millisecond)
		s.Stop()
	})
}

// 3. purgeExpired with missing tables logs errors but does not panic.
func TestPurgeExpired_EmptyDB(t *testing.T) {
	// DB has no tables; every ExecContext will fail.
	rawDB := newTestDB(t)
	conn := newTestConn(t, rawDB)

	s := NewPurgeScheduler(conn, testConfig(), testLogger(), nil)

	// purgeExpired is called inside the goroutine launched by Start.
	// We just ensure no panic; errors are logged internally.
	assert.NotPanics(t, func() {
		s.Start(context.Background())
		time.Sleep(20 * time.Millisecond)
		s.Stop()
	})
}

// 4. Rows older than the retention window are deleted; newer rows are kept.
func TestPurgeExpired_WithData(t *testing.T) {
	rawDB := newTestDB(t)
	createPurgeTables(rawDB)

	// Insert one expired row (deleted 60 days ago) and one live row per table.
	expired := time.Now().AddDate(0, 0, -60).Format("2006-01-02 15:04:05")
	recent := time.Now().AddDate(0, 0, -5).Format("2006-01-02 15:04:05")

	for _, table := range []string{"secrets", "keys", "certificates"} {
		_, err := rawDB.Exec(
			fmt.Sprintf(`INSERT INTO %s (id, deleted_at, purge_protection) VALUES (?, ?, ?)`, table),
			"expired-"+table, expired, false,
		)
		require.NoError(t, err)

		_, err = rawDB.Exec(
			fmt.Sprintf(`INSERT INTO %s (id, deleted_at, purge_protection) VALUES (?, ?, ?)`, table),
			"recent-"+table, recent, false,
		)
		require.NoError(t, err)

		_, err = rawDB.Exec(
			fmt.Sprintf(`INSERT INTO %s (id, deleted_at, purge_protection) VALUES (?, ?, ?)`, table),
			"protected-"+table, expired, true,
		)
		require.NoError(t, err)
	}

	// RetentionDays=30 — the 60-day-old rows are past the threshold.
	conn := newTestConn(t, rawDB)
	s := NewPurgeScheduler(conn, testConfig(), testLogger(), nil)
	s.Start(context.Background())

	// Give the goroutine enough time to run purgeExpired once.
	time.Sleep(50 * time.Millisecond)
	s.Stop()

	for _, table := range []string{"secrets", "keys", "certificates"} {
		// Expired unprotected row must be gone.
		var count int
		err := rawDB.QueryRow(
			fmt.Sprintf(`SELECT COUNT(*) FROM %s WHERE id = ?`, table),
			"expired-"+table,
		).Scan(&count)
		require.NoError(t, err)
		assert.Equal(t, 0, count, "expected expired row to be purged from %s", table)

		// Recent row must still be present.
		err = rawDB.QueryRow(
			fmt.Sprintf(`SELECT COUNT(*) FROM %s WHERE id = ?`, table),
			"recent-"+table,
		).Scan(&count)
		require.NoError(t, err)
		assert.Equal(t, 1, count, "expected recent row to survive in %s", table)

		// Purge-protected row must still be present despite being old.
		err = rawDB.QueryRow(
			fmt.Sprintf(`SELECT COUNT(*) FROM %s WHERE id = ?`, table),
			"protected-"+table,
		).Scan(&count)
		require.NoError(t, err)
		assert.Equal(t, 1, count, "expected protected row to survive in %s", table)
	}
}

// 5. A cancelled context causes the goroutine to exit cleanly.
func TestStopViaContext(t *testing.T) {
	rawDB := newTestDB(t)
	createPurgeTables(rawDB)
	conn := newTestConn(t, rawDB)

	ctx, cancel := context.WithCancel(context.Background())

	s := NewPurgeScheduler(conn, testConfig(), testLogger(), nil)
	s.Start(ctx)

	// Cancel the context; the goroutine must exit without a panic.
	assert.NotPanics(t, func() {
		cancel()
		// Allow the goroutine a moment to react.
		time.Sleep(20 * time.Millisecond)
	})
}

// 6. purgeExpired does not delete rows that are not soft-deleted (deleted_at IS NULL).
func TestPurgeExpired_NullDeletedAt_NotPurged(t *testing.T) {
	rawDB := newTestDB(t)
	createPurgeTables(rawDB)

	// Active row — never soft-deleted.
	_, err := rawDB.Exec(
		`INSERT INTO secrets (id, deleted_at, purge_protection) VALUES (?, NULL, FALSE)`,
		"active-secret",
	)
	require.NoError(t, err)

	conn := newTestConn(t, rawDB)
	s := NewPurgeScheduler(conn, testConfig(), testLogger(), nil)
	s.Start(context.Background())
	time.Sleep(30 * time.Millisecond)
	s.Stop()

	var count int
	err = rawDB.QueryRow(`SELECT COUNT(*) FROM secrets WHERE id = 'active-secret'`).Scan(&count)
	require.NoError(t, err)
	assert.Equal(t, 1, count, "active (non-soft-deleted) rows must not be purged")
}

// 7. purgeExpired skips the entire sweep -- no table touched, no vault
// purged -- when the global soft_delete.purge_protection switch is on.
func TestPurgeExpired_SkipsAllWhenGlobalPurgeProtectionEnabled(t *testing.T) {
	rawDB := newTestDB(t)
	createPurgeTables(rawDB)

	expired := time.Now().AddDate(0, 0, -60).Format("2006-01-02 15:04:05")
	_, err := rawDB.Exec(
		`INSERT INTO secrets (id, deleted_at, purge_protection) VALUES (?, ?, FALSE)`,
		"expired-secret", expired,
	)
	require.NoError(t, err)

	deletedAt := time.Now().AddDate(0, 0, -60)
	vaults := &fakeVaultPurger{vaults: []model.Vault{
		{Name: "old-vault", DeletedAt: &deletedAt, RetentionDays: 30},
	}}

	conn := newTestConn(t, rawDB)
	cfg := testConfig()
	cfg.PurgeProtection = true
	s := NewPurgeScheduler(conn, cfg, testLogger(), vaults)
	s.Start(context.Background())
	time.Sleep(30 * time.Millisecond)
	s.Stop()

	var count int
	err = rawDB.QueryRow(`SELECT COUNT(*) FROM secrets WHERE id = 'expired-secret'`).Scan(&count)
	require.NoError(t, err)
	assert.Equal(t, 1, count, "expired secret must survive when the global switch is on")
	assert.Empty(t, vaults.purgedNames(), "no vault should be purged when the global switch is on")
}

// 8. A vault's own RetentionDays overrides the global retention_days.
func TestPurgeExpiredVaults_UsesPerVaultRetentionOverride(t *testing.T) {
	rawDB := newTestDB(t)
	createPurgeTables(rawDB)
	conn := newTestConn(t, rawDB)

	// 15 days ago: past this vault's own 10-day retention, but well within
	// the global 30-day default -- proves the per-vault value wins.
	deletedAt := time.Now().AddDate(0, 0, -15)
	vaults := &fakeVaultPurger{vaults: []model.Vault{
		{Name: "short-retention", DeletedAt: &deletedAt, RetentionDays: 10},
	}}

	s := NewPurgeScheduler(conn, testConfig(), testLogger(), vaults)
	s.Start(context.Background())
	time.Sleep(30 * time.Millisecond)
	s.Stop()

	assert.Equal(t, []string{"short-retention"}, vaults.purgedNames())
}

// 9. A vault with no RetentionDays override (zero value) falls back to the
// global soft_delete.retention_days.
func TestPurgeExpiredVaults_FallsBackToGlobalRetentionWhenUnset(t *testing.T) {
	rawDB := newTestDB(t)
	createPurgeTables(rawDB)
	conn := newTestConn(t, rawDB)

	expiredByGlobal := time.Now().AddDate(0, 0, -40) // past global 30-day retention
	notYetExpired := time.Now().AddDate(0, 0, -5)    // within global 30-day retention
	vaults := &fakeVaultPurger{vaults: []model.Vault{
		{Name: "expired-by-global", DeletedAt: &expiredByGlobal},
		{Name: "recent", DeletedAt: &notYetExpired},
	}}

	s := NewPurgeScheduler(conn, testConfig(), testLogger(), vaults)
	s.Start(context.Background())
	time.Sleep(30 * time.Millisecond)
	s.Stop()

	assert.Equal(t, []string{"expired-by-global"}, vaults.purgedNames())
}

// 10. A vault with purge_protection enabled is never auto-purged, however
// old its deleted_at is.
func TestPurgeExpiredVaults_SkipsProtectedVault(t *testing.T) {
	rawDB := newTestDB(t)
	createPurgeTables(rawDB)
	conn := newTestConn(t, rawDB)

	deletedAt := time.Now().AddDate(0, 0, -365)
	vaults := &fakeVaultPurger{vaults: []model.Vault{
		{Name: "protected", DeletedAt: &deletedAt, PurgeProtection: true},
	}}

	s := NewPurgeScheduler(conn, testConfig(), testLogger(), vaults)
	s.Start(context.Background())
	time.Sleep(30 * time.Millisecond)
	s.Stop()

	assert.Empty(t, vaults.purgedNames())
}

// 11. An active (non-deleted) vault is never auto-purged.
func TestPurgeExpiredVaults_SkipsActiveVault(t *testing.T) {
	rawDB := newTestDB(t)
	createPurgeTables(rawDB)
	conn := newTestConn(t, rawDB)

	vaults := &fakeVaultPurger{vaults: []model.Vault{
		{Name: "active"},
	}}

	s := NewPurgeScheduler(conn, testConfig(), testLogger(), vaults)
	s.Start(context.Background())
	time.Sleep(30 * time.Millisecond)
	s.Stop()

	assert.Empty(t, vaults.purgedNames())
}

// 12. A nil VaultPurger is a no-op -- secrets/keys/certificates are still
// swept normally.
func TestPurgeExpiredVaults_NilVaultPurger_NoOp(t *testing.T) {
	rawDB := newTestDB(t)
	createPurgeTables(rawDB)
	conn := newTestConn(t, rawDB)

	s := NewPurgeScheduler(conn, testConfig(), testLogger(), nil)
	assert.NotPanics(t, func() {
		s.Start(context.Background())
		time.Sleep(20 * time.Millisecond)
		s.Stop()
	})
}

// The retention sweep must delete archived versions with their certificate,
// because SQLite runs with foreign keys off and cascades do not fire.
func TestPurgeExpired_DeletesCertificateVersions(t *testing.T) {
	rawDB := newTestDB(t)
	createPurgeTables(rawDB)

	expired := time.Now().AddDate(0, 0, -60).Format("2006-01-02 15:04:05")
	recent := time.Now().AddDate(0, 0, -5).Format("2006-01-02 15:04:05")
	rows := []struct {
		id        string
		deletedAt any
		protected bool
	}{
		{"expired", expired, false},
		{"recent", recent, false},
		{"protected", expired, true},
		{"live", nil, false},
	}
	for _, r := range rows {
		_, err := rawDB.Exec(`INSERT INTO certificates (id, deleted_at, purge_protection) VALUES (?, ?, ?)`,
			r.id, r.deletedAt, r.protected)
		require.NoError(t, err)
		_, err = rawDB.Exec(`INSERT INTO certificate_versions (certificate_id, version) VALUES (?, 1)`, r.id)
		require.NoError(t, err)
	}

	s := NewPurgeScheduler(newTestConn(t, rawDB), testConfig(), testLogger(), nil)
	s.purgeExpired(context.Background())

	count := func(id string) int {
		var n int
		require.NoError(t, rawDB.QueryRow(
			`SELECT COUNT(*) FROM certificate_versions WHERE certificate_id = ?`, id).Scan(&n))
		return n
	}
	assert.Equal(t, 0, count("expired"), "expired certificate versions must be purged")
	assert.Equal(t, 1, count("recent"))
	assert.Equal(t, 1, count("protected"))
	assert.Equal(t, 1, count("live"))
}
