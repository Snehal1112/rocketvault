package rekey

import (
	"context"
	"database/sql"
	"testing"

	_ "github.com/mattn/go-sqlite3"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"rocketvault/common"
	rvdb "rocketvault/internal/db"
	"rocketvault/internal/logging"
)

// newTestDB creates a throwaway in-memory SQLite database with the five
// master-key-encrypted tables, reduced to just the columns rekey touches.
// MaxOpenConns(1) is required: every new connection to ":memory:" would
// otherwise get its own empty database.
func newTestDB(t *testing.T) *rvdb.Conn {
	t.Helper()

	raw, err := sql.Open("sqlite3", ":memory:")
	require.NoError(t, err)
	raw.SetMaxOpenConns(1)
	t.Cleanup(func() { raw.Close() }) //nolint:errcheck,gosec

	_, err = raw.ExecContext(context.Background(), `
		CREATE TABLE secrets (id TEXT PRIMARY KEY, value TEXT NOT NULL);
		CREATE TABLE secret_versions (id TEXT PRIMARY KEY, value TEXT NOT NULL);
		CREATE TABLE keys (id TEXT PRIMARY KEY, value TEXT NOT NULL);
		CREATE TABLE key_versions (
			key_id  TEXT NOT NULL,
			version INTEGER NOT NULL,
			value   TEXT NOT NULL,
			PRIMARY KEY (key_id, version)
		);
		CREATE TABLE certificates (id TEXT PRIMARY KEY, private_key TEXT NOT NULL);
		CREATE TABLE certificate_versions (
			certificate_id TEXT NOT NULL,
			version        INTEGER NOT NULL,
			private_key    TEXT NOT NULL,
			PRIMARY KEY (certificate_id, version)
		);
	`)
	require.NoError(t, err)

	return rvdb.NewConn(raw, rvdb.SQLite)
}

func testLogger() *logging.Logger {
	return &logging.Logger{Logger: logrus.New()}
}

// seal encrypts a plaintext under key, failing the test if that is not possible.
func seal(t *testing.T, plaintext string, key []byte) string {
	t.Helper()
	value, err := common.EncryptWithKey(plaintext, key)
	require.NoError(t, err)
	return value
}

// exec runs a statement against the test database.
func exec(t *testing.T, conn *rvdb.Conn, query string, args ...any) {
	t.Helper()
	_, err := conn.ExecContext(context.Background(), query, args...)
	require.NoError(t, err)
}

// readValue returns a single column value from the test database.
func readValue(t *testing.T, conn *rvdb.Conn, query string) string {
	t.Helper()
	var value string
	require.NoError(t, conn.QueryRowContext(context.Background(), query).Scan(&value))
	return value
}

// seedAllTargets inserts one row per target, sealed with key.
func seedAllTargets(t *testing.T, conn *rvdb.Conn, key []byte) {
	t.Helper()
	exec(t, conn, "INSERT INTO secrets (id, value) VALUES (?, ?)", "s1", seal(t, "secret-one", key))
	exec(t, conn, "INSERT INTO secret_versions (id, value) VALUES (?, ?)", "sv1", seal(t, "secret-one-v1", key))
	exec(t, conn, "INSERT INTO keys (id, value) VALUES (?, ?)", "k1", seal(t, "key-pem", key))
	exec(t, conn, "INSERT INTO key_versions (key_id, version, value) VALUES (?, ?, ?)", "k1", 1, seal(t, "key-pem-v1", key))
	exec(t, conn, "INSERT INTO certificates (id, private_key) VALUES (?, ?)", "c1", seal(t, "cert-pem", key))
	exec(t, conn, "INSERT INTO certificate_versions (certificate_id, version, private_key) VALUES (?, ?, ?)", "c1", 1, seal(t, "cert-pem-v1", key))
}

func TestRun_ReEncryptsEveryTarget(t *testing.T) {
	conn := newTestDB(t)
	oldKey, newKey := testKey(1), testKey(100)
	seedAllTargets(t, conn, oldKey)

	report, err := New(conn, testLogger()).Run(context.Background(), Options{OldKey: oldKey, NewKey: newKey})
	require.NoError(t, err)
	assert.Equal(t, 6, report.TotalReEncrypted())
	assert.Len(t, report.Targets, 6)

	for query, want := range map[string]string{
		"SELECT value FROM secrets WHERE id = 's1'":                                                "secret-one",
		"SELECT value FROM secret_versions WHERE id = 'sv1'":                                       "secret-one-v1",
		"SELECT value FROM keys WHERE id = 'k1'":                                                   "key-pem",
		"SELECT value FROM key_versions WHERE key_id = 'k1' AND version = 1":                       "key-pem-v1",
		"SELECT private_key FROM certificates WHERE id = 'c1'":                                     "cert-pem",
		"SELECT private_key FROM certificate_versions WHERE certificate_id = 'c1' AND version = 1": "cert-pem-v1",
	} {
		stored := readValue(t, conn, query)

		_, err := common.DecryptWithKey(stored, oldKey)
		assert.Error(t, err, "row should no longer open with the old key: %s", query)

		plaintext, err := common.DecryptWithKey(stored, newKey)
		require.NoError(t, err, "row should open with the new key: %s", query)
		assert.Equal(t, want, plaintext)
	}
}

func TestRun_DryRunReportsWithoutWriting(t *testing.T) {
	conn := newTestDB(t)
	oldKey, newKey := testKey(1), testKey(100)
	seedAllTargets(t, conn, oldKey)
	before := readValue(t, conn, "SELECT value FROM secrets WHERE id = 's1'")

	report, err := New(conn, testLogger()).Run(context.Background(), Options{
		OldKey: oldKey, NewKey: newKey, DryRun: true,
	})
	require.NoError(t, err)
	assert.True(t, report.DryRun)
	assert.Equal(t, 6, report.TotalReEncrypted())

	assert.Equal(t, before, readValue(t, conn, "SELECT value FROM secrets WHERE id = 's1'"),
		"dry run must not modify any row")
	_, err = common.DecryptWithKey(readValue(t, conn, "SELECT value FROM keys WHERE id = 'k1'"), oldKey)
	assert.NoError(t, err, "dry run must leave rows on the old key")
}

func TestRun_SecondRunIsANoOp(t *testing.T) {
	conn := newTestDB(t)
	oldKey, newKey := testKey(1), testKey(100)
	seedAllTargets(t, conn, oldKey)
	rekeyer := New(conn, testLogger())

	_, err := rekeyer.Run(context.Background(), Options{OldKey: oldKey, NewKey: newKey})
	require.NoError(t, err)
	afterFirst := readValue(t, conn, "SELECT value FROM secrets WHERE id = 's1'")

	report, err := rekeyer.Run(context.Background(), Options{OldKey: oldKey, NewKey: newKey})
	require.NoError(t, err)
	assert.Equal(t, 0, report.TotalReEncrypted())
	for _, target := range report.Targets {
		assert.Equal(t, target.Total, target.AlreadyNewKey, "table %s", target.Table)
	}
	assert.Equal(t, afterFirst, readValue(t, conn, "SELECT value FROM secrets WHERE id = 's1'"),
		"a second run must not rewrite already-migrated rows")
}

func TestRun_ResumesPartiallyMigratedTable(t *testing.T) {
	conn := newTestDB(t)
	oldKey, newKey := testKey(1), testKey(100)
	exec(t, conn, "INSERT INTO secrets (id, value) VALUES (?, ?)", "old", seal(t, "still-old", oldKey))
	exec(t, conn, "INSERT INTO secrets (id, value) VALUES (?, ?)", "new", seal(t, "already-new", newKey))

	report, err := New(conn, testLogger()).Run(context.Background(), Options{OldKey: oldKey, NewKey: newKey})
	require.NoError(t, err)

	secrets := report.Targets[0]
	require.Equal(t, "secrets", secrets.Table)
	assert.Equal(t, 2, secrets.Total)
	assert.Equal(t, 1, secrets.ReEncrypted)
	assert.Equal(t, 1, secrets.AlreadyNewKey)

	plaintext, err := common.DecryptWithKey(readValue(t, conn, "SELECT value FROM secrets WHERE id = 'old'"), newKey)
	require.NoError(t, err)
	assert.Equal(t, "still-old", plaintext)
}

func TestRun_SkipsPKCS11Rows(t *testing.T) {
	conn := newTestDB(t)
	oldKey, newKey := testKey(1), testKey(100)
	const handle = "pkcs11:6f1c0a3e-1c1a-4a5f-9a3e-2b0d5f8c1a77"
	exec(t, conn, "INSERT INTO keys (id, value) VALUES (?, ?)", "hsm", handle)
	exec(t, conn, "INSERT INTO keys (id, value) VALUES (?, ?)", "soft", seal(t, "key-pem", oldKey))

	report, err := New(conn, testLogger()).Run(context.Background(), Options{OldKey: oldKey, NewKey: newKey})
	require.NoError(t, err)

	var keysReport TargetReport
	for _, target := range report.Targets {
		if target.Table == "keys" {
			keysReport = target
		}
	}
	assert.Equal(t, 1, keysReport.SkippedExternal)
	assert.Equal(t, 1, keysReport.ReEncrypted)
	assert.Equal(t, handle, readValue(t, conn, "SELECT value FROM keys WHERE id = 'hsm'"))
}

func TestRun_WrongOldKeyAbortsWithoutWriting(t *testing.T) {
	conn := newTestDB(t)
	realKey, newKey := testKey(1), testKey(100)
	seedAllTargets(t, conn, realKey)
	before := readValue(t, conn, "SELECT value FROM secrets WHERE id = 's1'")

	_, err := New(conn, testLogger()).Run(context.Background(), Options{
		OldKey: testKey(200), NewKey: newKey,
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "secrets.value")

	assert.Equal(t, before, readValue(t, conn, "SELECT value FROM secrets WHERE id = 's1'"),
		"a failed classification must not write anything")
}

// The wrong-key test above cannot tell plan-then-apply apart from a
// write-as-you-go implementation: with a wholly wrong old key, no row ever
// classifies successfully, so an implementation that wrote each row as it
// classified it would pass it too. This one seeds a table where the failing
// row sits between two rows that WOULD classify successfully under the given
// key pair, so an interleaved implementation would already have resealed row
// "a" by the time row "b" aborts the run. Both survivors must be byte-identical.
func TestRun_AbortsWithZeroWritesEvenWhenEarlierRowsWouldClassifySuccessfully(t *testing.T) {
	conn := newTestDB(t)
	oldKey, newKey, unknownKey := testKey(1), testKey(100), testKey(50)
	exec(t, conn, "INSERT INTO secrets (id, value) VALUES (?, ?)", "a", seal(t, "value-a", oldKey))
	exec(t, conn, "INSERT INTO secrets (id, value) VALUES (?, ?)", "b", seal(t, "value-b", unknownKey))
	exec(t, conn, "INSERT INTO secrets (id, value) VALUES (?, ?)", "c", seal(t, "value-c", oldKey))
	beforeA := readValue(t, conn, "SELECT value FROM secrets WHERE id = 'a'")
	beforeC := readValue(t, conn, "SELECT value FROM secrets WHERE id = 'c'")

	_, err := New(conn, testLogger()).Run(context.Background(), Options{OldKey: oldKey, NewKey: newKey})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "secrets.value")

	assert.Equal(t, beforeA, readValue(t, conn, "SELECT value FROM secrets WHERE id = 'a'"),
		"the row before the failing one must not have been written")
	assert.Equal(t, beforeC, readValue(t, conn, "SELECT value FROM secrets WHERE id = 'c'"),
		"the row after the failing one must not have been written")

	// Still sealed with the old key, so the whole table is left resumable.
	for _, id := range []string{"a", "c"} {
		plaintext, err := common.DecryptWithKey(readValue(t, conn, "SELECT value FROM secrets WHERE id = '"+id+"'"), oldKey)
		require.NoError(t, err, "row %s must still open with the old key", id)
		assert.Equal(t, "value-"+id, plaintext)
	}
}

func TestRun_RejectsIdenticalKeys(t *testing.T) {
	conn := newTestDB(t)
	key := testKey(1)

	_, err := New(conn, testLogger()).Run(context.Background(), Options{OldKey: key, NewKey: key})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "identical")
}

func TestRun_RejectsWrongKeyLength(t *testing.T) {
	conn := newTestDB(t)

	_, err := New(conn, testLogger()).Run(context.Background(), Options{
		OldKey: []byte("short"), NewKey: testKey(100),
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "32")
}

// A row rewritten between the plan and the apply phase must abort the batch
// and leave the rows updated earlier in the same transaction untouched. The
// guard is the whole reason the UPDATE carries "AND <column> = <old value>",
// so it is tested directly: Run alone can never reach this path, because
// nothing writes to the database between its two phases.
func TestApplyBatch_ConcurrentChangeRollsBackWholeBatch(t *testing.T) {
	conn := newTestDB(t)
	oldKey, newKey := testKey(1), testKey(100)
	for _, id := range []string{"a", "b"} {
		exec(t, conn, "INSERT INTO secrets (id, value) VALUES (?, ?)", id, seal(t, "value-"+id, oldKey))
	}

	rekeyer := New(conn, testLogger())
	target := Targets()[0]
	pending, _, err := rekeyer.planTarget(context.Background(), target,
		Options{OldKey: oldKey, NewKey: newKey})
	require.NoError(t, err)
	require.Len(t, pending, 2)

	// Simulate a still-running server rewriting the row the batch would touch
	// last, so the rows before it are already updated inside the transaction
	// when the abort happens.
	changed := pending[len(pending)-1].keys[0].(string)
	survivor := pending[0].keys[0].(string)
	require.NotEqual(t, changed, survivor)
	exec(t, conn, "UPDATE secrets SET value = ? WHERE id = ?", seal(t, "written-by-the-server", oldKey), changed)

	err = rekeyer.applyBatch(context.Background(), target.UpdateSQL(), pending)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "changed while the rotation was running")

	// The earlier row of the same transaction must be rolled back, not committed.
	plaintext, err := common.DecryptWithKey(readValue(t, conn, "SELECT value FROM secrets WHERE id = '"+survivor+"'"), oldKey)
	require.NoError(t, err, "the batch must roll back, leaving earlier rows on the old key")
	assert.Equal(t, "value-"+survivor, plaintext)
}

// The other way applyBatch can bail out mid-transaction is tx.ExecContext
// itself failing, which must roll back the whole batch rather than leave the
// rows updated before it committed. A UNIQUE column gives a value-dependent
// failure, so the first update of the batch succeeds and only the second one
// errors — which is what makes the surviving row's state meaningful.
func TestApplyBatch_ExecErrorRollsBackWholeBatch(t *testing.T) {
	conn := newTestDB(t)
	oldKey, newKey := testKey(1), testKey(100)
	exec(t, conn, "CREATE TABLE unique_secrets (id TEXT PRIMARY KEY, value TEXT NOT NULL UNIQUE)")

	first, second := seal(t, "value-a", oldKey), seal(t, "value-b", oldKey)
	taken := seal(t, "value-taken", newKey)
	exec(t, conn, "INSERT INTO unique_secrets (id, value) VALUES (?, ?)", "a", first)
	exec(t, conn, "INSERT INTO unique_secrets (id, value) VALUES (?, ?)", "b", second)
	exec(t, conn, "INSERT INTO unique_secrets (id, value) VALUES (?, ?)", "taken", taken)

	target := Target{Table: "unique_secrets", Column: "value", KeyColumns: []string{"id"}}
	batch := []pendingUpdate{
		{keys: []any{"a"}, oldValue: first, newValue: seal(t, "value-a", newKey)},
		// Collides with the value the "taken" row already holds, so the
		// statement itself fails instead of matching zero rows.
		{keys: []any{"b"}, oldValue: second, newValue: taken},
	}

	err := New(conn, testLogger()).applyBatch(context.Background(), target.UpdateSQL(), batch)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "update row")

	assert.Equal(t, first, readValue(t, conn, "SELECT value FROM unique_secrets WHERE id = 'a'"),
		"a failed statement must roll back the rows updated earlier in the same batch")
	assert.Equal(t, second, readValue(t, conn, "SELECT value FROM unique_secrets WHERE id = 'b'"))
}

func TestRun_BatchSizeSmallerThanRowCount(t *testing.T) {
	conn := newTestDB(t)
	oldKey, newKey := testKey(1), testKey(100)
	for _, id := range []string{"a", "b", "c", "d", "e"} {
		exec(t, conn, "INSERT INTO secrets (id, value) VALUES (?, ?)", id, seal(t, "value-"+id, oldKey))
	}

	report, err := New(conn, testLogger()).Run(context.Background(), Options{
		OldKey: oldKey, NewKey: newKey, BatchSize: 2,
	})
	require.NoError(t, err)
	assert.Equal(t, 5, report.TotalReEncrypted())

	for _, id := range []string{"a", "b", "c", "d", "e"} {
		stored := readValue(t, conn, "SELECT value FROM secrets WHERE id = '"+id+"'")
		plaintext, err := common.DecryptWithKey(stored, newKey)
		require.NoError(t, err)
		assert.Equal(t, "value-"+id, plaintext)
	}
}
