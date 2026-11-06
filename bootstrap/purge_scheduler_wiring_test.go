package bootstrap

import (
	"context"
	"database/sql"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"rocketvault/config"
	rvdb "rocketvault/internal/db"
	"rocketvault/internal/testutils"
)

// TestNewPurgeScheduler_UsesTheContainerAuditService pins the scheduler's
// audit wiring: with the container's audit service failing, an expired
// secret must survive the sweep. A scheduler built without it would purge.
func TestNewPurgeScheduler_UsesTheContainerAuditService(t *testing.T) {
	rawDB, err := sql.Open("sqlite3", ":memory:")
	require.NoError(t, err)
	defer rawDB.Close() //nolint:errcheck
	rawDB.SetMaxOpenConns(1)
	for _, table := range []string{"secrets", "keys", "certificates"} {
		_, err := rawDB.Exec(`CREATE TABLE ` + table + ` (id TEXT PRIMARY KEY, deleted_at DATETIME, purge_protection BOOLEAN DEFAULT FALSE)`)
		require.NoError(t, err)
	}
	_, err = rawDB.Exec(`CREATE TABLE certificate_versions (certificate_id TEXT NOT NULL, version INTEGER NOT NULL)`)
	require.NoError(t, err)
	_, err = rawDB.Exec(`INSERT INTO secrets (id, deleted_at, purge_protection) VALUES ('old', ?, FALSE)`,
		time.Now().AddDate(0, 0, -60).Format("2006-01-02 15:04:05"))
	require.NoError(t, err)

	audit := &testutils.MockAuditService{}
	audit.On("RecordCritical", mock.Anything, mock.Anything).Return(errors.New("audit down"))
	audit.On("RecordEvent", mock.Anything, mock.Anything).Return(nil)
	sc := &testutils.MockServiceContainer{}
	sc.On("GetAuditService").Return(audit)

	ps := newPurgeScheduler(rvdb.NewConn(rawDB, rvdb.SQLite), config.SoftDeleteConfig{RetentionDays: 30}, newTestLogger(), sc)
	ps.Start(context.Background())
	time.Sleep(50 * time.Millisecond)
	ps.Stop()

	var n int
	require.NoError(t, rawDB.QueryRow(`SELECT COUNT(*) FROM secrets`).Scan(&n))
	assert.Equal(t, 1, n, "the expired secret must stay while audit is down")
	audit.AssertCalled(t, "RecordCritical", mock.Anything, mock.Anything)
}
