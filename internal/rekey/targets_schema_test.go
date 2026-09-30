package rekey

import (
	"database/sql"
	"strings"
	"testing"

	_ "github.com/mattn/go-sqlite3"
	"github.com/stretchr/testify/require"

	rvdb "rocketvault/internal/db"
	"rocketvault/internal/logging"
)

// TestTargets_MatchLiveSchema is the drift guard for Targets. Every target
// must name a real table and columns, and every "<singular>_versions" table
// whose parent is a target must itself be a target: archived version rows
// hold the same sealed material as their parent, and a missed one stays
// sealed under a retired master key.
func TestTargets_MatchLiveSchema(t *testing.T) {
	raw, err := sql.Open("sqlite3", ":memory:")
	require.NoError(t, err)
	raw.SetMaxOpenConns(1)
	defer raw.Close() //nolint:errcheck
	require.NoError(t, rvdb.NewRepository(logging.InitLogger()).SetupSchema(raw, rvdb.SQLite))

	columns := func(table string) map[string]bool {
		rows, err := raw.Query("SELECT name FROM pragma_table_info(?)", table)
		require.NoError(t, err)
		defer rows.Close() //nolint:errcheck
		out := map[string]bool{}
		for rows.Next() {
			var name string
			require.NoError(t, rows.Scan(&name))
			out[name] = true
		}
		require.NoError(t, rows.Err())
		return out
	}

	targeted := map[string]bool{}
	for _, target := range Targets() {
		cols := columns(target.Table)
		require.NotEmpty(t, cols, "target table %q does not exist", target.Table)
		require.True(t, cols[target.Column], "target %s has no column %s", target.Table, target.Column)
		for _, key := range target.KeyColumns {
			require.True(t, cols[key], "target %s has no key column %s", target.Table, key)
		}
		targeted[target.Table] = true
	}

	for table := range targeted {
		versions := strings.TrimSuffix(table, "s") + "_versions"
		if len(columns(versions)) > 0 {
			require.True(t, targeted[versions], "%s holds %s's archived material and must be a rekey target", versions, table)
		}
	}
}
