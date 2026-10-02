package db

import (
	"context"
	"database/sql"
	"testing"

	_ "github.com/mattn/go-sqlite3"
	"github.com/stretchr/testify/require"

	"rocketvault/internal/logging"
)

// A fresh install must create totp_last_step in the users CREATE TABLE itself.
func TestUsersTOTPLastStep_CreatedOnFreshInstall(t *testing.T) {
	conn, err := sql.Open("sqlite3", ":memory:")
	require.NoError(t, err)
	defer conn.Close() //nolint:errcheck

	d := &DBRepository{dialect: SQLite}
	d.log = &logging.Logger{Logger: newSilentLogrus()}
	require.NoError(t, d.createOptimizedSchema(conn))

	require.True(t, columnExists(t, conn, "users", "totp_last_step"),
		"createOptimizedSchema must create users.totp_last_step")

	_, err = conn.ExecContext(context.Background(), `INSERT INTO users (id, username, password_hash, role) VALUES ('u1', 'alice', 'h', 'admin')`)
	require.NoError(t, err)
	var step int64
	require.NoError(t, conn.QueryRowContext(context.Background(), `SELECT totp_last_step FROM users WHERE id = 'u1'`).Scan(&step))
	require.Equal(t, int64(0), step)
}
