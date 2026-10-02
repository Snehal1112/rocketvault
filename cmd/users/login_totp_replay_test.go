package users

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"rocketvault/common"
	rvdb "rocketvault/internal/db"
	"rocketvault/internal/logging"
	"rocketvault/internal/repositories"
	authServices "rocketvault/internal/services/auth"
	"rocketvault/model"
)

// The CLI password login goes through the same service as HTTP, so a code
// used once cannot be used again from the CLI. The replay fails with the
// same message as a wrong code.
func TestPerformPasswordLogin_ReplayedTOTPCode_Rejected(t *testing.T) {
	common.SessionBaseDir = t.TempDir()

	conn, err := sql.Open("sqlite3", ":memory:")
	require.NoError(t, err)
	conn.SetMaxOpenConns(1) // Each :memory: connection is its own database.
	t.Cleanup(func() { _ = conn.Close() })
	_, err = conn.ExecContext(context.Background(), `CREATE TABLE users (id TEXT PRIMARY KEY, totp_last_step BIGINT NOT NULL DEFAULT 0)`)
	require.NoError(t, err)

	hash, err := authServices.NewPasswordService().HashPassword("Correct-Horse-9")
	require.NoError(t, err)
	totp := authServices.NewTOTPService()
	key, err := totp.GenerateSecret("PasswordManager", "dora")
	require.NoError(t, err)
	user := model.User{ID: uuid.New(), Username: "dora", PasswordHash: hash, TOTPSecret: key.Secret(), Roles: []string{model.RoleUser}}
	_, err = conn.ExecContext(context.Background(), `INSERT INTO users (id) VALUES (?)`, user.ID.String())
	require.NoError(t, err)

	authSvc := authServices.NewAuthenticationService(authServices.AuthenticationConfig{
		UserRepository:     &cliLoginUserRepo{users: map[string]model.User{"dora": user}},
		SessionRepository:  &cliLoginSessionRepo{},
		PasswordService:    authServices.NewPasswordService(),
		TOTPService:        totp,
		JWTService:         &cliLoginJWT{},
		TOTPStepRepository: repositories.NewTOTPStepRepository(rvdb.NewConn(conn, rvdb.SQLite)),
		Logger:             logging.InitLogger(),
	})

	code, err := totp.GenerateCode(key.Secret(), time.Now())
	require.NoError(t, err)
	wrongCode := wrongCodeFor(t, key.Secret())

	// A wrong code first: it must not use up the current step.
	_, wrongCodeErr := performPasswordLogin(context.Background(), authSvc, "dora", "Correct-Horse-9", wrongCode)
	require.Error(t, wrongCodeErr)

	first, err := performPasswordLogin(context.Background(), authSvc, "dora", "Correct-Horse-9", code)
	require.NoError(t, err, "the first use of a code must succeed")
	require.NotNil(t, first)

	_, replayErr := performPasswordLogin(context.Background(), authSvc, "dora", "Correct-Horse-9", code)
	require.Error(t, replayErr, "a replayed code must be rejected")
	assert.Equal(t, wrongCodeErr.Error(), replayErr.Error())
}

// wrongCodeFor returns a six-digit code that matches none of the codes near
// now for secret, so it is wrong for every step a login checks.
func wrongCodeFor(t *testing.T, secret string) string {
	t.Helper()
	totp := authServices.NewTOTPService()
	now := time.Now()
	// The login accepts two steps either side of now. Two more steps of margin
	// cover a step boundary crossed while the test runs.
	window := make(map[string]bool)
	for offset := -4; offset <= 4; offset++ {
		code, err := totp.GenerateCode(secret, now.Add(time.Duration(offset)*30*time.Second))
		require.NoError(t, err)
		window[code] = true
	}
	for _, candidate := range []string{"000000", "111111", "222222", "333333", "444444", "555555", "666666", "777777", "888888", "999999"} {
		if !window[candidate] {
			return candidate
		}
	}
	t.Fatal("no wrong code found")
	return ""
}
