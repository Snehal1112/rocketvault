package users

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"rocketvault/cmd/testutils"
	"rocketvault/common"
	authServices "rocketvault/internal/services/auth"
)

func TestPerformPasswordLogin_Success_SavesSession(t *testing.T) {
	common.SessionBaseDir = t.TempDir()
	// jwt.expiry is a required production config value (see CLAUDE.md); the
	// test binary loads no config file, so set it explicitly to avoid a
	// zero-duration ExpiresAt racing against time.Now() in the assertion below.
	previousExpiry := viper.Get("jwt.expiry")
	viper.Set("jwt.expiry", time.Hour)
	t.Cleanup(func() { viper.Set("jwt.expiry", previousExpiry) })

	tc := testutils.NewTestContext(t)
	userID := uuid.New()
	tc.MockAuthService.On("AuthenticateUser", mock.Anything, "admin", "admin123", "123456").
		Return(&authServices.AuthenticationResult{
			Token: "access-tok", RefreshToken: "refresh-tok", UserID: userID, Username: "admin", Roles: []string{"admin"},
		}, nil)

	session, err := performPasswordLogin(context.Background(), tc.MockAuthService, "admin", "admin123", "123456")

	require.NoError(t, err)
	assert.Equal(t, "access-tok", session.Token)

	cached, err := common.LoadSession("admin")
	require.NoError(t, err)
	require.NotNil(t, cached)
	assert.Equal(t, "access-tok", cached.Token)
	assert.True(t, cached.ExpiresAt.After(time.Now()))
}

func TestPerformPasswordLogin_AuthFails_NoSessionSaved(t *testing.T) {
	common.SessionBaseDir = t.TempDir()
	tc := testutils.NewTestContext(t)
	tc.MockAuthService.On("AuthenticateUser", mock.Anything, "admin", "wrong", "123456").
		Return(nil, assert.AnError)

	_, err := performPasswordLogin(context.Background(), tc.MockAuthService, "admin", "wrong", "123456")

	assert.Error(t, err)
	cached, err := common.LoadSession("admin")
	require.NoError(t, err)
	assert.Nil(t, cached)
}

// TestInitUsersLogin_RegistersOIDCFlag verifies the --oidc flag was
// registered on loginCmd. It deliberately does NOT call InitUsersLogin
// itself: this package's TestMain (cmd/users/users_cmd_test.go) already
// calls InitUsersLogin(parent) once before any test runs (to exercise it
// for coverage), and loginCmd is a package-level singleton whose
// pflag.FlagSet panics ("flag redefined") if the same flag name is
// registered twice within one test binary. By the time this test runs,
// TestMain's call has already registered every flag on loginCmd, so this
// test can simply assert on the result instead of re-registering.
func TestInitUsersLogin_RegistersOIDCFlag(t *testing.T) {
	flag := loginCmd.Flags().Lookup("oidc")
	require.NotNil(t, flag)
	assert.Equal(t, "false", flag.DefValue)
}

// A throttled login surfaces the wait to the CLI user and caches nothing.
func TestPerformPasswordLogin_Throttled_SurfacesRetryHint(t *testing.T) {
	common.SessionBaseDir = t.TempDir()
	tc := testutils.NewTestContext(t)
	tc.MockAuthService.On("AuthenticateUser", mock.Anything, "admin", "wrong", "123456").
		Return(nil, &authServices.ThrottledError{RetryAfter: 90 * time.Second})

	_, err := performPasswordLogin(context.Background(), tc.MockAuthService, "admin", "wrong", "123456")

	require.Error(t, err)
	assert.ErrorIs(t, err, authServices.ErrLoginThrottled)
	assert.Equal(t, "too many failed login attempts; retry in 1m30s", err.Error())
	cached, loadErr := common.LoadSession("admin")
	require.NoError(t, loadErr)
	assert.Nil(t, cached)
}
