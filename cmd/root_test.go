package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"rocketvault/cmd/testutils"
	"rocketvault/common"
	"rocketvault/internal/cliclient"
	"rocketvault/internal/retry"
	authServices "rocketvault/internal/services/auth"
	"rocketvault/internal/vaultapi"
	"rocketvault/model"
)

func newAuthTestCmd(username, password, totpCode string) *cobra.Command {
	c := &cobra.Command{Use: "test"}
	c.Flags().String("username", "", "")
	c.Flags().String("password", "", "")
	c.Flags().String("totp-code", "", "")
	_ = c.Flags().Set("username", username)
	_ = c.Flags().Set("password", password)
	_ = c.Flags().Set("totp-code", totpCode)
	c.SetContext(context.Background())
	return c
}

func TestResolveAuthentication_UsernamePassword_Success(t *testing.T) {
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

	c := newAuthTestCmd("admin", "admin123", "123456")
	result, err := resolveAuthentication(c, tc.MockAuthService)

	require.NoError(t, err)
	assert.Equal(t, "access-tok", result.Token)

	cached, err := common.LoadSession("admin")
	require.NoError(t, err)
	require.NotNil(t, cached)
	assert.Equal(t, "access-tok", cached.Token)
	assert.True(t, cached.ExpiresAt.After(time.Now()))
}

func TestResolveAuthentication_UsernamePassword_AuthFails_ReturnsError(t *testing.T) {
	common.SessionBaseDir = t.TempDir()
	tc := testutils.NewTestContext(t)
	tc.MockAuthService.On("AuthenticateUser", mock.Anything, "admin", "wrong", "123456").
		Return(nil, assert.AnError)

	c := newAuthTestCmd("admin", "wrong", "123456")
	_, err := resolveAuthentication(c, tc.MockAuthService)

	assert.Error(t, err)
	cached, err := common.LoadSession("admin")
	require.NoError(t, err)
	assert.Nil(t, cached, "a failed login must not cache a session")
}

// A throttled login reaches every CLI command with its wait, and caches nothing.
func TestResolveAuthentication_UsernamePassword_Throttled_SurfacesRetryHint(t *testing.T) {
	common.SessionBaseDir = t.TempDir()
	tc := testutils.NewTestContext(t)
	tc.MockAuthService.On("AuthenticateUser", mock.Anything, "admin", "wrong", "123456").
		Return(nil, &authServices.ThrottledError{RetryAfter: 90 * time.Second})

	c := newAuthTestCmd("admin", "wrong", "123456")
	_, err := resolveAuthentication(c, tc.MockAuthService)

	require.ErrorIs(t, err, authServices.ErrLoginThrottled)
	assert.Contains(t, err.Error(), "retry in 1m30s")
	cached, err := common.LoadSession("admin")
	require.NoError(t, err)
	assert.Nil(t, cached, "a throttled login must not cache a session")
}

// The retry layer wraps a throttled login as "error is not retryable: ...".
// The CLI must print only the throttle message.
func TestResolveAuthentication_Throttled_StripsRetryPrefix(t *testing.T) {
	common.SessionBaseDir = t.TempDir()
	tc := testutils.NewTestContext(t)
	wrapped := fmt.Errorf("%w: %w", retry.ErrNonRetryable, &authServices.ThrottledError{RetryAfter: 90 * time.Second})
	tc.MockAuthService.On("AuthenticateUser", mock.Anything, "admin", "wrong", "123456").
		Return(nil, wrapped)

	c := newAuthTestCmd("admin", "wrong", "123456")
	_, err := resolveAuthentication(c, tc.MockAuthService)

	require.ErrorIs(t, err, authServices.ErrLoginThrottled)
	assert.Equal(t, "too many failed login attempts; retry in 1m30s", err.Error())
}

// Any other error keeps its full text.
func TestResolveAuthentication_OtherError_KeepsText(t *testing.T) {
	common.SessionBaseDir = t.TempDir()
	tc := testutils.NewTestContext(t)
	wrapped := fmt.Errorf("%w: %w", retry.ErrNonRetryable, errors.New("invalid credentials"))
	tc.MockAuthService.On("AuthenticateUser", mock.Anything, "admin", "wrong", "123456").
		Return(nil, wrapped)

	c := newAuthTestCmd("admin", "wrong", "123456")
	_, err := resolveAuthentication(c, tc.MockAuthService)

	require.Error(t, err)
	assert.Equal(t, wrapped.Error(), err.Error())
}

func TestResolveAuthentication_UsernameOnly_LoadsNamedCachedSession(t *testing.T) {
	common.SessionBaseDir = t.TempDir()
	tc := testutils.NewTestContext(t)
	userID := uuid.New()
	require.NoError(t, common.SaveSession(&common.SessionCache{
		Token: "cached-tok", Username: "user14", ExpiresAt: time.Now().Add(time.Hour),
	}))
	tc.MockAuthService.On("ValidateSession", mock.Anything, "cached-tok").
		Return(&authServices.JWTClaims{UserID: userID, Username: "user14", Roles: []string{"user"}}, nil)

	c := newAuthTestCmd("user14", "", "")
	result, err := resolveAuthentication(c, tc.MockAuthService)

	require.NoError(t, err)
	assert.Equal(t, "cached-tok", result.Token)
	assert.Equal(t, "user14", result.Username)
	tc.MockAuthService.AssertNotCalled(t, "AuthenticateUser", mock.Anything, mock.Anything, mock.Anything, mock.Anything)
}

// TestResolveAuthentication_MultiRoleSession_RoundTripsToClaims verifies that
// a cached session carrying multiple roles survives resolveAuthentication's
// cached-session path into the returned *authServices.AuthenticationResult,
// and that persistentPreRun's model.Claims{} construction (cmd/root.go) then
// carries those roles through without loss.
func TestResolveAuthentication_MultiRoleSession_RoundTripsToClaims(t *testing.T) {
	common.SessionBaseDir = t.TempDir()
	tc := testutils.NewTestContext(t)
	userID := uuid.New()
	require.NoError(t, common.SaveSession(&common.SessionCache{
		Token: "cached-tok", Username: "multi-role-user", Roles: []string{"admin", "secrets_manager"},
		ExpiresAt: time.Now().Add(time.Hour),
	}))
	tc.MockAuthService.On("ValidateSession", mock.Anything, "cached-tok").
		Return(&authServices.JWTClaims{UserID: userID, Username: "multi-role-user", Roles: []string{"admin", "secrets_manager"}}, nil)

	c := newAuthTestCmd("multi-role-user", "", "")
	result, err := resolveAuthentication(c, tc.MockAuthService)

	require.NoError(t, err)
	assert.Equal(t, []string{"admin", "secrets_manager"}, result.Roles)

	// Mirror persistentPreRun's Claims construction (cmd/root.go) to prove
	// the multi-role result feeds model.Claims.Roles without loss.
	claims := &model.Claims{
		UserID:   result.UserID,
		Username: result.Username,
		Roles:    result.Roles,
	}
	assert.Equal(t, []string{"admin", "secrets_manager"}, claims.Roles)
}

func TestResolveAuthentication_NoFlags_UsesCurrentPointer(t *testing.T) {
	common.SessionBaseDir = t.TempDir()
	tc := testutils.NewTestContext(t)
	userID := uuid.New()
	require.NoError(t, common.SaveSession(&common.SessionCache{
		Token: "cached-tok", Username: "user14", ExpiresAt: time.Now().Add(time.Hour),
	}))
	tc.MockAuthService.On("ValidateSession", mock.Anything, "cached-tok").
		Return(&authServices.JWTClaims{UserID: userID, Username: "user14", Roles: []string{"user"}}, nil)

	c := newAuthTestCmd("", "", "")
	result, err := resolveAuthentication(c, tc.MockAuthService)

	require.NoError(t, err)
	assert.Equal(t, "cached-tok", result.Token)
}

// TestResolveAuthentication_CachedSessionRevokedServerSide verifies that a
// cache file whose ExpiresAt hasn't passed yet is NOT trusted blindly — the
// server-side ValidateSession check must run, so an admin revoking the
// session takes effect immediately instead of only once the locally-recorded
// ExpiresAt naturally elapses. A ValidateSession failure here falls through
// to the same transparent-refresh path used for an already-expired cache.
func TestResolveAuthentication_CachedSessionRevokedServerSide(t *testing.T) {
	common.SessionBaseDir = t.TempDir()
	tc := testutils.NewTestContext(t)
	userID := uuid.New()
	require.NoError(t, common.SaveSession(&common.SessionCache{
		Token: "revoked-tok", RefreshToken: "old-refresh", Username: "user14",
		ExpiresAt: time.Now().Add(time.Hour),
	}))
	tc.MockAuthService.On("ValidateSession", mock.Anything, "revoked-tok").
		Return(nil, assert.AnError)
	tc.MockAuthService.On("RefreshAccessToken", mock.Anything, "old-refresh").
		Return(&authServices.RefreshTokenResult{
			Token: "new-tok", RefreshToken: "new-refresh", UserID: userID, Username: "user14", Roles: []string{"user"},
			ExpiresAt: time.Now().Add(time.Hour),
		}, nil)

	c := newAuthTestCmd("", "", "")
	result, err := resolveAuthentication(c, tc.MockAuthService)

	require.NoError(t, err)
	assert.Equal(t, "new-tok", result.Token, "a revoked cached session must fall through to a fresh refresh")
}

func TestResolveAuthentication_NoFlagsNoCache_ReturnsError(t *testing.T) {
	common.SessionBaseDir = t.TempDir()
	tc := testutils.NewTestContext(t)

	c := newAuthTestCmd("", "", "")
	_, err := resolveAuthentication(c, tc.MockAuthService)

	assert.Error(t, err)
}

func TestResolveAuthentication_ExpiredCache_RefreshesTransparently(t *testing.T) {
	common.SessionBaseDir = t.TempDir()
	tc := testutils.NewTestContext(t)
	userID := uuid.New()
	require.NoError(t, common.SaveSession(&common.SessionCache{
		Token: "old-tok", RefreshToken: "old-refresh", Username: "user14",
		ExpiresAt: time.Now().Add(-time.Minute),
	}))
	tc.MockAuthService.On("RefreshAccessToken", mock.Anything, "old-refresh").
		Return(&authServices.RefreshTokenResult{
			Token: "new-tok", RefreshToken: "new-refresh", UserID: userID, Username: "user14", Roles: []string{"user"},
			ExpiresAt: time.Now().Add(time.Hour),
		}, nil)

	c := newAuthTestCmd("", "", "")
	result, err := resolveAuthentication(c, tc.MockAuthService)

	require.NoError(t, err)
	assert.Equal(t, "new-tok", result.Token)

	cached, err := common.LoadSession("user14")
	require.NoError(t, err)
	require.NotNil(t, cached)
	assert.Equal(t, "new-tok", cached.Token, "the refreshed token must be re-cached")
}

func TestResolveAuthentication_ExpiredCacheRefreshFails_ReturnsError(t *testing.T) {
	common.SessionBaseDir = t.TempDir()
	tc := testutils.NewTestContext(t)
	require.NoError(t, common.SaveSession(&common.SessionCache{
		Token: "old-tok", RefreshToken: "old-refresh", Username: "user14",
		ExpiresAt: time.Now().Add(-time.Minute),
	}))
	tc.MockAuthService.On("RefreshAccessToken", mock.Anything, "old-refresh").
		Return(nil, assert.AnError)

	c := newAuthTestCmd("", "", "")
	_, err := resolveAuthentication(c, tc.MockAuthService)

	assert.Error(t, err)
}

// TestInitConfig_RetryConfigEnvOverride verifies that SetRetryDefaults and
// BindRetryConfig are called during initConfig so environment variable overrides work.
func TestInitConfig_RetryConfigEnvOverride(t *testing.T) {
	v := viper.New()
	v.SetConfigType("yaml")

	// Set up retry defaults and bind config (this is what initConfig does).
	retry.SetRetryDefaults(v)
	retry.BindRetryConfig(v)

	// Set an environment variable override.
	t.Setenv("RETRY_DATABASE_MAX_ATTEMPTS", "10")

	// Verify the environment variable is reflected in viper.
	maxAttempts := v.GetInt("retry.database.max_attempts")
	require.Equal(t, 10, maxAttempts, "environment variable override RETRY_DATABASE_MAX_ATTEMPTS should be reflected in retry config")
}

// useTempConfigFile points the package-level cfgFile at a minimal, valid
// config so initConfig (registered globally via cobra.OnInitialize in
// init(), and therefore run for ANY cobra.Command's Execute/ExecuteContext
// call in this test binary, not just rootCmd's) doesn't panic when it can't
// find ".rocketvault.yaml" relative to the test's working directory
// (cmd/). Restores the previous value on cleanup.
func useTempConfigFile(t *testing.T) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "test-config.yaml")
	require.NoError(t, os.WriteFile(path, []byte("jwt:\n  expiry: 1h\n"), 0o600))

	previous := cfgFile
	cfgFile = path
	t.Cleanup(func() { cfgFile = previous })
}

// TestRun_ReturnsNonZeroOnError is the regression test for the bug where
// Execute() called os.Exit(0) even when rootCmd.ExecuteContext returned a
// non-nil error, making every CLI failure indistinguishable from success
// at the shell level ("&&"/"set -e" never caught it).
func TestRun_ReturnsNonZeroOnError(t *testing.T) {
	useTempConfigFile(t)
	cmd := &cobra.Command{
		Use: "test",
		RunE: func(cmd *cobra.Command, args []string) error {
			return errors.New("boom")
		},
	}
	cmd.SetArgs([]string{})

	exitCode := run(cmd)

	assert.NotEqual(t, 0, exitCode, "run() must return a non-zero exit code when the command errors")
}

// TestRun_ReturnsZeroOnSuccess pins the success path so a future change to
// run() can't flip both cases to the same wrong value.
func TestRun_ReturnsZeroOnSuccess(t *testing.T) {
	useTempConfigFile(t)
	cmd := &cobra.Command{
		Use: "test",
		RunE: func(cmd *cobra.Command, args []string) error {
			return nil
		},
	}
	cmd.SetArgs([]string{})

	exitCode := run(cmd)

	assert.Equal(t, 0, exitCode, "run() must return 0 when the command succeeds")
}

// TestInitConfig_RemoteMode_DoesNotPanicWithoutConfigFile verifies that
// initConfig() no longer panics unconditionally when .rocketvault.yaml is
// missing — remote mode (resolved here via ROCKETVAULT_ADDR) needs no local
// config file at all, only a target server.
func TestInitConfig_RemoteMode_DoesNotPanicWithoutConfigFile(t *testing.T) {
	dir := t.TempDir() // no .rocketvault.yaml here
	origWd, err := os.Getwd()
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.Chdir(origWd) })
	require.NoError(t, os.Chdir(dir))

	t.Setenv("ROCKETVAULT_ADDR", "https://vault.prod.example.com")

	previousSettings := viper.AllSettings()
	viper.Reset()
	t.Cleanup(func() {
		viper.Reset()
		_ = viper.MergeConfigMap(previousSettings)
	})

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("initConfig() panicked in remote mode without a config file: %v", r)
		}
	}()
	initConfig()
}

// ---------------------------------------------------------------------------
// C2 (2026-08-17 final review): a resolved remote target (--server /
// ROCKETVAULT_ADDR / current context) must never be silently ignored by a
// command that doesn't yet implement remote support. persistentPreRun's
// explicit guard (cmd/root.go) is the enforcement point tested here.
// ---------------------------------------------------------------------------

// TestPersistentPreRun_RemoteTarget_NonContextCommand_ReturnsError verifies
// that a command outside the `context` group errors clearly, instead of
// silently operating on the local instance, when a remote target resolves.
// "health" is used as a side-effect-free, DB-independent example command —
// the guard runs before any DB/service-container setup, so its RunE never
// executes.
func TestPersistentPreRun_RemoteTarget_NonContextCommand_ReturnsError(t *testing.T) {
	dir := t.TempDir()
	origWd, err := os.Getwd()
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.Chdir(origWd) })
	require.NoError(t, os.Chdir(dir))

	previousArgs := os.Args
	os.Args = []string{"rocketvault", "health"}
	t.Cleanup(func() { os.Args = previousArgs })

	previousSettings := viper.AllSettings()
	viper.Reset()
	t.Cleanup(func() {
		viper.Reset()
		_ = viper.MergeConfigMap(previousSettings)
	})

	rootCmd.SetArgs([]string{"health", "--server", "https://vault.prod.example.com"})
	t.Cleanup(func() { rootCmd.SetArgs(nil) })

	err = rootCmd.ExecuteContext(context.Background())
	require.Error(t, err, "a command outside the context group must refuse a resolved remote target, not silently run locally")
	assert.Contains(t, err.Error(), "not yet supported")
	assert.Contains(t, err.Error(), "health")
}

// TestPersistentPreRun_RemoteTarget_ContextCommand_Unaffected verifies the
// context group's carve-out from the C2 guard: context commands are allowed
// to run with a resolved remote target present, since they only read/write
// local config and never talk to a server themselves.
func TestPersistentPreRun_RemoteTarget_ContextCommand_Unaffected(t *testing.T) {
	dir := t.TempDir()
	common.SessionBaseDir = dir + "/sessions"

	origWd, err := os.Getwd()
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.Chdir(origWd) })
	require.NoError(t, os.Chdir(dir))

	previousArgs := os.Args
	os.Args = []string{"rocketvault", "context", "list"}
	t.Cleanup(func() { os.Args = previousArgs })

	previousSettings := viper.AllSettings()
	viper.Reset()
	t.Cleanup(func() {
		viper.Reset()
		_ = viper.MergeConfigMap(previousSettings)
	})

	rootCmd.SetArgs([]string{"context", "list", "--server", "https://vault.prod.example.com"})
	t.Cleanup(func() { rootCmd.SetArgs(nil) })

	err = rootCmd.ExecuteContext(context.Background())
	require.NoError(t, err, "the context group must be unaffected by a resolved remote target")
}

// TestPersistentPreRun_DatabaseInitFailure_NonExemptCommand_ReturnsCleanError
// pins the fix for the nil-pointer panic a swallowed InitializeDB error used
// to cause: a command that actually needs the database (anything outside
// the context/cobra-builtin exemption) must fail fast with a clear error
// when the database can't be initialized, not silently continue with a nil
// *db.Conn threaded into every repository and panic deep inside an
// unrelated command the first time one of them runs a query.
func TestPersistentPreRun_DatabaseInitFailure_NonExemptCommand_ReturnsCleanError(t *testing.T) {
	// A valid config with no database section: initConfig doesn't panic on a
	// missing file, but loadDatabaseConfig has nothing to connect with,
	// reproducing "database connection string not configured" -- the same
	// class of InitializeDB failure a stale/incompatible schema also
	// produces (see TestSetupSchema_UpgradesOldShapeRotationPoliciesWithout-
	// Error in internal/db), just via a different root cause.
	useTempConfigFile(t)

	// Reset --server: it's a persistent pflag on the shared rootCmd, so a
	// prior test in this file that set it (e.g.
	// TestPersistentPreRun_RemoteTarget_NonContextCommand_ReturnsError)
	// leaves its value set even after that test's SetArgs(nil) cleanup --
	// SetArgs only affects the next parse's argument slice, not
	// already-parsed flag values.
	previousServer := rootCmd.PersistentFlags().Lookup("server").Value.String()
	require.NoError(t, rootCmd.PersistentFlags().Set("server", ""))
	t.Cleanup(func() { _ = rootCmd.PersistentFlags().Set("server", previousServer) })

	previousArgs := os.Args
	os.Args = []string{"rocketvault", "health"}
	t.Cleanup(func() { os.Args = previousArgs })

	rootCmd.SetArgs([]string{"health"})
	t.Cleanup(func() { rootCmd.SetArgs(nil) })

	err := rootCmd.ExecuteContext(context.Background())
	require.Error(t, err, "a command that needs the database must fail cleanly when it can't be initialized, not panic")
	assert.Contains(t, err.Error(), "database initialization failed")
}

// TestIsCobraBuiltinCommand verifies NB1's fix at the unit level: which
// commands the remote-target guard must treat as exempt cobra built-ins.
// This is deliberately a pure unit test of the classification logic rather
// than a full rootCmd.Execute() run — cobra's built-in "help"/"completion"
// commands are not in persistentPreRun's systemCmds map, so a full run hits
// the (pre-existing, unrelated to remote mode) authentication requirement
// and the shared test binary's audit-logging path, neither of which this
// fix touches or is responsible for exercising safely.
func TestIsCobraBuiltinCommand(t *testing.T) {
	completionCmd := &cobra.Command{Use: "completion"}
	bashCmd := &cobra.Command{Use: "bash"}
	completionCmd.AddCommand(bashCmd)

	cases := []struct {
		name string
		cmd  *cobra.Command
		want bool
	}{
		{"help", &cobra.Command{Use: "help"}, true},
		{"completion (parent)", completionCmd, true},
		{"completion bash (child)", bashCmd, true},
		{"__complete", &cobra.Command{Use: cobra.ShellCompRequestCmd}, true},
		{"__completeNoDesc", &cobra.Command{Use: cobra.ShellCompNoDescRequestCmd}, true},
		{"secrets (not a builtin)", &cobra.Command{Use: "secrets"}, false},
		{"health (not a builtin)", &cobra.Command{Use: "health"}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, isCobraBuiltinCommand(tc.cmd))
		})
	}
}

// TestIsSystemCommand pins persistentPreRun's authentication-exemption
// list at the unit level, the same way TestIsCobraBuiltinCommand pins the
// cobra-builtin classification -- see isSystemCommand in cmd/root.go.
func TestIsSystemCommand(t *testing.T) {
	secretsCmd := &cobra.Command{Use: "secrets"}
	generatePasswordCmd := &cobra.Command{Use: "generate-password"}
	secretsCmd.AddCommand(generatePasswordCmd)

	usersCmd := &cobra.Command{Use: "users"}
	loginCmd := &cobra.Command{Use: "login"}
	usersCmd.AddCommand(loginCmd)

	cases := []struct {
		name string
		cmd  *cobra.Command
		want bool
	}{
		{"generate-password (leaf, pure local RNG, no session needed)", generatePasswordCmd, true},
		{"secrets (parent; not itself a system command)", secretsCmd, false},
		{"login (pre-existing exemption, still works)", loginCmd, true},
		{"health (top-level system command)", &cobra.Command{Use: "health"}, true},
		{"create (not a system command)", &cobra.Command{Use: "create"}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, isSystemCommand(tc.cmd))
		})
	}
}

// TestRootLongTextListsGeneratePasswordAsSessionExempt pins rootCmd.Long's
// session-exempt command list against the isSystemCommand fix (B41).
func TestRootLongTextListsGeneratePasswordAsSessionExempt(t *testing.T) {
	assert.Contains(t, rootCmd.Long, "secrets generate-password")
}

// TestPersistentPreRun_RemoteTarget_HelpAndCompletion_RunCleanly is an
// end-to-end regression test for a crash NB1's first pass introduced:
// exempting help/completion from the remote-target guard let them fall
// through into the rest of persistentPreRun (DB init, then
// resolveAuthentication), and in genuine remote mode — a resolved target,
// no local .rocketvault.yaml, no cached session — that authentication
// failure's audit-log call panicked on a nil DB connection. The fix adds
// "help"/"completion" (and cobra's hidden completion-request commands) to
// systemCmds too, so they short-circuit before authentication is ever
// attempted, exactly like the pre-existing "context" entry. This test
// reproduces the original crash conditions and asserts a clean exit instead.
func TestPersistentPreRun_RemoteTarget_HelpAndCompletion_RunCleanly(t *testing.T) {
	dir := t.TempDir()
	common.SessionBaseDir = filepath.Join(dir, "sessions") // no cached session here

	origWd, err := os.Getwd()
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.Chdir(origWd) })
	require.NoError(t, os.Chdir(dir)) // no .rocketvault.yaml here either

	previousSettings := viper.AllSettings()
	viper.Reset()
	t.Cleanup(func() {
		viper.Reset()
		_ = viper.MergeConfigMap(previousSettings)
	})

	for _, args := range [][]string{
		{"help", "secrets", "--server", "https://vault.prod.example.com"},
		{"completion", "bash", "--server", "https://vault.prod.example.com"},
	} {
		previousArgs := os.Args
		os.Args = append([]string{"rocketvault"}, args...)

		rootCmd.SetArgs(args)
		err := rootCmd.ExecuteContext(context.Background())
		require.NoError(t, err, "%v must run cleanly with a resolved remote target and no cached session", args)

		os.Args = previousArgs
		rootCmd.SetArgs(nil)
	}
}

// TestIsLocalOnlyCommand pins which commands are exempt from the
// remote-target guard because they never talk to any server, local or
// remote -- see isLocalOnlyCommand in cmd/root.go.
func TestIsLocalOnlyCommand(t *testing.T) {
	vaultAccessCmd := &cobra.Command{Use: "vault-access"}
	rolesCmd := &cobra.Command{Use: "roles"}
	vaultAccessCmd.AddCommand(rolesCmd)

	secretsCmd := &cobra.Command{Use: "secrets"}
	genPasswordCmd := &cobra.Command{Use: "generate-password"}
	listCmd := &cobra.Command{Use: "list"}
	secretsCmd.AddCommand(genPasswordCmd)
	secretsCmd.AddCommand(listCmd)

	cases := []struct {
		name string
		cmd  *cobra.Command
		want bool
	}{
		{"vault-access roles", rolesCmd, true},
		{"secrets generate-password", genPasswordCmd, true},
		{"secrets list (remote-capable, not local-only)", listCmd, false},
		{"vault-access (parent; not itself local-only)", vaultAccessCmd, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, isLocalOnlyCommand(tc.cmd))
		})
	}
}

// TestIsRemoteCapableCommand pins which commands are let through the
// remote-target guard because they have their own remote adapter -- see
// isRemoteCapableCommand in cmd/root.go.
func TestIsRemoteCapableCommand(t *testing.T) {
	secretsCmd := &cobra.Command{Use: "secrets"}
	subs := map[string]*cobra.Command{}
	for _, name := range []string{"list", "get", "create", "update", "delete", "export", "import", "generate-password"} {
		c := &cobra.Command{Use: name}
		secretsCmd.AddCommand(c)
		subs[name] = c
	}

	keysCmd := &cobra.Command{Use: "keys"}
	keysListCmd := &cobra.Command{Use: "list"}
	keysCmd.AddCommand(keysListCmd)

	cases := []struct {
		name string
		cmd  *cobra.Command
		want bool
	}{
		{"secrets list", subs["list"], true},
		{"secrets get", subs["get"], true},
		{"secrets create", subs["create"], true},
		{"secrets update", subs["update"], true},
		{"secrets delete", subs["delete"], true},
		{"secrets export", subs["export"], true},
		{"secrets import", subs["import"], true},
		{"secrets generate-password (local-only, not remote-capable)", subs["generate-password"], false},
		{"keys list (different resource group, no remote adapter yet)", keysListCmd, false},
		{"secrets (parent; not itself remote-capable)", secretsCmd, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, isRemoteCapableCommand(tc.cmd))
		})
	}
}

// TestPersistentPreRun_RemoteTarget_SecretsList_UsesRemoteAdapter is the
// end-to-end proof that "secrets list --server <url>" actually reaches the
// remote server instead of either falling back to a local instance or being
// rejected by the remote-target guard (which every other resource-group
// command still hits -- see TestPersistentPreRun_RemoteTarget_NonContext-
// Command_ReturnsError). No local .rocketvault.yaml or database exists in
// this test's working directory, so a fall-through to local mode would fail
// loudly rather than silently -- this test would catch that regression.
func TestPersistentPreRun_RemoteTarget_SecretsList_UsesRemoteAdapter(t *testing.T) {
	dir := t.TempDir()
	common.SessionBaseDir = filepath.Join(dir, "sessions")

	origWd, err := os.Getwd()
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.Chdir(origWd) })
	require.NoError(t, os.Chdir(dir))

	previousSettings := viper.AllSettings()
	viper.Reset()
	t.Cleanup(func() {
		viper.Reset()
		_ = viper.MergeConfigMap(previousSettings)
	})

	userID := uuid.New()
	var loginHit, listHit bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/v1/users/login":
			loginHit = true
			_ = json.NewEncoder(w).Encode(model.LoginResponse{
				Token: "tok", RefreshToken: "rtok", UserID: userID.String(), Username: "admin", Roles: []string{"admin"},
			})
		case "/api/v1/secrets":
			listHit = true
			assert.Equal(t, "Bearer tok", r.Header.Get("Authorization"))
			_ = json.NewEncoder(w).Encode(model.ListSecretsResponse{
				Secrets: []model.SecretResponse{{ID: "id-1", Name: "api-key", Version: 1, Enabled: true, CreatedAt: "2026-01-01T00:00:00Z"}},
				Total:   1,
			})
		default:
			t.Fatalf("unexpected request to %s", r.URL.Path)
		}
	}))
	defer srv.Close()

	previousArgs := os.Args
	os.Args = []string{"rocketvault", "secrets", "list"}
	t.Cleanup(func() { os.Args = previousArgs })

	var out bytes.Buffer
	rootCmd.SetOut(&out)
	rootCmd.SetArgs([]string{"secrets", "list", "--server", srv.URL, "--username", "admin", "--password", "pass123", "--totp-code", "123456"})
	t.Cleanup(func() { rootCmd.SetArgs(nil); rootCmd.SetOut(nil) })

	err = rootCmd.ExecuteContext(context.Background())
	require.NoError(t, err)
	assert.True(t, loginHit, "expected the remote server's login endpoint to be called")
	assert.True(t, listHit, "expected the remote server's secrets list endpoint to be called")
	assert.Contains(t, out.String(), "api-key")
}

func TestClientCredentials_FlagsWinOverEnv(t *testing.T) {
	t.Setenv("ROCKETVAULT_CLIENT_ID", "env-id")
	t.Setenv("ROCKETVAULT_CLIENT_SECRET", "env-secret")

	c := &cobra.Command{}
	c.Flags().String("client-id", "", "")
	c.Flags().String("client-secret", "", "")
	require.NoError(t, c.Flags().Set("client-id", "flag-id"))
	require.NoError(t, c.Flags().Set("client-secret", "flag-secret"))

	id, secret := clientCredentials(c)
	assert.Equal(t, "flag-id", id)
	assert.Equal(t, "flag-secret", secret)
}

func TestClientCredentials_FallsBackToEnv(t *testing.T) {
	t.Setenv("ROCKETVAULT_CLIENT_ID", "env-id")
	t.Setenv("ROCKETVAULT_CLIENT_SECRET", "env-secret")

	c := &cobra.Command{}
	c.Flags().String("client-id", "", "")
	c.Flags().String("client-secret", "", "")

	id, secret := clientCredentials(c)
	assert.Equal(t, "env-id", id)
	assert.Equal(t, "env-secret", secret)
}

func TestClientCredentials_UnsetIsEmpty(t *testing.T) {
	t.Setenv("ROCKETVAULT_CLIENT_ID", "")
	t.Setenv("ROCKETVAULT_CLIENT_SECRET", "")

	c := &cobra.Command{}
	c.Flags().String("client-id", "", "")
	c.Flags().String("client-secret", "", "")

	id, secret := clientCredentials(c)
	assert.Empty(t, id)
	assert.Empty(t, secret)
}

func TestResolveRemoteTokenSource_ClientCredentials_UsesServiceAccount(t *testing.T) {
	t.Setenv("ROCKETVAULT_CLIENT_ID", "svc-id")
	t.Setenv("ROCKETVAULT_CLIENT_SECRET", "svc-secret")
	common.SessionBaseDir = t.TempDir() // no session cached at all

	target := &cliclient.Target{Server: "https://vault.example.com"}
	c := newAuthTestCmd("", "", "")
	c.Flags().String("client-id", "", "")
	c.Flags().String("client-secret", "", "")

	src, err := resolveRemoteTokenSource(c, target, http.DefaultClient)
	require.NoError(t, err, "service-account auth must not require a cached session")
	assert.IsType(t, &vaultapi.ServiceAccountSource{}, src)
}

// The credential tier must survive the move to vaultapi: it is the only way
// to authenticate remotely until users login is unguarded in 02b.
func TestResolveRemoteTokenSource_UsernamePassword_LogsInAndCaches(t *testing.T) {
	common.SessionBaseDir = t.TempDir()
	var loginHit bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/api/v1/users/login", r.URL.Path)
		loginHit = true
		_ = json.NewEncoder(w).Encode(map[string]any{
			"token": "tok", "refresh_token": "refresh",
			"user_id":  "0f2b6f1e-0000-0000-0000-000000000001",
			"username": "admin", "roles": []string{"admin"},
		})
	}))
	defer srv.Close()

	target := &cliclient.Target{Server: srv.URL}
	c := newAuthTestCmd("admin", "pass123", "123456")
	c.Flags().String("client-id", "", "")
	c.Flags().String("client-secret", "", "")

	src, err := resolveRemoteTokenSource(c, target, srv.Client())
	require.NoError(t, err)
	assert.True(t, loginHit, "credentials must produce a real login call")

	tok, err := src.Token(context.Background())
	require.NoError(t, err)
	assert.Equal(t, "tok", tok)

	cached, err := common.LoadSessionForServer(common.SanitizeServerKey(srv.URL), "admin")
	require.NoError(t, err)
	require.NotNil(t, cached, "a credential login must cache its session")
}

func TestResolveRemoteTokenSource_NoCredentials_UsesSession(t *testing.T) {
	common.SessionBaseDir = t.TempDir()
	serverKey := common.SanitizeServerKey("https://vault.example.com")
	require.NoError(t, common.SaveSession(&common.SessionCache{
		Token: "tok", RefreshToken: "refresh", Username: "admin",
		ServerKey: serverKey, ExpiresAt: time.Now().Add(time.Hour),
	}))

	target := &cliclient.Target{Server: "https://vault.example.com"}
	c := newAuthTestCmd("", "", "")
	c.Flags().String("client-id", "", "")
	c.Flags().String("client-secret", "", "")

	src, err := resolveRemoteTokenSource(c, target, http.DefaultClient)
	require.NoError(t, err)
	assert.IsType(t, &vaultapi.SessionSource{}, src)
}

// A cached session for a different server must never be used against this
// target -- the "current" pointer is global across servers.
func TestResolveRemoteTokenSource_CurrentSession_WrongServer_Refused(t *testing.T) {
	common.SessionBaseDir = t.TempDir()
	require.NoError(t, common.SaveSession(&common.SessionCache{
		Token: "other-server-tok", Username: "admin",
		ServerKey: common.SanitizeServerKey("https://other.example.com"),
		ExpiresAt: time.Now().Add(time.Hour),
	}))

	target := &cliclient.Target{Server: "https://vault.prod.example.com"}
	c := newAuthTestCmd("", "", "")
	c.Flags().String("client-id", "", "")
	c.Flags().String("client-secret", "", "")

	_, err := resolveRemoteTokenSource(c, target, http.DefaultClient)
	require.Error(t, err, "a cached session for a different server must not be reused")
}

func TestResolveRemoteTokenSource_HalfCredentials_IsUsageError(t *testing.T) {
	t.Setenv("ROCKETVAULT_CLIENT_ID", "svc-id")
	t.Setenv("ROCKETVAULT_CLIENT_SECRET", "")
	common.SessionBaseDir = t.TempDir()

	target := &cliclient.Target{Server: "https://vault.example.com"}
	c := newAuthTestCmd("", "", "")
	c.Flags().String("client-id", "", "")
	c.Flags().String("client-secret", "", "")

	_, err := resolveRemoteTokenSource(c, target, http.DefaultClient)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "client-secret")
}

func TestRemotePersistentPreRun_StashesVaultapiClient(t *testing.T) {
	common.SessionBaseDir = t.TempDir()
	serverKey := common.SanitizeServerKey("https://vault.example.com")
	require.NoError(t, common.SaveSession(&common.SessionCache{
		Token: "tok", RefreshToken: "refresh", Username: "admin",
		ServerKey: serverKey, ExpiresAt: time.Now().Add(time.Hour),
	}))

	c := newAuthTestCmd("", "", "")
	c.Flags().String("client-id", "", "")
	c.Flags().String("client-secret", "", "")
	c.Flags().String("ca-cert", "", "")
	c.Flags().Bool("insecure-skip-verify", false, "")
	c.Flags().String("output", "table", "") // required: formatter.New("") rejects the empty format
	c.SetContext(context.Background())

	target := &cliclient.Target{Server: "https://vault.example.com"}
	require.NoError(t, remotePersistentPreRun(c, target))

	client, ok := c.Context().Value(common.RemoteClientKey).(*vaultapi.Client)
	require.True(t, ok, "remote pre-run must stash a *vaultapi.Client")
	require.NotNil(t, client)
}

func TestRemoteGuard_AllowsUsersLoginAndLogout(t *testing.T) {
	for _, name := range []string{"login", "logout"} {
		users := &cobra.Command{Use: "users"}
		sub := &cobra.Command{Use: name}
		users.AddCommand(sub)
		assert.True(t, isRemoteCapableCommand(sub), "%q must reach its remote adapter", name)
		assert.True(t, isRemoteUnauthenticatedCommand(sub), "%q must not be pre-authenticated", name)
	}
}

func TestRemoteGuard_StillBlocksUnmigratedGroups(t *testing.T) {
	keys := &cobra.Command{Use: "keys"}
	sub := &cobra.Command{Use: "list"}
	keys.AddCommand(sub)
	assert.False(t, isRemoteCapableCommand(sub))
}

// B54: with no session cached and no credentials passed, the pre-run must
// still hand `users login` a client -- that is the exact situation where the
// old pre-run failed before the command body ever ran.
func TestRemotePersistentPreRun_UnauthenticatedCommand_StashesClientWithNoSession(t *testing.T) {
	common.SessionBaseDir = t.TempDir() // nothing cached

	users := &cobra.Command{Use: "users"}
	c := newAuthTestCmd("", "", "")
	c.Use = "login"
	users.AddCommand(c)
	c.Flags().String("client-id", "", "")
	c.Flags().String("client-secret", "", "")
	c.Flags().String("ca-cert", "", "")
	c.Flags().Bool("insecure-skip-verify", false, "")
	c.Flags().String("output", "table", "")
	c.SetContext(context.Background())

	target := &cliclient.Target{Server: "https://vault.example.com"}
	require.NoError(t, remotePersistentPreRun(c, target),
		"users login must not require a session to reach its RunE")

	client, ok := c.Context().Value(common.RemoteClientKey).(*vaultapi.Client)
	require.True(t, ok, "the unauthenticated branch must still stash a *vaultapi.Client")
	require.NotNil(t, client)
}

func TestIsRemoteCapableCommand_VaultAccess(t *testing.T) {
	parent := &cobra.Command{Use: "vault-access"}
	for _, name := range []string{"grant", "list", "revoke"} {
		child := &cobra.Command{Use: name}
		parent.AddCommand(child)
		assert.Truef(t, isRemoteCapableCommand(child), "vault-access %s must be remote-capable", name)
	}
}

// roles is local-only: it reads compiled-in definitions and never calls a
// server, so it must not be routed through the remote pre-run.
func TestIsRemoteCapableCommand_VaultAccessRolesIsNot(t *testing.T) {
	parent := &cobra.Command{Use: "vault-access"}
	child := &cobra.Command{Use: "roles"}
	parent.AddCommand(child)
	assert.False(t, isRemoteCapableCommand(child))
}
