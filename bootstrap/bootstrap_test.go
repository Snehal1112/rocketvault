// Package bootstrap provides tests for the application bootstrap layer.
package bootstrap

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"testing"
	"time"

	_ "github.com/mattn/go-sqlite3"
	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"rocketvault/config"
	rvdb "rocketvault/internal/db"
	"rocketvault/internal/logging"
	authzServices "rocketvault/internal/services/authorization"
	certServices "rocketvault/internal/services/certificates"
	keysServices "rocketvault/internal/services/keys"
	"rocketvault/internal/services/softdelete"
)

// newTestLogger returns a minimal *logging.Logger for use in tests.
func newTestLogger() *logging.Logger {
	return &logging.Logger{Logger: logrus.New()}
}

// ----- buildServerConfigFromViper -----

func TestBuildServerConfigFromViper(t *testing.T) {
	viper.Set("server.tls.enabled", true)
	viper.Set("server.tls.cert_file", "/tmp/test.crt")
	viper.Set("server.tls.key_file", "/tmp/test.key")
	defer viper.Reset()

	cfg := buildServerConfigFromViper()
	assert.True(t, cfg.EnableTLS)
	assert.Equal(t, "/tmp/test.crt", cfg.CertFile)
	assert.Equal(t, "/tmp/test.key", cfg.KeyFile)
}

// TestBuildServerConfigFromViper_HTTP2Default verifies that HTTP/2 is enabled
// even when server.http2.enabled is absent from the YAML config.
func TestBuildServerConfigFromViper_HTTP2Default(t *testing.T) {
	// Use a clean viper state without the http2 key set.
	viper.Reset()
	defer viper.Reset()

	cfg := buildServerConfigFromViper()
	assert.True(t, cfg.EnableHTTP2, "HTTP/2 must be enabled by default when key is absent")
}

// ----- DatabaseInitializer constructor -----

func TestNewDatabaseInitializer(t *testing.T) {
	t.Parallel()
	logger := newTestLogger()
	di := NewDatabaseInitializer(logger)
	assert.NotNil(t, di)
}

// ----- ServerStarter constructor -----

func TestNewServerStarter(t *testing.T) {
	t.Parallel()
	logger := newTestLogger()
	ss := NewServerStarter(logger)
	assert.NotNil(t, ss)
}

// ----- ConfigurationValidator constructor -----

func TestNewConfigurationValidator(t *testing.T) {
	t.Parallel()
	logger := newTestLogger()
	cv := NewConfigurationValidator(logger)
	assert.NotNil(t, cv)
}

// ----- ConfigurationValidator.Validate -----

// validServerCfg returns a config.Config with a non-nil Logger,
// the minimum required by ConfigurationValidator.Validate.
func validServerCfg() *config.Config {
	return &config.Config{Logger: newTestLogger()}
}

// validBootstrapCfg returns a Config that satisfies all validator checks.
func validBootstrapCfg() *Config {
	return &Config{
		DatabaseName: "test.db",
		Listen:       ":8080",
		BasePath:     "/api",
		Logger:       logrus.New(),
	}
}

func TestValidate_Success(t *testing.T) {
	t.Parallel()
	cv := NewConfigurationValidator(newTestLogger())
	err := cv.Validate(validBootstrapCfg(), validServerCfg())
	require.NoError(t, err)
}

func TestValidate_MissingDatabaseName(t *testing.T) {
	t.Parallel()
	cv := NewConfigurationValidator(newTestLogger())
	cfg := validBootstrapCfg()
	cfg.DatabaseName = ""
	err := cv.Validate(cfg, validServerCfg())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "database name is required")
}

func TestValidate_MissingListenAddress(t *testing.T) {
	t.Parallel()
	cv := NewConfigurationValidator(newTestLogger())
	cfg := validBootstrapCfg()
	cfg.Listen = ""
	err := cv.Validate(cfg, validServerCfg())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "listen address is required")
}

func TestValidate_EmptyBasePathDefaultsToSlash(t *testing.T) {
	t.Parallel()
	cv := NewConfigurationValidator(newTestLogger())
	cfg := validBootstrapCfg()
	cfg.BasePath = ""
	err := cv.Validate(cfg, validServerCfg())
	// Validation should succeed and BasePath must be set to "/"
	require.NoError(t, err)
	assert.Equal(t, "/", cfg.BasePath)
}

func TestValidate_NilLogger(t *testing.T) {
	t.Parallel()
	cv := NewConfigurationValidator(newTestLogger())
	cfg := validBootstrapCfg()
	cfg.Logger = nil
	err := cv.Validate(cfg, validServerCfg())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "logger is required")
}

func TestValidate_NilServerLogger(t *testing.T) {
	t.Parallel()
	cv := NewConfigurationValidator(newTestLogger())
	serverCfg := &config.Config{Logger: nil}
	err := cv.Validate(validBootstrapCfg(), serverCfg)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "server logger is required")
}

// ----- newBootstrap / Config / GetServiceContainer -----

func TestNewBootstrap_ReturnsNonNil(t *testing.T) {
	t.Parallel()
	bs := newBootstrap(validServerCfg())
	require.NotNil(t, bs)
}

func TestBootstrap_ConfigReturnsServerCfg(t *testing.T) {
	t.Parallel()
	serverCfg := validServerCfg()
	bs := newBootstrap(serverCfg)
	assert.Equal(t, serverCfg, bs.Config())
}

func TestBootstrap_GetServiceContainerInitiallyNil(t *testing.T) {
	t.Parallel()
	bs := newBootstrap(validServerCfg())
	assert.Nil(t, bs.GetServiceContainer())
}

func TestNewBootstrap_InitializesSubComponents(t *testing.T) {
	t.Parallel()
	serverCfg := validServerCfg()
	bs := newBootstrap(serverCfg)
	// Verify the three sub-initializers were wired up.
	assert.NotNil(t, bs.dbInitializer)
	assert.NotNil(t, bs.serverStarter)
	assert.NotNil(t, bs.configValidator)
}

// ----- Shutdown with nil fields -----

func TestShutdown_AllNilFields_NoError(t *testing.T) {
	t.Parallel()
	bs := &bootstrap{}
	err := bs.Shutdown(context.Background())
	assert.NoError(t, err)
}

func TestShutdown_NilSchedulers_NoError(t *testing.T) {
	t.Parallel()
	// Only cfg set — all scheduler fields are nil.
	bs := &bootstrap{cfg: validServerCfg()}
	err := bs.Shutdown(context.Background())
	assert.NoError(t, err)
}

// ----- Shutdown with a live PurgeScheduler -----

func TestShutdown_WithPurgeScheduler_StopsCleanly(t *testing.T) {
	t.Parallel()

	// Open an in-memory SQLite DB and wrap it in a dialect-aware Conn.
	// The scheduler will fail silently on the purge query (no tables), which
	// is acceptable here since we are only testing Shutdown.
	rawDB, err := sql.Open("sqlite3", ":memory:")
	require.NoError(t, err)
	defer rawDB.Close() //nolint:errcheck
	conn := rvdb.NewConn(rawDB, rvdb.SQLite)

	logger := newTestLogger()
	sdCfg := config.SoftDeleteConfig{RetentionDays: 30}
	ps := softdelete.NewPurgeScheduler(conn, sdCfg, logger, nil, nil)
	ps.Start(context.Background())

	bs := &bootstrap{purgeScheduler: ps}
	err = bs.Shutdown(context.Background())
	assert.NoError(t, err)
}

// TestShutdown_WithRenewalScheduler covers the renewalScheduler != nil branch.
// We create the scheduler but do NOT Start() it so there is no goroutine that
// would dereference the nil svc field; Stop() simply closes the done channel.
func TestShutdown_WithRenewalScheduler_StopsCleanly(t *testing.T) {
	t.Parallel()

	logger := newTestLogger()
	sched := certServices.NewCertificateRenewalScheduler(nil, logger, 24*time.Hour)

	bs := &bootstrap{renewalScheduler: sched}
	err := bs.Shutdown(context.Background())
	assert.NoError(t, err)
}

// TestShutdown_WithKeyRotationScheduler covers the keyRotationScheduler != nil
// branch. We create the scheduler but do NOT Start() it, mirroring
// TestShutdown_WithRenewalScheduler_StopsCleanly -- Stop() must be safe on a
// never-started scheduler.
func TestShutdown_WithKeyRotationScheduler_StopsCleanly(t *testing.T) {
	t.Parallel()

	logger := newTestLogger()
	executor := keysServices.NewRotationExecutor(nil, nil, logger)
	sched := keysServices.NewRotationScheduler(executor, logger, time.Hour)

	bs := &bootstrap{keyRotationScheduler: sched}
	err := bs.Shutdown(context.Background())
	assert.NoError(t, err)
}

// TestDatabaseInitializer_Initialize covers the Initialize method with a valid SQLite DB.
func TestDatabaseInitializer_Initialize_WithSQLite(t *testing.T) {
	viper.Set("database.connection", ":memory:")
	defer viper.Reset()

	logger := newTestLogger()
	di := NewDatabaseInitializer(logger)
	serverCfg := &config.Config{Logger: logger}

	repo, err := di.Initialize(serverCfg)
	require.NoError(t, err)
	require.NotNil(t, repo)
}

// TestDatabaseInitializer_Initialize_MissingConnection covers the error path.
func TestDatabaseInitializer_Initialize_MissingConnection(t *testing.T) {
	viper.Reset()
	defer viper.Reset()

	logger := newTestLogger()
	di := NewDatabaseInitializer(logger)
	serverCfg := &config.Config{Logger: logger}

	_, err := di.Initialize(serverCfg)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to initialize database")
}

// TestBoot_ValidationFailure covers Boot + early-exit path through setup.
func TestBoot_ValidationFailure(t *testing.T) {
	logger := newTestLogger()
	serverCfg := &config.Config{Logger: logger}

	// DatabaseName empty → Validate returns an error.
	cfg := &Config{
		DatabaseName: "",
		Listen:       ":8080",
		Logger:       logrus.New(),
	}

	shutdownFn, err := Boot(context.Background(), cfg, serverCfg)
	require.Error(t, err)
	assert.Nil(t, shutdownFn)
	assert.Contains(t, err.Error(), "database name is required")
}

// TestBoot_FullStack exercises the complete happy path of setup() by using a
// SQLite in-memory database and a listen address that immediately fails
// (ServerStarter.Start ignores the error, so Boot still succeeds).
func TestBoot_FullStack(t *testing.T) {
	viper.Reset()
	viper.Set("database.connection", ":memory:")
	viper.Set("jwt.expiry", "15m")
	viper.Set("soft_delete.enabled", false) // Skip purge scheduler goroutine.
	strongKey := make([]byte, 32)
	_, err := rand.Read(strongKey)
	require.NoError(t, err)
	viper.Set("master_key", base64.StdEncoding.EncodeToString(strongKey)) // Step 1c requires a valid key.
	defer viper.Reset()

	logger := newTestLogger()
	serverCfg := &config.Config{
		Logger: logger,
		SoftDelete: config.SoftDeleteConfig{
			Enabled:       false,
			RetentionDays: 30,
		},
	}

	cfg := &Config{
		DatabaseName: "test-db",
		// Port 99999 is out of valid range — net.Listen fails immediately and
		// the error is swallowed by ServerStarter.Start, so Boot returns nil.
		Listen: "localhost:99999",
		// Must match authzServices.DataPlaneBasePath — validateAuthorizationBasePath
		// fails the boot otherwise. See TestBoot_BasePathMismatch_FailsClosed.
		BasePath: authzServices.DataPlaneBasePath,
		Logger:   logrus.New(),
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	shutdownFn, err := Boot(ctx, cfg, serverCfg)
	require.NoError(t, err)
	require.NotNil(t, shutdownFn)

	// Trigger graceful shutdown and verify it completes without error.
	cancel()
	shutdownErr := shutdownFn(context.Background())
	assert.NoError(t, shutdownErr)
}

// ----- validateAuthorizationBasePath -----

// TestValidateAuthorizationBasePath_Match verifies the happy path where
// cfg.BasePath equals the authorization layer's expected data-plane prefix.
func TestValidateAuthorizationBasePath_Match(t *testing.T) {
	t.Parallel()
	err := validateAuthorizationBasePath(authzServices.DataPlaneBasePath)
	assert.NoError(t, err)
}

// TestValidateAuthorizationBasePath_Mismatch verifies that an operator-configured
// base path that diverges from authzServices.DataPlaneBasePath is rejected. A
// silent mismatch here would mean every data-plane route falls through the
// hardcoded prefix strip in internal/services/authorization and bypasses
// authorization for the whole deployment — this must fail loudly instead.
func TestValidateAuthorizationBasePath_Mismatch(t *testing.T) {
	t.Parallel()
	err := validateAuthorizationBasePath("/myprefix")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "/myprefix")
	assert.Contains(t, err.Error(), authzServices.DataPlaneBasePath)
}

// TestBoot_BasePathMismatch_FailsClosed exercises the same check through the
// full Boot() entry point, mirroring how cmd/serve.go's --api_base flag
// reaches bootstrap.Config.BasePath in production. A mismatched base path
// must fail Boot before the server ever starts accepting requests, not just
// in the unit-level validateAuthorizationBasePath check above.
func TestBoot_BasePathMismatch_FailsClosed(t *testing.T) {
	logger := newTestLogger()
	serverCfg := &config.Config{Logger: logger}

	cfg := &Config{
		DatabaseName: "test-db",
		Listen:       ":8080",
		BasePath:     "/myprefix",
		Logger:       logrus.New(),
	}

	shutdownFn, err := Boot(context.Background(), cfg, serverCfg)
	require.Error(t, err)
	assert.Nil(t, shutdownFn)
	assert.Contains(t, err.Error(), "does not match")
}

// ----- ConfigurationValidator.ValidateMasterKey -----

func TestValidateMasterKey_AcceptsStrongKey(t *testing.T) {
	t.Parallel()
	key := make([]byte, 32)
	_, err := rand.Read(key)
	require.NoError(t, err)

	cv := NewConfigurationValidator(newTestLogger())
	assert.NoError(t, cv.ValidateMasterKey(base64.StdEncoding.EncodeToString(key)))
}

func TestValidateMasterKey_RejectsCompromisedDefault(t *testing.T) {
	t.Parallel()
	cv := NewConfigurationValidator(newTestLogger())

	err := cv.ValidateMasterKey("MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "master_key")
	assert.Contains(t, err.Error(), "master-key rotate")
}

func TestValidateMasterKey_RejectsMissingKey(t *testing.T) {
	t.Parallel()
	cv := NewConfigurationValidator(newTestLogger())

	assert.Error(t, cv.ValidateMasterKey(""))
}
