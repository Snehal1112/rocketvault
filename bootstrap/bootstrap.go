// Package bootstrap provides application initialization with proper separation of concerns.
// This refactored version follows SRP by delegating specific concerns to dedicated
// initializers while maintaining a clean orchestration layer.
package bootstrap

import (
	"context"
	"fmt"
	"os"

	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"

	"rocketvault/api"
	"rocketvault/app"
	"rocketvault/common"
	"rocketvault/config"
	"rocketvault/internal/container"
	"rocketvault/internal/db"
	"rocketvault/internal/health"
	"rocketvault/internal/logging"
	"rocketvault/internal/metrics"
	authzServices "rocketvault/internal/services/authorization"
	certServices "rocketvault/internal/services/certificates"
	keysServices "rocketvault/internal/services/keys"
	"rocketvault/internal/services/softdelete"
	"rocketvault/internal/vaultclient"
	"rocketvault/server"
)

// Config holds the configuration settings for the vault service application.
// It includes the base path for the application, the address to listen on,
// the backend endpoint, the database name, and the logger instance.
type Config struct {
	BasePath        string
	Listen          string
	BackendEndPoint string
	DatabaseName    string
	Logger          logrus.FieldLogger
}

// DatabaseInitializer handles database setup and initialization.
// It follows SRP by focusing only on database-related concerns.
type DatabaseInitializer struct {
	logger *logging.Logger
}

// NewDatabaseInitializer creates a new database initializer.
func NewDatabaseInitializer(logger *logging.Logger) *DatabaseInitializer {
	return &DatabaseInitializer{logger: logger}
}

// Initialize sets up the database connection and schema.
func (d *DatabaseInitializer) Initialize(cfg *config.Config) (*db.DBRepository, error) {
	d.logger.Info("Initializing database")

	database := db.NewRepository(cfg.Logger)
	if err := database.InitializeDB(); err != nil {
		return nil, fmt.Errorf("failed to initialize database: %w", err)
	}

	d.logger.Info("Database initialized successfully")
	return database, nil
}

// ServerStarter handles server lifecycle management.
// It follows SRP by focusing only on server startup concerns.
type ServerStarter struct {
	logger *logging.Logger
}

// NewServerStarter creates a new server starter.
func NewServerStarter(logger *logging.Logger) *ServerStarter {
	return &ServerStarter{logger: logger}
}

// Start initializes and starts the HTTP server.
func (s *ServerStarter) Start(ctx context.Context, app *app.App) error {
	s.logger.Info("Starting HTTP server")
	app.StartServer(ctx) //nolint:errcheck,gosec
	s.logger.Info("HTTP server started successfully")
	return nil
}

// ConfigurationValidator handles configuration validation.
// It follows SRP by focusing only on configuration validation concerns.
type ConfigurationValidator struct {
	logger *logging.Logger
}

// NewConfigurationValidator creates a new configuration validator.
func NewConfigurationValidator(logger *logging.Logger) *ConfigurationValidator {
	return &ConfigurationValidator{logger: logger}
}

// Validate checks that all required configuration is present and valid.
func (c *ConfigurationValidator) Validate(cfg *Config, serverCfg *config.Config) error {
	c.logger.Info("Validating configuration")

	if cfg.DatabaseName == "" {
		return fmt.Errorf("database name is required")
	}
	if cfg.Listen == "" {
		return fmt.Errorf("listen address is required")
	}
	if cfg.BasePath == "" {
		cfg.BasePath = "/"
	}
	if cfg.Logger == nil {
		return fmt.Errorf("logger is required")
	}
	if serverCfg.Logger == nil {
		return fmt.Errorf("server logger is required")
	}

	c.logger.Info("Configuration validation successful")
	return nil
}

// ValidateMasterKey fails startup when the configured master_key is missing,
// malformed, or known-weak. A 2026-08-16 penetration test decrypted a live
// database using the placeholder key committed to this repository, so booting
// on it is treated as a fatal misconfiguration rather than a warning.
//
// This is a separate method from Validate, and called later in setup, because
// it must run after vault-sourced secrets are injected into Viper — that
// injection can supply master_key itself, so validating alongside the other
// static config would read a value that is about to be replaced.
//
// There is deliberately no override flag: a guard with a documented bypass is
// the same guard the penetration test already walked through.
//
// Parameters:
//
//	encoded: The base64-encoded master key from configuration.
//
// Returns:
//
//	An error if the key must not be used, otherwise nil.
func (c *ConfigurationValidator) ValidateMasterKey(encoded string) error {
	if err := common.ValidateMasterKey(encoded); err != nil {
		return fmt.Errorf("refusing to start: configured master_key is not usable: %w", err)
	}

	c.logger.Info("Master key validation successful")
	return nil
}

// validateAuthorizationBasePath fails closed when the operator-configured API
// base path (cmd/serve.go's --api_base flag / PASSWORD_MANAGER_BASE_API env
// var, threaded through as cfg.BasePath) does not match the authorization
// layer's expected data-plane prefix.
//
// cfg.BasePath is a genuinely dynamic, runtime-configurable value — it is not
// pinned to any constant at the api.Init call site. Meanwhile
// internal/services/authorization strips a single hardcoded prefix
// (authzServices.DataPlaneBasePath) from every request path before mapping it
// to a required permission or data action, in both the currently-live
// rbac_service.go mapEndpointToPermission (reached today via
// AuthorizationMiddleware) and the not-yet-wired data_actions.go
// MapRouteToDataAction (reached once Task 9 lands). If api.Init ever serves
// routes under a different prefix than that hardcoded constant, the strip
// silently fails to match and the affected mapper falls through to its
// "no permission required" / "unmanaged route" branch — bypassing
// authorization for the entire deployment with no error and nothing in the
// logs pointing at the cause.
//
// api.VerifyRouteAuthorization repeats this assertion for every caller of
// api.Init, and additionally refuses any route whose authorization is not
// classified. Both stay: this one fails before the database is touched.
func validateAuthorizationBasePath(basePath string) error {
	if basePath != authzServices.DataPlaneBasePath {
		return fmt.Errorf(
			"configured API base path %q does not match the authorization layer's expected "+
				"data-plane base path %q — refusing to start because serving the API under a "+
				"different prefix would silently bypass data-plane authorization for every "+
				"request (see internal/services/authorization/data_actions.go and rbac_service.go)",
			basePath, authzServices.DataPlaneBasePath,
		)
	}
	return nil
}

// bootstrap provides orchestration for application startup following SRP.
// It coordinates different initializers while maintaining single responsibility.
type bootstrap struct {
	dbInitializer        *DatabaseInitializer
	serverStarter        *ServerStarter
	configValidator      *ConfigurationValidator
	serviceContainer     *container.ServiceContainer
	cfg                  *config.Config
	purgeScheduler       *softdelete.PurgeScheduler
	renewalScheduler     *certServices.CertificateRenewalScheduler
	keyRotationScheduler *keysServices.RotationScheduler
	metricsScheduler     *metrics.MetricsScheduler
	monitoringCfg        config.MonitoringConfig
	rotationCfg          config.RotationConfig
}

// newBootstrap creates a new bootstrap orchestrator with SRP-compliant design.
func newBootstrap(serverCfg *config.Config) *bootstrap {
	return &bootstrap{
		cfg:             serverCfg,
		dbInitializer:   NewDatabaseInitializer(serverCfg.Logger),
		serverStarter:   NewServerStarter(serverCfg.Logger),
		configValidator: NewConfigurationValidator(serverCfg.Logger),
	}
}

// Config returns the configuration settings for the bootstrap instance.
func (b *bootstrap) Config() *config.Config {
	return b.cfg
}

// GetServiceContainer returns the service container for external access.
func (b *bootstrap) GetServiceContainer() *container.ServiceContainer {
	return b.serviceContainer
}

// Boot initialises the application and returns a shutdown function and any setup error.
// Call the returned shutdown function after the HTTP server has stopped to release resources.
func Boot(ctx context.Context, cfg *Config, serverCfg *config.Config) (func(context.Context) error, error) {
	bs := newBootstrap(serverCfg)
	if err := bs.setup(ctx, cfg); err != nil {
		return nil, err
	}
	return bs.Shutdown, nil
}

// setup orchestrates the complete application startup process following SRP.
// It coordinates initialization steps while delegating specific tasks to specialized initializers.
//
// Parameters:
//   - ctx: The context for controlling the setup process.
//   - cfg: The configuration settings for the application.
//
// Returns:
//   - error: An error if the setup process fails, otherwise nil.
func (b *bootstrap) setup(ctx context.Context, cfg *Config) error {
	logrus.Info("Starting application bootstrap")

	// Step 1: Validate configuration (SRP: dedicated validator)
	if err := b.configValidator.Validate(cfg, b.cfg); err != nil {
		return fmt.Errorf("configuration validation failed: %w", err)
	}

	// Step 1a: Fail closed if the operator-configured API base path does not
	// match the authorization layer's expected data-plane prefix. See
	// validateAuthorizationBasePath for why a silent mismatch is a security
	// bug, not just a routing quirk.
	if err := validateAuthorizationBasePath(cfg.BasePath); err != nil {
		return err
	}

	// Step 1b: Fetch secrets from vault and inject them into Viper before
	// the service container reads any config values. Skipped when vault is not fully configured.
	// client_secret is never stored in the config file — it must come from VAULT_CLIENT_SECRET env var.
	vaultClientSecret := viper.GetString("vault_client.client_secret")
	if vaultClientSecret == "" {
		vaultClientSecret = os.Getenv("VAULT_CLIENT_SECRET")
	}
	if viper.GetString("vault_client.url") != "" &&
		viper.GetString("vault_client.client_id") != "" &&
		vaultClientSecret != "" {
		vaultClient, err := vaultclient.NewFromViper()
		if err != nil {
			return fmt.Errorf("vault client init: %w", err)
		}
		var mappings []vaultclient.SecretMapping
		if err := viper.UnmarshalKey("vault_client.secrets", &mappings); err != nil {
			return fmt.Errorf("vault_client.secrets config: %w", err)
		}
		secretsInit := NewSecretsInitializerFromMappings(vaultClient, mappings)
		if err := secretsInit.Initialize(ctx); err != nil {
			return fmt.Errorf("secrets init: %w", err)
		}
		logrus.Info("Vault secrets injected into config")
	}

	// Step 1c: Refuse to start on a weak or known-compromised master key. This
	// runs after Step 1b because vault-injected secrets can supply master_key.
	if err := b.configValidator.ValidateMasterKey(viper.GetString("master_key")); err != nil {
		return err
	}

	// Step 2: Initialize database (SRP: dedicated initializer)
	database, err := b.dbInitializer.Initialize(b.cfg)
	if err != nil {
		return fmt.Errorf("database initialization failed: %w", err)
	}

	// Step 2a: Load monitoring config and apply the slow-query threshold to
	// the db and health packages' query-performance tracking.
	b.monitoringCfg = config.LoadMonitoringConfig()
	db.SetSlowQueryThreshold(b.monitoringCfg.SlowQueryThreshold)
	health.SetDefaultSlowQueryThreshold(b.monitoringCfg.SlowQueryThreshold)

	// Step 2a-1: Load rotation scheduler config for secrets, certs, and keys.
	b.rotationCfg = config.LoadRotationConfig()

	// Start the periodic DB performance gauge collector when metrics are enabled.
	if b.monitoringCfg.EnableMetrics {
		dbMetrics := metrics.NewDefaultDBMetrics()
		b.metricsScheduler = metrics.NewMetricsScheduler(dbMetrics, dbPerformanceSnapshot(database), b.monitoringCfg.MetricsInterval)
		b.metricsScheduler.Start(ctx)
		b.cfg.Logger.Info("Metrics collector started")
	}

	// Step 2b: Load soft-delete config for the purge scheduler, started below
	// once the service container's VaultService is available (Step 3).
	softDeleteCfg := config.LoadSoftDeleteConfig()

	// Step 3: Initialize service container (SRP: dependency injection)
	serviceContainer, err := container.NewServiceContainer(container.Config{
		Database: database.GetDB(),
		Logger:   b.cfg.Logger,
	})
	if err != nil {
		return fmt.Errorf("service container initialization failed: %w", err)
	}
	b.serviceContainer = serviceContainer

	// Step 3a: Start background purge scheduler when soft-delete is enabled.
	// Constructed after the service container so it can auto-purge expired
	// vaults through VaultService, not just secrets/keys/certificates.
	if softDeleteCfg.Enabled {
		dialect := db.DialectFromDriver(viper.GetString("database.driver"))
		conn := db.NewConn(database.GetDB(), dialect)
		b.purgeScheduler = softdelete.NewPurgeScheduler(conn, softDeleteCfg, b.cfg.Logger, b.serviceContainer.GetVaultService())
		b.purgeScheduler.Start(ctx)
		b.cfg.Logger.Info("Soft-delete purge scheduler started")
	}

	// Step 2c: Start certificate renewal scheduler, if enabled.
	if sc := b.serviceContainer.GetCertificateRenewalService(); sc != nil && b.rotationCfg.Certificates.Enabled {
		b.renewalScheduler = certServices.NewCertificateRenewalScheduler(sc, b.cfg.Logger, b.rotationCfg.Certificates.Interval)
		b.renewalScheduler.Start(ctx)
		b.cfg.Logger.Info("Certificate renewal scheduler started")
	}

	// Step 2d: Start key rotation scheduler, if enabled.
	if b.rotationCfg.Keys.Enabled {
		executor := keysServices.NewRotationExecutor(
			b.serviceContainer.GetKeyService(),
			b.serviceContainer.GetKeyRotationPolicyRepository(),
			b.cfg.Logger,
		)
		b.keyRotationScheduler = keysServices.NewRotationScheduler(executor, b.cfg.Logger, b.rotationCfg.Keys.Interval)
		b.keyRotationScheduler.Start(ctx)
		b.cfg.Logger.Info("Key rotation scheduler started")
	}

	// Step 4: Create application with dependency injection
	app, err := b.createApplication(cfg)
	if err != nil {
		return fmt.Errorf("application creation failed: %w", err)
	}

	// Step 6: Initialize API with dependencies
	if err := b.initializeAPI(cfg, app); err != nil {
		return fmt.Errorf("API initialization failed: %w", err)
	}

	// Step 7: Start server (SRP: dedicated starter)
	if err := b.serverStarter.Start(ctx, app); err != nil {
		return fmt.Errorf("server startup failed: %w", err)
	}

	logrus.Info("Application bootstrap completed successfully")
	return nil
}

// dbPerformanceSnapshot adapts db.GetPerformanceMetrics into the shape the
// metrics package's periodic gauge collector expects.
func dbPerformanceSnapshot(database *db.DBRepository) func() metrics.DBSnapshot {
	return func() metrics.DBSnapshot {
		perf := db.GetPerformanceMetrics(database.GetDB())
		return metrics.DBSnapshot{
			QueryCount:         perf.QueryCount,
			SlowQueryCount:     perf.SlowQueryCount,
			AverageQueryTimeMS: float64(perf.AverageQueryTime.Microseconds()) / 1000.0,
			OpenConnections:    perf.ConnectionStats.OpenConnections,
			InUse:              perf.ConnectionStats.InUse,
			Idle:               perf.ConnectionStats.Idle,
		}
	}
}

// buildServerConfigFromViper reads server TLS and feature configuration from Viper.
func buildServerConfigFromViper() server.ServerConfig {
	// Default HTTP/2 to enabled — matches the previous NewDefaultServer default.
	if !viper.IsSet("server.http2.enabled") {
		viper.SetDefault("server.http2.enabled", true)
	}
	return server.ServerConfig{
		EnableHTTP2:     viper.GetBool("server.http2.enabled"),
		EnableTLS:       viper.GetBool("server.tls.enabled"),
		CertFile:        viper.GetString("server.tls.cert_file"),
		KeyFile:         viper.GetString("server.tls.key_file"),
		EnableWebSocket: false,
		MaxConnections:  1000,
	}
}

// createApplication creates the main application instance with injected dependencies.
// This method follows SRP by handling only application instance creation.
func (b *bootstrap) createApplication(cfg *Config) (*app.App, error) {
	logrus.Info("Creating application instance")

	fc := &app.FrontendConfig{
		FeatureFlags: map[string]bool{},
		PublicAPIURL: viper.GetString("frontend.public_api_url"),
		SentryDSN:    viper.GetString("frontend.sentry_dsn"),
	}

	serverCfg := buildServerConfigFromViper()
	application := app.NewApp(
		app.WithDBName(cfg.DatabaseName),
		app.WithBasePath(cfg.BasePath),
		app.WithBackendEndPoint(cfg.BackendEndPoint),
		app.WithLogger(b.cfg.Logger),
		app.WithServer(server.NewServer(b.cfg.Logger, cfg.Listen, serverCfg)),
		app.WithServiceContainer(b.serviceContainer),
		app.WithSchedulerEnabled(b.rotationCfg.Secrets.Enabled, b.rotationCfg.Secrets.Interval),
		app.WithFrontendConfig(fc),
	).(*app.App)

	logrus.Info("Application instance created successfully")
	return application, nil
}

// initializeAPI sets up the API layer with proper dependency injection.
// This method follows SRP by handling only API initialization concerns.
func (b *bootstrap) initializeAPI(cfg *Config, app *app.App) error {
	logrus.Info("Initializing API layer")

	api.Init(
		api.WithAPP(app),
		api.WithBasePath(cfg.BasePath),
		api.WithRouter(app.GetRouter()),
		api.WithLogger(b.cfg.Logger),
		api.WithMetricsEnabled(b.monitoringCfg.EnableMetrics),
	)

	// Refuse to serve a route whose authorization nobody classified. See
	// api.VerifyRouteAuthorization and B80 in .claude/known-bugs.md.
	if err := api.VerifyRouteAuthorization(app.GetRouter(), cfg.BasePath); err != nil {
		return fmt.Errorf("refusing to start: %w", err)
	}

	logrus.Info("API layer initialized successfully")
	return nil
}

// Shutdown performs graceful application shutdown.
// This method follows SRP by handling only shutdown concerns.
func (b *bootstrap) Shutdown(ctx context.Context) error {
	logrus.Info("Starting application shutdown")

	if b.renewalScheduler != nil {
		b.renewalScheduler.Stop()
		logrus.Info("Certificate renewal scheduler stopped")
	}

	if b.keyRotationScheduler != nil {
		b.keyRotationScheduler.Stop()
		logrus.Info("Key rotation scheduler stopped")
	}

	if b.metricsScheduler != nil {
		b.metricsScheduler.Stop()
		logrus.Info("Metrics collector stopped")
	}

	if b.purgeScheduler != nil {
		b.purgeScheduler.Stop()
		logrus.Info("Soft-delete purge scheduler stopped")
	}

	if b.serviceContainer != nil {
		if err := b.serviceContainer.Close(); err != nil {
			logrus.WithError(err).Error("Error closing service container")
			return fmt.Errorf("service container shutdown failed: %w", err)
		}
	}

	logrus.Info("Application shutdown completed")
	return nil
}
