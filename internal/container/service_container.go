// Package container provides dependency injection for the password manager.
// It manages service creation and lifecycle, ensuring proper dependency
// resolution and eliminating global state dependencies.
package container

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/spf13/viper"

	"rocketvault/internal/backup"
	"rocketvault/internal/cache"
	"rocketvault/internal/certcache"
	"rocketvault/internal/crypto"
	"rocketvault/internal/db"
	"rocketvault/internal/keycache"
	"rocketvault/internal/logging"
	"rocketvault/internal/metrics"
	"rocketvault/internal/repositories"
	"rocketvault/internal/rocketmemcache"
	auditServices "rocketvault/internal/services/audit"
	authServices "rocketvault/internal/services/auth"
	authzServices "rocketvault/internal/services/authorization"
	certServices "rocketvault/internal/services/certificates"
	keyServices "rocketvault/internal/services/keys"
	oauth2Services "rocketvault/internal/services/oauth2"
	"rocketvault/internal/services/provisioning"
	retryServices "rocketvault/internal/services/retry"
	secretServices "rocketvault/internal/services/secrets"
	secrets "rocketvault/internal/services/secrets"
	userServices "rocketvault/internal/services/users"
	vaultServices "rocketvault/internal/services/vaults"
	"rocketvault/internal/signing"
	"rocketvault/internal/vaultcache"

	rvconfig "rocketvault/config"
)

// ServiceContainerInterface defines the interface for the service container.
// This interface enables testability by allowing mock implementations
// to be used in place of the concrete ServiceContainer.
//
// The interface provides access to all application services, repositories,
// and infrastructure components through well-defined getter methods.
type ServiceContainerInterface interface {
	// Repository getters
	GetUserRepository() repositories.UserRepositoryInterface
	GetSecretRepository() repositories.SecretRepositoryInterface
	GetRotationRepository() repositories.RotationPolicyRepositoryInterface
	GetVersionRepository() repositories.SecretVersionRepositoryInterface
	GetKeyRepository() repositories.KeyRepositoryInterface
	GetCertificateRepository() repositories.CertificateRepositoryInterface
	GetCertificatePolicyRepository() repositories.CertificatePolicyRepositoryInterface
	GetKeyRotationPolicyRepository() repositories.KeyRotationPolicyRepositoryInterface
	GetSessionRepository() repositories.SessionRepositoryInterface
	GetVaultRepository() repositories.VaultRepositoryInterface

	// Authentication service getters
	GetPasswordService() authServices.PasswordService
	GetTOTPService() authServices.TOTPService
	GetJWTService() authServices.JWTService
	GetAuthenticationService() authServices.AuthenticationService
	GetOIDCService() authServices.OIDCService

	// Authorization service getters
	GetRBACService() authzServices.RBACService
	GetAccessPolicyRepository() repositories.AccessPolicyRepositoryInterface
	GetAccessPolicyService() authzServices.AccessPolicyService
	GetRoleAssignmentService() authzServices.RoleAssignmentService

	// Provisioning service getter
	GetGrantService() provisioning.GrantService

	// OAuth2 / service account getters
	GetOAuth2ClientRepository() repositories.OAuth2ClientRepositoryInterface
	GetOAuth2Service() oauth2Services.OAuth2Service

	// Business service getters
	GetUserService() userServices.UserService
	GetSecretService() secretServices.SecretService
	GetKeyService() keyServices.KeyService
	GetCertificateService() certServices.CertificateService
	GetCertificateRenewalService() certServices.CertificateRenewalService
	GetCryptoService() keyServices.CryptoService
	GetVaultService() vaultServices.VaultService
	GetVaultWebhookService() vaultServices.VaultWebhookService

	// Secret component service getters
	GetCryptographyService() secretServices.CryptographyService
	GetVersioningService() secretServices.VersioningServiceInterface
	GetTagService() secretServices.TagService
	GetRotationService() secretServices.RotationServiceInterface
	GetSchedulerService() secretServices.SchedulerServiceInterface

	// Infrastructure getters
	GetDatabase() *sql.DB
	GetLogger() *logging.Logger

	// Cache getters
	GetSecretCache() *cache.SecretCache
	GetCacheConfig() rvconfig.CacheConfig
	GetCachedSecretService() secrets.SecretService
	GetVaultCache() *vaultcache.Cache
	GetCertificateCache() *certcache.Cache

	// Retry service getters
	GetRetryService() retryServices.RetryService

	// Signing provider getter
	GetSigningProvider() signing.SigningKeyProvider

	// Backup service getter
	GetItemBackupService() *backup.ItemBackupService

	// Key provider getter
	GetKeyProvider() crypto.KeyProvider

	// Key cache and metrics getters
	GetKeyCache() keycache.Cache
	GetCryptoMetrics() metrics.CryptoMetrics

	// Audit service getters
	GetAuditService() auditServices.AuditServiceInterface
	GetComplianceReportService() auditServices.ComplianceReportServiceInterface

	// Lifecycle management
	Close() error
}

// ServiceContainer manages all application services and their dependencies.
// It provides a centralized way to create and inject dependencies,
// replacing global variables with proper dependency injection.
//
// ServiceContainer implements ServiceContainerInterface.
type ServiceContainer struct {
	// Core infrastructure
	db     *sql.DB  // raw handle for health checks, transactions, and Close
	conn   *db.Conn // dialect-aware wrapper repositories use for all queries
	logger *logging.Logger
	viper  *viper.Viper // Configuration manager

	// Cache infrastructure
	secretCache              *cache.SecretCache
	cachedSecretService      secrets.SecretService
	cacheConfig              rvconfig.CacheConfig
	vaultCache               *vaultcache.Cache
	certCache                *certcache.Cache
	cachedCertificateService certServices.CertificateService

	// globalPurgeProtection mirrors soft_delete.purge_protection: when true,
	// every purge operation (secret, key, certificate, vault; manual or
	// scheduled) is refused instance-wide.
	globalPurgeProtection bool

	// Repositories
	userRepository               repositories.UserRepositoryInterface
	secretRepository             repositories.SecretRepositoryInterface
	rotationRepository           repositories.RotationPolicyRepositoryInterface
	versionRepository            repositories.SecretVersionRepositoryInterface
	keyRepository                repositories.KeyRepositoryInterface
	certificateRepository        repositories.CertificateRepositoryInterface
	certificateVersionRepository repositories.CertificateVersionRepositoryInterface
	certPolicyRepository         repositories.CertificatePolicyRepositoryInterface
	keyRotationPolicyRepository  repositories.KeyRotationPolicyRepositoryInterface
	sessionRepository            repositories.SessionRepositoryInterface
	vaultRepository              repositories.VaultRepositoryInterface
	auditRepository              repositories.AuditRepositoryExtended

	// Audit services
	auditService            auditServices.AuditServiceInterface
	complianceReportService auditServices.ComplianceReportServiceInterface

	// Authentication services
	passwordService       authServices.PasswordService
	totpService           authServices.TOTPService
	jwtService            authServices.JWTService
	authenticationService authServices.AuthenticationService
	oidcService           authServices.OIDCService

	// Authorization services
	rbacService              authzServices.RBACService
	accessPolicyRepository   repositories.AccessPolicyRepositoryInterface
	accessPolicyService      authzServices.AccessPolicyService
	roleAssignmentRepository repositories.RoleAssignmentRepositoryInterface
	roleAssignmentService    authzServices.RoleAssignmentService

	// Provisioning
	vaultProvisioningGrantRepository repositories.VaultProvisioningGrantRepositoryInterface
	grantService                     provisioning.GrantService

	// OAuth2 service account services
	oauth2ClientRepository repositories.OAuth2ClientRepositoryInterface
	oauth2Service          oauth2Services.OAuth2Service

	// Business services
	userService         userServices.UserService
	secretService       secrets.SecretService
	keyService          keyServices.KeyService
	certificateService  certServices.CertificateService
	certRenewalService  certServices.CertificateRenewalService
	keyCryptoService    keyServices.CryptoService
	vaultService        vaultServices.VaultService
	vaultWebhookService vaultServices.VaultWebhookService

	// Secret component services
	cryptoService     secretServices.CryptographyService
	versioningService secretServices.VersioningServiceInterface
	tagService        secretServices.TagService
	rotationService   secretServices.RotationServiceInterface
	schedulerService  secretServices.SchedulerServiceInterface

	// Retry services
	retryService retryServices.RetryService

	// JWT signing provider
	signingProvider signing.SigningKeyProvider

	// Per-item backup service
	itemBackupService *backup.ItemBackupService

	// Key provider (software or PKCS#11 HSM).
	keyProvider crypto.KeyProvider

	// Key cache for decrypted key material.
	keyCache keycache.Cache
	// Prometheus metrics for crypto operations.
	cryptoMetrics metrics.CryptoMetrics

	// rocketMemClient is the single shared L2 connection backing every
	// domain's TieredCache (Plans 05-08). nil when cache.rocket_mem is
	// disabled. Not exposed via ServiceContainerInterface -- nothing outside
	// this package constructs a TieredCache, so no getter is needed yet.
	rocketMemClient *rocketmemcache.Client

	// rocketMemSupervisorCancel stops the background reconnect supervisor
	// goroutine (internal/rocketmemcache.Client.RunSupervisor). nil when
	// cache.rocket_mem is disabled. Called once, from Close(), before
	// closing rocketMemClient itself, so the goroutine exits before its
	// underlying connection pool is torn out from under it.
	rocketMemSupervisorCancel context.CancelFunc
}

// Config holds configuration for the service container.
type Config struct {
	Database    *sql.DB
	Logger      *logging.Logger
	CacheConfig *rvconfig.CacheConfig
	Viper       *viper.Viper // Configuration manager for retry policies and other settings

	// RocketMemConfig overrides the loaded cache.rocket_mem.* config, mirroring
	// CacheConfig's own override field -- nil means "load from Viper".
	RocketMemConfig *rvconfig.RocketMemConfig
}

// NewServiceContainer creates a new service container with the provided configuration.
// It initializes all services and their dependencies in the correct order.
//
// Parameters:
//
//	config: Configuration containing database, logger, and cache settings.
//
// Returns:
//
//	A ServiceContainer with all services properly initialized.
func NewServiceContainer(config Config) (*ServiceContainer, error) {
	// Resolve the SQL dialect from configuration so repositories rebind "?"
	// placeholders correctly for the active engine. Defaults to SQLite.
	dialect := db.DialectFromDriver(viper.GetString("database.driver"))

	// Wrap the raw handle so every repository query routes through the dialect.
	// config.Database may be nil on the unit-test path; conn stays nil then.
	var conn *db.Conn
	if config.Database != nil {
		conn = db.NewConn(config.Database, dialect)
	}

	container := &ServiceContainer{
		db:     config.Database,
		conn:   conn,
		logger: config.Logger,
		viper:  config.Viper,
	}

	if config.CacheConfig == nil {
		loaded, err := rvconfig.LoadCacheConfig()
		if err != nil {
			return nil, fmt.Errorf("load cache config: %w", err)
		}
		config.CacheConfig = &loaded
	}
	container.cacheConfig = *config.CacheConfig

	if config.RocketMemConfig == nil {
		loaded, err := rvconfig.LoadRocketMemConfig()
		if err != nil {
			return nil, fmt.Errorf("load rocket_mem config: %w", err)
		}
		config.RocketMemConfig = &loaded
	}
	if config.RocketMemConfig.Enabled {
		container.rocketMemClient = rocketmemcache.New(rocketmemcache.Config{
			Addr:         config.RocketMemConfig.Addr,
			ClusterMode:  config.RocketMemConfig.ClusterMode,
			Addrs:        config.RocketMemConfig.Addrs,
			TLS:          config.RocketMemConfig.TLS,
			CAPath:       config.RocketMemConfig.CAPath,
			Username:     config.RocketMemConfig.Username,
			Password:     config.RocketMemConfig.Password,
			DialTimeout:  config.RocketMemConfig.DialTimeout,
			ReadTimeout:  config.RocketMemConfig.ReadTimeout,
			WriteTimeout: config.RocketMemConfig.WriteTimeout,
			PoolSize:     config.RocketMemConfig.PoolSize,
			Logger:       container.logger.Logger,
		})
		// One-shot, non-fatal reachability check: a fully-broken L2 (wrong
		// TLS cert, bad ACL credentials, unreachable) must not abort
		// startup -- the data plane always has L1 (or the DB) to fall back
		// on -- but it must not look identical to a healthy L2 either, so
		// log loudly here rather than only on the first real operation.
		if err := container.rocketMemClient.Ping(); err != nil {
			container.logger.WithError(err).Warn("rocket_mem cache tier enabled but unreachable at startup; continuing with L1-only caching until it recovers")
		} else if config.RocketMemConfig.ClusterMode {
			container.logger.WithField("addrs", config.RocketMemConfig.Addrs).Info("rocket_mem cache tier connected (cluster mode)")
		} else {
			container.logger.WithField("addr", config.RocketMemConfig.Addr).Info("rocket_mem cache tier connected")
		}

		supervisorCtx, cancelSupervisor := context.WithCancel(context.Background())
		container.rocketMemSupervisorCancel = cancelSupervisor
		go container.rocketMemClient.RunSupervisor(supervisorCtx, rocketmemcache.ReconnectPolicy{
			SteadyStateInterval: config.RocketMemConfig.ReconnectSteadyStateInterval,
			InitialBackoff:      config.RocketMemConfig.ReconnectInitialBackoff,
			MaxBackoff:          config.RocketMemConfig.ReconnectMaxBackoff,
			BackoffMultiplier:   config.RocketMemConfig.ReconnectBackoffMultiplier,
		})
	}

	if err := container.initializeServices(); err != nil {
		return nil, fmt.Errorf("failed to initialize services: %w", err)
	}

	return container, nil
}

// initializeServices creates and wires all services in dependency order.
func (c *ServiceContainer) initializeServices() error {
	// Resolve the viper instance to use for config reads.
	// Falls back to the global viper populated by initConfig() when none was injected.
	viperCfg := c.viper
	if viperCfg == nil {
		viperCfg = viper.GetViper()
	}

	// Load the instance-wide purge safety switch. Read directly from Viper
	// (like CacheConfig's no-override path) since every container -- HTTP
	// bootstrap and the CLI's own container in cmd/root.go alike -- must see
	// the same value.
	c.globalPurgeProtection = rvconfig.LoadSoftDeleteConfig().PurgeProtection

	// Initialize repositories (data layer). They receive the dialect-aware conn
	// so every query is rebound for the active engine.
	c.userRepository = repositories.NewUserRepository(c.conn, c.logger)
	c.secretRepository = repositories.NewSecretRepository(c.conn, c.logger)
	c.rotationRepository = repositories.NewRotationPolicyRepository(c.conn, c.logger)
	c.versionRepository = repositories.NewSecretVersionRepository(c.conn, c.logger)
	c.keyRepository = repositories.NewKeyRepository(c.conn, c.logger)
	c.certificateRepository = repositories.NewCertificateRepository(c.conn, c.logger)
	c.certificateVersionRepository = repositories.NewCertificateVersionRepository(c.conn, c.logger)
	c.vaultRepository = repositories.NewVaultRepository(c.conn, c.logger)
	vaultCascade := vaultServices.NewCascadeAdapter(c.secretRepository, c.keyRepository, c.certificateRepository)
	c.vaultService = vaultServices.NewVaultService(c.vaultRepository, vaultCascade, c.logger)
	c.vaultService.SetGlobalPurgeProtection(c.globalPurgeProtection)
	c.vaultService.SetTxBeginner(c.conn)
	if c.rocketMemClient != nil {
		c.vaultCache = vaultcache.NewCacheWithL2(c.cacheConfig.Vaults, c.rocketMemClient, c.cacheConfig.Vaults.TTL)
	} else {
		c.vaultCache = vaultcache.NewCache(c.cacheConfig.Vaults)
	}
	c.vaultService.SetVaultCache(c.vaultCache)
	vaultWebhookRepo := repositories.NewVaultWebhookRepository(c.conn, c.logger)
	c.vaultWebhookService = vaultServices.NewVaultWebhookService(vaultWebhookRepo, c.logger)
	c.vaultService.SetWebhookCleaner(vaultWebhookRepo)
	c.certPolicyRepository = repositories.NewCertificatePolicyRepository(c.conn, c.logger)
	c.keyRotationPolicyRepository = repositories.NewKeyRotationPolicyRepository(c.conn, c.logger)
	c.sessionRepository = repositories.NewSessionRepository(repositories.SessionRepositoryConfig{
		DB:     c.conn,
		Logger: c.logger,
	})
	c.auditRepository = repositories.NewAuditRepository(c.conn)
	c.auditService = auditServices.NewAuditService(c.auditRepository)
	c.complianceReportService = auditServices.NewComplianceReportService(c.auditRepository)
	c.logger.SetAuditPersister(c.auditService)

	// Start daily audit log retention purge in the background.
	go func() {
		ticker := time.NewTicker(24 * time.Hour)
		defer ticker.Stop()
		for range ticker.C {
			if _, err := c.complianceReportService.PurgeExpiredLogs(context.Background()); err != nil {
				c.logger.WithError(err).Warn("audit retention purge failed")
			}
		}
	}()

	// Secret cache is always constructed: a real cache when enabled, a
	// no-op one otherwise, so downstream code never nil-checks it.
	if c.rocketMemClient != nil {
		c.secretCache = cache.NewSecretCacheWithL2(c.cacheConfig.Secrets, c.logger.Logger, c.rocketMemClient, c.cacheConfig.Secrets.TTL)
	} else {
		c.secretCache = cache.NewSecretCache(c.cacheConfig.Secrets, c.logger.Logger)
	}
	c.vaultService.SetSecretCacheFlusher(c.secretCache)

	// Certificate cache is always constructed: a real cache when enabled, a
	// no-op one otherwise, so downstream code never nil-checks it.
	if c.rocketMemClient != nil {
		c.certCache = certcache.NewCacheWithL2(c.cacheConfig.Certificates, c.logger.Logger, c.rocketMemClient, c.cacheConfig.Certificates.TTL)
	} else {
		c.certCache = certcache.NewCache(c.cacheConfig.Certificates, c.logger.Logger)
	}

	// Initialize retry service before any service that wraps with retry logic.
	if c.viper != nil {
		retrySvc, err := retryServices.NewRetryService(viperCfg)
		if err != nil {
			c.logger.WithError(err).Warn("Failed to initialize retry service, continuing without retry functionality")
			// Continue without retry service - operations will not have retry.
		} else {
			c.retryService = retrySvc
			c.logger.Info("Retry service initialized successfully")
		}
	} else {
		c.logger.Warn("Viper configuration not provided, retry service will not be available")
	}

	// Initialize authentication services
	c.passwordService = authServices.NewPasswordService()
	c.totpService = authServices.NewTOTPService()

	// Initialize cryptography service early — needed by SelfPKIProvider.
	c.cryptoService = secretServices.NewCryptographyService()

	// Initialize JWT signing provider. Asymmetric signing is mandatory: there
	// is no symmetric fallback, so a provider failure must abort startup.
	signingDeps := signing.ProviderDeps{
		CryptoService: c.cryptoService,
		KeyRepository: c.keyRepository,
	}
	provider, err := signing.NewProvider(viperCfg, signingDeps)
	if err != nil {
		return fmt.Errorf("JWT signing provider initialisation failed: %w", err)
	}
	c.signingProvider = provider

	// Initialize JWT service with configuration.
	jwtExpiry := viperCfg.GetDuration("jwt.expiry")
	if jwtExpiry == 0 {
		jwtExpiry = time.Hour // Default to 1 hour.
	}
	jwtConfig := authServices.JWTConfig{
		Issuer:   viperCfg.GetString("oauth2.issuer"),
		Audience: "PASSWORD_MANAGER",
		Expiry:   jwtExpiry,
		Logger:   c.logger.Logger,
	}

	c.jwtService = authServices.NewJWTServiceWithProvider(jwtConfig, provider)

	// Initialize OAuth2 client repository first — the auth service needs it to
	// validate service-account tokens against the live client record.
	c.oauth2ClientRepository = repositories.NewOAuth2ClientRepository(c.conn)

	// Initialize authentication service
	baseAuthService := authServices.NewAuthenticationService(authServices.AuthenticationConfig{
		UserRepository:         c.userRepository,
		SessionRepository:      c.sessionRepository,
		PasswordService:        c.passwordService,
		TOTPService:            c.totpService,
		JWTService:             c.jwtService,
		OAuth2ClientRepository: c.oauth2ClientRepository,
		Logger:                 c.logger,
		AuditService:           c.auditService,
	})

	// Wrap with retry logic if retry service is available.
	if c.retryService != nil {
		c.authenticationService = retryServices.NewRetryAuthenticationService(baseAuthService, c.retryService)
		c.logger.Info("Retry logic enabled for authentication service")
	} else {
		c.authenticationService = baseAuthService
	}

	// Initialize OIDC service if configured. This is fully optional: unlike
	// every other service constructed in this method, oidc.NewOIDCService
	// makes a real network call (fetching the issuer's discovery document),
	// so it is skipped entirely — not attempted and swallowed — when
	// oidc.enabled is false or unset, the default.
	if viperCfg.GetBool("oidc.enabled") {
		oidcCfg := authServices.OIDCConfig{
			IssuerURL:     viperCfg.GetString("oidc.issuer_url"),
			ClientID:      viperCfg.GetString("oidc.client_id"),
			ClientSecret:  viperCfg.GetString("oidc.client_secret"),
			RedirectURL:   viperCfg.GetString("oidc.redirect_url"),
			Scopes:        viperCfg.GetStringSlice("oidc.scopes"),
			CACertPath:    viperCfg.GetString("oidc.ca_cert_path"),
			RetryExecutor: c.retryService,
		}
		oidcSvc, err := authServices.NewOIDCService(context.Background(), oidcCfg)
		if err != nil {
			c.logger.WithError(err).Warn("Failed to initialise OIDC service; OIDC login will be unavailable")
		} else {
			c.oidcService = oidcSvc
			c.logger.Info("OIDC service initialised")
		}
	}

	// Initialize authorization services
	c.rbacService = authzServices.NewRBACService(c.logger)
	c.accessPolicyRepository = repositories.NewAccessPolicyRepository(c.conn)
	c.accessPolicyService = authzServices.NewAccessPolicyService(c.accessPolicyRepository)
	// Wire the policy cleaner now that the access-policy repository exists; the vault
	// service deletes vault-scoped policies on purge since access_policies has no FK to vaults.
	c.vaultService.SetPolicyCleaner(c.accessPolicyRepository)
	// Wire the policy-vault lister now that the access-policy repository
	// exists; ListVaultsScoped's non-admin path uses it to answer "what can
	// this principal reach" instead of returning every vault.
	c.vaultService.SetPolicyVaultLister(c.accessPolicyRepository)
	c.roleAssignmentRepository = repositories.NewRoleAssignmentRepository(c.conn)
	// Wire the role-assignment cleaner now that its repository exists; the
	// vault service deletes vault-scoped assignments on purge because the FK
	// cascade is inert on SQLite.
	c.vaultService.SetRoleAssignmentCleaner(c.roleAssignmentRepository)
	c.roleAssignmentService = authzServices.NewRoleAssignmentService(
		c.roleAssignmentRepository,
		c.accessPolicyRepository,
		c.userRepository,
		c.logger,
	)
	c.vaultProvisioningGrantRepository = repositories.NewVaultProvisioningGrantRepository(c.conn)
	c.grantService = provisioning.NewGrantService(c.vaultProvisioningGrantRepository, c.logger)
	// Wire the quota-bounded create path now that the grant repository and the
	// access-policy/role-assignment repositories all exist: the row-lock
	// quota check, and the creator's grant of full rights over what it
	// provisions, both run inside CreateVaultProvisioned's own transaction.
	c.vaultService.SetGrantLocker(c.vaultProvisioningGrantRepository)
	c.vaultService.SetCreatorGranter(&creatorGranterAdapter{
		policies: c.accessPolicyRepository,
		roles:    c.roleAssignmentRepository,
	})

	// Initialize remaining OAuth2 services (client repo already set above).
	oauth2TokenExpiry := viperCfg.GetDuration("oauth2.token_expiry")
	if oauth2TokenExpiry == 0 {
		oauth2TokenExpiry = 30 * time.Minute
	}
	c.oauth2Service = oauth2Services.NewOAuth2Service(oauth2Services.OAuth2Config{
		ClientRepo:      c.oauth2ClientRepository,
		PasswordService: c.passwordService,
		JWTService:      c.jwtService,
		TokenExpiry:     oauth2TokenExpiry,
	})

	// Initialize user service
	baseUserService := userServices.NewUserService(userServices.UserServiceConfig{
		UserRepository:  c.userRepository,
		PasswordService: c.passwordService,
		TOTPService:     c.totpService,
		Logger:          c.logger,
	})

	// Wrap with retry logic if retry service is available
	if c.retryService != nil {
		c.userService = retryServices.NewRetryUserService(baseUserService, c.retryService)
		c.logger.Info("Retry logic enabled for user service")
	} else {
		c.userService = baseUserService
	}

	// Rollback and rotation update the secrets table directly instead of going
	// through CachedSecretService, so they take their own invalidator.
	// c.secretCache is always constructed (real-or-no-op internally), so
	// this is never a nil interface.
	secretCacheInvalidator := secretServices.SecretCacheInvalidator(c.secretCache)

	// Initialize secret component services (cryptoService already initialised above).
	c.versioningService = secretServices.NewVersioningService(
		c.versionRepository,
		c.secretRepository,
		c.userRepository,
		c.cryptoService,
		c.logger,
		secretCacheInvalidator,
	)
	c.tagService = secretServices.NewTagService(repositories.NewSecretTagRepository(c.conn), c.logger)
	c.rotationService = secretServices.NewRotationService(
		c.rotationRepository,
		c.secretRepository,
		c.userRepository,
		c.cryptoService,
		c.versioningService,
		c.logger,
		secretCacheInvalidator,
	)
	c.schedulerService = secretServices.NewSchedulerService(
		c.rotationService,
		c.versioningService,
		c.userRepository,
		c.secretRepository,
		c.rotationRepository,
		c.logger,
	)

	// Initialize secret service
	baseSecretService := secretServices.NewSecretService(secretServices.SecretServiceConfig{
		SecretRepository:      c.secretRepository,
		CryptoService:         c.cryptoService,
		VersionService:        c.versioningService,
		TagService:            c.tagService,
		Logger:                c.logger,
		VaultRepository:       c.vaultRepository,
		GlobalPurgeProtection: c.globalPurgeProtection,
	})

	// Wrap with retry logic if retry service is available
	var retryEnabledSecretService secrets.SecretService
	if c.retryService != nil {
		// Create retry-aware secret service
		retryEnabledSecretService = retryServices.NewRetrySecretService(baseSecretService, c.retryService)
		c.logger.Info("Retry logic enabled for secret service")
	} else {
		retryEnabledSecretService = baseSecretService
	}

	// Always wrap: on a disabled (no-op) cache, CachedSecretService's Get
	// always misses and falls through to retryEnabledSecretService, which is
	// functionally identical to not wrapping — one fewer branch to reason about.
	c.cachedSecretService = cache.NewCachedSecretService(retryEnabledSecretService, c.secretCache, c.logger.Logger)
	c.secretService = c.cachedSecretService

	// Key cache is always constructed via the unified cache.keys.* config.
	if c.rocketMemClient != nil {
		c.keyCache = keycache.NewCacheWithL2(c.cacheConfig.Keys, c.rocketMemClient, c.cacheConfig.Keys.TTL)
	} else {
		c.keyCache = keycache.NewCache(c.cacheConfig.Keys)
	}

	// Initialize Prometheus metrics for crypto operations.
	c.cryptoMetrics = metrics.NewDefaultPrometheusCryptoMetrics()

	// Select key provider based on hsm.enabled config.
	if viperCfg.GetBool("hsm.enabled") {
		hsmCfg := crypto.PKCS11Config{
			LibPath:    viperCfg.GetString("hsm.lib_path"),
			TokenLabel: viperCfg.GetString("hsm.token_label"),
			PIN:        viperCfg.GetString("hsm.pin"),
			SlotID:     uint(viperCfg.GetUint("hsm.slot_id")),
		}
		p11Provider, p11Err := crypto.NewPKCS11KeyProvider(hsmCfg)
		if p11Err != nil {
			return fmt.Errorf("failed to initialise PKCS#11 key provider: %w", p11Err)
		}
		c.keyProvider = p11Provider
		c.logger.Info("PKCS#11 HSM key provider initialised")
	} else {
		c.keyProvider = crypto.NewSoftwareKeyProvider()
		c.logger.Info("Software key provider initialised (HSM disabled)")
	}

	// Initialize key service with cache for invalidation on mutations.
	baseKeyService := keyServices.NewKeyService(keyServices.KeyServiceConfig{
		KeyRepository:         c.keyRepository,
		KeyProvider:           c.keyProvider,
		KeyCache:              c.keyCache,
		PolicyRepository:      c.keyRotationPolicyRepository,
		Logger:                c.logger,
		VaultRepository:       c.vaultRepository,
		GlobalPurgeProtection: c.globalPurgeProtection,
	})

	// Wrap with retry logic if retry service is available.
	if c.retryService != nil {
		c.keyService = retryServices.NewRetryKeyService(baseKeyService, c.retryService)
		c.logger.Info("Retry logic enabled for key service")
	} else {
		c.keyService = baseKeyService
	}

	// Initialize crypto service with cache and Prometheus metrics.
	c.keyCryptoService = keyServices.NewCryptoService(keyServices.CryptoServiceConfig{
		KeyRepository: c.keyRepository,
		KeyProvider:   c.keyProvider,
		KeyCache:      c.keyCache,
		CryptoMetrics: c.cryptoMetrics,
		Logger:        c.logger,
	})

	// Initialize certificate service
	baseCertificateService := certServices.NewCertificateService(certServices.CertificateServiceConfig{
		CertificateRepository: c.certificateRepository,
		VersionRepository:     c.certificateVersionRepository,
		KeyRepository:         c.keyRepository,
		PolicyRepository:      c.certPolicyRepository,
		Logger:                c.logger,
		VaultRepository:       c.vaultRepository,
		GlobalPurgeProtection: c.globalPurgeProtection,
	})

	// Wrap with retry logic if retry service is available.
	var retryEnabledCertificateService certServices.CertificateService
	if c.retryService != nil {
		retryEnabledCertificateService = retryServices.NewRetryCertificateService(baseCertificateService, c.retryService)
		c.logger.Info("Retry logic enabled for certificate service")
	} else {
		retryEnabledCertificateService = baseCertificateService
	}

	// Wrap with caching. c.certCache is always constructed (real-or-no-op
	// internally), so this is safe unconditionally.
	c.cachedCertificateService = certcache.NewCachedCertificateService(retryEnabledCertificateService, c.certCache, c.logger.Logger)
	c.certificateService = c.cachedCertificateService

	// Initialize certificate renewal service.
	c.certRenewalService = certServices.NewCertificateRenewalService(certServices.RenewalServiceConfig{
		CertRepository:     c.certificateRepository,
		CertificateService: c.certificateService,
		Logger:             c.logger,
	})

	// Initialize per-item backup service.
	c.itemBackupService = backup.NewItemBackupService(
		c.secretRepository,
		c.keyRepository,
		c.certificateRepository,
		c.versionRepository,
	)
	// Makes RestoreSecret/RestoreKey/RestoreCertificate atomic (F3): a
	// failure partway through a restore rolls back everything already
	// written, instead of leaving a partial row under an ID the caller
	// never received. See vaultService.SetTxBeginner above for the same
	// pattern.
	c.itemBackupService.SetTxBeginner(c.conn)
	// Certificate backups carry their archived versions, and restores
	// replay them in the same transaction.
	c.itemBackupService.SetCertificateVersionRepository(c.certificateVersionRepository)

	return nil
}

// GetUserRepository returns the user repository.
func (c *ServiceContainer) GetUserRepository() repositories.UserRepositoryInterface {
	return c.userRepository
}

// GetSecretRepository returns the secret repository.
func (c *ServiceContainer) GetSecretRepository() repositories.SecretRepositoryInterface {
	return c.secretRepository
}

// GetPasswordService returns the password service.
func (c *ServiceContainer) GetPasswordService() authServices.PasswordService {
	return c.passwordService
}

// GetTOTPService returns the TOTP service.
func (c *ServiceContainer) GetTOTPService() authServices.TOTPService {
	return c.totpService
}

// GetJWTService returns the JWT service.
func (c *ServiceContainer) GetJWTService() authServices.JWTService {
	return c.jwtService
}

// GetAuthenticationService returns the authentication service.
func (c *ServiceContainer) GetAuthenticationService() authServices.AuthenticationService {
	return c.authenticationService
}

// GetOIDCService returns the OIDC authentication service, or nil if OIDC is
// not configured.
func (c *ServiceContainer) GetOIDCService() authServices.OIDCService {
	return c.oidcService
}

// GetRBACService returns the RBAC service.
func (c *ServiceContainer) GetRBACService() authzServices.RBACService {
	return c.rbacService
}

// GetAccessPolicyRepository returns the access policy repository.
func (c *ServiceContainer) GetAccessPolicyRepository() repositories.AccessPolicyRepositoryInterface {
	return c.accessPolicyRepository
}

// GetAccessPolicyService returns the access policy service.
func (c *ServiceContainer) GetAccessPolicyService() authzServices.AccessPolicyService {
	return c.accessPolicyService
}

// GetRoleAssignmentService returns the role assignment service.
func (c *ServiceContainer) GetRoleAssignmentService() authzServices.RoleAssignmentService {
	return c.roleAssignmentService
}

// GetGrantService returns the vault-provisioning grant service.
func (c *ServiceContainer) GetGrantService() provisioning.GrantService {
	return c.grantService
}

// GetOAuth2ClientRepository returns the OAuth2 client repository.
func (c *ServiceContainer) GetOAuth2ClientRepository() repositories.OAuth2ClientRepositoryInterface {
	return c.oauth2ClientRepository
}

// GetOAuth2Service returns the OAuth2 service for token issuance and service account management.
func (c *ServiceContainer) GetOAuth2Service() oauth2Services.OAuth2Service {
	return c.oauth2Service
}

// GetUserService returns the user service.
func (c *ServiceContainer) GetUserService() userServices.UserService {
	return c.userService
}

// GetSecretService returns the secret service.
func (c *ServiceContainer) GetSecretService() secretServices.SecretService {
	return c.secretService
}

// GetCryptographyService returns the cryptography service.
func (c *ServiceContainer) GetCryptographyService() secretServices.CryptographyService {
	return c.cryptoService
}

// GetVersioningService returns the versioning service.
func (c *ServiceContainer) GetVersioningService() secretServices.VersioningServiceInterface {
	return c.versioningService
}

// GetTagService returns the tag service.
func (c *ServiceContainer) GetTagService() secretServices.TagService {
	return c.tagService
}

// GetRotationRepository returns the rotation policy repository.
func (c *ServiceContainer) GetRotationRepository() repositories.RotationPolicyRepositoryInterface {
	return c.rotationRepository
}

// GetVersionRepository returns the secret version repository.
func (c *ServiceContainer) GetVersionRepository() repositories.SecretVersionRepositoryInterface {
	return c.versionRepository
}

// GetRotationService returns the rotation service.
func (c *ServiceContainer) GetRotationService() secretServices.RotationServiceInterface {
	return c.rotationService
}

// GetSchedulerService returns the scheduler service.
func (c *ServiceContainer) GetSchedulerService() secretServices.SchedulerServiceInterface {
	return c.schedulerService
}

// GetDatabase returns the database connection.
func (c *ServiceContainer) GetDatabase() *sql.DB {
	return c.db
}

// GetLogger returns the logger.
func (c *ServiceContainer) GetLogger() *logging.Logger {
	return c.logger
}

// GetKeyRepository returns the key repository.
func (c *ServiceContainer) GetKeyRepository() repositories.KeyRepositoryInterface {
	return c.keyRepository
}

// GetCertificateRepository returns the certificate repository.
func (c *ServiceContainer) GetCertificateRepository() repositories.CertificateRepositoryInterface {
	return c.certificateRepository
}

// GetCertificatePolicyRepository returns the certificate policy repository.
func (c *ServiceContainer) GetCertificatePolicyRepository() repositories.CertificatePolicyRepositoryInterface {
	return c.certPolicyRepository
}

// GetKeyRotationPolicyRepository returns the per-key rotation policy repository.
func (c *ServiceContainer) GetKeyRotationPolicyRepository() repositories.KeyRotationPolicyRepositoryInterface {
	return c.keyRotationPolicyRepository
}

// GetVaultRepository returns the vault repository.
func (c *ServiceContainer) GetVaultRepository() repositories.VaultRepositoryInterface {
	return c.vaultRepository
}

// GetVaultService returns the vault lifecycle service.
func (c *ServiceContainer) GetVaultService() vaultServices.VaultService {
	return c.vaultService
}

// GetVaultWebhookService returns the per-vault webhook configuration service.
func (c *ServiceContainer) GetVaultWebhookService() vaultServices.VaultWebhookService {
	return c.vaultWebhookService
}

// GetSessionRepository returns the session repository.
func (c *ServiceContainer) GetSessionRepository() repositories.SessionRepositoryInterface {
	return c.sessionRepository
}

// GetKeyService returns the key service.
func (c *ServiceContainer) GetKeyService() keyServices.KeyService {
	return c.keyService
}

// GetCertificateService returns the certificate service.
func (c *ServiceContainer) GetCertificateService() certServices.CertificateService {
	return c.certificateService
}

// GetCertificateRenewalService returns the certificate renewal service.
func (c *ServiceContainer) GetCertificateRenewalService() certServices.CertificateRenewalService {
	return c.certRenewalService
}

// GetCryptoService returns the key crypto service for wrap/unwrap operations.
func (c *ServiceContainer) GetCryptoService() keyServices.CryptoService {
	return c.keyCryptoService
}

// GetSecretCache returns the secret cache (if enabled).
func (c *ServiceContainer) GetSecretCache() *cache.SecretCache {
	return c.secretCache
}

// GetCacheConfig returns the cache configuration.
func (c *ServiceContainer) GetCacheConfig() rvconfig.CacheConfig {
	return c.cacheConfig
}

// GetCachedSecretService returns the cached secret service (if caching is enabled).
func (c *ServiceContainer) GetCachedSecretService() secrets.SecretService {
	return c.cachedSecretService
}

// GetVaultCache returns the vault-by-name cache.
func (c *ServiceContainer) GetVaultCache() *vaultcache.Cache {
	return c.vaultCache
}

// GetCertificateCache returns the in-process certificate cache.
func (c *ServiceContainer) GetCertificateCache() *certcache.Cache {
	return c.certCache
}

// GetRetryService returns the retry service for handling retry logic.
func (c *ServiceContainer) GetRetryService() retryServices.RetryService {
	return c.retryService
}

// GetSigningProvider returns the JWT signing key provider.
func (c *ServiceContainer) GetSigningProvider() signing.SigningKeyProvider {
	return c.signingProvider
}

// GetItemBackupService returns the per-item backup service.
func (c *ServiceContainer) GetItemBackupService() *backup.ItemBackupService {
	return c.itemBackupService
}

// Close closes the service container and cleans up resources.
func (c *ServiceContainer) Close() error {
	// Stop the secret cache background sweeper.
	if c.secretCache != nil {
		c.secretCache.Stop()
	}

	// Stop the key cache background sweeper.
	if c.keyCache != nil {
		c.keyCache.Stop()
	}

	// Stop the vault cache background sweeper.
	if c.vaultCache != nil {
		c.vaultCache.Stop()
	}

	// Stop the certificate cache background sweeper.
	if c.certCache != nil {
		c.certCache.Stop()
	}

	if c.keyProvider != nil {
		if err := c.keyProvider.Close(); err != nil {
			c.logger.WithError(err).Warn("Failed to close key provider")
		}
	}

	if c.rocketMemSupervisorCancel != nil {
		c.rocketMemSupervisorCancel()
	}
	if c.rocketMemClient != nil {
		if err := c.rocketMemClient.Close(); err != nil {
			c.logger.WithError(err).Warn("Failed to close rocket-mem client")
		}
	}

	if c.db != nil {
		return c.db.Close()
	}
	return nil
}

// GetKeyProvider returns the active key provider (software or PKCS#11).
func (c *ServiceContainer) GetKeyProvider() crypto.KeyProvider {
	return c.keyProvider
}

// GetKeyCache returns the in-process key cache.
func (c *ServiceContainer) GetKeyCache() keycache.Cache {
	return c.keyCache
}

// GetCryptoMetrics returns the Prometheus crypto metrics recorder.
func (c *ServiceContainer) GetCryptoMetrics() metrics.CryptoMetrics {
	return c.cryptoMetrics
}

// GetAuditService returns the audit event write-path service.
func (c *ServiceContainer) GetAuditService() auditServices.AuditServiceInterface {
	return c.auditService
}

// GetComplianceReportService returns the compliance report read-path service.
func (c *ServiceContainer) GetComplianceReportService() auditServices.ComplianceReportServiceInterface {
	return c.complianceReportService
}
