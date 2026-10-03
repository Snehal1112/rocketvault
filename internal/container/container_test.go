// Package container contains unit tests for the ServiceContainer dependency
// injection layer. Tests are in the same package to allow direct access to
// unexported struct fields without any reflection tricks.
package container

import (
	"context"
	"database/sql"
	"encoding/base64"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	_ "github.com/mattn/go-sqlite3"
	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	rvconfig "rocketvault/config"
	"rocketvault/internal/cache"
	"rocketvault/internal/cachekit"
	rvdb "rocketvault/internal/db"
	"rocketvault/internal/keycache"
	"rocketvault/internal/logging"
	"rocketvault/internal/retry"
	authServices "rocketvault/internal/services/auth"
	userServices "rocketvault/internal/services/users"
	vaultServices "rocketvault/internal/services/vaults"
	"rocketvault/internal/signing"
	"rocketvault/internal/vaultcache"
	"rocketvault/model"
)

// TestMain ensures every test in this package uses an in-memory fake OS
// keychain instead of the real one for jwt.key_source=os_store, so `go test`
// never touches the real GNOME Keyring / macOS Keychain / Windows Credential
// Manager entry that production uses by default ("jwt-signing-key-rocketvault").
func TestMain(m *testing.M) {
	restore := signing.UseFakeKeychainForTesting()
	code := m.Run()
	restore()
	os.Exit(code)
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

// newTestLogger returns a silent logrus-backed Logger so that test output
// stays clean.
func newTestLogger() *logging.Logger {
	l := logrus.New()
	l.SetLevel(logrus.PanicLevel) // suppress all log output during tests
	return logging.WrapLogrus(l)
}

// openSQLite opens a fresh in-memory SQLite database and registers it for
// cleanup when the test ends.
func openSQLite(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite3", ":memory:")
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })
	return db
}

// cacheConfigWithSecretsDisabled returns a valid CacheConfig -- loaded via
// rvconfig.LoadCacheConfig so every domain gets sane, validated defaults --
// with only the secrets cache turned off. This is the shape almost every
// "disabled cache" test in this file actually wants: Keys/Vaults stay
// enabled at their defaults, only Secrets.Enabled flips to false.
func cacheConfigWithSecretsDisabled(t *testing.T) *rvconfig.CacheConfig {
	t.Helper()
	cfg, err := rvconfig.LoadCacheConfig()
	require.NoError(t, err)
	cfg.Secrets.Enabled = false
	return &cfg
}

// newMinimalConfig returns a Config that has enough to bootstrap the container
// without touching the filesystem beyond what the OS key-store provider needs.
//
// The jwt.key_source defaults to "os_store" which auto-generates an RSA key
// when the keychain has no entry, so no jwt_secret is required.
func newMinimalConfig(t *testing.T) Config {
	t.Helper()
	v := viper.New()
	// Use os_store explicitly — it auto-generates a key and never errors.
	v.Set("jwt.key_source", "os_store")
	// Disable the secrets cache to avoid background goroutines in tests that
	// close quickly.
	return Config{
		Database:    openSQLite(t),
		Logger:      newTestLogger(),
		CacheConfig: cacheConfigWithSecretsDisabled(t),
		Viper:       v,
	}
}

// ---------------------------------------------------------------------------
// Test 1 — zero-value ServiceContainer returns nil from every getter
// ---------------------------------------------------------------------------

// TestGetters_ZeroValueContainer verifies that all getter methods return
// their zero value (nil interface / nil pointer / zero struct) on an
// uninitialised ServiceContainer. Each getter is a single-statement return,
// so calling every one drives all of those statements.
func TestGetters_ZeroValueContainer(t *testing.T) {
	c := &ServiceContainer{}

	// Repositories
	assert.Nil(t, c.GetUserRepository(), "GetUserRepository")
	assert.Nil(t, c.GetSecretRepository(), "GetSecretRepository")
	assert.Nil(t, c.GetRotationRepository(), "GetRotationRepository")
	assert.Nil(t, c.GetVersionRepository(), "GetVersionRepository")
	assert.Nil(t, c.GetKeyRepository(), "GetKeyRepository")
	assert.Nil(t, c.GetCertificateRepository(), "GetCertificateRepository")
	assert.Nil(t, c.GetCertificatePolicyRepository(), "GetCertificatePolicyRepository")
	assert.Nil(t, c.GetKeyRotationPolicyRepository(), "GetKeyRotationPolicyRepository")
	assert.Nil(t, c.GetSessionRepository(), "GetSessionRepository")
	assert.Nil(t, c.GetVaultRepository(), "GetVaultRepository")
	assert.Nil(t, c.GetAccessPolicyRepository(), "GetAccessPolicyRepository")
	assert.Nil(t, c.GetOAuth2ClientRepository(), "GetOAuth2ClientRepository")

	// Auth services
	assert.Nil(t, c.GetPasswordService(), "GetPasswordService")
	assert.Nil(t, c.GetTOTPService(), "GetTOTPService")
	assert.Nil(t, c.GetJWTService(), "GetJWTService")
	assert.Nil(t, c.GetAuthenticationService(), "GetAuthenticationService")
	assert.Nil(t, c.GetOIDCService(), "GetOIDCService")

	// Authorization services
	assert.Nil(t, c.GetRBACService(), "GetRBACService")
	assert.Nil(t, c.GetAccessPolicyService(), "GetAccessPolicyService")

	// Provisioning
	assert.Nil(t, c.GetGrantService(), "GetGrantService")

	// OAuth2
	assert.Nil(t, c.GetOAuth2Service(), "GetOAuth2Service")

	// Business services
	assert.Nil(t, c.GetUserService(), "GetUserService")
	assert.Nil(t, c.GetSecretService(), "GetSecretService")
	assert.Nil(t, c.GetKeyService(), "GetKeyService")
	assert.Nil(t, c.GetCertificateService(), "GetCertificateService")
	assert.Nil(t, c.GetCertificateRenewalService(), "GetCertificateRenewalService")
	assert.Nil(t, c.GetCryptoService(), "GetCryptoService")
	assert.Nil(t, c.GetVaultService(), "GetVaultService")
	assert.Nil(t, c.GetVaultWebhookService(), "GetVaultWebhookService")

	// Secret component services
	assert.Nil(t, c.GetCryptographyService(), "GetCryptographyService")
	assert.Nil(t, c.GetVersioningService(), "GetVersioningService")
	assert.Nil(t, c.GetTagService(), "GetTagService")
	assert.Nil(t, c.GetRotationService(), "GetRotationService")
	assert.Nil(t, c.GetSchedulerService(), "GetSchedulerService")

	// Infrastructure
	assert.Nil(t, c.GetDatabase(), "GetDatabase")
	assert.Nil(t, c.GetLogger(), "GetLogger")

	// Cache — an unconstructed zero-value container genuinely has nil/zero
	// cache fields; GetCacheConfig now returns a value type, so it is
	// asserted Zero rather than Nil.
	assert.Nil(t, c.GetSecretCache(), "GetSecretCache")
	assert.Zero(t, c.GetCacheConfig(), "GetCacheConfig")
	assert.Nil(t, c.GetCachedSecretService(), "GetCachedSecretService")
	assert.Nil(t, c.GetVaultCache(), "GetVaultCache")
	assert.Nil(t, c.GetCertificateCache(), "GetCertificateCache")

	// Retry
	assert.Nil(t, c.GetRetryService(), "GetRetryService")

	// Signing / key / metrics
	assert.Nil(t, c.GetSigningProvider(), "GetSigningProvider")
	assert.Nil(t, c.GetItemBackupService(), "GetItemBackupService")
	assert.Nil(t, c.GetKeyProvider(), "GetKeyProvider")
	assert.Nil(t, c.GetKeyCache(), "GetKeyCache")
	assert.Nil(t, c.GetCryptoMetrics(), "GetCryptoMetrics")

	// Audit
	assert.Nil(t, c.GetAuditService(), "GetAuditService")
	assert.Nil(t, c.GetComplianceReportService(), "GetComplianceReportService")
}

// ---------------------------------------------------------------------------
// Test 2 — Config struct zero-value
// ---------------------------------------------------------------------------

// TestConfig_ZeroValue confirms the Config struct is usable as a zero value
// (nil Database, Logger, CacheConfig, and Viper fields).
func TestConfig_ZeroValue(t *testing.T) {
	cfg := Config{}
	assert.Nil(t, cfg.Database)
	assert.Nil(t, cfg.Logger)
	assert.Nil(t, cfg.CacheConfig)
	assert.Nil(t, cfg.Viper)
}

// ---------------------------------------------------------------------------
// Test 3 — Close with all fields nil
// ---------------------------------------------------------------------------

// TestClose_AllFieldsNil verifies that Close() on a zero-value ServiceContainer
// returns nil without panicking. The secretCache, keyCache, vaultCache,
// keyProvider, and db fields are all nil — each guard in Close() must be
// exercised.
func TestClose_AllFieldsNil(t *testing.T) {
	c := &ServiceContainer{}
	err := c.Close()
	assert.NoError(t, err)
}

// ---------------------------------------------------------------------------
// Test 4 — Close stops the secret, key, and vault caches
// ---------------------------------------------------------------------------

// TestClose_StopsAllCaches exercises the secretCache/keyCache/vaultCache
// non-nil Stop() branches in Close(). cachekit.Cache self-manages its own
// sweep goroutine from construction, so Close() must call Stop() on each to
// avoid leaking it — this pins that all three guards fire without panicking.
func TestClose_StopsAllCaches(t *testing.T) {
	cfg := cachekit.Config{Enabled: true, TTL: time.Minute, CleanupInterval: time.Minute, MaxEntries: 10}
	c := &ServiceContainer{
		secretCache: cache.NewSecretCache(cfg, newTestLogger().Logger),
		keyCache:    keycache.NewCache(cfg),
		vaultCache:  vaultcache.NewCache(cfg),
	}
	err := c.Close()
	assert.NoError(t, err)
}

// ---------------------------------------------------------------------------
// Test 5 — Close with live database
// ---------------------------------------------------------------------------

// TestClose_WithDB exercises the db != nil branch in Close() and verifies the
// returned error propagates correctly (a closed DB returns nil from a second
// close, so we just check no unexpected error occurs).
func TestClose_WithDB(t *testing.T) {
	db, err := sql.Open("sqlite3", ":memory:")
	require.NoError(t, err)
	// Do NOT defer db.Close() here because Close() will close it for us.
	c := &ServiceContainer{db: db}
	err = c.Close()
	assert.NoError(t, err)
}

// ---------------------------------------------------------------------------
// Test 6 — NewServiceContainer success path (with secrets caching disabled)
// ---------------------------------------------------------------------------

// TestNewServiceContainer_Success_CacheDisabled bootstraps a full container
// against an in-memory SQLite database with the secrets cache turned off. It
// verifies that every core service getter returns a non-nil value after
// initialisation and that Close() tears everything down cleanly.
func TestNewServiceContainer_Success_CacheDisabled(t *testing.T) {
	cfg := newMinimalConfig(t)
	cfg.CacheConfig = cacheConfigWithSecretsDisabled(t)

	container, err := NewServiceContainer(cfg)
	require.NoError(t, err)
	require.NotNil(t, container)
	t.Cleanup(func() { _ = container.Close() })

	// Infrastructure
	assert.NotNil(t, container.GetDatabase(), "GetDatabase must not be nil after init")
	assert.NotNil(t, container.GetLogger(), "GetLogger must not be nil after init")

	// Repositories
	assert.NotNil(t, container.GetUserRepository(), "GetUserRepository")
	assert.NotNil(t, container.GetSecretRepository(), "GetSecretRepository")
	assert.NotNil(t, container.GetRotationRepository(), "GetRotationRepository")
	assert.NotNil(t, container.GetVersionRepository(), "GetVersionRepository")
	assert.NotNil(t, container.GetKeyRepository(), "GetKeyRepository")
	assert.NotNil(t, container.GetCertificateRepository(), "GetCertificateRepository")
	assert.NotNil(t, container.GetCertificatePolicyRepository(), "GetCertificatePolicyRepository")
	assert.NotNil(t, container.certificateVersionRepository, "certificateVersionRepository must be wired, or renewal fails closed")
	assert.NotNil(t, container.GetKeyRotationPolicyRepository(), "GetKeyRotationPolicyRepository")
	assert.NotNil(t, container.GetSessionRepository(), "GetSessionRepository")
	assert.NotNil(t, container.GetVaultRepository(), "GetVaultRepository")
	assert.NotNil(t, container.GetAccessPolicyRepository(), "GetAccessPolicyRepository")
	assert.NotNil(t, container.GetOAuth2ClientRepository(), "GetOAuth2ClientRepository")

	// Auth services
	assert.NotNil(t, container.GetPasswordService(), "GetPasswordService")
	assert.NotNil(t, container.GetTOTPService(), "GetTOTPService")
	assert.NotNil(t, container.GetJWTService(), "GetJWTService")
	assert.NotNil(t, container.GetAuthenticationService(), "GetAuthenticationService")
	assert.Nil(t, container.GetOIDCService(), "GetOIDCService") // oidc.enabled is false by default in every test fixture.

	// Authorization services
	assert.NotNil(t, container.GetRBACService(), "GetRBACService")
	assert.NotNil(t, container.GetAccessPolicyService(), "GetAccessPolicyService")

	// Provisioning
	assert.NotNil(t, container.GetGrantService(), "GetGrantService must be constructed during container initialization")

	// OAuth2
	assert.NotNil(t, container.GetOAuth2Service(), "GetOAuth2Service")

	// Business services
	assert.NotNil(t, container.GetUserService(), "GetUserService")
	assert.NotNil(t, container.GetSecretService(), "GetSecretService")
	assert.NotNil(t, container.GetKeyService(), "GetKeyService")
	assert.NotNil(t, container.GetCertificateService(), "GetCertificateService")
	assert.NotNil(t, container.GetCertificateRenewalService(), "GetCertificateRenewalService")
	assert.NotNil(t, container.GetCryptoService(), "GetCryptoService")
	assert.NotNil(t, container.GetVaultService(), "GetVaultService")
	assert.NotNil(t, container.GetVaultWebhookService(), "GetVaultWebhookService")

	// Secret component services
	assert.NotNil(t, container.GetCryptographyService(), "GetCryptographyService")
	assert.NotNil(t, container.GetVersioningService(), "GetVersioningService")
	assert.NotNil(t, container.GetTagService(), "GetTagService")
	assert.NotNil(t, container.GetRotationService(), "GetRotationService")
	assert.NotNil(t, container.GetSchedulerService(), "GetSchedulerService")

	// Cache — always constructed now (real-or-no-op internally), even with
	// the secrets domain disabled.
	assert.NotNil(t, container.GetSecretCache(), "GetSecretCache must always be non-nil (real or no-op)")
	assert.NotNil(t, container.GetCachedSecretService(), "GetCachedSecretService must always be non-nil (real or no-op)")
	assert.NotZero(t, container.GetCacheConfig().Secrets.TTL, "GetCacheConfig should return a populated config")
	assert.NotNil(t, container.GetVaultCache(), "GetVaultCache must always be non-nil (real or no-op)")
	assert.NotNil(t, container.GetCertificateCache(), "GetCertificateCache must always be non-nil (real or no-op)")

	// Signing / key / metrics
	assert.NotNil(t, container.GetSigningProvider(), "GetSigningProvider")
	assert.NotNil(t, container.GetItemBackupService(), "GetItemBackupService")
	assert.NotNil(t, container.GetKeyProvider(), "GetKeyProvider")
	assert.NotNil(t, container.GetKeyCache(), "GetKeyCache")
	assert.NotNil(t, container.GetCryptoMetrics(), "GetCryptoMetrics")

	// Audit
	assert.NotNil(t, container.GetAuditService(), "GetAuditService")
	assert.NotNil(t, container.GetComplianceReportService(), "GetComplianceReportService")

	// Retry service is nil because the injected Viper has no retry configuration
	// and the code intentionally skips retry when the RetryService init logs a
	// warning. That is fine — presence of the field is optional.
}

// ---------------------------------------------------------------------------
// Test 7 — NewServiceContainer success path (with caching enabled)
// ---------------------------------------------------------------------------

// TestNewServiceContainer_Success_CacheEnabled exercises the cache
// initialisation path in initializeServices with every domain at its default
// (enabled) settings, and confirms GetSecretCache, GetCachedSecretService,
// and GetVaultCache return non-nil values.
func TestNewServiceContainer_Success_CacheEnabled(t *testing.T) {
	v := viper.New()
	v.Set("jwt.key_source", "os_store")

	loaded, err := rvconfig.LoadCacheConfig()
	require.NoError(t, err)

	cfg := Config{
		Database:    openSQLite(t),
		Logger:      newTestLogger(),
		CacheConfig: &loaded, // Secrets.Enabled: true by default
		Viper:       v,
	}

	container, cerr := NewServiceContainer(cfg)
	require.NoError(t, cerr)
	require.NotNil(t, container)
	t.Cleanup(func() { _ = container.Close() })

	assert.NotNil(t, container.GetSecretCache(), "GetSecretCache must be non-nil when cache is enabled")
	assert.NotNil(t, container.GetCachedSecretService(), "GetCachedSecretService must be non-nil when cache is enabled")
	assert.NotZero(t, container.GetCacheConfig().Secrets.TTL, "GetCacheConfig should return a populated config")
	assert.NotNil(t, container.GetVaultCache(), "GetVaultCache")
	assert.NotNil(t, container.GetCertificateCache(), "GetCertificateCache")
}

// ---------------------------------------------------------------------------
// Test 8 — NewServiceContainer with nil CacheConfig falls back to default
// ---------------------------------------------------------------------------

// TestNewServiceContainer_NilCacheConfig confirms that a nil CacheConfig in the
// Config struct is replaced via rvconfig.LoadCacheConfig and does not panic.
func TestNewServiceContainer_NilCacheConfig(t *testing.T) {
	v := viper.New()
	v.Set("jwt.key_source", "os_store")

	cfg := Config{
		Database:    openSQLite(t),
		Logger:      newTestLogger(),
		CacheConfig: nil, // deliberately nil — should default
		Viper:       v,
	}

	container, err := NewServiceContainer(cfg)
	require.NoError(t, err)
	require.NotNil(t, container)
	t.Cleanup(func() { _ = container.Close() })

	// The container must have picked up the real LoadCacheConfig() defaults,
	// not just some non-zero value — pin the documented Secrets TTL default.
	assert.Equal(t, 5*time.Minute, container.GetCacheConfig().Secrets.TTL, "nil CacheConfig should trigger LoadCacheConfig(), producing the real Secrets default")
}

// ---------------------------------------------------------------------------
// Test 9 — NewServiceContainer with nil Viper falls back to global viper
// ---------------------------------------------------------------------------

// TestNewServiceContainer_NilViper verifies that omitting the Viper field
// causes initializeServices to fall back to the global viper instance, and
// the retry-service warning path is taken (c.viper == nil branch).
func TestNewServiceContainer_NilViper(t *testing.T) {
	// No jwt_secret is seeded: with the HS256 fallback gone, the default
	// jwt.key_source ("os_store") must carry the container on its own.
	cfg := Config{
		Database:    openSQLite(t),
		Logger:      newTestLogger(),
		CacheConfig: cacheConfigWithSecretsDisabled(t),
		Viper:       nil, // trigger fallback to global viper
	}

	container, err := NewServiceContainer(cfg)
	require.NoError(t, err)
	require.NotNil(t, container)
	t.Cleanup(func() { _ = container.Close() })

	// Core services must still be wired up.
	assert.NotNil(t, container.GetPasswordService())
	assert.NotNil(t, container.GetJWTService())
	assert.NotNil(t, container.GetDatabase())
	// Retry service should be nil because c.viper == nil skips retry init.
	assert.Nil(t, container.GetRetryService(), "RetryService must be nil when Viper not injected")
}

// ---------------------------------------------------------------------------
// Test 10 — NewServiceContainer with an unknown jwt.key_source
// ---------------------------------------------------------------------------

// TestNewServiceContainer_UnknownKeySource_Error verifies that an unusable
// signing provider now aborts container initialisation. Before the HS256
// fallback was removed (2026-08-16) this silently degraded to symmetric
// signing whenever jwt_secret happened to be set, which made forged
// kid-less tokens verifiable with a repo-committed secret.
func TestNewServiceContainer_UnknownKeySource_Error(t *testing.T) {
	v := viper.New()
	v.Set("jwt.key_source", "unknown_provider") // signing provider fails

	cfg := Config{
		Database:    openSQLite(t),
		Logger:      newTestLogger(),
		CacheConfig: cacheConfigWithSecretsDisabled(t),
		Viper:       v,
	}

	_, err := NewServiceContainer(cfg)
	require.Error(t, err, "an unusable signing provider must abort startup")
	assert.Contains(t, err.Error(), "JWT signing provider initialisation failed")
	assert.Contains(t, err.Error(), "unknown jwt.key_source")
}

// ---------------------------------------------------------------------------
// Test 12 — NewServiceContainer with viper-configured retry policies
// ---------------------------------------------------------------------------

// TestNewServiceContainer_WithRetryConfig exercises the retry-service
// initialisation path when valid retry config is present in viper.
func TestNewServiceContainer_WithRetryConfig(t *testing.T) {
	v := viper.New()
	v.Set("jwt.key_source", "os_store")
	v.Set("retry.database.enabled", true)
	v.Set("retry.database.max_attempts", 3)

	cfg := Config{
		Database:    openSQLite(t),
		Logger:      newTestLogger(),
		CacheConfig: cacheConfigWithSecretsDisabled(t),
		Viper:       v,
	}

	container, err := NewServiceContainer(cfg)
	require.NoError(t, err)
	require.NotNil(t, container)
	t.Cleanup(func() { _ = container.Close() })

	// The retry service should be initialised and returned non-nil.
	assert.NotNil(t, container.GetRetryService(), "GetRetryService must be non-nil with retry config")
}

// ---------------------------------------------------------------------------
// Test 11 — NewServiceContainer with external_pki and no key material
// ---------------------------------------------------------------------------

// TestNewServiceContainer_ExternalPKI_NoFile_Error exercises the code path
// where the signing provider is configured as "external_pki" with no key file
// and no env var. There is no symmetric fallback any more, so this must fail
// startup rather than quietly issuing HS256-verifiable sessions.
func TestNewServiceContainer_ExternalPKI_NoFile_Error(t *testing.T) {
	// Ensure env var is absent so external_pki returns an error.
	t.Setenv("ROCKETVAULT_JWT_SIGNING_KEY", "")

	v := viper.New()
	v.Set("jwt.key_source", "external_pki")
	v.Set("jwt.signing_key_file", "") // no file path — provider will fail

	cfg := Config{
		Database:    openSQLite(t),
		Logger:      newTestLogger(),
		CacheConfig: cacheConfigWithSecretsDisabled(t),
		Viper:       v,
	}

	_, err := NewServiceContainer(cfg)
	require.Error(t, err, "external_pki with no key material must abort startup")
	assert.Contains(t, err.Error(), "JWT signing provider initialisation failed")
}

// ---------------------------------------------------------------------------
// Test 14 — ServiceContainerInterface satisfaction
// ---------------------------------------------------------------------------

// TestServiceContainerInterface_Satisfaction is a compile-time check that
// *ServiceContainer satisfies the ServiceContainerInterface. If this fails to
// compile the test will not build.
func TestServiceContainerInterface_Satisfaction(t *testing.T) {
	var _ ServiceContainerInterface = (*ServiceContainer)(nil)
}

// ---------------------------------------------------------------------------
// Test 14b — GetGrantService is constructed and reachable via the interface
// ---------------------------------------------------------------------------

// TestServiceContainer_GetGrantService verifies the provisioning grant
// service is constructed during container initialization and reachable both
// on the concrete type and through ServiceContainerInterface -- CLI commands
// type-assert to the interface, so a getter that only exists on the concrete
// type would silently be unreachable from them.
func TestServiceContainer_GetGrantService(t *testing.T) {
	cfg := newMinimalConfig(t)

	c, err := NewServiceContainer(cfg)
	require.NoError(t, err)
	t.Cleanup(func() { _ = c.Close() })

	svc := c.GetGrantService()
	require.NotNil(t, svc, "grant service must be constructed during container initialization")

	var iface ServiceContainerInterface = c
	require.NotNil(t, iface.GetGrantService(),
		"accessor must be reachable through ServiceContainerInterface: CLI commands assert to the interface")
}

// ---------------------------------------------------------------------------
// Test 15 — GetDatabase returns the exact db passed in Config
// ---------------------------------------------------------------------------

// TestGetDatabase_ReturnsSameInstance checks that the db stored in the
// container is pointer-identical to the one provided in the Config.
func TestGetDatabase_ReturnsSameInstance(t *testing.T) {
	cfg := newMinimalConfig(t)
	originalDB := cfg.Database

	container, err := NewServiceContainer(cfg)
	require.NoError(t, err)
	t.Cleanup(func() { _ = container.Close() })

	assert.Same(t, originalDB, container.GetDatabase(),
		"GetDatabase must return the same *sql.DB pointer as provided in Config")
}

// ---------------------------------------------------------------------------
// Test 16 — GetLogger returns the exact logger passed in Config
// ---------------------------------------------------------------------------

// TestGetLogger_ReturnsSameInstance checks that the logger stored in the
// container is pointer-identical to the one provided in the Config.
func TestGetLogger_ReturnsSameInstance(t *testing.T) {
	cfg := newMinimalConfig(t)
	originalLogger := cfg.Logger

	container, err := NewServiceContainer(cfg)
	require.NoError(t, err)
	t.Cleanup(func() { _ = container.Close() })

	assert.Same(t, originalLogger, container.GetLogger(),
		"GetLogger must return the same *logging.Logger pointer as provided in Config")
}

// ---------------------------------------------------------------------------
// Test 17 — vault cache is always constructed, real or no-op internally
// ---------------------------------------------------------------------------

// TestNewServiceContainer_VaultCacheAlwaysNonNil pins that GetVaultCache
// never returns nil after a successful NewServiceContainer call, regardless
// of whether cache.vaults.enabled is on.
func TestNewServiceContainer_VaultCacheAlwaysNonNil(t *testing.T) {
	v := viper.New()
	v.Set("jwt.key_source", "os_store")

	container, err := NewServiceContainer(Config{
		Database: openSQLite(t),
		Logger:   newTestLogger(),
		Viper:    v,
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = container.Close() })

	assert.NotNil(t, container.GetVaultCache(), "GetVaultCache must always be non-nil")
}

// ---------------------------------------------------------------------------
// Test 18 — purge wiring actually removes a vault's webhook config row
// ---------------------------------------------------------------------------

// TestNewServiceContainer_PurgeRemovesWebhookConfig pins the orphan-prevention
// guarantee that service_container.go's
// `c.vaultService.SetWebhookCleaner(vaultWebhookRepo)` line exists to provide:
// purging a vault with a webhook config must not strand a
// vault_webhook_configs row (which holds an encrypted signing secret) behind.
//
// This is a behavioural check, not a wiring inspection, because
// VaultWebhookService's cleaner is not exposed on VaultService's exported
// interface. If that SetWebhookCleaner call is ever deleted, PurgeVault's
// s.webhooks fork is simply never taken (see
// TestPurgeVault_NoWebhookCleanerIsFine in
// internal/services/vaults/vault_service_webhook_cleanup_test.go, which
// explicitly asserts purge still succeeds with no cleaner set) and this test
// must fail by finding the row still present after purge.
func TestNewServiceContainer_PurgeRemovesWebhookConfig(t *testing.T) {
	// common.EncryptSecret (used by VaultWebhookService.Upsert) reads
	// master_key from the global viper singleton, not the per-container
	// Viper instance -- mirror setupWebhookTestMasterKey in
	// internal/services/vaults/webhook_service_test.go.
	origMasterKey := viper.GetString("master_key")
	k := make([]byte, 32)
	for i := range k {
		k[i] = byte(i + 1)
	}
	viper.Set("master_key", base64.StdEncoding.EncodeToString(k))
	t.Cleanup(func() { viper.Set("master_key", origMasterKey) })

	// A plain ":memory:" DSN gives every new pooled connection its own empty
	// database, which the container's background init (e.g. the softdelete
	// scheduler) can trip over via a second concurrent connection. Use a
	// named, shared-cache DSN instead so every connection in the pool sees
	// the same in-memory database, and open it directly rather than through
	// newMinimalConfig/openSQLite (which use plain ":memory:").
	dsn := "file:webhookpurgetest_" + uuid.NewString() + "?mode=memory&cache=shared"
	rawDB, err := sql.Open("sqlite3", dsn)
	require.NoError(t, err)
	t.Cleanup(func() { _ = rawDB.Close() })

	require.NoError(t, rvdb.NewRepository(newTestLogger()).SetupSchema(rawDB, rvdb.SQLite),
		"setup schema before exercising vault/webhook services")

	containerViper := viper.New()
	containerViper.Set("jwt.key_source", "os_store")
	cfg := Config{
		Database:    rawDB,
		Logger:      newTestLogger(),
		CacheConfig: cacheConfigWithSecretsDisabled(t),
		Viper:       containerViper,
	}

	container, err := NewServiceContainer(cfg)
	require.NoError(t, err)
	require.NotNil(t, container)
	t.Cleanup(func() { _ = container.Close() })

	ctx := context.Background()
	vaultSvc := container.GetVaultService()
	webhookSvc := container.GetVaultWebhookService()
	require.NotNil(t, vaultSvc)
	require.NotNil(t, webhookSvc)

	name := "webhook-purge-" + uuid.NewString()[:8]
	v, err := vaultSvc.CreateVault(ctx, model.CreateVaultRequest{Name: name}, uuid.New())
	require.NoError(t, err)

	_, _, err = webhookSvc.Upsert(ctx, v.ID, vaultServices.UpsertWebhookRequest{
		URL: "https://example.com/hook",
	}, uuid.New())
	require.NoError(t, err)

	// Sanity check: the row exists before purge.
	var countBefore int
	require.NoError(t, rawDB.QueryRow(
		"SELECT COUNT(*) FROM vault_webhook_configs WHERE vault_id = ?", v.ID.String(),
	).Scan(&countBefore))
	require.Equal(t, 1, countBefore, "webhook config row must exist before purge")

	require.NoError(t, vaultSvc.DeleteVault(ctx, name, uuid.New()))
	require.NoError(t, vaultSvc.PurgeVault(ctx, name, uuid.New()))

	var countAfter int
	require.NoError(t, rawDB.QueryRow(
		"SELECT COUNT(*) FROM vault_webhook_configs WHERE vault_id = ?", v.ID.String(),
	).Scan(&countAfter))
	assert.Equal(t, 0, countAfter,
		"purging a vault must remove its webhook config row -- if this fails, "+
			"check that service_container.go still calls "+
			"c.vaultService.SetWebhookCleaner(vaultWebhookRepo)")
}

// ---------------------------------------------------------------------------
// Test 19 — rocket-mem client construction is gated by cache.rocket_mem.enabled
// ---------------------------------------------------------------------------

// TestNewServiceContainer_RocketMemDisabledByDefault_NoClientConstructed
// pins that a container built with no RocketMemConfig override (so it loads
// from Viper, and cache.rocket_mem defaults to disabled) never constructs a
// rocket-mem client, and that Close() stays safe with a nil client.
func TestNewServiceContainer_RocketMemDisabledByDefault_NoClientConstructed(t *testing.T) {
	viper.Set("cache.rocket_mem.enabled", nil)
	c, err := NewServiceContainer(Config{
		Logger: newTestLogger(),
	})
	require.NoError(t, err)
	assert.Nil(t, c.rocketMemClient, "rocketMemClient must stay nil when cache.rocket_mem is disabled")
	assert.NotPanics(t, func() { _ = c.Close() }, "Close must be a no-op-safe even with rocket_mem disabled")
}

// TestNewServiceContainer_RocketMemEnabled_ClientConstructedAndClosed pins
// that an explicit, enabled RocketMemConfig override causes the container to
// construct a client and that Close() closes it without error, even though
// the configured address is unreachable.
func TestNewServiceContainer_RocketMemEnabled_ClientConstructedAndClosed(t *testing.T) {
	rmCfg := rvconfig.RocketMemConfig{
		Enabled: true, Addr: "127.0.0.1:1", TLS: true, Username: "u", Password: "p",
	}
	cacheCfg, err := rvconfig.LoadCacheConfig()
	require.NoError(t, err)
	c, err := NewServiceContainer(Config{
		Logger:          newTestLogger(),
		CacheConfig:     &cacheCfg,
		RocketMemConfig: &rmCfg,
	})
	require.NoError(t, err)
	assert.NotNil(t, c.rocketMemClient, "rocketMemClient must be constructed when cache.rocket_mem.enabled is true")
	// go-redis dials lazily, so constructing against an unreachable address
	// (127.0.0.1:1) must not fail container construction -- only actual
	// Get/Set calls degrade (proven in Plan 03's tests).
	assert.NoError(t, c.Close())
}

// TestNewServiceContainer_RocketMemDisabled_SupervisorCancel_Nil pins that the
// supervisor cancel func stays nil when rocket-mem is disabled.
func TestNewServiceContainer_RocketMemDisabled_SupervisorCancelNil(t *testing.T) {
	viper.Set("cache.rocket_mem.enabled", nil)
	c, err := NewServiceContainer(Config{
		Logger: newTestLogger(),
	})
	require.NoError(t, err)
	assert.Nil(t, c.rocketMemSupervisorCancel, "rocketMemSupervisorCancel must stay nil when cache.rocket_mem is disabled")
	assert.NotPanics(t, func() { _ = c.Close() }, "Close must be safe with nil supervisor cancel")
}

// TestNewServiceContainer_RocketMemEnabled_SupervisorCancelNonNil pins that the
// supervisor cancel func is constructed when rocket-mem is enabled.
func TestNewServiceContainer_RocketMemEnabled_SupervisorCancelNonNil(t *testing.T) {
	rmCfg := rvconfig.RocketMemConfig{
		Enabled: true, Addr: "127.0.0.1:1", TLS: true, Username: "u", Password: "p",
	}
	cacheCfg, err := rvconfig.LoadCacheConfig()
	require.NoError(t, err)
	c, err := NewServiceContainer(Config{
		Logger:          newTestLogger(),
		CacheConfig:     &cacheCfg,
		RocketMemConfig: &rmCfg,
	})
	require.NoError(t, err)
	assert.NotNil(t, c.rocketMemSupervisorCancel, "rocketMemSupervisorCancel must be constructed when cache.rocket_mem is enabled")
	assert.NotPanics(t, func() { _ = c.Close() }, "Close must safely call the cancel func")
}

// TestNewServiceContainer_UserServiceRevokesSessions pins that the container
// hands the user service a working session revoker (B74). Without the wiring,
// password changes and deletes fail closed instead of revoking.
func TestNewServiceContainer_UserServiceRevokesSessions(t *testing.T) {
	dsn := "file:userrevoketest_" + uuid.NewString() + "?mode=memory&cache=shared"
	rawDB, err := sql.Open("sqlite3", dsn)
	require.NoError(t, err)
	t.Cleanup(func() { _ = rawDB.Close() })
	require.NoError(t, rvdb.NewRepository(newTestLogger()).SetupSchema(rawDB, rvdb.SQLite))

	containerViper := viper.New()
	containerViper.Set("jwt.key_source", "os_store")
	container, err := NewServiceContainer(Config{
		Database:    rawDB,
		Logger:      newTestLogger(),
		CacheConfig: cacheConfigWithSecretsDisabled(t),
		Viper:       containerViper,
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = container.Close() })

	ctx := context.Background()
	sessions := container.GetSessionRepository()
	newUserWithSession := func(name string) (uuid.UUID, uuid.UUID) {
		userID := uuid.New()
		require.NoError(t, container.GetUserRepository().Create(ctx, &model.User{
			ID: userID, Username: name, PasswordHash: "hash", TOTPSecret: "SECRET",
			Roles: []string{model.RoleUser}, CreatedAt: time.Now(),
		}))
		sessionID := uuid.New()
		require.NoError(t, sessions.CreateSession(ctx, &model.Session{
			ID: sessionID, UserID: userID, RefreshTokenHash: uuid.NewString(),
			ExpiresAt: time.Now().Add(time.Hour), LastUsedAt: time.Now(), CreatedAt: time.Now(),
		}))
		return userID, sessionID
	}

	// A password change ends the user's sessions.
	userID, sessionID := newUserWithSession("revoke-pw-" + uuid.NewString()[:8])
	newPw := "newpass123"
	_, err = container.GetUserService().UpdateUser(ctx, userServices.UpdateUserRequest{
		UserID: userID, CallerID: userID, CallerRoles: []string{model.RoleUser}, Password: &newPw,
	})
	require.NoError(t, err)
	revoked, err := sessions.IsSessionRevoked(ctx, sessionID)
	require.NoError(t, err)
	assert.True(t, revoked, "a password change must revoke the user's sessions")

	// A delete ends the user's sessions too.
	userID, sessionID = newUserWithSession("revoke-del-" + uuid.NewString()[:8])
	require.NoError(t, container.GetUserService().DeleteUser(ctx, userID))
	revoked, err = sessions.IsSessionRevoked(ctx, sessionID)
	require.NoError(t, err)
	assert.True(t, revoked, "deleting a user must revoke their sessions")
}

// TestNewServiceContainer_LoginRejectsReplayedTOTPCode pins that the container
// hands the authentication service a working TOTP step repository (B75).
// Without the wiring every login fails closed; with a broken one a code could
// be used twice.
func TestNewServiceContainer_LoginRejectsReplayedTOTPCode(t *testing.T) {
	dsn := "file:totpreplaytest_" + uuid.NewString() + "?mode=memory&cache=shared"
	rawDB, err := sql.Open("sqlite3", dsn)
	require.NoError(t, err)
	t.Cleanup(func() { _ = rawDB.Close() })
	require.NoError(t, rvdb.NewRepository(newTestLogger()).SetupSchema(rawDB, rvdb.SQLite))

	containerViper := viper.New()
	containerViper.Set("jwt.key_source", "os_store")
	container, err := NewServiceContainer(Config{
		Database:    rawDB,
		Logger:      newTestLogger(),
		CacheConfig: cacheConfigWithSecretsDisabled(t),
		Viper:       containerViper,
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = container.Close() })
	require.NotNil(t, container.totpStepRepository, "the container must build a TOTP step repository")

	ctx := context.Background()
	hash, err := authServices.NewPasswordService().HashPassword("Correct-Horse-9")
	require.NoError(t, err)
	totp := authServices.NewTOTPService()
	key, err := totp.GenerateSecret("PasswordManager", "replay-wiring")
	require.NoError(t, err)
	require.NoError(t, container.GetUserRepository().Create(ctx, &model.User{
		ID: uuid.New(), Username: "replay-wiring", PasswordHash: hash, TOTPSecret: key.Secret(),
		Roles: []string{model.RoleUser}, CreatedAt: time.Now(),
	}))

	code, err := totp.GenerateCode(key.Secret(), time.Now())
	require.NoError(t, err)
	auth := container.GetAuthenticationService()

	_, err = auth.AuthenticateUser(ctx, "replay-wiring", "Correct-Horse-9", code)
	require.NoError(t, err, "the first use of a code must succeed")

	_, err = auth.AuthenticateUser(ctx, "replay-wiring", "Correct-Horse-9", code)
	require.Error(t, err, "a replayed code must be rejected")
	assert.Contains(t, err.Error(), "invalid TOTP code")
	assert.NotContains(t, err.Error(), "not configured")
}

// TestNewServiceContainer_LoginThrottleIsWired pins that the container hands
// the authentication service a working login throttle (issue #46). Without
// it, failed logins are never slowed down per account. It drives the real
// container, including the retry wrapper, against a real SQLite schema.
func TestNewServiceContainer_LoginThrottleIsWired(t *testing.T) {
	dsn := "file:loginthrottletest_" + uuid.NewString() + "?mode=memory&cache=shared"
	rawDB, err := sql.Open("sqlite3", dsn)
	require.NoError(t, err)
	t.Cleanup(func() { _ = rawDB.Close() })
	require.NoError(t, rvdb.NewRepository(newTestLogger()).SetupSchema(rawDB, rvdb.SQLite))

	containerViper := viper.New()
	containerViper.Set("jwt.key_source", "os_store")
	// The breaker keeps its default threshold of 5: failed logins are client
	// outcomes and must not open it (B90), or the throttle would be hidden.
	// The clock is frozen so the backoff window cannot expire while slow
	// bcrypt logins run on a loaded machine.
	frozen := time.Now()
	container, err := NewServiceContainer(Config{
		Database:    rawDB,
		Logger:      newTestLogger(),
		CacheConfig: cacheConfigWithSecretsDisabled(t),
		Viper:       containerViper,
		Now:         func() time.Time { return frozen },
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = container.Close() })
	require.NotNil(t, container.loginThrottle, "the container must build a login throttle")

	ctx := context.Background()
	hash, err := authServices.NewPasswordService().HashPassword("Correct-Horse-9")
	require.NoError(t, err)
	totp := authServices.NewTOTPService()
	key, err := totp.GenerateSecret("PasswordManager", "throttle-wiring")
	require.NoError(t, err)
	require.NoError(t, container.GetUserRepository().Create(ctx, &model.User{
		ID: uuid.New(), Username: "throttle-wiring", PasswordHash: hash, TOTPSecret: key.Secret(),
		Roles: []string{model.RoleUser}, CreatedAt: time.Now(),
	}))
	auth := container.GetAuthenticationService()

	for _, username := range []string{"throttle-wiring", "no-such-user"} {
		for i := 0; i < 6; i++ {
			_, err = auth.AuthenticateUser(ctx, username, "wrong-password", "123456")
			require.Error(t, err)
			require.NotErrorIs(t, err, authServices.ErrLoginThrottled)
		}
		_, err = auth.AuthenticateUser(ctx, username, "wrong-password", "123456")
		require.ErrorIs(t, err, authServices.ErrLoginThrottled, "user %q must be throttled after six failures", username)
	}

	// Correct credentials inside the window are refused as well.
	code, err := totp.GenerateCode(key.Secret(), time.Now())
	require.NoError(t, err)
	_, err = auth.AuthenticateUser(ctx, "throttle-wiring", "Correct-Horse-9", code)
	require.ErrorIs(t, err, authServices.ErrLoginThrottled)

	// A flood of invalid bearer tokens leaves the breaker closed, so other
	// database work still runs.
	for i := 0; i < 20; i++ {
		_, err = auth.ValidateSession(ctx, "not-a-token")
		require.Error(t, err)
		require.NotErrorIs(t, err, retry.ErrCircuitBreakerOpen)
	}
	_, err = container.GetUserRepository().ReadByUsername(ctx, "throttle-wiring")
	require.NoError(t, err)
	_, err = auth.AuthenticateUser(ctx, "another-user", "wrong-password", "123456")
	require.NotErrorIs(t, err, retry.ErrCircuitBreakerOpen, "the database breaker must still be closed")
}
