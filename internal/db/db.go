// Package db manages database operations for the password manager.
// It initializes and interacts with a SQLite or PostgreSQL database to store users,
// secrets, keys, certificates, and audit logs securely, using Go Generics for type-safe
// data access.
package db

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	_ "github.com/lib/pq"           // PostgreSQL driver for database/sql.
	_ "github.com/mattn/go-sqlite3" // SQLite driver for database/sql.
	"github.com/spf13/viper"

	"rocketvault/internal/logging"
	"rocketvault/model"
)

// ConnectionPoolConfig holds database connection pool configuration.
type ConnectionPoolConfig struct {
	MaxOpenConns    int           // Maximum number of open connections
	MaxIdleConns    int           // Maximum number of idle connections
	ConnMaxLifetime time.Duration // Maximum lifetime of a connection
	ConnMaxIdleTime time.Duration // Maximum idle time of a connection
}

// DatabaseConfig holds complete database configuration.
type DatabaseConfig struct {
	ConnectionString string
	DriverName       string
	PoolConfig       ConnectionPoolConfig
	Environment      string // dev, staging, prod
}

// PerformanceMetrics tracks database performance indicators.
type PerformanceMetrics struct {
	QueryCount       int64         `json:"query_count"`
	SlowQueryCount   int64         `json:"slow_query_count"`
	TotalQueryTime   time.Duration `json:"total_query_time"`
	AverageQueryTime time.Duration `json:"avg_query_time"`
	ConnectionStats  sql.DBStats   `json:"connection_stats"`
	mu               sync.RWMutex
}

// Global performance metrics
var metrics *PerformanceMetrics

// Initialize metrics
func init() {
	metrics = &PerformanceMetrics{}
}

// Repository defines a generic interface for database operations.
// It supports type-safe CRUD operations for entities like users, secrets, and keys.
type Repository[T any] interface {
	Create(ctx context.Context, entity *T) error
	Read(ctx context.Context, id uuid.UUID) (*T, error)
	Update(ctx context.Context, entity *T) error
	Delete(ctx context.Context, id uuid.UUID) error
}

// DBRepository implements the Repository interface for SQLite or PostgreSQL databases.
// It provides methods to create, read, update, and delete records in the database.
// The repository is initialized with a logger for logging database operations.
// It uses Go Generics to allow for type-safe operations on different entity types.
// The repository is designed to work with various database backends, including SQLite and PostgreSQL.
// The database connection is managed through the global DB variable.
type DBRepository struct {
	db      *sql.DB
	dialect Dialect // resolved at InitializeDB; drives bootstrap-query rebinding
	log     *logging.Logger
}

// NewRepository creates a new instance of DBRepository.
func NewRepository(log *logging.Logger) *DBRepository {
	return &DBRepository{log: log}
}

// GetDB returns the current database connection.
// It is used to access the database for executing queries and transactions.
// Parameters:
//
//	none
//
// Returns:
//
//	A pointer to the sql.DB instance representing the database connection.
//
// This function is useful for accessing the database directly when needed.
// It is typically used in conjunction with the Repository interface for CRUD operations.
// Example usage:
// db := repository.GetDB()
// result, err := db.Exec("INSERT INTO users (id, username) VALUES (?, ?)", userID, username)
//
//	if err != nil {
//	    log.Error("Failed to insert user: ", err)
//	}
func (d *DBRepository) GetDB() *sql.DB {
	return d.db
}

// OpenDatabase opens a database connection with the provided configuration.
// Exported for use by migration commands.
func (d *DBRepository) OpenDatabase(config *DatabaseConfig) (*sql.DB, error) {
	// Open a connection to the database
	db, err := sql.Open(config.DriverName, config.ConnectionString)
	if err != nil {
		d.log.Error("Failed to open database: ", err)
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	// Configure connection pool for optimal performance
	if err := d.configureConnectionPool(db, config.PoolConfig); err != nil {
		db.Close() //nolint:errcheck,gosec
		return nil, fmt.Errorf("failed to configure connection pool: %w", err)
	}

	return db, nil
}

// InitializeDB sets up the SQLite or PostgreSQL database with optimized connection pooling.
// It opens a connection using the configured connection string, configures connection pool,
// and creates tables for users, secrets, keys, CA keys, CRLs, and audit logs.
//
// Parameters:
//
//	none
//
// Returns:
//
//	An error if the connection or table creation fails.
//
// The function is called during application startup to prepare the database.
func (d *DBRepository) InitializeDB() error {
	// Get database configuration
	dbConfig, err := d.loadDatabaseConfig()
	if err != nil {
		return fmt.Errorf("failed to load database config: %w", err)
	}

	// Resolve the dialect so bootstrap queries (seeds) rebind correctly.
	d.dialect = DialectFromDriver(dbConfig.DriverName)

	// Open a connection to the database.
	db, err := sql.Open(dbConfig.DriverName, dbConfig.ConnectionString)
	if err != nil {
		d.log.Error("Failed to open database: ", err)
		return fmt.Errorf("failed to open database: %w", err)
	}

	// Configure connection pool for optimal performance
	if err := d.configureConnectionPool(db, dbConfig.PoolConfig); err != nil {
		db.Close() //nolint:errcheck,gosec
		return fmt.Errorf("failed to configure connection pool: %w", err)
	}

	// Verify the database connection with timeout.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := db.PingContext(ctx); err != nil {
		db.Close() //nolint:errcheck,gosec
		d.log.Error("Failed to ping database: ", err)
		return fmt.Errorf("failed to ping database: %w", err)
	}

	// Create schema, migrate, and seed using the resolved dialect.
	if err := d.SetupSchema(db, d.dialect); err != nil {
		db.Close() //nolint:errcheck,gosec
		return err
	}

	d.db = db
	d.log.Info("Database initialized successfully with connection pooling")
	return nil
}

// SetupSchema creates the schema, runs migrations, and seeds defaults on the
// given connection using the given dialect. InitializeDB calls it; integration
// tests call it directly against a Postgres container. It is idempotent.
func (d *DBRepository) SetupSchema(db *sql.DB, dialect Dialect) error {
	d.dialect = dialect

	if err := d.createOptimizedSchema(db); err != nil {
		return fmt.Errorf("failed to create schema: %w", err)
	}
	// Migrate schema for existing databases (idempotent — duplicate-column errors are ignored).
	if err := d.migrateSchema(db); err != nil {
		return fmt.Errorf("failed to migrate schema: %w", err)
	}
	// Seed the reserved system user before anything that might reference it
	// (SelfPKIProvider's own JWT signing key, seeded well after SetupSchema
	// returns, but keeping this early avoids relying on that ordering).
	if err := d.seedSystemUser(db); err != nil {
		return fmt.Errorf("failed to seed system user: %w", err)
	}
	// Seed the bootstrap token from config so the first admin can be created.
	if err := d.seedBootstrapToken(db); err != nil {
		return fmt.Errorf("failed to seed bootstrap token: %w", err)
	}
	if err := d.seedAuditConfig(db); err != nil {
		return fmt.Errorf("failed to seed audit config: %w", err)
	}
	// Seed the default vault before finalizing indexes so the row exists.
	if err := d.seedDefaultVault(db); err != nil {
		return fmt.Errorf("failed to seed default vault: %w", err)
	}
	// Resolve any name collisions and create the per-vault unique indexes.
	if err := d.finalizeVaultIndexes(db); err != nil {
		return fmt.Errorf("failed to finalize vault indexes: %w", err)
	}
	return nil
}

// LoadDatabaseConfig loads and validates database configuration.
// Exported for use by migration commands.
func (d *DBRepository) LoadDatabaseConfig() (*DatabaseConfig, error) {
	return d.loadDatabaseConfig()
}

// loadDatabaseConfig loads and validates database configuration (internal).
func (d *DBRepository) loadDatabaseConfig() (*DatabaseConfig, error) {
	// Retrieve the database connection string from configuration.
	connStr := viper.GetString("database.connection")
	if connStr == "" {
		d.log.Error("Database connection string is empty")
		return nil, fmt.Errorf("database connection string not configured")
	}

	// Determine and validate the driver from explicit config or the
	// connection string shape.
	driverName, err := resolveDriver(viper.GetString("database.driver"), connStr)
	if err != nil {
		d.log.Error("Invalid database driver: ", err)
		return nil, err
	}

	// Get environment-specific pool configuration
	env := viper.GetString("environment")
	if env == "" {
		env = "dev"
	}

	poolConfig := d.getEnvironmentPoolConfig(env)

	return &DatabaseConfig{
		ConnectionString: connStr,
		DriverName:       driverName,
		PoolConfig:       poolConfig,
		Environment:      env,
	}, nil
}

// resolveDriver determines the database/sql driver name from an explicit config
// value, falling back to sniffing the connection string. It validates the result
// against the supported set so a typo fails fast with a clear message instead of
// a late "unknown driver" from sql.Open.
func resolveDriver(explicit, connStr string) (string, error) {
	driver := explicit
	if driver == "" {
		driver = sniffDriver(connStr)
	}

	switch driver {
	case "sqlite3", "postgres":
		return driver, nil
	case "sqlite":
		// Accept the common alias for the registered "sqlite3" driver name.
		return "sqlite3", nil
	case "postgresql":
		// Accept the alternate spelling for the registered "postgres" driver.
		return "postgres", nil
	default:
		return "", fmt.Errorf(
			"unsupported database driver %q: must be \"sqlite3\" or \"postgres\"", driver,
		)
	}
}

// sniffDriver guesses the driver from the connection string when none is set.
// It recognizes both Postgres URL schemes and the DSN keyword form; anything
// else defaults to SQLite (a file path).
func sniffDriver(connStr string) string {
	lower := strings.ToLower(strings.TrimSpace(connStr))
	switch {
	case strings.HasPrefix(lower, "postgres://"), strings.HasPrefix(lower, "postgresql://"):
		return "postgres"
	case strings.Contains(lower, "host=") && strings.Contains(lower, "dbname="):
		// Postgres DSN keyword form, e.g. "host=... dbname=... sslmode=...".
		return "postgres"
	default:
		return "sqlite3"
	}
}

// getEnvironmentPoolConfig returns optimized pool config for each environment.
func (d *DBRepository) getEnvironmentPoolConfig(env string) ConnectionPoolConfig {
	switch env {
	case "prod", "production":
		return ConnectionPoolConfig{
			MaxOpenConns:    50,               // High concurrency for production
			MaxIdleConns:    10,               // Keep connections ready
			ConnMaxLifetime: 30 * time.Minute, // Rotate connections regularly
			ConnMaxIdleTime: 5 * time.Minute,  // Close idle connections
		}
	default: // dev, test
		return ConnectionPoolConfig{
			MaxOpenConns:    10,               // Limited concurrency for dev
			MaxIdleConns:    2,                // Minimal idle connections
			ConnMaxLifetime: 10 * time.Minute, // Shorter lifetime for dev
			ConnMaxIdleTime: 2 * time.Minute,  // Quick cleanup
		}
	}
}

// configureConnectionPool sets up optimized connection pool settings.
func (d *DBRepository) configureConnectionPool(db *sql.DB, config ConnectionPoolConfig) error {
	db.SetMaxOpenConns(config.MaxOpenConns)
	db.SetMaxIdleConns(config.MaxIdleConns)
	db.SetConnMaxLifetime(config.ConnMaxLifetime)
	db.SetConnMaxIdleTime(config.ConnMaxIdleTime)

	d.log.Info(fmt.Sprintf(
		"Connection pool configured: MaxOpen=%d, MaxIdle=%d, MaxLifetime=%v, MaxIdleTime=%v",
		config.MaxOpenConns, config.MaxIdleConns, config.ConnMaxLifetime, config.ConnMaxIdleTime,
	))

	return nil
}

// createOptimizedSchema creates tables with proper indexes for performance.
func (d *DBRepository) createOptimizedSchema(db *sql.DB) error {
	// Create tables with optimized schema.
	// The three vault_id column defaults below are hardcoded SQL literals and must
	// stay equal to model.DefaultVaultID ("00000000-0000-0000-0000-00000000efa1").
	_, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS users (
			id TEXT PRIMARY KEY,
			username TEXT UNIQUE NOT NULL,
			password_hash TEXT NOT NULL,
			totp_secret TEXT,
			role TEXT NOT NULL,
			auth_provider TEXT NOT NULL DEFAULT 'local',
			external_idp_subject TEXT,
			totp_last_step INTEGER NOT NULL DEFAULT 0,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		);
		CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
		CREATE INDEX IF NOT EXISTS idx_users_role ON users(role);
		CREATE INDEX IF NOT EXISTS idx_users_created_at ON users(created_at);
		-- idx_users_external_idp is created in migrateSchema, after the ALTER TABLE
		-- statements that add auth_provider/external_idp_subject to pre-existing
		-- databases. Creating it here would fail on upgraded DBs where those columns
		-- do not yet exist (see the audit_logs precedent below for the same trap).

		CREATE TABLE IF NOT EXISTS user_roles (
			id         TEXT PRIMARY KEY,
			user_id    TEXT NOT NULL,
			role       TEXT NOT NULL,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			UNIQUE (user_id, role),
			-- ON DELETE CASCADE only fires on Postgres: SQLite's foreign_keys
			-- PRAGMA is off project-wide (see the audit_logs note further down
			-- this file), so a SQLite deployment must delete user_roles rows
			-- manually on user deletion, the way vault_service.go:497 already
			-- does for its own SQLite-inert cascades.
			FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
		);
		CREATE INDEX IF NOT EXISTS idx_user_roles_user ON user_roles(user_id);

		CREATE TABLE IF NOT EXISTS vaults (
			id                 TEXT PRIMARY KEY,
			name               TEXT UNIQUE NOT NULL,
			enabled            BOOLEAN NOT NULL DEFAULT TRUE,
			purge_protection   BOOLEAN NOT NULL DEFAULT FALSE,
			retention_days     INTEGER NOT NULL DEFAULT 90,
			created_by         TEXT NOT NULL,
			created_at         TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			deleted_at         TIMESTAMP NULL,
			scheduled_purge_at TIMESTAMP NULL,
			tags               TEXT NOT NULL DEFAULT '{}',
			updated_at         TIMESTAMP NULL,
			updated_by         TEXT NULL
		);
		CREATE INDEX IF NOT EXISTS idx_vaults_name ON vaults(name);

		CREATE TABLE IF NOT EXISTS secrets (
			id TEXT PRIMARY KEY,
			user_id TEXT NOT NULL,
			name TEXT NOT NULL,
			vault_id TEXT NOT NULL DEFAULT '00000000-0000-0000-0000-00000000efa1',
			value TEXT NOT NULL,
			version INTEGER NOT NULL,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			deleted_at TIMESTAMP NULL,
			purge_protection BOOLEAN NOT NULL DEFAULT FALSE,
			scheduled_purge_at TIMESTAMP NULL,
			content_type TEXT NOT NULL DEFAULT '',
			enabled      BOOLEAN NOT NULL DEFAULT TRUE,
			expires_at   TIMESTAMP NULL,
			not_before   TIMESTAMP NULL,
			FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
		);
		CREATE INDEX IF NOT EXISTS idx_secrets_user_id ON secrets(user_id);
		CREATE INDEX IF NOT EXISTS idx_secrets_name ON secrets(name);
		CREATE INDEX IF NOT EXISTS idx_secrets_user_name ON secrets(user_id, name);
		CREATE INDEX IF NOT EXISTS idx_secrets_created_at ON secrets(created_at);

		CREATE TABLE IF NOT EXISTS keys (
			id TEXT PRIMARY KEY,
			user_id TEXT NOT NULL,
			name TEXT NOT NULL,
			vault_id TEXT NOT NULL DEFAULT '00000000-0000-0000-0000-00000000efa1',
			value TEXT NOT NULL,
			type TEXT NOT NULL,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			revoked BOOLEAN NOT NULL DEFAULT FALSE,
			deleted_at TIMESTAMP NULL,
			purge_protection BOOLEAN NOT NULL DEFAULT FALSE,
			scheduled_purge_at TIMESTAMP NULL,
			enabled BOOLEAN NOT NULL DEFAULT TRUE,
			expires_at TIMESTAMP NULL,
			not_before TIMESTAMP NULL,
			bits INTEGER NOT NULL DEFAULT 0,
			curve TEXT NOT NULL DEFAULT '',
			updated_at TIMESTAMP NULL,
			exportable BOOLEAN NOT NULL DEFAULT FALSE,
			FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
		);
		CREATE INDEX IF NOT EXISTS idx_keys_user_id ON keys(user_id);
		CREATE INDEX IF NOT EXISTS idx_keys_type ON keys(type);
		CREATE INDEX IF NOT EXISTS idx_keys_revoked ON keys(revoked);
		CREATE INDEX IF NOT EXISTS idx_keys_user_type ON keys(user_id, type);

		CREATE TABLE IF NOT EXISTS key_tags (
			key_id TEXT NOT NULL,
			tag TEXT NOT NULL,
			PRIMARY KEY (key_id, tag),
			FOREIGN KEY (key_id) REFERENCES keys(id) ON DELETE CASCADE
		);
		CREATE INDEX IF NOT EXISTS idx_key_tags_tag ON key_tags(tag);

		CREATE TABLE IF NOT EXISTS key_versions (
			key_id     TEXT NOT NULL,
			version    INTEGER NOT NULL,
			value      TEXT NOT NULL,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			PRIMARY KEY (key_id, version),
			FOREIGN KEY (key_id) REFERENCES keys(id) ON DELETE CASCADE
		);
		CREATE INDEX IF NOT EXISTS idx_key_versions_key_id ON key_versions(key_id);

		CREATE TABLE IF NOT EXISTS certificates (
			id TEXT PRIMARY KEY,
			user_id TEXT NOT NULL,
			key_id TEXT NOT NULL DEFAULT '',
			ca_cert_id TEXT NULL,
			name TEXT NOT NULL,
			vault_id TEXT NOT NULL DEFAULT '00000000-0000-0000-0000-00000000efa1',
			certificate TEXT NOT NULL,
			private_key TEXT NOT NULL,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			deleted_at TIMESTAMP NULL,
			purge_protection BOOLEAN NOT NULL DEFAULT FALSE,
			scheduled_purge_at TIMESTAMP NULL,
			expires_at TIMESTAMP,
			auto_renew BOOLEAN NOT NULL DEFAULT FALSE,
			renewal_days INTEGER NOT NULL DEFAULT 30,
			enabled BOOLEAN NOT NULL DEFAULT TRUE,
			not_before TIMESTAMP NULL,
			version INTEGER NOT NULL DEFAULT 1,
			exportable BOOLEAN NOT NULL DEFAULT FALSE,
			FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
		);
		CREATE INDEX IF NOT EXISTS idx_certificates_user_id ON certificates(user_id);
		CREATE INDEX IF NOT EXISTS idx_certificates_name ON certificates(name);
		CREATE INDEX IF NOT EXISTS idx_certificates_created_at ON certificates(created_at);

		CREATE TABLE IF NOT EXISTS certificate_tags (
			certificate_id TEXT NOT NULL,
			tag TEXT NOT NULL,
			PRIMARY KEY (certificate_id, tag),
			FOREIGN KEY (certificate_id) REFERENCES certificates(id) ON DELETE CASCADE
		);
		CREATE INDEX IF NOT EXISTS idx_certificate_tags_tag ON certificate_tags(tag);

		CREATE TABLE IF NOT EXISTS certificate_versions (
			certificate_id TEXT NOT NULL,
			version        INTEGER NOT NULL,
			certificate    TEXT NOT NULL,
			private_key    TEXT NOT NULL,
			key_id         TEXT NULL,
			created_at     TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			expires_at     TIMESTAMP NULL,
			not_before     TIMESTAMP NULL,
			enabled        BOOLEAN NOT NULL DEFAULT TRUE,
			PRIMARY KEY (certificate_id, version),
			FOREIGN KEY (certificate_id) REFERENCES certificates(id) ON DELETE CASCADE
		);
		CREATE INDEX IF NOT EXISTS idx_certificate_versions_certificate_id ON certificate_versions(certificate_id);

		CREATE TABLE IF NOT EXISTS certificate_policies (
			id                TEXT PRIMARY KEY,
			certificate_id    TEXT NOT NULL UNIQUE,
			user_id           TEXT NOT NULL,
			validity_months   INTEGER NOT NULL DEFAULT 12,
			key_type          TEXT NOT NULL DEFAULT 'RSA',
			key_size          INTEGER NOT NULL DEFAULT 2048,
			curve             TEXT NOT NULL DEFAULT '',
			subject           TEXT NOT NULL DEFAULT '',
			sans              TEXT NOT NULL DEFAULT '',
			auto_renew        BOOLEAN NOT NULL DEFAULT FALSE,
			days_before_expiry INTEGER NOT NULL DEFAULT 30,
			issuer_name       TEXT NOT NULL DEFAULT '',
			created_at        TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			updated_at        TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			FOREIGN KEY (certificate_id) REFERENCES certificates(id) ON DELETE CASCADE,
			FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
		);
		CREATE INDEX IF NOT EXISTS idx_cert_policies_cert_id ON certificate_policies(certificate_id);
		CREATE INDEX IF NOT EXISTS idx_cert_policies_user_id ON certificate_policies(user_id);

		CREATE TABLE IF NOT EXISTS key_rotation_policies (
			id                         TEXT PRIMARY KEY,
			key_id                     TEXT NOT NULL UNIQUE,
			user_id                    TEXT NOT NULL,
			vault_id                   TEXT NOT NULL DEFAULT '00000000-0000-0000-0000-00000000efa1',
			rotate_after_days          INTEGER NOT NULL DEFAULT 90,
			notify_before_expiry_days  INTEGER NOT NULL DEFAULT 30,
			expiry_days                INTEGER NOT NULL DEFAULT 365,
			enabled                    BOOLEAN NOT NULL DEFAULT TRUE,
			last_rotated_at            TIMESTAMP NULL,
			-- Nullable, no default: deliberately mirrors migrateSchema's ALTER
			-- TABLE for this column (see M3 in the final review). Every code
			-- path that creates a row (KeyService.UpsertKeyRotationPolicy)
			-- always sets this explicitly, so a fresh-install-only default
			-- would only create a divergence from upgraded installs, not
			-- serve any purpose. scanKeyRotationPolicyRow/Rows treat a NULL
			-- value defensively (never swept as due).
			next_rotation_at           TIMESTAMP NULL,
			created_at                 TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			updated_at                 TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			FOREIGN KEY (key_id) REFERENCES keys(id) ON DELETE CASCADE,
			FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
		);
		CREATE INDEX IF NOT EXISTS idx_key_rotation_policies_key_id ON key_rotation_policies(key_id);
		CREATE INDEX IF NOT EXISTS idx_key_rotation_policies_user_id ON key_rotation_policies(user_id);
		-- idx_key_rotation_policies_vault_id is created in migrateSchema, after
		-- the ALTER TABLE that adds vault_id to pre-existing databases. Creating
		-- it here would fail on an upgraded DB where key_rotation_policies
		-- already existed without vault_id: CREATE TABLE IF NOT EXISTS above
		-- no-ops on the old shape, but CREATE INDEX is not a no-op and errors
		-- with "no such column: vault_id" -- the same class of bug already
		-- avoided for audit_logs's enriched-column indexes below.

		CREATE TABLE IF NOT EXISTS vault_webhook_configs (
			id                       TEXT PRIMARY KEY,
			vault_id                 TEXT NOT NULL UNIQUE,
			url                      TEXT NOT NULL,
			signing_secret_encrypted TEXT NOT NULL,
			enabled                  BOOLEAN NOT NULL DEFAULT TRUE,
			created_at               TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			updated_at               TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			FOREIGN KEY (vault_id) REFERENCES vaults(id) ON DELETE CASCADE
		);
		CREATE INDEX IF NOT EXISTS idx_vault_webhook_configs_vault_id ON vault_webhook_configs(vault_id);

		CREATE TABLE IF NOT EXISTS crl (
			id TEXT PRIMARY KEY,
			user_id TEXT NOT NULL,
			serial_number TEXT NOT NULL,
			revoked_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			name TEXT NOT NULL,
			FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
		);
		CREATE INDEX IF NOT EXISTS idx_crl_user_id ON crl(user_id);
		CREATE INDEX IF NOT EXISTS idx_crl_serial_number ON crl(serial_number);

		CREATE TABLE IF NOT EXISTS audit_logs (
			id TEXT PRIMARY KEY,
			user_id TEXT,
			action TEXT NOT NULL,
			details TEXT,
			timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			resource_type TEXT,
			resource_id TEXT,
			ip_address TEXT,
			outcome TEXT,
			source TEXT,
			prev_hash TEXT
		);
		CREATE INDEX IF NOT EXISTS idx_audit_logs_user_id ON audit_logs(user_id);
		CREATE INDEX IF NOT EXISTS idx_audit_logs_action ON audit_logs(action);
		CREATE INDEX IF NOT EXISTS idx_audit_logs_timestamp ON audit_logs(timestamp);
		CREATE INDEX IF NOT EXISTS idx_audit_logs_user_action ON audit_logs(user_id, action);

		CREATE TABLE IF NOT EXISTS bootstrap_tokens (
			token TEXT PRIMARY KEY,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			used BOOLEAN DEFAULT FALSE
		);
		CREATE INDEX IF NOT EXISTS idx_bootstrap_tokens_used ON bootstrap_tokens(used);

		CREATE TABLE IF NOT EXISTS secret_tags (
			secret_id TEXT NOT NULL,
			tag TEXT NOT NULL,
			PRIMARY KEY (secret_id, tag),
			FOREIGN KEY (secret_id) REFERENCES secrets(id) ON DELETE CASCADE
		);
		CREATE INDEX IF NOT EXISTS idx_secret_tags_tag ON secret_tags(tag);

		CREATE TABLE IF NOT EXISTS secret_versions (
			id TEXT PRIMARY KEY,
			secret_id TEXT NOT NULL,
			user_id TEXT NOT NULL,
			name TEXT NOT NULL,
			value TEXT NOT NULL,
			version INTEGER NOT NULL,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			FOREIGN KEY (secret_id) REFERENCES secrets(id) ON DELETE CASCADE,
			FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
		);
		CREATE INDEX IF NOT EXISTS idx_secret_versions_secret_id ON secret_versions(secret_id);
		CREATE INDEX IF NOT EXISTS idx_secret_versions_version ON secret_versions(secret_id, version);
		CREATE INDEX IF NOT EXISTS idx_secret_versions_created_at ON secret_versions(created_at);

		CREATE TABLE IF NOT EXISTS rotation_policies (
			id TEXT PRIMARY KEY,
			user_id TEXT NOT NULL,
			vault_id TEXT NOT NULL DEFAULT '00000000-0000-0000-0000-00000000efa1',
			name TEXT NOT NULL,
			description TEXT,
			interval_days INTEGER NOT NULL,
			enabled BOOLEAN NOT NULL DEFAULT TRUE,
			reminder_days INTEGER NOT NULL DEFAULT 7,
			auto_rotate BOOLEAN NOT NULL DEFAULT FALSE,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
		);
		CREATE INDEX IF NOT EXISTS idx_rotation_policies_user_id ON rotation_policies(user_id);
		CREATE INDEX IF NOT EXISTS idx_rotation_policies_enabled ON rotation_policies(enabled);
		CREATE INDEX IF NOT EXISTS idx_rotation_policies_auto_rotate ON rotation_policies(auto_rotate);
		-- idx_rotation_policies_vault_id is created in migrateSchema, after the
		-- ALTER TABLE that adds vault_id to pre-existing databases -- same
		-- reasoning as idx_key_rotation_policies_vault_id above.

		CREATE TABLE IF NOT EXISTS secret_rotation_history (
			id TEXT PRIMARY KEY,
			secret_id TEXT NOT NULL,
			policy_id TEXT,
			rotated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			previous_version INTEGER,
			new_version INTEGER,
			triggered_by TEXT NOT NULL, -- 'manual', 'scheduled', 'auto'
			notes TEXT,
			FOREIGN KEY (secret_id) REFERENCES secrets(id) ON DELETE CASCADE,
			FOREIGN KEY (policy_id) REFERENCES rotation_policies(id) ON DELETE SET NULL
		);
		CREATE INDEX IF NOT EXISTS idx_rotation_history_secret_id ON secret_rotation_history(secret_id);
		CREATE INDEX IF NOT EXISTS idx_rotation_history_policy_id ON secret_rotation_history(policy_id);
		CREATE INDEX IF NOT EXISTS idx_rotation_history_rotated_at ON secret_rotation_history(rotated_at);
		CREATE INDEX IF NOT EXISTS idx_rotation_history_triggered_by ON secret_rotation_history(triggered_by);

		CREATE TABLE IF NOT EXISTS rotation_reminders (
			id TEXT PRIMARY KEY,
			secret_id TEXT NOT NULL,
			policy_id TEXT NOT NULL,
			reminder_type TEXT NOT NULL, -- 'upcoming', 'overdue'
			sent_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			next_reminder_at TIMESTAMP,
			acknowledged BOOLEAN NOT NULL DEFAULT FALSE,
			FOREIGN KEY (secret_id) REFERENCES secrets(id) ON DELETE CASCADE,
			FOREIGN KEY (policy_id) REFERENCES rotation_policies(id) ON DELETE CASCADE
		);
		CREATE INDEX IF NOT EXISTS idx_rotation_reminders_secret_id ON rotation_reminders(secret_id);
		CREATE INDEX IF NOT EXISTS idx_rotation_reminders_policy_id ON rotation_reminders(policy_id);
		CREATE INDEX IF NOT EXISTS idx_rotation_reminders_type ON rotation_reminders(reminder_type);
		CREATE INDEX IF NOT EXISTS idx_rotation_reminders_acknowledged ON rotation_reminders(acknowledged);
		CREATE INDEX IF NOT EXISTS idx_rotation_reminders_next_at ON rotation_reminders(next_reminder_at);

		CREATE TABLE IF NOT EXISTS secret_policies (
			secret_id TEXT NOT NULL,
			policy_id TEXT NOT NULL,
			assigned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			last_rotated_at TIMESTAMP,
			next_rotation_at TIMESTAMP,
			PRIMARY KEY (secret_id, policy_id),
			FOREIGN KEY (secret_id) REFERENCES secrets(id) ON DELETE CASCADE,
			FOREIGN KEY (policy_id) REFERENCES rotation_policies(id) ON DELETE CASCADE
		);
		CREATE INDEX IF NOT EXISTS idx_secret_policies_next_rotation ON secret_policies(next_rotation_at);
		CREATE INDEX IF NOT EXISTS idx_secret_policies_last_rotated ON secret_policies(last_rotated_at);

		CREATE TABLE IF NOT EXISTS user_sessions (
			id TEXT PRIMARY KEY,
			user_id TEXT NOT NULL,
			refresh_token_hash TEXT NOT NULL,
			device_info TEXT,
			ip_address TEXT,
			user_agent TEXT,
			expires_at TIMESTAMP NOT NULL,
			last_used_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			revoked BOOLEAN DEFAULT FALSE,
			revoked_at TIMESTAMP,
			revoked_reason TEXT,
			FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
		);
		CREATE INDEX IF NOT EXISTS idx_user_sessions_user_id ON user_sessions(user_id);
		CREATE INDEX IF NOT EXISTS idx_user_sessions_refresh_token ON user_sessions(refresh_token_hash);
		CREATE INDEX IF NOT EXISTS idx_user_sessions_expires_at ON user_sessions(expires_at);
		CREATE INDEX IF NOT EXISTS idx_user_sessions_revoked ON user_sessions(revoked);
		CREATE INDEX IF NOT EXISTS idx_user_sessions_last_used ON user_sessions(last_used_at);

		CREATE TABLE IF NOT EXISTS access_policies (
			id             TEXT PRIMARY KEY,
			principal_id   TEXT NOT NULL,
			principal_type TEXT NOT NULL,
			resource_type  TEXT NOT NULL,
			operation      TEXT NOT NULL,
			effect         TEXT NOT NULL,
			vault_id       TEXT NULL,
			assignment_id  TEXT NULL,
			created_at     TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		);
		CREATE INDEX IF NOT EXISTS idx_access_policies_principal ON access_policies(principal_id);
		CREATE INDEX IF NOT EXISTS idx_access_policies_lookup    ON access_policies(principal_id, resource_type, operation);

		CREATE TABLE IF NOT EXISTS role_assignments (
			id             TEXT PRIMARY KEY,
			principal_id   TEXT NOT NULL,
			principal_type TEXT NOT NULL,
			role           TEXT NOT NULL,
			vault_id       TEXT NOT NULL,
			created_by     TEXT NOT NULL,
			created_at     TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			UNIQUE (principal_id, role, vault_id),
			FOREIGN KEY (vault_id) REFERENCES vaults(id) ON DELETE CASCADE
		);
		CREATE INDEX IF NOT EXISTS idx_role_assignments_vault ON role_assignments(vault_id);
		CREATE INDEX IF NOT EXISTS idx_role_assignments_principal_vault ON role_assignments(principal_id, vault_id);

		CREATE TABLE IF NOT EXISTS vault_provisioning_grants (
			id           TEXT PRIMARY KEY,
			principal_id TEXT NOT NULL UNIQUE,
			quota        INTEGER NOT NULL,
			created_at   TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			created_by   TEXT NOT NULL
		);
		-- No FOREIGN KEY on principal_id: a grantee may be an oauth2_clients
		-- row (a service account) rather than a users row, and the MSP
		-- automation this table exists for is exactly that.
		CREATE INDEX IF NOT EXISTS idx_vaults_created_by ON vaults(created_by);

		CREATE TABLE IF NOT EXISTS oauth2_clients (
			id            TEXT PRIMARY KEY,
			name          TEXT NOT NULL UNIQUE,
			client_secret TEXT NOT NULL,
			description   TEXT DEFAULT '',
			enabled       BOOLEAN DEFAULT TRUE,
			created_at    TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			expires_at    TIMESTAMP NULL
		);
		CREATE INDEX IF NOT EXISTS idx_oauth2_clients_name ON oauth2_clients(name);

		CREATE TABLE IF NOT EXISTS audit_config (
			key   TEXT PRIMARY KEY,
			value TEXT NOT NULL
		);

		-- Indexes on the enriched audit_logs columns (outcome, resource_type,
		-- resource_id, source) are created in migrateSchema, after the ALTER TABLE
		-- statements that add those columns to pre-existing databases. Creating them
		-- here would fail on upgraded DBs where the columns do not yet exist.
	`)
	if err != nil {
		d.log.Error("Failed to create tables: ", err)
		return fmt.Errorf("failed to create tables: %w", err)
	}

	d.log.Info("Database schema created successfully with optimized indexes")
	return nil
}

// migrateSchema adds columns to existing databases that were created before
// those columns existed. Each ALTER TABLE is idempotent: duplicate-column errors
// are silently ignored so the function is safe to call on every startup.
func (d *DBRepository) migrateSchema(db *sql.DB) error {
	migrations := []string{
		// BUG-001: soft-delete columns missing from secrets (fresh-install schema fix)
		"ALTER TABLE secrets ADD COLUMN deleted_at TIMESTAMP NULL",
		"ALTER TABLE secrets ADD COLUMN purge_protection BOOLEAN NOT NULL DEFAULT FALSE",
		"ALTER TABLE secrets ADD COLUMN scheduled_purge_at TIMESTAMP NULL",
		// Feature: secret content types
		"ALTER TABLE secrets ADD COLUMN content_type TEXT NOT NULL DEFAULT ''",
		// Milestone 1: soft-delete columns for keys and certificates
		"ALTER TABLE keys ADD COLUMN deleted_at TIMESTAMP NULL",
		"ALTER TABLE keys ADD COLUMN purge_protection BOOLEAN NOT NULL DEFAULT FALSE",
		"ALTER TABLE keys ADD COLUMN scheduled_purge_at TIMESTAMP NULL",
		"ALTER TABLE certificates ADD COLUMN deleted_at TIMESTAMP NULL",
		"ALTER TABLE certificates ADD COLUMN purge_protection BOOLEAN NOT NULL DEFAULT FALSE",
		"ALTER TABLE certificates ADD COLUMN scheduled_purge_at TIMESTAMP NULL",
		// Bug fix: key_id column missing from certificates
		"ALTER TABLE certificates ADD COLUMN key_id TEXT NOT NULL DEFAULT ''",
		// Feature: certificate auto-renewal
		"ALTER TABLE certificates ADD COLUMN expires_at TIMESTAMP",
		"ALTER TABLE certificates ADD COLUMN auto_renew BOOLEAN NOT NULL DEFAULT FALSE",
		"ALTER TABLE certificates ADD COLUMN renewal_days INTEGER NOT NULL DEFAULT 30",
		// Feature: lifecycle attributes for secrets
		"ALTER TABLE secrets ADD COLUMN enabled BOOLEAN NOT NULL DEFAULT TRUE",
		"ALTER TABLE secrets ADD COLUMN expires_at TIMESTAMP NULL",
		"ALTER TABLE secrets ADD COLUMN not_before TIMESTAMP NULL",
		// Feature: lifecycle attributes for keys
		"ALTER TABLE keys ADD COLUMN enabled BOOLEAN NOT NULL DEFAULT TRUE",
		"ALTER TABLE keys ADD COLUMN expires_at TIMESTAMP NULL",
		"ALTER TABLE keys ADD COLUMN not_before TIMESTAMP NULL",
		"ALTER TABLE keys ADD COLUMN bits INTEGER NOT NULL DEFAULT 0",
		"ALTER TABLE keys ADD COLUMN curve TEXT NOT NULL DEFAULT ''",
		// Feature: Azure Key Vault parity — updated_at timestamp on keys.
		"ALTER TABLE keys ADD COLUMN updated_at TIMESTAMP NULL",
		// Feature: lifecycle attributes for certificates
		"ALTER TABLE certificates ADD COLUMN enabled BOOLEAN NOT NULL DEFAULT TRUE",
		"ALTER TABLE certificates ADD COLUMN not_before TIMESTAMP NULL",
		// B37: remember which CA signed a certificate, so renewal can re-issue
		// through the same CA instead of silently self-signing.
		"ALTER TABLE certificates ADD COLUMN ca_cert_id TEXT NULL",
		// Certificate versioning: the certificates row is always the current
		// version, and every earlier one is archived in certificate_versions.
		// Existing rows become version 1; nothing is backfilled. The ON DELETE
		// CASCADE only fires on Postgres; SQLite deletes these rows explicitly
		// in item_lifecycle.go.
		"ALTER TABLE certificates ADD COLUMN version INTEGER NOT NULL DEFAULT 1",
		`CREATE TABLE IF NOT EXISTS certificate_versions (
			certificate_id TEXT NOT NULL,
			version        INTEGER NOT NULL,
			certificate    TEXT NOT NULL,
			private_key    TEXT NOT NULL,
			key_id         TEXT NULL,
			created_at     TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			expires_at     TIMESTAMP NULL,
			not_before     TIMESTAMP NULL,
			enabled        BOOLEAN NOT NULL DEFAULT TRUE,
			PRIMARY KEY (certificate_id, version),
			FOREIGN KEY (certificate_id) REFERENCES certificates(id) ON DELETE CASCADE
		)`,
		"CREATE INDEX IF NOT EXISTS idx_certificate_versions_certificate_id ON certificate_versions(certificate_id)",
		// Export: an immutable opt-in flag set only at creation. Existing
		// rows become non-exportable and nothing is backfilled.
		// certificate_versions gets no column: versions share the parent's flag.
		"ALTER TABLE certificates ADD COLUMN exportable BOOLEAN NOT NULL DEFAULT FALSE",
		"ALTER TABLE keys ADD COLUMN exportable BOOLEAN NOT NULL DEFAULT FALSE",
		// Milestone 3: service-account / OAuth2 table (CREATE TABLE IF NOT EXISTS is idempotent)
		`CREATE TABLE IF NOT EXISTS oauth2_clients (
			id            TEXT PRIMARY KEY,
			name          TEXT NOT NULL UNIQUE,
			client_secret TEXT NOT NULL,
			description   TEXT DEFAULT '',
			enabled       BOOLEAN DEFAULT TRUE,
			created_at    TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			expires_at    TIMESTAMP NULL
		)`,
		"CREATE INDEX IF NOT EXISTS idx_oauth2_clients_name ON oauth2_clients(name)",
		// Feature: key versioning table for true rotation
		`CREATE TABLE IF NOT EXISTS key_versions (
			key_id     TEXT NOT NULL,
			version    INTEGER NOT NULL,
			value      TEXT NOT NULL,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			PRIMARY KEY (key_id, version),
			FOREIGN KEY (key_id) REFERENCES keys(id) ON DELETE CASCADE
		)`,
		"CREATE INDEX IF NOT EXISTS idx_key_versions_key_id ON key_versions(key_id)",
		// Feature: certificate policy table for creation and renewal settings
		`CREATE TABLE IF NOT EXISTS certificate_policies (
			id                TEXT PRIMARY KEY,
			certificate_id    TEXT NOT NULL UNIQUE,
			user_id           TEXT NOT NULL,
			validity_months   INTEGER NOT NULL DEFAULT 12,
			key_type          TEXT NOT NULL DEFAULT 'RSA',
			key_size          INTEGER NOT NULL DEFAULT 2048,
			curve             TEXT NOT NULL DEFAULT '',
			subject           TEXT NOT NULL DEFAULT '',
			sans              TEXT NOT NULL DEFAULT '',
			auto_renew        BOOLEAN NOT NULL DEFAULT FALSE,
			days_before_expiry INTEGER NOT NULL DEFAULT 30,
			issuer_name       TEXT NOT NULL DEFAULT '',
			created_at        TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			updated_at        TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			FOREIGN KEY (certificate_id) REFERENCES certificates(id) ON DELETE CASCADE,
			FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
		)`,
		"CREATE INDEX IF NOT EXISTS idx_cert_policies_cert_id ON certificate_policies(certificate_id)",
		"CREATE INDEX IF NOT EXISTS idx_cert_policies_user_id ON certificate_policies(user_id)",
		`CREATE TABLE IF NOT EXISTS key_rotation_policies (
			id                         TEXT PRIMARY KEY,
			key_id                     TEXT NOT NULL UNIQUE,
			user_id                    TEXT NOT NULL,
			vault_id                   TEXT NOT NULL DEFAULT '00000000-0000-0000-0000-00000000efa1',
			rotate_after_days          INTEGER NOT NULL DEFAULT 90,
			notify_before_expiry_days  INTEGER NOT NULL DEFAULT 30,
			expiry_days                INTEGER NOT NULL DEFAULT 365,
			enabled                    BOOLEAN NOT NULL DEFAULT TRUE,
			last_rotated_at            TIMESTAMP NULL,
			-- Nullable, no default: matches the ALTER TABLE pair below and
			-- createOptimizedSchema's copy of this table (see M3 in the
			-- final review).
			next_rotation_at           TIMESTAMP NULL,
			created_at                 TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			updated_at                 TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			FOREIGN KEY (key_id) REFERENCES keys(id) ON DELETE CASCADE,
			FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
		)`,
		"CREATE INDEX IF NOT EXISTS idx_key_rotation_policies_key_id ON key_rotation_policies(key_id)",
		"CREATE INDEX IF NOT EXISTS idx_key_rotation_policies_user_id ON key_rotation_policies(user_id)",
		// Feature: per-vault webhook configuration (idempotent — table did not
		// exist before this migration on any pre-existing database).
		`CREATE TABLE IF NOT EXISTS vault_webhook_configs (
			id                       TEXT PRIMARY KEY,
			vault_id                 TEXT NOT NULL UNIQUE,
			url                      TEXT NOT NULL,
			signing_secret_encrypted TEXT NOT NULL,
			enabled                  BOOLEAN NOT NULL DEFAULT TRUE,
			created_at               TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			updated_at               TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			FOREIGN KEY (vault_id) REFERENCES vaults(id) ON DELETE CASCADE
		)`,
		"CREATE INDEX IF NOT EXISTS idx_vault_webhook_configs_vault_id ON vault_webhook_configs(vault_id)",
		// Feature: bounded provisioning grants -- a right to create vaults up to
		// a quota, as a safer alternative to a global vaults:manage grant
		// (idempotent -- table did not exist before this migration on any
		// pre-existing database).
		`CREATE TABLE IF NOT EXISTS vault_provisioning_grants (
			id           TEXT PRIMARY KEY,
			principal_id TEXT NOT NULL UNIQUE,
			quota        INTEGER NOT NULL,
			created_at   TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			created_by   TEXT NOT NULL
		)`,
		// idx_vaults_created_by is created further down, after the vaults
		// table itself is created (a legacy database being migrated has no
		// vaults table yet at this point in the list).
		// Feature: rotation_policies for secrets (backfill will add vault_id below)
		`CREATE TABLE IF NOT EXISTS rotation_policies (
			id TEXT PRIMARY KEY,
			user_id TEXT NOT NULL,
			vault_id TEXT NOT NULL DEFAULT '00000000-0000-0000-0000-00000000efa1',
			name TEXT NOT NULL,
			description TEXT,
			interval_days INTEGER NOT NULL,
			enabled BOOLEAN NOT NULL DEFAULT TRUE,
			reminder_days INTEGER NOT NULL DEFAULT 7,
			auto_rotate BOOLEAN NOT NULL DEFAULT FALSE,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
		)`,
		"CREATE INDEX IF NOT EXISTS idx_rotation_policies_user_id ON rotation_policies(user_id)",
		"CREATE INDEX IF NOT EXISTS idx_rotation_policies_enabled ON rotation_policies(enabled)",
		"CREATE INDEX IF NOT EXISTS idx_rotation_policies_auto_rotate ON rotation_policies(auto_rotate)",
		// Feature: enriched audit fields for SOC 2 / GDPR compliance
		"ALTER TABLE audit_logs ADD COLUMN resource_type TEXT",
		"ALTER TABLE audit_logs ADD COLUMN resource_id TEXT",
		"ALTER TABLE audit_logs ADD COLUMN ip_address TEXT",
		"ALTER TABLE audit_logs ADD COLUMN outcome TEXT",
		"ALTER TABLE audit_logs ADD COLUMN source TEXT",
		"ALTER TABLE audit_logs ADD COLUMN prev_hash TEXT",
		// Indexes on the enriched audit_logs columns. These must run AFTER the
		// ALTER TABLE statements above so the columns exist on upgraded databases.
		"CREATE INDEX IF NOT EXISTS idx_audit_logs_outcome ON audit_logs(outcome)",
		"CREATE INDEX IF NOT EXISTS idx_audit_logs_resource ON audit_logs(resource_type, resource_id)",
		"CREATE INDEX IF NOT EXISTS idx_audit_logs_source ON audit_logs(source)",
		// Feature: audit configuration table (idempotent — IF NOT EXISTS prevents errors)
		"CREATE TABLE IF NOT EXISTS audit_config (key TEXT PRIMARY KEY, value TEXT NOT NULL)",
		// Multi-vault: vaults table and vault_id scoping columns.
		// The vault_id column defaults are hardcoded SQL literals and must stay
		// equal to model.DefaultVaultID ("00000000-0000-0000-0000-00000000efa1").
		`CREATE TABLE IF NOT EXISTS vaults (
			id                 TEXT PRIMARY KEY,
			name               TEXT UNIQUE NOT NULL,
			enabled            BOOLEAN NOT NULL DEFAULT TRUE,
			purge_protection   BOOLEAN NOT NULL DEFAULT FALSE,
			retention_days     INTEGER NOT NULL DEFAULT 90,
			created_by         TEXT NOT NULL,
			created_at         TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			deleted_at         TIMESTAMP NULL,
			scheduled_purge_at TIMESTAMP NULL
		)`,
		"CREATE INDEX IF NOT EXISTS idx_vaults_name ON vaults(name)",
		// Provisioning grants: plan 04 counts vaults by created_by on every
		// provisioned create, and vaults had only idx_vaults_name until now.
		"CREATE INDEX IF NOT EXISTS idx_vaults_created_by ON vaults(created_by)",
		// Vault tags + modification tracking (Azure parity). Tags stored as a JSON
		// object; (de)serialization is confined to vault_repository.go.
		"ALTER TABLE vaults ADD COLUMN tags TEXT NOT NULL DEFAULT '{}'",
		"ALTER TABLE vaults ADD COLUMN updated_at TIMESTAMP NULL",
		"ALTER TABLE vaults ADD COLUMN updated_by TEXT NULL",
		"ALTER TABLE secrets ADD COLUMN vault_id TEXT NOT NULL DEFAULT '00000000-0000-0000-0000-00000000efa1'",
		"ALTER TABLE keys ADD COLUMN vault_id TEXT NOT NULL DEFAULT '00000000-0000-0000-0000-00000000efa1'",
		"ALTER TABLE certificates ADD COLUMN vault_id TEXT NOT NULL DEFAULT '00000000-0000-0000-0000-00000000efa1'",
		"ALTER TABLE key_rotation_policies ADD COLUMN vault_id TEXT NOT NULL DEFAULT '00000000-0000-0000-0000-00000000efa1'",
		"ALTER TABLE key_rotation_policies ADD COLUMN last_rotated_at TIMESTAMP",
		"ALTER TABLE key_rotation_policies ADD COLUMN next_rotation_at TIMESTAMP",
		"ALTER TABLE rotation_policies ADD COLUMN vault_id TEXT NOT NULL DEFAULT '00000000-0000-0000-0000-00000000efa1'",
		"CREATE INDEX IF NOT EXISTS idx_key_rotation_policies_vault_id ON key_rotation_policies(vault_id)",
		"CREATE INDEX IF NOT EXISTS idx_rotation_policies_vault_id ON rotation_policies(vault_id)",
		"UPDATE key_rotation_policies SET vault_id = (SELECT vault_id FROM keys WHERE keys.id = key_rotation_policies.key_id) WHERE key_id IN (SELECT id FROM keys)",
		"ALTER TABLE access_policies ADD COLUMN vault_id TEXT NULL",
		"ALTER TABLE access_policies ADD COLUMN assignment_id TEXT NULL",
		// Feature: OIDC external identity provider login
		"ALTER TABLE users ADD COLUMN auth_provider TEXT NOT NULL DEFAULT 'local'",
		"ALTER TABLE users ADD COLUMN external_idp_subject TEXT",
		"CREATE UNIQUE INDEX IF NOT EXISTS idx_users_external_idp ON users(auth_provider, external_idp_subject) WHERE external_idp_subject IS NOT NULL",
		// Feature: TOTP replay protection, last accepted time step per user.
		"ALTER TABLE users ADD COLUMN totp_last_step INTEGER NOT NULL DEFAULT 0",
	}
	for _, stmt := range migrations {
		if _, err := db.Exec(stmt); err != nil {
			if !isDuplicateColumnError(err) {
				return fmt.Errorf("migration failed (%q): %w", stmt, err)
			}
		}
	}

	// Backfill key_rotation_policies.next_rotation_at for rows that predate
	// this column. Anchored on this migration's own run time, not the key's
	// created_at: using created_at would retroactively mark every existing
	// enabled policy whose key predates its own rotation window as
	// simultaneously overdue the moment this feature ships -- a mass
	// rotation nobody asked for at that moment. See
	// docs/superpowers/specs/2026-08-18-rotation-policy-scheduler-design.md
	// section 4. Only rows already migrated by the ALTER TABLE statements
	// above (next_rotation_at IS NULL) are touched, so re-running this is a
	// no-op once every row has a value.
	now := time.Now().UTC()
	backfillSQL := "UPDATE key_rotation_policies SET next_rotation_at = datetime(?, '+' || rotate_after_days || ' days') WHERE next_rotation_at IS NULL"
	if d.dialect == Postgres {
		backfillSQL = "UPDATE key_rotation_policies SET next_rotation_at = ?::timestamp + (rotate_after_days || ' days')::interval WHERE next_rotation_at IS NULL"
	}
	if _, err := db.Exec(d.dialect.Rebind(backfillSQL), now); err != nil {
		return fmt.Errorf("backfill key_rotation_policies.next_rotation_at: %w", err)
	}

	// Feature: vault-scoped role assignments table (idempotent).
	// Runs after the loop so the vaults table (created above) already exists.
	if _, err := db.Exec(`CREATE TABLE IF NOT EXISTS role_assignments (
		id             TEXT PRIMARY KEY,
		principal_id   TEXT NOT NULL,
		principal_type TEXT NOT NULL,
		role           TEXT NOT NULL,
		vault_id       TEXT NOT NULL,
		created_by     TEXT NOT NULL,
		created_at     TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		UNIQUE (principal_id, role, vault_id),
		FOREIGN KEY (vault_id) REFERENCES vaults(id) ON DELETE CASCADE
	)`); err != nil {
		return fmt.Errorf("create role_assignments: %w", err)
	}
	if _, err := db.Exec(`CREATE INDEX IF NOT EXISTS idx_role_assignments_vault ON role_assignments(vault_id)`); err != nil {
		return fmt.Errorf("index role_assignments vault: %w", err)
	}
	// Composite index for RoleAssignmentRepository's per-(principal, vault)
	// authorization lookup, which runs on every data-plane request.
	if _, err := db.Exec(`CREATE INDEX IF NOT EXISTS idx_role_assignments_principal_vault ON role_assignments(principal_id, vault_id)`); err != nil {
		return fmt.Errorf("index role_assignments principal/vault: %w", err)
	}

	// Feature: multi-role users (idempotent). users.role is left in place,
	// unused by new code — see docs/superpowers/specs/2026-08-23-multi-role-user-assignment-design.md.
	// ON DELETE CASCADE only fires on Postgres: SQLite's foreign_keys PRAGMA
	// is off project-wide (see the audit_logs note above), so a SQLite
	// deployment must delete user_roles rows manually on user deletion, the
	// way vault_service.go:497 already does for its own SQLite-inert cascades.
	if _, err := db.Exec(`CREATE TABLE IF NOT EXISTS user_roles (
		id         TEXT PRIMARY KEY,
		user_id    TEXT NOT NULL,
		role       TEXT NOT NULL,
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		UNIQUE (user_id, role),
		FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
	)`); err != nil {
		return fmt.Errorf("create user_roles: %w", err)
	}
	if _, err := db.Exec(`CREATE INDEX IF NOT EXISTS idx_user_roles_user ON user_roles(user_id)`); err != nil {
		return fmt.Errorf("index user_roles user: %w", err)
	}

	// Backfill: split every existing users.role value (including legacy
	// comma-joined strings from the pre-normalization multi-role feature)
	// into user_roles. INSERT OR IGNORE (ON CONFLICT DO NOTHING on Postgres)
	// makes each insert idempotent, and the NOT EXISTS guard below skips any
	// user who already has at least one user_roles row, so this does not
	// re-scan and rewrite every user on every startup once it has run once.
	rows, err := db.Query(`SELECT u.id, u.role FROM users u
		WHERE NOT EXISTS (SELECT 1 FROM user_roles ur WHERE ur.user_id = u.id)`)
	if err != nil {
		return fmt.Errorf("read users for role backfill: %w", err)
	}
	type userRoleRow struct{ userID, role string }
	var toBackfill []userRoleRow
	for rows.Next() {
		var id string
		var role sql.NullString
		if err := rows.Scan(&id, &role); err != nil {
			rows.Close()
			return fmt.Errorf("scan user for role backfill: %w", err)
		}
		toBackfill = append(toBackfill, userRoleRow{id, role.String})
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return fmt.Errorf("iterate users for role backfill: %w", err)
	}
	rows.Close()

	// Rebound once, outside the loop, per dialect: SQLite uses "INSERT OR
	// IGNORE" with "?" placeholders; Postgres needs "ON CONFLICT DO NOTHING"
	// with "$1, $2, $3" placeholders. Mirrors the key_rotation_policies
	// backfill above.
	insertSQL := d.dialect.Rebind(d.dialect.UpsertIgnore(
		"user_roles", "id, user_id, role", "?, ?, ?", "user_id, role",
	))

	for _, u := range toBackfill {
		seen := map[string]bool{}
		roles := []string{}
		for _, part := range strings.Split(u.role, ",") {
			r := strings.TrimSpace(part)
			if r == "" || seen[r] {
				continue
			}
			seen[r] = true
			roles = append(roles, r)
		}
		// Defensive guard: an empty or unparseable role column (empty string,
		// NULL, bare comma, whitespace-only) must not silently leave a user
		// with zero user_roles rows. No current write path persists a user
		// this way (CLI and service-layer validation both reject it), but the
		// migration's own invariant is "every users row gets at least one
		// user_roles row" -- fall back to the least-privilege default, same
		// as FindOrCreateExternalUser does for external users of unknown role.
		if len(roles) == 0 {
			roles = []string{model.RoleUser}
			d.log.WithFields(map[string]interface{}{
				"user_id": u.userID,
			}).Warn("User role column was empty or unparseable during user_roles backfill; defaulting to 'user'")
		}
		for _, r := range roles {
			if _, err := db.Exec(insertSQL, uuid.New().String(), u.userID, r); err != nil {
				return fmt.Errorf("backfill user_roles for user %s: %w", u.userID, err)
			}
		}
	}

	if _, err := db.Exec(`CREATE INDEX IF NOT EXISTS idx_access_policies_assignment ON access_policies(assignment_id)`); err != nil {
		return fmt.Errorf("index access_policies assignment: %w", err)
	}

	// Fix: audit_logs.user_id previously FK'd to users(id), but OAuth2 token-issuance
	// audit events (Task 3) write the client NAME there, which is never a users.id row.
	// SQLite never enforces this FK (foreign_keys PRAGMA is off by default here), so it's
	// left alone there; Postgres does enforce it, so drop it explicitly on that dialect.
	if d.dialect == Postgres {
		if _, err := db.Exec(`ALTER TABLE audit_logs DROP CONSTRAINT IF EXISTS audit_logs_user_id_fkey`); err != nil {
			return fmt.Errorf("drop audit_logs user_id FK: %w", err)
		}
	}

	// P2 upgrade: derive per-vault Azure role assignments from existing object
	// ownership. Must run before the deny-by-default PolicyMiddleware takes
	// effect, or every existing deployment loses access to its own data.
	if err := d.backfillRoleAssignments(db); err != nil {
		return fmt.Errorf("backfill role assignments: %w", err)
	}

	// Diagnostic only: surface legacy policy/secret pairings the vault_id
	// backfill cannot repair on its own. Never fails the migration.
	d.warnMismatchedRotationPolicyVaults(db)

	// Diagnostic only: surface principals whose global vaults:manage grant
	// will be narrowed by a planned follow-up release. Never fails the migration.
	d.warnGlobalVaultManageGrants(db)

	d.log.Info("Schema migration completed")
	return nil
}

// warnMismatchedRotationPolicyVaults logs (never fails) a warning for every
// secret_policies pairing whose secret and policy disagree on vault_id -- a
// legacy pairing from before secrets and rotation_policies were both
// vault-scoped. rotation_policies got a blind default-vault backfill, which is
// correct for the policy rows' own provenance (the table predates vault_id
// existing anywhere), but any pairing whose secret lives in a non-default
// vault becomes a cross-vault pair. Manual rotation of such a pair now fails
// from both vaults -- each read is scoped to its own vault -- while the
// scheduler keeps rotating it (its queries carry no vault predicate), so the
// breakage is otherwise silent until an operator tries a manual rotation.
//
// A query error here is expected and harmless on partially-built schemas (for
// example a migrateSchema-only test fixture with no secret_policies table), so
// it is logged at warn level and swallowed.
func (d *DBRepository) warnMismatchedRotationPolicyVaults(db *sql.DB) {
	rows, err := db.Query(`
		SELECT sp.secret_id, sp.policy_id, s.vault_id, rp.vault_id
		FROM secret_policies sp
		JOIN secrets s ON s.id = sp.secret_id
		JOIN rotation_policies rp ON rp.id = sp.policy_id
		WHERE s.vault_id != rp.vault_id
	`)
	if err != nil {
		d.log.WithError(err).Warn("Failed to check for cross-vault rotation-policy assignments")
		return
	}
	defer rows.Close() //nolint:errcheck

	for rows.Next() {
		var secretID, policyID, secretVault, policyVault string
		if err := rows.Scan(&secretID, &policyID, &secretVault, &policyVault); err != nil {
			d.log.WithError(err).Warn("Failed to scan cross-vault rotation-policy row")
			continue
		}
		d.log.WithFields(map[string]interface{}{
			"secret_id":    secretID,
			"policy_id":    policyID,
			"secret_vault": secretVault,
			"policy_vault": policyVault,
		}).Warn("Rotation policy assigned across vaults -- manual rotation of this pair will fail from either vault; run `rotation unassign` and reassign within one vault to fix")
	}
	if err := rows.Err(); err != nil {
		d.log.WithError(err).Warn("Failed to read cross-vault rotation-policy rows")
	}
}

// warnGlobalVaultManageGrants logs (never fails) every principal holding a
// global -- vault_id IS NULL -- (vaults, manage, allow) access policy.
//
// As of v4.6.0, such a policy confers only the ability to create and list
// vaults: CheckVaultScopedAccess (internal/services/authorization) is now used
// by CanManageVault and CanManageRoleAssignments whenever a concrete vault ID
// is in play, and it does not match a NULL-scoped allow the way CheckAccess
// does. A NULL-scoped allow still satisfies the uuid.Nil (create/list) branch
// of CanManageVault via CheckAccess/FindEffects -- that part is unchanged.
//
// This diagnostic exists so operators can see, on every boot, exactly which
// principals had their authority narrowed by this release -- get/update/
// delete, recover, webhook configuration, and role-assignment management on
// vaults they did not create are all gone for a global-only holder. If one of
// those principals genuinely needs standing authority over vaults it did not
// create, that must now be granted vault-scoped explicitly; if it only ever
// needed to create and manage its own vaults, a bounded provisioning grant
// (vault_provisioning_grants) is the replacement.
//
// A query error here is expected and harmless on partially-built schemas (for
// example a migrateSchema-only test fixture with no access_policies table), so
// it is logged at warn level and swallowed.
func (d *DBRepository) warnGlobalVaultManageGrants(db *sql.DB) {
	rows, err := db.Query(`
		SELECT principal_id, principal_type
		FROM access_policies
		WHERE resource_type = 'vaults' AND operation = 'manage'
		  AND effect = 'allow' AND vault_id IS NULL`)
	if err != nil {
		d.log.WithError(err).Warn("Failed to check for global vaults:manage grants")
		return
	}
	defer rows.Close() //nolint:errcheck

	for rows.Next() {
		var principalID, principalType string
		if err := rows.Scan(&principalID, &principalType); err != nil {
			d.log.WithError(err).Warn("Failed to scan a global vaults:manage grant; continuing")
			// This diagnostic must report EVERY affected principal, so a single
			// unreadable row must not truncate the list -- stopping here would
			// silently under-report who is affected by the coming narrowing.
			continue
		}
		d.log.WithFields(map[string]interface{}{
			"principal_id":   principalID,
			"principal_type": principalType,
		}).Warn("Principal holds a global vaults:manage grant, which since v4.6.0 confers vault create-and-list only; if it previously managed vaults it did not create, those grants must now be issued vault-scoped (see docs/release-notes/v4.6.0-narrow-global-vault-manage.md), or replaced with a bounded vault provisioning grant if it only ever needed to create and manage its own vaults.")
	}
	if err := rows.Err(); err != nil {
		d.log.WithError(err).Warn("Failed to iterate global vaults:manage grants")
	}
}

// finalizeVaultIndexes resolves name collisions then creates the per-vault unique
// indexes. Safe to run on every startup: it always leaves the same end state, so
// it is idempotent in effect even though the DROP/CREATE pair below really runs
// each time rather than becoming a no-op after the first boot.
//
// The indexes are partial -- WHERE deleted_at IS NULL -- so a soft-deleted
// secret, key or certificate no longer holds its name hostage against a
// replacement of the same name in the same vault (B50). Only active rows are
// constrained, which matches what every list and read path can actually see.
//
// Each index is dropped before being recreated, unconditionally. CREATE UNIQUE
// INDEX IF NOT EXISTS matches on the index NAME, not its definition, so on a
// database that already carries the old non-partial index of the same name it
// would be a silent no-op and the old definition would survive this fix
// forever. Introspecting the existing definition first would need
// dialect-specific queries (sqlite_master vs pg_indexes) for no real gain on
// three small indexes, so the drop is simply always done.
//
// DROP INDEX IF EXISTS and partial indexes are spelled identically in SQLite
// and PostgreSQL, so no dialect branching is needed here. Neither this function
// nor its caller runs inside a transaction (SetupSchema executes each step as
// plain statements), so the brief window between the DROP and the CREATE where
// the constraint is absent matches the existing risk profile of the boot
// sequence rather than introducing a new one.
func (d *DBRepository) finalizeVaultIndexes(db *sql.DB) error {
	ctx := context.Background()
	for _, table := range []string{"secrets", "keys", "certificates"} {
		if _, err := ResolveNameCollisions(ctx, NewConn(db, d.dialect), table); err != nil {
			return err
		}
	}
	indexes := []struct{ name, table string }{
		{"idx_secrets_vault_name", "secrets"},
		{"idx_keys_vault_name", "keys"},
		{"idx_certificates_vault_name", "certificates"},
	}
	for _, idx := range indexes {
		if _, err := db.Exec(fmt.Sprintf("DROP INDEX IF EXISTS %s", idx.name)); err != nil {
			return fmt.Errorf("drop vault unique index %s: %w", idx.name, err)
		}
		if _, err := db.Exec(fmt.Sprintf(
			"CREATE UNIQUE INDEX IF NOT EXISTS %s ON %s(vault_id, name) WHERE deleted_at IS NULL",
			idx.name, idx.table)); err != nil {
			return fmt.Errorf("create vault unique index %s: %w", idx.name, err)
		}
	}
	return nil
}

// isDuplicateColumnError returns true when err represents a "column already exists"
// error from SQLite or PostgreSQL, allowing migrateSchema to be idempotent.
// The logic now lives on Dialect; this shim keeps existing call sites unchanged.
func isDuplicateColumnError(err error) bool {
	// The check is dialect-agnostic (string match plus pq code), so either
	// dialect value produces the same result here.
	return SQLite.IsDuplicateColumnErr(err)
}

// systemUserPasswordHash is a deliberately syntactically-invalid bcrypt hash
// (a real hash always starts with "$2a$"/"$2b$" etc.). bcrypt.CompareHashAndPassword
// rejects any malformed hash before it ever compares a candidate password, so
// the system user can never authenticate under any password -- there is
// nothing to brute-force, unlike a valid hash of some fixed secret value.
const systemUserPasswordHash = "!system-account-no-login!"

// seedSystemUser inserts the reserved row at model.SystemUserID if absent.
// It is idempotent. This row exists solely so FOREIGN KEY (user_id)
// REFERENCES users(id) constraints -- e.g. on the keys table -- can be
// satisfied by internally-generated resources with no human owner, such as
// SelfPKIProvider's own JWT signing key (internal/signing/self_pki.go,
// stored with UserID: uuid.Nil). Postgres enforces that FK unconditionally;
// SQLite does not (foreign_keys PRAGMA is off project-wide, see the
// audit_logs note above), which is why a missing system user row only ever
// breaks a Postgres deployment. See known-bugs.md B60.
func (d *DBRepository) seedSystemUser(db *sql.DB) error {
	var count int
	if err := db.QueryRow(
		d.dialect.Rebind("SELECT COUNT(*) FROM users WHERE id = ?"), model.SystemUserID,
	).Scan(&count); err != nil {
		return fmt.Errorf("failed to check system user: %w", err)
	}
	if count > 0 {
		return nil
	}
	if _, err := db.Exec(
		d.dialect.Rebind("INSERT INTO users (id, username, password_hash, role, auth_provider) VALUES (?, ?, ?, ?, ?)"),
		model.SystemUserID, model.SystemUsername, systemUserPasswordHash, model.RoleSystem, "local",
	); err != nil {
		return fmt.Errorf("failed to seed system user: %w", err)
	}
	return nil
}

// seedBootstrapToken inserts the configured bootstrap token into the
// bootstrap_tokens table if it is not already present. The SELECT-then-INSERT
// approach keeps the SQL portable across SQLite and PostgreSQL drivers.
func (d *DBRepository) seedBootstrapToken(db *sql.DB) error {
	token := viper.GetString("bootstrap_token")
	if token == "" {
		return nil
	}

	var count int
	if err := db.QueryRow(
		d.dialect.Rebind("SELECT COUNT(*) FROM bootstrap_tokens WHERE token = ?"), token,
	).Scan(&count); err != nil {
		return fmt.Errorf("failed to check bootstrap token: %w", err)
	}

	if count > 0 {
		return nil // already seeded (or already used)
	}

	if _, err := db.Exec(
		d.dialect.Rebind("INSERT INTO bootstrap_tokens (token, used) VALUES (?, FALSE)"), token,
	); err != nil {
		return fmt.Errorf("failed to seed bootstrap token: %w", err)
	}
	return nil
}

// seedAuditConfig inserts default audit configuration values if they are not
// already present. Safe to call on every startup.
func (d *DBRepository) seedAuditConfig(db *sql.DB) error {
	defaults := map[string]string{
		"retention_days": "365",
	}
	for k, v := range defaults {
		var count int
		if err := db.QueryRow(
			d.dialect.Rebind("SELECT COUNT(*) FROM audit_config WHERE key = ?"), k,
		).Scan(&count); err != nil {
			return fmt.Errorf("failed to check audit_config key %q: %w", k, err)
		}
		if count == 0 {
			if _, err := db.Exec(
				d.dialect.Rebind("INSERT INTO audit_config (key, value) VALUES (?, ?)"), k, v,
			); err != nil {
				return fmt.Errorf("failed to seed audit_config key %q: %w", k, err)
			}
		}
	}
	return nil
}

// seedDefaultVault inserts the default vault if it is absent. It is idempotent.
// The default vault holds all pre-multi-vault data and backs the legacy flat routes.
func (d *DBRepository) seedDefaultVault(db *sql.DB) error {
	var count int
	if err := db.QueryRow(d.dialect.Rebind("SELECT COUNT(*) FROM vaults WHERE name = ?"), model.DefaultVaultName).Scan(&count); err != nil {
		return fmt.Errorf("failed to check default vault: %w", err)
	}
	if count > 0 {
		return nil
	}
	// Choose an owner: an existing admin, else any user, else the zero UUID.
	creator := "00000000-0000-0000-0000-000000000000"
	_ = db.QueryRow(d.dialect.Rebind("SELECT COALESCE((SELECT id FROM users WHERE role = 'admin' LIMIT 1), (SELECT id FROM users LIMIT 1), ?)"), creator).Scan(&creator)
	if _, err := db.Exec(
		d.dialect.Rebind("INSERT INTO vaults (id, name, enabled, retention_days, created_by) VALUES (?, ?, ?, ?, ?)"),
		model.DefaultVaultID, model.DefaultVaultName, true, 90, creator,
	); err != nil {
		return fmt.Errorf("failed to seed default vault: %w", err)
	}
	return nil
}

// CloseDB closes the database connection.
// It ensures the connection is properly closed during application shutdown.
//
// Parameters:
//
//	none
//
// Returns:
//
//	An error if the connection cannot be closed.
//
// The function is called to clean up resources when the application terminates.
func (d *DBRepository) CloseDB() error {
	if d.db == nil {
		return nil
	}

	// Close the database connection.
	if err := d.db.Close(); err != nil {
		d.log.Println("Failed to close database: ", err)
		return fmt.Errorf("failed to close database: %w", err)
	}

	d.log.Println("Database connection closed")
	return nil
}

// slowQueryThreshold is the duration above which a query counts as slow.
// Configurable via monitoring.slow_query_threshold (see config.LoadMonitoringConfig).
var (
	slowQueryThreshold   = 100 * time.Millisecond
	slowQueryThresholdMu sync.RWMutex
)

// SetSlowQueryThreshold configures the duration above which RecordQueryExecution
// counts a query as slow. Safe for concurrent use.
func SetSlowQueryThreshold(d time.Duration) {
	slowQueryThresholdMu.Lock()
	defer slowQueryThresholdMu.Unlock()
	slowQueryThreshold = d
}

func getSlowQueryThreshold() time.Duration {
	slowQueryThresholdMu.RLock()
	defer slowQueryThresholdMu.RUnlock()
	return slowQueryThreshold
}

// SlowQueryThreshold returns the duration above which a query counts as slow,
// as configured by monitoring.slow_query_threshold. Exported so the repository
// layer logs slow-query warnings at the same cutoff RecordQueryExecution uses
// for the SlowQueryCount metric -- they previously disagreed, because every
// repository hardcoded 100ms while this value was configurable.
// Safe for concurrent use.
func SlowQueryThreshold() time.Duration {
	return getSlowQueryThreshold()
}

// RecordQueryExecution records query performance metrics.
func RecordQueryExecution(duration time.Duration) {
	metrics.mu.Lock()
	defer metrics.mu.Unlock()

	metrics.QueryCount++
	metrics.TotalQueryTime += duration

	if metrics.QueryCount > 0 {
		metrics.AverageQueryTime = metrics.TotalQueryTime / time.Duration(metrics.QueryCount)
	}

	if duration > getSlowQueryThreshold() {
		metrics.SlowQueryCount++
	}
}

// PerformanceMetricsSnapshot is a copy of PerformanceMetrics without the mutex for safe return.
type PerformanceMetricsSnapshot struct {
	QueryCount       int64         `json:"query_count"`
	SlowQueryCount   int64         `json:"slow_query_count"`
	TotalQueryTime   time.Duration `json:"total_query_time"`
	AverageQueryTime time.Duration `json:"avg_query_time"`
	ConnectionStats  sql.DBStats   `json:"connection_stats"`
}

// GetPerformanceMetrics returns current database performance metrics without
// copying the mutex. conn is the connection to report pool stats for; pass
// nil to omit ConnectionStats.
func GetPerformanceMetrics(conn *sql.DB) PerformanceMetricsSnapshot {
	metrics.mu.RLock()
	defer metrics.mu.RUnlock()

	result := PerformanceMetricsSnapshot{
		QueryCount:       metrics.QueryCount,
		SlowQueryCount:   metrics.SlowQueryCount,
		TotalQueryTime:   metrics.TotalQueryTime,
		AverageQueryTime: metrics.AverageQueryTime,
	}

	// Add current connection stats if a connection was given.
	if conn != nil {
		result.ConnectionStats = conn.Stats()
	}

	return result
}

// ResetPerformanceMetrics resets performance tracking metrics.
func ResetPerformanceMetrics() {
	metrics.mu.Lock()
	defer metrics.mu.Unlock()

	metrics.QueryCount = 0
	metrics.SlowQueryCount = 0
	metrics.TotalQueryTime = 0
	metrics.AverageQueryTime = 0
}

// GetConnectionPoolStats returns detailed connection pool statistics.
func (d *DBRepository) GetConnectionPoolStats() map[string]interface{} {
	if d.db == nil {
		return map[string]interface{}{"error": "database not initialized"}
	}

	stats := d.db.Stats()
	return map[string]interface{}{
		"open_connections":    stats.OpenConnections,
		"in_use":              stats.InUse,
		"idle":                stats.Idle,
		"wait_count":          stats.WaitCount,
		"wait_duration_ms":    stats.WaitDuration.Milliseconds(),
		"max_idle_closed":     stats.MaxIdleClosed,
		"max_lifetime_closed": stats.MaxLifetimeClosed,
		"utilization_percent": float64(stats.InUse) / float64(stats.OpenConnections) * 100,
	}
}

// HealthCheck performs comprehensive database health validation.
func (d *DBRepository) HealthCheck(ctx context.Context) error {
	if d.db == nil {
		return fmt.Errorf("database not initialized")
	}

	// Test connection with timeout
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	start := time.Now()
	if err := d.db.PingContext(ctx); err != nil {
		return fmt.Errorf("database ping failed: %w", err)
	}
	duration := time.Since(start)

	// Record the health check as a query
	RecordQueryExecution(duration)

	// Check connection pool health
	stats := d.db.Stats()
	if stats.OpenConnections == 0 {
		return fmt.Errorf("no open database connections")
	}

	// Warn about potential issues
	if stats.WaitCount > 100 && stats.WaitDuration > time.Millisecond*100 {
		return fmt.Errorf("database connection pool under stress: wait_count=%d, wait_duration=%v",
			stats.WaitCount, stats.WaitDuration)
	}

	return nil
}
