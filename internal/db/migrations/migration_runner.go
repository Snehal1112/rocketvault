// Package migrations provides database migration functionality for the password manager.
package migrations

import (
	"context"
	"database/sql"
	"embed"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/sirupsen/logrus"

	"rocketvault/internal/db"
)

//go:embed *.sql
var migrationFiles embed.FS

// Migration represents a database migration.
type Migration struct {
	Version   string
	Name      string
	UpSQL     string
	DownSQL   string
	Timestamp time.Time
}

// MigrationRunner manages database migrations.
type MigrationRunner struct {
	db     *sql.DB
	logger *logrus.Logger
}

// NewMigrationRunner creates a new migration runner.
func NewMigrationRunner(db *sql.DB, logger *logrus.Logger) *MigrationRunner {
	return &MigrationRunner{
		db:     db,
		logger: logger,
	}
}

// Initialize creates the migrations tracking table if it doesn't exist.
func (r *MigrationRunner) Initialize(ctx context.Context) error {
	createTableSQL := `
	CREATE TABLE IF NOT EXISTS schema_migrations (
		version VARCHAR(255) PRIMARY KEY,
		applied_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
	)`

	_, err := r.db.ExecContext(ctx, createTableSQL)
	if err != nil {
		return fmt.Errorf("failed to create migrations table: %w", err)
	}

	return nil
}

// GetAppliedMigrations returns a list of already applied migrations.
func (r *MigrationRunner) GetAppliedMigrations(ctx context.Context) (map[string]bool, error) {
	rows, err := r.db.QueryContext(ctx, "SELECT version FROM schema_migrations")
	if err != nil {
		return nil, fmt.Errorf("failed to query applied migrations: %w", err)
	}
	defer rows.Close() //nolint:errcheck

	applied := make(map[string]bool)
	for rows.Next() {
		var version string
		if err := rows.Scan(&version); err != nil {
			return nil, fmt.Errorf("failed to scan migration version: %w", err)
		}
		applied[version] = true
	}

	return applied, nil
}

// LoadMigrations loads all available migration files from the embedded filesystem.
func (r *MigrationRunner) LoadMigrations() ([]Migration, error) {
	files, err := migrationFiles.ReadDir(".")
	if err != nil {
		return nil, fmt.Errorf("failed to read migration files: %w", err)
	}

	var migrations []Migration
	for _, file := range files {
		if file.IsDir() {
			continue
		}

		name := file.Name()
		if !strings.HasSuffix(name, ".sql") {
			continue
		}

		content, err := migrationFiles.ReadFile(name)
		if err != nil {
			return nil, fmt.Errorf("failed to read migration file %s: %w", name, err)
		}

		// Parse filename to extract version and direction
		base := strings.TrimSuffix(name, ".sql")
		parts := strings.Split(base, "_")
		if len(parts) < 2 {
			continue // Skip files that don't match expected format
		}

		version := parts[0]
		migrationName := strings.Join(parts[1:], "_")

		migration := Migration{
			Version: version,
			Name:    migrationName,
			UpSQL:   string(content),
		}

		// Try to parse timestamp from version
		if ts, err := time.Parse("20060102150405", version); err == nil {
			migration.Timestamp = ts
		}

		migrations = append(migrations, migration)
	}

	// Sort migrations by version
	sort.Slice(migrations, func(i, j int) bool {
		return migrations[i].Version < migrations[j].Version
	})

	return migrations, nil
}

// ApplyMigration applies a single migration.
//
// A database bootstrapped the normal way (serve's startup path, via
// createOptimizedSchema in internal/db/db.go) already has every column these
// migration files ALTER TABLE ... ADD COLUMN in their CREATE TABLE
// statements, since db.go is kept current for fresh installs; only upgrades
// of pre-existing databases actually need the ALTER TABLE to do anything.
// schema_migrations is never populated by that boot path, so the first
// `rocketvault migrate` run against such a database used to fail outright on
// the resulting "duplicate column" error (B47). Statements run one at a time
// so a harmless duplicate-column error on one ALTER TABLE doesn't abort
// later statements in the same file that do need to run.
func (r *MigrationRunner) ApplyMigration(ctx context.Context, migration Migration) error {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback() //nolint:errcheck

	for _, stmt := range splitStatements(migration.UpSQL) {
		if _, err := tx.ExecContext(ctx, stmt); err != nil {
			if db.SQLite.IsDuplicateColumnErr(err) {
				r.logger.WithFields(logrus.Fields{
					"version":   migration.Version,
					"statement": stmt,
				}).Warn("Column already exists, skipping statement (schema was already current from bootstrap)")
				continue
			}
			return fmt.Errorf("failed to execute migration %s: %w", migration.Version, err)
		}
	}

	// Record the migration as applied
	if _, err := tx.ExecContext(ctx,
		"INSERT INTO schema_migrations (version) VALUES (?)",
		migration.Version); err != nil {
		return fmt.Errorf("failed to record migration %s: %w", migration.Version, err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit migration %s: %w", migration.Version, err)
	}

	r.logger.WithFields(logrus.Fields{
		"version": migration.Version,
		"name":    migration.Name,
	}).Info("Migration applied successfully")

	return nil
}

// splitStatements splits a migration file's SQL into individual statements
// on ";" boundaries, dropping empty/comment-only fragments. It is not a
// general-purpose SQL parser, but it does track "--" line comments and
// single-quoted string literals so a ";" inside either of those (e.g. the
// comment prose in 20260308000002_add_access_policies.sql) does not split a
// statement in two.
func splitStatements(sql string) []string {
	var statements []string
	var current strings.Builder
	inLineComment := false
	inString := false

	runes := []rune(sql)
	for i := 0; i < len(runes); i++ {
		c := runes[i]

		if inLineComment {
			current.WriteRune(c)
			if c == '\n' {
				inLineComment = false
			}
			continue
		}

		if inString {
			current.WriteRune(c)
			if c == '\'' {
				inString = false
			}
			continue
		}

		switch {
		case c == '-' && i+1 < len(runes) && runes[i+1] == '-':
			inLineComment = true
			current.WriteRune(c)
		case c == '\'':
			inString = true
			current.WriteRune(c)
		case c == ';':
			statements = append(statements, current.String())
			current.Reset()
		default:
			current.WriteRune(c)
		}
	}
	if strings.TrimSpace(current.String()) != "" {
		statements = append(statements, current.String())
	}

	result := make([]string, 0, len(statements))
	for _, stmt := range statements {
		trimmed := strings.TrimSpace(stmt)
		if trimmed == "" {
			continue
		}
		isCommentOnly := true
		for _, line := range strings.Split(trimmed, "\n") {
			line = strings.TrimSpace(line)
			if line != "" && !strings.HasPrefix(line, "--") {
				isCommentOnly = false
				break
			}
		}
		if isCommentOnly {
			continue
		}
		result = append(result, trimmed)
	}
	return result
}

// MigrateUp applies all pending migrations.
func (r *MigrationRunner) MigrateUp(ctx context.Context) error {
	if err := r.Initialize(ctx); err != nil {
		return err
	}

	applied, err := r.GetAppliedMigrations(ctx)
	if err != nil {
		return err
	}

	migrations, err := r.LoadMigrations()
	if err != nil {
		return err
	}

	appliedCount := 0
	for _, migration := range migrations {
		if applied[migration.Version] {
			continue // Skip already applied migrations
		}

		r.logger.WithFields(logrus.Fields{
			"version": migration.Version,
			"name":    migration.Name,
		}).Info("Applying migration")

		if err := r.ApplyMigration(ctx, migration); err != nil {
			return fmt.Errorf("failed to apply migration %s: %w", migration.Version, err)
		}

		appliedCount++
	}

	if appliedCount == 0 {
		r.logger.Info("No pending migrations found")
	} else {
		r.logger.WithField("count", appliedCount).Info("All pending migrations applied")
	}

	return nil
}

// MigrateToVersion applies migrations up to a specific version.
//
// It refuses when targetVersion is lower than the database's current schema
// version rather than silently doing nothing: this package has no
// down-migration support, so treating a lower target as a no-op would let an
// operator believe they rolled back when nothing happened (B39).
func (r *MigrationRunner) MigrateToVersion(ctx context.Context, targetVersion string) error {
	if err := r.Initialize(ctx); err != nil {
		return err
	}

	currentVersion, err := r.GetCurrentVersion(ctx)
	if err != nil {
		return fmt.Errorf("cannot determine current schema version: %w", err)
	}

	// GetCurrentVersion already parsed and numerically compared every applied
	// version to find currentVersion, so this can only fail if the database
	// changed between that call and this one -- fail closed rather than
	// trusting a value that is no longer known-good.
	currentNum, err := parseVersionNumber(currentVersion)
	if err != nil {
		return fmt.Errorf("cannot determine current schema version: %w", err)
	}

	targetNum, err := parseVersionNumber(targetVersion)
	if err != nil {
		return fmt.Errorf("cannot parse target version %q: %w", targetVersion, err)
	}

	if targetNum < currentNum {
		//nolint:staticcheck // ST1005: this two-sentence error is the exact, deliberate
		// user-facing text the B39 fix specifies -- not a wrapped/chained error --
		// see docs/superpowers/specs/2026-08-21-cli-bug-fixes-b35-b41-design.md.
		return fmt.Errorf("cannot migrate down: current schema is at version %s, target %s is lower. Down-migrations are not supported.",
			currentVersion, targetVersion)
	}

	applied, err := r.GetAppliedMigrations(ctx)
	if err != nil {
		return err
	}

	migrations, err := r.LoadMigrations()
	if err != nil {
		return err
	}

	for _, migration := range migrations {
		migrationNum, err := parseVersionNumber(migration.Version)
		if err != nil {
			return fmt.Errorf("migration file version %q is not numeric: %w", migration.Version, err)
		}
		if migrationNum > targetNum {
			break // Stop at target version
		}

		if applied[migration.Version] {
			continue // Skip already applied migrations
		}

		r.logger.WithFields(logrus.Fields{
			"version": migration.Version,
			"name":    migration.Name,
		}).Info("Applying migration")

		if err := r.ApplyMigration(ctx, migration); err != nil {
			return fmt.Errorf("failed to apply migration %s: %w", migration.Version, err)
		}
	}

	r.logger.WithField("target_version", targetVersion).Info("Migrated to target version")
	return nil
}

// GetCurrentVersion returns the current database schema version: the applied
// version with the highest numeric magnitude, not the lexicographically
// greatest one. SQL's MAX() over the VARCHAR version column compares
// byte-wise, which misorders versions of different digit widths (e.g. the
// short legacy "9" would beat a real 14-digit timestamp version) -- the same
// defect class MigrateToVersion's refusal check was fixed against in this
// plan, and the one place that check actually depends on (B39 final review).
func (r *MigrationRunner) GetCurrentVersion(ctx context.Context) (string, error) {
	if err := r.Initialize(ctx); err != nil {
		return "", err
	}

	rows, err := r.db.QueryContext(ctx, "SELECT version FROM schema_migrations")
	if err != nil {
		return "", fmt.Errorf("failed to get current version: %w", err)
	}
	defer rows.Close() //nolint:errcheck

	var current string
	var currentNum int64
	found := false
	for rows.Next() {
		var version string
		if err := rows.Scan(&version); err != nil {
			return "", fmt.Errorf("failed to scan migration version: %w", err)
		}

		num, err := parseVersionNumber(version)
		if err != nil {
			return "", fmt.Errorf("recorded schema_migrations version %q is not numeric: %w", version, err)
		}

		if !found || num > currentNum {
			current = version
			currentNum = num
			found = true
		}
	}
	if err := rows.Err(); err != nil {
		return "", fmt.Errorf("failed to read schema_migrations rows: %w", err)
	}

	if !found {
		return "0", nil // No migrations applied yet
	}

	return current, nil
}

// parseVersionNumber converts a migration version string to its numeric
// value for magnitude comparison. Every version in this package is decimal
// digits only -- either the legacy zero-padded sequential form (e.g. "001")
// or the YYYYMMDDNNNNNN timestamp form migrate:create generates -- so a
// base-10 parse is safe. Comparing the strings directly is not: it is only
// correct when every version being compared has the same width, and nothing
// enforces that across this package's own version files (e.g. "9" < "10"
// numerically but "9" > "10" lexicographically).
func parseVersionNumber(version string) (int64, error) {
	n, err := strconv.ParseInt(version, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid migration version %q: must be a decimal number: %w", version, err)
	}
	return n, nil
}

// Example usage:
//
// // In your application initialization:
// runner := NewMigrationRunner(db, logger)
// if err := runner.MigrateUp(context.Background()); err != nil {
//     logrus.WithError(err).Fatal("Failed to run migrations")
// }
