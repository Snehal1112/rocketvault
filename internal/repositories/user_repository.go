// Package repositories provides data access layer implementations.
// This package contains repository implementations that focus solely on
// database operations without business logic, following the SRP principle.
package repositories

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"

	"rocketvault/internal/db"
	"rocketvault/internal/logging"
	"rocketvault/model"
)

// UserRepositoryInterface is a generic repository interface for user operations.
// It provides type-safe CRUD operations for the User type.
type UserRepositoryInterface interface {
	db.Repository[model.User]
	ReadByUsername(ctx context.Context, username string) (model.User, error)
	// ReadByExternalSubject retrieves a user by external IdP subject. Returns
	// an error if no such user exists.
	ReadByExternalSubject(ctx context.Context, provider, subject string) (*model.User, error)
	List(ctx context.Context) ([]model.User, error)
	ValidateBootstrapToken(ctx context.Context, token string) (bool, error)
	InvalidateBootstrapToken(ctx context.Context, token string) error
}

// UserRepository implements UserRepositoryInterface with pure CRUD operations.
// It focuses solely on database interactions without business logic with performance monitoring.
type UserRepository struct {
	db  db.DB
	log *logging.Logger
}

// executeWithMetrics wraps database operations with performance monitoring.
// See KeyRepository.executeWithMetrics for why this stays a method.
func (r *UserRepository) executeWithMetrics(operation string, fn func() error) error {
	return withMetrics("users", operation, fn)
}

// queryWithMetrics wraps query operations with performance monitoring.
func (r *UserRepository) queryWithMetrics(operation string, fn func() error) error {
	return r.executeWithMetrics(operation, fn)
}

// NewUserRepository creates a new UserRepository instance.
// It provides pure database operations for user entities.
//
// Parameters:
//
//	db: The database connection.
//	log: The logger for database operation logging.
//
// Returns:
//
//	A UserRepository implementation for user database operations.
func NewUserRepository(db db.DB, log *logging.Logger) UserRepositoryInterface {
	return &UserRepository{db: db, log: log}
}

// Create inserts a new user into the database.
// It expects all user fields to be properly prepared (password hashed, TOTP secret generated).
//
// Parameters:
//
//	ctx: The context for the database operation.
//	user: The user entity to store (with pre-processed fields).
//
// Returns:
//
//	An error if the insertion fails.
func (r *UserRepository) Create(ctx context.Context, user *model.User) error {
	logrus.WithFields(logrus.Fields{
		"username": user.Username,
		"roles":    user.Roles,
		"user_id":  user.ID.String(),
	}).Debug("Inserting user into database")

	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin transaction: %w", err)
	}
	defer tx.Rollback() //nolint:errcheck

	// NOTE on every error branch below: LogAuditError/LogAuditInfo persist a row
	// via auditPersister on a DIFFERENT pooled DB connection than the one tx is
	// using. On SQLite, calling it while tx is still open blocks that second
	// connection on the lock tx holds -- a ~5s stall that times out and silently
	// drops the audit record (see internal/logging.Logger.LogAuditError). So each
	// error branch rolls tx back explicitly (rather than relying on the deferred
	// rollback, which only runs after this function returns) before logging.
	var existingUserID string
	err = tx.QueryRowContext(ctx, "SELECT id FROM users WHERE username = ?", user.Username).Scan(&existingUserID)
	if err == nil {
		_ = tx.Rollback()
		r.log.LogAuditError(user.ID.String(), "create_user", "failed", "Username already exists", nil)
		return fmt.Errorf("username already exists")
	}
	if !errors.Is(err, sql.ErrNoRows) {
		_ = tx.Rollback()
		r.log.LogAuditError(user.ID.String(), "create_user", "failed", "Failed to check existing username", err)
		return fmt.Errorf("failed to check existing username: %w", err)
	}

	authProvider := user.AuthProvider
	if authProvider == "" {
		authProvider = model.AuthProviderLocal
	}
	var externalSubject any
	if user.ExternalIDPSubject != "" {
		externalSubject = user.ExternalIDPSubject
	}
	// Normalize once so the legacy comma-joined users.role column and the
	// user_roles table are always built from the same deduped, non-empty
	// role list -- otherwise they can diverge (e.g. Roles: []string{"admin",
	// "", "admin"} would yield user_roles = {admin} but users.role =
	// "admin,,admin").
	normalizedRoles := normalizeRoles(user.Roles)
	// users.role kept in sync (comma-joined) as a legacy/defense-in-depth
	// copy -- not read by any new code, see the design spec.
	_, err = tx.ExecContext(
		ctx,
		"INSERT INTO users (id, username, password_hash, totp_secret, role, auth_provider, external_idp_subject, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
		user.ID.String(), user.Username, user.PasswordHash, user.TOTPSecret, strings.Join(normalizedRoles, ","), authProvider, externalSubject, user.CreatedAt,
	)
	if err != nil {
		_ = tx.Rollback()
		r.log.LogAuditError(user.ID.String(), "create_user", "failed", "Failed to insert user", err)
		return fmt.Errorf("failed to insert user: %w", err)
	}

	if err := r.replaceUserRoles(ctx, tx, user.ID, normalizedRoles); err != nil {
		_ = tx.Rollback()
		r.log.LogAuditError(user.ID.String(), "create_user", "failed", "Failed to insert user_roles", err)
		return fmt.Errorf("failed to insert user_roles: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit user create: %w", err)
	}

	r.log.LogAuditInfo(user.ID.String(), "create_user", "success", fmt.Sprintf("User inserted: %s", user.Username))
	return nil
}

// Read retrieves a user by ID from the database.
//
// Parameters:
//
//	ctx: The context for the database operation.
//	id: The user's unique identifier.
//
// Returns:
//
//	The user entity or an error if not found.
func (r *UserRepository) Read(ctx context.Context, id uuid.UUID) (*model.User, error) {
	var user model.User
	var idStr string
	var legacyRole string
	var externalSubject sql.NullString

	err := r.db.QueryRowContext(
		ctx,
		"SELECT id, username, password_hash, totp_secret, role, auth_provider, external_idp_subject, created_at FROM users WHERE id = ?",
		id.String(),
	).Scan(&idStr, &user.Username, &user.PasswordHash, &user.TOTPSecret, &legacyRole, &user.AuthProvider, &externalSubject, &user.CreatedAt)

	if errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("user not found: %w", ErrNotFound)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to query user: %w", err)
	}
	user.ExternalIDPSubject = externalSubject.String

	user.ID, err = uuid.Parse(idStr)
	if err != nil {
		return nil, fmt.Errorf("failed to parse user ID: %w", err)
	}

	user.Roles, err = r.fetchUserRoles(ctx, user.ID)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch user roles: %w", err)
	}

	return &user, nil
}

// Update updates a user in the database.
// It expects all fields to be properly prepared (password hashed if changed).
//
// Parameters:
//
//	ctx: The context for the database operation.
//	user: The user entity with updated fields.
//
// Returns:
//
//	An error if the update fails.
func (r *UserRepository) Update(ctx context.Context, user *model.User) error {
	logrus.WithFields(logrus.Fields{
		"user_id":  user.ID.String(),
		"username": user.Username,
	}).Debug("Updating user in database")

	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin transaction: %w", err)
	}
	defer tx.Rollback() //nolint:errcheck

	// Normalize once, see the identical comment in Create -- keeps users.role
	// and user_roles from diverging on duplicate/empty role entries.
	normalizedRoles := normalizeRoles(user.Roles)

	// NOTE on every error branch below: see the explanation in Create -- tx is
	// rolled back explicitly before logging so the audit write (which uses a
	// different pooled DB connection) never blocks on the lock this tx holds.
	result, err := tx.ExecContext(
		ctx,
		"UPDATE users SET username = ?, password_hash = ?, totp_secret = ?, role = ? WHERE id = ?",
		user.Username, user.PasswordHash, user.TOTPSecret, strings.Join(normalizedRoles, ","), user.ID.String(),
	)
	if err != nil {
		_ = tx.Rollback()
		r.log.LogAuditError(user.ID.String(), "update_user", "failed", "Failed to update user", err)
		return fmt.Errorf("failed to update user: %w", err)
	}
	rowsAffected, err := result.RowsAffected()
	if err != nil {
		_ = tx.Rollback()
		r.log.LogAuditError(user.ID.String(), "update_user", "failed", "Failed to get rows affected", err)
		return fmt.Errorf("failed to get rows affected: %w", err)
	}
	if rowsAffected == 0 {
		_ = tx.Rollback()
		r.log.LogAuditError(user.ID.String(), "update_user", "failed", "User not found for update", nil)
		return fmt.Errorf("user not found: %w", ErrNotFound)
	}

	if err := r.replaceUserRoles(ctx, tx, user.ID, normalizedRoles); err != nil {
		_ = tx.Rollback()
		r.log.LogAuditError(user.ID.String(), "update_user", "failed", "Failed to replace user_roles", err)
		return fmt.Errorf("failed to replace user_roles: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit user update: %w", err)
	}

	r.log.LogAuditInfo(user.ID.String(), "update_user", "success", fmt.Sprintf("User updated: %s", user.Username))
	return nil
}

// Delete removes a user and all associated data from the database.
// It handles cascading deletion to maintain referential integrity with optimized batch operations.
//
// Parameters:
//
//	ctx: The context for the database operation.
//	id: The user's unique identifier.
//
// Returns:
//
//	An error if the deletion fails.
func (r *UserRepository) Delete(ctx context.Context, id uuid.UUID) error {
	return r.executeWithMetrics("delete_user", func() error {
		logrus.WithField("user_id", id.String()).Debug("Deleting user from database")

		tx, err := r.db.BeginTx(ctx, nil)
		if err != nil {
			// No transaction was opened here, so this log doesn't contend with
			// an open tx's lock -- safe to log immediately.
			r.log.LogAuditError(id.String(), "delete_user", "failed", "Failed to begin transaction", err)
			return fmt.Errorf("failed to begin transaction: %w", err)
		}
		defer tx.Rollback() //nolint:errcheck

		// NOTE on every error branch below: LogAuditError persists a row via a
		// different pooled DB connection than tx. On SQLite, logging while tx
		// is still open blocks that connection on tx's lock for ~5s and then
		// silently drops the audit record (see internal/logging.Logger). Each
		// branch rolls tx back explicitly before logging to avoid that.

		// user_roles' ON DELETE CASCADE is inert on SQLite (the foreign_keys
		// PRAGMA is off here), so the rows must be removed explicitly or
		// they strand role grants for a user that no longer exists. Harmless
		// no-op on Postgres, where the DB-level cascade already handles it.
		if _, err := tx.ExecContext(ctx, "DELETE FROM user_roles WHERE user_id = ?", id.String()); err != nil {
			_ = tx.Rollback()
			r.log.LogAuditError(id.String(), "delete_user", "failed", "Failed to delete user_roles", err)
			return fmt.Errorf("failed to delete user_roles: %w", err)
		}

		// Delete the user - cascading will handle most other related data
		result, err := tx.ExecContext(ctx, "DELETE FROM users WHERE id = ?", id.String())
		if err != nil {
			_ = tx.Rollback()
			r.log.LogAuditError(id.String(), "delete_user", "failed", "Failed to delete user", err)
			return fmt.Errorf("failed to delete user: %w", err)
		}

		rowsAffected, err := result.RowsAffected()
		if err != nil {
			_ = tx.Rollback()
			r.log.LogAuditError(id.String(), "delete_user", "failed", "Failed to get rows affected", err)
			return fmt.Errorf("failed to get rows affected: %w", err)
		}
		if rowsAffected == 0 {
			_ = tx.Rollback()
			r.log.LogAuditError(id.String(), "delete_user", "failed", "User not found for deletion", nil)
			return fmt.Errorf("user not found: %w", ErrNotFound)
		}

		if err := tx.Commit(); err != nil {
			// Commit itself resolves tx either way (success or failure), so no
			// open tx/lock remains here -- safe to log immediately.
			r.log.LogAuditError(id.String(), "delete_user", "failed", "Failed to commit transaction", err)
			return fmt.Errorf("failed to commit transaction: %w", err)
		}

		r.log.LogAuditInfo(id.String(), "delete_user", "success", "User and associated data deleted successfully")
		logrus.WithField("user_id", id.String()).Debug("User deleted successfully")

		return nil
	})
}

// normalizeRoles returns roles with empty strings and duplicates removed,
// preserving first-seen order. Callers must build both the legacy
// comma-joined users.role column and the user_roles table from the same
// normalized slice -- otherwise the two can silently diverge (e.g.
// []string{"admin", "", "admin"} would yield user_roles = {admin} but a
// naive strings.Join of the raw slice into users.role = "admin,,admin").
func normalizeRoles(roles []string) []string {
	seen := make(map[string]bool, len(roles))
	normalized := make([]string, 0, len(roles))
	for _, role := range roles {
		if role == "" || seen[role] {
			continue
		}
		seen[role] = true
		normalized = append(normalized, role)
	}
	return normalized
}

// replaceUserRoles deletes every existing user_roles row for userID and
// inserts one row per entry in roles, inside the given transaction. Empty
// or duplicate role strings are silently skipped -- callers are expected to
// have already validated the role names themselves (this repository does
// not know the valid-roles allowlist).
func (r *UserRepository) replaceUserRoles(ctx context.Context, tx *db.Tx, userID uuid.UUID, roles []string) error {
	if _, err := tx.ExecContext(ctx, `DELETE FROM user_roles WHERE user_id = ?`, userID.String()); err != nil {
		return fmt.Errorf("delete existing user_roles: %w", err)
	}
	seen := map[string]bool{}
	for _, role := range roles {
		if role == "" || seen[role] {
			continue
		}
		// A comma in a role name would corrupt the legacy comma-joined
		// users.role sync (strings.Join/strings.Split round-trip breaks).
		// No current caller can produce this -- role names all come from a
		// small hardcoded allowlist elsewhere -- but skip rather than trust
		// callers on this one representation detail, since a bad role name
		// merely fails to grant that one role instead of corrupting the
		// legacy column for every role on the user.
		if strings.Contains(role, ",") {
			continue
		}
		seen[role] = true
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO user_roles (id, user_id, role) VALUES (?, ?, ?)`,
			uuid.New().String(), userID.String(), role,
		); err != nil {
			return fmt.Errorf("insert user_roles row (role=%s): %w", role, err)
		}
	}
	return nil
}

// fetchUserRoles returns every role currently assigned to userID, ordered
// alphabetically for deterministic output (cheap on an indexed
// single-user lookup, and avoids nondeterministic ordering flowing into
// JWT payloads and API responses).
func (r *UserRepository) fetchUserRoles(ctx context.Context, userID uuid.UUID) ([]string, error) {
	rows, err := r.db.QueryContext(ctx, `SELECT role FROM user_roles WHERE user_id = ? ORDER BY role`, userID.String())
	if err != nil {
		return nil, fmt.Errorf("query user_roles: %w", err)
	}
	defer rows.Close() //nolint:errcheck

	var roles []string
	for rows.Next() {
		var role string
		if err := rows.Scan(&role); err != nil {
			return nil, fmt.Errorf("scan user_roles row: %w", err)
		}
		roles = append(roles, role)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate user_roles: %w", err)
	}
	return roles, nil
}

// ReadByUsername retrieves a user by username from the database.
//
// Parameters:
//
//	ctx: The context for the database operation.
//	username: The user's username.
//
// Returns:
//
//	The user entity or an error if not found.
func (r *UserRepository) ReadByUsername(ctx context.Context, username string) (model.User, error) {
	var user model.User
	var idStr string
	var legacyRole string
	var externalSubject sql.NullString

	err := r.db.QueryRowContext(
		ctx,
		"SELECT id, username, password_hash, totp_secret, role, auth_provider, external_idp_subject, created_at FROM users WHERE username = ?",
		username,
	).Scan(&idStr, &user.Username, &user.PasswordHash, &user.TOTPSecret, &legacyRole, &user.AuthProvider, &externalSubject, &user.CreatedAt)

	if errors.Is(err, sql.ErrNoRows) {
		return user, fmt.Errorf("user not found: %w", ErrNotFound)
	}
	if err != nil {
		logrus.WithError(err).Error("Failed to query user by username")
		return user, fmt.Errorf("failed to query user by username: %w", err)
	}
	user.ExternalIDPSubject = externalSubject.String

	user.ID, err = uuid.Parse(idStr)
	if err != nil {
		logrus.WithError(err).Error("Failed to parse user ID")
		return user, fmt.Errorf("failed to parse user ID: %w", err)
	}

	user.Roles, err = r.fetchUserRoles(ctx, user.ID)
	if err != nil {
		logrus.WithError(err).Error("Failed to fetch user roles")
		return user, fmt.Errorf("failed to fetch user roles: %w", err)
	}

	return user, nil
}

// ReadByExternalSubject retrieves a user by (provider, external subject).
// Returns an error if no such user exists.
func (r *UserRepository) ReadByExternalSubject(ctx context.Context, provider, subject string) (*model.User, error) {
	var user model.User
	var idStr string
	var legacyRole string
	var externalSubject sql.NullString

	err := r.db.QueryRowContext(
		ctx,
		"SELECT id, username, password_hash, totp_secret, role, auth_provider, external_idp_subject, created_at FROM users WHERE auth_provider = ? AND external_idp_subject = ?",
		provider, subject,
	).Scan(&idStr, &user.Username, &user.PasswordHash, &user.TOTPSecret, &legacyRole, &user.AuthProvider, &externalSubject, &user.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("user not found: %w", ErrNotFound)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to query user by external subject: %w", err)
	}
	user.ExternalIDPSubject = externalSubject.String

	user.ID, err = uuid.Parse(idStr)
	if err != nil {
		return nil, fmt.Errorf("failed to parse user ID: %w", err)
	}

	user.Roles, err = r.fetchUserRoles(ctx, user.ID)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch user roles: %w", err)
	}

	return &user, nil
}

// Login is deprecated and should not be used.
// Authentication logic has been moved to AuthenticationService.
func (r *UserRepository) Login(ctx context.Context, username, password, totpCode string) (string, error) {
	return "", fmt.Errorf("login method is deprecated, use AuthenticationService instead")
}

// List retrieves all users from the database with optimized query and monitoring.
//
// Parameters:
//
//	ctx: The context for the database operation.
//
// Returns:
//
//	A slice of all users or an error if retrieval fails.
func (r *UserRepository) List(ctx context.Context) ([]model.User, error) {
	var users []model.User

	err := r.queryWithMetrics("list_users", func() error {
		// Optimized query with explicit column selection and ordering for better performance.
		// Excludes the reserved system user row (model.SystemUserID) -- it is
		// not a real account and must never appear in a user listing.
		rows, err := r.db.QueryContext(ctx,
			"SELECT id, username, password_hash, totp_secret, role, auth_provider, external_idp_subject, created_at FROM users WHERE id != ? ORDER BY created_at DESC",
			model.SystemUserID)
		if err != nil {
			logrus.WithError(err).Error("Failed to list users")
			return fmt.Errorf("failed to list users: %w", err)
		}
		// Belt-and-suspenders alongside the manual rows.Close() calls below:
		// sql.Rows.Close() is idempotent, so keeping this defer costs nothing
		// and closes rows on any future early-return added inside the loop
		// that forgets to close manually.
		defer rows.Close() //nolint:errcheck

		// Pre-allocate slice for better memory performance
		users = make([]model.User, 0, 100) // Assume max 100 users initially

		for rows.Next() {
			var user model.User
			var idStr string
			var legacyRole string
			var externalSubject sql.NullString

			if err := rows.Scan(&idStr, &user.Username, &user.PasswordHash, &user.TOTPSecret, &legacyRole, &user.AuthProvider, &externalSubject, &user.CreatedAt); err != nil {
				rows.Close() //nolint:errcheck
				logrus.WithError(err).Error("Failed to scan user")
				return fmt.Errorf("failed to scan user: %w", err)
			}
			user.ExternalIDPSubject = externalSubject.String

			user.ID, err = uuid.Parse(idStr)
			if err != nil {
				rows.Close() //nolint:errcheck
				logrus.WithError(err).Error("Failed to parse user ID")
				return fmt.Errorf("failed to parse user ID: %w", err)
			}

			users = append(users, user)
		}

		if err := rows.Err(); err != nil {
			rows.Close() //nolint:errcheck
			return fmt.Errorf("row iteration error: %w", err)
		}
		// Close the result set before issuing further queries below -- on
		// SQLite ":memory:" databases a second connection checked out from
		// the pool while rows is still open sees a distinct, empty in-memory
		// database, so per-user role lookups must not run until rows is done.
		if err := rows.Close(); err != nil {
			return fmt.Errorf("close user rows: %w", err)
		}

		for i := range users {
			roles, err := r.fetchUserRoles(ctx, users[i].ID)
			if err != nil {
				logrus.WithError(err).Error("Failed to fetch user roles")
				return fmt.Errorf("failed to fetch user roles: %w", err)
			}
			users[i].Roles = roles
		}

		return nil
	})
	if err != nil {
		return nil, err
	}

	logrus.WithField("count", len(users)).Debug("Users listed successfully")
	return users, nil
}

// ValidateBootstrapToken checks if the provided bootstrap token is valid.
// This is a simple implementation and should be replaced with secure token storage.
//
// Parameters:
//
//	ctx: The context for the database operation.
//	token: The bootstrap token to validate.
//
// Returns:
//
//	True if valid, false otherwise, and an error if the operation fails.
func (r *UserRepository) ValidateBootstrapToken(ctx context.Context, token string) (bool, error) {
	// Check if users table is empty (bootstrap condition). Excludes the
	// reserved system user row (model.SystemUserID) -- it exists on every
	// fresh database (see db.seedSystemUser) and is not a real account, so
	// it must never count toward "an admin already exists."
	var count int
	err := r.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM users WHERE id != ?", model.SystemUserID).Scan(&count)
	if err != nil {
		r.log.LogAuditError(uuid.Nil.String(), "validate_bootstrap_token", "failed", "Failed to query user count", err)
		return false, fmt.Errorf("failed to query user count: %w", err)
	}

	// Bootstrap only allowed if no users exist
	if count > 0 {
		r.log.LogAuditError(uuid.Nil.String(), "validate_bootstrap_token", "failed", "Bootstrap not allowed: users exist", nil)
		return false, nil
	}

	// Check token in bootstrap_tokens table
	var used bool
	err = r.db.QueryRowContext(ctx, "SELECT used FROM bootstrap_tokens WHERE token = ?", token).Scan(&used)
	if errors.Is(err, sql.ErrNoRows) {
		r.log.LogAuditError(uuid.Nil.String(), "validate_bootstrap_token", "failed", "Bootstrap token not found", nil)
		return false, nil
	}
	if err != nil {
		r.log.LogAuditError(uuid.Nil.String(), "validate_bootstrap_token", "failed", "Failed to query bootstrap token", err)
		return false, fmt.Errorf("failed to query bootstrap token: %w", err)
	}

	if used {
		r.log.LogAuditError(uuid.Nil.String(), "validate_bootstrap_token", "failed", "Bootstrap token already used", nil)
		return false, nil
	}

	return true, nil
}

// InvalidateBootstrapToken marks a bootstrap token as used.
//
// Parameters:
//
//	ctx: The context for the database operation.
//	token: The bootstrap token to invalidate.
//
// Returns:
//
//	An error if the operation fails.
func (r *UserRepository) InvalidateBootstrapToken(ctx context.Context, token string) error {
	// Try to update existing token
	result, err := r.db.ExecContext(ctx, "UPDATE bootstrap_tokens SET used = TRUE WHERE token = ?", token)
	if err != nil {
		r.log.LogAuditError(uuid.Nil.String(), "invalidate_bootstrap_token", "failed", "Failed to update bootstrap token", err)
		return fmt.Errorf("failed to update bootstrap token: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		r.log.LogAuditError(uuid.Nil.String(), "invalidate_bootstrap_token", "failed", "Failed to get rows affected", err)
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	// If no rows affected, insert the token as used
	if rowsAffected == 0 {
		_, err = r.db.ExecContext(ctx, "INSERT INTO bootstrap_tokens (token, used) VALUES (?, TRUE)", token)
		if err != nil {
			r.log.LogAuditError(uuid.Nil.String(), "invalidate_bootstrap_token", "failed", "Failed to insert bootstrap token", err)
			return fmt.Errorf("failed to insert bootstrap token: %w", err)
		}
	}

	r.log.LogAuditInfo(uuid.Nil.String(), "invalidate_bootstrap_token", "success", "Bootstrap token invalidated")
	return nil
}
