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
	"time"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"

	"rocketvault/internal/db"
	"rocketvault/internal/logging"
	"rocketvault/model"
)

// KeyRepositoryInterface is a generic repository interface for key operations.
// It provides type-safe CRUD operations for the Key type.
type KeyRepositoryInterface interface {
	Create(ctx context.Context, key *model.Key) error
	// Read fetches a key authorized by scope. The scoped read is the access
	// check: a row outside the scope is indistinguishable from a row that
	// does not exist.
	Read(ctx context.Context, id uuid.UUID, scope model.Scope) (*model.Key, error)
	// Update updates a key authorized by scope. The predicate comes from the
	// scope argument, never from the entity.
	Update(ctx context.Context, key *model.Key, scope model.Scope) error
	// List lists keys authorized by scope and narrowed by filter.
	List(ctx context.Context, scope model.Scope, filter KeyFilter) ([]model.Key, error)
	Delete(ctx context.Context, id uuid.UUID) error
	UpdateRevocationStatus(ctx context.Context, id uuid.UUID, revoked bool) error
	SoftDelete(ctx context.Context, id uuid.UUID) error
	RecoverKey(ctx context.Context, id uuid.UUID) error
	PurgeKey(ctx context.Context, id uuid.UUID) error
	SetPurgeProtection(ctx context.Context, id uuid.UUID, enabled bool) error
	// ReadDeletedScoped retrieves a key by ID regardless of soft-deletion
	// state, authorized by scope. Used to return deletion metadata after a
	// soft-delete operation; the scope predicate is what makes this safe to
	// call from more than the one already-authorized call site it was
	// originally written for (see known-bugs B64).
	ReadDeletedScoped(ctx context.Context, id uuid.UUID, scope model.Scope) (*model.Key, error)
	// CreateVersion persists a versioned snapshot of a key's raw material.
	// Performs no authorization; see ReadVersionValue for the contract.
	CreateVersion(ctx context.Context, keyID uuid.UUID, version int, value string) error
	// ListVersions returns all version records for a key, ordered by version
	// ASC. Performs no authorization; see ReadVersionValue for the contract.
	ListVersions(ctx context.Context, keyID uuid.UUID) ([]model.KeyVersion, error)
	// ReadVersionValue returns the encrypted/handle material for one version
	// of a key, by key ID and version.
	//
	// It performs NO authorization. The caller MUST have already authorized
	// the parent key with a scoped Read -- these version rows are reachable
	// only through a key the caller has proved access to. A previous
	// signature took a userID and filtered on k.user_id; every caller
	// satisfied it by passing the owner ID from that same scoped Read, so it
	// could never fail while appearing to be a check. See known-bugs B28 for
	// the bug that ambiguity caused.
	ReadVersionValue(ctx context.Context, keyID uuid.UUID, version int) (string, error)
	// GetVersion returns metadata (no material) for one version of a key.
	// Performs no authorization; see ReadVersionValue for the contract.
	GetVersion(ctx context.Context, keyID uuid.UUID, version int) (*model.KeyVersion, error)
	// ListVersionRecords returns every version of a key INCLUDING material,
	// by key ID. Internal use only (the backup service) -- never wired to an
	// HTTP response.
	//
	// Performs no authorization; see ReadVersionValue for the contract.
	ListVersionRecords(ctx context.Context, keyID uuid.UUID) ([]model.KeyVersionRecord, error)
	// CurrentVersion returns keyID's current version number: the highest
	// key_versions row if any rotation has happened, else the implicit 1
	// (a never-rotated key's only material is keys.value). Single aggregate
	// query -- avoids fetching every version row just to find the max.
	// Performs no authorization; see ReadVersionValue for the contract.
	CurrentVersion(ctx context.Context, keyID uuid.UUID) (int, error)
	// SoftDeleteVaultContents soft-deletes every active key in a vault.
	SoftDeleteVaultContents(ctx context.Context, vaultID uuid.UUID, deletedAt time.Time) error
	// RecoverVaultContents recovers only the keys the cascade soft-deleted at deletedAt.
	RecoverVaultContents(ctx context.Context, vaultID uuid.UUID, deletedAt time.Time) error
}

// KeyFilter narrows a scoped key listing. Alias for model.KeyFilter: the
// canonical definition lives in model/ so api/ and cmd/ can construct one
// without importing this package.
type KeyFilter = model.KeyFilter

// keyColumns is the canonical SELECT list shared by every scoped key query.
const keyColumns = "id, user_id, vault_id, name, value, type, revoked, created_at, enabled, expires_at, not_before, bits, curve, updated_at, deleted_at, purge_protection"

// scanKeyRow scans one keys row in the canonical column order.
func scanKeyRow(scan func(dest ...any) error) (model.Key, error) {
	var key model.Key
	var idStr, userIDStr, vaultIDStr string

	if err := scan(&idStr, &userIDStr, &vaultIDStr, &key.Name, &key.Value, &key.Type, &key.Revoked,
		&key.CreatedAt, &key.Enabled, &key.ExpiresAt, &key.NotBefore, &key.Bits, &key.Curve, &key.UpdatedAt,
		&key.DeletedAt, &key.PurgeProtection); err != nil {
		return key, err
	}

	var err error
	if key.ID, err = uuid.Parse(idStr); err != nil {
		return key, fmt.Errorf("failed to parse key ID: %w", err)
	}
	if key.UserID, err = uuid.Parse(userIDStr); err != nil {
		return key, fmt.Errorf("failed to parse user ID: %w", err)
	}
	if key.VaultID, err = uuid.Parse(vaultIDStr); err != nil {
		return key, fmt.Errorf("failed to parse vault ID: %w", err)
	}
	return key, nil
}

// Read retrieves a key by ID, authorized by scope. Tags are loaded via
// TagRepository, matching the behaviour of the methods it replaces.
func (r *KeyRepository) Read(ctx context.Context, id uuid.UUID, scope model.Scope) (*model.Key, error) {
	query := "SELECT " + keyColumns + " FROM keys WHERE id = ? AND deleted_at IS NULL"
	key, err := ScopedGet(ctx, r.db, query, []any{id.String()}, scope, func(row *sql.Row) (model.Key, error) {
		return scanKeyRow(row.Scan)
	})
	switch {
	case errors.Is(err, ErrInvalidScope):
		return nil, err
	case errors.Is(err, sql.ErrNoRows):
		if scope.Kind() == model.ScopeAdmin {
			return nil, fmt.Errorf("key not found")
		}
		return nil, fmt.Errorf("key not found or access denied")
	case err != nil:
		return nil, fmt.Errorf("failed to query key: %w", err)
	}

	tagRepo := db.NewTagRepository[model.Key](r.db, "key_tags", "key_id")
	key.Tags, err = tagRepo.GetTags(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("failed to read tags: %w", err)
	}
	return &key, nil
}

// Update updates a key, authorized by scope. The predicate is built from
// the scope argument, never from the entity.
//
// This method does not emit audit rows: audit attribution belongs to the
// caller (service layer), which knows the acting principal from the request.
// UpdateKey already logs its own audit row after calling this, for
// every error path and on success — logging here too would duplicate every
// scoped update into two audit_logs rows.
func (r *KeyRepository) Update(ctx context.Context, key *model.Key, scope model.Scope) error {
	return r.executeWithMetrics("update_key_scoped", func() error {
		now := time.Now().UTC()
		key.UpdatedAt = &now

		query := "UPDATE keys SET name = ?, value = ?, revoked = ?, created_at = ?, enabled = ?, expires_at = ?, not_before = ?, bits = ?, curve = ?, updated_at = ? WHERE id = ?"
		execArgs := []any{
			key.Name, key.Value, key.Revoked, key.CreatedAt, key.Enabled,
			key.ExpiresAt, key.NotBefore, key.Bits, key.Curve, now, key.ID.String(),
		}

		result, execErr := ScopedExec(ctx, r.db, query, execArgs, scope)
		if execErr != nil {
			if errors.Is(execErr, ErrInvalidScope) {
				return execErr
			}
			return fmt.Errorf("failed to update key: %w", execErr)
		}

		rowsAffected, rowsErr := result.RowsAffected()
		if rowsErr != nil {
			return fmt.Errorf("failed to get rows affected: %w", rowsErr)
		}
		if rowsAffected == 0 {
			return fmt.Errorf("key not found")
		}

		logrus.WithFields(logrus.Fields{
			"key_id": key.ID.String(),
			"scope":  scope.String(),
		}).Debug("Key updated successfully")
		return nil
	})
}

// List lists keys authorized by scope and narrowed by filter.
func (r *KeyRepository) List(ctx context.Context, scope model.Scope, filter KeyFilter) ([]model.Key, error) {
	where := "1 = 1" // Base predicate ScopedList's appended "AND <scope>" attaches to when no filter condition below fires.
	switch {
	case filter.OnlyDeleted:
		where = "deleted_at IS NOT NULL"
	case filter.IncludeDeleted:
		// No deleted_at constraint.
	default:
		where = "deleted_at IS NULL"
	}

	conditions := []string{where}
	var args []any
	if filter.Type != "" {
		conditions = append(conditions, "type = ?")
		args = append(args, filter.Type)
	}
	if len(filter.Tags) > 0 {
		placeholders := strings.Repeat(",?", len(filter.Tags))[1:]
		conditions = append(conditions, fmt.Sprintf("id IN (SELECT key_id FROM key_tags WHERE tag IN (%s))", placeholders))
		for _, tag := range filter.Tags {
			args = append(args, tag)
		}
	}

	query := "SELECT " + keyColumns + " FROM keys WHERE " + strings.Join(conditions, " AND ")

	tail := " ORDER BY created_at DESC, id ASC"
	var tailArgs []any
	if filter.Limit > 0 {
		tail += " LIMIT ? OFFSET ?"
		tailArgs = []any{filter.Limit, filter.Offset}
	}

	var keyList []model.Key
	err := r.executeWithMetrics("list_keys_scoped", func() error {
		var listErr error
		keyList, listErr = ScopedList(ctx, r.db, query, args, scope, tail, tailArgs, func(rows *sql.Rows) (model.Key, error) {
			return scanKeyRow(rows.Scan)
		})
		if listErr != nil {
			return listErr
		}

		// Batch-fetch tags for every returned key in one query instead of one
		// GetTags query per row.
		ids := make([]uuid.UUID, len(keyList))
		for i, key := range keyList {
			ids[i] = key.ID
		}
		tagRepo := db.NewTagRepository[model.Key](r.db, "key_tags", "key_id")
		tagsByID, tagErr := tagRepo.GetTagsForMany(ctx, ids)
		if tagErr != nil {
			return fmt.Errorf("failed to read tags for keys: %w", tagErr)
		}
		for i := range keyList {
			keyList[i].Tags = tagsByID[keyList[i].ID]
		}
		return nil
	})
	if err != nil {
		if errors.Is(err, ErrInvalidScope) {
			return nil, err
		}
		return nil, fmt.Errorf("failed to query keys: %w", err)
	}

	logrus.WithField("count", len(keyList)).Debug("Keys listed successfully")
	return keyList, nil
}

// KeyRepository implements KeyRepositoryInterface with pure CRUD operations.
// It focuses solely on database interactions without business logic like encryption or key generation.
// All crypto operations (encryption, key generation) are handled by the service layer.
type KeyRepository struct {
	db  db.DB
	log *logging.Logger
}

// crud returns the itemLifecycleConfig for keys.
func (r *KeyRepository) crud() itemLifecycleConfig {
	return itemLifecycleConfig{
		table:              "keys",
		item:               "key",
		itemCap:            "Key",
		idField:            "key_id",
		tagTable:           "key_tags",
		tagFK:              "key_id",
		auditActor:         uuid.Nil.String(),
		purgeErr:           ErrKeyPurgeProtected,
		notFoundIsSentinel: false,
		log:                r.log,
		wrap:               r.executeWithMetrics,
	}
}

// executeWithMetrics wraps database operations with performance monitoring.
// Delegates to the shared withMetrics helper; kept as a method because
// crud() assigns it to itemLifecycleConfig.wrap, which needs this exact
// func(string, func() error) error shape.
func (r *KeyRepository) executeWithMetrics(operation string, fn func() error) error {
	return withMetrics("keys", operation, fn)
}

// NewKeyRepository creates a new KeyRepository instance.
// It provides pure database operations for key entities.
//
// Parameters:
//   - db: The database connection.
//   - log: The logger for database operation logging.
//
// Returns:
//
//	A KeyRepositoryInterface implementation for key database operations.
func NewKeyRepository(db db.DB, log *logging.Logger) KeyRepositoryInterface {
	return &KeyRepository{db: db, log: log}
}

// Create inserts a new key into the database.
// It expects the key value to be already encrypted by the service layer.
// NO encryption or key generation happens here - pure data access only.
//
// Parameters:
//   - ctx: The context for the database operation.
//   - key: The key entity to store (with pre-encrypted value).
//
// Returns:
//
//	An error if the insertion fails.
func (r *KeyRepository) Create(ctx context.Context, key *model.Key) error {
	return r.executeWithMetrics("create_key", func() error {
		logrus.WithFields(logrus.Fields{
			"key_id":  key.ID.String(),
			"user_id": key.UserID.String(),
			"name":    key.Name,
			"type":    key.Type,
		}).Debug("Inserting key into database")

		tx, err := r.db.BeginTx(ctx, nil)
		if err != nil {
			r.log.LogAuditError(key.UserID.String(), "create_key", "failed", "Failed to begin transaction", err)
			return fmt.Errorf("failed to begin transaction: %w", err)
		}
		defer tx.Rollback() //nolint:errcheck

		if err := r.insertKeyAndTags(ctx, tx, key); err != nil {
			return err
		}

		if err := tx.Commit(); err != nil {
			r.log.LogAuditError(key.UserID.String(), "create_key", "failed", "Failed to commit transaction", err)
			return fmt.Errorf("failed to commit transaction: %w", err)
		}

		r.log.LogAuditInfo(key.UserID.String(), "create_key", "success", fmt.Sprintf("Key created: %s", key.Name))
		logrus.WithFields(logrus.Fields{
			"key_id":  key.ID.String(),
			"user_id": key.UserID.String(),
			"name":    key.Name,
			"type":    key.Type,
		}).Debug("Key inserted successfully")

		return nil
	})
}

// CreateTx is Create's Tx-scoped variant. Unlike Create, it does not open
// its own transaction: ex is expected to already be a transaction the
// caller (ItemBackupService, for an atomic restore, F3) owns and will
// commit or roll back — nesting a second transaction inside it is neither
// necessary nor supported by database/sql.
func (r *KeyRepository) CreateTx(ctx context.Context, ex db.DBTX, key *model.Key) error {
	return r.executeWithMetrics("create_key", func() error {
		if err := r.insertKeyAndTags(ctx, ex, key); err != nil {
			return err
		}
		r.log.LogAuditInfo(key.UserID.String(), "create_key", "success", fmt.Sprintf("Key created: %s", key.Name))
		return nil
	})
}

// insertKeyAndTags issues the key row insert and its tag inserts against ex.
// Shared by Create (ex is a transaction it began and owns) and CreateTx (ex
// is a transaction an outer caller began and owns).
func (r *KeyRepository) insertKeyAndTags(ctx context.Context, ex db.DBTX, key *model.Key) error {
	// Insert key with pre-encrypted value.
	_, err := ex.ExecContext(
		ctx,
		"INSERT INTO keys (id, user_id, vault_id, name, value, type, revoked, created_at, enabled, expires_at, not_before, bits, curve) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
		key.ID.String(), key.UserID.String(), key.VaultID.String(), key.Name, key.Value, key.Type, key.Revoked, key.CreatedAt,
		key.Enabled, key.ExpiresAt, key.NotBefore, key.Bits, key.Curve,
	)
	if err != nil {
		if db.SQLite.IsConstraintErr(err) {
			r.log.LogAuditError(key.UserID.String(), "create_key", "failed", fmt.Sprintf("Key name already taken: %s", key.Name), err)
			return fmt.Errorf("key %q: %w: %w", key.Name, ErrNameTaken, err)
		}
		r.log.LogAuditError(key.UserID.String(), "create_key", "failed", "Failed to insert key", err)
		return fmt.Errorf("failed to insert key: %w", err)
	}

	// Insert tags if provided (using the same transaction to avoid locks).
	for _, tag := range key.Tags {
		_, err := ex.ExecContext(ctx,
			"INSERT INTO key_tags (key_id, tag) VALUES (?, ?)",
			key.ID.String(), tag,
		)
		if err != nil {
			r.log.LogAuditError(key.UserID.String(), "create_key", "failed", fmt.Sprintf("Failed to insert tag %s", tag), err)
			return fmt.Errorf("failed to insert tag %s: %w", tag, err)
		}
	}
	return nil
}

// ReadDeletedScoped retrieves a key by ID regardless of whether it has been
// soft-deleted, authorized by scope. This is used after SoftDelete to return
// deletion metadata to callers. It follows the same scan pattern as Read but
// omits the "deleted_at IS NULL" filter.
//
// Parameters:
//   - ctx: The context for the database operation.
//   - id: The key's unique identifier.
//   - scope: The authorization predicate. A row outside the scope is
//     indistinguishable from a row that does not exist.
//
// Returns:
//
//	The key entity (including deleted_at/scheduled_purge_at) or an error if not found.
func (r *KeyRepository) ReadDeletedScoped(ctx context.Context, id uuid.UUID, scope model.Scope) (*model.Key, error) {
	query := "SELECT id, user_id, vault_id, name, value, type, revoked, created_at, enabled, expires_at, not_before, bits, curve, updated_at, deleted_at, scheduled_purge_at FROM keys WHERE id = ?"
	key, err := ScopedGet(ctx, r.db, query, []any{id.String()}, scope, func(row *sql.Row) (model.Key, error) {
		var key model.Key
		var idStr, userIDStr, vaultIDStr string

		if err := row.Scan(&idStr, &userIDStr, &vaultIDStr, &key.Name, &key.Value, &key.Type, &key.Revoked, &key.CreatedAt,
			&key.Enabled, &key.ExpiresAt, &key.NotBefore, &key.Bits, &key.Curve, &key.UpdatedAt,
			&key.DeletedAt, &key.ScheduledPurgeAt); err != nil {
			return key, err
		}

		var err error
		if key.ID, err = uuid.Parse(idStr); err != nil {
			return key, fmt.Errorf("failed to parse key ID: %w", err)
		}
		if key.UserID, err = uuid.Parse(userIDStr); err != nil {
			return key, fmt.Errorf("failed to parse user ID: %w", err)
		}
		if key.VaultID, err = uuid.Parse(vaultIDStr); err != nil {
			return key, fmt.Errorf("failed to parse vault ID: %w", err)
		}
		return key, nil
	})
	switch {
	case errors.Is(err, ErrInvalidScope):
		return nil, err
	case errors.Is(err, sql.ErrNoRows):
		if scope.Kind() == model.ScopeAdmin {
			return nil, fmt.Errorf("key not found")
		}
		return nil, fmt.Errorf("key not found or access denied")
	case err != nil:
		r.log.LogAuditError(uuid.Nil.String(), "read_deleted_key", "failed", "Failed to query key", err)
		return nil, fmt.Errorf("failed to query key: %w", err)
	}

	// Tags are not strictly needed for deletion metadata but kept for consistency.
	tagRepo := db.NewTagRepository[model.Key](r.db, "key_tags", "key_id")
	key.Tags, err = tagRepo.GetTags(ctx, id)
	if err != nil {
		r.log.LogAuditError(uuid.Nil.String(), "read_deleted_key", "failed", "Failed to read tags", err)
		return nil, fmt.Errorf("failed to read tags: %w", err)
	}

	return &key, nil
}

// Delete removes a key from the database.
// It removes the key and its associated tags within a transaction.
//
// Parameters:
//   - ctx: The context for the database operation.
//   - id: The key's unique identifier.
//
// Returns:
//
//	An error if the deletion fails.
func (r *KeyRepository) Delete(ctx context.Context, id uuid.UUID) error {
	return deleteItemWithTags(ctx, r.db, r.crud(), id)
}

// UpdateRevocationStatus updates only the revocation status of a key.
// This is used for key rotation workflows.
//
// Parameters:
//   - ctx: The context for the database operation.
//   - id: The key's unique identifier.
//   - revoked: The new revocation status.
//
// Returns:
//
//	An error if the update fails.
func (r *KeyRepository) UpdateRevocationStatus(ctx context.Context, id uuid.UUID, revoked bool) error {
	return r.executeWithMetrics("update_key_revocation", func() error {
		result, err := r.db.ExecContext(
			ctx,
			"UPDATE keys SET revoked = ? WHERE id = ?",
			revoked, id.String(),
		)
		if err != nil {
			r.log.LogAuditError(uuid.Nil.String(), "update_key_revocation", "failed", "Failed to update revocation status", err)
			return fmt.Errorf("failed to update revocation status: %w", err)
		}

		rowsAffected, err := result.RowsAffected()
		if err != nil {
			r.log.LogAuditError(uuid.Nil.String(), "update_key_revocation", "failed", "Failed to get rows affected", err)
			return fmt.Errorf("failed to get rows affected: %w", err)
		}
		if rowsAffected == 0 {
			r.log.LogAuditError(uuid.Nil.String(), "update_key_revocation", "failed", "Key not found", nil)
			return fmt.Errorf("key not found")
		}

		r.log.LogAuditInfo(uuid.Nil.String(), "update_key_revocation", "success", fmt.Sprintf("Key revocation status updated to %v", revoked))
		return nil
	})
}

// SoftDelete marks a key as deleted without removing it from the database.
// The key is excluded from normal reads but remains available for recovery.
//
// Parameters:
//   - ctx: The context for the database operation.
//   - id: The key's unique identifier.
//
// Returns:
//
//	An error if the soft deletion fails.
func (r *KeyRepository) SoftDelete(ctx context.Context, id uuid.UUID) error {
	return softDeleteItem(ctx, r.db, r.crud(), id)
}

// RecoverKey restores a soft-deleted key by clearing its deleted_at timestamp.
//
// Parameters:
//   - ctx: The context for the database operation.
//   - id: The key's unique identifier.
//
// Returns:
//
//	An error if the key is not found in a deleted state or the update fails.
func (r *KeyRepository) RecoverKey(ctx context.Context, id uuid.UUID) error {
	return recoverItem(ctx, r.db, r.crud(), id)
}

// PurgeKey permanently removes a soft-deleted key from the database.
// It fails if the key has purge protection enabled.
//
// Parameters:
//   - ctx: The context for the database operation.
//   - id: The key's unique identifier.
//
// Returns:
//
//	An error if the purge operation fails or purge protection is enabled.
func (r *KeyRepository) PurgeKey(ctx context.Context, id uuid.UUID) error {
	return purgeItem(ctx, r.db, r.crud(), id)
}

// SetPurgeProtection enables or disables purge protection on a key.
// A key with purge protection cannot be permanently deleted via PurgeKey.
//
// Parameters:
//   - ctx: The context for the database operation.
//   - id: The key's unique identifier.
//   - enabled: True to enable purge protection, false to disable it.
//
// Returns:
//
//	An error if the update fails.
func (r *KeyRepository) SetPurgeProtection(ctx context.Context, id uuid.UUID, enabled bool) error {
	return r.setPurgeProtection(ctx, r.db, id, enabled)
}

// SetPurgeProtectionTx is SetPurgeProtection's Tx-scoped variant. See
// CreateTx.
func (r *KeyRepository) SetPurgeProtectionTx(ctx context.Context, ex db.DBTX, id uuid.UUID, enabled bool) error {
	return r.setPurgeProtection(ctx, ex, id, enabled)
}

func (r *KeyRepository) setPurgeProtection(ctx context.Context, ex db.DBTX, id uuid.UUID, enabled bool) error {
	return setPurgeProtectionItem(ctx, ex, r.crud(), id, enabled)
}

// CreateVersion inserts a new version row for a key into the key_versions table.
// value is the encrypted key material for this version.
//
// Parameters:
//   - ctx: The context for the database operation.
//   - keyID: The key's unique identifier.
//   - version: The version number (must be unique per key).
//   - value: The encrypted PEM material for this version.
//
// Returns:
//
//	An error if the insertion fails.
func (r *KeyRepository) CreateVersion(ctx context.Context, keyID uuid.UUID, version int, value string) error {
	return r.createVersion(ctx, r.db, keyID, version, value)
}

// CreateVersionTx is CreateVersion's Tx-scoped variant. See CreateTx.
func (r *KeyRepository) CreateVersionTx(ctx context.Context, ex db.DBTX, keyID uuid.UUID, version int, value string) error {
	return r.createVersion(ctx, ex, keyID, version, value)
}

func (r *KeyRepository) createVersion(ctx context.Context, ex db.DBTX, keyID uuid.UUID, version int, value string) error {
	_, err := ex.ExecContext(ctx,
		"INSERT INTO key_versions (key_id, version, value, created_at) VALUES (?, ?, ?, ?)",
		keyID.String(), version, value, time.Now(),
	)
	return err
}

// ListVersions retrieves all version metadata for a key. Raw key material
// (value) is not returned; only version number and timestamp are exposed.
//
// Performs no authorization; see ReadVersionValue for the contract.
//
// Parameters:
//   - ctx: The context for the database operation.
//   - keyID: The key's unique identifier.
//
// Returns:
//
//	An ordered (ASC) slice of KeyVersion records, or an error if retrieval fails.
func (r *KeyRepository) ListVersions(ctx context.Context, keyID uuid.UUID) ([]model.KeyVersion, error) {
	rows, err := r.db.QueryContext(ctx, `
		SELECT kv.version, kv.created_at
		FROM key_versions kv
		WHERE kv.key_id = ?
		ORDER BY kv.version ASC`,
		keyID.String(),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to query key versions: %w", err)
	}
	defer rows.Close() //nolint:errcheck

	var versions []model.KeyVersion
	for rows.Next() {
		var v model.KeyVersion
		v.KeyID = keyID
		if err := rows.Scan(&v.Version, &v.CreatedAt); err != nil {
			return nil, fmt.Errorf("failed to scan key version: %w", err)
		}
		versions = append(versions, v)
	}
	return versions, rows.Err()
}

// ReadVersionValue returns the encrypted/handle material for one version
// of a key, by key ID and version.
//
// It performs NO authorization. The caller MUST have already authorized
// the parent key with a scoped Read -- these version rows are reachable
// only through a key the caller has proved access to. A previous
// signature took a userID and filtered on k.user_id; every caller
// satisfied it by passing the owner ID from that same scoped Read, so it
// could never fail while appearing to be a check. See known-bugs B28 for
// the bug that ambiguity caused.
//
// Falls back to keys.value when version==1 and the key has never been
// rotated (zero key_versions rows), matching RotateKey's own versioning
// math: a never-rotated key's only material is keys.value, which is
// version 1 implicitly.
func (r *KeyRepository) ReadVersionValue(ctx context.Context, keyID uuid.UUID, version int) (string, error) {
	if version < 1 {
		return "", fmt.Errorf("%w: version must be >= 1", ErrKeyVersionNotFound)
	}

	var value string
	err := r.db.QueryRowContext(ctx, `
		SELECT kv.value
		FROM key_versions kv
		WHERE kv.key_id = ? AND kv.version = ?`,
		keyID.String(), version,
	).Scan(&value)
	if err == nil {
		return value, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return "", fmt.Errorf("failed to query key version: %w", err)
	}
	if version != 1 {
		return "", fmt.Errorf("%w: key %s has no version %d", ErrKeyVersionNotFound, keyID, version)
	}

	err = r.db.QueryRowContext(ctx,
		"SELECT value FROM keys WHERE id = ?",
		keyID.String(),
	).Scan(&value)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return "", fmt.Errorf("%w: key %s has no version %d", ErrKeyVersionNotFound, keyID, version)
		}
		return "", fmt.Errorf("failed to query key: %w", err)
	}
	return value, nil
}

// GetVersion returns metadata (no material) for one version of a key.
// Performs no authorization; see ReadVersionValue for the contract. Same
// not-found and implicit-version-1 fallback semantics as ReadVersionValue.
func (r *KeyRepository) GetVersion(ctx context.Context, keyID uuid.UUID, version int) (*model.KeyVersion, error) {
	if version < 1 {
		return nil, fmt.Errorf("%w: version must be >= 1", ErrKeyVersionNotFound)
	}

	var createdAt time.Time
	err := r.db.QueryRowContext(ctx, `
		SELECT kv.created_at
		FROM key_versions kv
		WHERE kv.key_id = ? AND kv.version = ?`,
		keyID.String(), version,
	).Scan(&createdAt)
	if err == nil {
		return &model.KeyVersion{KeyID: keyID, Version: version, CreatedAt: createdAt}, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("failed to query key version: %w", err)
	}
	if version != 1 {
		return nil, fmt.Errorf("%w: key %s has no version %d", ErrKeyVersionNotFound, keyID, version)
	}

	err = r.db.QueryRowContext(ctx,
		"SELECT created_at FROM keys WHERE id = ?",
		keyID.String(),
	).Scan(&createdAt)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("%w: key %s has no version %d", ErrKeyVersionNotFound, keyID, version)
		}
		return nil, fmt.Errorf("failed to query key: %w", err)
	}
	return &model.KeyVersion{KeyID: keyID, Version: 1, CreatedAt: createdAt}, nil
}

// ListVersionRecords returns every version of a key INCLUDING material,
// by key ID. Internal use only (the backup service) -- never wired to an
// HTTP response.
//
// Performs no authorization; see ReadVersionValue for the contract.
//
// Unlike ReadVersionValue/GetVersion, this does NOT synthesize an implicit
// version-1 entry for a never-rotated key: the backup service backs up
// keys.value separately, so no such entry is needed here.
func (r *KeyRepository) ListVersionRecords(ctx context.Context, keyID uuid.UUID) ([]model.KeyVersionRecord, error) {
	rows, err := r.db.QueryContext(ctx, `
		SELECT kv.version, kv.value, kv.created_at
		FROM key_versions kv
		WHERE kv.key_id = ?
		ORDER BY kv.version ASC`,
		keyID.String(),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to query key version records: %w", err)
	}
	defer rows.Close() //nolint:errcheck

	var records []model.KeyVersionRecord
	for rows.Next() {
		var rec model.KeyVersionRecord
		rec.KeyID = keyID
		if err := rows.Scan(&rec.Version, &rec.Value, &rec.CreatedAt); err != nil {
			return nil, fmt.Errorf("failed to scan key version record: %w", err)
		}
		records = append(records, rec)
	}
	return records, rows.Err()
}

// CurrentVersion returns keyID's current version number via a single
// aggregate query against key_versions alone -- no join against keys is
// needed. An ungrouped aggregate always yields exactly one row regardless
// of how many (if any) key_versions rows match, so COALESCE(MAX(version),
// 1) supplies the never-rotated fallback on its own; this also avoids
// fetching every version row just to find the max.
//
// Performs no authorization; see ReadVersionValue for the contract.
//
// Parameters:
//   - ctx: The context for the database operation.
//   - keyID: The key's unique identifier.
//
// Returns:
//
//	The current version number, or an error if the query fails.
func (r *KeyRepository) CurrentVersion(ctx context.Context, keyID uuid.UUID) (int, error) {
	var version int
	err := r.db.QueryRowContext(ctx, `
		SELECT COALESCE(MAX(version), 1)
		FROM key_versions
		WHERE key_id = ?`,
		keyID.String(),
	).Scan(&version)
	if err != nil {
		return 0, fmt.Errorf("failed to determine current key version: %w", err)
	}
	return version, nil
}

// SoftDeleteVaultContents marks every active key in a vault as soft-deleted.
//
// Parameters:
//   - ctx: The context for the database operation.
//   - vaultID: The vault whose keys should be soft-deleted.
//   - deletedAt: The exact deletion timestamp to stamp on each cascaded row.
//
// Returns:
//
//	An error if the soft deletion fails.
func (r *KeyRepository) SoftDeleteVaultContents(ctx context.Context, vaultID uuid.UUID, deletedAt time.Time) error {
	return softDeleteVaultContents(ctx, r.db, r.crud(), vaultID, deletedAt)
}

// SoftDeleteVaultContentsTx is SoftDeleteVaultContents scoped to an explicit executor.
func (r *KeyRepository) SoftDeleteVaultContentsTx(ctx context.Context, ex db.DBTX, vaultID uuid.UUID, deletedAt time.Time) error {
	return softDeleteVaultContents(ctx, ex, r.crud(), vaultID, deletedAt)
}

// RecoverVaultContents restores every soft-deleted key in a vault.
//
// Parameters:
//   - ctx: The context for the database operation.
//   - vaultID: The vault whose keys should be recovered.
//   - deletedAt: The cascade deletion timestamp; only rows stamped with it are restored.
//
// Returns:
//
//	An error if the recovery fails.
func (r *KeyRepository) RecoverVaultContents(ctx context.Context, vaultID uuid.UUID, deletedAt time.Time) error {
	return recoverVaultContents(ctx, r.db, r.crud(), vaultID, deletedAt)
}

// RecoverVaultContentsTx is RecoverVaultContents scoped to an explicit executor.
func (r *KeyRepository) RecoverVaultContentsTx(ctx context.Context, ex db.DBTX, vaultID uuid.UUID, deletedAt time.Time) error {
	return recoverVaultContents(ctx, ex, r.crud(), vaultID, deletedAt)
}

// PurgeVaultContents permanently deletes every key in a vault, regardless of
// soft-delete state. keys.vault_id carries no foreign key to vaults(id)
// (unlike role_assignments.vault_id, which cascades), so without this call a
// vault purge would strand every key it ever contained as an orphaned row,
// unreachable through any route and never swept by the soft-delete purge
// scheduler (which only purges individually-deleted items, not vault
// orphans). key_versions cascades automatically via its own FK on keys(id).
// Mirrors the unconditional DELETE the vault service already issues for
// access_policies on purge, for the same reason.
func (r *KeyRepository) PurgeVaultContents(ctx context.Context, vaultID uuid.UUID) error {
	return purgeVaultContents(ctx, r.db, r.crud(), vaultID)
}

// HasProtectedContent reports whether any key in the vault, active or
// soft-deleted, has purge_protection enabled. Consumed by the vault service's
// cascade purge-protection check (see vaults.CascadeRepository) so purging a
// vault can't bypass an individual key's own protection.
func (r *KeyRepository) HasProtectedContent(ctx context.Context, vaultID uuid.UUID) (bool, error) {
	return hasProtectedContent(ctx, r.db, r.crud(), vaultID)
}
