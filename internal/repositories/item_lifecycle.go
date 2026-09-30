package repositories

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"

	"rocketvault/internal/db"
	"rocketvault/internal/logging"
)

// itemLifecycleConfig holds the per-type constants softDeleteItem, recoverItem,
// purgeItem, setPurgeProtectionItem, softDeleteVaultContents,
// recoverVaultContents, purgeVaultContents, and hasProtectedContent need to
// reproduce SecretRepository's, KeyRepository's, and CertificateRepository's
// existing behavior exactly, including their pre-existing divergences:
//   - auditActor is the constant actor ID string item-scoped operations log.
//     Secret predates the uuid.Nil.String() convention and logs "" instead.
//   - wrap is the metrics-wrapping function each operation runs through.
//     Secret predates the metrics wrapper (internal/metrics) and passes
//     passthroughWrap; key and certificate pass their own executeWithMetrics.
//   - notFoundIsSentinel is true only for secret: SetPurgeProtection's
//     not-found error wraps the shared ErrNotFound sentinel, while key's and
//     certificate's return a plain, unwrapped error.
//   - tagTable/tagFK identify the item's tag join table. Each declares
//     ON DELETE CASCADE, but SQLite runs with the foreign_keys pragma off
//     project-wide, so the cascade never fires and the rows must be deleted
//     explicitly -- the same reason RoleAssignmentRepository.DeleteByVault and
//     AccessPolicyRepository.DeleteByVault exist.
type itemLifecycleConfig struct {
	table    string // SQL table name, plural: "secrets" / "keys" / "certificates"
	item     string // singular label: "secret" / "key" / "certificate"
	itemCap  string // capitalized singular label: "Secret" / "Key" / "Certificate"
	idField  string // logrus field key for id-scoped debug logs: "secret_id" / "key_id" / "cert_id"
	tagTable string // join table holding this item's tags: "secret_tags" / "key_tags" / "certificate_tags"
	tagFK    string // the tag table's column referencing the item: "secret_id" / "key_id" / "certificate_id"
	// versionTable/versionFK name the item's archived-version table when the
	// purge and delete paths must clear it explicitly. Only certificates set
	// them. The same SQLite cascade caveat applies to key_versions and
	// secret_versions, but those are tracked separately as B26.
	versionTable       string
	versionFK          string
	auditActor         string
	purgeErr           error
	notFoundIsSentinel bool
	log                *logging.Logger
	wrap               func(operation string, fn func() error) error
}

// passthroughWrap runs fn directly with no metrics wrapping — secret's wrap.
func passthroughWrap(_ string, fn func() error) error { return fn() }

// deleteItemVersions removes id's archived-version rows when cfg names a
// version table. See itemLifecycleConfig.versionTable.
func deleteItemVersions(ctx context.Context, ex db.DBTX, cfg itemLifecycleConfig, id uuid.UUID) error {
	if cfg.versionTable == "" {
		return nil
	}
	if _, err := ex.ExecContext(ctx,
		"DELETE FROM "+cfg.versionTable+" WHERE "+cfg.versionFK+" = ?", id.String()); err != nil {
		return fmt.Errorf("failed to delete %s versions: %w", cfg.item, err)
	}
	return nil
}

// softDeleteItem marks one row deleted_at = now(), refusing rows already
// soft-deleted.
func softDeleteItem(ctx context.Context, ex db.DBTX, cfg itemLifecycleConfig, id uuid.UUID) error {
	op := "soft_delete_" + cfg.item
	return cfg.wrap(op, func() error {
		logrus.WithField(cfg.idField, id.String()).Debug("Soft deleting " + cfg.item + " from database")

		now := time.Now()
		result, err := ex.ExecContext(ctx,
			"UPDATE "+cfg.table+" SET deleted_at = ? WHERE id = ? AND deleted_at IS NULL",
			now, id.String())
		if err != nil {
			cfg.log.LogAuditError(cfg.auditActor, op, "failed", "Failed to soft delete "+cfg.item, err)
			return fmt.Errorf("failed to soft delete %s: %w", cfg.item, err)
		}

		rowsAffected, err := result.RowsAffected()
		if err != nil {
			cfg.log.LogAuditError(cfg.auditActor, op, "failed", "Failed to get rows affected", err)
			return fmt.Errorf("failed to get rows affected: %w", err)
		}
		if rowsAffected == 0 {
			cfg.log.LogAuditError(cfg.auditActor, op, "failed", cfg.itemCap+" not found or already deleted", nil)
			return fmt.Errorf("%s not found or already deleted", cfg.item)
		}

		cfg.log.LogAuditInfo(cfg.auditActor, op, "success", cfg.itemCap+" soft deleted successfully")
		logrus.WithField(cfg.idField, id.String()).Debug(cfg.itemCap + " soft deleted successfully")
		return nil
	})
}

// recoverItem clears deleted_at on a soft-deleted row, refusing rows that
// aren't currently soft-deleted.
func recoverItem(ctx context.Context, ex db.DBTX, cfg itemLifecycleConfig, id uuid.UUID) error {
	op := "recover_" + cfg.item
	return cfg.wrap(op, func() error {
		logrus.WithField(cfg.idField, id.String()).Debug("Recovering soft-deleted " + cfg.item)

		result, err := ex.ExecContext(ctx,
			"UPDATE "+cfg.table+" SET deleted_at = NULL, scheduled_purge_at = NULL WHERE id = ? AND deleted_at IS NOT NULL",
			id.String())
		if err != nil {
			cfg.log.LogAuditError(cfg.auditActor, op, "failed", "Failed to recover "+cfg.item, err)
			return fmt.Errorf("failed to recover %s: %w", cfg.item, err)
		}

		rowsAffected, err := result.RowsAffected()
		if err != nil {
			cfg.log.LogAuditError(cfg.auditActor, op, "failed", "Failed to get rows affected", err)
			return fmt.Errorf("failed to get rows affected: %w", err)
		}
		if rowsAffected == 0 {
			cfg.log.LogAuditError(cfg.auditActor, op, "failed", cfg.itemCap+" not found in deleted state", nil)
			return fmt.Errorf("%s not found in deleted state", cfg.item)
		}

		cfg.log.LogAuditInfo(cfg.auditActor, op, "success", cfg.itemCap+" recovered successfully")
		logrus.WithField(cfg.idField, id.String()).Debug(cfg.itemCap + " recovered successfully")
		return nil
	})
}

// purgeItem permanently deletes a soft-deleted row, refusing rows that
// aren't soft-deleted or that have purge protection enabled. The status check
// runs against conn before any write; only once it passes does purgeItem open
// its own transaction for the tag delete and the item delete together, so a
// failure on either leaves both rows exactly as they were -- mirroring
// deleteItemWithTags below. Unlike the other functions in this file it takes
// a db.DB rather than a db.DBTX, because it begins the transaction itself;
// every call site already passes r.db, a db.DB, so this is not a
// call-site-visible change.
func purgeItem(ctx context.Context, conn db.DB, cfg itemLifecycleConfig, id uuid.UUID) error {
	op := "purge_" + cfg.item
	return cfg.wrap(op, func() error {
		logrus.WithField(cfg.idField, id.String()).Debug("Purging " + cfg.item + " from database")

		var deletedAt *time.Time
		var purgeProtection bool
		err := conn.QueryRowContext(ctx,
			"SELECT deleted_at, purge_protection FROM "+cfg.table+" WHERE id = ?", id.String()).
			Scan(&deletedAt, &purgeProtection)
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				cfg.log.LogAuditError(cfg.auditActor, op, "failed", cfg.itemCap+" not found", nil)
				return fmt.Errorf("%s not found", cfg.item)
			}
			cfg.log.LogAuditError(cfg.auditActor, op, "failed", "Failed to check "+cfg.item+" status", err)
			return fmt.Errorf("failed to check %s status: %w", cfg.item, err)
		}

		if deletedAt == nil {
			cfg.log.LogAuditError(cfg.auditActor, op, "failed", cfg.itemCap+" is not soft-deleted", nil)
			return fmt.Errorf("%s is not soft-deleted", cfg.item)
		}
		if purgeProtection {
			cfg.log.LogAuditError(cfg.auditActor, op, "failed", cfg.itemCap+" has purge protection enabled", nil)
			return cfg.purgeErr
		}

		tx, err := conn.BeginTx(ctx, nil)
		if err != nil {
			cfg.log.LogAuditError(cfg.auditActor, op, "failed", "Failed to begin transaction", err)
			return fmt.Errorf("failed to begin transaction: %w", err)
		}
		defer tx.Rollback() //nolint:errcheck

		// Tag rows first, then the item, both against tx. The tag table
		// declares ON DELETE CASCADE, but SQLite runs with the foreign_keys
		// pragma off project-wide, so that cascade never fires -- without this
		// the tags outlive the item as unreachable rows nothing ever sweeps.
		if _, tagErr := tx.ExecContext(ctx,
			"DELETE FROM "+cfg.tagTable+" WHERE "+cfg.tagFK+" = ?", id.String()); tagErr != nil {
			cfg.log.LogAuditError(cfg.auditActor, op, "failed", "Failed to purge "+cfg.item+" tags", tagErr)
			return fmt.Errorf("failed to purge %s tags: %w", cfg.item, tagErr)
		}
		if verErr := deleteItemVersions(ctx, tx, cfg, id); verErr != nil {
			cfg.log.LogAuditError(cfg.auditActor, op, "failed", "Failed to purge "+cfg.item+" versions", verErr)
			return verErr
		}

		result, err := tx.ExecContext(ctx, "DELETE FROM "+cfg.table+" WHERE id = ?", id.String())
		if err != nil {
			cfg.log.LogAuditError(cfg.auditActor, op, "failed", "Failed to purge "+cfg.item, err)
			return fmt.Errorf("failed to purge %s: %w", cfg.item, err)
		}

		rowsAffected, err := result.RowsAffected()
		if err != nil {
			cfg.log.LogAuditError(cfg.auditActor, op, "failed", "Failed to get rows affected", err)
			return fmt.Errorf("failed to get rows affected: %w", err)
		}
		if rowsAffected == 0 {
			cfg.log.LogAuditError(cfg.auditActor, op, "failed", cfg.itemCap+" not found for purge", nil)
			return fmt.Errorf("%s not found for purge", cfg.item)
		}

		if err := tx.Commit(); err != nil {
			cfg.log.LogAuditError(cfg.auditActor, op, "failed", "Failed to commit transaction", err)
			return fmt.Errorf("failed to commit transaction: %w", err)
		}

		cfg.log.LogAuditInfo(cfg.auditActor, op, "success", cfg.itemCap+" purged successfully")
		logrus.WithField(cfg.idField, id.String()).Debug(cfg.itemCap + " purged successfully")
		return nil
	})
}

// setPurgeProtectionItem enables or disables purge protection on one row.
func setPurgeProtectionItem(ctx context.Context, ex db.DBTX, cfg itemLifecycleConfig, id uuid.UUID, enabled bool) error {
	op := "set_purge_protection_" + cfg.item
	return cfg.wrap(op, func() error {
		result, err := ex.ExecContext(ctx,
			"UPDATE "+cfg.table+" SET purge_protection = ? WHERE id = ?", enabled, id.String())
		if err != nil {
			cfg.log.LogAuditError(cfg.auditActor, op, "failed", "Failed to set purge protection", err)
			return fmt.Errorf("failed to set purge protection: %w", err)
		}

		rowsAffected, err := result.RowsAffected()
		if err != nil {
			cfg.log.LogAuditError(cfg.auditActor, op, "failed", "Failed to get rows affected", err)
			return fmt.Errorf("failed to get rows affected: %w", err)
		}
		if rowsAffected == 0 {
			cfg.log.LogAuditError(cfg.auditActor, op, "failed", cfg.itemCap+" not found", nil)
			if cfg.notFoundIsSentinel {
				return fmt.Errorf("%s %s: %w", cfg.item, id.String(), ErrNotFound)
			}
			return fmt.Errorf("%s not found", cfg.item)
		}

		cfg.log.LogAuditInfo(cfg.auditActor, op, "success", fmt.Sprintf("%s purge protection set to %v", cfg.itemCap, enabled))
		return nil
	})
}

// softDeleteVaultContents marks every active row in vaultID deleted_at =
// deletedAt.
func softDeleteVaultContents(ctx context.Context, ex db.DBTX, cfg itemLifecycleConfig, vaultID uuid.UUID, deletedAt time.Time) error {
	op := "soft_delete_vault_" + cfg.table
	return cfg.wrap(op, func() error {
		logrus.WithField("vault_id", vaultID.String()).Debug("Soft deleting all " + cfg.table + " in vault")

		_, err := ex.ExecContext(ctx,
			"UPDATE "+cfg.table+" SET deleted_at = ? WHERE vault_id = ? AND deleted_at IS NULL",
			deletedAt, vaultID.String())
		if err != nil {
			cfg.log.LogAuditError(vaultID.String(), op, "failed", "Failed to soft delete vault "+cfg.table, err)
			return fmt.Errorf("failed to soft delete vault %s: %w", cfg.table, err)
		}

		cfg.log.LogAuditInfo(vaultID.String(), op, "success", "Vault "+cfg.table+" soft deleted successfully")
		return nil
	})
}

// recoverVaultContents restores only the rows the cascade soft-deleted at
// deletedAt.
func recoverVaultContents(ctx context.Context, ex db.DBTX, cfg itemLifecycleConfig, vaultID uuid.UUID, deletedAt time.Time) error {
	op := "recover_vault_" + cfg.table
	return cfg.wrap(op, func() error {
		logrus.WithField("vault_id", vaultID.String()).Debug("Recovering cascade soft-deleted " + cfg.table + " in vault")

		_, err := ex.ExecContext(ctx,
			"UPDATE "+cfg.table+" SET deleted_at = NULL, scheduled_purge_at = NULL WHERE vault_id = ? AND deleted_at = ?",
			vaultID.String(), deletedAt)
		if err != nil {
			cfg.log.LogAuditError(vaultID.String(), op, "failed", "Failed to recover vault "+cfg.table, err)
			return fmt.Errorf("failed to recover vault %s: %w", cfg.table, err)
		}

		cfg.log.LogAuditInfo(vaultID.String(), op, "success", "Vault "+cfg.table+" recovered successfully")
		return nil
	})
}

// purgeVaultContents permanently deletes every row in vaultID, regardless of
// soft-delete state.
func purgeVaultContents(ctx context.Context, ex db.DBTX, cfg itemLifecycleConfig, vaultID uuid.UUID) error {
	op := "purge_vault_" + cfg.table
	return cfg.wrap(op, func() error {
		logrus.WithField("vault_id", vaultID.String()).Debug("Purging all " + cfg.table + " in vault")

		// Same cascade caveat as purgeItem: delete the vault's tag rows via a
		// subquery over the items about to be removed, before removing them.
		if _, tagErr := ex.ExecContext(ctx,
			"DELETE FROM "+cfg.tagTable+" WHERE "+cfg.tagFK+
				" IN (SELECT id FROM "+cfg.table+" WHERE vault_id = ?)", vaultID.String()); tagErr != nil {
			cfg.log.LogAuditError(vaultID.String(), op, "failed", "Failed to purge vault "+cfg.tagTable, tagErr)
			return fmt.Errorf("failed to purge vault %s: %w", cfg.tagTable, tagErr)
		}
		// Same cascade caveat for archived versions, through the same subquery.
		if cfg.versionTable != "" {
			if _, verErr := ex.ExecContext(ctx,
				"DELETE FROM "+cfg.versionTable+" WHERE "+cfg.versionFK+
					" IN (SELECT id FROM "+cfg.table+" WHERE vault_id = ?)", vaultID.String()); verErr != nil {
				cfg.log.LogAuditError(vaultID.String(), op, "failed", "Failed to purge vault "+cfg.versionTable, verErr)
				return fmt.Errorf("failed to purge vault %s: %w", cfg.versionTable, verErr)
			}
		}

		_, err := ex.ExecContext(ctx, "DELETE FROM "+cfg.table+" WHERE vault_id = ?", vaultID.String())
		if err != nil {
			cfg.log.LogAuditError(vaultID.String(), op, "failed", "Failed to purge vault "+cfg.table, err)
			return fmt.Errorf("failed to purge vault %s: %w", cfg.table, err)
		}

		cfg.log.LogAuditInfo(vaultID.String(), op, "success", "Vault "+cfg.table+" purged successfully")
		return nil
	})
}

// deleteItemWithTags hard-deletes one row and its tag rows in a single
// transaction, tags first. Unlike the other functions in this file it takes a
// db.DB rather than a db.DBTX, because it begins the transaction itself.
//
// The tag delete is not optional bookkeeping: the tag tables declare
// ON DELETE CASCADE, but SQLite runs with the foreign_keys pragma off
// project-wide, so the cascade never fires. Before this helper, secret's
// Delete omitted the tag cleanup entirely while key's and certificate's
// performed it -- the divergence this consolidates away.
func deleteItemWithTags(ctx context.Context, conn db.DB, cfg itemLifecycleConfig, id uuid.UUID) error {
	op := "delete_" + cfg.item
	return cfg.wrap(op, func() error {
		logrus.WithField(cfg.idField, id.String()).Debug("Deleting " + cfg.item + " from database")

		tx, err := conn.BeginTx(ctx, nil)
		if err != nil {
			cfg.log.LogAuditError(cfg.auditActor, op, "failed", "Failed to begin transaction", err)
			return fmt.Errorf("failed to begin transaction: %w", err)
		}
		defer tx.Rollback() //nolint:errcheck

		if _, err := tx.ExecContext(ctx,
			"DELETE FROM "+cfg.tagTable+" WHERE "+cfg.tagFK+" = ?", id.String()); err != nil {
			cfg.log.LogAuditError(cfg.auditActor, op, "failed", "Failed to delete tags", err)
			return fmt.Errorf("failed to delete tags: %w", err)
		}
		if verErr := deleteItemVersions(ctx, tx, cfg, id); verErr != nil {
			cfg.log.LogAuditError(cfg.auditActor, op, "failed", "Failed to delete "+cfg.item+" versions", verErr)
			return verErr
		}

		result, err := tx.ExecContext(ctx, "DELETE FROM "+cfg.table+" WHERE id = ?", id.String())
		if err != nil {
			cfg.log.LogAuditError(cfg.auditActor, op, "failed", "Failed to delete "+cfg.item, err)
			return fmt.Errorf("failed to delete %s: %w", cfg.item, err)
		}

		rowsAffected, err := result.RowsAffected()
		if err != nil {
			cfg.log.LogAuditError(cfg.auditActor, op, "failed", "Failed to get rows affected", err)
			return fmt.Errorf("failed to get rows affected: %w", err)
		}
		if rowsAffected == 0 {
			cfg.log.LogAuditError(cfg.auditActor, op, "failed", cfg.itemCap+" not found for deletion", nil)
			return fmt.Errorf("%s not found", cfg.item)
		}

		if err := tx.Commit(); err != nil {
			cfg.log.LogAuditError(cfg.auditActor, op, "failed", "Failed to commit transaction", err)
			return fmt.Errorf("failed to commit transaction: %w", err)
		}

		cfg.log.LogAuditInfo(cfg.auditActor, op, "success", cfg.itemCap+" deleted successfully")
		logrus.WithField(cfg.idField, id.String()).Debug(cfg.itemCap + " deleted successfully")
		return nil
	})
}

// hasProtectedContent reports whether any row in vaultID, active or
// soft-deleted, has purge_protection enabled.
func hasProtectedContent(ctx context.Context, ex db.DBTX, cfg itemLifecycleConfig, vaultID uuid.UUID) (bool, error) {
	op := "has_protected_content_" + cfg.table
	var exists bool
	err := cfg.wrap(op, func() error {
		return ex.QueryRowContext(ctx,
			"SELECT EXISTS(SELECT 1 FROM "+cfg.table+" WHERE vault_id = ? AND purge_protection = TRUE)",
			vaultID.String()).Scan(&exists)
	})
	if err != nil {
		return false, fmt.Errorf("failed to check %s purge protection: %w", cfg.item, err)
	}
	return exists, nil
}
