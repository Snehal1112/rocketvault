// Package softdelete provides background scheduling for permanent deletion of
// soft-deleted records whose retention period has expired.
package softdelete

import (
	"context"
	"fmt"
	"time"

	"rocketvault/config"
	rvdb "rocketvault/internal/db"
	"rocketvault/internal/logging"
	"rocketvault/model"
)

// VaultPurger lists and purges vaults. Satisfied by
// internal/services/vaults.VaultService's ListVaults/PurgeVault methods -- a
// narrow interface naming exactly what this scheduler needs, rather than
// importing the vaults service package.
type VaultPurger interface {
	ListVaults(ctx context.Context, includeDeleted bool) ([]model.Vault, error)
	PurgeVault(ctx context.Context, name string) error
}

// PurgeScheduler runs daily and permanently deletes soft-deleted items
// whose retention period has expired and purge_protection is false.
type PurgeScheduler struct {
	db     rvdb.DB
	cfg    config.SoftDeleteConfig
	log    *logging.Logger
	done   chan struct{}
	vaults VaultPurger
}

// NewPurgeScheduler creates a new PurgeScheduler. vaults may be nil, in
// which case vault auto-purge is skipped (secrets/keys/certificates are
// still swept normally) -- tests that don't exercise vault behavior are not
// required to supply one.
func NewPurgeScheduler(db rvdb.DB, cfg config.SoftDeleteConfig, log *logging.Logger, vaults VaultPurger) *PurgeScheduler {
	return &PurgeScheduler{db: db, cfg: cfg, log: log, done: make(chan struct{}), vaults: vaults}
}

// Start launches the scheduler in a background goroutine.
func (s *PurgeScheduler) Start(ctx context.Context) {
	go s.run(ctx)
}

// Stop signals the scheduler to stop.
func (s *PurgeScheduler) Stop() {
	close(s.done)
}

func (s *PurgeScheduler) run(ctx context.Context) {
	ticker := time.NewTicker(24 * time.Hour)
	defer ticker.Stop()

	// Run once immediately on startup.
	s.purgeExpired(ctx)

	for {
		select {
		case <-ticker.C:
			s.purgeExpired(ctx)
		case <-s.done:
			return
		case <-ctx.Done():
			return
		}
	}
}

// purgeExpired permanently deletes items past their retention period. When
// soft_delete.purge_protection is enabled instance-wide, the entire sweep is
// skipped -- no table is touched.
func (s *PurgeScheduler) purgeExpired(ctx context.Context) {
	if s.cfg.PurgeProtection {
		s.log.Infof("auto-purge skipped: soft_delete.purge_protection is enabled")
		return
	}

	cutoff := time.Now().AddDate(0, 0, -s.cfg.RetentionDays)
	tables := []string{"secrets", "keys", "certificates"}
	for _, table := range tables {
		query := fmt.Sprintf(
			`DELETE FROM %s WHERE deleted_at IS NOT NULL AND deleted_at < ? AND purge_protection = FALSE`,
			table,
		)
		n, err := s.purgeTable(ctx, table, query, cutoff)
		if err != nil {
			s.log.WithError(err).Errorf("auto-purge failed for table %s", table)
			continue
		}
		if n > 0 {
			s.log.Infof("auto-purged %d expired items from %s", n, table)
		}
	}

	s.purgeExpiredVaults(ctx)
}

// purgeTable runs the expired-row DELETE for one table. For certificates it
// first deletes their archived versions in the same transaction, because
// SQLite runs with foreign keys off and the cascade never fires.
func (s *PurgeScheduler) purgeTable(ctx context.Context, table, query string, cutoff time.Time) (int64, error) {
	if table != "certificates" {
		result, err := s.db.ExecContext(ctx, query, cutoff)
		if err != nil {
			return 0, err
		}
		n, _ := result.RowsAffected()
		return n, nil
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer func() { _ = tx.Rollback() }()

	_, err = tx.ExecContext(ctx,
		`DELETE FROM certificate_versions WHERE certificate_id IN (
			SELECT id FROM certificates WHERE deleted_at IS NOT NULL AND deleted_at < ? AND purge_protection = FALSE)`,
		cutoff)
	if err != nil {
		return 0, err
	}
	result, err := tx.ExecContext(ctx, query, cutoff)
	if err != nil {
		return 0, err
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	n, _ := result.RowsAffected()
	return n, nil
}

// purgeExpiredVaults auto-purges soft-deleted vaults past their retention
// window. Unlike secrets/keys/certificates (leaf rows, purged with a single
// DELETE), a vault owns child rows, so each eligible vault is purged through
// VaultPurger.PurgeVault, which re-checks protection and cascades correctly
// -- a raw SQL delete here would either orphan the vault's contents or
// require duplicating that cascade logic.
//
// Each vault's own RetentionDays overrides the global soft_delete.retention_days
// when set (> 0); otherwise the global value applies, matching secrets/keys/certificates.
func (s *PurgeScheduler) purgeExpiredVaults(ctx context.Context) {
	if s.vaults == nil {
		return
	}

	vaultList, err := s.vaults.ListVaults(ctx, true)
	if err != nil {
		s.log.WithError(err).Error("auto-purge failed to list vaults")
		return
	}

	now := time.Now()
	purged := 0
	for _, v := range vaultList {
		if v.DeletedAt == nil || v.PurgeProtection {
			continue
		}
		retentionDays := v.RetentionDays
		if retentionDays <= 0 {
			retentionDays = s.cfg.RetentionDays
		}
		if !v.DeletedAt.AddDate(0, 0, retentionDays).Before(now) {
			continue
		}
		if err := s.vaults.PurgeVault(ctx, v.Name); err != nil {
			s.log.WithError(err).Errorf("auto-purge failed for vault %s", v.Name)
			continue
		}
		purged++
	}
	if purged > 0 {
		s.log.Infof("auto-purged %d expired vaults", purged)
	}
}
