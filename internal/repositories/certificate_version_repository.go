package repositories

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/google/uuid"

	"rocketvault/internal/db"
	"rocketvault/internal/logging"
	"rocketvault/model"
)

// CertificateVersionRepositoryInterface is the data access contract for
// archived certificate versions. The certificates row is always the current
// version; this repository owns the rows that hold every earlier one.
//
// Only ArchiveAndRenew and UpdateCurrentLifecycle take a scope, because they
// write the certificates row. Every other method performs no authorization:
// the caller MUST have authorized the parent certificate with a scoped read
// first. certificate_versions has no vault_id column, so its rows are
// reachable only through a parent the caller has proved access to. This is
// the same contract as KeyRepository.ReadVersionValue (B28).
type CertificateVersionRepositoryInterface interface {
	// ArchiveAndRenew inserts archived into certificate_versions and replaces
	// the certificates row with renewed, in one transaction. renewed.Version
	// must be archived.Version + 1, and the row must still be at
	// archived.Version; otherwise nothing is written and the error wraps
	// ErrCertificateVersionConflict.
	ArchiveAndRenew(ctx context.Context, archived model.CertificateVersionRecord, renewed *model.Certificate, scope model.Scope) error
	// CreateVersion inserts one archived version. Restore uses it.
	CreateVersion(ctx context.Context, rec *model.CertificateVersionRecord) error
	// ListVersions returns the archived versions' metadata, oldest first.
	ListVersions(ctx context.Context, certID uuid.UUID) ([]model.CertificateVersion, error)
	// GetVersion returns one archived version's metadata.
	GetVersion(ctx context.Context, certID uuid.UUID, version int) (*model.CertificateVersion, error)
	// ListVersionRecords returns the archived versions with their material,
	// oldest first. Internal use only: the backup service.
	ListVersionRecords(ctx context.Context, certID uuid.UUID) ([]model.CertificateVersionRecord, error)
	// UpdateVersionLifecycle sets one archived version's lifecycle attributes.
	UpdateVersionLifecycle(ctx context.Context, certID uuid.UUID, version int, attrs model.CertificateVersionAttributes) error
	// UpdateCurrentLifecycle sets the lifecycle attributes on the
	// certificates row, only while that row is still at version.
	UpdateCurrentLifecycle(ctx context.Context, certID uuid.UUID, version int, attrs model.CertificateVersionAttributes, scope model.Scope) error
}

// certificateVersionMetadataColumns is the SELECT list for metadata reads.
const certificateVersionMetadataColumns = "version, created_at, expires_at, not_before, enabled"

// certificateVersionRecordColumns is the SELECT list for material reads.
const certificateVersionRecordColumns = "version, certificate, private_key, key_id, created_at, expires_at, not_before, enabled"

// CertificateVersionRepository implements CertificateVersionRepositoryInterface.
type CertificateVersionRepository struct {
	db  db.DB
	log *logging.Logger
}

var _ CertificateVersionRepositoryInterface = (*CertificateVersionRepository)(nil)

// NewCertificateVersionRepository creates a CertificateVersionRepository.
func NewCertificateVersionRepository(conn db.DB, log *logging.Logger) CertificateVersionRepositoryInterface {
	return &CertificateVersionRepository{db: conn, log: log}
}

func (r *CertificateVersionRepository) executeWithMetrics(operation string, fn func() error) error {
	return withMetrics("certificate_versions", operation, fn)
}

// ArchiveAndRenew archives the current version and moves the certificates
// row to the renewed one, in a single transaction.
func (r *CertificateVersionRepository) ArchiveAndRenew(ctx context.Context, archived model.CertificateVersionRecord, renewed *model.Certificate, scope model.Scope) error {
	if renewed.Version != archived.Version+1 {
		return fmt.Errorf("renewed version %d must directly follow archived version %d", renewed.Version, archived.Version)
	}
	return r.executeWithMetrics("archive_and_renew", func() error {
		tx, err := r.db.BeginTx(ctx, nil)
		if err != nil {
			return fmt.Errorf("failed to begin transaction: %w", err)
		}
		defer tx.Rollback() //nolint:errcheck

		if err := r.insertVersion(ctx, tx, &archived); err != nil {
			return err
		}

		// The version guard is what makes a lost race a conflict: a renewal
		// that read version N cannot overwrite a row another renewal has
		// already moved to N+1.
		result, err := ScopedExec(ctx, tx,
			"UPDATE certificates SET certificate = ?, private_key = ?, version = ?, created_at = ?, expires_at = ?, not_before = ?, enabled = ? WHERE id = ? AND version = ? AND deleted_at IS NULL",
			[]any{
				renewed.Certificate, renewed.PrivateKey, renewed.Version, renewed.CreatedAt,
				renewed.ExpiresAt, renewed.NotBefore, renewed.Enabled, renewed.ID.String(), archived.Version,
			},
			scope)
		if err != nil {
			if errors.Is(err, ErrInvalidScope) {
				return err
			}
			return fmt.Errorf("failed to update renewed certificate: %w", err)
		}
		affected, err := result.RowsAffected()
		if err != nil {
			return fmt.Errorf("failed to get rows affected: %w", err)
		}
		if affected == 0 {
			return fmt.Errorf("certificate %s is no longer at version %d: %w", renewed.ID, archived.Version, ErrCertificateVersionConflict)
		}

		if err := tx.Commit(); err != nil {
			return fmt.Errorf("failed to commit transaction: %w", err)
		}
		return nil
	})
}

// CreateVersion inserts one archived version.
func (r *CertificateVersionRepository) CreateVersion(ctx context.Context, rec *model.CertificateVersionRecord) error {
	return r.executeWithMetrics("create_certificate_version", func() error {
		return r.insertVersion(ctx, r.db, rec)
	})
}

// CreateVersionTx is CreateVersion inside a transaction the caller owns.
// ItemBackupService uses it for an atomic restore.
func (r *CertificateVersionRepository) CreateVersionTx(ctx context.Context, ex db.DBTX, rec *model.CertificateVersionRecord) error {
	return r.executeWithMetrics("create_certificate_version", func() error {
		return r.insertVersion(ctx, ex, rec)
	})
}

// insertVersion writes one certificate_versions row against ex.
func (r *CertificateVersionRepository) insertVersion(ctx context.Context, ex db.DBTX, rec *model.CertificateVersionRecord) error {
	if rec.Version < 1 {
		return fmt.Errorf("certificate version must be >= 1, got %d", rec.Version)
	}
	var keyID any
	if rec.KeyID != uuid.Nil {
		keyID = rec.KeyID.String()
	}
	_, err := ex.ExecContext(ctx,
		"INSERT INTO certificate_versions (certificate_id, version, certificate, private_key, key_id, created_at, expires_at, not_before, enabled) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
		rec.CertificateID.String(), rec.Version, rec.Certificate, rec.PrivateKey, keyID,
		rec.CreatedAt, rec.ExpiresAt, rec.NotBefore, rec.Enabled,
	)
	if err != nil {
		if r.db.Dialect().IsConstraintErr(err) {
			return fmt.Errorf("certificate %s version %d is already archived: %w", rec.CertificateID, rec.Version, ErrCertificateVersionConflict)
		}
		return fmt.Errorf("failed to insert certificate version: %w", err)
	}
	return nil
}

// scanCertificateVersion scans one row of certificateVersionMetadataColumns.
func scanCertificateVersion(certID uuid.UUID, scan func(dest ...any) error) (model.CertificateVersion, error) {
	v := model.CertificateVersion{CertificateID: certID}
	err := scan(&v.Version, &v.CreatedAt, &v.ExpiresAt, &v.NotBefore, &v.Enabled)
	return v, err
}

// ListVersions returns the archived versions' metadata, oldest first.
func (r *CertificateVersionRepository) ListVersions(ctx context.Context, certID uuid.UUID) ([]model.CertificateVersion, error) {
	var versions []model.CertificateVersion
	err := r.executeWithMetrics("list_certificate_versions", func() error {
		rows, err := r.db.QueryContext(ctx,
			"SELECT "+certificateVersionMetadataColumns+" FROM certificate_versions WHERE certificate_id = ? ORDER BY version ASC",
			certID.String())
		if err != nil {
			return fmt.Errorf("failed to query certificate versions: %w", err)
		}
		defer rows.Close() //nolint:errcheck

		for rows.Next() {
			v, scanErr := scanCertificateVersion(certID, rows.Scan)
			if scanErr != nil {
				return fmt.Errorf("failed to scan certificate version: %w", scanErr)
			}
			versions = append(versions, v)
		}
		return rows.Err()
	})
	return versions, err
}

// GetVersion returns one archived version's metadata.
func (r *CertificateVersionRepository) GetVersion(ctx context.Context, certID uuid.UUID, version int) (*model.CertificateVersion, error) {
	if version < 1 {
		return nil, fmt.Errorf("%w: version must be >= 1", ErrCertificateVersionNotFound)
	}
	var out *model.CertificateVersion
	err := r.executeWithMetrics("get_certificate_version", func() error {
		row := r.db.QueryRowContext(ctx,
			"SELECT "+certificateVersionMetadataColumns+" FROM certificate_versions WHERE certificate_id = ? AND version = ?",
			certID.String(), version)
		v, scanErr := scanCertificateVersion(certID, row.Scan)
		if errors.Is(scanErr, sql.ErrNoRows) {
			return fmt.Errorf("%w: certificate %s has no archived version %d", ErrCertificateVersionNotFound, certID, version)
		}
		if scanErr != nil {
			return fmt.Errorf("failed to query certificate version: %w", scanErr)
		}
		out = &v
		return nil
	})
	return out, err
}

// ListVersionRecords returns the archived versions with material, oldest first.
func (r *CertificateVersionRepository) ListVersionRecords(ctx context.Context, certID uuid.UUID) ([]model.CertificateVersionRecord, error) {
	var records []model.CertificateVersionRecord
	err := r.executeWithMetrics("list_certificate_version_records", func() error {
		rows, err := r.db.QueryContext(ctx,
			"SELECT "+certificateVersionRecordColumns+" FROM certificate_versions WHERE certificate_id = ? ORDER BY version ASC",
			certID.String())
		if err != nil {
			return fmt.Errorf("failed to query certificate version records: %w", err)
		}
		defer rows.Close() //nolint:errcheck

		for rows.Next() {
			rec := model.CertificateVersionRecord{CertificateID: certID}
			var keyID sql.NullString
			if err := rows.Scan(&rec.Version, &rec.Certificate, &rec.PrivateKey, &keyID,
				&rec.CreatedAt, &rec.ExpiresAt, &rec.NotBefore, &rec.Enabled); err != nil {
				return fmt.Errorf("failed to scan certificate version record: %w", err)
			}
			if keyID.Valid && keyID.String != "" {
				parsed, parseErr := uuid.Parse(keyID.String)
				if parseErr != nil {
					return fmt.Errorf("failed to parse certificate version key ID: %w", parseErr)
				}
				rec.KeyID = parsed
			}
			records = append(records, rec)
		}
		return rows.Err()
	})
	return records, err
}

// UpdateVersionLifecycle sets one archived version's lifecycle attributes.
func (r *CertificateVersionRepository) UpdateVersionLifecycle(ctx context.Context, certID uuid.UUID, version int, attrs model.CertificateVersionAttributes) error {
	return r.executeWithMetrics("update_certificate_version", func() error {
		result, err := r.db.ExecContext(ctx,
			"UPDATE certificate_versions SET enabled = ?, expires_at = ?, not_before = ? WHERE certificate_id = ? AND version = ?",
			attrs.Enabled, attrs.ExpiresAt, attrs.NotBefore, certID.String(), version)
		if err != nil {
			return fmt.Errorf("failed to update certificate version: %w", err)
		}
		affected, err := result.RowsAffected()
		if err != nil {
			return fmt.Errorf("failed to get rows affected: %w", err)
		}
		if affected == 0 {
			return fmt.Errorf("%w: certificate %s has no archived version %d", ErrCertificateVersionNotFound, certID, version)
		}
		return nil
	})
}

// UpdateCurrentLifecycle sets the lifecycle attributes on the certificates
// row while it is still at version. A renewal that committed in between
// moves the row on, and the update then matches nothing and conflicts.
func (r *CertificateVersionRepository) UpdateCurrentLifecycle(ctx context.Context, certID uuid.UUID, version int, attrs model.CertificateVersionAttributes, scope model.Scope) error {
	return r.executeWithMetrics("update_current_certificate_version", func() error {
		result, err := ScopedExec(ctx, r.db,
			"UPDATE certificates SET enabled = ?, expires_at = ?, not_before = ? WHERE id = ? AND version = ? AND deleted_at IS NULL",
			[]any{attrs.Enabled, attrs.ExpiresAt, attrs.NotBefore, certID.String(), version},
			scope)
		if err != nil {
			if errors.Is(err, ErrInvalidScope) {
				return err
			}
			return fmt.Errorf("failed to update certificate lifecycle: %w", err)
		}
		affected, err := result.RowsAffected()
		if err != nil {
			return fmt.Errorf("failed to get rows affected: %w", err)
		}
		if affected == 0 {
			return fmt.Errorf("certificate %s is no longer at version %d: %w", certID, version, ErrCertificateVersionConflict)
		}
		return nil
	})
}
