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

// CertificateRepositoryInterface defines the interface for certificate repository operations.
// It provides type-safe CRUD operations for the Certificate type.
type CertificateRepositoryInterface interface {
	Create(ctx context.Context, cert *model.Certificate) error
	// Read fetches a certificate authorized by scope. The scoped read is the
	// access check: a row outside the scope is indistinguishable from a row
	// that does not exist.
	Read(ctx context.Context, id uuid.UUID, scope model.Scope) (*model.Certificate, error)
	// Update updates a certificate authorized by scope. The predicate comes
	// from the scope argument, never from the entity.
	Update(ctx context.Context, cert *model.Certificate, scope model.Scope) error
	// List lists certificates authorized by scope and narrowed by filter.
	List(ctx context.Context, scope model.Scope, filter CertificateFilter) ([]model.Certificate, error)
	// ListDueForRenewal returns certificates in scope's vault whose
	// auto-renewal window has been entered: AutoRenew is set, ExpiresAt is
	// set and still in the future, and days-until-expiry is at or below
	// RenewalDays (defaulting to 30 when RenewalDays is unset or
	// non-positive). This mirrors exactly the condition
	// CertificateRenewalService.CheckAndRenewCertificates itself acts on,
	// reading straight off this table's own columns -- not
	// model.CertificatePolicy's separate, disconnected AutoRenew and
	// DaysBeforeExpiry fields.
	ListDueForRenewal(ctx context.Context, scope model.Scope) ([]model.Certificate, error)
	Delete(ctx context.Context, id uuid.UUID) error
	Revoke(ctx context.Context, id uuid.UUID, serialNumber, name string) error
	ListRevoked(ctx context.Context, userID uuid.UUID) ([]model.RevokedCertificate, error)
	SoftDelete(ctx context.Context, id uuid.UUID) error
	RecoverCertificate(ctx context.Context, id uuid.UUID) error
	PurgeCertificate(ctx context.Context, id uuid.UUID) error
	SetPurgeProtection(ctx context.Context, id uuid.UUID, enabled bool) error
	ListAll(ctx context.Context) ([]model.Certificate, error)
	// SoftDeleteVaultContents soft-deletes every active certificate in a vault.
	SoftDeleteVaultContents(ctx context.Context, vaultID uuid.UUID, deletedAt time.Time) error
	// RecoverVaultContents recovers only the certificates the cascade soft-deleted at deletedAt.
	RecoverVaultContents(ctx context.Context, vaultID uuid.UUID, deletedAt time.Time) error
}

// CertificateFilter narrows a scoped certificate listing. Alias for
// model.CertificateFilter: the canonical definition lives in model/ so api/
// and cmd/ can construct one without importing this package.
type CertificateFilter = model.CertificateFilter

// certificateColumns is the canonical SELECT list for every certificates read
// in this file, ListAll included. It is the ONLY one: a new column goes here
// and into scanCertificateRow, never into a second hand-written list.
//
// This file has grown a competing list twice, and both times the drift was
// silent -- the omitted fields simply read back as their zero values, so
// nothing failed until someone depended on one. TestCertificateSelectListIsNotDuplicated
// now fails the build if a third one appears.
const certificateColumns = "id, user_id, vault_id, name, certificate, private_key, created_at, expires_at, auto_renew, renewal_days, key_id, ca_cert_id, enabled, not_before, deleted_at, purge_protection, version"

// scanCertificateRow scans one certificates row in the canonical column order.
func scanCertificateRow(scan func(dest ...any) error) (model.Certificate, error) {
	var cert model.Certificate
	var idStr, userIDStr, vaultIDStr string
	var keyIDStr, caCertIDStr sql.NullString

	if err := scan(&idStr, &userIDStr, &vaultIDStr, &cert.Name, &cert.Certificate, &cert.PrivateKey,
		&cert.CreatedAt, &cert.ExpiresAt, &cert.AutoRenew, &cert.RenewalDays, &keyIDStr, &caCertIDStr,
		&cert.Enabled, &cert.NotBefore, &cert.DeletedAt, &cert.PurgeProtection, &cert.Version); err != nil {
		return cert, err
	}

	var err error
	if cert.ID, err = uuid.Parse(idStr); err != nil {
		return cert, fmt.Errorf("failed to parse certificate ID: %w", err)
	}
	if cert.UserID, err = uuid.Parse(userIDStr); err != nil {
		return cert, fmt.Errorf("failed to parse user ID: %w", err)
	}
	if cert.VaultID, err = uuid.Parse(vaultIDStr); err != nil {
		return cert, fmt.Errorf("failed to parse vault ID: %w", err)
	}
	if keyIDStr.Valid && keyIDStr.String != "" {
		if cert.KeyID, err = uuid.Parse(keyIDStr.String); err != nil {
			return cert, fmt.Errorf("failed to parse key ID: %w", err)
		}
	}
	// A NULL or empty ca_cert_id means self-signed, which stays nil rather
	// than becoming a zero UUID that later reads as a real CA.
	if caCertIDStr.Valid && caCertIDStr.String != "" {
		caCertID, parseErr := uuid.Parse(caCertIDStr.String)
		if parseErr != nil {
			return cert, fmt.Errorf("failed to parse CA certificate ID: %w", parseErr)
		}
		cert.CACertID = &caCertID
	}
	return cert, nil
}

// Read retrieves a certificate by ID, authorized by scope.
func (r *CertificateRepository) Read(ctx context.Context, id uuid.UUID, scope model.Scope) (*model.Certificate, error) {
	query := "SELECT " + certificateColumns + " FROM certificates WHERE id = ? AND deleted_at IS NULL"
	cert, err := ScopedGet(ctx, r.db, query, []any{id.String()}, scope, func(row *sql.Row) (model.Certificate, error) {
		return scanCertificateRow(row.Scan)
	})
	switch {
	case errors.Is(err, ErrInvalidScope):
		return nil, err
	case errors.Is(err, sql.ErrNoRows):
		if scope.Kind() == model.ScopeAdmin {
			return nil, fmt.Errorf("certificate not found")
		}
		return nil, fmt.Errorf("certificate not found or access denied")
	case err != nil:
		return nil, fmt.Errorf("failed to query certificate: %w", err)
	}

	tagRepo := db.NewTagRepository[model.Certificate](r.db, "certificate_tags", "certificate_id")
	cert.Tags, err = tagRepo.GetTags(ctx, cert.ID)
	if err != nil {
		return nil, fmt.Errorf("failed to read tags: %w", err)
	}
	return &cert, nil
}

// Update updates a certificate, authorized by scope. The predicate is
// built from the scope argument, never from the entity.
//
// This method does not emit audit rows: audit attribution belongs to the
// caller (service layer), which knows the acting principal from the request.
// UpdateCertificate already logs its own audit row after calling this,
// for every error path and on success — logging here too would duplicate
// every scoped update into two audit_logs rows.
func (r *CertificateRepository) Update(ctx context.Context, cert *model.Certificate, scope model.Scope) error {
	return r.executeWithMetrics("update_certificate_scoped", func() error {
		tx, txErr := r.db.BeginTx(ctx, nil)
		if txErr != nil {
			return fmt.Errorf("failed to begin transaction: %w", txErr)
		}
		defer tx.Rollback() //nolint:errcheck

		// Only metadata is written here: the body, the private key and
		// created_at/expires_at belong to a version and change only through
		// CertificateVersionRepository.ArchiveAndRenew. enabled and not_before
		// stay user-settable, but a renewal rewrites them too, so the UPDATE is
		// guarded by the version the caller read. A write built from a read
		// taken before a concurrent renewal matches no row and reports
		// ErrCertificateVersionConflict instead of reverting the new version.
		// ca_cert_id is deliberately absent too: the CA link is set at
		// creation and immutable afterwards (B37).
		query := "UPDATE certificates SET name = ?, auto_renew = ?, renewal_days = ?, enabled = ?, not_before = ? WHERE id = ? AND version = ?"
		execArgs := []any{
			cert.Name, cert.AutoRenew, cert.RenewalDays, cert.Enabled, cert.NotBefore, cert.ID.String(), cert.CurrentVersion(),
		}

		result, execErr := ScopedExec(ctx, tx, query, execArgs, scope)
		if execErr != nil {
			if errors.Is(execErr, ErrInvalidScope) {
				return execErr
			}
			return fmt.Errorf("failed to update certificate: %w", execErr)
		}

		rowsAffected, rowsErr := result.RowsAffected()
		if rowsErr != nil {
			return fmt.Errorf("failed to get rows affected: %w", rowsErr)
		}
		if rowsAffected == 0 {
			// Tell a lost renewal race apart from a missing row. The probe is
			// scoped, so an out-of-scope row still reads as not found.
			current, probeErr := ScopedGet(ctx, tx, "SELECT version FROM certificates WHERE id = ? AND deleted_at IS NULL",
				[]any{cert.ID.String()}, scope, func(row *sql.Row) (int, error) {
					var v int
					return v, row.Scan(&v)
				})
			if probeErr == nil && current != cert.CurrentVersion() {
				return fmt.Errorf("certificate %s is no longer at version %d: %w", cert.ID, cert.CurrentVersion(), ErrCertificateVersionConflict)
			}
			return fmt.Errorf("certificate not found")
		}

		// Replace the tag set inside the outer transaction. The inserts run on
		// tx directly, the way Create's tag insertion already does, rather than
		// through a TagRepository built on r.db: that would open a second
		// transaction on a separate connection while this one still holds the
		// write lock (a SQLITE_BUSY risk), and its inserts would survive a
		// rollback of the certificate row they belong to.
		if len(cert.Tags) > 0 {
			if _, delErr := tx.ExecContext(ctx, "DELETE FROM certificate_tags WHERE certificate_id = ?", cert.ID.String()); delErr != nil {
				return fmt.Errorf("failed to delete existing tags: %w", delErr)
			}
			for _, tag := range cert.Tags {
				if _, tagErr := tx.ExecContext(ctx,
					"INSERT INTO certificate_tags (certificate_id, tag) VALUES (?, ?)",
					cert.ID.String(), tag,
				); tagErr != nil {
					return fmt.Errorf("failed to add tags: %w", tagErr)
				}
			}
		}

		if commitErr := tx.Commit(); commitErr != nil {
			return fmt.Errorf("failed to commit transaction: %w", commitErr)
		}

		logrus.WithFields(logrus.Fields{
			"certificate_id": cert.ID.String(),
			"scope":          scope.String(),
		}).Debug("Certificate updated successfully")
		return nil
	})
}

// List lists certificates authorized by scope and narrowed by filter.
func (r *CertificateRepository) List(ctx context.Context, scope model.Scope, filter CertificateFilter) ([]model.Certificate, error) {
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
	if len(filter.Tags) > 0 {
		placeholders := strings.Repeat(",?", len(filter.Tags))[1:]
		conditions = append(conditions, fmt.Sprintf("id IN (SELECT certificate_id FROM certificate_tags WHERE tag IN (%s))", placeholders))
		for _, tag := range filter.Tags {
			args = append(args, tag)
		}
	}

	query := "SELECT " + certificateColumns + " FROM certificates WHERE " + strings.Join(conditions, " AND ")

	tail := " ORDER BY created_at DESC, id ASC"
	var tailArgs []any
	if filter.Limit > 0 {
		tail += " LIMIT ? OFFSET ?"
		tailArgs = []any{filter.Limit, filter.Offset}
	}

	var certList []model.Certificate
	err := r.executeWithMetrics("list_certificates_scoped", func() error {
		var listErr error
		certList, listErr = ScopedList(ctx, r.db, query, args, scope, tail, tailArgs, func(rows *sql.Rows) (model.Certificate, error) {
			return scanCertificateRow(rows.Scan)
		})
		if listErr != nil {
			return listErr
		}

		// Batch-fetch tags for every returned certificate in one query instead
		// of one GetTags query per row.
		ids := make([]uuid.UUID, len(certList))
		for i, cert := range certList {
			ids[i] = cert.ID
		}
		tagRepo := db.NewTagRepository[model.Certificate](r.db, "certificate_tags", "certificate_id")
		tagsByID, tagErr := tagRepo.GetTagsForMany(ctx, ids)
		if tagErr != nil {
			return fmt.Errorf("failed to read tags for certificates: %w", tagErr)
		}
		for i := range certList {
			certList[i].Tags = tagsByID[certList[i].ID]
		}
		return nil
	})
	if err != nil {
		if errors.Is(err, ErrInvalidScope) {
			return nil, err
		}
		return nil, fmt.Errorf("failed to query certificates: %w", err)
	}

	logrus.WithField("count", len(certList)).Debug("Certificates listed successfully")
	return certList, nil
}

// ListDueForRenewal returns certificates in scope's vault whose auto-renewal
// window has been entered. Filtering happens in Go over List's own scoped,
// non-deleted results rather than in SQL, applying the identical condition
// CheckAndRenewCertificates applies over ListAll's results, so this can never
// drift from what the scheduler itself actually acts on.
func (r *CertificateRepository) ListDueForRenewal(ctx context.Context, scope model.Scope) ([]model.Certificate, error) {
	certs, err := r.List(ctx, scope, CertificateFilter{})
	if err != nil {
		return nil, fmt.Errorf("failed to list certificates for renewal check: %w", err)
	}

	now := time.Now()
	due := make([]model.Certificate, 0, len(certs))
	for _, cert := range certs {
		if !cert.AutoRenew || cert.ExpiresAt == nil {
			continue
		}
		if cert.ExpiresAt.Before(now) {
			continue // Already expired; the scheduler skips these too.
		}
		renewalDays := cert.RenewalDays
		if renewalDays <= 0 {
			renewalDays = 30
		}
		daysUntilExpiry := int(cert.ExpiresAt.Sub(now).Hours() / 24)
		if daysUntilExpiry > renewalDays {
			continue
		}
		due = append(due, cert)
	}
	return due, nil
}

// CertificateRepository implements CertificateRepositoryInterface with pure CRUD operations.
// It focuses solely on database interactions without business logic like X.509 generation or encryption.
// All crypto operations (encryption, certificate generation) are handled by the service layer.
type CertificateRepository struct {
	db  db.DB
	log *logging.Logger
}

// crud returns the itemLifecycleConfig for certificates.
func (r *CertificateRepository) crud() itemLifecycleConfig {
	return itemLifecycleConfig{
		table:              "certificates",
		item:               "certificate",
		itemCap:            "Certificate",
		idField:            "cert_id",
		tagTable:           "certificate_tags",
		tagFK:              "certificate_id",
		versionTable:       "certificate_versions",
		versionFK:          "certificate_id",
		auditActor:         uuid.Nil.String(),
		purgeErr:           ErrCertPurgeProtected,
		notFoundIsSentinel: false,
		log:                r.log,
		wrap:               r.executeWithMetrics,
	}
}

// executeWithMetrics wraps database operations with performance monitoring.
// See KeyRepository.executeWithMetrics for why this stays a method.
func (r *CertificateRepository) executeWithMetrics(operation string, fn func() error) error {
	return withMetrics("certificates", operation, fn)
}

// NewCertificateRepository creates a new CertificateRepository instance.
// It provides pure database operations for certificate entities.
//
// Parameters:
//   - db: The database connection.
//   - log: The logger for database operation logging.
//
// Returns:
//
//	A CertificateRepositoryInterface implementation for certificate database operations.
func NewCertificateRepository(db db.DB, log *logging.Logger) CertificateRepositoryInterface {
	return &CertificateRepository{db: db, log: log}
}

// Create inserts a new certificate into the database.
// It expects the certificate PEM and private key to be already generated and encrypted.
// NO X.509 generation or encryption happens here - pure data access only.
//
// Parameters:
//   - ctx: The context for the database operation.
//   - cert: The certificate entity to store (with pre-generated cert PEM and encrypted private key).
//
// Returns:
//
//	An error if the insertion fails.
func (r *CertificateRepository) Create(ctx context.Context, cert *model.Certificate) error {
	return r.executeWithMetrics("create_certificate", func() error {
		logrus.WithFields(logrus.Fields{
			"cert_id": cert.ID.String(),
			"user_id": cert.UserID.String(),
			"name":    cert.Name,
		}).Debug("Inserting certificate into database")

		tx, err := r.db.BeginTx(ctx, nil)
		if err != nil {
			r.log.LogAuditError(cert.UserID.String(), "create_certificate", "failed", "Failed to begin transaction", err)
			return fmt.Errorf("failed to begin transaction: %w", err)
		}
		defer tx.Rollback() //nolint:errcheck

		if err := r.insertCertAndTags(ctx, tx, cert); err != nil {
			return err
		}

		if err := tx.Commit(); err != nil {
			r.log.LogAuditError(cert.UserID.String(), "create_certificate", "failed", "Failed to commit transaction", err)
			return fmt.Errorf("failed to commit transaction: %w", err)
		}

		r.log.LogAuditInfo(cert.UserID.String(), "create_certificate", "success", fmt.Sprintf("Certificate created: %s", cert.Name))
		logrus.WithFields(logrus.Fields{
			"cert_id": cert.ID.String(),
			"user_id": cert.UserID.String(),
			"name":    cert.Name,
		}).Debug("Certificate inserted successfully")

		return nil
	})
}

// CreateTx is Create's Tx-scoped variant. Unlike Create, it does not open
// its own transaction: ex is expected to already be a transaction the
// caller (ItemBackupService, for an atomic restore, F3) owns and will
// commit or roll back.
func (r *CertificateRepository) CreateTx(ctx context.Context, ex db.DBTX, cert *model.Certificate) error {
	return r.executeWithMetrics("create_certificate", func() error {
		if err := r.insertCertAndTags(ctx, ex, cert); err != nil {
			return err
		}
		r.log.LogAuditInfo(cert.UserID.String(), "create_certificate", "success", fmt.Sprintf("Certificate created: %s", cert.Name))
		return nil
	})
}

// insertCertAndTags issues the certificate row insert and its tag inserts
// against ex. Shared by Create (ex is a transaction it began and owns) and
// CreateTx (ex is a transaction an outer caller began and owns).
func (r *CertificateRepository) insertCertAndTags(ctx context.Context, ex db.DBTX, cert *model.Certificate) error {
	// ca_cert_id is NULL for a self-signed certificate.
	var caCertID any
	if cert.CACertID != nil {
		caCertID = cert.CACertID.String()
	}

	// Insert certificate with pre-encrypted private key and renewal metadata.
	// version is the row's current version: 1 on create, the blob's own
	// number on restore.
	_, err := ex.ExecContext(
		ctx,
		"INSERT INTO certificates (id, user_id, vault_id, name, certificate, private_key, created_at, expires_at, auto_renew, renewal_days, key_id, ca_cert_id, enabled, not_before, version) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
		cert.ID.String(), cert.UserID.String(), cert.VaultID.String(), cert.Name, cert.Certificate, cert.PrivateKey, cert.CreatedAt,
		cert.ExpiresAt, cert.AutoRenew, cert.RenewalDays, cert.KeyID.String(), caCertID, cert.Enabled, cert.NotBefore, cert.CurrentVersion(),
	)
	if err != nil {
		if db.SQLite.IsConstraintErr(err) {
			r.log.LogAuditError(cert.UserID.String(), "create_certificate", "failed", fmt.Sprintf("Certificate name already taken: %s", cert.Name), err)
			return fmt.Errorf("certificate %q: %w: %w", cert.Name, ErrNameTaken, err)
		}
		r.log.LogAuditError(cert.UserID.String(), "create_certificate", "failed", "Failed to insert certificate", err)
		return fmt.Errorf("failed to insert certificate: %w", err)
	}

	// Insert tags if provided (using the same transaction to avoid locks).
	for _, tag := range cert.Tags {
		_, err := ex.ExecContext(ctx,
			"INSERT INTO certificate_tags (certificate_id, tag) VALUES (?, ?)",
			cert.ID.String(), tag,
		)
		if err != nil {
			r.log.LogAuditError(cert.UserID.String(), "create_certificate", "failed", fmt.Sprintf("Failed to insert tag %s", tag), err)
			return fmt.Errorf("failed to insert tag %s: %w", tag, err)
		}
	}
	return nil
}

// Delete removes a certificate from the database.
// It removes the certificate, its private key, and associated tags within a transaction.
//
// Parameters:
//   - ctx: The context for the database operation.
//   - id: The certificate's unique identifier.
//
// Returns:
//
//	An error if the deletion fails.
func (r *CertificateRepository) Delete(ctx context.Context, id uuid.UUID) error {
	return deleteItemWithTags(ctx, r.db, r.crud(), id)
}

// Revoke adds a certificate to the CRL (Certificate Revocation List).
// It marks the certificate as revoked in the database.
//
// Parameters:
//   - ctx: The context for the database operation.
//   - id: The certificate's ID.
//   - serialNumber: The certificate's serial number.
//   - name: The certificate's common name.
//
// Returns:
//
//	An error if revocation fails.
func (r *CertificateRepository) Revoke(ctx context.Context, id uuid.UUID, serialNumber, name string) error {
	return r.executeWithMetrics("revoke_certificate", func() error {
		// Read certificate to get user ID
		cert, err := r.Read(ctx, id, model.NewAdminScope(uuid.Nil))
		if err != nil {
			return fmt.Errorf("failed to read certificate: %w", err)
		}

		_, err = r.db.ExecContext(
			ctx,
			"INSERT INTO crl (id, user_id, serial_number, name, revoked_at) VALUES (?, ?, ?, ?, ?)",
			uuid.New().String(), cert.UserID.String(), serialNumber, name, time.Now(),
		)
		if err != nil {
			r.log.LogAuditError(cert.UserID.String(), "revoke_certificate", "failed", "Failed to insert into CRL", err)
			return fmt.Errorf("failed to revoke certificate: %w", err)
		}

		r.log.LogAuditInfo(cert.UserID.String(), "revoke_certificate", "success", fmt.Sprintf("Certificate revoked: %s", name))
		logrus.WithFields(logrus.Fields{
			"cert_id":       id.String(),
			"serial_number": serialNumber,
			"name":          name,
		}).Debug("Certificate revoked successfully")

		return nil
	})
}

// ListRevoked retrieves all revoked certificates for a user from the CRL.
//
// Parameters:
//   - ctx: The context for the database operation.
//   - userID: The user's ID.
//
// Returns:
//
//	A list of revoked certificates or an error if retrieval fails.
func (r *CertificateRepository) ListRevoked(ctx context.Context, userID uuid.UUID) ([]model.RevokedCertificate, error) {
	var revokedList []model.RevokedCertificate

	err := r.executeWithMetrics("list_revoked_certificates", func() error {
		rows, err := r.db.QueryContext(
			ctx,
			"SELECT id, user_id, serial_number, name, revoked_at FROM crl WHERE user_id = ? ORDER BY revoked_at DESC",
			userID.String(),
		)
		if err != nil {
			r.log.LogAuditError(userID.String(), "list_revoked_certificates", "failed", "Failed to query revoked certificates", err)
			return fmt.Errorf("failed to query revoked certificates: %w", err)
		}
		defer rows.Close() //nolint:errcheck

		// Pre-allocate slice
		revokedList = make([]model.RevokedCertificate, 0, 20)

		for rows.Next() {
			var cert model.RevokedCertificate
			var idStr, userIDStr string

			if err := rows.Scan(&idStr, &userIDStr, &cert.SerialNumber, &cert.Name, &cert.RevokedAt); err != nil {
				r.log.LogAuditError(userID.String(), "list_revoked_certificates", "failed", "Failed to scan revoked certificate", err)
				return fmt.Errorf("failed to scan revoked certificate: %w", err)
			}

			cert.ID, err = uuid.Parse(idStr)
			if err != nil {
				return fmt.Errorf("failed to parse revoked certificate ID: %w", err)
			}

			cert.UserID, err = uuid.Parse(userIDStr)
			if err != nil {
				return fmt.Errorf("failed to parse user ID: %w", err)
			}

			revokedList = append(revokedList, cert)
		}

		if err := rows.Err(); err != nil {
			return fmt.Errorf("row iteration error: %w", err)
		}

		return nil
	})
	if err != nil {
		return nil, err
	}

	logrus.WithFields(logrus.Fields{
		"user_id": userID.String(),
		"count":   len(revokedList),
	}).Debug("Revoked certificates listed successfully")

	return revokedList, nil
}

// SoftDelete marks a certificate as deleted without removing it from the database.
// The certificate is excluded from normal reads but remains available for recovery.
//
// Parameters:
//   - ctx: The context for the database operation.
//   - id: The certificate's unique identifier.
//
// Returns:
//
//	An error if the soft deletion fails.
func (r *CertificateRepository) SoftDelete(ctx context.Context, id uuid.UUID) error {
	return softDeleteItem(ctx, r.db, r.crud(), id)
}

// RecoverCertificate restores a soft-deleted certificate by clearing its deleted_at timestamp.
//
// Parameters:
//   - ctx: The context for the database operation.
//   - id: The certificate's unique identifier.
//
// Returns:
//
//	An error if the certificate is not found in a deleted state or the update fails.
func (r *CertificateRepository) RecoverCertificate(ctx context.Context, id uuid.UUID) error {
	return recoverItem(ctx, r.db, r.crud(), id)
}

// PurgeCertificate permanently removes a soft-deleted certificate from the database.
// It fails if the certificate has purge protection enabled.
//
// Parameters:
//   - ctx: The context for the database operation.
//   - id: The certificate's unique identifier.
//
// Returns:
//
//	An error if the purge operation fails or purge protection is enabled.
func (r *CertificateRepository) PurgeCertificate(ctx context.Context, id uuid.UUID) error {
	return purgeItem(ctx, r.db, r.crud(), id)
}

// SetPurgeProtection enables or disables purge protection on a certificate.
// A certificate with purge protection cannot be permanently deleted via PurgeCertificate.
//
// Parameters:
//   - ctx: The context for the database operation.
//   - id: The certificate's unique identifier.
//   - enabled: True to enable purge protection, false to disable it.
//
// Returns:
//
//	An error if the update fails.
func (r *CertificateRepository) SetPurgeProtection(ctx context.Context, id uuid.UUID, enabled bool) error {
	return r.setPurgeProtection(ctx, r.db, id, enabled)
}

// SetPurgeProtectionTx is SetPurgeProtection's Tx-scoped variant. See
// CreateTx.
func (r *CertificateRepository) SetPurgeProtectionTx(ctx context.Context, ex db.DBTX, id uuid.UUID, enabled bool) error {
	return r.setPurgeProtection(ctx, ex, id, enabled)
}

func (r *CertificateRepository) setPurgeProtection(ctx context.Context, ex db.DBTX, id uuid.UUID, enabled bool) error {
	return setPurgeProtectionItem(ctx, ex, r.crud(), id, enabled)
}

// ListAll returns all non-deleted certificates across all users.
// It is used by the renewal scheduler to find certificates that need renewal.
//
// Parameters:
//   - ctx: The context for the database operation.
//
// Returns:
//
//	A slice of all active certificates, or an error if retrieval fails.
func (r *CertificateRepository) ListAll(ctx context.Context) ([]model.Certificate, error) {
	var certs []model.Certificate

	err := r.executeWithMetrics("list_all_certificates", func() error {
		// Reads through the shared certificateColumns/scanCertificateRow pair
		// rather than a second hand-written SELECT list. The previous literal
		// omitted vault_id, deleted_at and purge_protection, and parsed IDs
		// with an unchecked Must-style parse -- a corrupt column panicked the
		// renewal scheduler's goroutine instead of returning an error.
		rows, err := r.db.QueryContext(ctx,
			"SELECT "+certificateColumns+" FROM certificates WHERE deleted_at IS NULL")
		if err != nil {
			return fmt.Errorf("failed to list all certificates: %w", err)
		}
		defer rows.Close() //nolint:errcheck

		for rows.Next() {
			cert, scanErr := scanCertificateRow(rows.Scan)
			if scanErr != nil {
				return scanErr
			}
			certs = append(certs, cert)
		}

		return rows.Err()
	})

	return certs, err
}

// SoftDeleteVaultContents marks every active certificate in a vault as soft-deleted.
//
// Parameters:
//   - ctx: The context for the database operation.
//   - vaultID: The vault whose certificates should be soft-deleted.
//   - deletedAt: The exact deletion timestamp to stamp on each cascaded row.
//
// Returns:
//
//	An error if the soft deletion fails.
func (r *CertificateRepository) SoftDeleteVaultContents(ctx context.Context, vaultID uuid.UUID, deletedAt time.Time) error {
	return softDeleteVaultContents(ctx, r.db, r.crud(), vaultID, deletedAt)
}

// SoftDeleteVaultContentsTx is SoftDeleteVaultContents scoped to an explicit executor.
func (r *CertificateRepository) SoftDeleteVaultContentsTx(ctx context.Context, ex db.DBTX, vaultID uuid.UUID, deletedAt time.Time) error {
	return softDeleteVaultContents(ctx, ex, r.crud(), vaultID, deletedAt)
}

// RecoverVaultContents restores every soft-deleted certificate in a vault.
//
// Parameters:
//   - ctx: The context for the database operation.
//   - vaultID: The vault whose certificates should be recovered.
//   - deletedAt: The cascade deletion timestamp; only rows stamped with it are restored.
//
// Returns:
//
//	An error if the recovery fails.
func (r *CertificateRepository) RecoverVaultContents(ctx context.Context, vaultID uuid.UUID, deletedAt time.Time) error {
	return recoverVaultContents(ctx, r.db, r.crud(), vaultID, deletedAt)
}

// RecoverVaultContentsTx is RecoverVaultContents scoped to an explicit executor.
func (r *CertificateRepository) RecoverVaultContentsTx(ctx context.Context, ex db.DBTX, vaultID uuid.UUID, deletedAt time.Time) error {
	return recoverVaultContents(ctx, ex, r.crud(), vaultID, deletedAt)
}

// PurgeVaultContents permanently deletes every certificate in a vault,
// regardless of soft-delete state. certificates.vault_id carries no foreign
// key to vaults(id) (unlike role_assignments.vault_id, which cascades), so
// without this call a vault purge would strand every certificate it ever
// contained as an orphaned row, unreachable through any route and never
// swept by the soft-delete purge scheduler (which only purges
// individually-deleted items, not vault orphans). Mirrors the unconditional
// DELETE the vault service already issues for access_policies on purge, for
// the same reason.
func (r *CertificateRepository) PurgeVaultContents(ctx context.Context, vaultID uuid.UUID) error {
	return purgeVaultContents(ctx, r.db, r.crud(), vaultID)
}

// HasProtectedContent reports whether any certificate in the vault, active
// or soft-deleted, has purge_protection enabled. Consumed by the vault
// service's cascade purge-protection check (see vaults.CascadeRepository) so
// purging a vault can't bypass an individual certificate's own protection.
func (r *CertificateRepository) HasProtectedContent(ctx context.Context, vaultID uuid.UUID) (bool, error) {
	return hasProtectedContent(ctx, r.db, r.crud(), vaultID)
}
