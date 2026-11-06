package repositories

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"rocketvault/internal/db"
	"rocketvault/model"

	"github.com/google/uuid"
)

// AuditLog is a single enriched audit event read from the database. Alias for
// model.AuditLog: the canonical definition lives in model/ so api/ and cmd/
// can name one without importing this package.
type AuditLog = model.AuditLog

// AuditFilter specifies query constraints for QueryAuditLogs. Alias for
// model.AuditFilter: the canonical definition lives in model/ so api/ and
// cmd/ can construct one without importing this package.
// Nil pointer fields are ignored (not filtered).
type AuditFilter = model.AuditFilter

// AuditRepositoryInterface is the contract for persisting audit log records.
// It satisfies logging.AuditPersister so the logger can write to the DB.
type AuditRepositoryInterface interface {
	PersistAudit(userID, action, details string) error
}

// AuditRepositoryExtended adds the read-side and enriched-write methods needed
// by the audit service layer.
type AuditRepositoryExtended interface {
	AuditRepositoryInterface
	InsertAuditLog(ctx context.Context, entry AuditLog) error
	AppendChained(ctx context.Context, build func(nextSeq int64, prevHash string, now time.Time) AuditLog) error
	QueryAuditLogs(ctx context.Context, filter AuditFilter) ([]AuditLog, int64, error)
	DeleteBefore(ctx context.Context, cutoff time.Time) (int64, error)
	GetAuditConfig(ctx context.Context, key string) (string, error)
	SetAuditConfig(ctx context.Context, key, value string) error
}

// AuditRepository writes and reads audit records from the audit_logs table.
type AuditRepository struct {
	db db.DB
}

// NewAuditRepository creates an AuditRepository backed by db.
// The returned value implements both AuditRepositoryInterface and
// AuditRepositoryExtended.
func NewAuditRepository(db db.DB) AuditRepositoryExtended {
	return &AuditRepository{db: db}
}

// PersistAudit inserts one row with the legacy (thin) signature.
// An empty userID is stored as an empty string (not NULL) for unauthenticated events.
func (r *AuditRepository) PersistAudit(userID, action, details string) error {
	id := uuid.New().String()
	now := time.Now().UTC()
	_, err := r.db.ExecContext(
		context.Background(),
		`INSERT INTO audit_logs (id, user_id, action, details, timestamp) VALUES (?, ?, ?, ?, ?)`,
		id, userID, action, details, now,
	)
	return err
}

// InsertAuditLog inserts a fully-populated AuditLog row.
func (r *AuditRepository) InsertAuditLog(ctx context.Context, entry AuditLog) error {
	if entry.ID == "" {
		entry.ID = uuid.New().String()
	}
	if entry.Timestamp.IsZero() {
		entry.Timestamp = time.Now().UTC()
	}
	_, err := r.db.ExecContext(
		ctx,
		`INSERT INTO audit_logs
			(id, user_id, action, details, timestamp,
			 resource_type, resource_id, ip_address, outcome, source, prev_hash)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		entry.ID, entry.UserID, entry.Action, entry.Details, entry.Timestamp,
		nullableString(entry.ResourceType), nullableString(entry.ResourceID),
		nullableString(entry.IPAddress), nullableString(entry.Outcome),
		nullableString(entry.Source), nullableString(entry.PrevHash),
	)
	return err
}

// AppendChained appends one hash-chained row in a single transaction.
// It locks the chain head, calls build with the next seq, the previous hash
// and the DB time, inserts the row and advances the head.
func (r *AuditRepository) AppendChained(ctx context.Context, build func(nextSeq int64, prevHash string, now time.Time) AuditLog) error {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("audit append begin: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback()
		}
	}()

	// A no-op update takes the write lock on both engines.
	res, err := tx.ExecContext(ctx, `UPDATE audit_chain_head SET last_seq = last_seq WHERE id = 1`)
	if err != nil {
		return fmt.Errorf("audit head lock: %w", err)
	}
	if n, err := res.RowsAffected(); err != nil {
		return fmt.Errorf("audit head lock: %w", err)
	} else if n == 0 {
		return errors.New("audit head lock: chain head missing")
	}
	var lastSeq int64
	var lastHash string
	if err := tx.QueryRowContext(ctx, `SELECT last_seq, last_hash FROM audit_chain_head WHERE id = 1`).Scan(&lastSeq, &lastHash); err != nil {
		return fmt.Errorf("audit head read: %w", err)
	}

	var now time.Time
	if r.db.Dialect() == db.Postgres {
		if err := tx.QueryRowContext(ctx, `SELECT clock_timestamp()`).Scan(&now); err != nil {
			return fmt.Errorf("audit db time: %w", err)
		}
	} else {
		now = time.Now()
	}
	now = now.UTC().Truncate(time.Microsecond)

	nextSeq := lastSeq + 1
	entry := build(nextSeq, lastHash, now)
	if entry.PrevHash == "" {
		// An empty hash would re-root the chain, so it is never stored.
		return errors.New("audit append: build returned an empty hash")
	}
	entry.Timestamp = now
	if entry.ID == "" {
		entry.ID = uuid.New().String()
	}

	if _, err := tx.ExecContext(
		ctx,
		`INSERT INTO audit_logs
			(id, user_id, action, details, timestamp,
			 resource_type, resource_id, ip_address, outcome, source, prev_hash, seq)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		entry.ID, entry.UserID, entry.Action, entry.Details, entry.Timestamp,
		nullableString(entry.ResourceType), nullableString(entry.ResourceID),
		nullableString(entry.IPAddress), nullableString(entry.Outcome),
		nullableString(entry.Source), nullableString(entry.PrevHash), nextSeq,
	); err != nil {
		return fmt.Errorf("audit insert: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `UPDATE audit_chain_head SET last_seq = ?, last_hash = ? WHERE id = 1`, nextSeq, entry.PrevHash); err != nil {
		return fmt.Errorf("audit head advance: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("audit append commit: %w", err)
	}
	committed = true
	return nil
}

// QueryAuditLogs returns audit log rows matching filter, along with the total
// count of matching rows (before limit).
func (r *AuditRepository) QueryAuditLogs(ctx context.Context, filter AuditFilter) ([]AuditLog, int64, error) {
	limit := filter.Limit
	if limit <= 0 {
		limit = 100
	}
	if limit > 1000 {
		limit = 1000
	}

	where, args := buildAuditWhere(filter)

	// Count total matching rows.
	var total int64
	countSQL := "SELECT COUNT(*) FROM audit_logs" + where
	if err := r.db.QueryRowContext(ctx, countSQL, args...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("audit count query: %w", err)
	}

	// Fetch page using a separate args slice to avoid mutating the count args.
	querySQL := `SELECT id, user_id, action, details, timestamp,
					resource_type, resource_id, ip_address, outcome, source, prev_hash, seq
				 FROM audit_logs` + where +
		` ORDER BY COALESCE(seq, 0) DESC, timestamp DESC, id DESC LIMIT ?`
	queryArgs := append(args, limit)

	rows, err := r.db.QueryContext(ctx, querySQL, queryArgs...)
	if err != nil {
		return nil, 0, fmt.Errorf("audit log query: %w", err)
	}
	defer rows.Close() //nolint:errcheck

	var logs []AuditLog
	for rows.Next() {
		var l AuditLog
		var userID, resourceType, resourceID, ipAddress, outcome, source, prevHash sql.NullString
		var seq sql.NullInt64
		if err := rows.Scan(
			&l.ID, &userID, &l.Action, &l.Details, &l.Timestamp,
			&resourceType, &resourceID, &ipAddress, &outcome, &source, &prevHash, &seq,
		); err != nil {
			return nil, 0, fmt.Errorf("audit log scan: %w", err)
		}
		l.UserID = userID.String
		l.ResourceType = resourceType.String
		l.ResourceID = resourceID.String
		l.IPAddress = ipAddress.String
		l.Outcome = outcome.String
		l.Source = source.String
		l.PrevHash = prevHash.String
		if seq.Valid {
			v := seq.Int64
			l.Seq = &v
		}
		logs = append(logs, l)
	}
	return logs, total, rows.Err()
}

// DeleteBefore deletes all audit_logs rows with timestamp < cutoff.
// Returns the number of deleted rows.
func (r *AuditRepository) DeleteBefore(ctx context.Context, cutoff time.Time) (int64, error) {
	result, err := r.db.ExecContext(
		ctx,
		`DELETE FROM audit_logs WHERE timestamp < ?`, cutoff,
	)
	if err != nil {
		return 0, err
	}
	return result.RowsAffected()
}

// GetAuditConfig reads a value from audit_config by key.
// Returns "" and no error if the key does not exist.
func (r *AuditRepository) GetAuditConfig(ctx context.Context, key string) (string, error) {
	var value sql.NullString
	err := r.db.QueryRowContext(ctx, `SELECT value FROM audit_config WHERE key = ?`, key).Scan(&value)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	return value.String, err
}

// SetAuditConfig upserts a key/value pair in audit_config.
func (r *AuditRepository) SetAuditConfig(ctx context.Context, key, value string) error {
	_, err := r.db.ExecContext(
		ctx,
		`INSERT INTO audit_config (key, value) VALUES (?, ?)
		 ON CONFLICT(key) DO UPDATE SET value = excluded.value`,
		key, value,
	)
	return err
}

// nullableString converts an empty string to a sql.NullString with Valid=false.
func nullableString(s string) sql.NullString {
	if s == "" {
		return sql.NullString{}
	}
	return sql.NullString{String: s, Valid: true}
}

// buildAuditWhere constructs a WHERE clause and args slice from an AuditFilter.
func buildAuditWhere(f AuditFilter) (string, []interface{}) {
	var clauses []string
	var args []interface{}

	if f.From != nil {
		clauses = append(clauses, "timestamp >= ?")
		args = append(args, *f.From)
	}
	if f.To != nil {
		clauses = append(clauses, "timestamp <= ?")
		args = append(args, *f.To)
	}
	if f.UserID != nil {
		clauses = append(clauses, "user_id = ?")
		args = append(args, *f.UserID)
	}
	if f.Action != nil {
		clauses = append(clauses, "action = ?")
		args = append(args, *f.Action)
	}
	if f.Outcome != nil {
		clauses = append(clauses, "outcome = ?")
		args = append(args, *f.Outcome)
	}
	if f.ResourceType != nil {
		clauses = append(clauses, "resource_type = ?")
		args = append(args, *f.ResourceType)
	}
	if f.ResourceID != nil {
		clauses = append(clauses, "resource_id = ?")
		args = append(args, *f.ResourceID)
	}
	if f.Source != nil {
		clauses = append(clauses, "source = ?")
		args = append(args, *f.Source)
	}

	if len(clauses) == 0 {
		return "", args
	}
	return " WHERE " + strings.Join(clauses, " AND "), args
}
