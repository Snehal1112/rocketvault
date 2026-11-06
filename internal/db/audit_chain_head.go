package db

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
)

// AuditChainTip returns the chain head that the audit_logs rows imply. With
// chained rows it is the seq and hash of the row with the highest seq.
// Without any, it is seq 0 and the hash of the newest legacy row by
// (timestamp, id), or an empty hash when the table is empty.
func AuditChainTip(ctx context.Context, q DBTX) (int64, string, error) {
	var seq int64
	var hash string
	err := q.QueryRowContext(ctx,
		"SELECT seq, COALESCE(prev_hash, '') FROM audit_logs WHERE seq IS NOT NULL ORDER BY seq DESC LIMIT 1",
	).Scan(&seq, &hash)
	if err == nil {
		return seq, hash, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return 0, "", fmt.Errorf("read newest chained audit row: %w", err)
	}
	err = q.QueryRowContext(ctx,
		"SELECT COALESCE(prev_hash, '') FROM audit_logs ORDER BY timestamp DESC, id DESC LIMIT 1",
	).Scan(&hash)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return 0, "", fmt.Errorf("read newest legacy audit row: %w", err)
	}
	return 0, hash, nil
}

// SeedAuditChainHead creates the head row from the audit_logs tip if it is
// absent. An existing head is left as it is.
func SeedAuditChainHead(ctx context.Context, q DBTX, d Dialect) error {
	seq, hash, err := AuditChainTip(ctx, q)
	if err != nil {
		return err
	}
	return insertAuditChainHeadIfAbsent(ctx, q, d, seq, hash)
}

// insertAuditChainHeadIfAbsent inserts the head row unless it already exists.
func insertAuditChainHeadIfAbsent(ctx context.Context, q DBTX, d Dialect, seq int64, hash string) error {
	insertSQL := d.Rebind(d.UpsertIgnore(
		"audit_chain_head", "id, last_seq, last_hash", "?, ?, ?", "id",
	))
	if _, err := q.ExecContext(ctx, insertSQL, 1, seq, hash); err != nil {
		return fmt.Errorf("seed audit_chain_head: %w", err)
	}
	return nil
}

// ReconcileAuditChainHead advances a head that lags behind the highest
// chained row. It never moves the head backwards, so it is safe to run on
// every startup and from several replicas at once.
func ReconcileAuditChainHead(ctx context.Context, q DBTX, d Dialect) error {
	seq, hash, err := AuditChainTip(ctx, q)
	if err != nil {
		return err
	}
	if seq == 0 {
		return nil
	}
	if _, err := q.ExecContext(ctx,
		d.Rebind("UPDATE audit_chain_head SET last_seq = ?, last_hash = ? WHERE id = 1 AND last_seq < ?"),
		seq, hash, seq,
	); err != nil {
		return fmt.Errorf("reconcile audit_chain_head: %w", err)
	}
	return nil
}

// ResetAuditChainHead sets the head to the audit_logs tip, creating the row
// if needed. Unlike ReconcileAuditChainHead it may move the head backwards,
// so only a restore that replaced audit_logs should call it.
func ResetAuditChainHead(ctx context.Context, q DBTX, d Dialect) error {
	seq, hash, err := AuditChainTip(ctx, q)
	if err != nil {
		return err
	}
	if err := insertAuditChainHeadIfAbsent(ctx, q, d, seq, hash); err != nil {
		return err
	}
	if _, err := q.ExecContext(ctx,
		d.Rebind("UPDATE audit_chain_head SET last_seq = ?, last_hash = ? WHERE id = 1"),
		seq, hash,
	); err != nil {
		return fmt.Errorf("reset audit_chain_head: %w", err)
	}
	return nil
}
