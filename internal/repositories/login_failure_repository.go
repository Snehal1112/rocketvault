package repositories

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"rocketvault/internal/db"
	"rocketvault/model"
)

// LoginFailureRepositoryInterface defines data access for failed-login
// counters. Repositories handle only data access; the backoff policy lives in
// the auth service layer.
type LoginFailureRepositoryInterface interface {
	// Get returns the counter for username, or ErrNotFound.
	Get(ctx context.Context, username string) (*model.LoginFailure, error)
	// RecordFailure counts one failure at time at in a single atomic
	// statement. A row whose last failure predates staleBefore restarts at
	// one instead of growing, so concurrent failures are never undercounted
	// and a stale counter never carries over.
	RecordFailure(ctx context.Context, username string, at, staleBefore time.Time) error
	// Delete removes the counter for username. A missing row is not an error.
	Delete(ctx context.Context, username string) error
	// DeleteOlderThan removes rows whose last failure predates cutoff.
	DeleteOlderThan(ctx context.Context, cutoff time.Time) (int64, error)
}

type loginFailureRepository struct {
	db db.DB
}

// NewLoginFailureRepository creates a LoginFailureRepositoryInterface backed by conn.
func NewLoginFailureRepository(conn db.DB) LoginFailureRepositoryInterface {
	return &loginFailureRepository{db: conn}
}

// Get returns the counter for username.
func (r *loginFailureRepository) Get(ctx context.Context, username string) (*model.LoginFailure, error) {
	var f model.LoginFailure
	err := withMetrics("login_failures", "get", func() error {
		return r.db.QueryRowContext(ctx,
			`SELECT username, failures, last_failure_at FROM login_failures WHERE username = ?`, username,
		).Scan(&f.Username, &f.Failures, &f.LastFailureAt)
	})
	if errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("loginFailureRepository.Get: %w", ErrNotFound)
	}
	if err != nil {
		return nil, fmt.Errorf("loginFailureRepository.Get: %w", err)
	}
	return &f, nil
}

// RecordFailure upserts the counter in one statement. Times are stored in UTC
// so the text comparison SQLite performs on TIMESTAMP columns stays ordered.
func (r *loginFailureRepository) RecordFailure(ctx context.Context, username string, at, staleBefore time.Time) error {
	err := withMetrics("login_failures", "record_failure", func() error {
		_, err := r.db.ExecContext(ctx,
			`INSERT INTO login_failures (username, failures, last_failure_at) VALUES (?, 1, ?)
			 ON CONFLICT (username) DO UPDATE SET
			   failures = CASE WHEN login_failures.last_failure_at < ? THEN 1
			                   ELSE login_failures.failures + 1 END,
			   last_failure_at = excluded.last_failure_at`,
			username, at.UTC(), staleBefore.UTC())
		return err
	})
	if err != nil {
		return fmt.Errorf("loginFailureRepository.RecordFailure: %w", err)
	}
	return nil
}

// Delete removes the counter for username.
func (r *loginFailureRepository) Delete(ctx context.Context, username string) error {
	err := withMetrics("login_failures", "delete", func() error {
		_, err := r.db.ExecContext(ctx, `DELETE FROM login_failures WHERE username = ?`, username)
		return err
	})
	if err != nil {
		return fmt.Errorf("loginFailureRepository.Delete: %w", err)
	}
	return nil
}

// DeleteOlderThan removes rows whose last failure predates cutoff.
func (r *loginFailureRepository) DeleteOlderThan(ctx context.Context, cutoff time.Time) (int64, error) {
	var n int64
	err := withMetrics("login_failures", "delete_older_than", func() error {
		res, err := r.db.ExecContext(ctx, `DELETE FROM login_failures WHERE last_failure_at < ?`, cutoff.UTC())
		if err != nil {
			return err
		}
		n, err = res.RowsAffected()
		return err
	})
	if err != nil {
		return 0, fmt.Errorf("loginFailureRepository.DeleteOlderThan: %w", err)
	}
	return n, nil
}
