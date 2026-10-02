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
	"rocketvault/model"
)

// SessionRepositoryInterface defines the contract for session data access operations.
// It provides methods for managing user sessions, refresh tokens, and session lifecycle.
type SessionRepositoryInterface interface {
	// CreateSession creates a new user session with refresh token.
	CreateSession(ctx context.Context, session *model.Session) error

	// GetSessionByID retrieves a session by its unique identifier.
	GetSessionByID(ctx context.Context, sessionID uuid.UUID) (*model.Session, error)

	// GetSessionByRefreshToken retrieves a session by refresh token hash.
	GetSessionByRefreshToken(ctx context.Context, refreshTokenHash string) (*model.Session, error)

	// GetActiveSessionsByUserID retrieves all active sessions for a user.
	GetActiveSessionsByUserID(ctx context.Context, userID uuid.UUID) ([]*model.Session, error)

	// UpdateSessionLastUsed updates the last used timestamp for a session.
	UpdateSessionLastUsed(ctx context.Context, sessionID uuid.UUID, lastUsedAt time.Time) error

	// RevokeSession marks a session as revoked.
	RevokeSession(ctx context.Context, sessionID uuid.UUID, reason string) error

	// RevokeUserSession marks a session as revoked only when userID owns it.
	// A session owned by another user reports ErrNotFound, the same as a missing one.
	RevokeUserSession(ctx context.Context, sessionID, userID uuid.UUID, reason string) error

	// RevokeAllUserSessions revokes all sessions for a user.
	RevokeAllUserSessions(ctx context.Context, userID uuid.UUID, reason string) error

	// DeleteExpiredSessions removes sessions that have expired.
	DeleteExpiredSessions(ctx context.Context, before time.Time) (int64, error)

	// CountActiveSessions counts active sessions for a user.
	CountActiveSessions(ctx context.Context, userID uuid.UUID) (int, error)

	// IsSessionRevoked checks if a session has been revoked.
	IsSessionRevoked(ctx context.Context, sessionID uuid.UUID) (bool, error)
}

// SessionRepository implements SessionRepositoryInterface for database operations.
// It provides CRUD operations for user sessions with performance monitoring.
type SessionRepository struct {
	db     db.DB
	logger *logging.Logger
}

// SessionRepositoryConfig holds configuration for session repository.
type SessionRepositoryConfig struct {
	DB     db.DB
	Logger *logging.Logger
}

// NewSessionRepository creates a new SessionRepository with the provided configuration.
func NewSessionRepository(config SessionRepositoryConfig) SessionRepositoryInterface {
	return &SessionRepository{
		db:     config.DB,
		logger: config.Logger,
	}
}

// CreateSession creates a new user session with refresh token.
func (r *SessionRepository) CreateSession(ctx context.Context, session *model.Session) error {
	return r.executeWithMetrics("create_session", func() error {
		query := `
			INSERT INTO user_sessions (
				id, user_id, refresh_token_hash, device_info, ip_address,
				user_agent, expires_at, last_used_at, created_at
			) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
		`
		_, err := r.db.ExecContext(ctx, query,
			session.ID.String(),
			session.UserID.String(),
			session.RefreshTokenHash,
			session.DeviceInfo,
			session.IPAddress,
			session.UserAgent,
			session.ExpiresAt,
			session.LastUsedAt,
			session.CreatedAt,
		)
		if err != nil {
			r.logger.LogAuditError(session.UserID.String(), "create_session", "failed", "Failed to create session", err)
			return fmt.Errorf("failed to create session: %w", err)
		}
		return nil
	})
}

// GetSessionByID retrieves a session by its unique identifier.
func (r *SessionRepository) GetSessionByID(ctx context.Context, sessionID uuid.UUID) (*model.Session, error) {
	var session model.Session
	var userID string
	var revokedAt sql.NullTime
	var revokedReason sql.NullString

	query := `
		SELECT id, user_id, refresh_token_hash, device_info, ip_address,
		       user_agent, expires_at, last_used_at, created_at, revoked,
		       revoked_at, revoked_reason
		FROM user_sessions
		WHERE id = ? AND revoked = FALSE
	`

	err := r.db.QueryRowContext(ctx, query, sessionID.String()).Scan(
		&session.ID, &userID, &session.RefreshTokenHash, &session.DeviceInfo,
		&session.IPAddress, &session.UserAgent, &session.ExpiresAt,
		&session.LastUsedAt, &session.CreatedAt, &session.Revoked,
		&revokedAt, &revokedReason,
	)

	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("session not found: %w", ErrNotFound)
		}
		r.logger.WithFields(logrus.Fields{
			"session_id": sessionID.String(),
		}).Errorf("Failed to get session by ID: %v", err)
		return nil, fmt.Errorf("failed to get session: %w", err)
	}

	// Convert userID string to UUID
	userUUID, err := uuid.Parse(userID)
	if err != nil {
		return nil, fmt.Errorf("invalid user ID format: %w", err)
	}
	session.UserID = userUUID

	// Handle nullable revoked_at
	if revokedAt.Valid {
		session.RevokedAt = &revokedAt.Time
	}

	// Handle nullable revoked_reason
	if revokedReason.Valid {
		session.RevokedReason = revokedReason.String
	}

	return &session, nil
}

// GetSessionByRefreshToken retrieves a session by refresh token hash.
func (r *SessionRepository) GetSessionByRefreshToken(ctx context.Context, refreshTokenHash string) (*model.Session, error) {
	var session model.Session
	var userID string
	var revokedAt sql.NullTime
	var revokedReason sql.NullString

	query := `
		SELECT id, user_id, refresh_token_hash, device_info, ip_address,
		       user_agent, expires_at, last_used_at, created_at, revoked,
		       revoked_at, revoked_reason
		FROM user_sessions
		WHERE refresh_token_hash = ? AND revoked = FALSE AND expires_at > ?
	`

	err := r.db.QueryRowContext(ctx, query, refreshTokenHash, time.Now()).Scan(
		&session.ID, &userID, &session.RefreshTokenHash, &session.DeviceInfo,
		&session.IPAddress, &session.UserAgent, &session.ExpiresAt,
		&session.LastUsedAt, &session.CreatedAt, &session.Revoked,
		&revokedAt, &revokedReason,
	)

	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("session not found or expired: %w", ErrNotFound)
		}
		r.logger.WithFields(logrus.Fields{
			"refresh_token_hash": refreshTokenHash[:10] + "...", // Log partial hash for security
		}).Errorf("Failed to get session by refresh token: %v", err)
		return nil, fmt.Errorf("failed to get session by refresh token: %w", err)
	}

	// Convert userID string to UUID
	userUUID, err := uuid.Parse(userID)
	if err != nil {
		return nil, fmt.Errorf("invalid user ID format: %w", err)
	}
	session.UserID = userUUID

	// Handle nullable revoked_at
	if revokedAt.Valid {
		session.RevokedAt = &revokedAt.Time
	}

	// Handle nullable revoked_reason
	if revokedReason.Valid {
		session.RevokedReason = revokedReason.String
	}

	return &session, nil
}

// GetActiveSessionsByUserID retrieves all active sessions for a user.
func (r *SessionRepository) GetActiveSessionsByUserID(ctx context.Context, userID uuid.UUID) ([]*model.Session, error) {
	query := `
		SELECT id, user_id, refresh_token_hash, device_info, ip_address,
		       user_agent, expires_at, last_used_at, created_at, revoked,
		       revoked_at, revoked_reason
		FROM user_sessions
		WHERE user_id = ? AND revoked = FALSE AND expires_at > ?
		ORDER BY last_used_at DESC
	`

	rows, err := r.db.QueryContext(ctx, query, userID.String(), time.Now())
	if err != nil {
		r.logger.WithFields(logrus.Fields{
			"user_id": userID.String(),
		}).Errorf("Failed to get active sessions: %v", err)
		return nil, fmt.Errorf("failed to get active sessions: %w", err)
	}
	defer rows.Close() //nolint:errcheck

	var sessions []*model.Session
	for rows.Next() {
		var session model.Session
		var userIDStr string
		var revokedAt sql.NullTime
		var revokedReason sql.NullString

		err := rows.Scan(
			&session.ID, &userIDStr, &session.RefreshTokenHash, &session.DeviceInfo,
			&session.IPAddress, &session.UserAgent, &session.ExpiresAt,
			&session.LastUsedAt, &session.CreatedAt, &session.Revoked,
			&revokedAt, &revokedReason,
		)
		if err != nil {
			r.logger.Errorf("Failed to scan session row: %v", err)
			return nil, fmt.Errorf("failed to scan session row: %w", err)
		}

		// Convert userID string to UUID. Defensive: this method's own WHERE
		// clause binds a uuid.UUID, so an unparseable user_id can never match
		// it. Returning rather than skipping keeps the listing honest if the
		// query ever grows a path that can reach such a row -- a session list
		// that silently omits entries is worse than one that fails loudly.
		userUUID, err := uuid.Parse(userIDStr)
		if err != nil {
			r.logger.WithFields(logrus.Fields{
				"user_id": userIDStr,
			}).Errorf("Invalid user ID format: %v", err)
			return nil, fmt.Errorf("invalid user id in session row: %w", err)
		}
		session.UserID = userUUID

		// Handle nullable revoked_at
		if revokedAt.Valid {
			session.RevokedAt = &revokedAt.Time
		}

		// Handle nullable revoked_reason
		if revokedReason.Valid {
			session.RevokedReason = revokedReason.String
		}

		sessions = append(sessions, &session)
	}

	if err := rows.Err(); err != nil {
		r.logger.Errorf("Error iterating session rows: %v", err)
		return nil, fmt.Errorf("error iterating sessions: %w", err)
	}

	return sessions, nil
}

// UpdateSessionLastUsed updates the last used timestamp for a session.
func (r *SessionRepository) UpdateSessionLastUsed(ctx context.Context, sessionID uuid.UUID, lastUsedAt time.Time) error {
	return r.executeWithMetrics("update_session_last_used", func() error {
		query := `
			UPDATE user_sessions
			SET last_used_at = ?
			WHERE id = ? AND revoked = FALSE
		`
		result, err := r.db.ExecContext(ctx, query, lastUsedAt, sessionID.String())
		if err != nil {
			r.logger.WithFields(logrus.Fields{
				"session_id": sessionID.String(),
			}).Errorf("Failed to update session last used: %v", err)
			return fmt.Errorf("failed to update session last used: %w", err)
		}

		rowsAffected, err := result.RowsAffected()
		if err != nil {
			return fmt.Errorf("failed to get rows affected: %w", err)
		}

		if rowsAffected == 0 {
			return fmt.Errorf("session not found or already revoked: %w", ErrNotFound)
		}

		return nil
	})
}

// RevokeSession marks a session as revoked.
func (r *SessionRepository) RevokeSession(ctx context.Context, sessionID uuid.UUID, reason string) error {
	return r.executeWithMetrics("revoke_session", func() error {
		now := time.Now()
		query := `
			UPDATE user_sessions
			SET revoked = TRUE, revoked_at = ?, revoked_reason = ?
			WHERE id = ? AND revoked = FALSE
		`
		result, err := r.db.ExecContext(ctx, query, now, reason, sessionID.String())
		if err != nil {
			r.logger.WithFields(logrus.Fields{
				"session_id": sessionID.String(),
				"reason":     reason,
			}).Errorf("Failed to revoke session: %v", err)
			return fmt.Errorf("failed to revoke session: %w", err)
		}

		rowsAffected, err := result.RowsAffected()
		if err != nil {
			return fmt.Errorf("failed to get rows affected: %w", err)
		}

		if rowsAffected == 0 {
			return fmt.Errorf("session not found or already revoked: %w", ErrNotFound)
		}

		return nil
	})
}

// RevokeUserSession marks a session as revoked only when userID owns it.
func (r *SessionRepository) RevokeUserSession(ctx context.Context, sessionID, userID uuid.UUID, reason string) error {
	return r.executeWithMetrics("revoke_user_session", func() error {
		query := `
			UPDATE user_sessions
			SET revoked = TRUE, revoked_at = ?, revoked_reason = ?
			WHERE id = ? AND user_id = ? AND revoked = FALSE
		`
		result, err := r.db.ExecContext(ctx, query, time.Now(), reason, sessionID.String(), userID.String())
		if err != nil {
			r.logger.WithFields(logrus.Fields{
				"session_id": sessionID.String(),
				"user_id":    userID.String(),
			}).Errorf("Failed to revoke user session: %v", err)
			return fmt.Errorf("failed to revoke session: %w", err)
		}

		rowsAffected, err := result.RowsAffected()
		if err != nil {
			return fmt.Errorf("failed to get rows affected: %w", err)
		}

		// Zero rows means missing, already revoked, or owned by someone else.
		// All three look the same to the caller on purpose.
		if rowsAffected == 0 {
			return fmt.Errorf("session not found or already revoked: %w", ErrNotFound)
		}

		return nil
	})
}

// RevokeAllUserSessions revokes all sessions for a user.
func (r *SessionRepository) RevokeAllUserSessions(ctx context.Context, userID uuid.UUID, reason string) error {
	return r.executeWithMetrics("revoke_all_user_sessions", func() error {
		now := time.Now()
		query := `
			UPDATE user_sessions
			SET revoked = TRUE, revoked_at = ?, revoked_reason = ?
			WHERE user_id = ? AND revoked = FALSE
		`
		result, err := r.db.ExecContext(ctx, query, now, reason, userID.String())
		if err != nil {
			r.logger.WithFields(logrus.Fields{
				"user_id": userID.String(),
				"reason":  reason,
			}).Errorf("Failed to revoke all user sessions: %v", err)
			return fmt.Errorf("failed to revoke all user sessions: %w", err)
		}

		rowsAffected, err := result.RowsAffected()
		if err != nil {
			return fmt.Errorf("failed to get rows affected: %w", err)
		}

		r.logger.WithFields(logrus.Fields{
			"user_id":        userID.String(),
			"reason":         reason,
			"sessions_count": rowsAffected,
		}).Info("Revoked all user sessions")

		return nil
	})
}

// DeleteExpiredSessions removes sessions that have expired.
func (r *SessionRepository) DeleteExpiredSessions(ctx context.Context, before time.Time) (int64, error) {
	var deletedCount int64
	err := r.executeWithMetrics("delete_expired_sessions", func() error {
		query := `
			DELETE FROM user_sessions
			WHERE expires_at < ? AND (revoked = TRUE OR expires_at < ?)
		`
		result, err := r.db.ExecContext(ctx, query, before, time.Now())
		if err != nil {
			r.logger.WithFields(logrus.Fields{
				"before": before,
			}).Errorf("Failed to delete expired sessions: %v", err)
			return fmt.Errorf("failed to delete expired sessions: %w", err)
		}

		count, err := result.RowsAffected()
		if err != nil {
			return fmt.Errorf("failed to get deleted count: %w", err)
		}

		deletedCount = count
		return nil
	})
	return deletedCount, err
}

// CountActiveSessions counts active sessions for a user.
func (r *SessionRepository) CountActiveSessions(ctx context.Context, userID uuid.UUID) (int, error) {
	var count int
	query := `
		SELECT COUNT(*)
		FROM user_sessions
		WHERE user_id = ? AND revoked = FALSE AND expires_at > ?
	`
	err := r.db.QueryRowContext(ctx, query, userID.String(), time.Now()).Scan(&count)
	if err != nil {
		r.logger.WithFields(logrus.Fields{
			"user_id": userID.String(),
		}).Errorf("Failed to count active sessions: %v", err)
		return 0, fmt.Errorf("failed to count active sessions: %w", err)
	}
	return count, nil
}

// IsSessionRevoked checks if a session has been revoked.
func (r *SessionRepository) IsSessionRevoked(ctx context.Context, sessionID uuid.UUID) (bool, error) {
	var revoked bool
	query := `
		SELECT revoked
		FROM user_sessions
		WHERE id = ?
	`
	err := r.db.QueryRowContext(ctx, query, sessionID.String()).Scan(&revoked)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return true, nil // Non-existent session is considered revoked
		}
		r.logger.WithFields(logrus.Fields{
			"session_id": sessionID.String(),
		}).Errorf("Failed to check if session is revoked: %v", err)
		return true, fmt.Errorf("failed to check session revocation: %w", err)
	}
	return revoked, nil
}

// executeWithMetrics wraps database operations with performance monitoring.
// See KeyRepository.executeWithMetrics for why this stays a method.
func (r *SessionRepository) executeWithMetrics(operation string, fn func() error) error {
	return withMetrics("user_sessions", operation, fn)
}
