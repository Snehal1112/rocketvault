package retry

import (
	"context"

	"github.com/google/uuid"

	"rocketvault/internal/services/auth"
	"rocketvault/model"
)

// RetryAuthenticationService wraps authentication operations with retry logic
type RetryAuthenticationService interface {
	auth.AuthenticationService
}

// retryAuthenticationService implements RetryAuthenticationService with retry logic
type retryAuthenticationService struct {
	baseService  auth.AuthenticationService
	retryService RetryService
}

// NewRetryAuthenticationService creates a new retry-aware authentication service
func NewRetryAuthenticationService(baseService auth.AuthenticationService, retryService RetryService) RetryAuthenticationService {
	return &retryAuthenticationService{
		baseService:  baseService,
		retryService: retryService,
	}
}

// AuthenticateUser authenticates a user with retry logic for database operations
func (s *retryAuthenticationService) AuthenticateUser(ctx context.Context, username, password, totpCode string) (*auth.AuthenticationResult, error) {
	return retried(ctx, s.retryService, func() (*auth.AuthenticationResult, error) {
		return s.baseService.AuthenticateUser(ctx, username, password, totpCode)
	})
}

// IssueSessionForUser issues a session with retry logic for database operations.
func (s *retryAuthenticationService) IssueSessionForUser(ctx context.Context, user *model.User) (*auth.AuthenticationResult, error) {
	return retried(ctx, s.retryService, func() (*auth.AuthenticationResult, error) {
		return s.baseService.IssueSessionForUser(ctx, user)
	})
}

// ValidateSession validates a session with retry logic for database operations
func (s *retryAuthenticationService) ValidateSession(ctx context.Context, token string) (*auth.JWTClaims, error) {
	return retried(ctx, s.retryService, func() (*auth.JWTClaims, error) {
		return s.baseService.ValidateSession(ctx, token)
	})
}

// RefreshAccessToken refreshes an access token with retry logic for database operations
func (s *retryAuthenticationService) RefreshAccessToken(ctx context.Context, refreshToken string) (*auth.RefreshTokenResult, error) {
	return retried(ctx, s.retryService, func() (*auth.RefreshTokenResult, error) {
		return s.baseService.RefreshAccessToken(ctx, refreshToken)
	})
}

// RevokeSession revokes a session with retry logic for database operations.
func (s *retryAuthenticationService) RevokeSession(ctx context.Context, req auth.RevokeSessionRequest) error {
	return s.retryService.ExecuteDatabaseOperation(ctx, func() error {
		return s.baseService.RevokeSession(ctx, req)
	})
}

// RevokeAllUserSessions revokes all user sessions with retry logic for database operations
func (s *retryAuthenticationService) RevokeAllUserSessions(ctx context.Context, userID uuid.UUID, reason string) error {
	return s.retryService.ExecuteDatabaseOperation(ctx, func() error {
		return s.baseService.RevokeAllUserSessions(ctx, userID, reason)
	})
}

// ListActiveSessions lists all active sessions for a user with retry logic for database operations
func (s *retryAuthenticationService) ListActiveSessions(ctx context.Context, userID uuid.UUID) ([]*model.Session, error) {
	return retried(ctx, s.retryService, func() ([]*model.Session, error) {
		return s.baseService.ListActiveSessions(ctx, userID)
	})
}
