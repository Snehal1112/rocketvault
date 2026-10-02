package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"

	"rocketvault/common"
	"rocketvault/internal/logging"
	"rocketvault/internal/repositories"
	"rocketvault/internal/retry"
	auditServices "rocketvault/internal/services/audit"
	"rocketvault/model"
)

// AuthenticationResult represents the result of a successful authentication.
type AuthenticationResult struct {
	Token        string // Access token
	RefreshToken string // Refresh token
	UserID       uuid.UUID
	Username     string
	Roles        []string
}

// RefreshTokenResult represents the result of a successful token refresh.
type RefreshTokenResult struct {
	Token        string // New access token
	RefreshToken string // New refresh token (if rotation is enabled)
	UserID       uuid.UUID
	Username     string
	Roles        []string
	ExpiresAt    time.Time
}

// ErrSessionNotFound reports a session that does not exist, is already revoked,
// or belongs to a user other than the caller.
var ErrSessionNotFound = errors.New("session not found")

// ErrMFANotEnrolled reports a login attempt on an account that has no TOTP secret.
// The error AuthenticateUser returns for it reads like a wrong TOTP code, so the
// message never reveals that the account has no second factor.
var ErrMFANotEnrolled = errors.New("multi-factor authentication is not enrolled for this account")

// invalidTOTPCodeMessage is the message every rejected TOTP step returns.
const invalidTOTPCodeMessage = "invalid TOTP code"

// concealedTOTPError reads like a wrong TOTP code but keeps its real cause for errors.Is.
type concealedTOTPError struct {
	cause error
}

// Error returns the same message a wrong TOTP code returns.
func (e *concealedTOTPError) Error() string { return invalidTOTPCodeMessage }

// Unwrap returns the real cause, which only server-side code inspects.
func (e *concealedTOTPError) Unwrap() error { return e.cause }

// RevokeSessionRequest identifies a session and the caller who revokes it.
type RevokeSessionRequest struct {
	SessionID   string
	CallerID    uuid.UUID
	CallerRoles []string
	Reason      string
}

// AuthenticationService orchestrates the user authentication workflow.
// It coordinates password validation, TOTP verification, and token generation
// while maintaining separation of concerns between different auth components.
type AuthenticationService interface {
	AuthenticateUser(ctx context.Context, username, password, totpCode string) (*AuthenticationResult, error)
	// IssueSessionForUser creates a session and issues an access/refresh
	// token pair for a user whose identity has already been established
	// out-of-band (e.g. a verified OIDC ID token). It performs no
	// password/TOTP check — callers are responsible for having authenticated
	// the user by some other means before calling this.
	IssueSessionForUser(ctx context.Context, user *model.User) (*AuthenticationResult, error)
	ValidateSession(ctx context.Context, token string) (*JWTClaims, error)
	RefreshAccessToken(ctx context.Context, refreshToken string) (*RefreshTokenResult, error)
	RevokeSession(ctx context.Context, req RevokeSessionRequest) error
	RevokeAllUserSessions(ctx context.Context, userID uuid.UUID, reason string) error
	// ListActiveSessions returns every active (non-revoked, non-expired)
	// session for userID.
	ListActiveSessions(ctx context.Context, userID uuid.UUID) ([]*model.Session, error)
}

// authenticationService implements AuthenticationService by coordinating
// multiple auth services and the user repository.
type authenticationService struct {
	userRepo         repositories.UserRepositoryInterface
	sessionRepo      repositories.SessionRepositoryInterface
	passwordService  PasswordService
	totpService      TOTPService
	jwtService       JWTService
	oauth2ClientRepo repositories.OAuth2ClientRepositoryInterface
	totpStepRepo     repositories.TOTPStepRepositoryInterface
	logger           *logging.Logger
	auditService     auditServices.AuditServiceInterface
	throttle         *LoginThrottle
	// burnCompare spends a dummy bcrypt compare when no account was found.
	// Tests replace it with a spy.
	burnCompare func(password string)
}

// AuthenticationConfig holds the dependencies for authentication service.
type AuthenticationConfig struct {
	UserRepository         repositories.UserRepositoryInterface
	SessionRepository      repositories.SessionRepositoryInterface
	PasswordService        PasswordService
	TOTPService            TOTPService
	JWTService             JWTService
	OAuth2ClientRepository repositories.OAuth2ClientRepositoryInterface
	// TOTPStepRepository records used TOTP time steps. Login fails closed
	// without it, because a code could otherwise be replayed.
	TOTPStepRepository repositories.TOTPStepRepositoryInterface
	Logger             *logging.Logger
	AuditService       auditServices.AuditServiceInterface
	// LoginThrottle applies per-account backoff to failed logins. It is
	// optional: nil disables the backoff, which the constructor logs as a
	// warning so a production wiring gap is never silent.
	LoginThrottle *LoginThrottle
}

// NewAuthenticationService creates a new AuthenticationService with the provided dependencies.
// It orchestrates the authentication workflow by coordinating different auth services.
//
// Parameters:
//
//	config: Configuration containing all required dependencies.
//
// Returns:
//
//	An AuthenticationService implementation for user authentication.
func NewAuthenticationService(config AuthenticationConfig) AuthenticationService {
	if config.LoginThrottle == nil && config.Logger != nil {
		config.Logger.Warn("Login throttle is not configured: failed logins are not rate limited per account")
	}
	return &authenticationService{
		userRepo:         config.UserRepository,
		sessionRepo:      config.SessionRepository,
		passwordService:  config.PasswordService,
		totpService:      config.TOTPService,
		jwtService:       config.JWTService,
		oauth2ClientRepo: config.OAuth2ClientRepository,
		totpStepRepo:     config.TOTPStepRepository,
		logger:           config.Logger,
		auditService:     config.AuditService,
		throttle:         config.LoginThrottle,
		burnCompare:      common.BurnPasswordCompare,
	}
}

// AuthenticateUser performs complete user authentication including password and TOTP verification.
// It orchestrates the multi-step authentication process and returns access and refresh tokens
// upon successful authentication.
//
// Parameters:
//
//	ctx: The context for the authentication operation.
//	username: The user's username.
//	password: The user's plaintext password.
//	totpCode: The TOTP code from the user's MFA device.
//
// Returns:
//
//	Authentication result with access token, refresh token, and user information, or an error if authentication fails.
func (s *authenticationService) AuthenticateUser(ctx context.Context, username, password, totpCode string) (*AuthenticationResult, error) {
	s.logger.WithField("username", username).Info("Starting user authentication")

	// The backoff check runs before the user lookup and the password hash,
	// and for unknown usernames too, so a throttled answer looks the same
	// whether or not the account exists. It never writes, so attempts made
	// inside the window cannot extend it.
	if s.throttle != nil {
		if err := s.throttle.Check(ctx, username); err != nil {
			s.logger.WithField("username", username).Warn("Authentication refused: account in backoff window")
			return nil, err
		}
	}

	// Retrieve user from repository
	user, err := s.userRepo.ReadByUsername(ctx, username)
	if err != nil {
		if s.auditService != nil {
			_ = s.auditService.RecordEvent(ctx, auditServices.AuditEvent{
				Action: "authenticate_user", Outcome: "failure", Source: "system",
				ResourceType: "user", Details: "user not found",
			})
		}
		s.logger.WithField("username", username).Warn("Authentication failed: user not found")
		// Spend the bcrypt time a wrong password costs, so timing does not
		// reveal which usernames exist.
		s.burnCompare(password)
		s.recordLoginFailure(ctx, username)
		// Only a missing user is a client outcome. A lookup fault answers
		// the same, but still counts toward the database breaker.
		if errors.Is(err, repositories.ErrNotFound) {
			return nil, retry.ClientError(errors.New("invalid credentials"))
		}
		return nil, errors.New("invalid credentials")
	}

	// Validate password
	if err := s.passwordService.ValidatePassword(password, user.PasswordHash); err != nil {
		if s.auditService != nil {
			_ = s.auditService.RecordEvent(ctx, auditServices.AuditEvent{
				UserID: user.ID.String(), Action: "authenticate_user", Outcome: "failure", Source: "system",
				ResourceType: "user", Details: "invalid password",
			})
		}
		s.logger.WithFields(logrus.Fields{
			"username": username,
			"user_id":  user.ID.String(),
		}).Warn("Authentication failed: invalid password")
		s.recordLoginFailure(ctx, username)
		return nil, retry.ClientError(errors.New("invalid credentials"))
	}

	// An empty secret makes every TOTP code computable by anyone, so an
	// unenrolled account must not log in with a password alone. The check runs
	// after the password so it tells nothing to someone without the password,
	// and its error reads exactly like a wrong code. A secret of only spaces
	// or padding counts as empty, because it decodes to the same empty key.
	if totpSecretIsEmpty(user.TOTPSecret) {
		if s.auditService != nil {
			_ = s.auditService.RecordEvent(ctx, auditServices.AuditEvent{
				UserID: user.ID.String(), Action: "authenticate_user", Outcome: "failure", Source: "system",
				ResourceType: "user", Details: "TOTP not enrolled",
			})
		}
		s.logger.WithFields(logrus.Fields{
			"username": username,
			"user_id":  user.ID.String(),
		}).Warn("Authentication failed: TOTP not enrolled")
		s.recordLoginFailure(ctx, username)
		return nil, retry.ClientError(&concealedTOTPError{cause: ErrMFANotEnrolled})
	}

	// Validate TOTP code and learn which time step it belongs to.
	step, valid, err := s.totpService.ValidateCodeWithStep(totpCode, user.TOTPSecret, time.Now())
	if err != nil {
		if s.auditService != nil {
			_ = s.auditService.RecordEvent(ctx, auditServices.AuditEvent{
				UserID: user.ID.String(), Action: "authenticate_user", Outcome: "failure", Source: "system",
				ResourceType: "user", Details: "TOTP validation error",
			})
		}
		s.logger.WithError(err).Error("TOTP validation error")
		s.recordLoginFailure(ctx, username)
		return nil, retry.ClientError(fmt.Errorf("authentication failed: %w", err))
	}

	if !valid {
		if s.auditService != nil {
			_ = s.auditService.RecordEvent(ctx, auditServices.AuditEvent{
				UserID: user.ID.String(), Action: "authenticate_user", Outcome: "failure", Source: "system",
				ResourceType: "user", Details: "invalid TOTP code",
			})
		}
		s.logger.WithFields(logrus.Fields{
			"username": username,
			"user_id":  user.ID.String(),
		}).Warn("Authentication failed: invalid TOTP code")
		s.recordLoginFailure(ctx, username)
		return nil, retry.ClientError(errors.New(invalidTOTPCodeMessage))
	}

	// A code is single use: claiming its time step fails when this step or a
	// later one was already accepted for the user. The claim runs only after
	// the password and the code were both accepted, so a wrong guess never
	// uses up a step.
	// Every claim failure counts, a replay as well as a server fault, so no
	// exit of a login that did not finish leaves the counter untouched.
	if err := s.claimTOTPStep(ctx, &user, username, step); err != nil {
		s.recordLoginFailure(ctx, username)
		return nil, err
	}

	result, err := s.issueSession(ctx, &user, "authenticate_user")
	if err != nil {
		// The step is already used, so a retry of the whole login could only
		// fail as a replay. The retry layer must not repeat it.
		return nil, retry.NonRetryable(err)
	}

	// Only a login that issued a session clears the counter.
	if s.throttle != nil {
		s.throttle.Reset(ctx, username)
	}

	s.logger.WithFields(logrus.Fields{
		"username": username,
		"user_id":  user.ID.String(),
		"roles":    user.Roles,
	}).Info("User authenticated successfully with session")

	return result, nil
}

// recordLoginFailure counts a failed attempt against the username.
func (s *authenticationService) recordLoginFailure(ctx context.Context, username string) {
	if s.throttle != nil {
		s.throttle.RecordFailure(ctx, username)
	}
}

// claimTOTPStep records step as used for user and fails closed. A missing
// repository, a repository error and a step that is not newer all deny the
// login. A replay returns the same error as a wrong code, so a caller cannot
// tell that the code was right but already used.
func (s *authenticationService) claimTOTPStep(ctx context.Context, user *model.User, username string, step int64) error {
	if s.totpStepRepo == nil {
		s.logger.WithField("user_id", user.ID.String()).Error("TOTP replay protection is not configured")
		return fmt.Errorf("authentication failed: TOTP replay protection is not configured")
	}

	claimed, err := s.totpStepRepo.ClaimTOTPStep(ctx, user.ID, step)
	if err != nil {
		if s.auditService != nil {
			_ = s.auditService.RecordEvent(ctx, auditServices.AuditEvent{
				UserID: user.ID.String(), Action: "authenticate_user", Outcome: "failure", Source: "system",
				ResourceType: "user", Details: "TOTP step claim error",
			})
		}
		s.logger.WithError(err).Error("TOTP step claim error")
		return fmt.Errorf("authentication failed: %w", err)
	}

	if !claimed {
		if s.auditService != nil {
			_ = s.auditService.RecordEvent(ctx, auditServices.AuditEvent{
				UserID: user.ID.String(), Action: "authenticate_user", Outcome: "failure", Source: "system",
				ResourceType: "user", Details: "replayed TOTP code",
			})
		}
		s.logger.WithFields(logrus.Fields{
			"username": username,
			"user_id":  user.ID.String(),
		}).Warn("Authentication failed: replayed TOTP code")
		return retry.ClientError(errors.New(invalidTOTPCodeMessage))
	}

	return nil
}

// issueSession creates a session and issues an access/refresh token pair for
// user. auditAction labels the audit log entries so callers (password login
// vs. OIDC callback) are distinguishable in the audit trail.
func (s *authenticationService) issueSession(ctx context.Context, user *model.User, auditAction string) (*AuthenticationResult, error) {
	refreshToken, err := s.generateRefreshToken()
	if err != nil {
		s.logger.LogAuditError(user.ID.String(), auditAction, "failed", "Failed to generate refresh token", err)
		s.logger.WithError(err).Error("Failed to generate refresh token")
		return nil, fmt.Errorf("authentication failed: %w", err)
	}

	// Create session in database first so we have a session.ID for the JWT jti.
	session := &model.Session{
		ID:               uuid.New(),
		UserID:           user.ID,
		RefreshTokenHash: s.hashRefreshToken(refreshToken),
		DeviceInfo:       "",                                 // Can be populated from request context.
		IPAddress:        "",                                 // Can be populated from request context.
		UserAgent:        "",                                 // Can be populated from request context.
		ExpiresAt:        time.Now().Add(7 * 24 * time.Hour), // 7 days
		LastUsedAt:       time.Now(),
		CreatedAt:        time.Now(),
		Revoked:          false,
	}

	if err := s.sessionRepo.CreateSession(ctx, session); err != nil {
		s.logger.LogAuditError(user.ID.String(), auditAction, "failed", "Failed to create session", err)
		s.logger.WithError(err).Error("Failed to create session")
		return nil, fmt.Errorf("authentication failed: %w", err)
	}

	// Generate access token (short-lived) with session.ID as jti for revocation checks.
	accessToken, err := s.jwtService.GenerateToken(user.ID, user.Username, user.Roles, session.ID)
	if err != nil {
		s.logger.LogAuditError(user.ID.String(), auditAction, "failed", "Failed to generate JWT token", err)
		s.logger.WithError(err).Error("Failed to generate JWT token")
		return nil, fmt.Errorf("authentication failed: %w", err)
	}

	if s.auditService != nil {
		_ = s.auditService.RecordEvent(ctx, auditServices.AuditEvent{
			UserID: user.ID.String(), Action: auditAction, Outcome: "success",
			Source: "system", ResourceType: "user", ResourceID: user.ID.String(),
		})
	} else {
		s.logger.LogAuditInfo(user.ID.String(), auditAction, "success", "Session issued successfully")
	}

	return &AuthenticationResult{
		Token:        accessToken,
		RefreshToken: refreshToken,
		UserID:       user.ID,
		Username:     user.Username,
		Roles:        user.Roles,
	}, nil
}

// IssueSessionForUser creates a session and issues an access/refresh token
// pair for a user whose identity has already been established out-of-band.
func (s *authenticationService) IssueSessionForUser(ctx context.Context, user *model.User) (*AuthenticationResult, error) {
	return s.issueSession(ctx, user, "issue_session_for_user")
}

// ValidateSession validates a JWT token and returns the user claims.
// It provides session validation for authenticated requests,
// ensuring tokens are valid and not expired.
// A user session must also be unrevoked and its user must still exist.
// A service-account session must name an enabled, unexpired client.
//
// Parameters:
//
//	ctx: The context for the validation operation.
//	token: The JWT token to validate.
//
// Returns:
//
//	The validated JWT claims or an error if validation fails.
func (s *authenticationService) ValidateSession(ctx context.Context, token string) (*JWTClaims, error) {
	claims, err := s.jwtService.ValidateToken(token)
	if err != nil {
		s.logger.LogAuditError("", "validate_session", "failed", "Invalid session token", err)
		return nil, retry.ClientError(fmt.Errorf("invalid session: %w", err))
	}

	// Check revocation using the session ID embedded in the JWT jti claim.
	sessionID, err := uuid.Parse(claims.ID)
	if err != nil {
		s.logger.LogAuditError(claims.UserID.String(), "validate_session", "failed", "JWT jti is not a valid UUID", err)
		return nil, retry.ClientError(errors.New("invalid session: malformed jti"))
	}

	if slices.Contains(claims.Roles, model.RoleServiceAccount) {
		// For service accounts, verify the client still exists and is active.
		// sessionID equals client.ID, set as jti in IssueToken.
		// Without a client repository nothing can be checked, so the token is denied.
		if s.oauth2ClientRepo == nil {
			s.logger.LogAuditError(claims.UserID.String(), "validate_session", "failed", "Service account client repository not configured", nil)
			return nil, errors.New("invalid session")
		}
		client, err := s.oauth2ClientRepo.GetByID(ctx, sessionID)
		if err != nil {
			s.logger.LogAuditError(claims.UserID.String(), "validate_session", "failed", "Service account client not found", err)
			if errors.Is(err, repositories.ErrNotFound) {
				return nil, retry.ClientError(errors.New("service account not found or revoked"))
			}
			return nil, errors.New("service account not found or revoked")
		}
		if !client.Enabled {
			s.logger.LogAuditError(claims.UserID.String(), "validate_session", "failed", "Service account disabled", nil)
			return nil, retry.ClientError(errors.New("service account disabled"))
		}
		if client.ExpiresAt != nil && client.ExpiresAt.Before(time.Now()) {
			s.logger.LogAuditError(claims.UserID.String(), "validate_session", "failed", "Service account expired", nil)
			return nil, retry.ClientError(errors.New("service account expired"))
		}
	} else {
		// For user sessions, check the session revocation table.
		revoked, err := s.sessionRepo.IsSessionRevoked(ctx, sessionID)
		if err != nil {
			s.logger.LogAuditError(claims.UserID.String(), "validate_session", "failed", "Could not check session revocation", err)
			return nil, fmt.Errorf("invalid session: revocation check failed")
		}
		if revoked {
			s.logger.LogAuditError(claims.UserID.String(), "validate_session", "failed", "Session is revoked", nil)
			return nil, retry.ClientError(errors.New("session revoked"))
		}

		// Tokens name a user that must still exist. SQLite keeps session rows
		// after a user delete, so the revocation table alone cannot tell.
		// Both failures return the same generic error, so a caller cannot
		// tell a deleted user from a failed lookup. A lookup error denies.
		if _, err := s.userRepo.Read(ctx, claims.UserID); err != nil {
			if errors.Is(err, repositories.ErrNotFound) {
				s.logger.LogAuditError(claims.UserID.String(), "validate_session", "failed", "User no longer exists", nil)
				return nil, retry.ClientError(errors.New("invalid session"))
			}
			s.logger.LogAuditError(claims.UserID.String(), "validate_session", "failed", "Could not load session user", err)
			return nil, errors.New("invalid session")
		}
	}

	s.logger.LogAuditInfo(claims.UserID.String(), "validate_session", "success", "Session validated successfully")
	return claims, nil
}

// RefreshAccessToken refreshes an access token using a valid refresh token.
// It validates the refresh token, creates a new access token, and optionally
// rotates the refresh token for enhanced security.
//
// Parameters:
//
//	ctx: The context for the refresh operation.
//	refreshToken: The refresh token to use for getting a new access token.
//
// Returns:
//
//	Refresh token result with new access token and optional new refresh token, or an error if refresh fails.
func (s *authenticationService) RefreshAccessToken(ctx context.Context, refreshToken string) (*RefreshTokenResult, error) {
	s.logger.Info("Starting token refresh")

	// Hash the refresh token for database lookup
	refreshTokenHash := s.hashRefreshToken(refreshToken)

	// Get session by refresh token
	session, err := s.sessionRepo.GetSessionByRefreshToken(ctx, refreshTokenHash)
	if err != nil {
		s.logger.LogAuditError("", "refresh_access_token", "failed", "Invalid or expired refresh token", err)
		s.logger.WithError(err).Warn("Token refresh failed: invalid refresh token")
		if errors.Is(err, repositories.ErrNotFound) {
			return nil, retry.ClientError(errors.New("invalid refresh token"))
		}
		return nil, errors.New("invalid refresh token")
	}

	// Check if session is revoked
	if session.Revoked {
		s.logger.LogAuditError(session.UserID.String(), "refresh_access_token", "failed", "Session is revoked", nil)
		s.logger.WithField("session_id", session.ID.String()).Warn("Token refresh failed: session revoked")
		return nil, retry.ClientError(errors.New("session revoked"))
	}

	// Check if session has expired
	if time.Now().After(session.ExpiresAt) {
		s.logger.LogAuditError(session.UserID.String(), "refresh_access_token", "failed", "Session expired", nil)
		s.logger.WithField("session_id", session.ID.String()).Warn("Token refresh failed: session expired")
		return nil, retry.ClientError(errors.New("session expired"))
	}

	// Get user information
	user, err := s.userRepo.Read(ctx, session.UserID)
	if err != nil {
		s.logger.LogAuditError(session.UserID.String(), "refresh_access_token", "failed", "User not found", err)
		s.logger.WithError(err).Error("Token refresh failed: user not found")
		if errors.Is(err, repositories.ErrNotFound) {
			return nil, retry.ClientError(errors.New("user not found"))
		}
		return nil, errors.New("user not found")
	}

	// Generate new access token with the existing session.ID as jti.
	accessToken, err := s.jwtService.GenerateToken(user.ID, user.Username, user.Roles, session.ID)
	if err != nil {
		s.logger.LogAuditError(user.ID.String(), "refresh_access_token", "failed", "Failed to generate access token", err)
		s.logger.WithError(err).Error("Token refresh failed: could not generate access token")
		return nil, fmt.Errorf("failed to generate access token")
	}

	// Update session last used time
	if err := s.sessionRepo.UpdateSessionLastUsed(ctx, session.ID, time.Now()); err != nil {
		s.logger.LogAuditError(user.ID.String(), "refresh_access_token", "failed", "Failed to update session last used", err)
		s.logger.WithError(err).Warn("Token refresh failed: could not update session last used")
		// Continue with refresh even if this fails.
	}

	// For now, we'll keep the same refresh token (no rotation).
	// In a production system, you might want to implement refresh token rotation.

	// Log successful token refresh
	s.logger.LogAuditInfo(user.ID.String(), "refresh_access_token", "success", "Access token refreshed successfully")
	s.logger.WithFields(logrus.Fields{
		"user_id":    user.ID.String(),
		"username":   user.Username,
		"session_id": session.ID.String(),
	}).Info("Access token refreshed successfully")

	return &RefreshTokenResult{
		Token:        accessToken,
		RefreshToken: refreshToken, // Same refresh token for now
		UserID:       user.ID,
		Username:     user.Username,
		Roles:        user.Roles,
		ExpiresAt:    time.Now().Add(time.Hour), // 1 hour from now
	}, nil
}

// RevokeSession revokes one session. Admins may revoke any session; every
// other caller may revoke only a session they own. A session the caller may
// not revoke reports ErrSessionNotFound, so its existence is not disclosed.
func (s *authenticationService) RevokeSession(ctx context.Context, req RevokeSessionRequest) error {
	sessionIDUUID, err := uuid.Parse(req.SessionID)
	if err != nil {
		s.logger.LogAuditError(req.CallerID.String(), "revoke_session", "failed", "Invalid session ID format", err)
		return fmt.Errorf("invalid session ID format: %w", err)
	}

	if slices.Contains(req.CallerRoles, model.RoleAdmin) {
		err = s.sessionRepo.RevokeSession(ctx, sessionIDUUID, req.Reason)
	} else {
		err = s.sessionRepo.RevokeUserSession(ctx, sessionIDUUID, req.CallerID, req.Reason)
	}
	if err != nil {
		if errors.Is(err, repositories.ErrNotFound) {
			s.logger.LogAuditError(req.CallerID.String(), "revoke_session", "failed", "Session not found or not owned by caller", nil)
			return fmt.Errorf("revoke session %s: %w", req.SessionID, ErrSessionNotFound)
		}
		s.logger.LogAuditError(req.CallerID.String(), "revoke_session", "failed", "Failed to revoke session", err)
		s.logger.WithError(err).Error("Failed to revoke session")
		return fmt.Errorf("failed to revoke session: %w", err)
	}

	s.logger.LogAuditInfo(req.CallerID.String(), "revoke_session", "success", fmt.Sprintf("Session %s revoked: %s", req.SessionID, req.Reason))
	s.logger.WithFields(logrus.Fields{
		"session_id": req.SessionID,
		"caller_id":  req.CallerID.String(),
		"reason":     req.Reason,
	}).Info("Session revoked successfully")

	return nil
}

// RevokeAllUserSessions revokes all active sessions for a user.
//
// Parameters:
//
//	ctx: The context for the revocation operation.
//	userID: The ID of the user whose sessions should be revoked.
//	reason: The reason for revocation.
//
// Returns:
//
//	An error if revocation fails.
func (s *authenticationService) RevokeAllUserSessions(ctx context.Context, userID uuid.UUID, reason string) error {
	if err := s.sessionRepo.RevokeAllUserSessions(ctx, userID, reason); err != nil {
		s.logger.LogAuditError(userID.String(), "revoke_all_sessions", "failed", "Failed to revoke all user sessions", err)
		s.logger.WithError(err).Error("Failed to revoke all user sessions")
		return fmt.Errorf("failed to revoke all user sessions: %w", err)
	}

	s.logger.LogAuditInfo(userID.String(), "revoke_all_sessions", "success", fmt.Sprintf("All sessions revoked: %s", reason))
	s.logger.WithFields(logrus.Fields{
		"user_id": userID.String(),
		"reason":  reason,
	}).Info("All user sessions revoked successfully")

	return nil
}

// ListActiveSessions returns all active (non-revoked, non-expired) sessions for the user.
//
// Parameters:
//
//	ctx: The context for the operation.
//	userID: The ID of the user whose sessions to list.
//
// Returns:
//
//	A slice of active sessions or an error if retrieval fails.
func (s *authenticationService) ListActiveSessions(ctx context.Context, userID uuid.UUID) ([]*model.Session, error) {
	return s.sessionRepo.GetActiveSessionsByUserID(ctx, userID)
}

// generateRefreshToken generates a cryptographically secure refresh token.
func (s *authenticationService) generateRefreshToken() (string, error) {
	// Generate 32 random bytes for the refresh token
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", fmt.Errorf("failed to generate random bytes: %w", err)
	}
	return hex.EncodeToString(bytes), nil
}

// hashRefreshToken produces a SHA-256 hash of the token for storage.
// The token (32 random bytes as hex) has enough entropy that SHA-256
// without salt is safe here.
func (s *authenticationService) hashRefreshToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}
