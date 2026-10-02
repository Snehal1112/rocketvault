// Package oauth2 implements the RFC 6749 §4.4 client credentials grant type.
// Service accounts authenticate with client_id + client_secret and receive
// short-lived JWTs. They are first-class principals in the access_policies table.
package oauth2

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/google/uuid"

	"rocketvault/common"
	"rocketvault/internal/repositories"
	"rocketvault/model"
)

// JWTService is the subset of authServices.JWTService required here.
// Token validation is performed by AuthenticationMiddleware, not this service.
type JWTService interface {
	GenerateToken(userID uuid.UUID, username string, roles []string, sessionID uuid.UUID) (string, error)
}

// PasswordService is the subset of authServices.PasswordService that this
// package requires, allowing test mocks to implement the interface directly.
type PasswordService interface {
	HashPassword(password string) (string, error)
	ValidatePassword(password, hash string) error
}

// TokenResponse is the RFC 6749 §5.1 successful token response body.
type TokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"` // seconds
}

// OAuth2Config holds all dependencies for OAuth2Service.
type OAuth2Config struct {
	ClientRepo      repositories.OAuth2ClientRepositoryInterface
	PasswordService PasswordService
	JWTService      JWTService
	TokenExpiry     time.Duration
}

// OAuth2Service manages service account lifecycle and issues OAuth2 tokens.
type OAuth2Service interface {
	// IssueToken validates client credentials and returns a signed JWT.
	IssueToken(ctx context.Context, clientName, clientSecret string) (*TokenResponse, error)
	// CreateClient registers a new service account; returns the plain-text secret once.
	// expiresAt is optional — pass nil for a non-expiring service account.
	CreateClient(ctx context.Context, name, description string, expiresAt *time.Time) (*model.OAuth2Client, string, error)
	GetClient(ctx context.Context, id uuid.UUID) (*model.OAuth2Client, error)
	ListClients(ctx context.Context) ([]*model.OAuth2Client, error)
	// RotateSecret generates a new secret; returns the plain-text secret once.
	RotateSecret(ctx context.Context, id uuid.UUID) (string, error)
	DeleteClient(ctx context.Context, id uuid.UUID) error
}

type oauth2Service struct {
	repo        repositories.OAuth2ClientRepositoryInterface
	passwordSvc PasswordService
	jwtSvc      JWTService
	tokenExpiry time.Duration
	// burnCompare spends a dummy bcrypt compare when a client is rejected
	// before its secret is checked. Tests replace it with a spy.
	burnCompare func(secret string)
}

// NewOAuth2Service creates a new OAuth2Service with the provided config.
func NewOAuth2Service(cfg OAuth2Config) OAuth2Service {
	expiry := cfg.TokenExpiry
	if expiry == 0 {
		expiry = 30 * time.Minute
	}
	return &oauth2Service{
		repo:        cfg.ClientRepo,
		passwordSvc: cfg.PasswordService,
		jwtSvc:      cfg.JWTService,
		tokenExpiry: expiry,
		burnCompare: common.BurnPasswordCompare,
	}
}

// IssueToken validates the client_id/client_secret pair and returns a signed JWT.
// Error messages are intentionally generic to prevent credential enumeration.
func (s *oauth2Service) IssueToken(ctx context.Context, clientName, secret string) (*TokenResponse, error) {
	client, err := s.repo.FindByName(ctx, clientName)
	if err != nil {
		// Spend the bcrypt time a wrong secret costs, so timing cannot tell
		// an unknown client from a wrong secret.
		s.burnCompare(secret)
		return nil, fmt.Errorf("invalid client credentials")
	}

	// Invalid-credentials errors are intentionally uniform to prevent
	// credential-enumeration (RFC 6749 §5.2 / OWASP). Disabled and expired
	// clients also pay the same bcrypt cost as a wrong secret.
	if !client.Enabled || (client.ExpiresAt != nil && client.ExpiresAt.Before(time.Now().UTC())) {
		s.burnCompare(secret)
		return nil, fmt.Errorf("invalid client credentials")
	}

	if err := s.passwordSvc.ValidatePassword(secret, client.ClientSecret); err != nil {
		return nil, fmt.Errorf("invalid client credentials")
	}

	// Use client.ID as jti so ValidateSession can verify the client is still
	// active on each request, enabling immediate revocation on delete/disable.
	tokenStr, err := s.jwtSvc.GenerateToken(client.ID, client.Name, []string{model.RoleServiceAccount}, client.ID)
	if err != nil {
		return nil, fmt.Errorf("failed to issue token: %w", err)
	}

	return &TokenResponse{
		AccessToken: tokenStr,
		TokenType:   "Bearer",
		ExpiresIn:   int(s.tokenExpiry.Seconds()),
	}, nil
}

// CreateClient registers a new service account.
// A cryptographically random 32-byte plain-text secret is generated, hashed,
// stored, and returned once — it cannot be recovered after this call.
func (s *oauth2Service) CreateClient(ctx context.Context, name, description string, expiresAt *time.Time) (*model.OAuth2Client, string, error) {
	plain, err := generateSecret()
	if err != nil {
		return nil, "", fmt.Errorf("failed to generate client secret: %w", err)
	}

	hash, err := s.passwordSvc.HashPassword(plain)
	if err != nil {
		return nil, "", fmt.Errorf("failed to hash client secret: %w", err)
	}

	client := &model.OAuth2Client{
		ID:           uuid.New(),
		Name:         name,
		ClientSecret: hash,
		Description:  description,
		Enabled:      true,
		CreatedAt:    time.Now().UTC(),
		ExpiresAt:    expiresAt,
	}

	if err := s.repo.Create(ctx, client); err != nil {
		return nil, "", fmt.Errorf("failed to create client: %w", err)
	}

	return client, plain, nil
}

// GetClient returns a single OAuth2 client by ID.
func (s *oauth2Service) GetClient(ctx context.Context, id uuid.UUID) (*model.OAuth2Client, error) {
	c, err := s.repo.GetByID(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("client not found: %w", err)
	}
	c.ClientSecret = "" // never expose hash in reads
	return c, nil
}

// ListClients returns all registered service accounts (secrets redacted).
func (s *oauth2Service) ListClients(ctx context.Context) ([]*model.OAuth2Client, error) {
	clients, err := s.repo.List(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to list clients: %w", err)
	}
	for _, c := range clients {
		c.ClientSecret = ""
	}
	return clients, nil
}

// RotateSecret replaces the stored secret with a newly generated one.
// Returns the plain-text new secret; the old one is immediately invalidated.
func (s *oauth2Service) RotateSecret(ctx context.Context, id uuid.UUID) (string, error) {
	client, err := s.repo.GetByID(ctx, id)
	if err != nil {
		return "", fmt.Errorf("client not found: %w", err)
	}

	plain, err := generateSecret()
	if err != nil {
		return "", fmt.Errorf("failed to generate new secret: %w", err)
	}

	hash, err := s.passwordSvc.HashPassword(plain)
	if err != nil {
		return "", fmt.Errorf("failed to hash new secret: %w", err)
	}

	client.ClientSecret = hash
	if err := s.repo.Update(ctx, client); err != nil {
		return "", fmt.Errorf("failed to update client: %w", err)
	}

	return plain, nil
}

// DeleteClient permanently removes a service account.
func (s *oauth2Service) DeleteClient(ctx context.Context, id uuid.UUID) error {
	if err := s.repo.Delete(ctx, id); err != nil {
		return fmt.Errorf("failed to delete client: %w", err)
	}
	return nil
}

// generateSecret creates a 32-byte cryptographically random hex string.
func generateSecret() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
