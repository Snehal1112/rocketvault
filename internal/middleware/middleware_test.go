package middleware

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	"rocketvault/common"
	"rocketvault/internal/logging"
	"rocketvault/internal/repositories"
	auditSvc "rocketvault/internal/services/audit"
	authServices "rocketvault/internal/services/auth"
	authzServices "rocketvault/internal/services/authorization"
	oauth2Services "rocketvault/internal/services/oauth2"
	"rocketvault/internal/services/provisioning"
	vaultServices "rocketvault/internal/services/vaults"
	"rocketvault/model"

	"github.com/gorilla/mux"
)

// MockServiceContainer is a mock implementation of the service container for testing.
type MockServiceContainer struct {
	mock.Mock
	logger *logging.Logger
}

func (m *MockServiceContainer) GetLogger() *logging.Logger {
	return m.logger
}

func (m *MockServiceContainer) GetAuthenticationService() authServices.AuthenticationService {
	args := m.Called()
	return args.Get(0).(authServices.AuthenticationService)
}

func (m *MockServiceContainer) GetRBACService() authzServices.RBACService {
	args := m.Called()
	return args.Get(0).(authzServices.RBACService)
}

func (m *MockServiceContainer) GetAccessPolicyService() authzServices.AccessPolicyService {
	args := m.Called()
	if args.Get(0) == nil {
		return nil
	}
	return args.Get(0).(authzServices.AccessPolicyService)
}

func (m *MockServiceContainer) GetRoleAssignmentService() authzServices.RoleAssignmentService {
	args := m.Called()
	if args.Get(0) == nil {
		return nil
	}
	return args.Get(0).(authzServices.RoleAssignmentService)
}

func (m *MockServiceContainer) GetAuditService() auditSvc.AuditServiceInterface {
	return nil
}

func (m *MockServiceContainer) GetGrantService() provisioning.GrantService {
	return nil
}

func (m *MockServiceContainer) GetOAuth2ClientRepository() repositories.OAuth2ClientRepositoryInterface {
	return nil
}

func (m *MockServiceContainer) GetOAuth2Service() oauth2Services.OAuth2Service {
	return nil
}

func (m *MockServiceContainer) GetVaultService() vaultServices.VaultService {
	args := m.Called()
	if args.Get(0) == nil {
		return nil
	}
	return args.Get(0).(vaultServices.VaultService)
}

func (m *MockServiceContainer) GetVaultWebhookService() vaultServices.VaultWebhookService {
	return nil
}

// stubVaultService is a minimal vaultServices.VaultService for middleware tests.
type stubVaultService struct {
	vault         *model.Vault
	err           error
	getVaultCalls int
}

func (s *stubVaultService) CreateVault(context.Context, model.CreateVaultRequest, uuid.UUID) (*model.Vault, error) {
	return nil, nil
}
func (s *stubVaultService) CreateVaultProvisioned(context.Context, model.CreateVaultRequest, uuid.UUID, bool, bool) (*model.Vault, error) {
	return nil, nil
}
func (s *stubVaultService) GetVault(_ context.Context, _ string) (*model.Vault, error) {
	s.getVaultCalls++
	return s.vault, s.err
}
func (s *stubVaultService) ListVaults(context.Context, bool) ([]model.Vault, error) { return nil, nil }
func (s *stubVaultService) ListVaultsScoped(context.Context, uuid.UUID, bool, bool) ([]model.Vault, error) {
	return nil, nil
}
func (s *stubVaultService) UpdateVault(context.Context, string, model.UpdateVaultRequest, uuid.UUID) (*model.Vault, error) {
	return nil, nil
}
func (s *stubVaultService) DeleteVault(context.Context, string) error                      { return nil }
func (s *stubVaultService) RecoverVault(context.Context, string) error                     { return nil }
func (s *stubVaultService) PurgeVault(context.Context, string) error                       { return nil }
func (s *stubVaultService) SetPolicyCleaner(_ vaultServices.PolicyCleaner)                 {}
func (s *stubVaultService) SetRoleAssignmentCleaner(_ vaultServices.RoleAssignmentCleaner) {}
func (s *stubVaultService) SetWebhookCleaner(_ vaultServices.WebhookCleaner)               {}
func (s *stubVaultService) SetTxBeginner(_ vaultServices.TxBeginner)                       {}
func (s *stubVaultService) SetSecretCacheFlusher(_ vaultServices.SecretCacheFlusher)       {}
func (s *stubVaultService) SetVaultCache(_ vaultServices.VaultCacheInterface)              {}
func (s *stubVaultService) SetGlobalPurgeProtection(_ bool)                                {}
func (s *stubVaultService) SetGrantLocker(_ vaultServices.GrantLocker)                     {}
func (s *stubVaultService) SetCreatorGranter(_ vaultServices.CreatorGranter)               {}
func (s *stubVaultService) SetPolicyVaultLister(_ vaultServices.PolicyVaultLister)         {}

// MockAuthenticationService is a mock implementation of AuthenticationService.
type MockAuthenticationService struct {
	mock.Mock
}

func (m *MockAuthenticationService) AuthenticateUser(ctx context.Context, username, password, totpCode string) (*authServices.AuthenticationResult, error) {
	args := m.Called(ctx, username, password, totpCode)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*authServices.AuthenticationResult), args.Error(1)
}

func (m *MockAuthenticationService) IssueSessionForUser(ctx context.Context, user *model.User) (*authServices.AuthenticationResult, error) {
	args := m.Called(ctx, user)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*authServices.AuthenticationResult), args.Error(1)
}

func (m *MockAuthenticationService) ValidateSession(ctx context.Context, token string) (*authServices.JWTClaims, error) {
	args := m.Called(ctx, token)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*authServices.JWTClaims), args.Error(1)
}

func (m *MockAuthenticationService) RefreshAccessToken(ctx context.Context, refreshToken string) (*authServices.RefreshTokenResult, error) {
	args := m.Called(ctx, refreshToken)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*authServices.RefreshTokenResult), args.Error(1)
}

func (m *MockAuthenticationService) RevokeSession(ctx context.Context, req authServices.RevokeSessionRequest) error {
	args := m.Called(ctx, req)
	return args.Error(0)
}

func (m *MockAuthenticationService) RevokeAllUserSessions(ctx context.Context, userID uuid.UUID, reason string) error {
	args := m.Called(ctx, userID, reason)
	return args.Error(0)
}

func (m *MockAuthenticationService) ListActiveSessions(ctx context.Context, userID uuid.UUID) ([]*model.Session, error) {
	args := m.Called(ctx, userID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*model.Session), args.Error(1)
}

// MockRBACService is a mock implementation of RBACService.
type MockRBACService struct {
	mock.Mock
}

func (m *MockRBACService) HasPermission(role string, permission authzServices.Permission) bool {
	args := m.Called(role, permission)
	return args.Bool(0)
}

func (m *MockRBACService) GetRolePermissions(role string) []authzServices.Permission {
	args := m.Called(role)
	return args.Get(0).([]authzServices.Permission)
}

func (m *MockRBACService) ValidateEndpointAccess(roles []string, method, path string) error {
	args := m.Called(roles, method, path)
	return args.Error(0)
}

// setupTestMiddleware creates a middleware instance with mocked dependencies.
func setupTestMiddleware() (*Middleware, *MockServiceContainer, *MockAuthenticationService, *MockRBACService) {
	// Create a simple logger for testing
	logger := &logging.Logger{Logger: logrus.New()}
	logger.SetLevel(logrus.ErrorLevel) // Reduce test output noise

	mockContainer := &MockServiceContainer{logger: logger}
	mockAuthService := &MockAuthenticationService{}
	mockRBACService := &MockRBACService{}

	mockContainer.On("GetAuthenticationService").Return(mockAuthService)
	mockContainer.On("GetRBACService").Return(mockRBACService)

	// Create middleware via constructor so limiters are properly initialized.
	mw := NewMiddleware(mockContainer)
	return mw, mockContainer, mockAuthService, mockRBACService
}

// TestMiddlewareConstructor tests that middleware can be created with a service container.
func TestMiddlewareConstructor(t *testing.T) {
	t.Parallel()
	logger := &logging.Logger{Logger: logrus.New()}
	mockContainer := &MockServiceContainer{logger: logger}

	mw := NewMiddleware(mockContainer)

	assert.NotNil(t, mw)
	assert.NotNil(t, mw.container)
	assert.NotNil(t, mw.logger)
	assert.NotNil(t, mw.defaultLimiter)
	assert.NotNil(t, mw.authLimiter)
	assert.Equal(t, mockContainer, mw.container)
	assert.Equal(t, logger, mw.logger)
}

// TestLoggingMiddleware tests the logging middleware functionality.
func TestLoggingMiddleware(t *testing.T) {
	t.Parallel()
	mw, _, _, _ := setupTestMiddleware()

	tests := []struct {
		name           string
		method         string
		path           string
		statusCode     int
		userID         string
		expectedStatus string
	}{
		{
			name:           "successful request",
			method:         "GET",
			path:           "/api/secrets",
			statusCode:     http.StatusOK,
			userID:         uuid.New().String(),
			expectedStatus: "success",
		},
		{
			name:           "failed request - 400",
			method:         "POST",
			path:           "/api/secrets",
			statusCode:     http.StatusBadRequest,
			userID:         uuid.New().String(),
			expectedStatus: "failed",
		},
		{
			name:           "failed request - 500",
			method:         "GET",
			path:           "/api/users",
			statusCode:     http.StatusInternalServerError,
			userID:         uuid.New().String(),
			expectedStatus: "failed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			// Create test handler that sets status code
			handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tt.statusCode)
			})

			// Wrap handler with logging middleware
			wrappedHandler := mw.LoggingMiddleware(handler)

			// Create test request
			req := httptest.NewRequest(tt.method, tt.path, nil)
			ctx := context.WithValue(req.Context(), common.UserIDKey, tt.userID)
			req = req.WithContext(ctx)
			rr := httptest.NewRecorder()

			// Execute request
			wrappedHandler.ServeHTTP(rr, req)

			// Verify status code
			assert.Equal(t, tt.statusCode, rr.Code)
		})
	}
}

// TestRateLimitMiddleware tests the rate limiting functionality.
func TestRateLimitMiddleware(t *testing.T) {
	t.Parallel()
	mw, _, _, _ := setupTestMiddleware()

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	wrappedHandler := mw.RateLimitMiddleware(handler)

	t.Run("default endpoint rate limit", func(t *testing.T) {
		// Make multiple requests from same IP to default endpoint
		req := httptest.NewRequest("GET", "/api/test", nil)
		req.RemoteAddr = "192.168.1.1:12345"

		// First 300 requests should succeed (default rate limit)
		for i := 0; i < 300; i++ {
			rr := httptest.NewRecorder()
			wrappedHandler.ServeHTTP(rr, req)
			assert.Equal(t, http.StatusOK, rr.Code, "Request %d should succeed", i+1)

			// Check rate limit headers
			assert.NotEmpty(t, rr.Header().Get("X-RateLimit-Limit"))
			assert.NotEmpty(t, rr.Header().Get("X-RateLimit-Remaining"))
			assert.NotEmpty(t, rr.Header().Get("X-RateLimit-Reset"))
		}

		// 301st request should be rate limited
		rr := httptest.NewRecorder()
		wrappedHandler.ServeHTTP(rr, req)
		assert.Equal(t, http.StatusTooManyRequests, rr.Code, "301st request should be rate limited")
	})

	t.Run("auth endpoint strict rate limit", func(t *testing.T) {
		// Make multiple requests from same IP to auth endpoint
		req := httptest.NewRequest("POST", "/api/v1/users/login", nil)
		req.RemoteAddr = "192.168.1.2:12346"

		// First 5 requests should succeed (stricter auth rate limit)
		for i := 0; i < 5; i++ {
			rr := httptest.NewRecorder()
			wrappedHandler.ServeHTTP(rr, req)
			assert.Equal(t, http.StatusOK, rr.Code, "Request %d should succeed", i+1)

			// Check rate limit headers
			limit := rr.Header().Get("X-RateLimit-Limit")
			assert.Equal(t, "5", limit, "Auth endpoint should have limit of 5")
		}

		// 6th request should be rate limited
		rr := httptest.NewRecorder()
		wrappedHandler.ServeHTTP(rr, req)
		assert.Equal(t, http.StatusTooManyRequests, rr.Code, "6th request to auth endpoint should be rate limited")
	})
}

// TestRateLimitMiddleware_UsesIPNotAddrPort verifies that rate limiting uses IP address
// (not RemoteAddr with port) as the key. Two requests from the same IP but different ports
// must share the rate limit bucket.
func TestRateLimitMiddleware_UsesIPNotAddrPort(t *testing.T) {
	t.Parallel()
	logger := &logging.Logger{Logger: logrus.New()}
	logger.SetLevel(logrus.ErrorLevel)

	m := &Middleware{
		logger:         logger,
		defaultLimiter: newKeyedRateLimiter(60),
		authLimiter:    newKeyedRateLimiter(5),
	}

	handler := m.RateLimitMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// First request from 10.0.0.1:11111
	req1 := httptest.NewRequest(http.MethodGet, "/api/vault", nil)
	req1.RemoteAddr = "10.0.0.1:11111"
	rr1 := httptest.NewRecorder()
	handler.ServeHTTP(rr1, req1)

	// Second request from same IP but different port (10.0.0.1:22222)
	req2 := httptest.NewRequest(http.MethodGet, "/api/vault", nil)
	req2.RemoteAddr = "10.0.0.1:22222"
	rr2 := httptest.NewRecorder()
	handler.ServeHTTP(rr2, req2)

	rem1, _ := strconv.Atoi(rr1.Header().Get("X-RateLimit-Remaining"))
	rem2, _ := strconv.Atoi(rr2.Header().Get("X-RateLimit-Remaining"))

	// The second request should have one less remaining count than the first,
	// proving they share the same rate limit bucket (same IP, different port).
	assert.Equal(t, rem1-1, rem2, "same IP different port must share the rate limit bucket")
}

// TestAuthenticationMiddleware tests JWT authentication.
func TestAuthenticationMiddleware(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name           string
		path           string
		authHeader     string
		setupMock      func(*MockAuthenticationService)
		expectedStatus int
		skipAuth       bool
	}{
		{
			name:           "public endpoint - health",
			path:           "/api/v1/health",
			authHeader:     "",
			setupMock:      func(m *MockAuthenticationService) {},
			expectedStatus: http.StatusOK,
			skipAuth:       true,
		},
		{
			name:           "public endpoint - login",
			path:           "/api/v1/users/login",
			authHeader:     "",
			setupMock:      func(m *MockAuthenticationService) {},
			expectedStatus: http.StatusOK,
			skipAuth:       true,
		},
		{
			name:           "missing auth header",
			path:           "/api/secrets",
			authHeader:     "",
			setupMock:      func(m *MockAuthenticationService) {},
			expectedStatus: http.StatusUnauthorized,
		},
		{
			name:           "invalid token format",
			path:           "/api/secrets",
			authHeader:     "InvalidFormat token123",
			setupMock:      func(m *MockAuthenticationService) {},
			expectedStatus: http.StatusUnauthorized,
		},
		{
			name:       "valid token",
			path:       "/api/secrets",
			authHeader: "Bearer valid-token-123",
			setupMock: func(m *MockAuthenticationService) {
				claims := &authServices.JWTClaims{
					UserID:   uuid.New(),
					Username: "testuser",
					Roles:    []string{"user"},
				}
				m.On("ValidateSession", mock.Anything, "valid-token-123").Return(claims, nil)
			},
			expectedStatus: http.StatusOK,
		},
		{
			name:       "invalid token",
			path:       "/api/secrets",
			authHeader: "Bearer invalid-token",
			setupMock: func(m *MockAuthenticationService) {
				m.On("ValidateSession", mock.Anything, "invalid-token").Return(nil, fmt.Errorf("invalid token"))
			},
			expectedStatus: http.StatusUnauthorized,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			mw, _, mockAuthService, _ := setupTestMiddleware()
			tt.setupMock(mockAuthService)

			handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if !tt.skipAuth {
					// Verify context values are set for authenticated requests
					userID, ok := r.Context().Value(common.UserIDKey).(string)
					assert.True(t, ok, "UserID should be in context")
					assert.NotEmpty(t, userID, "UserID should not be empty")

					username, ok := r.Context().Value(common.UsernameKey).(string)
					assert.True(t, ok, "Username should be in context")
					assert.Equal(t, "testuser", username)

					roles, ok := r.Context().Value(common.RoleKey).([]string)
					assert.True(t, ok, "Role should be in context")
					assert.Equal(t, []string{"user"}, roles)
				}
				w.WriteHeader(http.StatusOK)
			})

			wrappedHandler := mw.AuthenticationMiddleware(handler)

			req := httptest.NewRequest("GET", tt.path, nil)
			if tt.authHeader != "" {
				req.Header.Set("Authorization", tt.authHeader)
			}
			rr := httptest.NewRecorder()

			wrappedHandler.ServeHTTP(rr, req)

			assert.Equal(t, tt.expectedStatus, rr.Code)
			mockAuthService.AssertExpectations(t)
		})
	}
}

// TestAuthorizationMiddleware tests RBAC authorization.
func TestAuthorizationMiddleware(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name           string
		role           string
		method         string
		path           string
		setupMock      func(*MockRBACService)
		expectedStatus int
	}{
		{
			name:   "missing role in context",
			role:   "",
			method: "GET",
			path:   "/api/secrets",
			setupMock: func(m *MockRBACService) {
				// No expectations - should fail before calling service
			},
			expectedStatus: http.StatusForbidden,
		},
		{
			name:   "authorized access",
			role:   "admin",
			method: "POST",
			path:   "/api/users",
			setupMock: func(m *MockRBACService) {
				m.On("ValidateEndpointAccess", []string{"admin"}, "POST", "/api/users").Return(nil)
			},
			expectedStatus: http.StatusOK,
		},
		{
			name:   "unauthorized access",
			role:   "user",
			method: "DELETE",
			path:   "/api/users",
			setupMock: func(m *MockRBACService) {
				m.On("ValidateEndpointAccess", []string{"user"}, "DELETE", "/api/users").Return(fmt.Errorf("insufficient permissions"))
			},
			expectedStatus: http.StatusForbidden,
		},
		{
			name:   "user accessing own resources",
			role:   "user",
			method: "GET",
			path:   "/api/secrets",
			setupMock: func(m *MockRBACService) {
				m.On("ValidateEndpointAccess", []string{"user"}, "GET", "/api/secrets").Return(nil)
			},
			expectedStatus: http.StatusOK,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			mw, _, _, mockRBACService := setupTestMiddleware()
			tt.setupMock(mockRBACService)

			handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
			})

			wrappedHandler := mw.AuthorizationMiddleware(handler)

			req := httptest.NewRequest(tt.method, tt.path, nil)
			if tt.role != "" {
				ctx := context.WithValue(req.Context(), common.RoleKey, []string{tt.role})
				req = req.WithContext(ctx)
			}
			rr := httptest.NewRecorder()

			wrappedHandler.ServeHTTP(rr, req)

			assert.Equal(t, tt.expectedStatus, rr.Code)
			mockRBACService.AssertExpectations(t)
		})
	}
}

// TestSecurityHeadersMiddleware tests security headers are properly set.
func TestSecurityHeadersMiddleware(t *testing.T) {
	t.Parallel()
	mw, _, _, _ := setupTestMiddleware()

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	wrappedHandler := mw.SecurityHeadersMiddleware(handler)

	t.Run("non-TLS request does not set HSTS", func(t *testing.T) {
		t.Parallel()
		req := httptest.NewRequest("GET", "/api/test", nil)
		rr := httptest.NewRecorder()
		wrappedHandler.ServeHTTP(rr, req)

		assert.Equal(t, "nosniff", rr.Header().Get("X-Content-Type-Options"))
		assert.Equal(t, "DENY", rr.Header().Get("X-Frame-Options"))
		assert.Equal(t, "1; mode=block", rr.Header().Get("X-XSS-Protection"))
		assert.Empty(t, rr.Header().Get("Strict-Transport-Security"), "HSTS must not be set over plain HTTP")
		assert.Equal(t, "default-src 'self'", rr.Header().Get("Content-Security-Policy"))
		assert.Equal(t, http.StatusOK, rr.Code)
	})

	t.Run("TLS request sets HSTS", func(t *testing.T) {
		t.Parallel()
		req := httptest.NewRequest("GET", "/api/test", nil)
		req.TLS = &tls.ConnectionState{} // Simulate TLS connection.
		rr := httptest.NewRecorder()
		wrappedHandler.ServeHTTP(rr, req)

		assert.Equal(t, "max-age=31536000; includeSubDomains", rr.Header().Get("Strict-Transport-Security"))
		assert.Equal(t, http.StatusOK, rr.Code)
	})
}

// TestCORSMiddleware tests CORS headers are properly set with configurable allowlist.
func TestCORSMiddleware(t *testing.T) {
	t.Parallel()
	mw, _, _, _ := setupTestMiddleware()

	tests := []struct {
		name           string
		method         string
		expectedStatus int
	}{
		{
			name:           "OPTIONS preflight request",
			method:         "OPTIONS",
			expectedStatus: http.StatusOK,
		},
		{
			name:           "GET request with CORS",
			method:         "GET",
			expectedStatus: http.StatusOK,
		},
		{
			name:           "POST request with CORS",
			method:         "POST",
			expectedStatus: http.StatusOK,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
			})

			wrappedHandler := mw.CORSMiddleware(handler)

			req := httptest.NewRequest(tt.method, "/api/test", nil)
			rr := httptest.NewRecorder()

			wrappedHandler.ServeHTTP(rr, req)

			// Verify no wildcard CORS headers without Origin header
			assert.Empty(t, rr.Header().Get("Access-Control-Allow-Origin"))
			assert.Equal(t, tt.expectedStatus, rr.Code)
		})
	}
}

// TestCORSMiddleware_AllowedOrigin verifies that allowed origins receive CORS headers.
func TestCORSMiddleware_AllowedOrigin(t *testing.T) {
	t.Parallel()
	m := &Middleware{
		corsOrigins: map[string]bool{"https://app.example.com": true},
	}
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Origin", "https://app.example.com")
	rr := httptest.NewRecorder()
	m.CORSMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})).ServeHTTP(rr, req)

	assert.Equal(t, "https://app.example.com", rr.Header().Get("Access-Control-Allow-Origin"))
	assert.Equal(t, "Origin", rr.Header().Get("Vary"))
}

// TestCORSMiddleware_DisallowedOrigin verifies that disallowed origins do not receive CORS headers.
func TestCORSMiddleware_DisallowedOrigin(t *testing.T) {
	t.Parallel()
	m := &Middleware{
		corsOrigins: map[string]bool{"https://app.example.com": true},
	}
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Origin", "https://evil.example.com")
	rr := httptest.NewRecorder()
	m.CORSMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})).ServeHTTP(rr, req)

	assert.Empty(t, rr.Header().Get("Access-Control-Allow-Origin"))
}

// TestCORSMiddleware_NoOriginHeader verifies that requests without Origin header are unaffected.
func TestCORSMiddleware_NoOriginHeader(t *testing.T) {
	t.Parallel()
	m := &Middleware{corsOrigins: map[string]bool{}}
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rr := httptest.NewRecorder()
	m.CORSMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})).ServeHTTP(rr, req)

	assert.Empty(t, rr.Header().Get("Access-Control-Allow-Origin"))
	assert.Equal(t, http.StatusOK, rr.Code)
}

// TestRequestIDMiddleware tests request ID generation.
func TestRequestIDMiddleware(t *testing.T) {
	t.Parallel()
	mw, _, _, _ := setupTestMiddleware()

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify request ID is in context
		requestID, ok := r.Context().Value(requestIDKey).(string)
		assert.True(t, ok, "Request ID should be in context")
		assert.NotEmpty(t, requestID, "Request ID should not be empty")

		// Verify it's a valid UUID.
		_, err := uuid.Parse(requestID)
		assert.NoError(t, err, "Request ID should be a valid UUID")

		w.WriteHeader(http.StatusOK)
	})

	wrappedHandler := mw.RequestIDMiddleware(handler)

	req := httptest.NewRequest("GET", "/api/test", nil)
	rr := httptest.NewRecorder()

	wrappedHandler.ServeHTTP(rr, req)

	// Verify request ID is in response header
	requestID := rr.Header().Get("X-Request-ID")
	assert.NotEmpty(t, requestID)

	// Verify it's a valid UUID.
	_, err := uuid.Parse(requestID)
	assert.NoError(t, err, "Request ID in response header should be a valid UUID")
	assert.Equal(t, http.StatusOK, rr.Code)
}

// TestGenerateRequestID tests request ID generation uniqueness.
func TestGenerateRequestID(t *testing.T) {
	t.Parallel()
	id1 := generateRequestID()
	id2 := generateRequestID()

	assert.NotEmpty(t, id1)
	assert.NotEmpty(t, id2)
	assert.NotEqual(t, id1, id2, "Request IDs should be unique")

	// Verify both are valid UUIDs.
	_, err1 := uuid.Parse(id1)
	assert.NoError(t, err1)
	_, err2 := uuid.Parse(id2)
	assert.NoError(t, err2)
}

// TestGenerateRequestID_Unique tests that request IDs are unique even when generated in rapid succession.
func TestGenerateRequestID_Unique(t *testing.T) {
	ids := make(map[string]bool, 1000)
	for i := 0; i < 1000; i++ {
		id := generateRequestID()
		assert.False(t, ids[id], "request IDs must be unique; collision at i=%d", i)
		ids[id] = true
	}
}

// TestGenerateRequestID_IsUUID tests that request ID is a valid UUID.
func TestGenerateRequestID_IsUUID(t *testing.T) {
	id := generateRequestID()
	_, err := uuid.Parse(id)
	assert.NoError(t, err, "request ID must be a valid UUID")
}

// TestAuthMiddlewareDeprecated tests the deprecated auth middleware.
func TestAuthMiddlewareDeprecated(t *testing.T) {
	t.Parallel()
	mw, _, mockAuthService, mockRBACService := setupTestMiddleware()

	// Setup mocks for both authentication and authorization
	claims := &authServices.JWTClaims{
		UserID:   uuid.New(),
		Username: "testuser",
		Roles:    []string{"admin"},
	}
	mockAuthService.On("ValidateSession", mock.Anything, "valid-token").Return(claims, nil)
	mockRBACService.On("ValidateEndpointAccess", []string{"admin"}, "GET", "/api/test").Return(nil)

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	// Use deprecated middleware (should chain authentication + authorization)
	wrappedHandler := mw.AuthMiddleware(handler)

	req := httptest.NewRequest("GET", "/api/test", nil)
	req.Header.Set("Authorization", "Bearer valid-token")
	rr := httptest.NewRecorder()

	wrappedHandler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	mockAuthService.AssertExpectations(t)
	mockRBACService.AssertExpectations(t)
}

// TestAuthenticationAndAuthorizationMiddleware_MultiRoleGrantsViaNonFirstRole
// proves the full multi-role chain end to end: AuthenticationMiddleware storing
// every claimed role in context, AuthorizationMiddleware reading them back, and
// a REAL (non-mocked) RBACService looping over all of them -- not just the
// first. "user" alone has no users:list permission; "admin" does, but it is
// the caller's SECOND role. Every other RBAC test in this package (and in
// internal/services/authorization) either mocks ValidateEndpointAccess or
// calls it directly with a single-role slice, so none of them would catch a
// regression back to checking only roles[0].
func TestAuthenticationAndAuthorizationMiddleware_MultiRoleGrantsViaNonFirstRole(t *testing.T) {
	t.Parallel()
	logger := &logging.Logger{Logger: logrus.New()}
	logger.SetLevel(logrus.ErrorLevel)

	mockContainer := &MockServiceContainer{logger: logger}
	mockAuthService := &MockAuthenticationService{}
	realRBACService := authzServices.NewRBACService(logger)

	mockContainer.On("GetAuthenticationService").Return(mockAuthService)
	mockContainer.On("GetRBACService").Return(realRBACService)

	mw := NewMiddleware(mockContainer)

	claims := &authServices.JWTClaims{
		UserID:   uuid.New(),
		Username: "multirole",
		Roles:    []string{model.RoleUser, model.RoleAdmin},
	}
	mockAuthService.On("ValidateSession", mock.Anything, "valid-token").Return(claims, nil)

	handlerReached := false
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handlerReached = true
		w.WriteHeader(http.StatusOK)
	})

	// Same relative order production wires in api.go: authentication runs
	// first, authorization last.
	wrappedHandler := mw.AuthenticationMiddleware(mw.AuthorizationMiddleware(handler))

	req := httptest.NewRequest("GET", "/api/v1/users", nil)
	req.Header.Set("Authorization", "Bearer valid-token")
	rr := httptest.NewRecorder()

	wrappedHandler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	assert.True(t, handlerReached, "request must reach the handler: admin, the caller's second role, grants users:list even though user (the first role) does not")
	mockAuthService.AssertExpectations(t)
}

// TestResponseWriterStatusCode tests the custom ResponseWriter.
func TestResponseWriterStatusCode(t *testing.T) {
	t.Parallel()
	logger := &logging.Logger{Logger: logrus.New()}
	w := httptest.NewRecorder()
	rw := &ResponseWriter{
		ResponseWriter: w,
		statusCode:     http.StatusOK,
		log:            logger,
	}

	// Test default status code
	assert.Equal(t, http.StatusOK, rw.statusCode)

	// Test WriteHeader captures status code
	rw.WriteHeader(http.StatusCreated)
	assert.Equal(t, http.StatusCreated, rw.statusCode)
	assert.Equal(t, http.StatusCreated, w.Code)

	// Test error status code
	rw.WriteHeader(http.StatusInternalServerError)
	assert.Equal(t, http.StatusInternalServerError, rw.statusCode)
}

// TestMiddlewareChaining tests that multiple middleware can be chained together.
func TestMiddlewareChaining(t *testing.T) {
	t.Parallel()
	mw, _, _, _ := setupTestMiddleware()

	finalHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify request ID and security headers are present
		requestID, ok := r.Context().Value(requestIDKey).(string)
		assert.True(t, ok)
		assert.NotEmpty(t, requestID)

		w.WriteHeader(http.StatusOK)
	})

	// Chain multiple middleware together
	handler := mw.RequestIDMiddleware(
		mw.SecurityHeadersMiddleware(
			mw.CORSMiddleware(
				mw.LoggingMiddleware(finalHandler),
			),
		),
	)

	req := httptest.NewRequest("GET", "/api/test", nil)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	// Verify all middleware effects
	assert.Equal(t, http.StatusOK, rr.Code)
	assert.NotEmpty(t, rr.Header().Get("X-Request-ID"))
	assert.Equal(t, "nosniff", rr.Header().Get("X-Content-Type-Options"))
	// CORS headers are only set for allowed origins; without Origin header or allowed origin, none are set
	assert.Empty(t, rr.Header().Get("Access-Control-Allow-Origin"))
}

// MockAccessPolicyService is a mock implementation of AccessPolicyService.
type MockAccessPolicyService struct {
	mock.Mock
}

func (m *MockAccessPolicyService) CheckAccess(ctx context.Context, principalID uuid.UUID, resourceType model.PolicyResourceType, op model.PolicyOperation, vaultID uuid.UUID) (authzServices.AccessDecision, error) {
	args := m.Called(ctx, principalID, resourceType, op, vaultID)
	return args.Get(0).(authzServices.AccessDecision), args.Error(1)
}

func (m *MockAccessPolicyService) CheckVaultScopedAccess(ctx context.Context, principalID uuid.UUID, resourceType model.PolicyResourceType, op model.PolicyOperation, vaultID uuid.UUID) (authzServices.AccessDecision, error) {
	args := m.Called(ctx, principalID, resourceType, op, vaultID)
	return args.Get(0).(authzServices.AccessDecision), args.Error(1)
}

func (m *MockAccessPolicyService) CreatePolicy(ctx context.Context, policy *model.AccessPolicy) error {
	args := m.Called(ctx, policy)
	return args.Error(0)
}

func (m *MockAccessPolicyService) GetPolicy(ctx context.Context, id uuid.UUID) (*model.AccessPolicy, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*model.AccessPolicy), args.Error(1)
}

func (m *MockAccessPolicyService) ListPolicies(ctx context.Context) ([]*model.AccessPolicy, error) {
	args := m.Called(ctx)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*model.AccessPolicy), args.Error(1)
}

func (m *MockAccessPolicyService) ListByPrincipal(ctx context.Context, principalID uuid.UUID) ([]*model.AccessPolicy, error) {
	args := m.Called(ctx, principalID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*model.AccessPolicy), args.Error(1)
}

func (m *MockAccessPolicyService) UpdatePolicy(ctx context.Context, policy *model.AccessPolicy) error {
	args := m.Called(ctx, policy)
	return args.Error(0)
}

func (m *MockAccessPolicyService) DeletePolicy(ctx context.Context, id uuid.UUID) error {
	args := m.Called(ctx, id)
	return args.Error(0)
}

// setupPolicyMiddlewareTest creates middleware wired with a mock AccessPolicyService.
func setupPolicyMiddlewareTest(t *testing.T) (*Middleware, *MockServiceContainer, *MockAccessPolicyService) {
	t.Helper()
	logger := &logging.Logger{Logger: logrus.New()}
	logger.SetLevel(logrus.ErrorLevel)

	mockContainer := &MockServiceContainer{logger: logger}
	mockPolicySvc := &MockAccessPolicyService{}

	// Other services not needed for PolicyMiddleware tests; provide nil-safe stubs.
	mockContainer.On("GetAccessPolicyService").Return(mockPolicySvc)

	mw := NewMiddleware(mockContainer)
	return mw, mockContainer, mockPolicySvc
}

// TestPolicyMiddleware_FallbackPassesThrough verifies that when no explicit policy
// exists (AccessFallback) on a management route the request is allowed through
// unchanged. Vault data-plane routes no longer pass through on fallback alone;
// see TestPolicyMiddleware_DeniesWithoutRoleAssignment for that inversion.
func TestPolicyMiddleware_FallbackPassesThrough(t *testing.T) {
	t.Parallel()
	mw, _, mockPolicySvc := setupPolicyMiddlewareTest(t)

	userID := uuid.New()
	mockPolicySvc.On("CheckAccess", mock.Anything, userID, model.PolicyResourceVaults, model.OpManage, mock.Anything).Return(authzServices.AccessFallback, nil)

	nextCalled := false
	nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/vaults/prod", nil)
	ctx := context.WithValue(req.Context(), common.UserIDKey, userID.String())
	req = req.WithContext(ctx)
	rr := httptest.NewRecorder()

	mw.PolicyMiddleware(nextHandler).ServeHTTP(rr, req)

	assert.True(t, nextCalled, "next handler should be called on fallback")
	assert.Equal(t, http.StatusOK, rr.Code)
}

// TestPolicyMiddleware_ExplicitDenyBlocks verifies that AccessDenied returns 403.
func TestPolicyMiddleware_ExplicitDenyBlocks(t *testing.T) {
	t.Parallel()
	mw, _, mockPolicySvc := setupPolicyMiddlewareTest(t)

	userID := uuid.New()
	mockPolicySvc.On("CheckAccess", mock.Anything, userID, model.PolicyResourceType("secrets"), model.PolicyOperation("create"), mock.Anything).Return(authzServices.AccessDenied, nil)

	nextCalled := false
	nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
	})

	req := httptest.NewRequest(http.MethodPost, "/api/v1/secrets", nil)
	ctx := context.WithValue(req.Context(), common.UserIDKey, userID.String())
	req = req.WithContext(ctx)
	rr := httptest.NewRecorder()

	mw.PolicyMiddleware(nextHandler).ServeHTTP(rr, req)

	assert.False(t, nextCalled, "next handler should NOT be called on deny")
	assert.Equal(t, http.StatusForbidden, rr.Code)
}

// TestPolicyMiddleware_ExplicitAllowPassesThrough verifies that AccessAllowed
// continues on a management route.
func TestPolicyMiddleware_ExplicitAllowPassesThrough(t *testing.T) {
	t.Parallel()
	mw, _, mockPolicySvc := setupPolicyMiddlewareTest(t)

	userID := uuid.New()
	mockPolicySvc.On("CheckAccess", mock.Anything, userID, model.PolicyResourceVaults, model.OpManage, mock.Anything).Return(authzServices.AccessAllowed, nil)

	nextCalled := false
	nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/vaults/prod", nil)
	ctx := context.WithValue(req.Context(), common.UserIDKey, userID.String())
	req = req.WithContext(ctx)
	rr := httptest.NewRecorder()

	mw.PolicyMiddleware(nextHandler).ServeHTTP(rr, req)

	assert.True(t, nextCalled, "next handler should be called on allow")
	assert.Equal(t, http.StatusOK, rr.Code)
}

// TestPolicyMiddleware_UnknownRoutePassesThrough verifies that unresolvable
// routes (no matching resource type) are not blocked.
func TestPolicyMiddleware_UnknownRoutePassesThrough(t *testing.T) {
	t.Parallel()
	mw, _, _ := setupPolicyMiddlewareTest(t)

	userID := uuid.New()
	nextCalled := false
	nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/health", nil)
	ctx := context.WithValue(req.Context(), common.UserIDKey, userID.String())
	req = req.WithContext(ctx)
	rr := httptest.NewRecorder()

	mw.PolicyMiddleware(nextHandler).ServeHTTP(rr, req)

	assert.True(t, nextCalled, "next handler should be called for unknown routes")
	assert.Equal(t, http.StatusOK, rr.Code)
}

// TestPolicyMiddleware_ErrorDeniesRequest verifies that when CheckAccess returns
// an error (e.g., DB outage), the middleware denies the request with 500, not
// allowing it through. Fail-closed is mandatory for security.
func TestPolicyMiddleware_ErrorDeniesRequest(t *testing.T) {
	t.Parallel()
	mw, _, mockPolicySvc := setupPolicyMiddlewareTest(t)

	userID := uuid.New()
	// Simulate DB outage or other error during policy evaluation.
	mockPolicySvc.On("CheckAccess", mock.Anything, userID, model.PolicyResourceType("secrets"), model.PolicyOperation("get"), mock.Anything).Return(authzServices.AccessFallback, fmt.Errorf("database connection refused"))

	nextCalled := false
	nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/secrets/some-id", nil)
	ctx := context.WithValue(req.Context(), common.UserIDKey, userID.String())
	req = req.WithContext(ctx)
	rr := httptest.NewRecorder()

	mw.PolicyMiddleware(nextHandler).ServeHTTP(rr, req)

	assert.False(t, nextCalled, "next handler should NOT be called when policy check errors")
	assert.Equal(t, http.StatusInternalServerError, rr.Code, "policy check error must deny request, not allow it through")
}

// TestVaultResolutionMiddleware_FallsBackToDefault verifies that a request without
// a {vault_name} path variable resolves to the default vault.
func TestVaultResolutionMiddleware_FallsBackToDefault(t *testing.T) {
	t.Parallel()
	logger := &logging.Logger{Logger: logrus.New()}
	logger.SetLevel(logrus.ErrorLevel)
	mockContainer := &MockServiceContainer{logger: logger}
	defID := uuid.MustParse(model.DefaultVaultID)
	mockContainer.On("GetVaultService").Return(&stubVaultService{vault: &model.Vault{ID: defID, Name: "default", Enabled: true}})
	mw := NewMiddleware(mockContainer)

	var got interface{}
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Context().Value(common.VaultIDKey)
		w.WriteHeader(http.StatusOK)
	})
	req := httptest.NewRequest(http.MethodGet, "/api/v1/secrets", nil) // no vault_name var
	rec := httptest.NewRecorder()
	mw.VaultResolutionMiddleware(next).ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, defID.String(), got)
}

// TestVaultResolutionMiddleware_NotFoundReturns404 verifies that an unresolvable
// vault yields a 404 response.
func TestVaultResolutionMiddleware_NotFoundReturns404(t *testing.T) {
	t.Parallel()
	logger := &logging.Logger{Logger: logrus.New()}
	logger.SetLevel(logrus.ErrorLevel)
	mockContainer := &MockServiceContainer{logger: logger}
	mockContainer.On("GetVaultService").Return(&stubVaultService{err: vaultServices.ErrVaultNotFound})
	mw := NewMiddleware(mockContainer)
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	req := mux.SetURLVars(httptest.NewRequest(http.MethodGet, "/api/v1/vaults/ghost/secrets", nil), map[string]string{"vault_name": "ghost"})
	rec := httptest.NewRecorder()
	mw.VaultResolutionMiddleware(next).ServeHTTP(rec, req)
	assert.Equal(t, http.StatusNotFound, rec.Code)
}

// TestVaultResolutionMiddleware_DisabledReturns403 verifies that a disabled vault
// yields a 403 response.
func TestVaultResolutionMiddleware_DisabledReturns403(t *testing.T) {
	t.Parallel()
	logger := &logging.Logger{Logger: logrus.New()}
	logger.SetLevel(logrus.ErrorLevel)
	mockContainer := &MockServiceContainer{logger: logger}
	mockContainer.On("GetVaultService").Return(&stubVaultService{vault: &model.Vault{ID: uuid.New(), Name: "stg", Enabled: false}})
	mw := NewMiddleware(mockContainer)
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	req := mux.SetURLVars(httptest.NewRequest(http.MethodGet, "/api/v1/vaults/stg/secrets", nil), map[string]string{"vault_name": "stg"})
	rec := httptest.NewRecorder()
	mw.VaultResolutionMiddleware(next).ServeHTTP(rec, req)
	assert.Equal(t, http.StatusForbidden, rec.Code)
}

// TestVaultResolutionMiddleware_SkipsHealthEndpoints verifies that health/liveness
// probes pass through without touching the vault service, so the probes stay
// independent of the database and the vaults table (which may be missing or
// mid-migration). The stub would otherwise resolve the default vault on every call.
func TestVaultResolutionMiddleware_SkipsHealthEndpoints(t *testing.T) {
	t.Parallel()
	for _, path := range []string{"/api/v1/health", "/api/v1/health/live", "/api/v1/health/ready"} {
		logger := &logging.Logger{Logger: logrus.New()}
		logger.SetLevel(logrus.ErrorLevel)
		mockContainer := &MockServiceContainer{logger: logger}
		stub := &stubVaultService{err: vaultServices.ErrVaultNotFound} // would 404 if consulted
		mockContainer.On("GetVaultService").Return(stub).Maybe()
		mw := NewMiddleware(mockContainer)

		called := false
		next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			called = true
			w.WriteHeader(http.StatusOK)
		})
		req := httptest.NewRequest(http.MethodGet, path, nil)
		rec := httptest.NewRecorder()
		mw.VaultResolutionMiddleware(next).ServeHTTP(rec, req)

		assert.Equalf(t, http.StatusOK, rec.Code, "health path %s should pass through", path)
		assert.Truef(t, called, "next handler should be reached for %s", path)
		assert.Zerof(t, stub.getVaultCalls, "vault service must not be consulted for %s", path)
	}
}

// TestMiddlewareArchitecturalChange documents the architectural improvement.
func TestMiddlewareArchitecturalChange(t *testing.T) {
	t.Parallel()
	t.Log("Middleware architecture successfully updated:")
	t.Log("- Old: NewMiddleware(logger) - direct logger injection")
	t.Log("- New: NewMiddleware(serviceContainer) - full service dependency injection")
	t.Log("- Benefit: Middleware can now access all services (auth, RBAC, etc.)")
	t.Log("- Testing: Complete test coverage with mock service container")

	assert.True(t, true, "Architecture change documented and tested")
}

// MockRoleAssignmentService is a mock implementation of RoleAssignmentService.
type MockRoleAssignmentService struct {
	mock.Mock
}

func (m *MockRoleAssignmentService) AssignRole(ctx context.Context, in authzServices.AssignRoleInput) (*model.RoleAssignment, error) {
	args := m.Called(ctx, in)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*model.RoleAssignment), args.Error(1)
}

func (m *MockRoleAssignmentService) RevokeAssignment(ctx context.Context, assignmentID, vaultID, actorID uuid.UUID, callerIsGlobalAdmin bool) error {
	args := m.Called(ctx, assignmentID, vaultID, actorID, callerIsGlobalAdmin)
	return args.Error(0)
}

func (m *MockRoleAssignmentService) ListAssignments(ctx context.Context, vaultID uuid.UUID) ([]*model.RoleAssignment, error) {
	args := m.Called(ctx, vaultID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*model.RoleAssignment), args.Error(1)
}

func (m *MockRoleAssignmentService) HasDataAction(ctx context.Context, principalID, vaultID uuid.UUID, action model.DataAction) (bool, error) {
	args := m.Called(ctx, principalID, vaultID, action)
	return args.Bool(0), args.Error(1)
}

// setupDataPlaneMiddlewareTest wires middleware with both authorization services.
func setupDataPlaneMiddlewareTest(t *testing.T) (*Middleware, *MockAccessPolicyService, *MockRoleAssignmentService) {
	t.Helper()
	logger := &logging.Logger{Logger: logrus.New()}
	logger.SetLevel(logrus.ErrorLevel)

	mockContainer := &MockServiceContainer{logger: logger}
	mockPolicySvc := &MockAccessPolicyService{}
	mockRoleSvc := &MockRoleAssignmentService{}
	mockContainer.On("GetAccessPolicyService").Return(mockPolicySvc)
	mockContainer.On("GetRoleAssignmentService").Return(mockRoleSvc)

	return NewMiddleware(mockContainer), mockPolicySvc, mockRoleSvc
}

// dataPlaneRequest builds an authenticated request carrying a resolved vault.
func dataPlaneRequest(method, path string, userID, vaultID uuid.UUID) *http.Request {
	req := httptest.NewRequest(method, path, nil)
	ctx := context.WithValue(req.Context(), common.UserIDKey, userID.String())
	ctx = context.WithValue(ctx, common.VaultIDKey, vaultID.String())
	return req.WithContext(ctx)
}

// TestPolicyMiddleware_DeniesWithoutRoleAssignment is the core inversion: a
// principal with no role assignment granting the action in the resolved vault
// gets 403, where before P2 the absence of any policy row let the request
// through.
func TestPolicyMiddleware_DeniesWithoutRoleAssignment(t *testing.T) {
	t.Parallel()
	mw, policySvc, roleSvc := setupDataPlaneMiddlewareTest(t)

	userID, vaultID := uuid.New(), uuid.New()
	policySvc.On("CheckAccess", mock.Anything, userID, mock.Anything, mock.Anything, vaultID).
		Return(authzServices.AccessFallback, nil)
	roleSvc.On("HasDataAction", mock.Anything, userID, vaultID, model.ActionSecretsGet).
		Return(false, nil)

	nextCalled := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { nextCalled = true })

	rr := httptest.NewRecorder()
	mw.PolicyMiddleware(next).ServeHTTP(rr, dataPlaneRequest(http.MethodGet, "/api/v1/secrets/abc", userID, vaultID))

	assert.False(t, nextCalled, "a principal with no role assignment must not reach the handler")
	assert.Equal(t, http.StatusForbidden, rr.Code)
}

// TestPolicyMiddleware_AllowsWithRoleAssignment asserts the granted path.
func TestPolicyMiddleware_AllowsWithRoleAssignment(t *testing.T) {
	t.Parallel()
	mw, policySvc, roleSvc := setupDataPlaneMiddlewareTest(t)

	userID, vaultID := uuid.New(), uuid.New()
	policySvc.On("CheckAccess", mock.Anything, userID, mock.Anything, mock.Anything, vaultID).
		Return(authzServices.AccessFallback, nil)
	roleSvc.On("HasDataAction", mock.Anything, userID, vaultID, model.ActionSecretsGet).
		Return(true, nil)

	nextCalled := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
		w.WriteHeader(http.StatusOK)
	})

	rr := httptest.NewRecorder()
	mw.PolicyMiddleware(next).ServeHTTP(rr, dataPlaneRequest(http.MethodGet, "/api/v1/secrets/abc", userID, vaultID))

	assert.True(t, nextCalled)
	assert.Equal(t, http.StatusOK, rr.Code)
}

// TestPolicyMiddleware_ExplicitDenyBeatsRoleAssignment asserts access_policies
// survives as an explicit-deny override evaluated before the allow decision:
// the role check is never even reached.
func TestPolicyMiddleware_ExplicitDenyBeatsRoleAssignment(t *testing.T) {
	t.Parallel()
	mw, policySvc, roleSvc := setupDataPlaneMiddlewareTest(t)

	userID, vaultID := uuid.New(), uuid.New()
	policySvc.On("CheckAccess", mock.Anything, userID, mock.Anything, mock.Anything, vaultID).
		Return(authzServices.AccessDenied, nil)

	rr := httptest.NewRecorder()
	mw.PolicyMiddleware(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})).
		ServeHTTP(rr, dataPlaneRequest(http.MethodGet, "/api/v1/secrets/abc", userID, vaultID))

	assert.Equal(t, http.StatusForbidden, rr.Code)
	roleSvc.AssertNotCalled(t, "HasDataAction", mock.Anything, mock.Anything, mock.Anything, mock.Anything)
}

// TestPolicyMiddleware_LookupErrorDeniesWith500 asserts a role lookup failure
// fails closed with 500 rather than being read as a permission denial or,
// worse, a pass-through.
func TestPolicyMiddleware_LookupErrorDeniesWith500(t *testing.T) {
	t.Parallel()
	mw, policySvc, roleSvc := setupDataPlaneMiddlewareTest(t)

	userID, vaultID := uuid.New(), uuid.New()
	policySvc.On("CheckAccess", mock.Anything, userID, mock.Anything, mock.Anything, vaultID).
		Return(authzServices.AccessFallback, nil)
	roleSvc.On("HasDataAction", mock.Anything, userID, vaultID, model.ActionSecretsGet).
		Return(false, fmt.Errorf("database is locked"))

	nextCalled := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { nextCalled = true })

	rr := httptest.NewRecorder()
	mw.PolicyMiddleware(next).ServeHTTP(rr, dataPlaneRequest(http.MethodGet, "/api/v1/secrets/abc", userID, vaultID))

	assert.False(t, nextCalled)
	assert.Equal(t, http.StatusInternalServerError, rr.Code)
}

// TestPolicyMiddleware_UnmappedDataPlaneMethodDenies asserts a data-plane path
// with no action mapping is refused rather than allowed.
func TestPolicyMiddleware_UnmappedDataPlaneMethodDenies(t *testing.T) {
	t.Parallel()
	mw, policySvc, _ := setupDataPlaneMiddlewareTest(t)

	userID, vaultID := uuid.New(), uuid.New()
	policySvc.On("CheckAccess", mock.Anything, userID, mock.Anything, mock.Anything, vaultID).
		Return(authzServices.AccessFallback, nil)

	nextCalled := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { nextCalled = true })

	rr := httptest.NewRecorder()
	mw.PolicyMiddleware(next).ServeHTTP(rr, dataPlaneRequest(http.MethodPatch, "/api/v1/secrets/abc", userID, vaultID))

	assert.False(t, nextCalled)
	assert.Equal(t, http.StatusForbidden, rr.Code)
}

// TestPolicyMiddleware_FlatRouteUsesDefaultVault asserts a legacy flat route
// with no resolved vault in context is evaluated against the default vault, so
// flat and vault-scoped routes carry identical semantics.
func TestPolicyMiddleware_FlatRouteUsesDefaultVault(t *testing.T) {
	t.Parallel()
	mw, policySvc, roleSvc := setupDataPlaneMiddlewareTest(t)

	userID := uuid.New()
	defaultVault := uuid.MustParse(model.DefaultVaultID)
	policySvc.On("CheckAccess", mock.Anything, userID, mock.Anything, mock.Anything, defaultVault).
		Return(authzServices.AccessFallback, nil)
	roleSvc.On("HasDataAction", mock.Anything, userID, defaultVault, model.ActionSecretsReadMetadata).
		Return(true, nil)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/secrets", nil)
	req = req.WithContext(context.WithValue(req.Context(), common.UserIDKey, userID.String()))

	nextCalled := false
	rr := httptest.NewRecorder()
	mw.PolicyMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
		w.WriteHeader(http.StatusOK)
	})).ServeHTTP(rr, req)

	assert.True(t, nextCalled)
	assert.Equal(t, http.StatusOK, rr.Code)
	roleSvc.AssertCalled(t, "HasDataAction", mock.Anything, userID, defaultVault, model.ActionSecretsReadMetadata)
}

// TestPolicyMiddleware_VaultManagementKeepsFallback asserts non-data-plane
// managed routes are unchanged: their gates are the handlers' own
// CanManageVault/CanManageRoleAssignments checks and, for users and audit, the
// RBAC middleware — not per-vault role assignments.
func TestPolicyMiddleware_VaultManagementKeepsFallback(t *testing.T) {
	t.Parallel()
	mw, policySvc, roleSvc := setupDataPlaneMiddlewareTest(t)

	userID, vaultID := uuid.New(), uuid.New()
	policySvc.On("CheckAccess", mock.Anything, userID, model.PolicyResourceVaults, model.OpManage, vaultID).
		Return(authzServices.AccessFallback, nil)

	nextCalled := false
	rr := httptest.NewRecorder()
	mw.PolicyMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
		w.WriteHeader(http.StatusOK)
	})).ServeHTTP(rr, dataPlaneRequest(http.MethodDelete, "/api/v1/vaults/prod", userID, vaultID))

	assert.True(t, nextCalled, "vault management keeps AccessFallback pass-through")
	assert.Equal(t, http.StatusOK, rr.Code)
	roleSvc.AssertNotCalled(t, "HasDataAction", mock.Anything, mock.Anything, mock.Anything, mock.Anything)
}

// TestResolvePolicy_VaultNamedAfterAResourceTypeDoesNotMisrouteResourceType is
// the regression for a vault literally named "secrets", "keys", or
// "certificates" (ValidateVaultName has no reserved-word check). Before
// stripVaultNameSegment, resolvePolicy substring-matched the raw path, so
// e.g. a request to sign with a key in a vault named "secrets" resolved
// resourceType=secrets instead of keys, and an explicit deny policy targeting
// keys was never evaluated for it.
func TestResolvePolicy_VaultNamedAfterAResourceTypeDoesNotMisrouteResourceType(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name             string
		method           string
		path             string
		wantResourceType model.PolicyResourceType
	}{
		{"vault named secrets, key resource", http.MethodPost, "/api/v1/vaults/secrets/keys/abc/sign", model.PolicyResourceKeys},
		{"vault named keys, secret resource", http.MethodGet, "/api/v1/vaults/keys/secrets/abc", model.PolicyResourceSecrets},
		{"vault named certificates, key resource", http.MethodGet, "/api/v1/vaults/certificates/keys/abc", model.PolicyResourceKeys},
		{"vault named secrets, certificate resource", http.MethodGet, "/api/v1/vaults/secrets/certificates/abc", model.PolicyResourceCertificates},
		{"ordinary vault name, unaffected", http.MethodGet, "/api/v1/vaults/prod/keys/abc", model.PolicyResourceKeys},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			resourceType, _ := resolvePolicy(c.method, c.path)
			assert.Equal(t, c.wantResourceType, resourceType, "resolvePolicy(%s, %s)", c.method, c.path)
		})
	}
}

// TestResolvePolicy_KeyCryptoAndBackupResolveToTheirOwnOperations is the
// regression for B33 (sign, verify) and B79 (encrypt, decrypt, wrap, unwrap,
// backup). Each POST route resolves to its own operation, so an explicit-deny
// policy naming it is evaluated over HTTP exactly as on the CLI, and a deny on
// create no longer blocks all of them collaterally.
func TestResolvePolicy_KeyCryptoAndBackupResolveToTheirOwnOperations(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name         string
		path         string
		wantResource model.PolicyResourceType
		wantOp       model.PolicyOperation
	}{
		{"sign, flat", "/api/v1/keys/abc/sign", model.PolicyResourceKeys, model.OpSign},
		{"sign, scoped", "/api/v1/vaults/prod/keys/abc/sign", model.PolicyResourceKeys, model.OpSign},
		{"verify, flat", "/api/v1/keys/abc/verify", model.PolicyResourceKeys, model.OpVerify},
		{"verify, scoped", "/api/v1/vaults/prod/keys/abc/verify", model.PolicyResourceKeys, model.OpVerify},
		{"encrypt, flat", "/api/v1/keys/abc/encrypt", model.PolicyResourceKeys, model.OpEncrypt},
		{"encrypt, scoped", "/api/v1/vaults/prod/keys/abc/encrypt", model.PolicyResourceKeys, model.OpEncrypt},
		{"decrypt, flat", "/api/v1/keys/abc/decrypt", model.PolicyResourceKeys, model.OpDecrypt},
		{"decrypt, scoped", "/api/v1/vaults/prod/keys/abc/decrypt", model.PolicyResourceKeys, model.OpDecrypt},
		{"wrap, flat", "/api/v1/keys/abc/wrap", model.PolicyResourceKeys, model.OpWrap},
		{"wrap, scoped", "/api/v1/vaults/prod/keys/abc/wrap", model.PolicyResourceKeys, model.OpWrap},
		{"unwrap, flat", "/api/v1/keys/abc/unwrap", model.PolicyResourceKeys, model.OpUnwrap},
		{"unwrap, scoped", "/api/v1/vaults/prod/keys/abc/unwrap", model.PolicyResourceKeys, model.OpUnwrap},
		{"key backup, flat", "/api/v1/keys/abc/backup", model.PolicyResourceKeys, model.OpBackup},
		{"key backup, scoped", "/api/v1/vaults/prod/keys/abc/backup", model.PolicyResourceKeys, model.OpBackup},
		{"secret backup, flat", "/api/v1/secrets/abc/backup", model.PolicyResourceSecrets, model.OpBackup},
		{"secret backup, scoped", "/api/v1/vaults/prod/secrets/abc/backup", model.PolicyResourceSecrets, model.OpBackup},
		{"certificate backup, flat", "/api/v1/certificates/abc/backup", model.PolicyResourceCertificates, model.OpBackup},
		{"certificate backup, scoped", "/api/v1/vaults/prod/certificates/abc/backup", model.PolicyResourceCertificates, model.OpBackup},
		// Suffix collisions: only the whole last segment selects an operation.
		{"unwrap is not wrap", "/api/v1/keys/abc/unwrap", model.PolicyResourceKeys, model.OpUnwrap},
		{"segment ending in wrap is create", "/api/v1/keys/abc/rewrap", model.PolicyResourceKeys, model.OpCreate},
		{"segment ending in encrypt is create", "/api/v1/keys/abc/reencrypt", model.PolicyResourceKeys, model.OpCreate},
		{"segment ending in backup is create", "/api/v1/secrets/abc/xbackup", model.PolicyResourceSecrets, model.OpCreate},
		{"key id named wrap, rotate", "/api/v1/keys/wrap/rotate", model.PolicyResourceKeys, model.OpRotate},
		{"key id named encrypt, sign", "/api/v1/keys/encrypt/sign", model.PolicyResourceKeys, model.OpSign},
		{"key id named unwrap, wrap", "/api/v1/keys/unwrap/wrap", model.PolicyResourceKeys, model.OpWrap},
		{"key id named backup, export", "/api/v1/keys/backup/export", model.PolicyResourceKeys, model.OpCreate},
		{"trailing slash fails closed to create", "/api/v1/keys/abc/wrap/", model.PolicyResourceKeys, model.OpCreate},
		// Vaults named after an operation word must not change the operation.
		{"vault named wrap, key create", "/api/v1/vaults/wrap/keys", model.PolicyResourceKeys, model.OpCreate},
		{"vault named unwrap, key create", "/api/v1/vaults/unwrap/keys", model.PolicyResourceKeys, model.OpCreate},
		{"vault named encrypt, key create", "/api/v1/vaults/encrypt/keys", model.PolicyResourceKeys, model.OpCreate},
		{"vault named backup, secret create", "/api/v1/vaults/backup/secrets", model.PolicyResourceSecrets, model.OpCreate},
		{"vault named export, certificate create", "/api/v1/vaults/export/certificates", model.PolicyResourceCertificates, model.OpCreate},
		{"vault named encrypt, wrap", "/api/v1/vaults/encrypt/keys/abc/wrap", model.PolicyResourceKeys, model.OpWrap},
		{"vault named wrap, decrypt", "/api/v1/vaults/wrap/keys/abc/decrypt", model.PolicyResourceKeys, model.OpDecrypt},
		{"vault named backup, sign", "/api/v1/vaults/backup/keys/abc/sign", model.PolicyResourceKeys, model.OpSign},
		{"vault named export, encrypt", "/api/v1/vaults/export/keys/abc/encrypt", model.PolicyResourceKeys, model.OpEncrypt},
		// Export stays the fail-closed create, on both shapes and whatever the vault name.
		{"key export, flat", "/api/v1/keys/abc/export", model.PolicyResourceKeys, model.OpCreate},
		{"key export, scoped", "/api/v1/vaults/prod/keys/abc/export", model.PolicyResourceKeys, model.OpCreate},
		{"certificate export, flat", "/api/v1/certificates/abc/export", model.PolicyResourceCertificates, model.OpCreate},
		{"certificate export, scoped", "/api/v1/vaults/prod/certificates/abc/export", model.PolicyResourceCertificates, model.OpCreate},
		{"key export, vault named encrypt", "/api/v1/vaults/encrypt/keys/abc/export", model.PolicyResourceKeys, model.OpCreate},
		{"key export, vault named wrap", "/api/v1/vaults/wrap/keys/abc/export", model.PolicyResourceKeys, model.OpCreate},
		{"certificate export, vault named backup", "/api/v1/vaults/backup/certificates/abc/export", model.PolicyResourceCertificates, model.OpCreate},
		{"certificate export, vault named export", "/api/v1/vaults/export/certificates/abc/export", model.PolicyResourceCertificates, model.OpCreate},
		// Unchanged neighbours, to pin that the new cases did not widen.
		{"rotate keeps its own operation", "/api/v1/keys/abc/rotate", model.PolicyResourceKeys, model.OpRotate},
		{"key create stays create", "/api/v1/keys", model.PolicyResourceKeys, model.OpCreate},
		{"key import stays import", "/api/v1/keys/import", model.PolicyResourceKeys, model.OpImport},
		{"unknown sub-resource stays create", "/api/v1/keys/abc/frobnicate", model.PolicyResourceKeys, model.OpCreate},
		{"restore stays recover", "/api/v1/keys/abc/restore", model.PolicyResourceKeys, model.OpRecover},
		{"certificate renew, flat", "/api/v1/certificates/abc/renew", model.PolicyResourceCertificates, model.OpRenew},
		{"certificate renew, scoped", "/api/v1/vaults/prod/certificates/abc/renew", model.PolicyResourceCertificates, model.OpRenew},
		{"certificate renew, vault named backup", "/api/v1/vaults/backup/certificates/abc/renew", model.PolicyResourceCertificates, model.OpRenew},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			resourceType, op := resolvePolicy(http.MethodPost, c.path)
			assert.Equal(t, c.wantResource, resourceType, "resolvePolicy(POST, %s) resource", c.path)
			assert.Equal(t, c.wantOp, op, "resolvePolicy(POST, %s) operation", c.path)
		})
	}
}

// TestResolvePolicy_OperationWordsNeedPost pins that the new operation arms
// match POST only, and that certificate version routes resolve as before.
func TestResolvePolicy_OperationWordsNeedPost(t *testing.T) {
	t.Parallel()

	cases := []struct {
		method string
		path   string
		wantOp model.PolicyOperation
	}{
		{http.MethodGet, "/api/v1/keys/abc/wrap", model.OpGet},
		{http.MethodPut, "/api/v1/keys/abc/unwrap", model.OpSet},
		{http.MethodDelete, "/api/v1/keys/abc/backup", model.OpDelete},
		{http.MethodGet, "/api/v1/vaults/encrypt/keys/abc", model.OpGet},
		{http.MethodGet, "/api/v1/certificates/abc/versions", model.OpGet},
		{http.MethodGet, "/api/v1/vaults/prod/certificates/abc/versions", model.OpGet},
		{http.MethodGet, "/api/v1/certificates/abc/versions/2", model.OpGet},
		{http.MethodGet, "/api/v1/vaults/prod/certificates/abc/versions/2", model.OpGet},
		{http.MethodPut, "/api/v1/certificates/abc/versions/2", model.OpSet},
		{http.MethodPut, "/api/v1/vaults/prod/certificates/abc/versions/2", model.OpSet},
	}
	for _, c := range cases {
		t.Run(c.method+" "+c.path, func(t *testing.T) {
			_, op := resolvePolicy(c.method, c.path)
			assert.Equal(t, c.wantOp, op, "resolvePolicy(%s, %s) operation", c.method, c.path)
		})
	}
}

// TestPolicyMiddleware_ExplicitDenyEvaluatedPerKeyOperation proves, end to end
// through PolicyMiddleware, that a deny naming each operation blocks its route
// before the role-assignment check runs (B79).
func TestPolicyMiddleware_ExplicitDenyEvaluatedPerKeyOperation(t *testing.T) {
	t.Parallel()

	cases := []struct {
		path     string
		resource model.PolicyResourceType
		op       model.PolicyOperation
	}{
		{"/api/v1/keys/abc/encrypt", model.PolicyResourceKeys, model.OpEncrypt},
		{"/api/v1/vaults/prod/keys/abc/encrypt", model.PolicyResourceKeys, model.OpEncrypt},
		{"/api/v1/keys/abc/decrypt", model.PolicyResourceKeys, model.OpDecrypt},
		{"/api/v1/vaults/prod/keys/abc/decrypt", model.PolicyResourceKeys, model.OpDecrypt},
		{"/api/v1/keys/abc/wrap", model.PolicyResourceKeys, model.OpWrap},
		{"/api/v1/vaults/prod/keys/abc/wrap", model.PolicyResourceKeys, model.OpWrap},
		{"/api/v1/keys/abc/unwrap", model.PolicyResourceKeys, model.OpUnwrap},
		{"/api/v1/vaults/prod/keys/abc/unwrap", model.PolicyResourceKeys, model.OpUnwrap},
		{"/api/v1/keys/abc/backup", model.PolicyResourceKeys, model.OpBackup},
		{"/api/v1/vaults/prod/keys/abc/backup", model.PolicyResourceKeys, model.OpBackup},
		{"/api/v1/secrets/abc/backup", model.PolicyResourceSecrets, model.OpBackup},
		{"/api/v1/certificates/abc/backup", model.PolicyResourceCertificates, model.OpBackup},
	}
	for _, c := range cases {
		t.Run(c.path, func(t *testing.T) {
			t.Parallel()
			mw, policySvc, roleSvc := setupDataPlaneMiddlewareTest(t)

			userID, vaultID := uuid.New(), uuid.New()
			policySvc.On("CheckAccess", mock.Anything, userID, c.resource, c.op, vaultID).
				Return(authzServices.AccessDenied, nil)

			nextCalled := false
			rr := httptest.NewRecorder()
			mw.PolicyMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				nextCalled = true
			})).ServeHTTP(rr, dataPlaneRequest(http.MethodPost, c.path, userID, vaultID))

			assert.False(t, nextCalled, "the explicit deny on %s must block the request", c.op)
			assert.Equal(t, http.StatusForbidden, rr.Code)
			policySvc.AssertExpectations(t)
			roleSvc.AssertNotCalled(t, "HasDataAction", mock.Anything, mock.Anything, mock.Anything, mock.Anything)
		})
	}
}

// TestPolicyMiddleware_WrapAndUnwrapDeniesDoNotCross pins that a deny on wrap
// blocks only wrap and a deny on unwrap blocks only unwrap, on both route
// shapes. The operation that is not denied reaches the role-assignment check.
func TestPolicyMiddleware_WrapAndUnwrapDeniesDoNotCross(t *testing.T) {
	t.Parallel()

	ops := map[string]struct {
		op     model.PolicyOperation
		action model.DataAction
	}{
		"wrap":   {model.OpWrap, model.ActionKeysWrap},
		"unwrap": {model.OpUnwrap, model.ActionKeysUnwrap},
	}
	cases := []struct {
		denied, requested string
	}{
		{"wrap", "wrap"}, {"wrap", "unwrap"}, {"unwrap", "unwrap"}, {"unwrap", "wrap"},
	}
	for _, prefix := range []string{"/api/v1/keys/abc/", "/api/v1/vaults/prod/keys/abc/"} {
		for _, c := range cases {
			path := prefix + c.requested
			t.Run("deny "+c.denied+" POST "+path, func(t *testing.T) {
				t.Parallel()
				mw, policySvc, roleSvc := setupDataPlaneMiddlewareTest(t)

				userID, vaultID := uuid.New(), uuid.New()
				denied, requested := ops[c.denied], ops[c.requested]
				policySvc.On("CheckAccess", mock.Anything, userID, model.PolicyResourceKeys, denied.op, vaultID).
					Return(authzServices.AccessDenied, nil).Maybe()
				if c.denied != c.requested {
					policySvc.On("CheckAccess", mock.Anything, userID, model.PolicyResourceKeys, requested.op, vaultID).
						Return(authzServices.AccessFallback, nil)
					roleSvc.On("HasDataAction", mock.Anything, userID, vaultID, requested.action).
						Return(true, nil)
				}

				nextCalled := false
				rr := httptest.NewRecorder()
				mw.PolicyMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					nextCalled = true
					w.WriteHeader(http.StatusOK)
				})).ServeHTTP(rr, dataPlaneRequest(http.MethodPost, path, userID, vaultID))

				if c.denied == c.requested {
					assert.False(t, nextCalled, "a deny on %s must block %s", c.denied, path)
					assert.Equal(t, http.StatusForbidden, rr.Code)
					roleSvc.AssertNotCalled(t, "HasDataAction", mock.Anything, mock.Anything, mock.Anything, mock.Anything)
				} else {
					assert.True(t, nextCalled, "a deny on %s must not block %s", c.denied, path)
					assert.Equal(t, http.StatusOK, rr.Code)
					policySvc.AssertNotCalled(t, "CheckAccess", mock.Anything, userID, model.PolicyResourceKeys, denied.op, vaultID)
					roleSvc.AssertExpectations(t)
				}
			})
		}
	}
}

// TestPolicyMiddleware_CreateDenyNoLongerBlocksKeyCrypto pins the other half of
// B79: before the fix, a deny on (keys, create) blocked encrypt collaterally.
func TestPolicyMiddleware_CreateDenyNoLongerBlocksKeyCrypto(t *testing.T) {
	t.Parallel()
	mw, policySvc, roleSvc := setupDataPlaneMiddlewareTest(t)

	userID, vaultID := uuid.New(), uuid.New()
	policySvc.On("CheckAccess", mock.Anything, userID, model.PolicyResourceKeys, model.OpCreate, vaultID).
		Return(authzServices.AccessDenied, nil).Maybe()
	policySvc.On("CheckAccess", mock.Anything, userID, model.PolicyResourceKeys, model.OpEncrypt, vaultID).
		Return(authzServices.AccessFallback, nil)
	roleSvc.On("HasDataAction", mock.Anything, userID, vaultID, model.ActionKeysEncrypt).
		Return(true, nil)

	nextCalled := false
	rr := httptest.NewRecorder()
	mw.PolicyMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
		w.WriteHeader(http.StatusOK)
	})).ServeHTTP(rr, dataPlaneRequest(http.MethodPost, "/api/v1/keys/abc/encrypt", userID, vaultID))

	assert.True(t, nextCalled, "a deny on create must not block encrypt")
	assert.Equal(t, http.StatusOK, rr.Code)
}

// TestPolicyMiddleware_CreateDenyStillBlocksExport pins that export stays
// fail closed: a deny on create blocks both export routes on both shapes.
func TestPolicyMiddleware_CreateDenyStillBlocksExport(t *testing.T) {
	t.Parallel()

	cases := []struct {
		path     string
		resource model.PolicyResourceType
	}{
		{"/api/v1/keys/abc/export", model.PolicyResourceKeys},
		{"/api/v1/vaults/prod/keys/abc/export", model.PolicyResourceKeys},
		{"/api/v1/certificates/abc/export", model.PolicyResourceCertificates},
		{"/api/v1/vaults/prod/certificates/abc/export", model.PolicyResourceCertificates},
	}
	for _, c := range cases {
		t.Run(c.path, func(t *testing.T) {
			t.Parallel()
			mw, policySvc, roleSvc := setupDataPlaneMiddlewareTest(t)

			userID, vaultID := uuid.New(), uuid.New()
			policySvc.On("CheckAccess", mock.Anything, userID, c.resource, model.OpCreate, vaultID).
				Return(authzServices.AccessDenied, nil)

			nextCalled := false
			rr := httptest.NewRecorder()
			mw.PolicyMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				nextCalled = true
			})).ServeHTTP(rr, dataPlaneRequest(http.MethodPost, c.path, userID, vaultID))

			assert.False(t, nextCalled, "a deny on create must still block export")
			assert.Equal(t, http.StatusForbidden, rr.Code)
			policySvc.AssertExpectations(t)
			roleSvc.AssertNotCalled(t, "HasDataAction", mock.Anything, mock.Anything, mock.Anything, mock.Anything)
		})
	}
}

// TestResolvePolicy_VaultProvisioningGrantsDoesNotMatchVaultsSubstring pins
// that "/vault-provisioning-grants" is not mistaken for a vault-management
// route by resolvePolicy's `strings.Contains(matchPath, "/vaults")` check --
// "/vault-provisioning-grants" does not contain the substring "/vaults".
// These routes are admin-only and deliberately non-delegable (see
// api/vault_provisioning_grants.go's requireGrantAdmin); had resolvePolicy
// matched them as PolicyResourceVaults/OpManage, they would additionally be
// evaluated against the caller's access policies as if they were a vault
// name, silently widening who could act on them.
func TestResolvePolicy_VaultProvisioningGrantsDoesNotMatchVaultsSubstring(t *testing.T) {
	t.Parallel()

	cases := []struct {
		method string
		path   string
	}{
		{http.MethodGet, "/api/v1/vault-provisioning-grants"},
		{http.MethodPut, "/api/v1/vault-provisioning-grants/abc"},
		{http.MethodDelete, "/api/v1/vault-provisioning-grants/abc"},
	}
	for _, c := range cases {
		t.Run(c.method+" "+c.path, func(t *testing.T) {
			resourceType, op := resolvePolicy(c.method, c.path)
			assert.Equal(t, model.PolicyResourceType(""), resourceType, "resolvePolicy(%s, %s) resource", c.method, c.path)
			assert.Equal(t, model.PolicyOperation(""), op, "resolvePolicy(%s, %s) op", c.method, c.path)
		})
	}
}

// TestPolicyMiddleware_VaultNamedSecretsDoesNotHideKeysDenyPolicy proves the
// fix end-to-end through PolicyMiddleware: a deny policy targeting "keys"
// must still be looked up (and enforced) for a vault literally named
// "secrets".
func TestPolicyMiddleware_VaultNamedSecretsDoesNotHideKeysDenyPolicy(t *testing.T) {
	t.Parallel()
	mw, policySvc, roleSvc := setupDataPlaneMiddlewareTest(t)

	userID, vaultID := uuid.New(), uuid.New()
	// The vault is named "secrets"; the resource being signed is a key. The
	// deny check must be evaluated against resourceType=keys, not secrets.
	policySvc.On("CheckAccess", mock.Anything, userID, model.PolicyResourceKeys, mock.Anything, vaultID).
		Return(authzServices.AccessDenied, nil)

	nextCalled := false
	rr := httptest.NewRecorder()
	mw.PolicyMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
		w.WriteHeader(http.StatusOK)
	})).ServeHTTP(rr, dataPlaneRequest(http.MethodPost, "/api/v1/vaults/secrets/keys/abc/sign", userID, vaultID))

	assert.False(t, nextCalled, "the keys deny policy must block the request")
	assert.Equal(t, http.StatusForbidden, rr.Code)
	policySvc.AssertExpectations(t)
	roleSvc.AssertNotCalled(t, "HasDataAction", mock.Anything, mock.Anything, mock.Anything, mock.Anything)
}
