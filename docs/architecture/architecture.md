# Architecture, DI, patterns and testing

Moved verbatim out of the project CLAUDE.md on 2026-10-20 to keep it short.

## Architecture Overview

```
rocketvault/
├── cmd/                    # CLI commands (Cobra-based)
│   ├── vaults/             # Vault lifecycle commands (create, list, delete, ...)
│   ├── vault-access/       # Per-vault role assignment commands (grant, list, revoke, roles)
│   ├── vaultcli/           # Shared CLI authorization primitives (ResolveVaultID, RequireDataAction)
│   ├── certificates/       # Certificate management commands
│   ├── keys/                # Key management commands
│   ├── secrets/            # Secret management commands
│   ├── users/               # User management commands
│   └── audit/               # Audit log query commands
├── api/                    # HTTP API layer with service integration
├── app/                    # Application core and options
├── bootstrap/              # Application initialization (SRP-compliant)
├── common/                 # Shared CLI/API helpers: vault-flag resolution, auth context, encryption, i18n
├── examples/
│   └── consumer-service/  # Example service demonstrating vault-client secret consumption
├── model/                  # Pure domain types and constants (DDD)
│   ├── user.go            # User, Claims, Role constants
│   ├── secret.go          # Secret domain type
│   ├── key.go             # Key domain type
│   ├── certificate.go     # Certificate domain type
│   ├── vault.go           # Vault, DefaultVaultID, name/tag validation
│   ├── scope.go           # Scope authorization value object
│   └── azure_roles.go     # Azure Key Vault-parity built-in role definitions and data actions
├── internal/
│   ├── services/          # Business logic services (SRP-compliant)
│   │   ├── auth/          # Authentication services (password, TOTP, JWT, OIDC)
│   │   ├── users/         # User management services
│   │   ├── secrets/       # Secret management services (4 focused services)
│   │   ├── keys/          # Key management services
│   │   ├── certificates/  # Certificate management services
│   │   ├── vaults/        # Vault lifecycle and cascade soft-delete/recover
│   │   ├── authorization/ # RBAC, access-policy, and per-vault role-assignment services
│   │   ├── softdelete/    # Background scheduler that purges soft-deleted items past retention
│   │   ├── oauth2/        # OAuth2 client-credentials grant for service accounts
│   │   ├── audit/         # Audit log persistence and compliance reporting
│   │   └── retry/         # Retry-aware service wrappers
│   ├── repositories/      # Pure CRUD data access with interfaces
│   │   ├── user_repository.go         # UserRepositoryInterface + implementation
│   │   ├── secret_repository.go       # Secret data access
│   │   ├── key_repository.go          # Key data access
│   │   └── certificate_repository.go  # Certificate data access
│   ├── container/         # Dependency injection container
│   ├── middleware/        # HTTP middleware (SRP-compliant)
│   ├── backup/            # Backup and restore functionality
│   ├── cache/              # Secret caching layer, wraps cachekit
│   ├── cachekit/          # Generic TTL+LRU cache core (Cloneable/Zeroable, sync.Map-backed) shared by all domain caches
│   ├── keycache/          # In-process decrypted key cache for crypto operations, wraps cachekit
│   ├── vaultcache/        # In-process vault-by-name cache, wraps cachekit
│   ├── crypto/            # Cryptographic operations — software and PKCS#11/HSM key providers
│   ├── db/                # Database layer
│   ├── health/            # Health check endpoints
│   ├── logging/           # Structured logging
│   ├── metrics/           # Prometheus metrics
│   ├── retry/             # Retry logic and middleware
│   ├── signing/           # JWT asymmetric signing key storage (OS keychain)
│   ├── vaultclient/       # Client library for consuming secrets from a RocketVault instance
│   ├── vaultapi/          # Typed REST client for the RocketVault API (used by mcpserver; CLI remote mode next)
│   ├── mcpserver/         # Model Context Protocol server — tier-gated tool surface over vaultapi
│   └── validation/        # Input validation
├── scripts/
│   └── docsgen/            # Standalone Go module rendering the docs site (see Build and Run > Documentation)
└── config/                # Configuration management
```


## Dependency Injection Container

**Location**: `internal/container/service_container.go`

**Purpose**: Manages all service dependencies and eliminates global state

**Key Features**:
- Configuration-driven service creation
- Proper service lifecycle management
- Eliminates global variables like `db.DB`
- Enables easy testing with mock services

## Development Patterns

### Service Layer Pattern
```go
// Services orchestrate business logic
type SecretService interface {
    CreateSecret(ctx context.Context, req CreateSecretRequest) (*Secret, error)
}

// Services delegate to repositories for data access
func (s *secretService) CreateSecret(ctx context.Context, req CreateSecretRequest) (*Secret, error) {
    // Business logic
    encryptedValue, err := s.cryptoService.EncryptSecret(req.Value)

    // Data access delegation
    return s.secretRepo.Create(ctx, secret)
}
```

### Repository Pattern (Refactored)
```go
// Repositories handle ONLY data access - no business logic
type SecretRepository interface {
    Create(ctx context.Context, secret *Secret) error  // Pre-encrypted data expected
    Read(ctx context.Context, id uuid.UUID) (*Secret, error)
    Update(ctx context.Context, secret *Secret) error
    Delete(ctx context.Context, id uuid.UUID) error
}
```

### Middleware Pattern (SRP-Compliant)
```go
// Focused middleware delegates to services
func (m *Middleware) AuthenticationMiddleware(next http.Handler) http.Handler {
    // HTTP concern: extract token
    token := extractToken(r)

    // Business logic: delegate to service
    claims, err := m.container.GetAuthenticationService().ValidateSession(ctx, token)

    // HTTP concern: handle response
    next.ServeHTTP(w, r.WithContext(ctx))
}
```

## Testing Strategy

### Testing Infrastructure ✅
- **CLI Test Suite**: All CLI commands tested with 50+ test cases
  - Mock infrastructure with testify/mock framework
  - Security, authentication, and RBAC validation
  - End-to-end workflow validation
  - ✅ Type assertion issue resolved with ServiceContainerInterface pattern
- **Middleware Testing**: Comprehensive test suite with 94.9% coverage
  - Authentication and authorization middleware
  - Logging and error handling middleware
  - Rate limiting and CORS middleware
- **Service Layer Testing**: Integration tests for all service components
- **Repository Testing**: Repository pattern validation and consistency tests

**CLI Type Safety Fix (October 22, 2025)**: Implemented `ServiceContainerInterface` in `internal/container` package. Updated 16 command files across all CLI packages to use interface type assertion instead of concrete type. This eliminates type assertion panics in tests while maintaining type safety in production code.

### Service Testing (NEW)
- Each service can be tested independently with mocks
- Clear boundaries reduce test complexity
- No global state dependencies in tests

### Integration Testing
- Service container enables easy integration testing
- Mock services can be injected for specific test scenarios
