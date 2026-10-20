# CLAUDE.md archive

Historical sections moved out of the project CLAUDE.md on 2026-10-20 to cut
the per-session token cost. Nothing here is needed on every session; the code,
`git log` and `.claude/known-bugs.md` are the source of truth.

## Complete Domain-Driven Architecture Transformation ✅

### Core Architectural Problems SOLVED
- **85% Code Duplication**: Between `auth.go` and `user_repository.go` → **ELIMINATED**
- **Mixed-Responsibility Package**: `auth.go` contained domain types + repository + helpers → **SEPARATED**
- **Repository Pattern Violations**: Mixed data access with business logic → **SOLVED**
- **Authentication Logic Scattered**: JWT, TOTP, password logic mixed throughout → **SOLVED**
- **Bootstrap Module Complexity**: Single setup method handled all concerns → **SOLVED**
- **Middleware Violations**: Authentication + authorization + HTTP in single method → **SOLVED**
- **API Integration Gap**: Services disconnected from API layer → **SOLVED**
- **Global State Dependencies**: Direct database access, logger globals → **SOLVED**

### Perfect Domain-Driven Design Implementation
- **`internal/auth/auth.go`**: **COMPLETELY ELIMINATED** 🎉
- **Domain Types**: Moved to `model/user.go` (User, Claims, Role constants)
- **Repository Interface**: Moved to `internal/repositories/user_repository.go`
- **Helper Functions**: Already existed in service layer (TOTPService, JWTService)
- **Zero Code Duplication**: Single source of truth for all domain concepts

### Complete Solutions Implemented
- **Service Layer Architecture**: 15+ focused services with single responsibilities
- **Dependency Injection Container**: Complete service lifecycle management with proper initialization
- **API Integration**: Full service container integration via `WithServiceContainer` option
- **Pure Repository Pattern**: Data access only, expects pre-processed data (encrypted, hashed, versioned)
- **Modular Bootstrap**: Specialized initializers (DatabaseInitializer, ServerStarter, ConfigurationValidator)
- **End-to-End Integration**: Complete flow from bootstrap → container → API → middleware → services


## Current Architecture Status

> The two subsections below are a snapshot from the October 2025 DDD refactor —
> the codebase has since grown substantially (multi-vault + Azure RBAC parity,
> see the Authorization section above). Treat specific percentages here as
> historical, not current measurements; re-run `go build ./...` / `go test ./...`
> to check current state rather than trusting a number written down a refactor
> ago.

### ✅ **Perfect Architecture Achieved** *(Oct 2025 refactor)*
- **Complete SRP Compliance**: Every component has a single, well-defined responsibility
- **Perfect Domain-Driven Design**: Domain types in `model/`, services in `services/`, repositories in `repositories/`
- **Zero Code Duplication**: Eliminated duplication between auth.go and user_repository.go (auth.go has since been removed entirely)
- **Full Dependency Injection**: End-to-end service container integration eliminates all global state
- **Clean API Integration**: Service container properly integrated with API, middleware, and handlers
- **Modern Go Architecture**: Interfaces, dependency injection, proper error handling, structured logging
- **Security-First Design**: Comprehensive auth with properly separated services (JWT + TOTP + RBAC), extended since by per-vault Azure role authorization
- **Pure Repository Pattern**: Data access expects pre-processed data, no business logic
- **Enterprise-Grade Performance**: Connection pooling, strategic indexing, performance monitoring
- **Modular Bootstrap**: Specialized initializers with clear separation of concerns
- **Testable Architecture**: Services can be tested independently with mocked dependencies

### ✅ **Major Architectural Achievements** *(Oct 2025 refactor)*
- **Auth.go Complete Elimination**: Mixed-responsibility package completely removed and reorganized
- **Domain Type Consolidation**: All user-related types in single `model/user.go` file
- **Repository Interface Separation**: Clean separation of interface from implementation
- **Service Layer Completion**: All authentication logic properly moved to service layer
- **Comprehensive CLI Test Suite**: grew from this refactor's starting point to 600+ test files project-wide today
- **Admin User Bootstrap**: Complete initial admin setup with MFA configuration
- **Service Container Integration**: CMD commands integrated with the service layer, including `KeyService` and `CertificateService`
- **Database Optimization**: Enterprise-grade connection pooling and performance monitoring

### ✅ **Recent Major Improvements (October 2025)**
- **CLI Type Safety (Oct 22)**: Implemented `ServiceContainerInterface` pattern
  - Updated 16 command files to use interface type assertion
  - Eliminated all type assertion panics in test infrastructure
  - Enhanced testability with mock-friendly interface design
- **Logging Infrastructure**: Extracted log rotation to `internal/logging` package with proper error handling
- **Middleware Testing**: Comprehensive test suite with 94.9% coverage achieved
- **Repository Pattern Standardization**: Complete documentation and migration status tracking
- **Service Container Integration**: Complete 95% compatibility achieved with all CMD commands
- **Database Optimization**: Enterprise-grade connection pooling and performance monitoring
- **Query Performance**: 90%+ improvement with strategic indexing and N+1 elimination
- **Production Monitoring**: Real-time database performance metrics and health checks

### ⚠️ **Open Bugs**
See `.claude/known-bugs.md` for the current list with root-cause analysis and fix
recipes — don't copy bug status into this file, it goes stale (the "secrets table
missing columns" bug previously listed here was already fixed on 2026-03-08, per
that file, and was left in this file as still-open for 5 months).

### 🎯 **Future Improvements**
1. **Caching Layer** - Redis integration for high-performance operation caching
2. **Enhanced CLI Features** - Additional command options and output formats
3. **API Testing Suite** - REST API comprehensive testing framework
4. **Observability Enhancement** - Prometheus metrics and distributed tracing


## Performance and Production Readiness

### ✅ **Database Optimizations Implemented**
- **Connection Pooling**: Environment-specific pool configuration (dev/staging/prod)
- **Strategic Indexing**: 25+ indexes for optimal query performance
- **Performance Monitoring**: Real-time query execution tracking and slow query detection
- **Query Optimization**: N+1 elimination and batch operation improvements

### ✅ **Monitoring and Observability**
- **Health Checks**: Enhanced database health monitoring at `/health/database`
- **Performance Metrics**: Query execution time, connection pool utilization
- **Audit Logging**: Comprehensive security event tracking with structured logs

## Documentation History

- **2026-10-03**: Certificate restore and renewal isolation (B76-B78) —
  sealed item-backup blobs, cross-vault restore link dropping, vault-scoped
  and `keys/sign`-checked auto-renewal, `keys/sign` on every certificate
  issue and renew entry point, signing-key lifecycle, and a 36500-day
  validity cap. Plan:
  `docs/superpowers/plans/2026-10-02-certificate-restore-renewal-isolation-v2.md`.
- **2026-10-02**: CLI certificate and key export — `rocketvault certificates
  export`, `rocketvault keys export` and the offline `rocketvault export open`,
  sealed by default like `secrets export`; shared `internal/services/exportaudit`
  for the HTTP and CLI audit events. Spec:
  `docs/superpowers/specs/2026-10-02-cli-certificate-and-key-export-design.md`.
- **2026-10-01**: Certificate and key export — `POST .../certificates/{id}/export`
  (PEM chain + PKCS#8 or PKCS12) and `POST .../keys/{id}/export` (software keys,
  PKCS#8) on both route shapes, the immutable `exportable` flag on every
  creation surface, `exportable`/`key_algorithm` on certificate and key
  responses, two exporter roles (thirteen built-in roles), and the new
  `software.sslmate.com/src/go-pkcs12` dependency. Plans:
  `docs/superpowers/plans/2026-10-01-export-flag-roles-creation.md`,
  `2026-10-01-certificate-export.md`, `2026-10-01-key-export-and-docs.md`.
- **2026-10-01**: Certificate versioning — `GET .../versions`, `GET|PUT .../versions/{n}`
  and `POST .../renew` on both route shapes, version-aware backup, purge and
  master-key rotation, `rocketvault certificate versions list|get`, and the
  `renew_certificate` MCP write tool (28 tools with every gated tier
  enabled, 29 once `allow_interactive_login` adds `login`; 20 with only
  `allow_write`). Plan: `docs/superpowers/plans/2026-10-01-certificate-versioning.md`.
- **2026-08-24**: Added the MCP server (`rocketvault mcp`) — a Model Context
  Protocol interface exposing the vault to Claude Code and Claude Desktop over
  stdio. Read-only by default (10 tools), with independently gated tiers for
  writes, destructive operations, crypto and secret values (28 tools fully
  enabled as of then, before `renew_certificate` — verified live via `rocketvault mcp --check` on 2026-09-03; this
  line and the MCP plan docs previously said 27, which was off by one).
  Built on a new `internal/vaultapi` typed REST client, which the
  pending CLI remote-mode work is expected to reuse. Design:
  `docs/superpowers/specs/2026-08-21-mcp-server-design.md`; guide:
  `docs/mcp-server.md`.
- **2026-08-17**: Added `.claude/roadmap-azure-parity-and-beyond.md` — a phased
  roadmap built on the parity doc's gap analysis (close remaining Azure gaps,
  then platform maturity, then self-hosted-native differentiators). README's
  `## Roadmap > Planned` section was trimmed to a checklist linking to it.
- **2026-08-11**: README and this file corrected to document the multi-vault +
  Azure RBAC architecture (shipped ~May–Aug 2026); removed 13 dead `.claude/`
  doc links and two incorrect `cmd/README_*.md` paths (the files live under
  `doc/`); removed unverifiable grade/percentage claims.
- **2025-10-22**: `ServiceContainerInterface` pattern — 16 CLI command files
  updated to interface-based type assertions, eliminating type-assertion panics
  in tests.

## Retry System Implementation ✅

### **Phase 2: Retry Logic with Exponential Backoff - COMPLETED**

Comprehensive retry system with exponential backoff, circuit breakers, and configurable policies for enhanced reliability.

#### **Core Features**
- **Exponential Backoff**: Configurable delays with jitter to prevent thundering herd
- **Circuit Breaker**: Protection against cascading failures (foundation implemented)
- **Multiple Policies**: Separate retry strategies for database, external services, and internal operations
- **Context-Aware**: Proper cancellation handling and timeout support
- **Configurable**: YAML-based configuration with environment-specific defaults

#### **Service Integration**
- **Authentication Service**: Retry-aware user authentication and session management
- **User Service**: Retry logic for user CRUD operations
- **Secret Service**: Retry logic for secret management operations
- **Repository Wrappers**: Transparent retry logic for data access layer
- **HTTP Middleware**: Automatic retry of failed HTTP requests

#### **Configuration Example**
```yaml
retry:
  database:
    enabled: true
    max_attempts: 3
    initial_delay: "100ms"
    max_delay: "5s"
    backoff_multiplier: 2.0
    jitter_enabled: true
    retryable_errors:
      - "connection refused"
      - "database is locked"
      - "timeout"
  external_services:
    enabled: true
    max_attempts: 3
    initial_delay: "1s"
    max_delay: "30s"
    backoff_multiplier: 2.0
    jitter_enabled: true
```

#### **Usage Patterns**
```go
// Service layer automatically uses retry
user, err := container.GetUserService().GetUser(ctx, userID)

// Manual retry for custom operations
err := retryService.ExecuteDatabaseOperation(ctx, func() error {
    return db.Query("SELECT * FROM users WHERE id = ?", userID)
})
```

#### **Test Coverage**
- **Integration Tests**: 8 comprehensive test suites with 100% coverage
- **Mock-Based Testing**: testify/mock framework for reliable testing
- **Failure Simulation**: Tests for temporary failures, max attempts, context cancellation
- **Performance Benchmarks**: Included for optimization tracking

#### **Documentation**
No standalone retry docs exist; read `internal/retry/retry.go` (core policy/backoff
logic), `config.go` (YAML config loading), and `middleware.go` (HTTP retry wiring)
directly — they're the source of truth.

**Status**: Production-ready with comprehensive test coverage and enterprise-grade reliability.
