# Identity and Sessions Hardening Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (- [ ]) syntax for tracking.

**Goal:** Close four identity and session weaknesses: cross-user session revocation (#40), OIDC accounts that gain a password without a working second factor, sessions that survive password, role and delete changes (#47), and TOTP code replay (#45).

**Architecture:** Every fix sits in the service layer (`internal/services/auth`, `internal/services/users`). The HTTP handlers (`api/users.go`) and CLI commands (`cmd/users/update.go`) both go through those services, so both paths get the same behavior. Repositories gain three narrow, pure data-access methods: an owner-scoped session revoke, a `totp_secret` write in `UserRepository.Update`, and an atomic compare-and-set on a new `users.totp_last_step` column.

**Tech Stack:** Go 1.24.2, `database/sql` over SQLite and Postgres (`internal/db`), `github.com/pquerna/otp` v1.5.0, testify `mock`/`assert`/`require`, Cobra.

**Spec:**
- GitHub issue #40, "Any authenticated user can revoke any other user's session": https://github.com/Snehal1112/rocketvault/issues/40
- GitHub issue #47, "Password, role and delete changes do not revoke existing sessions": https://github.com/Snehal1112/rocketvault/issues/47
- GitHub issue #45, "TOTP codes can be replayed within the acceptance window": https://github.com/Snehal1112/rocketvault/issues/45
- Research doc, OIDC MFA enrollment: `.claude/research-oidc-user-mfa-enrollment.md` (Core steps 1-4 only)
- Source audit: 2026-09-30 static audit of `api/` (auth-endpoints sub-audit), cited by all three issues and the research doc

**Deferred (not tasks in this plan):**
- Research doc step 5, a fresh-login requirement before an OIDC account may set a password. Deferred because open question 3 is undecided: login time could come from the OIDC `auth_time` claim carried into the session or from a timestamp stored on the session row, and `RefreshAccessToken` re-issues access tokens with a new `iat`, so `iat` is not a usable substitute. Without step 5, threat 2 in the research doc (a stolen token sets a password and receives the enrollment secret too) stays open.
- Research doc step 6, pending enrollment that activates the new TOTP secret only after one valid code. Deferred because it depends on open question 2 (whether local login must stay tied to the IdP) and adds a confirm step to both the CLI and the API. The harm of skipping it is small: a user who loses the one-time URL still has OIDC login.

## Global Constraints

- Module path is `rocketvault`; Go 1.24.2.
- Every commit goes through the `dev-workflow-skills:1-git-commit` plugin skill (Skill tool), never a freeform `git commit -m`. All commits and tags are GPG-signed with key `61D246B30285ED35`.
- Code comments are short full sentences ending with a punctuation mark.
- Before any PR: `go build ./...`, `go vet ./...` and `go test ./...` must pass. golangci-lint fails in this environment (snap Go toolchain incompatibility), so lint runs in CI or on a fixed toolchain.
- CLI commands call services directly and skip HTTP middleware, so each behavior change is tested on both the HTTP and the CLI path.
- Repositories are pure CRUD. Ownership rules, admin bypass, enrollment and revocation decisions live in services.
- Schema changes are written twice in `internal/db/db.go`: once in the `CREATE TABLE` in `createOptimizedSchema` and once as an `ALTER TABLE` in the `migrations` slice of `migrateSchema`. Both must work on SQLite and Postgres.
- B-numbers used here: B72 = #40, B73 = OIDC MFA enrollment (new issue filed in Task 5), B74 = #47, B75 = #45. No other numbers.
- New `.claude/known-bugs.md` entries go directly above the line `## Deferred Refactors`, each followed by a `---` separator line, in the style of B70.
- TOTP issuer string stays `"PasswordManager"`, matching `CreateUser` (`internal/services/users/user_service.go:185`).
- TOTP period stays 30 seconds and skew stays 2 steps (`internal/services/auth/totp_service.go:41-42`). Replay tracking replaces the need to shrink skew.
- The admin role check uses `model.RoleAdmin`.
- Release note file: `docs/release-notes/v4.7.0-identity-sessions-hardening.md`.

## Review Focus

- Admin bypass on revoke: an admin must still revoke any session, and a non-admin whose `CallerID` does not own the session must get `ErrSessionNotFound`, never a silent success. Pinned by `TestRevokeSession_AdminBypassesOwnership` and `TestRevokeSession_OtherUsersSession_NotFound` in Task 2.
- Lockout of enrolled users: a password change on an account that already has a TOTP secret must not generate a new one, or the user's authenticator stops working. Pinned by `TestUpdateUser_PasswordOnEnrolledAccount_KeepsSecret` in Task 4.
- Retry wrapper dropping the enrollment URL: `retryUserService.UpdateUser` must pass the base result through, or the one-time URL is lost. Pinned by `TestRetryUser_UpdateUser_Success` (rewritten) in Task 4.
- Orphaned tokens on SQLite: SQLite runs with `foreign_keys` off, so `user_sessions` rows survive a user delete. A token for a deleted user must fail `ValidateSession`. Pinned by `TestValidateSession_DeletedUser_Rejected` in Task 7.
- Concurrent replay: two logins racing with the same code must not both succeed. The claim is a single conditional `UPDATE`, pinned by `TestTOTPStepRepository_ClaimTOTPStep` in Task 9 and end to end by `TestAuthenticateUser_SameCodeTwice_SecondRejected` in Task 11.

---

### Task 1: Owner-scoped session revoke in the repository

**Files:**
- Modify: `internal/repositories/session_repository.go` (interface lines 18-49; add method after `RevokeSession`, which ends at line 336)
- Modify: `internal/services/auth/authentication_service_test.go` (mock `MockSessionRepository`, lines 223-226)
- Test: `internal/repositories/session_ownership_test.go` (new)

**Interfaces:**
- Consumes: `repositories.ErrNotFound` (`internal/repositories/errors.go:12`), test helpers `setupSessionDB`, `newSession`, `newLogger` (`internal/repositories/missing_coverage_test.go:36, 91, 117`).
- Produces: `SessionRepositoryInterface.RevokeUserSession(ctx context.Context, sessionID, userID uuid.UUID, reason string) error`, returning an error wrapping `ErrNotFound` when no row matches.

- [ ] **Step 1: Write the failing test.** Create `internal/repositories/session_ownership_test.go`:

```go
package repositories_test

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	rvdb "rocketvault/internal/db"
	"rocketvault/internal/repositories"
)

// A session may only be revoked through RevokeUserSession by its owner.
func TestSessionRepository_RevokeUserSession_OwnerOnly(t *testing.T) {
	t.Parallel()
	db := setupSessionDB(t)
	repo := repositories.NewSessionRepository(repositories.SessionRepositoryConfig{DB: rvdb.NewConn(db, rvdb.SQLite), Logger: newLogger()})
	ctx := context.Background()

	owner := uuid.New()
	other := uuid.New()
	sess := newSession(owner)
	require.NoError(t, repo.CreateSession(ctx, sess))

	err := repo.RevokeUserSession(ctx, sess.ID, other, "cross-user")
	require.ErrorIs(t, err, repositories.ErrNotFound)

	revoked, err := repo.IsSessionRevoked(ctx, sess.ID)
	require.NoError(t, err)
	assert.False(t, revoked, "a non-owner must not revoke the session")

	require.NoError(t, repo.RevokeUserSession(ctx, sess.ID, owner, "self"))

	revoked, err = repo.IsSessionRevoked(ctx, sess.ID)
	require.NoError(t, err)
	assert.True(t, revoked)
}

func TestSessionRepository_RevokeUserSession_AlreadyRevoked(t *testing.T) {
	t.Parallel()
	db := setupSessionDB(t)
	repo := repositories.NewSessionRepository(repositories.SessionRepositoryConfig{DB: rvdb.NewConn(db, rvdb.SQLite), Logger: newLogger()})
	ctx := context.Background()

	owner := uuid.New()
	sess := newSession(owner)
	require.NoError(t, repo.CreateSession(ctx, sess))
	require.NoError(t, repo.RevokeUserSession(ctx, sess.ID, owner, "first"))

	err := repo.RevokeUserSession(ctx, sess.ID, owner, "second")
	require.ErrorIs(t, err, repositories.ErrNotFound)
}
```

- [ ] **Step 2: Run it and see it fail.**
Run: `go test ./internal/repositories/ -run TestSessionRepository_RevokeUserSession -v`
Expected: build failure, `repo.RevokeUserSession undefined (type repositories.SessionRepositoryInterface has no field or method RevokeUserSession)`.

- [ ] **Step 3: Add the interface method.** In `internal/repositories/session_repository.go`, directly below the `RevokeSession` line in `SessionRepositoryInterface`, add:

```go
	// RevokeUserSession marks a session as revoked only when userID owns it.
	// A session owned by another user reports ErrNotFound, the same as a missing one.
	RevokeUserSession(ctx context.Context, sessionID, userID uuid.UUID, reason string) error
```

- [ ] **Step 4: Implement it.** Add below `func (r *SessionRepository) RevokeSession` (after its closing brace at line 336):

```go
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
```

- [ ] **Step 5: Keep the auth mock compiling.** In `internal/services/auth/authentication_service_test.go`, add below `func (m *MockSessionRepository) RevokeSession`:

```go
func (m *MockSessionRepository) RevokeUserSession(ctx context.Context, sessionID, userID uuid.UUID, reason string) error {
	args := m.Called(ctx, sessionID, userID, reason)
	return args.Error(0)
}
```

- [ ] **Step 6: Run the tests and expect PASS.**
Run: `go test ./internal/repositories/ ./internal/services/auth/ -v -run 'TestSessionRepository_|TestRevoke'`
Expected: `PASS` for both packages.

- [ ] **Step 7: Commit.** Invoke the `dev-workflow-skills:1-git-commit` plugin skill via the Skill tool (GPG-signed, key `61D246B30285ED35`). Suggested subject: `Add owner-scoped RevokeUserSession to SessionRepository`.

---

### Task 2: Enforce session ownership in RevokeSession (B72, #40)

**Files:**
- Modify: `internal/services/auth/authentication_service.go` (imports lines 3-19; interface line 53; `RevokeSession` lines 402-433)
- Modify: `internal/services/retry/retry_auth_service.go` (lines 59-64)
- Modify: `api/users.go` (imports lines 25-36; `revokeSession` lines 530-546)
- Modify mocks: `internal/middleware/middleware_test.go:170-173`, `internal/testutils/mocks.go:86-89`, `internal/services/retry/retry_wrappers_test.go:96-99`, `api/users_test.go:155-158`, `cmd/testutils/test_utils.go:832-835`
- Modify tests: `internal/services/auth/authentication_service_critical_test.go:193-229`, `internal/services/auth/auth_edge_cases_test.go:374-397`, `internal/services/retry/retry_wrappers_test.go:812-830`, `api/users_test.go:1244-1285`
- Modify: `.claude/known-bugs.md` (new entry B72)

**Interfaces:**
- Consumes: `SessionRepositoryInterface.RevokeUserSession` (Task 1), `SessionRepositoryInterface.RevokeSession(ctx, sessionID uuid.UUID, reason string) error`.
- Produces:
  - `auth.ErrSessionNotFound` (package-level `error`).
  - `auth.RevokeSessionRequest{SessionID string; CallerID uuid.UUID; CallerRoles []string; Reason string}`.
  - `AuthenticationService.RevokeSession(ctx context.Context, req RevokeSessionRequest) error`.

- [ ] **Step 1: Write the failing service tests.** In `internal/services/auth/authentication_service_critical_test.go`, replace `TestRevokeSession_HappyPath` and `TestRevokeSession_InvalidSessionIDFormat` (lines 193-229) with:

```go
func TestRevokeSession_OwnSession_Revoked(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	sessionID := uuid.New()
	callerID := uuid.New()

	sessionRepo := &MockSessionRepository{}
	sessionRepo.On("RevokeUserSession", ctx, sessionID, callerID, "logout").Return(nil)

	svc := newAuthService(&MockUserRepository{}, sessionRepo, &MockPasswordService{}, &MockTOTPService{}, &MockJWTService{}, nil)
	err := svc.RevokeSession(ctx, RevokeSessionRequest{
		SessionID:   sessionID.String(),
		CallerID:    callerID,
		CallerRoles: []string{model.RoleUser},
		Reason:      "logout",
	})

	require.NoError(t, err)
	sessionRepo.AssertExpectations(t)
	sessionRepo.AssertNotCalled(t, "RevokeSession", mock.Anything, mock.Anything, mock.Anything)
}

func TestRevokeSession_OtherUsersSession_NotFound(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	sessionID := uuid.New()
	callerID := uuid.New()

	sessionRepo := &MockSessionRepository{}
	sessionRepo.On("RevokeUserSession", ctx, sessionID, callerID, "logout").
		Return(fmt.Errorf("session not found or already revoked: %w", repositories.ErrNotFound))

	svc := newAuthService(&MockUserRepository{}, sessionRepo, &MockPasswordService{}, &MockTOTPService{}, &MockJWTService{}, nil)
	err := svc.RevokeSession(ctx, RevokeSessionRequest{
		SessionID:   sessionID.String(),
		CallerID:    callerID,
		CallerRoles: []string{model.RoleUser},
		Reason:      "logout",
	})

	require.ErrorIs(t, err, ErrSessionNotFound)
	sessionRepo.AssertNotCalled(t, "RevokeSession", mock.Anything, mock.Anything, mock.Anything)
}

func TestRevokeSession_AdminBypassesOwnership(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	sessionID := uuid.New()

	sessionRepo := &MockSessionRepository{}
	sessionRepo.On("RevokeSession", ctx, sessionID, "admin action").Return(nil)

	svc := newAuthService(&MockUserRepository{}, sessionRepo, &MockPasswordService{}, &MockTOTPService{}, &MockJWTService{}, nil)
	err := svc.RevokeSession(ctx, RevokeSessionRequest{
		SessionID:   sessionID.String(),
		CallerID:    uuid.New(),
		CallerRoles: []string{model.RoleAdmin},
		Reason:      "admin action",
	})

	require.NoError(t, err)
	sessionRepo.AssertExpectations(t)
	sessionRepo.AssertNotCalled(t, "RevokeUserSession", mock.Anything, mock.Anything, mock.Anything, mock.Anything)
}

func TestRevokeSession_InvalidSessionIDFormat(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	sessionRepo := &MockSessionRepository{}

	svc := newAuthService(&MockUserRepository{}, sessionRepo, &MockPasswordService{}, &MockTOTPService{}, &MockJWTService{}, nil)
	err := svc.RevokeSession(ctx, RevokeSessionRequest{SessionID: "not-a-uuid", CallerID: uuid.New(), Reason: "logout"})

	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid session ID format")
	sessionRepo.AssertNotCalled(t, "RevokeSession", mock.Anything, mock.Anything, mock.Anything)
	sessionRepo.AssertNotCalled(t, "RevokeUserSession", mock.Anything, mock.Anything, mock.Anything, mock.Anything)
}
```

Add `"fmt"` and `"rocketvault/internal/repositories"` to that file's imports.

In `internal/services/auth/auth_edge_cases_test.go`, replace the body of `TestRevokeSession_RepoError` (lines 374-397) with:

```go
func TestRevokeSession_RepoError(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	sessionID := uuid.New()
	callerID := uuid.New()

	sessionRepo := &MockSessionRepository{}
	sessionRepo.On("RevokeUserSession", ctx, sessionID, callerID, "logout").
		Return(errors.New("db error"))

	svc := newAuthService(&MockUserRepository{}, sessionRepo, &MockPasswordService{}, &MockTOTPService{}, &MockJWTService{}, nil)
	err := svc.RevokeSession(ctx, RevokeSessionRequest{
		SessionID: sessionID.String(), CallerID: callerID, CallerRoles: []string{model.RoleUser}, Reason: "logout",
	})

	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to revoke session")
	assert.NotErrorIs(t, err, ErrSessionNotFound)
}
```

- [ ] **Step 2: Run them and see them fail.**
Run: `go test ./internal/services/auth/ -run TestRevokeSession -v`
Expected: build failure, `undefined: RevokeSessionRequest` and `undefined: ErrSessionNotFound`.

- [ ] **Step 3: Implement the service change.** In `internal/services/auth/authentication_service.go`, add `"errors"` to the imports. Below `RefreshTokenResult` (after line 38) add:

```go
// ErrSessionNotFound reports a session that does not exist, is already revoked,
// or belongs to a user other than the caller.
var ErrSessionNotFound = errors.New("session not found")

// RevokeSessionRequest identifies a session and the caller who revokes it.
type RevokeSessionRequest struct {
	SessionID   string
	CallerID    uuid.UUID
	CallerRoles []string
	Reason      string
}
```

Change the interface line 53 to:

```go
	RevokeSession(ctx context.Context, req RevokeSessionRequest) error
```

Replace the whole `RevokeSession` method (doc comment at line 402 through line 433) with:

```go
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
```

- [ ] **Step 4: Update the retry wrapper.** In `internal/services/retry/retry_auth_service.go`, replace `RevokeSession` (lines 59-64) with:

```go
// RevokeSession revokes a session with retry logic for database operations.
func (s *retryAuthenticationService) RevokeSession(ctx context.Context, req auth.RevokeSessionRequest) error {
	return s.retryService.ExecuteDatabaseOperation(ctx, func() error {
		return s.baseService.RevokeSession(ctx, req)
	})
}
```

- [ ] **Step 5: Update every mock.** Replace the `RevokeSession` method in each of these five files with the body below, keeping each file's receiver name and its import alias for the auth package (`authServices` in `internal/middleware/middleware_test.go`, `internal/testutils/mocks.go`, `api/users_test.go`, `cmd/testutils/test_utils.go`; `auth` in `internal/services/retry/retry_wrappers_test.go`):

```go
func (m *MockAuthenticationService) RevokeSession(ctx context.Context, req authServices.RevokeSessionRequest) error {
	args := m.Called(ctx, req)
	return args.Error(0)
}
```

(Receivers: `*MockAuthenticationService` in middleware_test.go, mocks.go and cmd/testutils/test_utils.go; `*mockAuthService` in api/users_test.go; `*MockAuthService` in retry_wrappers_test.go.) Check the alias in `internal/middleware/middleware_test.go` with `grep -n 'services/auth"' internal/middleware/middleware_test.go` before editing.

Replace the two retry tests (`internal/services/retry/retry_wrappers_test.go:812-830`) with:

```go
func TestRetryAuth_RevokeSession_Success(t *testing.T) {
	base := &MockAuthService{}
	req := auth.RevokeSessionRequest{SessionID: "sess-1", CallerID: uuid.New(), Reason: "logout"}
	base.On("RevokeSession", mock.Anything, req).Return(nil)

	svc := NewRetryAuthenticationService(base, newNoop())
	err := svc.RevokeSession(ctx, req)
	assert.NoError(t, err)
	base.AssertExpectations(t)
}

func TestRetryAuth_RevokeSession_Error(t *testing.T) {
	base := &MockAuthService{}
	req := auth.RevokeSessionRequest{SessionID: "sess-1", CallerID: uuid.New(), Reason: "logout"}
	base.On("RevokeSession", mock.Anything, req).Return(fmt.Errorf("revoke failed"))

	svc := NewRetryAuthenticationService(base, newNoop())
	err := svc.RevokeSession(ctx, req)
	assert.Error(t, err)
	base.AssertExpectations(t)
}
```

- [ ] **Step 6: Write the failing HTTP tests.** In `api/users_test.go`, replace `TestRevokeSession_Success_Returns200` and `TestRevokeSession_Error_Returns500` (lines 1244-1285) with:

```go
func TestRevokeSession_Success_Returns200(t *testing.T) {
	authSvc := &mockAuthService{}
	sessionID := uuid.New().String()
	callerID := uuid.New()
	authSvc.On("RevokeSession", mock.Anything, authServices.RevokeSessionRequest{
		SessionID: sessionID, CallerID: callerID, CallerRoles: []string{model.RoleUser}, Reason: "User requested revocation",
	}).Return(nil)

	c := newUserCtx(nil, authSvc, uViewerClaims(callerID.String()))
	c.Params = &ApiParams{SessionID: sessionID, PerPage: 60}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodDelete, "/users/sessions/"+sessionID, nil)

	revokeSession(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusOK, w.Code)
	authSvc.AssertExpectations(t)
}

// Revoking another user's session must look exactly like revoking a missing one.
func TestRevokeSession_OtherUsersSession_Returns404(t *testing.T) {
	authSvc := &mockAuthService{}
	sessionID := uuid.New().String()
	callerID := uuid.New()
	authSvc.On("RevokeSession", mock.Anything, mock.Anything).
		Return(fmt.Errorf("revoke session %s: %w", sessionID, authServices.ErrSessionNotFound))

	c := newUserCtx(nil, authSvc, uViewerClaims(callerID.String()))
	c.Params = &ApiParams{SessionID: sessionID, PerPage: 60}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodDelete, "/users/sessions/"+sessionID, nil)

	revokeSession(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusNotFound, w.Code)
	authSvc.AssertExpectations(t)
}

func TestRevokeSession_InvalidCallerID_Returns400(t *testing.T) {
	authSvc := &mockAuthService{}
	sessionID := uuid.New().String()

	c := newUserCtx(nil, authSvc, RequestClaims{UserID: "not-a-uuid"})
	c.Params = &ApiParams{SessionID: sessionID, PerPage: 60}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodDelete, "/users/sessions/"+sessionID, nil)

	revokeSession(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusBadRequest, w.Code)
	authSvc.AssertNotCalled(t, "RevokeSession", mock.Anything, mock.Anything)
}

func TestRevokeSession_Error_Returns500(t *testing.T) {
	authSvc := &mockAuthService{}
	sessionID := uuid.New().String()
	authSvc.On("RevokeSession", mock.Anything, mock.Anything).Return(errors.New("db error"))

	c := newUserCtx(nil, authSvc, uViewerClaims(uuid.New().String()))
	c.Params = &ApiParams{SessionID: sessionID, PerPage: 60}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodDelete, "/users/sessions/"+sessionID, nil)

	revokeSession(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusInternalServerError, w.Code)
	authSvc.AssertExpectations(t)
}
```

Add `"fmt"` to `api/users_test.go` imports if `grep -n '"fmt"' api/users_test.go` finds nothing.

- [ ] **Step 7: Update the handler.** In `api/users.go`, add `"errors"` and `authServices "rocketvault/internal/services/auth"` to the imports, and replace `revokeSession` (lines 530-546) with:

```go
// revokeSession handles the HTTP request to revoke a specific session.
// Admins may revoke any session; other callers may revoke only their own.
func revokeSession(c *Context, w http.ResponseWriter, r *http.Request) {
	sessionID := c.Params.SessionID

	callerID, err := uuid.Parse(c.Claims.UserID)
	if err != nil {
		c.SetInvalidParam("user_id")
		return
	}

	authSvc, svcOK := svc(c, container.ServiceContainerInterface.GetAuthenticationService)
	if !svcOK {
		return
	}
	if err := authSvc.RevokeSession(r.Context(), authServices.RevokeSessionRequest{
		SessionID:   sessionID,
		CallerID:    callerID,
		CallerRoles: c.Claims.Roles,
		Reason:      "User requested revocation",
	}); err != nil {
		if errors.Is(err, authServices.ErrSessionNotFound) {
			c.SetNotFound("session")
			return
		}
		c.SetInternalError(err)
		return
	}

	ReturnStatusOK(w)

	c.Logger.Printf("User %s revoked session %s", c.Claims.UserID, sessionID)
}
```

- [ ] **Step 8: Run all affected packages and expect PASS.**
Run: `go build ./... && go test ./internal/services/auth/ ./internal/services/retry/ ./internal/middleware/ ./internal/testutils/ ./api/ ./cmd/... -run 'Revoke|Session' -v`
Expected: build succeeds and every listed test passes.

- [ ] **Step 9: Record B72.** Insert above `## Deferred Refactors` in `.claude/known-bugs.md`:

```markdown
### B72 — Any authenticated caller could revoke any session

**Status**: Fixed (identity and sessions hardening, 2026-09-30); GitHub #40
**Severity**: Medium — defense in depth today, because `DELETE /users/*` maps
to the admin-only `users:delete` permission
(`internal/services/authorization/rbac_service.go:262-275`), so only admins
reach the handler; loosening that mapping for self-service would have made
this a full IDOR
**Files**: `api/users.go`, `internal/services/auth/authentication_service.go`,
`internal/repositories/session_repository.go`

**Symptom**: `revokeSession` passed only the session ID to
`AuthenticationService.RevokeSession`, and the repository ran
`UPDATE user_sessions ... WHERE id = ?` with no `user_id` condition. The
session ID is the JWT `jti`, readable in cleartext from any token.

**Root cause**: ownership was never part of the revoke contract; the caller's
identity did not reach the service or the query.

**What was fixed**: `RevokeSession` now takes a `RevokeSessionRequest` carrying
the caller's ID and roles. Admins keep the unscoped
`SessionRepository.RevokeSession`; everyone else goes through the new
`RevokeUserSession`, whose `UPDATE` adds `AND user_id = ?`. A session the caller
may not revoke returns `ErrSessionNotFound`, which the handler maps to 404, the
same answer as for a missing session.

---
```

- [ ] **Step 10: Commit.** Invoke the `dev-workflow-skills:1-git-commit` plugin skill via the Skill tool (GPG-signed, key `61D246B30285ED35`). Include the footer `Fixes #40`.

---

### Task 3: Persist `totp_secret` in UserRepository.Update

**Files:**
- Modify: `internal/repositories/user_repository.go:227-231` (the `UPDATE users SET ...` statement in `Update`)
- Test: `internal/repositories/missing_coverage_test.go` (add after `TestUserRepository_Update`, line 355)

**Interfaces:**
- Consumes: `setupUserDB`, `newUser`, `newLogger` (`internal/repositories/missing_coverage_test.go:44, 79, 36`).
- Produces: `UserRepository.Update` now writes `user.TOTPSecret`. The only production caller, `userService.UpdateUser` (`internal/services/users/user_service.go:329`), does read-modify-write, so existing secrets are carried through unchanged.

- [ ] **Step 1: Write the failing test.** Add to `internal/repositories/missing_coverage_test.go`:

```go
// Update must store the TOTP secret, or enrolling an OIDC account on password set is lost.
func TestUserRepository_Update_PersistsTOTPSecret(t *testing.T) {
	t.Parallel()
	db := setupUserDB(t)
	repo := repositories.NewUserRepository(rvdb.NewConn(db, rvdb.SQLite), newLogger())
	ctx := context.Background()

	u := newUser("totp-carrier", model.RoleUser)
	require.NoError(t, repo.Create(ctx, u))

	u.TOTPSecret = "JBSWY3DPEHPK3PXP"
	require.NoError(t, repo.Update(ctx, u))

	got, err := repo.Read(ctx, u.ID)
	require.NoError(t, err)
	assert.Equal(t, "JBSWY3DPEHPK3PXP", got.TOTPSecret)
}
```

- [ ] **Step 2: Run it and see it fail.**
Run: `go test ./internal/repositories/ -run TestUserRepository_Update_PersistsTOTPSecret -v`
Expected: FAIL, `expected: "JBSWY3DPEHPK3PXP" actual: ""`.

- [ ] **Step 3: Implement.** In `internal/repositories/user_repository.go`, replace the `tx.ExecContext` call inside `Update` with:

```go
	result, err := tx.ExecContext(
		ctx,
		"UPDATE users SET username = ?, password_hash = ?, totp_secret = ?, role = ? WHERE id = ?",
		user.Username, user.PasswordHash, user.TOTPSecret, strings.Join(normalizedRoles, ","), user.ID.String(),
	)
```

- [ ] **Step 4: Run the package and expect PASS.**
Run: `go test ./internal/repositories/ -v -run TestUserRepository_`
Expected: `PASS`.

- [ ] **Step 5: Commit.** Invoke the `dev-workflow-skills:1-git-commit` plugin skill via the Skill tool (GPG-signed, key `61D246B30285ED35`).

---

### Task 4: Enroll TOTP when a password is set on an account without a secret

**Files:**
- Modify: `internal/services/users/user_service.go` (types lines 46-54; interface line 84; `UpdateUser` lines 256-338)
- Modify: `internal/services/retry/retry_user_service.go:38-43`
- Modify: `api/users.go` (`updateUser`, lines 309-340)
- Modify: `cmd/users/update.go:115-137`
- Modify mocks: `internal/services/retry/retry_wrappers_test.go:130-133`, `api/users_test.go:68-71`, `cmd/testutils/test_utils.go:441-444`
- Modify tests: `internal/services/users/user_service_test.go` (14 `err := svc.UpdateUser(` sites), `internal/services/retry/retry_wrappers_test.go:889-910`, `api/users_test.go:887, 906`, `cmd/users/update_test.go:101-103`, `cmd/users/cmd_rune_test.go:271-272, 289-291, 306`

**Interfaces:**
- Consumes: `UserRepository.Update` writing `totp_secret` (Task 3); `authService.TOTPService.GenerateSecret(issuer, accountName string) (*otp.Key, error)`; generic `retried` helper in `internal/services/retry` (used by `retryUserService.CreateUser`).
- Produces:
  - `users.UpdateUserResult{TOTPEnrollmentURL string}`.
  - `UserService.UpdateUser(ctx context.Context, req UpdateUserRequest) (*UpdateUserResult, error)`. Non-nil result on success; `TOTPEnrollmentURL` is non-empty only when a secret was generated in this call.
  - HTTP `PUT /api/v1/users/{id}` response field `totp_secret` (existing `model.UserResponse.TOTPSecret`, same field `POST /users` uses) carries the `otpauth://` URL once.

- [ ] **Step 1: Write the failing service tests.** Append to `internal/services/users/user_service_test.go`:

```go
// ---------------------------------------------------------------------------
// TOTP enrollment on password set (B73)
// ---------------------------------------------------------------------------

func TestUpdateUser_PasswordOnAccountWithoutTOTP_EnrollsSecret(t *testing.T) {
	t.Parallel()
	repo := &mockUserRepository{}
	pw := &mockPasswordService{}
	totpSvc := &mockTOTPService{}
	svc := newService(repo, pw, totpSvc)

	userID := uuid.New()
	existing := &model.User{
		ID:           userID,
		Username:     "oidc-alice",
		Roles:        []string{model.RoleUser},
		AuthProvider: model.AuthProviderOIDC,
		TOTPSecret:   "",
	}
	key := realTOTPKey(t)
	repo.On("Read", mock.Anything, userID).Return(existing, nil)
	pw.On("HashPassword", "newpass123").Return("hashed-new", nil)
	totpSvc.On("GenerateSecret", "PasswordManager", "oidc-alice").Return(key, nil)
	repo.On("Update", mock.Anything, mock.MatchedBy(func(u *model.User) bool {
		return u.PasswordHash == "hashed-new" && u.TOTPSecret == key.Secret()
	})).Return(nil)

	newPw := "newpass123"
	result, err := svc.UpdateUser(context.Background(), UpdateUserRequest{
		UserID:      userID,
		CallerID:    userID,
		CallerRoles: []string{model.RoleUser},
		Password:    &newPw,
	})

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, key.URL(), result.TOTPEnrollmentURL)
	assert.Contains(t, result.TOTPEnrollmentURL, "otpauth://totp/")
	repo.AssertExpectations(t)
	totpSvc.AssertExpectations(t)
}

func TestUpdateUser_PasswordOnEnrolledAccount_KeepsSecret(t *testing.T) {
	t.Parallel()
	repo := &mockUserRepository{}
	pw := &mockPasswordService{}
	totpSvc := &mockTOTPService{}
	svc := newService(repo, pw, totpSvc)

	userID := uuid.New()
	existing := &model.User{ID: userID, Username: "bob", Roles: []string{model.RoleUser}, TOTPSecret: "EXISTINGSECRET"}
	repo.On("Read", mock.Anything, userID).Return(existing, nil)
	pw.On("HashPassword", "newpass123").Return("hashed-new", nil)
	repo.On("Update", mock.Anything, mock.MatchedBy(func(u *model.User) bool {
		return u.PasswordHash == "hashed-new" && u.TOTPSecret == "EXISTINGSECRET"
	})).Return(nil)

	newPw := "newpass123"
	result, err := svc.UpdateUser(context.Background(), UpdateUserRequest{
		UserID: userID, CallerID: userID, CallerRoles: []string{model.RoleUser}, Password: &newPw,
	})

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Empty(t, result.TOTPEnrollmentURL)
	totpSvc.AssertNotCalled(t, "GenerateSecret", mock.Anything, mock.Anything)
	repo.AssertExpectations(t)
}

func TestUpdateUser_UsernameOnlyOnAccountWithoutTOTP_DoesNotEnroll(t *testing.T) {
	t.Parallel()
	repo := &mockUserRepository{}
	totpSvc := &mockTOTPService{}
	svc := newService(repo, &mockPasswordService{}, totpSvc)

	userID := uuid.New()
	existing := &model.User{ID: userID, Username: "oidc-carol", Roles: []string{model.RoleUser}, TOTPSecret: ""}
	repo.On("Read", mock.Anything, userID).Return(existing, nil)
	repo.On("Update", mock.Anything, mock.MatchedBy(func(u *model.User) bool {
		return u.Username == "carol2" && u.TOTPSecret == ""
	})).Return(nil)

	newName := "carol2"
	result, err := svc.UpdateUser(context.Background(), UpdateUserRequest{
		UserID: userID, CallerRoles: []string{model.RoleUser}, Username: &newName,
	})

	require.NoError(t, err)
	assert.Empty(t, result.TOTPEnrollmentURL)
	totpSvc.AssertNotCalled(t, "GenerateSecret", mock.Anything, mock.Anything)
}

func TestUpdateUser_EnrollmentSecretGenerationFails(t *testing.T) {
	t.Parallel()
	repo := &mockUserRepository{}
	pw := &mockPasswordService{}
	totpSvc := &mockTOTPService{}
	svc := newService(repo, pw, totpSvc)

	userID := uuid.New()
	existing := &model.User{ID: userID, Username: "oidc-dave", Roles: []string{model.RoleUser}}
	repo.On("Read", mock.Anything, userID).Return(existing, nil)
	pw.On("HashPassword", "newpass123").Return("hashed-new", nil)
	totpSvc.On("GenerateSecret", "PasswordManager", "oidc-dave").Return(nil, errors.New("rng failure"))

	newPw := "newpass123"
	result, err := svc.UpdateUser(context.Background(), UpdateUserRequest{
		UserID: userID, CallerRoles: []string{model.RoleUser}, Password: &newPw,
	})

	require.Error(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "failed to generate TOTP secret")
	repo.AssertNotCalled(t, "Update", mock.Anything, mock.Anything)
}
```

Then convert the existing call sites:
Run: `sed -i 's/\berr := svc\.UpdateUser(/_, err := svc.UpdateUser(/' internal/services/users/user_service_test.go`
(The new tests above already use `result, err :=`; the sed only touches lines that start with `err := svc.UpdateUser(`, which the new tests do not contain.)

- [ ] **Step 2: Run them and see them fail.**
Run: `go test ./internal/services/users/ -run TestUpdateUser -v`
Expected: build failure, `assignment mismatch: 2 variables but svc.UpdateUser returns 1 value`.

- [ ] **Step 3: Implement the service change.** In `internal/services/users/user_service.go`, add below `UpdateUserRequest` (after line 54):

```go
// UpdateUserResult reports side effects of UpdateUser that the caller must show the user.
type UpdateUserResult struct {
	// TOTPEnrollmentURL is the otpauth:// URL of a TOTP secret generated by
	// this call. It is empty unless the account had no secret before.
	TOTPEnrollmentURL string
}
```

Change the interface line 84 to:

```go
	UpdateUser(ctx context.Context, req UpdateUserRequest) (*UpdateUserResult, error)
```

In the `UpdateUser` method: change the signature to `func (s *userService) UpdateUser(ctx context.Context, req UpdateUserRequest) (*UpdateUserResult, error)`, change every `return err` / `return fmt.Errorf(...)` inside it to `return nil, err` / `return nil, fmt.Errorf(...)`, and replace the password block (lines 316-323) with:

```go
	var enrollmentURL string
	if req.Password != nil {
		hashedPassword, err := s.passwordService.HashPassword(*req.Password)
		if err != nil {
			s.logger.LogAuditError(req.UserID.String(), "update_user", "failed", "Failed to hash password", err)
			return nil, fmt.Errorf("failed to hash password: %w", err)
		}
		updatedUser.PasswordHash = hashedPassword

		// An account with no TOTP secret, such as one created by OIDC login,
		// gets one now, so the new password is never a single-factor login.
		// An existing secret is kept, or the user's authenticator would stop working.
		if existingUser.TOTPSecret == "" {
			totpKey, err := s.totpService.GenerateSecret("PasswordManager", updatedUser.Username)
			if err != nil {
				s.logger.LogAuditError(req.UserID.String(), "update_user", "failed", "Failed to generate TOTP secret", err)
				return nil, fmt.Errorf("failed to generate TOTP secret: %w", err)
			}
			updatedUser.TOTPSecret = totpKey.Secret()
			enrollmentURL = totpKey.URL()
		}
	}
```

Replace the final `return nil` of `UpdateUser` with:

```go
	if enrollmentURL != "" {
		s.logger.LogAuditInfo(req.UserID.String(), "enroll_totp", "success", "TOTP secret generated on password set")
	}

	return &UpdateUserResult{TOTPEnrollmentURL: enrollmentURL}, nil
```

- [ ] **Step 4: Update the retry wrapper and its test.** In `internal/services/retry/retry_user_service.go`, replace `UpdateUser` (lines 38-43) with:

```go
// UpdateUser updates a user with retry logic for database operations.
func (s *retryUserService) UpdateUser(ctx context.Context, req users.UpdateUserRequest) (*users.UpdateUserResult, error) {
	return retried(ctx, s.retryService, func() (*users.UpdateUserResult, error) {
		return s.baseService.UpdateUser(ctx, req)
	})
}
```

In `internal/services/retry/retry_wrappers_test.go`, replace the mock method (lines 130-133) with:

```go
func (m *MockUserService) UpdateUser(ctx context.Context, req users.UpdateUserRequest) (*users.UpdateUserResult, error) {
	args := m.Called(ctx, req)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*users.UpdateUserResult), args.Error(1)
}
```

and replace `TestRetryUser_UpdateUser_Success` / `TestRetryUser_UpdateUser_Error` (lines 889-910) with:

```go
func TestRetryUser_UpdateUser_Success(t *testing.T) {
	base := &MockUserService{}
	req := users.UpdateUserRequest{UserID: uuid.New()}
	want := &users.UpdateUserResult{TOTPEnrollmentURL: "otpauth://totp/PasswordManager:alice?secret=ABC"}
	base.On("UpdateUser", mock.Anything, req).Return(want, nil)

	svc := NewRetryUserService(base, newNoop())
	got, err := svc.UpdateUser(ctx, req)
	assert.NoError(t, err)
	assert.Equal(t, want, got, "the wrapper must not drop the one-time enrollment URL")
	base.AssertExpectations(t)
}

func TestRetryUser_UpdateUser_Error(t *testing.T) {
	base := &MockUserService{}
	req := users.UpdateUserRequest{UserID: uuid.New()}
	base.On("UpdateUser", mock.Anything, req).Return(nil, fmt.Errorf("update failed"))

	svc := NewRetryUserService(base, newNoop())
	_, err := svc.UpdateUser(ctx, req)
	assert.Error(t, err)
	base.AssertExpectations(t)
}
```

- [ ] **Step 5: Update the other two mocks.** In `api/users_test.go` (lines 68-71, receiver `*mockUserService`) and `cmd/testutils/test_utils.go` (lines 441-444, receiver `*MockUserService`) use:

```go
func (m *mockUserService) UpdateUser(ctx context.Context, req userServices.UpdateUserRequest) (*userServices.UpdateUserResult, error) {
	args := m.Called(ctx, req)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*userServices.UpdateUserResult), args.Error(1)
}
```

Then change the existing expectations to two return values:
- `api/users_test.go:887`: `.Return(nil, errors.New("db error"))`
- `api/users_test.go:906`: `.Return(&userServices.UpdateUserResult{}, nil)`
- `cmd/users/update_test.go:103`: `})).Return(&userService.UpdateUserResult{}, nil)`
- `cmd/users/cmd_rune_test.go:272`: `Return(nil, fmt.Errorf("invalid role: superuser"))`
- `cmd/users/cmd_rune_test.go:291`: `})).Return(&userServices.UpdateUserResult{}, nil)`
- `cmd/users/cmd_rune_test.go:306`: `.Return(nil, fmt.Errorf("update failed"))`

- [ ] **Step 6: Write the failing HTTP and CLI tests.** Add to `api/users_test.go`:

```go
// A password set that enrolls TOTP must hand the otpauth URL back once.
func TestUpdateUser_PasswordEnrollment_ReturnsTOTPURL(t *testing.T) {
	svc := &mockUserService{}
	targetID := uuid.New()
	enrollURL := "otpauth://totp/PasswordManager:alice?secret=ABC"
	svc.On("UpdateUser", mock.Anything, mock.MatchedBy(func(req userServices.UpdateUserRequest) bool {
		return req.Password != nil && *req.Password == "newpass123"
	})).Return(&userServices.UpdateUserResult{TOTPEnrollmentURL: enrollURL}, nil)
	svc.On("GetUser", mock.Anything, targetID).Return(&model.User{
		ID: targetID, Username: "alice", Roles: []string{model.RoleUser}, CreatedAt: time.Now(),
	}, nil)

	c := newUserCtx(svc, nil, uViewerClaims(targetID.String()))
	c.Params = &ApiParams{UserID: targetID.String(), PerPage: 60}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPut, "/users/"+targetID.String(), encodeBody(map[string]string{"password": "newpass123"}))

	updateUser(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	require.Equal(t, http.StatusOK, w.Code)
	var body model.UserResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
	assert.Equal(t, enrollURL, body.TOTPSecret)
}
```

Add to `cmd/users/cmd_rune_test.go`:

```go
func TestUpdateCmdRunE_PasswordEnrollment_PrintsTOTPURL(t *testing.T) {
	tc := testutils.NewTestContext(t)
	targetID := uuid.New()
	ctx := newUsersTestCtx(tc.MockContainer)
	enrollURL := "otpauth://totp/PasswordManager:alice?secret=ABC"

	tc.MockUserService.On("UpdateUser", mock.Anything, mock.MatchedBy(func(r userServices.UpdateUserRequest) bool {
		return r.Password != nil && *r.Password == "newpass123"
	})).Return(&userServices.UpdateUserResult{TOTPEnrollmentURL: enrollURL}, nil)

	var out bytes.Buffer
	cmd := newUpdateTestCmd()
	cmd.SetContext(ctx)
	cmd.SetOut(&out)
	cmd.SetArgs([]string{targetID.String(), "--new-password=newpass123"})

	require.NoError(t, cmd.Execute())
	assert.Contains(t, out.String(), enrollURL)
	assert.Contains(t, out.String(), "shown only once")
}
```

Add `"github.com/stretchr/testify/require"` to `cmd/users/cmd_rune_test.go` imports if missing.

- [ ] **Step 7: Run them and see them fail.**
Run: `go test ./api/ -run TestUpdateUser_PasswordEnrollment -v; go test ./cmd/users/ -run TestUpdateCmdRunE_PasswordEnrollment -v`
Expected: build failures at `api/users.go` and `cmd/users/update.go` (`assignment mismatch: 1 variable but userSvc.UpdateUser returns 2 values`).

- [ ] **Step 8: Update the handler.** In `api/users.go` `updateUser`, replace `if err := userSvc.UpdateUser(r.Context(), userService.UpdateUserRequest{` ... `}); err != nil {` with:

```go
	result, err := userSvc.UpdateUser(r.Context(), userService.UpdateUserRequest{
		UserID:      userID,
		CallerID:    callerID,
		CallerRoles: currentRoles,
		Username:    usernamePtr,
		Password:    passwordPtr,
		Roles:       req.Roles,
	})
	if err != nil {
```

(keep the existing error-mapping body), and after building `response := model.UserResponse{...}` add:

```go
	// The enrollment URL is returned only by the call that generated the secret.
	if result != nil {
		response.TOTPSecret = result.TOTPEnrollmentURL
	}
```

- [ ] **Step 9: Update the CLI.** In `cmd/users/update.go`, replace `if err := userSvc.UpdateUser(ctx, userService.UpdateUserRequest{` ... `}); err != nil {` with `result, err := userSvc.UpdateUser(ctx, userService.UpdateUserRequest{ ... })` followed by `if err != nil {` (same body), and replace `fmt.Printf("User %s updated successfully\n", id)` with:

```go
		out := cmd.OutOrStdout()
		fmt.Fprintf(out, "User %s updated successfully\n", id)
		if result != nil && result.TOTPEnrollmentURL != "" {
			fmt.Fprintf(out, "TOTP Secret: %s\n", result.TOTPEnrollmentURL)
			fmt.Fprintf(out, "\nThis account had no second factor. Add this TOTP secret to your authenticator app now.\n")
			fmt.Fprintf(out, "It is shown only once, and local password login requires it.\n")
		}
```

- [ ] **Step 10: Run everything touched and expect PASS.**
Run: `go build ./... && go test ./internal/services/users/ ./internal/services/retry/ ./api/ ./cmd/... -v -run 'UpdateUser|UpdateCmd'`
Expected: `PASS` in every package.

- [ ] **Step 11: Commit.** Invoke the `dev-workflow-skills:1-git-commit` plugin skill via the Skill tool (GPG-signed, key `61D246B30285ED35`). No `Fixes` footer yet; B73's issue is filed in Task 5.

---

### Task 5: Fail closed on an empty TOTP secret at login (B73)

**Files:**
- Modify: `internal/services/auth/authentication_service.go` (`AuthenticateUser`, between the password check ending at line 151 and the TOTP check at line 153)
- Test: `internal/services/auth/authentication_service_critical_test.go` (append)
- Modify: `.claude/known-bugs.md` (new entry B73)

**Interfaces:**
- Consumes: `ErrSessionNotFound` block from Task 2 (the new sentinel sits beside it).
- Produces: `auth.ErrMFANotEnrolled` (package-level `error`); `AuthenticateUser` returns an error wrapping it when `user.TOTPSecret == ""` after a correct password.

- [ ] **Step 1: Write the failing test.** Append to `internal/services/auth/authentication_service_critical_test.go`:

```go
// An account with no TOTP secret must never log in with a password alone.
func TestAuthenticateUser_EmptyTOTPSecret_FailsClosed(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	userRepo := &MockUserRepository{}
	sessionRepo := &MockSessionRepository{}
	pwd := &MockPasswordService{}
	totp := &MockTOTPService{}
	jwt := &MockJWTService{}

	user := model.User{
		ID:           uuid.New(),
		Username:     "oidc-user",
		PasswordHash: "hashed",
		TOTPSecret:   "",
		Roles:        []string{model.RoleUser},
		AuthProvider: model.AuthProviderOIDC,
	}
	userRepo.On("ReadByUsername", ctx, "oidc-user").Return(user, nil)
	pwd.On("ValidatePassword", "pass", "hashed").Return(nil)

	svc := newAuthService(userRepo, sessionRepo, pwd, totp, jwt, nil)
	result, err := svc.AuthenticateUser(ctx, "oidc-user", "pass", "123456")

	require.ErrorIs(t, err, ErrMFANotEnrolled)
	assert.Nil(t, result)
	totp.AssertNotCalled(t, "ValidateCode", mock.Anything, mock.Anything, mock.Anything)
	sessionRepo.AssertNotCalled(t, "CreateSession", mock.Anything, mock.Anything)
}

// A wrong password on an unenrolled account must not reveal that it is unenrolled.
func TestAuthenticateUser_EmptyTOTPSecret_WrongPasswordStaysGeneric(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	userRepo := &MockUserRepository{}
	pwd := &MockPasswordService{}

	user := model.User{ID: uuid.New(), Username: "oidc-user", PasswordHash: "hashed", Roles: []string{model.RoleUser}}
	userRepo.On("ReadByUsername", ctx, "oidc-user").Return(user, nil)
	pwd.On("ValidatePassword", "wrong", "hashed").Return(errors.New("mismatch"))

	svc := newAuthService(userRepo, &MockSessionRepository{}, pwd, &MockTOTPService{}, &MockJWTService{}, nil)
	_, err := svc.AuthenticateUser(ctx, "oidc-user", "wrong", "123456")

	require.Error(t, err)
	assert.NotErrorIs(t, err, ErrMFANotEnrolled)
	assert.Equal(t, "invalid credentials", err.Error())
}
```

- [ ] **Step 2: Run it and see it fail.**
Run: `go test ./internal/services/auth/ -run TestAuthenticateUser_EmptyTOTPSecret -v`
Expected: build failure, `undefined: ErrMFANotEnrolled`.

- [ ] **Step 3: Implement.** In `internal/services/auth/authentication_service.go`, add below `ErrSessionNotFound`:

```go
// ErrMFANotEnrolled reports a login attempt on an account that has no TOTP secret.
var ErrMFANotEnrolled = errors.New("multi-factor authentication is not enrolled for this account; sign in with OIDC and set the password again to enroll TOTP")
```

In `AuthenticateUser`, directly after the password-validation `if` block and before `// Validate TOTP code`, add:

```go
	// An empty secret makes every TOTP code computable by anyone, so an
	// unenrolled account must not log in with a password alone. The check runs
	// after the password so it tells nothing to someone without the password.
	if user.TOTPSecret == "" {
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
		return nil, fmt.Errorf("authentication failed: %w", ErrMFANotEnrolled)
	}
```

- [ ] **Step 4: Run the package and expect PASS.**
Run: `go test ./internal/services/auth/ -v -run 'TestAuthenticate'`
Expected: `PASS`.

- [ ] **Step 5: File the GitHub issue for B73** (the repo convention requires one per new entry).
Write the body to a scratch file and create the issue:

```bash
cat > /tmp/b73-issue.md <<'EOF'
**Severity**: Medium

**Files**: `internal/services/users/user_service.go:233-234, 316-323`, `internal/services/auth/authentication_service.go:126-163`, `internal/services/auth/totp_service.go:85-99`, `api/users.go:266-300`, `cmd/users/update.go:108-126`

**Symptom**: An OIDC-provisioned user (empty password hash, empty TOTP secret) who sets a local password gets a login with no working second factor. `AuthenticateUser` still asks for a TOTP code, but the stored empty secret makes that code computable by anyone.

**Root cause**: `UpdateUser` writes the new password hash and never touches `TOTPSecret`, and `AuthenticateUser` validates TOTP against whatever secret is stored, including an empty one.

**Fix recipe**: Generate a TOTP secret in `UserService.UpdateUser` when a password is set on an account with an empty secret, return the otpauth URL once over HTTP and in the CLI, and have `AuthenticateUser` fail closed on an empty secret. A fresh-login requirement (research step 5) and pending enrollment (step 6) are deferred.

Full detail: .claude/known-bugs.md § B73 and .claude/research-oidc-user-mfa-enrollment.md
EOF
gh issue create --title "B73: OIDC users who set a password get a login with no working second factor" --label bug --body-file /tmp/b73-issue.md
```

Expected: `gh` prints the issue URL. Its trailing number is `<B73 issue number>` for Step 6 and Step 7.

- [ ] **Step 6: Record B73.** Insert above `## Deferred Refactors` in `.claude/known-bugs.md` (fill the issue number printed in Step 5):

```markdown
### B73 — OIDC accounts that set a password had no working second factor

**Status**: Fixed (identity and sessions hardening, 2026-09-30); GitHub #<B73 issue number printed by Step 5>
**Severity**: Medium — needs a stolen access token or a leaked password to
abuse; the research first rated it High, corrected in the research doc
**Files**: `internal/services/users/user_service.go`,
`internal/repositories/user_repository.go`,
`internal/services/auth/authentication_service.go`, `api/users.go`,
`cmd/users/update.go`

**Symptom**: `FindOrCreateExternalUser` creates OIDC users with
`PasswordHash: ""` and `TOTPSecret: ""`. Setting a password afterwards
(`rocketvault users update --new-password`, or `PUT /api/v1/users/{self}`)
produced a local login that still asked for a TOTP code, but an empty secret
makes that code computable by anyone. The password was the only real factor.

**Root cause**: `UpdateUser` never enrolled a secret, `UserRepository.Update`
did not even write `totp_secret`, and `AuthenticateUser` had no empty-secret
guard.

**What was fixed**: research doc Core steps 1-4. `UpdateUser` generates a TOTP
secret when a password is set on an account whose secret is empty (existing
secrets are kept), `UserRepository.Update` persists `totp_secret`, the
`otpauth://` URL is returned once in the `totp_secret` field of the
`PUT /users/{id}` response and printed once by `users update`, and
`AuthenticateUser` rejects an empty secret with `ErrMFANotEnrolled` after the
password check.

**Still open**: research step 5 (fresh IdP login before setting a password)
and step 6 (pending enrollment) are deferred on open questions 2 and 3 of
`.claude/research-oidc-user-mfa-enrollment.md`. Until step 5 lands, an attacker
holding a stolen token who sets a password also receives the enrollment URL.

---
```

- [ ] **Step 7: Commit.** Invoke the `dev-workflow-skills:1-git-commit` plugin skill via the Skill tool (GPG-signed, key `61D246B30285ED35`). Include the footer `Fixes #<B73 issue number printed by Step 5>`.

---

### Task 6: Revoke sessions on password change, role change and delete

**Files:**
- Modify: `internal/services/users/user_service.go` (struct and config lines 100-131; `UpdateUser` end; `DeleteUser` lines 398-410)
- Modify: `internal/container/service_container.go:565-570`
- Modify: `internal/services/users/user_service_test.go` (mocks section after line 118; `newService` lines 142-152; new tests)

**Interfaces:**
- Consumes: `UpdateUser` returning `(*UpdateUserResult, error)` (Task 4); `repositories.SessionRepositoryInterface.RevokeAllUserSessions(ctx, userID uuid.UUID, reason string) error` (already exists, `internal/repositories/session_repository.go:339`).
- Produces:
  - `users.SessionRevoker` interface with `RevokeAllUserSessions(ctx context.Context, userID uuid.UUID, reason string) error`.
  - `users.UserServiceConfig.SessionRevoker SessionRevoker`.
  - `UpdateUser` revokes all of the target user's sessions after a successful write when `req.Password != nil || req.Roles != nil`. `DeleteUser` revokes them before deleting.

- [ ] **Step 1: Write the failing tests.** In `internal/services/users/user_service_test.go`, add after the `mockTOTPService` methods:

```go
// ---------------------------------------------------------------------------
// Mock: SessionRevoker
// ---------------------------------------------------------------------------

type mockSessionRevoker struct {
	mock.Mock
}

func (m *mockSessionRevoker) RevokeAllUserSessions(ctx context.Context, userID uuid.UUID, reason string) error {
	return m.Called(ctx, userID, reason).Error(0)
}
```

Replace `newService` (lines 142-152) with:

```go
func newService(
	repo *mockUserRepository,
	pw *mockPasswordService,
	totpSvc *mockTOTPService,
) UserService {
	// Tests that do not care about revocation get a revoker that accepts anything.
	revoker := &mockSessionRevoker{}
	revoker.On("RevokeAllUserSessions", mock.Anything, mock.Anything, mock.Anything).Return(nil).Maybe()
	return newServiceWithRevoker(repo, pw, totpSvc, revoker)
}

func newServiceWithRevoker(
	repo *mockUserRepository,
	pw *mockPasswordService,
	totpSvc *mockTOTPService,
	revoker *mockSessionRevoker,
) UserService {
	return NewUserService(UserServiceConfig{
		UserRepository:  repo,
		PasswordService: pw,
		TOTPService:     totpSvc,
		SessionRevoker:  revoker,
		Logger:          testLogger(),
	})
}
```

Append:

```go
// ---------------------------------------------------------------------------
// Session revocation on credential and privilege changes (B74)
// ---------------------------------------------------------------------------

func TestUpdateUser_PasswordChange_RevokesSessions(t *testing.T) {
	t.Parallel()
	repo := &mockUserRepository{}
	pw := &mockPasswordService{}
	revoker := &mockSessionRevoker{}
	svc := newServiceWithRevoker(repo, pw, &mockTOTPService{}, revoker)

	userID := uuid.New()
	repo.On("Read", mock.Anything, userID).Return(&model.User{ID: userID, Username: "alice", Roles: []string{model.RoleUser}, TOTPSecret: "S"}, nil)
	pw.On("HashPassword", "newpass123").Return("hashed-new", nil)
	repo.On("Update", mock.Anything, mock.AnythingOfType("*model.User")).Return(nil)
	revoker.On("RevokeAllUserSessions", mock.Anything, userID, "password or roles changed").Return(nil)

	newPw := "newpass123"
	_, err := svc.UpdateUser(context.Background(), UpdateUserRequest{UserID: userID, CallerRoles: []string{model.RoleUser}, Password: &newPw})

	require.NoError(t, err)
	revoker.AssertExpectations(t)
}

func TestUpdateUser_RoleChange_RevokesSessions(t *testing.T) {
	t.Parallel()
	repo := &mockUserRepository{}
	revoker := &mockSessionRevoker{}
	svc := newServiceWithRevoker(repo, &mockPasswordService{}, &mockTOTPService{}, revoker)

	userID := uuid.New()
	repo.On("Read", mock.Anything, userID).Return(&model.User{ID: userID, Username: "alice", Roles: []string{model.RoleAdmin}}, nil)
	repo.On("Update", mock.Anything, mock.AnythingOfType("*model.User")).Return(nil)
	revoker.On("RevokeAllUserSessions", mock.Anything, userID, "password or roles changed").Return(nil)

	_, err := svc.UpdateUser(context.Background(), UpdateUserRequest{
		UserID: userID, CallerRoles: []string{model.RoleAdmin}, Roles: []string{model.RoleUser},
	})

	require.NoError(t, err)
	revoker.AssertExpectations(t)
}

func TestUpdateUser_UsernameOnly_KeepsSessions(t *testing.T) {
	t.Parallel()
	repo := &mockUserRepository{}
	revoker := &mockSessionRevoker{}
	svc := newServiceWithRevoker(repo, &mockPasswordService{}, &mockTOTPService{}, revoker)

	userID := uuid.New()
	repo.On("Read", mock.Anything, userID).Return(&model.User{ID: userID, Username: "alice", Roles: []string{model.RoleUser}}, nil)
	repo.On("Update", mock.Anything, mock.AnythingOfType("*model.User")).Return(nil)

	newName := "alice2"
	_, err := svc.UpdateUser(context.Background(), UpdateUserRequest{UserID: userID, CallerRoles: []string{model.RoleUser}, Username: &newName})

	require.NoError(t, err)
	revoker.AssertNotCalled(t, "RevokeAllUserSessions", mock.Anything, mock.Anything, mock.Anything)
}

func TestUpdateUser_FailedWrite_KeepsSessions(t *testing.T) {
	t.Parallel()
	repo := &mockUserRepository{}
	pw := &mockPasswordService{}
	revoker := &mockSessionRevoker{}
	svc := newServiceWithRevoker(repo, pw, &mockTOTPService{}, revoker)

	userID := uuid.New()
	repo.On("Read", mock.Anything, userID).Return(&model.User{ID: userID, Username: "alice", Roles: []string{model.RoleUser}, TOTPSecret: "S"}, nil)
	pw.On("HashPassword", "newpass123").Return("hashed-new", nil)
	repo.On("Update", mock.Anything, mock.AnythingOfType("*model.User")).Return(errors.New("db error"))

	newPw := "newpass123"
	_, err := svc.UpdateUser(context.Background(), UpdateUserRequest{UserID: userID, CallerRoles: []string{model.RoleUser}, Password: &newPw})

	require.Error(t, err)
	revoker.AssertNotCalled(t, "RevokeAllUserSessions", mock.Anything, mock.Anything, mock.Anything)
}

func TestUpdateUser_RevocationFails_ReturnsError(t *testing.T) {
	t.Parallel()
	repo := &mockUserRepository{}
	pw := &mockPasswordService{}
	revoker := &mockSessionRevoker{}
	svc := newServiceWithRevoker(repo, pw, &mockTOTPService{}, revoker)

	userID := uuid.New()
	repo.On("Read", mock.Anything, userID).Return(&model.User{ID: userID, Username: "alice", Roles: []string{model.RoleUser}, TOTPSecret: "S"}, nil)
	pw.On("HashPassword", "newpass123").Return("hashed-new", nil)
	repo.On("Update", mock.Anything, mock.AnythingOfType("*model.User")).Return(nil)
	revoker.On("RevokeAllUserSessions", mock.Anything, userID, "password or roles changed").Return(errors.New("db error"))

	newPw := "newpass123"
	_, err := svc.UpdateUser(context.Background(), UpdateUserRequest{UserID: userID, CallerRoles: []string{model.RoleUser}, Password: &newPw})

	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to revoke user sessions")
}

func TestDeleteUser_RevokesSessionsFirst(t *testing.T) {
	t.Parallel()
	repo := &mockUserRepository{}
	revoker := &mockSessionRevoker{}
	svc := newServiceWithRevoker(repo, &mockPasswordService{}, &mockTOTPService{}, revoker)

	userID := uuid.New()
	var order []string
	revoker.On("RevokeAllUserSessions", mock.Anything, userID, "user deleted").
		Run(func(mock.Arguments) { order = append(order, "revoke") }).Return(nil)
	repo.On("Delete", mock.Anything, userID).
		Run(func(mock.Arguments) { order = append(order, "delete") }).Return(nil)

	require.NoError(t, svc.DeleteUser(context.Background(), userID))
	assert.Equal(t, []string{"revoke", "delete"}, order)
}

func TestDeleteUser_RevocationFails_DoesNotDelete(t *testing.T) {
	t.Parallel()
	repo := &mockUserRepository{}
	revoker := &mockSessionRevoker{}
	svc := newServiceWithRevoker(repo, &mockPasswordService{}, &mockTOTPService{}, revoker)

	userID := uuid.New()
	revoker.On("RevokeAllUserSessions", mock.Anything, userID, "user deleted").Return(errors.New("db error"))

	err := svc.DeleteUser(context.Background(), userID)

	require.Error(t, err)
	repo.AssertNotCalled(t, "Delete", mock.Anything, mock.Anything)
}

func TestUpdateUser_NoRevokerConfigured_FailsClosed(t *testing.T) {
	t.Parallel()
	repo := &mockUserRepository{}
	svc := NewUserService(UserServiceConfig{UserRepository: repo, Logger: testLogger()})

	userID := uuid.New()
	repo.On("Read", mock.Anything, userID).Return(&model.User{ID: userID, Username: "alice", Roles: []string{model.RoleAdmin}}, nil)
	repo.On("Update", mock.Anything, mock.AnythingOfType("*model.User")).Return(nil)

	_, err := svc.UpdateUser(context.Background(), UpdateUserRequest{
		UserID: userID, CallerRoles: []string{model.RoleAdmin}, Roles: []string{model.RoleUser},
	})

	require.Error(t, err)
	assert.Contains(t, err.Error(), "session revocation is not configured")
}
```

- [ ] **Step 2: Run them and see them fail.**
Run: `go test ./internal/services/users/ -run 'Revok|KeepsSessions|NoRevoker' -v`
Expected: build failure, `unknown field SessionRevoker in struct literal of type UserServiceConfig`.

- [ ] **Step 3: Implement.** In `internal/services/users/user_service.go`, add above `type userService struct`:

```go
// SessionRevoker revokes every session a user holds.
// repositories.SessionRepositoryInterface satisfies it.
type SessionRevoker interface {
	RevokeAllUserSessions(ctx context.Context, userID uuid.UUID, reason string) error
}
```

Add `sessionRevoker SessionRevoker` to `userService`, `SessionRevoker SessionRevoker` to `UserServiceConfig`, and `sessionRevoker: config.SessionRevoker,` in `NewUserService`. Add the helper below `guardSystemUser`:

```go
// revokeSessions ends every session of userID. A missing revoker is an error,
// because silently skipping revocation would leave old credentials usable.
func (s *userService) revokeSessions(ctx context.Context, userID uuid.UUID, reason string) error {
	if s.sessionRevoker == nil {
		return fmt.Errorf("session revocation is not configured")
	}
	if err := s.sessionRevoker.RevokeAllUserSessions(ctx, userID, reason); err != nil {
		s.logger.LogAuditError(userID.String(), "revoke_user_sessions", "failed", "Failed to revoke sessions", err)
		return fmt.Errorf("failed to revoke user sessions: %w", err)
	}
	return nil
}
```

In `UpdateUser`, directly after the successful `s.userRepo.Update` block and before the `LogAuditInfo(... "update_user", "success" ...)` line, add:

```go
	// Access tokens carry roles and refresh tokens outlive a password, so both
	// changes must end every existing session of the user.
	if req.Password != nil || req.Roles != nil {
		if err := s.revokeSessions(ctx, req.UserID, "password or roles changed"); err != nil {
			return nil, err
		}
	}
```

In `DeleteUser`, directly after the `guardSystemUser` check, add:

```go
	// Revoke first: SQLite leaves user_sessions rows behind on delete because
	// its foreign keys are off, and a failed revoke must not orphan live sessions.
	if err := s.revokeSessions(ctx, userID, "user deleted"); err != nil {
		return err
	}
```

- [ ] **Step 4: Wire the container.** In `internal/container/service_container.go`, add `SessionRevoker:  c.sessionRepository,` to the `userServices.UserServiceConfig{...}` literal (lines 565-570). `c.sessionRepository` is set earlier at line 386.

- [ ] **Step 5: Run and expect PASS.**
Run: `go build ./... && go test ./internal/services/users/ ./internal/container/ -v`
Expected: `PASS`.

- [ ] **Step 6: Commit.** Invoke the `dev-workflow-skills:1-git-commit` plugin skill via the Skill tool (GPG-signed, key `61D246B30285ED35`).

---

### Task 7: ValidateSession rejects tokens of deleted users (B74)

**Files:**
- Modify: `internal/services/auth/authentication_service.go` (`ValidateSession`, the `else` branch at lines 301-311)
- Modify: `internal/services/auth/authentication_service_test.go:38-41` (`MockUserRepository.Read`, make it nil-safe)
- Modify: `internal/services/auth/authentication_service_critical_test.go` (`TestValidateSession_ActiveSession`, lines 261-289; new tests)
- Modify: `.claude/known-bugs.md` (new entry B74)

**Interfaces:**
- Consumes: `repositories.UserRepositoryInterface.Read(ctx, id uuid.UUID) (*model.User, error)`, which wraps `repositories.ErrNotFound` on a missing row (`internal/repositories/user_repository.go:174-175`).
- Produces: `ValidateSession` returns an error for a user session whose user row no longer exists or cannot be read. Service-account sessions are unchanged.

- [ ] **Step 1: Make the mock nil-safe.** Replace `MockUserRepository.Read` in `internal/services/auth/authentication_service_test.go` with:

```go
func (m *MockUserRepository) Read(ctx context.Context, id uuid.UUID) (*model.User, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*model.User), args.Error(1)
}
```

- [ ] **Step 2: Write the failing tests.** In `internal/services/auth/authentication_service_critical_test.go`, add to `TestValidateSession_ActiveSession` before `svc := newAuthService(...)`:

```go
	userRepo.On("Read", ctx, userID).Return(&model.User{ID: userID, Username: "alice"}, nil)
```

and before its final `sessionRepo.AssertExpectations(t)` add `userRepo.AssertExpectations(t)`. Append:

```go
// SQLite keeps user_sessions rows after a user delete, so a live token must
// not outlive its user.
func TestValidateSession_DeletedUser_Rejected(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	sessionID := uuid.New()
	userID := uuid.New()

	claims := &JWTClaims{UserID: userID, Username: "ghost", Roles: []string{model.RoleUser}}
	claims.ID = sessionID.String()

	userRepo := &MockUserRepository{}
	sessionRepo := &MockSessionRepository{}
	jwt := &MockJWTService{}

	jwt.On("ValidateToken", "orphan-token").Return(claims, nil)
	sessionRepo.On("IsSessionRevoked", ctx, sessionID).Return(false, nil)
	userRepo.On("Read", ctx, userID).Return(nil, fmt.Errorf("user not found: %w", repositories.ErrNotFound))

	svc := newAuthService(userRepo, sessionRepo, &MockPasswordService{}, &MockTOTPService{}, jwt, nil)
	_, err := svc.ValidateSession(ctx, "orphan-token")

	require.Error(t, err)
	assert.Contains(t, err.Error(), "user no longer exists")
}

func TestValidateSession_UserLookupError_Rejected(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	sessionID := uuid.New()
	userID := uuid.New()

	claims := &JWTClaims{UserID: userID, Username: "alice", Roles: []string{model.RoleUser}}
	claims.ID = sessionID.String()

	userRepo := &MockUserRepository{}
	sessionRepo := &MockSessionRepository{}
	jwt := &MockJWTService{}

	jwt.On("ValidateToken", "lookup-fails").Return(claims, nil)
	sessionRepo.On("IsSessionRevoked", ctx, sessionID).Return(false, nil)
	userRepo.On("Read", ctx, userID).Return(nil, errors.New("db unavailable"))

	svc := newAuthService(userRepo, sessionRepo, &MockPasswordService{}, &MockTOTPService{}, jwt, nil)
	_, err := svc.ValidateSession(ctx, "lookup-fails")

	require.Error(t, err)
	assert.Contains(t, err.Error(), "user lookup failed")
}
```

- [ ] **Step 3: Run them and see them fail.**
Run: `go test ./internal/services/auth/ -run 'TestValidateSession_(DeletedUser|UserLookupError|ActiveSession)' -v`
Expected: `TestValidateSession_DeletedUser_Rejected` and `TestValidateSession_UserLookupError_Rejected` FAIL (`An error is expected but got nil`); `TestValidateSession_ActiveSession` FAILS on `userRepo.AssertExpectations` (`Read` not called).

- [ ] **Step 4: Implement.** In `ValidateSession`, inside the `else` branch, directly after the `if revoked { ... }` block, add:

```go
		// Tokens name a user that must still exist. SQLite keeps session rows
		// after a user delete, so the revocation table alone cannot tell.
		if _, err := s.userRepo.Read(ctx, claims.UserID); err != nil {
			if errors.Is(err, repositories.ErrNotFound) {
				s.logger.LogAuditError(claims.UserID.String(), "validate_session", "failed", "User no longer exists", nil)
				return nil, fmt.Errorf("invalid session: user no longer exists")
			}
			s.logger.LogAuditError(claims.UserID.String(), "validate_session", "failed", "Could not load session user", err)
			return nil, fmt.Errorf("invalid session: user lookup failed")
		}
```

- [ ] **Step 5: Run the whole suite and expect PASS.**
Run: `go build ./... && go test ./...`
Expected: every package passes. If a test elsewhere mints a real token for a user id that has no `users` row and runs it through the real `AuthenticationService`, insert that user row in the test's fixture rather than weakening the check.

- [ ] **Step 6: Record B74.** Insert above `## Deferred Refactors` in `.claude/known-bugs.md`:

```markdown
### B74 — Password, role and delete changes left existing sessions alive

**Status**: Fixed (identity and sessions hardening, 2026-09-30); GitHub #47.
Refresh-token rotation and reuse detection from the same issue are an
optional follow-up (plan task 13) because they change the refresh contract
**Severity**: Medium
**Files**: `internal/services/users/user_service.go`,
`internal/services/auth/authentication_service.go`,
`internal/container/service_container.go`

**Symptom**: demoting an admin left the admin role in their JWT until it
expired (`jwt.expiry`, default 1h). Deleting a user left their access token
valid, and on SQLite, where foreign keys are off, their `user_sessions` rows
survived. A password change did not end existing refresh tokens (7 days).

**Root cause**: `UpdateUser` and `DeleteUser` never touched sessions, and
`ValidateSession` checked only the session revocation table, never that the
user still existed.

**What was fixed**: `UserService` gained a `SessionRevoker` dependency (wired
to the session repository). `UpdateUser` revokes every session of the target
user after a successful password or role change; a username-only change keeps
them. `DeleteUser` revokes first and deletes only if that succeeded. A missing
revoker fails closed. `ValidateSession` now reads the user row for every user
session and rejects the token when the user is gone or cannot be read. A user
who changes their own password is logged out too and must log in again.

---
```

- [ ] **Step 7: Commit.** Invoke the `dev-workflow-skills:1-git-commit` plugin skill via the Skill tool (GPG-signed, key `61D246B30285ED35`). Include the footer `Fixes #47`.

---

### Task 8: Add the `users.totp_last_step` column

**Files:**
- Modify: `internal/db/db.go:341-350` (users `CREATE TABLE`) and the `migrations` slice in `migrateSchema` (after line 972)
- Test: `internal/db/totp_last_step_schema_test.go` (new); `internal/db/upgrade_path_test.go` (extend `TestUpgradePath_PreFeatureUsersGetsAuthProvider`, lines 132-228)

**Interfaces:**
- Consumes: `DBRepository.createOptimizedSchema`, `DBRepository.migrateSchema`, test helpers `columnExists` (`internal/db/migrate_assignment_test.go:195`) and `newSilentLogrus` (used by `internal/db/user_roles_schema_test.go:19`).
- Produces: column `users.totp_last_step INTEGER NOT NULL DEFAULT 0` on fresh and upgraded databases.

- [ ] **Step 1: Write the failing tests.** Create `internal/db/totp_last_step_schema_test.go`:

```go
package db

import (
	"database/sql"
	"testing"

	_ "github.com/mattn/go-sqlite3"
	"github.com/stretchr/testify/require"

	"rocketvault/internal/logging"
)

// A fresh install must create totp_last_step in the users CREATE TABLE itself.
func TestUsersTOTPLastStep_CreatedOnFreshInstall(t *testing.T) {
	conn, err := sql.Open("sqlite3", ":memory:")
	require.NoError(t, err)
	defer conn.Close() //nolint:errcheck

	d := &DBRepository{dialect: SQLite}
	d.log = &logging.Logger{Logger: newSilentLogrus()}
	require.NoError(t, d.createOptimizedSchema(conn))

	require.True(t, columnExists(t, conn, "users", "totp_last_step"),
		"createOptimizedSchema must create users.totp_last_step")

	_, err = conn.Exec(`INSERT INTO users (id, username, password_hash, role) VALUES ('u1', 'alice', 'h', 'admin')`)
	require.NoError(t, err)
	var step int64
	require.NoError(t, conn.QueryRow(`SELECT totp_last_step FROM users WHERE id = 'u1'`).Scan(&step))
	require.Equal(t, int64(0), step)
}
```

In `internal/db/upgrade_path_test.go`, inside `TestUpgradePath_PreFeatureUsersGetsAuthProvider`, add after the existing `require.False(t, columnExists(t, conn, "users", "auth_provider"), ...)` sanity check:

```go
	require.False(t, columnExists(t, conn, "users", "totp_last_step"),
		"totp_last_step must not exist before the upgrade sequence runs")
```

and at the end of the function:

```go
	// The TOTP replay column must be added to the old table, defaulted to 0.
	var step int64
	if err := conn.QueryRow(`SELECT totp_last_step FROM users WHERE id = 'u1'`).Scan(&step); err != nil {
		t.Fatalf("querying pre-existing user's totp_last_step failed: %v", err)
	}
	require.Equal(t, int64(0), step, "pre-existing users must start with totp_last_step 0")
```

- [ ] **Step 2: Run them and see them fail.**
Run: `go test ./internal/db/ -run 'TestUsersTOTPLastStep|TestUpgradePath_PreFeatureUsersGetsAuthProvider' -v`
Expected: FAIL, `createOptimizedSchema must create users.totp_last_step` and `no such column: totp_last_step`.

- [ ] **Step 3: Implement both halves of the dual write.** In the users `CREATE TABLE` in `createOptimizedSchema`, add a line after `external_idp_subject TEXT,`:

```sql
			totp_last_step INTEGER NOT NULL DEFAULT 0,
```

In `migrateSchema`'s `migrations` slice, add after the `idx_users_external_idp` line:

```go
		// Feature: TOTP replay protection, last accepted time step per user.
		"ALTER TABLE users ADD COLUMN totp_last_step INTEGER NOT NULL DEFAULT 0",
```

Both statements are valid on SQLite and Postgres; a rerun hits `isDuplicateColumnError` and is skipped. `INTEGER` is 32-bit on Postgres, and the current step (`unix / 30`, about 5.9e7) stays far below its limit.

- [ ] **Step 4: Run and expect PASS.**
Run: `go test ./internal/db/ -v`
Expected: `PASS`.

- [ ] **Step 5: Commit.** Invoke the `dev-workflow-skills:1-git-commit` plugin skill via the Skill tool (GPG-signed, key `61D246B30285ED35`).

---

### Task 9: TOTPStepRepository with an atomic claim

**Files:**
- Create: `internal/repositories/totp_step_repository.go`
- Modify: `internal/repositories/missing_coverage_test.go:44-76` (`setupUserDB` users table)
- Test: `internal/repositories/totp_step_repository_test.go` (new)

**Interfaces:**
- Consumes: `users.totp_last_step` (Task 8); `withMetrics(table, operation string, fn func() error) error` (`internal/repositories/metrics.go:23`); `db.DB.ExecContext`.
- Produces:
  - `repositories.TOTPStepRepositoryInterface` with `ClaimTOTPStep(ctx context.Context, userID uuid.UUID, step int64) (bool, error)`.
  - `repositories.NewTOTPStepRepository(conn db.DB) TOTPStepRepositoryInterface`.

- [ ] **Step 1: Extend the test schema.** In `setupUserDB` in `internal/repositories/missing_coverage_test.go`, add after `external_idp_subject TEXT,`:

```sql
			totp_last_step       INTEGER NOT NULL DEFAULT 0,
```

- [ ] **Step 2: Write the failing test.** Create `internal/repositories/totp_step_repository_test.go`:

```go
package repositories_test

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	rvdb "rocketvault/internal/db"
	"rocketvault/internal/repositories"
	"rocketvault/model"
)

func TestTOTPStepRepository_ClaimTOTPStep(t *testing.T) {
	t.Parallel()
	db := setupUserDB(t)
	conn := rvdb.NewConn(db, rvdb.SQLite)
	users := repositories.NewUserRepository(conn, newLogger())
	steps := repositories.NewTOTPStepRepository(conn)
	ctx := context.Background()

	u := newUser("stepper", model.RoleUser)
	require.NoError(t, users.Create(ctx, u))

	claimed, err := steps.ClaimTOTPStep(ctx, u.ID, 100)
	require.NoError(t, err)
	assert.True(t, claimed, "the first use of a step must be accepted")

	claimed, err = steps.ClaimTOTPStep(ctx, u.ID, 100)
	require.NoError(t, err)
	assert.False(t, claimed, "the same step must not be accepted twice")

	claimed, err = steps.ClaimTOTPStep(ctx, u.ID, 99)
	require.NoError(t, err)
	assert.False(t, claimed, "an older step must be rejected")

	claimed, err = steps.ClaimTOTPStep(ctx, u.ID, 101)
	require.NoError(t, err)
	assert.True(t, claimed, "a newer step must be accepted")
}

func TestTOTPStepRepository_ClaimTOTPStep_UnknownUser(t *testing.T) {
	t.Parallel()
	db := setupUserDB(t)
	steps := repositories.NewTOTPStepRepository(rvdb.NewConn(db, rvdb.SQLite))

	claimed, err := steps.ClaimTOTPStep(context.Background(), uuid.New(), 100)
	require.NoError(t, err)
	assert.False(t, claimed, "a missing user can never claim a step")
}
```

- [ ] **Step 3: Run it and see it fail.**
Run: `go test ./internal/repositories/ -run TestTOTPStepRepository -v`
Expected: build failure, `undefined: repositories.NewTOTPStepRepository`.

- [ ] **Step 4: Implement.** Create `internal/repositories/totp_step_repository.go`:

```go
package repositories

import (
	"context"
	"fmt"

	"github.com/google/uuid"

	"rocketvault/internal/db"
)

// TOTPStepRepositoryInterface records the last TOTP time step each user has used.
type TOTPStepRepositoryInterface interface {
	// ClaimTOTPStep stores step as the user's last accepted TOTP time step.
	// It returns false when step is not newer than the stored one.
	ClaimTOTPStep(ctx context.Context, userID uuid.UUID, step int64) (bool, error)
}

// TOTPStepRepository implements TOTPStepRepositoryInterface on users.totp_last_step.
type TOTPStepRepository struct {
	db db.DB
}

// NewTOTPStepRepository creates a TOTPStepRepository.
func NewTOTPStepRepository(conn db.DB) TOTPStepRepositoryInterface {
	return &TOTPStepRepository{db: conn}
}

// ClaimTOTPStep is one conditional UPDATE, so two logins racing with the same
// code cannot both see the step as unused.
func (r *TOTPStepRepository) ClaimTOTPStep(ctx context.Context, userID uuid.UUID, step int64) (bool, error) {
	var claimed bool
	err := withMetrics("users", "claim_totp_step", func() error {
		result, err := r.db.ExecContext(ctx,
			"UPDATE users SET totp_last_step = ? WHERE id = ? AND totp_last_step < ?",
			step, userID.String(), step)
		if err != nil {
			return fmt.Errorf("failed to claim TOTP step: %w", err)
		}
		rowsAffected, err := result.RowsAffected()
		if err != nil {
			return fmt.Errorf("failed to get rows affected: %w", err)
		}
		claimed = rowsAffected == 1
		return nil
	})
	return claimed, err
}
```

- [ ] **Step 5: Run and expect PASS.**
Run: `go test ./internal/repositories/ -v -run 'TestTOTPStepRepository|TestUserRepository_'`
Expected: `PASS`.

- [ ] **Step 6: Commit.** Invoke the `dev-workflow-skills:1-git-commit` plugin skill via the Skill tool (GPG-signed, key `61D246B30285ED35`).

---

### Task 10: TOTPService.ValidateCodeWithStep

**Files:**
- Modify: `internal/services/auth/totp_service.go` (imports lines 3-9; interface lines 14-18; new method after `ValidateCode`, line 99)
- Modify mocks: `internal/services/auth/authentication_service_test.go:143-160` (`MockTOTPService`), `internal/services/users/user_service_test.go:100-118` (`mockTOTPService`)
- Test: `internal/services/auth/totp_step_test.go` (new)

**Interfaces:**
- Consumes: `github.com/pquerna/otp/hotp.GenerateCodeCustom(secret string, counter uint64, opts hotp.ValidateOpts) (string, error)`; `otp.Digits.Length() int`.
- Produces: `TOTPService.ValidateCodeWithStep(code, secret string, currentTime time.Time) (int64, bool, error)`. It returns the time step (`unix / 30`) the code belongs to. With several matches in the window it returns the latest one. It returns an error for an empty or malformed secret and `(0, false, nil)` for a wrong code or a wrong length.

- [ ] **Step 1: Write the failing test.** Create `internal/services/auth/totp_step_test.go`:

```go
package auth

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const stepTestSecret = "JBSWY3DPEHPK3PXP"

func TestTOTPService_ValidateCodeWithStep_ReturnsMatchedStep(t *testing.T) {
	t.Parallel()
	svc := NewTOTPService()
	now := time.Unix(1_700_000_000, 0)

	for _, offset := range []time.Duration{-60 * time.Second, -30 * time.Second, 0, 30 * time.Second, 60 * time.Second} {
		at := now.Add(offset)
		code, err := svc.GenerateCode(stepTestSecret, at)
		require.NoError(t, err)

		step, valid, err := svc.ValidateCodeWithStep(code, stepTestSecret, now)
		require.NoError(t, err)
		assert.True(t, valid, "offset %s must be inside the window", offset)
		assert.Equal(t, at.Unix()/30, step, "offset %s", offset)
	}
}

func TestTOTPService_ValidateCodeWithStep_OutsideWindow(t *testing.T) {
	t.Parallel()
	svc := NewTOTPService()
	now := time.Unix(1_700_000_000, 0)

	code, err := svc.GenerateCode(stepTestSecret, now.Add(-90*time.Second))
	require.NoError(t, err)

	_, valid, err := svc.ValidateCodeWithStep(code, stepTestSecret, now)
	require.NoError(t, err)
	assert.False(t, valid)
}

func TestTOTPService_ValidateCodeWithStep_EmptySecret(t *testing.T) {
	t.Parallel()
	_, valid, err := NewTOTPService().ValidateCodeWithStep("123456", "", time.Now())
	require.Error(t, err)
	assert.False(t, valid)
}

func TestTOTPService_ValidateCodeWithStep_WrongLength(t *testing.T) {
	t.Parallel()
	_, valid, err := NewTOTPService().ValidateCodeWithStep("12345", stepTestSecret, time.Now())
	require.NoError(t, err)
	assert.False(t, valid)
}

func TestTOTPService_ValidateCodeWithStep_InvalidSecret(t *testing.T) {
	t.Parallel()
	_, _, err := NewTOTPService().ValidateCodeWithStep("123456", "!!! not base32 !!!", time.Now())
	require.Error(t, err)
}
```

- [ ] **Step 2: Run it and see it fail.**
Run: `go test ./internal/services/auth/ -run TestTOTPService_ValidateCodeWithStep -v`
Expected: build failure, `svc.ValidateCodeWithStep undefined`.

- [ ] **Step 3: Implement.** In `internal/services/auth/totp_service.go`, change the imports to:

```go
import (
	"crypto/subtle"
	"fmt"
	"time"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/hotp"
	"github.com/pquerna/otp/totp"
)
```

Add to the `TOTPService` interface:

```go
	// ValidateCodeWithStep validates code and returns the time step it belongs to,
	// so callers can refuse a step that was already used.
	ValidateCodeWithStep(code, secret string, currentTime time.Time) (int64, bool, error)
```

Add after `ValidateCode`:

```go
// ValidateCodeWithStep checks code against every step in the skew window and
// returns the latest matching step. Every step is compared, so the timing does
// not reveal which step matched.
func (s *totpService) ValidateCodeWithStep(code, secret string, currentTime time.Time) (int64, bool, error) {
	if secret == "" {
		return 0, false, fmt.Errorf("TOTP validation error: empty secret")
	}
	if len(code) != s.digits.Length() {
		return 0, false, nil
	}

	period := int64(s.period)
	current := currentTime.Unix() / period
	opts := hotp.ValidateOpts{Digits: s.digits, Algorithm: s.algorithm}

	var matched int64
	found := false
	for step := current - int64(s.skew); step <= current+int64(s.skew); step++ {
		expected, err := hotp.GenerateCodeCustom(secret, uint64(step), opts) //nolint:gosec // Steps are positive Unix-time counters.
		if err != nil {
			return 0, false, fmt.Errorf("TOTP validation error: %w", err)
		}
		if subtle.ConstantTimeCompare([]byte(expected), []byte(code)) == 1 {
			matched = step
			found = true
		}
	}

	return matched, found, nil
}
```

- [ ] **Step 4: Update both TOTP mocks.** Add to `MockTOTPService` in `internal/services/auth/authentication_service_test.go` and to `mockTOTPService` in `internal/services/users/user_service_test.go` (adjust the receiver name):

```go
func (m *MockTOTPService) ValidateCodeWithStep(code, secret string, currentTime time.Time) (int64, bool, error) {
	args := m.Called(code, secret, currentTime)
	return args.Get(0).(int64), args.Bool(1), args.Error(2)
}
```

- [ ] **Step 5: Run and expect PASS.**
Run: `go build ./... && go test ./internal/services/auth/ ./internal/services/users/ -v -run 'TOTP'`
Expected: `PASS`.

- [ ] **Step 6: Commit.** Invoke the `dev-workflow-skills:1-git-commit` plugin skill via the Skill tool (GPG-signed, key `61D246B30285ED35`).

---

### Task 11: Reject replayed TOTP codes at login (B75, #45)

**Files:**
- Modify: `internal/services/auth/authentication_service.go` (struct lines 62-72; config lines 75-84; constructor lines 95-106; TOTP block in `AuthenticateUser`, lines 153-178)
- Modify: `internal/container/service_container.go` (field list near line 167; init after line 389; auth config lines 475-484)
- Modify tests: `internal/services/auth/authentication_service_test.go` (lines 250-313, 427-470, 507-567, 589-631; 423), `internal/services/auth/auth_edge_cases_test.go` (lines 172-304), `internal/services/auth/authentication_service_critical_test.go:60`
- Test: `internal/services/auth/totp_replay_test.go` (new)
- Modify: `.claude/known-bugs.md` (new entry B75)

**Interfaces:**
- Consumes: `TOTPService.ValidateCodeWithStep` (Task 10); `repositories.TOTPStepRepositoryInterface`, `repositories.NewTOTPStepRepository` (Task 9); `ErrMFANotEnrolled` check (Task 5), which stays in front of the TOTP check.
- Produces: `auth.AuthenticationConfig.TOTPStepRepository repositories.TOTPStepRepositoryInterface`. `AuthenticateUser` fails with `invalid TOTP code` when the step was already claimed, and fails closed when the repository is nil.

- [ ] **Step 1: Write the failing tests.** Create `internal/services/auth/totp_replay_test.go`:

```go
package auth

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	rvdb "rocketvault/internal/db"
	"rocketvault/internal/logging"
	"rocketvault/internal/repositories"
	"rocketvault/model"
)

type MockTOTPStepRepository struct {
	mock.Mock
}

func (m *MockTOTPStepRepository) ClaimTOTPStep(ctx context.Context, userID uuid.UUID, step int64) (bool, error) {
	args := m.Called(ctx, userID, step)
	return args.Bool(0), args.Error(1)
}

func TestAuthenticateUser_ReplayedStep_Rejected(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	userRepo := &MockUserRepository{}
	sessionRepo := &MockSessionRepository{}
	pwd := &MockPasswordService{}
	totp := &MockTOTPService{}
	steps := &MockTOTPStepRepository{}

	user := model.User{ID: uuid.New(), Username: "replay", PasswordHash: "hashed", TOTPSecret: "secret", Roles: []string{model.RoleUser}}
	userRepo.On("ReadByUsername", ctx, "replay").Return(user, nil)
	pwd.On("ValidatePassword", "pass", "hashed").Return(nil)
	totp.On("ValidateCodeWithStep", "123456", "secret", mock.AnythingOfType("time.Time")).Return(int64(56666666), true, nil)
	steps.On("ClaimTOTPStep", ctx, user.ID, int64(56666666)).Return(false, nil)

	svc := NewAuthenticationService(AuthenticationConfig{
		UserRepository: userRepo, SessionRepository: sessionRepo, PasswordService: pwd,
		TOTPService: totp, JWTService: &MockJWTService{}, TOTPStepRepository: steps, Logger: logging.InitLogger(),
	})
	_, err := svc.AuthenticateUser(ctx, "replay", "pass", "123456")

	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid TOTP code")
	sessionRepo.AssertNotCalled(t, "CreateSession", mock.Anything, mock.Anything)
}

func TestAuthenticateUser_NoStepRepository_FailsClosed(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	userRepo := &MockUserRepository{}
	sessionRepo := &MockSessionRepository{}
	pwd := &MockPasswordService{}
	totp := &MockTOTPService{}

	user := model.User{ID: uuid.New(), Username: "nostep", PasswordHash: "hashed", TOTPSecret: "secret", Roles: []string{model.RoleUser}}
	userRepo.On("ReadByUsername", ctx, "nostep").Return(user, nil)
	pwd.On("ValidatePassword", "pass", "hashed").Return(nil)
	totp.On("ValidateCodeWithStep", "123456", "secret", mock.AnythingOfType("time.Time")).Return(int64(1), true, nil)

	svc := NewAuthenticationService(AuthenticationConfig{
		UserRepository: userRepo, SessionRepository: sessionRepo, PasswordService: pwd,
		TOTPService: totp, JWTService: &MockJWTService{}, Logger: logging.InitLogger(),
	})
	_, err := svc.AuthenticateUser(ctx, "nostep", "pass", "123456")

	require.Error(t, err)
	assert.Contains(t, err.Error(), "replay protection is not configured")
	sessionRepo.AssertNotCalled(t, "CreateSession", mock.Anything, mock.Anything)
}

// End to end with the real TOTP service and a real SQLite claim.
func TestAuthenticateUser_SameCodeTwice_SecondRejected(t *testing.T) {
	ctx := context.Background()
	conn, err := sql.Open("sqlite3", ":memory:")
	require.NoError(t, err)
	conn.SetMaxOpenConns(1) // Each :memory: connection is its own database.
	t.Cleanup(func() { _ = conn.Close() })
	_, err = conn.Exec(`CREATE TABLE users (id TEXT PRIMARY KEY, totp_last_step INTEGER NOT NULL DEFAULT 0)`)
	require.NoError(t, err)

	totpSvc := NewTOTPService()
	key, err := totpSvc.GenerateSecret("RocketVault", "replay")
	require.NoError(t, err)
	user := model.User{ID: uuid.New(), Username: "replay", PasswordHash: "hashed", TOTPSecret: key.Secret(), Roles: []string{model.RoleUser}}
	_, err = conn.Exec(`INSERT INTO users (id) VALUES (?)`, user.ID.String())
	require.NoError(t, err)

	userRepo := &MockUserRepository{}
	sessionRepo := &MockSessionRepository{}
	pwd := &MockPasswordService{}
	jwt := &MockJWTService{}
	userRepo.On("ReadByUsername", ctx, "replay").Return(user, nil)
	pwd.On("ValidatePassword", "pass", "hashed").Return(nil)
	sessionRepo.On("CreateSession", ctx, mock.AnythingOfType("*model.Session")).Return(nil)
	jwt.On("GenerateToken", user.ID, "replay", user.Roles, mock.AnythingOfType("uuid.UUID")).Return("jwt", nil)

	svc := NewAuthenticationService(AuthenticationConfig{
		UserRepository: userRepo, SessionRepository: sessionRepo, PasswordService: pwd,
		TOTPService: totpSvc, JWTService: jwt, Logger: logging.InitLogger(),
		TOTPStepRepository: repositories.NewTOTPStepRepository(rvdb.NewConn(conn, rvdb.SQLite)),
	})

	code, err := totpSvc.GenerateCode(key.Secret(), time.Now())
	require.NoError(t, err)

	_, err = svc.AuthenticateUser(ctx, "replay", "pass", code)
	require.NoError(t, err, "the first use of a code must succeed")

	_, err = svc.AuthenticateUser(ctx, "replay", "pass", code)
	require.Error(t, err, "a replayed code must be rejected")
	assert.Contains(t, err.Error(), "invalid TOTP code")
}
```

- [ ] **Step 2: Run them and see them fail.**
Run: `go test ./internal/services/auth/ -run 'TestAuthenticateUser_(ReplayedStep|NoStepRepository|SameCodeTwice)' -v`
Expected: build failure, `unknown field TOTPStepRepository in struct literal of type AuthenticationConfig`.

- [ ] **Step 3: Implement.** In `internal/services/auth/authentication_service.go`, add `totpStepRepo repositories.TOTPStepRepositoryInterface` to `authenticationService`, `TOTPStepRepository repositories.TOTPStepRepositoryInterface` to `AuthenticationConfig`, and `totpStepRepo: config.TOTPStepRepository,` to `NewAuthenticationService`. In `AuthenticateUser`, replace

```go
	valid, err := s.totpService.ValidateCode(totpCode, user.TOTPSecret, time.Now())
```

with

```go
	step, valid, err := s.totpService.ValidateCodeWithStep(totpCode, user.TOTPSecret, time.Now())
```

and, directly after the `if !valid { ... }` block and before `result, err := s.issueSession(...)`, add:

```go
	// A code is single use: claiming its time step fails when this step or a
	// later one was already accepted for the user.
	if s.totpStepRepo == nil {
		s.logger.WithField("user_id", user.ID.String()).Error("TOTP replay protection is not configured")
		return nil, fmt.Errorf("authentication failed: TOTP replay protection is not configured")
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
		return nil, fmt.Errorf("authentication failed: %w", err)
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
		return nil, fmt.Errorf("invalid TOTP code")
	}
```

- [ ] **Step 4: Move the existing login tests to the new method.** For each site below, change `"ValidateCode"` to `"ValidateCodeWithStep"` and the return values to `(step, valid, err)`:
- `internal/services/auth/auth_edge_cases_test.go:192-193` (`TestAuthenticateUser_TOTPValidationError`): `.Return(int64(0), false, errors.New("totp internal error"))`
- `internal/services/auth/auth_edge_cases_test.go:236-237` (`TestAuthenticateUser_SessionCreationFails`): `.Return(int64(100), true, nil)`
- `internal/services/auth/auth_edge_cases_test.go:282-283` (`TestAuthenticateUser_JWTGenerationFails`): `.Return(int64(100), true, nil)`
- `internal/services/auth/authentication_service_test.go:278` (`TestAuthenticationService_AuthenticateUser_Success`): `.Return(int64(100), true, nil)`
- `internal/services/auth/authentication_service_test.go:454` (`TestAuthenticationService_AuthenticateUser_InvalidTOTP`): `.Return(int64(0), false, nil)`
- `internal/services/auth/authentication_service_test.go:531` (`TestAuthenticateUser_RecordsRichAuditOutcomeOnSuccessAndFailure`): `.Return(int64(100), true, nil)`
- `internal/services/auth/authentication_service_test.go:611-612` (`TestAuthenticateUser_FailedTOTP_DoesNotLogCode`): `.Return(int64(0), false, nil)`
- `internal/services/auth/authentication_service_test.go:423` and `internal/services/auth/authentication_service_critical_test.go:60`: `AssertNotCalled(t, "ValidateCodeWithStep")`

The four tests that reach the claim (`SessionCreationFails`, `JWTGenerationFails`, `AuthenticateUser_Success`, `RecordsRichAuditOutcomeOnSuccessAndFailure`) also need a step repository. In each, add

```go
	steps := &MockTOTPStepRepository{}
	steps.On("ClaimTOTPStep", mock.Anything, mock.Anything, int64(100)).Return(true, nil)
```

and `TOTPStepRepository: steps,` in its `AuthenticationConfig` literal. `RecordsRichAuditOutcomeOnSuccessAndFailure` claims twice only if both logins pass the TOTP check; its second login fails on the password, so one claim is enough and the `.On` above covers it.

- [ ] **Step 5: Wire the container.** In `internal/container/service_container.go`, add the field `totpStepRepository repositories.TOTPStepRepositoryInterface` next to `sessionRepository`, initialize it right after `c.sessionRepository = ...` (ends line 389):

```go
	c.totpStepRepository = repositories.NewTOTPStepRepository(c.conn)
```

and add `TOTPStepRepository:     c.totpStepRepository,` to the `authServices.AuthenticationConfig{...}` literal (lines 475-484).

- [ ] **Step 6: Run the whole suite and expect PASS.**
Run: `go build ./... && go vet ./... && go test ./...`
Expected: every package passes.

- [ ] **Step 7: Record B75.** Insert above `## Deferred Refactors` in `.claude/known-bugs.md`:

```markdown
### B75 — TOTP codes could be replayed inside the acceptance window

**Status**: Fixed (identity and sessions hardening, 2026-09-30); GitHub #45
**Severity**: Medium
**Files**: `internal/services/auth/totp_service.go`,
`internal/services/auth/authentication_service.go`,
`internal/repositories/totp_step_repository.go`, `internal/db/db.go`,
`internal/container/service_container.go`

**Symptom**: a captured code stayed reusable for its whole acceptance window,
about 150 seconds with a 30-second period and skew 2
(`totp_service.go:41-42`).

**Root cause**: `ValidateCode` delegated to `totp.ValidateCustom`, which
returns only a bool, and nothing recorded which time step a user had already
used.

**What was fixed**: new column `users.totp_last_step INTEGER NOT NULL DEFAULT 0`
(dual-written in `createOptimizedSchema` and `migrateSchema`).
`TOTPService.ValidateCodeWithStep` returns the step a code belongs to, and
`AuthenticateUser` claims that step through `TOTPStepRepository.ClaimTOTPStep`,
a single `UPDATE ... WHERE totp_last_step < ?`, so the same or an older step is
refused even when two logins race. A missing step repository fails closed.
Skew stays 2: replay tracking removes the reuse window, and a smaller skew
would only hurt users with drifting clocks.

**Known limitation**: a user can log in at most once per 30-second step with
TOTP, because the second login in the same step has to wait for a new code.
TOTP secrets are still stored in plaintext (`user_repository.go:129`); that is
a separate finding.

---
```

- [ ] **Step 8: Commit.** Invoke the `dev-workflow-skills:1-git-commit` plugin skill via the Skill tool (GPG-signed, key `61D246B30285ED35`). Include the footer `Fixes #45`.

---

### Task 12: Release note and final verification

**Files:**
- Create: `docs/release-notes/v4.7.0-identity-sessions-hardening.md`
- Modify: `scripts/docsgen/docs.go:45` (register the note after the v4.6.0 line)

**Interfaces:**
- Consumes: behavior from Tasks 2, 4, 5, 6, 7 and 11.
- Produces: operator-facing upgrade guidance.

- [ ] **Step 1: Write the release note.** Create `docs/release-notes/v4.7.0-identity-sessions-hardening.md`:

```markdown
# v4.7.0 — Identity and sessions hardening

This release fixes four identity weaknesses from the 2026-09-30 audit of
`api/`: cross-user session revocation (#40), OIDC accounts that gained a
password without a working second factor (B73), sessions that survived
password, role and delete changes (#47), and TOTP code replay (#45). Full
detail: `.claude/known-bugs.md` § B72-B75.

## Behavior changes

1. **Local login refuses accounts without a TOTP secret.** An account whose
   stored TOTP secret is empty can no longer log in with a password, even a
   correct one. Before this release any six digits worked for such an account,
   because an empty secret yields codes anyone can compute. In practice this
   affects only OIDC-provisioned users who set a local password
   (`rocketvault users update --new-password`, or `PUT /api/v1/users/{id}`).
   Admin-created users always had a secret.
2. **Setting a password on such an account enrolls TOTP.** The response of
   `PUT /api/v1/users/{id}` carries the new `otpauth://` URL in `totp_secret`,
   the same field `POST /api/v1/users` uses, and `rocketvault users update`
   prints it. It is shown once. Accounts that already have a secret keep it
   on every later password change.
3. **Password and role changes end every session of the user.** This
   includes the caller's own session when they change their own password, so
   the next CLI command or API call needs a new login. A username-only change
   keeps sessions.
4. **Deleting a user ends their sessions first**, and every request now
   confirms that the token's user still exists.
5. **Each TOTP code works once.** A second login with the same code, or with
   a code from an earlier 30-second step, fails with `invalid TOTP code`. Two
   local logins by the same user inside one 30-second step need two different
   codes.
6. **`DELETE /api/v1/users/sessions/{id}` is ownership-checked.** Admins can
   still revoke any session. Anyone else gets `404` for a session they do not
   own, the same answer as for a missing session. The route still requires
   the `users:delete` permission, as before.

## Schema

`users` gains `totp_last_step INTEGER NOT NULL DEFAULT 0`. It is added
automatically at startup (`migrateSchema`) on SQLite and Postgres; no manual
step is needed and existing rows start at 0.

## Upgrade procedure

1. Find accounts that the new login check will lock out:

   ```sql
   SELECT id, username, auth_provider FROM users
   WHERE (totp_secret IS NULL OR totp_secret = '') AND password_hash <> '';
   ```

2. Tell each of those users to sign in with `rocketvault users login --oidc`
   and set their password again with
   `rocketvault users update <their-user-id> --new-password <password>`. The
   command prints a TOTP secret; they add it to their authenticator app. Their
   OIDC login keeps working the whole time.
3. Expect every user to log in again after they change their password or an
   admin changes their roles.

## Not in this release

- A fresh IdP login is not yet required before an OIDC account sets a
  password. Someone holding a stolen access token can still set one, and
  would receive the enrollment URL too. See
  `.claude/research-oidc-user-mfa-enrollment.md`, step 5.
- Enrollment is not confirmed with a first code (step 6 of the same doc).
- Refresh tokens are not rotated yet.
```

- [ ] **Step 2: Register it for the docs build.** In `scripts/docsgen/docs.go`, add after line 45:

```go
	{"docs/release-notes/v4.7.0-identity-sessions-hardening.md", "docs/release-notes/v4.7.0-identity-sessions-hardening.html"},
```

- [ ] **Step 3: Build the docs and run the full verification.**
Run: `./scripts/docs.sh build && go build ./... && go vet ./... && go test ./...`
Expected: docs render `docs/release-notes/v4.7.0-identity-sessions-hardening.html`; build, vet and tests pass. golangci-lint runs in CI (it fails locally on the snap Go toolchain).

- [ ] **Step 4: Commit.** Invoke the `dev-workflow-skills:1-git-commit` plugin skill via the Skill tool (GPG-signed, key `61D246B30285ED35`).

---

### Task 13 (OPTIONAL): Refresh-token rotation and reuse detection

> **Optional. Do not start without an explicit go-ahead.** This changes the refresh contract: every `POST /api/v1/users/refresh` returns a new refresh token and the old one stops working. `internal/vaultapi/sessionsource.go:212-213` already expects rotation and writes the new token back, and `cmd/root.go:405-419` saves `refreshed.RefreshToken`. But `cmd/root.go:417-418` only logs a warning when that save fails, so after this change a failed save logs the CLI out on the next refresh. Two processes that share one cached session (CLI and `rocketvault mcp`) and refresh at the same moment would trip reuse detection and revoke the session. Decide on both before enabling.

**Files:**
- Modify: `internal/db/db.go` (user_sessions `CREATE TABLE`, lines 680-694; `migrations` slice)
- Modify: `internal/repositories/session_repository.go` (interface; two new methods)
- Modify: `internal/repositories/missing_coverage_test.go:91-115` (`setupSessionDB`)
- Modify: `internal/services/auth/authentication_service.go` (`RefreshAccessToken`, lines 330-400)
- Modify: `internal/services/auth/authentication_service_test.go` (`MockSessionRepository`; `TestRefreshAccessToken_UsesFreshRolesFromDB`)
- Modify: `internal/services/auth/authentication_service_critical_test.go` (`TestRefreshAccessToken_HappyPath`, `TestRefreshAccessToken_InvalidRefreshToken`)
- Test: `internal/repositories/session_rotation_test.go` (new)

**Interfaces:**
- Consumes: `SessionRepositoryInterface.RevokeSession` (unscoped, used for reuse revocation); `authenticationService.generateRefreshToken() (string, error)` and `hashRefreshToken(string) string`.
- Produces:
  - Column `user_sessions.previous_refresh_token_hash TEXT`.
  - `SessionRepositoryInterface.RotateRefreshToken(ctx context.Context, sessionID uuid.UUID, oldHash, newHash string) error` (wraps `ErrNotFound` when the old hash is no longer current).
  - `SessionRepositoryInterface.FindSessionIDByPreviousRefreshToken(ctx context.Context, hash string) (uuid.UUID, error)` (wraps `ErrNotFound`).
  - `RefreshTokenResult.RefreshToken` is always a new token.

- [ ] **Step 1: Add the column.** In `internal/db/db.go`, add `previous_refresh_token_hash TEXT,` after `revoked_reason TEXT,` in the `user_sessions` `CREATE TABLE`, and append to `migrations`:

```go
		// Feature: refresh-token rotation, the hash replaced by the last rotation.
		"ALTER TABLE user_sessions ADD COLUMN previous_refresh_token_hash TEXT",
		"CREATE INDEX IF NOT EXISTS idx_user_sessions_prev_refresh ON user_sessions(previous_refresh_token_hash)",
```

In `setupSessionDB` (`internal/repositories/missing_coverage_test.go`), `revoked_reason` is the last column. Change that line and add one after it:

```sql
			revoked_reason     TEXT NOT NULL DEFAULT '',
			previous_refresh_token_hash TEXT
```

- [ ] **Step 2: Write the failing repository test.** Create `internal/repositories/session_rotation_test.go`:

```go
package repositories_test

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	rvdb "rocketvault/internal/db"
	"rocketvault/internal/repositories"
)

func TestSessionRepository_RotateRefreshToken(t *testing.T) {
	t.Parallel()
	db := setupSessionDB(t)
	repo := repositories.NewSessionRepository(repositories.SessionRepositoryConfig{DB: rvdb.NewConn(db, rvdb.SQLite), Logger: newLogger()})
	ctx := context.Background()

	sess := newSession(uuid.New())
	oldHash := sess.RefreshTokenHash
	require.NoError(t, repo.CreateSession(ctx, sess))

	require.NoError(t, repo.RotateRefreshToken(ctx, sess.ID, oldHash, "new-hash"))

	got, err := repo.GetSessionByRefreshToken(ctx, "new-hash")
	require.NoError(t, err)
	assert.Equal(t, sess.ID, got.ID)

	_, err = repo.GetSessionByRefreshToken(ctx, oldHash)
	require.ErrorIs(t, err, repositories.ErrNotFound)

	id, err := repo.FindSessionIDByPreviousRefreshToken(ctx, oldHash)
	require.NoError(t, err)
	assert.Equal(t, sess.ID, id)

	// A second rotation from the stale hash must lose.
	err = repo.RotateRefreshToken(ctx, sess.ID, oldHash, "other-hash")
	require.ErrorIs(t, err, repositories.ErrNotFound)
}

func TestSessionRepository_FindSessionIDByPreviousRefreshToken_NotFound(t *testing.T) {
	t.Parallel()
	db := setupSessionDB(t)
	repo := repositories.NewSessionRepository(repositories.SessionRepositoryConfig{DB: rvdb.NewConn(db, rvdb.SQLite), Logger: newLogger()})

	_, err := repo.FindSessionIDByPreviousRefreshToken(context.Background(), "never-issued")
	require.ErrorIs(t, err, repositories.ErrNotFound)
}
```

Run: `go test ./internal/repositories/ -run 'TestSessionRepository_(RotateRefreshToken|FindSessionIDByPrevious)' -v`
Expected: build failure, `repo.RotateRefreshToken undefined`.

- [ ] **Step 3: Implement the repository methods.** Add to `SessionRepositoryInterface`:

```go
	// RotateRefreshToken replaces oldHash with newHash and remembers oldHash.
	// It reports ErrNotFound when oldHash is no longer the current hash.
	RotateRefreshToken(ctx context.Context, sessionID uuid.UUID, oldHash, newHash string) error

	// FindSessionIDByPreviousRefreshToken finds the session whose last rotation replaced hash.
	FindSessionIDByPreviousRefreshToken(ctx context.Context, hash string) (uuid.UUID, error)
```

Add to `session_repository.go`:

```go
// RotateRefreshToken replaces the session's refresh token hash in one conditional UPDATE.
func (r *SessionRepository) RotateRefreshToken(ctx context.Context, sessionID uuid.UUID, oldHash, newHash string) error {
	return r.executeWithMetrics("rotate_refresh_token", func() error {
		result, err := r.db.ExecContext(ctx, `
			UPDATE user_sessions
			SET refresh_token_hash = ?, previous_refresh_token_hash = ?
			WHERE id = ? AND refresh_token_hash = ? AND revoked = FALSE
		`, newHash, oldHash, sessionID.String(), oldHash)
		if err != nil {
			return fmt.Errorf("failed to rotate refresh token: %w", err)
		}
		rowsAffected, err := result.RowsAffected()
		if err != nil {
			return fmt.Errorf("failed to get rows affected: %w", err)
		}
		if rowsAffected == 0 {
			return fmt.Errorf("refresh token already rotated or session revoked: %w", ErrNotFound)
		}
		return nil
	})
}

// FindSessionIDByPreviousRefreshToken finds the session whose last rotation replaced hash.
func (r *SessionRepository) FindSessionIDByPreviousRefreshToken(ctx context.Context, hash string) (uuid.UUID, error) {
	var id string
	err := r.db.QueryRowContext(ctx,
		`SELECT id FROM user_sessions WHERE previous_refresh_token_hash = ?`, hash).Scan(&id)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return uuid.Nil, fmt.Errorf("no session with that previous refresh token: %w", ErrNotFound)
		}
		return uuid.Nil, fmt.Errorf("failed to look up previous refresh token: %w", err)
	}
	sessionID, err := uuid.Parse(id)
	if err != nil {
		return uuid.Nil, fmt.Errorf("invalid session id in session row: %w", err)
	}
	return sessionID, nil
}
```

Add the mock methods to `MockSessionRepository` in `internal/services/auth/authentication_service_test.go`:

```go
func (m *MockSessionRepository) RotateRefreshToken(ctx context.Context, sessionID uuid.UUID, oldHash, newHash string) error {
	args := m.Called(ctx, sessionID, oldHash, newHash)
	return args.Error(0)
}

func (m *MockSessionRepository) FindSessionIDByPreviousRefreshToken(ctx context.Context, hash string) (uuid.UUID, error) {
	args := m.Called(ctx, hash)
	return args.Get(0).(uuid.UUID), args.Error(1)
}
```

Run: `go test ./internal/repositories/ -run TestSessionRepository_ -v`
Expected: `PASS`.

- [ ] **Step 4: Write the failing service tests.** Append to `internal/services/auth/authentication_service_critical_test.go`:

```go
func TestRefreshAccessToken_RotatesRefreshToken(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	userID := uuid.New()
	sessionID := uuid.New()
	session := &model.Session{ID: sessionID, UserID: userID, RefreshTokenHash: "old-hash", ExpiresAt: time.Now().Add(time.Hour)}

	userRepo := &MockUserRepository{}
	sessionRepo := &MockSessionRepository{}
	jwt := &MockJWTService{}
	sessionRepo.On("GetSessionByRefreshToken", ctx, mock.AnythingOfType("string")).Return(session, nil)
	userRepo.On("Read", ctx, userID).Return(&model.User{ID: userID, Username: "bob", Roles: []string{model.RoleUser}}, nil)
	jwt.On("GenerateToken", userID, "bob", []string{model.RoleUser}, sessionID).Return("new-token", nil)
	sessionRepo.On("RotateRefreshToken", ctx, sessionID, "old-hash", mock.AnythingOfType("string")).Return(nil)
	sessionRepo.On("UpdateSessionLastUsed", ctx, sessionID, mock.AnythingOfType("time.Time")).Return(nil)

	svc := newAuthService(userRepo, sessionRepo, &MockPasswordService{}, &MockTOTPService{}, jwt, nil)
	result, err := svc.RefreshAccessToken(ctx, "refresh-token-value")

	require.NoError(t, err)
	assert.NotEqual(t, "refresh-token-value", result.RefreshToken)
	assert.NotEmpty(t, result.RefreshToken)
	sessionRepo.AssertExpectations(t)
}

func TestRefreshAccessToken_ReusedToken_RevokesSession(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	sessionID := uuid.New()

	sessionRepo := &MockSessionRepository{}
	sessionRepo.On("GetSessionByRefreshToken", ctx, mock.AnythingOfType("string")).Return(nil, errors.New("not found"))
	sessionRepo.On("FindSessionIDByPreviousRefreshToken", ctx, mock.AnythingOfType("string")).Return(sessionID, nil)
	sessionRepo.On("RevokeSession", ctx, sessionID, "refresh token reuse detected").Return(nil)

	svc := newAuthService(&MockUserRepository{}, sessionRepo, &MockPasswordService{}, &MockTOTPService{}, &MockJWTService{}, nil)
	_, err := svc.RefreshAccessToken(ctx, "stale-refresh-token")

	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid refresh token")
	sessionRepo.AssertExpectations(t)
}
```

Update the existing refresh tests so they keep passing under rotation:
- `TestRefreshAccessToken_HappyPath` and `TestRefreshAccessToken_UsesFreshRolesFromDB`: add `sessionRepo.On("RotateRefreshToken", ctx, sessionID, mock.AnythingOfType("string"), mock.AnythingOfType("string")).Return(nil)`.
- `TestRefreshAccessToken_InvalidRefreshToken`: add `sessionRepo.On("FindSessionIDByPreviousRefreshToken", ctx, mock.AnythingOfType("string")).Return(uuid.Nil, fmt.Errorf("none: %w", repositories.ErrNotFound))`.

Run: `go test ./internal/services/auth/ -run TestRefreshAccessToken -v`
Expected: `TestRefreshAccessToken_RotatesRefreshToken` FAILS (`result.RefreshToken` equals the input) and `TestRefreshAccessToken_ReusedToken_RevokesSession` FAILS (`RevokeSession` not called).

- [ ] **Step 5: Implement rotation in the service.** In `RefreshAccessToken`, replace the `GetSessionByRefreshToken` error branch with:

```go
	session, err := s.sessionRepo.GetSessionByRefreshToken(ctx, refreshTokenHash)
	if err != nil {
		// A token that an earlier rotation replaced was copied or stolen; end the session.
		if reusedID, findErr := s.sessionRepo.FindSessionIDByPreviousRefreshToken(ctx, refreshTokenHash); findErr == nil {
			if revokeErr := s.sessionRepo.RevokeSession(ctx, reusedID, "refresh token reuse detected"); revokeErr != nil {
				s.logger.WithError(revokeErr).Error("Failed to revoke session after refresh token reuse")
			}
			s.logger.LogAuditError("", "refresh_access_token", "failed", "Refresh token reuse detected", nil)
			return nil, fmt.Errorf("invalid refresh token")
		}
		s.logger.LogAuditError("", "refresh_access_token", "failed", "Invalid or expired refresh token", err)
		s.logger.WithError(err).Warn("Token refresh failed: invalid refresh token")
		return nil, fmt.Errorf("invalid refresh token")
	}
```

Replace the block from `// For now, we'll keep the same refresh token (no rotation).` through the `RefreshToken: refreshToken, // Same refresh token for now` field with a rotation that runs right after `GenerateToken` succeeds:

```go
	// Every refresh issues a new refresh token and retires the presented one.
	newRefreshToken, err := s.generateRefreshToken()
	if err != nil {
		s.logger.LogAuditError(user.ID.String(), "refresh_access_token", "failed", "Failed to generate refresh token", err)
		return nil, fmt.Errorf("failed to generate refresh token")
	}
	if err := s.sessionRepo.RotateRefreshToken(ctx, session.ID, session.RefreshTokenHash, s.hashRefreshToken(newRefreshToken)); err != nil {
		s.logger.LogAuditError(user.ID.String(), "refresh_access_token", "failed", "Refresh token rotation failed", err)
		return nil, fmt.Errorf("invalid refresh token")
	}
```

and set `RefreshToken: newRefreshToken,` in the returned `RefreshTokenResult`. Keep the `UpdateSessionLastUsed` call after the rotation.

- [ ] **Step 6: Run everything and expect PASS.**
Run: `go build ./... && go vet ./... && go test ./...`
Expected: every package passes, including `internal/vaultapi` (which already writes the rotated token back).

- [ ] **Step 7: Document.** Append to the B74 entry in `.claude/known-bugs.md`: `**Update**: refresh tokens now rotate on every refresh, and presenting a replaced token revokes its session.` Add item 7 to "Behavior changes" in `docs/release-notes/v4.7.0-identity-sessions-hardening.md`: `**Refresh tokens rotate.** Each refresh returns a new refresh token; reusing an old one ends the session.`, and delete the "Refresh tokens are not rotated yet." bullet.

- [ ] **Step 8: Commit.** Invoke the `dev-workflow-skills:1-git-commit` plugin skill via the Skill tool (GPG-signed, key `61D246B30285ED35`).

---

## Self-Review

**Spec coverage.**
- #40 (ownership on revoke, admin bypass, not-found on mismatch, cross-user test): Tasks 1-2.
- OIDC MFA Core steps 1-4: step 1 (empty-secret trigger in `UpdateUser`) and step 2 (service layer, so HTTP and CLI both get it) in Tasks 3-4; step 3 (one-time URL over HTTP and CLI) in Task 4; step 4 (fail closed) in Task 5. Steps 5 and 6 are listed as deferred in the header with their reasons. The release note covers the behavior change.
- #47 (revoke on password, role and delete; `ValidateSession` checks the user exists): Tasks 6-7. Rotation and reuse detection: optional Task 13.
- #45 (store the last step, reject codes at or before it, dual-write migration): Tasks 8-11.
- known-bugs B72-B75: Tasks 2, 5, 7, 11. Release note: Task 12.

**Placeholder scan.** The only fill-in value is the B73 GitHub issue number, which `gh issue create` prints at run time in Task 5 Step 5. Every code step shows the code.

**Type consistency.**
- `RevokeSessionRequest` / `ErrSessionNotFound` (Task 2) are used unchanged in the retry wrapper, the five mocks and `api/users.go`.
- `UpdateUserResult.TOTPEnrollmentURL` (Task 4) is read by `api/users.go`, `cmd/users/update.go` and the retry wrapper. Task 6 keeps the `(*UpdateUserResult, error)` return.
- `ValidateCodeWithStep` returns `(int64, bool, error)` (Task 10); `ClaimTOTPStep` takes `int64` (Task 9); both mocks and all test `.Return` values use `int64`.
- `SessionRevoker.RevokeAllUserSessions` matches `SessionRepositoryInterface.RevokeAllUserSessions`, so the container passes `c.sessionRepository` directly.
