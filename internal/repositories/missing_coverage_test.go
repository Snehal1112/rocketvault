// Package repositories_test contains tests targeting uncovered paths in
// user_repository.go, secret_repository.go, session_repository.go,
// tag_repository.go, versioning_repository.go, and vault_repository.go.
//
// Most tests use an in-memory SQLite database so no disk I/O or external
// services are required. One exception is
// TestUserRepository_Create_DuplicateUsername_DoesNotStallAuditLog, which
// needs a file-backed database so a second real pooled connection can
// contend for its lock.
package repositories_test

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/uuid"
	_ "github.com/mattn/go-sqlite3"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	rvdb "rocketvault/internal/db"
	"rocketvault/internal/logging"
	"rocketvault/internal/repositories"
	"rocketvault/model"
)

// ---------------------------------------------------------------------------
// Setup helpers
// ---------------------------------------------------------------------------

// newLogger returns a logging.Logger suitable for repository tests.
func newLogger() *logging.Logger {
	l := logrus.New()
	l.SetLevel(logrus.WarnLevel) // Keep test output clean.
	return &logging.Logger{Logger: l}
}

// setupUserDB creates an in-memory SQLite DB with the users and
// bootstrap_tokens tables required by UserRepository.
func setupUserDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite3", ":memory:")
	require.NoError(t, err)
	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS users (
			id                   TEXT PRIMARY KEY,
			username             TEXT UNIQUE NOT NULL,
			password_hash        TEXT NOT NULL,
			totp_secret          TEXT NOT NULL DEFAULT '',
			role                 TEXT NOT NULL,
			auth_provider        TEXT NOT NULL DEFAULT 'local',
			external_idp_subject TEXT,
			created_at           TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		);
		CREATE UNIQUE INDEX IF NOT EXISTS idx_users_external_idp ON users(auth_provider, external_idp_subject) WHERE external_idp_subject IS NOT NULL;
		CREATE TABLE IF NOT EXISTS bootstrap_tokens (
			token TEXT PRIMARY KEY,
			used  BOOLEAN NOT NULL DEFAULT FALSE
		);
		CREATE TABLE IF NOT EXISTS user_roles (
			id         TEXT PRIMARY KEY,
			user_id    TEXT NOT NULL,
			role       TEXT NOT NULL,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			UNIQUE (user_id, role),
			FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
		);
	`)
	require.NoError(t, err)
	t.Cleanup(func() { db.Close() }) //nolint:errcheck,gosec
	return db
}

// newUser returns a minimal *model.User ready for insertion.
func newUser(username, role string) *model.User {
	return &model.User{
		ID:           uuid.New(),
		Username:     username,
		PasswordHash: "hashed-password",
		TOTPSecret:   "",
		Roles:        []string{role},
		CreatedAt:    time.Now(),
	}
}

// setupSessionDB creates an in-memory SQLite DB with the user_sessions table.
func setupSessionDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite3", ":memory:")
	require.NoError(t, err)
	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS user_sessions (
			id                 TEXT PRIMARY KEY,
			user_id            TEXT NOT NULL,
			refresh_token_hash TEXT NOT NULL,
			device_info        TEXT NOT NULL DEFAULT '',
			ip_address         TEXT NOT NULL DEFAULT '',
			user_agent         TEXT NOT NULL DEFAULT '',
			expires_at         TIMESTAMP NOT NULL,
			last_used_at       TIMESTAMP NOT NULL,
			created_at         TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			revoked            BOOLEAN NOT NULL DEFAULT FALSE,
			revoked_at         TIMESTAMP NULL,
			revoked_reason     TEXT NOT NULL DEFAULT ''
		);
	`)
	require.NoError(t, err)
	t.Cleanup(func() { db.Close() }) //nolint:errcheck,gosec
	return db
}

// newSession returns a minimal *model.Session ready for insertion.
func newSession(userID uuid.UUID) *model.Session {
	return &model.Session{
		ID:               uuid.New(),
		UserID:           userID,
		RefreshTokenHash: uuid.NewString(),
		DeviceInfo:       "test-device",
		IPAddress:        "127.0.0.1",
		UserAgent:        "test-agent",
		ExpiresAt:        time.Now().Add(time.Hour),
		LastUsedAt:       time.Now(),
		CreatedAt:        time.Now(),
	}
}

// setupTagDB creates an in-memory SQLite DB with the secrets and secret_tags tables.
func setupTagDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite3", ":memory:")
	require.NoError(t, err)
	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS secrets (
			id               TEXT PRIMARY KEY,
			user_id          TEXT NOT NULL,
			vault_id         TEXT NOT NULL DEFAULT '00000000-0000-0000-0000-000000000000',
			name             TEXT NOT NULL,
			value            TEXT NOT NULL,
			version          INTEGER NOT NULL DEFAULT 1,
			created_at       TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			deleted_at       TIMESTAMP NULL,
			purge_protection BOOLEAN NOT NULL DEFAULT FALSE,
			scheduled_purge_at TIMESTAMP NULL,
			content_type     TEXT NOT NULL DEFAULT '',
			enabled          BOOLEAN NOT NULL DEFAULT TRUE,
			expires_at       TIMESTAMP NULL,
			not_before       TIMESTAMP NULL
		);
		CREATE TABLE IF NOT EXISTS secret_tags (
			secret_id TEXT NOT NULL,
			tag       TEXT NOT NULL,
			PRIMARY KEY (secret_id, tag)
		);
	`)
	require.NoError(t, err)
	t.Cleanup(func() { db.Close() }) //nolint:errcheck,gosec
	return db
}

// setupVersioningDB creates an in-memory SQLite DB with the secret_versions table.
func setupVersioningDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite3", ":memory:")
	require.NoError(t, err)
	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS secret_versions (
			id         TEXT PRIMARY KEY,
			secret_id  TEXT NOT NULL,
			user_id    TEXT NOT NULL,
			name       TEXT NOT NULL,
			value      TEXT NOT NULL,
			version    INTEGER NOT NULL,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		);
	`)
	require.NoError(t, err)
	t.Cleanup(func() { db.Close() }) //nolint:errcheck,gosec
	return db
}

// newSecretVersion returns a minimal *model.SecretVersion ready for insertion.
func newSecretVersion(secretID, userID uuid.UUID, ver int) *model.SecretVersion {
	return &model.SecretVersion{
		ID:        uuid.New(),
		SecretID:  secretID,
		UserID:    userID,
		Name:      "test-secret",
		Value:     "encrypted-value",
		Version:   ver,
		CreatedAt: time.Now(),
	}
}

// ---------------------------------------------------------------------------
// UserRepository tests
// ---------------------------------------------------------------------------

func TestUserRepository_Create_And_Read(t *testing.T) {
	t.Parallel()
	db := setupUserDB(t)
	repo := repositories.NewUserRepository(rvdb.NewConn(db, rvdb.SQLite), newLogger())
	ctx := context.Background()

	u := newUser("alice", model.RoleAdmin)
	require.NoError(t, repo.Create(ctx, u))

	got, err := repo.Read(ctx, u.ID)
	require.NoError(t, err)
	assert.Equal(t, u.ID, got.ID)
	assert.Equal(t, "alice", got.Username)
	assert.Equal(t, []string{model.RoleAdmin}, got.Roles)
}

func TestUserRepository_Create_DuplicateUsername(t *testing.T) {
	t.Parallel()
	db := setupUserDB(t)
	repo := repositories.NewUserRepository(rvdb.NewConn(db, rvdb.SQLite), newLogger())
	ctx := context.Background()

	u1 := newUser("bob", model.RoleUser)
	u2 := newUser("bob", model.RoleUser) // Same username.
	require.NoError(t, repo.Create(ctx, u1))

	err := repo.Create(ctx, u2)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "already exists")
}

// auditPersisterFunc adapts a plain function to logging.AuditPersister, so
// tests can observe exactly when/whether a durable audit write is attempted
// and what happens when it runs.
type auditPersisterFunc func(userID, action, details string) error

func (f auditPersisterFunc) PersistAudit(userID, action, details string) error {
	return f(userID, action, details)
}

// TestUserRepository_Create_DuplicateUsername_DoesNotStallAuditLog guards
// against a regression of the finding fixed in the final code review:
// LogAuditError used to run while Create's transaction was still open. On
// SQLite, a second pooled connection writing to the database file while
// another connection holds a lock from an open (uncommitted) transaction
// blocks until that transaction ends; with no busy_timeout configured
// (this project's default), that manifests as an immediate "database is
// locked" error rather than the ~5s stall production sees (production's
// driver-level busy handling waits before giving up) -- either way, the
// write must not contend at all once the fix is in place, which is what
// this test checks deterministically instead of relying on a timing
// threshold.
//
// This wires a real second connection into the audit persister (mirroring
// AuditRepository.PersistAudit, which really does write via a separate
// pooled connection) against a file-backed SQLite database, so contention
// is real, not simulated. If Create regresses to logging before rolling
// back its own transaction, the persister's write below observes lock
// contention and the test fails.
func TestUserRepository_Create_DuplicateUsername_DoesNotStallAuditLog(t *testing.T) {
	t.Parallel()

	dbPath := filepath.Join(t.TempDir(), "audit-lock.db")
	sqlDB, err := sql.Open("sqlite3", dbPath)
	require.NoError(t, err)
	t.Cleanup(func() { sqlDB.Close() }) //nolint:errcheck,gosec
	sqlDB.SetMaxOpenConns(4)            // Give the audit persister's write a distinct connection from tx's.

	_, err = sqlDB.Exec(`
		CREATE TABLE IF NOT EXISTS users (
			id                   TEXT PRIMARY KEY,
			username             TEXT UNIQUE NOT NULL,
			password_hash        TEXT NOT NULL,
			totp_secret          TEXT NOT NULL DEFAULT '',
			role                 TEXT NOT NULL,
			auth_provider        TEXT NOT NULL DEFAULT 'local',
			external_idp_subject TEXT,
			created_at           TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		);
		CREATE UNIQUE INDEX IF NOT EXISTS idx_users_external_idp ON users(auth_provider, external_idp_subject) WHERE external_idp_subject IS NOT NULL;
		CREATE TABLE IF NOT EXISTS bootstrap_tokens (
			token TEXT PRIMARY KEY,
			used  BOOLEAN NOT NULL DEFAULT FALSE
		);
		CREATE TABLE IF NOT EXISTS user_roles (
			id         TEXT PRIMARY KEY,
			user_id    TEXT NOT NULL,
			role       TEXT NOT NULL,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			UNIQUE (user_id, role),
			FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
		);
		CREATE TABLE IF NOT EXISTS audit_probe (id TEXT PRIMARY KEY);
	`)
	require.NoError(t, err)

	log := newLogger()
	var persistErr error
	var persistCalled bool
	log.SetAuditPersister(auditPersisterFunc(func(userID, action, details string) error {
		persistCalled = true
		// Mirrors AuditRepository.PersistAudit: a write via a pooled
		// connection distinct from whichever connection the caller's own
		// (possibly still-open) transaction is using.
		_, err := sqlDB.Exec("INSERT INTO audit_probe (id) VALUES (?)", uuid.NewString())
		persistErr = err
		return err
	}))

	repo := repositories.NewUserRepository(rvdb.NewConn(sqlDB, rvdb.SQLite), log)
	ctx := context.Background()

	u1 := newUser("lock-check", model.RoleUser)
	u2 := newUser("lock-check", model.RoleUser) // Same username -> duplicate-username error path.
	require.NoError(t, repo.Create(ctx, u1))

	start := time.Now()
	err = repo.Create(ctx, u2)
	elapsed := time.Since(start)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "already exists")
	require.True(t, persistCalled, "audit persister must have been invoked for the duplicate-username failure")
	assert.NoError(t, persistErr, "audit persister's write must not contend for the SQLite lock -- Create's tx must already be rolled back before logging")
	assert.Less(t, elapsed, 1*time.Second, "duplicate-username Create should fail fast, not stall on a locked audit write")
}

func TestUserRepository_Read_NotFound(t *testing.T) {
	t.Parallel()
	db := setupUserDB(t)
	repo := repositories.NewUserRepository(rvdb.NewConn(db, rvdb.SQLite), newLogger())
	ctx := context.Background()

	_, err := repo.Read(ctx, uuid.New())
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

func TestUserRepository_Update(t *testing.T) {
	t.Parallel()
	db := setupUserDB(t)
	repo := repositories.NewUserRepository(rvdb.NewConn(db, rvdb.SQLite), newLogger())
	ctx := context.Background()

	u := newUser("carol", model.RoleUser)
	require.NoError(t, repo.Create(ctx, u))

	u.Roles = []string{model.RoleAdmin}
	require.NoError(t, repo.Update(ctx, u))

	got, err := repo.Read(ctx, u.ID)
	require.NoError(t, err)
	assert.Equal(t, []string{model.RoleAdmin}, got.Roles)
}

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

// A read-modify-write update of another field must keep the stored secret.
func TestUserRepository_Update_KeepsTOTPSecretOnOtherFieldChange(t *testing.T) {
	t.Parallel()
	db := setupUserDB(t)
	repo := repositories.NewUserRepository(rvdb.NewConn(db, rvdb.SQLite), newLogger())
	ctx := context.Background()

	u := newUser("totp-keeper", model.RoleUser)
	u.TOTPSecret = "JBSWY3DPEHPK3PXP"
	require.NoError(t, repo.Create(ctx, u))

	loaded, err := repo.Read(ctx, u.ID)
	require.NoError(t, err)
	loaded.Roles = []string{model.RoleAdmin}
	require.NoError(t, repo.Update(ctx, loaded))

	got, err := repo.Read(ctx, u.ID)
	require.NoError(t, err)
	assert.Equal(t, "JBSWY3DPEHPK3PXP", got.TOTPSecret)
	assert.Equal(t, []string{model.RoleAdmin}, got.Roles)
}

func TestUserRepository_Update_NotFound(t *testing.T) {
	t.Parallel()
	db := setupUserDB(t)
	repo := repositories.NewUserRepository(rvdb.NewConn(db, rvdb.SQLite), newLogger())
	ctx := context.Background()

	u := newUser("ghost", model.RoleUser)
	err := repo.Update(ctx, u)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

func TestUserRepository_Delete(t *testing.T) {
	t.Parallel()
	db := setupUserDB(t)
	repo := repositories.NewUserRepository(rvdb.NewConn(db, rvdb.SQLite), newLogger())
	ctx := context.Background()

	u := newUser("dave", model.RoleUser)
	require.NoError(t, repo.Create(ctx, u))

	require.NoError(t, repo.Delete(ctx, u.ID))

	_, err := repo.Read(ctx, u.ID)
	assert.Error(t, err)
}

func TestUserRepository_Delete_NotFound(t *testing.T) {
	t.Parallel()
	db := setupUserDB(t)
	repo := repositories.NewUserRepository(rvdb.NewConn(db, rvdb.SQLite), newLogger())
	ctx := context.Background()

	err := repo.Delete(ctx, uuid.New())
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

func TestUserRepository_Delete_RemovesUserRoles(t *testing.T) {
	t.Parallel()
	db := setupUserDB(t)
	repo := repositories.NewUserRepository(rvdb.NewConn(db, rvdb.SQLite), newLogger())
	ctx := context.Background()

	u := &model.User{
		ID:           uuid.New(),
		Username:     "frank",
		PasswordHash: "hashed-password",
		Roles:        []string{"admin", "secrets_manager"},
		CreatedAt:    time.Now(),
	}
	require.NoError(t, repo.Create(ctx, u))

	require.NoError(t, repo.Delete(ctx, u.ID))

	var count int
	require.NoError(t, db.QueryRow(`SELECT COUNT(*) FROM user_roles WHERE user_id = ?`, u.ID.String()).Scan(&count))
	assert.Equal(t, 0, count, "user_roles rows must not survive user deletion on SQLite")
}

func TestUserRepository_ReadByUsername(t *testing.T) {
	t.Parallel()
	db := setupUserDB(t)
	repo := repositories.NewUserRepository(rvdb.NewConn(db, rvdb.SQLite), newLogger())
	ctx := context.Background()

	u := newUser("eve", model.RoleUser)
	require.NoError(t, repo.Create(ctx, u))

	got, err := repo.ReadByUsername(ctx, "eve")
	require.NoError(t, err)
	assert.Equal(t, u.ID, got.ID)
	assert.Equal(t, "eve", got.Username)
}

func TestUserRepository_ReadByUsername_NotFound(t *testing.T) {
	t.Parallel()
	db := setupUserDB(t)
	repo := repositories.NewUserRepository(rvdb.NewConn(db, rvdb.SQLite), newLogger())
	ctx := context.Background()

	_, err := repo.ReadByUsername(ctx, "nonexistent")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

func TestUserRepository_CreateAndReadByExternalSubject(t *testing.T) {
	t.Parallel()
	db := setupUserDB(t)
	repo := repositories.NewUserRepository(rvdb.NewConn(db, rvdb.SQLite), newLogger())
	ctx := context.Background()

	user := &model.User{
		ID: uuid.New(), Username: "oidc-user", PasswordHash: "", TOTPSecret: "",
		Roles: []string{model.RoleUser}, AuthProvider: model.AuthProviderOIDC, ExternalIDPSubject: "sub-123",
		CreatedAt: time.Now(),
	}
	require.NoError(t, repo.Create(ctx, user))

	loaded, err := repo.ReadByExternalSubject(ctx, model.AuthProviderOIDC, "sub-123")
	require.NoError(t, err)
	require.Equal(t, user.ID, loaded.ID)
	require.Equal(t, "sub-123", loaded.ExternalIDPSubject)
	assert.ElementsMatch(t, []string{model.RoleUser}, loaded.Roles)
}

func TestUserRepository_ReadByExternalSubject_NotFound(t *testing.T) {
	t.Parallel()
	db := setupUserDB(t)
	repo := repositories.NewUserRepository(rvdb.NewConn(db, rvdb.SQLite), newLogger())
	ctx := context.Background()

	_, err := repo.ReadByExternalSubject(ctx, model.AuthProviderOIDC, "nonexistent")
	require.Error(t, err)
}

func TestUserRepository_LocalUser_HasEmptyAuthProviderDefaultsToLocal(t *testing.T) {
	t.Parallel()
	db := setupUserDB(t)
	repo := repositories.NewUserRepository(rvdb.NewConn(db, rvdb.SQLite), newLogger())
	ctx := context.Background()

	user := &model.User{
		ID: uuid.New(), Username: "local-user", PasswordHash: "hash", TOTPSecret: "secret",
		Roles: []string{model.RoleUser}, CreatedAt: time.Now(), // AuthProvider left as zero value.
	}
	require.NoError(t, repo.Create(ctx, user))

	loaded, err := repo.Read(ctx, user.ID)
	require.NoError(t, err)
	require.Equal(t, model.AuthProviderLocal, loaded.AuthProvider)
	require.Empty(t, loaded.ExternalIDPSubject)
}

func TestUserRepository_List(t *testing.T) {
	t.Parallel()
	db := setupUserDB(t)
	repo := repositories.NewUserRepository(rvdb.NewConn(db, rvdb.SQLite), newLogger())
	ctx := context.Background()

	require.NoError(t, repo.Create(ctx, newUser("frank", model.RoleUser)))
	require.NoError(t, repo.Create(ctx, newUser("grace", model.RoleAdmin)))

	users, err := repo.List(ctx)
	require.NoError(t, err)
	assert.Len(t, users, 2)
}

// loginCaller is a local interface to access the Login method on the
// concrete UserRepository type without exposing it on UserRepositoryInterface.
type loginCaller interface {
	Login(ctx context.Context, username, password, totpCode string) (string, error)
}

func TestUserRepository_Login_Deprecated(t *testing.T) {
	t.Parallel()
	db := setupUserDB(t)
	repo := repositories.NewUserRepository(rvdb.NewConn(db, rvdb.SQLite), newLogger())
	ctx := context.Background()

	// Login is not on the interface but is on the struct.
	// Use a type assertion via a local interface to reach it.
	if lc, ok := repo.(loginCaller); ok {
		_, err := lc.Login(ctx, "any", "any", "any")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "deprecated")
	}
}

func TestUserRepository_List_Empty(t *testing.T) {
	t.Parallel()
	db := setupUserDB(t)
	repo := repositories.NewUserRepository(rvdb.NewConn(db, rvdb.SQLite), newLogger())
	ctx := context.Background()

	users, err := repo.List(ctx)
	require.NoError(t, err)
	assert.Empty(t, users)
}

func TestUserRepository_ValidateBootstrapToken_NoUsers(t *testing.T) {
	t.Parallel()
	db := setupUserDB(t)
	repo := repositories.NewUserRepository(rvdb.NewConn(db, rvdb.SQLite), newLogger())
	ctx := context.Background()

	// Insert a valid unused token.
	_, err := db.ExecContext(ctx, "INSERT INTO bootstrap_tokens (token, used) VALUES (?, FALSE)", "my-token")
	require.NoError(t, err)

	valid, err := repo.ValidateBootstrapToken(ctx, "my-token")
	require.NoError(t, err)
	assert.True(t, valid)
}

func TestUserRepository_ValidateBootstrapToken_TokenNotFound(t *testing.T) {
	t.Parallel()
	db := setupUserDB(t)
	repo := repositories.NewUserRepository(rvdb.NewConn(db, rvdb.SQLite), newLogger())
	ctx := context.Background()

	valid, err := repo.ValidateBootstrapToken(ctx, "nonexistent-token")
	require.NoError(t, err)
	assert.False(t, valid)
}

func TestUserRepository_ValidateBootstrapToken_UsedToken(t *testing.T) {
	t.Parallel()
	db := setupUserDB(t)
	repo := repositories.NewUserRepository(rvdb.NewConn(db, rvdb.SQLite), newLogger())
	ctx := context.Background()

	_, err := db.ExecContext(ctx, "INSERT INTO bootstrap_tokens (token, used) VALUES (?, TRUE)", "used-token")
	require.NoError(t, err)

	valid, err := repo.ValidateBootstrapToken(ctx, "used-token")
	require.NoError(t, err)
	assert.False(t, valid)
}

func TestUserRepository_ValidateBootstrapToken_UsersExist(t *testing.T) {
	t.Parallel()
	db := setupUserDB(t)
	repo := repositories.NewUserRepository(rvdb.NewConn(db, rvdb.SQLite), newLogger())
	ctx := context.Background()

	// Create a user — bootstrap is no longer allowed.
	require.NoError(t, repo.Create(ctx, newUser("hank", model.RoleAdmin)))
	_, err := db.ExecContext(ctx, "INSERT INTO bootstrap_tokens (token, used) VALUES (?, FALSE)", "token-123")
	require.NoError(t, err)

	valid, err := repo.ValidateBootstrapToken(ctx, "token-123")
	require.NoError(t, err)
	assert.False(t, valid)
}

func TestUserRepository_InvalidateBootstrapToken_Updates(t *testing.T) {
	t.Parallel()
	db := setupUserDB(t)
	repo := repositories.NewUserRepository(rvdb.NewConn(db, rvdb.SQLite), newLogger())
	ctx := context.Background()

	_, err := db.ExecContext(ctx, "INSERT INTO bootstrap_tokens (token, used) VALUES (?, FALSE)", "tok")
	require.NoError(t, err)

	require.NoError(t, repo.InvalidateBootstrapToken(ctx, "tok"))

	// The token should now be marked used.
	var used bool
	require.NoError(t, db.QueryRowContext(ctx, "SELECT used FROM bootstrap_tokens WHERE token = ?", "tok").Scan(&used))
	assert.True(t, used)
}

func TestUserRepository_InvalidateBootstrapToken_Inserts(t *testing.T) {
	t.Parallel()
	db := setupUserDB(t)
	repo := repositories.NewUserRepository(rvdb.NewConn(db, rvdb.SQLite), newLogger())
	ctx := context.Background()

	// Token does not exist yet — InvalidateBootstrapToken should insert it as used.
	require.NoError(t, repo.InvalidateBootstrapToken(ctx, "brand-new-token"))

	var used bool
	require.NoError(t, db.QueryRowContext(ctx, "SELECT used FROM bootstrap_tokens WHERE token = ?", "brand-new-token").Scan(&used))
	assert.True(t, used)
}

// ---------------------------------------------------------------------------
// SecretRepository – previously uncovered methods
// ---------------------------------------------------------------------------

func TestSecretRepository_Update(t *testing.T) {
	t.Parallel()
	db := setupSecretTestDB(t)
	repo := repositories.NewSecretRepository(rvdb.NewConn(db, rvdb.SQLite), newTestSecretLogger(t))
	ctx := context.Background()

	ownerID := uuid.New()
	s := &model.Secret{
		ID:        uuid.New(),
		UserID:    ownerID,
		Name:      "update-me",
		Value:     "old-value",
		Version:   1,
		CreatedAt: time.Now(),
		Enabled:   true,
	}
	require.NoError(t, repo.Create(ctx, s))

	s.Value = "new-value"
	s.Version = 2
	require.NoError(t, repo.Update(ctx, s, model.NewAdminScope(uuid.Nil)))

	got, err := repo.Read(ctx, s.ID, model.NewAdminScope(uuid.Nil))
	require.NoError(t, err)
	assert.Equal(t, "new-value", got.Value)
	assert.Equal(t, 2, got.Version)
}

func TestSecretRepository_Update_NotFound(t *testing.T) {
	t.Parallel()
	db := setupSecretTestDB(t)
	repo := repositories.NewSecretRepository(rvdb.NewConn(db, rvdb.SQLite), newTestSecretLogger(t))
	ctx := context.Background()

	s := &model.Secret{
		ID:      uuid.New(),
		UserID:  uuid.New(),
		Name:    "ghost",
		Value:   "val",
		Version: 1,
	}
	err := repo.Update(ctx, s, model.NewAdminScope(uuid.Nil))
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

func TestSecretRepository_Delete(t *testing.T) {
	t.Parallel()
	db := setupSecretTestDB(t)
	repo := repositories.NewSecretRepository(rvdb.NewConn(db, rvdb.SQLite), newTestSecretLogger(t))
	ctx := context.Background()

	s := &model.Secret{ID: uuid.New(), UserID: uuid.New(), Name: "delete-me", Value: "v", Version: 1, CreatedAt: time.Now()}
	require.NoError(t, repo.Create(ctx, s))

	require.NoError(t, repo.Delete(ctx, s.ID))

	_, err := repo.Read(ctx, s.ID, model.NewAdminScope(uuid.Nil))
	assert.Error(t, err)
}

func TestSecretRepository_Delete_NotFound(t *testing.T) {
	t.Parallel()
	db := setupSecretTestDB(t)
	repo := repositories.NewSecretRepository(rvdb.NewConn(db, rvdb.SQLite), newTestSecretLogger(t))
	ctx := context.Background()

	err := repo.Delete(ctx, uuid.New())
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

func TestSecretRepository_RecoverSecret(t *testing.T) {
	t.Parallel()
	db := setupSecretTestDB(t)
	repo := repositories.NewSecretRepository(rvdb.NewConn(db, rvdb.SQLite), newTestSecretLogger(t))
	ctx := context.Background()

	ownerID := uuid.New()
	s := &model.Secret{ID: uuid.New(), UserID: ownerID, Name: "recover-me", Value: "v", Version: 1, CreatedAt: time.Now()}
	require.NoError(t, repo.Create(ctx, s))
	require.NoError(t, repo.SoftDelete(ctx, s.ID))

	// Confirm hidden.
	_, err := repo.Read(ctx, s.ID, model.NewAdminScope(uuid.Nil))
	require.Error(t, err)

	// Recover.
	require.NoError(t, repo.RecoverSecret(ctx, s.ID))

	got, err := repo.Read(ctx, s.ID, model.NewAdminScope(uuid.Nil))
	require.NoError(t, err)
	assert.Equal(t, s.ID, got.ID)
}

func TestSecretRepository_RecoverSecret_NotDeleted(t *testing.T) {
	t.Parallel()
	db := setupSecretTestDB(t)
	repo := repositories.NewSecretRepository(rvdb.NewConn(db, rvdb.SQLite), newTestSecretLogger(t))
	ctx := context.Background()

	s := &model.Secret{ID: uuid.New(), UserID: uuid.New(), Name: "live", Value: "v", Version: 1, CreatedAt: time.Now()}
	require.NoError(t, repo.Create(ctx, s))

	err := repo.RecoverSecret(ctx, s.ID)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not found in deleted state")
}

func TestSecretRepository_PurgeSecret(t *testing.T) {
	t.Parallel()
	db := setupSecretTestDB(t)
	repo := repositories.NewSecretRepository(rvdb.NewConn(db, rvdb.SQLite), newTestSecretLogger(t))
	ctx := context.Background()

	s := &model.Secret{ID: uuid.New(), UserID: uuid.New(), Name: "purge-me", Value: "v", Version: 1, CreatedAt: time.Now()}
	require.NoError(t, repo.Create(ctx, s))
	require.NoError(t, repo.SoftDelete(ctx, s.ID))

	require.NoError(t, repo.PurgeSecret(ctx, s.ID))

	// Row must be gone permanently.
	var count int
	require.NoError(t, db.QueryRowContext(ctx, "SELECT COUNT(*) FROM secrets WHERE id = ?", s.ID.String()).Scan(&count))
	assert.Equal(t, 0, count)
}

func TestSecretRepository_PurgeSecret_NotSoftDeleted(t *testing.T) {
	t.Parallel()
	db := setupSecretTestDB(t)
	repo := repositories.NewSecretRepository(rvdb.NewConn(db, rvdb.SQLite), newTestSecretLogger(t))
	ctx := context.Background()

	s := &model.Secret{ID: uuid.New(), UserID: uuid.New(), Name: "active", Value: "v", Version: 1, CreatedAt: time.Now()}
	require.NoError(t, repo.Create(ctx, s))

	err := repo.PurgeSecret(ctx, s.ID)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not soft-deleted")
}

func TestSecretRepository_PurgeSecret_NotFound(t *testing.T) {
	t.Parallel()
	db := setupSecretTestDB(t)
	repo := repositories.NewSecretRepository(rvdb.NewConn(db, rvdb.SQLite), newTestSecretLogger(t))
	ctx := context.Background()

	err := repo.PurgeSecret(ctx, uuid.New())
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

func TestSecretRepository_PurgeSecret_PurgeProtection(t *testing.T) {
	t.Parallel()
	db := setupSecretTestDB(t)
	repo := repositories.NewSecretRepository(rvdb.NewConn(db, rvdb.SQLite), newTestSecretLogger(t))
	ctx := context.Background()

	s := &model.Secret{ID: uuid.New(), UserID: uuid.New(), Name: "protected", Value: "v", Version: 1, CreatedAt: time.Now()}
	require.NoError(t, repo.Create(ctx, s))
	require.NoError(t, repo.SoftDelete(ctx, s.ID))

	// Enable purge protection directly.
	_, err := db.ExecContext(ctx, "UPDATE secrets SET purge_protection = TRUE WHERE id = ?", s.ID.String())
	require.NoError(t, err)

	err = repo.PurgeSecret(ctx, s.ID)
	assert.ErrorIs(t, err, repositories.ErrSecretPurgeProtected)
}

func TestSecretRepository_SetPurgeProtection(t *testing.T) {
	t.Parallel()
	db := setupSecretTestDB(t)
	repo := repositories.NewSecretRepository(rvdb.NewConn(db, rvdb.SQLite), newTestSecretLogger(t))
	ctx := context.Background()

	s := &model.Secret{ID: uuid.New(), UserID: uuid.New(), Name: "protect-me", Value: "v", Version: 1, CreatedAt: time.Now(), Enabled: true}
	require.NoError(t, repo.Create(ctx, s))

	require.NoError(t, repo.SetPurgeProtection(ctx, s.ID, true))
	require.NoError(t, repo.SoftDelete(ctx, s.ID))

	err := repo.PurgeSecret(ctx, s.ID)
	assert.ErrorIs(t, err, repositories.ErrSecretPurgeProtected)

	// Disabling protection lets the purge through again.
	require.NoError(t, repo.SetPurgeProtection(ctx, s.ID, false))
	require.NoError(t, repo.PurgeSecret(ctx, s.ID))
}

func TestSecretRepository_SetPurgeProtection_NotFound(t *testing.T) {
	t.Parallel()
	db := setupSecretTestDB(t)
	repo := repositories.NewSecretRepository(rvdb.NewConn(db, rvdb.SQLite), newTestSecretLogger(t))

	err := repo.SetPurgeProtection(context.Background(), uuid.New(), true)
	assert.ErrorIs(t, err, repositories.ErrNotFound)
}

func TestSecretRepository_ListByUser(t *testing.T) {
	t.Parallel()
	db := setupSecretTestDB(t)
	repo := repositories.NewSecretRepository(rvdb.NewConn(db, rvdb.SQLite), newTestSecretLogger(t))
	ctx := context.Background()

	userA := uuid.New()
	userB := uuid.New()

	mk := func(owner uuid.UUID, name string) *model.Secret {
		return &model.Secret{ID: uuid.New(), UserID: owner, Name: name, Value: "v", Version: 1, CreatedAt: time.Now(), Enabled: true}
	}
	require.NoError(t, repo.Create(ctx, mk(userA, "s1")))
	require.NoError(t, repo.Create(ctx, mk(userA, "s2")))
	require.NoError(t, repo.Create(ctx, mk(userB, "s3")))

	listA, err := repo.List(ctx, model.NewOwnerScope(uuid.Nil, userA), repositories.SecretFilter{})
	require.NoError(t, err)
	assert.Len(t, listA, 2)

	listB, err := repo.List(ctx, model.NewOwnerScope(uuid.Nil, userB), repositories.SecretFilter{})
	require.NoError(t, err)
	assert.Len(t, listB, 1)
}

func TestSecretRepository_ListByUser_ExcludesSoftDeleted(t *testing.T) {
	t.Parallel()
	db := setupSecretTestDB(t)
	repo := repositories.NewSecretRepository(rvdb.NewConn(db, rvdb.SQLite), newTestSecretLogger(t))
	ctx := context.Background()

	userID := uuid.New()
	s := &model.Secret{ID: uuid.New(), UserID: userID, Name: "gone", Value: "v", Version: 1, CreatedAt: time.Now()}
	require.NoError(t, repo.Create(ctx, s))
	require.NoError(t, repo.SoftDelete(ctx, s.ID))

	list, err := repo.List(ctx, model.NewOwnerScope(uuid.Nil, userID), repositories.SecretFilter{})
	require.NoError(t, err)
	assert.Empty(t, list)
}

func TestSecretRepository_ListByUserIncludeDeleted(t *testing.T) {
	t.Parallel()
	db := setupSecretTestDB(t)
	repo := repositories.NewSecretRepository(rvdb.NewConn(db, rvdb.SQLite), newTestSecretLogger(t))
	ctx := context.Background()

	userID := uuid.New()
	s1 := &model.Secret{ID: uuid.New(), UserID: userID, Name: "active", Value: "v", Version: 1, CreatedAt: time.Now()}
	s2 := &model.Secret{ID: uuid.New(), UserID: userID, Name: "deleted", Value: "v", Version: 1, CreatedAt: time.Now()}
	require.NoError(t, repo.Create(ctx, s1))
	require.NoError(t, repo.Create(ctx, s2))
	require.NoError(t, repo.SoftDelete(ctx, s2.ID))

	all, err := repo.List(ctx, model.NewOwnerScope(uuid.Nil, userID), repositories.SecretFilter{IncludeDeleted: true})
	require.NoError(t, err)
	assert.Len(t, all, 2)
}

func TestSecretRepository_ReadInVault(t *testing.T) {
	t.Parallel()
	db := setupSecretTestDB(t)
	repo := repositories.NewSecretRepository(rvdb.NewConn(db, rvdb.SQLite), newTestSecretLogger(t))
	ctx := context.Background()

	vaultID := uuid.New()
	s := &model.Secret{ID: uuid.New(), UserID: uuid.New(), VaultID: vaultID, Name: "in-vault", Value: "v", Version: 1, CreatedAt: time.Now(), Enabled: true}
	require.NoError(t, repo.Create(ctx, s))

	got, err := repo.Read(ctx, s.ID, model.NewVaultScope(vaultID, uuid.Nil))
	require.NoError(t, err)
	assert.Equal(t, s.ID, got.ID)
	assert.Equal(t, vaultID, got.VaultID)
}

func TestSecretRepository_ReadInVault_WrongVault(t *testing.T) {
	t.Parallel()
	db := setupSecretTestDB(t)
	repo := repositories.NewSecretRepository(rvdb.NewConn(db, rvdb.SQLite), newTestSecretLogger(t))
	ctx := context.Background()

	vaultA := uuid.New()
	s := &model.Secret{ID: uuid.New(), UserID: uuid.New(), VaultID: vaultA, Name: "s", Value: "v", Version: 1, CreatedAt: time.Now()}
	require.NoError(t, repo.Create(ctx, s))

	_, err := repo.Read(ctx, s.ID, model.NewVaultScope(uuid.New(), uuid.Nil))
	assert.Error(t, err)
}

func TestSecretRepository_ExportImport_Deprecated(t *testing.T) {
	t.Parallel()
	db := setupSecretTestDB(t)
	repo := repositories.NewSecretRepository(rvdb.NewConn(db, rvdb.SQLite), newTestSecretLogger(t))
	ctx := context.Background()

	// Both methods are deprecated stubs that always return an error.
	_, err := repo.ExportSecrets(ctx, model.ExportOptions{})
	assert.Error(t, err)

	_, err = repo.ImportSecrets(ctx, []byte{}, model.ImportOptions{})
	assert.Error(t, err)
}

func TestSecretRepository_GetVersions_Deprecated(t *testing.T) {
	t.Parallel()
	db := setupSecretTestDB(t)
	repo := repositories.NewSecretRepository(rvdb.NewConn(db, rvdb.SQLite), newTestSecretLogger(t))
	ctx := context.Background()

	_, err := repo.GetVersions(ctx, uuid.New())
	assert.Error(t, err)

	_, err = repo.GetVersion(ctx, uuid.New(), 1)
	assert.Error(t, err)

	_, err = repo.GetLatestVersion(ctx, uuid.New())
	assert.Error(t, err)
}

// ---------------------------------------------------------------------------
// SessionRepository tests
// ---------------------------------------------------------------------------

func TestSessionRepository_CreateAndGetByID(t *testing.T) {
	t.Parallel()
	db := setupSessionDB(t)
	log := newLogger()
	repo := repositories.NewSessionRepository(repositories.SessionRepositoryConfig{DB: rvdb.NewConn(db, rvdb.SQLite), Logger: log})
	ctx := context.Background()

	userID := uuid.New()
	sess := newSession(userID)

	require.NoError(t, repo.CreateSession(ctx, sess))

	got, err := repo.GetSessionByID(ctx, sess.ID)
	require.NoError(t, err)
	assert.Equal(t, sess.ID, got.ID)
	assert.Equal(t, userID, got.UserID)
}

func TestSessionRepository_GetByID_NotFound(t *testing.T) {
	t.Parallel()
	db := setupSessionDB(t)
	log := newLogger()
	repo := repositories.NewSessionRepository(repositories.SessionRepositoryConfig{DB: rvdb.NewConn(db, rvdb.SQLite), Logger: log})
	ctx := context.Background()

	_, err := repo.GetSessionByID(ctx, uuid.New())
	assert.Error(t, err)
}

func TestSessionRepository_GetByRefreshToken(t *testing.T) {
	t.Parallel()
	db := setupSessionDB(t)
	log := newLogger()
	repo := repositories.NewSessionRepository(repositories.SessionRepositoryConfig{DB: rvdb.NewConn(db, rvdb.SQLite), Logger: log})
	ctx := context.Background()

	userID := uuid.New()
	sess := newSession(userID)
	require.NoError(t, repo.CreateSession(ctx, sess))

	got, err := repo.GetSessionByRefreshToken(ctx, sess.RefreshTokenHash)
	require.NoError(t, err)
	assert.Equal(t, sess.ID, got.ID)
}

func TestSessionRepository_GetByRefreshToken_NotFound(t *testing.T) {
	t.Parallel()
	db := setupSessionDB(t)
	log := newLogger()
	repo := repositories.NewSessionRepository(repositories.SessionRepositoryConfig{DB: rvdb.NewConn(db, rvdb.SQLite), Logger: log})
	ctx := context.Background()

	_, err := repo.GetSessionByRefreshToken(ctx, "nonexistent-token")
	assert.Error(t, err)
}

func TestSessionRepository_GetActiveSessionsByUserID(t *testing.T) {
	t.Parallel()
	db := setupSessionDB(t)
	log := newLogger()
	repo := repositories.NewSessionRepository(repositories.SessionRepositoryConfig{DB: rvdb.NewConn(db, rvdb.SQLite), Logger: log})
	ctx := context.Background()

	userID := uuid.New()
	sess1 := newSession(userID)
	sess2 := newSession(userID)
	require.NoError(t, repo.CreateSession(ctx, sess1))
	require.NoError(t, repo.CreateSession(ctx, sess2))

	// Revoke one session.
	require.NoError(t, repo.RevokeSession(ctx, sess2.ID, "test"))

	active, err := repo.GetActiveSessionsByUserID(ctx, userID)
	require.NoError(t, err)
	assert.Len(t, active, 1)
	assert.Equal(t, sess1.ID, active[0].ID)
}

func TestSessionRepository_UpdateSessionLastUsed(t *testing.T) {
	t.Parallel()
	db := setupSessionDB(t)
	log := newLogger()
	repo := repositories.NewSessionRepository(repositories.SessionRepositoryConfig{DB: rvdb.NewConn(db, rvdb.SQLite), Logger: log})
	ctx := context.Background()

	userID := uuid.New()
	sess := newSession(userID)
	require.NoError(t, repo.CreateSession(ctx, sess))

	newTime := time.Now().Add(5 * time.Minute)
	require.NoError(t, repo.UpdateSessionLastUsed(ctx, sess.ID, newTime))
}

func TestSessionRepository_RevokeSession(t *testing.T) {
	t.Parallel()
	db := setupSessionDB(t)
	log := newLogger()
	repo := repositories.NewSessionRepository(repositories.SessionRepositoryConfig{DB: rvdb.NewConn(db, rvdb.SQLite), Logger: log})
	ctx := context.Background()

	userID := uuid.New()
	sess := newSession(userID)
	require.NoError(t, repo.CreateSession(ctx, sess))

	require.NoError(t, repo.RevokeSession(ctx, sess.ID, "user-logout"))

	revoked, err := repo.IsSessionRevoked(ctx, sess.ID)
	require.NoError(t, err)
	assert.True(t, revoked)
}

func TestSessionRepository_IsSessionRevoked_NotRevoked(t *testing.T) {
	t.Parallel()
	db := setupSessionDB(t)
	log := newLogger()
	repo := repositories.NewSessionRepository(repositories.SessionRepositoryConfig{DB: rvdb.NewConn(db, rvdb.SQLite), Logger: log})
	ctx := context.Background()

	sess := newSession(uuid.New())
	require.NoError(t, repo.CreateSession(ctx, sess))

	revoked, err := repo.IsSessionRevoked(ctx, sess.ID)
	require.NoError(t, err)
	assert.False(t, revoked)
}

func TestSessionRepository_RevokeAllUserSessions(t *testing.T) {
	t.Parallel()
	db := setupSessionDB(t)
	log := newLogger()
	repo := repositories.NewSessionRepository(repositories.SessionRepositoryConfig{DB: rvdb.NewConn(db, rvdb.SQLite), Logger: log})
	ctx := context.Background()

	userID := uuid.New()
	sess1 := newSession(userID)
	sess2 := newSession(userID)
	require.NoError(t, repo.CreateSession(ctx, sess1))
	require.NoError(t, repo.CreateSession(ctx, sess2))

	require.NoError(t, repo.RevokeAllUserSessions(ctx, userID, "admin-revoke"))

	active, err := repo.GetActiveSessionsByUserID(ctx, userID)
	require.NoError(t, err)
	assert.Empty(t, active)
}

func TestSessionRepository_DeleteExpiredSessions(t *testing.T) {
	t.Parallel()
	db := setupSessionDB(t)
	log := newLogger()
	repo := repositories.NewSessionRepository(repositories.SessionRepositoryConfig{DB: rvdb.NewConn(db, rvdb.SQLite), Logger: log})
	ctx := context.Background()

	userID := uuid.New()
	// Expired session — expires_at in the past.
	expiredSess := newSession(userID)
	expiredSess.ExpiresAt = time.Now().Add(-time.Hour)
	// Active session — expires_at in the future.
	activeSess := newSession(userID)
	activeSess.ExpiresAt = time.Now().Add(time.Hour)

	require.NoError(t, repo.CreateSession(ctx, expiredSess))
	require.NoError(t, repo.CreateSession(ctx, activeSess))

	deleted, err := repo.DeleteExpiredSessions(ctx, time.Now())
	require.NoError(t, err)
	assert.Equal(t, int64(1), deleted)
}

func TestSessionRepository_CountActiveSessions(t *testing.T) {
	t.Parallel()
	db := setupSessionDB(t)
	log := newLogger()
	repo := repositories.NewSessionRepository(repositories.SessionRepositoryConfig{DB: rvdb.NewConn(db, rvdb.SQLite), Logger: log})
	ctx := context.Background()

	userID := uuid.New()
	sess1 := newSession(userID)
	sess2 := newSession(userID)
	require.NoError(t, repo.CreateSession(ctx, sess1))
	require.NoError(t, repo.CreateSession(ctx, sess2))
	require.NoError(t, repo.RevokeSession(ctx, sess2.ID, "test"))

	count, err := repo.CountActiveSessions(ctx, userID)
	require.NoError(t, err)
	assert.Equal(t, 1, count)
}

func TestSessionRepository_RevokeSession_NotFound(t *testing.T) {
	t.Parallel()
	db := setupSessionDB(t)
	log := newLogger()
	repo := repositories.NewSessionRepository(repositories.SessionRepositoryConfig{DB: rvdb.NewConn(db, rvdb.SQLite), Logger: log})
	ctx := context.Background()

	// Revoking a non-existent session should return an error.
	err := repo.RevokeSession(ctx, uuid.New(), "reason")
	assert.Error(t, err)
}

func TestSessionRepository_UpdateSessionLastUsed_NotFound(t *testing.T) {
	t.Parallel()
	db := setupSessionDB(t)
	log := newLogger()
	repo := repositories.NewSessionRepository(repositories.SessionRepositoryConfig{DB: rvdb.NewConn(db, rvdb.SQLite), Logger: log})
	ctx := context.Background()

	err := repo.UpdateSessionLastUsed(ctx, uuid.New(), time.Now())
	assert.Error(t, err)
}

func TestSessionRepository_IsSessionRevoked_NonExistent(t *testing.T) {
	t.Parallel()
	db := setupSessionDB(t)
	log := newLogger()
	repo := repositories.NewSessionRepository(repositories.SessionRepositoryConfig{DB: rvdb.NewConn(db, rvdb.SQLite), Logger: log})
	ctx := context.Background()

	// Non-existent session is treated as revoked.
	revoked, err := repo.IsSessionRevoked(ctx, uuid.New())
	require.NoError(t, err)
	assert.True(t, revoked)
}

// ---------------------------------------------------------------------------
// SecretTagRepository tests
// ---------------------------------------------------------------------------

func TestSecretTagRepository_AddAndGetTags(t *testing.T) {
	t.Parallel()
	db := setupTagDB(t)
	repo := repositories.NewSecretTagRepository(rvdb.NewConn(db, rvdb.SQLite))
	ctx := context.Background()

	secretID := uuid.New()
	require.NoError(t, repo.AddTags(ctx, secretID, []string{"env:prod", "tier:premium"}))

	tags, err := repo.GetTags(ctx, secretID)
	require.NoError(t, err)
	assert.ElementsMatch(t, []string{"env:prod", "tier:premium"}, tags)
}

func TestSecretTagRepository_GetTags_Empty(t *testing.T) {
	t.Parallel()
	db := setupTagDB(t)
	repo := repositories.NewSecretTagRepository(rvdb.NewConn(db, rvdb.SQLite))
	ctx := context.Background()

	tags, err := repo.GetTags(ctx, uuid.New())
	require.NoError(t, err)
	assert.Empty(t, tags)
}

func TestSecretTagRepository_RemoveTags(t *testing.T) {
	t.Parallel()
	db := setupTagDB(t)
	repo := repositories.NewSecretTagRepository(rvdb.NewConn(db, rvdb.SQLite))
	ctx := context.Background()

	secretID := uuid.New()
	require.NoError(t, repo.AddTags(ctx, secretID, []string{"a", "b", "c"}))

	require.NoError(t, repo.RemoveTags(ctx, secretID, []string{"b"}))

	tags, err := repo.GetTags(ctx, secretID)
	require.NoError(t, err)
	assert.ElementsMatch(t, []string{"a", "c"}, tags)
}

func TestSecretTagRepository_RemoveAllTags(t *testing.T) {
	t.Parallel()
	db := setupTagDB(t)
	repo := repositories.NewSecretTagRepository(rvdb.NewConn(db, rvdb.SQLite))
	ctx := context.Background()

	secretID := uuid.New()
	require.NoError(t, repo.AddTags(ctx, secretID, []string{"x", "y"}))

	require.NoError(t, repo.RemoveAllTags(ctx, secretID))

	tags, err := repo.GetTags(ctx, secretID)
	require.NoError(t, err)
	assert.Empty(t, tags)
}

func TestSecretTagRepository_FindSecretsByTags(t *testing.T) {
	t.Parallel()
	db := setupTagDB(t)
	repo := repositories.NewSecretTagRepository(rvdb.NewConn(db, rvdb.SQLite))
	ctx := context.Background()

	userID := uuid.New()
	s1 := uuid.New()
	s2 := uuid.New()

	// Insert two secrets directly so the JOIN in FindSecretsByTags works.
	insertSecret := func(id, uid uuid.UUID, name string) {
		_, err := db.ExecContext(ctx,
			"INSERT INTO secrets (id, user_id, name, value, version) VALUES (?, ?, ?, 'v', 1)",
			id.String(), uid.String(), name)
		require.NoError(t, err)
	}
	insertSecret(s1, userID, "secret1")
	insertSecret(s2, userID, "secret2")

	require.NoError(t, repo.AddTags(ctx, s1, []string{"env:prod"}))
	require.NoError(t, repo.AddTags(ctx, s2, []string{"env:staging"}))

	// Find secrets with "env:prod" tag.
	ids, err := repo.FindSecretsByTags(ctx, userID, []string{"env:prod"})
	require.NoError(t, err)
	assert.Len(t, ids, 1)
	assert.Equal(t, s1, ids[0])
}

func TestSecretTagRepository_FindSecretsByTags_EmptyTags(t *testing.T) {
	t.Parallel()
	db := setupTagDB(t)
	repo := repositories.NewSecretTagRepository(rvdb.NewConn(db, rvdb.SQLite))
	ctx := context.Background()

	// Empty tag list should return empty results without querying.
	ids, err := repo.FindSecretsByTags(ctx, uuid.New(), []string{})
	require.NoError(t, err)
	assert.Empty(t, ids)
}

// ---------------------------------------------------------------------------
// SecretVersionRepository tests
// ---------------------------------------------------------------------------

func TestSecretVersionRepository_CRUD(t *testing.T) {
	t.Parallel()
	db := setupVersioningDB(t)
	log := newLogger()
	repo := repositories.NewSecretVersionRepository(rvdb.NewConn(db, rvdb.SQLite), log)
	ctx := context.Background()

	secretID := uuid.New()
	userID := uuid.New()

	v1 := newSecretVersion(secretID, userID, 1)
	v2 := newSecretVersion(secretID, userID, 2)

	require.NoError(t, repo.CreateVersion(ctx, v1))
	require.NoError(t, repo.CreateVersion(ctx, v2))

	// GetVersions returns both, newest first.
	versions, err := repo.GetVersions(ctx, secretID)
	require.NoError(t, err)
	assert.Len(t, versions, 2)
	assert.Equal(t, 2, versions[0].Version)

	// GetVersion returns specific version.
	got, err := repo.GetVersion(ctx, secretID, 1)
	require.NoError(t, err)
	assert.Equal(t, v1.ID, got.ID)

	// GetLatestVersion returns highest version.
	latest, err := repo.GetLatestVersion(ctx, secretID)
	require.NoError(t, err)
	assert.Equal(t, 2, latest.Version)

	// DeleteSpecificVersion removes a single version.
	require.NoError(t, repo.DeleteSpecificVersion(ctx, secretID, 1))
	_, err = repo.GetVersion(ctx, secretID, 1)
	assert.Error(t, err)

	// DeleteVersions removes all remaining versions.
	require.NoError(t, repo.DeleteVersions(ctx, secretID))
	all, err := repo.GetVersions(ctx, secretID)
	require.NoError(t, err)
	assert.Empty(t, all)
}

func TestSecretVersionRepository_GetVersion_NotFound(t *testing.T) {
	t.Parallel()
	db := setupVersioningDB(t)
	log := newLogger()
	repo := repositories.NewSecretVersionRepository(rvdb.NewConn(db, rvdb.SQLite), log)
	ctx := context.Background()

	_, err := repo.GetVersion(ctx, uuid.New(), 99)
	assert.Error(t, err)
}

func TestSecretVersionRepository_GetLatestVersion_NoVersions(t *testing.T) {
	t.Parallel()
	db := setupVersioningDB(t)
	log := newLogger()
	repo := repositories.NewSecretVersionRepository(rvdb.NewConn(db, rvdb.SQLite), log)
	ctx := context.Background()

	_, err := repo.GetLatestVersion(ctx, uuid.New())
	assert.Error(t, err)
}

func TestSecretVersionRepository_DeleteSpecificVersion_NotFound(t *testing.T) {
	t.Parallel()
	db := setupVersioningDB(t)
	log := newLogger()
	repo := repositories.NewSecretVersionRepository(rvdb.NewConn(db, rvdb.SQLite), log)
	ctx := context.Background()

	err := repo.DeleteSpecificVersion(ctx, uuid.New(), 999)
	assert.Error(t, err)
}

// ---------------------------------------------------------------------------
// KeyRepository – additional coverage for purge, protection, vault listing
// ---------------------------------------------------------------------------

func TestKeyRepository_PurgeKey(t *testing.T) {
	t.Parallel()
	db := setupFullKeyDB(t)
	log := logging.InitLogger()
	repo := repositories.NewKeyRepository(rvdb.NewConn(db, rvdb.SQLite), log)
	ctx := context.Background()

	k := newKey(uuid.New(), uuid.New(), "purge-key")
	require.NoError(t, repo.Create(ctx, k))
	require.NoError(t, repo.SoftDelete(ctx, k.ID))

	require.NoError(t, repo.PurgeKey(ctx, k.ID))

	// Row must be gone permanently.
	var count int
	require.NoError(t, db.QueryRowContext(ctx, "SELECT COUNT(*) FROM keys WHERE id = ?", k.ID.String()).Scan(&count))
	assert.Equal(t, 0, count)
}

func TestKeyRepository_PurgeKey_NotSoftDeleted(t *testing.T) {
	t.Parallel()
	db := setupFullKeyDB(t)
	log := logging.InitLogger()
	repo := repositories.NewKeyRepository(rvdb.NewConn(db, rvdb.SQLite), log)
	ctx := context.Background()

	k := newKey(uuid.New(), uuid.New(), "active-key")
	require.NoError(t, repo.Create(ctx, k))

	err := repo.PurgeKey(ctx, k.ID)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not soft-deleted")
}

func TestKeyRepository_PurgeKey_NotFound(t *testing.T) {
	t.Parallel()
	db := setupFullKeyDB(t)
	log := logging.InitLogger()
	repo := repositories.NewKeyRepository(rvdb.NewConn(db, rvdb.SQLite), log)
	ctx := context.Background()

	err := repo.PurgeKey(ctx, uuid.New())
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

func TestKeyRepository_PurgeKey_PurgeProtection(t *testing.T) {
	t.Parallel()
	db := setupFullKeyDB(t)
	log := logging.InitLogger()
	repo := repositories.NewKeyRepository(rvdb.NewConn(db, rvdb.SQLite), log)
	ctx := context.Background()

	k := newKey(uuid.New(), uuid.New(), "protected-key")
	require.NoError(t, repo.Create(ctx, k))
	require.NoError(t, repo.SoftDelete(ctx, k.ID))

	// Enable purge protection.
	require.NoError(t, repo.SetPurgeProtection(ctx, k.ID, true))

	err := repo.PurgeKey(ctx, k.ID)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "purge protection")
}

func TestKeyRepository_SetPurgeProtection(t *testing.T) {
	t.Parallel()
	db := setupFullKeyDB(t)
	log := logging.InitLogger()
	repo := repositories.NewKeyRepository(rvdb.NewConn(db, rvdb.SQLite), log)
	ctx := context.Background()

	k := newKey(uuid.New(), uuid.New(), "pp-key")
	require.NoError(t, repo.Create(ctx, k))

	require.NoError(t, repo.SetPurgeProtection(ctx, k.ID, true))

	var pp bool
	require.NoError(t, db.QueryRowContext(ctx, "SELECT purge_protection FROM keys WHERE id = ?", k.ID.String()).Scan(&pp))
	assert.True(t, pp)
}

func TestKeyRepository_SetPurgeProtection_NotFound(t *testing.T) {
	t.Parallel()
	db := setupFullKeyDB(t)
	log := logging.InitLogger()
	repo := repositories.NewKeyRepository(rvdb.NewConn(db, rvdb.SQLite), log)
	ctx := context.Background()

	err := repo.SetPurgeProtection(ctx, uuid.New(), true)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

func TestKeyRepository_ListInVault_WithType(t *testing.T) {
	t.Parallel()
	db := setupFullKeyDB(t)
	log := logging.InitLogger()
	repo := repositories.NewKeyRepository(rvdb.NewConn(db, rvdb.SQLite), log)
	ctx := context.Background()

	vaultID := uuid.New()
	userID := uuid.New()

	k1 := newKey(userID, vaultID, "rsa-in-vault")
	k1.Type = model.KeyTypeRSA
	k2 := newKey(userID, vaultID, "ecdsa-in-vault")
	k2.Type = model.KeyTypeECDSA
	require.NoError(t, repo.Create(ctx, k1))
	require.NoError(t, repo.Create(ctx, k2))

	rsaOnly, err := repo.List(ctx, model.NewVaultScope(vaultID, uuid.Nil), repositories.KeyFilter{Type: model.KeyTypeRSA})
	require.NoError(t, err)
	assert.Len(t, rsaOnly, 1)
	assert.Equal(t, model.KeyTypeRSA, rsaOnly[0].Type)
}

func TestKeyRepository_ReadInVault(t *testing.T) {
	t.Parallel()
	db := setupFullKeyDB(t)
	log := logging.InitLogger()
	repo := repositories.NewKeyRepository(rvdb.NewConn(db, rvdb.SQLite), log)
	ctx := context.Background()

	vaultID := uuid.New()
	k := newKey(uuid.New(), vaultID, "vault-key")
	require.NoError(t, repo.Create(ctx, k))

	got, err := repo.Read(ctx, k.ID, model.NewVaultScope(vaultID, uuid.Nil))
	require.NoError(t, err)
	assert.Equal(t, k.ID, got.ID)
}

func TestKeyRepository_ReadInVault_WrongVault(t *testing.T) {
	t.Parallel()
	db := setupFullKeyDB(t)
	log := logging.InitLogger()
	repo := repositories.NewKeyRepository(rvdb.NewConn(db, rvdb.SQLite), log)
	ctx := context.Background()

	vaultA := uuid.New()
	k := newKey(uuid.New(), vaultA, "vault-key-a")
	require.NoError(t, repo.Create(ctx, k))

	_, err := repo.Read(ctx, k.ID, model.NewVaultScope(uuid.New(), uuid.Nil))
	assert.Error(t, err)
}

// ---------------------------------------------------------------------------
// CertificateRepository – purge, protection, and vault listing coverage
// ---------------------------------------------------------------------------

func TestCertificateRepository_PurgeCertificate(t *testing.T) {
	t.Parallel()
	db := setupFullCertDB(t)
	log := logging.InitLogger()
	repo := repositories.NewCertificateRepository(rvdb.NewConn(db, rvdb.SQLite), log)
	ctx := context.Background()

	cert := newCert(uuid.New(), uuid.New(), "purge-cert")
	require.NoError(t, repo.Create(ctx, cert))
	require.NoError(t, repo.SoftDelete(ctx, cert.ID))

	require.NoError(t, repo.PurgeCertificate(ctx, cert.ID))

	var count int
	require.NoError(t, db.QueryRowContext(ctx, "SELECT COUNT(*) FROM certificates WHERE id = ?", cert.ID.String()).Scan(&count))
	assert.Equal(t, 0, count)
}

func TestCertificateRepository_PurgeCertificate_NotSoftDeleted(t *testing.T) {
	t.Parallel()
	db := setupFullCertDB(t)
	log := logging.InitLogger()
	repo := repositories.NewCertificateRepository(rvdb.NewConn(db, rvdb.SQLite), log)
	ctx := context.Background()

	cert := newCert(uuid.New(), uuid.New(), "active-cert")
	require.NoError(t, repo.Create(ctx, cert))

	err := repo.PurgeCertificate(ctx, cert.ID)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not soft-deleted")
}

func TestCertificateRepository_PurgeCertificate_NotFound(t *testing.T) {
	t.Parallel()
	db := setupFullCertDB(t)
	log := logging.InitLogger()
	repo := repositories.NewCertificateRepository(rvdb.NewConn(db, rvdb.SQLite), log)
	ctx := context.Background()

	err := repo.PurgeCertificate(ctx, uuid.New())
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

func TestCertificateRepository_PurgeCertificate_PurgeProtection(t *testing.T) {
	t.Parallel()
	db := setupFullCertDB(t)
	log := logging.InitLogger()
	repo := repositories.NewCertificateRepository(rvdb.NewConn(db, rvdb.SQLite), log)
	ctx := context.Background()

	cert := newCert(uuid.New(), uuid.New(), "pp-cert")
	require.NoError(t, repo.Create(ctx, cert))
	require.NoError(t, repo.SoftDelete(ctx, cert.ID))

	// Enable purge protection directly.
	_, err := db.ExecContext(ctx, "UPDATE certificates SET purge_protection = TRUE WHERE id = ?", cert.ID.String())
	require.NoError(t, err)

	err = repo.PurgeCertificate(ctx, cert.ID)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "purge protection")
}

func TestCertificateRepository_SetPurgeProtection(t *testing.T) {
	t.Parallel()
	db := setupFullCertDB(t)
	log := logging.InitLogger()
	repo := repositories.NewCertificateRepository(rvdb.NewConn(db, rvdb.SQLite), log)
	ctx := context.Background()

	cert := newCert(uuid.New(), uuid.New(), "protect-cert")
	require.NoError(t, repo.Create(ctx, cert))

	require.NoError(t, repo.SetPurgeProtection(ctx, cert.ID, true))

	var pp bool
	require.NoError(t, db.QueryRowContext(ctx, "SELECT purge_protection FROM certificates WHERE id = ?", cert.ID.String()).Scan(&pp))
	assert.True(t, pp)
}

func TestCertificateRepository_SetPurgeProtection_NotFound(t *testing.T) {
	t.Parallel()
	db := setupFullCertDB(t)
	log := logging.InitLogger()
	repo := repositories.NewCertificateRepository(rvdb.NewConn(db, rvdb.SQLite), log)
	ctx := context.Background()

	err := repo.SetPurgeProtection(ctx, uuid.New(), true)
	assert.Error(t, err)
}

func TestCertificateRepository_ListInVault_ExcludesSoftDeleted(t *testing.T) {
	t.Parallel()
	db := setupFullCertDB(t)
	log := logging.InitLogger()
	repo := repositories.NewCertificateRepository(rvdb.NewConn(db, rvdb.SQLite), log)
	ctx := context.Background()

	vaultID := uuid.New()
	userID := uuid.New()

	c1 := newCert(userID, vaultID, "active-cert")
	c2 := newCert(userID, vaultID, "deleted-cert")
	require.NoError(t, repo.Create(ctx, c1))
	require.NoError(t, repo.Create(ctx, c2))
	require.NoError(t, repo.SoftDelete(ctx, c2.ID))

	active, err := repo.List(ctx, model.NewVaultScope(vaultID, uuid.Nil), repositories.CertificateFilter{})
	require.NoError(t, err)
	assert.Len(t, active, 1)
	assert.Equal(t, c1.ID, active[0].ID)
}

func TestKeyRepository_SoftDelete_NotFound(t *testing.T) {
	t.Parallel()
	db := setupFullKeyDB(t)
	log := logging.InitLogger()
	repo := repositories.NewKeyRepository(rvdb.NewConn(db, rvdb.SQLite), log)
	ctx := context.Background()

	err := repo.SoftDelete(ctx, uuid.New())
	assert.Error(t, err)
}

func TestKeyRepository_ListInVault_WithTags(t *testing.T) {
	t.Parallel()
	db := setupFullKeyDB(t)
	log := logging.InitLogger()
	repo := repositories.NewKeyRepository(rvdb.NewConn(db, rvdb.SQLite), log)
	ctx := context.Background()

	vaultID := uuid.New()
	userID := uuid.New()

	k1 := newKey(userID, vaultID, "tagged-vault-key")
	k1.Tags = []string{"env:prod"}
	k2 := newKey(userID, vaultID, "plain-vault-key")

	require.NoError(t, repo.Create(ctx, k1))
	require.NoError(t, repo.Create(ctx, k2))

	tagged, err := repo.List(ctx, model.NewVaultScope(vaultID, uuid.Nil), repositories.KeyFilter{Tags: []string{"env:prod"}})
	require.NoError(t, err)
	assert.Len(t, tagged, 1)
	assert.Equal(t, k1.ID, tagged[0].ID)
}

// TestKeyRepository_List_TagsPopulatedCorrectlyPerEntity guards
// List's batch tag-fetch (GetTagsForMany) against cross-contamination: three
// keys each get a distinct, disjoint tag set, and every returned key's .Tags
// must match only its own — not a neighbor's, not merged, not empty.
func TestKeyRepository_List_TagsPopulatedCorrectlyPerEntity(t *testing.T) {
	t.Parallel()
	db := setupFullKeyDB(t)
	log := logging.InitLogger()
	repo := repositories.NewKeyRepository(rvdb.NewConn(db, rvdb.SQLite), log)
	ctx := context.Background()

	vaultID := uuid.New()
	userID := uuid.New()

	k1 := newKey(userID, vaultID, "key-a")
	k1.Tags = []string{"team:payments", "env:prod"}
	k2 := newKey(userID, vaultID, "key-b")
	k2.Tags = []string{"team:auth"}
	k3 := newKey(userID, vaultID, "key-c") // no tags at all

	require.NoError(t, repo.Create(ctx, k1))
	require.NoError(t, repo.Create(ctx, k2))
	require.NoError(t, repo.Create(ctx, k3))

	all, err := repo.List(ctx, model.NewVaultScope(vaultID, uuid.Nil), repositories.KeyFilter{})
	require.NoError(t, err)
	require.Len(t, all, 3)

	byID := make(map[uuid.UUID][]string, len(all))
	for _, k := range all {
		byID[k.ID] = k.Tags
	}
	assert.ElementsMatch(t, []string{"team:payments", "env:prod"}, byID[k1.ID])
	assert.ElementsMatch(t, []string{"team:auth"}, byID[k2.ID])
	assert.Empty(t, byID[k3.ID])
}

func TestCertificateRepository_SoftDelete_NotFound(t *testing.T) {
	t.Parallel()
	db := setupFullCertDB(t)
	log := logging.InitLogger()
	repo := repositories.NewCertificateRepository(rvdb.NewConn(db, rvdb.SQLite), log)
	ctx := context.Background()

	err := repo.SoftDelete(ctx, uuid.New())
	assert.Error(t, err)
}

func TestCertificateRepository_ListInVault_WithType(t *testing.T) {
	t.Parallel()
	db := setupFullCertDB(t)
	log := logging.InitLogger()
	repo := repositories.NewCertificateRepository(rvdb.NewConn(db, rvdb.SQLite), log)
	ctx := context.Background()

	vaultID := uuid.New()
	userID := uuid.New()

	// No type filter needed — just verify multiple certs list correctly.
	c1 := newCert(userID, vaultID, "cert-v1")
	c2 := newCert(userID, vaultID, "cert-v2")
	require.NoError(t, repo.Create(ctx, c1))
	require.NoError(t, repo.Create(ctx, c2))

	all, err := repo.List(ctx, model.NewVaultScope(vaultID, uuid.Nil), repositories.CertificateFilter{})
	require.NoError(t, err)
	assert.Len(t, all, 2)
}

func TestCertificateRepository_ReadInVault_Correct(t *testing.T) {
	t.Parallel()
	db := setupFullCertDB(t)
	log := logging.InitLogger()
	repo := repositories.NewCertificateRepository(rvdb.NewConn(db, rvdb.SQLite), log)
	ctx := context.Background()

	vaultID := uuid.New()
	cert := newCert(uuid.New(), vaultID, "in-vault-cert")
	require.NoError(t, repo.Create(ctx, cert))

	got, err := repo.Read(ctx, cert.ID, model.NewVaultScope(vaultID, uuid.Nil))
	require.NoError(t, err)
	assert.Equal(t, cert.ID, got.ID)
}

func TestCertificateRepository_ListInVault_WithTags(t *testing.T) {
	t.Parallel()
	db := setupFullCertDB(t)
	log := logging.InitLogger()
	repo := repositories.NewCertificateRepository(rvdb.NewConn(db, rvdb.SQLite), log)
	ctx := context.Background()

	vaultID := uuid.New()
	userID := uuid.New()

	c1 := newCert(userID, vaultID, "tagged-vault-cert")
	c1.Tags = []string{"env:staging"}
	c2 := newCert(userID, vaultID, "plain-vault-cert")

	require.NoError(t, repo.Create(ctx, c1))
	require.NoError(t, repo.Create(ctx, c2))

	tagged, err := repo.List(ctx, model.NewVaultScope(vaultID, uuid.Nil), repositories.CertificateFilter{Tags: []string{"env:staging"}})
	require.NoError(t, err)
	assert.Len(t, tagged, 1)
	assert.Equal(t, c1.ID, tagged[0].ID)
}

// TestCertificateRepository_List_TagsPopulatedCorrectlyPerEntity guards
// List's batch tag-fetch (GetTagsForMany) against cross-contamination: three
// certificates each get a distinct, disjoint tag set, and every returned
// certificate's .Tags must match only its own — not a neighbor's, not
// merged, not empty.
func TestCertificateRepository_List_TagsPopulatedCorrectlyPerEntity(t *testing.T) {
	t.Parallel()
	db := setupFullCertDB(t)
	log := logging.InitLogger()
	repo := repositories.NewCertificateRepository(rvdb.NewConn(db, rvdb.SQLite), log)
	ctx := context.Background()

	vaultID := uuid.New()
	userID := uuid.New()

	c1 := newCert(userID, vaultID, "cert-a")
	c1.Tags = []string{"team:payments", "env:prod"}
	c2 := newCert(userID, vaultID, "cert-b")
	c2.Tags = []string{"team:auth"}
	c3 := newCert(userID, vaultID, "cert-c") // no tags at all

	require.NoError(t, repo.Create(ctx, c1))
	require.NoError(t, repo.Create(ctx, c2))
	require.NoError(t, repo.Create(ctx, c3))

	all, err := repo.List(ctx, model.NewVaultScope(vaultID, uuid.Nil), repositories.CertificateFilter{})
	require.NoError(t, err)
	require.Len(t, all, 3)

	byID := make(map[uuid.UUID][]string, len(all))
	for _, c := range all {
		byID[c.ID] = c.Tags
	}
	assert.ElementsMatch(t, []string{"team:payments", "env:prod"}, byID[c1.ID])
	assert.ElementsMatch(t, []string{"team:auth"}, byID[c2.ID])
	assert.Empty(t, byID[c3.ID])
}

func TestCertificateRepository_ListByUser_ExcludesSoftDeleted(t *testing.T) {
	t.Parallel()
	db := setupFullCertDB(t)
	log := logging.InitLogger()
	repo := repositories.NewCertificateRepository(rvdb.NewConn(db, rvdb.SQLite), log)
	ctx := context.Background()

	userID := uuid.New()
	c1 := newCert(userID, uuid.New(), "active")
	c2 := newCert(userID, uuid.New(), "deleted")
	require.NoError(t, repo.Create(ctx, c1))
	require.NoError(t, repo.Create(ctx, c2))
	require.NoError(t, repo.SoftDelete(ctx, c2.ID))

	list, err := repo.List(ctx, model.NewOwnerScope(uuid.Nil, userID), repositories.CertificateFilter{})
	require.NoError(t, err)
	assert.Len(t, list, 1)
	assert.Equal(t, c1.ID, list[0].ID)
}

// ---------------------------------------------------------------------------
// OAuth2ClientRepository – scan with expires_at not null
// ---------------------------------------------------------------------------

func TestOAuth2ClientRepository_WithExpiresAt(t *testing.T) {
	t.Parallel()
	db := setupOAuth2TestDB(t)
	repo := repositories.NewOAuth2ClientRepository(rvdb.NewConn(db, rvdb.SQLite))
	ctx := context.Background()

	expiresAt := time.Now().Add(24 * time.Hour)
	client := &model.OAuth2Client{
		ID:           uuid.New(),
		Name:         "expiring-client",
		ClientSecret: "secret",
		Description:  "a client with expiry",
		Enabled:      true,
		CreatedAt:    time.Now().UTC(),
		ExpiresAt:    &expiresAt,
	}
	require.NoError(t, repo.Create(ctx, client))

	// GetByID exercises scanOAuth2Client with non-null expires_at.
	got, err := repo.GetByID(ctx, client.ID)
	require.NoError(t, err)
	assert.NotNil(t, got.ExpiresAt)

	// List exercises scanOAuth2ClientRow with non-null expires_at.
	list, err := repo.List(ctx)
	require.NoError(t, err)
	require.Len(t, list, 1)
	assert.NotNil(t, list[0].ExpiresAt)
}

// ---------------------------------------------------------------------------
// CertificatePolicyRepository – DeleteByCertificateID not-found path
// ---------------------------------------------------------------------------

func TestCertificatePolicy_DeleteByCertificateID_NotFound(t *testing.T) {
	t.Parallel()
	db := setupCertPolicyTestDB(t)
	repo := repositories.NewCertificatePolicyRepository(rvdb.NewConn(db, rvdb.SQLite), newCertPolicyTestLogger(t))
	ctx := context.Background()

	// Delete when no policy exists should return sql.ErrNoRows.
	err := repo.DeleteByCertificateID(ctx, uuid.New(), uuid.New())
	assert.ErrorIs(t, err, sql.ErrNoRows)
}

// ---------------------------------------------------------------------------
// AccessPolicyRepository – scanAccessPolicy vault_id path
// ---------------------------------------------------------------------------

func TestAccessPolicyRepository_Update_WithVaultID(t *testing.T) {
	t.Parallel()
	db := setupAccessPolicyTestDB(t)
	repo := repositories.NewAccessPolicyRepository(rvdb.NewConn(db, rvdb.SQLite))
	ctx := context.Background()

	vaultID := uuid.New()
	p := &model.AccessPolicy{
		ID:            uuid.New(),
		PrincipalID:   uuid.New(),
		PrincipalType: model.PrincipalTypeUser,
		ResourceType:  model.PolicyResourceSecrets,
		Operation:     model.OpGet,
		Effect:        model.PolicyEffectAllow,
		VaultID:       &vaultID,
	}
	require.NoError(t, repo.Create(ctx, p))

	// Update with a different vault — exercises the vaultArg != nil branch in Update.
	newVaultID := uuid.New()
	p.VaultID = &newVaultID
	p.Operation = model.OpList
	require.NoError(t, repo.Update(ctx, p))

	got, err := repo.GetByID(ctx, p.ID)
	require.NoError(t, err)
	assert.Equal(t, model.OpList, got.Operation)
}

func TestAccessPolicyRepository_FindEffects_GlobalAndVaultScoped(t *testing.T) {
	t.Parallel()
	db := setupAccessPolicyTestDB(t)
	repo := repositories.NewAccessPolicyRepository(rvdb.NewConn(db, rvdb.SQLite))
	ctx := context.Background()

	principalID := uuid.New()
	vaultID := uuid.New()

	// Global policy (no vault scope).
	p1 := &model.AccessPolicy{
		ID:            uuid.New(),
		PrincipalID:   principalID,
		PrincipalType: model.PrincipalTypeUser,
		ResourceType:  model.PolicyResourceSecrets,
		Operation:     model.OpGet,
		Effect:        model.PolicyEffectAllow,
	}
	// Vault-scoped policy.
	p2 := &model.AccessPolicy{
		ID:            uuid.New(),
		PrincipalID:   principalID,
		PrincipalType: model.PrincipalTypeUser,
		ResourceType:  model.PolicyResourceSecrets,
		Operation:     model.OpGet,
		Effect:        model.PolicyEffectAllow,
		VaultID:       &vaultID,
	}
	require.NoError(t, repo.Create(ctx, p1))
	require.NoError(t, repo.Create(ctx, p2))

	effects, err := repo.FindEffects(ctx, principalID, model.PolicyResourceSecrets, model.OpGet, vaultID)
	require.NoError(t, err)
	// Both the global and vault-scoped policy should match.
	assert.Len(t, effects, 2)
}

func TestAccessPolicyRepository_ScanAccessPolicy_WithVaultID(t *testing.T) {
	t.Parallel()
	db := setupAccessPolicyTestDB(t)
	repo := repositories.NewAccessPolicyRepository(rvdb.NewConn(db, rvdb.SQLite))
	ctx := context.Background()

	vaultID := uuid.New()
	p := &model.AccessPolicy{
		ID:            uuid.New(),
		PrincipalID:   uuid.New(),
		PrincipalType: model.PrincipalTypeUser,
		ResourceType:  model.PolicyResourceSecrets,
		Operation:     model.OpGet,
		Effect:        model.PolicyEffectAllow,
		VaultID:       &vaultID,
	}
	require.NoError(t, repo.Create(ctx, p))

	// ListByPrincipal triggers scanAccessPolicy with a valid vault_id.
	policies, err := repo.ListByPrincipal(ctx, p.PrincipalID)
	require.NoError(t, err)
	require.Len(t, policies, 1)
	require.NotNil(t, policies[0].VaultID)
	assert.Equal(t, vaultID, *policies[0].VaultID)
}

// ---------------------------------------------------------------------------
// RotationPolicyRepository – more coverage
// ---------------------------------------------------------------------------

func TestRotationPolicyRepository_RemoveFromSecret_NotFound(t *testing.T) {
	t.Parallel()
	db := setupRotationDB(t)
	log := logging.InitLogger()
	repo := repositories.NewRotationPolicyRepository(rvdb.NewConn(db, rvdb.SQLite), log)
	ctx := context.Background()

	// Remove from a non-existent assignment should return an error.
	err := repo.RemoveFromSecret(ctx, uuid.New(), uuid.New())
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

func TestRotationPolicyRepository_UpdateSecretPolicyRotation_NotFound(t *testing.T) {
	t.Parallel()
	db := setupRotationDB(t)
	log := logging.InitLogger()
	repo := repositories.NewRotationPolicyRepository(rvdb.NewConn(db, rvdb.SQLite), log)
	ctx := context.Background()

	// Update non-existent secret policy — should fail.
	err := repo.UpdateSecretPolicyRotation(ctx, uuid.New(), uuid.New(), time.Now(), time.Now())
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

func TestRotationPolicyRepository_RecordRotation_WithPolicyID(t *testing.T) {
	t.Parallel()
	db := setupRotationDB(t)
	log := logging.InitLogger()
	repo := repositories.NewRotationPolicyRepository(rvdb.NewConn(db, rvdb.SQLite), log)
	ctx := context.Background()

	// Create a policy first so the policy_id FK is valid.
	now := time.Now()
	userID := uuid.New()
	policy := &model.RotationPolicy{
		ID:           uuid.New(),
		UserID:       userID,
		Name:         "p1",
		IntervalDays: 7,
		CreatedAt:    now,
		UpdatedAt:    now,
	}
	require.NoError(t, repo.Create(ctx, policy))

	secretID := uuid.New()
	policyID := policy.ID
	history := &model.RotationHistory{
		ID:              uuid.New(),
		SecretID:        secretID,
		PolicyID:        &policyID, // Non-nil — exercises the nil check branch.
		RotatedAt:       now,
		PreviousVersion: 1,
		NewVersion:      2,
		TriggeredBy:     "scheduler",
		Notes:           "scheduled rotation",
	}
	require.NoError(t, repo.RecordRotation(ctx, history))

	got, err := repo.GetRotationHistory(ctx, secretID)
	require.NoError(t, err)
	require.Len(t, got, 1)
	assert.NotNil(t, got[0].PolicyID)
	assert.Equal(t, policyID, *got[0].PolicyID)
}

// ---------------------------------------------------------------------------
// RotationPolicyRepository – GetUpcomingReminders with actual upcoming data
// ---------------------------------------------------------------------------

func TestRotationPolicyRepository_GetUpcomingReminders_HasData(t *testing.T) {
	t.Parallel()
	db := setupRotationDB(t)
	log := logging.InitLogger()
	repo := repositories.NewRotationPolicyRepository(rvdb.NewConn(db, rvdb.SQLite), log)
	ctx := context.Background()

	now := time.Now()
	userID := uuid.New()

	// Create a policy — GetUpcomingReminders JOINs with rotation_policies.
	policy := &model.RotationPolicy{
		ID:           uuid.New(),
		UserID:       userID,
		Name:         "upcoming-test",
		IntervalDays: 30,
		Enabled:      true,
		CreatedAt:    now,
		UpdatedAt:    now,
	}
	require.NoError(t, repo.Create(ctx, policy))

	secretID := uuid.New()
	pastReminder := now.Add(-2 * time.Minute) // In the past, not acknowledged.

	reminder := &model.RotationReminder{
		ID:             uuid.New(),
		SecretID:       secretID,
		PolicyID:       policy.ID,
		ReminderType:   "overdue",
		SentAt:         now.Add(-time.Hour),
		NextReminderAt: &pastReminder,
		Acknowledged:   false,
	}
	require.NoError(t, repo.CreateReminder(ctx, reminder))

	// GetUpcomingReminders should return this reminder.
	upcoming, err := repo.GetUpcomingReminders(ctx, model.NewAdminScope(userID))
	require.NoError(t, err)
	assert.Len(t, upcoming, 1)
	assert.Equal(t, reminder.ID, upcoming[0].ID)
}

// ---------------------------------------------------------------------------
// VaultRepository – ReadByID (0% uncovered)
// ---------------------------------------------------------------------------

func TestVaultRepository_ReadByID(t *testing.T) {
	t.Parallel()
	db := newVaultTestDB(t)
	repo := repositories.NewVaultRepository(rvdb.NewConn(db, rvdb.SQLite), newTestVaultLogger(t))
	ctx := context.Background()

	id := uuid.New()
	v := &model.Vault{ID: id, Name: "by-id", Enabled: true, RetentionDays: 90, CreatedBy: uuid.New()}
	require.NoError(t, repo.Create(ctx, v))

	got, err := repo.ReadByID(ctx, id)
	require.NoError(t, err)
	assert.Equal(t, id, got.ID)
	assert.Equal(t, "by-id", got.Name)
}

func TestVaultRepository_ReadByID_NotFound(t *testing.T) {
	t.Parallel()
	db := newVaultTestDB(t)
	repo := repositories.NewVaultRepository(rvdb.NewConn(db, rvdb.SQLite), newTestVaultLogger(t))
	ctx := context.Background()

	_, err := repo.ReadByID(ctx, uuid.New())
	assert.Error(t, err)
}

func TestVaultRepository_Update_WithUpdatedBy(t *testing.T) {
	t.Parallel()
	db := newVaultTestDB(t)
	repo := repositories.NewVaultRepository(rvdb.NewConn(db, rvdb.SQLite), newTestVaultLogger(t))
	ctx := context.Background()

	id := uuid.New()
	v := &model.Vault{ID: id, Name: "update-vault", Enabled: true, RetentionDays: 90, CreatedBy: uuid.New()}
	require.NoError(t, repo.Create(ctx, v))

	// Update with a non-nil, non-zero UpdatedBy — exercises the updatedBy branch.
	updatedBy := uuid.New()
	v.RetentionDays = 30
	v.UpdatedBy = &updatedBy
	require.NoError(t, repo.Update(ctx, v))

	got, err := repo.ReadByID(ctx, id)
	require.NoError(t, err)
	assert.Equal(t, 30, got.RetentionDays)
}

func TestVaultRepository_Purge(t *testing.T) {
	t.Parallel()
	db := newVaultTestDB(t)
	repo := repositories.NewVaultRepository(rvdb.NewConn(db, rvdb.SQLite), newTestVaultLogger(t))
	ctx := context.Background()

	id := uuid.New()
	v := &model.Vault{ID: id, Name: "purge-vault", Enabled: true, RetentionDays: 90, CreatedBy: uuid.New()}
	require.NoError(t, repo.Create(ctx, v))
	require.NoError(t, repo.SoftDelete(ctx, id))

	require.NoError(t, repo.Purge(ctx, id))

	_, err := repo.ReadByID(ctx, id)
	assert.Error(t, err)
}

// ---------------------------------------------------------------------------
// UserRepository – multi-role writes
// ---------------------------------------------------------------------------

func TestUserRepository_Create_WritesMultipleRoles(t *testing.T) {
	t.Parallel()
	db := setupUserDB(t)
	repo := repositories.NewUserRepository(rvdb.NewConn(db, rvdb.SQLite), newLogger())
	ctx := context.Background()

	u := &model.User{
		ID:           uuid.New(),
		Username:     "dave",
		PasswordHash: "hashed-password",
		Roles:        []string{"admin", "secrets_manager"},
		CreatedAt:    time.Now(),
	}
	require.NoError(t, repo.Create(ctx, u))

	got, err := repo.Read(ctx, u.ID)
	require.NoError(t, err)
	assert.ElementsMatch(t, []string{"admin", "secrets_manager"}, got.Roles)
}

func TestUserRepository_ReadPaths_PopulateRoles(t *testing.T) {
	t.Parallel()
	db := setupUserDB(t)
	repo := repositories.NewUserRepository(rvdb.NewConn(db, rvdb.SQLite), newLogger())
	ctx := context.Background()

	u := &model.User{
		ID:           uuid.New(),
		Username:     "erin",
		PasswordHash: "hashed-password",
		Roles:        []string{"crypto_manager", "certificate_manager"},
		CreatedAt:    time.Now(),
	}
	require.NoError(t, repo.Create(ctx, u))

	byID, err := repo.Read(ctx, u.ID)
	require.NoError(t, err)
	assert.ElementsMatch(t, u.Roles, byID.Roles, "Read")

	byUsername, err := repo.ReadByUsername(ctx, "erin")
	require.NoError(t, err)
	assert.ElementsMatch(t, u.Roles, byUsername.Roles, "ReadByUsername")

	list, err := repo.List(ctx)
	require.NoError(t, err)
	var found bool
	for _, lu := range list {
		if lu.ID == u.ID {
			found = true
			assert.ElementsMatch(t, u.Roles, lu.Roles, "List")
		}
	}
	require.True(t, found, "created user must appear in List")
}

func TestUserRepository_Update_ReplacesMultipleRolesAtOnce(t *testing.T) {
	t.Parallel()
	db := setupUserDB(t)
	repo := repositories.NewUserRepository(rvdb.NewConn(db, rvdb.SQLite), newLogger())
	ctx := context.Background()

	u := &model.User{
		ID:           uuid.New(),
		Username:     "frankie",
		PasswordHash: "hashed-password",
		Roles:        []string{"admin", "secrets_manager"},
		CreatedAt:    time.Now(),
	}
	require.NoError(t, repo.Create(ctx, u))

	u.Roles = []string{"user"}
	require.NoError(t, repo.Update(ctx, u))

	got, err := repo.Read(ctx, u.ID)
	require.NoError(t, err)
	assert.Equal(t, []string{"user"}, got.Roles, "Roles must be exactly [\"user\"] after replacing both admin and secrets_manager")
}
