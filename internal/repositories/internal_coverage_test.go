// Package repositories contains white-box tests that cover DB-error branches
// unreachable from an external test package. Each test drops or corrupts the
// relevant table after setup so that the repository method hits the error path.
package repositories

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/google/uuid"
	_ "github.com/mattn/go-sqlite3"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	rvdb "rocketvault/internal/db"
	"rocketvault/internal/logging"
	"rocketvault/model"
)

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

// newInternalLogger returns a silent logger for internal tests.
func newInternalLogger() *logging.Logger {
	l := logrus.New()
	l.SetLevel(logrus.PanicLevel)
	return &logging.Logger{Logger: l}
}

// openMemDB opens a plain in-memory SQLite database.
func openMemDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite3", ":memory:")
	require.NoError(t, err)
	t.Cleanup(func() { db.Close() }) //nolint:errcheck,gosec
	return db
}

// makeSecretsTable creates the minimal secrets schema.
func makeSecretsTable(t *testing.T, db *sql.DB) {
	t.Helper()
	_, err := db.Exec(`
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
}

// makeKeysTable creates the minimal keys schema.
func makeKeysTable(t *testing.T, db *sql.DB) {
	t.Helper()
	_, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS keys (
			id                TEXT PRIMARY KEY,
			user_id           TEXT NOT NULL,
			vault_id          TEXT NOT NULL DEFAULT '00000000-0000-0000-0000-00000000efa1',
			name              TEXT NOT NULL,
			value             TEXT NOT NULL,
			type              TEXT NOT NULL,
			revoked           BOOLEAN NOT NULL DEFAULT FALSE,
			created_at        TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			deleted_at        TIMESTAMP NULL,
			purge_protection  BOOLEAN NOT NULL DEFAULT FALSE,
			scheduled_purge_at TIMESTAMP NULL,
			enabled           BOOLEAN NOT NULL DEFAULT TRUE,
			expires_at        TIMESTAMP NULL,
			not_before        TIMESTAMP NULL,
			bits              INTEGER NOT NULL DEFAULT 0,
			curve             TEXT NOT NULL DEFAULT '',
			updated_at        TIMESTAMP NULL
		);
		CREATE TABLE IF NOT EXISTS key_tags (
			key_id TEXT NOT NULL,
			tag    TEXT NOT NULL,
			PRIMARY KEY (key_id, tag)
		);
		CREATE TABLE IF NOT EXISTS key_versions (
			key_id     TEXT NOT NULL,
			version    INTEGER NOT NULL,
			value      TEXT NOT NULL,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			PRIMARY KEY (key_id, version)
		);
	`)
	require.NoError(t, err)
}

// makeCertsTable creates the minimal certificates schema.
func makeCertsTable(t *testing.T, db *sql.DB) {
	t.Helper()
	_, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS certificates (
			id               TEXT PRIMARY KEY,
			user_id          TEXT NOT NULL,
			vault_id         TEXT NOT NULL DEFAULT '00000000-0000-0000-0000-00000000efa1',
			name             TEXT NOT NULL,
			certificate      TEXT NOT NULL,
			private_key      TEXT NOT NULL,
			created_at       TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			deleted_at       TIMESTAMP NULL,
			purge_protection BOOLEAN NOT NULL DEFAULT FALSE,
			scheduled_purge_at TIMESTAMP NULL,
			expires_at       DATETIME,
			auto_renew       BOOLEAN NOT NULL DEFAULT FALSE,
			renewal_days     INTEGER NOT NULL DEFAULT 30,
			key_id           TEXT NOT NULL DEFAULT '',
			ca_cert_id       TEXT NULL,
			enabled          BOOLEAN NOT NULL DEFAULT TRUE,
			not_before       TIMESTAMP NULL
		);
		CREATE TABLE IF NOT EXISTS certificate_tags (
			certificate_id TEXT NOT NULL,
			tag            TEXT NOT NULL,
			PRIMARY KEY (certificate_id, tag)
		);
		CREATE TABLE IF NOT EXISTS crl (
			id            TEXT PRIMARY KEY,
			user_id       TEXT NOT NULL,
			serial_number TEXT NOT NULL,
			name          TEXT NOT NULL,
			revoked_at    TIMESTAMP NOT NULL
		);
	`)
	require.NoError(t, err)
}

// makeUsersTable creates the minimal users + bootstrap_tokens schema.
func makeUsersTable(t *testing.T, db *sql.DB) {
	t.Helper()
	_, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS users (
			id            TEXT PRIMARY KEY,
			username      TEXT UNIQUE NOT NULL,
			password_hash TEXT NOT NULL,
			totp_secret   TEXT NOT NULL DEFAULT '',
			role          TEXT NOT NULL,
			created_at    TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		);
		CREATE TABLE IF NOT EXISTS bootstrap_tokens (
			token TEXT PRIMARY KEY,
			used  BOOLEAN NOT NULL DEFAULT FALSE
		);
	`)
	require.NoError(t, err)
}

// newTestSecret returns a minimal secret for insertion.
func newTestSecret(userID uuid.UUID) *model.Secret {
	return &model.Secret{
		ID:          uuid.New(),
		UserID:      userID,
		VaultID:     uuid.MustParse("00000000-0000-0000-0000-000000000000"),
		Name:        "test-secret",
		Value:       "enc-value",
		Version:     1,
		ContentType: "text/plain",
		Enabled:     true,
		CreatedAt:   time.Now(),
	}
}

// newTestKey returns a minimal key for insertion.
func newTestKey(userID uuid.UUID) *model.Key {
	return &model.Key{
		ID:        uuid.New(),
		UserID:    userID,
		VaultID:   uuid.MustParse("00000000-0000-0000-0000-00000000efa1"),
		Name:      "test-key",
		Value:     "enc-value",
		Type:      "RSA",
		CreatedAt: time.Now(),
		Enabled:   true,
	}
}

// newTestCert returns a minimal certificate for insertion.
func newTestCert(userID uuid.UUID) *model.Certificate {
	return &model.Certificate{
		ID:          uuid.New(),
		UserID:      userID,
		VaultID:     uuid.MustParse("00000000-0000-0000-0000-00000000efa1"),
		Name:        "test-cert",
		Certificate: "PEM-DATA",
		PrivateKey:  "ENC-KEY",
		KeyID:       uuid.New(),
		CreatedAt:   time.Now(),
		Enabled:     true,
		RenewalDays: 30,
	}
}

// ---------------------------------------------------------------------------
// SecretRepository internal tests
// ---------------------------------------------------------------------------

// TestSecretRepo_Create_DBError drops the secrets table then calls Create to
// exercise the ExecContext error branch.
func TestSecretRepo_Create_DBError(t *testing.T) {
	db := openMemDB(t)
	makeSecretsTable(t, db)
	_, err := db.Exec("DROP TABLE secrets")
	require.NoError(t, err)

	repo := &SecretRepository{db: rvdb.NewConn(db, rvdb.SQLite), log: newInternalLogger()}
	s := newTestSecret(uuid.New())
	err = repo.Create(context.Background(), s)
	assert.Error(t, err)
}

// TestSecretRepo_Create_TagInsertError drops secret_tags after secrets insert to
// exercise the tag insertion error branch.
func TestSecretRepo_Create_TagInsertError(t *testing.T) {
	db := openMemDB(t)
	makeSecretsTable(t, db)
	_, err := db.Exec("DROP TABLE secret_tags")
	require.NoError(t, err)

	repo := &SecretRepository{db: rvdb.NewConn(db, rvdb.SQLite), log: newInternalLogger()}
	s := newTestSecret(uuid.New())
	s.Tags = []string{"env:prod"}
	err = repo.Create(context.Background(), s)
	assert.Error(t, err)
}

// TestSecretRepo_Update_DBError drops the table to force an update error.
func TestSecretRepo_Update_DBError(t *testing.T) {
	db := openMemDB(t)
	makeSecretsTable(t, db)
	_, err := db.Exec("DROP TABLE secrets")
	require.NoError(t, err)

	repo := &SecretRepository{db: rvdb.NewConn(db, rvdb.SQLite), log: newInternalLogger()}
	s := newTestSecret(uuid.New())
	err = repo.Update(context.Background(), s, model.NewAdminScope(uuid.Nil))
	assert.Error(t, err)
}

// TestSecretRepo_Delete_DBError drops the table to force a delete error.
func TestSecretRepo_Delete_DBError(t *testing.T) {
	db := openMemDB(t)
	makeSecretsTable(t, db)
	_, err := db.Exec("DROP TABLE secrets")
	require.NoError(t, err)

	repo := &SecretRepository{db: rvdb.NewConn(db, rvdb.SQLite), log: newInternalLogger()}
	err = repo.Delete(context.Background(), uuid.New())
	assert.Error(t, err)
}

// TestSecretRepo_SoftDelete_DBError drops the table to force a soft-delete error.
func TestSecretRepo_SoftDelete_DBError(t *testing.T) {
	db := openMemDB(t)
	makeSecretsTable(t, db)
	_, err := db.Exec("DROP TABLE secrets")
	require.NoError(t, err)

	repo := &SecretRepository{db: rvdb.NewConn(db, rvdb.SQLite), log: newInternalLogger()}
	err = repo.SoftDelete(context.Background(), uuid.New())
	assert.Error(t, err)
}

// TestSecretRepo_SoftDelete_NotFound exercises the rowsAffected==0 branch.
func TestSecretRepo_SoftDelete_NotFound(t *testing.T) {
	db := openMemDB(t)
	makeSecretsTable(t, db)

	repo := &SecretRepository{db: rvdb.NewConn(db, rvdb.SQLite), log: newInternalLogger()}
	err := repo.SoftDelete(context.Background(), uuid.New())
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

// TestSecretRepo_Read_DBError drops the table to force a query error.
func TestSecretRepo_Read_DBError(t *testing.T) {
	db := openMemDB(t)
	makeSecretsTable(t, db)
	_, err := db.Exec("DROP TABLE secrets")
	require.NoError(t, err)

	repo := &SecretRepository{db: rvdb.NewConn(db, rvdb.SQLite), log: newInternalLogger()}
	_, err = repo.Read(context.Background(), uuid.New(), model.NewAdminScope(uuid.Nil))
	assert.Error(t, err)
}

// TestSecretRepo_executeWithMetrics_SlowQuery exercises the slow-query log path.
// We use a real operation that takes more than 100 ms by temporarily sleeping via
// a closure calling the helper directly — instead we verify it returns the inner error.
func TestSecretRepo_executeWithMetrics_Passthrough(t *testing.T) {
	db := openMemDB(t)
	repo := &SecretRepository{db: rvdb.NewConn(db, rvdb.SQLite), log: newInternalLogger()}
	sentinel := assert.AnError
	err := repo.executeWithMetrics("test-op", func() error { return sentinel })
	assert.ErrorIs(t, err, sentinel)
}

// ---------------------------------------------------------------------------
// KeyRepository internal tests
// ---------------------------------------------------------------------------

// TestKeyRepo_Create_DBError drops the keys table to force a create error.
func TestKeyRepo_Create_DBError(t *testing.T) {
	db := openMemDB(t)
	makeKeysTable(t, db)
	_, err := db.Exec("DROP TABLE keys")
	require.NoError(t, err)

	repo := &KeyRepository{db: rvdb.NewConn(db, rvdb.SQLite), log: newInternalLogger()}
	k := newTestKey(uuid.New())
	err = repo.Create(context.Background(), k)
	assert.Error(t, err)
}

// TestKeyRepo_Create_TagInsertError inserts a key then drops key_tags to trigger
// the tag-insertion error branch inside Create.
func TestKeyRepo_Create_TagInsertError(t *testing.T) {
	db := openMemDB(t)
	makeKeysTable(t, db)
	// Rename key_tags to break the INSERT but leave the keys table intact.
	_, err := db.Exec("DROP TABLE key_tags")
	require.NoError(t, err)

	repo := &KeyRepository{db: rvdb.NewConn(db, rvdb.SQLite), log: newInternalLogger()}
	k := newTestKey(uuid.New())
	k.Tags = []string{"env:prod"}
	err = repo.Create(context.Background(), k)
	assert.Error(t, err)
}

// TestKeyRepo_Read_DBError forces a query error.
func TestKeyRepo_Read_DBError(t *testing.T) {
	db := openMemDB(t)
	makeKeysTable(t, db)
	_, err := db.Exec("DROP TABLE keys")
	require.NoError(t, err)

	repo := &KeyRepository{db: rvdb.NewConn(db, rvdb.SQLite), log: newInternalLogger()}
	_, err = repo.Read(context.Background(), uuid.New(), model.NewAdminScope(uuid.Nil))
	assert.Error(t, err)
}

// TestKeyRepo_Delete_DBError forces a delete error by dropping the table.
func TestKeyRepo_Delete_DBError(t *testing.T) {
	db := openMemDB(t)
	makeKeysTable(t, db)
	_, err := db.Exec("DROP TABLE keys")
	require.NoError(t, err)

	repo := &KeyRepository{db: rvdb.NewConn(db, rvdb.SQLite), log: newInternalLogger()}
	err = repo.Delete(context.Background(), uuid.New())
	assert.Error(t, err)
}

// TestKeyRepo_Delete_NotFound exercises the rowsAffected==0 path.
func TestKeyRepo_Delete_NotFound(t *testing.T) {
	db := openMemDB(t)
	makeKeysTable(t, db)

	repo := &KeyRepository{db: rvdb.NewConn(db, rvdb.SQLite), log: newInternalLogger()}
	err := repo.Delete(context.Background(), uuid.New())
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

// TestKeyRepo_executeWithMetrics_Passthrough verifies the helper returns inner error.
func TestKeyRepo_executeWithMetrics_Passthrough(t *testing.T) {
	db := openMemDB(t)
	repo := &KeyRepository{db: rvdb.NewConn(db, rvdb.SQLite), log: newInternalLogger()}
	sentinel := assert.AnError
	err := repo.executeWithMetrics("test-op", func() error { return sentinel })
	assert.ErrorIs(t, err, sentinel)
}

// ---------------------------------------------------------------------------
// CertificateRepository internal tests
// ---------------------------------------------------------------------------

// TestCertRepo_Create_DBError drops the table to force a create error.
func TestCertRepo_Create_DBError(t *testing.T) {
	db := openMemDB(t)
	makeCertsTable(t, db)
	_, err := db.Exec("DROP TABLE certificates")
	require.NoError(t, err)

	repo := &CertificateRepository{db: rvdb.NewConn(db, rvdb.SQLite), log: newInternalLogger()}
	c := newTestCert(uuid.New())
	err = repo.Create(context.Background(), c)
	assert.Error(t, err)
}

// TestCertRepo_Create_TagInsertError inserts a cert then drops certificate_tags to
// trigger the tag-insertion error path in Create.
func TestCertRepo_Create_TagInsertError(t *testing.T) {
	db := openMemDB(t)
	makeCertsTable(t, db)
	_, err := db.Exec("DROP TABLE certificate_tags")
	require.NoError(t, err)

	repo := &CertificateRepository{db: rvdb.NewConn(db, rvdb.SQLite), log: newInternalLogger()}
	c := newTestCert(uuid.New())
	c.Tags = []string{"env:prod"}
	err = repo.Create(context.Background(), c)
	assert.Error(t, err)
}

// TestCertRepo_Update_NotFound exercises the rowsAffected==0 branch in Update.
func TestCertRepo_Update_NotFound(t *testing.T) {
	db := openMemDB(t)
	makeCertsTable(t, db)

	repo := &CertificateRepository{db: rvdb.NewConn(db, rvdb.SQLite), log: newInternalLogger()}
	c := newTestCert(uuid.New())
	err := repo.Update(context.Background(), c, model.NewAdminScope(uuid.Nil))
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

// TestCertRepo_Update_DBError drops the table to force an update error.
func TestCertRepo_Update_DBError(t *testing.T) {
	db := openMemDB(t)
	makeCertsTable(t, db)
	_, err := db.Exec("DROP TABLE certificates")
	require.NoError(t, err)

	repo := &CertificateRepository{db: rvdb.NewConn(db, rvdb.SQLite), log: newInternalLogger()}
	c := newTestCert(uuid.New())
	err = repo.Update(context.Background(), c, model.NewAdminScope(uuid.Nil))
	assert.Error(t, err)
}

// TestCertRepo_Delete_NotFound exercises the rowsAffected==0 path in Delete.
func TestCertRepo_Delete_NotFound(t *testing.T) {
	db := openMemDB(t)
	makeCertsTable(t, db)

	repo := &CertificateRepository{db: rvdb.NewConn(db, rvdb.SQLite), log: newInternalLogger()}
	err := repo.Delete(context.Background(), uuid.New())
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

// TestCertRepo_Delete_DBError drops the table to force a delete error.
func TestCertRepo_Delete_DBError(t *testing.T) {
	db := openMemDB(t)
	makeCertsTable(t, db)
	_, err := db.Exec("DROP TABLE certificates")
	require.NoError(t, err)

	repo := &CertificateRepository{db: rvdb.NewConn(db, rvdb.SQLite), log: newInternalLogger()}
	err = repo.Delete(context.Background(), uuid.New())
	assert.Error(t, err)
}

// TestCertRepo_executeWithMetrics_Passthrough verifies error passthrough.
func TestCertRepo_executeWithMetrics_Passthrough(t *testing.T) {
	db := openMemDB(t)
	repo := &CertificateRepository{db: rvdb.NewConn(db, rvdb.SQLite), log: newInternalLogger()}
	sentinel := assert.AnError
	err := repo.executeWithMetrics("test-op", func() error { return sentinel })
	assert.ErrorIs(t, err, sentinel)
}

// ---------------------------------------------------------------------------
// UserRepository internal tests
// ---------------------------------------------------------------------------

// TestUserRepo_Delete_DBError drops the users table to force a transaction error.
func TestUserRepo_Delete_DBError(t *testing.T) {
	db := openMemDB(t)
	makeUsersTable(t, db)
	_, err := db.Exec("DROP TABLE users")
	require.NoError(t, err)

	repo := &UserRepository{db: rvdb.NewConn(db, rvdb.SQLite), log: newInternalLogger()}
	err = repo.Delete(context.Background(), uuid.New())
	assert.Error(t, err)
}

// TestUserRepo_ReadByUsername_DBError drops the table to force a query error.
func TestUserRepo_ReadByUsername_DBError(t *testing.T) {
	db := openMemDB(t)
	makeUsersTable(t, db)
	_, err := db.Exec("DROP TABLE users")
	require.NoError(t, err)

	repo := &UserRepository{db: rvdb.NewConn(db, rvdb.SQLite), log: newInternalLogger()}
	_, err = repo.ReadByUsername(context.Background(), "nonexistent")
	assert.Error(t, err)
}

// TestUserRepo_List_DBError drops the table to trigger the query error in List.
func TestUserRepo_List_DBError(t *testing.T) {
	db := openMemDB(t)
	makeUsersTable(t, db)
	_, err := db.Exec("DROP TABLE users")
	require.NoError(t, err)

	repo := &UserRepository{db: rvdb.NewConn(db, rvdb.SQLite), log: newInternalLogger()}
	_, err = repo.List(context.Background())
	assert.Error(t, err)
}

// TestUserRepo_InvalidateBootstrapToken_InsertPath exercises the branch where no
// existing row is found, causing an INSERT of the token as used.
func TestUserRepo_InvalidateBootstrapToken_InsertPath(t *testing.T) {
	db := openMemDB(t)
	makeUsersTable(t, db)

	repo := &UserRepository{db: rvdb.NewConn(db, rvdb.SQLite), log: newInternalLogger()}
	// Token does not exist yet; should INSERT it as used.
	err := repo.InvalidateBootstrapToken(context.Background(), "new-token-xyz")
	assert.NoError(t, err)

	// Verify it was stored as used.
	var used bool
	row := db.QueryRow("SELECT used FROM bootstrap_tokens WHERE token = ?", "new-token-xyz")
	require.NoError(t, row.Scan(&used))
	assert.True(t, used)
}

// TestUserRepo_InvalidateBootstrapToken_UpdateError drops the table to force the
// UPDATE error branch in InvalidateBootstrapToken.
func TestUserRepo_InvalidateBootstrapToken_UpdateError(t *testing.T) {
	db := openMemDB(t)
	makeUsersTable(t, db)
	_, err := db.Exec("DROP TABLE bootstrap_tokens")
	require.NoError(t, err)

	repo := &UserRepository{db: rvdb.NewConn(db, rvdb.SQLite), log: newInternalLogger()}
	err = repo.InvalidateBootstrapToken(context.Background(), "token")
	assert.Error(t, err)
}

// TestUserRepo_executeWithMetrics_Passthrough verifies error passthrough.
func TestUserRepo_executeWithMetrics_Passthrough(t *testing.T) {
	db := openMemDB(t)
	repo := &UserRepository{db: rvdb.NewConn(db, rvdb.SQLite), log: newInternalLogger()}
	sentinel := assert.AnError
	err := repo.executeWithMetrics("test-op", func() error { return sentinel })
	assert.ErrorIs(t, err, sentinel)
}

// ---------------------------------------------------------------------------
// SessionRepository internal tests
// ---------------------------------------------------------------------------

// makeSessionTable creates the user_sessions table.
func makeSessionTable(t *testing.T, db *sql.DB) {
	t.Helper()
	_, err := db.Exec(`
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
}

// TestSessionRepo_CreateSession_DBError drops the table to force an insert error.
func TestSessionRepo_CreateSession_DBError(t *testing.T) {
	db := openMemDB(t)
	makeSessionTable(t, db)
	_, err := db.Exec("DROP TABLE user_sessions")
	require.NoError(t, err)

	repo := &SessionRepository{db: rvdb.NewConn(db, rvdb.SQLite), logger: newInternalLogger()}
	s := &model.Session{
		ID:               uuid.New(),
		UserID:           uuid.New(),
		RefreshTokenHash: "hash",
		ExpiresAt:        time.Now().Add(time.Hour),
		LastUsedAt:       time.Now(),
		CreatedAt:        time.Now(),
	}
	err = repo.CreateSession(context.Background(), s)
	assert.Error(t, err)
}

// TestSessionRepo_GetActiveSessionsByUserID_DBError drops the table to trigger a
// query error.
func TestSessionRepo_GetActiveSessionsByUserID_DBError(t *testing.T) {
	db := openMemDB(t)
	makeSessionTable(t, db)
	_, err := db.Exec("DROP TABLE user_sessions")
	require.NoError(t, err)

	repo := &SessionRepository{db: rvdb.NewConn(db, rvdb.SQLite), logger: newInternalLogger()}
	_, err = repo.GetActiveSessionsByUserID(context.Background(), uuid.New())
	assert.Error(t, err)
}

// TestSessionRepo_CountActiveSessions_DBError drops the table to trigger error.
func TestSessionRepo_CountActiveSessions_DBError(t *testing.T) {
	db := openMemDB(t)
	makeSessionTable(t, db)
	_, err := db.Exec("DROP TABLE user_sessions")
	require.NoError(t, err)

	repo := &SessionRepository{db: rvdb.NewConn(db, rvdb.SQLite), logger: newInternalLogger()}
	_, err = repo.CountActiveSessions(context.Background(), uuid.New())
	assert.Error(t, err)
}

// TestSessionRepo_executeWithMetrics_Passthrough verifies error passthrough.
func TestSessionRepo_executeWithMetrics_Passthrough(t *testing.T) {
	db := openMemDB(t)
	repo := &SessionRepository{db: rvdb.NewConn(db, rvdb.SQLite), logger: newInternalLogger()}
	sentinel := assert.AnError
	err := repo.executeWithMetrics("test-op", func() error { return sentinel })
	assert.ErrorIs(t, err, sentinel)
}

// ---------------------------------------------------------------------------
// RotationPolicyRepository internal tests
// ---------------------------------------------------------------------------

// makeRotationTables creates the rotation-related tables.
func makeRotationTables(t *testing.T, db *sql.DB) {
	t.Helper()
	_, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS rotation_policies (
			id              TEXT PRIMARY KEY,
			user_id         TEXT NOT NULL,
			name            TEXT NOT NULL,
			description     TEXT,
			interval_days   INTEGER NOT NULL,
			enabled         BOOLEAN NOT NULL DEFAULT TRUE,
			reminder_days   INTEGER NOT NULL DEFAULT 7,
			auto_rotate     BOOLEAN NOT NULL DEFAULT FALSE,
			created_at      TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			updated_at      TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		);
		CREATE TABLE IF NOT EXISTS secret_policies (
			secret_id       TEXT NOT NULL,
			policy_id       TEXT NOT NULL,
			assigned_at     TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			last_rotated_at TIMESTAMP,
			next_rotation_at TIMESTAMP,
			PRIMARY KEY (secret_id, policy_id)
		);
		CREATE TABLE IF NOT EXISTS secret_rotation_history (
			id              TEXT PRIMARY KEY,
			secret_id       TEXT NOT NULL,
			policy_id       TEXT,
			rotated_at      TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			previous_version INTEGER,
			new_version     INTEGER,
			triggered_by    TEXT NOT NULL,
			notes           TEXT
		);
		CREATE TABLE IF NOT EXISTS rotation_reminders (
			id              TEXT PRIMARY KEY,
			secret_id       TEXT NOT NULL,
			policy_id       TEXT NOT NULL,
			reminder_type   TEXT NOT NULL,
			scheduled_at    TIMESTAMP NOT NULL,
			sent_at         TIMESTAMP,
			status          TEXT NOT NULL DEFAULT 'pending',
			created_at      TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		);
	`)
	require.NoError(t, err)
}

// TestRotationRepo_Create_DBError drops rotation_policies to force an insert error.
func TestRotationRepo_Create_DBError(t *testing.T) {
	db := openMemDB(t)
	makeRotationTables(t, db)
	_, err := db.Exec("DROP TABLE rotation_policies")
	require.NoError(t, err)

	repo := &rotationPolicyRepository{db: rvdb.NewConn(db, rvdb.SQLite), log: newInternalLogger()}
	policy := &model.RotationPolicy{
		ID:           uuid.New(),
		UserID:       uuid.New(),
		Name:         "test-policy",
		IntervalDays: 30,
		Enabled:      true,
		ReminderDays: 7,
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	}
	err = repo.Create(context.Background(), policy)
	assert.Error(t, err)
}

// TestRotationRepo_AssignToSecret_DBError drops secret_policies to force an
// insert error.
func TestRotationRepo_AssignToSecret_DBError(t *testing.T) {
	db := openMemDB(t)
	makeRotationTables(t, db)
	_, err := db.Exec("DROP TABLE secret_policies")
	require.NoError(t, err)

	repo := &rotationPolicyRepository{db: rvdb.NewConn(db, rvdb.SQLite), log: newInternalLogger()}
	err = repo.AssignToSecret(context.Background(), uuid.New(), uuid.New(), time.Now(), time.Now().Add(24*time.Hour))
	assert.Error(t, err)
}

// TestRotationRepo_Read_DBError drops the table to force a query error.
func TestRotationRepo_Read_DBError(t *testing.T) {
	db := openMemDB(t)
	makeRotationTables(t, db)
	_, err := db.Exec("DROP TABLE rotation_policies")
	require.NoError(t, err)

	repo := &rotationPolicyRepository{db: rvdb.NewConn(db, rvdb.SQLite), log: newInternalLogger()}
	_, err = repo.Read(context.Background(), uuid.New(), model.NewAdminScope(uuid.New()))
	assert.Error(t, err)
}

// ---------------------------------------------------------------------------
// SecretVersionRepository internal tests
// ---------------------------------------------------------------------------

// makeVersionsTable creates the secret_versions table.
func makeVersionsTable(t *testing.T, db *sql.DB) {
	t.Helper()
	_, err := db.Exec(`
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
}

// TestVersionRepo_CreateVersion_DBError drops the table to force an insert error.
func TestVersionRepo_CreateVersion_DBError(t *testing.T) {
	db := openMemDB(t)
	makeVersionsTable(t, db)
	_, err := db.Exec("DROP TABLE secret_versions")
	require.NoError(t, err)

	repo := &secretVersionRepository{db: rvdb.NewConn(db, rvdb.SQLite), log: newInternalLogger()}
	v := &model.SecretVersion{
		ID:        uuid.New(),
		SecretID:  uuid.New(),
		UserID:    uuid.New(),
		Name:      "test",
		Value:     "enc-val",
		Version:   1,
		CreatedAt: time.Now(),
	}
	err = repo.CreateVersion(context.Background(), v)
	assert.Error(t, err)
}

// TestVersionRepo_GetVersion_DBError drops the table to force a query error.
func TestVersionRepo_GetVersion_DBError(t *testing.T) {
	db := openMemDB(t)
	makeVersionsTable(t, db)
	_, err := db.Exec("DROP TABLE secret_versions")
	require.NoError(t, err)

	repo := &secretVersionRepository{db: rvdb.NewConn(db, rvdb.SQLite), log: newInternalLogger()}
	_, err = repo.GetVersion(context.Background(), uuid.New(), 1)
	assert.Error(t, err)
}

// TestVersionRepo_GetLatestVersion_DBError drops the table to force a query error.
func TestVersionRepo_GetLatestVersion_DBError(t *testing.T) {
	db := openMemDB(t)
	makeVersionsTable(t, db)
	_, err := db.Exec("DROP TABLE secret_versions")
	require.NoError(t, err)

	repo := &secretVersionRepository{db: rvdb.NewConn(db, rvdb.SQLite), log: newInternalLogger()}
	_, err = repo.GetLatestVersion(context.Background(), uuid.New())
	assert.Error(t, err)
}

// ---------------------------------------------------------------------------
// Additional KeyRepository DB-error branch tests
// ---------------------------------------------------------------------------

// TestKeyRepo_UpdateRevocationStatus_DBError drops the table to force an error.
func TestKeyRepo_UpdateRevocationStatus_DBError(t *testing.T) {
	db := openMemDB(t)
	makeKeysTable(t, db)
	_, err := db.Exec("DROP TABLE keys")
	require.NoError(t, err)

	repo := &KeyRepository{db: rvdb.NewConn(db, rvdb.SQLite), log: newInternalLogger()}
	err = repo.UpdateRevocationStatus(context.Background(), uuid.New(), true)
	assert.Error(t, err)
}

// TestKeyRepo_SetPurgeProtection_DBError drops the table to force an error.
func TestKeyRepo_SetPurgeProtection_DBError(t *testing.T) {
	db := openMemDB(t)
	makeKeysTable(t, db)
	_, err := db.Exec("DROP TABLE keys")
	require.NoError(t, err)

	repo := &KeyRepository{db: rvdb.NewConn(db, rvdb.SQLite), log: newInternalLogger()}
	err = repo.SetPurgeProtection(context.Background(), uuid.New(), true)
	assert.Error(t, err)
}

// TestKeyRepo_SetPurgeProtection_NotFound exercises the rowsAffected==0 path.
func TestKeyRepo_SetPurgeProtection_NotFound(t *testing.T) {
	db := openMemDB(t)
	makeKeysTable(t, db)

	repo := &KeyRepository{db: rvdb.NewConn(db, rvdb.SQLite), log: newInternalLogger()}
	err := repo.SetPurgeProtection(context.Background(), uuid.New(), true)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

// TestKeyRepo_ReadInVault_DBError drops the table to force a query error.
func TestKeyRepo_ReadInVault_DBError(t *testing.T) {
	db := openMemDB(t)
	makeKeysTable(t, db)
	_, err := db.Exec("DROP TABLE keys")
	require.NoError(t, err)

	repo := &KeyRepository{db: rvdb.NewConn(db, rvdb.SQLite), log: newInternalLogger()}
	_, err = repo.Read(context.Background(), uuid.New(), model.NewVaultScope(uuid.New(), uuid.Nil))
	assert.Error(t, err)
}

// TestKeyRepo_ReadDeletedScoped_DBError drops the table to force a query error.
func TestKeyRepo_ReadDeletedScoped_DBError(t *testing.T) {
	db := openMemDB(t)
	makeKeysTable(t, db)
	_, err := db.Exec("DROP TABLE keys")
	require.NoError(t, err)

	repo := &KeyRepository{db: rvdb.NewConn(db, rvdb.SQLite), log: newInternalLogger()}
	_, err = repo.ReadDeletedScoped(context.Background(), uuid.New(), model.NewAdminScope(uuid.Nil))
	assert.Error(t, err)
}

// TestKeyRepo_Delete_TagsError drops key_tags to trigger the tag-deletion error
// inside Delete (after BeginTx succeeds).
func TestKeyRepo_Delete_TagsDBError(t *testing.T) {
	db := openMemDB(t)
	makeKeysTable(t, db)
	_, err := db.Exec("DROP TABLE key_tags")
	require.NoError(t, err)

	repo := &KeyRepository{db: rvdb.NewConn(db, rvdb.SQLite), log: newInternalLogger()}
	// key_tags is gone but keys still exists — DELETE FROM key_tags will fail.
	err = repo.Delete(context.Background(), uuid.New())
	assert.Error(t, err)
}

// ---------------------------------------------------------------------------
// Additional CertificateRepository DB-error branch tests
// ---------------------------------------------------------------------------

// TestCertRepo_SetPurgeProtection_DBError drops the table to force an error.
func TestCertRepo_SetPurgeProtection_DBError(t *testing.T) {
	db := openMemDB(t)
	makeCertsTable(t, db)
	_, err := db.Exec("DROP TABLE certificates")
	require.NoError(t, err)

	repo := &CertificateRepository{db: rvdb.NewConn(db, rvdb.SQLite), log: newInternalLogger()}
	err = repo.SetPurgeProtection(context.Background(), uuid.New(), true)
	assert.Error(t, err)
}

// TestCertRepo_SetPurgeProtection_NotFound exercises the rowsAffected==0 path.
func TestCertRepo_SetPurgeProtection_NotFound(t *testing.T) {
	db := openMemDB(t)
	makeCertsTable(t, db)

	repo := &CertificateRepository{db: rvdb.NewConn(db, rvdb.SQLite), log: newInternalLogger()}
	err := repo.SetPurgeProtection(context.Background(), uuid.New(), true)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

// TestCertRepo_ListRevoked_DBError drops the crl table to force a query error.
func TestCertRepo_ListRevoked_DBError(t *testing.T) {
	db := openMemDB(t)
	makeCertsTable(t, db)
	_, err := db.Exec("DROP TABLE crl")
	require.NoError(t, err)

	repo := &CertificateRepository{db: rvdb.NewConn(db, rvdb.SQLite), log: newInternalLogger()}
	_, err = repo.ListRevoked(context.Background(), uuid.New())
	assert.Error(t, err)
}

// TestCertRepo_ListByUser_DBError drops the table to force a query error.
func TestCertRepo_ListByUser_DBError(t *testing.T) {
	db := openMemDB(t)
	makeCertsTable(t, db)
	_, err := db.Exec("DROP TABLE certificates")
	require.NoError(t, err)

	repo := &CertificateRepository{db: rvdb.NewConn(db, rvdb.SQLite), log: newInternalLogger()}
	_, err = repo.List(context.Background(), model.NewOwnerScope(uuid.Nil, uuid.New()), CertificateFilter{})
	assert.Error(t, err)
}

// TestCertRepo_ListInVault_DBError drops the table to force a query error.
func TestCertRepo_ListInVault_DBError(t *testing.T) {
	db := openMemDB(t)
	makeCertsTable(t, db)
	_, err := db.Exec("DROP TABLE certificates")
	require.NoError(t, err)

	repo := &CertificateRepository{db: rvdb.NewConn(db, rvdb.SQLite), log: newInternalLogger()}
	_, err = repo.List(context.Background(), model.NewVaultScope(uuid.New(), uuid.Nil), CertificateFilter{})
	assert.Error(t, err)
}

// TestCertRepo_Delete_TagsDBError drops certificate_tags to trigger the tag-deletion
// error inside Delete (main certificates table still present).
func TestCertRepo_Delete_TagsDBError(t *testing.T) {
	db := openMemDB(t)
	makeCertsTable(t, db)
	_, err := db.Exec("DROP TABLE certificate_tags")
	require.NoError(t, err)

	repo := &CertificateRepository{db: rvdb.NewConn(db, rvdb.SQLite), log: newInternalLogger()}
	err = repo.Delete(context.Background(), uuid.New())
	assert.Error(t, err)
}

// ---------------------------------------------------------------------------
// Additional SecretRepository DB-error branch tests
// ---------------------------------------------------------------------------

// TestSecretRepo_List_OwnerScope_DBError drops the table to force a query error.
func TestSecretRepo_List_OwnerScope_DBError(t *testing.T) {
	db := openMemDB(t)
	makeSecretsTable(t, db)
	_, err := db.Exec("DROP TABLE secrets")
	require.NoError(t, err)

	repo := &SecretRepository{db: rvdb.NewConn(db, rvdb.SQLite), log: newInternalLogger()}
	_, err = repo.List(context.Background(), model.NewOwnerScope(uuid.Nil, uuid.New()), SecretFilter{})
	assert.Error(t, err)
}

// TestSecretRepo_List_VaultScope_DBError drops the table to force a query error.
func TestSecretRepo_List_VaultScope_DBError(t *testing.T) {
	db := openMemDB(t)
	makeSecretsTable(t, db)
	_, err := db.Exec("DROP TABLE secrets")
	require.NoError(t, err)

	repo := &SecretRepository{db: rvdb.NewConn(db, rvdb.SQLite), log: newInternalLogger()}
	_, err = repo.List(context.Background(), model.NewVaultScope(uuid.New(), uuid.Nil), SecretFilter{})
	assert.Error(t, err)
}

// TestSecretRepo_SoftDeleteVaultContents_DBError drops table to force an error.
func TestSecretRepo_SoftDeleteVaultContents_DBError(t *testing.T) {
	db := openMemDB(t)
	makeSecretsTable(t, db)
	_, err := db.Exec("DROP TABLE secrets")
	require.NoError(t, err)

	repo := &SecretRepository{db: rvdb.NewConn(db, rvdb.SQLite), log: newInternalLogger()}
	err = repo.SoftDeleteVaultContents(context.Background(), uuid.New(), time.Now())
	assert.Error(t, err)
}

// TestSecretRepo_RecoverVaultContents_DBError drops table to force an error.
func TestSecretRepo_RecoverVaultContents_DBError(t *testing.T) {
	db := openMemDB(t)
	makeSecretsTable(t, db)
	_, err := db.Exec("DROP TABLE secrets")
	require.NoError(t, err)

	repo := &SecretRepository{db: rvdb.NewConn(db, rvdb.SQLite), log: newInternalLogger()}
	err = repo.RecoverVaultContents(context.Background(), uuid.New(), time.Now())
	assert.Error(t, err)
}
