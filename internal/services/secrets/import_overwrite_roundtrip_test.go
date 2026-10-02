/*
Copyright © 2025 Snehal Dangroshiya

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
*/

package secrets_test

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"

	"github.com/google/uuid"
	_ "github.com/mattn/go-sqlite3"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	rvdb "rocketvault/internal/db"
	"rocketvault/internal/logging"
	"rocketvault/internal/repositories"
	"rocketvault/internal/services/secrets"
	"rocketvault/internal/testutils"
	"rocketvault/model"
)

// importFixtureSchema mirrors rotationFixtureSchema for only the tables
// import touches. Unlike rotationFixtureSchema, it includes
// idx_secrets_vault_name: the unique index that decides whether FindByName
// sees an existing row, so a schema without it would not exercise the real
// create-vs-overwrite branch this test proves. It carries the same
// WHERE deleted_at IS NULL predicate finalizeVaultIndexes builds in
// production (B50), so the fixture cannot drift from the real constraint.
const importFixtureSchema = `
	CREATE TABLE users (
		id TEXT PRIMARY KEY,
		username TEXT UNIQUE NOT NULL,
		password_hash TEXT NOT NULL,
		totp_secret TEXT,
		role TEXT NOT NULL,
		auth_provider TEXT NOT NULL DEFAULT 'local',
		external_idp_subject TEXT,
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
	);
	CREATE TABLE user_roles (
		id         TEXT PRIMARY KEY,
		user_id    TEXT NOT NULL,
		role       TEXT NOT NULL,
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		UNIQUE (user_id, role),
		FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
	);
	CREATE TABLE secrets (
		id TEXT PRIMARY KEY,
		user_id TEXT NOT NULL,
		name TEXT NOT NULL,
		vault_id TEXT NOT NULL,
		value TEXT NOT NULL,
		version INTEGER NOT NULL,
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		deleted_at TIMESTAMP NULL,
		purge_protection BOOLEAN NOT NULL DEFAULT FALSE,
		content_type TEXT NOT NULL DEFAULT '',
		enabled BOOLEAN NOT NULL DEFAULT TRUE,
		expires_at TIMESTAMP NULL,
		not_before TIMESTAMP NULL
	);
	CREATE UNIQUE INDEX idx_secrets_vault_name ON secrets(vault_id, name) WHERE deleted_at IS NULL;
	CREATE TABLE secret_tags (
		secret_id TEXT NOT NULL,
		tag TEXT NOT NULL,
		PRIMARY KEY (secret_id, tag)
	);
	CREATE TABLE secret_versions (
		id TEXT PRIMARY KEY,
		secret_id TEXT NOT NULL,
		user_id TEXT NOT NULL,
		name TEXT NOT NULL,
		value TEXT NOT NULL,
		version INTEGER NOT NULL,
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
	);
`

// importFixture wires the real secret repository, the real cryptography
// service, and a real database -- mocked crypto cannot prove a round trip,
// and B38 shipped in the first place because nothing ever round-tripped
// --overwrite against real behavior.
type importFixture struct {
	secretSvc   secrets.SecretService
	secretRepo  repositories.SecretRepositoryInterface
	versionRepo repositories.SecretVersionRepositoryInterface
	tagSvc      secrets.TagService
	crypto      secrets.CryptographyService
	versionSvc  secrets.VersioningServiceInterface
	log         *logging.Logger
	userID      uuid.UUID
	vaultID     uuid.UUID
}

func (f *importFixture) scope() model.Scope {
	return model.NewVaultScope(f.vaultID, f.userID)
}

// newImportFixture seeds one owner and no secrets; each test imports its own.
func newImportFixture(t *testing.T) *importFixture {
	t.Helper()

	// The cryptography service reads master_key from the global viper
	// singleton, so these tests must not run in parallel.
	key := make([]byte, 32)
	_, err := rand.Read(key)
	require.NoError(t, err)
	previousKey := viper.GetString("master_key")
	viper.Set("master_key", base64.StdEncoding.EncodeToString(key))
	t.Cleanup(func() { viper.Set("master_key", previousKey) })

	conn, err := sql.Open("sqlite3", ":memory:")
	require.NoError(t, err)
	t.Cleanup(func() { conn.Close() }) //nolint:errcheck,gosec

	_, err = conn.Exec(importFixtureSchema)
	require.NoError(t, err)

	log := testutils.NewTestLogger(t)
	dbConn := rvdb.NewConn(conn, rvdb.SQLite)

	secretRepo := repositories.NewSecretRepository(dbConn, log)
	versionRepo := repositories.NewSecretVersionRepository(dbConn, log)
	userRepo := repositories.NewUserRepository(dbConn, log)
	tagRepo := repositories.NewSecretTagRepository(dbConn)

	crypto := secrets.NewCryptographyService()
	versioningSvc := secrets.NewVersioningService(versionRepo, secretRepo, userRepo, crypto, log, nil)
	tagSvc := secrets.NewTagService(tagRepo, log)
	secretSvc := secrets.NewSecretService(secrets.SecretServiceConfig{
		SecretRepository: secretRepo,
		CryptoService:    crypto,
		VersionService:   versioningSvc,
		TagService:       tagSvc,
		Logger:           log,
	})

	f := &importFixture{
		secretSvc:   secretSvc,
		secretRepo:  secretRepo,
		versionRepo: versionRepo,
		tagSvc:      tagSvc,
		crypto:      crypto,
		versionSvc:  versioningSvc,
		log:         log,
		userID:      uuid.New(),
		vaultID:     uuid.New(),
	}

	now := time.Now()
	_, err = conn.Exec(
		`INSERT INTO users (id, username, password_hash, totp_secret, role, auth_provider, created_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?)`,
		f.userID.String(), "alice", "hash", "", model.RoleUser, "local", now,
	)
	require.NoError(t, err)

	return f
}

// importRecord mirrors the unexported importSecret type ImportSecrets
// decodes JSON records into.
type importRecord struct {
	Name  string   `json:"name"`
	Value string   `json:"value"`
	Tags  []string `json:"tags,omitempty"`
}

func marshalRecords(t *testing.T, records ...importRecord) []byte {
	t.Helper()
	data, err := json.Marshal(records)
	require.NoError(t, err)
	return data
}

// TestImportSecrets_OverwriteRoundTrip is the test whose absence let B38
// ship: nothing ever imported a secret, overwrote it, and read the result
// back through real crypto and a real unique-index-backed lookup.
func TestImportSecrets_OverwriteRoundTrip(t *testing.T) {
	ctx := context.Background()
	f := newImportFixture(t)

	// 1. First import: the name does not exist yet, so it is created at
	// version 1.
	result, err := f.secretSvc.ImportSecrets(ctx, secrets.ImportSecretsRequest{
		Scope:  f.scope(),
		Format: "json",
		Data:   marshalRecords(t, importRecord{Name: "db-password", Value: "v1", Tags: []string{"initial"}}),
	})
	require.NoError(t, err)
	assert.Equal(t, 1, result.ImportedCount)
	assert.Equal(t, 0, result.SkippedCount)
	assert.Equal(t, 0, result.FailedCount)

	existing, err := f.secretRepo.FindByName(ctx, "db-password", f.scope())
	require.NoError(t, err)
	assert.Equal(t, 1, existing.Version)
	plaintext, err := f.crypto.DecryptSecret(existing.Value)
	require.NoError(t, err)
	assert.Equal(t, "v1", plaintext)

	// 2. Second import, same name, Overwrite: true, a new value and new
	// tags: the existing row must be versioned and updated, not duplicated.
	result, err = f.secretSvc.ImportSecrets(ctx, secrets.ImportSecretsRequest{
		Scope:     f.scope(),
		Format:    "json",
		Overwrite: true,
		Data:      marshalRecords(t, importRecord{Name: "db-password", Value: "v2", Tags: []string{"prod", "db"}}),
	})
	require.NoError(t, err)
	assert.Equal(t, 1, result.ImportedCount)
	assert.Equal(t, 0, result.SkippedCount)
	assert.Equal(t, 0, result.FailedCount)

	overwritten, err := f.secretRepo.FindByName(ctx, "db-password", f.scope())
	require.NoError(t, err)
	assert.Equal(t, existing.ID, overwritten.ID, "overwrite must update the same row, not insert a new one")
	assert.Equal(t, 2, overwritten.Version)
	newPlaintext, err := f.crypto.DecryptSecret(overwritten.Value)
	require.NoError(t, err)
	assert.Equal(t, "v2", newPlaintext)

	versions, err := f.versionRepo.GetVersions(ctx, overwritten.ID)
	require.NoError(t, err)
	require.Len(t, versions, 1, "overwrite must archive exactly one version row")
	assert.Equal(t, 1, versions[0].Version)
	archived, err := f.crypto.DecryptSecret(versions[0].Value)
	require.NoError(t, err, "the archived version must be singly encrypted, not double-encrypted")
	assert.Equal(t, "v1", archived)

	tags, err := f.tagSvc.GetTags(ctx, overwritten.ID)
	require.NoError(t, err)
	assert.ElementsMatch(t, []string{"prod", "db"}, tags)

	// 3. Third import, same name, Overwrite: false: the record must be
	// skipped and the secret left exactly as step 2 produced it.
	result, err = f.secretSvc.ImportSecrets(ctx, secrets.ImportSecretsRequest{
		Scope:  f.scope(),
		Format: "json",
		Data:   marshalRecords(t, importRecord{Name: "db-password", Value: "v3-should-not-apply"}),
	})
	require.NoError(t, err)
	assert.Equal(t, 0, result.ImportedCount)
	assert.Equal(t, 1, result.SkippedCount)
	assert.Equal(t, 0, result.FailedCount)

	unchanged, err := f.secretRepo.FindByName(ctx, "db-password", f.scope())
	require.NoError(t, err)
	assert.Equal(t, 2, unchanged.Version, "a skipped import must not bump the version")
	unchangedPlaintext, err := f.crypto.DecryptSecret(unchanged.Value)
	require.NoError(t, err)
	assert.Equal(t, "v2", unchangedPlaintext, "a skipped import must not mutate the value")
}
