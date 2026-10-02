package keys

// This file is the load-bearing regression test for Task 11's actual fix:
// crypto_service.go's six operations (Sign, Verify, Encrypt, Decrypt, WrapKey,
// UnwrapKey) using req.Scope instead of a hardcoded
// model.NewOwnerScope(req.VaultID, req.UserID) when calling loadAndAuthorize.
//
// api/vault_scoped_keys_certs_test.go's TestCryptoOperationsUseVaultScope only
// proves the HANDLER populates req.Scope with a vault scope -- it fakes out
// CryptoService entirely, so it never proves the SERVICE enforces that scope
// against a repository the way a real one would. If the six loadAndAuthorize
// call sites in crypto_service.go reverted to hardcoding
// model.NewOwnerScope(req.VaultID, req.UserID), that handler-level test would
// stay green.
//
// This file closes that gap by wiring a real repositories.KeyRepository
// backed by an in-memory SQLite database -- not a mock that echoes back
// whatever scope it is handed -- into a real CryptoService, matching the
// "cross-vault denial against real SQLite" pattern already established by
// TestUpdateKey_VaultScope_AuditRowsAttributeTheActor_NotTheOwner in
// key_service_update_test.go. The schema mirrors that test's.

import (
	"context"
	"database/sql"
	"encoding/base64"
	"testing"

	"github.com/google/uuid"
	_ "github.com/mattn/go-sqlite3"
	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"rocketvault/common"
	rvcrypto "rocketvault/internal/crypto"
	rvdb "rocketvault/internal/db"
	"rocketvault/internal/logging"
	"rocketvault/internal/repositories"
	"rocketvault/model"
)

// setupCryptoVaultScopeTestMasterKey configures a deterministic 32-byte AES
// master key so common.EncryptSecret/DecryptSecret work in-process. Must not
// run in parallel with other tests that also call viper.Set("master_key",...).
func setupCryptoVaultScopeTestMasterKey() {
	k := make([]byte, 32)
	for i := range k {
		k[i] = byte(i + 1)
	}
	viper.Set("master_key", base64.StdEncoding.EncodeToString(k))
}

// newCryptoVaultScopeFixture builds a real, SQLite-backed KeyRepository
// (the same schema and wiring as
// TestUpdateKey_VaultScope_AuditRowsAttributeTheActor_NotTheOwner in
// key_service_update_test.go) and a real CryptoService on top of it, then
// inserts one key owned by ownerID in vaultID. Using the real repository
// means the vault-scope predicate that gates the test is the production
// SQL predicate (scopePredicate in internal/repositories), not a test double
// that could silently ignore the scope argument.
func newCryptoVaultScopeFixture(t *testing.T, vaultID, ownerID, keyID uuid.UUID) *cryptoService {
	t.Helper()
	setupCryptoVaultScopeTestMasterKey()

	sqlDB, err := sql.Open("sqlite3", ":memory:")
	require.NoError(t, err)
	t.Cleanup(func() { sqlDB.Close() }) //nolint:errcheck,gosec

	_, err = sqlDB.Exec(`CREATE TABLE IF NOT EXISTS keys (
		id TEXT PRIMARY KEY,
		user_id TEXT NOT NULL,
		vault_id TEXT NOT NULL DEFAULT '00000000-0000-0000-0000-00000000efa1',
		name TEXT NOT NULL,
		value TEXT NOT NULL,
		type TEXT NOT NULL,
		revoked BOOLEAN NOT NULL DEFAULT FALSE,
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		deleted_at TIMESTAMP DEFAULT NULL,
		purge_protection BOOLEAN NOT NULL DEFAULT FALSE,
		scheduled_purge_at TIMESTAMP DEFAULT NULL,
		enabled BOOLEAN NOT NULL DEFAULT TRUE,
		expires_at TIMESTAMP NULL,
		not_before TIMESTAMP NULL,
		bits INTEGER NOT NULL DEFAULT 0,
		curve TEXT NOT NULL DEFAULT '',
		updated_at TIMESTAMP NULL,
		exportable BOOLEAN NOT NULL DEFAULT FALSE
	)`)
	require.NoError(t, err)
	_, err = sqlDB.Exec(`CREATE TABLE IF NOT EXISTS key_tags (
		key_id TEXT NOT NULL,
		tag TEXT NOT NULL,
		PRIMARY KEY (key_id, tag)
	)`)
	require.NoError(t, err)
	// key_versions is required by KeyRepository.CurrentVersion, which
	// CryptoService now calls on every crypto operation to resolve the
	// current version number (Task 2, key-version-addressability). Schema
	// mirrors internal/db/db.go's migration.
	_, err = sqlDB.Exec(`CREATE TABLE IF NOT EXISTS key_versions (
		key_id TEXT NOT NULL,
		version INTEGER NOT NULL,
		value TEXT NOT NULL,
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		PRIMARY KEY (key_id, version)
	)`)
	require.NoError(t, err)

	logger := &logging.Logger{Logger: logrus.New()}
	keyRepo := repositories.NewKeyRepository(rvdb.NewConn(sqlDB, rvdb.SQLite), logger)

	privateKeyPEM, err := rvcrypto.GenerateRSAKeyPEM(2048)
	require.NoError(t, err)
	encryptedPEM, err := common.EncryptSecret(privateKeyPEM)
	require.NoError(t, err)

	require.NoError(t, keyRepo.Create(context.Background(), &model.Key{
		ID: keyID, UserID: ownerID, VaultID: vaultID, Name: "prod-signing-key",
		Type: "RSA", Value: encryptedPEM, Enabled: true,
	}))

	svc := NewCryptoService(CryptoServiceConfig{KeyRepository: keyRepo, Logger: logger})
	return svc.(*cryptoService)
}

// TestSign_VaultScope_NonOwnerVaultMemberSucceeds is the P2 behavior change
// under test: a vault member who does not own the key can now sign with it,
// because authorization is vault-role membership, not key ownership. This
// would fail (ErrKeyNotFound) if crypto_service.go's Sign still hardcoded
// model.NewOwnerScope(req.VaultID, req.UserID) instead of using req.Scope,
// since the SQL owner predicate would filter out a non-owner caller's read.
func TestSign_VaultScope_NonOwnerVaultMemberSucceeds(t *testing.T) {
	vaultID, ownerID, memberID, keyID := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	svc := newCryptoVaultScopeFixture(t, vaultID, ownerID, keyID)

	result, err := svc.Sign(context.Background(), SignRequest{
		KeyID:     keyID,
		Data:      []byte("hello"),
		Algorithm: rvcrypto.AlgorithmRS256,
		UserID:    memberID,
		VaultID:   vaultID,
		Scope:     model.NewVaultScope(vaultID, memberID),
	})
	require.NoError(t, err, "a vault member who is not the key's owner must be able to sign under a vault scope")
	assert.NotEmpty(t, result.Signature)
}

// TestSign_VaultScope_WrongVaultDenied is the inverse: a vault scope for a
// vault the key does NOT belong to is denied, even when the actor id on the
// scope is the key's actual owner. This proves the vault-scope predicate
// gates on vault membership (vault_id), not on who the caller claims to be --
// the previous test's success is not merely because the actor happened to
// match some owner check.
func TestSign_VaultScope_WrongVaultDenied(t *testing.T) {
	vaultA, otherVault, ownerID, keyID := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	svc := newCryptoVaultScopeFixture(t, vaultA, ownerID, keyID)

	_, err := svc.Sign(context.Background(), SignRequest{
		KeyID:     keyID,
		Data:      []byte("hello"),
		Algorithm: rvcrypto.AlgorithmRS256,
		UserID:    ownerID,
		VaultID:   otherVault,
		Scope:     model.NewVaultScope(otherVault, ownerID),
	})
	require.Error(t, err, "a vault scope for a vault the key does not belong to must be denied, even carrying the real owner's id as actor")
	assert.ErrorIs(t, err, ErrKeyNotFound)
}

// TestEncrypt_VaultScope_NonOwnerVaultMemberSucceeds mirrors the Sign
// assertion for Encrypt, confirming the fix is not Sign-specific: all six
// crypto_service.go operations share the same loadAndAuthorize call, so this
// exercises a second call site through the same real repository.
func TestEncrypt_VaultScope_NonOwnerVaultMemberSucceeds(t *testing.T) {
	vaultID, ownerID, memberID, keyID := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	svc := newCryptoVaultScopeFixture(t, vaultID, ownerID, keyID)

	result, err := svc.Encrypt(context.Background(), EncryptRequest{
		KeyID:     keyID,
		Data:      []byte("sensitive data"),
		Algorithm: rvcrypto.AlgorithmRSAOAEP,
		UserID:    memberID,
		VaultID:   vaultID,
		Scope:     model.NewVaultScope(vaultID, memberID),
	})
	require.NoError(t, err, "a vault member who is not the key's owner must be able to encrypt under a vault scope")
	assert.NotEmpty(t, result.Ciphertext)
}

// TestEncrypt_VaultScope_WrongVaultDenied mirrors
// TestSign_VaultScope_WrongVaultDenied for Encrypt.
func TestEncrypt_VaultScope_WrongVaultDenied(t *testing.T) {
	vaultA, otherVault, ownerID, keyID := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	svc := newCryptoVaultScopeFixture(t, vaultA, ownerID, keyID)

	_, err := svc.Encrypt(context.Background(), EncryptRequest{
		KeyID:     keyID,
		Data:      []byte("sensitive data"),
		Algorithm: rvcrypto.AlgorithmRSAOAEP,
		UserID:    ownerID,
		VaultID:   otherVault,
		Scope:     model.NewVaultScope(otherVault, ownerID),
	})
	require.Error(t, err, "a vault scope for a vault the key does not belong to must be denied, even carrying the real owner's id as actor")
	assert.ErrorIs(t, err, ErrKeyNotFound)
}
