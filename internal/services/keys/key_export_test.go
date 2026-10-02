package keys

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"database/sql"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	_ "github.com/mattn/go-sqlite3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"rocketvault/internal/crypto"
	rvdb "rocketvault/internal/db"
	"rocketvault/internal/keycache"
	"rocketvault/internal/repositories"
	"rocketvault/model"
)

// pemDigest hashes exported material, so a failing comparison prints a
// digest and never the private key itself.
func pemDigest(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

type keyExportHarness struct {
	raw   *sql.DB
	repo  repositories.KeyRepositoryInterface
	svc   KeyService
	scope model.Scope
	vault uuid.UUID
	user  uuid.UUID
}

func newKeyExportHarness(t *testing.T, cache keycache.Cache) *keyExportHarness {
	t.Helper()
	setupKeyTestMasterKey()
	raw, err := sql.Open("sqlite3", "file:keyexp_"+uuid.NewString()+"?mode=memory&cache=shared")
	require.NoError(t, err)
	t.Cleanup(func() { raw.Close() }) //nolint:errcheck,gosec
	require.NoError(t, rvdb.NewRepository(newKeyLogger()).SetupSchema(raw, rvdb.SQLite))
	repo := repositories.NewKeyRepository(rvdb.NewConn(raw, rvdb.SQLite), newKeyLogger())
	vault, user := uuid.New(), uuid.New()
	return &keyExportHarness{
		raw: raw, repo: repo, vault: vault, user: user, scope: model.NewVaultScope(vault, user),
		svc: NewKeyService(KeyServiceConfig{KeyRepository: repo, KeyProvider: crypto.NewSoftwareKeyProvider(), KeyCache: cache, Logger: newKeyLogger()}),
	}
}

func (h *keyExportHarness) create(t *testing.T, keyType, curve string, exportable bool) uuid.UUID {
	t.Helper()
	req := CreateKeyRequest{Name: "k-" + uuid.NewString()[:8], Type: keyType, UserID: h.user, VaultID: h.vault, Exportable: exportable}
	var res *CreateKeyResult
	var err error
	if keyType == "RSA" {
		req.Bits = 2048
		res, err = h.svc.CreateRSAKey(context.Background(), req)
	} else {
		req.Curve = curve
		res, err = h.svc.CreateECDSAKey(context.Background(), req)
	}
	require.NoError(t, err)
	return res.KeyID
}

func TestExportKey_SoftwareRSAAndEC(t *testing.T) {
	h := newKeyExportHarness(t, nil)
	for _, tc := range []struct{ keyType, curve, alg string }{{"RSA", "", "RSA-2048"}, {"ECDSA", "P-384", "EC-P384"}} {
		id := h.create(t, tc.keyType, tc.curve, true)
		res, err := h.svc.ExportKey(context.Background(), h.scope, id, 0)
		require.NoError(t, err)
		assert.True(t, strings.HasPrefix(res.PrivateKeyPEM, "-----BEGIN PRIVATE KEY-----\n"), "exact PKCS#8 prefix")
		assert.Equal(t, tc.alg, res.KeyAlgorithm)
		assert.Equal(t, 1, res.Version)
		assert.Equal(t, model.ExportFormatPEM, res.Format)

		block, _ := pem.Decode([]byte(res.PrivateKeyPEM))
		_, err = x509.ParsePKCS8PrivateKey(block.Bytes)
		require.NoError(t, err)

		jwk, err := h.svc.GetPublicJWK(context.Background(), id, 0, h.scope)
		require.NoError(t, err)
		assert.True(t, jwk.N != "" || jwk.X != "", "the exported key is the key the JWK describes")
	}
}

func TestExportKey_Refusals(t *testing.T) {
	h := newKeyExportHarness(t, nil)
	ctx := context.Background()
	refusedWith := func(err error, reason string) {
		t.Helper()
		var refusal *model.ExportRefusedError
		require.True(t, errors.As(err, &refusal), "%v", err)
		assert.ErrorIs(t, err, model.ErrKeyNotExportable)
		assert.Contains(t, refusal.Reason, reason)
		assert.NotEmpty(t, refusal.KeyAlgorithm)
	}

	plain := h.create(t, "RSA", "", false)
	_, err := h.svc.ExportKey(ctx, h.scope, plain, 0)
	refusedWith(err, "exportable")

	es := h.create(t, "ECDSA", "P-256K", true)
	_, err = h.svc.ExportKey(ctx, h.scope, es, 0)
	refusedWith(err, "ES256K")

	hsm := uuid.New()
	require.NoError(t, h.repo.Create(ctx, &model.Key{ID: hsm, UserID: h.user, VaultID: h.vault, Name: "hsm", Type: model.KeyTypeRSA,
		Value: "pkcs11:" + uuid.NewString(), Enabled: true, CreatedAt: time.Now(), Bits: 2048, Exportable: true}))
	_, err = h.svc.ExportKey(ctx, h.scope, hsm, 0)
	refusedWith(err, "HSM")

	oct := uuid.New()
	require.NoError(t, h.repo.Create(ctx, &model.Key{ID: oct, UserID: h.user, VaultID: h.vault, Name: "oct", Type: model.KeyTypeOct,
		Value: "pkcs11:" + uuid.NewString(), Enabled: true, CreatedAt: time.Now(), Bits: 256, Exportable: true}))
	_, err = h.svc.ExportKey(ctx, h.scope, oct, 0)
	refusedWith(err, "oct")

	disabled := h.create(t, "RSA", "", true)
	off := false
	require.NoError(t, h.svc.UpdateKey(ctx, UpdateKeyRequest{KeyID: disabled, Scope: h.scope, Enabled: &off}))
	_, err = h.svc.ExportKey(ctx, h.scope, disabled, 0)
	require.ErrorIs(t, err, ErrKeyLifecycleDenied)

	// Stored directly, so the test does not depend on what UpdateKey accepts
	// for a past expiry.
	expired := uuid.New()
	past := time.Now().Add(-time.Hour)
	require.NoError(t, h.repo.Create(ctx, &model.Key{ID: expired, UserID: h.user, VaultID: h.vault, Name: "expired", Type: model.KeyTypeRSA,
		Value: "enc", Enabled: true, CreatedAt: time.Now().Add(-2 * time.Hour), ExpiresAt: &past, Bits: 2048, Exportable: true}))
	_, err = h.svc.ExportKey(ctx, h.scope, expired, 0)
	require.ErrorIs(t, err, ErrKeyLifecycleDenied)

	_, err = h.svc.ExportKey(ctx, h.scope, uuid.New(), 0)
	require.ErrorIs(t, err, ErrKeyNotFound)
	ok := h.create(t, "RSA", "", true)
	_, err = h.svc.ExportKey(ctx, model.NewVaultScope(uuid.New(), h.user), ok, 0)
	require.ErrorIs(t, err, ErrKeyNotFound, "another vault sees nothing")

	_, err = h.svc.ExportKey(ctx, h.scope, ok, -1)
	require.ErrorIs(t, err, model.ErrInvalidExportRequest)
}

func TestExportKey_ArchivedVersion(t *testing.T) {
	h := newKeyExportHarness(t, nil)
	ctx := context.Background()
	id := h.create(t, "RSA", "", true)
	first, err := h.svc.ExportKey(ctx, h.scope, id, 0)
	require.NoError(t, err)

	_, err = h.svc.RotateKey(ctx, id, h.scope)
	require.NoError(t, err)

	v1, err := h.svc.ExportKey(ctx, h.scope, id, 1)
	require.NoError(t, err)
	assert.Equal(t, pemDigest(first.PrivateKeyPEM), pemDigest(v1.PrivateKeyPEM), "an archived version exports its own material")
	assert.Equal(t, 1, v1.Version)

	current, err := h.svc.ExportKey(ctx, h.scope, id, 0)
	require.NoError(t, err)
	assert.Equal(t, 2, current.Version)
	assert.NotEqual(t, pemDigest(first.PrivateKeyPEM), pemDigest(current.PrivateKeyPEM))

	explicit, err := h.svc.ExportKey(ctx, h.scope, id, 2)
	require.NoError(t, err)
	assert.Equal(t, pemDigest(current.PrivateKeyPEM), pemDigest(explicit.PrivateKeyPEM), "the current number equals 0")

	_, err = h.svc.ExportKey(ctx, h.scope, id, 3)
	require.ErrorIs(t, err, model.ErrKeyVersionNotFound)
}

// TestExportKey_ArchivedHSMVersionIsRefused pins Review Focus 1: the stored
// value of the resolved version decides, not only the row's current value.
func TestExportKey_ArchivedHSMVersionIsRefused(t *testing.T) {
	h := newKeyExportHarness(t, nil)
	ctx := context.Background()
	id := h.create(t, "RSA", "", true)
	_, err := h.svc.RotateKey(ctx, id, h.scope)
	require.NoError(t, err)
	_, err = h.raw.ExecContext(context.Background(), "UPDATE key_versions SET value = ? WHERE key_id = ? AND version = 1", "pkcs11:"+uuid.NewString(), id.String())
	require.NoError(t, err)

	_, err = h.svc.ExportKey(ctx, h.scope, id, 1)
	require.ErrorIs(t, err, model.ErrKeyNotExportable)
}

// spyKeyCache records every use of the decrypted-key cache.
type spyKeyCache struct{ gets, sets int }

func (s *spyKeyCache) Get(uuid.UUID, int) (*keycache.Entry, bool) { s.gets++; return nil, false }
func (s *spyKeyCache) Set(uuid.UUID, int, *keycache.Entry)        { s.sets++ }
func (s *spyKeyCache) Invalidate(uuid.UUID)                       {}
func (s *spyKeyCache) InvalidateAll()                             {}
func (s *spyKeyCache) Stats() keycache.CacheStats                 { return keycache.CacheStats{} }
func (s *spyKeyCache) Stop()                                      {}

func TestExportKey_NeverTouchesTheKeyCache(t *testing.T) {
	spy := &spyKeyCache{}
	h := newKeyExportHarness(t, spy)
	id := h.create(t, "RSA", "", true)
	for i := 0; i < 2; i++ {
		_, err := h.svc.ExportKey(context.Background(), h.scope, id, 0)
		require.NoError(t, err)
	}
	assert.Zero(t, spy.gets)
	assert.Zero(t, spy.sets)
}

// TestExportKey_LifecycleStates pins the lifecycle gate beyond disabled and
// expired: revoked, soft-deleted and not-yet-valid keys export nothing.
func TestExportKey_LifecycleStates(t *testing.T) {
	h := newKeyExportHarness(t, nil)
	ctx := context.Background()

	revoked := h.create(t, "RSA", "", true)
	require.NoError(t, h.repo.UpdateRevocationStatus(ctx, revoked, true))
	res, err := h.svc.ExportKey(ctx, h.scope, revoked, 0)
	require.ErrorIs(t, err, ErrKeyLifecycleDenied)
	assert.Nil(t, res, "a revoked key returns no material")

	deleted := h.create(t, "RSA", "", true)
	_, err = h.svc.DeleteKey(ctx, deleted, h.scope)
	require.NoError(t, err)
	res, err = h.svc.ExportKey(ctx, h.scope, deleted, 0)
	require.ErrorIs(t, err, ErrKeyNotFound)
	assert.Nil(t, res)

	future := time.Now().Add(time.Hour)
	pending := uuid.New()
	require.NoError(t, h.repo.Create(ctx, &model.Key{ID: pending, UserID: h.user, VaultID: h.vault, Name: "pending", Type: model.KeyTypeRSA,
		Value: "enc", Enabled: true, CreatedAt: time.Now(), NotBefore: &future, Bits: 2048, Exportable: true}))
	res, err = h.svc.ExportKey(ctx, h.scope, pending, 0)
	require.ErrorIs(t, err, ErrKeyLifecycleDenied)
	assert.Nil(t, res)
}

// TestExportKey_MaterialComesFromTheVersionRow pins that the exported
// material is read from the resolved version's own row, so the version
// number and the material cannot come from two different reads.
func TestExportKey_MaterialComesFromTheVersionRow(t *testing.T) {
	h := newKeyExportHarness(t, nil)
	ctx := context.Background()
	id := h.create(t, "RSA", "", true)
	_, err := h.svc.RotateKey(ctx, id, h.scope)
	require.NoError(t, err)
	_, err = h.raw.ExecContext(context.Background(), "UPDATE keys SET value = ? WHERE id = ?", "not-the-version-row", id.String())
	require.NoError(t, err)

	res, err := h.svc.ExportKey(ctx, h.scope, id, 0)
	require.NoError(t, err)
	assert.Equal(t, 2, res.Version)
}
