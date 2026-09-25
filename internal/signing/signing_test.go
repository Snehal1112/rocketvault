// Package signing provides white-box tests for signing package internals,
// covering unexported helpers and providers that need dependency injection.
package signing

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"rocketvault/internal/repositories"
	"rocketvault/model"
)

// ---------------------------------------------------------------------------
// Mock CryptographyService
// ---------------------------------------------------------------------------

type mockCryptoService struct {
	encryptCallCount int
	decryptFn        func(string) (string, error)
	encryptFail      int // fail on this call number (1-indexed, 0 = never)
}

func (m *mockCryptoService) EncryptSecret(plaintext string) (string, error) {
	m.encryptCallCount++
	if m.encryptFail > 0 && m.encryptCallCount >= m.encryptFail {
		return "", fmt.Errorf("encrypt failed")
	}
	return "enc:" + plaintext, nil
}

func (m *mockCryptoService) DecryptSecret(ciphertext string) (string, error) {
	if m.decryptFn != nil {
		return m.decryptFn(ciphertext)
	}
	if len(ciphertext) >= 4 && ciphertext[:4] == "enc:" {
		return ciphertext[4:], nil
	}
	return "", fmt.Errorf("cannot decrypt %q", ciphertext)
}

// ---------------------------------------------------------------------------
// Mock KeyRepositoryInterface
// ---------------------------------------------------------------------------

type mockKeyRepo struct {
	keys          []model.Key
	created       []model.Key
	listByUserErr error
	createErr     error
	createCallNum int
	createFailAt  int // fail on this call number (1-indexed, 0 = never)
}

func (m *mockKeyRepo) Create(ctx context.Context, key *model.Key) error {
	m.createCallNum++
	if m.createFailAt > 0 && m.createCallNum >= m.createFailAt {
		return m.createErr
	}
	if m.createErr != nil && m.createFailAt == 0 {
		return m.createErr
	}
	m.created = append(m.created, *key)
	return nil
}

func (m *mockKeyRepo) Delete(_ context.Context, _ uuid.UUID) error {
	return fmt.Errorf("not implemented")
}

func (m *mockKeyRepo) UpdateRevocationStatus(_ context.Context, _ uuid.UUID, _ bool) error {
	return fmt.Errorf("not implemented")
}

func (m *mockKeyRepo) SoftDelete(_ context.Context, _ uuid.UUID) error {
	return fmt.Errorf("not implemented")
}

func (m *mockKeyRepo) RecoverKey(_ context.Context, _ uuid.UUID) error {
	return fmt.Errorf("not implemented")
}

func (m *mockKeyRepo) PurgeKey(_ context.Context, _ uuid.UUID) error {
	return fmt.Errorf("not implemented")
}

func (m *mockKeyRepo) SetPurgeProtection(_ context.Context, _ uuid.UUID, _ bool) error {
	return fmt.Errorf("not implemented")
}

func (m *mockKeyRepo) ReadDeletedScoped(_ context.Context, _ uuid.UUID, _ model.Scope) (*model.Key, error) {
	return nil, fmt.Errorf("not implemented")
}

func (m *mockKeyRepo) CreateVersion(_ context.Context, _ uuid.UUID, _ int, _ string) error {
	return fmt.Errorf("not implemented")
}

func (m *mockKeyRepo) ListVersions(_ context.Context, _ uuid.UUID) ([]model.KeyVersion, error) {
	return nil, fmt.Errorf("not implemented")
}

func (m *mockKeyRepo) CurrentVersion(_ context.Context, _ uuid.UUID) (int, error) {
	return 0, fmt.Errorf("not implemented")
}

func (m *mockKeyRepo) ReadVersionValue(_ context.Context, _ uuid.UUID, _ int) (string, error) {
	return "", fmt.Errorf("not implemented")
}

func (m *mockKeyRepo) GetVersion(_ context.Context, _ uuid.UUID, _ int) (*model.KeyVersion, error) {
	return nil, fmt.Errorf("not implemented")
}

func (m *mockKeyRepo) ListVersionRecords(_ context.Context, _ uuid.UUID) ([]model.KeyVersionRecord, error) {
	return nil, fmt.Errorf("not implemented")
}

func (m *mockKeyRepo) SoftDeleteVaultContents(_ context.Context, _ uuid.UUID, _ time.Time) error {
	return fmt.Errorf("not implemented")
}

func (m *mockKeyRepo) RecoverVaultContents(_ context.Context, _ uuid.UUID, _ time.Time) error {
	return fmt.Errorf("not implemented")
}

func (m *mockKeyRepo) Read(_ context.Context, _ uuid.UUID, _ model.Scope) (*model.Key, error) {
	return nil, fmt.Errorf("not implemented")
}

func (m *mockKeyRepo) Update(_ context.Context, _ *model.Key, _ model.Scope) error {
	return fmt.Errorf("not implemented")
}

// List backs loadOrGenerate's admin-scoped lookup (self_pki.go). It ignores
// scope and filter since the mock only needs to simulate the stored key set.
func (m *mockKeyRepo) List(_ context.Context, _ model.Scope, _ repositories.KeyFilter) ([]model.Key, error) {
	if m.listByUserErr != nil {
		return nil, m.listByUserErr
	}
	return m.keys, nil
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func genRSAKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	return k
}

func genECDSAKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	return k
}

func rsaPEM(t *testing.T, key *rsa.PrivateKey) string {
	t.Helper()
	return string(pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	}))
}

func ecPEM(t *testing.T, key *ecdsa.PrivateKey) string {
	t.Helper()
	der, err := x509.MarshalECPrivateKey(key)
	require.NoError(t, err)
	return string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}))
}

func writeTempPEM(t *testing.T, content string) string {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), "key-*.pem")
	require.NoError(t, err)
	_, err = f.WriteString(content)
	require.NoError(t, err)
	require.NoError(t, f.Close())
	return f.Name()
}

// ---------------------------------------------------------------------------
// NewProvider tests
// ---------------------------------------------------------------------------

func TestNewProvider_DefaultsToOSStore(t *testing.T) {
	v := viper.New()
	// jwt.key_source not set — should default to os_store.
	p, err := NewProvider(v, ProviderDeps{})
	require.NoError(t, err)
	require.NotNil(t, p)
	assert.Equal(t, "RS256", p.Algorithm())
}

func TestNewProvider_ExplicitOSStore(t *testing.T) {
	v := viper.New()
	v.Set("jwt.key_source", "os_store")
	v.Set("jwt.key_cn", "test-cn-provider")

	p, err := NewProvider(v, ProviderDeps{})
	require.NoError(t, err)
	require.NotNil(t, p)
	assert.Equal(t, "RS256", p.Algorithm())
}

func TestNewProvider_ExternalPKI_FromFile(t *testing.T) {
	t.Setenv("ROCKETVAULT_JWT_SIGNING_KEY", "") // ensure env var doesn't interfere

	keyPEM := rsaPEM(t, genRSAKey(t))
	keyFile := writeTempPEM(t, keyPEM)

	v := viper.New()
	v.Set("jwt.key_source", "external_pki")
	v.Set("jwt.signing_key_file", keyFile)

	p, err := NewProvider(v, ProviderDeps{})
	require.NoError(t, err)
	assert.Equal(t, "RS256", p.Algorithm())
}

func TestNewProvider_SelfPKI_MissingDeps(t *testing.T) {
	v := viper.New()
	v.Set("jwt.key_source", "self_pki")

	_, err := NewProvider(v, ProviderDeps{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "CryptoService and KeyRepository")
}

func TestNewProvider_SelfPKI_WithDeps(t *testing.T) {
	v := viper.New()
	v.Set("jwt.key_source", "self_pki")
	v.Set("jwt.rotation_overlap", "30m")

	deps := ProviderDeps{
		CryptoService: &mockCryptoService{},
		KeyRepository: &mockKeyRepo{},
	}
	p, err := NewProvider(v, deps)
	require.NoError(t, err)
	require.NotNil(t, p)
	assert.Equal(t, selfPKIAlgorithm, p.Algorithm())
}

func TestNewProvider_UnknownSource(t *testing.T) {
	v := viper.New()
	v.Set("jwt.key_source", "nonexistent_source")

	_, err := NewProvider(v, ProviderDeps{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unknown jwt.key_source")
}

// ---------------------------------------------------------------------------
// SelfPKIProvider tests
// ---------------------------------------------------------------------------

func TestNewSelfPKIProvider_GeneratesKey_WhenNoneExists(t *testing.T) {
	crypto := &mockCryptoService{}
	repo := &mockKeyRepo{}

	p, err := NewSelfPKIProvider(crypto, repo, "")
	require.NoError(t, err)
	require.NotNil(t, p)

	assert.Equal(t, selfPKIAlgorithm, p.Algorithm())
	assert.NotEmpty(t, p.KeyID())
	assert.NotNil(t, p.PrivateKey())

	require.Len(t, repo.created, 1)
	assert.Equal(t, jwtSigningKeyName, repo.created[0].Name)
}

func TestNewSelfPKIProvider_LoadsExistingKey(t *testing.T) {
	crypto := &mockCryptoService{}

	// Encode a real ECDSA key as PEM and "encrypt" it with the mock crypto.
	key := genECDSAKey(t)
	pemStr := ecPEM(t, key)
	encrypted, _ := crypto.EncryptSecret(pemStr)

	existingKey := model.Key{
		ID:        uuid.New(),
		Name:      jwtSigningKeyName,
		Type:      model.KeyTypeECDSA,
		Value:     encrypted,
		CreatedAt: time.Now(),
	}
	repo := &mockKeyRepo{keys: []model.Key{existingKey}}

	p, err := NewSelfPKIProvider(crypto, repo, "1h")
	require.NoError(t, err)
	assert.Equal(t, selfPKIAlgorithm, p.Algorithm())
	assert.NotEmpty(t, p.KeyID())
	// No new key generated.
	assert.Len(t, repo.created, 0)
}

func TestNewSelfPKIProvider_SkipsDeletedKeys(t *testing.T) {
	crypto := &mockCryptoService{}
	deletedAt := time.Now()

	deletedKey := model.Key{
		ID:        uuid.New(),
		Name:      jwtSigningKeyName,
		Type:      model.KeyTypeECDSA,
		Value:     "enc:whatever",
		CreatedAt: time.Now().Add(-time.Hour),
		DeletedAt: &deletedAt,
	}
	repo := &mockKeyRepo{keys: []model.Key{deletedKey}}

	p, err := NewSelfPKIProvider(crypto, repo, "")
	require.NoError(t, err)
	require.NotNil(t, p)
	// New key generated because the stored one is deleted.
	assert.Len(t, repo.created, 1)
}

func TestNewSelfPKIProvider_SkipsNonSigningKeys(t *testing.T) {
	crypto := &mockCryptoService{}

	otherKey := model.Key{
		ID:        uuid.New(),
		Name:      "user-generated-key",
		Type:      model.KeyTypeECDSA,
		Value:     "enc:whatever",
		CreatedAt: time.Now(),
	}
	repo := &mockKeyRepo{keys: []model.Key{otherKey}}

	p, err := NewSelfPKIProvider(crypto, repo, "")
	require.NoError(t, err)
	require.NotNil(t, p)
	// New key generated because the existing key doesn't have the jwt signing name.
	assert.Len(t, repo.created, 1)
}

func TestNewSelfPKIProvider_ListByUserError(t *testing.T) {
	crypto := &mockCryptoService{}
	repo := &mockKeyRepo{listByUserErr: fmt.Errorf("db error")}

	_, err := NewSelfPKIProvider(crypto, repo, "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "list keys")
}

func TestNewSelfPKIProvider_CreateKeyError(t *testing.T) {
	crypto := &mockCryptoService{}
	repo := &mockKeyRepo{createErr: fmt.Errorf("write error")}

	_, err := NewSelfPKIProvider(crypto, repo, "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "store generated key")
}

func TestNewSelfPKIProvider_BadDecrypt_Regenerates(t *testing.T) {
	badKey := model.Key{
		ID:        uuid.New(),
		Name:      jwtSigningKeyName,
		Type:      model.KeyTypeECDSA,
		Value:     "corrupted-ciphertext",
		CreatedAt: time.Now(),
	}
	crypto := &mockCryptoService{
		decryptFn: func(s string) (string, error) {
			return "", fmt.Errorf("decryption failed")
		},
	}
	repo := &mockKeyRepo{keys: []model.Key{badKey}}

	p, err := NewSelfPKIProvider(crypto, repo, "")
	require.NoError(t, err)
	require.NotNil(t, p)
	// New key generated after decrypt failure.
	assert.Len(t, repo.created, 1)
}

func TestSelfPKIProvider_PrivateKey_Algorithm_KeyID(t *testing.T) {
	p, err := NewSelfPKIProvider(&mockCryptoService{}, &mockKeyRepo{}, "1s")
	require.NoError(t, err)

	assert.NotNil(t, p.PrivateKey())
	assert.Equal(t, "ES256", p.Algorithm())
	assert.NotEmpty(t, p.KeyID())
}

func TestSelfPKIProvider_PublicKeys_SingleKey(t *testing.T) {
	p, err := NewSelfPKIProvider(&mockCryptoService{}, &mockKeyRepo{}, "")
	require.NoError(t, err)

	keys := p.PublicKeys()
	require.Len(t, keys, 1)
	assert.Equal(t, selfPKIAlgorithm, keys[0].Algorithm)
	assert.Equal(t, p.KeyID(), keys[0].KeyID)
	assert.NotNil(t, keys[0].PublicKey)
}

func TestSelfPKIProvider_Rotate_PromotesNewKey(t *testing.T) {
	p, err := NewSelfPKIProvider(&mockCryptoService{}, &mockKeyRepo{}, "10m")
	require.NoError(t, err)

	originalKID := p.KeyID()
	newKID, overlapUntil, err := p.Rotate()
	require.NoError(t, err)

	assert.NotEmpty(t, newKID)
	assert.NotEmpty(t, overlapUntil)
	assert.NotEqual(t, originalKID, newKID)
	assert.Equal(t, newKID, p.KeyID())

	// During the overlap window there should be two public keys.
	pubKeys := p.PublicKeys()
	assert.Len(t, pubKeys, 2)
}

func TestSelfPKIProvider_Rotate_CreateError(t *testing.T) {
	repo := &mockKeyRepo{}
	p, err := NewSelfPKIProvider(&mockCryptoService{}, repo, "")
	require.NoError(t, err)

	// Make subsequent Creates (for rotation) fail.
	repo.createErr = fmt.Errorf("disk full")
	repo.createFailAt = 2 // first call succeeded during init; fail on second (rotation)

	_, _, err = p.Rotate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "store new key")
}

func TestSelfPKIProvider_Rotate_EncryptError(t *testing.T) {
	// First encrypt (during init) succeeds; second (during rotate) fails.
	crypto := &mockCryptoService{encryptFail: 2}
	repo := &mockKeyRepo{}

	p, err := NewSelfPKIProvider(crypto, repo, "")
	require.NoError(t, err)

	_, _, err = p.Rotate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "encrypt new key")
}

// ---------------------------------------------------------------------------
// parsePEMKey edge cases
// ---------------------------------------------------------------------------

func TestParsePEMKey_RSA_PKCS1(t *testing.T) {
	pemStr := rsaPEM(t, genRSAKey(t))
	signer, alg, err := parsePEMKey([]byte(pemStr))
	require.NoError(t, err)
	assert.Equal(t, "RS256", alg)
	assert.NotNil(t, signer)
}

func TestParsePEMKey_ECDSA_P256(t *testing.T) {
	pemStr := ecPEM(t, genECDSAKey(t))
	signer, alg, err := parsePEMKey([]byte(pemStr))
	require.NoError(t, err)
	assert.Equal(t, "ES256", alg)
	assert.NotNil(t, signer)
}

func TestParsePEMKey_ECDSA_P384(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err)
	der, err := x509.MarshalECPrivateKey(key)
	require.NoError(t, err)
	pemStr := string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}))

	signer, alg, err := parsePEMKey([]byte(pemStr))
	require.NoError(t, err)
	assert.Equal(t, "ES384", alg)
	assert.NotNil(t, signer)
}

func TestParsePEMKey_ECDSA_P521(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	require.NoError(t, err)
	der, err := x509.MarshalECPrivateKey(key)
	require.NoError(t, err)
	pemStr := string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}))

	signer, alg, err := parsePEMKey([]byte(pemStr))
	require.NoError(t, err)
	assert.Equal(t, "ES512", alg)
	assert.NotNil(t, signer)
}

func TestParsePEMKey_PKCS8_RSA(t *testing.T) {
	key := genRSAKey(t)
	der, err := x509.MarshalPKCS8PrivateKey(key)
	require.NoError(t, err)
	pemStr := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))

	signer, alg, err := parsePEMKey([]byte(pemStr))
	require.NoError(t, err)
	assert.Equal(t, "RS256", alg)
	assert.NotNil(t, signer)
}

func TestParsePEMKey_PKCS8_ECDSA(t *testing.T) {
	key := genECDSAKey(t)
	der, err := x509.MarshalPKCS8PrivateKey(key)
	require.NoError(t, err)
	pemStr := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))

	signer, alg, err := parsePEMKey([]byte(pemStr))
	require.NoError(t, err)
	assert.Equal(t, "ES256", alg)
	assert.NotNil(t, signer)
}

func TestParsePEMKey_NoPEMBlock(t *testing.T) {
	_, _, err := parsePEMKey([]byte("not pem data"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no PEM block")
}

func TestParsePEMKey_UnsupportedPEMType(t *testing.T) {
	pemStr := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("fake")}))
	_, _, err := parsePEMKey([]byte(pemStr))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported PEM type")
}

// ---------------------------------------------------------------------------
// ecAlgorithm
// ---------------------------------------------------------------------------

func TestEcAlgorithm_P256(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	alg, err := ecAlgorithm(key)
	require.NoError(t, err)
	assert.Equal(t, "ES256", alg)
}

func TestEcAlgorithm_P384(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err)
	alg, err := ecAlgorithm(key)
	require.NoError(t, err)
	assert.Equal(t, "ES384", alg)
}

func TestEcAlgorithm_P521(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	require.NoError(t, err)
	alg, err := ecAlgorithm(key)
	require.NoError(t, err)
	assert.Equal(t, "ES512", alg)
}

// ---------------------------------------------------------------------------
// PublicKeyInfoToJWK
// ---------------------------------------------------------------------------

func TestPublicKeyInfoToJWK_RSA(t *testing.T) {
	key := genRSAKey(t)
	info := PublicKeyInfo{
		KeyID:     "rsa-kid",
		Algorithm: "RS256",
		PublicKey: &key.PublicKey,
	}
	jwk, err := PublicKeyInfoToJWK(info)
	require.NoError(t, err)
	assert.Equal(t, "RSA", jwk["kty"])
	assert.Equal(t, "rsa-kid", jwk["kid"])
}

func TestPublicKeyInfoToJWK_ECDSA(t *testing.T) {
	key := genECDSAKey(t)
	info := PublicKeyInfo{
		KeyID:     "ec-kid",
		Algorithm: "ES256",
		PublicKey: &key.PublicKey,
	}
	jwk, err := PublicKeyInfoToJWK(info)
	require.NoError(t, err)
	assert.Equal(t, "EC", jwk["kty"])
	assert.Equal(t, "ec-kid", jwk["kid"])
}

func TestPublicKeyInfoToJWK_UnsupportedType(t *testing.T) {
	info := PublicKeyInfo{
		KeyID:     "unknown",
		Algorithm: "??",
		PublicKey: "not-a-key",
	}
	_, err := PublicKeyInfoToJWK(info)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported public key type")
}

// ---------------------------------------------------------------------------
// curveParams
// ---------------------------------------------------------------------------

func TestCurveParams_P256(t *testing.T) {
	key := genECDSAKey(t)
	crv, byteLen, err := curveParams(&key.PublicKey)
	require.NoError(t, err)
	assert.Equal(t, "P-256", crv)
	assert.Equal(t, 32, byteLen)
}

func TestCurveParams_P384(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err)
	crv, byteLen, err := curveParams(&key.PublicKey)
	require.NoError(t, err)
	assert.Equal(t, "P-384", crv)
	assert.Equal(t, 48, byteLen)
}

func TestCurveParams_P521(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	require.NoError(t, err)
	crv, byteLen, err := curveParams(&key.PublicKey)
	require.NoError(t, err)
	assert.Equal(t, "P-521", crv)
	assert.Equal(t, 66, byteLen)
}

// ---------------------------------------------------------------------------
// padBytes
// ---------------------------------------------------------------------------

func TestPadBytes_ShortInput(t *testing.T) {
	result := padBytes([]byte{0xAB, 0xCD}, 4)
	assert.Equal(t, []byte{0x00, 0x00, 0xAB, 0xCD}, result)
}

func TestPadBytes_ExactLength(t *testing.T) {
	input := []byte{0x01, 0x02, 0x03}
	result := padBytes(input, 3)
	assert.Equal(t, input, result)
}

func TestPadBytes_LongerInput(t *testing.T) {
	input := []byte{0x01, 0x02, 0x03, 0x04, 0x05}
	result := padBytes(input, 3)
	assert.Equal(t, input, result)
}

// ---------------------------------------------------------------------------
// ECDSAPublicKeyToJWK — all supported curves
// ---------------------------------------------------------------------------

func TestECDSAPublicKeyToJWK_P384(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err)
	jwk, err := ECDSAPublicKeyToJWK(&key.PublicKey, "kid-384", "ES384")
	require.NoError(t, err)
	assert.Equal(t, "P-384", jwk["crv"])
}

func TestECDSAPublicKeyToJWK_P521(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	require.NoError(t, err)
	jwk, err := ECDSAPublicKeyToJWK(&key.PublicKey, "kid-521", "ES512")
	require.NoError(t, err)
	assert.Equal(t, "P-521", jwk["crv"])
}

// ---------------------------------------------------------------------------
// ecdsaKeyToPEM / parseECDSAPEM round-trip
// ---------------------------------------------------------------------------

func TestEcdsaKeyToPEM_RoundTrip(t *testing.T) {
	key := genECDSAKey(t)

	pemStr, err := ecdsaKeyToPEM(key)
	require.NoError(t, err)
	assert.Contains(t, pemStr, "EC PRIVATE KEY")

	parsed, err := parseECDSAPEM(pemStr)
	require.NoError(t, err)
	assert.Equal(t, key.D, parsed.D)
}

func TestParseECDSAPEM_Invalid(t *testing.T) {
	_, err := parseECDSAPEM("not a pem string")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no PEM block")
}
