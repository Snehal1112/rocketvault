package common

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"sync"

	"github.com/spf13/viper"
	"golang.org/x/crypto/bcrypt"
)

// bcryptCost is the work factor used for password hashing.
// Cost 12 is strong enough for production while remaining performant.
const bcryptCost = 12

// CheckPassword compares a plaintext password with a hashed password. A stored
// hash that is not a usable bcrypt hash, such as the empty hash of an
// OIDC-only account or the system account's marker, is rejected only after a
// dummy compare. Otherwise bcrypt would refuse it at once and the fast answer
// would reveal that such an account exists.
func CheckPassword(password, hash string) error {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	if err != nil && !IsUsableBcryptHash(hash) {
		burnPasswordCompare(password)
	}
	return err
}

// bcryptHashLen is the length of every well-formed bcrypt hash.
const bcryptHashLen = 60

// bcryptSaltLen is the length of the encoded salt inside a bcrypt hash.
const bcryptSaltLen = 22

// bcryptEncoding is the base64 alphabet bcrypt uses for its salt and digest.
var bcryptEncoding = base64.NewEncoding("./ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789").WithPadding(base64.NoPadding)

// IsUsableBcryptHash reports whether hash is a well-formed bcrypt hash that a
// compare would do the full key-derivation work against. Empty strings and
// marker values such as "!system-account-no-login!" are not.
func IsUsableBcryptHash(hash string) bool {
	if len(hash) != bcryptHashLen {
		return false
	}
	if _, err := bcrypt.Cost([]byte(hash)); err != nil {
		return false
	}
	// The salt follows the "$2a$12$" prefix, so it starts seven bytes in.
	_, err := bcryptEncoding.DecodeString(hash[7 : 7+bcryptSaltLen])
	return err == nil
}

// HashString hashes a string using bcrypt.
func HashString(input string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(input), bcryptCost)
	if err != nil {
		return "", err
	}
	return string(hash), nil
}

var (
	dummyHashOnce sync.Once
	dummyHash     []byte
)

// burnPasswordCompare is the dummy compare CheckPassword runs. Tests replace
// it with a spy.
var burnPasswordCompare = BurnPasswordCompare

// loadDummyHash returns the dummy bcrypt hash, building it on first use. It is
// the hash of random bytes nobody knows, at the production cost, so it guards
// nothing and no password can match it.
func loadDummyHash() []byte {
	dummyHashOnce.Do(func() {
		dummyHash = buildDummyHash(bcrypt.GenerateFromPassword)
	})
	return dummyHash
}

// buildDummyHash hashes 32 random bytes with generate at the production cost.
// It panics on failure, because a missing hash would make every later burn
// instant and silently reopen the timing oracle. It runs once, at startup.
func buildDummyHash(generate func(password []byte, cost int) ([]byte, error)) []byte {
	random := make([]byte, 32)
	if _, err := rand.Read(random); err != nil {
		panic(fmt.Sprintf("dummy password hash: %v", err))
	}
	hash, err := generate(random, bcryptCost)
	if err != nil {
		panic(fmt.Sprintf("dummy password hash: %v", err))
	}
	return hash
}

// PrimeBurnPasswordCompare builds the dummy hash ahead of the first request,
// so the first unknown account is not slower than later ones.
func PrimeBurnPasswordCompare() {
	loadDummyHash()
}

// BurnPasswordCompare spends one bcrypt comparison at the production cost and
// discards the outcome. Callers run it when a lookup finds no account, so a
// missing account takes as long to reject as a wrong password and response
// timing does not reveal which names exist.
func BurnPasswordCompare(password string) {
	_ = bcrypt.CompareHashAndPassword(loadDummyHash(), []byte(password))
}

// masterKeySize is the AES-256 key length in raw bytes.
const masterKeySize = 32

// ParseMasterKey decodes a base64-encoded master key and checks its length.
// It makes no judgement about key quality; use ValidateMasterKey for that.
//
// Parameters:
//
//	encoded: The base64-encoded master key.
//
// Returns:
//
//	The raw 32-byte key and an error if the key is missing or malformed.
func ParseMasterKey(encoded string) ([]byte, error) {
	if encoded == "" {
		return nil, fmt.Errorf("master key not configured")
	}

	key, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("failed to decode master key: %w", err)
	}
	if len(key) != masterKeySize {
		return nil, fmt.Errorf("master key must be %d bytes, got %d", masterKeySize, len(key))
	}
	return key, nil
}

// EncryptWithKey seals a value with AES-256-GCM under an explicit key. A fresh
// random 12-byte nonce is prepended to the ciphertext and the result is
// base64-encoded. Taking the key as a parameter is what lets the master key
// rotation tool re-encrypt under a second key in the same process.
//
// Parameters:
//
//	value: The plaintext value.
//	key: The raw 32-byte AES-256 key.
//
// Returns:
//
//	The encrypted value (base64-encoded) and an error if encryption fails.
func EncryptWithKey(value string, key []byte) (string, error) {
	if len(key) != masterKeySize {
		return "", fmt.Errorf("master key must be %d bytes, got %d", masterKeySize, len(key))
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("failed to create AES cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("failed to create GCM: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", fmt.Errorf("failed to generate nonce: %w", err)
	}

	ciphertext := gcm.Seal(nonce, nonce, []byte(value), nil)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// DecryptWithKey opens a value sealed by EncryptWithKey under an explicit key.
// AES-GCM is authenticated, so a wrong key reliably returns an error rather
// than garbage plaintext.
//
// Parameters:
//
//	encryptedValue: The encrypted value (base64-encoded).
//	key: The raw 32-byte AES-256 key.
//
// Returns:
//
//	The decrypted plaintext value and an error if decryption fails.
func DecryptWithKey(encryptedValue string, key []byte) (string, error) {
	if len(key) != masterKeySize {
		return "", fmt.Errorf("master key must be %d bytes, got %d", masterKeySize, len(key))
	}

	ciphertext, err := base64.StdEncoding.DecodeString(encryptedValue)
	if err != nil {
		return "", fmt.Errorf("failed to decode encrypted value: %w", err)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("failed to create AES cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("failed to create GCM: %w", err)
	}

	if len(ciphertext) < gcm.NonceSize() {
		return "", fmt.Errorf("ciphertext too short")
	}

	nonce, ciphertext := ciphertext[:gcm.NonceSize()], ciphertext[gcm.NonceSize():]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", fmt.Errorf("failed to decrypt: %w", err)
	}

	return string(plaintext), nil
}

// EncryptSecret encrypts a secret value using AES-256-GCM under the master key
// from configuration.
//
// Parameters:
//
//	value: The plaintext secret value.
//
// Returns:
//
//	The encrypted value (base64-encoded) and an error if encryption fails.
func EncryptSecret(value string) (string, error) {
	key, err := ParseMasterKey(viper.GetString("master_key"))
	if err != nil {
		return "", err
	}
	return EncryptWithKey(value, key)
}

// DecryptSecret decrypts a secret value encrypted with AES-256-GCM under the
// master key from configuration.
//
// Parameters:
//
//	encryptedValue: The encrypted value (base64-encoded).
//
// Returns:
//
//	The decrypted plaintext value and an error if decryption fails.
func DecryptSecret(encryptedValue string) (string, error) {
	key, err := ParseMasterKey(viper.GetString("master_key"))
	if err != nil {
		return "", err
	}
	return DecryptWithKey(encryptedValue, key)
}
