package common

import (
	"encoding/base64"
	"testing"
	"time"

	"github.com/spf13/viper"
	"golang.org/x/crypto/bcrypt"
)

func setupMasterKey(t *testing.T) string {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 1)
	}
	encoded := base64.StdEncoding.EncodeToString(key)
	viper.Set("master_key", encoded)
	return encoded
}

func TestHashStringAndCheckPassword(t *testing.T) {
	password := "supersecret"
	hash, err := HashString(password)
	if err != nil {
		t.Fatalf("HashString failed: %v", err)
	}
	if err := CheckPassword(password, hash); err != nil {
		t.Errorf("CheckPassword failed: %v", err)
	}
	if err := CheckPassword("wrongpassword", hash); err == nil {
		t.Error("CheckPassword should fail for wrong password")
	}
}

func TestEncryptSecretAndDecryptSecret(t *testing.T) {
	setupMasterKey(t)
	plaintext := "my secret value"
	encrypted, err := EncryptSecret(plaintext)
	if err != nil {
		t.Fatalf("EncryptSecret failed: %v", err)
	}
	decrypted, err := DecryptSecret(encrypted)
	if err != nil {
		t.Fatalf("DecryptSecret failed: %v", err)
	}
	if decrypted != plaintext {
		t.Errorf("expected %q, got %q", plaintext, decrypted)
	}
}

func TestEncryptSecret_MissingMasterKey(t *testing.T) {
	viper.Set("master_key", "")
	_, err := EncryptSecret("test")
	if err == nil {
		t.Error("expected error when master key is missing")
	}
}

func TestEncryptSecret_InvalidMasterKey(t *testing.T) {
	viper.Set("master_key", "not-base64")
	_, err := EncryptSecret("test")
	if err == nil {
		t.Error("expected error for invalid base64 master key")
	}
}

func TestEncryptSecret_ShortMasterKey(t *testing.T) {
	shortKey := base64.StdEncoding.EncodeToString([]byte("short"))
	viper.Set("master_key", shortKey)
	_, err := EncryptSecret("test")
	if err == nil {
		t.Error("expected error for short master key")
	}
}

func TestDecryptSecret_MissingMasterKey(t *testing.T) {
	viper.Set("master_key", "")
	_, err := DecryptSecret("test")
	if err == nil {
		t.Error("expected error when master key is missing")
	}
}

func TestDecryptSecret_InvalidMasterKey(t *testing.T) {
	viper.Set("master_key", "not-base64")
	_, err := DecryptSecret("test")
	if err == nil {
		t.Error("expected error for invalid base64 master key")
	}
}

func TestDecryptSecret_ShortMasterKey(t *testing.T) {
	shortKey := base64.StdEncoding.EncodeToString([]byte("short"))
	viper.Set("master_key", shortKey)
	_, err := DecryptSecret("test")
	if err == nil {
		t.Error("expected error for short master key")
	}
}

func TestDecryptSecret_InvalidCiphertext(t *testing.T) {
	setupMasterKey(t)
	_, err := DecryptSecret("not-base64")
	if err == nil {
		t.Error("expected error for invalid base64 ciphertext")
	}
}

func TestDecryptSecret_CiphertextTooShort(t *testing.T) {
	setupMasterKey(t)
	// 12 bytes is a typical GCM nonce size, so use less than that
	short := base64.StdEncoding.EncodeToString([]byte{1, 2, 3, 4, 5})
	_, err := DecryptSecret(short)
	if err == nil {
		t.Error("expected error for ciphertext too short")
	}
}

func TestDecryptSecret_BadCiphertext(t *testing.T) {
	setupMasterKey(t)
	// Encrypt a value, then corrupt the ciphertext
	encrypted, err := EncryptSecret("hello")
	if err != nil {
		t.Fatalf("EncryptSecret failed: %v", err)
	}
	decoded, _ := base64.StdEncoding.DecodeString(encrypted)
	decoded[len(decoded)-1] ^= 0xFF // corrupt last byte
	bad := base64.StdEncoding.EncodeToString(decoded)
	_, err = DecryptSecret(bad)
	if err == nil {
		t.Error("expected error for corrupted ciphertext")
	}
}

func TestBurnPasswordCompare_DummyHashUsesProductionCost(t *testing.T) {
	cost, err := bcrypt.Cost(loadDummyHash())
	if err != nil {
		t.Fatalf("dummy hash is not a bcrypt hash: %v", err)
	}
	if cost != bcryptCost {
		t.Fatalf("dummy hash cost %d, want the production cost %d", cost, bcryptCost)
	}
}

func TestBurnPasswordCompare_BuildsDummyHashOnce(t *testing.T) {
	PrimeBurnPasswordCompare()
	first := loadDummyHash()
	BurnPasswordCompare("x")
	second := loadDummyHash()
	if len(first) == 0 || &first[0] != &second[0] {
		t.Fatal("the dummy hash must be built once and reused")
	}
}

func TestBurnPasswordCompare_CostsAsMuchAsARealCompare(t *testing.T) {
	hash, err := HashString("real")
	if err != nil {
		t.Fatal(err)
	}
	PrimeBurnPasswordCompare()

	// Take the fastest of a few runs on each side, so one slow scheduling
	// slice cannot fail the test.
	fastest := func(f func()) time.Duration {
		best := time.Duration(1<<63 - 1)
		for i := 0; i < 3; i++ {
			start := time.Now()
			f()
			if d := time.Since(start); d < best {
				best = d
			}
		}
		return best
	}
	realCompare := fastest(func() { _ = CheckPassword("x", hash) })
	burned := fastest(func() { BurnPasswordCompare("x") })

	// Same bcrypt cost, so the same order of magnitude; allow a wide band.
	if burned < realCompare/4 {
		t.Fatalf("dummy compare took %v, real compare %v", burned, realCompare)
	}
}

func TestIsUsableBcryptHash(t *testing.T) {
	usable, err := HashString("pw")
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string]bool{
		usable:                      true,
		"":                          false,
		"!system-account-no-login!": false,
		"hashed":                    false,
		// Right length and prefix, but the salt holds characters bcrypt's
		// alphabet lacks, so a compare would fail before the expensive part.
		"$2a$12$" + "!!!!!!!!!!!!!!!!!!!!!!" + usable[29:]: false,
	}
	for hash, want := range cases {
		if got := IsUsableBcryptHash(hash); got != want {
			t.Errorf("IsUsableBcryptHash(%q) = %v, want %v", hash, got, want)
		}
	}
}

// withBurnSpy replaces CheckPassword's dummy compare for one test and returns
// a pointer to the number of burns.
func withBurnSpy(t *testing.T) *int {
	t.Helper()
	burns := 0
	orig := burnPasswordCompare
	burnPasswordCompare = func(string) { burns++ }
	t.Cleanup(func() { burnPasswordCompare = orig })
	return &burns
}

// An account whose stored hash bcrypt rejects at once, an OIDC-only user or
// the system user, must still cost one compare, or the fast rejection
// reveals that it exists.
func TestCheckPassword_UnusableHashBurnsOnce(t *testing.T) {
	for _, hash := range []string{"", "!system-account-no-login!"} {
		burns := withBurnSpy(t)
		if err := CheckPassword("guess", hash); err == nil {
			t.Fatalf("CheckPassword accepted unusable hash %q", hash)
		}
		if *burns != 1 {
			t.Fatalf("hash %q: %d burns, want 1", hash, *burns)
		}
	}
}

// A real hash already pays the full compare, so neither a wrong nor a right
// password may burn a second one.
func TestCheckPassword_UsableHashDoesNotBurn(t *testing.T) {
	hash, err := HashString("right")
	if err != nil {
		t.Fatal(err)
	}
	burns := withBurnSpy(t)
	if err := CheckPassword("wrong", hash); err == nil {
		t.Fatal("wrong password accepted")
	}
	if err := CheckPassword("right", hash); err != nil {
		t.Fatalf("right password rejected: %v", err)
	}
	if *burns != 0 {
		t.Fatalf("%d burns, want 0", *burns)
	}
}

// A failed dummy hash must stop startup rather than leave every burn instant.
func TestBuildDummyHash_PanicsOnFailure(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("buildDummyHash must panic when hashing fails")
		}
	}()
	buildDummyHash(func([]byte, int) ([]byte, error) { return nil, bcrypt.ErrPasswordTooLong })
}
