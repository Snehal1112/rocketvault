package rekey

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"rocketvault/common"
)

// testKey builds a deterministic 32-byte key. Distinct seeds give distinct keys.
func testKey(seed byte) []byte {
	key := make([]byte, 32)
	for i := range key {
		key[i] = seed + byte(i)
	}
	return key
}

func TestClassify_ReEncryptsOldKeyValue(t *testing.T) {
	oldKey, newKey := testKey(1), testKey(100)
	sealed, err := common.EncryptWithKey("secret-value", oldKey)
	require.NoError(t, err)

	act, resealed, err := classify(sealed, oldKey, newKey)
	require.NoError(t, err)
	assert.Equal(t, actionReEncrypt, act)
	assert.NotEqual(t, sealed, resealed)

	plaintext, err := common.DecryptWithKey(resealed, newKey)
	require.NoError(t, err)
	assert.Equal(t, "secret-value", plaintext)
}

func TestClassify_DetectsAlreadyMigratedValue(t *testing.T) {
	oldKey, newKey := testKey(1), testKey(100)
	sealed, err := common.EncryptWithKey("secret-value", newKey)
	require.NoError(t, err)

	act, resealed, err := classify(sealed, oldKey, newKey)
	require.NoError(t, err)
	assert.Equal(t, actionAlreadyNewKey, act)
	assert.Empty(t, resealed)
}

func TestClassify_SkipsPKCS11Handle(t *testing.T) {
	act, resealed, err := classify("pkcs11:6f1c0a3e-1c1a-4a5f-9a3e-2b0d5f8c1a77", testKey(1), testKey(100))
	require.NoError(t, err)
	assert.Equal(t, actionSkipExternal, act)
	assert.Empty(t, resealed)
}

func TestClassify_UndecryptableValue(t *testing.T) {
	sealed, err := common.EncryptWithKey("secret-value", testKey(50))
	require.NoError(t, err)

	_, _, err = classify(sealed, testKey(1), testKey(100))
	assert.True(t, errors.Is(err, ErrUndecryptable), "expected ErrUndecryptable, got %v", err)
}

func TestClassify_GarbageValue(t *testing.T) {
	_, _, err := classify("this is not ciphertext", testKey(1), testKey(100))
	assert.True(t, errors.Is(err, ErrUndecryptable), "expected ErrUndecryptable, got %v", err)
}

// The zero value must never be an actionable instruction, so a caller that
// reads the action before checking the error cannot be told to re-encrypt with
// an empty resealed value. Mirrors the ScopeInvalid convention in model/scope.go.
func TestClassify_ErrorPathsReturnInvalidAction(t *testing.T) {
	var zero action
	assert.Equal(t, actionInvalid, zero, "the zero value must be actionInvalid")
	assert.NotEqual(t, actionInvalid, actionReEncrypt)

	sealed, err := common.EncryptWithKey("secret-value", testKey(50))
	require.NoError(t, err)

	cases := map[string]string{
		"undecryptable": sealed,
		"garbage":       "this is not ciphertext",
	}
	for name, value := range cases {
		t.Run(name, func(t *testing.T) {
			act, resealed, err := classify(value, testKey(1), testKey(100))
			require.Error(t, err)
			assert.Equal(t, actionInvalid, act)
			assert.NotEqual(t, actionReEncrypt, act, "the error path must not return the destructive action")
			assert.Empty(t, resealed)
		})
	}
}

func TestTargets_CoverEveryMasterKeyColumn(t *testing.T) {
	got := map[string]string{}
	for _, target := range Targets() {
		got[target.Table] = target.Column
	}

	assert.Equal(t, map[string]string{
		"secrets":              "value",
		"secret_versions":      "value",
		"keys":                 "value",
		"key_versions":         "value",
		"certificates":         "private_key",
		"certificate_versions": "private_key",
	}, got)
}

func TestTarget_SelectSQL(t *testing.T) {
	target := Target{Table: "key_versions", Column: "value", KeyColumns: []string{"key_id", "version"}}
	assert.Equal(t, "SELECT key_id, version, value FROM key_versions", target.SelectSQL())
}

func TestTarget_UpdateSQL(t *testing.T) {
	target := Target{Table: "key_versions", Column: "value", KeyColumns: []string{"key_id", "version"}}
	assert.Equal(t,
		"UPDATE key_versions SET value = ? WHERE key_id = ? AND version = ? AND value = ?",
		target.UpdateSQL())
}
