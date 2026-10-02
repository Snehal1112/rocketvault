package validation

import (
	"math"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"

	"rocketvault/model"
)

// TestValidateSecretCreate tests secret creation validation.
func TestValidateSecretCreate(t *testing.T) {
	t.Parallel()
	validExpiresAt := time.Now().Add(24 * time.Hour)
	validNotBefore := time.Now()

	tests := []struct {
		name      string
		request   SecretCreateRequest
		wantError bool
	}{
		{
			name: "valid secret",
			request: SecretCreateRequest{
				Name:    "my-secret",
				Value:   "secret-value",
				Tags:    []string{"env:prod"},
				Enabled: true,
			},
			wantError: false,
		},
		{
			name: "valid with lifecycle",
			request: SecretCreateRequest{
				Name:      "my-secret",
				Value:     "secret-value",
				NotBefore: &validNotBefore,
				ExpiresAt: &validExpiresAt,
			},
			wantError: false,
		},
		{
			name: "missing name",
			request: SecretCreateRequest{
				Value: "secret-value",
			},
			wantError: true,
		},
		{
			name: "missing value",
			request: SecretCreateRequest{
				Name: "my-secret",
			},
			wantError: true,
		},
		{
			name: "name too long",
			request: SecretCreateRequest{
				Name:  string(make([]byte, 128)),
				Value: "secret-value",
			},
			wantError: true,
		},
		{
			name: "too many tags",
			request: SecretCreateRequest{
				Name:  "my-secret",
				Value: "secret-value",
				Tags:  make([]string, 16),
			},
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := ValidateSecretCreate(tt.request)
			if tt.wantError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// TestValidateKeyCreate tests key creation validation.
func TestValidateKeyCreate(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name      string
		request   KeyCreateRequest
		wantError bool
	}{
		{
			name: "valid RSA key",
			request: KeyCreateRequest{
				Name: "my-rsa-key",
				Type: model.KeyTypeRSA,
				Bits: 2048,
			},
			wantError: false,
		},
		{
			name: "valid ECDSA key",
			request: KeyCreateRequest{
				Name:  "my-ecdsa-key",
				Type:  model.KeyTypeECDSA,
				Curve: "P-256",
			},
			wantError: false,
		},
		{
			name: "valid 3072 bit RSA key",
			request: KeyCreateRequest{
				Name: "my-3072-rsa-key",
				Type: model.KeyTypeRSA,
				Bits: 3072,
			},
			wantError: false,
		},
		{
			name: "invalid RSA bits",
			request: KeyCreateRequest{
				Name: "my-rsa-key",
				Type: model.KeyTypeRSA,
				Bits: 1024,
			},
			wantError: true,
		},
		{
			name: "invalid ECDSA curve",
			request: KeyCreateRequest{
				Name:  "my-ecdsa-key",
				Type:  model.KeyTypeECDSA,
				Curve: "invalid-curve",
			},
			wantError: true,
		},
		{
			name: "valid ECDSA P-256K key",
			request: KeyCreateRequest{
				Name:  "my-secp256k1-key",
				Type:  model.KeyTypeECDSA,
				Curve: "P-256K",
			},
			wantError: false,
		},
		{
			name: "missing name",
			request: KeyCreateRequest{
				Type: model.KeyTypeRSA,
				Bits: 2048,
			},
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := ValidateKeyCreate(tt.request)
			if tt.wantError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestValidateKeyRotationPolicy(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name      string
		request   KeyRotationPolicyRequest
		wantError bool
	}{
		{
			name:      "zero days while enabled is rejected",
			request:   KeyRotationPolicyRequest{RotateAfterDays: 0, Enabled: true},
			wantError: true,
		},
		{
			name:      "negative days while enabled is rejected",
			request:   KeyRotationPolicyRequest{RotateAfterDays: -1, Enabled: true},
			wantError: true,
		},
		{
			name:      "below the 7-day minimum while enabled is rejected",
			request:   KeyRotationPolicyRequest{RotateAfterDays: 3, Enabled: true},
			wantError: true,
		},
		{
			name:      "exactly 7 days while enabled is accepted",
			request:   KeyRotationPolicyRequest{RotateAfterDays: 7, Enabled: true},
			wantError: false,
		},
		{
			name:      "below the minimum is accepted while disabled",
			request:   KeyRotationPolicyRequest{RotateAfterDays: 3, Enabled: false},
			wantError: false,
		},
		{
			name:      "zero days is accepted while disabled",
			request:   KeyRotationPolicyRequest{RotateAfterDays: 0, Enabled: false},
			wantError: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := ValidateKeyRotationPolicy(tt.request)
			if tt.wantError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// TestCommonValidationRules tests common validation rules.
func TestCommonValidationRules(t *testing.T) {
	t.Parallel()
	rules := &CommonValidationRules{}

	t.Run("email validation", func(t *testing.T) {
		t.Parallel()
		assert.NoError(t, rules.ValidateEmail("user@example.com"))
		assert.Error(t, rules.ValidateEmail("invalid-email"))
		assert.Error(t, rules.ValidateEmail(""))
	})

	t.Run("username validation", func(t *testing.T) {
		t.Parallel()
		assert.NoError(t, rules.ValidateUsername("validuser123"))
		assert.NoError(t, rules.ValidateUsername("user-name_1"))
		assert.Error(t, rules.ValidateUsername("ab")) // too short
		assert.Error(t, rules.ValidateUsername("invalid@user"))
	})

	t.Run("password validation", func(t *testing.T) {
		t.Parallel()
		assert.NoError(t, rules.ValidatePassword("SecurePass123!"))
		assert.NoError(t, rules.ValidatePassword("MyP@ssw0rd"))
		assert.Error(t, rules.ValidatePassword("weak"))          // too short
		assert.Error(t, rules.ValidatePassword("onlylowercase")) // weak
		assert.Error(t, rules.ValidatePassword("12345678"))      // no letters
	})

	t.Run("tag validation", func(t *testing.T) {
		t.Parallel()
		assert.NoError(t, rules.ValidateTag("env:prod"))
		assert.Error(t, rules.ValidateTag(""))
		assert.Error(t, rules.ValidateTag(string(make([]byte, 257)))) // too long
	})

	t.Run("tags validation", func(t *testing.T) {
		t.Parallel()
		assert.NoError(t, rules.ValidateTags([]string{"tag1", "tag2"}))
		assert.NoError(t, rules.ValidateTags([]string{}))
		assert.Error(t, rules.ValidateTags(make([]string, 16))) // too many
	})
}

// TestSecretNamePattern tests secret name pattern matching.
func TestSecretNamePattern(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name  string
		input string
		valid bool
	}{
		{"valid name", "my-secret", true},
		{"valid with numbers", "secret123", true},
		{"valid with hyphens", "my-secret-123", true},
		{"invalid - starts with number", "123secret", false},
		{"invalid - starts with hyphen", "-secret", false},
		{"invalid - special chars", "my_secret", false},
		{"invalid - spaces", "my secret", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matched := SecretNamePattern.MatchString(tt.input)
			assert.Equal(t, tt.valid, matched)
		})
	}
}

// TestValidateSecret tests full domain secret validation.
func TestValidateSecret(t *testing.T) {
	validSecret := &model.Secret{
		ID:      uuid.New(),
		UserID:  uuid.New(),
		Name:    "my-secret",
		Value:   "encrypted-value",
		Version: 1,
		Tags:    []string{"env:prod"},
		Enabled: true,
	}

	assert.NoError(t, ValidateSecret(validSecret))

	invalidSecret := &model.Secret{
		ID:     uuid.Nil,
		UserID: uuid.Nil,
		Name:   "",
		Value:  "",
	}

	assert.Error(t, ValidateSecret(invalidSecret))
}

// TestCreateRSAKey_3072Accepted verifies that 3072-bit RSA keys pass validation.
func TestCreateRSAKey_3072Accepted(t *testing.T) {
	err := ValidateKeyCreate(KeyCreateRequest{
		Name: "test-3072",
		Type: model.KeyTypeRSA,
		Bits: 3072,
	})
	assert.NoError(t, err, "3072-bit RSA should be valid")
}

// TestValidateKey tests full domain key validation.
func TestValidateKey(t *testing.T) {
	validKey := &model.Key{
		ID:      uuid.New(),
		UserID:  uuid.New(),
		Name:    "my-key",
		Type:    model.KeyTypeRSA,
		Value:   "encrypted-key-data",
		Revoked: false,
	}

	assert.NoError(t, ValidateKey(validKey))

	invalidKey := &model.Key{
		ID:     uuid.Nil,
		UserID: uuid.Nil,
		Name:   "",
		Type:   "invalid",
	}

	assert.Error(t, ValidateKey(invalidKey))
}

// TestValidateCertificateCreate_ValidityDaysUpperBound pins B78. Without a
// cap, a huge value pushes NotAfter past X.509's four-digit year and the
// request fails deep inside certificate generation as a 500.
func TestValidateCertificateCreate_ValidityDaysUpperBound(t *testing.T) {
	t.Parallel()

	ok := ValidateCertificateCreate(CertificateCreateRequest{Name: "cert", ValidityDays: model.MaxCertificateValidityDays})
	assert.NoError(t, ok, "the maximum itself is allowed")

	tooLong := ValidateCertificateCreate(CertificateCreateRequest{Name: "cert", ValidityDays: model.MaxCertificateValidityDays + 1})
	assert.Error(t, tooLong)

	// The lower bound belongs to the caller, so only the cap applies here.
	for _, days := range []int{1, 365} {
		assert.NoError(t, ValidateCertificateCreate(CertificateCreateRequest{Name: "cert", ValidityDays: days}), days)
	}
	assert.Error(t, ValidateCertificateCreate(CertificateCreateRequest{Name: "cert", ValidityDays: math.MaxInt}))
}
