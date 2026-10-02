package auth

import (
	"crypto/subtle"
	"encoding/base32"
	"fmt"
	"strings"
	"time"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/hotp"
	"github.com/pquerna/otp/totp"
)

// TOTPService handles Time-based One-Time Password operations.
// It provides TOTP generation, validation, and key management
// for multi-factor authentication.
type TOTPService interface {
	GenerateSecret(issuer, accountName string) (*otp.Key, error)
	ValidateCode(code, secret string, currentTime time.Time) (bool, error)
	// ValidateCodeWithStep validates code and returns the time step it belongs to,
	// so callers can refuse a step that was already used.
	ValidateCodeWithStep(code, secret string, currentTime time.Time) (int64, bool, error)
	GenerateCode(secret string, currentTime time.Time) (string, error)
}

// totpService implements TOTPService for TOTP operations.
type totpService struct {
	// TOTP configuration options
	period    uint
	skew      uint
	digits    otp.Digits
	algorithm otp.Algorithm
}

// NewTOTPService creates a new TOTPService with default TOTP parameters.
// It configures the service with standard TOTP settings:
// - 30 second period
// - 2 step skew tolerance
// - 6 digits
// - SHA1 algorithm
//
// Returns:
//
//	A TOTPService implementation for TOTP operations.
func NewTOTPService() TOTPService {
	return &totpService{
		period:    30,
		skew:      2,
		digits:    otp.DigitsSix,
		algorithm: otp.AlgorithmSHA1,
	}
}

// GenerateSecret creates a new TOTP secret key for a user account.
// It generates a secure random secret and returns the key with metadata
// including the QR code URL for user setup.
//
// Parameters:
//
//	issuer: The service name (e.g., "PasswordManager").
//	accountName: The user's account identifier (e.g., username).
//
// Returns:
//
//	The generated TOTP key and an error if generation fails.
func (s *totpService) GenerateSecret(issuer, accountName string) (*otp.Key, error) {
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      issuer,
		AccountName: accountName,
		SecretSize:  20,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to generate TOTP secret: %w", err)
	}
	return key, nil
}

// ValidateCode verifies a TOTP code against a secret at a specific time.
// It uses the configured tolerance settings to allow for clock skew
// and provides secure validation of user-provided codes.
//
// Parameters:
//
//	code: The TOTP code to validate.
//	secret: The base32-encoded TOTP secret.
//	currentTime: The time to use for validation.
//
// Returns:
//
//	True if the code is valid, false otherwise, and an error if validation fails.
func (s *totpService) ValidateCode(code, secret string, currentTime time.Time) (bool, error) {
	opts := totp.ValidateOpts{
		Period:    s.period,
		Skew:      s.skew,
		Digits:    s.digits,
		Algorithm: s.algorithm,
	}

	valid, err := totp.ValidateCustom(code, secret, currentTime, opts)
	if err != nil {
		return false, fmt.Errorf("TOTP validation error: %w", err)
	}

	return valid, nil
}

// ValidateCodeWithStep verifies a TOTP code and returns the time step it matched.
// The step is the counter of the window slot that matched, which is Unix time
// divided by the period. It is not the current step. Callers record it to refuse
// a replay of the same code.
//
// It uses the same period, skew, digits and algorithm as ValidateCode. Like the
// library, it trims surrounding whitespace from the code.
//
// Timing: the library's totp.ValidateCustom stops at the first matching slot,
// which reveals through timing which slot matched. This method instead computes
// and compares every slot in the window with subtle.ConstantTimeCompare and picks
// the result with subtle.ConstantTimeSelect, so the work does not depend on which
// slot matched. A wrong length still returns early, as it does in the library;
// the length of a code is not secret.
//
// When several slots match, the latest step wins.
//
// Returns:
//
//	The matched step and true for a valid code. Zero and false with a nil error
//	for a wrong code or a wrong length. An error for an empty or malformed secret.
func (s *totpService) ValidateCodeWithStep(code, secret string, currentTime time.Time) (int64, bool, error) {
	// An empty secret decodes to an empty HMAC key that still yields codes, so
	// it must never validate. Spaces or padding alone count as empty too.
	if totpSecretIsEmpty(secret) {
		return 0, false, fmt.Errorf("TOTP validation error: empty secret")
	}

	code = strings.TrimSpace(code)
	if len(code) != s.digits.Length() {
		return 0, false, nil
	}

	period := int64(s.period)
	skew := int64(s.skew)
	current := currentTime.Unix() / period
	opts := hotp.ValidateOpts{Digits: s.digits, Algorithm: s.algorithm}

	matched := 0
	found := 0
	for step := current - skew; step <= current+skew; step++ {
		// A step before the Unix epoch cannot be a real code.
		if step < 0 {
			continue
		}
		expected, err := hotp.GenerateCodeCustom(secret, uint64(step), opts)
		if err != nil {
			return 0, false, fmt.Errorf("TOTP validation error: %w", err)
		}
		eq := subtle.ConstantTimeCompare([]byte(expected), []byte(code))
		matched = subtle.ConstantTimeSelect(eq, int(step), matched)
		found |= eq
	}

	if found != 1 {
		return 0, false, nil
	}
	return int64(matched), true, nil
}

// GenerateCode creates a TOTP code for a secret at a specific time.
// This is primarily used for testing purposes to generate valid codes
// for verification workflows.
//
// Parameters:
//
//	secret: The base32-encoded TOTP secret.
//	currentTime: The time to use for code generation.
//
// Returns:
//
//	The generated TOTP code and an error if generation fails.
func (s *totpService) GenerateCode(secret string, currentTime time.Time) (string, error) {
	code, err := totp.GenerateCodeCustom(secret, currentTime, totp.ValidateOpts{
		Period:    s.period,
		Skew:      s.skew,
		Digits:    s.digits,
		Algorithm: s.algorithm,
	})
	if err != nil {
		return "", fmt.Errorf("failed to generate TOTP code: %w", err)
	}
	return code, nil
}

// totpSecretIsEmpty reports whether a secret yields no HMAC key material.
// It normalizes the secret the same way the otp library does before decoding,
// so a secret made only of whitespace or base32 padding counts as empty.
// A secret that does not decode at all is not empty; validation rejects it.
func totpSecretIsEmpty(secret string) bool {
	trimmed := strings.TrimSpace(secret)
	if strings.TrimSpace(strings.TrimRight(trimmed, "=")) == "" {
		return true
	}
	if n := len(trimmed) % 8; n != 0 {
		trimmed += strings.Repeat("=", 8-n)
	}
	key, err := base32.StdEncoding.DecodeString(strings.ToUpper(trimmed))
	return err == nil && len(key) == 0
}
