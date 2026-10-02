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

package api

import (
	"encoding/json"
	"time"

	"github.com/google/uuid"

	"rocketvault/model"
)

// CreateKeyRequest represents the request structure for creating a cryptographic key.
type CreateKeyRequest struct {
	Name      string     `json:"name"`              // Key name.
	Type      string     `json:"type"`              // Key type (RSA, ECDSA).
	Bits      int        `json:"bits"`              // RSA key size in bits (2048, 3072, or 4096).
	Curve     string     `json:"curve"`             // ECDSA curve (P-256, P-384, P-521).
	Tags      []string   `json:"tags"`              // Tags for the key.
	Enabled   *bool      `json:"enabled,omitempty"` // Defaults to true if nil.
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
	NotBefore *time.Time `json:"not_before,omitempty"`
	// PurgeProtection is optional; nil leaves the stored default alone.
	PurgeProtection *bool `json:"purge_protection,omitempty"`

	// Exportable requests an exportable key; immutable after creation. HSM
	// and OCT keys refuse it with 400.
	Exportable bool `json:"exportable,omitempty"`
}

// ImportKeyRequest represents the request structure for importing a
// cryptographic key from a JWK.
type ImportKeyRequest struct {
	Name      string          `json:"name"`
	JWK       json.RawMessage `json:"jwk"`
	Tags      []string        `json:"tags"`
	Enabled   *bool           `json:"enabled,omitempty"`
	ExpiresAt *time.Time      `json:"expires_at,omitempty"`
	NotBefore *time.Time      `json:"not_before,omitempty"`
	// PurgeProtection is optional; nil leaves the stored default alone.
	PurgeProtection *bool `json:"purge_protection,omitempty"`

	// Exportable requests an exportable key; immutable after creation. HSM
	// and OCT keys refuse it with 400.
	Exportable bool `json:"exportable,omitempty"`
}

// UpdateKeyRequest represents the request structure for updating a cryptographic key.
type UpdateKeyRequest struct {
	Name      *string    `json:"name,omitempty"`    // New name for the key.
	Revoked   *bool      `json:"revoked,omitempty"` // Set key revocation status.
	Tags      []string   `json:"tags,omitempty"`    // Replace existing tags.
	Enabled   *bool      `json:"enabled,omitempty"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
	NotBefore *time.Time `json:"not_before,omitempty"`
	// PurgeProtection is optional; nil means no change.
	PurgeProtection *bool `json:"purge_protection,omitempty"`
}

// KeyResponse represents the response structure for a cryptographic key.
type KeyResponse struct {
	ID        uuid.UUID  `json:"id"`
	Name      string     `json:"name"`
	Type      string     `json:"type"`
	UserID    uuid.UUID  `json:"user_id"`
	Revoked   bool       `json:"revoked"`
	CreatedAt time.Time  `json:"created_at"`
	UpdatedAt *time.Time `json:"updated_at,omitempty"`
	Tags      []string   `json:"tags"`
	Enabled   bool       `json:"enabled"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
	NotBefore *time.Time `json:"not_before,omitempty"`
	Bits      int        `json:"bits,omitempty"`
	Curve     string     `json:"curve,omitempty"`

	Exportable   bool   `json:"exportable"`    // Whether the key can be exported. Immutable.
	KeyAlgorithm string `json:"key_algorithm"` // Algorithm and size, such as RSA-2048 or EC-P256.

	// JWK public components (omitted for HSM-backed keys).
	N string `json:"n,omitempty"` // RSA modulus (base64url).
	E string `json:"e,omitempty"` // RSA public exponent (base64url).
	X string `json:"x,omitempty"` // EC x coordinate (base64url).
	Y string `json:"y,omitempty"` // EC y coordinate (base64url).
}

// KeyVersionResponse is one key version's metadata plus its public JWK
// components, matching what Azure Key Vault's GET /keys/{name}/{version}
// returns.
//
// It embeds model.KeyVersion rather than adding fields to it, so that type's
// no-material guarantee is untouched: there is deliberately no Value or PEM
// field here, and none may be added.
type KeyVersionResponse struct {
	model.KeyVersion
	N string `json:"n,omitempty"` // RSA modulus (base64url).
	E string `json:"e,omitempty"` // RSA public exponent (base64url).
	X string `json:"x,omitempty"` // EC x coordinate (base64url).
	Y string `json:"y,omitempty"` // EC y coordinate (base64url).
}

// KeyListResponse represents the response structure for listing keys.
type KeyListResponse struct {
	Keys []KeyResponse `json:"keys"`
}

// WrapKeyRequest is the HTTP request body for POST /keys/{key_id}/wrap.
type WrapKeyRequest struct {
	PlaintextKey string `json:"plaintext_key"`     // base64-encoded key material.
	Algorithm    string `json:"algorithm"`         // defaults to "RSA-OAEP".
	Version      int    `json:"version,omitempty"` // 0 = current
}

// WrapKeyResponse is the HTTP response for a successful wrap.
type WrapKeyResponse struct {
	WrappedKey string `json:"wrapped_key"` // base64-encoded wrapped bytes.
	Algorithm  string `json:"algorithm"`
	Version    int    `json:"version"` // the version actually used
}

// UnwrapKeyRequest is the HTTP request body for POST /keys/{key_id}/unwrap.
type UnwrapKeyRequest struct {
	WrappedKey string `json:"wrapped_key"`       // base64-encoded wrapped bytes.
	Algorithm  string `json:"algorithm"`         // defaults to "RSA-OAEP".
	Version    int    `json:"version,omitempty"` // 0 = current
}

// UnwrapKeyResponse is the HTTP response for a successful unwrap.
type UnwrapKeyResponse struct {
	PlaintextKey string `json:"plaintext_key"` // base64-encoded recovered key.
	Algorithm    string `json:"algorithm"`
	Version      int    `json:"version"` // the version actually used
}

// SignKeyRequest is the HTTP request body for POST /keys/{key_id}/sign.
type SignKeyRequest struct {
	Value     string `json:"value"`             // base64-encoded data to sign
	Algorithm string `json:"algorithm"`         // RS256, RS384, RS512, PS256, PS384, PS512, ES256, ES384, ES512
	Version   int    `json:"version,omitempty"` // 0 = current
}

// SignKeyResponse is the HTTP response for a successful sign.
type SignKeyResponse struct {
	KeyID     string `json:"key_id"`
	Algorithm string `json:"algorithm"`
	Value     string `json:"value"`   // base64-encoded signature
	Version   int    `json:"version"` // the version actually used
}

// VerifyKeyRequest is the HTTP request body for POST /keys/{key_id}/verify.
type VerifyKeyRequest struct {
	Value     string `json:"value"`     // base64-encoded original data
	Signature string `json:"signature"` // base64-encoded signature
	Algorithm string `json:"algorithm"`
	Version   int    `json:"version,omitempty"` // 0 = current
}

// VerifyKeyResponse is the HTTP response for a verify operation.
type VerifyKeyResponse struct {
	KeyID     string `json:"key_id"`
	Algorithm string `json:"algorithm"`
	Valid     bool   `json:"valid"`
	Version   int    `json:"version"` // the version actually used
}

// EncryptKeyRequest is the HTTP request body for POST /keys/{key_id}/encrypt.
type EncryptKeyRequest struct {
	Value     string `json:"value"`             // base64-encoded plaintext
	Algorithm string `json:"algorithm"`         // RSA-OAEP, RSA-OAEP-256, AES256-GCM
	Version   int    `json:"version,omitempty"` // 0 = current
}

// EncryptKeyResponse is the HTTP response for a successful encrypt.
type EncryptKeyResponse struct {
	KeyID     string `json:"key_id"`
	Algorithm string `json:"algorithm"`
	Value     string `json:"value"`           // base64-encoded ciphertext
	Nonce     string `json:"nonce,omitempty"` // base64-encoded, for AES-GCM
	Version   int    `json:"version"`         // the version actually used
}

// DecryptKeyRequest is the HTTP request body for POST /keys/{key_id}/decrypt.
type DecryptKeyRequest struct {
	Value     string `json:"value"`           // base64-encoded ciphertext
	Nonce     string `json:"nonce,omitempty"` // base64-encoded, for AES-GCM
	Algorithm string `json:"algorithm"`
	Version   int    `json:"version,omitempty"` // 0 = current
}

// DecryptKeyResponse is the HTTP response for a successful decrypt.
type DecryptKeyResponse struct {
	KeyID     string `json:"key_id"`
	Algorithm string `json:"algorithm"`
	Value     string `json:"value"`   // base64-encoded plaintext
	Version   int    `json:"version"` // the version actually used
}
