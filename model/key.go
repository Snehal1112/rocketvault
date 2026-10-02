package model

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/google/uuid"
)

// Key represents a cryptographic key in the password manager.
type Key struct {
	ID               uuid.UUID  `json:"id"`
	UserID           uuid.UUID  `json:"user_id"`
	VaultID          uuid.UUID  `json:"vault_id"`
	Name             string     `json:"name"`
	Type             string     `json:"type"`
	Value            string     `json:"value"`
	Revoked          bool       `json:"revoked"`
	CreatedAt        time.Time  `json:"created_at"`
	Tags             []string   `json:"tags"`
	DeletedAt        *time.Time `json:"deleted_at,omitempty"`
	PurgeProtection  bool       `json:"purge_protection"`
	ScheduledPurgeAt *time.Time `json:"scheduled_purge_at,omitempty"`
	Enabled          bool       `json:"enabled"`
	ExpiresAt        *time.Time `json:"expires_at,omitempty"`
	NotBefore        *time.Time `json:"not_before,omitempty"`
	Bits             int        `json:"bits,omitempty"`
	Curve            string     `json:"curve,omitempty"`
	UpdatedAt        *time.Time `json:"updated_at,omitempty"`
	// Exportable reports whether the key's private material may ever be
	// exported. It is set at creation or import only; rotation keeps it
	// because rotation updates the same row. HSM and oct keys are never
	// exportable.
	Exportable bool `json:"exportable"`
}

// IsAccessible returns true when the key is enabled and within its validity window.
func (k *Key) IsAccessible() bool {
	if !k.Enabled {
		return false
	}
	now := time.Now()
	if k.NotBefore != nil && now.Before(*k.NotBefore) {
		return false
	}
	if k.ExpiresAt != nil && now.After(*k.ExpiresAt) {
		return false
	}
	return true
}

// KeyAlgorithm returns a short label for the key's algorithm and size, such
// as RSA-2048 or EC-P256. It reads only stored metadata, so it is safe on a
// list response and for HSM-backed keys. A size the row does not record
// yields the bare family name.
func (k *Key) KeyAlgorithm() string {
	switch k.Type {
	case KeyTypeRSA:
		if k.Bits > 0 {
			return fmt.Sprintf("RSA-%d", k.Bits)
		}
		return "RSA"
	case KeyTypeECDSA:
		if k.Curve != "" {
			return "EC-" + strings.ReplaceAll(k.Curve, "-", "")
		}
		return "EC"
	case KeyTypeES256K:
		return "EC-P256K"
	case KeyTypeOct:
		return fmt.Sprintf("oct-%d", k.Bits)
	}
	return k.Type
}

const (
	KeyTypeRSA    = "RSA"
	KeyTypeECDSA  = "ECDSA"
	KeyTypeES256K = "ES256K" // secp256k1 ECDSA
	KeyTypeOct    = "oct"    // Symmetric key (HMAC / AES)
)

// KeyVersion represents a single version snapshot of a cryptographic key.
// The raw key material (Value/PEM) is intentionally omitted from this struct
// to prevent accidental exposure in HTTP responses.
type KeyVersion struct {
	KeyID     uuid.UUID `json:"key_id"`
	Version   int       `json:"version"`
	CreatedAt time.Time `json:"created_at"`
}

// KeyVersionRecord carries one version's material for internal use only
// (the backup service). It is never marshaled into a key or key-version API
// response — those use KeyVersion, which has no Value field, so the
// versions-list and versions-get handlers cannot leak material even by
// future mistake. It IS marshaled into a key backup blob, which
// POST /keys/{key_id}/backup returns sealed under a master-key-derived key
// (B76). A blob must still be handled as key material: anyone holding the
// master key can open it. Value itself carries the same master-key-encrypted
// form the database stores.
type KeyVersionRecord struct {
	KeyID     uuid.UUID `json:"key_id"`
	Version   int       `json:"version"`
	Value     string    `json:"value"`
	CreatedAt time.Time `json:"created_at"`
}

// PublicJWK carries the public components of a key, in the base64url form JWK
// uses: N and E for RSA, X and Y for EC. It never carries private material,
// and no field may be added to it that would -- callers copy it straight onto
// HTTP responses.
//
// All four fields are empty for an HSM-backed key, whose material never leaves
// the token. That is a normal result, not an error.
type PublicJWK struct {
	N string `json:"n,omitempty"`
	E string `json:"e,omitempty"`
	X string `json:"x,omitempty"`
	Y string `json:"y,omitempty"`
}

// --- HTTP request/response types ---

type CreateKeyRequest struct {
	Name      string     `json:"name"`
	Type      string     `json:"type"`
	Bits      int        `json:"bits"`
	Curve     string     `json:"curve"`
	Tags      []string   `json:"tags"`
	Enabled   *bool      `json:"enabled,omitempty"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
	NotBefore *time.Time `json:"not_before,omitempty"`
	// PurgeProtection is optional; nil leaves the stored default alone.
	PurgeProtection *bool `json:"purge_protection,omitempty"`
}

func CreateKeyRequestFromJson(data io.Reader) (*CreateKeyRequest, error) {
	var r CreateKeyRequest
	return &r, json.NewDecoder(data).Decode(&r)
}

type UpdateKeyRequest struct {
	Name      *string    `json:"name,omitempty"`
	Revoked   *bool      `json:"revoked,omitempty"`
	Tags      []string   `json:"tags,omitempty"`
	Enabled   *bool      `json:"enabled,omitempty"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
	NotBefore *time.Time `json:"not_before,omitempty"`
	// PurgeProtection is optional; nil means no change.
	PurgeProtection *bool `json:"purge_protection,omitempty"`
}

func UpdateKeyRequestFromJson(data io.Reader) (*UpdateKeyRequest, error) {
	var r UpdateKeyRequest
	return &r, json.NewDecoder(data).Decode(&r)
}

type KeyResponse struct {
	ID        uuid.UUID  `json:"id"`
	Name      string     `json:"name"`
	Type      string     `json:"type"`
	UserID    uuid.UUID  `json:"user_id"`
	Revoked   bool       `json:"revoked"`
	CreatedAt time.Time  `json:"created_at"`
	Tags      []string   `json:"tags"`
	Enabled   bool       `json:"enabled"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
	NotBefore *time.Time `json:"not_before,omitempty"`
	Bits      int        `json:"bits,omitempty"`
	Curve     string     `json:"curve,omitempty"`
	UpdatedAt *time.Time `json:"updated_at,omitempty"`
}

func (r *KeyResponse) ToJson() string {
	b, _ := json.Marshal(r)
	return string(b)
}

type KeyListResponse struct {
	Keys []KeyResponse `json:"keys"`
}

func (r *KeyListResponse) ToJson() string {
	b, _ := json.Marshal(r)
	return string(b)
}

type WrapKeyRequest struct {
	PlaintextKey string `json:"plaintext_key"`
	Algorithm    string `json:"algorithm"`
}

func WrapKeyRequestFromJson(data io.Reader) (*WrapKeyRequest, error) {
	var r WrapKeyRequest
	return &r, json.NewDecoder(data).Decode(&r)
}

type WrapKeyResponse struct {
	WrappedKey string `json:"wrapped_key"`
	Algorithm  string `json:"algorithm"`
}

func (r *WrapKeyResponse) ToJson() string {
	b, _ := json.Marshal(r)
	return string(b)
}

type UnwrapKeyRequest struct {
	WrappedKey string `json:"wrapped_key"`
	Algorithm  string `json:"algorithm"`
}

func UnwrapKeyRequestFromJson(data io.Reader) (*UnwrapKeyRequest, error) {
	var r UnwrapKeyRequest
	return &r, json.NewDecoder(data).Decode(&r)
}

type UnwrapKeyResponse struct {
	PlaintextKey string `json:"plaintext_key"`
	Algorithm    string `json:"algorithm"`
}

func (r *UnwrapKeyResponse) ToJson() string {
	b, _ := json.Marshal(r)
	return string(b)
}
