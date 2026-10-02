package vaultapi

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
)

// keyTypes are the values the server accepts (api/keys.go:338).
var keyTypes = []string{"RSA", "ECDSA", "OCT"}

// CreateKeyRequest describes a key to create.
type CreateKeyRequest struct {
	Name      string     `json:"name"`
	Type      string     `json:"type"`
	Bits      int        `json:"bits,omitempty"`
	Curve     string     `json:"curve,omitempty"`
	Tags      []string   `json:"tags,omitempty"`
	Enabled   *bool      `json:"enabled,omitempty"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
	NotBefore *time.Time `json:"not_before,omitempty"`
	// Exportable requests an exportable key. The server refuses it for HSM
	// and OCT keys, and it can never be changed later.
	Exportable bool `json:"exportable,omitempty"`
}

// CreateKey creates a key in vault.
//
// The type is checked locally because the accepted set is small, stable, and
// easy to get wrong -- "EC" is the natural guess and the server wants
// "ECDSA". Nothing else is: bit sizes, curves, and whether an OCT key is
// possible all depend on server configuration this client cannot see. An OCT
// key requires HSM (api/keys.go:430), which is the server's state to report.
func (c *Client) CreateKey(ctx context.Context, vault string, req CreateKeyRequest) (*Key, error) {
	if vault == "" {
		return nil, fmt.Errorf("vaultapi: vault is required to create a key")
	}
	if req.Name == "" {
		return nil, fmt.Errorf("vaultapi: key name is required")
	}
	if req.Type == "" {
		return nil, fmt.Errorf("vaultapi: key type is required; one of %s", strings.Join(keyTypes, ", "))
	}
	if !isKnownKeyType(req.Type) {
		return nil, fmt.Errorf("vaultapi: unknown key type %q; must be one of %s",
			req.Type, strings.Join(keyTypes, ", "))
	}

	var wire keyWire
	path := fmt.Sprintf("/api/v1/vaults/%s/keys", vault)
	if err := c.Do(ctx, http.MethodPost, path, req, &wire); err != nil {
		return nil, err
	}
	return keyFromWire(wire)
}

func isKnownKeyType(value string) bool {
	for _, known := range keyTypes {
		if known == value {
			return true
		}
	}
	return false
}

// RotateKey creates a new version of a key.
func (c *Client) RotateKey(ctx context.Context, vault, name string) (*Key, error) {
	if vault == "" {
		return nil, fmt.Errorf("vaultapi: vault is required to rotate a key")
	}
	if name == "" {
		return nil, fmt.Errorf("vaultapi: key name is required to rotate a key")
	}

	id, err := c.Resolver().Resolve(ctx, vault, KindKeys, name)
	if err != nil {
		return nil, err
	}

	var wire keyWire
	path := fmt.Sprintf("/api/v1/vaults/%s/keys/%s/rotate", vault, id)
	// The rotate route takes no body.
	if err := c.Do(ctx, http.MethodPost, path, nil, &wire); err != nil {
		return nil, err
	}
	return keyFromWire(wire)
}

// SetKeyRotationPolicyRequest is a complete rotation policy.
//
// Every field is a plain value, not a pointer, mirroring
// model.UpsertKeyRotationPolicyRequest (model/key_rotation_policy.go:32).
// That means an upsert is always a full replacement: omitting a field sets it
// to zero rather than leaving it alone. There is no partial update, and
// callers must present the operation that way rather than implying a merge.
type SetKeyRotationPolicyRequest struct {
	RotateAfterDays        int  `json:"rotate_after_days"`
	NotifyBeforeExpiryDays int  `json:"notify_before_expiry_days"`
	ExpiryDays             int  `json:"expiry_days"`
	Enabled                bool `json:"enabled"`
}

// UpsertKeyRotationPolicy replaces a key's rotation policy.
func (c *Client) UpsertKeyRotationPolicy(ctx context.Context, vault, name string, req SetKeyRotationPolicyRequest) (*KeyRotationPolicy, error) {
	if vault == "" {
		return nil, fmt.Errorf("vaultapi: vault is required to set a key rotation policy")
	}
	if name == "" {
		return nil, fmt.Errorf("vaultapi: key name is required to set a rotation policy")
	}

	id, err := c.Resolver().Resolve(ctx, vault, KindKeys, name)
	if err != nil {
		return nil, err
	}

	var wire struct {
		KeyID                  string     `json:"key_id"`
		RotateAfterDays        int        `json:"rotate_after_days"`
		NotifyBeforeExpiryDays int        `json:"notify_before_expiry_days"`
		ExpiryDays             int        `json:"expiry_days"`
		Enabled                bool       `json:"enabled"`
		LastRotatedAt          *time.Time `json:"last_rotated_at"`
		NextRotationAt         time.Time  `json:"next_rotation_at"`
	}

	path := fmt.Sprintf("/api/v1/vaults/%s/keys/%s/rotationpolicy", vault, id)
	if err := c.Do(ctx, http.MethodPut, path, req, &wire); err != nil {
		return nil, err
	}

	keyID, parseErr := uuid.Parse(wire.KeyID)
	if parseErr != nil {
		keyID = id
	}
	return &KeyRotationPolicy{
		KeyID:                  keyID,
		RotateAfterDays:        wire.RotateAfterDays,
		NotifyBeforeExpiryDays: wire.NotifyBeforeExpiryDays,
		ExpiryDays:             wire.ExpiryDays,
		Enabled:                wire.Enabled,
		LastRotatedAt:          wire.LastRotatedAt,
		NextRotationAt:         wire.NextRotationAt,
	}, nil
}
