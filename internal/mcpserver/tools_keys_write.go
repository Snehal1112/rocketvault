package mcpserver

import (
	"context"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"rocketvault/internal/vaultapi"
)

type createKeyArgs struct {
	Name       string   `json:"name" jsonschema:"the new key's name"`
	Type       string   `json:"type" jsonschema:"RSA, ECDSA or OCT"`
	Bits       int      `json:"bits,omitempty" jsonschema:"key size for RSA (2048, 3072, 4096) or OCT (128, 192, 256)"`
	Curve      string   `json:"curve,omitempty" jsonschema:"curve for ECDSA, such as P-256, P-384 or P-521"`
	Tags       []string `json:"tags,omitempty" jsonschema:"tags to attach to the key"`
	Exportable bool     `json:"exportable,omitempty" jsonschema:"allow the key to be exported later; refused for HSM and OCT keys; cannot be changed after creation"`
	Vault      string   `json:"vault,omitempty" jsonschema:"the vault to create in; defaults to the server's configured vault"`
}

// createKeyResult describes the created key. It has no field for private
// material, and none may be added.
type createKeyResult struct {
	Vault   string `json:"vault"`
	Name    string `json:"name"`
	ID      string `json:"id"`
	Type    string `json:"type"`
	Bits    int    `json:"bits,omitempty"`
	Curve   string `json:"curve,omitempty"`
	Enabled bool   `json:"enabled"`
}

type rotateKeyArgs struct {
	Name  string `json:"name" jsonschema:"the key's name, or its id"`
	Vault string `json:"vault,omitempty" jsonschema:"the vault holding the key; defaults to the server's configured vault"`
}

type rotateKeyResult struct {
	Vault string `json:"vault"`
	Name  string `json:"name"`
	ID    string `json:"id"`
	Type  string `json:"type"`
}

// setKeyRotationPolicyArgs are the arguments to set_key_rotation_policy.
//
// Every policy field is required, with no omitempty, so the inferred schema
// marks it so. The underlying operation is a full replacement -- the server's
// request type has no pointer fields -- and a field that cannot be omitted
// cannot be accidentally zeroed. That makes replacement safe by construction,
// without a read-then-merge round trip or the TOCTOU window it would open.
//
// Enabled is a pointer despite being required, so that a missing value is
// rejected rather than read as false.
type setKeyRotationPolicyArgs struct {
	Name                   string `json:"name" jsonschema:"the key's name, or its id"`
	RotateAfterDays        int    `json:"rotate_after_days" jsonschema:"how many days after creation a version is rotated"`
	NotifyBeforeExpiryDays int    `json:"notify_before_expiry_days" jsonschema:"how many days before expiry to notify"`
	ExpiryDays             int    `json:"expiry_days" jsonschema:"how many days a version remains valid"`
	Enabled                *bool  `json:"enabled" jsonschema:"whether automatic rotation is active"`
	Vault                  string `json:"vault,omitempty" jsonschema:"the vault holding the key; defaults to the server's configured vault"`
}

type setKeyRotationPolicyResult struct {
	Vault                  string `json:"vault"`
	KeyName                string `json:"key_name"`
	RotateAfterDays        int    `json:"rotate_after_days"`
	NotifyBeforeExpiryDays int    `json:"notify_before_expiry_days"`
	ExpiryDays             int    `json:"expiry_days"`
	Enabled                bool   `json:"enabled"`
	NextRotationAt         string `json:"next_rotation_at,omitempty"`
}

// registerKeysWriteTools adds the write-tier key tools.
func registerKeysWriteTools(s *Server) {
	registerIf(s, TierWrite, "create_key",
		"Create a cryptographic key. Type must be RSA, ECDSA or OCT. "+
			"OCT (symmetric, AES) keys require the server to have an HSM configured, matching Azure Key Vault. "+
			"Never returns private key material.",
		Annotations{ReadOnly: false, Idempotent: false, Destructive: false},
		s.handleCreateKey)

	registerIf(s, TierWrite, "rotate_key",
		"Create a new version of an existing key. Previous versions remain and stay usable for verification and decryption.",
		// Not idempotent: each call creates another version.
		Annotations{ReadOnly: false, Idempotent: false, Destructive: false},
		s.handleRotateKey)

	registerIf(s, TierWrite, "set_key_rotation_policy",
		"Replaces a key's entire rotation policy. Every field is required, and any value not supplied would be lost, "+
			"so read the current policy with get_key first and pass all four values.",
		// A full replacement applied twice leaves the same state.
		Annotations{ReadOnly: false, Idempotent: true, Destructive: false},
		s.handleSetKeyRotationPolicy)
}

func (s *Server) handleCreateKey(ctx context.Context, _ *mcp.CallToolRequest, args createKeyArgs) (*mcp.CallToolResult, createKeyResult, error) {
	if args.Name == "" {
		return errorResult("create_key requires a name"), createKeyResult{}, nil
	}
	if args.Type == "" {
		return errorResult("create_key requires a type: RSA, ECDSA or OCT"), createKeyResult{}, nil
	}
	vault, err := s.ResolveVault(args.Vault)
	if err != nil {
		return errorResult("%s", err), createKeyResult{}, nil
	}

	key, err := s.client.CreateKey(ctx, vault, vaultapi.CreateKeyRequest{
		Name:       args.Name,
		Type:       args.Type,
		Bits:       args.Bits,
		Curve:      args.Curve,
		Tags:       args.Tags,
		Exportable: args.Exportable,
	})
	if err != nil {
		return errorResult("could not create key %q in vault %q: %s", args.Name, vault, err), createKeyResult{}, nil
	}

	return nil, createKeyResult{
		Vault:   vault,
		Name:    key.Name,
		ID:      key.ID.String(),
		Type:    key.Type,
		Bits:    key.Bits,
		Curve:   key.Curve,
		Enabled: key.Enabled,
	}, nil
}

func (s *Server) handleRotateKey(ctx context.Context, _ *mcp.CallToolRequest, args rotateKeyArgs) (*mcp.CallToolResult, rotateKeyResult, error) {
	if args.Name == "" {
		return errorResult("rotate_key requires a name"), rotateKeyResult{}, nil
	}
	vault, err := s.ResolveVault(args.Vault)
	if err != nil {
		return errorResult("%s", err), rotateKeyResult{}, nil
	}

	key, err := s.client.RotateKey(ctx, vault, args.Name)
	if err != nil {
		return errorResult("could not rotate key %q in vault %q: %s", args.Name, vault, err), rotateKeyResult{}, nil
	}

	return nil, rotateKeyResult{
		Vault: vault,
		Name:  key.Name,
		ID:    key.ID.String(),
		Type:  key.Type,
	}, nil
}

func (s *Server) handleSetKeyRotationPolicy(ctx context.Context, _ *mcp.CallToolRequest, args setKeyRotationPolicyArgs) (*mcp.CallToolResult, setKeyRotationPolicyResult, error) {
	if args.Name == "" {
		return errorResult("set_key_rotation_policy requires a name"), setKeyRotationPolicyResult{}, nil
	}
	if args.Enabled == nil {
		return errorResult(
			"set_key_rotation_policy requires enabled: this call replaces the whole policy, " +
				"so every field must be supplied. Read the current values with get_key first."), setKeyRotationPolicyResult{}, nil
	}
	vault, err := s.ResolveVault(args.Vault)
	if err != nil {
		return errorResult("%s", err), setKeyRotationPolicyResult{}, nil
	}

	policy, err := s.client.UpsertKeyRotationPolicy(ctx, vault, args.Name, vaultapi.SetKeyRotationPolicyRequest{
		RotateAfterDays:        args.RotateAfterDays,
		NotifyBeforeExpiryDays: args.NotifyBeforeExpiryDays,
		ExpiryDays:             args.ExpiryDays,
		Enabled:                *args.Enabled,
	})
	if err != nil {
		return errorResult("could not set the rotation policy for key %q in vault %q: %s",
			args.Name, vault, err), setKeyRotationPolicyResult{}, nil
	}

	result := setKeyRotationPolicyResult{
		Vault:                  vault,
		KeyName:                args.Name,
		RotateAfterDays:        policy.RotateAfterDays,
		NotifyBeforeExpiryDays: policy.NotifyBeforeExpiryDays,
		ExpiryDays:             policy.ExpiryDays,
		Enabled:                policy.Enabled,
	}
	if !policy.NextRotationAt.IsZero() {
		result.NextRotationAt = policy.NextRotationAt.Format(time.RFC3339)
	}
	return nil, result, nil
}
