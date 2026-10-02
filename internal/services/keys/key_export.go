package keys

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/google/uuid"

	"rocketvault/common"
	"rocketvault/internal/crypto"
	"rocketvault/model"
)

// ExportKeyResult is one exported key version. It carries private material
// and must never be logged, cached or stored.
type ExportKeyResult struct {
	ID            uuid.UUID
	Name          string
	Type          string
	Version       int
	Format        string // Always model.ExportFormatPEM.
	PrivateKeyPEM string // Unencrypted PKCS#8.
	KeyAlgorithm  string
}

// ExportKey implements KeyService.ExportKey. It sits beside GetPublicJWK and
// shares its version resolution, but it never touches keyCache: that cache
// is for crypto operations, and an export must not leave plaintext behind.
func (s *keyService) ExportKey(ctx context.Context, scope model.Scope, id uuid.UUID, version int) (*ExportKeyResult, error) {
	actor := scope.ActorID().String()
	if version < 0 {
		return nil, fmt.Errorf("%w: version must be 0 or a positive version number", model.ErrInvalidExportRequest)
	}

	// The scoped read and the lifecycle gate.
	key, err := s.GetKey(ctx, id, scope)
	if err != nil {
		return nil, err
	}
	// A revoked key is refused before anything is decrypted, matching the
	// crypto operations, which refuse it with ErrKeyRevoked.
	if key.Revoked {
		s.logger.LogAuditError(actor, "export_key", "denied", fmt.Sprintf("Key %s is revoked", id), nil)
		return nil, fmt.Errorf("%w", ErrKeyLifecycleDenied)
	}
	refuse := func(reason string) error {
		s.logger.LogAuditError(actor, "export_key", "denied", fmt.Sprintf("Key %s not exportable: %s", id, reason), nil)
		return &model.ExportRefusedError{Sentinel: model.ErrKeyNotExportable, Reason: reason, Name: key.Name, KeyAlgorithm: key.KeyAlgorithm()}
	}
	// Oct keys are always HSM-backed, so the type is checked first to give
	// the more specific reason.
	if key.Type == model.KeyTypeOct {
		return nil, refuse("symmetric oct keys are not exportable")
	}
	if key.Type == model.KeyTypeES256K {
		return nil, refuse("ES256K (secp256k1) keys cannot be encoded as PKCS#8")
	}
	if strings.HasPrefix(key.Value, pkcs11Prefix) {
		return nil, refuse("HSM-backed keys never leave the token")
	}
	if !key.Exportable {
		return nil, refuse("the key was not created with exportable: true")
	}

	// Resolve the version number first, then read that version's own row.
	// RotateKey writes the new version's row before it updates keys.value,
	// and ReadVersionValue falls back to keys.value only for a never-rotated
	// version 1. The number and the material therefore always come from the
	// same row, even during a concurrent rotation. The scoped read above
	// authorizes the version row.
	current, err := s.keyRepo.CurrentVersion(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("resolve current version: %w", err)
	}
	if version == 0 {
		version = current
	}
	if version > current {
		return nil, fmt.Errorf("%w: key %s has no version %d", model.ErrKeyVersionNotFound, id, version)
	}
	stored, err := s.keyRepo.ReadVersionValue(ctx, id, version)
	if err != nil {
		return nil, err
	}
	if strings.HasPrefix(stored, pkcs11Prefix) {
		return nil, refuse("HSM-backed keys never leave the token")
	}

	keyPEM, err := common.DecryptSecret(stored)
	if err != nil {
		return nil, fmt.Errorf("decrypt key material: %w", err)
	}
	priv, err := crypto.ParsePrivateKey(keyPEM, key.Type)
	if err != nil {
		return nil, fmt.Errorf("parse key material: %w", err)
	}
	out, err := crypto.MarshalPKCS8PrivateKeyPEM(priv)
	if errors.Is(err, crypto.ErrNotPKCS8Encodable) {
		return nil, refuse("the key type cannot be encoded as PKCS#8")
	}
	if err != nil {
		return nil, fmt.Errorf("encode key material: %w", err)
	}

	s.logger.LogAuditInfo(actor, "export_key", "success", fmt.Sprintf("Key %s version %d exported", id, version))
	return &ExportKeyResult{
		ID: key.ID, Name: key.Name, Type: key.Type, Version: version, Format: model.ExportFormatPEM,
		PrivateKeyPEM: out, KeyAlgorithm: key.KeyAlgorithm(),
	}, nil
}
