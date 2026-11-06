// Package signing provides the pluggable JWT signing key abstraction.
// Concrete providers (os_store, self_pki, external_pki) implement
// SigningKeyProvider and are selected at startup by jwt.key_source config.
package signing

import (
	"crypto"
	"fmt"

	"github.com/spf13/viper"

	"rocketvault/internal/repositories"
	auditServices "rocketvault/internal/services/audit"
	secretServices "rocketvault/internal/services/secrets"
)

// SigningKeyProvider supplies private/public key material for JWT operations.
type SigningKeyProvider interface {
	// PrivateKey returns the active signing key.
	PrivateKey() crypto.Signer
	// PublicKeys returns all active public keys (old + new during rotation).
	PublicKeys() []PublicKeyInfo
	// Algorithm returns "RS256" or "ES256".
	Algorithm() string
	// KeyID returns the kid for the current active key.
	KeyID() string
}

// PublicKeyInfo is one entry in the JWK Set.
type PublicKeyInfo struct {
	KeyID     string
	Algorithm string
	PublicKey crypto.PublicKey
}

// RotatableProvider is implemented by providers that support runtime key rotation.
type RotatableProvider interface {
	SigningKeyProvider
	// Rotate generates a new key and returns the new kid and overlap-until time.
	Rotate() (newKID string, overlapUntil string, err error)
}

// ProviderDeps holds optional dependencies needed by some providers.
type ProviderDeps struct {
	CryptoService secretServices.CryptographyService
	KeyRepository repositories.KeyRepositoryInterface
	// AuditService writes the critical row when self_pki generates a key.
	AuditService auditServices.AuditServiceInterface
}

// NewProvider constructs the appropriate SigningKeyProvider based on jwt.key_source.
func NewProvider(v *viper.Viper, deps ProviderDeps) (SigningKeyProvider, error) {
	source := v.GetString("jwt.key_source")
	if source == "" {
		source = "os_store"
	}

	switch source {
	case "os_store":
		cn := v.GetString("jwt.key_cn")
		if cn == "" {
			cn = "rocketvault"
		}
		return NewOSStoreProvider(cn)

	case "self_pki":
		if deps.CryptoService == nil || deps.KeyRepository == nil {
			return nil, fmt.Errorf("self_pki requires CryptoService and KeyRepository")
		}
		overlapStr := v.GetString("jwt.rotation_overlap")
		return NewSelfPKIProvider(deps.CryptoService, deps.KeyRepository, overlapStr, deps.AuditService)

	case "external_pki":
		keyFile := v.GetString("jwt.signing_key_file")
		return NewExternalPKIProvider(keyFile)

	default:
		return nil, fmt.Errorf("unknown jwt.key_source: %q (must be os_store, self_pki, or external_pki)", source)
	}
}
