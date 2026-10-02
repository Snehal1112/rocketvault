package crypto

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"

	pkcs12 "software.sslmate.com/src/go-pkcs12"
)

// ErrNotPKCS8Encodable is returned for a private key the standard library
// cannot encode as PKCS#8, such as a secp256k1 (ES256K) key.
var ErrNotPKCS8Encodable = errors.New("key type cannot be encoded as PKCS#8")

// MarshalPKCS8PrivateKeyPEM encodes priv as an unencrypted PKCS#8 PEM block.
// The result starts exactly with "-----BEGIN PRIVATE KEY-----" and carries
// no preamble. Stored keys are PKCS#1 or SEC1; export always emits PKCS#8.
func MarshalPKCS8PrivateKeyPEM(priv any) (string, error) {
	switch priv.(type) {
	case *rsa.PrivateKey, *ecdsa.PrivateKey, ed25519.PrivateKey:
	default:
		return "", ErrNotPKCS8Encodable
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return "", fmt.Errorf("%w: %w", ErrNotPKCS8Encodable, err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})), nil
}

// EncodePKCS12 builds a PKCS12 bundle of priv, leaf and the intermediates.
// The modern encoder is the default; legacy selects PBE-SHA1-3DES with a
// SHA-1 MAC for old consumers. An empty password is allowed.
func EncodePKCS12(priv any, leaf *x509.Certificate, intermediates []*x509.Certificate, password string, legacy bool) ([]byte, error) {
	enc := pkcs12.Modern
	if legacy {
		enc = pkcs12.LegacyDES
	}
	pfx, err := enc.Encode(priv, leaf, intermediates, password)
	if err != nil {
		return nil, fmt.Errorf("encode pkcs12: %w", err)
	}
	return pfx, nil
}
