package crypto

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"strings"
)

// KeyAlgorithmFromPublicKey returns a short label such as RSA-2048 or
// EC-P256 for a public key. An unknown type yields an empty string.
func KeyAlgorithmFromPublicKey(pub any) string {
	switch k := pub.(type) {
	case *rsa.PublicKey:
		return fmt.Sprintf("RSA-%d", k.N.BitLen())
	case *ecdsa.PublicKey:
		return "EC-" + strings.ReplaceAll(k.Curve.Params().Name, "-", "")
	case ed25519.PublicKey:
		return "Ed25519"
	}
	return ""
}

// KeyAlgorithmFromCertificatePEM returns the algorithm label of the public
// key in the first certificate of certPEM. It parses only; it never touches
// private material. An unparseable input yields an empty string.
func KeyAlgorithmFromCertificatePEM(certPEM string) string {
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		return ""
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return ""
	}
	return KeyAlgorithmFromPublicKey(cert.PublicKey)
}
