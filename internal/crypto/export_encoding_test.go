package crypto

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"strings"
	"testing"

	secp256k1 "github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	pkcs12 "software.sslmate.com/src/go-pkcs12"
)

func TestMarshalPKCS8PrivateKeyPEM_RSAAndEC(t *testing.T) {
	for keyType, gen := range map[string]func() (string, error){
		"RSA":   func() (string, error) { return GenerateRSAKeyPEM(2048) },
		"ECDSA": func() (string, error) { return GenerateECDSAKeyPEM("P-256") },
	} {
		stored, err := gen()
		require.NoError(t, err)
		priv, err := ParsePrivateKey(stored, keyType)
		require.NoError(t, err)

		out, err := MarshalPKCS8PrivateKeyPEM(priv)
		require.NoError(t, err)
		assert.True(t, strings.HasPrefix(out, "-----BEGIN PRIVATE KEY-----\n"), "exact PKCS#8 prefix, no preamble")
		assert.NotContains(t, out, "RSA PRIVATE KEY")
		assert.NotContains(t, out, "EC PRIVATE KEY")

		block, _ := pem.Decode([]byte(out))
		require.NotNil(t, block)
		parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		require.NoError(t, err)
		switch keyType {
		case "RSA":
			assert.True(t, parsed.(*rsa.PrivateKey).Equal(priv))
		case "ECDSA":
			assert.True(t, parsed.(*ecdsa.PrivateKey).Equal(priv))
		}
	}
}

func TestMarshalPKCS8PrivateKeyPEM_ES256KIsRefused(t *testing.T) {
	k, err := secp256k1.GeneratePrivateKey()
	require.NoError(t, err)
	stored, err := MarshalSecp256k1PrivateKeyPEM(k)
	require.NoError(t, err)
	priv, err := ParsePrivateKey(stored, "ES256K")
	require.NoError(t, err)

	_, err = MarshalPKCS8PrivateKeyPEM(priv)
	require.True(t, errors.Is(err, ErrNotPKCS8Encodable))
}

func TestEncodePKCS12_ModernAndLegacyRoundTrip(t *testing.T) {
	stored, err := GenerateECDSAKeyPEM("P-256")
	require.NoError(t, err)
	certPEM, err := CreateSelfSignedCertificatePEM(stored, "ECDSA", CertificateTemplate{CommonName: "p12", ValidityDays: 1})
	require.NoError(t, err)
	priv, err := ParsePrivateKey(stored, "ECDSA")
	require.NoError(t, err)
	block, _ := pem.Decode([]byte(certPEM))
	leaf, err := x509.ParseCertificate(block.Bytes)
	require.NoError(t, err)

	for _, legacy := range []bool{false, true} {
		for _, password := range []string{"", "s3cret"} {
			pfx, err := EncodePKCS12(priv, leaf, nil, password, legacy)
			require.NoError(t, err)
			gotKey, gotLeaf, cas, err := pkcs12.DecodeChain(pfx, password)
			require.NoError(t, err, "legacy=%v password=%q", legacy, password)
			assert.True(t, gotKey.(*ecdsa.PrivateKey).Equal(priv))
			assert.Equal(t, leaf.Raw, gotLeaf.Raw)
			assert.Empty(t, cas)
		}
	}
}
