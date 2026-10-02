package crypto

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestKeyAlgorithmFromPublicKey(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	assert.Equal(t, "RSA-2048", KeyAlgorithmFromPublicKey(&rsaKey.PublicKey))

	for curve, want := range map[elliptic.Curve]string{
		elliptic.P256(): "EC-P256", elliptic.P384(): "EC-P384", elliptic.P521(): "EC-P521",
	} {
		ecKey, err := ecdsa.GenerateKey(curve, rand.Reader)
		require.NoError(t, err)
		assert.Equal(t, want, KeyAlgorithmFromPublicKey(&ecKey.PublicKey))
	}
	assert.Equal(t, "", KeyAlgorithmFromPublicKey("not a key"))
}

func TestKeyAlgorithmFromCertificatePEM(t *testing.T) {
	keyPEM, err := GenerateECDSAKeyPEM("P-384")
	require.NoError(t, err)
	certPEM, err := CreateSelfSignedCertificatePEM(keyPEM, "ECDSA", CertificateTemplate{CommonName: "alg", ValidityDays: 1})
	require.NoError(t, err)
	assert.Equal(t, "EC-P384", KeyAlgorithmFromCertificatePEM(certPEM))
	assert.Equal(t, "", KeyAlgorithmFromCertificatePEM("garbage"))
}
