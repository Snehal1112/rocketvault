package certificates

import (
	"context"
	gocrypto "crypto"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	pkcs12 "software.sslmate.com/src/go-pkcs12"

	"rocketvault/common"
	"rocketvault/internal/crypto"
	"rocketvault/model"
)

func strPtr(s string) *string { return &s }

// createExportable issues a self-signed exportable certificate over a fresh
// exportable key of the given type ("RSA" or "ECDSA").
func createExportable(t *testing.T, h *versioningHarness, name, keyType string) uuid.UUID {
	t.Helper()
	keyID := uuid.New()
	var keyPEM string
	var err error
	if keyType == "RSA" {
		keyPEM, err = crypto.GenerateRSAKeyPEM(2048)
	} else {
		keyPEM, err = crypto.GenerateECDSAKeyPEM("P-256")
	}
	require.NoError(t, err)
	enc, err := common.EncryptSecret(keyPEM)
	require.NoError(t, err)
	k := &model.Key{ID: keyID, UserID: h.userID, VaultID: h.vaultID, Name: name + "-key", Type: model.KeyTypeRSA,
		Value: enc, Enabled: true, CreatedAt: time.Now(), Bits: 2048, Exportable: true}
	if keyType != "RSA" {
		k.Type, k.Bits, k.Curve = model.KeyTypeECDSA, 0, "P-256"
	}
	require.NoError(t, h.keyRepo.Create(context.Background(), k))
	res, err := h.svc.CreateSelfSignedCertificate(context.Background(), CreateCertificateRequest{
		Name: name, KeyID: keyID, ValidityDays: 30, UserID: h.userID, VaultID: h.vaultID, Exportable: true,
	})
	require.NoError(t, err)
	return res.CertID
}

// insertCert stores a certificate row directly, for chains the create paths
// cannot build (intermediate CAs) and for edited-row guards.
func insertCert(t *testing.T, h *versioningHarness, vaultID uuid.UUID, certPEM, keyPEM string, caID *uuid.UUID) uuid.UUID {
	t.Helper()
	enc, err := common.EncryptSecret(keyPEM)
	require.NoError(t, err)
	id := uuid.New()
	require.NoError(t, h.certRepo.Create(context.Background(), &model.Certificate{
		ID: id, UserID: h.userID, VaultID: vaultID, KeyID: uuid.New(), CACertID: caID, Name: "c-" + id.String()[:8],
		Certificate: certPEM, PrivateKey: enc, CreatedAt: time.Now(), Enabled: true, Version: 1, Exportable: true,
	}))
	return id
}

func parsePEMCerts(t *testing.T, chain string) []*x509.Certificate {
	t.Helper()
	var out []*x509.Certificate
	rest := []byte(chain)
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			return out
		}
		c, err := x509.ParseCertificate(block.Bytes)
		require.NoError(t, err)
		out = append(out, c)
	}
}

func TestExportCertificate_PEM_RSAAndEC(t *testing.T) {
	h := newVersioningHarness(t)
	for keyType, alg := range map[string]string{"RSA": "RSA-2048", "ECDSA": "EC-P256"} {
		id := createExportable(t, h, "pem-"+strings.ToLower(keyType), keyType)
		res, err := h.svc.ExportCertificate(context.Background(), h.scope(), id, ExportCertificateRequest{Format: model.ExportFormatPEM})
		require.NoError(t, err)

		assert.True(t, strings.HasPrefix(res.PrivateKeyPEM, "-----BEGIN PRIVATE KEY-----\n"), "exact PKCS#8 prefix")
		assert.Equal(t, alg, res.KeyAlgorithm)
		assert.Equal(t, 1, res.Version)
		assert.Equal(t, model.ExportFormatPEM, res.Format)
		require.NotNil(t, res.NotBefore)
		require.NotNil(t, res.ExpiresAt)
		assert.True(t, res.PKCS12 == nil, "a pem export carries no PKCS#12 bytes")

		certs := parsePEMCerts(t, res.CertificatePEM)
		require.Len(t, certs, 1, "a self-signed leaf exports alone")
		block, _ := pem.Decode([]byte(res.PrivateKeyPEM))
		priv, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		require.NoError(t, err)
		leafPub := certs[0].PublicKey.(interface{ Equal(gocrypto.PublicKey) bool })
		assert.True(t, leafPub.Equal(priv.(gocrypto.Signer).Public()), "the key matches the leaf")
	}
}

func TestExportCertificate_PKCS12ModernLegacyAndEmptyPassword(t *testing.T) {
	h := newVersioningHarness(t)
	id := createExportable(t, h, "p12", "ECDSA")
	for _, compat := range []string{"", model.ExportCompatModern, model.ExportCompatLegacy} {
		for _, password := range []string{"", "s3cret"} {
			res, err := h.svc.ExportCertificate(context.Background(), h.scope(), id, ExportCertificateRequest{
				Format: model.ExportFormatPKCS12, Password: strPtr(password), Compat: compat,
			})
			require.NoError(t, err)
			assert.True(t, res.PrivateKeyPEM == "", "a pkcs12 export carries no separate private key PEM")
			_, leaf, cas, err := pkcs12.DecodeChain(res.PKCS12, password)
			require.NoError(t, err, "compat=%q empty-password=%t", compat, password == "")
			assert.Equal(t, "p12", leaf.Subject.CommonName)
			assert.Empty(t, cas)
		}
	}
}

func TestExportCertificate_RequestValidation(t *testing.T) {
	h := newVersioningHarness(t)
	id := createExportable(t, h, "bad", "RSA")
	const password = "zz-validation-secret-zz"
	for name, req := range map[string]ExportCertificateRequest{
		"unknown format":     {Format: "der", Password: strPtr(password)},
		"missing format":     {},
		"unknown compat":     {Format: model.ExportFormatPKCS12, Password: strPtr(password), Compat: "ancient"},
		"pkcs12 no password": {Format: model.ExportFormatPKCS12},
		"negative version":   {Format: model.ExportFormatPEM, Password: strPtr(password), Version: -1},
	} {
		_, err := h.svc.ExportCertificate(context.Background(), h.scope(), id, req)
		require.ErrorIs(t, err, model.ErrInvalidExportRequest, name)
		assert.NotContains(t, err.Error(), password, "the password never reaches the message: "+name)
	}
}

func TestExportCertificate_Refusals(t *testing.T) {
	h := newVersioningHarness(t)
	ctx := context.Background()

	// Not exportable: created over a key without the flag.
	plain, err := h.svc.CreateSelfSignedCertificate(ctx, CreateCertificateRequest{
		Name: "plain", KeyID: h.keyID, ValidityDays: 30, UserID: h.userID, VaultID: h.vaultID,
	})
	require.NoError(t, err)
	_, err = h.svc.ExportCertificate(ctx, h.scope(), plain.CertID, ExportCertificateRequest{Format: model.ExportFormatPEM})
	var refusal *model.ExportRefusedError
	require.True(t, errors.As(err, &refusal))
	assert.ErrorIs(t, err, model.ErrCertificateNotExportable)
	assert.Equal(t, "RSA-2048", refusal.KeyAlgorithm, "key_algorithm is reported on refusal too")
	assert.Equal(t, "plain", refusal.Name)

	// ES256K: a stored secp256k1 key cannot be encoded as PKCS#8.
	rsaKeyPEM, err := crypto.GenerateRSAKeyPEM(2048)
	require.NoError(t, err)
	leafPEM, err := crypto.CreateSelfSignedCertificatePEM(rsaKeyPEM, "RSA", crypto.CertificateTemplate{CommonName: "k1", ValidityDays: 1})
	require.NoError(t, err)
	k1, err := crypto.GenerateECDSAKeyPEM("P-256K")
	require.NoError(t, err)
	es := insertCert(t, h, h.vaultID, leafPEM, k1, nil)
	_, err = h.svc.ExportCertificate(ctx, h.scope(), es, ExportCertificateRequest{Format: model.ExportFormatPEM})
	require.ErrorIs(t, err, model.ErrCertificateNotExportable)
	assert.Contains(t, err.Error(), "PKCS#8")

	// Disabled.
	disabledID := createExportable(t, h, "disabled", "RSA")
	off := false
	require.NoError(t, h.svc.UpdateCertificate(ctx, UpdateCertificateRequest{CertID: disabledID, Scope: h.scope(), Enabled: &off}))
	_, err = h.svc.ExportCertificate(ctx, h.scope(), disabledID, ExportCertificateRequest{Format: model.ExportFormatPEM})
	require.ErrorIs(t, err, ErrCertLifecycleDenied)

	// Unknown, out of vault, soft-deleted.
	_, err = h.svc.ExportCertificate(ctx, h.scope(), uuid.New(), ExportCertificateRequest{Format: model.ExportFormatPEM})
	require.ErrorIs(t, err, ErrCertNotFound)
	other := model.NewVaultScope(uuid.New(), h.userID)
	okID := createExportable(t, h, "elsewhere", "RSA")
	_, err = h.svc.ExportCertificate(ctx, other, okID, ExportCertificateRequest{Format: model.ExportFormatPEM})
	require.ErrorIs(t, err, ErrCertNotFound)
	require.NoError(t, h.svc.DeleteCertificate(ctx, okID, h.scope()))
	_, err = h.svc.ExportCertificate(ctx, h.scope(), okID, ExportCertificateRequest{Format: model.ExportFormatPEM})
	require.ErrorIs(t, err, ErrCertNotFound)
}

func TestExportCertificate_VersionGating(t *testing.T) {
	h := newVersioningHarness(t)
	ctx := context.Background()
	id := createExportable(t, h, "versions", "RSA")
	_, err := h.svc.RenewCertificate(ctx, id, h.scope(), 30)
	require.NoError(t, err)

	v1, err := h.svc.ExportCertificate(ctx, h.scope(), id, ExportCertificateRequest{Format: model.ExportFormatPEM, Version: 1})
	require.NoError(t, err, "an enabled archived version exports")
	v2, err := h.svc.ExportCertificate(ctx, h.scope(), id, ExportCertificateRequest{Format: model.ExportFormatPEM})
	require.NoError(t, err)
	assert.Equal(t, 1, v1.Version)
	assert.Equal(t, 2, v2.Version)
	assert.False(t, v1.CertificatePEM == v2.CertificatePEM, "the archived version exports its own body")

	_, err = h.svc.ExportCertificate(ctx, h.scope(), id, ExportCertificateRequest{Format: model.ExportFormatPEM, Version: 3})
	require.ErrorIs(t, err, model.ErrCertificateVersionNotFound)

	off := false
	_, err = h.svc.UpdateCertificateVersion(ctx, UpdateCertificateVersionRequest{CertID: id, Version: 1, Scope: h.scope(), Enabled: &off})
	require.NoError(t, err)
	_, err = h.svc.ExportCertificate(ctx, h.scope(), id, ExportCertificateRequest{Format: model.ExportFormatPEM, Version: 1})
	require.ErrorIs(t, err, ErrCertLifecycleDenied, "a disabled archived version is a 409")

	on := true
	future := time.Now().Add(time.Hour)
	_, err = h.svc.UpdateCertificateVersion(ctx, UpdateCertificateVersionRequest{CertID: id, Version: 1, Scope: h.scope(), Enabled: &on, NotBefore: &future})
	require.NoError(t, err)
	_, err = h.svc.ExportCertificate(ctx, h.scope(), id, ExportCertificateRequest{Format: model.ExportFormatPEM, Version: 1})
	require.ErrorIs(t, err, ErrCertLifecycleDenied, "a not-yet-valid archived version is a 409")

	past := time.Now().Add(-time.Hour)
	before := past.Add(-time.Hour)
	_, err = h.svc.UpdateCertificateVersion(ctx, UpdateCertificateVersionRequest{CertID: id, Version: 1, Scope: h.scope(), NotBefore: &before, ExpiresAt: &past})
	require.NoError(t, err)
	_, err = h.svc.ExportCertificate(ctx, h.scope(), id, ExportCertificateRequest{Format: model.ExportFormatPEM, Version: 1})
	require.ErrorIs(t, err, ErrCertLifecycleDenied, "an expired archived version is a 409")

	require.NoError(t, h.svc.UpdateCertificate(ctx, UpdateCertificateRequest{CertID: id, Scope: h.scope(), Enabled: &off}))
	_, err = h.svc.ExportCertificate(ctx, h.scope(), id, ExportCertificateRequest{Format: model.ExportFormatPEM})
	require.ErrorIs(t, err, ErrCertLifecycleDenied, "a disabled certificate blocks every version")
}

// TestExportCertificate_ChainLeafFirstNoRoot builds root -> intermediate ->
// leaf directly in the repository (the create path refuses intermediate CAs)
// and checks the chain is leaf then intermediate, with the root excluded.
func TestExportCertificate_ChainLeafFirstNoRoot(t *testing.T) {
	h := newVersioningHarness(t)
	rootKey, err := crypto.GenerateRSAKeyPEM(2048)
	require.NoError(t, err)
	rootPEM, err := crypto.CreateSelfSignedCertificatePEM(rootKey, "RSA", crypto.CertificateTemplate{CommonName: "root", ValidityDays: 30, IsCA: true})
	require.NoError(t, err)
	intKey, err := crypto.GenerateRSAKeyPEM(2048)
	require.NoError(t, err)
	intPEM, err := crypto.CreateCASignedCertificatePEM(intKey, "RSA", rootPEM, rootKey, "RSA", crypto.CertificateTemplate{CommonName: "intermediate", ValidityDays: 30, IsCA: true})
	require.NoError(t, err)
	leafKey, err := crypto.GenerateECDSAKeyPEM("P-256")
	require.NoError(t, err)
	leafPEM, err := crypto.CreateCASignedCertificatePEM(leafKey, "ECDSA", intPEM, intKey, "RSA", crypto.CertificateTemplate{CommonName: "leaf", ValidityDays: 30})
	require.NoError(t, err)

	rootID := insertCert(t, h, h.vaultID, rootPEM, rootKey, nil)
	intID := insertCert(t, h, h.vaultID, intPEM, intKey, &rootID)
	leafID := insertCert(t, h, h.vaultID, leafPEM, leafKey, &intID)

	res, err := h.svc.ExportCertificate(context.Background(), h.scope(), leafID, ExportCertificateRequest{Format: model.ExportFormatPEM})
	require.NoError(t, err)
	certs := parsePEMCerts(t, res.CertificatePEM)
	require.Len(t, certs, 2)
	assert.Equal(t, "leaf", certs[0].Subject.CommonName)
	assert.Equal(t, "intermediate", certs[1].Subject.CommonName)

	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM([]byte(rootPEM))
	inters := x509.NewCertPool()
	inters.AddCert(certs[1])
	_, err = certs[0].Verify(x509.VerifyOptions{Roots: roots, Intermediates: inters, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}})
	require.NoError(t, err, "the exported chain verifies against the root")

	p12, err := h.svc.ExportCertificate(context.Background(), h.scope(), leafID, ExportCertificateRequest{Format: model.ExportFormatPKCS12, Password: strPtr("")})
	require.NoError(t, err)
	_, _, cas, err := pkcs12.DecodeChain(p12.PKCS12, "")
	require.NoError(t, err)
	require.Len(t, cas, 1)
	assert.Equal(t, "intermediate", cas[0].Subject.CommonName)
}

func TestExportCertificate_ChainGuards(t *testing.T) {
	h := newVersioningHarness(t)
	ctx := context.Background()
	caKey, err := crypto.GenerateRSAKeyPEM(2048)
	require.NoError(t, err)
	caPEM, err := crypto.CreateSelfSignedCertificatePEM(caKey, "RSA", crypto.CertificateTemplate{CommonName: "ca", ValidityDays: 30, IsCA: true})
	require.NoError(t, err)
	// hopPEM is CA-signed, so the walk never treats a hop as the root.
	hopPEM, err := crypto.CreateCASignedCertificatePEM(caKey, "RSA", caPEM, caKey, "RSA", crypto.CertificateTemplate{CommonName: "hop", ValidityDays: 30, IsCA: true})
	require.NoError(t, err)

	// Depth: a leaf over a straight line of 11 non-root hops exceeds the cap.
	var next *uuid.UUID
	for i := 0; i < maxExportChainDepth+1; i++ {
		id := insertCert(t, h, h.vaultID, hopPEM, caKey, next)
		next = &id
	}
	deep := insertCert(t, h, h.vaultID, hopPEM, caKey, next)
	_, err = h.svc.ExportCertificate(ctx, h.scope(), deep, ExportCertificateRequest{Format: model.ExportFormatPEM})
	require.ErrorIs(t, err, ErrCertificateChainUnavailable)

	// Cycle: a and b name each other.
	a := insertCert(t, h, h.vaultID, hopPEM, caKey, nil)
	b := insertCert(t, h, h.vaultID, hopPEM, caKey, &a)
	_, err = h.raw.ExecContext(context.Background(), "UPDATE certificates SET ca_cert_id = ? WHERE id = ?", b.String(), a.String())
	require.NoError(t, err)
	_, err = h.svc.ExportCertificate(ctx, h.scope(), a, ExportCertificateRequest{Format: model.ExportFormatPEM})
	require.ErrorIs(t, err, ErrCertificateChainUnavailable)

	// Scope: a hop in another vault is not readable, so the chain fails
	// closed rather than leaking that vault's certificate.
	foreign := insertCert(t, h, uuid.New(), hopPEM, caKey, nil)
	leaf := insertCert(t, h, h.vaultID, hopPEM, caKey, &foreign)
	_, err = h.svc.ExportCertificate(ctx, h.scope(), leaf, ExportCertificateRequest{Format: model.ExportFormatPEM})
	require.ErrorIs(t, err, ErrCertificateChainUnavailable)
}

// TestExportCertificate_ReflectsStoredKeyCopy pins the documented caveat: a
// key rotation does not change the exported certificate's key until the
// certificate is renewed.
func TestExportCertificate_ReflectsStoredKeyCopy(t *testing.T) {
	h := newVersioningHarness(t)
	ctx := context.Background()
	id := createExportable(t, h, "stable", "RSA")
	before, err := h.svc.ExportCertificate(ctx, h.scope(), id, ExportCertificateRequest{Format: model.ExportFormatPEM})
	require.NoError(t, err)

	cert, err := h.certRepo.Read(ctx, id, h.scope())
	require.NoError(t, err)
	newKey, err := crypto.GenerateRSAKeyPEM(2048)
	require.NoError(t, err)
	enc, err := common.EncryptSecret(newKey)
	require.NoError(t, err)
	_, err = h.raw.ExecContext(context.Background(), "UPDATE keys SET value = ? WHERE id = ?", enc, cert.KeyID.String())
	require.NoError(t, err)

	after, err := h.svc.ExportCertificate(ctx, h.scope(), id, ExportCertificateRequest{Format: model.ExportFormatPEM})
	require.NoError(t, err)
	assert.True(t, sha256.Sum256([]byte(before.PrivateKeyPEM)) == sha256.Sum256([]byte(after.PrivateKeyPEM)),
		"the export still carries the certificate's stored key copy")
}

// TestExportCertificate_ChainVerifiesEverySignature pins that each hop must
// have signed the certificate below it. A CA reissued with a new key keeps
// its name, so a walk that only follows ca_cert_id would ship a chain that
// cannot verify. Export fails closed instead.
func TestExportCertificate_ChainVerifiesEverySignature(t *testing.T) {
	h := newVersioningHarness(t)
	ctx := context.Background()
	newCA := func(name string, parentPEM, parentKey string) (string, string) {
		key, err := crypto.GenerateRSAKeyPEM(2048)
		require.NoError(t, err)
		tmpl := crypto.CertificateTemplate{CommonName: name, ValidityDays: 30, IsCA: true}
		if parentPEM == "" {
			certPEM, err := crypto.CreateSelfSignedCertificatePEM(key, "RSA", tmpl)
			require.NoError(t, err)
			return certPEM, key
		}
		certPEM, err := crypto.CreateCASignedCertificatePEM(key, "RSA", parentPEM, parentKey, "RSA", tmpl)
		require.NoError(t, err)
		return certPEM, key
	}
	rootPEM, rootKey := newCA("root", "", "")
	intPEM, intKey := newCA("intermediate", rootPEM, rootKey)
	leafKey, err := crypto.GenerateECDSAKeyPEM("P-256")
	require.NoError(t, err)
	leafPEM, err := crypto.CreateCASignedCertificatePEM(leafKey, "ECDSA", intPEM, intKey, "RSA", crypto.CertificateTemplate{CommonName: "leaf", ValidityDays: 30})
	require.NoError(t, err)

	rootID := insertCert(t, h, h.vaultID, rootPEM, rootKey, nil)
	intID := insertCert(t, h, h.vaultID, intPEM, intKey, &rootID)

	t.Run("a correct chain exports", func(t *testing.T) {
		leafID := insertCert(t, h, h.vaultID, leafPEM, leafKey, &intID)
		res, err := h.svc.ExportCertificate(ctx, h.scope(), leafID, ExportCertificateRequest{Format: model.ExportFormatPEM})
		require.NoError(t, err)
		certs := parsePEMCerts(t, res.CertificatePEM)
		require.Len(t, certs, 2)
		require.NoError(t, certs[0].CheckSignatureFrom(certs[1]))
	})

	t.Run("an intermediate that did not sign the leaf fails closed", func(t *testing.T) {
		// Same name and same root, but a different key: what a renewal
		// after a key rotation produces.
		reissuedPEM, reissuedKey := newCA("intermediate", rootPEM, rootKey)
		reissuedID := insertCert(t, h, h.vaultID, reissuedPEM, reissuedKey, &rootID)
		leafID := insertCert(t, h, h.vaultID, leafPEM, leafKey, &reissuedID)
		res, err := h.svc.ExportCertificate(ctx, h.scope(), leafID, ExportCertificateRequest{Format: model.ExportFormatPEM})
		require.ErrorIs(t, err, ErrCertificateChainUnavailable)
		assert.True(t, res == nil, "nothing is exported")
	})

	t.Run("a root that did not sign the intermediate fails closed", func(t *testing.T) {
		otherRootPEM, otherRootKey := newCA("root", "", "")
		otherRootID := insertCert(t, h, h.vaultID, otherRootPEM, otherRootKey, nil)
		badIntID := insertCert(t, h, h.vaultID, intPEM, intKey, &otherRootID)
		leafID := insertCert(t, h, h.vaultID, leafPEM, leafKey, &badIntID)
		_, err := h.svc.ExportCertificate(ctx, h.scope(), leafID, ExportCertificateRequest{Format: model.ExportFormatPKCS12, Password: strPtr("")})
		require.ErrorIs(t, err, ErrCertificateChainUnavailable)
	})
}
