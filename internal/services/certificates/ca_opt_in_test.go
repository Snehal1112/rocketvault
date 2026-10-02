package certificates

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"rocketvault/common"
	"rocketvault/internal/crypto"
	"rocketvault/internal/logging"
	"rocketvault/model"
)

// parseIssuedCert decodes and parses a certificate the service just issued.
// The name deliberately avoids parseCertPEM, which plan 03 adds to this
// package in chain_assert_test.go.
func parseIssuedCert(t *testing.T, certPEM string) *x509.Certificate {
	t.Helper()

	block, _ := pem.Decode([]byte(certPEM))
	require.NotNil(t, block, "certificate PEM must decode")
	cert, err := x509.ParseCertificate(block.Bytes)
	require.NoError(t, err)
	return cert
}

// certCapture records the certificate the service handed to the repository.
type certCapture struct {
	cert *model.Certificate
}

// selfSignedFixture wires everything CreateSelfSignedCertificate needs.
type selfSignedFixture struct {
	svc     CertificateService
	userID  uuid.UUID
	keyID   uuid.UUID
	capture *certCapture
}

// newSelfSignedFixture gives the caller a readable RSA key it owns, and a
// Create that records the stored certificate for inspection.
func newSelfSignedFixture(t *testing.T) *selfSignedFixture {
	t.Helper()
	setupMasterKey()

	userID := uuid.New()
	keyID := uuid.New()

	privateKeyPEM, err := crypto.GenerateRSAKeyPEM(2048)
	require.NoError(t, err)
	encryptedKey, err := common.EncryptSecret(privateKeyPEM)
	require.NoError(t, err)

	certRepo := &mockCertRepository{}
	keyRepo := &mockKeyRepo{}

	keyRepo.On("Read", mock.Anything, keyID, certVaultScope(userID)).Return(&model.Key{
		ID:      keyID,
		UserID:  userID,
		Type:    model.KeyTypeRSA,
		Value:   encryptedKey,
		Enabled: true,
	}, nil)

	capture := &certCapture{}
	certRepo.On("Create", mock.Anything, mock.AnythingOfType("*model.Certificate")).
		Run(func(args mock.Arguments) { capture.cert = args.Get(1).(*model.Certificate) }).
		Return(nil)

	return &selfSignedFixture{
		svc:     newCertSvc(certRepo, keyRepo),
		userID:  userID,
		keyID:   keyID,
		capture: capture,
	}
}

// An ordinary self-signed certificate is a leaf. Both self-signed call sites
// hardcoded IsCA: true, so every certificate this service issued asserted
// CA:TRUE -- and a leaked leaf key could then mint certificates for arbitrary
// names (B44).
func TestCreateSelfSignedCertificate_DefaultsToNonCA(t *testing.T) {
	f := newSelfSignedFixture(t)

	_, err := f.svc.CreateSelfSignedCertificate(context.Background(), CreateCertificateRequest{
		Name:         "tls-server",
		KeyID:        f.keyID,
		ValidityDays: 365,
		UserID:       f.userID,
	})
	require.NoError(t, err)
	require.NotNil(t, f.capture.cert)

	issued := parseIssuedCert(t, f.capture.cert.Certificate)
	assert.False(t, issued.IsCA, "an ordinary self-signed certificate must not be a CA")
	assert.True(t, issued.BasicConstraintsValid, "basic constraints must still be asserted")
}

// A CA is something you ask for. IsCA is the opt-in behind the --is-ca flag
// and the is_ca API field.
func TestCreateSelfSignedCertificate_CAOptIn(t *testing.T) {
	f := newSelfSignedFixture(t)

	_, err := f.svc.CreateSelfSignedCertificate(context.Background(), CreateCertificateRequest{
		Name:         "issuing-ca",
		KeyID:        f.keyID,
		ValidityDays: 3650,
		UserID:       f.userID,
		IsCA:         true,
	})
	require.NoError(t, err)
	require.NotNil(t, f.capture.cert)

	issued := parseIssuedCert(t, f.capture.cert.Certificate)
	assert.True(t, issued.IsCA, "the opt-in must produce a CA certificate")
}

// The opt-in has no meaning on the CA-signed path: issuing an intermediate CA
// is a separate feature. Quietly returning a leaf when a CA was asked for is
// the same silent wrongness B44 is about, so it is refused instead.
func TestCreateCASignedCertificate_RejectsCAOptIn(t *testing.T) {
	caCertID := uuid.New()
	svc := newCertSvc(&mockCertRepository{}, &mockKeyRepo{})

	_, err := svc.CreateCASignedCertificate(context.Background(), CreateCertificateRequest{
		Name:         "intermediate",
		KeyID:        uuid.New(),
		ValidityDays: 365,
		UserID:       uuid.New(),
		CACertID:     &caCertID,
		IsCA:         true,
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "intermediate CA certificates are not supported")
}

// renewalFixture wires a renewal over a certificate whose stored body was
// issued with a known CA status.
type renewalFixture struct {
	svc     CertificateService
	scope   model.Scope
	certID  uuid.UUID
	capture *certCapture
	logs    *bytes.Buffer
}

func newRenewalFixture(t *testing.T, storedIsCA bool) *renewalFixture {
	t.Helper()
	setupMasterKey()

	privateKeyPEM, err := crypto.GenerateRSAKeyPEM(2048)
	require.NoError(t, err)

	storedPEM, err := crypto.CreateSelfSignedCertificatePEM(privateKeyPEM, model.KeyTypeRSA, crypto.CertificateTemplate{
		CommonName:   "renew-me",
		ValidityDays: 365,
		IsCA:         storedIsCA,
	})
	require.NoError(t, err)

	return newRenewalFixtureWithStoredCert(t, privateKeyPEM, storedPEM)
}

// newRenewalFixtureWithStoredCert wires a renewal over a caller-supplied
// stored certificate body, so a test can hand renewal a shape the current
// template can no longer produce. Its logger writes to fixture.logs, which is
// how a test asserts what renewal recorded in the audit log.
func newRenewalFixtureWithStoredCert(t *testing.T, privateKeyPEM, storedPEM string) *renewalFixture {
	t.Helper()
	setupMasterKey()

	userID := uuid.New()
	vaultID := uuid.New()
	certID := uuid.New()
	keyID := uuid.New()

	encryptedKey, err := common.EncryptSecret(privateKeyPEM)
	require.NoError(t, err)

	scope := model.NewVaultScope(vaultID, userID)
	original := &model.Certificate{
		ID:          certID,
		UserID:      userID,
		VaultID:     vaultID,
		KeyID:       keyID,
		Name:        "renew-me",
		Certificate: storedPEM,
		PrivateKey:  encryptedKey,
		CreatedAt:   time.Now().Add(-300 * 24 * time.Hour),
		Enabled:     true,
		RenewalDays: 30,
	}

	certRepo := &mockCertRepository{}
	keyRepo := &mockKeyRepo{}

	certRepo.On("Read", mock.Anything, certID, scope).Return(original, nil)
	keyRepo.On("Read", mock.Anything, keyID, scope).Return(&model.Key{
		ID:      keyID,
		UserID:  userID,
		Type:    model.KeyTypeRSA,
		Value:   encryptedKey,
		Enabled: true,
	}, nil)

	capture := &certCapture{}
	certRepo.On("Update", mock.Anything, mock.AnythingOfType("*model.Certificate"), scope).
		Run(func(args mock.Arguments) { capture.cert = args.Get(1).(*model.Certificate) }).
		Return(nil)

	logs := &bytes.Buffer{}
	logrusLogger := logrus.New()
	logrusLogger.SetOutput(logs)

	svc := NewCertificateService(CertificateServiceConfig{
		CertificateRepository: certRepo,
		VersionRepository:     &fakeCertVersionRepo{certRepo: certRepo},
		KeyRepository:         keyRepo,
		Logger:                &logging.Logger{Logger: logrusLogger},
	})

	return &renewalFixture{
		svc:     svc,
		scope:   scope,
		certID:  certID,
		capture: capture,
		logs:    logs,
	}
}

// prefixShapedCertPEM builds a certificate in the shape every certificate
// issued before this release carries: CA:TRUE with no keyCertSign. That
// missing bit is the only reason those certificates never worked as
// authorities. It is constructed directly with crypto/x509 because the fixed
// template can no longer produce it -- IsCA there always implies keyCertSign.
func prefixShapedCertPEM(t *testing.T, privateKeyPEM string) string {
	t.Helper()

	block, _ := pem.Decode([]byte(privateKeyPEM))
	require.NotNil(t, block, "private key PEM must decode")
	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "renew-me"},
		NotBefore:             time.Now().Add(-24 * time.Hour),
		NotAfter:              time.Now().Add(30 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)

	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

// Renewal must not promote a leaf to a CA. The renewal call site hardcoded
// IsCA: true, so the first renewal turned any certificate into a CA (B44).
func TestRenewCertificate_PreservesNonCA(t *testing.T) {
	f := newRenewalFixture(t, false)

	_, err := f.svc.RenewCertificate(context.Background(), f.certID, f.scope, 365)
	require.NoError(t, err)
	require.NotNil(t, f.capture.cert)

	renewed := parseIssuedCert(t, f.capture.cert.Certificate)
	assert.False(t, renewed.IsCA, "renewing a leaf must not turn it into a CA")
	assert.Zero(t, renewed.KeyUsage&x509.KeyUsageCertSign,
		"renewing a leaf must not grant it certificate-signing authority")
	assert.NotContains(t, f.logs.String(), "ca_demoted",
		"an ordinary leaf has no authority to demote, so nothing should be logged")
}

// The other direction matters just as much: renewal must not strip the CA bit
// from a real CA, or every CA this system issued would break the first time it
// renewed. Renewal preserves; it does not choose.
func TestRenewCertificate_PreservesCA(t *testing.T) {
	f := newRenewalFixture(t, true)

	_, err := f.svc.RenewCertificate(context.Background(), f.certID, f.scope, 365)
	require.NoError(t, err)
	require.NotNil(t, f.capture.cert)

	renewed := parseIssuedCert(t, f.capture.cert.Certificate)
	assert.True(t, renewed.IsCA, "renewing a CA must keep it a CA")
	assert.NotZero(t, renewed.KeyUsage&x509.KeyUsageCertSign,
		"a renewed CA must keep its certificate-signing authority")
	assert.NotZero(t, renewed.KeyUsage&x509.KeyUsageCRLSign,
		"a renewed CA must keep its CRL-signing authority")
	assert.NotContains(t, f.logs.String(), "ca_demoted",
		"a genuine CA must not be demoted")
}

// A certificate issued before this release asserts CA:TRUE but carries no
// keyCertSign, which is the only reason it never worked as an authority. Now
// that the template adds keyCertSign to anything with IsCA set, renewing such
// a certificate as a CA would arm it -- unattended, across the whole existing
// fleet, via the auto-renew scheduler. Renewal demotes it to a leaf instead.
// Nothing is lost: nothing it ever signed verified in the first place.
func TestRenewCertificate_DemotesPreFixPseudoCAToLeaf(t *testing.T) {
	setupMasterKey()

	privateKeyPEM, err := crypto.GenerateRSAKeyPEM(2048)
	require.NoError(t, err)

	storedPEM := prefixShapedCertPEM(t, privateKeyPEM)

	// Guard the fixture itself: it must really carry the pre-fix shape, or
	// this test would pass while proving nothing.
	stored := parseIssuedCert(t, storedPEM)
	require.True(t, stored.IsCA, "the fixture must assert CA:TRUE")
	require.Zero(t, stored.KeyUsage&x509.KeyUsageCertSign, "the fixture must have no keyCertSign")

	f := newRenewalFixtureWithStoredCert(t, privateKeyPEM, storedPEM)

	_, err = f.svc.RenewCertificate(context.Background(), f.certID, f.scope, 365)
	require.NoError(t, err, "renewal must not be refused: that would break auto-renew across the fleet")
	require.NotNil(t, f.capture.cert)

	renewed := parseIssuedCert(t, f.capture.cert.Certificate)
	assert.False(t, renewed.IsCA, "a pre-fix pseudo-CA must renew as a leaf, not as a working CA")
	assert.Zero(t, renewed.KeyUsage&x509.KeyUsageCertSign,
		"the renewed certificate must not gain certificate-signing authority")
	assert.Zero(t, renewed.KeyUsage&x509.KeyUsageCRLSign,
		"the renewed certificate must not gain CRL-signing authority")
}

// The demotion changes what a certificate is allowed to do, so it must be
// visible to an operator rather than happening silently.
func TestRenewCertificate_DemotionIsAuditLogged(t *testing.T) {
	setupMasterKey()

	privateKeyPEM, err := crypto.GenerateRSAKeyPEM(2048)
	require.NoError(t, err)

	f := newRenewalFixtureWithStoredCert(t, privateKeyPEM, prefixShapedCertPEM(t, privateKeyPEM))

	_, err = f.svc.RenewCertificate(context.Background(), f.certID, f.scope, 365)
	require.NoError(t, err)

	logged := f.logs.String()
	assert.Contains(t, logged, "ca_demoted", "the demotion must carry its own audit status")
	assert.Contains(t, logged, "renew_certificate", "the demotion must be logged against the renewal operation")
	assert.Contains(t, logged, f.certID.String(), "the audit entry must name the certificate that was demoted")
}

// The opt-in must produce a certificate that can actually sign. IsCA alone is
// only half a CA: without CertSign no verifier will accept anything it signs,
// which was B43. This is the assertion that ties the two fixes together.
func TestCreateSelfSignedCertificate_CAOptInCarriesCertSign(t *testing.T) {
	f := newSelfSignedFixture(t)

	_, err := f.svc.CreateSelfSignedCertificate(context.Background(), CreateCertificateRequest{
		Name:         "issuing-ca",
		KeyID:        f.keyID,
		ValidityDays: 3650,
		UserID:       f.userID,
		IsCA:         true,
	})
	require.NoError(t, err)
	require.NotNil(t, f.capture.cert)

	issued := parseIssuedCert(t, f.capture.cert.Certificate)
	assert.True(t, issued.IsCA, "the opt-in must produce a CA certificate")
	assert.NotZero(t, issued.KeyUsage&x509.KeyUsageCertSign, "a CA must be allowed to sign certificates")
	assert.NotZero(t, issued.KeyUsage&x509.KeyUsageCRLSign, "a CA must be allowed to sign CRLs")
}

// And the mirror. This is the assertion that would have caught landing B43's
// fix while B44 stood: an ordinary certificate must gain no signing authority
// from it.
func TestCreateSelfSignedCertificate_LeafGetsNoCertSign(t *testing.T) {
	f := newSelfSignedFixture(t)

	_, err := f.svc.CreateSelfSignedCertificate(context.Background(), CreateCertificateRequest{
		Name:         "tls-server",
		KeyID:        f.keyID,
		ValidityDays: 365,
		UserID:       f.userID,
	})
	require.NoError(t, err)
	require.NotNil(t, f.capture.cert)

	issued := parseIssuedCert(t, f.capture.cert.Certificate)
	assert.False(t, issued.IsCA)
	assert.Zero(t, issued.KeyUsage&x509.KeyUsageCertSign, "an ordinary certificate must not be able to sign certificates")
	assert.Zero(t, issued.KeyUsage&x509.KeyUsageCRLSign, "an ordinary certificate must not be able to sign CRLs")
}

// inspectCertificateCA's parse-failure branches are fail-closed: renewal
// aborts rather than guessing a CA status for a certificate it cannot read.
// That behaviour has no lock on it -- a future "cleanup" turning either
// branch into `return caStatusLeaf, nil` would silently strip the CA bit off
// every real CA on its first renewal, with the rest of the suite still
// green. This pins both of inspectCertificateCA's two distinct failure
// paths: pem.Decode rejecting the stored bytes outright, and
// x509.ParseCertificate rejecting a syntactically valid PEM block whose DER
// body isn't a certificate.
func TestRenewCertificate_UnparsableCertificateAbortsWithoutIssuing(t *testing.T) {
	garbageDERPEM := string(pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: []byte("this is not a valid DER-encoded certificate"),
	}))

	tests := []struct {
		name         string
		storedCert   string
		wantErrorMsg string
	}{
		{
			name:         "not PEM at all",
			storedCert:   "not a valid PEM certificate",
			wantErrorMsg: "renewal must abort when the stored certificate cannot be PEM-decoded",
		},
		{
			name:         "valid PEM block, unparsable DER",
			storedCert:   garbageDERPEM,
			wantErrorMsg: "renewal must abort when the stored certificate's DER body cannot be parsed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			setupMasterKey()

			userID := uuid.New()
			vaultID := uuid.New()
			certID := uuid.New()
			keyID := uuid.New()

			privateKeyPEM, err := crypto.GenerateRSAKeyPEM(2048)
			require.NoError(t, err)
			encryptedKey, err := common.EncryptSecret(privateKeyPEM)
			require.NoError(t, err)

			scope := model.NewVaultScope(vaultID, userID)
			original := &model.Certificate{
				ID:          certID,
				UserID:      userID,
				VaultID:     vaultID,
				KeyID:       keyID,
				Name:        "renew-me",
				Certificate: tt.storedCert,
				PrivateKey:  encryptedKey,
				CreatedAt:   time.Now().Add(-300 * 24 * time.Hour),
				Enabled:     true,
				RenewalDays: 30,
			}

			certRepo := &mockCertRepository{}
			keyRepo := &mockKeyRepo{}

			certRepo.On("Read", mock.Anything, certID, scope).Return(original, nil)
			keyRepo.On("Read", mock.Anything, keyID, scope).Return(&model.Key{
				ID:      keyID,
				UserID:  userID,
				Type:    model.KeyTypeRSA,
				Value:   encryptedKey,
				Enabled: true,
			}, nil)
			// No certRepo.On("Update", ...) stub: renewal must abort before it
			// would ever call Update. The hand-written mocks in this package
			// panic on an unexpected call rather than failing just the one
			// test, so an unintended Update call here fails loudly instead of
			// quietly.

			svc := newCertSvc(certRepo, keyRepo)

			_, err = svc.RenewCertificate(context.Background(), certID, scope, 365)
			require.Error(t, err, tt.wantErrorMsg)

			certRepo.AssertNotCalled(t, "Update", mock.Anything, mock.Anything, mock.Anything)
		})
	}
}
