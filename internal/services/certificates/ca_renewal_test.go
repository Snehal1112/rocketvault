package certificates

import (
	"context"
	"crypto/x509"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"rocketvault/common"
	"rocketvault/internal/crypto"
	"rocketvault/model"
)

// caRenewalFixture builds a CA (self-signed) and a leaf signed by it, wired
// into mock repositories, ready for a renewal call.
type caRenewalFixture struct {
	svc      CertificateService
	certRepo *mockCertRepository
	keyRepo  *mockKeyRepo
	scope    model.Scope
	certID   uuid.UUID
	caCertID uuid.UUID
	caPEM    string
	original *model.Certificate
	updated  **model.Certificate
}

// newCARenewalFixture wires a leaf certificate signed by a CA whose key uses
// caKeyType ("RSA" or "ECDSA").
func newCARenewalFixture(t *testing.T, caKeyType string) *caRenewalFixture {
	t.Helper()
	setupMasterKey()

	userID := uuid.New()
	vaultID := uuid.New()
	certID := uuid.New()
	keyID := uuid.New()
	caCertID := uuid.New()

	entityKeyPEM, err := crypto.GenerateRSAKeyPEM(2048)
	require.NoError(t, err)

	var caKeyPEM string
	switch caKeyType {
	case "RSA":
		caKeyPEM, err = crypto.GenerateRSAKeyPEM(2048)
	case "ECDSA":
		caKeyPEM, err = crypto.GenerateECDSAKeyPEM("P-256")
	default:
		t.Fatalf("unsupported CA key type in fixture: %s", caKeyType)
	}
	require.NoError(t, err)

	caPEM, err := crypto.CreateSelfSignedCertificatePEM(caKeyPEM, caKeyType, crypto.CertificateTemplate{
		CommonName: "Fixture CA", ValidityDays: 3650, IsCA: true,
	})
	require.NoError(t, err)

	leafPEM, err := crypto.CreateCASignedCertificatePEM(entityKeyPEM, "RSA", caPEM, caKeyPEM, caKeyType, crypto.CertificateTemplate{
		CommonName: "leaf-cert", ValidityDays: 365, IsCA: false,
	})
	require.NoError(t, err)

	encEntity, err := common.EncryptSecret(entityKeyPEM)
	require.NoError(t, err)
	encCA, err := common.EncryptSecret(caKeyPEM)
	require.NoError(t, err)

	scope := model.NewVaultScope(vaultID, userID)

	original := &model.Certificate{
		ID:          certID,
		UserID:      userID,
		VaultID:     vaultID,
		KeyID:       keyID,
		CACertID:    &caCertID,
		Name:        "leaf-cert",
		Certificate: leafPEM,
		PrivateKey:  encEntity,
		Enabled:     true,
		RenewalDays: 30,
	}
	caCert := &model.Certificate{
		ID:          caCertID,
		UserID:      userID,
		VaultID:     vaultID,
		Name:        "fixture-ca",
		Certificate: caPEM,
		PrivateKey:  encCA,
		Enabled:     true,
	}

	certRepo := &mockCertRepository{}
	keyRepo := &mockKeyRepo{}

	certRepo.On("Read", mock.Anything, certID, scope).Return(original, nil)
	certRepo.On("Read", mock.Anything, caCertID, scope).Return(caCert, nil)
	keyRepo.On("Read", mock.Anything, keyID, scope).
		Return(&model.Key{ID: keyID, UserID: userID, Type: model.KeyTypeRSA, Value: encEntity}, nil)

	var updated *model.Certificate
	certRepo.On("Update", mock.Anything, mock.AnythingOfType("*model.Certificate"), scope).
		Run(func(args mock.Arguments) { updated = args.Get(1).(*model.Certificate) }).
		Return(nil)

	return &caRenewalFixture{
		svc:      newCertSvc(certRepo, keyRepo),
		certRepo: certRepo,
		keyRepo:  keyRepo,
		scope:    scope,
		certID:   certID,
		caCertID: caCertID,
		caPEM:    caPEM,
		original: original,
		updated:  &updated,
	}
}

// The headline test for B37: renewing a CA-signed certificate must keep its
// issuer and leave the chain verifiable.
func TestRenewCertificate_CASignedPreservesIssuerAndChain(t *testing.T) {
	f := newCARenewalFixture(t, "RSA")

	originalIssuer := parseCertPEM(t, f.original.Certificate).Issuer.CommonName

	result, err := f.svc.RenewCertificate(context.Background(), f.certID, f.scope, 365)
	require.NoError(t, err)
	require.NotNil(t, result)

	updated := *f.updated
	require.NotNil(t, updated, "certRepo.Update must have been called")

	renewed := parseCertPEM(t, updated.Certificate)
	assert.Equal(t, originalIssuer, renewed.Issuer.CommonName, "renewal must not change the issuer")
	assert.False(t, renewed.IsCA, "renewing a leaf must not turn it into a CA")
	assertSignedBy(t, updated.Certificate, f.caPEM, "Fixture CA")

	// The renewal is written in place, so the ID and the CA link both survive.
	assert.Equal(t, f.certID, updated.ID)
	assert.Equal(t, f.certID, result.CertID)
	require.NotNil(t, updated.CACertID)
	assert.Equal(t, f.caCertID, *updated.CACertID)
}

// The same, with an ECDSA CA. This is the hardcoded-"RSA" bug: before the fix
// the CA private key was parsed as RSA and the renewal failed outright.
func TestRenewCertificate_ECDSACAPreservesChain(t *testing.T) {
	f := newCARenewalFixture(t, "ECDSA")

	_, err := f.svc.RenewCertificate(context.Background(), f.certID, f.scope, 365)
	require.NoError(t, err)

	updated := *f.updated
	require.NotNil(t, updated)
	assertSignedBy(t, updated.Certificate, f.caPEM, "Fixture CA")
}

// A self-signed certificate must renew as self-signed. This fixture stores a
// CA, so the renewal must still be a CA -- renewal preserves the stored flag
// rather than choosing one (B44).
func TestRenewCertificate_SelfSignedStaysSelfSigned(t *testing.T) {
	setupMasterKey()

	userID := uuid.New()
	vaultID := uuid.New()
	certID := uuid.New()
	keyID := uuid.New()

	keyPEM, err := crypto.GenerateRSAKeyPEM(2048)
	require.NoError(t, err)
	certPEM, err := crypto.CreateSelfSignedCertificatePEM(keyPEM, "RSA", crypto.CertificateTemplate{
		CommonName: "self-signed-cert", ValidityDays: 365, IsCA: true,
	})
	require.NoError(t, err)
	encKey, err := common.EncryptSecret(keyPEM)
	require.NoError(t, err)

	scope := model.NewVaultScope(vaultID, userID)
	original := &model.Certificate{
		ID: certID, UserID: userID, VaultID: vaultID, KeyID: keyID,
		Name: "self-signed-cert", Certificate: certPEM, PrivateKey: encKey,
		Enabled: true, RenewalDays: 30,
	}

	certRepo := &mockCertRepository{}
	keyRepo := &mockKeyRepo{}
	certRepo.On("Read", mock.Anything, certID, scope).Return(original, nil)
	keyRepo.On("Read", mock.Anything, keyID, scope).
		Return(&model.Key{ID: keyID, UserID: userID, Type: model.KeyTypeRSA, Value: encKey}, nil)

	var updated *model.Certificate
	certRepo.On("Update", mock.Anything, mock.AnythingOfType("*model.Certificate"), scope).
		Run(func(args mock.Arguments) { updated = args.Get(1).(*model.Certificate) }).
		Return(nil)

	svc := newCertSvc(certRepo, keyRepo)
	_, err = svc.RenewCertificate(context.Background(), certID, scope, 365)
	require.NoError(t, err)

	require.NotNil(t, updated)
	assertSelfSigned(t, updated.Certificate)
	assert.True(t, parseCertPEM(t, updated.Certificate).IsCA,
		"renewing a stored CA must keep IsCA; renewal preserves the flag it finds")
	assert.Nil(t, updated.CACertID)
}

// A CA that has been deleted, purged or moved out of scope must refuse the
// renewal, never fall back to self-signing. The silent fallback is B37.
func TestRenewCertificate_MissingCARefusesRatherThanSelfSigns(t *testing.T) {
	f := newCARenewalFixture(t, "RSA")

	// Replace the CA read with a not-found.
	f.certRepo.ExpectedCalls = nil
	f.certRepo.On("Read", mock.Anything, f.certID, f.scope).Return(f.original, nil)
	f.certRepo.On("Read", mock.Anything, f.caCertID, f.scope).
		Return(nil, assert.AnError)

	_, err := f.svc.RenewCertificate(context.Background(), f.certID, f.scope, 365)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not accessible")
	f.certRepo.AssertNotCalled(t, "Update", mock.Anything, mock.Anything, mock.Anything)
}

// A CA that is disabled or past its own expiry must refuse the renewal too:
// a certificate it signs cannot chain-verify.
func TestRenewCertificate_ExpiredCARefusesRenewal(t *testing.T) {
	f := newCARenewalFixture(t, "RSA")

	past := timeInPast()
	disabledCA := &model.Certificate{
		ID: f.caCertID, UserID: f.scope.ActorID(), VaultID: f.scope.VaultID(),
		Name: "fixture-ca", Certificate: f.caPEM, PrivateKey: "unused",
		Enabled: true, ExpiresAt: &past,
	}

	f.certRepo.ExpectedCalls = nil
	f.certRepo.On("Read", mock.Anything, f.certID, f.scope).Return(f.original, nil)
	f.certRepo.On("Read", mock.Anything, f.caCertID, f.scope).Return(disabledCA, nil)

	_, err := f.svc.RenewCertificate(context.Background(), f.certID, f.scope, 365)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unusable")
	f.certRepo.AssertNotCalled(t, "Update", mock.Anything, mock.Anything, mock.Anything)
}

// A row created before ca_cert_id existed carries no CA link. If its stored
// body says it was signed by somebody else, renewing it self-signed would
// reintroduce exactly the bug this change fixes, so it is refused.
func TestRenewCertificate_LegacyCASignedRowWithNoLinkRefuses(t *testing.T) {
	f := newCARenewalFixture(t, "RSA")

	// Same fixture, but the CA link was never recorded.
	f.original.CACertID = nil

	_, err := f.svc.RenewCertificate(context.Background(), f.certID, f.scope, 365)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no longer records")
	f.certRepo.AssertNotCalled(t, "Update", mock.Anything, mock.Anything, mock.Anything)
}

// Renewal must keep refusing an inaccessible certificate. This is deliberate,
// preserved behavior: renew before a certificate lapses, not after.
func TestRenewCertificate_ExpiredCertificateStillRefused(t *testing.T) {
	f := newCARenewalFixture(t, "RSA")

	past := timeInPast()
	f.original.ExpiresAt = &past

	_, err := f.svc.RenewCertificate(context.Background(), f.certID, f.scope, 365)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrCertLifecycleDenied)
	f.certRepo.AssertNotCalled(t, "Update", mock.Anything, mock.Anything, mock.Anything)
}

// timeInPast returns a timestamp comfortably before now, for lifecycle tests.
func timeInPast() time.Time {
	return time.Now().Add(-24 * time.Hour)
}

// x509.CreateCertificate does not check the parent's IsCA/KeyUsage bits, so
// without an explicit gate renewal would sign through a CA whose own body
// cannot actually verify as an issuer, report success, and leave a chain that
// silently fails CheckSignatureFrom/Verify. This is the pre-B43 shape every
// CA certificate in an unrepaired deployment carries: CA:TRUE with no
// keyCertSign.
func TestRenewCertificate_UnsignableCARefusesRenewal(t *testing.T) {
	f := newCARenewalFixture(t, "RSA")

	caKeyPEM, err := crypto.GenerateRSAKeyPEM(2048)
	require.NoError(t, err)
	unsignableCAPEM := prefixShapedCertPEM(t, caKeyPEM)
	encCAKey, err := common.EncryptSecret(caKeyPEM)
	require.NoError(t, err)

	unsignableCA := &model.Certificate{
		ID: f.caCertID, UserID: f.scope.ActorID(), VaultID: f.scope.VaultID(),
		Name: "fixture-ca", Certificate: unsignableCAPEM, PrivateKey: encCAKey,
		Enabled: true,
	}

	f.certRepo.ExpectedCalls = nil
	f.certRepo.On("Read", mock.Anything, f.certID, f.scope).Return(f.original, nil)
	f.certRepo.On("Read", mock.Anything, f.caCertID, f.scope).Return(unsignableCA, nil)

	_, err = f.svc.RenewCertificate(context.Background(), f.certID, f.scope, 365)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "cannot sign certificates")
	f.certRepo.AssertNotCalled(t, "Update", mock.Anything, mock.Anything, mock.Anything)
}

// A ca_cert_id can point at a certificate that is not a CA at all -- an
// ordinary leaf, if the link was set up wrong or the target was since
// re-issued without --is-ca. Renewal must refuse rather than sign through it.
func TestRenewCertificate_LeafAsCARefusesRenewal(t *testing.T) {
	f := newCARenewalFixture(t, "RSA")

	caKeyPEM, err := crypto.GenerateRSAKeyPEM(2048)
	require.NoError(t, err)
	leafAsCAPEM, err := crypto.CreateSelfSignedCertificatePEM(caKeyPEM, "RSA", crypto.CertificateTemplate{
		CommonName: "not-actually-a-ca", ValidityDays: 3650, IsCA: false,
	})
	require.NoError(t, err)
	encCAKey, err := common.EncryptSecret(caKeyPEM)
	require.NoError(t, err)

	leafAsCA := &model.Certificate{
		ID: f.caCertID, UserID: f.scope.ActorID(), VaultID: f.scope.VaultID(),
		Name: "fixture-ca", Certificate: leafAsCAPEM, PrivateKey: encCAKey,
		Enabled: true,
	}

	f.certRepo.ExpectedCalls = nil
	f.certRepo.On("Read", mock.Anything, f.certID, f.scope).Return(f.original, nil)
	f.certRepo.On("Read", mock.Anything, f.caCertID, f.scope).Return(leafAsCA, nil)

	_, err = f.svc.RenewCertificate(context.Background(), f.certID, f.scope, 365)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "cannot sign certificates")
	f.certRepo.AssertNotCalled(t, "Update", mock.Anything, mock.Anything, mock.Anything)
}

// Creation needs the same gate renewal has. Without it, pointing
// "certificate create --ca-cert-id" at a pre-fix pseudo-CA (CA:TRUE with no
// keyCertSign) still mints a certificate that fails CheckSignatureFrom and
// Verify against its own CA -- B43's broken-chain defect, reached through the
// creation path instead of the renewal path.
func TestCreateCASignedCertificate_PreFixPseudoCARefusesCreation(t *testing.T) {
	setupMasterKey()

	userID := uuid.New()
	keyID := uuid.New()
	caCertID := uuid.New()

	entityKeyPEM, err := crypto.GenerateRSAKeyPEM(2048)
	require.NoError(t, err)
	caKeyPEM, err := crypto.GenerateRSAKeyPEM(2048)
	require.NoError(t, err)

	pseudoCAPEM := prefixShapedCertPEM(t, caKeyPEM)

	// Guard the fixture: it must really carry the pre-fix shape, or this test
	// would pass while proving nothing.
	stored := parseCertPEM(t, pseudoCAPEM)
	require.True(t, stored.IsCA, "the fixture must assert CA:TRUE")
	require.Zero(t, stored.KeyUsage&x509.KeyUsageCertSign, "the fixture must have no keyCertSign")

	encEntityKey, err := common.EncryptSecret(entityKeyPEM)
	require.NoError(t, err)
	encCAKey, err := common.EncryptSecret(caKeyPEM)
	require.NoError(t, err)

	certRepo := &mockCertRepository{}
	keyRepo := &mockKeyRepo{}

	keyRepo.On("Read", mock.Anything, keyID, certVaultScope(userID)).
		Return(&model.Key{ID: keyID, UserID: userID, Type: model.KeyTypeRSA, Value: encEntityKey}, nil)
	certRepo.On("Read", mock.Anything, caCertID, certVaultScope(userID)).Return(&model.Certificate{
		ID: caCertID, UserID: userID, Name: "pre-fix-ca",
		Certificate: pseudoCAPEM, PrivateKey: encCAKey, Enabled: true,
	}, nil)
	// No certRepo.On("Create", ...) stub: creation must abort before storing
	// anything, and the hand-written mocks panic on an unexpected call.

	svc := newCertSvc(certRepo, keyRepo)
	_, err = svc.CreateCASignedCertificate(context.Background(), CreateCertificateRequest{
		Name:         "entity-cert",
		KeyID:        keyID,
		ValidityDays: 365,
		UserID:       userID,
		CACertID:     &caCertID,
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "cannot sign certificates")
	certRepo.AssertNotCalled(t, "Create", mock.Anything, mock.Anything)
}

// The same gate, for the other shape a ca_cert_id can wrongly point at: an
// ordinary leaf that was never a CA at all.
func TestCreateCASignedCertificate_LeafAsCARefusesCreation(t *testing.T) {
	setupMasterKey()

	userID := uuid.New()
	keyID := uuid.New()
	caCertID := uuid.New()

	entityKeyPEM, err := crypto.GenerateRSAKeyPEM(2048)
	require.NoError(t, err)
	caKeyPEM, err := crypto.GenerateRSAKeyPEM(2048)
	require.NoError(t, err)

	leafAsCAPEM, err := crypto.CreateSelfSignedCertificatePEM(caKeyPEM, "RSA", crypto.CertificateTemplate{
		CommonName: "not-actually-a-ca", ValidityDays: 3650, IsCA: false,
	})
	require.NoError(t, err)

	encEntityKey, err := common.EncryptSecret(entityKeyPEM)
	require.NoError(t, err)
	encCAKey, err := common.EncryptSecret(caKeyPEM)
	require.NoError(t, err)

	certRepo := &mockCertRepository{}
	keyRepo := &mockKeyRepo{}

	keyRepo.On("Read", mock.Anything, keyID, certVaultScope(userID)).
		Return(&model.Key{ID: keyID, UserID: userID, Type: model.KeyTypeRSA, Value: encEntityKey}, nil)
	certRepo.On("Read", mock.Anything, caCertID, certVaultScope(userID)).Return(&model.Certificate{
		ID: caCertID, UserID: userID, Name: "not-a-ca",
		Certificate: leafAsCAPEM, PrivateKey: encCAKey, Enabled: true,
	}, nil)

	svc := newCertSvc(certRepo, keyRepo)
	_, err = svc.CreateCASignedCertificate(context.Background(), CreateCertificateRequest{
		Name:         "entity-cert",
		KeyID:        keyID,
		ValidityDays: 365,
		UserID:       userID,
		CACertID:     &caCertID,
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "cannot sign certificates")
	certRepo.AssertNotCalled(t, "Create", mock.Anything, mock.Anything)
}

// A renewal result reports the immutable exportable flag and the key algorithm.
func TestRenewCertificate_ResultReportsExportableAndKeyAlgorithm(t *testing.T) {
	f := newCARenewalFixture(t, "RSA")
	f.original.Exportable = true

	result, err := f.svc.RenewCertificate(context.Background(), f.certID, f.scope, 365)
	require.NoError(t, err)
	assert.True(t, result.Exportable)
	assert.Equal(t, crypto.KeyAlgorithmFromCertificatePEM((*f.updated).Certificate), result.KeyAlgorithm)
	assert.NotEmpty(t, result.KeyAlgorithm)
}
