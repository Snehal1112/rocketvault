package certificates

import (
	"context"
	"errors"
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

// TestValidateKeyOwnership_RefusesUnusableKey is the B77 regression. The key
// crypto path refuses these keys in loadAndAuthorize; issuing a certificate
// signs with the key, so it must refuse them too.
func TestValidateKeyOwnership_RefusesUnusableKey(t *testing.T) {
	t.Parallel()

	past := time.Now().Add(-time.Hour)
	future := time.Now().Add(time.Hour)
	cases := []struct {
		name string
		key  model.Key
	}{
		{"revoked", model.Key{Enabled: true, Revoked: true}},
		{"disabled", model.Key{Enabled: false}},
		{"expired", model.Key{Enabled: true, ExpiresAt: &past}},
		{"not yet active", model.Key{Enabled: true, NotBefore: &future}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			userID, keyID, vaultID := uuid.New(), uuid.New(), uuid.New()
			key := tc.key
			key.ID, key.UserID, key.VaultID = keyID, userID, vaultID
			keyRepo := &mockKeyRepo{}
			vaultScopedKeyRepo(keyRepo, keyID, vaultID, &key)

			svc := newCertSvc(&mockCertRepository{}, keyRepo)
			err := svc.ValidateKeyOwnership(context.Background(), keyID, model.NewVaultScope(vaultID, userID))
			require.ErrorIs(t, err, ErrSigningKeyUnusable)
		})
	}
}

func TestValidateKeyOwnership_AcceptsUsableKey(t *testing.T) {
	t.Parallel()

	future := time.Now().Add(time.Hour)
	userID, keyID, vaultID := uuid.New(), uuid.New(), uuid.New()
	keyRepo := &mockKeyRepo{}
	vaultScopedKeyRepo(keyRepo, keyID, vaultID, &model.Key{
		ID: keyID, UserID: userID, VaultID: vaultID, Enabled: true, ExpiresAt: &future,
	})

	svc := newCertSvc(&mockCertRepository{}, keyRepo)
	require.NoError(t, svc.ValidateKeyOwnership(context.Background(), keyID, model.NewVaultScope(vaultID, userID)))
}

func TestCreateSelfSignedCertificate_RefusesRevokedKey(t *testing.T) {
	t.Parallel()

	userID, keyID, vaultID := uuid.New(), uuid.New(), uuid.New()
	keyRepo := &mockKeyRepo{}
	vaultScopedKeyRepo(keyRepo, keyID, vaultID, &model.Key{
		ID: keyID, UserID: userID, VaultID: vaultID, Enabled: true, Revoked: true,
	})
	certRepo := &mockCertRepository{}

	svc := newCertSvc(certRepo, keyRepo)
	_, err := svc.CreateSelfSignedCertificate(context.Background(), CreateCertificateRequest{
		Name: "revoked-key-cert", KeyID: keyID, ValidityDays: 30, UserID: userID, VaultID: vaultID,
	})
	require.ErrorIs(t, err, ErrSigningKeyUnusable)
	certRepo.AssertNotCalled(t, "Create", mock.Anything, mock.Anything)
}

// TestRenewCertificate_RefusesDisabledKey covers the renewal path, which
// reads its key inline rather than through ValidateKeyOwnership.
func TestRenewCertificate_RefusesDisabledKey(t *testing.T) {
	t.Parallel()

	userID, keyID, vaultID, certID := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	scope := model.NewVaultScope(vaultID, userID)
	certRepo := &mockCertRepository{}
	certRepo.On("Read", mock.Anything, certID, scope).Return(&model.Certificate{
		ID: certID, UserID: userID, VaultID: vaultID, KeyID: keyID, Name: "c", Enabled: true,
	}, nil)
	keyRepo := &mockKeyRepo{}
	vaultScopedKeyRepo(keyRepo, keyID, vaultID, &model.Key{
		ID: keyID, UserID: userID, VaultID: vaultID, Enabled: false,
	})

	svc := newCertSvc(certRepo, keyRepo)
	_, err := svc.RenewCertificate(context.Background(), certID, scope, 30)
	require.ErrorIs(t, err, ErrSigningKeyUnusable)
	certRepo.AssertNotCalled(t, "Update", mock.Anything, mock.Anything, mock.Anything)
}

// keyLifecycleCase names one lifecycle state of a signing key. The tests
// below run every issuing path over the same states, with real key material,
// so that a refused case would otherwise have signed and written.
type keyLifecycleCase struct {
	name   string
	mutate func(k *model.Key)
	usable bool
}

func keyLifecycleCases() []keyLifecycleCase {
	past := time.Now().Add(-time.Hour)
	future := time.Now().Add(time.Hour)
	return []keyLifecycleCase{
		{"usable", func(*model.Key) {}, true},
		{"usable inside its window", func(k *model.Key) { k.NotBefore, k.ExpiresAt = &past, &future }, true},
		{"revoked", func(k *model.Key) { k.Revoked = true }, false},
		{"disabled", func(k *model.Key) { k.Enabled = false }, false},
		{"expired", func(k *model.Key) { k.ExpiresAt = &past }, false},
		{"not yet active", func(k *model.Key) { k.NotBefore = &future }, false},
	}
}

// signingMaterial is a real ECDSA key, stored encrypted the way the key
// repository stores it, so every path can actually sign with it.
type signingMaterial struct {
	pem       string
	encrypted string
}

func newSigningMaterial(t *testing.T) signingMaterial {
	t.Helper()
	keyPEM, err := crypto.GenerateECDSAKeyPEM("P-256")
	require.NoError(t, err)
	enc, err := common.EncryptSecret(keyPEM)
	require.NoError(t, err)
	return signingMaterial{pem: keyPEM, encrypted: enc}
}

// signingKey returns an enabled key row owned by userID in vaultID.
func (m signingMaterial) signingKey(keyID, userID, vaultID uuid.UUID) *model.Key {
	return &model.Key{
		ID: keyID, UserID: userID, VaultID: vaultID, Name: "signing-key",
		Type: model.KeyTypeECDSA, Value: m.encrypted, Enabled: true,
	}
}

// TestCreateSelfSignedCertificate_SigningKeyLifecycle pins B77 on the
// self-signed create path: an unusable key is refused before the certificate
// is stored, and a usable key still issues.
func TestCreateSelfSignedCertificate_SigningKeyLifecycle(t *testing.T) {
	setupMasterKey()
	material := newSigningMaterial(t)

	for _, tc := range keyLifecycleCases() {
		t.Run(tc.name, func(t *testing.T) {
			userID, keyID, vaultID := uuid.New(), uuid.New(), uuid.New()
			key := material.signingKey(keyID, userID, vaultID)
			tc.mutate(key)
			keyRepo := &mockKeyRepo{}
			vaultScopedKeyRepo(keyRepo, keyID, vaultID, key)
			certRepo := &mockCertRepository{}
			// Registered for every case, so a missing refusal shows up as a
			// write the assertions below catch rather than as a mock panic.
			certRepo.On("Create", mock.Anything, mock.AnythingOfType("*model.Certificate")).Return(nil).Maybe()

			svc := newCertSvc(certRepo, keyRepo)
			res, err := svc.CreateSelfSignedCertificate(context.Background(), CreateCertificateRequest{
				Name: "lifecycle-self-signed", KeyID: keyID, ValidityDays: 30, UserID: userID, VaultID: vaultID,
			})

			if tc.usable {
				require.NoError(t, err)
				require.NotNil(t, res)
				certRepo.AssertCalled(t, "Create", mock.Anything, mock.AnythingOfType("*model.Certificate"))
				return
			}
			require.ErrorIs(t, err, ErrSigningKeyUnusable)
			certRepo.AssertNotCalled(t, "Create", mock.Anything, mock.Anything)
		})
	}
}

// TestCreateCASignedCertificate_SigningKeyLifecycle pins B77 on the CA-signed
// create path. The leaf key is refused before the CA is even read, so nothing
// is signed or stored.
func TestCreateCASignedCertificate_SigningKeyLifecycle(t *testing.T) {
	setupMasterKey()
	leaf := newSigningMaterial(t)
	ca := newSigningMaterial(t)
	caPEM, err := crypto.CreateSelfSignedCertificatePEM(ca.pem, model.KeyTypeECDSA, crypto.CertificateTemplate{
		CommonName: "Lifecycle CA", ValidityDays: 3650, IsCA: true,
	})
	require.NoError(t, err)

	for _, tc := range keyLifecycleCases() {
		t.Run(tc.name, func(t *testing.T) {
			userID, keyID, vaultID := uuid.New(), uuid.New(), uuid.New()
			caCertID, caKeyID := uuid.New(), uuid.New()
			scope := model.NewVaultScope(vaultID, userID)

			key := leaf.signingKey(keyID, userID, vaultID)
			tc.mutate(key)
			keyRepo := &mockKeyRepo{}
			vaultScopedKeyRepo(keyRepo, keyID, vaultID, key)
			// The CA links a usable key of its own, so the CA side never is
			// the reason a case is refused.
			vaultScopedKeyRepo(keyRepo, caKeyID, vaultID, ca.signingKey(caKeyID, userID, vaultID))

			certRepo := &mockCertRepository{}
			certRepo.On("Read", mock.Anything, caCertID, scope).Return(&model.Certificate{
				ID: caCertID, UserID: userID, VaultID: vaultID, KeyID: caKeyID, Name: "lifecycle-ca",
				Certificate: caPEM, PrivateKey: ca.encrypted, Enabled: true,
			}, nil)
			certRepo.On("Create", mock.Anything, mock.AnythingOfType("*model.Certificate")).Return(nil).Maybe()

			svc := newCertSvc(certRepo, keyRepo)
			res, err := svc.CreateCASignedCertificate(context.Background(), CreateCertificateRequest{
				Name: "lifecycle-ca-signed", KeyID: keyID, ValidityDays: 30, UserID: userID, VaultID: vaultID,
				CACertID: &caCertID,
			})

			if tc.usable {
				require.NoError(t, err)
				require.NotNil(t, res)
				certRepo.AssertCalled(t, "Create", mock.Anything, mock.AnythingOfType("*model.Certificate"))
				return
			}
			require.ErrorIs(t, err, ErrSigningKeyUnusable)
			certRepo.AssertNotCalled(t, "Create", mock.Anything, mock.Anything)
			certRepo.AssertNotCalled(t, "Read", mock.Anything, caCertID, mock.Anything)
		})
	}
}

// renewLifecycleFixture is a self-signed certificate that RenewCertificate
// can really renew when its key is usable.
type renewLifecycleFixture struct {
	certID   uuid.UUID
	scope    model.Scope
	original *model.Certificate
	key      *model.Key
	certRepo *mockCertRepository
	keyRepo  *mockKeyRepo
	versions *fakeCertVersionRepo
	svc      CertificateService
}

func newRenewLifecycleFixture(t *testing.T, material signingMaterial, tc keyLifecycleCase) *renewLifecycleFixture {
	t.Helper()
	userID, keyID, vaultID, certID := uuid.New(), uuid.New(), uuid.New(), uuid.New()

	certPEM, err := crypto.CreateSelfSignedCertificatePEM(material.pem, model.KeyTypeECDSA, crypto.CertificateTemplate{
		CommonName: "lifecycle-renew", ValidityDays: 365,
	})
	require.NoError(t, err)

	// Inside its renewal window, so the scheduler picks it up too.
	expiresAt := time.Now().Add(5 * 24 * time.Hour)
	original := &model.Certificate{
		ID: certID, UserID: userID, VaultID: vaultID, KeyID: keyID, Name: "lifecycle-renew",
		Certificate: certPEM, PrivateKey: material.encrypted, Version: 1,
		CreatedAt: time.Now().Add(-360 * 24 * time.Hour), ExpiresAt: &expiresAt,
		AutoRenew: true, RenewalDays: 30, Enabled: true,
	}
	key := material.signingKey(keyID, userID, vaultID)
	tc.mutate(key)

	f := &renewLifecycleFixture{
		certID: certID, scope: model.NewVaultScope(vaultID, userID), original: original, key: key,
		certRepo: &mockCertRepository{}, keyRepo: &mockKeyRepo{},
	}
	f.certRepo.On("Read", mock.Anything, certID, f.scope).Return(original, nil)
	vaultScopedKeyRepo(f.keyRepo, keyID, vaultID, key)
	// Registered for every case, so a missing refusal shows up as a write
	// assertNothingWritten catches rather than as a mock panic.
	f.certRepo.On("Update", mock.Anything, mock.AnythingOfType("*model.Certificate"), f.scope).Return(nil).Maybe()
	f.versions = &fakeCertVersionRepo{certRepo: f.certRepo}
	f.svc = newCertSvcWithVersions(f.certRepo, f.keyRepo, f.versions)
	return f
}

// assertNothingWritten checks that no version was archived and no row was
// renewed, which is what a refusal before signing must leave behind.
func (f *renewLifecycleFixture) assertNothingWritten(t *testing.T) {
	t.Helper()
	assert.Empty(t, f.versions.archived, "a refused renewal must archive nothing")
	assert.Nil(t, f.versions.renewed, "a refused renewal must renew nothing")
	f.certRepo.AssertNotCalled(t, "Update", mock.Anything, mock.Anything, mock.Anything)
}

// TestRenewCertificate_SigningKeyLifecycle pins B77 on RenewCertificate, the
// path the HTTP renew route, the CLI and the MCP tool all reach.
func TestRenewCertificate_SigningKeyLifecycle(t *testing.T) {
	setupMasterKey()
	material := newSigningMaterial(t)

	for _, tc := range keyLifecycleCases() {
		t.Run(tc.name, func(t *testing.T) {
			f := newRenewLifecycleFixture(t, material, tc)

			res, err := f.svc.RenewCertificate(context.Background(), f.certID, f.scope, 30)

			if tc.usable {
				require.NoError(t, err)
				require.NotNil(t, res)
				require.Len(t, f.versions.archived, 1)
				require.NotNil(t, f.versions.renewed)
				return
			}
			require.ErrorIs(t, err, ErrSigningKeyUnusable)
			f.assertNothingWritten(t)
		})
	}
}

// TestCheckAndRenewCertificates_SigningKeyLifecycle pins B77 on the
// unattended path: the scheduler reaches RenewCertificate, so it inherits the
// refusal, counts nothing as renewed, and writes nothing.
func TestCheckAndRenewCertificates_SigningKeyLifecycle(t *testing.T) {
	setupMasterKey()
	material := newSigningMaterial(t)

	for _, tc := range keyLifecycleCases() {
		t.Run(tc.name, func(t *testing.T) {
			f := newRenewLifecycleFixture(t, material, tc)
			f.certRepo.On("ListAll", mock.Anything).Return([]model.Certificate{*f.original}, nil)

			renewalSvc := NewCertificateRenewalService(RenewalServiceConfig{
				CertRepository:     f.certRepo,
				CertificateService: f.svc,
				Logger:             newTestCertLogger(),
			})
			renewed, warned, err := renewalSvc.CheckAndRenewCertificates(context.Background())
			require.NoError(t, err)
			require.Equal(t, 0, warned)

			if tc.usable {
				require.Equal(t, 1, renewed)
				require.Len(t, f.versions.archived, 1)
				return
			}
			require.Equal(t, 0, renewed)
			f.assertNothingWritten(t)
		})
	}
}

// TestSigningKeyLifecycle_OwnerCheckRunsFirst pins the ordering: a key that
// is both foreign and unusable is refused by the B32 owner check with its
// unchanged error, never by the lifecycle check.
func TestSigningKeyLifecycle_OwnerCheckRunsFirst(t *testing.T) {
	setupMasterKey()
	material := newSigningMaterial(t)
	unusable := keyLifecycleCase{name: "foreign and revoked", mutate: func(k *model.Key) {
		k.UserID = uuid.New()
		k.Revoked = true
		k.Enabled = false
	}}

	t.Run("ValidateKeyOwnership", func(t *testing.T) {
		userID, keyID, vaultID := uuid.New(), uuid.New(), uuid.New()
		key := material.signingKey(keyID, userID, vaultID)
		unusable.mutate(key)
		keyRepo := &mockKeyRepo{}
		vaultScopedKeyRepo(keyRepo, keyID, vaultID, key)

		svc := newCertSvc(&mockCertRepository{}, keyRepo)
		err := svc.ValidateKeyOwnership(context.Background(), keyID, model.NewVaultScope(vaultID, userID))
		require.Error(t, err)
		assert.Equal(t, "forbidden: cannot use other users' keys", err.Error())
		assert.NotErrorIs(t, err, ErrSigningKeyUnusable)
	})

	t.Run("ValidateKeyOwnership missing key", func(t *testing.T) {
		userID, keyID, vaultID := uuid.New(), uuid.New(), uuid.New()
		keyRepo := &mockKeyRepo{}
		keyRepo.On("Read", mock.Anything, keyID, mock.Anything).Return(nil, errors.New("not found"))

		svc := newCertSvc(&mockCertRepository{}, keyRepo)
		err := svc.ValidateKeyOwnership(context.Background(), keyID, model.NewVaultScope(vaultID, userID))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "key not found")
		assert.NotErrorIs(t, err, ErrSigningKeyUnusable)
	})

	t.Run("RenewCertificate", func(t *testing.T) {
		f := newRenewLifecycleFixture(t, material, unusable)

		_, err := f.svc.RenewCertificate(context.Background(), f.certID, f.scope, 30)
		require.ErrorIs(t, err, ErrRenewKeyForbidden)
		assert.Equal(t, "forbidden: cannot use other users' keys", err.Error())
		assert.NotErrorIs(t, err, ErrSigningKeyUnusable)
		f.assertNothingWritten(t)
	})
}
