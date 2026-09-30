package certificates

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"rocketvault/common"
	"rocketvault/internal/crypto"
	"rocketvault/internal/repositories"
	"rocketvault/model"
)

// selfSignedRenewalFixture is a self-signed certificate at a chosen version,
// wired to mocks and a fake version repository that records every write.
type selfSignedRenewalFixture struct {
	svc      CertificateService
	certRepo *mockCertRepository
	keyRepo  *mockKeyRepo
	versions *fakeCertVersionRepo
	scope    model.Scope
	original *model.Certificate
}

// newSelfSignedRenewalFixture issues the stored body with one key. When
// currentKeyPEM is non-empty the key row holds that PEM instead, which is
// what the certificate's key looks like after a key rotation.
func newSelfSignedRenewalFixture(t *testing.T, version int, currentKeyPEM string) *selfSignedRenewalFixture {
	t.Helper()
	setupMasterKey()

	userID, vaultID, certID, keyID := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	issuedKeyPEM, err := crypto.GenerateRSAKeyPEM(2048)
	require.NoError(t, err)
	body, err := crypto.CreateSelfSignedCertificatePEM(issuedKeyPEM, "RSA", crypto.CertificateTemplate{
		CommonName: "versioned-cert", ValidityDays: 365,
	})
	require.NoError(t, err)
	issuedEnc, err := common.EncryptSecret(issuedKeyPEM)
	require.NoError(t, err)
	if currentKeyPEM == "" {
		currentKeyPEM = issuedKeyPEM
	}
	currentEnc, err := common.EncryptSecret(currentKeyPEM)
	require.NoError(t, err)

	scope := model.NewVaultScope(vaultID, userID)
	expires := time.Now().Add(20 * 24 * time.Hour)
	original := &model.Certificate{
		ID: certID, UserID: userID, VaultID: vaultID, KeyID: keyID, Name: "versioned-cert",
		Certificate: body, PrivateKey: issuedEnc, CreatedAt: time.Now().Add(-345 * 24 * time.Hour),
		ExpiresAt: &expires, Enabled: true, RenewalDays: 30, Version: version,
	}

	certRepo := &mockCertRepository{}
	keyRepo := &mockKeyRepo{}
	certRepo.On("Read", mock.Anything, certID, scope).Return(original, nil)
	keyRepo.On("Read", mock.Anything, keyID, scope).
		Return(&model.Key{ID: keyID, UserID: userID, Type: model.KeyTypeRSA, Value: currentEnc}, nil)

	versions := &fakeCertVersionRepo{}
	return &selfSignedRenewalFixture{
		svc:      newCertSvcWithVersions(certRepo, keyRepo, versions),
		certRepo: certRepo,
		keyRepo:  keyRepo,
		versions: versions,
		scope:    scope,
		original: original,
	}
}

func TestRenewCertificate_ArchivesCurrentVersionAndBumpsParent(t *testing.T) {
	f := newSelfSignedRenewalFixture(t, 3, "")
	originalBody := f.original.Certificate
	originalKey := f.original.PrivateKey
	originalExpiry := *f.original.ExpiresAt

	result, err := f.svc.RenewCertificate(context.Background(), f.original.ID, f.scope, 90)
	require.NoError(t, err)

	require.Len(t, f.versions.archived, 1)
	archived := f.versions.archived[0]
	assert.Equal(t, 3, archived.Version)
	assert.Equal(t, originalBody, archived.Certificate)
	assert.Equal(t, originalKey, archived.PrivateKey)
	assert.Equal(t, f.original.KeyID, archived.KeyID)
	require.NotNil(t, archived.ExpiresAt)
	assert.Equal(t, originalExpiry, *archived.ExpiresAt)

	renewed := f.versions.renewed
	require.NotNil(t, renewed)
	assert.Equal(t, 4, renewed.Version)
	assert.NotEqual(t, originalBody, renewed.Certificate)
	assert.True(t, renewed.Enabled)
	require.NotNil(t, renewed.NotBefore, "a new version takes not_before from its certificate")
	require.NotNil(t, renewed.ExpiresAt)
	assert.WithinDuration(t, time.Now().AddDate(0, 0, 90), *renewed.ExpiresAt, 24*time.Hour)
	assert.Equal(t, 4, result.Version)
}

func TestRenewCertificate_PreVersioningRowArchivesAsVersionOne(t *testing.T) {
	f := newSelfSignedRenewalFixture(t, 0, "")

	result, err := f.svc.RenewCertificate(context.Background(), f.original.ID, f.scope, 90)
	require.NoError(t, err)
	require.Len(t, f.versions.archived, 1)
	assert.Equal(t, 1, f.versions.archived[0].Version)
	assert.Equal(t, 2, result.Version)
}

func TestRenewCertificate_GuardFailureWritesNoVersion(t *testing.T) {
	cases := []struct {
		name      string
		mutate    func(*model.Certificate)
		validity  int
		wantIsErr error
	}{
		{"disabled certificate", func(c *model.Certificate) { c.Enabled = false }, 90, ErrCertLifecycleDenied},
		{"no key", func(c *model.Certificate) { c.KeyID = uuid.Nil }, 90, nil},
		{"non-positive validity", func(*model.Certificate) {}, 0, nil},
		{"legacy CA-signed row with no link", func(c *model.Certificate) { c.Certificate = foreignIssuerPEM(t) }, 90, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newSelfSignedRenewalFixture(t, 2, "")
			tc.mutate(f.original)

			_, err := f.svc.RenewCertificate(context.Background(), f.original.ID, f.scope, tc.validity)
			require.Error(t, err)
			if tc.wantIsErr != nil {
				assert.True(t, errors.Is(err, tc.wantIsErr))
			}
			assert.Empty(t, f.versions.archived, "a guard failure must write no version")
			assert.Nil(t, f.versions.renewed)
		})
	}
}

// foreignIssuerPEM returns a leaf signed by a separate CA, so it is not
// self-signed and carries no ca_cert_id link.
func foreignIssuerPEM(t *testing.T) string {
	t.Helper()
	caKeyPEM, err := crypto.GenerateRSAKeyPEM(2048)
	require.NoError(t, err)
	caPEM, err := crypto.CreateSelfSignedCertificatePEM(caKeyPEM, "RSA", crypto.CertificateTemplate{
		CommonName: "Foreign CA", ValidityDays: 3650, IsCA: true,
	})
	require.NoError(t, err)
	leafKeyPEM, err := crypto.GenerateRSAKeyPEM(2048)
	require.NoError(t, err)
	leafPEM, err := crypto.CreateCASignedCertificatePEM(leafKeyPEM, "RSA", caPEM, caKeyPEM, "RSA", crypto.CertificateTemplate{
		CommonName: "versioned-cert", ValidityDays: 365,
	})
	require.NoError(t, err)
	return leafPEM
}

func TestRenewCertificate_VersionConflictKeepsSentinel(t *testing.T) {
	f := newSelfSignedRenewalFixture(t, 2, "")
	f.versions.archiveErr = fmt.Errorf("lost the race: %w", repositories.ErrCertificateVersionConflict)

	_, err := f.svc.RenewCertificate(context.Background(), f.original.ID, f.scope, 90)
	require.Error(t, err)
	assert.True(t, errors.Is(err, model.ErrCertificateVersionConflict), "the API maps this sentinel to 409")
}

func TestRenewCertificate_AfterKeyRotationKeepsArchivedKeyCopy(t *testing.T) {
	rotatedPEM, err := crypto.GenerateRSAKeyPEM(2048)
	require.NoError(t, err)
	f := newSelfSignedRenewalFixture(t, 1, rotatedPEM)
	issuedKey := f.original.PrivateKey

	_, err = f.svc.RenewCertificate(context.Background(), f.original.ID, f.scope, 90)
	require.NoError(t, err)

	require.Len(t, f.versions.archived, 1)
	assert.Equal(t, issuedKey, f.versions.archived[0].PrivateKey,
		"a version keeps the key it was issued with")
	renewedKey, err := common.DecryptSecret(f.versions.renewed.PrivateKey)
	require.NoError(t, err)
	assert.Equal(t, rotatedPEM, renewedKey, "the new version is issued over the rotated key")
}

func TestRenewCertificate_WithoutVersionRepositoryFailsClosed(t *testing.T) {
	f := newSelfSignedRenewalFixture(t, 1, "")
	svc := NewCertificateService(CertificateServiceConfig{
		CertificateRepository: f.certRepo,
		KeyRepository:         f.keyRepo,
		Logger:                newTestCertLogger(),
	})

	_, err := svc.RenewCertificate(context.Background(), f.original.ID, f.scope, 90)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrCertVersioningUnavailable))
	f.certRepo.AssertNotCalled(t, "Update", mock.Anything, mock.Anything, mock.Anything)
}

func TestListCertificateVersions_ArchivedThenCurrent(t *testing.T) {
	f := newSelfSignedRenewalFixture(t, 3, "")
	f.versions.stored = []model.CertificateVersion{
		{CertificateID: f.original.ID, Version: 1, Enabled: true},
		{CertificateID: f.original.ID, Version: 2, Enabled: false},
	}

	list, err := f.svc.ListCertificateVersions(context.Background(), f.original.ID, f.scope)
	require.NoError(t, err)
	require.Len(t, list, 3)
	assert.Equal(t, []int{1, 2, 3}, []int{list[0].Version, list[1].Version, list[2].Version})
	assert.True(t, list[2].Current)
	assert.False(t, list[0].Current)
}

func TestGetCertificateVersion(t *testing.T) {
	f := newSelfSignedRenewalFixture(t, 3, "")
	f.versions.stored = []model.CertificateVersion{{CertificateID: f.original.ID, Version: 2, Enabled: true}}
	ctx := context.Background()

	current, err := f.svc.GetCertificateVersion(ctx, f.original.ID, 3, f.scope)
	require.NoError(t, err)
	assert.True(t, current.Current)

	archived, err := f.svc.GetCertificateVersion(ctx, f.original.ID, 2, f.scope)
	require.NoError(t, err)
	assert.False(t, archived.Current)

	for _, missing := range []int{0, 4} {
		_, err := f.svc.GetCertificateVersion(ctx, f.original.ID, missing, f.scope)
		assert.True(t, errors.Is(err, model.ErrCertificateVersionNotFound), "version %d", missing)
	}
}

func TestUpdateCertificateVersion_RejectsNotBeforeAfterExpiry(t *testing.T) {
	f := newSelfSignedRenewalFixture(t, 1, "")
	early := time.Now()
	late := early.Add(time.Hour)

	_, err := f.svc.UpdateCertificateVersion(context.Background(), UpdateCertificateVersionRequest{
		CertID: f.original.ID, Version: 1, Scope: f.scope, NotBefore: &late, ExpiresAt: &early,
	})
	require.Error(t, err)
	assert.True(t, errors.Is(err, model.ErrInvalidCertificateVersionAttributes))
	assert.Empty(t, f.versions.currentUpdates)
}

func TestUpdateCertificateVersion_NoAttributesRejected(t *testing.T) {
	f := newSelfSignedRenewalFixture(t, 1, "")

	_, err := f.svc.UpdateCertificateVersion(context.Background(), UpdateCertificateVersionRequest{
		CertID: f.original.ID, Version: 1, Scope: f.scope,
	})
	assert.True(t, errors.Is(err, model.ErrInvalidCertificateVersionAttributes))
}

func TestUpdateCertificateVersion_RoutesCurrentAndArchived(t *testing.T) {
	f := newSelfSignedRenewalFixture(t, 3, "")
	f.versions.stored = []model.CertificateVersion{{CertificateID: f.original.ID, Version: 2, Enabled: true}}
	disabled := false
	ctx := context.Background()

	current, err := f.svc.UpdateCertificateVersion(ctx, UpdateCertificateVersionRequest{
		CertID: f.original.ID, Version: 3, Scope: f.scope, Enabled: &disabled,
	})
	require.NoError(t, err)
	assert.True(t, current.Current)
	assert.False(t, current.Enabled)
	require.Len(t, f.versions.currentUpdates, 1)
	assert.False(t, f.versions.currentUpdates[0].Enabled)
	assert.Equal(t, f.original.ExpiresAt, f.versions.currentUpdates[0].ExpiresAt, "untouched attributes are kept")

	archived, err := f.svc.UpdateCertificateVersion(ctx, UpdateCertificateVersionRequest{
		CertID: f.original.ID, Version: 2, Scope: f.scope, Enabled: &disabled,
	})
	require.NoError(t, err)
	assert.False(t, archived.Current)
	assert.False(t, f.versions.archivedUpdates[2].Enabled)
}

func TestCertificateVersionMethods_UnknownParentIsNotFound(t *testing.T) {
	f := newSelfSignedRenewalFixture(t, 1, "")
	other := uuid.New()
	f.certRepo.On("Read", mock.Anything, other, f.scope).Return(nil, errors.New("certificate not found or access denied"))

	_, err := f.svc.ListCertificateVersions(context.Background(), other, f.scope)
	assert.True(t, errors.Is(err, ErrCertNotFound))
}
