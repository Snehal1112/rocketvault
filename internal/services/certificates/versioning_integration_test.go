package certificates

import (
	"context"
	"database/sql"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	_ "github.com/mattn/go-sqlite3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"rocketvault/common"
	"rocketvault/internal/crypto"
	rvdb "rocketvault/internal/db"
	"rocketvault/internal/repositories"
	"rocketvault/model"
)

// versioningHarness runs the real certificate service over the real
// repositories and the real schema, so a renewal really archives and really
// commits.
type versioningHarness struct {
	raw      *sql.DB
	certRepo repositories.CertificateRepositoryInterface
	keyRepo  repositories.KeyRepositoryInterface
	versions repositories.CertificateVersionRepositoryInterface
	svc      CertificateService
	userID   uuid.UUID
	vaultID  uuid.UUID
	keyID    uuid.UUID
}

func newVersioningHarness(t *testing.T) *versioningHarness {
	t.Helper()
	setupMasterKey()

	raw, err := sql.Open("sqlite3", "file:certver_"+uuid.NewString()+"?mode=memory&cache=shared")
	require.NoError(t, err)
	t.Cleanup(func() { raw.Close() }) //nolint:errcheck,gosec

	logger := newTestCertLogger()
	require.NoError(t, rvdb.NewRepository(logger).SetupSchema(raw, rvdb.SQLite))
	conn := rvdb.NewConn(raw, rvdb.SQLite)

	h := &versioningHarness{
		raw:      raw,
		certRepo: repositories.NewCertificateRepository(conn, logger),
		keyRepo:  repositories.NewKeyRepository(conn, logger),
		versions: repositories.NewCertificateVersionRepository(conn, logger),
		userID:   uuid.New(),
		vaultID:  uuid.New(),
		keyID:    uuid.New(),
	}
	h.svc = NewCertificateService(CertificateServiceConfig{
		CertificateRepository: h.certRepo,
		KeyRepository:         h.keyRepo,
		VersionRepository:     h.versions,
		Logger:                logger,
	})

	keyPEM, err := crypto.GenerateRSAKeyPEM(2048)
	require.NoError(t, err)
	enc, err := common.EncryptSecret(keyPEM)
	require.NoError(t, err)
	require.NoError(t, h.keyRepo.Create(context.Background(), &model.Key{
		ID: h.keyID, UserID: h.userID, VaultID: h.vaultID, Name: "versioning-key",
		Type: model.KeyTypeRSA, Value: enc, Enabled: true, CreatedAt: time.Now(),
	}))
	return h
}

func (h *versioningHarness) scope() model.Scope { return model.NewVaultScope(h.vaultID, h.userID) }

func (h *versioningHarness) createCert(t *testing.T, name string) uuid.UUID {
	t.Helper()
	result, err := h.svc.CreateSelfSignedCertificate(context.Background(), CreateCertificateRequest{
		Name: name, KeyID: h.keyID, ValidityDays: 365, UserID: h.userID, VaultID: h.vaultID,
	})
	require.NoError(t, err)
	require.Equal(t, 1, result.Version)
	return result.CertID
}

func TestVersioning_RenewTwiceThroughRealRepositories(t *testing.T) {
	h := newVersioningHarness(t)
	ctx := context.Background()
	certID := h.createCert(t, "renew-twice")

	first, err := h.svc.RenewCertificate(ctx, certID, h.scope(), 30)
	require.NoError(t, err)
	assert.Equal(t, 2, first.Version)
	second, err := h.svc.RenewCertificate(ctx, certID, h.scope(), 30)
	require.NoError(t, err)
	assert.Equal(t, 3, second.Version)

	list, err := h.svc.ListCertificateVersions(ctx, certID, h.scope())
	require.NoError(t, err)
	require.Len(t, list, 3)
	assert.Equal(t, []int{1, 2, 3}, []int{list[0].Version, list[1].Version, list[2].Version})
	assert.True(t, list[2].Current)

	cert, err := h.svc.GetCertificate(ctx, certID, h.scope())
	require.NoError(t, err)
	assert.Equal(t, 3, cert.Version)
}

func TestVersioning_CurrentVersionUpdateEqualsCertificateUpdate(t *testing.T) {
	h := newVersioningHarness(t)
	ctx := context.Background()
	viaCert := h.createCert(t, "via-certificate-update")
	viaVersion := h.createCert(t, "via-version-update")

	disabled := false
	notBefore := time.Now().Add(-time.Hour).UTC().Truncate(time.Second)
	require.NoError(t, h.svc.UpdateCertificate(ctx, UpdateCertificateRequest{
		CertID: viaCert, Scope: h.scope(), Enabled: &disabled, NotBefore: &notBefore,
	}))
	_, err := h.svc.UpdateCertificateVersion(ctx, UpdateCertificateVersionRequest{
		CertID: viaVersion, Version: 1, Scope: h.scope(), Enabled: &disabled, NotBefore: &notBefore,
	})
	require.NoError(t, err)

	a, err := h.certRepo.Read(ctx, viaCert, h.scope())
	require.NoError(t, err)
	b, err := h.certRepo.Read(ctx, viaVersion, h.scope())
	require.NoError(t, err)
	assert.Equal(t, a.Enabled, b.Enabled)
	require.NotNil(t, a.NotBefore)
	require.NotNil(t, b.NotBefore)
	assert.True(t, a.NotBefore.Equal(*b.NotBefore))
	assert.Equal(t, a.Version, b.Version)
}

// TestCertificateVersions_OutOfScopeOrDeletedParentIsNotFound pins Review
// Focus 2: certificate_versions has no vault column, so the parent's scoped
// read is the only gate, and a soft-deleted parent hides its history.
func TestCertificateVersions_OutOfScopeOrDeletedParentIsNotFound(t *testing.T) {
	h := newVersioningHarness(t)
	ctx := context.Background()
	certID := h.createCert(t, "scoped-history")
	_, err := h.svc.RenewCertificate(ctx, certID, h.scope(), 30)
	require.NoError(t, err)

	otherVault := model.NewVaultScope(uuid.New(), h.userID)
	enabled := true
	_, err = h.svc.ListCertificateVersions(ctx, certID, otherVault)
	assert.True(t, errors.Is(err, ErrCertNotFound), "list")
	_, err = h.svc.GetCertificateVersion(ctx, certID, 1, otherVault)
	assert.True(t, errors.Is(err, ErrCertNotFound), "get")
	_, err = h.svc.UpdateCertificateVersion(ctx, UpdateCertificateVersionRequest{
		CertID: certID, Version: 1, Scope: otherVault, Enabled: &enabled,
	})
	assert.True(t, errors.Is(err, ErrCertNotFound), "update")
	_, err = h.svc.RenewCertificate(ctx, certID, otherVault, 30)
	assert.True(t, errors.Is(err, ErrCertNotFound), "renew")

	require.NoError(t, h.svc.DeleteCertificate(ctx, certID, h.scope()))
	_, err = h.svc.ListCertificateVersions(ctx, certID, h.scope())
	assert.True(t, errors.Is(err, ErrCertNotFound), "a soft-deleted parent is a 404")
}

func TestCheckAndRenewCertificates_CreatesVersionWithPreservedValidity(t *testing.T) {
	h := newVersioningHarness(t)
	ctx := context.Background()
	certID := h.createCert(t, "auto-renewed")

	// Move the certificate into its renewal window, with a 365-day validity.
	now := time.Now().UTC()
	created := now.Add(-355 * 24 * time.Hour)
	expires := now.Add(10 * 24 * time.Hour)
	_, err := h.raw.Exec("UPDATE certificates SET created_at = ?, expires_at = ?, auto_renew = ?, renewal_days = ? WHERE id = ?",
		created, expires, true, 30, certID.String())
	require.NoError(t, err)

	scheduler := NewCertificateRenewalService(RenewalServiceConfig{
		CertRepository:     h.certRepo,
		CertificateService: h.svc,
		Logger:             newTestCertLogger(),
		SignAuthorizer:     allowSign,
	})
	renewed, warned, err := scheduler.CheckAndRenewCertificates(ctx)
	require.NoError(t, err)
	assert.Equal(t, 1, renewed)
	assert.Zero(t, warned)

	versions, err := h.svc.ListCertificateVersions(ctx, certID, h.scope())
	require.NoError(t, err)
	require.Len(t, versions, 2)
	assert.Equal(t, 1, versions[0].Version)
	assert.False(t, versions[0].Current)
	require.NotNil(t, versions[0].ExpiresAt)
	assert.WithinDuration(t, expires, *versions[0].ExpiresAt, time.Second)

	assert.Equal(t, 2, versions[1].Version)
	assert.True(t, versions[1].Current)
	require.NotNil(t, versions[1].ExpiresAt)
	assert.WithinDuration(t, time.Now().AddDate(0, 0, 365), *versions[1].ExpiresAt, 24*time.Hour,
		"validity is computed from the current version's created_at and expires_at")
}
