package certificates

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"rocketvault/common"
	"rocketvault/internal/crypto"
	"rocketvault/model"
)

// addKey stores an RSA key owned by the harness user with the given flag.
func addKey(t *testing.T, h *versioningHarness, exportable bool) uuid.UUID {
	t.Helper()
	keyPEM, err := crypto.GenerateRSAKeyPEM(2048)
	require.NoError(t, err)
	enc, err := common.EncryptSecret(keyPEM)
	require.NoError(t, err)
	id := uuid.New()
	require.NoError(t, h.keyRepo.Create(context.Background(), &model.Key{
		ID: id, UserID: h.userID, VaultID: h.vaultID, Name: "k-" + id.String()[:8],
		Type: model.KeyTypeRSA, Value: enc, Enabled: true, CreatedAt: time.Now(), Bits: 2048, Exportable: exportable,
	}))
	return id
}

func TestCreateCertificate_ExportableRequiresExportableKey(t *testing.T) {
	h := newVersioningHarness(t)
	ctx := context.Background()

	// h.keyID was created without the flag.
	_, err := h.svc.CreateSelfSignedCertificate(ctx, CreateCertificateRequest{
		Name: "refused", KeyID: h.keyID, ValidityDays: 30, UserID: h.userID, VaultID: h.vaultID, Exportable: true,
	})
	require.ErrorIs(t, err, model.ErrExportableKeyRequired)
	assert.Contains(t, err.Error(), "exportable")

	list, err := h.svc.ListCertificates(ctx, h.scope(), model.CertificateFilter{})
	require.NoError(t, err)
	assert.Empty(t, list, "a refused create writes nothing")

	exportableKey := addKey(t, h, true)
	res, err := h.svc.CreateSelfSignedCertificate(ctx, CreateCertificateRequest{
		Name: "allowed", KeyID: exportableKey, ValidityDays: 30, UserID: h.userID, VaultID: h.vaultID, Exportable: true,
	})
	require.NoError(t, err)
	assert.True(t, res.Exportable)
	assert.Equal(t, "RSA-2048", res.KeyAlgorithm)

	stored, err := h.certRepo.Read(ctx, res.CertID, h.scope())
	require.NoError(t, err)
	assert.True(t, stored.Exportable)
}

func TestCreateCertificate_NonExportableOverExportableKeyIsAllowed(t *testing.T) {
	h := newVersioningHarness(t)
	key := addKey(t, h, true)
	res, err := h.svc.CreateSelfSignedCertificate(context.Background(), CreateCertificateRequest{
		Name: "plain", KeyID: key, ValidityDays: 30, UserID: h.userID, VaultID: h.vaultID,
	})
	require.NoError(t, err)
	assert.False(t, res.Exportable, "a create without the field stays non-exportable")
}

func TestCreateCASignedCertificate_ExportableRequiresExportableKey(t *testing.T) {
	h := newVersioningHarness(t)
	ctx := context.Background()
	ca, err := h.svc.CreateSelfSignedCertificate(ctx, CreateCertificateRequest{
		Name: "ca", KeyID: h.keyID, ValidityDays: 365, UserID: h.userID, VaultID: h.vaultID, IsCA: true,
	})
	require.NoError(t, err)

	leafKey := addKey(t, h, false)
	_, err = h.svc.CreateCASignedCertificate(ctx, CreateCertificateRequest{
		Name: "leaf", KeyID: leafKey, CACertID: &ca.CertID, ValidityDays: 30, UserID: h.userID, VaultID: h.vaultID, Exportable: true,
	})
	require.ErrorIs(t, err, model.ErrExportableKeyRequired)

	exportableLeafKey := addKey(t, h, true)
	res, err := h.svc.CreateCASignedCertificate(ctx, CreateCertificateRequest{
		Name: "leaf2", KeyID: exportableLeafKey, CACertID: &ca.CertID, ValidityDays: 30, UserID: h.userID, VaultID: h.vaultID, Exportable: true,
	})
	require.NoError(t, err)
	assert.True(t, res.Exportable)
}

func TestRenewCertificate_PreservesExportable(t *testing.T) {
	h := newVersioningHarness(t)
	ctx := context.Background()
	key := addKey(t, h, true)
	res, err := h.svc.CreateSelfSignedCertificate(ctx, CreateCertificateRequest{
		Name: "renewed", KeyID: key, ValidityDays: 30, UserID: h.userID, VaultID: h.vaultID, Exportable: true,
	})
	require.NoError(t, err)
	_, err = h.svc.RenewCertificate(ctx, res.CertID, h.scope(), 30)
	require.NoError(t, err)
	got, err := h.certRepo.Read(ctx, res.CertID, h.scope())
	require.NoError(t, err)
	assert.Equal(t, 2, got.Version)
	assert.True(t, got.Exportable, "renewal updates the same row and keeps the flag")
}
