package backup_test

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"rocketvault/internal/backup"
	"rocketvault/model"
)

// TestRestore_ForcesExportableFalse pins that a blob claiming exportable,
// whether genuine or edited (the blob is unauthenticated base64 JSON), never
// restores an exportable item.
func TestRestore_ForcesExportableFalse(t *testing.T) {
	ctx := context.Background()
	keys := newStubKeyRepo()
	certs := newStubCertRepo()
	svc := backup.NewItemBackupService(newStubSecretRepo(), keys, certs, nil)
	userID, vaultID := uuid.New(), uuid.New()

	keyBlob, err := backup.ExportedEncodeBlob("key", uuid.NewString(), &model.Key{
		Name: "k", Type: model.KeyTypeRSA, Value: "enc", Enabled: true, CreatedAt: time.Now(), Exportable: true,
	}, backup.ExportedBlobVersions{})
	require.NoError(t, err)
	newKeyID := uuid.New()
	require.NoError(t, svc.RestoreKey(ctx, keyBlob, userID, vaultID, newKeyID))
	assert.False(t, keys.keys[newKeyID].Exportable)

	certBlob, err := backup.ExportedEncodeBlob("certificate", uuid.NewString(), &model.Certificate{
		Name: "c", Certificate: "pem", PrivateKey: "enc", Enabled: true, CreatedAt: time.Now(), Version: 1, Exportable: true,
	}, backup.ExportedBlobVersions{})
	require.NoError(t, err)
	newCertID := uuid.New()
	require.NoError(t, svc.RestoreCertificate(ctx, certBlob, userID, vaultID, newCertID))
	assert.False(t, certs.certs[newCertID].Exportable)
}
