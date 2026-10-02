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

// TestRestore_ForcesExportableFalse pins that a blob claiming exportable
// never restores an exportable item. The blob is sealed now, but the
// exportable decision belongs to the item's creator, so restore still forces
// it off.
func TestRestore_ForcesExportableFalse(t *testing.T) {
	ctx := context.Background()
	keys := newStubKeyRepo()
	certs := newStubCertRepo()
	svc := newTestItemBackupService(newStubSecretRepo(), keys, certs, nil)
	userID, vaultID := uuid.New(), uuid.New()

	keyInner, err := backup.ExportedEncodeBlob("key", uuid.NewString(), &model.Key{
		Name: "k", Type: model.KeyTypeRSA, Value: "enc", Enabled: true, CreatedAt: time.Now(), Exportable: true,
	}, backup.ExportedBlobVersions{})
	require.NoError(t, err)
	keyBlob := sealForTest(t, svc, keyInner)
	newKeyID := uuid.New()
	require.NoError(t, svc.RestoreKey(ctx, keyBlob, userID, vaultID, newKeyID))
	assert.False(t, keys.keys[newKeyID].Exportable)

	certInner, err := backup.ExportedEncodeBlob("certificate", uuid.NewString(), &model.Certificate{
		Name: "c", Certificate: "pem", PrivateKey: "enc", Enabled: true, CreatedAt: time.Now(), Version: 1, Exportable: true,
	}, backup.ExportedBlobVersions{})
	require.NoError(t, err)
	certBlob := sealForTest(t, svc, certInner)
	newCertID := uuid.New()
	require.NoError(t, svc.RestoreCertificate(ctx, certBlob, userID, vaultID, newCertID))
	assert.False(t, certs.certs[newCertID].Exportable)
}
