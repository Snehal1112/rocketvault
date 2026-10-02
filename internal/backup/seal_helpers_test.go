package backup_test

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/require"

	"rocketvault/internal/backup"
	"rocketvault/internal/repositories"
)

// testMasterKey is a fixed 32-byte master key used only by tests.
var testMasterKey = bytes.Repeat([]byte{0x42}, 32)

// newTestItemBackupService builds an ItemBackupService with its seal key set,
// so tests exercise the sealed blob format production uses.
func newTestItemBackupService(
	secretRepo repositories.SecretRepositoryInterface,
	keyRepo repositories.KeyRepositoryInterface,
	certRepo repositories.CertificateRepositoryInterface,
	versionRepo repositories.SecretVersionRepositoryInterface,
) *backup.ItemBackupService {
	svc := backup.NewItemBackupService(secretRepo, keyRepo, certRepo, versionRepo)
	if err := svc.SetSealKey(testMasterKey); err != nil {
		panic(err)
	}
	return svc
}

// sealForTest seals a hand-built inner envelope with svc's key. Tests that
// restore an inner shape no Backup call produces today use it.
func sealForTest(t *testing.T, svc *backup.ItemBackupService, inner string) string {
	t.Helper()
	blob, err := svc.ExportedSealBlob(inner)
	require.NoError(t, err)
	return blob
}
