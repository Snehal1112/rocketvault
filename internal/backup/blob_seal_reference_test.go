package backup_test

import (
	"context"
	"encoding/hex"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"rocketvault/internal/backup"
	"rocketvault/model"
)

// The literals below pin the sealed blob format. They were generated once
// from the original implementation with testMasterKey, and the derived key
// was checked against an independent HKDF-SHA256 computation. Never
// regenerate them to make this test pass: a failure here means blobs that
// production servers already handed out would stop restoring. A deliberate
// format change needs a new prefix and a new reference, not a new literal.
const (
	// referenceSealKeyHex is HKDF-SHA256(testMasterKey, no salt,
	// "rocketvault item-backup blob seal v2"), 32 bytes.
	referenceSealKeyHex = "656f2ac0729f3608eaf73eea896607c8dfffc7fbad4e0a71f5c3391f5b9e154d"

	// referenceInner is the base64url envelope sealed in referenceBlob.
	referenceInner = "eyJyZXNvdXJjZV90eXBlIjoic2VjcmV0IiwicmVzb3VyY2VfaWQiOiIwMDAwMDAwMC0wMDAwLTAwMDAtMDAwMC0wMDAwMDAwMDAwMDEiLCJkYXRhIjp7ImlkIjoiMDAwMDAwMDAtMDAwMC0wMDAwLTAwMDAtMDAwMDAwMDAwMDAxIiwibmFtZSI6InJlZmVyZW5jZS1zZWNyZXQiLCJ2YWx1ZSI6ImVuYyIsInZlcnNpb24iOjF9fQ=="

	// referenceBlob is "rvb2." followed by standard base64 of a 12-byte
	// nonce, the AES-256-GCM ciphertext and its tag.
	referenceBlob = "rvb2.woT2eOUpPCywTSYfUX4zNbSHXwLwj90JvzVmNpkrfVkONDxrqI5k09eo2gBIpXvaI71GUIoJrPi63iCS8RMdPdGlUsRupven+b8n6AUUskVzmD0lisExAq6Hv63f08/LDowa7GtP8oFR1slDyPfaqzBaThmxgipRyHcgW7aFhEPq8AysU2CAC3hsbcYYtYGoEIt92IBT6U9PlGTKgfukrT9teDmV50sERlVtTx7dhOy7p/ONIMrhl1seU1py8T85sTyNQY1VMiADf5yLFV/ChA0qgq8Y4jXpDTo9EPrnv0Wc8worGMCEzHD+Q9iQBEFsEJmcJtsdEJ7OvbizIFYDByKZM2DZKOkVtAcB10wOH6I5ckgr"
)

// TestSealKey_MatchesReferenceDerivation fails on any change to the HKDF
// hash, salt, info string or key length.
func TestSealKey_MatchesReferenceDerivation(t *testing.T) {
	t.Parallel()

	svc := newTestItemBackupService(nil, nil, nil, nil)
	assert.Equal(t, referenceSealKeyHex, hex.EncodeToString(svc.ExportedSealKey()))
}

// TestOpenBlob_ReferenceBlob fails on any change to the prefix, the nonce
// layout, the cipher or the base64 flavour of the sealed body.
func TestOpenBlob_ReferenceBlob(t *testing.T) {
	t.Parallel()

	svc := newTestItemBackupService(nil, nil, nil, nil)
	inner, err := svc.ExportedOpenBlob(referenceBlob)
	require.NoError(t, err)
	assert.Equal(t, referenceInner, inner)
}

// TestRestoreSecret_ReferenceBlob proves the reference blob restores end to
// end through the public API, not only through openBlob.
func TestRestoreSecret_ReferenceBlob(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	repo := newStubSecretRepo()
	svc := newTestItemBackupService(repo, nil, nil, newStubSecretVersionRepo())
	owner, vaultID, newID := uuid.New(), uuid.New(), uuid.New()

	require.NoError(t, svc.RestoreSecret(ctx, referenceBlob, owner, vaultID, newID))
	restored, err := repo.Read(ctx, newID, model.NewVaultScope(vaultID, owner))
	require.NoError(t, err)
	assert.Equal(t, "reference-secret", restored.Name)
	assert.Equal(t, backup.ExportedSealedBlobPrefix, referenceBlob[:len(backup.ExportedSealedBlobPrefix)])
}
