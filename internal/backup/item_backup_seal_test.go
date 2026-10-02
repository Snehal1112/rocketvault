package backup_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"rocketvault/common"
	"rocketvault/internal/backup"
	"rocketvault/model"
)

// legacyBlob hand-builds a blob in the pre-sealing format: a bare base64url
// JSON envelope, which anyone can write.
func legacyBlob(t *testing.T, resourceType string, data any) string {
	t.Helper()
	raw, err := json.Marshal(data)
	require.NoError(t, err)
	env, err := json.Marshal(map[string]any{
		"resource_type": resourceType,
		"resource_id":   uuid.New().String(),
		"data":          json.RawMessage(raw),
	})
	require.NoError(t, err)
	return base64.URLEncoding.EncodeToString(env)
}

func TestBackupBlob_IsSealed(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	owner, vaultID := uuid.New(), uuid.New()
	repo := newStubCertRepo()
	cert := &model.Certificate{ID: uuid.New(), UserID: owner, VaultID: vaultID, Name: "sealed-cert"}
	require.NoError(t, repo.Create(ctx, cert))
	svc := newTestItemBackupService(nil, nil, repo, nil)

	blob, err := svc.BackupCertificate(ctx, cert.ID, owner, vaultID)
	require.NoError(t, err)
	assert.True(t, strings.HasPrefix(blob, backup.ExportedSealedBlobPrefix),
		"a new blob must carry the sealed-format marker")
	_, decodeErr := base64.URLEncoding.DecodeString(blob)
	assert.Error(t, decodeErr, "a sealed blob must not be a bare base64url envelope")
}

// TestBackupCertificate_SealedBlobKeepsVersionHistory guards the version-aware
// envelope: sealing wraps it, and must not drop certificate_versions.
func TestBackupCertificate_SealedBlobKeepsVersionHistory(t *testing.T) {
	f := newCertBackupFixture(t)
	cert := f.seedCertAtVersion3(t)

	blob, err := f.svc.BackupCertificate(context.Background(), cert.ID, f.userID, f.vaultID)
	require.NoError(t, err)
	inner, err := f.svc.ExportedOpenBlob(blob)
	require.NoError(t, err)

	var decoded model.Certificate
	versions, err := backup.ExportedDecodeBlob(inner, "certificate", &decoded)
	require.NoError(t, err)
	assert.Equal(t, 3, decoded.Version)
	require.Len(t, versions.Certificate, 2, "both archived versions must stay in the sealed blob")
}

// TestRestoreCertificate_RejectsLegacyUnsealedBlob is the B76 regression: a
// forged blob naming a key in another vault must be refused outright.
func TestRestoreCertificate_RejectsLegacyUnsealedBlob(t *testing.T) {
	t.Parallel()

	blob := legacyBlob(t, "certificate", &model.Certificate{
		ID: uuid.New(), Name: "forged", KeyID: uuid.New(), AutoRenew: true,
	})
	repo := newStubCertRepo()
	svc := newTestItemBackupService(nil, nil, repo, nil)

	err := svc.RestoreCertificate(context.Background(), blob, uuid.New(), uuid.New(), uuid.New())
	require.ErrorIs(t, err, backup.ErrInvalidBlob)
	require.ErrorIs(t, err, backup.ErrUnsealedBlob)
	assert.Empty(t, repo.certs, "a rejected blob must write nothing")
}

// TestRestoreKey_RejectsForgedHSMHandle pins the HSM half of B76: an HSM key
// blob stores a pkcs11 handle, so a forged blob could bind a new key row to
// any HSM object. Sealing makes that blob unrestorable.
func TestRestoreKey_RejectsForgedHSMHandle(t *testing.T) {
	t.Parallel()

	blob := legacyBlob(t, "key", &model.Key{
		ID: uuid.New(), Name: "hijack", Type: model.KeyTypeRSA,
		Value: "pkcs11:victim-vault-key", Enabled: true,
	})
	repo := newStubKeyRepo()
	svc := newTestItemBackupService(nil, repo, nil, nil)

	err := svc.RestoreKey(context.Background(), blob, uuid.New(), uuid.New(), uuid.New())
	require.ErrorIs(t, err, backup.ErrUnsealedBlob)
	assert.Empty(t, repo.keys, "a rejected blob must write nothing")
}

func TestRestore_RejectsTamperedBlob(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	owner, vaultID, secretID := uuid.New(), uuid.New(), uuid.New()
	repo := newStubSecretRepo()
	require.NoError(t, repo.Create(ctx, &model.Secret{
		ID: secretID, UserID: owner, VaultID: vaultID, Name: "s", Value: "v", Version: 1, Enabled: true,
	}))
	svc := newTestItemBackupService(repo, nil, nil, newStubSecretVersionRepo())

	blob, err := svc.BackupSecret(ctx, secretID, owner, vaultID)
	require.NoError(t, err)

	raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(blob, backup.ExportedSealedBlobPrefix))
	require.NoError(t, err)
	raw[len(raw)-1] ^= 0x01
	tampered := backup.ExportedSealedBlobPrefix + base64.StdEncoding.EncodeToString(raw)

	err = svc.RestoreSecret(ctx, tampered, owner, vaultID, uuid.New())
	require.ErrorIs(t, err, backup.ErrInvalidBlob)
	require.ErrorIs(t, err, backup.ErrBlobAuthentication)
}

// TestRestore_RejectsBlobSealedUnderAnotherMasterKey covers blobs taken
// before a master-key rotation. Their inner values are ciphertext under the
// old key anyway, so refusing them loses nothing that ever worked.
func TestRestore_RejectsBlobSealedUnderAnotherMasterKey(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	owner, vaultID, secretID := uuid.New(), uuid.New(), uuid.New()
	repo := newStubSecretRepo()
	require.NoError(t, repo.Create(ctx, &model.Secret{
		ID: secretID, UserID: owner, VaultID: vaultID, Name: "s", Value: "v", Version: 1, Enabled: true,
	}))
	svc := newTestItemBackupService(repo, nil, nil, newStubSecretVersionRepo())
	blob, err := svc.BackupSecret(ctx, secretID, owner, vaultID)
	require.NoError(t, err)

	other := backup.NewItemBackupService(repo, nil, nil, newStubSecretVersionRepo())
	require.NoError(t, other.SetSealKey(bytes.Repeat([]byte{0x43}, 32)))

	err = other.RestoreSecret(ctx, blob, owner, vaultID, uuid.New())
	require.ErrorIs(t, err, backup.ErrBlobAuthentication)
}

func TestItemBackup_FailsClosedWithoutSealKey(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	owner, vaultID, secretID := uuid.New(), uuid.New(), uuid.New()
	repo := newStubSecretRepo()
	require.NoError(t, repo.Create(ctx, &model.Secret{
		ID: secretID, UserID: owner, VaultID: vaultID, Name: "s", Value: "v", Version: 1, Enabled: true,
	}))
	svc := backup.NewItemBackupService(repo, nil, nil, newStubSecretVersionRepo())

	_, err := svc.BackupSecret(ctx, secretID, owner, vaultID)
	require.ErrorIs(t, err, backup.ErrSealKeyUnset)

	err = svc.RestoreSecret(ctx, "rvb2.anything", owner, vaultID, uuid.New())
	require.ErrorIs(t, err, backup.ErrSealKeyUnset)
}

func TestSetSealKey_RejectsWrongLength(t *testing.T) {
	t.Parallel()

	svc := backup.NewItemBackupService(nil, nil, nil, nil)
	require.Error(t, svc.SetSealKey(make([]byte, 16)))
}

// TestRestore_RejectsUnsealedBlobForEveryType extends the B76 regression to
// all three resource types. A hand-written blob in the old format is refused
// as unsealed, wraps ErrInvalidBlob for the 400 mapping, and writes nothing.
func TestRestore_RejectsUnsealedBlobForEveryType(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	secrets, keys, certs := newStubSecretRepo(), newStubKeyRepo(), newStubCertRepo()
	versions := newStubSecretVersionRepo()
	svc := newTestItemBackupService(secrets, keys, certs, versions)

	cases := map[string]func(blob string) error{
		"secret": func(blob string) error {
			return svc.RestoreSecret(ctx, blob, uuid.New(), uuid.New(), uuid.New())
		},
		"key": func(blob string) error {
			return svc.RestoreKey(ctx, blob, uuid.New(), uuid.New(), uuid.New())
		},
		"certificate": func(blob string) error {
			return svc.RestoreCertificate(ctx, blob, uuid.New(), uuid.New(), uuid.New())
		},
	}
	for resourceType, restore := range cases {
		blob := legacyBlob(t, resourceType, map[string]any{"name": "forged", "value": "v", "version": 1})
		err := restore(blob)
		require.ErrorIs(t, err, backup.ErrInvalidBlob, resourceType)
		require.ErrorIs(t, err, backup.ErrUnsealedBlob, resourceType)
	}
	assert.Empty(t, secrets.secrets, "a rejected secret blob must write nothing")
	assert.Empty(t, versions.versions, "a rejected secret blob must write no version")
	assert.Empty(t, keys.keys, "a rejected key blob must write nothing")
	assert.Empty(t, certs.certs, "a rejected certificate blob must write nothing")
}

// TestRestore_ForeignKeyBlobWritesNothing pins that a blob sealed under
// another master key is refused at the seal, for every resource type, and
// never reaches the repositories.
func TestRestore_ForeignKeyBlobWritesNothing(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	owner, vaultID := uuid.New(), uuid.New()

	srcSecrets, srcKeys, srcCerts := newStubSecretRepo(), newStubKeyRepo(), newStubCertRepo()
	secretID, keyID, certID := uuid.New(), uuid.New(), uuid.New()
	require.NoError(t, srcSecrets.Create(ctx, &model.Secret{ID: secretID, UserID: owner, VaultID: vaultID, Name: "s", Value: "v", Version: 1, Enabled: true}))
	require.NoError(t, srcKeys.Create(ctx, &model.Key{ID: keyID, UserID: owner, VaultID: vaultID, Name: "k", Type: model.KeyTypeRSA, Value: "enc", Enabled: true}))
	require.NoError(t, srcCerts.Create(ctx, &model.Certificate{ID: certID, UserID: owner, VaultID: vaultID, Name: "c"}))

	src := backup.NewItemBackupService(srcSecrets, srcKeys, srcCerts, newStubSecretVersionRepo())
	require.NoError(t, src.SetSealKey(bytes.Repeat([]byte{0x43}, 32)))
	secretBlob, err := src.BackupSecret(ctx, secretID, owner, vaultID)
	require.NoError(t, err)
	keyBlob, err := src.BackupKey(ctx, keyID, owner, vaultID)
	require.NoError(t, err)
	certBlob, err := src.BackupCertificate(ctx, certID, owner, vaultID)
	require.NoError(t, err)

	dstSecrets, dstKeys, dstCerts := newStubSecretRepo(), newStubKeyRepo(), newStubCertRepo()
	dst := newTestItemBackupService(dstSecrets, dstKeys, dstCerts, newStubSecretVersionRepo())

	err = dst.RestoreSecret(ctx, secretBlob, owner, vaultID, uuid.New())
	require.ErrorIs(t, err, backup.ErrInvalidBlob)
	require.ErrorIs(t, err, backup.ErrBlobAuthentication)
	err = dst.RestoreKey(ctx, keyBlob, owner, vaultID, uuid.New())
	require.ErrorIs(t, err, backup.ErrBlobAuthentication)
	err = dst.RestoreCertificate(ctx, certBlob, owner, vaultID, uuid.New())
	require.ErrorIs(t, err, backup.ErrBlobAuthentication)

	assert.Empty(t, dstSecrets.secrets)
	assert.Empty(t, dstKeys.keys)
	assert.Empty(t, dstCerts.certs)
}

// TestRestore_RejectsMalformedSealedBody covers blobs that carry the sealed
// prefix but whose body is not valid sealed data. Each is reported as an
// authentication failure, never as a decode error that echoes the input.
func TestRestore_RejectsMalformedSealedBody(t *testing.T) {
	t.Parallel()

	svc := newTestItemBackupService(newStubSecretRepo(), nil, nil, newStubSecretVersionRepo())
	bodies := map[string]string{
		"empty":         "",
		"not base64":    "!!!not-base64!!!",
		"too short":     base64.StdEncoding.EncodeToString([]byte("short")),
		"random bytes":  base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x7f}, 64)),
		"bare envelope": legacyBlob(t, "secret", map[string]any{"name": "forged"}),
	}
	for name, body := range bodies {
		err := svc.RestoreSecret(context.Background(), backup.ExportedSealedBlobPrefix+body, uuid.New(), uuid.New(), uuid.New())
		require.ErrorIs(t, err, backup.ErrInvalidBlob, name)
		require.ErrorIs(t, err, backup.ErrBlobAuthentication, name)
	}
}

// TestItemBackup_FailsClosedWithoutSealKey_AllTypes pins that an unwired
// service refuses every backup and every restore, rather than producing or
// accepting the unauthenticated format.
func TestItemBackup_FailsClosedWithoutSealKey_AllTypes(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	owner, vaultID := uuid.New(), uuid.New()
	secrets, keys, certs := newStubSecretRepo(), newStubKeyRepo(), newStubCertRepo()
	secretID, keyID, certID := uuid.New(), uuid.New(), uuid.New()
	require.NoError(t, secrets.Create(ctx, &model.Secret{ID: secretID, UserID: owner, VaultID: vaultID, Name: "s", Value: "v", Version: 1, Enabled: true}))
	require.NoError(t, keys.Create(ctx, &model.Key{ID: keyID, UserID: owner, VaultID: vaultID, Name: "k", Type: model.KeyTypeRSA, Value: "enc", Enabled: true}))
	require.NoError(t, certs.Create(ctx, &model.Certificate{ID: certID, UserID: owner, VaultID: vaultID, Name: "c"}))

	sealed := newTestItemBackupService(secrets, keys, certs, newStubSecretVersionRepo())
	secretBlob, err := sealed.BackupSecret(ctx, secretID, owner, vaultID)
	require.NoError(t, err)
	keyBlob, err := sealed.BackupKey(ctx, keyID, owner, vaultID)
	require.NoError(t, err)
	certBlob, err := sealed.BackupCertificate(ctx, certID, owner, vaultID)
	require.NoError(t, err)

	unwired := backup.NewItemBackupService(secrets, keys, certs, newStubSecretVersionRepo())
	_, err = unwired.BackupKey(ctx, keyID, owner, vaultID)
	require.ErrorIs(t, err, backup.ErrSealKeyUnset)
	_, err = unwired.BackupCertificate(ctx, certID, owner, vaultID)
	require.ErrorIs(t, err, backup.ErrSealKeyUnset)

	// Even a genuine sealed blob, and a legacy blob, are refused.
	require.ErrorIs(t, unwired.RestoreSecret(ctx, secretBlob, owner, vaultID, uuid.New()), backup.ErrSealKeyUnset)
	require.ErrorIs(t, unwired.RestoreKey(ctx, keyBlob, owner, vaultID, uuid.New()), backup.ErrSealKeyUnset)
	require.ErrorIs(t, unwired.RestoreCertificate(ctx, certBlob, owner, vaultID, uuid.New()), backup.ErrSealKeyUnset)
	legacy := legacyBlob(t, "key", &model.Key{Name: "k", Type: model.KeyTypeRSA, Value: "pkcs11:x", Enabled: true})
	require.ErrorIs(t, unwired.RestoreKey(ctx, legacy, owner, vaultID, uuid.New()), backup.ErrSealKeyUnset)

	assert.Len(t, secrets.secrets, 1, "an unwired restore must write nothing")
	assert.Len(t, keys.keys, 1, "an unwired restore must write nothing")
	assert.Len(t, certs.certs, 1, "an unwired restore must write nothing")
}

// TestRestore_ErrorTextLeaksNothing pins that a refused blob's error never
// echoes the blob, its decoded contents, or key material.
func TestRestore_ErrorTextLeaksNothing(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	owner, vaultID, secretID := uuid.New(), uuid.New(), uuid.New()
	repo := newStubSecretRepo()
	require.NoError(t, repo.Create(ctx, &model.Secret{
		ID: secretID, UserID: owner, VaultID: vaultID, Name: "canary-name", Value: "canary-value", Version: 1, Enabled: true,
	}))
	svc := newTestItemBackupService(repo, nil, nil, newStubSecretVersionRepo())
	blob, err := svc.BackupSecret(ctx, secretID, owner, vaultID)
	require.NoError(t, err)

	other := backup.NewItemBackupService(repo, nil, nil, newStubSecretVersionRepo())
	otherKey := bytes.Repeat([]byte{0x43}, 32)
	require.NoError(t, other.SetSealKey(otherKey))

	legacy := legacyBlob(t, "secret", map[string]any{"name": "canary-legacy"})
	refusals := map[string]error{
		"foreign key": other.RestoreSecret(ctx, blob, owner, vaultID, uuid.New()),
		"legacy":      svc.RestoreSecret(ctx, legacy, owner, vaultID, uuid.New()),
		"bad body":    svc.RestoreSecret(ctx, backup.ExportedSealedBlobPrefix+"!!canary-body!!", owner, vaultID, uuid.New()),
	}
	forbidden := []string{
		strings.TrimPrefix(blob, backup.ExportedSealedBlobPrefix),
		legacy,
		"canary",
		base64.StdEncoding.EncodeToString(testMasterKey),
		base64.StdEncoding.EncodeToString(otherKey),
		string(testMasterKey),
	}
	for name, refusal := range refusals {
		require.Error(t, refusal, name)
		for _, f := range forbidden {
			assert.NotContains(t, refusal.Error(), f, name)
		}
	}
}

// TestSealBlob_FreshNoncePerSeal pins that sealing the same envelope twice
// gives two different blobs, so equal items are not linkable by their blob.
func TestSealBlob_FreshNoncePerSeal(t *testing.T) {
	t.Parallel()

	svc := newTestItemBackupService(nil, nil, nil, nil)
	a := sealForTest(t, svc, "same inner envelope")
	b := sealForTest(t, svc, "same inner envelope")
	assert.NotEqual(t, a, b)

	inner, err := svc.ExportedOpenBlob(a)
	require.NoError(t, err)
	assert.Equal(t, "same inner envelope", inner)
}

// TestSealKey_IsDerivedNotRaw pins that the seal key is not the master key
// itself: a blob sealed directly under the raw master key must not open.
func TestSealKey_IsDerivedNotRaw(t *testing.T) {
	t.Parallel()

	svc := newTestItemBackupService(nil, nil, nil, nil)
	rawSealed, err := common.EncryptWithKey("inner", testMasterKey)
	require.NoError(t, err)

	_, err = svc.ExportedOpenBlob(backup.ExportedSealedBlobPrefix + rawSealed)
	require.ErrorIs(t, err, backup.ErrBlobAuthentication)
}

// TestRestore_SealedButUndecodableInnerIsInvalid keeps the envelope decode
// checks covered now that unsealed input stops at the seal. A correctly
// sealed body that is not a valid envelope is still refused as invalid, by
// the decoder rather than by the seal, and writes nothing.
func TestRestore_SealedButUndecodableInnerIsInvalid(t *testing.T) {
	t.Parallel()

	repo := newStubSecretRepo()
	svc := newTestItemBackupService(repo, nil, nil, newStubSecretVersionRepo())
	inners := map[string]string{
		"not base64": "!!!not-base64!!!",
		"not json":   base64.URLEncoding.EncodeToString([]byte("this is not an envelope")),
	}
	for name, inner := range inners {
		err := svc.RestoreSecret(context.Background(), sealForTest(t, svc, inner), uuid.New(), uuid.New(), uuid.New())
		require.ErrorIs(t, err, backup.ErrInvalidBlob, name)
		require.NotErrorIs(t, err, backup.ErrUnsealedBlob, name)
		require.NotErrorIs(t, err, backup.ErrBlobAuthentication, name)
	}
	assert.Empty(t, repo.secrets)
}
