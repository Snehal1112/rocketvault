package api

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"

	"rocketvault/internal/backup"
	"rocketvault/internal/repositories"
	"rocketvault/model"
)

// apiTestSealKey is a fixed 32-byte master key used only by tests.
var apiTestSealKey = bytes.Repeat([]byte{0x42}, 32)

// newSealedItemBackupService builds an ItemBackupService with its seal key
// set, as the real container does.
func newSealedItemBackupService(
	secretRepo repositories.SecretRepositoryInterface,
	keyRepo repositories.KeyRepositoryInterface,
	certRepo repositories.CertificateRepositoryInterface,
	versionRepo repositories.SecretVersionRepositoryInterface,
) *backup.ItemBackupService {
	svc := backup.NewItemBackupService(secretRepo, keyRepo, certRepo, versionRepo)
	if err := svc.SetSealKey(apiTestSealKey); err != nil {
		panic(err)
	}
	return svc
}

// TestRestoreCertificateHandler_LegacyUnsealedBlob_Returns400 pins B76 on the
// HTTP path. A hand-written blob in the old base64url format names a key in
// another vault; it must be refused as a bad parameter and write nothing.
func TestRestoreCertificateHandler_LegacyUnsealedBlob_Returns400(t *testing.T) {
	raw, err := json.Marshal(map[string]any{
		"resource_type": "certificate",
		"resource_id":   uuid.New().String(),
		"data":          map[string]any{"name": "forged", "key_id": uuid.New().String(), "auto_renew": true},
	})
	if err != nil {
		t.Fatal(err)
	}
	legacy := base64.URLEncoding.EncodeToString(raw)

	created := false
	certRepo := &mockCertRepo{
		createFn: func(_ context.Context, _ *model.Certificate) error {
			created = true
			return nil
		},
	}
	c := newBackupCtxWithCert(certRepo)
	w := httptest.NewRecorder()
	body, _ := json.Marshal(map[string]string{"blob": legacy})
	r := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/certificates/restore", bytes.NewReader(body))

	restoreCertificateHandler(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.False(t, created, "a rejected blob must not reach the repository")
}

// TestRestoreKeyHandler_ForgedHSMHandle_Returns400 pins the HSM half of B76
// on the HTTP path. A hand-written key blob carrying a pkcs11 handle is
// refused as a bad parameter and never reaches the repository.
func TestRestoreKeyHandler_ForgedHSMHandle_Returns400(t *testing.T) {
	raw, err := json.Marshal(map[string]any{
		"resource_type": "key",
		"resource_id":   uuid.New().String(),
		"data":          map[string]any{"name": "hijack", "type": "RSA", "value": "pkcs11:victim-vault-key", "enabled": true},
	})
	if err != nil {
		t.Fatal(err)
	}
	legacy := base64.URLEncoding.EncodeToString(raw)

	created := false
	keyRepo := &mockKeyRepo{
		createFn: func(_ context.Context, _ *model.Key) error {
			created = true
			return nil
		},
	}
	c := newBackupCtxWithKey(keyRepo)
	w := httptest.NewRecorder()
	body, _ := json.Marshal(map[string]string{"blob": legacy})
	r := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/keys/restore", bytes.NewReader(body))

	restoreKeyHandler(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.False(t, created, "a rejected blob must not reach the repository")
	assert.NotContains(t, w.Body.String(), "pkcs11", "the response must not echo the blob")
}

// TestRestoreCertificateHandler_ForeignMasterKey_Returns400 pins that a blob
// sealed by a server with another master key is refused as a bad parameter,
// writes nothing, and is not echoed back.
func TestRestoreCertificateHandler_ForeignMasterKey_Returns400(t *testing.T) {
	userID := uuid.MustParse(secretHTestUserID)
	srcRepo := &mockCertRepo{
		readFn: func(_ context.Context, id uuid.UUID) (*model.Certificate, error) {
			return &model.Certificate{ID: id, Name: "foreign-cert", UserID: userID}, nil
		},
	}
	src := backup.NewItemBackupService(nil, nil, srcRepo, nil)
	if err := src.SetSealKey(bytes.Repeat([]byte{0x43}, 32)); err != nil {
		t.Fatal(err)
	}
	blob, err := src.BackupCertificate(context.Background(), uuid.New(), userID, uuid.Nil)
	if err != nil {
		t.Fatal(err)
	}

	created := false
	certRepo := &mockCertRepo{
		createFn: func(_ context.Context, _ *model.Certificate) error {
			created = true
			return nil
		},
	}
	c := newBackupCtxWithCert(certRepo)
	w := httptest.NewRecorder()
	body, _ := json.Marshal(map[string]string{"blob": blob})
	r := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/certificates/restore", bytes.NewReader(body))

	restoreCertificateHandler(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.False(t, created, "a rejected blob must not reach the repository")
	assert.NotContains(t, w.Body.String(), strings.TrimPrefix(blob, "rvb2."),
		"the response must not echo the blob")
}
