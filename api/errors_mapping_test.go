package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	"github.com/google/uuid"

	"rocketvault/internal/repositories"
	"rocketvault/internal/services/secrets"
)

// nameTakenChain mimics what the repositories return: the sentinel wrapped
// next to the raw driver text.
func nameTakenChain() error {
	return fmt.Errorf("failed to create: %w: UNIQUE constraint failed: secrets.vault_id, secrets.name",
		repositories.ErrNameTaken)
}

func errorBody(c *Context) (int, string) {
	w := httptest.NewRecorder()
	writeError(w, c)
	return w.Code, w.Body.String()
}

func TestWriteErrors_NameTaken_Returns409WithoutDriverText(t *testing.T) {
	mappers := map[string]func(*Context, error){
		"secret":      writeSecretError,
		"key":         writeKeyError,
		"certificate": writeCertificateError,
	}
	for name, mapper := range mappers {
		t.Run(name, func(t *testing.T) {
			c := &Context{RequestID: "req-test"}
			mapper(c, nameTakenChain())
			code, body := errorBody(c)
			assert.Equal(t, http.StatusConflict, code)
			assert.NotContains(t, body, "UNIQUE constraint")
			assert.Contains(t, body, "already exists")
		})
	}
}

func TestWriteSecretError_InvalidContentType_Returns400(t *testing.T) {
	c := &Context{RequestID: "req-test"}
	writeSecretError(c, fmt.Errorf("%w: %q", secrets.ErrInvalidContentType, "x/y"))
	code, _ := errorBody(c)
	assert.Equal(t, http.StatusBadRequest, code)
}

// postJSON builds a POST request carrying body as JSON.
func postJSON(t *testing.T, path string, body map[string]any) *http.Request {
	t.Helper()
	b, err := json.Marshal(body)
	assert.NoError(t, err)
	return httptest.NewRequestWithContext(context.Background(), http.MethodPost, path, bytes.NewReader(b))
}

// assertConflictBody checks a handler answered 409 with no driver text.
func assertConflictBody(t *testing.T, c *Context, w *httptest.ResponseRecorder) {
	t.Helper()
	if c.Err != nil {
		writeError(w, c)
	}
	assert.Equal(t, http.StatusConflict, w.Code)
	assert.NotContains(t, w.Body.String(), "UNIQUE constraint")
}

func TestCreateSecret_NameTaken_Returns409(t *testing.T) {
	svc := &mockSecretService{}
	svc.On("CreateSecret", mock.Anything, mock.Anything).Return(nil, nameTakenChain())
	c := newSecretCtx(svc)
	w := httptest.NewRecorder()
	createSecret(c, w, postJSON(t, "/secrets", map[string]any{"name": "dup", "value": "v"}))
	assertConflictBody(t, c, w)
}

func TestCreateSecret_InvalidContentType_Returns400(t *testing.T) {
	svc := &mockSecretService{}
	svc.On("CreateSecret", mock.Anything, mock.Anything).
		Return(nil, fmt.Errorf("%w: %q", secrets.ErrInvalidContentType, "x/y"))
	c := newSecretCtx(svc)
	w := httptest.NewRecorder()
	createSecret(c, w, postJSON(t, "/secrets", map[string]any{"name": "dup", "value": "v"}))
	if c.Err != nil {
		writeError(w, c)
	}
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestGenerateSecret_NameTaken_Returns409(t *testing.T) {
	svc := &mockSecretService{}
	svc.On("GenerateSecret", mock.Anything, mock.Anything).Return(nil, nameTakenChain())
	c := newSecretCtx(svc)
	w := httptest.NewRecorder()
	generateSecret(c, w, postJSON(t, "/secrets/generate", map[string]any{"name": "dup", "length": 16}))
	assertConflictBody(t, c, w)
}

func TestCreateCertificate_NameTaken_Returns409(t *testing.T) {
	svc := &mockCertService{}
	svc.On("CreateSelfSignedCertificate", mock.Anything, mock.Anything).Return(nil, nameTakenChain())
	c := newCertCtx(svc, certAdminClaims())
	w := httptest.NewRecorder()
	createCertificate(c, w, postJSON(t, "/certificates", map[string]any{
		"name": "dup", "key_id": uuid.New().String(), "validity_days": 365,
	}))
	assertConflictBody(t, c, w)
}

func TestCreateKey_NameTaken_Returns409(t *testing.T) {
	svc := &mockKeyService{}
	svc.On("CreateRSAKey", mock.Anything, mock.Anything).Return(nil, nameTakenChain())
	c := newKeyCtx(svc)
	w := httptest.NewRecorder()
	createKey(c, w, postJSON(t, "/keys", map[string]any{"name": "dup", "type": "RSA", "bits": 2048}))
	assertConflictBody(t, c, w)
}
