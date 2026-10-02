package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"rocketvault/internal/services/secrets"
)

// putSecret sets the SecretID route param itself: newSecretCtx leaves it empty,
// and resourceID answers 400 for an empty id before updateSecret does anything.
func putSecret(t *testing.T, c *Context, id uuid.UUID, body map[string]any) *httptest.ResponseRecorder {
	t.Helper()
	c.Params = &ApiParams{SecretID: id.String(), PerPage: 60}
	b, err := json.Marshal(body)
	require.NoError(t, err)
	w := httptest.NewRecorder()
	r := httptest.NewRequestWithContext(t.Context(), http.MethodPut, "/secrets/"+id.String(), bytes.NewReader(b))
	updateSecret(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}
	return w
}

// Enabling a disabled secret must work: the old pre-read returned 403.
func TestUpdateSecret_EnableDisabledSecret_Returns200(t *testing.T) {
	id := uuid.New()
	svc := &mockSecretService{}
	enabled := makeSecretModel(id)
	svc.On("UpdateSecret", mock.Anything, mock.MatchedBy(func(r secrets.UpdateSecretRequest) bool {
		return r.Enabled != nil && *r.Enabled && r.Value == nil && r.Name == nil
	})).Return(nil).Once()
	svc.On("GetSecret", mock.Anything, id, mock.Anything).Return(enabled, nil).Once()

	w := putSecret(t, newSecretCtx(svc), id, map[string]any{"enabled": true})
	assert.Equal(t, http.StatusOK, w.Code)
	svc.AssertExpectations(t)
}

// A PUT whose value equals the stored value must not be told apart from any
// other PUT: it is accepted, never a 400 "no changes provided".
func TestUpdateSecret_IdenticalValue_Returns200NotEqualityOracle(t *testing.T) {
	id := uuid.New()
	svc := &mockSecretService{}
	same := makeSecretModel(id)
	svc.On("UpdateSecret", mock.Anything, mock.Anything).Return(nil).Once()
	svc.On("GetSecret", mock.Anything, id, mock.Anything).Return(same, nil).Once()

	w := putSecret(t, newSecretCtx(svc), id, map[string]any{"value": same.Value})
	assert.Equal(t, http.StatusOK, w.Code)
}

// Disabling a secret makes the read-back legitimately refuse it; the update
// itself succeeded, so the handler still answers 200 with a minimal body.
func TestUpdateSecret_DisableSecret_Returns200WithMinimalBody(t *testing.T) {
	id := uuid.New()
	svc := &mockSecretService{}
	svc.On("UpdateSecret", mock.Anything, mock.Anything).Return(nil).Once()
	svc.On("GetSecret", mock.Anything, id, mock.Anything).Return(nil, secrets.ErrSecretLifecycleDenied).Once()

	w := putSecret(t, newSecretCtx(svc), id, map[string]any{"enabled": false})
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), id.String())
	assert.Contains(t, w.Body.String(), `"enabled":false`)
}

func TestUpdateSecret_DuplicateName_Returns409(t *testing.T) {
	id := uuid.New()
	svc := &mockSecretService{}
	svc.On("UpdateSecret", mock.Anything, mock.Anything).Return(nameTakenChain()).Once()

	w := putSecret(t, newSecretCtx(svc), id, map[string]any{"name": "taken-name"})
	assert.Equal(t, http.StatusConflict, w.Code)
	assert.NotContains(t, w.Body.String(), "UNIQUE constraint")
}
