package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	secretServices "rocketvault/internal/services/secrets"
	"rocketvault/model"
)

// TestImportSecrets_ReportsPerItemFailures verifies that per-item failures
// reach the HTTP response body.
func TestImportSecrets_ReportsPerItemFailures(t *testing.T) {
	svc := &mockSecretService{}
	svc.On("ImportSecrets", mock.Anything, mock.Anything).
		Return(&secretServices.ImportResult{
			ImportedCount: 1,
			TotalCount:    3,
			FailedCount:   2,
			SkippedCount:  0,
			Errors:        []string{"Invalid 'a': bad", "Invalid 'b': bad"},
		}, nil)

	c := newSecretCtx(svc)
	w := httptest.NewRecorder()
	r := buildMultipartRequest(t, `[{"name":"a","value":"v"}]`, map[string]string{"format": "json"})

	importSecrets(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusOK, w.Code)
	var resp model.ImportResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.False(t, resp.Success)
	assert.Equal(t, 2, resp.FailedCount)
	assert.Equal(t, []string{"Invalid 'a': bad", "Invalid 'b': bad"}, resp.Errors)
	assert.Contains(t, resp.Message, "2 failed")
}

// TestImportSecrets_CleanRunStaysSuccessful verifies the clean-run shape.
func TestImportSecrets_CleanRunStaysSuccessful(t *testing.T) {
	svc := &mockSecretService{}
	svc.On("ImportSecrets", mock.Anything, mock.Anything).
		Return(&secretServices.ImportResult{ImportedCount: 2, TotalCount: 2}, nil)

	c := newSecretCtx(svc)
	w := httptest.NewRecorder()
	r := buildMultipartRequest(t, `[]`, map[string]string{"format": "json"})

	importSecrets(c, w, r)

	var resp model.ImportResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.True(t, resp.Success)
	assert.Equal(t, "Successfully imported 2/2 secrets", resp.Message)
	assert.NotContains(t, w.Body.String(), `"errors"`)
}

// TestImportSecrets_MalformedFileIs400 verifies that a file the real service
// cannot parse is reported as a client error, not an opaque 500. The real
// service is used because the parse step runs before any repository call.
func TestImportSecrets_MalformedFileIs400(t *testing.T) {
	cases := []struct {
		name    string
		format  string
		content string
	}{
		{name: "json", format: "json", content: `not json at all`},
		{name: "csv header", format: "csv", content: "name,va\"lue\nx,y\n"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			svc := secretServices.NewSecretService(secretServices.SecretServiceConfig{Logger: userTestLog()})
			c := newSecretCtx(svc)
			w := httptest.NewRecorder()
			r := buildMultipartRequest(t, tc.content, map[string]string{"format": tc.format})

			importSecrets(c, w, r)
			require.NotNil(t, c.Err)
			writeError(w, c)

			assert.Equal(t, http.StatusBadRequest, w.Code)
			assert.Contains(t, w.Body.String(), "could not be parsed")
		})
	}
}
