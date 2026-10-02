package api

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"

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
