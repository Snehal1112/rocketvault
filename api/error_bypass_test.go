package api

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// runRotateWithFailingProvider drives rotateJWKS with a provider whose Rotate fails.
func runRotateWithFailingProvider(t *testing.T, rotateErr string) *httptest.ResponseRecorder {
	t.Helper()
	provider := &rotatableStubProvider{rotateErr: errors.New(rotateErr)}
	c := newJWKSAdminCtx(provider)
	w := httptest.NewRecorder()
	r := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/api/v1/jwks/rotate", nil)

	rotateJWKS(c, w, r)
	require.NotNil(t, c.Err)
	writeError(w, c)
	return w
}

// runOIDCCallbackWithHandleCallbackError drives the callback with a failing issuer exchange.
func runOIDCCallbackWithHandleCallbackError(t *testing.T, cbErr string) *httptest.ResponseRecorder {
	t.Helper()
	oidcSvc := &mockOIDCService{}
	oidcSvc.On("HandleCallback", mock.Anything, "x", "nonce-1").Return(nil, errors.New(cbErr))
	api := newOIDCHAPI(oidcSvc, nil, nil)
	w := httptest.NewRecorder()
	r := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/oidc/callback?state=expected&code=x", nil)
	r.AddCookie(&http.Cookie{Name: "oidc_state", Value: "expected"})
	r.AddCookie(&http.Cookie{Name: "oidc_nonce", Value: "nonce-1"})

	api.oidcCallbackHandler(w, r)
	return w
}

func TestRotateJWKS_Failure_DoesNotLeakProviderError(t *testing.T) {
	w := runRotateWithFailingProvider(t, "PKCS#11 slot 3: CKR_DEVICE_ERROR")
	assert.Equal(t, http.StatusInternalServerError, w.Code)
	assert.NotContains(t, w.Body.String(), "CKR_DEVICE_ERROR")
	assert.Contains(t, w.Body.String(), "An internal error occurred.")
}

func TestOIDCCallback_Failure_DoesNotLeakIssuerError(t *testing.T) {
	w := runOIDCCallbackWithHandleCallbackError(t, "oidc: id token signature invalid: key abc")
	assert.Equal(t, http.StatusUnauthorized, w.Code)
	assert.NotContains(t, w.Body.String(), "signature invalid")
	assert.Contains(t, w.Body.String(), "authentication failed")
}
