package vaultapi

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
)

// doAgainstStatus runs one request against a server that always replies with
// status and body, and returns the resulting error.
func doAgainstStatus(t *testing.T, status int, body, method, path string) error {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	defer srv.Close()

	c, err := New(Config{BaseURL: srv.URL, HTTPClient: srv.Client(), Tokens: staticToken("t")})
	require.NoError(t, err)
	return c.Do(context.Background(), method, path, nil, nil)
}

func TestAPIError_MapsStatusToKind(t *testing.T) {
	cases := []struct {
		status int
		want   ErrorKind
	}{
		{http.StatusUnauthorized, KindUnauthorized},
		{http.StatusForbidden, KindForbidden},
		{http.StatusNotFound, KindNotFound},
		{http.StatusConflict, KindConflict},
		{http.StatusInternalServerError, KindServer},
		{http.StatusBadGateway, KindServer},
		{http.StatusTeapot, KindUnknown},
	}
	for _, tc := range cases {
		err := doAgainstStatus(t, tc.status, `{}`, http.MethodGet, "/api/v1/vaults")
		var apiErr *APIError
		require.ErrorAs(t, err, &apiErr)
		require.Equal(t, tc.want, apiErr.Kind, "status %d", tc.status)
		require.Equal(t, tc.status, apiErr.StatusCode)
	}
}

func TestAPIError_NeverLeaksResponseBody(t *testing.T) {
	leaky := `{"message":"denied while writing value s3cr3t-p4ssw0rd"}`
	err := doAgainstStatus(t, http.StatusForbidden, leaky, http.MethodPut,
		"/api/v1/vaults/prod/secrets/1f0c8a3e-0000-0000-0000-000000000000")

	require.NotContains(t, err.Error(), "s3cr3t-p4ssw0rd")
	require.NotContains(t, err.Error(), "denied while writing")
}

func TestAPIError_ForbiddenCarriesActionableRoleHint(t *testing.T) {
	err := doAgainstStatus(t, http.StatusForbidden, `{}`, http.MethodGet, "/api/v1/vaults/prod/secrets")

	var apiErr *APIError
	require.ErrorAs(t, err, &apiErr)
	require.Contains(t, apiErr.Hint, "secrets/read")
	require.Contains(t, apiErr.Hint, "Key Vault Secrets User")
	require.Contains(t, apiErr.Error(), "prod")
}

func TestAPIError_HintDistinguishesReadFromWrite(t *testing.T) {
	readErr := doAgainstStatus(t, http.StatusForbidden, `{}`, http.MethodGet, "/api/v1/vaults/prod/keys")
	writeErr := doAgainstStatus(t, http.StatusForbidden, `{}`, http.MethodPost, "/api/v1/vaults/prod/keys")

	var readAPI, writeAPI *APIError
	require.ErrorAs(t, readErr, &readAPI)
	require.ErrorAs(t, writeErr, &writeAPI)
	require.Contains(t, readAPI.Hint, "keys/read")
	require.Contains(t, writeAPI.Hint, "keys/create")
	require.NotEqual(t, readAPI.Hint, writeAPI.Hint)
}

func TestAPIError_UnauthorizedTellsOperatorToLogIn(t *testing.T) {
	err := doAgainstStatus(t, http.StatusUnauthorized, `{}`, http.MethodGet, "/api/v1/vaults")
	require.Contains(t, err.Error(), "rocketvault users login")
}

func TestAPIError_ServerKindIsRetryable(t *testing.T) {
	err := doAgainstStatus(t, http.StatusServiceUnavailable, `{}`, http.MethodGet, "/api/v1/vaults")
	var apiErr *APIError
	require.ErrorAs(t, err, &apiErr)
	require.True(t, apiErr.Retryable())

	err = doAgainstStatus(t, http.StatusNotFound, `{}`, http.MethodGet, "/api/v1/vaults")
	require.ErrorAs(t, err, &apiErr)
	require.False(t, apiErr.Retryable())
}

func TestAPIError_IsDiscoverableWithErrorsAs(t *testing.T) {
	err := doAgainstStatus(t, http.StatusNotFound, `{}`, http.MethodGet, "/api/v1/vaults/prod/keys")
	var apiErr *APIError
	require.True(t, errors.As(err, &apiErr))
}

// TestAPIError_CertificateIssueHintNamesKeySign pins that a 403 on issuing or
// renewing a certificate points at the second action it needs (B77).
func TestAPIError_CertificateIssueHintNamesKeySign(t *testing.T) {
	for _, path := range []string{"/api/v1/vaults/prod/certificates", "/api/v1/vaults/prod/certificates/tls/renew"} {
		err := doAgainstStatus(t, http.StatusForbidden, `{}`, http.MethodPost, path)
		var apiErr *APIError
		require.ErrorAs(t, err, &apiErr)
		require.Contains(t, apiErr.Hint, "Key Vault Certificates Officer")
		require.Contains(t, apiErr.Hint, "keys/sign/action")
	}

	err := doAgainstStatus(t, http.StatusForbidden, `{}`, http.MethodGet, "/api/v1/vaults/prod/certificates")
	var readAPI *APIError
	require.ErrorAs(t, err, &readAPI)
	require.NotContains(t, readAPI.Hint, "keys/sign")
}
