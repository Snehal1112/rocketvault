package vaultapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"rocketvault/common"
)

func loginServer(t *testing.T, respond func(w http.ResponseWriter, body map[string]string)) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, http.MethodPost, r.Method)
		require.Equal(t, "/api/v1/users/login", r.URL.Path)
		var body map[string]string
		require.NoError(t, json.NewDecoder(r.Body).Decode(&body))
		respond(w, body)
	}))
}

func newTestClient(t *testing.T, baseURL string, httpClient *http.Client) *Client {
	t.Helper()
	c, err := New(Config{
		BaseURL: baseURL, HTTPClient: httpClient,
		Tokens: stubTokenSource{token: "unused"}, DisableRetry: true,
	})
	require.NoError(t, err)
	return c
}

func TestClientLogin_Success(t *testing.T) {
	srv := loginServer(t, func(w http.ResponseWriter, body map[string]string) {
		require.Equal(t, "admin", body["username"])
		require.Equal(t, "hunter2", body["password"])
		require.Equal(t, "123456", body["totp_code"])
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"token":"access-1","refresh_token":"refresh-1","user_id":"11111111-1111-1111-1111-111111111111","username":"admin","roles":["admin"]}`))
	})
	defer srv.Close()

	c := newTestClient(t, srv.URL, srv.Client())
	source, identity, err := c.Login(context.Background(), "admin", "hunter2", "123456", LoginOptions{Expiry: time.Hour})
	require.NoError(t, err)
	require.Equal(t, "admin", identity.Username)
	require.Equal(t, []string{"admin"}, identity.Roles)
	require.WithinDuration(t, time.Now().Add(time.Hour), identity.ExpiresAt, time.Second)

	tok, err := source.Token(context.Background())
	require.NoError(t, err)
	require.Equal(t, "access-1", tok)
}

func TestClientLogin_RejectionDoesNotEchoBody(t *testing.T) {
	srv := loginServer(t, func(w http.ResponseWriter, _ map[string]string) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"message":"authentication failed"}`))
	})
	defer srv.Close()

	c := newTestClient(t, srv.URL, srv.Client())
	_, _, err := c.Login(context.Background(), "admin", "wrong", "000000", LoginOptions{Expiry: time.Hour})
	require.Error(t, err)
	require.NotContains(t, err.Error(), "authentication failed")
	require.Contains(t, err.Error(), "401")
}

// A throttled login reports HTTP 429, so the remote CLI shows throttling
// rather than a generic failure.
func TestClientLogin_ThrottledReportsHTTP429(t *testing.T) {
	srv := loginServer(t, func(w http.ResponseWriter, _ map[string]string) {
		w.Header().Set("Retry-After", "37")
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = w.Write([]byte(`{"message":"Too many failed login attempts"}`))
	})
	defer srv.Close()

	c := newTestClient(t, srv.URL, srv.Client())
	_, _, err := c.Login(context.Background(), "admin", "wrong", "000000", LoginOptions{Expiry: time.Hour})
	require.Error(t, err)
	require.Contains(t, err.Error(), "HTTP 429")
}

func TestClientLogin_MissingTokenInResponseIsAnError(t *testing.T) {
	srv := loginServer(t, func(w http.ResponseWriter, _ map[string]string) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"username":"admin","roles":["admin"]}`))
	})
	defer srv.Close()

	c := newTestClient(t, srv.URL, srv.Client())
	_, _, err := c.Login(context.Background(), "admin", "hunter2", "123456", LoginOptions{Expiry: time.Hour})
	require.ErrorContains(t, err, "missing a token")
}

func TestClientLogin_SendsNoAuthorizationHeader(t *testing.T) {
	var gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"token":"access-1","refresh_token":"refresh-1","user_id":"11111111-1111-1111-1111-111111111111","username":"admin","roles":["admin"]}`))
	}))
	defer srv.Close()

	c := newTestClient(t, srv.URL, srv.Client())
	_, _, err := c.Login(context.Background(), "admin", "hunter2", "123456", LoginOptions{Expiry: time.Hour})
	require.NoError(t, err)
	require.Empty(t, gotAuth, "login is unauthenticated -- it must not send whatever c.tokens holds")
}

func TestLogin_PersistsSessionWhenSaveSessionSupplied(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/api/v1/users/login", r.URL.Path)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"token": "tok", "refresh_token": "refresh",
			"user_id":  "0f2b6f1e-0000-0000-0000-000000000001",
			"username": "admin", "roles": []string{"admin"},
		})
	}))
	defer srv.Close()

	client := newTestClient(t, srv.URL, srv.Client())

	var saved *common.SessionCache
	_, identity, err := client.Login(context.Background(), "admin", "pw", "123456", LoginOptions{
		Expiry:      time.Hour,
		SaveSession: func(s *common.SessionCache) error { saved = s; return nil },
	})
	require.NoError(t, err)
	assert.Equal(t, "admin", identity.Username)

	require.NotNil(t, saved, "Login must persist through the supplied hook")
	assert.Equal(t, "tok", saved.Token)
	assert.Equal(t, "refresh", saved.RefreshToken)
	assert.Equal(t, common.SanitizeServerKey(srv.URL), saved.ServerKey)
}

// TestLogin_NilSaveSessionWritesNothing pins the MCP server's contract: an
// in-chat login is memory-only and must never touch ~/.rocketvault/sessions.
func TestLogin_NilSaveSessionWritesNothing(t *testing.T) {
	baseDir := t.TempDir()
	originalBaseDir := common.SessionBaseDir
	common.SessionBaseDir = baseDir
	t.Cleanup(func() { common.SessionBaseDir = originalBaseDir })

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"token": "tok", "refresh_token": "refresh",
			"user_id":  "0f2b6f1e-0000-0000-0000-000000000001",
			"username": "admin", "roles": []string{"admin"},
		})
	}))
	defer srv.Close()

	client := newTestClient(t, srv.URL, srv.Client())

	_, _, err := client.Login(context.Background(), "admin", "pw", "123456", LoginOptions{Expiry: time.Hour})
	require.NoError(t, err)

	entries, err := os.ReadDir(baseDir)
	require.NoError(t, err)
	assert.Empty(t, entries, "a login with no SaveSession hook must write nothing to disk")
}
