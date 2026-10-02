package api

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"rocketvault/app"
	rvconfig "rocketvault/config"
	"rocketvault/internal/container"
	rvdb "rocketvault/internal/db"
	"rocketvault/internal/logging"
	authServices "rocketvault/internal/services/auth"
	"rocketvault/internal/signing"
	"rocketvault/model"
)

// replayRouter is the real router over a real service container and a real
// file-backed SQLite database, with one enrolled user.
type replayRouter struct {
	handler  http.Handler
	username string
	password string
	secret   string
}

// newReplayRouter builds the production router and container. The signing key
// lives in a fake keychain and a temporary home, so the test never touches
// the developer's real key material.
func newReplayRouter(t *testing.T) *replayRouter {
	t.Helper()
	t.Setenv("HOME", t.TempDir())
	restore := signing.UseFakeKeychainForTesting()
	t.Cleanup(restore)

	quiet := logrus.New()
	quiet.SetLevel(logrus.PanicLevel)
	logger := logging.WrapLogrus(quiet)

	dbPath := filepath.Join(t.TempDir(), "replay.db")
	rawDB, err := sql.Open("sqlite3", "file:"+dbPath+"?_busy_timeout=10000&_journal_mode=WAL")
	require.NoError(t, err)
	t.Cleanup(func() { _ = rawDB.Close() })
	require.NoError(t, rvdb.NewRepository(logger).SetupSchema(rawDB, rvdb.SQLite))

	cacheCfg, err := rvconfig.LoadCacheConfig()
	require.NoError(t, err)
	cacheCfg.Secrets.Enabled = false
	v := viper.New()
	v.Set("jwt.key_source", "os_store")
	c, err := container.NewServiceContainer(container.Config{
		Database: rawDB, Logger: logger, CacheConfig: &cacheCfg, Viper: v,
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = c.Close() })

	hash, err := authServices.NewPasswordService().HashPassword("Correct-Horse-9")
	require.NoError(t, err)
	key, err := authServices.NewTOTPService().GenerateSecret("PasswordManager", "replay-http")
	require.NoError(t, err)
	require.NoError(t, c.GetUserRepository().Create(context.Background(), &model.User{
		ID: uuid.New(), Username: "replay-http", PasswordHash: hash, TOTPSecret: key.Secret(),
		Roles: []string{model.RoleUser}, CreatedAt: time.Now(),
	}))

	router := mux.NewRouter()
	Init(
		WithAPP(&app.App{ServiceContainer: c, Logger: logger}),
		WithRouter(router),
		WithBasePath("/api/v1"),
		WithLogger(logger),
	)
	return &replayRouter{handler: router, username: "replay-http", password: "Correct-Horse-9", secret: key.Secret()}
}

// login posts to /api/v1/users/login through the real middleware chain. It
// takes no *testing.T, so racing goroutines may call it.
func (rr *replayRouter) login(code string) *httptest.ResponseRecorder {
	body := encodeBody(map[string]string{"username": rr.username, "password": rr.password, "totp_code": code})
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/api/v1/users/login", body)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	rr.handler.ServeHTTP(w, req)
	return w
}

// wrongCodeFor returns a six-digit code that matches none of the codes near
// now for secret, so it is wrong for every step a login checks.
func wrongCodeFor(t *testing.T, secret string) string {
	t.Helper()
	totp := authServices.NewTOTPService()
	now := time.Now()
	// The login accepts two steps either side of now. Two more steps of margin
	// cover a step boundary crossed while the test runs.
	window := make(map[string]bool)
	for offset := -4; offset <= 4; offset++ {
		code, err := totp.GenerateCode(secret, now.Add(time.Duration(offset)*30*time.Second))
		require.NoError(t, err)
		window[code] = true
	}
	for _, candidate := range []string{"000000", "111111", "222222", "333333", "444444", "555555", "666666", "777777", "888888", "999999"} {
		if !window[candidate] {
			return candidate
		}
	}
	t.Fatal("no wrong code found")
	return ""
}

// A replayed code is refused over HTTP with the same status and body as a
// wrong code, so the response does not reveal that the code was right.
func TestLoginRoute_ReplayedTOTPCode_LooksLikeWrongCode(t *testing.T) {
	rr := newReplayRouter(t)

	// A wrong code first: it must not use up the current step.
	wrongResp := rr.login(wrongCodeFor(t, rr.secret))
	require.Equal(t, http.StatusForbidden, wrongResp.Code)

	code, err := authServices.NewTOTPService().GenerateCode(rr.secret, time.Now())
	require.NoError(t, err)

	okResp := rr.login(code)
	require.Equal(t, http.StatusOK, okResp.Code, okResp.Body.String())
	assert.Contains(t, okResp.Body.String(), "refresh_token")

	replayResp := rr.login(code)
	assert.Equal(t, http.StatusForbidden, replayResp.Code)
	assert.Equal(t, withoutRequestID(t, wrongResp), withoutRequestID(t, replayResp))
	assert.NotContains(t, replayResp.Body.String(), "token")
}

// withoutRequestID decodes an error body and drops its per-request id, which
// differs on every response.
func withoutRequestID(t *testing.T, w *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var body map[string]any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
	require.Contains(t, body, "request_id")
	delete(body, "request_id")
	return body
}

// Two logins racing with the same code over HTTP: exactly one gets a session.
func TestLoginRoute_ConcurrentSameTOTPCode_ExactlyOne200(t *testing.T) {
	rr := newReplayRouter(t)
	code, err := authServices.NewTOTPService().GenerateCode(rr.secret, time.Now())
	require.NoError(t, err)

	var (
		wg    sync.WaitGroup
		start = make(chan struct{})
		codes = make([]int, 2)
	)
	for i := range codes {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			codes[i] = rr.login(code).Code
		}()
	}
	close(start)
	wg.Wait()

	ok, forbidden := 0, 0
	for _, status := range codes {
		switch status {
		case http.StatusOK:
			ok++
		case http.StatusForbidden:
			forbidden++
		}
	}
	assert.Equal(t, 1, ok, "exactly one racing login may succeed, got %v", codes)
	assert.Equal(t, 1, forbidden, "the other racing login must be refused, got %v", codes)
}
