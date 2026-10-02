package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"rocketvault/app"
	"rocketvault/common"

	"github.com/stretchr/testify/assert"
)

func TestWriteJSON_SetsNoStore(t *testing.T) {
	w := httptest.NewRecorder()
	writeJSON(w, map[string]string{"a": "b"})
	assert.Equal(t, "no-store", w.Header().Get("Cache-Control"))
}

func TestWriteJSONStatus_SetsNoStore(t *testing.T) {
	w := httptest.NewRecorder()
	writeJSONStatus(w, http.StatusConflict, map[string]string{"a": "b"})
	assert.Equal(t, "no-store", w.Header().Get("Cache-Control"))
}

func TestWriteJSON_KeepsExplicitCacheControl(t *testing.T) {
	w := httptest.NewRecorder()
	w.Header().Set("Cache-Control", "public, max-age=3600")
	writeJSON(w, map[string]string{"a": "b"})
	assert.Equal(t, "public, max-age=3600", w.Header().Get("Cache-Control"))
}

func TestApiSessionRequired_SetsNoStoreOnDirectWrites(t *testing.T) {
	h := ApiSessionRequired(&app.App{}, func(c *Context, w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{}`)) //nolint:errcheck,gosec
	})
	ctx := context.WithValue(context.Background(), common.UserIDKey, secretHTestUserID)
	r := httptest.NewRequestWithContext(ctx, http.MethodGet, "/x", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	assert.Equal(t, "no-store", w.Header().Get("Cache-Control"))
}
