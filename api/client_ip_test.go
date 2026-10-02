package api

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"rocketvault/app"
	"rocketvault/internal/middleware"
)

// TestApiHandler_IPAddressUsesClientIPResolver checks that the handler context
// records the resolved client address, never a forged header from an untrusted peer.
// It mutates the published resolver, so it must not run in parallel.
func TestApiHandler_IPAddressUsesClientIPResolver(t *testing.T) {
	_, proxies, err := net.ParseCIDR("10.0.0.0/8")
	require.NoError(t, err)
	middleware.SetClientIPResolver(middleware.NewClientIPResolver([]*net.IPNet{proxies}))
	t.Cleanup(func() { middleware.SetClientIPResolver(nil) })

	var got string
	handler := ApiHandler(&app.App{}, func(c *Context, w http.ResponseWriter, _ *http.Request) {
		got = c.IPAddress
		w.WriteHeader(http.StatusOK)
	})

	r := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/api/v1/users/login", nil)
	r.RemoteAddr = "10.0.0.2:4000"
	r.Header.Set("X-Forwarded-For", "6.6.6.6, 198.51.100.7")
	handler.ServeHTTP(httptest.NewRecorder(), r)
	assert.Equal(t, "198.51.100.7", got)

	r = httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/api/v1/users/login", nil)
	r.RemoteAddr = "203.0.113.9:4000"
	r.Header.Set("X-Forwarded-For", "198.51.100.7")
	handler.ServeHTTP(httptest.NewRecorder(), r)
	assert.Equal(t, "203.0.113.9", got)
}
