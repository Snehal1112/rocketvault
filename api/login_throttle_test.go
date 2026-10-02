package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// loginFrom posts a login through the real router from its own client
// address, so the per-IP limiter never answers before the per-account one.
func (rr *replayRouter) loginFrom(t *testing.T, ip int, username, password, code string) *httptest.ResponseRecorder {
	t.Helper()
	body := encodeBody(map[string]string{"username": username, "password": password, "totp_code": code})
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/api/v1/users/login", body)
	req.Header.Set("Content-Type", "application/json")
	req.RemoteAddr = "198.51.100." + strconv.Itoa(ip) + ":40000"
	w := httptest.NewRecorder()
	rr.handler.ServeHTTP(w, req)
	return w
}

// After six failures from six different addresses, the seventh attempt is
// refused with 429 and a Retry-After, for a real account and an unknown name
// alike. The two throttled responses are identical, so they do not reveal
// whether the account exists.
func TestLoginRoute_PerAccountBackoff_Returns429ForKnownAndUnknownUsers(t *testing.T) {
	// Failed logins count toward the shared database circuit breaker (B90),
	// which would open after five of them and answer 403 first. Raise the
	// threshold so this test observes the per-account throttle alone.
	rr := newReplayRouterWith(t, func(v *viper.Viper) {
		v.Set("retry.circuit_breaker.failure_threshold", 1000)
	})
	wrong := wrongCodeFor(t, rr.secret)

	ip := 1
	throttled := map[string]*httptest.ResponseRecorder{}
	for _, username := range []string{rr.username, "no-such-user"} {
		for i := 0; i < 6; i++ {
			resp := rr.loginFrom(t, ip, username, "wrong-password", wrong)
			ip++
			require.Equal(t, http.StatusForbidden, resp.Code, "failure %d for %q: %s", i+1, username, resp.Body.String())
		}
		resp := rr.loginFrom(t, ip, username, "wrong-password", wrong)
		ip++
		require.Equal(t, http.StatusTooManyRequests, resp.Code, resp.Body.String())
		retryAfter, err := strconv.Atoi(resp.Header().Get("Retry-After"))
		require.NoError(t, err)
		assert.True(t, retryAfter >= 1 && retryAfter <= 2, "the sixth failure imposes a 2s wait, got %d", retryAfter)
		assert.NotContains(t, resp.Body.String(), username)
		throttled[username] = resp
	}

	assert.Equal(t,
		withoutRequestID(t, throttled[rr.username]),
		withoutRequestID(t, throttled["no-such-user"]),
		"throttle responses must not reveal whether the account exists")
}
