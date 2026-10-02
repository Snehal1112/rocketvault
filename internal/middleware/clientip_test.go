package middleware

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"

	"github.com/sirupsen/logrus"
	logtest "github.com/sirupsen/logrus/hooks/test"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"

	"rocketvault/internal/logging"
)

func mustNets(t *testing.T, cidrs ...string) []*net.IPNet {
	t.Helper()
	var out []*net.IPNet
	for _, c := range cidrs {
		_, n, err := net.ParseCIDR(c)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, n)
	}
	return out
}

func reqFrom(remote string, headers map[string]string) *http.Request {
	r := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/api/v1/users/login", nil)
	r.RemoteAddr = remote
	for k, v := range headers {
		r.Header.Set(k, v)
	}
	return r
}

func TestClientIP_UntrustedPeerIgnoresForwardedHeaders(t *testing.T) {
	t.Parallel()
	res := NewClientIPResolver(nil)
	r := reqFrom("203.0.113.9:4000", map[string]string{
		"X-Forwarded-For": "1.2.3.4", "X-Real-IP": "5.6.7.8",
	})
	assert.Equal(t, "203.0.113.9", res.ClientIP(r))

	// A peer outside the trusted list is also ignored when a list exists.
	res = NewClientIPResolver(mustNets(t, "10.0.0.0/8"))
	assert.Equal(t, "203.0.113.9", res.ClientIP(r))
}

func TestClientIP_TrustedPeerWalksRightToLeft(t *testing.T) {
	t.Parallel()
	res := NewClientIPResolver(mustNets(t, "10.0.0.0/8"))
	// The leftmost entry is client-forged; the rightmost untrusted hop is real.
	r := reqFrom("10.0.0.2:4000", map[string]string{
		"X-Forwarded-For": "6.6.6.6, 198.51.100.7, 10.0.0.9",
	})
	assert.Equal(t, "198.51.100.7", res.ClientIP(r))
}

func TestClientIP_TrustedPeerJoinsRepeatedHeaders(t *testing.T) {
	t.Parallel()
	res := NewClientIPResolver(mustNets(t, "10.0.0.0/8"))
	r := reqFrom("10.0.0.2:4000", nil)
	// The client sends its own forged header; the proxy appends a second one.
	r.Header.Add("X-Forwarded-For", "6.6.6.6")
	r.Header.Add("X-Forwarded-For", "198.51.100.7")
	assert.Equal(t, "198.51.100.7", res.ClientIP(r))
}

func TestClientIP_MalformedHopFallsBackToPeer(t *testing.T) {
	t.Parallel()
	res := NewClientIPResolver(mustNets(t, "10.0.0.0/8"))
	r := reqFrom("10.0.0.2:4000", map[string]string{"X-Forwarded-For": "garbage, 10.0.0.9"})
	assert.Equal(t, "10.0.0.2", res.ClientIP(r))

	// An empty hop is malformed too.
	r = reqFrom("10.0.0.2:4000", map[string]string{"X-Forwarded-For": "198.51.100.7, , 10.0.0.9"})
	assert.Equal(t, "10.0.0.2", res.ClientIP(r))
}

func TestClientIP_AllHopsTrustedReturnsOrigin(t *testing.T) {
	t.Parallel()
	res := NewClientIPResolver(mustNets(t, "10.0.0.0/8"))
	// X-Real-IP is not consulted once a forwarded chain is present.
	r := reqFrom("10.0.0.2:4000", map[string]string{
		"X-Forwarded-For": "10.1.1.1, 10.0.0.9", "X-Real-IP": "6.6.6.6",
	})
	assert.Equal(t, "10.1.1.1", res.ClientIP(r))
}

func TestClientIP_TrustedPeerFallsBackToXRealIPThenPeer(t *testing.T) {
	t.Parallel()
	res := NewClientIPResolver(mustNets(t, "10.0.0.0/8"))
	r := reqFrom("10.0.0.2:4000", map[string]string{"X-Real-IP": "198.51.100.8"})
	assert.Equal(t, "198.51.100.8", res.ClientIP(r))
	assert.Equal(t, "10.0.0.2", res.ClientIP(reqFrom("10.0.0.2:4000", nil)))
	bad := reqFrom("10.0.0.2:4000", map[string]string{"X-Real-IP": "garbage"})
	assert.Equal(t, "10.0.0.2", res.ClientIP(bad))
}

func TestClientIP_IPv6PeerAndHops(t *testing.T) {
	t.Parallel()
	res := NewClientIPResolver(mustNets(t, "fd00::/8"))
	r := reqFrom("[fd00::2]:4000", map[string]string{
		"X-Forwarded-For": "2001:db8::66, 2001:db8::7, fd00::9",
	})
	assert.Equal(t, "2001:db8::7", res.ClientIP(r))
	assert.Equal(t, "2001:db8::5", res.ClientIP(reqFrom("[2001:db8::5]:1", map[string]string{
		"X-Forwarded-For": "1.2.3.4",
	})))
}

func TestClientIP_NilResolverAndBadRemoteAddr(t *testing.T) {
	t.Parallel()
	var res *ClientIPResolver
	assert.Equal(t, "203.0.113.9", res.ClientIP(reqFrom("203.0.113.9:1", nil)))
	assert.Equal(t, "not-an-addr", res.ClientIP(reqFrom("not-an-addr", nil)))
	assert.Equal(t, "fe80::1", res.ClientIP(reqFrom("[fe80::1%eth0]:1", nil)))
}

func TestExtractClientIP_UsesPublishedResolver(t *testing.T) {
	SetClientIPResolver(NewClientIPResolver(mustNets(t, "10.0.0.0/8")))
	t.Cleanup(func() { SetClientIPResolver(nil) })
	r := reqFrom("10.0.0.2:1", map[string]string{"X-Forwarded-For": "198.51.100.7"})
	assert.Equal(t, "198.51.100.7", ExtractClientIP(r))

	SetClientIPResolver(nil)
	assert.Equal(t, "10.0.0.2", ExtractClientIP(r))
}

// rateLimitRemaining sends one login request and returns X-RateLimit-Remaining.
func rateLimitRemaining(t *testing.T, h http.Handler, r *http.Request) int {
	t.Helper()
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, r)
	n, err := strconv.Atoi(rr.Header().Get("X-RateLimit-Remaining"))
	if err != nil {
		t.Fatal(err)
	}
	return n
}

func TestRateLimitMiddleware_UntrustedPeerCannotSwitchBucket(t *testing.T) {
	t.Parallel()
	logger := &logging.Logger{Logger: logrus.New()}
	logger.SetLevel(logrus.ErrorLevel)
	m := &Middleware{
		logger:         logger,
		defaultLimiter: newKeyedRateLimiter(60),
		authLimiter:    newKeyedRateLimiter(5),
		clientIPs:      NewClientIPResolver(mustNets(t, "10.0.0.0/8")),
	}
	h := m.RateLimitMiddleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// A forged header per request must not give an untrusted peer a fresh bucket.
	first := rateLimitRemaining(t, h, reqFrom("203.0.113.9:1", map[string]string{"X-Forwarded-For": "1.1.1.1"}))
	second := rateLimitRemaining(t, h, reqFrom("203.0.113.9:2", map[string]string{"X-Forwarded-For": "2.2.2.2"}))
	assert.Equal(t, first-1, second)
}

func TestRateLimitMiddleware_TrustedProxyBucketsByClient(t *testing.T) {
	t.Parallel()
	logger := &logging.Logger{Logger: logrus.New()}
	logger.SetLevel(logrus.ErrorLevel)
	m := &Middleware{
		logger:         logger,
		defaultLimiter: newKeyedRateLimiter(60),
		authLimiter:    newKeyedRateLimiter(5),
		clientIPs:      NewClientIPResolver(mustNets(t, "10.0.0.0/8")),
	}
	h := m.RateLimitMiddleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// Two clients behind the same proxy get separate buckets.
	a := rateLimitRemaining(t, h, reqFrom("10.0.0.2:1", map[string]string{"X-Forwarded-For": "198.51.100.1"}))
	b := rateLimitRemaining(t, h, reqFrom("10.0.0.2:1", map[string]string{"X-Forwarded-For": "198.51.100.2"}))
	assert.Equal(t, a, b)
	// The same client through the proxy shares its bucket, even with a forged prefix.
	c := rateLimitRemaining(t, h, reqFrom("10.0.0.2:1", map[string]string{"X-Forwarded-For": "9.9.9.9, 198.51.100.1"}))
	assert.Equal(t, a-1, c)
}

func TestLoggingMiddleware_LogsResolvedClientIP(t *testing.T) {
	t.Parallel()
	base := logrus.New()
	hook := logtest.NewLocal(base)
	m := &Middleware{
		logger:    &logging.Logger{Logger: base},
		clientIPs: NewClientIPResolver(mustNets(t, "10.0.0.0/8")),
	}
	h := m.LoggingMiddleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	h.ServeHTTP(httptest.NewRecorder(), reqFrom("10.0.0.2:4000", map[string]string{"X-Forwarded-For": "198.51.100.7"}))
	h.ServeHTTP(httptest.NewRecorder(), reqFrom("203.0.113.9:4000", map[string]string{"X-Forwarded-For": "198.51.100.7"}))

	entries := hook.AllEntries()
	if assert.Len(t, entries, 2) {
		assert.Equal(t, "198.51.100.7", entries[0].Data["client_ip"])
		assert.Equal(t, "203.0.113.9", entries[1].Data["client_ip"])
	}
}

// setTrustedProxiesForTest sets server.trusted_proxies on the global viper
// and restores the previous value when the test ends, so other tests keep
// their configuration.
func setTrustedProxiesForTest(t *testing.T, value []string) {
	t.Helper()
	const key = "server.trusted_proxies"
	previous := viper.Get(key)
	t.Cleanup(func() {
		viper.Set(key, previous)
		SetClientIPResolver(nil)
	})
	viper.Set(key, value)
}

func TestNewMiddleware_LoadsTrustedProxies(t *testing.T) {
	setTrustedProxiesForTest(t, []string{"10.0.0.0/8"})
	mw := NewMiddleware(&MockServiceContainer{logger: &logging.Logger{Logger: logrus.New()}})

	r := reqFrom("10.0.0.2:1", map[string]string{"X-Forwarded-For": "198.51.100.7"})
	assert.Equal(t, "198.51.100.7", mw.clientIP(r))
	assert.Equal(t, "198.51.100.7", ExtractClientIP(r))
}

func TestNewMiddleware_InvalidTrustedProxiesTrustsNothing(t *testing.T) {
	setTrustedProxiesForTest(t, []string{"10.0.0.0/8", "not-an-ip"})
	base := logrus.New()
	hook := logtest.NewLocal(base)
	mw := NewMiddleware(&MockServiceContainer{logger: &logging.Logger{Logger: base}})

	// The valid entry is dropped too: a half-applied list is not trusted.
	r := reqFrom("10.0.0.2:1", map[string]string{"X-Forwarded-For": "198.51.100.7"})
	assert.Equal(t, "10.0.0.2", mw.clientIP(r))
	assert.Equal(t, "10.0.0.2", ExtractClientIP(r))
	if assert.NotNil(t, hook.LastEntry()) {
		assert.Equal(t, logrus.ErrorLevel, hook.LastEntry().Level)
	}
}

func TestRateLimitKey(t *testing.T) {
	t.Parallel()
	assert.Equal(t, "203.0.113.9", rateLimitKey("203.0.113.9"))
	assert.Equal(t, "203.0.113.9", rateLimitKey("::ffff:203.0.113.9"))
	// Two hosts in one /64 share a key; a different /64 does not.
	a := rateLimitKey("2001:db8:1:2:aaaa:bbbb:cccc:dddd")
	b := rateLimitKey("2001:db8:1:2:1111:2222:3333:4444")
	c := rateLimitKey("2001:db8:1:3::1")
	assert.Equal(t, a, b)
	assert.NotEqual(t, a, c)
	assert.Equal(t, "2001:db8:1:2::/64", a)
	// Unparseable input is used as-is.
	assert.Equal(t, "not-an-ip", rateLimitKey("not-an-ip"))
}

func newRateLimitTestMiddleware(defaultPerMin, authPerMin int64) *Middleware {
	logger := &logging.Logger{Logger: logrus.New()}
	logger.SetLevel(logrus.ErrorLevel)
	return &Middleware{
		logger:         logger,
		defaultLimiter: newKeyedRateLimiter(defaultPerMin),
		authLimiter:    newKeyedRateLimiter(authPerMin),
	}
}

func TestRateLimitMiddleware_IPv6SameSlash64SharesBucket(t *testing.T) {
	t.Parallel()
	m := newRateLimitTestMiddleware(60, 2)
	h := m.RateLimitMiddleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	codes := []int{}
	for _, remote := range []string{
		"[2001:db8:1:2::1]:1", "[2001:db8:1:2::2]:1", "[2001:db8:1:2::3]:1",
	} {
		req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/api/v1/users/login", nil)
		req.RemoteAddr = remote
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		codes = append(codes, rr.Code)
	}
	// Burst is 2 on the auth limiter, so the third source in the /64 is refused.
	assert.Equal(t, []int{200, 200, 429}, codes)
}
