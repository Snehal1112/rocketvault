# Login Rate Limiting Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (- [ ]) syntax for tracking.

> **PREREQUISITE: implement this plan AFTER `docs/superpowers/plans/2026-09-30-identity-sessions-hardening.md` has landed.** That plan edits the same function, `AuthenticationService.AuthenticateUser` in `internal/services/auth/authentication_service.go`, and the same test helpers. It adds two new failure exits (empty TOTP secret, replayed TOTP step), adds `AuthenticationConfig.TOTPStepRepository`, and replaces `TOTPService.ValidateCode` with `ValidateCodeWithStep` in the mocks and tests. Tasks 4 and 5 below are written against the post-identity state of the code. If for some reason this plan must go first, skip the steps marked "if the identity plan has landed" and use `ValidateCode` (returning `(bool, error)`) in the Task 4 test helpers, then re-apply those steps when the identity plan lands. Line numbers quoted for `authentication_service.go` are from the pre-identity file and will shift; locate code by the branch comments, not the numbers.

**Goal:** Make login and token rate limiting correct behind a reverse proxy and under IPv6 rotation, add per-account exponential backoff, and close the related timing, audit and query-string findings.

**Architecture:** One `ClientIPResolver` (new, `internal/middleware/clientip.go`) is the only place that decides a caller's IP; it honours `X-Forwarded-For` / `X-Real-IP` only when the TCP peer is inside the new `server.trusted_proxies` list (default empty, so direct deployments are unchanged). `keyedRateLimiter` is rebuilt around a mutex-guarded bounded map with idle eviction on an injectable clock. Per-account backoff is a service (`LoginThrottle`) over a new pure-CRUD repository and a `login_failures` table, consulted by `AuthenticationService.AuthenticateUser`, which both HTTP login and the CLI call.

**Tech Stack:** Go 1.24, gorilla/mux, golang.org/x/time/rate, viper, SQLite/Postgres, testify.

**Spec:** GitHub issue #46 (login rate limiting is per IP only and breaks behind a reverse proxy; closed by this plan). Audit: `.claude/pentest-report-2026-08-16.md` and the Low findings named in the issue (username timing in `internal/services/auth/authentication_service.go`, `internal/services/oauth2/oauth2_service.go`; audit-row pollution and query-string secret in `api/oauth2.go`; unthrottled `/config` in `api/api.go`). Known-bug entry: `.claude/known-bugs.md` § B85.

## Global Constraints

- Commits: invoke the `dev-workflow-skills:1-git-commit` plugin skill via the Skill tool; never a freeform `git commit -m`. All commits and tags are GPG signed (key 61D246B30285ED35). The final commit footer carries `Fixes #46`.
- Code comments are short full sentences ending with a punctuation mark.
- Before any PR: `go build ./...`, `go vet ./...` and `go test ./...` must pass. `golangci-lint` currently fails in this environment (snap Go toolchain incompatibility); lint must run in CI or on a fixed toolchain.
- CLI commands call the service layer directly and bypass HTTP middleware: tasks 4 and 5 change `AuthenticateUser`, so they are tested on the HTTP path (`api/users.go` `loginUser`) and the CLI path (`cmd/users/login.go` `performPasswordLogin`, `cmd/root.go` `resolveAuthentication`). Tasks 1, 2, 3, 6 are HTTP-only; task 7 is HTTP-only.
- Repositories are pure CRUD; backoff arithmetic lives in `LoginThrottle` (service), not the repository.
- Schema change follows the dual-write pattern in `internal/db/db.go`: `CREATE TABLE IF NOT EXISTS` in the initial schema block and again in `migrateSchema`'s statement list. Use `?` placeholders (the DB wrapper rewrites them for Postgres) and `TEXT`/`INTEGER`/`TIMESTAMP` only.
- No real secret in `.rocketvault.yaml.example` or `.rocketvault.docker.yaml.tmpl`.
- Defaults: `server.trusted_proxies` empty (XFF ignored); limiter idle TTL 2 minutes; limiter cap 100000 entries; login backoff 5 free failures, then 2s doubling, capped at 15 minutes, counter reset after 24 hours without a failure.
- Documentation goes under `.claude/` or `docs/`; no new top-level files.
- Only B85 is used from the bug-number range.

## Review Focus

- Spoofed `X-Forwarded-For` from an untrusted peer must not change the bucket or audit IP: test in Task 1 (`TestClientIP_UntrustedPeerIgnoresForwardedHeaders`).
- Rightmost-untrusted walk with a forged leftmost entry and a malformed hop: test in Task 1 (`TestClientIP_TrustedPeerWalksRightToLeft`, `TestClientIP_MalformedHopFallsBackToPeer`).
- Two IPv6 addresses in one /64 must share a bucket, IPv4-mapped IPv6 must equal the IPv4 key: Task 2 (`TestRateLimitKey`).
- Limiter map must stay bounded and must not drop a live (recently seen) bucket when sweeping: Task 3 (`TestKeyedRateLimiter_SweepKeepsActiveEntries`, `TestKeyedRateLimiter_CapEvictsOldest`).
- An attacker must not be able to extend an admin's throttle by hammering during the window: Task 4 (`TestLoginThrottle_AttemptsDuringWindowDoNotGrowCounter`), and a correct login after the window must succeed and reset: `TestAuthenticateUser_SuccessResetsThrottle`.
- Throttle responses must not reveal whether a username exists: Task 4 (`TestAuthenticateUser_UnknownUserIsThrottledLikeKnownUser`).
- `client_secret` in the query string must be ignored, and control characters / invalid UTF-8 in `client_id` must not reach the audit row: Tasks 6 and 7.

---

### Task 1: Trusted-proxy config and the single ClientIP helper

**Files**:
- Create: `config/trusted_proxy.go`, `config/trusted_proxy_test.go`
- Create: `internal/middleware/clientip.go`, `internal/middleware/clientip_test.go`
- Modify: `internal/middleware/middleware.go` (struct `Middleware` ~lines 87-97; `NewMiddleware` ~lines 112-147; `LoggingMiddleware` `client_ip` field ~line 167; `RateLimitMiddleware` IP extraction ~lines 188-195; `ExtractClientIP` ~lines 247-260)
- Modify: `.rocketvault.yaml.example` (`server:` section), `.rocketvault.docker.yaml.tmpl` (`server:` section ~line 61)

**Interfaces**:
- Consumes: `viper`, existing `Middleware` struct.
- Produces:
  - `config.LoadTrustedProxies() ([]*net.IPNet, error)` reading `server.trusted_proxies` (list of IPs or CIDRs).
  - `middleware.NewClientIPResolver(nets []*net.IPNet) *ClientIPResolver`
  - `func (c *ClientIPResolver) ClientIP(r *http.Request) string` (nil receiver behaves as no trusted proxies).
  - `middleware.SetClientIPResolver(c *ClientIPResolver)`; `ExtractClientIP(r *http.Request) string` keeps its signature and delegates to the published resolver.
  - `func (m *Middleware) clientIP(r *http.Request) string`.

The existing `config.Config.TrustedProxyIPs/TrustedProxyNets` fields are unused by any code; leave them alone and do not wire to them.

- [ ] **Step 1: Write the failing config test** in `config/trusted_proxy_test.go`:

```go
package config

import (
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLoadTrustedProxies_DefaultsToNone(t *testing.T) {
	viper.Reset()
	nets, err := LoadTrustedProxies()
	require.NoError(t, err)
	assert.Empty(t, nets)
}

func TestLoadTrustedProxies_ParsesIPsAndCIDRs(t *testing.T) {
	viper.Reset()
	viper.Set("server.trusted_proxies", []string{"10.0.0.0/8", "192.168.1.5", "fd00::/8", "2001:db8::1"})
	nets, err := LoadTrustedProxies()
	require.NoError(t, err)
	require.Len(t, nets, 4)
	assert.True(t, nets[0].Contains([]byte{10, 1, 2, 3}))
	assert.Equal(t, "192.168.1.5/32", nets[1].String())
	assert.Equal(t, "2001:db8::1/128", nets[3].String())
}

func TestLoadTrustedProxies_RejectsGarbage(t *testing.T) {
	viper.Reset()
	viper.Set("server.trusted_proxies", []string{"not-an-ip"})
	_, err := LoadTrustedProxies()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "server.trusted_proxies")
}
```

- [ ] **Step 2: Run it** `go test ./config/ -run TestLoadTrustedProxies -v`. Expected: FAIL, `undefined: LoadTrustedProxies`.

- [ ] **Step 3: Implement** `config/trusted_proxy.go`:

```go
package config

import (
	"fmt"
	"net"
	"strings"

	"github.com/spf13/viper"
)

// LoadTrustedProxies reads server.trusted_proxies, a list of IP addresses or
// CIDR ranges of reverse proxies whose forwarded-address headers may be trusted.
// The default is an empty list, which means the headers are never trusted.
func LoadTrustedProxies() ([]*net.IPNet, error) {
	raw := viper.GetStringSlice("server.trusted_proxies")
	nets := make([]*net.IPNet, 0, len(raw))
	for _, entry := range raw {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		if _, n, err := net.ParseCIDR(entry); err == nil {
			nets = append(nets, n)
			continue
		}
		ip := net.ParseIP(entry)
		if ip == nil {
			return nil, fmt.Errorf("server.trusted_proxies: %q is not an IP address or CIDR range", entry)
		}
		bits := 128
		if ip.To4() != nil {
			ip = ip.To4()
			bits = 32
		}
		nets = append(nets, &net.IPNet{IP: ip, Mask: net.CIDRMask(bits, bits)})
	}
	return nets, nil
}
```

- [ ] **Step 4: Run** `go test ./config/ -run TestLoadTrustedProxies -v`. Expected: PASS.

- [ ] **Step 5: Write the failing resolver tests** in `internal/middleware/clientip_test.go`:

```go
package middleware

import (
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
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
	r := httptest.NewRequest(http.MethodPost, "/api/v1/users/login", nil)
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

func TestClientIP_MalformedHopFallsBackToPeer(t *testing.T) {
	t.Parallel()
	res := NewClientIPResolver(mustNets(t, "10.0.0.0/8"))
	r := reqFrom("10.0.0.2:4000", map[string]string{"X-Forwarded-For": "garbage, 10.0.0.9"})
	assert.Equal(t, "10.0.0.2", res.ClientIP(r))
}

func TestClientIP_TrustedPeerFallsBackToXRealIPThenPeer(t *testing.T) {
	t.Parallel()
	res := NewClientIPResolver(mustNets(t, "10.0.0.0/8"))
	r := reqFrom("10.0.0.2:4000", map[string]string{"X-Real-IP": "198.51.100.8"})
	assert.Equal(t, "198.51.100.8", res.ClientIP(r))
	assert.Equal(t, "10.0.0.2", res.ClientIP(reqFrom("10.0.0.2:4000", nil)))
}

func TestClientIP_NilResolverAndBadRemoteAddr(t *testing.T) {
	t.Parallel()
	var res *ClientIPResolver
	assert.Equal(t, "203.0.113.9", res.ClientIP(reqFrom("203.0.113.9:1", nil)))
	assert.Equal(t, "not-an-addr", res.ClientIP(reqFrom("not-an-addr", nil)))
}

func TestExtractClientIP_UsesPublishedResolver(t *testing.T) {
	SetClientIPResolver(NewClientIPResolver(mustNets(t, "10.0.0.0/8")))
	t.Cleanup(func() { SetClientIPResolver(nil) })
	r := reqFrom("10.0.0.2:1", map[string]string{"X-Forwarded-For": "198.51.100.7"})
	assert.Equal(t, "198.51.100.7", ExtractClientIP(r))

	SetClientIPResolver(nil)
	assert.Equal(t, "10.0.0.2", ExtractClientIP(r))
}
```

The last test mutates package state, so do not add `t.Parallel()` to it.

- [ ] **Step 6: Run** `go test ./internal/middleware/ -run 'TestClientIP|TestExtractClientIP' -v`. Expected: FAIL, `undefined: NewClientIPResolver`.

- [ ] **Step 7: Implement** `internal/middleware/clientip.go`:

```go
package middleware

import (
	"net"
	"net/http"
	"strings"
	"sync/atomic"
)

// ClientIPResolver decides which IP address a request really came from.
// Forwarded-address headers are honoured only when the TCP peer is itself a
// trusted proxy, because any client can send them.
type ClientIPResolver struct {
	trusted []*net.IPNet
}

// NewClientIPResolver builds a resolver trusting the given proxy networks.
// A nil or empty list means forwarded headers are never trusted.
func NewClientIPResolver(trusted []*net.IPNet) *ClientIPResolver {
	return &ClientIPResolver{trusted: trusted}
}

func (c *ClientIPResolver) trusts(ip net.IP) bool {
	if c == nil {
		return false
	}
	for _, n := range c.trusted {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// ClientIP returns the caller's address. A nil receiver trusts no proxies.
func (c *ClientIPResolver) ClientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	peer := net.ParseIP(host)
	if peer == nil {
		return r.RemoteAddr
	}
	if !c.trusts(peer) {
		return peer.String()
	}

	// Walk the forwarded chain from the proxy side. The first hop that is not
	// a trusted proxy is the client; anything further left is client-supplied.
	var hops []string
	for _, v := range r.Header.Values("X-Forwarded-For") {
		hops = append(hops, strings.Split(v, ",")...)
	}
	for i := len(hops) - 1; i >= 0; i-- {
		ip := net.ParseIP(strings.TrimSpace(hops[i]))
		if ip == nil {
			return peer.String()
		}
		if !c.trusts(ip) {
			return ip.String()
		}
	}
	if ip := net.ParseIP(strings.TrimSpace(r.Header.Get("X-Real-IP"))); ip != nil {
		return ip.String()
	}
	return peer.String()
}

var publishedResolver atomic.Pointer[ClientIPResolver]

// SetClientIPResolver publishes the resolver used by ExtractClientIP.
// Passing nil restores the trust-nothing default.
func SetClientIPResolver(c *ClientIPResolver) {
	publishedResolver.Store(c)
}

// ExtractClientIP returns the client's IP address using the published resolver.
// It is kept for the API handlers that record an audit IP.
func ExtractClientIP(r *http.Request) string {
	return publishedResolver.Load().ClientIP(r)
}
```

- [ ] **Step 8: Wire into `middleware.go`.** Delete the old `ExtractClientIP` (lines ~247-260). Add to `Middleware` struct `clientIPs *ClientIPResolver`. In `NewMiddleware`, before the `return`:

```go
	trusted, err := config.LoadTrustedProxies()
	if err != nil {
		// Fail closed: with no trusted proxies the headers are simply ignored.
		container.GetLogger().WithError(err).Error("Invalid server.trusted_proxies, ignoring forwarded headers")
		trusted = nil
	}
	resolver := NewClientIPResolver(trusted)
	SetClientIPResolver(resolver)
```

add `clientIPs: resolver,` to the returned struct, and import `"rocketvault/config"`. (Check `config` does not import `middleware`; it imports only logging.) Add:

```go
// clientIP resolves the caller's address through the configured resolver.
func (m *Middleware) clientIP(r *http.Request) string {
	return m.clientIPs.ClientIP(r)
}
```

In `RateLimitMiddleware` replace lines 188-195 (the `net.SplitHostPort` block) with `ip := m.clientIP(r)`. In `LoggingMiddleware` change `"client_ip": r.RemoteAddr` to `"client_ip": m.clientIP(r)`. Remove the `net` import if now unused.

- [ ] **Step 9: Config files.** In `.rocketvault.yaml.example` under `server:` add:

```yaml
  # Reverse proxies whose X-Forwarded-For / X-Real-IP headers may be trusted,
  # as IP addresses or CIDR ranges. Leave empty when clients connect directly:
  # the headers are then ignored, since any client can forge them. Behind a
  # proxy (Railway, Fly, nginx) set this to the proxy's address range, or every
  # client shares the proxy's rate-limit bucket.
  trusted_proxies: []
```

Add the same block to `.rocketvault.docker.yaml.tmpl` under `server:` with `trusted_proxies: []`.

- [ ] **Step 10: Run** `go test ./internal/middleware/ ./config/ -v -run 'TestClientIP|TestExtractClientIP|TestLoadTrustedProxies|TestRateLimit'`. Expected: PASS (existing `TestRateLimitMiddleware*` still pass because those tests use `Middleware` literals with a nil resolver, which trusts nothing).
- [ ] **Step 11: Commit.** Invoke the `dev-workflow-skills:1-git-commit` skill.

---

### Task 2: IPv6 /64 bucketing

**Files**:
- Modify: `internal/middleware/clientip.go` (append `rateLimitKey`)
- Modify: `internal/middleware/middleware.go` (`RateLimitMiddleware`, the `selectedLimiter.get(ip)` call ~line 208)
- Test: `internal/middleware/clientip_test.go`

**Interfaces**:
- Consumes: `(*Middleware).clientIP` from Task 1.
- Produces: `func rateLimitKey(ip string) string`.

- [ ] **Step 1: Failing tests** appended to `clientip_test.go`:

```go
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
		req := httptest.NewRequest(http.MethodPost, "/api/v1/users/login", nil)
		req.RemoteAddr = remote
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		codes = append(codes, rr.Code)
	}
	// Burst is 2 on the auth limiter, so the third source in the /64 is refused.
	assert.Equal(t, []int{200, 200, 429}, codes)
}
```

Add this helper to the same file (it needs `logging` and `logrus` imports, mirroring `vault_rate_limit_test.go`):

```go
func newRateLimitTestMiddleware(defaultPerMin, authPerMin int64) *Middleware {
	logger := &logging.Logger{Logger: logrus.New()}
	logger.SetLevel(logrus.ErrorLevel)
	return &Middleware{
		logger:         logger,
		defaultLimiter: newKeyedRateLimiter(defaultPerMin),
		authLimiter:    newKeyedRateLimiter(authPerMin),
	}
}
```

- [ ] **Step 2: Run** `go test ./internal/middleware/ -run 'TestRateLimitKey|TestRateLimitMiddleware_IPv6' -v`. Expected: FAIL, `undefined: rateLimitKey`.
- [ ] **Step 3: Implement** in `clientip.go`:

```go
// rateLimitKey maps an address to its rate-limit bucket key. IPv6 clients are
// bucketed by /64, the smallest block an ISP hands out, so one host rotating
// through its own addresses cannot mint unlimited buckets. IPv4-mapped IPv6
// addresses use their IPv4 key.
func rateLimitKey(ip string) string {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return ip
	}
	if v4 := parsed.To4(); v4 != nil {
		return v4.String()
	}
	return parsed.Mask(net.CIDRMask(64, 128)).String() + "/64"
}
```

Change the limiter lookup in `RateLimitMiddleware` to `lim := selectedLimiter.get(rateLimitKey(ip))`; keep `ip` for the log field.
- [ ] **Step 4: Run** `go test ./internal/middleware/ -v -run 'TestRateLimit'`. Expected: PASS, including `TestRateLimitMiddleware_UsesIPNotAddrPort`.
- [ ] **Step 5: Commit** via the `dev-workflow-skills:1-git-commit` skill.

---

### Task 3: Bounded limiter map with idle eviction

**Files**:
- Modify: `internal/middleware/middleware.go` (`keyedRateLimiter`, `newKeyedRateLimiter`, `get`, lines ~62-84; imports: `sync` stays)
- Test: `internal/middleware/limiter_eviction_test.go` (create)

**Interfaces**:
- Consumes: `newKeyedRateLimiter(perMinute int64) *keyedRateLimiter` (existing; signature preserved, used by `NewMiddleware`, `vault_rate_limit_test.go`, `middleware_test.go`), `get(key string) *rate.Limiter`, fields `r`, `b`.
- Produces: `newKeyedRateLimiterWith(perMinute int64, maxEntries int, now func() time.Time) *keyedRateLimiter`; `(*keyedRateLimiter).len() int`; constants `limiterIdleTTL = 2 * time.Minute`, `limiterSweepInterval = time.Minute`, `defaultLimiterMaxEntries = 100000`.

A bucket idle for one minute is already full, so dropping it after 2 minutes is lossless. The rate.Limiter itself keeps using real time; only eviction uses the injected clock. At the cap the oldest entry is evicted after a sweep; this can reset a long-idle bucket, never a recently active one unless the map is full of active ones, which /64 bucketing and the per-IP cost make impractical.

- [ ] **Step 1: Failing tests** in `limiter_eviction_test.go`:

```go
package middleware

import (
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

type fakeClock struct{ t time.Time }

func (f *fakeClock) now() time.Time          { return f.t }
func (f *fakeClock) advance(d time.Duration) { f.t = f.t.Add(d) }

func TestKeyedRateLimiter_EvictsIdleEntries(t *testing.T) {
	t.Parallel()
	clk := &fakeClock{t: time.Unix(1_700_000_000, 0)}
	l := newKeyedRateLimiterWith(5, 1000, clk.now)
	for i := 0; i < 50; i++ {
		l.get(fmt.Sprintf("10.0.0.%d", i))
	}
	assert.Equal(t, 50, l.len())

	clk.advance(limiterIdleTTL + limiterSweepInterval)
	l.get("10.9.9.9") // Triggers the lazy sweep.
	assert.Equal(t, 1, l.len())
}

func TestKeyedRateLimiter_SweepKeepsActiveEntries(t *testing.T) {
	t.Parallel()
	clk := &fakeClock{t: time.Unix(1_700_000_000, 0)}
	l := newKeyedRateLimiterWith(5, 1000, clk.now)
	active := l.get("active")
	l.get("idle")

	for i := 0; i < 4; i++ {
		clk.advance(limiterSweepInterval)
		assert.Same(t, active, l.get("active"), "a recently used bucket must survive sweeps")
	}
	assert.Equal(t, 1, l.len(), "only the idle entry is evicted")
}

func TestKeyedRateLimiter_CapEvictsOldest(t *testing.T) {
	t.Parallel()
	clk := &fakeClock{t: time.Unix(1_700_000_000, 0)}
	l := newKeyedRateLimiterWith(5, 3, clk.now)
	l.get("a")
	clk.advance(time.Second)
	l.get("b")
	clk.advance(time.Second)
	l.get("c")
	clk.advance(time.Second)
	l.get("d") // Over the cap: "a" is the oldest.
	assert.Equal(t, 3, l.len())
	assert.NotContains(t, l.keys(), "a")
	assert.Contains(t, l.keys(), "d")
}

func TestKeyedRateLimiter_SameKeySameLimiter(t *testing.T) {
	t.Parallel()
	l := newKeyedRateLimiter(5)
	assert.Same(t, l.get("k"), l.get("k"))
}
```

`keys()` is a test helper; define it at the bottom of this test file:

```go
func (l *keyedRateLimiter) keys() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := make([]string, 0, len(l.entries))
	for k := range l.entries {
		out = append(out, k)
	}
	return out
}
```

- [ ] **Step 2: Run** `go test ./internal/middleware/ -run TestKeyedRateLimiter -v`. Expected: FAIL (`undefined: newKeyedRateLimiterWith`).
- [ ] **Step 3: Implement.** Replace the type and its methods in `middleware.go`:

```go
const (
	// limiterIdleTTL is how long a bucket may sit unused before it is dropped.
	// A bucket refills completely within a minute, so dropping an idle one
	// loses no rate-limit state.
	limiterIdleTTL = 2 * time.Minute
	// limiterSweepInterval bounds how often get() scans for idle buckets.
	limiterSweepInterval = time.Minute
	// defaultLimiterMaxEntries caps the map so a flood of distinct keys cannot
	// exhaust memory.
	defaultLimiterMaxEntries = 100000
)

type limiterEntry struct {
	lim      *rate.Limiter
	lastSeen time.Time
}

// keyedRateLimiter manages token-bucket limiters keyed by an arbitrary string.
// The key is a client IP (IPv6 grouped by /64) for the per-IP limiters and a
// vault id for the per-vault limiter. Token buckets refill continuously, so
// steady traffic is never blocked by a fixed-window reset. The map is bounded:
// idle buckets are swept lazily and the oldest is evicted at the cap.
type keyedRateLimiter struct {
	mu         sync.Mutex
	entries    map[string]*limiterEntry
	r          rate.Limit // tokens added per second
	b          int        // burst size (= configured per-minute limit)
	maxEntries int
	now        func() time.Time
	lastSweep  time.Time
}

func newKeyedRateLimiter(perMinute int64) *keyedRateLimiter {
	return newKeyedRateLimiterWith(perMinute, defaultLimiterMaxEntries, time.Now)
}

// newKeyedRateLimiterWith lets tests inject the clock and the entry cap.
func newKeyedRateLimiterWith(perMinute int64, maxEntries int, now func() time.Time) *keyedRateLimiter {
	return &keyedRateLimiter{
		entries:    make(map[string]*limiterEntry),
		r:          rate.Every(time.Minute / time.Duration(perMinute)),
		b:          int(perMinute),
		maxEntries: maxEntries,
		now:        now,
		lastSweep:  now(),
	}
}

// get returns the limiter for the given key, creating one if it doesn't exist.
func (l *keyedRateLimiter) get(key string) *rate.Limiter {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	if now.Sub(l.lastSweep) >= limiterSweepInterval {
		l.sweepLocked(now)
	}
	if e, ok := l.entries[key]; ok {
		e.lastSeen = now
		return e.lim
	}
	if len(l.entries) >= l.maxEntries {
		l.sweepLocked(now)
		if len(l.entries) >= l.maxEntries {
			l.evictOldestLocked()
		}
	}
	e := &limiterEntry{lim: rate.NewLimiter(l.r, l.b), lastSeen: now}
	l.entries[key] = e
	return e.lim
}

func (l *keyedRateLimiter) sweepLocked(now time.Time) {
	l.lastSweep = now
	for k, e := range l.entries {
		if now.Sub(e.lastSeen) >= limiterIdleTTL {
			delete(l.entries, k)
		}
	}
}

func (l *keyedRateLimiter) evictOldestLocked() {
	var oldestKey string
	var oldest time.Time
	first := true
	for k, e := range l.entries {
		if first || e.lastSeen.Before(oldest) {
			oldestKey, oldest, first = k, e.lastSeen, false
		}
	}
	if !first {
		delete(l.entries, oldestKey)
	}
}

// len reports the number of tracked keys.
func (l *keyedRateLimiter) len() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.entries)
}
```

Update the `Middleware` comment about the vault limiter ("entries are never evicted") to say the shared limiter now evicts idle entries but its keyspace is bounded by vault count anyway.
- [ ] **Step 4: Run** `go test -race ./internal/middleware/ -v`. Expected: PASS including `vault_rate_limit_test.go` and the existing rate-limit tests.
- [ ] **Step 5: Commit** via the `dev-workflow-skills:1-git-commit` skill.

---

### Task 4: Per-account failed-login backoff

**Files**:
- Create: `model/login_failure.go`
- Create: `internal/repositories/login_failure_repository.go`, `internal/repositories/login_failure_repository_test.go`
- Modify: `internal/db/db.go` (initial schema block near the `oauth2_clients` table ~line 740; `migrateSchema` statement list near `vault_provisioning_grants` ~line 893)
- Create: `internal/services/auth/login_throttle.go`, `internal/services/auth/login_throttle_test.go`
- Modify: `internal/services/auth/authentication_service.go` (`authenticationService` struct, `AuthenticationConfig` lines 74-83, constructor lines 95-105, `AuthenticateUser` lines ~126-200)
- Modify: `internal/container/service_container.go` (~lines 467-485, construct repo and throttle)
- Modify: `api/users.go` (`loginUser` error branch ~lines 412-416)
- Modify: `cmd/users/login.go` (no code change expected; add test only)
- Test: `internal/services/auth/authentication_service_throttle_test.go`, `api/users_test.go`, `cmd/users/login_password_test.go`

**Interfaces**:
- Consumes: `db.DB`, `repositories.ErrNotFound` (`internal/repositories/errors.go:12`), `AuthenticationConfig`, existing mocks `MockUserRepository`, `MockSessionRepository`, `MockPasswordService`, `MockTOTPService`, `MockJWTService` in `authentication_service_test.go`.
- Produces:
  - `model.LoginFailure{Username string; Failures int; LastFailureAt time.Time}`
  - `repositories.LoginFailureRepositoryInterface { Get(ctx, username string) (*model.LoginFailure, error); RecordFailure(ctx, username string, at time.Time) error; Delete(ctx, username string) error; DeleteOlderThan(ctx, cutoff time.Time) (int64, error) }`; `repositories.NewLoginFailureRepository(db db.DB)`.
  - `auth.ErrLoginThrottled`, `auth.ThrottledError{RetryAfter time.Duration}` (`errors.Is(err, ErrLoginThrottled)`), `auth.NewLoginThrottle(repo, now func() time.Time) *LoginThrottle`, methods `Check(ctx, username) error`, `RecordFailure(ctx, username)`, `Reset(ctx, username)`, function `loginDelay(failures int) time.Duration`.
  - `AuthenticationConfig.LoginThrottle *LoginThrottle` (optional; nil disables throttling so existing tests and callers are unchanged).

Design and thresholds. The counter lives in the database, not in process memory, so it holds across restarts, across several server instances sharing Postgres, and across the CLI, which opens the database directly. It is keyed by lower-cased username (capped at 64 chars) and is recorded for unknown usernames too, so a throttled response cannot be used to tell whether an account exists. Policy: the first 5 consecutive failures are free (typos, a stale TOTP), failure number `f > 5` imposes a wait of `2s * 2^(f-6)` counted from the last failure, capped at 15 minutes. It is a delay, never a hard lock: an attacker who hammers an admin's name delays it at most 15 minutes at a time, and the admin gets in the moment the window passes. Attempts made inside the window are refused without incrementing the counter, so an attacker cannot push the window out by hammering. A success deletes the row. A row whose last failure is older than 24 hours is treated as zero. At 15 minutes per guess an attacker gets about 96 guesses per account per day, and each guess also needs a valid TOTP code.

- [ ] **Step 1: Failing repository test** `internal/repositories/login_failure_repository_test.go` (follows `oauth2_client_repository_test.go`'s in-memory SQLite setup, which wraps the `*sql.DB` with `rvdb.NewConn(db, rvdb.SQLite)`, `internal/db/conn.go:29`):

```go
package repositories_test

import (
	"context"
	"database/sql"
	"testing"
	"time"

	_ "github.com/mattn/go-sqlite3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	rvdb "rocketvault/internal/db"
	"rocketvault/internal/repositories"
)

func setupLoginFailureDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite3", ":memory:")
	require.NoError(t, err)
	_, err = db.Exec(`CREATE TABLE login_failures (
		username        TEXT PRIMARY KEY,
		failures        INTEGER NOT NULL,
		last_failure_at TIMESTAMP NOT NULL
	)`)
	require.NoError(t, err)
	t.Cleanup(func() { db.Close() })
	return db
}

func TestLoginFailureRepository_RecordGetDelete(t *testing.T) {
	sqlDB := setupLoginFailureDB(t)
	repo := repositories.NewLoginFailureRepository(rvdb.NewConn(sqlDB, rvdb.SQLite))
	ctx := context.Background()
	t0 := time.Now().UTC().Truncate(time.Second)

	_, err := repo.Get(ctx, "alice")
	assert.ErrorIs(t, err, repositories.ErrNotFound)

	require.NoError(t, repo.RecordFailure(ctx, "alice", t0))
	require.NoError(t, repo.RecordFailure(ctx, "alice", t0.Add(time.Second)))
	got, err := repo.Get(ctx, "alice")
	require.NoError(t, err)
	assert.Equal(t, 2, got.Failures)
	assert.True(t, got.LastFailureAt.Equal(t0.Add(time.Second)))

	require.NoError(t, repo.Delete(ctx, "alice"))
	_, err = repo.Get(ctx, "alice")
	assert.ErrorIs(t, err, repositories.ErrNotFound)
}

func TestLoginFailureRepository_DeleteOlderThan(t *testing.T) {
	sqlDB := setupLoginFailureDB(t)
	repo := repositories.NewLoginFailureRepository(rvdb.NewConn(sqlDB, rvdb.SQLite))
	ctx := context.Background()
	now := time.Now().UTC()
	require.NoError(t, repo.RecordFailure(ctx, "old", now.Add(-48*time.Hour)))
	require.NoError(t, repo.RecordFailure(ctx, "new", now))

	n, err := repo.DeleteOlderThan(ctx, now.Add(-24*time.Hour))
	require.NoError(t, err)
	assert.EqualValues(t, 1, n)
	_, err = repo.Get(ctx, "new")
	assert.NoError(t, err)
}
```

`*rvdb.Conn` satisfies `db.DB`, exactly as in `oauth2_client_repository_test.go` (`repositories.NewOAuth2ClientRepository(rvdb.NewConn(db, rvdb.SQLite))`).
- [ ] **Step 2: Run** `go test ./internal/repositories/ -run TestLoginFailureRepository -v`. Expected: FAIL, `undefined: repositories.NewLoginFailureRepository`.
- [ ] **Step 3: Implement** `model/login_failure.go`:

```go
package model

import "time"

// LoginFailure counts consecutive failed logins for one username.
type LoginFailure struct {
	Username      string
	Failures      int
	LastFailureAt time.Time
}
```

and `internal/repositories/login_failure_repository.go`:

```go
package repositories

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"rocketvault/internal/db"
	"rocketvault/model"
)

// LoginFailureRepositoryInterface defines CRUD for failed-login counters.
// Repositories handle only data access; the backoff policy lives in the
// auth service layer.
type LoginFailureRepositoryInterface interface {
	Get(ctx context.Context, username string) (*model.LoginFailure, error)
	// RecordFailure atomically increments the counter and stamps the time.
	RecordFailure(ctx context.Context, username string, at time.Time) error
	Delete(ctx context.Context, username string) error
	// DeleteOlderThan removes rows whose last failure predates cutoff.
	DeleteOlderThan(ctx context.Context, cutoff time.Time) (int64, error)
}

type loginFailureRepository struct {
	db db.DB
}

// NewLoginFailureRepository creates a LoginFailureRepositoryInterface backed by db.
func NewLoginFailureRepository(db db.DB) LoginFailureRepositoryInterface {
	return &loginFailureRepository{db: db}
}

func (r *loginFailureRepository) Get(ctx context.Context, username string) (*model.LoginFailure, error) {
	var f model.LoginFailure
	err := r.db.QueryRowContext(ctx,
		`SELECT username, failures, last_failure_at FROM login_failures WHERE username = ?`, username,
	).Scan(&f.Username, &f.Failures, &f.LastFailureAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("loginFailureRepository.Get: %w", ErrNotFound)
	}
	if err != nil {
		return nil, fmt.Errorf("loginFailureRepository.Get: %w", err)
	}
	return &f, nil
}

func (r *loginFailureRepository) RecordFailure(ctx context.Context, username string, at time.Time) error {
	_, err := r.db.ExecContext(ctx,
		`INSERT INTO login_failures (username, failures, last_failure_at) VALUES (?, 1, ?)
		 ON CONFLICT(username) DO UPDATE SET failures = login_failures.failures + 1, last_failure_at = excluded.last_failure_at`,
		username, at)
	if err != nil {
		return fmt.Errorf("loginFailureRepository.RecordFailure: %w", err)
	}
	return nil
}

func (r *loginFailureRepository) Delete(ctx context.Context, username string) error {
	if _, err := r.db.ExecContext(ctx, `DELETE FROM login_failures WHERE username = ?`, username); err != nil {
		return fmt.Errorf("loginFailureRepository.Delete: %w", err)
	}
	return nil
}

func (r *loginFailureRepository) DeleteOlderThan(ctx context.Context, cutoff time.Time) (int64, error) {
	res, err := r.db.ExecContext(ctx, `DELETE FROM login_failures WHERE last_failure_at < ?`, cutoff)
	if err != nil {
		return 0, fmt.Errorf("loginFailureRepository.DeleteOlderThan: %w", err)
	}
	return res.RowsAffected()
}
```

In `internal/db/db.go` add to the initial schema block right after the `oauth2_clients` index line:

```sql
		CREATE TABLE IF NOT EXISTS login_failures (
			username        TEXT PRIMARY KEY,
			failures        INTEGER NOT NULL,
			last_failure_at TIMESTAMP NOT NULL
		);
```

and to `migrateSchema`'s statement list after the `vault_provisioning_grants` entry:

```go
		// Feature: per-account failed-login backoff (idempotent; the table did
		// not exist before this migration on any pre-existing database).
		`CREATE TABLE IF NOT EXISTS login_failures (
			username        TEXT PRIMARY KEY,
			failures        INTEGER NOT NULL,
			last_failure_at TIMESTAMP NOT NULL
		)`,
```

- [ ] **Step 4: Run** `go test ./internal/repositories/ ./internal/db/ -v -run 'LoginFailure|Migrate|Schema'`. Expected: PASS. Then add a migration assertion: find the existing db test that checks a table exists after `migrateSchema` (grep `vault_provisioning_grants` in `internal/db/*_test.go`) and add `login_failures` to it in the same style.
- [ ] **Step 5: Commit** via the `dev-workflow-skills:1-git-commit` skill (repo and schema).
- [ ] **Step 6: Failing throttle tests** `internal/services/auth/login_throttle_test.go`, with an in-memory fake repo:

```go
package auth

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"rocketvault/internal/repositories"
	"rocketvault/model"
)

type fakeFailureRepo struct {
	mu   sync.Mutex
	rows map[string]*model.LoginFailure
}

func newFakeFailureRepo() *fakeFailureRepo {
	return &fakeFailureRepo{rows: map[string]*model.LoginFailure{}}
}
func (f *fakeFailureRepo) Get(_ context.Context, u string) (*model.LoginFailure, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if r, ok := f.rows[u]; ok {
		c := *r
		return &c, nil
	}
	return nil, repositories.ErrNotFound
}
func (f *fakeFailureRepo) RecordFailure(_ context.Context, u string, at time.Time) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if r, ok := f.rows[u]; ok {
		r.Failures++
		r.LastFailureAt = at
		return nil
	}
	f.rows[u] = &model.LoginFailure{Username: u, Failures: 1, LastFailureAt: at}
	return nil
}
func (f *fakeFailureRepo) Delete(_ context.Context, u string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.rows, u)
	return nil
}
func (f *fakeFailureRepo) DeleteOlderThan(_ context.Context, cutoff time.Time) (int64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var n int64
	for k, r := range f.rows {
		if r.LastFailureAt.Before(cutoff) {
			delete(f.rows, k)
			n++
		}
	}
	return n, nil
}

type throttleClock struct{ t time.Time }

func (c *throttleClock) now() time.Time { return c.t }

func TestLoginDelay(t *testing.T) {
	t.Parallel()
	assert.Equal(t, time.Duration(0), loginDelay(5))
	assert.Equal(t, 2*time.Second, loginDelay(6))
	assert.Equal(t, 4*time.Second, loginDelay(7))
	assert.Equal(t, 15*time.Minute, loginDelay(15))
	assert.Equal(t, 15*time.Minute, loginDelay(10_000), "no shift overflow at huge counts")
}

func TestLoginThrottle_FreeAttemptsThenBackoff(t *testing.T) {
	t.Parallel()
	clk := &throttleClock{t: time.Unix(1_700_000_000, 0)}
	th := NewLoginThrottle(newFakeFailureRepo(), clk.now)
	ctx := context.Background()

	for i := 0; i < 5; i++ {
		require.NoError(t, th.Check(ctx, "Alice"))
		th.RecordFailure(ctx, "Alice")
	}
	err := th.Check(ctx, "alice") // Case-insensitive key; 5 failures are still free.
	require.NoError(t, err)

	th.RecordFailure(ctx, "alice") // Sixth failure: 2s wait.
	err = th.Check(ctx, "alice")
	require.ErrorIs(t, err, ErrLoginThrottled)
	var te *ThrottledError
	require.True(t, errors.As(err, &te))
	assert.Equal(t, 2*time.Second, te.RetryAfter)

	clk.t = clk.t.Add(2 * time.Second)
	assert.NoError(t, th.Check(ctx, "alice"), "the throttle is a delay, not a lock")
}

func TestLoginThrottle_AttemptsDuringWindowDoNotGrowCounter(t *testing.T) {
	t.Parallel()
	clk := &throttleClock{t: time.Unix(1_700_000_000, 0)}
	repo := newFakeFailureRepo()
	th := NewLoginThrottle(repo, clk.now)
	ctx := context.Background()
	for i := 0; i < 6; i++ {
		th.RecordFailure(ctx, "admin")
	}
	for i := 0; i < 100; i++ {
		require.ErrorIs(t, th.Check(ctx, "admin"), ErrLoginThrottled)
	}
	row, err := repo.Get(ctx, "admin")
	require.NoError(t, err)
	assert.Equal(t, 6, row.Failures, "Check must never write")
}

func TestLoginThrottle_StaleCounterIsIgnoredAndResetClears(t *testing.T) {
	t.Parallel()
	clk := &throttleClock{t: time.Unix(1_700_000_000, 0)}
	repo := newFakeFailureRepo()
	th := NewLoginThrottle(repo, clk.now)
	ctx := context.Background()
	for i := 0; i < 8; i++ {
		th.RecordFailure(ctx, "bob")
	}
	clk.t = clk.t.Add(25 * time.Hour)
	assert.NoError(t, th.Check(ctx, "bob"))
	th.RecordFailure(ctx, "bob") // A stale row restarts at 1, not 9.
	row, _ := repo.Get(ctx, "bob")
	assert.Equal(t, 1, row.Failures)

	th.Reset(ctx, "bob")
	_, err := repo.Get(ctx, "bob")
	assert.ErrorIs(t, err, repositories.ErrNotFound)
}

func TestLoginThrottle_LongUsernameIsCapped(t *testing.T) {
	t.Parallel()
	repo := newFakeFailureRepo()
	th := NewLoginThrottle(repo, time.Now)
	th.RecordFailure(context.Background(), strings.Repeat("x", 500))
	for k := range repo.rows {
		assert.LessOrEqual(t, len(k), 64)
	}
}
```

- [ ] **Step 7: Run** `go test ./internal/services/auth/ -run 'TestLoginDelay|TestLoginThrottle' -v`. Expected: FAIL, `undefined: loginDelay`.
- [ ] **Step 8: Implement** `internal/services/auth/login_throttle.go`:

```go
package auth

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/sirupsen/logrus"

	"rocketvault/internal/repositories"
)

const (
	// loginFreeAttempts failures are tolerated before any wait is imposed.
	loginFreeAttempts = 5
	// loginBaseDelay is the wait after the first failure past the free ones.
	loginBaseDelay = 2 * time.Second
	// loginMaxDelay caps the wait so an attacker can never lock an account out
	// for longer than this at a time.
	loginMaxDelay = 15 * time.Minute
	// loginResetAfter forgets a counter whose last failure is this old.
	loginResetAfter = 24 * time.Hour
	// maxThrottleKeyLen bounds stored usernames so spraying long names cannot
	// grow rows without limit.
	maxThrottleKeyLen = 64
)

// ErrLoginThrottled is returned when an account is inside its backoff window.
var ErrLoginThrottled = errors.New("too many failed login attempts")

// ThrottledError carries how long the caller must wait.
type ThrottledError struct {
	RetryAfter time.Duration
}

func (e *ThrottledError) Error() string {
	return fmt.Sprintf("%s; retry in %s", ErrLoginThrottled, e.RetryAfter.Round(time.Second))
}

// Is lets errors.Is(err, ErrLoginThrottled) match.
func (e *ThrottledError) Is(target error) bool { return target == ErrLoginThrottled }

// loginDelay returns the wait imposed after the given number of consecutive failures.
func loginDelay(failures int) time.Duration {
	over := failures - loginFreeAttempts
	if over <= 0 {
		return 0
	}
	// 2s << 10 already exceeds the cap; bail out before the shift can overflow.
	if over > 10 {
		return loginMaxDelay
	}
	d := loginBaseDelay << (over - 1)
	if d > loginMaxDelay {
		return loginMaxDelay
	}
	return d
}

// LoginThrottle applies exponential backoff to repeated failed logins per
// account. It is a delay, never a permanent lock.
type LoginThrottle struct {
	repo repositories.LoginFailureRepositoryInterface
	now  func() time.Time
}

// NewLoginThrottle builds a throttle; now is injectable for tests.
func NewLoginThrottle(repo repositories.LoginFailureRepositoryInterface, now func() time.Time) *LoginThrottle {
	if now == nil {
		now = time.Now
	}
	return &LoginThrottle{repo: repo, now: now}
}

func throttleKey(username string) string {
	k := strings.ToLower(strings.TrimSpace(username))
	if len(k) > maxThrottleKeyLen {
		k = k[:maxThrottleKeyLen]
	}
	return k
}

// Check returns a *ThrottledError while the account is inside its window.
// It never writes, so attempts made during the window cannot extend it.
// A storage error fails open: the per-IP limiter still applies.
func (t *LoginThrottle) Check(ctx context.Context, username string) error {
	row, err := t.repo.Get(ctx, throttleKey(username))
	if err != nil {
		if !errors.Is(err, repositories.ErrNotFound) {
			logrus.WithError(err).Warn("login throttle lookup failed")
		}
		return nil
	}
	if t.now().Sub(row.LastFailureAt) >= loginResetAfter {
		return nil
	}
	wait := row.LastFailureAt.Add(loginDelay(row.Failures)).Sub(t.now())
	if wait > 0 {
		return &ThrottledError{RetryAfter: wait}
	}
	return nil
}

// RecordFailure counts one failed attempt. It also prunes rows past the
// reset age, which keeps the table bounded under username spraying.
func (t *LoginThrottle) RecordFailure(ctx context.Context, username string) {
	key := throttleKey(username)
	now := t.now()
	if row, err := t.repo.Get(ctx, key); err == nil && now.Sub(row.LastFailureAt) >= loginResetAfter {
		_ = t.repo.Delete(ctx, key)
	}
	if err := t.repo.RecordFailure(ctx, key, now); err != nil {
		logrus.WithError(err).Warn("recording login failure failed")
		return
	}
	_, _ = t.repo.DeleteOlderThan(ctx, now.Add(-loginResetAfter))
}

// Reset clears the counter after a successful login.
func (t *LoginThrottle) Reset(ctx context.Context, username string) {
	if err := t.repo.Delete(ctx, throttleKey(username)); err != nil {
		logrus.WithError(err).Warn("clearing login failures failed")
	}
}
```

- [ ] **Step 9: Run** `go test ./internal/services/auth/ -run 'TestLoginDelay|TestLoginThrottle' -v`. Expected: PASS.
- [ ] **Step 10: Failing integration tests** in `internal/services/auth/authentication_service_throttle_test.go`. The mocks (`MockUserRepository`, `MockSessionRepository`, `MockPasswordService`, `MockTOTPService`, `MockJWTService`) live in `authentication_service_test.go`, and the logger is `logging.InitLogger()` (the same call `TestAuthenticationService_AuthenticateUser_Success` uses). The existing `newAuthService` helper takes six positional arguments and cannot set `LoginThrottle`, so these tests build `AuthenticationConfig` directly. The file needs these imports: `context`, `errors`, `testing`, `time`, `github.com/google/uuid`, `github.com/stretchr/testify/assert`, `github.com/stretchr/testify/mock`, `github.com/stretchr/testify/require`, `rocketvault/internal/logging`, `rocketvault/internal/repositories`, `rocketvault/model`. Write:

```go
func newThrottledService(t *testing.T, users *MockUserRepository, pw *MockPasswordService, th *LoginThrottle) AuthenticationService {
	t.Helper()
	return NewAuthenticationService(AuthenticationConfig{
		UserRepository:    users,
		SessionRepository: &MockSessionRepository{},
		PasswordService:   pw,
		TOTPService:       &MockTOTPService{},
		JWTService:        &MockJWTService{},
		Logger:            logging.InitLogger(),
		LoginThrottle:     th,
	})
}

func TestAuthenticateUser_ThrottledAfterRepeatedWrongPasswords(t *testing.T) {
	ctx := context.Background()
	clk := &throttleClock{t: time.Unix(1_700_000_000, 0)}
	th := NewLoginThrottle(newFakeFailureRepo(), clk.now)
	users := &MockUserRepository{}
	pw := &MockPasswordService{}
	user := model.User{ID: uuid.New(), Username: "alice", PasswordHash: "h", TOTPSecret: "s"}
	users.On("ReadByUsername", ctx, "alice").Return(user, nil)
	pw.On("ValidatePassword", "wrong", "h").Return(errors.New("bad"))
	svc := newThrottledService(t, users, pw, th)

	for i := 0; i < 6; i++ {
		_, err := svc.AuthenticateUser(ctx, "alice", "wrong", "123456")
		require.Error(t, err)
		require.NotErrorIs(t, err, ErrLoginThrottled)
	}
	_, err := svc.AuthenticateUser(ctx, "alice", "wrong", "123456")
	require.ErrorIs(t, err, ErrLoginThrottled)
	// The throttled attempt never reached the password check.
	pw.AssertNumberOfCalls(t, "ValidatePassword", 6)
}

func TestAuthenticateUser_UnknownUserIsThrottledLikeKnownUser(t *testing.T) {
	ctx := context.Background()
	clk := &throttleClock{t: time.Unix(1_700_000_000, 0)}
	th := NewLoginThrottle(newFakeFailureRepo(), clk.now)
	users := &MockUserRepository{}
	users.On("ReadByUsername", ctx, "ghost").Return(model.User{}, errors.New("not found"))
	svc := newThrottledService(t, users, &MockPasswordService{}, th)

	for i := 0; i < 6; i++ {
		_, err := svc.AuthenticateUser(ctx, "ghost", "x", "123456")
		require.Error(t, err)
	}
	_, err := svc.AuthenticateUser(ctx, "ghost", "x", "123456")
	require.ErrorIs(t, err, ErrLoginThrottled, "a missing account must throttle too, or the response leaks existence")
}

func TestAuthenticateUser_SuccessResetsThrottle(t *testing.T) {
	ctx := context.Background()
	clk := &throttleClock{t: time.Unix(1_700_000_000, 0)}
	repo := newFakeFailureRepo()
	th := NewLoginThrottle(repo, clk.now)
	for i := 0; i < 6; i++ {
		th.RecordFailure(ctx, "alice")
	}
	clk.t = clk.t.Add(time.Minute) // Past the 2s window.

	svc := buildSuccessService(t, th)
	_, err := svc.AuthenticateUser(ctx, "alice", "password123", "123456")
	require.NoError(t, err)
	_, getErr := repo.Get(ctx, "alice")
	assert.ErrorIs(t, getErr, repositories.ErrNotFound)
}

// buildSuccessService wires mocks for a fully successful login of "alice".
// It assumes the identity plan has landed, so TOTP goes through
// ValidateCodeWithStep and ClaimTOTPStep (see the prerequisite note).
func buildSuccessService(t *testing.T, th *LoginThrottle) AuthenticationService {
	t.Helper()
	ctx := context.Background()
	user := model.User{
		ID: uuid.New(), Username: "alice", PasswordHash: "hashed",
		TOTPSecret: "secret123", Roles: []string{model.RoleUser},
	}
	users := &MockUserRepository{}
	sessions := &MockSessionRepository{}
	pw := &MockPasswordService{}
	totp := &MockTOTPService{}
	jwt := &MockJWTService{}
	steps := &MockTOTPStepRepository{}

	users.On("ReadByUsername", ctx, "alice").Return(user, nil)
	pw.On("ValidatePassword", "password123", "hashed").Return(nil)
	totp.On("ValidateCodeWithStep", "123456", "secret123", mock.AnythingOfType("time.Time")).Return(int64(100), true, nil)
	steps.On("ClaimTOTPStep", mock.Anything, user.ID, int64(100)).Return(true, nil)
	sessions.On("CreateSession", ctx, mock.AnythingOfType("*model.Session")).Return(nil)
	jwt.On("GenerateToken", user.ID, "alice", user.Roles, mock.AnythingOfType("uuid.UUID")).Return("jwt_token", nil)

	return NewAuthenticationService(AuthenticationConfig{
		UserRepository:     users,
		SessionRepository:  sessions,
		PasswordService:    pw,
		TOTPService:        totp,
		JWTService:         jwt,
		TOTPStepRepository: steps,
		Logger:             logging.InitLogger(),
		LoginThrottle:      th,
	})
}
```

`MockTOTPStepRepository` is defined in `totp_replay_test.go` by the identity plan (same package). Before that plan lands, use `totp.On("ValidateCode", "123456", "secret123", mock.AnythingOfType("time.Time")).Return(true, nil)` and drop the `steps` lines and the `TOTPStepRepository` field.
- [ ] **Step 11: Run** `go test ./internal/services/auth/ -run 'TestAuthenticateUser_(Throttled|UnknownUser|SuccessResets)' -v`. Expected: FAIL (`unknown field LoginThrottle`).
- [ ] **Step 12: Implement in `authentication_service.go`.** Add `LoginThrottle *LoginThrottle` to `AuthenticationConfig` and a `throttle *LoginThrottle` field to `authenticationService`, set in the constructor. At the top of `AuthenticateUser`, right after the "Starting user authentication" log:

```go
	if s.throttle != nil {
		if err := s.throttle.Check(ctx, username); err != nil {
			s.logger.WithField("username", username).Warn("Authentication refused: account in backoff window")
			return nil, err
		}
	}
```

Add a small helper:

```go
// recordLoginFailure counts a failed attempt against the username.
func (s *authenticationService) recordLoginFailure(ctx context.Context, username string) {
	if s.throttle != nil {
		s.throttle.RecordFailure(ctx, username)
	}
}
```

and call it in the user-not-found branch, the invalid-password branch, the TOTP-error branch and the `!valid` TOTP branch (just before each `return nil, ...`). After the TOTP check passes (immediately before session creation, and after the replay claim when the identity plan has landed), add `if s.throttle != nil { s.throttle.Reset(ctx, username) }`.

Task 4 is the only task that records failures in the user-not-found branch. Task 5 adds only `common.BurnPasswordCompare` there, so an unknown-user attempt counts once.

**Step 12a (only if the identity plan has landed): empty TOTP secret exit.** In the `if user.TOTPSecret == "" { ... }` block the identity plan added after the password check, add the call directly before the final return, so the block ends:

```go
		s.recordLoginFailure(ctx, username)
		return nil, fmt.Errorf("authentication failed: %w", ErrMFANotEnrolled)
```

**Step 12b (only if the identity plan has landed): replayed TOTP step exit.** In the `if !claimed { ... }` block, add the call directly before the final return, so the block ends:

```go
		s.recordLoginFailure(ctx, username)
		return nil, fmt.Errorf("invalid TOTP code")
```

The claim-error branch (`TOTP step claim error`) and the nil `totpStepRepo` branch are server faults, not bad credentials, so they do not count. The `Reset` call from step 12 must sit after the `!claimed` block, so a replayed code never clears the counter.

Add these tests to `authentication_service_throttle_test.go` (same imports, plus `rocketvault/internal/repositories` already listed):

```go
func TestAuthenticateUser_EmptyTOTPSecretCountsAsFailure(t *testing.T) {
	ctx := context.Background()
	clk := &throttleClock{t: time.Unix(1_700_000_000, 0)}
	repo := newFakeFailureRepo()
	th := NewLoginThrottle(repo, clk.now)
	users := &MockUserRepository{}
	pw := &MockPasswordService{}
	user := model.User{ID: uuid.New(), Username: "oidc", PasswordHash: "h", TOTPSecret: ""}
	users.On("ReadByUsername", ctx, "oidc").Return(user, nil)
	pw.On("ValidatePassword", "pw", "h").Return(nil)
	svc := newThrottledService(t, users, pw, th)

	_, err := svc.AuthenticateUser(ctx, "oidc", "pw", "123456")

	require.ErrorIs(t, err, ErrMFANotEnrolled)
	row, getErr := repo.Get(ctx, "oidc")
	require.NoError(t, getErr)
	assert.Equal(t, 1, row.Failures)
}

func TestAuthenticateUser_ReplayedStepCountsAsFailureAndKeepsCounter(t *testing.T) {
	ctx := context.Background()
	clk := &throttleClock{t: time.Unix(1_700_000_000, 0)}
	repo := newFakeFailureRepo()
	th := NewLoginThrottle(repo, clk.now)
	users := &MockUserRepository{}
	pw := &MockPasswordService{}
	totp := &MockTOTPService{}
	steps := &MockTOTPStepRepository{}
	user := model.User{ID: uuid.New(), Username: "replay", PasswordHash: "h", TOTPSecret: "s", Roles: []string{model.RoleUser}}
	users.On("ReadByUsername", ctx, "replay").Return(user, nil)
	pw.On("ValidatePassword", "pw", "h").Return(nil)
	totp.On("ValidateCodeWithStep", "123456", "s", mock.AnythingOfType("time.Time")).Return(int64(100), true, nil)
	steps.On("ClaimTOTPStep", mock.Anything, user.ID, int64(100)).Return(false, nil)
	svc := NewAuthenticationService(AuthenticationConfig{
		UserRepository: users, SessionRepository: &MockSessionRepository{}, PasswordService: pw,
		TOTPService: totp, JWTService: &MockJWTService{}, TOTPStepRepository: steps,
		Logger: logging.InitLogger(), LoginThrottle: th,
	})

	_, err := svc.AuthenticateUser(ctx, "replay", "pw", "123456")

	require.Error(t, err)
	row, getErr := repo.Get(ctx, "replay")
	require.NoError(t, getErr, "a replay must not reset the counter and must record a failure")
	assert.Equal(t, 1, row.Failures)
}
```
- [ ] **Step 13: Wire the container.** In `service_container.go` just before `baseAuthService := ...` (~line 475) add:

```go
	loginThrottle := authServices.NewLoginThrottle(repositories.NewLoginFailureRepository(c.conn), time.Now)
```

and add `LoginThrottle: loginThrottle,` to the `AuthenticationConfig` literal. (`time` is already imported there; confirm with `go build ./...`.)
- [ ] **Step 14: Run** `go test ./internal/services/auth/ ./internal/container/ -v`. Expected: PASS (existing tests leave `LoginThrottle` nil).

  **Retry wrapper note.** The container wraps `AuthenticateUser` in `retryAuthenticationService` (`internal/services/retry/retry_auth_service.go:32`), which runs it through `retried` and `WithExponentialBackoff` (`internal/retry/retry.go`). This is safe for the throttle: a `*ThrottledError` is not retryable (its text, `too many failed login attempts; retry in ...`, matches none of the `RetryableErrors` patterns `connection refused`, `timeout`, `temporary failure`), so it is returned on the first attempt, never re-run against the counter. Both the non-retryable and the max-retries branches wrap with `%w`, so `errors.As(err, &*ThrottledError)`, `errors.Is(err, ErrLoginThrottled)` and the `retry in ...` wait text still reach `api/users.go` and the CLI. Throttled and failed logins count toward circuit-breaker failures exactly as wrong passwords already do today; this plan adds no new breaker behaviour. Pin it with a test appended to `internal/services/retry/retry_wrappers_test.go`, which uses a real `RetryService` so the wrapping path actually runs:

  ```go
  func TestRetryAuth_AuthenticateUser_ThrottledErrorSurvivesWrapping(t *testing.T) {
  	v := viper.New()
  	v.Set("retry.database.enabled", true)
  	v.Set("retry.database.max_attempts", 3)
  	v.Set("retry.database.initial_delay", "1ms")
  	v.Set("retry.database.max_delay", "1ms")
  	v.Set("retry.database.backoff_multiplier", 1.0)
  	v.Set("retry.circuit_breaker.failure_threshold", 5)
  	v.Set("retry.circuit_breaker.timeout", "60s")
  	v.Set("retry.circuit_breaker.half_open_requests", 3)
  	rs, err := NewRetryService(v)
  	assert.NoError(t, err)

  	base := &MockAuthService{}
  	base.On("AuthenticateUser", mock.Anything, "alice", "wrong", "123456").
  		Return(nil, &auth.ThrottledError{RetryAfter: 37 * time.Second})

  	svc := NewRetryAuthenticationService(base, rs)
  	result, err := svc.AuthenticateUser(ctx, "alice", "wrong", "123456")

  	assert.Nil(t, result)
  	var te *auth.ThrottledError
  	assert.True(t, errors.As(err, &te), "errors.As must see the typed error through the retry wrapper")
  	assert.Equal(t, 37*time.Second, te.RetryAfter)
  	assert.ErrorIs(t, err, auth.ErrLoginThrottled)
  	assert.Contains(t, err.Error(), "retry in 37s")
  	base.AssertNumberOfCalls(t, "AuthenticateUser", 1) // Not retried.
  }
  ```

  Run `go test ./internal/services/retry/ -run TestRetryAuth_AuthenticateUser_Throttled -v`. Expected: PASS without code change. If it fails, the retry layer stopped wrapping with `%w` and Task 4's HTTP 429 mapping would silently degrade to 403.
- [ ] **Step 15: HTTP path: failing test** in `api/users_test.go` next to `TestLoginUser_AuthFailure_Returns403`:

```go
func TestLoginUser_Throttled_Returns429WithRetryAfter(t *testing.T) {
	authSvc := &mockAuthService{}
	authSvc.On("AuthenticateUser", mock.Anything, "alice", "wrong", "123456").
		Return(nil, &authServices.ThrottledError{RetryAfter: 37 * time.Second})

	c := newUserCtx(nil, authSvc, RequestClaims{})
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/users/login", encodeBody(map[string]string{
		"username": "alice", "password": "wrong", "totp_code": "123456",
	}))

	loginUser(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusTooManyRequests, w.Code)
	assert.Equal(t, "37", w.Header().Get("Retry-After"))
}
```

Run `go test ./api/ -run TestLoginUser_Throttled -v`. Expected FAIL (403 returned).
- [ ] **Step 16: Implement** in `api/users.go` `loginUser` error branch, before the existing `c.SetPermissionError`:

```go
		var throttled *authServices.ThrottledError
		if errors.As(err, &throttled) {
			secs := int(math.Ceil(throttled.RetryAfter.Seconds()))
			w.Header().Set("Retry-After", strconv.Itoa(secs))
			c.Err = common.NewAppError("api.login.throttled",
				"Too many failed login attempts", nil, "", http.StatusTooManyRequests)
			return
		}
```

`api/users.go` currently imports only `net/http`, `strings`, `time`, `github.com/google/uuid`, `rocketvault/common`, `rocketvault/internal/container`, `userService "rocketvault/internal/services/users"` and `rocketvault/model`. Change the import block to (the identity plan's Task 2 may already have added `errors` and the `authServices` alias; keep one copy of each):

```go
import (
	"errors"
	"math"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"

	"rocketvault/common"
	"rocketvault/internal/container"
	authServices "rocketvault/internal/services/auth"
	userService "rocketvault/internal/services/users"
	"rocketvault/model"
)
```

`api/users_test.go` already imports `authServices` and `time`; add them there only if the build says otherwise.
- [ ] **Step 17: Run** `go test ./api/ -run TestLoginUser -v`. Expected: PASS.
- [ ] **Step 18: CLI path test** appended to `cmd/users/login_password_test.go`:

```go
func TestPerformPasswordLogin_Throttled_SurfacesRetryHint(t *testing.T) {
	common.SessionBaseDir = t.TempDir()
	tc := testutils.NewTestContext(t)
	tc.MockAuthService.On("AuthenticateUser", mock.Anything, "admin", "wrong", "123456").
		Return(nil, &authServices.ThrottledError{RetryAfter: 90 * time.Second})

	_, err := performPasswordLogin(context.Background(), tc.MockAuthService, "admin", "wrong", "123456")

	require.Error(t, err)
	assert.ErrorIs(t, err, authServices.ErrLoginThrottled)
	assert.Contains(t, err.Error(), "retry in 1m30s")
	cached, loadErr := common.LoadSession("admin")
	require.NoError(t, loadErr)
	assert.Nil(t, cached)
}
```

Run `go test ./cmd/users/ -run TestPerformPasswordLogin -v`. Expected: PASS without code change (the error is returned unwrapped). Add the same style assertion for `cmd/root.go`'s `resolveAuthentication` if a test helper for it exists (`grep -n resolveAuthentication cmd/*_test.go`); otherwise note it is covered by the service-level tests. For the remote CLI mode (`internal/vaultapi/login.go:96-99`) the error is `vaultapi: login failed (HTTP 429)`; add a test in `internal/vaultapi/login_test.go` modelled on `TestClientLogin_RejectionDoesNotEchoBody` (line 61) that serves 429 and asserts the error contains `HTTP 429`, to pin that the CLI remote path reports throttling rather than a generic failure.
- [ ] **Step 19: Commit** via the `dev-workflow-skills:1-git-commit` skill (service, wiring, handler, tests).

---

### Task 5: Constant-time handling of unknown users and clients

**Files**:
- Modify: `common/encrypt.go` (append after `HashString`, ~line 30)
- Test: `common/encrypt_test.go`
- Modify: `internal/services/auth/authentication_service.go` (user-not-found branch ~lines 126-136)
- Modify: `internal/services/oauth2/oauth2_service.go` (`IssueToken` lines ~85-110)
- Test: `internal/services/auth/authentication_service_critical_test.go` (`TestAuthenticateUser_UserNotFound`, line 42), `internal/services/oauth2/oauth2_service_test.go`

**Interfaces**:
- Consumes: `bcryptCost` (`common/encrypt.go:16`), `CheckPassword`, `HashString`.
- Produces: `common.BurnPasswordCompare(password string)`: runs one bcrypt comparison against a fixed dummy hash at the production cost and discards the result.

The dummy compare calls `common` directly instead of the injected `PasswordService`, so the existing mock-based service tests need no new expectations. HTTP and CLI login both go through `AuthenticateUser`, so both paths get the fix and the CLI test in Task 4 still passes.

- [ ] **Step 1: Failing test** in `common/encrypt_test.go`:

```go
func TestBurnPasswordCompare_CostsAsMuchAsARealCompare(t *testing.T) {
	hash, err := HashString("real")
	if err != nil {
		t.Fatal(err)
	}
	startReal := time.Now()
	_ = CheckPassword("x", hash)
	real := time.Since(startReal)

	BurnPasswordCompare("warm-up") // First call builds the dummy hash.
	start := time.Now()
	BurnPasswordCompare("x")
	burned := time.Since(start)

	// Same bcrypt cost, so the same order of magnitude; allow a wide band.
	if burned < real/4 {
		t.Fatalf("dummy compare took %v, real compare %v", burned, real)
	}
}
```

(Add `time` to the file's imports if absent.) Run `go test ./common/ -run TestBurnPasswordCompare -v`. Expected: FAIL, `undefined: BurnPasswordCompare`.
- [ ] **Step 2: Implement** in `common/encrypt.go`:

```go
var (
	dummyHashOnce sync.Once
	dummyHash     string
)

// BurnPasswordCompare spends one bcrypt comparison at the production cost and
// discards the outcome. Callers run it when a lookup finds no account, so a
// missing account takes as long to reject as a wrong password and response
// timing does not reveal which usernames exist.
func BurnPasswordCompare(password string) {
	dummyHashOnce.Do(func() {
		// A failure here only makes the burn cheaper, never wrong.
		dummyHash, _ = HashString("rocketvault-timing-equaliser")
	})
	_ = CheckPassword(password, dummyHash)
}
```

(Add `sync` to imports.) Run the test: expected PASS.
- [ ] **Step 3: Failing service tests.** In `authentication_service_critical_test.go` add, using the setup from `TestAuthenticateUser_UserNotFound` (line 42):

```go
func TestAuthenticateUser_UserNotFound_CostsAsMuchAsWrongPassword(t *testing.T) {
	ctx := context.Background()
	users := &MockUserRepository{}
	users.On("ReadByUsername", ctx, "nobody").Return(model.User{}, errors.New("not found"))
	svc := NewAuthenticationService(AuthenticationConfig{
		UserRepository: users, SessionRepository: &MockSessionRepository{},
		PasswordService: &MockPasswordService{}, TOTPService: &MockTOTPService{},
		JWTService: &MockJWTService{}, Logger: logging.InitLogger(),
	})
	common.BurnPasswordCompare("warm-up")

	start := time.Now()
	_, err := svc.AuthenticateUser(ctx, "nobody", "whatever", "123456")
	elapsed := time.Since(start)

	require.Error(t, err)
	assert.Equal(t, "invalid credentials", err.Error())
	assert.Greater(t, elapsed, 20*time.Millisecond, "an unknown user must still pay for a bcrypt compare")
}
```

(Import `rocketvault/common` and `rocketvault/internal/logging`, plus `time`, `errors` and `model` if the file lacks them.) In `oauth2_service_test.go` add the same shape for `ghost`, a disabled client and an expired client, asserting each takes over 20ms (bcrypt cost 12 is roughly 200ms on any CI box, so the bound is loose):

```go
func TestOAuth2Service_IssueToken_RejectionsPayBcryptCost(t *testing.T) {
	past := time.Now().UTC().Add(-time.Hour)
	cases := map[string]*model.OAuth2Client{
		"ghost":    nil,
		"disabled": {ID: uuid.New(), Name: "disabled", Enabled: false},
		"expired":  {ID: uuid.New(), Name: "expired", Enabled: true, ExpiresAt: &past},
	}
	common.BurnPasswordCompare("warm-up")
	for name, client := range cases {
		t.Run(name, func(t *testing.T) {
			repo := &mockOAuth2ClientRepo{}
			if client == nil {
				repo.On("FindByName", mock.Anything, name).Return(nil, errors.New("not found"))
			} else {
				repo.On("FindByName", mock.Anything, name).Return(client, nil)
			}
			svc := buildService(repo, &mockPasswordService{}, &mockJWTService{})

			start := time.Now()
			_, err := svc.IssueToken(context.Background(), name, "secret")

			require.Error(t, err)
			assert.Contains(t, err.Error(), "invalid client credentials")
			assert.Greater(t, time.Since(start), 20*time.Millisecond)
		})
	}
}
```

Run both: expected FAIL (near-instant return).
- [ ] **Step 4: Implement.** In `AuthenticateUser`'s not-found branch, add only `common.BurnPasswordCompare(password)` before the `return`; import `rocketvault/common`. Do not add `s.recordLoginFailure` here: Task 4 step 12 already records the failure in this branch, and adding it again would count two failures per unknown-user attempt and shift the backoff window. In `oauth2_service.go` `IssueToken`, restructure:

```go
	client, err := s.repo.FindByName(ctx, clientName)
	if err != nil {
		// Spend the same bcrypt time as a real rejection so timing cannot
		// distinguish an unknown client from a wrong secret.
		common.BurnPasswordCompare(secret)
		return nil, fmt.Errorf("invalid client credentials")
	}

	// Disabled and expired clients get the same uniform error and the same cost.
	if !client.Enabled || (client.ExpiresAt != nil && client.ExpiresAt.Before(time.Now().UTC())) {
		common.BurnPasswordCompare(secret)
		return nil, fmt.Errorf("invalid client credentials")
	}
```

(keep the following `ValidatePassword` block unchanged; import `rocketvault/common`).
- [ ] **Step 5: Run** `go test ./common/ ./internal/services/auth/ ./internal/services/oauth2/ ./cmd/users/ ./api/ -v -run 'Burn|UserNotFound|IssueToken|TestPerformPasswordLogin|TestTokenHandler'`. Expected: PASS.
- [ ] **Step 6: Commit** via the `dev-workflow-skills:1-git-commit` skill.

---

### Task 6: Token endpoint ignores the query string; rate limit the Config router

**Files**:
- Modify: `api/oauth2.go` (`tokenHandler` line ~70, `extractClientCredentials` line ~156)
- Modify: `api/api.go` (line ~147, `r.Config.Use(...)`)
- Test: `api/oauth2_handlers_test.go`, `internal/middleware/middleware_test.go` or an `api` routing test

**Interfaces**:
- Consumes: `tokenHandler`, `extractClientCredentials`, `mw.RateLimitMiddleware`.
- Produces: no new names. `grant_type` also moves to `PostFormValue`.

- [ ] **Step 1: Failing tests** appended to `api/oauth2_handlers_test.go`:

```go
func TestTokenHandler_SecretInQueryStringIsIgnored(t *testing.T) {
	svc := &mockOAuth2Svc{} // IssueToken must never be called.
	api := newOAuth2HAPI(svc)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost,
		"/oauth2/token?client_id=app&client_secret=leaked", strings.NewReader("grant_type=client_credentials"))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	api.tokenHandler(w, r)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
	svc.AssertNotCalled(t, "IssueToken", mock.Anything, mock.Anything, mock.Anything)
}

func TestTokenHandler_GrantTypeInQueryStringIsIgnored(t *testing.T) {
	api := newOAuth2HAPI(nil)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/oauth2/token?grant_type=client_credentials", strings.NewReader(""))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	api.tokenHandler(w, r)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}
```

Run `go test ./api/ -run 'TestTokenHandler_(SecretInQuery|GrantTypeInQuery)' -v`. Expected: FAIL (the query secret currently reaches `IssueToken`, which panics on the un-stubbed mock).
- [ ] **Step 2: Implement.** In `api/oauth2.go` change `r.FormValue("grant_type")` to `r.PostFormValue("grant_type")` and in `extractClientCredentials` the last line to `return r.PostFormValue("client_id"), r.PostFormValue("client_secret"), true`. Update the doc comment there: body only, per RFC 6749 §2.3.1. The existing `ParseForm()` call stays (it fills `PostForm`).
- [ ] **Step 3: Failing test for the Config router limit.** Find how routes are assembled in `api/api.go` tests (`grep -n "BaseRoutes.Config\|NewAPI(" api/*_test.go`). Add a test that builds the router through the same constructor those tests use, sets `rate_limit.default` via `viper.Set("rate_limit.default", 3)` before constructing, issues 4 `GET <basePath>/config` requests from one `RemoteAddr`, and asserts the fourth returns 429. Run it, expect FAIL (no limiter on Config).
- [ ] **Step 4: Implement** in `api/api.go`: change `r.Config.Use(mw.CORSMiddleware, mw.SecurityHeadersMiddleware)` to `r.Config.Use(mw.CORSMiddleware, mw.SecurityHeadersMiddleware, mw.RateLimitMiddleware)` and extend the comment above it to say it is rate limited because it is reachable without authentication.
- [ ] **Step 5: Run** `go test ./api/ ./internal/middleware/ -v`. Expected: PASS.
- [ ] **Step 6: Commit** via the `dev-workflow-skills:1-git-commit` skill.

---

### Task 7: client_id length cap and sanitisation in audit rows

**Files**:
- Modify: `api/oauth2.go` (`recordOAuth2TokenAudit` ~lines 120-136)
- Test: `api/oauth2_handlers_test.go`

**Interfaces**:
- Consumes: `maxAuditClientIDLen = 255` (already exists, byte-based; the existing `TestTokenHandler_OversizedClientID_TruncatedInAuditEvent` pins it and must keep passing).
- Produces: `func sanitizeAuditClientID(s string) string`.

The length cap already exists; what is missing is sanitisation. Control characters (newlines for log injection, NUL) and invalid UTF-8 are dropped, and truncation must not split a multi-byte rune.

- [ ] **Step 1: Failing tests**:

```go
func TestSanitizeAuditClientID(t *testing.T) {
	assert.Equal(t, "my-app_1", sanitizeAuditClientID("my-app_1"))
	assert.Equal(t, "evilfake", sanitizeAuditClientID("evil\r\n\x00fake"))
	assert.Equal(t, "ab", sanitizeAuditClientID("a\xffb"), "invalid UTF-8 is dropped")
	assert.Equal(t, "", sanitizeAuditClientID("\n\t"))

	long := strings.Repeat("é", 200) // 400 bytes.
	got := sanitizeAuditClientID(long)
	assert.LessOrEqual(t, len(got), maxAuditClientIDLen)
	assert.True(t, utf8.ValidString(got), "truncation must not split a rune")
}

func TestTokenHandler_ControlCharsInClientIDAreStrippedFromAuditEvent(t *testing.T) {
	svc := &mockOAuth2Svc{}
	svc.On("IssueToken", mock.Anything, "evil\nname", "s").Return(nil, errors.New("invalid"))
	mockAudit := &testutils.MockAuditService{}
	mockAudit.On("RecordEvent", mock.Anything, mock.MatchedBy(func(e auditServices.AuditEvent) bool {
		return e.UserID == "evilname" && e.ResourceID == "evilname"
	})).Return(nil)

	a := &app.App{ServiceContainer: &oauth2HTestContainer{svc: svc, auditSvc: mockAudit}}
	api := &API{App: a, Logger: userTestLog()}
	w := httptest.NewRecorder()
	body := strings.NewReader("grant_type=client_credentials&client_id=evil%0Aname&client_secret=s")
	r := httptest.NewRequest(http.MethodPost, "/oauth2/token", body)
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	api.tokenHandler(w, r)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
	mockAudit.AssertExpectations(t)
}
```

(Import `unicode/utf8` in the test file.) Run `go test ./api/ -run 'TestSanitizeAuditClientID|ControlChars' -v`. Expected: FAIL, `undefined: sanitizeAuditClientID`.
- [ ] **Step 2: Implement** in `api/oauth2.go`, replacing the byte-truncation block in `recordOAuth2TokenAudit` with `clientID = sanitizeAuditClientID(clientID)`, and adding:

```go
// sanitizeAuditClientID makes an untrusted client_id safe to store in an audit
// row. It drops control characters and invalid UTF-8, then caps the length at
// maxAuditClientIDLen bytes without splitting a rune.
func sanitizeAuditClientID(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r == utf8.RuneError || !unicode.IsPrint(r) {
			continue
		}
		if b.Len()+utf8.RuneLen(r) > maxAuditClientIDLen {
			break
		}
		b.WriteRune(r)
	}
	return b.String()
}
```

Add `unicode` and `unicode/utf8` imports. Note `for range` over a string yields `RuneError` for each invalid byte, which the first condition drops; a literal U+FFFD in the input is also dropped, which is acceptable.
- [ ] **Step 3: Run** `go test ./api/ -run 'TestTokenHandler|TestSanitize' -v`. Expected: PASS, including the existing oversized-ID test.
- [ ] **Step 4: Commit** via the `dev-workflow-skills:1-git-commit` skill.

---

### Task 8: Docs, release note, known-bugs B85

**Files**:
- Modify: `docs/api-developer-guide.md` (rate limit table ~lines 420-432)
- Create: `docs/release-notes/v4.7.0-login-rate-limiting.md` (copy the heading and section style of `docs/release-notes/v4.6.0-narrow-global-vault-manage.md`; if `scripts/docsgen/docs.go` lists release notes, add the new file there in the same style as v4.6.0)
- Modify: `.claude/known-bugs.md` (append `### B85` after the last entry; copy the structure of B69, lines 4099-4145)
- Test: `go build ./... && go vet ./... && go test ./...`

**Interfaces**: none.

- [ ] **Step 1: Update the API guide.** Change the auth-endpoints row to say the key is the client IP as resolved through `server.trusted_proxies` (IPv6 grouped by /64), add a row for the public `/config` endpoint (client IP, `rate_limit.default`), and add a short "Behind a reverse proxy" paragraph naming `server.trusted_proxies` and the per-account backoff (5 free failures, then 2s doubling to 15 minutes, `429` with `Retry-After`).
- [ ] **Step 2: Write the release note** with these sections: "What changed" (trusted-proxy key, /64 bucketing, bounded limiter, per-account backoff, constant-time rejection, query-string secret rejected, `/config` limited, audit client_id sanitised); "Breaking changes" (1. forwarded headers are no longer trusted by default, so audit-row IPs behind a proxy now show the proxy's address until `server.trusted_proxies` is set, which is also what lets the limiter tell clients apart; 2. clients that send `client_secret`, `client_id` or `grant_type` in the `/oauth2/token` query string now get 401/400; 3. a sixth consecutive failed login for one account now returns 429 with `Retry-After` for a growing delay); "Upgrade procedure" (set `server.trusted_proxies` to the proxy range on Railway, Fly, nginx; no action for direct deployments; the `login_failures` table is created automatically on start); "What did not change" (limits `rate_limit.default` / `rate_limit.auth` and the per-vault limiter).
- [ ] **Step 3: Write the B85 entry** with Status `Fixed in commits <fill in after the commits land>` (the implementer replaces this with the real short hashes from `git log --oneline` once Tasks 1-7 are committed), Severity Medium, Files list, Symptom, Root cause, What was fixed (one paragraph per task 1-7), Accepted behaviour changes (as above), and `**GitHub issue**: #46`.
- [ ] **Step 4: Full verification.** Run `go build ./... && go vet ./... && go test ./...`. Expected: all pass. State in the PR description that `golangci-lint` could not be run locally (snap Go toolchain incompatibility) and must pass in CI.
- [ ] **Step 5: Commit** via the `dev-workflow-skills:1-git-commit` skill with footer `Fixes #46`.

---

## Self-Review

**Spec coverage.** Issue tasks 1 to 7 map to plan tasks 1 to 7 one to one: trusted-proxy key plus single helper (1), /64 bucketing (2), eviction on an injectable clock (3), per-account backoff with stated thresholds and a DB-backed counter under the db.go dual-write pattern (4), dummy bcrypt for auth and OAuth2 not-found, disabled and expired cases (5), `PostFormValue` and Config-router limiter (6), client_id cap plus sanitisation (7). Release note, known-bugs B85 and docs are Task 8. CLI coverage: Task 4 tests `performPasswordLogin`, the remote-mode 429 message and the service directly; Task 5 flows through the same `AuthenticateUser` so the CLI test in Task 4 covers it; Tasks 1, 2, 3, 6, 7 are HTTP-only and say so.

**Placeholder scan.** Two spots instruct the implementer to read an adjacent file and copy mock setup rather than showing every line (Task 4 steps 1 and 10, and the Config-router routing test in Task 6 step 3), because the exact constructor names there depend on helpers I read only partially; each names the file, line range and the helper to write. B85's commit hashes are filled in after the commits exist, by design.

**Type consistency.** `ClientIPResolver`, `NewClientIPResolver`, `SetClientIPResolver`, `rateLimitKey` (Tasks 1, 2); `newKeyedRateLimiterWith`, `limiterIdleTTL`, `limiterSweepInterval`, `len()` (Task 3); `LoginFailureRepositoryInterface`, `LoginThrottle`, `ThrottledError`, `ErrLoginThrottled`, `loginDelay`, `recordLoginFailure` (Tasks 4, 5); `common.BurnPasswordCompare` (Task 5); `sanitizeAuditClientID` (Task 7). Task 5 no longer calls `recordLoginFailure` (Task 4 owns it); the tasks must still run in order, and both run after the identity plan.
