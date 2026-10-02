package middleware

import (
	"net"
	"net/http"
	"strings"
	"sync/atomic"
)

// ClientIPResolver decides which IP address a request really came from.
// Forwarded-address headers are honoured only when the TCP peer is itself a
// trusted proxy, because any client can send them. It is the only code in the
// server that may read X-Forwarded-For or X-Real-IP.
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

// parseHost parses an address with an optional IPv6 zone, which is dropped.
func parseHost(s string) net.IP {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, '%'); i >= 0 {
		s = s[:i]
	}
	return net.ParseIP(s)
}

// ClientIP returns the caller's address. A nil receiver trusts no proxies.
func (c *ClientIPResolver) ClientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	peer := parseHost(host)
	if peer == nil {
		return host
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
		ip := parseHost(hops[i])
		if ip == nil {
			// A hop we cannot read means the chain cannot be trusted past it.
			return peer.String()
		}
		if !c.trusts(ip) {
			return ip.String()
		}
		if i == 0 {
			// Every hop was a trusted proxy, so the leftmost one is the origin.
			return ip.String()
		}
	}
	// X-Real-IP is consulted only when the trusted proxy sent no chain.
	if ip := parseHost(r.Header.Get("X-Real-IP")); ip != nil {
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
