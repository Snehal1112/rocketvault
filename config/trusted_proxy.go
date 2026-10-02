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
// Any entry that is not a valid IP address or CIDR range is an error.
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
		if v4 := ip.To4(); v4 != nil {
			ip = v4
			bits = 32
		}
		nets = append(nets, &net.IPNet{IP: ip, Mask: net.CIDRMask(bits, bits)})
	}
	return nets, nil
}
