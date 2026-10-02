package config

import (
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLoadTrustedProxies_DefaultsToNone(t *testing.T) {
	viper.Reset()
	t.Cleanup(viper.Reset)
	nets, err := LoadTrustedProxies()
	require.NoError(t, err)
	assert.Empty(t, nets)
}

func TestLoadTrustedProxies_ParsesIPsAndCIDRs(t *testing.T) {
	viper.Reset()
	t.Cleanup(viper.Reset)
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
	t.Cleanup(viper.Reset)
	viper.Set("server.trusted_proxies", []string{"not-an-ip"})
	_, err := LoadTrustedProxies()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "server.trusted_proxies")
}

func TestLoadTrustedProxies_RejectsBadCIDR(t *testing.T) {
	viper.Reset()
	t.Cleanup(viper.Reset)
	viper.Set("server.trusted_proxies", []string{"10.0.0.0/8", "10.0.0.0/99"})
	_, err := LoadTrustedProxies()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "server.trusted_proxies")
}
