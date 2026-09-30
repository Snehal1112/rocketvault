package mcpserver

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestGetCertificate_IncludesVersionHistory(t *testing.T) {
	routes := certRoutes()
	routes["/api/v1/vaults/default/certificates/"+tlsCertUUID+"/versions"] = `{"versions":[
		{"certificate_id":"` + tlsCertUUID + `","version":1,"current":false,"enabled":true,"created_at":"2026-08-01T00:00:00Z"},
		{"certificate_id":"` + tlsCertUUID + `","version":2,"current":true,"enabled":true,"created_at":"2026-09-01T00:00:00Z"}]}`
	f := newFakeVault(t, routes)
	s := f.server(t, testConfig())
	registerCertificatesReadTools(s)

	var got getCertificateResult
	structured(t, callTool(t, s, "get_certificate", map[string]any{"name": "tls-cert"}), &got)
	require.Len(t, got.Versions, 2)
	require.True(t, got.Versions[1].Current)
	require.Equal(t, 2, got.Versions[1].Version)
}

func TestRenewCertificate_IsAbsentWithoutAllowWrite(t *testing.T) {
	f := newFakeVault(t, certRoutes())
	s := f.server(t, testConfig())
	registerCertificatesWriteTools(s)
	require.NotContains(t, s.RegisteredTools(), "renew_certificate")
}

func TestRenewCertificate_PostsAndReportsTheNewVersion(t *testing.T) {
	f := newFakeVault(t, certRoutes())
	f.writeResponse = `{"certificate_id":"` + tlsCertUUID + `","version":2,"current":true,"enabled":true,
		"created_at":"2026-10-01T00:00:00Z","expires_at":"2027-10-01T00:00:00Z"}`
	s := f.server(t, writeConfig())
	registerCertificatesWriteTools(s)

	var got renewCertificateResult
	structured(t, callTool(t, s, "renew_certificate", map[string]any{"name": "tls-cert", "validity_days": 90}), &got)
	require.Equal(t, 2, got.Version)
	require.NotEmpty(t, got.ExpiresAt)
	require.True(t, f.hit("/api/v1/vaults/default/certificates/"+tlsCertUUID+"/renew"))
	require.Equal(t, float64(90), f.lastWriteBody["validity_days"])
}

func TestRenewCertificate_RequiresName(t *testing.T) {
	f := newFakeVault(t, certRoutes())
	s := f.server(t, writeConfig())
	registerCertificatesWriteTools(s)
	require.True(t, callTool(t, s, "renew_certificate", map[string]any{}).IsError)
}
