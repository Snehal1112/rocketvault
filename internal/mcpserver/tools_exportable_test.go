package mcpserver

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCreateCertificateTool_ForwardsExportable(t *testing.T) {
	f := newFakeVault(t, map[string]string{
		"/api/v1/vaults/default/keys": `{"keys":[{"id":"` + signKeyUUID + `","name":"tls-key"}]}`,
	})
	f.writeResponse = `{"id":"` + tlsCertUUID + `","name":"tls-cert"}`
	s := f.server(t, writeConfig())
	registerCertificatesWriteTools(s)

	var got createCertificateResult
	structured(t, callTool(t, s, "create_certificate", map[string]any{
		"name": "tls-cert", "key_name": "tls-key", "validity_days": 30, "exportable": true,
	}), &got)
	require.Equal(t, true, f.lastWriteBody["exportable"])
}

func TestCreateKeyTool_ForwardsExportable(t *testing.T) {
	f := newFakeVault(t, map[string]string{})
	f.writeResponse = `{"id":"` + signKeyUUID + `","name":"k","type":"RSA","bits":2048}`
	s := f.server(t, writeConfig())
	registerKeysWriteTools(s)

	var got createKeyResult
	structured(t, callTool(t, s, "create_key", map[string]any{
		"name": "k", "type": "RSA", "bits": 2048, "exportable": true,
	}), &got)
	require.Equal(t, true, f.lastWriteBody["exportable"])
}
