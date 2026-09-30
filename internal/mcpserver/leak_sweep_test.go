package mcpserver

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/stretchr/testify/require"
)

// leakMarker stands in for genuine secret material: a secret's value, a
// private key, decrypted plaintext. No tool output may contain it while
// allow_secret_values is off.
const leakMarker = "LEAKMARKER-hunter2-super-secret"

// freeTextMarker stands in for ordinary vault-resident free text -- tags, a
// vault note, a principal's username, an audit detail. The design always
// returns this, wrapped as untrusted, regardless of allow_secret_values: it
// is metadata, not secret material, and TestListSecrets_WrapsTagsAsUntrusted
// already pins that it must survive intact. Stuffing leakMarker into these
// fields too would make the sweep fail on correct behavior.
const freeTextMarker = "FREETEXT-vault-resident-note"

// leakRoutes returns responses that stuff leakMarker into every field that
// carries genuine secret material, and freeTextMarker into every field that
// is ordinary metadata the design always returns.
func leakRoutes() map[string]string {
	encoded := base64.StdEncoding.EncodeToString([]byte(leakMarker))
	return map[string]string{
		"/api/v1/vaults": `{"vaults":[{"id":"` + prodVaultID + `","name":"default",
			"tags":{"note":"` + freeTextMarker + `"}}],"total":1}`,

		"/api/v1/vaults/default/secrets": `{"secrets":[{"id":"` + dbSecretUUID + `",
			"name":"db-password","value":"` + leakMarker + `","tags":["` + freeTextMarker + `"]}],"total":1}`,

		"/api/v1/vaults/default/secrets/" + dbSecretUUID: `{"id":"` + dbSecretUUID + `",
			"name":"db-password","value":"` + leakMarker + `","tags":["` + freeTextMarker + `"],
			"content_type":"` + freeTextMarker + `"}`,

		"/api/v1/vaults/default/secrets/" + dbSecretUUID + "/versions": `[{"version":1,
			"value":"` + leakMarker + `"}]`,

		"/api/v1/vaults/default/keys": `{"keys":[{"id":"` + signKeyUUID + `","name":"signing-key",
			"type":"RSA","value":"` + leakMarker + `","tags":["` + freeTextMarker + `"]}]}`,

		"/api/v1/vaults/default/keys/" + signKeyUUID: `{"id":"` + signKeyUUID + `",
			"name":"signing-key","type":"RSA","value":"` + leakMarker + `"}`,

		"/api/v1/vaults/default/certificates": `{"certificates":[{"id":"` + tlsCertUUID + `",
			"name":"tls-cert","private_key":"` + leakMarker + `","tags":["` + freeTextMarker + `"]}]}`,

		"/api/v1/vaults/default/certificates/" + tlsCertUUID: `{"id":"` + tlsCertUUID + `",
			"name":"tls-cert","private_key":"` + leakMarker + `"}`,

		"/api/v1/vaults/default/deleted/secrets": `{"deleted_secrets":[{"id":"` + dbSecretUUID + `",
			"name":"old","value":"` + leakMarker + `"}],"total":1}`,

		"/api/v1/vaults/default/certificates/" + tlsCertUUID + "/versions": `{"versions":[{"version":1,"current":true,
			"private_key":"` + leakMarker + `","certificate":"` + leakMarker + `"}]}`,

		"/api/v1/vaults/default/role-assignments": `{"role_assignments":[{"id":"` + assignmentID + `",
			"principal_username":"` + freeTextMarker + `","role":"Key Vault Reader"}],"total":1}`,

		"/api/v1/audit/logs": `{"logs":[{"id":"1","action":"secret.read",
			"details":"` + freeTextMarker + `"}],"total":1,"integrity_ok":true}`,

		// Crypto responses carry the marker base64-encoded, which is how a
		// leak would actually look on these routes.
		"__write__": `{"key_id":"` + signKeyUUID + `","value":"` + encoded + `","status":"OK"}`,
	}
}

// sweepArgs supplies plausible arguments per tool, so each one runs rather
// than failing validation before it can leak.
func sweepArgs(name string) map[string]any {
	base := map[string]any{}
	switch name {
	case "get_secret", "get_key", "get_certificate":
		base["name"] = "db-password"
	case "list_deleted":
		base["type"] = "secrets"
	case "query_audit_log", "list_secrets", "list_keys", "list_certificates",
		"list_vaults", "list_role_assignments":
		// No arguments needed.
	}
	if name == "get_key" {
		base["name"] = "signing-key"
	}
	if name == "get_certificate" {
		base["name"] = "tls-cert"
	}
	return base
}

func TestLeakSweep_NoReadToolLeaksSecretMaterial(t *testing.T) {
	f := newFakeVault(t, leakRoutes())
	f.writeResponse = leakRoutes()["__write__"]

	// Disclosure off: no tool may return the marker in any form.
	s := f.server(t, testConfig())
	RegisterAllTools(s)

	cs := connect(t, s)
	encoded := base64.StdEncoding.EncodeToString([]byte(leakMarker))

	for _, name := range s.RegisteredTools() {
		t.Run(name, func(t *testing.T) {
			result, err := cs.CallTool(context.Background(), &mcp.CallToolParams{
				Name: name, Arguments: sweepArgs(name),
			})
			require.NoError(t, err)

			serialized, err := json.Marshal(result)
			require.NoError(t, err)

			require.NotContains(t, string(serialized), leakMarker,
				"%s leaked secret material in plain form", name)
			require.NotContains(t, string(serialized), encoded,
				"%s leaked secret material base64-encoded -- base64 is an encoding, not protection", name)
		})
	}
}

func TestLeakSweep_CoversEveryReadTool(t *testing.T) {
	f := newFakeVault(t, leakRoutes())
	s := f.server(t, testConfig())
	RegisterAllTools(s)

	require.Len(t, s.RegisteredTools(), 10,
		"the sweep must cover the whole default surface, not a subset")
}

func TestLeakSweep_MarkerWouldBeDetectedIfPresent(t *testing.T) {
	// A sweep that cannot fail proves nothing. Confirm the assertion catches
	// the marker when it genuinely is present.
	f := newFakeVault(t, leakRoutes())

	cfg := testConfig()
	cfg.AllowSecretValues = true
	s := f.server(t, cfg)
	RegisterAllTools(s)

	cs := connect(t, s)
	result, err := cs.CallTool(context.Background(), &mcp.CallToolParams{
		Name: "get_secret", Arguments: map[string]any{"name": "db-password", "include_value": true},
	})
	require.NoError(t, err)

	serialized, err := json.Marshal(result)
	require.NoError(t, err)
	require.Contains(t, string(serialized), leakMarker,
		"with disclosure explicitly enabled and requested, the value should appear -- "+
			"otherwise the sweep above is vacuous")
}

func TestLeakSweep_UntrustedTextIsMarkedNotStripped(t *testing.T) {
	f := newFakeVault(t, leakRoutes())
	s := f.server(t, testConfig())
	RegisterAllTools(s)

	cs := connect(t, s)
	result, err := cs.CallTool(context.Background(), &mcp.CallToolParams{
		Name: "query_audit_log", Arguments: map[string]any{},
	})
	require.NoError(t, err)

	serialized, err := json.Marshal(result)
	require.NoError(t, err)
	require.Contains(t, string(serialized), "UNTRUSTED-VAULT-DATA",
		"audit details are vault-resident free text and must be marked")
	require.Contains(t, string(serialized), freeTextMarker,
		"marking must delimit the text, not strip it -- the content is still there")
}

func TestLeakSweep_LogsCarryNoSecretMaterial(t *testing.T) {
	var logs strings.Builder
	f := newFakeVault(t, leakRoutes())

	cfg := testConfig()
	cfg.AllowSecretValues = true // Even with disclosure on, logs stay clean.
	s := f.serverWithLogger(t, cfg, &logs)
	RegisterAllTools(s)

	cs := connect(t, s)
	for _, name := range []string{"list_secrets", "get_secret"} {
		_, err := cs.CallTool(context.Background(), &mcp.CallToolParams{
			Name: name, Arguments: sweepArgs(name),
		})
		require.NoError(t, err)
	}

	encoded := base64.StdEncoding.EncodeToString([]byte(leakMarker))
	require.NotContains(t, logs.String(), leakMarker)
	require.NotContains(t, logs.String(), encoded,
		"a value disclosed to the model must still never reach a log line")
}
