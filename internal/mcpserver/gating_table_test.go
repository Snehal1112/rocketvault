package mcpserver

import (
	"context"
	"sort"
	"testing"

	"github.com/stretchr/testify/require"

	"rocketvault/config"
	"rocketvault/internal/vaultapi"
)

// The four tiers, written out in full rather than computed. A computed
// expectation would derive from the same logic under test and pass whether
// or not that logic is right.
var (
	readTools = []string{
		"get_certificate", "get_key", "get_secret",
		"list_certificates", "list_deleted", "list_keys",
		"list_role_assignments", "list_secrets", "list_vaults",
		"query_audit_log",
	}
	writeTools = []string{
		"create_certificate", "create_key", "create_vault",
		"grant_vault_role", "recover_deleted", "renew_certificate", "rotate_key",
		"set_certificate_policy", "set_key_rotation_policy", "set_secret",
	}
	destructiveTools = []string{
		"delete_item", "purge_item", "purge_vault", "revoke_vault_role",
	}
	// decrypt is absent here: it needs allow_secret_values as well.
	cryptoTools = []string{"encrypt", "sign", "verify"}
	// disclosureTools appear only when allow_secret_values is set, and
	// then only if their tier is enabled too.
	cryptoDisclosureTools = []string{"decrypt"}
)

// expectedTools assembles the set for a flag combination.
func expectedTools(write, destructive, crypto, values bool) []string {
	tools := append([]string{}, readTools...)
	if write {
		tools = append(tools, writeTools...)
	}
	if destructive {
		tools = append(tools, destructiveTools...)
	}
	if crypto {
		tools = append(tools, cryptoTools...)
		if values {
			tools = append(tools, cryptoDisclosureTools...)
		}
	}
	sort.Strings(tools)
	return tools
}

// configFor builds a config with the four flags set as given.
func configFor(write, destructive, crypto, values bool) config.MCPConfig {
	cfg := testConfig()
	cfg.AllowWrite = write
	cfg.AllowDestructive = destructive
	cfg.AllowCrypto = crypto
	cfg.AllowSecretValues = values
	return cfg
}

func TestGatingTable_EveryFlagCombination(t *testing.T) {
	// All 16 combinations. Exhaustive rather than representative: sampling
	// would let through exactly the mistake this exists to catch.
	for _, write := range []bool{false, true} {
		for _, destructive := range []bool{false, true} {
			for _, crypto := range []bool{false, true} {
				for _, values := range []bool{false, true} {
					name := combinationName(write, destructive, crypto, values)
					t.Run(name, func(t *testing.T) {
						f := newFakeVault(t, map[string]string{})
						s := f.server(t, configFor(write, destructive, crypto, values))
						RegisterAllTools(s)

						require.Equal(t, expectedTools(write, destructive, crypto, values),
							s.RegisteredTools(),
							"the exposed surface must match the configuration exactly")
					})
				}
			}
		}
	}
}

// combinationName renders a readable subtest name.
func combinationName(write, destructive, crypto, values bool) string {
	name := ""
	for _, part := range []struct {
		on    bool
		label string
	}{
		{write, "write"}, {destructive, "destructive"},
		{crypto, "crypto"}, {values, "values"},
	} {
		if part.on {
			if name != "" {
				name += "+"
			}
			name += part.label
		}
	}
	if name == "" {
		return "default"
	}
	return name
}

func TestGatingTable_CountsMatchTheDocumentedSurface(t *testing.T) {
	cases := []struct {
		write, destructive, crypto, values bool
		want                               int
	}{
		{false, false, false, false, 10},
		{true, false, false, false, 20},
		{true, true, false, false, 24},
		{true, true, true, false, 27},
		{true, true, true, true, 28},
	}

	for _, tc := range cases {
		t.Run(combinationName(tc.write, tc.destructive, tc.crypto, tc.values), func(t *testing.T) {
			f := newFakeVault(t, map[string]string{})
			s := f.server(t, configFor(tc.write, tc.destructive, tc.crypto, tc.values))
			RegisterAllTools(s)

			require.Len(t, s.RegisteredTools(), tc.want,
				"docs/mcp-server.md and the --check output quote these numbers")
		})
	}
}

func TestGatingTable_DecryptNeedsBothCryptoAndValues(t *testing.T) {
	cases := []struct {
		crypto, values bool
		want           bool
	}{
		{false, false, false},
		{true, false, false},
		{false, true, false},
		{true, true, true},
	}

	for _, tc := range cases {
		f := newFakeVault(t, map[string]string{})
		s := f.server(t, configFor(false, false, tc.crypto, tc.values))
		RegisterAllTools(s)

		present := contains(s.RegisteredTools(), "decrypt")
		require.Equal(t, tc.want, present,
			"decrypt returns plaintext, so allow_crypto alone must not expose it (crypto=%v values=%v)",
			tc.crypto, tc.values)
	}
}

func TestGatingTable_NoDestructiveToolUnderWriteAlone(t *testing.T) {
	f := newFakeVault(t, map[string]string{})
	s := f.server(t, configFor(true, false, false, false))
	RegisterAllTools(s)

	for _, name := range destructiveTools {
		require.False(t, contains(s.RegisteredTools(), name),
			"allow_write must never expose %q", name)
	}
}

func TestGatingTable_RecoverIsAWriteToolNotADestructiveOne(t *testing.T) {
	f := newFakeVault(t, map[string]string{})

	writeOnly := f.server(t, configFor(true, false, false, false))
	RegisterAllTools(writeOnly)
	require.True(t, contains(writeOnly.RegisteredTools(), "recover_deleted"),
		"an operator who can write must be able to undo a deletion")

	destructiveOnly := f.server(t, configFor(false, true, false, false))
	RegisterAllTools(destructiveOnly)
	require.False(t, contains(destructiveOnly.RegisteredTools(), "recover_deleted"),
		"recovery is additive and does not belong to the destructive tier")
}

func TestGatingTable_EveryToolIsAccountedFor(t *testing.T) {
	// The union of the tier lists must equal the fully-enabled surface. This
	// is what fails when a tool is added without a tier decision.
	f := newFakeVault(t, map[string]string{})
	s := f.server(t, configFor(true, true, true, true))
	RegisterAllTools(s)

	all := append([]string{}, readTools...)
	all = append(all, writeTools...)
	all = append(all, destructiveTools...)
	all = append(all, cryptoTools...)
	all = append(all, cryptoDisclosureTools...)
	sort.Strings(all)

	require.Equal(t, all, s.RegisteredTools(),
		"a tool missing from the tier lists above has no deliberate tier assignment")
}

func TestGatingTable_ReadToolsAreAlwaysPresent(t *testing.T) {
	for _, write := range []bool{false, true} {
		for _, destructive := range []bool{false, true} {
			f := newFakeVault(t, map[string]string{})
			s := f.server(t, configFor(write, destructive, false, false))
			RegisterAllTools(s)

			for _, name := range readTools {
				require.True(t, contains(s.RegisteredTools(), name),
					"read tools are unconditional; %q was missing", name)
			}
		}
	}
}

func TestGatingTable_MatchesWhatTheProtocolExposes(t *testing.T) {
	// RegisteredTools is bookkeeping; tools/list is what a host actually
	// sees. They must agree, or --check would report a surface that is not
	// the real one.
	f := newFakeVault(t, map[string]string{})
	s := f.server(t, configFor(true, true, true, true))
	RegisterAllTools(s)

	cs := connect(t, s)
	require.Equal(t, s.RegisteredTools(), toolNames(t, cs))
}

// contains reports whether values includes target.
func contains(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

var _ = context.Background

func TestGatingTable_LoginPresentOnlyWithFlagAndSessionIdentity(t *testing.T) {
	cases := []struct {
		name                  string
		allowInteractiveLogin bool
		serviceAccount        bool
		wantPresent           bool
	}{
		{"default", false, false, false},
		{"flag on, session identity", true, false, true},
		{"flag on, service account", true, true, false},
		{"flag off, service account", false, true, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := testConfig()
			cfg.AllowInteractiveLogin = tc.allowInteractiveLogin

			f := newFakeVault(t, map[string]string{})
			client, err := vaultapi.New(vaultapi.Config{
				BaseURL: f.srv.URL, HTTPClient: f.srv.Client(),
				Tokens: staticTestToken("test-token"), DisableRetry: true,
			})
			require.NoError(t, err)

			deps := Deps{
				Client: client, Config: cfg, Logger: discardLogger(), Version: "test",
				IsServiceAccountIdentity: tc.serviceAccount,
			}
			if tc.allowInteractiveLogin && !tc.serviceAccount {
				// New requires an Identity for exactly this combination,
				// since it is the one where login gets registered.
				deps.Identity = vaultapi.NewSwappableSource(staticTestToken("test"))
			}
			s, err := New(deps)
			require.NoError(t, err)
			RegisterAllTools(s)

			require.Equal(t, tc.wantPresent, contains(s.RegisteredTools(), "login"))
		})
	}
}

func TestGatingTable_LoginAbsentFromDefaultConfiguration(t *testing.T) {
	f := newFakeVault(t, map[string]string{})
	s := f.server(t, testConfig())
	RegisterAllTools(s)
	require.False(t, contains(s.RegisteredTools(), "login"),
		"a config with no mcp section must not expose login")
}
