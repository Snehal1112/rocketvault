package secrets_test

import (
	"context"
	"encoding/csv"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"rocketvault/internal/services/secrets"
)

func TestCSVExportImport_FormulaValuesRoundTripAndAreGuarded(t *testing.T) {
	ctx := context.Background()
	f := newImportFixture(t)
	for name, value := range map[string]string{"dash-secret": "-dash", "eq-secret": "=1+1", "quote-secret": "'lead"} {
		_, err := f.secretSvc.CreateSecret(ctx, secrets.CreateSecretRequest{UserID: f.userID, VaultID: f.vaultID, Name: name, Value: value})
		require.NoError(t, err)
	}

	data, err := f.secretSvc.ExportSecrets(ctx, secrets.ExportSecretsRequest{Scope: f.scope(), Format: "csv"})
	require.NoError(t, err)
	assert.Contains(t, string(data), "'=1+1")
	assert.NotContains(t, string(data), ",=1+1")

	g := newImportFixture(t)
	result, err := g.secretSvc.ImportSecrets(ctx, secrets.ImportSecretsRequest{Scope: g.scope(), Format: "csv", Data: data})
	require.NoError(t, err)
	assert.Equal(t, 3, result.ImportedCount)
	got, err := g.secretSvc.ListSecrets(ctx, g.scope(), nil, 0, 0)
	require.NoError(t, err)
	values := map[string]string{}
	for _, s := range got {
		values[s.Name] = s.Value
	}
	assert.Equal(t, "-dash", values["dash-secret"])
	assert.Equal(t, "=1+1", values["eq-secret"])
	assert.Equal(t, "'lead", values["quote-secret"])
}

func TestCSVExportImport_TrickyValuesRoundTripExactly(t *testing.T) {
	ctx := context.Background()
	values := []string{
		"=1+1", "+cmd", "-2", "@SUM(A1)", "\ttab", "'quote", "''two", `say "hi"`,
		"a,b,c", "line1\nline2", "=a,\"b\"\nc", "unicode-é世界", "plain", "a=b",
	}
	f := newImportFixture(t)
	names := map[string]string{}
	for i, v := range values {
		name := "tricky-" + strings.Repeat("a", i+1)
		names[name] = v
		_, err := f.secretSvc.CreateSecret(ctx, secrets.CreateSecretRequest{UserID: f.userID, VaultID: f.vaultID, Name: name, Value: v})
		require.NoError(t, err, v)
	}

	data, err := f.secretSvc.ExportSecrets(ctx, secrets.ExportSecretsRequest{Scope: f.scope(), Format: "csv"})
	require.NoError(t, err)

	// No exported cell may begin with a formula trigger.
	records, err := csv.NewReader(strings.NewReader(string(data))).ReadAll()
	require.NoError(t, err)
	for _, rec := range records[1:] {
		for _, cell := range rec {
			if cell != "" {
				assert.NotContains(t, "=+-@\t", cell[:1], "unguarded cell %q", cell)
			}
		}
	}

	g := newImportFixture(t)
	result, err := g.secretSvc.ImportSecrets(ctx, secrets.ImportSecretsRequest{Scope: g.scope(), Format: "csv", Data: data})
	require.NoError(t, err)
	assert.Equal(t, len(values), result.ImportedCount, strings.Join(result.Errors, "; "))
	got, err := g.secretSvc.ListSecrets(ctx, g.scope(), nil, 0, 0)
	require.NoError(t, err)
	gotValues := map[string]string{}
	for _, s := range got {
		gotValues[s.Name] = s.Value
	}
	for name, want := range names {
		assert.Equal(t, want, gotValues[name], name)
	}
}
