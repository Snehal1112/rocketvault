package secrets_test

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"rocketvault/common"
	"rocketvault/internal/services/secrets"
)

func TestExportSecrets_SkipsDisabledExpiredAndNotYetActive(t *testing.T) {
	ctx := context.Background()
	f := newImportFixture(t)
	off, past, future := false, time.Now().Add(-time.Hour), time.Now().Add(time.Hour)
	mk := func(name, value string, enabled *bool, exp, nbf *time.Time) {
		_, err := f.secretSvc.CreateSecret(ctx, secrets.CreateSecretRequest{
			UserID: f.userID, VaultID: f.vaultID, Name: name, Value: value,
			Enabled: enabled, ExpiresAt: exp, NotBefore: nbf,
		})
		require.NoError(t, err)
	}
	mk("live-secret", "live-value", nil, nil, nil)
	mk("disabled-secret", "disabled-value", &off, nil, nil)
	mk("expired-secret", "expired-value", nil, &past, nil)
	mk("future-secret", "future-value", nil, nil, &future)

	check := func(t *testing.T, data []byte, label string) {
		t.Helper()
		assert.Contains(t, string(data), "live-value", label)
		assert.NotContains(t, string(data), "disabled-value", label)
		assert.NotContains(t, string(data), "expired-value", label)
		assert.NotContains(t, string(data), "future-value", label)
	}

	for _, format := range []string{"json", "csv"} {
		data, err := f.secretSvc.ExportSecrets(ctx, secrets.ExportSecretsRequest{Scope: f.scope(), Format: format})
		require.NoError(t, err)
		check(t, data, format)

		sealed, err := f.secretSvc.ExportSecrets(ctx, secrets.ExportSecretsRequest{
			Scope: f.scope(), Format: format, Encrypt: true, Passphrase: "pass-phrase-123",
		})
		require.NoError(t, err)
		plain, err := common.OpenExport(sealed, "pass-phrase-123")
		require.NoError(t, err)
		check(t, plain, "sealed "+format)
	}

	data, err := f.secretSvc.ExportSecrets(ctx, secrets.ExportSecretsRequest{Scope: f.scope(), Format: "json"})
	require.NoError(t, err)
	var got []map[string]any
	require.NoError(t, json.Unmarshal(data, &got))
	assert.Len(t, got, 1)
}
