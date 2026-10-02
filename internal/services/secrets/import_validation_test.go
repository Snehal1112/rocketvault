package secrets_test

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"rocketvault/internal/services/secrets"
)

func TestImportSecrets_ValidatesEachItem_JSON(t *testing.T) {
	ctx := context.Background()
	f := newImportFixture(t)

	tooMany := make([]string, 16)
	for i := range tooMany {
		tooMany[i] = fmt.Sprintf("tag%d", i)
	}
	data := marshalRecords(t,
		importRecord{Name: "good-secret", Value: "ok"},
		importRecord{Name: "1-bad-name", Value: "ok"},
		importRecord{Name: "big-value", Value: strings.Repeat("x", 25601)},
		importRecord{Name: "many-tags", Value: "ok", Tags: tooMany},
		importRecord{Name: "edge-value", Value: strings.Repeat("x", 25600)},
	)

	result, err := f.secretSvc.ImportSecrets(ctx, secrets.ImportSecretsRequest{Scope: f.scope(), Format: "json", Data: data})
	require.NoError(t, err)
	assert.Equal(t, 2, result.ImportedCount, "good-secret and the 25600-byte edge value")
	assert.Equal(t, 3, result.FailedCount)
	require.Len(t, result.Errors, 3)
	assert.Contains(t, strings.Join(result.Errors, "\n"), "1-bad-name")
	assert.Contains(t, strings.Join(result.Errors, "\n"), "big-value")
	assert.Contains(t, strings.Join(result.Errors, "\n"), "many-tags")

	_, err = f.secretRepo.FindByName(ctx, "1-bad-name", f.scope())
	assert.Error(t, err, "an invalid record must not be stored")
}

func TestImportSecrets_ValidatesEachItem_CSV(t *testing.T) {
	ctx := context.Background()
	f := newImportFixture(t)
	csvData := "name,value\ngood-secret,ok\nbad_name_underscore,ok\n"

	result, err := f.secretSvc.ImportSecrets(ctx, secrets.ImportSecretsRequest{Scope: f.scope(), Format: "csv", Data: []byte(csvData)})
	require.NoError(t, err)
	assert.Equal(t, 1, result.ImportedCount)
	assert.Equal(t, 1, result.FailedCount)
}

// Overwrite takes the update path, which must be validated too.
func TestImportSecrets_OverwriteValidatesValueSize(t *testing.T) {
	ctx := context.Background()
	f := newImportFixture(t)
	_, err := f.secretSvc.ImportSecrets(ctx, secrets.ImportSecretsRequest{
		Scope: f.scope(), Format: "json", Data: marshalRecords(t, importRecord{Name: "db-password", Value: "v1"}),
	})
	require.NoError(t, err)

	result, err := f.secretSvc.ImportSecrets(ctx, secrets.ImportSecretsRequest{
		Scope: f.scope(), Format: "json", Overwrite: true,
		Data: marshalRecords(t, importRecord{Name: "db-password", Value: strings.Repeat("x", 25601)}),
	})
	require.NoError(t, err)
	assert.Equal(t, 0, result.ImportedCount)
	assert.Equal(t, 1, result.FailedCount)
}
