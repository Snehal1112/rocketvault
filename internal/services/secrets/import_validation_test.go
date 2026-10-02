package secrets_test

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"rocketvault/internal/repositories"
	"rocketvault/internal/services/secrets"
	"rocketvault/model"
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
	// The rejected value must never be echoed back to the caller.
	assert.NotContains(t, strings.Join(result.Errors, "\n"), strings.Repeat("x", 64))

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

// driverFailingSecretRepo wraps the real repository and fails chosen names
// with raw driver-style errors, the kind that must never reach a client.
type driverFailingSecretRepo struct {
	repositories.SecretRepositoryInterface
}

func (r *driverFailingSecretRepo) FindByName(ctx context.Context, name string, scope model.Scope) (*model.Secret, error) {
	if name == "lookup-fails" {
		return nil, errors.New("database is locked (SQLITE_BUSY)")
	}
	return r.SecretRepositoryInterface.FindByName(ctx, name, scope)
}

func (r *driverFailingSecretRepo) Create(ctx context.Context, secret *model.Secret) error {
	switch secret.Name {
	case "dup-name":
		return fmt.Errorf("secret %q: %w: %w", secret.Name, repositories.ErrNameTaken,
			errors.New("UNIQUE constraint failed: secrets.vault_id, secrets.name"))
	case "create-fails":
		return errors.New("pq: could not serialize access due to concurrent update")
	}
	return r.SecretRepositoryInterface.Create(ctx, secret)
}

func (r *driverFailingSecretRepo) Update(ctx context.Context, secret *model.Secret, scope model.Scope) error {
	if secret.Name == "overwrite-fails" {
		return errors.New("pq: deadlock detected")
	}
	return r.SecretRepositoryInterface.Update(ctx, secret, scope)
}

// TestImportSecrets_ErrorsCarryNoDriverText pins I1: per-item failures reach
// the HTTP body and the CLI, so they must be fixed classes, not raw errors.
func TestImportSecrets_ErrorsCarryNoDriverText(t *testing.T) {
	ctx := context.Background()
	f := newImportFixture(t)

	// Seed the secret the overwrite path will fail to update.
	_, err := f.secretSvc.ImportSecrets(ctx, secrets.ImportSecretsRequest{
		Scope: f.scope(), Format: "json",
		Data: marshalRecords(t, importRecord{Name: "overwrite-fails", Value: "v1"}),
	})
	require.NoError(t, err)

	svc := secrets.NewSecretService(secrets.SecretServiceConfig{
		SecretRepository: &driverFailingSecretRepo{SecretRepositoryInterface: f.secretRepo},
		CryptoService:    f.crypto,
		VersionService:   f.versionSvc,
		TagService:       f.tagSvc,
		Logger:           f.log,
	})

	result, err := svc.ImportSecrets(ctx, secrets.ImportSecretsRequest{
		Scope: f.scope(), Format: "json", Overwrite: true,
		Data: marshalRecords(t,
			importRecord{Name: "dup-name", Value: "dup-value"},
			importRecord{Name: "lookup-fails", Value: "lookup-value"},
			importRecord{Name: "create-fails", Value: "create-value"},
			importRecord{Name: "overwrite-fails", Value: "overwrite-value"},
			importRecord{Name: "big-value", Value: strings.Repeat("x", 25601)},
		),
	})
	require.NoError(t, err)
	assert.Equal(t, 5, result.FailedCount)
	require.Len(t, result.Errors, 5)

	joined := strings.Join(result.Errors, "\n")
	assert.Contains(t, result.Errors, "'dup-name': name already exists")
	assert.Contains(t, result.Errors, "'lookup-fails': internal error")
	assert.Contains(t, result.Errors, "'create-fails': internal error")
	assert.Contains(t, result.Errors, "'overwrite-fails': internal error")
	for _, leaked := range []string{"UNIQUE", "constraint", "SQLITE_BUSY", "database is locked", "pq:", "deadlock", "serialize"} {
		assert.NotContains(t, joined, leaked)
	}
	for _, value := range []string{"dup-value", "lookup-value", "create-value", "overwrite-value", strings.Repeat("x", 64)} {
		assert.NotContains(t, joined, value)
	}
}
