package repositories

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	rvdb "rocketvault/internal/db"
	"rocketvault/internal/logging"
	"rocketvault/model"
)

// TestUpgrade_PreExportDatabaseStaysIntact builds a database with the full
// current schema, populates certificates (with an archived version), keys,
// secrets and role assignments, then drops the exportable columns so it has
// exactly the pre-export shape. Re-running the real schema setup must add the
// columns back as false and leave every existing row intact and readable.
func TestUpgrade_PreExportDatabaseStaysIntact(t *testing.T) {
	path := filepath.Join(t.TempDir(), "pre-export.db")
	raw, err := sql.Open("sqlite3", path)
	require.NoError(t, err)
	raw.SetMaxOpenConns(1)
	t.Cleanup(func() { raw.Close() }) //nolint:errcheck,gosec

	setup := rvdb.NewRepository(logging.InitLogger())
	require.NoError(t, setup.SetupSchema(raw, rvdb.SQLite))
	conn := rvdb.NewConn(raw, rvdb.SQLite)
	log := logging.InitLogger()
	ctx := context.Background()

	vaultID, userID := uuid.MustParse(model.DefaultVaultID), uuid.New()
	scope := model.NewVaultScope(vaultID, userID)
	keys := NewKeyRepository(conn, log)
	certs := NewCertificateRepository(conn, log)
	versions := NewCertificateVersionRepository(conn, log)
	secrets := NewSecretRepository(conn, log)
	roles := NewRoleAssignmentRepository(conn)

	key := &model.Key{ID: uuid.New(), UserID: userID, VaultID: vaultID, Name: "old-key", Type: model.KeyTypeRSA,
		Value: "enc", Enabled: true, CreatedAt: time.Now(), Bits: 2048}
	require.NoError(t, keys.Create(ctx, key))
	cert := &model.Certificate{ID: uuid.New(), UserID: userID, VaultID: vaultID, KeyID: key.ID, Name: "old-cert",
		Certificate: "pem-v2", PrivateKey: "enc-v2", CreatedAt: time.Now(), Enabled: true, Version: 2}
	require.NoError(t, certs.Create(ctx, cert))
	require.NoError(t, versions.CreateVersion(ctx, &model.CertificateVersionRecord{
		CertificateID: cert.ID, Version: 1, Certificate: "pem-v1", PrivateKey: "enc-v1", KeyID: key.ID,
		CreatedAt: time.Now().Add(-time.Hour), Enabled: true,
	}))
	secret := &model.Secret{ID: uuid.New(), UserID: userID, VaultID: vaultID, Name: "old-secret", Value: "enc-s",
		Version: 1, CreatedAt: time.Now(), Enabled: true}
	require.NoError(t, secrets.Create(ctx, secret))
	assignment := &model.RoleAssignment{ID: uuid.New(), PrincipalID: userID, PrincipalType: model.PrincipalTypeUser,
		Role: model.RoleKeyVaultSecretsUser, VaultID: vaultID, CreatedBy: userID}
	require.NoError(t, roles.Create(ctx, assignment))

	// Turn this into a pre-export database.
	_, err = raw.ExecContext(context.Background(), `ALTER TABLE certificates DROP COLUMN exportable`)
	require.NoError(t, err)
	_, err = raw.ExecContext(context.Background(), `ALTER TABLE keys DROP COLUMN exportable`)
	require.NoError(t, err)

	// The upgrade: the same setup production runs on every start.
	require.NoError(t, setup.SetupSchema(raw, rvdb.SQLite))

	gotKey, err := keys.Read(ctx, key.ID, scope)
	require.NoError(t, err)
	assert.Equal(t, "old-key", gotKey.Name)
	assert.Equal(t, "enc", gotKey.Value)
	assert.False(t, gotKey.Exportable)

	gotCert, err := certs.Read(ctx, cert.ID, scope)
	require.NoError(t, err)
	assert.Equal(t, "pem-v2", gotCert.Certificate)
	assert.Equal(t, 2, gotCert.Version)
	assert.False(t, gotCert.Exportable)

	records, err := versions.ListVersionRecords(ctx, cert.ID)
	require.NoError(t, err)
	require.Len(t, records, 1)
	assert.Equal(t, "enc-v1", records[0].PrivateKey)

	gotSecret, err := secrets.Read(ctx, secret.ID, scope)
	require.NoError(t, err)
	assert.Equal(t, "old-secret", gotSecret.Name)

	listed, err := roles.ListByVault(ctx, vaultID)
	require.NoError(t, err)
	require.Len(t, listed, 1)
	assert.Equal(t, model.RoleKeyVaultSecretsUser, listed[0].Role)
}
