package container

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/base64"
	"errors"
	"path/filepath"
	"testing"

	"github.com/google/uuid"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	rvdb "rocketvault/internal/db"
	auditServices "rocketvault/internal/services/audit"
	authzServices "rocketvault/internal/services/authorization"
	certServices "rocketvault/internal/services/certificates"
	keyServices "rocketvault/internal/services/keys"
	secretServices "rocketvault/internal/services/secrets"
	userServices "rocketvault/internal/services/users"
	"rocketvault/model"
)

// TestContainer_CriticalSitesRefuseWhenAuditIsDown pins the audit wiring of
// every audit-first service. A service built without the audit service would
// fail open, so each critical operation must be refused once audit_logs is
// gone. Dropping any one wiring line makes its assertion fail.
func TestContainer_CriticalSitesRefuseWhenAuditIsDown(t *testing.T) {
	w := newRenewalWiring(t)
	ctx := context.Background()
	owner := uuid.New()
	scope := model.NewVaultScope(w.vaultID, owner)

	user, err := w.c.GetUserService().CreateUser(ctx, userServices.CreateUserRequest{
		Username: "wiring", Password: "Correct-Horse-Battery-9!",
		Roles: []string{model.RoleUser}, CallerRoles: []string{model.RoleAdmin},
	})
	require.NoError(t, err)
	key, err := w.c.GetKeyService().CreateECDSAKey(ctx, keyServices.CreateKeyRequest{
		Name: "wiring-key", Type: "ECDSA", Curve: "P-256", UserID: owner, VaultID: w.vaultID, Exportable: true,
	})
	require.NoError(t, err)
	cert, err := w.c.GetCertificateService().CreateSelfSignedCertificate(ctx, certServices.CreateCertificateRequest{
		Name: "wiring-cert", KeyID: key.KeyID, ValidityDays: 30, UserID: owner, VaultID: w.vaultID, Exportable: true,
	})
	require.NoError(t, err)
	secret, err := w.c.GetSecretService().CreateSecret(ctx, secretServices.CreateSecretRequest{
		UserID: owner, VaultID: w.vaultID, Name: "wiring-secret", Value: "v",
	})
	require.NoError(t, err)
	require.NoError(t, w.c.GetSecretService().DeleteSecret(ctx, secret.ID, scope))
	_, err = w.c.GetVaultService().CreateVault(ctx, model.CreateVaultRequest{Name: "wiring-vault"}, owner)
	require.NoError(t, err)

	// Every chained write fails from here on.
	_, err = w.raw.ExecContext(ctx, "DROP TABLE audit_logs")
	require.NoError(t, err)

	refused := func(name string, err error) {
		t.Helper()
		assert.True(t, errors.Is(err, auditServices.ErrAuditUnavailable), "%s must be refused, got %v", name, err)
	}
	_, err = w.c.GetKeyService().ExportKey(ctx, scope, key.KeyID, 0)
	refused("key export", err)
	_, err = w.c.GetCertificateService().ExportCertificate(ctx, scope, cert.CertID, certServices.ExportCertificateRequest{Format: model.ExportFormatPEM})
	refused("certificate export", err)
	refused("secret purge", w.c.GetSecretService().PurgeSecret(ctx, secret.ID, scope))
	refused("user delete", w.c.GetUserService().DeleteUser(ctx, user.UserID, owner))
	refused("vault delete", w.c.GetVaultService().DeleteVault(ctx, "wiring-vault", owner))
	_, err = w.c.GetComplianceReportService().PurgeExpiredLogs(ctx)
	refused("audit retention purge", err)
}

// TestContainer_KeyAndRoleSitesRefuseWhenAuditIsDown pins the audit wiring of
// the key lifecycle, wrap and unwrap, role assignments and secret rotation.
// Dropping any one wiring line makes its assertion fail.
func TestContainer_KeyAndRoleSitesRefuseWhenAuditIsDown(t *testing.T) {
	w := newRenewalWiring(t)
	ctx := context.Background()
	user, err := w.c.GetUserService().CreateUser(ctx, userServices.CreateUserRequest{
		Username: "wiring3", Password: "Correct-Horse-Battery-9!",
		Roles: []string{model.RoleUser}, CallerRoles: []string{model.RoleAdmin},
	})
	require.NoError(t, err)
	owner := user.UserID
	scope := model.NewVaultScope(w.vaultID, owner)

	key, err := w.c.GetKeyService().CreateRSAKey(ctx, keyServices.CreateKeyRequest{
		Name: "wiring-rsa", Type: "RSA", Bits: 2048, UserID: owner, VaultID: w.vaultID,
	})
	require.NoError(t, err)
	grant, err := w.c.GetRoleAssignmentService().AssignRole(ctx, authzServices.AssignRoleInput{
		Principal: owner.String(), Role: model.RoleKeyVaultReader, VaultID: w.vaultID,
		CreatedBy: owner, CallerIsGlobalAdmin: true,
	})
	require.NoError(t, err)
	secret, err := w.c.GetSecretService().CreateSecret(ctx, secretServices.CreateSecretRequest{
		UserID: owner, VaultID: w.vaultID, Name: "wiring-rotate", Value: "v1",
	})
	require.NoError(t, err)
	policy, err := w.c.GetRotationService().CreatePolicy(ctx, secretServices.CreatePolicyRequest{
		Scope: scope, Name: "wiring-policy", IntervalDays: 30, Enabled: true,
	})
	require.NoError(t, err)
	require.NoError(t, w.c.GetRotationService().AssignPolicyToSecret(ctx, secretServices.AssignPolicyRequest{
		SecretID: secret.ID, PolicyID: policy.ID, Scope: scope,
	}))

	// Every chained write fails from here on.
	_, err = w.raw.ExecContext(ctx, "DROP TABLE audit_logs")
	require.NoError(t, err)

	refused := func(name string, err error) {
		t.Helper()
		assert.True(t, errors.Is(err, auditServices.ErrAuditUnavailable), "%s must be refused, got %v", name, err)
	}
	keys := w.c.GetKeyService()
	_, err = keys.CreateECDSAKey(ctx, keyServices.CreateKeyRequest{Name: "refused", Curve: "P-256", UserID: owner, VaultID: w.vaultID})
	refused("key create", err)
	_, err = keys.RotateKey(ctx, key.KeyID, scope)
	refused("key rotate", err)
	_, err = keys.DeleteKey(ctx, key.KeyID, scope)
	refused("key delete", err)
	_, err = w.c.GetCryptoService().WrapKey(ctx, keyServices.WrapKeyRequest{
		KeyID: key.KeyID, UserID: owner, Scope: scope, PlaintextKey: []byte("dek"), Algorithm: "RSA-OAEP",
	})
	refused("key wrap", err)
	_, err = w.c.GetCryptoService().UnwrapKey(ctx, keyServices.UnwrapKeyRequest{
		KeyID: key.KeyID, UserID: owner, Scope: scope, WrappedKey: []byte("blob"), Algorithm: "RSA-OAEP",
	})
	refused("key unwrap", err)
	_, err = w.c.GetRoleAssignmentService().AssignRole(ctx, authzServices.AssignRoleInput{
		Principal: owner.String(), Role: model.RoleKeyVaultSecretsUser, VaultID: w.vaultID,
		CreatedBy: owner, CallerIsGlobalAdmin: true,
	})
	refused("role grant", err)
	refused("role revoke", w.c.GetRoleAssignmentService().RevokeAssignment(ctx, grant.ID, w.vaultID, owner, true))
	refused("secret rotation", w.c.GetRotationService().PerformManualRotation(ctx, secretServices.ManualRotationRequest{
		SecretID: secret.ID, PolicyID: policy.ID, Scope: scope, NewValue: "v2",
	}))
}

// TestContainer_SelfPKIRefusesUnauditedKey pins the signing provider's audit
// wiring: with self_pki on a fresh store and audit_logs gone, startup fails
// instead of generating an unaudited JWT signing key.
func TestContainer_SelfPKIRefusesUnauditedKey(t *testing.T) {
	orig := viper.GetString("master_key")
	t.Cleanup(func() { viper.Set("master_key", orig) })
	viper.Set("master_key", base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x31}, 32)))

	raw, err := sql.Open("sqlite3", "file:"+filepath.Join(t.TempDir(), "selfpki.db")+"?_busy_timeout=10000")
	require.NoError(t, err)
	t.Cleanup(func() { _ = raw.Close() })
	cfg := newMinimalConfig(t)
	require.NoError(t, rvdb.NewRepository(cfg.Logger).SetupSchema(raw, rvdb.SQLite))
	_, err = raw.Exec("DROP TABLE audit_logs")
	require.NoError(t, err)
	cfg.Database = raw
	cfg.Viper.Set("jwt.key_source", "self_pki")

	c, err := NewServiceContainer(cfg)
	if c != nil {
		t.Cleanup(func() { _ = c.Close() })
	}

	require.Error(t, err)
	assert.True(t, errors.Is(err, auditServices.ErrAuditUnavailable), "got %v", err)
	var stored int
	require.NoError(t, raw.QueryRow("SELECT COUNT(*) FROM keys").Scan(&stored))
	assert.Zero(t, stored, "no signing key may be stored")
}
