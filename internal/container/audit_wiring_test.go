package container

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	auditServices "rocketvault/internal/services/audit"
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
