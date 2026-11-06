package container

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/base64"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	rvdb "rocketvault/internal/db"
	authzServices "rocketvault/internal/services/authorization"
	certServices "rocketvault/internal/services/certificates"
	keyServices "rocketvault/internal/services/keys"
	userServices "rocketvault/internal/services/users"
	"rocketvault/model"
)

// renewalWiring drives the real, container-wired renewal scheduler over a
// fully migrated database.
type renewalWiring struct {
	c       *ServiceContainer
	raw     *sql.DB
	vaultID uuid.UUID
}

func newRenewalWiring(t *testing.T) *renewalWiring {
	t.Helper()
	orig := viper.GetString("master_key")
	t.Cleanup(func() { viper.Set("master_key", orig) })
	viper.Set("master_key", base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x24}, 32)))

	dsn := "file:" + filepath.Join(t.TempDir(), "renewal.db") + "?_busy_timeout=10000&_journal_mode=WAL"
	raw, err := sql.Open("sqlite3", dsn)
	require.NoError(t, err)
	t.Cleanup(func() { _ = raw.Close() })

	cfg := newMinimalConfig(t)
	require.NoError(t, rvdb.NewRepository(cfg.Logger).SetupSchema(raw, rvdb.SQLite))
	cfg.Database = raw

	c, err := NewServiceContainer(cfg)
	require.NoError(t, err)
	t.Cleanup(func() { _ = c.Close() })

	return &renewalWiring{c: c, raw: raw, vaultID: uuid.MustParse(model.DefaultVaultID)}
}

// grantSign gives principalID keys/sign in the default vault.
func (w *renewalWiring) grantSign(t *testing.T, principalID uuid.UUID, pType model.PrincipalType) {
	t.Helper()
	_, err := w.c.GetRoleAssignmentService().AssignRole(context.Background(), authzServices.AssignRoleInput{
		Principal:           principalID.String(),
		PrincipalType:       pType,
		Role:                model.RoleKeyVaultCryptoUser,
		VaultID:             w.vaultID,
		CreatedBy:           principalID,
		CallerIsGlobalAdmin: true,
	})
	require.NoError(t, err)
}

// issueAutoRenewCert creates a key and an auto-renewing certificate for ownerID.
func (w *renewalWiring) issueAutoRenewCert(t *testing.T, ownerID uuid.UUID) uuid.UUID {
	t.Helper()
	ctx := context.Background()
	key, err := w.c.GetKeyService().CreateECDSAKey(ctx, keyServices.CreateKeyRequest{
		Name: "key-" + ownerID.String(), Type: "ECDSA", Curve: "P-256", UserID: ownerID, VaultID: w.vaultID,
	})
	require.NoError(t, err)
	cert, err := w.c.GetCertificateService().CreateSelfSignedCertificate(ctx, certServices.CreateCertificateRequest{
		Name: "cert-" + ownerID.String(), KeyID: key.KeyID, ValidityDays: 365,
		UserID: ownerID, VaultID: w.vaultID, AutoRenew: true, RenewalDays: 30,
	})
	require.NoError(t, err)
	return cert.CertID
}

// renewAfterAging moves certID into its renewal window and runs the scheduler.
func (w *renewalWiring) renewAfterAging(t *testing.T, certID uuid.UUID) int {
	t.Helper()
	now := time.Now().UTC()
	_, err := w.raw.ExecContext(context.Background(), "UPDATE certificates SET created_at = ?, expires_at = ? WHERE id = ?",
		now.Add(-355*24*time.Hour), now.Add(10*24*time.Hour), certID.String())
	require.NoError(t, err)
	renewed, _, err := w.c.GetCertificateRenewalService().CheckAndRenewCertificates(context.Background())
	require.NoError(t, err)
	return renewed
}

func (w *renewalWiring) assignmentCount(t *testing.T, principalID uuid.UUID) int {
	t.Helper()
	var n int
	require.NoError(t, w.raw.QueryRowContext(context.Background(), "SELECT COUNT(*) FROM role_assignments WHERE principal_id = ?", principalID.String()).Scan(&n))
	return n
}

// insertStaleGrant recreates the orphan row a delete left behind before B99.
func (w *renewalWiring) insertStaleGrant(t *testing.T, principalID uuid.UUID) {
	t.Helper()
	_, err := w.raw.ExecContext(context.Background(),
		"INSERT INTO role_assignments (id, principal_id, principal_type, role, vault_id, created_by) VALUES (?, ?, ?, ?, ?, ?)",
		uuid.NewString(), principalID.String(), string(model.PrincipalTypeUser), model.RoleKeyVaultCryptoUser, w.vaultID.String(), principalID.String())
	require.NoError(t, err)
}

// TestRenewalScheduler_DeletedUser pins the container wiring for B99. A live
// owner renews, which a scheduler without an owner checker would refuse. A
// deleted owner does not, even with a stale grant left from before the fix.
func TestRenewalScheduler_DeletedUser(t *testing.T) {
	w := newRenewalWiring(t)
	ctx := context.Background()

	user, err := w.c.GetUserService().CreateUser(ctx, userServices.CreateUserRequest{
		Username: "departing", Password: "Correct-Horse-Battery-9!",
		Roles: []string{model.RoleUser}, CallerRoles: []string{model.RoleAdmin},
	})
	require.NoError(t, err)
	w.grantSign(t, user.UserID, model.PrincipalTypeUser)
	certID := w.issueAutoRenewCert(t, user.UserID)

	assert.Equal(t, 1, w.renewAfterAging(t, certID), "a live owner with keys/sign renews")

	require.NoError(t, w.c.GetUserService().DeleteUser(ctx, user.UserID))
	assert.Zero(t, w.assignmentCount(t, user.UserID), "deleting the user removes its grants")
	assert.Zero(t, w.renewAfterAging(t, certID), "no grant remains to renew on")

	w.insertStaleGrant(t, user.UserID)
	assert.Zero(t, w.renewAfterAging(t, certID), "a stale grant does not revive a deleted owner")
}

// TestRenewalScheduler_InactiveServiceAccount covers the service-account half:
// disabled and expired owners stop renewing, and re-enabling restores renewal,
// so the refusal comes from the owner check and not from a side effect. A
// deleted account loses its grants.
func TestRenewalScheduler_InactiveServiceAccount(t *testing.T) {
	w := newRenewalWiring(t)
	ctx := context.Background()

	client, _, err := w.c.GetOAuth2Service().CreateClient(ctx, "renewal-sa", "", nil)
	require.NoError(t, err)
	w.grantSign(t, client.ID, model.PrincipalTypeServiceAccount)
	certID := w.issueAutoRenewCert(t, client.ID)

	assert.Equal(t, 1, w.renewAfterAging(t, certID), "an active service account renews")

	client.Enabled = false
	require.NoError(t, w.c.oauth2ClientRepository.Update(ctx, client))
	assert.Zero(t, w.renewAfterAging(t, certID), "a disabled service account does not renew")

	past := time.Now().Add(-time.Hour)
	client.Enabled, client.ExpiresAt = true, &past
	require.NoError(t, w.c.oauth2ClientRepository.Update(ctx, client))
	assert.Zero(t, w.renewAfterAging(t, certID), "an expired service account does not renew")

	client.ExpiresAt = nil
	require.NoError(t, w.c.oauth2ClientRepository.Update(ctx, client))
	assert.Equal(t, 1, w.renewAfterAging(t, certID), "a reactivated service account renews again")

	require.NoError(t, w.c.GetOAuth2Service().DeleteClient(ctx, client.ID))
	assert.Zero(t, w.assignmentCount(t, client.ID), "deleting the service account removes its grants")

	w.insertStaleGrant(t, client.ID)
	assert.Zero(t, w.renewAfterAging(t, certID), "a stale grant does not revive a deleted service account")
}
