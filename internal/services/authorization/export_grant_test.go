package authorization

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"rocketvault/model"
)

func TestExporterRoles_OnlyGlobalAdminCanGrantOrRevoke(t *testing.T) {
	for _, role := range []string{model.RoleKeyVaultCertificateExporter, model.RoleKeyVaultKeyExporter} {
		rr, pr := newFakeRoleRepo(), newFakePolicyRepo()
		ul := &fakeUserLookup{users: map[string]model.User{"alice": {ID: uuid.New(), Username: "alice"}}}
		svc := newSvc(rr, pr, ul)
		vaultID := uuid.New()

		_, err := svc.AssignRole(context.Background(), AssignRoleInput{
			Principal: "alice", PrincipalType: model.PrincipalTypeUser, Role: role,
			VaultID: vaultID, CreatedBy: uuid.New(), CallerIsGlobalAdmin: false,
		})
		require.ErrorIs(t, err, ErrRoleNotGrantable, role)

		granted, err := svc.AssignRole(context.Background(), AssignRoleInput{
			Principal: "alice", PrincipalType: model.PrincipalTypeUser, Role: role,
			VaultID: vaultID, CreatedBy: uuid.New(), CallerIsGlobalAdmin: true,
		})
		require.NoError(t, err, role)

		err = svc.RevokeAssignment(context.Background(), granted.ID, vaultID, false)
		require.ErrorIs(t, err, ErrRoleNotGrantable, role)
		require.NoError(t, svc.RevokeAssignment(context.Background(), granted.ID, vaultID, true), role)
	}
}
