package model

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestExportActions_Strings(t *testing.T) {
	assert.Equal(t, DataAction("Microsoft.KeyVault/vaults/certificates/export/action"), ActionCertificatesExportItem)
	assert.Equal(t, DataAction("Microsoft.KeyVault/vaults/keys/export/action"), ActionKeysExport)
}

func TestExporterRoles_GrantOnlyTheirAction(t *testing.T) {
	assert.Equal(t, []DataAction{ActionCertificatesExportItem}, AzureRoleDataActions(RoleKeyVaultCertificateExporter))
	assert.Equal(t, []DataAction{ActionKeysExport}, AzureRoleDataActions(RoleKeyVaultKeyExporter))
	assert.True(t, IsAzureRole(RoleKeyVaultCertificateExporter))
	assert.True(t, IsAzureRole(RoleKeyVaultKeyExporter))
}

func TestAdministrator_GrantsBothExportActions(t *testing.T) {
	assert.True(t, RoleGrantsDataAction(RoleKeyVaultAdministrator, ActionCertificatesExportItem))
	assert.True(t, RoleGrantsDataAction(RoleKeyVaultAdministrator, ActionKeysExport))
}

// preExportBundles is every pre-existing role's bundle exactly as it was
// before export. Only Administrator may differ, and only by the two export
// actions.
var preExportBundles = map[string][]DataAction{
	RoleKeyVaultReader:      {ActionSecretsReadMetadata, ActionKeysRead, ActionCertificatesRead},
	RoleKeyVaultSecretsUser: {ActionSecretsReadMetadata, ActionSecretsGet},
	RoleKeyVaultSecretsOfficer: {ActionSecretsReadMetadata, ActionSecretsGet, ActionSecretsSet,
		ActionSecretsDelete, ActionSecretsBackup, ActionSecretsRestore, ActionSecretsRecover, ActionSecretsPurge},
	RoleKeyVaultCryptoUser: {ActionKeysRead, ActionKeysUpdate, ActionKeysEncrypt, ActionKeysDecrypt,
		ActionKeysWrap, ActionKeysUnwrap, ActionKeysSign, ActionKeysVerify, ActionKeysBackup},
	RoleKeyVaultCryptoOfficer: {ActionKeysRead, ActionKeysCreate, ActionKeysUpdate, ActionKeysDelete,
		ActionKeysBackup, ActionKeysRestore, ActionKeysRecover, ActionKeysPurge, ActionKeysImport, ActionKeysRotate,
		ActionKeysEncrypt, ActionKeysDecrypt, ActionKeysWrap, ActionKeysUnwrap, ActionKeysSign, ActionKeysVerify,
		ActionKeysRotationPolicyRead, ActionKeysRotationPolicyWrite},
	RoleKeyVaultCertificatesOfficer: {ActionCertificatesRead, ActionCertificatesCreate, ActionCertificatesUpdate,
		ActionCertificatesDelete, ActionCertificatesBackup, ActionCertificatesRestore, ActionCertificatesRecover,
		ActionCertificatesPurge},
	RoleKeyVaultPurgeOperator:               {ActionVaultPurge},
	RoleKeyVaultCertificateUser:             {ActionCertificatesRead},
	RoleKeyVaultCryptoServiceEncryptionUser: {ActionKeysRead, ActionKeysWrap, ActionKeysUnwrap},
	RoleKeyVaultDataAccessAdministrator:     {ActionRoleAssignmentsWrite, ActionRoleAssignmentsDelete},
}

// TestPreExistingRoles_DataActionsUnchanged is the regression gate: no role
// that existed before export gains any action, and only Administrator gains
// the two export actions.
func TestPreExistingRoles_DataActionsUnchanged(t *testing.T) {
	for role, want := range preExportBundles {
		assert.ElementsMatch(t, want, AzureRoleDataActions(role), "role %q changed", role)
		assert.False(t, RoleGrantsDataAction(role, ActionCertificatesExportItem), "role %q must not export certificates", role)
		assert.False(t, RoleGrantsDataAction(role, ActionKeysExport), "role %q must not export keys", role)
	}
	admin := AzureRoleDataActions(RoleKeyVaultAdministrator)
	assert.Len(t, admin, 36, "34 pre-existing actions plus the two export actions")
}
