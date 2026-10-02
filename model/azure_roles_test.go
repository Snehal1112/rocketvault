package model

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestAzureRoleNames asserts the exact thirteen built-in data-plane roles, sorted.
func TestAzureRoleNames(t *testing.T) {
	assert.Equal(t, []string{
		"Key Vault Administrator",
		"Key Vault Certificate Exporter",
		"Key Vault Certificate User",
		"Key Vault Certificates Officer",
		"Key Vault Crypto Officer",
		"Key Vault Crypto Service Encryption User",
		"Key Vault Crypto User",
		"Key Vault Data Access Administrator",
		"Key Vault Key Exporter",
		"Key Vault Purge Operator",
		"Key Vault Reader",
		"Key Vault Secrets Officer",
		"Key Vault Secrets User",
	}, AzureRoleNames())
}

// TestIsAzureRole accepts the thirteen names and rejects everything else,
// including the legacy vault role vocabulary and case variations.
func TestIsAzureRole(t *testing.T) {
	for _, name := range AzureRoleNames() {
		assert.True(t, IsAzureRole(name), "expected %q to be an Azure role", name)
	}
	for _, name := range []string{"", "vault-admin", "secrets-officer", "admin",
		"key vault administrator", "Key Vault Owner"} {
		assert.False(t, IsAzureRole(name), "expected %q not to be an Azure role", name)
	}
}

// TestAzureRoleDataActions pins the exact grant of every role. Any change to a
// role's bundle must change this table too.
func TestAzureRoleDataActions(t *testing.T) {
	cases := map[string][]DataAction{
		RoleKeyVaultReader: {
			ActionSecretsReadMetadata,
			ActionKeysRead,
			ActionCertificatesRead,
		},
		RoleKeyVaultSecretsUser: {
			ActionSecretsReadMetadata,
			ActionSecretsGet,
		},
		RoleKeyVaultSecretsOfficer: {
			ActionSecretsReadMetadata, ActionSecretsGet, ActionSecretsSet,
			ActionSecretsDelete, ActionSecretsBackup, ActionSecretsRestore,
			ActionSecretsRecover, ActionSecretsPurge,
		},
		RoleKeyVaultCryptoUser: {
			ActionKeysRead, ActionKeysUpdate, ActionKeysEncrypt, ActionKeysDecrypt,
			ActionKeysWrap, ActionKeysUnwrap, ActionKeysSign, ActionKeysVerify,
			ActionKeysBackup,
		},
		RoleKeyVaultCryptoOfficer: {
			ActionKeysRead, ActionKeysCreate, ActionKeysUpdate, ActionKeysDelete,
			ActionKeysBackup, ActionKeysRestore, ActionKeysRecover, ActionKeysPurge,
			ActionKeysImport, ActionKeysRotate, ActionKeysEncrypt, ActionKeysDecrypt,
			ActionKeysWrap, ActionKeysUnwrap, ActionKeysSign, ActionKeysVerify,
			ActionKeysRotationPolicyRead, ActionKeysRotationPolicyWrite,
		},
		RoleKeyVaultCertificatesOfficer: {
			ActionCertificatesRead, ActionCertificatesCreate, ActionCertificatesUpdate,
			ActionCertificatesDelete, ActionCertificatesBackup, ActionCertificatesRestore,
			ActionCertificatesRecover, ActionCertificatesPurge,
		},
	}
	for role, want := range cases {
		assert.ElementsMatch(t, want, AzureRoleDataActions(role), "role %q", role)
	}

	// Administrator holds every action any other role holds, except for the
	// two roles that intentionally hold actions outside Administrator's scope:
	// RoleKeyVaultPurgeOperator (vault purge) and RoleKeyVaultDataAccessAdministrator
	// (role assignment management). These exist as separate roles precisely because
	// Administrator doesn't have those permissions in Azure. All other roles grant
	// actions already covered by Administrator's 36 data-plane actions.
	var union []DataAction
	seen := map[DataAction]bool{}
	for _, role := range AzureRoleNames() {
		if role == RoleKeyVaultAdministrator || role == RoleKeyVaultPurgeOperator || role == RoleKeyVaultDataAccessAdministrator {
			continue
		}
		for _, a := range AzureRoleDataActions(role) {
			if !seen[a] {
				seen[a] = true
				union = append(union, a)
			}
		}
	}
	admin := AzureRoleDataActions(RoleKeyVaultAdministrator)
	assert.Len(t, admin, 36, "administrator must grant all 36 data actions")
	for _, a := range union {
		assert.Contains(t, admin, a)
	}
}

// TestAzureRoleDataActionsUnknownRole returns an empty slice, never nil-panics.
func TestAzureRoleDataActionsUnknownRole(t *testing.T) {
	assert.Empty(t, AzureRoleDataActions("vault-admin"))
	assert.Empty(t, AzureRoleDataActions(""))
}

// TestAzureRoleDataActionsIsACopy proves the caller cannot mutate the table.
func TestAzureRoleDataActionsIsACopy(t *testing.T) {
	got := AzureRoleDataActions(RoleKeyVaultSecretsUser)
	require.Len(t, got, 2)
	got[0] = "tampered"
	assert.Equal(t, ActionSecretsReadMetadata, AzureRoleDataActions(RoleKeyVaultSecretsUser)[0])
}

// TestRoleGrantsDataAction covers the allow and deny directions and the
// fail-closed cases: unknown role, empty role, empty action.
func TestRoleGrantsDataAction(t *testing.T) {
	assert.True(t, RoleGrantsDataAction(RoleKeyVaultSecretsUser, ActionSecretsGet))
	assert.False(t, RoleGrantsDataAction(RoleKeyVaultSecretsUser, ActionSecretsSet))
	assert.True(t, RoleGrantsDataAction(RoleKeyVaultCryptoUser, ActionKeysSign))
	assert.False(t, RoleGrantsDataAction(RoleKeyVaultCryptoUser, ActionKeysCreate))
	assert.True(t, RoleGrantsDataAction(RoleKeyVaultAdministrator, ActionCertificatesPurge))
	assert.False(t, RoleGrantsDataAction("vault-admin", ActionSecretsGet))
	assert.False(t, RoleGrantsDataAction("", ActionSecretsGet))
	assert.False(t, RoleGrantsDataAction(RoleKeyVaultAdministrator, ""))
}

func TestNewDataActionConstants_MatchAzureStrings(t *testing.T) {
	cases := []struct {
		name string
		got  DataAction
		want DataAction
	}{
		{"vault purge", ActionVaultPurge, "Microsoft.KeyVault/vaults/purge/action"},
		{"role assignments write", ActionRoleAssignmentsWrite, "Microsoft.Authorization/roleAssignments/write"},
		{"role assignments delete", ActionRoleAssignmentsDelete, "Microsoft.Authorization/roleAssignments/delete"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if c.got != c.want {
				t.Fatalf("got %q, want %q", c.got, c.want)
			}
		})
	}
}

func TestNewRoles_AreAzureRoles(t *testing.T) {
	for _, role := range []string{
		RoleKeyVaultPurgeOperator,
		RoleKeyVaultCertificateUser,
		RoleKeyVaultCryptoServiceEncryptionUser,
		RoleKeyVaultDataAccessAdministrator,
	} {
		if !IsAzureRole(role) {
			t.Errorf("IsAzureRole(%q) = false, want true", role)
		}
	}
}

func TestRoleKeyVaultPurgeOperator_GrantsOnlyVaultPurge(t *testing.T) {
	actions := AzureRoleDataActions(RoleKeyVaultPurgeOperator)
	if len(actions) != 1 || actions[0] != ActionVaultPurge {
		t.Fatalf("got %v, want [%q]", actions, ActionVaultPurge)
	}
	if RoleGrantsDataAction(RoleKeyVaultPurgeOperator, ActionSecretsGet) {
		t.Fatal("Purge Operator must not grant secret access")
	}
}

func TestRoleKeyVaultCertificateUser_GrantsOnlyCertificatesRead(t *testing.T) {
	actions := AzureRoleDataActions(RoleKeyVaultCertificateUser)
	if len(actions) != 1 || actions[0] != ActionCertificatesRead {
		t.Fatalf("got %v, want [%q]", actions, ActionCertificatesRead)
	}
}

func TestRoleKeyVaultCryptoServiceEncryptionUser_GrantsReadWrapUnwrapOnly(t *testing.T) {
	want := map[DataAction]bool{ActionKeysRead: true, ActionKeysWrap: true, ActionKeysUnwrap: true}
	actions := AzureRoleDataActions(RoleKeyVaultCryptoServiceEncryptionUser)
	if len(actions) != len(want) {
		t.Fatalf("got %d actions, want %d: %v", len(actions), len(want), actions)
	}
	for _, a := range actions {
		if !want[a] {
			t.Errorf("unexpected action %q", a)
		}
	}
	for _, denied := range []DataAction{ActionKeysEncrypt, ActionKeysDecrypt, ActionKeysSign, ActionKeysVerify} {
		if RoleGrantsDataAction(RoleKeyVaultCryptoServiceEncryptionUser, denied) {
			t.Errorf("Crypto Service Encryption User must not grant %q", denied)
		}
	}
}

func TestRoleKeyVaultDataAccessAdministrator_GrantsRoleAssignmentActionsOnly(t *testing.T) {
	want := map[DataAction]bool{ActionRoleAssignmentsWrite: true, ActionRoleAssignmentsDelete: true}
	actions := AzureRoleDataActions(RoleKeyVaultDataAccessAdministrator)
	if len(actions) != len(want) {
		t.Fatalf("got %d actions, want %d: %v", len(actions), len(want), actions)
	}
	for _, a := range actions {
		if !want[a] {
			t.Errorf("unexpected action %q", a)
		}
	}
	if RoleGrantsDataAction(RoleKeyVaultDataAccessAdministrator, ActionSecretsGet) {
		t.Fatal("Data Access Administrator must not grant any secrets/keys/certificates action")
	}
}

func TestAzureRoleNames_IncludesAllThirteenGrantableRoles(t *testing.T) {
	names := AzureRoleNames()
	if len(names) != 13 {
		t.Fatalf("got %d role names, want 13: %v", len(names), names)
	}
}

func TestReleaseUser_IsNotAnAzureRole(t *testing.T) {
	if IsAzureRole("Key Vault Crypto Service Release User") {
		t.Fatal("Key Vault Crypto Service Release User must not be grantable: RocketVault has no confidential-compute/TEE attestation flow to gate")
	}
}
