package authorization

import (
	"testing"

	"github.com/google/uuid"

	"rocketvault/model"
)

func TestIsValidRole(t *testing.T) {
	if !IsValidRole("secrets-user") {
		t.Fatal("secrets-user should be valid")
	}
	if IsValidRole("nope") {
		t.Fatal("nope should be invalid")
	}
}

func TestExpandRole_SecretsUser(t *testing.T) {
	vid := uuid.New()
	pid := uuid.New()
	aid := uuid.New()
	policies, err := ExpandRole("secrets-user", pid, model.PrincipalTypeUser, vid, aid)
	if err != nil {
		t.Fatalf("expand: %v", err)
	}
	if len(policies) != 2 { // get, list
		t.Fatalf("expected 2 policies, got %d", len(policies))
	}
	for _, p := range policies {
		if p.ResourceType != model.PolicyResourceSecrets || p.Effect != model.PolicyEffectAllow {
			t.Fatalf("bad policy: %+v", p)
		}
		if p.VaultID == nil || *p.VaultID != vid {
			t.Fatalf("vault not set: %+v", p)
		}
		if p.AssignmentID == nil || *p.AssignmentID != aid {
			t.Fatalf("assignment not set: %+v", p)
		}
	}
}

func TestExpandRole_VaultAdminIncludesManage(t *testing.T) {
	policies, err := ExpandRole("vault-admin", uuid.New(), model.PrincipalTypeUser, uuid.New(), uuid.New())
	if err != nil {
		t.Fatalf("expand: %v", err)
	}
	found := false
	for _, p := range policies {
		if p.ResourceType == model.PolicyResourceVaults && p.Operation == model.OpManage {
			found = true
		}
	}
	if !found {
		t.Fatal("vault-admin must include vaults/manage")
	}
}

func TestExpandRole_Unknown(t *testing.T) {
	if _, err := ExpandRole("nope", uuid.New(), model.PrincipalTypeUser, uuid.New(), uuid.New()); err == nil {
		t.Fatal("expected error for unknown role")
	}
}

func TestBuiltInRoleNames(t *testing.T) {
	names := BuiltInRoleNames()
	want := map[string]bool{"vault-admin": false, "secrets-user": false, "crypto-user": false}
	for _, n := range names {
		if _, ok := want[n]; ok {
			want[n] = true
		}
	}
	for k, seen := range want {
		if !seen {
			t.Fatalf("missing role %q", k)
		}
	}
	for i := 1; i < len(names); i++ {
		if names[i-1] > names[i] {
			t.Fatalf("not sorted: %v", names)
		}
	}
}

func TestRolePermissions(t *testing.T) {
	perms, err := RolePermissions("secrets-user")
	if err != nil || len(perms) == 0 {
		t.Fatalf("expected perms, got %v err=%v", perms, err)
	}
	for _, p := range perms {
		if p[0] != string(model.PolicyResourceSecrets) {
			t.Fatalf("unexpected resource %q", p[0])
		}
		if p[1] == "" {
			t.Fatalf("empty operation in pair %v", p)
		}
	}
	if _, err := RolePermissions("nope"); err == nil {
		t.Fatal("expected error for unknown role")
	}
}

func TestIsValidRole_EdgeCases(t *testing.T) {
	if !IsValidRole("vault-admin") {
		t.Fatal("vault-admin valid")
	}
	if IsValidRole("") {
		t.Fatal("empty invalid")
	}
}

// TestIsValidRole_AcceptsAzureRoles asserts the thirteen Azure built-in role names
// are grantable alongside the legacy vault role vocabulary.
func TestIsValidRole_AcceptsAzureRoles(t *testing.T) {
	for _, role := range []string{
		model.RoleKeyVaultAdministrator,
		model.RoleKeyVaultReader,
		model.RoleKeyVaultSecretsUser,
		model.RoleKeyVaultSecretsOfficer,
		model.RoleKeyVaultCryptoUser,
		model.RoleKeyVaultCryptoOfficer,
		model.RoleKeyVaultCertificatesOfficer,
	} {
		if !IsValidRole(role) {
			t.Fatalf("IsValidRole(%q) = false, want true", role)
		}
	}
	if IsValidRole("Key Vault Owner") {
		t.Fatal("IsValidRole should reject an unknown Azure-looking role")
	}
}

// TestExpandRole_AzureRolesProduceNoPolicies asserts Azure roles materialise no
// access_policies rows. They are evaluated directly from role_assignments; a
// second materialised copy of the same grant could drift.
func TestExpandRole_AzureRolesProduceNoPolicies(t *testing.T) {
	for _, role := range model.AzureRoleNames() {
		policies, err := ExpandRole(role, uuid.New(), model.PrincipalTypeUser, uuid.New(), uuid.New())
		if err != nil {
			t.Fatalf("ExpandRole(%q): %v", role, err)
		}
		if len(policies) != 0 {
			t.Fatalf("ExpandRole(%q) produced %d policies, want 0", role, len(policies))
		}
	}
}

// TestBuiltInRoleNames_IncludesAzureRoles asserts the CLI-facing role list
// covers both vocabularies.
func TestBuiltInRoleNames_IncludesAzureRoles(t *testing.T) {
	names := BuiltInRoleNames()
	have := map[string]bool{}
	for _, n := range names {
		have[n] = true
	}
	for _, n := range append(model.AzureRoleNames(),
		"vault-admin", "vault-reader", "secrets-user", "secrets-officer",
		"crypto-user", "crypto-officer", "certificates-officer") {
		if !have[n] {
			t.Fatalf("BuiltInRoleNames missing %q", n)
		}
	}
	if len(names) != 20 {
		t.Fatalf("want 20 role names (7 legacy + 13 Azure), got %d: %v", len(names), names)
	}
}

// TestRolePermissions_AzureRoleIsEmpty asserts the display helper reports no
// (resource, operation) pairs for an Azure role, since those roles are not
// expressed in the legacy permission vocabulary.
func TestRolePermissions_AzureRoleIsEmpty(t *testing.T) {
	perms, err := RolePermissions(model.RoleKeyVaultAdministrator)
	if err != nil {
		t.Fatalf("RolePermissions: %v", err)
	}
	if len(perms) != 0 {
		t.Fatalf("want 0 legacy permissions for an Azure role, got %d", len(perms))
	}
}
