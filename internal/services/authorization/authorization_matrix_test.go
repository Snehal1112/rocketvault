package authorization

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"rocketvault/model"
)

// matrixOp is one data-plane operation, named and addressed by the route that
// performs it. Paths use the vault-scoped shape; the flat shape maps identically.
type matrixOp struct {
	name   string
	method string
	path   string
}

// matrixOps lists every vault data-plane operation exactly once.
//
// Paths use the vault-scoped shape wherever that shape is actually a
// registered route; MapRouteToDataAction maps the flat and vault-scoped
// shapes identically (it strips the "vaults/{name}/" prefix before matching),
// so the two are interchangeable for this test's purposes and the choice
// below tracks what api/*.go actually registers, not what would map cleanly.
// A handful of operations are ONLY reachable at the flat path: per-item
// backup/restore (api/backup_item.go registers on the flat Secrets/Keys/
// Certificates routers only) and the key/certificate deleted-flow (still
// user-scoped, api/soft_delete.go registers those on the flat router only —
// see its InitDeleted doc comment). See also TestAuthorizationMatrixOpsAreRealRoutes
// in router_authorization_matrix_test.go (package api), which walks the real
// router so a future path change here can't drift silently from it again.
var matrixOps = []matrixOp{
	{"secrets.list", http.MethodGet, "/api/v1/vaults/prod/secrets"},
	{"secrets.get", http.MethodGet, "/api/v1/vaults/prod/secrets/abc"},
	{"secrets.create", http.MethodPost, "/api/v1/vaults/prod/secrets"},
	{"secrets.update", http.MethodPut, "/api/v1/vaults/prod/secrets/abc"},
	{"secrets.delete", http.MethodDelete, "/api/v1/vaults/prod/secrets/abc"},
	{"secrets.generate", http.MethodPost, "/api/v1/vaults/prod/secrets/generate"},
	{"secrets.export", http.MethodPost, "/api/v1/vaults/prod/secrets/export"},
	{"secrets.import", http.MethodPost, "/api/v1/vaults/prod/secrets/import"},
	{"secrets.listVersions", http.MethodGet, "/api/v1/vaults/prod/secrets/abc/versions"},
	{"secrets.getVersion", http.MethodGet, "/api/v1/vaults/prod/secrets/abc/versions/3"},
	{"secrets.getLatestVersion", http.MethodGet, "/api/v1/vaults/prod/secrets/abc/versions/latest"},
	{"secrets.backup", http.MethodPost, "/api/v1/secrets/abc/backup"}, // flat only, see doc comment above
	{"secrets.restore", http.MethodPost, "/api/v1/secrets/restore"},   // flat only, see doc comment above
	{"secrets.listDeleted", http.MethodGet, "/api/v1/vaults/prod/deleted/secrets"},
	{"secrets.recover", http.MethodPost, "/api/v1/vaults/prod/deleted/secrets/abc/restore"},
	{"secrets.purge", http.MethodDelete, "/api/v1/vaults/prod/deleted/secrets/abc/purge"},

	{"keys.list", http.MethodGet, "/api/v1/vaults/prod/keys"},
	{"keys.get", http.MethodGet, "/api/v1/vaults/prod/keys/abc"},
	{"keys.create", http.MethodPost, "/api/v1/vaults/prod/keys"},
	{"keys.update", http.MethodPut, "/api/v1/vaults/prod/keys/abc"},
	{"keys.delete", http.MethodDelete, "/api/v1/vaults/prod/keys/abc"},
	{"keys.rotate", http.MethodPost, "/api/v1/vaults/prod/keys/abc/rotate"},
	{"keys.listVersions", http.MethodGet, "/api/v1/vaults/prod/keys/abc/versions"},
	{"keys.getVersion", http.MethodGet, "/api/v1/vaults/prod/keys/abc/versions/1"},
	{"keys.sign", http.MethodPost, "/api/v1/vaults/prod/keys/abc/sign"},
	{"keys.verify", http.MethodPost, "/api/v1/vaults/prod/keys/abc/verify"},
	{"keys.encrypt", http.MethodPost, "/api/v1/vaults/prod/keys/abc/encrypt"},
	{"keys.decrypt", http.MethodPost, "/api/v1/vaults/prod/keys/abc/decrypt"},
	{"keys.wrap", http.MethodPost, "/api/v1/vaults/prod/keys/abc/wrap"},
	{"keys.unwrap", http.MethodPost, "/api/v1/vaults/prod/keys/abc/unwrap"},
	{"keys.getRotationPolicy", http.MethodGet, "/api/v1/vaults/prod/keys/abc/rotationpolicy"},
	{"keys.setRotationPolicy", http.MethodPut, "/api/v1/vaults/prod/keys/abc/rotationpolicy"},
	{"keys.backup", http.MethodPost, "/api/v1/keys/abc/backup"},           // flat only, see doc comment above
	{"keys.restore", http.MethodPost, "/api/v1/keys/restore"},             // flat only, see doc comment above
	{"keys.listDeleted", http.MethodGet, "/api/v1/deleted/keys"},          // flat only, see doc comment above
	{"keys.getDeleted", http.MethodGet, "/api/v1/deleted/keys/abc"},       // flat only, see doc comment above
	{"keys.recover", http.MethodPost, "/api/v1/deleted/keys/abc/restore"}, // flat only, see doc comment above
	{"keys.purge", http.MethodDelete, "/api/v1/deleted/keys/abc/purge"},   // flat only, see doc comment above

	{"certs.list", http.MethodGet, "/api/v1/vaults/prod/certificates"},
	{"certs.get", http.MethodGet, "/api/v1/vaults/prod/certificates/abc"},
	{"certs.create", http.MethodPost, "/api/v1/vaults/prod/certificates"},
	{"certs.update", http.MethodPut, "/api/v1/vaults/prod/certificates/abc"},
	{"certs.delete", http.MethodDelete, "/api/v1/vaults/prod/certificates/abc"},
	{"certs.getPolicy", http.MethodGet, "/api/v1/vaults/prod/certificates/abc/policy"},
	{"certs.setPolicy", http.MethodPut, "/api/v1/vaults/prod/certificates/abc/policy"},
	{"certs.deletePolicy", http.MethodDelete, "/api/v1/vaults/prod/certificates/abc/policy"},
	{"certs.backup", http.MethodPost, "/api/v1/certificates/abc/backup"},           // flat only, see doc comment above
	{"certs.restore", http.MethodPost, "/api/v1/certificates/restore"},             // flat only, see doc comment above
	{"certs.listDeleted", http.MethodGet, "/api/v1/deleted/certificates"},          // flat only, see doc comment above
	{"certs.recover", http.MethodPost, "/api/v1/deleted/certificates/abc/restore"}, // flat only, see doc comment above
	{"certs.purge", http.MethodDelete, "/api/v1/deleted/certificates/abc/purge"},   // flat only, see doc comment above
	{"certs.export", http.MethodPost, "/api/v1/vaults/prod/certificates/abc/export"},
	{"keys.export", http.MethodPost, "/api/v1/vaults/prod/keys/abc/export"},
}

// allSecretOps, allKeyOps and allCertOps are named once so the officer roles
// below read as "everything for this object type".
var (
	allSecretOps = []string{
		"secrets.list", "secrets.get", "secrets.create", "secrets.update",
		"secrets.delete", "secrets.generate", "secrets.export", "secrets.import",
		"secrets.listVersions", "secrets.getVersion", "secrets.getLatestVersion",
		"secrets.backup", "secrets.restore", "secrets.listDeleted",
		"secrets.recover", "secrets.purge",
	}
	allKeyOps = []string{
		"keys.list", "keys.get", "keys.create", "keys.update", "keys.delete",
		"keys.rotate", "keys.listVersions", "keys.getVersion", "keys.sign", "keys.verify",
		"keys.encrypt", "keys.decrypt", "keys.wrap", "keys.unwrap",
		"keys.getRotationPolicy", "keys.setRotationPolicy",
		"keys.backup", "keys.restore", "keys.listDeleted", "keys.getDeleted",
		"keys.recover", "keys.purge",
	}
	allCertOps = []string{
		"certs.list", "certs.get", "certs.create", "certs.update", "certs.delete",
		"certs.getPolicy", "certs.setPolicy", "certs.deletePolicy",
		"certs.backup", "certs.restore", "certs.listDeleted",
		"certs.recover", "certs.purge",
	}
)

// matrixAllowed names, per role, the exact operations that role permits.
// Every operation absent from a role's list is asserted denied.
var matrixAllowed = map[string][]string{
	model.RoleKeyVaultAdministrator: append(append(append(append([]string{},
		allSecretOps...), allKeyOps...), allCertOps...), "certs.export", "keys.export"),

	model.RoleKeyVaultReader: {
		"secrets.list", "secrets.listVersions", "secrets.listDeleted",
		"keys.list", "keys.get", "keys.listVersions", "keys.getVersion", "keys.listDeleted", "keys.getDeleted",
		"certs.list", "certs.get", "certs.getPolicy", "certs.listDeleted",
	},

	model.RoleKeyVaultSecretsUser: {
		"secrets.list", "secrets.get", "secrets.export",
		"secrets.listVersions", "secrets.getVersion", "secrets.getLatestVersion",
		"secrets.listDeleted",
	},

	model.RoleKeyVaultSecretsOfficer: allSecretOps,

	model.RoleKeyVaultCryptoUser: {
		"keys.list", "keys.get", "keys.listVersions", "keys.getVersion", "keys.listDeleted", "keys.getDeleted",
		"keys.sign", "keys.verify", "keys.encrypt", "keys.decrypt",
		"keys.wrap", "keys.unwrap", "keys.update", "keys.backup",
	},

	model.RoleKeyVaultCryptoOfficer: allKeyOps,

	model.RoleKeyVaultCertificatesOfficer: allCertOps,

	model.RoleKeyVaultPurgeOperator: {}, // vault-level operation only, no data-plane operations

	model.RoleKeyVaultCertificateUser: {
		"certs.list", "certs.get", "certs.getPolicy", "certs.listDeleted",
	},

	model.RoleKeyVaultCryptoServiceEncryptionUser: {
		"keys.list", "keys.get", "keys.listVersions", "keys.getVersion", "keys.listDeleted", "keys.getDeleted",
		"keys.wrap", "keys.unwrap",
	},

	model.RoleKeyVaultDataAccessAdministrator: {}, // control-plane operation only, no data-plane operations

	model.RoleKeyVaultCertificateExporter: {"certs.export"},
	model.RoleKeyVaultKeyExporter:         {"keys.export"},
}

// TestAuthorizationMatrix asserts, for every (role, operation) pair, that the
// role's data actions permit exactly the operations named for it and no others.
func TestAuthorizationMatrix(t *testing.T) {
	require.Len(t, matrixAllowed, 13, "all thirteen Azure roles must appear in the matrix")

	for _, role := range model.AzureRoleNames() {
		allowedNames, ok := matrixAllowed[role]
		require.True(t, ok, "role %q missing from the matrix", role)
		allowed := map[string]bool{}
		for _, n := range allowedNames {
			allowed[n] = true
		}

		for _, op := range matrixOps {
			action, kind := MapRouteToDataAction(op.method, op.path)
			require.Equal(t, RouteVaultData, kind, "%s must be a data-plane route", op.name)
			require.NotEmpty(t, action, "%s must map to a data action", op.name)

			got := model.RoleGrantsDataAction(role, action)
			want := allowed[op.name]
			assert.Equal(t, want, got,
				"role %q, operation %s (%s %s, action %s): got allowed=%v want %v",
				role, op.name, op.method, op.path, action, got, want)
		}
	}
}

// TestAuthorizationMatrixCoversEveryOperation asserts the operation list has no
// duplicates and that the officer bundles reference only listed operations, so
// a typo in a role's allow-list cannot silently widen the denied set.
func TestAuthorizationMatrixCoversEveryOperation(t *testing.T) {
	known := map[string]bool{}
	for _, op := range matrixOps {
		require.False(t, known[op.name], "duplicate operation %q", op.name)
		known[op.name] = true
	}
	assert.Len(t, matrixOps, 53)

	for role, names := range matrixAllowed {
		for _, n := range names {
			assert.True(t, known[n], "role %q allows unknown operation %q", role, n)
		}
	}
}

// TestAuthorizationMatrixNoRoleGrantsEverythingButAdministrator asserts only the
// Administrator role covers all three object types.
func TestAuthorizationMatrixNoRoleGrantsEverythingButAdministrator(t *testing.T) {
	for role, names := range matrixAllowed {
		if role == model.RoleKeyVaultAdministrator {
			assert.Len(t, names, 53)
			continue
		}
		assert.Less(t, len(names), 53, "only Key Vault Administrator may grant every operation")
	}
}
