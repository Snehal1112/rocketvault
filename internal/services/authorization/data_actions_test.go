package authorization

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"

	"rocketvault/model"
)

// TestMapRouteToDataAction covers every registered resource route in both its
// flat and its vault-scoped shape. Both shapes map to the same action: the
// vault identity comes from the resolved vault in the request context, never
// from this string. The pre-P2 behaviour collapsed the vault-scoped shape onto
// a global permission, which is exactly what this replaces.
func TestMapRouteToDataAction(t *testing.T) {
	cases := []struct {
		name   string
		method string
		path   string
		want   model.DataAction
		kind   RouteKind
	}{
		// Secrets.
		{"list secrets", http.MethodGet, "/api/v1/secrets", model.ActionSecretsReadMetadata, RouteVaultData},
		{"create secret", http.MethodPost, "/api/v1/secrets", model.ActionSecretsSet, RouteVaultData},
		{"get secret", http.MethodGet, "/api/v1/secrets/abc", model.ActionSecretsGet, RouteVaultData},
		{"update secret", http.MethodPut, "/api/v1/secrets/abc", model.ActionSecretsSet, RouteVaultData},
		{"delete secret", http.MethodDelete, "/api/v1/secrets/abc", model.ActionSecretsDelete, RouteVaultData},
		{"generate secret", http.MethodPost, "/api/v1/secrets/generate", model.ActionSecretsSet, RouteVaultData},
		{"import secrets", http.MethodPost, "/api/v1/secrets/import", model.ActionSecretsSet, RouteVaultData},
		{"export secrets", http.MethodPost, "/api/v1/secrets/export", model.ActionSecretsGet, RouteVaultData},
		{"list secret versions", http.MethodGet, "/api/v1/secrets/abc/versions", model.ActionSecretsReadMetadata, RouteVaultData},
		{"get secret version", http.MethodGet, "/api/v1/secrets/abc/versions/3", model.ActionSecretsGet, RouteVaultData},
		{"get latest secret version", http.MethodGet, "/api/v1/secrets/abc/versions/latest", model.ActionSecretsGet, RouteVaultData},
		{"backup secret", http.MethodPost, "/api/v1/secrets/abc/backup", model.ActionSecretsBackup, RouteVaultData},
		{"restore secret", http.MethodPost, "/api/v1/secrets/restore", model.ActionSecretsRestore, RouteVaultData},
		{"list deleted secrets", http.MethodGet, "/api/v1/deleted/secrets", model.ActionSecretsReadMetadata, RouteVaultData},
		{"recover secret", http.MethodPost, "/api/v1/deleted/secrets/abc/restore", model.ActionSecretsRecover, RouteVaultData},
		{"purge secret", http.MethodDelete, "/api/v1/deleted/secrets/abc/purge", model.ActionSecretsPurge, RouteVaultData},

		// Keys.
		{"list keys", http.MethodGet, "/api/v1/keys", model.ActionKeysRead, RouteVaultData},
		{"create key", http.MethodPost, "/api/v1/keys", model.ActionKeysCreate, RouteVaultData},
		{"get key", http.MethodGet, "/api/v1/keys/abc", model.ActionKeysRead, RouteVaultData},
		{"update key", http.MethodPut, "/api/v1/keys/abc", model.ActionKeysUpdate, RouteVaultData},
		{"delete key", http.MethodDelete, "/api/v1/keys/abc", model.ActionKeysDelete, RouteVaultData},
		{"rotate key", http.MethodPost, "/api/v1/keys/abc/rotate", model.ActionKeysRotate, RouteVaultData},
		{"list key versions", http.MethodGet, "/api/v1/keys/abc/versions", model.ActionKeysRead, RouteVaultData},
		{"wrap", http.MethodPost, "/api/v1/keys/abc/wrap", model.ActionKeysWrap, RouteVaultData},
		{"unwrap", http.MethodPost, "/api/v1/keys/abc/unwrap", model.ActionKeysUnwrap, RouteVaultData},
		{"sign", http.MethodPost, "/api/v1/keys/abc/sign", model.ActionKeysSign, RouteVaultData},
		{"verify", http.MethodPost, "/api/v1/keys/abc/verify", model.ActionKeysVerify, RouteVaultData},
		{"encrypt", http.MethodPost, "/api/v1/keys/abc/encrypt", model.ActionKeysEncrypt, RouteVaultData},
		{"decrypt", http.MethodPost, "/api/v1/keys/abc/decrypt", model.ActionKeysDecrypt, RouteVaultData},
		{"backup key", http.MethodPost, "/api/v1/keys/abc/backup", model.ActionKeysBackup, RouteVaultData},
		{"restore key", http.MethodPost, "/api/v1/keys/restore", model.ActionKeysRestore, RouteVaultData},
		{"import key", http.MethodPost, "/api/v1/keys/import", model.ActionKeysImport, RouteVaultData},
		{"list deleted keys", http.MethodGet, "/api/v1/deleted/keys", model.ActionKeysRead, RouteVaultData},
		{"get deleted key", http.MethodGet, "/api/v1/deleted/keys/abc", model.ActionKeysRead, RouteVaultData},
		{"recover key", http.MethodPost, "/api/v1/deleted/keys/abc/restore", model.ActionKeysRecover, RouteVaultData},
		{"purge key", http.MethodDelete, "/api/v1/deleted/keys/abc/purge", model.ActionKeysPurge, RouteVaultData},

		// Certificates.
		{"list certificates", http.MethodGet, "/api/v1/certificates", model.ActionCertificatesRead, RouteVaultData},
		{"create certificate", http.MethodPost, "/api/v1/certificates", model.ActionCertificatesCreate, RouteVaultData},
		{"get certificate", http.MethodGet, "/api/v1/certificates/abc", model.ActionCertificatesRead, RouteVaultData},
		{"update certificate", http.MethodPut, "/api/v1/certificates/abc", model.ActionCertificatesUpdate, RouteVaultData},
		{"delete certificate", http.MethodDelete, "/api/v1/certificates/abc", model.ActionCertificatesDelete, RouteVaultData},
		{"get certificate policy", http.MethodGet, "/api/v1/certificates/abc/policy", model.ActionCertificatesRead, RouteVaultData},
		{"upsert certificate policy", http.MethodPut, "/api/v1/certificates/abc/policy", model.ActionCertificatesUpdate, RouteVaultData},
		{"delete certificate policy", http.MethodDelete, "/api/v1/certificates/abc/policy", model.ActionCertificatesUpdate, RouteVaultData},
		{"backup certificate", http.MethodPost, "/api/v1/certificates/abc/backup", model.ActionCertificatesBackup, RouteVaultData},
		{"restore certificate", http.MethodPost, "/api/v1/certificates/restore", model.ActionCertificatesRestore, RouteVaultData},
		{"list deleted certificates", http.MethodGet, "/api/v1/deleted/certificates", model.ActionCertificatesRead, RouteVaultData},
		{"recover certificate", http.MethodPost, "/api/v1/deleted/certificates/abc/restore", model.ActionCertificatesRecover, RouteVaultData},
		{"purge certificate", http.MethodDelete, "/api/v1/deleted/certificates/abc/purge", model.ActionCertificatesPurge, RouteVaultData},
		{"list certificate versions", http.MethodGet, "/api/v1/certificates/abc/versions", model.ActionCertificatesRead, RouteVaultData},
		{"get certificate version", http.MethodGet, "/api/v1/certificates/abc/versions/2", model.ActionCertificatesRead, RouteVaultData},
		{"update certificate version", http.MethodPut, "/api/v1/certificates/abc/versions/2", model.ActionCertificatesUpdate, RouteVaultData},
		{"renew certificate", http.MethodPost, "/api/v1/certificates/abc/renew", model.ActionCertificatesCreate, RouteVaultData},

		// Vault data-plane. Use flat path "/api/v1/purge"; the test loop below
		// auto-generates vault-scoped "/api/v1/vaults/prod/purge" by prepending
		// "/api/v1/vaults/prod" to trimmed paths. Using the vault-scoped path
		// directly here would cause double-prefixing in that loop.
		{"purge vault", http.MethodDelete, "/api/v1/purge", model.ActionVaultPurge, RouteVaultData},

		// Non-data-plane routes.
		{"vault list", http.MethodGet, "/api/v1/vaults", "", RouteUnmanaged},
		{"vault get", http.MethodGet, "/api/v1/vaults/prod", "", RouteUnmanaged},
		{"vault delete", http.MethodDelete, "/api/v1/vaults/prod", "", RouteUnmanaged},
		{"role assignments", http.MethodPost, "/api/v1/vaults/prod/role-assignments", "", RouteUnmanaged},
		{"users", http.MethodGet, "/api/v1/users", "", RouteUnmanaged},
		{"health", http.MethodGet, "/api/v1/health", "", RouteUnmanaged},
		{"audit", http.MethodGet, "/api/v1/audit/logs", "", RouteUnmanaged},

		// Vault provisioning grants: admin-only, deliberately non-delegable
		// (api/vault_provisioning_grants.go's requireGrantAdmin is the only
		// gate). These routes work at all today because
		// "vault-provisioning-grants" differs from "vaults" at the 6th
		// character, so neither this mapper's "vaults/" prefix check nor
		// mapEndpointToPermission's mirror of it misclassifies them as vault
		// data. Pinned directly so a future edit to either check can't widen
		// the match without failing here -- a misclassification here would
		// 403 admins out of their own admin surface with nothing explaining
		// why.
		{"list provisioning grants", http.MethodGet, "/api/v1/vault-provisioning-grants", "", RouteUnmanaged},
		{"issue provisioning grant", http.MethodPut, "/api/v1/vault-provisioning-grants/abc", "", RouteUnmanaged},
		{"revoke provisioning grant", http.MethodDelete, "/api/v1/vault-provisioning-grants/abc", "", RouteUnmanaged},
	}

	for _, c := range cases {
		t.Run(c.name+" (flat)", func(t *testing.T) {
			gotAction, gotKind := MapRouteToDataAction(c.method, c.path)
			assert.Equal(t, c.want, gotAction)
			assert.Equal(t, c.kind, gotKind)
		})
	}

	// Every data-plane route must map identically under the vault-scoped shape.
	for _, c := range cases {
		if c.kind != RouteVaultData {
			continue
		}
		scoped := "/api/v1/vaults/prod" + trimAPIPrefixForTest(c.path)
		t.Run(c.name+" (vault-scoped)", func(t *testing.T) {
			gotAction, gotKind := MapRouteToDataAction(c.method, scoped)
			assert.Equal(t, c.want, gotAction)
			assert.Equal(t, RouteVaultData, gotKind)
		})
	}
}

// trimAPIPrefixForTest strips the "/api/v1" prefix so a flat path can be
// rewritten into its vault-scoped equivalent.
func trimAPIPrefixForTest(path string) string {
	const prefix = "/api/v1"
	if len(path) >= len(prefix) && path[:len(prefix)] == prefix {
		return path[len(prefix):]
	}
	return path
}

// TestMapRouteToDataActionUnmappedMethodFailsClosed asserts that a data-plane
// path with a method no route serves yields RouteVaultData and an empty action,
// which the middleware must treat as a denial rather than a pass-through.
func TestMapRouteToDataActionUnmappedMethodFailsClosed(t *testing.T) {
	cases := []struct {
		method string
		path   string
	}{
		{http.MethodPatch, "/api/v1/secrets/abc"},
		{http.MethodPut, "/api/v1/keys"},
		{http.MethodDelete, "/api/v1/certificates/abc/backup"},
		{http.MethodPost, "/api/v1/deleted/secrets/abc/unknown"},
		{http.MethodGet, "/api/v1/vaults/prod/secrets/abc/unknown"},
		{http.MethodGet, "/api/v1/keys/import"},
		{http.MethodDelete, "/api/v1/certificates/abc/versions/2"},
		{http.MethodPost, "/api/v1/certificates/abc/versions"},
		{http.MethodGet, "/api/v1/certificates/abc/renew"},
		{http.MethodGet, "/api/v1/certificates/abc/versions/2/extra"},
	}
	for _, c := range cases {
		action, kind := MapRouteToDataAction(c.method, c.path)
		assert.Equal(t, RouteVaultData, kind, "%s %s", c.method, c.path)
		assert.Equal(t, model.DataAction(""), action, "%s %s", c.method, c.path)
	}
}

// TestMapRouteToDataAction_PurgeWrongMethodIsUnmapped proves a non-DELETE
// method on the purge path yields RouteVaultData with no action, so
// PolicyMiddleware's deny-by-default (empty action) path rejects it rather
// than silently falling through to RouteUnmanaged.
func TestMapRouteToDataAction_PurgeWrongMethodIsUnmapped(t *testing.T) {
	action, kind := MapRouteToDataAction(http.MethodGet, "/api/v1/vaults/prod/purge")
	if kind != RouteVaultData {
		t.Fatalf("kind = %v, want RouteVaultData", kind)
	}
	if action != "" {
		t.Fatalf("action = %q, want empty (GET is not a valid purge method)", action)
	}
}
