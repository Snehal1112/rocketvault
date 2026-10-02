// Package api — proves every registered named data-plane route resolves to the
// policy operation the CLI passes for the same command (B79).
package api

import (
	"net/http"
	"sort"
	"strings"
	"testing"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"rocketvault/app"
	"rocketvault/internal/middleware"
	"rocketvault/model"
)

// policyExpectation is the access-policy triple half that resolvePolicy
// produces for one route.
type policyExpectation struct {
	resource model.PolicyResourceType
	op       model.PolicyOperation
}

// normalizePolicyRoute turns a router path template into a shape-free key.
// It drops the base path and the vault segment, and replaces every path
// variable with "{id}". The second result reports whether the route is
// vault-scoped.
func normalizePolicyRoute(tmpl string) (string, bool) {
	p := strings.TrimPrefix(tmpl, "/api/v1")
	scoped := false
	if strings.HasPrefix(p, "/vaults/{") {
		rest := p[len("/vaults/"):]
		slash := strings.Index(rest, "/")
		if slash == -1 {
			return p, false
		}
		p = rest[slash:]
		scoped = true
	}
	segs := strings.Split(p, "/")
	for i, s := range segs {
		if strings.HasPrefix(s, "{") {
			segs[i] = "{id}"
		}
	}
	return strings.Join(segs, "/"), scoped
}

// isNamedPolicyRoute reports whether a resolved data-plane route ends in a
// literal word, such as /wrap or /export, rather than a path variable or the
// collection name. These are the routes whose operation depends on the
// suffix, so each one must be classified on purpose.
func isNamedPolicyRoute(normalized string) bool {
	last := normalized[strings.LastIndex(normalized, "/")+1:]
	switch last {
	case "", "{id}", "secrets", "keys", "certificates":
		return false
	}
	return true
}

// buildPolicyTestRouter builds the real router through api.Init, the same
// construction production uses.
func buildPolicyTestRouter(t *testing.T) *mux.Router {
	t.Helper()
	container := &routerWalkContainer{policyContainer: &policyContainer{}, logger: userTestLog()}
	a := &app.App{ServiceContainer: container, Logger: userTestLog()}
	router := mux.NewRouter()
	require.NotNil(t, Init(WithAPP(a), WithRouter(router), WithBasePath("/api/v1"), WithLogger(userTestLog())))
	return router
}

// TestKeyCryptoRoutesResolveToTheirOwnPolicyOperation walks the real router
// and checks every POST data-plane route that ends in a literal word. The set
// of such routes must equal the table below on both route shapes, so a new
// route with an operation-like suffix fails this test until it is classified.
//
// The CLI side of the crypto rows is pinned in cmd/keys: sign.go passes
// OpSign, verify.go OpVerify, wrap.go OpWrap and unwrap.go OpUnwrap. Encrypt,
// decrypt and item backup have no CLI command.
func TestKeyCryptoRoutesResolveToTheirOwnPolicyOperation(t *testing.T) {
	router := buildPolicyTestRouter(t)

	secrets, keys, certs := model.PolicyResourceSecrets, model.PolicyResourceKeys, model.PolicyResourceCertificates
	want := map[string]policyExpectation{
		// B33 and B79: key crypto operations.
		"/keys/{id}/sign":    {keys, model.OpSign},
		"/keys/{id}/verify":  {keys, model.OpVerify},
		"/keys/{id}/encrypt": {keys, model.OpEncrypt},
		"/keys/{id}/decrypt": {keys, model.OpDecrypt},
		"/keys/{id}/wrap":    {keys, model.OpWrap},
		"/keys/{id}/unwrap":  {keys, model.OpUnwrap},
		// B79: item backup for every resource.
		"/keys/{id}/backup":         {keys, model.OpBackup},
		"/secrets/{id}/backup":      {secrets, model.OpBackup},
		"/certificates/{id}/backup": {certs, model.OpBackup},
		// Export stays create on purpose, so a deny on create still blocks it.
		"/keys/{id}/export":         {keys, model.OpCreate},
		"/certificates/{id}/export": {certs, model.OpCreate},
		"/secrets/export":           {secrets, model.OpCreate},
		// Other named routes.
		"/keys/{id}/rotate":                  {keys, model.OpRotate},
		"/certificates/{id}/renew":           {certs, model.OpRenew},
		"/keys/import":                       {keys, model.OpImport},
		"/secrets/import":                    {secrets, model.OpImport},
		"/secrets/generate":                  {secrets, model.OpCreate},
		"/deleted/secrets/{id}/restore":      {secrets, model.OpRecover},
		"/deleted/keys/{id}/restore":         {keys, model.OpRecover},
		"/deleted/certificates/{id}/restore": {certs, model.OpRecover},
		// Known gap recorded in B79: restore from a backup blob resolves to
		// recover, so a deny on restore is not evaluated over HTTP.
		"/secrets/restore":      {secrets, model.OpRecover},
		"/keys/restore":         {keys, model.OpRecover},
		"/certificates/restore": {certs, model.OpRecover},
	}

	routes, err := WalkRoutes(router)
	require.NoError(t, err)

	// found[path][scoped] counts each route shape separately.
	found := map[string]map[bool]int{}
	for _, rt := range routes {
		if rt.Method != http.MethodPost {
			continue
		}
		resource, op := middleware.ResolvePolicy(rt.Method, rt.Path)
		if resource != secrets && resource != keys && resource != certs {
			continue
		}
		normalized, scoped := normalizePolicyRoute(rt.Path)
		if !isNamedPolicyRoute(normalized) {
			continue
		}
		if found[normalized] == nil {
			found[normalized] = map[bool]int{}
		}
		found[normalized][scoped]++

		exp, ok := want[normalized]
		if !assert.True(t, ok, "unclassified named route %s %s resolves to (%s, %s): add it to the table", rt.Method, rt.Path, resource, op) {
			continue
		}
		assert.Equal(t, exp.resource, resource, "resource for %s %s", rt.Method, rt.Path)
		assert.Equal(t, exp.op, op, "operation for %s %s", rt.Method, rt.Path)
	}

	// Every expected route exists exactly once on each shape.
	paths := make([]string, 0, len(want))
	for p := range want {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	for _, p := range paths {
		assert.Equal(t, 1, found[p][false], "flat POST /api/v1%s registrations", p)
		assert.Equal(t, 1, found[p][true], "vault-scoped POST /api/v1/vaults/{vault_name}%s registrations", p)
	}
}

// TestCertificateVersionRoutesResolveToPlainOperations pins the certificate
// version routes on both shapes. They end in a path variable or in
// "versions", so they resolve by HTTP method alone.
func TestCertificateVersionRoutesResolveToPlainOperations(t *testing.T) {
	router := buildPolicyTestRouter(t)

	want := map[string]model.PolicyOperation{
		http.MethodGet + " /certificates/{id}/versions":      model.OpGet,
		http.MethodGet + " /certificates/{id}/versions/{id}": model.OpGet,
		http.MethodPut + " /certificates/{id}/versions/{id}": model.OpSet,
	}

	routes, err := WalkRoutes(router)
	require.NoError(t, err)

	found := map[string]map[bool]int{}
	for _, rt := range routes {
		normalized, scoped := normalizePolicyRoute(rt.Path)
		key := rt.Method + " " + normalized
		wantOp, ok := want[key]
		if !ok {
			continue
		}
		resource, op := middleware.ResolvePolicy(rt.Method, rt.Path)
		assert.Equal(t, model.PolicyResourceCertificates, resource, "resource for %s %s", rt.Method, rt.Path)
		assert.Equal(t, wantOp, op, "operation for %s %s", rt.Method, rt.Path)
		if found[key] == nil {
			found[key] = map[bool]int{}
		}
		found[key][scoped]++
	}

	for key := range want {
		assert.Equal(t, 1, found[key][false], "flat %s registrations", key)
		assert.Equal(t, 1, found[key][true], "vault-scoped %s registrations", key)
	}
}
