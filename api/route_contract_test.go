package api

import (
	"strings"
	"testing"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/require"

	"rocketvault/app"
)

// clientCalledRoute is one method+path pair a Go client in this repo actually
// sends a request to, paired with the name of the caller that sends it.
type clientCalledRoute struct {
	Method string
	Path   string
	Caller string
}

// clientCalledRoutes lists every path called by internal/vaultapi. Keep this
// in sync when that package starts or stops calling a path.
var clientCalledRoutes = []clientCalledRoute{
	{"POST", "/api/v1/users/login", "vaultapi.Login"},
	{"POST", "/api/v1/users/refresh", "vaultapi.SessionSource.refresh"},
	{"POST", "/api/v1/oauth2/token", "vaultapi.ServiceAccountSource"},
	{"GET", "/api/v1/vaults/{vault_name}/role-assignments", "vaultapi.ListRoleAssignments"},
	{"POST", "/api/v1/vaults/{vault_name}/role-assignments", "vaultapi.CreateRoleAssignment"},
	{"DELETE", "/api/v1/vaults/{vault_name}/role-assignments/{assignment_id}", "vaultapi.DeleteRoleAssignment"},
	{"GET", "/api/v1/vaults/{vault_name}/certificates/{certificate_id}/versions", "vaultapi.GetCertificateVersions"},
	{"POST", "/api/v1/vaults/{vault_name}/certificates/{certificate_id}/renew", "vaultapi.RenewCertificate"},
}

// stripConstraints removes mux regex constraints from a path template so a
// client's literal "{assignment_id}" matches the server's
// "{assignment_id:[A-Fa-f0-9-]+}".
func stripConstraints(tmpl string) string {
	var b strings.Builder
	inVar, seenColon := false, false
	for _, r := range tmpl {
		switch {
		case r == '{':
			inVar, seenColon = true, false
			b.WriteRune(r)
		case r == '}':
			inVar, seenColon = false, false
			b.WriteRune(r)
		case inVar && r == ':':
			seenColon = true
		case inVar && seenColon:
			// drop constraint characters
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

// TestClientPathsAreRegistered walks the real router -- the same
// construction api.Init uses in production -- and asserts that every path a
// Go client in this repo (internal/vaultapi) calls is registered with the
// method it uses.
//
// This test exists because the httptest-server mocks used by vaultapi's own
// unit tests answer whatever path they are asked for -- a mock is not a
// router, so it cannot catch a client calling a path the real server never
// registers. That gap let the now-deleted cliclient.RefreshRemote post to
// "/api/v1/refresh" (unregistered; refreshToken is only mounted at
// "/api/v1/users/refresh" on the users subrouter) while its own test and
// cmd/root_test.go both asserted the wrong path against such a mock and
// passed. Walking the real route table closes that gap.
func TestClientPathsAreRegistered(t *testing.T) {
	container := &routerWalkContainer{policyContainer: &policyContainer{}, logger: userTestLog()}
	a := &app.App{ServiceContainer: container, Logger: userTestLog()}

	router := mux.NewRouter()
	built := Init(
		WithAPP(a),
		WithRouter(router),
		WithBasePath("/api/v1"),
		WithLogger(userTestLog()),
		WithMetricsEnabled(true),
	)
	require.NotNil(t, built)

	routes, err := WalkRoutes(router)
	require.NoError(t, err)
	require.Greater(t, len(routes), 30, "expected a substantial number of real routes")

	registered := make(map[string]bool, len(routes))
	for _, r := range routes {
		registered[r.Method+" "+stripConstraints(r.Path)] = true
	}

	for _, cr := range clientCalledRoutes {
		t.Run(cr.Method+"_"+cr.Path, func(t *testing.T) {
			key := cr.Method + " " + stripConstraints(cr.Path)
			if !registered[key] {
				t.Errorf("%s calls %s %s but the server registers no such path", cr.Caller, cr.Method, cr.Path)
			}
		})
	}
}
