package authorization

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"

	"rocketvault/model"
)

func TestMapRouteToDataAction_Export(t *testing.T) {
	cases := []struct {
		method, path string
		want         model.DataAction
	}{
		{http.MethodPost, "/api/v1/certificates/abc/export", model.ActionCertificatesExportItem},
		{http.MethodPost, "/api/v1/vaults/prod/certificates/abc/export", model.ActionCertificatesExportItem},
		{http.MethodPost, "/api/v1/keys/abc/export", model.ActionKeysExport},
		{http.MethodPost, "/api/v1/vaults/prod/keys/abc/export", model.ActionKeysExport},
		// Every other method on an export path fails closed.
		{http.MethodGet, "/api/v1/certificates/abc/export", ""},
		{http.MethodPut, "/api/v1/vaults/prod/keys/abc/export", ""},
		{http.MethodDelete, "/api/v1/keys/abc/export", ""},
	}
	for _, tc := range cases {
		action, kind := MapRouteToDataAction(tc.method, tc.path)
		assert.Equal(t, RouteVaultData, kind, "%s %s", tc.method, tc.path)
		assert.Equal(t, tc.want, action, "%s %s", tc.method, tc.path)
	}
}

// TestMapRouteToDataAction_ExportDoesNotShadowCollectionRoutes pins that the
// unbuilt bulk route POST /certificates/export stays unmapped (fail closed),
// and POST /keys/import keeps its own action.
func TestMapRouteToDataAction_ExportDoesNotShadowCollectionRoutes(t *testing.T) {
	// rest is "export", one segment, and the one-segment switch has no POST
	// arm, so the unbuilt bulk route stays unmapped and fails closed.
	action, kind := MapRouteToDataAction(http.MethodPost, "/api/v1/certificates/export")
	assert.Equal(t, RouteVaultData, kind)
	assert.Equal(t, model.DataAction(""), action)
	action, _ = MapRouteToDataAction(http.MethodPost, "/api/v1/keys/import")
	assert.Equal(t, model.ActionKeysImport, action)
}
