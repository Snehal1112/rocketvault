package middleware

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"

	"rocketvault/model"
)

// TestResolvePolicy_ExportIsACreate pins the fail-closed legacy path: an
// explicit deny-create access policy also blocks export on both shapes.
func TestResolvePolicy_ExportIsACreate(t *testing.T) {
	for path, resource := range map[string]model.PolicyResourceType{
		"/api/v1/certificates/abc/export":             model.PolicyResourceCertificates,
		"/api/v1/vaults/prod/certificates/abc/export": model.PolicyResourceCertificates,
		"/api/v1/keys/abc/export":                     model.PolicyResourceKeys,
		"/api/v1/vaults/prod/keys/abc/export":         model.PolicyResourceKeys,
	} {
		gotResource, op := resolvePolicy(http.MethodPost, path)
		assert.Equal(t, resource, gotResource, path)
		assert.Equal(t, model.OpCreate, op, path)
	}
}
