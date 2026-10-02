// Package api — handler-level refusals are audited (B81).
package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"rocketvault/app"
	"rocketvault/common"
	"rocketvault/internal/logging/logtest"
	authzServices "rocketvault/internal/services/authorization"
	"rocketvault/internal/testutils"
	"rocketvault/model"
)

// TestDeleteVault_RefusalIsAudited proves a vault 403 leaves a denied row.
func TestDeleteVault_RefusalIsAudited(t *testing.T) {
	policySvc := &mockAccessPolicyService{}
	policySvc.On("CheckAccess", mock.Anything, mock.Anything, model.PolicyResourceVaults, model.OpManage, mock.Anything).
		Return(authzServices.AccessFallback, nil)
	policySvc.On("CheckVaultScopedAccess", mock.Anything, mock.Anything, model.PolicyResourceVaults, model.OpManage, mock.Anything).
		Return(authzServices.AccessFallback, nil)
	api, _ := buildAuthzVaultAPI(policySvc)
	logger, rec := logtest.NewLogger()
	api.App.Logger = logger

	w := doVaultRequestAs(api, string(model.RoleUser), http.MethodDelete, "/api/v1/vaults/prod", nil)
	require.Equal(t, http.StatusForbidden, w.Code)

	row, ok := rec.Find("delete_vault", "denied")
	require.True(t, ok, "a refused vault delete must be audited")
	assert.Equal(t, vaultTestUserID, row.UserID)
}

// TestCreateRoleAssignment_RefusalIsAudited proves a refused grant leaves a
// denied row naming the caller.
func TestCreateRoleAssignment_RefusalIsAudited(t *testing.T) {
	policySvc := &mockAccessPolicyService{}
	policySvc.On("CheckAccess", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).
		Return(authzServices.AccessFallback, nil)
	policySvc.On("CheckVaultScopedAccess", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).
		Return(authzServices.AccessFallback, nil)

	c := newRoleAssignmentCtx("user", policySvc)
	logger, rec := logtest.NewLogger()
	c.Logger = logger
	w := httptest.NewRecorder()
	body := []byte(`{"principal":"alice","role":"Key Vault Administrator"}`)
	r := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/api/v1/vaults/prod/role-assignments", bytes.NewReader(body))

	createRoleAssignment(c, w, r)
	require.NotNil(t, c.Err)
	assert.Equal(t, http.StatusForbidden, c.Err.StatusCode)

	row, ok := rec.Find("assign_role", "denied")
	require.True(t, ok, "a refused grant must be audited")
	assert.Equal(t, c.Claims.UserID, row.UserID)
}

// TestDeleteRoleAssignment_NotGrantableRefusalIsAudited covers the second
// refusal point on revoke: the service's ErrRoleNotGrantable.
func TestDeleteRoleAssignment_NotGrantableRefusalIsAudited(t *testing.T) {
	vaultID := uuid.New()
	assignmentID := uuid.New()
	callerID := uuid.MustParse("00000000-0000-0000-0000-000000000001")

	// The api tests use internal/testutils.MockServiceContainer, whose
	// GetAccessPolicyService always returns nil. CanManageRoleAssignments
	// tolerates a nil policy service and falls through to HasDataAction, so
	// the first gate passes and the handler reaches ErrRoleNotGrantable.
	roleSvc := &mockRoleAssignmentService{}
	roleSvc.On("HasDataAction", mock.Anything, callerID, vaultID, model.ActionRoleAssignmentsDelete).Return(true, nil)
	roleSvc.On("RevokeAssignment", mock.Anything, assignmentID, vaultID, callerID, false).
		Return(authzServices.ErrRoleNotGrantable)

	mc := &testutils.MockServiceContainer{}
	mc.On("GetRoleAssignmentService").Return(roleSvc)
	logger, rec := logtest.NewLogger()
	c := &Context{
		App:    &app.App{ServiceContainer: mc},
		Claims: RequestClaims{UserID: callerID.String(), Roles: []string{"user"}},
		Params: &ApiParams{VaultName: "prod", AssignmentID: assignmentID.String(), PerPage: 60},
		Logger: logger,
	}
	r := httptest.NewRequestWithContext(context.Background(), http.MethodDelete, "/api/v1/vaults/prod/role-assignments/"+assignmentID.String(), nil)
	r = r.WithContext(context.WithValue(r.Context(), common.VaultIDKey, vaultID.String()))

	deleteRoleAssignment(c, httptest.NewRecorder(), r)
	require.NotNil(t, c.Err)
	// Guard against a vacuous pass at the first gate: the service must be reached.
	roleSvc.AssertCalled(t, "RevokeAssignment", mock.Anything, assignmentID, vaultID, callerID, false)

	row, ok := rec.Find("revoke_role_assignment", "denied")
	require.True(t, ok, "a refused revoke must be audited")
	assert.Equal(t, callerID.String(), row.UserID)
}

// TestCreateAccessPolicy_NonAdminRefusalIsAudited proves an attempt to write
// an explicit deny without the admin role leaves a trail.
func TestCreateAccessPolicy_NonAdminRefusalIsAudited(t *testing.T) {
	c := newNonAdminPolicyCtx(nil)
	c.Claims.UserID = "00000000-0000-0000-0000-0000000000bb"
	logger, rec := logtest.NewLogger()
	c.Logger = logger
	body, _ := json.Marshal(map[string]string{"principal_id": uuid.New().String()})
	r := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/access-policies", bytes.NewReader(body))

	createAccessPolicy(c, httptest.NewRecorder(), r)
	require.NotNil(t, c.Err)
	assert.Equal(t, http.StatusForbidden, c.Err.StatusCode)

	row, ok := rec.Find("manage_access_policy", "denied")
	require.True(t, ok)
	assert.Equal(t, "00000000-0000-0000-0000-0000000000bb", row.UserID)
}
