package vaultaccess

import (
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"rocketvault/cmd/testutils"
	"rocketvault/internal/apitest"
	"rocketvault/model"
)

func TestRevokeRemote_DeletesByAssignmentID(t *testing.T) {
	id := uuid.New()

	roleSvc := &testutils.MockRoleAssignmentService{}
	roleSvc.On("RevokeAssignment", mock.Anything, id, mock.Anything, mock.Anything, mock.Anything).
		Return(nil)
	roleSvc.On("HasDataAction", mock.Anything, mock.Anything, mock.Anything, mock.Anything).
		Return(true, nil).Maybe()

	srv := apitest.New(t, apitest.Options{RoleAssignments: roleSvc})

	var gotVault string
	vs := srv.TestContext().MockVaultService
	vs.ExpectedCalls = nil
	vs.On("GetVault", mock.Anything, mock.Anything).
		Run(func(a mock.Arguments) { gotVault = a.String(1) }).
		Return(&model.Vault{ID: srv.TestContext().TestVaultID, Name: "payments", Enabled: true}, nil).Maybe()

	cmd, out := remoteTestCmd(t, "payments")
	require.NoError(t, runRevokeRemote(cmd, srv.Client(), srv.Target(), id.String()))
	assert.Contains(t, out.String(), "revoked assignment "+id.String())
	assert.Equal(t, "payments", gotVault, "--vault must reach the URL")
}

func TestRevokeRemote_RejectsPrincipalName(t *testing.T) {
	// No RevokeAssignment expectation, so if a request reached the handler
	// the mock would panic on the unregistered call. In practice no request
	// is ever attempted: vaultapi.DeleteRoleAssignment
	// (internal/vaultapi/destructive.go) rejects a non-UUID argument
	// client-side before issuing one, and even if it did not, the route's
	// {assignment_id:[A-Fa-f0-9-]+} regex (api/api.go) would not match
	// "alice" either. The missing expectation is a belt-and-suspenders
	// safety net, not the mechanism under test.
	roleSvc := &testutils.MockRoleAssignmentService{}
	roleSvc.On("HasDataAction", mock.Anything, mock.Anything, mock.Anything, mock.Anything).
		Return(true, nil).Maybe()

	srv := apitest.New(t, apitest.Options{RoleAssignments: roleSvc})

	cmd, _ := remoteTestCmd(t, "payments")

	err := runRevokeRemote(cmd, srv.Client(), srv.Target(), "alice")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "assignment id")
}
