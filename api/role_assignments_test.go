// Package api — internal tests for vault-scoped role-assignment handlers.
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

	"rocketvault/app"
	"rocketvault/common"
	authzServices "rocketvault/internal/services/authorization"
	"rocketvault/internal/testutils"
	"rocketvault/model"
)

// mockRoleAssignmentService is a local testify mock for authzServices.RoleAssignmentService.
type mockRoleAssignmentService struct {
	mock.Mock
}

func (m *mockRoleAssignmentService) AssignRole(ctx context.Context, in authzServices.AssignRoleInput) (*model.RoleAssignment, error) {
	args := m.Called(ctx, in)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*model.RoleAssignment), args.Error(1)
}

func (m *mockRoleAssignmentService) RevokeAssignment(ctx context.Context, assignmentID, vaultID, actorID uuid.UUID, callerIsGlobalAdmin bool) error {
	args := m.Called(ctx, assignmentID, vaultID, actorID, callerIsGlobalAdmin)
	return args.Error(0)
}

func (m *mockRoleAssignmentService) ListAssignments(ctx context.Context, vaultID uuid.UUID) ([]*model.RoleAssignment, error) {
	args := m.Called(ctx, vaultID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*model.RoleAssignment), args.Error(1)
}

func (m *mockRoleAssignmentService) HasDataAction(ctx context.Context, principalID, vaultID uuid.UUID, action model.DataAction) (bool, error) {
	args := m.Called(ctx, principalID, vaultID, action)
	return args.Bool(0), args.Error(1)
}

// newRoleAssignmentCtx builds a Context whose session carries the given role,
// backed by the given AccessPolicyService. It reuses policyContainer from
// access_policies_test.go. A nil RoleAssignmentService is fine for the gate
// path because the gate rejects before the role-assignment service is touched.
func newRoleAssignmentCtx(role string, policySvc authzServices.AccessPolicyService) *Context {
	a := &app.App{ServiceContainer: &policyContainer{policySvc: policySvc}}
	return &Context{
		App: a,
		Claims: RequestClaims{
			UserID: "00000000-0000-0000-0000-000000000001",
			Roles:  []string{role},
		},
		Params: &ApiParams{VaultName: "prod", PerPage: 60},
	}
}

// TestRoleAssignments_GlobalVaultsManageCannotGrantInAnyVault pins the
// escalation path from the design doc's Problem section. Before the narrowing,
// a NULL-scoped vaults:manage allow satisfied CanManageRoleAssignments for
// EVERY vault, so its holder could award itself Key Vault Administrator
// anywhere. CheckAccess still says allowed -- the global row does match -- and
// that must no longer be what the handler consults.
func TestRoleAssignments_GlobalVaultsManageCannotGrantInAnyVault(t *testing.T) {
	policySvc := &mockAccessPolicyService{}
	policySvc.On("CheckAccess", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).
		Return(authzServices.AccessAllowed, nil)
	policySvc.On("CheckVaultScopedAccess", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).
		Return(authzServices.AccessFallback, nil)

	c := newRoleAssignmentCtx("user", policySvc)
	w := httptest.NewRecorder()
	body := []byte(`{"principal":"alice","role":"key-vault-administrator"}`)
	r := httptest.NewRequest(http.MethodPost, "/api/v1/vaults/prod/role-assignments", bytes.NewReader(body))

	createRoleAssignment(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusForbidden, w.Code,
		"a global vaults:manage allow must not permit granting roles in a vault")
}

// TestRoleAssignments_GrantRequiresAdmin verifies a non-admin caller without a
// vaults/manage policy is rejected with 403 before the service is invoked.
func TestRoleAssignments_GrantRequiresAdmin(t *testing.T) {
	// Non-admin: CanManageRoleAssignments falls through to the vault-scoped
	// policy check, which returns AccessFallback (no policy), so the caller is
	// denied.
	policySvc := &mockAccessPolicyService{}
	policySvc.On("CheckAccess", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).
		Return(authzServices.AccessFallback, nil)
	policySvc.On("CheckVaultScopedAccess", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).
		Return(authzServices.AccessFallback, nil)

	c := newRoleAssignmentCtx("user", policySvc)
	w := httptest.NewRecorder()
	body := []byte(`{"principal":"alice","role":"secrets-user"}`)
	r := httptest.NewRequest(http.MethodPost, "/api/v1/vaults/prod/role-assignments", bytes.NewReader(body))

	createRoleAssignment(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusForbidden, w.Code)
}

// TestListRoleAssignments_ReturnsEnrichedResponse verifies the list handler
// returns the ListRoleAssignmentsResponse shape (not a raw model array/map),
// with vault_name filled from the URL and expanded_policy_count derived from
// the role bundle. The caller is an authorized admin so the shape, not the
// gate, is what this test exercises.
func TestListRoleAssignments_ReturnsEnrichedResponse(t *testing.T) {
	vaultID := uuid.New()
	principalID := uuid.New()
	assignment := &model.RoleAssignment{
		ID:            uuid.New(),
		PrincipalID:   principalID,
		PrincipalType: model.PrincipalTypeUser,
		Role:          "secrets-user", // bundle = get, list => 2 policies
		VaultID:       vaultID,
	}

	roleSvc := &mockRoleAssignmentService{}
	roleSvc.On("ListAssignments", mock.Anything, mock.Anything).Return([]*model.RoleAssignment{assignment}, nil)

	mc := &testutils.MockServiceContainer{}
	mc.On("GetRoleAssignmentService").Return(roleSvc)

	c := &Context{
		App:    &app.App{ServiceContainer: mc},
		Claims: RequestClaims{UserID: "00000000-0000-0000-0000-000000000001", Roles: []string{string(model.RoleAdmin)}},
		Params: &ApiParams{VaultName: "prod", PerPage: 60},
	}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/api/v1/vaults/prod/role-assignments", nil)

	listRoleAssignments(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusOK, w.Code)

	var resp model.ListRoleAssignmentsResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	assert.Equal(t, 1, resp.Total)
	assert.Len(t, resp.RoleAssignments, 1)
	assert.Equal(t, "prod", resp.RoleAssignments[0].VaultName)
	assert.Equal(t, 2, resp.RoleAssignments[0].ExpandedPolicyCount)
	assert.Equal(t, assignment.ID.String(), resp.RoleAssignments[0].ID)
}

// TestRoleAssignments_GrantAllowedForDataAccessAdministrator proves a
// non-admin holding Key Vault Data Access Administrator in the target vault
// can create a role assignment there — the fix for the documented known
// limitation (role-assignment management was global-admin-only).
func TestRoleAssignments_GrantAllowedForDataAccessAdministrator(t *testing.T) {
	vaultID := uuid.New()
	callerID := uuid.MustParse("00000000-0000-0000-0000-000000000001")

	policySvc := &mockAccessPolicyService{}
	policySvc.On("CheckAccess", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).
		Return(authzServices.AccessFallback, nil)
	policySvc.On("CheckVaultScopedAccess", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).
		Return(authzServices.AccessFallback, nil)

	roleSvc := &mockRoleAssignmentService{}
	roleSvc.On("HasDataAction", mock.Anything, callerID, vaultID, model.ActionRoleAssignmentsWrite).
		Return(true, nil)
	roleSvc.On("AssignRole", mock.Anything, mock.Anything).
		Return(&model.RoleAssignment{ID: uuid.New(), VaultID: vaultID, Role: "Key Vault Secrets User"}, nil)

	mc := &testutils.MockServiceContainer{}
	mc.On("GetAccessPolicyService").Return(policySvc)
	mc.On("GetRoleAssignmentService").Return(roleSvc)

	c := &Context{
		App:    &app.App{ServiceContainer: mc},
		Claims: RequestClaims{UserID: callerID.String(), Roles: []string{"user"}},
		Params: &ApiParams{VaultName: "prod", PerPage: 60},
	}
	body := []byte(`{"principal":"alice","role":"Key Vault Secrets User"}`)
	r := httptest.NewRequest(http.MethodPost, "/api/v1/vaults/prod/role-assignments", bytes.NewReader(body))
	r = r.WithContext(context.WithValue(r.Context(), common.VaultIDKey, vaultID.String()))
	w := httptest.NewRecorder()

	createRoleAssignment(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusCreated, w.Code)
}

// TestRoleAssignments_GrantDeniedRoleNotGrantable_Returns403 proves a rejected
// grant surfaces as 403 (SetPermissionError), not 500 (SetInternalError): the
// caller passes the CanManageRoleAssignments gate (holds Key Vault Data
// Access Administrator in the vault) but AssignRole itself refuses the
// specific role via ErrRoleNotGrantable — an authorization rejection, not an
// unexpected server failure, and must be reported the same way the earlier
// CanManageRoleAssignments gate reports rejection in this same handler.
func TestRoleAssignments_GrantDeniedRoleNotGrantable_Returns403(t *testing.T) {
	vaultID := uuid.New()
	callerID := uuid.MustParse("00000000-0000-0000-0000-000000000001")

	policySvc := &mockAccessPolicyService{}
	policySvc.On("CheckAccess", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).
		Return(authzServices.AccessFallback, nil)
	policySvc.On("CheckVaultScopedAccess", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).
		Return(authzServices.AccessFallback, nil)

	roleSvc := &mockRoleAssignmentService{}
	roleSvc.On("HasDataAction", mock.Anything, callerID, vaultID, model.ActionRoleAssignmentsWrite).
		Return(true, nil)
	roleSvc.On("AssignRole", mock.Anything, mock.Anything).
		Return(nil, authzServices.ErrRoleNotGrantable)

	mc := &testutils.MockServiceContainer{}
	mc.On("GetAccessPolicyService").Return(policySvc)
	mc.On("GetRoleAssignmentService").Return(roleSvc)

	c := &Context{
		App:    &app.App{ServiceContainer: mc},
		Claims: RequestClaims{UserID: callerID.String(), Roles: []string{"user"}},
		Params: &ApiParams{VaultName: "prod", PerPage: 60},
	}
	body := []byte(`{"principal":"alice","role":"Key Vault Data Access Administrator"}`)
	r := httptest.NewRequest(http.MethodPost, "/api/v1/vaults/prod/role-assignments", bytes.NewReader(body))
	r = r.WithContext(context.WithValue(r.Context(), common.VaultIDKey, vaultID.String()))
	w := httptest.NewRecorder()

	createRoleAssignment(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusForbidden, w.Code)
}

// TestRoleAssignments_RevokeDeniedRoleNotGrantable_Returns403 mirrors
// TestRoleAssignments_GrantDeniedRoleNotGrantable_Returns403 for the revoke
// path (B21): a non-global-admin caller who otherwise passes the
// CanManageRoleAssignments gate (holds Key Vault Data Access Administrator in
// the vault) is still refused by RevokeAssignment's own ErrRoleNotGrantable
// check when the assignment being revoked is outside the allow-list, and the
// rejection surfaces as 403, not 500.
func TestRoleAssignments_RevokeDeniedRoleNotGrantable_Returns403(t *testing.T) {
	vaultID := uuid.New()
	assignmentID := uuid.New()
	callerID := uuid.MustParse("00000000-0000-0000-0000-000000000001")

	policySvc := &mockAccessPolicyService{}
	policySvc.On("CheckAccess", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).
		Return(authzServices.AccessFallback, nil)
	policySvc.On("CheckVaultScopedAccess", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).
		Return(authzServices.AccessFallback, nil)

	roleSvc := &mockRoleAssignmentService{}
	roleSvc.On("HasDataAction", mock.Anything, callerID, vaultID, model.ActionRoleAssignmentsDelete).
		Return(true, nil)
	roleSvc.On("RevokeAssignment", mock.Anything, assignmentID, vaultID, callerID, false).
		Return(authzServices.ErrRoleNotGrantable)

	mc := &testutils.MockServiceContainer{}
	mc.On("GetAccessPolicyService").Return(policySvc)
	mc.On("GetRoleAssignmentService").Return(roleSvc)

	c := &Context{
		App:    &app.App{ServiceContainer: mc},
		Claims: RequestClaims{UserID: callerID.String(), Roles: []string{"user"}},
		Params: &ApiParams{VaultName: "prod", AssignmentID: assignmentID.String(), PerPage: 60},
	}
	r := httptest.NewRequest(http.MethodDelete, "/api/v1/vaults/prod/role-assignments/"+assignmentID.String(), nil)
	r = r.WithContext(context.WithValue(r.Context(), common.VaultIDKey, vaultID.String()))
	w := httptest.NewRecorder()

	deleteRoleAssignment(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusForbidden, w.Code)
}

// TestRoleAssignments_GrantDeniedForDataAccessAdministratorInWrongVault
// proves the grant is scoped: holding Key Vault Data Access Administrator in
// vault A does not authorize creating a role assignment in vault B.
func TestRoleAssignments_GrantDeniedForDataAccessAdministratorInWrongVault(t *testing.T) {
	grantedVault := uuid.New()
	targetVault := uuid.New()
	callerID := uuid.MustParse("00000000-0000-0000-0000-000000000001")

	policySvc := &mockAccessPolicyService{}
	policySvc.On("CheckAccess", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).
		Return(authzServices.AccessFallback, nil)
	policySvc.On("CheckVaultScopedAccess", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).
		Return(authzServices.AccessFallback, nil)

	roleSvc := &mockRoleAssignmentService{}
	roleSvc.On("HasDataAction", mock.Anything, callerID, targetVault, model.ActionRoleAssignmentsWrite).
		Return(false, nil)
	_ = grantedVault // the grant (not registered on roleSvc at all) is scoped elsewhere; omitted here since HasDataAction is queried only against targetVault

	mc := &testutils.MockServiceContainer{}
	mc.On("GetAccessPolicyService").Return(policySvc)
	mc.On("GetRoleAssignmentService").Return(roleSvc)

	c := &Context{
		App:    &app.App{ServiceContainer: mc},
		Claims: RequestClaims{UserID: callerID.String(), Roles: []string{"user"}},
		Params: &ApiParams{VaultName: "other", PerPage: 60},
	}
	body := []byte(`{"principal":"alice","role":"Key Vault Secrets User"}`)
	r := httptest.NewRequest(http.MethodPost, "/api/v1/vaults/other/role-assignments", bytes.NewReader(body))
	r = r.WithContext(context.WithValue(r.Context(), common.VaultIDKey, targetVault.String()))
	w := httptest.NewRecorder()

	createRoleAssignment(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusForbidden, w.Code)
}

// TestRoleAssignments_RevokeAllowedForDataAccessAdministrator mirrors the
// grant test for the delete path, and proves write/delete are checked as
// distinct actions (a principal could in principle hold write without
// delete, or vice versa, though the built-in role grants both).
func TestRoleAssignments_RevokeAllowedForDataAccessAdministrator(t *testing.T) {
	vaultID := uuid.New()
	assignmentID := uuid.New()
	callerID := uuid.MustParse("00000000-0000-0000-0000-000000000001")

	policySvc := &mockAccessPolicyService{}
	policySvc.On("CheckAccess", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).
		Return(authzServices.AccessFallback, nil)
	policySvc.On("CheckVaultScopedAccess", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).
		Return(authzServices.AccessFallback, nil)

	roleSvc := &mockRoleAssignmentService{}
	roleSvc.On("HasDataAction", mock.Anything, callerID, vaultID, model.ActionRoleAssignmentsDelete).
		Return(true, nil)
	roleSvc.On("RevokeAssignment", mock.Anything, assignmentID, vaultID, callerID, false).Return(nil)

	mc := &testutils.MockServiceContainer{}
	mc.On("GetAccessPolicyService").Return(policySvc)
	mc.On("GetRoleAssignmentService").Return(roleSvc)

	c := &Context{
		App:    &app.App{ServiceContainer: mc},
		Claims: RequestClaims{UserID: callerID.String(), Roles: []string{"user"}},
		Params: &ApiParams{VaultName: "prod", AssignmentID: assignmentID.String(), PerPage: 60},
	}
	r := httptest.NewRequest(http.MethodDelete, "/api/v1/vaults/prod/role-assignments/"+assignmentID.String(), nil)
	r = r.WithContext(context.WithValue(r.Context(), common.VaultIDKey, vaultID.String()))
	w := httptest.NewRecorder()

	deleteRoleAssignment(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusOK, w.Code)
}

// TestRoleAssignments_DataAccessAdministrator_GrantAndRevokeComposeAcrossVaults
// is the closing regression for the known limitation this plan fixes: a
// single principal holding Key Vault Data Access Administrator in vault A
// can both grant AND revoke assignments in vault A, using the same mocked
// grant, and is denied both operations in vault B.
func TestRoleAssignments_DataAccessAdministrator_GrantAndRevokeComposeAcrossVaults(t *testing.T) {
	vaultA := uuid.New()
	vaultB := uuid.New()
	assignmentID := uuid.New()
	callerID := uuid.MustParse("00000000-0000-0000-0000-000000000001")

	policySvc := &mockAccessPolicyService{}
	policySvc.On("CheckAccess", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).
		Return(authzServices.AccessFallback, nil)
	policySvc.On("CheckVaultScopedAccess", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).
		Return(authzServices.AccessFallback, nil)

	roleSvc := &mockRoleAssignmentService{}
	roleSvc.On("HasDataAction", mock.Anything, callerID, vaultA, model.ActionRoleAssignmentsWrite).Return(true, nil)
	roleSvc.On("HasDataAction", mock.Anything, callerID, vaultA, model.ActionRoleAssignmentsDelete).Return(true, nil)
	roleSvc.On("HasDataAction", mock.Anything, callerID, vaultB, model.ActionRoleAssignmentsWrite).Return(false, nil)
	roleSvc.On("HasDataAction", mock.Anything, callerID, vaultB, model.ActionRoleAssignmentsDelete).Return(false, nil)
	roleSvc.On("AssignRole", mock.Anything, mock.Anything).
		Return(&model.RoleAssignment{ID: uuid.New(), VaultID: vaultA, Role: "Key Vault Secrets User"}, nil)
	roleSvc.On("RevokeAssignment", mock.Anything, assignmentID, vaultA, callerID, false).Return(nil)

	mc := &testutils.MockServiceContainer{}
	mc.On("GetAccessPolicyService").Return(policySvc)
	mc.On("GetRoleAssignmentService").Return(roleSvc)

	newCtx := func(vaultName string) *Context {
		return &Context{
			App:    &app.App{ServiceContainer: mc},
			Claims: RequestClaims{UserID: callerID.String(), Roles: []string{"user"}},
			Params: &ApiParams{VaultName: vaultName, AssignmentID: assignmentID.String(), PerPage: 60},
		}
	}

	// Grant in A: allowed.
	cGrantA := newCtx("a")
	rGrantA := httptest.NewRequest(http.MethodPost, "/api/v1/vaults/a/role-assignments", bytes.NewReader([]byte(`{"principal":"alice","role":"Key Vault Secrets User"}`)))
	rGrantA = rGrantA.WithContext(context.WithValue(rGrantA.Context(), common.VaultIDKey, vaultA.String()))
	wGrantA := httptest.NewRecorder()
	createRoleAssignment(cGrantA, wGrantA, rGrantA)
	if cGrantA.Err != nil {
		writeError(wGrantA, cGrantA)
	}
	assert.Equal(t, http.StatusCreated, wGrantA.Code, "grant in own vault must succeed")

	// Revoke in A: allowed.
	cRevokeA := newCtx("a")
	rRevokeA := httptest.NewRequest(http.MethodDelete, "/api/v1/vaults/a/role-assignments/"+assignmentID.String(), nil)
	rRevokeA = rRevokeA.WithContext(context.WithValue(rRevokeA.Context(), common.VaultIDKey, vaultA.String()))
	wRevokeA := httptest.NewRecorder()
	deleteRoleAssignment(cRevokeA, wRevokeA, rRevokeA)
	if cRevokeA.Err != nil {
		writeError(wRevokeA, cRevokeA)
	}
	assert.Equal(t, http.StatusOK, wRevokeA.Code, "revoke in own vault must succeed")

	// Grant in B: denied.
	cGrantB := newCtx("b")
	rGrantB := httptest.NewRequest(http.MethodPost, "/api/v1/vaults/b/role-assignments", bytes.NewReader([]byte(`{"principal":"alice","role":"Key Vault Secrets User"}`)))
	rGrantB = rGrantB.WithContext(context.WithValue(rGrantB.Context(), common.VaultIDKey, vaultB.String()))
	wGrantB := httptest.NewRecorder()
	createRoleAssignment(cGrantB, wGrantB, rGrantB)
	if cGrantB.Err != nil {
		writeError(wGrantB, cGrantB)
	}
	assert.Equal(t, http.StatusForbidden, wGrantB.Code, "grant in a different vault must be denied")

	// Revoke in B: denied.
	cRevokeB := newCtx("b")
	rRevokeB := httptest.NewRequest(http.MethodDelete, "/api/v1/vaults/b/role-assignments/"+assignmentID.String(), nil)
	rRevokeB = rRevokeB.WithContext(context.WithValue(rRevokeB.Context(), common.VaultIDKey, vaultB.String()))
	wRevokeB := httptest.NewRecorder()
	deleteRoleAssignment(cRevokeB, wRevokeB, rRevokeB)
	if cRevokeB.Err != nil {
		writeError(wRevokeB, cRevokeB)
	}
	assert.Equal(t, http.StatusForbidden, wRevokeB.Code, "revoke in a different vault must be denied")
}

// --- Read-path authorization (list / get) ---
//
// Reading role assignments discloses who holds which role in a vault,
// including principal usernames resolved by buildRoleAssignmentResponse. Both
// read handlers shipped with NO authorization check at all once the global
// admin-only gate on /vaults/... was removed; the tests below pin the
// CanManageRoleAssignments(write=false) gate that closes that leak.

// newReadRoleAssignmentCtx builds a non-admin caller Context and the matching
// request for a role-assignment read against vaultID.
func newReadRoleAssignmentCtx(mc *testutils.MockServiceContainer, callerID, vaultID uuid.UUID, assignmentID, method, path string) (*Context, *http.Request) {
	c := &Context{
		App:    &app.App{ServiceContainer: mc},
		Claims: RequestClaims{UserID: callerID.String(), Roles: []string{"user"}},
		Params: &ApiParams{VaultName: "prod", AssignmentID: assignmentID, PerPage: 60},
	}
	r := httptest.NewRequest(method, path, nil)
	r = r.WithContext(context.WithValue(r.Context(), common.VaultIDKey, vaultID.String()))
	return c, r
}

// TestListRoleAssignments_DeniedWithoutGrant proves a non-admin with no
// vaults/manage policy and no role assignment cannot enumerate a vault's role
// assignments, and that the service is never reached.
func TestListRoleAssignments_DeniedWithoutGrant(t *testing.T) {
	vaultID := uuid.New()
	callerID := uuid.New()

	roleSvc := &mockRoleAssignmentService{}
	roleSvc.On("HasDataAction", mock.Anything, callerID, vaultID, model.ActionRoleAssignmentsDelete).
		Return(false, nil)
	// Registered only so an authorization regression surfaces as a failed
	// assertion below rather than an unexpected-call panic.
	roleSvc.On("ListAssignments", mock.Anything, mock.Anything).
		Return([]*model.RoleAssignment{}, nil)

	mc := &testutils.MockServiceContainer{}
	mc.On("GetRoleAssignmentService").Return(roleSvc)

	c, r := newReadRoleAssignmentCtx(mc, callerID, vaultID, "", http.MethodGet, "/api/v1/vaults/prod/role-assignments")
	w := httptest.NewRecorder()

	listRoleAssignments(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusForbidden, w.Code)
	roleSvc.AssertNotCalled(t, "ListAssignments", mock.Anything, mock.Anything)
}

// TestGetRoleAssignment_DeniedWithoutGrant mirrors the list case for the
// single-assignment read.
func TestGetRoleAssignment_DeniedWithoutGrant(t *testing.T) {
	vaultID := uuid.New()
	callerID := uuid.New()
	assignmentID := uuid.New()

	roleSvc := &mockRoleAssignmentService{}
	roleSvc.On("HasDataAction", mock.Anything, callerID, vaultID, model.ActionRoleAssignmentsDelete).
		Return(false, nil)
	// Registered only so an authorization regression surfaces as a failed
	// assertion below rather than an unexpected-call panic.
	roleSvc.On("ListAssignments", mock.Anything, mock.Anything).
		Return([]*model.RoleAssignment{}, nil)

	mc := &testutils.MockServiceContainer{}
	mc.On("GetRoleAssignmentService").Return(roleSvc)

	c, r := newReadRoleAssignmentCtx(mc, callerID, vaultID, assignmentID.String(),
		http.MethodGet, "/api/v1/vaults/prod/role-assignments/"+assignmentID.String())
	w := httptest.NewRecorder()

	getRoleAssignment(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusForbidden, w.Code)
	roleSvc.AssertNotCalled(t, "ListAssignments", mock.Anything, mock.Anything)
}

// TestListRoleAssignments_AllowedForDataAccessAdministrator proves the gate is
// not simply admin-only: a non-admin holding Key Vault Data Access
// Administrator in the target vault can read its assignments.
func TestListRoleAssignments_AllowedForDataAccessAdministrator(t *testing.T) {
	vaultID := uuid.New()
	callerID := uuid.New()
	assignment := &model.RoleAssignment{
		ID:            uuid.New(),
		PrincipalID:   uuid.New(),
		PrincipalType: model.PrincipalTypeUser,
		Role:          model.RoleKeyVaultSecretsUser,
		VaultID:       vaultID,
	}

	roleSvc := &mockRoleAssignmentService{}
	roleSvc.On("HasDataAction", mock.Anything, callerID, vaultID, model.ActionRoleAssignmentsDelete).
		Return(true, nil)
	roleSvc.On("ListAssignments", mock.Anything, vaultID).
		Return([]*model.RoleAssignment{assignment}, nil)

	mc := &testutils.MockServiceContainer{}
	mc.On("GetRoleAssignmentService").Return(roleSvc)
	mc.On("GetUserService").Return(nil)

	c, r := newReadRoleAssignmentCtx(mc, callerID, vaultID, "", http.MethodGet, "/api/v1/vaults/prod/role-assignments")
	w := httptest.NewRecorder()

	listRoleAssignments(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusOK, w.Code)

	var resp model.ListRoleAssignmentsResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	assert.Equal(t, 1, resp.Total)
}

// TestGetRoleAssignment_AllowedForDataAccessAdministrator mirrors the list
// case for the single-assignment read.
func TestGetRoleAssignment_AllowedForDataAccessAdministrator(t *testing.T) {
	vaultID := uuid.New()
	callerID := uuid.New()
	assignment := &model.RoleAssignment{
		ID:            uuid.New(),
		PrincipalID:   uuid.New(),
		PrincipalType: model.PrincipalTypeUser,
		Role:          model.RoleKeyVaultSecretsUser,
		VaultID:       vaultID,
	}

	roleSvc := &mockRoleAssignmentService{}
	roleSvc.On("HasDataAction", mock.Anything, callerID, vaultID, model.ActionRoleAssignmentsDelete).
		Return(true, nil)
	roleSvc.On("ListAssignments", mock.Anything, vaultID).
		Return([]*model.RoleAssignment{assignment}, nil)

	mc := &testutils.MockServiceContainer{}
	mc.On("GetRoleAssignmentService").Return(roleSvc)
	mc.On("GetUserService").Return(nil)

	c, r := newReadRoleAssignmentCtx(mc, callerID, vaultID, assignment.ID.String(),
		http.MethodGet, "/api/v1/vaults/prod/role-assignments/"+assignment.ID.String())
	w := httptest.NewRecorder()

	getRoleAssignment(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusOK, w.Code)

	var resp model.RoleAssignmentResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	assert.Equal(t, assignment.ID.String(), resp.ID)
}
