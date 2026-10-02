package vaultcli

import (
	"context"
	"errors"
	"testing"

	"github.com/sirupsen/logrus"
	logtest "github.com/sirupsen/logrus/hooks/test"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"rocketvault/cmd/testutils"
	"rocketvault/internal/logging"
	"rocketvault/internal/services/authorization"
	"rocketvault/model"
)

// TestRequireAlso_BeforeAuthorizeFailsClosed pins that the second check never
// runs against an unresolved vault.
func TestRequireAlso_BeforeAuthorizeFailsClosed(t *testing.T) {
	s := &Session{op: Op{Audit: "create_certificate", AuthzFailMsg: "failed to create certificate"}}

	err := s.RequireAlso(model.ActionKeysSign, model.OpSign)
	require.Error(t, err)
	require.Contains(t, err.Error(), "failed to create certificate")
	require.Contains(t, err.Error(), "before Authorize")
}

// TestRequireAlso_NilClaimsFailsClosed pins that a session without claims
// never reaches the authorization services.
func TestRequireAlso_NilClaimsFailsClosed(t *testing.T) {
	tc := testutils.NewTestContext(t)

	policies := &testutils.MockAccessPolicyService{}
	tc.MockContainer.AccessPolicyService = policies
	roles := &testutils.MockRoleAssignmentService{}
	tc.MockContainer.RoleAssignmentService = roles

	s, hook := authorizedSession(t, tc)
	s.Claims = nil

	err := s.RequireAlso(model.ActionKeysSign, model.OpSign)
	require.Error(t, err)
	require.Contains(t, err.Error(), "failed to create certificate")
	require.NotErrorIs(t, err, authorization.ErrDataPlaneDenied)
	policies.AssertNotCalled(t, "CheckAccess", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything)
	roles.AssertNotCalled(t, "HasDataAction", mock.Anything, mock.Anything, mock.Anything, mock.Anything)
	require.Len(t, hook.AllEntries(), 1, "the failure is audited through Fail")
}

// authorizedSession builds a Session as Authorize would leave it, with a
// logger whose entries the returned hook records.
func authorizedSession(t *testing.T, tc *testutils.TestContext) (*Session, *logtest.Hook) {
	t.Helper()
	logger, hook := logtest.NewNullLogger()
	logger.SetLevel(logrus.DebugLevel)
	return &Session{
		Ctx:       context.Background(),
		Claims:    &model.Claims{UserID: tc.TestUserID},
		Container: tc.MockContainer,
		Log:       &logging.Logger{Logger: logger},
		VaultID:   tc.TestVaultID,
		Scope:     model.NewVaultScope(tc.TestVaultID, tc.TestUserID),
		op:        Op{Audit: "create_certificate", AuthzFailMsg: "failed to create certificate"},
	}, hook
}

// TestRequireAlso_GrantPassesWithSessionVaultAndCaller pins that the second
// check runs for the session's own caller and vault, with the resource type
// derived from the second action rather than the first.
func TestRequireAlso_GrantPassesWithSessionVaultAndCaller(t *testing.T) {
	tc := testutils.NewTestContext(t)

	policies := &testutils.MockAccessPolicyService{}
	policies.On("CheckAccess", mock.Anything, tc.TestUserID, model.PolicyResourceKeys, model.OpSign, tc.TestVaultID).
		Return(authorization.AccessFallback, nil).Once()
	tc.MockContainer.AccessPolicyService = policies

	roles := &testutils.MockRoleAssignmentService{}
	roles.On("HasDataAction", mock.Anything, tc.TestUserID, tc.TestVaultID, model.ActionKeysSign).
		Return(true, nil).Once()
	tc.MockContainer.RoleAssignmentService = roles

	s, hook := authorizedSession(t, tc)
	require.NoError(t, s.RequireAlso(model.ActionKeysSign, model.OpSign))
	policies.AssertExpectations(t)
	roles.AssertExpectations(t)
	require.Empty(t, hook.AllEntries(), "a passing check records no failure")
}

// TestRequireAlso_ExplicitDenyWinsAndIsAudited pins that an explicit deny
// refuses even with a role grant, and is reported and audited through Fail
// exactly as an Authorize refusal is.
func TestRequireAlso_ExplicitDenyWinsAndIsAudited(t *testing.T) {
	tc := testutils.NewTestContext(t)

	policies := &testutils.MockAccessPolicyService{}
	policies.On("CheckAccess", mock.Anything, tc.TestUserID, model.PolicyResourceKeys, model.OpSign, tc.TestVaultID).
		Return(authorization.AccessDenied, nil).Once()
	tc.MockContainer.AccessPolicyService = policies

	roles := &testutils.MockRoleAssignmentService{}
	tc.MockContainer.RoleAssignmentService = roles

	s, hook := authorizedSession(t, tc)
	err := s.RequireAlso(model.ActionKeysSign, model.OpSign)
	require.ErrorIs(t, err, authorization.ErrDataPlaneDenied)
	require.Equal(t, "failed to create certificate: forbidden: access denied by an explicit access policy for "+
		string(model.ActionKeysSign), err.Error())
	roles.AssertNotCalled(t, "HasDataAction", mock.Anything, mock.Anything, mock.Anything, mock.Anything)

	entry := hook.LastEntry()
	require.NotNil(t, entry)
	require.Equal(t, logrus.ErrorLevel, entry.Level)
	require.Equal(t, "create_certificate", entry.Data["operation"])
	require.Equal(t, "failed", entry.Data["status"])
	require.Equal(t, tc.TestUserID.String(), entry.Data["user_id"])
}

func TestRequireAlso_NoRoleGrantIsDenied(t *testing.T) {
	tc := testutils.NewTestContext(t)

	roles := &testutils.MockRoleAssignmentService{}
	roles.On("HasDataAction", mock.Anything, tc.TestUserID, tc.TestVaultID, model.ActionKeysSign).
		Return(false, nil).Once()
	tc.MockContainer.RoleAssignmentService = roles

	s, hook := authorizedSession(t, tc)
	err := s.RequireAlso(model.ActionKeysSign, model.OpSign)
	require.ErrorIs(t, err, authorization.ErrDataPlaneDenied)
	require.Equal(t, "failed to create certificate: forbidden: no role grants "+
		string(model.ActionKeysSign)+" in this vault", err.Error())
	require.Len(t, hook.AllEntries(), 1)
}

// TestRequireAlso_LookupFailureIsNotADenial pins that a role lookup failure
// fails the command without being reported as an authorization refusal.
func TestRequireAlso_LookupFailureIsNotADenial(t *testing.T) {
	tc := testutils.NewTestContext(t)

	lookup := errors.New("role table exploded")
	roles := &testutils.MockRoleAssignmentService{}
	roles.On("HasDataAction", mock.Anything, mock.Anything, mock.Anything, mock.Anything).
		Return(true, lookup).Once()
	tc.MockContainer.RoleAssignmentService = roles

	s, _ := authorizedSession(t, tc)
	err := s.RequireAlso(model.ActionKeysSign, model.OpSign)
	require.ErrorIs(t, err, lookup)
	require.NotErrorIs(t, err, authorization.ErrDataPlaneDenied)
}
