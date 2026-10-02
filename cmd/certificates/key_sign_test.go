package certificates

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"rocketvault/cmd/testutils"
	"rocketvault/common"
	"rocketvault/internal/logging/logtest"
	authzServices "rocketvault/internal/services/authorization"
	"rocketvault/model"
)

// TestCertCreateCmd_RequiresKeySign pins B77 on the CLI path:
// certificates/create alone is not enough, exactly as over HTTP.
func TestCertCreateCmd_RequiresKeySign(t *testing.T) {
	tc := testutils.NewTestContext(t)
	certSvc := &certCmdCertService{}
	keyID := uuid.New()

	roles := &testutils.MockRoleAssignmentService{}
	roles.On("HasDataAction", mock.Anything, tc.TestUserID, tc.TestVaultID, model.ActionCertificatesCreate).Return(true, nil)
	roles.On("HasDataAction", mock.Anything, tc.TestUserID, tc.TestVaultID, model.ActionKeysSign).Return(false, nil)
	tc.MockContainer.RoleAssignmentService = roles

	sc := &certsTestContainer{MockServiceContainer: tc.MockContainer, certSvc: certSvc}
	claims := &model.Claims{UserID: tc.TestUserID, Username: "admin", Roles: []string{model.RoleAdmin}}
	ctx := context.WithValue(context.Background(), common.ClaimsKey, claims)
	ctx = context.WithValue(ctx, common.LogKey, newCertLogger())
	ctx = context.WithValue(ctx, common.ServiceContainerKey, sc)
	ctx = context.WithValue(ctx, common.OutputFormatterKey, newCertFmtr())

	cmd, _ := newCertCmd(createCmd.RunE, nil)
	cmd.Flags().Bool("auto-renew", false, "")
	cmd.Flags().Int("renewal-days", 30, "")
	setFlags(cmd, map[string]any{"name": "mycert",
		"key-id":        keyID.String(),
		"validity-days": 365,
		"tags":          "",
		"ca-cert-id":    ""})
	cmd.SetContext(ctx)
	err := cmd.Execute()
	assert.ErrorContains(t, err, "failed to create certificate")
	assert.ErrorContains(t, err, string(model.ActionKeysSign))
	certSvc.AssertNotCalled(t, "CreateSelfSignedCertificate", mock.Anything, mock.Anything)
}

// TestCertRenewCmd_RequiresKeySign pins the same requirement for renewal.
func TestCertRenewCmd_RequiresKeySign(t *testing.T) {
	tc := testutils.NewTestContext(t)
	certSvc := &certCmdCertService{}
	certID := uuid.New()

	roles := &testutils.MockRoleAssignmentService{}
	roles.On("HasDataAction", mock.Anything, tc.TestUserID, tc.TestVaultID, model.ActionCertificatesCreate).Return(true, nil)
	roles.On("HasDataAction", mock.Anything, tc.TestUserID, tc.TestVaultID, model.ActionKeysSign).Return(false, nil)
	tc.MockContainer.RoleAssignmentService = roles

	sc := &certsTestContainer{MockServiceContainer: tc.MockContainer, certSvc: certSvc}
	claims := &model.Claims{UserID: tc.TestUserID, Roles: []string{model.RoleAdmin}}
	ctx := context.WithValue(context.Background(), common.ClaimsKey, claims)
	ctx = context.WithValue(ctx, common.LogKey, newCertLogger())
	ctx = context.WithValue(ctx, common.ServiceContainerKey, sc)

	cmd, _ := newCertCmd(renewCmd.RunE, []string{certID.String()})
	cmd.Args = cobra.ExactArgs(1)
	setFlags(cmd, map[string]any{"validity-days": 365})
	cmd.SetContext(ctx)
	err := cmd.Execute()
	assert.ErrorContains(t, err, "failed to renew certificate")
	assert.ErrorContains(t, err, string(model.ActionKeysSign))
	certSvc.AssertNotCalled(t, "RenewCertificate", mock.Anything, mock.Anything, mock.Anything, mock.Anything)
	certSvc.AssertNotCalled(t, "GetCertificate", mock.Anything, mock.Anything, mock.Anything)
}

// runKeySignCmd runs the create or renew command with role and policy
// services the caller configured, and a logger whose audit rows it returns.
func runKeySignCmd(t *testing.T, tc *testutils.TestContext, renew bool, certSvc *certCmdCertService) (*logtest.Recorder, error) {
	t.Helper()
	sc := &certsTestContainer{MockServiceContainer: tc.MockContainer, certSvc: certSvc}
	logger, rec := logtest.NewLogger()
	claims := &model.Claims{UserID: tc.TestUserID, Username: "admin", Roles: []string{model.RoleAdmin}}
	ctx := context.WithValue(context.Background(), common.ClaimsKey, claims)
	ctx = context.WithValue(ctx, common.LogKey, logger)
	ctx = context.WithValue(ctx, common.ServiceContainerKey, sc)
	ctx = context.WithValue(ctx, common.OutputFormatterKey, newCertFmtr())

	var cmd *cobra.Command
	if renew {
		cmd, _ = newCertCmd(renewCmd.RunE, []string{uuid.New().String()})
		cmd.Args = cobra.ExactArgs(1)
		setFlags(cmd, map[string]any{"validity-days": 365})
	} else {
		cmd, _ = newCertCmd(createCmd.RunE, nil)
		cmd.Flags().Bool("auto-renew", false, "")
		cmd.Flags().Int("renewal-days", 30, "")
		setFlags(cmd, map[string]any{"name": "mycert",
			"key-id":        uuid.New().String(),
			"validity-days": 365,
			"tags":          "",
			"ca-cert-id":    ""})
	}
	cmd.SetContext(ctx)
	err := cmd.Execute()
	return rec, err
}

// TestCertIssueCmds_KeySignRefusalsAndFaults covers the explicit deny on
// (keys, sign) and a failed role lookup for both commands. Each must stop
// before any certificate service call and leave a failed audit row.
func TestCertIssueCmds_KeySignRefusalsAndFaults(t *testing.T) {
	type setup func(tc *testutils.TestContext)
	scenarios := map[string]setup{
		"explicit deny on keys sign": func(tc *testutils.TestContext) {
			policies := &testutils.MockAccessPolicyService{}
			policies.On("CheckAccess", mock.Anything, tc.TestUserID, model.PolicyResourceCertificates, mock.Anything, tc.TestVaultID).
				Return(authzServices.AccessAllowed, nil)
			policies.On("CheckAccess", mock.Anything, tc.TestUserID, model.PolicyResourceKeys, model.OpSign, tc.TestVaultID).
				Return(authzServices.AccessDenied, nil).Once()
			tc.MockContainer.AccessPolicyService = policies
		},
		"role lookup failure": func(tc *testutils.TestContext) {
			roles := &testutils.MockRoleAssignmentService{}
			roles.On("HasDataAction", mock.Anything, tc.TestUserID, tc.TestVaultID, model.ActionCertificatesCreate).Return(true, nil)
			roles.On("HasDataAction", mock.Anything, tc.TestUserID, tc.TestVaultID, model.ActionKeysSign).
				Return(false, errors.New("role store unavailable")).Once()
			tc.MockContainer.RoleAssignmentService = roles
		},
	}
	commands := map[string]struct {
		renew           bool
		audit, failText string
	}{
		"create": {false, "create_certificate", "failed to create certificate"},
		"renew":  {true, "renew_certificate", "failed to renew certificate"},
	}
	for sName, configure := range scenarios {
		for cName, c := range commands {
			t.Run(cName+" "+sName, func(t *testing.T) {
				tc := testutils.NewTestContext(t)
				configure(tc)
				certSvc := &certCmdCertService{}

				rec, err := runKeySignCmd(t, tc, c.renew, certSvc)

				require.Error(t, err)
				assert.ErrorContains(t, err, c.failText)
				assert.Empty(t, certSvc.Calls, "no certificate service call after a failed keys/sign check")
				_, ok := rec.Find(c.audit, "failed")
				assert.True(t, ok, "the refusal must be audited")
			})
		}
	}
}
