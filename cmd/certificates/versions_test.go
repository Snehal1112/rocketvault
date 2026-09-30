package certificates

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"rocketvault/cmd/testutils"
	"rocketvault/common"
	authzServices "rocketvault/internal/services/authorization"
	certServices "rocketvault/internal/services/certificates"
	"rocketvault/model"
)

func versionsTestCtx(tc *testutils.TestContext, svc *certCmdCertService) context.Context {
	sc := &certsTestContainer{MockServiceContainer: tc.MockContainer, certSvc: svc}
	claims := &model.Claims{UserID: tc.TestUserID, Roles: []string{model.RoleAdmin}}
	ctx := context.WithValue(context.Background(), common.ClaimsKey, claims)
	ctx = context.WithValue(ctx, common.LogKey, newCertLogger())
	ctx = context.WithValue(ctx, common.ServiceContainerKey, sc)
	return context.WithValue(ctx, common.OutputFormatterKey, newCertFmtr())
}

func TestCertVersionsListCmd_PrintsEveryVersion(t *testing.T) {
	tc := testutils.NewTestContext(t)
	svc := &certCmdCertService{}
	certID := uuid.New()
	svc.On("ListCertificateVersions", mock.Anything, certID, model.NewVaultScope(tc.TestVaultID, tc.TestUserID)).
		Return([]model.CertificateVersion{
			{CertificateID: certID, Version: 1, Enabled: true, CreatedAt: time.Now()},
			{CertificateID: certID, Version: 2, Current: true, Enabled: true, CreatedAt: time.Now()},
		}, nil)

	cmd, buf := newCertCmd(versionsListCmd.RunE, []string{certID.String()})
	cmd.Args = cobra.ExactArgs(1)
	cmd.SetContext(versionsTestCtx(tc, svc))
	require.NoError(t, cmd.Execute())

	out := buf.String()
	assert.Contains(t, out, "Version")
	assert.Contains(t, out, "Current")
	assert.NotContains(t, out, "BEGIN", "versions output never carries a PEM")
	svc.AssertExpectations(t)
}

func TestCertVersionsGetCmd_RejectsBadVersion(t *testing.T) {
	tc := testutils.NewTestContext(t)
	// "-1" is not listed: cobra reads it as a shorthand flag before RunE runs.
	for _, bad := range []string{"0", "abc", "99999999999999999999"} {
		cmd, _ := newCertCmd(versionsGetCmd.RunE, []string{uuid.New().String(), bad})
		cmd.Args = cobra.ExactArgs(2)
		cmd.SetContext(versionsTestCtx(tc, &certCmdCertService{}))
		assert.ErrorContains(t, cmd.Execute(), "invalid version", bad)
	}
}

func TestCertVersionsGetCmd_PrintsOneVersion(t *testing.T) {
	tc := testutils.NewTestContext(t)
	svc := &certCmdCertService{}
	certID := uuid.New()
	svc.On("GetCertificateVersion", mock.Anything, certID, 2, model.NewVaultScope(tc.TestVaultID, tc.TestUserID)).
		Return(&model.CertificateVersion{CertificateID: certID, Version: 2, Current: true, Enabled: true}, nil)

	cmd, buf := newCertCmd(versionsGetCmd.RunE, []string{certID.String(), "2"})
	cmd.Args = cobra.ExactArgs(2)
	cmd.SetContext(versionsTestCtx(tc, svc))
	require.NoError(t, cmd.Execute())
	assert.Contains(t, buf.String(), "2")
	svc.AssertExpectations(t)
}

func TestCertVersionsGetCmd_ServiceError(t *testing.T) {
	tc := testutils.NewTestContext(t)
	svc := &certCmdCertService{}
	certID := uuid.New()
	svc.On("GetCertificateVersion", mock.Anything, certID, 9, model.NewVaultScope(tc.TestVaultID, tc.TestUserID)).
		Return(nil, fmt.Errorf("%w: none", model.ErrCertificateVersionNotFound))

	cmd, _ := newCertCmd(versionsGetCmd.RunE, []string{certID.String(), "9"})
	cmd.Args = cobra.ExactArgs(2)
	cmd.SetContext(versionsTestCtx(tc, svc))
	assert.ErrorContains(t, cmd.Execute(), "failed to get certificate version")
}

// A caller without the read data action never reaches the service.
func TestCertVersionsCmds_DeniedWithoutReadAction(t *testing.T) {
	cases := []struct {
		name string
		run  func(*cobra.Command, []string) error
		args func(uuid.UUID) []string
		n    cobra.PositionalArgs
		msg  string
		mth  string
	}{
		{"list", versionsListCmd.RunE, func(id uuid.UUID) []string { return []string{id.String()} },
			cobra.ExactArgs(1), "failed to list certificate versions", "ListCertificateVersions"},
		{"get", versionsGetCmd.RunE, func(id uuid.UUID) []string { return []string{id.String(), "1"} },
			cobra.ExactArgs(2), "failed to get certificate version", "GetCertificateVersion"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			tc := testutils.NewTestContext(t)
			svc := &certCmdCertService{}
			roles := &testutils.MockRoleAssignmentService{}
			roles.On("HasDataAction", mock.Anything, tc.TestUserID, tc.TestVaultID, model.ActionCertificatesRead).
				Return(false, nil).Once()
			tc.MockContainer.RoleAssignmentService = roles

			cmd, _ := newCertCmd(c.run, c.args(uuid.New()))
			cmd.Args = c.n
			cmd.SetContext(versionsTestCtx(tc, svc))
			assert.ErrorContains(t, cmd.Execute(), c.msg)
			roles.AssertExpectations(t)
			svc.AssertNotCalled(t, c.mth)
		})
	}
}

// An allowed caller is checked for certificates/read and the policy op get.
func TestCertVersionsCmds_AuthorizedChecksReadAction(t *testing.T) {
	tc := testutils.NewTestContext(t)
	svc := &certCmdCertService{}
	certID := uuid.New()
	scope := model.NewVaultScope(tc.TestVaultID, tc.TestUserID)
	svc.On("ListCertificateVersions", mock.Anything, certID, scope).
		Return([]model.CertificateVersion{{CertificateID: certID, Version: 1, Current: true}}, nil)

	roles := &testutils.MockRoleAssignmentService{}
	roles.On("HasDataAction", mock.Anything, tc.TestUserID, tc.TestVaultID, model.ActionCertificatesRead).
		Return(true, nil).Once()
	policies := &testutils.MockAccessPolicyService{}
	policies.On("CheckAccess", mock.Anything, tc.TestUserID, model.PolicyResourceCertificates, model.OpGet, tc.TestVaultID).
		Return(authzServices.AccessAllowed, nil).Once()
	tc.MockContainer.RoleAssignmentService = roles
	tc.MockContainer.AccessPolicyService = policies

	cmd, _ := newCertCmd(versionsListCmd.RunE, []string{certID.String()})
	cmd.Args = cobra.ExactArgs(1)
	cmd.SetContext(versionsTestCtx(tc, svc))
	require.NoError(t, cmd.Execute())
	svc.AssertExpectations(t)
	roles.AssertExpectations(t)
	policies.AssertExpectations(t)
}

func TestCertRenewCmd_PrintsNewVersion(t *testing.T) {
	tc := testutils.NewTestContext(t)
	svc := &certCmdCertService{}
	certID := uuid.New()
	svc.On("RenewCertificate", mock.Anything, certID, model.NewVaultScope(tc.TestVaultID, tc.TestUserID), 365).
		Return(&certServices.CreateCertificateResult{CertID: certID, Version: 4}, nil)

	cmd, buf := newCertCmd(renewCmd.RunE, []string{certID.String()})
	cmd.Args = cobra.ExactArgs(1)
	setFlags(cmd, map[string]any{"validity-days": 365})
	cmd.SetContext(versionsTestCtx(tc, svc))
	require.NoError(t, cmd.Execute())
	assert.Contains(t, buf.String(), "Version: 4")
}

// An omitted --validity-days keeps the current version's validity period.
func TestCertRenewCmd_OmittedValidityKeepsCurrentPeriod(t *testing.T) {
	tc := testutils.NewTestContext(t)
	svc := &certCmdCertService{}
	certID := uuid.New()
	scope := model.NewVaultScope(tc.TestVaultID, tc.TestUserID)
	created := time.Now()
	expires := created.AddDate(0, 0, 90)
	cert := &model.Certificate{ID: certID, CreatedAt: created, ExpiresAt: &expires}
	svc.On("GetCertificate", mock.Anything, certID, scope).Return(cert, nil)
	svc.On("RenewCertificate", mock.Anything, certID, scope, certServices.CurrentValidityDays(cert)).
		Return(&certServices.CreateCertificateResult{CertID: certID, Version: 2}, nil)

	cmd, buf := newCertCmd(renewCmd.RunE, []string{certID.String()})
	cmd.Args = cobra.ExactArgs(1)
	cmd.Flags().AddFlagSet(renewCmd.Flags())
	cmd.SetContext(versionsTestCtx(tc, svc))
	require.NoError(t, cmd.Execute())
	assert.Contains(t, buf.String(), "Validity: 90 days")
	svc.AssertExpectations(t)
}
