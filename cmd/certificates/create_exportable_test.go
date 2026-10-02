package certificates

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"rocketvault/cmd/testutils"
	"rocketvault/common"
	certServices "rocketvault/internal/services/certificates"
	"rocketvault/model"
)

func TestCertCreateCmd_ExportableReachesTheService(t *testing.T) {
	tc := testutils.NewTestContext(t)
	certSvc := &certCmdCertService{}
	keyID := uuid.New()
	certSvc.On("CreateSelfSignedCertificate", mock.Anything, mock.MatchedBy(func(r certServices.CreateCertificateRequest) bool {
		return r.KeyID == keyID && r.Exportable
	})).Return(&certServices.CreateCertificateResult{CertID: uuid.New(), Name: "c", CreatedAt: time.Now()}, nil)

	sc := &certsTestContainer{MockServiceContainer: tc.MockContainer, certSvc: certSvc}
	claims := &model.Claims{UserID: tc.TestUserID, Username: "admin", Roles: []string{model.RoleAdmin}}
	ctx := context.WithValue(context.Background(), common.ClaimsKey, claims)
	ctx = context.WithValue(ctx, common.LogKey, newCertLogger())
	ctx = context.WithValue(ctx, common.ServiceContainerKey, sc)
	ctx = context.WithValue(ctx, common.OutputFormatterKey, newCertFmtr())

	cmd, _ := newCertCmd(createCmd.RunE, nil)
	cmd.Flags().Bool("auto-renew", false, "")
	cmd.Flags().Int("renewal-days", 30, "")
	setFlags(cmd, map[string]any{"name": "c", "key-id": keyID.String(), "validity-days": 365, "ca-cert-id": "", "exportable": true})
	cmd.SetContext(ctx)
	require.NoError(t, cmd.Execute())
	certSvc.AssertExpectations(t)
}

func TestCertCreateCmd_RegistersExportableFlag(t *testing.T) {
	// Init registers flags on the shared command value; run it once if no
	// other test in this binary already has.
	if createCmd.Flags().Lookup("name") == nil {
		InitCertificatesCreate(&cobra.Command{})
	}
	f := createCmd.Flags().Lookup("exportable")
	require.NotNil(t, f)
	assert.Equal(t, "false", f.DefValue)
}
