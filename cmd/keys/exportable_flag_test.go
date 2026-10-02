package keys

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"rocketvault/common"
	keyServices "rocketvault/internal/services/keys"
	"rocketvault/model"
)

func keyCmdCtx(sc any) context.Context {
	claims := &model.Claims{UserID: uuid.New(), Roles: []string{model.RoleAdmin}}
	ctx := context.WithValue(context.Background(), common.ClaimsKey, claims)
	ctx = context.WithValue(ctx, common.LogKey, newLogger())
	ctx = context.WithValue(ctx, common.ServiceContainerKey, sc)
	return context.WithValue(ctx, common.OutputFormatterKey, newTestFmtr())
}

func TestCreateCmd_ExportableReachesTheService(t *testing.T) {
	keySvc := &keyCmdKeyService{}
	sc, _ := newAllowedContainer(keySvc, nil)
	keySvc.On("CreateRSAKey", mock.Anything, mock.MatchedBy(func(r keyServices.CreateKeyRequest) bool { return r.Exportable })).
		Return(&keyServices.CreateKeyResult{KeyID: uuid.New(), Name: "k", Type: "RSA", CreatedAt: time.Now()}, nil)

	cmd, _ := newTestCmd(createCmd.RunE, nil)
	setFlags(cmd, map[string]any{"name": "k", "type": "RSA", "bits": 2048, "curve": "P-256", "tags": "", "exportable": true})
	cmd.SetContext(keyCmdCtx(sc))
	require.NoError(t, cmd.Execute())
	keySvc.AssertExpectations(t)
}

func TestImportCmd_ExportableReachesTheService(t *testing.T) {
	keySvc := &keyCmdKeyService{}
	sc, _ := newAllowedContainer(keySvc, nil)
	keySvc.On("ImportKey", mock.Anything, mock.MatchedBy(func(r keyServices.ImportKeyRequest) bool { return r.Exportable })).
		Return(&keyServices.CreateKeyResult{KeyID: uuid.New(), Name: "i", Type: "RSA", CreatedAt: time.Now()}, nil)

	cmd, _ := newTestCmd(importCmd.RunE, nil)
	setFlags(cmd, map[string]any{"name": "i", "jwk": `{"kty":"RSA"}`, "tags": "", "exportable": true})
	cmd.SetContext(keyCmdCtx(sc))
	require.NoError(t, cmd.Execute())
	keySvc.AssertExpectations(t)
}

func TestKeyCommands_RegisterExportableFlag(t *testing.T) {
	// The Init functions register flags on the shared command values; run
	// them once if no other test in this binary already has.
	if createCmd.Flags().Lookup("name") == nil {
		InitKeysCreate(&cobra.Command{})
	}
	if importCmd.Flags().Lookup("name") == nil {
		InitKeysImport(&cobra.Command{})
	}
	require.NotNil(t, createCmd.Flags().Lookup("exportable"))
	require.NotNil(t, importCmd.Flags().Lookup("exportable"))
	assert.Equal(t, "false", createCmd.Flags().Lookup("exportable").DefValue)
	assert.Equal(t, "false", importCmd.Flags().Lookup("exportable").DefValue)
}
