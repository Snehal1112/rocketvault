package secrets

import (
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"rocketvault/cmd/testutils"
	"rocketvault/common"
	authzServices "rocketvault/internal/services/authorization"
	secretServices "rocketvault/internal/services/secrets"
	"rocketvault/model"
)

func TestImportCommand_CallsServiceImport(t *testing.T) {
	tc := testutils.NewTestContext(t)

	// The request must carry the resolved vault scope, not the zero-value
	// Scope: a zero Scope has kind ScopeInvalid and every repository query
	// rejects it, so this assertion catches the "Scope never set" regression
	// that a service-level mock alone would miss.
	//
	// The actor must be the real authenticated user, never uuid.Nil:
	// ImportSecrets derives each new secret's owner from Scope.ActorID, so a
	// nil actor orphans every imported row (and violates the PostgreSQL
	// foreign key).
	wantScope := model.NewVaultScope(tc.TestVaultID, tc.TestUserID)
	tc.MockSecretService.On("ImportSecrets", mock.Anything, mock.MatchedBy(func(r secretServices.ImportSecretsRequest) bool {
		return r.Format == "json" && r.Scope == wantScope
	})).Return(&secretServices.ImportResult{ImportedCount: 2}, nil)
	tc.MockContainer.On("GetSecretService").Return(tc.MockSecretService)

	// Assert the exact args reaching both authorization checks, not just
	// "some" values — a transposed action/op or swapped principal/vault must
	// fail this test, not pass it.
	roles := &testutils.MockRoleAssignmentService{}
	roles.On("HasDataAction", mock.Anything, tc.TestUserID, tc.TestVaultID, model.ActionSecretsSet).
		Return(true, nil).Once()
	policies := &testutils.MockAccessPolicyService{}
	policies.On("CheckAccess", mock.Anything, tc.TestUserID, model.PolicyResourceSecrets, model.OpImport, tc.TestVaultID).
		Return(authzServices.AccessAllowed, nil).Once()
	tc.MockContainer.RoleAssignmentService = roles
	tc.MockContainer.AccessPolicyService = policies

	tmpFile := t.TempDir() + "/import.json"
	os.WriteFile(tmpFile, []byte(`{}`), 0o600) //nolint:errcheck,gosec

	// Reset package-level vars.
	importFormat = "json"
	importFile = tmpFile
	importEncrypted = false
	importPassphraseFile = ""
	importOverwrite = false

	cmd := &cobra.Command{Use: "import", RunE: secretsImportCmd.RunE}
	cmd.Flags().StringVarP(&importFormat, "format", "f", "json", "")
	cmd.Flags().StringVarP(&importFile, "file", "i", tmpFile, "")
	cmd.Flags().BoolVarP(&importEncrypted, "encrypted", "e", false, "")
	cmd.Flags().BoolVarP(&importOverwrite, "overwrite", "w", false, "")
	cmd.SetContext(tc.Ctx)

	err := cmd.Execute()
	assert.NoError(t, err)
	tc.MockSecretService.AssertExpectations(t)
	roles.AssertExpectations(t)
	policies.AssertExpectations(t)
}

func TestImportCommand_FileNotFound(t *testing.T) {
	tc := testutils.NewTestContext(t)

	importFormat = "json"
	importFile = "/nonexistent/path/import.json"
	importEncrypted = false
	importPassphraseFile = ""
	importOverwrite = false

	cmd := &cobra.Command{Use: "import", RunE: secretsImportCmd.RunE}
	cmd.Flags().StringVarP(&importFormat, "format", "f", "json", "")
	cmd.Flags().StringVarP(&importFile, "file", "i", "/nonexistent/path/import.json", "")
	cmd.Flags().BoolVarP(&importEncrypted, "encrypted", "e", false, "")
	cmd.Flags().BoolVarP(&importOverwrite, "overwrite", "w", false, "")
	cmd.SetContext(tc.Ctx)

	err := cmd.Execute()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "import file does not exist")
}

func TestImportCommand_Forbidden(t *testing.T) {
	tc := testutils.NewTestContext(t)

	denyRoles := &testutils.MockRoleAssignmentService{}
	denyRoles.On("HasDataAction", mock.Anything, mock.Anything, mock.Anything, mock.Anything).
		Return(false, nil).Maybe()
	tc.MockContainer.RoleAssignmentService = denyRoles

	tmpFile := t.TempDir() + "/import.json"
	os.WriteFile(tmpFile, []byte(`{}`), 0o600) //nolint:errcheck,gosec

	importFormat = "json"
	importFile = tmpFile
	importEncrypted = false
	importPassphraseFile = ""
	importOverwrite = false

	cmd := &cobra.Command{Use: "import", RunE: secretsImportCmd.RunE}
	cmd.Flags().StringVarP(&importFormat, "format", "f", "json", "")
	cmd.Flags().StringVarP(&importFile, "file", "i", tmpFile, "")
	cmd.Flags().BoolVarP(&importEncrypted, "encrypted", "e", false, "")
	cmd.Flags().BoolVarP(&importOverwrite, "overwrite", "w", false, "")
	cmd.SetContext(tc.Ctx)

	err := cmd.Execute()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "forbidden")
	tc.MockSecretService.AssertNotCalled(t, "ImportSecrets", mock.Anything, mock.Anything)
}

// newImportTestCmd builds a standalone command sharing the real import RunE.
func newImportTestCmd(file string) *cobra.Command {
	cmd := &cobra.Command{Use: "import", RunE: secretsImportCmd.RunE}
	cmd.Flags().StringVarP(&importFormat, "format", "f", "json", "")
	cmd.Flags().StringVarP(&importFile, "file", "i", file, "")
	cmd.Flags().BoolVarP(&importEncrypted, "encrypted", "e", false, "")
	cmd.Flags().StringVar(&importPassphraseFile, "passphrase-file", importPassphraseFile, "")
	cmd.Flags().BoolVarP(&importOverwrite, "overwrite", "w", false, "")
	return cmd
}

func TestImportCommand_SealedFileIsDecryptedBeforeTheService(t *testing.T) {
	tc := testutils.NewTestContext(t)
	t.Setenv("ROCKETVAULT_EXPORT_PASSPHRASE", "pw")

	plain := []byte(`[{"name":"db-password","value":"hunter2"}]`)
	sealed, err := common.SealExport(plain, "pw")
	require.NoError(t, err)

	tmpFile := filepath.Join(t.TempDir(), "import.json")
	require.NoError(t, os.WriteFile(tmpFile, sealed, 0o600))

	// The service must receive the opened payload, never the envelope.
	tc.MockSecretService.On("ImportSecrets", mock.Anything, mock.MatchedBy(func(r secretServices.ImportSecretsRequest) bool {
		return string(r.Data) == string(plain)
	})).Return(&secretServices.ImportResult{ImportedCount: 1}, nil)
	tc.MockContainer.On("GetSecretService").Return(tc.MockSecretService)

	importFormat = "json"
	importFile = tmpFile
	importEncrypted = false
	importPassphraseFile = ""
	importOverwrite = false

	cmd := newImportTestCmd(tmpFile)
	cmd.SetContext(tc.Ctx)

	require.NoError(t, cmd.Execute())
	tc.MockSecretService.AssertExpectations(t)
}

func TestImportCommand_SealedFileWithNoPassphraseSource_Fails(t *testing.T) {
	tc := testutils.NewTestContext(t)
	tc.MockContainer.On("GetSecretService").Return(tc.MockSecretService).Maybe()
	t.Setenv("ROCKETVAULT_EXPORT_PASSPHRASE", "")

	sealed, err := common.SealExport([]byte(`[{"name":"n","value":"v"}]`), "pw")
	require.NoError(t, err)

	tmpFile := filepath.Join(t.TempDir(), "import.json")
	require.NoError(t, os.WriteFile(tmpFile, sealed, 0o600))

	importFormat = "json"
	importFile = tmpFile
	importEncrypted = false
	importPassphraseFile = ""
	importOverwrite = false

	cmd := newImportTestCmd(tmpFile)
	cmd.SetContext(tc.Ctx)

	err = cmd.Execute()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no passphrase")
	tc.MockSecretService.AssertNotCalled(t, "ImportSecrets", mock.Anything, mock.Anything)
}

func TestImportCommand_SealedFileWithWrongPassphrase_Fails(t *testing.T) {
	tc := testutils.NewTestContext(t)
	tc.MockContainer.On("GetSecretService").Return(tc.MockSecretService).Maybe()
	t.Setenv("ROCKETVAULT_EXPORT_PASSPHRASE", "not-the-passphrase")

	sealed, err := common.SealExport([]byte(`[{"name":"n","value":"v"}]`), "pw")
	require.NoError(t, err)

	tmpFile := filepath.Join(t.TempDir(), "import.json")
	require.NoError(t, os.WriteFile(tmpFile, sealed, 0o600))

	importFormat = "json"
	importFile = tmpFile
	importEncrypted = false
	importPassphraseFile = ""
	importOverwrite = false

	cmd := newImportTestCmd(tmpFile)
	cmd.SetContext(tc.Ctx)

	err = cmd.Execute()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "wrong passphrase")
	tc.MockSecretService.AssertNotCalled(t, "ImportSecrets", mock.Anything, mock.Anything)
}

func TestImportCommand_PlaintextFileNeedsNoPassphrase(t *testing.T) {
	tc := testutils.NewTestContext(t)
	t.Setenv("ROCKETVAULT_EXPORT_PASSPHRASE", "")

	plain := []byte(`[{"name":"n","value":"v"}]`)
	tmpFile := filepath.Join(t.TempDir(), "import.json")
	require.NoError(t, os.WriteFile(tmpFile, plain, 0o600))

	tc.MockSecretService.On("ImportSecrets", mock.Anything, mock.MatchedBy(func(r secretServices.ImportSecretsRequest) bool {
		return string(r.Data) == string(plain)
	})).Return(&secretServices.ImportResult{ImportedCount: 1}, nil)
	tc.MockContainer.On("GetSecretService").Return(tc.MockSecretService)

	importFormat = "json"
	importFile = tmpFile
	importEncrypted = false
	importPassphraseFile = ""
	importOverwrite = false

	cmd := newImportTestCmd(tmpFile)
	cmd.SetContext(tc.Ctx)

	require.NoError(t, cmd.Execute())
	tc.MockSecretService.AssertExpectations(t)
}

// TestImportCommand_Forbidden_NeverPromptsForPassphrase guards the ordering
// itself, not just its outcome: with a sealed file present and no passphrase
// source available, a denied authorization check must still fail with the
// authorization error, never the passphrase error. If a future edit moved
// envelope detection/opening above the vaultcli.RequireDataAction check, this
// test would start seeing the "no passphrase" error instead and fail, even
// though every other test in this file would still pass. Modeled on
// TestExportCommand_Forbidden_NeverPromptsForPassphrase in export_test.go.
func TestImportCommand_Forbidden_NeverPromptsForPassphrase(t *testing.T) {
	tc := testutils.NewTestContext(t)

	denyRoles := &testutils.MockRoleAssignmentService{}
	denyRoles.On("HasDataAction", mock.Anything, mock.Anything, mock.Anything, mock.Anything).
		Return(false, nil).Maybe()
	tc.MockContainer.RoleAssignmentService = denyRoles

	// go test runs with stdin detached, so if passphrase resolution were ever
	// reached it would fail with ErrNoPassphraseAvailable rather than hanging
	// on a prompt.
	t.Setenv("ROCKETVAULT_EXPORT_PASSPHRASE", "")

	sealed, err := common.SealExport([]byte(`[{"name":"n","value":"v"}]`), "pw")
	require.NoError(t, err)

	tmpFile := filepath.Join(t.TempDir(), "import.json")
	require.NoError(t, os.WriteFile(tmpFile, sealed, 0o600))

	importFormat = "json"
	importFile = tmpFile
	importEncrypted = false
	importPassphraseFile = ""
	importOverwrite = false

	cmd := newImportTestCmd(tmpFile)
	cmd.SetContext(tc.Ctx)

	err = cmd.Execute()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "forbidden")
	assert.NotContains(t, err.Error(), "no passphrase")
	tc.MockSecretService.AssertNotCalled(t, "ImportSecrets", mock.Anything, mock.Anything)
}

func TestImportCommand_PrintsImportedSkippedAndFailedCounts(t *testing.T) {
	tc := testutils.NewTestContext(t)

	// FailedCount is 0 here: this test is only about the counter line, not
	// the error-detail/exit-code behavior a nonzero FailedCount now
	// triggers -- see TestImportCommand_ReturnsErrorAndPrintsDetailsOnFailure
	// for that.
	tc.MockSecretService.On("ImportSecrets", mock.Anything, mock.Anything).
		Return(&secretServices.ImportResult{ImportedCount: 1, SkippedCount: 2, FailedCount: 0}, nil)
	tc.MockContainer.On("GetSecretService").Return(tc.MockSecretService)

	roles := &testutils.MockRoleAssignmentService{}
	roles.On("HasDataAction", mock.Anything, tc.TestUserID, tc.TestVaultID, model.ActionSecretsSet).
		Return(true, nil).Once()
	policies := &testutils.MockAccessPolicyService{}
	policies.On("CheckAccess", mock.Anything, tc.TestUserID, model.PolicyResourceSecrets, model.OpImport, tc.TestVaultID).
		Return(authzServices.AccessAllowed, nil).Once()
	tc.MockContainer.RoleAssignmentService = roles
	tc.MockContainer.AccessPolicyService = policies

	tmpFile := t.TempDir() + "/import.json"
	os.WriteFile(tmpFile, []byte(`{}`), 0o600) //nolint:errcheck,gosec

	importFormat = "json"
	importFile = tmpFile
	importEncrypted = false
	importOverwrite = true

	cmd := &cobra.Command{Use: "import", RunE: secretsImportCmd.RunE}
	cmd.Flags().StringVarP(&importFormat, "format", "f", "json", "")
	cmd.Flags().StringVarP(&importFile, "file", "i", tmpFile, "")
	cmd.Flags().BoolVarP(&importEncrypted, "encrypted", "e", false, "")
	cmd.Flags().BoolVarP(&importOverwrite, "overwrite", "w", false, "")
	cmd.SetContext(tc.Ctx)

	origStdout := os.Stdout
	r, w, pipeErr := os.Pipe()
	require.NoError(t, pipeErr)
	os.Stdout = w

	execErr := cmd.Execute()

	w.Close() //nolint:errcheck
	os.Stdout = origStdout

	out, readErr := io.ReadAll(r)
	require.NoError(t, readErr)

	assert.NoError(t, execErr)
	assert.Equal(t, "Secrets imported successfully\nImported: 1\nSkipped: 2\nFailed: 0\n", string(out))
}

// TestImportCommand_ReturnsErrorAndPrintsDetailsOnFailure pins B38 review
// finding 3: a nonzero FailedCount used to be silent -- the command printed
// only the counters and always returned nil, so a failed record was
// invisible both on screen and to the exit code. It must now print each
// entry in result.Errors and exit non-zero.
func TestImportCommand_ReturnsErrorAndPrintsDetailsOnFailure(t *testing.T) {
	tc := testutils.NewTestContext(t)

	tc.MockSecretService.On("ImportSecrets", mock.Anything, mock.Anything).
		Return(&secretServices.ImportResult{
			ImportedCount: 1,
			SkippedCount:  0,
			FailedCount:   1,
			Errors:        []string{"'db-password': internal error"},
		}, nil)
	tc.MockContainer.On("GetSecretService").Return(tc.MockSecretService)

	roles := &testutils.MockRoleAssignmentService{}
	roles.On("HasDataAction", mock.Anything, tc.TestUserID, tc.TestVaultID, model.ActionSecretsSet).
		Return(true, nil).Once()
	policies := &testutils.MockAccessPolicyService{}
	policies.On("CheckAccess", mock.Anything, tc.TestUserID, model.PolicyResourceSecrets, model.OpImport, tc.TestVaultID).
		Return(authzServices.AccessAllowed, nil).Once()
	tc.MockContainer.RoleAssignmentService = roles
	tc.MockContainer.AccessPolicyService = policies

	tmpFile := t.TempDir() + "/import.json"
	os.WriteFile(tmpFile, []byte(`{}`), 0o600) //nolint:errcheck,gosec

	importFormat = "json"
	importFile = tmpFile
	importEncrypted = false
	importOverwrite = false

	cmd := &cobra.Command{Use: "import", RunE: secretsImportCmd.RunE}
	cmd.Flags().StringVarP(&importFormat, "format", "f", "json", "")
	cmd.Flags().StringVarP(&importFile, "file", "i", tmpFile, "")
	cmd.Flags().BoolVarP(&importEncrypted, "encrypted", "e", false, "")
	cmd.Flags().BoolVarP(&importOverwrite, "overwrite", "w", false, "")
	cmd.SetContext(tc.Ctx)

	origStdout := os.Stdout
	r, w, pipeErr := os.Pipe()
	require.NoError(t, pipeErr)
	os.Stdout = w

	execErr := cmd.Execute()

	w.Close() //nolint:errcheck
	os.Stdout = origStdout

	out, readErr := io.ReadAll(r)
	require.NoError(t, readErr)

	require.Error(t, execErr, "a nonzero FailedCount must fail the command")
	assert.Contains(t, execErr.Error(), "1 record(s) failed to import")
	assert.Contains(t, string(out), "Errors:")
	assert.Contains(t, string(out), "'db-password': internal error")
}
