package keys

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"rocketvault/cmd/testutils"
	"rocketvault/common"
	"rocketvault/internal/logging"
	auditServices "rocketvault/internal/services/audit"
	authzServices "rocketvault/internal/services/authorization"
	keyServices "rocketvault/internal/services/keys"
	"rocketvault/model"
)

// Test material is marked so that a leak is easy to search for.
const (
	keyExportTestPEM        = "-----BEGIN PRIVATE KEY-----\nTEST-KEY-MATERIAL\n-----END PRIVATE KEY-----\n"
	keyExportTestPassphrase = "export-pass-2"
)

// keyExportAudit records every structured audit event.
type keyExportAudit struct {
	mu     sync.Mutex
	events []auditServices.AuditEvent
}

func (a *keyExportAudit) RecordEvent(_ context.Context, e auditServices.AuditEvent) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.events = append(a.events, e)
	return nil
}

func (a *keyExportAudit) PersistAudit(string, string, string) error { return nil }

// only returns the single event an attempt must have recorded.
func (a *keyExportAudit) only(t *testing.T) auditServices.AuditEvent {
	t.Helper()
	a.mu.Lock()
	defer a.mu.Unlock()
	require.Len(t, a.events, 1, "exactly one structured audit event per attempt")
	return a.events[0]
}

// keyExportFixture is one export test's world: the mocks, the audit
// capture, a log buffer, a scratch directory and a key id.
type keyExportFixture struct {
	tc    *testutils.TestContext
	svc   *keyCmdKeyService
	audit *keyExportAudit
	logs  bytes.Buffer
	dir   string
	id    uuid.UUID
}

func newKeyExportFixture(t *testing.T) *keyExportFixture {
	t.Helper()
	f := &keyExportFixture{
		tc: testutils.NewTestContext(t), svc: &keyCmdKeyService{}, audit: &keyExportAudit{},
		dir: t.TempDir(), id: uuid.New(),
	}
	f.tc.MockContainer.On("GetAuditService").Return(f.audit)
	// Isolate every run from the developer's own environment.
	t.Setenv(common.ExportPassphraseEnvVar, "")
	return f
}

func (f *keyExportFixture) scope() model.Scope {
	return model.NewVaultScope(f.tc.TestVaultID, f.tc.TestUserID)
}

func (f *keyExportFixture) path(name string) string { return filepath.Join(f.dir, name) }

// run executes a fresh "keys export" as a caller holding only the plain user
// account role, so a pass proves no account role is required.
func (f *keyExportFixture) run(args ...string) (stdout, stderr string, err error) {
	cmd := newKeyExportCmd()
	var out, errOut bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&errOut)
	cmd.SetArgs(args)
	l := logrus.New()
	l.SetOutput(&f.logs)
	claims := &model.Claims{UserID: f.tc.TestUserID, Username: "exporter", Roles: []string{model.RoleUser}}
	ctx := context.WithValue(context.Background(), common.ClaimsKey, claims)
	ctx = context.WithValue(ctx, common.LogKey, &logging.Logger{Logger: l})
	ctx = context.WithValue(ctx, common.ServiceContainerKey, &keysTestContainer{MockServiceContainer: f.tc.MockContainer, keySvc: f.svc})
	cmd.SetContext(ctx)
	err = cmd.Execute()
	return out.String(), errOut.String(), err
}

// everything returns every byte a run could have leaked through.
func (f *keyExportFixture) everything(stdout, stderr string) string {
	f.audit.mu.Lock()
	defer f.audit.mu.Unlock()
	var b strings.Builder
	b.WriteString(stdout + stderr + f.logs.String())
	for _, e := range f.audit.events {
		b.WriteString(e.Details + e.ResourceID + e.Action)
	}
	return b.String()
}

func keyExport(id uuid.UUID, version int) *keyServices.ExportKeyResult {
	return &keyServices.ExportKeyResult{
		ID: id, Name: "signer", Type: model.KeyTypeRSA, Version: version, Format: model.ExportFormatPEM,
		PrivateKeyPEM: keyExportTestPEM, KeyAlgorithm: "RSA-2048",
	}
}

// assertNoKeyFile fails if path exists or a temporary file was left beside it.
func assertNoKeyFile(t *testing.T, path string) {
	t.Helper()
	_, err := os.Stat(path)
	assert.ErrorIs(t, err, fs.ErrNotExist, "no file may be written at %s", path)
	entries, err := os.ReadDir(filepath.Dir(path))
	require.NoError(t, err)
	for _, e := range entries {
		assert.False(t, strings.HasPrefix(e.Name(), ".rocketvault-export-"), "temporary file left behind: %s", e.Name())
	}
}

func assertKeyMode0600(t *testing.T, path string) {
	t.Helper()
	info, err := os.Stat(path)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o600), info.Mode().Perm())
}

func TestKeyExport_SealedByDefaultAndOpensBack(t *testing.T) {
	f := newKeyExportFixture(t)
	t.Setenv(common.ExportPassphraseEnvVar, keyExportTestPassphrase)
	f.svc.On("ExportKey", mock.Anything, f.scope(), f.id, 0).Return(keyExport(f.id, 3), nil).Once()

	out := f.path("signer.pem.sealed")
	stdout, stderr, err := f.run(f.id.String(), "--file", out)
	require.NoError(t, err)
	f.svc.AssertExpectations(t)
	assert.Contains(t, stdout, "Key exported successfully")
	assert.Contains(t, stdout, "Version: 3")
	assert.Contains(t, stdout, "Encryption: passphrase (argon2id + AES-256-GCM)")
	assert.Empty(t, stderr)

	data, err := os.ReadFile(out)
	require.NoError(t, err)
	assert.NotContains(t, string(data), "TEST-KEY-MATERIAL")
	assertKeyMode0600(t, out)

	p, err := common.OpenItemExport(data, keyExportTestPassphrase)
	require.NoError(t, err)
	assert.Equal(t, common.ItemExportKindKey, p.Kind)
	assert.Equal(t, f.id.String(), p.ID)
	assert.Equal(t, "signer", p.Name)
	assert.Equal(t, 3, p.Version)
	assert.Equal(t, model.ExportFormatPEM, p.Format)
	assert.Equal(t, "RSA-2048", p.KeyAlgorithm)
	assert.Equal(t, keyExportTestPEM, string(p.Content))

	ev := f.audit.only(t)
	assert.Equal(t, "export_key", ev.Action)
	assert.Equal(t, "success", ev.Outcome)
	assert.Equal(t, "cli", ev.Source)
	assert.Equal(t, "key", ev.ResourceType)
	assert.Equal(t, f.id.String(), ev.ResourceID)
	assert.Equal(t, f.tc.TestUserID.String(), ev.UserID)
	assert.Contains(t, ev.Details, `"vault_id":"`+f.tc.TestVaultID.String()+`"`)
	assert.Contains(t, ev.Details, `"name":"signer"`)
	assert.Contains(t, ev.Details, `"version":3`)
	assert.Contains(t, ev.Details, `"format":"pem"`)
}

func TestKeyExport_EncryptFlagValuesAreCaseInsensitive(t *testing.T) {
	// Cobra parses booleans with strconv.ParseBool, so "TRUE" still seals.
	f := newKeyExportFixture(t)
	t.Setenv(common.ExportPassphraseEnvVar, keyExportTestPassphrase)
	f.svc.On("ExportKey", mock.Anything, f.scope(), f.id, 0).Return(keyExport(f.id, 1), nil).Once()

	out := f.path("signer.pem.sealed")
	stdout, stderr, err := f.run(f.id.String(), "--file", out, "--encrypt=TRUE")
	require.NoError(t, err)
	assert.Empty(t, stderr)
	assert.Contains(t, stdout, "Encryption: passphrase (argon2id + AES-256-GCM)")
	data, err := os.ReadFile(out)
	require.NoError(t, err)
	_, err = common.OpenItemExport(data, keyExportTestPassphrase)
	require.NoError(t, err)
	assert.Equal(t, "success", f.audit.only(t).Outcome)
}

func TestKeyExport_PlaintextWritesThePEMAndWarns(t *testing.T) {
	f := newKeyExportFixture(t)
	f.svc.On("ExportKey", mock.Anything, f.scope(), f.id, 1).Return(keyExport(f.id, 1), nil).Once()

	out := f.path("signer.pem")
	stdout, stderr, err := f.run(f.id.String(), "--file", out, "--encrypt=false", "--version", "1")
	require.NoError(t, err)
	f.svc.AssertExpectations(t)
	data, err := os.ReadFile(out)
	require.NoError(t, err)
	assert.Equal(t, keyExportTestPEM, string(data))
	assertKeyMode0600(t, out)
	assert.Equal(t, "Warning: --encrypt=false — "+out+" will hold the key's private key unencrypted, in the clear.\n", stderr)
	assert.Contains(t, stdout, "Encryption: none (plaintext)")
	assert.NotContains(t, f.everything(stdout, stderr), "TEST-KEY-MATERIAL")
	assert.Equal(t, "success", f.audit.only(t).Outcome)
}

func TestKeyExport_PassphraseFileComesBeforeTheEnvironment(t *testing.T) {
	f := newKeyExportFixture(t)
	t.Setenv(common.ExportPassphraseEnvVar, "from-environment")
	pw := f.path("export-pass")
	require.NoError(t, os.WriteFile(pw, []byte(keyExportTestPassphrase+"\n"), 0o600))
	f.svc.On("ExportKey", mock.Anything, f.scope(), f.id, 0).Return(keyExport(f.id, 1), nil).Once()

	out := f.path("signer.pem.sealed")
	stdout, stderr, err := f.run(f.id.String(), "--file", out, "--passphrase-file", pw)
	require.NoError(t, err)
	data, err := os.ReadFile(out)
	require.NoError(t, err)
	_, err = common.OpenItemExport(data, keyExportTestPassphrase)
	require.NoError(t, err, "the file's passphrase seals the export")
	_, err = common.OpenItemExport(data, "from-environment")
	assert.ErrorIs(t, err, common.ErrWrongPassphrase)
	assert.NotContains(t, f.everything(stdout, stderr), keyExportTestPassphrase)
	assert.Equal(t, "success", f.audit.only(t).Outcome)
}

func TestKeyExport_NoPassphraseWritesNothing(t *testing.T) {
	f := newKeyExportFixture(t)
	out := f.path("signer.pem.sealed")

	_, _, err := f.run(f.id.String(), "--file", out)
	require.Error(t, err)
	assert.True(t, strings.HasPrefix(err.Error(), "failed to export key: "), err.Error())
	assert.Contains(t, err.Error(), "no passphrase is available")
	f.svc.AssertNotCalled(t, "ExportKey", mock.Anything, mock.Anything, mock.Anything, mock.Anything)
	assertNoKeyFile(t, out)
	ev := f.audit.only(t)
	assert.Equal(t, "failure", ev.Outcome)
	assert.Contains(t, ev.Details, `"reason":"export passphrase unavailable"`)
}

func TestKeyExport_PassphraseFileProblemsWriteNothing(t *testing.T) {
	cases := []struct {
		name  string
		setup func(t *testing.T, f *keyExportFixture) string
		want  string
	}{
		{"missing", func(_ *testing.T, f *keyExportFixture) string { return f.path("absent") },
			"failed to read passphrase file"},
		{"empty", func(t *testing.T, f *keyExportFixture) string {
			p := f.path("blank")
			require.NoError(t, os.WriteFile(p, []byte("\n"), 0o600))
			return p
		}, "is empty"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := newKeyExportFixture(t)
			// The file comes first, so the environment must not rescue it.
			t.Setenv(common.ExportPassphraseEnvVar, keyExportTestPassphrase)
			out := f.path("signer.pem.sealed")

			_, _, err := f.run(f.id.String(), "--file", out, "--passphrase-file", c.setup(t, f))
			require.Error(t, err)
			assert.True(t, strings.HasPrefix(err.Error(), "failed to export key: "), err.Error())
			assert.Contains(t, err.Error(), c.want)
			f.svc.AssertNotCalled(t, "ExportKey", mock.Anything, mock.Anything, mock.Anything, mock.Anything)
			assertNoKeyFile(t, out)
			ev := f.audit.only(t)
			assert.Equal(t, "failure", ev.Outcome)
			assert.Contains(t, ev.Details, `"reason":"export passphrase unavailable"`)
		})
	}
}

func TestKeyExport_RejectsBadInputBeforeAuthorization(t *testing.T) {
	cases := []struct {
		name string
		args func(f *keyExportFixture) []string
		want string
	}{
		{"id is not a UUID", func(f *keyExportFixture) []string { return []string{"not-a-uuid", "--file", f.path("o")} },
			"key ID must be a UUID"},
		{"negative version", func(f *keyExportFixture) []string {
			return []string{f.id.String(), "--file", f.path("o"), "--version=-1"}
		}, "--version must be 0 or a positive version number"},
		{"stdout", func(f *keyExportFixture) []string { return []string{f.id.String(), "--file", "-"} },
			"--file - is not supported: an export is only ever written to a file"},
		{"plaintext with passphrase file", func(f *keyExportFixture) []string {
			return []string{f.id.String(), "--file", f.path("o"), "--encrypt=false", "--passphrase-file", f.path("pw")}
		}, "--passphrase-file was given with --encrypt=false: drop one, since a plaintext export has no passphrase"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := newKeyExportFixture(t)
			roles := &testutils.MockRoleAssignmentService{}
			f.tc.MockContainer.RoleAssignmentService = roles

			_, _, err := f.run(c.args(f)...)
			require.Error(t, err)
			assert.Equal(t, "failed to export key: "+c.want, err.Error())
			roles.AssertNotCalled(t, "HasDataAction", mock.Anything, mock.Anything, mock.Anything, mock.Anything)
			f.svc.AssertNotCalled(t, "ExportKey", mock.Anything, mock.Anything, mock.Anything, mock.Anything)
			assertNoKeyFile(t, f.path("o"))
			ev := f.audit.only(t)
			assert.Equal(t, "failure", ev.Outcome)
			assert.Contains(t, ev.Details, `"code":"bad_request"`)
			assert.Contains(t, ev.Details, `"reason":"`+c.want+`"`)
		})
	}
}

func TestKeyExport_InvalidIDIsNeverAudited(t *testing.T) {
	f := newKeyExportFixture(t)

	_, _, err := f.run("raw-id-text", "--file", f.path("o"))
	require.Error(t, err)
	ev := f.audit.only(t)
	assert.Empty(t, ev.ResourceID)
	assert.NotContains(t, ev.Details, "raw-id-text")
}

func TestKeyExport_NeverReplacesAFileWithoutForce(t *testing.T) {
	f := newKeyExportFixture(t)
	out := f.path("signer.pem")
	require.NoError(t, os.WriteFile(out, []byte("original"), 0o644))

	_, _, err := f.run(f.id.String(), "--file", out, "--encrypt=false")
	assert.EqualError(t, err, "failed to export key: the output file already exists: pass --force to replace it")
	f.svc.AssertNotCalled(t, "ExportKey", mock.Anything, mock.Anything, mock.Anything, mock.Anything)
	data, err := os.ReadFile(out)
	require.NoError(t, err)
	assert.Equal(t, "original", string(data))
	ev := f.audit.only(t)
	assert.Equal(t, "failure", ev.Outcome)
	assert.Contains(t, ev.Details, `"reason":"the output file already exists: pass --force to replace it"`)
	f.audit.events = nil

	f.svc.On("ExportKey", mock.Anything, f.scope(), f.id, 0).Return(keyExport(f.id, 1), nil).Once()
	_, _, err = f.run(f.id.String(), "--file", out, "--encrypt=false", "--force")
	require.NoError(t, err)
	data, err = os.ReadFile(out)
	require.NoError(t, err)
	assert.Equal(t, keyExportTestPEM, string(data))
	assertKeyMode0600(t, out)
	assert.Equal(t, "success", f.audit.only(t).Outcome)
}

func TestKeyExport_DanglingSymlinkCountsAsAnExistingFile(t *testing.T) {
	f := newKeyExportFixture(t)
	out := f.path("signer.pem")
	require.NoError(t, os.Symlink(f.path("nowhere"), out))

	_, _, err := f.run(f.id.String(), "--file", out, "--encrypt=false")
	assert.EqualError(t, err, "failed to export key: the output file already exists: pass --force to replace it")
	f.svc.AssertNotCalled(t, "ExportKey", mock.Anything, mock.Anything, mock.Anything, mock.Anything)
	_, err = os.Stat(f.path("nowhere"))
	assert.ErrorIs(t, err, fs.ErrNotExist, "the symlink target must never be written")
	assert.Contains(t, f.audit.only(t).Details, `"code":"bad_request"`)
}

func TestKeyExport_DeniedWithoutTheExportAction(t *testing.T) {
	f := newKeyExportFixture(t)
	roles := &testutils.MockRoleAssignmentService{}
	roles.On("HasDataAction", mock.Anything, f.tc.TestUserID, f.tc.TestVaultID, model.ActionKeysExport).
		Return(false, nil).Once()
	f.tc.MockContainer.RoleAssignmentService = roles
	out := f.path("signer.pem.sealed")

	_, _, err := f.run(f.id.String(), "--file", out)
	require.Error(t, err)
	assert.True(t, strings.HasPrefix(err.Error(), "failed to export key: "), err.Error())
	assert.Contains(t, err.Error(), "forbidden")
	assert.NotContains(t, err.Error(), "passphrase", "an unauthorized caller is never asked for a passphrase")
	roles.AssertExpectations(t)
	f.svc.AssertNotCalled(t, "ExportKey", mock.Anything, mock.Anything, mock.Anything, mock.Anything)
	assertNoKeyFile(t, out)
	ev := f.audit.only(t)
	assert.Equal(t, "failure", ev.Outcome)
	assert.Contains(t, ev.Details, `"code":"forbidden"`)
	assert.Contains(t, ev.Details, `"reason":"vault authorization failed"`)
	assert.Contains(t, ev.Details, `"vault_id":"`+f.tc.TestVaultID.String()+`"`)
}

func TestKeyExport_DeniedCallerNeverReachesAPassphraseSource(t *testing.T) {
	f := newKeyExportFixture(t)
	roles := &testutils.MockRoleAssignmentService{}
	roles.On("HasDataAction", mock.Anything, f.tc.TestUserID, f.tc.TestVaultID, model.ActionKeysExport).
		Return(false, nil).Once()
	f.tc.MockContainer.RoleAssignmentService = roles
	out := f.path("signer.pem.sealed")

	// The passphrase file is missing, so reading it before authorization
	// would change the error.
	_, _, err := f.run(f.id.String(), "--file", out, "--passphrase-file", f.path("missing-export-pass"))
	require.Error(t, err)
	assert.True(t, strings.HasPrefix(err.Error(), "failed to export key: "), err.Error())
	assert.Contains(t, err.Error(), "forbidden")
	assert.NotContains(t, err.Error(), "missing-export-pass")
	f.svc.AssertNotCalled(t, "ExportKey", mock.Anything, mock.Anything, mock.Anything, mock.Anything)
	assertNoKeyFile(t, out)
	assert.Contains(t, f.audit.only(t).Details, `"code":"forbidden"`)
}

func TestKeyExport_ExplicitDenyOverridesARoleGrant(t *testing.T) {
	f := newKeyExportFixture(t)
	policies := &testutils.MockAccessPolicyService{}
	policies.On("CheckAccess", mock.Anything, f.tc.TestUserID, model.PolicyResourceKeys, model.OpCreate, f.tc.TestVaultID).
		Return(authzServices.AccessDenied, nil).Once()
	f.tc.MockContainer.AccessPolicyService = policies
	out := f.path("signer.pem.sealed")

	_, _, err := f.run(f.id.String(), "--file", out)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "explicit access policy")
	policies.AssertExpectations(t)
	f.svc.AssertNotCalled(t, "ExportKey", mock.Anything, mock.Anything, mock.Anything, mock.Anything)
	assertNoKeyFile(t, out)
	assert.Contains(t, f.audit.only(t).Details, `"code":"forbidden"`)
}

func TestKeyExport_ChecksTheExportActionAndCreatePolicy(t *testing.T) {
	f := newKeyExportFixture(t)
	t.Setenv(common.ExportPassphraseEnvVar, keyExportTestPassphrase)
	roles := &testutils.MockRoleAssignmentService{}
	roles.On("HasDataAction", mock.Anything, f.tc.TestUserID, f.tc.TestVaultID, model.ActionKeysExport).Return(true, nil).Once()
	policies := &testutils.MockAccessPolicyService{}
	policies.On("CheckAccess", mock.Anything, f.tc.TestUserID, model.PolicyResourceKeys, model.OpCreate, f.tc.TestVaultID).
		Return(authzServices.AccessAllowed, nil).Once()
	f.tc.MockContainer.RoleAssignmentService = roles
	f.tc.MockContainer.AccessPolicyService = policies
	f.svc.On("ExportKey", mock.Anything, f.scope(), f.id, 0).Return(keyExport(f.id, 1), nil).Once()

	_, _, err := f.run(f.id.String(), "--file", f.path("signer.pem.sealed"))
	require.NoError(t, err)
	roles.AssertExpectations(t)
	policies.AssertExpectations(t)
	f.svc.AssertExpectations(t)
}

func TestKeyExport_ServiceErrorsShowOnlyFixedMessages(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want string
		code string
	}{
		{"oct refusal", &model.ExportRefusedError{Sentinel: model.ErrKeyNotExportable, Reason: "symmetric oct keys are not exportable", Name: "wrap"},
			"failed to export key: key is not exportable: symmetric oct keys are not exportable", "key_not_exportable"},
		{"es256k refusal", &model.ExportRefusedError{Sentinel: model.ErrKeyNotExportable, Reason: "ES256K (secp256k1) keys cannot be encoded as PKCS#8", Name: "chain"},
			"failed to export key: key is not exportable: ES256K (secp256k1) keys cannot be encoded as PKCS#8", "key_not_exportable"},
		{"hsm refusal", &model.ExportRefusedError{Sentinel: model.ErrKeyNotExportable, Reason: "HSM-backed keys never leave the token", Name: "hsm"},
			"failed to export key: key is not exportable: HSM-backed keys never leave the token", "key_not_exportable"},
		{"not exportable", &model.ExportRefusedError{Sentinel: model.ErrKeyNotExportable, Reason: "the key was not created with exportable: true", Name: "signer"},
			"failed to export key: key is not exportable: the key was not created with exportable: true", "key_not_exportable"},
		{"not found", fmt.Errorf("%w: sql: raw-detail", keyServices.ErrKeyNotFound), "failed to export key: key or version not found", "not_found"},
		{"version not found", fmt.Errorf("%w: key raw-detail has no version 9", model.ErrKeyVersionNotFound), "failed to export key: key or version not found", "not_found"},
		{"revoked", fmt.Errorf("%w", keyServices.ErrKeyLifecycleDenied), "failed to export key: the key is disabled or outside its valid time window", "key_disabled"},
		{"invalid request", fmt.Errorf("%w: version must be 0 or a positive version number", model.ErrInvalidExportRequest),
			"failed to export key: invalid export request: version must be 0 or a positive version number", "bad_request"},
		{"internal", errors.New("decrypt key material: raw-detail"), "failed to export key: internal error; see the RocketVault log for details", "internal_error"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := newKeyExportFixture(t)
			t.Setenv(common.ExportPassphraseEnvVar, keyExportTestPassphrase)
			f.svc.On("ExportKey", mock.Anything, f.scope(), f.id, 0).Return(nil, c.err).Once()
			out := f.path("signer.pem.sealed")

			stdout, stderr, err := f.run(f.id.String(), "--file", out)
			assert.EqualError(t, err, c.want)
			assert.NotContains(t, stdout, "exported successfully")
			assertNoKeyFile(t, out)
			ev := f.audit.only(t)
			assert.Equal(t, "failure", ev.Outcome)
			assert.Contains(t, ev.Details, `"code":"`+c.code+`"`)
			assert.NotContains(t, ev.Details, "raw-detail")
			assert.NotContains(t, stdout+stderr, "raw-detail")
		})
	}
}

func TestKeyExport_RefusalNamesTheKeyInTheAuditEvent(t *testing.T) {
	f := newKeyExportFixture(t)
	t.Setenv(common.ExportPassphraseEnvVar, keyExportTestPassphrase)
	f.svc.On("ExportKey", mock.Anything, f.scope(), f.id, 0).Return(nil, &model.ExportRefusedError{
		Sentinel: model.ErrKeyNotExportable, Reason: "the key was not created with exportable: true",
		Name: "signer", KeyAlgorithm: "RSA-2048",
	}).Once()

	_, _, err := f.run(f.id.String(), "--file", f.path("signer.pem.sealed"))
	require.Error(t, err)
	ev := f.audit.only(t)
	assert.Contains(t, ev.Details, `"reason":"the key was not created with exportable: true"`)
	assert.Contains(t, ev.Details, `"name":"signer"`)
}

func TestKeyExport_WriteFailureIsAuditedOnceAsAFailure(t *testing.T) {
	f := newKeyExportFixture(t)
	t.Setenv(common.ExportPassphraseEnvVar, keyExportTestPassphrase)
	// A regular file where a parent directory should be makes the write fail
	// after the service has released the material.
	require.NoError(t, os.WriteFile(f.path("blocker"), []byte("x"), 0o600))
	out := filepath.Join(f.path("blocker"), "signer.pem.sealed")
	f.svc.On("ExportKey", mock.Anything, f.scope(), f.id, 0).Return(keyExport(f.id, 1), nil).Once()

	stdout, stderr, err := f.run(f.id.String(), "--file", out)
	require.Error(t, err)
	assert.True(t, strings.HasPrefix(err.Error(), "failed to export key: "), err.Error())
	f.svc.AssertExpectations(t)
	assert.NotContains(t, stdout, "exported successfully")
	ev := f.audit.only(t)
	assert.Equal(t, "failure", ev.Outcome)
	assert.Contains(t, ev.Details, `"code":"output_failed"`)
	assert.Contains(t, ev.Details, `"reason":"the output file could not be written"`)
	all := f.everything(stdout, stderr) + err.Error()
	for _, secret := range []string{"TEST-KEY-MATERIAL", keyExportTestPassphrase} {
		assert.NotContains(t, all, secret)
	}
}

func TestKeyExport_MissingClaimsRecordsNoAttempt(t *testing.T) {
	f := newKeyExportFixture(t)
	cmd := newKeyExportCmd()
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	cmd.SetArgs([]string{f.id.String(), "--file", f.path("o")})
	cmd.SetContext(context.WithValue(context.Background(), common.ServiceContainerKey,
		&keysTestContainer{MockServiceContainer: f.tc.MockContainer, keySvc: f.svc}))

	err := cmd.Execute()
	assert.EqualError(t, err, "unauthorized: missing authentication claims")
	f.svc.AssertNotCalled(t, "ExportKey", mock.Anything, mock.Anything, mock.Anything, mock.Anything)
	assert.Empty(t, f.audit.events, "no caller means no attempt to audit")
}

func TestKeyExport_NoMaterialOrSecretInAnyOutput(t *testing.T) {
	cases := []struct {
		name    string
		result  *keyServices.ExportKeyResult
		err     error
		encrypt string
	}{
		{"sealed", &keyServices.ExportKeyResult{}, nil, "--encrypt=true"},
		{"plaintext", &keyServices.ExportKeyResult{}, nil, "--encrypt=false"},
		{"service failure", nil, errors.New("encode key material: raw-detail"), "--encrypt=true"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := newKeyExportFixture(t)
			// The passphrase arrives through a file, so a leak of the file's
			// content would show up here too.
			pw := f.path("export-pass")
			require.NoError(t, os.WriteFile(pw, []byte(keyExportTestPassphrase+"\n"), 0o600))
			args := []string{f.id.String(), "--file", f.path("out"), c.encrypt}
			if c.encrypt == "--encrypt=true" {
				args = append(args, "--passphrase-file", pw)
			}
			result := c.result
			if result != nil {
				result = keyExport(f.id, 1)
			}
			f.svc.On("ExportKey", mock.Anything, f.scope(), f.id, 0).Return(result, c.err).Once()

			stdout, stderr, err := f.run(args...)
			assert.Equal(t, c.err != nil, err != nil)
			all := f.everything(stdout, stderr)
			if err != nil {
				all += err.Error()
			}
			// Guard against a vacuous pass: the run must have produced output.
			assert.NotEmpty(t, all)
			for _, secret := range []string{"TEST-KEY-MATERIAL", keyExportTestPassphrase} {
				assert.NotContains(t, all, secret)
			}
			// An internal cause goes to the log file only.
			assert.NotContains(t, stdout+stderr, "raw-detail")
			assert.NotContains(t, f.audit.only(t).Details, "raw-detail")
		})
	}
}

func TestInitKeysExport_RegistersTheCommandAndFlags(t *testing.T) {
	parent := &cobra.Command{Use: "keys"}
	InitKeysExport(parent)
	cmd, _, err := parent.Find([]string{"export"})
	require.NoError(t, err)
	assert.Equal(t, "export <id>", cmd.Use)
	for name, def := range map[string]string{
		"file": "", "encrypt": "true", "passphrase-file": "", "force": "false", "version": "0",
	} {
		fl := cmd.Flags().Lookup(name)
		require.NotNil(t, fl, name)
		assert.Equal(t, def, fl.DefValue, name)
	}
	assert.Equal(t, "o", cmd.Flags().Lookup("file").Shorthand)
	assert.Equal(t, "e", cmd.Flags().Lookup("encrypt").Shorthand)
	assert.Equal(t, []string{"true"}, cmd.Flags().Lookup("file").Annotations[cobra.BashCompOneRequiredFlag])
	for _, absent := range []string{"format", "compat", "pkcs12-password-file", "pkcs12-empty-password", "passphrase"} {
		assert.Nil(t, cmd.Flags().Lookup(absent), "keys export has no --%s flag", absent)
	}
}
