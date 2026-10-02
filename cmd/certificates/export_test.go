package certificates

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
	certServices "rocketvault/internal/services/certificates"
	"rocketvault/model"
)

// Test material is marked so that a leak is easy to search for.
const (
	exportTestLeaf       = "-----BEGIN CERTIFICATE-----\nTEST-LEAF-BODY\n-----END CERTIFICATE-----\n"
	exportTestKey        = "-----BEGIN PRIVATE KEY-----\nTEST-KEY-MATERIAL\n-----END PRIVATE KEY-----\n"
	exportTestPassphrase = "export-pass-1"
	exportTestP12        = "p12-secret-1"
)

// certExportAudit records every structured audit event.
type certExportAudit struct {
	mu     sync.Mutex
	events []auditServices.AuditEvent
}

func (a *certExportAudit) RecordEvent(_ context.Context, e auditServices.AuditEvent) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.events = append(a.events, e)
	return nil
}

func (a *certExportAudit) PersistAudit(string, string, string) error { return nil }

// only returns the single event an attempt must have recorded.
func (a *certExportAudit) only(t *testing.T) auditServices.AuditEvent {
	t.Helper()
	a.mu.Lock()
	defer a.mu.Unlock()
	require.Len(t, a.events, 1, "exactly one structured audit event per attempt")
	return a.events[0]
}

// certExportFixture is one export test's world: the mocks, the audit
// capture, a log buffer, a scratch directory and a certificate id.
type certExportFixture struct {
	tc    *testutils.TestContext
	svc   *certCmdCertService
	audit *certExportAudit
	logs  bytes.Buffer
	dir   string
	id    uuid.UUID
}

func newCertExportFixture(t *testing.T) *certExportFixture {
	t.Helper()
	f := &certExportFixture{
		tc: testutils.NewTestContext(t), svc: &certCmdCertService{}, audit: &certExportAudit{},
		dir: t.TempDir(), id: uuid.New(),
	}
	f.tc.MockContainer.On("GetAuditService").Return(f.audit)
	// Isolate every run from the developer's own environment.
	t.Setenv(common.ExportPassphraseEnvVar, "")
	t.Setenv(pkcs12PasswordEnvVar, "")
	return f
}

func (f *certExportFixture) scope() model.Scope {
	return model.NewVaultScope(f.tc.TestVaultID, f.tc.TestUserID)
}

func (f *certExportFixture) path(name string) string { return filepath.Join(f.dir, name) }

// run executes a fresh "certificates export" as a caller holding only the
// plain user account role, so a pass proves no account role is required.
func (f *certExportFixture) run(args ...string) (stdout, stderr string, err error) {
	cmd := newExportCmd()
	var out, errOut bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&errOut)
	cmd.SetArgs(args)
	l := logrus.New()
	l.SetOutput(&f.logs)
	claims := &model.Claims{UserID: f.tc.TestUserID, Username: "exporter", Roles: []string{model.RoleUser}}
	ctx := context.WithValue(context.Background(), common.ClaimsKey, claims)
	ctx = context.WithValue(ctx, common.LogKey, &logging.Logger{Logger: l})
	ctx = context.WithValue(ctx, common.ServiceContainerKey, &certsTestContainer{MockServiceContainer: f.tc.MockContainer, certSvc: f.svc})
	cmd.SetContext(ctx)
	err = cmd.Execute()
	return out.String(), errOut.String(), err
}

// everything returns every byte a run could have leaked through.
func (f *certExportFixture) everything(stdout, stderr string) string {
	f.audit.mu.Lock()
	defer f.audit.mu.Unlock()
	var b strings.Builder
	b.WriteString(stdout + stderr + f.logs.String())
	for _, e := range f.audit.events {
		b.WriteString(e.Details + e.ResourceID + e.Action)
	}
	return b.String()
}

func pemExport(id uuid.UUID) *certServices.ExportCertificateResult {
	return &certServices.ExportCertificateResult{
		ID: id, Name: "client", Version: 2, Format: model.ExportFormatPEM,
		CertificatePEM: exportTestLeaf, PrivateKeyPEM: exportTestKey, KeyAlgorithm: "RSA-2048",
	}
}

// assertNoFile fails if path exists or a temporary file was left beside it.
func assertNoFile(t *testing.T, path string) {
	t.Helper()
	_, err := os.Stat(path)
	assert.ErrorIs(t, err, fs.ErrNotExist, "no file may be written at %s", path)
	entries, err := os.ReadDir(filepath.Dir(path))
	require.NoError(t, err)
	for _, e := range entries {
		assert.False(t, strings.HasPrefix(e.Name(), ".rocketvault-export-"), "temporary file left behind: %s", e.Name())
	}
}

func assertMode0600(t *testing.T, path string) {
	t.Helper()
	info, err := os.Stat(path)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o600), info.Mode().Perm())
}

func TestCertExport_SealedByDefaultAndOpensBack(t *testing.T) {
	f := newCertExportFixture(t)
	t.Setenv(common.ExportPassphraseEnvVar, exportTestPassphrase)
	f.svc.On("ExportCertificate", mock.Anything, f.scope(), f.id, certServices.ExportCertificateRequest{
		Format: model.ExportFormatPEM, Compat: model.ExportCompatModern,
	}).Return(pemExport(f.id), nil).Once()

	out := f.path("client.pem.sealed")
	stdout, stderr, err := f.run(f.id.String(), "--file", out)
	require.NoError(t, err)
	f.svc.AssertExpectations(t)
	assert.Contains(t, stdout, "Certificate exported successfully")
	assert.Contains(t, stdout, "Encryption: passphrase (argon2id + AES-256-GCM)")
	assert.Empty(t, stderr)

	data, err := os.ReadFile(out)
	require.NoError(t, err)
	assert.NotContains(t, string(data), "TEST-KEY-MATERIAL")
	assertMode0600(t, out)

	p, err := common.OpenItemExport(data, exportTestPassphrase)
	require.NoError(t, err)
	assert.Equal(t, common.ItemExportKindCertificate, p.Kind)
	assert.Equal(t, f.id.String(), p.ID)
	assert.Equal(t, "client", p.Name)
	assert.Equal(t, 2, p.Version)
	assert.Equal(t, model.ExportFormatPEM, p.Format)
	assert.Equal(t, "RSA-2048", p.KeyAlgorithm)
	assert.Equal(t, exportTestLeaf+exportTestKey, string(p.Content))

	ev := f.audit.only(t)
	assert.Equal(t, "export_certificate", ev.Action)
	assert.Equal(t, "success", ev.Outcome)
	assert.Equal(t, "cli", ev.Source)
	assert.Equal(t, "certificate", ev.ResourceType)
	assert.Equal(t, f.id.String(), ev.ResourceID)
	assert.Equal(t, f.tc.TestUserID.String(), ev.UserID)
	assert.Contains(t, ev.Details, `"vault_id":"`+f.tc.TestVaultID.String()+`"`)
	assert.Contains(t, ev.Details, `"name":"client"`)
	assert.Contains(t, ev.Details, `"version":2`)
	assert.Contains(t, ev.Details, `"format":"pem"`)
}

func TestCertExport_PlaintextWritesThePEMAndWarns(t *testing.T) {
	f := newCertExportFixture(t)
	f.svc.On("ExportCertificate", mock.Anything, f.scope(), f.id, mock.Anything).Return(pemExport(f.id), nil).Once()

	out := f.path("client.pem")
	stdout, stderr, err := f.run(f.id.String(), "--file", out, "--encrypt=false")
	require.NoError(t, err)
	data, err := os.ReadFile(out)
	require.NoError(t, err)
	assert.Equal(t, exportTestLeaf+exportTestKey, string(data))
	assertMode0600(t, out)
	assert.Equal(t, "Warning: --encrypt=false — "+out+" will hold the certificate's private key unencrypted, in the clear.\n", stderr)
	assert.Contains(t, stdout, "Encryption: none (plaintext)")
	assert.NotContains(t, f.everything(stdout, stderr), "TEST-KEY-MATERIAL")
}

func TestCertExport_VersionReachesTheService(t *testing.T) {
	f := newCertExportFixture(t)
	f.svc.On("ExportCertificate", mock.Anything, f.scope(), f.id, certServices.ExportCertificateRequest{
		Format: model.ExportFormatPEM, Compat: model.ExportCompatModern, Version: 1,
	}).Return(pemExport(f.id), nil).Once()

	_, _, err := f.run(f.id.String(), "--file", f.path("v1.pem"), "--encrypt=false", "--version", "1")
	require.NoError(t, err)
	f.svc.AssertExpectations(t)
}

func TestCertExport_PKCS12PasswordSources(t *testing.T) {
	cases := []struct {
		name  string
		setup func(t *testing.T, f *certExportFixture) []string
		want  string
	}{
		{"file", func(t *testing.T, f *certExportFixture) []string {
			pw := f.path("p12-pass")
			require.NoError(t, os.WriteFile(pw, []byte(exportTestP12+"\n"), 0o600))
			return []string{"--pkcs12-password-file", pw}
		}, exportTestP12},
		{"environment", func(t *testing.T, _ *certExportFixture) []string {
			t.Setenv(pkcs12PasswordEnvVar, exportTestP12)
			return nil
		}, exportTestP12},
		{"explicit empty", func(_ *testing.T, _ *certExportFixture) []string {
			return []string{"--pkcs12-empty-password"}
		}, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := newCertExportFixture(t)
			extra := c.setup(t, f)
			want := c.want
			f.svc.On("ExportCertificate", mock.Anything, f.scope(), f.id, mock.MatchedBy(func(r certServices.ExportCertificateRequest) bool {
				return r.Format == model.ExportFormatPKCS12 && r.Compat == model.ExportCompatLegacy && r.Password != nil && *r.Password == want
			})).Return(&certServices.ExportCertificateResult{
				ID: f.id, Name: "client", Version: 1, Format: model.ExportFormatPKCS12, PKCS12: []byte("P12-BYTES"), KeyAlgorithm: "EC-P256",
			}, nil).Once()

			out := f.path("client.p12")
			args := append([]string{f.id.String(), "--format", "pkcs12", "--compat", "legacy", "--file", out, "--encrypt=false"}, extra...)
			stdout, stderr, err := f.run(args...)
			require.NoError(t, err)
			f.svc.AssertExpectations(t)
			data, err := os.ReadFile(out)
			require.NoError(t, err)
			assert.Equal(t, "P12-BYTES", string(data))
			assert.Contains(t, stderr, "protected only by the PKCS12 password")
			if want != "" {
				assert.NotContains(t, f.everything(stdout, stderr), want)
			}
		})
	}
}

func TestCertExport_PKCS12WithoutAPasswordWritesNothing(t *testing.T) {
	f := newCertExportFixture(t)
	out := f.path("client.p12")

	_, _, err := f.run(f.id.String(), "--format", "pkcs12", "--file", out, "--encrypt=false")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "pkcs12 needs a password")
	f.svc.AssertNotCalled(t, "ExportCertificate", mock.Anything, mock.Anything, mock.Anything, mock.Anything)
	assertNoFile(t, out)
	ev := f.audit.only(t)
	assert.Equal(t, "failure", ev.Outcome)
	assert.Contains(t, ev.Details, `"reason":"pkcs12 password unavailable"`)
}

func TestCertExport_NoPassphraseWritesNothing(t *testing.T) {
	f := newCertExportFixture(t)
	out := f.path("client.pem.sealed")

	_, _, err := f.run(f.id.String(), "--file", out)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no passphrase is available")
	f.svc.AssertNotCalled(t, "ExportCertificate", mock.Anything, mock.Anything, mock.Anything, mock.Anything)
	assertNoFile(t, out)
	assert.Contains(t, f.audit.only(t).Details, `"reason":"export passphrase unavailable"`)
}

func TestCertExport_RejectsBadInputBeforeAuthorization(t *testing.T) {
	cases := []struct {
		name string
		args func(f *certExportFixture) []string
		want string
	}{
		{"id is not a UUID", func(f *certExportFixture) []string { return []string{"not-a-uuid", "--file", f.path("o")} },
			"certificate ID must be a UUID"},
		{"unknown format", func(f *certExportFixture) []string {
			return []string{f.id.String(), "--file", f.path("o"), "--format", "der"}
		}, "--format must be pem or pkcs12"},
		{"unknown compat", func(f *certExportFixture) []string {
			return []string{f.id.String(), "--file", f.path("o"), "--format", "pkcs12", "--compat", "weak"}
		}, "--compat must be modern or legacy"},
		{"negative version", func(f *certExportFixture) []string {
			return []string{f.id.String(), "--file", f.path("o"), "--version=-1"}
		}, "--version must be 0 or a positive version number"},
		{"compat with pem", func(f *certExportFixture) []string {
			return []string{f.id.String(), "--file", f.path("o"), "--compat", "legacy"}
		}, "--compat, --pkcs12-password-file and --pkcs12-empty-password apply only to --format pkcs12"},
		{"empty password with pem", func(f *certExportFixture) []string {
			return []string{f.id.String(), "--file", f.path("o"), "--pkcs12-empty-password"}
		}, "--compat, --pkcs12-password-file and --pkcs12-empty-password apply only to --format pkcs12"},
		{"two password sources", func(f *certExportFixture) []string {
			return []string{f.id.String(), "--file", f.path("o"), "--format", "pkcs12",
				"--pkcs12-password-file", f.path("pw"), "--pkcs12-empty-password"}
		}, "pass --pkcs12-password-file or --pkcs12-empty-password, not both"},
		{"stdout", func(f *certExportFixture) []string { return []string{f.id.String(), "--file", "-"} },
			"--file - is not supported: an export is only ever written to a file"},
		{"plaintext with passphrase file", func(f *certExportFixture) []string {
			return []string{f.id.String(), "--file", f.path("o"), "--encrypt=false", "--passphrase-file", f.path("pw")}
		}, "--passphrase-file was given with --encrypt=false: drop one, since a plaintext export has no passphrase"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := newCertExportFixture(t)
			roles := &testutils.MockRoleAssignmentService{}
			f.tc.MockContainer.RoleAssignmentService = roles

			_, _, err := f.run(c.args(f)...)
			require.Error(t, err)
			assert.Equal(t, "failed to export certificate: "+c.want, err.Error())
			roles.AssertNotCalled(t, "HasDataAction", mock.Anything, mock.Anything, mock.Anything, mock.Anything)
			f.svc.AssertNotCalled(t, "ExportCertificate", mock.Anything, mock.Anything, mock.Anything, mock.Anything)
			assertNoFile(t, f.path("o"))
			ev := f.audit.only(t)
			assert.Equal(t, "failure", ev.Outcome)
			assert.Contains(t, ev.Details, `"code":"bad_request"`)
			assert.Contains(t, ev.Details, `"reason":"`+c.want+`"`)
		})
	}
}

func TestCertExport_NeverReplacesAFileWithoutForce(t *testing.T) {
	f := newCertExportFixture(t)
	out := f.path("client.pem")
	require.NoError(t, os.WriteFile(out, []byte("original"), 0o644))

	_, _, err := f.run(f.id.String(), "--file", out, "--encrypt=false")
	assert.EqualError(t, err, "failed to export certificate: the output file already exists: pass --force to replace it")
	f.svc.AssertNotCalled(t, "ExportCertificate", mock.Anything, mock.Anything, mock.Anything, mock.Anything)
	data, err := os.ReadFile(out)
	require.NoError(t, err)
	assert.Equal(t, "original", string(data))
	ev := f.audit.only(t)
	assert.Equal(t, "failure", ev.Outcome)
	assert.Contains(t, ev.Details, `"reason":"the output file already exists: pass --force to replace it"`)
	f.audit.events = nil

	f.svc.On("ExportCertificate", mock.Anything, f.scope(), f.id, mock.Anything).Return(pemExport(f.id), nil).Once()
	_, _, err = f.run(f.id.String(), "--file", out, "--encrypt=false", "--force")
	require.NoError(t, err)
	data, err = os.ReadFile(out)
	require.NoError(t, err)
	assert.Equal(t, exportTestLeaf+exportTestKey, string(data))
	assertMode0600(t, out)
	assert.Equal(t, "success", f.audit.only(t).Outcome)
}

func TestCertExport_DeniedWithoutTheExportAction(t *testing.T) {
	f := newCertExportFixture(t)
	roles := &testutils.MockRoleAssignmentService{}
	roles.On("HasDataAction", mock.Anything, f.tc.TestUserID, f.tc.TestVaultID, model.ActionCertificatesExportItem).
		Return(false, nil).Once()
	f.tc.MockContainer.RoleAssignmentService = roles
	out := f.path("client.pem.sealed")

	_, _, err := f.run(f.id.String(), "--file", out)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to export certificate")
	assert.Contains(t, err.Error(), "forbidden")
	assert.NotContains(t, err.Error(), "passphrase", "an unauthorized caller is never asked for a passphrase")
	roles.AssertExpectations(t)
	f.svc.AssertNotCalled(t, "ExportCertificate", mock.Anything, mock.Anything, mock.Anything, mock.Anything)
	assertNoFile(t, out)
	ev := f.audit.only(t)
	assert.Equal(t, "failure", ev.Outcome)
	assert.Contains(t, ev.Details, `"code":"forbidden"`)
	assert.Contains(t, ev.Details, `"reason":"vault authorization failed"`)
	assert.Contains(t, ev.Details, `"vault_id":"`+f.tc.TestVaultID.String()+`"`)
}

func TestCertExport_ExplicitDenyOverridesARoleGrant(t *testing.T) {
	f := newCertExportFixture(t)
	policies := &testutils.MockAccessPolicyService{}
	policies.On("CheckAccess", mock.Anything, f.tc.TestUserID, model.PolicyResourceCertificates, model.OpCreate, f.tc.TestVaultID).
		Return(authzServices.AccessDenied, nil).Once()
	f.tc.MockContainer.AccessPolicyService = policies
	out := f.path("client.pem.sealed")

	_, _, err := f.run(f.id.String(), "--file", out)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "explicit access policy")
	policies.AssertExpectations(t)
	f.svc.AssertNotCalled(t, "ExportCertificate", mock.Anything, mock.Anything, mock.Anything, mock.Anything)
	assertNoFile(t, out)
	assert.Contains(t, f.audit.only(t).Details, `"code":"forbidden"`)
}

func TestCertExport_ChecksTheExportActionAndCreatePolicy(t *testing.T) {
	f := newCertExportFixture(t)
	t.Setenv(common.ExportPassphraseEnvVar, exportTestPassphrase)
	roles := &testutils.MockRoleAssignmentService{}
	roles.On("HasDataAction", mock.Anything, f.tc.TestUserID, f.tc.TestVaultID, model.ActionCertificatesExportItem).
		Return(true, nil).Once()
	policies := &testutils.MockAccessPolicyService{}
	policies.On("CheckAccess", mock.Anything, f.tc.TestUserID, model.PolicyResourceCertificates, model.OpCreate, f.tc.TestVaultID).
		Return(authzServices.AccessAllowed, nil).Once()
	f.tc.MockContainer.RoleAssignmentService = roles
	f.tc.MockContainer.AccessPolicyService = policies
	f.svc.On("ExportCertificate", mock.Anything, f.scope(), f.id, mock.Anything).Return(pemExport(f.id), nil).Once()

	_, _, err := f.run(f.id.String(), "--file", f.path("client.pem.sealed"))
	require.NoError(t, err)
	roles.AssertExpectations(t)
	policies.AssertExpectations(t)
	f.svc.AssertExpectations(t)
}

func TestCertExport_RefusalShowsTheFixedReasonAndWritesNothing(t *testing.T) {
	f := newCertExportFixture(t)
	t.Setenv(common.ExportPassphraseEnvVar, exportTestPassphrase)
	f.svc.On("ExportCertificate", mock.Anything, f.scope(), f.id, mock.Anything).Return(nil, &model.ExportRefusedError{
		Sentinel: model.ErrCertificateNotExportable, Reason: "the certificate was not created with exportable: true",
		Name: "client", KeyAlgorithm: "RSA-2048",
	}).Once()
	out := f.path("client.pem.sealed")

	_, _, err := f.run(f.id.String(), "--file", out)
	assert.EqualError(t, err, "failed to export certificate: certificate is not exportable: the certificate was not created with exportable: true")
	assertNoFile(t, out)
	ev := f.audit.only(t)
	assert.Equal(t, "failure", ev.Outcome)
	assert.Contains(t, ev.Details, `"code":"certificate_not_exportable"`)
	assert.Contains(t, ev.Details, `"reason":"the certificate was not created with exportable: true"`)
	assert.Contains(t, ev.Details, `"name":"client"`)
}

func TestCertExport_ServiceErrorsShowOnlyFixedMessages(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want string
	}{
		{"not found", fmt.Errorf("%w: sql: raw-detail", certServices.ErrCertNotFound),
			"failed to export certificate: certificate or version not found"},
		{"disabled", certServices.ErrCertLifecycleDenied,
			"failed to export certificate: the certificate or this version is disabled or outside its valid time window"},
		{"invalid request", fmt.Errorf("%w: version must be 0 or a positive version number", model.ErrInvalidExportRequest),
			"failed to export certificate: invalid export request: version must be 0 or a positive version number"},
		{"internal", errors.New("decrypt certificate key: raw-detail"),
			"failed to export certificate: internal error; see the RocketVault log for details"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := newCertExportFixture(t)
			t.Setenv(common.ExportPassphraseEnvVar, exportTestPassphrase)
			f.svc.On("ExportCertificate", mock.Anything, f.scope(), f.id, mock.Anything).Return(nil, c.err).Once()
			out := f.path("client.pem.sealed")

			_, _, err := f.run(f.id.String(), "--file", out)
			assert.EqualError(t, err, c.want)
			assertNoFile(t, out)
			assert.NotContains(t, f.audit.only(t).Details, "raw-detail")
		})
	}
}

func TestCertExport_NoMaterialOrSecretInAnyOutput(t *testing.T) {
	for _, encrypt := range []string{"--encrypt=true", "--encrypt=false"} {
		t.Run(encrypt, func(t *testing.T) {
			f := newCertExportFixture(t)
			t.Setenv(common.ExportPassphraseEnvVar, exportTestPassphrase)
			f.svc.On("ExportCertificate", mock.Anything, f.scope(), f.id, mock.Anything).Return(pemExport(f.id), nil).Once()

			stdout, stderr, err := f.run(f.id.String(), "--file", f.path("out"), encrypt)
			require.NoError(t, err)
			all := f.everything(stdout, stderr)
			for _, secret := range []string{"TEST-KEY-MATERIAL", "TEST-LEAF-BODY", exportTestPassphrase} {
				assert.NotContains(t, all, secret)
			}
		})
	}
}

func TestInitCertificatesExport_RegistersTheCommandAndFlags(t *testing.T) {
	parent := &cobra.Command{Use: "certificates"}
	InitCertificatesExport(parent)
	cmd, _, err := parent.Find([]string{"export"})
	require.NoError(t, err)
	assert.Equal(t, "export <id>", cmd.Use)
	for name, def := range map[string]string{
		"file": "", "encrypt": "true", "passphrase-file": "", "force": "false", "format": "pem",
		"compat": "modern", "version": "0", "pkcs12-password-file": "", "pkcs12-empty-password": "false",
	} {
		fl := cmd.Flags().Lookup(name)
		require.NotNil(t, fl, name)
		assert.Equal(t, def, fl.DefValue, name)
	}
	assert.Equal(t, "o", cmd.Flags().Lookup("file").Shorthand)
	assert.Equal(t, []string{"true"}, cmd.Flags().Lookup("file").Annotations[cobra.BashCompOneRequiredFlag])
	assert.Nil(t, cmd.Flags().Lookup("pkcs12-password"), "a password is never a command-line value")
}

func TestCertExport_DeniedCallerNeverReachesAPasswordSource(t *testing.T) {
	f := newCertExportFixture(t)
	roles := &testutils.MockRoleAssignmentService{}
	roles.On("HasDataAction", mock.Anything, f.tc.TestUserID, f.tc.TestVaultID, model.ActionCertificatesExportItem).
		Return(false, nil).Once()
	f.tc.MockContainer.RoleAssignmentService = roles
	out := f.path("client.p12.sealed")

	// Both sources name missing files, so reading either one before
	// authorization would change the error.
	_, _, err := f.run(f.id.String(), "--file", out, "--format", "pkcs12",
		"--passphrase-file", f.path("missing-export-pass"), "--pkcs12-password-file", f.path("missing-p12-pass"))
	require.Error(t, err)
	assert.True(t, strings.HasPrefix(err.Error(), "failed to export certificate: "), err.Error())
	assert.Contains(t, err.Error(), "forbidden")
	assert.NotContains(t, err.Error(), "missing-export-pass")
	assert.NotContains(t, err.Error(), "missing-p12-pass")
	f.svc.AssertNotCalled(t, "ExportCertificate", mock.Anything, mock.Anything, mock.Anything, mock.Anything)
	assertNoFile(t, out)
	assert.Contains(t, f.audit.only(t).Details, `"code":"forbidden"`)
}

func TestCertExport_MissingClaimsRecordsNoAttempt(t *testing.T) {
	f := newCertExportFixture(t)
	cmd := newExportCmd()
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	cmd.SetArgs([]string{f.id.String(), "--file", f.path("o")})
	cmd.SetContext(context.WithValue(context.Background(), common.ServiceContainerKey,
		&certsTestContainer{MockServiceContainer: f.tc.MockContainer, certSvc: f.svc}))

	err := cmd.Execute()
	assert.EqualError(t, err, "unauthorized: missing authentication claims")
	f.svc.AssertNotCalled(t, "ExportCertificate", mock.Anything, mock.Anything, mock.Anything, mock.Anything)
	assert.Empty(t, f.audit.events, "no caller means no attempt to audit")
}

func TestCertExport_DanglingSymlinkCountsAsAnExistingFile(t *testing.T) {
	f := newCertExportFixture(t)
	out := f.path("client.pem")
	require.NoError(t, os.Symlink(f.path("nowhere"), out))

	_, _, err := f.run(f.id.String(), "--file", out, "--encrypt=false")
	assert.EqualError(t, err, "failed to export certificate: the output file already exists: pass --force to replace it")
	f.svc.AssertNotCalled(t, "ExportCertificate", mock.Anything, mock.Anything, mock.Anything, mock.Anything)
	_, err = os.Stat(f.path("nowhere"))
	assert.ErrorIs(t, err, fs.ErrNotExist, "the symlink target must never be written")
	assert.Contains(t, f.audit.only(t).Details, `"code":"bad_request"`)
}

func TestCertExport_PassphraseFileProblemsWriteNothing(t *testing.T) {
	cases := []struct {
		name  string
		setup func(t *testing.T, f *certExportFixture) string
		want  string
	}{
		{"missing", func(_ *testing.T, f *certExportFixture) string { return f.path("absent") },
			"failed to read passphrase file"},
		{"empty", func(t *testing.T, f *certExportFixture) string {
			p := f.path("blank")
			require.NoError(t, os.WriteFile(p, []byte("\n"), 0o600))
			return p
		}, "is empty"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := newCertExportFixture(t)
			// The file comes first, so the environment must not rescue it.
			t.Setenv(common.ExportPassphraseEnvVar, exportTestPassphrase)
			out := f.path("client.pem.sealed")

			_, _, err := f.run(f.id.String(), "--file", out, "--passphrase-file", c.setup(t, f))
			require.Error(t, err)
			assert.Contains(t, err.Error(), c.want)
			f.svc.AssertNotCalled(t, "ExportCertificate", mock.Anything, mock.Anything, mock.Anything, mock.Anything)
			assertNoFile(t, out)
			ev := f.audit.only(t)
			assert.Equal(t, "failure", ev.Outcome)
			assert.Contains(t, ev.Details, `"reason":"export passphrase unavailable"`)
		})
	}
}

func TestCertExport_PKCS12PasswordFileProblemsUsePKCS12Wording(t *testing.T) {
	cases := []struct {
		name  string
		setup func(t *testing.T, f *certExportFixture) string
		want  string
	}{
		{"missing", func(_ *testing.T, f *certExportFixture) string { return f.path("absent") },
			"failed to read the PKCS12 password file: open "},
		{"empty", func(t *testing.T, f *certExportFixture) string {
			p := f.path("blank")
			require.NoError(t, os.WriteFile(p, []byte("  \n"), 0o600))
			return p
		}, "is empty: pass --pkcs12-empty-password for an empty password"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := newCertExportFixture(t)
			// The file comes before the environment, so this must not rescue it.
			t.Setenv(pkcs12PasswordEnvVar, exportTestP12)
			out := f.path("client.p12")

			_, _, err := f.run(f.id.String(), "--file", out, "--encrypt=false", "--format", "pkcs12",
				"--pkcs12-password-file", c.setup(t, f))
			require.Error(t, err)
			assert.True(t, strings.HasPrefix(err.Error(), "failed to export certificate: "), err.Error())
			assert.Contains(t, err.Error(), c.want)
			assert.NotContains(t, err.Error(), "passphrase file")
			f.svc.AssertNotCalled(t, "ExportCertificate", mock.Anything, mock.Anything, mock.Anything, mock.Anything)
			assertNoFile(t, out)
			assert.Contains(t, f.audit.only(t).Details, `"reason":"pkcs12 password unavailable"`)
		})
	}
}

func TestCertExport_PKCS12PasswordPrecedence(t *testing.T) {
	cases := []struct {
		name  string
		extra func(t *testing.T, f *certExportFixture) []string
		want  string
	}{
		{"file before environment", func(t *testing.T, f *certExportFixture) []string {
			pw := f.path("p12-pass")
			require.NoError(t, os.WriteFile(pw, []byte("from-file\n"), 0o600))
			return []string{"--pkcs12-password-file", pw}
		}, "from-file"},
		{"empty flag before environment", func(_ *testing.T, _ *certExportFixture) []string {
			return []string{"--pkcs12-empty-password"}
		}, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := newCertExportFixture(t)
			t.Setenv(pkcs12PasswordEnvVar, "from-environment")
			want := c.want
			f.svc.On("ExportCertificate", mock.Anything, f.scope(), f.id, mock.MatchedBy(func(r certServices.ExportCertificateRequest) bool {
				return r.Password != nil && *r.Password == want
			})).Return(&certServices.ExportCertificateResult{
				ID: f.id, Name: "client", Version: 1, Format: model.ExportFormatPKCS12, PKCS12: []byte("P12-BYTES"),
			}, nil).Once()

			args := append([]string{f.id.String(), "--format", "pkcs12", "--file", f.path("client.p12"), "--encrypt=false"}, c.extra(t, f)...)
			_, _, err := f.run(args...)
			require.NoError(t, err)
			f.svc.AssertExpectations(t)
			assert.Equal(t, "success", f.audit.only(t).Outcome)
		})
	}
}

func TestPKCS12PasswordError_NeverSaysPassphrase(t *testing.T) {
	readErr := errors.New("input/output error")
	cases := []struct {
		name string
		err  error
		file string
		want string
	}{
		{"no source", common.ErrNoPassphraseAvailable, "",
			"pkcs12 needs a password: pass --pkcs12-password-file, set ROCKETVAULT_PKCS12_PASSWORD, or pass --pkcs12-empty-password"},
		{"prompt mismatch", errors.New("passphrases do not match"), "", "the PKCS12 passwords do not match"},
		{"prompt empty", errors.New("passphrase must not be empty"), "",
			"the PKCS12 password must not be empty: pass --pkcs12-empty-password for an empty password"},
		{"prompt read", fmt.Errorf("failed to read passphrase: %w", readErr), "",
			"failed to read the PKCS12 password: input/output error"},
		{"prompt confirmation read", fmt.Errorf("failed to read passphrase confirmation: %w", readErr), "",
			"failed to read the PKCS12 password: input/output error"},
		{"unknown prompt text", errors.New("some new passphrase text"), "", "failed to read the PKCS12 password"},
		{"file read", fmt.Errorf("failed to read passphrase file: %w", readErr), "/p",
			"failed to read the PKCS12 password file: input/output error"},
		{"file empty", errors.New("passphrase file /p is empty"), "/p",
			"the PKCS12 password file /p is empty: pass --pkcs12-empty-password for an empty password"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := pkcs12PasswordError(c.err, c.file)
			assert.EqualError(t, got, c.want)
			assert.NotContains(t, got.Error(), "passphrase")
		})
	}
}

func TestCertExport_WriteFailureIsAuditedOnceAsAFailure(t *testing.T) {
	f := newCertExportFixture(t)
	t.Setenv(common.ExportPassphraseEnvVar, exportTestPassphrase)
	// A regular file where a parent directory should be makes the write fail
	// after the service has released the material.
	require.NoError(t, os.WriteFile(f.path("blocker"), []byte("x"), 0o600))
	out := filepath.Join(f.path("blocker"), "client.pem.sealed")
	f.svc.On("ExportCertificate", mock.Anything, f.scope(), f.id, mock.Anything).Return(pemExport(f.id), nil).Once()

	stdout, stderr, err := f.run(f.id.String(), "--file", out)
	require.Error(t, err)
	assert.True(t, strings.HasPrefix(err.Error(), "failed to export certificate: "), err.Error())
	f.svc.AssertExpectations(t)
	assert.NotContains(t, stdout, "exported successfully")
	ev := f.audit.only(t)
	assert.Equal(t, "failure", ev.Outcome)
	assert.Contains(t, ev.Details, `"code":"output_failed"`)
	assert.Contains(t, ev.Details, `"reason":"the output file could not be written"`)
	all := f.everything(stdout, stderr) + err.Error()
	for _, secret := range []string{"TEST-KEY-MATERIAL", "TEST-LEAF-BODY", exportTestPassphrase} {
		assert.NotContains(t, all, secret)
	}
}

func TestCertExport_NoSecretInAnyOutputForPKCS12OrAFailure(t *testing.T) {
	cases := []struct {
		name    string
		result  *certServices.ExportCertificateResult
		err     error
		encrypt string
	}{
		{"sealed pkcs12", &certServices.ExportCertificateResult{Name: "client", Version: 1, Format: model.ExportFormatPKCS12,
			PKCS12: []byte("P12-BYTES-MATERIAL")}, nil, "--encrypt=true"},
		{"plaintext pkcs12", &certServices.ExportCertificateResult{Name: "client", Version: 1, Format: model.ExportFormatPKCS12,
			PKCS12: []byte("P12-BYTES-MATERIAL")}, nil, "--encrypt=false"},
		{"service failure", nil, errors.New("encode pkcs12: raw-detail"), "--encrypt=true"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := newCertExportFixture(t)
			t.Setenv(common.ExportPassphraseEnvVar, exportTestPassphrase)
			pw := f.path("p12-pass")
			require.NoError(t, os.WriteFile(pw, []byte(exportTestP12+"\n"), 0o600))
			if c.result != nil {
				c.result.ID = f.id
			}
			f.svc.On("ExportCertificate", mock.Anything, f.scope(), f.id, mock.Anything).Return(c.result, c.err).Once()

			stdout, stderr, err := f.run(f.id.String(), "--file", f.path("out"), "--format", "pkcs12",
				"--pkcs12-password-file", pw, c.encrypt)
			all := f.everything(stdout, stderr)
			if err != nil {
				all += err.Error()
			}
			assert.Equal(t, c.err != nil, err != nil)
			for _, secret := range []string{"P12-BYTES-MATERIAL", exportTestPassphrase, exportTestP12} {
				assert.NotContains(t, all, secret)
			}
			f.audit.only(t)
		})
	}
}
