package vaultcli

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"rocketvault/cmd/testutils"
	"rocketvault/common"
	"rocketvault/internal/logging"
	auditServices "rocketvault/internal/services/audit"
	"rocketvault/internal/services/exportaudit"
	"rocketvault/model"
)

// exportAuditRecorder captures structured audit events.
type exportAuditRecorder struct {
	mu     sync.Mutex
	events []auditServices.AuditEvent
}

func (r *exportAuditRecorder) RecordEvent(_ context.Context, e auditServices.AuditEvent) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.events = append(r.events, e)
	return nil
}

func (r *exportAuditRecorder) PersistAudit(string, string, string) error { return nil }

// exportSession builds an unauthorized Session whose context carries a
// container that hands out rec, and a logger that writes to logs.
func exportSession(t *testing.T, rec *exportAuditRecorder, logs *bytes.Buffer) (*Session, *testutils.TestContext) {
	t.Helper()
	tc := testutils.NewTestContext(t)
	tc.MockContainer.On("GetAuditService").Return(rec)
	l := logrus.New()
	l.SetOutput(logs)
	return &Session{Ctx: tc.Ctx, Claims: &model.Claims{UserID: tc.TestUserID}, Log: &logging.Logger{Logger: l}}, tc
}

func TestExportAttempt_RecordsExactlyOneEvent(t *testing.T) {
	rec := &exportAuditRecorder{}
	s, _ := exportSession(t, rec, &bytes.Buffer{})
	id := uuid.New()

	e := BeginExportAttempt(s, "certificate", id.String(), "pem", 3)
	err := e.Fail(exportaudit.BadRequest("--format must be pem or pkcs12"))
	assert.EqualError(t, err, "failed to export certificate: --format must be pem or pkcs12")
	e.Succeed("client", 3) // A second outcome is never recorded.

	require.Len(t, rec.events, 1)
	ev := rec.events[0]
	assert.Equal(t, "export_certificate", ev.Action)
	assert.Equal(t, "cli", ev.Source)
	assert.Equal(t, "failure", ev.Outcome)
	assert.Equal(t, id.String(), ev.ResourceID)
	assert.Equal(t, s.Claims.UserID.String(), ev.UserID)
	assert.Contains(t, ev.Details, `"reason":"--format must be pem or pkcs12"`)
	assert.Contains(t, ev.Details, `"code":"bad_request"`)
	assert.Contains(t, ev.Details, `"vault_id":""`)
	assert.Contains(t, ev.Details, `"version":3`)
}

func TestExportAttempt_SuccessCarriesVaultNameAndVersion(t *testing.T) {
	rec := &exportAuditRecorder{}
	s, tc := exportSession(t, rec, &bytes.Buffer{})
	s.VaultID = tc.TestVaultID

	BeginExportAttempt(s, "key", uuid.NewString(), "pem", 0).Succeed("signer", 4)

	require.Len(t, rec.events, 1)
	ev := rec.events[0]
	assert.Equal(t, "success", ev.Outcome)
	assert.Equal(t, "export_key", ev.Action)
	assert.Contains(t, ev.Details, `"vault_id":"`+tc.TestVaultID.String()+`"`)
	assert.Contains(t, ev.Details, `"name":"signer"`)
	assert.Contains(t, ev.Details, `"version":4`)
	assert.Contains(t, ev.Details, `"code":""`)
}

func TestExportAttempt_ArbitraryTextNeverReachesTheAuditTrail(t *testing.T) {
	rec := &exportAuditRecorder{}
	s, _ := exportSession(t, rec, &bytes.Buffer{})

	_ = BeginExportAttempt(s, "certificate", "not-a-uuid hunter2", "der hunter2", 0).
		Fail(exportaudit.BadRequest("certificate ID must be a UUID"))

	require.Len(t, rec.events, 1)
	assert.Empty(t, rec.events[0].ResourceID)
	assert.Contains(t, rec.events[0].Details, `"format":"invalid"`)
	assert.NotContains(t, rec.events[0].Details+rec.events[0].ResourceID, "hunter2")
}

func TestExportAttempt_FailServiceShowsOnlyFixedText(t *testing.T) {
	rec := &exportAuditRecorder{}
	logs := &bytes.Buffer{}
	s, _ := exportSession(t, rec, logs)

	err := BeginExportAttempt(s, "key", uuid.NewString(), "pem", 0).FailService(errors.New("decrypt key material: raw-detail"))
	assert.EqualError(t, err, "failed to export key: internal error; see the RocketVault log for details")
	assert.Contains(t, logs.String(), "raw-detail", "the cause goes to the log file only")
	require.Len(t, rec.events, 1)
	assert.Contains(t, rec.events[0].Details, `"reason":"internal failure"`)
	assert.NotContains(t, rec.events[0].Details, "raw-detail")
}

func TestExportAttempt_FailServiceShowsTheRefusalReason(t *testing.T) {
	rec := &exportAuditRecorder{}
	s, _ := exportSession(t, rec, &bytes.Buffer{})

	err := BeginExportAttempt(s, "key", uuid.NewString(), "pem", 0).FailService(&model.ExportRefusedError{
		Sentinel: model.ErrKeyNotExportable, Reason: "symmetric oct keys are not exportable", Name: "wrap",
	})
	assert.EqualError(t, err, "failed to export key: key is not exportable: symmetric oct keys are not exportable")
	require.Len(t, rec.events, 1)
	assert.Contains(t, rec.events[0].Details, `"name":"wrap"`)
	assert.Contains(t, rec.events[0].Details, `"code":"key_not_exportable"`)
}

func TestExportAttempt_DeniedReturnsTheAuthorizationErrorAndRecordsTheVault(t *testing.T) {
	rec := &exportAuditRecorder{}
	s, tc := exportSession(t, rec, &bytes.Buffer{})
	authzErr := errors.New("failed to export key: forbidden: no role grants it in this vault")

	err := BeginExportAttempt(s, "key", uuid.NewString(), "pem", 0).Denied(authzErr)
	assert.Equal(t, authzErr, err)
	require.Len(t, rec.events, 1)
	assert.Contains(t, rec.events[0].Details, `"code":"forbidden"`)
	assert.Contains(t, rec.events[0].Details, `"reason":"vault authorization failed"`)
	assert.Contains(t, rec.events[0].Details, `"vault_id":"`+tc.TestVaultID.String()+`"`)
}

func TestExportAttempt_FailOutput(t *testing.T) {
	t.Run("target appeared", func(t *testing.T) {
		rec := &exportAuditRecorder{}
		s, _ := exportSession(t, rec, &bytes.Buffer{})
		err := BeginExportAttempt(s, "key", uuid.NewString(), "pem", 0).FailOutput(common.ErrOutputExists)
		assert.EqualError(t, err, "failed to export key: the output file already exists: pass --force to replace it")
		require.Len(t, rec.events, 1)
		assert.Contains(t, rec.events[0].Details, `"code":"bad_request"`)
	})
	t.Run("no hard links", func(t *testing.T) {
		rec := &exportAuditRecorder{}
		s, _ := exportSession(t, rec, &bytes.Buffer{})
		err := BeginExportAttempt(s, "certificate", uuid.NewString(), "pem", 0).
			FailOutput(fmt.Errorf("wrapped: %w", common.ErrHardLinksUnsupported))
		assert.EqualError(t, err, "failed to export certificate: "+common.ErrHardLinksUnsupported.Error())
		require.Len(t, rec.events, 1)
		assert.Contains(t, rec.events[0].Details, `"code":"output_failed"`)
		assert.Contains(t, rec.events[0].Details, `"reason":"the output filesystem does not support hard links"`)
	})
	t.Run("write failed", func(t *testing.T) {
		rec := &exportAuditRecorder{}
		s, _ := exportSession(t, rec, &bytes.Buffer{})
		err := BeginExportAttempt(s, "key", uuid.NewString(), "pem", 0).FailOutput(errors.New("failed to write the export file: disk full"))
		assert.EqualError(t, err, "failed to export key: failed to write the export file: disk full")
		require.Len(t, rec.events, 1)
		assert.Contains(t, rec.events[0].Details, `"code":"output_failed"`)
		assert.Contains(t, rec.events[0].Details, `"reason":"the output file could not be written"`)
	})
}

func TestExportOutput_Check(t *testing.T) {
	dir := t.TempDir()
	existing := filepath.Join(dir, "exists.pem")
	require.NoError(t, os.WriteFile(existing, []byte("x"), 0o600))
	fresh := filepath.Join(dir, "new.pem")

	cases := []struct {
		name string
		o    ExportOutput
		want string
	}{
		{"usable", ExportOutput{File: fresh, Encrypt: true}, ""},
		{"no file", ExportOutput{Encrypt: true}, "--file is required"},
		{"stdout", ExportOutput{File: "-", Encrypt: true}, "--file - is not supported: an export is only ever written to a file"},
		{"plaintext with passphrase file", ExportOutput{File: fresh, PassphraseFile: "p"},
			"--passphrase-file was given with --encrypt=false: drop one, since a plaintext export has no passphrase"},
		{"existing without force", ExportOutput{File: existing, Encrypt: true}, "the output file already exists: pass --force to replace it"},
		{"existing with force", ExportOutput{File: existing, Encrypt: true, Force: true}, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := c.o.Check()
			if c.want == "" {
				assert.Nil(t, f)
				return
			}
			require.NotNil(t, f)
			assert.Equal(t, c.want, f.Message)
			assert.Equal(t, "bad_request", f.Code)
		})
	}
}

func TestExportOutput_Passphrase(t *testing.T) {
	t.Setenv(common.ExportPassphraseEnvVar, "")

	got, err := ExportOutput{Encrypt: false}.Passphrase()
	require.NoError(t, err)
	assert.Empty(t, got)

	// go test runs with stdin detached, so there is no terminal to prompt on.
	_, err = ExportOutput{Encrypt: true}.Passphrase()
	assert.ErrorContains(t, err, "no passphrase is available")

	t.Setenv(common.ExportPassphraseEnvVar, "from-env")
	got, err = ExportOutput{Encrypt: true}.Passphrase()
	require.NoError(t, err)
	assert.Equal(t, "from-env", got)

	file := filepath.Join(t.TempDir(), "pass")
	require.NoError(t, os.WriteFile(file, []byte("from-file\n"), 0o600))
	got, err = ExportOutput{Encrypt: true, PassphraseFile: file}.Passphrase()
	require.NoError(t, err)
	assert.Equal(t, "from-file", got, "the file comes before the environment")
}

func TestExportOutput_Write(t *testing.T) {
	payload := common.ItemExportPayload{
		Kind: common.ItemExportKindKey, ID: "id", Name: "signer", Version: 1, Format: "pem",
		Content: []byte("-----BEGIN PRIVATE KEY-----\nKEY-MATERIAL\n-----END PRIVATE KEY-----\n"),
	}

	t.Run("sealed", func(t *testing.T) {
		var stderr bytes.Buffer
		cmd := &cobra.Command{}
		cmd.SetErr(&stderr)
		o := ExportOutput{File: filepath.Join(t.TempDir(), "k.sealed"), Encrypt: true}

		require.NoError(t, o.Write(cmd, payload, "pass", "unused"))
		data, err := os.ReadFile(o.File)
		require.NoError(t, err)
		assert.NotContains(t, string(data), "KEY-MATERIAL")
		got, err := common.OpenItemExport(data, "pass")
		require.NoError(t, err)
		assert.Equal(t, payload.Content, got.Content)
		assert.Empty(t, stderr.String())
		info, err := os.Stat(o.File)
		require.NoError(t, err)
		assert.Equal(t, os.FileMode(0o600), info.Mode().Perm())
	})

	t.Run("plaintext", func(t *testing.T) {
		var stderr bytes.Buffer
		cmd := &cobra.Command{}
		cmd.SetErr(&stderr)
		o := ExportOutput{File: filepath.Join(t.TempDir(), "k.pem")}

		require.NoError(t, o.Write(cmd, payload, "", "will hold the key's private key unencrypted, in the clear."))
		data, err := os.ReadFile(o.File)
		require.NoError(t, err)
		assert.Equal(t, payload.Content, data)
		assert.Equal(t, "Warning: --encrypt=false — "+o.File+" will hold the key's private key unencrypted, in the clear.\n", stderr.String())
	})

	t.Run("existing target without force", func(t *testing.T) {
		cmd := &cobra.Command{}
		cmd.SetErr(&bytes.Buffer{})
		o := ExportOutput{File: filepath.Join(t.TempDir(), "k.pem")}
		require.NoError(t, os.WriteFile(o.File, []byte("original"), 0o600))
		assert.ErrorIs(t, o.Write(cmd, payload, "", "x"), common.ErrOutputExists)
	})
}

func TestExportOutput_PrintStatus(t *testing.T) {
	var stdout bytes.Buffer
	cmd := &cobra.Command{}
	cmd.SetOut(&stdout)
	ExportOutput{File: "k.sealed", Encrypt: true}.PrintStatus(cmd, "Key", "signer", 2, "pem")
	assert.Equal(t, "Key exported successfully\nName: signer\nVersion: 2\nFormat: pem\n"+
		"Encryption: passphrase (argon2id + AES-256-GCM)\nFile: k.sealed\n", stdout.String())
}

func TestAddExportOutputFlags(t *testing.T) {
	cmd := &cobra.Command{Use: "export"}
	AddExportOutputFlags(cmd)
	file := cmd.Flags().Lookup("file")
	require.NotNil(t, file)
	assert.Equal(t, "o", file.Shorthand)
	assert.Equal(t, []string{"true"}, file.Annotations[cobra.BashCompOneRequiredFlag])
	encrypt := cmd.Flags().Lookup("encrypt")
	require.NotNil(t, encrypt)
	assert.Equal(t, "e", encrypt.Shorthand)
	assert.Equal(t, "true", encrypt.DefValue)
	require.NotNil(t, cmd.Flags().Lookup("passphrase-file"))
	assert.Equal(t, "false", cmd.Flags().Lookup("force").DefValue)

	require.NoError(t, cmd.ParseFlags([]string{"-o", "x.pem", "--encrypt=false", "--force"}))
	assert.Equal(t, ExportOutput{File: "x.pem", Encrypt: false, Force: true}, ReadExportOutput(cmd))
}
