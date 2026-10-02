package cmd

import (
	"bytes"
	"context"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"rocketvault/common"
	"rocketvault/model"
)

const openTestContent = "-----BEGIN CERTIFICATE-----\nLEAF\n-----END CERTIFICATE-----\n" +
	"-----BEGIN PRIVATE KEY-----\nKEY-MATERIAL\n-----END PRIVATE KEY-----\n"

// sealedFixture writes a sealed export of p and a passphrase file into dir.
func sealedFixture(t *testing.T, dir string, p common.ItemExportPayload, passphrase string) (sealedPath, passFile string) {
	t.Helper()
	sealed, err := common.SealItemExport(p, passphrase)
	require.NoError(t, err)
	sealedPath = filepath.Join(dir, "export.sealed")
	require.NoError(t, os.WriteFile(sealedPath, sealed, 0o600))
	passFile = filepath.Join(dir, "pass")
	require.NoError(t, os.WriteFile(passFile, []byte(passphrase+"\n"), 0o600))
	return sealedPath, passFile
}

// rawSealedFixture seals arbitrary plaintext under passphrase and writes it
// with a passphrase file into dir.
func rawSealedFixture(t *testing.T, dir string, plaintext, passphrase string) (sealedPath, passFile string) {
	t.Helper()
	sealed, err := common.SealExport([]byte(plaintext), passphrase)
	require.NoError(t, err)
	sealedPath = filepath.Join(dir, "raw.sealed")
	require.NoError(t, os.WriteFile(sealedPath, sealed, 0o600))
	passFile = filepath.Join(dir, "pass")
	require.NoError(t, os.WriteFile(passFile, []byte(passphrase+"\n"), 0o600))
	return sealedPath, passFile
}

func certPayload() common.ItemExportPayload {
	return common.ItemExportPayload{
		Kind: common.ItemExportKindCertificate, ID: uuid.NewString(), Name: "client", Version: 2,
		Format: "pem", KeyAlgorithm: "RSA-2048", Content: []byte(openTestContent),
	}
}

// runOpen runs a fresh "export open" with args. It parses the flags and
// calls RunE directly: Execute would run root.go's process-wide
// cobra.OnInitialize hook, which loads a config file (see rotation_test.go).
// The end-to-end tests below go through rootCmd instead.
func runOpen(args ...string) (stdout, stderr string, err error) {
	cmd := newExportOpenCmd()
	var out, errOut bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&errOut)
	cmd.SetContext(context.Background())
	if err := cmd.ParseFlags(args); err != nil {
		return "", "", err
	}
	err = cmd.RunE(cmd, cmd.Flags().Args())
	return out.String(), errOut.String(), err
}

func TestExportOpen_WritesTheExactPlaintextFile(t *testing.T) {
	t.Setenv(common.ExportPassphraseEnvVar, "")
	dir := t.TempDir()
	sealed, pass := sealedFixture(t, dir, certPayload(), "open-pass")
	out := filepath.Join(dir, "client.pem")

	stdout, stderr, err := runOpen(sealed, "--file", out, "--passphrase-file", pass)
	require.NoError(t, err)
	data, err := os.ReadFile(out)
	require.NoError(t, err)
	assert.Equal(t, openTestContent, string(data))
	info, err := os.Stat(out)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o600), info.Mode().Perm())
	assert.Contains(t, stdout, "Kind: certificate")
	assert.Contains(t, stdout, "Name: client")
	assert.Contains(t, stdout, "Version: 2")
	assert.Contains(t, stdout, "Format: pem")
	assert.Contains(t, stdout, "File: "+out)
	assert.Equal(t, "Warning: "+out+" holds the certificate's private key unencrypted, in the clear. Delete it when you are done.\n", stderr)
	assert.NotContains(t, stdout+stderr, "KEY-MATERIAL")
	assert.NotContains(t, stdout+stderr, "open-pass")
}

func TestExportOpen_PKCS12WarningNamesThePKCS12Password(t *testing.T) {
	t.Setenv(common.ExportPassphraseEnvVar, "")
	dir := t.TempDir()
	p := certPayload()
	p.Format = model.ExportFormatPKCS12
	p.Content = []byte{0x30, 0x82, 0x01, 0x02, 0x03}
	sealed, pass := sealedFixture(t, dir, p, "p12-pass")
	out := filepath.Join(dir, "client.p12")

	_, stderr, err := runOpen(sealed, "--file", out, "--passphrase-file", pass)
	require.NoError(t, err)
	data, err := os.ReadFile(out)
	require.NoError(t, err)
	assert.Equal(t, p.Content, data)
	assert.Equal(t, "Warning: "+out+" holds the certificate's private key protected only by its PKCS12 password. Delete it when you are done.\n", stderr)
}

func TestExportOpen_OpensAKeyExport(t *testing.T) {
	t.Setenv(common.ExportPassphraseEnvVar, "")
	dir := t.TempDir()
	p := common.ItemExportPayload{
		Kind: common.ItemExportKindKey, ID: uuid.NewString(), Name: "signer", Version: 1,
		Format: "pem", KeyAlgorithm: "EC-P256", Content: []byte("-----BEGIN PRIVATE KEY-----\nK\n-----END PRIVATE KEY-----\n"),
	}
	sealed, pass := sealedFixture(t, dir, p, "key-pass")
	out := filepath.Join(dir, "signer.pem")

	stdout, stderr, err := runOpen(sealed, "--file", out, "--passphrase-file", pass)
	require.NoError(t, err)
	assert.Contains(t, stdout, "Kind: key")
	assert.Equal(t, "Warning: "+out+" holds the key's private key unencrypted, in the clear. Delete it when you are done.\n", stderr)
}

func TestExportOpen_ReadsThePassphraseFromTheEnvironment(t *testing.T) {
	dir := t.TempDir()
	sealed, _ := sealedFixture(t, dir, certPayload(), "env-pass")
	t.Setenv(common.ExportPassphraseEnvVar, "env-pass")

	_, _, err := runOpen(sealed, "--file", filepath.Join(dir, "client.pem"))
	require.NoError(t, err)
}

func TestExportOpen_PassphraseFileWinsOverTheEnvironment(t *testing.T) {
	dir := t.TempDir()
	sealed, pass := sealedFixture(t, dir, certPayload(), "file-pass")
	t.Setenv(common.ExportPassphraseEnvVar, "env-pass")

	_, _, err := runOpen(sealed, "--file", filepath.Join(dir, "client.pem"), "--passphrase-file", pass)
	require.NoError(t, err)
}

func TestExportOpen_RefusalsWriteNothing(t *testing.T) {
	cases := []struct {
		name  string
		setup func(t *testing.T, dir, out string) []string
		want  string
	}{
		{"wrong passphrase", func(t *testing.T, dir, out string) []string {
			sealed, _ := sealedFixture(t, dir, certPayload(), "right")
			wrong := filepath.Join(dir, "wrong")
			require.NoError(t, os.WriteFile(wrong, []byte("wrong\n"), 0o600))
			return []string{sealed, "--passphrase-file", wrong, "--file", out}
		}, "failed to open export: wrong passphrase or corrupted export file"},
		{"a sealed secrets export", func(t *testing.T, dir, out string) []string {
			path, pass := rawSealedFixture(t, dir, `[{"name":"db","value":"x"}]`, "p")
			return []string{path, "--passphrase-file", pass, "--file", out}
		}, "this file is not a certificate or key export; read a sealed secrets export with rocketvault secrets import"},
		{"an unknown item kind", func(t *testing.T, dir, out string) []string {
			path, pass := rawSealedFixture(t, dir, `{"rocketvault_item_export":1,"kind":"secret","content":"eA=="}`, "p")
			return []string{path, "--passphrase-file", pass, "--file", out}
		}, "this file is not a certificate or key export; read a sealed secrets export with rocketvault secrets import"},
		{"an unknown item payload version", func(t *testing.T, dir, out string) []string {
			path, pass := rawSealedFixture(t, dir, `{"rocketvault_item_export":2,"kind":"certificate","content":"eA=="}`, "p")
			return []string{path, "--passphrase-file", pass, "--file", out}
		}, "failed to open export: the export file was written by a newer or unknown RocketVault version"},
		{"an unknown envelope version", func(t *testing.T, dir, out string) []string {
			path := filepath.Join(dir, "future.sealed")
			require.NoError(t, os.WriteFile(path, []byte(`{"rocketvault_export":99}`), 0o600))
			pass := filepath.Join(dir, "pass")
			require.NoError(t, os.WriteFile(pass, []byte("p\n"), 0o600))
			return []string{path, "--passphrase-file", pass, "--file", out}
		}, "failed to open export: the export file was written by a newer or unknown RocketVault version"},
		{"a malformed envelope", func(t *testing.T, dir, out string) []string {
			path := filepath.Join(dir, "bad.sealed")
			require.NoError(t, os.WriteFile(path, []byte(`{"rocketvault_export":1,"kdf":"argon2id","salt":"!!not-base64!!"}`), 0o600))
			pass := filepath.Join(dir, "pass")
			require.NoError(t, os.WriteFile(pass, []byte("p\n"), 0o600))
			return []string{path, "--passphrase-file", pass, "--file", out}
		}, "failed to open export: the export file is malformed"},
		{"an item export with no content", func(t *testing.T, dir, out string) []string {
			p := certPayload()
			p.Content = nil
			sealed, pass := sealedFixture(t, dir, p, "p")
			return []string{sealed, "--passphrase-file", pass, "--file", out}
		}, "failed to open export: the export holds no content"},
		{"a plain PEM file", func(t *testing.T, dir, out string) []string {
			path := filepath.Join(dir, "plain.pem")
			require.NoError(t, os.WriteFile(path, []byte(openTestContent), 0o600))
			return []string{path, "--file", out}
		}, "not a sealed RocketVault export file"},
		{"a file larger than the cap", func(t *testing.T, dir, out string) []string {
			path := filepath.Join(dir, "big.sealed")
			require.NoError(t, os.WriteFile(path, bytes.Repeat([]byte("x"), maxSealedExportBytes+1), 0o600))
			return []string{path, "--file", out}
		}, "not a sealed RocketVault export file: it is larger than 1 MiB"},
		{"no passphrase available", func(t *testing.T, dir, out string) []string {
			sealed, _ := sealedFixture(t, dir, certPayload(), "p")
			return []string{sealed, "--file", out}
		}, "no passphrase is available: pass --passphrase-file or set ROCKETVAULT_EXPORT_PASSPHRASE"},
		{"stdout", func(t *testing.T, dir, _ string) []string {
			sealed, pass := sealedFixture(t, dir, certPayload(), "p")
			return []string{sealed, "--passphrase-file", pass, "--file", "-"}
		}, "--file must name an output file: an opened export is only ever written to a file"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Setenv(common.ExportPassphraseEnvVar, "")
			dir := t.TempDir()
			out := filepath.Join(dir, "out.pem")

			stdout, stderr, err := runOpen(c.setup(t, dir, out)...)
			assert.EqualError(t, err, c.want)
			assert.Empty(t, stdout)
			assert.Empty(t, stderr)
			_, statErr := os.Stat(out)
			assert.ErrorIs(t, statErr, fs.ErrNotExist)
			// Nothing else, such as a temporary file, was left behind.
			entries, err := os.ReadDir(dir)
			require.NoError(t, err)
			for _, e := range entries {
				assert.False(t, strings.HasPrefix(e.Name(), ".rocketvault-export-"), "temporary file left: %s", e.Name())
			}
		})
	}
}

func TestExportOpen_MissingFileNamesThePath(t *testing.T) {
	dir := t.TempDir()
	_, _, err := runOpen(filepath.Join(dir, "missing.sealed"), "--file", filepath.Join(dir, "out.pem"))
	require.Error(t, err)
	assert.True(t, strings.HasPrefix(err.Error(), "failed to read export file: "), err.Error())
}

func TestExportOpen_NeverReplacesAFileWithoutForce(t *testing.T) {
	t.Setenv(common.ExportPassphraseEnvVar, "")
	dir := t.TempDir()
	sealed, pass := sealedFixture(t, dir, certPayload(), "p")
	out := filepath.Join(dir, "client.pem")
	require.NoError(t, os.WriteFile(out, []byte("original"), 0o644))

	_, _, err := runOpen(sealed, "--file", out, "--passphrase-file", pass)
	assert.EqualError(t, err, "the output file already exists: pass --force to replace it")
	data, err := os.ReadFile(out)
	require.NoError(t, err)
	assert.Equal(t, "original", string(data))

	_, _, err = runOpen(sealed, "--file", out, "--passphrase-file", pass, "--force")
	require.NoError(t, err)
	data, err = os.ReadFile(out)
	require.NoError(t, err)
	assert.Equal(t, openTestContent, string(data))
	info, err := os.Stat(out)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o600), info.Mode().Perm())
}

func TestExportOpen_NeverFollowsASymlinkWithoutForce(t *testing.T) {
	t.Setenv(common.ExportPassphraseEnvVar, "")
	dir := t.TempDir()
	sealed, pass := sealedFixture(t, dir, certPayload(), "p")
	target := filepath.Join(dir, "target")
	out := filepath.Join(dir, "link.pem")
	require.NoError(t, os.Symlink(target, out))

	_, _, err := runOpen(sealed, "--file", out, "--passphrase-file", pass)
	assert.EqualError(t, err, "the output file already exists: pass --force to replace it")
	_, statErr := os.Stat(target)
	assert.ErrorIs(t, statErr, fs.ErrNotExist)
}

// resetChangedFlags restores every flag that a rootCmd run changed, on root
// and on every subcommand, so later tests see the defaults again.
func resetChangedFlags(c *cobra.Command) {
	reset := func(f *pflag.Flag) {
		if f.Changed {
			_ = f.Value.Set(f.DefValue)
			f.Changed = false
		}
	}
	c.Flags().VisitAll(reset)
	c.PersistentFlags().VisitAll(reset)
	for _, sub := range c.Commands() {
		resetChangedFlags(sub)
	}
}

// isolateRootRun runs rootCmd with args from an empty directory, with no
// config file, no cached session and no home directory state, and restores
// the global state after. It never touches the real ~/.rocketvault.
func isolateRootRun(t *testing.T, args ...string) error {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("HOME", filepath.Join(dir, "home"))
	t.Setenv("ROCKETVAULT_ADDR", "")
	t.Setenv("ROCKETVAULT_VAULT", "")

	previousBase := common.SessionBaseDir
	common.SessionBaseDir = filepath.Join(dir, "home", ".rocketvault", "sessions")
	t.Cleanup(func() { common.SessionBaseDir = previousBase })

	previousCfgFile := cfgFile
	cfgFile = ""
	t.Cleanup(func() { cfgFile = previousCfgFile })

	t.Chdir(dir)

	previousSettings := viper.AllSettings()
	viper.Reset()
	t.Cleanup(func() {
		viper.Reset()
		_ = viper.MergeConfigMap(previousSettings)
	})

	previousArgs := os.Args
	os.Args = append([]string{"rocketvault"}, args...)
	t.Cleanup(func() { os.Args = previousArgs })

	rootCmd.SetArgs(args)
	t.Cleanup(func() {
		rootCmd.SetArgs(nil)
		resetChangedFlags(rootCmd)
	})

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("rocketvault %s panicked: %v", strings.Join(args, " "), r)
		}
	}()
	return rootCmd.ExecuteContext(context.Background())
}

// TestExportOpen_NeedsNoConfigSessionDatabaseOrServer runs "export open"
// through the real root command from a directory with no config file and no
// cached session, once in local mode and once with a remote target set.
func TestExportOpen_NeedsNoConfigSessionDatabaseOrServer(t *testing.T) {
	for _, tc := range []struct {
		name  string
		extra []string
	}{
		{"local", nil},
		{"remote", []string{"--server", "https://vault.example.com"}},
		{"flags first", []string{"--vault", "payments", "--output", "json"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv(common.ExportPassphraseEnvVar, "")
			dir := t.TempDir()
			sealed, pass := sealedFixture(t, dir, certPayload(), "p")
			out := filepath.Join(dir, "client.pem")

			args := append(append([]string{}, tc.extra...), "export", "open", sealed, "--file", out, "--passphrase-file", pass)
			require.NoError(t, isolateRootRun(t, args...))
			data, err := os.ReadFile(out)
			require.NoError(t, err)
			assert.Equal(t, openTestContent, string(data))
			// No database file, log file or session was created anywhere.
			entries, err := os.ReadDir(".")
			require.NoError(t, err)
			for _, e := range entries {
				assert.Equal(t, "home", e.Name(), "unexpected file in the working directory")
			}
		})
	}
}

func TestIsExportGroupArgs(t *testing.T) {
	matches := [][]string{
		{"export"},
		{"export", "open"},
		{"export", "open", "f"},
		{"export", "open", "f", "--file", "o", "--force"},
		{"export", "--help"},
		{"--vault", "x", "export", "open", "f"},
		{"--server", "https://vault.example.com", "export", "open", "f"},
		{"--output=json", "export", "open", "f"},
	}
	for _, args := range matches {
		assert.True(t, isExportGroupArgs(args), "%q must match the export group", args)
	}

	others := [][]string{
		nil,
		{},
		{"secrets", "export"},
		{"secrets", "export", "--file", "out.json"},
		{"--vault", "x", "secrets", "export"},
		{"certificates", "export"},
		{"certificates", "export", "id"},
		{"certificates", "export", "id", "--file", "export"},
		{"--vault", "x", "certificates", "export", "id"},
		{"keys", "export"},
		{"keys", "export", "id"},
		{"--vault", "export", "keys", "export", "id"},
		{"help", "export"},
		{"secrets"},
		{"context", "list"},
		{"open"},
		{"not-a-command", "export"},
	}
	for _, args := range others {
		assert.False(t, isExportGroupArgs(args), "%q must not match the export group", args)
	}
}

// TestExportGroup_PreRunCoversOnlyTheGroup pins that the no-op pre-run is
// reached only from the export group, and that the item export commands
// still resolve to the root pre-run that authenticates and guards remote
// mode.
func TestExportGroup_PreRunCoversOnlyTheGroup(t *testing.T) {
	nearestPreRun := func(c *cobra.Command) *cobra.Command {
		for p := c; p != nil; p = p.Parent() {
			if p.PersistentPreRunE != nil || p.PersistentPreRun != nil {
				return p
			}
		}
		return nil
	}
	open, _, err := rootCmd.Find([]string{"export", "open"})
	require.NoError(t, err)
	assert.Same(t, exportGroupCmd, nearestPreRun(open))

	for _, path := range [][]string{{"secrets", "export"}, {"certificates", "export"}, {"keys", "export"}} {
		c, _, err := rootCmd.Find(path)
		require.NoError(t, err)
		require.Equal(t, "export", c.Name(), "%q", path)
		assert.NotSame(t, exportGroupCmd, nearestPreRun(c), "%q must not use the export group's pre-run", path)
		assert.Same(t, rootCmd, nearestPreRun(c), "%q must use the root pre-run", path)
	}
}

// TestItemExportCommands_RemoteModeIsRefused pins that both export commands
// stay behind the remote-target guard: neither group has a remote adapter.
func TestItemExportCommands_RemoteModeIsRefused(t *testing.T) {
	for _, group := range []string{"certificates", "keys"} {
		t.Run(group, func(t *testing.T) {
			out := filepath.Join(t.TempDir(), "out.pem")
			err := isolateRootRun(t, group, "export", uuid.NewString(), "--file", out,
				"--server", "https://vault.example.com")
			require.Error(t, err)
			assert.Contains(t, err.Error(), "remote mode")
			assert.Contains(t, err.Error(), "is not yet supported for \"rocketvault "+group+" export\"")
			_, statErr := os.Stat(out)
			assert.ErrorIs(t, statErr, fs.ErrNotExist)
		})
	}

	for _, group := range []string{"certificates", "keys"} {
		parent := &cobra.Command{Use: group}
		export := &cobra.Command{Use: "export"}
		parent.AddCommand(export)
		assert.False(t, isRemoteCapableCommand(export), "%s export has no remote adapter", group)
	}
}

func TestExportGroup_IsRegisteredWithOpen(t *testing.T) {
	cmd, _, err := rootCmd.Find([]string{"export", "open"})
	require.NoError(t, err)
	assert.Equal(t, "open <sealed-file>", cmd.Use)
	assert.Same(t, exportGroupCmd, cmd.Parent())
	assert.Contains(t, rootCmd.Long, "export\nopen")
}

func TestExportOpen_PayloadStringsCannotDriveTheTerminal(t *testing.T) {
	t.Setenv(common.ExportPassphraseEnvVar, "")
	dir := t.TempDir()
	p := certPayload()
	p.Name = "client\x1b[2K\rFile: /safe\x1b]0;PWNED\x07\u009b"
	p.Format = "pem\x1b[31m"
	sealed, pass := sealedFixture(t, dir, p, "p")
	out := filepath.Join(dir, "client.pem")

	stdout, stderr, err := runOpen(sealed, "--file", out, "--passphrase-file", pass)
	require.NoError(t, err)
	for _, b := range []string{"\x1b", "\x07", "\r", "\u009b"} {
		assert.NotContains(t, stdout+stderr, b)
	}
	assert.Contains(t, stdout, "Name: client[2KFile: /safe]0;PWNED\n")
	assert.Contains(t, stdout, "Format: pem[31m\n")
}

// TestExportOpen_ExistingOutputIsRefusedBeforeAnyPassphrase pins the early
// check: with no passphrase source at all, the refusal is the exists message,
// not the no-passphrase one.
func TestExportOpen_ExistingOutputIsRefusedBeforeAnyPassphrase(t *testing.T) {
	t.Setenv(common.ExportPassphraseEnvVar, "")
	dir := t.TempDir()
	sealed, _ := sealedFixture(t, dir, certPayload(), "p")
	out := filepath.Join(dir, "client.pem")
	require.NoError(t, os.WriteFile(out, []byte("original"), 0o600))

	_, _, err := runOpen(sealed, "--file", out)
	assert.EqualError(t, err, "the output file already exists: pass --force to replace it")
	data, err := os.ReadFile(out)
	require.NoError(t, err)
	assert.Equal(t, "original", string(data))
}

func TestExportOpen_UncheckableOutputPathIsRefused(t *testing.T) {
	t.Setenv(common.ExportPassphraseEnvVar, "")
	dir := t.TempDir()
	sealed, pass := sealedFixture(t, dir, certPayload(), "p")
	notADir := filepath.Join(dir, "plain-file")
	require.NoError(t, os.WriteFile(notADir, []byte("x"), 0o600))

	_, _, err := runOpen(sealed, "--file", filepath.Join(notADir, "out.pem"), "--passphrase-file", pass)
	assert.EqualError(t, err, "failed to write the output file: the output path could not be checked")
}
