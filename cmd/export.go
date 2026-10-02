/*
Copyright © 2025 Snehal Dangroshiya
*/

package cmd

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"unicode"

	"github.com/spf13/cobra"

	"rocketvault/common"
	"rocketvault/model"
)

// maxSealedExportBytes bounds a sealed export read from disk. Real
// certificate and key exports are a few KiB; anything larger is not one.
const maxSealedExportBytes = 1 << 20

// exportOutputExistsMessage is the fixed message for an output file that
// already exists when --force was not given. It matches the export commands.
const exportOutputExistsMessage = "the output file already exists: pass --force to replace it"

// Fixed messages for "export open" refusals. None of them carries file
// content, a passphrase or a raw decryption error.
const (
	exportNotSealedMessage         = "not a sealed RocketVault export file"
	exportNotItemMessage           = "this file is not a certificate or key export; read a sealed secrets export with rocketvault secrets import"
	exportWrongPassMessage         = "failed to open export: wrong passphrase or corrupted export file"
	exportVersionMessage           = "failed to open export: the export file was written by a newer or unknown RocketVault version"
	exportMalformedMessage         = "failed to open export: the export file is malformed"
	exportEmptyPassMessage         = "failed to open export: a passphrase is required"
	exportEmptyContentMessage      = "failed to open export: the export holds no content"
	exportStdoutRefusedMessage     = "--file must name an output file: an opened export is only ever written to a file"
	exportWriteFailedPrefix        = "failed to write the output file: "
	exportOutputUncheckableMessage = "failed to write the output file: the output path could not be checked"
)

// exportGroupCmd groups the commands that work on export files offline.
var exportGroupCmd = &cobra.Command{
	Use:   "export",
	Short: "Work with sealed certificate and key export files",
	Long: `Work with the sealed files that "certificates export" and "keys export"
write. These commands read only local files: they need no session, no
database, no config file and no server, so they work on a machine that has
nothing but the rocketvault binary.`,
	Example: `  # Open a sealed certificate export
  rocketvault export open client.pem.sealed --file client.pem`,
	// Replace the root PersistentPreRunE. Opening an export decrypts a local
	// file; it must not open a database, require a session or be refused by
	// the remote-target guard. cmd/mcp.go uses the same pattern. Adding
	// "export" to isSystemCommand instead would also exempt "secrets export",
	// because that function matches parent names too.
	PersistentPreRunE: func(_ *cobra.Command, _ []string) error { return nil },
	Run: func(cmd *cobra.Command, _ []string) {
		cmd.Help() //nolint:errcheck,gosec
	},
}

// newExportOpenCmd builds "export open". It is a constructor rather than a
// package variable so every test gets fresh flags.
func newExportOpenCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "open <sealed-file>",
		Short: "Decrypt a sealed certificate or key export",
		Long: `Decrypt a file written by "certificates export" or "keys export" with
--encrypt (the default) and write the plaintext file it holds: a PEM chain
and private key, a PKCS12 bundle, or a PEM private key, exactly as the same
export with --encrypt=false would have written it.

The passphrase is read from --passphrase-file, then the
ROCKETVAULT_EXPORT_PASSPHRASE environment variable, then a prompt. A wrong
passphrase writes nothing. A sealed "secrets export" file is refused; read
it with "rocketvault secrets import".

The output is written with 0600 permissions through a temporary file in the
same directory, and an existing file is never replaced unless --force is
given. It holds a private key, so delete it when you are done. Opening is
not audited: it touches no vault. No session, database, config file or
server is needed.`,
		Example: `  # Open a sealed certificate export, prompting for the passphrase
  rocketvault export open client.pem.sealed --file client.pem

  # Open non-interactively, replacing an earlier output
  rocketvault export open signer.pem.sealed --file signer.pem \
    --passphrase-file /run/secrets/export-pass --force`,
		Args: cobra.ExactArgs(1),
		RunE: runExportOpen,
	}
	cmd.Flags().StringP("file", "o", "", "Output file path (required)")
	cmd.Flags().String("passphrase-file", "", "Read the export passphrase from the first line of this file")
	cmd.Flags().Bool("force", false, "Replace the output file if it already exists")
	cmd.MarkFlagRequired("file") //nolint:errcheck,gosec
	return cmd
}

// runExportOpen is "export open"'s RunE.
func runExportOpen(cmd *cobra.Command, args []string) error {
	out, _ := cmd.Flags().GetString("file")
	passphraseFile, _ := cmd.Flags().GetString("passphrase-file")
	force, _ := cmd.Flags().GetBool("force")

	if out == "" || out == "-" {
		return errors.New(exportStdoutRefusedMessage)
	}
	// Refuse early, before any prompt. WritePrivateFile checks again
	// atomically, so a file that appears later is still never replaced.
	if !force {
		_, err := os.Lstat(out)
		switch {
		case err == nil:
			return errors.New(exportOutputExistsMessage)
		case !errors.Is(err, fs.ErrNotExist):
			return errors.New(exportOutputUncheckableMessage)
		}
	}

	data, err := readSealedExport(args[0])
	if err != nil {
		return err
	}
	if !common.IsSealedExport(data) {
		return errors.New(exportNotSealedMessage)
	}

	passphrase, err := common.ResolvePassphrase(common.PassphraseSource{
		File:   passphraseFile,
		EnvVar: common.ExportPassphraseEnvVar,
		Prompt: "Export passphrase: ",
	})
	if errors.Is(err, common.ErrNoPassphraseAvailable) {
		return fmt.Errorf("no passphrase is available: pass --passphrase-file or set %s", common.ExportPassphraseEnvVar)
	}
	if err != nil {
		return fmt.Errorf("failed to resolve export passphrase: %w", err)
	}

	p, err := common.OpenItemExport(data, passphrase)
	if err != nil {
		return openExportError(err)
	}
	defer clear(p.Content)
	if len(p.Content) == 0 {
		return errors.New(exportEmptyContentMessage)
	}

	if err := common.WritePrivateFile(out, p.Content, force); err != nil {
		switch {
		case errors.Is(err, common.ErrOutputExists):
			return errors.New(exportOutputExistsMessage)
		case errors.Is(err, common.ErrHardLinksUnsupported):
			return errors.New(exportWriteFailedPrefix + common.ErrHardLinksUnsupported.Error())
		}
		return fmt.Errorf("%s%w", exportWriteFailedPrefix, err)
	}

	protection := "unencrypted, in the clear"
	if p.Format == model.ExportFormatPKCS12 {
		protection = "protected only by its PKCS12 password"
	}
	fmt.Fprintf(cmd.ErrOrStderr(), "Warning: %s holds the %s's private key %s. Delete it when you are done.\n", //nolint:errcheck
		out, terminalSafe(p.Kind), protection)
	fmt.Fprintf(cmd.OutOrStdout(), "Export opened\nKind: %s\nName: %s\nVersion: %d\nFormat: %s\nFile: %s\n", //nolint:errcheck
		terminalSafe(p.Kind), terminalSafe(p.Name), p.Version, terminalSafe(p.Format), out)
	return nil
}

// terminalSafe drops every control rune from s, including ESC, BEL, CR and
// the C1 range. Payload strings come from a file that may have been crafted,
// so they must not be able to drive the terminal.
func terminalSafe(s string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return -1
		}
		return r
	}, s)
}

// openExportError maps an OpenItemExport failure to a fixed message, so no
// raw decoding error reaches the terminal.
func openExportError(err error) error {
	switch {
	case errors.Is(err, common.ErrNotItemExport):
		return errors.New(exportNotItemMessage)
	case errors.Is(err, common.ErrWrongPassphrase):
		return errors.New(exportWrongPassMessage)
	case errors.Is(err, common.ErrUnsupportedExportVersion):
		return errors.New(exportVersionMessage)
	case errors.Is(err, common.ErrPassphraseRequired):
		return errors.New(exportEmptyPassMessage)
	}
	return errors.New(exportMalformedMessage)
}

// readSealedExport reads at most maxSealedExportBytes from path.
func readSealedExport(path string) ([]byte, error) {
	f, err := os.Open(filepath.Clean(path)) //nolint:gosec // G304: the path is the caller's own argument.
	if err != nil {
		return nil, fmt.Errorf("failed to read export file: %w", err)
	}
	defer f.Close() //nolint:errcheck
	data, err := io.ReadAll(io.LimitReader(f, maxSealedExportBytes+1))
	if err != nil {
		return nil, fmt.Errorf("failed to read export file: %w", err)
	}
	if len(data) > maxSealedExportBytes {
		return nil, errors.New(exportNotSealedMessage + ": it is larger than 1 MiB")
	}
	return data, nil
}

// isExportGroupArgs reports whether args select the top-level "export" group
// or one of its commands. initConfig uses it to skip the config file, which
// these commands never read. It compares command pointers, not names, so
// "secrets export", "certificates export" and "keys export" never match.
func isExportGroupArgs(args []string) bool {
	cmd, _, err := rootCmd.Find(args)
	if err != nil || cmd == nil {
		return false
	}
	return cmd == exportGroupCmd || cmd.Parent() == exportGroupCmd
}

func init() {
	rootCmd.AddCommand(exportGroupCmd)
	exportGroupCmd.AddCommand(newExportOpenCmd())
}
