/*
Copyright © 2025 Snehal Dangroshiya
*/

package certificates

import (
	"errors"
	"fmt"
	"strings"

	"github.com/google/uuid"
	"github.com/spf13/cobra"

	"rocketvault/cmd/vaultcli"
	"rocketvault/common"
	certServices "rocketvault/internal/services/certificates"
	"rocketvault/internal/services/exportaudit"
	"rocketvault/model"
)

// pkcs12PasswordEnvVar names the environment variable that supplies a PKCS12
// password without a terminal. An empty value counts as unset; an empty
// password needs --pkcs12-empty-password.
const pkcs12PasswordEnvVar = "ROCKETVAULT_PKCS12_PASSWORD" //nolint:gosec // G101: an environment variable name, not a credential.

// These are the fixed texts common.ResolvePassphrase's prompt returns. They
// say "passphrase", so they are reworded for the PKCS12 password.
const (
	promptMismatchText = "passphrases do not match"
	promptEmptyText    = "passphrase must not be empty"
)

// newExportCmd builds the "certificates export" command. It is a
// constructor rather than a package variable so every test gets fresh flags.
func newExportCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "export <id>",
		Short: "Export a certificate and its private key to a file",
		Long: `Export one version of a certificate and its private key to a file: as
PEM (the leaf certificate, then any intermediates, then the unencrypted
PKCS#8 private key, in one file) or as a PKCS12 bundle.

Only a certificate created with --exportable can be exported. A refusal
names the reason and writes no file.

Requires the Microsoft.KeyVault/vaults/certificates/export/action data
action in the target vault, held by the Key Vault Certificate Exporter and
Key Vault Administrator roles. No account role is required. Acts on the
vault named by --vault, defaulting to "default". Every attempt that reaches
this command's own checks, allowed or denied, is written to the audit log; a
failed login or a missing service container records nothing.

The file is sealed by default, as with "secrets export": --encrypt (default
true) seals it under a passphrase read from --passphrase-file, then the
ROCKETVAULT_EXPORT_PASSPHRASE environment variable, then a prompt asked
twice. If none of those yields a passphrase the command fails and writes no
file. Open a sealed file with "rocketvault export open". --encrypt=false
writes the PEM or PKCS12 file directly and prints a warning.

--format pkcs12 needs a PKCS12 password, read from --pkcs12-password-file,
then the ROCKETVAULT_PKCS12_PASSWORD environment variable, then a prompt
asked twice. An empty password is used only with --pkcs12-empty-password.
--compat legacy uses 3DES and SHA-1 for tools that cannot read the default
AES-256 encoding.

The file is written with 0600 permissions through a temporary file in the
same directory, so a failure leaves no partial file. An existing file is
never replaced unless --force is given. Missing parent directories are
created with 0700 permissions. Nothing secret is printed to the terminal.`,
		Example: `  # Export the current version as a sealed PEM file
  rocketvault certificates export <id> --file client.pem.sealed

  # Export version 2 as a sealed PKCS12 bundle from a named vault
  rocketvault certificates export <id> --format pkcs12 --version 2 \
    --file client.p12.sealed --passphrase-file /run/secrets/export-pass \
    --pkcs12-password-file /run/secrets/p12-pass --vault payments

  # Write a plaintext PEM file deliberately, accepting the warning
  rocketvault certificates export <id> --file client.pem --encrypt=false`,
		Args: cobra.ExactArgs(1),
		RunE: runCertificateExport,
	}
	vaultcli.AddExportOutputFlags(cmd)
	cmd.Flags().StringP("format", "f", model.ExportFormatPEM, "Output format: pem (chain plus PKCS#8 key) or pkcs12")
	cmd.Flags().String("compat", model.ExportCompatModern, "PKCS12 encoding: modern (AES-256) or legacy (3DES and SHA-1)")
	cmd.Flags().Int("version", 0, "Certificate version to export (0 or omitted = the current version)")
	cmd.Flags().String("pkcs12-password-file", "", "Read the PKCS12 password from the first line of this file")
	cmd.Flags().Bool("pkcs12-empty-password", false, "Encode the PKCS12 bundle with an empty password, deliberately")
	return cmd
}

// InitCertificatesExport registers the export command.
func InitCertificatesExport(certificatesCmd *cobra.Command) {
	certificatesCmd.AddCommand(newExportCmd())
}

// runCertificateExport is the export command's RunE. Every path after
// Caller records exactly one audit event.
func runCertificateExport(cmd *cobra.Command, args []string) error {
	s, err := vaultcli.Caller(cmd, vaultcli.Op{
		Audit: "export_certificate", Action: model.ActionCertificatesExportItem, Policy: model.OpCreate,
		AuthzFailMsg: "failed to export certificate",
	})
	if err != nil {
		return err
	}

	format, _ := cmd.Flags().GetString("format")
	format = strings.ToLower(format)
	compat, _ := cmd.Flags().GetString("compat")
	compat = strings.ToLower(compat)
	version, _ := cmd.Flags().GetInt("version")
	p12File, _ := cmd.Flags().GetString("pkcs12-password-file")
	p12Empty, _ := cmd.Flags().GetBool("pkcs12-empty-password")
	out := vaultcli.ReadExportOutput(cmd)
	e := vaultcli.BeginExportAttempt(s, "certificate", args[0], format, version)

	certID, err := uuid.Parse(args[0])
	if err != nil {
		return e.Fail(exportaudit.BadRequest("certificate ID must be a UUID"))
	}
	if msg := checkCertificateExportFlags(format, compat, version, cmd.Flags().Changed("compat"), p12File, p12Empty); msg != "" {
		return e.Fail(exportaudit.BadRequest(msg))
	}
	if f := out.Check(); f != nil {
		return e.Fail(*f)
	}

	// Authorize only after the input is known good, so a malformed argument
	// reports itself, and before any prompt, so an unauthorized caller is
	// never asked for a passphrase or a password.
	if err := s.Authorize(); err != nil {
		return e.Denied(err)
	}

	passphrase, err := out.Passphrase()
	if err != nil {
		return e.FailInput("export passphrase unavailable", err)
	}
	var password *string
	if format == model.ExportFormatPKCS12 {
		pw, pwErr := resolvePKCS12Password(p12File, p12Empty)
		if pwErr != nil {
			return e.FailInput("pkcs12 password unavailable", pwErr)
		}
		password = &pw
	}

	result, err := s.Container.GetCertificateService().ExportCertificate(s.Ctx, s.Scope, certID, certServices.ExportCertificateRequest{
		Format: format, Password: password, Compat: compat, Version: version,
	})
	if err != nil {
		return e.FailService(err)
	}

	payload := common.ItemExportPayload{
		Kind: common.ItemExportKindCertificate, ID: result.ID.String(), Name: result.Name, Version: result.Version,
		Format: result.Format, KeyAlgorithm: result.KeyAlgorithm, Content: certificateExportContent(result),
	}
	defer clear(payload.Content)
	if err := out.Write(cmd, payload, passphrase, certificatePlaintextWarning(result.Format)); err != nil {
		return e.FailOutput(err)
	}
	e.Succeed(result.Name, result.Version)
	out.PrintStatus(cmd, "Certificate", result.Name, result.Version, result.Format)
	return nil
}

// checkCertificateExportFlags validates the certificate-specific flags and
// returns a fixed message, or "" when they are usable.
func checkCertificateExportFlags(format, compat string, version int, compatSet bool, p12File string, p12Empty bool) string {
	switch {
	case format != model.ExportFormatPEM && format != model.ExportFormatPKCS12:
		return "--format must be pem or pkcs12"
	case compat != model.ExportCompatModern && compat != model.ExportCompatLegacy:
		return "--compat must be modern or legacy"
	case version < 0:
		return "--version must be 0 or a positive version number"
	case format == model.ExportFormatPEM && (compatSet || p12File != "" || p12Empty):
		return "--compat, --pkcs12-password-file and --pkcs12-empty-password apply only to --format pkcs12"
	case p12File != "" && p12Empty:
		return "pass --pkcs12-password-file or --pkcs12-empty-password, not both"
	}
	return ""
}

// resolvePKCS12Password returns the PKCS12 password from
// --pkcs12-empty-password, then --pkcs12-password-file, then
// ROCKETVAULT_PKCS12_PASSWORD, then a prompt asked twice. A password is never
// a command-line value, and only --pkcs12-empty-password yields an empty one.
func resolvePKCS12Password(file string, empty bool) (string, error) {
	if empty {
		return "", nil
	}
	password, err := common.ResolvePassphrase(common.PassphraseSource{
		File:          file,
		EnvVar:        pkcs12PasswordEnvVar,
		Prompt:        "PKCS12 password: ",
		Confirm:       true,
		ConfirmPrompt: "Confirm PKCS12 password: ",
	})
	if err != nil {
		return "", pkcs12PasswordError(err, file)
	}
	return password, nil
}

// pkcs12PasswordError rewords an error from common.ResolvePassphrase, whose
// texts say "passphrase", so it names the PKCS12 password instead. Only
// fixed text and the reader's own cause are kept, never a password.
func pkcs12PasswordError(err error, file string) error {
	cause := errors.Unwrap(err)
	switch {
	case errors.Is(err, common.ErrNoPassphraseAvailable):
		return fmt.Errorf("pkcs12 needs a password: pass --pkcs12-password-file, set %s, or pass --pkcs12-empty-password",
			pkcs12PasswordEnvVar)
	case file != "" && cause != nil:
		return fmt.Errorf("failed to read the PKCS12 password file: %w", cause)
	case file != "":
		return fmt.Errorf("the PKCS12 password file %s is empty: pass --pkcs12-empty-password for an empty password", file)
	case err.Error() == promptMismatchText:
		return errors.New("the PKCS12 passwords do not match")
	case err.Error() == promptEmptyText:
		return errors.New("the PKCS12 password must not be empty: pass --pkcs12-empty-password for an empty password")
	case cause != nil:
		return fmt.Errorf("failed to read the PKCS12 password: %w", cause)
	}
	return errors.New("failed to read the PKCS12 password")
}

// certificateExportContent returns the file an export writes in the clear:
// the PEM chain followed by the PKCS#8 key, or the PKCS12 bytes.
func certificateExportContent(r *certServices.ExportCertificateResult) []byte {
	if r.Format == model.ExportFormatPKCS12 {
		return r.PKCS12
	}
	return []byte(r.CertificatePEM + r.PrivateKeyPEM)
}

// certificatePlaintextWarning completes the --encrypt=false warning for
// format.
func certificatePlaintextWarning(format string) string {
	if format == model.ExportFormatPKCS12 {
		return "will hold the certificate's private key protected only by the PKCS12 password."
	}
	return "will hold the certificate's private key unencrypted, in the clear."
}
