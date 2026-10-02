/*
Copyright © 2025 Snehal Dangroshiya
*/

package keys

import (
	"github.com/google/uuid"
	"github.com/spf13/cobra"

	"rocketvault/cmd/vaultcli"
	"rocketvault/common"
	"rocketvault/internal/services/exportaudit"
	"rocketvault/model"
)

// keyPlaintextWarning completes the --encrypt=false warning for a key.
const keyPlaintextWarning = "will hold the key's private key unencrypted, in the clear."

// newKeyExportCmd builds the "keys export" command. It is a constructor
// rather than a package variable so every test gets fresh flags.
func newKeyExportCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "export <id>",
		Short: "Export a key's private key to a PEM file",
		Long: `Export one version of a software-backed key as an unencrypted PKCS#8
private key in PEM, written to a file.

Only a key created or imported with --exportable can be exported.
HSM-backed, symmetric oct and ES256K keys never can. A refusal names the
reason and writes no file.

Requires the Microsoft.KeyVault/vaults/keys/export/action data action in
the target vault, held by the Key Vault Key Exporter and Key Vault
Administrator roles. No account role is required. Acts on the vault named
by --vault, defaulting to "default". Every attempt that reaches this command's
own checks, allowed or denied, is written to the audit log; a failed login or
a missing service container records nothing.

The file is sealed by default, as with "secrets export": --encrypt (default
true) seals it under a passphrase read from --passphrase-file, then the
ROCKETVAULT_EXPORT_PASSPHRASE environment variable, then a prompt asked
twice. If none of those yields a passphrase the command fails and writes no
file. Open a sealed file with "rocketvault export open". --encrypt=false
writes the PEM file directly and prints a warning.

The file is written with 0600 permissions through a temporary file in the
same directory, so a failure leaves no partial file. An existing file is
never replaced unless --force is given. Missing parent directories are
created with 0700 permissions. Nothing secret is printed to the terminal.`,
		Example: `  # Export the current version as a sealed file
  rocketvault keys export <key-id> --file signer.pem.sealed

  # Export version 1 of a rotated key from a named vault, non-interactively
  rocketvault keys export <key-id> --version 1 --file signer-v1.pem.sealed \
    --passphrase-file /run/secrets/export-pass --vault payments

  # Write a plaintext PEM file deliberately, accepting the warning
  rocketvault keys export <key-id> --file signer.pem --encrypt=false`,
		Args: cobra.ExactArgs(1),
		RunE: runKeyExport,
	}
	vaultcli.AddExportOutputFlags(cmd)
	cmd.Flags().Int("version", 0, "Key version to export (0 or omitted = the key's current version)")
	return cmd
}

// InitKeysExport registers the export command.
func InitKeysExport(keysCmd *cobra.Command) {
	keysCmd.AddCommand(newKeyExportCmd())
}

// runKeyExport is the export command's RunE. Every path after Caller
// records exactly one audit event.
func runKeyExport(cmd *cobra.Command, args []string) error {
	s, err := vaultcli.Caller(cmd, vaultcli.Op{
		Audit: "export_key", Action: model.ActionKeysExport, Policy: model.OpCreate,
		AuthzFailMsg: "failed to export key",
	})
	if err != nil {
		return err
	}

	version, _ := cmd.Flags().GetInt("version")
	out := vaultcli.ReadExportOutput(cmd)
	e := vaultcli.BeginExportAttempt(s, "key", args[0], model.ExportFormatPEM, version)

	keyID, err := uuid.Parse(args[0])
	if err != nil {
		return e.Fail(exportaudit.BadRequest("key ID must be a UUID"))
	}
	if version < 0 {
		return e.Fail(exportaudit.BadRequest("--version must be 0 or a positive version number"))
	}
	if f := out.Check(); f != nil {
		return e.Fail(*f)
	}

	// Authorize only after the input is known good, so a malformed argument
	// reports itself, and before any prompt, so an unauthorized caller is
	// never asked for a passphrase.
	if err := s.Authorize(); err != nil {
		return e.Denied(err)
	}

	passphrase, err := out.Passphrase()
	if err != nil {
		return e.FailInput("export passphrase unavailable", err)
	}

	result, err := s.Container.GetKeyService().ExportKey(s.Ctx, s.Scope, keyID, version)
	if err != nil {
		return e.FailService(err)
	}

	payload := common.ItemExportPayload{
		Kind: common.ItemExportKindKey, ID: result.ID.String(), Name: result.Name, Version: result.Version,
		Format: result.Format, KeyAlgorithm: result.KeyAlgorithm, Content: []byte(result.PrivateKeyPEM),
	}
	defer clear(payload.Content)
	if err := out.Write(cmd, payload, passphrase, keyPlaintextWarning); err != nil {
		return e.FailOutput(err)
	}
	e.Succeed(result.Name, result.Version)
	out.PrintStatus(cmd, "Key", result.Name, result.Version, result.Format)
	return nil
}
