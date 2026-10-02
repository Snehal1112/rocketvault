/*
Copyright © 2025 Snehal Dangroshiya

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
*/

package secrets

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"rocketvault/cmd/vaultcli"
	"rocketvault/common"
	"rocketvault/internal/cliclient"
	"rocketvault/internal/container"
	secretServices "rocketvault/internal/services/secrets"
	"rocketvault/model"
)

var (
	importFormat         string
	importFile           string
	importEncrypted      bool
	importPassphraseFile string
	importOverwrite      bool
)

// secretsImportCmd represents the import command.
var secretsImportCmd = &cobra.Command{
	Use:   "import",
	Short: "Import secrets from a file",
	Long: `Import secrets into the target vault from a file in the layout
"secrets export" produces. Each record is matched by name against the
target vault: a name that does not already exist is created at version 1.
A name that already exists is updated when --overwrite is set, which
versions the previous value; otherwise it is skipped.

An encrypted export is detected by its contents, not by a flag or a file
extension. When the file is encrypted the passphrase is read from
--passphrase-file, then the ROCKETVAULT_EXPORT_PASSPHRASE environment
variable, then an interactive prompt. A plaintext file needs no passphrase
and is never prompted for. --encrypted is deprecated and ignored.

--format describes the payload, not the file: an encrypted CSV export is a
JSON envelope on disk, so it is still imported with --format csv.

Requires the admin or secrets_manager role, and the
Microsoft.KeyVault/vaults/secrets/setSecret/action data action in the
target vault.

Acts on the vault named by --vault, which defaults to "default". The caller
becomes the owner of every secret this import creates; an overwritten
secret keeps its existing owner.

Records missing a name or a value are skipped rather than failing the run.
Imported, skipped, and failed counts are all printed when the run finishes.`,
	Example: `  # Import an encrypted export, prompting for the passphrase
  rocketvault secrets import --file secrets.json

  # Import non-interactively, reading the passphrase from a file
  rocketvault secrets import --file secrets.json \
    --passphrase-file /run/secrets/export-pass

  # Import a CSV export into a named vault
  rocketvault secrets import --format csv --file payments.csv \
    --vault <vault-name>

  # Overwrite existing secrets with the same name
  rocketvault secrets import --file secrets.json --overwrite`,
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := cmd.Context()

		format := strings.ToLower(importFormat)
		if format != "json" && format != "csv" {
			return fmt.Errorf("unsupported format: %s (supported: json, csv)", importFormat)
		}

		if target, ok := ctx.Value(common.RemoteTargetKey).(*cliclient.Target); ok && target != nil {
			return runSecretsImportRemote(cmd, ctx, target, format)
		}

		claims, ok := ctx.Value(common.ClaimsKey).(*model.Claims)
		if !ok {
			return fmt.Errorf("unauthorized: missing authentication claims")
		}
		userID := claims.UserID

		if !common.HasAnyRole(claims.Roles, model.RoleAdmin, model.RoleSecretsManager) {
			return fmt.Errorf("forbidden: requires admin or secrets_manager role")
		}

		sc, ok := ctx.Value(common.ServiceContainerKey).(container.ServiceContainerInterface)
		if !ok || sc == nil {
			return fmt.Errorf("service container not available in context")
		}

		if _, err := os.Stat(importFile); os.IsNotExist(err) {
			return fmt.Errorf("import file does not exist: %s", importFile)
		}

		data, err := os.ReadFile(importFile)
		if err != nil {
			return fmt.Errorf("failed to read import file: %w", err)
		}

		// Resolve the target vault by name and check the caller holds a role
		// assignment in it granting ActionSecretsSet.
		vaultID, err := vaultcli.RequireDataAction(ctx, cmd, sc, userID, model.ActionSecretsSet, model.OpImport)
		if err != nil {
			return err
		}

		// A sealed export is opened here, not in the service: the CLI is the
		// only layer that can prompt for a passphrase. Detection is by content,
		// so --format and the file extension are irrelevant to it.
		if common.IsSealedExport(data) {
			passphrase, phErr := common.ResolvePassphrase(common.PassphraseSource{
				File:   importPassphraseFile,
				EnvVar: exportPassphraseEnvVar,
				Prompt: "Import passphrase: ",
			})
			if phErr != nil {
				if errors.Is(phErr, common.ErrNoPassphraseAvailable) {
					return fmt.Errorf("%s is an encrypted export but no passphrase is available: "+
						"pass --passphrase-file or set %s", importFile, exportPassphraseEnvVar)
				}
				return fmt.Errorf("failed to resolve import passphrase: %w", phErr)
			}

			opened, openErr := common.OpenExport(data, passphrase)
			if openErr != nil {
				if errors.Is(openErr, common.ErrWrongPassphrase) {
					return fmt.Errorf("failed to decrypt %s: wrong passphrase or corrupted file", importFile)
				}
				return fmt.Errorf("failed to decrypt %s: %w", importFile, openErr)
			}
			data = opened
		}

		// The scope's actor becomes the owner of every secret this import
		// creates (an overwritten secret keeps its existing owner), so the
		// scope must carry the real authenticated user; uuid.Nil would orphan
		// every created row (and fail the PostgreSQL foreign key outright).
		result, err := sc.GetSecretService().ImportSecrets(ctx, secretServices.ImportSecretsRequest{
			Scope:     model.NewVaultScope(vaultID, userID),
			Data:      data,
			Format:    format,
			Overwrite: importOverwrite,
		})
		if err != nil {
			return fmt.Errorf("failed to import secrets: %w", err)
		}

		fmt.Printf("Secrets imported successfully\nImported: %d\nSkipped: %d\nFailed: %d\n",
			result.ImportedCount, result.SkippedCount, result.FailedCount)

		if len(result.Errors) > 0 {
			fmt.Printf("Errors:\n")
			for _, e := range result.Errors {
				fmt.Printf("  - %s\n", e)
			}
		}

		if result.FailedCount > 0 {
			return fmt.Errorf("%d record(s) failed to import; see errors above", result.FailedCount)
		}

		return nil
	},
}

// runSecretsImportRemote is "secrets import"'s remote-mode path. format and
// data were already resolved by the caller. The server's ImportResponse carries
// the same imported, skipped, failed and per-record error details as local
// mode, and this path exits non-zero on any failed record exactly like local
// mode.
func runSecretsImportRemote(cmd *cobra.Command, ctx context.Context, target *cliclient.Target, format string) error {
	httpClient, ok := ctx.Value(common.RemoteHTTPClientKey).(*http.Client)
	if !ok || httpClient == nil {
		return fmt.Errorf("remote HTTP client not available in context")
	}
	token, ok := ctx.Value(common.TokenKey).(string)
	if !ok || token == "" {
		return fmt.Errorf("remote session token not available in context")
	}

	if _, err := os.Stat(importFile); os.IsNotExist(err) {
		return fmt.Errorf("import file does not exist: %s", importFile)
	}
	data, err := os.ReadFile(importFile)
	if err != nil {
		return fmt.Errorf("failed to read import file: %w", err)
	}

	vault, _ := cmd.Flags().GetString("vault")
	if vault == "" {
		vault = target.Vault
	}

	// A sealed export is only detected, never opened, here: the server
	// decrypts it itself when given the passphrase form field (see
	// ImportSecretsRemote), so the raw (possibly still-encrypted) bytes are
	// sent as-is. A plaintext file is never prompted for, matching local mode.
	var passphrase string
	if common.IsSealedExport(data) {
		var phErr error
		passphrase, phErr = common.ResolvePassphrase(common.PassphraseSource{
			File:   importPassphraseFile,
			EnvVar: exportPassphraseEnvVar,
			Prompt: "Import passphrase: ",
		})
		if phErr != nil {
			if errors.Is(phErr, common.ErrNoPassphraseAvailable) {
				return fmt.Errorf("%s is an encrypted export but no passphrase is available: "+
					"pass --passphrase-file or set %s", importFile, exportPassphraseEnvVar)
			}
			return fmt.Errorf("failed to resolve import passphrase: %w", phErr)
		}
	}

	result, err := cliclient.ImportSecretsRemote(ctx, httpClient, token, target.Server, vault, data, format, importOverwrite, passphrase)
	if err != nil {
		return fmt.Errorf("failed to import secrets: %w", err)
	}

	return reportRemoteImport(os.Stdout, result)
}

// reportRemoteImport prints the server's import result and returns an error
// when any record failed, matching the local import command's exit behavior.
func reportRemoteImport(w io.Writer, result *model.ImportResponse) error {
	if result.FailedCount == 0 {
		fmt.Fprintf(w, "Secrets imported successfully\nImported: %d\nSkipped: %d\nFailed: %d\nTotal: %d\n", //nolint:errcheck,gosec
			result.ImportedCount, result.SkippedCount, result.FailedCount, result.TotalCount)
		return nil
	}

	fmt.Fprintf(w, "Import finished with errors\nImported: %d\nSkipped: %d\nFailed: %d\nTotal: %d\n", //nolint:errcheck,gosec
		result.ImportedCount, result.SkippedCount, result.FailedCount, result.TotalCount)
	if len(result.Errors) > 0 {
		fmt.Fprintf(w, "Errors:\n") //nolint:errcheck,gosec
		for _, e := range result.Errors {
			fmt.Fprintf(w, "  - %s\n", e) //nolint:errcheck,gosec
		}
	}
	return fmt.Errorf("%d record(s) failed to import; see errors above", result.FailedCount)
}

// InitSecretsImport initializes the secrets import command.
func InitSecretsImport(parentCmd *cobra.Command) {
	parentCmd.AddCommand(secretsImportCmd)
	secretsImportCmd.Flags().StringVarP(&importFormat, "format", "f", "json", "Import format (json or csv)")
	secretsImportCmd.Flags().StringVarP(&importFile, "file", "i", "", "Input file path (required)")
	secretsImportCmd.Flags().BoolVarP(&importEncrypted, "encrypted", "e", true, "File is encrypted (deprecated: detected automatically)")
	// Kept rather than removed: detection makes it redundant, but deleting it
	// would break existing invocations for no benefit.
	secretsImportCmd.Flags().MarkDeprecated("encrypted", //nolint:errcheck,gosec
		"encryption is detected automatically and this flag is ignored")
	secretsImportCmd.Flags().StringVar(&importPassphraseFile, "passphrase-file", "",
		"Read the import passphrase from the first line of this file")
	secretsImportCmd.Flags().BoolVarP(&importOverwrite, "overwrite", "w", false, "Overwrite existing secrets")
	secretsImportCmd.MarkFlagRequired("file") //nolint:errcheck,gosec
}
