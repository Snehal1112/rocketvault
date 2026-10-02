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

package keys

import (
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"rocketvault/cmd/vaultcli"
	keyServices "rocketvault/internal/services/keys"
	"rocketvault/model"
)

var importCmd = &cobra.Command{
	Use:   "import",
	Short: "Import an externally-generated key",
	Long: `Import an RSA or ECDSA private key supplied as a JWK into the target vault,
storing it exactly as if RocketVault had generated it -- encrypted PEM for a
software-backed vault, a non-extractable PKCS#11 object for an HSM-backed one.

Requires the admin or crypto_manager role, and the
Microsoft.KeyVault/vaults/keys/import/action data action in the target vault.

--name and one of --jwk-file or --jwk (inline JSON) are required. A JWK with
no private key material (public-only) is rejected.

The key is created in the vault named by --vault, which defaults to
"default".

--exportable marks the key exportable. It can only be set at creation or
import, never later, and an HSM-backed key refuses it. Exporting still
requires the Key Vault Key Exporter role.`,
	Example: `  # Import from a JWK file
  rocketvault keys import --name <name> --jwk-file ./key.jwk.json

  # Import from inline JSON
  rocketvault keys import --name <name> --jwk '{"kty":"RSA","n":"...","e":"AQAB","d":"..."}'`,
	RunE: func(cmd *cobra.Command, args []string) error {
		s, err := vaultcli.Caller(cmd, vaultcli.Op{
			Audit: "import_key", Action: model.ActionKeysImport, Policy: model.OpImport,
			Roles: []string{model.RoleAdmin, model.RoleCryptoManager},
		})
		if err != nil {
			return err
		}

		name, _ := cmd.Flags().GetString("name")
		jwkInline, _ := cmd.Flags().GetString("jwk")
		jwkFile, _ := cmd.Flags().GetString("jwk-file")
		tagsStr, _ := cmd.Flags().GetString("tags")

		if name == "" {
			return s.Fail("name is required", nil)
		}
		if jwkInline == "" && jwkFile == "" {
			return s.Fail("one of --jwk or --jwk-file is required", nil)
		}
		if jwkInline != "" && jwkFile != "" {
			return s.Fail("--jwk and --jwk-file are mutually exclusive", nil)
		}

		jwkBytes := []byte(jwkInline)
		if jwkFile != "" {
			data, readErr := os.ReadFile(jwkFile) //nolint:gosec // operator-supplied path, same as any CLI file argument
			if readErr != nil {
				return s.Fail("failed to read jwk file", readErr)
			}
			jwkBytes = data
		}

		var tags []string
		if tagsStr != "" {
			tags = strings.Split(tagsStr, ",")
			for i, tag := range tags {
				tags[i] = strings.TrimSpace(tag)
			}
		}

		// Authorize only after the input is known good, so a malformed
		// argument still reports itself rather than a permission error.
		if err := s.Authorize(); err != nil {
			return err
		}

		exportable, _ := cmd.Flags().GetBool("exportable")

		req := keyServices.ImportKeyRequest{
			Name:       name,
			JWK:        jwkBytes,
			Tags:       tags,
			UserID:     s.Claims.UserID,
			VaultID:    s.VaultID,
			Exportable: exportable,
		}
		if cmd.Flags().Changed("purge-protection") {
			purgeProtection, _ := cmd.Flags().GetBool("purge-protection")
			req.PurgeProtection = &purgeProtection
		}

		result, err := s.Container.GetKeyService().ImportKey(s.Ctx, req)
		if err != nil {
			return s.Fail("failed to import key", err)
		}

		s.OK(fmt.Sprintf("key imported: %s, ID: %s", result.Name, result.KeyID))
		return vaultcli.Print(s, createdKeyColumns, result)
	},
}

// InitKeysImport initializes the import command for keys and adds it to the
// keys command.
func InitKeysImport(keysCmd *cobra.Command) {
	keysCmd.AddCommand(importCmd)

	importCmd.Flags().String("name", "", "Name for the imported key")
	importCmd.Flags().String("jwk", "", "Inline JWK JSON containing private key material")
	importCmd.Flags().String("jwk-file", "", "Path to a file containing JWK JSON")
	importCmd.Flags().String("tags", "", "Comma-separated tags for the key")
	importCmd.Flags().Bool("purge-protection", false, "Protect the key from being purged")
	importCmd.Flags().Bool("exportable", false, "Allow this key's private material to be exported later; refused for HSM-backed keys; cannot be changed after creation")
}
