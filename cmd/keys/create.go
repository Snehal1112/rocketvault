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
	"strings"

	"github.com/spf13/cobra"

	"rocketvault/cmd/vaultcli"
	keyServices "rocketvault/internal/services/keys"
	"rocketvault/model"
)

// createCmd represents the create command
var createCmd = &cobra.Command{
	Use:   "create",
	Short: "Create a new key",
	Long: `Generate a new asymmetric key and store its material in the target vault,
encrypted with the server master key. Software keys are stored as encrypted
PEM; when an HSM is configured, only a PKCS#11 handle is stored.

Requires the admin or crypto_manager role, and the
Microsoft.KeyVault/vaults/keys/create data action in the target vault.

--name and --type are both required. --type accepts only RSA or ECDSA;
any other value is rejected before any key is generated. RSA keys must be
2048, 3072 or 4096 bits. ECDSA keys must use curve P-256, P-384, P-521 or
P-256K, and a P-256K key is recorded with type ES256K. Symmetric OCT keys
are HSM-only and cannot be created from the CLI at all.

The key is created in the vault named by --vault, which defaults to
"default".

--exportable marks the key exportable. It can only be set at creation or
import, never later, and an HSM-backed key refuses it. Exporting still
requires the Key Vault Key Exporter role.`,
	Example: `  # RSA key in the default vault
  rocketvault keys create --name <name> --type RSA --bits 2048

  # ECDSA key in a named vault, with tags
  rocketvault keys create --name <name> --type ECDSA \
    --curve P-384 --tags prod,secure --vault payments

  # RSA key that cannot be purged until purge protection is cleared
  rocketvault keys create --name <name> --type RSA --bits 4096 \
    --purge-protection`,
	RunE: func(cmd *cobra.Command, args []string) error {
		s, err := vaultcli.Caller(cmd, vaultcli.Op{
			Audit: "create_key", Action: model.ActionKeysCreate, Policy: model.OpCreate,
			Roles: []string{model.RoleAdmin, model.RoleCryptoManager},
		})
		if err != nil {
			return err
		}

		name, _ := cmd.Flags().GetString("name")
		keyType, _ := cmd.Flags().GetString("type")
		bits, _ := cmd.Flags().GetInt("bits")
		curve, _ := cmd.Flags().GetString("curve")
		tagsStr, _ := cmd.Flags().GetString("tags")

		if name == "" || keyType == "" {
			return s.Fail("name and type are required", nil)
		}

		keyType = strings.ToUpper(keyType)
		if keyType != "RSA" && keyType != "ECDSA" {
			return s.Fail("invalid key type: must be RSA or ECDSA", nil)
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

		req := keyServices.CreateKeyRequest{
			Name:       name,
			Type:       keyType,
			Bits:       bits,
			Curve:      curve,
			Tags:       tags,
			UserID:     s.Claims.UserID,
			VaultID:    s.VaultID,
			Exportable: exportable,
		}
		// Only send purge protection when the flag was explicitly passed.
		if cmd.Flags().Changed("purge-protection") {
			purgeProtection, _ := cmd.Flags().GetBool("purge-protection")
			req.PurgeProtection = &purgeProtection
		}

		keyService := s.Container.GetKeyService()
		var result *keyServices.CreateKeyResult
		if keyType == "RSA" {
			result, err = keyService.CreateRSAKey(s.Ctx, req)
		} else {
			result, err = keyService.CreateECDSAKey(s.Ctx, req)
		}
		if err != nil {
			return s.Fail("failed to create key", err)
		}

		s.OK(fmt.Sprintf("key created: %s, ID: %s", result.Name, result.KeyID))
		return vaultcli.Print(s, createdKeyColumns, result)
	},
}

// InitKeysCreate initializes the create command for keys
// and adds it to the keys command. It also sets up the necessary flags
// and configuration settings. The create command allows users to create
// a new key. It requires the key details to be specified.
//
// parameters:
//
// - keysCmd: The parent command under which the create command will be added.
//
// This function is called in the main function of the application to set up the command structure.
// It is part of the Cobra library, which is used for creating command-line applications in Go.
// The create command is a subcommand of the keys command and is used to create a new key.
// It is part of the Cobra library, which is used for creating command-line applications in Go.
func InitKeysCreate(keysCmd *cobra.Command) {
	keysCmd.AddCommand(createCmd)

	createCmd.Flags().String("name", "", "Name for the new key")
	createCmd.Flags().String("type", "", "Key type (RSA, ECDSA)")
	createCmd.Flags().Int("bits", 2048, "RSA key size in bits (2048, 3072 or 4096)")
	createCmd.Flags().String("curve", "P-256", "ECDSA curve (P-256, P-384, P-521, P-256K)")
	createCmd.Flags().String("tags", "", "Comma-separated tags for the key")
	createCmd.Flags().Bool("purge-protection", false, "Protect the key from being purged")
	createCmd.Flags().Bool("exportable", false, "Allow this key's private material to be exported later; refused for HSM-backed keys; cannot be changed after creation")
}
