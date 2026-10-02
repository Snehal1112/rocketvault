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
	"encoding/base64"
	"fmt"

	"github.com/google/uuid"
	"github.com/spf13/cobra"

	"rocketvault/cmd/vaultcli"
	keyServices "rocketvault/internal/services/keys"
	"rocketvault/model"
)

// wrapCmd represents the wrap subcommand.
var wrapCmd = &cobra.Command{
	Use:   "wrap",
	Short: "Wrap key material using a vault RSA key",
	Long: `Wrap (encrypt) plaintext key material with an RSA key held in the target
vault and print the wrapped result to stdout as standard base64. The CLI
always requests RSA-OAEP; there is no algorithm flag, so this path needs an
RSA key.

Requires the admin or crypto_manager role, and the
Microsoft.KeyVault/vaults/keys/wrap/action data action in the target vault,
which defaults to "default".

--key-id and --key-material are both required, and --key-material must be
standard base64. --version selects an archived key version produced by
"keys rotate"; 0 or omitted wraps with the key's current material. A key
that is revoked, disabled, or outside its not-before/expiry window is
refused.`,
	Example: `  # Wrap key material with an RSA key in the default vault
  rocketvault keys wrap --key-id <uuid> --key-material <base64>

  # Wrap with an RSA key in a named vault
  rocketvault keys wrap --key-id <uuid> --key-material <base64> \
    --vault payments

  # Wrap with an earlier version of a rotated key
  rocketvault keys wrap --key-id <uuid> --key-material <base64> \
    --version 1`,
	RunE: func(cmd *cobra.Command, args []string) error {
		s, err := vaultcli.Caller(cmd, vaultcli.Op{
			// Policy matches the operation HTTP passes for the wrap route.
			Audit: "wrap_key", Action: model.ActionKeysWrap, Policy: model.OpWrap,
			Roles: []string{model.RoleAdmin, model.RoleCryptoManager},
		})
		if err != nil {
			return err
		}

		keyIDStr, _ := cmd.Flags().GetString("key-id")
		keyMaterialB64, _ := cmd.Flags().GetString("key-material")
		version, _ := cmd.Flags().GetInt("version")

		if keyIDStr == "" || keyMaterialB64 == "" {
			return s.Fail("--key-id and --key-material are required", nil)
		}

		keyID, err := uuid.Parse(keyIDStr)
		if err != nil {
			return s.Fail("invalid key ID", err)
		}

		plaintext, err := base64.StdEncoding.DecodeString(keyMaterialB64)
		if err != nil {
			return s.Fail("failed to decode --key-material (must be standard base64)", err)
		}

		// Authorize only after the input is known good, so a malformed
		// argument still reports itself rather than a permission error.
		if err := s.Authorize(); err != nil {
			return err
		}

		cryptoService := s.Container.GetCryptoService()

		result, err := cryptoService.WrapKey(s.Ctx, keyServices.WrapKeyRequest{
			KeyID:        keyID,
			UserID:       s.Claims.UserID,
			VaultID:      s.VaultID,
			Scope:        s.Scope,
			PlaintextKey: plaintext,
			Algorithm:    "RSA-OAEP",
			Version:      version,
		})
		if err != nil {
			return s.Fail("wrap failed", err)
		}

		s.OK(fmt.Sprintf("key material wrapped with vault key %s", keyID))
		_, _ = fmt.Fprintln(cmd.OutOrStdout(), base64.StdEncoding.EncodeToString(result.WrappedKey))
		return nil
	},
}

// NewWrapCmd returns the wrap cobra command (used in registration).
func NewWrapCmd() *cobra.Command {
	return wrapCmd
}

// InitKeysWrap adds the wrap subcommand to the keys command.
func InitKeysWrap(keysCmd *cobra.Command) {
	keysCmd.AddCommand(wrapCmd)

	wrapCmd.Flags().String("key-id", "", "UUID of the vault RSA key used for wrapping")
	wrapCmd.Flags().String("key-material", "", "Base64-encoded plaintext key material to wrap")
	wrapCmd.Flags().Int("version", 0, "Key version to use (0 or omitted = the key's current version)")
}
