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

// unwrapCmd represents the unwrap subcommand.
var unwrapCmd = &cobra.Command{
	Use:   "unwrap",
	Short: "Unwrap key material using a vault RSA key",
	Long: `Unwrap (decrypt) wrapped key material with an RSA key held in the target
vault and print the recovered plaintext key to stdout as standard base64.
The CLI always requests RSA-OAEP; there is no algorithm flag, so this path
needs the RSA key the material was wrapped with.

Requires the admin or crypto_manager role, and the
Microsoft.KeyVault/vaults/keys/unwrap/action data action in the target
vault, which defaults to "default".

--key-id and --wrapped-key are both required, and --wrapped-key must be
standard base64. --version selects an archived key version produced by
"keys rotate", and must be the version that did the wrapping; 0 or omitted
unwraps with the key's current material. A key that is revoked, disabled,
or outside its not-before/expiry window is refused.`,
	Example: `  # Unwrap key material with an RSA key in the default vault
  rocketvault keys unwrap --key-id <uuid> --wrapped-key <base64>

  # Unwrap with an RSA key in a named vault
  rocketvault keys unwrap --key-id <uuid> --wrapped-key <base64> \
    --vault payments

  # Unwrap material that was wrapped before the key was rotated
  rocketvault keys unwrap --key-id <uuid> --wrapped-key <base64> \
    --version 1`,
	RunE: func(cmd *cobra.Command, args []string) error {
		s, err := vaultcli.Caller(cmd, vaultcli.Op{
			// Policy matches the operation HTTP passes for the unwrap route.
			Audit: "unwrap_key", Action: model.ActionKeysUnwrap, Policy: model.OpUnwrap,
			Roles: []string{model.RoleAdmin, model.RoleCryptoManager},
		})
		if err != nil {
			return err
		}

		keyIDStr, _ := cmd.Flags().GetString("key-id")
		wrappedKeyB64, _ := cmd.Flags().GetString("wrapped-key")
		version, _ := cmd.Flags().GetInt("version")

		if keyIDStr == "" || wrappedKeyB64 == "" {
			return s.Fail("--key-id and --wrapped-key are required", nil)
		}

		keyID, err := uuid.Parse(keyIDStr)
		if err != nil {
			return s.Fail("invalid key ID", err)
		}

		wrappedKey, err := base64.StdEncoding.DecodeString(wrappedKeyB64)
		if err != nil {
			return s.Fail("failed to decode --wrapped-key (must be standard base64)", err)
		}

		// Authorize only after the input is known good, so a malformed
		// argument still reports itself rather than a permission error.
		if err := s.Authorize(); err != nil {
			return err
		}

		cryptoService := s.Container.GetCryptoService()

		result, err := cryptoService.UnwrapKey(s.Ctx, keyServices.UnwrapKeyRequest{
			KeyID:      keyID,
			UserID:     s.Claims.UserID,
			VaultID:    s.VaultID,
			Scope:      s.Scope,
			WrappedKey: wrappedKey,
			Algorithm:  "RSA-OAEP",
			Version:    version,
		})
		if err != nil {
			return s.Fail("unwrap failed", err)
		}

		s.OK(fmt.Sprintf("key material unwrapped with vault key %s", keyID))
		_, _ = fmt.Fprintln(cmd.OutOrStdout(), base64.StdEncoding.EncodeToString(result.PlaintextKey))
		return nil
	},
}

// NewUnwrapCmd returns the unwrap cobra command (used in registration).
func NewUnwrapCmd() *cobra.Command {
	return unwrapCmd
}

// InitKeysUnwrap adds the unwrap subcommand to the keys command.
func InitKeysUnwrap(keysCmd *cobra.Command) {
	keysCmd.AddCommand(unwrapCmd)

	unwrapCmd.Flags().String("key-id", "", "UUID of the vault RSA key used for unwrapping")
	unwrapCmd.Flags().String("wrapped-key", "", "Base64-encoded wrapped key material to unwrap")
	unwrapCmd.Flags().Int("version", 0, "Key version to use (0 or omitted = the key's current version)")
}
