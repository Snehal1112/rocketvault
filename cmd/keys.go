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

package cmd

import (
	"github.com/spf13/cobra"

	"rocketvault/cmd/keys"
)

// keysCmd represents the keys command
var keysCmd = &cobra.Command{
	Use:   "keys",
	Short: "Manage keys",
	Long: `Manage the cryptographic keys held in a vault: create RSA and ECDSA keys,
inspect and list them, update their metadata, rotate them, delete them, and
use them to sign, verify, wrap, and unwrap. Crypto operations run inside the
vault and return only the result. Private key material leaves the vault only
through "keys export", and only for a key created or imported with --exportable.

Creating, updating, rotating, deleting, and every crypto operation require the
admin or crypto_manager role plus the matching data action (keys/create,
keys/sign, keys/wrap, ...) in the target vault. get and list require only the
keys/read data action. export needs only the keys/export data action, held by
the Key Vault Key Exporter and Key Vault Administrator roles, and no account
role. Vault access is deny-by-default, so a role assignment must exist for the
target vault — see 'rocketvault vault-access'.

Every command here acts on the vault named by --vault, defaulting to
"default". The CLI creates RSA and ECDSA keys only; symmetric AES (OCT) keys
are HSM-only and available through the REST API when hsm.enabled is true.`,
	Example: `  # Log in once; the session is cached
  rocketvault users login --username admin

  # Create an RSA key in the default vault
  rocketvault keys create --name <name> --type RSA --bits 2048

  # List the keys in a named vault
  rocketvault keys list --vault payments

  # Sign base64-encoded data with a key
  rocketvault keys sign --key-id <key-id> --data <base64-data> \
    --algorithm RS256`,
	Run: func(cmd *cobra.Command, args []string) {
		// Show help when command is called without subcommands
		cmd.Help() //nolint:errcheck,gosec
	},
}

func init() {
	rootCmd.AddCommand(keysCmd)

	keys.InitKeysCreate(keysCmd)
	keys.InitKeysImport(keysCmd)
	keys.InitKeysDelete(keysCmd)
	keys.InitKeysGet(keysCmd)
	keys.InitKeysList(keysCmd)
	keys.InitKeysUpdate(keysCmd)
	keys.InitKeysRotate(keysCmd)
	keys.InitKeysRotationPolicy(keysCmd)
	keys.InitKeysWrap(keysCmd)
	keys.InitKeysUnwrap(keysCmd)
	keys.InitKeysSign(keysCmd)
	keys.InitKeysVerify(keysCmd)
	keys.InitKeysExport(keysCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// keysCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// keysCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}
