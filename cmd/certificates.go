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
	"rocketvault/cmd/certificates"

	"github.com/spf13/cobra"
)

// certificateCmd represents the certificates command
var certificateCmd = &cobra.Command{
	Use:     "certificates",
	Aliases: []string{"certificate"},
	Short:   "Manage certificates",
	Long: `Manage the X.509 certificates held in a vault: issue a self-signed or
CA-signed certificate over a key that already lives in that vault, inspect and
list certificates, update their metadata, renew them, and delete them.

Issuing, updating, renewing, and deleting require the admin or
certificate_manager role plus the matching data action
(certificates/create, certificates/update, certificates/delete) in the target
vault. get and list require only certificates/read, and export only
certificates/export/action, with no account role. Vault access is
deny-by-default, so a role assignment must exist for the target vault — see
'rocketvault vault-access'.

Every command here acts on the vault named by --vault, defaulting to
"default". A certificate is always bound to an existing key named by --key-id,
so create the key with 'rocketvault keys create' first; pass --ca-cert-id to
sign the new certificate with a CA certificate instead of itself.`,
	Example: `  # Log in once; the session is cached
  rocketvault users login --username admin

  # Issue a self-signed certificate over an existing key
  rocketvault certificates create --name <name> --key-id <key-id> \
    --validity-days 365

  # List the certificates in a named vault
  rocketvault certificates list --vault payments

  # Renew a certificate before it expires
  rocketvault certificates renew <id>`,
	Run: func(cmd *cobra.Command, args []string) {
		// Show help when command is called without subcommands
		cmd.Help() //nolint:errcheck,gosec
	},
}

func init() {
	rootCmd.AddCommand(certificateCmd)

	certificates.InitCertificatesCreate(certificateCmd)
	certificates.InitCertificatesGet(certificateCmd)
	certificates.InitCertificatesList(certificateCmd)
	certificates.InitCertificatesUpdate(certificateCmd)
	certificates.InitCertificatesDelete(certificateCmd)
	certificates.InitCertificatesRenew(certificateCmd)
	certificates.InitCertificatesVersions(certificateCmd)
	certificates.InitCertificatesExport(certificateCmd)
	certificates.InitCertificatesRotationPolicy(certificateCmd)
}
