/*
Copyright © 2025 Snehal Dangroshiya
*/

package certificates

import (
	"fmt"
	"strconv"

	"github.com/google/uuid"
	"github.com/spf13/cobra"

	"rocketvault/cmd/vaultcli"
	"rocketvault/model"
)

// versionsCmd groups the certificate version commands.
var versionsCmd = &cobra.Command{
	Use:   "versions",
	Short: "List or inspect a certificate's versions",
	Long: `Every create and every renewal gives a certificate a numbered version.
The certificate keeps its ID; the highest number is the current version.
These commands print metadata only: never a PEM or a private key.`,
	Run: func(cmd *cobra.Command, args []string) {
		cmd.Help() //nolint:errcheck,gosec
	},
}

// versionsListCmd lists a certificate's versions.
var versionsListCmd = &cobra.Command{
	Use:   "list <id>",
	Short: "List a certificate's versions",
	Long: `Print every version of a certificate, oldest first, with the current
version last.

Requires the Microsoft.KeyVault/vaults/certificates/read data action in the
target vault. Acts on the vault named by --vault, defaulting to "default".
A disabled certificate's versions are still listed.`,
	Example: `  rocketvault certificate versions list <id>
  rocketvault certificate versions list <id> --vault payments --output json`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		s, err := vaultcli.Caller(cmd, vaultcli.Op{
			Audit: "list_certificate_versions", Action: model.ActionCertificatesRead, Policy: model.OpGet,
			AuthzFailMsg: "failed to list certificate versions",
		})
		if err != nil {
			return err
		}
		certID, err := uuid.Parse(args[0])
		if err != nil {
			return s.Fail("invalid certificate ID", err)
		}
		if err := s.Authorize(); err != nil {
			return err
		}

		versions, err := s.Container.GetCertificateService().ListCertificateVersions(s.Ctx, certID, s.Scope)
		if err != nil {
			return s.Fail("failed to list certificate versions", err)
		}
		s.OK(fmt.Sprintf("certificate versions listed: %s", certID))
		return vaultcli.Print(s, certVersionColumns, versions...)
	},
}

// versionsGetCmd prints one certificate version.
var versionsGetCmd = &cobra.Command{
	Use:   "get <id> <version>",
	Short: "Show one certificate version",
	Long: `Print one version of a certificate by number.

Requires the Microsoft.KeyVault/vaults/certificates/read data action in the
target vault. Acts on the vault named by --vault, defaulting to "default".`,
	Example: `  rocketvault certificate versions get <id> 2`,
	Args:    cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		s, err := vaultcli.Caller(cmd, vaultcli.Op{
			Audit: "get_certificate_version", Action: model.ActionCertificatesRead, Policy: model.OpGet,
			AuthzFailMsg: "failed to get certificate version",
		})
		if err != nil {
			return err
		}
		certID, err := uuid.Parse(args[0])
		if err != nil {
			return s.Fail("invalid certificate ID", err)
		}
		number, err := strconv.Atoi(args[1])
		if err != nil || number < 1 {
			return s.Fail("invalid version: must be a positive integer", err)
		}
		if err := s.Authorize(); err != nil {
			return err
		}

		version, err := s.Container.GetCertificateService().GetCertificateVersion(s.Ctx, certID, number, s.Scope)
		if err != nil {
			return s.Fail("failed to get certificate version", err)
		}
		s.OK(fmt.Sprintf("certificate version retrieved: %s v%d", certID, number))
		return vaultcli.Print(s, certVersionColumns, *version)
	},
}

// InitCertificatesVersions registers the versions command group.
func InitCertificatesVersions(certificatesCmd *cobra.Command) {
	versionsCmd.AddCommand(versionsListCmd, versionsGetCmd)
	certificatesCmd.AddCommand(versionsCmd)
}
