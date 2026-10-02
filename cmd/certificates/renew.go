/*
Copyright © 2025 Snehal Dangroshiya
*/

package certificates

import (
	"fmt"

	"github.com/google/uuid"
	"github.com/spf13/cobra"

	"rocketvault/cmd/vaultcli"
	certServices "rocketvault/internal/services/certificates"
	"rocketvault/model"
)

// renewCmd represents the renew command
var renewCmd = &cobra.Command{
	Use:   "renew <id>",
	Short: "Renew a certificate",
	Long: `Re-issue an X.509 certificate over its existing key with a fresh validity
period counted from now. The certificate keeps its ID, name, tags and
vault. There is no new certificate ID to record: the renewal adds a
new version instead, and the body it replaces is kept as the previous
version. List them with 'rocketvault certificate versions list <id>'.

A certificate originally signed by a CA is re-issued through that same CA,
so its issuer and chain are preserved; a self-signed certificate is
re-issued self-signed. The signing CA must still exist in the vault, be
enabled, and be within its own validity window, or the renewal is refused
rather than quietly downgraded to self-signed.

Requires the admin or certificate_manager role, and the
Microsoft.KeyVault/vaults/certificates/create data action in the target
vault — not certificates/update. Renewal also needs the
Microsoft.KeyVault/vaults/keys/sign/action data action there, because it
signs with the certificate's key. That key must still exist in the vault,
be owned by the calling user, and be enabled, not revoked, and inside its
validity window. A CA's own key must be usable in the same way.

Acts on the vault named by --vault, defaulting to "default".
--validity-days must be between 1 and 36500; when omitted, the current
version's validity period is kept, capped at 36500. A certificate that is
disabled, not yet valid or already expired reads as inaccessible and cannot
be renewed, so renew before it lapses rather than after.`,
	Example: `  # Renew for the same period as the current version
  rocketvault certificate renew <id>

  # Renew for a shorter period
  rocketvault certificate renew <id> --validity-days 90

  # Renew a certificate in a named vault
  rocketvault certificate renew <id> --validity-days 365 --vault payments`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		s, err := vaultcli.Caller(cmd, vaultcli.Op{
			Audit: "renew_certificate", Action: model.ActionCertificatesCreate, Policy: model.OpRenew,
			Roles:        []string{model.RoleAdmin, model.RoleCertificateManager},
			AuthzFailMsg: "failed to renew certificate",
		})
		if err != nil {
			return err
		}

		certID, err := uuid.Parse(args[0])
		if err != nil {
			return s.Fail("invalid certificate ID", err)
		}

		validityDays, _ := cmd.Flags().GetInt("validity-days")
		// An omitted flag keeps the current period; an explicit value must be positive.
		keepPeriod := !cmd.Flags().Changed("validity-days") && validityDays < 0
		if !keepPeriod && validityDays <= 0 {
			return s.Fail("validity-days must be greater than 0", nil)
		}

		if err := s.Authorize(); err != nil {
			return err
		}
		// Renewal re-signs with the certificate's key, so it needs keys/sign
		// like issuance does (B77).
		if err := s.RequireAlso(model.ActionKeysSign, model.OpSign); err != nil {
			return err
		}
		certService := s.Container.GetCertificateService()

		if keepPeriod {
			current, err := certService.GetCertificate(s.Ctx, certID, s.Scope)
			if err != nil {
				return s.Fail("failed to renew certificate", err)
			}
			validityDays = certServices.CurrentValidityDays(current)
		}

		result, err := certService.RenewCertificate(s.Ctx, certID, s.Scope, validityDays)
		if err != nil {
			return s.Fail("failed to renew certificate", err)
		}

		s.OK(fmt.Sprintf("certificate renewed: %s, now version %d", result.CertID, result.Version))
		// Renewal adds a version under the same ID, so there is one ID to print.
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Certificate renewed successfully!\nCertificate ID: %s\nVersion: %d\nValidity: %d days\n",
			result.CertID, result.Version, validityDays)
		return nil
	},
}

// InitCertificatesRenew initializes the renew command for certificates.
func InitCertificatesRenew(certificatesCmd *cobra.Command) {
	certificatesCmd.AddCommand(renewCmd)

	renewCmd.Flags().Int("validity-days", -1, "Certificate validity period in days (default: the current version's period)")
}
