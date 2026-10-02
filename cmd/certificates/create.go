/*
Copyright © 2025 Snehal Dangroshiya
*/

package certificates

import (
	"fmt"
	"strings"

	"github.com/google/uuid"
	"github.com/spf13/cobra"

	"rocketvault/cmd/vaultcli"
	certServices "rocketvault/internal/services/certificates"
	"rocketvault/model"
)

// createCmd represents the create command
// createCmd represents the create command
var createCmd = &cobra.Command{
	Use:   "create",
	Short: "Create a new X.509 certificate",
	Long: `Issue an X.509 certificate over a key that already exists in the target
vault, and store the certificate in that same vault. Without --ca-cert-id
the certificate is self-signed; with --ca-cert-id it is signed by that CA
certificate, which must live in the same vault.

The certificate is an ordinary leaf unless you pass --is-ca, which marks it
as a Certificate Authority so it can sign later certificates. Ask for that
only when you mean it: anything holding a CA's private key can issue
certificates for any name. --is-ca cannot be combined with --ca-cert-id.

Requires the admin or certificate_manager role, and the
Microsoft.KeyVault/vaults/certificates/create data action in the target
vault. The key named by --key-id must also be owned by the calling user, as
must the certificate named by --ca-cert-id.

Acts on the vault named by --vault, defaulting to "default". --name and
--key-id are required and --validity-days must be positive. --auto-renew and
--renewal-days only arm the background renewal scheduler for later; they
change nothing about the certificate being issued now. --purge-protection is
sent only when the flag is passed explicitly.

--exportable marks the certificate exportable. It can only be set here, never
later, and needs a key that was itself created with --exportable (otherwise
the create is refused). Exporting still requires the Key Vault Certificate
Exporter role.`,
	Example: `  # Self-signed certificate over an existing key
  rocketvault certificate create --name <name> --key-id <key-id> \
    --validity-days 365

  # Self-signed CA that can sign later certificates
  rocketvault certificate create --name <name> --key-id <key-id> \
    --is-ca --validity-days 3650

  # Certificate signed by a CA certificate in the same vault
  rocketvault certificate create --name <name> --key-id <key-id> \
    --ca-cert-id <ca-cert-id> --validity-days 90

  # Tagged, auto-renewing certificate in a named vault
  rocketvault certificate create --name <name> --key-id <key-id> \
    --tags prod,tls --auto-renew --renewal-days 45 --vault payments`,
	Args: cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		s, err := vaultcli.Caller(cmd, vaultcli.Op{
			Audit: "create_certificate", Action: model.ActionCertificatesCreate, Policy: model.OpCreate,
			Roles:        []string{model.RoleAdmin, model.RoleCertificateManager},
			AuthzFailMsg: "failed to create certificate",
		})
		if err != nil {
			return err
		}

		name, _ := cmd.Flags().GetString("name")
		keyIDStr, _ := cmd.Flags().GetString("key-id")
		validityDays, _ := cmd.Flags().GetInt("validity-days")
		tagsStr, _ := cmd.Flags().GetString("tags")
		caCertIDStr, _ := cmd.Flags().GetString("ca-cert-id")
		autoRenew, _ := cmd.Flags().GetBool("auto-renew")
		renewalDays, _ := cmd.Flags().GetInt("renewal-days")
		isCA, _ := cmd.Flags().GetBool("is-ca")

		if name == "" || keyIDStr == "" || validityDays <= 0 {
			return s.Fail("name, key-id, and validity-days are required", nil)
		}

		keyID, err := uuid.Parse(keyIDStr)
		if err != nil {
			return s.Fail("invalid key ID", err)
		}

		var tags []string
		if tagsStr != "" {
			tags = strings.Split(tagsStr, ",")
			for i, tag := range tags {
				tags[i] = strings.TrimSpace(tag)
			}
		}

		if err := s.Authorize(); err != nil {
			return err
		}
		certService := s.Container.GetCertificateService()

		exportable, _ := cmd.Flags().GetBool("exportable")

		// Create certificate request
		req := certServices.CreateCertificateRequest{
			Name:         name,
			KeyID:        keyID,
			ValidityDays: validityDays,
			Tags:         tags,
			UserID:       s.Claims.UserID,
			VaultID:      s.VaultID,
			AutoRenew:    autoRenew,
			RenewalDays:  renewalDays,
			IsCA:         isCA,
			Exportable:   exportable,
		}
		// Only send purge protection when the flag was explicitly passed.
		if cmd.Flags().Changed("purge-protection") {
			purgeProtection, _ := cmd.Flags().GetBool("purge-protection")
			req.PurgeProtection = &purgeProtection
		}

		var result *certServices.CreateCertificateResult
		if caCertIDStr != "" {
			// CA-signed certificate
			caCertID, parseErr := uuid.Parse(caCertIDStr)
			if parseErr != nil {
				return s.Fail("invalid CA certificate ID", parseErr)
			}
			req.CACertID = &caCertID
			s.Log.WithField("ca_cert_id", caCertID).Info("Creating CA-signed certificate")
			result, err = certService.CreateCASignedCertificate(s.Ctx, req)
		} else {
			// Self-signed certificate
			result, err = certService.CreateSelfSignedCertificate(s.Ctx, req)
		}

		if err != nil {
			return s.Fail("failed to create certificate", err)
		}

		s.OK(fmt.Sprintf("certificate created: %s, ID: %s", result.Name, result.CertID))
		return vaultcli.Print(s, createdCertColumns, result)
	},
}

// InitCertificatesCreate initializes the create command for certificates.
func InitCertificatesCreate(certificatesCmd *cobra.Command) {
	certificatesCmd.AddCommand(createCmd)

	createCmd.Flags().String("name", "", "Name (Common Name) for the new certificate")
	createCmd.Flags().String("key-id", "", "UUID of the key to use for the certificate")
	createCmd.Flags().Int("validity-days", 365, "Certificate validity period in days")
	createCmd.Flags().String("tags", "", "Comma-separated tags for the certificate")
	createCmd.Flags().String("ca-cert-id", "", "UUID of the CA certificate for CA-signed certificates (optional)")
	createCmd.Flags().Bool("auto-renew", false, "Automatically renew certificate before expiry")
	createCmd.Flags().Int("renewal-days", 30, "Days before expiry to trigger renewal")
	createCmd.Flags().Bool("purge-protection", false, "Protect the certificate from being purged")
	createCmd.Flags().Bool("is-ca", false, "Issue the certificate as a Certificate Authority that can sign other certificates")
	createCmd.Flags().Bool("exportable", false, "Allow this certificate and its private key to be exported later; requires a key created with --exportable; cannot be changed after creation")
}
