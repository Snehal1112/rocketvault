package mcpserver

import (
	"context"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"rocketvault/internal/vaultapi"
)

type createCertificateArgs struct {
	Name         string   `json:"name" jsonschema:"the new certificate's name"`
	KeyName      string   `json:"key_name" jsonschema:"the name of an existing key in this vault to issue against"`
	ValidityDays int      `json:"validity_days" jsonschema:"how many days the certificate is valid for"`
	AutoRenew    bool     `json:"auto_renew,omitempty" jsonschema:"renew automatically before expiry"`
	RenewalDays  int      `json:"renewal_days,omitempty" jsonschema:"how many days before expiry to renew"`
	Tags         []string `json:"tags,omitempty" jsonschema:"tags to attach to the certificate"`
	CAKeyName    string   `json:"ca_key_name,omitempty" jsonschema:"the name of an issuing CA key, if this is not self-signed"`
	CACertName   string   `json:"ca_cert_name,omitempty" jsonschema:"the name of an issuing CA certificate"`
	Vault        string   `json:"vault,omitempty" jsonschema:"the vault to create in; defaults to the server's configured vault"`
}

// createCertificateResult describes the issued certificate. It has no field
// for a PEM or a private key.
type createCertificateResult struct {
	Vault       string `json:"vault"`
	Name        string `json:"name"`
	ID          string `json:"id"`
	Enabled     bool   `json:"enabled"`
	AutoRenew   bool   `json:"auto_renew"`
	RenewalDays int    `json:"renewal_days"`
	ExpiresAt   string `json:"expires_at,omitempty"`
}

// setCertificatePolicyArgs replaces a certificate's issuance policy.
//
// The required fields follow the same rule as the key rotation policy: the
// underlying upsert is a full replacement, so a field that cannot be omitted
// cannot be accidentally zeroed. key_size and curve stay optional because
// exactly one applies per key type, and requiring both would be
// unsatisfiable.
type setCertificatePolicyArgs struct {
	Name             string `json:"name" jsonschema:"the certificate's name, or its id"`
	ValidityMonths   int    `json:"validity_months" jsonschema:"how many months an issued certificate is valid for"`
	KeyType          string `json:"key_type" jsonschema:"RSA or ECDSA"`
	Subject          string `json:"subject" jsonschema:"the distinguished name, such as CN=example.com"`
	AutoRenew        *bool  `json:"auto_renew" jsonschema:"renew automatically before expiry"`
	DaysBeforeExpiry int    `json:"days_before_expiry" jsonschema:"how many days before expiry to renew"`
	KeySize          int    `json:"key_size,omitempty" jsonschema:"key size for RSA"`
	Curve            string `json:"curve,omitempty" jsonschema:"curve for ECDSA"`
	SANs             string `json:"sans,omitempty" jsonschema:"comma-separated subject alternative names"`
	IssuerName       string `json:"issuer_name,omitempty" jsonschema:"the issuer to request from"`
	Vault            string `json:"vault,omitempty" jsonschema:"the vault holding the certificate; defaults to the server's configured vault"`
}

type setCertificatePolicyResult struct {
	Vault            string    `json:"vault"`
	CertificateName  string    `json:"certificate_name"`
	ValidityMonths   int       `json:"validity_months"`
	KeyType          string    `json:"key_type"`
	KeySize          int       `json:"key_size,omitempty"`
	Curve            string    `json:"curve,omitempty"`
	Subject          Untrusted `json:"subject"`
	SANs             Untrusted `json:"sans,omitempty"`
	AutoRenew        bool      `json:"auto_renew"`
	DaysBeforeExpiry int       `json:"days_before_expiry"`
}

type renewCertificateArgs struct {
	Name         string `json:"name" jsonschema:"the certificate's name, or its id"`
	ValidityDays int    `json:"validity_days,omitempty" jsonschema:"days the new version is valid for; omitted keeps the current version's validity period"`
	Vault        string `json:"vault,omitempty" jsonschema:"the vault holding the certificate; defaults to the server's configured vault"`
}

// renewCertificateResult describes the new version. It has no field for a
// PEM or a private key.
type renewCertificateResult struct {
	Vault     string `json:"vault"`
	Name      string `json:"name"`
	Version   int    `json:"version"`
	Enabled   bool   `json:"enabled"`
	ExpiresAt string `json:"expires_at,omitempty"`
}

// registerCertificatesWriteTools adds the write-tier certificate tools.
func registerCertificatesWriteTools(s *Server) {
	registerIf(s, TierWrite, "create_certificate",
		"Issue a certificate against an existing key in the vault. The key must already exist -- "+
			"use list_keys to find one or create_key to make one first. Never returns private key material.",
		Annotations{ReadOnly: false, Idempotent: false, Destructive: false},
		s.handleCreateCertificate)

	registerIf(s, TierWrite, "renew_certificate",
		"Renew a certificate: re-issue it over its key as a new version. The previous version is kept in the "+
			"certificate's history. The caller must own the certificate's key. Never returns private key material.",
		// Not idempotent: each call creates another version.
		Annotations{ReadOnly: false, Idempotent: false, Destructive: false},
		s.handleRenewCertificate)

	registerIf(s, TierWrite, "set_certificate_policy",
		"Replaces a certificate's entire issuance policy. Every required field is applied as given, and anything "+
			"not supplied would be lost, so read the current policy with get_certificate first.",
		Annotations{ReadOnly: false, Idempotent: true, Destructive: false},
		s.handleSetCertificatePolicy)
}

func (s *Server) handleCreateCertificate(ctx context.Context, _ *mcp.CallToolRequest, args createCertificateArgs) (*mcp.CallToolResult, createCertificateResult, error) {
	if args.Name == "" {
		return errorResult("create_certificate requires a name"), createCertificateResult{}, nil
	}
	if args.KeyName == "" {
		return errorResult(
			"create_certificate requires key_name: a certificate is issued against an existing key. " +
				"Use list_keys to find one, or create_key to make one."), createCertificateResult{}, nil
	}
	if args.ValidityDays <= 0 {
		return errorResult("create_certificate requires a positive validity_days"), createCertificateResult{}, nil
	}
	vault, err := s.ResolveVault(args.Vault)
	if err != nil {
		return errorResult("%s", err), createCertificateResult{}, nil
	}

	certificate, err := s.client.CreateCertificate(ctx, vault, vaultapi.CreateCertificateRequest{
		Name:         args.Name,
		KeyName:      args.KeyName,
		ValidityDays: args.ValidityDays,
		Tags:         args.Tags,
		AutoRenew:    args.AutoRenew,
		RenewalDays:  args.RenewalDays,
		CAKeyName:    args.CAKeyName,
		CACertName:   args.CACertName,
	})
	if err != nil {
		return errorResult("could not create certificate %q in vault %q: %s",
			args.Name, vault, err), createCertificateResult{}, nil
	}

	result := createCertificateResult{
		Vault:       vault,
		Name:        certificate.Name,
		ID:          certificate.ID.String(),
		Enabled:     certificate.Enabled,
		AutoRenew:   certificate.AutoRenew,
		RenewalDays: certificate.RenewalDays,
	}
	if certificate.ExpiresAt != nil {
		result.ExpiresAt = certificate.ExpiresAt.Format(time.RFC3339)
	}
	return nil, result, nil
}

func (s *Server) handleSetCertificatePolicy(ctx context.Context, _ *mcp.CallToolRequest, args setCertificatePolicyArgs) (*mcp.CallToolResult, setCertificatePolicyResult, error) {
	if args.Name == "" {
		return errorResult("set_certificate_policy requires a name"), setCertificatePolicyResult{}, nil
	}
	if args.AutoRenew == nil {
		return errorResult(
			"set_certificate_policy requires auto_renew: this call replaces the whole policy, " +
				"so every field must be supplied. Read the current values with get_certificate first."), setCertificatePolicyResult{}, nil
	}
	vault, err := s.ResolveVault(args.Vault)
	if err != nil {
		return errorResult("%s", err), setCertificatePolicyResult{}, nil
	}

	policy, err := s.client.UpsertCertificatePolicy(ctx, vault, args.Name, vaultapi.SetCertificatePolicyRequest{
		ValidityMonths:   args.ValidityMonths,
		KeyType:          args.KeyType,
		KeySize:          args.KeySize,
		Curve:            args.Curve,
		Subject:          args.Subject,
		SANs:             args.SANs,
		AutoRenew:        *args.AutoRenew,
		DaysBeforeExpiry: args.DaysBeforeExpiry,
		IssuerName:       args.IssuerName,
	})
	if err != nil {
		return errorResult("could not set the policy for certificate %q in vault %q: %s",
			args.Name, vault, err), setCertificatePolicyResult{}, nil
	}

	return nil, setCertificatePolicyResult{
		Vault:            vault,
		CertificateName:  args.Name,
		ValidityMonths:   policy.ValidityMonths,
		KeyType:          policy.KeyType,
		KeySize:          policy.KeySize,
		Curve:            policy.Curve,
		Subject:          Wrap(policy.Subject),
		SANs:             Wrap(policy.SANs),
		AutoRenew:        policy.AutoRenew,
		DaysBeforeExpiry: policy.DaysBeforeExpiry,
	}, nil
}

func (s *Server) handleRenewCertificate(ctx context.Context, _ *mcp.CallToolRequest, args renewCertificateArgs) (*mcp.CallToolResult, renewCertificateResult, error) {
	if args.Name == "" {
		return errorResult("renew_certificate requires a name"), renewCertificateResult{}, nil
	}
	if args.ValidityDays < 0 {
		return errorResult("renew_certificate requires a positive validity_days, or none"), renewCertificateResult{}, nil
	}
	vault, err := s.ResolveVault(args.Vault)
	if err != nil {
		return errorResult("%s", err), renewCertificateResult{}, nil
	}

	version, err := s.client.RenewCertificate(ctx, vault, args.Name, args.ValidityDays)
	if err != nil {
		return errorResult("could not renew certificate %q in vault %q: %s", args.Name, vault, err), renewCertificateResult{}, nil
	}

	result := renewCertificateResult{
		Vault:   vault,
		Name:    args.Name,
		Version: version.Version,
		Enabled: version.Enabled,
	}
	if version.ExpiresAt != nil {
		result.ExpiresAt = version.ExpiresAt.Format(time.RFC3339)
	}
	return nil, result, nil
}
