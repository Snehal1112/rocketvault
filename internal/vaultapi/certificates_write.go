package vaultapi

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/google/uuid"
)

// CreateCertificateRequest describes a certificate to issue.
//
// The key, and any CA references, are given by name. Every other method in
// this package addresses resources by name, and a caller who has just created
// a key has its name to hand more readily than its UUID. Resolve passes a
// UUID through unchanged, so a caller holding one loses nothing.
type CreateCertificateRequest struct {
	Name         string
	KeyName      string
	ValidityDays int
	Tags         []string
	AutoRenew    bool
	RenewalDays  int
	// CAKeyName and CACertName are optional issuer references.
	CAKeyName  string
	CACertName string
	Enabled    *bool
	NotBefore  *time.Time
	// Exportable requests an exportable certificate. It needs a key created
	// exportable and can never be changed later.
	Exportable bool
}

// createCertificateBody mirrors model.CreateCertificateRequest
// (model/certificate.go:58), which addresses by id.
type createCertificateBody struct {
	Name         string     `json:"name"`
	KeyID        string     `json:"key_id"`
	ValidityDays int        `json:"validity_days"`
	Tags         []string   `json:"tags,omitempty"`
	AutoRenew    bool       `json:"auto_renew"`
	RenewalDays  int        `json:"renewal_days"`
	CAKeyID      string     `json:"ca_key_id,omitempty"`
	CACertID     string     `json:"ca_cert_id,omitempty"`
	Enabled      *bool      `json:"enabled,omitempty"`
	NotBefore    *time.Time `json:"not_before,omitempty"`
	Exportable   bool       `json:"exportable,omitempty"`
}

// CreateCertificate issues a certificate against an existing key.
func (c *Client) CreateCertificate(ctx context.Context, vault string, req CreateCertificateRequest) (*Certificate, error) {
	if vault == "" {
		return nil, fmt.Errorf("vaultapi: vault is required to create a certificate")
	}
	if req.Name == "" {
		return nil, fmt.Errorf("vaultapi: certificate name is required")
	}
	if req.KeyName == "" {
		return nil, fmt.Errorf("vaultapi: a key is required to create a certificate")
	}
	if req.ValidityDays <= 0 {
		return nil, fmt.Errorf("vaultapi: validity_days must be positive, got %d", req.ValidityDays)
	}

	// One resolver serves every lookup below, so a shared list is fetched once.
	resolver := c.Resolver()

	keyID, err := resolver.Resolve(ctx, vault, KindKeys, req.KeyName)
	if err != nil {
		return nil, err
	}

	body := createCertificateBody{
		Name:         req.Name,
		KeyID:        keyID.String(),
		ValidityDays: req.ValidityDays,
		Tags:         req.Tags,
		AutoRenew:    req.AutoRenew,
		RenewalDays:  req.RenewalDays,
		Enabled:      req.Enabled,
		NotBefore:    req.NotBefore,
		Exportable:   req.Exportable,
	}

	if req.CAKeyName != "" {
		caKeyID, err := resolver.Resolve(ctx, vault, KindKeys, req.CAKeyName)
		if err != nil {
			return nil, fmt.Errorf("vaultapi: resolving the CA key: %w", err)
		}
		body.CAKeyID = caKeyID.String()
	}
	if req.CACertName != "" {
		caCertID, err := resolver.Resolve(ctx, vault, KindCertificates, req.CACertName)
		if err != nil {
			return nil, fmt.Errorf("vaultapi: resolving the CA certificate: %w", err)
		}
		body.CACertID = caCertID.String()
	}

	var wire certificateWire
	path := fmt.Sprintf("/api/v1/vaults/%s/certificates", vault)
	if err := c.Do(ctx, http.MethodPost, path, body, &wire); err != nil {
		return nil, err
	}
	return certificateFromWire(wire)
}

// SetCertificatePolicyRequest is a complete issuance policy.
//
// Like the key rotation policy, the server's request type has no pointer
// fields (model/certificate_policy.go:30), so an upsert is a full
// replacement: omitting a value sets it to zero rather than leaving it alone.
// KeySize and Curve are omitempty on the wire because only one applies per
// key type.
type SetCertificatePolicyRequest struct {
	ValidityMonths   int    `json:"validity_months"`
	KeyType          string `json:"key_type"`
	KeySize          int    `json:"key_size,omitempty"`
	Curve            string `json:"curve,omitempty"`
	Subject          string `json:"subject"`
	SANs             string `json:"sans,omitempty"`
	AutoRenew        bool   `json:"auto_renew"`
	DaysBeforeExpiry int    `json:"days_before_expiry"`
	IssuerName       string `json:"issuer_name,omitempty"`
}

// UpsertCertificatePolicy replaces a certificate's issuance policy.
func (c *Client) UpsertCertificatePolicy(ctx context.Context, vault, name string, req SetCertificatePolicyRequest) (*CertificatePolicy, error) {
	if vault == "" {
		return nil, fmt.Errorf("vaultapi: vault is required to set a certificate policy")
	}
	if name == "" {
		return nil, fmt.Errorf("vaultapi: certificate name is required to set a policy")
	}

	id, err := c.Resolver().Resolve(ctx, vault, KindCertificates, name)
	if err != nil {
		return nil, err
	}

	var wire struct {
		CertificateID    string `json:"certificate_id"`
		ValidityMonths   int    `json:"validity_months"`
		KeyType          string `json:"key_type"`
		KeySize          int    `json:"key_size"`
		Curve            string `json:"curve"`
		Subject          string `json:"subject"`
		SANs             string `json:"sans"`
		AutoRenew        bool   `json:"auto_renew"`
		DaysBeforeExpiry int    `json:"days_before_expiry"`
		IssuerName       string `json:"issuer_name"`
	}

	path := fmt.Sprintf("/api/v1/vaults/%s/certificates/%s/policy", vault, id)
	if err := c.Do(ctx, http.MethodPut, path, req, &wire); err != nil {
		return nil, err
	}

	certID, parseErr := uuid.Parse(wire.CertificateID)
	if parseErr != nil {
		certID = id
	}
	return &CertificatePolicy{
		CertificateID:    certID,
		ValidityMonths:   wire.ValidityMonths,
		KeyType:          wire.KeyType,
		KeySize:          wire.KeySize,
		Curve:            wire.Curve,
		Subject:          wire.Subject,
		SANs:             wire.SANs,
		AutoRenew:        wire.AutoRenew,
		DaysBeforeExpiry: wire.DaysBeforeExpiry,
		IssuerName:       wire.IssuerName,
	}, nil
}

// renewCertificateBody is the renew route's optional body. A zero
// ValidityDays is omitted, which keeps the current validity period.
type renewCertificateBody struct {
	ValidityDays int `json:"validity_days,omitempty"`
}

// RenewCertificate issues a new version of a certificate and returns that
// version's metadata. validityDays of zero keeps the current period.
func (c *Client) RenewCertificate(ctx context.Context, vault, name string, validityDays int) (*CertificateVersion, error) {
	if vault == "" {
		return nil, fmt.Errorf("vaultapi: vault is required to renew a certificate")
	}
	if name == "" {
		return nil, fmt.Errorf("vaultapi: certificate name is required to renew a certificate")
	}
	if validityDays < 0 {
		return nil, fmt.Errorf("vaultapi: validity_days must not be negative, got %d", validityDays)
	}

	id, err := c.Resolver().Resolve(ctx, vault, KindCertificates, name)
	if err != nil {
		return nil, err
	}

	var version CertificateVersion
	path := fmt.Sprintf("/api/v1/vaults/%s/certificates/%s/renew", vault, id)
	if err := c.Do(ctx, http.MethodPost, path, renewCertificateBody{ValidityDays: validityDays}, &version); err != nil {
		return nil, err
	}
	return &version, nil
}
