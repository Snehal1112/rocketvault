package vaultapi

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/google/uuid"
)

// CertificateSummary is a certificate as it appears in a list.
//
// api.CertificateResponse carries metadata only, with no PEM and no chain, so
// nothing here needs a redacting type.
type CertificateSummary struct {
	ID        uuid.UUID  `json:"id"`
	Name      string     `json:"name"`
	Tags      []string   `json:"tags,omitempty"`
	Enabled   bool       `json:"enabled"`
	CreatedAt time.Time  `json:"created_at"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
	NotBefore *time.Time `json:"not_before,omitempty"`
	Version   int        `json:"version"`
}

// Certificate is a single certificate with its renewal settings.
type Certificate struct {
	CertificateSummary
	AutoRenew   bool `json:"auto_renew"`
	RenewalDays int  `json:"renewal_days"`
}

// certificateWire is the raw response shape (api/certificates.go:68).
type certificateWire struct {
	ID          string     `json:"id"`
	Name        string     `json:"name"`
	CreatedAt   time.Time  `json:"created_at"`
	Tags        []string   `json:"tags"`
	AutoRenew   bool       `json:"auto_renew"`
	RenewalDays int        `json:"renewal_days"`
	ExpiresAt   *time.Time `json:"expires_at"`
	Enabled     bool       `json:"enabled"`
	NotBefore   *time.Time `json:"not_before"`
	Version     int        `json:"version"`
}

type certificatesListResponse struct {
	Certificates []certificateWire `json:"certificates"`
}

func (w certificateWire) summary() (CertificateSummary, error) {
	id, err := uuid.Parse(w.ID)
	if err != nil {
		return CertificateSummary{}, fmt.Errorf("vaultapi: certificate %q has an unparseable id: %w", w.Name, err)
	}
	return CertificateSummary{
		ID:        id,
		Name:      w.Name,
		Tags:      w.Tags,
		Enabled:   w.Enabled,
		CreatedAt: w.CreatedAt,
		ExpiresAt: w.ExpiresAt,
		NotBefore: w.NotBefore,
		Version:   w.Version,
	}, nil
}

// ListCertificates returns the certificates in vault, capped at limit. The
// bool reports truncation. A limit of zero or less returns everything.
func (c *Client) ListCertificates(ctx context.Context, vault string, limit int) ([]CertificateSummary, bool, error) {
	if vault == "" {
		return nil, false, fmt.Errorf("vaultapi: vault is required to list certificates")
	}

	var response certificatesListResponse
	path := fmt.Sprintf("/api/v1/vaults/%s/certificates", vault)
	if err := c.Do(ctx, http.MethodGet, path, nil, &response); err != nil {
		return nil, false, err
	}

	truncated := limit > 0 && len(response.Certificates) > limit
	wires := response.Certificates
	if truncated {
		wires = wires[:limit]
	}

	summaries := make([]CertificateSummary, 0, len(wires))
	for _, wire := range wires {
		summary, err := wire.summary()
		if err != nil {
			return nil, false, err
		}
		summaries = append(summaries, summary)
	}
	return summaries, truncated, nil
}

// certificateFromWire converts a decoded response into a Certificate.
func certificateFromWire(wire certificateWire) (*Certificate, error) {
	summary, err := wire.summary()
	if err != nil {
		return nil, err
	}
	return &Certificate{
		CertificateSummary: summary,
		AutoRenew:          wire.AutoRenew,
		RenewalDays:        wire.RenewalDays,
	}, nil
}

// GetCertificate fetches one certificate by name or id.
func (c *Client) GetCertificate(ctx context.Context, vault, name string) (*Certificate, error) {
	if vault == "" {
		return nil, fmt.Errorf("vaultapi: vault is required to get a certificate")
	}

	id, err := c.Resolver().Resolve(ctx, vault, KindCertificates, name)
	if err != nil {
		return nil, err
	}

	var wire certificateWire
	path := fmt.Sprintf("/api/v1/vaults/%s/certificates/%s", vault, id)
	if err := c.Do(ctx, http.MethodGet, path, nil, &wire); err != nil {
		return nil, err
	}

	return certificateFromWire(wire)
}

// CertificatePolicy describes how a certificate is issued and renewed.
//
// model.CertificatePolicy also carries id and user_id, which are internal and
// mean nothing to an agent, so they are not surfaced.
//
// Subject and SANs are operator-supplied free text and therefore
// attacker-influenceable. This layer passes them through verbatim; wrapping
// them as untrusted content before they reach a model is the MCP layer's job.
type CertificatePolicy struct {
	CertificateID    uuid.UUID `json:"certificate_id"`
	ValidityMonths   int       `json:"validity_months"`
	KeyType          string    `json:"key_type"`
	KeySize          int       `json:"key_size,omitempty"`
	Curve            string    `json:"curve,omitempty"`
	Subject          string    `json:"subject"`
	SANs             string    `json:"sans,omitempty"`
	AutoRenew        bool      `json:"auto_renew"`
	DaysBeforeExpiry int       `json:"days_before_expiry"`
	IssuerName       string    `json:"issuer_name,omitempty"`
}

// GetCertificatePolicy returns a certificate's policy, or (nil, nil) when
// none is set. A denial is still an error, so absent and forbidden are never
// conflated.
func (c *Client) GetCertificatePolicy(ctx context.Context, vault, name string) (*CertificatePolicy, error) {
	if vault == "" {
		return nil, fmt.Errorf("vaultapi: vault is required to get a certificate policy")
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
	if err := c.Do(ctx, http.MethodGet, path, nil, &wire); err != nil {
		var apiErr *APIError
		if errors.As(err, &apiErr) && apiErr.Kind == KindNotFound {
			return nil, nil
		}
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

// CertificateVersion is one entry of a certificate's version history. Like
// the API type it mirrors, it has no field for a PEM or a private key.
type CertificateVersion struct {
	CertificateID uuid.UUID  `json:"certificate_id"`
	Version       int        `json:"version"`
	Current       bool       `json:"current"`
	Enabled       bool       `json:"enabled"`
	CreatedAt     time.Time  `json:"created_at"`
	ExpiresAt     *time.Time `json:"expires_at,omitempty"`
	NotBefore     *time.Time `json:"not_before,omitempty"`
}

type certificateVersionsResponse struct {
	Versions []CertificateVersion `json:"versions"`
}

// GetCertificateVersions returns a certificate's versions, oldest first,
// with the current one last.
func (c *Client) GetCertificateVersions(ctx context.Context, vault, name string) ([]CertificateVersion, error) {
	if vault == "" {
		return nil, fmt.Errorf("vaultapi: vault is required to list certificate versions")
	}
	id, err := c.Resolver().Resolve(ctx, vault, KindCertificates, name)
	if err != nil {
		return nil, err
	}

	var response certificateVersionsResponse
	path := fmt.Sprintf("/api/v1/vaults/%s/certificates/%s/versions", vault, id)
	if err := c.Do(ctx, http.MethodGet, path, nil, &response); err != nil {
		return nil, err
	}
	return response.Versions, nil
}
