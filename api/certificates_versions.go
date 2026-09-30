package api

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"time"

	"rocketvault/internal/container"
	certServices "rocketvault/internal/services/certificates"
	"rocketvault/model"
)

// UpdateCertificateVersionAPIRequest is the body for
// PUT /certificates/{certificate_id}/versions/{version}. Nil fields are left
// as they are; at least one is required.
type UpdateCertificateVersionAPIRequest struct {
	Enabled   *bool      `json:"enabled,omitempty"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
	NotBefore *time.Time `json:"not_before,omitempty"`
}

// RenewCertificateAPIRequest is the optional body for
// POST /certificates/{certificate_id}/renew. An omitted validity_days keeps
// the current version's validity period.
type RenewCertificateAPIRequest struct {
	ValidityDays *int `json:"validity_days,omitempty"`
}

// CertificateVersionListResponse is the body for GET .../versions. Every
// entry is metadata only; model.CertificateVersion has no material field.
type CertificateVersionListResponse struct {
	Versions []model.CertificateVersion `json:"versions"`
}

// listCertificateVersions returns a certificate's versions, oldest first,
// with the current one last.
func listCertificateVersions(c *Context, w http.ResponseWriter, r *http.Request) {
	certID, certOK := resourceID(c, c.Params.CertificateID, "certificate_id")
	if !certOK {
		return
	}
	certService, svcOK := svc(c, container.ServiceContainerInterface.GetCertificateService)
	if !svcOK {
		return
	}
	scope, ok := scopeFromRequest(c, r)
	if !ok {
		return
	}

	versions, err := certService.ListCertificateVersions(r.Context(), certID, scope)
	if err != nil {
		writeCertificateError(c, err)
		return
	}
	if versions == nil {
		versions = []model.CertificateVersion{}
	}
	writeJSON(w, CertificateVersionListResponse{Versions: versions})
}

// getCertificateVersion returns one version's metadata.
func getCertificateVersion(c *Context, w http.ResponseWriter, r *http.Request) {
	certID, certOK := resourceID(c, c.Params.CertificateID, "certificate_id")
	if !certOK {
		return
	}
	if c.Params.Version < 1 {
		c.SetInvalidParam("version")
		return
	}
	certService, svcOK := svc(c, container.ServiceContainerInterface.GetCertificateService)
	if !svcOK {
		return
	}
	scope, ok := scopeFromRequest(c, r)
	if !ok {
		return
	}

	version, err := certService.GetCertificateVersion(r.Context(), certID, c.Params.Version, scope)
	if err != nil {
		writeCertificateError(c, err)
		return
	}
	writeJSON(w, version)
}

// updateCertificateVersion changes one version's lifecycle attributes.
func updateCertificateVersion(c *Context, w http.ResponseWriter, r *http.Request) {
	certID, certOK := resourceID(c, c.Params.CertificateID, "certificate_id")
	if !certOK {
		return
	}
	if c.Params.Version < 1 {
		c.SetInvalidParam("version")
		return
	}
	req, bodyOK := decodeBody[UpdateCertificateVersionAPIRequest](c, r)
	if !bodyOK {
		return
	}
	if req.Enabled == nil && req.ExpiresAt == nil && req.NotBefore == nil {
		c.SetInvalidParam("at least one of enabled, expires_at or not_before must be provided")
		return
	}
	certService, svcOK := svc(c, container.ServiceContainerInterface.GetCertificateService)
	if !svcOK {
		return
	}
	scope, ok := scopeFromRequest(c, r)
	if !ok {
		return
	}

	updated, err := certService.UpdateCertificateVersion(r.Context(), certServices.UpdateCertificateVersionRequest{
		CertID:    certID,
		Version:   c.Params.Version,
		Scope:     scope,
		Enabled:   req.Enabled,
		ExpiresAt: req.ExpiresAt,
		NotBefore: req.NotBefore,
	})
	if err != nil {
		writeCertificateError(c, err)
		return
	}
	writeJSON(w, updated)
}

// decodeRenewBody decodes the optional renew body. An empty body is valid
// and means every default.
func decodeRenewBody(c *Context, r *http.Request) (RenewCertificateAPIRequest, bool) {
	var req RenewCertificateAPIRequest
	if r.Body == nil {
		return req, true
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil && !errors.Is(err, io.EOF) {
		c.SetInvalidParam("request body")
		return req, false
	}
	return req, true
}

// renewCertificate issues a new version of a certificate and returns that
// version's metadata. Authorization happens in PolicyMiddleware: renewing
// requires the certificates/create data action (data_actions.go).
func renewCertificate(c *Context, w http.ResponseWriter, r *http.Request) {
	certID, certOK := resourceID(c, c.Params.CertificateID, "certificate_id")
	if !certOK {
		return
	}
	req, bodyOK := decodeRenewBody(c, r)
	if !bodyOK {
		return
	}
	if req.ValidityDays != nil && *req.ValidityDays <= 0 {
		c.SetInvalidParam("validity_days: must be positive")
		return
	}
	certService, svcOK := svc(c, container.ServiceContainerInterface.GetCertificateService)
	if !svcOK {
		return
	}
	scope, ok := scopeFromRequest(c, r)
	if !ok {
		return
	}

	var validityDays int
	if req.ValidityDays != nil {
		validityDays = *req.ValidityDays
	} else {
		current, err := certService.GetCertificate(r.Context(), certID, scope)
		if err != nil {
			writeCertificateRenewError(c, err)
			return
		}
		validityDays = certServices.CurrentValidityDays(current)
	}

	result, err := certService.RenewCertificate(r.Context(), certID, scope, validityDays)
	if err != nil {
		writeCertificateRenewError(c, err)
		return
	}

	version, err := certService.GetCertificateVersion(r.Context(), certID, result.Version, scope)
	if err != nil {
		writeCertificateError(c, err)
		return
	}
	writeJSON(w, version)
}
