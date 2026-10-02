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

package api

import (
	"errors"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/mux"

	"rocketvault/internal/container"
	"rocketvault/internal/crypto"
	certServices "rocketvault/internal/services/certificates"
	vvalidation "rocketvault/internal/validation"
	"rocketvault/model"
)

// CreateCertificateAPIRequest is the HTTP request body for POST /certificates.
type CreateCertificateAPIRequest struct {
	Name         string     `json:"name"`                 // Certificate common name.
	KeyID        string     `json:"key_id"`               // UUID of the signing key.
	ValidityDays int        `json:"validity_days"`        // Certificate validity in days.
	Tags         []string   `json:"tags,omitempty"`       // Optional tags.
	AutoRenew    bool       `json:"auto_renew"`           // Schedule automatic renewal.
	RenewalDays  int        `json:"renewal_days"`         // Days before expiry to renew; defaults to 30.
	CAKeyID      string     `json:"ca_key_id,omitempty"`  // Unused; kept for future use.
	CACertID     string     `json:"ca_cert_id,omitempty"` // UUID of CA cert; triggers CA-signed path.
	IsCA         bool       `json:"is_ca,omitempty"`      // Issue as a Certificate Authority; defaults to false.
	Enabled      *bool      `json:"enabled,omitempty"`    // Defaults to true when omitted.
	NotBefore    *time.Time `json:"not_before,omitempty"` // Optional activation time.
	// PurgeProtection is optional; nil leaves the stored default alone.
	PurgeProtection *bool `json:"purge_protection,omitempty"`
	// Exportable requests an exportable certificate; immutable after creation.
	Exportable bool `json:"exportable,omitempty"`
}

// UpdateCertificateAPIRequest is the HTTP request body for PUT /certificates/{certificate_id}.
type UpdateCertificateAPIRequest struct {
	Name        *string    `json:"name,omitempty"`         // New name; nil means no change.
	Tags        []string   `json:"tags,omitempty"`         // Replace existing tags.
	AutoRenew   *bool      `json:"auto_renew,omitempty"`   // Enable or disable auto-renewal.
	RenewalDays *int       `json:"renewal_days,omitempty"` // Days before expiry to renew.
	Enabled     *bool      `json:"enabled,omitempty"`      // Enable or disable the certificate.
	NotBefore   *time.Time `json:"not_before,omitempty"`   // Activation timestamp.
	// PurgeProtection is optional; nil means no change.
	PurgeProtection *bool `json:"purge_protection,omitempty"`
}

// CertificateResponse is the JSON response for a single certificate.
type CertificateResponse struct {
	ID          uuid.UUID  `json:"id"`
	Name        string     `json:"name"`
	UserID      uuid.UUID  `json:"user_id"`
	CreatedAt   time.Time  `json:"created_at"`
	Tags        []string   `json:"tags"`
	AutoRenew   bool       `json:"auto_renew"`
	RenewalDays int        `json:"renewal_days"`
	ExpiresAt   *time.Time `json:"expires_at,omitempty"`
	Enabled     bool       `json:"enabled"`
	NotBefore   *time.Time `json:"not_before,omitempty"`
	Version     int        `json:"version"` // The current version number.

	Exportable   bool   `json:"exportable"`    // Whether the certificate can be exported. Immutable.
	KeyAlgorithm string `json:"key_algorithm"` // The leaf public key's algorithm, such as RSA-2048.
}

// CertificateListResponse is the JSON response for listing certificates.
type CertificateListResponse struct {
	Certificates []CertificateResponse `json:"certificates"`
}

// InitCertificates registers all certificate HTTP routes under the provided router.
// It sets up the following endpoints:
// - POST /certificates: Create a new certificate.
// - GET /certificates: List certificates for the authenticated user.
// - GET /certificates/{certificate_id}: Get a specific certificate by ID.
// - PUT /certificates/{certificate_id}: Update certificate metadata.
// - DELETE /certificates/{certificate_id}: Delete a certificate.
func (api *API) InitCertificates() {
	api.registerCertificateRoutes(api.BaseRoutes.Certificates, "legacy")
	if api.BaseRoutes.VaultScoped != nil {
		api.registerCertificateRoutes(api.BaseRoutes.VaultScoped.PathPrefix("/certificates").Subrouter(), "vault-scoped")
	}
}

// registerCertificateRoutes registers the certificate handlers on the provided
// subrouter. It is called for both the legacy flat routes and the vault-scoped
// routes; scope identifies which one, for the completion log line.
func (api *API) registerCertificateRoutes(c *mux.Router, scope string) {
	c.Handle("", ApiSessionRequired(api.App, createCertificate)).Methods("POST")
	c.Handle("", ApiSessionRequired(api.App, listCertificates)).Methods("GET")
	c.Handle("/{certificate_id:[A-Fa-f0-9-]+}", ApiSessionRequired(api.App, getCertificate)).Methods("GET")
	c.Handle("/{certificate_id:[A-Fa-f0-9-]+}", ApiSessionRequired(api.App, updateCertificate)).Methods("PUT")
	c.Handle("/{certificate_id:[A-Fa-f0-9-]+}", ApiSessionRequired(api.App, deleteCertificate)).Methods("DELETE")

	// Policy sub-resource: GET/PUT/DELETE /certificates/{certificate_id}/policy
	c.Handle("/{certificate_id:[A-Fa-f0-9-]+}/policy", ApiSessionRequired(api.App, getCertificatePolicy)).Methods("GET")
	c.Handle("/{certificate_id:[A-Fa-f0-9-]+}/policy", ApiSessionRequired(api.App, upsertCertificatePolicy)).Methods("PUT")
	c.Handle("/{certificate_id:[A-Fa-f0-9-]+}/policy", ApiSessionRequired(api.App, deleteCertificatePolicy)).Methods("DELETE")

	// Versions sub-resource and renewal. Renewal creates a new version.
	c.Handle("/{certificate_id:[A-Fa-f0-9-]+}/versions", ApiSessionRequired(api.App, listCertificateVersions)).Methods("GET")
	c.Handle("/{certificate_id:[A-Fa-f0-9-]+}/versions/{version:[0-9]+}", ApiSessionRequired(api.App, getCertificateVersion)).Methods("GET")
	c.Handle("/{certificate_id:[A-Fa-f0-9-]+}/versions/{version:[0-9]+}", ApiSessionRequired(api.App, updateCertificateVersion)).Methods("PUT")
	c.Handle("/{certificate_id:[A-Fa-f0-9-]+}/renew", ApiSessionRequired(api.App, renewCertificate)).Methods("POST")

	api.Logger.WithField("scope", scope).Infoln("Certificates API routes initialized")
}

// certToDomainResponse converts a model.Certificate to a CertificateResponse.
func certToDomainResponse(cert *model.Certificate) CertificateResponse {
	return CertificateResponse{
		ID:          cert.ID,
		Name:        cert.Name,
		UserID:      cert.UserID,
		CreatedAt:   cert.CreatedAt,
		Tags:        cert.Tags,
		AutoRenew:   cert.AutoRenew,
		RenewalDays: cert.RenewalDays,
		ExpiresAt:   cert.ExpiresAt,
		Enabled:     cert.Enabled,
		NotBefore:   cert.NotBefore,
		Version:     cert.CurrentVersion(),

		Exportable:   cert.Exportable,
		KeyAlgorithm: crypto.KeyAlgorithmFromCertificatePEM(cert.Certificate),
	}
}

// createCertificate creates a new X.509 certificate.
func createCertificate(c *Context, w http.ResponseWriter, r *http.Request) {
	// Authorization happens in PolicyMiddleware: creating a certificate requires
	// the Microsoft.KeyVault/vaults/certificates/create data action, granted by
	// Key Vault Certificates Officer or Key Vault Administrator in this vault.

	req, ok := decodeBody[CreateCertificateAPIRequest](c, r)
	if !ok {
		return
	}

	if req.Name == "" || req.KeyID == "" || req.ValidityDays <= 0 {
		c.SetInvalidParam("name, key_id, and validity_days are required")
		return
	}

	// Validate name format and tag limits.
	if err := vvalidation.ValidateCertificateCreate(vvalidation.CertificateCreateRequest{
		Name: req.Name,
		Tags: req.Tags,
	}); err != nil {
		c.SetInvalidParam(err.Error())
		return
	}

	keyID, err := uuid.Parse(req.KeyID)
	if err != nil {
		c.SetInvalidParam("key_id")
		return
	}

	userID, err := uuid.Parse(c.Claims.UserID)
	if err != nil {
		c.SetInvalidParam("user_id")
		return
	}

	// Resolve the target vault from the request context.
	vaultID, err := vaultIDFromRequest(r)
	if err != nil {
		c.SetInvalidParam("vault")
		return
	}

	certService, svcOK := svc(c, container.ServiceContainerInterface.GetCertificateService)
	if !svcOK {
		return
	}

	createReq := certServices.CreateCertificateRequest{
		Name:            req.Name,
		KeyID:           keyID,
		ValidityDays:    req.ValidityDays,
		Tags:            req.Tags,
		UserID:          userID,
		VaultID:         vaultID,
		AutoRenew:       req.AutoRenew,
		RenewalDays:     req.RenewalDays,
		IsCA:            req.IsCA,
		Enabled:         req.Enabled,
		NotBefore:       req.NotBefore,
		PurgeProtection: req.PurgeProtection,
		Exportable:      req.Exportable,
	}

	var result *certServices.CreateCertificateResult

	if req.CACertID != "" {
		// CA-signed certificate path.
		caCertID, parseErr := uuid.Parse(req.CACertID)
		if parseErr != nil {
			c.SetInvalidParam("ca_cert_id")
			return
		}
		createReq.CACertID = &caCertID
		result, err = certService.CreateCASignedCertificate(r.Context(), createReq)
	} else {
		result, err = certService.CreateSelfSignedCertificate(r.Context(), createReq)
	}

	if err != nil {
		if errors.Is(err, model.ErrExportableKeyRequired) {
			c.SetConflict("exportable: the key's exportable flag is false; an exportable certificate requires a key created with exportable: true")
			return
		}
		c.SetInternalError(err)
		return
	}

	// Resolve enabled value shown in the response.
	enabled := true
	if req.Enabled != nil {
		enabled = *req.Enabled
	}

	response := CertificateResponse{
		ID:          result.CertID,
		Version:     result.Version,
		Name:        result.Name,
		UserID:      userID,
		CreatedAt:   result.CreatedAt,
		Tags:        result.Tags,
		AutoRenew:   req.AutoRenew,
		RenewalDays: req.RenewalDays,
		ExpiresAt:   result.ExpiresAt,
		Enabled:     enabled,
		NotBefore:   req.NotBefore,

		Exportable:   result.Exportable,
		KeyAlgorithm: result.KeyAlgorithm,
	}

	writeJSONStatus(w, http.StatusCreated, response)
}

// listCertificates lists certificates. Legacy flat routes list the default
// vault; explicit vault-scoped routes list the vault named in the path. Both
// use vault-level "members see all" visibility.
func listCertificates(c *Context, w http.ResponseWriter, r *http.Request) {
	certService, svcOK := svc(c, container.ServiceContainerInterface.GetCertificateService)
	if !svcOK {
		return
	}

	scope, ok := scopeFromRequest(c, r)
	if !ok {
		return
	}

	certs, err := certService.ListCertificates(r.Context(), scope, model.CertificateFilter{
		Limit:  c.Params.PerPage,
		Offset: c.Params.Page * c.Params.PerPage,
	})
	if err != nil {
		c.SetInternalError(err)
		return
	}

	response := CertificateListResponse{Certificates: make([]CertificateResponse, len(certs))}
	for i := range certs {
		response.Certificates[i] = certToDomainResponse(&certs[i])
	}

	writeJSON(w, response)
}

// getCertificate retrieves a specific certificate by ID.
func getCertificate(c *Context, w http.ResponseWriter, r *http.Request) {
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

	cert, err := certService.GetCertificate(r.Context(), certID, scope)
	if err != nil {
		writeCertificateError(c, err)
		return
	}

	writeJSON(w, certToDomainResponse(cert))
}

// updateCertificate updates an existing certificate's metadata.
func updateCertificate(c *Context, w http.ResponseWriter, r *http.Request) {
	certID, certOK := resourceID(c, c.Params.CertificateID, "certificate_id")
	if !certOK {
		return
	}

	req, bodyOK := decodeBody[UpdateCertificateAPIRequest](c, r)
	if !bodyOK {
		return
	}

	if req.Name == nil && req.Tags == nil && req.AutoRenew == nil && req.RenewalDays == nil && req.Enabled == nil && req.NotBefore == nil && req.PurgeProtection == nil {
		c.SetInvalidParam("at least one update field must be provided")
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

	updateReq := certServices.UpdateCertificateRequest{
		CertID:          certID,
		Scope:           scope,
		Name:            req.Name,
		Tags:            req.Tags,
		AutoRenew:       req.AutoRenew,
		RenewalDays:     req.RenewalDays,
		Enabled:         req.Enabled,
		NotBefore:       req.NotBefore,
		PurgeProtection: req.PurgeProtection,
	}

	if err := certService.UpdateCertificate(r.Context(), updateReq); err != nil {
		writeCertificateError(c, err)
		return
	}

	// Fetch updated certificate for response. The read-back can legitimately
	// be lifecycle-denied — the update may have just disabled the certificate,
	// or it may already have expired — so map it like any other lifecycle
	// denial rather than reporting an internal error for a write that
	// succeeded.
	cert, err := certService.GetCertificate(r.Context(), certID, scope)
	if err != nil {
		writeCertificateError(c, err)
		return
	}

	writeJSON(w, certToDomainResponse(cert))
}

// deleteCertificate removes a certificate from the system.
func deleteCertificate(c *Context, w http.ResponseWriter, r *http.Request) {
	certID, certOK := resourceID(c, c.Params.CertificateID, "certificate_id")
	if !certOK {
		return
	}

	// Resolve the target vault from the request context.
	vaultID, err := vaultIDFromRequest(r)
	if err != nil {
		c.SetInvalidParam("vault")
		return
	}

	certService, svcOK := svc(c, container.ServiceContainerInterface.GetCertificateService)
	if !svcOK {
		return
	}

	// deleteCertificate builds its scope explicitly rather than calling
	// scopeFromRequest, like deleteSecret. Both now produce the same vault
	// scope, so this is belt-and-braces against route-shape branching being
	// reintroduced into the shared helper. The actor comes from the claims — a
	// uuid.Nil actor would attribute every certificate deletion to nobody in
	// the audit log.
	userID, ok := userIDFromClaims(c)
	if !ok {
		return
	}

	if err := certService.DeleteCertificate(r.Context(), certID, model.NewVaultScope(vaultID, userID)); err != nil {
		writeCertificateError(c, err)
		return
	}

	ReturnStatusOK(w)
}
