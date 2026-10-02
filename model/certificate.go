package model

import (
	"encoding/json"
	"fmt"
	"io"
	"time"

	"github.com/google/uuid"
)

// Certificate represents an X.509 certificate in the password manager.
type Certificate struct {
	ID      uuid.UUID `json:"id"`
	UserID  uuid.UUID `json:"user_id"`
	VaultID uuid.UUID `json:"vault_id"`
	KeyID   uuid.UUID `json:"key_id" db:"key_id"`
	// CACertID names the certificate of the CA that signed this one. Nil means
	// the certificate is self-signed. It is set at creation and never changes,
	// so no update path writes it.
	CACertID         *uuid.UUID `json:"ca_cert_id,omitempty" db:"ca_cert_id"`
	Name             string     `json:"name"`
	Certificate      string     `json:"certificate"`
	PrivateKey       string     `json:"private_key"`
	CreatedAt        time.Time  `json:"created_at"`
	Tags             []string   `json:"tags"`
	DeletedAt        *time.Time `json:"deleted_at,omitempty"`
	PurgeProtection  bool       `json:"purge_protection"`
	ScheduledPurgeAt *time.Time `json:"scheduled_purge_at,omitempty"`
	ExpiresAt        *time.Time `json:"expires_at,omitempty"`
	AutoRenew        bool       `json:"auto_renew"`
	RenewalDays      int        `json:"renewal_days"`
	Enabled          bool       `json:"enabled"`
	NotBefore        *time.Time `json:"not_before,omitempty"`
	// Version is the number of the version this row holds. The row is
	// always the current version; earlier ones live in certificate_versions.
	// Zero is a row that predates versioning and reads as version 1, see
	// CurrentVersion.
	Version int `json:"version"`
	// Exportable reports whether the certificate's private key may ever be
	// exported. It is set at creation only and no update path writes it, so
	// it is immutable. A certificate's archived versions share this flag.
	Exportable bool `json:"exportable"`
}

// Clone returns a copy of c that shares no mutable state with the original:
// the struct itself, its tag slice, its CACertID pointer, and every time
// pointer are all independently copied. Used by internal/certcache so a
// caller that mutates a fetched certificate before persisting an update can
// never corrupt a cache entry or race a concurrent reader — same pattern as
// Secret.Clone.
func (c *Certificate) Clone() *Certificate {
	cp := *c
	if c.Tags != nil {
		cp.Tags = append([]string(nil), c.Tags...)
	}
	if c.CACertID != nil {
		id := *c.CACertID
		cp.CACertID = &id
	}
	cp.DeletedAt = cloneTimePtr(c.DeletedAt)
	cp.ScheduledPurgeAt = cloneTimePtr(c.ScheduledPurgeAt)
	cp.ExpiresAt = cloneTimePtr(c.ExpiresAt)
	cp.NotBefore = cloneTimePtr(c.NotBefore)
	return &cp
}

// IsAccessible returns true when the certificate is enabled and within its validity window.
func (c *Certificate) IsAccessible() bool {
	if !c.Enabled {
		return false
	}
	now := time.Now()
	if c.NotBefore != nil && now.Before(*c.NotBefore) {
		return false
	}
	if c.ExpiresAt != nil && now.After(*c.ExpiresAt) {
		return false
	}
	return true
}

// CurrentVersion returns the version number the certificate row holds. A
// zero Version, from a caller or a backup blob that predates versioning, is
// version 1: every certificate has at least one version.
func (c *Certificate) CurrentVersion() int {
	if c.Version < 1 {
		return 1
	}
	return c.Version
}

// VersionMetadata returns the current version's metadata, read off the
// certificate row itself.
func (c *Certificate) VersionMetadata() CertificateVersion {
	return CertificateVersion{
		CertificateID: c.ID,
		Version:       c.CurrentVersion(),
		Current:       true,
		CreatedAt:     c.CreatedAt,
		ExpiresAt:     cloneTimePtr(c.ExpiresAt),
		NotBefore:     cloneTimePtr(c.NotBefore),
		Enabled:       c.Enabled,
	}
}

// ArchiveRecord snapshots the current version, material included, so a
// renewal can move it into certificate_versions under its own number.
func (c *Certificate) ArchiveRecord() CertificateVersionRecord {
	return CertificateVersionRecord{
		CertificateID: c.ID,
		Version:       c.CurrentVersion(),
		Certificate:   c.Certificate,
		PrivateKey:    c.PrivateKey,
		KeyID:         c.KeyID,
		CreatedAt:     c.CreatedAt,
		ExpiresAt:     cloneTimePtr(c.ExpiresAt),
		NotBefore:     cloneTimePtr(c.NotBefore),
		Enabled:       c.Enabled,
	}
}

// VersionUsable reports whether version v of this certificate may be used.
// A disabled certificate gates every one of its versions; otherwise the
// version's own lifecycle decides.
func (c *Certificate) VersionUsable(v CertificateVersion) bool {
	return c.Enabled && v.IsAccessible()
}

// CertificateVersion is one version of a certificate. It is metadata only:
// there is deliberately no PEM and no private key field here, and none may
// be added, because the versions handlers encode it straight onto the
// response. CertificateVersionRecord carries the material, for backup only.
type CertificateVersion struct {
	CertificateID uuid.UUID  `json:"certificate_id"`
	Version       int        `json:"version"`
	Current       bool       `json:"current"`
	CreatedAt     time.Time  `json:"created_at"`
	ExpiresAt     *time.Time `json:"expires_at,omitempty"`
	NotBefore     *time.Time `json:"not_before,omitempty"`
	Enabled       bool       `json:"enabled"`
}

// IsAccessible reports whether the version is enabled and inside its own
// validity window.
func (v CertificateVersion) IsAccessible() bool {
	if !v.Enabled {
		return false
	}
	now := time.Now()
	if v.NotBefore != nil && now.Before(*v.NotBefore) {
		return false
	}
	if v.ExpiresAt != nil && now.After(*v.ExpiresAt) {
		return false
	}
	return true
}

// CertificateVersionRecord carries one archived version's material for
// internal use: the repository and the backup service. It is never encoded
// into an API response. PrivateKey holds the same master-key-encrypted form
// the database stores, so a backup blob carrying records is key material.
type CertificateVersionRecord struct {
	CertificateID uuid.UUID  `json:"certificate_id"`
	Version       int        `json:"version"`
	Certificate   string     `json:"certificate"`
	PrivateKey    string     `json:"private_key"`
	KeyID         uuid.UUID  `json:"key_id"`
	CreatedAt     time.Time  `json:"created_at"`
	ExpiresAt     *time.Time `json:"expires_at,omitempty"`
	NotBefore     *time.Time `json:"not_before,omitempty"`
	Enabled       bool       `json:"enabled"`
}

// Metadata returns the metadata of this archived version.
func (r CertificateVersionRecord) Metadata() CertificateVersion {
	return CertificateVersion{
		CertificateID: r.CertificateID,
		Version:       r.Version,
		Current:       false,
		CreatedAt:     r.CreatedAt,
		ExpiresAt:     cloneTimePtr(r.ExpiresAt),
		NotBefore:     cloneTimePtr(r.NotBefore),
		Enabled:       r.Enabled,
	}
}

// CertificateVersionAttributes are the lifecycle attributes every version
// carries and PUT .../versions/{version} may change.
type CertificateVersionAttributes struct {
	Enabled   bool
	ExpiresAt *time.Time
	NotBefore *time.Time
}

// ValidateCertificateVersionWindow rejects a not_before that falls after
// expires_at. Either may be unset.
func ValidateCertificateVersionWindow(notBefore, expiresAt *time.Time) error {
	if notBefore != nil && expiresAt != nil && notBefore.After(*expiresAt) {
		return fmt.Errorf("%w: not_before %s is after expires_at %s", ErrInvalidCertificateVersionAttributes,
			notBefore.Format(time.RFC3339), expiresAt.Format(time.RFC3339))
	}
	return nil
}

// RevokedCertificate represents a revoked certificate in the CRL.
type RevokedCertificate struct {
	ID           uuid.UUID
	UserID       uuid.UUID
	SerialNumber string
	Name         string
	RevokedAt    time.Time
}

// --- HTTP request/response types ---

type CreateCertificateRequest struct {
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
	// PurgeProtection is optional; nil leaves the stored default alone.
	PurgeProtection *bool `json:"purge_protection,omitempty"`
}

func CreateCertificateRequestFromJson(data io.Reader) (*CreateCertificateRequest, error) {
	var r CreateCertificateRequest
	return &r, json.NewDecoder(data).Decode(&r)
}

type UpdateCertificateRequest struct {
	Name        *string    `json:"name,omitempty"`
	Tags        []string   `json:"tags,omitempty"`
	AutoRenew   *bool      `json:"auto_renew,omitempty"`
	RenewalDays *int       `json:"renewal_days,omitempty"`
	Enabled     *bool      `json:"enabled,omitempty"`
	NotBefore   *time.Time `json:"not_before,omitempty"`
	// PurgeProtection is optional; nil means no change.
	PurgeProtection *bool `json:"purge_protection,omitempty"`
}

func UpdateCertificateRequestFromJson(data io.Reader) (*UpdateCertificateRequest, error) {
	var r UpdateCertificateRequest
	return &r, json.NewDecoder(data).Decode(&r)
}

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
}

func (r *CertificateResponse) ToJson() string {
	b, _ := json.Marshal(r)
	return string(b)
}

type CertificateListResponse struct {
	Certificates []CertificateResponse `json:"certificates"`
}

func (r *CertificateListResponse) ToJson() string {
	b, _ := json.Marshal(r)
	return string(b)
}
