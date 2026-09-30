package model

import (
	"errors"
	"time"
)

// KeyFilter narrows a scoped key listing.
type KeyFilter struct {
	Type           string // Empty means every type. The keys table really has this column.
	Tags           []string
	IncludeDeleted bool
	OnlyDeleted    bool
	// Limit caps the number of rows returned; 0 means unlimited.
	Limit int
	// Offset skips this many matching rows before Limit is applied. Ignored
	// when Limit is 0.
	Offset int
}

// CertificateFilter narrows a scoped certificate listing. There is no Type
// field: the certificates table has no type column.
type CertificateFilter struct {
	Tags           []string
	IncludeDeleted bool
	OnlyDeleted    bool
	// Limit caps the number of rows returned; 0 means unlimited.
	Limit int
	// Offset skips this many matching rows before Limit is applied. Ignored
	// when Limit is 0.
	Offset int
}

// AuditFilter specifies query constraints for QueryAuditLogs.
// Nil pointer fields are ignored (not filtered).
type AuditFilter struct {
	From         *time.Time
	To           *time.Time
	UserID       *string
	Action       *string
	Outcome      *string
	ResourceType *string
	ResourceID   *string
	Source       *string
	Limit        int // 0 defaults to 100; max 1000
}

// ErrSecretPurgeProtected is returned when PurgeSecret refuses to act because
// the secret itself, or the vault containing it, has purge protection
// enabled.
var ErrSecretPurgeProtected = errors.New("secret has purge protection enabled (directly or via its vault)")

// ErrKeyPurgeProtected is returned when PurgeKey refuses to act because the
// key itself, or the vault containing it, has purge protection enabled.
var ErrKeyPurgeProtected = errors.New("key has purge protection enabled (directly or via its vault)")

// ErrCertPurgeProtected is returned when PurgeCertificate refuses to act
// because the certificate itself, or the vault containing it, has purge
// protection enabled.
var ErrCertPurgeProtected = errors.New("certificate has purge protection enabled (directly or via its vault)")

// ErrGlobalPurgeProtectionEnabled is returned when a purge operation (secret,
// key, certificate, or vault; manual or scheduled) refuses to act because the
// operator has enabled the instance-wide soft_delete.purge_protection safety
// switch. This is independent of any resource's own purge_protection flag —
// it blocks every purge regardless of per-item settings.
var ErrGlobalPurgeProtectionEnabled = errors.New("purge refused: soft_delete.purge_protection is enabled instance-wide")

// ErrKeyVersionNotFound is returned when a requested key version does not
// exist (or is not visible to the requesting owner). Propagates unwrapped to
// callers — same pattern as ErrKeyPurgeProtected above.
var ErrKeyVersionNotFound = errors.New("key version not found")

// ErrCertificateVersionNotFound is returned when a certificate has no
// version with the requested number, or the number is below 1.
var ErrCertificateVersionNotFound = errors.New("certificate version not found")

// ErrCertificateVersionConflict is returned when a renewal or a
// current-version update loses a race: the version it read is no longer the
// current one. The caller may re-read and retry.
var ErrCertificateVersionConflict = errors.New("certificate version changed concurrently")

// ErrInvalidCertificateVersionAttributes is returned when a version update
// carries no attribute, or sets not_before after expires_at.
var ErrInvalidCertificateVersionAttributes = errors.New("invalid certificate version attributes")
