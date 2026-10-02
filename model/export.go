package model

import "errors"

// ErrExportableKeyRequired is returned when an exportable certificate is
// requested over a key whose exportable flag is false. A certificate keeps
// its own copy of the key, so allowing this would bypass the key's flag.
// The API maps it to 409.
var ErrExportableKeyRequired = errors.New("an exportable certificate requires a key whose exportable flag is true")

// ErrExportableNotSupported is returned when exportable is requested for a
// key that can never be exported: an HSM-backed key or a symmetric oct key.
// The API maps it to 400.
var ErrExportableNotSupported = errors.New("exportable is not supported for HSM-backed or oct keys")

// Export formats and PKCS12 compatibility modes accepted by the export routes.
const (
	ExportFormatPEM    = "pem"
	ExportFormatPKCS12 = "pkcs12"
	ExportCompatModern = "modern"
	ExportCompatLegacy = "legacy"
)

// ErrInvalidExportRequest is returned for a malformed export request: an
// unknown format or compat, pkcs12 without a password, or a negative
// version. Its wrapped message is safe to show: it never carries the
// password. The API maps it to 400 bad_request.
var ErrInvalidExportRequest = errors.New("invalid export request")

// ErrCertificateNotExportable is the sentinel behind every certificate
// export refusal. The API maps it to 403 certificate_not_exportable.
var ErrCertificateNotExportable = errors.New("certificate is not exportable")

// ErrKeyNotExportable is the sentinel behind every key export refusal. The
// API maps it to 403 key_not_exportable.
var ErrKeyNotExportable = errors.New("key is not exportable")

// ExportRefusedError explains why an item may not be exported. Reason is a
// fixed phrase chosen by the service, never derived from material. Name and
// KeyAlgorithm let a client and the audit trail show what was refused.
type ExportRefusedError struct {
	Sentinel     error
	Reason       string
	Name         string
	KeyAlgorithm string
}

// Error returns the sentinel's text followed by the reason.
func (e *ExportRefusedError) Error() string {
	return e.Sentinel.Error() + ": " + e.Reason
}

// Unwrap returns the sentinel, so errors.Is matches the refusal kind.
func (e *ExportRefusedError) Unwrap() error { return e.Sentinel }
