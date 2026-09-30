package repositories

import "rocketvault/model"

// ErrCertificateVersionNotFound and ErrCertificateVersionConflict alias the
// model sentinels, so api/ and cmd/ can check them without importing this
// package. Same pattern as ErrKeyVersionNotFound.
var (
	ErrCertificateVersionNotFound = model.ErrCertificateVersionNotFound
	ErrCertificateVersionConflict = model.ErrCertificateVersionConflict
)
