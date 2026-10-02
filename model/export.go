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
