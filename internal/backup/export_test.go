package backup

// Test-only aliases. This file is compiled only under `go test`, so these
// export nothing to production consumers.

type ExportedBlobVersions = blobVersions

var (
	ExportedEncodeBlob = encodeBlob
	ExportedDecodeBlob = decodeBlob
)

// ExportedSealedBlobPrefix is the sealed-format marker, for format tests.
const ExportedSealedBlobPrefix = sealedBlobPrefix

// ExportedSealBlob seals a hand-built inner envelope, so a test can restore
// an older or deliberately inconsistent inner shape through the real seal.
func (s *ItemBackupService) ExportedSealBlob(inner string) (string, error) {
	return s.sealBlob(inner)
}

// ExportedOpenBlob unseals a blob this service produced and returns its inner
// envelope, so a test can decode what a Backup method returned.
func (s *ItemBackupService) ExportedOpenBlob(blob string) (string, error) {
	return s.openBlob(blob)
}
