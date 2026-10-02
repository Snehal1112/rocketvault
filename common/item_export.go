package common

import (
	"encoding/json"
	"errors"
	"fmt"
)

// ExportPassphraseEnvVar names the environment variable that supplies an
// export passphrase without a terminal. "secrets export" and "secrets
// import" read the same variable through their own constant.
const ExportPassphraseEnvVar = "ROCKETVAULT_EXPORT_PASSPHRASE"

// Item export kinds, as written into a sealed item export.
const (
	ItemExportKindCertificate = "certificate"
	ItemExportKindKey         = "key"
)

// itemExportPayloadVersion marks and versions a sealed item payload. Readers
// refuse a version they do not know rather than misparse it.
const itemExportPayloadVersion = 1

// ErrNotItemExport is returned when a sealed file opens but does not hold a
// certificate or key export, for example a sealed "secrets export" file.
var ErrNotItemExport = errors.New("not a RocketVault certificate or key export")

// ItemExportPayload is the plaintext a certificate or key export seals.
// Content is exactly the file the same export writes with --encrypt=false,
// so opening a sealed export yields that file byte for byte. It carries
// private material and must never be logged.
type ItemExportPayload struct {
	PayloadVersion int    `json:"rocketvault_item_export"`
	Kind           string `json:"kind"`
	ID             string `json:"id"`
	Name           string `json:"name"`
	Version        int    `json:"version"`
	Format         string `json:"format"`
	KeyAlgorithm   string `json:"key_algorithm"`
	Content        []byte `json:"content"`
}

// SealItemExport seals p under passphrase in the envelope SealExport writes.
// It sets the payload version itself.
func SealItemExport(p ItemExportPayload, passphrase string) ([]byte, error) {
	if p.Kind != ItemExportKindCertificate && p.Kind != ItemExportKindKey {
		return nil, fmt.Errorf("unknown item export kind %q", p.Kind)
	}
	p.PayloadVersion = itemExportPayloadVersion
	plain, err := json.Marshal(p)
	if err != nil {
		return nil, fmt.Errorf("failed to encode export payload: %w", err)
	}
	defer clear(plain)
	return SealExport(plain, passphrase)
}

// OpenItemExport reverses SealItemExport. A wrong passphrase returns
// ErrWrongPassphrase, and an envelope that holds anything other than a
// certificate or key export returns ErrNotItemExport.
func OpenItemExport(data []byte, passphrase string) (*ItemExportPayload, error) {
	plain, err := OpenExport(data, passphrase)
	if err != nil {
		return nil, err
	}
	defer clear(plain)

	var p ItemExportPayload
	if err := json.Unmarshal(plain, &p); err != nil {
		return nil, ErrNotItemExport
	}
	switch {
	case p.PayloadVersion == 0:
		return nil, ErrNotItemExport
	case p.PayloadVersion != itemExportPayloadVersion:
		return nil, fmt.Errorf("%w: item payload %d", ErrUnsupportedExportVersion, p.PayloadVersion)
	case p.Kind != ItemExportKindCertificate && p.Kind != ItemExportKindKey:
		return nil, ErrNotItemExport
	}
	return &p, nil
}
