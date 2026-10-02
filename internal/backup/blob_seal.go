package backup

import (
	"crypto/hkdf"
	"crypto/sha256"
	"errors"
	"fmt"
	"strings"

	"rocketvault/common"
)

// sealedBlobPrefix marks a blob sealed under the item-backup key. It is also
// the format version: a blob without it predates sealing and is refused.
const sealedBlobPrefix = "rvb2."

// sealKeyInfo is the HKDF info string. It keeps the item-backup key distinct
// from the master key itself and from any other key derived from it.
const sealKeyInfo = "rocketvault item-backup blob seal v2"

// sealKeySize is the AES-256 key length in bytes.
const sealKeySize = 32

var (
	// ErrSealKeyUnset is returned when backup or restore runs before
	// SetSealKey. Both fail closed rather than fall back to the
	// unauthenticated format.
	ErrSealKeyUnset = errors.New("item backup seal key is not configured")

	// ErrUnsealedBlob marks a blob in the pre-sealing format. Such a blob was
	// either taken before the upgrade or written by hand, and the two cannot
	// be told apart, so both are refused.
	ErrUnsealedBlob = errors.New("blob is not sealed; take a new backup with this server")

	// ErrBlobAuthentication marks a sealed blob that failed its integrity
	// check: it was modified, or sealed under a different master key.
	ErrBlobAuthentication = errors.New("blob failed authentication")
)

// SetSealKey derives the blob-sealing key from the raw 32-byte master key.
// Every blob is then encrypted and authenticated, so restore accepts only
// blobs this server produced, unmodified (B76).
func (s *ItemBackupService) SetSealKey(masterKey []byte) error {
	if len(masterKey) != sealKeySize {
		return fmt.Errorf("item backup seal key: master key must be %d bytes, got %d", sealKeySize, len(masterKey))
	}
	key, err := hkdf.Key(sha256.New, masterKey, nil, sealKeyInfo, sealKeySize)
	if err != nil {
		return fmt.Errorf("item backup seal key: derive: %w", err)
	}
	s.sealKey = key
	return nil
}

// sealBlob encrypts and authenticates an encoded envelope with AES-256-GCM.
func (s *ItemBackupService) sealBlob(inner string) (string, error) {
	if s.sealKey == nil {
		return "", ErrSealKeyUnset
	}
	sealed, err := common.EncryptWithKey(inner, s.sealKey)
	if err != nil {
		return "", fmt.Errorf("seal backup blob: %w", err)
	}
	return sealedBlobPrefix + sealed, nil
}

// openBlob reverses sealBlob. Both refusals wrap ErrInvalidBlob, so the HTTP
// handlers report them as a bad parameter rather than a server fault. The
// underlying decrypt error is dropped on purpose, so no part of the blob or
// the key ever reaches the caller.
func (s *ItemBackupService) openBlob(blob string) (string, error) {
	if s.sealKey == nil {
		return "", ErrSealKeyUnset
	}
	body, ok := strings.CutPrefix(blob, sealedBlobPrefix)
	if !ok {
		return "", fmt.Errorf("%w: %w", ErrInvalidBlob, ErrUnsealedBlob)
	}
	inner, err := common.DecryptWithKey(body, s.sealKey)
	if err != nil {
		return "", fmt.Errorf("%w: %w", ErrInvalidBlob, ErrBlobAuthentication)
	}
	return inner, nil
}
