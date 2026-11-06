package signing

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"

	"rocketvault/internal/repositories"
	auditServices "rocketvault/internal/services/audit"
	secretServices "rocketvault/internal/services/secrets"
	"rocketvault/model"
)

const (
	jwtSigningKeyName      = "_jwt_signing"
	selfPKIAlgorithm       = "ES256"
	defaultRotationOverlap = time.Hour
)

// SelfPKIProvider stores the JWT signing key in RocketVault's own encrypted key store.
// It uses ECDSA P-256 (ES256) and supports runtime rotation via Rotate().
type SelfPKIProvider struct {
	mu         sync.RWMutex
	crypto     secretServices.CryptographyService
	keyRepo    repositories.KeyRepositoryInterface
	overlapDur time.Duration
	// audit writes the critical row for a generated key. Nil only in tests;
	// the container always wires it.
	audit auditServices.AuditServiceInterface

	activeKey   *ecdsa.PrivateKey
	activeKID   string
	activeKeyID uuid.UUID

	previousKey  *ecdsa.PrivateKey
	previousKID  string
	overlapUntil time.Time
}

// NewSelfPKIProvider looks up or generates the JWT signing key in the key
// store. audit writes the critical row for a generated key; nil skips it and
// is meant for tests.
func NewSelfPKIProvider(
	cryptoSvc secretServices.CryptographyService,
	keyRepo repositories.KeyRepositoryInterface,
	overlapStr string,
	audit auditServices.AuditServiceInterface,
) (*SelfPKIProvider, error) {
	overlap := defaultRotationOverlap
	if overlapStr != "" {
		if d, err := time.ParseDuration(overlapStr); err == nil {
			overlap = d
		}
	}

	p := &SelfPKIProvider{
		crypto:     cryptoSvc,
		keyRepo:    keyRepo,
		overlapDur: overlap,
		audit:      audit,
	}

	if err := p.loadOrGenerate(context.Background()); err != nil {
		return nil, fmt.Errorf("SelfPKIProvider init: %w", err)
	}
	return p, nil
}

func (p *SelfPKIProvider) PrivateKey() crypto.Signer {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.activeKey
}

func (p *SelfPKIProvider) Algorithm() string { return selfPKIAlgorithm }

func (p *SelfPKIProvider) KeyID() string {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.activeKID
}

// PublicKeys returns the active key and, during the rotation overlap window, the previous key.
func (p *SelfPKIProvider) PublicKeys() []PublicKeyInfo {
	p.mu.RLock()
	defer p.mu.RUnlock()

	keys := []PublicKeyInfo{{
		KeyID:     p.activeKID,
		Algorithm: selfPKIAlgorithm,
		PublicKey: p.activeKey.Public(),
	}}

	if p.previousKey != nil && time.Now().Before(p.overlapUntil) {
		keys = append(keys, PublicKeyInfo{
			KeyID:     p.previousKID,
			Algorithm: selfPKIAlgorithm,
			PublicKey: p.previousKey.Public(),
		})
	}
	return keys
}

// Rotate generates a new signing key, promotes it to active, and retains the previous key
// in PublicKeys() for the configured rotation_overlap window. Implements RotatableProvider.
func (p *SelfPKIProvider) Rotate() (newKID string, overlapUntil string, err error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	newKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", "", fmt.Errorf("generate ECDSA key: %w", err)
	}
	newKIDStr := thumbprint(newKey.Public())

	pemStr, err := ecdsaKeyToPEM(newKey)
	if err != nil {
		return "", "", err
	}
	encrypted, err := p.crypto.EncryptSecret(pemStr)
	if err != nil {
		return "", "", fmt.Errorf("encrypt new key: %w", err)
	}

	keyRecord := &model.Key{
		ID:        uuid.New(),
		UserID:    uuid.Nil,
		Name:      jwtSigningKeyName + "_" + newKIDStr,
		Type:      model.KeyTypeECDSA,
		Value:     encrypted,
		CreatedAt: time.Now(),
	}
	if err := p.keyRepo.Create(context.Background(), keyRecord); err != nil {
		return "", "", fmt.Errorf("store new key: %w", err)
	}

	p.previousKey = p.activeKey
	p.previousKID = p.activeKID
	p.overlapUntil = time.Now().Add(p.overlapDur)

	p.activeKey = newKey
	p.activeKID = newKIDStr
	p.activeKeyID = keyRecord.ID

	logrus.WithFields(logrus.Fields{
		"new_kid":       newKIDStr,
		"overlap_until": p.overlapUntil.Format(time.RFC3339),
	}).Info("SelfPKIProvider: key rotated")

	return newKIDStr, p.overlapUntil.Format(time.RFC3339), nil
}

// loadOrGenerate finds the most recently stored _jwt_signing key or generates one.
func (p *SelfPKIProvider) loadOrGenerate(ctx context.Context) error {
	keys, err := p.keyRepo.List(ctx, model.NewAdminScope(uuid.Nil), repositories.KeyFilter{Type: model.KeyTypeECDSA})
	if err != nil {
		return fmt.Errorf("list keys: %w", err)
	}

	for i := len(keys) - 1; i >= 0; i-- {
		k := keys[i]
		if k.DeletedAt != nil {
			continue
		}
		nameLen := len(jwtSigningKeyName)
		if len(k.Name) < nameLen || k.Name[:nameLen] != jwtSigningKeyName {
			continue
		}

		decrypted, err := p.crypto.DecryptSecret(k.Value)
		if err != nil {
			logrus.WithError(err).Warn("SelfPKIProvider: could not decrypt stored key, regenerating")
			break
		}
		ecKey, err := parseECDSAPEM(decrypted)
		if err != nil {
			logrus.WithError(err).Warn("SelfPKIProvider: could not parse stored key, regenerating")
			break
		}
		p.activeKey = ecKey
		p.activeKID = thumbprint(ecKey.Public())
		p.activeKeyID = k.ID
		logrus.WithField("kid", p.activeKID).Info("SelfPKIProvider: loaded existing JWT signing key")
		return nil
	}

	return p.generateAndStore(ctx)
}

func (p *SelfPKIProvider) generateAndStore(ctx context.Context) error {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("generate ECDSA key: %w", err)
	}
	kid := thumbprint(key.Public())

	pemStr, err := ecdsaKeyToPEM(key)
	if err != nil {
		return err
	}
	encrypted, err := p.crypto.EncryptSecret(pemStr)
	if err != nil {
		return fmt.Errorf("encrypt key: %w", err)
	}

	keyRecord := &model.Key{
		ID:        uuid.New(),
		UserID:    uuid.Nil,
		Name:      jwtSigningKeyName,
		Type:      model.KeyTypeECDSA,
		Value:     encrypted,
		CreatedAt: time.Now(),
	}
	store := func(ctx context.Context) error {
		if err := p.keyRepo.Create(ctx, keyRecord); err != nil {
			return fmt.Errorf("store generated key: %w", err)
		}
		return nil
	}
	if p.audit != nil {
		// The attempt row must be written before the key is stored. A failed
		// write returns audit.ErrAuditUnavailable and startup fails rather
		// than sign with an unaudited key.
		err = auditServices.WithCritical(ctx, p.audit, auditServices.AuditEvent{
			UserID: "system", Action: "signing_key_generate",
			Details:      fmt.Sprintf(`{"key_id":%q,"algorithm":%q}`, keyRecord.ID.String(), selfPKIAlgorithm),
			ResourceType: "signing_key", ResourceID: kid, Source: "system",
		}, store)
	} else {
		err = store(ctx)
	}
	if err != nil {
		return err
	}

	p.activeKey = key
	p.activeKID = kid
	p.activeKeyID = keyRecord.ID
	logrus.WithField("kid", kid).Info("SelfPKIProvider: generated and stored new JWT signing key")
	return nil
}

func ecdsaKeyToPEM(key *ecdsa.PrivateKey) (string, error) {
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return "", fmt.Errorf("marshal ECDSA key: %w", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})), nil
}

func parseECDSAPEM(pemStr string) (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return nil, fmt.Errorf("no PEM block found")
	}
	return x509.ParseECPrivateKey(block.Bytes)
}
