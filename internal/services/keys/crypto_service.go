package keys

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"

	"rocketvault/common"
	"rocketvault/internal/crypto"
	"rocketvault/internal/keycache"
	"rocketvault/internal/logging"
	"rocketvault/internal/metrics"
	"rocketvault/internal/repositories"
	auditServices "rocketvault/internal/services/audit"
	"rocketvault/model"
)

// SignRequest represents a request to sign data.
type SignRequest struct {
	KeyID     uuid.UUID
	Data      []byte
	Algorithm crypto.SignatureAlgorithm
	UserID    uuid.UUID
	VaultID   uuid.UUID
	Scope     model.Scope
	Version   int // 0 = current
}

// SignResult represents the result of a sign operation.
type SignResult struct {
	Signature []byte
	Algorithm crypto.SignatureAlgorithm
	Digest    []byte
	KeyID     uuid.UUID
	Version   int // the version actually used
}

// VerifyRequest represents a request to verify a signature.
type VerifyRequest struct {
	KeyID     uuid.UUID
	Data      []byte
	Signature []byte
	Algorithm crypto.SignatureAlgorithm
	UserID    uuid.UUID
	VaultID   uuid.UUID
	Scope     model.Scope
	Version   int // 0 = current
}

// VerifyResult represents the result of a verify operation.
type VerifyResult struct {
	Valid     bool
	Algorithm crypto.SignatureAlgorithm
	KeyID     uuid.UUID
	Version   int // the version actually used
}

// EncryptRequest represents a request to encrypt data.
type EncryptRequest struct {
	KeyID     uuid.UUID
	Data      []byte
	Algorithm crypto.EncryptionAlgorithm
	UserID    uuid.UUID
	VaultID   uuid.UUID
	Scope     model.Scope
	Version   int // 0 = current
}

// EncryptResult represents the result of an encrypt operation.
type EncryptResult struct {
	Ciphertext []byte
	Algorithm  crypto.EncryptionAlgorithm
	Nonce      []byte
	KeyID      uuid.UUID
	Version    int // the version actually used
}

// DecryptRequest represents a request to decrypt data.
type DecryptRequest struct {
	KeyID      uuid.UUID
	Ciphertext []byte
	Nonce      []byte
	Algorithm  crypto.EncryptionAlgorithm
	UserID     uuid.UUID
	VaultID    uuid.UUID
	Scope      model.Scope
	Version    int // 0 = current
}

// DecryptResult represents the result of a decrypt operation.
type DecryptResult struct {
	Plaintext []byte
	Algorithm crypto.EncryptionAlgorithm
	KeyID     uuid.UUID
	Version   int // the version actually used
}

// WrapKeyRequest is a request to wrap key material with an RSA vault key.
type WrapKeyRequest struct {
	KeyID        uuid.UUID
	UserID       uuid.UUID
	VaultID      uuid.UUID
	Scope        model.Scope
	PlaintextKey []byte
	Algorithm    string // must be one of: RSA-OAEP, RSA-OAEP-256, A128KW, A192KW, A256KW, A128CBC, A192CBC, A256CBC
	Version      int    // 0 = current
}

// WrapKeyResult holds the wrapped key bytes.
type WrapKeyResult struct {
	WrappedKey []byte
	Algorithm  string
	Version    int // the version actually used
}

// UnwrapKeyRequest is a request to unwrap key material with an RSA vault key.
type UnwrapKeyRequest struct {
	KeyID      uuid.UUID
	UserID     uuid.UUID
	VaultID    uuid.UUID
	Scope      model.Scope
	WrappedKey []byte
	Algorithm  string // must be one of: RSA-OAEP, RSA-OAEP-256, A128KW, A192KW, A256KW, A128CBC, A192CBC, A256CBC
	Version    int    // 0 = current
}

// UnwrapKeyResult holds the recovered plaintext key bytes.
type UnwrapKeyResult struct {
	PlaintextKey []byte
	Algorithm    string
	Version      int // the version actually used
}

// CryptoService provides cryptographic operations using stored keys.
type CryptoService interface {
	Sign(ctx context.Context, req SignRequest) (*SignResult, error)
	Verify(ctx context.Context, req VerifyRequest) (*VerifyResult, error)
	Encrypt(ctx context.Context, req EncryptRequest) (*EncryptResult, error)
	Decrypt(ctx context.Context, req DecryptRequest) (*DecryptResult, error)
	WrapKey(ctx context.Context, req WrapKeyRequest) (*WrapKeyResult, error)
	UnwrapKey(ctx context.Context, req UnwrapKeyRequest) (*UnwrapKeyResult, error)
}

// cryptoService implements CryptoService.
type cryptoService struct {
	keyRepo       repositories.KeyRepositoryInterface
	cryptoOps     *crypto.CryptoOperations
	keyProvider   crypto.KeyProvider
	logger        *logging.Logger
	keyCache      keycache.Cache
	cryptoMetrics metrics.CryptoMetrics
	cfg           CryptoServiceConfig
}

// CryptoServiceConfig holds dependencies for crypto service.
type CryptoServiceConfig struct {
	KeyRepository repositories.KeyRepositoryInterface
	KeyProvider   crypto.KeyProvider
	Logger        *logging.Logger
	// KeyCache is optional; nil defaults to NopCache (no caching).
	KeyCache keycache.Cache
	// CryptoMetrics is optional; nil defaults to NopCryptoMetrics (no metrics).
	CryptoMetrics metrics.CryptoMetrics
	// AuditService writes the critical audit rows for wrap and unwrap. Nil
	// only in tests; the container always wires it.
	AuditService auditServices.AuditServiceInterface
}

// NewCryptoService creates a new crypto service.
func NewCryptoService(config CryptoServiceConfig) CryptoService {
	if config.KeyCache == nil {
		config.KeyCache = keycache.NewNopCache()
	}
	if config.CryptoMetrics == nil {
		config.CryptoMetrics = metrics.NewNopCryptoMetrics()
	}
	return &cryptoService{
		keyRepo:       config.KeyRepository,
		cryptoOps:     crypto.NewCryptoOperations(),
		keyProvider:   config.KeyProvider,
		logger:        config.Logger,
		keyCache:      config.KeyCache,
		cryptoMetrics: config.CryptoMetrics,
		cfg:           config,
	}
}

// runCritical runs op after a critical attempt row for action with key by
// the scope's actor, and records its result. The algorithm and version are
// recorded; the key material and payload never are.
func (s *cryptoService) runCritical(ctx context.Context, scope model.Scope, action string, key *model.Key, algorithm string, version int, op func(context.Context) error) error {
	ev := keyCriticalEvent(scope.ActorID(), action, key.ID, map[string]any{
		"vault_id": key.VaultID.String(), "algorithm": algorithm, "version": version,
	})
	return runKeyCritical(ctx, s.cfg.AuditService, ev, op)
}

const pkcs11Prefix = "pkcs11:"

// resolveKeyHandle decodes the stored key value into a plain handle string.
// For software keys, it AES-GCM decrypts the stored PEM. For PKCS#11 keys,
// it strips the "pkcs11:" prefix and returns the bare UUID label.
// The boolean return is true when the handle refers to a PKCS#11 key.
func resolveKeyHandle(storedValue string) (handle string, isPKCS11 bool, err error) {
	if strings.HasPrefix(storedValue, pkcs11Prefix) {
		return strings.TrimPrefix(storedValue, pkcs11Prefix), true, nil
	}
	decrypted, decErr := common.DecryptSecret(storedValue)
	if decErr != nil {
		return "", false, fmt.Errorf("failed to decrypt key: %w", decErr)
	}
	return decrypted, false, nil
}

// currentVersionNumber returns key's current version number: the highest
// key_versions row if any rotation has happened, else the implicit 1 (a
// never-rotated key's only material is keys.value). Matches RotateKey's own
// versioning math (key_service.go). This runs on every crypto operation, so
// it uses the repository's single-row aggregate query rather than fetching
// every version row just to read the last one.
func (s *cryptoService) currentVersionNumber(ctx context.Context, key *model.Key) (int, error) {
	return s.keyRepo.CurrentVersion(ctx, key.ID)
}

// resolveVersionValue resolves which material to use for a crypto
// operation. requested == 0 (or equal to the current version number)
// resolves to key.Value directly — no key_versions read. Otherwise fetches
// the archived version's material via ReadVersionValue.
func (s *cryptoService) resolveVersionValue(ctx context.Context, key *model.Key, requested int) (value string, resolvedVersion int, err error) {
	current, err := s.currentVersionNumber(ctx, key)
	if err != nil {
		return "", 0, err
	}
	if requested == 0 || requested == current {
		return key.Value, current, nil
	}
	value, err = s.keyRepo.ReadVersionValue(ctx, key.ID, requested)
	if err != nil {
		return "", 0, err
	}
	return value, requested, nil
}

// resolveKeyMaterial returns decrypted PEM key material from cache (hit) or
// via AES-GCM decrypt (miss), for the given value at the given version. For
// PKCS#11 keys the material is the raw token handle and caching is skipped
// entirely. On a cache hit, handle contains the decrypted PEM string stored
// earlier. The cache key is (key.ID, version) — using the real resolved
// version, not a hardcoded constant, is required for correctness once more
// than one version can be resolved per key: a hardcoded key would serve one
// version's material for a different version's request.
func (s *cryptoService) resolveKeyMaterial(key *model.Key, value string, version int) (
	handle string,
	isPKCS11 bool,
	cacheHit bool,
	err error,
) {
	// PKCS#11 keys store the token handle directly; never cache them.
	if strings.HasPrefix(value, pkcs11Prefix) {
		handle = strings.TrimPrefix(value, pkcs11Prefix)
		isPKCS11 = true
		return
	}

	// Check cache using keyID and the real resolved version.
	if entry, ok := s.keyCache.Get(key.ID, version); ok {
		if pemKey, ok := entry.PrivateKey.(keycache.PEMKey); ok {
			handle = string(pemKey.PEM)
			cacheHit = true
			return
		}
	}

	// Cache miss: AES-GCM decrypt the stored PEM.
	decrypted, decErr := common.DecryptSecret(value)
	if decErr != nil {
		err = fmt.Errorf("failed to decrypt key: %w", decErr)
		return
	}

	// Store decrypted PEM in cache for subsequent calls.
	s.keyCache.Set(key.ID, version, &keycache.Entry{
		PrivateKey: keycache.PEMKey{PEM: []byte(decrypted)},
		KeyType:    key.Type,
		Version:    version,
	})

	handle = decrypted
	return
}

// loadAndAuthorize fetches the key authorized by scope and enforces the
// remaining lifecycle rules for op. Authorization (vault membership or
// ownership) lives in the scope; revocation and the validity window do not.
//
// Deviation from the task brief: the not-found branch wraps the exported
// ErrKeyNotFound sentinel (fmt.Errorf("%w: %s", ErrKeyNotFound, err.Error()))
// rather than the brief's literal fmt.Errorf("key not found: %w", err).
// Read's own error (repositories.KeyRepository.Read) does not
// wrap any sentinel, so the brief's literal form leaves a cross-user key
// unmatched by every case in the six API handlers' error switches (they all
// test errors.Is against the exported Err* vars), falling through to the
// generic 500 branch. That is a real regression for what is fundamentally an
// authorization denial. Task 19's KeyRepository.Read and KeyService.DeleteKey
// already established this exact pattern for the identical class of problem, so this
// keeps loadAndAuthorize consistent with it: a cross-user key now reports 404
// via ErrKeyNotFound, same as the non-crypto scoped key paths. See
// TestCryptoService_Sign_RevokedKey and its siblings in
// internal/services/keys/key_service_extended_test.go, and
// TestCryptoOperationsUseVaultScope in api/vault_scoped_keys_certs_test.go,
// for the regression coverage this updates.
func (s *cryptoService) loadAndAuthorize(ctx context.Context, keyID uuid.UUID, scope model.Scope, op string) (*model.Key, error) {
	actor := scope.ActorID().String()

	key, err := s.keyRepo.Read(ctx, keyID, scope)
	if err != nil {
		s.logger.LogAuditError(actor, op, "failed", "Key not found", err)
		return nil, fmt.Errorf("%w: %s", ErrKeyNotFound, err.Error())
	}

	// B6 conjunction: retired from the vault-scoped route as of P2 -- callers
	// on that route now pass a genuine ScopeVault (see api/keys.go's six
	// crypto handlers), whose own predicate in KeyRepository.Read already
	// enforces vault membership, so this branch's ownerScoped condition is
	// false for them and it never runs.
	//
	// Dead in production today, kept deliberately: the B11 flat-route fix
	// (docs/superpowers/specs/2026-08-16-flat-route-vault-scope-fix-design.md)
	// changed scopeFromRequest (api/context.go) to always return a vault scope,
	// even for legacy flat routes, so no HTTP or CLI caller constructs an owner
	// scope for a key/crypto operation anymore. This branch only still fires
	// from tests that call the service directly with a hand-built owner
	// scope carrying a non-nil vault id (e.g. crypto_scope_test.go). It
	// stays as defense-in-depth for any future
	// direct caller of this exported method that reintroduces an owner scope.
	// DeleteKey/RotateKey (internal/services/keys/key_service.go) carry the
	// identical conjunction for the identical reason.
	if _, ownerScoped := scope.OwnerID(); ownerScoped && scope.VaultID() != uuid.Nil && key.VaultID != scope.VaultID() {
		s.logger.LogAuditError(actor, op, "forbidden",
			fmt.Sprintf("Unauthorized %s attempt: key %s not in vault %s", op, keyID, scope.VaultID()), nil)
		return nil, fmt.Errorf("%w: key does not belong to the requested vault", ErrKeyForbidden)
	}

	if key.Revoked {
		s.logger.LogAuditError(actor, op, "failed",
			fmt.Sprintf("Attempted to %s with revoked key: %s", op, keyID), nil)
		return nil, fmt.Errorf("%w: %s", ErrKeyRevoked, keyID)
	}

	if !key.IsAccessible() {
		s.logger.LogAuditError(actor, op, "failed",
			fmt.Sprintf("Attempted %s with inaccessible key: %s", op, keyID), nil)
		return nil, fmt.Errorf("%w", ErrKeyLifecycleDenied)
	}

	return key, nil
}

// wrapAlgorithmToEncryption maps a wrap/unwrap algorithm string to the internal
// crypto.EncryptionAlgorithm constant. Returns an error for unrecognised algorithms.
func wrapAlgorithmToEncryption(algorithm string) (crypto.EncryptionAlgorithm, error) {
	switch algorithm {
	case "RSA-OAEP-256":
		return crypto.AlgorithmRSAOAEP256, nil
	case "RSA-OAEP":
		return crypto.AlgorithmRSAOAEP, nil
	case "A128KW":
		return crypto.AlgorithmA128KW, nil
	case "A192KW":
		return crypto.AlgorithmA192KW, nil
	case "A256KW":
		return crypto.AlgorithmA256KW, nil
	case "A128CBC":
		return crypto.AlgorithmA128CBC, nil
	case "A192CBC":
		return crypto.AlgorithmA192CBC, nil
	case "A256CBC":
		return crypto.AlgorithmA256CBC, nil
	default:
		return "", fmt.Errorf("%w: %q", ErrUnsupportedAlgorithm, algorithm)
	}
}

// isHSMWrapAlgorithm reports whether algorithm can be used to wrap or unwrap
// with a PKCS#11-backed key. AES-CBC is deliberately excluded even though
// crypto.PKCS11KeyProvider does implement CKM_AES_CBC_PAD: the wrap/unwrap
// contract has no IV channel. WrapKeyResult and UnwrapKeyRequest (and their
// api.WrapKeyResponse/api.UnwrapKeyRequest counterparts) carry only the
// wrapped bytes and the algorithm name, so the IV the provider generates on
// wrap cannot be returned to the caller, and no IV can be supplied back on
// unwrap. AES-CBC on HSM-backed keys is reachable through Encrypt/Decrypt
// instead, which do round-trip the IV as EncryptResult.Nonce and
// DecryptRequest.Nonce.
func isHSMWrapAlgorithm(algorithm string) bool {
	switch algorithm {
	case "RSA-OAEP", "RSA-OAEP-256", "A128KW", "A192KW", "A256KW":
		return true
	default:
		return false
	}
}

// aesKWKeyBits returns the AES key size, in bits, required by an AES-KW wrap
// algorithm variant, or 0 if algorithm isn't an AES-KW variant (RSA-OAEP
// variants and AES-CBC have no such size relationship and should skip the
// check entirely).
func aesKWKeyBits(algorithm string) int {
	switch algorithm {
	case "A128KW":
		return 128
	case "A192KW":
		return 192
	case "A256KW":
		return 256
	default:
		return 0
	}
}

// Sign signs data using the specified key.
func (s *cryptoService) Sign(ctx context.Context, req SignRequest) (*SignResult, error) {
	start := time.Now()

	key, err := s.loadAndAuthorize(ctx, req.KeyID, req.Scope, "sign")
	if err != nil {
		return nil, err
	}

	value, resolvedVersion, err := s.resolveVersionValue(ctx, key, req.Version)
	if err != nil {
		s.logger.LogAuditError(req.UserID.String(), "sign", "failed", "Failed to resolve key version", err)
		return nil, err
	}
	handle, isPKCS11, cacheHit, err := s.resolveKeyMaterial(key, value, resolvedVersion)
	if err != nil {
		s.logger.LogAuditError(req.UserID.String(), "sign", "failed", "Failed to resolve key handle", err)
		return nil, err
	}
	defer func() {
		s.cryptoMetrics.RecordOp("sign", key.Type, cacheHit, time.Since(start))
	}()

	var signature, digest []byte
	if isPKCS11 {
		if s.keyProvider == nil {
			return nil, fmt.Errorf("no HSM key provider configured")
		}
		signature, err = s.keyProvider.Sign(ctx, handle, key.Type, req.Data, req.Algorithm)
		if err != nil {
			s.logger.LogAuditError(req.UserID.String(), "sign", "failed", "PKCS#11 signing failed", err)
			return nil, fmt.Errorf("signing failed: %w", err)
		}
	} else {
		signResult, signErr := s.cryptoOps.Sign(handle, key.Type, req.Data, req.Algorithm)
		if signErr != nil {
			s.logger.LogAuditError(req.UserID.String(), "sign", "failed", "Signing operation failed", signErr)
			return nil, fmt.Errorf("signing failed: %w", signErr)
		}
		signature = signResult.Signature
		digest = signResult.Digest
	}

	s.logger.LogAuditInfo(req.UserID.String(), "sign", "success",
		fmt.Sprintf("Data signed with key: %s (algorithm: %s)", req.KeyID, req.Algorithm))

	logrus.WithFields(logrus.Fields{
		"key_id":    req.KeyID,
		"key_type":  key.Type,
		"algorithm": req.Algorithm,
		"user_id":   req.UserID,
	}).Info("Data signed successfully")

	return &SignResult{
		Signature: signature,
		Algorithm: req.Algorithm,
		Digest:    digest,
		KeyID:     req.KeyID,
		Version:   resolvedVersion,
	}, nil
}

// Verify verifies a signature using the specified key.
func (s *cryptoService) Verify(ctx context.Context, req VerifyRequest) (*VerifyResult, error) {
	start := time.Now()

	key, err := s.loadAndAuthorize(ctx, req.KeyID, req.Scope, "verify")
	if err != nil {
		return nil, err
	}

	value, resolvedVersion, err := s.resolveVersionValue(ctx, key, req.Version)
	if err != nil {
		s.logger.LogAuditError(req.UserID.String(), "verify", "failed", "Failed to resolve key version", err)
		return nil, err
	}
	handle, isPKCS11, cacheHit, err := s.resolveKeyMaterial(key, value, resolvedVersion)
	if err != nil {
		s.logger.LogAuditError(req.UserID.String(), "verify", "failed", "Failed to resolve key handle", err)
		return nil, err
	}
	defer func() {
		s.cryptoMetrics.RecordOp("verify", key.Type, cacheHit, time.Since(start))
	}()

	var valid bool
	if isPKCS11 {
		valid, err = s.keyProvider.Verify(ctx, handle, key.Type, req.Data, req.Signature, req.Algorithm)
		if err != nil {
			s.logger.LogAuditError(req.UserID.String(), "verify", "failed", "PKCS#11 verification failed", err)
			return nil, fmt.Errorf("verification failed: %w", err)
		}
	} else {
		verifyResult, verifyErr := s.cryptoOps.Verify(handle, key.Type, req.Data, req.Signature, req.Algorithm)
		if verifyErr != nil {
			s.logger.LogAuditError(req.UserID.String(), "verify", "failed", "Verification operation failed", verifyErr)
			return nil, fmt.Errorf("verification failed: %w", verifyErr)
		}
		valid = verifyResult.Valid
	}

	status := "valid"
	if !valid {
		status = "invalid"
	}

	s.logger.LogAuditInfo(req.UserID.String(), "verify", status,
		fmt.Sprintf("Signature verification with key: %s (result: %s)", req.KeyID, status))

	logrus.WithFields(logrus.Fields{
		"key_id":    req.KeyID,
		"key_type":  key.Type,
		"algorithm": req.Algorithm,
		"valid":     valid,
		"user_id":   req.UserID,
	}).Info("Signature verified")

	return &VerifyResult{
		Valid:     valid,
		Algorithm: req.Algorithm,
		KeyID:     req.KeyID,
		Version:   resolvedVersion,
	}, nil
}

// Encrypt encrypts data using the specified key.
func (s *cryptoService) Encrypt(ctx context.Context, req EncryptRequest) (*EncryptResult, error) {
	start := time.Now()

	key, err := s.loadAndAuthorize(ctx, req.KeyID, req.Scope, "encrypt")
	if err != nil {
		return nil, err
	}

	value, resolvedVersion, err := s.resolveVersionValue(ctx, key, req.Version)
	if err != nil {
		s.logger.LogAuditError(req.UserID.String(), "encrypt", "failed", "Failed to resolve key version", err)
		return nil, err
	}
	handle, isPKCS11, cacheHit, err := s.resolveKeyMaterial(key, value, resolvedVersion)
	if err != nil {
		s.logger.LogAuditError(req.UserID.String(), "encrypt", "failed", "Failed to resolve key handle", err)
		return nil, err
	}
	defer func() {
		s.cryptoMetrics.RecordOp("encrypt", key.Type, cacheHit, time.Since(start))
	}()

	var ct, nonce []byte
	if isPKCS11 {
		ct, nonce, err = s.keyProvider.Encrypt(ctx, handle, req.Data, req.Algorithm)
		if err != nil {
			s.logger.LogAuditError(req.UserID.String(), "encrypt", "failed", "PKCS#11 encryption failed", err)
			return nil, fmt.Errorf("encryption failed: %w", err)
		}
	} else {
		encResult, encErr := s.cryptoOps.Encrypt(handle, req.Data, req.Algorithm)
		if encErr != nil {
			s.logger.LogAuditError(req.UserID.String(), "encrypt", "failed", "Encryption operation failed", encErr)
			return nil, fmt.Errorf("encryption failed: %w", encErr)
		}
		ct = encResult.Ciphertext
		nonce = encResult.Nonce
	}

	s.logger.LogAuditInfo(req.UserID.String(), "encrypt", "success",
		fmt.Sprintf("Data encrypted with key: %s (algorithm: %s)", req.KeyID, req.Algorithm))

	logrus.WithFields(logrus.Fields{
		"key_id":    req.KeyID,
		"key_type":  key.Type,
		"algorithm": req.Algorithm,
		"user_id":   req.UserID,
	}).Info("Data encrypted successfully")

	return &EncryptResult{
		Ciphertext: ct,
		Algorithm:  req.Algorithm,
		Nonce:      nonce,
		KeyID:      req.KeyID,
		Version:    resolvedVersion,
	}, nil
}

// Decrypt decrypts data using the specified key.
func (s *cryptoService) Decrypt(ctx context.Context, req DecryptRequest) (*DecryptResult, error) {
	start := time.Now()

	key, err := s.loadAndAuthorize(ctx, req.KeyID, req.Scope, "decrypt")
	if err != nil {
		return nil, err
	}

	value, resolvedVersion, err := s.resolveVersionValue(ctx, key, req.Version)
	if err != nil {
		s.logger.LogAuditError(req.UserID.String(), "decrypt", "failed", "Failed to resolve key version", err)
		return nil, err
	}
	handle, isPKCS11, cacheHit, err := s.resolveKeyMaterial(key, value, resolvedVersion)
	if err != nil {
		s.logger.LogAuditError(req.UserID.String(), "decrypt", "failed", "Failed to resolve key handle", err)
		return nil, err
	}
	defer func() {
		s.cryptoMetrics.RecordOp("decrypt", key.Type, cacheHit, time.Since(start))
	}()

	var plaintext []byte
	if isPKCS11 {
		plaintext, err = s.keyProvider.Decrypt(ctx, handle, req.Ciphertext, req.Nonce, req.Algorithm)
		if err != nil {
			s.logger.LogAuditError(req.UserID.String(), "decrypt", "failed", "PKCS#11 decryption failed", err)
			return nil, fmt.Errorf("decryption failed: %w", err)
		}
	} else {
		decResult, decErr := s.cryptoOps.Decrypt(handle, req.Ciphertext, req.Nonce, req.Algorithm)
		if decErr != nil {
			s.logger.LogAuditError(req.UserID.String(), "decrypt", "failed", "Decryption operation failed", decErr)
			return nil, fmt.Errorf("decryption failed: %w", decErr)
		}
		plaintext = decResult.Plaintext
	}

	s.logger.LogAuditInfo(req.UserID.String(), "decrypt", "success",
		fmt.Sprintf("Data decrypted with key: %s (algorithm: %s)", req.KeyID, req.Algorithm))

	logrus.WithFields(logrus.Fields{
		"key_id":    req.KeyID,
		"key_type":  key.Type,
		"algorithm": req.Algorithm,
		"user_id":   req.UserID,
	}).Info("Data decrypted successfully")

	return &DecryptResult{
		Plaintext: plaintext,
		Algorithm: req.Algorithm,
		KeyID:     req.KeyID,
		Version:   resolvedVersion,
	}, nil
}

// WrapKey encrypts plaintext key material using RSA-OAEP, RSA-OAEP-256, AES-KW,
// or AES-CBC with the specified vault key. HSM-backed keys support the
// RSA-OAEP and AES-KW variants only: AES-CBC needs an IV, and WrapKeyResult
// has no field to return one, so a CBC-wrapped blob could never be unwrapped.
// Use Encrypt/Decrypt for AES-CBC on an HSM-backed key — those do carry the IV.
func (s *cryptoService) WrapKey(ctx context.Context, req WrapKeyRequest) (*WrapKeyResult, error) {
	start := time.Now()

	validWrapAlgorithms := map[string]bool{
		"RSA-OAEP": true, "RSA-OAEP-256": true,
		"A128KW": true, "A192KW": true, "A256KW": true,
		"A128CBC": true, "A192CBC": true, "A256CBC": true,
	}
	if !validWrapAlgorithms[req.Algorithm] {
		return nil, fmt.Errorf("%w: %q", ErrUnsupportedAlgorithm, req.Algorithm)
	}

	key, err := s.loadAndAuthorize(ctx, req.KeyID, req.Scope, "wrap_key")
	if err != nil {
		return nil, err
	}

	value, resolvedVersion, err := s.resolveVersionValue(ctx, key, req.Version)
	if err != nil {
		s.logger.LogAuditError(req.UserID.String(), "wrap_key", "failed", "Failed to resolve key version", err)
		return nil, err
	}
	wrapHandle, wrapIsPKCS11, cacheHit, err := s.resolveKeyMaterial(key, value, resolvedVersion)
	if err != nil {
		s.logger.LogAuditError(req.UserID.String(), "wrap_key", "failed", "failed to resolve vault key handle", err)
		return nil, err
	}
	defer func() {
		s.cryptoMetrics.RecordOp("wrap_key", key.Type, cacheHit, time.Since(start))
	}()

	encAlgo, err := wrapAlgorithmToEncryption(req.Algorithm)
	if err != nil {
		return nil, err
	}

	// RSA-OAEP variants (via the RSA key pair) and AES-KW variants (via the AES
	// secret key) have HSM wrap paths. AES-CBC does not, because wrap has no IV
	// channel to return the provider-generated IV on — see isHSMWrapAlgorithm.
	if wrapIsPKCS11 && !isHSMWrapAlgorithm(req.Algorithm) {
		return nil, fmt.Errorf("algorithm %q is not supported for HSM-backed keys; use RSA-OAEP, RSA-OAEP-256, A128KW, A192KW, or A256KW", req.Algorithm)
	}
	if wrapIsPKCS11 {
		if expectedBits := aesKWKeyBits(req.Algorithm); expectedBits != 0 && key.Bits != expectedBits {
			return nil, fmt.Errorf("algorithm %q requires a %d-bit key, but key %s is %d-bit", req.Algorithm, expectedBits, req.KeyID, key.Bits)
		}
	}
	// Every gate has passed. The attempt row must be written before the key
	// is used; if it fails, nothing is wrapped or returned.
	var wrappedKey []byte
	err = s.runCritical(ctx, req.Scope, "wrap_key", key, req.Algorithm, resolvedVersion, func(ctx context.Context) error {
		var err error
		if wrapIsPKCS11 {
			wrappedKey, _, err = s.keyProvider.Encrypt(ctx, wrapHandle, req.PlaintextKey, encAlgo)
		} else {
			var result *crypto.EncryptResult
			result, err = s.cryptoOps.Encrypt(wrapHandle, req.PlaintextKey, encAlgo)
			if err == nil {
				wrappedKey = result.Ciphertext
			}
		}
		if err != nil {
			s.logger.LogAuditError(req.UserID.String(), "wrap_key", "failed", "wrap operation failed", err)
			return fmt.Errorf("wrap failed: %w", err)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	logLegacySuccess(s.cfg.AuditService, s.logger, req.UserID.String(), "wrap_key",
		fmt.Sprintf("key material wrapped with vault key %s", req.KeyID))
	return &WrapKeyResult{WrappedKey: wrappedKey, Algorithm: req.Algorithm, Version: resolvedVersion}, nil
}

// UnwrapKey decrypts wrapped key material using RSA-OAEP, RSA-OAEP-256, AES-KW,
// or AES-CBC with the specified vault key. HSM-backed keys support the
// RSA-OAEP and AES-KW variants only: AES-CBC needs an IV, and UnwrapKeyRequest
// has no field to supply one, so the PKCS#11 DecryptInit call would fail with
// CKR_ARGUMENTS_BAD. Use Encrypt/Decrypt for AES-CBC on an HSM-backed key —
// those do carry the IV.
func (s *cryptoService) UnwrapKey(ctx context.Context, req UnwrapKeyRequest) (*UnwrapKeyResult, error) {
	start := time.Now()

	validUnwrapAlgorithms := map[string]bool{
		"RSA-OAEP": true, "RSA-OAEP-256": true,
		"A128KW": true, "A192KW": true, "A256KW": true,
		"A128CBC": true, "A192CBC": true, "A256CBC": true,
	}
	if !validUnwrapAlgorithms[req.Algorithm] {
		return nil, fmt.Errorf("%w: %q", ErrUnsupportedAlgorithm, req.Algorithm)
	}

	key, err := s.loadAndAuthorize(ctx, req.KeyID, req.Scope, "unwrap_key")
	if err != nil {
		return nil, err
	}

	value, resolvedVersion, err := s.resolveVersionValue(ctx, key, req.Version)
	if err != nil {
		s.logger.LogAuditError(req.UserID.String(), "unwrap_key", "failed", "Failed to resolve key version", err)
		return nil, err
	}
	unwrapHandle, unwrapIsPKCS11, cacheHit, err := s.resolveKeyMaterial(key, value, resolvedVersion)
	if err != nil {
		s.logger.LogAuditError(req.UserID.String(), "unwrap_key", "failed", "failed to resolve vault key handle", err)
		return nil, err
	}
	defer func() {
		s.cryptoMetrics.RecordOp("unwrap_key", key.Type, cacheHit, time.Since(start))
	}()

	decAlgo, err := wrapAlgorithmToEncryption(req.Algorithm)
	if err != nil {
		return nil, err
	}

	// RSA-OAEP variants (via the RSA key pair) and AES-KW variants (via the AES
	// secret key) have HSM unwrap paths. AES-CBC does not, because unwrap has no
	// IV channel to accept the IV back on — see isHSMWrapAlgorithm.
	if unwrapIsPKCS11 && !isHSMWrapAlgorithm(req.Algorithm) {
		return nil, fmt.Errorf("algorithm %q is not supported for HSM-backed keys; use RSA-OAEP, RSA-OAEP-256, A128KW, A192KW, or A256KW", req.Algorithm)
	}
	if unwrapIsPKCS11 {
		if expectedBits := aesKWKeyBits(req.Algorithm); expectedBits != 0 && key.Bits != expectedBits {
			return nil, fmt.Errorf("algorithm %q requires a %d-bit key, but key %s is %d-bit", req.Algorithm, expectedBits, req.KeyID, key.Bits)
		}
	}
	// Every gate has passed. The attempt row must be written before the key
	// is used; if it fails, no plaintext key is recovered or returned.
	var plaintext []byte
	err = s.runCritical(ctx, req.Scope, "unwrap_key", key, req.Algorithm, resolvedVersion, func(ctx context.Context) error {
		var err error
		if unwrapIsPKCS11 {
			plaintext, err = s.keyProvider.Decrypt(ctx, unwrapHandle, req.WrappedKey, nil, decAlgo)
		} else {
			var result *crypto.DecryptResult
			result, err = s.cryptoOps.Decrypt(unwrapHandle, req.WrappedKey, nil, decAlgo)
			if err == nil {
				plaintext = result.Plaintext
			}
		}
		if err != nil {
			s.logger.LogAuditError(req.UserID.String(), "unwrap_key", "failed", "unwrap operation failed", err)
			return fmt.Errorf("unwrap failed: %w", err)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	logLegacySuccess(s.cfg.AuditService, s.logger, req.UserID.String(), "unwrap_key",
		fmt.Sprintf("key material unwrapped with vault key %s", req.KeyID))
	return &UnwrapKeyResult{PlaintextKey: plaintext, Algorithm: req.Algorithm, Version: resolvedVersion}, nil
}
