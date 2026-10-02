package backup

import (
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/google/uuid"

	"rocketvault/internal/db"
	"rocketvault/internal/repositories"
	"rocketvault/model"
)

// ErrInvalidBlob is returned when the backup blob cannot be decoded.
var ErrInvalidBlob = errors.New("invalid backup blob")

// TxBeginner begins a transaction usable by the Tx-scoped repository
// methods. Satisfied by *db.Conn. Injected via SetTxBeginner so unit tests
// that construct an ItemBackupService without a real database (every
// existing test in this package, until F3's atomicity tests) keep
// exercising the pre-existing non-transactional path.
type TxBeginner interface {
	BeginTx(ctx context.Context, opts *sql.TxOptions) (*db.Tx, error)
}

// txCapableSecretRepo is implemented by SecretRepositoryInterface's concrete
// type when it also supports the Tx-scoped restore path (F3). The Tx-scoped
// methods live only on the concrete *repositories.SecretRepository, not on
// the exported interface, so adding them doesn't ripple to every test
// double implementing that interface — mirrors vault_service.go's
// txCapableVaultRepo.
type txCapableSecretRepo interface {
	CreateTx(ctx context.Context, ex db.DBTX, secret *model.Secret) error
	SetPurgeProtectionTx(ctx context.Context, ex db.DBTX, id uuid.UUID, enabled bool) error
}

// txCapableSecretVersionRepo is SecretVersionRepositoryInterface's Tx-scoped
// counterpart. See txCapableSecretRepo.
type txCapableSecretVersionRepo interface {
	CreateVersionTx(ctx context.Context, ex db.DBTX, version *model.SecretVersion) error
}

// txCapableKeyRepo is KeyRepositoryInterface's Tx-scoped counterpart. See
// txCapableSecretRepo.
type txCapableKeyRepo interface {
	CreateTx(ctx context.Context, ex db.DBTX, key *model.Key) error
	CreateVersionTx(ctx context.Context, ex db.DBTX, keyID uuid.UUID, version int, value string) error
	SetPurgeProtectionTx(ctx context.Context, ex db.DBTX, id uuid.UUID, enabled bool) error
}

// txCapableCertRepo is CertificateRepositoryInterface's Tx-scoped
// counterpart. See txCapableSecretRepo.
type txCapableCertRepo interface {
	CreateTx(ctx context.Context, ex db.DBTX, cert *model.Certificate) error
	SetPurgeProtectionTx(ctx context.Context, ex db.DBTX, id uuid.UUID, enabled bool) error
}

// txCapableCertVersionRepo is CertificateVersionRepositoryInterface's
// Tx-scoped counterpart. See txCapableSecretRepo.
type txCapableCertVersionRepo interface {
	CreateVersionTx(ctx context.Context, ex db.DBTX, rec *model.CertificateVersionRecord) error
}

// ItemBackupService provides per-item backup and restore for secrets, keys,
// and certificates. Each backup is a base64url-encoded JSON envelope that is
// opaque to the caller.
type ItemBackupService struct {
	secretRepo      repositories.SecretRepositoryInterface
	keyRepo         repositories.KeyRepositoryInterface
	certRepo        repositories.CertificateRepositoryInterface
	versionRepo     repositories.SecretVersionRepositoryInterface
	certVersionRepo repositories.CertificateVersionRepositoryInterface
	txBeginner      TxBeginner
}

// NewItemBackupService creates an ItemBackupService wired to the given repos.
// Any repo may be nil if that resource type is not required by the caller.
func NewItemBackupService(
	secretRepo repositories.SecretRepositoryInterface,
	keyRepo repositories.KeyRepositoryInterface,
	certRepo repositories.CertificateRepositoryInterface,
	versionRepo repositories.SecretVersionRepositoryInterface,
) *ItemBackupService {
	return &ItemBackupService{
		secretRepo:  secretRepo,
		keyRepo:     keyRepo,
		certRepo:    certRepo,
		versionRepo: versionRepo,
	}
}

// SetTxBeginner attaches an optional transaction beginner. When set (and the
// injected repos support the Tx-scoped methods — always true for the real
// repositories, never for a test double that only implements the exported
// interfaces), RestoreSecret/RestoreKey/RestoreCertificate run their whole
// restore atomically inside one transaction (F3): a failure partway rolls
// back everything already written, rather than leaving a partial row under
// an ID the caller never received. When unset, they run the pre-existing
// non-transactional sequence.
func (s *ItemBackupService) SetTxBeginner(tb TxBeginner) { s.txBeginner = tb }

// SetCertificateVersionRepository attaches the certificate version store.
// Without it, BackupCertificate refuses a certificate that has history and
// RestoreCertificate refuses a blob that carries history, rather than
// silently dropping either.
func (s *ItemBackupService) SetCertificateVersionRepository(repo repositories.CertificateVersionRepositoryInterface) {
	s.certVersionRepo = repo
}

// withTx runs fn inside a transaction begun via txBeginner, committing on
// success and rolling back on error. Mirrors vault_service.go's withTx.
func (s *ItemBackupService) withTx(ctx context.Context, fn func(tx *db.Tx) error) error {
	tx, err := s.txBeginner.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin transaction: %w", err)
	}
	if err := fn(tx); err != nil {
		if rbErr := tx.Rollback(); rbErr != nil {
			return fmt.Errorf("rollback failed: %w (original: %v)", rbErr, err)
		}
		return err
	}
	return tx.Commit()
}

// blobVersions carries whatever version history a resource type has. Every
// field is optional: a key blob populates Key, a secret blob Secret, and a
// certificate blob Certificate.
type blobVersions struct {
	Key         []model.KeyVersionRecord
	Secret      []model.SecretVersion
	Certificate []model.CertificateVersionRecord
}

// backupEnvelope is the internal structure stored inside the opaque blob.
//
// Every version field is omitempty and additive: a blob written before a
// given field existed simply decodes it as nil. That is what lets pre-2026-08
// key blobs, pre-2026-08-20 secret blobs and pre-2026-10-01 certificate blobs
// still restore. Never rename or retype an existing field here, it is a wire
// format.
type backupEnvelope struct {
	ResourceType        string                           `json:"resource_type"`
	ResourceID          string                           `json:"resource_id"`
	Data                json.RawMessage                  `json:"data"`
	Versions            []model.KeyVersionRecord         `json:"versions,omitempty"`             // keys only
	SecretVersions      []model.SecretVersion            `json:"secret_versions,omitempty"`      // secrets only
	CertificateVersions []model.CertificateVersionRecord `json:"certificate_versions,omitempty"` // certificates only
}

// BackupSecret creates a base64url-encoded backup blob for the given secret.
//
// vaultID is the vault the caller's request was authorized against. See
// BackupKey for why the scoped read replaces the previous unscoped read plus
// ownership comparison.
func (s *ItemBackupService) BackupSecret(ctx context.Context, id, userID, vaultID uuid.UUID) (string, error) {
	secret, err := s.secretRepo.Read(ctx, id, model.NewVaultScope(vaultID, userID))
	if err != nil {
		return "", fmt.Errorf("backup secret: %w", err)
	}

	// Version rows are fetched by secret ID; the scoped read above is their
	// authorization. Without these the blob would restore a single version
	// and silently discard the rest — the same loss B26 closed for keys.
	versions, err := s.versionRepo.GetVersions(ctx, id)
	if err != nil {
		return "", fmt.Errorf("backup secret: list versions: %w", err)
	}
	return encodeBlob("secret", id.String(), secret, blobVersions{Secret: versions})
}

// RestoreSecret decodes blob and re-inserts it as newID, owned by userID,
// into vaultID — the vault authorized by the caller's request, never the
// vault embedded in the blob. Trusting the blob's vault_id would let a
// caller with restore permission in one vault silently write into any vault
// a blob happens to reference.
//
// Archived versions in the blob are replayed under newID. Each gets a fresh
// primary key: secret_versions.id is a PRIMARY KEY, and the source secret
// usually still exists, so reusing the blob's IDs would collide.
func (s *ItemBackupService) RestoreSecret(ctx context.Context, blob string, userID, vaultID, newID uuid.UUID) error {
	var secret model.Secret
	versions, err := decodeBlob(blob, "secret", &secret)
	if err != nil {
		return err
	}
	secret.ID = newID
	secret.UserID = userID
	secret.VaultID = vaultID

	// The write order below (versions before purge protection) matters
	// regardless of which path runs: it is what keeps a NON-transactional
	// partial restore purgeable rather than a stranded protected orphan.
	// See the comment inside restoreSecretWith for the full reasoning.
	// The tx path additionally makes the whole sequence atomic (F3): a
	// version-replay failure there leaves NOTHING behind, not even the
	// unprotected partial row this ordering used to guarantee.
	if txSecretRepo, repoOK := s.secretRepo.(txCapableSecretRepo); repoOK {
		if txVersionRepo, verOK := s.versionRepo.(txCapableSecretVersionRepo); verOK && s.txBeginner != nil {
			return s.withTx(ctx, func(tx *db.Tx) error {
				return s.restoreSecretWith(ctx, &secret, versions.Secret, userID, newID,
					func(ctx context.Context, sec *model.Secret) error { return txSecretRepo.CreateTx(ctx, tx, sec) },
					func(ctx context.Context, v *model.SecretVersion) error {
						return txVersionRepo.CreateVersionTx(ctx, tx, v)
					},
					func(ctx context.Context, id uuid.UUID, enabled bool) error {
						return txSecretRepo.SetPurgeProtectionTx(ctx, tx, id, enabled)
					},
				)
			})
		}
	}
	// Closures, not bare method values: NewItemBackupService's contract lets
	// any repo be nil when its resource type is unneeded by the caller, and
	// taking a method value directly off a nil interface panics immediately
	// on evaluation — even if the method itself is never called.
	return s.restoreSecretWith(ctx, &secret, versions.Secret, userID, newID,
		func(ctx context.Context, sec *model.Secret) error { return s.secretRepo.Create(ctx, sec) },
		func(ctx context.Context, v *model.SecretVersion) error { return s.versionRepo.CreateVersion(ctx, v) },
		func(ctx context.Context, id uuid.UUID, enabled bool) error {
			return s.secretRepo.SetPurgeProtection(ctx, id, enabled)
		},
	)
}

// restoreSecretWith runs the actual restore sequence — create, replay
// versions, re-apply purge protection — against whichever create/
// createVersion/setPurgeProtection functions the caller passes: the plain
// repository methods for the non-transactional path, or Tx-scoped ones
// closed over a shared transaction for the atomic path (F3). Keeping one
// copy of this sequence, parameterized by the write functions, is what lets
// both paths share the exact same ordering logic instead of drifting apart
// the way RestoreSecret and RestoreKey once did (see the comment below).
func (s *ItemBackupService) restoreSecretWith(
	ctx context.Context,
	secret *model.Secret,
	versions []model.SecretVersion,
	userID, newID uuid.UUID,
	create func(context.Context, *model.Secret) error,
	createVersion func(context.Context, *model.SecretVersion) error,
	setPurgeProtection func(context.Context, uuid.UUID, bool) error,
) error {
	if err := create(ctx, secret); err != nil {
		return err
	}
	// Replay versions before applying purge protection: on the
	// non-transactional path, if this fails the partial restore is left
	// unprotected and can still be purged by an operator. Setting purge
	// protection first would leave a partial restore that PurgeSecret
	// refuses to clean up, orphaning it under an ID the caller never
	// received. On the transactional path this ordering no longer matters
	// for correctness (a failure here rolls back the Create too), but is
	// kept identical so the two paths are trivially comparable.
	for _, v := range versions {
		v.ID = uuid.New()
		v.SecretID = newID
		v.UserID = userID
		if err := createVersion(ctx, &v); err != nil {
			return fmt.Errorf("restore secret: create version %d: %w", v.Version, err)
		}
	}
	// Create does not write purge_protection, so a protected item would be
	// restored unprotected. Re-apply the blob's flag as a second write.
	if secret.PurgeProtection {
		if err := setPurgeProtection(ctx, newID, true); err != nil {
			return fmt.Errorf("restore secret: set purge protection: %w", err)
		}
	}
	return nil
}

// BackupKey creates a base64url-encoded backup blob for the given key.
//
// vaultID is the vault the caller's request was authorized against, never a
// vault taken from user input — the same rule RestoreKey follows. The scoped
// read is the entire authorization gate: an unscoped read plus an ownership
// comparison (the previous design) refused a Crypto User who legitimately held
// ActionKeysBackup without owning the key, while still letting any caller name
// a key in a vault they were never authorized for.
func (s *ItemBackupService) BackupKey(ctx context.Context, id, userID, vaultID uuid.UUID) (string, error) {
	key, err := s.keyRepo.Read(ctx, id, model.NewVaultScope(vaultID, userID))
	if err != nil {
		return "", fmt.Errorf("backup key: %w", err)
	}

	// Version records are fetched by key ID. The scoped Read above is the
	// authorization for them.
	versions, err := s.keyRepo.ListVersionRecords(ctx, id)
	if err != nil {
		return "", fmt.Errorf("backup key: list versions: %w", err)
	}
	return encodeBlob("key", id.String(), key, blobVersions{Key: versions})
}

// RestoreKey decodes blob and re-inserts it as newID, owned by userID, into
// vaultID — the vault authorized by the caller's request. See RestoreSecret.
func (s *ItemBackupService) RestoreKey(ctx context.Context, blob string, userID, vaultID, newID uuid.UUID) error {
	var key model.Key
	versions, err := decodeBlob(blob, "key", &key)
	if err != nil {
		return err
	}
	key.ID = newID
	key.UserID = userID
	key.VaultID = vaultID
	// A restore never grants exportability: the blob is unauthenticated
	// base64 JSON, so its exportable value cannot be trusted.
	key.Exportable = false

	if txKeyRepo, repoOK := s.keyRepo.(txCapableKeyRepo); repoOK && s.txBeginner != nil {
		return s.withTx(ctx, func(tx *db.Tx) error {
			return s.restoreKeyWith(ctx, &key, versions.Key, newID,
				func(ctx context.Context, k *model.Key) error { return txKeyRepo.CreateTx(ctx, tx, k) },
				func(ctx context.Context, id uuid.UUID, version int, value string) error {
					return txKeyRepo.CreateVersionTx(ctx, tx, id, version, value)
				},
				func(ctx context.Context, id uuid.UUID, enabled bool) error {
					return txKeyRepo.SetPurgeProtectionTx(ctx, tx, id, enabled)
				},
			)
		})
	}
	// See RestoreSecret for why these are closures, not bare method values.
	return s.restoreKeyWith(ctx, &key, versions.Key, newID,
		func(ctx context.Context, k *model.Key) error { return s.keyRepo.Create(ctx, k) },
		func(ctx context.Context, id uuid.UUID, version int, value string) error {
			return s.keyRepo.CreateVersion(ctx, id, version, value)
		},
		func(ctx context.Context, id uuid.UUID, enabled bool) error {
			return s.keyRepo.SetPurgeProtection(ctx, id, enabled)
		},
	)
}

// restoreKeyWith is RestoreKey's write sequence, parameterized the same way
// restoreSecretWith is. See restoreSecretWith for why this shape exists.
func (s *ItemBackupService) restoreKeyWith(
	ctx context.Context,
	key *model.Key,
	versions []model.KeyVersionRecord,
	newID uuid.UUID,
	create func(context.Context, *model.Key) error,
	createVersion func(context.Context, uuid.UUID, int, string) error,
	setPurgeProtection func(context.Context, uuid.UUID, bool) error,
) error {
	if err := create(ctx, key); err != nil {
		return err
	}
	// Replay versions before applying purge protection, for the reason
	// spelled out in restoreSecretWith: on the non-transactional path, a
	// failure here must leave the partial restore purgeable. Setting purge
	// protection first would strand it, since PurgeKey refuses a protected
	// key. On the transactional path this ordering no longer matters for
	// correctness, but is kept identical to restoreSecretWith's on purpose —
	// see the write-order-divergence lesson recorded for F3.
	for _, v := range versions {
		if err := createVersion(ctx, newID, v.Version, v.Value); err != nil {
			return fmt.Errorf("restore key: create version %d: %w", v.Version, err)
		}
	}
	// See restoreSecretWith: Create does not write purge_protection.
	if key.PurgeProtection {
		if err := setPurgeProtection(ctx, newID, true); err != nil {
			return fmt.Errorf("restore key: set purge protection: %w", err)
		}
	}
	return nil
}

// BackupCertificate creates a base64url-encoded backup blob for the given
// certificate, archived versions included.
//
// vaultID is the vault the caller's request was authorized against. See
// BackupKey for why the scoped read replaces the previous unscoped read plus
// ownership comparison.
func (s *ItemBackupService) BackupCertificate(ctx context.Context, id, userID, vaultID uuid.UUID) (string, error) {
	cert, err := s.certRepo.Read(ctx, id, model.NewVaultScope(vaultID, userID))
	if err != nil {
		return "", fmt.Errorf("backup certificate: %w", err)
	}

	// Version rows are fetched by certificate ID; the scoped read above is
	// their authorization. A certificate with history and no version store
	// fails closed: a blob without its history would restore a single
	// version and silently discard the rest (the loss B26 closed for keys).
	var versions []model.CertificateVersionRecord
	switch {
	case s.certVersionRepo != nil:
		versions, err = s.certVersionRepo.ListVersionRecords(ctx, id)
		if err != nil {
			return "", fmt.Errorf("backup certificate: list versions: %w", err)
		}
	case cert.CurrentVersion() > 1:
		return "", fmt.Errorf("backup certificate: %s is at version %d but no version repository is configured", id, cert.CurrentVersion())
	}
	return encodeBlob("certificate", id.String(), cert, blobVersions{Certificate: versions})
}

// validateCertificateVersions refuses a blob whose archived versions do not
// sit strictly below the current one, or repeat a number. A forged or
// corrupt blob is rejected before anything is written.
func validateCertificateVersions(current int, versions []model.CertificateVersionRecord) error {
	seen := make(map[int]bool, len(versions))
	for _, v := range versions {
		if v.Version < 1 || v.Version >= current || seen[v.Version] {
			return fmt.Errorf("%w: certificate version %d is inconsistent with current version %d", ErrInvalidBlob, v.Version, current)
		}
		seen[v.Version] = true
	}
	return nil
}

// RestoreCertificate decodes blob and re-inserts it as newID, owned by
// userID, into vaultID, the vault authorized by the caller's request. The
// blob's archived versions are replayed under their own numbers. See
// RestoreSecret.
func (s *ItemBackupService) RestoreCertificate(ctx context.Context, blob string, userID, vaultID, newID uuid.UUID) error {
	var cert model.Certificate
	versions, err := decodeBlob(blob, "certificate", &cert)
	if err != nil {
		return err
	}
	if err := validateCertificateVersions(cert.CurrentVersion(), versions.Certificate); err != nil {
		return err
	}
	if len(versions.Certificate) > 0 && s.certVersionRepo == nil {
		return fmt.Errorf("restore certificate: blob carries %d versions but no version repository is configured", len(versions.Certificate))
	}
	cert.ID = newID
	cert.UserID = userID
	cert.VaultID = vaultID
	// A restore never grants exportability; see RestoreKey.
	cert.Exportable = false

	if txCertRepo, repoOK := s.certRepo.(txCapableCertRepo); repoOK && s.txBeginner != nil {
		txVersionRepo, versionOK := s.certVersionRepo.(txCapableCertVersionRepo)
		if len(versions.Certificate) == 0 || versionOK {
			return s.withTx(ctx, func(tx *db.Tx) error {
				return s.restoreCertificateWith(ctx, &cert, versions.Certificate, newID,
					func(ctx context.Context, c *model.Certificate) error { return txCertRepo.CreateTx(ctx, tx, c) },
					func(ctx context.Context, rec *model.CertificateVersionRecord) error {
						return txVersionRepo.CreateVersionTx(ctx, tx, rec)
					},
					func(ctx context.Context, id uuid.UUID, enabled bool) error {
						return txCertRepo.SetPurgeProtectionTx(ctx, tx, id, enabled)
					},
				)
			})
		}
	}
	// See RestoreSecret for why these are closures, not bare method values.
	return s.restoreCertificateWith(ctx, &cert, versions.Certificate, newID,
		func(ctx context.Context, c *model.Certificate) error { return s.certRepo.Create(ctx, c) },
		func(ctx context.Context, rec *model.CertificateVersionRecord) error {
			return s.certVersionRepo.CreateVersion(ctx, rec)
		},
		func(ctx context.Context, id uuid.UUID, enabled bool) error {
			return s.certRepo.SetPurgeProtection(ctx, id, enabled)
		},
	)
}

// restoreCertificateWith is RestoreCertificate's write sequence: create,
// replay versions, re-apply purge protection, parameterized the same way
// restoreSecretWith is. See restoreSecretWith for why this shape exists and
// why versions are replayed before purge protection.
func (s *ItemBackupService) restoreCertificateWith(
	ctx context.Context,
	cert *model.Certificate,
	versions []model.CertificateVersionRecord,
	newID uuid.UUID,
	create func(context.Context, *model.Certificate) error,
	createVersion func(context.Context, *model.CertificateVersionRecord) error,
	setPurgeProtection func(context.Context, uuid.UUID, bool) error,
) error {
	if err := create(ctx, cert); err != nil {
		return err
	}
	for _, v := range versions {
		v.CertificateID = newID
		if err := createVersion(ctx, &v); err != nil {
			return fmt.Errorf("restore certificate: create version %d: %w", v.Version, err)
		}
	}
	// See restoreSecretWith: Create does not write purge_protection.
	if cert.PurgeProtection {
		if err := setPurgeProtection(ctx, newID, true); err != nil {
			return fmt.Errorf("restore certificate: set purge protection: %w", err)
		}
	}
	return nil
}

// encodeBlob marshals data into a JSON envelope and base64url-encodes it.
// versions carries whatever history the resource type has; a zero blobVersions
// means none, and both envelope fields are then omitted.
func encodeBlob(resourceType, resourceID string, data interface{}, versions blobVersions) (string, error) {
	raw, err := json.Marshal(data)
	if err != nil {
		return "", fmt.Errorf("marshal data: %w", err)
	}
	envelope, err := json.Marshal(backupEnvelope{
		ResourceType:        resourceType,
		ResourceID:          resourceID,
		Data:                raw,
		Versions:            versions.Key,
		SecretVersions:      versions.Secret,
		CertificateVersions: versions.Certificate,
	})
	if err != nil {
		return "", fmt.Errorf("marshal envelope: %w", err)
	}
	return base64.URLEncoding.EncodeToString(envelope), nil
}

// decodeBlob base64url-decodes a blob and unmarshals the envelope into out.
// The returned blobVersions is zero for a resource type with no history, and
// zero for a blob encoded before the corresponding field existed — both
// fields are purely additive.
func decodeBlob(blob, expectedType string, out interface{}) (blobVersions, error) {
	var none blobVersions

	raw, err := base64.URLEncoding.DecodeString(blob)
	if err != nil {
		return none, fmt.Errorf("%w: invalid encoding: %w", ErrInvalidBlob, err)
	}
	var envelope backupEnvelope
	if err := json.Unmarshal(raw, &envelope); err != nil {
		return none, fmt.Errorf("%w: invalid format: %w", ErrInvalidBlob, err)
	}
	if envelope.ResourceType != expectedType {
		return none, fmt.Errorf("%w: type mismatch: expected %s, got %s", ErrInvalidBlob, expectedType, envelope.ResourceType)
	}
	if err := json.Unmarshal(envelope.Data, out); err != nil {
		return none, err
	}
	return blobVersions{Key: envelope.Versions, Secret: envelope.SecretVersions, Certificate: envelope.CertificateVersions}, nil
}
