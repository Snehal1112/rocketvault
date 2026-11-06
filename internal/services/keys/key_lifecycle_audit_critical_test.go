package keys

// Audit-first tests for the key lifecycle: create, import, rotate, delete,
// wrap and unwrap must not change or release anything unless the critical
// attempt row was written first.

import (
	"context"
	stdcrypto "crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"testing"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"rocketvault/internal/crypto"
	"rocketvault/internal/repositories"
	auditServices "rocketvault/internal/services/audit"
	"rocketvault/model"
)

// countingKeyProvider counts key generation and import calls and notes them
// on an audit fake so tests can check ordering.
type countingKeyProvider struct {
	crypto.KeyProvider
	audit *fakeKeyAudit
	calls int
}

func (p *countingKeyProvider) record() {
	p.calls++
	if p.audit != nil {
		p.audit.note("generate")
	}
}

func (p *countingKeyProvider) GenerateRSAKey(ctx context.Context, bits int) (string, error) {
	p.record()
	return p.KeyProvider.GenerateRSAKey(ctx, bits)
}

func (p *countingKeyProvider) GenerateECDSAKey(ctx context.Context, curve string) (string, error) {
	p.record()
	return p.KeyProvider.GenerateECDSAKey(ctx, curve)
}

func (p *countingKeyProvider) GenerateAESKey(ctx context.Context, bits int) (string, error) {
	p.record()
	return "aes-label", nil
}

func (p *countingKeyProvider) ImportKey(ctx context.Context, keyType string, key stdcrypto.PrivateKey) (string, error) {
	p.record()
	return p.KeyProvider.ImportKey(ctx, keyType, key)
}

// notingKeyRepo notes every mutation on an audit fake so tests can check
// that the attempt row precedes it.
type notingKeyRepo struct {
	repositories.KeyRepositoryInterface
	audit *fakeKeyAudit
}

func (r *notingKeyRepo) Create(ctx context.Context, k *model.Key) error {
	r.audit.note("create")
	return r.KeyRepositoryInterface.Create(ctx, k)
}

func (r *notingKeyRepo) SoftDelete(ctx context.Context, id uuid.UUID) error {
	r.audit.note("soft_delete")
	return r.KeyRepositoryInterface.SoftDelete(ctx, id)
}

func (r *notingKeyRepo) Update(ctx context.Context, k *model.Key, scope model.Scope) error {
	r.audit.note("update")
	return r.KeyRepositoryInterface.Update(ctx, k, scope)
}

// keyStoreState is a snapshot of every key-store row a lifecycle operation could touch.
type keyStoreState struct {
	keys, versions, live int
}

func snapshotKeyStore(t *testing.T, h *keyExportHarness) keyStoreState {
	t.Helper()
	var s keyStoreState
	require.NoError(t, h.raw.QueryRow("SELECT COUNT(*) FROM keys").Scan(&s.keys))
	require.NoError(t, h.raw.QueryRow("SELECT COUNT(*) FROM key_versions").Scan(&s.versions))
	require.NoError(t, h.raw.QueryRow("SELECT COUNT(*) FROM keys WHERE deleted_at IS NULL").Scan(&s.live))
	return s
}

// auditedLifecycleService builds a key service over h's repository with p and audit wired.
func auditedLifecycleService(h *keyExportHarness, repo repositories.KeyRepositoryInterface, p crypto.KeyProvider, audit auditServices.AuditServiceInterface) KeyService {
	return NewKeyService(KeyServiceConfig{KeyRepository: repo, KeyProvider: p, Logger: newKeyLogger(), AuditService: audit})
}

func ecJWK(t *testing.T) []byte {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	out, err := jose.JSONWebKey{Key: priv}.MarshalJSON()
	require.NoError(t, err)
	return out
}

// lifecycleCase drives one key lifecycle operation. target is a pre-created
// key the operation may act on.
type lifecycleCase struct {
	name   string
	action string
	run    func(svc KeyService, h *keyExportHarness, target uuid.UUID) error
	// newResource reports whether the resource id is minted by the operation.
	newResource bool
}

func lifecycleCases(t *testing.T) []lifecycleCase {
	ctx := context.Background()
	return []lifecycleCase{
		{name: "create RSA", action: "create_rsa_key", newResource: true, run: func(svc KeyService, h *keyExportHarness, _ uuid.UUID) error {
			_, err := svc.CreateRSAKey(ctx, CreateKeyRequest{Name: "rsa-new", Type: "RSA", Bits: 2048, UserID: h.user, VaultID: h.vault})
			return err
		}},
		{name: "create ECDSA", action: "create_ecdsa_key", newResource: true, run: func(svc KeyService, h *keyExportHarness, _ uuid.UUID) error {
			_, err := svc.CreateECDSAKey(ctx, CreateKeyRequest{Name: "ec-new", Type: "ECDSA", Curve: "P-256", UserID: h.user, VaultID: h.vault})
			return err
		}},
		{name: "create oct", action: "create_oct_key", newResource: true, run: func(svc KeyService, h *keyExportHarness, _ uuid.UUID) error {
			_, err := svc.CreateOctKey(ctx, CreateKeyRequest{Name: "oct-new", Type: "OCT", Bits: 256, UserID: h.user, VaultID: h.vault})
			return err
		}},
		{name: "import", action: "import_key", newResource: true, run: func(svc KeyService, h *keyExportHarness, _ uuid.UUID) error {
			_, err := svc.ImportKey(ctx, ImportKeyRequest{Name: "imported", JWK: ecJWK(t), UserID: h.user, VaultID: h.vault})
			return err
		}},
		{name: "rotate", action: "rotate_key", run: func(svc KeyService, h *keyExportHarness, target uuid.UUID) error {
			_, err := svc.RotateKey(ctx, target, h.scope)
			return err
		}},
		{name: "delete", action: "delete_key", run: func(svc KeyService, h *keyExportHarness, target uuid.UUID) error {
			_, err := svc.DeleteKey(ctx, target, h.scope)
			return err
		}},
	}
}

func TestKeyLifecycle_AuditFailureChangesNothing(t *testing.T) {
	for _, tc := range lifecycleCases(t) {
		t.Run(tc.name, func(t *testing.T) {
			h := newKeyExportHarness(t, nil)
			target := h.create(t, "ECDSA", "P-256", false)
			before := snapshotKeyStore(t, h)
			var valueBefore string
			require.NoError(t, h.raw.QueryRow("SELECT value FROM keys WHERE id = ?", target.String()).Scan(&valueBefore))

			audit := &fakeKeyAudit{criticalErr: errors.New("pq: disk full on audit_logs")}
			provider := &countingKeyProvider{KeyProvider: crypto.NewSoftwareKeyProvider()}
			err := tc.run(auditedLifecycleService(h, h.repo, provider, audit), h, target)

			requireAuditUnavailable(t, err)
			assert.Zero(t, provider.calls, "no key material may be generated or imported")
			assert.Equal(t, before, snapshotKeyStore(t, h), "no key row may change")
			var valueAfter string
			require.NoError(t, h.raw.QueryRow("SELECT value FROM keys WHERE id = ?", target.String()).Scan(&valueAfter))
			assert.Equal(t, valueBefore, valueAfter)

			require.Len(t, audit.critical, 1)
			ev := audit.critical[0]
			assert.Equal(t, tc.action, ev.Action)
			assert.Equal(t, "attempt", ev.Outcome)
			assert.Equal(t, "key", ev.ResourceType)
			assert.Equal(t, h.user.String(), ev.UserID, "the actor is the caller")
			if tc.newResource {
				assert.NotEmpty(t, ev.ResourceID)
				assert.NotEqual(t, h.user.String(), ev.ResourceID)
			} else {
				assert.Equal(t, target.String(), ev.ResourceID)
			}
			assert.Empty(t, audit.events, "a refused operation writes no result row")
		})
	}
}

func TestKeyLifecycle_WritesAttemptBeforeEffect(t *testing.T) {
	effects := map[string][]string{
		"create RSA":   {"critical:attempt", "generate", "create", "event:success"},
		"create ECDSA": {"critical:attempt", "generate", "create", "event:success"},
		"import":       {"critical:attempt", "generate", "create", "event:success"},
		"rotate":       {"critical:attempt", "generate", "update", "event:success"},
		"delete":       {"critical:attempt", "soft_delete", "event:success"},
	}
	for _, tc := range lifecycleCases(t) {
		want, ok := effects[tc.name]
		if !ok {
			continue // Oct keys need an HSM to be stored for real.
		}
		t.Run(tc.name, func(t *testing.T) {
			h := newKeyExportHarness(t, nil)
			target := h.create(t, "ECDSA", "P-256", false)
			audit := &fakeKeyAudit{}
			provider := &countingKeyProvider{KeyProvider: crypto.NewSoftwareKeyProvider(), audit: audit}
			repo := &notingKeyRepo{KeyRepositoryInterface: h.repo, audit: audit}

			require.NoError(t, tc.run(auditedLifecycleService(h, repo, provider, audit), h, target))

			assert.Equal(t, want, audit.calls)
			require.Len(t, audit.events, 1)
			assert.Equal(t, audit.critical[0].ResourceID, audit.events[0].ResourceID, "the result row names the same key")
		})
	}
}

// TestKeyLifecycle_CreatedKeyIDMatchesAuditRow pins that the attempt row
// names the key that is then stored, not a different minted id.
func TestKeyLifecycle_CreatedKeyIDMatchesAuditRow(t *testing.T) {
	h := newKeyExportHarness(t, nil)
	audit := &fakeKeyAudit{}
	svc := auditedLifecycleService(h, h.repo, crypto.NewSoftwareKeyProvider(), audit)

	res, err := svc.CreateRSAKey(context.Background(), CreateKeyRequest{Name: "rsa", Type: "RSA", Bits: 2048, UserID: h.user, VaultID: h.vault})

	require.NoError(t, err)
	require.Len(t, audit.critical, 1)
	assert.Equal(t, res.KeyID.String(), audit.critical[0].ResourceID)
}

// TestKeyLifecycle_RefusalsAreNotCritical pins that requests refused before
// the effect (bad input, not found) are answered as before with audit down
// and write no critical row.
func TestKeyLifecycle_RefusalsAreNotCritical(t *testing.T) {
	ctx := context.Background()
	h := newKeyExportHarness(t, nil)
	audit := &fakeKeyAudit{criticalErr: errors.New("down")}
	svc := auditedLifecycleService(h, h.repo, crypto.NewSoftwareKeyProvider(), audit)
	missing := uuid.New()

	_, err := svc.CreateRSAKey(ctx, CreateKeyRequest{Name: "bad", Bits: 1024, UserID: h.user, VaultID: h.vault})
	assert.Error(t, err)
	assert.NotErrorIs(t, err, auditServices.ErrAuditUnavailable)
	_, err = svc.CreateECDSAKey(ctx, CreateKeyRequest{Name: "bad", Curve: "P-999", UserID: h.user, VaultID: h.vault})
	assert.NotErrorIs(t, err, auditServices.ErrAuditUnavailable)
	_, err = svc.CreateOctKey(ctx, CreateKeyRequest{Name: "bad", Bits: 256, Exportable: true, UserID: h.user, VaultID: h.vault})
	assert.ErrorIs(t, err, model.ErrExportableNotSupported)
	_, err = svc.CreateOctKey(ctx, CreateKeyRequest{Name: "bad", Bits: 256, UserID: h.user, VaultID: h.vault})
	assert.ErrorIs(t, err, crypto.ErrOctKeysRequireHSM, "the software provider refusal stays a 400")
	_, err = svc.ImportKey(ctx, ImportKeyRequest{Name: "bad", JWK: []byte(`{}`), UserID: h.user, VaultID: h.vault})
	assert.ErrorIs(t, err, ErrInvalidJWK)
	_, err = svc.RotateKey(ctx, missing, h.scope)
	assert.NotErrorIs(t, err, auditServices.ErrAuditUnavailable)
	_, err = svc.DeleteKey(ctx, missing, h.scope)
	assert.ErrorIs(t, err, ErrKeyNotFound)

	assert.Empty(t, audit.critical)
}

// TestRotateKey_SystemActorWhenScheduled pins that a background rotation
// with no acting principal records "system", never the key owner.
func TestRotateKey_SystemActorWhenScheduled(t *testing.T) {
	h := newKeyExportHarness(t, nil)
	target := h.create(t, "ECDSA", "P-256", false)
	audit := &fakeKeyAudit{}
	svc := auditedLifecycleService(h, h.repo, crypto.NewSoftwareKeyProvider(), audit)

	_, err := svc.RotateKey(context.Background(), target, model.NewAdminScope(uuid.Nil))

	require.NoError(t, err)
	require.Len(t, audit.critical, 1)
	assert.Equal(t, "system", audit.critical[0].UserID)
	assert.Equal(t, target.String(), audit.critical[0].ResourceID)
}

// TestRotationExecutor_AuditDownSkipsAndRetries pins that the scheduled key
// rotation does not rotate or mark a key while audit is down, so the policy
// stays due and the next tick retries it.
func TestRotationExecutor_AuditDownSkipsAndRetries(t *testing.T) {
	h := newKeyExportHarness(t, nil)
	target := h.create(t, "ECDSA", "P-256", false)
	before := snapshotKeyStore(t, h)
	audit := &fakeKeyAudit{criticalErr: errors.New("down")}
	svc := auditedLifecycleService(h, h.repo, crypto.NewSoftwareKeyProvider(), audit)
	policyRepo := new(mockKeyPolicyRepo)
	policyRepo.On("GetDuePolicies", mock.Anything, mock.Anything).
		Return([]model.KeyRotationPolicy{{ID: uuid.New(), KeyID: target, Enabled: true, RotateAfterDays: 30}}, nil)

	require.NoError(t, NewRotationExecutor(svc, policyRepo, newTestKeyLogger(t)).Check(context.Background()))

	policyRepo.AssertNotCalled(t, "MarkRotated", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything)
	assert.Equal(t, before, snapshotKeyStore(t, h))
}

// wrapHarness creates an RSA key and a crypto service over h with audit wired.
func wrapHarness(t *testing.T, audit auditServices.AuditServiceInterface) (*keyExportHarness, CryptoService, uuid.UUID) {
	t.Helper()
	h := newKeyExportHarness(t, nil)
	id := h.create(t, "RSA", "", false)
	svc := NewCryptoService(CryptoServiceConfig{KeyRepository: h.repo, KeyProvider: crypto.NewSoftwareKeyProvider(),
		Logger: newKeyLogger(), AuditService: audit})
	return h, svc, id
}

func TestWrapUnwrap_AuditFailureReleasesNothing(t *testing.T) {
	ctx := context.Background()
	audit := &fakeKeyAudit{criticalErr: errors.New("down")}
	hh, svc, keyID := wrapHarness(t, audit)

	wrapped, err := svc.WrapKey(ctx, WrapKeyRequest{KeyID: keyID, UserID: hh.user, Scope: hh.scope, PlaintextKey: []byte("dek"), Algorithm: "RSA-OAEP"})
	requireAuditUnavailable(t, err)
	assert.Nil(t, wrapped, "no wrapped key may be returned")

	unwrapped, err := svc.UnwrapKey(ctx, UnwrapKeyRequest{KeyID: keyID, UserID: hh.user, Scope: hh.scope, WrappedKey: []byte("blob"), Algorithm: "RSA-OAEP"})
	requireAuditUnavailable(t, err)
	assert.Nil(t, unwrapped, "no plaintext key may be returned")

	require.Len(t, audit.critical, 2)
	for i, action := range []string{"wrap_key", "unwrap_key"} {
		assert.Equal(t, action, audit.critical[i].Action)
		assert.Equal(t, "attempt", audit.critical[i].Outcome)
		assert.Equal(t, hh.user.String(), audit.critical[i].UserID)
		assert.Equal(t, keyID.String(), audit.critical[i].ResourceID)
	}
}

func TestWrapUnwrap_WritesAttemptThenResult(t *testing.T) {
	ctx := context.Background()
	audit := &fakeKeyAudit{}
	h, svc, keyID := wrapHarness(t, audit)

	wrapped, err := svc.WrapKey(ctx, WrapKeyRequest{KeyID: keyID, UserID: h.user, Scope: h.scope, PlaintextKey: []byte("dek"), Algorithm: "RSA-OAEP"})
	require.NoError(t, err)
	out, err := svc.UnwrapKey(ctx, UnwrapKeyRequest{KeyID: keyID, UserID: h.user, Scope: h.scope, WrappedKey: wrapped.WrappedKey, Algorithm: "RSA-OAEP"})
	require.NoError(t, err)
	assert.Equal(t, []byte("dek"), out.PlaintextKey)

	assert.Equal(t, []string{"critical:attempt", "event:success", "critical:attempt", "event:success"}, audit.calls)
}

// TestWrapUnwrap_RefusalsAreNotCritical pins that bad input and an unknown
// key are refused before the attempt row.
func TestWrapUnwrap_RefusalsAreNotCritical(t *testing.T) {
	ctx := context.Background()
	audit := &fakeKeyAudit{criticalErr: errors.New("down")}
	h, svc, keyID := wrapHarness(t, audit)

	_, err := svc.WrapKey(ctx, WrapKeyRequest{KeyID: keyID, Scope: h.scope, PlaintextKey: []byte("dek"), Algorithm: "BOGUS"})
	assert.ErrorIs(t, err, ErrUnsupportedAlgorithm)
	_, err = svc.UnwrapKey(ctx, UnwrapKeyRequest{KeyID: uuid.New(), Scope: h.scope, WrappedKey: []byte("x"), Algorithm: "RSA-OAEP"})
	assert.ErrorIs(t, err, ErrKeyNotFound)

	assert.Empty(t, audit.critical)
}
