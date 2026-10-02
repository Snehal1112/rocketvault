package certificates

// Extended tests for CertificateService and CertificateRenewalScheduler.
// These tests live in the same package (white-box) so they can reuse the mocks
// already declared in cert_soft_delete_test.go.

import (
	"context"
	"encoding/base64"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"rocketvault/common"
	"rocketvault/internal/crypto"
	"rocketvault/internal/logging"
	"rocketvault/internal/repositories"
	"rocketvault/model"
)

// ────────────────────────────────────────────────────────────────────────────
// helpers
// ────────────────────────────────────────────────────────────────────────────

func newTestCertLogger() *logging.Logger {
	return &logging.Logger{Logger: logrus.New()}
}

func newCertSvc(certRepo *mockCertRepository, keyRepo *mockKeyRepo) CertificateService {
	return newCertSvcWithVersions(certRepo, keyRepo, &fakeCertVersionRepo{certRepo: certRepo})
}

// certVaultScope matches the scope the certificate service now passes when it
// reads a signing key or CA certificate: a vault scope naming the vault the
// certificate is being created in, acting as the requesting user (B32).
//
// These call sites used to expect model.NewAdminScope(userID) exactly. Matching
// on kind and actor rather than on a specific vault id keeps the assertion
// meaningful — an admin scope still fails it, which is the regression that
// matters — without every test having to restate which vault it defaulted to.
func certVaultScope(userID uuid.UUID) any {
	return mock.MatchedBy(func(s model.Scope) bool {
		return s.Kind() == model.ScopeVault && s.ActorID() == userID
	})
}

func accessibleCert(userID, certID uuid.UUID) *model.Certificate {
	return &model.Certificate{
		ID:      certID,
		UserID:  userID,
		Name:    "test-cert",
		Enabled: true,
	}
}

// ────────────────────────────────────────────────────────────────────────────
// resolveVaultID
// ────────────────────────────────────────────────────────────────────────────

func TestResolveVaultID_NilReturnsDefault(t *testing.T) {
	result := resolveVaultID(uuid.Nil)
	assert.Equal(t, uuid.MustParse(model.DefaultVaultID), result)
}

func TestResolveVaultID_NonNilPreserved(t *testing.T) {
	vaultID := uuid.New()
	result := resolveVaultID(vaultID)
	assert.Equal(t, vaultID, result)
}

// ────────────────────────────────────────────────────────────────────────────
// ListCertificates
// ────────────────────────────────────────────────────────────────────────────

func TestListCertificates_Success(t *testing.T) {
	userID := uuid.New()
	certRepo := &mockCertRepository{}
	keyRepo := &mockKeyRepo{}

	scope := model.NewOwnerScope(uuid.Nil, userID)
	expected := []model.Certificate{{ID: uuid.New(), UserID: userID, Name: "c1", Enabled: true}}
	certRepo.On("List", mock.Anything, scope, repositories.CertificateFilter{}).Return(expected, nil)

	svc := newCertSvc(certRepo, keyRepo)
	got, err := svc.ListCertificates(context.Background(), scope, repositories.CertificateFilter{})
	require.NoError(t, err)
	assert.Equal(t, expected, got)
	certRepo.AssertExpectations(t)
}

func TestListCertificates_RepositoryError(t *testing.T) {
	userID := uuid.New()
	certRepo := &mockCertRepository{}
	keyRepo := &mockKeyRepo{}

	scope := model.NewOwnerScope(uuid.Nil, userID)
	certRepo.On("List", mock.Anything, scope, repositories.CertificateFilter{}).
		Return(nil, errors.New("db error"))

	svc := newCertSvc(certRepo, keyRepo)
	_, err := svc.ListCertificates(context.Background(), scope, repositories.CertificateFilter{})
	assert.Error(t, err)
	certRepo.AssertExpectations(t)
}

// ────────────────────────────────────────────────────────────────────────────
// GetCertificate – additional branches
// ────────────────────────────────────────────────────────────────────────────

func TestGetCertificate_NotFound(t *testing.T) {
	userID := uuid.New()
	certID := uuid.New()
	certRepo := &mockCertRepository{}
	keyRepo := &mockKeyRepo{}

	certRepo.On("Read", mock.Anything, certID, model.NewOwnerScope(uuid.Nil, userID)).Return(nil, errors.New("not found"))

	svc := newCertSvc(certRepo, keyRepo)
	_, err := svc.GetCertificate(context.Background(), certID, model.NewOwnerScope(uuid.Nil, userID))
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrCertNotFound)
}

// TestGetCertificate_WrongOwner verifies that a certificate owned by a
// different user is treated as not-found. Authorization is now enforced by
// the repository's Read predicate rather than a post-fetch Go
// comparison, so the mock simulates the repository finding no row that
// matches the caller's scope.
func TestGetCertificate_WrongOwner(t *testing.T) {
	callerID := uuid.New()
	certID := uuid.New()
	certRepo := &mockCertRepository{}
	keyRepo := &mockKeyRepo{}

	certRepo.On("Read", mock.Anything, certID, model.NewOwnerScope(uuid.Nil, callerID)).
		Return(nil, errors.New("not found"))

	svc := newCertSvc(certRepo, keyRepo)
	_, err := svc.GetCertificate(context.Background(), certID, model.NewOwnerScope(uuid.Nil, callerID))
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrCertNotFound)
}

func TestGetCertificate_LifecycleDenied(t *testing.T) {
	userID := uuid.New()
	certID := uuid.New()
	certRepo := &mockCertRepository{}
	keyRepo := &mockKeyRepo{}

	// disabled cert
	certRepo.On("Read", mock.Anything, certID, model.NewOwnerScope(uuid.Nil, userID)).Return(&model.Certificate{
		ID:      certID,
		UserID:  userID,
		Name:    "cert",
		Enabled: false,
	}, nil)

	svc := newCertSvc(certRepo, keyRepo)
	_, err := svc.GetCertificate(context.Background(), certID, model.NewOwnerScope(uuid.Nil, userID))
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrCertLifecycleDenied)
}

// ────────────────────────────────────────────────────────────────────────────
// UpdateCertificate
// ────────────────────────────────────────────────────────────────────────────

func TestUpdateCertificate_AllFields(t *testing.T) {
	userID := uuid.New()
	certID := uuid.New()
	certRepo := &mockCertRepository{}
	keyRepo := &mockKeyRepo{}

	existing := accessibleCert(userID, certID)
	scope := model.NewOwnerScope(uuid.Nil, userID)
	certRepo.On("Read", mock.Anything, certID, scope).Return(existing, nil)
	certRepo.On("Update", mock.Anything, mock.AnythingOfType("*model.Certificate"), scope).Return(nil)

	newName := "updated-cert"
	autoRenew := true
	renewDays := 60
	enabled := false
	nb := time.Now().Add(time.Hour)

	svc := newCertSvc(certRepo, keyRepo)
	err := svc.UpdateCertificate(context.Background(), UpdateCertificateRequest{
		CertID:      certID,
		Scope:       scope,
		Name:        &newName,
		Tags:        []string{"tag1"},
		AutoRenew:   &autoRenew,
		RenewalDays: &renewDays,
		Enabled:     &enabled,
		NotBefore:   &nb,
	})
	require.NoError(t, err)
	certRepo.AssertExpectations(t)
}

func TestUpdateCertificate_NoOptionalFields(t *testing.T) {
	userID := uuid.New()
	certID := uuid.New()
	certRepo := &mockCertRepository{}
	keyRepo := &mockKeyRepo{}

	existing := accessibleCert(userID, certID)
	scope := model.NewOwnerScope(uuid.Nil, userID)
	certRepo.On("Read", mock.Anything, certID, scope).Return(existing, nil)
	certRepo.On("Update", mock.Anything, mock.AnythingOfType("*model.Certificate"), scope).Return(nil)

	svc := newCertSvc(certRepo, keyRepo)
	err := svc.UpdateCertificate(context.Background(), UpdateCertificateRequest{
		CertID: certID,
		Scope:  scope,
		// all optional fields nil / empty
	})
	require.NoError(t, err)
	certRepo.AssertExpectations(t)
}

func TestUpdateCertificate_GetCertificateFails(t *testing.T) {
	userID := uuid.New()
	certID := uuid.New()
	certRepo := &mockCertRepository{}
	keyRepo := &mockKeyRepo{}

	scope := model.NewOwnerScope(uuid.Nil, userID)
	certRepo.On("Read", mock.Anything, certID, scope).Return(nil, errors.New("not found"))

	svc := newCertSvc(certRepo, keyRepo)
	err := svc.UpdateCertificate(context.Background(), UpdateCertificateRequest{
		CertID: certID,
		Scope:  scope,
	})
	require.Error(t, err)
}

func TestUpdateCertificate_RepositoryUpdateFails(t *testing.T) {
	userID := uuid.New()
	certID := uuid.New()
	certRepo := &mockCertRepository{}
	keyRepo := &mockKeyRepo{}

	existing := accessibleCert(userID, certID)
	scope := model.NewOwnerScope(uuid.Nil, userID)
	certRepo.On("Read", mock.Anything, certID, scope).Return(existing, nil)
	certRepo.On("Update", mock.Anything, mock.AnythingOfType("*model.Certificate"), scope).
		Return(errors.New("update failed"))

	svc := newCertSvc(certRepo, keyRepo)
	err := svc.UpdateCertificate(context.Background(), UpdateCertificateRequest{
		CertID: certID,
		Scope:  scope,
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to update certificate")
}

// ────────────────────────────────────────────────────────────────────────────
// DeleteCertificate – SoftDelete failure
// ────────────────────────────────────────────────────────────────────────────

func TestDeleteCertificate_SoftDeleteFails(t *testing.T) {
	userID := uuid.New()
	certID := uuid.New()
	certRepo := &mockCertRepository{}
	keyRepo := &mockKeyRepo{}

	scope := model.NewOwnerScope(uuid.Nil, userID)
	certRepo.On("Read", mock.Anything, certID, scope).Return(accessibleCert(userID, certID), nil)
	certRepo.On("SoftDelete", mock.Anything, certID).Return(errors.New("db error"))

	svc := newCertSvc(certRepo, keyRepo)
	err := svc.DeleteCertificate(context.Background(), certID, scope)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to delete certificate")
}

// ────────────────────────────────────────────────────────────────────────────
// GetCertificate — vault-scoped access
// ────────────────────────────────────────────────────────────────────────────

func TestGetCertificateVaultScope_Success(t *testing.T) {
	vaultID := uuid.New()
	certID := uuid.New()
	certRepo := &mockCertRepository{}
	keyRepo := &mockKeyRepo{}

	cert := &model.Certificate{ID: certID, UserID: uuid.New(), Name: "vc", Enabled: true}
	scope := model.NewVaultScope(vaultID, uuid.Nil)
	certRepo.On("Read", mock.Anything, certID, scope).Return(cert, nil)

	svc := newCertSvc(certRepo, keyRepo)
	got, err := svc.GetCertificate(context.Background(), certID, scope)
	require.NoError(t, err)
	assert.Equal(t, certID, got.ID)
	certRepo.AssertExpectations(t)
}

func TestGetCertificateVaultScope_NotFound(t *testing.T) {
	vaultID := uuid.New()
	certID := uuid.New()
	certRepo := &mockCertRepository{}
	keyRepo := &mockKeyRepo{}

	scope := model.NewVaultScope(vaultID, uuid.Nil)
	certRepo.On("Read", mock.Anything, certID, scope).Return(nil, errors.New("not found"))

	svc := newCertSvc(certRepo, keyRepo)
	_, err := svc.GetCertificate(context.Background(), certID, scope)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrCertNotFound)
}

func TestGetCertificateVaultScope_LifecycleDenied(t *testing.T) {
	vaultID := uuid.New()
	certID := uuid.New()
	certRepo := &mockCertRepository{}
	keyRepo := &mockKeyRepo{}

	cert := &model.Certificate{ID: certID, UserID: uuid.New(), Name: "vc", Enabled: false}
	scope := model.NewVaultScope(vaultID, uuid.Nil)
	certRepo.On("Read", mock.Anything, certID, scope).Return(cert, nil)

	svc := newCertSvc(certRepo, keyRepo)
	_, err := svc.GetCertificate(context.Background(), certID, scope)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrCertLifecycleDenied)
}

// ────────────────────────────────────────────────────────────────────────────
// ListCertificates — vault-scoped access
// ────────────────────────────────────────────────────────────────────────────

func TestListCertificatesVaultScope_Success(t *testing.T) {
	vaultID := uuid.New()
	certRepo := &mockCertRepository{}
	keyRepo := &mockKeyRepo{}

	scope := model.NewVaultScope(vaultID, uuid.Nil)
	certs := []model.Certificate{{ID: uuid.New(), Name: "c1", Enabled: true}}
	certRepo.On("List", mock.Anything, scope, repositories.CertificateFilter{}).Return(certs, nil)

	svc := newCertSvc(certRepo, keyRepo)
	got, err := svc.ListCertificates(context.Background(), scope, repositories.CertificateFilter{})
	require.NoError(t, err)
	assert.Len(t, got, 1)
	certRepo.AssertExpectations(t)
}

func TestListCertificatesVaultScope_RepositoryError(t *testing.T) {
	vaultID := uuid.New()
	certRepo := &mockCertRepository{}
	keyRepo := &mockKeyRepo{}

	scope := model.NewVaultScope(vaultID, uuid.Nil)
	certRepo.On("List", mock.Anything, scope, repositories.CertificateFilter{}).
		Return(nil, errors.New("db error"))

	svc := newCertSvc(certRepo, keyRepo)
	_, err := svc.ListCertificates(context.Background(), scope, repositories.CertificateFilter{})
	assert.Error(t, err)
}

// ────────────────────────────────────────────────────────────────────────────
// DeleteCertificate — vault-scoped access
// ────────────────────────────────────────────────────────────────────────────

func TestDeleteCertificateVaultScope_Success(t *testing.T) {
	vaultID := uuid.New()
	certID := uuid.New()
	certRepo := &mockCertRepository{}
	keyRepo := &mockKeyRepo{}

	cert := &model.Certificate{ID: certID, UserID: uuid.New(), Name: "vc", Enabled: true}
	scope := model.NewVaultScope(vaultID, uuid.Nil)
	certRepo.On("Read", mock.Anything, certID, scope).Return(cert, nil)
	certRepo.On("SoftDelete", mock.Anything, certID).Return(nil)

	svc := newCertSvc(certRepo, keyRepo)
	err := svc.DeleteCertificate(context.Background(), certID, scope)
	require.NoError(t, err)
	certRepo.AssertCalled(t, "SoftDelete", mock.Anything, certID)
	certRepo.AssertExpectations(t)
}

func TestDeleteCertificateVaultScope_NotFound(t *testing.T) {
	vaultID := uuid.New()
	certID := uuid.New()
	certRepo := &mockCertRepository{}
	keyRepo := &mockKeyRepo{}

	scope := model.NewVaultScope(vaultID, uuid.Nil)
	certRepo.On("Read", mock.Anything, certID, scope).Return(nil, errors.New("not found"))

	svc := newCertSvc(certRepo, keyRepo)
	err := svc.DeleteCertificate(context.Background(), certID, scope)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrCertNotFound)
}

func TestDeleteCertificateVaultScope_SoftDeleteFails(t *testing.T) {
	vaultID := uuid.New()
	certID := uuid.New()
	certRepo := &mockCertRepository{}
	keyRepo := &mockKeyRepo{}

	cert := &model.Certificate{ID: certID, UserID: uuid.New(), Enabled: true}
	scope := model.NewVaultScope(vaultID, uuid.Nil)
	certRepo.On("Read", mock.Anything, certID, scope).Return(cert, nil)
	certRepo.On("SoftDelete", mock.Anything, certID).Return(errors.New("db error"))

	svc := newCertSvc(certRepo, keyRepo)
	err := svc.DeleteCertificate(context.Background(), certID, scope)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to delete certificate")
}

// ────────────────────────────────────────────────────────────────────────────
// ValidateCertificateAccess
// ────────────────────────────────────────────────────────────────────────────

// TestValidateCertificateAccess_HasNoAdminBypass replaces a test that asserted
// the opposite. ValidateCertificateAccess used to open with
// `if role == model.RoleAdmin { return nil }`, and the old
// TestValidateCertificateAccess_AdminBypassesCheck pinned that as required
// behaviour -- while every production call site passed "" for role, so the
// branch never actually fired. The parameter is gone with B32; authorization is
// the scoped read now, for admins and everyone else alike.
func TestValidateCertificateAccess_HasNoAdminBypass(t *testing.T) {
	t.Parallel()

	certID := uuid.New()
	userID := uuid.New()
	vaultID := uuid.New()
	certRepo := &mockCertRepository{}
	certRepo.On("Read", mock.Anything, certID, mock.Anything).Return(nil, errors.New("not found"))

	svc := newCertSvc(certRepo, &mockKeyRepo{})
	err := svc.ValidateCertificateAccess(context.Background(), certID, model.NewVaultScope(vaultID, userID))
	require.Error(t, err, "there is no role that skips the repository read")
	certRepo.AssertCalled(t, "Read", mock.Anything, certID, mock.Anything)
}

// TestValidateCertificateAccess_IsVaultScoped is the certificate-side twin of
// TestValidateKeyOwnership_IsVaultScoped -- the CA certificate on the CA-signed
// path had the identical B32 shape.
func TestValidateCertificateAccess_IsVaultScoped(t *testing.T) {
	t.Parallel()

	userID := uuid.New()
	certID := uuid.New()
	vaultA := uuid.New()
	vaultB := uuid.New()
	cert := &model.Certificate{ID: certID, UserID: userID, VaultID: vaultA, Enabled: true}

	newRepo := func() *mockCertRepository {
		r := &mockCertRepository{}
		r.On("Read", mock.Anything, certID, mock.MatchedBy(func(s model.Scope) bool {
			return s.Kind() == model.ScopeVault && s.VaultID() == vaultA
		})).Return(cert, nil)
		r.On("Read", mock.Anything, certID, mock.Anything).Return(nil, errors.New("not found"))
		return r
	}

	t.Run("granted in the certificate's own vault", func(t *testing.T) {
		svc := newCertSvc(newRepo(), &mockKeyRepo{})
		require.NoError(t, svc.ValidateCertificateAccess(context.Background(), certID, model.NewVaultScope(vaultA, userID)))
	})

	t.Run("denied from a different vault", func(t *testing.T) {
		svc := newCertSvc(newRepo(), &mockKeyRepo{})
		err := svc.ValidateCertificateAccess(context.Background(), certID, model.NewVaultScope(vaultB, userID))
		require.Error(t, err, "a CA certificate in vault A must not be usable from vault B")
		assert.Contains(t, err.Error(), "certificate not found")
	})
}

func TestValidateCertificateAccess_ForbiddenForOtherUser(t *testing.T) {
	t.Parallel()

	ownerID := uuid.New()
	callerID := uuid.New()
	certID := uuid.New()
	vaultID := uuid.New()
	certRepo := &mockCertRepository{}

	certRepo.On("Read", mock.Anything, certID, mock.Anything).Return(&model.Certificate{
		ID: certID, UserID: ownerID, VaultID: vaultID, Enabled: true,
	}, nil)

	svc := newCertSvc(certRepo, &mockKeyRepo{})
	err := svc.ValidateCertificateAccess(context.Background(), certID, model.NewVaultScope(vaultID, callerID))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "forbidden")
}

func TestValidateCertificateAccess_CertNotFound(t *testing.T) {
	t.Parallel()

	certID := uuid.New()
	userID := uuid.New()
	vaultID := uuid.New()
	certRepo := &mockCertRepository{}

	certRepo.On("Read", mock.Anything, certID, mock.Anything).Return(nil, errors.New("not found"))

	svc := newCertSvc(certRepo, &mockKeyRepo{})
	err := svc.ValidateCertificateAccess(context.Background(), certID, model.NewVaultScope(vaultID, userID))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "certificate not found")
}

// ────────────────────────────────────────────────────────────────────────────
// ValidateKeyOwnership – additional branches
// ────────────────────────────────────────────────────────────────────────────

// vaultScopedKeyRepo registers a mockKeyRepo expectation that behaves like the
// real repository's vault predicate: the key is visible only through a vault
// scope naming the vault it actually lives in, and any other scope -- including
// an admin scope -- sees nothing.
//
// Expectation order matters: testify matches the first registered expectation,
// so the specific vault matcher has to precede the catch-all.
func vaultScopedKeyRepo(keyRepo *mockKeyRepo, keyID, keyVaultID uuid.UUID, key *model.Key) {
	keyRepo.On("Read", mock.Anything, keyID, mock.MatchedBy(func(s model.Scope) bool {
		return s.Kind() == model.ScopeVault && s.VaultID() == keyVaultID
	})).Return(key, nil)
	keyRepo.On("Read", mock.Anything, keyID, mock.Anything).Return(nil, errors.New("not found"))
}

// TestValidateKeyOwnership_IsVaultScoped is the regression for B32.
//
// ValidateKeyOwnership used to read the signing key with model.NewAdminScope --
// which carries no vault predicate -- and then check only key.UserID == userID.
// A user who owned a key in vault A could therefore mint a certificate in
// vault B signed by it, with no role assignment relating the two vaults. The
// vault boundary, which is the security boundary everywhere else, did not
// apply on this path.
//
// The same-vault case is the half that fails against the old code: under an
// admin scope the repository stub returns nothing, so a legitimate caller is
// refused. The cross-vault case alone would pass either way, which is exactly
// why it is not asserted on its own.
func TestValidateKeyOwnership_IsVaultScoped(t *testing.T) {
	t.Parallel()

	userID := uuid.New()
	keyID := uuid.New()
	vaultA := uuid.New()
	vaultB := uuid.New()
	key := &model.Key{ID: keyID, UserID: userID, VaultID: vaultA, Enabled: true}

	t.Run("granted in the key's own vault", func(t *testing.T) {
		keyRepo := &mockKeyRepo{}
		vaultScopedKeyRepo(keyRepo, keyID, vaultA, key)

		svc := newCertSvc(&mockCertRepository{}, keyRepo)
		err := svc.ValidateKeyOwnership(context.Background(), keyID, model.NewVaultScope(vaultA, userID))
		require.NoError(t, err, "the key's owner must be able to use it inside its own vault")
	})

	t.Run("denied from a different vault", func(t *testing.T) {
		keyRepo := &mockKeyRepo{}
		vaultScopedKeyRepo(keyRepo, keyID, vaultA, key)

		svc := newCertSvc(&mockCertRepository{}, keyRepo)
		err := svc.ValidateKeyOwnership(context.Background(), keyID, model.NewVaultScope(vaultB, userID))
		require.Error(t, err, "owning a key in vault A must not authorize using it in vault B")
		assert.Contains(t, err.Error(), "key not found")
	})
}

// TestValidateKeyOwnership_OwnerCheckSurvivesInsideTheVault pins that the B32
// fix tightened access without widening it. Adding the vault predicate closed
// the cross-vault hole; it deliberately did NOT drop the owner comparison, so a
// non-owner in the same vault is still refused exactly as before.
func TestValidateKeyOwnership_OwnerCheckSurvivesInsideTheVault(t *testing.T) {
	t.Parallel()

	ownerID := uuid.New()
	callerID := uuid.New()
	keyID := uuid.New()
	vaultID := uuid.New()
	keyRepo := &mockKeyRepo{}
	vaultScopedKeyRepo(keyRepo, keyID, vaultID, &model.Key{ID: keyID, UserID: ownerID, VaultID: vaultID})

	svc := newCertSvc(&mockCertRepository{}, keyRepo)
	err := svc.ValidateKeyOwnership(context.Background(), keyID, model.NewVaultScope(vaultID, callerID))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "forbidden")
}

func TestValidateKeyOwnership_KeyNotFound(t *testing.T) {
	t.Parallel()

	keyID := uuid.New()
	userID := uuid.New()
	vaultID := uuid.New()
	keyRepo := &mockKeyRepo{}

	keyRepo.On("Read", mock.Anything, keyID, mock.Anything).Return(nil, errors.New("not found"))

	svc := newCertSvc(&mockCertRepository{}, keyRepo)
	err := svc.ValidateKeyOwnership(context.Background(), keyID, model.NewVaultScope(vaultID, userID))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "key not found")
}

// ────────────────────────────────────────────────────────────────────────────
// RenewCertificate – error branches
// ────────────────────────────────────────────────────────────────────────────

func TestRenewCertificate_NoKeyID(t *testing.T) {
	userID := uuid.New()
	certID := uuid.New()
	scope := model.NewOwnerScope(uuid.Nil, userID)
	certRepo := &mockCertRepository{}
	keyRepo := &mockKeyRepo{}

	certRepo.On("Read", mock.Anything, certID, scope).Return(&model.Certificate{
		ID:      certID,
		UserID:  userID,
		Enabled: true,
		KeyID:   uuid.Nil, // no key attached
	}, nil)

	svc := newCertSvc(certRepo, keyRepo)
	_, err := svc.RenewCertificate(context.Background(), certID, scope, 365)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no associated key ID")
}

func TestRenewCertificate_GetCertificateFails(t *testing.T) {
	userID := uuid.New()
	certID := uuid.New()
	scope := model.NewOwnerScope(uuid.Nil, userID)
	certRepo := &mockCertRepository{}
	keyRepo := &mockKeyRepo{}

	certRepo.On("Read", mock.Anything, certID, scope).Return(nil, errors.New("not found"))

	svc := newCertSvc(certRepo, keyRepo)
	_, err := svc.RenewCertificate(context.Background(), certID, scope, 365)
	require.Error(t, err)
}

// ────────────────────────────────────────────────────────────────────────────
// CreateSelfSignedCertificate – validation failures
// ────────────────────────────────────────────────────────────────────────────

func TestCreateSelfSignedCertificate_InvalidValidityDays(t *testing.T) {
	userID := uuid.New()
	certRepo := &mockCertRepository{}
	keyRepo := &mockKeyRepo{}

	svc := newCertSvc(certRepo, keyRepo)
	_, err := svc.CreateSelfSignedCertificate(context.Background(), CreateCertificateRequest{
		Name:         "test",
		KeyID:        uuid.New(),
		ValidityDays: 0, // invalid
		UserID:       userID,
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "validity days must be positive")
}

func TestCreateSelfSignedCertificate_KeyOwnershipFails(t *testing.T) {
	userID := uuid.New()
	keyID := uuid.New()
	certRepo := &mockCertRepository{}
	keyRepo := &mockKeyRepo{}

	keyRepo.On("Read", mock.Anything, keyID, certVaultScope(userID)).Return(nil, errors.New("key not found"))

	svc := newCertSvc(certRepo, keyRepo)
	_, err := svc.CreateSelfSignedCertificate(context.Background(), CreateCertificateRequest{
		Name:         "test",
		KeyID:        keyID,
		ValidityDays: 365,
		UserID:       userID,
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "key not found")
}

// ────────────────────────────────────────────────────────────────────────────
// CreateCASignedCertificate – validation failures
// ────────────────────────────────────────────────────────────────────────────

func TestCreateCASignedCertificate_NilCACertID_Panics(t *testing.T) {
	// Known production bug: CreateCASignedCertificate dereferences CACertID in the
	// logrus call (line 266 of certificate_service.go) before the nil guard on line 272.
	// This test documents the behaviour: passing nil CACertID causes a panic.
	userID := uuid.New()
	certRepo := &mockCertRepository{}
	keyRepo := &mockKeyRepo{}
	svc := newCertSvc(certRepo, keyRepo)
	require.Panics(t, func() {
		_, _ = svc.CreateCASignedCertificate(context.Background(), CreateCertificateRequest{
			Name:         "test",
			KeyID:        uuid.New(),
			ValidityDays: 365,
			UserID:       userID,
			CACertID:     nil,
		})
	})
}

func TestCreateCASignedCertificate_InvalidValidityDays(t *testing.T) {
	userID := uuid.New()
	caCertID := uuid.New()
	certRepo := &mockCertRepository{}
	keyRepo := &mockKeyRepo{}

	svc := newCertSvc(certRepo, keyRepo)
	_, err := svc.CreateCASignedCertificate(context.Background(), CreateCertificateRequest{
		Name:         "test",
		KeyID:        uuid.New(),
		ValidityDays: -1,
		UserID:       userID,
		CACertID:     &caCertID,
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "validity days must be positive")
}

func TestCreateCASignedCertificate_KeyOwnershipFails(t *testing.T) {
	userID := uuid.New()
	keyID := uuid.New()
	caCertID := uuid.New()
	certRepo := &mockCertRepository{}
	keyRepo := &mockKeyRepo{}

	keyRepo.On("Read", mock.Anything, keyID, certVaultScope(userID)).Return(nil, errors.New("key not found"))

	svc := newCertSvc(certRepo, keyRepo)
	_, err := svc.CreateCASignedCertificate(context.Background(), CreateCertificateRequest{
		Name:         "test",
		KeyID:        keyID,
		ValidityDays: 365,
		UserID:       userID,
		CACertID:     &caCertID,
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "key not found")
}

func TestCreateCASignedCertificate_CACertAccessFails(t *testing.T) {
	userID := uuid.New()
	keyID := uuid.New()
	caCertID := uuid.New()
	certRepo := &mockCertRepository{}
	keyRepo := &mockKeyRepo{}

	// key ownership succeeds
	keyRepo.On("Read", mock.Anything, keyID, certVaultScope(userID)).Return(&model.Key{
		ID:     keyID,
		UserID: userID,
	}, nil)
	// CA cert not found
	certRepo.On("Read", mock.Anything, caCertID, certVaultScope(userID)).Return(nil, errors.New("not found"))

	svc := newCertSvc(certRepo, keyRepo)
	_, err := svc.CreateCASignedCertificate(context.Background(), CreateCertificateRequest{
		Name:         "test",
		KeyID:        keyID,
		ValidityDays: 365,
		UserID:       userID,
		CACertID:     &caCertID,
	})
	require.Error(t, err)
	// access to CA cert fails → "cannot access CA certificate"
	assert.Contains(t, err.Error(), "cannot access CA certificate")
}

// ────────────────────────────────────────────────────────────────────────────
// CertificateRenewalScheduler
// ────────────────────────────────────────────────────────────────────────────

// mockRenewalSvc satisfies CertificateRenewalService for scheduler tests.
type mockRenewalSvc struct {
	mock.Mock
}

func (m *mockRenewalSvc) CheckAndRenewCertificates(ctx context.Context) (int, int, error) {
	args := m.Called(ctx)
	return args.Int(0), args.Int(1), args.Error(2)
}

func TestScheduler_StartStop(t *testing.T) {
	renewalSvc := &mockRenewalSvc{}
	// We use a very long interval so the ticker never fires during the test;
	// the check() called immediately on startup will execute once.
	renewalSvc.On("CheckAndRenewCertificates", mock.Anything).Return(0, 0, nil).Maybe()

	logger := newTestCertLogger()
	scheduler := NewCertificateRenewalScheduler(renewalSvc, logger, 24*time.Hour)

	ctx, cancel := context.WithCancel(context.Background())
	scheduler.Start(ctx)

	// Give the goroutine a moment to call check() on startup.
	time.Sleep(20 * time.Millisecond)

	scheduler.Stop()
	cancel()

	// No panic and scheduler stopped cleanly.
}

func TestScheduler_DefaultIntervalWhenZero(t *testing.T) {
	renewalSvc := &mockRenewalSvc{}
	renewalSvc.On("CheckAndRenewCertificates", mock.Anything).Return(0, 0, nil).Maybe()

	logger := newTestCertLogger()
	// Passing 0 interval should default to 24 hours (tested via construction only).
	scheduler := NewCertificateRenewalScheduler(renewalSvc, logger, 0)
	assert.NotNil(t, scheduler)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	scheduler.Start(ctx)
	time.Sleep(20 * time.Millisecond)
	scheduler.Stop()
}

func TestScheduler_ContextCancellation(t *testing.T) {
	renewalSvc := &mockRenewalSvc{}
	renewalSvc.On("CheckAndRenewCertificates", mock.Anything).Return(0, 0, nil).Maybe()

	logger := newTestCertLogger()
	scheduler := NewCertificateRenewalScheduler(renewalSvc, logger, 24*time.Hour)

	ctx, cancel := context.WithCancel(context.Background())
	scheduler.Start(ctx)
	time.Sleep(10 * time.Millisecond)
	cancel() // cancel context instead of Stop()
	time.Sleep(20 * time.Millisecond)
	// goroutine should have exited; no assertion needed beyond no deadlock.
}

func TestScheduler_CheckLogsRenewalResults(t *testing.T) {
	renewalSvc := &mockRenewalSvc{}
	// Return non-zero counts so the log branch is exercised.
	renewalSvc.On("CheckAndRenewCertificates", mock.Anything).Return(2, 1, nil).Once()
	renewalSvc.On("CheckAndRenewCertificates", mock.Anything).Return(0, 0, nil).Maybe()

	logger := newTestCertLogger()
	scheduler := NewCertificateRenewalScheduler(renewalSvc, logger, 24*time.Hour)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	scheduler.Start(ctx)
	time.Sleep(30 * time.Millisecond)
	scheduler.Stop()
	// The first check (startup) should have exercised the renewed>0 || warned>0 branch.
}

func TestScheduler_CheckLogsError(t *testing.T) {
	renewalSvc := &mockRenewalSvc{}
	renewalSvc.On("CheckAndRenewCertificates", mock.Anything).
		Return(0, 0, errors.New("renewal error")).Maybe()

	logger := newTestCertLogger()
	scheduler := NewCertificateRenewalScheduler(renewalSvc, logger, 24*time.Hour)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	scheduler.Start(ctx)
	time.Sleep(30 * time.Millisecond)
	scheduler.Stop()
	// Scheduler must not panic when renewal service returns an error.
}

// ────────────────────────────────────────────────────────────────────────────
// CheckAndRenewCertificates – remaining branches
// ────────────────────────────────────────────────────────────────────────────

// mockRenewalCertSvc is a CertificateService mock for renewal service tests.
type mockRenewalCertSvc struct{ mock.Mock }

func (m *mockRenewalCertSvc) CreateSelfSignedCertificate(ctx context.Context, req CreateCertificateRequest) (*CreateCertificateResult, error) {
	panic("not called")
}
func (m *mockRenewalCertSvc) CreateCASignedCertificate(ctx context.Context, req CreateCertificateRequest) (*CreateCertificateResult, error) {
	panic("not called")
}
func (m *mockRenewalCertSvc) GetCertificate(ctx context.Context, certID uuid.UUID, scope model.Scope) (*model.Certificate, error) {
	panic("not called")
}
func (m *mockRenewalCertSvc) ListCertificates(ctx context.Context, scope model.Scope, filter repositories.CertificateFilter) ([]model.Certificate, error) {
	panic("not called")
}
func (m *mockRenewalCertSvc) UpdateCertificate(ctx context.Context, req UpdateCertificateRequest) error {
	panic("not called")
}
func (m *mockRenewalCertSvc) DeleteCertificate(ctx context.Context, certID uuid.UUID, scope model.Scope) error {
	panic("not called")
}
func (m *mockRenewalCertSvc) RenewCertificate(ctx context.Context, certID uuid.UUID, scope model.Scope, validityDays int) (*CreateCertificateResult, error) {
	args := m.Called(ctx, certID, scope, validityDays)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*CreateCertificateResult), args.Error(1)
}
func (m *mockRenewalCertSvc) ValidateCertificateAccess(ctx context.Context, certID uuid.UUID, scope model.Scope) error {
	panic("not called")
}
func (m *mockRenewalCertSvc) ValidateKeyOwnership(ctx context.Context, keyID uuid.UUID, scope model.Scope) error {
	panic("not called")
}
func (m *mockRenewalCertSvc) ListDeletedCertificates(ctx context.Context, scope model.Scope) ([]model.Certificate, error) {
	panic("not called")
}
func (m *mockRenewalCertSvc) RecoverCertificate(ctx context.Context, certID uuid.UUID, scope model.Scope) error {
	panic("not called")
}
func (m *mockRenewalCertSvc) PurgeCertificate(ctx context.Context, certID uuid.UUID, scope model.Scope) error {
	panic("not called")
}
func (m *mockRenewalCertSvc) GetCertificatePolicy(ctx context.Context, certID uuid.UUID, scope model.Scope) (*model.CertificatePolicy, error) {
	panic("not called")
}
func (m *mockRenewalCertSvc) UpsertCertificatePolicy(ctx context.Context, certID uuid.UUID, scope model.Scope, req model.UpsertCertificatePolicyRequest) (*model.CertificatePolicy, error) {
	panic("not called")
}
func (m *mockRenewalCertSvc) DeleteCertificatePolicy(ctx context.Context, certID uuid.UUID, scope model.Scope) error {
	panic("not called")
}
func (m *mockRenewalCertSvc) ListCertificatePolicies(ctx context.Context, scope model.Scope) ([]model.CertificatePolicyWithCertName, error) {
	panic("not called")
}
func (m *mockRenewalCertSvc) ListCertificatesDueForRenewal(ctx context.Context, scope model.Scope) ([]model.Certificate, error) {
	panic("not called")
}

func TestCheckAndRenewCertificates_ListAllFails(t *testing.T) {
	repo := &mockCertRepository{}
	repo.On("ListAll", mock.Anything).Return(nil, errors.New("db error"))

	svc := NewCertificateRenewalService(RenewalServiceConfig{
		CertRepository:     repo,
		CertificateService: &mockRenewalCertSvc{},
		Logger:             newTestCertLogger(),
	})

	_, _, err := svc.CheckAndRenewCertificates(context.Background())
	require.Error(t, err)
}

func TestCheckAndRenewCertificates_NilExpiresAtSkipped(t *testing.T) {
	repo := &mockCertRepository{}
	repo.On("ListAll", mock.Anything).Return([]model.Certificate{
		{ID: uuid.New(), UserID: uuid.New(), Name: "no-expiry", ExpiresAt: nil},
	}, nil)

	svc := NewCertificateRenewalService(RenewalServiceConfig{
		CertRepository:     repo,
		CertificateService: &mockRenewalCertSvc{},
		Logger:             newTestCertLogger(),
	})

	renewed, warned, err := svc.CheckAndRenewCertificates(context.Background())
	require.NoError(t, err)
	assert.Equal(t, 0, renewed)
	assert.Equal(t, 0, warned)
}

func TestCheckAndRenewCertificates_AlreadyExpiredSkipped(t *testing.T) {
	past := time.Now().Add(-24 * time.Hour)
	repo := &mockCertRepository{}
	repo.On("ListAll", mock.Anything).Return([]model.Certificate{
		{ID: uuid.New(), UserID: uuid.New(), Name: "expired", ExpiresAt: &past},
	}, nil)

	svc := NewCertificateRenewalService(RenewalServiceConfig{
		CertRepository:     repo,
		CertificateService: &mockRenewalCertSvc{},
		Logger:             newTestCertLogger(),
	})

	renewed, warned, err := svc.CheckAndRenewCertificates(context.Background())
	require.NoError(t, err)
	assert.Equal(t, 0, renewed)
	assert.Equal(t, 0, warned)
}

func TestCheckAndRenewCertificates_OutsideWindowSkipped(t *testing.T) {
	// Expires in 90 days, renewal window is 30 days → no action needed.
	farFuture := time.Now().Add(90 * 24 * time.Hour)
	repo := &mockCertRepository{}
	repo.On("ListAll", mock.Anything).Return([]model.Certificate{
		{
			ID: uuid.New(), UserID: uuid.New(), Name: "not-due",
			ExpiresAt:   &farFuture,
			AutoRenew:   true,
			RenewalDays: 30,
		},
	}, nil)

	certSvc := &mockRenewalCertSvc{}
	svc := NewCertificateRenewalService(RenewalServiceConfig{
		CertRepository:     repo,
		CertificateService: certSvc,
		Logger:             newTestCertLogger(),
	})

	renewed, warned, err := svc.CheckAndRenewCertificates(context.Background())
	require.NoError(t, err)
	assert.Equal(t, 0, renewed)
	assert.Equal(t, 0, warned)
	certSvc.AssertNotCalled(t, "RenewCertificate")
}

func TestCheckAndRenewCertificates_AutoRenewFailureSkipped(t *testing.T) {
	expires := time.Now().Add(10 * 24 * time.Hour)
	certID := uuid.New()
	userID := uuid.New()

	repo := &mockCertRepository{}
	repo.On("ListAll", mock.Anything).Return([]model.Certificate{
		{
			ID:          certID,
			UserID:      userID,
			Name:        "failing",
			CreatedAt:   time.Now().Add(-365 * 24 * time.Hour),
			ExpiresAt:   &expires,
			AutoRenew:   true,
			RenewalDays: 30,
		},
	}, nil)

	certSvc := &mockRenewalCertSvc{}
	certSvc.On("RenewCertificate", mock.Anything, certID, model.NewAdminScope(userID), mock.AnythingOfType("int")).
		Return(nil, errors.New("renewal failed"))

	svc := NewCertificateRenewalService(RenewalServiceConfig{
		CertRepository:     repo,
		CertificateService: certSvc,
		Logger:             newTestCertLogger(),
	})

	renewed, warned, err := svc.CheckAndRenewCertificates(context.Background())
	require.NoError(t, err)
	assert.Equal(t, 0, renewed) // failure is skipped, not counted
	assert.Equal(t, 0, warned)
	certSvc.AssertExpectations(t)
}

func TestCheckAndRenewCertificates_DefaultRenewalDays(t *testing.T) {
	// RenewalDays == 0 should default to 30; cert expiring in 10 days → warn.
	expires := time.Now().Add(10 * 24 * time.Hour)
	repo := &mockCertRepository{}
	repo.On("ListAll", mock.Anything).Return([]model.Certificate{
		{
			ID:          uuid.New(),
			UserID:      uuid.New(),
			Name:        "default-renewal",
			ExpiresAt:   &expires,
			AutoRenew:   false,
			RenewalDays: 0, // zero → defaults to 30
		},
	}, nil)

	certSvc := &mockRenewalCertSvc{}
	svc := NewCertificateRenewalService(RenewalServiceConfig{
		CertRepository:     repo,
		CertificateService: certSvc,
		Logger:             newTestCertLogger(),
	})

	renewed, warned, err := svc.CheckAndRenewCertificates(context.Background())
	require.NoError(t, err)
	assert.Equal(t, 0, renewed)
	assert.Equal(t, 1, warned)
}

// ────────────────────────────────────────────────────────────────────────────
// CreateSelfSignedCertificate – full success paths (real crypto)
// ────────────────────────────────────────────────────────────────────────────

func setupMasterKey() {
	k := make([]byte, 32)
	for i := range k {
		k[i] = byte(i + 1)
	}
	viper.Set("master_key", base64.StdEncoding.EncodeToString(k))
}

func TestCreateSelfSignedCertificate_SuccessDefaultRenewalDays(t *testing.T) {
	setupMasterKey()

	userID := uuid.New()
	keyID := uuid.New()

	privateKeyPEM, err := crypto.GenerateRSAKeyPEM(2048)
	require.NoError(t, err)

	encryptedKey, err := common.EncryptSecret(privateKeyPEM)
	require.NoError(t, err)

	certRepo := &mockCertRepository{}
	keyRepo := &mockKeyRepo{}

	keyRepo.On("Read", mock.Anything, keyID, certVaultScope(userID)).Return(&model.Key{
		ID:     keyID,
		UserID: userID,
		Type:   model.KeyTypeRSA,
		Value:  encryptedKey,
	}, nil)
	certRepo.On("Create", mock.Anything, mock.AnythingOfType("*model.Certificate")).Return(nil)

	svc := newCertSvc(certRepo, keyRepo)
	result, err := svc.CreateSelfSignedCertificate(context.Background(), CreateCertificateRequest{
		Name:         "self-signed-test",
		KeyID:        keyID,
		ValidityDays: 90,
		UserID:       userID,
		RenewalDays:  0, // should default to 30
	})
	require.NoError(t, err)
	assert.NotNil(t, result)
	assert.Equal(t, "self-signed-test", result.Name)
	assert.NotNil(t, result.ExpiresAt)
	certRepo.AssertExpectations(t)
	keyRepo.AssertExpectations(t)
}

func TestCreateSelfSignedCertificate_SuccessWithExplicitEnabled(t *testing.T) {
	setupMasterKey()

	userID := uuid.New()
	keyID := uuid.New()

	privateKeyPEM, err := crypto.GenerateRSAKeyPEM(2048)
	require.NoError(t, err)

	encryptedKey, err := common.EncryptSecret(privateKeyPEM)
	require.NoError(t, err)

	certRepo := &mockCertRepository{}
	keyRepo := &mockKeyRepo{}

	keyRepo.On("Read", mock.Anything, keyID, certVaultScope(userID)).Return(&model.Key{
		ID:     keyID,
		UserID: userID,
		Type:   model.KeyTypeRSA,
		Value:  encryptedKey,
	}, nil)

	var createdCert *model.Certificate
	certRepo.On("Create", mock.Anything, mock.AnythingOfType("*model.Certificate")).
		Run(func(args mock.Arguments) {
			createdCert = args.Get(1).(*model.Certificate)
		}).Return(nil)

	disabled := false
	svc := newCertSvc(certRepo, keyRepo)
	result, err := svc.CreateSelfSignedCertificate(context.Background(), CreateCertificateRequest{
		Name:         "disabled-cert",
		KeyID:        keyID,
		ValidityDays: 30,
		UserID:       userID,
		RenewalDays:  60,
		Enabled:      &disabled,
		AutoRenew:    true,
	})
	require.NoError(t, err)
	assert.NotNil(t, result)
	require.NotNil(t, createdCert)
	assert.False(t, createdCert.Enabled)
	assert.Equal(t, 60, createdCert.RenewalDays)
	assert.True(t, createdCert.AutoRenew)
}

func TestCreateSelfSignedCertificate_SuccessWithVaultID(t *testing.T) {
	setupMasterKey()

	userID := uuid.New()
	keyID := uuid.New()
	vaultID := uuid.New()

	privateKeyPEM, err := crypto.GenerateRSAKeyPEM(2048)
	require.NoError(t, err)

	encryptedKey, err := common.EncryptSecret(privateKeyPEM)
	require.NoError(t, err)

	certRepo := &mockCertRepository{}
	keyRepo := &mockKeyRepo{}

	keyRepo.On("Read", mock.Anything, keyID, certVaultScope(userID)).Return(&model.Key{
		ID:     keyID,
		UserID: userID,
		Type:   model.KeyTypeRSA,
		Value:  encryptedKey,
	}, nil)

	var createdCert *model.Certificate
	certRepo.On("Create", mock.Anything, mock.AnythingOfType("*model.Certificate")).
		Run(func(args mock.Arguments) {
			createdCert = args.Get(1).(*model.Certificate)
		}).Return(nil)

	svc := newCertSvc(certRepo, keyRepo)
	result, err := svc.CreateSelfSignedCertificate(context.Background(), CreateCertificateRequest{
		Name:         "vaulted-cert",
		KeyID:        keyID,
		ValidityDays: 365,
		UserID:       userID,
		VaultID:      vaultID,
	})
	require.NoError(t, err)
	assert.NotNil(t, result)
	require.NotNil(t, createdCert)
	assert.Equal(t, vaultID, createdCert.VaultID)
}

func TestCreateSelfSignedCertificate_RepoCreateFails(t *testing.T) {
	setupMasterKey()

	userID := uuid.New()
	keyID := uuid.New()

	privateKeyPEM, err := crypto.GenerateRSAKeyPEM(2048)
	require.NoError(t, err)

	encryptedKey, err := common.EncryptSecret(privateKeyPEM)
	require.NoError(t, err)

	certRepo := &mockCertRepository{}
	keyRepo := &mockKeyRepo{}

	keyRepo.On("Read", mock.Anything, keyID, certVaultScope(userID)).Return(&model.Key{
		ID:     keyID,
		UserID: userID,
		Type:   model.KeyTypeRSA,
		Value:  encryptedKey,
	}, nil)
	certRepo.On("Create", mock.Anything, mock.AnythingOfType("*model.Certificate")).
		Return(errors.New("db write error"))

	svc := newCertSvc(certRepo, keyRepo)
	_, err = svc.CreateSelfSignedCertificate(context.Background(), CreateCertificateRequest{
		Name:         "fail-cert",
		KeyID:        keyID,
		ValidityDays: 30,
		UserID:       userID,
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to store self-signed certificate")
}

func TestCreateSelfSignedCertificate_KeyReadFails(t *testing.T) {
	setupMasterKey()

	userID := uuid.New()
	keyID := uuid.New()

	certRepo := &mockCertRepository{}
	keyRepo := &mockKeyRepo{}

	// ValidateKeyOwnership passes (user is owner), then keyRepo.Read called again for key material
	keyRepo.On("Read", mock.Anything, keyID, certVaultScope(userID)).Return(&model.Key{
		ID:     keyID,
		UserID: userID,
		Type:   model.KeyTypeRSA,
		Value:  "not-valid-encrypted-data",
	}, nil)

	svc := newCertSvc(certRepo, keyRepo)
	_, err := svc.CreateSelfSignedCertificate(context.Background(), CreateCertificateRequest{
		Name:         "err-cert",
		KeyID:        keyID,
		ValidityDays: 30,
		UserID:       userID,
	})
	require.Error(t, err)
}

// ────────────────────────────────────────────────────────────────────────────
// CreateCASignedCertificate – deeper coverage
// ────────────────────────────────────────────────────────────────────────────

func TestCreateCASignedCertificate_FullSuccess(t *testing.T) {
	setupMasterKey()

	userID := uuid.New()
	keyID := uuid.New()
	caCertID := uuid.New()

	// Generate two RSA keys: one for the end-entity cert, one for the CA.
	entityKeyPEM, err := crypto.GenerateRSAKeyPEM(2048)
	require.NoError(t, err)
	caKeyPEM, err := crypto.GenerateRSAKeyPEM(2048)
	require.NoError(t, err)

	// Create self-signed CA cert using the CA key.
	caCertPEM, err := crypto.CreateSelfSignedCertificatePEM(caKeyPEM, "RSA", crypto.CertificateTemplate{
		CommonName:   "Test CA",
		ValidityDays: 3650,
		IsCA:         true,
	})
	require.NoError(t, err)

	encryptedEntityKey, err := common.EncryptSecret(entityKeyPEM)
	require.NoError(t, err)
	encryptedCAKey, err := common.EncryptSecret(caKeyPEM)
	require.NoError(t, err)

	entityKey := &model.Key{ID: keyID, UserID: userID, Type: model.KeyTypeRSA, Value: encryptedEntityKey}
	caCert := &model.Certificate{
		ID:          caCertID,
		UserID:      userID,
		Name:        "test-ca",
		Certificate: caCertPEM,
		PrivateKey:  encryptedCAKey,
		Enabled:     true,
	}

	certRepo := &mockCertRepository{}
	keyRepo := &mockKeyRepo{}

	keyRepo.On("Read", mock.Anything, keyID, certVaultScope(userID)).Return(entityKey, nil)
	// ValidateCertificateAccess calls certRepo.Read for the CA cert
	certRepo.On("Read", mock.Anything, caCertID, certVaultScope(userID)).Return(caCert, nil)
	certRepo.On("Create", mock.Anything, mock.AnythingOfType("*model.Certificate")).Return(nil)

	svc := newCertSvc(certRepo, keyRepo)
	result, err := svc.CreateCASignedCertificate(context.Background(), CreateCertificateRequest{
		Name:         "entity-cert",
		KeyID:        keyID,
		ValidityDays: 365,
		UserID:       userID,
		CACertID:     &caCertID,
		RenewalDays:  0, // default to 30
		AutoRenew:    true,
	})
	require.NoError(t, err)
	assert.NotNil(t, result)
	assert.Equal(t, "entity-cert", result.Name)
	assert.NotNil(t, result.ExpiresAt)
}

// The CA link must be stored, or renewal has nothing to branch on (B37).
func TestCreateCASignedCertificate_StoresCACertID(t *testing.T) {
	setupMasterKey()

	userID := uuid.New()
	keyID := uuid.New()
	caCertID := uuid.New()

	entityKeyPEM, err := crypto.GenerateRSAKeyPEM(2048)
	require.NoError(t, err)
	caKeyPEM, err := crypto.GenerateRSAKeyPEM(2048)
	require.NoError(t, err)

	caCertPEM, err := crypto.CreateSelfSignedCertificatePEM(caKeyPEM, "RSA", crypto.CertificateTemplate{
		CommonName: "Test CA", ValidityDays: 3650, IsCA: true,
	})
	require.NoError(t, err)

	encEntity, err := common.EncryptSecret(entityKeyPEM)
	require.NoError(t, err)
	encCA, err := common.EncryptSecret(caKeyPEM)
	require.NoError(t, err)

	certRepo := &mockCertRepository{}
	keyRepo := &mockKeyRepo{}

	keyRepo.On("Read", mock.Anything, keyID, certVaultScope(userID)).
		Return(&model.Key{ID: keyID, UserID: userID, Type: model.KeyTypeRSA, Value: encEntity}, nil)
	certRepo.On("Read", mock.Anything, caCertID, certVaultScope(userID)).
		Return(&model.Certificate{
			ID: caCertID, UserID: userID, Name: "test-ca",
			Certificate: caCertPEM, PrivateKey: encCA, Enabled: true,
		}, nil)

	var created *model.Certificate
	certRepo.On("Create", mock.Anything, mock.AnythingOfType("*model.Certificate")).
		Run(func(args mock.Arguments) { created = args.Get(1).(*model.Certificate) }).
		Return(nil)

	svc := newCertSvc(certRepo, keyRepo)
	_, err = svc.CreateCASignedCertificate(context.Background(), CreateCertificateRequest{
		Name: "entity-cert", KeyID: keyID, ValidityDays: 365,
		UserID: userID, CACertID: &caCertID,
	})
	require.NoError(t, err)
	require.NotNil(t, created)
	require.NotNil(t, created.CACertID, "a CA-signed certificate must record its CA")
	assert.Equal(t, caCertID, *created.CACertID)
}

// An ECDSA CA used to be sent down the RSA parsing path, because the CA key
// type was hardcoded as "RSA" (B37, related finding).
func TestCreateCASignedCertificate_ECDSACA(t *testing.T) {
	setupMasterKey()

	userID := uuid.New()
	keyID := uuid.New()
	caCertID := uuid.New()

	entityKeyPEM, err := crypto.GenerateRSAKeyPEM(2048)
	require.NoError(t, err)
	caKeyPEM, err := crypto.GenerateECDSAKeyPEM("P-256")
	require.NoError(t, err)

	caCertPEM, err := crypto.CreateSelfSignedCertificatePEM(caKeyPEM, "ECDSA", crypto.CertificateTemplate{
		CommonName: "ECDSA CA", ValidityDays: 3650, IsCA: true,
	})
	require.NoError(t, err)

	encEntity, err := common.EncryptSecret(entityKeyPEM)
	require.NoError(t, err)
	encCA, err := common.EncryptSecret(caKeyPEM)
	require.NoError(t, err)

	certRepo := &mockCertRepository{}
	keyRepo := &mockKeyRepo{}

	keyRepo.On("Read", mock.Anything, keyID, certVaultScope(userID)).
		Return(&model.Key{ID: keyID, UserID: userID, Type: model.KeyTypeRSA, Value: encEntity}, nil)
	certRepo.On("Read", mock.Anything, caCertID, certVaultScope(userID)).
		Return(&model.Certificate{
			ID: caCertID, UserID: userID, Name: "ecdsa-ca",
			Certificate: caCertPEM, PrivateKey: encCA, Enabled: true,
		}, nil)

	var created *model.Certificate
	certRepo.On("Create", mock.Anything, mock.AnythingOfType("*model.Certificate")).
		Run(func(args mock.Arguments) { created = args.Get(1).(*model.Certificate) }).
		Return(nil)

	svc := newCertSvc(certRepo, keyRepo)
	_, err = svc.CreateCASignedCertificate(context.Background(), CreateCertificateRequest{
		Name: "entity-cert", KeyID: keyID, ValidityDays: 365,
		UserID: userID, CACertID: &caCertID,
	})
	require.NoError(t, err)
	require.NotNil(t, created)

	// The issuer must be the ECDSA CA, and the CA's public key must verify the
	// leaf's signature.
	assertSignedBy(t, created.Certificate, caCertPEM, "ECDSA CA")
}

func TestCreateCASignedCertificate_RepoCreateFails(t *testing.T) {
	setupMasterKey()

	userID := uuid.New()
	keyID := uuid.New()
	caCertID := uuid.New()

	entityKeyPEM, err := crypto.GenerateRSAKeyPEM(2048)
	require.NoError(t, err)
	caKeyPEM, err := crypto.GenerateRSAKeyPEM(2048)
	require.NoError(t, err)

	caCertPEM, err := crypto.CreateSelfSignedCertificatePEM(caKeyPEM, "RSA", crypto.CertificateTemplate{
		CommonName:   "Test CA",
		ValidityDays: 3650,
		IsCA:         true,
	})
	require.NoError(t, err)

	encryptedEntityKey, err := common.EncryptSecret(entityKeyPEM)
	require.NoError(t, err)
	encryptedCAKey, err := common.EncryptSecret(caKeyPEM)
	require.NoError(t, err)

	entityKey := &model.Key{ID: keyID, UserID: userID, Type: model.KeyTypeRSA, Value: encryptedEntityKey}
	caCert := &model.Certificate{
		ID: caCertID, UserID: userID, Name: "test-ca",
		Certificate: caCertPEM, PrivateKey: encryptedCAKey, Enabled: true,
	}

	certRepo := &mockCertRepository{}
	keyRepo := &mockKeyRepo{}

	keyRepo.On("Read", mock.Anything, keyID, certVaultScope(userID)).Return(entityKey, nil)
	certRepo.On("Read", mock.Anything, caCertID, certVaultScope(userID)).Return(caCert, nil)
	certRepo.On("Create", mock.Anything, mock.AnythingOfType("*model.Certificate")).
		Return(errors.New("db write error"))

	svc := newCertSvc(certRepo, keyRepo)
	_, err = svc.CreateCASignedCertificate(context.Background(), CreateCertificateRequest{
		Name: "failing-entity", KeyID: keyID, ValidityDays: 365,
		UserID: userID, CACertID: &caCertID,
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to store CA-signed certificate")
}

func TestCreateCASignedCertificate_WithExplicitEnabledFalse(t *testing.T) {
	setupMasterKey()

	userID := uuid.New()
	keyID := uuid.New()
	caCertID := uuid.New()

	entityKeyPEM, err := crypto.GenerateRSAKeyPEM(2048)
	require.NoError(t, err)
	caKeyPEM, err := crypto.GenerateRSAKeyPEM(2048)
	require.NoError(t, err)

	caCertPEM, err := crypto.CreateSelfSignedCertificatePEM(caKeyPEM, "RSA", crypto.CertificateTemplate{
		CommonName: "CA", ValidityDays: 3650, IsCA: true,
	})
	require.NoError(t, err)

	encEntity, _ := common.EncryptSecret(entityKeyPEM)
	encCA, _ := common.EncryptSecret(caKeyPEM)

	entityKey := &model.Key{ID: keyID, UserID: userID, Type: model.KeyTypeRSA, Value: encEntity}
	caCert := &model.Certificate{
		ID: caCertID, UserID: userID, Name: "ca",
		Certificate: caCertPEM, PrivateKey: encCA, Enabled: true,
	}

	certRepo := &mockCertRepository{}
	keyRepo := &mockKeyRepo{}

	keyRepo.On("Read", mock.Anything, keyID, certVaultScope(userID)).Return(entityKey, nil)
	certRepo.On("Read", mock.Anything, caCertID, certVaultScope(userID)).Return(caCert, nil)

	var createdCert *model.Certificate
	certRepo.On("Create", mock.Anything, mock.AnythingOfType("*model.Certificate")).
		Run(func(args mock.Arguments) { createdCert = args.Get(1).(*model.Certificate) }).
		Return(nil)

	disabled := false
	svc := newCertSvc(certRepo, keyRepo)
	result, err := svc.CreateCASignedCertificate(context.Background(), CreateCertificateRequest{
		Name: "entity", KeyID: keyID, ValidityDays: 365,
		UserID: userID, CACertID: &caCertID,
		RenewalDays: 90,
		Enabled:     &disabled,
	})
	require.NoError(t, err)
	assert.NotNil(t, result)
	require.NotNil(t, createdCert)
	assert.False(t, createdCert.Enabled)
	assert.Equal(t, 90, createdCert.RenewalDays)
}

// ────────────────────────────────────────────────────────────────────────────
// extractExpiresAt – invalid PEM
// ────────────────────────────────────────────────────────────────────────────

func TestExtractExpiresAt_InvalidPEM(t *testing.T) {
	_, err := extractExpiresAt("not-a-pem")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to decode PEM block")
}

func TestExtractExpiresAt_ValidCert(t *testing.T) {
	privateKeyPEM, err := crypto.GenerateRSAKeyPEM(2048)
	require.NoError(t, err)

	certPEM, err := crypto.CreateSelfSignedCertificatePEM(privateKeyPEM, "RSA", crypto.CertificateTemplate{
		CommonName:   "test",
		ValidityDays: 30,
		IsCA:         false,
	})
	require.NoError(t, err)

	expiresAt, err := extractExpiresAt(certPEM)
	require.NoError(t, err)
	assert.NotNil(t, expiresAt)
	assert.True(t, expiresAt.After(time.Now()))
}

func (m *mockRenewalCertSvc) ListCertificateVersions(ctx context.Context, certID uuid.UUID, scope model.Scope) ([]model.CertificateVersion, error) {
	panic("not called")
}
func (m *mockRenewalCertSvc) GetCertificateVersion(ctx context.Context, certID uuid.UUID, version int, scope model.Scope) (*model.CertificateVersion, error) {
	panic("not called")
}
func (m *mockRenewalCertSvc) UpdateCertificateVersion(ctx context.Context, req UpdateCertificateVersionRequest) (*model.CertificateVersion, error) {
	panic("not called")
}

func (m *mockRenewalCertSvc) ExportCertificate(context.Context, model.Scope, uuid.UUID, ExportCertificateRequest) (*ExportCertificateResult, error) {
	panic("not called")
}
