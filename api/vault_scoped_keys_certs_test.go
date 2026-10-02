// Package api — tests that legacy flat key/certificate routes use per-user
// visibility while explicit vault-scoped routes use vault-level visibility.
package api

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"github.com/stretchr/testify/mock"

	"rocketvault/app"
	"rocketvault/internal/repositories"
	certServices "rocketvault/internal/services/certificates"
	keyServices "rocketvault/internal/services/keys"
	vaultServices "rocketvault/internal/services/vaults"
	"rocketvault/model"
)

// recordingKeyService records which list/get method was called and with what
// scope. The legacy flat route must call the user-scoped ListKeys/GetKey; the
// vault-scoped route must call ListKeysInVault/GetKeyInVault. Unused methods
// panic so an accidental call surfaces immediately.
type recordingKeyService struct {
	listCalled     bool
	listUserScoped bool
	listUserID     uuid.UUID
	listVaultID    uuid.UUID
	getCalled      bool
	getUserScoped  bool

	updateCalled      bool
	updateVaultScoped bool
	updateVaultID     uuid.UUID
	updateUserID      uuid.UUID

	deleteCalled bool
	deleteScope  model.Scope

	exportScope model.Scope
}

func (s *recordingKeyService) CreateRSAKey(context.Context, keyServices.CreateKeyRequest) (*keyServices.CreateKeyResult, error) {
	panic("unexpected")
}
func (s *recordingKeyService) CreateECDSAKey(context.Context, keyServices.CreateKeyRequest) (*keyServices.CreateKeyResult, error) {
	panic("unexpected")
}
func (s *recordingKeyService) CreateOctKey(context.Context, keyServices.CreateKeyRequest) (*keyServices.CreateKeyResult, error) {
	panic("unexpected")
}
func (s *recordingKeyService) ImportKey(context.Context, keyServices.ImportKeyRequest) (*keyServices.CreateKeyResult, error) {
	panic("unexpected")
}
func (s *recordingKeyService) RotateKey(context.Context, uuid.UUID, model.Scope) (*keyServices.CreateKeyResult, error) {
	panic("unexpected")
}
func (s *recordingKeyService) ValidateKeyAccess(context.Context, uuid.UUID, uuid.UUID, string) error {
	panic("unexpected")
}
func (s *recordingKeyService) GetKey(_ context.Context, _ uuid.UUID, scope model.Scope) (*model.Key, error) {
	s.getCalled = true
	s.getUserScoped = scope.Kind() == model.ScopeOwner
	s.listUserID = scope.ActorID()
	s.listVaultID = scope.VaultID()
	return &model.Key{ID: uuid.New(), Name: "k", Type: model.KeyTypeRSA, UserID: scope.ActorID()}, nil
}
func (s *recordingKeyService) ListKeys(_ context.Context, scope model.Scope, _ repositories.KeyFilter) ([]model.Key, error) {
	s.listCalled = true
	s.listUserScoped = scope.Kind() == model.ScopeOwner
	s.listUserID = scope.ActorID()
	s.listVaultID = scope.VaultID()
	return []model.Key{}, nil
}
func (s *recordingKeyService) UpdateKey(_ context.Context, req keyServices.UpdateKeyRequest) error {
	s.updateCalled = true
	s.updateVaultScoped = req.Scope.Kind() == model.ScopeVault
	s.updateVaultID = req.Scope.VaultID()
	s.updateUserID = req.Scope.ActorID()
	return nil
}
func (s *recordingKeyService) DeleteKey(_ context.Context, keyID uuid.UUID, scope model.Scope) (*model.Key, error) {
	s.deleteCalled = true
	s.deleteScope = scope
	return &model.Key{ID: keyID, Name: "k"}, nil
}
func (s *recordingKeyService) ListDeletedKeys(context.Context, model.Scope) ([]model.Key, error) {
	panic("unexpected")
}
func (s *recordingKeyService) RecoverKey(context.Context, uuid.UUID, model.Scope) error {
	panic("unexpected")
}
func (s *recordingKeyService) PurgeKey(context.Context, uuid.UUID, model.Scope) error {
	panic("unexpected")
}
func (s *recordingKeyService) GetKeyRotationPolicy(context.Context, uuid.UUID, model.Scope) (*model.KeyRotationPolicy, error) {
	panic("unexpected")
}
func (s *recordingKeyService) UpsertKeyRotationPolicy(context.Context, uuid.UUID, model.Scope, model.UpsertKeyRotationPolicyRequest) (*model.KeyRotationPolicy, error) {
	panic("unexpected")
}
func (s *recordingKeyService) DeleteKeyRotationPolicy(context.Context, uuid.UUID, model.Scope) error {
	panic("unexpected")
}
func (s *recordingKeyService) ListKeyRotationPolicies(context.Context, model.Scope) ([]model.KeyRotationPolicyWithKeyName, error) {
	panic("unexpected")
}
func (s *recordingKeyService) ListDueKeyRotationPolicies(context.Context, model.Scope) ([]model.KeyRotationPolicy, error) {
	panic("unexpected")
}
func (s *recordingKeyService) ListKeyVersions(context.Context, uuid.UUID, model.Scope) ([]model.KeyVersion, error) {
	panic("unexpected")
}
func (s *recordingKeyService) GetKeyVersion(context.Context, uuid.UUID, int, model.Scope) (*model.KeyVersion, error) {
	panic("unexpected")
}
func (s *recordingKeyService) GetPublicJWK(context.Context, uuid.UUID, int, model.Scope) (*model.PublicJWK, error) {
	// These tests exercise routing and authorization, not response bodies, and
	// keyJWK tolerates an error by omitting the components.
	return nil, errors.New("not used in these tests")
}
func (s *recordingKeyService) ExportKey(_ context.Context, scope model.Scope, id uuid.UUID, version int) (*keyServices.ExportKeyResult, error) {
	s.exportScope = scope
	return &keyServices.ExportKeyResult{ID: id, Name: "k", Type: "RSA", Version: 1, Format: "pem",
		PrivateKeyPEM: "key", KeyAlgorithm: "RSA-2048"}, nil
}

// recordingCertService records which list/get method was called and with what
// scope, mirroring recordingKeyService for certificates.
type recordingCertService struct {
	listCalled     bool
	listUserScoped bool
	listUserID     uuid.UUID
	listVaultID    uuid.UUID
	getCalled      bool
	getUserScoped  bool

	updateCalled      bool
	updateVaultScoped bool
	updateVaultID     uuid.UUID
	updateUserID      uuid.UUID

	// getInVaultErr, when set, is returned by GetCertificateInVault instead of
	// a synthetic certificate -- simulates the vault-membership pre-check
	// failing (e.g. the certificate does not belong to the resolved vault).
	getInVaultErr error

	// policyRepo backs the certificate-policy methods below, mirroring the
	// real CertificateService's "verify cert access, then delegate to the
	// policy repository" flow.
	policyRepo repositories.CertificatePolicyRepositoryInterface

	// versionCalls and versionScope record the version operations and the
	// scope they were dispatched with, for the route-shape tests.
	versionCalls []string
	versionScope model.Scope
}

func (s *recordingCertService) CreateSelfSignedCertificate(context.Context, certServices.CreateCertificateRequest) (*certServices.CreateCertificateResult, error) {
	panic("unexpected")
}
func (s *recordingCertService) CreateCASignedCertificate(context.Context, certServices.CreateCertificateRequest) (*certServices.CreateCertificateResult, error) {
	panic("unexpected")
}
func (s *recordingCertService) UpdateCertificate(_ context.Context, req certServices.UpdateCertificateRequest) error {
	s.updateCalled = true
	s.updateVaultScoped = req.Scope.Kind() == model.ScopeVault
	s.updateVaultID = req.Scope.VaultID()
	s.updateUserID = req.Scope.ActorID()
	return nil
}
func (s *recordingCertService) GetCertificate(_ context.Context, _ uuid.UUID, scope model.Scope) (*model.Certificate, error) {
	s.getCalled = true
	s.getUserScoped = scope.Kind() == model.ScopeOwner
	s.listUserID = scope.ActorID()
	s.listVaultID = scope.VaultID()
	if s.getInVaultErr != nil {
		return nil, s.getInVaultErr
	}
	return &model.Certificate{ID: uuid.New(), Name: "c", UserID: scope.ActorID()}, nil
}
func (s *recordingCertService) ListCertificates(_ context.Context, scope model.Scope, _ repositories.CertificateFilter) ([]model.Certificate, error) {
	s.listCalled = true
	s.listUserScoped = scope.Kind() == model.ScopeOwner
	s.listUserID = scope.ActorID()
	s.listVaultID = scope.VaultID()
	return []model.Certificate{}, nil
}
func (s *recordingCertService) DeleteCertificate(context.Context, uuid.UUID, model.Scope) error {
	panic("unexpected")
}
func (s *recordingCertService) RenewCertificate(_ context.Context, certID uuid.UUID, scope model.Scope, _ int) (*certServices.CreateCertificateResult, error) {
	s.versionCalls = append(s.versionCalls, "renew")
	s.versionScope = scope
	if s.getInVaultErr != nil {
		return nil, s.getInVaultErr
	}
	return &certServices.CreateCertificateResult{CertID: certID, Version: 2}, nil
}
func (s *recordingCertService) ValidateCertificateAccess(context.Context, uuid.UUID, model.Scope) error {
	panic("unexpected")
}
func (s *recordingCertService) ValidateKeyOwnership(context.Context, uuid.UUID, model.Scope) error {
	panic("unexpected")
}
func (s *recordingCertService) ListDeletedCertificates(context.Context, model.Scope) ([]model.Certificate, error) {
	panic("unexpected")
}
func (s *recordingCertService) RecoverCertificate(context.Context, uuid.UUID, model.Scope) error {
	panic("unexpected")
}
func (s *recordingCertService) PurgeCertificate(context.Context, uuid.UUID, model.Scope) error {
	panic("unexpected")
}
func (s *recordingCertService) GetCertificatePolicy(ctx context.Context, certID uuid.UUID, scope model.Scope) (*model.CertificatePolicy, error) {
	if _, err := s.GetCertificate(ctx, certID, scope); err != nil {
		return nil, err
	}
	return s.policyRepo.GetByCertificateIDAny(ctx, certID)
}
func (s *recordingCertService) UpsertCertificatePolicy(ctx context.Context, certID uuid.UUID, scope model.Scope, req model.UpsertCertificatePolicyRequest) (*model.CertificatePolicy, error) {
	if _, err := s.GetCertificate(ctx, certID, scope); err != nil {
		return nil, err
	}
	now := time.Now()
	policy := &model.CertificatePolicy{
		ID:               uuid.New(),
		CertificateID:    certID,
		UserID:           scope.ActorID(),
		ValidityMonths:   req.ValidityMonths,
		KeyType:          req.KeyType,
		KeySize:          req.KeySize,
		Curve:            req.Curve,
		Subject:          req.Subject,
		SANs:             req.SANs,
		AutoRenew:        req.AutoRenew,
		DaysBeforeExpiry: req.DaysBeforeExpiry,
		IssuerName:       req.IssuerName,
		CreatedAt:        now,
		UpdatedAt:        now,
	}
	if err := s.policyRepo.Upsert(ctx, policy); err != nil {
		return nil, err
	}
	return s.policyRepo.GetByCertificateIDAny(ctx, certID)
}
func (s *recordingCertService) DeleteCertificatePolicy(ctx context.Context, certID uuid.UUID, scope model.Scope) error {
	if _, err := s.GetCertificate(ctx, certID, scope); err != nil {
		return err
	}
	return s.policyRepo.DeleteByCertificateIDAny(ctx, certID)
}
func (s *recordingCertService) ListCertificatePolicies(context.Context, model.Scope) ([]model.CertificatePolicyWithCertName, error) {
	panic("unexpected")
}
func (s *recordingCertService) ListCertificatesDueForRenewal(context.Context, model.Scope) ([]model.Certificate, error) {
	panic("unexpected")
}

// recordingCryptoService records the scope used for each of the six crypto
// operations, so tests can assert vault-scoped routes authorize by vault
// membership, not by key ownership (P2's B6 policy change). It returns a
// fixed, valid result for every operation so handlers reach the
// response-writing path without a real key or crypto engine.
type recordingCryptoService struct {
	lastScope model.Scope
}

func (s *recordingCryptoService) Sign(_ context.Context, req keyServices.SignRequest) (*keyServices.SignResult, error) {
	s.lastScope = req.Scope
	return &keyServices.SignResult{KeyID: req.KeyID, Algorithm: req.Algorithm, Signature: []byte("sig")}, nil
}
func (s *recordingCryptoService) Verify(_ context.Context, req keyServices.VerifyRequest) (*keyServices.VerifyResult, error) {
	s.lastScope = req.Scope
	return &keyServices.VerifyResult{KeyID: req.KeyID, Algorithm: req.Algorithm, Valid: true}, nil
}
func (s *recordingCryptoService) Encrypt(_ context.Context, req keyServices.EncryptRequest) (*keyServices.EncryptResult, error) {
	s.lastScope = req.Scope
	return &keyServices.EncryptResult{KeyID: req.KeyID, Algorithm: req.Algorithm, Ciphertext: []byte("ct")}, nil
}
func (s *recordingCryptoService) Decrypt(_ context.Context, req keyServices.DecryptRequest) (*keyServices.DecryptResult, error) {
	s.lastScope = req.Scope
	return &keyServices.DecryptResult{KeyID: req.KeyID, Algorithm: req.Algorithm, Plaintext: []byte("pt")}, nil
}
func (s *recordingCryptoService) WrapKey(_ context.Context, req keyServices.WrapKeyRequest) (*keyServices.WrapKeyResult, error) {
	s.lastScope = req.Scope
	return &keyServices.WrapKeyResult{WrappedKey: []byte("wrapped"), Algorithm: req.Algorithm}, nil
}
func (s *recordingCryptoService) UnwrapKey(_ context.Context, req keyServices.UnwrapKeyRequest) (*keyServices.UnwrapKeyResult, error) {
	s.lastScope = req.Scope
	return &keyServices.UnwrapKeyResult{PlaintextKey: []byte("plain"), Algorithm: req.Algorithm}, nil
}

// newVaultScopedKeyCertTestAPI wires both the legacy flat key/certificate routes
// and the vault-scoped resource routes onto one router, backed by recording
// services so each test can assert which scope was used. cryptoSvc may be nil
// for tests that never dispatch to a crypto operation handler.
func newVaultScopedKeyCertTestAPI(keySvc keyServices.KeyService, certSvc certServices.CertificateService, cryptoSvc keyServices.CryptoService) (*API, *vaultFakeRepo) {
	repo := newVaultFakeRepo()
	vsvc := vaultServices.NewVaultService(repo, vaultNoopCascade{}, nil)
	a := &app.App{ServiceContainer: &vaultSvcTestContainer{vaultSvc: vsvc, keySvc: keySvc, certSvc: certSvc, cryptoSvc: cryptoSvc}}
	a.Logger = userTestLog()

	router := mux.NewRouter()
	api := &API{
		App:        a,
		BaseRoutes: &Routes{},
		basePath:   "/api/v1",
		rootRouter: router,
		Logger:     userTestLog(),
	}
	r := api.BaseRoutes
	r.ApiRoot = router.PathPrefix("/api/v1").Subrouter()
	r.Vaults = r.ApiRoot.PathPrefix("/vaults").Subrouter()
	r.VaultScoped = r.Vaults.PathPrefix("/{vault_name:[a-z0-9-]+}").Subrouter()
	r.VaultScoped.Use(vaultResolutionTestMiddleware(repo))
	r.Keys = r.ApiRoot.PathPrefix("/keys").Subrouter()
	r.Certificates = r.ApiRoot.PathPrefix("/certificates").Subrouter()
	api.InitVault()
	api.InitKeys()
	api.InitCertificates()
	return api, repo
}

// newVaultScopedCertPolicyTestAPI wires vault management and vault-scoped
// certificate routes (including the policy sub-resource) onto one router,
// backed by a recording cert service and a certificate policy repository.
// The handlers under test only ever go through certSvc; when it's a
// *recordingCertService its own policy methods delegate to policyRepo, so
// wire it through here for callers that don't set it themselves.
func newVaultScopedCertPolicyTestAPI(certSvc certServices.CertificateService, policyRepo repositories.CertificatePolicyRepositoryInterface) (*API, *vaultFakeRepo) {
	if rec, ok := certSvc.(*recordingCertService); ok && rec.policyRepo == nil {
		rec.policyRepo = policyRepo
	}
	repo := newVaultFakeRepo()
	vsvc := vaultServices.NewVaultService(repo, vaultNoopCascade{}, nil)
	a := &app.App{ServiceContainer: &vaultSvcTestContainer{vaultSvc: vsvc, certSvc: certSvc, certPolicyRepo: policyRepo}}
	a.Logger = userTestLog()

	router := mux.NewRouter()
	api := &API{
		App:        a,
		BaseRoutes: &Routes{},
		basePath:   "/api/v1",
		rootRouter: router,
		Logger:     userTestLog(),
	}
	r := api.BaseRoutes
	r.ApiRoot = router.PathPrefix("/api/v1").Subrouter()
	r.Vaults = r.ApiRoot.PathPrefix("/vaults").Subrouter()
	r.VaultScoped = r.Vaults.PathPrefix("/{vault_name:[a-z0-9-]+}").Subrouter()
	r.VaultScoped.Use(vaultResolutionTestMiddleware(repo))
	r.Certificates = r.ApiRoot.PathPrefix("/certificates").Subrouter()
	api.InitVault()
	api.InitCertificates()
	return api, repo
}

// TestGetCertificatePolicy_VaultScopedRoute_UsesGetByCertificateIDAny verifies
// that GET on the explicit /vaults/{name}/certificates/{id}/policy route
// succeeds even when the stored policy's owner differs from the caller,
// proving vault-wide access rather than ownership-gated access.
func TestGetCertificatePolicy_VaultScopedRoute_UsesGetByCertificateIDAny(t *testing.T) {
	certSvc := &recordingCertService{}
	policyRepo := &mockCertPolicyRepo{}
	api, repo := newVaultScopedCertPolicyTestAPI(certSvc, policyRepo)

	id := uuid.New()
	repo.byName["prod"] = &model.Vault{ID: id, Name: "prod", Enabled: true}
	repo.byID[id.String()] = repo.byName["prod"]

	certID := uuid.New()
	otherOwnerID := uuid.New() // different from the caller (vaultTestUserID)
	stored := &model.CertificatePolicy{ID: uuid.New(), CertificateID: certID, UserID: otherOwnerID, ValidityMonths: 12}
	policyRepo.On("GetByCertificateIDAny", mock.Anything, certID).Return(stored, nil)

	w := doVaultRequest(api, http.MethodGet, "/api/v1/vaults/prod/certificates/"+certID.String()+"/policy", nil)

	if w.Code != http.StatusOK {
		t.Fatalf("vault-scoped GET .../policy: expected 200, got %d (%s)", w.Code, w.Body.String())
	}
	if certSvc.listVaultID != id {
		t.Fatalf("policy operation dispatched with vault ID %s, want %s", certSvc.listVaultID, id)
	}
	policyRepo.AssertExpectations(t)
}

// TestUpsertCertificatePolicy_VaultScopedRoute_VerifiesCertInVaultFirst
// verifies that PUT on the vault-scoped policy route 404s (and never calls
// Upsert) when the certificate does not belong to the resolved vault.
func TestUpsertCertificatePolicy_VaultScopedRoute_VerifiesCertInVaultFirst(t *testing.T) {
	certSvc := &recordingCertService{getInVaultErr: fmt.Errorf("%w: not in vault", certServices.ErrCertNotFound)}
	policyRepo := &mockCertPolicyRepo{}
	api, repo := newVaultScopedCertPolicyTestAPI(certSvc, policyRepo)

	id := uuid.New()
	repo.byName["prod"] = &model.Vault{ID: id, Name: "prod", Enabled: true}
	repo.byID[id.String()] = repo.byName["prod"]

	certID := uuid.New()
	body := []byte(`{"validity_months":12,"key_type":"RSA","key_size":2048}`)
	w := doVaultRequest(api, http.MethodPut, "/api/v1/vaults/prod/certificates/"+certID.String()+"/policy", body)

	if w.Code != http.StatusNotFound {
		t.Fatalf("vault-scoped PUT .../policy for cert not in vault: expected 404, got %d (%s)", w.Code, w.Body.String())
	}
	if certSvc.listVaultID != id {
		t.Fatalf("policy operation dispatched with vault ID %s, want %s", certSvc.listVaultID, id)
	}
	policyRepo.AssertNotCalled(t, "Upsert", mock.Anything, mock.Anything)
}

// TestDeleteCertificatePolicy_VaultScopedRoute_UsesDeleteByCertificateIDAny verifies
// that DELETE on the explicit vault-scoped policy route succeeds even when
// the stored policy's owner differs from the caller.
func TestDeleteCertificatePolicy_VaultScopedRoute_UsesDeleteByCertificateIDAny(t *testing.T) {
	certSvc := &recordingCertService{}
	policyRepo := &mockCertPolicyRepo{}
	api, repo := newVaultScopedCertPolicyTestAPI(certSvc, policyRepo)

	id := uuid.New()
	repo.byName["prod"] = &model.Vault{ID: id, Name: "prod", Enabled: true}
	repo.byID[id.String()] = repo.byName["prod"]

	certID := uuid.New()
	policyRepo.On("DeleteByCertificateIDAny", mock.Anything, certID).Return(nil)

	w := doVaultRequest(api, http.MethodDelete, "/api/v1/vaults/prod/certificates/"+certID.String()+"/policy", nil)

	if w.Code != http.StatusOK {
		t.Fatalf("vault-scoped DELETE .../policy: expected 200, got %d (%s)", w.Code, w.Body.String())
	}
	if certSvc.listVaultID != id {
		t.Fatalf("policy operation dispatched with vault ID %s, want %s", certSvc.listVaultID, id)
	}
	policyRepo.AssertExpectations(t)
}

// TestLegacyFlatKeyRoute_UsesDefaultVaultScopedListing verifies the legacy flat
// /keys route lists the default vault rather than the caller's keys across
// every vault.
func TestLegacyFlatKeyRoute_UsesDefaultVaultScopedListing(t *testing.T) {
	rec := &recordingKeyService{}
	api, _ := newVaultScopedKeyCertTestAPI(rec, nil, nil)

	w := doScopedRequest(api, http.MethodGet, "/api/v1/keys")
	if w.Code != http.StatusOK {
		t.Fatalf("legacy GET /keys: expected 200, got %d (%s)", w.Code, w.Body.String())
	}
	if !rec.listCalled {
		t.Fatalf("legacy route did not dispatch to the key list handler")
	}
	if rec.listUserScoped {
		t.Fatalf("legacy /keys must no longer build an owner scope")
	}
	if rec.listVaultID != uuid.MustParse(model.DefaultVaultID) {
		t.Fatalf("legacy /keys scoped to vault %s, want the default vault", rec.listVaultID)
	}
	if rec.listUserID != uuid.MustParse(vaultTestUserID) {
		t.Fatalf("legacy /keys actor %s, want caller %s", rec.listUserID, vaultTestUserID)
	}
}

// TestVaultScopedKeyRoute_UsesVaultScopedListing verifies the vault-scoped
// /vaults/{name}/keys route uses vault-level visibility (ListKeysInVault).
func TestVaultScopedKeyRoute_UsesVaultScopedListing(t *testing.T) {
	rec := &recordingKeyService{}
	api, repo := newVaultScopedKeyCertTestAPI(rec, nil, nil)

	id := uuid.New()
	repo.byName["prod"] = &model.Vault{ID: id, Name: "prod", Enabled: true}
	repo.byID[id.String()] = repo.byName["prod"]

	w := doScopedRequest(api, http.MethodGet, "/api/v1/vaults/prod/keys")
	if w.Code != http.StatusOK {
		t.Fatalf("vault-scoped GET /vaults/prod/keys: expected 200, got %d (%s)", w.Code, w.Body.String())
	}
	if !rec.listCalled {
		t.Fatalf("vault-scoped route did not dispatch to the key list handler")
	}
	if rec.listUserScoped {
		t.Fatalf("vault-scoped /keys must use vault-scoped listing (ListKeysInVault)")
	}
}

// TestVaultScopedKeyRoute_UsesVaultScopedUpdate verifies that PUT on the
// explicit /vaults/{name}/keys/{id} route dispatches to UpdateKeyInVault,
// not the owner-scoped UpdateKey.
func TestVaultScopedKeyRoute_UsesVaultScopedUpdate(t *testing.T) {
	rec := &recordingKeyService{}
	api, repo := newVaultScopedKeyCertTestAPI(rec, nil, nil)

	id := uuid.New()
	repo.byName["prod"] = &model.Vault{ID: id, Name: "prod", Enabled: true}
	repo.byID[id.String()] = repo.byName["prod"]

	keyID := uuid.New()
	body := []byte(`{"name":"new-name"}`)
	w := doVaultRequest(api, http.MethodPut, "/api/v1/vaults/prod/keys/"+keyID.String(), body)

	if w.Code != http.StatusOK {
		t.Fatalf("vault-scoped PUT /vaults/prod/keys/%s: expected 200, got %d (%s)", keyID, w.Code, w.Body.String())
	}
	if !rec.updateCalled {
		t.Fatalf("vault-scoped route did not dispatch to the key update handler")
	}
	if !rec.updateVaultScoped {
		t.Fatalf("vault-scoped /keys/{id} PUT must use vault-scoped update (UpdateKeyInVault)")
	}
	if rec.updateVaultID != id {
		t.Fatalf("update dispatched with vault ID %s, want %s", rec.updateVaultID, id)
	}
}

// TestLegacyFlatKeyRoute_UsesDefaultVaultScopedUpdate verifies that PUT on the
// legacy flat /keys/{id} route updates within the default vault.
func TestLegacyFlatKeyRoute_UsesDefaultVaultScopedUpdate(t *testing.T) {
	rec := &recordingKeyService{}
	api, _ := newVaultScopedKeyCertTestAPI(rec, nil, nil)

	keyID := uuid.New()
	body := []byte(`{"name":"new-name"}`)
	w := doVaultRequest(api, http.MethodPut, "/api/v1/keys/"+keyID.String(), body)

	if w.Code != http.StatusOK {
		t.Fatalf("legacy PUT /keys/%s: expected 200, got %d (%s)", keyID, w.Code, w.Body.String())
	}
	if !rec.updateCalled {
		t.Fatalf("legacy route did not dispatch to the key update handler")
	}
	if !rec.updateVaultScoped {
		t.Fatalf("legacy /keys/{id} PUT must use a vault scope, not an owner scope")
	}
	if rec.updateVaultID != uuid.MustParse(model.DefaultVaultID) {
		t.Fatalf("legacy update scoped to vault %s, want the default vault", rec.updateVaultID)
	}
	if rec.updateUserID != uuid.MustParse(vaultTestUserID) {
		t.Fatalf("legacy route actor %s, want caller %s", rec.updateUserID, vaultTestUserID)
	}
}

// TestLegacyFlatCertRoute_UsesDefaultVaultScopedListing verifies the legacy
// flat /certificates route lists the default vault rather than the caller's
// certificates across every vault.
func TestLegacyFlatCertRoute_UsesDefaultVaultScopedListing(t *testing.T) {
	rec := &recordingCertService{}
	api, _ := newVaultScopedKeyCertTestAPI(nil, rec, nil)

	w := doScopedRequest(api, http.MethodGet, "/api/v1/certificates")
	if w.Code != http.StatusOK {
		t.Fatalf("legacy GET /certificates: expected 200, got %d (%s)", w.Code, w.Body.String())
	}
	if !rec.listCalled {
		t.Fatalf("legacy route did not dispatch to the certificate list handler")
	}
	if rec.listUserScoped {
		t.Fatalf("legacy /certificates must no longer build an owner scope")
	}
	if rec.listVaultID != uuid.MustParse(model.DefaultVaultID) {
		t.Fatalf("legacy /certificates scoped to vault %s, want the default vault", rec.listVaultID)
	}
	if rec.listUserID != uuid.MustParse(vaultTestUserID) {
		t.Fatalf("legacy /certificates actor %s, want caller %s", rec.listUserID, vaultTestUserID)
	}
}

// TestVaultScopedCertRoute_UsesVaultScopedListing verifies the vault-scoped
// /vaults/{name}/certificates route uses vault-level visibility.
func TestVaultScopedCertRoute_UsesVaultScopedListing(t *testing.T) {
	rec := &recordingCertService{}
	api, repo := newVaultScopedKeyCertTestAPI(nil, rec, nil)

	id := uuid.New()
	repo.byName["prod"] = &model.Vault{ID: id, Name: "prod", Enabled: true}
	repo.byID[id.String()] = repo.byName["prod"]

	w := doScopedRequest(api, http.MethodGet, "/api/v1/vaults/prod/certificates")
	if w.Code != http.StatusOK {
		t.Fatalf("vault-scoped GET /vaults/prod/certificates: expected 200, got %d (%s)", w.Code, w.Body.String())
	}
	if !rec.listCalled {
		t.Fatalf("vault-scoped route did not dispatch to the certificate list handler")
	}
	if rec.listUserScoped {
		t.Fatalf("vault-scoped /certificates must use vault-scoped listing (ListCertificatesInVault)")
	}
}

// TestVaultScopedCertRoute_UsesVaultScopedUpdate verifies that PUT on the
// explicit /vaults/{name}/certificates/{id} route dispatches with a vault
// scope, proving the updateCertificate fix: it is no longer hardcoded to an
// owner scope regardless of route shape.
func TestVaultScopedCertRoute_UsesVaultScopedUpdate(t *testing.T) {
	rec := &recordingCertService{}
	api, repo := newVaultScopedKeyCertTestAPI(nil, rec, nil)

	id := uuid.New()
	repo.byName["prod"] = &model.Vault{ID: id, Name: "prod", Enabled: true}
	repo.byID[id.String()] = repo.byName["prod"]

	certID := uuid.New()
	body := []byte(`{"name":"new-name"}`)
	w := doVaultRequest(api, http.MethodPut, "/api/v1/vaults/prod/certificates/"+certID.String(), body)

	if w.Code != http.StatusOK {
		t.Fatalf("vault-scoped PUT /vaults/prod/certificates/%s: expected 200, got %d (%s)", certID, w.Code, w.Body.String())
	}
	if !rec.updateCalled {
		t.Fatalf("vault-scoped route did not dispatch to the certificate update handler")
	}
	if !rec.updateVaultScoped {
		t.Fatalf("vault-scoped /certificates/{id} PUT must use a vault scope, not an owner scope")
	}
	if rec.updateVaultID != id {
		t.Fatalf("update dispatched with vault ID %s, want %s", rec.updateVaultID, id)
	}
}

// TestLegacyFlatCertRoute_UsesDefaultVaultScopedUpdate verifies that PUT on the
// legacy flat /certificates/{id} route updates within the default vault.
func TestLegacyFlatCertRoute_UsesDefaultVaultScopedUpdate(t *testing.T) {
	rec := &recordingCertService{}
	api, _ := newVaultScopedKeyCertTestAPI(nil, rec, nil)

	certID := uuid.New()
	body := []byte(`{"name":"new-name"}`)
	w := doVaultRequest(api, http.MethodPut, "/api/v1/certificates/"+certID.String(), body)

	if w.Code != http.StatusOK {
		t.Fatalf("legacy PUT /certificates/%s: expected 200, got %d (%s)", certID, w.Code, w.Body.String())
	}
	if !rec.updateCalled {
		t.Fatalf("legacy route did not dispatch to the certificate update handler")
	}
	if !rec.updateVaultScoped {
		t.Fatalf("legacy /certificates/{id} PUT must use a vault scope, not an owner scope")
	}
	if rec.updateVaultID != uuid.MustParse(model.DefaultVaultID) {
		t.Fatalf("legacy update scoped to vault %s, want the default vault", rec.updateVaultID)
	}
	if rec.updateUserID != uuid.MustParse(vaultTestUserID) {
		t.Fatalf("legacy route actor %s, want caller %s", rec.updateUserID, vaultTestUserID)
	}
}

// TestCryptoOperationsUseVaultScope asserts the crypto handlers authorize by
// vault membership, not by key ownership. This is the deliberate B6 policy
// change: under Azure parity, crypto operations are gated by Key Vault Crypto
// User at vault scope, and the P0 tests that pinned owner-gating
// (api/vault_scoped_crypto_b6_test.go, api/keys_scope_test.go's
// TestDeleteKeyUsesAnOwnerScope, api/scope_helpers_test.go's
// TestOwnerScopeFromRequestAlwaysYieldsOwnerScope) are deleted in the same
// commit as this test.
func TestCryptoOperationsUseVaultScope(t *testing.T) {
	caller := uuid.MustParse(vaultTestUserID)
	cryptoSvc := &recordingCryptoService{}
	api, repo := newVaultScopedKeyCertTestAPI(nil, nil, cryptoSvc)

	id := uuid.New()
	repo.byName["prod"] = &model.Vault{ID: id, Name: "prod", Enabled: true}
	repo.byID[id.String()] = repo.byName["prod"]

	keyID := uuid.New()
	tests := []struct {
		name string
		path string
		body []byte
	}{
		{"sign", "/sign", []byte(`{"value":"aGVsbG8="}`)},
		{"verify", "/verify", []byte(`{"value":"aGVsbG8=","signature":"c2ln"}`)},
		{"encrypt", "/encrypt", []byte(`{"value":"aGVsbG8="}`)},
		{"decrypt", "/decrypt", []byte(`{"value":"Y3Q="}`)},
		{"wrap", "/wrap", []byte(`{"plaintext_key":"a2V5"}`)},
		{"unwrap", "/unwrap", []byte(`{"wrapped_key":"d3JhcHBlZA=="}`)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := doVaultRequest(api, http.MethodPost, "/api/v1/vaults/prod/keys/"+keyID.String()+tt.path, tt.body)
			if w.Code != http.StatusOK {
				t.Fatalf("%s via vault route: expected 200, got %d (%s)", tt.name, w.Code, w.Body.String())
			}

			got := cryptoSvc.lastScope
			if got.Kind() != model.ScopeVault {
				t.Fatalf("%s: crypto operations must build a vault scope, not an owner scope (got kind %v)", tt.name, got.Kind())
			}
			if got.VaultID() != id {
				t.Fatalf("%s: scope vault ID %s, want %s", tt.name, got.VaultID(), id)
			}
			if got.ActorID() != caller {
				t.Fatalf("%s: scope actor %s, want caller %s", tt.name, got.ActorID(), caller)
			}
			if _, isOwnerScoped := got.OwnerID(); isOwnerScoped {
				t.Fatalf("%s: no owner predicate may remain on the data plane", tt.name)
			}
		})
	}
}

// TestDeleteKeyUsesVaultScope asserts key delete follows the same change: the
// vault-scoped route authorizes by vault membership, not by key ownership.
func TestDeleteKeyUsesVaultScope(t *testing.T) {
	caller := uuid.MustParse(vaultTestUserID)
	rec := &recordingKeyService{}
	api, repo := newVaultScopedKeyCertTestAPI(rec, nil, nil)

	id := uuid.New()
	repo.byName["prod"] = &model.Vault{ID: id, Name: "prod", Enabled: true}
	repo.byID[id.String()] = repo.byName["prod"]

	keyID := uuid.New()
	w := doVaultRequest(api, http.MethodDelete, "/api/v1/vaults/prod/keys/"+keyID.String(), nil)
	if w.Code != http.StatusOK {
		t.Fatalf("vault-scoped DELETE: expected 200, got %d (%s)", w.Code, w.Body.String())
	}
	if !rec.deleteCalled {
		t.Fatalf("vault-scoped route did not dispatch to the key delete handler")
	}

	got := rec.deleteScope
	if got.Kind() != model.ScopeVault {
		t.Fatalf("delete key: expected ScopeVault, got kind %v", got.Kind())
	}
	if got.VaultID() != id {
		t.Fatalf("delete key: scope vault ID %s, want %s", got.VaultID(), id)
	}
	if got.ActorID() != caller {
		t.Fatalf("delete key: scope actor %s, want caller %s", got.ActorID(), caller)
	}
	if _, isOwnerScoped := got.OwnerID(); isOwnerScoped {
		t.Fatalf("delete key: no owner predicate may remain on the data plane")
	}
}

func (s *recordingCertService) ListCertificateVersions(_ context.Context, certID uuid.UUID, scope model.Scope) ([]model.CertificateVersion, error) {
	s.versionCalls = append(s.versionCalls, "list")
	s.versionScope = scope
	if s.getInVaultErr != nil {
		return nil, s.getInVaultErr
	}
	return []model.CertificateVersion{{CertificateID: certID, Version: 1, Current: true, Enabled: true}}, nil
}
func (s *recordingCertService) GetCertificateVersion(_ context.Context, certID uuid.UUID, version int, scope model.Scope) (*model.CertificateVersion, error) {
	s.versionCalls = append(s.versionCalls, "get")
	s.versionScope = scope
	if s.getInVaultErr != nil {
		return nil, s.getInVaultErr
	}
	return &model.CertificateVersion{CertificateID: certID, Version: version, Current: true, Enabled: true}, nil
}
func (s *recordingCertService) UpdateCertificateVersion(_ context.Context, req certServices.UpdateCertificateVersionRequest) (*model.CertificateVersion, error) {
	s.versionCalls = append(s.versionCalls, "update")
	s.versionScope = req.Scope
	if s.getInVaultErr != nil {
		return nil, s.getInVaultErr
	}
	return &model.CertificateVersion{CertificateID: req.CertID, Version: req.Version, Current: true, Enabled: true}, nil
}

func (s *recordingCertService) ExportCertificate(_ context.Context, scope model.Scope, id uuid.UUID, req certServices.ExportCertificateRequest) (*certServices.ExportCertificateResult, error) {
	s.versionCalls = append(s.versionCalls, "export")
	s.versionScope = scope
	if s.getInVaultErr != nil {
		return nil, s.getInVaultErr
	}
	return &certServices.ExportCertificateResult{ID: id, Name: "c", Version: 1, Format: req.Format,
		CertificatePEM: "chain", PrivateKeyPEM: "key", KeyAlgorithm: "RSA-2048"}, nil
}
