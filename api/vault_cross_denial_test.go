// Package api — cross-vault denial regression tests backed by real SQLite
// repositories (design spec 2026-07-26, section 4.1 / 8). Unlike the
// hand-written fakes used elsewhere in this package, whose *InVault methods
// unconditionally succeed, these tests exercise the real repository SQL
// predicates (WHERE id = ? AND vault_id = ?) so a resource seeded in vault B
// is provably denied when requested via /vaults/{vault-a}/... . Permanent
// tests — not deleted by any later phase.
package api

import (
	"context"
	"database/sql"
	"net/http"
	"testing"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
	_ "github.com/mattn/go-sqlite3"
	"github.com/stretchr/testify/mock"

	"rocketvault/app"
	rvdb "rocketvault/internal/db"
	"rocketvault/internal/repositories"
	certServices "rocketvault/internal/services/certificates"
	keyServices "rocketvault/internal/services/keys"
	secretServices "rocketvault/internal/services/secrets"
	vaultServices "rocketvault/internal/services/vaults"
	"rocketvault/model"
)

// TestCrossVaultDenial_Secret_RealSQLite seeds a secret in vault B and
// requests it via /vaults/vault-a/secrets/{id}, asserting 404. The real
// SecretRepository.ReadInVault predicate enforces the denial, not a fake.
func TestCrossVaultDenial_Secret_RealSQLite(t *testing.T) {
	api, vrepo, secretRepo := newCrossVaultSecretsTestAPI(t)
	_, vaultBID := seedCrossVaultPair(vrepo)

	secretID := uuid.New()
	if err := secretRepo.Create(context.Background(), &model.Secret{
		ID: secretID, UserID: uuid.New(), VaultID: vaultBID,
		Name: "db-password", Value: "ciphertext", Version: 1,
	}); err != nil {
		t.Fatalf("seed secret in vault B: %v", err)
	}

	w := doVaultRequest(api, http.MethodGet, "/api/v1/vaults/vault-a/secrets/"+secretID.String(), nil)
	if w.Code != http.StatusNotFound {
		t.Fatalf("cross-vault GET secret: expected 404, got %d (%s)", w.Code, w.Body.String())
	}
}

// newCrossVaultSecretsTestAPI wires the vault-scoped secret routes onto a
// real SecretService backed by a real SecretRepository over an in-memory
// SQLite database. Only the SecretRepository needs to be real:
// GetSecretInVault's cross-vault-denial path returns before ever touching
// cryptoService or tagService, so both are left nil.
func newCrossVaultSecretsTestAPI(t *testing.T) (*API, *vaultFakeRepo, repositories.SecretRepositoryInterface) {
	t.Helper()

	sqlDB, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	t.Cleanup(func() { sqlDB.Close() }) //nolint:errcheck,gosec

	_, err = sqlDB.Exec(`CREATE TABLE IF NOT EXISTS secrets (
		id               TEXT PRIMARY KEY,
		user_id          TEXT NOT NULL,
		vault_id         TEXT NOT NULL DEFAULT '00000000-0000-0000-0000-00000000efa1',
		name             TEXT NOT NULL,
		value            TEXT NOT NULL,
		version          INTEGER NOT NULL,
		created_at       TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		deleted_at       TIMESTAMP NULL,
		purge_protection BOOLEAN NOT NULL DEFAULT FALSE,
		scheduled_purge_at TIMESTAMP NULL,
		content_type     TEXT NOT NULL DEFAULT '',
		enabled          BOOLEAN NOT NULL DEFAULT TRUE,
		expires_at       TIMESTAMP NULL,
		not_before       TIMESTAMP NULL
	)`)
	if err != nil {
		t.Fatalf("create secrets schema: %v", err)
	}

	secretRepo := repositories.NewSecretRepository(rvdb.NewConn(sqlDB, rvdb.SQLite), userTestLog())
	secretSvc := secretServices.NewSecretService(secretServices.SecretServiceConfig{
		SecretRepository: secretRepo,
		Logger:           userTestLog(),
	})

	vrepo := newVaultFakeRepo()
	vsvc := vaultServices.NewVaultService(vrepo, vaultNoopCascade{}, nil)
	a := &app.App{ServiceContainer: &vaultSvcTestContainer{vaultSvc: vsvc, secretSvc: secretSvc, logger: userTestLog()}}
	a.Logger = userTestLog()

	router := mux.NewRouter()
	api := &API{App: a, BaseRoutes: &Routes{}, basePath: "/api/v1", rootRouter: router, Logger: userTestLog()}
	r := api.BaseRoutes
	r.ApiRoot = router.PathPrefix("/api/v1").Subrouter()
	r.Vaults = r.ApiRoot.PathPrefix("/vaults").Subrouter()
	r.VaultScoped = r.Vaults.PathPrefix("/{vault_name:[a-z0-9-]+}").Subrouter()
	r.VaultScoped.Use(vaultResolutionTestMiddleware(vrepo))
	r.Secrets = r.ApiRoot.PathPrefix("/secrets").Subrouter()
	api.InitVault()
	api.InitSecrets()
	return api, vrepo, secretRepo
}

// TestCrossVaultDenial_Key_RealSQLite seeds a key in vault B and requests it
// via /vaults/vault-a/keys/{id}, asserting 404.
func TestCrossVaultDenial_Key_RealSQLite(t *testing.T) {
	api, vrepo, keyRepo := newCrossVaultKeysTestAPI(t)
	_, vaultBID := seedCrossVaultPair(vrepo)

	keyID := uuid.New()
	if err := keyRepo.Create(context.Background(), &model.Key{
		ID: keyID, UserID: uuid.New(), VaultID: vaultBID,
		Name: "signing-key", Type: "RSA", Value: "encrypted-pem", Enabled: true,
	}); err != nil {
		t.Fatalf("seed key in vault B: %v", err)
	}

	w := doVaultRequest(api, http.MethodGet, "/api/v1/vaults/vault-a/keys/"+keyID.String(), nil)
	if w.Code != http.StatusNotFound {
		t.Fatalf("cross-vault GET key: expected 404, got %d (%s)", w.Code, w.Body.String())
	}
}

// newCrossVaultKeysTestAPI wires the vault-scoped key routes onto a real
// KeyService backed by a real KeyRepository over an in-memory SQLite
// database. GetKeyInVault's cross-vault-denial path returns before
// touching keyProvider or keyCache, so both stay at their zero values.
func newCrossVaultKeysTestAPI(t *testing.T) (*API, *vaultFakeRepo, repositories.KeyRepositoryInterface) {
	t.Helper()

	sqlDB, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	t.Cleanup(func() { sqlDB.Close() }) //nolint:errcheck,gosec

	_, err = sqlDB.Exec(`CREATE TABLE IF NOT EXISTS keys (
		id TEXT PRIMARY KEY,
		user_id TEXT NOT NULL,
		vault_id TEXT NOT NULL DEFAULT '00000000-0000-0000-0000-00000000efa1',
		name TEXT NOT NULL,
		value TEXT NOT NULL,
		type TEXT NOT NULL,
		revoked BOOLEAN NOT NULL DEFAULT FALSE,
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		deleted_at TIMESTAMP DEFAULT NULL,
		purge_protection BOOLEAN NOT NULL DEFAULT FALSE,
		scheduled_purge_at TIMESTAMP DEFAULT NULL,
		enabled BOOLEAN NOT NULL DEFAULT TRUE,
		expires_at TIMESTAMP NULL,
		not_before TIMESTAMP NULL,
		bits INTEGER NOT NULL DEFAULT 0,
		curve TEXT NOT NULL DEFAULT '',
		updated_at TIMESTAMP NULL,
		exportable BOOLEAN NOT NULL DEFAULT FALSE
	)`)
	if err != nil {
		t.Fatalf("create keys schema: %v", err)
	}

	_, err = sqlDB.Exec(`CREATE TABLE IF NOT EXISTS key_tags (
		key_id TEXT NOT NULL,
		tag TEXT NOT NULL,
		PRIMARY KEY (key_id, tag)
	)`)
	if err != nil {
		t.Fatalf("create key_tags schema: %v", err)
	}

	keyRepo := repositories.NewKeyRepository(rvdb.NewConn(sqlDB, rvdb.SQLite), userTestLog())
	keySvc := keyServices.NewKeyService(keyServices.KeyServiceConfig{
		KeyRepository: keyRepo,
		Logger:        userTestLog(),
	})

	vrepo := newVaultFakeRepo()
	vsvc := vaultServices.NewVaultService(vrepo, vaultNoopCascade{}, nil)
	a := &app.App{ServiceContainer: &vaultSvcTestContainer{vaultSvc: vsvc, keySvc: keySvc, logger: userTestLog()}}
	a.Logger = userTestLog()

	router := mux.NewRouter()
	api := &API{App: a, BaseRoutes: &Routes{}, basePath: "/api/v1", rootRouter: router, Logger: userTestLog()}
	r := api.BaseRoutes
	r.ApiRoot = router.PathPrefix("/api/v1").Subrouter()
	r.Vaults = r.ApiRoot.PathPrefix("/vaults").Subrouter()
	r.VaultScoped = r.Vaults.PathPrefix("/{vault_name:[a-z0-9-]+}").Subrouter()
	r.VaultScoped.Use(vaultResolutionTestMiddleware(vrepo))
	r.Keys = r.ApiRoot.PathPrefix("/keys").Subrouter()
	api.InitVault()
	api.InitKeys()
	return api, vrepo, keyRepo
}

// TestCrossVaultDenial_Certificate_RealSQLite seeds a certificate in vault B
// and requests it via /vaults/vault-a/certificates/{id}, asserting 404.
func TestCrossVaultDenial_Certificate_RealSQLite(t *testing.T) {
	api, vrepo, certRepo := newCrossVaultCertsTestAPI(t)
	_, vaultBID := seedCrossVaultPair(vrepo)

	certID := uuid.New()
	if err := certRepo.Create(context.Background(), &model.Certificate{
		ID: certID, UserID: uuid.New(), VaultID: vaultBID,
		Name:        "tls-cert",
		Certificate: "-----BEGIN CERTIFICATE-----\nMIItest\n-----END CERTIFICATE-----",
		PrivateKey:  "encrypted-private-key",
	}); err != nil {
		t.Fatalf("seed certificate in vault B: %v", err)
	}

	w := doVaultRequest(api, http.MethodGet, "/api/v1/vaults/vault-a/certificates/"+certID.String(), nil)
	if w.Code != http.StatusNotFound {
		t.Fatalf("cross-vault GET certificate: expected 404, got %d (%s)", w.Code, w.Body.String())
	}
}

// newCrossVaultCertsTestAPI wires the vault-scoped certificate routes onto a
// real CertificateService backed by a real CertificateRepository over an
// in-memory SQLite database. GetCertificateInVault's cross-vault-denial path
// returns before touching keyRepo, so it stays nil.
func newCrossVaultCertsTestAPI(t *testing.T) (*API, *vaultFakeRepo, repositories.CertificateRepositoryInterface) {
	t.Helper()

	sqlDB, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	t.Cleanup(func() { sqlDB.Close() }) //nolint:errcheck,gosec

	_, err = sqlDB.Exec(`CREATE TABLE IF NOT EXISTS certificates (
		id TEXT PRIMARY KEY,
		user_id TEXT NOT NULL,
		vault_id TEXT NOT NULL DEFAULT '00000000-0000-0000-0000-00000000efa1',
		name TEXT NOT NULL,
		certificate TEXT NOT NULL,
		private_key TEXT NOT NULL,
		version INTEGER NOT NULL DEFAULT 1,
		exportable BOOLEAN NOT NULL DEFAULT FALSE,
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		deleted_at TIMESTAMP DEFAULT NULL,
		purge_protection BOOLEAN NOT NULL DEFAULT FALSE,
		scheduled_purge_at TIMESTAMP DEFAULT NULL,
		expires_at TIMESTAMP,
		auto_renew BOOLEAN NOT NULL DEFAULT FALSE,
		renewal_days INTEGER NOT NULL DEFAULT 30,
		key_id TEXT,
		ca_cert_id TEXT NULL,
		enabled BOOLEAN NOT NULL DEFAULT TRUE,
		not_before TIMESTAMP NULL
	)`)
	if err != nil {
		t.Fatalf("create certificates schema: %v", err)
	}

	_, err = sqlDB.Exec(`CREATE TABLE IF NOT EXISTS certificate_tags (
		certificate_id TEXT NOT NULL,
		tag TEXT NOT NULL,
		PRIMARY KEY (certificate_id, tag)
	)`)
	if err != nil {
		t.Fatalf("create certificate_tags schema: %v", err)
	}

	_, err = sqlDB.Exec(`CREATE TABLE IF NOT EXISTS certificate_versions (
		certificate_id TEXT NOT NULL,
		version        INTEGER NOT NULL,
		certificate    TEXT NOT NULL,
		private_key    TEXT NOT NULL,
		key_id         TEXT NULL,
		created_at     TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		expires_at     TIMESTAMP NULL,
		not_before     TIMESTAMP NULL,
		enabled        BOOLEAN NOT NULL DEFAULT TRUE,
		PRIMARY KEY (certificate_id, version)
	)`)
	if err != nil {
		t.Fatalf("create certificate_versions schema: %v", err)
	}

	certRepo := repositories.NewCertificateRepository(rvdb.NewConn(sqlDB, rvdb.SQLite), userTestLog())
	certSvc := certServices.NewCertificateService(certServices.CertificateServiceConfig{
		CertificateRepository: certRepo,
		Logger:                userTestLog(),
	})

	vrepo := newVaultFakeRepo()
	vsvc := vaultServices.NewVaultService(vrepo, vaultNoopCascade{}, nil)
	a := &app.App{ServiceContainer: &vaultSvcTestContainer{vaultSvc: vsvc, certSvc: certSvc, logger: userTestLog()}}
	a.Logger = userTestLog()

	router := mux.NewRouter()
	api := &API{App: a, BaseRoutes: &Routes{}, basePath: "/api/v1", rootRouter: router, Logger: userTestLog()}
	r := api.BaseRoutes
	r.ApiRoot = router.PathPrefix("/api/v1").Subrouter()
	r.Vaults = r.ApiRoot.PathPrefix("/vaults").Subrouter()
	r.VaultScoped = r.Vaults.PathPrefix("/{vault_name:[a-z0-9-]+}").Subrouter()
	r.VaultScoped.Use(vaultResolutionTestMiddleware(vrepo))
	r.Certificates = r.ApiRoot.PathPrefix("/certificates").Subrouter()
	api.InitVault()
	api.InitCertificates()
	return api, vrepo, certRepo
}

// TestCrossVaultDenial_CertificatePolicy_RealSQLite seeds a certificate (with
// its policy sub-resource) in vault B and requests the policy via
// /vaults/vault-a/certificates/{id}/policy, asserting 404 and that the
// policy repository is never consulted.
func TestCrossVaultDenial_CertificatePolicy_RealSQLite(t *testing.T) {
	api, vrepo, certRepo, policyRepo := newCrossVaultCertPolicyTestAPI(t)
	_, vaultBID := seedCrossVaultPair(vrepo)

	certID := uuid.New()
	if err := certRepo.Create(context.Background(), &model.Certificate{
		ID: certID, UserID: uuid.New(), VaultID: vaultBID,
		Name:        "tls-cert",
		Certificate: "-----BEGIN CERTIFICATE-----\nMIItest\n-----END CERTIFICATE-----",
		PrivateKey:  "encrypted-private-key",
	}); err != nil {
		t.Fatalf("seed certificate in vault B: %v", err)
	}

	w := doVaultRequest(api, http.MethodGet, "/api/v1/vaults/vault-a/certificates/"+certID.String()+"/policy", nil)
	if w.Code != http.StatusNotFound {
		t.Fatalf("cross-vault GET .../policy: expected 404, got %d (%s)", w.Code, w.Body.String())
	}
	policyRepo.AssertNotCalled(t, "GetByCertificateIDAny", mock.Anything, mock.Anything)
}

// newCrossVaultCertPolicyTestAPI wires the vault management routes and the
// vault-scoped certificate + policy routes onto a real CertificateService
// (real CertificateRepository over SQLite) and a mock certificate policy
// repository, so the test can assert the policy repository is never
// consulted once GetCertificateInVault denies the request.
func newCrossVaultCertPolicyTestAPI(t *testing.T) (*API, *vaultFakeRepo, repositories.CertificateRepositoryInterface, *mockCertPolicyRepo) {
	t.Helper()

	sqlDB, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	t.Cleanup(func() { sqlDB.Close() }) //nolint:errcheck,gosec

	_, err = sqlDB.Exec(`CREATE TABLE IF NOT EXISTS certificates (
		id TEXT PRIMARY KEY,
		user_id TEXT NOT NULL,
		vault_id TEXT NOT NULL DEFAULT '00000000-0000-0000-0000-00000000efa1',
		name TEXT NOT NULL,
		certificate TEXT NOT NULL,
		private_key TEXT NOT NULL,
		version INTEGER NOT NULL DEFAULT 1,
		exportable BOOLEAN NOT NULL DEFAULT FALSE,
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		deleted_at TIMESTAMP DEFAULT NULL,
		purge_protection BOOLEAN NOT NULL DEFAULT FALSE,
		scheduled_purge_at TIMESTAMP DEFAULT NULL,
		expires_at TIMESTAMP,
		auto_renew BOOLEAN NOT NULL DEFAULT FALSE,
		renewal_days INTEGER NOT NULL DEFAULT 30,
		key_id TEXT,
		ca_cert_id TEXT NULL,
		enabled BOOLEAN NOT NULL DEFAULT TRUE,
		not_before TIMESTAMP NULL
	)`)
	if err != nil {
		t.Fatalf("create certificates schema: %v", err)
	}

	certRepo := repositories.NewCertificateRepository(rvdb.NewConn(sqlDB, rvdb.SQLite), userTestLog())
	certSvc := certServices.NewCertificateService(certServices.CertificateServiceConfig{
		CertificateRepository: certRepo,
		Logger:                userTestLog(),
	})
	policyRepo := &mockCertPolicyRepo{}

	vrepo := newVaultFakeRepo()
	vsvc := vaultServices.NewVaultService(vrepo, vaultNoopCascade{}, nil)
	a := &app.App{ServiceContainer: &vaultSvcTestContainer{
		vaultSvc: vsvc, certSvc: certSvc, certPolicyRepo: policyRepo, logger: userTestLog(),
	}}
	a.Logger = userTestLog()

	router := mux.NewRouter()
	api := &API{App: a, BaseRoutes: &Routes{}, basePath: "/api/v1", rootRouter: router, Logger: userTestLog()}
	r := api.BaseRoutes
	r.ApiRoot = router.PathPrefix("/api/v1").Subrouter()
	r.Vaults = r.ApiRoot.PathPrefix("/vaults").Subrouter()
	r.VaultScoped = r.Vaults.PathPrefix("/{vault_name:[a-z0-9-]+}").Subrouter()
	r.VaultScoped.Use(vaultResolutionTestMiddleware(vrepo))
	r.Certificates = r.ApiRoot.PathPrefix("/certificates").Subrouter()
	api.InitVault()
	api.InitCertificates()
	return api, vrepo, certRepo, policyRepo
}

// seedCrossVaultPair seeds two enabled vaults ("vault-a", "vault-b") into
// repo and returns their IDs. Shared by every cross-vault-denial test.
func seedCrossVaultPair(repo *vaultFakeRepo) (vaultAID, vaultBID uuid.UUID) {
	vaultAID = uuid.New()
	repo.byName["vault-a"] = &model.Vault{ID: vaultAID, Name: "vault-a", Enabled: true}
	repo.byID[vaultAID.String()] = repo.byName["vault-a"]

	vaultBID = uuid.New()
	repo.byName["vault-b"] = &model.Vault{ID: vaultBID, Name: "vault-b", Enabled: true}
	repo.byID[vaultBID.String()] = repo.byName["vault-b"]
	return
}

// TestCrossVaultDenial_SecretVersions_RealSQLite seeds a secret in vault B
// and requests its version endpoints via /vaults/vault-a/secrets/{id}/...,
// asserting denial on all three.
func TestCrossVaultDenial_SecretVersions_RealSQLite(t *testing.T) {
	api, vrepo, secretRepo := newCrossVaultSecretVersionsTestAPI(t)
	_, vaultBID := seedCrossVaultPair(vrepo)

	secretID := uuid.New()
	if err := secretRepo.Create(context.Background(), &model.Secret{
		ID: secretID, UserID: uuid.New(), VaultID: vaultBID,
		Name: "api-key", Value: "ciphertext", Version: 1,
	}); err != nil {
		t.Fatalf("seed secret in vault B: %v", err)
	}

	// listSecretVersionsHandler now drives its vault-scoped branch through
	// scopeFromRequest + GetSecretVersions + writeSecretError, the same
	// path its two siblings below already used (design spec 2026-07-26,
	// section 5.3, P1 Phase 4: "the listSecretVersionsHandler 500->404
	// correction"). The 500-for-wrong-vault defect P0 pinned is now fixed.
	w := doVaultRequest(api, http.MethodGet, "/api/v1/vaults/vault-a/secrets/"+secretID.String()+"/versions", nil)
	if w.Code != http.StatusNotFound {
		t.Fatalf("cross-vault GET .../versions: expected 404, got %d (%s)", w.Code, w.Body.String())
	}

	w = doVaultRequest(api, http.MethodGet, "/api/v1/vaults/vault-a/secrets/"+secretID.String()+"/versions/1", nil)
	if w.Code != http.StatusNotFound {
		t.Fatalf("cross-vault GET .../versions/1: expected 404, got %d (%s)", w.Code, w.Body.String())
	}

	w = doVaultRequest(api, http.MethodGet, "/api/v1/vaults/vault-a/secrets/"+secretID.String()+"/versions/latest", nil)
	if w.Code != http.StatusNotFound {
		t.Fatalf("cross-vault GET .../versions/latest: expected 404, got %d (%s)", w.Code, w.Body.String())
	}
}

// TestInScopeSecretMissingVersion_RealSQLite is a regression test (found in
// code review of the 500->404 fix above): a secret that IS in scope, but has
// no matching secret_versions row for the requested version number (or none
// at all for "latest"), must still 404 — not 500. This is an entirely
// ordinary case (e.g. iterating version numbers, or after old versions were
// pruned), distinct from the cross-vault-denial case above. Real
// SecretRepository + SecretVersionRepository + VersioningService over
// in-memory SQLite: no secret_versions rows are ever inserted for this
// secret, so versionRepo.GetVersion/GetLatestVersion hit the real
// sql.ErrNoRows path.
func TestInScopeSecretMissingVersion_RealSQLite(t *testing.T) {
	api, vrepo, secretRepo := newCrossVaultSecretVersionsTestAPI(t)
	vaultAID, _ := seedCrossVaultPair(vrepo)

	secretID := uuid.New()
	if err := secretRepo.Create(context.Background(), &model.Secret{
		ID: secretID, UserID: uuid.New(), VaultID: vaultAID,
		Name: "no-versions-yet", Value: "ciphertext", Version: 1, Enabled: true,
	}); err != nil {
		t.Fatalf("seed secret in vault A: %v", err)
	}

	// Listing versions of an in-scope secret with zero rows is a valid empty
	// result, not a 404 (Azure Key Vault parity: listing an existing
	// resource's sub-collection returns an empty array, not not-found).
	w := doVaultRequest(api, http.MethodGet, "/api/v1/vaults/vault-a/secrets/"+secretID.String()+"/versions", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("in-scope GET .../versions with no versions: expected 200, got %d (%s)", w.Code, w.Body.String())
	}

	w = doVaultRequest(api, http.MethodGet, "/api/v1/vaults/vault-a/secrets/"+secretID.String()+"/versions/1", nil)
	if w.Code != http.StatusNotFound {
		t.Fatalf("in-scope GET .../versions/1 with no such version: expected 404, got %d (%s)", w.Code, w.Body.String())
	}

	w = doVaultRequest(api, http.MethodGet, "/api/v1/vaults/vault-a/secrets/"+secretID.String()+"/versions/latest", nil)
	if w.Code != http.StatusNotFound {
		t.Fatalf("in-scope GET .../versions/latest with no versions: expected 404, got %d (%s)", w.Code, w.Body.String())
	}
}

// newCrossVaultSecretVersionsTestAPI mirrors newCrossVaultSecretsTestAPI but
// wires a real VersioningService (backed by the same real SecretRepository)
// into SecretServiceConfig.VersionService, since the version-endpoint
// handlers delegate straight through to it. versionRepo/userRepo/cryptoSvc
// stay nil: every vault-scoped versioning method checks
// secretRepo.ReadInVault first and returns before touching them.
func newCrossVaultSecretVersionsTestAPI(t *testing.T) (*API, *vaultFakeRepo, repositories.SecretRepositoryInterface) {
	t.Helper()

	sqlDB, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	t.Cleanup(func() { sqlDB.Close() }) //nolint:errcheck,gosec

	_, err = sqlDB.Exec(`CREATE TABLE IF NOT EXISTS secrets (
		id               TEXT PRIMARY KEY,
		user_id          TEXT NOT NULL,
		vault_id         TEXT NOT NULL DEFAULT '00000000-0000-0000-0000-00000000efa1',
		name             TEXT NOT NULL,
		value            TEXT NOT NULL,
		version          INTEGER NOT NULL,
		created_at       TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		deleted_at       TIMESTAMP NULL,
		purge_protection BOOLEAN NOT NULL DEFAULT FALSE,
		scheduled_purge_at TIMESTAMP NULL,
		content_type     TEXT NOT NULL DEFAULT '',
		enabled          BOOLEAN NOT NULL DEFAULT TRUE,
		expires_at       TIMESTAMP NULL,
		not_before       TIMESTAMP NULL
	)`)
	if err != nil {
		t.Fatalf("create secrets schema: %v", err)
	}

	_, err = sqlDB.Exec(`CREATE TABLE IF NOT EXISTS secret_versions (
		id         TEXT PRIMARY KEY,
		secret_id  TEXT NOT NULL,
		user_id    TEXT NOT NULL,
		name       TEXT NOT NULL,
		value      TEXT NOT NULL,
		version    INTEGER NOT NULL,
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
	)`)
	if err != nil {
		t.Fatalf("create secret_versions schema: %v", err)
	}

	secretRepo := repositories.NewSecretRepository(rvdb.NewConn(sqlDB, rvdb.SQLite), userTestLog())
	// versionRepo is real (not nil): TestInScopeSecretMissingVersion_RealSQLite
	// below reaches it (an in-scope secret with no matching version row), so
	// it must actually query a real secret_versions table rather than panic.
	// cryptoSvc stays nil: every path this fixture exercises returns before
	// touching it (the cross-vault denial's scoped Read failure, and the
	// missing-version/no-versions "not found" returns in versioning_service.go
	// both return before any DecryptSecret call).
	versionRepo := repositories.NewSecretVersionRepository(rvdb.NewConn(sqlDB, rvdb.SQLite), userTestLog())
	versionSvc := secretServices.NewVersioningService(versionRepo, secretRepo, nil, nil, userTestLog(), nil)
	secretSvc := secretServices.NewSecretService(secretServices.SecretServiceConfig{
		SecretRepository: secretRepo,
		VersionService:   versionSvc,
		Logger:           userTestLog(),
	})

	vrepo := newVaultFakeRepo()
	vsvc := vaultServices.NewVaultService(vrepo, vaultNoopCascade{}, nil)
	a := &app.App{ServiceContainer: &vaultSvcTestContainer{vaultSvc: vsvc, secretSvc: secretSvc, logger: userTestLog()}}
	a.Logger = userTestLog()

	router := mux.NewRouter()
	api := &API{App: a, BaseRoutes: &Routes{}, basePath: "/api/v1", rootRouter: router, Logger: userTestLog()}
	r := api.BaseRoutes
	r.ApiRoot = router.PathPrefix("/api/v1").Subrouter()
	r.Vaults = r.ApiRoot.PathPrefix("/vaults").Subrouter()
	r.VaultScoped = r.Vaults.PathPrefix("/{vault_name:[a-z0-9-]+}").Subrouter()
	r.VaultScoped.Use(vaultResolutionTestMiddleware(vrepo))
	r.Secrets = r.ApiRoot.PathPrefix("/secrets").Subrouter()
	api.InitVault()
	api.InitSecrets()
	return api, vrepo, secretRepo
}
