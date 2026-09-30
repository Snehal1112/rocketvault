package certificates_test

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"rocketvault/internal/logging"
	"rocketvault/internal/repositories"
	"rocketvault/internal/services/certificates"
	"rocketvault/model"
)

// mockCertRepoForRenewal satisfies CertificateRepositoryInterface for renewal tests.
type mockCertRepoForRenewal struct{ mock.Mock }

func (m *mockCertRepoForRenewal) Create(ctx context.Context, cert *model.Certificate) error {
	return m.Called(ctx, cert).Error(0)
}

func (m *mockCertRepoForRenewal) Read(ctx context.Context, id uuid.UUID, scope model.Scope) (*model.Certificate, error) {
	args := m.Called(ctx, id, scope)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*model.Certificate), args.Error(1)
}

func (m *mockCertRepoForRenewal) Update(ctx context.Context, cert *model.Certificate, scope model.Scope) error {
	args := m.Called(ctx, cert, scope)
	return args.Error(0)
}

func (m *mockCertRepoForRenewal) List(ctx context.Context, scope model.Scope, filter repositories.CertificateFilter) ([]model.Certificate, error) {
	args := m.Called(ctx, scope, filter)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]model.Certificate), args.Error(1)
}

func (m *mockCertRepoForRenewal) ListDueForRenewal(ctx context.Context, scope model.Scope) ([]model.Certificate, error) {
	args := m.Called(ctx, scope)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]model.Certificate), args.Error(1)
}

func (m *mockCertRepoForRenewal) Delete(ctx context.Context, id uuid.UUID) error {
	return m.Called(ctx, id).Error(0)
}

func (m *mockCertRepoForRenewal) Revoke(ctx context.Context, id uuid.UUID, serialNumber, name string) error {
	return m.Called(ctx, id, serialNumber, name).Error(0)
}

func (m *mockCertRepoForRenewal) ListRevoked(ctx context.Context, userID uuid.UUID) ([]model.RevokedCertificate, error) {
	args := m.Called(ctx, userID)
	if v := args.Get(0); v != nil {
		return v.([]model.RevokedCertificate), args.Error(1)
	}
	return nil, args.Error(1)
}

func (m *mockCertRepoForRenewal) SoftDelete(ctx context.Context, id uuid.UUID) error {
	return m.Called(ctx, id).Error(0)
}

func (m *mockCertRepoForRenewal) RecoverCertificate(ctx context.Context, id uuid.UUID) error {
	return m.Called(ctx, id).Error(0)
}

func (m *mockCertRepoForRenewal) PurgeCertificate(ctx context.Context, id uuid.UUID) error {
	return m.Called(ctx, id).Error(0)
}

func (m *mockCertRepoForRenewal) SetPurgeProtection(ctx context.Context, id uuid.UUID, enabled bool) error {
	return m.Called(ctx, id, enabled).Error(0)
}

func (m *mockCertRepoForRenewal) ListAll(ctx context.Context) ([]model.Certificate, error) {
	args := m.Called(ctx)
	if v := args.Get(0); v != nil {
		return v.([]model.Certificate), args.Error(1)
	}
	return nil, args.Error(1)
}

func (m *mockCertRepoForRenewal) SoftDeleteVaultContents(ctx context.Context, vaultID uuid.UUID, deletedAt time.Time) error {
	args := m.Called(ctx, vaultID, deletedAt)
	return args.Error(0)
}

func (m *mockCertRepoForRenewal) RecoverVaultContents(ctx context.Context, vaultID uuid.UUID, deletedAt time.Time) error {
	args := m.Called(ctx, vaultID, deletedAt)
	return args.Error(0)
}

// mockCertSvcForRenewal satisfies CertificateService for renewal tests.
// Only RenewCertificate is exercised; all other methods panic if called unexpectedly.
type mockCertSvcForRenewal struct{ mock.Mock }

func (m *mockCertSvcForRenewal) CreateSelfSignedCertificate(ctx context.Context, req certificates.CreateCertificateRequest) (*certificates.CreateCertificateResult, error) {
	panic("not called")
}

func (m *mockCertSvcForRenewal) CreateCASignedCertificate(ctx context.Context, req certificates.CreateCertificateRequest) (*certificates.CreateCertificateResult, error) {
	panic("not called")
}

func (m *mockCertSvcForRenewal) GetCertificate(ctx context.Context, certID uuid.UUID, scope model.Scope) (*model.Certificate, error) {
	panic("not called")
}

func (m *mockCertSvcForRenewal) ListCertificates(ctx context.Context, scope model.Scope, filter repositories.CertificateFilter) ([]model.Certificate, error) {
	panic("not called")
}

func (m *mockCertSvcForRenewal) UpdateCertificate(ctx context.Context, req certificates.UpdateCertificateRequest) error {
	panic("not called")
}

func (m *mockCertSvcForRenewal) DeleteCertificate(ctx context.Context, certID uuid.UUID, scope model.Scope) error {
	panic("not called")
}

func (m *mockCertSvcForRenewal) RenewCertificate(ctx context.Context, certID uuid.UUID, scope model.Scope, validityDays int) (*certificates.CreateCertificateResult, error) {
	args := m.Called(ctx, certID, scope, validityDays)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*certificates.CreateCertificateResult), args.Error(1)
}

func (m *mockCertSvcForRenewal) ValidateCertificateAccess(ctx context.Context, certID uuid.UUID, scope model.Scope) error {
	panic("not called")
}

func (m *mockCertSvcForRenewal) ValidateKeyOwnership(ctx context.Context, keyID uuid.UUID, scope model.Scope) error {
	panic("not called")
}

func (m *mockCertSvcForRenewal) ListDeletedCertificates(ctx context.Context, scope model.Scope) ([]model.Certificate, error) {
	panic("not called")
}

func (m *mockCertSvcForRenewal) RecoverCertificate(ctx context.Context, certID uuid.UUID, scope model.Scope) error {
	panic("not called")
}

func (m *mockCertSvcForRenewal) PurgeCertificate(ctx context.Context, certID uuid.UUID, scope model.Scope) error {
	panic("not called")
}

func (m *mockCertSvcForRenewal) GetCertificatePolicy(ctx context.Context, certID uuid.UUID, scope model.Scope) (*model.CertificatePolicy, error) {
	panic("not called")
}

func (m *mockCertSvcForRenewal) UpsertCertificatePolicy(ctx context.Context, certID uuid.UUID, scope model.Scope, req model.UpsertCertificatePolicyRequest) (*model.CertificatePolicy, error) {
	panic("not called")
}

func (m *mockCertSvcForRenewal) DeleteCertificatePolicy(ctx context.Context, certID uuid.UUID, scope model.Scope) error {
	panic("not called")
}

func (m *mockCertSvcForRenewal) ListCertificatePolicies(ctx context.Context, scope model.Scope) ([]model.CertificatePolicyWithCertName, error) {
	panic("not called")
}

func (m *mockCertSvcForRenewal) ListCertificatesDueForRenewal(ctx context.Context, scope model.Scope) ([]model.Certificate, error) {
	panic("not called")
}

// newTestLogger creates a minimal logger for unit tests.
func newTestLogger() *logging.Logger {
	return &logging.Logger{Logger: logrus.New()}
}

func TestCheckAndRenewCertificates_AutoRenew(t *testing.T) {
	expires := time.Now().Add(10 * 24 * time.Hour)
	certID := uuid.New()
	userID := uuid.New()
	cert := model.Certificate{
		ID:          certID,
		UserID:      userID,
		Name:        "test-cert",
		CreatedAt:   time.Now().Add(-365 * 24 * time.Hour),
		ExpiresAt:   &expires,
		AutoRenew:   true,
		RenewalDays: 30,
	}

	repo := &mockCertRepoForRenewal{}
	repo.On("ListAll", mock.Anything).Return([]model.Certificate{cert}, nil)

	certSvc := &mockCertSvcForRenewal{}
	certSvc.On("RenewCertificate", mock.Anything, certID, model.NewAdminScope(userID), mock.AnythingOfType("int")).
		Return(&certificates.CreateCertificateResult{CertID: uuid.New()}, nil)

	svc := certificates.NewCertificateRenewalService(certificates.RenewalServiceConfig{
		CertRepository:     repo,
		CertificateService: certSvc,
		Logger:             newTestLogger(),
	})

	renewed, warned, err := svc.CheckAndRenewCertificates(context.Background())
	require.NoError(t, err)
	assert.Equal(t, 1, renewed)
	assert.Equal(t, 0, warned)
	certSvc.AssertExpectations(t)
}

func TestCheckAndRenewCertificates_WarnOnly(t *testing.T) {
	expires := time.Now().Add(10 * 24 * time.Hour)
	cert := model.Certificate{
		ID:          uuid.New(),
		UserID:      uuid.New(),
		Name:        "warn-cert",
		CreatedAt:   time.Now().Add(-365 * 24 * time.Hour),
		ExpiresAt:   &expires,
		AutoRenew:   false,
		RenewalDays: 30,
	}

	repo := &mockCertRepoForRenewal{}
	repo.On("ListAll", mock.Anything).Return([]model.Certificate{cert}, nil)

	certSvc := &mockCertSvcForRenewal{}
	// RenewCertificate must NOT be called.

	svc := certificates.NewCertificateRenewalService(certificates.RenewalServiceConfig{
		CertRepository:     repo,
		CertificateService: certSvc,
		Logger:             newTestLogger(),
	})

	renewed, warned, err := svc.CheckAndRenewCertificates(context.Background())
	require.NoError(t, err)
	assert.Equal(t, 0, renewed)
	assert.Equal(t, 1, warned)
	certSvc.AssertNotCalled(t, "RenewCertificate")
}

func (m *mockCertSvcForRenewal) ListCertificateVersions(ctx context.Context, certID uuid.UUID, scope model.Scope) ([]model.CertificateVersion, error) {
	panic("not called")
}

func (m *mockCertSvcForRenewal) GetCertificateVersion(ctx context.Context, certID uuid.UUID, version int, scope model.Scope) (*model.CertificateVersion, error) {
	panic("not called")
}

func (m *mockCertSvcForRenewal) UpdateCertificateVersion(ctx context.Context, req certificates.UpdateCertificateVersionRequest) (*model.CertificateVersion, error) {
	panic("not called")
}
