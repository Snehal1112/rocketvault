package certificates_test

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
	logtest "github.com/sirupsen/logrus/hooks/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"rocketvault/internal/logging"
	"rocketvault/internal/repositories"
	"rocketvault/internal/services/authorization"
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
	vaultID := uuid.New()
	cert := model.Certificate{
		ID:          certID,
		UserID:      userID,
		VaultID:     vaultID,
		Name:        "test-cert",
		CreatedAt:   time.Now().Add(-365 * 24 * time.Hour),
		ExpiresAt:   &expires,
		AutoRenew:   true,
		RenewalDays: 30,
	}

	repo := &mockCertRepoForRenewal{}
	repo.On("ListAll", mock.Anything).Return([]model.Certificate{cert}, nil)

	// B76: the scheduler must renew inside the certificate's own vault. An
	// admin scope carries no vault predicate, so it let a restored row reach
	// keys and CA certificates in other vaults.
	certSvc := &mockCertSvcForRenewal{}
	certSvc.On("RenewCertificate", mock.Anything, certID, model.NewVaultScope(vaultID, userID), mock.AnythingOfType("int")).
		Return(&certificates.CreateCertificateResult{CertID: uuid.New()}, nil)

	svc := certificates.NewCertificateRenewalService(certificates.RenewalServiceConfig{
		CertRepository:     repo,
		CertificateService: certSvc,
		Logger:             newTestLogger(),
		SignAuthorizer:     allowSign,
	})

	renewed, warned, err := svc.CheckAndRenewCertificates(context.Background())
	require.NoError(t, err)
	assert.Equal(t, 1, renewed)
	assert.Equal(t, 0, warned)
	certSvc.AssertExpectations(t)
}

// TestCheckAndRenewCertificates_NilVaultSkipped pins that a row with no vault
// is never renewed. There is no vault to scope the renewal to, and falling
// back to a broader scope is the B76 defect.
func TestCheckAndRenewCertificates_NilVaultSkipped(t *testing.T) {
	expires := time.Now().Add(10 * 24 * time.Hour)
	cert := model.Certificate{
		ID:          uuid.New(),
		UserID:      uuid.New(),
		Name:        "no-vault",
		CreatedAt:   time.Now().Add(-365 * 24 * time.Hour),
		ExpiresAt:   &expires,
		AutoRenew:   true,
		RenewalDays: 30,
	}

	repo := &mockCertRepoForRenewal{}
	repo.On("ListAll", mock.Anything).Return([]model.Certificate{cert}, nil)
	certSvc := &mockCertSvcForRenewal{}

	svc := certificates.NewCertificateRenewalService(certificates.RenewalServiceConfig{
		CertRepository:     repo,
		CertificateService: certSvc,
		Logger:             newTestLogger(),
	})

	renewed, warned, err := svc.CheckAndRenewCertificates(context.Background())
	require.NoError(t, err)
	assert.Equal(t, 0, renewed)
	assert.Equal(t, 0, warned)
	certSvc.AssertNotCalled(t, "RenewCertificate", mock.Anything, mock.Anything, mock.Anything, mock.Anything)
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

func (m *mockCertSvcForRenewal) ExportCertificate(context.Context, model.Scope, uuid.UUID, certificates.ExportCertificateRequest) (*certificates.ExportCertificateResult, error) {
	panic("not called")
}

// allowSign is a KeySignAuthorizer that grants every request.
func allowSign(context.Context, uuid.UUID, uuid.UUID) error { return nil }

// dueAutoRenewCert returns a certificate inside its renewal window with
// auto-renew on, in vaultID, owned by userID.
func dueAutoRenewCert(userID, vaultID uuid.UUID) model.Certificate {
	expires := time.Now().Add(10 * 24 * time.Hour)
	return model.Certificate{
		ID: uuid.New(), UserID: userID, VaultID: vaultID, Name: "due",
		CreatedAt: time.Now().Add(-365 * 24 * time.Hour), ExpiresAt: &expires,
		AutoRenew: true, RenewalDays: 30,
	}
}

// newHookedLogger returns a logger and a hook that records every entry, so a
// test can tell a refusal from a fault by the logged audit status.
func newHookedLogger() (*logging.Logger, *logtest.Hook) {
	l, hook := logtest.NewNullLogger()
	return &logging.Logger{Logger: l}, hook
}

// autoRenewStatuses returns the status field of every cert_auto_renew entry.
func autoRenewStatuses(hook *logtest.Hook) []string {
	var statuses []string
	for _, e := range hook.AllEntries() {
		if e.Data["operation"] == "cert_auto_renew" {
			statuses = append(statuses, fmt.Sprint(e.Data["status"]))
		}
	}
	return statuses
}

// TestCheckAndRenewCertificates_RefusesWhenOwnerCannotSign is the scheduler
// half of B77: an owner who lost keys/sign in the vault gets no more
// unattended re-signing. The check names the owner and the certificate's own
// vault, never an admin or another vault.
func TestCheckAndRenewCertificates_RefusesWhenOwnerCannotSign(t *testing.T) {
	userID, vaultID := uuid.New(), uuid.New()
	repo := &mockCertRepoForRenewal{}
	repo.On("ListAll", mock.Anything).Return([]model.Certificate{dueAutoRenewCert(userID, vaultID)}, nil)
	certSvc := &mockCertSvcForRenewal{}
	logger, hook := newHookedLogger()

	var gotPrincipal, gotVault uuid.UUID
	calls := 0
	svc := certificates.NewCertificateRenewalService(certificates.RenewalServiceConfig{
		CertRepository:     repo,
		CertificateService: certSvc,
		Logger:             logger,
		SignAuthorizer: func(_ context.Context, principalID, vaultID uuid.UUID) error {
			calls++
			gotPrincipal, gotVault = principalID, vaultID
			return fmt.Errorf("%w: no role grants keys/sign in this vault", authorization.ErrDataPlaneDenied)
		},
	})

	renewed, warned, err := svc.CheckAndRenewCertificates(context.Background())
	require.NoError(t, err)
	assert.Equal(t, 0, renewed)
	assert.Equal(t, 0, warned)
	assert.Equal(t, 1, calls)
	assert.Equal(t, userID, gotPrincipal)
	assert.Equal(t, vaultID, gotVault)
	assert.Equal(t, []string{"denied"}, autoRenewStatuses(hook))
	certSvc.AssertNotCalled(t, "RenewCertificate", mock.Anything, mock.Anything, mock.Anything, mock.Anything)
}

// TestCheckAndRenewCertificates_RefusesWithoutSignAuthorizer pins the
// fail-closed default: a scheduler wired without the check renews nothing.
func TestCheckAndRenewCertificates_RefusesWithoutSignAuthorizer(t *testing.T) {
	repo := &mockCertRepoForRenewal{}
	repo.On("ListAll", mock.Anything).Return([]model.Certificate{dueAutoRenewCert(uuid.New(), uuid.New())}, nil)
	certSvc := &mockCertSvcForRenewal{}
	logger, hook := newHookedLogger()

	svc := certificates.NewCertificateRenewalService(certificates.RenewalServiceConfig{
		CertRepository:     repo,
		CertificateService: certSvc,
		Logger:             logger,
	})

	renewed, _, err := svc.CheckAndRenewCertificates(context.Background())
	require.NoError(t, err)
	assert.Equal(t, 0, renewed)
	assert.Equal(t, []string{"failed"}, autoRenewStatuses(hook))
	certSvc.AssertNotCalled(t, "RenewCertificate", mock.Anything, mock.Anything, mock.Anything, mock.Anything)
}

// TestCheckAndRenewCertificates_AuthorizerFaultSkipsAsFailure pins that a
// fault in the check, such as a failed role lookup, never renews and is
// logged as a failure, not as a refusal.
func TestCheckAndRenewCertificates_AuthorizerFaultSkipsAsFailure(t *testing.T) {
	faults := map[string]error{
		"lookup failure": fmt.Errorf("checking vault authorization: %w", errors.New("database is locked")),
		"misuse":         authorization.ErrDataPlaneMisuse,
		"unavailable":    authorization.ErrAuthorizationUnavailable,
	}
	for name, fault := range faults {
		t.Run(name, func(t *testing.T) {
			repo := &mockCertRepoForRenewal{}
			repo.On("ListAll", mock.Anything).Return([]model.Certificate{dueAutoRenewCert(uuid.New(), uuid.New())}, nil)
			certSvc := &mockCertSvcForRenewal{}
			logger, hook := newHookedLogger()

			svc := certificates.NewCertificateRenewalService(certificates.RenewalServiceConfig{
				CertRepository:     repo,
				CertificateService: certSvc,
				Logger:             logger,
				SignAuthorizer:     func(context.Context, uuid.UUID, uuid.UUID) error { return fault },
			})

			renewed, _, err := svc.CheckAndRenewCertificates(context.Background())
			require.NoError(t, err)
			assert.Equal(t, 0, renewed)
			assert.Equal(t, []string{"failed"}, autoRenewStatuses(hook))
			entry := hook.LastEntry()
			require.NotNil(t, entry)
			assert.Equal(t, logrus.ErrorLevel, entry.Level)
			assert.ErrorIs(t, entry.Data[logrus.ErrorKey].(error), fault)
			certSvc.AssertNotCalled(t, "RenewCertificate", mock.Anything, mock.Anything, mock.Anything, mock.Anything)
		})
	}
}

// TestCheckAndRenewCertificates_ChecksSignBeforeRenewing pins the order: the
// keys/sign check runs before RenewCertificate, so a refusal can never come
// after the certificate was already re-signed.
func TestCheckAndRenewCertificates_ChecksSignBeforeRenewing(t *testing.T) {
	userID, vaultID := uuid.New(), uuid.New()
	cert := dueAutoRenewCert(userID, vaultID)
	repo := &mockCertRepoForRenewal{}
	repo.On("ListAll", mock.Anything).Return([]model.Certificate{cert}, nil)

	var order []string
	certSvc := &mockCertSvcForRenewal{}
	certSvc.On("RenewCertificate", mock.Anything, cert.ID, model.NewVaultScope(vaultID, userID), mock.AnythingOfType("int")).
		Run(func(mock.Arguments) { order = append(order, "renew") }).
		Return(&certificates.CreateCertificateResult{CertID: uuid.New()}, nil)

	svc := certificates.NewCertificateRenewalService(certificates.RenewalServiceConfig{
		CertRepository:     repo,
		CertificateService: certSvc,
		Logger:             newTestLogger(),
		SignAuthorizer: func(context.Context, uuid.UUID, uuid.UUID) error {
			order = append(order, "authorize")
			return nil
		},
	})

	renewed, _, err := svc.CheckAndRenewCertificates(context.Background())
	require.NoError(t, err)
	assert.Equal(t, 1, renewed)
	assert.Equal(t, []string{"authorize", "renew"}, order)
	certSvc.AssertExpectations(t)
}

// TestCheckAndRenewCertificates_SkippedRowDoesNotStopLaterRows pins that a
// skip is per row: a row with no vault and a row whose owner cannot sign are
// both skipped, and a later valid row still renews.
func TestCheckAndRenewCertificates_SkippedRowDoesNotStopLaterRows(t *testing.T) {
	deniedOwner, allowedOwner, vaultID := uuid.New(), uuid.New(), uuid.New()
	noVault := dueAutoRenewCert(uuid.New(), uuid.Nil)
	denied := dueAutoRenewCert(deniedOwner, vaultID)
	allowed := dueAutoRenewCert(allowedOwner, vaultID)

	repo := &mockCertRepoForRenewal{}
	repo.On("ListAll", mock.Anything).Return([]model.Certificate{noVault, denied, allowed}, nil)
	certSvc := &mockCertSvcForRenewal{}
	certSvc.On("RenewCertificate", mock.Anything, allowed.ID, model.NewVaultScope(vaultID, allowedOwner), mock.AnythingOfType("int")).
		Return(&certificates.CreateCertificateResult{CertID: uuid.New()}, nil).Once()

	svc := certificates.NewCertificateRenewalService(certificates.RenewalServiceConfig{
		CertRepository:     repo,
		CertificateService: certSvc,
		Logger:             newTestLogger(),
		SignAuthorizer: func(_ context.Context, principalID, _ uuid.UUID) error {
			if principalID == deniedOwner {
				return fmt.Errorf("%w: no role grants keys/sign in this vault", authorization.ErrDataPlaneDenied)
			}
			return nil
		},
	})

	renewed, _, err := svc.CheckAndRenewCertificates(context.Background())
	require.NoError(t, err)
	assert.Equal(t, 1, renewed)
	certSvc.AssertExpectations(t)
	certSvc.AssertNumberOfCalls(t, "RenewCertificate", 1)
}

// fakeSignPolicies is an AccessPolicyService whose CheckAccess denies only
// (keys, sign), and records the arguments it was asked about.
type fakeSignPolicies struct {
	authorization.AccessPolicyService
	err          error
	gotResource  model.PolicyResourceType
	gotOperation model.PolicyOperation
	gotPrincipal uuid.UUID
	gotVault     uuid.UUID
}

func (f *fakeSignPolicies) CheckAccess(_ context.Context, principalID uuid.UUID, resourceType model.PolicyResourceType, operation model.PolicyOperation, vaultID uuid.UUID) (authorization.AccessDecision, error) {
	f.gotResource, f.gotOperation, f.gotPrincipal, f.gotVault = resourceType, operation, principalID, vaultID
	if f.err != nil {
		return authorization.AccessFallback, f.err
	}
	if resourceType == model.PolicyResourceKeys && operation == model.OpSign {
		return authorization.AccessDenied, nil
	}
	return authorization.AccessFallback, nil
}

// fakeSignRoles is a RoleAssignmentService that grants every data action, or
// fails the lookup when err is set.
type fakeSignRoles struct {
	authorization.RoleAssignmentService
	grant     bool
	err       error
	gotAction model.DataAction
}

func (f *fakeSignRoles) HasDataAction(_ context.Context, _, _ uuid.UUID, action model.DataAction) (bool, error) {
	f.gotAction = action
	return f.grant, f.err
}

// noDenyPolicies is an AccessPolicyService with no policy at all.
type noDenyPolicies struct {
	authorization.AccessPolicyService
}

func (noDenyPolicies) CheckAccess(context.Context, uuid.UUID, model.PolicyResourceType, model.PolicyOperation, uuid.UUID) (authorization.AccessDecision, error) {
	return authorization.AccessFallback, nil
}

// TestNewKeySignAuthorizer_ExplicitKeySignDenyWins pins the authorizer the
// container wires: its policy check names (keys, sign), so an explicit deny
// on key sign refuses even when a role grants keys/sign, and the scheduler
// skips the row as a refusal.
func TestNewKeySignAuthorizer_ExplicitKeySignDenyWins(t *testing.T) {
	userID, vaultID := uuid.New(), uuid.New()
	policies := &fakeSignPolicies{}
	roles := &fakeSignRoles{grant: true}

	repo := &mockCertRepoForRenewal{}
	repo.On("ListAll", mock.Anything).Return([]model.Certificate{dueAutoRenewCert(userID, vaultID)}, nil)
	certSvc := &mockCertSvcForRenewal{}
	logger, hook := newHookedLogger()

	svc := certificates.NewCertificateRenewalService(certificates.RenewalServiceConfig{
		CertRepository:     repo,
		CertificateService: certSvc,
		Logger:             logger,
		SignAuthorizer:     certificates.NewKeySignAuthorizer(policies, roles),
	})

	renewed, _, err := svc.CheckAndRenewCertificates(context.Background())
	require.NoError(t, err)
	assert.Equal(t, 0, renewed)
	assert.Equal(t, model.PolicyResourceKeys, policies.gotResource)
	assert.Equal(t, model.OpSign, policies.gotOperation)
	assert.Equal(t, userID, policies.gotPrincipal)
	assert.Equal(t, vaultID, policies.gotVault)
	assert.Empty(t, roles.gotAction, "an explicit deny must short-circuit the role check")
	assert.Equal(t, []string{"denied"}, autoRenewStatuses(hook))
	certSvc.AssertNotCalled(t, "RenewCertificate", mock.Anything, mock.Anything, mock.Anything, mock.Anything)
}

// TestNewKeySignAuthorizer_Outcomes pins the error class of each outcome of
// the wired authorizer: a grant passes, no grant is a refusal, and a lookup
// failure or missing service is a fault that never reads as a refusal.
func TestNewKeySignAuthorizer_Outcomes(t *testing.T) {
	ctx := context.Background()
	principalID, vaultID := uuid.New(), uuid.New()

	granted := &fakeSignRoles{grant: true}
	require.NoError(t, certificates.NewKeySignAuthorizer(noDenyPolicies{}, granted)(ctx, principalID, vaultID))
	assert.Equal(t, model.ActionKeysSign, granted.gotAction)

	err := certificates.NewKeySignAuthorizer(noDenyPolicies{}, &fakeSignRoles{})(ctx, principalID, vaultID)
	require.ErrorIs(t, err, authorization.ErrDataPlaneDenied)

	lookup := errors.New("database is locked")
	err = certificates.NewKeySignAuthorizer(noDenyPolicies{}, &fakeSignRoles{err: lookup})(ctx, principalID, vaultID)
	require.ErrorIs(t, err, lookup)
	require.NotErrorIs(t, err, authorization.ErrDataPlaneDenied)

	err = certificates.NewKeySignAuthorizer(&fakeSignPolicies{err: lookup}, granted)(ctx, principalID, vaultID)
	require.ErrorIs(t, err, lookup)
	require.NotErrorIs(t, err, authorization.ErrDataPlaneDenied)

	err = certificates.NewKeySignAuthorizer(nil, nil)(ctx, principalID, vaultID)
	require.ErrorIs(t, err, authorization.ErrAuthorizationUnavailable)
	require.NotErrorIs(t, err, authorization.ErrDataPlaneDenied)
}

// TestCheckAndRenewCertificates_ClampsPreCapValidity pins Decision D5 of B78:
// a certificate issued before the cap with a longer period still auto-renews,
// at the capped period, instead of failing ErrInvalidValidityDays every run.
func TestCheckAndRenewCertificates_ClampsPreCapValidity(t *testing.T) {
	expires := time.Now().Add(10 * 24 * time.Hour)
	certID, userID, vaultID := uuid.New(), uuid.New(), uuid.New()
	cert := model.Certificate{
		ID:          certID,
		UserID:      userID,
		VaultID:     vaultID,
		Name:        "long-lived",
		CreatedAt:   expires.AddDate(0, 0, -(model.MaxCertificateValidityDays + 1000)),
		ExpiresAt:   &expires,
		AutoRenew:   true,
		RenewalDays: 30,
	}

	repo := &mockCertRepoForRenewal{}
	repo.On("ListAll", mock.Anything).Return([]model.Certificate{cert}, nil)

	certSvc := &mockCertSvcForRenewal{}
	certSvc.On("RenewCertificate", mock.Anything, certID, model.NewVaultScope(vaultID, userID), model.MaxCertificateValidityDays).
		Return(&certificates.CreateCertificateResult{CertID: uuid.New()}, nil)

	svc := certificates.NewCertificateRenewalService(certificates.RenewalServiceConfig{
		CertRepository:     repo,
		CertificateService: certSvc,
		Logger:             newTestLogger(),
		SignAuthorizer:     allowSign,
	})

	renewed, _, err := svc.CheckAndRenewCertificates(context.Background())
	require.NoError(t, err)
	assert.Equal(t, 1, renewed)
	certSvc.AssertExpectations(t)
}
