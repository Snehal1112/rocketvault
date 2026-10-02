package certificates

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	"rocketvault/cmd/testutils"
	"rocketvault/cmd/vaultcli"
	"rocketvault/common"
	"rocketvault/internal/formatter"
	"rocketvault/internal/logging"
	"rocketvault/internal/repositories"
	authzServices "rocketvault/internal/services/authorization"
	certServices "rocketvault/internal/services/certificates"
	"rocketvault/model"
)

// TestMain registers every Init function exactly once (covering those
// registration code paths) and then runs all tests in the package.
func TestMain(m *testing.M) {
	parent := &cobra.Command{Use: "certs"}
	InitCertificatesCreate(parent)
	InitCertificatesDelete(parent)
	InitCertificatesGet(parent)
	InitCertificatesList(parent)
	InitCertificatesRenew(parent)
	InitCertificatesUpdate(parent)
	InitCertificatesRotationPolicy(parent)
	os.Exit(m.Run())
}

// ---- mock certificate service ----

type certCmdCertService struct{ mock.Mock }

func (m *certCmdCertService) CreateSelfSignedCertificate(ctx context.Context, req certServices.CreateCertificateRequest) (*certServices.CreateCertificateResult, error) {
	args := m.Called(ctx, req)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*certServices.CreateCertificateResult), args.Error(1)
}

func (m *certCmdCertService) CreateCASignedCertificate(ctx context.Context, req certServices.CreateCertificateRequest) (*certServices.CreateCertificateResult, error) {
	args := m.Called(ctx, req)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*certServices.CreateCertificateResult), args.Error(1)
}

func (m *certCmdCertService) GetCertificate(ctx context.Context, certID uuid.UUID, scope model.Scope) (*model.Certificate, error) {
	args := m.Called(ctx, certID, scope)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*model.Certificate), args.Error(1)
}

func (m *certCmdCertService) ListCertificates(ctx context.Context, scope model.Scope, filter repositories.CertificateFilter) ([]model.Certificate, error) {
	args := m.Called(ctx, scope, filter)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]model.Certificate), args.Error(1)
}

func (m *certCmdCertService) UpdateCertificate(ctx context.Context, req certServices.UpdateCertificateRequest) error {
	args := m.Called(ctx, req)
	return args.Error(0)
}

func (m *certCmdCertService) DeleteCertificate(ctx context.Context, certID uuid.UUID, scope model.Scope) error {
	args := m.Called(ctx, certID, scope)
	return args.Error(0)
}

func (m *certCmdCertService) RenewCertificate(ctx context.Context, certID uuid.UUID, scope model.Scope, validityDays int) (*certServices.CreateCertificateResult, error) {
	args := m.Called(ctx, certID, scope, validityDays)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*certServices.CreateCertificateResult), args.Error(1)
}

func (m *certCmdCertService) ValidateCertificateAccess(ctx context.Context, certID uuid.UUID, scope model.Scope) error {
	return nil
}

func (m *certCmdCertService) ValidateKeyOwnership(ctx context.Context, keyID uuid.UUID, scope model.Scope) error {
	return nil
}

func (m *certCmdCertService) ListDeletedCertificates(ctx context.Context, scope model.Scope) ([]model.Certificate, error) {
	args := m.Called(ctx, scope)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]model.Certificate), args.Error(1)
}

func (m *certCmdCertService) RecoverCertificate(ctx context.Context, certID uuid.UUID, scope model.Scope) error {
	return m.Called(ctx, certID, scope).Error(0)
}

func (m *certCmdCertService) PurgeCertificate(ctx context.Context, certID uuid.UUID, scope model.Scope) error {
	return m.Called(ctx, certID, scope).Error(0)
}

func (m *certCmdCertService) GetCertificatePolicy(ctx context.Context, certID uuid.UUID, scope model.Scope) (*model.CertificatePolicy, error) {
	args := m.Called(ctx, certID, scope)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*model.CertificatePolicy), args.Error(1)
}

func (m *certCmdCertService) UpsertCertificatePolicy(ctx context.Context, certID uuid.UUID, scope model.Scope, req model.UpsertCertificatePolicyRequest) (*model.CertificatePolicy, error) {
	args := m.Called(ctx, certID, scope, req)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*model.CertificatePolicy), args.Error(1)
}

func (m *certCmdCertService) DeleteCertificatePolicy(ctx context.Context, certID uuid.UUID, scope model.Scope) error {
	return m.Called(ctx, certID, scope).Error(0)
}

func (m *certCmdCertService) ListCertificatePolicies(ctx context.Context, scope model.Scope) ([]model.CertificatePolicyWithCertName, error) {
	args := m.Called(ctx, scope)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]model.CertificatePolicyWithCertName), args.Error(1)
}

func (m *certCmdCertService) ListCertificatesDueForRenewal(ctx context.Context, scope model.Scope) ([]model.Certificate, error) {
	args := m.Called(ctx, scope)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]model.Certificate), args.Error(1)
}

// ---- container wrapper ----

// certsTestContainer wraps MockServiceContainer and overrides GetCertificateService.
type certsTestContainer struct {
	*testutils.MockServiceContainer
	certSvc certServices.CertificateService
}

func (c *certsTestContainer) GetCertificateService() certServices.CertificateService {
	return c.certSvc
}

// ---- context/helper factories ----

func newCertLogger() *logging.Logger {
	return &logging.Logger{Logger: logrus.New()}
}

func newCertFmtr() formatter.Formatter {
	f, _ := formatter.New(formatter.FormatTable)
	return f
}

// buildCertAdminCtx creates a context carrying admin claims, a logger, the
// given service container, and an output formatter.
func buildCertAdminCtx(sc interface{}) context.Context {
	userID := uuid.New()
	claims := &model.Claims{UserID: userID, Username: "admin", Roles: []string{model.RoleAdmin}}
	ctx := context.Background()
	ctx = context.WithValue(ctx, common.ClaimsKey, claims)
	ctx = context.WithValue(ctx, common.LogKey, newCertLogger())
	ctx = context.WithValue(ctx, common.ServiceContainerKey, sc)
	ctx = context.WithValue(ctx, common.OutputFormatterKey, newCertFmtr())
	return ctx
}

// buildCertRoleCtx creates a context with the specified role.
func buildCertRoleCtx(sc interface{}, role string) context.Context {
	userID := uuid.New()
	claims := &model.Claims{UserID: userID, Username: "user", Roles: []string{role}}
	ctx := context.Background()
	ctx = context.WithValue(ctx, common.ClaimsKey, claims)
	ctx = context.WithValue(ctx, common.LogKey, newCertLogger())
	ctx = context.WithValue(ctx, common.ServiceContainerKey, sc)
	ctx = context.WithValue(ctx, common.OutputFormatterKey, newCertFmtr())
	return ctx
}

// setFlags registers each key as a flag on cmd (if not already registered)
// and sets its value. Commands read their inputs from their own flag set,
// never from global viper: two commands binding the same viper key overwrite
// each other process-wide, which is what silently disabled `keys list --tags`.
func setFlags(cmd *cobra.Command, kvs map[string]any) {
	for k, v := range kvs {
		switch val := v.(type) {
		case string:
			if cmd.Flags().Lookup(k) == nil {
				cmd.Flags().String(k, val, "")
				continue
			}
			_ = cmd.Flags().Set(k, val)
		case int:
			if cmd.Flags().Lookup(k) == nil {
				cmd.Flags().Int(k, val, "")
				continue
			}
			_ = cmd.Flags().Set(k, strconv.Itoa(val))
		case bool:
			if cmd.Flags().Lookup(k) == nil {
				cmd.Flags().Bool(k, val, "")
				continue
			}
			_ = cmd.Flags().Set(k, strconv.FormatBool(val))
		default:
			panic("setFlags: unsupported flag type for " + k)
		}
	}
}

// newCertCmd creates a minimal test command that delegates to the given RunE
// and captures output in a buffer.
func newCertCmd(runE func(*cobra.Command, []string) error, args []string) (*cobra.Command, *bytes.Buffer) {
	cmd := &cobra.Command{Use: "test", RunE: runE}
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	cmd.SetArgs(args)
	return cmd, &buf
}

// ========== createCmd tests ==========

func TestCertCreateCmd_NoClaims(t *testing.T) {
	ctx := context.Background()
	cmd, _ := newCertCmd(createCmd.RunE, nil)
	cmd.Flags().Bool("auto-renew", false, "")
	cmd.Flags().Int("renewal-days", 30, "")
	cmd.SetContext(ctx)
	err := cmd.Execute()
	assert.ErrorContains(t, err, "unauthorized")
}

func TestCertCreateCmd_ForbiddenRole(t *testing.T) {
	sc := &certsTestContainer{MockServiceContainer: &testutils.MockServiceContainer{}}
	ctx := buildCertRoleCtx(sc, model.RoleUser)
	cmd, _ := newCertCmd(createCmd.RunE, nil)
	cmd.Flags().Bool("auto-renew", false, "")
	cmd.Flags().Int("renewal-days", 30, "")
	setFlags(cmd, map[string]any{"name": "mycert", "key-id": uuid.New().String(), "validity-days": 365})
	cmd.SetContext(ctx)
	err := cmd.Execute()
	assert.ErrorContains(t, err, "forbidden")
}

func TestCertCreateCmd_NoServiceContainer(t *testing.T) {
	claims := &model.Claims{UserID: uuid.New(), Roles: []string{model.RoleAdmin}}
	ctx := context.WithValue(context.Background(), common.ClaimsKey, claims)
	ctx = context.WithValue(ctx, common.LogKey, newCertLogger())
	// No ServiceContainerKey in context.
	cmd, _ := newCertCmd(createCmd.RunE, nil)
	cmd.Flags().Bool("auto-renew", false, "")
	cmd.Flags().Int("renewal-days", 30, "")
	setFlags(cmd, map[string]any{"name": "mycert", "key-id": uuid.New().String(), "validity-days": 365})
	cmd.SetContext(ctx)
	err := cmd.Execute()
	assert.ErrorContains(t, err, "service container not available")
}

func TestCertCreateCmd_MissingName(t *testing.T) {
	sc := &certsTestContainer{MockServiceContainer: &testutils.MockServiceContainer{}}
	ctx := buildCertAdminCtx(sc)
	cmd, _ := newCertCmd(createCmd.RunE, nil)
	cmd.Flags().Bool("auto-renew", false, "")
	cmd.Flags().Int("renewal-days", 30, "")
	setFlags(cmd, map[string]any{"name": "", "key-id": uuid.New().String(), "validity-days": 365})
	cmd.SetContext(ctx)
	err := cmd.Execute()
	assert.ErrorContains(t, err, "name, key-id, and validity-days are required")
}

func TestCertCreateCmd_MissingKeyID(t *testing.T) {
	sc := &certsTestContainer{MockServiceContainer: &testutils.MockServiceContainer{}}
	ctx := buildCertAdminCtx(sc)
	cmd, _ := newCertCmd(createCmd.RunE, nil)
	cmd.Flags().Bool("auto-renew", false, "")
	cmd.Flags().Int("renewal-days", 30, "")
	setFlags(cmd, map[string]any{"name": "mycert", "key-id": "", "validity-days": 365})
	cmd.SetContext(ctx)
	err := cmd.Execute()
	assert.ErrorContains(t, err, "name, key-id, and validity-days are required")
}

func TestCertCreateCmd_InvalidValidityDays(t *testing.T) {
	sc := &certsTestContainer{MockServiceContainer: &testutils.MockServiceContainer{}}
	ctx := buildCertAdminCtx(sc)
	cmd, _ := newCertCmd(createCmd.RunE, nil)
	cmd.Flags().Bool("auto-renew", false, "")
	cmd.Flags().Int("renewal-days", 30, "")
	setFlags(cmd, map[string]any{"name": "mycert", "key-id": uuid.New().String(), "validity-days": 0})
	cmd.SetContext(ctx)
	err := cmd.Execute()
	assert.ErrorContains(t, err, "name, key-id, and validity-days are required")
}

func TestCertCreateCmd_InvalidKeyIDUUID(t *testing.T) {
	sc := &certsTestContainer{MockServiceContainer: &testutils.MockServiceContainer{}}
	ctx := buildCertAdminCtx(sc)
	cmd, _ := newCertCmd(createCmd.RunE, nil)
	cmd.Flags().Bool("auto-renew", false, "")
	cmd.Flags().Int("renewal-days", 30, "")
	setFlags(cmd, map[string]any{"name": "mycert", "key-id": "not-a-uuid", "validity-days": 365})
	cmd.SetContext(ctx)
	err := cmd.Execute()
	assert.ErrorContains(t, err, "invalid key ID")
}

func TestCertCreateCmd_SelfSignedSuccess(t *testing.T) {
	tc := testutils.NewTestContext(t)
	certSvc := &certCmdCertService{}
	keyID := uuid.New()
	result := &certServices.CreateCertificateResult{
		CertID:    uuid.New(),
		Name:      "mycert",
		Tags:      []string{"prod"},
		CreatedAt: time.Now(),
	}
	certSvc.On("CreateSelfSignedCertificate", mock.Anything, mock.MatchedBy(func(r certServices.CreateCertificateRequest) bool {
		return r.Name == "mycert" && r.KeyID == keyID && r.ValidityDays == 365 && r.VaultID == tc.TestVaultID
	})).Return(result, nil)

	sc := &certsTestContainer{
		MockServiceContainer: tc.MockContainer,
		certSvc:              certSvc,
	}
	claims := &model.Claims{UserID: tc.TestUserID, Username: "admin", Roles: []string{model.RoleAdmin}}
	ctx := context.WithValue(context.Background(), common.ClaimsKey, claims)
	ctx = context.WithValue(ctx, common.LogKey, newCertLogger())
	ctx = context.WithValue(ctx, common.ServiceContainerKey, sc)
	ctx = context.WithValue(ctx, common.OutputFormatterKey, newCertFmtr())

	cmd, buf := newCertCmd(createCmd.RunE, nil)
	cmd.Flags().Bool("auto-renew", false, "")
	cmd.Flags().Int("renewal-days", 30, "")
	setFlags(cmd, map[string]any{"name": "mycert",
		"key-id":        keyID.String(),
		"validity-days": 365,
		"tags":          "prod",
		"ca-cert-id":    ""})
	cmd.SetContext(ctx)
	err := cmd.Execute()
	assert.NoError(t, err)
	assert.NotEmpty(t, buf.String())
	certSvc.AssertExpectations(t)
}

func TestCertCreateCmd_CASignedSuccess(t *testing.T) {
	tc := testutils.NewTestContext(t)
	certSvc := &certCmdCertService{}
	keyID := uuid.New()
	caCertID := uuid.New()
	result := &certServices.CreateCertificateResult{
		CertID:    uuid.New(),
		Name:      "casignedcert",
		CreatedAt: time.Now(),
	}
	certSvc.On("CreateCASignedCertificate", mock.Anything, mock.MatchedBy(func(r certServices.CreateCertificateRequest) bool {
		return r.Name == "casignedcert" && r.KeyID == keyID && r.CACertID != nil && *r.CACertID == caCertID && r.VaultID == tc.TestVaultID
	})).Return(result, nil)

	sc := &certsTestContainer{
		MockServiceContainer: tc.MockContainer,
		certSvc:              certSvc,
	}
	claims := &model.Claims{UserID: tc.TestUserID, Username: "admin", Roles: []string{model.RoleAdmin}}
	ctx := context.WithValue(context.Background(), common.ClaimsKey, claims)
	ctx = context.WithValue(ctx, common.LogKey, newCertLogger())
	ctx = context.WithValue(ctx, common.ServiceContainerKey, sc)
	ctx = context.WithValue(ctx, common.OutputFormatterKey, newCertFmtr())

	cmd, buf := newCertCmd(createCmd.RunE, nil)
	cmd.Flags().Bool("auto-renew", false, "")
	cmd.Flags().Int("renewal-days", 30, "")
	setFlags(cmd, map[string]any{"name": "casignedcert",
		"key-id":        keyID.String(),
		"validity-days": 180,
		"tags":          "",
		"ca-cert-id":    caCertID.String()})
	cmd.SetContext(ctx)
	err := cmd.Execute()
	assert.NoError(t, err)
	assert.NotEmpty(t, buf.String())
	certSvc.AssertExpectations(t)
}

func TestCertCreateCmd_InvalidCACertID(t *testing.T) {
	tc := testutils.NewTestContext(t)
	sc := &certsTestContainer{MockServiceContainer: tc.MockContainer}
	claims := &model.Claims{UserID: tc.TestUserID, Username: "admin", Roles: []string{model.RoleAdmin}}
	ctx := context.WithValue(context.Background(), common.ClaimsKey, claims)
	ctx = context.WithValue(ctx, common.LogKey, newCertLogger())
	ctx = context.WithValue(ctx, common.ServiceContainerKey, sc)
	ctx = context.WithValue(ctx, common.OutputFormatterKey, newCertFmtr())

	cmd, _ := newCertCmd(createCmd.RunE, nil)
	cmd.Flags().Bool("auto-renew", false, "")
	cmd.Flags().Int("renewal-days", 30, "")
	setFlags(cmd, map[string]any{"name": "mycert",
		"key-id":        uuid.New().String(),
		"validity-days": 365,
		"tags":          "",
		"ca-cert-id":    "bad-uuid"})
	cmd.SetContext(ctx)
	err := cmd.Execute()
	assert.ErrorContains(t, err, "invalid CA certificate ID")
}

func TestCertCreateCmd_ServiceError(t *testing.T) {
	tc := testutils.NewTestContext(t)
	certSvc := &certCmdCertService{}
	certSvc.On("CreateSelfSignedCertificate", mock.Anything, mock.Anything).Return(nil, fmt.Errorf("db error"))

	sc := &certsTestContainer{
		MockServiceContainer: tc.MockContainer,
		certSvc:              certSvc,
	}
	claims := &model.Claims{UserID: tc.TestUserID, Username: "admin", Roles: []string{model.RoleAdmin}}
	ctx := context.WithValue(context.Background(), common.ClaimsKey, claims)
	ctx = context.WithValue(ctx, common.LogKey, newCertLogger())
	ctx = context.WithValue(ctx, common.ServiceContainerKey, sc)
	ctx = context.WithValue(ctx, common.OutputFormatterKey, newCertFmtr())

	cmd, _ := newCertCmd(createCmd.RunE, nil)
	cmd.Flags().Bool("auto-renew", false, "")
	cmd.Flags().Int("renewal-days", 30, "")
	setFlags(cmd, map[string]any{"name": "failcert",
		"key-id":        uuid.New().String(),
		"validity-days": 365,
		"tags":          "",
		"ca-cert-id":    ""})
	cmd.SetContext(ctx)
	err := cmd.Execute()
	assert.ErrorContains(t, err, "failed to create certificate")
	certSvc.AssertExpectations(t)
}

func TestCertCreateCmd_NoFormatter(t *testing.T) {
	tc := testutils.NewTestContext(t)
	certSvc := &certCmdCertService{}
	keyID := uuid.New()
	result := &certServices.CreateCertificateResult{CertID: uuid.New(), Name: "k", CreatedAt: time.Now()}
	certSvc.On("CreateSelfSignedCertificate", mock.Anything, mock.Anything).Return(result, nil)

	sc := &certsTestContainer{
		MockServiceContainer: tc.MockContainer,
		certSvc:              certSvc,
	}
	// Build context WITHOUT formatter.
	claims := &model.Claims{UserID: tc.TestUserID, Roles: []string{model.RoleAdmin}}
	ctx := context.WithValue(context.Background(), common.ClaimsKey, claims)
	ctx = context.WithValue(ctx, common.LogKey, newCertLogger())
	ctx = context.WithValue(ctx, common.ServiceContainerKey, sc)

	cmd, _ := newCertCmd(createCmd.RunE, nil)
	cmd.Flags().Bool("auto-renew", false, "")
	cmd.Flags().Int("renewal-days", 30, "")
	setFlags(cmd, map[string]any{"name": "k",
		"key-id":        keyID.String(),
		"validity-days": 365,
		"tags":          "",
		"ca-cert-id":    ""})
	cmd.SetContext(ctx)
	err := cmd.Execute()
	assert.ErrorContains(t, err, "output formatter not available")
	certSvc.AssertExpectations(t)
}

func TestCertCreateCmd_CertificateManagerRoleAllowed(t *testing.T) {
	tc := testutils.NewTestContext(t)
	certSvc := &certCmdCertService{}
	keyID := uuid.New()
	result := &certServices.CreateCertificateResult{CertID: uuid.New(), Name: "cert", CreatedAt: time.Now()}
	certSvc.On("CreateSelfSignedCertificate", mock.Anything, mock.Anything).Return(result, nil)

	sc := &certsTestContainer{
		MockServiceContainer: tc.MockContainer,
		certSvc:              certSvc,
	}
	claims := &model.Claims{UserID: tc.TestUserID, Username: "user", Roles: []string{model.RoleCertificateManager}}
	ctx := context.WithValue(context.Background(), common.ClaimsKey, claims)
	ctx = context.WithValue(ctx, common.LogKey, newCertLogger())
	ctx = context.WithValue(ctx, common.ServiceContainerKey, sc)
	ctx = context.WithValue(ctx, common.OutputFormatterKey, newCertFmtr())

	cmd, _ := newCertCmd(createCmd.RunE, nil)
	cmd.Flags().Bool("auto-renew", false, "")
	cmd.Flags().Int("renewal-days", 30, "")
	setFlags(cmd, map[string]any{"name": "cert",
		"key-id":        keyID.String(),
		"validity-days": 365,
		"tags":          "",
		"ca-cert-id":    ""})
	cmd.SetContext(ctx)
	err := cmd.Execute()
	assert.NoError(t, err)
	certSvc.AssertExpectations(t)
}

func TestCertCreateCmd_MultiRoleCaller_PrivilegedRoleNotFirst_Allowed(t *testing.T) {
	tc := testutils.NewTestContext(t)
	certSvc := &certCmdCertService{}
	keyID := uuid.New()
	result := &certServices.CreateCertificateResult{CertID: uuid.New(), Name: "cert", CreatedAt: time.Now()}
	certSvc.On("CreateSelfSignedCertificate", mock.Anything, mock.Anything).Return(result, nil)

	sc := &certsTestContainer{
		MockServiceContainer: tc.MockContainer,
		certSvc:              certSvc,
	}
	// The privileged role (certificate_manager) is second in Roles, not
	// first, to prove common.HasAnyRole is used at this call site rather
	// than only checking claims.Roles[0].
	claims := &model.Claims{UserID: tc.TestUserID, Username: "user", Roles: []string{model.RoleUser, model.RoleCertificateManager}}
	ctx := context.WithValue(context.Background(), common.ClaimsKey, claims)
	ctx = context.WithValue(ctx, common.LogKey, newCertLogger())
	ctx = context.WithValue(ctx, common.ServiceContainerKey, sc)
	ctx = context.WithValue(ctx, common.OutputFormatterKey, newCertFmtr())

	cmd, _ := newCertCmd(createCmd.RunE, nil)
	cmd.Flags().Bool("auto-renew", false, "")
	cmd.Flags().Int("renewal-days", 30, "")
	setFlags(cmd, map[string]any{"name": "cert",
		"key-id":        keyID.String(),
		"validity-days": 365,
		"tags":          "",
		"ca-cert-id":    ""})
	cmd.SetContext(ctx)
	err := cmd.Execute()
	assert.NoError(t, err)
	certSvc.AssertExpectations(t)
}

func TestCertCreateCmd_Denied(t *testing.T) {
	tc := testutils.NewTestContext(t)
	certSvc := &certCmdCertService{}
	keyID := uuid.New()

	denyRoles := &testutils.MockRoleAssignmentService{}
	denyRoles.On("HasDataAction", mock.Anything, mock.Anything, mock.Anything, mock.Anything).
		Return(false, nil).Maybe()
	tc.MockContainer.RoleAssignmentService = denyRoles

	sc := &certsTestContainer{
		MockServiceContainer: tc.MockContainer,
		certSvc:              certSvc,
	}
	claims := &model.Claims{UserID: tc.TestUserID, Username: "admin", Roles: []string{model.RoleAdmin}}
	ctx := context.WithValue(context.Background(), common.ClaimsKey, claims)
	ctx = context.WithValue(ctx, common.LogKey, newCertLogger())
	ctx = context.WithValue(ctx, common.ServiceContainerKey, sc)
	ctx = context.WithValue(ctx, common.OutputFormatterKey, newCertFmtr())

	cmd, _ := newCertCmd(createCmd.RunE, nil)
	cmd.Flags().Bool("auto-renew", false, "")
	cmd.Flags().Int("renewal-days", 30, "")
	setFlags(cmd, map[string]any{"name": "mycert",
		"key-id":        keyID.String(),
		"validity-days": 365,
		"tags":          "",
		"ca-cert-id":    ""})
	cmd.SetContext(ctx)
	err := cmd.Execute()
	assert.ErrorContains(t, err, "failed to create certificate")
	certSvc.AssertNotCalled(t, "CreateSelfSignedCertificate", mock.Anything, mock.Anything)
	certSvc.AssertNotCalled(t, "CreateCASignedCertificate", mock.Anything, mock.Anything)
}

func TestCertCreateCmd_Authorized(t *testing.T) {
	tc := testutils.NewTestContext(t)
	certSvc := &certCmdCertService{}
	keyID := uuid.New()
	result := &certServices.CreateCertificateResult{CertID: uuid.New(), Name: "mycert", CreatedAt: time.Now()}
	certSvc.On("CreateSelfSignedCertificate", mock.Anything, mock.MatchedBy(func(r certServices.CreateCertificateRequest) bool {
		return r.Name == "mycert" && r.KeyID == keyID && r.VaultID == tc.TestVaultID
	})).Return(result, nil)

	roles := &testutils.MockRoleAssignmentService{}
	roles.On("HasDataAction", mock.Anything, tc.TestUserID, tc.TestVaultID, model.ActionCertificatesCreate).
		Return(true, nil).Once()
	roles.On("HasDataAction", mock.Anything, tc.TestUserID, tc.TestVaultID, model.ActionKeysSign).
		Return(true, nil).Once()
	policies := &testutils.MockAccessPolicyService{}
	policies.On("CheckAccess", mock.Anything, tc.TestUserID, model.PolicyResourceCertificates, model.OpCreate, tc.TestVaultID).
		Return(authzServices.AccessAllowed, nil).Once()
	policies.On("CheckAccess", mock.Anything, tc.TestUserID, model.PolicyResourceKeys, model.OpSign, tc.TestVaultID).
		Return(authzServices.AccessAllowed, nil).Once()
	tc.MockContainer.RoleAssignmentService = roles
	tc.MockContainer.AccessPolicyService = policies

	sc := &certsTestContainer{
		MockServiceContainer: tc.MockContainer,
		certSvc:              certSvc,
	}
	claims := &model.Claims{UserID: tc.TestUserID, Username: "admin", Roles: []string{model.RoleAdmin}}
	ctx := context.WithValue(context.Background(), common.ClaimsKey, claims)
	ctx = context.WithValue(ctx, common.LogKey, newCertLogger())
	ctx = context.WithValue(ctx, common.ServiceContainerKey, sc)
	ctx = context.WithValue(ctx, common.OutputFormatterKey, newCertFmtr())

	cmd, _ := newCertCmd(createCmd.RunE, nil)
	cmd.Flags().Bool("auto-renew", false, "")
	cmd.Flags().Int("renewal-days", 30, "")
	setFlags(cmd, map[string]any{"name": "mycert",
		"key-id":        keyID.String(),
		"validity-days": 365,
		"tags":          "",
		"ca-cert-id":    ""})
	cmd.SetContext(ctx)
	err := cmd.Execute()
	assert.NoError(t, err)
	certSvc.AssertExpectations(t)
	roles.AssertExpectations(t)
	policies.AssertExpectations(t)
}

// ========== deleteCmd tests ==========

func TestCertDeleteCmd_NoClaims(t *testing.T) {
	ctx := context.Background()
	cmd, _ := newCertCmd(deleteCmd.RunE, []string{uuid.New().String()})
	cmd.Args = cobra.ExactArgs(1)
	cmd.SetContext(ctx)
	err := cmd.Execute()
	assert.ErrorContains(t, err, "unauthorized")
}

func TestCertDeleteCmd_ForbiddenRole(t *testing.T) {
	sc := &certsTestContainer{MockServiceContainer: &testutils.MockServiceContainer{}}
	ctx := buildCertRoleCtx(sc, model.RoleUser)
	cmd, _ := newCertCmd(deleteCmd.RunE, []string{uuid.New().String()})
	cmd.Args = cobra.ExactArgs(1)
	cmd.SetContext(ctx)
	err := cmd.Execute()
	assert.ErrorContains(t, err, "forbidden")
}

func TestCertDeleteCmd_InvalidUUID(t *testing.T) {
	claims := &model.Claims{UserID: uuid.New(), Roles: []string{model.RoleAdmin}}
	ctx := context.WithValue(context.Background(), common.ClaimsKey, claims)
	ctx = context.WithValue(ctx, common.LogKey, newCertLogger())
	cmd, _ := newCertCmd(deleteCmd.RunE, []string{"not-a-uuid"})
	cmd.Args = cobra.ExactArgs(1)
	cmd.SetContext(ctx)
	err := cmd.Execute()
	assert.ErrorContains(t, err, "invalid certificate ID")
}

func TestCertDeleteCmd_NoServiceContainer(t *testing.T) {
	claims := &model.Claims{UserID: uuid.New(), Roles: []string{model.RoleAdmin}}
	ctx := context.WithValue(context.Background(), common.ClaimsKey, claims)
	ctx = context.WithValue(ctx, common.LogKey, newCertLogger())
	// No service container.
	cmd, _ := newCertCmd(deleteCmd.RunE, []string{uuid.New().String()})
	cmd.Args = cobra.ExactArgs(1)
	cmd.SetContext(ctx)
	err := cmd.Execute()
	assert.ErrorContains(t, err, "service container not available")
}

func TestCertDeleteCmd_Success(t *testing.T) {
	tc := testutils.NewTestContext(t)
	certSvc := &certCmdCertService{}
	certID := uuid.New()
	certSvc.On("DeleteCertificate", mock.Anything, certID, model.NewVaultScope(tc.TestVaultID, tc.TestUserID)).Return(nil)

	sc := &certsTestContainer{
		MockServiceContainer: tc.MockContainer,
		certSvc:              certSvc,
	}
	claims := &model.Claims{UserID: tc.TestUserID, Roles: []string{model.RoleAdmin}}
	ctx := context.WithValue(context.Background(), common.ClaimsKey, claims)
	ctx = context.WithValue(ctx, common.LogKey, newCertLogger())
	ctx = context.WithValue(ctx, common.ServiceContainerKey, sc)

	cmd, _ := newCertCmd(deleteCmd.RunE, []string{certID.String()})
	cmd.Args = cobra.ExactArgs(1)
	cmd.SetContext(ctx)
	err := cmd.Execute()
	assert.NoError(t, err)
	certSvc.AssertExpectations(t)
}

func TestCertDeleteCmd_ServiceError(t *testing.T) {
	tc := testutils.NewTestContext(t)
	certSvc := &certCmdCertService{}
	certID := uuid.New()
	certSvc.On("DeleteCertificate", mock.Anything, certID, model.NewVaultScope(tc.TestVaultID, tc.TestUserID)).Return(fmt.Errorf("delete failed"))

	sc := &certsTestContainer{
		MockServiceContainer: tc.MockContainer,
		certSvc:              certSvc,
	}
	claims := &model.Claims{UserID: tc.TestUserID, Roles: []string{model.RoleAdmin}}
	ctx := context.WithValue(context.Background(), common.ClaimsKey, claims)
	ctx = context.WithValue(ctx, common.LogKey, newCertLogger())
	ctx = context.WithValue(ctx, common.ServiceContainerKey, sc)

	cmd, _ := newCertCmd(deleteCmd.RunE, []string{certID.String()})
	cmd.Args = cobra.ExactArgs(1)
	cmd.SetContext(ctx)
	err := cmd.Execute()
	assert.ErrorContains(t, err, "failed to delete certificate")
	certSvc.AssertExpectations(t)
}

func TestCertDeleteCmd_Denied(t *testing.T) {
	tc := testutils.NewTestContext(t)
	certSvc := &certCmdCertService{}
	certID := uuid.New()

	denyRoles := &testutils.MockRoleAssignmentService{}
	denyRoles.On("HasDataAction", mock.Anything, mock.Anything, mock.Anything, mock.Anything).
		Return(false, nil).Maybe()
	tc.MockContainer.RoleAssignmentService = denyRoles

	sc := &certsTestContainer{
		MockServiceContainer: tc.MockContainer,
		certSvc:              certSvc,
	}
	claims := &model.Claims{UserID: tc.TestUserID, Roles: []string{model.RoleAdmin}}
	ctx := context.WithValue(context.Background(), common.ClaimsKey, claims)
	ctx = context.WithValue(ctx, common.LogKey, newCertLogger())
	ctx = context.WithValue(ctx, common.ServiceContainerKey, sc)

	cmd, _ := newCertCmd(deleteCmd.RunE, []string{certID.String()})
	cmd.Args = cobra.ExactArgs(1)
	cmd.SetContext(ctx)
	err := cmd.Execute()
	assert.ErrorContains(t, err, "failed to delete certificate")
	certSvc.AssertNotCalled(t, "DeleteCertificate", mock.Anything, mock.Anything, mock.Anything)
}

func TestCertDeleteCmd_Authorized(t *testing.T) {
	tc := testutils.NewTestContext(t)
	certSvc := &certCmdCertService{}
	certID := uuid.New()
	certSvc.On("DeleteCertificate", mock.Anything, certID, model.NewVaultScope(tc.TestVaultID, tc.TestUserID)).Return(nil)

	roles := &testutils.MockRoleAssignmentService{}
	roles.On("HasDataAction", mock.Anything, tc.TestUserID, tc.TestVaultID, model.ActionCertificatesDelete).
		Return(true, nil).Once()
	policies := &testutils.MockAccessPolicyService{}
	policies.On("CheckAccess", mock.Anything, tc.TestUserID, model.PolicyResourceCertificates, model.OpDelete, tc.TestVaultID).
		Return(authzServices.AccessAllowed, nil).Once()
	tc.MockContainer.RoleAssignmentService = roles
	tc.MockContainer.AccessPolicyService = policies

	sc := &certsTestContainer{
		MockServiceContainer: tc.MockContainer,
		certSvc:              certSvc,
	}
	claims := &model.Claims{UserID: tc.TestUserID, Roles: []string{model.RoleAdmin}}
	ctx := context.WithValue(context.Background(), common.ClaimsKey, claims)
	ctx = context.WithValue(ctx, common.LogKey, newCertLogger())
	ctx = context.WithValue(ctx, common.ServiceContainerKey, sc)

	cmd, _ := newCertCmd(deleteCmd.RunE, []string{certID.String()})
	cmd.Args = cobra.ExactArgs(1)
	cmd.SetContext(ctx)
	err := cmd.Execute()
	assert.NoError(t, err)
	certSvc.AssertExpectations(t)
	roles.AssertExpectations(t)
	policies.AssertExpectations(t)
}

// ========== getCmd tests ==========

func TestCertGetCmd_NoClaims(t *testing.T) {
	ctx := context.Background()
	cmd, _ := newCertCmd(getCmd.RunE, []string{uuid.New().String()})
	cmd.Args = cobra.ExactArgs(1)
	cmd.SetContext(ctx)
	err := cmd.Execute()
	assert.ErrorContains(t, err, "unauthorized")
}

func TestCertGetCmd_InvalidUUID(t *testing.T) {
	claims := &model.Claims{UserID: uuid.New(), Roles: []string{model.RoleAdmin}}
	ctx := context.WithValue(context.Background(), common.ClaimsKey, claims)
	ctx = context.WithValue(ctx, common.LogKey, newCertLogger())
	cmd, _ := newCertCmd(getCmd.RunE, []string{"bad-uuid"})
	cmd.Args = cobra.ExactArgs(1)
	cmd.SetContext(ctx)
	err := cmd.Execute()
	assert.ErrorContains(t, err, "invalid certificate ID")
}

func TestCertGetCmd_NoServiceContainer(t *testing.T) {
	claims := &model.Claims{UserID: uuid.New(), Roles: []string{model.RoleAdmin}}
	ctx := context.WithValue(context.Background(), common.ClaimsKey, claims)
	ctx = context.WithValue(ctx, common.LogKey, newCertLogger())
	// No service container.
	cmd, _ := newCertCmd(getCmd.RunE, []string{uuid.New().String()})
	cmd.Args = cobra.ExactArgs(1)
	cmd.SetContext(ctx)
	err := cmd.Execute()
	assert.ErrorContains(t, err, "service container not available")
}

func TestCertGetCmd_Success(t *testing.T) {
	tc := testutils.NewTestContext(t)
	certSvc := &certCmdCertService{}
	certID := uuid.New()
	expiresAt := time.Now().Add(365 * 24 * time.Hour)
	cert := &model.Certificate{
		ID: certID, UserID: tc.TestUserID, Name: "mycert",
		Tags: []string{"ssl"}, CreatedAt: time.Now(), ExpiresAt: &expiresAt,
		AutoRenew: true, Enabled: true,
	}
	certSvc.On("GetCertificate", mock.Anything, certID, model.NewVaultScope(tc.TestVaultID, tc.TestUserID)).Return(cert, nil)

	sc := &certsTestContainer{
		MockServiceContainer: tc.MockContainer,
		certSvc:              certSvc,
	}
	claims := &model.Claims{UserID: tc.TestUserID, Roles: []string{model.RoleAdmin}}
	ctx := context.WithValue(context.Background(), common.ClaimsKey, claims)
	ctx = context.WithValue(ctx, common.LogKey, newCertLogger())
	ctx = context.WithValue(ctx, common.ServiceContainerKey, sc)
	ctx = context.WithValue(ctx, common.OutputFormatterKey, newCertFmtr())

	cmd, buf := newCertCmd(getCmd.RunE, []string{certID.String()})
	cmd.Args = cobra.ExactArgs(1)
	cmd.SetContext(ctx)
	err := cmd.Execute()
	assert.NoError(t, err)
	assert.NotEmpty(t, buf.String())
	certSvc.AssertExpectations(t)
}

func TestCertGetCmd_ServiceError(t *testing.T) {
	tc := testutils.NewTestContext(t)
	certSvc := &certCmdCertService{}
	certID := uuid.New()
	certSvc.On("GetCertificate", mock.Anything, certID, model.NewVaultScope(tc.TestVaultID, tc.TestUserID)).Return(nil, fmt.Errorf("not found"))

	sc := &certsTestContainer{
		MockServiceContainer: tc.MockContainer,
		certSvc:              certSvc,
	}
	claims := &model.Claims{UserID: tc.TestUserID, Roles: []string{model.RoleAdmin}}
	ctx := context.WithValue(context.Background(), common.ClaimsKey, claims)
	ctx = context.WithValue(ctx, common.LogKey, newCertLogger())
	ctx = context.WithValue(ctx, common.ServiceContainerKey, sc)
	ctx = context.WithValue(ctx, common.OutputFormatterKey, newCertFmtr())

	cmd, _ := newCertCmd(getCmd.RunE, []string{certID.String()})
	cmd.Args = cobra.ExactArgs(1)
	cmd.SetContext(ctx)
	err := cmd.Execute()
	assert.ErrorContains(t, err, "failed to get certificate")
	certSvc.AssertExpectations(t)
}

func TestCertGetCmd_NoFormatter(t *testing.T) {
	tc := testutils.NewTestContext(t)
	certSvc := &certCmdCertService{}
	certID := uuid.New()
	cert := &model.Certificate{
		ID: certID, UserID: tc.TestUserID, Name: "k",
		CreatedAt: time.Now(), Enabled: true,
	}
	certSvc.On("GetCertificate", mock.Anything, certID, model.NewVaultScope(tc.TestVaultID, tc.TestUserID)).Return(cert, nil)

	sc := &certsTestContainer{
		MockServiceContainer: tc.MockContainer,
		certSvc:              certSvc,
	}
	claims := &model.Claims{UserID: tc.TestUserID, Roles: []string{model.RoleAdmin}}
	ctx := context.WithValue(context.Background(), common.ClaimsKey, claims)
	ctx = context.WithValue(ctx, common.LogKey, newCertLogger())
	ctx = context.WithValue(ctx, common.ServiceContainerKey, sc)
	// No formatter.

	cmd, _ := newCertCmd(getCmd.RunE, []string{certID.String()})
	cmd.Args = cobra.ExactArgs(1)
	cmd.SetContext(ctx)
	err := cmd.Execute()
	assert.ErrorContains(t, err, "output formatter not available")
	certSvc.AssertExpectations(t)
}

func TestCertGetCmd_Denied(t *testing.T) {
	tc := testutils.NewTestContext(t)
	certSvc := &certCmdCertService{}
	certID := uuid.New()

	denyRoles := &testutils.MockRoleAssignmentService{}
	denyRoles.On("HasDataAction", mock.Anything, mock.Anything, mock.Anything, mock.Anything).
		Return(false, nil).Maybe()
	tc.MockContainer.RoleAssignmentService = denyRoles

	sc := &certsTestContainer{
		MockServiceContainer: tc.MockContainer,
		certSvc:              certSvc,
	}
	claims := &model.Claims{UserID: tc.TestUserID, Roles: []string{model.RoleAdmin}}
	ctx := context.WithValue(context.Background(), common.ClaimsKey, claims)
	ctx = context.WithValue(ctx, common.LogKey, newCertLogger())
	ctx = context.WithValue(ctx, common.ServiceContainerKey, sc)
	ctx = context.WithValue(ctx, common.OutputFormatterKey, newCertFmtr())

	cmd, _ := newCertCmd(getCmd.RunE, []string{certID.String()})
	cmd.Args = cobra.ExactArgs(1)
	cmd.SetContext(ctx)
	err := cmd.Execute()
	assert.ErrorContains(t, err, "failed to get certificate")
	certSvc.AssertNotCalled(t, "GetCertificate", mock.Anything, mock.Anything, mock.Anything)
}

func TestCertGetCmd_Authorized(t *testing.T) {
	tc := testutils.NewTestContext(t)
	certSvc := &certCmdCertService{}
	certID := uuid.New()
	cert := &model.Certificate{
		ID: certID, UserID: tc.TestUserID, Name: "mycert", CreatedAt: time.Now(), Enabled: true,
	}
	certSvc.On("GetCertificate", mock.Anything, certID, model.NewVaultScope(tc.TestVaultID, tc.TestUserID)).Return(cert, nil)

	roles := &testutils.MockRoleAssignmentService{}
	roles.On("HasDataAction", mock.Anything, tc.TestUserID, tc.TestVaultID, model.ActionCertificatesRead).
		Return(true, nil).Once()
	policies := &testutils.MockAccessPolicyService{}
	policies.On("CheckAccess", mock.Anything, tc.TestUserID, model.PolicyResourceCertificates, model.OpGet, tc.TestVaultID).
		Return(authzServices.AccessAllowed, nil).Once()
	tc.MockContainer.RoleAssignmentService = roles
	tc.MockContainer.AccessPolicyService = policies

	sc := &certsTestContainer{
		MockServiceContainer: tc.MockContainer,
		certSvc:              certSvc,
	}
	claims := &model.Claims{UserID: tc.TestUserID, Roles: []string{model.RoleAdmin}}
	ctx := context.WithValue(context.Background(), common.ClaimsKey, claims)
	ctx = context.WithValue(ctx, common.LogKey, newCertLogger())
	ctx = context.WithValue(ctx, common.ServiceContainerKey, sc)
	ctx = context.WithValue(ctx, common.OutputFormatterKey, newCertFmtr())

	cmd, _ := newCertCmd(getCmd.RunE, []string{certID.String()})
	cmd.Args = cobra.ExactArgs(1)
	cmd.SetContext(ctx)
	err := cmd.Execute()
	assert.NoError(t, err)
	certSvc.AssertExpectations(t)
	roles.AssertExpectations(t)
	policies.AssertExpectations(t)
}

// ========== listCmd tests ==========

func TestCertListCmd_NoClaims(t *testing.T) {
	ctx := context.Background()
	cmd, _ := newCertCmd(listCmd.RunE, nil)
	cmd.SetContext(ctx)
	err := cmd.Execute()
	assert.ErrorContains(t, err, "unauthorized")
}

func TestCertListCmd_NoServiceContainer(t *testing.T) {
	claims := &model.Claims{UserID: uuid.New(), Roles: []string{model.RoleAdmin}}
	ctx := context.WithValue(context.Background(), common.ClaimsKey, claims)
	ctx = context.WithValue(ctx, common.LogKey, newCertLogger())
	// No service container.
	cmd, _ := newCertCmd(listCmd.RunE, nil)
	cmd.SetContext(ctx)
	err := cmd.Execute()
	assert.ErrorContains(t, err, "service container not available")
}

func TestCertListCmd_SuccessTwoCerts(t *testing.T) {
	tc := testutils.NewTestContext(t)
	certSvc := &certCmdCertService{}
	certs := []model.Certificate{
		{ID: uuid.New(), UserID: tc.TestUserID, Name: "cert1", CreatedAt: time.Now(), Enabled: true},
		{ID: uuid.New(), UserID: tc.TestUserID, Name: "cert2", CreatedAt: time.Now(), Enabled: true},
	}
	certSvc.On("ListCertificates", mock.Anything, model.NewVaultScope(tc.TestVaultID, tc.TestUserID), repositories.CertificateFilter{}).Return(certs, nil)

	sc := &certsTestContainer{
		MockServiceContainer: tc.MockContainer,
		certSvc:              certSvc,
	}
	claims := &model.Claims{UserID: tc.TestUserID, Roles: []string{model.RoleAdmin}}
	ctx := context.WithValue(context.Background(), common.ClaimsKey, claims)
	ctx = context.WithValue(ctx, common.LogKey, newCertLogger())
	ctx = context.WithValue(ctx, common.ServiceContainerKey, sc)
	ctx = context.WithValue(ctx, common.OutputFormatterKey, newCertFmtr())

	cmd, buf := newCertCmd(listCmd.RunE, nil)
	cmd.SetContext(ctx)
	err := cmd.Execute()
	assert.NoError(t, err)
	assert.NotEmpty(t, buf.String())
	certSvc.AssertExpectations(t)
}

func TestCertListCmd_EmptyList(t *testing.T) {
	tc := testutils.NewTestContext(t)
	certSvc := &certCmdCertService{}
	certSvc.On("ListCertificates", mock.Anything, model.NewVaultScope(tc.TestVaultID, tc.TestUserID), repositories.CertificateFilter{}).Return([]model.Certificate{}, nil)

	sc := &certsTestContainer{
		MockServiceContainer: tc.MockContainer,
		certSvc:              certSvc,
	}
	claims := &model.Claims{UserID: tc.TestUserID, Roles: []string{model.RoleUser}}
	ctx := context.WithValue(context.Background(), common.ClaimsKey, claims)
	ctx = context.WithValue(ctx, common.LogKey, newCertLogger())
	ctx = context.WithValue(ctx, common.ServiceContainerKey, sc)
	ctx = context.WithValue(ctx, common.OutputFormatterKey, newCertFmtr())

	cmd, _ := newCertCmd(listCmd.RunE, nil)
	cmd.SetContext(ctx)
	err := cmd.Execute()
	assert.NoError(t, err)
	certSvc.AssertExpectations(t)
}

func TestCertListCmd_ServiceError(t *testing.T) {
	tc := testutils.NewTestContext(t)
	certSvc := &certCmdCertService{}
	certSvc.On("ListCertificates", mock.Anything, model.NewVaultScope(tc.TestVaultID, tc.TestUserID), repositories.CertificateFilter{}).Return(nil, fmt.Errorf("db error"))

	sc := &certsTestContainer{
		MockServiceContainer: tc.MockContainer,
		certSvc:              certSvc,
	}
	claims := &model.Claims{UserID: tc.TestUserID, Roles: []string{model.RoleSecretsManager}}
	ctx := context.WithValue(context.Background(), common.ClaimsKey, claims)
	ctx = context.WithValue(ctx, common.LogKey, newCertLogger())
	ctx = context.WithValue(ctx, common.ServiceContainerKey, sc)
	ctx = context.WithValue(ctx, common.OutputFormatterKey, newCertFmtr())

	cmd, _ := newCertCmd(listCmd.RunE, nil)
	cmd.SetContext(ctx)
	err := cmd.Execute()
	assert.ErrorContains(t, err, "failed to list certificates")
	certSvc.AssertExpectations(t)
}

func TestCertListCmd_NoFormatter(t *testing.T) {
	tc := testutils.NewTestContext(t)
	certSvc := &certCmdCertService{}
	certSvc.On("ListCertificates", mock.Anything, model.NewVaultScope(tc.TestVaultID, tc.TestUserID), repositories.CertificateFilter{}).Return([]model.Certificate{}, nil)

	sc := &certsTestContainer{
		MockServiceContainer: tc.MockContainer,
		certSvc:              certSvc,
	}
	claims := &model.Claims{UserID: tc.TestUserID, Roles: []string{model.RoleUser}}
	ctx := context.WithValue(context.Background(), common.ClaimsKey, claims)
	ctx = context.WithValue(ctx, common.LogKey, newCertLogger())
	ctx = context.WithValue(ctx, common.ServiceContainerKey, sc)
	// No formatter.

	cmd, _ := newCertCmd(listCmd.RunE, nil)
	cmd.SetContext(ctx)
	err := cmd.Execute()
	assert.ErrorContains(t, err, "output formatter not available")
	certSvc.AssertExpectations(t)
}

func TestCertListCmd_Denied(t *testing.T) {
	tc := testutils.NewTestContext(t)
	certSvc := &certCmdCertService{}

	denyRoles := &testutils.MockRoleAssignmentService{}
	denyRoles.On("HasDataAction", mock.Anything, mock.Anything, mock.Anything, mock.Anything).
		Return(false, nil).Maybe()
	tc.MockContainer.RoleAssignmentService = denyRoles

	sc := &certsTestContainer{
		MockServiceContainer: tc.MockContainer,
		certSvc:              certSvc,
	}
	claims := &model.Claims{UserID: tc.TestUserID, Roles: []string{model.RoleAdmin}}
	ctx := context.WithValue(context.Background(), common.ClaimsKey, claims)
	ctx = context.WithValue(ctx, common.LogKey, newCertLogger())
	ctx = context.WithValue(ctx, common.ServiceContainerKey, sc)
	ctx = context.WithValue(ctx, common.OutputFormatterKey, newCertFmtr())

	cmd, _ := newCertCmd(listCmd.RunE, nil)
	cmd.SetContext(ctx)
	err := cmd.Execute()
	assert.ErrorContains(t, err, "failed to list certificates")
	certSvc.AssertNotCalled(t, "ListCertificates", mock.Anything, mock.Anything, mock.Anything)
}

func TestCertListCmd_Authorized(t *testing.T) {
	tc := testutils.NewTestContext(t)
	certSvc := &certCmdCertService{}
	certs := []model.Certificate{
		{ID: uuid.New(), UserID: tc.TestUserID, Name: "cert1", CreatedAt: time.Now(), Enabled: true},
	}
	certSvc.On("ListCertificates", mock.Anything, model.NewVaultScope(tc.TestVaultID, tc.TestUserID), repositories.CertificateFilter{}).Return(certs, nil)

	roles := &testutils.MockRoleAssignmentService{}
	roles.On("HasDataAction", mock.Anything, tc.TestUserID, tc.TestVaultID, model.ActionCertificatesRead).
		Return(true, nil).Once()
	policies := &testutils.MockAccessPolicyService{}
	policies.On("CheckAccess", mock.Anything, tc.TestUserID, model.PolicyResourceCertificates, model.OpGet, tc.TestVaultID).
		Return(authzServices.AccessAllowed, nil).Once()
	tc.MockContainer.RoleAssignmentService = roles
	tc.MockContainer.AccessPolicyService = policies

	sc := &certsTestContainer{
		MockServiceContainer: tc.MockContainer,
		certSvc:              certSvc,
	}
	claims := &model.Claims{UserID: tc.TestUserID, Roles: []string{model.RoleAdmin}}
	ctx := context.WithValue(context.Background(), common.ClaimsKey, claims)
	ctx = context.WithValue(ctx, common.LogKey, newCertLogger())
	ctx = context.WithValue(ctx, common.ServiceContainerKey, sc)
	ctx = context.WithValue(ctx, common.OutputFormatterKey, newCertFmtr())

	cmd, _ := newCertCmd(listCmd.RunE, nil)
	cmd.SetContext(ctx)
	err := cmd.Execute()
	assert.NoError(t, err)
	certSvc.AssertExpectations(t)
	roles.AssertExpectations(t)
	policies.AssertExpectations(t)
}

// ========== renewCmd tests ==========

func TestCertRenewCmd_NoClaims(t *testing.T) {
	ctx := context.Background()
	cmd, _ := newCertCmd(renewCmd.RunE, []string{uuid.New().String()})
	cmd.Args = cobra.ExactArgs(1)
	cmd.SetContext(ctx)
	err := cmd.Execute()
	assert.ErrorContains(t, err, "unauthorized")
}

func TestCertRenewCmd_ForbiddenRole(t *testing.T) {
	sc := &certsTestContainer{MockServiceContainer: &testutils.MockServiceContainer{}}
	ctx := buildCertRoleCtx(sc, model.RoleUser)
	cmd, _ := newCertCmd(renewCmd.RunE, []string{uuid.New().String()})
	cmd.Args = cobra.ExactArgs(1)
	cmd.SetContext(ctx)
	err := cmd.Execute()
	assert.ErrorContains(t, err, "forbidden")
}

func TestCertRenewCmd_InvalidUUID(t *testing.T) {
	claims := &model.Claims{UserID: uuid.New(), Roles: []string{model.RoleAdmin}}
	ctx := context.WithValue(context.Background(), common.ClaimsKey, claims)
	ctx = context.WithValue(ctx, common.LogKey, newCertLogger())
	cmd, _ := newCertCmd(renewCmd.RunE, []string{"not-a-uuid"})
	cmd.Args = cobra.ExactArgs(1)
	setFlags(cmd, map[string]any{"validity-days": 365})
	cmd.SetContext(ctx)
	err := cmd.Execute()
	assert.ErrorContains(t, err, "invalid certificate ID")
}

func TestCertRenewCmd_InvalidValidityDays(t *testing.T) {
	claims := &model.Claims{UserID: uuid.New(), Roles: []string{model.RoleAdmin}}
	ctx := context.WithValue(context.Background(), common.ClaimsKey, claims)
	ctx = context.WithValue(ctx, common.LogKey, newCertLogger())
	cmd, _ := newCertCmd(renewCmd.RunE, []string{uuid.New().String()})
	cmd.Args = cobra.ExactArgs(1)
	setFlags(cmd, map[string]any{"validity-days": 0})
	cmd.SetContext(ctx)
	err := cmd.Execute()
	assert.ErrorContains(t, err, "validity-days must be greater than 0")
}

func TestCertRenewCmd_NoServiceContainer(t *testing.T) {
	claims := &model.Claims{UserID: uuid.New(), Roles: []string{model.RoleAdmin}}
	ctx := context.WithValue(context.Background(), common.ClaimsKey, claims)
	ctx = context.WithValue(ctx, common.LogKey, newCertLogger())
	// No service container.
	cmd, _ := newCertCmd(renewCmd.RunE, []string{uuid.New().String()})
	cmd.Args = cobra.ExactArgs(1)
	setFlags(cmd, map[string]any{"validity-days": 365})
	cmd.SetContext(ctx)
	err := cmd.Execute()
	assert.ErrorContains(t, err, "service container not available")
}

func TestCertRenewCmd_Success(t *testing.T) {
	tc := testutils.NewTestContext(t)
	certSvc := &certCmdCertService{}
	certID := uuid.New()
	result := &certServices.CreateCertificateResult{
		CertID:    uuid.New(),
		Name:      "renewed",
		CreatedAt: time.Now(),
	}
	certSvc.On("RenewCertificate", mock.Anything, certID, model.NewVaultScope(tc.TestVaultID, tc.TestUserID), 365).Return(result, nil)

	sc := &certsTestContainer{
		MockServiceContainer: tc.MockContainer,
		certSvc:              certSvc,
	}
	claims := &model.Claims{UserID: tc.TestUserID, Roles: []string{model.RoleAdmin}}
	ctx := context.WithValue(context.Background(), common.ClaimsKey, claims)
	ctx = context.WithValue(ctx, common.LogKey, newCertLogger())
	ctx = context.WithValue(ctx, common.ServiceContainerKey, sc)

	cmd, _ := newCertCmd(renewCmd.RunE, []string{certID.String()})
	cmd.Args = cobra.ExactArgs(1)
	setFlags(cmd, map[string]any{"validity-days": 365})
	cmd.SetContext(ctx)
	err := cmd.Execute()
	assert.NoError(t, err)
	certSvc.AssertExpectations(t)
}

func TestCertRenewCmd_ServiceError(t *testing.T) {
	tc := testutils.NewTestContext(t)
	certSvc := &certCmdCertService{}
	certID := uuid.New()
	certSvc.On("RenewCertificate", mock.Anything, certID, model.NewVaultScope(tc.TestVaultID, tc.TestUserID), 180).Return(nil, fmt.Errorf("renew failed"))

	sc := &certsTestContainer{
		MockServiceContainer: tc.MockContainer,
		certSvc:              certSvc,
	}
	claims := &model.Claims{UserID: tc.TestUserID, Roles: []string{model.RoleAdmin}}
	ctx := context.WithValue(context.Background(), common.ClaimsKey, claims)
	ctx = context.WithValue(ctx, common.LogKey, newCertLogger())
	ctx = context.WithValue(ctx, common.ServiceContainerKey, sc)

	cmd, _ := newCertCmd(renewCmd.RunE, []string{certID.String()})
	cmd.Args = cobra.ExactArgs(1)
	setFlags(cmd, map[string]any{"validity-days": 180})
	cmd.SetContext(ctx)
	err := cmd.Execute()
	assert.ErrorContains(t, err, "failed to renew certificate")
	certSvc.AssertExpectations(t)
}

func TestCertRenewCmd_Denied(t *testing.T) {
	tc := testutils.NewTestContext(t)
	certSvc := &certCmdCertService{}
	certID := uuid.New()

	denyRoles := &testutils.MockRoleAssignmentService{}
	denyRoles.On("HasDataAction", mock.Anything, mock.Anything, mock.Anything, mock.Anything).
		Return(false, nil).Maybe()
	tc.MockContainer.RoleAssignmentService = denyRoles

	sc := &certsTestContainer{
		MockServiceContainer: tc.MockContainer,
		certSvc:              certSvc,
	}
	claims := &model.Claims{UserID: tc.TestUserID, Roles: []string{model.RoleAdmin}}
	ctx := context.WithValue(context.Background(), common.ClaimsKey, claims)
	ctx = context.WithValue(ctx, common.LogKey, newCertLogger())
	ctx = context.WithValue(ctx, common.ServiceContainerKey, sc)

	cmd, _ := newCertCmd(renewCmd.RunE, []string{certID.String()})
	cmd.Args = cobra.ExactArgs(1)
	setFlags(cmd, map[string]any{"validity-days": 365})
	cmd.SetContext(ctx)
	err := cmd.Execute()
	assert.ErrorContains(t, err, "failed to renew certificate")
	certSvc.AssertNotCalled(t, "RenewCertificate", mock.Anything, mock.Anything, mock.Anything, mock.Anything)
}

func TestCertRenewCmd_Authorized(t *testing.T) {
	tc := testutils.NewTestContext(t)
	certSvc := &certCmdCertService{}
	certID := uuid.New()
	result := &certServices.CreateCertificateResult{
		CertID:    uuid.New(),
		Name:      "renewed",
		CreatedAt: time.Now(),
	}
	certSvc.On("RenewCertificate", mock.Anything, certID, model.NewVaultScope(tc.TestVaultID, tc.TestUserID), 365).Return(result, nil)

	roles := &testutils.MockRoleAssignmentService{}
	roles.On("HasDataAction", mock.Anything, tc.TestUserID, tc.TestVaultID, model.ActionCertificatesCreate).
		Return(true, nil).Once()
	roles.On("HasDataAction", mock.Anything, tc.TestUserID, tc.TestVaultID, model.ActionKeysSign).
		Return(true, nil).Once()
	policies := &testutils.MockAccessPolicyService{}
	policies.On("CheckAccess", mock.Anything, tc.TestUserID, model.PolicyResourceCertificates, model.OpRenew, tc.TestVaultID).
		Return(authzServices.AccessAllowed, nil).Once()
	policies.On("CheckAccess", mock.Anything, tc.TestUserID, model.PolicyResourceKeys, model.OpSign, tc.TestVaultID).
		Return(authzServices.AccessAllowed, nil).Once()
	tc.MockContainer.RoleAssignmentService = roles
	tc.MockContainer.AccessPolicyService = policies

	sc := &certsTestContainer{
		MockServiceContainer: tc.MockContainer,
		certSvc:              certSvc,
	}
	claims := &model.Claims{UserID: tc.TestUserID, Roles: []string{model.RoleAdmin}}
	ctx := context.WithValue(context.Background(), common.ClaimsKey, claims)
	ctx = context.WithValue(ctx, common.LogKey, newCertLogger())
	ctx = context.WithValue(ctx, common.ServiceContainerKey, sc)

	cmd, _ := newCertCmd(renewCmd.RunE, []string{certID.String()})
	cmd.Args = cobra.ExactArgs(1)
	setFlags(cmd, map[string]any{"validity-days": 365})
	cmd.SetContext(ctx)
	err := cmd.Execute()
	assert.NoError(t, err)
	certSvc.AssertExpectations(t)
	roles.AssertExpectations(t)
	policies.AssertExpectations(t)
}

// ========== updateCmd tests ==========

func TestCertUpdateCmd_NoClaims(t *testing.T) {
	ctx := context.Background()
	cmd, _ := newCertCmd(updateCmd.RunE, []string{uuid.New().String()})
	cmd.Args = cobra.ExactArgs(1)
	cmd.Flags().String("name", "", "")
	cmd.Flags().String("tags", "", "")
	cmd.Flags().Bool("auto-renew", false, "")
	cmd.Flags().Int("renewal-days", 0, "")
	cmd.SetContext(ctx)
	err := cmd.Execute()
	assert.ErrorContains(t, err, "unauthorized")
}

func TestCertUpdateCmd_ForbiddenRole(t *testing.T) {
	sc := &certsTestContainer{MockServiceContainer: &testutils.MockServiceContainer{}}
	ctx := buildCertRoleCtx(sc, model.RoleUser)
	cmd, _ := newCertCmd(updateCmd.RunE, []string{uuid.New().String()})
	cmd.Args = cobra.ExactArgs(1)
	cmd.Flags().String("name", "", "")
	cmd.Flags().String("tags", "", "")
	cmd.Flags().Bool("auto-renew", false, "")
	cmd.Flags().Int("renewal-days", 0, "")
	setFlags(cmd, map[string]any{"name": "n", "tags": ""})
	cmd.SetContext(ctx)
	err := cmd.Execute()
	assert.ErrorContains(t, err, "forbidden")
}

func TestCertUpdateCmd_InvalidUUID(t *testing.T) {
	claims := &model.Claims{UserID: uuid.New(), Roles: []string{model.RoleAdmin}}
	ctx := context.WithValue(context.Background(), common.ClaimsKey, claims)
	ctx = context.WithValue(ctx, common.LogKey, newCertLogger())
	cmd, _ := newCertCmd(updateCmd.RunE, []string{"not-a-uuid"})
	cmd.Args = cobra.ExactArgs(1)
	cmd.Flags().String("name", "", "")
	cmd.Flags().String("tags", "", "")
	cmd.Flags().Bool("auto-renew", false, "")
	cmd.Flags().Int("renewal-days", 0, "")
	setFlags(cmd, map[string]any{"name": "", "tags": ""})
	cmd.SetContext(ctx)
	err := cmd.Execute()
	assert.ErrorContains(t, err, "invalid certificate ID")
}

func TestCertUpdateCmd_NoServiceContainer(t *testing.T) {
	claims := &model.Claims{UserID: uuid.New(), Roles: []string{model.RoleAdmin}}
	ctx := context.WithValue(context.Background(), common.ClaimsKey, claims)
	ctx = context.WithValue(ctx, common.LogKey, newCertLogger())
	// No service container.
	cmd, _ := newCertCmd(updateCmd.RunE, []string{uuid.New().String()})
	cmd.Args = cobra.ExactArgs(1)
	cmd.Flags().String("name", "", "")
	cmd.Flags().String("tags", "", "")
	cmd.Flags().Bool("auto-renew", false, "")
	cmd.Flags().Int("renewal-days", 0, "")
	setFlags(cmd, map[string]any{"name": "n", "tags": ""})
	cmd.SetContext(ctx)
	err := cmd.Execute()
	assert.ErrorContains(t, err, "service container not available")
}

func TestCertUpdateCmd_SuccessWithNameUpdate(t *testing.T) {
	tc := testutils.NewTestContext(t)
	certSvc := &certCmdCertService{}
	certID := uuid.New()
	certSvc.On("UpdateCertificate", mock.Anything, mock.MatchedBy(func(r certServices.UpdateCertificateRequest) bool {
		return r.CertID == certID && r.Scope == model.NewVaultScope(tc.TestVaultID, tc.TestUserID) && r.Name != nil && *r.Name == "newname"
	})).Return(nil)

	sc := &certsTestContainer{
		MockServiceContainer: tc.MockContainer,
		certSvc:              certSvc,
	}
	claims := &model.Claims{UserID: tc.TestUserID, Roles: []string{model.RoleAdmin}}
	ctx := context.WithValue(context.Background(), common.ClaimsKey, claims)
	ctx = context.WithValue(ctx, common.LogKey, newCertLogger())
	ctx = context.WithValue(ctx, common.ServiceContainerKey, sc)

	// Use a fresh command with args so viper picks up the name correctly.
	cmd := &cobra.Command{Use: "test", Args: cobra.ExactArgs(1), RunE: updateCmd.RunE}
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	cmd.Flags().String("name", "", "")
	cmd.Flags().String("tags", "", "")
	cmd.Flags().Bool("auto-renew", false, "")
	cmd.Flags().Int("renewal-days", 0, "")
	cmd.SetArgs([]string{certID.String()})
	setFlags(cmd, map[string]any{"name": "newname", "tags": ""})
	cmd.SetContext(ctx)

	err := cmd.Execute()
	assert.NoError(t, err)
	certSvc.AssertExpectations(t)
}

func TestCertUpdateCmd_SuccessWithAutoRenewFlagChanged(t *testing.T) {
	tc := testutils.NewTestContext(t)
	certSvc := &certCmdCertService{}
	certID := uuid.New()
	certSvc.On("UpdateCertificate", mock.Anything, mock.MatchedBy(func(r certServices.UpdateCertificateRequest) bool {
		return r.CertID == certID && r.AutoRenew != nil && *r.AutoRenew == true
	})).Return(nil)

	sc := &certsTestContainer{
		MockServiceContainer: tc.MockContainer,
		certSvc:              certSvc,
	}
	claims := &model.Claims{UserID: tc.TestUserID, Roles: []string{model.RoleAdmin}}
	ctx := context.WithValue(context.Background(), common.ClaimsKey, claims)
	ctx = context.WithValue(ctx, common.LogKey, newCertLogger())
	ctx = context.WithValue(ctx, common.ServiceContainerKey, sc)

	// Register flags and set args so that --auto-renew is marked Changed.
	cmd := &cobra.Command{Use: "test", Args: cobra.ExactArgs(1), RunE: updateCmd.RunE}
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	cmd.Flags().String("name", "", "")
	cmd.Flags().String("tags", "", "")
	cmd.Flags().Bool("auto-renew", false, "")
	cmd.Flags().Int("renewal-days", 0, "")
	cmd.SetArgs([]string{certID.String(), "--auto-renew=true"})
	setFlags(cmd, map[string]any{"name": "", "tags": ""})
	cmd.SetContext(ctx)

	err := cmd.Execute()
	assert.NoError(t, err)
	certSvc.AssertExpectations(t)
}

func TestCertUpdateCmd_SuccessWithRenewalDaysFlagChanged(t *testing.T) {
	tc := testutils.NewTestContext(t)
	certSvc := &certCmdCertService{}
	certID := uuid.New()
	certSvc.On("UpdateCertificate", mock.Anything, mock.MatchedBy(func(r certServices.UpdateCertificateRequest) bool {
		return r.CertID == certID && r.RenewalDays != nil && *r.RenewalDays == 60
	})).Return(nil)

	sc := &certsTestContainer{
		MockServiceContainer: tc.MockContainer,
		certSvc:              certSvc,
	}
	claims := &model.Claims{UserID: tc.TestUserID, Roles: []string{model.RoleAdmin}}
	ctx := context.WithValue(context.Background(), common.ClaimsKey, claims)
	ctx = context.WithValue(ctx, common.LogKey, newCertLogger())
	ctx = context.WithValue(ctx, common.ServiceContainerKey, sc)

	cmd := &cobra.Command{Use: "test", Args: cobra.ExactArgs(1), RunE: updateCmd.RunE}
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	cmd.Flags().String("name", "", "")
	cmd.Flags().String("tags", "", "")
	cmd.Flags().Bool("auto-renew", false, "")
	cmd.Flags().Int("renewal-days", 0, "")
	cmd.SetArgs([]string{certID.String(), "--renewal-days=60"})
	setFlags(cmd, map[string]any{"name": "", "tags": ""})
	cmd.SetContext(ctx)

	err := cmd.Execute()
	assert.NoError(t, err)
	certSvc.AssertExpectations(t)
}

func TestCertUpdateCmd_ServiceError(t *testing.T) {
	tc := testutils.NewTestContext(t)
	certSvc := &certCmdCertService{}
	certID := uuid.New()
	certSvc.On("UpdateCertificate", mock.Anything, mock.Anything).Return(fmt.Errorf("update failed"))

	sc := &certsTestContainer{
		MockServiceContainer: tc.MockContainer,
		certSvc:              certSvc,
	}
	claims := &model.Claims{UserID: tc.TestUserID, Roles: []string{model.RoleAdmin}}
	ctx := context.WithValue(context.Background(), common.ClaimsKey, claims)
	ctx = context.WithValue(ctx, common.LogKey, newCertLogger())
	ctx = context.WithValue(ctx, common.ServiceContainerKey, sc)

	cmd := &cobra.Command{Use: "test", Args: cobra.ExactArgs(1), RunE: updateCmd.RunE}
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	cmd.Flags().String("name", "", "")
	cmd.Flags().String("tags", "", "")
	cmd.Flags().Bool("auto-renew", false, "")
	cmd.Flags().Int("renewal-days", 0, "")
	cmd.SetArgs([]string{certID.String()})
	setFlags(cmd, map[string]any{"name": "n", "tags": ""})
	cmd.SetContext(ctx)

	err := cmd.Execute()
	assert.ErrorContains(t, err, "failed to update certificate")
	certSvc.AssertExpectations(t)
}

func TestCertUpdateCmd_Denied(t *testing.T) {
	tc := testutils.NewTestContext(t)
	certSvc := &certCmdCertService{}
	certID := uuid.New()

	denyRoles := &testutils.MockRoleAssignmentService{}
	denyRoles.On("HasDataAction", mock.Anything, mock.Anything, mock.Anything, mock.Anything).
		Return(false, nil).Maybe()
	tc.MockContainer.RoleAssignmentService = denyRoles

	sc := &certsTestContainer{
		MockServiceContainer: tc.MockContainer,
		certSvc:              certSvc,
	}
	claims := &model.Claims{UserID: tc.TestUserID, Roles: []string{model.RoleAdmin}}
	ctx := context.WithValue(context.Background(), common.ClaimsKey, claims)
	ctx = context.WithValue(ctx, common.LogKey, newCertLogger())
	ctx = context.WithValue(ctx, common.ServiceContainerKey, sc)

	cmd := &cobra.Command{Use: "test", Args: cobra.ExactArgs(1), RunE: updateCmd.RunE}
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	cmd.Flags().String("name", "", "")
	cmd.Flags().String("tags", "", "")
	cmd.Flags().Bool("auto-renew", false, "")
	cmd.Flags().Int("renewal-days", 0, "")
	cmd.SetArgs([]string{certID.String()})
	setFlags(cmd, map[string]any{"name": "n", "tags": ""})
	cmd.SetContext(ctx)

	err := cmd.Execute()
	assert.ErrorContains(t, err, "failed to update certificate")
	certSvc.AssertNotCalled(t, "UpdateCertificate", mock.Anything, mock.Anything)
}

func TestCertUpdateCmd_Authorized(t *testing.T) {
	tc := testutils.NewTestContext(t)
	certSvc := &certCmdCertService{}
	certID := uuid.New()
	certSvc.On("UpdateCertificate", mock.Anything, mock.MatchedBy(func(r certServices.UpdateCertificateRequest) bool {
		return r.CertID == certID && r.Scope == model.NewVaultScope(tc.TestVaultID, tc.TestUserID) && r.Name != nil && *r.Name == "newname"
	})).Return(nil)

	roles := &testutils.MockRoleAssignmentService{}
	roles.On("HasDataAction", mock.Anything, tc.TestUserID, tc.TestVaultID, model.ActionCertificatesUpdate).
		Return(true, nil).Once()
	policies := &testutils.MockAccessPolicyService{}
	policies.On("CheckAccess", mock.Anything, tc.TestUserID, model.PolicyResourceCertificates, model.OpSet, tc.TestVaultID).
		Return(authzServices.AccessAllowed, nil).Once()
	tc.MockContainer.RoleAssignmentService = roles
	tc.MockContainer.AccessPolicyService = policies

	sc := &certsTestContainer{
		MockServiceContainer: tc.MockContainer,
		certSvc:              certSvc,
	}
	claims := &model.Claims{UserID: tc.TestUserID, Roles: []string{model.RoleAdmin}}
	ctx := context.WithValue(context.Background(), common.ClaimsKey, claims)
	ctx = context.WithValue(ctx, common.LogKey, newCertLogger())
	ctx = context.WithValue(ctx, common.ServiceContainerKey, sc)

	cmd := &cobra.Command{Use: "test", Args: cobra.ExactArgs(1), RunE: updateCmd.RunE}
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	cmd.Flags().String("name", "", "")
	cmd.Flags().String("tags", "", "")
	cmd.Flags().Bool("auto-renew", false, "")
	cmd.Flags().Int("renewal-days", 0, "")
	cmd.SetArgs([]string{certID.String()})
	setFlags(cmd, map[string]any{"name": "newname", "tags": ""})
	cmd.SetContext(ctx)

	err := cmd.Execute()
	assert.NoError(t, err)
	certSvc.AssertExpectations(t)
	roles.AssertExpectations(t)
	policies.AssertExpectations(t)
}

// ========== optional-time cell tests ==========
//
// This package's own formatOptionalTime is gone; the shared
// vaultcli.CellOptTime replaces it (cmd/secrets had an identical copy). These
// tests stay here because they cover what the Expires column renders.

func TestFormatOptionalTime_Nil(t *testing.T) {
	result := vaultcli.CellOptTime(nil)
	assert.Equal(t, "", result)
}

func TestFormatOptionalTime_NonNil(t *testing.T) {
	ts := time.Date(2026, 1, 15, 10, 30, 0, 0, time.UTC)
	result := vaultcli.CellOptTime(&ts)
	assert.Equal(t, ts.Format(time.RFC3339), result)
	assert.Contains(t, result, "2026-01-15")
}

// --is-ca is the opt-in that replaces the old blanket CA:TRUE (B44). It has to
// reach the service, or the flag is decoration.
func TestCertCreateCmd_IsCAFlagOptsIn(t *testing.T) {
	tc := testutils.NewTestContext(t)
	certSvc := &certCmdCertService{}
	keyID := uuid.New()
	result := &certServices.CreateCertificateResult{
		CertID:    uuid.New(),
		Name:      "issuing-ca",
		CreatedAt: time.Now(),
	}
	certSvc.On("CreateSelfSignedCertificate", mock.Anything, mock.MatchedBy(func(r certServices.CreateCertificateRequest) bool {
		return r.Name == "issuing-ca" && r.KeyID == keyID && r.IsCA
	})).Return(result, nil)

	sc := &certsTestContainer{
		MockServiceContainer: tc.MockContainer,
		certSvc:              certSvc,
	}
	claims := &model.Claims{UserID: tc.TestUserID, Username: "admin", Roles: []string{model.RoleAdmin}}
	ctx := context.WithValue(context.Background(), common.ClaimsKey, claims)
	ctx = context.WithValue(ctx, common.LogKey, newCertLogger())
	ctx = context.WithValue(ctx, common.ServiceContainerKey, sc)
	ctx = context.WithValue(ctx, common.OutputFormatterKey, newCertFmtr())

	cmd, buf := newCertCmd(createCmd.RunE, nil)
	cmd.Flags().Bool("auto-renew", false, "")
	cmd.Flags().Int("renewal-days", 30, "")
	cmd.Flags().Bool("is-ca", false, "")
	assert.NoError(t, cmd.Flags().Set("is-ca", "true"))
	setFlags(cmd, map[string]any{"name": "issuing-ca",
		"key-id":        keyID.String(),
		"validity-days": 3650,
		"tags":          "",
		"ca-cert-id":    ""})
	cmd.SetContext(ctx)
	err := cmd.Execute()
	assert.NoError(t, err)
	assert.NotEmpty(t, buf.String())
	certSvc.AssertExpectations(t)
}

// Without the flag the request must ask for a leaf. This is the default that
// B44 was missing.
func TestCertCreateCmd_WithoutIsCAFlagRequestsALeaf(t *testing.T) {
	tc := testutils.NewTestContext(t)
	certSvc := &certCmdCertService{}
	keyID := uuid.New()
	result := &certServices.CreateCertificateResult{
		CertID:    uuid.New(),
		Name:      "tls-server",
		CreatedAt: time.Now(),
	}
	certSvc.On("CreateSelfSignedCertificate", mock.Anything, mock.MatchedBy(func(r certServices.CreateCertificateRequest) bool {
		return r.Name == "tls-server" && !r.IsCA
	})).Return(result, nil)

	sc := &certsTestContainer{
		MockServiceContainer: tc.MockContainer,
		certSvc:              certSvc,
	}
	claims := &model.Claims{UserID: tc.TestUserID, Username: "admin", Roles: []string{model.RoleAdmin}}
	ctx := context.WithValue(context.Background(), common.ClaimsKey, claims)
	ctx = context.WithValue(ctx, common.LogKey, newCertLogger())
	ctx = context.WithValue(ctx, common.ServiceContainerKey, sc)
	ctx = context.WithValue(ctx, common.OutputFormatterKey, newCertFmtr())

	cmd, buf := newCertCmd(createCmd.RunE, nil)
	cmd.Flags().Bool("auto-renew", false, "")
	cmd.Flags().Int("renewal-days", 30, "")
	cmd.Flags().Bool("is-ca", false, "")
	setFlags(cmd, map[string]any{"name": "tls-server",
		"key-id":        keyID.String(),
		"validity-days": 365,
		"tags":          "",
		"ca-cert-id":    ""})
	cmd.SetContext(ctx)
	err := cmd.Execute()
	assert.NoError(t, err)
	assert.NotEmpty(t, buf.String())
	certSvc.AssertExpectations(t)
}

func (m *certCmdCertService) ListCertificateVersions(ctx context.Context, certID uuid.UUID, scope model.Scope) ([]model.CertificateVersion, error) {
	args := m.Called(ctx, certID, scope)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]model.CertificateVersion), args.Error(1)
}

func (m *certCmdCertService) GetCertificateVersion(ctx context.Context, certID uuid.UUID, version int, scope model.Scope) (*model.CertificateVersion, error) {
	args := m.Called(ctx, certID, version, scope)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*model.CertificateVersion), args.Error(1)
}

func (m *certCmdCertService) UpdateCertificateVersion(ctx context.Context, req certServices.UpdateCertificateVersionRequest) (*model.CertificateVersion, error) {
	args := m.Called(ctx, req)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*model.CertificateVersion), args.Error(1)
}

func (m *certCmdCertService) ExportCertificate(ctx context.Context, scope model.Scope, id uuid.UUID, req certServices.ExportCertificateRequest) (*certServices.ExportCertificateResult, error) {
	args := m.Called(ctx, scope, id, req)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*certServices.ExportCertificateResult), args.Error(1)
}
