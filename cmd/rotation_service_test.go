package cmd

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"rocketvault/cmd/testutils"
	"rocketvault/internal/pwgen"
	auditServices "rocketvault/internal/services/audit"
	secretServices "rocketvault/internal/services/secrets"
	"rocketvault/model"
)

// MockRotationSvc is a testify mock that satisfies RotationServiceInterface.
type MockRotationSvc struct{ mock.Mock }

var _ secretServices.RotationServiceInterface = (*MockRotationSvc)(nil)

func (m *MockRotationSvc) CreatePolicy(ctx context.Context, req secretServices.CreatePolicyRequest) (*model.RotationPolicy, error) {
	args := m.Called(ctx, req)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*model.RotationPolicy), args.Error(1)
}

func (m *MockRotationSvc) GetPolicy(ctx context.Context, id uuid.UUID, scope model.Scope) (*model.RotationPolicy, error) {
	args := m.Called(ctx, id, scope)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*model.RotationPolicy), args.Error(1)
}

func (m *MockRotationSvc) UpdatePolicy(ctx context.Context, req secretServices.UpdatePolicyRequest) (*model.RotationPolicy, error) {
	args := m.Called(ctx, req)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*model.RotationPolicy), args.Error(1)
}

func (m *MockRotationSvc) DeletePolicy(ctx context.Context, id uuid.UUID, scope model.Scope) error {
	args := m.Called(ctx, id, scope)
	return args.Error(0)
}

func (m *MockRotationSvc) ListPolicies(ctx context.Context, scope model.Scope) ([]model.RotationPolicy, error) {
	args := m.Called(ctx, scope)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]model.RotationPolicy), args.Error(1)
}

func (m *MockRotationSvc) AssignPolicyToSecret(ctx context.Context, req secretServices.AssignPolicyRequest) error {
	args := m.Called(ctx, req)
	return args.Error(0)
}

func (m *MockRotationSvc) RemovePolicyFromSecret(ctx context.Context, sID, pID uuid.UUID, scope model.Scope) error {
	args := m.Called(ctx, sID, pID, scope)
	return args.Error(0)
}

func (m *MockRotationSvc) GetSecretPolicies(ctx context.Context, secretID uuid.UUID, scope model.Scope) ([]model.RotationPolicy, error) {
	args := m.Called(ctx, secretID, scope)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]model.RotationPolicy), args.Error(1)
}

func (m *MockRotationSvc) PerformManualRotation(ctx context.Context, req secretServices.ManualRotationRequest) error {
	args := m.Called(ctx, req)
	return args.Error(0)
}

func (m *MockRotationSvc) GetRotationHistory(ctx context.Context, sID uuid.UUID, scope model.Scope) ([]model.RotationHistory, error) {
	args := m.Called(ctx, sID, scope)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]model.RotationHistory), args.Error(1)
}

func (m *MockRotationSvc) GetDueRotations(ctx context.Context, scope model.Scope) ([]model.SecretPolicy, error) {
	args := m.Called(ctx, scope)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]model.SecretPolicy), args.Error(1)
}

func (m *MockRotationSvc) CreateRotationReminder(ctx context.Context, req secretServices.CreateReminderRequest) error {
	return nil
}

func (m *MockRotationSvc) GetUpcomingReminders(ctx context.Context, scope model.Scope) ([]model.RotationReminder, error) {
	args := m.Called(ctx, scope)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]model.RotationReminder), args.Error(1)
}

func (m *MockRotationSvc) AcknowledgeReminder(ctx context.Context, reminderID, secretID uuid.UUID, scope model.Scope) error {
	return nil
}

func (m *MockRotationSvc) SetAuditService(auditServices.AuditServiceInterface) {}

func setupRotationTestContext(t *testing.T) (*testutils.TestContext, *MockRotationSvc) {
	tc := testutils.NewTestContext(t)
	mockRotSvc := &MockRotationSvc{}
	tc.MockContainer.On("GetRotationService").Return(mockRotSvc)
	return tc, mockRotSvc
}

func TestRotationCreateCommand_UsesService(t *testing.T) {
	tc, mockRotSvc := setupRotationTestContext(t)
	polID := uuid.New()

	mockRotSvc.On("CreatePolicy", mock.Anything, mock.MatchedBy(func(r secretServices.CreatePolicyRequest) bool {
		return r.Name == "test-policy" && r.IntervalDays == 30 &&
			r.Scope == model.NewVaultScope(tc.TestVaultID, tc.TestUserID)
	})).Return(&model.RotationPolicy{ID: polID, Name: "test-policy", IntervalDays: 30}, nil)

	policyName = "test-policy"
	policyInterval = 30
	policyReminder = 7
	policyAutoRotate = false
	policyDescription = ""

	var out bytes.Buffer
	cmd := &cobra.Command{Use: "create", RunE: rotationCreateCmd.RunE}
	cmd.SetContext(tc.Ctx)
	cmd.SetOut(&out)

	err := cmd.RunE(cmd, []string{})
	assert.NoError(t, err)
	assert.Contains(t, out.String(), "created successfully")
	mockRotSvc.AssertExpectations(t)
}

func TestRotationListCommand_UsesService(t *testing.T) {
	tc, mockRotSvc := setupRotationTestContext(t)

	mockRotSvc.On("ListPolicies", mock.Anything, model.NewVaultScope(tc.TestVaultID, tc.TestUserID)).
		Return([]model.RotationPolicy{
			{ID: uuid.New(), Name: "policy-1", IntervalDays: 30, AutoRotate: true, Enabled: true, CreatedAt: time.Now()},
		}, nil)

	var out bytes.Buffer
	cmd := &cobra.Command{Use: "list", RunE: rotationListCmd.RunE}
	cmd.SetContext(tc.Ctx)
	cmd.SetOut(&out)

	err := cmd.RunE(cmd, []string{})
	assert.NoError(t, err)
	assert.Contains(t, out.String(), "policy-1")
	mockRotSvc.AssertExpectations(t)
}

func TestRotationRotateCommand_UsesContextContainer(t *testing.T) {
	tc, mockRotSvc := setupRotationTestContext(t)
	sid := uuid.New()
	pid := uuid.New()

	mockRotSvc.On("PerformManualRotation", mock.Anything, mock.MatchedBy(func(r secretServices.ManualRotationRequest) bool {
		return r.SecretID == sid && r.PolicyID == pid &&
			r.Scope == model.NewVaultScope(tc.TestVaultID, tc.TestUserID) &&
			r.NewValue == "operator-supplied" && !r.Generate
	})).Return(nil)

	secretID = sid.String()
	policyID = pid.String()
	rotateValue = "operator-supplied"
	rotateGenerate = false
	t.Cleanup(func() { rotateValue = "" })

	cmd := &cobra.Command{Use: "rotate", RunE: rotationRotateCmd.RunE}
	cmd.SetContext(tc.Ctx)

	err := cmd.RunE(cmd, []string{})
	assert.NoError(t, err)
	mockRotSvc.AssertExpectations(t)
}

// TestRotationRotate_NeitherValueNorGenerate_IsAnError pins the CLI half of
// B35's "never invent a value" rule: the error must name both ways out.
func TestRotationRotate_NeitherValueNorGenerate_IsAnError(t *testing.T) {
	tc, _ := setupRotationTestContext(t)

	secretID = uuid.New().String()
	policyID = uuid.New().String()
	rotateValue = ""
	rotateGenerate = false

	cmd := &cobra.Command{Use: "rotate", RunE: rotationRotateCmd.RunE}
	cmd.SetContext(tc.Ctx)

	err := cmd.RunE(cmd, []string{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "--value")
	assert.Contains(t, err.Error(), "--generate")
}

// TestRotationRotate_BothValueAndGenerate_IsAnError keeps the two sources
// mutually exclusive at the CLI, not just in the service.
func TestRotationRotate_BothValueAndGenerate_IsAnError(t *testing.T) {
	tc, _ := setupRotationTestContext(t)

	secretID = uuid.New().String()
	policyID = uuid.New().String()
	rotateValue = "explicit"
	rotateGenerate = true
	t.Cleanup(func() { rotateValue = ""; rotateGenerate = false })

	cmd := &cobra.Command{Use: "rotate", RunE: rotationRotateCmd.RunE}
	cmd.SetContext(tc.Ctx)

	err := cmd.RunE(cmd, []string{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "--value")
	assert.Contains(t, err.Error(), "--generate")
}

// TestRotationRotate_GenerateFlagsReachTheService proves the character-set
// flags are not decorative.
func TestRotationRotate_GenerateFlagsReachTheService(t *testing.T) {
	tc, mockRotSvc := setupRotationTestContext(t)
	sid := uuid.New()
	pid := uuid.New()

	mockRotSvc.On("PerformManualRotation", mock.Anything, mock.MatchedBy(func(r secretServices.ManualRotationRequest) bool {
		return r.SecretID == sid && r.PolicyID == pid && r.NewValue == "" && r.Generate &&
			r.GenerateOpts == (pwgen.Options{Length: 32, Upper: true, Lower: true, Numbers: true, Special: false})
	})).Return(nil)

	secretID = sid.String()
	policyID = pid.String()
	rotateValue = ""
	rotateGenerate = true
	rotateLength = 32
	rotateUpper, rotateLower, rotateNumbers, rotateSpecial = true, true, true, false
	t.Cleanup(func() { rotateGenerate = false; rotateLength = 16; rotateSpecial = true })

	cmd := &cobra.Command{Use: "rotate", RunE: rotationRotateCmd.RunE}
	cmd.SetContext(tc.Ctx)

	err := cmd.RunE(cmd, []string{})
	assert.NoError(t, err)
	mockRotSvc.AssertExpectations(t)
}
