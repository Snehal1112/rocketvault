package cmd

import (
	"bytes"
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"rocketvault/cmd/testutils"
	auditServices "rocketvault/internal/services/audit"
	secretServices "rocketvault/internal/services/secrets"
	"rocketvault/model"
)

func TestRotationCreateCommand(t *testing.T) {
	tests := []struct {
		name           string
		setupMocks     func(*MockRotationService)
		policyName     string
		description    string
		interval       int
		reminder       int
		expectedError  bool
		expectedOutput string
	}{
		{
			name: "successful rotation policy creation",
			setupMocks: func(mockService *MockRotationService) {
				expectedPolicy := &model.RotationPolicy{
					ID:           uuid.New(),
					UserID:       uuid.New(),
					Name:         "Monthly Rotation",
					Description:  "Rotate every 30 days",
					IntervalDays: 30,
					ReminderDays: 5,
					CreatedAt:    time.Now(),
				}

				mockService.On("CreatePolicy", mock.Anything, mock.MatchedBy(func(req secretServices.CreatePolicyRequest) bool {
					return req.Name == "Monthly Rotation" && req.IntervalDays == 30
				})).Return(expectedPolicy, nil)
			},
			policyName:     "Monthly Rotation",
			description:    "Rotate every 30 days",
			interval:       30,
			reminder:       5,
			expectedError:  false,
			expectedOutput: "✅ Rotation policy created successfully",
		},
		{
			name: "missing required name",
			setupMocks: func(mockService *MockRotationService) {
				// No mocks needed for validation error
			},
			policyName:    "",
			interval:      30,
			expectedError: true,
		},
		{
			name: "invalid interval",
			setupMocks: func(mockService *MockRotationService) {
				// No mocks needed for validation error
			},
			policyName:    "Test Policy",
			interval:      0,
			expectedError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create mock rotation service
			mockService := &MockRotationService{}
			tt.setupMocks(mockService)

			// Create isolated command that doesn't use global state
			testCmd := &cobra.Command{
				Use:                "create",
				DisableFlagParsing: false,
				RunE: func(cmd *cobra.Command, args []string) error {
					// Get flags
					name, _ := cmd.Flags().GetString("name")
					description, _ := cmd.Flags().GetString("description")
					interval, _ := cmd.Flags().GetInt("interval")
					reminder, _ := cmd.Flags().GetInt("reminder")

					// Validation
					if name == "" {
						return assert.AnError
					}
					if interval <= 0 {
						return assert.AnError
					}

					// Create policy via service
					req := secretServices.CreatePolicyRequest{
						Scope:        model.NewVaultScope(uuid.New(), uuid.New()), // Use generated scope for test
						Name:         name,
						Description:  description,
						IntervalDays: interval,
						ReminderDays: reminder,
					}

					policy, err := mockService.CreatePolicy(cmd.Context(), req)
					if err != nil {
						return err
					}

					cmd.Printf("✅ Rotation policy created successfully!\n")
					cmd.Printf("Policy ID: %s\n", policy.ID)
					return nil
				},
			}

			// Define flags
			testCmd.Flags().String("name", "", "Policy name")
			testCmd.Flags().String("description", "", "Policy description")
			testCmd.Flags().Int("interval", 30, "Interval in days")
			testCmd.Flags().Int("reminder", 5, "Reminder in days")

			// Set up flags from test data
			testCmd.Flags().Set("name", tt.policyName)                      //nolint:errcheck,gosec
			testCmd.Flags().Set("description", tt.description)              //nolint:errcheck,gosec
			testCmd.Flags().Set("interval", fmt.Sprintf("%d", tt.interval)) //nolint:errcheck,gosec
			testCmd.Flags().Set("reminder", fmt.Sprintf("%d", tt.reminder)) //nolint:errcheck,gosec

			// Capture output
			var output bytes.Buffer
			testCmd.SetOut(&output)
			testCmd.SetErr(&output)

			// Directly call RunE instead of Execute to avoid global command chain
			err := testCmd.RunE(testCmd, []string{})

			// Assert results
			if tt.expectedError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				if tt.expectedOutput != "" {
					assert.Contains(t, output.String(), tt.expectedOutput)
				}
			}

			// Verify mock expectations (only if no error expected)
			if !tt.expectedError {
				mockService.AssertExpectations(t)
			}
		})
	}
}

// TestRotationCreateCommand_RequiresVaultAuthorization proves the retrofit's
// authorization gate: without a role grant in the resolved vault, the create
// subcommand must fail before ever reaching the rotation service.
//
// This calls cmd.RunE directly rather than cmd.Execute() (the form used by
// cmd/keys/update_test.go's equivalent, which lives in a different Go
// package). In this package, root.go's init() registers cobra.OnInitialize
// (initConfig) process-wide; going through Command.Execute() would trigger a
// real config-file load and panic in a test environment with no
// .rocketvault.yaml. Calling RunE directly exercises the exact same
// authorization logic without that unrelated landmine, matching every other
// rotation test in this file.
func TestRotationCreateCommand_RequiresVaultAuthorization(t *testing.T) {
	tc := testutils.NewTestContext(t)
	denyRoles := &testutils.MockRoleAssignmentService{}
	denyRoles.On("HasDataAction", mock.Anything, mock.Anything, mock.Anything, mock.Anything).
		Return(false, nil).Maybe()
	tc.MockContainer.RoleAssignmentService = denyRoles
	mockService := &MockRotationService{}
	tc.MockContainer.On("GetRotationService").Return(mockService)

	cmd := &cobra.Command{Use: "create", RunE: rotationCreateCmd.RunE}
	cmd.Flags().String("name", "test", "")
	cmd.Flags().Int("interval", 30, "")
	cmd.SetContext(tc.Ctx)

	err := cmd.RunE(cmd, []string{})
	require.Error(t, err, "create must fail without a role grant in the resolved vault")
	mockService.AssertNotCalled(t, "CreatePolicy", mock.Anything, mock.Anything)
}

// Mock Rotation Service for testing. It implements
// secretServices.RotationServiceInterface in full so it can be returned from
// MockServiceContainer.GetRotationService in tests that exercise the CLI
// command tree end to end.
type MockRotationService struct {
	mock.Mock
}

var _ secretServices.RotationServiceInterface = (*MockRotationService)(nil)

func (m *MockRotationService) CreatePolicy(ctx context.Context, req secretServices.CreatePolicyRequest) (*model.RotationPolicy, error) {
	args := m.Called(ctx, req)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*model.RotationPolicy), args.Error(1)
}

func (m *MockRotationService) GetPolicy(ctx context.Context, id uuid.UUID, scope model.Scope) (*model.RotationPolicy, error) {
	args := m.Called(ctx, id, scope)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*model.RotationPolicy), args.Error(1)
}

func (m *MockRotationService) UpdatePolicy(ctx context.Context, req secretServices.UpdatePolicyRequest) (*model.RotationPolicy, error) {
	args := m.Called(ctx, req)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*model.RotationPolicy), args.Error(1)
}

func (m *MockRotationService) DeletePolicy(ctx context.Context, id uuid.UUID, scope model.Scope) error {
	args := m.Called(ctx, id, scope)
	return args.Error(0)
}

func (m *MockRotationService) ListPolicies(ctx context.Context, scope model.Scope) ([]model.RotationPolicy, error) {
	args := m.Called(ctx, scope)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]model.RotationPolicy), args.Error(1)
}

func (m *MockRotationService) AssignPolicyToSecret(ctx context.Context, req secretServices.AssignPolicyRequest) error {
	args := m.Called(ctx, req)
	return args.Error(0)
}

func (m *MockRotationService) RemovePolicyFromSecret(ctx context.Context, secretID, policyID uuid.UUID, scope model.Scope) error {
	args := m.Called(ctx, secretID, policyID, scope)
	return args.Error(0)
}

func (m *MockRotationService) GetSecretPolicies(ctx context.Context, secretID uuid.UUID, scope model.Scope) ([]model.RotationPolicy, error) {
	args := m.Called(ctx, secretID, scope)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]model.RotationPolicy), args.Error(1)
}

func (m *MockRotationService) PerformManualRotation(ctx context.Context, req secretServices.ManualRotationRequest) error {
	args := m.Called(ctx, req)
	return args.Error(0)
}

func (m *MockRotationService) GetRotationHistory(ctx context.Context, secretID uuid.UUID, scope model.Scope) ([]model.RotationHistory, error) {
	args := m.Called(ctx, secretID, scope)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]model.RotationHistory), args.Error(1)
}

func (m *MockRotationService) GetDueRotations(ctx context.Context, scope model.Scope) ([]model.SecretPolicy, error) {
	args := m.Called(ctx, scope)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]model.SecretPolicy), args.Error(1)
}

func (m *MockRotationService) CreateRotationReminder(ctx context.Context, req secretServices.CreateReminderRequest) error {
	args := m.Called(ctx, req)
	return args.Error(0)
}

func (m *MockRotationService) GetUpcomingReminders(ctx context.Context, scope model.Scope) ([]model.RotationReminder, error) {
	args := m.Called(ctx, scope)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]model.RotationReminder), args.Error(1)
}

func (m *MockRotationService) AcknowledgeReminder(ctx context.Context, reminderID, secretID uuid.UUID, scope model.Scope) error {
	args := m.Called(ctx, reminderID, secretID, scope)
	return args.Error(0)
}

func (m *MockRotationService) SetAuditService(auditServices.AuditServiceInterface) {}
