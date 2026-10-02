package users

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"rocketvault/cmd/testutils"
	"rocketvault/common"
	"rocketvault/internal/container"
	"rocketvault/internal/logging"
	authServices "rocketvault/internal/services/auth"
	userService "rocketvault/internal/services/users"
	internaltestutils "rocketvault/internal/testutils"
	"rocketvault/model"
)

// newUpdateTestContextWithRole creates a test context where the caller has the given role and user ID.
func newUpdateTestContextWithRole(t *testing.T, callerID uuid.UUID, role string) *testutils.TestContext {
	tc := testutils.NewTestContext(t)
	claims := &model.Claims{
		UserID:   callerID,
		Username: "testuser",
		Roles:    []string{role},
	}
	ctx := context.WithValue(tc.Ctx, common.ClaimsKey, claims)
	ctx = context.WithValue(ctx, common.UserIDKey, callerID)
	tc.Ctx = ctx
	return tc
}

func TestUpdateUserRoleEnforcement(t *testing.T) {
	ownID := uuid.New()

	tests := []struct {
		name        string
		callerRole  string
		targetID    string
		newRole     string
		expectError string
	}{
		{
			name:        "non-admin cannot change own role",
			callerRole:  model.RoleUser,
			targetID:    ownID.String(),
			newRole:     model.RoleAdmin,
			expectError: "forbidden",
		},
		{
			name:        "non-admin cannot change other user role",
			callerRole:  model.RoleSecretsManager,
			targetID:    uuid.New().String(),
			newRole:     model.RoleUser,
			expectError: "forbidden",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			viper.Reset()
			tc := newUpdateTestContextWithRole(t, ownID, tt.callerRole)

			cmd := &cobra.Command{
				Use:  "update",
				Args: cobra.ExactArgs(1),
				RunE: updateCmd.RunE,
			}
			cmd.Flags().String("new-username", "", "")
			cmd.Flags().String("new-password", "", "")
			cmd.Flags().StringArray("new-role", []string{}, "")
			cmd.SetContext(tc.Ctx)
			cmd.SetArgs([]string{tt.targetID, "--new-role=" + tt.newRole})

			err := cmd.Execute()

			assert.Error(t, err)
			assert.Contains(t, err.Error(), tt.expectError)
			tc.MockUserService.AssertNotCalled(t, "UpdateUser")
		})
	}
}

func TestUpdateUserCommand_MultipleRoles_AdminAllowed(t *testing.T) {
	viper.Reset()
	targetID := uuid.New()
	tc := newUpdateTestContextWithRole(t, uuid.New(), model.RoleAdmin)

	cmd := &cobra.Command{
		Use:  "update",
		Args: cobra.ExactArgs(1),
		RunE: updateCmd.RunE,
	}
	cmd.Flags().String("new-username", "", "")
	cmd.Flags().String("new-password", "", "")
	cmd.Flags().StringArray("new-role", []string{}, "")
	cmd.SetContext(tc.Ctx)
	cmd.SetArgs([]string{targetID.String(), "--new-role=secrets_manager", "--new-role=crypto_manager"})

	tc.MockUserService.On("UpdateUser", mock.Anything, mock.MatchedBy(func(req userService.UpdateUserRequest) bool {
		return assert.ObjectsAreEqualValues([]string{"secrets_manager", "crypto_manager"}, req.Roles)
	})).Return(&userService.UpdateUserResult{}, nil)

	err := cmd.Execute()
	require.NoError(t, err)
	tc.MockUserService.AssertExpectations(t)
}

// cliRecordingRevoker records which users had their sessions revoked.
type cliRecordingRevoker struct {
	revoked []uuid.UUID
}

func (r *cliRecordingRevoker) RevokeAllUserSessions(_ context.Context, userID uuid.UUID, _ string) error {
	r.revoked = append(r.revoked, userID)
	return nil
}

// A user changing their own password on the CLI loses every session, including
// the cached one the command ran under, the same as over HTTP (B74).
func TestUpdateUserCommand_SelfPasswordChange_RevokesOwnSessions(t *testing.T) {
	viper.Reset()
	userID := uuid.New()

	repo := &internaltestutils.MockUserRepository{}
	repo.On("Read", mock.Anything, userID).Return(&model.User{
		ID: userID, Username: "alice", PasswordHash: "old", TOTPSecret: "SECRET", Roles: []string{model.RoleUser},
	}, nil)
	repo.On("Update", mock.Anything, mock.Anything).Return(nil)
	revoker := &cliRecordingRevoker{}
	realSvc := userService.NewUserService(userService.UserServiceConfig{
		UserRepository:  repo,
		PasswordService: authServices.NewPasswordService(),
		TOTPService:     authServices.NewTOTPService(),
		SessionRevoker:  revoker,
		Logger:          &logging.Logger{Logger: logrus.New()},
	})

	mc := &testutils.MockServiceContainer{}
	mc.On("GetUserService").Return(realSvc)
	mc.On("GetLogger").Return(&logging.Logger{Logger: logrus.New()})
	ctx := context.WithValue(context.Background(), common.ServiceContainerKey, container.ServiceContainerInterface(mc))
	ctx = context.WithValue(ctx, common.ClaimsKey, &model.Claims{UserID: userID, Username: "alice", Roles: []string{model.RoleUser}})

	cmd := &cobra.Command{
		Use:  "update",
		Args: cobra.ExactArgs(1),
		RunE: updateCmd.RunE,
	}
	cmd.Flags().String("new-username", "", "")
	cmd.Flags().String("new-password", "", "")
	cmd.Flags().StringArray("new-role", []string{}, "")
	cmd.SetContext(ctx)
	cmd.SetArgs([]string{userID.String(), "--new-password=newpass123"})

	require.NoError(t, cmd.Execute())
	assert.Equal(t, []uuid.UUID{userID}, revoker.revoked)
}
