package users

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"rocketvault/cmd/testutils"
	"rocketvault/common"
	"rocketvault/internal/formatter"
	"rocketvault/internal/logging"
	authServices "rocketvault/internal/services/auth"
	"rocketvault/model"
)

// TestMain runs the Init functions so their code paths are covered, then runs all tests.
func TestMain(m *testing.M) {
	parent := &cobra.Command{Use: "users"}
	InitUsersRegisterAdmin(parent)
	InitUsersCreate(parent)
	InitUsersDelete(parent)
	InitUsersGet(parent)
	InitUsersList(parent)
	InitUsersLogin(parent)
	InitUsersUpdate(parent)
	os.Exit(m.Run())
}

// newUsersTestCtx builds a test context that carries claims, a service container, a
// formatter and a logger — matching what the real middleware injects at runtime.
func newUsersTestCtx(sc interface{}) context.Context {
	userID := uuid.New()
	claims := &model.Claims{UserID: userID, Roles: []string{model.RoleAdmin}}
	ctx := context.Background()
	ctx = context.WithValue(ctx, common.ClaimsKey, claims)
	ctx = context.WithValue(ctx, common.LogKey, &logging.Logger{Logger: logrus.New()})
	ctx = context.WithValue(ctx, common.ServiceContainerKey, sc)
	fmtr, _ := formatter.New(formatter.FormatTable)
	ctx = context.WithValue(ctx, common.OutputFormatterKey, fmtr)
	return ctx
}

// newUsersTestCtxWithRole is like newUsersTestCtx but lets the caller choose the
// claims role and the callerID that appears inside the JWT claims.
func newUsersTestCtxWithRole(sc interface{}, callerID uuid.UUID, role string) context.Context {
	claims := &model.Claims{UserID: callerID, Roles: []string{role}}
	ctx := context.Background()
	ctx = context.WithValue(ctx, common.ClaimsKey, claims)
	ctx = context.WithValue(ctx, common.LogKey, &logging.Logger{Logger: logrus.New()})
	ctx = context.WithValue(ctx, common.ServiceContainerKey, sc)
	fmtr, _ := formatter.New(formatter.FormatTable)
	ctx = context.WithValue(ctx, common.OutputFormatterKey, fmtr)
	return ctx
}

// --------------------------------------------------------------------------
// deleteCmd tests
// --------------------------------------------------------------------------

func TestDeleteCmd_NoClaims(t *testing.T) {
	ctx := context.Background() // no ClaimsKey
	cmd := &cobra.Command{Use: "delete", Args: cobra.ExactArgs(1), RunE: deleteCmd.RunE}
	cmd.SetContext(ctx)
	cmd.SetArgs([]string{uuid.New().String()})
	err := cmd.Execute()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unauthorized")
}

func TestDeleteCmd_InvalidUUID(t *testing.T) {
	tc := testutils.NewTestContext(t)
	cmd := &cobra.Command{Use: "delete", Args: cobra.ExactArgs(1), RunE: deleteCmd.RunE}
	cmd.SetContext(tc.Ctx)
	cmd.SetArgs([]string{"not-a-uuid"})
	err := cmd.Execute()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid user ID")
}

func TestDeleteCmd_NonAdminDeleteOther(t *testing.T) {
	tc := testutils.NewTestContext(t)
	callerID := uuid.New()
	targetID := uuid.New() // different from caller
	ctx := newUsersTestCtxWithRole(tc.MockContainer, callerID, model.RoleUser)

	cmd := &cobra.Command{Use: "delete", Args: cobra.ExactArgs(1), RunE: deleteCmd.RunE}
	cmd.SetContext(ctx)
	cmd.SetArgs([]string{targetID.String()})
	err := cmd.Execute()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "forbidden")
}

func TestDeleteCmd_NonAdminDeleteSelf(t *testing.T) {
	tc := testutils.NewTestContext(t)
	callerID := uuid.New()
	ctx := newUsersTestCtxWithRole(tc.MockContainer, callerID, model.RoleUser)

	tc.MockUserService.On("DeleteUser", mock.Anything, callerID, callerID).Return(nil)

	cmd := &cobra.Command{Use: "delete", Args: cobra.ExactArgs(1), RunE: deleteCmd.RunE}
	cmd.SetContext(ctx)
	cmd.SetArgs([]string{callerID.String()})
	err := cmd.Execute()
	assert.NoError(t, err)
	tc.MockUserService.AssertExpectations(t)
}

func TestDeleteCmd_AdminDeleteAnyUser(t *testing.T) {
	tc := testutils.NewTestContext(t)
	targetID := uuid.New()
	adminID := uuid.New()
	ctx := newUsersTestCtxWithRole(tc.MockContainer, adminID, model.RoleAdmin)

	// The CLI names the caller as the actor of the delete.
	tc.MockUserService.On("DeleteUser", mock.Anything, targetID, adminID).Return(nil)

	cmd := &cobra.Command{Use: "delete", Args: cobra.ExactArgs(1), RunE: deleteCmd.RunE}
	cmd.SetContext(ctx)
	cmd.SetArgs([]string{targetID.String()})
	err := cmd.Execute()
	assert.NoError(t, err)
	tc.MockUserService.AssertExpectations(t)
}

func TestDeleteCmd_ServiceError(t *testing.T) {
	tc := testutils.NewTestContext(t)
	targetID := uuid.New()
	ctx := newUsersTestCtx(tc.MockContainer)

	tc.MockUserService.On("DeleteUser", mock.Anything, targetID, mock.Anything).Return(fmt.Errorf("db error"))

	cmd := &cobra.Command{Use: "delete", Args: cobra.ExactArgs(1), RunE: deleteCmd.RunE}
	cmd.SetContext(ctx)
	cmd.SetArgs([]string{targetID.String()})
	err := cmd.Execute()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to delete user")
	tc.MockUserService.AssertExpectations(t)
}

func TestDeleteCmd_NoServiceContainer(t *testing.T) {
	// Claims present but no service container in context.
	userID := uuid.New()
	claims := &model.Claims{UserID: userID, Roles: []string{model.RoleAdmin}}
	ctx := context.WithValue(context.Background(), common.ClaimsKey, claims)

	cmd := &cobra.Command{Use: "delete", Args: cobra.ExactArgs(1), RunE: deleteCmd.RunE}
	cmd.SetContext(ctx)
	cmd.SetArgs([]string{uuid.New().String()})
	err := cmd.Execute()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "service container not available")
}

// --------------------------------------------------------------------------
// getCmd tests
// --------------------------------------------------------------------------

func TestGetCmd_NoClaims(t *testing.T) {
	ctx := context.Background()
	cmd := &cobra.Command{Use: "get", RunE: getCmd.RunE}
	cmd.SetContext(ctx)
	cmd.SetArgs([]string{uuid.New().String()})
	err := cmd.Execute()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unauthorized")
}

func TestGetCmd_NoServiceContainer(t *testing.T) {
	userID := uuid.New()
	claims := &model.Claims{UserID: userID, Roles: []string{model.RoleAdmin}}
	ctx := context.WithValue(context.Background(), common.ClaimsKey, claims)

	cmd := &cobra.Command{Use: "get", RunE: getCmd.RunE}
	cmd.SetContext(ctx)
	cmd.SetArgs([]string{uuid.New().String()})
	err := cmd.Execute()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "service container not available")
}

func TestGetCmd_InvalidUUID(t *testing.T) {
	tc := testutils.NewTestContext(t)
	ctx := newUsersTestCtx(tc.MockContainer)

	cmd := &cobra.Command{Use: "get", RunE: getCmd.RunE}
	cmd.SetContext(ctx)
	cmd.SetArgs([]string{"bad-uuid"})
	err := cmd.Execute()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid user ID")
}

func TestGetCmd_ForbiddenNonAdmin(t *testing.T) {
	tc := testutils.NewTestContext(t)
	callerID := uuid.New()
	otherID := uuid.New()
	ctx := newUsersTestCtxWithRole(tc.MockContainer, callerID, model.RoleUser)

	cmd := &cobra.Command{Use: "get", RunE: getCmd.RunE}
	cmd.SetContext(ctx)
	cmd.SetArgs([]string{otherID.String()})
	err := cmd.Execute()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "forbidden")
}

func TestGetCmd_ServiceError(t *testing.T) {
	tc := testutils.NewTestContext(t)
	targetID := uuid.New()
	ctx := newUsersTestCtx(tc.MockContainer)

	tc.MockUserService.On("GetUser", mock.Anything, targetID).Return(nil, fmt.Errorf("not found"))

	cmd := &cobra.Command{Use: "get", RunE: getCmd.RunE}
	cmd.SetContext(ctx)
	cmd.SetArgs([]string{targetID.String()})
	err := cmd.Execute()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to get user")
	tc.MockUserService.AssertExpectations(t)
}

func TestGetCmd_Success(t *testing.T) {
	tc := testutils.NewTestContext(t)
	targetID := uuid.New()
	ctx := newUsersTestCtx(tc.MockContainer)

	user := &model.User{
		ID:        targetID,
		Username:  "alice",
		Roles:     []string{model.RoleUser},
		CreatedAt: time.Now(),
	}
	tc.MockUserService.On("GetUser", mock.Anything, targetID).Return(user, nil)

	cmd := &cobra.Command{Use: "get", RunE: getCmd.RunE}
	cmd.SetContext(ctx)
	cmd.SetArgs([]string{targetID.String()})
	err := cmd.Execute()
	assert.NoError(t, err)
	tc.MockUserService.AssertExpectations(t)
}

func TestGetCmd_NoFormatter(t *testing.T) {
	tc := testutils.NewTestContext(t)
	targetID := uuid.New()

	// Build context without the OutputFormatterKey.
	userID := uuid.New()
	claims := &model.Claims{UserID: userID, Roles: []string{model.RoleAdmin}}
	ctx := context.Background()
	ctx = context.WithValue(ctx, common.ClaimsKey, claims)
	ctx = context.WithValue(ctx, common.ServiceContainerKey, tc.MockContainer)

	user := &model.User{
		ID:        targetID,
		Username:  "alice",
		Roles:     []string{model.RoleUser},
		CreatedAt: time.Now(),
	}
	tc.MockUserService.On("GetUser", mock.Anything, targetID).Return(user, nil)

	cmd := &cobra.Command{Use: "get", RunE: getCmd.RunE}
	cmd.SetContext(ctx)
	cmd.SetArgs([]string{targetID.String()})
	err := cmd.Execute()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "output formatter not available")
	tc.MockUserService.AssertExpectations(t)
}

// --------------------------------------------------------------------------
// loginCmd tests
// --------------------------------------------------------------------------

// setLoginFlags sets the credential flags on cmd. loginCmd reads them from
// its own flag set, not from global viper -- see cmd/flag_binding_test.go.
func setLoginFlags(t *testing.T, cmd *cobra.Command, username, password, totp string) {
	t.Helper()
	require.NoError(t, cmd.Flags().Set("username", username))
	require.NoError(t, cmd.Flags().Set("password", password))
	require.NoError(t, cmd.Flags().Set("totp-code", totp))
}

func TestLoginCmd_NoServiceContainer(t *testing.T) {
	ctx := context.Background() // no container

	cmd := &cobra.Command{Use: "login", Args: cobra.NoArgs, RunE: loginCmd.RunE}
	cmd.Flags().String("username", "", "")
	cmd.Flags().String("password", "", "")
	cmd.Flags().String("totp-code", "", "")
	setLoginFlags(t, cmd, "alice", "secret", "123456")
	cmd.SetContext(ctx)
	err := cmd.Execute()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "service container not available")
}

func TestLoginCmd_MissingCredentials(t *testing.T) {
	tc := testutils.NewTestContext(t)
	ctx := context.WithValue(context.Background(), common.ServiceContainerKey, tc.MockContainer)

	// No username / password / totp set — the flags keep their "" defaults.
	cmd := &cobra.Command{Use: "login", Args: cobra.NoArgs, RunE: loginCmd.RunE}
	cmd.Flags().String("username", "", "")
	cmd.Flags().String("password", "", "")
	cmd.Flags().String("totp-code", "", "")
	cmd.SetContext(ctx)
	err := cmd.Execute()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "username, password, and totp-code are required")
}

func TestLoginCmd_AuthServiceError(t *testing.T) {
	tc := testutils.NewTestContext(t)
	ctx := context.WithValue(context.Background(), common.ServiceContainerKey, tc.MockContainer)

	tc.MockAuthService.On("AuthenticateUser", mock.Anything, "alice", "secret", "123456").
		Return(nil, fmt.Errorf("invalid credentials"))

	cmd := &cobra.Command{Use: "login", Args: cobra.NoArgs, RunE: loginCmd.RunE}
	cmd.Flags().String("username", "", "")
	cmd.Flags().String("password", "", "")
	cmd.Flags().String("totp-code", "", "")
	setLoginFlags(t, cmd, "alice", "secret", "123456")
	cmd.SetContext(ctx)
	err := cmd.Execute()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to login")
	tc.MockAuthService.AssertExpectations(t)
}

func TestLoginCmd_Success(t *testing.T) {
	common.SessionBaseDir = t.TempDir()
	tc := testutils.NewTestContext(t)
	ctx := context.WithValue(context.Background(), common.ServiceContainerKey, tc.MockContainer)

	authResult := &authServices.AuthenticationResult{
		Token:    "jwt-token-abc",
		UserID:   uuid.New(),
		Username: "alice",
		Roles:    []string{model.RoleUser},
	}
	tc.MockAuthService.On("AuthenticateUser", mock.Anything, "alice", "secret", "123456").
		Return(authResult, nil)

	cmd := &cobra.Command{Use: "login", Args: cobra.NoArgs, RunE: loginCmd.RunE}
	cmd.Flags().String("username", "", "")
	cmd.Flags().String("password", "", "")
	cmd.Flags().String("totp-code", "", "")
	setLoginFlags(t, cmd, "alice", "secret", "123456")
	cmd.SetContext(ctx)
	err := cmd.Execute()
	assert.NoError(t, err)
	tc.MockAuthService.AssertExpectations(t)
}
