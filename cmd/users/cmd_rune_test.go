package users

// Tests for the actual createCmd.RunE, listCmd.RunE, updateCmd.RunE closures.
// The existing create_test.go / list_test.go / update_test.go use inline commands
// that do NOT call these package-level vars, so statement coverage for the real
// RunE bodies is zero. These tests fix that gap.

import (
	"bytes"
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"rocketvault/cmd/testutils"
	"rocketvault/common"
	userServices "rocketvault/internal/services/users"
	"rocketvault/model"
)

// newCreateTestCmd returns a fresh cobra.Command with createCmd.RunE and the
// flags that the RunE reads via cmd.Flags().GetString().
func newCreateTestCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "create", RunE: createCmd.RunE}
	cmd.Flags().String("new-username", "", "")
	cmd.Flags().String("new-password", "", "")
	cmd.Flags().StringArray("new-role", []string{}, "")
	return cmd
}

// newListTestCmd returns a fresh cobra.Command backed by the real listCmd.RunE.
func newListTestCmd() *cobra.Command {
	return &cobra.Command{Use: "list", Args: cobra.NoArgs, RunE: listCmd.RunE}
}

// newUpdateTestCmd returns a fresh cobra.Command backed by the real updateCmd.RunE.
func newUpdateTestCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "update", Args: cobra.ExactArgs(1), RunE: updateCmd.RunE}
	cmd.Flags().String("new-username", "", "")
	cmd.Flags().String("new-password", "", "")
	cmd.Flags().StringArray("new-role", []string{}, "")
	return cmd
}

// --------------------------------------------------------------------------
// createCmd.RunE
// --------------------------------------------------------------------------

func TestCreateCmdRunE_NoClaims(t *testing.T) {
	cmd := newCreateTestCmd()
	cmd.SetContext(context.Background())
	err := cmd.Execute()
	assert.ErrorContains(t, err, "unauthorized")
}

func TestCreateCmdRunE_NonAdminRole(t *testing.T) {
	tc := testutils.NewTestContext(t)
	ctx := newUsersTestCtxWithRole(tc.MockContainer, uuid.New(), model.RoleUser)
	cmd := newCreateTestCmd()
	cmd.SetContext(ctx)
	err := cmd.Execute()
	assert.ErrorContains(t, err, "forbidden")
}

func TestCreateCmdRunE_NoServiceContainer(t *testing.T) {
	claims := &model.Claims{UserID: uuid.New(), Roles: []string{model.RoleAdmin}}
	ctx := context.WithValue(context.Background(), common.ClaimsKey, claims)
	cmd := newCreateTestCmd()
	cmd.SetContext(ctx)
	err := cmd.Execute()
	assert.ErrorContains(t, err, "service container not available")
}

func TestCreateCmdRunE_MissingFields(t *testing.T) {
	tc := testutils.NewTestContext(t)
	ctx := newUsersTestCtx(tc.MockContainer)
	cmd := newCreateTestCmd()
	cmd.SetContext(ctx)
	// All flag values default to "" → validation fails.
	err := cmd.Execute()
	assert.ErrorContains(t, err, "required")
}

func TestCreateCmdRunE_Success(t *testing.T) {
	tc := testutils.NewTestContext(t)
	ctx := newUsersTestCtx(tc.MockContainer)

	result := &userServices.CreateUserResult{
		UserID:     uuid.New(),
		Username:   "newuser",
		Roles:      []string{model.RoleUser},
		TOTPSecret: "otpauth://totp/...",
		CreatedAt:  time.Now(),
	}
	tc.MockUserService.On("CreateUser", mock.Anything, mock.MatchedBy(func(r userServices.CreateUserRequest) bool {
		return r.Username == "newuser" && r.Password == "pw123" && len(r.Roles) == 1 && r.Roles[0] == model.RoleUser
	})).Return(result, nil)

	cmd := newCreateTestCmd()
	cmd.SetContext(ctx)
	cmd.SetArgs([]string{"--new-username=newuser", "--new-password=pw123", "--new-role=user"})

	// createCmd uses fmt.Printf (os.Stdout), not cmd.OutOrStdout(), so buf stays empty.
	err := cmd.Execute()
	assert.NoError(t, err)
	tc.MockUserService.AssertExpectations(t)
}

func TestCreateCmdRunE_ServiceError(t *testing.T) {
	tc := testutils.NewTestContext(t)
	ctx := newUsersTestCtx(tc.MockContainer)

	tc.MockUserService.On("CreateUser", mock.Anything, mock.Anything).
		Return(nil, fmt.Errorf("db error"))

	cmd := newCreateTestCmd()
	cmd.SetContext(ctx)
	cmd.SetArgs([]string{"--new-username=u", "--new-password=p", "--new-role=user"})
	err := cmd.Execute()
	assert.ErrorContains(t, err, "failed to create user")
	tc.MockUserService.AssertExpectations(t)
}

// --------------------------------------------------------------------------
// listCmd.RunE
// --------------------------------------------------------------------------

func TestListCmdRunE_NoClaims(t *testing.T) {
	cmd := newListTestCmd()
	cmd.SetContext(context.Background())
	err := cmd.Execute()
	assert.ErrorContains(t, err, "unauthorized")
}

func TestListCmdRunE_NoServiceContainer(t *testing.T) {
	claims := &model.Claims{UserID: uuid.New(), Roles: []string{model.RoleAdmin}}
	ctx := context.WithValue(context.Background(), common.ClaimsKey, claims)
	cmd := newListTestCmd()
	cmd.SetContext(ctx)
	err := cmd.Execute()
	assert.ErrorContains(t, err, "service container not available")
}

func TestListCmdRunE_NonAdminForbidden(t *testing.T) {
	tc := testutils.NewTestContext(t)
	ctx := newUsersTestCtxWithRole(tc.MockContainer, uuid.New(), model.RoleUser)
	cmd := newListTestCmd()
	cmd.SetContext(ctx)
	err := cmd.Execute()
	assert.ErrorContains(t, err, "forbidden")
}

func TestListCmdRunE_Success(t *testing.T) {
	tc := testutils.NewTestContext(t)
	ctx := newUsersTestCtx(tc.MockContainer)

	users := []model.User{
		{ID: uuid.New(), Username: "alice", Roles: []string{model.RoleUser}, CreatedAt: time.Now()},
		{ID: uuid.New(), Username: "bob", Roles: []string{model.RoleAdmin}, CreatedAt: time.Now()},
	}
	tc.MockUserService.On("ListUsers", mock.Anything).Return(users, nil)

	cmd := newListTestCmd()
	cmd.SetContext(ctx)
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	err := cmd.Execute()
	assert.NoError(t, err)
	assert.Contains(t, buf.String(), "alice")
	tc.MockUserService.AssertExpectations(t)
}

func TestListCmdRunE_ServiceError(t *testing.T) {
	tc := testutils.NewTestContext(t)
	ctx := newUsersTestCtx(tc.MockContainer)

	tc.MockUserService.On("ListUsers", mock.Anything).Return(nil, fmt.Errorf("db down"))

	cmd := newListTestCmd()
	cmd.SetContext(ctx)
	err := cmd.Execute()
	assert.ErrorContains(t, err, "failed to list users")
}

func TestListCmdRunE_NoFormatter(t *testing.T) {
	tc := testutils.NewTestContext(t)

	claims := &model.Claims{UserID: uuid.New(), Roles: []string{model.RoleAdmin}}
	ctx := context.WithValue(context.Background(), common.ClaimsKey, claims)
	ctx = context.WithValue(ctx, common.ServiceContainerKey, tc.MockContainer)
	// No OutputFormatterKey.

	tc.MockUserService.On("ListUsers", mock.Anything).Return([]model.User{}, nil)

	cmd := newListTestCmd()
	cmd.SetContext(ctx)
	err := cmd.Execute()
	assert.ErrorContains(t, err, "output formatter not available")
}

// --------------------------------------------------------------------------
// updateCmd.RunE
// --------------------------------------------------------------------------

func TestUpdateCmdRunE_NoClaims(t *testing.T) {
	cmd := newUpdateTestCmd()
	cmd.SetContext(context.Background())
	cmd.SetArgs([]string{uuid.New().String()})
	err := cmd.Execute()
	assert.ErrorContains(t, err, "unauthorized")
}

func TestUpdateCmdRunE_InvalidUUID(t *testing.T) {
	tc := testutils.NewTestContext(t)
	ctx := newUsersTestCtx(tc.MockContainer)
	cmd := newUpdateTestCmd()
	cmd.SetContext(ctx)
	cmd.SetArgs([]string{"not-a-uuid"})
	err := cmd.Execute()
	assert.ErrorContains(t, err, "invalid user ID")
}

func TestUpdateCmdRunE_NoFields(t *testing.T) {
	tc := testutils.NewTestContext(t)
	ctx := newUsersTestCtx(tc.MockContainer)
	cmd := newUpdateTestCmd()
	cmd.SetContext(ctx)
	cmd.SetArgs([]string{uuid.New().String()})
	err := cmd.Execute()
	assert.ErrorContains(t, err, "at least one field")
}

func TestUpdateCmdRunE_NonAdminCannotUpdateOther(t *testing.T) {
	tc := testutils.NewTestContext(t)
	callerID := uuid.New()
	otherID := uuid.New()
	ctx := newUsersTestCtxWithRole(tc.MockContainer, callerID, model.RoleUser)
	cmd := newUpdateTestCmd()
	cmd.SetContext(ctx)
	cmd.SetArgs([]string{otherID.String(), "--new-username=x"})
	err := cmd.Execute()
	assert.ErrorContains(t, err, "forbidden")
}

func TestUpdateCmdRunE_NonAdminCannotChangeRole(t *testing.T) {
	tc := testutils.NewTestContext(t)
	callerID := uuid.New()
	ctx := newUsersTestCtxWithRole(tc.MockContainer, callerID, model.RoleUser)
	cmd := newUpdateTestCmd()
	cmd.SetContext(ctx)
	cmd.SetArgs([]string{callerID.String(), "--new-role=admin"})
	err := cmd.Execute()
	assert.ErrorContains(t, err, "forbidden: only admins")
}

func TestUpdateCmdRunE_InvalidRole(t *testing.T) {
	tc := testutils.NewTestContext(t)
	ctx := newUsersTestCtx(tc.MockContainer)
	cmd := newUpdateTestCmd()
	cmd.SetContext(ctx)
	cmd.SetArgs([]string{uuid.New().String(), "--new-role=superuser"})

	// Role validation now lives in the service layer, not the CLI: updateCmd
	// forwards --new-role verbatim and surfaces whatever error UpdateUser
	// returns.
	tc.MockUserService.On("UpdateUser", mock.Anything, mock.Anything).
		Return(nil, fmt.Errorf("invalid role: superuser"))

	err := cmd.Execute()
	assert.ErrorContains(t, err, "invalid role")
	tc.MockUserService.AssertExpectations(t)
}

func TestUpdateCmdRunE_Success(t *testing.T) {
	tc := testutils.NewTestContext(t)
	targetID := uuid.New()
	ctx := newUsersTestCtx(tc.MockContainer)

	// req.Roles must come through as nil, not a non-nil empty slice: per
	// UpdateUserRequest's contract, nil means "no change" while any non-nil
	// value (even empty) is an explicit role-change request that fails
	// validation. This pins the absent-flag-to-nil guard in updateCmd.RunE --
	// see the comment above `var rolesArg []string` there.
	tc.MockUserService.On("UpdateUser", mock.Anything, mock.MatchedBy(func(r userServices.UpdateUserRequest) bool {
		return r.UserID == targetID && r.Username != nil && *r.Username == "renamed" && r.Roles == nil
	})).Return(&userServices.UpdateUserResult{}, nil)

	cmd := newUpdateTestCmd()
	cmd.SetContext(ctx)
	cmd.SetArgs([]string{targetID.String(), "--new-username=renamed"})
	err := cmd.Execute()
	assert.NoError(t, err)
	tc.MockUserService.AssertExpectations(t)
}

func TestUpdateCmdRunE_ServiceError(t *testing.T) {
	tc := testutils.NewTestContext(t)
	targetID := uuid.New()
	ctx := newUsersTestCtx(tc.MockContainer)

	tc.MockUserService.On("UpdateUser", mock.Anything, mock.Anything).Return(nil, fmt.Errorf("update failed"))

	cmd := newUpdateTestCmd()
	cmd.SetContext(ctx)
	cmd.SetArgs([]string{targetID.String(), "--new-username=x"})
	err := cmd.Execute()
	assert.ErrorContains(t, err, "failed to update user")
}

func TestUpdateCmdRunE_PasswordEnrollment_PrintsTOTPURL(t *testing.T) {
	tc := testutils.NewTestContext(t)
	targetID := uuid.New()
	ctx := newUsersTestCtx(tc.MockContainer)
	enrollURL := "otpauth://totp/PasswordManager:alice?secret=ABC"

	// Capture the audit log, which must never carry the enrollment URL.
	var logBuf bytes.Buffer
	tc.Logger.SetOutput(&logBuf)

	tc.MockUserService.On("UpdateUser", mock.Anything, mock.MatchedBy(func(r userServices.UpdateUserRequest) bool {
		return r.Password != nil && *r.Password == "newpass123"
	})).Return(&userServices.UpdateUserResult{TOTPEnrollmentURL: enrollURL}, nil)

	var out bytes.Buffer
	cmd := newUpdateTestCmd()
	cmd.SetContext(ctx)
	cmd.SetOut(&out)
	cmd.SetArgs([]string{targetID.String(), "--new-password=newpass123"})

	require.NoError(t, cmd.Execute())
	assert.Contains(t, out.String(), enrollURL)
	assert.Equal(t, 1, strings.Count(out.String(), enrollURL), "the URL is printed exactly once")
	assert.Contains(t, out.String(), "shown only once")
	assert.NotContains(t, logBuf.String(), enrollURL)
	assert.NotContains(t, logBuf.String(), "secret=ABC")
}

func TestUpdateCmdRunE_NoEnrollment_PrintsNoTOTPSecret(t *testing.T) {
	tc := testutils.NewTestContext(t)
	targetID := uuid.New()
	ctx := newUsersTestCtx(tc.MockContainer)

	tc.MockUserService.On("UpdateUser", mock.Anything, mock.Anything).
		Return(&userServices.UpdateUserResult{}, nil)

	var out bytes.Buffer
	cmd := newUpdateTestCmd()
	cmd.SetContext(ctx)
	cmd.SetOut(&out)
	cmd.SetArgs([]string{targetID.String(), "--new-password=newpass123"})

	require.NoError(t, cmd.Execute())
	assert.Contains(t, out.String(), "updated successfully")
	assert.NotContains(t, out.String(), "TOTP Secret")
}
