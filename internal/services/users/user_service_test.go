package users

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"rocketvault/internal/logging"
	"rocketvault/model"
)

// ---------------------------------------------------------------------------
// Mock: UserRepositoryInterface
// ---------------------------------------------------------------------------

type mockUserRepository struct {
	mock.Mock
}

func (m *mockUserRepository) Create(ctx context.Context, user *model.User) error {
	return m.Called(ctx, user).Error(0)
}

func (m *mockUserRepository) Read(ctx context.Context, id uuid.UUID) (*model.User, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*model.User), args.Error(1)
}

func (m *mockUserRepository) Update(ctx context.Context, user *model.User) error {
	return m.Called(ctx, user).Error(0)
}

func (m *mockUserRepository) Delete(ctx context.Context, id uuid.UUID) error {
	return m.Called(ctx, id).Error(0)
}

func (m *mockUserRepository) ReadByUsername(ctx context.Context, username string) (model.User, error) {
	args := m.Called(ctx, username)
	return args.Get(0).(model.User), args.Error(1)
}

func (m *mockUserRepository) ReadByExternalSubject(ctx context.Context, provider, subject string) (*model.User, error) {
	args := m.Called(ctx, provider, subject)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*model.User), args.Error(1)
}

func (m *mockUserRepository) List(ctx context.Context) ([]model.User, error) {
	args := m.Called(ctx)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]model.User), args.Error(1)
}

func (m *mockUserRepository) ValidateBootstrapToken(ctx context.Context, token string) (bool, error) {
	args := m.Called(ctx, token)
	return args.Bool(0), args.Error(1)
}

func (m *mockUserRepository) InvalidateBootstrapToken(ctx context.Context, token string) error {
	return m.Called(ctx, token).Error(0)
}

// ---------------------------------------------------------------------------
// Mock: PasswordService
// ---------------------------------------------------------------------------

type mockPasswordService struct {
	mock.Mock
}

func (m *mockPasswordService) HashPassword(password string) (string, error) {
	args := m.Called(password)
	return args.String(0), args.Error(1)
}

func (m *mockPasswordService) ValidatePassword(password, hash string) error {
	return m.Called(password, hash).Error(0)
}

// ---------------------------------------------------------------------------
// Mock: TOTPService
// ---------------------------------------------------------------------------

type mockTOTPService struct {
	mock.Mock
}

func (m *mockTOTPService) GenerateSecret(issuer, accountName string) (*otp.Key, error) {
	args := m.Called(issuer, accountName)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*otp.Key), args.Error(1)
}

func (m *mockTOTPService) ValidateCode(code, secret string, currentTime time.Time) (bool, error) {
	args := m.Called(code, secret, currentTime)
	return args.Bool(0), args.Error(1)
}

func (m *mockTOTPService) GenerateCode(secret string, currentTime time.Time) (string, error) {
	args := m.Called(secret, currentTime)
	return args.String(0), args.Error(1)
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func testLogger() *logging.Logger {
	return &logging.Logger{Logger: logrus.New()}
}

// realTOTPKey generates a genuine *otp.Key so the mock can return something
// the service can call .Secret() and .URL() on.
func realTOTPKey(t *testing.T) *otp.Key {
	t.Helper()
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      "Test",
		AccountName: "user",
	})
	require.NoError(t, err)
	return key
}

func newService(
	repo *mockUserRepository,
	pw *mockPasswordService,
	totpSvc *mockTOTPService,
) UserService {
	return NewUserService(UserServiceConfig{
		UserRepository:  repo,
		PasswordService: pw,
		TOTPService:     totpSvc,
		Logger:          testLogger(),
	})
}

// ---------------------------------------------------------------------------
// CreateUser tests
// ---------------------------------------------------------------------------

// 1. Non-admin caller is forbidden.
func TestCreateUser_NonAdmin_Forbidden(t *testing.T) {
	t.Parallel()
	repo := &mockUserRepository{}
	pw := &mockPasswordService{}
	totpSvc := &mockTOTPService{}
	svc := newService(repo, pw, totpSvc)

	req := CreateUserRequest{
		Username:    "bob",
		Password:    "pass",
		Roles:       []string{model.RoleUser},
		CallerRoles: []string{model.RoleUser}, // not admin
	}

	result, err := svc.CreateUser(context.Background(), req)

	assert.Nil(t, result)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "forbidden")
	repo.AssertNotCalled(t, "Create")
}

// 2. HashPassword failure propagates.
func TestCreateUser_HashPasswordFails(t *testing.T) {
	t.Parallel()
	repo := &mockUserRepository{}
	pw := &mockPasswordService{}
	totpSvc := &mockTOTPService{}
	svc := newService(repo, pw, totpSvc)

	pw.On("HashPassword", "pass").Return("", errors.New("bcrypt error"))

	req := CreateUserRequest{
		Username:    "alice",
		Password:    "pass",
		Roles:       []string{model.RoleUser},
		CallerRoles: []string{model.RoleAdmin},
	}

	result, err := svc.CreateUser(context.Background(), req)

	assert.Nil(t, result)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to prepare user")
	repo.AssertNotCalled(t, "Create")
}

// 3. GenerateSecret failure propagates.
func TestCreateUser_GenerateSecretFails(t *testing.T) {
	t.Parallel()
	repo := &mockUserRepository{}
	pw := &mockPasswordService{}
	totpSvc := &mockTOTPService{}
	svc := newService(repo, pw, totpSvc)

	pw.On("HashPassword", "pass").Return("hashed", nil)
	totpSvc.On("GenerateSecret", "PasswordManager", "alice").Return(nil, errors.New("totp error"))

	req := CreateUserRequest{
		Username:    "alice",
		Password:    "pass",
		Roles:       []string{model.RoleUser},
		CallerRoles: []string{model.RoleAdmin},
	}

	result, err := svc.CreateUser(context.Background(), req)

	assert.Nil(t, result)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to generate TOTP secret")
	repo.AssertNotCalled(t, "Create")
}

// 4. Repository Create failure propagates.
func TestCreateUser_RepoCreateFails(t *testing.T) {
	t.Parallel()
	repo := &mockUserRepository{}
	pw := &mockPasswordService{}
	totpSvc := &mockTOTPService{}
	svc := newService(repo, pw, totpSvc)

	key := realTOTPKey(t)
	pw.On("HashPassword", "pass").Return("hashed", nil)
	totpSvc.On("GenerateSecret", "PasswordManager", "alice").Return(key, nil)
	repo.On("Create", mock.Anything, mock.AnythingOfType("*model.User")).Return(errors.New("db error"))

	req := CreateUserRequest{
		Username:    "alice",
		Password:    "pass",
		Roles:       []string{model.RoleUser},
		CallerRoles: []string{model.RoleAdmin},
	}

	result, err := svc.CreateUser(context.Background(), req)

	assert.Nil(t, result)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to create user")
}

// 5. Success path returns populated result.
func TestCreateUser_Success(t *testing.T) {
	t.Parallel()
	repo := &mockUserRepository{}
	pw := &mockPasswordService{}
	totpSvc := &mockTOTPService{}
	svc := newService(repo, pw, totpSvc)

	key := realTOTPKey(t)
	pw.On("HashPassword", "pass").Return("hashed", nil)
	totpSvc.On("GenerateSecret", "PasswordManager", "alice").Return(key, nil)
	repo.On("Create", mock.Anything, mock.AnythingOfType("*model.User")).Return(nil)

	req := CreateUserRequest{
		Username:    "alice",
		Password:    "pass",
		Roles:       []string{model.RoleAdmin},
		CallerRoles: []string{model.RoleAdmin},
	}

	result, err := svc.CreateUser(context.Background(), req)

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, "alice", result.Username)
	assert.ElementsMatch(t, []string{model.RoleAdmin}, result.Roles)
	assert.NotEmpty(t, result.TOTPSecret)
	assert.NotEqual(t, uuid.Nil, result.UserID)
	repo.AssertExpectations(t)
}

func TestCreateUser_AllValidRoles_Accepted(t *testing.T) {
	t.Parallel()
	for _, role := range model.ValidRoles {
		t.Run(role, func(t *testing.T) {
			t.Parallel()
			repo := &mockUserRepository{}
			pw := &mockPasswordService{}
			totpSvc := &mockTOTPService{}
			svc := newService(repo, pw, totpSvc)

			key := realTOTPKey(t)
			pw.On("HashPassword", "pw12345678").Return("hashed", nil)
			totpSvc.On("GenerateSecret", "PasswordManager", "newuser").Return(key, nil)
			repo.On("Create", mock.Anything, mock.MatchedBy(func(u *model.User) bool {
				return len(u.Roles) == 1 && u.Roles[0] == role
			})).Return(nil)

			req := CreateUserRequest{
				Username:    "newuser",
				Password:    "pw12345678",
				Roles:       []string{role},
				CallerRoles: []string{model.RoleAdmin},
			}
			result, err := svc.CreateUser(context.Background(), req)
			require.NoError(t, err)
			assert.ElementsMatch(t, []string{role}, result.Roles)
		})
	}
}

func TestCreateUser_InvalidRole_Rejected(t *testing.T) {
	t.Parallel()
	repo := &mockUserRepository{}
	pw := &mockPasswordService{}
	totpSvc := &mockTOTPService{}
	svc := newService(repo, pw, totpSvc)

	req := CreateUserRequest{
		Username:    "newuser",
		Password:    "pw12345678",
		Roles:       []string{"not_a_real_role"},
		CallerRoles: []string{model.RoleAdmin},
	}
	_, err := svc.CreateUser(context.Background(), req)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid role")
	repo.AssertNotCalled(t, "Create")
}

func TestCreateUser_MultipleRoles_AllStored(t *testing.T) {
	t.Parallel()
	repo := &mockUserRepository{}
	pw := &mockPasswordService{}
	totpSvc := &mockTOTPService{}
	svc := newService(repo, pw, totpSvc)

	key := realTOTPKey(t)
	pw.On("HashPassword", "pw12345678").Return("hashed", nil)
	totpSvc.On("GenerateSecret", "PasswordManager", "newuser").Return(key, nil)
	repo.On("Create", mock.Anything, mock.MatchedBy(func(u *model.User) bool {
		return assert.ObjectsAreEqualValues([]string{"secrets_manager", "crypto_manager"}, u.Roles) ||
			assert.ObjectsAreEqualValues([]string{"crypto_manager", "secrets_manager"}, u.Roles)
	})).Return(nil)

	req := CreateUserRequest{
		Username:    "newuser",
		Password:    "pw12345678",
		Roles:       []string{"secrets_manager", "crypto_manager"},
		CallerRoles: []string{model.RoleAdmin},
	}
	result, err := svc.CreateUser(context.Background(), req)
	require.NoError(t, err)
	assert.ElementsMatch(t, []string{"secrets_manager", "crypto_manager"}, result.Roles)
}

// TestCreateUser_RolesTrimmedAndDeduped proves whitespace is trimmed and
// duplicates are collapsed before storage: " admin " and "admin" collapse to
// a single "admin" entry.
func TestCreateUser_RolesTrimmedAndDeduped(t *testing.T) {
	t.Parallel()
	repo := &mockUserRepository{}
	pw := &mockPasswordService{}
	totpSvc := &mockTOTPService{}
	svc := newService(repo, pw, totpSvc)

	key := realTOTPKey(t)
	pw.On("HashPassword", "pw12345678").Return("hashed", nil)
	totpSvc.On("GenerateSecret", "PasswordManager", "newuser").Return(key, nil)
	repo.On("Create", mock.Anything, mock.MatchedBy(func(u *model.User) bool {
		return len(u.Roles) == 1 && u.Roles[0] == model.RoleAdmin
	})).Return(nil)

	req := CreateUserRequest{
		Username:    "newuser",
		Password:    "pw12345678",
		Roles:       []string{" admin ", "admin"},
		CallerRoles: []string{model.RoleAdmin},
	}
	result, err := svc.CreateUser(context.Background(), req)
	require.NoError(t, err)
	assert.Equal(t, []string{model.RoleAdmin}, result.Roles)
	repo.AssertExpectations(t)
}

// TestCreateUser_WhitespaceOnlyRoles_Rejected is the Finding-1 regression
// test: a Roles list containing only whitespace must not silently produce a
// role-less user. The pre-loop len(req.Roles) == 0 check alone would miss
// this, since len([]string{"  "}) == 1.
func TestCreateUser_WhitespaceOnlyRoles_Rejected(t *testing.T) {
	t.Parallel()
	repo := &mockUserRepository{}
	pw := &mockPasswordService{}
	totpSvc := &mockTOTPService{}
	svc := newService(repo, pw, totpSvc)

	req := CreateUserRequest{
		Username:    "newuser",
		Password:    "pw12345678",
		Roles:       []string{"  "},
		CallerRoles: []string{model.RoleAdmin},
	}
	result, err := svc.CreateUser(context.Background(), req)

	assert.Nil(t, result)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid role")
	repo.AssertNotCalled(t, "Create")
}

// ---------------------------------------------------------------------------
// UpdateUser tests
// ---------------------------------------------------------------------------

// 6. Role change by non-admin is forbidden.
func TestUpdateUser_RoleChangeByNonAdmin_Forbidden(t *testing.T) {
	t.Parallel()
	repo := &mockUserRepository{}
	pw := &mockPasswordService{}
	totpSvc := &mockTOTPService{}
	svc := newService(repo, pw, totpSvc)

	req := UpdateUserRequest{
		UserID:      uuid.New(),
		CallerRoles: []string{model.RoleUser},
		Roles:       []string{model.RoleSecretsManager},
	}

	_, err := svc.UpdateUser(context.Background(), req)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "forbidden")
	repo.AssertNotCalled(t, "Read")
}

// 7. Invalid role value rejected.
func TestUpdateUser_InvalidRole(t *testing.T) {
	t.Parallel()
	repo := &mockUserRepository{}
	pw := &mockPasswordService{}
	totpSvc := &mockTOTPService{}
	svc := newService(repo, pw, totpSvc)

	req := UpdateUserRequest{
		UserID:      uuid.New(),
		CallerRoles: []string{model.RoleAdmin},
		Roles:       []string{"super_hacker"},
	}

	_, err := svc.UpdateUser(context.Background(), req)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid role")
}

// 8. User not found (repo.Read fails).
func TestUpdateUser_UserNotFound(t *testing.T) {
	t.Parallel()
	repo := &mockUserRepository{}
	pw := &mockPasswordService{}
	totpSvc := &mockTOTPService{}
	svc := newService(repo, pw, totpSvc)

	userID := uuid.New()
	repo.On("Read", mock.Anything, userID).Return(nil, errors.New("user not found"))

	req := UpdateUserRequest{
		UserID:      userID,
		CallerRoles: []string{model.RoleUser},
	}

	_, err := svc.UpdateUser(context.Background(), req)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "user not found")
}

// 9. Password hash fails during update.
func TestUpdateUser_PasswordHashFails(t *testing.T) {
	t.Parallel()
	repo := &mockUserRepository{}
	pw := &mockPasswordService{}
	totpSvc := &mockTOTPService{}
	svc := newService(repo, pw, totpSvc)

	userID := uuid.New()
	existing := &model.User{
		ID:       userID,
		Username: "alice",
		Roles:    []string{model.RoleUser},
	}
	repo.On("Read", mock.Anything, userID).Return(existing, nil)

	newPw := "newpass"
	pw.On("HashPassword", "newpass").Return("", errors.New("hash error"))

	req := UpdateUserRequest{
		UserID:      userID,
		CallerRoles: []string{model.RoleUser},
		Password:    &newPw,
	}

	_, err := svc.UpdateUser(context.Background(), req)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to hash password")
}

// 10. repo.Update fails.
func TestUpdateUser_RepoUpdateFails(t *testing.T) {
	t.Parallel()
	repo := &mockUserRepository{}
	pw := &mockPasswordService{}
	totpSvc := &mockTOTPService{}
	svc := newService(repo, pw, totpSvc)

	userID := uuid.New()
	existing := &model.User{
		ID:       userID,
		Username: "alice",
		Roles:    []string{model.RoleUser},
	}
	repo.On("Read", mock.Anything, userID).Return(existing, nil)
	repo.On("Update", mock.Anything, mock.AnythingOfType("*model.User")).Return(errors.New("db error"))

	req := UpdateUserRequest{
		UserID:      userID,
		CallerRoles: []string{model.RoleUser},
	}

	_, err := svc.UpdateUser(context.Background(), req)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to update user")
}

// 11. Success with username change.
func TestUpdateUser_SuccessUsernameChange(t *testing.T) {
	t.Parallel()
	repo := &mockUserRepository{}
	pw := &mockPasswordService{}
	totpSvc := &mockTOTPService{}
	svc := newService(repo, pw, totpSvc)

	userID := uuid.New()
	existing := &model.User{
		ID:       userID,
		Username: "alice",
		Roles:    []string{model.RoleUser},
	}
	repo.On("Read", mock.Anything, userID).Return(existing, nil)
	repo.On("Update", mock.Anything, mock.MatchedBy(func(u *model.User) bool {
		return u.Username == "alice_new"
	})).Return(nil)

	newUsername := "alice_new"
	req := UpdateUserRequest{
		UserID:      userID,
		CallerRoles: []string{model.RoleUser},
		Username:    &newUsername,
	}

	_, err := svc.UpdateUser(context.Background(), req)
	require.NoError(t, err)
	repo.AssertExpectations(t)
}

// 12. Success with role change (admin caller).
func TestUpdateUser_SuccessRoleChange(t *testing.T) {
	t.Parallel()
	repo := &mockUserRepository{}
	pw := &mockPasswordService{}
	totpSvc := &mockTOTPService{}
	svc := newService(repo, pw, totpSvc)

	userID := uuid.New()
	existing := &model.User{
		ID:       userID,
		Username: "alice",
		Roles:    []string{model.RoleUser},
	}
	repo.On("Read", mock.Anything, userID).Return(existing, nil)
	repo.On("Update", mock.Anything, mock.MatchedBy(func(u *model.User) bool {
		return len(u.Roles) == 1 && u.Roles[0] == model.RoleSecretsManager
	})).Return(nil)

	req := UpdateUserRequest{
		UserID:      userID,
		CallerRoles: []string{model.RoleAdmin},
		Roles:       []string{model.RoleSecretsManager},
	}

	_, err := svc.UpdateUser(context.Background(), req)
	require.NoError(t, err)
	repo.AssertExpectations(t)
}

// 25. Self-promotion is blocked: even a caller including their own already-
// held role in the new Roles list is rejected without admin.
func TestUpdateUser_SelfPromotion_Blocked(t *testing.T) {
	t.Parallel()
	repo := &mockUserRepository{}
	pw := &mockPasswordService{}
	totpSvc := &mockTOTPService{}
	svc := newService(repo, pw, totpSvc)

	userID := uuid.New()
	req := UpdateUserRequest{
		UserID:      userID,
		CallerRoles: []string{model.RoleUser},
		Roles:       []string{model.RoleUser, model.RoleAdmin}, // self-promotion attempt
	}

	_, err := svc.UpdateUser(context.Background(), req)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "forbidden")
	repo.AssertNotCalled(t, "Update")
}

// 26. Admin caller can grant multiple roles in one update.
func TestUpdateUser_AdminCanGrantMultipleRoles(t *testing.T) {
	t.Parallel()
	repo := &mockUserRepository{}
	pw := &mockPasswordService{}
	totpSvc := &mockTOTPService{}
	svc := newService(repo, pw, totpSvc)

	userID := uuid.New()
	existing := &model.User{ID: userID, Username: "alice", Roles: []string{model.RoleUser}}
	repo.On("Read", mock.Anything, userID).Return(existing, nil)
	repo.On("Update", mock.Anything, mock.MatchedBy(func(u *model.User) bool {
		return assert.ObjectsAreEqualValues([]string{"secrets_manager", "crypto_manager"}, u.Roles)
	})).Return(nil)

	req := UpdateUserRequest{
		UserID:      userID,
		CallerRoles: []string{model.RoleAdmin},
		Roles:       []string{model.RoleSecretsManager, model.RoleCryptoManager},
	}
	_, err := svc.UpdateUser(context.Background(), req)
	require.NoError(t, err)
	repo.AssertExpectations(t)
}

// 27. An invalid role anywhere in the list rejects the whole update.
func TestUpdateUser_InvalidRoleInList_Rejected(t *testing.T) {
	t.Parallel()
	repo := &mockUserRepository{}
	pw := &mockPasswordService{}
	totpSvc := &mockTOTPService{}
	svc := newService(repo, pw, totpSvc)

	req := UpdateUserRequest{
		UserID:      uuid.New(),
		CallerRoles: []string{model.RoleAdmin},
		Roles:       []string{model.RoleAdmin, "not_a_real_role"},
	}
	_, err := svc.UpdateUser(context.Background(), req)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid role")
	repo.AssertNotCalled(t, "Update")
}

// TestUpdateUser_RoleSubstringBypass_Rejected verifies that a garbage role
// string sharing a substring with a real role name (e.g. "min" is a substring
// of "admin", "_manager" is a substring of "secrets_manager") is rejected by
// exact-match validation, not accidentally accepted by a substring check.
// This case moved here from cmd/users/update_test.go once role validation
// moved from the CLI layer into UserService.
func TestUpdateUser_RoleSubstringBypass_Rejected(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		role string
	}{
		{name: "min substring of admin", role: "min"},
		{name: "_manager substring of secrets_manager", role: "_manager"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			repo := &mockUserRepository{}
			pw := &mockPasswordService{}
			totpSvc := &mockTOTPService{}
			svc := newService(repo, pw, totpSvc)

			req := UpdateUserRequest{
				UserID:      uuid.New(),
				CallerRoles: []string{model.RoleAdmin},
				Roles:       []string{tt.role},
			}
			_, err := svc.UpdateUser(context.Background(), req)
			require.Error(t, err)
			assert.Contains(t, err.Error(), "invalid role")
			repo.AssertNotCalled(t, "Update")
		})
	}
}

// TestUpdateUser_WhitespaceOnlyRoles_Rejected is the Finding-1 regression
// test for UpdateUser: a Roles list containing only whitespace must not
// silently strip all of the user's existing roles. The roles-empty check
// runs before repo.Read, so Read is never reached either.
func TestUpdateUser_WhitespaceOnlyRoles_Rejected(t *testing.T) {
	t.Parallel()
	repo := &mockUserRepository{}
	pw := &mockPasswordService{}
	totpSvc := &mockTOTPService{}
	svc := newService(repo, pw, totpSvc)

	req := UpdateUserRequest{
		UserID:      uuid.New(),
		CallerRoles: []string{model.RoleAdmin},
		Roles:       []string{"  "},
	}
	_, err := svc.UpdateUser(context.Background(), req)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid role")
	repo.AssertNotCalled(t, "Update")
}

// ---------------------------------------------------------------------------
// GetUser tests
// ---------------------------------------------------------------------------

// 13. GetUser success.
func TestGetUser_Success(t *testing.T) {
	t.Parallel()
	repo := &mockUserRepository{}
	pw := &mockPasswordService{}
	totpSvc := &mockTOTPService{}
	svc := newService(repo, pw, totpSvc)

	userID := uuid.New()
	expected := &model.User{
		ID:        userID,
		Username:  "alice",
		Roles:     []string{model.RoleUser},
		CreatedAt: time.Now(),
	}
	repo.On("Read", mock.Anything, userID).Return(expected, nil)

	result, err := svc.GetUser(context.Background(), userID)

	require.NoError(t, err)
	assert.Equal(t, expected, result)
}

// 14. GetUser not found.
func TestGetUser_NotFound(t *testing.T) {
	t.Parallel()
	repo := &mockUserRepository{}
	pw := &mockPasswordService{}
	totpSvc := &mockTOTPService{}
	svc := newService(repo, pw, totpSvc)

	userID := uuid.New()
	repo.On("Read", mock.Anything, userID).Return(nil, errors.New("user not found"))

	result, err := svc.GetUser(context.Background(), userID)

	assert.Nil(t, result)
	require.Error(t, err)
}

// ---------------------------------------------------------------------------
// GetUserByUsername tests
// ---------------------------------------------------------------------------

// 15. GetUserByUsername success.
func TestGetUserByUsername_Success(t *testing.T) {
	t.Parallel()
	repo := &mockUserRepository{}
	pw := &mockPasswordService{}
	totpSvc := &mockTOTPService{}
	svc := newService(repo, pw, totpSvc)

	expected := model.User{
		ID:       uuid.New(),
		Username: "alice",
		Roles:    []string{model.RoleUser},
	}
	repo.On("ReadByUsername", mock.Anything, "alice").Return(expected, nil)

	result, err := svc.GetUserByUsername(context.Background(), "alice")

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, expected.Username, result.Username)
}

// 16. GetUserByUsername not found.
func TestGetUserByUsername_NotFound(t *testing.T) {
	t.Parallel()
	repo := &mockUserRepository{}
	pw := &mockPasswordService{}
	totpSvc := &mockTOTPService{}
	svc := newService(repo, pw, totpSvc)

	repo.On("ReadByUsername", mock.Anything, "ghost").Return(model.User{}, errors.New("user not found"))

	result, err := svc.GetUserByUsername(context.Background(), "ghost")

	assert.Nil(t, result)
	require.Error(t, err)
}

// ---------------------------------------------------------------------------
// ListUsers tests
// ---------------------------------------------------------------------------

// 17. ListUsers success with multiple users.
func TestListUsers_Success(t *testing.T) {
	t.Parallel()
	repo := &mockUserRepository{}
	pw := &mockPasswordService{}
	totpSvc := &mockTOTPService{}
	svc := newService(repo, pw, totpSvc)

	users := []model.User{
		{ID: uuid.New(), Username: "alice", Roles: []string{model.RoleAdmin}},
		{ID: uuid.New(), Username: "bob", Roles: []string{model.RoleUser}},
	}
	repo.On("List", mock.Anything).Return(users, nil)

	result, err := svc.ListUsers(context.Background())

	require.NoError(t, err)
	assert.Len(t, result, 2)
}

// 18. ListUsers returns empty slice.
func TestListUsers_Empty(t *testing.T) {
	t.Parallel()
	repo := &mockUserRepository{}
	pw := &mockPasswordService{}
	totpSvc := &mockTOTPService{}
	svc := newService(repo, pw, totpSvc)

	repo.On("List", mock.Anything).Return([]model.User{}, nil)

	result, err := svc.ListUsers(context.Background())

	require.NoError(t, err)
	assert.Empty(t, result)
}

// ---------------------------------------------------------------------------
// DeleteUser tests
// ---------------------------------------------------------------------------

// 19. DeleteUser success.
func TestDeleteUser_Success(t *testing.T) {
	t.Parallel()
	repo := &mockUserRepository{}
	pw := &mockPasswordService{}
	totpSvc := &mockTOTPService{}
	svc := newService(repo, pw, totpSvc)

	userID := uuid.New()
	repo.On("Delete", mock.Anything, userID).Return(nil)

	err := svc.DeleteUser(context.Background(), userID)
	require.NoError(t, err)
}

// 20. DeleteUser repo delete fails.
func TestDeleteUser_RepoFails(t *testing.T) {
	t.Parallel()
	repo := &mockUserRepository{}
	pw := &mockPasswordService{}
	totpSvc := &mockTOTPService{}
	svc := newService(repo, pw, totpSvc)

	userID := uuid.New()
	repo.On("Delete", mock.Anything, userID).Return(errors.New("constraint error"))

	err := svc.DeleteUser(context.Background(), userID)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to delete user")
}

// ---------------------------------------------------------------------------
// ValidateBootstrapToken tests
// ---------------------------------------------------------------------------

// 21. ValidateBootstrapToken returns true for valid token.
func TestValidateBootstrapToken_Valid(t *testing.T) {
	t.Parallel()
	repo := &mockUserRepository{}
	pw := &mockPasswordService{}
	totpSvc := &mockTOTPService{}
	svc := newService(repo, pw, totpSvc)

	repo.On("ValidateBootstrapToken", mock.Anything, "secret-token").Return(true, nil)

	ok, err := svc.ValidateBootstrapToken(context.Background(), "secret-token")

	require.NoError(t, err)
	assert.True(t, ok)
}

// 22. ValidateBootstrapToken returns false for invalid/used token.
func TestValidateBootstrapToken_Invalid(t *testing.T) {
	t.Parallel()
	repo := &mockUserRepository{}
	pw := &mockPasswordService{}
	totpSvc := &mockTOTPService{}
	svc := newService(repo, pw, totpSvc)

	repo.On("ValidateBootstrapToken", mock.Anything, "used-token").Return(false, nil)

	ok, err := svc.ValidateBootstrapToken(context.Background(), "used-token")

	require.NoError(t, err)
	assert.False(t, ok)
}

// ---------------------------------------------------------------------------
// InvalidateBootstrapToken tests
// ---------------------------------------------------------------------------

// 23. InvalidateBootstrapToken success.
func TestInvalidateBootstrapToken_Success(t *testing.T) {
	t.Parallel()
	repo := &mockUserRepository{}
	pw := &mockPasswordService{}
	totpSvc := &mockTOTPService{}
	svc := newService(repo, pw, totpSvc)

	repo.On("InvalidateBootstrapToken", mock.Anything, "secret-token").Return(nil)

	err := svc.InvalidateBootstrapToken(context.Background(), "secret-token")
	require.NoError(t, err)
}

// 24. InvalidateBootstrapToken propagates error.
func TestInvalidateBootstrapToken_Error(t *testing.T) {
	t.Parallel()
	repo := &mockUserRepository{}
	pw := &mockPasswordService{}
	totpSvc := &mockTOTPService{}
	svc := newService(repo, pw, totpSvc)

	repo.On("InvalidateBootstrapToken", mock.Anything, "bad-token").Return(errors.New("db error"))

	err := svc.InvalidateBootstrapToken(context.Background(), "bad-token")
	require.Error(t, err)
}

// ---------------------------------------------------------------------------
// Additional all-valid-roles coverage for UpdateUser role validation.
// ---------------------------------------------------------------------------

func TestUpdateUser_AllValidRoles_Accepted(t *testing.T) {
	t.Parallel()

	for _, role := range model.ValidRoles {
		role := role // capture
		t.Run(role, func(t *testing.T) {
			t.Parallel()
			repo := &mockUserRepository{}
			pw := &mockPasswordService{}
			totpSvc := &mockTOTPService{}
			svc := newService(repo, pw, totpSvc)

			userID := uuid.New()
			existing := &model.User{ID: userID, Username: "alice", Roles: []string{model.RoleUser}}
			repo.On("Read", mock.Anything, userID).Return(existing, nil)
			repo.On("Update", mock.Anything, mock.AnythingOfType("*model.User")).Return(nil)

			req := UpdateUserRequest{
				UserID:      userID,
				CallerRoles: []string{model.RoleAdmin},
				Roles:       []string{role},
			}
			_, err := svc.UpdateUser(context.Background(), req)
			require.NoError(t, err)
		})
	}
}

// ---------------------------------------------------------------------------
// FindOrCreateExternalUser tests
// ---------------------------------------------------------------------------

func TestFindOrCreateExternalUser_ExistingUser_ReturnsIt(t *testing.T) {
	repo := &mockUserRepository{}
	existing := &model.User{ID: uuid.New(), Username: "existing", AuthProvider: model.AuthProviderOIDC, ExternalIDPSubject: "sub-1"}
	repo.On("ReadByExternalSubject", mock.Anything, model.AuthProviderOIDC, "sub-1").Return(existing, nil)

	svc := NewUserService(UserServiceConfig{UserRepository: repo, Logger: testLogger()})

	got, err := svc.FindOrCreateExternalUser(context.Background(), FindOrCreateExternalUserRequest{
		Provider: model.AuthProviderOIDC, Subject: "sub-1", PreferredUsername: "existing",
	})
	require.NoError(t, err)
	assert.Equal(t, existing.ID, got.ID)
	repo.AssertNotCalled(t, "Create", mock.Anything, mock.Anything)
}

func TestFindOrCreateExternalUser_NewUser_CreatesWithDefaultRole(t *testing.T) {
	repo := &mockUserRepository{}
	repo.On("ReadByExternalSubject", mock.Anything, model.AuthProviderOIDC, "sub-2").
		Return(nil, errors.New("user not found"))
	repo.On("Create", mock.Anything, mock.MatchedBy(func(u *model.User) bool {
		return u.AuthProvider == model.AuthProviderOIDC && u.ExternalIDPSubject == "sub-2" &&
			len(u.Roles) == 1 && u.Roles[0] == model.RoleUser && u.PasswordHash == "" && u.TOTPSecret == ""
	})).Return(nil)

	svc := NewUserService(UserServiceConfig{UserRepository: repo, Logger: testLogger()})

	got, err := svc.FindOrCreateExternalUser(context.Background(), FindOrCreateExternalUserRequest{
		Provider: model.AuthProviderOIDC, Subject: "sub-2", PreferredUsername: "new-user",
	})
	require.NoError(t, err)
	assert.ElementsMatch(t, []string{model.RoleUser}, got.Roles)
	repo.AssertExpectations(t)
}

func TestFindOrCreateExternalUser_NewUser_GetsLeastPrivilegeRole(t *testing.T) {
	t.Parallel()
	repo := &mockUserRepository{}
	pw := &mockPasswordService{}
	totpSvc := &mockTOTPService{}
	svc := newService(repo, pw, totpSvc)

	repo.On("ReadByExternalSubject", mock.Anything, "oidc", "sub-123").
		Return(nil, errors.New("not found"))
	repo.On("Create", mock.Anything, mock.MatchedBy(func(u *model.User) bool {
		return assert.ObjectsAreEqualValues([]string{model.RoleUser}, u.Roles)
	})).Return(nil)

	user, err := svc.FindOrCreateExternalUser(context.Background(), FindOrCreateExternalUserRequest{
		Provider:          "oidc",
		Subject:           "sub-123",
		PreferredUsername: "newoidcuser",
	})
	require.NoError(t, err)
	assert.ElementsMatch(t, []string{model.RoleUser}, user.Roles)
}

func TestFindOrCreateExternalUser_UsernameCollision_Suffixes(t *testing.T) {
	repo := &mockUserRepository{}
	repo.On("ReadByExternalSubject", mock.Anything, model.AuthProviderOIDC, "sub-3").
		Return(nil, errors.New("user not found"))
	// First Create attempt collides on username; service must retry with a
	// disambiguated username rather than failing the login outright.
	repo.On("Create", mock.Anything, mock.MatchedBy(func(u *model.User) bool { return u.Username == "taken" })).
		Return(errors.New("username already exists")).Once()
	repo.On("Create", mock.Anything, mock.MatchedBy(func(u *model.User) bool { return u.Username != "taken" })).
		Return(nil).Once()

	svc := NewUserService(UserServiceConfig{UserRepository: repo, Logger: testLogger()})

	got, err := svc.FindOrCreateExternalUser(context.Background(), FindOrCreateExternalUserRequest{
		Provider: model.AuthProviderOIDC, Subject: "sub-3", PreferredUsername: "taken",
	})
	require.NoError(t, err)
	assert.NotEqual(t, "taken", got.Username)
	repo.AssertExpectations(t)
}

// ---------------------------------------------------------------------------
// Reserved system user guard
// ---------------------------------------------------------------------------

// The row at model.SystemUserID is not an account: it exists so the `keys`
// table's foreign key is satisfiable for SelfPKIProvider's JWT signing key.
// Deleting it cascades that key away on Postgres; updating it hands the
// reserved row a real password and role. Neither must reach the repository.
func TestDeleteUser_SystemUser_Refused(t *testing.T) {
	t.Parallel()
	repo := &mockUserRepository{}
	svc := newService(repo, &mockPasswordService{}, &mockTOTPService{})

	err := svc.DeleteUser(context.Background(), uuid.MustParse(model.SystemUserID))

	require.Error(t, err)
	assert.Contains(t, err.Error(), "reserved system user")
	repo.AssertNotCalled(t, "Delete", mock.Anything, mock.Anything)
}

func TestUpdateUser_SystemUser_Refused(t *testing.T) {
	t.Parallel()
	repo := &mockUserRepository{}
	svc := newService(repo, &mockPasswordService{}, &mockTOTPService{})

	newName := "attacker"
	_, err := svc.UpdateUser(context.Background(), UpdateUserRequest{
		UserID:      uuid.MustParse(model.SystemUserID),
		CallerRoles: []string{model.RoleAdmin},
		Username:    &newName,
	})

	require.Error(t, err)
	assert.Contains(t, err.Error(), "reserved system user")
	repo.AssertNotCalled(t, "Read", mock.Anything, mock.Anything)
	repo.AssertNotCalled(t, "Update", mock.Anything, mock.Anything)
}

// A normal user id must still pass the guard untouched.
func TestDeleteUser_OrdinaryUser_Allowed(t *testing.T) {
	t.Parallel()
	repo := &mockUserRepository{}
	id := uuid.New()
	repo.On("Delete", mock.Anything, id).Return(nil)
	svc := newService(repo, &mockPasswordService{}, &mockTOTPService{})

	require.NoError(t, svc.DeleteUser(context.Background(), id))
	repo.AssertExpectations(t)
}

// ---------------------------------------------------------------------------
// TOTP enrollment on password set (B73)
// ---------------------------------------------------------------------------

func TestUpdateUser_PasswordOnAccountWithoutTOTP_EnrollsSecret(t *testing.T) {
	t.Parallel()
	repo := &mockUserRepository{}
	pw := &mockPasswordService{}
	totpSvc := &mockTOTPService{}
	svc := newService(repo, pw, totpSvc)

	userID := uuid.New()
	existing := &model.User{
		ID:           userID,
		Username:     "oidc-alice",
		Roles:        []string{model.RoleUser},
		AuthProvider: model.AuthProviderOIDC,
		TOTPSecret:   "",
	}
	key := realTOTPKey(t)
	repo.On("Read", mock.Anything, userID).Return(existing, nil)
	pw.On("HashPassword", "newpass123").Return("hashed-new", nil)
	totpSvc.On("GenerateSecret", "PasswordManager", "oidc-alice").Return(key, nil)
	repo.On("Update", mock.Anything, mock.MatchedBy(func(u *model.User) bool {
		return u.PasswordHash == "hashed-new" && u.TOTPSecret == key.Secret()
	})).Return(nil)

	newPw := "newpass123"
	result, err := svc.UpdateUser(context.Background(), UpdateUserRequest{
		UserID:      userID,
		CallerID:    userID,
		CallerRoles: []string{model.RoleUser},
		Password:    &newPw,
	})

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, key.URL(), result.TOTPEnrollmentURL)
	assert.Contains(t, result.TOTPEnrollmentURL, "otpauth://totp/")
	repo.AssertExpectations(t)
	totpSvc.AssertExpectations(t)
}

func TestUpdateUser_PasswordOnEnrolledAccount_KeepsSecret(t *testing.T) {
	t.Parallel()
	repo := &mockUserRepository{}
	pw := &mockPasswordService{}
	totpSvc := &mockTOTPService{}
	svc := newService(repo, pw, totpSvc)

	userID := uuid.New()
	existing := &model.User{ID: userID, Username: "bob", Roles: []string{model.RoleUser}, TOTPSecret: "EXISTINGSECRET"}
	repo.On("Read", mock.Anything, userID).Return(existing, nil)
	pw.On("HashPassword", "newpass123").Return("hashed-new", nil)
	repo.On("Update", mock.Anything, mock.MatchedBy(func(u *model.User) bool {
		return u.PasswordHash == "hashed-new" && u.TOTPSecret == "EXISTINGSECRET"
	})).Return(nil)

	newPw := "newpass123"
	result, err := svc.UpdateUser(context.Background(), UpdateUserRequest{
		UserID: userID, CallerID: userID, CallerRoles: []string{model.RoleUser}, Password: &newPw,
	})

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Empty(t, result.TOTPEnrollmentURL)
	totpSvc.AssertNotCalled(t, "GenerateSecret", mock.Anything, mock.Anything)
	repo.AssertExpectations(t)
}

func TestUpdateUser_UsernameOnlyOnAccountWithoutTOTP_DoesNotEnroll(t *testing.T) {
	t.Parallel()
	repo := &mockUserRepository{}
	totpSvc := &mockTOTPService{}
	svc := newService(repo, &mockPasswordService{}, totpSvc)

	userID := uuid.New()
	existing := &model.User{ID: userID, Username: "oidc-carol", Roles: []string{model.RoleUser}, TOTPSecret: ""}
	repo.On("Read", mock.Anything, userID).Return(existing, nil)
	repo.On("Update", mock.Anything, mock.MatchedBy(func(u *model.User) bool {
		return u.Username == "carol2" && u.TOTPSecret == ""
	})).Return(nil)

	newName := "carol2"
	result, err := svc.UpdateUser(context.Background(), UpdateUserRequest{
		UserID: userID, CallerRoles: []string{model.RoleUser}, Username: &newName,
	})

	require.NoError(t, err)
	assert.Empty(t, result.TOTPEnrollmentURL)
	totpSvc.AssertNotCalled(t, "GenerateSecret", mock.Anything, mock.Anything)
}

func TestUpdateUser_EnrollmentSecretGenerationFails(t *testing.T) {
	t.Parallel()
	repo := &mockUserRepository{}
	pw := &mockPasswordService{}
	totpSvc := &mockTOTPService{}
	svc := newService(repo, pw, totpSvc)

	userID := uuid.New()
	existing := &model.User{ID: userID, Username: "oidc-dave", Roles: []string{model.RoleUser}}
	repo.On("Read", mock.Anything, userID).Return(existing, nil)
	pw.On("HashPassword", "newpass123").Return("hashed-new", nil)
	totpSvc.On("GenerateSecret", "PasswordManager", "oidc-dave").Return(nil, errors.New("rng failure"))

	newPw := "newpass123"
	result, err := svc.UpdateUser(context.Background(), UpdateUserRequest{
		UserID: userID, CallerRoles: []string{model.RoleUser}, Password: &newPw,
	})

	require.Error(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "failed to generate TOTP secret")
	repo.AssertNotCalled(t, "Update", mock.Anything, mock.Anything)
}

// recordingPersister captures every audit record the service writes.
type recordingPersister struct {
	records []string
}

func (p *recordingPersister) PersistAudit(userID, action, details string) error {
	p.records = append(p.records, userID+" "+action+" "+details)
	return nil
}

// The generated secret is a credential, so neither the audit log nor the
// persisted audit records may carry the secret or its otpauth URL.
func TestUpdateUser_Enrollment_NeverLogsOrAuditsSecret(t *testing.T) {
	t.Parallel()
	repo := &mockUserRepository{}
	pw := &mockPasswordService{}
	totpSvc := &mockTOTPService{}

	var logBuf bytes.Buffer
	base := logrus.New()
	base.SetOutput(&logBuf)
	logger := &logging.Logger{Logger: base}
	persister := &recordingPersister{}
	logger.SetAuditPersister(persister)
	svc := NewUserService(UserServiceConfig{
		UserRepository:  repo,
		PasswordService: pw,
		TOTPService:     totpSvc,
		Logger:          logger,
	})

	userID := uuid.New()
	existing := &model.User{ID: userID, Username: "oidc-erin", Roles: []string{model.RoleUser}}
	key := realTOTPKey(t)
	repo.On("Read", mock.Anything, userID).Return(existing, nil)
	pw.On("HashPassword", "newpass123").Return("hashed-new", nil)
	totpSvc.On("GenerateSecret", "PasswordManager", "oidc-erin").Return(key, nil)
	repo.On("Update", mock.Anything, mock.Anything).Return(nil)

	newPw := "newpass123"
	result, err := svc.UpdateUser(context.Background(), UpdateUserRequest{
		UserID: userID, CallerID: userID, CallerRoles: []string{model.RoleUser}, Password: &newPw,
	})

	require.NoError(t, err)
	require.NotEmpty(t, result.TOTPEnrollmentURL)
	require.NotEmpty(t, persister.records, "the enrollment must still be audited")
	assert.Contains(t, logBuf.String(), "enroll_totp")
	assert.NotContains(t, logBuf.String(), key.Secret())
	for _, rec := range persister.records {
		assert.NotContains(t, rec, key.Secret())
		assert.NotContains(t, rec, "otpauth://")
	}
}
