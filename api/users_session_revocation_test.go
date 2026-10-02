package api

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	authServices "rocketvault/internal/services/auth"
	userServices "rocketvault/internal/services/users"
	"rocketvault/internal/testutils"
	"rocketvault/model"
)

// recordingRevoker records which users had their sessions revoked.
type recordingRevoker struct {
	revoked []uuid.UUID
	err     error
}

func (r *recordingRevoker) RevokeAllUserSessions(_ context.Context, userID uuid.UUID, _ string) error {
	if r.err != nil {
		return r.err
	}
	r.revoked = append(r.revoked, userID)
	return nil
}

// newRevokingUserService builds a real UserService over a mocked repository
// that holds one enrolled user, so the HTTP path runs the real revocation.
func newRevokingUserService(t *testing.T, userID uuid.UUID, revoker *recordingRevoker) userServices.UserService {
	t.Helper()
	repo := &testutils.MockUserRepository{}
	repo.On("Read", mock.Anything, userID).Return(&model.User{
		ID: userID, Username: "alice", PasswordHash: "old", TOTPSecret: "SECRET", Roles: []string{model.RoleUser},
	}, nil)
	repo.On("Update", mock.Anything, mock.Anything).Return(nil)
	return userServices.NewUserService(userServices.UserServiceConfig{
		UserRepository:  repo,
		PasswordService: authServices.NewPasswordService(),
		TOTPService:     authServices.NewTOTPService(),
		SessionRevoker:  revoker,
		Logger:          userTestLog(),
	})
}

// A user changing their own password over HTTP loses every session, including
// the one that made the request, the same as on the CLI (B74).
func TestUpdateUser_SelfPasswordChange_RevokesOwnSessions(t *testing.T) {
	userID := uuid.New()
	revoker := &recordingRevoker{}
	c := newUserCtx(newRevokingUserService(t, userID, revoker), nil, uViewerClaims(userID.String()))
	c.Params = &ApiParams{UserID: userID.String(), PerPage: 60}
	w := httptest.NewRecorder()
	r := httptest.NewRequestWithContext(context.Background(), http.MethodPut, "/users/"+userID.String(),
		encodeBody(map[string]string{"password": "newpass123"}))

	updateUser(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	require.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, []uuid.UUID{userID}, revoker.revoked)
}

// A failed revocation fails the request, so the caller never sees a success
// that left old sessions alive.
func TestUpdateUser_RevocationFails_Returns500(t *testing.T) {
	userID := uuid.New()
	revoker := &recordingRevoker{err: errors.New("db error")}
	c := newUserCtx(newRevokingUserService(t, userID, revoker), nil, uViewerClaims(userID.String()))
	c.Params = &ApiParams{UserID: userID.String(), PerPage: 60}
	w := httptest.NewRecorder()
	r := httptest.NewRequestWithContext(context.Background(), http.MethodPut, "/users/"+userID.String(),
		encodeBody(map[string]string{"password": "newpass123"}))

	updateUser(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}
