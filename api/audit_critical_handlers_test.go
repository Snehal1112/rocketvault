package api

// Audit-first handler tests: a token, a session, a signing-key rotation or a
// service-account change must not happen unless its critical audit row was
// written, and the response never carries the underlying audit error.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"rocketvault/app"
	auditServices "rocketvault/internal/services/audit"
	authServices "rocketvault/internal/services/auth"
	oauth2Services "rocketvault/internal/services/oauth2"
	"rocketvault/internal/testutils"
	"rocketvault/model"
)

// handlerAuditCause is the underlying failure text that must never reach a client.
const handlerAuditCause = "pq: could not extend file audit_logs"

// failingCriticalAudit returns an audit mock whose critical writes fail and
// whose plain events succeed.
func failingCriticalAudit() *testutils.MockAuditService {
	m := &testutils.MockAuditService{}
	m.On("RecordCritical", mock.Anything, mock.Anything).Return(errors.New(handlerAuditCause))
	m.On("RecordEvent", mock.Anything, mock.Anything).Return(nil)
	return m
}

// assertAuditUnavailableBody checks the 503 contract shared by every handler.
func assertAuditUnavailableBody(t *testing.T, w *httptest.ResponseRecorder) {
	t.Helper()
	assert.Equal(t, http.StatusServiceUnavailable, w.Code)
	assert.Contains(t, w.Body.String(), "audit unavailable")
	assert.NotContains(t, w.Body.String(), handlerAuditCause)
}

func newTokenRequest() *http.Request {
	body := strings.NewReader("grant_type=client_credentials&client_id=good_client&client_secret=good_sec")
	r := httptest.NewRequest(http.MethodPost, "/oauth2/token", body)
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return r
}

func TestTokenHandler_AuditUnavailable_Returns503WithoutToken(t *testing.T) {
	svc := &mockOAuth2Svc{}
	svc.On("IssueToken", mock.Anything, "good_client", "good_sec").Return(&oauth2Services.TokenResponse{
		AccessToken: "minted-jwt-value", TokenType: "Bearer", ExpiresIn: 3600,
	}, nil)
	mockAudit := failingCriticalAudit()
	api := &API{App: &app.App{ServiceContainer: &oauth2HTestContainer{svc: svc, auditSvc: mockAudit}}, Logger: userTestLog()}
	w := httptest.NewRecorder()

	api.tokenHandler(w, newTokenRequest())

	assertAuditUnavailableBody(t, w)
	assert.NotContains(t, w.Body.String(), "access_token")
	assert.NotContains(t, w.Body.String(), "minted-jwt-value")
	assert.Equal(t, "no-store", w.Header().Get("Cache-Control"))
	mockAudit.AssertNotCalled(t, "RecordEvent", mock.Anything, mock.MatchedBy(func(e auditServices.AuditEvent) bool {
		return e.Outcome == "success"
	}))
}

func TestTokenHandler_AuditAttemptPrecedesToken(t *testing.T) {
	svc := &mockOAuth2Svc{}
	svc.On("IssueToken", mock.Anything, "good_client", "good_sec").Return(&oauth2Services.TokenResponse{
		AccessToken: "tok", TokenType: "Bearer", ExpiresIn: 3600,
	}, nil)
	mockAudit := &testutils.MockAuditService{}
	attempt := mockAudit.On("RecordCritical", mock.Anything, mock.MatchedBy(func(e auditServices.AuditEvent) bool {
		return e.Action == "oauth2_token_issue" && e.Outcome == "attempt" && e.ResourceID == "good_client"
	})).Return(nil)
	mockAudit.On("RecordEvent", mock.Anything, mock.MatchedBy(func(e auditServices.AuditEvent) bool {
		return e.Action == "oauth2_token_issue" && e.Outcome == "success"
	})).Return(nil).NotBefore(attempt)
	api := &API{App: &app.App{ServiceContainer: &oauth2HTestContainer{svc: svc, auditSvc: mockAudit}}, Logger: userTestLog()}
	w := httptest.NewRecorder()

	api.tokenHandler(w, newTokenRequest())

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "access_token")
	mockAudit.AssertExpectations(t)
}

func TestTokenHandler_AuditBadCredentials_StaysPlainEvent(t *testing.T) {
	svc := &mockOAuth2Svc{}
	svc.On("IssueToken", mock.Anything, "good_client", "good_sec").Return(nil, errors.New("invalid client credentials"))
	mockAudit := failingCriticalAudit()
	api := &API{App: &app.App{ServiceContainer: &oauth2HTestContainer{svc: svc, auditSvc: mockAudit}}, Logger: userTestLog()}
	w := httptest.NewRecorder()

	api.tokenHandler(w, newTokenRequest())

	assert.Equal(t, http.StatusUnauthorized, w.Code)
	assert.Contains(t, w.Body.String(), "invalid_client")
	mockAudit.AssertNotCalled(t, "RecordCritical", mock.Anything, mock.Anything)
	mockAudit.AssertCalled(t, "RecordEvent", mock.Anything, mock.MatchedBy(func(e auditServices.AuditEvent) bool {
		return e.Action == "oauth2_token_issue" && e.Outcome == "failure"
	}))
}

func TestLoginUser_AuditUnavailable_Returns503(t *testing.T) {
	// Build the real error the service returns when the attempt row fails.
	auditErr := auditServices.WithCritical(context.Background(), failingCriticalAudit(),
		auditServices.AuditEvent{Action: "authenticate_user"},
		func(context.Context) error { return nil })
	require.ErrorIs(t, auditErr, auditServices.ErrAuditUnavailable)

	authSvc := &mockAuthService{}
	authSvc.On("AuthenticateUser", mock.Anything, "alice", "goodpass", "123456").Return(nil, auditErr)
	c := newUserCtx(nil, authSvc, RequestClaims{})
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/users/login", encodeBody(map[string]string{
		"username": "alice", "password": "goodpass", "totp_code": "123456",
	}))

	loginUser(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assertAuditUnavailableBody(t, w)
	assert.NotContains(t, w.Body.String(), "token")
}

func TestRotateJWKS_AuditUnavailable_DoesNotRotate(t *testing.T) {
	provider := &rotatableStubProvider{rotateKID: "new-kid", rotateUntil: "2026-01-01T00:00:00Z"}
	mockAudit := failingCriticalAudit()
	c := newJWKSAdminCtx(provider)
	c.App.ServiceContainer.(*jwkContainerBase).auditSvc = mockAudit
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/api/v1/jwks/rotate", nil)

	rotateJWKS(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assertAuditUnavailableBody(t, w)
	assert.Zero(t, provider.rotateCalls, "the signing key must not rotate without an audit row")
	assert.NotContains(t, w.Body.String(), "new-kid")
}

func TestRotateJWKS_AuditAttemptPrecedesRotation(t *testing.T) {
	provider := &rotatableStubProvider{rotateKID: "new-kid", rotateUntil: "2026-01-01T00:00:00Z"}
	mockAudit := &testutils.MockAuditService{}
	attempt := mockAudit.On("RecordCritical", mock.Anything, mock.MatchedBy(func(e auditServices.AuditEvent) bool {
		return e.Action == "jwks_rotate" && e.Outcome == "attempt" && provider.rotateCalls == 0
	})).Return(nil)
	mockAudit.On("RecordEvent", mock.Anything, mock.MatchedBy(func(e auditServices.AuditEvent) bool {
		return e.Action == "jwks_rotate" && e.Outcome == "success" && e.ResourceID == "new-kid"
	})).Return(nil).NotBefore(attempt)
	c := newJWKSAdminCtx(provider)
	c.App.ServiceContainer.(*jwkContainerBase).auditSvc = mockAudit
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/api/v1/jwks/rotate", nil)

	rotateJWKS(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, 1, provider.rotateCalls)
	mockAudit.AssertExpectations(t)
}

// The public JWKS document is a read-only publication, so it stays up when
// audit is down.
func TestGetJWKS_AuditUnavailable_StillServes(t *testing.T) {
	provider := &rotatableStubProvider{}
	mockAudit := failingCriticalAudit()
	c := newJWKSCtx(provider)
	c.App.ServiceContainer.(*jwkContainerBase).auditSvc = mockAudit
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/jwks.json", nil)

	getJWKS(c, w, r)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "keys")
	mockAudit.AssertNotCalled(t, "RecordCritical", mock.Anything, mock.Anything)
}

func TestCreateSA_AuditUnavailable_DoesNotCreate(t *testing.T) {
	svc := &mockOAuth2Svc{}
	c := newOAuth2HCtx(svc)
	c.App.ServiceContainer.(*oauth2HTestContainer).auditSvc = failingCriticalAudit()
	w := httptest.NewRecorder()
	body, _ := json.Marshal(map[string]any{"name": "svcname"})
	r := httptest.NewRequest(http.MethodPost, "/service-accounts", bytes.NewReader(body))

	createServiceAccount(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assertAuditUnavailableBody(t, w)
	assert.NotContains(t, w.Body.String(), "client_secret")
	svc.AssertNotCalled(t, "CreateClient", mock.Anything, mock.Anything, mock.Anything, mock.Anything)
}

func TestCreateSA_AuditAttemptPrecedesCreate(t *testing.T) {
	svc := &mockOAuth2Svc{}
	clientID := uuid.New()
	svc.On("CreateClient", mock.Anything, "svcname", "", (*time.Time)(nil)).Return(&model.OAuth2Client{
		ID: clientID, Name: "svcname", Enabled: true, CreatedAt: time.Now(),
	}, "plain-secret", nil)
	mockAudit := &testutils.MockAuditService{}
	attempt := mockAudit.On("RecordCritical", mock.Anything, mock.MatchedBy(func(e auditServices.AuditEvent) bool {
		return e.Action == "service_account_create" && e.Outcome == "attempt"
	})).Return(nil)
	mockAudit.On("RecordEvent", mock.Anything, mock.MatchedBy(func(e auditServices.AuditEvent) bool {
		return e.Action == "service_account_create" && e.Outcome == "success" && e.ResourceID == clientID.String()
	})).Return(nil).NotBefore(attempt)
	c := newOAuth2HCtx(svc)
	c.App.ServiceContainer.(*oauth2HTestContainer).auditSvc = mockAudit
	w := httptest.NewRecorder()
	body, _ := json.Marshal(map[string]any{"name": "svcname"})
	r := httptest.NewRequest(http.MethodPost, "/service-accounts", bytes.NewReader(body))

	createServiceAccount(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusCreated, w.Code)
	mockAudit.AssertExpectations(t)
}

func TestDeleteSA_AuditUnavailable_DoesNotDelete(t *testing.T) {
	svc := &mockOAuth2Svc{}
	saID := uuid.New()
	c := newOAuth2HCtx(svc)
	c.App.ServiceContainer.(*oauth2HTestContainer).auditSvc = failingCriticalAudit()
	c.Params.ServiceAccountID = saID.String()
	w := httptest.NewRecorder()
	r := mux.SetURLVars(httptest.NewRequest(http.MethodDelete, "/service-accounts/"+saID.String(), nil),
		map[string]string{"service_account_id": saID.String()})

	deleteServiceAccount(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assertAuditUnavailableBody(t, w)
	svc.AssertNotCalled(t, "DeleteClient", mock.Anything, mock.Anything)
}

func TestRotateSASecret_AuditUnavailable_DoesNotRotate(t *testing.T) {
	svc := &mockOAuth2Svc{}
	saID := uuid.New()
	c := newOAuth2HCtx(svc)
	c.App.ServiceContainer.(*oauth2HTestContainer).auditSvc = failingCriticalAudit()
	c.Params.ServiceAccountID = saID.String()
	w := httptest.NewRecorder()
	r := mux.SetURLVars(httptest.NewRequest(http.MethodPost, "/service-accounts/"+saID.String()+"/rotate", nil),
		map[string]string{"service_account_id": saID.String()})

	rotateServiceAccountSecret(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assertAuditUnavailableBody(t, w)
	assert.NotContains(t, w.Body.String(), "client_secret")
	svc.AssertNotCalled(t, "RotateSecret", mock.Anything, mock.Anything)
}

// realAuditUnavailableErr builds the error a service returns when the
// attempt row cannot be written.
func realAuditUnavailableErr(t *testing.T) error {
	t.Helper()
	err := auditServices.WithCritical(context.Background(), failingCriticalAudit(),
		auditServices.AuditEvent{Action: "test"}, func(context.Context) error { return nil })
	require.ErrorIs(t, err, auditServices.ErrAuditUnavailable)
	return err
}

func TestRefreshToken_AuditUnavailable_Returns503(t *testing.T) {
	authSvc := &mockAuthService{}
	authSvc.On("RefreshAccessToken", mock.Anything, "validtoken").Return(nil, realAuditUnavailableErr(t))
	c := newUserCtx(nil, authSvc, RequestClaims{})
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/users/refresh", encodeBody(map[string]string{
		"refresh_token": "validtoken",
	}))

	refreshToken(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assertAuditUnavailableBody(t, w)
	assert.NotContains(t, w.Body.String(), "token\"")
}

func TestOIDCCallback_AuditUnavailable_Returns503(t *testing.T) {
	identity := &authServices.OIDCIdentity{Subject: "sub-1", PreferredUsername: "jdoe"}
	oidcSvc := &mockOIDCService{}
	oidcSvc.On("HandleCallback", mock.Anything, "auth-code", "nonce-1", "verifier-1").Return(identity, nil)
	user := &model.User{ID: uuid.New(), Username: "jdoe", Roles: []string{model.RoleUser}}
	userSvc := &mockUserServiceForOIDC{}
	userSvc.On("FindOrCreateExternalUser", mock.Anything, mock.Anything).Return(user, nil)
	authSvc := &mockAuthServiceForOIDC{}
	authSvc.On("IssueSessionForUser", mock.Anything, user).Return(nil, realAuditUnavailableErr(t))
	api := newOIDCHAPI(oidcSvc, userSvc, authSvc)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/oidc/callback?state=expected&code=auth-code", nil)
	r.AddCookie(&http.Cookie{Name: "oidc_state", Value: "expected"})
	r.AddCookie(&http.Cookie{Name: "oidc_nonce", Value: "nonce-1"})
	r.AddCookie(&http.Cookie{Name: "oidc_pkce", Value: "verifier-1"})

	api.oidcCallbackHandler(w, r)

	assertAuditUnavailableBody(t, w)
	assert.NotContains(t, w.Body.String(), "token")
}
