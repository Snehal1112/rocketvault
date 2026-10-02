package oauth2_test

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"rocketvault/common"
	"rocketvault/internal/repositories"
	oauth2svc "rocketvault/internal/services/oauth2"
	"rocketvault/model"
)

// --- mock repo ---

type mockOAuth2ClientRepo struct{ mock.Mock }

func (m *mockOAuth2ClientRepo) Create(ctx context.Context, c *model.OAuth2Client) error {
	return m.Called(ctx, c).Error(0)
}
func (m *mockOAuth2ClientRepo) GetByID(ctx context.Context, id uuid.UUID) (*model.OAuth2Client, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*model.OAuth2Client), args.Error(1)
}
func (m *mockOAuth2ClientRepo) FindByName(ctx context.Context, name string) (*model.OAuth2Client, error) {
	args := m.Called(ctx, name)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*model.OAuth2Client), args.Error(1)
}
func (m *mockOAuth2ClientRepo) List(ctx context.Context) ([]*model.OAuth2Client, error) {
	args := m.Called(ctx)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*model.OAuth2Client), args.Error(1)
}
func (m *mockOAuth2ClientRepo) Update(ctx context.Context, c *model.OAuth2Client) error {
	return m.Called(ctx, c).Error(0)
}
func (m *mockOAuth2ClientRepo) Delete(ctx context.Context, id uuid.UUID) error {
	return m.Called(ctx, id).Error(0)
}

// compile-time check
var _ repositories.OAuth2ClientRepositoryInterface = (*mockOAuth2ClientRepo)(nil)

// --- mock password service ---

type mockPasswordService struct{ mock.Mock }

func (m *mockPasswordService) HashPassword(pw string) (string, error) {
	args := m.Called(pw)
	return args.String(0), args.Error(1)
}
func (m *mockPasswordService) ValidatePassword(pw, hash string) error {
	return m.Called(pw, hash).Error(0)
}

// --- mock JWT service ---

type mockJWTService struct{ mock.Mock }

func (m *mockJWTService) GenerateToken(userID uuid.UUID, username string, roles []string, sessionID uuid.UUID) (string, error) {
	args := m.Called(userID, username, roles, sessionID)
	return args.String(0), args.Error(1)
}

// --- helper ---

func buildService(repo *mockOAuth2ClientRepo, pw *mockPasswordService, jwt *mockJWTService) oauth2svc.OAuth2Service {
	return oauth2svc.NewOAuth2Service(oauth2svc.OAuth2Config{
		ClientRepo:      repo,
		PasswordService: pw,
		JWTService:      jwt,
		TokenExpiry:     30 * time.Minute,
	})
}

// --- tests ---

func TestOAuth2Service_IssueToken_Success(t *testing.T) {
	repo := &mockOAuth2ClientRepo{}
	pw := &mockPasswordService{}
	jwt := &mockJWTService{}
	svc := buildService(repo, pw, jwt)

	clientID := uuid.New()
	client := &model.OAuth2Client{
		ID:        clientID,
		Name:      "my-app",
		Enabled:   true,
		CreatedAt: time.Now().UTC(),
	}

	repo.On("FindByName", mock.Anything, "my-app").Return(client, nil)
	pw.On("ValidatePassword", "plain-secret", client.ClientSecret).Return(nil)
	// jti must now be client.ID so ValidateSession can verify the client is active.
	jwt.On("GenerateToken", clientID, "my-app", []string{model.RoleServiceAccount}, clientID).Return("tok.en.str", nil)

	resp, err := svc.IssueToken(context.Background(), "my-app", "plain-secret")
	require.NoError(t, err)
	assert.Equal(t, "tok.en.str", resp.AccessToken)
	assert.Equal(t, "Bearer", resp.TokenType)
	assert.Equal(t, int(30*60), resp.ExpiresIn)

	// Assert the call site passes the service-account role as a single-element
	// slice, not a bare string — GenerateToken's claims-facing contract.
	jwt.AssertCalled(t, "GenerateToken", clientID, "my-app", []string{model.RoleServiceAccount}, clientID)
}

func TestOAuth2Service_IssueToken_ClientNotFound(t *testing.T) {
	repo := &mockOAuth2ClientRepo{}
	pw := &mockPasswordService{}
	jwt := &mockJWTService{}
	svc := buildService(repo, pw, jwt)

	repo.On("FindByName", mock.Anything, "ghost").Return(nil, errors.New("not found"))

	_, err := svc.IssueToken(context.Background(), "ghost", "secret")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid client credentials")
}

func TestOAuth2Service_IssueToken_WrongSecret(t *testing.T) {
	repo := &mockOAuth2ClientRepo{}
	pw := &mockPasswordService{}
	jwt := &mockJWTService{}
	svc := buildService(repo, pw, jwt)

	client := &model.OAuth2Client{ID: uuid.New(), Name: "svc", Enabled: true, CreatedAt: time.Now().UTC()}
	repo.On("FindByName", mock.Anything, "svc").Return(client, nil)
	pw.On("ValidatePassword", "wrong", client.ClientSecret).Return(errors.New("hash mismatch"))

	_, err := svc.IssueToken(context.Background(), "svc", "wrong")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid client credentials")
}

func TestOAuth2Service_IssueToken_DisabledClient(t *testing.T) {
	repo := &mockOAuth2ClientRepo{}
	pw := &mockPasswordService{}
	jwt := &mockJWTService{}
	svc := buildService(repo, pw, jwt)

	client := &model.OAuth2Client{ID: uuid.New(), Name: "disabled", Enabled: false, CreatedAt: time.Now().UTC()}
	repo.On("FindByName", mock.Anything, "disabled").Return(client, nil)

	_, err := svc.IssueToken(context.Background(), "disabled", "anything")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid client credentials") // generic — must not hint client exists
}

func TestOAuth2Service_CreateClient_HashesSecret(t *testing.T) {
	repo := &mockOAuth2ClientRepo{}
	pw := &mockPasswordService{}
	jwt := &mockJWTService{}
	svc := buildService(repo, pw, jwt)

	pw.On("HashPassword", mock.AnythingOfType("string")).Return("hashed-secret", nil)
	repo.On("Create", mock.Anything, mock.AnythingOfType("*model.OAuth2Client")).Return(nil)

	client, plainSecret, err := svc.CreateClient(context.Background(), "new-app", "a description", nil)
	require.NoError(t, err)
	assert.NotEmpty(t, plainSecret, "plain secret should be returned on creation")
	assert.Equal(t, "hashed-secret", client.ClientSecret)
	assert.Equal(t, "new-app", client.Name)
}

func TestOAuth2Service_IssueToken_ExpiredClient(t *testing.T) {
	repo := &mockOAuth2ClientRepo{}
	pw := &mockPasswordService{}
	jwt := &mockJWTService{}
	svc := buildService(repo, pw, jwt)

	past := time.Now().UTC().Add(-24 * time.Hour)
	client := &model.OAuth2Client{
		ID:        uuid.New(),
		Name:      "expired-svc",
		Enabled:   true,
		ExpiresAt: &past,
		CreatedAt: time.Now().UTC(),
	}
	repo.On("FindByName", mock.Anything, "expired-svc").Return(client, nil)

	_, err := svc.IssueToken(context.Background(), "expired-svc", "any-secret")
	assert.Error(t, err)
	// Must return the same generic message as wrong-secret to prevent enumeration.
	assert.Contains(t, err.Error(), "invalid client credentials")
}

func TestOAuth2Service_RotateSecret_ReturnsPlainText(t *testing.T) {
	repo := &mockOAuth2ClientRepo{}
	pw := &mockPasswordService{}
	jwt := &mockJWTService{}
	svc := buildService(repo, pw, jwt)

	clientID := uuid.New()
	existing := &model.OAuth2Client{ID: clientID, Name: "rotate-me", Enabled: true, CreatedAt: time.Now().UTC()}

	repo.On("GetByID", mock.Anything, clientID).Return(existing, nil)
	pw.On("HashPassword", mock.AnythingOfType("string")).Return("new-hash", nil)
	repo.On("Update", mock.Anything, mock.AnythingOfType("*model.OAuth2Client")).Return(nil)

	plain, err := svc.RotateSecret(context.Background(), clientID)
	require.NoError(t, err)
	assert.NotEmpty(t, plain)
}

// burnRecorder replaces the dummy bcrypt compare and records each secret it
// was asked to burn.
type burnRecorder struct {
	mu     sync.Mutex
	burned []string
}

func (b *burnRecorder) burn(secret string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.burned = append(b.burned, secret)
}

func (b *burnRecorder) calls() []string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]string(nil), b.burned...)
}

// Every rejection that skips the real secret compare must pay a dummy one,
// so timing cannot tell an unknown, disabled or expired client from a wrong
// secret. The error stays the uniform one.
func TestOAuth2Service_IssueToken_RejectionsBurnPasswordCompare(t *testing.T) {
	past := time.Now().UTC().Add(-time.Hour)
	cases := map[string]*model.OAuth2Client{
		"ghost":    nil,
		"disabled": {ID: uuid.New(), Name: "disabled", ClientSecret: "hash", Enabled: false},
		"expired":  {ID: uuid.New(), Name: "expired", ClientSecret: "hash", Enabled: true, ExpiresAt: &past},
	}
	for name, client := range cases {
		t.Run(name, func(t *testing.T) {
			repo := &mockOAuth2ClientRepo{}
			if client == nil {
				repo.On("FindByName", mock.Anything, name).Return(nil, errors.New("not found"))
			} else {
				repo.On("FindByName", mock.Anything, name).Return(client, nil)
			}
			pw := &mockPasswordService{}
			svc := buildService(repo, pw, &mockJWTService{})
			rec := &burnRecorder{}
			oauth2svc.SetBurnCompareForTest(svc, rec.burn)

			_, err := svc.IssueToken(context.Background(), name, "secret")

			require.Error(t, err)
			assert.Equal(t, "invalid client credentials", err.Error())
			assert.Equal(t, []string{"secret"}, rec.calls())
			pw.AssertNotCalled(t, "ValidatePassword")
		})
	}
}

// A wrong secret already pays the real compare and must not burn a second.
func TestOAuth2Service_IssueToken_WrongSecretDoesNotBurn(t *testing.T) {
	repo := &mockOAuth2ClientRepo{}
	pw := &mockPasswordService{}
	svc := buildService(repo, pw, &mockJWTService{})
	rec := &burnRecorder{}
	oauth2svc.SetBurnCompareForTest(svc, rec.burn)

	client := &model.OAuth2Client{ID: uuid.New(), Name: "svc", ClientSecret: "hash", Enabled: true}
	repo.On("FindByName", mock.Anything, "svc").Return(client, nil)
	pw.On("ValidatePassword", "wrong", "hash").Return(errors.New("hash mismatch"))

	_, err := svc.IssueToken(context.Background(), "svc", "wrong")

	require.Error(t, err)
	assert.Empty(t, rec.calls())
}

// The default dummy compare is the real bcrypt one. The bound is a loose lower
// limit: cost 12 takes far longer than 20ms, and a slow machine only adds time.
func TestOAuth2Service_IssueToken_UnknownClientPaysBcryptCost(t *testing.T) {
	repo := &mockOAuth2ClientRepo{}
	repo.On("FindByName", mock.Anything, "ghost").Return(nil, errors.New("not found"))
	svc := buildService(repo, &mockPasswordService{}, &mockJWTService{})
	common.PrimeBurnPasswordCompare()

	start := time.Now()
	_, err := svc.IssueToken(context.Background(), "ghost", "secret")

	require.Error(t, err)
	assert.Greater(t, time.Since(start), 20*time.Millisecond, "an unknown client must still pay for a bcrypt compare")
}
