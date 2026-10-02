package certificates

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"rocketvault/model"
)

// renewWithKeyRepo runs RenewCertificate for a certificate that points at keyID.
func renewWithKeyRepo(t *testing.T, keyID uuid.UUID, keyRepo *mockKeyRepo) error {
	t.Helper()
	userID := uuid.New()
	certID := uuid.New()
	scope := model.NewOwnerScope(uuid.Nil, userID)
	certRepo := &mockCertRepository{}
	certRepo.On("Read", mock.Anything, certID, scope).Return(&model.Certificate{
		ID: certID, UserID: userID, Enabled: true, KeyID: keyID,
	}, nil)

	svc := newCertSvc(certRepo, keyRepo)
	_, err := svc.RenewCertificate(context.Background(), certID, scope, 365)
	return err
}

func TestRenewCertificate_ReturnsSentinelForForeignKey(t *testing.T) {
	keyID := uuid.New()
	keyRepo := &mockKeyRepo{}
	keyRepo.On("Read", mock.Anything, keyID, mock.Anything).Return(&model.Key{ID: keyID, UserID: uuid.New(), Enabled: true}, nil)

	err := renewWithKeyRepo(t, keyID, keyRepo)
	require.ErrorIs(t, err, ErrRenewKeyForbidden)
	assert.Contains(t, err.Error(), "forbidden: cannot use other users' keys")
}

func TestRenewCertificate_ReturnsSentinelForMissingKey(t *testing.T) {
	keyID := uuid.New()
	keyRepo := &mockKeyRepo{}
	keyRepo.On("Read", mock.Anything, keyID, mock.Anything).Return(nil, errors.New("not found"))

	err := renewWithKeyRepo(t, keyID, keyRepo)
	require.ErrorIs(t, err, ErrRenewKeyNotFound)
	assert.Contains(t, err.Error(), "key not found")
}

func TestRenewCertificate_ReturnsSentinelForNoKeyID(t *testing.T) {
	err := renewWithKeyRepo(t, uuid.Nil, &mockKeyRepo{})
	require.ErrorIs(t, err, ErrRenewNotPossible)
	assert.Contains(t, err.Error(), "no associated key ID")
}

func TestRenewCertificate_ReturnsSentinelForUnrecordedCA(t *testing.T) {
	f := newCARenewalFixture(t, "RSA")
	f.original.CACertID = nil

	_, err := f.svc.RenewCertificate(context.Background(), f.certID, f.scope, 365)
	require.ErrorIs(t, err, ErrRenewNotPossible)
	assert.Contains(t, err.Error(), "no longer records")
}
