package certificates

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"rocketvault/common"
	"rocketvault/internal/crypto"
	"rocketvault/internal/logging"
	"rocketvault/model"
)

// Auto-renewal runs unattended, so it is the path where a silent conversion to
// self-signed does the most damage. It must preserve the chain too.
func TestCheckAndRenewCertificates_CASignedKeepsIssuer(t *testing.T) {
	setupMasterKey()

	userID := uuid.New()
	vaultID := uuid.New()
	certID := uuid.New()
	keyID := uuid.New()
	caCertID := uuid.New()

	entityKeyPEM, err := crypto.GenerateRSAKeyPEM(2048)
	require.NoError(t, err)
	caKeyPEM, err := crypto.GenerateRSAKeyPEM(2048)
	require.NoError(t, err)

	caPEM, err := crypto.CreateSelfSignedCertificatePEM(caKeyPEM, "RSA", crypto.CertificateTemplate{
		CommonName: "Scheduler CA", ValidityDays: 3650, IsCA: true,
	})
	require.NoError(t, err)
	leafPEM, err := crypto.CreateCASignedCertificatePEM(entityKeyPEM, "RSA", caPEM, caKeyPEM, "RSA", crypto.CertificateTemplate{
		CommonName: "scheduled-leaf", ValidityDays: 365, IsCA: false,
	})
	require.NoError(t, err)

	encEntity, err := common.EncryptSecret(entityKeyPEM)
	require.NoError(t, err)
	encCA, err := common.EncryptSecret(caKeyPEM)
	require.NoError(t, err)

	// Inside its renewal window: expires in 5 days, renewal_days 30.
	expiresAt := time.Now().Add(5 * 24 * time.Hour)
	original := &model.Certificate{
		ID: certID, UserID: userID, VaultID: vaultID, KeyID: keyID, CACertID: &caCertID,
		Name: "scheduled-leaf", Certificate: leafPEM, PrivateKey: encEntity,
		CreatedAt: time.Now().Add(-360 * 24 * time.Hour), ExpiresAt: &expiresAt,
		AutoRenew: true, RenewalDays: 30, Enabled: true,
	}
	caCert := &model.Certificate{
		ID: caCertID, UserID: userID, VaultID: vaultID, Name: "scheduler-ca",
		Certificate: caPEM, PrivateKey: encCA, Enabled: true,
	}

	certRepo := &mockCertRepository{}
	keyRepo := &mockKeyRepo{}

	vaultScope := model.NewVaultScope(vaultID, userID)
	certRepo.On("ListAll", mock.Anything).Return([]model.Certificate{*original}, nil)
	certRepo.On("Read", mock.Anything, certID, vaultScope).Return(original, nil)
	certRepo.On("Read", mock.Anything, caCertID, vaultScope).Return(caCert, nil)
	keyRepo.On("Read", mock.Anything, keyID, vaultScope).
		Return(&model.Key{ID: keyID, UserID: userID, Type: model.KeyTypeRSA, Value: encEntity, Enabled: true}, nil)

	var updated *model.Certificate
	certRepo.On("Update", mock.Anything, mock.AnythingOfType("*model.Certificate"), vaultScope).
		Run(func(args mock.Arguments) { updated = args.Get(1).(*model.Certificate) }).
		Return(nil)

	logger := &logging.Logger{Logger: logrus.New()}
	certSvc := newCertSvc(certRepo, keyRepo)
	renewalSvc := NewCertificateRenewalService(RenewalServiceConfig{
		CertRepository:     certRepo,
		CertificateService: certSvc,
		Logger:             logger,
	})

	renewed, warned, err := renewalSvc.CheckAndRenewCertificates(context.Background())
	require.NoError(t, err)
	require.Equal(t, 1, renewed)
	require.Equal(t, 0, warned)

	require.NotNil(t, updated, "the scheduler must have written a renewal")
	assertSignedBy(t, updated.Certificate, caPEM, "Scheduler CA")
}
