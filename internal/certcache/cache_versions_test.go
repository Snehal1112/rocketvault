package certcache

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"rocketvault/internal/cachekit"
	"rocketvault/internal/services/certificates"
	"rocketvault/internal/services/certificates/mocks"
	"rocketvault/model"
)

func newVersionTestCache(t *testing.T) *Cache {
	t.Helper()
	c := NewCache(cachekit.Config{Enabled: true, TTL: 5 * time.Minute, CleanupInterval: time.Minute, MaxEntries: 100}, logrus.New())
	t.Cleanup(c.Stop)
	return c
}

func TestCachedUpdateCertificateVersion_EvictsOnlyForCurrentVersion(t *testing.T) {
	ctx := context.Background()
	c := newVersionTestCache(t)
	vaultID := uuid.New()
	scope := model.NewVaultScope(vaultID, uuid.New())
	cert := &model.Certificate{ID: uuid.New(), VaultID: vaultID, Name: "c", Enabled: true, Version: 3}
	require.NoError(t, c.Set(ctx, cert, scope))

	inner := mocks.NewMockCertificateService(t)
	svc := NewCachedCertificateService(inner, c, logrus.New())

	archivedReq := certificates.UpdateCertificateVersionRequest{CertID: cert.ID, Version: 2, Scope: scope}
	inner.On("UpdateCertificateVersion", mock.Anything, archivedReq).
		Return(&model.CertificateVersion{CertificateID: cert.ID, Version: 2}, nil)
	_, err := svc.UpdateCertificateVersion(ctx, archivedReq)
	require.NoError(t, err)
	_, found := c.Get(ctx, cert.ID, scope)
	assert.True(t, found, "archived versions are not cached, so the entry stays")

	currentReq := certificates.UpdateCertificateVersionRequest{CertID: cert.ID, Version: 3, Scope: scope}
	inner.On("UpdateCertificateVersion", mock.Anything, currentReq).
		Return(&model.CertificateVersion{CertificateID: cert.ID, Version: 3, Current: true}, nil)
	_, err = svc.UpdateCertificateVersion(ctx, currentReq)
	require.NoError(t, err)
	_, found = c.Get(ctx, cert.ID, scope)
	assert.False(t, found, "the current version's attributes live on the cached row")
}

func TestCachedRenewCertificate_Evicts(t *testing.T) {
	ctx := context.Background()
	c := newVersionTestCache(t)
	vaultID := uuid.New()
	scope := model.NewVaultScope(vaultID, uuid.New())
	cert := &model.Certificate{ID: uuid.New(), VaultID: vaultID, Name: "c", Enabled: true, Version: 1}
	require.NoError(t, c.Set(ctx, cert, scope))

	inner := mocks.NewMockCertificateService(t)
	inner.On("RenewCertificate", mock.Anything, cert.ID, scope, 30).
		Return(&certificates.CreateCertificateResult{CertID: cert.ID, Version: 2}, nil)
	svc := NewCachedCertificateService(inner, c, logrus.New())

	_, err := svc.RenewCertificate(ctx, cert.ID, scope, 30)
	require.NoError(t, err)
	_, found := c.Get(ctx, cert.ID, scope)
	assert.False(t, found)
}
