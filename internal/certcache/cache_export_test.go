package certcache

import (
	"context"
	"strings"
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

func TestCachedExportCertificate_NeverCaches(t *testing.T) {
	ctx := context.Background()
	c := NewCache(cachekit.Config{Enabled: true, TTL: 5 * time.Minute, CleanupInterval: time.Minute, MaxEntries: 10}, logrus.New())
	t.Cleanup(c.Stop)
	vaultID := uuid.New()
	scope := model.NewVaultScope(vaultID, uuid.New())
	certID := uuid.New()
	password := "never-cache-this-password"
	keyText := "-----BEGIN PRIVATE KEY-----\nMIIEexported\n-----END PRIVATE KEY-----\n"

	// A cached metadata row already exists; export must neither read nor
	// replace it.
	require.NoError(t, c.Set(ctx, &model.Certificate{ID: certID, VaultID: vaultID, Name: "c", Enabled: true}, scope))

	inner := mocks.NewMockCertificateService(t)
	req := certificates.ExportCertificateRequest{Format: model.ExportFormatPKCS12, Password: &password}
	inner.On("ExportCertificate", mock.Anything, scope, certID, req).
		Return(&certificates.ExportCertificateResult{ID: certID, PrivateKeyPEM: keyText, PKCS12: []byte("pfx")}, nil).Twice()
	svc := NewCachedCertificateService(inner, c, logrus.New())

	for i := 0; i < 2; i++ {
		_, err := svc.ExportCertificate(ctx, scope, certID, req)
		require.NoError(t, err)
	}
	inner.AssertNumberOfCalls(t, "ExportCertificate", 2) // Both exports reached the service.

	// Guard against a no-op cache: the seeded row must be visible.
	seeded, ok := c.Get(ctx, certID, scope)
	require.True(t, ok)
	require.Equal(t, "c", seeded.Name)

	var dump strings.Builder
	c.core.Range(func(key string, v *model.Certificate) bool {
		dump.WriteString(key)
		dump.WriteString(v.Name + v.Certificate + v.PrivateKey)
		return true
	})
	require.NotEmpty(t, dump.String())
	assert.NotContains(t, dump.String(), password)
	assert.NotContains(t, dump.String(), "BEGIN PRIVATE KEY")
	assert.NotContains(t, dump.String(), "MIIEexported")
}
