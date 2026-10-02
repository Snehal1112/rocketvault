package certcache

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"rocketvault/internal/cachekit"
	"rocketvault/model"
)

// TestCache_ExportableSurvivesClone pins that a cached certificate keeps its
// flag: the list and get responses read exportable off whatever the cache
// returns.
func TestCache_ExportableSurvivesClone(t *testing.T) {
	c := NewCache(cachekit.Config{Enabled: true, TTL: 5 * time.Minute, CleanupInterval: time.Minute, MaxEntries: 10}, logrus.New())
	t.Cleanup(c.Stop)
	ctx := context.Background()
	vaultID := uuid.New()
	scope := model.NewVaultScope(vaultID, uuid.New())
	cert := &model.Certificate{ID: uuid.New(), VaultID: vaultID, Name: "c", Enabled: true, Exportable: true}
	require.NoError(t, c.Set(ctx, cert, scope))

	got, ok := c.Get(ctx, cert.ID, scope)
	require.True(t, ok)
	assert.True(t, got.Exportable)
}
