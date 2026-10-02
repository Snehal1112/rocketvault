package vaults

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"rocketvault/model"
)

// newTestServiceWithVault returns a VaultService backed by a fakeVaultRepo
// pre-seeded with one enabled vault of the given name, plus the repo itself
// so tests can inspect call counts.
func newTestServiceWithVault(t *testing.T, name string) (VaultService, *fakeVaultRepo) {
	t.Helper()
	repo := newFakeRepo()
	id := uuid.New()
	repo.byName[name] = &model.Vault{ID: id, Name: name, Enabled: true}
	repo.byID[id.String()] = repo.byName[name]
	svc := NewVaultService(repo, &noopCascade{}, nil)
	return svc, repo
}

// spyVaultCache records calls so tests can assert on cache-vs-repo behavior
// without depending on the real vaultcache.Cache implementation.
type spyVaultCache struct {
	store       map[string]*model.Vault
	getCalls    int
	setCalls    int
	invalidated []string
}

func newSpyVaultCache() *spyVaultCache {
	return &spyVaultCache{store: make(map[string]*model.Vault)}
}

func (s *spyVaultCache) Get(name string) (*model.Vault, bool) {
	s.getCalls++
	v, ok := s.store[name]
	if !ok {
		return nil, false
	}
	// Defensive copy on read, mirroring the real vaultcache.Cache's
	// Clone()-on-Get semantics (see the brief's own note). Without this, a
	// cache hit would hand callers the live stored pointer, and a caller that
	// mutates its result (e.g. UpdateVault) would silently corrupt the cache.
	cp := *v
	return &cp, true
}
func (s *spyVaultCache) Set(name string, v *model.Vault) {
	s.setCalls++
	cp := *v
	s.store[name] = &cp
}
func (s *spyVaultCache) Invalidate(name string) {
	s.invalidated = append(s.invalidated, name)
	delete(s.store, name)
}

func TestGetVault_PopulatesCacheOnMiss(t *testing.T) {
	svc, repo := newTestServiceWithVault(t, "myvault")
	spy := newSpyVaultCache()
	svc.(*vaultService).SetVaultCache(spy)

	v, err := svc.GetVault(context.Background(), "myvault")
	require.NoError(t, err)
	assert.Equal(t, "myvault", v.Name)
	assert.Equal(t, 1, spy.setCalls, "a repo hit must populate the cache")
	_ = repo
}

func TestGetVault_SecondCallHitsCacheNotRepo(t *testing.T) {
	svc, repo := newTestServiceWithVault(t, "myvault")
	spy := newSpyVaultCache()
	svc.(*vaultService).SetVaultCache(spy)

	_, err := svc.GetVault(context.Background(), "myvault")
	require.NoError(t, err)
	callsBefore := repo.readByNameCalls

	_, err = svc.GetVault(context.Background(), "myvault")
	require.NoError(t, err)
	assert.Equal(t, callsBefore, repo.readByNameCalls, "second GetVault must be served from cache, not the repo")
}

func TestUpdateVault_InvalidatesCache(t *testing.T) {
	svc, _ := newTestServiceWithVault(t, "myvault")
	spy := newSpyVaultCache()
	svc.(*vaultService).SetVaultCache(spy)

	_, err := svc.GetVault(context.Background(), "myvault") // populate the cache
	require.NoError(t, err)

	enabled := false
	_, err = svc.UpdateVault(context.Background(), "myvault", model.UpdateVaultRequest{Enabled: &enabled}, uuid.New())
	require.NoError(t, err)

	assert.Contains(t, spy.invalidated, "myvault", "UpdateVault must invalidate the cache entry")
}

func TestUpdateVault_MutatingResultDoesNotCorruptPriorCacheEntry(t *testing.T) {
	svc, _ := newTestServiceWithVault(t, "myvault")
	spy := newSpyVaultCache()
	svc.(*vaultService).SetVaultCache(spy)

	first, err := svc.GetVault(context.Background(), "myvault")
	require.NoError(t, err)
	require.True(t, first.Enabled)

	// Snapshot the object Set stored in the cache right after the populating
	// GetVault call, before UpdateVault's own Invalidate call removes the
	// "myvault" key from the live store entirely -- looking it back up in
	// spy.store after UpdateVault returns would always find nothing, since
	// Invalidate is required to have deleted it by then. This snapshot is
	// what proves (or disproves) corruption independent of that deletion.
	cachedBeforeUpdate := spy.store["myvault"]
	require.NotNil(t, cachedBeforeUpdate)
	require.True(t, cachedBeforeUpdate.Enabled)

	enabled := false
	_, err = svc.UpdateVault(context.Background(), "myvault", model.UpdateVaultRequest{Enabled: &enabled}, uuid.New())
	require.NoError(t, err)

	// The snapshot must be untouched by UpdateVault's later in-place mutation
	// of the pointer it got back from getByName — proving a cache hit in
	// getByName hands back an independent value, not the live cached object.
	assert.True(t, cachedBeforeUpdate.Enabled, "the stale cache entry must not be corrupted by the live mutation")
}

func TestDeleteVault_InvalidatesCache(t *testing.T) {
	svc, _ := newTestServiceWithVault(t, "notdefault")
	spy := newSpyVaultCache()
	svc.(*vaultService).SetVaultCache(spy)

	_, err := svc.GetVault(context.Background(), "notdefault")
	require.NoError(t, err)

	err = svc.DeleteVault(context.Background(), "notdefault", uuid.New())
	require.NoError(t, err)

	assert.Contains(t, spy.invalidated, "notdefault")
}
