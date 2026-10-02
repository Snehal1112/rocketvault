package vaults

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"rocketvault/internal/db"
	"rocketvault/internal/repositories"
	"rocketvault/model"
)

func nowForTest() time.Time { return time.Unix(1700000000, 0) }

// fakeVaultRepo is a hand-rolled in-memory VaultRepositoryInterface for tests.
type fakeVaultRepo struct {
	byName map[string]*model.Vault
	byID   map[string]*model.Vault
	// readErr, when set, is returned by ReadByName/ReadByID instead of the
	// normal not-found sentinel — simulates a real failure (e.g. DB outage)
	// distinct from an honest missing row.
	readErr error
	// readByNameCalls counts ReadByName invocations, so cache tests can assert
	// a cache hit never falls through to the repo.
	readByNameCalls int
}

func newFakeRepo() *fakeVaultRepo {
	return &fakeVaultRepo{byName: map[string]*model.Vault{}, byID: map[string]*model.Vault{}}
}

var errFakeNotFound = repositories.ErrNotFound

func (f *fakeVaultRepo) Create(_ context.Context, v *model.Vault) error {
	if _, ok := f.byName[v.Name]; ok {
		return errors.New("duplicate")
	}
	cp := *v
	f.byName[v.Name] = &cp
	f.byID[v.ID.String()] = &cp
	return nil
}
func (f *fakeVaultRepo) ReadByName(_ context.Context, n string) (*model.Vault, error) {
	f.readByNameCalls++
	if f.readErr != nil {
		return nil, f.readErr
	}
	if v, ok := f.byName[n]; ok && v.DeletedAt == nil {
		return v, nil
	}
	return nil, errFakeNotFound
}
func (f *fakeVaultRepo) ReadByID(_ context.Context, id uuid.UUID) (*model.Vault, error) {
	if f.readErr != nil {
		return nil, f.readErr
	}
	if v, ok := f.byID[id.String()]; ok {
		return v, nil
	}
	return nil, errFakeNotFound
}
func (f *fakeVaultRepo) List(context.Context) ([]model.Vault, error) {
	var out []model.Vault
	for _, v := range f.byName {
		if v.DeletedAt == nil {
			out = append(out, *v)
		}
	}
	return out, nil
}
func (f *fakeVaultRepo) ListDeleted(context.Context) ([]model.Vault, error) {
	var out []model.Vault
	for _, v := range f.byName {
		if v.DeletedAt != nil {
			out = append(out, *v)
		}
	}
	return out, nil
}
func (f *fakeVaultRepo) Update(_ context.Context, v *model.Vault) error {
	f.byName[v.Name] = v
	f.byID[v.ID.String()] = v
	return nil
}
func (f *fakeVaultRepo) SoftDelete(_ context.Context, id uuid.UUID) error {
	if v, ok := f.byID[id.String()]; ok {
		now := nowForTest()
		v.DeletedAt = &now
	}
	return nil
}
func (f *fakeVaultRepo) Recover(_ context.Context, id uuid.UUID) error {
	if v, ok := f.byID[id.String()]; ok {
		v.DeletedAt = nil
	}
	return nil
}
func (f *fakeVaultRepo) Purge(_ context.Context, id uuid.UUID) error {
	if v, ok := f.byID[id.String()]; ok {
		delete(f.byName, v.Name)
		delete(f.byID, id.String())
	}
	return nil
}

type noopCascade struct {
	soft, recover, purge int
	protected            bool
	protectedErr         error
}

func (n *noopCascade) SoftDeleteVaultContents(context.Context, uuid.UUID, time.Time) error {
	n.soft++
	return nil
}
func (n *noopCascade) RecoverVaultContents(context.Context, uuid.UUID, time.Time) error {
	n.recover++
	return nil
}
func (n *noopCascade) SoftDeleteVaultContentsTx(context.Context, db.DBTX, uuid.UUID, time.Time) error {
	n.soft++
	return nil
}
func (n *noopCascade) RecoverVaultContentsTx(context.Context, db.DBTX, uuid.UUID, time.Time) error {
	n.recover++
	return nil
}
func (n *noopCascade) PurgeVaultContents(context.Context, uuid.UUID) error {
	n.purge++
	return nil
}
func (n *noopCascade) HasProtectedContent(context.Context, uuid.UUID) (bool, error) {
	return n.protected, n.protectedErr
}

func TestCreateVault_RejectsInvalidName(t *testing.T) {
	svc := NewVaultService(newFakeRepo(), &noopCascade{}, nil)
	if _, err := svc.CreateVault(context.Background(), model.CreateVaultRequest{Name: "BAD_NAME"}, uuid.New()); err == nil {
		t.Fatal("expected invalid-name error")
	}
}

func TestCreateVault_AppliesDefaultsAndOverrides(t *testing.T) {
	svc := NewVaultService(newFakeRepo(), &noopCascade{}, nil)
	v, err := svc.CreateVault(context.Background(), model.CreateVaultRequest{Name: "prod"}, uuid.New())
	if err != nil {
		t.Fatalf("CreateVault: %v", err)
	}
	if !v.Enabled || v.RetentionDays != 90 {
		t.Fatalf("expected defaults enabled=true retention=90, got %+v", v)
	}
}

func TestDeleteVault_RefusesDefault(t *testing.T) {
	repo := newFakeRepo()
	defID := uuid.MustParse(model.DefaultVaultID)
	repo.byName["default"] = &model.Vault{ID: defID, Name: "default"}
	repo.byID[defID.String()] = repo.byName["default"]
	svc := NewVaultService(repo, &noopCascade{}, nil)
	if err := svc.DeleteVault(context.Background(), "default", uuid.New()); err == nil {
		t.Fatal("expected refusal to delete the default vault")
	}
}

func TestDeleteVault_CascadesContents(t *testing.T) {
	repo := newFakeRepo()
	id := uuid.New()
	repo.byName["stg"] = &model.Vault{ID: id, Name: "stg", Enabled: true}
	repo.byID[id.String()] = repo.byName["stg"]
	casc := &noopCascade{}
	svc := NewVaultService(repo, casc, nil)
	if err := svc.DeleteVault(context.Background(), "stg", uuid.New()); err != nil {
		t.Fatalf("DeleteVault: %v", err)
	}
	if casc.soft != 1 {
		t.Fatalf("expected cascade soft-delete called once, got %d", casc.soft)
	}
}

func TestPurgeVault_RefusedWhenProtected(t *testing.T) {
	repo := newFakeRepo()
	id := uuid.New()
	repo.byName["p"] = &model.Vault{ID: id, Name: "p", PurgeProtection: true}
	repo.byID[id.String()] = repo.byName["p"]
	svc := NewVaultService(repo, &noopCascade{}, nil)
	if err := svc.PurgeVault(context.Background(), "p", uuid.New()); err == nil {
		t.Fatal("expected purge refusal when purge protection is on")
	}
}

// TestPurgeVault_RefusedWhenGlobalPurgeProtectionEnabled pins the
// instance-wide soft_delete.purge_protection safety switch: it refuses the
// purge before any repository call, regardless of the vault's own
// purge_protection flag.
func TestPurgeVault_RefusedWhenGlobalPurgeProtectionEnabled(t *testing.T) {
	repo := newFakeRepo()
	id := uuid.New()
	repo.byName["p"] = &model.Vault{ID: id, Name: "p"}
	repo.byID[id.String()] = repo.byName["p"]
	svc := NewVaultService(repo, &noopCascade{}, nil)
	svc.SetGlobalPurgeProtection(true)
	err := svc.PurgeVault(context.Background(), "p", uuid.New())
	if err == nil {
		t.Fatal("expected purge refusal when global purge protection is on")
	}
	if !errors.Is(err, model.ErrGlobalPurgeProtectionEnabled) {
		t.Fatalf("expected model.ErrGlobalPurgeProtectionEnabled, got %v", err)
	}
}

func TestRecoverVault_RestoresAndCascades(t *testing.T) {
	repo := newFakeRepo()
	id := uuid.New()
	now := nowForTest()
	repo.byName["r"] = &model.Vault{ID: id, Name: "r", DeletedAt: &now}
	repo.byID[id.String()] = repo.byName["r"]
	casc := &noopCascade{}
	svc := NewVaultService(repo, casc, nil)
	if err := svc.RecoverVault(context.Background(), "r", uuid.New()); err != nil {
		t.Fatalf("RecoverVault: %v", err)
	}
	if casc.recover != 1 {
		t.Fatalf("expected cascade recover called once, got %d", casc.recover)
	}
}

func TestGetVault_UnknownReturnsSentinel(t *testing.T) {
	svc := NewVaultService(newFakeRepo(), &noopCascade{}, nil)
	_, err := svc.GetVault(context.Background(), "nope")
	if !errors.Is(err, ErrVaultNotFound) {
		t.Fatalf("expected ErrVaultNotFound, got %v", err)
	}
}

// TestGetVault_NonNotFoundRepoErrorIsNotMaskedAsSentinel proves a real repo
// failure (e.g. a DB outage) is NOT reported as ErrVaultNotFound.
func TestGetVault_NonNotFoundRepoErrorIsNotMaskedAsSentinel(t *testing.T) {
	repo := newFakeRepo()
	repo.readErr = errors.New("connection refused")
	svc := NewVaultService(repo, &noopCascade{}, nil)

	_, err := svc.GetVault(context.Background(), "prod")
	if err == nil {
		t.Fatal("expected an error")
	}
	if errors.Is(err, ErrVaultNotFound) {
		t.Fatalf("a DB-outage error must not be reported as ErrVaultNotFound, got %v", err)
	}
}

func TestRecoverVault_UnknownReturnsSentinel(t *testing.T) {
	svc := NewVaultService(newFakeRepo(), &noopCascade{}, nil)
	err := svc.RecoverVault(context.Background(), "nope", uuid.New())
	if !errors.Is(err, ErrVaultNotFound) {
		t.Fatalf("expected ErrVaultNotFound, got %v", err)
	}
}

func boolPtr(b bool) *bool { return &b }
func intPtr(i int) *int    { return &i }

func TestListVaults_ActiveOnly(t *testing.T) {
	repo := newFakeRepo()
	a1 := uuid.New()
	a2 := uuid.New()
	repo.byName["a1"] = &model.Vault{ID: a1, Name: "a1", Enabled: true}
	repo.byID[a1.String()] = repo.byName["a1"]
	repo.byName["a2"] = &model.Vault{ID: a2, Name: "a2", Enabled: true}
	repo.byID[a2.String()] = repo.byName["a2"]
	svc := NewVaultService(repo, &noopCascade{}, nil)

	vaults, err := svc.ListVaults(context.Background(), false)
	if err != nil {
		t.Fatalf("ListVaults: %v", err)
	}
	if len(vaults) != 2 {
		t.Fatalf("expected 2 active vaults, got %d", len(vaults))
	}
}

func TestListVaults_IncludeDeleted(t *testing.T) {
	repo := newFakeRepo()
	active := uuid.New()
	deleted := uuid.New()
	now := nowForTest()
	repo.byName["active"] = &model.Vault{ID: active, Name: "active", Enabled: true}
	repo.byID[active.String()] = repo.byName["active"]
	repo.byName["gone"] = &model.Vault{ID: deleted, Name: "gone", DeletedAt: &now}
	repo.byID[deleted.String()] = repo.byName["gone"]
	svc := NewVaultService(repo, &noopCascade{}, nil)

	vaults, err := svc.ListVaults(context.Background(), true)
	if err != nil {
		t.Fatalf("ListVaults: %v", err)
	}
	if len(vaults) != 2 {
		t.Fatalf("expected active + deleted = 2 vaults, got %d", len(vaults))
	}
	names := map[string]bool{}
	for _, v := range vaults {
		names[v.Name] = true
	}
	if !names["active"] || !names["gone"] {
		t.Fatalf("expected both active and gone, got %v", names)
	}
}

func TestUpdateVault_AppliesNonNilFields(t *testing.T) {
	svc := NewVaultService(newFakeRepo(), &noopCascade{}, nil)
	created, err := svc.CreateVault(context.Background(), model.CreateVaultRequest{Name: "upd"}, uuid.New())
	if err != nil {
		t.Fatalf("CreateVault: %v", err)
	}
	if !created.Enabled || created.PurgeProtection {
		t.Fatalf("unexpected initial state: %+v", created)
	}

	updated, err := svc.UpdateVault(context.Background(), "upd", model.UpdateVaultRequest{
		Enabled:       boolPtr(false),
		RetentionDays: intPtr(30),
		// PurgeProtection left nil so it must remain unchanged.
	}, uuid.New())
	if err != nil {
		t.Fatalf("UpdateVault: %v", err)
	}
	if updated.Enabled {
		t.Fatalf("expected Enabled=false")
	}
	if updated.RetentionDays != 30 {
		t.Fatalf("expected RetentionDays=30, got %d", updated.RetentionDays)
	}
	if updated.PurgeProtection {
		t.Fatalf("expected PurgeProtection unchanged (false)")
	}
}

func TestUpdateVault_ReplacesTagsAndSetsUpdatedBy(t *testing.T) {
	svc := NewVaultService(newFakeRepo(), &noopCascade{}, nil)
	if _, err := svc.CreateVault(context.Background(), model.CreateVaultRequest{Name: "tagged"}, uuid.New()); err != nil {
		t.Fatalf("CreateVault: %v", err)
	}

	updater := uuid.New()
	tags := map[string]string{"env": "prod"}
	got, err := svc.UpdateVault(context.Background(), "tagged",
		model.UpdateVaultRequest{Tags: &tags}, updater)
	if err != nil {
		t.Fatalf("update: %v", err)
	}
	if got.Tags["env"] != "prod" {
		t.Fatalf("tags not applied: %v", got.Tags)
	}
	if got.UpdatedBy == nil || *got.UpdatedBy != updater {
		t.Fatalf("updated_by not set: %v", got.UpdatedBy)
	}
}

func TestUpdateVault_NotFound(t *testing.T) {
	svc := NewVaultService(newFakeRepo(), &noopCascade{}, nil)
	_, err := svc.UpdateVault(context.Background(), "missing", model.UpdateVaultRequest{Enabled: boolPtr(true)}, uuid.New())
	if !errors.Is(err, ErrVaultNotFound) {
		t.Fatalf("expected ErrVaultNotFound, got %v", err)
	}
}

func TestCreateVault_AppliesAllOverrides(t *testing.T) {
	svc := NewVaultService(newFakeRepo(), &noopCascade{}, nil)
	v, err := svc.CreateVault(context.Background(), model.CreateVaultRequest{
		Name:            "over",
		Enabled:         boolPtr(false),
		PurgeProtection: boolPtr(true),
		RetentionDays:   intPtr(7),
	}, uuid.New())
	if err != nil {
		t.Fatalf("CreateVault: %v", err)
	}
	if v.Enabled {
		t.Fatalf("expected Enabled=false override")
	}
	if !v.PurgeProtection {
		t.Fatalf("expected PurgeProtection=true override")
	}
	if v.RetentionDays != 7 {
		t.Fatalf("expected RetentionDays=7 override, got %d", v.RetentionDays)
	}
}

func TestPurgeVault_DeletedVaultSucceeds(t *testing.T) {
	repo := newFakeRepo()
	id := uuid.New()
	now := nowForTest()
	repo.byName["d"] = &model.Vault{ID: id, Name: "d", PurgeProtection: false, DeletedAt: &now}
	repo.byID[id.String()] = repo.byName["d"]
	svc := NewVaultService(repo, &noopCascade{}, nil)

	if err := svc.PurgeVault(context.Background(), "d", uuid.New()); err != nil {
		t.Fatalf("PurgeVault: %v", err)
	}
	if _, ok := repo.byID[id.String()]; ok {
		t.Fatal("expected purged vault to be removed from the repo")
	}
}

type fakePolicyCleaner struct {
	called   bool
	gotVault uuid.UUID
}

func (f *fakePolicyCleaner) DeleteByVault(_ context.Context, vid uuid.UUID) error {
	f.called = true
	f.gotVault = vid
	return nil
}

func TestPurgeVault_DeletesVaultPolicies(t *testing.T) {
	repo := newFakeRepo()
	id := uuid.New()
	now := nowForTest()
	repo.byName["prod"] = &model.Vault{ID: id, Name: "prod", PurgeProtection: false, DeletedAt: &now}
	repo.byID[id.String()] = repo.byName["prod"]
	svc := NewVaultService(repo, &noopCascade{}, nil)

	cleaner := &fakePolicyCleaner{}
	svc.SetPolicyCleaner(cleaner)

	if err := svc.PurgeVault(context.Background(), "prod", uuid.New()); err != nil {
		t.Fatalf("purge: %v", err)
	}
	if !cleaner.called {
		t.Fatal("expected vault policies to be deleted on purge")
	}
	if cleaner.gotVault != id {
		t.Fatalf("expected policies deleted for vault %s, got %s", id, cleaner.gotVault)
	}
}

func TestRecoverVault_RestoresFromDeleted(t *testing.T) {
	repo := newFakeRepo()
	id := uuid.New()
	now := nowForTest()
	repo.byName["rec"] = &model.Vault{ID: id, Name: "rec", DeletedAt: &now}
	repo.byID[id.String()] = repo.byName["rec"]
	casc := &noopCascade{}
	svc := NewVaultService(repo, casc, nil)

	if err := svc.RecoverVault(context.Background(), "rec", uuid.New()); err != nil {
		t.Fatalf("RecoverVault: %v", err)
	}
	if repo.byID[id.String()].DeletedAt != nil {
		t.Fatal("expected recovered vault to have DeletedAt cleared")
	}
	if casc.recover != 1 {
		t.Fatalf("expected cascade recover called once, got %d", casc.recover)
	}
}

func TestDeleteVault_NotFound(t *testing.T) {
	svc := NewVaultService(newFakeRepo(), &noopCascade{}, nil)
	err := svc.DeleteVault(context.Background(), "missing", uuid.New())
	if !errors.Is(err, ErrVaultNotFound) {
		t.Fatalf("expected ErrVaultNotFound, got %v", err)
	}
}

func TestVaultService_SetTxBeginnerIsPartOfTheInterface(t *testing.T) {
	svc := NewVaultService(newFakeRepo(), &noopCascade{}, nil)
	var _ interface {
		SetTxBeginner(tb TxBeginner)
	} = svc
}

// countingFlusher records how many times the cascade flushed the secret cache.
type countingFlusher struct{ flushes int }

func (c *countingFlusher) Flush(context.Context) error { c.flushes++; return nil }

// TestDeleteAndRecoverVaultFlushTheSecretCache pins the cache half of the
// cascade. The cascade stamps deleted_at on every secret in the vault with one
// bulk UPDATE that never goes through CachedSecretService, so without this
// flush a member who read a secret just before the delete keeps being served
// its plaintext from cache for the full TTL.
func TestDeleteAndRecoverVaultFlushTheSecretCache(t *testing.T) {
	repo := newFakeRepo()
	id := uuid.New()
	repo.byName["stg"] = &model.Vault{ID: id, Name: "stg", Enabled: true}
	repo.byID[id.String()] = repo.byName["stg"]

	flusher := &countingFlusher{}
	svc := NewVaultService(repo, &noopCascade{}, nil)
	svc.SetSecretCacheFlusher(flusher)

	if err := svc.DeleteVault(context.Background(), "stg", uuid.New()); err != nil {
		t.Fatalf("DeleteVault: %v", err)
	}
	if flusher.flushes != 1 {
		t.Fatalf("expected one flush after the delete cascade, got %d", flusher.flushes)
	}

	if err := svc.RecoverVault(context.Background(), "stg", uuid.New()); err != nil {
		t.Fatalf("RecoverVault: %v", err)
	}
	if flusher.flushes != 2 {
		t.Fatalf("expected a second flush after the recover cascade, got %d", flusher.flushes)
	}
}

// TestVaultCascadeToleratesADisabledCache pins that an unset flusher (caching
// disabled) is a no-op rather than a nil-pointer panic.
// testPrincipal is a fixed principal ID shared by the ListVaultsScoped tests below.
var testPrincipal = uuid.New()

// fakePolicyVaultLister is an in-memory PolicyVaultLister for ListVaultsScoped tests.
type fakePolicyVaultLister struct {
	ids map[uuid.UUID][]uuid.UUID
	err error
}

func (f *fakePolicyVaultLister) ListVaultIDsForPrincipal(_ context.Context, principalID uuid.UUID) ([]uuid.UUID, error) {
	if f.err != nil {
		return nil, f.err
	}
	return f.ids[principalID], nil
}

// newScopedListTestService builds a vaultService backed by a fake repo seeded
// with one vault per name in grants (granted to the corresponding principal),
// plus two extra vaults nobody holds a scoped grant on, so all=false and
// all=true can diverge. It returns the service and the total vault count, for
// asserting all=true matches ListVaults exactly.
func newScopedListTestService(t *testing.T, grants map[uuid.UUID][]string) (VaultService, int) {
	t.Helper()
	repo := newFakeRepo()
	ids := make(map[uuid.UUID][]uuid.UUID, len(grants))
	for principal, names := range grants {
		for _, name := range names {
			id := uuid.New()
			repo.byName[name] = &model.Vault{ID: id, Name: name, Enabled: true}
			repo.byID[id.String()] = repo.byName[name]
			ids[principal] = append(ids[principal], id)
		}
	}
	for _, name := range []string{"unrelated-1", "unrelated-2"} {
		id := uuid.New()
		repo.byName[name] = &model.Vault{ID: id, Name: name, Enabled: true}
		repo.byID[id.String()] = repo.byName[name]
	}

	svc := NewVaultService(repo, &noopCascade{}, nil)
	svc.SetPolicyVaultLister(&fakePolicyVaultLister{ids: ids})
	return svc, len(repo.byName)
}

func TestListVaultsScoped_FiltersToPrincipalsVaults(t *testing.T) {
	svc, _ := newScopedListTestService(t, map[uuid.UUID][]string{
		testPrincipal: {"acme-prod"},
	})

	got, err := svc.ListVaultsScoped(context.Background(), testPrincipal, false, false)
	require.NoError(t, err)
	require.Len(t, got, 1)
	require.Equal(t, "acme-prod", got[0].Name)
}

func TestListVaultsScoped_AllReturnsEverything(t *testing.T) {
	svc, total := newScopedListTestService(t, map[uuid.UUID][]string{
		testPrincipal: {"acme-prod"},
	})

	got, err := svc.ListVaultsScoped(context.Background(), testPrincipal, false, true)
	require.NoError(t, err)
	require.Len(t, got, total, "all=true must match ListVaults exactly")
}

func TestListVaultsScoped_NoPoliciesReturnsEmpty(t *testing.T) {
	svc, _ := newScopedListTestService(t, nil)

	got, err := svc.ListVaultsScoped(context.Background(), uuid.New(), false, false)
	require.NoError(t, err)
	require.Empty(t, got, "a principal with no scoped policy sees nothing, not everything")
}

// TestListVaultsScoped_UnwiredListerReturnsEmpty pins that an unset
// policyVaults dependency (mirroring every other optional dependency on this
// service) yields an empty list, not an error.
func TestListVaultsScoped_UnwiredListerReturnsEmpty(t *testing.T) {
	svc := NewVaultService(newFakeRepo(), &noopCascade{}, nil)

	got, err := svc.ListVaultsScoped(context.Background(), uuid.New(), false, false)
	require.NoError(t, err)
	require.Empty(t, got)
}

// TestListVaultsScoped_PropagatesPolicyLookupError pins the deliberate
// deviation from the naive "fail closed to empty" approach: an empty list is
// a positive claim ("you manage no vaults"), so a policy-lookup failure (e.g.
// a DB outage) must surface as an error, not be swallowed into an empty list
// that would misrepresent the caller's vaults as gone.
func TestListVaultsScoped_PropagatesPolicyLookupError(t *testing.T) {
	svc := NewVaultService(newFakeRepo(), &noopCascade{}, nil)
	wantErr := errors.New("db outage")
	svc.SetPolicyVaultLister(&fakePolicyVaultLister{err: wantErr})

	_, err := svc.ListVaultsScoped(context.Background(), uuid.New(), false, false)
	require.Error(t, err, "expected the policy-lookup error to propagate, not be swallowed into an empty list")
	require.ErrorIs(t, err, wantErr)
}

func TestVaultCascadeToleratesADisabledCache(t *testing.T) {
	repo := newFakeRepo()
	id := uuid.New()
	repo.byName["stg"] = &model.Vault{ID: id, Name: "stg", Enabled: true}
	repo.byID[id.String()] = repo.byName["stg"]

	svc := NewVaultService(repo, &noopCascade{}, nil)
	if err := svc.DeleteVault(context.Background(), "stg", uuid.New()); err != nil {
		t.Fatalf("DeleteVault: %v", err)
	}
}

// TestCreateVault_RefusesReservedName proves both create paths use the
// reservation (B80).
func TestCreateVault_RefusesReservedName(t *testing.T) {
	svc := NewVaultService(newFakeRepo(), &noopCascade{}, nil)
	_, err := svc.CreateVault(context.Background(), model.CreateVaultRequest{Name: "login"}, uuid.New())
	require.ErrorIs(t, err, model.ErrReservedVaultName)
	_, err = svc.CreateVaultProvisioned(context.Background(), model.CreateVaultRequest{Name: "health"}, uuid.New(), false, false)
	require.ErrorIs(t, err, model.ErrReservedVaultName)
}
