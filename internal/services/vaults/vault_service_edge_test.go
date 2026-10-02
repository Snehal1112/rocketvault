// Edge-case tests for vault service error branches.
package vaults

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"rocketvault/internal/db"
	"rocketvault/model"
)

// errVaultRepo wraps fakeVaultRepo but injects failures on specific operations.
type errVaultRepo struct {
	*fakeVaultRepo
	readByIDErr    error
	softDeleteErr  error
	recoverErr     error
	purgeErr       error
	listDeletedErr error
	listErr        error
	readByNameErr  error
}

func (r *errVaultRepo) ReadByID(_ context.Context, id uuid.UUID) (*model.Vault, error) {
	if r.readByIDErr != nil {
		return nil, r.readByIDErr
	}
	return r.fakeVaultRepo.ReadByID(context.Background(), id)
}

func (r *errVaultRepo) SoftDelete(_ context.Context, id uuid.UUID) error {
	if r.softDeleteErr != nil {
		return r.softDeleteErr
	}
	return r.fakeVaultRepo.SoftDelete(context.Background(), id)
}

func (r *errVaultRepo) Recover(_ context.Context, id uuid.UUID) error {
	if r.recoverErr != nil {
		return r.recoverErr
	}
	return r.fakeVaultRepo.Recover(context.Background(), id)
}

func (r *errVaultRepo) Purge(_ context.Context, id uuid.UUID) error {
	if r.purgeErr != nil {
		return r.purgeErr
	}
	return r.fakeVaultRepo.Purge(context.Background(), id)
}

func (r *errVaultRepo) ListDeleted(_ context.Context) ([]model.Vault, error) {
	if r.listDeletedErr != nil {
		return nil, r.listDeletedErr
	}
	return r.fakeVaultRepo.ListDeleted(context.Background())
}

func (r *errVaultRepo) List(_ context.Context) ([]model.Vault, error) {
	if r.listErr != nil {
		return nil, r.listErr
	}
	return r.fakeVaultRepo.List(context.Background())
}

func (r *errVaultRepo) ReadByName(_ context.Context, n string) (*model.Vault, error) {
	if r.readByNameErr != nil {
		return nil, r.readByNameErr
	}
	return r.fakeVaultRepo.ReadByName(context.Background(), n)
}

// -- DeleteVault error branches ----------------------------------------------

func TestDeleteVault_SoftDeleteRepoError(t *testing.T) {
	inner := newFakeRepo()
	id := uuid.New()
	inner.byName["x"] = &model.Vault{ID: id, Name: "x"}
	inner.byID[id.String()] = inner.byName["x"]

	repo := &errVaultRepo{fakeVaultRepo: inner, softDeleteErr: errors.New("db error")}
	svc := NewVaultService(repo, &noopCascade{}, nil)

	err := svc.DeleteVault(context.Background(), "x", uuid.New())
	if err == nil {
		t.Fatal("expected error from SoftDelete")
	}
}

func TestDeleteVault_ReadByIDAfterSoftDeleteError(t *testing.T) {
	inner := newFakeRepo()
	id := uuid.New()
	inner.byName["x"] = &model.Vault{ID: id, Name: "x"}
	inner.byID[id.String()] = inner.byName["x"]

	repo := &errVaultRepo{fakeVaultRepo: inner, readByIDErr: errors.New("db error")}
	svc := NewVaultService(repo, &noopCascade{}, nil)

	err := svc.DeleteVault(context.Background(), "x", uuid.New())
	if err == nil {
		t.Fatal("expected error from ReadByID after soft-delete")
	}
}

func TestDeleteVault_CascadeError(t *testing.T) {
	inner := newFakeRepo()
	id := uuid.New()
	inner.byName["x"] = &model.Vault{ID: id, Name: "x"}
	inner.byID[id.String()] = inner.byName["x"]

	boom := errors.New("cascade boom")
	casc := &failingCascade{err: boom}
	svc := NewVaultService(inner, casc, nil)

	err := svc.DeleteVault(context.Background(), "x", uuid.New())
	if !errors.Is(err, boom) {
		t.Fatalf("expected cascade error, got %v", err)
	}
}

// -- RecoverVault error branches ---------------------------------------------

func TestRecoverVault_RecoverRepoError(t *testing.T) {
	inner := newFakeRepo()
	id := uuid.New()
	now := nowForTest()
	inner.byName["r"] = &model.Vault{ID: id, Name: "r", DeletedAt: &now}
	inner.byID[id.String()] = inner.byName["r"]

	repo := &errVaultRepo{fakeVaultRepo: inner, recoverErr: errors.New("db error")}
	svc := NewVaultService(repo, &noopCascade{}, nil)

	err := svc.RecoverVault(context.Background(), "r", uuid.New())
	if err == nil {
		t.Fatal("expected error from Recover repo call")
	}
}

func TestRecoverVault_CascadeError(t *testing.T) {
	inner := newFakeRepo()
	id := uuid.New()
	now := nowForTest()
	inner.byName["r"] = &model.Vault{ID: id, Name: "r", DeletedAt: &now}
	inner.byID[id.String()] = inner.byName["r"]

	boom := errors.New("recover cascade boom")
	casc := &failingCascade{err: boom}
	svc := NewVaultService(inner, casc, nil)

	err := svc.RecoverVault(context.Background(), "r", uuid.New())
	if !errors.Is(err, boom) {
		t.Fatalf("expected cascade recover error, got %v", err)
	}
}

// -- PurgeVault error branches -----------------------------------------------

func TestPurgeVault_RefusesDefault(t *testing.T) {
	svc := NewVaultService(newFakeRepo(), &noopCascade{}, nil)
	err := svc.PurgeVault(context.Background(), model.DefaultVaultName, uuid.New())
	if err == nil {
		t.Fatal("expected refusal to purge the default vault")
	}
}

func TestPurgeVault_ActiveVaultFallback(t *testing.T) {
	// Vault is active (not deleted) — PurgeVault must fall back to ReadByName.
	inner := newFakeRepo()
	id := uuid.New()
	inner.byName["active"] = &model.Vault{ID: id, Name: "active", PurgeProtection: false}
	inner.byID[id.String()] = inner.byName["active"]

	svc := NewVaultService(inner, &noopCascade{}, nil)
	if err := svc.PurgeVault(context.Background(), "active", uuid.New()); err != nil {
		t.Fatalf("PurgeVault active vault: %v", err)
	}
}

func TestPurgeVault_PurgeRepoError(t *testing.T) {
	inner := newFakeRepo()
	id := uuid.New()
	now := nowForTest()
	inner.byName["d"] = &model.Vault{ID: id, Name: "d", DeletedAt: &now}
	inner.byID[id.String()] = inner.byName["d"]

	repo := &errVaultRepo{fakeVaultRepo: inner, purgeErr: errors.New("db error")}
	svc := NewVaultService(repo, &noopCascade{}, nil)

	err := svc.PurgeVault(context.Background(), "d", uuid.New())
	if err == nil {
		t.Fatal("expected error from Purge repo call")
	}
}

func TestPurgeVault_NotFoundInBothLists(t *testing.T) {
	svc := NewVaultService(newFakeRepo(), &noopCascade{}, nil)
	err := svc.PurgeVault(context.Background(), "nonexistent", uuid.New())
	if err == nil {
		t.Fatal("expected not-found error")
	}
}

// TestPurgeVault_CascadesContentPurge proves PurgeVault calls
// CascadeRepository.PurgeVaultContents, so secrets/keys/certificates don't
// get stranded when their vault is purged (matching the existing
// access_policies cleanup PurgeVault already performs).
func TestPurgeVault_CascadesContentPurge(t *testing.T) {
	inner := newFakeRepo()
	id := uuid.New()
	now := nowForTest()
	inner.byName["d"] = &model.Vault{ID: id, Name: "d", DeletedAt: &now}
	inner.byID[id.String()] = inner.byName["d"]

	cascade := &noopCascade{}
	svc := NewVaultService(inner, cascade, nil)

	if err := svc.PurgeVault(context.Background(), "d", uuid.New()); err != nil {
		t.Fatalf("PurgeVault: %v", err)
	}
	if cascade.purge != 1 {
		t.Fatalf("expected PurgeVaultContents to be called once, got %d", cascade.purge)
	}
}

// TestPurgeVault_CascadePurgeError proves a cascade purge failure surfaces
// as an error from PurgeVault, rather than being silently swallowed.
func TestPurgeVault_CascadePurgeError(t *testing.T) {
	inner := newFakeRepo()
	id := uuid.New()
	now := nowForTest()
	inner.byName["d"] = &model.Vault{ID: id, Name: "d", DeletedAt: &now}
	inner.byID[id.String()] = inner.byName["d"]

	boom := errors.New("cascade purge failed")
	svc := NewVaultService(inner, &failingCascade{err: boom}, nil)

	err := svc.PurgeVault(context.Background(), "d", uuid.New())
	if err == nil || !errors.Is(err, boom) {
		t.Fatalf("expected cascade purge error to propagate, got %v", err)
	}
}

// TestPurgeVault_RefusesWhenContentsProtected proves a vault purge is
// refused when a contained secret/key/certificate has its own
// purge_protection flag set, even though the vault itself is unprotected --
// closing B22, where the cascade purge previously bypassed item-level
// protection entirely.
func TestPurgeVault_RefusesWhenContentsProtected(t *testing.T) {
	inner := newFakeRepo()
	id := uuid.New()
	now := nowForTest()
	inner.byName["d"] = &model.Vault{ID: id, Name: "d", PurgeProtection: false, DeletedAt: &now}
	inner.byID[id.String()] = inner.byName["d"]

	cascade := &noopCascade{protected: true}
	svc := NewVaultService(inner, cascade, nil)

	err := svc.PurgeVault(context.Background(), "d", uuid.New())
	if !errors.Is(err, ErrVaultContentsPurgeProtected) {
		t.Fatalf("expected ErrVaultContentsPurgeProtected, got %v", err)
	}
	if cascade.purge != 0 {
		t.Fatalf("expected PurgeVaultContents not to be called, got %d calls", cascade.purge)
	}
	if _, ok := inner.byID[id.String()]; !ok {
		t.Fatal("expected the vault itself to remain unpurged")
	}
}

// TestPurgeVault_ContentsProtectionCheckError_FailsClosed proves that if the
// purge-protection check itself errors, PurgeVault refuses rather than
// risking a bypass of an item's protection because its status couldn't be
// read.
func TestPurgeVault_ContentsProtectionCheckError_FailsClosed(t *testing.T) {
	inner := newFakeRepo()
	id := uuid.New()
	now := nowForTest()
	inner.byName["d"] = &model.Vault{ID: id, Name: "d", PurgeProtection: false, DeletedAt: &now}
	inner.byID[id.String()] = inner.byName["d"]

	boom := errors.New("db unavailable")
	cascade := &noopCascade{protectedErr: boom}
	svc := NewVaultService(inner, cascade, nil)

	err := svc.PurgeVault(context.Background(), "d", uuid.New())
	if !errors.Is(err, boom) {
		t.Fatalf("expected the check error to propagate, got %v", err)
	}
	if cascade.purge != 0 {
		t.Fatalf("expected PurgeVaultContents not to be called, got %d calls", cascade.purge)
	}
}

// -- ListVaults error branches -----------------------------------------------

func TestListVaults_ListError(t *testing.T) {
	inner := newFakeRepo()
	repo := &errVaultRepo{fakeVaultRepo: inner, listErr: errors.New("db error")}
	svc := NewVaultService(repo, &noopCascade{}, nil)

	_, err := svc.ListVaults(context.Background(), false)
	if err == nil {
		t.Fatal("expected list error")
	}
}

func TestListVaults_ListDeletedError(t *testing.T) {
	inner := newFakeRepo()
	repo := &errVaultRepo{fakeVaultRepo: inner, listDeletedErr: errors.New("db error")}
	svc := NewVaultService(repo, &noopCascade{}, nil)

	_, err := svc.ListVaults(context.Background(), true)
	if err == nil {
		t.Fatal("expected list-deleted error")
	}
}

// -- cascade adapter recover error path -------------------------------------

func TestCascadeAdapter_RecoverError(t *testing.T) {
	boom := errors.New("recover error")
	failing := &failingRepo{err: boom}
	later := &recordingRepo{}
	ad := NewCascadeAdapter(failing, later)

	err := ad.RecoverVaultContents(context.Background(), uuid.New(), time.Now())
	if !errors.Is(err, boom) {
		t.Fatalf("expected first repo error, got %v", err)
	}
	if later.recoverCalls != 0 {
		t.Fatalf("expected later repo not to be called after error")
	}
}

// failingCascade is a CascadeRepository that always returns an error.
type failingCascade struct{ err error }

func (f *failingCascade) SoftDeleteVaultContents(context.Context, uuid.UUID, time.Time) error {
	return f.err
}
func (f *failingCascade) RecoverVaultContents(context.Context, uuid.UUID, time.Time) error {
	return f.err
}
func (f *failingCascade) SoftDeleteVaultContentsTx(context.Context, db.DBTX, uuid.UUID, time.Time) error {
	return f.err
}
func (f *failingCascade) RecoverVaultContentsTx(context.Context, db.DBTX, uuid.UUID, time.Time) error {
	return f.err
}
func (f *failingCascade) PurgeVaultContents(context.Context, uuid.UUID) error {
	return f.err
}
func (f *failingCascade) HasProtectedContent(context.Context, uuid.UUID) (bool, error) {
	return false, f.err
}
