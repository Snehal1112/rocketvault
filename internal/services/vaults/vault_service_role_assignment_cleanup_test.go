package vaults

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/google/uuid"

	"rocketvault/model"
)

// spyRoleAssignmentCleaner records the vault ids it was asked to clean.
type spyRoleAssignmentCleaner struct {
	cleaned []uuid.UUID
	err     error
}

func (s *spyRoleAssignmentCleaner) DeleteByVault(_ context.Context, vaultID uuid.UUID) error {
	s.cleaned = append(s.cleaned, vaultID)
	return s.err
}

// TestPurgeVault_RemovesRoleAssignments is the real cascade test.
// role_assignments declares ON DELETE CASCADE on vault_id, but that clause is
// inert on SQLite (the foreign_keys PRAGMA is off in this project), so the
// application-level hook is the actual mechanism keeping a purged vault from
// stranding its role-assignment rows.
func TestPurgeVault_RemovesRoleAssignments(t *testing.T) {
	repo := newFakeRepo()
	id := uuid.New()
	now := nowForTest()
	repo.byName["doomed"] = &model.Vault{ID: id, Name: "doomed", PurgeProtection: false, DeletedAt: &now}
	repo.byID[id.String()] = repo.byName["doomed"]
	svc := NewVaultService(repo, &noopCascade{}, nil)

	spy := &spyRoleAssignmentCleaner{}
	svc.SetRoleAssignmentCleaner(spy)

	if err := svc.PurgeVault(context.Background(), "doomed", uuid.New()); err != nil {
		t.Fatalf("PurgeVault: %v", err)
	}

	if len(spy.cleaned) != 1 {
		t.Fatalf("expected purge to clean the vault's role assignments once, got %d", len(spy.cleaned))
	}
	if spy.cleaned[0] != id {
		t.Fatalf("expected role assignments cleaned for vault %s, got %s", id, spy.cleaned[0])
	}
}

// TestPurgeVault_RoleAssignmentCleanerErrorSurfaces keeps a failed cleanup
// from being swallowed -- a silently-skipped cleanup is exactly the
// stranded-row bug this hook exists to prevent. This matches the established
// PolicyCleaner/WebhookCleaner posture (vault_service.go's PurgeVault returns
// a wrapped error rather than logging and continuing), so the role-assignment
// cleaner follows the same shape for consistency across purge cleaners.
func TestPurgeVault_RoleAssignmentCleanerErrorSurfaces(t *testing.T) {
	repo := newFakeRepo()
	id := uuid.New()
	now := nowForTest()
	repo.byName["doomed"] = &model.Vault{ID: id, Name: "doomed", PurgeProtection: false, DeletedAt: &now}
	repo.byID[id.String()] = repo.byName["doomed"]
	svc := NewVaultService(repo, &noopCascade{}, nil)

	svc.SetRoleAssignmentCleaner(&spyRoleAssignmentCleaner{err: errors.New("boom")})

	err := svc.PurgeVault(context.Background(), "doomed", uuid.New())
	if err == nil {
		t.Fatal("expected the role-assignment cleaner error to surface")
	}
	if got := err.Error(); !strings.Contains(got, "role") {
		t.Fatalf("expected error to mention role assignments, got %q", got)
	}
}

// TestPurgeVault_NoRoleAssignmentCleanerIsFine keeps the hook optional,
// matching PolicyCleaner/WebhookCleaner: a service constructed without one
// must still purge.
func TestPurgeVault_NoRoleAssignmentCleanerIsFine(t *testing.T) {
	repo := newFakeRepo()
	id := uuid.New()
	now := nowForTest()
	repo.byName["doomed"] = &model.Vault{ID: id, Name: "doomed", PurgeProtection: false, DeletedAt: &now}
	repo.byID[id.String()] = repo.byName["doomed"]
	svc := NewVaultService(repo, &noopCascade{}, nil)

	if err := svc.PurgeVault(context.Background(), "doomed", uuid.New()); err != nil {
		t.Fatalf("expected purge to succeed without a role-assignment cleaner set, got %v", err)
	}
}
