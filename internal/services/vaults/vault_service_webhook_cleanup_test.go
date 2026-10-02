package vaults

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/google/uuid"

	"rocketvault/model"
)

// spyWebhookCleaner records the vault ids it was asked to clean.
type spyWebhookCleaner struct {
	cleaned []uuid.UUID
	err     error
}

func (s *spyWebhookCleaner) DeleteByVaultID(_ context.Context, vaultID uuid.UUID) error {
	s.cleaned = append(s.cleaned, vaultID)
	return s.err
}

// TestPurgeVault_RemovesWebhookConfig is the real cascade test. The DDL's ON
// DELETE CASCADE is inert on SQLite (the foreign_keys PRAGMA is off in this
// project), so the application-level hook is the actual mechanism keeping a
// purged vault from stranding a row that holds an encrypted signing secret.
func TestPurgeVault_RemovesWebhookConfig(t *testing.T) {
	repo := newFakeRepo()
	id := uuid.New()
	now := nowForTest()
	repo.byName["doomed"] = &model.Vault{ID: id, Name: "doomed", PurgeProtection: false, DeletedAt: &now}
	repo.byID[id.String()] = repo.byName["doomed"]
	svc := NewVaultService(repo, &noopCascade{}, nil)

	spy := &spyWebhookCleaner{}
	svc.SetWebhookCleaner(spy)

	if err := svc.PurgeVault(context.Background(), "doomed", uuid.New()); err != nil {
		t.Fatalf("PurgeVault: %v", err)
	}

	if len(spy.cleaned) != 1 {
		t.Fatalf("expected purge to clean the vault's webhook config once, got %d", len(spy.cleaned))
	}
	if spy.cleaned[0] != id {
		t.Fatalf("expected webhook config cleaned for vault %s, got %s", id, spy.cleaned[0])
	}
}

// TestPurgeVault_WebhookCleanerErrorSurfaces keeps a failed cleanup from
// being swallowed -- a silently-skipped cleanup is exactly the
// stranded-secret bug this hook exists to prevent. This matches the
// established PolicyCleaner posture (vault_service.go's PurgeVault returns
// a wrapped error rather than logging and continuing), so the webhook
// cleaner follows the same shape for consistency across purge cleaners.
func TestPurgeVault_WebhookCleanerErrorSurfaces(t *testing.T) {
	repo := newFakeRepo()
	id := uuid.New()
	now := nowForTest()
	repo.byName["doomed"] = &model.Vault{ID: id, Name: "doomed", PurgeProtection: false, DeletedAt: &now}
	repo.byID[id.String()] = repo.byName["doomed"]
	svc := NewVaultService(repo, &noopCascade{}, nil)

	svc.SetWebhookCleaner(&spyWebhookCleaner{err: errors.New("boom")})

	err := svc.PurgeVault(context.Background(), "doomed", uuid.New())
	if err == nil {
		t.Fatal("expected the webhook cleaner error to surface")
	}
	if got := err.Error(); !strings.Contains(got, "webhook") {
		t.Fatalf("expected error to mention webhook, got %q", got)
	}
}

// TestPurgeVault_NoWebhookCleanerIsFine keeps the hook optional, matching
// PolicyCleaner: a service constructed without one must still purge.
func TestPurgeVault_NoWebhookCleanerIsFine(t *testing.T) {
	repo := newFakeRepo()
	id := uuid.New()
	now := nowForTest()
	repo.byName["doomed"] = &model.Vault{ID: id, Name: "doomed", PurgeProtection: false, DeletedAt: &now}
	repo.byID[id.String()] = repo.byName["doomed"]
	svc := NewVaultService(repo, &noopCascade{}, nil)

	if err := svc.PurgeVault(context.Background(), "doomed", uuid.New()); err != nil {
		t.Fatalf("expected purge to succeed without a webhook cleaner set, got %v", err)
	}
}
