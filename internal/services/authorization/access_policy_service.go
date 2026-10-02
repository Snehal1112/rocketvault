package authorization

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"

	"rocketvault/internal/logging"
	"rocketvault/internal/repositories"
	"rocketvault/model"
)

// AccessDecision is the result of CheckAccess.
type AccessDecision int

const (
	// AccessAllowed — an explicit allow policy exists and no deny policy exists.
	AccessAllowed AccessDecision = iota
	// AccessDenied — at least one explicit deny policy exists.
	AccessDenied
	// AccessFallback — no policy row found; caller should use RBAC.
	AccessFallback
)

// AccessPolicyService provides CRUD and access-check operations for access policies.
type AccessPolicyService interface {
	// CheckAccess evaluates policies for the (principal, resourceType, operation) triple
	// within the given vault. Global (nil vault) policies always apply.
	// Returns AccessAllowed, AccessDenied, or AccessFallback (use RBAC).
	CheckAccess(ctx context.Context, principalID uuid.UUID, resourceType model.PolicyResourceType, operation model.PolicyOperation, vaultID uuid.UUID) (AccessDecision, error)

	// CheckVaultScopedAccess evaluates a policy against ONE specific vault. It
	// differs from CheckAccess in exactly one way, and the asymmetry is
	// deliberate: a NULL-scoped (global) DENY still matches, because a global
	// deny must keep blocking every vault; a NULL-scoped ALLOW does not,
	// because an instance-wide allow is a grant to operate on the vault
	// COLLECTION (create, list) and never authority over a vault someone else
	// owns.
	//
	// Callers pass a concrete vaultID. Use CheckAccess, not this, for the
	// collection-level (uuid.Nil) decision.
	CheckVaultScopedAccess(ctx context.Context, principalID uuid.UUID, resourceType model.PolicyResourceType, operation model.PolicyOperation, vaultID uuid.UUID) (AccessDecision, error)

	// CreatePolicy, UpdatePolicy and DeletePolicy write an audit row naming
	// actorID and the policy's principal, resource, operation, effect and
	// scope, because an explicit deny overrides every role grant.
	CreatePolicy(ctx context.Context, policy *model.AccessPolicy, actorID uuid.UUID) error
	GetPolicy(ctx context.Context, id uuid.UUID) (*model.AccessPolicy, error)
	ListPolicies(ctx context.Context) ([]*model.AccessPolicy, error)
	ListByPrincipal(ctx context.Context, principalID uuid.UUID) ([]*model.AccessPolicy, error)
	UpdatePolicy(ctx context.Context, policy *model.AccessPolicy, actorID uuid.UUID) error
	DeletePolicy(ctx context.Context, id, actorID uuid.UUID) error
}

type accessPolicyService struct {
	repo repositories.AccessPolicyRepositoryInterface
	log  *logging.Logger
}

// NewAccessPolicyService creates a new AccessPolicyService backed by repo. The
// logger may be nil, in which case mutations are not audited.
func NewAccessPolicyService(repo repositories.AccessPolicyRepositoryInterface, log *logging.Logger) AccessPolicyService {
	return &accessPolicyService{repo: repo, log: log}
}

// CheckAccess evaluates access policies for the triple (principalID, resourceType, operation).
// Explicit deny always wins. Falls back to RBAC when no matching policy exists.
func (s *accessPolicyService) CheckAccess(ctx context.Context, principalID uuid.UUID, resourceType model.PolicyResourceType, operation model.PolicyOperation, vaultID uuid.UUID) (AccessDecision, error) {
	policies, err := s.repo.FindEffects(ctx, principalID, resourceType, operation, vaultID)
	if err != nil {
		return AccessFallback, fmt.Errorf("policy lookup: %w", err)
	}
	if len(policies) == 0 {
		return AccessFallback, nil
	}
	for _, p := range policies {
		if p.Effect == model.PolicyEffectDeny {
			return AccessDenied, nil
		}
	}
	return AccessAllowed, nil
}

// CheckVaultScopedAccess evaluates access policies for the triple
// (principalID, resourceType, operation) against one specific vault.
//
// It reuses FindEffects — which matches "(vault_id = ? OR vault_id IS NULL)"
// — and then discards NULL-scoped ALLOW rows, keeping NULL-scoped DENY rows.
// The narrowing is applied here rather than in FindEffects or CheckAccess on
// purpose: those two are shared with PolicyMiddleware and
// vaultcli.RequireDataAction for secrets/keys/certificates, where the
// "OR vault_id IS NULL" clause is what makes a global explicit deny work.
func (s *accessPolicyService) CheckVaultScopedAccess(ctx context.Context, principalID uuid.UUID, resourceType model.PolicyResourceType, operation model.PolicyOperation, vaultID uuid.UUID) (AccessDecision, error) {
	policies, err := s.repo.FindEffects(ctx, principalID, resourceType, operation, vaultID)
	if err != nil {
		return AccessFallback, fmt.Errorf("policy lookup: %w", err)
	}

	// Any deny wins outright, whatever its scope, so every row is inspected
	// for a deny before any allow can be honoured.
	scopedAllow := false
	for _, p := range policies {
		if p.Effect == model.PolicyEffectDeny {
			return AccessDenied, nil
		}
		if p.VaultID != nil && *p.VaultID == vaultID {
			scopedAllow = true
		}
	}
	if scopedAllow {
		return AccessAllowed, nil
	}
	// Either no rows, or only NULL-scoped allows -- which confer nothing here.
	return AccessFallback, nil
}

func (s *accessPolicyService) CreatePolicy(ctx context.Context, policy *model.AccessPolicy, actorID uuid.UUID) error {
	if policy.ID == uuid.Nil {
		policy.ID = uuid.New()
	}
	if policy.CreatedAt.IsZero() {
		policy.CreatedAt = time.Now()
	}
	if err := s.repo.Create(ctx, policy); err != nil {
		return err
	}
	s.audit(actorID, "create_access_policy",
		fmt.Sprintf("Access policy %s created: %s", policy.ID, describePolicy(policy)))
	return nil
}

func (s *accessPolicyService) GetPolicy(ctx context.Context, id uuid.UUID) (*model.AccessPolicy, error) {
	return s.repo.GetByID(ctx, id)
}

func (s *accessPolicyService) ListPolicies(ctx context.Context) ([]*model.AccessPolicy, error) {
	return s.repo.List(ctx)
}

func (s *accessPolicyService) ListByPrincipal(ctx context.Context, principalID uuid.UUID) ([]*model.AccessPolicy, error) {
	return s.repo.ListByPrincipal(ctx, principalID)
}

func (s *accessPolicyService) UpdatePolicy(ctx context.Context, policy *model.AccessPolicy, actorID uuid.UUID) error {
	// Read the stored row first so the audit row records the old effect. A
	// failed read loses only the old value; it never blocks the update.
	previous := "unknown"
	if old, err := s.repo.GetByID(ctx, policy.ID); err == nil && old != nil {
		previous = string(old.Effect)
	}
	if err := s.repo.Update(ctx, policy); err != nil {
		return err
	}
	s.audit(actorID, "update_access_policy",
		fmt.Sprintf("Access policy %s updated: effect %s -> %s (%s)", policy.ID, previous, policy.Effect, describePolicy(policy)))
	return nil
}

func (s *accessPolicyService) DeletePolicy(ctx context.Context, id, actorID uuid.UUID) error {
	// Read the row first so the audit row says what the deleted policy did.
	detail := "policy row not readable before delete"
	if old, err := s.repo.GetByID(ctx, id); err == nil && old != nil {
		detail = describePolicy(old)
	}
	if err := s.repo.Delete(ctx, id); err != nil {
		return err
	}
	s.audit(actorID, "delete_access_policy", fmt.Sprintf("Access policy %s deleted: %s", id, detail))
	return nil
}

// describePolicy renders the fields an auditor needs to see what a policy did.
func describePolicy(p *model.AccessPolicy) string {
	scope := "global"
	if p.VaultID != nil {
		scope = "vault " + p.VaultID.String()
	}
	return fmt.Sprintf("principal=%s (%s) resource=%s operation=%s effect=%s scope=%s",
		p.PrincipalID, p.PrincipalType, p.ResourceType, p.Operation, p.Effect, scope)
}

// audit writes one success row when a logger is configured.
func (s *accessPolicyService) audit(actorID uuid.UUID, operation, message string) {
	if s.log != nil {
		s.log.LogAuditInfo(actorID.String(), operation, "success", message)
	}
}
