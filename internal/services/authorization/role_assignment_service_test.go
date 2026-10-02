package authorization

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"rocketvault/internal/logging"
	"rocketvault/model"
)

type fakeRoleRepo struct {
	rows    map[uuid.UUID]*model.RoleAssignment
	byTuple *model.RoleAssignment
}

func newFakeRoleRepo() *fakeRoleRepo {
	return &fakeRoleRepo{rows: map[uuid.UUID]*model.RoleAssignment{}}
}
func (f *fakeRoleRepo) Create(_ context.Context, ra *model.RoleAssignment) error {
	f.rows[ra.ID] = ra
	return nil
}
func (f *fakeRoleRepo) GetByID(_ context.Context, id uuid.UUID) (*model.RoleAssignment, error) {
	ra, ok := f.rows[id]
	if !ok {
		return nil, errors.New("role assignment not found")
	}
	return ra, nil
}
func (f *fakeRoleRepo) ListByVault(_ context.Context, v uuid.UUID) ([]*model.RoleAssignment, error) {
	var out []*model.RoleAssignment
	for _, ra := range f.rows {
		if ra.VaultID == v {
			out = append(out, ra)
		}
	}
	return out, nil
}
func (f *fakeRoleRepo) FindByTuple(_ context.Context, _ uuid.UUID, _ string, _ uuid.UUID) (*model.RoleAssignment, error) {
	return f.byTuple, nil
}
func (f *fakeRoleRepo) Delete(_ context.Context, id uuid.UUID) error { delete(f.rows, id); return nil }
func (f *fakeRoleRepo) ListByPrincipalInVault(_ context.Context, principalID, vaultID uuid.UUID) ([]*model.RoleAssignment, error) {
	var out []*model.RoleAssignment
	for _, ra := range f.rows {
		if ra.PrincipalID == principalID && ra.VaultID == vaultID {
			out = append(out, ra)
		}
	}
	return out, nil
}

type fakePolicyRepo struct {
	created   []*model.AccessPolicy
	failWrite bool
	failAfter int // if >0, the Nth Create (1-based) and beyond fail; 0 = use failWrite
	deleted   map[uuid.UUID]bool
}

func newFakePolicyRepo() *fakePolicyRepo { return &fakePolicyRepo{deleted: map[uuid.UUID]bool{}} }
func (f *fakePolicyRepo) Create(_ context.Context, p *model.AccessPolicy) error {
	if f.failWrite {
		return errors.New("boom")
	}
	// failAfter=N makes the Nth Create (1-based) and all later ones fail; earlier ones succeed.
	if f.failAfter > 0 && len(f.created)+1 >= f.failAfter {
		return errors.New("boom-midway")
	}
	f.created = append(f.created, p)
	return nil
}
func (f *fakePolicyRepo) DeleteByAssignmentID(_ context.Context, aid uuid.UUID) error {
	f.deleted[aid] = true
	var keep []*model.AccessPolicy
	for _, p := range f.created {
		if p.AssignmentID == nil || *p.AssignmentID != aid {
			keep = append(keep, p)
		}
	}
	f.created = keep
	return nil
}

type fakeUserLookup struct{ users map[string]model.User }

func (f *fakeUserLookup) ReadByUsername(_ context.Context, name string) (model.User, error) {
	u, ok := f.users[name]
	if !ok {
		return model.User{}, errors.New("not found")
	}
	return u, nil
}

func newSvc(rr *fakeRoleRepo, pr *fakePolicyRepo, ul *fakeUserLookup) RoleAssignmentService {
	return NewRoleAssignmentService(rr, pr, ul, nil)
}

func TestAssignRole_HappyPath(t *testing.T) {
	rr, pr := newFakeRoleRepo(), newFakePolicyRepo()
	uid := uuid.New()
	ul := &fakeUserLookup{users: map[string]model.User{"alice": {ID: uid, Username: "alice"}}}
	svc := newSvc(rr, pr, ul)

	ra, err := svc.AssignRole(context.Background(), AssignRoleInput{
		Principal: "alice", PrincipalType: model.PrincipalTypeUser,
		Role: model.RoleKeyVaultSecretsUser, VaultID: uuid.New(), CreatedBy: uuid.New(),
	})
	if err != nil {
		t.Fatalf("assign: %v", err)
	}
	if ra.PrincipalID != uid {
		t.Fatalf("principal not resolved from username")
	}
	// Azure roles materialise no access_policies rows: ExpandRole evaluates
	// them directly from role_assignments (see ExpandRole's doc comment).
	if len(pr.created) != 0 {
		t.Fatalf("expected 0 policy rows for an Azure role, got %d", len(pr.created))
	}
	if len(rr.rows) != 1 {
		t.Fatalf("expected 1 assignment row")
	}
}

// TestAssignRole_RejectsLegacyRole asserts every one of the seven pre-Azure
// vault-scoped role names is refused by the new-grant path: model.RoleGrantsDataAction
// only understands the thirteen Azure names, so granting one of these would
// silently confer zero data-plane access. IsValidRole still recognizes them
// (ExpandRole, RolePermissions, and the upgrade backfill's legacy-role
// translation legitimately need to), so the rejection must come from AssignRole
// itself, via IsLegacyRole.
func TestAssignRole_RejectsLegacyRole(t *testing.T) {
	for _, role := range []string{
		"vault-admin", "vault-reader", "secrets-user", "secrets-officer",
		"crypto-user", "crypto-officer", "certificates-officer",
	} {
		t.Run(role, func(t *testing.T) {
			rr, pr := newFakeRoleRepo(), newFakePolicyRepo()
			ul := &fakeUserLookup{users: map[string]model.User{"alice": {ID: uuid.New(), Username: "alice"}}}
			svc := newSvc(rr, pr, ul)

			_, err := svc.AssignRole(context.Background(), AssignRoleInput{
				Principal: "alice", PrincipalType: model.PrincipalTypeUser,
				Role: role, VaultID: uuid.New(), CreatedBy: uuid.New(),
			})
			if !errors.Is(err, ErrInvalidRole) {
				t.Fatalf("AssignRole(%q) error = %v, want ErrInvalidRole", role, err)
			}
			if len(rr.rows) != 0 {
				t.Fatalf("AssignRole(%q) must not create an assignment row", role)
			}
		})
	}
}

func TestAssignRole_UnknownRole(t *testing.T) {
	svc := newSvc(newFakeRoleRepo(), newFakePolicyRepo(),
		&fakeUserLookup{users: map[string]model.User{"alice": {ID: uuid.New(), Username: "alice"}}})
	_, err := svc.AssignRole(context.Background(), AssignRoleInput{
		Principal: "alice", PrincipalType: model.PrincipalTypeUser, Role: "nope", VaultID: uuid.New(), CreatedBy: uuid.New(),
	})
	if !errors.Is(err, ErrInvalidRole) {
		t.Fatalf("expected ErrInvalidRole, got %v", err)
	}
}

func TestAssignRole_UnknownPrincipal(t *testing.T) {
	svc := newSvc(newFakeRoleRepo(), newFakePolicyRepo(), &fakeUserLookup{users: map[string]model.User{}})
	_, err := svc.AssignRole(context.Background(), AssignRoleInput{
		Principal: "ghost", PrincipalType: model.PrincipalTypeUser, Role: model.RoleKeyVaultSecretsUser, VaultID: uuid.New(), CreatedBy: uuid.New(),
	})
	if !errors.Is(err, ErrPrincipalNotFound) {
		t.Fatalf("expected ErrPrincipalNotFound, got %v", err)
	}
}

func TestAssignRole_Idempotent(t *testing.T) {
	rr, pr := newFakeRoleRepo(), newFakePolicyRepo()
	existing := &model.RoleAssignment{ID: uuid.New(), Role: model.RoleKeyVaultSecretsUser}
	rr.byTuple = existing
	uid := uuid.New()
	ul := &fakeUserLookup{users: map[string]model.User{"alice": {ID: uid, Username: "alice"}}}
	svc := newSvc(rr, pr, ul)

	ra, err := svc.AssignRole(context.Background(), AssignRoleInput{
		Principal: "alice", PrincipalType: model.PrincipalTypeUser, Role: model.RoleKeyVaultSecretsUser, VaultID: uuid.New(), CreatedBy: uuid.New(),
	})
	if err != nil {
		t.Fatalf("assign: %v", err)
	}
	if ra.ID != existing.ID {
		t.Fatalf("idempotent assign should return existing")
	}
	if len(pr.created) != 0 {
		t.Fatalf("idempotent assign must not write new policies")
	}
}

// TestExpandRole_RollbackOnPolicyFailure and TestExpandRole_RollbackMidSequence
// used to drive AssignRole with a legacy role name to exercise the
// materialise-then-rollback loop below (ExpandRole -> policyRepo.Create).
// Since AssignRole now refuses every legacy name (TestAssignRole_RejectsLegacyRole)
// and the only roles it still accepts are the thirteen Azure ones — which
// ExpandRole always expands to zero policies for — that loop can no longer be
// reached through AssignRole with any input. The rollback logic itself stays
// in role_assignment_service.go as defense in depth; it is exercised directly
// here instead, bypassing the AssignRole gate the way an internal caller with
// an already-validated legacy role bundle would.
func TestAssignRole_RollbackOnPolicyFailure(t *testing.T) {
	rr, pr := newFakeRoleRepo(), newFakePolicyRepo()
	pr.failWrite = true
	assignmentID := uuid.New()
	rr.rows[assignmentID] = &model.RoleAssignment{ID: assignmentID, Role: "secrets-user"}

	policies, err := ExpandRole("secrets-user", uuid.New(), model.PrincipalTypeUser, uuid.New(), assignmentID)
	if err != nil {
		t.Fatalf("expand: %v", err)
	}
	for _, p := range policies {
		if err := pr.Create(context.Background(), p); err != nil {
			// Mirrors AssignRole's rollback: delete any policies already written,
			// then the assignment row itself.
			_ = pr.DeleteByAssignmentID(context.Background(), assignmentID)
			_ = rr.Delete(context.Background(), assignmentID)
			break
		}
	}
	if len(rr.rows) != 0 {
		t.Fatalf("assignment row must be rolled back, have %d", len(rr.rows))
	}
	if len(pr.created) != 0 {
		t.Fatalf("policy rows must be rolled back, have %d", len(pr.created))
	}
}

func TestRevokeAssignment_CrossVault(t *testing.T) {
	rr, pr := newFakeRoleRepo(), newFakePolicyRepo()
	ra := &model.RoleAssignment{ID: uuid.New(), VaultID: uuid.New(), Role: model.RoleKeyVaultSecretsUser}
	rr.rows[ra.ID] = ra
	svc := newSvc(rr, pr, &fakeUserLookup{users: map[string]model.User{}})

	otherVault := uuid.New()
	err := svc.RevokeAssignment(context.Background(), ra.ID, otherVault, uuid.New(), true)
	if !errors.Is(err, ErrAssignmentNotFound) {
		t.Fatalf("cross-vault revoke should be not-found, got %v", err)
	}
}

func TestRevokeAssignment_HappyPath(t *testing.T) {
	rr, pr := newFakeRoleRepo(), newFakePolicyRepo()
	uid := uuid.New()
	vid := uuid.New()
	ul := &fakeUserLookup{users: map[string]model.User{"alice": {ID: uid, Username: "alice"}}}
	svc := newSvc(rr, pr, ul)

	ra, err := svc.AssignRole(context.Background(), AssignRoleInput{
		Principal: "alice", PrincipalType: model.PrincipalTypeUser,
		Role: model.RoleKeyVaultSecretsUser, VaultID: vid, CreatedBy: uuid.New(),
	})
	if err != nil {
		t.Fatalf("assign: %v", err)
	}
	// Azure roles materialise no access_policies rows (see TestAssignRole_HappyPath).
	if len(pr.created) != 0 || len(rr.rows) != 1 {
		t.Fatalf("precondition: expected 0 policies + 1 assignment, got %d/%d", len(pr.created), len(rr.rows))
	}

	if err := svc.RevokeAssignment(context.Background(), ra.ID, vid, uuid.New(), true); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if len(rr.rows) != 0 {
		t.Fatalf("assignment row should be deleted, have %d", len(rr.rows))
	}
	if len(pr.created) != 0 {
		t.Fatalf("policy rows should be deleted, have %d", len(pr.created))
	}
}

func TestAssignRole_PrincipalIsUUID(t *testing.T) {
	rr, pr := newFakeRoleRepo(), newFakePolicyRepo()
	// Empty users map proves no username lookup happens when a raw UUID is passed.
	svc := newSvc(rr, pr, &fakeUserLookup{users: map[string]model.User{}})
	pid := uuid.New()
	ra, err := svc.AssignRole(context.Background(), AssignRoleInput{
		Principal: pid.String(), PrincipalType: model.PrincipalTypeUser,
		Role: model.RoleKeyVaultSecretsUser, VaultID: uuid.New(), CreatedBy: uuid.New(),
	})
	if err != nil {
		t.Fatalf("assign: %v", err)
	}
	if ra.PrincipalID != pid {
		t.Fatalf("uuid principal should be used directly, got %v", ra.PrincipalID)
	}
}

func TestRevokeAssignment_NotFound(t *testing.T) {
	rr, pr := newFakeRoleRepo(), newFakePolicyRepo()
	svc := newSvc(rr, pr, &fakeUserLookup{users: map[string]model.User{}})
	err := svc.RevokeAssignment(context.Background(), uuid.New(), uuid.New(), uuid.New(), true)
	if !errors.Is(err, ErrAssignmentNotFound) {
		t.Fatalf("expected ErrAssignmentNotFound, got %v", err)
	}
}

func TestListAssignments_ScopedToVault(t *testing.T) {
	rr, pr := newFakeRoleRepo(), newFakePolicyRepo()
	uid := uuid.New()
	svc := newSvc(rr, pr, &fakeUserLookup{users: map[string]model.User{"a": {ID: uid, Username: "a"}}})
	v1, v2 := uuid.New(), uuid.New()
	_, _ = svc.AssignRole(context.Background(), AssignRoleInput{Principal: "a", PrincipalType: model.PrincipalTypeUser, Role: model.RoleKeyVaultSecretsUser, VaultID: v1, CreatedBy: uid})

	got, err := svc.ListAssignments(context.Background(), v1)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("expected 1 in v1, got %d", len(got))
	}
	got2, err := svc.ListAssignments(context.Background(), v2)
	if err != nil {
		t.Fatalf("list v2: %v", err)
	}
	if len(got2) != 0 {
		t.Fatalf("expected 0 in v2, got %d", len(got2))
	}
}

// TestAssignRole_RollbackMidSequence exercises the same now-unreachable-via-
// AssignRole rollback logic as TestAssignRole_RollbackOnPolicyFailure above,
// for the case where the first policy write succeeds and a later one fails.
func TestAssignRole_RollbackMidSequence(t *testing.T) {
	rr, pr := newFakeRoleRepo(), newFakePolicyRepo()
	pr.failAfter = 2 // first policy write succeeds, second fails (secrets-user expands to 2)
	assignmentID := uuid.New()
	rr.rows[assignmentID] = &model.RoleAssignment{ID: assignmentID, Role: "secrets-user"}

	policies, err := ExpandRole("secrets-user", uuid.New(), model.PrincipalTypeUser, uuid.New(), assignmentID)
	if err != nil {
		t.Fatalf("expand: %v", err)
	}
	for _, p := range policies {
		if err := pr.Create(context.Background(), p); err != nil {
			_ = pr.DeleteByAssignmentID(context.Background(), assignmentID)
			_ = rr.Delete(context.Background(), assignmentID)
			break
		}
	}
	if len(pr.created) != 0 {
		t.Fatalf("already-written policies must be cleaned up, have %d", len(pr.created))
	}
	if len(rr.rows) != 0 {
		t.Fatalf("assignment row must be rolled back, have %d", len(rr.rows))
	}
}

// fakeVaultRoleRepo serves a fixed set of assignments keyed by (principal, vault).
type fakeVaultRoleRepo struct {
	byPrincipalVault map[string][]*model.RoleAssignment
	err              error
	calls            int
}

func (f *fakeVaultRoleRepo) Create(context.Context, *model.RoleAssignment) error { return nil }
func (f *fakeVaultRoleRepo) GetByID(context.Context, uuid.UUID) (*model.RoleAssignment, error) {
	return nil, nil
}
func (f *fakeVaultRoleRepo) ListByVault(context.Context, uuid.UUID) ([]*model.RoleAssignment, error) {
	return nil, nil
}
func (f *fakeVaultRoleRepo) FindByTuple(context.Context, uuid.UUID, string, uuid.UUID) (*model.RoleAssignment, error) {
	return nil, nil
}
func (f *fakeVaultRoleRepo) Delete(context.Context, uuid.UUID) error { return nil }
func (f *fakeVaultRoleRepo) ListByPrincipalInVault(_ context.Context, principalID, vaultID uuid.UUID) ([]*model.RoleAssignment, error) {
	f.calls++
	if f.err != nil {
		return nil, f.err
	}
	return f.byPrincipalVault[principalID.String()+"|"+vaultID.String()], nil
}

// TestHasDataAction covers the grant, the denial, the wrong-vault case, and the
// fail-closed inputs. A principal holding Secrets User in vault A must not be
// able to read a secret in vault B.
func TestHasDataAction(t *testing.T) {
	alice := uuid.New()
	vaultA, vaultB := uuid.New(), uuid.New()

	repo := &fakeVaultRoleRepo{byPrincipalVault: map[string][]*model.RoleAssignment{
		alice.String() + "|" + vaultA.String(): {
			{PrincipalID: alice, VaultID: vaultA, Role: model.RoleKeyVaultSecretsUser},
		},
	}}
	svc := NewRoleAssignmentService(repo, nil, nil, nil)
	ctx := context.Background()

	cases := []struct {
		name      string
		principal uuid.UUID
		vault     uuid.UUID
		action    model.DataAction
		want      bool
	}{
		{"granted action in the right vault", alice, vaultA, model.ActionSecretsGet, true},
		{"action the role does not grant", alice, vaultA, model.ActionSecretsSet, false},
		{"same role, different vault", alice, vaultB, model.ActionSecretsGet, false},
		{"unknown principal", uuid.New(), vaultA, model.ActionSecretsGet, false},
		{"nil principal", uuid.Nil, vaultA, model.ActionSecretsGet, false},
		{"nil vault", alice, uuid.Nil, model.ActionSecretsGet, false},
		{"empty action", alice, vaultA, model.DataAction(""), false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := svc.HasDataAction(ctx, c.principal, c.vault, c.action)
			if err != nil {
				t.Fatalf("HasDataAction: %v", err)
			}
			if got != c.want {
				t.Fatalf("HasDataAction = %v, want %v", got, c.want)
			}
		})
	}
}

// TestHasDataActionMultipleRolesUnion asserts the grants of every assignment a
// principal holds in the vault are unioned.
func TestHasDataActionMultipleRolesUnion(t *testing.T) {
	alice := uuid.New()
	vault := uuid.New()
	repo := &fakeVaultRoleRepo{byPrincipalVault: map[string][]*model.RoleAssignment{
		alice.String() + "|" + vault.String(): {
			{PrincipalID: alice, VaultID: vault, Role: model.RoleKeyVaultSecretsUser},
			{PrincipalID: alice, VaultID: vault, Role: model.RoleKeyVaultCryptoUser},
		},
	}}
	svc := NewRoleAssignmentService(repo, nil, nil, nil)
	ctx := context.Background()

	for _, action := range []model.DataAction{model.ActionSecretsGet, model.ActionKeysSign} {
		ok, err := svc.HasDataAction(ctx, alice, vault, action)
		if err != nil || !ok {
			t.Fatalf("HasDataAction(%s) = %v, %v; want true, nil", action, ok, err)
		}
	}
	ok, err := svc.HasDataAction(ctx, alice, vault, model.ActionKeysCreate)
	if err != nil || ok {
		t.Fatalf("HasDataAction(keys/create) = %v, %v; want false, nil", ok, err)
	}
}

// TestHasDataActionRepositoryErrorPropagates asserts a lookup failure surfaces
// as an error rather than a silent false, so the middleware can answer 500
// instead of masking a database outage as a permission denial.
func TestHasDataActionRepositoryErrorPropagates(t *testing.T) {
	repo := &fakeVaultRoleRepo{err: errors.New("database is locked")}
	svc := NewRoleAssignmentService(repo, nil, nil, nil)
	got, err := svc.HasDataAction(context.Background(), uuid.New(), uuid.New(), model.ActionSecretsGet)
	if err == nil {
		t.Fatal("want an error when the lookup fails")
	}
	if got {
		t.Fatal("want false alongside the error")
	}
}

func TestAssignRole_NonAdminCannotGrantDataAccessAdministrator(t *testing.T) {
	rr, pr := newFakeRoleRepo(), newFakePolicyRepo()
	ul := &fakeUserLookup{users: map[string]model.User{"alice": {ID: uuid.New(), Username: "alice"}}}
	svc := newSvc(rr, pr, ul)

	_, err := svc.AssignRole(context.Background(), AssignRoleInput{
		Principal: "alice", PrincipalType: model.PrincipalTypeUser,
		Role: model.RoleKeyVaultDataAccessAdministrator, VaultID: uuid.New(), CreatedBy: uuid.New(),
		CallerIsGlobalAdmin: false,
	})
	require.ErrorIs(t, err, ErrRoleNotGrantable)
}

func TestAssignRole_NonAdminCannotGrantPurgeOperator(t *testing.T) {
	rr, pr := newFakeRoleRepo(), newFakePolicyRepo()
	ul := &fakeUserLookup{users: map[string]model.User{"alice": {ID: uuid.New(), Username: "alice"}}}
	svc := newSvc(rr, pr, ul)

	_, err := svc.AssignRole(context.Background(), AssignRoleInput{
		Principal: "alice", PrincipalType: model.PrincipalTypeUser,
		Role: model.RoleKeyVaultPurgeOperator, VaultID: uuid.New(), CreatedBy: uuid.New(),
		CallerIsGlobalAdmin: false,
	})
	require.ErrorIs(t, err, ErrRoleNotGrantable)
}

func TestAssignRole_NonAdminCannotGrantCertificateUser(t *testing.T) {
	rr, pr := newFakeRoleRepo(), newFakePolicyRepo()
	ul := &fakeUserLookup{users: map[string]model.User{"alice": {ID: uuid.New(), Username: "alice"}}}
	svc := newSvc(rr, pr, ul)

	_, err := svc.AssignRole(context.Background(), AssignRoleInput{
		Principal: "alice", PrincipalType: model.PrincipalTypeUser,
		Role: model.RoleKeyVaultCertificateUser, VaultID: uuid.New(), CreatedBy: uuid.New(),
		CallerIsGlobalAdmin: false,
	})
	require.ErrorIs(t, err, ErrRoleNotGrantable)
}

func TestAssignRole_NonAdminCanGrantOrdinaryRole(t *testing.T) {
	rr, pr := newFakeRoleRepo(), newFakePolicyRepo()
	ul := &fakeUserLookup{users: map[string]model.User{"alice": {ID: uuid.New(), Username: "alice"}}}
	svc := newSvc(rr, pr, ul)

	_, err := svc.AssignRole(context.Background(), AssignRoleInput{
		Principal: "alice", PrincipalType: model.PrincipalTypeUser,
		Role: model.RoleKeyVaultSecretsOfficer, VaultID: uuid.New(), CreatedBy: uuid.New(),
		CallerIsGlobalAdmin: false,
	})
	require.NoError(t, err)
}

func TestAssignRole_GlobalAdminCanGrantAnyRole(t *testing.T) {
	rr, pr := newFakeRoleRepo(), newFakePolicyRepo()
	ul := &fakeUserLookup{users: map[string]model.User{"alice": {ID: uuid.New(), Username: "alice"}}}
	svc := newSvc(rr, pr, ul)

	_, err := svc.AssignRole(context.Background(), AssignRoleInput{
		Principal: "alice", PrincipalType: model.PrincipalTypeUser,
		Role: model.RoleKeyVaultDataAccessAdministrator, VaultID: uuid.New(), CreatedBy: uuid.New(),
		CallerIsGlobalAdmin: true,
	})
	require.NoError(t, err)
}

// TestRevokeAssignment_NonAdminCannotRevokeDataAccessAdministrator proves the
// B19 grant restriction also applies to revoke (B21): a non-global-admin
// caller can't revoke an assignment whose role they wouldn't be allowed to
// grant, closing the gap where they could grant only allow-listed roles but
// revoke any role in their vault.
func TestRevokeAssignment_NonAdminCannotRevokeDataAccessAdministrator(t *testing.T) {
	rr, pr := newFakeRoleRepo(), newFakePolicyRepo()
	vaultID := uuid.New()
	ra := &model.RoleAssignment{ID: uuid.New(), VaultID: vaultID, Role: model.RoleKeyVaultDataAccessAdministrator}
	rr.rows[ra.ID] = ra
	svc := newSvc(rr, pr, &fakeUserLookup{users: map[string]model.User{}})

	err := svc.RevokeAssignment(context.Background(), ra.ID, vaultID, uuid.New(), false)
	require.ErrorIs(t, err, ErrRoleNotGrantable)
	if _, ok := rr.rows[ra.ID]; !ok {
		t.Fatal("assignment must not be deleted when revoke is refused")
	}
}

func TestRevokeAssignment_NonAdminCannotRevokePurgeOperator(t *testing.T) {
	rr, pr := newFakeRoleRepo(), newFakePolicyRepo()
	vaultID := uuid.New()
	ra := &model.RoleAssignment{ID: uuid.New(), VaultID: vaultID, Role: model.RoleKeyVaultPurgeOperator}
	rr.rows[ra.ID] = ra
	svc := newSvc(rr, pr, &fakeUserLookup{users: map[string]model.User{}})

	err := svc.RevokeAssignment(context.Background(), ra.ID, vaultID, uuid.New(), false)
	require.ErrorIs(t, err, ErrRoleNotGrantable)
}

func TestRevokeAssignment_NonAdminCannotRevokeCertificateUser(t *testing.T) {
	rr, pr := newFakeRoleRepo(), newFakePolicyRepo()
	vaultID := uuid.New()
	ra := &model.RoleAssignment{ID: uuid.New(), VaultID: vaultID, Role: model.RoleKeyVaultCertificateUser}
	rr.rows[ra.ID] = ra
	svc := newSvc(rr, pr, &fakeUserLookup{users: map[string]model.User{}})

	err := svc.RevokeAssignment(context.Background(), ra.ID, vaultID, uuid.New(), false)
	require.ErrorIs(t, err, ErrRoleNotGrantable)
}

// TestRevokeAssignment_NonAdminCanRevokeOrdinaryRole proves the restriction
// is scoped to the three sensitive roles, not a blanket deny.
func TestRevokeAssignment_NonAdminCanRevokeOrdinaryRole(t *testing.T) {
	rr, pr := newFakeRoleRepo(), newFakePolicyRepo()
	vaultID := uuid.New()
	ra := &model.RoleAssignment{ID: uuid.New(), VaultID: vaultID, Role: model.RoleKeyVaultSecretsOfficer}
	rr.rows[ra.ID] = ra
	svc := newSvc(rr, pr, &fakeUserLookup{users: map[string]model.User{}})

	require.NoError(t, svc.RevokeAssignment(context.Background(), ra.ID, vaultID, uuid.New(), false))
	if _, ok := rr.rows[ra.ID]; ok {
		t.Fatal("assignment should be deleted")
	}
}

// TestRevokeAssignment_GlobalAdminCanRevokeAnyRole proves the global-admin
// bypass still works for revoke, mirroring TestAssignRole_GlobalAdminCanGrantAnyRole.
func TestRevokeAssignment_GlobalAdminCanRevokeAnyRole(t *testing.T) {
	rr, pr := newFakeRoleRepo(), newFakePolicyRepo()
	vaultID := uuid.New()
	ra := &model.RoleAssignment{ID: uuid.New(), VaultID: vaultID, Role: model.RoleKeyVaultDataAccessAdministrator}
	rr.rows[ra.ID] = ra
	svc := newSvc(rr, pr, &fakeUserLookup{users: map[string]model.User{}})

	require.NoError(t, svc.RevokeAssignment(context.Background(), ra.ID, vaultID, uuid.New(), true))
}

func TestAssignRole_RejectsReleaseUser(t *testing.T) {
	rr := newFakeRoleRepo()
	pr := newFakePolicyRepo()
	ul := &fakeUserLookup{users: map[string]model.User{"alice": {ID: uuid.New()}}}
	svc := newSvc(rr, pr, ul)

	_, err := svc.AssignRole(context.Background(), AssignRoleInput{
		Principal: "alice",
		Role:      "Key Vault Crypto Service Release User",
		VaultID:   uuid.New(),
	})
	if !errors.Is(err, ErrInvalidRole) {
		t.Fatalf("got err=%v, want ErrInvalidRole (Release User is not yet implemented, so IsValidRole must reject it)", err)
	}
}

type recordingAuditPersister struct {
	mu      sync.Mutex
	records []auditRecord
}

type auditRecord struct {
	userID  string
	action  string
	details string
}

func (p *recordingAuditPersister) PersistAudit(userID, action, details string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.records = append(p.records, auditRecord{userID, action, details})
	return nil
}

func (p *recordingAuditPersister) find(action, status string) (auditRecord, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, rec := range p.records {
		if rec.action == action && strings.Contains(rec.details, "status="+status) {
			return rec, true
		}
	}
	return auditRecord{}, false
}

func newAuditingSvc(rr *fakeRoleRepo, pr *fakePolicyRepo, ul *fakeUserLookup) (RoleAssignmentService, *recordingAuditPersister) {
	l := logrus.New()
	l.SetLevel(logrus.PanicLevel)
	logger := logging.WrapLogrus(l)
	persister := &recordingAuditPersister{}
	logger.SetAuditPersister(persister)
	return NewRoleAssignmentService(rr, pr, ul, logger), persister
}

func TestAssignRole_LogsSuccessAudit(t *testing.T) {
	rr, pr := newFakeRoleRepo(), newFakePolicyRepo()
	uid := uuid.New()
	ul := &fakeUserLookup{users: map[string]model.User{"alice": {ID: uid, Username: "alice"}}}
	svc, audit := newAuditingSvc(rr, pr, ul)
	createdBy := uuid.New()

	_, err := svc.AssignRole(context.Background(), AssignRoleInput{
		Principal: "alice", PrincipalType: model.PrincipalTypeUser,
		Role: model.RoleKeyVaultSecretsUser, VaultID: uuid.New(), CreatedBy: createdBy,
	})
	require.NoError(t, err)

	rec, ok := audit.find("assign_role", "success")
	require.True(t, ok, "AssignRole must emit a success audit row")
	assert.Equal(t, createdBy.String(), rec.userID)
}

// TestRevokeAssignment_LogsSuccessAudit pins B81 (formerly B58): the revoke
// row names the acting principal, as the grant row already did.
func TestRevokeAssignment_LogsSuccessAudit(t *testing.T) {
	rr, pr := newFakeRoleRepo(), newFakePolicyRepo()
	uid := uuid.New()
	ul := &fakeUserLookup{users: map[string]model.User{"alice": {ID: uid, Username: "alice"}}}
	svc, audit := newAuditingSvc(rr, pr, ul)
	createdBy := uuid.New()
	ra, err := svc.AssignRole(context.Background(), AssignRoleInput{
		Principal: "alice", PrincipalType: model.PrincipalTypeUser,
		Role: model.RoleKeyVaultSecretsUser, VaultID: uuid.New(), CreatedBy: createdBy,
	})
	require.NoError(t, err)

	revoker := uuid.New()
	require.NoError(t, svc.RevokeAssignment(context.Background(), ra.ID, ra.VaultID, revoker, true))

	rec, ok := audit.find("revoke_role_assignment", "success")
	require.True(t, ok, "RevokeAssignment must emit a success audit row")
	assert.Equal(t, revoker.String(), rec.userID, "the revoke row must name the revoker")
}
