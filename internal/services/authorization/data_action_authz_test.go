package authorization

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"

	"rocketvault/model"
)

// fakeRoleAssignmentService is a minimal test double for RoleAssignmentService,
// returning a fixed decision/error for HasDataAction. The remaining interface
// methods are no-ops; no test in this file exercises them. It also records the
// arguments HasDataAction was called with, so tests can pin that
// RequireDataAction forwards principalID/vaultID/action correctly rather than,
// say, a transposed or zero value.
type fakeRoleAssignmentService struct {
	hasAction bool
	err       error

	// Recorded arguments from the most recent HasDataAction call.
	calledPrincipalID uuid.UUID
	calledVaultID     uuid.UUID
	calledAction      model.DataAction
}

func (f *fakeRoleAssignmentService) AssignRole(ctx context.Context, in AssignRoleInput) (*model.RoleAssignment, error) {
	return nil, nil
}

func (f *fakeRoleAssignmentService) RevokeAssignment(ctx context.Context, assignmentID, vaultID, actorID uuid.UUID, callerIsGlobalAdmin bool) error {
	return nil
}

func (f *fakeRoleAssignmentService) ListAssignments(ctx context.Context, vaultID uuid.UUID) ([]*model.RoleAssignment, error) {
	return nil, nil
}

func (f *fakeRoleAssignmentService) HasDataAction(ctx context.Context, principalID, vaultID uuid.UUID, action model.DataAction) (bool, error) {
	f.calledPrincipalID = principalID
	f.calledVaultID = vaultID
	f.calledAction = action
	return f.hasAction, f.err
}

func TestRequireDataAction_Grants(t *testing.T) {
	roles := &fakeRoleAssignmentService{hasAction: true}
	err := RequireDataAction(context.Background(), roles, uuid.New(), uuid.New(), model.ActionSecretsGet)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
}

func TestRequireDataAction_Denies(t *testing.T) {
	roles := &fakeRoleAssignmentService{hasAction: false}
	err := RequireDataAction(context.Background(), roles, uuid.New(), uuid.New(), model.ActionSecretsGet)
	if err == nil {
		t.Fatal("expected a forbidden error, got nil")
	}
}

func TestRequireDataAction_PropagatesLookupError(t *testing.T) {
	wantErr := errors.New("db exploded")
	roles := &fakeRoleAssignmentService{err: wantErr}
	err := RequireDataAction(context.Background(), roles, uuid.New(), uuid.New(), model.ActionSecretsGet)
	if err == nil || !errors.Is(err, wantErr) {
		t.Fatalf("expected error wrapping %v, got %v", wantErr, err)
	}
}

func TestRequireDataAction_DenyNotConflatedWithLookupError(t *testing.T) {
	// A plain deny (false, nil) must not satisfy errors.Is against some
	// sentinel lookup error — they're different failure classes with
	// different messages, per the design's error-handling section.
	roles := &fakeRoleAssignmentService{hasAction: false}
	err := RequireDataAction(context.Background(), roles, uuid.New(), uuid.New(), model.ActionKeysWrap)
	if errors.Is(err, errors.New("db exploded")) {
		t.Fatal("a plain deny must not resemble a lookup error")
	}
}

func TestRequireDataAction_ForwardsExactArguments(t *testing.T) {
	// Pins that RequireDataAction forwards principalID/vaultID/action through
	// to HasDataAction unchanged rather than, say, a transposed or zero
	// value — a bug today's other tests (which use fixed hasAction/err
	// fields, never inspecting what was actually passed in) would miss.
	roles := &fakeRoleAssignmentService{hasAction: true}
	wantPrincipalID := uuid.New()
	wantVaultID := uuid.New()
	wantAction := model.ActionKeysWrap

	if err := RequireDataAction(context.Background(), roles, wantPrincipalID, wantVaultID, wantAction); err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if roles.calledPrincipalID != wantPrincipalID {
		t.Fatalf("expected principalID %s, got %s", wantPrincipalID, roles.calledPrincipalID)
	}
	if roles.calledVaultID != wantVaultID {
		t.Fatalf("expected vaultID %s, got %s", wantVaultID, roles.calledVaultID)
	}
	if roles.calledAction != wantAction {
		t.Fatalf("expected action %s, got %s", wantAction, roles.calledAction)
	}
}
