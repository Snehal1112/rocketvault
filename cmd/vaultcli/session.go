package vaultcli

import (
	"context"
	"fmt"
	"strings"

	"github.com/google/uuid"
	"github.com/spf13/cobra"

	"rocketvault/common"
	"rocketvault/internal/container"
	"rocketvault/internal/logging"
	"rocketvault/internal/services/authorization"
	"rocketvault/model"
)

// Op describes what a data-plane CLI command is about to do, in the terms the
// authorization check needs.
type Op struct {
	// Audit names the operation in the audit log, e.g. "delete_key".
	Audit string

	// Action is the Azure data action this command requires in the target
	// vault. Required: Begin refuses an Op without one, because skipping the
	// data-action check is the single mistake this type exists to prevent.
	Action model.DataAction

	// Policy is what an equivalent HTTP request would resolve to via
	// internal/middleware's resolvePolicy. It cannot be derived from Action:
	// several DataActions are deliberately coarser than PolicyOperation
	// (ActionSecretsSet covers both create's OpCreate and update's OpSet).
	Policy model.PolicyOperation

	// Roles, when non-empty, additionally requires the caller to hold one of
	// these account roles. This is the legacy global-role gate that the HTTP
	// API does not apply -- see the note on Session below.
	Roles []string

	// AuthzFailMsg overrides the message an authorization failure is reported
	// under. It exists because the packages do not agree: cmd/keys reports
	// "vault authorization failed", while cmd/certificates reports the
	// operation that was refused ("failed to delete certificate"). Preserving
	// each command's existing wording keeps this refactor invisible to
	// callers and to the tests that pin those strings. Defaults to
	// "vault authorization failed".
	AuthzFailMsg string
}

// Session is the authorized context a data-plane command runs in: who the
// caller is, which vault they are acting on, and the scope to hand the
// service layer. Begin produces a fully authorized one; Caller produces one
// that still needs Authorize, for commands that validate their input first.
//
// Every CLI command bypasses PolicyMiddleware entirely (see CLAUDE.md's "CLI
// Authorization"), so the RequireDataAction call inside Authorize is the only
// authorization enforcement point on this path. Routing commands through a
// Session is what makes that check structural rather than something each new
// command has to remember: VaultID and Scope are only ever populated by
// Authorize, and an un-authorized Session's zero Scope is ScopeInvalid, which
// every repository rejects. Forgetting the check reads nothing; it does not
// read the wrong vault.
//
// Op.Roles preserves the account-role gate that 22 commands enforce today
// (admin or crypto_manager, etc.). The HTTP handlers for the same operations
// do not apply it, so a principal holding only a vault role assignment can
// create a key over the API but not over the CLI. That divergence is
// pre-existing and deliberately preserved here rather than silently changed;
// it is recorded as an open question, not settled by this refactor.
type Session struct {
	Ctx       context.Context
	Cmd       *cobra.Command
	Claims    *model.Claims
	Container container.ServiceContainerInterface
	Log       *logging.Logger

	// VaultID is the vault the caller was authorized against, and Scope is
	// the model.Scope to pass to the service layer. The scope's actor is the
	// real authenticated caller, never uuid.Nil, so audit rows are attributed
	// to the person who made the request.
	VaultID uuid.UUID
	Scope   model.Scope

	op Op
}

// Begin resolves the caller and authorizes them against the target vault in
// one step: Caller followed by Authorize. Use it for commands that have no
// input to validate before the authorization check.
func Begin(cmd *cobra.Command, op Op) (*Session, error) {
	s, err := Caller(cmd, op)
	if err != nil {
		return nil, err
	}
	if err := s.Authorize(); err != nil {
		return nil, err
	}
	return s, nil
}

// Caller identifies the acting principal and applies op.Roles, without yet
// resolving or authorizing a vault. It is the half of Begin that commands
// which validate their flags before authorizing need -- calling Begin up
// front would reorder authorization ahead of validation, changing which error
// a malformed argument produces.
//
// A Session from Caller has a zero Scope. model.Scope's zero value is
// ScopeInvalid, which every repository and service rejects, so a command that
// forgets Authorize fails closed at the service layer rather than reading
// another vault's data.
func Caller(cmd *cobra.Command, op Op) (*Session, error) {
	if op.Action == "" {
		return nil, fmt.Errorf("vaultcli.Caller: Op.Action is required for %q", op.Audit)
	}

	ctx := cmd.Context()

	claims, err := CtxClaims.From(ctx)
	if err != nil {
		return nil, fmt.Errorf("unauthorized: missing authentication claims")
	}

	log, err := CtxLogger.From(ctx)
	if err != nil {
		return nil, err
	}

	s := &Session{Ctx: ctx, Cmd: cmd, Claims: claims, Log: log, op: op}

	if len(op.Roles) > 0 && !common.HasAnyRole(claims.Roles, op.Roles...) {
		return nil, s.Fail("forbidden: requires "+humanRoles(op.Roles), nil)
	}

	// The service container is deliberately NOT looked up here. Commands that
	// validate their flags first must report a malformed argument as such,
	// even in a context that carries no container -- which is exactly what the
	// hand-written commands did, since their container lookup sat below the
	// validation. Authorize fetches it.
	return s, nil
}

// Authorize resolves the target vault and runs the same two-stage check
// PolicyMiddleware runs for HTTP: the access_policies explicit-deny override,
// then the deny-by-default role-assignment check. On success it fills VaultID
// and Scope.
//
// The CLI bypasses PolicyMiddleware entirely, so this is the only
// authorization enforcement point on this path.
func (s *Session) Authorize() error {
	sc, err := CtxContainer.From(s.Ctx)
	if err != nil || sc == nil {
		return s.Fail("service container not available in context", nil)
	}
	s.Container = sc

	msg := s.op.AuthzFailMsg
	if msg == "" {
		msg = "vault authorization failed"
	}

	vaultID, err := RequireDataAction(s.Ctx, s.Cmd, sc, s.Claims.UserID, s.op.Action, s.op.Policy)
	if err != nil {
		return s.Fail(msg, err)
	}
	s.VaultID = vaultID
	s.Scope = model.NewVaultScope(vaultID, s.Claims.UserID)
	return nil
}

// RequireAlso runs Authorize's two-stage check for one more data action, in
// the vault Authorize already resolved. It is for commands that act on two
// object types at once, such as issuing a certificate with a key. Calling it
// before Authorize fails closed.
func (s *Session) RequireAlso(action model.DataAction, op model.PolicyOperation) error {
	msg := s.op.AuthzFailMsg
	if msg == "" {
		msg = "vault authorization failed"
	}
	if s.Container == nil || s.VaultID == uuid.Nil {
		return s.Fail(msg, fmt.Errorf("RequireAlso called before Authorize"))
	}

	if err := authorization.RequireDataPlaneAccess(s.Ctx, s.Container.GetAccessPolicyService(),
		s.Container.GetRoleAssignmentService(), s.Claims.UserID, s.VaultID,
		resourceTypeFromAction(action), op, action); err != nil {
		return s.Fail(msg, err)
	}
	return nil
}

// Fail records an audit failure for the session's operation and returns the
// error to hand back to cobra. A nil cause produces a bare message, matching
// what the hand-written commands did for validation failures.
func (s *Session) Fail(msg string, cause error) error {
	actor := ""
	if s.Claims != nil {
		actor = s.Claims.UserID.String()
	}
	if s.Log != nil {
		detail := msg
		if cause != nil {
			detail = fmt.Sprintf("%s: %s", msg, cause)
		}
		s.Log.LogAuditError(actor, s.op.Audit, "failed", detail, cause)
	}
	if cause != nil {
		return fmt.Errorf("%s: %w", msg, cause)
	}
	return fmt.Errorf("%s", msg)
}

// OK records an audit success for the session's operation.
func (s *Session) OK(detail string) {
	if s.Log == nil {
		return
	}
	s.Log.LogAuditInfo(s.Claims.UserID.String(), s.op.Audit, "success", detail)
}

// Print writes items to the command's output through the formatter the
// pre-run selected, using cols for headers and cells. It is a free function
// rather than a method because Go has no generic methods.
func Print[T any](s *Session, cols []Column[T], items ...T) error {
	fmtr, err := CtxFormatter.From(s.Ctx)
	if err != nil {
		return err
	}
	return Render(s.Cmd.OutOrStdout(), fmtr, cols, items...)
}

// humanRoles renders a role list the way the existing error messages read:
// "admin or crypto_manager".
func humanRoles(roles []string) string {
	if len(roles) == 0 {
		return ""
	}
	last := roles[len(roles)-1] + " role"
	if len(roles) == 1 {
		return last
	}
	return strings.Join(roles[:len(roles)-1], ", ") + " or " + last
}
