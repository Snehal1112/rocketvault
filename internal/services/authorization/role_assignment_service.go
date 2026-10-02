package authorization

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/google/uuid"

	"rocketvault/internal/logging"
	"rocketvault/model"
)

var (
	ErrInvalidRole        = errors.New("invalid role")
	ErrPrincipalNotFound  = errors.New("principal not found")
	ErrAssignmentNotFound = errors.New("role assignment not found")
	// ErrRoleNotGrantable is returned when a non-global-admin caller attempts
	// to grant a role outside the allow-list a Key Vault Data Access
	// Administrator may assign — mirroring Azure's ABAC restriction that bars
	// Data Access Administrator from granting itself, Purge Operator, or
	// Certificate User.
	ErrRoleNotGrantable = errors.New("role cannot be granted by a non-admin caller")
)

// nonAdminGrantableRoles is the allow-list of roles a non-global-admin caller
// (i.e. one whose authority to manage role assignments comes from holding
// Key Vault Data Access Administrator, not the admin bypass) may grant or
// revoke. It deliberately excludes RoleKeyVaultDataAccessAdministrator
// itself, RoleKeyVaultPurgeOperator, and RoleKeyVaultCertificateUser.
//
// Enforced by both AssignRole and RevokeAssignment, so a non-global-admin
// Data Access Administrator can't sidestep the grant restriction by revoking
// an assignment they aren't allowed to create.
var nonAdminGrantableRoles = map[string]bool{
	model.RoleKeyVaultAdministrator:               true,
	model.RoleKeyVaultReader:                      true,
	model.RoleKeyVaultSecretsUser:                 true,
	model.RoleKeyVaultSecretsOfficer:              true,
	model.RoleKeyVaultCryptoUser:                  true,
	model.RoleKeyVaultCryptoOfficer:               true,
	model.RoleKeyVaultCertificatesOfficer:         true,
	model.RoleKeyVaultCryptoServiceEncryptionUser: true,
}

// roleAssignmentRepo is the subset of the role-assignment repository the service needs.
type roleAssignmentRepo interface {
	Create(ctx context.Context, ra *model.RoleAssignment) error
	GetByID(ctx context.Context, id uuid.UUID) (*model.RoleAssignment, error)
	ListByVault(ctx context.Context, vaultID uuid.UUID) ([]*model.RoleAssignment, error)
	FindByTuple(ctx context.Context, principalID uuid.UUID, role string, vaultID uuid.UUID) (*model.RoleAssignment, error)
	Delete(ctx context.Context, id uuid.UUID) error
	ListByPrincipalInVault(ctx context.Context, principalID, vaultID uuid.UUID) ([]*model.RoleAssignment, error)
}

// policyWriter is the subset of the access-policy repository the service needs.
type policyWriter interface {
	Create(ctx context.Context, p *model.AccessPolicy) error
	DeleteByAssignmentID(ctx context.Context, assignmentID uuid.UUID) error
}

// userLookup resolves a username to a user.
type userLookup interface {
	ReadByUsername(ctx context.Context, username string) (model.User, error)
}

// AssignRoleInput carries the resolved request to AssignRole.
type AssignRoleInput struct {
	Principal     string
	PrincipalType model.PrincipalType
	Role          string
	VaultID       uuid.UUID
	CreatedBy     uuid.UUID
	// CallerIsGlobalAdmin is true when the caller's authority to manage role
	// assignments comes from the global admin role, not from holding Key
	// Vault Data Access Administrator in this vault. Set by the caller (HTTP
	// handler or CLI command) from the same check CanManageRoleAssignments
	// already performs, since AssignRole itself has no access to the
	// account-role/session context.
	CallerIsGlobalAdmin bool
}

// RoleAssignmentService grants, revokes, and lists vault-scoped role assignments.
type RoleAssignmentService interface {
	AssignRole(ctx context.Context, in AssignRoleInput) (*model.RoleAssignment, error)
	// RevokeAssignment revokes assignmentID in vaultID. callerIsGlobalAdmin
	// mirrors AssignRoleInput.CallerIsGlobalAdmin: when false, revoking an
	// assignment whose Role is outside nonAdminGrantableRoles is refused with
	// ErrRoleNotGrantable, so a non-global-admin Data Access Administrator
	// can't revoke a role they aren't allowed to grant.
	RevokeAssignment(ctx context.Context, assignmentID, vaultID uuid.UUID, callerIsGlobalAdmin bool) error
	ListAssignments(ctx context.Context, vaultID uuid.UUID) ([]*model.RoleAssignment, error)
	// HasDataAction reports whether the principal holds a role assignment in the
	// given vault that grants the data action. It is the fail-closed
	// authorization decision for every vault data-plane route: an empty
	// assignment list is a denial, and a lookup failure is an error, never a
	// silent false.
	HasDataAction(ctx context.Context, principalID, vaultID uuid.UUID, action model.DataAction) (bool, error)
}

type roleAssignmentService struct {
	roleRepo   roleAssignmentRepo
	policyRepo policyWriter
	users      userLookup
	log        *logging.Logger
}

// NewRoleAssignmentService constructs the service. The logger is optional and may be nil.
func NewRoleAssignmentService(rr roleAssignmentRepo, pr policyWriter, ul userLookup, log *logging.Logger) RoleAssignmentService {
	return &roleAssignmentService{roleRepo: rr, policyRepo: pr, users: ul, log: log}
}

func (s *roleAssignmentService) AssignRole(ctx context.Context, in AssignRoleInput) (*model.RoleAssignment, error) {
	if !IsValidRole(in.Role) {
		return nil, fmt.Errorf("%w: %s", ErrInvalidRole, in.Role)
	}
	if IsLegacyRole(in.Role) {
		// IsValidRole still accepts these for ExpandRole/RolePermissions/the
		// backfill's legacy-role translation, but model.RoleGrantsDataAction only
		// understands the thirteen Azure names — granting one of these now would
		// silently confer zero data-plane access.
		return nil, fmt.Errorf("%w: %q is a legacy role name and grants no data-plane access; use one of the Azure built-in roles instead: %s",
			ErrInvalidRole, in.Role, strings.Join(model.AzureRoleNames(), ", "))
	}
	if !in.CallerIsGlobalAdmin && !nonAdminGrantableRoles[in.Role] {
		return nil, fmt.Errorf("%w: %q may only be granted by a global admin", ErrRoleNotGrantable, in.Role)
	}
	pType := in.PrincipalType
	if pType == "" {
		pType = model.PrincipalTypeUser
	}

	principalID, err := s.resolvePrincipal(ctx, in.Principal)
	if err != nil {
		return nil, err
	}

	existing, err := s.roleRepo.FindByTuple(ctx, principalID, in.Role, in.VaultID)
	if err != nil {
		return nil, err
	}
	if existing != nil {
		return existing, nil
	}

	assignmentID := uuid.New()
	ra := &model.RoleAssignment{
		ID:            assignmentID,
		PrincipalID:   principalID,
		PrincipalType: pType,
		Role:          in.Role,
		VaultID:       in.VaultID,
		CreatedBy:     in.CreatedBy,
	}
	if err := s.roleRepo.Create(ctx, ra); err != nil {
		return nil, fmt.Errorf("create assignment: %w", err)
	}

	policies, err := ExpandRole(in.Role, principalID, pType, in.VaultID, assignmentID)
	if err != nil {
		if delErr := s.roleRepo.Delete(ctx, assignmentID); delErr != nil && s.log != nil {
			s.log.LogAuditError("", "assign_role", "rollback", fmt.Sprintf("rollback: failed to delete assignment %s", assignmentID), delErr)
		}
		return nil, err
	}
	for _, p := range policies {
		if err := s.policyRepo.Create(ctx, p); err != nil {
			if delErr := s.policyRepo.DeleteByAssignmentID(ctx, assignmentID); delErr != nil && s.log != nil {
				s.log.LogAuditError("", "assign_role", "rollback", fmt.Sprintf("rollback: failed to delete policies for assignment %s", assignmentID), delErr)
			}
			if delErr := s.roleRepo.Delete(ctx, assignmentID); delErr != nil && s.log != nil {
				s.log.LogAuditError("", "assign_role", "rollback", fmt.Sprintf("rollback: failed to delete assignment %s", assignmentID), delErr)
			}
			return nil, fmt.Errorf("expand role policies: %w", err)
		}
	}
	if s.log != nil {
		s.log.LogAuditInfo(in.CreatedBy.String(), "assign_role", "success",
			fmt.Sprintf("Role %q assigned to principal %s in vault %s", in.Role, principalID, in.VaultID))
	}
	return ra, nil
}

func (s *roleAssignmentService) RevokeAssignment(ctx context.Context, assignmentID, vaultID uuid.UUID, callerIsGlobalAdmin bool) error {
	ra, err := s.roleRepo.GetByID(ctx, assignmentID)
	if err != nil {
		return ErrAssignmentNotFound
	}
	if ra.VaultID != vaultID {
		return ErrAssignmentNotFound
	}
	if !callerIsGlobalAdmin && !nonAdminGrantableRoles[ra.Role] {
		return fmt.Errorf("%w: %q may only be revoked by a global admin", ErrRoleNotGrantable, ra.Role)
	}
	if err := s.policyRepo.DeleteByAssignmentID(ctx, assignmentID); err != nil {
		return fmt.Errorf("delete policies: %w", err)
	}
	if err := s.roleRepo.Delete(ctx, assignmentID); err != nil {
		return fmt.Errorf("delete assignment: %w", err)
	}
	if s.log != nil {
		s.log.LogAuditInfo("", "revoke_role_assignment", "success",
			fmt.Sprintf("Role assignment %s (role %q) revoked in vault %s", assignmentID, ra.Role, vaultID))
	}
	return nil
}

func (s *roleAssignmentService) ListAssignments(ctx context.Context, vaultID uuid.UUID) ([]*model.RoleAssignment, error) {
	return s.roleRepo.ListByVault(ctx, vaultID)
}

func (s *roleAssignmentService) HasDataAction(ctx context.Context, principalID, vaultID uuid.UUID, action model.DataAction) (bool, error) {
	// Reject the degenerate inputs before touching the database. A nil principal
	// or vault can only come from a malformed context, and an empty action means
	// the route had no mapping; all three must deny.
	if principalID == uuid.Nil || vaultID == uuid.Nil || action == "" {
		return false, nil
	}
	assignments, err := s.roleRepo.ListByPrincipalInVault(ctx, principalID, vaultID)
	if err != nil {
		return false, fmt.Errorf("list role assignments: %w", err)
	}
	for _, ra := range assignments {
		if model.RoleGrantsDataAction(ra.Role, action) {
			return true, nil
		}
	}
	return false, nil
}

// resolvePrincipal accepts a UUID string or a username and returns the principal UUID.
func (s *roleAssignmentService) resolvePrincipal(ctx context.Context, principal string) (uuid.UUID, error) {
	if id, err := uuid.Parse(principal); err == nil {
		return id, nil
	}
	u, err := s.users.ReadByUsername(ctx, principal)
	if err != nil {
		return uuid.Nil, fmt.Errorf("%w: %s", ErrPrincipalNotFound, principal)
	}
	return u.ID, nil
}
