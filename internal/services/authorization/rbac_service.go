// Package authorization provides authorization services for the password manager.
// It handles role-based access control (RBAC) and permission checking,
// separating authorization logic from middleware and other components.
package authorization

import (
	"fmt"
	"strings"

	"github.com/sirupsen/logrus"

	"rocketvault/internal/logging"
	"rocketvault/model"
)

// Permission represents a specific permission that can be granted to roles.
type Permission string

const (
	// Secret permissions
	PermissionCreateSecret Permission = "secrets:create"
	PermissionReadSecret   Permission = "secrets:read"
	PermissionUpdateSecret Permission = "secrets:update"
	PermissionDeleteSecret Permission = "secrets:delete"
	PermissionListSecrets  Permission = "secrets:list"

	// Key permissions
	PermissionCreateKey Permission = "keys:create"
	PermissionReadKey   Permission = "keys:read"
	PermissionUpdateKey Permission = "keys:update"
	PermissionDeleteKey Permission = "keys:delete"
	PermissionListKeys  Permission = "keys:list"

	// Certificate permissions
	PermissionCreateCertificate Permission = "certificates:create"
	PermissionReadCertificate   Permission = "certificates:read"
	PermissionUpdateCertificate Permission = "certificates:update"
	PermissionDeleteCertificate Permission = "certificates:delete"
	PermissionListCertificates  Permission = "certificates:list"

	// User management permissions
	PermissionCreateUser Permission = "users:create"
	PermissionReadUser   Permission = "users:read"
	PermissionUpdateUser Permission = "users:update"
	PermissionDeleteUser Permission = "users:delete"
	PermissionListUsers  Permission = "users:list"

	// Vault management permissions
	PermissionManageVaults Permission = "vaults:manage"

	// Admin permissions
	PermissionManageSystem Permission = "system:manage"
)

// RBACService handles role-based access control operations.
// It provides permission checking and role management functionality,
// separating authorization concerns from HTTP middleware.
type RBACService interface {
	HasPermission(role string, permission Permission) bool
	GetRolePermissions(role string) []Permission
	ValidateEndpointAccess(roles []string, method, path string) error
}

// rbacService implements RBACService with configurable role-permission mappings.
type rbacService struct {
	rolePermissions map[string][]Permission
	logger          *logging.Logger
}

// NewRBACService creates a new RBACService with default role-permission mappings.
// It initializes the service with standard permissions for each role.
//
// Parameters:
//
//	logger: The logger for audit and error logging.
//
// Returns:
//
//	An RBACService implementation for authorization operations.
func NewRBACService(logger *logging.Logger) RBACService {
	return &rbacService{
		rolePermissions: getDefaultRolePermissions(),
		logger:          logger,
	}
}

// getDefaultRolePermissions returns the default role-permission mappings.
func getDefaultRolePermissions() map[string][]Permission {
	return map[string][]Permission{
		model.RoleAdmin: {
			// Admin has all permissions
			PermissionCreateSecret, PermissionReadSecret, PermissionUpdateSecret, PermissionDeleteSecret, PermissionListSecrets,
			PermissionCreateKey, PermissionReadKey, PermissionUpdateKey, PermissionDeleteKey, PermissionListKeys,
			PermissionCreateCertificate, PermissionReadCertificate, PermissionUpdateCertificate, PermissionDeleteCertificate, PermissionListCertificates,
			PermissionCreateUser, PermissionReadUser, PermissionUpdateUser, PermissionDeleteUser, PermissionListUsers,
			PermissionManageVaults,
			PermissionManageSystem,
		},
		model.RoleUser: {
			// Basic user has limited permissions
			PermissionReadSecret, PermissionListSecrets,
			PermissionReadKey, PermissionListKeys,
			PermissionReadCertificate, PermissionListCertificates,
		},
		model.RoleSecretsManager: {
			// Secrets manager has full secret permissions
			PermissionCreateSecret, PermissionReadSecret, PermissionUpdateSecret, PermissionDeleteSecret, PermissionListSecrets,
		},
		model.RoleCryptoManager: {
			// Crypto manager has full key permissions
			PermissionCreateKey, PermissionReadKey, PermissionUpdateKey, PermissionDeleteKey, PermissionListKeys,
		},
		model.RoleCertificateManager: {
			// Certificate manager has full certificate permissions
			PermissionCreateCertificate, PermissionReadCertificate, PermissionUpdateCertificate, PermissionDeleteCertificate, PermissionListCertificates,
		},
		model.RoleServiceAccount: {
			// Service accounts are read-only consumers (Azure Key Vault model).
			// Admins create secrets/keys/certs and grant access via access policies.
			PermissionReadSecret, PermissionListSecrets,
			PermissionReadKey, PermissionListKeys,
			PermissionReadCertificate, PermissionListCertificates,
		},
	}
}

// HasPermission checks if a role has a specific permission.
//
// Parameters:
//
//	role: The user's role.
//	permission: The permission to check.
//
// Returns:
//
//	True if the role has the permission, false otherwise.
func (s *rbacService) HasPermission(role string, permission Permission) bool {
	permissions, exists := s.rolePermissions[role]
	if !exists {
		logrus.WithFields(logrus.Fields{
			"role":       role,
			"permission": string(permission),
		}).Warn("Unknown role in permission check")
		return false
	}

	for _, perm := range permissions {
		if perm == permission {
			return true
		}
	}

	return false
}

// GetRolePermissions returns all permissions for a given role.
//
// Parameters:
//
//	role: The role to get permissions for.
//
// Returns:
//
//	A slice of permissions granted to the role.
func (s *rbacService) GetRolePermissions(role string) []Permission {
	permissions, exists := s.rolePermissions[role]
	if !exists {
		return []Permission{}
	}

	// Return a copy to prevent modification
	result := make([]Permission, len(permissions))
	copy(result, permissions)
	return result
}

// ValidateEndpointAccess validates if any of a caller's roles can access a
// specific endpoint. It maps HTTP endpoints to required permissions and
// checks authorization.
//
// Parameters:
//
//	roles: The caller's roles.
//	method: The HTTP method (GET, POST, PUT, DELETE).
//	path: The request path.
//
// Returns:
//
//	An error if access is denied, nil if access is granted.
//
// An unrecognized path is allowed here on purpose: this is the global-role
// gate, and every route it does not recognize is either a vault data-plane
// route (PolicyMiddleware) or a handler-authorized route listed in
// api.nonDataPlaneRoutes, which api.VerifyRouteAuthorization enforces at
// startup.
func (s *rbacService) ValidateEndpointAccess(roles []string, method, path string) error {
	permission := s.mapEndpointToPermission(method, path)
	if permission == "" {
		return nil
	}

	for _, role := range roles {
		if s.HasPermission(role, permission) {
			logrus.WithFields(logrus.Fields{
				"roles":      roles,
				"method":     method,
				"path":       path,
				"permission": string(permission),
			}).Debug("Access granted")
			return nil
		}
	}

	s.logger.LogAuditError("", "authorization", "failed",
		fmt.Sprintf("Access denied for roles %v to %s %s", roles, method, path), nil)
	logrus.WithFields(logrus.Fields{
		"roles":               roles,
		"method":              method,
		"path":                path,
		"required_permission": string(permission),
	}).Warn("Access denied: insufficient permissions")
	return fmt.Errorf("insufficient permissions: %s required", permission)
}

// mapEndpointToPermission maps HTTP endpoints to the global permission they
// require. It deliberately answers "" for every vault data-plane route AND
// every vault-management route (create/list/get/update/delete a vault,
// purge, and role-assignment management).
//
// Before P2 this function stripped the "vaults/{name}/" prefix and returned the
// same global permission as the flat equivalent, which made RBAC vault-agnostic
// by construction: any principal holding a global permission could operate on
// any vault by name. Those routes are now authorized by PolicyMiddleware
// against the caller's role assignments in the resolved vault, and a second,
// vault-blind gate here would only contradict that decision — a Key Vault
// Crypto Officer in one vault would be refused for holding the global "user"
// role.
//
// Before 2026-08-11 this function additionally required the admin-only
// PermissionManageVaults for every /vaults path, including vault management
// and role-assignment routes. That made every handler-level per-vault check
// (CanManageVault, CanManageRoleAssignments — internal/services/authorization/vault_authz.go)
// unreachable for non-admins: this vault-blind global gate ran and denied
// the request before the handler's vault-aware check ever got a chance. See
// docs/superpowers/specs/2026-08-11-azure-role-parity-and-vault-authz-fix-design.md,
// "Root cause", for the full analysis. Vault management now defers entirely
// to the handler, the same way vault data-plane routes already did.
//
// User management is not a vault route at all and keeps its global permissions.
func (s *rbacService) mapEndpointToPermission(method, path string) Permission {
	// Vault data-plane routes are authorized per vault, not per global role.
	if _, kind := MapRouteToDataAction(method, path); kind == RouteVaultData {
		return ""
	}

	// Normalize path for comparison.
	path = strings.TrimPrefix(path, DataPlaneBasePath)
	path = strings.TrimPrefix(path, "/")

	// Every /vaults path — management (create/list/get/update/delete/purge)
	// and role-assignment management alike — defers entirely to the
	// handler's own CanManageVault/CanManageRoleAssignments check.
	if strings.HasPrefix(path, "vaults") {
		return ""
	}

	// Users endpoints.
	if strings.HasPrefix(path, "users") {
		switch method {
		case "POST":
			return PermissionCreateUser
		case "GET":
			if strings.Contains(path, "/") {
				return PermissionReadUser
			}
			return PermissionListUsers
		case "PUT":
			return PermissionUpdateUser
		case "DELETE":
			return PermissionDeleteUser
		}
	}

	// Health and other endpoints don't require specific permissions.
	return ""
}
