package model

import (
	"encoding/json"
	"io"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// User represents a user in the password manager.
type User struct {
	ID           uuid.UUID `json:"id"`
	Username     string    `json:"user_name"`
	PasswordHash string    `json:"password_hash"`
	TOTPSecret   string    `json:"totp_secret"`
	Roles        []string  `json:"roles"`
	// AuthProvider is "local" for username/password/TOTP users, or an OIDC
	// provider identifier (e.g. "oidc") for externally-authenticated users.
	AuthProvider string `json:"auth_provider"`
	// ExternalIDPSubject is the external provider's stable subject (`sub`
	// claim) for externally-authenticated users, empty for local users.
	ExternalIDPSubject string `json:"external_idp_subject,omitempty"`
	// Email is the user's email address from the external provider, empty when
	// unknown.
	Email     string    `json:"email,omitempty"`
	CreatedAt time.Time `json:"created_at"`
}

// Claims extends JWT claims with user-specific fields.
type Claims struct {
	UserID   uuid.UUID `json:"user_id"`
	Username string    `json:"username"`
	Roles    []string  `json:"roles"`
	jwt.RegisteredClaims
}

// Role constants for RBAC.
const (
	RoleAdmin              = "admin"
	RoleUser               = "user"
	RoleSecretsManager     = "secrets_manager"
	RoleCryptoManager      = "crypto_manager"
	RoleCertificateManager = "certificate_manager"
	RoleServiceAccount     = "service_account"
	RoleSystem             = "system"
)

// ValidRoles is every role assignable to a human user account via
// CreateUser/UpdateUser. RoleServiceAccount is deliberately excluded --
// service accounts are OAuth2 clients (model.OAuth2Client), not rows in the
// users table, and never go through this validation path. RoleSystem is
// deliberately excluded too -- it belongs solely to the row at SystemUserID
// and must never be assignable to a real account.
var ValidRoles = []string{RoleAdmin, RoleSecretsManager, RoleCryptoManager, RoleCertificateManager, RoleUser}

// SystemUserID is the fixed, well-known id of a real row in the users table
// that owns internally-generated resources with no human behind them --
// currently SelfPKIProvider's own JWT signing key
// (internal/signing/self_pki.go), stored with UserID: uuid.Nil. Tables like
// `keys` have FOREIGN KEY (user_id) REFERENCES users(id): Postgres enforces
// that unconditionally, so the row at this id must actually exist (seeded by
// db.seedSystemUser) or such an insert fails outright. SQLite does not
// enforce it, which is why this went unnoticed until a fresh Postgres
// deployment -- see known-bugs.md B60. Deliberately the same value as
// uuid.Nil.String(), matching the "no real owner yet" sentinel already used
// elsewhere in this codebase (e.g. seedDefaultVault's creator fallback).
const SystemUserID = "00000000-0000-0000-0000-000000000000"

// SystemUsername is the reserved username of the row at SystemUserID. The
// users table's own UNIQUE constraint on username is what actually prevents
// a real account from ever registering under this name.
const SystemUsername = "__rocketvault_system__"

// IsValidRole reports whether role is one of ValidRoles.
func IsValidRole(role string) bool {
	for _, r := range ValidRoles {
		if r == role {
			return true
		}
	}
	return false
}

// AuthProviderLocal identifies a username/password/TOTP user. This is the
// default and the only provider value that existed before OIDC support.
const AuthProviderLocal = "local"

// AuthProviderOIDC identifies a user authenticated via the configured OIDC
// provider.
const AuthProviderOIDC = "oidc"

// --- HTTP request/response types ---

type CreateUserRequest struct {
	Username string   `json:"username"`
	Password string   `json:"password"`
	Roles    []string `json:"roles"`
	// DeprecatedRole detects the pre-multi-role "role" string field so the
	// handler can reject it with a clear error. It is never read for its
	// value -- the multi-role API has no dual-field transition period.
	DeprecatedRole string `json:"role,omitempty"`
}

func CreateUserRequestFromJson(data io.Reader) (*CreateUserRequest, error) {
	var r CreateUserRequest
	return &r, json.NewDecoder(data).Decode(&r)
}

type UpdateUserRequest struct {
	Username string   `json:"username,omitempty"`
	Password string   `json:"password,omitempty"`
	Roles    []string `json:"roles,omitempty"`
	// DeprecatedRole detects the pre-multi-role "role" string field so the
	// handler can reject it with a clear error. It is never read for its
	// value -- the multi-role API has no dual-field transition period.
	DeprecatedRole string `json:"role,omitempty"`
}

func UpdateUserRequestFromJson(data io.Reader) (*UpdateUserRequest, error) {
	var r UpdateUserRequest
	return &r, json.NewDecoder(data).Decode(&r)
}

type UserResponse struct {
	ID         string   `json:"id"`
	Username   string   `json:"username"`
	Roles      []string `json:"roles"`
	CreatedAt  string   `json:"created_at"`
	TOTPSecret string   `json:"totp_secret,omitempty"`
}

func (r *UserResponse) ToJson() string {
	b, _ := json.Marshal(r)
	return string(b)
}

type ListUsersResponse struct {
	Users []UserResponse `json:"users"`
	Total int            `json:"total"`
}

func (r *ListUsersResponse) ToJson() string {
	b, _ := json.Marshal(r)
	return string(b)
}

type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
	TOTPCode string `json:"totp_code"`
}

func LoginRequestFromJson(data io.Reader) (*LoginRequest, error) {
	var r LoginRequest
	return &r, json.NewDecoder(data).Decode(&r)
}

type LoginResponse struct {
	Token        string   `json:"token"`
	RefreshToken string   `json:"refresh_token"`
	UserID       string   `json:"user_id"`
	Username     string   `json:"username"`
	Roles        []string `json:"roles"`
}

func (r *LoginResponse) ToJson() string {
	b, _ := json.Marshal(r)
	return string(b)
}

type RefreshTokenRequest struct {
	RefreshToken string `json:"refresh_token"`
}

func RefreshTokenRequestFromJson(data io.Reader) (*RefreshTokenRequest, error) {
	var r RefreshTokenRequest
	return &r, json.NewDecoder(data).Decode(&r)
}

type RefreshTokenResponse struct {
	Token        string    `json:"token"`
	RefreshToken string    `json:"refresh_token"`
	UserID       string    `json:"user_id"`
	Username     string    `json:"username"`
	Roles        []string  `json:"roles"`
	ExpiresAt    time.Time `json:"expires_at"`
}

func (r *RefreshTokenResponse) ToJson() string {
	b, _ := json.Marshal(r)
	return string(b)
}
