package model

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"time"

	"github.com/google/uuid"
)

// DefaultVaultName is the reserved name of the vault that holds pre-multi-vault data.
const DefaultVaultName = "default"

// DefaultVaultID is the fixed, well-known UUID of the default vault.
// It is shared by the migration, the fresh-DB schema default, and the resolver.
const DefaultVaultID = "00000000-0000-0000-0000-00000000efa1"

// vaultNameRe enforces Azure's vault naming rule: lowercase alphanumeric and
// hyphens, 3-63 chars, no leading or trailing hyphen.
var vaultNameRe = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{1,61}[a-z0-9])$`)

// Vault represents a named container for secrets, keys, and certificates.
type Vault struct {
	ID               uuid.UUID         `json:"id"`
	Name             string            `json:"name"`
	Enabled          bool              `json:"enabled"`
	PurgeProtection  bool              `json:"purge_protection"`
	RetentionDays    int               `json:"retention_days"`
	CreatedBy        uuid.UUID         `json:"created_by"`
	CreatedAt        time.Time         `json:"created_at"`
	DeletedAt        *time.Time        `json:"deleted_at,omitempty"`
	ScheduledPurgeAt *time.Time        `json:"scheduled_purge_at,omitempty"`
	Tags             map[string]string `json:"tags,omitempty"`
	UpdatedAt        *time.Time        `json:"updated_at,omitempty"`
	UpdatedBy        *uuid.UUID        `json:"updated_by,omitempty"`
}

// ValidateVaultName returns an error if name violates the vault naming rule.
func ValidateVaultName(name string) error {
	if !vaultNameRe.MatchString(name) {
		return fmt.Errorf("invalid vault name %q: must be 3-63 lowercase alphanumerics or hyphens, no leading/trailing hyphen", name)
	}
	return nil
}

// ErrReservedVaultName is returned when a new vault would take a reserved name.
var ErrReservedVaultName = errors.New("reserved vault name")

// reservedVaultNames are refused for new vaults. Each is the last segment of
// a public endpoint, which the authentication middleware once matched by
// suffix, so a vault with that name could not be managed over HTTP (B80).
// Exact matching removed the collision; the reservation is defense in depth
// in case suffix matching is ever reintroduced.
var reservedVaultNames = map[string]struct{}{
	"login":    {},
	"health":   {},
	"refresh":  {},
	"register": {},
}

// ValidateNewVaultName applies ValidateVaultName plus the reserved-name rule.
// Use it only when creating a vault. Lookups keep using ValidateVaultName, so
// a vault created before the reservation stays reachable.
func ValidateNewVaultName(name string) error {
	if err := ValidateVaultName(name); err != nil {
		return err
	}
	if _, reserved := reservedVaultNames[name]; reserved {
		return fmt.Errorf("%w: %q is reserved for an API endpoint", ErrReservedVaultName, name)
	}
	return nil
}

// ValidateVaultTags enforces Azure Key Vault tag limits: at most 15 tags, each
// key and value non-empty and at most 256 characters.
func ValidateVaultTags(tags map[string]string) error {
	if len(tags) > 15 {
		return fmt.Errorf("too many tags: %d (max 15)", len(tags))
	}
	for k, val := range tags {
		if k == "" {
			return fmt.Errorf("tag key must not be empty")
		}
		if val == "" {
			return fmt.Errorf("tag value for key %q must not be empty", k)
		}
		if len(k) > 256 {
			return fmt.Errorf("tag key %q exceeds 256 characters", k)
		}
		if len(val) > 256 {
			return fmt.Errorf("tag value for key %q exceeds 256 characters", k)
		}
	}
	return nil
}

// Clone returns a copy of v that shares no mutable state with the original —
// the struct itself, its Tags map, and every pointer field are independently
// copied. Used by vaultcache.Cache so a caller that mutates a fetched vault
// before persisting an update (VaultService.UpdateVault does exactly this)
// can never corrupt a cache entry.
func (v *Vault) Clone() *Vault {
	cp := *v
	if v.Tags != nil {
		cp.Tags = make(map[string]string, len(v.Tags))
		for k, val := range v.Tags {
			cp.Tags[k] = val
		}
	}
	cp.DeletedAt = cloneTimePtr(v.DeletedAt)
	cp.ScheduledPurgeAt = cloneTimePtr(v.ScheduledPurgeAt)
	cp.UpdatedAt = cloneTimePtr(v.UpdatedAt)
	if v.UpdatedBy != nil {
		id := *v.UpdatedBy
		cp.UpdatedBy = &id
	}
	return &cp
}

// CreateVaultRequest is the body of a create-vault API call.
type CreateVaultRequest struct {
	Name            string            `json:"name"`
	Enabled         *bool             `json:"enabled,omitempty"`
	PurgeProtection *bool             `json:"purge_protection,omitempty"`
	RetentionDays   *int              `json:"retention_days,omitempty"`
	Tags            map[string]string `json:"tags,omitempty"`
}

// UpdateVaultRequest is the body of an update-vault API call. Nil fields are unchanged.
type UpdateVaultRequest struct {
	Enabled         *bool              `json:"enabled,omitempty"`
	PurgeProtection *bool              `json:"purge_protection,omitempty"`
	RetentionDays   *int               `json:"retention_days,omitempty"`
	Tags            *map[string]string `json:"tags,omitempty"` // nil = unchanged, {} = clear, set = replace
}

func CreateVaultRequestFromJson(data io.Reader) (*CreateVaultRequest, error) {
	var r CreateVaultRequest
	return &r, json.NewDecoder(data).Decode(&r)
}

func UpdateVaultRequestFromJson(data io.Reader) (*UpdateVaultRequest, error) {
	var r UpdateVaultRequest
	return &r, json.NewDecoder(data).Decode(&r)
}

// VaultResponse is the API representation of a vault.
type VaultResponse struct {
	ID               string            `json:"id"`
	Name             string            `json:"name"`
	Enabled          bool              `json:"enabled"`
	PurgeProtection  bool              `json:"purge_protection"`
	RetentionDays    int               `json:"retention_days"`
	CreatedBy        string            `json:"created_by"`
	CreatedAt        string            `json:"created_at"`
	DeletedAt        string            `json:"deleted_at,omitempty"`
	ScheduledPurgeAt string            `json:"scheduled_purge_at,omitempty"`
	Tags             map[string]string `json:"tags,omitempty"`
	UpdatedAt        string            `json:"updated_at,omitempty"`
	UpdatedBy        string            `json:"updated_by,omitempty"`
}

func (v *Vault) ToResponse() VaultResponse {
	resp := VaultResponse{
		ID:              v.ID.String(),
		Name:            v.Name,
		Enabled:         v.Enabled,
		PurgeProtection: v.PurgeProtection,
		RetentionDays:   v.RetentionDays,
		CreatedBy:       v.CreatedBy.String(),
		CreatedAt:       v.CreatedAt.Format(time.RFC3339),
	}
	if v.DeletedAt != nil {
		resp.DeletedAt = v.DeletedAt.Format(time.RFC3339)
	}
	if v.ScheduledPurgeAt != nil {
		resp.ScheduledPurgeAt = v.ScheduledPurgeAt.Format(time.RFC3339)
	}
	if len(v.Tags) > 0 {
		resp.Tags = v.Tags
	}
	if v.UpdatedAt != nil {
		resp.UpdatedAt = v.UpdatedAt.Format(time.RFC3339)
	}
	if v.UpdatedBy != nil {
		resp.UpdatedBy = v.UpdatedBy.String()
	}
	return resp
}

// ListVaultsResponse is the API representation of a vault list.
type ListVaultsResponse struct {
	Vaults []VaultResponse `json:"vaults"`
	Total  int             `json:"total"`
}

func (r *ListVaultsResponse) ToJson() string {
	b, _ := json.Marshal(r)
	return string(b)
}

func (r *VaultResponse) ToJson() string {
	b, _ := json.Marshal(r)
	return string(b)
}
