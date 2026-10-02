package model

import (
	"encoding/json"
	"io"
	"time"

	"github.com/google/uuid"
)

// Secret represents a secret in the password manager.
type Secret struct {
	ID               uuid.UUID  `json:"id"`
	UserID           uuid.UUID  `json:"user_id"`
	VaultID          uuid.UUID  `json:"vault_id"`
	Name             string     `json:"name"`
	Value            string     `json:"value"`
	Version          int        `json:"version"`
	Tags             []string   `json:"tags"`
	CreatedAt        time.Time  `json:"created_at"`
	DeletedAt        *time.Time `json:"deleted_at,omitempty"`
	PurgeProtection  bool       `json:"purge_protection"`
	ExpiresAt        *time.Time `json:"expires_at,omitempty"`
	NotBefore        *time.Time `json:"not_before,omitempty"`
	Enabled          bool       `json:"enabled"`
	ContentType      string     `json:"content_type,omitempty"`
	ScheduledPurgeAt *time.Time `json:"scheduled_purge_at,omitempty"`
}

func (s *Secret) IsExpired() bool {
	if s.ExpiresAt == nil {
		return false
	}
	return time.Now().After(*s.ExpiresAt)
}

func (s *Secret) IsActive() bool {
	if s.NotBefore == nil {
		return true
	}
	return time.Now().After(*s.NotBefore)
}

// IsAccessible reports whether the secret may be served. A soft-deleted
// secret never is: the SQL read path filters deleted_at IS NULL, and the
// cache hit path relies on this check alone, so omitting DeletedAt here would
// let a vault-delete cascade leave a still-servable cached copy behind.
func (s *Secret) IsAccessible() bool {
	return s.DeletedAt == nil && s.Enabled && s.IsActive() && !s.IsExpired()
}

func (s *Secret) DaysUntilExpiration() int {
	if s.ExpiresAt == nil {
		return -1
	}
	if s.IsExpired() {
		return 0
	}
	return int(time.Until(*s.ExpiresAt).Hours() / 24)
}

// Clone returns a copy of s that shares no mutable state with the original:
// the struct itself, its tag slice, and every time pointer are all
// independently copied. Used by SecretCache so a caller that mutates a
// fetched secret before persisting an update can never corrupt a cache entry
// or race a concurrent reader.
func (s *Secret) Clone() *Secret {
	cp := *s
	if s.Tags != nil {
		cp.Tags = append([]string(nil), s.Tags...)
	}
	cp.ExpiresAt = cloneTimePtr(s.ExpiresAt)
	cp.NotBefore = cloneTimePtr(s.NotBefore)
	cp.DeletedAt = cloneTimePtr(s.DeletedAt)
	cp.ScheduledPurgeAt = cloneTimePtr(s.ScheduledPurgeAt)
	return &cp
}

// Zero clears the decrypted value in place. Called by cachekit after an
// entry is removed (TTL expiry, LRU eviction, invalidation) to shrink the
// in-memory exposure window rather than waiting for GC. Go strings are
// immutable, so this drops the reference rather than overwriting the
// underlying bytes — the same best-effort guarantee as
// internal/vaultapi/secretvalue.go's SecretValue.Zero().
func (s *Secret) Zero() {
	s.Value = ""
}

// cloneTimePtr copies an optional timestamp, preserving nil. Shared by
// Secret.Clone and Vault.Clone (Task 6).
func cloneTimePtr(t *time.Time) *time.Time {
	if t == nil {
		return nil
	}
	v := *t
	return &v
}

// SecretVersion is one archived version of a secret. Value carries the same
// master-key-encrypted form the database stores.
//
// This type IS marshaled into a secret backup blob, which
// POST /secrets/{id}/backup returns in its response body as a merely
// base64url-encoded (not encrypted) JSON envelope. A secret backup blob
// therefore contains every historical value of that secret and must be
// handled as secret material — the same warning model.KeyVersionRecord
// carries for keys.
type SecretVersion struct {
	ID        uuid.UUID `json:"id"`
	SecretID  uuid.UUID `json:"secret_id"`
	UserID    uuid.UUID `json:"user_id"`
	Name      string    `json:"name"`
	Value     string    `json:"value"`
	Version   int       `json:"version"`
	CreatedAt time.Time `json:"created_at"`
}

// SecretVersionMetadata describes one version of a secret without its value.
//
// This type exists so listing a secret's versions cannot disclose the values:
// it has no Value field, so a handler physically cannot serialize one, in the
// same way model.KeyVersion makes key-version listing safe by construction.
//
// The distinction is load-bearing, not stylistic. GET /secrets/{id}/versions
// is authorized by ActionSecretsReadMetadata, which Key Vault Reader holds;
// before 2026-08-20 that route returned model.SecretVersion with every
// historical plaintext decrypted into it, so the least-privileged built-in
// role could read every value of every secret in its vault
// (.claude/known-bugs.md § B30). Reading an actual value goes through
// GET /secrets/{id}/versions/{n}, which requires ActionSecretsGet.
//
// Do not add a Value field. Callers that legitimately need plaintext -- backup
// and restore -- use model.SecretVersion via VersioningService.GetVersions.
type SecretVersionMetadata struct {
	ID        uuid.UUID `json:"id"`
	SecretID  uuid.UUID `json:"secret_id"`
	Name      string    `json:"name"`
	Version   int       `json:"version"`
	CreatedAt time.Time `json:"created_at"`
}

// ExportFormat represents the format for exporting secrets.
type ExportFormat string

const (
	ExportFormatJSON ExportFormat = "json"
	ExportFormatCSV  ExportFormat = "csv"
)

// ExportOptions contains options for exporting secrets.
type ExportOptions struct {
	Format      ExportFormat `json:"format"`
	IncludeTags bool         `json:"include_tags"`
	FilterTags  []string     `json:"filter_tags,omitempty"`
	Encrypt     bool         `json:"encrypt"`
	UserID      uuid.UUID    `json:"user_id"`
	ExportedAt  time.Time    `json:"exported_at"`
	ExportedBy  string       `json:"exported_by"`
}

// ImportOptions contains options for importing secrets.
type ImportOptions struct {
	Format            ExportFormat `json:"format"`
	OverwriteExisting bool         `json:"overwrite_existing"`
	Encrypted         bool         `json:"encrypted"`
	UserID            uuid.UUID    `json:"user_id"`
	ImportedBy        string       `json:"imported_by"`
}

// ExportedSecret represents a secret in export format.
type ExportedSecret struct {
	ID        string    `json:"id" csv:"id"`
	Name      string    `json:"name" csv:"name"`
	Value     string    `json:"value" csv:"value"`
	Version   int       `json:"version" csv:"version"`
	Tags      []string  `json:"tags" csv:"tags"`
	CreatedAt time.Time `json:"created_at" csv:"created_at"`
}

// ExportContainer is the complete export structure.
type ExportContainer struct {
	Metadata ExportOptions    `json:"metadata"`
	Secrets  []ExportedSecret `json:"secrets"`
}

// --- HTTP request/response types ---

type CreateSecretRequest struct {
	Name        string     `json:"name"`
	Value       string     `json:"value"`
	Tags        []string   `json:"tags,omitempty"`
	ContentType string     `json:"content_type,omitempty"`
	Enabled     *bool      `json:"enabled,omitempty"`
	ExpiresAt   *time.Time `json:"expires_at,omitempty"`
	NotBefore   *time.Time `json:"not_before,omitempty"`
	// PurgeProtection is optional; omitting it leaves protection off.
	PurgeProtection *bool `json:"purge_protection,omitempty"`
}

func CreateSecretRequestFromJson(data io.Reader) (*CreateSecretRequest, error) {
	var r CreateSecretRequest
	return &r, json.NewDecoder(data).Decode(&r)
}

type UpdateSecretRequest struct {
	Name        string     `json:"name,omitempty"`
	Value       string     `json:"value,omitempty"`
	Tags        []string   `json:"tags,omitempty"`
	ContentType *string    `json:"content_type,omitempty"`
	Enabled     *bool      `json:"enabled,omitempty"`
	ExpiresAt   *time.Time `json:"expires_at,omitempty"`
	NotBefore   *time.Time `json:"not_before,omitempty"`
	// PurgeProtection is optional; nil means no change.
	PurgeProtection *bool `json:"purge_protection,omitempty"`
}

func UpdateSecretRequestFromJson(data io.Reader) (*UpdateSecretRequest, error) {
	var r UpdateSecretRequest
	return &r, json.NewDecoder(data).Decode(&r)
}

type GenerateSecretRequest struct {
	Length       int    `json:"length,omitempty"`
	UseSymbols   bool   `json:"use_symbols,omitempty"`
	UseNumbers   bool   `json:"use_numbers,omitempty"`
	UseUppercase bool   `json:"use_uppercase,omitempty"`
	UseLowercase bool   `json:"use_lowercase,omitempty"`
	Name         string `json:"name"`
}

func GenerateSecretRequestFromJson(data io.Reader) (*GenerateSecretRequest, error) {
	var r GenerateSecretRequest
	return &r, json.NewDecoder(data).Decode(&r)
}

type ExportSecretsRequest struct {
	Format      string   `json:"format"`
	Encrypt     bool     `json:"encrypt"`
	Tags        []string `json:"tags"`
	IncludeTags bool     `json:"include_tags"`
	// Passphrase seals the export via common.SealExport when Encrypt is true,
	// or when Passphrase is itself non-empty (the service treats either as
	// sufficient — see secret_service.go's ExportSecrets). It is request-scoped
	// only: never logged, never echoed back, never audit-logged verbatim.
	Passphrase string `json:"passphrase,omitempty"`
}

func ExportSecretsRequestFromJson(data io.Reader) (*ExportSecretsRequest, error) {
	var r ExportSecretsRequest
	return &r, json.NewDecoder(data).Decode(&r)
}

type SecretResponse struct {
	ID          string     `json:"id"`
	Name        string     `json:"name"`
	Value       string     `json:"value,omitempty"`
	Tags        []string   `json:"tags,omitempty"`
	Version     int        `json:"version"`
	ContentType string     `json:"content_type,omitempty"`
	CreatedAt   string     `json:"created_at"`
	UpdatedAt   string     `json:"updated_at,omitempty"`
	Enabled     bool       `json:"enabled"`
	ExpiresAt   *time.Time `json:"expires_at,omitempty"`
	NotBefore   *time.Time `json:"not_before,omitempty"`
}

func (r *SecretResponse) ToJson() string {
	b, _ := json.Marshal(r)
	return string(b)
}

type ListSecretsResponse struct {
	Secrets []SecretResponse `json:"secrets"`
	// Total is len(Secrets): the count in this response, not a count across
	// every page.
	Total int `json:"total"`
}

func (r *ListSecretsResponse) ToJson() string {
	b, _ := json.Marshal(r)
	return string(b)
}

type ExportResponse struct {
	Success    bool   `json:"success"`
	Message    string `json:"message"`
	Count      int    `json:"count"`
	Format     string `json:"format"`
	Encrypted  bool   `json:"encrypted"`
	ExportedAt string `json:"exported_at"`
}

func (r *ExportResponse) ToJson() string {
	b, _ := json.Marshal(r)
	return string(b)
}

type ImportResponse struct {
	Success       bool     `json:"success"`
	Message       string   `json:"message"`
	ImportedCount int      `json:"imported_count"`
	SkippedCount  int      `json:"skipped_count"`
	FailedCount   int      `json:"failed_count"`
	TotalCount    int      `json:"total_count"`
	Format        string   `json:"format"`
	ImportedAt    string   `json:"imported_at"`
	Errors        []string `json:"errors,omitempty"`
}

func (r *ImportResponse) ToJson() string {
	b, _ := json.Marshal(r)
	return string(b)
}
