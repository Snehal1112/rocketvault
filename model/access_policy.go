package model

import (
	"encoding/json"
	"fmt"
	"io"
	"time"

	"github.com/google/uuid"
)

type PrincipalType string

const (
	PrincipalTypeUser           PrincipalType = "user"
	PrincipalTypeServiceAccount PrincipalType = "service_account"
)

type PolicyEffect string

const (
	PolicyEffectAllow PolicyEffect = "allow"
	PolicyEffectDeny  PolicyEffect = "deny"
)

type PolicyResourceType string

const (
	PolicyResourceSecrets      PolicyResourceType = "secrets"
	PolicyResourceKeys         PolicyResourceType = "keys"
	PolicyResourceCertificates PolicyResourceType = "certificates"
	PolicyResourceVaults       PolicyResourceType = "vaults"
)

type PolicyOperation string

const (
	OpGet     PolicyOperation = "get"
	OpList    PolicyOperation = "list"
	OpSet     PolicyOperation = "set"
	OpCreate  PolicyOperation = "create"
	OpDelete  PolicyOperation = "delete"
	OpBackup  PolicyOperation = "backup"
	OpRestore PolicyOperation = "restore"
	OpPurge   PolicyOperation = "purge"
	OpRecover PolicyOperation = "recover"
	OpRotate  PolicyOperation = "rotate"
	OpSign    PolicyOperation = "sign"
	OpVerify  PolicyOperation = "verify"
	OpEncrypt PolicyOperation = "encrypt"
	OpDecrypt PolicyOperation = "decrypt"
	OpWrap    PolicyOperation = "wrap"
	OpUnwrap  PolicyOperation = "unwrap"
	OpImport  PolicyOperation = "import"
	OpRenew   PolicyOperation = "renew"
	OpManage  PolicyOperation = "manage"
)

type AccessPolicy struct {
	ID            uuid.UUID          `json:"id"`
	PrincipalID   uuid.UUID          `json:"principal_id"`
	PrincipalType PrincipalType      `json:"principal_type"`
	ResourceType  PolicyResourceType `json:"resource_type"`
	Operation     PolicyOperation    `json:"operation"`
	Effect        PolicyEffect       `json:"effect"`
	// VaultID scopes the policy to a single vault. A nil VaultID means the
	// policy is GLOBAL and applies in any vault.
	VaultID *uuid.UUID `json:"vault_id,omitempty"`
	// AssignmentID links this policy to a role assignment. Nil means the policy
	// was created directly (hand-written), not via a role grant.
	AssignmentID *uuid.UUID `json:"assignment_id,omitempty"`
	CreatedAt    time.Time  `json:"created_at"`
}

type CreateAccessPolicyRequest struct {
	PrincipalID   string `json:"principal_id"`
	PrincipalType string `json:"principal_type"`
	ResourceType  string `json:"resource_type"`
	Operation     string `json:"operation"`
	Effect        string `json:"effect"`
	// VaultID scopes the policy to a vault; empty means GLOBAL.
	VaultID string `json:"vault_id,omitempty"`
}

func CreateAccessPolicyRequestFromJson(data io.Reader) (*CreateAccessPolicyRequest, error) {
	var r CreateAccessPolicyRequest
	return &r, json.NewDecoder(data).Decode(&r)
}

// ValidatePrincipalType returns an error if s is not a known PrincipalType.
func ValidatePrincipalType(s string) error {
	switch PrincipalType(s) {
	case PrincipalTypeUser, PrincipalTypeServiceAccount:
		return nil
	}
	return fmt.Errorf("invalid principal_type %q", s)
}

// ValidatePolicyResourceType returns an error if s is not a known PolicyResourceType.
func ValidatePolicyResourceType(s string) error {
	switch PolicyResourceType(s) {
	case PolicyResourceSecrets, PolicyResourceKeys, PolicyResourceCertificates, PolicyResourceVaults:
		return nil
	}
	return fmt.Errorf("invalid resource_type %q", s)
}

// ValidatePolicyOperation returns an error if s is not a known PolicyOperation.
func ValidatePolicyOperation(s string) error {
	switch PolicyOperation(s) {
	case OpGet, OpList, OpSet, OpCreate, OpDelete, OpBackup, OpRestore, OpPurge,
		OpRecover, OpRotate, OpSign, OpVerify, OpEncrypt, OpDecrypt, OpWrap, OpUnwrap,
		OpImport, OpRenew, OpManage:
		return nil
	}
	return fmt.Errorf("invalid operation %q", s)
}

// ValidatePolicyEffect returns an error if s is not a known PolicyEffect.
func ValidatePolicyEffect(s string) error {
	switch PolicyEffect(s) {
	case PolicyEffectAllow, PolicyEffectDeny:
		return nil
	}
	return fmt.Errorf("invalid effect %q", s)
}

type AccessPolicyResponse struct {
	ID            string `json:"id"`
	PrincipalID   string `json:"principal_id"`
	PrincipalType string `json:"principal_type"`
	ResourceType  string `json:"resource_type"`
	Operation     string `json:"operation"`
	Effect        string `json:"effect"`
	// VaultID scopes the policy to a vault; empty means GLOBAL.
	VaultID   string `json:"vault_id,omitempty"`
	CreatedAt string `json:"created_at"`
}

func (r *AccessPolicyResponse) ToJson() string {
	b, _ := json.Marshal(r)
	return string(b)
}

type ListAccessPoliciesResponse struct {
	AccessPolicies []AccessPolicyResponse `json:"access_policies"`
	Total          int                    `json:"total"`
}

func (r *ListAccessPoliciesResponse) ToJson() string {
	b, _ := json.Marshal(r)
	return string(b)
}
