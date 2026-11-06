package users

import (
	"errors"
	"fmt"
	"strings"
	"unicode"

	"rocketvault/model"
)

// Reasons recorded on a NotAllowedError. They go to the audit log only.
const (
	reasonJITDisabled     = "jit_disabled"
	reasonDomain          = "domain"
	reasonEmailUnverified = "email_unverified"
	reasonClaim           = "claim"
)

// ErrExternalUserNotAllowed is returned when the policy refuses an external identity.
var ErrExternalUserNotAllowed = errors.New("external user not allowed")

// NotAllowedError carries the reason a policy refused an external identity.
// Its text never includes the reason, so a client cannot learn which rule failed.
type NotAllowedError struct {
	Reason string
}

// Error returns a generic message without the reason.
func (e *NotAllowedError) Error() string { return ErrExternalUserNotAllowed.Error() }

// ClientFault marks the error as a client outcome so the circuit breaker ignores it.
func (e *NotAllowedError) ClientFault() bool { return true }

// Is makes errors.Is match ErrExternalUserNotAllowed.
func (e *NotAllowedError) Is(target error) bool { return target == ErrExternalUserNotAllowed }

// ExternalUserPolicyConfig holds the raw policy settings.
type ExternalUserPolicyConfig struct {
	JITEnabled           bool
	AllowedEmailDomains  []string
	RequireEmailVerified bool
	RequiredClaims       map[string]string
	DefaultRole          string
	EnforceOnExisting    bool
}

// ExternalIdentity is the verified identity data from an external provider.
type ExternalIdentity struct {
	Email         string
	EmailVerified bool
	Claims        map[string]any
}

// ExternalUserPolicy decides whether an external identity may sign in.
type ExternalUserPolicy struct {
	cfg ExternalUserPolicyConfig
}

// NewExternalUserPolicy validates and normalizes the config.
func NewExternalUserPolicy(cfg ExternalUserPolicyConfig) (*ExternalUserPolicy, error) {
	domains := make([]string, 0, len(cfg.AllowedEmailDomains))
	for _, d := range cfg.AllowedEmailDomains {
		d = strings.ToLower(strings.TrimSpace(d))
		if d == "" || strings.ContainsAny(d, "@*:/") || strings.IndexFunc(d, unicode.IsSpace) >= 0 {
			return nil, fmt.Errorf("invalid allowed email domain %q", d)
		}
		domains = append(domains, d)
	}
	cfg.AllowedEmailDomains = domains

	for k := range cfg.RequiredClaims {
		if strings.TrimSpace(k) == "" {
			return nil, errors.New("required claims must not have an empty claim name")
		}
	}

	if cfg.DefaultRole == "" {
		cfg.DefaultRole = model.RoleUser
	}
	if cfg.DefaultRole != model.RoleUser {
		return nil, fmt.Errorf("default role must be %q", model.RoleUser)
	}
	return &ExternalUserPolicy{cfg: cfg}, nil
}

// DefaultRole returns the role given to a newly created external user.
func (p *ExternalUserPolicy) DefaultRole() string {
	if p == nil {
		return model.RoleUser
	}
	return p.cfg.DefaultRole
}

// Evaluate returns a *NotAllowedError when the identity is refused. A nil
// policy acts as JIT off with enforcement on existing users and no other checks.
func (p *ExternalUserPolicy) Evaluate(id ExternalIdentity, isNew bool) error {
	if p == nil {
		if isNew {
			return &NotAllowedError{Reason: reasonJITDisabled}
		}
		return nil
	}
	if isNew && !p.cfg.JITEnabled {
		return &NotAllowedError{Reason: reasonJITDisabled}
	}
	if !isNew && !p.cfg.EnforceOnExisting {
		return nil
	}

	if len(p.cfg.AllowedEmailDomains) > 0 && !p.domainAllowed(id.Email) {
		return &NotAllowedError{Reason: reasonDomain}
	}
	// A domain allow-list is only safe when the provider verified the email.
	if (p.cfg.RequireEmailVerified || len(p.cfg.AllowedEmailDomains) > 0) && !id.EmailVerified {
		return &NotAllowedError{Reason: reasonEmailUnverified}
	}
	for name, want := range p.cfg.RequiredClaims {
		if !claimMatches(id.Claims, name, want) {
			return &NotAllowedError{Reason: reasonClaim}
		}
	}
	return nil
}

// domainAllowed reports whether the email has exactly one @ and an allowed domain.
func (p *ExternalUserPolicy) domainAllowed(email string) bool {
	parts := strings.Split(strings.ToLower(strings.TrimSpace(email)), "@")
	if len(parts) != 2 || parts[0] == "" {
		return false
	}
	for _, d := range p.cfg.AllowedEmailDomains {
		if parts[1] == d {
			return true
		}
	}
	return false
}

// claimMatches finds the claim by name, ignoring case, and matches a string
// value or a string array member. Other value types never match. When several
// keys differ only in case, all of them must match, so the result never
// depends on map order.
func claimMatches(claims map[string]any, name, want string) bool {
	found := false
	for k, v := range claims {
		if !strings.EqualFold(k, name) {
			continue
		}
		if !claimValueMatches(v, want) {
			return false
		}
		found = true
	}
	return found
}

// claimValueMatches matches a string value or a string array member.
func claimValueMatches(v any, want string) bool {
	switch val := v.(type) {
	case string:
		return val == want
	case []string:
		for _, s := range val {
			if s == want {
				return true
			}
		}
	case []any:
		for _, item := range val {
			if s, ok := item.(string); ok && s == want {
				return true
			}
		}
	}
	return false
}
