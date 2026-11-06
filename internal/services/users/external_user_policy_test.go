package users

import (
	"errors"
	"fmt"
	"testing"

	"rocketvault/model"
)

func reasonOf(t *testing.T, err error) string {
	t.Helper()
	var na *NotAllowedError
	if !errors.As(err, &na) {
		t.Fatalf("expected *NotAllowedError, got %v", err)
	}
	return na.Reason
}

func TestEvaluate(t *testing.T) {
	ok := ExternalIdentity{Email: "user@example.com", EmailVerified: true}
	tests := []struct {
		name   string
		cfg    ExternalUserPolicyConfig
		id     ExternalIdentity
		isNew  bool
		reason string // Empty means allowed.
	}{
		{"new user jit off", ExternalUserPolicyConfig{}, ok, true, "jit_disabled"},
		{"jit on no restrictions", ExternalUserPolicyConfig{JITEnabled: true}, ExternalIdentity{}, true, ""},
		{"domain match", ExternalUserPolicyConfig{JITEnabled: true, AllowedEmailDomains: []string{"example.com"}}, ok, true, ""},
		{"domain mismatch", ExternalUserPolicyConfig{JITEnabled: true, AllowedEmailDomains: []string{"other.com"}}, ok, true, "domain"},
		{"domain case", ExternalUserPolicyConfig{JITEnabled: true, AllowedEmailDomains: []string{"Example.COM"}},
			ExternalIdentity{Email: "USER@Example.COM", EmailVerified: true}, true, ""},
		{"several at signs", ExternalUserPolicyConfig{JITEnabled: true, AllowedEmailDomains: []string{"example.com"}},
			ExternalIdentity{Email: "a@evil.com@example.com", EmailVerified: true}, true, "domain"},
		{"missing email", ExternalUserPolicyConfig{JITEnabled: true, AllowedEmailDomains: []string{"example.com"}},
			ExternalIdentity{EmailVerified: true}, true, "domain"},
		{"require verified fails", ExternalUserPolicyConfig{JITEnabled: true, RequireEmailVerified: true},
			ExternalIdentity{Email: "user@example.com"}, true, "email_unverified"},
		{"domains need verified", ExternalUserPolicyConfig{JITEnabled: true, AllowedEmailDomains: []string{"example.com"}},
			ExternalIdentity{Email: "user@example.com"}, true, "email_unverified"},
		{"claim scalar match", ExternalUserPolicyConfig{JITEnabled: true, RequiredClaims: map[string]string{"hd": "example.com"}},
			ExternalIdentity{Claims: map[string]any{"hd": "example.com"}}, true, ""},
		{"claim scalar mismatch", ExternalUserPolicyConfig{JITEnabled: true, RequiredClaims: map[string]string{"hd": "example.com"}},
			ExternalIdentity{Claims: map[string]any{"hd": "other.com"}}, true, "claim"},
		{"claim array member", ExternalUserPolicyConfig{JITEnabled: true, RequiredClaims: map[string]string{"groups": "rv"}},
			ExternalIdentity{Claims: map[string]any{"groups": []any{"a", "rv"}}}, true, ""},
		{"claim string slice", ExternalUserPolicyConfig{JITEnabled: true, RequiredClaims: map[string]string{"groups": "rv"}},
			ExternalIdentity{Claims: map[string]any{"groups": []string{"rv"}}}, true, ""},
		{"claim array non-strings", ExternalUserPolicyConfig{JITEnabled: true, RequiredClaims: map[string]string{"groups": "1"}},
			ExternalIdentity{Claims: map[string]any{"groups": []any{1, true}}}, true, "claim"},
		{"claim absent", ExternalUserPolicyConfig{JITEnabled: true, RequiredClaims: map[string]string{"groups": "rv"}},
			ExternalIdentity{Claims: map[string]any{}}, true, "claim"},
		{"claim other type", ExternalUserPolicyConfig{JITEnabled: true, RequiredClaims: map[string]string{"admin": "true"}},
			ExternalIdentity{Claims: map[string]any{"admin": true}}, true, "claim"},
		{"claim key case-insensitive", ExternalUserPolicyConfig{JITEnabled: true, RequiredClaims: map[string]string{"groups": "rv"}},
			ExternalIdentity{Claims: map[string]any{"Groups": []any{"rv"}}}, true, ""},
		{"existing enforced", ExternalUserPolicyConfig{EnforceOnExisting: true, AllowedEmailDomains: []string{"other.com"}}, ok, false, "domain"},
		{"existing not enforced", ExternalUserPolicyConfig{AllowedEmailDomains: []string{"other.com"}}, ok, false, ""},
		{"existing jit off allowed", ExternalUserPolicyConfig{EnforceOnExisting: true}, ok, false, ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p, err := NewExternalUserPolicy(tc.cfg)
			if err != nil {
				t.Fatal(err)
			}
			err = p.Evaluate(tc.id, tc.isNew)
			if tc.reason == "" {
				if err != nil {
					t.Fatalf("expected allow, got %v", err)
				}
				return
			}
			if !errors.Is(err, ErrExternalUserNotAllowed) {
				t.Fatalf("expected ErrExternalUserNotAllowed, got %v", err)
			}
			if got := reasonOf(t, err); got != tc.reason {
				t.Fatalf("reason = %q, want %q", got, tc.reason)
			}
		})
	}
}

func TestEvaluate_ClaimKeysDifferingInCase_FailClosed(t *testing.T) {
	p, err := NewExternalUserPolicy(ExternalUserPolicyConfig{
		JITEnabled: true, RequiredClaims: map[string]string{"groups": "a"},
	})
	if err != nil {
		t.Fatal(err)
	}
	// Map iteration order is random, so repeat to cover both orders.
	for i := 0; i < 100; i++ {
		deny := ExternalIdentity{Claims: map[string]any{"Groups": "a", "groups": "b"}}
		if err := p.Evaluate(deny, true); reasonOf(t, err) != "claim" {
			t.Fatalf("conflicting claims must be denied, got %v", err)
		}
		allow := ExternalIdentity{Claims: map[string]any{"Groups": "a", "groups": "a"}}
		if err := p.Evaluate(allow, true); err != nil {
			t.Fatalf("agreeing claims must be allowed, got %v", err)
		}
	}
}

func TestEvaluate_NilPolicy(t *testing.T) {
	var p *ExternalUserPolicy
	if err := p.Evaluate(ExternalIdentity{}, true); reasonOf(t, err) != "jit_disabled" {
		t.Fatalf("new user must be denied, got %v", err)
	}
	if err := p.Evaluate(ExternalIdentity{}, false); err != nil {
		t.Fatalf("existing user must be allowed, got %v", err)
	}
	if p.DefaultRole() != model.RoleUser {
		t.Fatalf("nil policy role = %q", p.DefaultRole())
	}
}

func TestNewExternalUserPolicy_Invalid(t *testing.T) {
	tests := []struct {
		name string
		cfg  ExternalUserPolicyConfig
	}{
		{"empty domain", ExternalUserPolicyConfig{AllowedEmailDomains: []string{""}}},
		{"domain with at", ExternalUserPolicyConfig{AllowedEmailDomains: []string{"@example.com"}}},
		{"domain with space", ExternalUserPolicyConfig{AllowedEmailDomains: []string{"exa mple.com"}}},
		{"empty claim key", ExternalUserPolicyConfig{RequiredClaims: map[string]string{"": "x"}}},
		{"admin role", ExternalUserPolicyConfig{DefaultRole: "admin"}},
		{"domain with star", ExternalUserPolicyConfig{AllowedEmailDomains: []string{"*.example.com"}}},
		{"domain with scheme", ExternalUserPolicyConfig{AllowedEmailDomains: []string{"https://example.com"}}},
		{"domain with slash", ExternalUserPolicyConfig{AllowedEmailDomains: []string{"example.com/"}}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := NewExternalUserPolicy(tc.cfg); err == nil {
				t.Fatal("expected error")
			}
		})
	}
}

func TestExternalUserPolicy_DefaultRole(t *testing.T) {
	p, err := NewExternalUserPolicy(ExternalUserPolicyConfig{})
	if err != nil || p.DefaultRole() != model.RoleUser {
		t.Fatalf("empty role: %v %q", err, p.DefaultRole())
	}
}

func TestNotAllowedError(t *testing.T) {
	err := &NotAllowedError{Reason: "domain"}
	wrapped := fmt.Errorf("login: %w", err)
	for _, e := range []error{err, wrapped} {
		if !errors.Is(e, ErrExternalUserNotAllowed) {
			t.Fatalf("errors.Is failed for %v", e)
		}
	}
	if !err.ClientFault() {
		t.Fatal("ClientFault must be true")
	}
	if err.Error() == "" || err.Error() != ErrExternalUserNotAllowed.Error() {
		t.Fatalf("Error() must be reason-free, got %q", err.Error())
	}
}
