package model

import (
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
)

func TestValidateVaultName(t *testing.T) {
	cases := []struct {
		name string
		in   string
		ok   bool
	}{
		{"valid simple", "prod", true},
		{"valid hyphen", "team-a", true},
		{"too short", "ab", false},
		{"uppercase", "Prod", false},
		{"underscore", "team_a", false},
		{"leading hyphen", "-prod", false},
		{"trailing hyphen", "prod-", false},
		{"too long", "a-very-long-vault-name-that-exceeds-the-sixty-three-character-limit-xx", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := ValidateVaultName(c.in) == nil; got != c.ok {
				t.Fatalf("ValidateVaultName(%q) ok=%v, want %v", c.in, got, c.ok)
			}
		})
	}
}

func TestDefaultVaultConstants(t *testing.T) {
	if DefaultVaultName != "default" {
		t.Fatalf("DefaultVaultName = %q", DefaultVaultName)
	}
	if DefaultVaultID != "00000000-0000-0000-0000-00000000efa1" {
		t.Fatalf("DefaultVaultID = %q", DefaultVaultID)
	}
}

func TestVault_Clone_IndependentCopy(t *testing.T) {
	updatedBy := uuid.New()
	v := &Vault{
		ID:        uuid.New(),
		Name:      "original",
		Tags:      map[string]string{"env": "prod"},
		UpdatedBy: &updatedBy,
	}
	clone := v.Clone()

	clone.Name = "changed"
	clone.Tags["env"] = "mutated"
	*clone.UpdatedBy = uuid.New()

	assert.Equal(t, "original", v.Name)
	assert.Equal(t, "prod", v.Tags["env"], "mutating the clone's Tags must not affect the original's backing map")
	assert.NotEqual(t, *v.UpdatedBy, *clone.UpdatedBy)
}

func TestVault_Clone_NilFieldsStayNil(t *testing.T) {
	v := &Vault{ID: uuid.New(), Name: "x"}
	clone := v.Clone()
	assert.Nil(t, clone.Tags)
	assert.Nil(t, clone.DeletedAt)
	assert.Nil(t, clone.ScheduledPurgeAt)
	assert.Nil(t, clone.UpdatedAt)
	assert.Nil(t, clone.UpdatedBy)
}

// TestValidateNewVaultName_RefusesReservedNames pins B80's reservation, and
// that lookups through ValidateVaultName still accept the same names.
func TestValidateNewVaultName_RefusesReservedNames(t *testing.T) {
	for _, name := range []string{"login", "health", "refresh", "register"} {
		err := ValidateNewVaultName(name)
		if !errors.Is(err, ErrReservedVaultName) {
			t.Fatalf("ValidateNewVaultName(%q) = %v, want ErrReservedVaultName", name, err)
		}
		if err := ValidateVaultName(name); err != nil {
			t.Fatalf("ValidateVaultName(%q) = %v, want nil so existing vaults stay reachable", name, err)
		}
	}
	for _, ok := range []string{"prod", "default", "login-2", "my-health"} {
		if err := ValidateNewVaultName(ok); err != nil {
			t.Fatalf("ValidateNewVaultName(%q) = %v, want nil", ok, err)
		}
	}
	if err := ValidateNewVaultName("ab"); err == nil {
		t.Fatal("ValidateNewVaultName(ab) must still apply the syntax rule")
	}
	if err := ValidateNewVaultName("LOGIN"); err == nil || errors.Is(err, ErrReservedVaultName) {
		t.Fatalf("uppercase must fail the syntax rule, got %v", err)
	}
}
