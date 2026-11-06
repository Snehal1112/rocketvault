package container

import (
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	userServices "rocketvault/internal/services/users"
)

func TestOIDCPolicyDisabledIgnoresJunkKeys(t *testing.T) {
	v := viper.New()
	v.Set("oidc.enabled", false)
	v.Set("oidc.default_role", "admin")
	v.Set("oidc.allowed_email_domains", []string{"@bad domain"})

	p, err := buildExternalUserPolicy(v)
	require.NoError(t, err)
	assert.Nil(t, p)
}

func TestOIDCPolicyDefaults(t *testing.T) {
	v := viper.New()
	v.Set("oidc.enabled", true)

	p, err := buildExternalUserPolicy(v)
	require.NoError(t, err)
	require.NotNil(t, p)
	assert.Equal(t, "user", p.DefaultRole())
	// JIT is off by default, so a new identity is denied.
	assert.ErrorIs(t, p.Evaluate(userServices.ExternalIdentity{}, true), userServices.ErrExternalUserNotAllowed)
}

func TestOIDCPolicyEnforceOnExistingDefaultsTrue(t *testing.T) {
	v := viper.New()
	v.Set("oidc.enabled", true)
	v.Set("oidc.require_email_verified", true)

	p, err := buildExternalUserPolicy(v)
	require.NoError(t, err)
	assert.ErrorIs(t, p.Evaluate(userServices.ExternalIdentity{EmailVerified: false}, false), userServices.ErrExternalUserNotAllowed)

	v.Set("oidc.enforce_on_existing", false)
	p, err = buildExternalUserPolicy(v)
	require.NoError(t, err)
	assert.NoError(t, p.Evaluate(userServices.ExternalIdentity{EmailVerified: false}, false))
}

func TestOIDCPolicyReadsAllKeys(t *testing.T) {
	v := viper.New()
	v.Set("oidc.enabled", true)
	v.Set("oidc.jit_enabled", true)
	v.Set("oidc.allowed_email_domains", []string{"example.com"})
	v.Set("oidc.require_email_verified", true)
	v.Set("oidc.required_claims", map[string]string{"hd": "example.com"})
	v.Set("oidc.default_role", "user")

	p, err := buildExternalUserPolicy(v)
	require.NoError(t, err)

	ok := userServices.ExternalIdentity{
		Email: "a@Example.com", EmailVerified: true,
		Claims: map[string]any{"hd": "example.com"},
	}
	assert.NoError(t, p.Evaluate(ok, true))

	badDomain := ok
	badDomain.Email = "a@other.com"
	assert.Error(t, p.Evaluate(badDomain, true))

	unverified := ok
	unverified.EmailVerified = false
	assert.Error(t, p.Evaluate(unverified, true))

	noClaim := ok
	noClaim.Claims = map[string]any{}
	assert.Error(t, p.Evaluate(noClaim, true))
}

func TestOIDCPolicyRequiredClaimsRejectsNonString(t *testing.T) {
	cases := map[string]any{"bool": true, "number": 5, "list": []any{"a", "b"}}
	for name, val := range cases {
		t.Run(name, func(t *testing.T) {
			v := viper.New()
			v.Set("oidc.enabled", true)
			v.Set("oidc.required_claims", map[string]any{"hd": val})
			_, err := buildExternalUserPolicy(v)
			require.Error(t, err)
			assert.Contains(t, err.Error(), "hd")
		})
	}
}

func TestOIDCPolicyRequiredClaimsTrimsNames(t *testing.T) {
	v := viper.New()
	v.Set("oidc.enabled", true)
	v.Set("oidc.required_claims", map[string]any{" hd ": "example.com"})
	p, err := buildExternalUserPolicy(v)
	require.NoError(t, err)
	assert.NoError(t, p.Evaluate(userServices.ExternalIdentity{Claims: map[string]any{"hd": "example.com"}}, false))
}

func TestOIDCPolicyRequiredClaimsEmptyMapIsFine(t *testing.T) {
	v := viper.New()
	v.Set("oidc.enabled", true)
	v.Set("oidc.required_claims", map[string]any{})
	_, err := buildExternalUserPolicy(v)
	require.NoError(t, err)
}

func TestOIDCPolicyInvalidConfig(t *testing.T) {
	v := viper.New()
	v.Set("oidc.enabled", true)
	v.Set("oidc.default_role", "admin")
	_, err := buildExternalUserPolicy(v)
	assert.Error(t, err)

	v = viper.New()
	v.Set("oidc.enabled", true)
	v.Set("oidc.allowed_email_domains", []string{"@bad domain"})
	_, err = buildExternalUserPolicy(v)
	assert.Error(t, err)
}
