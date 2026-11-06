package container

import (
	"github.com/spf13/viper"

	userServices "rocketvault/internal/services/users"
)

// buildExternalUserPolicy reads the oidc.* policy keys and validates them. It
// returns a nil policy without reading any other key when OIDC is disabled.
func buildExternalUserPolicy(v *viper.Viper) (*userServices.ExternalUserPolicy, error) {
	if !v.GetBool("oidc.enabled") {
		return nil, nil
	}

	// An unset key enforces the policy on existing users; an explicit false wins.
	enforceOnExisting := true
	if v.IsSet("oidc.enforce_on_existing") {
		enforceOnExisting = v.GetBool("oidc.enforce_on_existing")
	}

	return userServices.NewExternalUserPolicy(userServices.ExternalUserPolicyConfig{
		JITEnabled:           v.GetBool("oidc.jit_enabled"),
		AllowedEmailDomains:  v.GetStringSlice("oidc.allowed_email_domains"),
		RequireEmailVerified: v.GetBool("oidc.require_email_verified"),
		RequiredClaims:       v.GetStringMapString("oidc.required_claims"),
		DefaultRole:          v.GetString("oidc.default_role"),
		EnforceOnExisting:    enforceOnExisting,
	})
}
