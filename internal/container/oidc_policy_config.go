package container

import (
	"errors"
	"fmt"
	"strings"

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

	requiredClaims, err := readRequiredClaims(v.Get("oidc.required_claims"))
	if err != nil {
		return nil, err
	}

	return userServices.NewExternalUserPolicy(userServices.ExternalUserPolicyConfig{
		JITEnabled:           v.GetBool("oidc.jit_enabled"),
		AllowedEmailDomains:  v.GetStringSlice("oidc.allowed_email_domains"),
		RequireEmailVerified: v.GetBool("oidc.require_email_verified"),
		RequiredClaims:       requiredClaims,
		DefaultRole:          v.GetString("oidc.default_role"),
		EnforceOnExisting:    enforceOnExisting,
	})
}

// readRequiredClaims converts the raw oidc.required_claims value into a map of
// trimmed claim names to string values. Any non-string value is an error that
// names the key only, so a typo cannot silently lock out every OIDC user.
func readRequiredClaims(raw any) (map[string]string, error) {
	out := map[string]string{}
	switch m := raw.(type) {
	case nil:
		return out, nil
	case map[string]string:
		for k, val := range m {
			out[strings.TrimSpace(k)] = val
		}
	case map[string]any:
		for k, val := range m {
			s, ok := val.(string)
			if !ok {
				return nil, fmt.Errorf("oidc.required_claims.%s must be a string", strings.TrimSpace(k))
			}
			out[strings.TrimSpace(k)] = s
		}
	default:
		return nil, errors.New("oidc.required_claims must be a map of claim names to strings")
	}
	return out, nil
}
