package vaultapi

import (
	"fmt"
	"net/http"
	"strings"
)

// ErrorKind classifies an API failure so callers can react without matching
// on status codes.
type ErrorKind int

const (
	// KindUnknown is any status this package does not classify.
	KindUnknown ErrorKind = iota
	KindUnauthorized
	KindForbidden
	KindNotFound
	KindConflict
	KindServer
)

// APIError describes a non-2xx response.
//
// It deliberately carries no part of the response body. A 403 or 409 payload
// can echo the request that produced it, and for a secret write that request
// contains a secret value. Everything user-facing here is derived from the
// request line we sent, which holds no secret material.
type APIError struct {
	Kind       ErrorKind
	StatusCode int
	Method     string
	Path       string
	// Hint is operator-facing guidance, such as the data action that was
	// denied and a role that would grant it.
	Hint string
}

func (e *APIError) Error() string {
	if e.Hint != "" {
		return fmt.Sprintf("%s %s: %s (HTTP %d)", e.Method, e.Path, e.Hint, e.StatusCode)
	}
	return fmt.Sprintf("%s %s: HTTP %d", e.Method, e.Path, e.StatusCode)
}

// Retryable reports whether retrying the same request could plausibly succeed.
func (e *APIError) Retryable() bool { return e.Kind == KindServer }

// newAPIError classifies a response. The response body is never read.
func newAPIError(method, path string, statusCode int) *APIError {
	err := &APIError{
		Kind:       kindForStatus(statusCode),
		StatusCode: statusCode,
		Method:     method,
		Path:       path,
	}
	err.Hint = hintFor(err)
	return err
}

func kindForStatus(status int) ErrorKind {
	switch {
	case status == http.StatusUnauthorized:
		return KindUnauthorized
	case status == http.StatusForbidden:
		return KindForbidden
	case status == http.StatusNotFound:
		return KindNotFound
	case status == http.StatusConflict:
		return KindConflict
	case status >= http.StatusInternalServerError:
		return KindServer
	default:
		return KindUnknown
	}
}

// hintFor builds operator-facing guidance from the request line alone.
func hintFor(e *APIError) string {
	switch e.Kind {
	case KindUnauthorized:
		return "not authenticated — run `rocketvault users login`, or check the MCP service-account credentials"
	case KindForbidden:
		// The audit route gates on the global admin role, not on a data
		// action (api/audit.go:66). Suggesting a vault role here would send
		// the operator to a grant that cannot help.
		if strings.HasPrefix(e.Path, auditLogsPath) {
			return "audit querying requires the global admin role; no per-vault role assignment grants it"
		}
		if issuesCertificate(e.Method, e.Path) {
			return certificateIssueForbiddenHint(e.Path)
		}
		resource, verb := resourceAndVerb(e.Method, e.Path)
		action := fmt.Sprintf("Microsoft.KeyVault/vaults/%s/%s", resource, verb)
		role := roleFor(resource, verb)
		vault := vaultFromPath(e.Path)
		hint := fmt.Sprintf("principal lacks %s; grant e.g. %q", action, role)
		if vault != "" {
			hint = fmt.Sprintf("principal lacks %s in vault %q; grant e.g. %q", action, vault, role)
		}
		return hint
	case KindNotFound:
		// On create, a 404 means the key or CA named in the body is missing
		// (B78). Renewal's 404 is the certificate itself, as elsewhere.
		if e.Method == http.MethodPost && strings.HasSuffix(e.Path, "/certificates") {
			return "the signing key or CA certificate named in the request does not exist in this vault"
		}
		return "no such resource in this vault"
	case KindConflict:
		return "a resource with that name already exists, or the operation conflicts with current state"
	case KindServer:
		return "the server failed to handle the request"
	default:
		return ""
	}
}

// resourceAndVerb derives the data-action resource and verb from the request.
func resourceAndVerb(method, path string) (resource, verb string) {
	resource = "secrets"
	for _, candidate := range []string{"secrets", "keys", "certificates", "role-assignments"} {
		if strings.Contains(path, "/"+candidate) {
			resource = candidate
			break
		}
	}

	switch method {
	case http.MethodGet, http.MethodHead:
		verb = "read"
	case http.MethodPost:
		verb = "create"
	case http.MethodPut, http.MethodPatch:
		verb = "update"
	case http.MethodDelete:
		verb = "delete"
		if strings.HasSuffix(path, "/purge") {
			verb = "purge"
		}
	default:
		verb = "read"
	}
	return resource, verb
}

// certificateIssueForbiddenHint covers every reason issuing or renewing a
// certificate answers 403. The response body is never read, so the hint
// cannot tell a missing role from a refused signing key; it names both
// (B77, B78).
func certificateIssueForbiddenHint(path string) string {
	where := ""
	if vault := vaultFromPath(path); vault != "" {
		where = fmt.Sprintf(" in vault %q", vault)
	}
	return fmt.Sprintf("issuing or renewing a certificate needs Microsoft.KeyVault/vaults/certificates/create "+
		"(e.g. %q) and Microsoft.KeyVault/vaults/keys/sign/action (e.g. %q)%s, "+
		"and a signing key and CA certificate the principal owns, with the key enabled, not revoked "+
		"and inside its valid time window",
		roleFor("certificates", "create"), roleFor("keys", "read"), where)
}

// issuesCertificate reports whether a request issues or renews a
// certificate. Both sign with a key, so they need keys/sign as well as
// certificates/create (B77).
func issuesCertificate(method, path string) bool {
	if method != http.MethodPost {
		return false
	}
	return strings.HasSuffix(path, "/certificates") ||
		(strings.Contains(path, "/certificates/") && strings.HasSuffix(path, "/renew"))
}

// roleFor names a built-in role that grants the given action. The names come
// from model/azure_roles.go.
func roleFor(resource, verb string) string {
	readOnly := verb == "read"
	switch resource {
	case "keys":
		if readOnly {
			return "Key Vault Crypto User"
		}
		return "Key Vault Crypto Officer"
	case "certificates":
		if readOnly {
			return "Key Vault Certificate User"
		}
		return "Key Vault Certificates Officer"
	case "role-assignments":
		return "Key Vault Data Access Administrator"
	default:
		if readOnly {
			return "Key Vault Secrets User"
		}
		return "Key Vault Secrets Officer"
	}
}

// vaultFromPath extracts the vault name from a vault-scoped path such as
// /api/v1/vaults/prod/secrets. It returns "" for any other shape.
func vaultFromPath(path string) string {
	const marker = "/vaults/"
	idx := strings.Index(path, marker)
	if idx < 0 {
		return ""
	}
	rest := path[idx+len(marker):]
	if rest == "" {
		return ""
	}
	if slash := strings.Index(rest, "/"); slash >= 0 {
		return rest[:slash]
	}
	return rest
}
