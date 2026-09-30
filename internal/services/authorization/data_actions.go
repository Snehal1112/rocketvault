package authorization

import (
	"net/http"
	"strings"

	"rocketvault/model"
)

// RouteKind classifies a request path for authorization purposes.
type RouteKind uint8

const (
	// RouteUnmanaged is a route that carries no vault data-plane authorization:
	// health probes, login, user management, vault management, role assignments,
	// access policies, and audit. These keep their existing gates.
	RouteUnmanaged RouteKind = iota
	// RouteVaultData is a vault data-plane resource route. Access requires a role
	// assignment in the resolved vault granting the mapped data action. A
	// RouteVaultData result with an empty action means "no mapping exists", which
	// callers MUST treat as a denial.
	RouteVaultData
)

// DataPlaneBasePath is the API version prefix stripped from request paths
// before route-to-data-action mapping. It must match the base path the API
// is actually served under (api.WithBasePath), or every data-plane route
// silently falls through to RouteUnmanaged, bypassing the deny-by-default
// gate this package drives.
const DataPlaneBasePath = "/api/v1"

// MapRouteToDataAction maps an HTTP method and path to the single Azure data
// action required to perform it.
//
// The flat shape ("/api/v1/secrets/{id}") and the vault-scoped shape
// ("/api/v1/vaults/{name}/secrets/{id}") map to the same action on purpose: the
// vault the action is evaluated against comes from the vault resolved into the
// request context, never from this string. That is the whole difference from
// the pre-P2 mapEndpointToPermission, which stripped the vault prefix and then
// checked a single vault-agnostic global permission, letting any principal with
// that permission operate on any vault by name.
//
// Returns RouteUnmanaged for paths that are not vault data-plane routes.
func MapRouteToDataAction(method, path string) (model.DataAction, RouteKind) {
	p := normalizeAuthPath(path)

	// A leading "vaults/{name}/" segment only locates the resource. Dropping it
	// does not widen the check: the caller evaluates the returned action against
	// the resolved vault.
	if rest, found := strings.CutPrefix(p, "vaults/"); found {
		parts := strings.SplitN(rest, "/", 2)
		if len(parts) < 2 || parts[1] == "" {
			// "vaults" or "vaults/{name}" — vault management, not data plane.
			return "", RouteUnmanaged
		}
		p = parts[1]
	} else if p == "vaults" {
		return "", RouteUnmanaged
	}

	switch {
	case p == "deleted":
		return "", RouteUnmanaged
	case strings.HasPrefix(p, "deleted/"):
		return mapDeletedAction(method, strings.TrimPrefix(p, "deleted/"))
	case p == "secrets" || strings.HasPrefix(p, "secrets/"):
		return mapSecretAction(method, strings.TrimPrefix(strings.TrimPrefix(p, "secrets"), "/"))
	case p == "keys" || strings.HasPrefix(p, "keys/"):
		return mapKeyAction(method, strings.TrimPrefix(strings.TrimPrefix(p, "keys"), "/"))
	case p == "certificates" || strings.HasPrefix(p, "certificates/"):
		return mapCertificateAction(method, strings.TrimPrefix(strings.TrimPrefix(p, "certificates"), "/"))
	case p == "purge":
		if method == http.MethodDelete {
			return model.ActionVaultPurge, RouteVaultData
		}
		return "", RouteVaultData
	}
	return "", RouteUnmanaged
}

// normalizeAuthPath strips the API version prefix and the surrounding slashes so
// the mappers below see a bare "resource/segments" string.
func normalizeAuthPath(path string) string {
	p := strings.TrimPrefix(path, DataPlaneBasePath)
	return strings.Trim(p, "/")
}

// mapSecretAction maps the segments after "secrets" to a secret data action.
func mapSecretAction(method, rest string) (model.DataAction, RouteKind) {
	switch rest {
	case "":
		switch method {
		case http.MethodGet:
			return model.ActionSecretsReadMetadata, RouteVaultData
		case http.MethodPost:
			return model.ActionSecretsSet, RouteVaultData
		}
		return "", RouteVaultData
	case "generate", "import":
		if method == http.MethodPost {
			return model.ActionSecretsSet, RouteVaultData
		}
		return "", RouteVaultData
	case "export":
		if method == http.MethodPost {
			return model.ActionSecretsGet, RouteVaultData
		}
		return "", RouteVaultData
	case "restore":
		if method == http.MethodPost {
			return model.ActionSecretsRestore, RouteVaultData
		}
		return "", RouteVaultData
	}

	seg := strings.Split(rest, "/")
	switch {
	case len(seg) == 1:
		switch method {
		case http.MethodGet:
			return model.ActionSecretsGet, RouteVaultData
		case http.MethodPut:
			return model.ActionSecretsSet, RouteVaultData
		case http.MethodDelete:
			return model.ActionSecretsDelete, RouteVaultData
		}
	case len(seg) == 2 && seg[1] == "backup" && method == http.MethodPost:
		return model.ActionSecretsBackup, RouteVaultData
	case len(seg) == 2 && seg[1] == "versions" && method == http.MethodGet:
		// Listing versions exposes metadata only.
		return model.ActionSecretsReadMetadata, RouteVaultData
	case len(seg) == 3 && seg[1] == "versions" && method == http.MethodGet:
		// A specific version, or "latest", returns the value.
		return model.ActionSecretsGet, RouteVaultData
	}
	return "", RouteVaultData
}

// mapKeyAction maps the segments after "keys" to a key data action.
func mapKeyAction(method, rest string) (model.DataAction, RouteKind) {
	switch rest {
	case "":
		switch method {
		case http.MethodGet:
			return model.ActionKeysRead, RouteVaultData
		case http.MethodPost:
			return model.ActionKeysCreate, RouteVaultData
		}
		return "", RouteVaultData
	case "restore":
		if method == http.MethodPost {
			return model.ActionKeysRestore, RouteVaultData
		}
		return "", RouteVaultData
	case "import":
		if method == http.MethodPost {
			return model.ActionKeysImport, RouteVaultData
		}
		return "", RouteVaultData
	}

	seg := strings.Split(rest, "/")
	if len(seg) == 1 {
		switch method {
		case http.MethodGet:
			return model.ActionKeysRead, RouteVaultData
		case http.MethodPut:
			return model.ActionKeysUpdate, RouteVaultData
		case http.MethodDelete:
			return model.ActionKeysDelete, RouteVaultData
		}
		return "", RouteVaultData
	}
	if len(seg) == 2 {
		if seg[1] == "versions" && method == http.MethodGet {
			return model.ActionKeysRead, RouteVaultData
		}
		if seg[1] == "rotationpolicy" {
			switch method {
			case http.MethodGet:
				return model.ActionKeysRotationPolicyRead, RouteVaultData
			case http.MethodPut, http.MethodDelete:
				return model.ActionKeysRotationPolicyWrite, RouteVaultData
			}
			return "", RouteVaultData
		}
		if method == http.MethodPost {
			switch seg[1] {
			case "rotate":
				return model.ActionKeysRotate, RouteVaultData
			case "backup":
				return model.ActionKeysBackup, RouteVaultData
			case "wrap":
				return model.ActionKeysWrap, RouteVaultData
			case "unwrap":
				return model.ActionKeysUnwrap, RouteVaultData
			case "sign":
				return model.ActionKeysSign, RouteVaultData
			case "verify":
				return model.ActionKeysVerify, RouteVaultData
			case "encrypt":
				return model.ActionKeysEncrypt, RouteVaultData
			case "decrypt":
				return model.ActionKeysDecrypt, RouteVaultData
			}
		}
	}
	if len(seg) == 3 && seg[1] == "versions" && method == http.MethodGet {
		// A specific key version returns metadata only.
		return model.ActionKeysRead, RouteVaultData
	}
	return "", RouteVaultData
}

// mapCertificateAction maps the segments after "certificates" to a certificate
// data action. Writing or clearing a certificate's policy is an update of the
// certificate, matching Azure, which has no separate policy data action.
func mapCertificateAction(method, rest string) (model.DataAction, RouteKind) {
	switch rest {
	case "":
		switch method {
		case http.MethodGet:
			return model.ActionCertificatesRead, RouteVaultData
		case http.MethodPost:
			return model.ActionCertificatesCreate, RouteVaultData
		}
		return "", RouteVaultData
	case "restore":
		if method == http.MethodPost {
			return model.ActionCertificatesRestore, RouteVaultData
		}
		return "", RouteVaultData
	}

	seg := strings.Split(rest, "/")
	if len(seg) == 1 {
		switch method {
		case http.MethodGet:
			return model.ActionCertificatesRead, RouteVaultData
		case http.MethodPut:
			return model.ActionCertificatesUpdate, RouteVaultData
		case http.MethodDelete:
			return model.ActionCertificatesDelete, RouteVaultData
		}
		return "", RouteVaultData
	}
	if len(seg) == 2 {
		switch seg[1] {
		case "policy":
			switch method {
			case http.MethodGet:
				return model.ActionCertificatesRead, RouteVaultData
			case http.MethodPut, http.MethodDelete:
				return model.ActionCertificatesUpdate, RouteVaultData
			}
		case "backup":
			if method == http.MethodPost {
				return model.ActionCertificatesBackup, RouteVaultData
			}
		case "versions":
			if method == http.MethodGet {
				return model.ActionCertificatesRead, RouteVaultData
			}
		case "renew":
			if method == http.MethodPost {
				return model.ActionCertificatesCreate, RouteVaultData
			}
		}
	}
	if len(seg) == 3 && seg[1] == "versions" {
		switch method {
		case http.MethodGet:
			return model.ActionCertificatesRead, RouteVaultData
		case http.MethodPut:
			return model.ActionCertificatesUpdate, RouteVaultData
		}
	}
	return "", RouteVaultData
}

// mapDeletedAction maps the soft-delete routes. rest is everything after
// "deleted/", i.e. "{resource}", "{resource}/{id}", or "{resource}/{id}/{op}".
func mapDeletedAction(method, rest string) (model.DataAction, RouteKind) {
	seg := strings.Split(rest, "/")
	if seg[0] != "secrets" && seg[0] != "keys" && seg[0] != "certificates" {
		return "", RouteVaultData
	}

	switch len(seg) {
	case 1: // GET /deleted/{resource}
		if method == http.MethodGet {
			switch seg[0] {
			case "secrets":
				return model.ActionSecretsReadMetadata, RouteVaultData
			case "keys":
				return model.ActionKeysRead, RouteVaultData
			case "certificates":
				return model.ActionCertificatesRead, RouteVaultData
			}
		}
	case 2: // GET /deleted/{resource}/{id}
		if method == http.MethodGet {
			switch seg[0] {
			case "secrets":
				return model.ActionSecretsGet, RouteVaultData
			case "keys":
				return model.ActionKeysRead, RouteVaultData
			case "certificates":
				return model.ActionCertificatesRead, RouteVaultData
			}
		}
	case 3: // /deleted/{resource}/{id}/restore | /purge
		switch {
		case seg[2] == "restore" && method == http.MethodPost:
			switch seg[0] {
			case "secrets":
				return model.ActionSecretsRecover, RouteVaultData
			case "keys":
				return model.ActionKeysRecover, RouteVaultData
			case "certificates":
				return model.ActionCertificatesRecover, RouteVaultData
			}
		case seg[2] == "purge" && method == http.MethodDelete:
			switch seg[0] {
			case "secrets":
				return model.ActionSecretsPurge, RouteVaultData
			case "keys":
				return model.ActionKeysPurge, RouteVaultData
			case "certificates":
				return model.ActionCertificatesPurge, RouteVaultData
			}
		}
	}
	return "", RouteVaultData
}
