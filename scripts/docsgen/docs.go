package main

import (
	"path/filepath"
	"runtime"
)

// repoRoot is resolved from this source file's own location so the tool
// behaves the same regardless of the working directory it's invoked from.
var repoRoot = func() string {
	_, file, _, _ := runtime.Caller(0)
	// scripts/docsgen/docs.go -> repo root is two directories up.
	return filepath.Dir(filepath.Dir(filepath.Dir(file)))
}()

var (
	assetsCSS   = filepath.Join(repoRoot, "docs/assets/doc-theme.css")
	assetsJS    = filepath.Join(repoRoot, "docs/assets/doc-theme.js")
	adminManual = filepath.Join(repoRoot, "docs/admin-manual.html")
)

type docEntry struct {
	Src string // markdown source, relative to repo root
	Out string // generated HTML, relative to repo root
}

// docsList mirrors admin-manual.html's "see also" links: every markdown file
// it points to gets rendered into a matching styled HTML sibling.
var docsList = []docEntry{
	{"MANUAL_TESTING.md", "MANUAL_TESTING.html"},
	{"doc/README_ADMIN_SETUP.md", "doc/README_ADMIN_SETUP.html"},
	{"doc/security.markdown", "doc/security.html"},
	{"doc/setup.md", "doc/setup.html"},
	{"doc/troubleshooting.markdown", "doc/troubleshooting.html"},
	{"docs/api-developer-guide.md", "docs/api-developer-guide.html"},
	{"docs/consuming-secrets-guide.md", "docs/consuming-secrets-guide.html"},
	{"docs/deploy-railway.md", "docs/deploy-railway.html"},
	{"docs/hsm-softhsm2-testing.md", "docs/hsm-softhsm2-testing.html"},
	{"docs/integration-examples.md", "docs/integration-examples.html"},
	{"docs/release-notes/v4.0.0-azure-rbac.md", "docs/release-notes/v4.0.0-azure-rbac.html"},
	{"docs/release-notes/v4.1.0-role-parity-and-authz-fix.md", "docs/release-notes/v4.1.0-role-parity-and-authz-fix.html"},
	{"docs/release-notes/v4.2.0-ca-certificates.md", "docs/release-notes/v4.2.0-ca-certificates.html"},
	{"docs/release-notes/v4.3.0-api-secrets-passphrase.md", "docs/release-notes/v4.3.0-api-secrets-passphrase.html"},
	{"docs/release-notes/v4.5.0-vault-provisioning.md", "docs/release-notes/v4.5.0-vault-provisioning.html"},
	{"docs/release-notes/v4.6.0-narrow-global-vault-manage.md", "docs/release-notes/v4.6.0-narrow-global-vault-manage.html"},
	{"docs/release-notes/v4.7.1-secrets-and-error-responses.md", "docs/release-notes/v4.7.1-secrets-and-error-responses.html"},
	{"docs/release-notes/v4.8.0-identity-sessions-hardening.md", "docs/release-notes/v4.8.0-identity-sessions-hardening.html"},
	{"docs/release-notes/v4.9.0-login-rate-limiting.md", "docs/release-notes/v4.9.0-login-rate-limiting.html"},
	{"docs/runbooks/hsm-pin-rotation.md", "docs/runbooks/hsm-pin-rotation.html"},
	{"docs/runbooks/master-key-rotation.md", "docs/runbooks/master-key-rotation.html"},
	{"docs/usage-guide.md", "docs/usage-guide.html"},
	{"docs/VAULT_USER_ACCESS_JOURNEYS_v3.md", "docs/VAULT_USER_ACCESS_JOURNEYS_v3.html"},
}

// extraFiles are hand-written HTML pages the docsList generator doesn't
// cover, but that belong in a packaged docs bundle alongside it.
var extraFiles = []string{
	"docs/admin-manual.html",
	"docs/rocketvault-architecture.html",
	"docs/assets/doc-theme.css",
	"docs/assets/doc-theme.js",
}
