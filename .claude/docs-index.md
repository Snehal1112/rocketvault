# Documentation index

Moved verbatim out of the project CLAUDE.md on 2026-10-20 to keep it short.

## Key Components Documentation

### 🧠 AI Knowledge Base (`~/data/rocket/Nl-knowledge-base/rocketvault/`)
- Local-machine, AI-maintained reference — not part of this repo, not committed, don't expect it on a fresh clone
- 10 topic pages (overview, architecture, dev-workflow, database, testing, security-auth, multi-vault, release-process, known-issues-gotchas, glossary), each re-verified against source, not just transcribed from docs — see its `README.md` for the one-line index and last-verified commit per page
- **Before implementing in a subsystem**, read that subsystem's page first (e.g. touching `internal/services/authorization/` → `security-auth.md`) — cheaper and more precise than re-deriving architecture from source each time
- **Before debugging**, check `known-issues-gotchas.md` first — it's a grep-first catalogue of past incidents and filed bugs with root cause and fix, and often the bug is already documented
- Refreshed via the `kb-refresh` skill (targeted diff since last verified commit, not a full rebuild) — if a page looks stale for the current HEAD, ask for a refresh rather than trusting it blindly

### 📘 [Administrator Manual](docs/admin-manual.html)
- Single authoritative, operationally-focused handbook covering every feature
- Getting started, identity & access, core resources, operations, integration
- Canonical entry point; older guides are linked as deep-dives

### 🏛️ [Multi-Vault Architecture](.claude/multi-vault.md)
- Vault as a routing + context-scoping layer (Azure Key Vault parity)
- Vault-scoped resources, per-vault access policies, default-vault migration
- Keys/certs CLI `--vault` wiring and vault-scoped soft-delete (list/restore/purge) shipped 2026-08-11–13; `.claude/multi-vault.md`'s "Known deferrals" section was refreshed to match on 2026-08-26

### 🔵 [Azure Key Vault Feature Parity](.claude/azure-keyvault-parity.md)
- Feature-by-feature comparison (secrets, keys, certs, RBAC, soft-delete, HSM, audit)
- Parity status per capability with code and Azure-doc sources
- RocketVault extras and intentional gaps vs Azure Key Vault

### 🐛 [Known Bugs](.claude/known-bugs.md)
- Open bugs, fixed bugs, and deferred refactors with root-cause analysis and fix recipes
- This is the living source of truth for bug status — don't duplicate bug entries elsewhere in this file, they will drift stale (see the "Open Bugs" note below)

### 🗺️ [Roadmap — Azure Parity & Beyond](.claude/roadmap-azure-parity-and-beyond.md)
- Phased plan built on `.claude/azure-keyvault-parity.md`'s gap analysis: close remaining Azure Key Vault gaps first (key import, rotation-policy scheduler, HSM P-256K/AES-CBC, ACME certs, one RBAC role fix), then platform maturity, then self-hosted-native differentiators beyond Azure
- README's `## Roadmap > Planned` section is a short checklist pointing here — this doc carries the rationale, non-goals, and phase grouping

### 🧪 [CLI Test Suite Implementation](doc/README_TESTS.md)
- Comprehensive test coverage for all CLI commands
- Mock infrastructure and service testing framework
- Security validation and authentication testing
- Performance and integration testing capabilities

### 👤 [Admin User Setup Guide](doc/README_ADMIN_SETUP.md)
- Bootstrap token configuration and management
- Initial admin user creation process
- MFA setup and TOTP configuration
- Authentication flow validation

> Nine previously-listed docs here (`current-architecture-state.md`, `service-layer-analysis.md`,
> `dependency-injection-guide.md`, `database-optimization.md`, `auth-elimination-guide.md`,
> `service-container-integration.md`, `retry-system-architecture.md`, `retry-integration-guide.md`,
> `retry-configuration-reference.md`, plus `database-init-patterns.md`,
> `repository-migration-status.md`, `repository-pattern-standardization.md`,
> `configuration-standardization.md`, `cmd-cleanup-report.md`) do not exist under `.claude/` and
> were removed 2026-08-11 — they described one-time refactors that already landed; the code itself
> and `.claude/known-bugs.md` are now the source of truth for that history. If you need one of
> these topics, check `git log` for the commit that did the work rather than looking for a doc.

## Additional Documentation

### Developer Resources
- **[API Developer Guide](docs/api-developer-guide.md)**: REST API reference, authentication, and SDK examples
- **[Testing Guide](docs/testing-guide.md)**: Comprehensive testing procedures and scenarios
- **[Integration Examples](docs/integration-examples.md)**: Integration patterns and examples
- **[CLI Usage Guide](docs/cli-guide.md)**: Step-by-step CLI walkthrough, first-time setup to everyday use
- **[Vault, User & Access Journeys](docs/VAULT_USER_ACCESS_JOURNEYS_v3.md)**: 21 end-to-end scenarios organized by actor and role rather than by command — onboarding, delegated access management, emergency explicit-deny, offboarding, vault retirement, multi-vault isolation. Its commands are taken from `cmd/`, never invented, and where a capability has no CLI equivalent the journey says so instead of showing a plausible-looking invocation; several journeys exist specifically to document CLI/HTTP behaviour divergences (e.g. the `vaults purge` admin-bypass split described under Azure Role Additions above). Useful when you need to know how a role behaves in practice, not what a command's flags are
- **[QA Journeybook](journeybook/README.md)**: The journeys document above, turned into a single-file offline HTML page (`journeybook/dist/journeybook.html`) that a QA engineer opens from disk and records a pass or fail against — 23 suites, 247 checks, each carrying its command, its verbatim expected output, and which of the three gates it exercises. Most checks also carry the mechanism behind the behaviour, how to settle a result the expected line leaves ambiguous, what the check leaves behind, and cross-references to the checks it depends on or contradicts — each claim citing the document section or `file.go:line` it came from, enforced by `bun run check:links`. Checks the sources do not explain carry no explanation, which is deliberate: an absent field is honest and an invented one would send a tester to file a defect against working software. Verdicts live in the tester's own browser and export as a plain-text summary. The cases are transcribed from `docs/VAULT_USER_ACCESS_JOURNEYS_v3.md` and go stale the moment the CLI changes without them — see `journeybook/.claude/authoring-cases.md` for the rules before editing them
- **[Setup Guide](doc/setup.md)**: Installation and initial configuration
- **[Intent Convention](.claude/intent-convention.md)**: Before brainstorming's architectural path starts designing, write a short `docs/superpowers/intents/YYYY-MM-DD-<topic>.md` first — what/why/scope/out-of-scope, a few sentences each
- **[v4.0.0 Azure RBAC Release Notes](docs/release-notes/v4.0.0-azure-rbac.md)**: Breaking changes, role table, and upgrade procedure
- **[MCP Server Guide](docs/mcp-server.md)**: Running `rocketvault mcp` for Claude Code and Claude Desktop, capability tiers, and service-account setup
