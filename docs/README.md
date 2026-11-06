# RocketVault documentation

Start with the [Administrator Manual](admin-manual.html). It is the single operational handbook and
links every guide below as a deep dive.

## Guides

| Guide | What it covers |
|---|---|
| [Getting started](getting-started.md) | Install, configure and run a first instance |
| [Usage guide](usage-guide.md) | Everyday tasks across CLI, REST and MCP |
| [CLI guide](cli-guide.md) | CLI walkthrough from first setup to daily use |
| [API developer guide](api-developer-guide.md) | REST reference, authentication, SDK examples |
| [Consuming secrets](consuming-secrets-guide.md) | How applications and service accounts read secrets |
| [Integration examples](integration-examples.md) | Integration patterns |
| [MCP server](mcp-server.md) | Running `rocketvault mcp` for Claude Code and Claude Desktop |
| [Deploy on Railway](deploy-railway.md) | Railway deployment recipe |
| [HSM with SoftHSM2](hsm-softhsm2-testing.md) | Testing PKCS#11 HSM support locally |
| [Vault, user and access journeys](VAULT_USER_ACCESS_JOURNEYS_v3.md) | 21 end-to-end scenarios by actor and role |
| [QA journeybook](../journeybook/README.md) | The journeys as an offline HTML checklist for QA |
| [Admin user setup](admin-setup.md) | Bootstrap token and first admin |

## Architecture and design

| Document | What it covers |
|---|---|
| [Architecture](architecture/architecture.md) | Directory tree, DI container, code patterns, testing |
| [Service layer](architecture/service-layer.md) | Service, repository and middleware split; authorization tiers; role history |
| [Multi-vault](architecture/multi-vault.md) | Vaults as isolation boundaries, vault-scoped resources, known deferrals |
| [Azure Key Vault parity](architecture/azure-keyvault-parity.md) | Feature-by-feature comparison with Azure Key Vault |
| [Secret cache cloning](architecture/secret-cache-cloning.md) | Clone-on-get and clone-on-set in the secret cache |
| [Scope and access policy model](architecture/scope-vault-access-policy-viz.html) | Visual explainer of scopes, vaults and access policies |
| [Architecture overview (HTML)](rocketvault-architecture.html) | High-level diagram |

## Contributing

| Document | What it covers |
|---|---|
| [Configuration](contributing/configuration.md) | Config keys and admin setup notes |
| [CLI help conventions](contributing/cli-help-conventions.md) | How to write CLI help text and examples |
| [Testing guide](testing-guide.md) | Automated test suites and how to run them |
| [Manual testing plan](testing/manual-testing-plan.md) | Step-by-step QA plan covering every feature |
| [Manual test checklist](testing/manual-test-checklist.md) | Short pre-release checklist |

## Project status

| Document | What it covers |
|---|---|
| [Known bugs](known-bugs.md) | Source of truth for bug status; each entry has a GitHub issue |
| [Roadmap: Azure parity and beyond](roadmap/azure-parity-and-beyond.md) | Phased product roadmap |
| [Release notes](release-notes/) | Per-version changes and upgrade steps |
| [Plans](plans/) and [superpowers](superpowers/) | Dated design intents, specs and implementation plans |

## Operations and security

| Document | What it covers |
|---|---|
| [Master key rotation runbook](runbooks/master-key-rotation.md) | Offline master key rotation |
| [HSM PIN rotation runbook](runbooks/hsm-pin-rotation.md) | Rotating the PKCS#11 user PIN |
| [Security incident 2026-03-07](security/security-incident-2026-03-07.md) | Config secrets committed to git: timeline and remediation |
| [Master key rotation log 2026-08-16](security/master-key-rotation-log-2026-08-16.md) | Record of the dev-instance rotation after that incident |

## Where new docs go

- Public docs go in `docs/`, in the folder that matches the tables above.
- Docs with unfixed-vulnerability detail, commercial plans or working notes go in `docs/internal/`.
  That folder is gitignored and never committed, because the repository is public.
- Files that configure Claude Code (agents, skills, commands, settings) stay in `.claude/`.
