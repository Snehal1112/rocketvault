# Roadmap — Azure Key Vault Parity & Beyond

Phased plan for what RocketVault builds next. Sourced from the gap analysis in
[`azure-keyvault-parity.md`](azure-keyvault-parity.md) (re-verify that doc's own
tables before treating any status here as current — it's the source of truth for
parity state, this doc is the plan built on top of it).

**Sequencing philosophy:** close the remaining, narrow Azure Key Vault gaps first,
then build self-hosted-native capabilities Azure structurally can't offer. Parity
is already strong (see the parity doc's Summary section) — this isn't a long
catch-up, it's a short list of specific closures followed by genuine
differentiation work.

This supersedes the flat "Planned" bullet list previously in README.md's
`## Roadmap` section (last touched 2026-08-11). README keeps a short checklist
linking here; this doc carries the rationale, non-goals, and phase grouping.

---

## High priority — multi-tenancy gaps (outside the Azure-parity frame)

Added 2026-09-03. These sit deliberately *before* Phase 1 by priority but outside
its definition: they are not Azure Key Vault parity gaps, because Azure has no
tenancy concept inside the vault service either — tenancy lives in the Azure
platform above it (subscription / Entra ID tenant). Nothing here maps to a row in
`azure-keyvault-parity.md`, so filing them under Phase 1 would misrepresent both
documents. They are Phase 3-shaped work (beyond Azure) promoted to the top by
priority.

**Why these matter:** RocketVault's honest positioning is *multi-vault isolation
with delegated per-vault administration*, not self-service multi-tenant SaaS. The
isolation itself is real — resources are scoped by `vault_id` at the query level,
per-vault RBAC is independent, and a vault member cannot enumerate other vaults.
The two gaps below are what stop that model from serving an MSP or hosting
provider, and they are the two things an evaluator will file as missing the moment
the product is described as "multi-tenant" without qualification.

The third gap in this set — **no per-vault quotas or rate limits**, where one
noisy tenant could spend the whole instance's request budget — was closed on
2026-09-03 by `VaultRateLimitMiddleware` (`internal/middleware/vault_rate_limit.go`,
config key `rate_limit.per_vault`). Metering beyond a rejection counter (per-vault
request volume, storage, billing) is still absent and belongs with the items below.

- **Self-service vault provisioning** — creating a vault, or listing vaults,
  requires a *global* `vaults:manage` grant: `createVault` and `listVaults` both
  check with `vaultID: uuid.Nil`, i.e. instance-wide rather than scoped to any one
  vault (`api/vault.go:77` and `api/vault.go:121`, and the explanatory comment at
  `api/vault.go:63`). Only a global `admin` account role or a `vaults:manage`
  access policy with `vault_id: NULL` satisfies that, so there is no way to say
  "may create vaults" without also saying "may manage every vault on the
  instance". A tenant administrator therefore cannot spin up their own
  vault — a platform operator has to provision it for them. This is the single
  blocker for the MSP / hosting-provider use case, where customers expect to
  create their own vaults without a support ticket. Closing it means a delegated
  provisioning right that is bounded (a quota on how many vaults a principal may
  create) rather than simply widening `vaults:manage`, which would hand out
  instance-wide authority.

  *Scope corrected 2026-09-03:* this entry previously read "creating or updating
  a vault" and cited `api/vault.go:121` as `updateVault`. Line 121 is
  `listVaults`; `updateVault` is at `api/vault.go:191` and authorizes against
  `target.ID` (line 218), so it is **already** properly vault-scoped — as are
  `getVault` (line 180) and `deleteVault` (line 275). The gap is narrower than
  the original text implied: a vault-scoped manager can already get, update and
  delete their vault, and only create and list demand a global grant. `listVaults`
  belongs in this item rather than a separate one — a delegated manager who could
  create a vault still could not enumerate their own.

  ***Release 1 shipped 2026-09-04:*** provisioning grants
  (`vault_provisioning_grants`) now exist. `CanCreateVault` (`internal/services/
  authorization/vault_authz.go`) decides admin / global-policy / bounded-grant;
  quota enforcement runs inside `VaultService.CreateVaultProvisioned`'s creation
  transaction (soft-deleted vaults count, only a purge frees a slot; a grantee
  cannot set `purge_protection`); `ListVaults` gained a scoped path so a grantee
  can see what it created; the admin API
  (`PUT`/`DELETE`/`GET /vault-provisioning-grants[/{principal_id}]`) and the CLI
  (`rocketvault vault-provisioning grant/revoke/list`) are both admin-only and
  deliberately non-delegable. Full detail:
  `docs/release-notes/v4.5.0-vault-provisioning.md`; design:
  `docs/superpowers/specs/2026-09-03-self-service-vault-provisioning-design.md`.

  **What remains open after release 1:**
  1. **The narrowing — shipped 2026-09-05 (release 2, v4.6.0).** A global
     `vaults:manage` grant now confers create-and-list only:
     `CanManageVault` and `CanManageRoleAssignments` both consult the new
     `AccessPolicyService.CheckVaultScopedAccess` for a concrete vault (a
     `NULL`-scoped deny still matches, a `NULL`-scoped allow no longer does),
     and fall back to `CheckAccess` only for the `uuid.Nil` collection-level
     create/list decision. `CheckAccess` and `FindEffects` themselves are
     untouched, so the secrets/keys/certificates data plane's global explicit
     deny still works exactly as before. Release 1's open question — what a
     global-policy holder gets on the create path once the narrowing lands —
     is **resolved, not deferred**: such a holder now receives the same
     vault-scoped creator grants (`vaults:manage` policy + `Key Vault
     Administrator` assignment) a provisioning grantee already gets, minus
     the quota check (`VaultService.CreateVaultProvisioned`'s new
     `grantCreatorRights` parameter). Full detail:
     `docs/release-notes/v4.6.0-narrow-global-vault-manage.md`.
  2. **Name prefixes / namespacing.** Still deliberately deferred (design
     doc's Non-goals) — one MSP automation principal creates every vault
     today, so a grantee's vault names still share one flat namespace with
     admin-created ones and can collide.
  3. **The tenant entity.** Still absent — see the next bullet below. `quota`
     lives on the grant row itself for now; when tenants land, `quota` and the
     future `name_prefix` move to the tenant row and the enforcement code does
     not change (design doc §"Non-goals").

- **No tenant entity — vaults are flat, not hierarchical** — there is no object
  grouping several vaults under one customer or organisation; the vault is the
  only isolation unit. Confirmed still true 2026-09-03: `tenant` appears nowhere
  in the Go source except `model/azure_roles.go`, where it refers to Azure's own
  vocabulary. The consequences are bulk operations that cannot be expressed
  ("revoke this contractor from all of customer X's vaults"), reporting that
  cannot roll up per customer, and no unit to attach billing or quota to. Adding
  it is a genuine data-model change — a `tenants` table, a nullable `tenant_id` on
  `vaults`, and a decision about whether role assignments can be made at the
  tenant level or only per vault. Worth deciding the model before the vault count
  in real deployments makes a migration expensive.

**Sequencing note:** these two are related but independently shippable, and the
order matters. Self-service provisioning is the smaller change and delivers the
MSP use case on its own; the tenant entity is what makes that use case
*manageable* at scale. Doing the tenant entity first would be building the
grouping before anything needs grouping.

---

## Phase 1 — Close remaining Azure Key Vault gaps

Everything here maps to a ❌ or 🟡 row in `azure-keyvault-parity.md`. Ordered by
real-world value, re-reviewed 2026-08-17 — see the value-review note at the end
of this section for what changed from the original ordering and why.

- **Rotation-policy scheduler** — rotation-policy CRUD already matches Azure
  (parity doc §2, "Get/Set rotation policy" — closed 2026-08-14), but nothing
  executes a rotation on schedule yet. This closes the CRUD-vs-enforcement gap;
  parity doc §1 and the Summary section both flag rotation as still 🟡 for this
  reason. **Highest priority in this phase**: a user can configure a rotation
  policy today and it silently never fires — that's worse than the feature not
  existing at all, since it can create a false sense of security for anyone
  relying on it for compliance. Note this is specifically the *key*
  rotation-policy scheduler; secrets already have a working one
  (`internal/services/secrets/scheduler_service.go`, confirmed running via
  `bootstrap.go`), so this closes an inconsistency between the two, not a
  brand-new capability class.

- ~~**Key import (JWK)**~~ — shipped 2026-08-25: `POST /keys/import` and
  `rocketvault keys import` accept an RSA/ECDSA private-key JWK and store it
  exactly as a generated key would, gated by `ActionKeysImport`. Closes parity
  doc §2's "Import key" row (now ✅). Design:
  `docs/superpowers/specs/2026-08-25-key-import-jwk-design.md`.

- **Certificate import (PFX/PEM) & CSR merge** — Azure Key Vault supports both
  uploading a complete externally-issued cert+key bundle and completing a
  vault-generated CSR once an external CA has signed it. RocketVault has
  neither, and unlike key import this gap was not previously tracked in the
  parity doc at all (parity doc §4, "Import certificate" and "Merge CSR" rows,
  added 2026-08-25). Same adoption-blocker shape as key import — anyone
  migrating existing certificates in has no path to do so today. CSR merge is
  scoped to a single-call operation for v1 (no persisted pending-request
  state), which is 🟡 relative to Azure's full lifecycle — see the design doc's
  §2.1 for the reasoning. Design specified, not yet built:
  `docs/superpowers/specs/2026-08-25-certificate-import-merge-design.md`.

- **ACME / Let's Encrypt certificate enrollment** — Azure only integrates with
  partner CAs (DigiCert, GlobalSign). ACME is the open, self-hosted-native way to
  reach the same outcome (automated cert issuance from a real trusted CA) and
  arguably beats Azure's approach for anyone not already on those specific
  partners. Parity doc §4 lists both "Public-CA integration (DigiCert/GlobalSign)"
  and "ACME / external CA enrollment" as separate ❌ rows today (self-signed /
  internal CA only); this one item is the deliberate substitute for both —
  partner-specific DigiCert/GlobalSign API integration is not separately planned.
  Self-signed-only certs are a real production blocker for anyone wanting
  RocketVault-issued certs on internet-facing services; ACME is table-stakes for
  a modern cert issuer and well-understood to implement (cert-manager, Caddy,
  etc. all do it the same way).

### Not planned, or needs a feasibility check first

- **Confidential-compute key release (TEE attestation)** — no realistic
  self-hosted equivalent to Azure's confidential-compute release flow; the
  Azure role built for it (`Key Vault Crypto Service Release User`) was
  deliberately *not* added to RocketVault's role set for the same reason
  (parity doc §6, "Not added" note) — adding the concept without a real
  capability behind it repeats an anti-pattern this project already retired
  once (the legacy pre-Azure role vocabulary).
- **FIPS 140-3 L3 certification** — a hardware certification process, not
  something achievable through code. The honest substitute, already true
  today, is that RocketVault supports FIPS-validated HSMs via its PKCS#11
  provider (parity doc §8) — the certification lives in the HSM you plug in,
  not in RocketVault itself.
- **Geo-replication identical to Azure's managed regional failover** — folded
  into Phase 3 instead as a different, open, multi-primary design rather than
  a literal copy of a fully-managed cloud feature RocketVault has no platform
  underneath to replicate.
- **HSM coverage: P-256K + AES-CBC** — demoted here 2026-08-17 after a value
  review. The two remaining PKCS#11 mechanism gaps on the HSM path (parity doc
  §8): P-256K has no PKCS#11 mechanism verified against real hardware in the
  current environment; AES-CBC wrap has no PKCS#11 mechanism at all yet. RSA,
  EC P-256/P-384/P-521, and AES-KW are already HSM-backed. Niche on both counts:
  P-256K is mainly a blockchain/cryptocurrency signing curve, a narrow audience
  for a general secrets/PKI vault; AES-CBC key wrap is superseded by AES-KW
  (RFC 3394, already HSM-supported) as the modern standard, so real demand for
  CBC specifically is low. More importantly, this may not be a pure coding gap
  at all — it depends on what the HSM/PKCS#11 library actually supports, the
  same class of problem as the FIPS L3 non-goal above. Revisit only if real
  user demand shows up, and check PKCS#11 mechanism availability before
  committing effort.

**Value-review note (2026-08-17):** the original Phase 1 ordering listed items
roughly in the order they appear in the parity doc, not by value. A review
reordered to lead with the rotation scheduler (highest real-world impact —
silent no-op risk), and moved HSM P-256K/AES-CBC out of the committed list
entirely given its niche audience and uncertain feasibility. The Crypto User
role fix (missing `update`/`backup` data actions), demoted here to a bundled
quick patch rather than a standalone item, was itself closed the same day —
see parity doc §6.

## Phase 2 — Platform maturity

Carried forward from README's existing Planned list — these are about finishing
what's already started, not new parity gaps or new differentiators. Ordered by
real-world value, re-reviewed 2026-08-17 — see the value-review note at the end
of this section for what changed and why.

- **Vault-scope role-assignment management for non-admin `vaults:manage`
  holders** — currently requires the global admin role even for a caller who
  already holds vault-scoped management rights; documented as a known
  limitation in [`docs/release-notes/v4.0.0-azure-rbac.md`](../docs/release-notes/v4.0.0-azure-rbac.md#known-limitations).
  **Highest priority in this phase**: this is core to the multi-vault
  delegation model, not just a convenience gap. The whole point of per-vault
  delegation is that a team's vault-manager can run their own vault
  independently — but today they still can't grant or revoke their own team's
  access without going through the global admin every time, which defeats
  delegation.
- **Redis caching layer for distributed deployments** — today's in-process
  caches (`internal/cache`, `internal/keycache`, `internal/vaultcache`) don't
  share state across instances. This is more than a performance gap: if a key
  is rotated on one replica, only that replica's in-process cache is
  invalidated — a second replica behind the same load balancer can keep
  serving the old (revoked) key from its own cache until the TTL expires
  (default 60s per `key_cache.ttl`). In any multi-replica deployment that's a
  real revocation-latency window, not just a missed performance optimization.
- **Official Helm chart + signed/scanned container images (cosign/sigstore)** —
  moved here from Phase 3 2026-08-17 as the natural prerequisite for the
  Kubernetes operator below; see that entry's rationale for why. (Also still
  reinforces the "fully self-hosted, no cloud dependency" extra from the
  parity doc, which was the original reason it was listed under Phase 3.)
- **Kubernetes operator for automated deployment** — standard self-hosted-infra
  expectation once a project moves past single-instance manual deployment.
  Sequenced after the Helm chart above: a full operator (CRDs, a reconciliation
  loop, its own release lifecycle) is substantial, ongoing engineering
  investment, and building one before a basic Helm chart exists is backwards —
  the operator is "the Helm chart, but with more automation," built on the same
  foundation. Let the Helm chart prove out real deployment demand first.
- **Web-based administration interface** — RocketVault is REST API + CLI only
  today; a web UI is the natural next maturity step for day-to-day operators
  and meaningfully broadens adoption beyond CLI/API-comfortable users. Sequenced
  last in this phase: it's by far the largest effort item here (a whole
  separate frontend application — auth flows, every CRUD screen, RBAC-aware
  UI), and unlike the other four items it doesn't unblock any existing
  functionality — it's about audience growth, not fixing a gap.

**Value-review note (2026-08-17):** the original Phase 2 ordering matched
README's pre-existing Planned list order, not value. A review reordered to
lead with the delegation fix and Redis cache (both closing real functional/
security gaps — the Redis gap is arguably a correctness issue, not just
performance), pulled the Helm chart forward from Phase 3 as a Kubernetes
operator prerequisite, and moved the web admin UI to last given its effort
relative to the other items.

## Phase 3 — Beyond Azure

Capabilities Azure Key Vault structurally can't offer (single-tenant cloud SaaS)
or handles more awkwardly than a self-hosted product can. The two multi-tenancy
gaps in the "High priority" section at the top of this doc belong to this phase
by shape and were promoted above Phase 1 by priority — read them as part of this
list. This is where
RocketVault's extras list (parity doc's "RocketVault extras (➕)" section —
bulk export/import, tamper-evident audit chain, SOC 2/GDPR reports, JWKS
rotation, rate limiting, no cloud dependency) grows rather than just gets
maintained.

- **Multi-region / multi-primary replication** — an open design with conflict
  resolution, not a copy of Azure's managed regional failover. Useful for
  multi-cloud, hybrid, and air-gapped deployments Azure literally cannot reach.
- **GitOps / policy-as-code + Terraform provider** — declarative YAML for
  vaults, role assignments, and rotation policies with `apply`/drift-detection,
  plus a Terraform provider. Azure has ARM/Bicep at the resource level but
  nothing this workflow-native scoped to a single vault product.
- **WebAuthn / passkey login** alongside TOTP MFA — phishing-resistant MFA that
  doesn't assume an Entra ID tenant behind it.
- **Native webhook/notification system** — rotation failures, expiry warnings,
  and audit events pushed to Slack/PagerDuty/a generic webhook. This is the
  honest self-hosted answer to the cloud-log-sink gap in Phase 1 (parity doc §9,
  "Stream to Event Hub / archive to storage" — ❌, no self-hosted equivalent
  exists for the Azure-specific sink, but a native webhook system solves the
  same underlying problem and is arguably better DX for teams without a cloud
  monitoring stack).
- **Break-glass emergency access workflow** — time-boxed elevated access with
  mandatory justification and an audit trail. Azure has no clean equivalent;
  genuinely useful for on-call incident response.
- **Extended compliance report templates** — PCI-DSS and HIPAA templates
  alongside the existing SOC 2/GDPR reports (`internal/services/audit/compliance_report_service.go`),
  building on infrastructure that already exists rather than starting fresh.
  Also add optional scheduled delivery (email/webhook on a cadence) instead of
  pull-only, once the native webhook system above exists.
- **Local dev secret injection** — a `direnv`-style `rocketvault run -- <command>`
  that injects secrets as environment variables for local development, lighter
  weight than Azure's tooling for this use case.
- **Format-aware bulk import/export** — extend the existing bulk export/import
  (parity doc §1, already a RocketVault extra with no Azure equivalent) with
  importers/exporters for common external formats: Kubernetes Secrets YAML,
  `.env` files, Terraform tfvars. Makes migrating in or out of another secret
  store turnkey instead of requiring a custom script. Each format is its own
  maintenance surface, so start with the one or two formats real users ask for.
- **Certificate export (passphrase-sealed)** — extend the bulk export/import
  extras list to certificates, mirroring the existing secrets export/import
  pattern (argon2id + AES-256-GCM sealed envelope, `common/export_envelope.go`).
  Genuinely distinct from the existing `POST /certificates/{id}/backup`, which
  is a same-instance restore blob (sealed under a master-key-derived key since B76, so it restores only on an instance with the same master key), not a portable human-shareable
  export — see the design doc's Problem section for the distinction. No Azure
  equivalent, so this doesn't close a parity gap; it's a self-hosted
  convenience. Design specified, not yet built:
  `docs/superpowers/specs/2026-08-25-certificate-export-design.md`.
- **Externally-anchored tamper-evident audit log** — the existing hash-chained
  audit log (parity doc §9, `prev_hash`-chained rows, already a RocketVault
  extra) only detects tampering *within* the chain; someone who compromises the
  whole database wholesale could still replace the chain from the start. Sign
  and timestamp the chain head periodically (or publish it to an external
  transparency log) so tampering is detectable even against a full database
  compromise. Needs an external trust anchor to add real value over today's
  in-DB-only chaining.
- **Per-principal rate limiting** — today's rate limiting (parity doc §10, a
  RocketVault extra) is per-IP only, global + a stricter auth tier. Add
  per-principal (per user/service-account) limits alongside it, since per-IP
  alone doesn't stop a single compromised credential hammering the API from
  rotating or many IPs.
- **Operation-aware health readiness** — gate `/health/ready` (parity doc §9,
  a RocketVault extra with no Azure equivalent) during long-running operations
  like master-key rotation or a purge run, so a load balancer doesn't route
  traffic mid-operation. Natural complement to the Phase 2 Kubernetes operator.
- ~~Official Helm chart + signed/scanned container images~~ — moved to Phase 2
  2026-08-17 as the Kubernetes operator's prerequisite; see that entry.

---

*Created 2026-08-17, following the priority decision to close Azure parity gaps
before building differentiators. Re-derive phase groupings from
`azure-keyvault-parity.md`'s current tables if this doc drifts — parity status
changes faster than a roadmap should.*
