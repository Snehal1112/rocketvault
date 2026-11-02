# RocketVault Dashboard — Design

**Date:** 2026-09-08
**Status:** Draft
**Branch target:** webapp-implementation

## Problem

`web/` is a fresh Vite scaffold — `src/App.tsx` renders only the marketing
landing page. RocketVault's Go backend (`../`) exposes ~159 REST endpoints
across 7 functional domains (auth/sessions, users, vaults, secrets, keys,
certificates, platform admin), all reachable only via CLI or raw HTTP today.
There is no way to operate a RocketVault instance from a browser.

## Goals

- Cover every user-facing capability the REST API exposes, organized into
  reviewable epics small enough to plan and ship independently.
- Reuse the landing page's existing design system exactly (typography, color
  tokens, component library) rather than introducing a second visual language.
- Reflect the backend's actual authorization model in the information
  architecture: per-vault RBAC (11 Azure-parity roles) is a completely
  separate axis from global admin — the app's navigation and route guards
  must not conflate them.
- Produce a spec + numbered implementation plans following this repo's own
  `docs/superpowers/` convention, so the work is resumable/reviewable the same
  way the backend's multi-vault and MCP-server efforts were.

## Non-goals

- Backend changes. Three gaps are identified below (§ Deferred) that block a
  fully clean implementation of a couple of screens; this spec documents them
  rather than fixing them.
- Feature parity with the CLI's `context` command (multi-server profile
  switching). The webapp is inherently pointed at one backend origin per
  deployment (see `Caddyfile`/`Caddyfile.local` — SPA and API share an
  origin); a context-switcher has no clear use case in a browser app and is
  explicitly out of scope unless a future requirement says otherwise.
- Deciding the fate of the current landing page content (kept as a public
  route vs. dropped). Flagged as an open decision in the foundation plan.

## Design

### 1. Design system (must be preserved, not reinvented)

Source of truth: `web/src/index.css`, `web/src/components/landing/*`.

- **Stack**: React 19 + TypeScript (strict) on Vite 8, Tailwind CSS v4
  (CSS-first, no `tailwind.config.js`), shadcn/ui `base-luma` style on
  `@base-ui/react` (not Radix). Package manager: bun.
- **Typography**: body = Noto Sans Variable (`font-sans`, global default);
  headings/labels/nav/badges/code = JetBrains Mono Variable (`font-heading`)
  — a deliberate technical/CLI-adjacent feel that every new screen should
  keep (e.g. table headers, section titles, breadcrumb, sidebar nav labels
  all use `font-heading`; body copy and form values use `font-sans`).
- **Color**: oklch tokens in `:root`/`.dark`, primary = deep teal
  (`#0A6B62` light / `#0FA89A` dark). No `--success`/`--warning` tokens exist
  yet — the foundation plan adds them (same oklch pattern, same
  `:root`/`.dark`/`@theme inline` wiring) because several epics need status
  color (soft-deleted, rotation/renewal due, webhook enabled/disabled).
- **Shape/elevation**: unusually large border-radius scale
  (`--radius-4xl` ≈ 26px, used on cards/buttons — a rounded/pill aesthetic),
  cards use `shadow-md ring-1 ring-foreground/5` rather than heavy shadows.
- **Components**: all 62 shadcn components already vendored in
  `src/components/ui/` — use them as-is (see
  `web/.claude/shadcn-components.md` for the full inventory); do not
  re-`shadcn add` anything already present, and prefer wrapping/composing
  over editing a vendored file in place (keeps `shadcn add --overwrite`
  upgrades clean).

### 2. Information architecture

Two structurally separate authenticated branches, because the backend treats
them as two unrelated authorization questions:

```
/app/login, /app/oidc/callback        — public
/app/                                  — redirect to last-used vault or /vaults
/app/vaults                            — vault picker/landing
/app/vaults/:vaultName/...             — per-vault role required (Epics 1-6)
/app/admin/...                         — global admin role required (Epics 7-12)
/app/account                           — authenticated, unscoped (Epic 13)
```

A vault-scoped route's guard cannot be pre-checked client-side (no
"which vaults am I in" endpoint exists for non-admins — see § Deferred) and
instead defers to the first real data call's 403/404, rendered by a route
error boundary. The admin branch's guard *can* be checked purely from the
JWT-derived `roles` claim already present in session state after login.

### 3. Auth & session model

Access token in memory only (XSS blast-radius reduction, appropriate for a
secrets manager); refresh token in `localStorage` (the backend returns it in
the JSON body, not an HttpOnly cookie, so this is the only realistic
persistence option today — flagged as a residual risk, not something the
frontend alone can fully mitigate). Login is one call — username, password,
and TOTP code together (`POST /api/v1/users/login`); there is no separate
TOTP-challenge round trip to design a wizard around. Refresh **rotates** the
refresh token server-side, so the client-side interceptor must dedupe
concurrent refreshes through a single in-flight promise rather than firing
one per parallel failed request.

### 4. API client architecture

One typed module per backend resource domain under `src/api/`, over a shared
`client.ts` request helper. Same-origin relative fetches (`/api/v1/...`) — no
CORS or base-URL env var needed for the primary deployment shape, since both
`Caddyfile.local` (dev) and the production `Caddyfile` proxy the SPA and the
API through one origin. `ApiError` mirrors the backend's real error envelope:
`{id, message, detailed_error, request_id, status_code, retry_after_seconds}`
(`common.AppError`). 401 → refresh-and-retry-once; 403 is never retried
(authenticated-but-not-authorized is not something a token refresh fixes) and
surfaces as-is for the UI's access-denied states.

### 5. App shell

One `SidebarProvider` mounted once at the authenticated root; `SidebarContent`
swaps between vault-mode and admin-mode nav based on the active route — no
manual mode toggle, the URL already encodes which mode is active. Built on
the already-vendored `sidebar.tsx`, `brand.tsx` (header), and
`theme-provider.tsx` (unchanged, reused as-is). Vault switcher lives under
`SidebarHeader`.

### 6. Epics

One numbered implementation plan per epic, `docs/superpowers/plans/2026-09-08-webapp-NN-<slug>.md`, all building on the Phase 0 foundation:

| # | Epic | Domain | Auth model |
|---|---|---|---|
| 00 | Foundation scaffold | routing, API client, auth, app shell | n/a (prerequisite) |
| 01 | Vault Management | vault lifecycle (create/list/get/update/delete/purge) | admin or `vaults:manage` |
| 02 | Secrets | CRUD, versions, generate, import/export, backup/restore, soft-delete | per-vault role |
| 03 | Keys | CRUD, import, crypto ops, rotation + policy, backup/restore, soft-delete | per-vault role |
| 04 | Certificates | CRUD, policy/auto-renew, backup/restore, soft-delete | per-vault role |
| 05 | Vault Access (RBAC) | role assignment grant/list/revoke | admin, `vaults:manage`, or Data Access Administrator |
| 06 | Vault Webhook | set/get/delete webhook config | admin or `vaults:manage` |
| 07 | User Management | user CRUD, TOTP enrollment display | global admin |
| 08 | Service Accounts | CRUD, secret rotation | global admin |
| 09 | Access Policies | global/vault explicit allow/deny | global admin |
| 10 | Vault Provisioning Grants | quota-based vault-creation grants | global admin |
| 11 | Audit & Compliance | log viewer, SOC2/GDPR reports, retention config | global admin |
| 12 | JWKS | view active keys, rotate | public read / admin rotate |
| 13 | Account & Sessions | own sessions list/revoke, profile, logout | authenticated (self) |
| 14 | Platform Status | health checks, metrics visibility | mixed public/admin |

### 7. Journeys

Persona-driven flows, matching `docs/VAULT_USER_ACCESS_JOURNEYS_v3.md`'s
lettered style, each exercised as an integration/E2E scenario once its epics
land:

- **A** — First login & vault picker landing.
- **B** — Admin creates a vault, grants themselves access, creates a first
  secret (UI version of the README quick-start).
- **C** — Secrets Officer: create → version update → soft-delete → recover.
- **D** — Crypto Officer creates a key and sets a rotation policy; a
  separate Crypto User signs data with it (two-role handoff).
- **E** — Certificates Officer issues a cert with auto-renew, then renews it.
- **F** — Admin grants "Key Vault Data Access Administrator" to a delegate,
  who manages role assignments without gaining data access themselves.
- **G** — Admin reviews audit logs and exports a SOC2 report.
- **H** — Session expires mid-work: silent refresh vs. forced logout on
  refresh failure.
- **I** — OIDC SSO login (deferred — see § Deferred).

## Testing

`web/` has no test runner wired up yet (`web/CLAUDE.md`: "add one rather than
assuming `bun test` is configured"). The foundation plan (00) adds Vitest +
React Testing Library + jsdom as Task 1, before anything else, so every
subsequent epic plan can follow this repo's TDD convention (failing test →
minimal implementation → refactor) the same way the backend's Go plans do.
Component tests for interactive flows (forms, table actions, guards);
`client.ts`'s refresh-interceptor gets dedicated unit tests (concurrent 401s,
rotation, 403-never-retried) since it's the piece every other epic depends on
being correct.

## Phasing

- **Phase 0** (epic 00): foundation — must land first, everything else
  depends on its routes/api/auth/shell primitives.
- **Phase 1** (epics 01–06): core vault data-plane — highest end-user value,
  matches what the CLI already treats as its most complete remote surface.
- **Phase 2** (epics 07–12): platform administration, admin-only.
- **Phase 3** (epic 13): account/session self-service.
- **Phase 4** (epic 14): platform status visibility, lowest priority.

Epics within a phase have no ordering dependency on each other beyond the
foundation — 01–06 (and 07–12) can be built and reviewed in any order or in
parallel by different contributors.

## Deferred

Real gaps found during research, not fixed by this spec — documented so
they're not silently rediscovered mid-epic:

- **No REST endpoint found for first-admin bootstrap.** `users admin` is
  CLI-only, using `.rocketvault.yaml`'s `bootstrap_token` directly against the
  local DB. The webapp cannot perform first-run setup itself; document this
  as a CLI-first prerequisite until/unless a bootstrap endpoint exists.
  Affects: initial deployment docs, not any specific epic.
- **`GET /api/v1/config` does not expose `oidc.enabled`.** The SSO button
  (Journey I) must stay hidden until the backend adds this — likely
  `feature_flags.oidc_enabled`, a zero-schema-change addition. Affects:
  Epic 00 (login form's conditional SSO button), Epic 13.
- **`GET /api/v1/vaults` only returns vaults the caller can *manage***
  (admin / `vaults:manage` tier), not "vaults I hold any data-plane role in."
  A plain Secrets User has no API-driven way to discover their own vault
  list. Mitigation (client-side MRU cache + manual vault-name entry) is part
  of Epic 00; a real `GET /vaults/mine` is a documented backend gap that
  would materially simplify Epic 00's vault switcher and Epic 01's landing
  page once available.
- **No static-file serving for `/app/*` exists in the Go server** (`app/app.go`).
  The production `Caddyfile` has no `/app` path at all, implying the binary
  is expected to serve the built SPA itself eventually. Out of scope for
  every epic in this spec; flagged for whoever picks up deployment.
- **No dedicated vault-recover HTTP endpoint confirmed.** The CLI has
  `vaults recover <name>`, but the route inventory only confirms
  create/list/get/update/delete/purge for `/vaults`. Epic 01 must verify
  (via `api/vault.go`) whether recovery is its own route (e.g.
  `POST /vaults/{name}/recover`) or folded into `PATCH` before implementing
  the recover action — do not assume either shape.

## Documentation

- Update `web/CLAUDE.md`'s Commands section once Epic 00 adds `bun run test`.
- Each epic plan's final task updates any docs it touches (e.g. a future
  `web/docs/` user guide, once one exists — none does today).

## References

- `../CLAUDE.md` — backend architecture, auth model, RBAC.
- `.claude/azure-keyvault-parity.md`, `.claude/multi-vault.md` (main repo)
  — the authorization model this UI must reflect.
- `docs/VAULT_USER_ACCESS_JOURNEYS_v3.md` (main repo) — journey style/tone
  this spec's § Journeys follows.
- `docs/superpowers/plans/2026-08-21-mcp-server-design.md` and its numbered
  plan family (main repo) — the spec→numbered-plans convention this doc and
  its sibling plan files follow.
- `web/.claude/shadcn-components.md` — full vendored component inventory.
