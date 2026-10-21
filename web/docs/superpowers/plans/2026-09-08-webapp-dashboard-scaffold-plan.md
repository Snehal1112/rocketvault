# RocketVault Dashboard — Epics/Flows Spec + Scaffold Implementation

## Context

RocketVault's backend (`../`) exposes ~159 REST endpoints across 7 functional
domains (auth, users, vaults, secrets, keys, certificates, admin/audit), but
`web/` is still just a landing page — `App.tsx` renders marketing sections only,
no routing, no API client, no auth. The user wants (1) a durable planning
artifact breaking "build a webapp for the whole API" into epics and concrete
user flows, matching this repo's own `docs/superpowers/specs/` convention and
the landing page's existing design system, and (2) — decided via user
clarification — the basic app skeleton (routing, API client, auth, app shell)
scaffolded immediately after this plan is approved, so later epics have
somewhere to land.

Research already completed (4 Explore agents + 1 Plan agent): full design-
token/typography audit of `web/`, full 159-route API inventory grouped by
domain with auth requirements, full CLI command inventory cross-checked
against the API, this repo's spec/plan doc conventions, and a concrete
scaffold architecture (routing library, API client, auth/session design, app
shell) grounded in `Caddyfile.local`, `api/api.go`, `api/users.go`,
`app/app.go`.

## Deliverable 1 — Spec doc: `docs/superpowers/specs/2026-09-08-webapp-dashboard-epics-design.md`

Follows house spec template (Problem/Goals/Non-goals/Design/Phasing/Deferred/
Documentation). Content:

**Design System section** — transcribes the audit: React 19 + TS + Vite 8 +
Tailwind v4 (CSS-first) + shadcn `base-luma`/Base UI, bun; fonts (Noto Sans
Variable body, JetBrains Mono Variable for headings/labels/nav — deliberate
"technical" feel to preserve); oklch color tokens (primary deep teal
`#0A6B62`/`#0FA89A`); large border-radius scale (`--radius-4xl` ~26px, pill
aesthetic); card style (`shadow-md ring-1 ring-foreground/5`, no heavy
shadows); no `--success`/`--warning` tokens yet — new epic work needs them for
status badges (soft-deleted, rotation-due, cert-expiring), add alongside
existing tokens in `src/index.css` using the same oklch pattern, don't invent
a parallel palette.

**Epics** (mirrors the repo's `## Phase N` roadmap style), each mapped to its
API/CLI domain:

- *Phase 0 — Foundation* (this session, deliverable 2 below): routing, API
  client, auth/session, app shell, account/sessions screen.
- *Phase 1 — Core vault data-plane* (highest end-user value, matches what the
  CLI already treats as "remote-capable" for secrets):
  - Epic 1: Vault Management — list/create/get/update/delete/recover/purge,
    vault picker landing page.
  - Epic 2: Secrets — CRUD, versions, generate, import/export, backup/restore,
    soft-delete/restore/purge.
  - Epic 3: Keys — CRUD, import, versions, crypto ops (sign/verify/encrypt/
    decrypt/wrap/unwrap), rotation + rotation policy, backup/restore,
    soft-delete/restore/purge.
  - Epic 4: Certificates — CRUD, policy (incl. auto-renew), backup/restore,
    soft-delete/restore/purge.
  - Epic 5: Vault Access (RBAC) — role assignment grant/list/revoke, roles
    reference table.
  - Epic 6: Vault Webhook — set/get/delete (show-once secret pattern, `get`
    never returns the signing secret).
- *Phase 2 — Platform administration* (admin-only, separate `/admin` section):
  - Epic 7: User Management — CRUD, TOTP-secret-once-on-create display.
  - Epic 8: Service Accounts — CRUD, secret rotation (show-once pattern).
  - Epic 9: Access Policies — global/vault explicit allow/deny CRUD.
  - Epic 10: Vault Provisioning Grants — quota-based vault-creation grants
    (distinct control-plane concept from Epic 5's data-plane roles).
  - Epic 11: Audit & Compliance — log viewer + filters, SOC2/GDPR reports,
    retention config.
  - Epic 12: JWKS — view active signing keys, rotate (self_pki only).
- *Phase 3 — Account* : Epic 13, sessions list/revoke, logout, profile.
- *Phase 4 — Platform status* (low priority): Epic 14, health/metrics
  visibility for admins.

**Journeys** (persona-driven flows, matching `VAULT_USER_ACCESS_JOURNEYS_v3.md`'s
lettered style, each citing the exact screens/API calls involved):
A) First login & vault picker landing; B) Admin creates a vault, grants self
access, creates first secret (UI version of the README quick-start); C) Secrets
Officer: create → version update → soft-delete → recover; D) Crypto Officer
creates a key, sets rotation policy; a separate Crypto User signs data with it
(demonstrates two-role handoff); E) Certificates Officer issues a cert with
auto-renew, then renews it; F) Admin grants "Key Vault Data Access
Administrator" to a delegate who then manages role assignments without gaining
data access themselves; G) Admin reviews audit logs, exports a SOC2 report; H)
Session-expiry mid-work — silent refresh vs. forced logout on refresh failure;
I) OIDC SSO login (flagged deferred, see gaps below).

**Known gaps to flag in the doc** (found during research, not fixed by this
plan — surfaced so they're not silently rediscovered later):
- No REST endpoint found for first-admin bootstrap (CLI-only via
  `users admin` + `.rocketvault.yaml`'s `bootstrap_token`) — the webapp likely
  cannot do first-run setup itself; document this as a CLI-first prerequisite
  unless/until a bootstrap endpoint is confirmed or added.
- `GET /api/v1/config` doesn't currently expose `oidc.enabled` — the SSO
  button must stay hidden until that flag exists server-side; document as a
  backend dependency, not something the frontend works around.
- `GET /api/v1/vaults` only returns vaults the caller can *manage* (admin/
  `vaults:manage` tier), not "vaults I have any data-plane role in" — a plain
  Secrets User has no API-driven way to discover their own vault list.
  Frontend mitigation (MRU `localStorage` cache + manual vault-name entry) is
  part of deliverable 2; a real `GET /vaults/mine` is a documented backend gap.
- No static-file serving for `/app/*` exists in the Go server yet (`app/app.go`)
  — production topology (`Caddyfile`, no `/app` path) implies the binary is
  expected to serve the built SPA eventually; out of scope for this plan,
  flagged for whoever picks up deployment.

## Deliverable 2 — Scaffold implementation (this session, after approval)

**Stack additions**: `@tanstack/react-router` + Vite plugin, `@tanstack/react-query`.

**Routing** — code-based route tree (not filesystem codegen, to stay consistent
with biome/prettier already governing `src/`), mounted at `basepath: "/app"`.
Two structurally separate authenticated branches reflecting the two unrelated
authorization models: `/vaults/$vaultName/*` (per-vault role, guard deferred
to first data call rather than precomputed — no reliable "am I in this vault"
endpoint per gaps above) and `/admin/*` (guarded by `roles.includes("admin")`
from the JWT, no extra call needed). Plus `/login`, `/oidc/callback` (public),
`/account`, `/` (redirect to last-used vault or `/vaults` picker).

**API client** (`src/api/`) — one typed module per domain (`auth.ts`,
`vaults.ts`, `secrets.ts`, `keys.ts`, `certificates.ts`, `deleted.ts`,
`role-assignments.ts`, `admin/*.ts`) over a shared `client.ts` `request()`
helper. Same-origin relative fetches (`/api/v1/...`, no CORS/env var needed —
`Caddyfile.local` and prod `Caddyfile` both put API and SPA on one origin),
with a `VITE_API_BASE_URL` override slot for future split-origin deploys.
`ApiError` mirrors the backend's `{id, message, detailed_error, request_id,
status_code, retry_after_seconds}` envelope. 401-refresh-retry interceptor:
dedupe concurrent refreshes via a single in-flight promise (refresh **rotates**
the refresh token server-side, so parallel un-deduped refreshes would race each
other invalid), retry the original call once, hard-logout on refresh failure.
403s are never retried (auth ≠ authz; refreshing a token can't fix a
permissions error) and surface as-is for the UI to render.

**Auth/session** (`src/lib/auth/`) — access token in-memory only (XSS
blast-radius reduction for a secrets manager; refresh token re-mints it on
reload), refresh token in `localStorage` (backend returns it in the JSON body,
not an HttpOnly cookie, so this is the only realistic persistence option
today). Login form: username + password + TOTP code via the already-vendored
`input-otp.tsx`, submitted as one call (the API has no separate TOTP-challenge
round trip). OIDC button conditionally rendered on the config flag (currently
always off per the gap above). Current-vault selection: URL is source of
truth inside `/vaults/$vaultName/*`; `localStorage` MRU list backs the
switcher for non-admins per the `GET /vaults` gap.

**App shell** (`src/components/app-shell/`) — one `SidebarProvider` mounted
once at the authenticated root, contents swapped between vault-mode and
admin-mode nav based on the active route (no manual mode toggle — the URL
already encodes which mode you're in). Reuses existing `sidebar.tsx`,
`brand.tsx` (header), `theme-provider.tsx` (unchanged, already wired). Vault
switcher lives under `SidebarHeader` as a dropdown (MRU + admin's real vault
list + manual entry). Mounts `ToastProvider`/`TooltipProvider` alongside the
existing `ThemeProvider` in `main.tsx` (none of these three are mounted today
per `web/CLAUDE.md`).

**File structure**: `src/routes/*.tsx` (route tree), `src/api/*.ts`,
`src/lib/auth/*.ts`, `src/lib/query-client.ts`, `src/lib/current-vault.ts`,
`src/components/app-shell/*.tsx`, `src/components/auth/*.tsx`. `App.tsx`'s
current landing content is left in place but no longer mounted from
`main.tsx` (the router takes over); the landing page's fate (keep as public
marketing route vs. drop) is a follow-up decision, not resolved by this
scaffold.

## Verification

- `bun run typecheck` and `bun run lint` (both flags matter per `web/CLAUDE.md`
  — `-b` and `--error-on-warnings` — don't drop them) must pass after scaffold.
- `bun run dev`, visually confirm: `/app/login` renders and matches existing
  typography/color tokens (JetBrains Mono headings, teal primary, rounded-4xl
  cards); a login attempt against a real running backend (`go run main.go
  serve` + an existing admin user) reaches the vault picker; sidebar nav
  switches correctly between a `/vaults/:name/...` and `/admin/...` URL.
- Confirm the spec doc renders correctly and cross-check its journey commands
  against actual CLI/API behavior already inventoried (no invented endpoints).
