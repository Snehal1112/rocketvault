# RocketVault Dashboard Foundation Scaffold Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development
> for the multi-task breakdown below, or superpowers:executing-plans if executing
> this plan directly, top to bottom.

**Goal:** Stand up routing, an API client, browser auth/session handling, and
an app shell in `web/`, so every subsequent epic (01–14) has routes, an API
module pattern, and a nav slot to land in — currently none of this exists;
`App.tsx` renders only the landing page and there is no router, no fetch
wrapper, and no test runner.

**Architecture:** See
`docs/superpowers/specs/2026-09-08-webapp-dashboard-epics-design.md` §§ 2–5
for the full rationale (routing split by authorization model, API client
error/refresh semantics, in-memory-access-token/localStorage-refresh-token
session design, single-`SidebarProvider` shell).

**Tech Stack:** React 19 + TypeScript strict + Vite 8 + Tailwind v4 (existing)
plus new dependencies added by this plan: `@tanstack/react-router`,
`@tanstack/router-plugin`, `@tanstack/react-query`, `vitest`,
`@testing-library/react`, `@testing-library/jest-dom`, `@testing-library/user-event`,
`jsdom`.

**Conventions to follow (verified in codebase):**
- `@/` maps to `src/` (`vite.config.ts` + `tsconfig.app.json` — keep both in
  sync if adding new aliases).
- `import type` for type-only imports (`verbatimModuleSyntax` is on).
- Tailwind + `cva` for variants, `cn()` from `@/lib/utils` to merge classes,
  `data-slot` attribute on component roots — match `src/components/ui/button.tsx`'s
  pattern for any new non-vendored component.
- Prettier: no semicolons, double quotes, 2-space indent. Run
  `bun run format` after editing class strings (sorts Tailwind classes via
  `prettier-plugin-tailwindcss`, including inside `cn()`/`cva()`).
- Do not edit `src/components/ui/**` in place — wrap/compose instead (keeps
  byte-identity with the shadcn registry for future `--overwrite` upgrades).

**Fixed constant used throughout:** Vite `base: "/app/"` → router
`basepath: "/app"` (`vite.config.ts` already sets this; do not change it).

**Verification gate (run before every commit):**
```bash
cd web
bun run typecheck   # tsc -b --noEmit — keep the -b flag, see web/CLAUDE.md
bun run lint         # biome lint --error-on-warnings — keep the flag
bun run test         # vitest run (added by Task 1)
bun run build         # tsc -b && vite build
```

## File Structure

New files:
- `src/routes/__root.tsx`, `router.ts`, `login.tsx`, `oidc.callback.tsx`,
  `index.tsx`, `vaults.tsx`, `vaults.$vaultName.tsx`,
  `vaults.$vaultName.index.tsx`, `admin.tsx`, `account.tsx`
- `src/api/client.ts`, `types.ts`, `auth.ts`, `config.ts`
- `src/lib/auth/auth-context.tsx`, `session-storage.ts`, `guards.ts`
- `src/lib/query-client.ts`, `src/lib/current-vault.ts`
- `src/components/app-shell/app-shell.tsx`, `vault-nav.tsx`, `admin-nav.tsx`,
  `vault-switcher.tsx`, `account-menu.tsx`, `top-bar.tsx`
- `src/components/auth/login-form.tsx`, `oidc-button.tsx`
- `vitest.config.ts`, `src/test/setup.ts`

Modified files:
- `src/main.tsx` (mount `RouterProvider` instead of `<App />`)
- `src/index.css` (add `--success`/`--warning` oklch tokens)
- `package.json` (new deps + `test`/`test:watch` scripts)
- `web/CLAUDE.md` (document the new `bun run test` command)

## Task 1: Add a test runner (Vitest + RTL)

**Files:** Create `vitest.config.ts`, `src/test/setup.ts`. Modify `package.json`.

- [ ] **Step 1:** Add dev deps: `vitest`, `jsdom`, `@testing-library/react`,
      `@testing-library/jest-dom`, `@testing-library/user-event`,
      `@vitejs/plugin-react` (already present — reuse, don't duplicate).
- [ ] **Step 2:** `vitest.config.ts` extending the existing `vite.config.ts`
      (`mergeConfig`), `environment: "jsdom"`, `setupFiles: ["./src/test/setup.ts"]`.
- [ ] **Step 3:** `src/test/setup.ts` imports `@testing-library/jest-dom/vitest`.
- [ ] **Step 4:** Add `package.json` scripts: `"test": "vitest run"`,
      `"test:watch": "vitest"`.
- [ ] **Step 5:** Write a smoke test `src/test/smoke.test.tsx` rendering a
      trivial `<div>ok</div>` to confirm the harness works; run `bun run test`,
      confirm it passes, then delete the smoke test once Task 2+ have real
      tests to prove the harness with.
- [ ] **Step 6:** Update `web/CLAUDE.md`'s Commands section to list `bun run test`.
- [ ] **Step 7:** Commit: `git commit -S -m "test: add vitest + react-testing-library"`

## Task 2: Add routing (TanStack Router) and data fetching (TanStack Query)

**Files:** Create `src/routes/router.ts`, `src/routes/__root.tsx`,
`src/lib/query-client.ts`. Modify `src/main.tsx`, `vite.config.ts`.

- [ ] **Step 1:** Add deps: `@tanstack/react-router`, `@tanstack/router-plugin`,
      `@tanstack/react-query`.
- [ ] **Step 2:** `src/lib/query-client.ts` — a `QueryClient` instance with
      shared defaults (retry disabled for mutations, a bounded retry/backoff
      for queries that respects a `retry_after_seconds` hint from `ApiError`
      once Task 3 defines it — write this as a small pure function
      `shouldRetry(failureCount, error)` so it's unit-testable in isolation).
- [ ] **Step 3:** Write a failing test for `shouldRetry`: given an `ApiError`
      with `status_code: 429` and `retry_after_seconds: 5`, asserts it does
      not retry immediately (query-level retry defers to a toast + manual
      refetch instead of hammering a rate limit — see spec § API client).
- [ ] **Step 4:** Implement `shouldRetry` minimally to pass.
- [ ] **Step 5:** `src/routes/__root.tsx` — root layout component: wraps
      children in `QueryClientProvider`, exports a root `beforeLoad` stub
      (auth check wired in Task 5).
- [ ] **Step 6:** `src/routes/router.ts` — `createRouter({ routeTree,
      basepath: "/app" })`. Route tree built code-first (not filesystem
      codegen — see spec's rationale) by importing each route file and
      composing with `createRoute`/`createRootRoute`.
- [ ] **Step 7:** Modify `src/main.tsx`: keep `ThemeProvider`, replace
      `<App />` with `<RouterProvider router={router} />`. `App.tsx` itself
      is left in place but unmounted — flag its fate (public marketing route
      vs. deletion) as an open question in the PR description, not resolved
      by this task.
- [ ] **Step 8:** Verification gate. Commit:
      `git commit -S -m "feat(routing): add TanStack Router + Query scaffold"`

## Task 3: API client core

**Files:** Create `src/api/client.ts`, `src/api/types.ts`, and
`src/api/client.test.ts`.

- [ ] **Step 1 (failing test first):** `src/api/client.test.ts` — mock
      `global.fetch`, assert:
      - a 401 triggers exactly one `POST /api/v1/users/refresh` call, then
        retries the original request once with the new token;
      - two concurrent requests that both 401 trigger only **one** refresh
        call (dedupe via in-flight promise), not two;
      - a failed refresh (any non-2xx) clears session and does not retry
        the original request infinitely;
      - a 403 is never retried and rejects with an `ApiError` carrying
        `status_code: 403`;
      - the request/response envelope maps onto `ApiError`'s
        `{id, message, detailed_error, request_id, status_code,
        retry_after_seconds}` shape from a mocked JSON body matching
        `common.AppError`'s real shape (verify this shape against
        `../common/utils.go` before writing the mock, don't guess it).
  ```ts
  // src/api/client.test.ts (excerpt)
  it("dedupes concurrent 401s into a single refresh call", async () => {
    const fetchMock = vi.spyOn(global, "fetch")
      .mockResolvedValueOnce(unauthorized())
      .mockResolvedValueOnce(unauthorized())
      .mockResolvedValueOnce(refreshOk("new-token", "new-refresh"))
      .mockResolvedValue(ok({ data: "x" }))
    await Promise.all([request("/secrets"), request("/keys")])
    const refreshCalls = fetchMock.mock.calls.filter(([url]) =>
      String(url).includes("/users/refresh")
    )
    expect(refreshCalls).toHaveLength(1)
  })
  ```
- [ ] **Step 2:** Run, confirm failure (no `client.ts` yet).
- [ ] **Step 3 (minimal implementation):** `src/api/types.ts` — `ApiError`
      class, `ApiResponse<T>` envelope types. `src/api/client.ts` —
      `getAccessToken`/`setSession` getters backed by Task 5's auth module
      (import, don't duplicate state), `request<T>(path, init)`: attaches
      `Authorization` header unless path is `/users/login`, `/users/refresh`,
      or `/config`; on 401 dedupes-and-retries per the test; on other
      non-2xx throws `ApiError`.
- [ ] **Step 4:** Run tests, confirm pass. Refactor for clarity (extract the
      in-flight-refresh-promise into a small module-level singleton with a
      clear reset-on-success/failure contract).
- [ ] **Step 5:** Verification gate. Commit:
      `git commit -S -m "feat(api): add typed request client with 401 refresh-retry"`

## Task 4: Auth + config API modules

**Files:** Create `src/api/auth.ts`, `src/api/config.ts`, tests for both.

- [ ] **Step 1:** Failing tests: `login(username, password, totpCode)` posts
      to `/api/v1/users/login` with the three fields and returns
      `{token, refreshToken, userId, username, roles}`; `refresh(token)`
      posts to `/api/v1/users/refresh`; `logout()`/`listSessions()`/
      `revokeSession(id)`/`revokeAllSessions()` hit their respective
      `/users/sessions` routes; `getConfig()` hits `GET /api/v1/config`
      **without** an auth header even when a token is present (public route).
- [ ] **Step 2:** Run, confirm failure.
- [ ] **Step 3:** Implement both modules using `client.ts`'s `request()`.
- [ ] **Step 4:** Verification gate. Commit:
      `git commit -S -m "feat(api): add auth and config modules"`

## Task 5: Browser auth/session state

**Files:** Create `src/lib/auth/auth-context.tsx`, `session-storage.ts`,
`guards.ts`, and tests for each.

- [ ] **Step 1 (failing tests):**
      - `session-storage.ts`: `getRefreshToken`/`setRefreshToken`/`clear`
        round-trip through `localStorage`; `getRecentVaults`/`pushRecentVault`
        maintain an MRU list capped at 10, no duplicates (re-pushing an
        existing entry moves it to the front, doesn't duplicate).
      - `auth-context.tsx`: `setSession(token, refreshToken, user)` moves
        status from `"loading"` to `"authenticated"`; `clearSession()` moves
        to `"anonymous"` and clears the stored refresh token;
        `isGlobalAdmin` derives from `user.roles.includes("admin")`.
      - `guards.ts`: `requireAuth` throws/redirects when
        `status !== "authenticated"`; `requireGlobalAdmin` additionally
        checks `isGlobalAdmin` and redirects to `/` (not to `/login`) with a
        toast when false, per spec § 2.
- [ ] **Step 2:** Run, confirm failure.
- [ ] **Step 3:** Implement. `auth-context.tsx` uses
      `useSyncExternalStore`-backed store (not Redux — unnecessary for this
      scaffold's size), exposes `useAuth()`. On module load / app boot, if a
      refresh token exists in storage, attempt one silent refresh before the
      root route resolves (wire into `__root.tsx`'s `beforeLoad` from Task 2).
- [ ] **Step 4:** Verification gate. Commit:
      `git commit -S -m "feat(auth): add session state, storage, and route guards"`

## Task 6: Login route + form

**Files:** Create `src/routes/login.tsx`, `src/components/auth/login-form.tsx`,
`oidc-button.tsx`, and a component test for `login-form.tsx`.

- [ ] **Step 1 (failing test):** Render `<LoginForm />`, fill username/
      password/TOTP fields (TOTP via the vendored `input-otp.tsx`), submit,
      assert `auth.login` is called with all three values and, on success,
      `setSession` is called and the user is navigated to `/`. Assert a
      failed login (mocked 403) shows a generic "invalid username, password,
      or code" message — not a field-specific one (avoids enumeration,
      matches the backend's own non-distinguishing 403).
- [ ] **Step 2:** Run, confirm failure.
- [ ] **Step 3:** Implement `login-form.tsx` using vendored `input.tsx`,
      `input-otp.tsx`, `button.tsx`, `field.tsx`; `oidc-button.tsx` reads
      `config.feature_flags.oidc_enabled` (via `getConfig()`, Task 4) and
      renders nothing when falsy or absent — **confirm this flag does not
      exist server-side yet** (spec § Deferred) so the button is expected to
      stay hidden until a backend change lands; do not treat its absence as
      a frontend bug. `src/routes/login.tsx` composes both, uses the design
      tokens (`font-heading` for the page title, teal primary button,
      rounded-4xl card) matching the landing page's visual language.
- [ ] **Step 4:** Verification gate. Commit:
      `git commit -S -m "feat(auth): add login route and form"`

## Task 7: current-vault helpers

**Files:** Create `src/lib/current-vault.ts` + test.

- [ ] **Step 1 (failing test):** `getLastVault`/`setLastVault` round-trip;
      redirect-target logic (`/` route) prefers an explicit URL vault over
      the stored last-vault, and falls back to `/vaults` when neither exists.
- [ ] **Step 2:** Run, confirm failure. Implement. Verification gate.
- [ ] **Step 3:** Commit: `git commit -S -m "feat: add current-vault selection helpers"`

## Task 8: Add success/warning color tokens

**Files:** Modify `src/index.css`.

- [ ] **Step 1:** Add `--success`/`--success-foreground`,
      `--warning`/`--warning-foreground` oklch values to both `:root` and
      `.dark`, following the exact pattern of the existing `--destructive`
      pair (comment with the equivalent hex for readability, matching how
      `--primary` documents `#0A6B62`/`#0FA89A`). Expose both via
      `@theme inline` alongside the existing `--color-destructive` mapping.
- [ ] **Step 2:** `grep -- '--token:' dist/assets/index-*.css` after a build
      to confirm the new tokens are actually emitted (per `web/CLAUDE.md`'s
      documented gotcha about `@theme inline`-only tokens not existing at
      runtime for styled-components use — these are plain `:root`/`.dark`
      tokens so this should pass, but verify rather than assume).
- [ ] **Step 3:** Verification gate. Commit:
      `git commit -S -m "feat(theme): add success/warning color tokens"`

## Task 9: App shell

**Files:** Create `src/components/app-shell/app-shell.tsx`, `vault-nav.tsx`,
`admin-nav.tsx`, `vault-switcher.tsx`, `account-menu.tsx`, `top-bar.tsx`, and
a component test for `app-shell.tsx`'s mode-switching behavior.

- [ ] **Step 1 (failing test):** Render `<AppShell>` inside a router memory
      history at `/app/vaults/prod/secrets`, assert vault-mode nav items are
      present and admin-mode items are absent; re-render at
      `/app/admin/users`, assert the reverse.
- [ ] **Step 2:** Run, confirm failure.
- [ ] **Step 3:** Implement. `app-shell.tsx` mounts one `SidebarProvider` +
      `ToastProvider` + `TooltipProvider` (per `web/CLAUDE.md`'s note that
      none of the five context-requiring components are mounted anywhere
      yet — `DirectionProvider`/`MessageScrollerProvider` are correctly
      *not* mounted here, this app needs neither). `SidebarHeader` renders
      `BrandLockup` from `landing/brand.tsx` plus an "Admin" `badge.tsx`
      when in admin mode. `vault-switcher.tsx`: dropdown-menu-based, backed
      by Task 7's MRU list plus (for admin-tier sessions) a live
      `GET /vaults` call — merge, dedupe by name. `account-menu.tsx` in
      `SidebarFooter`: username, "My sessions" link (`/account`), theme
      toggle wired to the existing `useTheme()`, logout (calls
      `auth.logout()` then `clearSession()`). `top-bar.tsx`: `breadcrumb.tsx`
      + `SidebarTrigger`, mounted inside `SidebarInset`.
- [ ] **Step 4:** Verification gate. Commit:
      `git commit -S -m "feat(shell): add app shell with vault/admin nav modes"`

## Task 10: Wire the full route tree with placeholder pages

**Files:** Create the remaining route files listed in File Structure
(`vaults.tsx`, `vaults.$vaultName.tsx`, `vaults.$vaultName.index.tsx`,
`admin.tsx`, `account.tsx`, `index.tsx`, `oidc.callback.tsx`).

- [ ] **Step 1:** `vaults.$vaultName.tsx` — layout route: `beforeLoad` calls
      `requireAuth` (Task 5); mounts `<AppShell mode="vault">`; does **not**
      precompute per-vault role (spec § 2) — a placeholder
      `<Outlet />`-rendered child page is where the first real data call and
      its 403/404 error boundary will live once Epic 01+ lands.
- [ ] **Step 2:** `admin.tsx` — layout route: `beforeLoad` calls
      `requireGlobalAdmin`; mounts `<AppShell mode="admin">`.
- [ ] **Step 3:** `vaults.tsx`, `vaults.$vaultName.index.tsx` (redirects to
      `.../secrets`), `account.tsx`, `index.tsx` (redirect logic from
      Task 7), `oidc.callback.tsx` (stub — real exchange logic depends on
      confirming `api/oidc.go`'s callback response shape, left as a TODO
      comment citing that file, not guessed at here) all get minimal
      placeholder content (`<Empty>` from `empty.tsx` with a "Coming in
      Epic NN" message) so the route tree is fully navigable end-to-end
      before any feature epic lands.
- [ ] **Step 4:** Verification gate. Commit:
      `git commit -S -m "feat(routing): wire full route tree with epic placeholders"`

## Final Task: Full verification + docs

- [ ] Run the full verification gate one more time from a clean state
      (`rm -rf node_modules && bun install && bun run typecheck && bun run
      lint && bun run test && bun run build`).
- [ ] `bun run dev`, manually confirm: `/app/login` renders matching the
      landing page's tokens (JetBrains Mono headings, teal primary button,
      rounded-4xl card); a login against a real running backend
      (`go run main.go serve` + an existing admin user, per the parent
      repo's Quick Start) reaches `/app/vaults`; navigating to
      `/app/admin/users` as a non-admin redirects away with a toast.
- [ ] Confirm `web/CLAUDE.md`'s Commands section documents `bun run test`.
- [ ] Final commit: `git commit -S -m "docs: document bun run test in web/CLAUDE.md"`

## Self-Review (completed by plan author)

- Spec §§ 2–5 (routing, auth, API client, shell) are each covered by a
  dedicated task (2, 5, 3–4, 9) — no section left unaddressed.
- Spec's three Epic-00-relevant Deferred items (OIDC flag, `GET /vaults`
  scope, vault-recover route) are each called out inline at the task that
  touches them (6, 9, and flagged for Epic 01 respectively) rather than
  silently assumed away.
- No placeholder/TODO left unscanned: Task 10's `oidc.callback.tsx` is the
  one deliberately-incomplete stub, and its gap is explicit (cites the file
  to check, not a guessed implementation).
- Type consistency: `ApiError`/`ApiResponse<T>` (Task 3) are the single
  shared types every later task and every epic's API module will import —
  verified no epic plan redefines them locally.
