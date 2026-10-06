# RocketVault Dashboard — Vault Provisioning Grants Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development
> for the multi-task breakdown below, or superpowers:executing-plans if executing
> this plan directly, top to bottom.

**Goal:** Admin screen for quota-based vault-creation grants — issue a grant to a
principal, list every outstanding grant, re-quota an existing one, and revoke.
Mounted at `/app/admin/provisioning-grants`.

**Architecture:** See `docs/superpowers/specs/2026-09-08-webapp-dashboard-epics-design.md`
§§ 2, 6 (Epic 10). Admin branch only — builds on Phase 0's `src/api/client.ts`,
`useAuth()`, and the `admin.tsx` layout route whose `beforeLoad` already calls
`requireGlobalAdmin` (foundation Task 10, Step 2). This epic adds no guard of
its own; it adds a nav item and child routes under that layout.

**Tech Stack:** unchanged from foundation.

**Conventions to follow:** see foundation plan §Conventions — `@/` alias,
`import type`, `cva`/`cn()`, Prettier (no semicolons, double quotes, 80 cols),
don't edit `src/components/ui/**` in place. Design tokens from `src/index.css`:
teal `--primary`, `font-heading` (JetBrains Mono) for page/section titles and
table headers, `font-sans` (Noto Sans) for body and form values, `rounded-4xl`
cards with `shadow-md ring-1 ring-foreground/5`. All 61 shadcn components are
already vendored (`web/.claude/shadcn-components.md`) — this epic needs
`table.tsx`, `dialog.tsx`, `alert-dialog.tsx`, `input.tsx`, `field.tsx`,
`button.tsx`, `badge.tsx`, `alert.tsx`, `empty.tsx`, `combobox.tsx`, `card.tsx`,
all present. Do not `shadcn add` anything.

**Verification gate (run before every commit):**
```bash
cd web && bun run typecheck && bun run lint && bun run test && bun run build
```

## Backend contract (verified — do not re-derive)

Verified against `api/vault_provisioning_grants.go`, `cmd/vault-provisioning/`,
`internal/services/provisioning/grant_service.go`,
`internal/repositories/vault_provisioning_grant_repository.go`,
`model/vault_provisioning_grant.go`, and
`docs/release-notes/v4.5.0-vault-provisioning.md`.

| Method | Path | Success |
|---|---|---|
| GET | `/api/v1/vault-provisioning-grants` | 200, JSON array (never `null` — `api/vault_provisioning_grants.go:162-165`) |
| PUT | `/api/v1/vault-provisioning-grants/{principal_id}` | **201** if new, **200** on re-quota (`api/vault_provisioning_grants.go:116-120`) |
| DELETE | `/api/v1/vault-provisioning-grants/{principal_id}` | **204**, empty body (`:146`) |

- Subrouter mounted at `api/api.go:132`; handlers registered at
  `api/vault_provisioning_grants.go:39-44`.
- **There is no GET-one route.** `GetGrant` exists only on the service
  interface (`internal/services/provisioning/grant_service.go:32`). A detail
  screen must filter the list client-side.
- **Request body is `{"quota": <int>}` and nothing else**
  (`IssueGrantRequest`, `api/vault_provisioning_grants.go:49-51`). The
  principal comes from the path, never the body (comment at `:46-48`).
- **Response object fields** (`model/vault_provisioning_grant.go:23-32`, no
  `omitempty`, all always present): `id`, `principal_id`, `quota`,
  `created_at`, `created_by`.
- **There is no `used` and no `remaining` field** — not in the model, not in
  the response, not in the DB (`internal/db/db.go:729-734`: columns are exactly
  `id, principal_id, quota, created_at, created_by`). Consumption is computed
  only inside the create transaction from
  `SELECT COUNT(*) FROM vaults WHERE created_by = ?`
  (`internal/repositories/vault_repository.go:158-166`) and is never returned
  by any endpoint.
- **No expiry, no `revoked_at`, no soft-delete.** Revoke is a hard `DELETE`
  (`internal/repositories/vault_provisioning_grant_repository.go:72-76`) that
  returns 204 even when no row matched.
- **No list filters, no pagination, no query params at all**
  (`api/vault_provisioning_grants.go:151-166`; repository is a bare
  `SELECT ... ORDER BY created_at DESC`, `repository.go:78-81`).
- **Quota exhaustion never surfaces on these routes.** It surfaces on
  `POST /api/v1/vaults` as a 403 whose message is
  `"Insufficient permissions: vault provisioning quota exceeded: N of M used"`
  (`api/vault.go:104-105`, sentinel at
  `internal/services/vaults/vault_service.go:345`, wrapped at `:415`).

### Authorization — admin-only and deliberately non-delegable

Both surfaces gate on the **global `admin` account role only**:

- HTTP: `requireGrantAdmin(c)` at `api/vault_provisioning_grants.go:58-64` calls
  `common.HasAnyRole(c.Claims.Roles, model.RoleAdmin)` and is the first
  statement of all three handlers (`:71`, `:130`, `:153`).
- CLI: `requireGrantAdmin(ctx)` at `cmd/vault-provisioning/authz.go:30-39`,
  called first in `grant.go:42`, `revoke.go:20`, `list.go:19`.

There is **no access-policy path and no role-assignment path** into this tier.
`PolicyMiddleware` is a pass-through here — `resolvePolicy` matches none of
`/secrets`, `/keys`, `/certificates`, `/vaults`
(`internal/middleware/middleware.go:414-429`; see the deliberate note at
`api/api.go:127-131` that `"vault-"` ≠ `"vaults"`), and
`MapRouteToDataAction` returns `RouteUnmanaged`
(`internal/services/authorization/data_actions.go:44-79`). `RBACService`
contributes nothing either (`rbac_service.go:277` falls through to `""`).

**This constrains the UI.** Per `../CLAUDE.md` § CLI Authorization, the tier is
non-delegable by design: a principal able to amend its own grant could raise its
own quota and the bound would be decorative. Therefore:

- Do **not** render a "delegate grant management" affordance, a role picker, an
  access-policy link, or any copy implying a Data Access Administrator or a
  `vaults:manage` holder can reach this screen.
- Do **not** reuse Epic 05's role-assignment components here. The two have no
  shared authorization concept.
- The only correct explanatory copy is that grant management requires the
  global admin role and cannot be granted to anyone else.

## File Structure

New: `src/api/provisioning-grants.ts` (+ test),
`src/routes/admin.provisioning-grants.tsx`,
`src/components/provisioning/grant-list.tsx`, `grant-issue-dialog.tsx`,
`grant-revoke-dialog.tsx`, `grant-quota-note.tsx`, tests for each.

Modified: `src/components/app-shell/admin-nav.tsx` (add a
"Provisioning Grants" item).

## Task 1: Provisioning-grants API module

**Files:** Create `src/api/provisioning-grants.ts`,
`src/api/provisioning-grants.test.ts`.

- [ ] **Step 1 (failing tests):** three functions, no more —
      `listGrants()` → `GET /api/v1/vault-provisioning-grants`;
      `issueGrant(principalId, quota)` →
      `PUT /api/v1/vault-provisioning-grants/{principalId}` with body
      `{ quota }` **only** (write a test asserting `principal_id` is *not* in
      the request body — it lives in the path, per
      `api/vault_provisioning_grants.go:46-48`);
      `revokeGrant(principalId)` → `DELETE .../{principalId}`, resolving to
      `void` on 204 without attempting to parse an empty body.
- [ ] **Step 2 (failing test):** `issueGrant` returns the parsed grant **and**
      a `created: boolean` derived from the HTTP status (201 → `true`,
      200 → `false`), so the UI can say "grant issued" vs. "quota updated".
      Assert both branches. Do not infer this from the body — the body is
      identical in both cases.
  ```ts
  // src/api/provisioning-grants.test.ts (excerpt)
  it("distinguishes a new grant (201) from a re-quota (200)", async () => {
    vi.spyOn(global, "fetch").mockResolvedValueOnce(json(grantFixture, 200))
    await expect(issueGrant(PRINCIPAL, 5)).resolves.toMatchObject({
      created: false,
    })
  })
  ```
- [ ] **Step 3:** Type the grant as exactly
      `{ id: string; principal_id: string; quota: number; created_at: string;
      created_by: string }`. **Do not add `used`, `remaining`, `expires_at`, or
      `revoked_at`** — none exist server-side. A test should assert the type has
      no extra optional fields by round-tripping a fixture built from
      `model/vault_provisioning_grant.go:23-32`.
- [ ] **Step 4:** Run, confirm failure. Implement with `client.ts`'s
      `request()`. Verification gate. Commit:
      `git commit -S -m "feat(api): add vault provisioning grants module"`

## Task 2: Grant list screen

**Files:** Create `src/routes/admin.provisioning-grants.tsx`,
`src/components/provisioning/grant-list.tsx`, tests. Modify
`src/components/app-shell/admin-nav.tsx`.

- [ ] **Step 1 (failing test):** `<GrantList>` renders one row per grant from
      `listGrants()` (TanStack Query) with columns Principal, Quota, Issued,
      Issued by — table headers in `font-heading`. An empty array renders
      `empty.tsx` with an "Issue the first grant" CTA, not a bare table.
- [ ] **Step 2 (failing test):** the table renders **no** "used" or "remaining"
      column and no progress bar. Assert this explicitly — it is the single
      easiest thing for an implementer to invent, and there is no server field
      behind it (`model/vault_provisioning_grant.go:23-32`).
  ```tsx
  it("does not render a consumption column the API cannot populate", () => {
    render(<GrantList grants={[grantFixture]} />)
    expect(screen.queryByText(/used/i)).not.toBeInTheDocument()
    expect(screen.queryByText(/remaining/i)).not.toBeInTheDocument()
    expect(screen.queryByRole("progressbar")).not.toBeInTheDocument()
  })
  ```
- [ ] **Step 3 (failing test):** `<GrantQuotaNote>` — a small `alert.tsx`
      above the table stating the two non-obvious quota rules, both verified:
      soft-deleted vaults still consume a slot and only a purge frees one
      (`internal/repositories/vault_repository.go:150-166`,
      `docs/release-notes/v4.5.0-vault-provisioning.md:71-86`), and pre-existing
      vaults count retroactively because the count is keyed on `created_by`,
      not on the grant's `created_at`. Assert both sentences render.
- [ ] **Step 4:** No filter/search controls and no pagination — the endpoint
      accepts no query params. If the list grows unwieldy, filter client-side
      over the already-fetched array; do **not** add a query param the server
      ignores.
- [ ] **Step 5:** Add the nav item to `admin-nav.tsx`. Run, confirm failure,
      implement, verification gate. Commit:
      `git commit -S -m "feat(provisioning): add grant list screen"`

## Task 3: Issue / re-quota dialog

**Files:** Create `src/components/provisioning/grant-issue-dialog.tsx`, test.

- [ ] **Step 1 (failing test):** `<GrantIssueDialog>` takes a principal
      identifier and a quota, calls `issueGrant`, invalidates the list query,
      and shows "Grant issued" on `created: true` / "Quota updated" on
      `created: false`.
- [ ] **Step 2 (failing test):** client-side validation rejects `quota <= 0`
      before the request, with the backend's own reasoning as the message —
      the CLI states it as "a zero-quota grant is indistinguishable from no
      grant" (`cmd/vault-provisioning/grant.go:47`); the service returns
      `model.ErrInvalidQuota` = `"quota must be greater than zero"`
      (`model/vault_provisioning_grant.go:11, 39-41`). Also assert a server
      400 (`id: "api.context.set_invalid_param"`, param `"quota"`,
      `api/vault_provisioning_grants.go:107-110`) is surfaced verbatim rather
      than replaced by a generic failure.
- [ ] **Step 3 (failing test — principal input):** the API accepts **only a
      raw UUID** in the path. The CLI additionally resolves a username to a
      UUID (`cmd/vault-provisioning/grant.go:32`, `"resolve principal %q: %w"`),
      but that resolution is CLI-local and has **no HTTP equivalent**. So the
      dialog uses `combobox.tsx` over `GET /api/v1/users` (Epic 07's
      `listUsers`) for convenience **and** accepts a pasted UUID as a free-text
      fallback. The fallback is mandatory, not a nicety: `principal_id` has no
      foreign key to `users` and may be an `oauth2_clients` service account
      (`docs/release-notes/v4.5.0-vault-provisioning.md:21-32`), which the user
      list will never contain. Write a test that submits a raw UUID with the
      user list mocked empty.
- [ ] **Step 4:** If Epic 07 has not landed, implement the UUID field only and
      leave a one-line comment citing `admin.users` as the future source of the
      combobox options — do not block this epic on Epic 07.
- [ ] **Step 5:** Run, confirm failure, implement using `dialog.tsx`,
      `field.tsx`, `input.tsx`, `combobox.tsx`. Verification gate. Commit:
      `git commit -S -m "feat(provisioning): add issue/re-quota dialog"`

## Task 4: Revoke, and the two consequences it does not have

**Files:** Create `src/components/provisioning/grant-revoke-dialog.tsx`, test.

- [ ] **Step 1 (failing test):** revoke behind `alert-dialog.tsx` with
      `--destructive` styling, calls `revokeGrant(principalId)`, removes the
      row on success.
- [ ] **Step 2 (failing test):** the confirm body must state that revocation
      **stops future creates only** — it does not delete, disable, or reassign
      any vault the principal already created, and the principal keeps its
      creator rights over those vaults
      (`api/vault_provisioning_grants.go:123-127`,
      `internal/services/provisioning/grant_service.go:94-102`,
      `docs/release-notes/v4.5.0-vault-provisioning.md:105-126`). Assert that
      sentence renders. Getting this wrong is a real operational hazard: an
      admin who believes revoke is a lockout will stop there.
- [ ] **Step 3 (failing test):** the confirm body also notes that full lockout
      additionally requires removing the vault-scoped `vaults:manage` access
      policy — removing only the role assignment leaves the creator able to
      re-grant itself Key Vault Administrator
      (`docs/release-notes/v4.5.0-vault-provisioning.md:105-126`). Link to
      Epic 09's access-policies screen if it exists; if it does not, render the
      sentence without a link rather than inventing a route.
- [ ] **Step 4:** Note in a code comment that a revoke of a non-existent grant
      returns 204, not 404
      (`internal/repositories/vault_provisioning_grant_repository.go:72-76`), so
      a successful revoke is not proof a grant existed. Do not build
      "already revoked" detection on the status code.
- [ ] **Step 5:** Run, confirm failure, implement, verification gate. Commit:
      `git commit -S -m "feat(provisioning): add grant revoke with scope warning"`

## Task 5: Surface the quota-exceeded error where it actually happens

**Files:** Modify `src/components/vaults/vault-create-dialog.tsx` (Epic 01) if
it exists; otherwise create a test-only note and defer.

- [ ] **Step 1 (failing test):** a mocked 403 from `createVault` whose message
      matches `/vault provisioning quota exceeded/i` renders the server's
      message verbatim plus a line pointing at `/app/admin/provisioning-grants`
      (shown only when `isGlobalAdmin`) — the grant screen itself can never
      raise this error, because quota is enforced in the vault-creation
      transaction (`internal/services/vaults/vault_service.go:403-417`) and
      mapped to 403 at `api/vault.go:104-105`.
- [ ] **Step 2 (failing test):** the sibling 403
      `"purge protection may only be set on a create that is not quota-bounded"`
      (`internal/services/vaults/vault_service.go:353, 372-374`) is likewise
      surfaced verbatim. Do not pre-disable the purge-protection toggle — the
      client has no way to know whether the caller's create is quota-bounded.
- [ ] **Step 3:** If Epic 01 has not landed, skip the implementation and record
      this task's two assertions as a TODO comment in
      `src/api/provisioning-grants.ts` citing `api/vault.go:104-105`, so Epic 01
      inherits the requirement instead of losing it.
- [ ] **Step 4:** Run, confirm failure, implement, verification gate. Commit:
      `git commit -S -m "feat(vaults): surface provisioning quota errors on create"`

## Self-Review

- Every route the backend actually exposes (list, upsert, delete) has a task;
  no GET-one route is invented, because none exists.
- No `used`/`remaining`/`expires_at`/`revoked_at` field appears anywhere — an
  explicit negative test (Task 2, Step 2) keeps a future implementer from
  adding a consumption meter the API cannot feed.
- The non-delegable admin tier is respected: no delegation affordance, no
  role-assignment reuse, and the constraint is stated with its rationale rather
  than left implicit.
- 201-vs-200 is carried through the API module (Task 1) instead of being
  guessed from the response body, which is identical in both cases.
- Revoke's two *non*-consequences (no cascade, no lockout) are tested copy, not
  optional documentation — this is the epic's highest-risk misunderstanding.
- Quota-exceeded is handled on the vault-create path where it is actually
  raised, not faked on the grant screen.
