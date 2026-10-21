# RocketVault Dashboard — Access Policies Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development
> for the multi-task breakdown below, or superpowers:executing-plans if executing
> this plan directly, top to bottom.

**Goal:** Manage the `access_policies` layer — the authorization axis that sits
*beside* per-vault RBAC role assignments (Epic 05), not on top of it. In
practice that means a screen for **explicit denies** (global or vault-scoped,
evaluated before any role grant) plus the one surviving allow path,
`(vaults, manage)`. It is emphatically **not** a general-purpose
"grant a data-plane action" UI, and this plan's principal job is to stop one
being built.

**Architecture:** See `docs/superpowers/specs/2026-09-08-webapp-dashboard-epics-design.md`
§§ 2, 6 (Epic 09), and `.claude/azure-keyvault-parity.md` /
`../CLAUDE.md` § Authorization in the main repo. Global-admin only, entirely
under `/app/admin/...`. Builds on Phase 0's `src/api/client.ts`, `useAuth()`,
`requireAuth`, and the admin-mode app-shell nav.

**Tech Stack:** unchanged from foundation.

**Conventions to follow:** see foundation plan §Conventions — `@/` alias,
`import type`, `cva`/`cn()`, Prettier (no semicolons, double quotes, 80 cols),
`bun run format` after touching class strings, no in-place edits to
`src/components/ui/**`. Design tokens from `web/src/index.css` only: teal
primary (`src/index.css:17` / `:53`), `font-heading` (JetBrains Mono,
`src/index.css:82`) for headings, table headers, badges, and every
enum/identifier rendered on screen (principal UUIDs, resource types,
operations); `font-sans` (Noto Sans, `src/index.css:81`) for explanatory copy —
of which this screen needs an unusual amount; cards `rounded-4xl`
(`src/index.css:120`) with `shadow-md ring-1 ring-foreground/5`. Deny rows use
`--destructive`; the `(vaults, manage)` allow rows use `--warning` (added by
foundation Task 8) rather than a success tone, because they are a legacy
escalation path, not a healthy state. Compose from the 61 already-vendored
shadcn components in `src/components/ui/`
(`web/.claude/shadcn-components.md`); nothing new is required.

**Verification gate (run before every commit):**
```bash
cd web && bun run typecheck && bun run lint && bun run test && bun run build
```

## Backend contract — CRUD (verified against Go source)

Routes: `api/access_policies.go:14-22`, under the `/access-policies` subrouter
(`api/api.go:124-125`).

| Method | Path | Handler | Success |
|---|---|---|---|
| GET | `/api/v1/access-policies` | `listAccessPolicies` (`api/access_policies.go:41`) | 200 `{access_policies: [...], total}` (`:57-60`) |
| POST | `/api/v1/access-policies` | `createAccessPolicy` (`:65`) | **201** + the created `model.AccessPolicy` (`:127`) |
| GET | `/api/v1/access-policies/{policy_id}` | `getAccessPolicy` (`:132`) | 200 bare `model.AccessPolicy` (`:149`); 404 (`:144-147`) |
| PUT | `/api/v1/access-policies/{policy_id}` | `updateAccessPolicy` (`:154`) | 200 — **updates `effect` only** (`:164-192`) |
| DELETE | `/api/v1/access-policies/{policy_id}` | `deleteAccessPolicy` (`:197`) | 200 `{"status":"OK"}` (`:213`, `api/api.go:210-212`) |
| GET | `/api/v1/access-policies/principal/{principal_id}` | `listAccessPoliciesByPrincipal` (`:218`) | 200 same envelope as list (`:239-242`) |

All six gate on the global `admin` role via `requireAccessPolicyAdmin`
(`api/access_policies.go:31-37`), whose doc comment states the reason plainly:
a principal able to write policies could silence its own deny or deny everyone
else out of every vault. As with `/users` and `/service-accounts`,
`resolvePolicy` (`internal/middleware/middleware.go:407-428`) returns an empty
pair for `/access-policies`, so no policy governs the policy routes themselves.

Shapes (`model/access_policy.go`):

- `AccessPolicy` = `{id, principal_id, principal_type, resource_type,
  operation, effect, vault_id?, assignment_id?, created_at}` (`:57-71`).
  **`vault_id` absent (nil) means GLOBAL** (`:64-66`); `assignment_id` present
  means the row was materialized by a role grant, not hand-written (`:67-69`).
- `CreateAccessPolicyRequest` = `{principal_id, principal_type, resource_type,
  operation, effect, vault_id?}` (`:73-81`). `principal_id` must parse as a
  UUID (`api/access_policies.go:75-79`, 400 otherwise); the other four are
  required (`:80-83`); an empty `vault_id` leaves the policy global
  (`:111-119`).
- **PUT accepts one field, `effect`** — an anonymous `{Effect string}` struct
  (`api/access_policies.go:164-169`). Principal, resource, operation and vault
  are immutable; changing any of them means delete + recreate.
- Enums: `principal_type` ∈ `user` | `service_account` (`:14-17`);
  `effect` ∈ `allow` | `deny` (`:19-24`); `resource_type` ∈ `secrets` | `keys`
  | `certificates` | `vaults` (`:26-33`); `operation` ∈ 17 values (`:35-55`),
  validated by `ValidatePolicyOperation` (`:107-114`).
- `model.AccessPolicyResponse` and `model.ListAccessPoliciesResponse`
  (`:125-145`) are **unused by every handler** and drop `assignment_id`. Derive
  TypeScript types from the handler bodies above, not from those structs.
- List has **no pagination and no filters** (`api/access_policies.go:41-61`) —
  it returns every row on the instance, and `total` is just its length.
  Filtering is therefore a client-side responsibility for this screen.

## Backend contract — what a policy actually DOES today (the part that shapes the UI)

This is the section to read before designing any form. A naive "pick a
principal, pick an action, click Allow" screen would model behaviour that has
not existed since the Azure-RBAC work landed.

**1. On the vault data plane, only `deny` has any effect. `allow` grants
nothing.**

`PolicyMiddleware` runs two stages in order
(`internal/middleware/middleware.go:532-583`):

- Stage 1 calls `AccessPolicyService.CheckAccess` and acts **only** on
  `AccessDenied` → 403 (`:543-549`). An `AccessAllowed` here is carried forward
  in a local variable and nothing more.
- Stage 2, for any `RouteVaultData` route, calls
  `RoleAssignmentService.HasDataAction` unconditionally and returns from the
  handler chain either way (`:553-583`). Stage 1's `AccessAllowed` never
  reaches the stage-3 branch below, so it cannot satisfy the deny-by-default
  data-plane check.
- Stage 3 (`:586-591`) — non-data-plane managed routes — logs `AccessAllowed`
  and then calls `next.ServeHTTP` **regardless of the decision**. The allow is
  not load-bearing there either; those handlers run their own checks.

The CLI reproduces exactly this: `vaultcli.RequireDataAction`
(`cmd/vaultcli/vault.go:56-66`) short-circuits on `AccessDenied` only, then
defers to `authorization.RequireDataAction`. So an `allow` policy on
`secrets`/`keys`/`certificates` is inert on **both** entry points. Granting
data-plane access is Epic 05's job (role assignments), full stop.

**2. The one live allow path is `(resource_type: vaults, operation: manage)`,
and it is deliberately narrow.**

Three call sites in `internal/services/authorization/vault_authz.go` consult
policies for an allow:

- `CanCreateVault` (`:171-195`) — a **global** (`vault_id` null) allow yields
  `CreateRightGlobalPolicy`. As of v4.6.0 that is **create-and-list only**; it
  confers no authority over any individual vault.
- `CanManageVault` (`:35-55`) — for a concrete vault it uses
  `CheckVaultScopedAccess`, so only a **vault-scoped** allow manages that
  vault; a global allow does not (`:46-50`).
- `CanManageRoleAssignments` (`:100-134`) — vault-scoped allow only;
  `uuid.Nil` always denies a non-admin (`:104-106`).

The asymmetry is implemented in `CheckVaultScopedAccess`
(`internal/services/authorization/access_policy_service.go:89-111`): it keeps
NULL-scoped **denies** (a global deny must keep blocking every vault) and
discards NULL-scoped **allows**.

**3. Several valid `operation` values can never match a real request.**

`ValidatePolicyOperation` accepts all 17 constants
(`model/access_policy.go:107-114`), but `resolvePolicy`
(`internal/middleware/middleware.go:430-464`) can only ever *produce*:
`purge` (DELETE `…/purge`), `recover` (POST `…/restore` — note the name
mismatch), `rotate`, `import`, `renew`, `sign`, `verify`, then `get` (any GET),
`create` (any other POST), `set` (PUT), `delete` (DELETE). Plus `manage`, which
is returned for `/vaults` paths and only those (`:422-425`). The CLI passes the
same set and no others — a sweep of `cmd/secrets/`, `cmd/keys/` and
`cmd/certificates/` yields exactly `get`, `create`, `set`, `delete`, `sign`,
`verify`, `rotate`, `renew`, `import`.

Therefore **`list`, `backup`, `restore`, `encrypt` and `decrypt` are accepted
by the API and silently inert** — a deny naming one of them blocks nothing. The
mappings that surprise people:

- a GET always resolves to `get`, never `list` — so "deny listing" is written
  as a deny on `get`;
- `…/backup`, `…/encrypt`, `…/decrypt`, `…/wrap`, `…/unwrap` are all plain
  POSTs and therefore resolve to `create`;
- `…/restore` resolves to `recover`, not `restore`.

**4. Role assignments no longer write policy rows.** `ExpandRole` returns
`nil, nil` for every Azure built-in role
(`internal/services/authorization/roles.go:162-165`), with the comment stating
that `access_policies` "is retained only as an explicit-deny override". Only
the legacy non-Azure bundle roles still expand into rows with
`assignment_id` set (`:174-186`), and those rows are deleted wholesale on
revoke via `DeleteByAssignmentID`
(`internal/services/authorization/role_assignment_service.go:196`). A row with
`assignment_id` present is therefore **owned by a role assignment** — editing
or deleting it from this screen desynchronizes the two tables.

## Documented gaps (verified; do not design around them)

1. **No CLI exists for access policies.** There is no `cmd/access-policies`
   package and nothing under `cmd/` creates, lists or deletes a policy. Like
   Epic 08, this screen is the first interactive surface for the feature, so
   unexpected responses are findings worth recording rather than papering over.
2. **The API will happily accept an inert policy** — an `allow` on
   `secrets`/`get`, or a deny on `backup` — and return 201. There is no
   server-side warning. Every guard-rail in this epic is client-side, which is
   why each is backed by a test rather than left to reviewer discipline.
3. **`list` returns every row with no filter or page parameter**
   (`api/access_policies.go:41-61`). Filtering, sorting and paging are the
   UI's problem.
4. **A principal is a bare UUID with no resolution endpoint.** `principal_id`
   is a UUID and `principal_type` says only whether it names a user or a
   service account (`model/access_policy.go:58-60`); nothing joins it to a
   username or account name. The UI can resolve it client-side by cross-
   referencing Epic 07's `GET /users` and Epic 08's `GET /service-accounts`,
   both of which this admin already has access to. An unresolvable UUID (a
   deleted principal) must render as the raw UUID plus an "unknown principal"
   marker — orphaned rows are not cleaned up on user deletion.
5. **`vault_id` is a UUID, but every other vault surface in this app is keyed
   by vault *name*** (`/app/vaults/:vaultName/…`, spec § 2). Epic 01's
   `listVaults()` is the only source for the id↔name mapping; a vault deleted
   after its policy was written leaves an unresolvable id, which must render
   as the raw UUID rather than a blank.

## File Structure

New: `src/api/access-policies.ts` (+ test),
`src/routes/admin.access-policies.index.tsx`,
`src/components/admin/access-policies/policy-list.tsx`,
`policy-effect-badge.tsx`, `policy-create-dialog.tsx`,
`policy-principal-cell.tsx`, `policy-model-explainer.tsx`, tests for each.

Modified: `src/components/app-shell/admin-nav.tsx` (add "Access Policies").

## Task 1: Access policies API module

**Files:** Create `src/api/access-policies.ts`,
`src/api/access-policies.test.ts`.

- [ ] **Step 1 (failing tests):** `listAccessPolicies()` →
      `GET /api/v1/access-policies`, unwrapping `access_policies`;
      `listAccessPoliciesByPrincipal(principalId)` →
      `GET /api/v1/access-policies/principal/{id}`, same envelope;
      `getAccessPolicy(id)` → bare object;
      `createAccessPolicy(input)` → `POST`, expecting **201**;
      `updateAccessPolicyEffect(id, effect)` → `PUT` with a body of
      **exactly** `{effect}` and no other key (`api/access_policies.go:164-169`
      ignores everything else, so sending more is a lie about what happened);
      `deleteAccessPolicy(id)` → `DELETE`.
- [ ] **Step 2 (failing test — global vs scoped):** assert `vault_id` is
      **omitted** from the create body for a global policy, not sent as `null`
      or `""`; and that a response with no `vault_id` key maps to a
      `scope: "global"` discriminant rather than `vaultId: undefined`. The
      nil-means-global rule (`model/access_policy.go:64-66`) is the single
      most misreadable thing in this API — encode it in the type, not in
      component logic.
- [ ] **Step 3 (failing test — the enums come from Go, not from memory):**
      export `PRINCIPAL_TYPES`, `POLICY_EFFECTS`, `POLICY_RESOURCE_TYPES` and
      `POLICY_OPERATIONS` as `const` tuples, each with a comment citing its
      `model/access_policy.go` line range. Additionally export
      `ENFORCEABLE_OPERATIONS` — the subset `resolvePolicy` and the CLI can
      actually produce (`get`, `create`, `set`, `delete`, `purge`, `recover`,
      `rotate`, `import`, `renew`, `sign`, `verify`, and `manage` for `vaults`
      only) — with a comment citing
      `internal/middleware/middleware.go:430-464`. Assert
      `ENFORCEABLE_OPERATIONS` is a strict subset of `POLICY_OPERATIONS` and
      that `list`, `backup`, `restore`, `encrypt` and `decrypt` are excluded.
- [ ] **Step 4:** Run, confirm failure.
- [ ] **Step 5:** Implement over `client.ts`'s `request()`. Header comment:
      one paragraph recording that `allow` is inert on the data plane, citing
      `internal/middleware/middleware.go:553-583` and
      `internal/services/authorization/roles.go:162-165`.
- [ ] **Step 6:** Verification gate. Commit:
      `git commit -S -m "feat(api): add access policies module"`

## Task 2: The explainer — get the mental model on screen before any form

**Files:** Create
`src/components/admin/access-policies/policy-model-explainer.tsx`, test.

- [ ] **Step 1 (failing test):** a persistent `card.tsx` at the top of the
      route (collapsible via `collapsible.tsx`, expanded by default on first
      visit) states, in `font-sans` body copy, the three facts that make the
      rest of the screen legible:
      1. access policies are evaluated **before** RBAC role assignments, and an
         explicit deny always wins;
      2. an **allow** on `secrets`, `keys` or `certificates` grants nothing —
         data-plane access is granted by role assignments, with a link to
         Epic 05's vault-access screen;
      3. the only allow that still does anything is `(vaults, manage)`, and a
         global one means create-and-list only.
- [ ] **Step 2 (failing test — the copy does not overclaim):** assert the
      component does **not** contain the strings "grant access to secrets",
      "allow read" or any phrasing that presents this screen as a way to give
      someone data-plane permissions. A snapshot-style assertion over the
      rendered text is appropriate here; this is the one place where wording
      is the deliverable.
- [ ] **Step 3:** Run, confirm failure, implement, verification gate. Commit:
      `git commit -S -m "feat(admin): add access policy model explainer"`

## Task 3: Policy list with client-side filtering and honest badges

**Files:** Create `src/routes/admin.access-policies.index.tsx`,
`policy-list.tsx`, `policy-effect-badge.tsx`, `policy-principal-cell.tsx`,
tests.

- [ ] **Step 1 (failing test):** `<PolicyList>` renders a `table.tsx` row per
      policy — principal, type, resource, operation, effect, scope, created.
      Since the endpoint returns everything unpaged (gap 3), add client-side
      filter controls (`select.tsx` for effect / resource type / scope, a
      `input.tsx` search over principal) and `pagination.tsx` over the filtered
      set.
- [ ] **Step 2 (failing test — scope is rendered as a word, not a blank):** a
      policy with no `vault_id` renders a **"Global"** badge; one with a
      `vault_id` renders the vault's name resolved from Epic 01's
      `listVaults()`, falling back to the raw UUID when unresolvable (gap 5).
      Assert both, and assert an empty cell is never produced — a blank here
      reads as "no scope" when it means the opposite of narrow.
  ```tsx
  // policy-list.test.tsx (excerpt)
  it("renders a missing vault_id as Global, never as an empty cell", async () => {
    vi.mocked(listAccessPolicies).mockResolvedValue([
      { id: "…", effect: "deny", resource_type: "secrets", operation: "get" },
    ])
    render(<PolicyList />)
    const row = await screen.findByRole("row", { name: /deny/i })
    expect(within(row).getByText(/global/i)).toBeInTheDocument()
  })
  ```
- [ ] **Step 3 (failing test — `assignment_id` rows are read-only):** a policy
      carrying `assignment_id` renders a "Managed by role assignment" marker
      (`marker.tsx` or `badge.tsx`) and its Edit and Delete actions are
      **absent**, with a `tooltip.tsx` pointing at the vault-access screen.
      Deleting such a row by hand desynchronizes it from the
      `role_assignments` table that owns it
      (`internal/services/authorization/role_assignment_service.go:196`).
      Assert both the marker and the absence of the actions.
- [ ] **Step 4 (failing test — inert rows are flagged):** a row whose
      `operation` is outside `ENFORCEABLE_OPERATIONS`, or whose `effect` is
      `allow` on a data-plane `resource_type`, renders an "inert" warning
      marker explaining it matches no request today. These rows exist in
      real deployments and the screen's value is largely in surfacing them.
  ```tsx
  it("flags an allow on a data-plane resource as inert", async () => {
    vi.mocked(listAccessPolicies).mockResolvedValue([
      { id: "…", effect: "allow", resource_type: "keys", operation: "sign" },
    ])
    render(<PolicyList />)
    expect(await screen.findByText(/grants nothing/i)).toBeInTheDocument()
  })
  ```
- [ ] **Step 5 (failing test — principal resolution):** `<PolicyPrincipalCell>`
      resolves a `principal_id` against Epic 07's users and Epic 08's service
      accounts by `principal_type`, and renders the raw UUID plus an "unknown
      principal" marker when neither matches (gap 4). Assert the unknown case
      explicitly — orphaned rows outlive their principals.
- [ ] **Step 6:** Run, confirm failure, implement, verification gate. Commit:
      `git commit -S -m "feat(admin): add access policy list"`

## Task 4: Create dialog — two named flows, not one generic form

**Files:** Create `policy-create-dialog.tsx`, test.

The dialog opens on a choice (`radio-group.tsx` or two `card.tsx` options),
because the two things this API can usefully do have nothing in common:

- [ ] **Step 1 (failing test — "Block an operation"):** the deny flow. Pick a
      principal (a `combobox.tsx` over users + service accounts, which also
      fills `principal_type`), a resource type, an operation from
      `ENFORCEABLE_OPERATIONS`, and a scope (Global, or a specific vault from
      Epic 01's list). `effect` is fixed to `deny` and is **not** a user
      choice in this flow — assert no effect selector renders.
- [ ] **Step 2 (failing test — the operation list is filtered):** assert the
      operation select offers only `ENFORCEABLE_OPERATIONS` and that `list`,
      `backup`, `restore`, `encrypt` and `decrypt` are absent, each with the
      helper text that explains the real mapping ("a GET resolves to `get`, not
      `list`"; "`/restore` resolves to `recover`"; "backup, encrypt, decrypt
      and wrap are plain POSTs and resolve to `create`"). Citing
      `internal/middleware/middleware.go:430-464`, this is the difference
      between a deny that works and one that quietly does not.
- [ ] **Step 3 (failing test — "Grant vault management"):** the allow flow,
      available only with `resource_type: vaults` and `operation: manage`.
      `effect` is fixed to `allow`. Assert the scope selector's two options
      carry their real, different meanings in the label itself: **Global** →
      "may create and list vaults, and nothing more" (v4.6.0 narrowing,
      `internal/services/authorization/vault_authz.go:171-195`); **This vault**
      → "may manage this vault and its role assignments"
      (`:35-55`, `:100-134`). Assert a global allow's copy does **not** claim
      management of existing vaults.
- [ ] **Step 4 (failing test — the escape hatch is guarded, not hidden):**
      an "Advanced" disclosure (`collapsible.tsx`) permits any valid
      `(resource_type, operation, effect)` combination the API accepts,
      because a deployment may need one this UI has not anticipated. Assert
      that selecting an inert combination there renders a blocking
      confirmation naming exactly why it will do nothing, and that the
      confirmation must be acknowledged before submit is enabled. The server
      returns 201 for these (gap 2); the warning is the only one there is.
- [ ] **Step 5 (failing test — server errors surface verbatim):** a 400 from
      `createAccessPolicy` (bad `principal_id`, unknown enum —
      `api/access_policies.go:75-99`) renders the server's own message rather
      than a generic failure.
- [ ] **Step 6:** Run, confirm failure, implement, verification gate. Commit:
      `git commit -S -m "feat(admin): add access policy create dialog"`

## Task 5: Effect toggle and delete

**Files:** Modify `policy-list.tsx`; create tests.

- [ ] **Step 1 (failing test — the only edit is `effect`):** the row action is
      "Flip effect", not "Edit". Assert it sends `PUT` with a body of exactly
      `{effect}` and that no other field is offered for editing anywhere —
      principal, resource, operation and vault are immutable
      (`api/access_policies.go:164-192`). Assert the UI tells the user that
      changing anything else means deleting and recreating.
- [ ] **Step 2 (failing test — flipping to `allow` warns):** flipping a
      data-plane deny to `allow` renders an `alert-dialog.tsx` stating that the
      result grants nothing and merely removes the block, and that the
      principal's actual access then falls back to their role assignments.
      This is the single most likely misunderstanding on the screen.
- [ ] **Step 3 (failing test — delete):** delete behind `alert-dialog.tsx`.
      For a **deny** row the copy must state that removal *restores* whatever
      the principal's role assignments grant — deleting a deny is a
      privilege-increasing action, which is not how a delete button usually
      reads. Assert that wording. The backend returns 200 with
      `{"status":"OK"}` (`api/access_policies.go:213`), not 204.
- [ ] **Step 4 (failing test — `assignment_id` rows stay untouched):** assert
      neither action is reachable for a role-derived row, reusing Task 3
      Step 3's fixture.
- [ ] **Step 5:** Run, confirm failure, implement, verification gate. Commit:
      `git commit -S -m "feat(admin): add access policy effect toggle and delete"`

## Task 6: Per-principal view, admin guard, nav wiring

**Files:** Modify `policy-list.tsx` and
`src/components/app-shell/admin-nav.tsx`; create a guard test.

- [ ] **Step 1 (failing test):** clicking a principal filters the list through
      `listAccessPoliciesByPrincipal` (`api/access_policies.go:218`) rather
      than client-side, so the "what does this principal have?" question is
      answered by the endpoint built for it. Assert the request is made and
      that the view is linkable (a search param, so it can be shared).
- [ ] **Step 2 (failing test):** a session without `admin` in its `roles`
      claim is redirected away from `/app/admin/access-policies` and issues no
      `listAccessPolicies` request — assert the fetch mock was never called.
      This matters more here than elsewhere: the list endpoint enumerates every
      policy row and principal UUID on the instance, which is precisely the
      exposure `requireAccessPolicyAdmin`'s doc comment
      (`api/access_policies.go:24-30`) exists to prevent.
- [ ] **Step 3:** Add the "Access Policies" nav item, `font-heading` label,
      placed adjacent to Epic 05's vault-access entry so the two authorization
      axes read as siblings in the nav.
- [ ] **Step 4:** Run, confirm failure, implement, verification gate. Commit:
      `git commit -S -m "feat(admin): wire access policies into admin nav and guard"`

## Self-Review

- All six routes in `api/access_policies.go:14-22` have a task, and the one
  that is easy to miss — `GET /access-policies/principal/{id}` — drives a real
  view (Task 6) rather than being reimplemented as a client-side filter.
- The epic brief's central risk is addressed structurally, not by a caveat:
  there is **no generic allow form**. Task 4 splits creation into a deny flow
  (effect fixed to `deny`) and a `(vaults, manage)` allow flow (effect fixed to
  `allow`), with the arbitrary-combination path behind an Advanced disclosure
  that blocks on an acknowledged warning. A form that offered "allow" on
  `secrets` as a peer of "deny" would have modelled behaviour that
  `internal/middleware/middleware.go:553-583` has not implemented for some
  time.
- Confirmed live today, from source rather than from documentation: full CRUD
  exists (create/list/get/update/delete + list-by-principal), but **update
  changes `effect` and nothing else** (`api/access_policies.go:164-192`); an
  `allow` on `secrets`/`keys`/`certificates` is inert on both HTTP and CLI; the
  sole load-bearing allow is `(vaults, manage)`, split three ways by
  `vault_authz.go`; and role assignments stop writing policy rows entirely for
  Azure roles (`roles.go:162-165`).
- The five operations the API accepts but can never match (`list`, `backup`,
  `restore`, `encrypt`, `decrypt`) are excluded from the primary form and
  flagged on existing rows (Task 3 Step 4), with the surprising real mappings
  spelled out in helper text rather than left for a future operator to
  discover after a deny fails to fire.
- Rows owned by a role assignment (`assignment_id` present) are read-only in
  three places — list marker, missing row actions, and a repeated assertion in
  Task 5 — because the desync they would cause is silent.
