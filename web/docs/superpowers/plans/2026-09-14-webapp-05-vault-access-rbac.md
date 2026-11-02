# RocketVault Dashboard — Vault Access (RBAC) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development
> for the multi-task breakdown below, or superpowers:executing-plans if executing
> this plan directly, top to bottom.

**Goal:** Per-vault role assignment management — list who holds which of the
eleven Azure-parity built-in roles in a vault, grant a role to a principal,
and revoke an assignment — on one route, `/app/vaults/:vaultName/access`.

**Architecture:** See `docs/superpowers/specs/2026-09-08-webapp-dashboard-epics-design.md`
§§ 2, 6 (Epic 05). This is the epic where the spec's § Goals requirement that
"per-vault RBAC is a completely separate axis from global admin" becomes
literal UI: the screen is reachable by three different authorities that grant
three different capabilities, and conflating them produces a UI that offers
actions the server will refuse. Builds on Phase 0's `src/api/client.ts`,
`useAuth()` (for the JWT-derived `roles` claim), and the
`vaults.$vaultName.tsx` layout route.

**Tech Stack:** unchanged from foundation (React 19 + TS strict + TanStack
Router/Query + Vitest/RTL).

**Conventions to follow:** see foundation plan §Conventions — `@/` alias,
`import type` (`verbatimModuleSyntax`), `cva`/`cn()` from `@/lib/utils`,
`data-slot` on component roots, Prettier (no semicolons, double quotes,
2-space, 80 cols; `bun run format` after touching class strings), and do not
edit `src/components/ui/**` in place.

Design system is fixed by `web/src/index.css`: teal `--primary`, `font-heading`
(JetBrains Mono Variable) for the page title, table headers, role badges and
nav labels, `font-sans` (Noto Sans Variable) for body and form values, cards
`rounded-4xl shadow-md ring-1 ring-foreground/5`. Everything needed is already
among the 61 vendored components in `src/components/ui/` — `table.tsx`,
`dialog.tsx`, `alert-dialog.tsx`, `select.tsx`, `combobox.tsx`, `field.tsx`,
`badge.tsx`, `alert.tsx`, `empty.tsx`, `tooltip.tsx`, `radio-group.tsx`,
`hover-card.tsx`, `skeleton.tsx`. Do not `shadcn add` anything; see
`web/.claude/shadcn-components.md`.

**Verification gate (run before every commit):**
```bash
cd web && bun run typecheck && bun run lint && bun run test && bun run build
```

## Backend contract (verified against source — do not re-derive)

Four endpoints, registered at `api/role_assignments.go:15-22` on the
vault-scoped subrouter (`api/api.go:106-107`):

| Method | Path | Source | Success |
|---|---|---|---|
| `GET` | `/api/v1/vaults/{vault_name}/role-assignments` | `api/role_assignments.go:18` | `{"role_assignments":[…],"total":n}` (`model/role_assignment.go:68-71`) |
| `POST` | `/api/v1/vaults/{vault_name}/role-assignments` | `api/role_assignments.go:19` | **201** + one `RoleAssignmentResponse` (`:112`) |
| `GET` | `…/role-assignments/{assignment_id}` | `api/role_assignments.go:20` | one `RoleAssignmentResponse` |
| `DELETE` | `…/role-assignments/{assignment_id}` | `api/role_assignments.go:21` | `{"status":"OK"}` (`:237`) |

`{assignment_id}` matches `[A-Fa-f0-9-]+` (`api/api.go:107`) — UUIDs only.

**Grant body** (`model.AssignRoleRequest`, `model/role_assignment.go:24-28`):
`principal` (a username **or** a UUID; the server resolves it — `:23`),
`principal_type` (optional, `"user"` or `"service_account"` per
`model/access_policy.go:15-16`, defaulting to `"user"` at
`api/role_assignments.go:85-88`), and `role`. Nothing else: there is no
expiry, no condition, no description field.

**Response** (`model.RoleAssignmentResponse`, `model/role_assignment.go:36-46`):
`id`, `principal_id`, `principal_username` (omitempty), `principal_type`,
`role`, `vault_id`, `vault_name` (omitempty), `created_at`,
`expanded_policy_count` (omitempty).

Error mapping on grant (`api/role_assignments.go:99-111`): `ErrInvalidRole` →
**400** `"role"`; `ErrPrincipalNotFound` → **404** `"principal"`;
`ErrRoleNotGrantable` → **403** `"role not grantable by a non-admin caller"`.
On revoke (`:227-236`): `ErrAssignmentNotFound` → **404**;
`ErrRoleNotGrantable` → **403** `"role not revocable by a non-admin caller"`.
An authorization failure on any of the four → **403**
`"admin, vaults/manage, or Key Vault Data Access Administrator required"`
(`:71`, `:138`, `:176`, `:217`).

### The authorization model, precisely

All four handlers call the same primitive,
`authorization.CanManageRoleAssignments`
(`internal/services/authorization/vault_authz.go:98-131`), which admits three
authorities and fails closed otherwise:

1. **Global `admin` account role** — short-circuits to allow (`:99-101`).
2. **A vault-scoped `vaults:manage` access-policy allow** on *this* vault
   (`:108-119`). A global (`vault_id NULL`) allow no longer satisfies this as
   of v4.6.0 — only a global *deny* still matches, and it wins outright.
3. **A `Key Vault Data Access Administrator` role assignment in this vault**
   (`:121-130`), whose entire grant is
   `{ActionRoleAssignmentsWrite, ActionRoleAssignmentsDelete}` and **no data
   action on any secret, key, or certificate** (`model/azure_roles.go:210-212`,
   and the role's own doc comment at `:145-148`). This is the delegation the
   spec's Journey F is about, and the one thing the UI copy must make legible:
   the holder administers access without being able to read anything.

Oddity worth knowing, not worth surfacing: reading (list/get) and revoking
both check `ActionRoleAssignmentsDelete` while only granting checks
`ActionRoleAssignmentsWrite` (`vault_authz.go:124-127` — `write=false` maps to
the delete action). Data Access Administrator holds both, so no caller can
observe the difference today.

### The eight-role allow-list — the constraint most likely to be got wrong

A caller whose authority comes from holding Data Access Administrator (i.e.
**not** a global admin) may only grant or revoke roles in
`nonAdminGrantableRoles`
(`internal/services/authorization/role_assignment_service.go:36-45`), which is
eight of the eleven:

- Key Vault Administrator
- Key Vault Reader
- Key Vault Secrets User
- Key Vault Secrets Officer
- Key Vault Crypto User
- Key Vault Crypto Officer
- Key Vault Certificates Officer
- Key Vault Crypto Service Encryption User

The three **excluded** are `Key Vault Data Access Administrator` itself,
`Key Vault Purge Operator`, and `Key Vault Certificate User` — mirroring
Azure's ABAC restriction, per the comment at `:19-35`. The restriction is
enforced on **both** paths: `AssignRole` (`:126-128`) and `RevokeAssignment`
(`:193-195`), deliberately, "so a non-global-admin Data Access Administrator
can't sidestep the grant restriction by revoking an assignment they aren't
allowed to create" (`:33-35`). The `CallerIsGlobalAdmin` flag the service
branches on is set by the handler from the session claims
(`api/role_assignments.go:74`, `:220`).

So a Data Access Administrator's view of this screen is: eight roles offered
in the picker, and revoke disabled on rows holding one of the other three.

### Backend gaps this epic must design around

1. **No endpoint enumerates the roles or their permissions.**
   `model.AzureRoleNames()` and `model.AzureRoleDataActions()` are reachable
   only from `rocketvault vault-access roles`
   (`cmd/vault-access/roles.go:28`, `:47`). The webapp must carry its own
   copy of the eleven names, the eight-role allow-list, and the per-role data
   actions, transcribed from `model/azure_roles.go:113-213`. Task 1 pins that
   copy with a test so drift is loud rather than silent.
2. **`expanded_policy_count` is always absent for every Azure role.** It is
   populated from `authzServices.RolePermissions`
   (`api/role_assignments.go:37-39`), and that function returns an empty slice
   for any Azure built-in role by design — "Azure built-in roles are not
   expressed in this legacy permission vocabulary"
   (`internal/services/authorization/roles.go:76-80`). Combined with
   `omitempty`, the field never appears. **Do not render it as a permission
   count**; it would read as "this role grants 0 permissions" for all eleven.
3. **Granting is idempotent and still returns 201.** `AssignRole` returns the
   pre-existing row when the (principal, role, vault) tuple already exists
   (`role_assignment_service.go:139-145`) and the handler writes 201
   unconditionally (`api/role_assignments.go:112`). There is no 409, so a
   duplicate grant is a success with an `id` the list already contains.
4. **The seven legacy role names are rejected on new grants** with a 400 and
   a long message listing the Azure names
   (`role_assignment_service.go:118-125`), but rows created before the P2
   backfill may still hold them and will list fine. A row whose `role` is not
   one of the eleven must render as unrecognised rather than crashing a
   lookup into the hardcoded table.
5. **`principal_username` is best-effort.** Resolution failure is
   deliberately non-fatal so a stale or deleted principal does not block the
   response (`api/role_assignments.go:24-36`). The UI must fall back to
   `principal_id`.
6. **There is no "what can I do in this vault" endpoint.** The caller's own
   capability cannot be pre-checked; the global `admin` claim is the one
   signal available client-side, from the JWT `roles` claim already in session
   state (spec § 2).

## File Structure

New: `src/api/role-assignments.ts` (+ test),
`src/lib/rbac/azure-roles.ts` (+ test — the transcribed role catalogue),
`src/routes/vaults.$vaultName.access.tsx`,
`src/components/access/role-assignment-list.tsx`,
`role-grant-dialog.tsx`, `role-picker.tsx`, `role-permissions-popover.tsx`,
`data-access-admin-notice.tsx`, tests for each.

Modified: `src/components/app-shell/vault-nav.tsx` (add an "Access" item).

## Task 1: The role catalogue, transcribed and pinned

**Files:** Create `src/lib/rbac/azure-roles.ts`,
`src/lib/rbac/azure-roles.test.ts`.

This is a client-side copy of backend truth (gap 1). It is the only place in
the webapp allowed to hold that copy.

- [ ] **Step 1 (failing test):** export `AZURE_ROLES` — the eleven names
      verbatim from `model/azure_roles.go:113-149` — and assert the array has
      exactly eleven entries with those exact strings. The comparison is exact
      on the backend too ("role names are stored verbatim in
      `role_assignments.role`", `model/azure_roles.go:226`), so a typo here is
      a 400 at runtime, not a cosmetic bug.
- [ ] **Step 2 (failing test):** export `NON_ADMIN_GRANTABLE_ROLES` — the
      eight from `role_assignment_service.go:36-45` — and assert that the
      three excluded are exactly `Key Vault Data Access Administrator`,
      `Key Vault Purge Operator`, and `Key Vault Certificate User`. Write the
      assertion on the *exclusion set*, not the inclusion set: it is the
      exclusions that encode the security property, and stating them makes a
      future contributor who widens the list break a test that names why.
  ```ts
  it("excludes exactly the three roles a Data Access Administrator may not grant", () => {
    const excluded = AZURE_ROLES.filter((r) => !NON_ADMIN_GRANTABLE_ROLES.includes(r))
    expect(excluded).toEqual([
      "Key Vault Certificate User",
      "Key Vault Data Access Administrator",
      "Key Vault Purge Operator",
    ])
  })
  ```
- [ ] **Step 3 (failing test):** export `roleSummary(role)` returning a short
      human description per role, and `isKnownRole(role)` returning false for
      a legacy name such as `"secrets-officer"` (gap 4). Assert
      `isKnownRole("secrets-officer") === false`.
- [ ] **Step 4:** Add a file-header comment naming
      `../model/azure_roles.go` and
      `../internal/services/authorization/role_assignment_service.go` as the
      sources, so the next person to touch it knows where truth lives.
- [ ] **Step 5:** Run, confirm failure. Implement. Verification gate. Commit:
      `git commit -S -m "feat(rbac): add the Azure built-in role catalogue"`

## Task 2: Role assignments API module

**Files:** Create `src/api/role-assignments.ts`,
`src/api/role-assignments.test.ts`.

- [ ] **Step 1 (failing tests):** `listRoleAssignments(vault)`,
      `getRoleAssignment(vault, assignmentId)`,
      `grantRole(vault, {principal, principalType?, role})`, and
      `revokeRoleAssignment(vault, assignmentId)`, each against the paths in
      the contract table. Types transcribed from
      `model/role_assignment.go:24-46` — no invented fields, and
      `expanded_policy_count` typed as optional and marked deprecated-in-effect
      per gap 2.
- [ ] **Step 2 (failing test):** `grantRole` omits `principal_type` entirely
      when the caller did not choose one, rather than sending `"user"` — the
      server already defaults it (`api/role_assignments.go:85-88`) and an
      omitted optional is the convention Epic 01 Task 2 established.
- [ ] **Step 3:** Run, confirm failure. Implement using `client.ts`'s
      `request()`. Verification gate. Commit:
      `git commit -S -m "feat(api): add role-assignments module"`

## Task 3: Assignment list

**Files:** Create `src/routes/vaults.$vaultName.access.tsx`,
`src/components/access/role-assignment-list.tsx`,
`role-permissions-popover.tsx`, tests.

- [ ] **Step 1 (failing test):** `<RoleAssignmentList>` renders a `table.tsx`
      of principal, principal type, role, and granted-at from
      `listRoleAssignments`. Principal shows `principal_username` when
      present and falls back to `principal_id` when absent (gap 5) — assert
      both branches. Headers and role badges use `font-heading`.
- [ ] **Step 2 (failing test):** the row renders **no** permission count.
      Assert `expanded_policy_count` is not rendered even when a mocked
      response includes it, and that a `hover-card.tsx` /
      `<RolePermissionsPopover>` shows the role's data actions from Task 1's
      catalogue instead (gap 2).
- [ ] **Step 3 (failing test):** a row whose `role` is not in the catalogue
      (e.g. the legacy `"secrets-officer"`) renders as an unrecognised-role
      badge with an explanatory tooltip — it grants no data-plane access
      (`internal/services/authorization/roles.go:110-115`) — rather than
      throwing on an undefined lookup (gap 4).
- [ ] **Step 4 (failing test):** an empty list renders `empty.tsx` reading
      "No one has been granted a role in this vault", with the grant CTA — not
      a bare table.
- [ ] **Step 5 (failing test):** a **403** renders an access-denied state
      quoting the three authorities by name: global `admin`, a vault-scoped
      `vaults:manage` policy on *this* vault, or a
      `Key Vault Data Access Administrator` assignment in *this* vault. The
      copy must say **vault-scoped** for the second — a global
      `vaults:manage` allow does not satisfy a concrete-vault decision
      (`internal/services/authorization/vault_authz.go:108-119`), and copy
      that says plain "vaults:manage" will send an operator hunting a
      permission they already hold.
- [ ] **Step 6:** Run, confirm failure, implement, verification gate. Commit:
      `git commit -S -m "feat(access): add role assignment list"`

## Task 4: Grant dialog with a grantable-only role picker

**Files:** Create `src/components/access/role-grant-dialog.tsx`,
`role-picker.tsx`, tests.

- [ ] **Step 1 (failing test):** `<RoleGrantDialog>` submits `principal`
      (free text, accepting a username or a UUID — say so in the field's
      helper text, per `model/role_assignment.go:23`), an optional
      `principal_type` (`radio-group.tsx`: user / service_account), and a
      `role`, to `grantRole`. On success it invalidates the list query.
- [ ] **Step 2 (failing test):** `<RolePicker>` takes a
      `callerIsGlobalAdmin` prop, derived from the JWT `roles` claim in
      session state (the one capability signal available client-side, gap 6).
      When false it offers **only** `NON_ADMIN_GRANTABLE_ROLES` — eight
      options — and when true it offers all eleven. Assert both counts, and
      assert by name that Data Access Administrator, Purge Operator, and
      Certificate User are absent from the non-admin picker.
  ```tsx
  it("offers only the eight grantable roles to a non-admin delegate", () => {
    render(<RolePicker callerIsGlobalAdmin={false} />)
    expect(screen.getAllByRole("option")).toHaveLength(8)
    expect(
      screen.queryByRole("option", { name: "Key Vault Data Access Administrator" })
    ).not.toBeInTheDocument()
  })
  ```
- [ ] **Step 3 (failing test):** the picker is a *convenience*, not the
      enforcement point — a **403** carrying
      `"role not grantable by a non-admin caller"` still renders the server's
      message on the dialog. The client-side filter can be wrong (a caller may
      be an admin by a path the claim does not reflect, or the allow-list may
      change server-side), so the server's refusal must always be legible.
      Likewise assert a **404** `"principal"` renders as "no such user or
      service account", not as a generic failure, and a **400** `"role"`
      renders on the role field.
- [ ] **Step 4 (failing test):** re-granting an existing (principal, role)
      pair succeeds and does not duplicate a row — the server returns the
      existing assignment with a 201 (gap 3). Assert the dialog closes and
      the list is refetched rather than optimistically appending a second row.
- [ ] **Step 5:** Run, confirm failure, implement using `dialog.tsx`,
      `field.tsx`, `select.tsx`, `radio-group.tsx`. Verification gate.
      Commit: `git commit -S -m "feat(access): add role grant dialog"`

## Task 5: Revoke, with the same eight-role restriction

**Files:** Modify `role-assignment-list.tsx`, tests.

- [ ] **Step 1 (failing test):** each row has a revoke action behind
      `alert-dialog.tsx` calling `revokeRoleAssignment`, naming the principal
      and role in the confirm copy.
- [ ] **Step 2 (failing test):** when `callerIsGlobalAdmin` is false, rows
      holding one of the three non-grantable roles render revoke disabled with
      a tooltip explaining only a global admin may revoke it. The allow-list
      genuinely applies to revoke as well as grant
      (`role_assignment_service.go:193-195`), so a UI that offers revoke on
      every row produces a 403 on exactly the rows a delegate most wants to
      act on.
- [ ] **Step 3 (failing test):** a 403 carrying
      `"role not revocable by a non-admin caller"` surfaces on the row's
      action, not as a page-level error, and leaves the other rows' actions
      enabled — the independent-per-action shape Epic 01 Task 4 established.
- [ ] **Step 4:** Run, confirm failure, implement, verification gate. Commit:
      `git commit -S -m "feat(access): add role assignment revoke"`

## Task 6: Make the Data Access Administrator distinction legible

**Files:** Create `src/components/access/data-access-admin-notice.tsx`, test;
modify `role-picker.tsx`, `role-assignment-list.tsx`.

The spec's Journey F is entirely about this role, and it is the single most
counter-intuitive thing in RocketVault's authorization model: it administers
access to a vault while holding no access to the vault's contents. If the UI
does not say so, the first operator to grant it will assume it is an
"everything" role.

- [ ] **Step 1 (failing test):** `<DataAccessAdminNotice>` renders on the
      access page explaining that `Key Vault Data Access Administrator` is the
      one role that manages *other* principals' role assignments **without
      granting any access to the vault's secrets, keys, or certificates** —
      its complete grant is the two `Microsoft.Authorization/roleAssignments/*`
      actions (`model/azure_roles.go:210-212`). Assert the copy states both
      halves; a notice that only says "manages access" is the misreading this
      task exists to prevent.
- [ ] **Step 2 (failing test):** the role picker's entry for Data Access
      Administrator (visible to a global admin only) carries the same
      two-part description inline, so the distinction is present at the moment
      of the decision rather than only in a page-level banner.
- [ ] **Step 3 (failing test):** the list's empty state, when the caller is
      *not* a global admin, adds a line noting the caller may grant eight of
      the eleven roles and that the remaining three require a global admin —
      naming them. An empty state is where a delegate first arrives, and it is
      the cheapest place to explain the restriction before they hit a 403.
- [ ] **Step 4:** Run, confirm failure, implement using `alert.tsx` and
      `tooltip.tsx`. Verification gate. Commit:
      `git commit -S -m "feat(access): explain the Data Access Administrator boundary"`

## Self-Review

- All four confirmed endpoints have a task, each cited to `file:line`.
- The eight-role allow-list is implemented in the picker (Task 4 Step 2) **and**
  on revoke (Task 5 Step 2), matching the backend's deliberate two-path
  enforcement — a plan that only filtered the picker would have left the
  revoke half broken exactly as the backend comment warns.
- The allow-list is pinned by an exclusion-set test (Task 1 Step 2), so the
  three excluded roles cannot quietly drift into the picker.
- The client-side filter is explicitly not the enforcement point (Task 4
  Step 3) — the server's 403 is still surfaced verbatim.
- `expanded_policy_count` is blocked from the UI by a test (Task 3 Step 2)
  rather than rendered as a misleading zero.
- Access-denied copy says *vault-scoped* `vaults:manage`, matching v4.6.0's
  narrowing, rather than the pre-v4.6.0 wording a reader of older docs would
  write.
- The Data Access Administrator's "manages access, holds none" property has a
  dedicated task (Task 6) rather than being left implicit in a role name.
- No new shadcn component is introduced.
