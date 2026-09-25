# RocketVault Dashboard — Vault Management Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development
> for the multi-task breakdown below, or superpowers:executing-plans if executing
> this plan directly, top to bottom.

**Goal:** Vault lifecycle screens — create, list, view/update settings, soft-delete,
and purge — the entry point every other epic's vault-scoped routes depend on.

**Architecture:** See `docs/superpowers/specs/2026-09-08-webapp-dashboard-epics-design.md`
§§ 2, 6 (Epic 01). Builds on Phase 0's `src/api/client.ts`, `useAuth()`,
`requireAuth`, the `vaults.$vaultName.tsx` layout route, and app-shell nav.

**Tech Stack:** unchanged from foundation (React 19 + TS + TanStack Router/Query
+ Vitest/RTL).

**Conventions to follow:** see foundation plan §Conventions — `@/` alias,
`import type`, `cva`/`cn()`, Prettier, don't edit `src/components/ui/**` in place.

**Verification gate (run before every commit):**
```bash
cd web && bun run typecheck && bun run lint && bun run test && bun run build
```

## File Structure

New: `src/api/vaults.ts` (+ test), `src/routes/vaults.index.tsx` (vault
picker/landing, replaces Task 10 foundation placeholder),
`src/routes/vaults.$vaultName.settings.tsx`, `src/components/vaults/vault-list.tsx`,
`vault-create-dialog.tsx`, `vault-settings-form.tsx`, `vault-danger-zone.tsx`
(delete/purge actions), tests for each.

Modified: `src/components/app-shell/vault-nav.tsx` (add "Settings" nav item).

## Task 1: Verify the vault-recover route shape before building anything that assumes it

**Files:** none (research task, produces a decision recorded in this plan's
Task 4).

- [ ] **Step 1:** Read `/home/numericlabs/Khushali/rocketvault/api/vault.go`
      and `internal/services/vaults/vault_service.go` directly. The CLI has
      `vaults recover <name>`, but the route inventory only confirmed
      create/list/get/update/delete/purge. Determine: is there a dedicated
      route (e.g. `POST /vaults/{name}/recover`), or is recovery folded into
      `PATCH /vaults/{name}` via some field (e.g. `enabled: true` on a
      soft-deleted row)?
- [ ] **Step 2:** Record the finding as a one-line comment at the top of
      `src/api/vaults.ts` (Task 2) so the shape is documented in the code,
      not just this plan. If no recovery path exists at all yet, do not
      build a recover UI — note it as a real backend gap and skip Task 4's
      recover action (ship the rest of this epic without it, don't block on it).

## Task 2: Vaults API module

**Files:** Create `src/api/vaults.ts`, `src/api/vaults.test.ts`.

- [ ] **Step 1 (failing tests):** `listVaults(includeDeleted?)` →
      `GET /api/v1/vaults?include_deleted=true` when the flag is set, omitted
      otherwise; `getVault(name)` → `GET /vaults/{name}`; `createVault(input)`
      → `POST /vaults`; `updateVault(name, patch)` → `PATCH /vaults/{name}`
      (only send explicitly-changed fields, mirroring the CLI's "only
      explicitly-passed flags applied" behavior — write a test asserting an
      unset field is omitted from the request body, not sent as `null`/`""`);
      `deleteVault(name)` → `DELETE /vaults/{name}`; `purgeVault(name)` →
      `DELETE /vaults/{name}/purge`; plus whatever Task 1 determined for recovery.
- [ ] **Step 2:** Run, confirm failure.
- [ ] **Step 3:** Implement using `client.ts`'s `request()`.
- [ ] **Step 4:** Verification gate. Commit: `git commit -S -m "feat(api): add vaults module"`

## Task 3: Vault picker / landing page

**Files:** Create `src/routes/vaults.index.tsx`, `src/components/vaults/vault-list.tsx`,
`vault-create-dialog.tsx`, and tests.

- [ ] **Step 1 (failing test):** `<VaultList>` renders one row per vault from
      `listVaults()` (via TanStack Query), each row links to
      `/app/vaults/:name/secrets` (the default tab per foundation Task 10);
      an empty result renders `empty.tsx` with a "Create your first vault"
      CTA, not a bare blank table.
- [ ] **Step 2:** Failing test for `<VaultCreateDialog>`: submits name +
      optional tags to `createVault`, on success invalidates the vaults
      query and navigates to the new vault.
- [ ] **Step 3:** Run, confirm failure. Implement using `table.tsx`,
      `dialog.tsx`, `empty.tsx`, `button.tsx`. Page title uses `font-heading`
      per the design system.
- [ ] **Step 4:** Verification gate. Commit:
      `git commit -S -m "feat(vaults): add vault picker and create dialog"`

## Task 4: Vault settings page

**Files:** Create `src/routes/vaults.$vaultName.settings.tsx`,
`src/components/vaults/vault-settings-form.tsx`, `vault-danger-zone.tsx`, tests.

- [ ] **Step 1 (failing test):** `<VaultSettingsForm>` pre-fills from
      `getVault(name)`, submits only changed fields to `updateVault` (per
      Task 2's partial-update contract).
- [ ] **Step 2 (failing test):** `<VaultDangerZone>` renders a "Delete vault"
      action (blocked/hidden for the default vault, matching the backend's
      protection — assert this via a test with `vaultName="default"`) behind
      `alert-dialog.tsx`, and a SEPARATE "Purge vault" action. **Critical:
      these two actions are gated by different permissions** — delete uses
      `CanManageVault`, purge uses a distinct vault data-action
      (`ActionVaultPurge`, effectively requiring a Purge Operator/
      Administrator role on that specific vault). Do not show/hide both
      buttons based on one shared permission signal; each action attempts
      its call and surfaces its own 403 via the shared `ApiError` handling
      from the foundation — write a test asserting a 403 from `purgeVault`
      renders an access-denied message without also hiding the (still
      permitted) delete button.
  ```tsx
  // vault-danger-zone.test.tsx (excerpt)
  it("surfaces a 403 from purge independently of delete's permission", async () => {
    vi.mocked(purgeVault).mockRejectedValue(new ApiError({ status_code: 403, message: "forbidden" }))
    render(<VaultDangerZone vaultName="prod" />)
    await userEvent.click(screen.getByRole("button", { name: /purge vault/i }))
    await userEvent.click(screen.getByRole("button", { name: /confirm/i }))
    expect(await screen.findByText(/don't have permission to purge/i)).toBeInTheDocument()
    expect(screen.getByRole("button", { name: /delete vault/i })).toBeEnabled()
  })
  ```
- [ ] **Step 3:** If Task 1 confirmed a recover path, add a recover action
      here too (or on a "Deleted Vaults" view under `/app/vaults` if listing
      soft-deleted vaults proves more natural); if Task 1 found no
      confirmed path, skip this and note it in Self-Review as deferred.
- [ ] **Step 4:** Run, confirm failure, implement, verification gate.
      Commit: `git commit -S -m "feat(vaults): add settings page with delete/purge"`

## Self-Review

- Task 1 resolves the plan's one open unknown (recover route shape) before
  Task 4 needs it — no guessed endpoint shipped.
- Delete vs. purge's distinct authorization is explicitly tested (Task 4),
  not conflated.
- Every screen in the spec's Epic 01 row (list/create/get/update/delete/purge)
  has a corresponding task; recovery is conditional on Task 1's finding,
  documented either way.
