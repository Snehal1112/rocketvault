# RocketVault Dashboard — Secrets Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development
> for the multi-task breakdown below, or superpowers:executing-plans if executing
> this plan directly, top to bottom.

**Goal:** Full secrets lifecycle UI — list, create/generate, view (masked,
reveal-on-demand), edit, version history, soft-delete/recover/purge,
import/export, single-item backup/restore.

**Architecture:** See `docs/superpowers/specs/2026-09-08-webapp-dashboard-epics-design.md`
§§ 2, 6 (Epic 02). Builds EXCLUSIVELY against the vault-scoped route shape
(`/api/v1/vaults/{vault_name}/secrets/...`) — never the legacy flat aliases.
Builds on Phase 0's `src/api/client.ts`, `useAuth()`, the
`vaults.$vaultName.tsx` layout route.

**Tech Stack:** unchanged from foundation.

**Conventions to follow:** see foundation plan §Conventions.

**Verification gate:**
```bash
cd web && bun run typecheck && bun run lint && bun run test && bun run build
```

## File Structure

New: `src/api/secrets.ts` (+ test), `src/routes/vaults.$vaultName.secrets.tsx`,
`vaults.$vaultName.secrets.$secretName.tsx`,
`vaults.$vaultName.secrets.deleted.tsx`,
`src/components/secrets/secret-list.tsx`, `secret-create-dialog.tsx`,
`secret-detail.tsx`, `secret-value.tsx` (masked/reveal), `secret-versions.tsx`,
`secret-deleted-list.tsx`, `secret-import-export.tsx`, tests for each.

Modified: `src/components/app-shell/vault-nav.tsx` (add "Secrets" item, already
default per foundation Task 10).

## Task 1: Secrets API module

**Files:** Create `src/api/secrets.ts`, `src/api/secrets.test.ts`.

- [ ] **Step 1 (failing tests):** every confirmed endpoint gets a typed
      function against the vault-scoped path: `listSecrets(vault)`,
      `createSecret(vault, input)`, `getSecret(vault, id)`,
      `updateSecret(vault, id, input)`, `deleteSecret(vault, id)`,
      `generateSecret(vault, input)` (⚠ distinct from any client-side RNG —
      this calls the real server endpoint and results in a stored secret;
      do not add a pure-local "generate password" utility as a substitute),
      `exportSecrets(vault, format)` (returns a blob for download),
      `importSecrets(vault, file)`, `listSecretVersions(vault, id)`,
      `getSecretVersion(vault, id, version)`, `getLatestSecretVersion(vault, id)`,
      `backupSecret(vault, id)`, `restoreSecret(vault, blob)`,
      `listDeletedSecrets(vault)`, `restoreDeletedSecret(vault, id)`,
      `purgeSecret(vault, id)`.
- [ ] **Step 2:** Run, confirm failure. Implement. Verification gate.
      Commit: `git commit -S -m "feat(api): add secrets module"`

## Task 2: Secrets list + create/generate

**Files:** Create `src/routes/vaults.$vaultName.secrets.tsx`,
`src/components/secrets/secret-list.tsx`, `secret-create-dialog.tsx`, tests.

- [ ] **Step 1 (failing test):** `<SecretList>` table (name, tags, enabled,
      updated-at) from `listSecrets`; row click navigates to the detail
      route. `<SecretCreateDialog>` has two tabs (`tabs.tsx`): "Manual value"
      (posts to `createSecret`) and "Generate" (posts to `generateSecret`
      with length/character-set options) — both converge on the same
      success handler (invalidate list query, navigate to the new secret).
- [ ] **Step 2:** Run, confirm failure, implement, verification gate.
      Commit: `git commit -S -m "feat(secrets): add list and create/generate"`

## Task 3: Secret detail — masked value, edit, versions

**Files:** Create `src/routes/vaults.$vaultName.secrets.$secretName.tsx`,
`src/components/secrets/secret-detail.tsx`, `secret-value.tsx`,
`secret-versions.tsx`, tests.

- [ ] **Step 1 (failing test):** `<SecretValue>` renders the value masked
      (`••••••••`) by default; clicking "Reveal" calls `getSecret` (or uses
      already-fetched data) and shows the real value; a "Copy" button copies
      without permanently revealing. Assert the masked state is the initial
      render — a secrets manager should never flash a value unprompted.
  ```tsx
  it("renders the value masked until Reveal is clicked", () => {
    render(<SecretValue value="s3cr3t" />)
    expect(screen.queryByText("s3cr3t")).not.toBeInTheDocument()
    expect(screen.getByText("••••••••")).toBeInTheDocument()
  })
  ```
- [ ] **Step 2 (failing test):** `<SecretVersions>` lists version history
      (metadata) from `listSecretVersions`; selecting a version fetches and
      displays that version's value (masked-by-default too) via
      `getSecretVersion`.
- [ ] **Step 3 (failing test):** edit form updates value/tags/content-type
      via `updateSecret`.
- [ ] **Step 4:** Run, confirm failure, implement using `card.tsx`,
      `tabs.tsx`, `badge.tsx` for tags. Verification gate. Commit:
      `git commit -S -m "feat(secrets): add detail view with masked value and versions"`

## Task 4: Soft-delete, deleted-items tab, import/export, backup/restore

**Files:** Create `src/routes/vaults.$vaultName.secrets.deleted.tsx`,
`src/components/secrets/secret-deleted-list.tsx`,
`secret-import-export.tsx`, tests.

- [ ] **Step 1 (failing test):** delete action behind `alert-dialog.tsx`
      confirm, calls `deleteSecret`, removes row from the active list.
- [ ] **Step 2 (failing test):** `<SecretDeletedList>` shows soft-deleted
      secrets with recover (`restoreDeletedSecret`) and purge
      (`purgeSecret`, separate confirm, `--destructive` styling) actions.
- [ ] **Step 3 (failing test):** `<SecretImportExport>` — export button
      triggers a file download for JSON and CSV (assert the correct MIME/
      filename per format); import accepts a file upload and posts to
      `importSecrets`, surfacing per-row success/failure if the API returns
      that detail (verify the response shape against `api/secrets.go` before
      assuming a per-row result exists).
- [ ] **Step 4:** Run, confirm failure, implement, verification gate.
      Commit: `git commit -S -m "feat(secrets): add soft-delete recovery, import/export"`

## Self-Review

- All 16 confirmed endpoints (13 core + 3 deleted-recovery) have a task.
- `generateSecret` vs. a client-only RNG utility is explicitly disambiguated
  (Task 1) so no one accidentally reimplements the CLI's local-only
  `generate-password` behavior here.
- Masked-by-default is enforced by an actual test (Task 3), not just UI copy.
