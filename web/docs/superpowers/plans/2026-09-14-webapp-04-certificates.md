# RocketVault Dashboard — Certificates Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development
> for the multi-task breakdown below, or superpowers:executing-plans if executing
> this plan directly, top to bottom.

**Goal:** X.509 certificate lifecycle UI — list, issue (self-signed or
CA-signed, over an existing key), view metadata, edit attributes, certificate
policy (get/set/delete), auto-renewal configuration, single-item
backup/restore, and soft-delete/recover/purge.

**Architecture:** See `docs/superpowers/specs/2026-09-08-webapp-dashboard-epics-design.md`
§§ 2, 6 (Epic 04). Vault-scoped only — build exclusively against
`/api/v1/vaults/{vault_name}/certificates/...`, never the legacy flat
`/api/v1/certificates` aliases (both shapes exist and resolve to the same
handlers: `api/certificates.go:93-98`, but the flat ones silently resolve to
the default vault). Builds on Phase 0's `src/api/client.ts`, `useAuth()`, and
the `vaults.$vaultName.tsx` layout route; reuses Epic 03's `listKeys` for the
key picker.

**Tech Stack:** unchanged from foundation (React 19 + TS strict + TanStack
Router/Query + Vitest/RTL).

**Conventions to follow:** see foundation plan §Conventions — `@/` alias,
`import type` (`verbatimModuleSyntax`), `cva`/`cn()` from `@/lib/utils`,
`data-slot` on component roots, Prettier (no semicolons, double quotes,
2-space, 80 cols; run `bun run format` after touching class strings), and do
not edit `src/components/ui/**` in place — wrap/compose instead.

Design system is fixed by `web/src/index.css`: teal `--primary`
(`oklch(0.476 0.081 184.6)` light / `oklch(0.659 0.114 184.3)` dark), section
titles / table headers / badges in `font-heading` (JetBrains Mono Variable),
body copy and form values in `font-sans` (Noto Sans Variable), cards
`rounded-4xl shadow-md ring-1 ring-foreground/5`. Every component this epic
needs is already among the 61 vendored in `src/components/ui/` — `table.tsx`,
`dialog.tsx`, `alert-dialog.tsx`, `tabs.tsx`, `field.tsx`, `select.tsx`,
`native-select.tsx`, `switch.tsx`, `badge.tsx`, `alert.tsx`, `empty.tsx`,
`tooltip.tsx`, `skeleton.tsx`, `separator.tsx`, `combobox.tsx`. Do not
`shadcn add` anything; check `web/.claude/shadcn-components.md` first if in
doubt.

**Verification gate (run before every commit):**
```bash
cd web && bun run typecheck && bun run lint && bun run test && bun run build
```

## Backend contract (verified against source — do not re-derive)

Twelve endpoints exist, all under `/api/v1/vaults/{vault_name}`:

| Method | Path | Source | Success |
|---|---|---|---|
| `GET` | `/certificates` | `api/certificates.go:105` | `{"certificates":[…]}` (`:82-84`) |
| `POST` | `/certificates` | `api/certificates.go:104` | **201** + `CertificateResponse` (`:237`) |
| `GET` | `/certificates/{certificate_id}` | `api/certificates.go:106` | `CertificateResponse` |
| `PUT` | `/certificates/{certificate_id}` | `api/certificates.go:107` | `CertificateResponse` (read-back) |
| `DELETE` | `/certificates/{certificate_id}` | `api/certificates.go:108` | `{"status":"OK"}` (`:390`) |
| `GET` | `/certificates/{certificate_id}/policy` | `api/certificates.go:111` | `model.CertificatePolicy` |
| `PUT` | `/certificates/{certificate_id}/policy` | `api/certificates.go:112` | **200** + policy (`api/certificate_policy.go:76`) |
| `DELETE` | `/certificates/{certificate_id}/policy` | `api/certificates.go:113` | `{"status":"OK"}` |
| `POST` | `/certificates/{certificate_id}/backup` | `api/backup_item.go:46` | `{"blob":"…"}` (`:254`) |
| `POST` | `/certificates/restore` | `api/backup_item.go:48` | `{"status":"OK"}`; body `{"blob":"…"}` (`:74-76`) |
| `GET` | `/deleted/certificates` | `api/soft_delete.go:415` | `{"deleted_certificates":[…],"total":n}` (`:61-65`) |
| `POST` | `/deleted/certificates/{certificate_id}/restore` | `api/soft_delete.go:416` | `{"id":"…","message":"Certificate recovered successfully"}` (`:72-75`, `:275`) |
| `DELETE` | `/deleted/certificates/{certificate_id}/purge` | `api/soft_delete.go:417` | `{"status":"OK"}` |

Request/response field names, verbatim:

- **Create** (`CreateCertificateAPIRequest`, `api/certificates.go:39-53`):
  `name`, `key_id` (UUID of an existing key), `validity_days`, `tags`,
  `auto_renew`, `renewal_days`, `ca_cert_id` (presence switches to the
  CA-signed path, `:200-211`), `is_ca`, `enabled`, `not_before`,
  `purge_protection`. `ca_key_id` exists in the struct but is explicitly
  **unused** (`:46`) — do not surface it. `name`, `key_id` and a positive
  `validity_days` are required (400 otherwise, `:145-148`).
- **Update** (`UpdateCertificateAPIRequest`, `api/certificates.go:56-65`):
  `name`, `tags`, `auto_renew`, `renewal_days`, `enabled`, `not_before`,
  `purge_protection` — all optional pointers; sending none is a 400
  (`:309-312`). There is **no** `key_id` or `ca_cert_id` on update.
- **Response** (`CertificateResponse`, `api/certificates.go:68-79`): `id`,
  `name`, `user_id`, `created_at`, `tags`, `auto_renew`, `renewal_days`,
  `expires_at`, `enabled`, `not_before`.
- **Policy** (`model/certificate_policy.go:12-49`): request
  `UpsertCertificatePolicyRequest` = `validity_months`, `key_type`,
  `key_size`, `curve`, `subject`, `sans`, `auto_renew`,
  `days_before_expiry`, `issuer_name`; the GET response additionally carries
  `id`, `certificate_id`, `user_id`, `created_at`, `updated_at`.
- **Deleted row** (`deletedCertItem`, `api/soft_delete.go:203-208`): `id`,
  `name`, `deleted_at`, `purge_protection` — note no `created_at`, unlike the
  deleted-secrets row.

Error mapping (`api/errors_certificate.go:18-31`): `ErrCertLifecycleDenied`
→ **403** "certificate is disabled or outside its valid time window";
`ErrCertNotFound` → 404; purge protection (per-certificate, per-vault, or
instance-wide `soft_delete.purge_protection`) → **403**.

Per-vault roles that reach these routes, from `model/azure_roles.go:154-213`:
`Key Vault Certificates Officer` (all eight certificate data actions,
`:196-200`), `Key Vault Administrator` (superset, `:155-167`),
`Key Vault Certificate User` (`ActionCertificatesRead` only, `:204-206`), and
`Key Vault Reader` (also read-only, `:168-172`). Route→action mapping is
`internal/services/authorization/data_actions.go:218-267`; note that
**writing or clearing a policy maps to `certificates/update`**, not a separate
policy action (`:249-255`).

### Backend gaps this epic must design around

1. **There is no HTTP renew endpoint.** `rocketvault certificate renew <id>`
   (`cmd/certificates/renew.go:18-88`) calls `CertificateService.RenewCertificate`
   directly; no route registers it (`api/certificates.go:103-116` is the
   complete list). The authorization mapper *already anticipates* one —
   `internal/services/authorization/data_actions.go:260-263` maps
   `POST certificates/{id}/renew` → `ActionCertificatesCreate` — so the
   plumbing is half-built and the route is simply absent. **Do not ship a
   "Renew now" button.** Ship the auto-renew configuration instead, and say in
   the UI that manual renewal is CLI-only today.
2. **No response anywhere carries the certificate PEM.** `model.Certificate`
   stores `Certificate` and `PrivateKey` (`model/certificate.go:22-23`) but
   `CertificateResponse` has no field for either, and the existing Go REST
   client records the same conclusion:
   "`api.CertificateResponse` carries metadata only, with no PEM and no chain"
   (`internal/vaultapi/certificates.go:15-16`). There is no download-the-cert
   feature to build. Backup (`/backup`) returns an opaque blob, not a PEM.
3. **Two independent auto-renew settings exist and only one is honoured.**
   The renewal scheduler reads the *certificate's own* `auto_renew` /
   `renewal_days` / `expires_at` columns and **does not consult**
   `CertificatePolicy.auto_renew` / `days_before_expiry` — stated explicitly
   at `internal/services/certificates/certificate_service.go:128-134`. The
   scheduler itself only runs when `rotation.certificates.enabled` is set
   (`bootstrap/bootstrap.go:336`), and `GET /api/v1/config`'s `FrontendConfig`
   (`app/app.go:27-31`: `feature_flags`, `public_api_url`, `sentry_dsn`)
   exposes no such flag, so the UI cannot tell whether renewal is actually
   scheduled.
4. **No `GET` for a single soft-deleted certificate.** Keys have
   `getDeletedKey` (`api/soft_delete.go:326-366`); certificates and secrets do
   not (`:383-387` records this as deliberate). The deleted list is the only
   source.
5. **No certificate policy list/status routes.**
   `ListCertificatePolicies` and `ListCertificatesDueForRenewal`
   (`internal/services/certificates/certificate_service.go:123-134`) back
   `certificates rotation-policy list` / `status` in the CLI only.
6. **No certificate versions.** Renewal rewrites the row in place — "there is
   no new certificate ID to record" (`cmd/certificates/renew.go:20-23`). Do
   not build a versions tab by analogy with Epics 02/03.

### Routing note — IDs, not names

Every certificate route matches `{certificate_id:[A-Fa-f0-9-]+}`
(`api/certificates.go:106`), so the API accepts **UUIDs only**; there is no
name lookup. Epics 02/03 named their detail routes `$secretName`/`$keyName`,
but for certificates use **`vaults.$vaultName.certificates.$certificateId`**
and link rows by `id`. (`internal/vaultapi`'s `Resolver()` gets name support by
listing and matching client-side — if that convenience is wanted later it is a
frontend concern, not an API one.)

## File Structure

New: `src/api/certificates.ts` (+ test),
`src/routes/vaults.$vaultName.certificates.tsx`,
`vaults.$vaultName.certificates.$certificateId.tsx`,
`vaults.$vaultName.certificates.deleted.tsx`,
`src/components/certificates/certificate-list.tsx`,
`certificate-create-dialog.tsx`, `certificate-detail.tsx`,
`certificate-attributes-form.tsx`, `certificate-policy-form.tsx`,
`certificate-renewal-card.tsx`, `certificate-deleted-list.tsx`, tests for each.

Modified: `src/components/app-shell/vault-nav.tsx` (add a "Certificates" item
between "Keys" and the vault settings entry).

## Task 1: Certificates API module

**Files:** Create `src/api/certificates.ts`, `src/api/certificates.test.ts`.

- [ ] **Step 1 (failing tests):** one typed function per confirmed endpoint,
      all against the vault-scoped path:
      `listCertificates(vault)`, `createCertificate(vault, input)`,
      `getCertificate(vault, id)`, `updateCertificate(vault, id, patch)`,
      `deleteCertificate(vault, id)`, `getCertificatePolicy(vault, id)`,
      `upsertCertificatePolicy(vault, id, policy)`,
      `deleteCertificatePolicy(vault, id)`, `backupCertificate(vault, id)`,
      `restoreCertificate(vault, blob)`, `listDeletedCertificates(vault)`,
      `recoverCertificate(vault, id)`, `purgeCertificate(vault, id)`.
      Types are transcribed from the table above — **no invented fields**, and
      no `renewCertificate` (gap 1) and no `certificate`/`pem` field (gap 2).
- [ ] **Step 2 (failing test):** `updateCertificate` sends only keys the
      caller explicitly changed. Assert an untouched field is *absent* from
      the JSON body, not sent as `null` — the backend rejects a body with
      every field unset with a 400 (`api/certificates.go:309-312`), so a
      naive "send the whole form" implementation turns a no-op save into a
      confusing server error.
- [ ] **Step 3 (failing test):** `getCertificatePolicy` maps a 404 to `null`
      rather than throwing — "no policy set" and "certificate not found" both
      return 404 here (`api/certificate_policy.go:32-37`), and the UI needs
      "no policy yet" to be an empty state, not an error banner. Mirror
      `internal/vaultapi/certificates.go:178-184`'s handling of exactly this.
- [ ] **Step 4:** Run, confirm failure. Implement using `client.ts`'s
      `request()`. Verification gate. Commit:
      `git commit -S -m "feat(api): add certificates module"`

## Task 2: Certificate list + issue dialog

**Files:** Create `src/routes/vaults.$vaultName.certificates.tsx`,
`src/components/certificates/certificate-list.tsx`,
`certificate-create-dialog.tsx`, tests.

- [ ] **Step 1 (failing test):** `<CertificateList>` renders a `table.tsx`
      with name, tags (`badge.tsx`), enabled, expires-at, and auto-renew
      columns from `listCertificates`; headers use `font-heading`. A row links
      to `/app/vaults/:vaultName/certificates/:id`. An empty result renders
      `empty.tsx` with an "Issue your first certificate" CTA.
- [ ] **Step 2 (failing test):** an expiry within the certificate's own
      `renewal_days` window renders a warning affordance using the
      `--warning` token the foundation plan adds to `src/index.css` — assert
      via an accessible label ("expires in N days"), not a class name.
- [ ] **Step 3 (failing test):** `<CertificateCreateDialog>` submits `name`,
      `key_id`, `validity_days`, `tags`, `auto_renew`, `renewal_days`,
      `is_ca`, `enabled`, `not_before`, `purge_protection`. The key field is a
      `combobox.tsx` populated from Epic 03's `listKeys(vault)` — a
      certificate **must** reference an existing key in the same vault
      (`api/certificates.go:159-163`, and the service requires the key be
      present and owned by the caller). Assert the dialog blocks submit with
      no key selected rather than posting an empty `key_id`.
- [ ] **Step 4 (failing test):** an optional "Sign with a CA certificate"
      field, also a `combobox.tsx` over `listCertificates(vault)` — supplying
      it sets `ca_cert_id` and selects the CA-signed path
      (`api/certificates.go:200-211`); leaving it empty issues self-signed.
      Assert `ca_cert_id` is **omitted**, not sent empty, when unset. Do not
      render a `ca_key_id` field (`api/certificates.go:46` — unused).
- [ ] **Step 5:** Run, confirm failure, implement, verification gate. Commit:
      `git commit -S -m "feat(certificates): add list and issue dialog"`

## Task 3: Certificate detail — attributes, lifecycle-denial handling

**Files:** Create `src/routes/vaults.$vaultName.certificates.$certificateId.tsx`,
`src/components/certificates/certificate-detail.tsx`,
`certificate-attributes-form.tsx`, tests.

- [ ] **Step 1 (failing test):** `<CertificateDetail>` renders the response's
      fields inside `card.tsx` — and renders them from an explicit allow-list
      of keys, so that a response which ever grew a `certificate` or
      `private_key` field (both exist on the domain type,
      `model/certificate.go:22-23`) could not be spread onto the page. Assert
      that a mocked response carrying `private_key` renders nothing
      containing it. Same defense-in-depth shape as Epic 03 Task 3.
- [ ] **Step 2 (failing test):** a **403** from `getCertificate` renders
      "this certificate is disabled or outside its valid time window", not a
      generic permission-denied. This is not a hypothetical: a disabled or
      expired certificate still appears in the list but 403s on read
      (`api/errors_certificate.go:20-21`), so the list→detail transition
      routinely produces a 403 that has nothing to do with the caller's role.
      Distinguish it from a role denial by the server's message, and keep a
      "back to certificates" affordance on the error state.
  ```tsx
  it("explains a lifecycle 403 as a certificate state, not a permission problem", async () => {
    vi.mocked(getCertificate).mockRejectedValue(
      new ApiError({
        status_code: 403,
        message: "certificate is disabled or outside its valid time window",
      })
    )
    render(<CertificateDetail vaultName="prod" certificateId={CERT_ID} />)
    expect(
      await screen.findByText(/disabled or outside its valid time window/i)
    ).toBeInTheDocument()
    expect(screen.queryByText(/don't have permission/i)).not.toBeInTheDocument()
  })
  ```
- [ ] **Step 3 (failing test):** `<CertificateAttributesForm>` edits `name`,
      `tags`, `enabled`, `not_before`, and `purge_protection` via
      `updateCertificate`, sending only changed fields (Task 1 Step 2's
      contract). `key_id` and `ca_cert_id` are rendered read-only with a
      tooltip saying they are fixed at issuance — `ca_cert_id` is "set at
      creation and never changes" (`model/certificate.go:16-18`) and neither
      appears on the update request.
- [ ] **Step 4:** Run, confirm failure, implement, verification gate. Commit:
      `git commit -S -m "feat(certificates): add detail view and attribute editing"`

## Task 4: Auto-renewal configuration and certificate policy

**Files:** Create `src/components/certificates/certificate-renewal-card.tsx`,
`certificate-policy-form.tsx`, tests.

This task exists chiefly to keep a genuinely confusing backend split from
becoming a genuinely confusing UI. Read gap 3 above before writing a line.

- [ ] **Step 1 (failing test):** `<CertificateRenewalCard>` edits the
      certificate's own `auto_renew` (`switch.tsx`) and `renewal_days` via
      `updateCertificate`, and is labelled as *the* setting the renewal
      scheduler acts on
      (`internal/services/certificates/certificate_service.go:128-134`).
- [ ] **Step 2 (failing test):** `<CertificatePolicyForm>` is a separate
      card for `validity_months`, `key_type`, `key_size`, `curve`, `subject`,
      `sans`, `issuer_name`, `auto_renew`, `days_before_expiry` via
      `upsertCertificatePolicy`, with a delete action
      (`deleteCertificatePolicy`) behind `alert-dialog.tsx`. `subject` and
      `validity_months` are the two the CLI treats as required
      (`cmd/certificates/rotation_policy.go:126-129`) — mirror that client-side
      so the user gets a field error rather than a server round trip.
- [ ] **Step 3 (failing test):** the policy form's `auto_renew` /
      `days_before_expiry` controls carry an inline `alert.tsx` stating these
      describe the *re-issuance template* and are **not read by the renewal
      scheduler** — the certificate's own settings in Step 1 are. Assert the
      notice renders whenever the policy's `auto_renew` is on while the
      certificate's `auto_renew` is off, because that combination looks like
      working auto-renewal and is not.
- [ ] **Step 4 (failing test):** the card does **not** render a "Renew now"
      button (gap 1). Instead it renders a short note that manual renewal is
      available only as `rocketvault certificate renew <id>` today. Write the
      test as an explicit negative assertion so a future contributor adding
      the button has to consciously delete a test that says why it isn't there.
  ```tsx
  it("offers no manual renew action — the HTTP route does not exist", () => {
    render(<CertificateRenewalCard vaultName="prod" certificate={CERT} />)
    expect(screen.queryByRole("button", { name: /renew/i })).not.toBeInTheDocument()
    expect(screen.getByText(/rocketvault certificate renew/i)).toBeInTheDocument()
  })
  ```
- [ ] **Step 5:** Run, confirm failure, implement using `tabs.tsx` to sit both
      cards under the detail route. Verification gate. Commit:
      `git commit -S -m "feat(certificates): add renewal config and policy editor"`

## Task 5: Soft-delete, deleted list, backup/restore

**Files:** Create `src/routes/vaults.$vaultName.certificates.deleted.tsx`,
`src/components/certificates/certificate-deleted-list.tsx`, tests.

- [ ] **Step 1 (failing test):** the detail page's delete action sits behind
      `alert-dialog.tsx`, calls `deleteCertificate`, invalidates the list
      query, and navigates back to the list.
- [ ] **Step 2 (failing test):** `<CertificateDeletedList>` renders `id`,
      `name`, `deleted_at`, and `purge_protection` from
      `listDeletedCertificates` (those four fields and no others —
      `api/soft_delete.go:203-208`), with recover (`recoverCertificate`) and
      purge (`purgeCertificate`, separate confirm, `destructive` styling)
      actions. Recover renders the server's `message`
      ("Certificate recovered successfully").
- [ ] **Step 3 (failing test):** a purge attempt on a `purge_protection: true`
      row surfaces the server's 403 verbatim rather than being pre-blocked
      client-side. The flag on the row is only one of three independent
      protections — the certificate's own flag, its vault's, and the
      instance-wide `soft_delete.purge_protection`
      (`internal/services/certificates/certificate_service.go:144-150`) — and
      the last two are invisible to the client, so a client-side guard would
      be wrong in both directions.
- [ ] **Step 4 (failing test):** backup downloads the `{"blob": …}` payload
      from `backupCertificate` as a file; restore uploads a file and posts
      `{"blob": …}` to `restoreCertificate`. Reuse whatever shared
      download/upload component Epics 02/03 extracted; if none exists,
      implement locally and note the duplication for a consolidation pass.
      An invalid blob returns 400 (`api/backup_item.go:281-289`) — assert that
      message is surfaced on the upload control, not as a page-level error.
- [ ] **Step 5:** Run, confirm failure, implement, verification gate. Commit:
      `git commit -S -m "feat(certificates): add soft-delete recovery and backup/restore"`

## Task 6: Access-denied states for the four certificate roles

**Files:** Modify `certificate-list.tsx`, `certificate-detail.tsx`, tests.

- [ ] **Step 1 (failing test):** a 403 whose message is *not* the lifecycle
      text renders a role-oriented empty state naming what is needed:
      `Key Vault Certificates Officer` or `Key Vault Administrator` to issue
      or modify, `Key Vault Certificate User` or `Key Vault Reader` to view
      (role names verbatim from `model/azure_roles.go:115-140`). No client-side
      permission pre-check: the spec's § 2 is explicit that a vault-scoped
      guard cannot be resolved before the first real data call, and no
      endpoint reports the caller's own roles in a vault.
- [ ] **Step 2 (failing test):** a read-only caller who can `GET` but gets a
      403 on `createCertificate` still sees the list — assert the issue
      dialog's failure does not blank the page, the same
      independent-per-action shape Epic 01 Task 4 established for
      delete-vs-purge.
- [ ] **Step 3:** Run, confirm failure, implement, verification gate. Commit:
      `git commit -S -m "feat(certificates): add role-aware access-denied states"`

## Self-Review

- All 12 confirmed endpoints (8 core + 1 backup + 1 restore + 3 deleted-flow,
  counting policy's three as one row each) have a task; each is cited to a
  `file:line` in the contract table rather than assumed.
- The three things a reasonable implementer would otherwise invent are each
  blocked by an explicit test: a "Renew now" button (Task 4 Step 4), a
  certificate PEM download (Task 3 Step 1's allow-list), and a client-side
  purge-protection guard (Task 5 Step 3).
- The certificate-vs-policy auto-renew split is surfaced as UI copy backed by
  a test (Task 4 Step 3), not left for a user to discover by watching a
  certificate expire with auto-renew apparently on.
- Lifecycle 403 is distinguished from authorization 403 (Task 3 Step 2 vs
  Task 6 Step 1) — conflating them would tell a Certificates Officer they
  lack permission when in fact the certificate is simply disabled.
- Route params use `$certificateId`, diverging from Epics 02/03's name-based
  params, because the backend route regex accepts UUIDs only.
- No new shadcn component is introduced; every control named above is already
  vendored.
