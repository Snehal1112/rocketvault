# RocketVault Dashboard — Service Accounts Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development
> for the multi-task breakdown below, or superpowers:executing-plans if executing
> this plan directly, top to bottom.

**Goal:** Manage RocketVault's OAuth2 client-credentials service accounts —
create, list, view, delete, and rotate the client secret — including the
one-time plaintext-secret display that both create and rotate return.

**Architecture:** See `docs/superpowers/specs/2026-09-08-webapp-dashboard-epics-design.md`
§§ 2, 6 (Epic 08). Global-admin only, entirely under `/app/admin/...`. Builds on
Phase 0's `src/api/client.ts`, `useAuth()`, `requireAuth`, and the admin-mode
app-shell nav.

**Tech Stack:** unchanged from foundation.

**Conventions to follow:** see foundation plan §Conventions — `@/` alias,
`import type`, `cva`/`cn()`, Prettier (no semicolons, double quotes, 80 cols),
`bun run format` after touching class strings, no in-place edits to
`src/components/ui/**`. Design tokens from `web/src/index.css` only: teal
primary (`src/index.css:17` / `:53`), `font-heading` (JetBrains Mono,
`src/index.css:82`) for headings, table headers, badges and — importantly here
— every rendered credential, token and code block; `font-sans` (Noto Sans,
`src/index.css:81`) for body copy; cards `rounded-4xl` (`src/index.css:120`)
with `shadow-md ring-1 ring-foreground/5`. Compose from the 61 already-vendored
shadcn components in `src/components/ui/` (`web/.claude/shadcn-components.md`);
nothing new is needed, so do not run `shadcn add`.

**Verification gate (run before every commit):**
```bash
cd web && bun run typecheck && bun run lint && bun run test && bun run build
```

## Backend contract (verified against Go source — do not re-derive)

This is **RocketVault's own** OAuth2 client-credentials feature
(`internal/services/oauth2/`), not an Azure-shaped API. Routes are registered in
`api/oauth2.go:27-38`; the management subrouter is `/service-accounts`
(`api/api.go:134-135`) with `{service_account_id}` constrained to
`[A-Fa-f0-9-]+`. Status codes below are the ones asserted by
`api/oauth2_handlers_test.go:464-800`.

| Method | Path | Handler | Success | Error cases |
|---|---|---|---|---|
| POST | `/api/v1/service-accounts` | `createServiceAccount` (`api/oauth2.go:191`) | **201** + object incl. one-time `client_secret` (`api/oauth2.go:218-226`) | 400 missing `name` (`:203-206`); 500 service error |
| GET | `/api/v1/service-accounts` | `listServiceAccounts` (`api/oauth2.go:230`) | 200 `{service_accounts: [...], total}` (`:244-247`) | 500 |
| GET | `/api/v1/service-accounts/{id}` | `getServiceAccount` (`api/oauth2.go:251`) | 200 — **bare object, not wrapped** (`:270`) | 400 malformed id; 404 not found (`:265-268`) |
| DELETE | `/api/v1/service-accounts/{id}` | `deleteServiceAccount` (`api/oauth2.go:274`) | **200** `{"status":"OK"}` (`api/api.go:210-212`) — not 204 | 400 malformed id; 500 |
| POST | `/api/v1/service-accounts/{id}/rotate` | `rotateServiceAccountSecret` (`api/oauth2.go:300`) | 200 `{"client_secret": "..."}` (`:322-324`) | 400 malformed id; 500 |
| POST | `/api/v1/oauth2/token` | `tokenHandler` (`api/oauth2.go:53`) | 200 RFC 6749 §5.1 body | **public, unauthenticated** — see below |

Every one of the five management handlers gates on the global `admin` account
role and nothing else (`api/oauth2.go:193-196`, `:232-235`, `:252-255`,
`:275-279`, `:301-305`). As with `/users`, `resolvePolicy`
(`internal/middleware/middleware.go:407-428`) returns an empty
`(resourceType, operation)` pair for `/service-accounts` — it matches none of
`/secrets`, `/keys`, `/certificates`, `/vaults` — so no access policy and no
vault role participates in the decision.

Request and response fields:

- **Create body** is an inline anonymous struct, `{name, description,
  expires_at}` (`api/oauth2.go:198-202`). `name` is required (`:203-206`);
  `expires_at` is `*time.Time`, so RFC 3339 or omitted/`null` for
  non-expiring (`internal/services/oauth2/oauth2_service.go:53`).
- **Create 201 body** is an explicit map: `id`, `name`, `description`,
  `enabled`, `created_at`, `expires_at`, `client_secret`
  (`api/oauth2.go:218-226`).
- **List and get** return `model.OAuth2Client` = `{id, name, client_secret?,
  description, enabled, created_at, expires_at?}` (`model/oauth2_client.go:12-20`).
  The service blanks the stored hash before returning
  (`internal/services/oauth2/oauth2_service.go:155`, `:166`) and the field
  carries `omitempty`, so `client_secret` is simply absent from reads.
- The generated secret is 32 random bytes hex-encoded — a 64-character string
  (`internal/services/oauth2/oauth2_service.go:206-212`). It is bcrypt-hashed
  before storage (`:127-130`) and is unrecoverable after the response.

## Documented gaps and traps (verified; do not design around them)

1. **`client_id` is the service account's `name`, not its UUID.**
   `IssueToken` resolves the caller with `repo.FindByName(ctx, clientName)`
   (`internal/services/oauth2/oauth2_service.go:85`), and `tokenHandler` passes
   the form's `client_id` value straight into it (`api/oauth2.go:91`). The
   credential pair a consumer configures is therefore `(name, secret)`. The UI
   **must** label the name field as the client ID; showing the UUID beside a
   "Client ID" label would send integrators to a credential that never
   authenticates. Names are consequently identity — treat a rename as
   impossible (see gap 2) and warn that the name is the public credential.
2. **There is no update route at all.** `OAuth2Service`
   (`internal/services/oauth2/oauth2_service.go:48-59`) exposes
   `IssueToken`/`CreateClient`/`GetClient`/`ListClients`/`RotateSecret`/
   `DeleteClient` — no `UpdateClient` — and `InitOAuth2` registers no
   PUT or PATCH (`api/oauth2.go:31-36`). So **`name`, `description` and
   `expires_at` are immutable after creation**, and `enabled` can never be
   toggled: it is hardcoded `true` at creation
   (`internal/services/oauth2/oauth2_service.go:137`) and nothing writes it
   again. The field is live at the authorization boundary —
   `IssueToken` refuses a disabled client (`:92-94`) — so it is a real switch
   with no handle. Render `enabled` read-only; delete is the only revocation.
   A `PATCH /service-accounts/{id}` accepting `{enabled, description,
   expires_at}` is the smallest backend addition that would unblock a proper
   disable action.
3. **Two model types exist that no handler uses, and both disagree with the
   wire format.** `model.CreateOAuth2ClientRequest`
   (`model/oauth2_client.go:22-25`) has no `expires_at`, and
   `model.ListOAuth2ClientsResponse` (`model/oauth2_client.go:47-50`) keys the
   array `clients` — while the live list handler emits `service_accounts`
   (`api/oauth2.go:244-247`). Generate the TypeScript types from the handler
   bodies cited above, never from those model structs.
4. **List and get envelopes are inconsistent.** List wraps
   (`{service_accounts, total}`); get returns the bare object
   (`api/oauth2.go:270`). The API module must normalize this rather than
   leaking it into components.
5. **Delete is permanent and immediate, with no soft-delete and no
   confirmation semantics server-side** (`api/oauth2.go:287`,
   `internal/services/oauth2/oauth2_service.go:198-203`). Existing tokens are
   invalidated by the `jti`-as-client-ID design (`oauth2_service.go:104-106`)
   — `ValidateSession` re-checks the client on every request — so deletion is
   effectively instant revocation. Worth saying on screen; it is the one
   genuinely good news item in this list.
6. **No CLI equivalent exists.** Unlike vaults, secrets, keys and
   vault-access, there is no `cmd/service-accounts` package — nothing under
   `cmd/` manages OAuth2 clients. This epic is the **first** interactive
   surface for the feature, which means the backend behaviours above have had
   no CLI exercising them; treat unexpected responses as real findings and
   record them rather than working around them silently.
7. **Token expiry is server-configured, default 30 minutes**
   (`internal/services/oauth2/oauth2_service.go:70-73`), and is not exposed by
   any read endpoint. Do not display a token lifetime you cannot source.
8. **`expires_at` is enforced only at token issuance**
   (`internal/services/oauth2/oauth2_service.go:96-98`), not by a background
   job — an expired account still lists as `enabled: true`. The list UI must
   derive "expired" from the timestamp itself rather than trusting `enabled`.

## File Structure

New: `src/api/service-accounts.ts` (+ test),
`src/routes/admin.service-accounts.index.tsx`,
`src/routes/admin.service-accounts.$serviceAccountId.tsx`,
`src/components/admin/service-accounts/service-account-list.tsx`,
`service-account-create-dialog.tsx`, `service-account-detail.tsx`,
`client-secret-reveal.tsx`, `token-usage-snippet.tsx`, tests for each.

Modified: `src/components/app-shell/admin-nav.tsx` (add "Service Accounts").

## Task 1: Service accounts API module

**Files:** Create `src/api/service-accounts.ts`,
`src/api/service-accounts.test.ts`.

- [ ] **Step 1 (failing tests):** `listServiceAccounts()` →
      `GET /api/v1/service-accounts`, unwrapping `service_accounts`;
      `getServiceAccount(id)` → `GET /api/v1/service-accounts/{id}`, returning
      the **bare** object (gap 4 — assert the module normalizes both shapes to
      one `ServiceAccount` type);
      `createServiceAccount({name, description?, expiresAt?})` →
      `POST /api/v1/service-accounts`;
      `deleteServiceAccount(id)` → `DELETE /api/v1/service-accounts/{id}`;
      `rotateServiceAccountSecret(id)` →
      `POST /api/v1/service-accounts/{id}/rotate`.
- [ ] **Step 2 (failing test — the request body):** assert `expiresAt` is
      omitted from the JSON body entirely when unset, and serialized as an
      RFC 3339 string when set — `*time.Time` decodes `null` and absence
      identically (`api/oauth2.go:201`), but an empty string does not decode.
- [ ] **Step 3 (failing test — the types):** three distinct exported types,
      not one with optional fields: `ServiceAccount` (read shape, **no**
      `client_secret` key at all), `CreatedServiceAccount` (`ServiceAccount` +
      `client_secret: string`), and `RotatedSecret` (`{client_secret: string}`).
      Assert the list mapper strips a `client_secret` that appears in a mocked
      payload, so a future backend change cannot quietly start rendering
      hashes in a table.
- [ ] **Step 4:** Run, confirm failure.
- [ ] **Step 5:** Implement over `client.ts`'s `request()`. Put a header
      comment recording gap 1 — that the OAuth2 `client_id` is `name`, citing
      `internal/services/oauth2/oauth2_service.go:85` — so the fact lives in
      the code, not only in this plan.
- [ ] **Step 6:** Verification gate. Commit:
      `git commit -S -m "feat(api): add service accounts module"`

## Task 2: Service account list

**Files:** Create `src/routes/admin.service-accounts.index.tsx`,
`src/components/admin/service-accounts/service-account-list.tsx`, test.

- [ ] **Step 1 (failing test):** `<ServiceAccountList>` renders a `table.tsx`
      row per account — name (labelled **Client ID**, `font-heading`),
      description, created, expires — linking to the detail route. Empty state
      via `empty.tsx` with a "Create a service account" CTA.
- [ ] **Step 2 (failing test — status is derived, not reported):** an account
      with `enabled: true` and an `expires_at` in the past renders an
      "Expired" badge, because the backend only checks expiry at token
      issuance and never flips `enabled` (gap 8). Assert with a fixed clock.
  ```tsx
  // service-account-list.test.tsx (excerpt)
  it("shows expired for a past expires_at even though enabled is still true", async () => {
    vi.setSystemTime(new Date("2026-09-14T00:00:00Z"))
    vi.mocked(listServiceAccounts).mockResolvedValue([
      { id: "…", name: "ci-runner", enabled: true, expires_at: "2026-01-01T00:00:00Z" },
    ])
    render(<ServiceAccountList />)
    expect(await screen.findByText(/expired/i)).toBeInTheDocument()
  })
  ```
- [ ] **Step 3 (failing test — no disable control):** assert the row renders
      no enable/disable toggle and no rename action. Both are absent from the
      API (gap 2); a disabled-looking control that silently does nothing is
      worse than its absence. `enabled` renders as a read-only badge.
- [ ] **Step 4:** Run, confirm failure, implement, verification gate. Commit:
      `git commit -S -m "feat(admin): add service account list"`

## Task 3: Create dialog + one-time secret reveal

**Files:** Create `service-account-create-dialog.tsx`,
`client-secret-reveal.tsx`, tests.

- [ ] **Step 1 (failing test):** `<ServiceAccountCreateDialog>` takes name
      (required — mirror `api/oauth2.go:203-206`), optional description, and
      an optional expiry via `calendar.tsx` in a `popover.tsx`. Assert the
      form explains that the name **is** the `client_id` and cannot be changed
      afterwards (gaps 1 and 2).
- [ ] **Step 2 (failing test):** on 201 the dialog does not close; it swaps to
      `<ClientSecretReveal clientId={name} secret={client_secret} />`. Assert
      the secret is rendered in `font-heading` inside an `input-group.tsx` with
      a copy button, alongside the `client_id`, and that closing requires an
      explicit "I have stored this secret" acknowledgement
      (`checkbox.tsx` gating the Close button) — not a click-outside dismissal.
- [ ] **Step 3 (failing test — the security property):** after dismissal the
      secret is gone. Re-render the list and the detail page and assert the
      64-character value appears nowhere in the DOM, and that
      `JSON.stringify(localStorage)` does not contain it. The value lives only
      in the mutation result; it is never a query-cache value, a route param,
      or a search param.
- [ ] **Step 4 (failing test — the copy is accurate):** assert the panel says
      the secret cannot be retrieved later and that the recovery path is
      **rotate**, not reveal (`internal/services/oauth2/oauth2_service.go:173-195`).
      `alert.tsx` in the warning tone (`--warning` from foundation Task 8).
- [ ] **Step 5:** Run, confirm failure, implement, verification gate. Commit:
      `git commit -S -m "feat(admin): add service account creation with one-time secret"`

## Task 4: Detail page — rotate, delete, and an accurate integration snippet

**Files:** Create `src/routes/admin.service-accounts.$serviceAccountId.tsx`,
`service-account-detail.tsx`, `token-usage-snippet.tsx`, tests.

- [ ] **Step 1 (failing test):** `<ServiceAccountDetail>` renders id, name
      (as Client ID), description, enabled, created and expires in a
      `rounded-4xl` `card.tsx`. Assert a 404 from `getServiceAccount`
      (`api/oauth2.go:265-268`) renders a not-found state rather than an
      empty card.
- [ ] **Step 2 (failing test — rotate):** "Rotate secret" behind
      `alert-dialog.tsx` whose copy states that the previous secret stops
      working immediately (the old hash is overwritten in place,
      `internal/services/oauth2/oauth2_service.go:189-192`). On success it
      reuses `<ClientSecretReveal>` from Task 3 with the same one-time
      guarantees — assert the reveal component is the same one, not a second
      copy with weaker handling.
- [ ] **Step 3 (failing test — delete):** "Delete" behind `alert-dialog.tsx`
      requiring the account name to be typed to confirm. Assert the copy says
      deletion revokes issued tokens immediately (gap 5,
      `internal/services/oauth2/oauth2_service.go:104-106`) and that a
      successful delete navigates back to the list and invalidates its query.
      The backend returns **200**, not 204 — assert the module treats a JSON
      `{"status":"OK"}` body as success rather than choking on an unexpected
      body.
- [ ] **Step 4 (failing test — the integration snippet):**
      `<TokenUsageSnippet clientId={name} />` renders a copyable curl example
      against `POST /api/v1/oauth2/token`. It must be **exactly** what the
      handler accepts: `Content-Type: application/x-www-form-urlencoded`
      (enforced at `api/oauth2.go:59-63`, a 400 otherwise) and
      `grant_type=client_credentials` (`:70-74`). Assert the snippet contains
      both, that it uses the account's **name** as `client_id` (gap 1), and
      that it renders a `<client-secret>` placeholder rather than any real
      value. Mention that HTTP Basic is also accepted and takes priority over
      the body (`api/oauth2.go:141-157`).
  ```tsx
  // token-usage-snippet.test.tsx (excerpt)
  it("uses the account name as client_id and never a real secret", () => {
    render(<TokenUsageSnippet clientId="ci-runner" />)
    const snippet = screen.getByRole("code").textContent ?? ""
    expect(snippet).toContain("grant_type=client_credentials")
    expect(snippet).toContain("application/x-www-form-urlencoded")
    expect(snippet).toContain("client_id=ci-runner")
    expect(snippet).toContain("<client-secret>")
  })
  ```
- [ ] **Step 5:** Run, confirm failure, implement, verification gate. Commit:
      `git commit -S -m "feat(admin): add service account detail, rotate and delete"`

## Task 5: Admin guard coverage and nav wiring

**Files:** Modify `src/components/app-shell/admin-nav.tsx`; create a guard test.

- [ ] **Step 1 (failing test):** a session without `admin` in its `roles` claim
      is redirected away from `/app/admin/service-accounts` and issues no
      `listServiceAccounts` request — assert the fetch mock was never called.
- [ ] **Step 2 (failing test):** a 403 arriving anyway renders the shared
      access-denied state and is not retried (`client.ts` never refreshes on
      403, spec § 4). Note for the implementer: the backend's 403 here is a
      plain-text `http.Error` from the handler's `SetPermissionError`, so
      assert the UI degrades to its own message when the body is not the
      `common.AppError` JSON envelope.
- [ ] **Step 3:** Add the "Service Accounts" nav item, `font-heading` label,
      matching the existing item shape.
- [ ] **Step 4:** Run, confirm failure, implement, verification gate. Commit:
      `git commit -S -m "feat(admin): wire service accounts into admin nav and guard"`

## Self-Review

- All five management routes in `api/oauth2.go:31-36` have a task. The public
  token endpoint (`api/oauth2.go:28`) is deliberately not called by the app —
  it is surfaced only as a copyable snippet (Task 4 Step 4), because the
  browser holding a service-account secret is precisely what this feature
  exists to avoid.
- Naming was verified rather than assumed: this is RocketVault's own
  client-credentials feature, the wire keys are `service_accounts` /
  `client_secret` / `expires_at`, and the two `model/oauth2_client.go` structs
  that suggest otherwise are unused by any handler (gap 3) — the plan says so
  explicitly so a future implementer does not "fix" the code to match them.
- The single most dangerous detail — that `client_id` is the account **name**
  and not its UUID (`internal/services/oauth2/oauth2_service.go:85`) — is
  recorded in this plan, asserted by a test (Task 4 Step 4), and written into
  the API module as a source comment (Task 1 Step 5), so it survives in three
  places.
- Two absent capabilities (no update/disable, no rename) are handled by
  asserting the controls are **absent** (Task 2 Step 3) rather than rendering
  disabled ones, and the smallest unblocking backend change is named.
- The one-time secret appears on two paths (create and rotate) and both reuse
  one `<ClientSecretReveal>` with a DOM-and-`localStorage` assertion after
  dismissal — tested once, not duplicated with weaker handling.
