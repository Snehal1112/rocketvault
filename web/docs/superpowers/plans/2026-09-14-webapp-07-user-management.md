# RocketVault Dashboard — User Management Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development
> for the multi-task breakdown below, or superpowers:executing-plans if executing
> this plan directly, top to bottom.

**Goal:** Global-admin user administration — create, list, view, update, delete
local user accounts — plus the one-time TOTP enrollment display shown at
creation, rendered so a new user can actually finish MFA setup from the browser.

**Architecture:** See `docs/superpowers/specs/2026-09-08-webapp-dashboard-epics-design.md`
§§ 2, 6 (Epic 07). Lives entirely under the `/app/admin/...` branch, whose guard
is checkable client-side from the JWT-derived `roles` claim already in session
state (spec § 2). Builds on Phase 0's `src/api/client.ts`, `useAuth()`,
`requireAuth`, and the admin-mode app-shell nav.

**Tech Stack:** unchanged from foundation (React 19 + TS + TanStack Router/Query
+ Vitest/RTL).

**Conventions to follow:** see foundation plan §Conventions — `@/` alias,
`import type`, `cva`/`cn()`, Prettier (no semicolons, double quotes, 80 cols),
`bun run format` after touching class strings, and do not edit
`src/components/ui/**` in place. Design tokens come from `web/src/index.css`
only: teal primary (`--primary` at `src/index.css:17` light / `:53` dark),
`font-heading` (JetBrains Mono Variable, `src/index.css:82`) for page titles,
section headings, table headers, badges and any rendered secret/URI text;
`font-sans` (Noto Sans Variable, `src/index.css:81`) for body copy and form
values; cards use `rounded-4xl` (`--radius-4xl`, `src/index.css:120`) with
`shadow-md ring-1 ring-foreground/5`. Compose from the 61 already-vendored
shadcn components in `src/components/ui/` (inventory:
`web/.claude/shadcn-components.md`) — every component this epic needs is already
there, so do not run `shadcn add`.

**Verification gate (run before every commit):**
```bash
cd web && bun run typecheck && bun run lint && bun run test && bun run build
```

## Backend contract (verified against Go source — do not re-derive)

Routes are registered in `api/users.go:50-68` under the `/users` subrouter
(`api/api.go:112-113`); `{user_id}` is constrained to `[A-Fa-f0-9-]+`
(`api/api.go:113`), so a non-UUID-shaped path segment 404s at the router before
any handler runs.

| Method | Path | Handler | Gate | Success |
|---|---|---|---|---|
| POST | `/api/v1/users` | `createUser` (`api/users.go:74`) | `admin` only (`api/users.go:75-78`) | **201** + `model.UserResponse` **including `totp_secret`** (`api/users.go:126-136`) |
| GET | `/api/v1/users` | `listUsers` (`api/users.go:143`) | `admin` only (`api/users.go:145-148`) | 200 `{users: [...], total}` (`model/user.go:136-139`) |
| GET | `/api/v1/users/{user_id}` | `getUser` (`api/users.go:199`) | `admin` **or self** (`api/users.go:209-212`) | 200 `model.UserResponse`, **no `totp_secret`** |
| PUT | `/api/v1/users/{user_id}` | `updateUser` (`api/users.go:240`) | `admin` **or self** (`api/users.go:276-286`) | 200 `model.UserResponse` |
| DELETE | `/api/v1/users/{user_id}` | `deleteUser` (`api/users.go:351`) | `admin` only (`api/users.go:353-356`) | 200 `{"status":"OK"}` (`api/api.go:210-212`) |

Field shapes (`model/user.go`):

- `UserResponse` = `{id, username, roles[], created_at, totp_secret?}`
  (`model/user.go:123-129`). `totp_secret` carries `omitempty` (`:128`) and is
  populated on the create path only.
- `CreateUserRequest` = `{username, password, roles[]}` (`model/user.go:93-101`).
- `UpdateUserRequest` = `{username?, password?, roles?}` (`model/user.go:108-116`).
- A legacy singular `"role"` string in either body is **rejected with 400**, not
  ignored (`api/users.go:89-92` and `:256-259`) — always send `roles: [...]`.
- `model.ValidRoles` = `admin`, `secrets_manager`, `crypto_manager`,
  `certificate_manager`, `user` (`model/user.go:53`). `service_account` and
  `system` are deliberately excluded (`model/user.go:47-52`) — never offer them.

Validation and error mapping:

- username 3–50 chars → 400 (`api/users.go:94-97`, `:262-265`).
- password ≥ 8 chars → 400 (`api/users.go:98-101`, `:266-269`).
- an unknown role or an empty `roles` array surfaces as **400**, not 500 — the
  handler string-matches `"invalid role"` / `"role is required"` out of the
  service error (`api/users.go:118-121`, `:319-322`).
- self-deletion is blocked with **400**, not 403 (`api/users.go:363-367`).
- a non-admin sending `roles` on their own profile gets **403 "cannot change
  own role"** (`api/users.go:282-285`).

Authorization layering: `resolvePolicy` (`internal/middleware/middleware.go:407-428`)
returns an empty `(resourceType, operation)` pair for any path that contains
none of `/secrets`, `/keys`, `/certificates`, `/vaults` — `/users` is one of
them. So **no access policy and no vault role touches these routes**; the
handler's own `common.HasAnyRole(c.Claims.Roles, model.RoleAdmin)` is the
single gate. That is exactly what makes the client-side `/app/admin` guard
honest here.

**TOTP enrollment — the API does return it, and it is a full `otpauth://` URI.**
`UserService.CreateUser` stores `totpKey.Secret()` (the raw base32) on the row
but returns `totpKey.URL()` in the result
(`internal/services/users/user_service.go:194` vs `:210`), and the handler
copies that straight into `UserResponse.TOTPSecret` (`api/users.go:131`). The
key is produced by `totp.Generate` with 20-byte secret, 30s period, 6 digits,
SHA1 (`internal/services/auth/totp_service.go:41-45`, `:60-66`). So
`POST /api/v1/users`'s 201 body carries a complete provisioning URI of the form
`otpauth://totp/PasswordManager:<username>?secret=<base32>&issuer=PasswordManager`
— everything a QR needs, client-side, with no extra endpoint. This is **not**
CLI-only; the CLI merely prints the same string (`cmd/users/create.go:106`).

## Documented gaps (verify before assuming otherwise; do not build around them)

Recorded in the spec's own § Deferred style — these are real backend limits
found while verifying, not things this epic fixes.

1. **The TOTP issuer is hardcoded to `"PasswordManager"`**
   (`internal/services/users/user_service.go:183`). Authenticator apps will
   list the entry under that legacy name, not "RocketVault". The UI must not
   pretend otherwise — render the URI's own issuer, never a hand-written
   "RocketVault" label next to it.
2. **There is no TOTP reset / re-enrollment endpoint.** `UpdateUserRequest`
   carries only username/password/roles (`model/user.go:108-116`) and
   `getUser` never sets `TOTPSecret`. A user who loses their authenticator
   cannot be recovered through the API — the account must be deleted and
   recreated. Say this in the enrollment screen's copy; it is the whole reason
   the one-time display has to be taken seriously.
3. **There is no user enable/disable flag.** `model.User`
   (`model/user.go:13-26`) has no `enabled` field, so "suspend this account"
   does not exist — delete is the only off switch. Do not render a status
   toggle.
4. **`auth_provider` and `external_idp_subject` exist on `model.User`
   (`model/user.go:19-24`) but are absent from `UserResponse`
   (`model/user.go:123-129`).** The webapp therefore cannot distinguish an
   OIDC-provisioned user (who has no usable local password) from a local one.
   Do not invent a "Local / SSO" column. Adding those two fields to
   `UserResponse` is a zero-schema-change backend addition that would unblock
   it.
5. **First-admin bootstrap stays CLI-only** (`cmd/users/admin.go`, spec
   § Deferred). Nothing in this epic can perform first-run setup.
6. **`created_at` on the create response is `time.Now()` at response-build
   time, not the persisted value** (`api/users.go:130`). Harmless, but do not
   treat the create response as authoritative for timestamps — refetch.
7. **Pagination is applied in memory after loading every user**
   (`api/users.go:161-174`); `total` is the pre-slice count (`:162`).
   `per_page` defaults to 60 and is capped at 200 (`api/params.go:30-31`).
   Fine at current scale, worth knowing before adding an infinite-scroll UX.

## File Structure

New: `src/api/users-admin.ts` (+ test) — named to avoid colliding with the
foundation's `src/api/auth.ts` login/refresh module, which already owns
`/users/login` and `/users/refresh`; `src/routes/admin.users.index.tsx`,
`src/routes/admin.users.$userId.tsx`,
`src/components/admin/users/user-list.tsx`, `user-create-dialog.tsx`,
`user-detail.tsx`, `user-roles-field.tsx`, `totp-enrollment-panel.tsx`, and a
test per component.

Modified: `src/components/app-shell/admin-nav.tsx` (add the "Users" item).

## Task 1: Decide how the TOTP URI is rendered, before building the panel

**Files:** none (decision task; the outcome is recorded as a comment at the top
of `src/components/admin/users/totp-enrollment-panel.tsx` in Task 4).

- [ ] **Step 1:** Confirm by reading, not by assuming: none of the 61 vendored
      components in `src/components/ui/` renders a QR code
      (`web/.claude/shadcn-components.md`), and `web/package.json` has no QR
      dependency today.
- [ ] **Step 2:** Choose one and write the reason down:
      - **(a) Recommended — add a QR renderer.** `bun add qrcode` +
        `bun add -d @types/qrcode`, draw into a `<canvas>` from the
        `otpauth://` URI. This is a real dependency addition: it changes
        `package.json`/`bun.lock` and must be its own reviewable commit, not
        folded into a feature commit.
      - **(b) No-dependency fallback.** Show the `otpauth://` URI and the
        `secret` query parameter parsed out of it, each with a copy button.
        Every authenticator app supports manual secret entry, so this ships a
        complete, usable enrollment flow with zero new dependencies.
      Either way the rest of this epic is unchanged — Task 4's panel takes the
      URI string as its only input.
- [ ] **Step 3:** Whichever is chosen, the URI must never be sent anywhere:
      no logging, no analytics, no query string, no `localStorage`. It is
      equivalent to a password.

## Task 2: Users admin API module

**Files:** Create `src/api/users-admin.ts`, `src/api/users-admin.test.ts`.

- [ ] **Step 1 (failing tests):** `listUsers({page, perPage})` →
      `GET /api/v1/users?page=&per_page=`, returning `{users, total}`;
      `getUser(id)` → `GET /api/v1/users/{id}`; `createUser(input)` →
      `POST /api/v1/users`; `updateUser(id, patch)` →
      `PUT /api/v1/users/{id}`; `deleteUser(id)` → `DELETE /api/v1/users/{id}`.
- [ ] **Step 2 (failing test — the request body contract):** assert
      `createUser` sends `roles: string[]` and **never** a singular `role`
      key, because the backend 400s on it rather than ignoring it
      (`api/users.go:89-92`). Assert `updateUser` omits unset fields entirely
      rather than sending `""` — the handler treats empty string as "not
      provided" (`api/users.go:294-300`), so `""` is merely wasteful, but a
      `null` would fail JSON decoding into `string` and 400.
- [ ] **Step 3 (failing test — the type):** `CreatedUser` (the 201 shape)
      carries `totp_secret: string`; `User` (the read shape) does **not** have
      it at all. Two distinct exported types, not one optional field — that is
      what stops a later refactor from leaking the enrollment URI into a list
      row. Assert with a type-level test plus a runtime test that the list
      mapper drops any `totp_secret` present in a mocked payload.
- [ ] **Step 4:** Run, confirm failure.
- [ ] **Step 5:** Implement over `client.ts`'s `request()`. Export
      `VALID_ROLES = ["admin", "secrets_manager", "crypto_manager",
      "certificate_manager", "user"] as const` with a comment citing
      `model/user.go:53`.
- [ ] **Step 6:** Verification gate. Commit:
      `git commit -S -m "feat(api): add users admin module"`

## Task 3: User list + create dialog

**Files:** Create `src/routes/admin.users.index.tsx`,
`src/components/admin/users/user-list.tsx`, `user-create-dialog.tsx`,
`user-roles-field.tsx`, and tests.

- [ ] **Step 1 (failing test):** `<UserList>` renders one row per user from
      `listUsers()` via TanStack Query — username, roles as `badge.tsx` chips
      (`font-heading`), created date via `date-fns`, each row linking to
      `/app/admin/users/$userId`. Table headers use `font-heading`; values use
      `font-sans`. An empty result renders `empty.tsx`, not a bare table.
      Pagination via `pagination.tsx` driven by the `total` field.
- [ ] **Step 2 (failing test):** `<UserRolesField>` is a multi-select over
      `VALID_ROLES` (`checkbox.tsx` inside `field.tsx`, or `combobox.tsx` with
      chips). Assert it offers exactly the five valid roles and **never**
      `service_account` or `system` — those are excluded on purpose
      (`model/user.go:47-52`) and offering them would produce a guaranteed 400.
      Assert submitting with zero roles selected is blocked client-side with
      the same wording the server uses ("at least one role is required"), so
      the two layers do not disagree.
- [ ] **Step 3 (failing test):** `<UserCreateDialog>` (`dialog.tsx`) validates
      username 3–50 and password ≥ 8 before submit, mirroring
      `api/users.go:94-101`, and surfaces a server-side 400's `message`
      verbatim when client validation passes but the server still refuses.
  ```tsx
  // user-create-dialog.test.tsx (excerpt)
  it("surfaces the server's role error verbatim rather than a generic failure", async () => {
    vi.mocked(createUser).mockRejectedValue(
      new ApiError({ status_code: 400, message: "invalid role: operator" })
    )
    render(<UserCreateDialog />)
    await fillValidUser()
    await submitForm()
    expect(await screen.findByText(/invalid role: operator/i)).toBeInTheDocument()
  })
  ```
- [ ] **Step 4:** Run, confirm failure, implement, verification gate. Commit:
      `git commit -S -m "feat(admin): add user list and create dialog"`

## Task 4: TOTP enrollment panel (one-time display)

**Files:** Create `src/components/admin/users/totp-enrollment-panel.tsx`, test.
Modify `user-create-dialog.tsx` to hand off to it.

- [ ] **Step 1 (failing test):** on a successful create, the dialog does **not**
      close — it swaps to `<TotpEnrollmentPanel uri={...} username={...} />`.
      Assert the panel renders the QR (or, under Task 1 option (b), the URI and
      its parsed `secret` parameter) plus copy buttons, and that dismissing it
      requires an explicit acknowledgement (`checkbox.tsx` "I have saved this"
      gating the Close button) rather than a click-outside.
- [ ] **Step 2 (failing test — the security property):** assert the panel is
      unreachable after dismissal. Re-render the list, open the same user's
      detail page, and assert no `otpauth://` substring appears anywhere in the
      document. The value exists only in the create mutation's result and is
      never written to a query cache key, `localStorage`, or the URL.
  ```tsx
  // totp-enrollment-panel.test.tsx (excerpt)
  it("never persists the enrollment URI anywhere recoverable", async () => {
    render(<UserCreateDialog />)
    await fillValidUser()
    await submitForm()
    expect(await screen.findByText(/otpauth:\/\//)).toBeInTheDocument()
    await acknowledgeAndClose()
    expect(document.body.textContent).not.toMatch(/otpauth:\/\//)
    expect(JSON.stringify(localStorage)).not.toMatch(/otpauth:\/\//)
  })
  ```
- [ ] **Step 3 (failing test — the copy is accurate):** the panel states that
      this is the only time the secret is shown and that there is **no reset
      endpoint** — losing it means deleting and recreating the account (gap 2
      above). Assert that sentence renders. Do not write "you can reset this
      later"; it would be false.
- [ ] **Step 4:** Implement. Render the URI's own issuer as returned; do not
      relabel it "RocketVault" (gap 1). Use `alert.tsx` in a warning tone for
      the one-time notice — `--warning` is added by foundation Task 8.
- [ ] **Step 5:** Run, confirm failure, implement, verification gate. Commit:
      `git commit -S -m "feat(admin): add one-time TOTP enrollment panel"`

## Task 5: User detail — view, edit, delete

**Files:** Create `src/routes/admin.users.$userId.tsx`,
`src/components/admin/users/user-detail.tsx`, test.

- [ ] **Step 1 (failing test):** `<UserDetail>` renders id, username, roles and
      created date from `getUser(id)` in a `rounded-4xl` `card.tsx`. Assert it
      renders no MFA status, no enabled/disabled control, and no auth-provider
      column — none of those exist in the response (gaps 3 and 4), and a
      placeholder would read as broken rather than absent.
- [ ] **Step 2 (failing test):** inline edit submits only changed fields to
      `updateUser`. Changing the password is a distinct, separately-confirmed
      action from renaming or re-roling — assert a password change alone sends
      `{password}` and nothing else.
- [ ] **Step 3 (failing test — self-deletion):** the Delete action is disabled,
      with an explanatory tooltip, when `userId === session.userId`. The
      backend rejects it with **400** (`api/users.go:363-367`), so also assert
      that a 400 from `deleteUser` renders that message rather than being
      mistaken for a validation error on some field.
- [ ] **Step 4 (failing test — last-admin foot-gun):** the backend has **no**
      last-admin protection: an admin may strip `admin` from the only other
      admin, or delete every admin but themselves. Assert the UI shows a
      confirming `alert-dialog.tsx` naming the consequence whenever the edit
      removes `admin` from a user, and that the dialog copy does not claim the
      server will prevent it — it will not.
- [ ] **Step 5:** Run, confirm failure, implement, verification gate. Commit:
      `git commit -S -m "feat(admin): add user detail with edit and delete"`

## Task 6: Admin route guard coverage and nav wiring

**Files:** Modify `src/components/app-shell/admin-nav.tsx`; create
`src/routes/admin.users.index.test.tsx` guard test.

- [ ] **Step 1 (failing test):** a session whose `roles` claim lacks `admin`
      is redirected away from `/app/admin/users` by the foundation's admin
      guard and never issues a `listUsers` request. Assert the fetch mock was
      not called — a guard that renders the page and merely hides it still
      leaks the 403 and the request.
- [ ] **Step 2 (failing test):** a 403 arriving anyway (role revoked
      mid-session) renders the shared access-denied state from the foundation
      and is **not** retried — `client.ts` never refreshes on 403 (spec § 4).
- [ ] **Step 3:** Add the "Users" item to the admin nav with `font-heading`
      labels, matching the existing nav item shape.
- [ ] **Step 4:** Run, confirm failure, implement, verification gate. Commit:
      `git commit -S -m "feat(admin): wire users into admin nav and guard"`

## Self-Review

- Every route in `api/users.go:50-68` that belongs to this epic
  (create/list/get/update/delete) has a task; `/users/login`, `/users/refresh`
  and the `/users/sessions*` routes are deliberately excluded — they belong to
  Epic 00 and Epic 13 respectively, and are called out here only so a future
  implementer does not add a second client for them.
- The TOTP question the epic brief raised is **answered, not assumed**: the
  REST API does return the enrollment payload, and it is a full `otpauth://`
  URI rather than a bare secret (`internal/services/users/user_service.go:210`).
  The CLI-only claim would have been wrong; the genuine gaps are the hardcoded
  `PasswordManager` issuer and the total absence of a reset path, both
  documented above and both reflected in Task 4's on-screen copy.
- Roles are sourced from `model/user.go:53` rather than guessed, and the two
  deliberately-excluded roles are asserted absent (Task 3 Step 2) instead of
  merely omitted.
- The one-time secret's blast radius is enforced by a test that greps the DOM
  and `localStorage` after dismissal (Task 4 Step 2), not by component intent.
- Four backend absences (no TOTP reset, no enable/disable, no auth-provider in
  the response, no last-admin protection) are each handled by *not* rendering a
  control, with a test asserting the absence — the failure mode this guards
  against is a plausible-looking button that can never work.
