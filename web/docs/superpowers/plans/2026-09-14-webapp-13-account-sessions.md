# RocketVault Dashboard — Account & Sessions Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development
> for the multi-task breakdown below, or superpowers:executing-plans if executing
> this plan directly, top to bottom.

**Goal:** Authenticated self-service at `/app/account` — view your own profile,
change your own password, list your active sessions, revoke one or all of them,
and log out. No admin role required by the route itself.

**Architecture:** See `docs/superpowers/specs/2026-09-08-webapp-dashboard-epics-design.md`
§§ 2, 3, 6 (Epic 13) and Journey H (session expiry: silent refresh vs. forced
logout). This route already exists as a placeholder: foundation Task 10, Step 3
created `src/routes/account.tsx` with `<Empty>` content, and foundation Task 9
already links to it from `account-menu.tsx`'s "My sessions" item. This epic
fills that route in.

**⚠ This plan builds ON TOP of the foundation's existing API module — it does
not redefine it.** Foundation Task 4 (`2026-09-08-webapp-00-foundation-scaffold.md`,
lines 170-184) already creates `src/api/auth.ts` with `login`, `refresh`,
`logout`, `listSessions`, `revokeSession(id)`, `revokeAllSessions`, and their
tests. **Do not create a `src/api/sessions.ts`, do not re-declare any of those
five functions, and do not duplicate their tests.** This epic *extends*
`src/api/auth.ts` with the profile calls it lacks (Task 1) and corrects the
`logout` stub's semantics (Task 2), then builds components on top. Read
`src/api/auth.ts` before writing a line — if a function is already there, import
it.

**Tech Stack:** unchanged from foundation.

**Conventions to follow:** see foundation plan §Conventions — `@/` alias,
`import type`, `cva`/`cn()`, Prettier, don't edit `src/components/ui/**` in
place. Design tokens from `src/index.css`: teal `--primary`, `font-heading`
(JetBrains Mono) for titles, session ids, and user agents, `font-sans` for prose
and form values, `rounded-4xl` cards. Vendored components needed — `card.tsx`,
`table.tsx`, `badge.tsx`, `alert.tsx`, `alert-dialog.tsx`, `button.tsx`,
`field.tsx`, `input.tsx`, `separator.tsx`, `empty.tsx`, `item.tsx`,
`skeleton.tsx` — are all present (`web/.claude/shadcn-components.md`). Do not
`shadcn add` anything.

**Verification gate (run before every commit):**
```bash
cd web && bun run typecheck && bun run lint && bun run test && bun run build
```

## Backend contract (verified — do not re-derive)

Verified against `api/users.go`, `api/params.go`, `api/context.go`,
`internal/middleware/middleware.go`, `internal/services/auth/`,
`internal/services/authorization/rbac_service.go`, `model/user.go`,
`model/session.go`, and `cmd/users/`.

| Method | Path | Registration | Auth |
|---|---|---|---|
| POST | `/api/v1/users/login` | `api/users.go:54` | public |
| POST | `/api/v1/users/refresh` | `api/users.go:55` | public |
| GET | `/api/v1/users/sessions` | `api/users.go:58` | `ApiSessionRequired` |
| DELETE | `/api/v1/users/sessions/{session_id}` | `api/users.go:59` | `ApiSessionRequired` |
| DELETE | `/api/v1/users/sessions` | `api/users.go:60` | `ApiSessionRequired` |
| GET / PUT | `/api/v1/users/{user_id}` | `api/users.go:65-66` | `ApiSessionRequired` |

- Single-session revoke takes the id as a **path param**, pattern
  `"/sessions/{session_id:[A-Fa-f0-9-]+}"` (`api/users.go:59`), read via
  `c.Params.SessionID` (`api/params.go:46`) — **not** a body field.
- Revoke-all is `DELETE` on the **same path as the list** (`api/users.go:60`).

**Session object fields.** The handler builds an anonymous struct
(`api/users.go:502-511`), **not** `model.SessionResponse`. Actual tags:
`id`, `device_info`, `ip_address`, `user_agent`, `expires_at`, `last_used_at`,
`created_at`, `revoked`. Envelope: `{"sessions": [...], "total": <int>}`
(`api/users.go:527`); timestamps RFC3339 (`:519-521`). **There is no `user_id`
in the payload** (it exists on `model.Session` at `model/session.go:13` but is
not copied), and `revoked` is always `false` in practice because the query
filters `revoked = FALSE AND expires_at > ?`
(`internal/repositories/session_repository.go:212`). `model.SessionResponse` /
`model.ListSessionsResponse` (`model/session.go:52-71`) exist but are **unused
by the handler** — do not model the client type on them. `refresh_token_hash`,
`revoked_at`, `revoked_reason` are never exposed.

### Five findings that shape this epic

1. **There is no logout endpoint.** No `/logout` handler exists in the Go
   server; grep finds only `cmd/users/logout.go` and PKCS#11's `ctx.Logout`.
   The CLI's `rocketvault users logout` is explicitly **client-side only** —
   "This does not revoke the session server-side — the underlying JWT simply
   expires naturally" (`cmd/users/logout.go:38-42`, implementation `:64-83`).
   Foundation Task 4 stubs a `logout()` in `src/api/auth.ts`; Task 2 below
   settles what it must actually do.

2. **There is no `/users/me`.** No `/me` or `/profile` route exists anywhere.
   Self-profile is `GET /api/v1/users/{user_id}` with the caller's own id;
   `getUser` permits admin **or** own id (`api/users.go:209-212`). It returns
   `model.UserResponse` (`model/user.go:123-129`): `id`, `username`, `roles`,
   `created_at`, `totp_secret` (omitempty, only populated at create time,
   `api/users.go:131`).

3. **⚠ The RBAC map makes all three session routes admin-only today.**
   `ApiSessionRequired` (`api/context.go:201`) and `AuthorizationMiddleware`
   (`internal/middleware/middleware.go:360`) both call `ValidateEndpointAccess`,
   which maps by prefix `users` + method
   (`internal/services/authorization/rbac_service.go:261-274`): any `GET` under
   `/users` containing a `/` → `users:read`; any `DELETE` → `users:delete`. Only
   `RoleAdmin` holds those (`rbac_service.go:90-104`; `model.RoleUser` gets no
   user permissions). **So a plain `user` gets 403 listing or revoking their
   own sessions, and 403 reading their own profile.** This is a backend
   authorization bug, not a frontend one — the handlers themselves implement
   correct self-scoping (`api/users.go:485-495` hardcodes `c.Claims.UserID`),
   but the RBAC gate fires first. Design for it (Task 3) rather than around it.

4. **There is no `is_current` flag.** Nothing in the response marks "this
   device" (`api/users.go:502-523`). The only handle is that the JWT's `jti`
   claim **is** the session id (`internal/services/auth/jwt_service.go:72-73`,
   preserved across refresh at
   `internal/services/auth/authentication_service.go:367`). Neither
   `LoginResponse` nor `RefreshTokenResponse` returns a session id
   (`model/user.go:157-163, 179-186`), so the client must read `jti` out of its
   own access token.

5. **Revoke-all includes your own session.** `revokeAllSessions` passes only the
   caller's user id (`api/users.go:552-563`) → `RevokeAllUserSessions`
   (`authentication_service.go:446`) → `UPDATE user_sessions SET revoked = TRUE
   ... WHERE user_id = ? AND revoked = FALSE`
   (`internal/repositories/session_repository.go:342-346`) with **no exclusion
   of the current `jti`**. Because `ValidateSession` checks `IsSessionRevoked`
   on every request (`authentication_service.go:302-311`), the caller's own
   token is rejected on the very next call. It is logout-everywhere.

**Also worth knowing.** Password change has **no dedicated endpoint and no
current-password confirmation** — it is a field on the generic
`PUT /api/v1/users/{user_id}` body `model.UpdateUserRequest`
(`model/user.go:108-116`: `username`, `password`, `roles`), min length 8
(`api/users.go:266-269`), and a non-admin may not change their own `roles`
(`api/users.go:276-286`, `"cannot change own role"`). **TOTP re-enrollment does
not exist** — secrets are generated only in `CreateUser`
(`internal/services/users/user_service.go:185-210`) and returned once. And
**refresh tokens are not rotated**: the same `refresh_token` comes back
(`authentication_service.go:381-394`) and `RefreshTokenResponse.expires_at` is a
hardcoded `time.Now().Add(time.Hour)` (`:398`) that does not reflect the JWT's
real expiry — note this contradicts the spec's § 3 claim that refresh rotates
the token server-side; the code is authoritative.

## File Structure

New: `src/lib/auth/access-token-claims.ts` (+ test),
`src/components/account/profile-card.tsx`, `password-change-form.tsx`,
`session-list.tsx`, `session-revoke-dialog.tsx`, `revoke-all-dialog.tsx`,
tests for each.

Modified: `src/api/auth.ts` (**extend** — add `getOwnProfile`,
`updateOwnPassword`; correct the `logout` stub), `src/api/auth.test.ts`
(extend), `src/routes/account.tsx` (replace the foundation's `<Empty>`
placeholder), `src/lib/auth/auth-context.tsx` (expose the decoded `jti`).

## Task 1: Extend `src/api/auth.ts` with the profile calls it lacks

**Files:** Modify `src/api/auth.ts`, `src/api/auth.test.ts`.

- [ ] **Step 1:** Open `src/api/auth.ts` first and inventory what foundation
      Task 4 already shipped. `login`, `refresh`, `logout`, `listSessions`,
      `revokeSession`, `revokeAllSessions` are expected to be present. **Add
      nothing that already exists**; if a signature is wrong for this epic,
      amend it in place and update the existing test rather than adding a
      parallel function.
- [ ] **Step 2 (failing test):** add `getOwnProfile(userId)` →
      `GET /api/v1/users/{userId}`, returning
      `{ id, username, roles, created_at, totp_secret? }`
      (`model/user.go:123-129`). Name it `getOwnProfile`, not `getMe` — there is
      no `/me` route (`api/users.go` has none) and the name would imply one.
- [ ] **Step 3 (failing test):** add `updateOwnPassword(userId, password)` →
      `PUT /api/v1/users/{userId}` with a body containing **only** `password`.
      Assert `roles` is never in the body — a non-admin sending it is rejected
      with `"cannot change own role"` (`api/users.go:276-286`) even if the value
      is unchanged.
  ```ts
  // src/api/auth.test.ts (excerpt)
  it("sends only password on a self password change", async () => {
    const fetchMock = vi.spyOn(global, "fetch").mockResolvedValue(json(userFixture))
    await updateOwnPassword(USER_ID, "correct horse battery staple")
    const body = JSON.parse(String(fetchMock.mock.calls[0][1]?.body))
    expect(Object.keys(body)).toEqual(["password"])
  })
  ```
- [ ] **Step 4 (failing test):** assert the session list decodes the real
      envelope `{ sessions, total }` with the eight fields at
      `api/users.go:502-511` — and that the client type has **no `user_id`**,
      since the handler does not copy it. If foundation Task 4's `listSessions`
      already asserts this, leave it alone.
- [ ] **Step 5:** Run, confirm failure. Implement. Verification gate. Commit:
      `git commit -S -m "feat(api): extend auth module with self-profile calls"`

## Task 2: Settle what `logout()` means

**Files:** Modify `src/api/auth.ts`, `src/api/auth.test.ts`,
`src/components/app-shell/account-menu.tsx`.

- [ ] **Step 1:** There is no server logout route. Foundation Task 9 already
      wires `account-menu.tsx`'s logout to `auth.logout()` then
      `clearSession()`. Decide and document the semantics here, once, so a
      later reader does not go looking for a `/logout` endpoint.
- [ ] **Step 2 (failing test):** `logout()` performs a **real server-side
      revocation of the current session** by calling
      `revokeSession(currentSessionId)` — the `jti` from Task 4's decoder —
      and then clears local state, falling back to a local-only clear when the
      id is unavailable or the revoke fails. This is better than the CLI's
      behaviour, which is local-only and leaves the JWT valid until expiry
      (`cmd/users/logout.go:38-42`); revoking is what actually invalidates it,
      because `ValidateSession` checks `IsSessionRevoked` per request
      (`internal/services/auth/authentication_service.go:302-311`).
- [ ] **Step 3 (failing test):** a failed revoke (including the 403 from
      finding 3 above) still clears local session state and navigates to
      `/app/login`. A user clicking Log out must never be left logged in
      because a server call failed. Assert this branch explicitly.
- [ ] **Step 4:** Add a comment in `src/api/auth.ts` stating that no
      `POST /users/logout` exists and that revocation is the substitute, citing
      `api/users.go:54-60` (the complete session route list).
- [ ] **Step 5:** Run, confirm failure, implement, verification gate. Commit:
      `git commit -S -m "feat(auth): make logout revoke the current session"`

## Task 3: Account route — profile, and honest handling of the RBAC 403

**Files:** Modify `src/routes/account.tsx`. Create
`src/components/account/profile-card.tsx`, `password-change-form.tsx`, tests.

- [ ] **Step 1 (failing test):** `account.tsx` replaces the foundation's
      `<Empty>` placeholder with two stacked `card.tsx` sections — Profile and
      Sessions. `beforeLoad` calls `requireAuth` only (foundation Task 5);
      **do not add `requireGlobalAdmin`** — the route is self-service by design
      even though the backend currently over-gates its data.
- [ ] **Step 2 (failing test):** `<ProfileCard>` renders username, roles as
      `badge.tsx`, `created_at`, and the user id, sourced from
      `getOwnProfile(user.id)`.
- [ ] **Step 3 (failing test — the central case):** a 403 from
      `getOwnProfile` does **not** render a generic error. Per finding 3,
      `mapEndpointToPermission` maps any `GET /users/<something>` to
      `users:read`, held only by `admin` (`rbac_service.go:261-274, 90-104`), so
      a plain `user` is refused their own profile even though the handler would
      have allowed it (`api/users.go:209-212`). Fall back to rendering the
      identity already in session state (`username`, `roles`, `id` from
      `useAuth()`), plus a `--warning` `alert.tsx` explaining that full profile
      details require the admin role on this server version, citing the gap as a
      backend issue rather than blaming the user.
  ```tsx
  it("falls back to session identity when the server 403s on own profile", async () => {
    vi.mocked(getOwnProfile).mockRejectedValue(
      new ApiError({ status_code: 403, message: "forbidden" })
    )
    renderWithAuth(<ProfileCard />, { username: "alice", roles: ["user"] })
    expect(await screen.findByText("alice")).toBeVisible()
    expect(screen.getByText(/require the admin role on this server/i)).toBeVisible()
  })
  ```
- [ ] **Step 4 (failing test):** `<PasswordChangeForm>` submits
      `updateOwnPassword`, enforces the server's 8-character minimum client-side
      (`api/users.go:266-269`), and requires a confirm field. It must **not**
      render a "current password" field — the endpoint neither accepts nor
      verifies one (`model/user.go:108-116`), and a field that is collected and
      discarded is worse than none. Assert no current-password input exists, and
      add a short note that the change takes effect on next login since existing
      sessions are not invalidated by a password change.
- [ ] **Step 5 (failing test):** **no TOTP re-enrollment UI.** No endpoint
      regenerates a TOTP secret — secrets are issued once in `CreateUser`
      (`internal/services/users/user_service.go:185-210`). Assert no "reset
      MFA" / "regenerate TOTP" control renders; if the section explains
      anything, it says an admin must recreate the user. Do not build a form
      against a route that does not exist.
- [ ] **Step 6:** Run, confirm failure, implement, verification gate. Commit:
      `git commit -S -m "feat(account): add profile card and password change"`

## Task 4: Identify the current session from the access token's `jti`

**Files:** Create `src/lib/auth/access-token-claims.ts` + test. Modify
`src/lib/auth/auth-context.tsx`.

- [ ] **Step 1 (failing test):** `decodeAccessTokenClaims(token)` splits the
      JWT, base64url-decodes the payload, and returns `{ jti, sub, exp, roles }`
      — **no signature verification**, and a comment saying so plainly: this is
      display-only convenience. The browser must never treat decoded claims as
      an authorization decision; every real check happens server-side. Assert a
      malformed token returns `null` rather than throwing.
- [ ] **Step 2 (failing test):** `jti` is the session id
      (`internal/services/auth/jwt_service.go:72-73`) and survives refresh
      (`authentication_service.go:367`), which is the only reason this works.
      Assert a fixture token's `jti` equals the expected session uuid.
- [ ] **Step 3:** Expose `currentSessionId` from `useAuth()` in
      `auth-context.tsx`, recomputed whenever the access token changes. Do not
      persist it — it is derived state.
- [ ] **Step 4:** Add a comment recording that this decoder exists only because
      the sessions response has no `is_current` field
      (`api/users.go:502-523`) and neither `LoginResponse` nor
      `RefreshTokenResponse` returns a session id
      (`model/user.go:157-163, 179-186`). A future backend `is_current` flag
      should replace it.
- [ ] **Step 5:** Run, confirm failure, implement, verification gate. Commit:
      `git commit -S -m "feat(auth): derive current session id from access token jti"`

## Task 5: Session list and single-session revoke

**Files:** Create `src/components/account/session-list.tsx`,
`session-revoke-dialog.tsx`, tests.

- [ ] **Step 1 (failing test):** `<SessionList>` renders rows from
      `listSessions()` with columns Device, IP, Last used, Created, Expires,
      built from `device_info`, `ip_address`, `user_agent`, `last_used_at`,
      `created_at`, `expires_at`. Empty list → `empty.tsx`. `total` from the
      envelope drives a count in the section header.
- [ ] **Step 2 (failing test):** the row whose `id` equals `currentSessionId`
      (Task 4) renders a "This device" `badge.tsx`. Assert exactly one row gets
      it, and that **no** row gets it when the token cannot be decoded — never
      guess by recency or IP.
- [ ] **Step 3 (failing test):** per-row "Revoke" behind `alert-dialog.tsx`
      calls `revokeSession(id)` and refetches. Revoking the **current** session
      is allowed but must warn that it logs this browser out, and on success it
      clears local session state and navigates to `/app/login` rather than
      leaving a dead UI making 401s.
- [ ] **Step 4 (failing test):** do **not** render a `revoked` column.
      The field exists in the payload but the query filters revoked rows out
      (`internal/repositories/session_repository.go:212`), so it is always
      `false` and a column of identical values is noise. Assert it is absent.
- [ ] **Step 5 (failing test):** a 403 from `listSessions` renders the same
      backend-gap explanation as Task 3, Step 3 — finding 3 applies to
      `DELETE`/`GET` under `/users` alike (`rbac_service.go:261-274`). Extract
      that message into one shared component so the two places cannot drift.
- [ ] **Step 6:** Run, confirm failure, implement, verification gate. Commit:
      `git commit -S -m "feat(account): add session list with per-session revoke"`

## Task 6: Revoke all — the logout-everywhere action

**Files:** Create `src/components/account/revoke-all-dialog.tsx`, test.

- [ ] **Step 1 (failing test):** "Revoke all sessions" is styled
      `--destructive`, sits below a `separator.tsx` from the per-row actions,
      and calls `revokeAllSessions()`.
- [ ] **Step 2 (failing test):** the confirm copy states that this **includes
      this device** and will log you out immediately. Per finding 5, the server
      excludes nothing (`api/users.go:552-563`,
      `internal/repositories/session_repository.go:342-346`) and the caller's
      own token fails on the very next request
      (`authentication_service.go:302-311`). Assert the sentence renders — a
      user who expects "all *other* devices" will be surprised at exactly the
      wrong moment.
  ```tsx
  it("warns that revoke-all signs out this device too", async () => {
    render(<RevokeAllDialog />)
    await userEvent.click(screen.getByRole("button", { name: /revoke all/i }))
    expect(screen.getByText(/including this device/i)).toBeVisible()
  })
  ```
- [ ] **Step 3 (failing test):** on success, clear local session state and
      navigate to `/app/login` without attempting any further authenticated
      call. Assert no post-revoke refetch of `listSessions` is issued — it would
      401 and, via the foundation's interceptor, trigger a pointless refresh
      attempt against an already-revoked session.
- [ ] **Step 4:** Do **not** offer "revoke all except this device" — the server
      has no such variant (`api/users.go:60` is the only revoke-all route and it
      is always self-scoped with no exclusion). Record this in a comment.
- [ ] **Step 5:** Run, confirm failure, implement, verification gate. Commit:
      `git commit -S -m "feat(account): add revoke-all-sessions action"`

## Self-Review

- Nothing from foundation Task 4's `src/api/auth.ts` is redefined: this plan
  extends that file with two genuinely missing calls (Task 1) and corrects the
  `logout` stub's semantics (Task 2), and Task 1 Step 1 makes reading the
  existing module a required first step. No `src/api/sessions.ts` is created.
- Every one of the five verified findings drives a concrete task: no logout
  route → Task 2; no `/users/me` → Task 3; the RBAC over-gate → Task 3 Step 3
  and Task 5 Step 5, sharing one component; no `is_current` → Task 4; revoke-all
  includes self → Task 6.
- The `jti` decoder is scoped as display-only with an explicit non-authorization
  warning, and is marked for deletion once a backend `is_current` lands.
- Three affordances are deliberately *not* built, each with a negative test or
  cited comment: current-password field, TOTP re-enrollment, and
  "revoke all except this device" — all would be forms against routes that do
  not exist.
- The spec's § 3 claim that refresh rotates the refresh token is contradicted by
  `authentication_service.go:381-394`; recorded here so Epic 13's reviewer does
  not "fix" the client to expect a new token that never arrives.
