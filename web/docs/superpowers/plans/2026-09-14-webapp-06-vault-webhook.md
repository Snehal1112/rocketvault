# RocketVault Dashboard — Vault Webhook Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development
> for the multi-task breakdown below, or superpowers:executing-plans if executing
> this plan directly, top to bottom.

**Goal:** Per-vault webhook configuration UI — set (create or update), view,
rotate the signing secret, enable/disable, and delete — on one route,
`/app/vaults/:vaultName/webhook`.

**Read this before anything else:** RocketVault **does not deliver webhooks
today.** The backend stores a URL, an encrypted signing secret, and an
`enabled` flag, and nothing in the server ever dials that URL. The service's
own doc comment says so plainly: SSRF policy "belongs to the sub-project that
actually makes the outbound call, not to a layer that never dials anything"
(`internal/services/vaults/webhook_service.go:23-31`), and a repo-wide search
for a dispatcher finds only the config surface (model, repository, service,
API handler, CLI) plus an example *receiver* under `examples/webhook-receiver/`.
This epic therefore ships **configuration only**. There is no "Send test
webhook" button to build, because there is nothing behind it to fire. Task 4
makes that statement part of the UI and pins it with a test, so nobody adds a
button that silently does nothing.

**Architecture:** See `docs/superpowers/specs/2026-09-08-webapp-dashboard-epics-design.md`
§§ 2, 6 (Epic 06). Builds on Phase 0's `src/api/client.ts`, `useAuth()`, and
the `vaults.$vaultName.tsx` layout route.

**Tech Stack:** unchanged from foundation (React 19 + TS strict + TanStack
Router/Query + Vitest/RTL).

**Conventions to follow:** see foundation plan §Conventions — `@/` alias,
`import type` (`verbatimModuleSyntax`), `cva`/`cn()` from `@/lib/utils`,
`data-slot` on component roots, Prettier (no semicolons, double quotes,
2-space, 80 cols; `bun run format` after touching class strings), and do not
edit `src/components/ui/**` in place.

Design system is fixed by `web/src/index.css`: teal `--primary`, `font-heading`
(JetBrains Mono Variable) for the page title, field labels and the secret's
monospace display, `font-sans` (Noto Sans Variable) for body copy, cards
`rounded-4xl shadow-md ring-1 ring-foreground/5`. Status uses the
`--success`/`--warning` tokens the foundation plan adds. Every control needed
is already among the 61 vendored components in `src/components/ui/` —
`card.tsx`, `field.tsx`, `input.tsx`, `input-group.tsx`, `switch.tsx`,
`button.tsx`, `alert.tsx`, `alert-dialog.tsx`, `badge.tsx`, `empty.tsx`,
`dialog.tsx`, `tooltip.tsx`, `skeleton.tsx`. Do not `shadcn add` anything; see
`web/.claude/shadcn-components.md`.

**Verification gate (run before every commit):**
```bash
cd web && bun run typecheck && bun run lint && bun run test && bun run build
```

## Backend contract (verified against source — do not re-derive)

Three endpoints, registered at `api/vault.go:43-45` on the **vault-management**
router — note the path variable is `{name}`, not `{vault_name}`, and carries
no regex constraint, unlike the vault-scoped resource routes
(`api/api.go:98`, `:104`):

| Method | Path | Source | Success |
|---|---|---|---|
| `PUT` | `/api/v1/vaults/{name}/webhook` | `api/vault.go:43` | **200** + config; **+ `signing_secret` when this call minted one** |
| `GET` | `/api/v1/vaults/{name}/webhook` | `api/vault.go:44` | **200** + config; **404** when none is set |
| `DELETE` | `/api/v1/vaults/{name}/webhook` | `api/vault.go:45` | **204 No Content**, empty body (`api/vault_webhook.go:156`) |

The 204 is worth calling out: every other delete in this app returns
`{"status":"OK"}` with a 200 (e.g. `api/certificates.go:390`,
`api/role_assignments.go:237`). A shared response parser that assumes a JSON
body will throw here.

**PUT body** (`model.UpsertVaultWebhookRequest`,
`model/vault_webhook.go:70-82`): `url`, `rotate_secret` (bool), `enabled`
(**`*bool`**). The pointer is load-bearing and documented as such at `:71-76`:
an omitted `enabled` means "keep the current value" (and `true` on create),
whereas sending `false` disables the webhook. A form that always serializes
its switch would silently disable a webhook on any URL-only edit.

There is **no client-supplied secret field**. The server mints a 32-byte
random secret (`internal/services/vaults/webhook_service.go:34-36`);
`rotate_secret: true` replaces an existing one.

**Response** (`model.VaultWebhookConfigResponse`, `model/vault_webhook.go:39-45`):
`url`, `enabled`, `created_at`, `updated_at` — RFC3339 strings, formatted at
`:29-37`. That is the whole shape. The stored `VaultWebhookConfig` deliberately
carries **no json tags at all** so it cannot be marshalled into a response by
accident (`:11-18`) — "the API shape cannot carry the secret is true by
construction rather than by remembering to clear a field."

**The show-once secret** (`model.VaultWebhookConfigCreatedResponse`,
`model/vault_webhook.go:53-63`): the PUT response embeds the normal config
plus a `signing_secret` string, and **only** when that call minted a secret —
on create, or on an explicit `rotate_secret: true`
(`api/vault_webhook.go:68-70`, `:102-109`). `GET` never returns it in any form.
There is no recovery path: a lost secret must be rotated, which invalidates the
old one.

**Authorization** — `authorization.CanManageVault`
(`internal/services/authorization/vault_authz.go:33-53`), called via
`resolveAndAuthorizeVault` (`api/vault_webhook.go:38-64`), which resolves the
vault name first and then authorizes. The resolve-then-authorize order is
deliberate and documented (`:30-37`): these `{name}` routes bypass
`VaultResolutionMiddleware`, so `PolicyMiddleware` only ever evaluated the
*default* vault for them, and each handler restores the per-vault check itself.

Two authorities pass: the global `admin` account role (short-circuit,
`vault_authz.go:35-37`), or a **vault-scoped** `vaults:manage` access-policy
allow on this specific vault. Since v4.6.0 a global (`vault_id NULL`)
`vaults:manage` allow does **not** satisfy a concrete-vault decision — only a
global *deny* still matches and blocks (`vault_authz.go:19-32`, `:44-50`).
Denial → **403** `"admin or vaults/manage required"` (`api/vault_webhook.go:60`).
An unknown vault name → **404** `"vault"` (`:47-50`).

**URL validation** (`internal/services/vaults/webhook_service.go:22-31` and
`validateWebhookURL` below it): the URL must be absolute `https`, have a host,
and embed no credentials. Failure → **400** with the body message
`"url: webhook url must be an absolute https URL"`
(`api/vault_webhook.go:93-96`). The error text **never quotes the supplied
URL** — that is a deliberate storage-layer decision, so do not expect the
server to echo the bad value back for display.

**Delete is idempotent**: "Deleting when none exists succeeds"
(`internal/services/vaults/webhook_service.go`, `VaultWebhookService.Delete`
doc). A delete on an unconfigured vault returns 204, not 404.

**What the signing secret is for**, per the example receiver
(`examples/webhook-receiver/signature.go`): an `X-RocketVault-Signature`
header of the form `t=<unix>,v1=<hex>`, an HMAC-SHA256 over the payload with
the secret used as the key **verbatim — never base64-decoded first** (`:25`).
That detail belongs in the UI's show-once copy, because an integrator who
decodes the secret before using it will get a receiver that rejects everything
— if and when delivery ever ships.

### CLI cross-check

`rocketvault vault-webhook set|get|delete` (`cmd/vault-webhook/`) exposes
exactly three flags on `set`: `--url`, `--rotate-secret`, `--enabled`
(`cmd/vault-webhook/set.go:103-105`), whose help text records the same
"default: keep current value, true on create" semantics. Its authorization
helper is the same `CanManageVault` primitive
(`cmd/vault-webhook/authz.go:31-40`) with the message "requires admin or
vaults/manage". No CLI command sends a test event either — confirming the
capability genuinely does not exist rather than merely being unexposed over
HTTP.

## File Structure

New: `src/api/vault-webhook.ts` (+ test),
`src/routes/vaults.$vaultName.webhook.tsx`,
`src/components/webhook/webhook-config-form.tsx`,
`webhook-secret-dialog.tsx`, `webhook-empty-state.tsx`,
`webhook-delivery-notice.tsx`, tests for each.

Modified: `src/components/app-shell/vault-nav.tsx` (add a "Webhook" item
alongside "Settings" and "Access" — it is vault administration, not vault
data, and belongs next to them rather than among secrets/keys/certificates).

## Task 1: Vault webhook API module

**Files:** Create `src/api/vault-webhook.ts`, `src/api/vault-webhook.test.ts`.

- [ ] **Step 1 (failing tests):** `getVaultWebhook(vault)`,
      `upsertVaultWebhook(vault, {url, rotateSecret?, enabled?})`, and
      `deleteVaultWebhook(vault)`, against
      `/api/v1/vaults/{vault}/webhook`. Types transcribed from
      `model/vault_webhook.go:39-45` and `:53-63` — `url`, `enabled`,
      `created_at`, `updated_at`, plus an optional `signing_secret` present
      only on the mint path.
- [ ] **Step 2 (failing test):** `getVaultWebhook` maps a **404** to `null`
      rather than throwing. "No webhook configured" is the normal state of
      every vault and must be an empty state, not an error banner. Assert a
      403 still throws — absent and forbidden must never be conflated.
  ```ts
  it("returns null for an unconfigured vault but still throws on 403", async () => {
    mockFetch(404, { message: "webhook config not found" })
    await expect(getVaultWebhook("prod")).resolves.toBeNull()
    mockFetch(403, { message: "admin or vaults/manage required" })
    await expect(getVaultWebhook("prod")).rejects.toBeInstanceOf(ApiError)
  })
  ```
- [ ] **Step 3 (failing test):** `upsertVaultWebhook` **omits** `enabled` from
      the body when the caller did not explicitly set it, and sends
      `"enabled": false` when they did. This is the pointer semantics at
      `model/vault_webhook.go:71-76`; getting it wrong disables a working
      webhook on an unrelated URL edit. Assert both branches on the serialized
      body, not on the function's arguments.
- [ ] **Step 4 (failing test):** `deleteVaultWebhook` handles a **204 with an
      empty body** without attempting to parse JSON
      (`api/vault_webhook.go:156`). If `client.ts`'s `request()` assumes a
      JSON body on 2xx, this is where that assumption first breaks — fix it in
      `client.ts` (a 204/empty-body guard benefits every future epic) rather
      than working around it here, and add the guard's own test there.
- [ ] **Step 5:** Run, confirm failure. Implement. Verification gate. Commit:
      `git commit -S -m "feat(api): add vault webhook module"`

## Task 2: Webhook configuration page and form

**Files:** Create `src/routes/vaults.$vaultName.webhook.tsx`,
`src/components/webhook/webhook-config-form.tsx`,
`webhook-empty-state.tsx`, tests.

- [ ] **Step 1 (failing test):** with no config (Task 1's `null`),
      `<WebhookEmptyState>` renders via `empty.tsx` — "No webhook configured
      for this vault" plus a "Configure webhook" CTA. Not a blank card, and
      not an error.
- [ ] **Step 2 (failing test):** `<WebhookConfigForm>` pre-fills `url` and
      `enabled` from `getVaultWebhook`, shows `created_at`/`updated_at` as
      read-only metadata, and submits via `upsertVaultWebhook`. The `enabled`
      control is a `switch.tsx`; the form tracks whether the user touched it
      and only sends `enabled` when they did (Task 1 Step 3's contract).
      Assert an URL-only edit leaves an enabled webhook enabled.
- [ ] **Step 3 (failing test):** a **400** carrying
      `"url: webhook url must be an absolute https URL"` renders on the URL
      field, not as a page-level error. Add client-side pre-validation for the
      same three rules — absolute, `https`, has a host, no embedded
      credentials (`internal/services/vaults/webhook_service.go:22-31`) — but
      write the test so the *server's* message is what renders when it arrives,
      since the client check is a convenience and the server is the authority.
      Note in a code comment that the server never echoes the offending URL
      back (deliberate, `webhook_service.go:88-91`), so the field must preserve
      the user's input itself for correction.
- [ ] **Step 4 (failing test):** a **403** renders an access-denied state
      naming the two authorities: global `admin`, or a **vault-scoped**
      `vaults:manage` policy on *this* vault. Say vault-scoped explicitly — a
      global `vaults:manage` allow no longer satisfies a concrete-vault
      decision since v4.6.0 (`internal/services/authorization/vault_authz.go:19-32`),
      and copy that omits it will send an operator hunting a permission they
      already hold. A **404** on the vault name (as opposed to on the webhook)
      renders as "vault not found", which is distinguishable by the server's
      message.
- [ ] **Step 5:** Run, confirm failure, implement using `card.tsx`,
      `field.tsx`, `input.tsx`, `switch.tsx`, `alert.tsx`. Page title in
      `font-heading`. Verification gate. Commit:
      `git commit -S -m "feat(webhook): add vault webhook configuration form"`

## Task 3: Show-once signing secret and rotation

**Files:** Create `src/components/webhook/webhook-secret-dialog.tsx`, test;
modify `webhook-config-form.tsx`.

- [ ] **Step 1 (failing test):** when an `upsertVaultWebhook` response
      includes `signing_secret`, `<WebhookSecretDialog>` opens showing it in
      `font-heading` (monospace) with a copy button, and copy that states
      plainly it is shown **once** and cannot be retrieved later — `GET` has
      no field for it in any form (`model/vault_webhook.go:39-45`,
      `api/vault_webhook.go:114-115`), and the only recovery is rotation,
      which invalidates the old secret.
- [ ] **Step 2 (failing test):** when the response has **no** `signing_secret`
      — every plain update — the dialog does not open. Assert this explicitly:
      a dialog that opened on every save showing a stale or empty value would
      train users to dismiss the one time it matters.
  ```tsx
  it("shows the secret only when the server minted one", async () => {
    vi.mocked(upsertVaultWebhook).mockResolvedValue({ ...CONFIG })
    render(<WebhookConfigForm vaultName="prod" config={CONFIG} />)
    await saveForm()
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument()
  })
  ```
- [ ] **Step 3 (failing test):** a "Rotate signing secret" action, separate
      from Save and behind `alert-dialog.tsx`, sends
      `rotate_secret: true` with the current URL and surfaces the new secret
      through the same dialog. The confirm copy must say the previous secret
      stops working immediately — a receiver verifying with the old secret
      will reject every subsequent request.
- [ ] **Step 4 (failing test):** the dialog's integrator note states the
      signature scheme the example receiver implements: an
      `X-RocketVault-Signature` header of `t=<unix>,v1=<hex>`, HMAC-SHA256,
      with the secret used as the HMAC key **verbatim, not base64-decoded**
      (`examples/webhook-receiver/signature.go:14-28`). Link
      `examples/webhook-receiver/README.md` by path.
- [ ] **Step 5:** Run, confirm failure, implement, verification gate. Commit:
      `git commit -S -m "feat(webhook): add show-once signing secret and rotation"`

## Task 4: State plainly that nothing is delivered yet

**Files:** Create `src/components/webhook/webhook-delivery-notice.tsx`, test;
modify `vaults.$vaultName.webhook.tsx`.

Without this, the page is actively misleading: it offers a URL field, an
enable switch, and a signing secret, all of which imply that saving it causes
requests to be sent. Nothing is sent.

- [ ] **Step 1 (failing test):** `<WebhookDeliveryNotice>` renders an
      `alert.tsx` on the page stating that RocketVault currently **stores**
      webhook configuration but does not yet deliver events — no request is
      made to the configured URL by any part of the server today. Cite the
      basis in a code comment, not in the user-facing copy:
      `internal/services/vaults/webhook_service.go:23-31` describes the
      outbound call as belonging to a separate, not-yet-built sub-project, and
      no dispatcher exists anywhere in the repo.
- [ ] **Step 2 (failing test):** the page renders **no** "Send test webhook",
      "Test delivery", or "Ping" control. Write this as an explicit negative
      assertion so a future contributor adding one has to delete a test that
      explains why it cannot work.
  ```tsx
  it("offers no test-delivery action — nothing dispatches webhooks yet", () => {
    render(<WebhookPage vaultName="prod" />)
    expect(screen.queryByRole("button", { name: /test|ping|send/i })).not.toBeInTheDocument()
    expect(screen.getByText(/does not yet deliver/i)).toBeInTheDocument()
  })
  ```
- [ ] **Step 3 (failing test):** the `enabled` switch's helper text says what
      the flag currently means — a stored intent that takes effect once
      delivery ships — rather than implying it turns live notifications on and
      off.
- [ ] **Step 4:** Run, confirm failure, implement, verification gate. Commit:
      `git commit -S -m "feat(webhook): state that delivery is not yet implemented"`

## Task 5: Delete

**Files:** Modify `webhook-config-form.tsx`, test.

- [ ] **Step 1 (failing test):** a "Remove webhook configuration" action
      behind `alert-dialog.tsx` calls `deleteVaultWebhook`, then returns the
      page to the empty state from Task 2 Step 1. The confirm copy notes the
      signing secret is destroyed with the config and cannot be recovered —
      re-creating mints a new one.
- [ ] **Step 2 (failing test):** the delete succeeds against a vault with no
      configuration (the server is idempotent here —
      `VaultWebhookService.Delete`'s contract, "Deleting when none exists
      succeeds"), returning **204**. Assert the UI treats that as success and
      shows the empty state, rather than reporting a phantom error.
- [ ] **Step 3:** Run, confirm failure, implement, verification gate. Commit:
      `git commit -S -m "feat(webhook): add webhook configuration delete"`

## Self-Review

- All three confirmed endpoints have a task, each cited to `file:line`.
- The single most important fact about this feature — that nothing delivers
  webhooks — is a task with a negative test (Task 4), not a footnote. The plan
  would otherwise produce a page that lies about what it does.
- `enabled`'s pointer semantics are enforced by a serialization test (Task 1
  Step 3), so an URL-only edit cannot silently disable a webhook.
- DELETE's **204 with an empty body** is flagged as the outlier it is and the
  fix is pushed into `client.ts` (Task 1 Step 4) where it benefits every epic,
  rather than being special-cased here.
- Show-once is enforced in both directions (Task 3 Steps 1 and 2): the dialog
  opens exactly when the server minted a secret and never otherwise.
- Access-denied copy says *vault-scoped* `vaults:manage`, matching v4.6.0's
  narrowing and the resolve-then-authorize order these `{name}` routes restore
  by hand.
- The signature scheme's "use the secret verbatim, do not base64-decode it"
  detail is carried into the UI (Task 3 Step 4) because it is the one thing an
  integrator reliably gets wrong and it is documented nowhere a user will look.
- No new shadcn component is introduced.
