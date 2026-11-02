# RocketVault Dashboard — Audit & Compliance Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development
> for the multi-task breakdown below, or superpowers:executing-plans if executing
> this plan directly, top to bottom.

**Goal:** Admin audit surface — a filterable audit-log viewer that honestly
reports hash-chain integrity, SOC2 and GDPR report generation with CSV export,
and the retention-days setting. Mounted under `/app/admin/audit/...`.

**Architecture:** See `docs/superpowers/specs/2026-09-08-webapp-dashboard-epics-design.md`
§§ 2, 6 (Epic 11), and Journey G (admin reviews audit logs and exports a SOC2
report). Admin branch only — builds on Phase 0's `src/api/client.ts`,
`useAuth()`, and the `admin.tsx` layout route whose `beforeLoad` already calls
`requireGlobalAdmin` (foundation Task 10, Step 2).

**Tech Stack:** unchanged from foundation.

**Conventions to follow:** see foundation plan §Conventions — `@/` alias,
`import type`, `cva`/`cn()`, Prettier, don't edit `src/components/ui/**` in
place. Design tokens from `src/index.css`: teal `--primary`, `font-heading`
(JetBrains Mono) for titles/table headers/badges, `font-sans` (Noto Sans) for
body, `rounded-4xl` cards. Uses the foundation's `--success`/`--warning` tokens
(foundation Task 8) for the integrity banner. Vendored shadcn components needed
— `table.tsx`, `calendar.tsx`, `popover.tsx`, `select.tsx`, `input.tsx`,
`badge.tsx`, `alert.tsx`, `card.tsx`, `tabs.tsx`, `empty.tsx`, `sheet.tsx`,
`button.tsx`, `chart.tsx` — are all present (`web/.claude/shadcn-components.md`).
Do not `shadcn add` anything.

**Verification gate (run before every commit):**
```bash
cd web && bun run typecheck && bun run lint && bun run test && bun run build
```

## Backend contract (verified — do not re-derive)

Verified against `api/audit.go`, `internal/services/audit/audit_service.go`,
`internal/services/audit/compliance_report_service.go`,
`internal/repositories/audit_repository.go`, `model/audit.go`, `cmd/audit/`,
and the route dump `docs/api-routes.generated.txt:7-11`.

| Method | Path | Handler |
|---|---|---|
| GET | `/api/v1/audit/logs` | `getAuditLogs` (`api/audit.go:46`) |
| GET | `/api/v1/audit/reports/soc2` | `getSOC2Report` (`api/audit.go:47`) |
| GET | `/api/v1/audit/reports/gdpr` | `getGDPRReport` (`api/audit.go:48`) |
| GET | `/api/v1/audit/config` | `getAuditConfig` (`api/audit.go:49`) |
| PATCH | `/api/v1/audit/config` | `patchAuditConfig` (`api/audit.go:50`) |

That is the complete set. **There is no chain-verification route, no POST
report-generation route, and no separate export route.**

**Log query params** (literal strings, read in `parseAuditFilter`,
`api/audit.go:255-300`): `from`, `to` (RFC3339 — **silently ignored if
unparseable**, `:259-268`), `user_id`, `action`, `outcome`, `resource_type`,
`resource_id`, `source`, `limit` (default 100, silently capped at 1000,
`:288-297`). There is **no `vault` param** — audit is deliberately global
(`cmd/audit/audit.go:14-16`) — and **no `offset`, `page`, or cursor param**.

**Response envelope** (`auditLogsResponse`, `api/audit.go:99-104`):
`integrity_ok` (bool), `logs` (array), `next_cursor` (string), `total` (int64).
`next_cursor` is **hardcoded to `""`** (`api/audit.go:88`, with the comment at
`:96-98` saying so), and there is no offset param, so **the API can return at
most 1000 rows and there is no mechanism to reach row 1001.**

**⚠ Entry fields are PascalCase.** `model.AuditLog`
(`model/audit.go:6-18`) carries **zero json tags**, so `encoding/json` emits Go
field names verbatim: `ID`, `UserID`, `Action`, `Details`, `Timestamp`,
`ResourceType`, `ResourceID`, `IPAddress`, `Outcome`, `Source`, `PrevHash`. The
OpenAPI spec says so explicitly (`docs/api-specification.yaml:5346-5348`). Only
the envelope is snake_case. Do not write `user_id` anywhere in this epic's entry
types.

**Reports.** `from` and `to` are required RFC3339 query params on both
(`api/audit.go:304-327`); GDPR additionally requires `subject_id`
(`api/audit.go:159-163`). Only two report types exist — the literal strings
`"soc2"` and `"gdpr"` (`cmd/audit/report.go:76, 105, 128-129`). Only two output
formats exist: JSON and **CSV**. There is **no PDF anywhere**. CSV is selected
by an exact header compare `r.Header.Get("Accept") == "text/csv"`
(`api/audit.go:127, 176`) — `Accept: text/csv, */*` or any q-value falls through
to JSON. CSV responses set
`Content-Disposition: attachment; filename=soc2-report.csv` / `gdpr-report.csv`
(`api/audit.go:134, 183`).

Report bodies are also PascalCase (no json tags,
`internal/services/audit/compliance_report_service.go:16-45`):
SOC2 — `From`, `To`, `TotalEvents`, `UniqueUsers`, `AuthSuccesses`,
`AuthFailures`, `DataAccessEvents`, `AdminActions`, `KeyOperations`,
`TopActions` (`[{Action, Count}]`, `:30-33`).
GDPR — `SubjectID`, `From`, `To`, `TotalEvents`, `DataAccess`, `Deletions`,
`AuthEvents`, `Events` (array of `AuditLog`).

**Retention** is database-backed, not config-file-backed: key
`"retention_days"` in the `audit_config` table
(`compliance_report_service.go:212, 231`), default **365**
(`:211-224`), minimum 1 (`:228-230`, plus `> 0` at `api/audit.go:235-238`).
There is no `audit:` block in `.rocketvault.yaml` — `soft_delete.retention_days`
(`config/config.go:20`) is a different setting and must not be conflated.
`GET`/`PATCH /api/v1/audit/config` both use the body `{"retention_days": <int>}`
(`api/audit.go:217, 229-250`).

**Authorization:** admin-role-only, enforced by a copy-pasted
`common.HasAnyRole(roles, model.RoleAdmin)` inside each of the five handlers
(`api/audit.go:66-70, 110-114, 152-157, 200-204, 223-227`). `PolicyMiddleware`
does not gate audit — `resolvePolicy` returns `"", ""` for `/audit`
(`internal/middleware/middleware.go:415-428`) — and `RBACService` contributes
nothing (`rbac_service.go:278-279`). The CLI duplicates the same check in
`cmd/audit/authz.go:23-33`.

### The hash chain — what the UI can and cannot honestly say

This is the epic's defining constraint. Get it wrong and the dashboard makes a
compliance claim the backend does not support.

- There is exactly **one** chain field, `PrevHash`, and its name is misleading:
  `RecordEvent` stores *this* row's computed hash into it
  (`internal/services/audit/audit_service.go:64, 77`), and `GetLastHash` feeds
  it forward (`internal/repositories/audit_repository.go:95-108`). There is no
  `hash` field and no sequence number.
- Hash formula (`audit_service.go:99-106`):
  `SHA-256(prevHash|RFC3339Nano ts|userID|action|details|resourceType+resourceID|outcome)`.
  **`IPAddress` and `Source` are not in the hash** — they can be altered
  undetected.
- Verification is the unexported `verifyChain(logs)`
  (`compliance_report_service.go:236-258`), reachable **only** as a side effect
  of `QueryLogs` (`:76`). It is not on
  `ComplianceReportServiceInterface` (`:48-57`). **There is no verification
  endpoint and no `audit verify` CLI command** (`cmd/audit/audit.go:31-33`
  registers only `logs`, `report`, `config`). This is a real backend gap.
- `integrity_ok` describes **only the rows in the current response**, not the
  table. Consequences the UI must respect:
  - Applying any filter makes non-adjacent rows adjacent, so `verifyChain`
    compares links that were never linked — **a filtered query can report
    `integrity_ok: false` on a perfectly intact log.**
  - The default unfiltered 100-row page can report `true` while the rest of
    the table is corrupt.
  - Rows with an empty `PrevHash` are skipped rather than failed
    (`compliance_report_service.go:240-243`).
  - The response says *that* something broke, never *where* — no row id, no
    index, no count.

## File Structure

New: `src/api/audit.ts` (+ test), `src/routes/admin.audit.tsx` (layout with
tabs), `admin.audit.logs.tsx`, `admin.audit.reports.tsx`,
`admin.audit.settings.tsx`, `src/components/audit/audit-log-table.tsx`,
`audit-filter-bar.tsx`, `audit-entry-sheet.tsx`, `audit-integrity-banner.tsx`,
`audit-result-cap-notice.tsx`, `soc2-report-panel.tsx`, `gdpr-report-panel.tsx`,
`audit-retention-form.tsx`, tests for each.

Modified: `src/components/app-shell/admin-nav.tsx` (add an "Audit" item).

## Task 1: Audit API module

**Files:** Create `src/api/audit.ts`, `src/api/audit.test.ts`.

- [ ] **Step 1 (failing tests):** `queryAuditLogs(filter)` →
      `GET /api/v1/audit/logs`, sending **only** the params the backend reads
      (`from`, `to`, `user_id`, `action`, `outcome`, `resource_type`,
      `resource_id`, `source`, `limit`). Write a test asserting an unset filter
      key is **omitted** from the query string, not sent empty — and a second
      test asserting an invented param (`vault`, `offset`, `page`) is never
      sent, since the server silently ignores unknown params and an implementer
      would otherwise never notice.
- [ ] **Step 2 (failing test):** the entry type is PascalCase. Decode a fixture
      built from `model/audit.go:6-18` and assert `entry.UserID` /
      `entry.ResourceType` / `entry.IPAddress` / `entry.PrevHash` are populated.
      Assert the snake_case spellings are `undefined`.
  ```ts
  // src/api/audit.test.ts (excerpt)
  it("decodes PascalCase entry fields — model.AuditLog has no json tags", async () => {
    const [entry] = (await queryAuditLogs({})).logs
    expect(entry.UserID).toBe("6f2c…")
    expect(entry.ResourceType).toBe("secret")
    // @ts-expect-error the server never emits snake_case entry fields
    expect(entry.user_id).toBeUndefined()
  })
  ```
  There is prior art for getting this wrong: `internal/vaultapi/audit.go:56-67`
  decodes into snake_case tags and therefore **silently loses `UserID`,
  `ResourceType`, `ResourceID`, and `IPAddress`** against a real server, which
  propagates into MCP's `query_audit_log`
  (`internal/mcpserver/tools_audit.go:85-92`). Its tests pass because
  `internal/vaultapi/audit_test.go:18-19` hand-writes snake_case fixtures. Build
  this module's fixtures from the Go struct, not from that client.
- [ ] **Step 3 (failing tests):** `getSOC2Report(from, to, format)` and
      `getGDPRReport(from, to, subjectId, format)`. For `format: "csv"` the
      request must send **exactly** `Accept: text/csv` — write a test asserting
      the header is that literal string with no `, */*` suffix and no q-value,
      because `api/audit.go:127, 176` is an exact compare and anything else
      silently returns JSON. CSV resolves to a `Blob`; JSON resolves to the
      parsed PascalCase report.
- [ ] **Step 4 (failing tests):** `getAuditConfig()` → `{ retention_days }`;
      `setAuditConfig(days)` → `PATCH` with `{ retention_days: days }`.
- [ ] **Step 5:** Run, confirm failure. Implement with `client.ts`'s
      `request()` (add a blob-response path if `client.ts` lacks one — extend
      it rather than bypassing it with a raw `fetch`). Verification gate.
      Commit: `git commit -S -m "feat(api): add audit module"`

## Task 2: Log viewer — table, filters, detail sheet

**Files:** Create `src/routes/admin.audit.tsx`, `admin.audit.logs.tsx`,
`src/components/audit/audit-log-table.tsx`, `audit-filter-bar.tsx`,
`audit-entry-sheet.tsx`, tests. Modify `admin-nav.tsx`.

- [ ] **Step 1 (failing test):** `admin.audit.tsx` is a layout route with
      `tabs.tsx`-style nav to Logs / Reports / Settings; `<AuditLogTable>`
      renders `logs` with columns Timestamp, Action, Outcome, User, Resource,
      Source. `Outcome` renders as a `badge.tsx` coloured from the foundation's
      `--success`/`--destructive` tokens. Empty result → `empty.tsx`.
- [ ] **Step 2 (failing test):** `<AuditFilterBar>` exposes exactly the nine
      supported filters and nothing else. Date range uses `calendar.tsx` inside
      `popover.tsx` and must emit **RFC3339** — write a test asserting the
      serialized `from` parses as RFC3339, because an unparseable value is
      *silently dropped* by `parseAuditFilter` (`api/audit.go:259-268`) and the
      user would see unfiltered results with no error at all.
- [ ] **Step 3 (failing test):** there is deliberately **no vault filter**.
      Assert no vault control renders, and put a one-line comment citing
      `cmd/audit/audit.go:14-16` (audit is global by design) so nobody adds one.
- [ ] **Step 4 (failing test):** row click opens `<AuditEntrySheet>`
      (`sheet.tsx`) showing every field including `PrevHash` in `font-heading`
      with a copy button. The sheet must **not** label `PrevHash` as "previous
      entry's hash" — per `audit_service.go:64, 77` it is this row's own hash.
      Label it "Chain hash" and assert that string.
- [ ] **Step 5:** Run, confirm failure, implement, verification gate. Commit:
      `git commit -S -m "feat(audit): add log viewer with filters and detail sheet"`

## Task 3: Integrity banner and the 1000-row ceiling — the two honesty tasks

**Files:** Create `src/components/audit/audit-integrity-banner.tsx`,
`audit-result-cap-notice.tsx`, tests.

- [ ] **Step 1 (failing test):** `<AuditIntegrityBanner>` renders from
      `integrity_ok`, and its copy is scoped to what the flag actually covers.
      On `true` with **no filters applied**: "Hash chain intact across the N
      entries shown." On `true` **with filters applied**: it must *not* claim
      intact — filtering makes the check meaningless
      (`compliance_report_service.go:236-258` compares adjacent rows of the
      filtered page). Render a neutral "Integrity not checkable on a filtered
      view" instead, and assert that branch.
  ```tsx
  it("does not claim chain integrity on a filtered view", () => {
    render(<AuditIntegrityBanner integrityOk filterActive count={12} />)
    expect(screen.queryByText(/intact/i)).not.toBeInTheDocument()
    expect(screen.getByText(/not checkable on a filtered view/i)).toBeVisible()
  })
  ```
- [ ] **Step 2 (failing test):** on `integrity_ok: false` the banner is a
      `--destructive` alert that states (a) the chain broke somewhere in the
      rows shown, (b) **the API does not report which row** — no endpoint and
      no CLI command exists to locate or verify the break
      (`cmd/audit/audit.go:31-33`; `verifyChain` is unexported,
      `compliance_report_service.go:236-258`), and (c) on a filtered view a
      false result may be an artifact of filtering rather than tampering.
      Assert all three sentences. This is the difference between a useful alert
      and one that sends an operator hunting a nonexistent incident.
- [ ] **Step 3 (failing test):** `<AuditResultCapNotice>` renders whenever
      `total > logs.length`, stating that only the newest `logs.length` of
      `total` entries are reachable and that **there is no pagination** —
      `next_cursor` is always `""` (`api/audit.go:88`) and no offset param
      exists, so the only way to see older entries is to narrow the date range.
      Assert the notice appears at `total: 5000, logs.length: 1000` and does not
      appear when they are equal.
- [ ] **Step 4:** Do **not** build a pagination control, a "load more" button,
      or a cursor loop. `next_cursor` is dead; wiring a control to it produces
      an infinite no-op. Record this in a comment citing `api/audit.go:96-98`.
- [ ] **Step 5:** Run, confirm failure, implement, verification gate. Commit:
      `git commit -S -m "feat(audit): add integrity banner and result-cap notice"`

## Task 4: SOC2 and GDPR reports

**Files:** Create `src/routes/admin.audit.reports.tsx`,
`src/components/audit/soc2-report-panel.tsx`, `gdpr-report-panel.tsx`, tests.

- [ ] **Step 1 (failing test):** `<Soc2ReportPanel>` — required from/to date
      range, "Generate" renders the JSON report as stat cards (`card.tsx`,
      numbers in `font-heading`) plus a Top Actions bar chart using the vendored
      `chart.tsx`. Field names are PascalCase
      (`compliance_report_service.go:16-33`).
- [ ] **Step 2 (failing test):** `<GdprReportPanel>` additionally requires
      `subject_id` and is blocked from submitting without it — the server
      returns 400 otherwise (`api/audit.go:159-163`). Renders the summary
      counts plus the `Events` table, reusing `<AuditLogTable>` rather than a
      second table implementation.
- [ ] **Step 3 (failing test):** each panel has a "Download CSV" action calling
      the API module with `format: "csv"`, creating an object URL from the blob
      and using the server's filename (`soc2-report.csv` / `gdpr-report.csv`,
      `api/audit.go:134, 183`). Assert the download filename. Offer **JSON and
      CSV only** — assert no PDF option renders; none exists server-side.
- [ ] **Step 4 (failing test — the accuracy caveat):** both panels render a
      `--warning` note whenever `TotalEvents` could be truncated. Both report
      services hard-code `Limit: 1000` (`compliance_report_service.go:82, 148`)
      and the repository caps there anyway (`audit_repository.go:117-119`), so:
      SOC2's `TotalEvents` is counted from the **truncated page**
      (`:92`) and therefore silently understates a busy period; GDPR's
      `TotalEvents` uses the real total but its `Events`, `DataAccess`,
      `Deletions`, and `AuthEvents` come from the truncated page (`:154-164`),
      so **its own numbers will not add up**. Neither is flagged in the
      response. The note must say the report covers at most the newest 1000
      events in the range and to narrow the range for a complete picture.
      Assert the note renders on both panels.
- [ ] **Step 5:** Run, confirm failure, implement, verification gate. Commit:
      `git commit -S -m "feat(audit): add SOC2 and GDPR report panels"`

## Task 5: Retention settings

**Files:** Create `src/routes/admin.audit.settings.tsx`,
`src/components/audit/audit-retention-form.tsx`, test.

- [ ] **Step 1 (failing test):** form pre-fills from `getAuditConfig()`,
      submits `setAuditConfig(days)`, rejects `< 1` client-side with the
      backend's own bound (`compliance_report_service.go:228-230`,
      `api/audit.go:235-238`), and shows 365 as the documented default when the
      row is absent (`compliance_report_service.go:211-224`).
- [ ] **Step 2 (failing test):** helper copy states that this is a
      **database-backed** setting, not a `.rocketvault.yaml` key, and is
      distinct from `soft_delete.retention_days` (`config/config.go:20`) which
      governs soft-deleted resource purge. Assert the disambiguation renders —
      the two are trivially confusable and controlled from different places.
- [ ] **Step 3 (failing test):** copy notes that purge runs on a fixed 24h
      ticker that fires 24h **after** process start, never immediately, and has
      no interval knob (`internal/container/service_container.go:391-400`), so a
      retention change does not take effect at once. Do not render a "purge now"
      button — no endpoint exists.
- [ ] **Step 4:** Run, confirm failure, implement using `field.tsx`,
      `input.tsx`, `card.tsx`. Verification gate. Commit:
      `git commit -S -m "feat(audit): add retention settings form"`

## Self-Review

- All five real endpoints have a task; no verification endpoint is invented,
  and its absence is stated as a backend gap in the integrity banner's own copy
  (Task 3) rather than buried in this plan.
- The PascalCase entry shape is locked in by a test (Task 1) that cites the
  exact bug the same mistake already caused in `internal/vaultapi/audit.go`.
- `integrity_ok` is never over-claimed: filtered views explicitly refuse to
  assert integrity in either direction, which is the only truthful reading of
  `verifyChain`'s page-local comparison.
- The 1000-row ceiling is surfaced in two places it actually bites — the log
  viewer (Task 3) and the report accuracy note (Task 4) — and no pagination
  control is built against the dead `next_cursor`.
- CSV's exact-`Accept`-match requirement is a test assertion (Task 1), not a
  comment, because a `, */*` suffix fails silently by returning JSON.
- No PDF option, no vault filter, no offset param: each absent affordance has a
  negative test or a cited comment so it is not re-added later.
