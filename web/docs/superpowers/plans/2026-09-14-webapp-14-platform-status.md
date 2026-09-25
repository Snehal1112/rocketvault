# RocketVault Dashboard — Platform Status Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development
> for the multi-task breakdown below, or superpowers:executing-plans if executing
> this plan directly, top to bottom.

**Goal:** An operator-facing status screen — liveness/readiness, database health
and connection-pool detail, runtime metrics, and visibility into whether the
Prometheus endpoint is served. Mounted at `/app/admin/status` per the spec's
information architecture.

**Architecture:** See `docs/superpowers/specs/2026-09-08-webapp-dashboard-epics-design.md`
§§ 2, 6 (Epic 14), and `../CLAUDE.md` § Config facts on
`monitoring.enable_metrics`. Builds on Phase 0's `src/api/client.ts`,
`useAuth()`, and the `admin.tsx` layout route. Lowest-priority phase — nothing
depends on it.

**Tech Stack:** unchanged from foundation.

**Conventions to follow:** see foundation plan §Conventions — `@/` alias,
`import type`, `cva`/`cn()`, Prettier, don't edit `src/components/ui/**` in
place. Design tokens from `src/index.css`: teal `--primary`, `font-heading`
(JetBrains Mono) for titles, metric values, and stat numbers, `font-sans` for
prose, `rounded-4xl` cards. Uses the foundation's `--success`/`--warning` tokens
(foundation Task 8) for status pills. Vendored components needed —
`card.tsx`, `badge.tsx`, `alert.tsx`, `table.tsx`, `progress.tsx`, `chart.tsx`,
`tabs.tsx`, `accordion.tsx`, `skeleton.tsx`, `tooltip.tsx`, `button.tsx`,
`empty.tsx` — are all present (`web/.claude/shadcn-components.md`). Do not
`shadcn add` anything.

**Verification gate (run before every commit):**
```bash
cd web && bun run typecheck && bun run lint && bun run test && bun run build
```

## Backend contract (verified — do not re-derive)

Verified against `api/health.go`, `api/metrics.go`, `api/health_test.go`,
`api/health_check_test.go`, `api/metrics_test.go`, `internal/health/health.go`,
`internal/metrics/`, `internal/middleware/middleware.go`, `config/config.go`,
and the router wiring in `api/api.go`.

### Auth posture — the question that decides this epic's route guard

| Route | Method | Auth required? | Proof |
|---|---|---|---|
| `GET /api/v1/health` | GET | **No — public** | skipped at `internal/middleware/middleware.go:268` and `:335` |
| `GET /api/v1/health/live` | GET | **No — public** | `middleware.go:270`, `:337` |
| `GET /api/v1/health/ready` | GET | **No — public** | `middleware.go:269`, `:336` |
| `GET /api/v1/health/database` | GET | **Yes — any authenticated role** | absent from both skip lists (`middleware.go:268-279`, `:335-346`) |
| `GET /metrics` | GET | **No — fully anonymous** | `api/api.go:155`, `api/metrics.go:18` |

- All four health routes are registered on the `Health` subrouter
  (`api/health.go:69-80`), a child of `ApiRoot` (`api/api.go:121`), so the whole
  middleware chain runs; three of the four are exempted by explicit path-suffix
  checks inside `AuthenticationMiddleware` and `AuthorizationMiddleware`.
  `/health/database` is **deliberately** excluded from those lists — see the
  comment at `middleware.go:237-239` stating `isHealthProbe`'s list "is
  deliberately not shared with AuthenticationMiddleware's public-path list,
  which excludes /health/database". Unauthenticated it returns **401**
  `text/plain` `"Unauthorized: missing token"` (`middleware.go:288`). Once
  authenticated, any role passes — `mapEndpointToPermission` falls through to
  `""` (`internal/services/authorization/rbac_service.go:277-278`) and an empty
  permission is allowed (`:190-193`).
- **`GET /metrics` is fully public.** `r.Metrics = api.rootRouter.NewRoute().Subrouter()`
  (`api/api.go:155`) is on the **root** router and **no `.Use(...)` is ever
  called on it** — compare `r.Config` (`api.go:146-147`) and `r.JWKS`
  (`api.go:150-151`), which at least get CORS and security headers. The handler
  is `promhttp.Handler()` (`api/metrics.go:18`). The intent is stated at
  `api/api.go:43` and `:153-154`, and the spec agrees (`security: []`,
  `docs/api-specification.yaml:137-150`). **It also has no CORS middleware**,
  so a cross-origin fetch from the SPA fails regardless of auth; only the
  same-origin Caddy deployment shape works.
- **Discrepancy to know:** `docs/api-specification.yaml:256` declares
  `security: []` for `/api/v1/health/database`, contradicting the code. The
  code is authoritative.

**Conclusion for the route guard.** No backend route in this epic requires the
admin role. The strongest requirement anywhere is "authenticated, any role"
(`/health/database`). Keeping the screen at `/app/admin/status` under
`admin.tsx`'s `requireGlobalAdmin` is therefore an **information-architecture
choice, not a security boundary** — the same data is readable by anyone who can
reach the origin. Task 1 records that decision explicitly instead of letting a
future reader infer a protection that does not exist.

### Response shapes

**`GET /api/v1/health`** (`api/health.go:100-130`, fields at
`internal/health/health.go:39-92` and `api/health.go:35-46`) — embedded
`*health.HealthMetrics` plus `query_metrics`. **There is no top-level `status`,
`version`, or `checks` field.** Keys: `memory_usage` (`alloc_bytes`,
`total_alloc_bytes`, `sys_bytes`, `lookups`, `mallocs`, `frees`,
`heap_alloc_bytes`, `heap_sys_bytes`, `heap_idle_bytes`, `heap_inuse_bytes`,
`heap_released_bytes`, `heap_objects`, `stack_inuse_bytes`, `stack_sys_bytes`,
`gc_sys_bytes`, `next_gc_bytes`, `last_gc_timestamp`, `num_gc`), `cpu_stats`
(`goroutines`, `cgo_calls`), `database_stats` (`open_connections`, `in_use`,
`idle`, `wait_count`, `wait_duration`, `max_idle_closed`, `max_lifetime_closed`,
`utilization_percent`, `query_count`, `slow_query_count`, `avg_query_time`,
`total_query_time`, `health_status`), `uptime`, `go_version`, `goroutines`,
`timestamp`, `query_metrics` (`query_count`, `total_duration`, `avg_duration`,
`slow_queries`).

Type traps: `uptime`, `database_stats.wait_duration`, `avg_query_time`, and
`total_query_time` are Go `time.Duration` → **integer nanoseconds**, not
strings. But `query_metrics.total_duration` and `avg_duration` **are** strings,
pre-formatted by `health.FormatDuration` (`api/health.go:114-115`,
`internal/health/health.go:272-280`) — e.g. `"12.34 ms"`, `"450.00 μs"`. Same
concept, two encodings, in one payload. `database_stats` is the **zero value**
when `db == nil` (`internal/health/health.go:185`).

`database_stats.health_status` literal values (`internal/health/health.go:196-205`):
`"healthy"` | `"warning"` | `"degraded"` | `"critical"`. Never `"ok"`, never
`"unhealthy"`.

**`GET /api/v1/health/live`** — `{"status": "alive"}`, always
(`api/health.go:153-160`; asserted at `api/health_test.go:79`).

**`GET /api/v1/health/ready`** — `{"status": "ready"}` (`api/health.go:145-147`,
`api/health_test.go:92`) or `{"status": "not ready", "error": "..."}`
(`:138-141`). Note the space: `"not ready"`, not `"not_ready"`.

**`GET /api/v1/health/database`** (`api/health.go:163-175` →
`internal/health/health.go:310-406`) — a `map[string]any` whose keys vary:
- `db == nil`: `{"status": "critical", "error": "database not initialized"}`
  (`health.go:312-315`; asserted at `api/health_test.go:105`).
- ping failure: `{"status": "critical", "ping_error": "...",
  "ping_duration_ms": <int>}` (`health.go:323-327`).
- normal: `ping_duration_ms`, `connection_pool` (`open_connections`, `in_use`,
  `idle`, `wait_count`, `wait_duration_ms`, `max_idle_closed`,
  `max_lifetime_closed`, `utilization_percent`), `performance` (`query_count`,
  `slow_query_count`, `avg_query_time_ms`, `total_query_time_ms`,
  `slow_query_percentage`), `status`, `warnings` (**omitted when empty**,
  `health.go:380-382`), `query_test` (`{success, user_count, duration_ms}` or
  `{error, duration_ms}`).

Two backend quirks to code defensively around:
`connection_pool.utilization_percent` is `InUse/OpenConnections*100` with **no
zero guard** (`health.go:341`), so an idle pool can produce `NaN`, which Go's
`encoding/json` refuses to encode — the whole response can fail. And the final
`result["status"] = status` at `health.go:404` **overwrites** the earlier
assignment at `:379`, so a failing query test downgrades `"critical"` to
`"degraded"`.

**Status codes.** `/api/v1/health` returns **200 always** on success
(`api/health.go:121`) — even when `database_stats.health_status == "critical"`.
`/health/live` 200 always. `/health/ready` 200 or **503** (`health.go:138, 145`).
`/health/database` 200 only when `"healthy"`; **503** for `"critical"`,
`"degraded"`, `"warning"`, or any error (`api/health.go:166-172`;
`api/health_check_test.go:66-75`). **So HTTP 200 from `/api/v1/health` means
"reachable", not "healthy"** — the UI must read `database_stats.health_status`.

### Metrics

`/metrics` is **Prometheus text exposition format only** — `promhttp.Handler()`
is the sole handler (`api/metrics.go:18`), content type pinned to
`text/plain; version=0.0.4` (`docs/api-specification.yaml:155`). **There is no
JSON metrics endpoint anywhere.**

When `monitoring.enable_metrics` is `false`, `InitMetrics` returns early
(`api/metrics.go:12-16`) and the route is **never registered** — requests get a
**404** from the catch-all `Handle404` with body
`{"id":"api.not_found","message":"Not found","status_code":404}`
(`api/api.go:176, 201-207`), proven by `api/metrics_test.go:49-59`. Config
default is **`true`** (`config/config.go:55`), overridden only when the key is
explicitly set (`:59-61`), loaded at `bootstrap/bootstrap.go:295` and passed via
`api.WithMetricsEnabled` (`bootstrap/bootstrap.go:443`, `api/options.go:75-78`).

Metric names actually registered on the default registry (hence scrapeable):
`rocketvault_db_query_count`, `rocketvault_db_slow_query_count`,
`rocketvault_db_avg_query_time_ms`, `rocketvault_db_open_connections`,
`rocketvault_db_connections_in_use`, `rocketvault_db_connections_idle`
(`internal/metrics/db_metrics.go:34-54`, registered only when metrics are
enabled, `bootstrap/bootstrap.go:303-304`, refreshed on a
`monitoring.metrics_interval` ticker, default 60s);
`rocketvault_crypto_op_duration_seconds` (HistogramVec, labels
`{op, key_type, cache_hit}`, `internal/metrics/crypto_metrics.go:26-35`);
`rocketvault_vault_rate_limit_exceeded_total` (CounterVec, label `{vault}`,
`internal/metrics/vault_rate_limit_metrics.go:15-20`, wired only when metrics
are enabled, `api/api.go:70-72`). Plus the standard `go_*`/`process_*`
collectors.

**Crucially, the six `rocketvault_db_*` gauges are the same numbers already
available as JSON** from `/api/v1/health`'s `database_stats` and
`/health/database`'s `connection_pool`/`performance`. Only two metrics have no
JSON equivalent anywhere: `rocketvault_crypto_op_duration_seconds` and
`rocketvault_vault_rate_limit_exceeded_total`.

**There is no version or build-info endpoint.** No `/version`, no
`/build-info`. `GET /api/v1/config` returns only `feature_flags`,
`public_api_url`, `sentry_dsn` (`app/app.go:27-31`) — note the doc comment at
`api/config.go:16` claiming it is for authenticated callers is stale; the route
is public (`api/api.go:146-147`). The only version-ish field anywhere is
`go_version` in `/api/v1/health` (`internal/health/health.go:44, 179`), which is
the Go toolchain version, not the RocketVault release.

## File Structure

New: `src/api/health.ts` (+ test), `src/routes/admin.status.tsx`,
`src/components/status/liveness-card.tsx`, `database-health-card.tsx`,
`runtime-card.tsx`, `metrics-availability-card.tsx`, `status-pill.tsx`,
`format-duration.ts` (+ test), tests for each.

Modified: `src/components/app-shell/admin-nav.tsx` (add a "Status" item).

## Task 1: Decide and record the route guard

**Files:** none (decision task; its outcome is a comment at the top of
`src/routes/admin.status.tsx` in Task 3).

- [ ] **Step 1:** The verification above is definitive: `/metrics` and three of
      four health routes are anonymous; `/health/database` needs any
      authenticated token. **No admin guard is required by the backend.**
- [ ] **Step 2:** Decide where the screen lives. The spec's IA (§ 2, § 6) puts
      Epic 14 in the admin branch, and the default is to keep it there —
      operator tooling belongs with operator tooling, and `admin.tsx` already
      provides the shell and guard for free. Record, in the route file, that
      this placement is **presentational, not protective**: the underlying data
      is readable by anyone who can reach the origin, so nothing sensitive may
      be added to this screen on the assumption the guard protects it.
- [ ] **Step 3:** Do **not** build a second public `/app/status` route in this
      epic. It is a product decision with no requirement behind it, and a
      duplicated screen would drift. If one is wanted later, the components
      built here are already guard-agnostic and can be remounted.
- [ ] **Step 4:** No commit — this decision lands with Task 3.

## Task 2: Health API module and the duration formatter

**Files:** Create `src/api/health.ts`, `src/api/health.test.ts`,
`src/components/status/format-duration.ts`, and its test.

- [ ] **Step 1 (failing tests):** `getHealth()` → `GET /api/v1/health`;
      `getLiveness()` → `/api/v1/health/live`; `getReadiness()` →
      `/api/v1/health/ready`; `getDatabaseHealth()` → `/api/v1/health/database`.
      Type each response from the field lists above — in particular, do **not**
      give `/api/v1/health` a top-level `status` field; it has none
      (`api/health.go:100-130`).
- [ ] **Step 2 (failing test):** `getReadiness()` treats **503** as a valid,
      parseable result (`{status: "not ready", error}`), not an exception —
      readiness failing is the thing this screen exists to show. Same for
      `getDatabaseHealth()`, which 503s for `"warning"`, `"degraded"`, and
      `"critical"` alike (`api/health.go:166-172`). Assert both parse a 503 body
      rather than rejecting with `ApiError`.
  ```ts
  // src/api/health.test.ts (excerpt)
  it("parses a 503 readiness body instead of throwing", async () => {
    vi.spyOn(global, "fetch").mockResolvedValue(
      json({ status: "not ready", error: "database ping failed" }, 503)
    )
    await expect(getReadiness()).resolves.toMatchObject({ status: "not ready" })
  })
  ```
- [ ] **Step 3 (failing test):** `getDatabaseHealth()` tolerates the three
      differently-shaped bodies — nil-db, ping-failure, and normal
      (`internal/health/health.go:312-327`) — with `connection_pool`,
      `performance`, `warnings`, and `query_test` all optional. Assert the
      nil-db body (`{"status":"critical","error":"database not initialized"}`,
      `api/health_test.go:105`) parses without a runtime error.
- [ ] **Step 4 (failing test):** `getDatabaseHealth()` survives a malformed
      response. `utilization_percent` has no zero guard
      (`internal/health/health.go:341`) so `encoding/json` can fail to encode
      the whole payload on an idle pool; assert a non-JSON body yields a clean
      `ApiError` with the raw text, not an unhandled parse exception.
- [ ] **Step 5 (failing tests):** `formatNanoseconds(n)` renders the integer-
      nanosecond fields (`uptime`, `wait_duration`, `avg_query_time`,
      `total_query_time`). Assert `uptime: 3_600_000_000_000` → `"1h 0m"` and
      that it is **not** applied to `query_metrics.total_duration`, which is
      already a formatted string from the server (`api/health.go:114-115`).
      Write the negative assertion — double-formatting these is the exact
      mistake the mixed encoding invites.
- [ ] **Step 6:** Run, confirm failure. Implement. Verification gate. Commit:
      `git commit -S -m "feat(api): add health module and duration formatting"`

## Task 3: Status page — liveness, readiness, and the 200-is-not-healthy rule

**Files:** Create `src/routes/admin.status.tsx`,
`src/components/status/liveness-card.tsx`, `status-pill.tsx`, tests. Modify
`admin-nav.tsx`.

- [ ] **Step 1 (failing test):** `<StatusPill>` maps the literal server strings
      to tokens — `"healthy"`/`"alive"`/`"ready"` → `--success`,
      `"warning"` → `--warning`, `"degraded"`/`"critical"`/`"not ready"` →
      `--destructive`. Assert `"not ready"` (with the space,
      `api/health.go:138`) is handled, and that an unrecognised string renders a
      neutral pill with the raw value rather than defaulting to green.
- [ ] **Step 2 (failing test — the central rule):** `<LivenessCard>` derives
      overall health from `database_stats.health_status`, **never** from the
      HTTP status of `/api/v1/health`, which is 200 even when the database is
      critical (`api/health.go:121`). Assert that a 200 response carrying
      `database_stats.health_status: "critical"` renders a destructive pill.
  ```tsx
  it("reports critical from the payload even though the endpoint returns 200", () => {
    render(<LivenessCard health={{ ...healthFixture,
      database_stats: { ...dbStats, health_status: "critical" } }} />)
    expect(screen.getByText(/critical/i)).toBeVisible()
  })
  ```
- [ ] **Step 3 (failing test):** liveness and readiness render as separate
      indicators with their distinct meanings — `/health/live` is "the process
      is up" and is 200 unconditionally (`api/health.go:153-160`), so a green
      liveness pill next to a red readiness pill is a normal, expected state,
      not a contradiction. Assert both render independently.
- [ ] **Step 4:** Poll with TanStack Query `refetchInterval` (30s is ample —
      the DB gauges behind these numbers refresh on a 60s ticker by default,
      `config/config.go:56`). Add a manual Refresh button. Do not poll faster
      than the data changes.
- [ ] **Step 5:** Add the nav item. Run, confirm failure, implement using
      `card.tsx`, `badge.tsx`, `skeleton.tsx`. Record Task 1's guard decision as
      the file's opening comment. Verification gate. Commit:
      `git commit -S -m "feat(status): add platform status page with liveness/readiness"`

## Task 4: Database health and runtime detail

**Files:** Create `src/components/status/database-health-card.tsx`,
`runtime-card.tsx`, tests.

- [ ] **Step 1 (failing test):** `<DatabaseHealthCard>` renders
      `ping_duration_ms`, the `connection_pool` block (with
      `utilization_percent` on `progress.tsx`), and the `performance` block,
      from `getDatabaseHealth()`. Numbers use `font-heading`.
- [ ] **Step 2 (failing test):** `warnings` is **omitted** when empty
      (`internal/health/health.go:380-382`), so the component must treat
      `undefined` as "no warnings" and not render an empty list. When present,
      each entry renders in an `alert.tsx` — the four literal strings are
      "slow database ping response", "connection pool under stress", "high
      percentage of slow queries", "no open database connections".
- [ ] **Step 3 (failing test):** a **401** from `getDatabaseHealth` renders a
      sign-in prompt rather than an error — this is the one route in the epic
      that requires a token (`middleware.go:288`), and it is reachable from a
      logged-out state if the components are ever remounted publicly. The other
      three cards must still render. Assert the partial-render behaviour.
- [ ] **Step 4 (failing test):** `<RuntimeCard>` renders `go_version`,
      `goroutines`, `uptime` (via `formatNanoseconds`), and the `memory_usage`
      heap figures, with the full `memory_usage` block behind
      `accordion.tsx`. It must **not** label `go_version` as the RocketVault
      version — it is `runtime.Version()`
      (`internal/health/health.go:44, 179`). Assert the label reads "Go runtime".
- [ ] **Step 5:** Do **not** add an application version or build SHA anywhere.
      No endpoint returns one; `GET /api/v1/config` carries only
      `feature_flags`, `public_api_url`, `sentry_dsn` (`app/app.go:27-31`).
      Record this as a backend gap in a comment — a `version` field on
      `FrontendConfig` would be a zero-schema-change addition.
- [ ] **Step 6:** Run, confirm failure, implement, verification gate. Commit:
      `git commit -S -m "feat(status): add database health and runtime cards"`

## Task 5: Metrics availability — visibility, not a scraper

**Files:** Create `src/components/status/metrics-availability-card.tsx`, test.

- [ ] **Step 1:** Decide the scope up front, because the obvious implementation
      is the wrong one. `/metrics` returns Prometheus **text**, and six of the
      eight app metrics (`rocketvault_db_*`) are already available as JSON via
      the health endpoints this epic already calls. Writing a text-format parser
      to re-derive numbers the UI already has is duplicated work with a fragile
      parser attached. **Do not build a general Prometheus parser.**
- [ ] **Step 2 (failing test):** `<MetricsAvailabilityCard>` probes
      `GET /metrics` and reports one of three states: served (2xx),
      **disabled** (404 — `monitoring.enable_metrics: false`, the route is never
      registered, `api/metrics.go:12-16`, `api/api.go:176`), or unreachable.
      Assert the 404 branch renders "metrics endpoint disabled" and names the
      config key `monitoring.enable_metrics`, rather than reporting the server
      as down.
  ```tsx
  it("reads a 404 as metrics-disabled, not as an outage", async () => {
    vi.spyOn(global, "fetch").mockResolvedValue(text("", 404))
    render(<MetricsAvailabilityCard />)
    expect(await screen.findByText(/monitoring\.enable_metrics/)).toBeVisible()
  })
  ```
- [ ] **Step 3 (failing test):** when served, the card lists the scrapeable
      metric names (the six `rocketvault_db_*` gauges plus
      `rocketvault_crypto_op_duration_seconds` and
      `rocketvault_vault_rate_limit_exceeded_total`) and links to `/metrics`
      for an operator to point a scraper at. It explicitly notes that the two
      non-`db` metrics have **no JSON equivalent** and are only observable via
      Prometheus — that is the honest statement of what this dashboard cannot
      show.
- [ ] **Step 4:** Add a comment recording that `/metrics` has **no CORS
      middleware** (`api/api.go:155` registers the subrouter with no `.Use`),
      so this probe only works in the same-origin Caddy deployment shape the
      spec assumes (§ 4). In a split-origin dev setup the fetch fails at the
      browser and the card must degrade to "unreachable" rather than throwing —
      assert that branch too. Also verify `Caddyfile`/`Caddyfile.local` actually
      proxy `/metrics`; if they do not, say so in the card's copy instead of
      silently reporting unreachable.
- [ ] **Step 5:** If a later requirement genuinely needs the two
      Prometheus-only metrics on screen, the right fix is a small JSON endpoint
      in the Go backend, not a client-side parser. Record that as the
      recommended path in the comment, and leave it unbuilt — backend changes
      are out of scope for every epic in this spec.
- [ ] **Step 6:** Run, confirm failure, implement, verification gate. Commit:
      `git commit -S -m "feat(status): add metrics endpoint availability card"`

## Self-Review

- The auth question the epic hinged on is answered with router-level evidence,
  not inference: `/metrics` is fully anonymous and three of four health routes
  are public, so the admin guard is IA, not protection — Task 1 records that in
  the route file so nobody later adds sensitive data behind a guard that is not
  one.
- `/health/database`'s authenticated-only status (the one real exception,
  deliberately excluded from the middleware skip lists) drives a concrete
  partial-render test in Task 4 rather than being averaged into "the health
  endpoints".
- The "HTTP 200 does not mean healthy" trap has a dedicated failing test
  (Task 3, Step 2) — it is the single most likely way this screen ends up
  lying.
- The mixed nanosecond-int / pre-formatted-string duration encoding is handled
  by one formatter with a negative test against double-formatting.
- No Prometheus text parser is built, and the reasoning (six of eight metrics
  are already JSON; the other two warrant a backend endpoint, not a client
  parser) is recorded where the next person will look.
- Three absent things are stated rather than invented: no application version
  endpoint, no JSON metrics endpoint, no CORS on `/metrics`.
