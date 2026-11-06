# RocketVault — Full Manual Test Plan

Step-by-step walkthrough for exercising every feature by hand. Complements
`MANUAL_TESTING.md` (endpoint reference table) and `docs/admin-manual.html`
(canonical per-endpoint docs) — this document is the *procedure*, those are
the *reference*.

Each section: **Setup** (if any) → **Steps** → **Expected** → **Watch for**
(known gotchas pulled from `docs/known-bugs.md` and prior test sessions).
Check items off as `[x]` while you go.

**Last reconciled 2026-09-04** against `docs/architecture/azure-keyvault-parity.md` and the
code. Added since the previous pass: key import (JWK) and key-version
addressability in §8.1; per-vault webhook configuration in §5; per-vault rate
limiting as §11.1; the MCP server as §19 (Configuration Reference moved to §20).
§20's config block was refreshed from `.rocketvault.yaml.example`, which had
gained `rate_limit.per_vault`, the `rotation:` scheduler section, and the whole
`mcp:` section. Deliberately **not** added: certificate import, CSR merge and
passphrase-sealed certificate export — all three are specified but not built, so
there is nothing to exercise (see the parity doc §4 and the Phase 3 roadmap).
This pass added two §5 worked examples for self-service provisioning —
quotas and what a soft-delete costs you, and what a provisioning grantee
cannot do — both captured live, in sequence, against one shared scratch
instance. The run surfaced two previously unrecorded bugs, now filed as
`docs/known-bugs.md` § B57 (the `secrets` CLI's legacy global-role gate,
which contradicts a vault's own role assignments) and § B58 (four
service-layer call sites writing audit rows with an empty actor, including
`delete_vault` and `purge_vault`).

---

## 0. Environment Setup

**Do this once, before anything else.**

- [ ] **Use an isolated config + DB, not your working `.rocketvault.yaml` directly.**
      That file is *not* checked in — it is gitignored and generated per clone
      from `.rocketvault.yaml.example` (see `docs/known-bugs.md` § B10), so
      what it contains varies per machine. On this development machine it has
      `hsm.enabled: true` (SoftHSM2) and `oidc.enabled: true` against
      a real, reachable internal OIDC issuer — starting the server with it
      as-is will attempt a live OIDC discovery call at boot and requires SoftHSM2
      configured locally. Copy it to a scratch config and point `database.connection`
      at a throwaway file so repeated test runs don't accumulate state in
      `dev-rocketvault.db`:
      ```bash
      cp .rocketvault.yaml /tmp/rv-test.yaml
      # edit /tmp/rv-test.yaml: database.connection -> /tmp/rv-test.db
      go run main.go --config /tmp/rv-test.yaml serve
      ```
      Decide per test pass whether OIDC/HSM sections should stay enabled (needed
      for §3.3/§8.2) or be turned off for a faster, dependency-free pass — see
      §3.3 and §8.2 for what each requires. **If you leave `hsm.enabled: true`
      with a `lib_path` that doesn't actually exist, the server does not fail
      gracefully — it panics with a nil-pointer dereference and crashes the
      whole process** (see worked example gotcha #3). OIDC, by contrast,
      degrades gracefully to a `Warn` log line if its issuer is unreachable.
- [ ] Confirm build is clean before testing:
      ```bash
      go build ./...
      go vet ./...
      ```
- [ ] `rm -f ~/.rocketvault/sessions/*` if you have stale cached CLI sessions from
      a previous project checkout — stale sessions can mask auth bugs.

#### Worked example: config resolution, and why the checked-in config panics instead of degrading

> **Concept: config resolution has no silent fallback, and "enabled: true"
> means two very different things depending on the subsystem.**
> `initConfig()` (`cmd/root.go:105-130`) resolves exactly one file, in
> order: `--config <path>` if given, otherwise a search for
> `.rocketvault.yaml` **in the current working directory** —
> `viper.AddConfigPath(".")` — not `$HOME`, despite both the `--config`
> flag's own help text ("default is `$HOME/.rocketvault.yaml`") and the
> code comment directly above the fallback ("Find home directory" / "Search
> config in home directory") being stale, dead, commented-out code that's
> never acted on. There is no environment-variable override for *which
> file* gets loaded. If no file resolves at all, there is no
> built-in-defaults fallback: `viper.ReadInConfig()`'s error goes straight
> into `log.Panicf` (`cmd/root.go:123-124`), crashing the process before
> any command logic runs. Separately, this machine's local (gitignored,
> per-clone) `.rocketvault.yaml`
> has both `hsm.enabled: true` and `oidc.enabled: true` — but a boot-time
> failure in each is handled by completely different code paths. OIDC
> failing is caught and logged as a `Warn`; the server boots fine. HSM's
> happy-path failure is a clean Go `error` — but if the configured
> `hsm.lib_path` file doesn't exist at all, the underlying PKCS#11
> library's `New()` returns a nil context, and the very next line
> unconditionally calls `.Initialize()` on it
> (`internal/crypto/pkcs11_provider.go:48-49`) — an unrecovered nil-pointer
> dereference **panic**, not a returned `error`. Nothing in the call chain
> recovers it, so it crashes the whole process.

##### Prerequisites

- Repo cloned, Go toolchain available, `go build ./...` already confirmed clean.
- No admin/session state needed — every step below fails or succeeds before
  authentication would even be reachable.

##### Gotchas this example is built to surface

1. **The `--config` flag's own help text is wrong, and so is the comment
   above the fallback code.** `--config`'s description says "default is
   `$HOME/.rocketvault.yaml`"; the actual fallback (used whenever
   `--config` is omitted) is the **current working directory**. Confirmed
   live: running the binary from an empty scratch dir with no `--config`
   produces `Config File ".rocketvault" Not Found in "[<that exact scratch
   dir>]" ()`, never mentioning `$HOME`.
2. **A missing/unreadable config file is a `panic`, not a clean CLI error
   — for every command, not just `serve`.** `log.Panicf` runs inside
   `cobra.OnInitialize(initConfig)`, before any command's own logic. Exit
   code is `2` (Go's standard unrecovered-panic exit code) via the built
   binary; `go run` itself exits `1` while printing `exit status 2` — the
   visible exit code differs depending on which way you invoke it.
3. **`hsm.enabled: true` with an unreachable library file crashes server
   startup with a raw Go panic, not a logged error — while
   `oidc.enabled: true` with an unreachable issuer only logs a `Warn` and
   boots fine.** Confirmed by actually running the built binary both ways
   (steps 3 and 4 below). The asymmetry is real: OIDC's failure is caught
   explicitly and logged; the HSM path's *only* caught failure is a
   working-library-wrong-token scenario (step 5) — a genuinely absent
   library file skips the `error` path entirely and panics one line
   earlier, inside the PKCS#11 library's own `Initialize()` call.
4. **CLI command failures used to exit `0` unconditionally — FIXED
   `c0bb545` (2026-08-17).** `Execute()` (`cmd/root.go`) called
   `os.Exit(0)` even when `rootCmd.ExecuteContext` returned an error,
   making every CLI failure indistinguishable from success at the shell
   level — confirmed live at the time: a `serve` that failed cleanly with
   a PKCS#11 "token not found" error still exited `0`. Now exits `1` on
   any command error via the `run()` helper extracted in the fix; this is
   still distinct from gotcha #3's panic case — a panic bypasses
   `Execute()`'s return path entirely and exits non-zero (`2`) regardless.
   If you're on a checkout older than `c0bb545`, the old
   behavior still applies — check `git log -1 --format=%H -- cmd/root.go`
   against that hash before trusting `$?` from this CLI.
5. **A bind failure on `server.listen_addr` is swallowed the same way —
   logged as `error`, then immediately followed by a misleading `"HTTP
   server started successfully"` info line, full clean shutdown, exit
   `0`.** `ServerStarter.Start` (`bootstrap/bootstrap.go:77-82`) discards
   `app.StartServer`'s return value outright and unconditionally logs
   success one line later. Practical consequence: running two scratch
   instances at once against the same `server.listen_addr` does **not**
   fail loudly — the second one logs an `error`-level line, then still
   claims success and exits `0` (step 6).
   (This remains `0` even after the `c0bb545` fix to `Execute()`'s
   exit code — the bind failure here never reaches `Execute()`'s error path
   at all, since `ServerStarter.Start` discards `StartServer`'s return
   value before `Execute()` ever sees it. A separate fix, not covered by
   this session's plans.)
6. **The scratch-config pattern in this section's own checklist item 1 is
   incomplete for a truly isolated run — three more fields collide or leak
   by default.** Copying `.rocketvault.yaml` and only editing
   `database.connection` still leaves: `server.listen_addr: ":8774"`
   shared across every scratch instance (gotcha #5); `log.file:
   "./logs/development.log"` resolved relative to the **process's current
   working directory at launch**, not the config file's own location or
   the DB path — so running the documented `go run main.go --config
   /tmp/rv-test.yaml serve` from the repo root as literally written still
   writes into `<repo root>/logs/development.log`, colliding with a normal
   non-scratch dev run; and `master_key`/`jwt_secret`/`bootstrap_token`
   are copied byte-for-byte from the checked-in file — which is git-tracked
   with real, non-placeholder values currently in this repo's history, not
   gitignored. A scratch config built by blind `cp` inherits those same
   committed secret values rather than getting fresh ones.

##### Setup

```bash
cd /path/to/rocketvault
go build ./...
go vet ./...
# Both must be clean before anything below is meaningful. No Makefile exists
# in this repo — these two `go` commands are the canonical baseline.
```

---

**1. Confirm the default (no `--config`) search path, and that a missing
file panics rather than falling back to defaults** — run from an empty
directory so nothing resolves:
```bash
mkdir -p /tmp/rv-empty && cd /tmp/rv-empty
go run /path/to/rocketvault/main.go serve
```
Expect (the scratch dir is what gets searched, not `$HOME`):
```
2026/08/17 10:28:50 Error reading config file: Config File ".rocketvault" Not Found in "[/tmp/rv-empty]" ()
panic: Error reading config file: Config File ".rocketvault" Not Found in "[/tmp/rv-empty]" ()
...
exit status 2
```
`go run` itself exits `1` here; the built binary run directly (next step)
exits `2`.

**2. Same failure, but pointing `--config` at a path that doesn't exist at
all** — confirms the flag takes priority, same panic/exit-code shape:
```bash
go build -o /tmp/rocketvault-bin /path/to/rocketvault
/tmp/rocketvault-bin --config /tmp/does-not-exist.yaml serve
echo "exit: $?"
```
Expect:
```
panic: Error reading config file: open /tmp/does-not-exist.yaml: no such file or directory (/tmp/does-not-exist.yaml)
...
exit: 2
```

**3. Build a real scratch config, point `database.connection` at a scratch
file, disable OIDC for now, but leave `hsm.enabled: true` with a
deliberately wrong `hsm.lib_path`** — simulates "SoftHSM2 not installed":
```bash
cp .rocketvault.yaml /tmp/rv-test.yaml
# edit /tmp/rv-test.yaml:
#   database.connection -> /tmp/rv-test.db
#   oidc.enabled -> false          (isolate this step to HSM only)
#   hsm.lib_path -> /nonexistent/libsofthsm2.so
/tmp/rocketvault-bin --config /tmp/rv-test.yaml serve
echo "exit: $?"
```
Expect the server to get all the way through DB init and JWT key loading,
then crash with a raw Go panic — **not** a clean `Error: ...` line:
```
...
time="..." level=info msg="OSStoreProvider: loaded JWT signing key from OS keychain" kid=...
panic: runtime error: invalid memory address or nil pointer dereference
[signal SIGSEGV: segmentation violation code=0x1 addr=0x0 pc=...]

goroutine 1 [running]:
github.com/miekg/pkcs11.(*Ctx).Initialize.func1(...)
	.../miekg/pkcs11@v1.1.1/pkcs11.go:808
rocketvault/internal/crypto.NewPKCS11KeyProvider(...)
	.../internal/crypto/pkcs11_provider.go:49 +0x71
rocketvault/internal/container.(*ServiceContainer).initializeServices(...)
	.../internal/container/service_container.go:534 +0x2e53
...
exit: 2
```

**4. Same scratch config, flipped — `hsm.enabled: false`, restore
`oidc.enabled: true`** — confirms OIDC degrades gracefully instead of
crashing:
```bash
# edit /tmp/rv-test.yaml: hsm.enabled -> false, oidc.enabled -> true (as checked in)
/tmp/rocketvault-bin --config /tmp/rv-test.yaml serve &
sleep 3
curl -s -w '\n%{http_code}\n' http://localhost:8774/api/v1/health/live
kill %1
```
Expect a `Warn`-level line, then the server continuing to boot and the
health check succeeding:
```
time="..." level=warning msg="Failed to initialise OIDC service; OIDC login will be unavailable" error="oidc: failed to discover issuer ..."
time="..." level=info msg="Server ready to handle requests" address="127.0.0.1:8774" http2=true tls=false websocket=false
```
```json
{"status":"alive"}
200
```
`GET /oidc/login`/`GET /oidc/callback` still register as routes but return
`503 "OIDC is not configured"` at request time — distinct from the routes
not existing at all.

**5. Confirm HSM's *other* failure mode — library file present, but the
configured token label doesn't exist — returns a clean `error` instead of
panicking, and confirm the exit code correctly reflects the failure:**
```bash
# edit /tmp/rv-test.yaml: hsm.enabled -> true, hsm.lib_path -> the real path
# (e.g. /usr/lib/softhsm/libsofthsm2.so), hsm.token_label -> nonexistent-token-label
go run main.go --config /tmp/rv-test.yaml serve
echo "exit: $?"
```
Expect:
```
Error: service container initialization failed: failed to initialize services: failed to initialise PKCS#11 key provider: pkcs11: token with label "nonexistent-token-label" not found
Usage:
  rocketvault serve [flags]
...
exit: 1
```
(Before `c0bb545`, this printed `exit: 0` — see gotcha #4.)

**6. Confirm two scratch instances sharing `server.listen_addr` don't fail
loudly either:**
```bash
/tmp/rocketvault-bin --config /tmp/rv-test.yaml serve &   # first instance, hsm disabled
sleep 4
/tmp/rocketvault-bin --config /tmp/rv-test.yaml serve     # second instance, foreground
echo "exit: $?"
kill %1
```
Expect the second instance's log to show an `error`-level bind failure
immediately followed by a contradictory success line, then a full clean
shutdown and exit `0`:
```
time="..." level=info msg="starting http listener" listenAddr="127.0.0.1:8774"
time="..." level=error msg="Failed to create listener" error="listen tcp 127.0.0.1:8774: bind: address already in use"
time="..." level=info msg="HTTP server started successfully"
...
exit: 0
```

**7. Clean end-to-end sequence — from a fresh scratch config to a passing
health check, avoiding every gotcha above:**
```bash
cd /path/to/rocketvault
go build ./... && go vet ./...
cp .rocketvault.yaml /tmp/rv-test.yaml
# edit /tmp/rv-test.yaml:
#   database.connection -> /tmp/rv-test.db
#   hsm.enabled  -> false   (or leave true only if SoftHSM2 is genuinely set up)
#   oidc.enabled -> false   (or leave true — it degrades gracefully either way)
rm -f ~/.rocketvault/sessions/*   # stale CLI sessions from a prior checkout — see §3.4
cd /tmp   # run from outside the repo so logs/ doesn't land in the checkout
go run /path/to/rocketvault/main.go --config /tmp/rv-test.yaml serve &
sleep 3
curl -s -w '\n%{http_code}\n' http://localhost:8774/api/v1/health/live
curl -s -w '\n%{http_code}\n' http://localhost:8774/api/v1/health/ready
kill %1
```
Expect both health checks to return `200`, and `/tmp/rv-test.db` to exist
as a non-empty SQLite file afterward — confirming the scratch config, not
the checked-in one, was actually loaded.

##### Cleanup

```bash
rm -f /tmp/rv-test.yaml /tmp/rv-test.db /tmp/rocketvault-bin /tmp/does-not-exist.yaml
rm -rf /tmp/rv-empty /tmp/logs
```
No server-side state to worry about — every scratch DB above is a
throwaway SQLite file, and step 7's `cd /tmp` specifically avoids writing
into the repo's own `logs/` directory (gotcha #6).

---

## 1. Build, Health, and Docs Build

- [ ] `go build ./...` — succeeds with no errors.
- [ ] `go test ./...` — full suite passes (baseline before manual testing).
- [ ] Start server: `go run main.go --config /tmp/rv-test.yaml serve`
- [ ] `curl localhost:8774/api/v1/health/live` → `200`, no auth.
- [ ] `curl localhost:8774/api/v1/health/ready` → `200` once DB is up.
- [ ] `curl localhost:8774/api/v1/health` → full status JSON.
- [ ] `curl localhost:8774/api/v1/health/database` → DB-specific health (pool stats,
      slow-query threshold reflects `monitoring.slow_query_threshold`). **Requires
      auth, unlike the three endpoints above it** — its path doesn't match any of
      the `/health`, `/health/ready`, `/health/live` suffix checks the middleware
      skip-lists use, so it falls through to a normal Bearer-token check. Any
      authenticated user works, not just admin — see worked example gotcha #1.
- [ ] `curl localhost:8774/api/v1/config` → frontend config (public_api_url, sentry_dsn), no auth.
- [ ] `curl localhost:8774/jwks.json` → JWKS public keys, no auth.
- [ ] If `monitoring.enable_metrics: true`: `curl localhost:8774/metrics` → Prometheus
      text format, includes `rocketvault_db_*` gauges. Toggle the config flag off,
      restart, confirm the route now 404s.
- [ ] **Docs build**: `./scripts/docs.sh build` renders markdown → styled HTML
      siblings of `docs/admin-manual.html`. `./scripts/docs.sh serve` and open a
      couple of rendered pages — confirm nav/search/styling match `admin-manual.html`.
      `./scripts/docs.sh package` produces a tar.gz/zip with checksums — verify the
      checksum file matches (`sha256sum -c`).
- [ ] Watch for: **serve must not double-init.** Startup log should show exactly one
      "Rotation scheduler started" line and one DB connection opened (see known-bugs
      B4 — this was fixed, confirm it stays fixed).

#### Worked example: build/vet/test, the four health endpoints, config/JWKS/metrics, and the docs pipeline

> **Concept: §1 is the only section that never touches the database's
> business data — it's entirely about "does the binary work at all."**
> Four things here are easy to get subtly wrong if you only skim the
> checklist above: **(1)** three of the four health-ish endpoints
> (`/health`, `/health/live`, `/health/ready`) are genuinely public, but
> the fourth, `/health/database`, is not — it sits one path segment below
> where the public-endpoint allowlist stops matching, so it silently
> requires a valid Bearer token like any other API route; **(2)** `/metrics`
> is either fully public or a genuine `404`, controlled by whether the
> route gets *registered at all* at startup — there's no third
> "exists but denies" state; **(3)** `./scripts/docs.sh build` overwrites
> `.html` files that are already committed to the repo, so running it
> leaves your working tree dirty even on a no-op content change unless you
> diff/revert afterward; **(4)** B4 (double DB/container init on `serve`)
> is fixed, and this example shows exactly what correct startup logging
> looks like now, so a regression is recognizable on sight.

##### Prerequisites

- A scratch config + DB per **§0** — §1 doesn't need OIDC/HSM, so it's
  fine (and faster) to disable both in the scratch config for this pass.
- `curl` and `jq` (optional, for readability).
- `rocketvault` CLI built and admin bootstrapped per **§2**, with
  `ROCKETVAULT_TOTP_SECRET` exported — needed only for step 6's
  authenticated `/health/database` call.
- A clean `git status` before you start, so step 10's docs-build diff is
  easy to interpret.

##### Gotchas this example is built to surface

1. **`/health/database` requires a valid Bearer token; `/health`,
   `/health/ready`, and `/health/live` do not — and this is genuinely
   inconsistent, not a documentation error.** `AuthenticationMiddleware`
   (`internal/middleware/middleware.go:245-256`) skips auth only for paths
   whose suffix is exactly `/health`, `/health/ready`, or `/health/live`;
   `/health/database` matches none of those three, so it falls through to
   the normal Bearer-token check — missing header returns `401` with
   plain-text body `Unauthorized: missing token`. `AuthorizationMiddleware`
   has the identical three-item skip list (`middleware.go:312-323`), so
   `/health/database` also runs through the RBAC check — but
   `mapEndpointToPermission` returns `""` for every `/health` path (its
   final fallback: "Health and other endpoints don't require specific
   permissions"), so once *any* authenticated user presents a valid token,
   no specific permission is ever consulted. Net effect: `/health`,
   `/live`, `/ready` are fully anonymous; `/health/database` needs
   "logged in as anyone," not admin specifically.
2. **`/metrics` is registered-or-not, not allowed-or-denied.** `InitMetrics`
   (`api/metrics.go:12-20`) only registers the route when `enabled` is
   `true`; when `false` it logs `"Metrics endpoint disabled
   (monitoring.enable_metrics=false)"` and returns without registering
   anything, so the route falls through to gorilla/mux's default `404
   page not found` — there's no auth check to fail, the handler simply
   doesn't exist. When enabled, `/metrics` has **no** auth middleware at
   all (it's a bare root route, not nested under the API's auth-wrapped
   subrouter). Also note the path: `/metrics`, not `/api/v1/metrics` —
   same for `/jwks.json`.
3. **`docs.sh build`'s output files are already `git`-tracked, not
   gitignored scratch output.** Every `.html` in `scripts/docsgen/docs.go`'s
   `docsList` (`MANUAL_TESTING.html`, `docs/usage-guide.html`, etc.) is
   committed. Running `build` regenerates and overwrites them in place —
   if the source `.md` hasn't changed, the diff should be empty, but the
   mtimes change regardless. `dist/` (where `package` writes its
   `.tar.gz`/`.zip`/`.sha256`) **is** gitignored, so only `build`'s output
   needs a post-test diff check, not `package`'s.
4. **The full-status `/health` body's `uptime` field is a raw integer
   (nanoseconds), while its own nested `query_metrics.total_duration`/
   `avg_duration` are pre-formatted strings — same response, two different
   duration representations.** `HealthMetrics.Uptime` is a plain
   `time.Duration` with no custom `MarshalJSON`, so it serializes as a
   JSON number of nanoseconds, but `query_metrics`'s duration fields
   explicitly run through a formatter producing strings like `"1.23 ms"`.
   The same asymmetry applies to every `time.Duration` field inside
   `database_stats` versus `/health/database`'s own separate response,
   which reports everything already converted to milliseconds
   (`ping_duration_ms`, `wait_duration_ms`). Three different duration
   encodings across two endpoints in the same response family.
5. **B4 (double DB/container init on `serve`) is still fixed** — confirmed
   by re-reading the current code, not just trusting `known-bugs.md`.
   `serveCmd.PersistentPreRunE` is `servePreRun`, which only installs a
   logger on the context and explicitly does **not** build a DB
   connection or `ServiceContainer` — `bootstrap.Boot` remains the single
   real initializer. The one log line to look for is `"Rotation scheduler
   started"` with an `interval` field, logged exactly once — `app.StartServer`
   no longer logs its own redundant success line. Two of that line, or two
   `"database initialized"`-style lines near startup, would mean B4
   regressed.

##### Setup

```bash
BASE=http://localhost:8774
```

---

**1. Build, vet, and full test suite.** There is no `Makefile` in this
repo — these three `go` commands, run directly from repo root, are the
complete verification sequence:
```bash
go build ./...
go vet ./...
go test ./...
```
Expect no output at all for `build`/`vet` (silence = success), and every
package printing `ok` for `test` (no `FAIL` anywhere, `?` for packages
with no test files). Two packages are worth knowing about up front so a
long pause doesn't look like a hang: `internal/crypto` (~18s,
PKCS#11/software key-provider tests) and `internal/vaultclient` (~70s, the
slowest single package).

**2. Start the server:**
```bash
go run main.go --config /tmp/rv-test.yaml serve
```
Watch the startup log for gotcha #5 — exactly **one** `"Rotation
scheduler started" interval=...` line, and no duplicated
"database initialized"-style lines from two separate boot sequences.

**3. Liveness — public, no token:**
```bash
curl -s -w '\n%{http_code}\n' $BASE/api/v1/health/live
```
Expect `200`: `{"status":"alive"}`

**4. Readiness — public, no token:**
```bash
curl -s -w '\n%{http_code}\n' $BASE/api/v1/health/ready
```
Expect `200`: `{"status":"ready"}`

**5. Full status — public, no token, the largest of the four bodies:**
```bash
curl -s -w '\n%{http_code}\n' $BASE/api/v1/health
```
Expect `200` with top-level keys `memory_usage`, `cpu_stats`,
`database_stats`, `uptime`, `go_version`, `goroutines`, `timestamp`,
`query_metrics`. Confirm gotcha #4 directly: `uptime` and
`database_stats.wait_duration`/`avg_query_time`/`total_query_time` are
bare integers (nanoseconds), while `query_metrics.total_duration`/
`avg_duration` are formatted strings like `"0.37 ms"` — same response,
two encodings.

**6. Database health — the one that's actually gated (gotcha #1). First,
no token:**
```bash
curl -s -w '\n%{http_code}\n' $BASE/api/v1/health/database
```
Expect `401`, plain text: `Unauthorized: missing token`. Now with a valid
token from **any** authenticated user — admin's session from §2 works,
but a plain non-admin `user`-role token would work identically, since the
permission check is a no-op for `/health` paths:
```bash
TOTP_CODE=$(go run scripts/totp_generator.go -secret="$ROCKETVAULT_TOTP_SECRET" 2>&1 | grep -m1 -oP '(?<=--totp-code )\S+')
TOKEN=$(curl -s $BASE/api/v1/users/login -H 'Content-Type: application/json' \
  -d "{\"username\":\"admin\",\"password\":\"admin123\",\"totp_code\":\"$TOTP_CODE\"}" | jq -r .token)
curl -s -w '\n%{http_code}\n' $BASE/api/v1/health/database -H "Authorization: Bearer $TOKEN"
```
Expect `200` with `status: "healthy"` and nested `connection_pool`/
`performance`/`query_test` objects, all durations in milliseconds. `status`
can also come back `"warning"`/`"degraded"`/`"critical"` under load, which
flips the HTTP status to `503` even though the body still decodes fine —
`"healthy"` is the only status that returns `200`.

**7. Frontend config — public, no token:**
```bash
curl -s -w '\n%{http_code}\n' $BASE/api/v1/config
```
Expect `200`: `{"feature_flags":{},"public_api_url":"","sentry_dsn":""}`
on an empty scratch config with no explicit frontend values set.

**8. JWKS — public, no token, no `/api/v1` prefix:**
```bash
curl -s -w '\n%{http_code}\n' $BASE/jwks.json
```
Expect `200`, RFC 7517 shape: `{"keys":[{"kty":"RSA","use":"sig","alg":"RS256","kid":"...","n":"...","e":"..."}]}`
— `alg: RS256` for this repo's default `jwt.key_source: "os_store"`.

**9. Metrics toggle — confirm both states (gotcha #2).** With
`monitoring.enable_metrics: true` (the checked-in default):
```bash
curl -s -w '\n%{http_code}\n' $BASE/metrics | head -5
```
Expect `200`, Prometheus text format, `rocketvault_db_*` gauges somewhere
in the body. Edit the scratch config to `false`, restart, repeat:
```bash
curl -s -w '\n%{http_code}\n' $BASE/metrics
```
Expect `404 page not found` — gorilla/mux's bare default, since the route
was never registered. Startup log should show `"Metrics endpoint disabled
(monitoring.enable_metrics=false)"` instead of `"Metrics API route
initialized"`.

**10. Docs build:**
```bash
./scripts/docs.sh build
```
Expect one `built <path>` line per tracked doc. Confirm gotcha #3:
```bash
git status --porcelain -- '*.html'
```
Expect either no output (byte-identical regeneration) or modified-but-not-new
entries for already-tracked `.html` files — any untracked (`??`) entry
means the doc list and repo state have drifted.

**11. Docs serve — preview a couple of pages:**
```bash
./scripts/docs.sh serve
```
Open `http://localhost:8000/docs/admin-manual.html` and
`http://localhost:8000/docs/usage-guide.html`, confirm nav/search/styling
match. `Ctrl+C` to stop.

**12. Docs package — build a distributable bundle and verify checksums:**
```bash
./scripts/docs.sh package
cd dist && sha256sum -c rocketvault-docs-*.tar.gz.sha256 && sha256sum -c rocketvault-docs-*.zip.sha256 && cd ..
```
Expect `<filename>: OK` for both. The checksum file records only the
archive's basename, so verification must run from inside `dist/`. Spot-check
the archive layout preserves real repo-relative paths:
```bash
tar -tzf dist/rocketvault-docs-*.tar.gz | head -10
```
Expect entries like `rocketvault-docs-<version>/docs/admin-manual.html` —
`index.html` at the archive root is a generated redirect to that file, not
a rendered doc itself.

##### Cleanup

```bash
# Stop the server (Ctrl+C on step 2's process).
rm -rf dist/   # gitignored, safe to remove outright
git checkout -- '*.html' 2>/dev/null || true
git status --porcelain -- '*.html'   # confirm clean before moving on
```

---

## 2. Admin Bootstrap (CLI-only)

There is **no HTTP route** for this — `POST /api/v1/users/admin` does not exist
(404). Admin bootstrap is CLI-only.

- [ ] ```bash
      rocketvault --config /tmp/rv-test.yaml users admin \
        --admin-username admin --admin-password admin123 \
        --bootstrap-token <value of bootstrap_token in your config>
      ```
- [ ] Expected: prints a TOTP secret as an `otpauth://` URL. Extract the base32
      secret and export it as `ROCKETVAULT_TOTP_SECRET` — the repo's own
      `scripts/totp_generator.go` reads this exact env var automatically, so
      every later step in this plan can just run
      `go run scripts/totp_generator.go` instead of reaching for an external
      `oathtool` install:
      ```bash
      export ROCKETVAULT_TOTP_SECRET=$(echo "$OTPAUTH_URL" | sed -n 's/.*secret=\([A-Z2-7]*\).*/\1/p')
      go run scripts/totp_generator.go   # prints the current code + a countdown bar
      ```
      (`oathtool --totp --base32 "$ROCKETVAULT_TOTP_SECRET"` works too if you
      prefer it, but the in-repo generator needs no separate install and shows
      the 30s countdown so you know how much time is left before it expires.)
- [ ] Re-run the same command a second time with the same bootstrap token → should
      fail with `invalid or used bootstrap token` — but per the worked example
      below, this is enforced by "a user already exists," not by the token's
      `used` flag; both would reject it, but only the user-count check ever fires.
- [ ] Run with a wrong `--bootstrap-token` → rejected, same error text as above —
      the CLI never distinguishes *why* (wrong token vs. already bootstrapped vs.
      already-used token); see worked example gotcha #2 for how to tell them apart.

#### Worked example: bootstrapping the trust root, and the four ways it can refuse

> **Concept: the bootstrap token is not the security boundary — an empty
> `users` table is.** `rocketvault users admin` is the only way an account
> ever comes into existence without an existing admin, so it is the trust
> root of every other section in this plan. Its RunE does exactly three
> things in order (`cmd/users/admin.go:63-83`): `ValidateBootstrapToken`,
> then `CreateUser`, then `InvalidateBootstrapToken` — no transaction
> around them. What actually makes bootstrap single-use is *not* the
> `used` column you'd expect: `UserRepository.ValidateBootstrapToken`
> (`internal/repositories/user_repository.go:420-453`) checks
> `SELECT COUNT(*) FROM users` **first** (line 423) and bails at line 430
> if any user exists at all, before it has even looked at the token you
> passed. The `used` flag is the second gate, not the first. And the whole
> command never touches the HTTP server — the CLI opens the database
> directly (`cmd/root.go:263-264`), so §2 works with `serve` stopped, and
> the token's real boundary is "who can write this database file."

##### Prerequisites

- A **fresh** scratch DB per §0 — this example is only meaningful against a
  database with zero users. If you have already bootstrapped, delete the
  scratch DB file and start over; there is no "reset bootstrap" command.
- The `bootstrap_token` value from the config the **CLI** will load (not the
  server's) — read it out of your own `.rocketvault.yaml` (or scratch config) at
  test time. **Do not paste the literal value back into this file.** An earlier
  revision of this document quoted a then-live token inline; that token has since
  been rotated and `.rocketvault.yaml` is no longer git-tracked (`docs/known-bugs.md`
  § B10, `docs/security/security-incident-2026-03-07.md`). Reproducing a real secret in a
  doc is the incident, not a convenience. See gotcha #3.
- `sqlite3` (steps 4 and 6 inspect the DB directly) and `jq` (step 5).
- The server does **not** need to be running for steps 1-4 and 6-9. Step 5
  (login) does need it.
- **Do not enable OIDC on a not-yet-bootstrapped instance** — see gotcha #1
  for why that can permanently lock you out of local admin creation.

##### Gotchas this example is built to surface

All eight are real, verified-against-source behaviors, not hypotheticals.

1. **Single-use is enforced by "no users may exist", not by the token's
   `used` flag — and that gate is broader than it looks.**
   `ValidateBootstrapToken` returns `(false, nil)` at
   `user_repository.go:430-433` whenever `SELECT COUNT(*) FROM users` is
   non-zero, *before* the token lookup at line 437. So the second `users
   admin` run below fails on the users-exist check, not on the
   already-used check — both would reject it, but only the first ever
   fires. The consequence worth internalizing: **any** user blocks
   bootstrap, including one auto-provisioned by an OIDC login
   (`FindOrCreateExternalUser`, `user_service.go:183-219`, creates a
   `model.RoleUser` row with no admin involvement). If OIDC is enabled and
   anyone completes a callback before you bootstrap, `users admin` is dead
   forever on that database and there is no CLI path to recover — you'd be
   editing the `users` table by hand.
2. **Three completely different failure reasons produce one identical
   error string.** "Users already exist" (line 431), "token not found"
   (line 439), and "token already used" (line 448) each log a distinct
   `LogAuditError` message but all return the same `(false, nil)`, which
   `cmd/users/admin.go:67-69` flattens into `invalid or used bootstrap
   token`. The only way to distinguish them is the log line or the
   `audit_logs` row — and audit persistence *is* live on the CLI path,
   because `NewServiceContainer` wires `SetAuditPersister` onto the same
   logger `persistentPreRun` built.
3. **The token is stored in plaintext and compared with a plain SQL `=`.**
   The schema is `token TEXT PRIMARY KEY` with no hash column
   (`internal/db/db.go:531-535`); `seedBootstrapToken` (`db.go:934-957`)
   reads `viper.GetString("bootstrap_token")` and inserts it verbatim;
   validation is `SELECT used FROM bootstrap_tokens WHERE token = ?`
   (`user_repository.go:437`) — an indexed B-tree equality, not
   constant-time. Don't overstate the timing angle: this path is only
   reachable by someone who can already open the database file (gotcha
   #4), so a timing oracle buys an attacker nothing they don't already
   have. The genuinely actionable fact is the cleartext at rest in **two**
   places — the DB row and the config file — with the config file's copy
   currently committed to git.
4. **`users admin` never contacts the server; it opens the database
   itself, and will create and seed that database if it doesn't exist.**
   `persistentPreRun` runs `db.NewRepository(log)` +
   `database.InitializeDB()` before *every* CLI command, and `InitializeDB`
   is what runs schema creation and `seedBootstrapToken`. Two
   consequences: the `--bootstrap-token` you pass must match the
   `bootstrap_token` in whatever config **the CLI** loaded, not the
   server's; and pointing the CLI at a different `--config` seeds *that*
   config's token into the same DB as unused. Also note `InitializeDB()`'s
   error is discarded outright (`//nolint:errcheck,gosec` on line 264), so
   a genuine DB init failure surfaces later as a confusing downstream error
   rather than at the point of failure.
5. **The token is consumed only *after* `CreateUser` succeeds, and there
   is no transaction — so the interesting failure is the reverse of the
   one you'd worry about.** If `CreateUser` fails, RunE returns at
   `admin.go:78` and `InvalidateBootstrapToken` is never reached: the
   token stays unused and the attempt is retryable, which is correct. But
   if `CreateUser` **succeeds** and `InvalidateBootstrapToken` then fails
   (`admin.go:81-83`), you get `Error: failed to invalidate bootstrap
   token: ...` describing a command that already committed an admin user —
   and because the `fmt.Printf` calls are at lines 85-87, *after* that
   error return, **the TOTP secret is never printed**. You would have an
   admin account whose MFA secret exists only in `users.totp_secret` in
   the database. Gotcha #1's user-count check still blocks anyone reusing
   the left-unused token, so this is a recoverability hazard, not an auth
   bypass — but know it before you panic.
6. **`admin`'s presence on the no-auth allowlist is the intentional,
   compensated exemption — unlike `backup`, which was a real bug.**
   `systemCmds` (`cmd/root.go:237-249`) contains `"admin": true // Allow
   admin registration without prior authentication`; matching is by leaf
   name or parent name, and since `admin`'s parent `users` is *not* on the
   list, it matches on its own name. The exemption is unavoidable (there
   is no account to authenticate as yet) and its compensating control is
   precisely the empty-users-table check in gotcha #1. That this list needs
   per-entry justification is not theoretical: `backup` sat on this same
   list until commit `47c89fe` (2026-08-13), giving `backup
   create/list/restore` unauthenticated dump and restore of the entire
   database. Note also that matching on the bare name means any future
   command anywhere in the tree named `admin` silently inherits this
   exemption.
7. **What's printed as "TOTP Secret" is an `otpauth://` URL, and the
   issuer in it says `PasswordManager`, not RocketVault.** `CreateUser`
   stores `totpKey.Secret()` in the DB but returns `totpKey.URL()`
   (`user_service.go:152` vs `:174`), and `admin.go:86` prints that URL
   under the label `TOTP Secret:`. `GenerateSecret`
   (`totp_service.go:60-70`) passes only `Issuer` (hardcoded
   `"PasswordManager"` at `user_service.go:140`), `AccountName`, and
   `SecretSize: 20`; period/digits/algorithm come from pquerna/otp's
   `totp.Generate` defaults (30 / 6 / SHA1). Exact shape:
   `otpauth://totp/PasswordManager:admin?algorithm=SHA1&digits=6&issuer=PasswordManager&period=30&secret=<32-char base32, unpadded>`.
   Those parameters agree with what login actually enforces —
   `NewTOTPService` sets period 30, skew 2, digits 6, SHA1, used by
   `ValidateCode` — so §3.1's skew arithmetic and §3.2's "no replay
   tracking" note both hold. The `PasswordManager` issuer is cosmetic
   (it's the label your authenticator shows) but is baked into the
   *caller*, not the TOTP service, so it cannot be configured.
8. **Every failure below used to still exit `0` — FIXED `c0bb545`
   (2026-08-17).** `Execute()` (`cmd/root.go:73-78`) called `os.Exit(0)`
   inside its `if err != nil` branch. Combined with the fact that no
   `SilenceUsage`/`SilenceErrors` is set anywhere under `cmd/`, a failed
   bootstrap printed `Error: ...` followed by the full usage block and
   returned `$? == 0` regardless. **This was not specific to bootstrap —
   every CLI command in this codebase exited 0 on failure**, until the fix.
   Step 9 now demonstrates the corrected `exit=1` behavior. If you're
   testing against a checkout older than `c0bb545`, the old
   behavior still applies.

##### Setup

```bash
CFG=/tmp/rv-test.yaml
DB=/tmp/rv-test.db
BOOTSTRAP_TOKEN=$(grep '^bootstrap_token:' "$CFG" | cut -d'"' -f2)
```

---

**1. Confirm you are actually in the bootstrappable state** — an empty
`users` table is the real precondition (gotcha #1), so check it rather
than assuming a fresh file:
```bash
sqlite3 "$DB" 'SELECT COUNT(*) FROM users;' 2>/dev/null || echo "no DB yet — fine"
```
Expect `0`, or the "no DB yet" message. Anything greater than `0` means
step 2 will fail no matter which token you pass.

**2. Bootstrap the first admin:**
```bash
go run main.go --config "$CFG" users admin \
  --admin-username admin --admin-password admin123 \
  --bootstrap-token "$BOOTSTRAP_TOKEN"
```
Expect exactly three lines on stdout (`cmd/users/admin.go:85-87`), after
the usual logrus startup noise:
```
Admin user admin created successfully with ID: 3f8c1b2a-....-............
TOTP Secret: otpauth://totp/PasswordManager:admin?algorithm=SHA1&digits=6&issuer=PasswordManager&period=30&secret=JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP
Configure the TOTP secret in your authenticator app for MFA.
```
Note `PasswordManager`, not RocketVault — that's gotcha #7, and it is what
your authenticator app will display. **This is the only time the secret
is ever printed**; capture it now.

**3. Extract the base32 secret and export it as `ROCKETVAULT_TOTP_SECRET`**
— the same convention every later section of this plan relies on. The
label says "TOTP Secret" but the value is a URL, so pull the `secret=`
parameter out of it:
```bash
OTPAUTH_URL='otpauth://totp/PasswordManager:admin?algorithm=SHA1&digits=6&issuer=PasswordManager&period=30&secret=JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP'
export ROCKETVAULT_TOTP_SECRET=$(echo "$OTPAUTH_URL" | sed -n 's/.*secret=\([A-Z2-7]*\).*/\1/p')
go run scripts/totp_generator.go
```
Expect the generator's block with a current code and countdown:
```
RocketVault TOTP — user: admin
─────────────────────────────────
Current code : 481920
Valid for    : 24s  [████████████░░░]
```
Add the `export` line to your shell profile for the rest of this test pass.

**4. Verify the database state the command actually produced** — one user
row, and the token flipped to used:
```bash
sqlite3 "$DB" 'SELECT username, role, auth_provider, length(totp_secret) FROM users;'
sqlite3 "$DB" 'SELECT token, used FROM bootstrap_tokens;'
```
Expect `admin|admin|local|32` (the stored `totp_secret` is the raw base32
from `totpKey.Secret()`, not the URL — gotcha #7) and your token with
`used` = `1`. The `users` row is what makes bootstrap single-use; the
`used` flag is the belt to that suspenders.

**5. Confirm the new admin can immediately log in** — this is the handoff
into §3.1. Start the server, then:
```bash
TOTP_CODE=$(go run scripts/totp_generator.go 2>&1 | grep -m1 -oP '(?<=--totp-code )\S+')
curl -s -w '\n%{http_code}\n' http://localhost:8774/api/v1/users/login \
  -H 'Content-Type: application/json' \
  -d "{\"username\":\"admin\",\"password\":\"admin123\",\"totp_code\":\"$TOTP_CODE\"}" | jq .
```
Expect `200` and the five-field body from §3.1 step 1, with
`"role":"admin"`. If the TOTP is rejected here but the password isn't, the
secret you exported in step 3 is wrong — but the API won't tell you which
check failed (§3.1 gotcha #2); run the CLI form to get the specific error:
```bash
go run main.go --config "$CFG" users login --username admin --password admin123 --totp-code "$TOTP_CODE"
```

**6. Negative — reuse the same token a second time.** This is the
single-use test, and it does not fail for the reason the error text
suggests:
```bash
go run main.go --config "$CFG" users admin \
  --admin-username admin2 --admin-password admin123 \
  --bootstrap-token "$BOOTSTRAP_TOKEN"
```
Expect on stderr, followed by the full cobra usage block:
```
Error: invalid or used bootstrap token
```
Now prove *which* gate rejected it (gotcha #2) — the users-exist check at
`user_repository.go:430`, not the `used` flag:
```bash
sqlite3 "$DB" "SELECT action, details FROM audit_logs WHERE action='validate_bootstrap_token' ORDER BY timestamp DESC LIMIT 1;"
```
Expect the details string to contain `message=Bootstrap not allowed: users
exist` — **not** "Bootstrap token already used", even though the token
genuinely is used.

**7. Negative — a wrong token entirely, producing identical CLI output:**
```bash
go run main.go --config "$CFG" users admin \
  --admin-username admin3 --admin-password admin123 \
  --bootstrap-token totally-wrong-token
```
Expect the same `Error: invalid or used bootstrap token` — byte-identical
to step 6, and on this already-bootstrapped database the audit reason is
still `Bootstrap not allowed: users exist`, because the user-count check
fires before the token is ever read. To see `Bootstrap token not found`
instead, this needs to run against a **fresh, userless** DB — three
different causes, one error string, is the gotcha #2 payoff, and it means
"invalid or used bootstrap token" in a support ticket tells you
essentially nothing on its own.

**8. Negative — missing required flags.** The check is in the command
itself, before any service call (`cmd/users/admin.go:52-54`), so it fires
without touching the token or the database:
```bash
go run main.go --config "$CFG" users admin --admin-username admin
```
Expect:
```
Error: admin-username, bootstrap-token, and admin-password are required
```
All three flags are checked together in one condition, so the message is
the same whichever one (or two) you omit — it never names the missing one.

**9. Confirm the exit code correctly reflects failure** (gotcha #8 — fixed
`c0bb545`; kept as a regression check rather than removed):
```bash
go run main.go --config "$CFG" users admin --admin-username admin >/dev/null 2>&1
echo "exit=$?"
```
Expect `exit=1`. (Before `c0bb545`, this printed `exit=0` despite
the command genuinely failing on missing required flags — see gotcha #8.)

**10. Confirm there is genuinely no HTTP route for this** — the checklist
above claims 404; verify the body shape too, since it's this API's JSON
404 handler rather than mux's plain-text default:
```bash
curl -s -w '\n%{http_code}\n' -X POST http://localhost:8774/api/v1/users/admin \
  -H 'Content-Type: application/json' -d '{}'
```
Expect `404` with exactly:
```json
{"id":"api.not_found","message":"Not found","status_code":404}
```
Nothing under `api/` registers an `/admin` path — admin bootstrap is
reachable only by someone with local database write access, which is the
actual security model described in gotcha #4.

##### Cleanup

```bash
unset OTPAUTH_URL
```
Keep `ROCKETVAULT_TOTP_SECRET` exported — every later section needs it.
Nothing else to undo: the admin user and the consumed token are the
intended end state of this section. To rerun §2 from scratch, delete the
scratch DB file entirely (`rm -f /tmp/rv-test.db`) — deleting just the
`bootstrap_tokens` row is not enough, because `ValidateBootstrapToken`
checks the `users` table first, and deleting just the `users` rows is not
enough either unless you also reset `used` or put a new value in the
config's `bootstrap_token` (which `seedBootstrapToken` will then insert as
unused on the next CLI invocation).

---

## 3. Authentication

### 3.1 Local login (password + TOTP)

- [ ] `POST /api/v1/users/login` with correct username/password/TOTP → `200`, JWT + refresh token.
- [ ] Wrong password → `403` (not `401` — `loginUser` uses `SetPermissionError`,
      which hardcodes 403; see the worked example below for the full citation).
- [ ] Wrong/stale TOTP code → `403`, identical body to wrong password — the API
      never reveals which check failed (see worked example gotcha #2).
- [ ] `POST /api/v1/users/refresh` with the refresh token → new JWT (same
      `refresh_token` echoed back — refresh does not rotate it).
- [ ] Expired/garbage refresh token → `403`.
- [ ] Rate limiting: hammer `/api/v1/users/login` past `rate_limit.auth` (5/min in
      dev config) from one IP → `429` once exceeded. Note the bucket is shared
      per-IP across `/users/login`, `/users/refresh`, **and** `/oauth2/token`
      together, not 5 separate allowances per endpoint.

#### Worked example: local login status codes, the auth rate-limit bucket, and refresh

> **Concept: local login is the one auth path everything else measures itself
> against.** OIDC (§3.3) explicitly reuses its session-issuing plumbing
> (`IssueSessionForUser`) and service accounts (§3.5) are a deliberately
> separate layer — but `POST /users/login` and `POST /users/refresh` are the
> baseline. Three things about this baseline are easy to get wrong if you
> only read the checklist above instead of the source: **(1)** failed auth is
> `403`, not `401` — the checklist above has already been corrected to match,
> but it's worth internalizing why; **(2)** the HTTP API deliberately tells
> the caller nothing about *why* auth failed (bad username vs. bad password
> vs. bad TOTP all collapse to the same string), while the CLI, calling the
> same service in-process, does not collapse anything and shows the real
> reason; **(3)** `/login`, `/refresh`, and `/oauth2/token` share one
> 5-req/min token-bucket per IP, not five each.

##### Prerequisites

- Admin already bootstrapped, `ROCKETVAULT_TOTP_SECRET` exported (see §2).
- `jq` for reading JSON responses legibly (optional but used below).
- A server freshly started (or at least not already close to its rate-limit
  ceiling from other testing) — see gotcha #4, it matters for step 7.

##### Gotchas this example is built to surface

1. **Failed login/refresh is `403 Forbidden`, not `401 Unauthorized`.**
   `loginUser` (`api/users.go:449`) and `refreshToken` (`api/users.go:494`)
   both call `c.SetPermissionError(...)` on any failure from
   `AuthenticateUser`/`RefreshAccessToken`, and `SetPermissionError`
   (`api/context.go:96-99`) hardcodes `http.StatusForbidden`. This applies
   uniformly to wrong password, wrong/unknown username, wrong TOTP code, and
   expired/garbage refresh tokens — none of them ever produce a `401` from
   this API.
2. **The client never learns *which* check failed — only the server log
   does.** `AuthenticationService.AuthenticateUser` returns three distinct
   Go errors depending on what went wrong: `"invalid credentials"` for an
   unknown username (`authentication_service.go:125`), the same
   `"invalid credentials"` for a wrong password (`authentication_service.go:135`
   — deliberately identical to the unknown-username case, so the API can't
   be used to enumerate valid usernames), and `"invalid TOTP code"` for a
   wrong/stale code (`authentication_service.go:152`). `loginUser` logs the
   real error server-side (`api/users.go:448`, `"Login failed for user %s: %v"`)
   but returns the same generic `"Insufficient permissions: authentication
   failed"` to the client regardless of which of the three it was
   (`api/users.go:449`). By contrast, `rocketvault users login` calls
   `AuthenticateUser` directly and does **not** collapse the error —
   `cmd/users/login.go:79-80` wraps and prints the real message verbatim
   (e.g. `Error: failed to login: invalid credentials` vs. `Error: failed
   to login: invalid TOTP code`). Same backend check, two very different
   error-verbosity postures depending on which path you test through.
3. **Refresh never rotates the refresh token, and the response's
   `expires_at` is a hardcoded constant, not the real JWT TTL.**
   `authentication_service.go:349-350` (comment: "we'll keep the same
   refresh token (no rotation)") returns the identical `refresh_token` you
   sent in; `authentication_service.go:366` hardcodes
   `ExpiresAt: time.Now().Add(time.Hour)` unconditionally. In this repo's
   local `.rocketvault.yaml`, `jwt.expiry: "1h"` happens to
   match that hardcoded hour, but the two are not wired together — change
   `jwt.expiry` to anything else and `expires_at` in the refresh response
   will silently stop reflecting the token's actual lifetime.
4. **The `auth` rate-limit bucket is shared per-IP across three endpoints,
   not 5-per-endpoint.** `RateLimitMiddleware` (`internal/middleware/
   middleware.go:190-194`) routes `/users/login`, `/users/refresh`, and
   `/oauth2/token` all through the same `m.authLimiter`, and
   `ipRateLimiter.get` keys purely by IP — one bucket, not one per path.
   Three login attempts plus two refresh calls from the same IP exhausts
   the entire 5/min allowance; it is not "5 login attempts AND separately 5
   refresh attempts."
5. **It's a continuously-refilling token bucket, not a fixed one-minute
   window.** `newIPRateLimiter` builds `rate.NewLimiter(rate.Every(time.Minute
   / 5), 5)` — burst of 5, refilling at 1 token per 12 seconds. After
   exhausting the burst, the next request succeeds ~12s later, not "at the
   top of the next minute." `rate_limit.auth: 5` and `rate_limit.default:
   300` in `.rocketvault.yaml:61-63` are confirmed current.
6. **The `429` response body is plain text, not this API's usual JSON error
   envelope.** `middleware.go:216` calls `http.Error(w, "Rate limit
   exceeded", http.StatusTooManyRequests)` — body is exactly `Rate limit
   exceeded\n`, `Content-Type: text/plain; charset=utf-8`. Every other error
   in this plan goes through `writeError`'s `{"id","message",
   "detailed_error","status_code","request_id"}` JSON shape
   (`api/context.go:214-225`); `429` is the one exception.

##### Setup

```bash
BASE=http://localhost:8774/api/v1
TOTP_CODE=$(go run scripts/totp_generator.go -secret="$ROCKETVAULT_TOTP_SECRET" 2>&1 | grep -m1 -oP '(?<=--totp-code )\S+')
```

---

**1. Successful login over raw HTTP — confirm the exact request/response
shapes:**
```bash
curl -s -w '\n%{http_code}\n' $BASE/users/login \
  -H 'Content-Type: application/json' \
  -d "{\"username\":\"admin\",\"password\":\"admin123\",\"totp_code\":\"$TOTP_CODE\"}"
```
Expect `200` and a body shaped exactly:
```json
{"token":"eyJhbGciOi...","refresh_token":"...","user_id":"...","username":"admin","role":"admin"}
```
Note there is no `expires_at` field on login's response — only refresh's
response has one (step 6). Capture both tokens for later steps:
```bash
LOGIN_JSON=$(curl -s $BASE/users/login -H 'Content-Type: application/json' \
  -d "{\"username\":\"admin\",\"password\":\"admin123\",\"totp_code\":\"$TOTP_CODE\"}")
TOKEN=$(echo "$LOGIN_JSON" | jq -r .token)
REFRESH_TOKEN=$(echo "$LOGIN_JSON" | jq -r .refresh_token)
```

**2. Missing-field validation — omit `totp_code`:**
```bash
curl -s -w '\n%{http_code}\n' $BASE/users/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"admin123"}'
```
Expect `400` with body:
```json
{"id":"Invalid or missing parameter: username, password, and totp_code are required","message":"Invalid or missing parameter: username, password, and totp_code are required","detailed_error":"","status_code":400,"request_id":"req-xxxxxxxx"}
```

**3. Wrong password — confirms gotcha #1 (`403`, not `401`):**
```bash
curl -s -w '\n%{http_code}\n' $BASE/users/login \
  -H 'Content-Type: application/json' \
  -d "{\"username\":\"admin\",\"password\":\"wrongpassword\",\"totp_code\":\"$TOTP_CODE\"}"
```
Expect `403` with body:
```json
{"id":"Insufficient permissions: authentication failed","message":"Insufficient permissions: authentication failed","detailed_error":"","status_code":403,"request_id":"req-xxxxxxxx"}
```
Same body shape you'd get for an unknown username entirely — check the
server's own stdout/log for this request; it should show the real reason
(`Login failed for user admin: invalid credentials`), which the HTTP client
never sees (gotcha #2).

**4. Wrong/stale TOTP code — same generic body, different underlying
cause:**
```bash
curl -s -w '\n%{http_code}\n' $BASE/users/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"admin123","totp_code":"000000"}'
```
Expect the identical `403`/`"authentication failed"` body as step 3 — the
API gives no signal that this time it was the TOTP check that failed, not
the password. Contrast with the CLI, which does distinguish:
```bash
rocketvault users login --username admin --password admin123 --totp-code 000000
```
Expect `Error: failed to login: invalid TOTP code` — a different, more
specific string than what a wrong password produces via the same CLI
command (`Error: failed to login: invalid credentials`).

**5. Skew-tolerance timing check (`period=30`, `skew=2`) — a code stays
valid up to ~60s after its own 30s window closes, then stops working:**
```bash
STALE_CODE=$(go run scripts/totp_generator.go -secret="$ROCKETVAULT_TOTP_SECRET" 2>&1 | grep -m1 -oP '(?<=--totp-code )\S+')
sleep 45
curl -s -w '\n%{http_code}\n' $BASE/users/login -H 'Content-Type: application/json' \
  -d "{\"username\":\"admin\",\"password\":\"admin123\",\"totp_code\":\"$STALE_CODE\"}"
```
Expect `200` — 45s old is still inside the ±2-period (±60s) skew window.
Now let it go further stale:
```bash
sleep 60
curl -s -w '\n%{http_code}\n' $BASE/users/login -H 'Content-Type: application/json' \
  -d "{\"username\":\"admin\",\"password\":\"admin123\",\"totp_code\":\"$STALE_CODE\"}"
```
Expect `403` now (~105s old total, outside the tolerance window) — useful
for negative-testing timing without needing to fake the system clock.

**6. Refresh flow — happy path, then both its negative cases:**
```bash
curl -s -w '\n%{http_code}\n' $BASE/users/refresh \
  -H 'Content-Type: application/json' \
  -d "{\"refresh_token\":\"$REFRESH_TOKEN\"}"
```
Expect `200` with body shaped:
```json
{"token":"eyJhbGciOi...","refresh_token":"<same value you sent>","user_id":"...","username":"admin","role":"admin","expires_at":"2026-08-17T...Z"}
```
Confirm `refresh_token` in the response is byte-for-byte identical to what
you sent (gotcha #3 — no rotation). Missing field:
```bash
curl -s -w '\n%{http_code}\n' $BASE/users/refresh -H 'Content-Type: application/json' -d '{}'
```
Expect `400`, `"Invalid or missing parameter: refresh_token is required"`.
Garbage/expired token:
```bash
curl -s -w '\n%{http_code}\n' $BASE/users/refresh \
  -H 'Content-Type: application/json' -d '{"refresh_token":"not-a-real-token"}'
```
Expect `403`, `"Insufficient permissions: token refresh failed"` — same
shape/status as a failed login, not `401`.

**7. Rate-limit negative case — hammer `/login` past the shared 5/min
bucket.** Because steps 1-6 above already spent several tokens from this
IP's `auth` bucket (gotcha #4), either restart the server first or just
run enough requests to see the transition; either way, watch the status
codes and headers, not a fixed count:
```bash
for i in $(seq 1 8); do
  echo "--- attempt $i ---"
  curl -s -o /dev/null -D - $BASE/users/login \
    -H 'Content-Type: application/json' \
    -d '{"username":"admin","password":"wrongpassword","totp_code":"000000"}' \
    | grep -E '^(HTTP|X-RateLimit)'
done
```
Expect the first several attempts to show `403` with `X-RateLimit-Remaining`
trending toward `0` (exact per-request numbers aren't guaranteed to be
whole-number-stable — it's a float token count truncated at read time),
then subsequent attempts flip to:
```
HTTP/1.1 429 Too Many Requests
```
with a plain-text body (confirm separately, gotcha #6):
```bash
curl -s $BASE/users/login -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"x","totp_code":"x"}'
```
Expect literally `Rate limit exceeded` (plus a trailing newline), not a
JSON error body. Wait ~12s and confirm exactly one more request succeeds
(token bucket refill, gotcha #5) before hitting `429` again.

**8. Confirm the CLI's own login path produces the matching cached-session
shape, tying this back to §3.4's session-cache example:**
```bash
rocketvault users login --username admin --password admin123 --totp-code "$TOTP_CODE"
```
Expect a success message and `~/.rocketvault/sessions/admin.json` populated
exactly per §3.4 step 1.

##### Cleanup

```bash
rocketvault users logout
```
No server-side state needs cleaning up beyond this — the rate limiter's
per-IP buckets are purely in-memory and reset on server restart; nothing
persists to the database from any of the negative-case requests above.

### 3.2 Sessions

- [ ] `GET /api/v1/users/sessions` (authenticated) → lists active sessions for the caller.
      **Admin-only in practice**: `mapEndpointToPermission` matches the bare
      `users` path prefix, so this maps to `PermissionReadUser`/`PermissionDeleteUser`,
      held only by `RoleAdmin` — a non-admin gets `403` on their *own* sessions
      (see worked example gotcha #1). The handler itself is written as
      self-service (derives the user from claims), so this looks like an
      unintended side effect of prefix matching, not a deliberate design choice.
- [ ] Log in from a second "device" (separate curl session/cookie jar) → two sessions listed.
- [ ] `DELETE /api/v1/users/sessions/{id}` on one of them → that session's JWT now
      401s on next use (plain-text body `Unauthorized: invalid token` — the
      string `"session revoked"` only ever reaches the server log, never the
      HTTP response); the other still works. **No ownership check**: the
      revoke query filters `WHERE id = ? AND revoked = FALSE` only — any
      caller who can reach this admin-only route can revoke *any* session
      given its UUID, not just their own (worked example gotcha #2).
- [ ] `DELETE /api/v1/users/sessions` (revoke all) → all this user's JWTs 401 on next use.
      Confirm it's a one-shot sweep, not a lockout: logging in again
      immediately afterward on the same account succeeds normally.

#### Worked example: two devices, one revoked, then all revoked

> **Concept: a session is a database row, and the JWT's `jti` *is* that
> row's UUID.** Every successful login runs `issueSession`
> (`internal/services/auth/authentication_service.go:172-217`), which does
> three things in order: mints a random refresh token, `INSERT`s one new
> `user_sessions` row with a fresh `uuid.New()`, and signs a JWT whose `jti`
> is set to *that row's ID*. So "device" is not a concept the server models
> at all — "two devices" simply means "two rows, two `jti`s". Revocation
> flips `revoked = TRUE` on the row; enforcement is `ValidateSession`
> re-reading that column on **every single authenticated request** via
> `IsSessionRevoked`, so revocation takes effect immediately rather than at
> token expiry. Two clocks run independently: the access token's TTL
> (`jwt.expiry`, `1h` in the checked-in dev config) and the session row's
> own `expires_at`, hard-coded to **7 days** and not configurable.
> Refreshing does **not** create a new session — `RefreshAccessToken` reuses
> the existing `session.ID` as the new token's `jti`, so a refreshed token
> dies with the same revocation as its parent.

##### Prerequisites

- Server running against a scratch config/DB (see **§0**) — step 11 deletes
  a row directly from that database, so do not point this at anything shared.
- Admin bootstrapped and `ROCKETVAULT_TOTP_SECRET` exported (see **§2**).
- `curl`, `jq`, `python3` (used to base64url-decode a JWT payload), and
  `sqlite3` (step 11 only, if your scratch DB is SQLite).
- **Raise `rate_limit.auth` in your scratch config first, or pace
  yourself.** This walkthrough performs six-plus logins; the dev config
  sets `rate_limit.auth: 5` (shared across `/login`/`/refresh`/
  `/oauth2/token`, per §3.1), so a straight copy-paste run will start
  returning `429` partway through. Bump it to e.g. `60` for the duration.
- **There is no CLI for any of this.** `cmd/users/` has `login`, `logout`,
  `create`, `list`, `get`, `update`, `delete`, `admin` — no `sessions`
  command exists, so every session call below is `curl`.

##### Gotchas this example is built to surface

All six are real, verified-against-source behaviors, not hypotheticals.

1. **Session self-management is admin-only — by accident of prefix
   matching, not by design.** `mapEndpointToPermission`
   (`internal/services/authorization/rbac_service.go:263-277`) matches on
   `strings.HasPrefix(path, "users")` and never special-cases `sessions`,
   so `GET /users/sessions` maps to `PermissionReadUser` and both `DELETE`
   variants map to `PermissionDeleteUser`. Only `model.RoleAdmin` holds
   either permission. Net effect: **a plain `user`, `secrets_manager`,
   `crypto_manager`, or `certificate_manager` cannot list or revoke even
   their own sessions** — `AuthorizationMiddleware` rejects them before the
   handler runs. Step 12 proves it.
2. **`revokeSession` has no ownership check whatsoever.** `api/users.go:566-582`
   reads `c.Params.SessionID` and hands it straight to `authSvc.RevokeSession`
   — `c.Claims.UserID` is used *only* in the trailing log line, never passed
   into the service call. The repository's `UPDATE` filters `WHERE id = ?
   AND revoked = FALSE` (`session_repository.go:304-311`) — no `user_id`
   predicate anywhere in the chain. **Anyone who can reach the route can
   revoke anyone else's session given its UUID.** Two things bound the
   blast radius, but neither is the missing check: the route is admin-only
   (gotcha #1), and no endpoint ever discloses another user's session IDs.
   Contrast `revokeAllSessions`, which takes its user ID from
   `c.Claims.UserID` and therefore *cannot* cross users. Step 9
   demonstrates the gap concretely.
3. **A missing session row reads as "revoked", not as "unknown".**
   `IsSessionRevoked` (`session_repository.go:413-431`) catches
   `sql.ErrNoRows` and returns `(true, nil)` — literally commented
   `// Non-existent session is considered revoked`. Any JWT whose `jti`
   matches no `user_sessions` row is rejected with `session revoked` → 401,
   even though nothing was ever revoked. This is the exact mechanism
   behind **B3** in `docs/known-bugs.md` (pre-upgrade JWTs carrying a
   random, non-session `jti`). Nothing in production ever calls
   `DeleteExpiredSessions` — the only callers are tests — so rows are never
   purged; step 11 forces this state with a manual `DELETE`.
4. **The 401 body never says "session revoked".** The response is
   `http.Error(w, "Unauthorized: invalid token", 401)` — plain text, and
   *identical* for a revoked session, an expired token, a bad signature,
   and garbage. The string `session revoked` only ever reaches the server
   log and audit trail. Watch the server log, not the HTTP response, when
   you need to know *why* a token was rejected.
5. **`device_info`, `ip_address`, and `user_agent` are always empty
   strings.** `issueSession` hardcodes `""` for all three (comment: "Can be
   populated from request context.") — the request's real IP/User-Agent is
   never plumbed through. The list response gives no human-readable way to
   tell "the CLI" from "curl"; match sessions by `id` (= the token's `jti`)
   or `created_at`. Relatedly, `last_used_at` only advances on **refresh**
   — the sole caller of `UpdateSessionLastUsed` is `RefreshAccessToken` —
   so a session used heavily for an hour still shows its login timestamp.
6. **Revoking an already-revoked or non-existent session returns `500`,
   not `404`.** The repository treats `rowsAffected == 0` as an error
   (`"session not found or already revoked"`), and the handler funnels
   *every* error into `c.SetInternalError`, hard-wired to `500`. Steps 8
   shows both this and two other distinct error shapes for "wrong session
   ID" depending on exactly how it's wrong.

##### Setup

```bash
BASE=http://localhost:8774/api/v1
TOTP_CODE=$(go run scripts/totp_generator.go -secret="$ROCKETVAULT_TOTP_SECRET" 2>&1 | grep -m1 -oP '(?<=--totp-code )\S+')

# Decode a JWT's jti (= its session ID). Base64url + padding, hence python3.
jti() { python3 -c "
import sys, base64, json
p = sys.argv[1].split('.')[1]
p += '=' * (-len(p) % 4)
print(json.loads(base64.urlsafe_b64decode(p))['jti'])" "$1"; }
```

The same `$TOTP_CODE` works for both logins in steps 1-2: `ValidateCode`
(`internal/services/auth/totp_service.go:85-99`) has **no replay
tracking** — a code stays valid for its whole window (plus configured
skew) no matter how many times it's used.

---

**1. Log in as "device A" (raw curl) and capture both tokens:**
```bash
LOGIN_A=$(curl -s -X POST $BASE/users/login -H "Content-Type: application/json" \
  -d "{\"username\":\"admin\",\"password\":\"admin123\",\"totp_code\":\"$TOTP_CODE\"}")
echo "$LOGIN_A" | jq .
TOKEN_A=$(echo "$LOGIN_A" | jq -r .token)
REFRESH_A=$(echo "$LOGIN_A" | jq -r .refresh_token)
```
Expect exactly these five fields — note there is **no** `expires_at` on the
login response, unlike refresh's:
```json
{"token":"eyJhbGciOi...","refresh_token":"6f3c...","user_id":"...","username":"admin","role":"admin"}
```

**2. Log in a second time as "device B" — same user, same credentials:**
```bash
LOGIN_B=$(curl -s -X POST $BASE/users/login -H "Content-Type: application/json" \
  -d "{\"username\":\"admin\",\"password\":\"admin123\",\"totp_code\":\"$TOTP_CODE\"}")
TOKEN_B=$(echo "$LOGIN_B" | jq -r .token)
[ "$TOKEN_A" = "$TOKEN_B" ] && echo "SAME (unexpected)" || echo "different tokens"
```
Expect `different tokens`. Nothing about the second login disturbs the
first — `issueSession` only ever `INSERT`s; there is no "one session per
user" constraint and no eviction of older sessions anywhere in the codebase.

**3. Prove the two sessions are genuinely independent rows:**
```bash
JTI_A=$(jti "$TOKEN_A"); JTI_B=$(jti "$TOKEN_B")
echo "A=$JTI_A"; echo "B=$JTI_B"
```
Expect two different UUIDs.

**4. List sessions (as device A) and confirm both appear:**
```bash
curl -s $BASE/users/sessions -H "Authorization: Bearer $TOKEN_A" | jq .
```
Expect `200` and this shape:
```json
{
  "sessions": [
    {"id": "<JTI_B>", "device_info": "", "ip_address": "", "user_agent": "",
     "expires_at": "2026-08-24T...Z", "last_used_at": "2026-08-17T...Z",
     "created_at": "2026-08-17T...Z", "revoked": false},
    {"id": "<JTI_A>", "...": "..."}
  ],
  "total": 2
}
```
Three things worth actually checking rather than skimming past: the three
device-identifying fields are **empty strings** (gotcha #5); `expires_at`
is seven days out, not one hour; and `revoked` is always `false` here
because the underlying query already filters `revoked = FALSE` — the field
can never be `true` in this response, making it decorative on this endpoint.

**5. Confirm this list is scoped to the caller only** — there is no query
parameter and no admin variant anywhere; an admin cannot list another
user's sessions through the API at all:
```bash
curl -s $BASE/users/sessions -H "Authorization: Bearer $TOKEN_A" | jq -r '.sessions[].id' | sort > /tmp/listed
printf '%s\n%s\n' "$JTI_A" "$JTI_B" | sort > /tmp/expected
diff /tmp/listed /tmp/expected && echo "exactly the caller's own two sessions"
```

**6. Revoke device A specifically — using device B's token — and watch
only A die:**
```bash
curl -s -X DELETE $BASE/users/sessions/$JTI_A -H "Authorization: Bearer $TOKEN_B"
echo "--- A (revoked):"; curl -s -o /dev/null -w "%{http_code}\n" $BASE/vaults -H "Authorization: Bearer $TOKEN_A"
echo "--- B (untouched):"; curl -s -o /dev/null -w "%{http_code}\n" $BASE/vaults -H "Authorization: Bearer $TOKEN_B"
```
Expect the revoke call to print exactly `{"status":"OK"}`, then `401` for
A and `200` for B. Drop `-o /dev/null` on A's request to see the body:
```
Unauthorized: invalid token
```
plain text, not JSON, and not the words "session revoked" (gotcha #4). The
server log for that same request carries the real reason:
`Token validation failed ... error="session revoked"`.

**7. A's refresh token is dead too — and it fails with `403`, not `401`:**
```bash
curl -s -X POST $BASE/users/refresh -H "Content-Type: application/json" \
  -d "{\"refresh_token\":\"$REFRESH_A\"}" | jq .
```
Expect:
```json
{"id":"Insufficient permissions: token refresh failed","message":"Insufficient permissions: token refresh failed","detailed_error":"","status_code":403,"request_id":"req-..."}
```
`GetSessionByRefreshToken` filters `revoked = FALSE` in SQL, so a revoked
session's refresh token looks simply *absent*; every refresh failure maps
to `SetPermissionError` → `403`.

**8. Negative cases — three different "wrong session ID" shapes, not one:**
```bash
# Already revoked: 500
curl -s -X DELETE $BASE/users/sessions/$JTI_A -H "Authorization: Bearer $TOKEN_B" | jq .
# Well-formed UUID that never existed: also 500, same message
curl -s -X DELETE $BASE/users/sessions/00000000-0000-0000-0000-000000000000 \
  -H "Authorization: Bearer $TOKEN_B" | jq .
```
Both:
```json
{"id":"Internal server error","message":"Internal server error","detailed_error":"failed to revoke session: session not found or already revoked","status_code":500,"request_id":"req-..."}
```
A malformed-but-short ID never reaches the database — `uuid.Parse` rejects
it first:
```bash
curl -s -X DELETE $BASE/users/sessions/abc -H "Authorization: Bearer $TOKEN_B" | jq .
```
```json
{"id":"Internal server error","message":"Internal server error","detailed_error":"invalid session ID format: invalid UUID length: 3","status_code":500,"request_id":"req-..."}
```
And an ID with characters outside `[A-Fa-f0-9-]` never even matches the
route, falling through to the global 404 handler instead — a third, again
different, shape:
```bash
curl -s -X DELETE $BASE/users/sessions/not-a-session -H "Authorization: Bearer $TOKEN_B" | jq .
```
```json
{"id":"api.not_found","message":"Not found","status_code":404}
```

**9. The missing ownership check (gotcha #2), demonstrated.** Create a
*second admin* (the route is admin-only, so a non-admin can't be used
here), log them in, and revoke their session using the first admin's token:
```bash
OUT=$(rocketvault users create --new-username ops-admin --new-password opsadmin12345 --new-role admin)
export OPS_TOTP=$(echo "$OUT" | grep -oP 'secret=\K[A-Z2-7]+')
OPS_CODE=$(go run scripts/totp_generator.go -secret="$OPS_TOTP" 2>&1 | grep -m1 -oP '(?<=--totp-code )\S+')
TOKEN_C=$(curl -s -X POST $BASE/users/login -H "Content-Type: application/json" \
  -d "{\"username\":\"ops-admin\",\"password\":\"opsadmin12345\",\"totp_code\":\"$OPS_CODE\"}" | jq -r .token)
JTI_C=$(jti "$TOKEN_C")

# admin (TOKEN_B) revokes ops-admin's session — belonging to a DIFFERENT user:
curl -s -X DELETE $BASE/users/sessions/$JTI_C -H "Authorization: Bearer $TOKEN_B"
curl -s -o /dev/null -w "%{http_code}\n" $BASE/vaults -H "Authorization: Bearer $TOKEN_C"
```
Expect `{"status":"OK"}` followed by `401`. No `403`, no "not your
session" — the cross-user revoke simply succeeds. Note what made this
*possible* to run: we obtained `$JTI_C` by decoding a token we already
held ourselves. The API never hands one user another user's session ID
(step 5), so this is a missing defence-in-depth check on an admin-only
route rather than a directly exploitable IDOR — but don't record it as
expected behavior either.

**10. Revoke-all, and confirm it's a one-shot sweep, not a lockout flag:**
```bash
curl -s -X DELETE $BASE/users/sessions -H "Authorization: Bearer $TOKEN_B"
curl -s -o /dev/null -w "%{http_code}\n" $BASE/vaults -H "Authorization: Bearer $TOKEN_B"

TOKEN_D=$(curl -s -X POST $BASE/users/login -H "Content-Type: application/json" \
  -d "{\"username\":\"admin\",\"password\":\"admin123\",\"totp_code\":\"$TOTP_CODE\"}" | jq -r .token)
curl -s -o /dev/null -w "%{http_code}\n" $BASE/vaults -H "Authorization: Bearer $TOKEN_D"
curl -s $BASE/users/sessions -H "Authorization: Bearer $TOKEN_D" | jq .
```
Expect `{"status":"OK"}`, then `401` for the now-revoked `$TOKEN_B`, then
`200` for the brand-new `$TOKEN_D`, immediately, no delay. The final list
shows exactly **one** session — `RevokeAllUserSessions` is a single
`UPDATE ... WHERE user_id = ? AND revoked = FALSE`: it flips whatever rows
exist at that instant and stores nothing that could affect a later login.

**11. Force gotcha #3 — the `sql.ErrNoRows`-means-revoked path.**
Hard-delete `$TOKEN_D`'s row instead of revoking it, then reuse the token:
```bash
JTI_D=$(jti "$TOKEN_D")
sqlite3 /tmp/rv-test.db "SELECT id, revoked FROM user_sessions WHERE id='$JTI_D';"
sqlite3 /tmp/rv-test.db "DELETE FROM user_sessions WHERE id='$JTI_D';"
curl -s -o /dev/null -w "%{http_code}\n" $BASE/vaults -H "Authorization: Bearer $TOKEN_D"
```
Expect the `SELECT` to show `revoked = 0` beforehand, and the request to
return `401` afterward anyway — the row is gone, `IsSessionRevoked` hits
`sql.ErrNoRows` and answers `(true, nil)`. This is exactly what a
pre-upgrade JWT experienced in incident B3: same code path, different
cause for the row being absent. Deliberate fail-closed behavior, but the
diagnostic wording is actively misleading.

**12. Negative case confirming gotcha #1 — a non-admin cannot manage even
their own sessions:**
```bash
OUT=$(rocketvault users create --new-username alice --new-password alice123456 --new-role user)
export ALICE_TOTP=$(echo "$OUT" | grep -oP 'secret=\K[A-Z2-7]+')
ALICE_CODE=$(go run scripts/totp_generator.go -secret="$ALICE_TOTP" 2>&1 | grep -m1 -oP '(?<=--totp-code )\S+')
ALICE_TOKEN=$(curl -s -X POST $BASE/users/login -H "Content-Type: application/json" \
  -d "{\"username\":\"alice\",\"password\":\"alice123456\",\"totp_code\":\"$ALICE_CODE\"}" | jq -r .token)

curl -s -w "\n%{http_code}\n" $BASE/users/sessions -H "Authorization: Bearer $ALICE_TOKEN"
curl -s -w "\n%{http_code}\n" -X DELETE $BASE/users/sessions -H "Authorization: Bearer $ALICE_TOKEN"
curl -s -w "\n%{http_code}\n" -X DELETE $BASE/users/sessions/$(jti "$ALICE_TOKEN") \
  -H "Authorization: Bearer $ALICE_TOKEN"
```
Expect all three to return `403` with plain-text body
`Forbidden: insufficient permissions`. Alice's login succeeded, her token
is valid, and the sessions being listed/revoked would be *her own* — the
refusal comes from `AuthorizationMiddleware` mapping the `users` path
prefix to `users:read`/`users:delete`, which her `user` role doesn't hold.

##### Cleanup

```bash
ADMIN_TOKEN=$(curl -s -X POST $BASE/users/login -H "Content-Type: application/json" \
  -d "{\"username\":\"admin\",\"password\":\"admin123\",\"totp_code\":\"$TOTP_CODE\"}" | jq -r .token)
curl -s -X DELETE $BASE/users/sessions -H "Authorization: Bearer $ADMIN_TOKEN"
rocketvault users delete <ops-admin user_id> --username admin
rocketvault users delete <alice user_id> --username admin
rm -f ~/.rocketvault/sessions/*
```
If you raised `rate_limit.auth` for this example, restore it before
running §3.1's rate-limiting check.

### 3.3 OIDC login (only if `oidc.enabled: true` and you have a reachable test issuer)

- [ ] `GET /api/v1/oidc/login` → redirects to issuer's authorization endpoint.
- [ ] Complete the browser flow, land on `GET /api/v1/oidc/callback` → issues the
      same JWT/session pair local login uses (`AuthenticationService.IssueSessionForUser`
      — no separate OIDC token path).
- [ ] First-time login for a given external identity → `UserService.FindOrCreateExternalUser`
      creates a new `model.User` with the least-privilege `user` role. Confirm via
      `GET /api/v1/users/{id}` (as admin) that the new user has role `user`, not `admin`.
- [ ] CLI: `rocketvault users login --oidc` — opens a browser, completes the flow,
      caches the session under `~/.rocketvault/sessions/<username>.json`, and updates
      `~/.rocketvault/sessions/current`. Confirm a subsequent bare CLI command (no
      `--username`/`--password` flags) reuses this session.
- [ ] With `oidc.enabled: false` (or unset): `GET /oidc/login` and `GET /oidc/callback`
      → `503`, and confirm server startup does **not** attempt any network call to
      the issuer (this is the point of the gate — verify no outbound connection in
      logs/tcpdump if you want to be thorough).
- [ ] Known gotcha (B7, fixed): re-submitting/retrying a callback with the same
      authorization code must fail cleanly (`invalid_grant`), not silently retry the
      exchange. Not easily triggered manually — skip unless you have a proxy that
      can replay requests.

#### Worked example: OIDC login, disabled → enabled, browser → CLI

> **Concept: OIDC is additive, never a replacement.** Everything in §3.1
> (local username/password/TOTP) keeps working exactly as before whether or
> not OIDC is configured — `AuthenticationService.IssueSessionForUser`
> (called from the OIDC callback) issues the same JWT/session pair
> `AuthenticateUser` (called from local login) does; there is no separate
> "OIDC token" format to drift out of sync. The one real behavioral
> difference: OIDC's session has **no password/TOTP check at all** —
> `IssueSessionForUser` skips both entirely, because the identity provider
> already authenticated the user before RocketVault's callback ever runs.
> MFA, if any, is delegated 100% to the IdP; RocketVault enforces none of
> its own for this path. That's a deliberate design choice, not a gap — but
> it means "does this account have TOTP configured" is meaningless to ask
> about an OIDC-provisioned user, since `FindOrCreateExternalUser` gives
> them an empty `PasswordHash`/`TOTPSecret` (`internal/services/users/
> user_service.go`).

**Unlike §3.4/§3.5, this example is not fully self-contained** — a
complete browser round-trip needs a real, reachable, spec-compliant OIDC
provider (your org's real IdP, the test issuer this repo's checked-in
`.rocketvault.yaml` already points at, or a local mock like Dex/Keycloak
you stand up yourself). Part A below needs nothing external at all; Part B
needs that reachable provider.

##### Prerequisites (Part B only)

- `oidc.issuer_url`/`client_id`/`client_secret`/`redirect_url`/`scopes` set
  in your config to a real, reachable OIDC provider that will let you log in
  as a test user.
- `frontend.public_api_url` set correctly — the CLI flow reads this
  directly (`viper.GetString("frontend.public_api_url")`,
  `cmd/users/login_oidc.go`) to know where to open the browser to.
- **HTTPS, not plain HTTP** — see gotcha #1 below before you burn time
  debugging a cookie error that has nothing to do with your OIDC config.
- Admin session already cached (`rocketvault users login --username admin
  ...`), to inspect the resulting user via the API afterward.

##### Gotchas this example is built to surface

1. **State/nonce cookies are `Secure: true` — plain HTTP silently breaks
   the flow with a misleading error.** `api/oidc.go`'s `setOIDCCookie` sets
   `Secure: true` unconditionally. Browsers refuse to send `Secure`
   cookies back over plain HTTP. If your `frontend.public_api_url`/
   `server.tls.enabled` setup is plain HTTP (e.g. the quick `go run main.go
   serve` from §0, which doesn't enable TLS), the callback will fail with
   `missing or expired oidc_state cookie` — which reads like a timing/
   expiry problem, not a "you're on HTTP" problem. Put a TLS-terminating
   reverse proxy in front (this repo's own `docker-compose.yml` ships a
   Caddy profile for exactly this) or use a provider/setup that's already
   HTTPS end-to-end, matching the HTTPS host your own dev config points at.
2. **The CLI flow is not "paste a code back" — it's a real loopback HTTP
   listener.** `rocketvault users login --oidc` starts a plain-HTTP server
   on `127.0.0.1:<random port>` (`startLoopbackListener`,
   `cmd/users/login_oidc.go`) *before* opening the browser, embeds that
   port plus a random 32-byte state token into the redirect URI
   (`http://127.0.0.1:<port>/callback/<state>`), and blocks for up to 5
   minutes (`oidcLoginTimeout`) waiting for exactly one GET to that exact
   path. If you're testing over SSH/a remote box with no browser and no
   port-forwarding, this flow cannot complete — you'd need to forward that
   ephemeral port back to wherever the browser actually runs, which is
   awkward precisely because the port is random per attempt.
3. **The exchange code is single-use and expires in 60 seconds, server-side
   only.** `api/oidc_cli.go`'s `cliExchangeStore` is a pure in-memory map —
   if you restart the server between the callback redirecting to your
   loopback listener and the CLI's exchange POST, or if 60 seconds elapse,
   the code is simply gone (`unknown or expired code`, `410 Gone`) and you
   restart the whole `login --oidc` command. There's no persistence or
   retry here by design — losing the map on restart just means "log in
   again."

##### Part A — fully self-contained, no external IdP needed

**1. Confirm OIDC-disabled behavior first.** Set `oidc.enabled: false` (or
leave it unset) in a scratch config, start the server, and check:
```bash
curl -s -o /dev/null -w "%{http_code}\n" http://localhost:8774/api/v1/oidc/login
curl -s -o /dev/null -w "%{http_code}\n" http://localhost:8774/api/v1/oidc/callback
```
Expect `503` for both — `oidcLoginHandler`/`oidcCallbackHandler` both check
`svc == nil` first and return immediately. Check the server's startup logs
for this run: there should be **no** OIDC discovery log line and no
outbound network attempt at all — the container/service is never
constructed when `oidc.enabled` is false, not constructed-then-rejected.

**2. Confirm local login is completely unaffected by OIDC being off:**
```bash
rocketvault users login --username admin --password admin123 --totp-code "$TOTP_CODE"
```
Expect this to succeed exactly as it does throughout the rest of this
plan — proving OIDC's presence/absence never gates the local auth path.

##### Part B — needs a reachable OIDC provider

**3. Enable OIDC** (`oidc.enabled: true`, real issuer details filled in)
and restart the server. Watch the startup log for the discovery outcome:
```
{"level":"info","msg":"OIDC service initialised", ...}
```
If discovery fails instead, the log carries a warning and `GetOIDCService()`
returns `nil` for the rest of the process — `/oidc/*` routes will 503
exactly like Part A even though `oidc.enabled: true`, which is the "OIDC
not configured vs. discovery failed at boot" ambiguity called out in
CLAUDE.md. Check this log line, not just the config flag, before assuming
anything past this point should work.

**4. Negative check — the CLI redirect-URI allow-list**, testable without
completing a full login (only needs step 3's discovery to have succeeded):
```bash
curl -s -o /dev/null -w "%{http_code}\n" \
  "http://localhost:8774/api/v1/oidc/login?cli_redirect_uri=https://evil.example.com/steal"
curl -s -o /dev/null -w "%{http_code}\n" \
  "http://localhost:8774/api/v1/oidc/login?cli_redirect_uri=http://127.0.0.1"
```
Expect `400` for both — the first fails `u.Scheme != "http"` (https
rejected outright, this parameter only ever accepts plain `http` since
it's always `127.0.0.1`/`localhost`), the second fails the missing-port
check (`validateCLIRedirectURI`, `api/oidc_cli.go`). Then confirm a
well-formed one is accepted (redirects rather than erroring):
```bash
curl -s -o /dev/null -w "%{http_code}\n" \
  "http://localhost:8774/api/v1/oidc/login?cli_redirect_uri=http://127.0.0.1:54321/callback/abc"
```
Expect `302` (redirect to the real provider's authorization endpoint).

**5. Full browser flow, no CLI involved:**
```
open http://localhost:8774/api/v1/oidc/login   (or the HTTPS equivalent — see gotcha #1)
```
Complete the login at your provider. Expect to land back on `/oidc/callback`
with a JSON body shaped exactly like local login's response:
```json
{"token":"eyJhbGciOi...","refresh_token":"...","user_id":"...","username":"...","role":"user"}
```
`role` should be `user` — confirm via admin:
```bash
rocketvault users get <user_id from above> --username admin
```
Expect this to be a **brand-new** user (least-privilege `user` role, per
`FindOrCreateExternalUser`'s default) if this external identity has never
logged in before.

**6. Full CLI flow — trace what actually happens, don't just run it blind:**
```bash
rocketvault users login --oidc
```
Expect, in order: `Opening browser to complete OIDC login...` (or a raw URL
printed if `common.OpenBrowser` couldn't launch one — e.g. over SSH with no
`$DISPLAY`), then — after you complete the login in that browser tab — the
tab itself shows a plain-text `Login successful — you can close this tab.`
served directly by the loopback listener, and the terminal prints
`Login successful as <username>`. Confirm the session cached exactly like a
local login would:
```bash
cat ~/.rocketvault/sessions/current
cat ~/.rocketvault/sessions/*.json | jq .
```

**7. Same identity, second login — confirm idempotent lookup, not a
duplicate user:**
```bash
rocketvault users login --oidc
rocketvault users list --username admin | grep <the username from step 6>
```
Expect exactly one row for that username — `FindOrCreateExternalUser` looks
up by `(auth_provider, external_idp_subject)`, not by creating unconditionally,
so logging in again reuses the same local user rather than minting a second one.

**8. Confirm no TOTP prompt anywhere in this flow** — re-read the terminal
output from step 6: there is no `--totp-code` flag, no TOTP prompt, nothing.
This is the concept box's point made concrete: MFA is entirely the
provider's responsibility on this path, by design, not an oversight.

##### Cleanup

```bash
rocketvault users logout
# If you want the OIDC-provisioned user gone too, delete it as admin:
rocketvault users delete <user_id> --username admin
```

### 3.4 CLI session cache (login/logout)

- [ ] `rocketvault users login --username admin --password admin123 --totp-code <code>`
      → caches session to `~/.rocketvault/sessions/admin.json`, sets `current`.
- [ ] Run any command with no credential flags, e.g. `rocketvault vaults list` →
      succeeds using the cached session.
- [ ] Let the session's JWT expire (or fake it by editing the cached file's
      timestamp) then run a command → session refreshes transparently via its
      refresh token; confirm no login prompt.
- [ ] `rocketvault users logout` → clears the cache. Confirm it's **client-side
      only** — the server-side session is NOT revoked (per CLAUDE.md, this is
      documented, expected behavior, not a bug). Verify: after logout, the old
      JWT (captured before logout) still works if reused directly against the API.
- [ ] Log in as two different users in sequence, confirm `~/.rocketvault/sessions/current`
      points at the most recent, and `rocketvault users login --username <first>`
      (no password, relying on cache) switches back correctly if that session file
      still exists and is unexpired.

#### Worked example: switching between two cached CLI sessions

> **Concept: three resolution tiers, one file mechanism.** Every CLI command
> that needs auth calls `resolveAuthentication` (`cmd/root.go`), which tries,
> in this order:
> 1. `--username` + `--password` (+ `--totp-code`): fresh login, always works,
>    always overwrites both the session file **and** the `current` pointer.
> 2. `--username` alone, no `--password`: loads *that* user's existing cached
>    session file — no fresh credentials needed, but only touches `current`
>    conditionally (see gotcha #2 below).
> 3. No flags at all: loads whichever user `~/.rocketvault/sessions/current`
>    currently names.
>
> Mechanically it's just two kinds of files, per `common/session.go`:
> `~/.rocketvault/sessions/<sanitized-username>.json` (one per user who has
> ever logged in — `{"token","refresh_token","user_id","username","role",
> "expires_at"}`) and `~/.rocketvault/sessions/current` (a **plain-text file
> containing exactly the raw username**, nothing else — not JSON, not a
> symlink). `SaveSession` is the only function that writes the `current`
> file, and it does so as a side effect of a successful login/refresh, never
> as an independent "switch user" action.

##### Prerequisites

- Admin already bootstrapped, `ROCKETVAULT_TOTP_SECRET` exported (see §2 and
  §3.5's Prerequisites — same convention, reused here).
- `jq` for reading the session JSON files legibly (optional).

##### The three gotchas this example is built to surface

1. **Manually editing `current` with `echo` silently corrupts it.** `echo
   'alice' > .../current` appends a trailing newline; `sessionFilePath`
   sanitizes whatever it reads via a regex that maps anything outside
   `[a-zA-Z0-9._-]` — including `\n` — to `_`. So the pointer ends up
   containing `alice\n`, the next lookup goes to `sessionFilePath("alice\n")`
   → `alice_.json`, that file doesn't exist, and the CLI falls through to
   "no cached session found" instead of clearly saying the pointer file is
   malformed. Use `printf '%s' 'alice' > .../current` instead — no newline.
2. **`--username X` alone does not *always* update `current` — only when a
   refresh actually happens.** In `resolveAuthentication`, both the
   `--username`-only path and the no-flags path converge into the same
   `cached` variable, and the refresh-and-save logic after that point is
   identical for both. If `cached`'s token is still valid,
   `ValidateSession` succeeds and the function returns **immediately,
   without calling `SaveSession`** — so `current` is untouched. If the
   token happened to be expired, the fallthrough refresh path DOES call
   `SaveSession`, which DOES overwrite `current` to that username as a
   side effect. So the exact same command, `rocketvault <cmd> --username
   alice`, either changes or doesn't change who "current" points to
   afterward, **depending purely on whether alice's cached token was
   already stale at that moment** — not on anything about the command
   itself. Steps 5-6 below demonstrate both outcomes.
3. **Logout is client-side only — the server never hears about it.**
   `cmd/users/logout.go`'s own doc comment says so directly: "This does not
   revoke the session server-side — the underlying JWT simply expires
   naturally." A JWT captured before logout keeps working against the API
   directly until its own TTL elapses, logout or not. Step 9 below proves
   this concretely rather than just asserting it.

##### Setup

```bash
BASE=http://localhost:8774/api/v1
TOTP_CODE=$(go run scripts/totp_generator.go -secret="$ROCKETVAULT_TOTP_SECRET" 2>&1 | grep -m1 -oP '(?<=--totp-code )\S+')
```

---

**1. Fresh login as admin, then inspect what got written:**
```bash
rocketvault users login --username admin --password admin123 --totp-code "$TOTP_CODE"
cat ~/.rocketvault/sessions/current
echo
cat ~/.rocketvault/sessions/admin.json | jq .
```
Expect `current` to contain exactly `admin` (no trailing newline visible —
if you see one, that's `cat`'s own line wrap, not the file's actual
content; verify with `xxd ~/.rocketvault/sessions/current | tail -1` if in
doubt). Expect the session file shaped like:
```json
{"token":"eyJhbGciOi...","refresh_token":"eyJhbGciOi...","user_id":"...","username":"admin","role":"admin","expires_at":"2026-08-17T...Z"}
```

**2. Confirm a bare command uses it with zero flags:**
```bash
rocketvault vaults list
```
Expect it to succeed with no login prompt and no `--username` passed at all
— tier 3 of the resolution order.

**3. Create a second user, "alice", while still relying on admin's cached
session** (no credentials needed — this is tier 3 again, working for a
*different* command). Capture the output once so the TOTP secret can be
extracted from it directly, rather than creating the user twice:
```bash
CREATE_OUTPUT=$(rocketvault users create --new-username alice --new-password alice123456 --new-role user)
echo "$CREATE_OUTPUT"
export ALICE_TOTP_SECRET=$(echo "$CREATE_OUTPUT" | grep -oP 'secret=\K[A-Z2-7]+')
```
Expect `$CREATE_OUTPUT` to end in
`TOTP Secret: otpauth://totp/PasswordManager:alice?...&secret=XXXX&issuer=...`
and `$ALICE_TOTP_SECRET` to hold just the extracted base32 value.

**4. Log in as alice — this is tier 1 (fresh credentials), so `current`
unconditionally switches:**
```bash
ALICE_CODE=$(go run scripts/totp_generator.go -secret="$ALICE_TOTP_SECRET" 2>&1 | grep -m1 -oP '(?<=--totp-code )\S+')
rocketvault users login --username alice --password alice123456 --totp-code "$ALICE_CODE"
cat ~/.rocketvault/sessions/current
```
Expect `current` now contains `alice`. Both `admin.json` and `alice.json`
exist side by side — logging in as a new user never deletes anyone else's
cached session.

**5. Switch back to admin WITHOUT re-entering credentials, while admin's
cached token is still valid — demonstrates gotcha #2's "doesn't switch"
case:**
```bash
rocketvault vaults list --username admin
cat ~/.rocketvault/sessions/current
```
Expect the command to succeed (admin's still-valid cached token is loaded
and used), but `current` **still says `alice`** — this one-off command
never called `SaveSession` because no refresh was needed.

**6. Force gotcha #2's "does switch" case** by making admin's cached token
look expired, then repeat the same command:
```bash
python3 -c "
import json, datetime
p = '$HOME/.rocketvault/sessions/admin.json'
d = json.load(open(p))
d['expires_at'] = (datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(hours=1)).isoformat()
json.dump(d, open(p, 'w'))
"
rocketvault vaults list --username admin
cat ~/.rocketvault/sessions/current
```
Expect the command to still succeed (transparent refresh via admin's
`refresh_token`), but this time `current` **does** flip back to `admin` —
the refresh path called `SaveSession`. Same CLI invocation as step 5,
opposite effect on `current`, purely because of token freshness at the
moment it ran.

**7. Negative check confirming gotcha #1** — manually corrupt the pointer
with a trailing newline and watch it fail non-obviously:
```bash
echo 'alice' > ~/.rocketvault/sessions/current   # note: echo, not printf — adds \n
rocketvault vaults list
```
Expect `Error: Authentication failed - no credentials provided and no
cached session found` even though `alice.json` genuinely exists and is
valid — because the lookup key became `alice_` (sanitized from `alice\n`),
not `alice`. Fix it:
```bash
printf '%s' 'alice' > ~/.rocketvault/sessions/current
rocketvault vaults list
```
Expect this to succeed — same target user, only the trailing newline
differed.

**8. Capture a token, then log out, then prove gotcha #3 concretely:**
```bash
CAPTURED_TOKEN=$(cat ~/.rocketvault/sessions/alice.json | jq -r .token)
rocketvault users logout
cat ~/.rocketvault/sessions/current 2>&1   # expect: No such file or directory
curl -s -o /dev/null -w "%{http_code}\n" $BASE/vaults \
  -H "Authorization: Bearer $CAPTURED_TOKEN"
```
Expect `logout` to print `Logged out alice.` and remove the `current`
pointer (the `alice.json` file itself is also deleted by `DeleteSession`).
Expect the final `curl` — using the token captured *before* logout — to
still return `200`, not `401`. This is the proof: `logout` never told the
server anything; the JWT is still valid until its own TTL naturally
expires. If you want the token to actually stop working, you need session
*revocation* (`DELETE /api/v1/users/sessions/{id}` or `/sessions` — see
§3.2), which logout does not do.

**9. Targeted logout — clear one user without touching another:**
```bash
rocketvault users login --username admin --password admin123 --totp-code "$TOTP_CODE"
rocketvault users login --username alice --password alice123456 --totp-code "$ALICE_CODE"
# current now points at alice; log out admin specifically instead
rocketvault users logout --username admin
ls ~/.rocketvault/sessions/
cat ~/.rocketvault/sessions/current
```
Expect `admin.json` gone, `alice.json` and `current` (still `alice`)
untouched — `logout --username` targets one file without disturbing
whichever session is actually active.

**10. Negative case — zero cached sessions at all:**
```bash
rocketvault users logout   # clears alice, the only one left
rocketvault vaults list
```
Expect exactly:
```
Error: Authentication failed - no credentials provided and no cached session found
Run 'rocketvault users login' or 'rocketvault users login --oidc' first, or pass --username/--password/--totp-code.
```

##### Cleanup

```bash
rm -rf ~/.rocketvault/sessions
```

### 3.5 OAuth2 service accounts

> **Concept: service accounts vs. human users.** Two separate layers, easy to
> conflate:
> - **Management plane** (create/list/get/delete/rotate a service account) is
>   **admin-only, no exceptions** — every handler in `api/oauth2.go` checks
>   `common.HasRequiredRole(c.Claims.Role, model.RoleAdmin)` directly, with no
>   role hierarchy and no vault-scoped override (not even `Key Vault Data
>   Access Administrator` reaches it). This is intentional: a service account
>   is a new credential that can be granted access, so letting any regular
>   user mint one would be a privilege-escalation hole.
> - **Usage/data plane** (what the resulting client_id/secret can actually
>   touch) is **not admin-gated at all**. The app authenticates itself via
>   `POST /api/v1/oauth2/token` (client-credentials grant, no human, no TOTP)
>   to get a JWT with `role: service_account`. From there its access is
>   exactly as fine-grained as any human's: the flat `service_account` global
>   role (read/list only), or — the realistic case — a per-vault Azure role
>   grant via `rocketvault vault-access grant <name> --role "..." --principal-type service_account --vault <vault>`.
>
> The use case is machine-to-machine access: an application (e.g.
> `internal/vaultclient` / `examples/consumer-service`) that needs to fetch
> secrets/keys/certs unattended — a container or CI job with no human present
> to type a TOTP code. An admin creates and scopes the identity once; the app
> then authenticates itself on every subsequent run. Non-admin humans never
> manage service accounts directly — they ask an admin to create/scope one,
> same as asking an admin to create a vault or grant a role.

- [ ] `POST /api/v1/service-accounts` (admin) → creates a service account, returns
      client ID/secret.
- [ ] `POST /api/v1/oauth2/token` with HTTP Basic (client_id:client_secret),
      grant_type=client_credentials → `200`, JWT with `role: service_account`.
- [ ] Use that JWT against a data-plane route (e.g. `GET /api/v1/secrets`) →
      read-only per the `service_account` global role (read/list only, no write).
- [ ] `POST /api/v1/service-accounts/{id}/rotate` → new secret issued; old secret
      immediately fails a new `/oauth2/token` request.
- [ ] Known gotcha (B2, fixed): tokens issued **before** rotation stay valid until
      their own TTL expires — rotation doesn't revoke live tokens, this is
      intentional (standard OAuth2 behavior). Don't file this as a bug if observed.
- [ ] `DELETE /api/v1/service-accounts/{id}` → subsequent `/oauth2/token` for that
      client fails, and any already-issued JWT for it now 401s immediately (not
      just at TTL expiry — service-account revocation is checked per-request via
      `oauth2ClientRepo.GetByID`).
- [ ] **Negative case — management plane is admin-only, no exceptions**: as a
      non-admin (`user`, `secrets_manager`, or even a service-account-role JWT),
      hit all five endpoints — `POST /service-accounts`, `GET /service-accounts`,
      `GET /service-accounts/{id}`, `DELETE /service-accounts/{id}`,
      `POST /service-accounts/{id}/rotate` — confirm every one returns `403`
      (`SetPermissionError`), including a user holding `Key Vault Data Access
      Administrator` in some vault (that role manages vault role assignments
      only, not service accounts — this route doesn't go through the vault
      role-assignment layer at all).

#### Worked example: `connect-dev` vault + `Connect-Dev-ci` service account

**New to this repo?** This is a fully self-contained, copy-pasteable
walkthrough — you shouldn't need to read any other file first. It builds one
vault and one service account from scratch, then proves the two-audience
model from the concept box above by testing each audience's boundary with
both a positive and a negative case.

##### Prerequisites

- Server running against a scratch config/DB (see **§0 Environment Setup**
  above — don't point this at a shared dev database).
- `rocketvault` CLI built and on your `PATH` (`go build -o rocketvault . `
  from repo root, or substitute `go run main.go` for every `rocketvault ...`
  command below).
- `curl` and [`jq`](https://jqlang.org/) installed (`jq` just pretty-prints
  and extracts JSON — every `| jq` below is optional but makes the output
  readable).
- An admin user already created, with `ROCKETVAULT_TOTP_SECRET` exported in
  your shell (see **§2 Admin Bootstrap** above — the bootstrap command prints
  an `otpauth://...` URL; extract and export the base32 secret from it, then
  add it to your shell profile so you don't repeat this every session):
  ```bash
  export ROCKETVAULT_TOTP_SECRET=$(echo "$OTPAUTH_URL" | sed -n 's/.*secret=\([A-Z2-7]*\).*/\1/p')
  ```
  This is the exact env var `scripts/totp_generator.go` (`envSecretKey =
  "ROCKETVAULT_TOTP_SECRET"`) reads automatically — no `-secret` flag needed
  once it's exported. Don't invent a different variable name here (e.g.
  `ADMIN_TOTP_SECRET`) — it won't be read by anything and `oathtool`/the
  generator will silently produce a code from an empty string instead of
  erroring, which looks exactly like a wrong-code auth failure and wastes
  time debugging the wrong thing.

##### The three gotchas this example is built to surface

All three are real, verified-against-source behaviors, not hypothetical edge
cases — you will hit them if you don't know about them going in.

1. **A fresh admin has ZERO vault data-plane access anywhere — even in a
   vault admin themselves just created.** Global `admin` bypasses vault
   *management* checks (create/delete/purge vault, grant/revoke roles —
   `CanManageVault`/`CanManageRoleAssignments`, both of which short-circuit
   for `admin`: `if common.HasRequiredRole(accountRole, model.RoleAdmin) {
   return true }`) but **never** vault *data-plane* checks (secrets/keys/
   certs CRUD — `RequireDataAction`, which deliberately has no admin
   short-circuit, matching HTTP exactly). So immediately after creating
   `connect-dev`, admin must explicitly self-grant a role there before doing
   anything with secrets/keys/certs in it — skipping this produces
   `forbidden: no role grants Microsoft.KeyVault/vaults/secrets/setSecret/action
   in this vault` the moment a secret is seeded. Step 2 below handles this.
2. **Vault names must be lowercase.** `model.ValidateVaultName` enforces
   `^[a-z0-9](?:[a-z0-9-]{1,61}[a-z0-9])$` (Azure's own vault-naming rule,
   `model/vault.go`) — `Connect-Dev` is **rejected**; use `connect-dev`. The
   service account's *display* name (`Connect-Dev-ci`) has no such
   restriction — only vault names are constrained.
3. **The service account has two different identifiers, used in two
   different places, and they are not interchangeable:**
   | Where | Identifier | Why |
   |---|---|---|
   | `POST /oauth2/token`'s `client_id` | the service account's **name** (`Connect-Dev-ci`) | `oauth2_service.go`'s `IssueToken(clientName, secret)` resolves it via `repo.FindByName(ctx, clientName)` — a `SELECT ... WHERE name = ?` |
   | `vault-access grant`/`revoke` **principal** argument | the service account's **UUID** (the `id` field from its create response) | `resolvePrincipal` in `internal/services/authorization/role_assignment_service.go` only accepts a UUID *or* a human username resolved via `userLookup.ReadByUsername` — there is no service-account-by-name lookup anywhere in the codebase |

   Passing the name where the UUID is expected fails with
   `grant failed: principal not found: Connect-Dev-ci` — not a helpful
   "did you mean the UUID?" hint, so it's easy to assume the command itself
   is broken rather than realizing the wrong identifier was passed. There is
   also **no CLI command for service-account management at all** — only HTTP
   routes exist for create/list/get/delete/rotate (`api/oauth2.go`) — so
   Part 1 below uses `curl` throughout, while Part 2's vault/vault-access
   steps use the `rocketvault` CLI.

##### Setup

```bash
BASE=http://localhost:8774/api/v1     # adjust host:port to your scratch config's server.listen_addr
TOTP_CODE=$(go run scripts/totp_generator.go -secret="$ROCKETVAULT_TOTP_SECRET" 2>&1 | grep -m1 -oP '(?<=--totp-code )\S+')
```
The `printCodes` function in `totp_generator.go` prints the code **twice** —
once under "Ready to use:" and again inside the "Full example:" line — so a
plain `grep -oP` without a match limit captures both occurrences and
`$TOTP_CODE` ends up as a two-line value with an embedded newline
(`"494610\n494610"`), which silently corrupts anything you embed it in (a
JSON body, a URL). `-m1` stops after the first match. If this ever breaks
(output format changes), fall back to running
`go run scripts/totp_generator.go` bare and reading the code off the screen
by hand.

TOTP codes are time-windowed (30s) — generate and use `$TOTP_CODE` in the
same breath. If a later step fails with an auth error and any real time has
passed since you generated it, regenerate before assuming anything else is
wrong.

---

##### Part 1 — Management plane: "who can mint machine identities" (admin-only, no exceptions)

**1. Create the vault**, using the CLI. The first `login` caches a session to
`~/.rocketvault/sessions/`, so no further command in this walkthrough needs
credential flags unless noted:
```bash
rocketvault users login --username admin --password admin123 --totp-code "$TOTP_CODE"
rocketvault vaults create connect-dev
```
Expect: a confirmation line with the new vault's ID. Verify with
`rocketvault vaults get connect-dev`.

**2. Self-grant admin access to the new vault (gotcha #1, fixed here).**
Creating a vault is a management operation, which admin's role bypasses —
but everything you do *inside* that vault from here on (including the
secret seeded in step 13) is a data-plane operation, which admin does
**not** bypass. Grant yourself full control now so the rest of this
walkthrough doesn't stall on the exact error described in gotcha #1 above:
```bash
rocketvault vault-access grant admin --role "Key Vault Administrator" --vault connect-dev
```
Expect: `granted Key Vault Administrator to admin in vault (assignment <id>)`.
This works because `vault-access grant` is itself a management operation
(`CanManageRoleAssignments`, which **does** short-circuit for admin) — the
one place admin's bypass reaches far enough to close its own later
data-plane gap. `admin` here is a plain username (default `--principal-type
user`), not a UUID — unlike the service account's grant in step 8, which
needs a UUID (gotcha #3 below).

**3. Negative check — the lowercase-naming rule (gotcha #2):**
```bash
rocketvault vaults create Connect-Dev
```
Expect failure with the underlying validation error surfacing through the
CLI's error output:
`invalid vault name "Connect-Dev": must be 3-63 lowercase alphanumerics or hyphens, no leading/trailing hyphen`

**4. Get an admin JWT** — needed because service-account management is
HTTP-only, so we can't rely on the CLI's cached session for these calls:
```bash
ADMIN_TOKEN=$(curl -s -X POST $BASE/users/login \
  -H "Content-Type: application/json" \
  -d "{\"username\":\"admin\",\"password\":\"admin123\",\"totp_code\":\"$TOTP_CODE\"}" \
  | jq -r .token)
```
Expect the full login response (before the `jq -r .token` extraction) to
look like:
```json
{"token":"eyJhbGciOi...","refresh_token":"eyJhbGciOi...","user_id":"...","username":"admin","role":"admin"}
```
If `$ADMIN_TOKEN` comes back empty/`null`, the TOTP code likely expired
between generating it and this step — regenerate and retry.

**5. Create the service account:**
```bash
curl -s -X POST $BASE/service-accounts \
  -H "Authorization: Bearer $ADMIN_TOKEN" -H "Content-Type: application/json" \
  -d '{"name":"Connect-Dev-ci","description":"CI pipeline for connect-dev vault"}' | jq .
```
Expect `201` with a body shaped like:
```json
{
  "id": "b3e1a2c4-....",
  "name": "Connect-Dev-ci",
  "description": "CI pipeline for connect-dev vault",
  "enabled": true,
  "created_at": "2026-08-16T...Z",
  "expires_at": null,
  "client_secret": "a-long-random-string-shown-only-once"
}
```
**Save both `id` and `client_secret` now** — `client_secret` is a one-time
value; there is no "reveal" later, only `rotate` (which invalidates it and
issues a new one):
```bash
SA_ID=<id from the response above>
SA_SECRET=<client_secret from the response above>
```

**6. Round out management-plane coverage** (all admin-only, all HTTP):
```bash
curl -s $BASE/service-accounts -H "Authorization: Bearer $ADMIN_TOKEN" | jq .
curl -s $BASE/service-accounts/$SA_ID -H "Authorization: Bearer $ADMIN_TOKEN" | jq .
```
The list response wraps the array: `{"service_accounts":[...],"total":N}`.

**7. Negative test — confirm management really is admin-only, no exceptions.**
Create (or reuse) a plain `user`-role account, log in as them to get a
non-admin token, then repeat every management call with it:
```bash
USER_TOKEN=$(curl -s -X POST $BASE/users/login \
  -H "Content-Type: application/json" \
  -d '{"username":"<some-non-admin-username>","password":"<their-password>","totp_code":"<their-code>"}' \
  | jq -r .token)

curl -s -o /dev/null -w "%{http_code}\n" -X POST $BASE/service-accounts \
  -H "Authorization: Bearer $USER_TOKEN" -H "Content-Type: application/json" \
  -d '{"name":"should-fail"}'
curl -s -o /dev/null -w "%{http_code}\n" $BASE/service-accounts -H "Authorization: Bearer $USER_TOKEN"
curl -s -o /dev/null -w "%{http_code}\n" $BASE/service-accounts/$SA_ID -H "Authorization: Bearer $USER_TOKEN"
curl -s -o /dev/null -w "%{http_code}\n" -X DELETE $BASE/service-accounts/$SA_ID -H "Authorization: Bearer $USER_TOKEN"
curl -s -o /dev/null -w "%{http_code}\n" -X POST $BASE/service-accounts/$SA_ID/rotate -H "Authorization: Bearer $USER_TOKEN"
```
Expect all five `-w "%{http_code}"` lines to print `403`. The JSON body on
each (drop `-o /dev/null` to see it) looks like:
```json
{"id":"Insufficient permissions: admin role required to create service accounts","message":"Insufficient permissions: admin role required to create service accounts","detailed_error":"","status_code":403}
```
(`api/context.go`'s `SetPermissionError` reuses the permission string as both
the `id` and `message` fields — the exact wording differs slightly between
`create` ("admin role required to create service accounts") and the other
four ("admin role required to manage service accounts"), but the shape and
status code are identical.)

**Don't run `rotate` or `delete` against `$SA_ID` yet** — Part 2 needs its
current, still-valid secret.

---

##### Part 2 — Usage/data plane: "what can that machine identity actually touch" (not admin-gated at all)

**8. Grant the service account a role in the vault.** The principal argument
is `$SA_ID` (the UUID from step 5) — **not** the name:
```bash
rocketvault vault-access grant "$SA_ID" \
  --role "Key Vault Secrets User" --principal-type service_account --vault connect-dev
```
Expect: `granted Key Vault Secrets User to <SA_ID> in vault (assignment <assignment-id>)`.
**Copy the `assignment <id>` from this output** — you'll need it for step 16's revocation test.

**9. Negative check confirming gotcha #3** — try the same grant using the
service account's *name* instead of its UUID:
```bash
rocketvault vault-access grant Connect-Dev-ci --role "Key Vault Secrets User" \
  --principal-type service_account --vault connect-dev
```
Expect failure: `grant failed: principal not found: Connect-Dev-ci`.

**10. Confirm the grant landed:**
```bash
rocketvault vault-access list --vault connect-dev
```
Expect a table:
```
ASSIGNMENT-ID                          ROLE                     PRINCIPAL-ID
<assignment-id>                        Key Vault Secrets User   <SA_ID>
```

**11. The service account authenticates itself** — no admin, no TOTP, no
human involved at all. This is the crux of "usage plane is not admin-gated":
```bash
SA_TOKEN=$(curl -s -X POST $BASE/oauth2/token \
  -u "Connect-Dev-ci:$SA_SECRET" \
  -d "grant_type=client_credentials" | jq -r .access_token)
```
Note `client_id` here (the `-u` username half) is the **name**
(`Connect-Dev-ci`) — the opposite identifier from step 8. Expect a response
shaped like:
```json
{"access_token":"eyJhbGciOi...","token_type":"Bearer","expires_in":1800}
```
(`expires_in` reflects your config's `oauth2.token_expiry`, 1800s = 30m in
the dev config.)

**12. Negative case — try to write with the service account's token.**
`Key Vault Secrets User` is read/list only, no write, so this must fail:
```bash
curl -s -o /dev/null -w "%{http_code}\n" -X POST $BASE/vaults/connect-dev/secrets \
  -H "Authorization: Bearer $SA_TOKEN" -H "Content-Type: application/json" \
  -d '{"name":"ci-token","value":"s3cr3t"}'
```
Expect `403`.

**13. Seed a secret as admin.** The service account genuinely cannot create
one (that's what step 12 just proved), so the vault needs at least one secret
in it, created with `$ADMIN_TOKEN`, before the read check in step 14 has
anything to actually read. This is also the step that would have failed with
`forbidden: no role grants ... setSecret ... in this vault` if step 2's
self-grant had been skipped:
```bash
curl -s -X POST $BASE/vaults/connect-dev/secrets \
  -H "Authorization: Bearer $ADMIN_TOKEN" -H "Content-Type: application/json" \
  -d '{"name":"ci-token","value":"s3cr3t"}' | jq .
```
Expect `201` with the created secret's metadata (no `value` field echoed back
in the response — RocketVault doesn't return secret values on write).

**14. Positive case — read with the service account's token.** This is the
step that closes the loop: the identity created in Part 1, granted access in
step 8, and authenticated in step 11 can now actually do the one thing it was
scoped to do:
```bash
curl -s $BASE/vaults/connect-dev/secrets -H "Authorization: Bearer $SA_TOKEN" | jq .
```
Expect `200`, listing the `ci-token` secret admin created in step 13 (list
view doesn't include the value — use `GET .../secrets/{id}` with `$SA_TOKEN`
if you want to confirm it can also read the value itself, which `Secrets
User` does grant).

**15. Scope check** — same `$SA_TOKEN` against a vault it has *no* grant in
(e.g. `default`):
```bash
curl -s -o /dev/null -w "%{http_code}\n" $BASE/vaults/default/secrets \
  -H "Authorization: Bearer $SA_TOKEN"
```
Expect `403` — confirms the grant from step 8 is scoped to `connect-dev`
only, not a blanket "this identity can read secrets everywhere" grant. Note
this also holds for `admin`'s own token from step 2's grant — that grant was
`connect-dev`-only too, not global; admin still has zero data-plane access in
`default` unless separately granted.

**16. Revocation is live, not tied to token expiry.** Using the assignment
ID you saved in step 8:
```bash
rocketvault vault-access revoke <assignment-id> --vault connect-dev
```
Then immediately retry the **same, still-unexpired** `$SA_TOKEN` from step 11
against the read that worked in step 14:
```bash
curl -s -o /dev/null -w "%{http_code}\n" $BASE/vaults/connect-dev/secrets \
  -H "Authorization: Bearer $SA_TOKEN"
```
Expect `403` now, even though the JWT itself hasn't expired — proving
`HasDataAction` re-checks the live role-assignment table on every request
rather than baking the grant into the token at issuance.

##### Cleanup

```bash
rocketvault vaults delete connect-dev        # soft-delete
rocketvault vaults purge connect-dev         # if you want it fully gone
curl -s -X DELETE $BASE/service-accounts/$SA_ID -H "Authorization: Bearer $ADMIN_TOKEN"
```

### 3.6 JWKS rotation

- [ ] `POST /api/v1/jwks/rotate` (admin) → new signing key generated.
- [ ] `GET /jwks.json` now lists both old and new public keys (old stays for
      `jwt.rotation_overlap`, 1h in dev config).
- [ ] A JWT signed with the old key still validates during the overlap window.
      After the overlap window, it should not (hard to test live without waiting —
      note as a config-driven expectation rather than exercising the full wait).

### 3.7 CLI remote-server targeting (contexts, target resolution, local-only guard)

> **Concept: this is a foundation, not a working remote CLI yet.** Nothing
> below performs a real remote HTTP call — there is no second RocketVault
> instance to stand up for this section, and no resource command
> (`secrets`/`keys`/`certificates`/`vaults`/etc.) can actually read or write
> anything on a remote server today. What exists is the shared machinery
> every future remote adapter will build on:
> - **Target resolution** (`internal/cliclient.ResolveTarget`): an explicit
>   `--server <url>` flag beats the `ROCKETVAULT_ADDR` env var, which beats
>   the active named context (`rocketvault context use <name>`), which beats
>   local mode (nothing resolves).
> - **The local-only guard** (`persistentPreRun` in `cmd/root.go`): whenever
>   *any* target resolves, every command except the `context` group itself
>   and cobra's own built-ins (`help`, `completion`) refuses outright with a
>   clear error instead of silently running against the local instance. This
>   is deliberate, temporary scaffolding — the code comment above it in
>   `cmd/root.go` says so directly — that gets carved back command-by-command
>   as each resource group's own remote adapter ships (see
>   `docs/superpowers/plans/2026-08-17-cli-remote-server-foundation.md`'s
>   Follow-on plans list). Today it means: nothing can accidentally read or
>   write the wrong instance's data, but also nothing remote works yet.
> - **Named contexts** (`~/.rocketvault/contexts.json`) hold no credentials —
>   only `Server`/`Username`/`Vault` defaults. Credentials live in the
>   session cache, which was made server-aware (Task 1 of the foundation
>   plan) so it *can* hold one session per server — but nothing populates a
>   remote session yet: `rocketvault users login --server <url>` is refused
>   by the same guard as every other command, so there is currently no way to
>   actually authenticate against a remote server. That's the first
>   follow-on plan (`users` remote adapter), not this one.
> - **TLS trust flags** (`--ca-cert`, `--insecure-skip-verify`) are built and
>   unit-tested (`internal/cliclient/httpclient_test.go`) but have zero
>   observable effect in this section — no command calls
>   `internal/cliclient.NewHTTPClient` yet. Checking their `--help` text below
>   confirms they exist, not that they do anything yet.
> - **`internal/cliclient.RequireLocal`** exists for commands that can never
>   be remoted at all (`backup create/restore`, `master-key rotate`, `vaults
>   purge/recover`) but isn't wired into any of them yet. They're safe today
>   regardless, because the blanket guard above already refuses them like
>   every other non-`context` command — so there's no live gap, just
>   not-yet-paid-down wiring debt for when their resource groups start
>   gaining real remote support and get carved out of the blanket guard.

- [ ] `context add <name> --server <url> [--default-username U] [--default-vault V]`
      saves a context; `--server` is required (fails with `--server is required`
      if omitted).
- [ ] `context list` shows every saved context, with `*` in the `Current`
      column for whichever one is active (none marked, if none is active).
- [ ] `context use <name>` sets the active context; an unknown name fails
      with `context "<name>" not found` and does not change the current
      pointer.
- [ ] `context current` prints `<name> -> <server>`, or
      `no current context set (local mode)` if none is active.
- [ ] `context remove <name>` deletes it; removing the *active* context also
      clears the current pointer (`context current` goes back to "no current
      context set"). Removing an unknown name is a silent no-op (exit 0, no
      error) — not a bug, just not validated.
- [ ] Each of `--server`, `ROCKETVAULT_ADDR`, and an active context
      independently makes a resource command (e.g. `secrets list`) resolve a
      remote target and get refused.
- [ ] Precedence holds when more than one is set at once: `--server` beats
      `ROCKETVAULT_ADDR` beats the active context — confirm by checking which
      URL appears in the refusal's error message.
- [ ] The guard fires for every resource-group command (`secrets`, `keys`,
      `certificates`, `vaults`, `vault-access`, `users`, `audit`) and for
      `backup create`, `master-key rotate`, `vaults purge`, `vaults recover` —
      none of them silently falls back to local.
- [ ] `context` subcommands and `help`/`completion` remain completely
      unaffected even with a remote target active (this was NB1/NB2 from the
      2026-08-17 final review — regression-check it specifically, it broke
      once already).
- [ ] Local mode is byte-for-byte unchanged when nothing resolves: no
      `--server`, no `ROCKETVAULT_ADDR`, no active context.

#### Worked example: contexts, precedence, and the refusal (not a live remote round-trip)

**New to this repo?** This is a fully self-contained, copy-pasteable
walkthrough. It proves the resolution precedence and the local-only guard —
it does **not** create, read, or modify any secret/key/certificate anywhere,
local or remote, because no command can do that remotely yet.

##### Prerequisites

- `rocketvault` CLI built (`go build -o rocketvault .` from repo root).
- An **isolated `$HOME`**, e.g. `export HOME=/tmp/rv-remote-demo` — contexts
  and sessions are read from `$HOME/.rocketvault/`, and this walkthrough adds
  and removes contexts freely. Don't point it at your real home directory.
- No running server needed at all — every step below either manages local
  context state or gets refused before any network call would occur.

##### The gotchas this example is built to surface

1. **There is nothing to "connect" to yet.** If you came here expecting to
   read a secret from a second RocketVault instance, that feature doesn't
   exist — this section tests the targeting/refusal machinery only.
2. **`context add --server` does not validate its value at all** beyond
   "non-empty" — `rocketvault context add weird --server not-a-url` succeeds
   and saves it verbatim. Don't read a successful `context add` as
   confirmation the URL is reachable or even well-formed.
3. **`users login --server <url>` is refused, same as everything else.**
   There is currently no way to authenticate against a remote server via the
   CLI — the session cache is *ready* for it (per-server keys, non-breaking
   migration), but nothing populates one yet.
4. **The refusal error always names the *resolved* target, not necessarily
   the flag you typed** — with `ROCKETVAULT_ADDR` set and no `--server`, the
   error names the env var's URL; this is how you confirm precedence
   resolved the value you expected instead of guessing from behavior alone.

##### Steps

**1. Save and inspect a context:**
```bash
rocketvault context add prod --server https://vault.prod.example.com \
  --default-username admin --default-vault prod-vault
rocketvault context list
```
Expect:
```
Name  Server                          Default Username  Default Vault  Current
----  ------------------------------  ----------------  -------------  -------
prod  https://vault.prod.example.com  admin              prod-vault
```
No `*` yet — `add` only saves it, `use` is a separate step.

**2. Negative case — `--server` is required:**
```bash
rocketvault context add bad
```
Expect: `Error: --server is required`.

**3. Activate it and confirm:**
```bash
rocketvault context use prod
rocketvault context current
rocketvault context list
```
Expect `context current` → `prod -> https://vault.prod.example.com`, and
`context list` now shows `*` in prod's `Current` column.

**4. Negative case — unknown context name:**
```bash
rocketvault context use does-not-exist
```
Expect: `Error: context "does-not-exist" not found` — and `context current`
still reports `prod`, unchanged.

**5. With `prod` active, a real resource command now resolves it
automatically — no `--server` needed — and gets refused, not silently run
locally:**
```bash
rocketvault secrets list
```
Expect:
```
Error: remote mode (--server/ROCKETVAULT_ADDR/context "https://vault.prod.example.com")
is not yet supported for "rocketvault secrets list"; unset it to run against the local instance
```

**6. Precedence — `ROCKETVAULT_ADDR` beats the active context:**
```bash
ROCKETVAULT_ADDR=https://vault.staging.example.com rocketvault secrets list
```
Expect the same refusal, but naming `https://vault.staging.example.com` —
proving the env var, not the context, resolved.

**7. Precedence — `--server` beats both:**
```bash
ROCKETVAULT_ADDR=https://vault.staging.example.com rocketvault secrets list \
  --server https://vault.qa.example.com
```
Expect the refusal to name `https://vault.qa.example.com`.

**8. The `context` group and cobra's built-ins are unaffected by all of the
above (this is the NB1/NB2 regression check):**
```bash
rocketvault context list                 # still works, active target ignored
rocketvault help secrets                 # succeeds, no auth/DB error
rocketvault completion bash | head -3    # succeeds
```

**9. Commands with no remote route at all are refused too — but not always
by the same check, and the error shape differs accordingly:**
```bash
rocketvault backup create --output /tmp/x.backup
rocketvault master-key rotate --new-key-env X
```
Expect both refused by the generic blanket guard (same shape as step 5):
`remote mode (...) is not yet supported for "rocketvault backup create"` /
`"rocketvault master-key rotate"`. Neither calls `RequireLocal` yet — see
the concept box above.
```bash
rocketvault vaults preview-migration
```
Expect a **different** message: `vaults preview-migration is a local-only
operation and cannot target a remote server; unset --server / ROCKETVAULT_ADDR
/ the active context to run it against this machine's own instance`. This one
*does* call `RequireLocal` (the NB2 fix, 2026-08-17) — it has its own
`PersistentPreRunE` that bypasses the blanket guard entirely (so it needed an
explicit check), while backup/master-key rotate go through root's shared
`PersistentPreRunE` and hit the blanket guard like any other command. Two
different code paths landing on the same outcome — don't assume the message
text is interchangeable across local-only commands.

**10. Clean up and confirm local mode is unaffected once nothing resolves:**
```bash
rocketvault context remove prod
rocketvault context current
# no current context set (local mode)
```
From here, every command in the rest of this test plan behaves exactly as
it always has — this section adds no risk to local-mode usage.

---

## 4. User Management

- [ ] `POST /api/v1/users` (admin) → create users with each global role: `admin`,
      `user`, `secrets_manager`, `crypto_manager`, `certificate_manager`,
      `service_account`. Confirm `totp_secret` returned as a full `otpauth://` URL.
- [ ] `GET /api/v1/users` (admin) → lists all.
- [ ] `GET /api/v1/users/{id}` as a non-admin for **their own** ID → succeeds; for
      **someone else's** ID → confirm actual behavior (403 vs 404) and note it.
- [ ] `PUT /api/v1/users/{id}` (admin) → update role/username; as non-admin → `403`.
- [ ] `DELETE /api/v1/users/{id}` (admin) → user removed; their existing JWT should
      immediately 401 (not wait for TTL) — cross-check against §3.2 session revocation.
- [ ] Role-permission matrix spot check (`.claude/manual-testing/CLAUDE.md` §
      "Account Roles & Permissions" table in `MANUAL_TESTING.md`): log in as
      `secrets_manager` and confirm full CRUD on secrets but `403` on any key/cert
      write; repeat for `crypto_manager` (keys) and `certificate_manager` (certs).

---

## 5. Vault Lifecycle

- [ ] `rocketvault vaults list` — the `default` vault always exists out of the box.
- [ ] ```bash
      rocketvault vaults create test-vault-1 \
        --username admin --password admin123 --totp-code <code>
      rocketvault vaults create test-vault-2 --purge-protection --retention-days 30 \
        --username admin --password admin123 --totp-code <code>
      ```
- [ ] `GET /api/v1/vaults` / `rocketvault vaults list` → both appear.
- [ ] `GET /api/v1/vaults/{name}` / `rocketvault vaults get test-vault-1` → detail view.
- [ ] `PATCH /api/v1/vaults/{name}` / `rocketvault vaults update test-vault-1 ...` →
      update tags/description.
- [ ] `DELETE /api/v1/vaults/default` → **must be refused** (`default` vault can't
      be soft-deleted). Confirm 400/403 with a clear message.
- [ ] `DELETE /api/v1/vaults/test-vault-1` → `204`, soft-deleted.
- [ ] `GET /api/v1/vaults?include_deleted=true` → shows `test-vault-1` as deleted;
      without the flag it's absent.
- [ ] `rocketvault vaults recover test-vault-1` → restored, visible again in a
      normal list.
- [ ] Delete `test-vault-1` again, then `DELETE /api/v1/vaults/test-vault-1/purge`
      (or `rocketvault vaults purge test-vault-1`) → permanently gone, `recover`
      now fails.
- [ ] **Cascade soft-delete**: create a vault, add a secret/key/cert to it, soft-delete
      the vault, confirm its child resources become inaccessible via the normal
      vault-scoped routes and are separately recoverable/purgeable per §8–10's
      soft-delete sections (this is the vaults→children cascade, not vault
      resurrection auto-restoring children — verify which behavior actually happens).
- [ ] **Admin-bypass vs. role-grant divergence** (per CLAUDE.md "Azure Role
      Additions"): as a non-admin holding only `Key Vault Purge Operator` in
      `test-vault-2`, confirm the CLI `vaults purge` succeeds (admin-bypass logic in
      `CanPurgeVault` doesn't apply here since you're not admin, but the explicit
      role grant does) — then confirm the same non-admin hitting
      `DELETE /api/v1/vaults/test-vault-2/purge` over HTTP also succeeds (role-gated,
      no admin bypass either way for this user). Then, as a **different** admin user
      with **no** role grant in a vault, confirm CLI `vaults purge` succeeds (admin
      bypass) but the HTTP purge route on the same vault returns `403` (no admin
      bypass on the HTTP path) — this is the one documented place CLI and HTTP
      genuinely diverge, worth explicitly confirming rather than assuming.
- [ ] `rocketvault vaults preview-migration` — dry-run command, confirm it doesn't
      require the same DB/container bootstrap as other commands (per known-bugs B4,
      it has its own lightweight `PersistentPreRunE`) and produces a sensible report
      against the default vault's pre-multi-vault resources, if any exist.

#### Per-vault webhook configuration (storage only — nothing is delivered yet)

Landed 2026-08-20. This is **configuration, not delivery**: there is no outbound
HTTP anywhere in the vault/secret/key service packages, so nothing will ever
arrive at the URL you set. Delivery is specified but unbuilt
(`docs/superpowers/specs/2026-08-20-webhook-delivery-primitive-design.md`), and
the parity doc deliberately declines to score a row for it. Test the CRUD and
the authorization boundary; do **not** stand up a listener and wait for a call.

- [ ] Set a config, both ways:
      ```bash
      rocketvault vault-webhook set --vault test-vault-1 --url https://example.invalid/hook
      # HTTP equivalent:
      #   PUT /api/v1/vaults/test-vault-1/webhook  {"url":"https://example.invalid/hook"}
      ```
- [ ] `rocketvault vault-webhook get --vault test-vault-1` / `GET .../webhook` →
      returns `url`, `enabled`, `created_at`, `updated_at` and **never** the
      signing secret. `model.VaultWebhookConfig.ToResponse` drops
      `SigningSecretEncrypted` by construction.
- [ ] The **`PUT` response is different, and deliberately so**: it includes a
      plaintext `signing_secret` on create and on `rotate_secret: true`, and only
      then. A plain update (same URL, no rotate) and every `GET` omit it. This is
      a show-once credential, the same pattern as an API key — verified live
      2026-09-03. Confirm you see it exactly twice in the sequence below and
      never again.
- [ ] URL validation (`validateWebhookURL`, `internal/services/vaults/webhook_service.go`)
      rejects, with `ErrInvalidWebhookURL`, *before* touching storage: a non-`https`
      scheme (`http://...`), a scheme with no host (`https://`), an unparseable
      URL, and one embedding credentials (`https://user:pw@host/path`). Try each —
      confirm nothing is stored on any of them (a following `get` still shows the
      previous config, or `404` if there was none).
- [ ] `--rotate-secret` on `set` → replaces the signing secret; confirm `get`
      still shows the same `url` and no secret material either before or after.
- [ ] `--enabled=false` then `--enabled=true` → toggles without clearing the URL.
      Omitting `--enabled` on an update keeps the current value (it defaults to
      `true` on create only).
- [ ] `rocketvault vault-webhook delete --vault test-vault-1` → removed; a
      following `get` → `404`.
- [ ] **Authorization**: this is a vault-*management* operation, not data-plane.
      Both the CLI (`requireCanManageVault`, `cmd/vault-webhook/authz.go`) and the
      HTTP handlers (`api/vault_webhook.go`) gate on `CanManageVault` — the same
      primitive, deliberately, so the two paths cannot drift. Confirm a user
      holding only a data-plane role (e.g. `Key Vault Secrets Officer`) in the
      vault is refused on **both** paths, and that a caller with `vaults/manage`
      succeeds on both. Per the CLI-authorization contract in CLAUDE.md, the CLI
      helper is the only enforcement point on that path.
- [ ] Confirm each successful change lands in the audit log attributed to a real
      principal, not to nobody — the CLI has no middleware to stamp an actor, so
      `requireCanManageVault`'s returned principal ID is what makes attribution
      work (see its doc comment).

### Worked example: webhook config, the show-once secret, and URL validation

> **Concept: this is a credential-issuing endpoint wearing a CRUD endpoint's
> clothes.** `PUT .../webhook` doesn't just store a URL — it mints a signing
> secret and returns it **once, in plaintext**, then never again. The stored
> copy is encrypted (`VaultWebhookConfig.SigningSecretEncrypted`) and
> `ToResponse` (`model/vault_webhook.go:31-38`) drops it, so every `GET` is
> secret-free. Miss the `PUT` response and the only recovery is
> `rotate_secret: true`, which mints a new one and invalidates the old. Also
> note what this feature is *not*: nothing sends. There is no outbound HTTP
> anywhere in the vault/secret/key service packages — delivery is specified but
> unbuilt. Do not stand up a listener and wait for a call.

All output below was captured live on 2026-09-03 against a scratch instance,
not inferred from the code.

#### Prerequisites

- Scratch config/DB and a running server (**§0**), admin bootstrapped (**§2**),
  `$TOKEN` holding an admin JWT, `$BASE` = `http://localhost:<port>/api/v1`.
- No role assignment is needed: webhook config is a vault-*management*
  operation gated by `CanManageVault`, which short-circuits for the global
  admin role. Contrast the key-import example in §8.1, where admin is **not**
  enough.

#### The 2 gotchas this example surfaces

1. **The signing secret appears in exactly two responses and no others** —
   create, and a rotate. A plain update omits it. Treat the `PUT` response as
   credential output and don't log it.
2. **Validation runs before storage, so a rejected write changes nothing.**
   All four rejection classes return `400` with a specific reason, and the
   previously stored config survives intact.

#### Walkthrough

**1. Create — note the secret, it will not be shown again.**

```bash
curl -s -X PUT $BASE/vaults/default/webhook -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' -d '{"url":"https://hooks.example.com/rv"}'
```
```json
{"url":"https://hooks.example.com/rv","enabled":true,"created_at":"2026-09-03T16:18:22Z",
 "updated_at":"2026-09-03T16:18:22Z","signing_secret":"<43-char base64url, shown once>"}
```

**2. GET — no secret.**

```bash
curl -s $BASE/vaults/default/webhook -H "Authorization: Bearer $TOKEN"
```
```json
{"url":"https://hooks.example.com/rv","enabled":true,"created_at":"2026-09-03T16:18:22Z","updated_at":"2026-09-03T16:18:22Z"}
```

**3. Plain update — still no secret, and `updated_at` moves.** Re-run the
step-1 command verbatim: the response now omits `signing_secret` entirely.
This is gotcha #1 — the same verb returns a credential or doesn't, depending
on whether a secret was minted.

**4. Rotate — a new secret, invalidating the old one.**

```bash
curl -s -X PUT $BASE/vaults/default/webhook -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"url":"https://hooks.example.com/rv","rotate_secret":true}'
```
```json
{"url":"https://hooks.example.com/rv","enabled":true,...,"signing_secret":"<a NEW 43-char base64url; the old one is now invalid>"}
```

**5. All four URL rejections — each `400`, nothing stored.**

```bash
for u in 'http://hooks.example.com/rv' 'https://' \
         'https://user:hunter2@hooks.example.com/rv' 'not-a-url'; do
  curl -s -X PUT $BASE/vaults/default/webhook -H "Authorization: Bearer $TOKEN" \
    -H 'Content-Type: application/json' -d "{\"url\":\"$u\"}"
done
```

Real messages, in order:

- `webhook url must be an absolute https URL: got scheme "http"`
- `webhook url must be an absolute https URL: missing host`
- `webhook url must be an absolute https URL: must not embed credentials (user:password@); authenticate the receiver with this vault's webhook signing secret instead`
- `webhook url must be an absolute https URL: got scheme ""`

Then `GET` again and confirm the step-4 config is untouched — that is the
half of gotcha #2 worth actually checking.

**6. Disable, then delete.**

```bash
curl -s -X PUT $BASE/vaults/default/webhook -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"url":"https://hooks.example.com/rv","enabled":false}'   # enabled:false, url preserved
curl -s -o /dev/null -w "%{http_code}\n" -X DELETE $BASE/vaults/default/webhook \
  -H "Authorization: Bearer $TOKEN"                             # 204
curl -s $BASE/vaults/default/webhook -H "Authorization: Bearer $TOKEN"
```
```json
{"id":"webhook config not found","message":"webhook config not found","status_code":404}
```

#### Teardown

Nothing to clean beyond the config itself, which step 6 deleted.

### Worked example: vault lifecycle, cascade delete, and the CLI-vs-HTTP purge divergence

> **Concept: soft-delete and recovery are symmetric and timestamp-scoped;
> purge is asymmetric and leaves a mess behind.** Deleting a vault cascades:
> `VaultService` explicitly fans out to the secret/key/cert repositories
> (`CascadeRepository.SoftDeleteVaultContents`,
> `internal/services/vaults/vault_service.go`) and stamps every child it
> touches with the vault's own `deleted_at`. Recovering a vault cascades the
> same way in reverse, restoring only the children carrying that exact
> timestamp — a child that was already soft-deleted on its own, earlier, is
> left alone. Purging a vault does **none of this**: `PurgeVault`
> (`internal/services/vaults/vault_service.go:408-445`) deletes the vault row
> and its `access_policies` rows and stops — no cascade repository call at
> all. There is also no database foreign key forcing the issue:
> `secrets`/`keys`/`certificates` all carry a plain `vault_id TEXT NOT NULL`
> column with no `REFERENCES vaults(id)` constraint (`internal/db/db.go:369-455`),
> unlike `role_assignments.vault_id`, which does have `ON DELETE CASCADE`
> (`internal/db/db.go:682`/`926`). The result: purge doesn't clean up a
> vault's children — it strands them, permanently soft-deleted, pointing at a
> `vault_id` that no longer resolves to anything, unreachable through any
> route and never swept by the soft-delete purge scheduler (which only
> purges individually-deleted *items*, not children orphaned by a vault
> purge). Soft-delete/recover is a real, reversible round-trip; purge is
> irreversible in a way that also fails to actually remove data — the
> opposite of what "purge" implies.

#### Prerequisites

- Server running against a scratch config/DB (see **§0 Environment Setup**
  above — don't point this at a shared dev database).
- `rocketvault` CLI built and on your `PATH` (`go build -o rocketvault .`
  from repo root, or substitute `go run main.go` for every `rocketvault ...`
  command below).
- `curl`, [`jq`](https://jqlang.org/), and `sqlite3` installed — this example
  leans on direct DB inspection (see gotcha 3 below for why: while a vault
  is soft-deleted, the API can't show you its own state).
- An admin user already created, with `ROCKETVAULT_TOTP_SECRET` exported in
  your shell (see **§2 Admin Bootstrap** above and §3.5's Prerequisites for
  the exact `export` one-liner — not repeated here).
- For Part 2: a second, non-admin `user`-role account (`bob` below) with its
  own password and TOTP secret already created — same setup as §3.5 step 7's
  negative-test user. Any plain user works; the point is that `bob` starts
  with no role grants anywhere.

#### The 4 gotchas this example is built to surface

All four were reproduced live against a scratch instance, not inferred from
reading the code alone — each has an exact command/output pair below.

1. **Purging a vault does not purge its children — they become permanently
   orphaned rows, not removed data.** `PurgeVault` calls `s.repo.Purge(ctx,
   v.ID)` and, if wired, `s.policies.DeleteByVault(ctx, v.ID)` — nothing
   else touches `secrets`/`keys`/`certificates`. Contrast with
   `DeleteVault`/`RecoverVault`, which both route through `CascadeRepository`
   to fan out to all three resource repositories. No cascade call exists in
   `PurgeVault` at all. Confirmed live: after soft-deleting then purging
   `cascade-vault`, the vault row is gone from `vaults`, but both secrets
   that lived in it are still sitting in `secrets`, still soft-deleted,
   `vault_id` still set to the now-nonexistent vault ID — unreachable via
   any HTTP or CLI route (vault-scoped routes 404 because the vault name no
   longer resolves; the flat `/secrets` routes only ever operate against the
   `default` vault, which doesn't match). This is a genuine gap, not a
   hypothetical — the same shape as the `Secrets` section's documented
   `purge_protection` gap.
2. **Vault recovery *does* auto-restore cascade-deleted children — but only
   the ones the vault's own delete touched, matched by exact timestamp, not
   children that were already deleted individually beforehand.** This
   resolves the checklist's "verify which behavior actually happens":
   recovery isn't a no-op for children. `RecoverVault`
   (`internal/services/vaults/vault_service.go:356-405`) reads the vault's
   `deleted_at` before clearing it, then calls
   `cascade.RecoverVaultContents(ctx, v.ID, deletedAt)`, which restores only
   rows matching `WHERE vault_id = ? AND deleted_at = ?`
   (`internal/repositories/secret_repository.go:561-571`) — that exact
   cascade timestamp, nothing else. A secret deleted on its own, earlier,
   carries its own different `deleted_at` and is excluded by that `WHERE`
   clause; it needs its own explicit restore call. Confirmed live below —
   after vault recovery, a secret that was active when the vault was deleted
   comes back automatically; a secret that was already soft-deleted before
   the vault was does not.
3. **While a vault is soft-deleted, every vault-scoped route 404s —
   including the deleted-items listing route for its own children.** There's
   a window, between `vaults delete` and `vaults recover`/`purge`, during
   which you cannot list, restore, or purge a soft-deleted vault's own
   soft-deleted children through any route — both the normal route and the
   `/deleted/...` route go through the same `VaultResolutionMiddleware`,
   which only resolves active vaults, so both fail with the identical `404
   vault not found`. This is why the walkthrough below reaches for `sqlite3`
   instead of the API to inspect state while the vault is deleted.
4. **The admin-bypass-vs-role-grant divergence on `vaults purge` is real,
   and it's narrower than "CLI and HTTP disagree" — they agree whenever a
   real role grant is doing the work, and diverge only for admin's bypass.**
   `CanPurgeVault` (`internal/services/authorization/vault_authz.go:41-53`)
   short-circuits `true` for `model.RoleAdmin` before checking any role
   assignment. The HTTP purge route (`api/vault.go:296-325`) has no
   handler-level authorization call at all — it relies entirely on
   `PolicyMiddleware`'s deny-by-default role-assignment check, which has no
   admin exception anywhere in its path. So: a non-admin holding only `Key
   Vault Purge Operator` gets identical behavior on both CLI and HTTP
   (Case A below — no divergence, the role grant does the work either way).
   A global admin with *no* role grant in the vault gets CLI success (the
   bypass) and HTTP `403` (no bypass) on the exact same scenario (Case B —
   the one place these two paths genuinely disagree).

#### Setup

```bash
BASE=http://localhost:8774/api/v1     # adjust host:port to your scratch config's server.listen_addr
TOTP_CODE=$(go run scripts/totp_generator.go -secret="$ROCKETVAULT_TOTP_SECRET" 2>&1 | grep -m1 -oP '(?<=--totp-code )\S+')
rocketvault users login --username admin --password admin123 --totp-code "$TOTP_CODE"

ADMIN_TOKEN=$(curl -s -X POST $BASE/users/login \
  -H "Content-Type: application/json" \
  -d "{\"username\":\"admin\",\"password\":\"admin123\",\"totp_code\":\"$TOTP_CODE\"}" \
  | jq -r .token)
```
The `login` call caches a session so the CLI commands below don't need
credential flags; `$ADMIN_TOKEN` is needed separately for the `curl` calls
and for the DB comparisons, since HTTP doesn't read the CLI's session cache.

---

#### Part 1 — Cascade delete, recover, and purge, traced through the database

**1. Create the vault and self-grant data-plane access.** Creating a vault is
a management operation admin bypasses; everything inside it (seeding the
secrets below) is not — see §3.5's gotcha 1 for the full explanation, not
repeated here:
```bash
rocketvault vaults create cascade-vault
rocketvault vault-access grant admin --role "Key Vault Administrator" --vault cascade-vault
```

**2. Seed two secrets with different delete histories.** `cascade-secret`
stays active; `pre-deleted-secret` gets soft-deleted individually, before the
vault itself is touched — this is what makes step 6 below meaningful:
```bash
curl -s -X POST $BASE/vaults/cascade-vault/secrets \
  -H "Authorization: Bearer $ADMIN_TOKEN" -H "Content-Type: application/json" \
  -d '{"name":"cascade-secret","value":"stays-active-until-vault-delete"}' | jq .
curl -s -X POST $BASE/vaults/cascade-vault/secrets \
  -H "Authorization: Bearer $ADMIN_TOKEN" -H "Content-Type: application/json" \
  -d '{"name":"pre-deleted-secret","value":"deleted-before-the-vault-is"}' | jq .
```
This example uses secrets only, since that's what was live-verified — but
`CascadeRepository` fans out identically to the key and certificate
repositories (source: gotcha 1's citation above), so the same mechanism
applies to keys and certs seeded the same way.

**3. Soft-delete `pre-deleted-secret` on its own**, capturing its ID from
step 2's response first:
```bash
curl -s -X DELETE $BASE/vaults/cascade-vault/secrets/<pre-deleted-secret-id> \
  -H "Authorization: Bearer $ADMIN_TOKEN"
```
Expect `204`. At this point `pre-deleted-secret` carries its own
`deleted_at`; `cascade-secret` is still active.

**4. Soft-delete the vault itself:**
```bash
rocketvault vaults delete cascade-vault
```

**5. Confirm gotcha 3 — the vault's own routes, including its deleted-items
bin, are now unreachable:**
```bash
curl -s -o /dev/null -w '%{http_code}\n' $BASE/vaults/cascade-vault/secrets \
  -H "Authorization: Bearer $ADMIN_TOKEN"
curl -s -o /dev/null -w '%{http_code}\n' $BASE/vaults/cascade-vault/deleted/secrets \
  -H "Authorization: Bearer $ADMIN_TOKEN"
```
Expect `404` on both, same body on each:
```
404   {"error":"vault not found"}
```
This is why the next check goes straight to the database instead of the API.

**6. Inspect the cascade with `sqlite3` (gotcha 2, first half) — confirm
`cascade-secret` got a fresh, cascade-stamped `deleted_at`, while
`pre-deleted-secret` kept the earlier timestamp from step 3:**
```bash
sqlite3 -header -column /tmp/rv-test.db \
  "SELECT name, deleted_at FROM secrets WHERE vault_id='<cascade-vault-id>';"
```
Expect:
```
name                deleted_at
------------------  -----------------------------------
cascade-secret      2026-08-18 09:56:00.263802997+05:30   <- stamped by the cascade
pre-deleted-secret  2026-08-18 09:55:49.446576507+05:30   <- its own earlier timestamp, untouched
```

**7. Recover the vault:**
```bash
rocketvault vaults recover cascade-vault
```

**8. Re-run the same query (gotcha 2, second half) — `cascade-secret` comes
back automatically; `pre-deleted-secret` does not:**
```bash
sqlite3 -header -column /tmp/rv-test.db \
  "SELECT name, deleted_at FROM secrets WHERE vault_id='<cascade-vault-id>';"
```
Expect:
```
name                deleted_at
------------------  -----------------------------------
cascade-secret                                            <- restored (NULL)
pre-deleted-secret  2026-08-18 09:55:49.446576507+05:30   <- still deleted
```
`pre-deleted-secret` still needs its own explicit restore
(`POST /vaults/cascade-vault/secrets/<id>/restore` or equivalent) — it does
not come back with the vault, because it never carried the vault's cascade
timestamp in the first place.

**9. Soft-delete the vault again, then purge it (gotcha 1):**
```bash
rocketvault vaults delete cascade-vault
rocketvault vaults purge cascade-vault
```
Expect: `Vault "cascade-vault" purged successfully`.

**10. Confirm the vault row is gone, but both secret rows survive,
orphaned:**
```bash
sqlite3 -header -column /tmp/rv-test.db \
  "SELECT id, name FROM vaults WHERE name='cascade-vault';"
sqlite3 -header -column /tmp/rv-test.db \
  "SELECT name, vault_id, deleted_at FROM secrets WHERE vault_id='<cascade-vault-id>';"
```
Expect the first query to return no rows, and the second to still return
both secrets, unmodified, still soft-deleted, `vault_id` pointing at a vault
that no longer exists:
```
name                vault_id                              deleted_at
------------------  ------------------------------------  -----------------------------------
cascade-secret      887aba07-1ea4-4036-9da4-486f2fb956bd  2026-08-18 09:56:44.561090683+05:30
pre-deleted-secret  887aba07-1ea4-4036-9da4-486f2fb956bd  2026-08-18 09:55:49.446576507+05:30
```
Neither row is reachable through any route from here on, and nothing will
ever clean them up automatically.

---

#### Part 2 — The admin-bypass-vs-HTTP purge divergence, confirmed both ways

This needs a second principal (a non-admin) and a separate admin scenario,
so it's split from Part 1's narrative rather than folded into it. Four more
vaults, purged in pairs, isolate the two cases cleanly.

**11. Case A — a non-admin with an explicit role grant: CLI and HTTP agree,
no divergence.** Create two vaults, soft-delete both as admin (bob has no
`vaults:manage` to delete them himself), grant bob `Key Vault Purge
Operator` in both, nothing else:
```bash
rocketvault vaults create test-vault-2
rocketvault vaults create test-vault-3
rocketvault vaults delete test-vault-2
rocketvault vaults delete test-vault-3
rocketvault vault-access grant bob --role "Key Vault Purge Operator" --vault test-vault-2
rocketvault vault-access grant bob --role "Key Vault Purge Operator" --vault test-vault-3
```
Purge `test-vault-2` as bob via the CLI:
```bash
rocketvault vaults purge test-vault-2 \
  --username bob --password 'BobPass123!' --totp-code <bobs-code>
```
Expect: `Vault "test-vault-2" purged successfully`.

Purge `test-vault-3` as bob over HTTP:
```bash
BOB_TOKEN=$(curl -s -X POST $BASE/users/login \
  -H "Content-Type: application/json" \
  -d '{"username":"bob","password":"BobPass123!","totp_code":"<bobs-code>"}' \
  | jq -r .token)
curl -s -o /dev/null -w '%{http_code}\n' -X DELETE \
  $BASE/vaults/test-vault-3/purge -H "Authorization: Bearer $BOB_TOKEN"
```
Expect `204`. Both succeed identically — the explicit role grant is doing
the work in both cases, so there's nothing for admin's bypass to add or
withhold.

**12. Case B — a global admin with *no* role grant in the vault: CLI
succeeds via the bypass, HTTP returns 403. This is the genuine divergence.**
Create two more vaults, soft-delete both, and grant admin nothing in either:
```bash
rocketvault vaults create test-vault-4
rocketvault vaults create test-vault-5
rocketvault vaults delete test-vault-4
rocketvault vaults delete test-vault-5
```
Purge `test-vault-4` as admin via the CLI:
```bash
rocketvault vaults purge test-vault-4 --username admin --password admin123 --totp-code "$TOTP_CODE"
```
Expect: `Vault "test-vault-4" purged successfully` — `requireCanPurgeVault`
(`cmd/vaults/authz.go:83-98`) calls `CanPurgeVault`, which short-circuits
for `model.RoleAdmin` with no role-assignment lookup at all.

Purge `test-vault-5` as admin over HTTP, same setup:
```bash
curl -s -o /dev/null -w '%{http_code}\n' -X DELETE \
  $BASE/vaults/test-vault-5/purge -H "Authorization: Bearer $ADMIN_TOKEN"
```
Expect `403`:
```
403   Forbidden: no role assignment grants this operation in this vault
```
Identical vault, identical principal, identical missing role grant — the CLI
succeeded purely because `CanPurgeVault`'s admin short-circuit never asks
the HTTP path's question at all.

#### Cleanup

```bash
# cascade-vault, test-vault-2, and test-vault-4 are already purged by the
# walkthrough above (test-vault-3 and test-vault-5 too, via HTTP). Nothing
# left to soft-delete/recover/purge from this example.
rocketvault users logout
```

---

#### Self-service vault provisioning (bounded creation right)

Landed 2026-09-04. A provisioning grant lets a non-admin principal create
vaults up to a quota, becoming full manager (vault-scoped `vaults:manage`
plus `Key Vault Administrator`) of what it creates and nothing else — the
safe alternative to a global `vaults:manage` access policy, which today also
confers management of every existing vault and role-assignment management
everywhere (release 2, not yet shipped, narrows that). Design:
`docs/superpowers/specs/2026-09-03-self-service-vault-provisioning-design.md`.

- [ ] As admin: `rocketvault vault-provisioning grant <principal> --quota 2`
      → grant issued. Re-run with `--quota 5` → quota changes, `list` still
      shows exactly one grant for that principal (`principal_id` is UNIQUE).
- [ ] `--quota 0` and `--quota -1` → both refused. A zero-quota grant and no
      grant at all are the same permission.
- [ ] Issue a grant to an OAuth2 **service account** by UUID (§3.5) → works.
      A service account is not a `users` row, so a username-only path would
      fail here; this is the MSP automation's actual identity.
- [ ] As the grantee (not an admin): create a vault → succeeds, and
      `rocketvault vaults list` now shows it. Before this feature the grantee
      got 403 on both.
- [ ] Create up to the quota, then one more → the last is refused with a
      quota error naming the count and the limit (`vault provisioning quota
      exceeded: N of N used`).
- [ ] Soft-delete one of the grantee's vaults, then create again → **still
      refused**. A soft-deleted vault holds its name and is recoverable, so it
      keeps its quota slot. **As admin**, purge it (`rocketvault vaults purge`
      or `DELETE .../purge`), then create again as the grantee → now
      succeeds. The grantee cannot purge its own vault to free the slot: the
      creator's automatic `Key Vault Administrator` role assignment does not
      include `ActionVaultPurge` (only `Key Vault Purge Operator` does, or
      the global admin role), so this step genuinely requires an admin, or a
      separate `Key Vault Purge Operator` grant in that vault.
- [ ] Grantee tries `--purge-protection` on create → refused. Allowing it
      would let the grantee pin a quota slot permanently, since `PurgeVault`
      refuses a protected vault.
- [ ] Grantee has full rights over its own vault (read/write secrets, manage
      role assignments) but **403 on a vault it did not create** — check both
      CLI and HTTP. CLI secret writes blocked per `docs/known-bugs.md` § B57.
- [ ] Grantee tries to raise its own quota via
      `PUT /api/v1/vault-provisioning-grants/{own_id}` → `403`. This tier is
      admin-only and deliberately non-delegable — there is no access-policy
      or role-assignment path at all, unlike `vaults`/`vault-access`.
- [ ] Revoke the grant (`rocketvault vault-provisioning revoke <principal>`)
      → grantee can no longer create, but **keeps** its existing vaults and
      its rights over them. Revocation is not a cascade.
- [ ] Purge a provisioned vault (as admin), then check the DB: no orphan row
      remains in `role_assignments` for it (the FK cascade is inert on
      SQLite — `roleAssignmentRepository.DeleteByVault` is what actually
      cleans it up).
- [ ] Start the server against a DB where some principal holds a global
      `vaults:manage` policy → a warn line names that principal at startup
      (`warnGlobalVaultManageGrants`, `internal/db/db.go`).

### Worked example: self-service provisioning, quotas, and what a soft-delete costs you

> **Concept: a provisioning grant is a bounded right; a global `vaults:manage`
> access policy is not.** `VaultProvisioningGrant`'s own doc comment frames it
> as the delegated alternative to a global grant, "which additionally confers
> authority over every vault that already exists"
> (`model/vault_provisioning_grant.go:16-18`) — and that isn't loose framing:
> a global (`vault_id: null`) access policy "always appl[ies]" to every vault
> (`internal/services/authorization/access_policy_service.go:26-31`), while a
> grant's `Quota` bounds only vaults *this principal* creates from here on
> (`model/vault_provisioning_grant.go:23-32`). `createVault`'s authorization
> is a genuine three-way decision, not two names for the same check — admin,
> a global `vaults:manage` allow, or a provisioning grant each satisfy it, but
> only the grant path is quota-bounded (`api/vault.go:63-84`). Creation makes
> that bound real: the creator walks away with vault-scoped `vaults:manage`
> and `Key Vault Administrator`, both scoped to the one vault just created and
> nothing else (`internal/services/vaults/vault_service.go:405-436`) — full
> manager of what it made, a stranger everywhere else. And the two operations
> that make the grant visible are deliberately asymmetric: **quota** is
> enforced by counting rows this principal created
> (`internal/services/vaults/vault_service.go:395`), but **listing** is
> answered by walking the access-policy grants a principal actually holds
> (`internal/services/vaults/vault_service.go:509-538`) — two different
> queries over two different tables, not one list filtered two ways.

All output below was captured live on 2026-09-04 against the scratch instance
from Prerequisites, not inferred from the code.

#### Prerequisites

- Scratch config/DB and a running server (**§0 Environment Setup**), not a
  shared dev database. This example was captured against a dedicated
  instance rather than reusing `default`'s port: config `/tmp/rv-prov/rv.yaml`
  (copied from `.rocketvault.yaml.example`, with `master_key`,
  `bootstrap_token` regenerated via `openssl rand -base64 32`,
  `server.listen_addr` changed to `:18774`, and `database.connection`
  pointed at `/tmp/rv-prov/rv.db`); `hsm.enabled` and `oidc.enabled` were
  already `false` in the template, so no edit was needed there. `$BASE` =
  `http://localhost:18774/api/v1`.
- `rocketvault` CLI built from repo root: `go build -o /tmp/rv-prov/rocketvault .`
  — substitute `go run main.go` for every `rocketvault ...` command below if
  you'd rather not build a scratch binary.
- The server must be started **from the repo root**. Starting it from
  anywhere else still boots and still serves traffic, but logs `level=error
  msg="Unable to initialize the localization."` at startup (i18n assets
  resolve relative to cwd) — confirmed live by starting a second instance
  from `/tmp` against the same config; it also hit the unrelated but easy
  to conflate `listen tcp :18774: bind: address already in use` from the
  already-running instance on the same port, and shut itself down. Neither
  failure corrupted the first instance, which kept serving throughout.
- An admin user, bootstrapped **with an isolated `$HOME`**:
  ```bash
  export HOME=/tmp/rv-prov/home   # in a script/subshell, not the caller's real $HOME
  rocketvault --config /tmp/rv-prov/rv.yaml users admin \
    --admin-username=admin --admin-password=<password> \
    --bootstrap-token="$(grep '^bootstrap_token:' /tmp/rv-prov/rv.yaml | cut -d'"' -f2)"
  ```
  Confirmed live: **without** the `$HOME` override, the same command against
  this machine's real developer environment refused immediately, before
  touching the scratch DB at all:
  ```
  Error: remote mode (--server/ROCKETVAULT_ADDR/context "https://numericlabs.lxd") is not yet supported for "rocketvault users admin"; unset it to run against the local instance
  ```
  The CLI resolved `~/.rocketvault/contexts.json`'s saved remote context and
  refused rather than silently doing something unintended — this is the
  guard working as designed, not a bug, but it costs a genuinely confusing
  first error if you don't know to look for it. Every CLI command in this
  example needs the same isolated-`$HOME` treatment, not just bootstrap.
- The admin's TOTP secret, captured from the bootstrap command's one-time
  output, and a way to mint a fresh 30-second code from it
  (`go run scripts/totp_generator.go -secret=<secret>`, run from repo root)
  — `$TOKEN` below is `POST $BASE/users/login`'s `token` field using that
  code.
- A non-admin, no-role-anywhere principal to act as the grantee, created as
  admin:
  ```bash
  rocketvault users create --new-username msp-bot --new-password <password> --new-role user
  ```
  This principal starts with zero role grants in any vault — the example
  below is what a provisioning grant adds on top of that baseline, not on
  top of some other pre-existing access.
- An OAuth2 service account (**§3.5**), created as admin, to prove the
  grant path also accepts a non-`users` principal:
  ```bash
  curl -s -X POST $BASE/service-accounts -H "Authorization: Bearer $TOKEN" \
    -H 'Content-Type: application/json' \
    -d '{"name":"msp-provisioning-sa","description":"..."}'
  ```
  Save the response's `id` (a UUID) — that is the principal argument
  `vault-provisioning grant` needs for a service account, per
  `resolvePrincipal` (`cmd/vault-provisioning/grant.go`): a raw UUID is
  tried first and takes precedence over a username lookup, which is the
  only reason a service account (an `oauth2_clients` row, not a `users`
  row, with no username to look up) can be granted a provisioning right at
  all. The response's `name` field is a display label only, useless for
  this purpose — passing it where the grant command expects a UUID fails
  the same way the webhook example's §3.5 sibling gotcha describes for
  `vault-access grant`.

#### Walkthrough

CLI commands below run with the isolated `$HOME` from Prerequisites already
exported in the shell. Every `rocketvault` invocation also emits structured
JSON logs on stderr/stdout via logrus — trimmed throughout below for
readability; only the command's own printed result is shown.

**1. Confirm the pre-feature failure mode: `msp-bot` cannot create a vault
without a grant.**

```bash
BOT_TOKEN=$(curl -s -X POST $BASE/users/login -H "Content-Type: application/json" \
  -d '{"username":"msp-bot","password":"<password>","totp_code":"<code>"}' \
  | python3 -c "import json,sys; print(json.load(sys.stdin)['token'])")
curl -s -X POST $BASE/vaults -H "Authorization: Bearer $BOT_TOKEN" \
  -H 'Content-Type: application/json' -d '{"name":"acme-prod"}'
```
```json
{"detailed_error":"","id":"Insufficient permissions: admin, vaults/manage, or a vault provisioning grant required","message":"Insufficient permissions: admin, vaults/manage, or a vault provisioning grant required","request_id":"req-fbf7f85a","status_code":403}
```
`403`. `msp-bot` holds no role anywhere and no provisioning grant, so
`createVault`'s three-way decision (`api/vault.go:63-84`) finds nothing to
allow — this is the baseline the rest of this example changes.

**2. Issue the grant via the CLI, then re-issue it over HTTP for the same
principal.**

```bash
rocketvault --config /tmp/rv-prov/rv.yaml vault-provisioning grant msp-bot --quota 2
```
```
Provisioning grant issued: principal=a10eee1d-f25f-432c-9b20-bd9abf416e5a quota=2
```
The CLI's own output above already names msp-bot's user ID as `principal=`
— assign it from there rather than looking it up separately:
```bash
BOT_ID=a10eee1d-f25f-432c-9b20-bd9abf416e5a   # from "principal=" above
```
Then, with `$TOKEN` the admin JWT from Prerequisites and `$BOT_ID` now set:
```bash
curl -s -o /dev/null -w '%{http_code}\n' -X PUT $BASE/vault-provisioning-grants/$BOT_ID \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' -d '{"quota":2}'
```
```
200
```
This is a **re-quota**, not a first issue: the CLI call above already
created the row, and `principal_id` is UNIQUE
(`upsertVaultProvisioningGrant`, `api/vault_provisioning_grants.go:67-126`),
so the handler's pre-read finds an existing grant and returns `200` rather
than `201`. Run in this order — CLI first, HTTP second, same principal —
only `200` is observable over HTTP at all; step 3 below is where a genuine
`201` actually shows up.

**3. Issue a grant to the service account, by UUID — this is where the `201`
shows up.**

A service account has no username, so this is the one grant a username-only
path could never express:
```bash
curl -s -X PUT $BASE/vault-provisioning-grants/$SA_ID \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' -d '{"quota":20}'
```
```json
{"id":"590a6c82-df46-4610-9993-04dc3a353faf","principal_id":"04dc5b4e-df77-414b-aac6-bcbc39e482f1","quota":20,"created_at":"2026-09-04T12:56:55.760307381Z","created_by":"5c481eeb-19f4-49c4-a00d-157fff8f565c"}
```
`201` — `$SA_ID` had no prior grant, so this is the genuine first issue the
brief predicted for a bare PUT. The CLI accepts the same UUID directly,
ahead of any username lookup (`resolvePrincipal`,
`cmd/vault-provisioning/grant.go:23-35`):
```bash
rocketvault --config /tmp/rv-prov/rv.yaml vault-provisioning grant $SA_ID --quota 20
```
```
Provisioning grant issued: principal=04dc5b4e-df77-414b-aac6-bcbc39e482f1 quota=20
```
A re-quota this time (same 20) — the CLI has no HTTP status to show, but
`principal_id` being UNIQUE means the row is unchanged either way.

**4. Create, as `msp-bot` — then prove the grant is real, inside `acme-prod`
only.**

```bash
rocketvault --config /tmp/rv-prov/rv.yaml vaults create acme-prod   # as msp-bot, cached session
```
```
Vault created under provisioning grant: acme-prod
ID                                    Name       Enabled  PurgeProtection  RetentionDays  Created
------------------------------------  ---------  -------  ---------------  -------------  -------------------------
056c2416-16bc-49cd-8559-e4822a68f375  acme-prod  true     false            90             2026-09-04T18:27:24+05:30
```
Writing a secret **over the CLI** fails, for a reason this plan did not
predict:
```bash
rocketvault --config /tmp/rv-prov/rv.yaml secrets create example-secret hello-acme --vault acme-prod
```
```
Error: forbidden: requires admin or secrets_manager role
```
This is a genuine divergence, recorded as found rather than reconciled.
`cmd/secrets/create.go:95-97` gates on the caller's **global account role**
(`admin` or `secrets_manager`) before it ever reaches the vault-scoped
`RequireDataAction` check (`cmd/secrets/create.go:105`) that would honor
`msp-bot`'s brand-new `Key Vault Administrator` role assignment in
`acme-prod`. `msp-bot`'s global account role is plain `user`, so it never
gets that far — the provisioning grant conferred a real, vault-scoped `Key
Vault Administrator`, but this particular CLI command carries its own,
older, global-role gate in front of it that the grant does nothing to
satisfy. `secrets get` (`cmd/secrets/get.go:53-56`) and the HTTP write path
(`api/secrets.go`'s `createSecret`) carry no such gate — confirmed by
writing the same secret over HTTP instead:
```bash
curl -s -X POST $BASE/vaults/acme-prod/secrets -H "Authorization: Bearer $BOT_TOKEN" \
  -H 'Content-Type: application/json' -d '{"name":"example-secret","value":"hello-acme"}'
```
```json
{"id":"d590bb30-8507-4953-9b8e-697345fd7b1a","name":"example-secret","version":1,"created_at":"2026-09-04T18:28:32+05:30","enabled":true}
```
`201`. Reading it back over the CLI now works, since `secrets get` has no
global-role gate:
```bash
rocketvault --config /tmp/rv-prov/rv.yaml secrets get d590bb30-8507-4953-9b8e-697345fd7b1a --vault acme-prod
```
```
ID                                    Name            Value       Version  Enabled  ContentType  Tags  Expires  NotBefore  Created
------------------------------------  --------------  ----------  -------  -------  -----------  ----  -------  ---------  -------------------------
d590bb30-8507-4953-9b8e-697345fd7b1a  example-secret  hello-acme  1        true                                            2026-09-04T18:28:32+05:30
```
And the role assignment the create wrote:
```bash
rocketvault --config /tmp/rv-prov/rv.yaml vault-access list --vault acme-prod
```
```
ASSIGNMENT-ID                          ROLE                     PRINCIPAL-ID
83fc20ac-7172-4ae1-8c95-61573ae0da21   Key Vault Administrator  a10eee1d-f25f-432c-9b20-bd9abf416e5a
```
Exactly one row, msp-bot's own principal ID — the automatic grant written by
`CreateVaultProvisioned` (`internal/services/vaults/vault_service.go:429-436`),
and nothing else in this vault.

**5. `rocketvault vaults list` as `msp-bot` — the step that would have failed
before plan 05.**

```bash
rocketvault --config /tmp/rv-prov/rv.yaml vaults list
```
```
ID                                    Name       Enabled  RetentionDays  Created
------------------------------------  ---------  -------  -------------  -------------------------
056c2416-16bc-49cd-8559-e4822a68f375  acme-prod  true     90             2026-09-04T18:27:24+05:30
```
Only `acme-prod` — `default` does not appear. `ListVaultsScoped`
(`internal/services/vaults/vault_service.go:509-538`) filters to vaults
where the caller holds a `vaults:manage` access policy, and msp-bot's only
such policy is the vault-scoped one `acme-prod`'s creation wrote for it
(step 4's `vault-access list` output above shows the role-assignment half of
that same grant, not this access policy directly — see the Concept note
above). Before this feature, `msp-bot` held no policy anywhere and would
have seen an empty list or a `403`, never `default`.

**6. Exhaust the quota — msp-bot's grant was issued at quota 2, and step 4
already spent one slot on `acme-prod`.**

Spend the second slot:

```bash
rocketvault --config /tmp/rv-prov/rv.yaml vaults create acme-staging
```
```
ID                                    Name          Enabled  PurgeProtection  RetentionDays  Created
------------------------------------  ------------  -------  ---------------  -------------  -------------------------
1b6487d6-5384-4d2f-946b-87a1cd17a3f0  acme-staging  true     false            90             2026-09-04T18:37:34+05:30
```
Now at 2 of 2. A third create is refused, and the message names both the
count and the limit, exactly as predicted:

```bash
rocketvault --config /tmp/rv-prov/rv.yaml vaults create acme-third
```
```
Error: failed to create vault: vault provisioning quota exceeded: 2 of 2 used -- delete or purge an existing vault, or ask an administrator to raise your provisioning quota
```
Exit code `1`. The identical refusal over HTTP is worded differently — a
divergence this plan did not predict:

```bash
curl -s -X POST $BASE/vaults -H "Authorization: Bearer $BOT_TOKEN" \
  -H 'Content-Type: application/json' -d '{"name":"acme-third-http"}'
```
```json
{"detailed_error":"","id":"Insufficient permissions: vault provisioning quota exceeded: 2 of 2 used","message":"Insufficient permissions: vault provisioning quota exceeded: 2 of 2 used","request_id":"req-4bf30dcc","status_code":403}
```
`403`. Same underlying error (`ErrVaultQuotaExceeded`,
`internal/services/vaults/vault_service.go:342,399-400`) reaches both surfaces,
but only the CLI appends the "delete or purge... or ask an administrator"
remediation — that text is `cmd/vaults/create.go:84`'s own `%w`-wrapping,
added on top of `err.Error()`. The HTTP handler
(`api/vault.go:104`, `c.SetPermissionError(err.Error())`) passes the bare
`err.Error()` straight through `SetPermissionError`, which itself prepends
a fixed `"Insufficient permissions: "` prefix (`api/context.go:100-102`) —
so the HTTP caller sees the count and the limit, but not the CLI's
human-facing hint about what to do next.

**7. Soft-delete `acme-staging` — the slot is *not* released.**

```bash
curl -s -o /dev/null -w '%{http_code}\n' -X DELETE $BASE/vaults/acme-staging \
  -H "Authorization: Bearer $BOT_TOKEN"
```
```
204
```
Retry the create — still refused, byte-identical message to step 6:

```bash
rocketvault --config /tmp/rv-prov/rv.yaml vaults create acme-third
```
```
Error: failed to create vault: vault provisioning quota exceeded: 2 of 2 used -- delete or purge an existing vault, or ask an administrator to raise your provisioning quota
```
The database confirms why: the row is still there, merely flagged deleted.
`CountByCreatedBy` (`internal/services/vaults/vault_service.go:397`) counts
every row this principal created regardless of `deleted_at` — a soft-delete
changes nothing it looks at.

```bash
sqlite3 /tmp/rv-prov/rv.db \
  "SELECT name, deleted_at IS NOT NULL AS soft_deleted FROM vaults WHERE created_by='$BOT_ID';"
```
```
acme-prod|0
acme-staging|1
```

**8. Purge frees the slot — but the grantee cannot do it itself. This is
the counter-intuitive half of this whole example.**

`msp-bot`'s automatic grant from creating `acme-staging` is `Key Vault
Administrator`, scoped to that one vault (step 4). That role's data-action
bundle does not include `ActionVaultPurge` — the *only* built-in role that
carries it is `Key Vault Purge Operator`
(`model/azure_roles.go:201-203`):
```go
RoleKeyVaultPurgeOperator: {
    ActionVaultPurge,
},
```
Confirmed live — `msp-bot` attempts the purge on the vault it created and
soft-deleted itself, and is refused:

```bash
rocketvault --config /tmp/rv-prov/rv.yaml vaults purge acme-staging
```
```
Error: permission denied: admin or Key Vault Purge Operator required for vault "acme-staging"
```
Exit code `1`. This is `requireCanPurgeVault`
(`cmd/vaults/authz.go:124-134`) calling `CanPurgeVault`
(`internal/services/authorization/vault_authz.go:41-53`), which
short-circuits only for the global `admin` account role, then falls back to
a real `HasDataAction(ActionVaultPurge)` lookup that `msp-bot`'s `Key Vault
Administrator` assignment does not satisfy. Being the vault's creator and
sole manager is not enough — purge is carved out on purpose, and nothing
about the provisioning grant hands it over.

Only an admin (via the account-role bypass) or an explicit `Key Vault Purge
Operator` grant in that vault can free the slot. Log in as admin and purge:

```bash
rocketvault --config /tmp/rv-prov/rv.yaml users login --username admin --password <admin-password> --totp-code <admin-code>
rocketvault --config /tmp/rv-prov/rv.yaml vaults purge acme-staging
```
```
Vault "acme-staging" purged successfully
```
Switch the cached session back to `msp-bot` and retry the create that has
failed twice already — it now succeeds:

```bash
rocketvault --config /tmp/rv-prov/rv.yaml users login --username msp-bot --password <msp-bot-password> --totp-code <msp-bot-code>
rocketvault --config /tmp/rv-prov/rv.yaml vaults create acme-third
```
```
ID                                    Name        Enabled  PurgeProtection  RetentionDays  Created
------------------------------------  ----------  -------  ---------------  -------------  -------------------------
2d1fff01-a352-48de-8c1d-942a8911101a  acme-third  true     false            90             2026-09-04T18:39:12+05:30
```
Only a purge frees a slot — not a delete, not time, not the creator asking
nicely. And the purge cleaned up after itself correctly: `acme-staging`'s
role assignment is gone, not orphaned.

```bash
sqlite3 /tmp/rv-prov/rv.db \
  "SELECT COUNT(*) FROM role_assignments WHERE vault_id NOT IN (SELECT id FROM vaults);"
```
```
0
```
This check is load-bearing, not decoration: SQLite's FK cascade is inert
here, so `roleAssignmentRepository.DeleteByVault` is the only thing that
cleans up a purged vault's role assignments, and nothing in the automated
test suite would catch a regression in it. `0` confirms it is still doing
its job.

**9. Confirm `purge_protection` is refused for a quota-bounded caller — and
why that restriction has to exist for step 8 to have worked at all.**

```bash
rocketvault --config /tmp/rv-prov/rv.yaml vaults create acme-pp-test --purge-protection
```
```
Error: failed to create vault: purge protection may only be set by an administrator -- only an administrator can set --purge-protection
```
`CreateVaultProvisioned` refuses this before ever reaching the database
(`internal/services/vaults/vault_service.go:361-364`), returning
`ErrPurgeProtectionNotPermitted`
(`internal/services/vaults/vault_service.go:344-348`) whenever the caller is
quota-bounded and asked for `purge_protection: true`. The doc comment on
that error spells out exactly why, and step 8 above is a live demonstration
of the failure mode it prevents: "Allowing it would let a grantee protect a
vault, soft-delete it, and hold the quota slot forever, since PurgeVault
refuses a protected vault and the purge scheduler honours the same flag." A
grantee that could set purge protection on its own vault could turn step
8's temporary, admin-recoverable stuck slot into a permanent one — the
purge that freed `acme-staging`'s slot would itself have been refused.

#### The 5 gotchas this example surfaces

1. **A provisioning-grant creator cannot write secrets into the vault it
   just created — over the CLI, though the identical write succeeds over
   HTTP.** `cmd/secrets/create.go:95-97` gates on the caller's global
   account role (`admin` or `secrets_manager`) *before* it reaches the
   vault-scoped `RequireDataAction` check at `cmd/secrets/create.go:105`
   that would honor the creator's brand-new, vault-scoped `Key Vault
   Administrator` assignment. `msp-bot`'s global role is plain `user`, so it
   never gets that far. `secrets get` and the HTTP write path
   (`api/secrets.go`) carry no such gate — see walkthrough step 4 above for
   the live confirmation (CLI refused with `forbidden: requires admin or
   secrets_manager role`, HTTP succeeded with `201`).
2. **Quota counts every vault this principal ever created, soft-deleted or
   not — only a purge releases a slot.** `CountByCreatedBy`
   (`internal/services/vaults/vault_service.go:397`) has no `deleted_at`
   filter, so a soft-delete is invisible to it. Confirmed live in steps 6-7:
   the same `2 of 2 used` refusal, byte-identical, both before and after
   soft-deleting `acme-staging`.
3. **A grantee sitting at quota cannot free a slot by itself.** Vault
   creation only ever grants the creator `Key Vault Administrator`
   (`internal/services/vaults/vault_service.go:405-436`), and that role's
   data-action bundle does not include `ActionVaultPurge` — the only
   built-in role that carries it is `Key Vault Purge Operator`
   (`model/azure_roles.go:201-203`). Confirmed live in step 8: `msp-bot`
   purging the vault it created and soft-deleted itself was refused with
   `permission denied: admin or Key Vault Purge Operator required`. A
   grantee genuinely stuck at quota has exactly two ways out, neither of
   which it can trigger itself: wait for the background retention scheduler
   to auto-purge the soft-deleted vault once its retention window elapses
   (`internal/services/softdelete/purge_scheduler.go:16-22,99-105`), or ask
   an administrator to purge it now (or grant `Key Vault Purge Operator` in
   that vault). This is the counter-intuitive half of the whole feature —
   deleting a vault feels like it should give the slot back, and it
   deliberately does not.
4. **`purge_protection` is refused for a quota-bounded caller, and that
   restriction is what keeps gotcha #3's stuck slot temporary instead of
   permanent.** `ErrPurgeProtectionNotPermitted`
   (`internal/services/vaults/vault_service.go:344-348`) is returned before
   the vault is even inserted
   (`internal/services/vaults/vault_service.go:361-364`) whenever the caller
   is quota-bounded. Its own doc comment says why: with purge protection
   allowed, the exact sequence step 8 just walked through — soft-delete,
   then purge to reclaim the slot — would itself fail, and the slot would
   be pinned forever. Confirmed live in step 9.
5. **The CLI and HTTP quota-exceeded refusals share the same underlying
   error but not the same wording.** Both report the count and the limit
   (`2 of 2 used`), but only the CLI appends a "delete or purge... or ask an
   administrator" remediation hint
   (`cmd/vaults/create.go:84`) — the HTTP handler passes the bare
   `err.Error()` through `SetPermissionError`
   (`api/vault.go:104`, `api/context.go:100-102`), which prepends only a
   fixed `"Insufficient permissions: "` prefix. Don't parse either message
   expecting it to match the other verbatim.

#### Teardown

This scratch instance is shared with a follow-on worked example (self-service
provisioning boundaries) and is **left running** at the end of this example —
do not stop it or delete its data as part of this walkthrough. For a reader
running this example in true isolation and finished with it for good:

```bash
pkill -f "rocketvault --config /tmp/rv-prov/rv.yaml"
rm -rf /tmp/rv-prov
```
`acme-staging` is already purged (step 8); `acme-prod` and `acme-third`
remain, owned by `msp-bot`, at quota (2 of 2 used) — that state is
intentional, not leftover mess, since the next worked example needs a
principal already sitting at its limit.

This example showed what the grant *lets* `msp-bot` do. The next one, "Worked
example: what a provisioning grantee cannot do" below, picks up this same
instance and shows where that grant stops.

### Worked example: what a provisioning grantee cannot do

> **Continues from the example above.** That one showed what a provisioning
> grant lets a principal do; this one shows where it stops. Read both —
> neither is the whole story alone.

> **Concept: the grant is bounded on three independent axes, enforced in three
> different places.** **Scope** — a grantee's authority never reaches a vault
> it did not create, checked by `CanManageVault`
> (`internal/services/authorization/vault_authz.go`) for vault-management
> operations and by `HasDataAction`
> (`internal/services/authorization/role_assignment_service.go`) for
> data-plane operations. **Count** — a grantee cannot create past its quota,
> checked inside `CreateVaultProvisioned`'s own transaction
> (`internal/services/vaults/vault_service.go`). **Authority** — a grantee
> cannot amend its own grant, checked by `requireGrantAdmin`
> (`cmd/vault-provisioning/authz.go`), which per this repo's CLAUDE.md "CLI
> Authorization" section has no access-policy or role-assignment path at all
> — it is admin-only and deliberately non-delegable, because a principal able
> to amend its own grant could raise its own quota, and the bound the grant
> exists to impose would be decorative. A reader who understands only "there's
> a quota" will not know to test the other two — this example tests all
> three, plus what survives when the grant itself is taken away.

All output below was captured live on 2026-09-04 against the same scratch
instance as the example above (`/tmp/rv-prov/rv.yaml`, port `18774`), reusing
its already-bootstrapped `admin` and `msp-bot` principals and cached CLI
sessions — not inferred from the code, and not a fresh instance.

#### Walkthrough

**1. Cross-vault denial: `msp-bot` against `default`, a vault it did not
create.** Four HTTP attempts, then the same four probes over the CLI. The
CLI's cross-vault read probe deliberately uses `secrets list` (a read), not
one of the five `secrets` write commands — those carry an unrelated legacy
global-role gate (`docs/known-bugs.md` § B57) that refuses `msp-bot` for a
reason having nothing to do with the vault boundary being tested here; using
one would have made the refusal ambiguous. `1d` and `1d-cli`, a grantee
attempting to grant *itself* a role in a vault it does not own, is the single
most important attempt in this whole example.

```bash
curl -s -X GET $BASE/vaults/default/secrets -H "Authorization: Bearer $BOT_TOKEN"
```
```
Forbidden: no role assignment grants this operation in this vault
```
`[403]`

```bash
curl -s -X PATCH $BASE/vaults/default -H "Authorization: Bearer $BOT_TOKEN" \
  -H 'Content-Type: application/json' -d '{"enabled":false}'
```
```json
{"detailed_error":"","id":"Insufficient permissions: admin or vaults/manage required","message":"Insufficient permissions: admin or vaults/manage required","request_id":"req-e684a213","status_code":403}
```

```bash
curl -s -X DELETE $BASE/vaults/default -H "Authorization: Bearer $BOT_TOKEN"
```
```json
{"detailed_error":"","id":"Insufficient permissions: admin or vaults/manage required","message":"Insufficient permissions: admin or vaults/manage required","request_id":"req-ffc876ff","status_code":403}
```

```bash
curl -s -X POST $BASE/vaults/default/role-assignments -H "Authorization: Bearer $BOT_TOKEN" \
  -H 'Content-Type: application/json' -d '{"principal_id":"'$BOT_ID'","role":"Key Vault Administrator"}'
```
```json
{"detailed_error":"","id":"Insufficient permissions: admin, vaults/manage, or Key Vault Data Access Administrator required","message":"Insufficient permissions: admin, vaults/manage, or Key Vault Data Access Administrator required","request_id":"req-e8707f30","status_code":403}
```
All four `[403]`. Now the same four, over the CLI, as `msp-bot` (cached
session):

```bash
rocketvault --config /tmp/rv-prov/rv.yaml secrets list --vault default
```
```
Error: forbidden: no role grants Microsoft.KeyVault/vaults/secrets/readMetadata/action in this vault
```
Exit code `1`.

```bash
rocketvault --config /tmp/rv-prov/rv.yaml vaults update default --enabled=false
```
```
Error: permission denied: admin or vaults/manage required for vault "default"
```
Exit code `1`.

```bash
rocketvault --config /tmp/rv-prov/rv.yaml vaults delete default
```
```
Error: permission denied: admin or vaults/manage required for vault "default"
```
Exit code `1`.

```bash
rocketvault --config /tmp/rv-prov/rv.yaml vault-access grant msp-bot --role "Key Vault Administrator" --vault default
```
```
Error: permission denied: admin, vaults/manage, or Key Vault Data Access Administrator required for this vault
```
Exit code `1`. All 8 of step 1's attempts refused — the self-escalation
attempt held on both the HTTP and the CLI path.

**2. Self-quota escalation: `msp-bot` attempts to raise its own quota,
revoke its own grant, and list every grant — over HTTP, then the CLI.**

```bash
curl -s -X PUT $BASE/vault-provisioning-grants/$BOT_ID -H "Authorization: Bearer $BOT_TOKEN" \
  -H 'Content-Type: application/json' -d '{"quota":99}'
```
```json
{"detailed_error":"","id":"Insufficient permissions: admin role required to manage vault provisioning grants","message":"Insufficient permissions: admin role required to manage vault provisioning grants","request_id":"req-da245d41","status_code":403}
```

```bash
curl -s -X DELETE $BASE/vault-provisioning-grants/$BOT_ID -H "Authorization: Bearer $BOT_TOKEN"
```
```json
{"detailed_error":"","id":"Insufficient permissions: admin role required to manage vault provisioning grants","message":"Insufficient permissions: admin role required to manage vault provisioning grants","request_id":"req-94eb3961","status_code":403}
```

```bash
curl -s -X GET $BASE/vault-provisioning-grants -H "Authorization: Bearer $BOT_TOKEN"
```
```json
{"detailed_error":"","id":"Insufficient permissions: admin role required to manage vault provisioning grants","message":"Insufficient permissions: admin role required to manage vault provisioning grants","request_id":"req-6cd46f37","status_code":403}
```

```bash
rocketvault --config /tmp/rv-prov/rv.yaml vault-provisioning grant msp-bot --quota 99
```
```
Error: permission denied: managing vault provisioning grants requires the admin role
```
Exit code `1`. All 4 refused, all with the identical message — this tier has
exactly one check, and it is the same check regardless of surface.

**3. Does holding a vault role help? `msp-bot` already holds `Key Vault
Administrator` in `acme-prod` (granted automatically at creation).**

```bash
rocketvault --config /tmp/rv-prov/rv.yaml vault-access list --vault acme-prod
```
```
ASSIGNMENT-ID                          ROLE                     PRINCIPAL-ID
83fc20ac-7172-4ae1-8c95-61573ae0da21   Key Vault Administrator  a10eee1d-f25f-432c-9b20-bd9abf416e5a
```
Retrying step 2's probes changes nothing:

```bash
curl -s -X PUT $BASE/vault-provisioning-grants/$BOT_ID -H "Authorization: Bearer $BOT_TOKEN" \
  -H 'Content-Type: application/json' -d '{"quota":99}'
```
```json
{"detailed_error":"","id":"Insufficient permissions: admin role required to manage vault provisioning grants","message":"Insufficient permissions: admin role required to manage vault provisioning grants","request_id":"req-d2d28427","status_code":403}
```

```bash
curl -s -X DELETE $BASE/vault-provisioning-grants/$BOT_ID -H "Authorization: Bearer $BOT_TOKEN"
```
```json
{"detailed_error":"","id":"Insufficient permissions: admin role required to manage vault provisioning grants","message":"Insufficient permissions: admin role required to manage vault provisioning grants","request_id":"req-6e01ef5f","status_code":403}
```

```bash
rocketvault --config /tmp/rv-prov/rv.yaml vault-provisioning grant msp-bot --quota 99
```
```
Error: permission denied: managing vault provisioning grants requires the admin role
```
Exit code `1`. The provisioning-grant tier is non-delegable regardless of
data-plane authority — holding "administrator of the vault you made" buys
nothing here, exactly as `requireGrantAdmin`'s admin-only, non-delegable
design predicts.

**4. Revocation is not a cascade — but proving that needs a quota slot freed
first, or the test proves nothing.**

`msp-bot` was at quota 2 of 2 (`acme-prod`, `acme-third`) at this point. A
create attempted straight after revoking the grant would fail on *quota*
regardless of whether the grant itself still existed, so the revocation
boundary would never actually be exercised. As admin, free a slot first by
purging `acme-third` (kept `acme-prod`, since the previous example refers to
it by name):

```bash
rocketvault --config /tmp/rv-prov/rv.yaml vaults delete acme-third   # as admin
rocketvault --config /tmp/rv-prov/rv.yaml vaults purge acme-third    # as admin
```
```
Vault "acme-third" deleted successfully
```
```
Vault "acme-third" purged successfully
```
Confirmed via direct DB query that `msp-bot`'s grant quota (2) now exceeds
its owned-vault count (1, `acme-prod` only) — quota is no longer the
blocker. Now, as admin, revoke the grant itself:

```bash
rocketvault --config /tmp/rv-prov/rv.yaml vault-provisioning revoke msp-bot
```
```
Provisioning grant revoked: principal=a10eee1d-f25f-432c-9b20-bd9abf416e5a
```
As `msp-bot`, with the grant gone and a free slot:

```bash
rocketvault --config /tmp/rv-prov/rv.yaml vaults create post-revocation-test
```
```
Error: permission denied: admin, a global vaults/manage grant, or a vault provisioning grant required to create a vault
```
Exit code `1`. This is a **distinct error text** from step 6's earlier
quota-exceeded message in the previous example (`"vault provisioning quota
exceeded: 2 of 2 used"`) — proof this run genuinely exercised the no-grant
path, not the quota path. Pre-existing rights, by contrast, survive
revocation untouched:

```bash
rocketvault --config /tmp/rv-prov/rv.yaml secrets list --vault acme-prod
```
```
ID                                    Name            Version  Enabled  Tags  Created
------------------------------------  --------------  -------  -------  ----  -------------------------
d590bb30-8507-4953-9b8e-697345fd7b1a  example-secret  1        true           2026-09-04T18:28:32+05:30
```
```bash
rocketvault --config /tmp/rv-prov/rv.yaml vaults list
```
```
ID                                    Name       Enabled  RetentionDays  Created
------------------------------------  ---------  -------  -------------  -------------------------
056c2416-16bc-49cd-8559-e4822a68f375  acme-prod  true     90             2026-09-04T18:27:24+05:30
```
Both succeed — revoking the *right to create more* does not touch what the
grant already produced.

**5. The audit trail names somebody — mostly.**

The brief's own check queries `audit_logs` for `action LIKE
'%provisioning_grant%' OR action='create_vault'`. Every row it returns
(`revoke_provisioning_grant`, `create_vault` ×7, `issue_provisioning_grant`
×2) carries a real, non-empty, non-zero `user_id` matching the actual admin
or `msp-bot` principal. That check passes as specified.

Broadening the same query to `delete_vault`/`purge_vault` around the same
window (step 4's admin-run purge of `acme-third`) does not pass:

```sql
sqlite3 -readonly /tmp/rv-prov/rv.db "select rowid, action, user_id from audit_logs where action in ('delete_vault','purge_vault') order by rowid desc limit 2;"
```
```
+-------+--------------+---------+
| rowid |    action    | user_id |
+-------+--------------+---------+
| 139   | purge_vault  |         |
| 134   | delete_vault |         |
+-------+--------------+---------+
```
Both rows carry an **empty `user_id`**, even though the CLI session that ran
them was `admin`, fully authenticated, in the same run that stamped
`create_vault` and `issue_provisioning_grant` correctly. This is the finding
now recorded as `docs/known-bugs.md` § B58: `DeleteVault`, `RecoverVault`,
and `PurgeVault` (`internal/services/vaults/vault_service.go:638`, `:690`,
`:770`) and `RevokeRoleAssignment`
(`internal/services/authorization/role_assignment_service.go:203`) all
hardcode an empty actor in their audit call, while their siblings
(`create_vault`, `update_vault`, `AssignRole`) pass the real principal
correctly. The four most destructive operations in the system are exactly
the ones the audit log cannot attribute — for every actor, including a
global admin, on both the CLI and HTTP paths. See § B58 for the full root
cause; this step is what found it, which is the best argument for why this
check belongs in the plan at all.

**6. The startup diagnostic for a global `vaults:manage` grant fires
correctly.**

As admin, hand-create a global (`vault_id: null`) `vaults:manage` allow
policy for `msp-bot` — deliberate test input on a scratch instance, not a
real production grant:

```bash
curl -s -X POST $BASE/access-policies -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"principal_id":"'$BOT_ID'","principal_type":"user","resource_type":"vaults","operation":"manage","effect":"allow"}'
```
```json
{"id":"afe3b3a1-3324-4160-b7c6-01b01014bd02","principal_id":"a10eee1d-f25f-432c-9b20-bd9abf416e5a","principal_type":"user","resource_type":"vaults","operation":"manage","effect":"allow","created_at":"2026-09-04T13:31:16.550176763Z"}
```
Restart the server (same config, same port). `GET /health/live` → `200`
confirms a clean boot, then the startup log carries:

```
level=warning msg="Principal holds a global vaults:manage grant, which
confers management of EVERY vault and role-assignment management
everywhere; a future release narrows this to create-and-list only.
Consider replacing it with a bounded vault provisioning grant."
principal_id=a10eee1d-f25f-432c-9b20-bd9abf416e5a principal_type=user
```
The diagnostic named `msp-bot`'s own principal ID, not a generic message.
Then, to confirm what that policy actually buys in release 1 — the same
probe as step 1, against the same vault `msp-bot` does not own:

```bash
rocketvault --config /tmp/rv-prov/rv.yaml vaults update default --enabled=false   # as msp-bot
```
```
ID                                    Name     Enabled  PurgeProtection  RetentionDays  Created
------------------------------------  -------  -------  ---------------  -------------  --------------------
00000000-0000-0000-0000-00000000efa1  default  false    false            90             2026-09-04T12:44:47Z
```
Exit code `0` — it **succeeds**. The identical operation that step 1 refused
under a provisioning grant succeeds here, under a global `vaults:manage`
policy, against a vault `msp-bot` never created — exactly the behavior
release 2 removes (see below). Reverted immediately:

```bash
rocketvault --config /tmp/rv-prov/rv.yaml vaults update default --enabled=true   # as admin
```
```
ID                                    Name     Enabled  PurgeProtection  RetentionDays  Created
------------------------------------  -------  -------  ---------------  -------------  --------------------
00000000-0000-0000-0000-00000000efa1  default  true     false            90             2026-09-04T12:44:47Z
```

#### Gotchas this example surfaces

1. **Every boundary held.** Step 1 refused all 8 attempts (4 HTTP + 4 CLI),
   step 2 refused all 4 (3 HTTP + 1 CLI), and step 3 refused all 3 (2 HTTP +
   1 CLI) — 15 refusal attempts in total, on both the HTTP and CLI paths,
   including the step-1 self-escalation probe, the single most important
   attempt in this plan. A boundary example whose conclusion is "it all
   worked" is a valid and valuable result, not an anticlimax.
2. **Revocation is not a cascade.** Revoking a provisioning grant removes
   only the right to create *more* vaults; it does not touch what the grant
   already produced — `msp-bot` keeps `acme-prod`, its `Key Vault
   Administrator` role there, and everything in it. Confirmed live in step 4.
3. **An HTTP `403` does not imply a CLI `403` — they are separate
   enforcement points.** HTTP requests get authorization for free from
   `PolicyMiddleware`; every CLI command reproduces the equivalent check
   itself (this repo's CLAUDE.md, "CLI Authorization"). Both paths held for
   every probe in this example, but that is a result to confirm, not an
   assumption to skip — a new CLI command that omits its tier's check
   bypasses authorization entirely, with no other enforcement point behind
   it.
4. **The revocation test in step 4 needed a quota slot freed first.**
   `msp-bot` was sitting at quota (2 of 2) going in; reversing the grant
   without freeing a slot would have produced the same quota-exceeded
   refusal regardless of revocation, proving nothing about the revocation
   boundary itself. Freeing the slot first (purging `acme-third`) let the
   post-revocation create attempt fail on a genuinely different error —
   `"admin, a global vaults/manage grant, or a vault provisioning grant
   required to create a vault"` versus the earlier `"vault provisioning
   quota exceeded: 2 of 2 used"` — which is how step 4 can tell the two
   boundaries apart at all.
5. **The CLI cross-vault probes in step 1 deliberately used a `secrets`
   *read* command, not a write.** `secrets create/update/delete/import/export`
   carry an unrelated legacy global-role gate (`docs/known-bugs.md` §
   B57) that refuses `msp-bot` regardless of the vault boundary being
   tested, since its global account role is plain `user`. `secrets get`
   (`cmd/secrets/get.go`) carries no such gate, so it isolates the vault
   check the way the probe needs — a write command here would have made the
   refusal ambiguous between "the vault boundary held" and "the unrelated
   B57 gate fired first."
6. **A global `vaults:manage` access policy still confers management of
   every vault, in release 1, exactly as the startup diagnostic warns.**
   Confirmed live in step 6: with only that policy (no vault-specific role
   assignment), `msp-bot` disabled the `default` vault — one it neither
   created nor holds any role in. This is expected, by-design release-1
   behavior, not a violated boundary; it is precisely what release 2
   removes.

#### Release 2 has since shipped — the escalation path above is now closed

Step 6 above showed a global `vaults:manage` allow policy at its old,
unnarrowed strength: full management of every vault and every
role-assignment, everywhere, for as long as that policy existed. That was
true of the release this worked example was written against (release 1);
it is **no longer true** — release 2 (v4.6.0) narrowed both `CanManageVault`
and `CanManageRoleAssignments` to consult a vault-scoped check for a
concrete vault, so a global allow now confers create-and-list only. Do not
read step 6 above as current behavior; it documents the pre-narrowing state
for historical/regression-comparison purposes. See the "Narrowed global
`vaults:manage` (release 2)" subsection below (after this example's Teardown)
for the current test procedure, and
`docs/release-notes/v4.6.0-narrow-global-vault-manage.md` for the full
account of what changed.

For the design of the narrowing itself, see
`docs/superpowers/specs/2026-09-03-self-service-vault-provisioning-design.md`
§2 ("Narrowing the global grant — without breaking global denies," the
`CheckVaultScopedAccess` asymmetry: a global deny still blocks every vault, a
global allow no longer reaches one the principal doesn't own) and §9
("Sequencing — two releases," which spells out why release 1 is additive and
non-breaking, and what release 2 changes). §9's open question — what a
global-policy holder gets on the create path once the narrowing lands — is
now resolved too: such a holder receives the same vault-scoped creator
grants (`vaults:manage` policy + `Key Vault Administrator` assignment) a
provisioning grantee already gets, minus the quota check. See the release
note's "Creator grants on the global-policy create path" section.

#### Teardown

This example leaves the shared scratch instance running, per the previous
example's Teardown note — Task 3 of this plan owns tearing it down. State
left behind, for the record: `msp-bot`'s provisioning grant is revoked; it
still owns `acme-prod` with `Key Vault Administrator` there; `acme-third` is
purged; the global `vaults:manage` access policy created for `msp-bot` in
step 6 is left in place, since it's harmless scratch state and is the live
evidence the diagnostic warning is tied to.

#### Narrowed global vaults:manage (release 2)

- [ ] Give a non-admin principal a global `vaults:manage` allow
      (`vault_id: null`, via the admin-only `createAccessPolicy` HTTP route --
      there is no CLI for access policies).
- [ ] That principal can still **create** a vault and **list** vaults.
- [ ] It can manage the vault it just created -- get, update, role
      assignments -- because the create now writes it vault-scoped creator
      grants.
- [ ] Against a vault it did **not** create: `vaults get`, `vaults update`,
      `vaults delete` and `vault-access grant` all refuse. Before this release
      all four succeeded. Check the HTTP API too, not just the CLI.
- [ ] It cannot award itself `Key Vault Administrator` in another principal's
      vault -- this is the escalation path the release closes.
- [ ] A global `vaults:manage` **deny** still blocks that principal on every
      vault, including ones it created.
- [ ] A global **deny** on secrets still blocks reads and writes through both
      the API and the CLI. This path was deliberately not touched; if it
      regressed, the narrowing leaked into `CheckAccess`.
- [ ] An `admin` account role is unaffected throughout.
- [ ] A provisioning grantee is unaffected throughout -- its rights were
      already vault-scoped.

## 6. Vault Access (RBAC) — Azure Role Assignments

- [ ] `rocketvault vault-access roles` (no auth) → lists all built-in Azure roles
      and their data actions: `Key Vault Administrator`, `Key Vault Reader`,
      `Key Vault Secrets User`, `Key Vault Secrets Officer`, `Key Vault Crypto User`,
      `Key Vault Crypto Officer`, `Key Vault Certificates Officer`,
      `Key Vault Purge Operator`, `Key Vault Certificate User`,
      `Key Vault Crypto Service Encryption User`, `Key Vault Data Access Administrator`.
      Also confirm any **legacy** role names print as
      `(deprecated: no longer grantable, grants no access — use an Azure role instead)`.
- [ ] ```bash
      rocketvault vault-access grant alice --role "Key Vault Secrets User" \
        --vault test-vault-2 --username admin --password admin123 --totp-code <code>
      ```
- [ ] `rocketvault vault-access list --vault test-vault-2` → shows the new assignment.
- [ ] `GET /api/v1/vaults/test-vault-2/role-assignments` (HTTP) → same data.
- [ ] As `alice`, confirm she can read secrets in `test-vault-2` (matches
      `Secrets User` data action) but **cannot** create/update/delete secrets
      there, and has **zero** access to keys/certs in that vault.
- [ ] `rocketvault vault-access revoke <assignment-id> --vault test-vault-2` →
      alice loses access immediately (next request 403, not waiting for JWT expiry —
      confirm this, since it implies a live per-request check, not a JWT-embedded claim).
- [ ] Grant a role to a **service account** principal type:
      `rocketvault vault-access grant my-svc --role "Key Vault Crypto User" --principal-type service_account --vault test-vault-2 ...`
      → confirm the service account's OAuth2 token can now do crypto ops in that vault.
- [ ] **Deny-by-default**: create a brand-new vault, grant nobody any role, confirm
      even the vault creator (if not global admin) gets `403` on data-plane routes
      in that vault until explicitly granted — this is the "Vault data-plane routes
      are deny-by-default" behavior called out in CLAUDE.md.
- [ ] **`Key Vault Data Access Administrator`**: grant this role (and *nothing
      else*) to a user in a vault. Confirm they can grant/revoke *other* role
      assignments in that vault but have **zero** data-plane access themselves
      (can't read/write secrets, keys, or certs there) — this is the one role
      that manages access without granting access.
- [ ] **Access policies explicit-deny override**: create an access policy
      (`POST /api/v1/access-policies`) that explicitly denies a principal who
      otherwise holds a role granting access, confirm the deny wins (evaluated
      before role grants, per CLAUDE.md's Authorization section). Then
      `GET /api/v1/access-policies/principal/{id}` to confirm it lists correctly,
      and delete it, confirming access is restored.
- [ ] **`rotationpolicy` narrow-role check**: grant a user `Key Vault Crypto User`
      only (not Crypto Officer/Administrator) in a vault, confirm they can use a
      key for crypto ops (`sign`/`encrypt`/etc.) but get `403` on
      `GET/PUT/DELETE .../rotationpolicy` — this role is deliberately excluded
      from rotation-policy management even though it can use the key.

### Worked example: role assignments, deny-by-default, and the roles that don't do what you'd expect

> **Concept: authorization can say no from more than one place, and managing
> access is not the same as having it.** Every vault data-plane request runs
> through two independent checks, in a fixed order. `PolicyMiddleware` step 1
> is the access-policy explicit-deny override
> (`internal/middleware/middleware.go:453-561`) — an `AccessDenied` decision
> there returns `403` immediately, before step 2, the deny-by-default
> role-assignment check, ever runs. Step 2 calls
> `RoleAssignmentService.HasDataAction`
> (`internal/services/authorization/role_assignment_service.go:161-178`) fresh
> on every single request — a live `ListByPrincipalInVault` query, no caching,
> nothing baked into the JWT at issuance — and has **no admin short-circuit**,
> by design (`internal/services/authorization/data_action_authz.go:16-19`).
> Either layer can independently withhold access; only a role-assignment row
> can grant it. And one built-in role inverts the usual assumption that "can
> manage access" implies "has access": `Key Vault Data Access
> Administrator`'s entire data-action bundle is exactly
> `{ActionRoleAssignmentsWrite, ActionRoleAssignmentsDelete}`
> (`model/azure_roles.go:210-212`) — the only built-in role whose bundle
> contains zero `secrets`/`keys`/`certificates` actions. It can grant and
> revoke every other role in a vault while holding no permission to read or
> write a single secret, key, or certificate there itself.

#### Prerequisites

- Server running against a scratch config/DB (see **§0 Environment Setup**
  above — don't point this at a shared dev database).
- `rocketvault` CLI built and on your `PATH` (`go build -o rocketvault .`
  from repo root, or substitute `go run main.go` for every `rocketvault ...`
  command below).
- `curl` and [`jq`](https://jqlang.org/) installed.
- An admin user already created, with `ROCKETVAULT_TOTP_SECRET` exported in
  your shell (see **§2 Admin Bootstrap** above and §3.5's Prerequisites for
  the exact `export` one-liner — not repeated here).
- Four non-admin `user`-role accounts already created, same setup as §3.5
  step 7's negative-test user — each with its own password and TOTP secret,
  starting with no role grants anywhere: `alice`, `dataadmin`, `charlie`,
  `cryptouser`. The names describe the role each is about to be granted, not
  anything intrinsic to the account.

#### The 5 gotchas this example is built to surface

All five are real, verified-against-source behaviors — the first two were
reproduced live with byte-for-byte command/output pairs; the rest come from
the same live-verification pass and are quoted the same way.

1. **Deny-by-default holds identically for a global admin and a non-admin in
   a freshly created, ungranted vault.** `HasDataAction` has no admin
   short-circuit, by design — the comment in
   `internal/services/authorization/data_action_authz.go` reads "Data-plane
   access has none today, even over HTTP... copying that idiom here would
   grant the CLI a bypass the HTTP API doesn't have." Confirmed live on a
   brand-new vault (`test-fresh-vault`, zero grants to anyone): admin's own
   JWT and alice's JWT both got `403 Forbidden: no role assignment grants
   this operation in this vault` on the same route. A non-admin can't even
   route around this by creating her own vault to test against — vault
   *creation* is a separate, management-level check
   (`CanManageVault`, requires admin or a `(vaults, manage)` access-policy
   allow), and a fresh plain user has neither.
2. **Revocation is a live per-request DB check, not a JWT-embedded claim —
   the same, still-unexpired token goes from 200 to 403 with nothing about
   the token itself changing.** Both `RequireDataAction` on the CLI side and
   `PolicyMiddleware` on the HTTP side call the same live `HasDataAction`
   lookup; decoding the token's payload before and after a revocation showed
   byte-identical claims (`exp`, `jti`, `sub` unchanged, `exp` still ~55
   minutes out both times) — only the underlying `role_assignments` row
   changed.
3. **`Key Vault Data Access Administrator` can grant and revoke every other
   role in a vault while having zero data-plane access there itself.**
   Confirmed live: granted *only* that role to `dataadmin`. `dataadmin`
   successfully granted `charlie` `Key Vault Secrets User` in the same
   vault, then got `403` on both reading and writing a secret in that same
   vault — `CanManageRoleAssignments`, the check both the grant/revoke/list
   CLI commands and their HTTP equivalents call, never touches
   `secrets`/`keys`/`certificates` actions at all.
4. **An explicit access-policy deny beats an existing role grant, and it's
   a separate, admin-only management surface from role assignments —
   holding `Key Vault Data Access Administrator` does not let you touch
   access policies.** Confirmed live: `charlie`, holding `Key Vault Secrets
   User`, could read a secret (`200`) until admin created an explicit
   `deny` access policy against her for that resource/operation — the same
   `GET` then returned `403 Forbidden: access policy denied` (a distinct
   error string from the role-assignment `403`, confirming it was rejected
   at the explicit-deny step, before the role check ever ran). Deleting the
   policy restored access immediately, no restart or cache flush needed.
   Separately, `dataadmin` — the one role built to manage access — got
   `403 Insufficient permissions: admin role required to manage access
   policies` on the same access-policy routes: managing role assignments and
   managing access policies are disjoint code paths, gated by different
   checks entirely.
5. **`Key Vault Crypto User` can use a key for every crypto operation and can
   even update its attributes, but is deliberately, individually excluded
   from rotation-policy management.** Its data-action bundle
   (`model/azure_roles.go:182-189`) has no
   `ActionKeysRotationPolicyRead`/`Write`. Git history shows this is
   intentional, not an oversight, and pulls in two different directions on
   two adjacent-looking capabilities: commit `cdd591c` ("feat(authz): add
   key rotation-policy data actions, grant to Crypto Officer and
   Administrator", 2026-08-14) added the two rotation-policy actions to only
   `Key Vault Crypto Officer` and `Key Vault Administrator`, stating
   explicitly "not Crypto User, matching Azure." Four days later, commit
   `b93ee39` ("feat(model): add missing update/backup data actions to Key
   Vault Crypto User role", 2026-08-18) separately *added* `update` and
   `backup` to `Key Vault Crypto User`, citing real Azure's actual data-action
   list for that role as "the last live RBAC boundary gap identified in the
   2026-08-13 role-by-role re-verification." Confirmed live: granted *only*
   `Key Vault Crypto User` to `cryptouser` — an encrypt operation and a key
   attribute update both succeeded (`200`), but `GET`/`PUT`/`DELETE` on
   `.../rotationpolicy` all returned `403`. Contrast check: the identical
   `GET .../rotationpolicy` as admin (holding `Key Vault Administrator`,
   which does include the rotation-policy actions) returned
   `404 rotation policy not found` — a real "nothing set yet" response, not
   a `403` — confirming `cryptouser`'s `403` is a genuine authorization
   denial, not some unrelated 404-vs-403 quirk in the endpoint itself.

A service account's granted role was separately confirmed to behave exactly
like a human's for these purposes — same `HasDataAction` codepath, same
per-vault scoping, proven end-to-end through an actual key-sign operation via
a `client_credentials`-issued JWT — so nothing below is human-only behavior;
it's not walked through again here to keep this example to one cast of
principals.

#### Setup

```bash
BASE=http://localhost:8774/api/v1     # adjust host:port to your scratch config's server.listen_addr
TOTP_CODE=$(go run scripts/totp_generator.go -secret="$ROCKETVAULT_TOTP_SECRET" 2>&1 | grep -m1 -oP '(?<=--totp-code )\S+')
rocketvault users login --username admin --password admin123 --totp-code "$TOTP_CODE"

ADMIN_TOKEN=$(curl -s -X POST $BASE/users/login \
  -H "Content-Type: application/json" \
  -d "{\"username\":\"admin\",\"password\":\"admin123\",\"totp_code\":\"$TOTP_CODE\"}" \
  | jq -r .token)

rocketvault vaults create test-rbac
rocketvault vault-access grant admin --role "Key Vault Administrator" --vault test-rbac
```
Creating the vault is a management operation admin bypasses; everything
inside it is not — see §3.5's gotcha 1 for the full explanation, not repeated
here.

---

#### Part 1 — Grant, live revocation, and deny-by-default

**1. Seed a secret, then grant `alice` read access:**
```bash
curl -s -X POST $BASE/vaults/test-rbac/secrets \
  -H "Authorization: Bearer $ADMIN_TOKEN" -H "Content-Type: application/json" \
  -d '{"name":"rbac-test-secret","value":"visible-to-secrets-user"}' | jq .

rocketvault vault-access grant alice --role "Key Vault Secrets User" --vault test-rbac \
  --username admin --password admin123 --totp-code "$TOTP_CODE"
```
Expect: `granted Key Vault Secrets User to alice in vault (assignment
80de6ae2-e853-4d82-89d8-2d008c626702)`. **Copy the assignment ID** — needed
for step 3's revocation. Note `rocketvault vault-access list --vault
test-rbac` only works for a principal holding a management-level grant
(admin, `Key Vault Data Access Administrator`, or a `(vaults, manage)`
access-policy allow) — `alice` herself, holding only `Key Vault Secrets
User`, would get `Error: permission denied: admin, vaults/manage, or Key
Vault Data Access Administrator required for this vault` if she tried it.
Re-running the same grant a second time is harmless: `AssignRole` looks up
the existing `(principal, role, vault)` tuple first and returns the
original assignment unchanged rather than erroring or duplicating the row.

**2. As `alice`, confirm read access, then get admin to revoke it — same
token throughout (gotcha 2):**
```bash
ALICE_TOKEN=$(curl -s -X POST $BASE/users/login \
  -H "Content-Type: application/json" \
  -d '{"username":"alice","password":"<alices-password>","totp_code":"<alices-code>"}' \
  | jq -r .token)

curl -s $BASE/vaults/test-rbac/secrets -H "Authorization: Bearer $ALICE_TOKEN"
```
Expect `200` with `{"secrets":[{"id":"ed4f2242-...","name":"rbac-test-secret",...}],"total":1}`.

```bash
rocketvault vault-access revoke 80de6ae2-e853-4d82-89d8-2d008c626702 --vault test-rbac \
  --username admin --password admin123 --totp-code "$TOTP_CODE"
```
Expect: `revoked assignment 80de6ae2-e853-4d82-89d8-2d008c626702`.

```bash
curl -s $BASE/vaults/test-rbac/secrets -H "Authorization: Bearer $ALICE_TOKEN"
```
Expect `403 Forbidden: no role assignment grants this operation in this
vault` — the **exact same `$ALICE_TOKEN`**, no new login, no token reissued.

**3. Deny-by-default in a fresh vault, for both a global admin and a
non-admin (gotcha 1):**
```bash
rocketvault vaults create test-fresh-vault --username admin --password admin123 --totp-code "$TOTP_CODE"

curl -s -o /dev/null -w '%{http_code}\n' $BASE/vaults/test-fresh-vault/secrets \
  -H "Authorization: Bearer $ADMIN_TOKEN"
curl -s -o /dev/null -w '%{http_code}\n' $BASE/vaults/test-fresh-vault/secrets \
  -H "Authorization: Bearer $ALICE_TOKEN"
```
Expect `403` on both — identical body,
`Forbidden: no role assignment grants this operation in this vault`, whether
the caller is the global admin who just created the vault or a non-admin
with zero grants in it. As a further check, `alice` cannot route around this
by creating her *own* vault to test against:
```bash
curl -s -o /dev/null -w '%{http_code}\n' -X POST $BASE/vaults \
  -H "Authorization: Bearer $ALICE_TOKEN" -H "Content-Type: application/json" \
  -d '{"name":"alices-vault"}'
```
Expect `403` — vault creation is gated by the separate, management-level
`CanManageVault` check, which a fresh plain user never satisfies either.

---

#### Part 2 — The roles that don't do what you'd expect

**4. `Key Vault Data Access Administrator`: manages access, has none itself
(gotcha 3).** Grant `dataadmin` *only* that role in `test-rbac`:
```bash
rocketvault vault-access grant dataadmin --role "Key Vault Data Access Administrator" \
  --vault test-rbac --username admin --password admin123 --totp-code "$TOTP_CODE"
```
As `dataadmin`, grant `charlie` a data-plane role — this should succeed:
```bash
rocketvault vault-access grant charlie --role "Key Vault Secrets User" --vault test-rbac \
  --username dataadmin --password DataAdmin123! --totp-code <dataadmins-code>
```
Expect: `granted Key Vault Secrets User to charlie in vault (assignment
8516e7fd-eabf-4930-9d69-a4a661a8eb8a)`.

Now, as the same `dataadmin`, try to touch a secret directly:
```bash
DATAADMIN_TOKEN=$(curl -s -X POST $BASE/users/login \
  -H "Content-Type: application/json" \
  -d '{"username":"dataadmin","password":"DataAdmin123!","totp_code":"<dataadmins-code>"}' \
  | jq -r .token)

curl -s -o /dev/null -w '%{http_code}\n' $BASE/vaults/test-rbac/secrets/ed4f2242-... \
  -H "Authorization: Bearer $DATAADMIN_TOKEN"
curl -s -o /dev/null -w '%{http_code}\n' -X POST $BASE/vaults/test-rbac/secrets \
  -H "Authorization: Bearer $DATAADMIN_TOKEN" -H "Content-Type: application/json" \
  -d '{"name":"dataadmin-secret","value":"x"}'
```
Expect `403` on both — same `Forbidden: no role assignment grants this
operation in this vault` body. `dataadmin` just proved she can hand out
access to others while holding none of it herself.

**5. Access-policy explicit-deny beats a role grant, and it's a separate,
admin-only surface (gotcha 4).** `charlie` (granted `Key Vault Secrets User`
in step 4) can currently read the vault's secret — confirm `200`. Now, as
admin, create an explicit deny:
```bash
curl -s -X POST $BASE/access-policies \
  -H "Authorization: Bearer $ADMIN_TOKEN" -H "Content-Type: application/json" \
  -d '{"principal_id":"<charlies-user-id>","principal_type":"user",
       "resource_type":"secrets","operation":"get","effect":"deny",
       "vault_id":"<test-rbac-vault-id>"}' | jq .
```
Expect `201` with the new policy's `id`. `charlie`'s same `GET` now returns:
```
403  Forbidden: access policy denied
```
Note the different wording from step 2's role-assignment `403` — this is a
distinct rejection, at a distinct step, before the role check even runs.
Confirm it lists and reverts cleanly:
```bash
curl -s $BASE/access-policies/principal/<charlies-user-id> -H "Authorization: Bearer $ADMIN_TOKEN" | jq .
curl -s -X DELETE $BASE/access-policies/<policy-id> -H "Authorization: Bearer $ADMIN_TOKEN"
curl -s -o /dev/null -w '%{http_code}\n' $BASE/vaults/test-rbac/secrets/<secret-id> \
  -H "Authorization: Bearer $CHARLIE_TOKEN"
```
Expect the list to show `"total":1`, the delete to return `200
{"status":"OK"}`, and the final `GET` to return `200` again — access reverted
to being governed purely by `charlie`'s role grant, no restart needed.
Finally, confirm this surface really is disjoint from role-assignment
management: as `dataadmin` (the role built to manage access),
`GET $BASE/access-policies` returns `403 Insufficient permissions: admin
role required to manage access policies` — her `ActionRoleAssignmentsWrite/
Delete` grant nothing here.

**6. `Key Vault Crypto User` can use a key but not manage its rotation
policy (gotcha 5).** Grant `cryptouser` *only* that role in `test-rbac`,
against a key `admin` already created:
```bash
rocketvault vault-access grant cryptouser --role "Key Vault Crypto User" --vault test-rbac \
  --username admin --password admin123 --totp-code "$TOTP_CODE"
```
As `cryptouser`, a crypto operation and an attribute update both succeed:
```bash
curl -s -X POST $BASE/vaults/test-rbac/keys/<key-id>/encrypt \
  -H "Authorization: Bearer $CRYPTOUSER_TOKEN" -H "Content-Type: application/json" \
  -d '{"algorithm":"RSA-OAEP-256","value":"<base64>"}'
curl -s -X PUT $BASE/vaults/test-rbac/keys/<key-id> \
  -H "Authorization: Bearer $CRYPTOUSER_TOKEN" -H "Content-Type: application/json" \
  -d '{"tags":["updated-by-cryptouser"]}'
```
Expect `200` on both. Now the rotation policy, all three methods:
```bash
curl -s -o /dev/null -w '%{http_code}\n' $BASE/vaults/test-rbac/keys/<key-id>/rotationpolicy \
  -H "Authorization: Bearer $CRYPTOUSER_TOKEN"
curl -s -o /dev/null -w '%{http_code}\n' -X PUT $BASE/vaults/test-rbac/keys/<key-id>/rotationpolicy \
  -H "Authorization: Bearer $CRYPTOUSER_TOKEN"
curl -s -o /dev/null -w '%{http_code}\n' -X DELETE $BASE/vaults/test-rbac/keys/<key-id>/rotationpolicy \
  -H "Authorization: Bearer $CRYPTOUSER_TOKEN"
```
Expect `403` on all three. Contrast check, same `GET`, as admin (holding
`Key Vault Administrator`, which does include the rotation-policy actions):
```bash
curl -s -o /dev/null -w '%{http_code}\n' $BASE/vaults/test-rbac/keys/<key-id>/rotationpolicy \
  -H "Authorization: Bearer $ADMIN_TOKEN"
```
Expect `404 rotation policy not found` — a real "none set yet" response, not
a `403`, confirming `cryptouser`'s `403`s above are genuine authorization
denials rather than some 404-vs-403 quirk in the endpoint itself.

#### Cleanup

```bash
rocketvault vaults delete test-rbac --username admin --password admin123 --totp-code "$TOTP_CODE"
rocketvault vaults purge test-rbac --username admin --password admin123 --totp-code "$TOTP_CODE"
rocketvault vaults delete test-fresh-vault --username admin --password admin123 --totp-code "$TOTP_CODE"
rocketvault vaults purge test-fresh-vault --username admin --password admin123 --totp-code "$TOTP_CODE"
rocketvault users logout
```

---

## 7. Secrets

Run this whole section twice: once against the **flat** routes
(`/api/v1/secrets`) and once against a **vault-scoped** vault
(`/api/v1/vaults/{name}/secrets`) — they're meant to behave identically 1:1,
so any divergence is a bug.

- [ ] Create: `POST /api/v1/secrets` `{"name":"db-pass","value":"s3cr3t","tags":["prod"]}`
      → `201`.
- [ ] `rocketvault secrets create db-pass s3cr3t --tags prod --username admin ...`
      → same via CLI.
- [ ] List / get / update (`PUT`, creates a new version) / soft-delete (`DELETE`).
- [ ] Versions: `GET /api/v1/secrets/{id}/versions`, `/versions/{n}`, `/versions/latest`
      — update the secret 2–3 times, confirm each version retrievable and values match.
- [ ] Generate: `POST /api/v1/secrets/generate` and
      `rocketvault secrets generate-password --length 32 --special=false ...` →
      confirm length/charset flags actually take effect (count chars, check for
      special chars absent).
- [ ] Export/Import round trip:
      ```bash
      rocketvault secrets export --format json --file /tmp/secrets.json --tags prod ...
      rocketvault secrets import --file /tmp/secrets.json ...          # collides on name (skipped), same either way
      rocketvault secrets import --file /tmp/secrets.json --overwrite ... # --overwrite is a known no-op, see worked example below
      ```
      Also test `--format csv` for export. **Known gap**: `--overwrite` is parsed
      and logged but never branched on — every import row is an unconditional
      create, so a name collision is always skipped, with or without the flag,
      and the collision reason (a UNIQUE constraint error) never reaches the
      CLI/HTTP caller. See the worked example's gotcha #3 for the verified
      behavior and exact source lines.
- [ ] Backup/restore item: `POST /api/v1/secrets/{id}/backup` → opaque blob;
      `POST /api/v1/secrets/restore` with that blob → recreates the secret (confirm
      behavior if the original still exists vs. was deleted first).
- [ ] Soft-delete → `GET /api/v1/deleted/secrets` (flat) or
      `GET /api/v1/vaults/{name}/deleted/secrets` (vault-scoped) lists it →
      `POST .../restore` brings it back → delete again → `DELETE .../purge`
      permanently removes it, `restore` now 404s.
- [ ] `purge_protection`: **known gap, don't expect this to be settable for a
      secret.** The `secrets` table has a `purge_protection` column and
      `PurgeSecret` does check it, but no API field, CLI flag, or repository
      method can ever set it to `true` — `SecretRepositoryInterface` has no
      `SetPurgeProtection` (unlike `KeyRepositoryInterface`/
      `CertificateRepositoryInterface`, which both have one). So a soft-deleted
      secret's manual `purge` always succeeds immediately, regardless of the
      vault's `retention_days`. This is distinct from *vault-level* purge
      protection (`vaults create --purge-protection`), which does work — confirm
      that one separately if you want to exercise purge protection at all in
      this section.
- [ ] **Vault-scoped isolation**: create a same-named secret in two different
      vaults, confirm they're fully independent (different IDs, different values,
      deleting one doesn't touch the other).
- [ ] **Vault membership visibility**: per `[[project-multi-vault]]` memory, vault
      members see *all* secrets in a vault they belong to (not filtered by creator)
      — confirm as two different users both granted `Key Vault Secrets Officer` in
      the same vault, User B can see/edit a secret User A created.

#### Worked example: versions, tag filtering, import `--overwrite`, and per-item backup — four gaps between what the CLI/API imply and what actually happens

**New to this repo?** This is a fully self-contained, copy-pasteable
walkthrough — you shouldn't need to read any other file first. It creates two
secrets in the `default` vault, then deliberately runs each one into the four
gaps named above.

##### Prerequisites

- Server running against a scratch config/DB (see **§0 Environment Setup**
  above), started as `go run main.go --config /tmp/rv-test.yaml serve` (or your
  built binary) — export `CFG=/tmp/rv-test.yaml` in the shell you run this
  walkthrough's CLI commands from, so every `rocketvault` invocation below can
  pass `--config "$CFG"` and read/write the same database the server is using.
- `rocketvault` CLI built and on your `PATH` (`go build -o rocketvault .` from
  repo root, or substitute `go run main.go` for every `rocketvault ...`
  command below).
- `curl` and [`jq`](https://jqlang.org/) installed.
- An admin user already created, with `ROCKETVAULT_TOTP_SECRET` exported in
  your shell (see **§2 Admin Bootstrap** and **§3.5's Prerequisites** above for
  the full explanation of this convention and why `-m1` matters below).
- A **fresh** vault data-plane state in `default` — a brand-new scratch DB per
  §0 has zero role grants anywhere, `default` included, so step 1 below
  self-grants before touching anything.

##### The four gotchas this example is built to surface

All four are real, verified-against-source behaviors — you will hit them if
you don't know about them going in.

1. **`versions/latest` always returns the value from *before* the most recent
   update, and a brand-new secret has zero version rows at all.**
   `secretService.CreateSecret` sets `Version: 1`
   (`internal/services/secrets/secret_service.go:228`) and writes **no**
   version row — so immediately after create, `GET .../versions` returns the
   literal JSON `null` (not `[]`), and `GET .../versions/latest` /
   `.../versions/1` both 404. `UpdateSecret` archives the **pre-update** state
   as a new version row before applying the change
   (`internal/services/secrets/secret_service.go:285-294`), so after the first
   update the secret is `version: 2` and version row `1` holds the *original*
   value — not the new one. The invariant: version row `k` holds whatever the
   secret looked like while it *was* version `k`; the current version has no
   row of its own, so `versions/latest` is always one step behind `GET
   /secrets/{id}`. HTTP `PUT` short-circuits an identical-value update with a
   `400` (`api/secrets.go:557-560`, `no changes provided`) — so a same-value
   `PUT` creates no version. CLI `secrets update` has no such guard
   (`cmd/secrets/update.go:92-96` always sends the value through), so it
   **does** create a version even when the value is unchanged, and its output
   (`cmd/secrets/update.go:111`, exactly `Secret <uuid> updated successfully`)
   never prints the new version number — you have to re-`get` to see it.
2. **`--tags`/`?tags=` filtering is a silent no-op on both `list` and
   `export`.** The flag is parsed and threaded all the way down
   (`api/params.go:32,72` → `internal/services/secrets/secret_service.go:363`
   → `internal/services/secrets/secret_service.go:580` for export's call into
   `ListSecrets`), but `SecretRepository.List`'s SQL `WHERE` clause never reads
   `filter.Tags` at all (`internal/repositories/secret_repository.go:256-273`)
   — the struct's own comment admits "Tags is accepted for compatibility; tag
   filtering lives in TagService"
   (`internal/repositories/secret_repository.go:46-47`), but no caller ever
   does that post-filtering. So `secrets export --tags prod` silently exports
   **every** secret in the vault, plaintext values included, no error, no
   warning — directly contradicting `docs/testing-guide.md`'s tag-filtering
   section (that doc is stale; don't treat it as a source of truth here).
   Aggravating this: the CLI's `--encrypt` flag on export (default `true`) and
   `--encrypted` flag on import (default `true`) are both dead — never read
   outside tests — export always writes plaintext via
   `os.WriteFile(exportFile, data, 0o600)` (`cmd/secrets/export.go:115`).
3. **Import's `--overwrite` flag does nothing — a plain re-import and an
   `--overwrite` re-import of the same file produce byte-identical output, and
   the actual collision reason is silently dropped.** `Overwrite` is parsed and
   threaded through but read at exactly one place, a logrus log field
   (`internal/services/secrets/secret_service.go:658`) — never branched on.
   Every import row is an unconditional `CreateSecret` call
   (`internal/services/secrets/secret_service.go:721-735`). Collision
   detection is enforced purely by the DB's unique index on `(vault_id, name)`
   (`internal/db/db.go:910`) — with **no** `WHERE deleted_at IS NULL`, so even
   a *soft-deleted* secret still blocks reuse of its name. Both a plain
   re-import and an `--overwrite` re-import report the identical
   `Secrets imported successfully` / `Imported: 0` / `Skipped: N`
   (`cmd/secrets/import.go:111-112`); the real per-row reason (a UNIQUE
   constraint error) lands in an internal `result.Errors` field that neither
   the CLI nor the HTTP response (`api/secrets.go:280-292`,
   `"Successfully imported 0/N secrets"`) ever surfaces.
4. **Per-item secret backup is owner-gated — not vault-gated, unlike
   everything else in this section — and exists only on the flat route, not
   the vault-scoped one.** `POST /api/v1/secrets/{id}/backup` and
   `POST /api/v1/secrets/restore` exist; `POST
   /api/v1/vaults/{name}/secrets/{id}/backup` does not — `InitBackupItem`
   binds only to the flat `api.BaseRoutes.Secrets` subrouter
   (`api/backup_item.go:16-24`, `api/api.go:152`), so that vault-scoped path
   never matches any route at all and falls through to the router's generic
   `Handle404` (`api/api.go:181-189`) — no auth even attempted, and a visibly
   different, thinner JSON shape than a normal "not found" (compare
   `api/context.go:106-109`'s `SetNotFound`, used everywhere else in this
   section). `BackupSecret` reads the secret with an **admin** scope (ignoring
   vault membership entirely) then does a manual ownership check:
   `if secret.UserID != userID { return ErrForbidden }`
   (`internal/backup/item_backup.go:57-62`) — mapped by the handler to a `403`
   whose `id`/`message` are both `Insufficient permissions: backup_secret`
   (`api/context.go:100-103`'s `SetPermissionError`, same pattern §3.5 already
   demonstrates for service accounts). So a vault peer holding `Key Vault
   Secrets Officer` in the same vault — who **can** read/update/delete that
   same secret, and whose role even grants the `ActionSecretsBackup`/
   `ActionSecretsRestore` data actions themselves — still gets `403` backing it
   up: the route-level role check passes, and the ownership check inside the
   service is the thing that actually blocks it. `RestoreSecret` has no such
   ownership check (`internal/backup/item_backup.go:69-77`) — it just
   overwrites the decoded blob's `UserID` with whoever is restoring
   (`secret.UserID = userID`) and inserts under a fresh ID, so restoring a
   blob you didn't create is allowed, and makes *you* the new owner. Restoring
   while the original still exists collides on the same unique index as
   gotcha #3 (`UNIQUE constraint failed: secrets.vault_id, secrets.name`,
   surfaced as a `500` via `detailed_error`, since `RestoreSecret` adds no
   wrap of its own); restoring after the original is purged succeeds (`200
   {"status":"OK"}`) and the secret reappears under a **new** ID.

##### Setup

```bash
CFG=/tmp/rv-test.yaml
BASE=http://localhost:8774/api/v1     # adjust host:port to your scratch config's server.listen_addr
TOTP_CODE=$(go run scripts/totp_generator.go -secret="$ROCKETVAULT_TOTP_SECRET" 2>&1 | grep -m1 -oP '(?<=--totp-code )\S+')
ADMIN_TOKEN=$(curl -s -X POST $BASE/users/login \
  -H "Content-Type: application/json" \
  -d "{\"username\":\"admin\",\"password\":\"admin123\",\"totp_code\":\"$TOTP_CODE\"}" \
  | jq -r .token)
```
If `$ADMIN_TOKEN` comes back empty/`null`, the TOTP code likely expired between
generating it and this step — regenerate and retry (codes are time-windowed,
30s).

---

**1. Log in with the CLI and self-grant full control of `default`.** A fresh
admin has zero vault data-plane access anywhere, `default` included:
```bash
rocketvault --config "$CFG" users login --username admin --password admin123 --totp-code "$TOTP_CODE"
rocketvault --config "$CFG" vault-access grant admin --role "Key Vault Administrator" --vault default
```
Expect: `granted Key Vault Administrator to admin in vault (assignment <id>)`.
Skipping this makes step 2 fail with `forbidden: no role grants
Microsoft.KeyVault/vaults/secrets/setSecret/action in this vault`.

**2. Create two secrets** — one tagged `prod`, one deliberately not, so
gotcha #2 has something to expose:
```bash
rocketvault --config "$CFG" secrets create db-pass "s3cr3t-v1" --tags prod --vault default
rocketvault --config "$CFG" secrets create smtp-key "smtp-v1" --vault default
```
Expect a confirmation table for each with `Version 1`, `Enabled: true`.
Capture both IDs:
```bash
SECRET1_ID=$(rocketvault --config "$CFG" secrets list --vault default --output json | jq -r '.[] | select(.Name=="db-pass") | .ID')
SECRET2_ID=$(rocketvault --config "$CFG" secrets list --vault default --output json | jq -r '.[] | select(.Name=="smtp-key") | .ID')
```

**3. Gotcha #1, first half — a brand-new secret has no version rows at all:**
```bash
curl -s $BASE/secrets/$SECRET1_ID/versions -H "Authorization: Bearer $ADMIN_TOKEN"
curl -s -o /dev/null -w "%{http_code}\n" $BASE/secrets/$SECRET1_ID/versions/latest -H "Authorization: Bearer $ADMIN_TOKEN"
curl -s -o /dev/null -w "%{http_code}\n" $BASE/secrets/$SECRET1_ID/versions/1 -H "Authorization: Bearer $ADMIN_TOKEN"
```
Expect, in order: the literal body `null` (not `[]`), then `404`, then `404`.
Both 404 bodies are the same generic
`{"id":"secret not found","message":"secret not found","detailed_error":"","status_code":404,"request_id":"req-xxxxxxxx"}`
you'd get for a wholly nonexistent secret ID — nothing distinguishes "the
secret exists but this version doesn't" from "the secret doesn't exist".

**4. Gotcha #1, second half — update the secret, then watch `versions/latest`
lag one step behind:**
```bash
rocketvault --config "$CFG" secrets update "$SECRET1_ID" "s3cr3t-v2" --vault default
rocketvault --config "$CFG" secrets get "$SECRET1_ID" --vault default --output json | jq -r '.[0] | "\(.Version) \(.Value)"'
```
Expect the update to print `Secret <uuid> updated successfully` (no version
number), then `get` to show `2 s3cr3t-v2` — the secret itself is current. Now
check the version endpoint:
```bash
curl -s $BASE/secrets/$SECRET1_ID/versions/latest -H "Authorization: Bearer $ADMIN_TOKEN" | jq '{version, value}'
```
Expect `{"version": 1, "value": "s3cr3t-v1"}` — the **old** value, archived
the moment the update ran, not what `secrets get` just showed you.

**5. Gotcha #1, continued — the CLI/HTTP divergence on a no-op update.** Run
the identical already-current value through the CLI again:
```bash
rocketvault --config "$CFG" secrets update "$SECRET1_ID" "s3cr3t-v2" --vault default
rocketvault --config "$CFG" secrets get "$SECRET1_ID" --vault default --output json | jq -r '.[0].Version'
```
Expect `Secret <uuid> updated successfully` again, and the version now `3` —
the CLI created a version for a value that didn't change. Contrast with the
same no-op sent straight to the HTTP API:
```bash
curl -s -X PUT $BASE/secrets/$SECRET1_ID \
  -H "Authorization: Bearer $ADMIN_TOKEN" -H "Content-Type: application/json" \
  -d '{"value":"s3cr3t-v2"}' | jq .
```
Expect `400`:
`{"id":"Invalid or missing parameter: no changes provided","message":"Invalid or missing parameter: no changes provided","detailed_error":"","status_code":400,"request_id":"req-xxxxxxxx"}`
— the HTTP handler's own equality check catches this; the CLI's request
builder never gives it the chance to, since it always sends the value.

**6. Gotcha #2 — tag filtering is a no-op on `list` and `export`:**
```bash
rocketvault --config "$CFG" secrets list --vault default --tags prod --output json | jq -r '.[].Name'
```
Expect **both** `db-pass` and `smtp-key` printed, even though `smtp-key` was
never tagged `prod`. Now export with the same filter:
```bash
rocketvault --config "$CFG" secrets export --format json --file /tmp/secrets-export.json --tags prod --vault default
jq . /tmp/secrets-export.json
```
Expect a two-element array containing both secrets' plaintext `value` fields —
`smtp-key` again slipping through the `--tags prod` filter, and both values
readable in the clear despite `--encrypt` defaulting to `true`.

**7. Gotcha #3 — reimport the same file with and without `--overwrite`,
compare the output byte-for-byte:**
```bash
rocketvault --config "$CFG" secrets import --file /tmp/secrets-export.json --vault default
rocketvault --config "$CFG" secrets import --file /tmp/secrets-export.json --overwrite --vault default
```
Expect the identical three lines both times:
```
Secrets imported successfully
Imported: 0
Skipped: 2
```
Both names already exist in `default`, so every row collides on the unique
index — `--overwrite` changes nothing about that, and neither run tells you
*why* the rows were skipped.

**8. The aggravating half of gotcha #3 — a soft-deleted secret still blocks
its own name.** Soft-delete `smtp-key`, then try to reuse the name:
```bash
curl -s -o /dev/null -w "%{http_code}\n" -X DELETE $BASE/secrets/$SECRET2_ID -H "Authorization: Bearer $ADMIN_TOKEN"
rocketvault --config "$CFG" secrets create smtp-key "smtp-v2" --vault default
```
Expect the `DELETE` to return `200`, then the `create` to fail:
```
Error: failed to create secret: failed to create secret: failed to insert secret: UNIQUE constraint failed: secrets.vault_id, secrets.name
```
(The doubled "failed to create secret" is the CLI's own wrap around the
service's identically-worded wrap — harmless, just noisy.) `smtp-key` is only
*soft*-deleted, not purged, and the unique index has no `deleted_at IS NULL`
predicate, so its name stays reserved.

**9. Gotcha #4, first half — flat backup works, vault-scoped backup doesn't
exist:**
```bash
BLOB=$(curl -s -X POST $BASE/secrets/$SECRET1_ID/backup -H "Authorization: Bearer $ADMIN_TOKEN" | jq -r .blob)
curl -s $BASE/vaults/default/secrets/$SECRET1_ID/backup -X POST -H "Authorization: Bearer $ADMIN_TOKEN" | jq .
```
Expect the first call to return `200` with a `blob` field (save it — `$BLOB`
is needed in step 12); the second to return the router's generic 404,
`{"id":"api.not_found","message":"Not found","status_code":404}` — a visibly
different, thinner shape than the app-level "secret not found" from step 3,
confirming this is a route that was never registered, not a lookup that
failed.

**10. Gotcha #4, second half — a vault peer with a role that grants backup
still can't back up someone else's secret.** Create `qa-peer` and grant them
`Key Vault Secrets Officer` in `default`:
```bash
rocketvault --config "$CFG" users create --new-username qa-peer --new-password qa-password123 --new-role user
```
Capture that command's `TOTP Secret: otpauth://...` line as `QA_OTPAUTH_URL`,
then grant the role and log in as `qa-peer` without disturbing admin's session:
```bash
rocketvault --config "$CFG" vault-access grant qa-peer --role "Key Vault Secrets Officer" --vault default
QA_TOTP_SECRET=$(echo "$QA_OTPAUTH_URL" | sed -n 's/.*secret=\([A-Z2-7]*\).*/\1/p')
QA_TOTP_CODE=$(ROCKETVAULT_TOTP_SECRET="$QA_TOTP_SECRET" go run scripts/totp_generator.go 2>&1 | grep -m1 -oP '(?<=--totp-code )\S+')
PEER_TOKEN=$(curl -s -X POST $BASE/users/login \
  -H "Content-Type: application/json" \
  -d "{\"username\":\"qa-peer\",\"password\":\"qa-password123\",\"totp_code\":\"$QA_TOTP_CODE\"}" \
  | jq -r .token)
```
Now prove membership visibility and the ownership gate in the same secret:
```bash
curl -s $BASE/secrets/$SECRET1_ID -H "Authorization: Bearer $PEER_TOKEN" | jq -r .value
curl -s -o /dev/null -w "%{http_code}\n" -X PUT $BASE/secrets/$SECRET1_ID \
  -H "Authorization: Bearer $PEER_TOKEN" -H "Content-Type: application/json" \
  -d '{"value":"s3cr3t-peer-edit"}'
curl -s $BASE/secrets/$SECRET1_ID/backup -X POST -H "Authorization: Bearer $PEER_TOKEN" | jq .
```
Expect: the `GET` returns admin's plaintext value (**membership visibility** —
`qa-peer` never created this secret and sees it anyway); the `PUT` returns
`200` (editing is membership-gated, not ownership-gated, so it succeeds); the
`backup` returns `403`:
`{"id":"Insufficient permissions: backup_secret","message":"Insufficient permissions: backup_secret","detailed_error":"","status_code":403,"request_id":"req-xxxxxxxx"}`
— even though `Key Vault Secrets Officer` grants `ActionSecretsBackup`, so the
route-level role check already passed; it's the ownership check inside
`BackupSecret` alone that stops this.

**11. Gotcha #4, continued — restore collision: try to restore `$BLOB` while
the original still exists:**
```bash
curl -s -X POST $BASE/secrets/restore -H "Authorization: Bearer $ADMIN_TOKEN" -H "Content-Type: application/json" -d "{\"blob\":\"$BLOB\"}" | jq .
```
Expect `500`, with `detailed_error` containing
`failed to insert secret: UNIQUE constraint failed: secrets.vault_id, secrets.name`
— same index as gotchas #3/#8, tripped by the same name colliding with the
still-live original.

**12. Purge the original, then have the peer — not the original owner —
restore the same blob:**
```bash
curl -s -X DELETE $BASE/secrets/$SECRET1_ID -H "Authorization: Bearer $ADMIN_TOKEN"
curl -s $BASE/deleted/secrets -H "Authorization: Bearer $ADMIN_TOKEN" | jq .
curl -s -X DELETE $BASE/deleted/secrets/$SECRET1_ID/purge -H "Authorization: Bearer $ADMIN_TOKEN"
curl -s -X POST $BASE/secrets/restore -H "Authorization: Bearer $PEER_TOKEN" -H "Content-Type: application/json" -d "{\"blob\":\"$BLOB\"}" | jq .
```
Expect the soft-delete and purge to each return `200`, and the restore —
this time by `qa-peer`, who never owned the original — to succeed with
`{"status":"OK"}`. `RestoreSecret` doesn't check who the blob's data used to
belong to; it just re-inserts under the caller's own user ID, so nothing
stopped `qa-peer` from doing this using a blob they were never authorized to
create in the first place.

**13. Confirm the restore reassigned ownership to the restoring caller, not
the original creator.** Find the new secret (same name, new ID, since the old
ID was purged in step 12):
```bash
NEW_ID=$(curl -s $BASE/secrets -H "Authorization: Bearer $ADMIN_TOKEN" | jq -r '.secrets[] | select(.name=="db-pass") | .id')
curl -s -o /dev/null -w "%{http_code}\n" -X POST $BASE/secrets/$NEW_ID/backup -H "Authorization: Bearer $PEER_TOKEN"
curl -s -o /dev/null -w "%{http_code}\n" -X POST $BASE/secrets/$NEW_ID/backup -H "Authorization: Bearer $ADMIN_TOKEN"
```
Expect `200` for `qa-peer` (now the owner, by virtue of having restored it)
and `403` for `admin` (the original creator, who created a version of this
secret that no longer exists under this ID) — direct proof that restore
assigns ownership to whoever calls it, independent of the blob's origin.

##### Cleanup

```bash
curl -s -X DELETE $BASE/secrets/$NEW_ID -H "Authorization: Bearer $PEER_TOKEN"
curl -s -X DELETE $BASE/deleted/secrets/$NEW_ID/purge -H "Authorization: Bearer $PEER_TOKEN"
curl -s -X DELETE $BASE/secrets/$SECRET2_ID -H "Authorization: Bearer $ADMIN_TOKEN"   # smtp-key was already soft-deleted in step 8; this is a no-op if so
curl -s -X DELETE $BASE/deleted/secrets/$SECRET2_ID/purge -H "Authorization: Bearer $ADMIN_TOKEN"
rocketvault --config "$CFG" users logout
rm -f /tmp/secrets-export.json
```

---

## 8. Keys

Same flat-vs-vault-scoped duplication note as §7 applies here.

### 8.1 RSA / ECDSA (software or HSM depending on `hsm.enabled`)

- [ ] `rocketvault keys create --name mykey --type RSA --bits 2048 ...` → `201`.
- [ ] `rocketvault keys create --name eckey --type ECDSA --curve P-256 --tags prod,secure ...`
- [ ] List / get / update / soft-delete.
- [ ] Rotate: `POST /api/v1/keys/{id}/rotate` / `rocketvault keys rotate <id>` →
      new key version generated; `GET /api/v1/keys/{id}/versions` shows both.
- [ ] `GET /api/v1/keys/{id}/versions/{version}` → that version's metadata **plus
      its public JWK components** (`n`/`e` for RSA, `x`/`y`/`crv` for EC), matching
      Azure's `GET /keys/{name}/{version}`. This route returned bookkeeping fields
      only until 2026-08-20 (§ B34) — confirm the components are actually populated
      and not empty strings, which is the exact shape of the bug that was fixed.
      `GET /api/v1/keys` stays JWK-free by design; don't treat that as a defect.
- [ ] Crypto ops round-trips. Note the CLI covers only four of the six operations —
      `keys sign`, `verify`, `wrap`, `unwrap` exist; **there is no `keys encrypt` or
      `keys decrypt` command**, so encrypt/decrypt must be exercised over REST
      (`POST /api/v1/keys/{id}/encrypt` and `/decrypt`). Don't file the missing
      commands as a bug without checking the roadmap first.
      - `sign` → `verify` (signature validates; tampered payload fails verify).
      - `encrypt` → `decrypt`, over REST (round-trips to original plaintext; wrong
        key fails).
      - `wrap` → `unwrap`:
        ```bash
        rocketvault keys wrap --key-id <uuid> --key-material <base64> ...
        rocketvault keys unwrap --key-id <uuid> --wrapped-key <base64-from-above> ...
        ```
- [ ] **Version addressability across a rotation** (fixed 2026-08-19, `docs/known-bugs.md`
      § B26 — before that fix, `RotateKey` overwrote `keys.value` in place and every
      pre-rotation ciphertext and signature became permanently unusable). This is the
      check that proves the fix, so do it in this order:
      1. Create an RSA key. `sign` a known payload and `wrap` known key material
         against it. Note the key is at version 1.
      2. Rotate the key.
      3. `verify` the step-1 signature **with `--version 1`**, and `unwrap` the
         step-1 blob the same way → both must succeed.
      4. Repeat step 3 with the flag omitted (which sends `0`, meaning "current") →
         both must now **fail**, because the current version is different material.
         A pass here would mean version resolution isn't happening at all.
      Exactly four CLI commands take the flag (added 2026-08-20, each bound to its
      own viper key — `sign-version`, `verify-version`, `wrap-version`,
      `unwrap-version`):
      ```bash
      rocketvault keys verify --key-id <uuid> --version 1 ...
      rocketvault keys unwrap --key-id <uuid> --version 1 --wrapped-key <base64> ...
      ```
      All **six** service operations accept an optional `version` field over REST,
      so repeat the same before/after-rotation check for `encrypt`/`decrypt` there —
      that pair has no CLI command, and it is the operation where the original bug
      did the most damage (unrecoverable ciphertext).
- [ ] **Import an externally-generated key (JWK)** — shipped 2026-08-25, closing the
      last `❌` on the parity doc's §2 key-operations table. An imported key must be
      stored exactly as a generated one is: encrypted PEM on a software instance, a
      non-extractable PKCS#11 object on an HSM-backed one.
      ```bash
      rocketvault keys import --name imported-rsa --jwk-file /tmp/priv.jwk --vault default
      # or inline:  --jwk '{"kty":"RSA",...}'
      # HTTP equivalent:
      #   POST /api/v1/keys/import  {"name":"imported-rsa","jwk":{...},"tags":[...]}
      ```
      - [ ] An RSA **private-key** JWK and an ECDSA private-key JWK both import → `201`.
      - [ ] A **public-only** JWK is rejected (`internal/signing.ParseJWK`) — confirm
            a clean 400, not a 500 and not a silently-stored useless key.
      - [ ] The imported key is fully usable: `sign`/`verify` via the CLI, and
            `encrypt`/`decrypt` over REST for RSA, all round-trip against it, and it
            appears in `keys list` and `GET /keys/{id}/versions` like any generated key.
      - [ ] `GET /keys/{id}` on the imported key emits **only** public JWK components —
            no private material, matching the "keys never leave the vault" rule that
            the parity doc's EXPORT-blocked row asserts.
      - [ ] Optional fields behave: `--tags`, `--purge-protection`, and the REST-only
            `enabled` / `expires_at` / `not_before` (omitting `purge_protection`
            leaves the stored default alone rather than forcing `false`).
      - [ ] **Two independent authorization gates, both required.** Over HTTP,
            `PolicyMiddleware` requires the `ActionKeysImport` data action, granted
            only by `Key Vault Crypto Officer` and `Key Vault Administrator` — confirm
            a `Key Vault Crypto User` (which has no import action) gets `403`. The CLI
            additionally requires the caller's *account* role to be global `admin` or
            `crypto_manager` **on top of** `vaultcli.RequireDataAction`
            (`cmd/keys/import.go`) — so confirm a non-admin who holds Crypto Officer
            in the vault succeeds over HTTP but is refused by the CLI with
            `forbidden: requires admin or crypto_manager role`. That asymmetry is
            deliberate; verify it rather than filing it as a bug.
- [ ] Rotation policy: `PUT .../rotationpolicy` with all four required fields
      `{"rotate_after_days":90,"notify_before_expiry_days":30,"expiry_days":365,"enabled":true}`
      → `201`/`200`. Repeat `PUT` with the same key → same `id` returned (upsert,
      not duplicate). `GET`/`DELETE` on a key with **no** policy set → `404`.
      Confirm only `Key Vault Crypto Officer`/`Key Vault Administrator` can manage
      it (see §6's narrow-role check).
- [ ] Backup/restore item, same pattern as secrets.
- [ ] Soft-delete/restore/purge, vault-scoped — same pattern as §7, using
      `/api/v1/vaults/{name}/deleted/keys`.

#### Worked example: importing a JWK, and the two things that surprise you

> **Concept: import is a data-plane operation, so being an admin buys you
> nothing.** Vault data-plane routes are deny-by-default with no admin bypass:
> `PolicyMiddleware` grants only through `RoleAssignmentService.HasDataAction`,
> which consults `model.azureRoleDataActions`. The global `admin` account role
> is not in that map, so a freshly bootstrapped admin — with every global
> privilege there is — gets `403` on `POST /keys/import` until someone grants
> it `Key Vault Crypto Officer` **in that specific vault**. This is the single
> most common "why is this broken" moment on a fresh instance, and it is
> working as designed.

All output below was captured live on 2026-09-03 against a scratch instance
with `hsm.enabled: false`.

#### Prerequisites

- Scratch config/DB, running server, admin bootstrapped, `$TOKEN` and `$BASE`
  as in §5's webhook example.
- Python with `cryptography` installed, to mint a test JWK. Generate one:

```bash
python3 - <<'PY' > /tmp/priv.jwk
import base64, json
from cryptography.hazmat.primitives.asymmetric import rsa
def b64u(i): return base64.urlsafe_b64encode(
    i.to_bytes((i.bit_length()+7)//8,'big')).decode().rstrip('=')
k = rsa.generate_private_key(public_exponent=65537, key_size=2048)
n = k.private_numbers(); p = n.public_numbers
print(json.dumps({"kty":"RSA","n":b64u(p.n),"e":b64u(p.e),"d":b64u(n.d),
  "p":b64u(n.p),"q":b64u(n.q),"dp":b64u(n.dmp1),"dq":b64u(n.dmq1),"qi":b64u(n.iqmp)}))
PY
```

#### The 3 gotchas this example surfaces

1. **A global admin is refused until it holds a vault role.** See the concept
   note. The message is `Forbidden: no role assignment grants this operation in
   this vault`.
2. **Re-importing an existing name returns `500`, not `409`, and leaks the SQL
   constraint.** A name collision is a client error; this reports it as a server
   fault and exposes `UNIQUE constraint failed: keys.vault_id, keys.name` plus
   the schema. Reproduced live — file it under `docs/known-bugs.md` if it is
   not already there.
3. **`sign` returns the signature under `value`, and `verify` also takes a
   `value` — but they mean different things.** On sign, `value` is the
   signature it produced. On verify, `value` is the *payload* and the signature
   goes in `signature`. Sending the sign response's `value` as verify's `value`
   silently compares the wrong bytes.

#### Walkthrough

**1. Try the import as a fresh admin — expect a refusal.**

```bash
jq -n --argjson jwk "$(cat /tmp/priv.jwk)" \
  '{name:"imported-rsa", jwk:$jwk, tags:["migrated"]}' > /tmp/import.json
curl -s -X POST $BASE/keys/import -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' --data @/tmp/import.json
```
```
Forbidden: no role assignment grants this operation in this vault      [403]
```

**2. Grant the role, in that vault specifically.**

```bash
curl -s -X POST $BASE/vaults/default/role-assignments -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"principal":"admin","role":"Key Vault Crypto Officer"}'
```
```json
{"id":"0db106be-...","principal_username":"admin","role":"Key Vault Crypto Officer",
 "vault_name":"default","created_at":"2026-09-03T16:16:58Z"}
```

**3. Re-run the import — now `201`, and note what comes back.**

```json
{"id":"6bd787b3-7ac6-48e5-b083-67a2200e10e6","name":"imported-rsa","type":"RSA",
 "bits":2048,"enabled":true,"tags":["migrated"],
 "n":"shLYyfX4l_vlXwgZU-5vVWeZm5odUNWRu7vDI8JsXQZ7...","e":"AQAB"}
```

Only `n` and `e` — the public components. No `d`, `p`, `q`, `dp`, `dq`, `qi`.
That is the "keys never leave the vault" guarantee holding for an imported key,
which is the property worth actually checking on an import path.

**4. A public-only JWK is refused cleanly.** Strip everything but `kty`, `n`,
`e` and POST it:

```json
{"message":"Invalid or missing parameter: invalid jwk: jwk contains no private key material","status_code":400}
```

**5. Gotcha #2 — re-import the same name.**

```json
{"detailed_error":"failed to store imported key: key \"imported-rsa\": a resource with this name already exists in this vault: UNIQUE constraint failed: keys.vault_id, keys.name",
 "id":"Internal server error","status_code":500}
```

A `500` for what is plainly a client error, with the database constraint and
column names in the body. Worth noting whether your deployment returns
`detailed_error` to unauthenticated or lower-privileged callers.

**6. Sign and verify — mind gotcha #3.**

```bash
KID=6bd787b3-7ac6-48e5-b083-67a2200e10e6
PAY=$(printf 'hello provisioning' | base64 -w0)
SIG=$(curl -s -X POST $BASE/keys/$KID/sign -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' -d "{\"value\":\"$PAY\",\"algorithm\":\"RS256\"}" \
  | jq -r .value)          # <-- the signature arrives as "value"

curl -s -X POST $BASE/keys/$KID/verify -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d "{\"value\":\"$PAY\",\"signature\":\"$SIG\",\"algorithm\":\"RS256\"}"
```
```json
{"key_id":"6bd787b3-...","algorithm":"RS256","valid":true,"version":1}
```

Flip one character of the payload and re-verify:

```json
{"key_id":"6bd787b3-...","algorithm":"RS256","valid":false,"version":1}
```

Note `valid:false` still returns `200` — a failed verification is a successful
API call. Do not test this by checking the status code.

**7. Confirm no private material is reachable.**

```bash
curl -s $BASE/keys/$KID -H "Authorization: Bearer $TOKEN" | jq 'keys'
```
```json
["bits","created_at","e","enabled","id","n","name","revoked","tags","type","user_id"]
```

#### Teardown

```bash
curl -s -o /dev/null -X DELETE $BASE/keys/$KID -H "Authorization: Bearer $TOKEN"
curl -s -o /dev/null -X DELETE $BASE/vaults/default/deleted/keys/$KID/purge -H "Authorization: Bearer $TOKEN"
```

#### Worked example: RSA/ECDSA key creation, and what changes when HSM is enabled

> **Concept: two independent axes, and one option that's real but invisible
> in the CLI's own help text.** Creating a key varies along two things that
> combine, not three separate stories: **key type** (RSA vs. ECDSA, plus a
> fourth type-like value, `ES256K`, that's only reachable *through* ECDSA —
> see below) and **backend** (software vs. HSM/PKCS#11). The backend is a
> single global switch, not a per-key or per-request choice: one
> `crypto.KeyProvider` is built once when the service container starts
> (`internal/container/service_container.go:516-533`) and every key created
> for the rest of that process's life goes through it — there is no flag on
> `keys create` to request the other backend on a running instance, only a
> config edit and a restart. The single most surprising thing this example
> surfaces: `--curve P-256K` (secp256k1, the Bitcoin/Ethereum curve) is fully
> implemented and reachable **today**, in software mode, even though neither
> `--curve`'s nor `--type`'s help text mentions it, and
> `docs/roadmap/azure-parity-and-beyond.md`'s line about P-256K reads —
> easy to misread — like the whole feature is unimplemented, when it's
> actually only the **HSM** side of it that's an open gap.

##### Prerequisites

- Server running against a scratch config/DB (see **§0 Environment Setup**
  above — don't point this at a shared dev database).
- `rocketvault` CLI built and on your `PATH` (`go build -o rocketvault .`
  from repo root, or substitute `go run main.go` for every `rocketvault ...`
  command below).
- `curl`, [`jq`](https://jqlang.org/), and `sqlite3` installed.
- An admin user already created, with `ROCKETVAULT_TOTP_SECRET` exported in
  your shell (see **§2 Admin Bootstrap** above and §3.5's Prerequisites for
  the exact `export` one-liner — not repeated here).
- For Part 2 only: SoftHSM2 installed, with its shared library present
  (typically `/usr/lib/softhsm/libsofthsm2.so` on Linux). §8.2's checklist
  above already documents the token-init command; Part 2 below reuses it
  verbatim rather than restating it.

##### The 8 gotchas this example is built to surface

1. **`--bits` help text says "2048 or 4096" — 3072 is silently also valid,
   and an invalid size is rejected only after a full authenticated round
   trip, not by flag parsing.** The flag's help string
   (`cmd/keys/create.go:180`) omits 3072; the actual check
   (`internal/services/keys/key_service.go:193`) accepts 2048, 3072, and
   4096. Both the HTTP handler's inline check (`api/keys.go:331`) and the
   shared `ValidateKeyCreate` rule (`internal/validation/key_validation.go:39`)
   agree with the service, not the CLI help text — the help text is the only
   place that's wrong. An invalid value like `--bits 1024` (or an explicit
   `--bits 0`, which overrides Cobra's 2048 default rather than falling back
   to it) comes back as a service-layer error *after* login, TOTP, and audit
   logging have already run — never caught at argument-parsing time. HTTP has
   no default at all for a missing `bits`: `ValidateKeyCreate` requires it
   before the handler's own `if req.Bits == 0 { req.Bits = 2048 }` fallback
   (`api/keys.go:331-338`) is ever reached, so that fallback is dead code —
   a request must always specify a valid `bits` value explicitly.
2. **Duplicate key names are rejected only after the expensive part (RSA key
   generation) has already run, with a raw driver error, not a friendly
   one.** The unique constraint is `(vault_id, name)`
   (`internal/db/db.go:1024`); neither the CLI nor `createKey` pre-checks for
   an existing name, so the insert fails and whatever the driver returns
   surfaces unwrapped. On SQLite that's `UNIQUE constraint failed:
   keys.vault_id, keys.name` threaded up through three `%w` layers — on
   Postgres this reads completely differently, so don't expect this exact
   string universally, only the shape (unwrapped driver error, not a clean
   message).
3. **The CLI validates almost nothing about a key's name — the HTTP API
   enforces a real pattern and length limit.** `ValidateKeyCreate`'s
   `KeyNameRule` requires `^[a-zA-Z][a-zA-Z0-9-]{0,126}$`
   (`internal/validation/common.go:16`) and runs on every `POST /keys`
   request; `rocketvault keys create` never calls this validator at all —
   its only client-side check is an empty-string test on `name`/`type`
   (`cmd/keys/create.go:70-73`). A key created through the CLI alone can
   already violate a constraint the HTTP API would reject at creation time,
   and would only surface that mismatch later if ever round-tripped through
   an HTTP call that re-validates it (e.g. an update).
4. **`--curve P-256K` works today, and it changes the stored/returned `type`
   from `"ECDSA"` to `"ES256K"` — a value the CLI's own `--type` flag refuses
   to accept directly.** `--curve`'s help text
   (`cmd/keys/create.go:170`) lists only `P-256, P-384, P-521`; the real
   check, `internal/services/keys/key_service.go:283`, also accepts
   `P-256K` (secp256k1, generated via `github.com/decred/dcrd/dcrec/secp256k1/v4`
   since Go's stdlib has no secp256k1 curve — `internal/crypto/key_crypto.go:56`).
   The key that comes back reports `"Type": "ES256K"`, not `"ECDSA"`
   (`key_service.go:306-309`) — any tooling asserting `type == "ECDSA"` will
   silently miss these keys. There is no way to request this type directly:
   `--type ES256K` is rejected before curve is even consulted
   (`cmd/keys/create.go:78` only accepts `RSA`/`ECDSA`) — `ES256K` is
   reachable only via `--type ECDSA --curve P-256K`.
5. **Software vs. HSM: the `keys.value` column holds either an encrypted PEM
   blob or a 43-byte `pkcs11:<uuid>` pointer — nothing in between, and no
   separate column marks which.** Both `CreateRSAKey` and `CreateECDSAKey`
   (`key_service.go:205-216`, `:295-304`) branch on `isPKCS11Handle`
   (`key_service.go:853-859`, a syntactic check — 36 chars, dashes at UUID
   positions) rather than a stored type tag: a software handle gets
   AES-GCM-encrypted via `common.EncryptSecret` before storage; a PKCS#11
   handle gets stored as `"pkcs11:" + handle` as-is. The consuming side,
   `resolveKeyHandle` (`internal/services/keys/crypto_service.go:176-191`),
   does the inverse by checking the stored `"pkcs11:"` prefix, not by
   re-deriving anything from the key's type.
6. **The REST API surfaces the backend as a type suffix, matching Azure's
   convention — `RSA` becomes `RSA-HSM`, `ECDSA` becomes `EC-HSM` — but only
   on that path.** `buildKeyResponse` (`api/keys.go:172-179`) appends
   `-HSM` when `key.Value` carries the `"pkcs11:"` prefix. The CLI's own
   `keys list --output json` for the identical key still prints plain
   `"RSA"`/`"ECDSA"` — the suffix is added only by the HTTP handler, not
   stored on the record itself.
7. **P-256K support genuinely diverges by backend: works in software, is a
   hard, explicit rejection on PKCS#11 — not a silent fallback, not a
   panic.** `internal/crypto/pkcs11_provider.go:166-179`'s `ecOID` map (used
   by `GenerateECDSAKey`) has entries only for `P-256`, `P-384`, `P-521` —
   `P-256K` isn't in it, so the PKCS#11 path returns a clean
   `ErrUnsupportedCurve`. `key_service.go`'s own curve validation is
   backend-agnostic (it accepts all four curve values before ever calling
   the provider), so this rejection happens one layer down, only when HSM is
   actually on. Already tracked as a deferred gap in
   `docs/roadmap/azure-parity-and-beyond.md` — this walkthrough
   reproduces it directly against a real SoftHSM2 token.
8. **Operational trap (source-only — not reproduced live in this pass): a
   software-created P-256K key becomes permanently un-rotatable if its
   instance is later switched to `hsm.enabled: true`.** `RotateKey`'s
   `model.KeyTypeES256K` case (`key_service.go:744-751`) always calls
   `s.keyProvider.GenerateECDSAKey(ctx, "P-256K")` against whichever provider
   is currently configured, with no per-curve fallback — so it hits gotcha
   7's `ErrUnsupportedCurve` every time once HSM is on, including from an
   automated rotation-policy scheduler, until `hsm.enabled` is turned back
   off.

##### Setup

```bash
BASE=http://localhost:8774/api/v1     # adjust host:port to your scratch config's server.listen_addr
TOTP_CODE=$(go run scripts/totp_generator.go -secret="$ROCKETVAULT_TOTP_SECRET" 2>&1 | grep -m1 -oP '(?<=--totp-code )\S+')
rocketvault users login --username admin --password admin123 --totp-code "$TOTP_CODE"

ADMIN_TOKEN=$(curl -s -X POST $BASE/users/login \
  -H "Content-Type: application/json" \
  -d "{\"username\":\"admin\",\"password\":\"admin123\",\"totp_code\":\"$TOTP_CODE\"}" \
  | jq -r .token)

rocketvault vault-access grant admin --role "Key Vault Crypto Officer" --vault default
```
The `login` call caches a session so the CLI commands below don't need
credential flags; `$ADMIN_TOKEN` is needed separately for the `curl` calls,
since HTTP doesn't read the CLI's session cache. The `vault-access grant` is
the same "fresh admin has zero vault data-plane access anywhere" self-grant
already fully documented in §3.5's worked example — skipping it produces
`forbidden: no role grants Microsoft.KeyVault/vaults/keys/create/action in
this vault` the moment step 1 below runs.

---

##### Part 1 — Software path (`hsm.enabled: false`, the scratch config's default)

**1. Create an RSA key with an undocumented-but-valid bit size (gotcha 1):**
```bash
rocketvault keys create --name rsa3072 --type RSA --bits 3072
```
Expect success despite the flag help never mentioning 3072:
```
ID: 5ac2f492-ed33-45ba-a6e2-80934ce190ef  Name: rsa3072  Type: RSA
```

**2. Negative — an invalid bit size, rejected late, not by flag parsing
(gotcha 1 continued):**
```bash
rocketvault keys create --name rsa-bad --type RSA --bits 1024
```
Expect:
```
Error: failed to create key: invalid RSA key size: must be 2048, 3072, or 4096
```
And confirm HTTP's side of the same gotcha — a request with no `bits` field
at all:
```bash
curl -s -X POST $BASE/keys -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" -d '{"name":"rsa-nobits","type":"RSA"}' | jq .
```
Expect `400`, not a silently-defaulted 2048 key:
```json
{"message":"Invalid or missing parameter: Bits: cannot be blank.","status_code":400}
```

**3. Duplicate name — rejected only after key generation already ran
(gotcha 2):**
```bash
rocketvault keys create --name rsa2048dup --type RSA --bits 2048
rocketvault keys create --name rsa2048dup --type RSA --bits 2048
```
Expect the second call to fail with the raw driver error (SQLite shown; a
Postgres backend reads differently — see gotcha 2):
```
Error: failed to create key: failed to store RSA key: failed to insert key: UNIQUE constraint failed: keys.vault_id, keys.name
```

**4. CLI accepts a name the HTTP API would reject outright (gotcha 3):**
```bash
rocketvault keys create --name 1_bad_name --type RSA --bits 2048
```
Expect success — starts with a digit and contains an underscore, both
illegal per the HTTP-side pattern, yet the CLI has no pattern check at all:
```
ID: 82f976d0-d6bd-4a56-ad64-0f6c57614972  Name: 1_bad_name  Type: RSA
```
The identical shape via HTTP:
```bash
curl -s -X POST $BASE/keys -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name":"1_bad_name2","type":"RSA","bits":2048}' | jq .
```
Expect `400`:
```json
{"message":"Invalid or missing parameter: Name: must contain only alphanumeric characters and hyphens, and start with a letter.","status_code":400}
```

**5. `--curve P-256K` — reachable, undocumented, and it changes the reported
type (gotcha 4):**
```bash
rocketvault keys create --name eckey-p256k --type ECDSA --curve P-256K --output json
```
Expect:
```json
[
  {
    "Created": "2026-08-18T09:36:08+05:30",
    "ID": "16b1c5c9-710d-4f20-89c5-1fc6d475c7db",
    "Name": "eckey-p256k",
    "Tags": "",
    "Type": "ES256K"
  }
]
```

**6. Confirm the type divergence sits alongside ordinary ECDSA keys, not in
place of them:**
```bash
rocketvault keys create --name eckey-p256 --type ECDSA --curve P-256
rocketvault keys list
```
Expect only the P-256K row to show `ES256K`, every other curve to show
plain `ECDSA`:
```
ID                                    Name         Type    Revoked  Tags  Created
------------------------------------  -----------  ------  -------  ----  -------------------------
16b1c5c9-710d-4f20-89c5-1fc6d475c7db  eckey-p256k  ES256K  false          2026-08-18T09:36:08+05:30
6f59781d-502b-4be2-9035-8ee3fe124be5  eckey-p256   ECDSA   false          2026-08-18T09:35:37+05:30
```

**7. Negative — `--type ES256K` is not a door in on its own (gotcha 4
continued):**
```bash
rocketvault keys create --name eckey-typees256k --type ES256K --curve P-256K
```
Expect:
```
Error: invalid key type: must be RSA or ECDSA
```
`ES256K` only exists as an outcome of `--type ECDSA --curve P-256K` — there
is no `--type` value that produces it directly.

---

##### Part 2 — Flip the same instance to HSM (`hsm.enabled: true`, SoftHSM2)

Because the backend is a single process-wide switch (see the Concept box
above), this reuses the same scratch config and database from Part 1 rather
than standing up a second instance — the keys created in steps 1-7 stay
exactly as they are; only new creates from here on go through PKCS#11.

**8. Initialize a SoftHSM2 token**, the same command §8.2's checklist above
already documents:
```bash
softhsm2-util --init-token --slot 0 --label rocketvault --pin 1234 --so-pin 0000
```

**9. Stop the server, edit the scratch config, restart:**
```bash
# Ctrl-C the running server, then edit the scratch config:
#   hsm.enabled: true
#   hsm.lib_path: /usr/lib/softhsm/libsofthsm2.so
#   hsm.token_label: rocketvault
#   hsm.pin: "1234"
#   hsm.slot_id: 0
/tmp/rocketvault-bin --config /tmp/rv-test.yaml serve --listen :8774
```
Wait for `"PKCS#11 HSM key provider initialised"` in the log before
continuing — a wrong `lib_path` or missing token panics instead of failing
cleanly (already covered by §0's own worked example; not repeated here).

**10. Create an RSA key on the HSM path, and look at what's actually stored
(gotcha 5):**
```bash
rocketvault keys create --name hsm-rsa-key --type RSA --bits 2048
sqlite3 /tmp/rv-test.db "SELECT name, type, length(value), value FROM keys WHERE name='hsm-rsa-key';"
```
Expect a 43-byte pointer, not key material:
```
hsm-rsa-key|RSA|43|pkcs11:6cfcf1e1-686a-49ff-92d8-35239dfca989
```
Compare against the software-path key from step 1, same schema, same query:
```bash
sqlite3 /tmp/rv-test.db "SELECT name, type, length(value) FROM keys WHERE name='rsa3072';"
```
Expect a much larger encrypted blob:
```
rsa3072|RSA|2276
```

**11. The REST API surfaces the divergence as a type suffix (gotcha 6):**
```bash
KEY_ID=$(rocketvault keys list --output json | jq -r '.[] | select(.Name=="hsm-rsa-key") | .ID')
curl -s $BASE/keys/$KEY_ID -H "Authorization: Bearer $ADMIN_TOKEN" | jq .
```
Expect `"type": "RSA-HSM"`:
```json
{
  "id": "90cb5dc6-2456-4c33-8905-a08a558f94d7",
  "name": "hsm-rsa-key",
  "type": "RSA-HSM",
  "user_id": "264718ab-d1bc-4ab0-84e7-03e299ddc21c",
  "revoked": false,
  "created_at": "2026-08-18T09:35:19.592519746+05:30",
  "tags": null,
  "enabled": true,
  "bits": 2048
}
```
`rocketvault keys list --output json` for this same key still prints plain
`"RSA"` — the `-HSM` suffix is an HTTP-response-only convention, not a
stored attribute.

**12. P-256K support itself diverges by backend — same curve, opposite
outcome (gotcha 7):**
```bash
rocketvault keys create --name hsm-ec-256k --type ECDSA --curve P-256K
```
Expect a clean, typed error, not a panic or silent fallback:
```
Error: failed to create key: failed to generate ECDSA key: curve not supported by PKCS#11 provider: P-256K
```
Contrast with step 5 above, where the identical `--curve P-256K` succeeded
against the software provider on this same instance before the restart.

**13. Operational trap, noted rather than reproduced (gotcha 8):** if
`eckey-p256k` from step 5 needed rotating now that this instance is
HSM-enabled, `rocketvault keys rotate <its-id>` would hit the exact same
`ErrUnsupportedCurve` from step 12 — rotation for an `ES256K` key always
regenerates via the currently-configured provider, with no fallback to
software. This wasn't exercised live in this pass; the code path (cited in
gotcha 8) is unambiguous enough that reproducing it adds a rotate call but
no new information.

##### Cleanup

```bash
# Delete + purge each key created above (capture each ID at creation time,
# or via `rocketvault keys list`), vault-scoped per the checklist above:
#   DELETE /api/v1/keys/{id}
#   DELETE /api/v1/vaults/default/deleted/keys/{id}/purge
# Then tear down the instance itself:
softhsm2-util --delete-token --token rocketvault
rm -f /tmp/rv-test.yaml /tmp/rv-test.db
rocketvault users logout
```

### 8.2 Symmetric AES (`OCT`) — HSM-only by design

- [ ] With `hsm.enabled: false`: `POST /keys` `{"name":"k","type":"OCT","bits":256}`
      → must fail with `crypto.ErrOctKeysRequireHSM` (this mirrors Azure — Managed
      HSM never allows symmetric key creation on Standard/Premium vaults). Confirm
      it's a clean error, not a panic or 500.
- [ ] With `hsm.enabled: true` and SoftHSM2 configured (`softhsm2-util --init-token
      --slot 0 --label rocketvault --pin 1234 --so-pin 0000`, matching the dev
      config's `hsm.token_label`/`hsm.pin`): create an `OCT` key with `bits` 128,
      192, and 256 → each `201`.
- [ ] `wrap`/`unwrap` against the OCT key uses real AES-KW — round-trip a piece of
      key material and confirm it decrypts back to the original bytes.
- [ ] Confirm `sign`/`verify` and `encrypt`/`decrypt` are **not** offered (or fail
      cleanly) for OCT keys — those are asymmetric-only operations; note actual
      behavior if it differs from expectation.

> **Concept: two different "OCT support" levels hiding under one key type.** Azure's own rule — symmetric keys only exist on Managed HSM, never software vaults — is enforced once, cleanly, at creation (`api/keys.go`'s `hsm.enabled` check, `crypto.ErrOctKeysRequireHSM`). Everything past that point is not uniformly implemented:
> - **Wrap/unwrap is real, HSM-native support.** The crypto path routes into `internal/crypto/pkcs11_provider.go`'s `wrapRawData` (`pkcs11_provider.go:349-373`), which imports the caller's plaintext as a temporary `CKO_SECRET_KEY` object and wraps it via `CKM_AES_KEY_WRAP` (RFC 3394 AES-KW) — a real HSM operation, not a stub.
> - **Sign/verify/encrypt/decrypt are not OCT-aware at all — a genuine unhandled gap, not an intentional restriction.** `internal/services/keys/crypto_service.go`'s Sign/Verify/Encrypt/Decrypt have no `key.Type == OCT` branch; they call straight into the same PKCS#11 lookup asymmetric keys use, which searches for a `CKO_PRIVATE_KEY`/`CKO_PUBLIC_KEY` object. An OCT key is a `CKO_SECRET_KEY`, so the lookup just fails, and `api/keys.go`'s error-mapping switch doesn't recognize the resulting error string, so it falls through to `SetInternalError` — an HTTP `500`, not a clean `400`. Don't mistake this for a deliberate "OCT keys can't sign" rejection when you hit it below; it's a missing type check.
> - **The CLI implements neither.** `cmd/keys/create.go:75-78` rejects any `--type` other than `RSA`/`ECDSA` outright, and `cmd/keys/wrap.go`/`unwrap.go` hardcode `Algorithm: "RSA-OAEP"` with no flag to override it. Every step below that touches an OCT key goes through `curl` against the HTTP API — this is the one worked example in this doc where the CLI simply cannot follow along.

#### Worked example: `payments-hsm` vault + `db-encryption-key` AES wrapping key

##### Prerequisites

- SoftHSM2 already initialized exactly as `docs/hsm-softhsm2-testing.md` describes: `softhsm2-util --init-token --slot 0 --label rocketvault --so-pin 0000 --pin 1234`, and your scratch `.rocketvault.yaml` has:
  ```yaml
  hsm:
    enabled: true
    lib_path: /usr/lib/softhsm/libsofthsm2.so
    token_label: rocketvault
    pin: "1234"
    slot_id: 0
  ```
  Note that doc's own "Supported algorithms" table predates AES-KW/OCT support and is stale — don't treat it as the source of truth for what's covered here, and don't fix it as part of this walkthrough.
- Server running against that config (**§0 Environment Setup**).
- Admin user bootstrapped, `ROCKETVAULT_TOTP_SECRET` exported — same as §3.5's prerequisites (**§2 Admin Bootstrap**).
- `curl` and `jq`.

##### The 8 gotchas this example is built to surface

All eight are real, verified-against-source behaviors — you will hit them if you don't know about them going in.

1. **No CLI path exists for OCT keys, at all** — not creation (`cmd/keys/create.go:75-78` rejects any `--type` besides `RSA`/`ECDSA`), not wrap/unwrap (`cmd/keys/wrap.go`/`unwrap.go` hardcode `Algorithm: "RSA-OAEP"`). Every OCT-specific command below uses `curl`, unlike §8.1's RSA/ECDSA walkthrough.
2. **The created key's `type` field is not `"OCT"`.** The response suffixes it with `-HSM` (`api/keys.go:176-184`'s generic `kty+"-HSM"` logic) — expect `"OCT-HSM"`. A filter scripted against `type == "OCT"` on the list endpoint will silently match nothing.
3. **`bits` is validated to an exact set, not "any positive integer."** Only 128/192/256 are accepted; anything else (including a plausible-looking 512) fails with `400` and both `id` and `message` equal to `"Invalid or missing parameter: bits: must be 128, 192, or 256"` (`api/keys.go:341-347,346`, `SetInvalidParam` prepends that fixed prefix — see `common/utils.go:57-67` for why `id`/`message` are always identical on this error family).
4. **AES-KW plaintext length is constrained, and the error surface for violating it isn't pinned down in this doc.** RFC 3394 requires the wrap input be a multiple of 8 bytes; a 15- or 17-byte value will fail. Pick 16-byte test material (`sixteen-bytes!!!`) to avoid this in the main path, and deliberately trigger it in step 4 below to record what you actually see.
5. **Wrap/unwrap algorithm-vs-key-size mismatches are rejected before the HSM is ever touched**, with a specific message: `"algorithm %q requires a %d-bit key, but key %s is %d-bit"` (`internal/services/keys/crypto_service.go:612-614,676-678`) — e.g. `A128KW` against a 256-bit key.
6. **`hsm.enabled: false` produces a specific message**, both `id` and `message` equal to `"Invalid or missing parameter: type: OCT key creation requires an HSM-backed key provider (hsm.enabled: true)"` (`api/keys.go:363-364`, same `SetInvalidParam` prefix as gotcha #3). Already covered by the plain checklist bullet above and not re-demonstrated in the steps below, since it needs a second, HSM-disabled server instance.
7. **Sign/verify/encrypt/decrypt against an OCT key are not gated anywhere — this is the gap the concept box above describes, made concrete.** Expect `500` (`SetInternalError`), not `400`, the first time you try it.
8. **The three crypto-adjacent Azure roles split create vs. use differently than their names suggest.** `Key Vault Crypto Officer` grants create + wrap/unwrap + sign/verify. `Key Vault Crypto User` grants wrap/unwrap but *not* create. `Key Vault Crypto Service Encryption User` is narrower still — read + wrap/unwrap only (`model/azure_roles.go`). Granting the wrong one and expecting `create` to work is a plausible mistake; step 6 below deliberately triggers it.

##### Setup

Vault creation, self-grant, and admin-token retrieval follow §3.5 steps 1-2 and 4 exactly — reuse that pattern rather than re-deriving it, substituting the vault name and the crypto-specific role:

```bash
BASE=http://localhost:8774/api/v1     # adjust host:port to your scratch config
TOTP_CODE=$(go run scripts/totp_generator.go -secret="$ROCKETVAULT_TOTP_SECRET" 2>&1 | grep -m1 -oP '(?<=--totp-code )\S+')

rocketvault users login --username admin --password admin123 --totp-code "$TOTP_CODE"
rocketvault vaults create payments-hsm
rocketvault vault-access grant admin --role "Key Vault Crypto Officer" --vault payments-hsm

ADMIN_TOKEN=$(curl -s -X POST $BASE/users/login \
  -H "Content-Type: application/json" \
  -d "{\"username\":\"admin\",\"password\":\"admin123\",\"totp_code\":\"$TOTP_CODE\"}" \
  | jq -r .token)
```
`Key Vault Crypto Officer`, not §3.5's `Key Vault Administrator` — this walkthrough is entirely about crypto operations (create + wrap/unwrap + sign), so grant the role that actually covers all three (gotcha #8) instead of the broadest management role.

---

**1. Negative check — invalid `bits` (gotcha #3):**
```bash
curl -s -X POST $BASE/vaults/payments-hsm/keys \
  -H "Authorization: Bearer $ADMIN_TOKEN" -H "Content-Type: application/json" \
  -d '{"name":"bad-bits-key","type":"OCT","bits":512}' | jq .
```
Expect `400`, with `id` and `message` both equal to
`"Invalid or missing parameter: bits: must be 128, 192, or 256"`
(`common.AppError`'s JSON shape: `{id, message, detailed_error, status_code}`, same family as §3.5 step 7's `SetPermissionError` example).

**2. Create the real key (gotcha #2):**
```bash
curl -s -X POST $BASE/vaults/payments-hsm/keys \
  -H "Authorization: Bearer $ADMIN_TOKEN" -H "Content-Type: application/json" \
  -d '{"name":"db-encryption-key","type":"OCT","bits":256}' | jq .
```
Expect `201` with `"type":"OCT-HSM"` — not `"OCT"`. Save the id:
```bash
KEY_ID=<id from the response above>
```

**3. Round-trip AES-KW wrap/unwrap** — the real HSM operation per the concept box:
```bash
PLAINTEXT_B64=$(printf 'sixteen-bytes!!!' | base64)

WRAPPED=$(curl -s -X POST $BASE/keys/$KEY_ID/wrap \
  -H "Authorization: Bearer $ADMIN_TOKEN" -H "Content-Type: application/json" \
  -d "{\"plaintext_key\":\"$PLAINTEXT_B64\",\"algorithm\":\"A256KW\"}" | jq -r .wrapped_key)

curl -s -X POST $BASE/keys/$KEY_ID/unwrap \
  -H "Authorization: Bearer $ADMIN_TOKEN" -H "Content-Type: application/json" \
  -d "{\"wrapped_key\":\"$WRAPPED\",\"algorithm\":\"A256KW\"}" | jq .
```
Expect the wrap call to return `200` with `{"wrapped_key":"<base64>","algorithm":"A256KW"}`, and the unwrap call's `plaintext_key` to equal `$PLAINTEXT_B64` exactly — verify programmatically:
```bash
GOT=$(curl -s -X POST $BASE/keys/$KEY_ID/unwrap \
  -H "Authorization: Bearer $ADMIN_TOKEN" -H "Content-Type: application/json" \
  -d "{\"wrapped_key\":\"$WRAPPED\",\"algorithm\":\"A256KW\"}" | jq -r .plaintext_key)
[ "$GOT" = "$PLAINTEXT_B64" ] && echo MATCH
```

**4. Negative check — non-multiple-of-8 plaintext (gotcha #4):**
```bash
BAD_PLAINTEXT_B64=$(printf 'fifteen-bytes!!' | base64)   # 15 bytes, not a multiple of 8
curl -s -o /dev/null -w "%{http_code}\n" -X POST $BASE/keys/$KEY_ID/wrap \
  -H "Authorization: Bearer $ADMIN_TOKEN" -H "Content-Type: application/json" \
  -d "{\"plaintext_key\":\"$BAD_PLAINTEXT_B64\",\"algorithm\":\"A256KW\"}"
```
Expect a failure — the exact status code and error string aren't pinned down here (it depends on how the PKCS#11-level `CKM_AES_KEY_WRAP` rejection gets mapped by `api/keys.go`'s error switch); confirm and record the real response.

**5. Negative check — algorithm/key-size mismatch, caught before the HSM (gotcha #5):**
```bash
curl -s -X POST $BASE/keys/$KEY_ID/wrap \
  -H "Authorization: Bearer $ADMIN_TOKEN" -H "Content-Type: application/json" \
  -d "{\"plaintext_key\":\"$PLAINTEXT_B64\",\"algorithm\":\"A128KW\"}" | jq .
```
Expect the message `algorithm "A128KW" requires a 128-bit key, but key $KEY_ID is 256-bit` — this is `crypto_service.go`'s own size check firing before any PKCS#11 call is made, not an HSM-level error.

**6. RBAC negative check — `Key Vault Crypto User` grants wrap/unwrap but not create (gotcha #8):**
```bash
OUT=$(rocketvault users create --new-username crypto-user --new-password cryptouser12345 --new-role user)
CU_ID=$(echo "$OUT" | grep -oP 'User ID: \K\S+')
CU_TOTP=$(echo "$OUT" | grep -oP 'TOTP Secret: \K\S+')
CU_CODE=$(go run scripts/totp_generator.go -secret="$CU_TOTP" 2>&1 | grep -m1 -oP '(?<=--totp-code )\S+')
CU_TOKEN=$(curl -s -X POST $BASE/users/login -H "Content-Type: application/json" \
  -d "{\"username\":\"crypto-user\",\"password\":\"cryptouser12345\",\"totp_code\":\"$CU_CODE\"}" | jq -r .token)

rocketvault vault-access grant crypto-user --role "Key Vault Crypto User" --vault payments-hsm

curl -s -o /dev/null -w "%{http_code}\n" -X POST $BASE/keys/$KEY_ID/wrap \
  -H "Authorization: Bearer $CU_TOKEN" -H "Content-Type: application/json" \
  -d "{\"plaintext_key\":\"$PLAINTEXT_B64\",\"algorithm\":\"A256KW\"}"
curl -s -o /dev/null -w "%{http_code}\n" -X POST $BASE/vaults/payments-hsm/keys \
  -H "Authorization: Bearer $CU_TOKEN" -H "Content-Type: application/json" \
  -d '{"name":"crypto-user-key","type":"OCT","bits":128}'
```
`rocketvault users create`'s output prints `TOTP Secret: <secret>` on its own line (`cmd/users/create.go:97`) — not an `otpauth://` URL like the bootstrap admin command — so the capture pattern above differs from **§2 Admin Bootstrap**'s on purpose. The CLI commands (`users create`, `vault-access grant`) run under admin's already-cached session from Setup; only the two `curl` calls below use `$CU_TOKEN`. Expect `200` for the wrap and `403` for the create — `Key Vault Crypto User` and `Key Vault Crypto Officer` sound like a hierarchy but grant genuinely different action sets (`model/azure_roles.go`).

**7. The main result — sign against an OCT key (gotcha #7, resolves the open question in the checklist bullet above):**
```bash
curl -s -X POST $BASE/keys/$KEY_ID/sign \
  -H "Authorization: Bearer $ADMIN_TOKEN" -H "Content-Type: application/json" \
  -d "{\"value\":\"$(printf test | base64)\",\"algorithm\":\"RS256\"}" | jq .
```
(Request body is `SignKeyRequest{Value, Algorithm}` — `Value` is base64-encoded data to sign, `api/keys.go:117-120`.) Expect `500`, not a clean `400` — `SetInternalError`, with the wrapped PKCS#11 lookup failure (`"signing failed: pkcs11: private key not found for label ..."`) surfacing in the `detailed_error` field. Repeat against `/encrypt` if you want to confirm the same shape there — it goes through the equivalent public-key lookup and fails the same way. This is a real gap: neither the crypto service's methods nor `api/keys.go`'s error mapping have an OCT-specific branch, so the failure looks like an internal-server fault rather than a deliberate "operation not supported for this key type" rejection. Worth flagging if you hit it in the wild — this is the opposite of §3.5's OAuth2-rotation gotcha, which documents *intentional* behavior; this one is an unhandled case.

##### Cleanup

```bash
curl -s -X DELETE $BASE/keys/$KEY_ID -H "Authorization: Bearer $ADMIN_TOKEN"
rocketvault users delete "$CU_ID"
rocketvault vaults delete payments-hsm        # soft-delete
rocketvault vaults purge payments-hsm         # if you want it fully gone
```

---

## 9. Certificates

Same flat-vs-vault-scoped duplication as §7/§8.

- [ ] Create a key first (§8), then:
      ```bash
      rocketvault certificate create --name mycert --key-id <key-id> \
        --validity-days 365 --tags prod,secure ...
      ```
- [ ] Self-signed vs. CA-signed: repeat with `--ca-cert-id <existing-cert-id>` →
      confirm the resulting cert's issuer chain reflects the CA cert, not self-signed.
- [ ] List / get / update / soft-delete.
- [ ] Renew: `rocketvault certificate renew <cert-id> --validity-days 365` →
      new version/expiry; confirm old cert's key material is untouched if renewal
      reuses the same key vs. rotates it (check actual behavior).
- [ ] Policy: `GET/PUT/DELETE .../policy` — confirm upsert semantics like key
      rotation policy.
- [ ] Backup/restore item.
- [ ] Soft-delete/restore/purge, vault-scoped — `/api/v1/vaults/{name}/deleted/certificates`.
- [ ] **Auto-renewal**: if a cert has `--auto-renew` and `--renewal-days` set and
      you can fast-forward its expiry (e.g. create one with a very short
      `--validity-days` in a scratch environment), confirm the renewal scheduler
      actually renews it near expiry rather than only documenting the flag.

> **Concept: certificate writes are gated twice, and the two gates don't
> always agree.** Unlike secrets/keys (§7/§8), whose CLI commands only ever
> run the real per-vault `RequireDataAction` check, four of `certificate`'s
> six subcommands — `create`, `update`, `delete`, `renew` — run a **second,
> older check first**: a flat global-role gate,
> `common.HasRequiredRole(claims.Role, model.RoleAdmin,
> model.RoleCertificateManager)` (`cmd/certificates/create.go:49-51`, the
> same pattern repeated in `delete.go:32`, `update.go:35`, `renew.go:38-40`),
> that predates the per-vault Azure-role system and was apparently never
> removed once the real check (`vaultcli.RequireDataAction(ctx, cmd,
> serviceContainer, claims.UserID, model.ActionCertificatesCreate,
> model.OpCreate)`, `create.go:87`) landed. `get`/`list` carry no such legacy
> gate — only the real check (`get.go:57`, `list.go:47`). The practical
> effect: a user holding only a real per-vault role like `Key Vault
> Certificates Officer` — which fully satisfies `RequireDataAction` on its
> own — is still rejected outright by the CLI on create/update/delete/renew,
> with the exact string `"forbidden: requires admin or certificate_manager
> role"`, unless they *also* hold the legacy global `certificate_manager`
> role. Read access doesn't have this problem at all, which makes the split
> easy to miss until you specifically try a write with a "real-role-only"
> user. This is the same class of divergence flagged elsewhere in this doc
> (`docs/internal/archive/e2e-manual-testing-guide.md`'s "Finding 8"); the worked example
> below demonstrates it concretely for certificates.

#### Worked example: `docs-tls` vault — self-signed root, CA-signed leaf, and the legacy-role authorization gap

##### Prerequisites

- Server running against a scratch config/DB (**§0 Environment Setup**),
  with `CFG=/tmp/rv-test.yaml` and `DB=/tmp/rv-test.db` exported — same
  convention §7's and §8.1's worked examples use.
- `rocketvault` CLI built and on your `PATH`.
- `curl`, [`jq`](https://jqlang.org/), `sqlite3`, and `openssl` installed
  (`openssl` is required here specifically — see gotcha #3, there is no
  other way to inspect a certificate's issuer).
- An admin user already bootstrapped, with `ROCKETVAULT_TOTP_SECRET`
  exported (**§2 Admin Bootstrap**, **§3.5's Prerequisites** for the exact
  capture pattern).
- Vault creation and the admin self-grant follow **§3.5 steps 1-2** exactly
  — reuse that pattern rather than re-deriving it, substituting the vault
  name and `Key Vault Administrator` as the role.
- An RSA signing key created first, per **§8.1**'s checklist
  (`rocketvault keys create --name ... --type RSA --bits 2048 ...`) — use
  RSA, not ECDSA (see gotcha #2 below for why).

##### The 10 gotchas this example is built to surface

All ten are real, verified-against-source behaviors — you will hit them if
you don't know about them going in.

1. **The legacy-role gate described in the concept box above is real and
   will reject a user whose only credential is a correct, real per-vault
   role.** Granting `Key Vault Certificates Officer` in a vault is not
   enough to run `certificate create`/`update`/`delete`/`renew` in that
   vault — the user also needs the legacy global `certificate_manager` role
   (or `admin`), assigned at user-creation time (`--new-role
   certificate_manager`), which is a completely separate mechanism from
   `vault-access grant`. Step 6 below demonstrates this concretely.
2. **CA-signing hardcodes the signing algorithm as RSA, regardless of the
   CA key's actual type** — the code comment at
   `internal/services/certificates/certificate_service.go:344` literally
   says "assume CA uses RSA for simplicity." An ECDSA CA key would likely
   fail CA-signing, but the exact failure mode is unconfirmed — this
   walkthrough sidesteps it entirely by using an RSA key throughout,
   rather than triggering and guessing at the error.
3. **There is no issuer field anywhere in any API or CLI response.**
   `model.Certificate` and both `CertificateResponse` shapes
   (`model/certificate.go:90-101`, `api/certificates.go:63-73`) omit the
   certificate PEM body entirely; `certificate get`/`list` only show
   ID/Name/Tags/Expires/AutoRenew/Created. The **only** way to confirm
   whether a cert is self-signed or CA-signed, or to see its real issuer,
   is to pull the raw `certificate` column out of the DB and decode it with
   `openssl x509` — steps 3 and 5 below do exactly that.
4. **There is also no `is_ca` column, or any column like it, in the schema**
   (`internal/db/db.go:434-451`): `id, user_id, key_id, name, vault_id,
   certificate, private_key, created_at, deleted_at, purge_protection,
   scheduled_purge_at, expires_at, auto_renew, renewal_days, enabled,
   not_before`. "Is this a CA cert" is not a queryable fact anywhere except
   by decoding the PEM itself.
5. **Renew never rotates the key, and always regenerates the certificate as
   self-signed — even if the original was CA-signed — and the certificate's
   own UUID never changes.** `RenewCertificate`
   (`certificate_service.go:629-709`) decrypts and re-encrypts the exact
   same key (`original.KeyID`, `:655,661,683`), always builds the new cert
   with `IsCA: true` (`:667-671`, self-signed), and does `updated :=
   *original` before updating in place (`:689`) — the row's `id` is
   preserved. The CLI's own success message is misleading about this: the
   format string at `renew.go:76` is `"Certificate renewed
   successfully!\nOld Certificate ID: %s\nNew Certificate ID: %s\nValidity:
   %d days\n"`, and both `%s` values print the **same** UUID. Renewing a
   CA-signed leaf silently converts it to self-signed — step 7 proves this.
6. **There is no HTTP route for `/renew` at all — it is CLI-only.**
   `api/certificates.go`'s route registration has no renew handler; a dead,
   unreferenced mapping entry exists in
   `internal/services/authorization/data_actions.go:251-254` but nothing
   calls it. Step 8 confirms this by hitting the path directly.
7. **Every `PUT` on a certificate's rotation policy mints a brand-new
   internal `id`, even though it's still exactly one row per certificate.**
   `certificate_service.go:458` calls `uuid.New()` unconditionally on every
   upsert, and the repository's `Upsert` is keyed by `certificate_id`, so
   there's still only one policy row per cert — but unlike a key's rotation
   policy (§8.1's checklist: repeated `PUT` on the same key returns the
   *same* `id`), the policy's own `id` field is not stable across repeated
   `PUT`s. Don't assume the two "policy" upsert semantics match just
   because they're named the same.
8. **Backup/restore is a real exception to the flat-vs-vault-scoped
   duplication this section's intro line describes.**
   `POST /certificates/{id}/backup` and `POST /certificates/restore` exist
   **only** on the legacy flat router (`api/backup_item.go:32-36`) — unlike
   create/get/list/update/delete/policy, which are all duplicated onto
   `/vaults/{name}/certificates/...`, there is no vault-scoped backup route
   for certificates at all.
9. **`Key Vault Certificate User` currently grants nothing beyond `Key
   Vault Reader` — read-only, full stop.** This is intentional and
   documented in code (`model/azure_roles.go:137-141`): certs aren't yet
   linked to key/secret material, so there's no narrower "use" permission to
   grant beyond read. Not a gap to flag if you notice the two roles are
   identical — it's a known, deliberate deferral.
10. **There is no API or CLI way to set a certificate's `expires_at`
    directly**, which makes exercising the auto-renewal scheduler
    (`internal/services/certificates/renewal_scheduler.go`, wraps
    `schedulerkit.Runner`) require a direct `sqlite3 UPDATE` against the DB
    row, plus a config edit (`rotation.certificates.interval`, YAML-only,
    not an env var) to shrink the poll interval to something observable in
    a test session. Step 11 (optional) walks through this.

##### Setup

```bash
BASE=http://localhost:8774/api/v1     # adjust host:port to your scratch config
CFG=/tmp/rv-test.yaml
DB=/tmp/rv-test.db
TOTP_CODE=$(go run scripts/totp_generator.go -secret="$ROCKETVAULT_TOTP_SECRET" 2>&1 | grep -m1 -oP '(?<=--totp-code )\S+')

rocketvault --config "$CFG" users login --username admin --password admin123 --totp-code "$TOTP_CODE"
rocketvault --config "$CFG" vaults create docs-tls
rocketvault --config "$CFG" vault-access grant admin --role "Key Vault Administrator" --vault docs-tls

ADMIN_TOKEN=$(curl -s -X POST $BASE/users/login \
  -H "Content-Type: application/json" \
  -d "{\"username\":\"admin\",\"password\":\"admin123\",\"totp_code\":\"$TOTP_CODE\"}" \
  | jq -r .token)
```
Vault creation and the self-grant follow §3.5 steps 1-2 exactly — see that
section if any part of this fails, rather than re-deriving it here.

---

**1. Create the RSA signing key (gotcha #2 — RSA, not ECDSA, to sidestep the CA-signing algorithm assumption):**
```bash
rocketvault --config "$CFG" keys create --name ca-signing-key --type RSA --bits 2048 --vault docs-tls
```
Expect success with the new key's ID printed. Save it:
```bash
KEY_ID=<id from the output above>
```

**2. Create the self-signed "root" certificate:**
```bash
rocketvault --config "$CFG" certificate create --name docs-root --key-id "$KEY_ID" \
  --validity-days 3650 --vault docs-tls
```
Expect success. Note the response has no `issuer` or `is_ca` field to
confirm anything about it — that's expected (gotchas #3, #4), not a bug.
Save the ID:
```bash
ROOT_CERT_ID=<id from the output above>
```

**3. Confirm it's self-signed, and confirm the missing `is_ca` column, via raw DB inspection (gotchas #3, #4):**
```bash
sqlite3 "$DB" "SELECT certificate FROM certificates WHERE id='$ROOT_CERT_ID';" | openssl x509 -noout -subject -issuer
sqlite3 "$DB" ".schema certificates"
```
Expect the `subject` and `issuer` lines from the first command to be
identical (self-signed). Expect the schema dump to list exactly the columns
in gotcha #4, with no `is_ca` (or similarly-named) column anywhere.

**4. Create a CA-signed leaf certificate referencing the root:**
```bash
rocketvault --config "$CFG" certificate create --name docs-leaf --key-id "$KEY_ID" \
  --validity-days 365 --ca-cert-id "$ROOT_CERT_ID" --vault docs-tls
```
Expect success (RSA key signing an RSA-keyed CA — this sidesteps gotcha
#2's unconfirmed ECDSA failure path entirely). Save the ID:
```bash
LEAF_CERT_ID=<id from the output above>
```

**5. Confirm the leaf's issuer chain — again, the only way to see this (gotcha #3):**
```bash
sqlite3 "$DB" "SELECT certificate FROM certificates WHERE id='$LEAF_CERT_ID';" | openssl x509 -noout -subject -issuer
```
Expect `issuer` to match the root's `subject` from step 3, and `subject` to
be the leaf's own name — proving it's genuinely CA-signed, not self-signed.
Neither `rocketvault certificate get "$LEAF_CERT_ID" --vault docs-tls` nor
the equivalent `GET` API call shows any of this — both omit the certificate
body entirely.

**6. Demonstrate the legacy-role divergence (gotcha #1).** Create a second
user holding only the real per-vault Azure role, deliberately withholding
the legacy global `certificate_manager` role:
```bash
OUT=$(rocketvault --config "$CFG" users create --new-username cert-officer --new-password certofficer12345 --new-role user)
CO_ID=$(echo "$OUT" | grep -oP 'User ID: \K\S+')
CO_TOTP=$(echo "$OUT" | grep -oP 'TOTP Secret: \K\S+')
CO_CODE=$(go run scripts/totp_generator.go -secret="$CO_TOTP" 2>&1 | grep -m1 -oP '(?<=--totp-code )\S+')

rocketvault --config "$CFG" vault-access grant cert-officer --role "Key Vault Certificates Officer" --vault docs-tls
rocketvault --config "$CFG" users login --username cert-officer --password certofficer12345 --totp-code "$CO_CODE"
rocketvault --config "$CFG" certificate create --name should-fail --key-id "$KEY_ID" --validity-days 365 --vault docs-tls
```
Expect the create to fail with exactly `forbidden: requires admin or
certificate_manager role` — even though `Key Vault Certificates Officer`
fully satisfies the real per-vault check. Confirm the double standard by
running a read with the same session:
```bash
rocketvault --config "$CFG" certificate get "$LEAF_CERT_ID" --vault docs-tls
```
Expect this one to **succeed** — `get` never runs the legacy check.

Re-login as admin before continuing:
```bash
rocketvault --config "$CFG" users login --username admin --password admin123 --totp-code "$TOTP_CODE"
```

**7. Renew the leaf, and observe both the identical-ID output and the silent conversion to self-signed (gotcha #5):**
```bash
rocketvault --config "$CFG" certificate renew "$LEAF_CERT_ID" --validity-days 365 --vault docs-tls
```
Expect output matching `renew.go:76`'s format string, with both the "Old
Certificate ID" and "New Certificate ID" values identical to
`$LEAF_CERT_ID` — don't read "New Certificate ID" as a distinct resource.
Then confirm the conversion:
```bash
sqlite3 "$DB" "SELECT certificate FROM certificates WHERE id='$LEAF_CERT_ID';" | openssl x509 -noout -subject -issuer
```
Expect `subject` and `issuer` to now match — the cert that was CA-signed in
step 4 has silently reverted to self-signed. Confirm the key itself never
changed:
```bash
sqlite3 "$DB" "SELECT key_id FROM certificates WHERE id='$LEAF_CERT_ID';"
```
Expect this to still equal `$KEY_ID`.

**8. Confirm there is no HTTP route for renew (gotcha #6):**
```bash
curl -s -o /dev/null -w "%{http_code}\n" -X POST $BASE/certificates/$LEAF_CERT_ID/renew \
  -H "Authorization: Bearer $ADMIN_TOKEN"
```
Expect a not-found response (confirm the exact status code when you run
this — no route is registered for this path, but the precise code Gorilla
Mux returns for an unmatched sub-path isn't independently pinned down
here). Either way, expect no renewal to have occurred — re-check
`expires_at` before and after if you want to confirm nothing happened.

**9. Certificate policy — PUT twice, watch the internal `id` change (gotcha #7):**
```bash
curl -s -X PUT $BASE/certificates/$LEAF_CERT_ID/policy \
  -H "Authorization: Bearer $ADMIN_TOKEN" -H "Content-Type: application/json" \
  -d '{"validity_months":12,"key_type":"RSA","key_size":2048,"subject":"CN=docs-leaf","auto_renew":true,"days_before_expiry":30,"issuer_name":"Self"}' | jq -r .id
```
Save the first id, then repeat the identical `PUT`:
```bash
POLICY_ID_1=<value from above>
curl -s -X PUT $BASE/certificates/$LEAF_CERT_ID/policy \
  -H "Authorization: Bearer $ADMIN_TOKEN" -H "Content-Type: application/json" \
  -d '{"validity_months":12,"key_type":"RSA","key_size":2048,"subject":"CN=docs-leaf","auto_renew":true,"days_before_expiry":30,"issuer_name":"Self"}' | jq -r .id
```
Expect the second `id` to **differ** from `$POLICY_ID_1`. Confirm it's
still one row throughout with a `GET` in between the two `PUT`s:
```bash
curl -s $BASE/certificates/$LEAF_CERT_ID/policy -H "Authorization: Bearer $ADMIN_TOKEN" | jq .
```
This is a genuine difference from a key's rotation policy (§8.1: repeated
`PUT` returns the *same* `id`) — don't assume the two "policy" upserts
behave the same way just because they're named alike.

**10. Backup/restore — confirm the flat-only exception (gotcha #8):**
```bash
curl -s -X POST $BASE/certificates/$LEAF_CERT_ID/backup \
  -H "Authorization: Bearer $ADMIN_TOKEN" | jq .
```
Expect `{"blob": "<string>"}`. Then confirm there's no vault-scoped
equivalent:
```bash
curl -s -o /dev/null -w "%{http_code}\n" -X POST $BASE/vaults/docs-tls/certificates/$LEAF_CERT_ID/backup \
  -H "Authorization: Bearer $ADMIN_TOKEN"
```
Expect a not-found response — unlike create/get/list/update/delete/policy,
which all exist on both routers, backup/restore for certificates is
legacy-flat-only.

**11. (Optional) Observe the auto-renewal scheduler (gotcha #10).** Stop the
server, add to `/tmp/rv-test.yaml`:
```yaml
rotation:
  certificates:
    enabled: true
    interval: 10s
```
Restart it against the same config, then create a dedicated short-lived
cert with auto-renew set at creation time (there is no confirmed `update`
flag for this — set it at `create` instead):
```bash
rocketvault --config "$CFG" certificate create --name docs-shortlived --key-id "$KEY_ID" \
  --validity-days 1 --auto-renew --renewal-days 30 --vault docs-tls
```
```bash
SHORT_CERT_ID=<id from the output above>
sqlite3 "$DB" "UPDATE certificates SET expires_at = datetime('now', '+20 seconds') WHERE id = '$SHORT_CERT_ID';"
```
Wait roughly 30 seconds (past both the 10s poll interval and the edited
`expires_at`), then check:
```bash
sqlite3 "$DB" "SELECT expires_at FROM certificates WHERE id='$SHORT_CERT_ID';"
```
Expect `expires_at` to have moved forward — the scheduler renewed it,
producing the same identical-ID / self-signed-conversion behavior as step 7,
just scheduler-triggered instead of CLI-triggered. Confirm the exact server
log line if you want provenance beyond the DB row — its format isn't pinned
down here.

##### Cleanup

```bash
rocketvault --config "$CFG" users delete "$CO_ID"
rocketvault --config "$CFG" vaults delete docs-tls        # soft-delete
rocketvault --config "$CFG" vaults purge docs-tls          # if you want it fully gone
```

---

## 10. Access Policies (explicit-deny layer)

Already partially covered in §6's deny-override test. Additionally:

- [ ] `POST /api/v1/access-policies` for a principal + resource type → `201`.
- [ ] `GET /api/v1/access-policies` (list all), `GET /{id}` (single),
      `GET /principal/{id}` (by principal) all return consistent data.
- [ ] `PUT /api/v1/access-policies/{id}` → update; `DELETE` → removes it, access
      reverts to whatever the role-assignment layer alone would grant.

> **Concept: `effect: "allow"` access policies are accepted, validated, and
> stored — but there is currently no code path where an allow-effect policy
> grants access beyond what role assignments already grant.** Only `deny`
> actually does anything today. The three-way decision
> (`internal/services/authorization/access_policy_service.go:14-24`,
> `CheckAccess` at `:52-66`) is `AccessDenied` on any matching deny row
> (immediate short-circuit — the role check is never even reached, see
> gotcha #4), `AccessAllowed` on a matching non-deny row, or `AccessFallback`
> when nothing matches. But both HTTP (`PolicyMiddleware`,
> `internal/middleware/middleware.go:453-561`) and CLI
> (`cmd/vaultcli.RequireDataAction`, `cmd/vaultcli/vault.go:40-59`) run the
> real role-assignment check **unconditionally** afterward, regardless of
> whether step one returned `AccessAllowed` or `AccessFallback` — nothing
> ever substitutes the access-policy decision *for* the role decision on an
> allow. So storing an allow-effect policy for a principal with no matching
> role grant produces a `201` on creation and then silently changes nothing:
> the subsequent role check still fails and the request still `403`s. This
> worked example builds on §6's already-proven deny-override mechanic
> (`docs/testing/manual-testing-plan.md:2658-2663`) rather than re-deriving it,
> and instead fills in the request/response shapes §6 skips, plus this
> inert-allow finding.

#### Worked example: `policy-demo` vault — full access-policy CRUD shape, and proving allow-effect policies are inert

##### Prerequisites

- Server running against a scratch config/DB (**§0 Environment Setup**).
- Admin bootstrapped, `ROCKETVAULT_TOTP_SECRET` exported (**§2 Admin
  Bootstrap**).
- Familiarity with §3.5's vault-create + self-grant + admin-token pattern
  (`docs/testing/manual-testing-plan.md:2105-2154`) and §6's deny-override test —
  this example reuses both rather than re-explaining them.
- `curl` and `jq`. **No CLI command group exists for access policies at
  all** — every access-policy call below is `curl`; only vault creation,
  the admin self-grant, user creation, and the `Key Vault Secrets User`
  grant use the `rocketvault` CLI.

##### The 7 gotchas this example is built to surface

All seven are real, verified-against-source behaviors — you will hit them
if you don't know about them going in.

1. **A policy is keyed on four dimensions, not two.** The checklist
   bullet above says "principal + resource type," but `operation` is a
   required fourth field (`model.CreateAccessPolicyRequest`,
   `model/access_policy.go:73-81`) — omitting it is a clean `400`
   (`api/access_policies.go:83`), not an implied "applies to all
   operations." `resource_type` is also plural (`"secrets"`, `"keys"`,
   `"certificates"`, `"vaults"` — `model/access_policy.go:29-32`), not the
   singular form you might guess.
2. **Policies are flat, not vault-scoped in the URL.** All five routes live
   under `/api/v1/access-policies` (`api/api.go:34,112`) — `vault_id` is a
   body/response field, not a path segment. `GET
   /access-policies/principal/{id}` returns every policy for that
   principal across every vault it has one in, all in one array
   (`api/access_policies.go:251-255`) — filter by the `vault_id` field
   client-side if you only want one vault's policies. A `vault_id: null`
   row is global and matches every vault, not "no vault"
   (`internal/repositories/access_policy_repository.go:90-102`).
3. **`PUT` can only flip `effect`.** The update body is `{effect}` and
   nothing else (`api/access_policies.go:172-174`) — there is no way to
   repoint an existing policy at a different principal, resource type,
   operation, or vault; delete and recreate instead.
4. **A deny short-circuits before the role lookup ever runs — on both HTTP
   and CLI.** `PolicyMiddleware` (`internal/middleware/middleware.go:500-518`)
   returns `403` immediately on `AccessDenied`, never reaching the
   `HasDataAction` role check at `:520-551`. `RequireDataAction`
   (`cmd/vaultcli/vault.go:51-57`) is identical — confirmed by
   `TestRequireDataAction_DeniedByPolicy`
   (`cmd/vaultcli/vault_test.go:94-114`), which asserts
   `roles.AssertNotCalled("HasDataAction", ...)` on a deny. This is a true
   short-circuit, not a decision made and then overridden after the fact.
5. **The headline finding: allow-effect policies are inert.** `effect:
   "allow"` (`model.PolicyEffectAllow`, `model/access_policy.go:22`) is
   accepted, validated, and persisted with no error and no warning — but
   because the role check always runs afterward regardless of an
   `AccessAllowed` result, an allow policy for a principal with zero role
   grants in that vault grants that principal literally nothing. Step 6
   below proves this directly.
6. **No CLI support exists for access policies at all.** Every `POST`,
   `GET`, `PUT`, `DELETE` against `/access-policies*` below is `curl` —
   unlike §3.5/§8.2, there is no partial CLI coverage to fall back on here.
7. **Management is admin-only by design, with no per-vault delegation —
   and the code says so explicitly.** All five handlers gate on
   `requireAccessPolicyAdmin` → `common.HasRequiredRole(...,
   model.RoleAdmin)` (`api/access_policies.go:32-38`), with a comment
   (`:25-31`) explaining why: an allow-scoped-anywhere or deny-anyone
   policy is too powerful to delegate to a per-vault role like `Key Vault
   Data Access Administrator`. Don't file this as a gap — it's intentional.

##### Setup

Vault creation, self-grant, and admin-token retrieval follow §3.5 steps
1-2 and 4 exactly (`docs/testing/manual-testing-plan.md:2105-2154`):

```bash
BASE=http://localhost:8774/api/v1
TOTP_CODE=$(go run scripts/totp_generator.go -secret="$ROCKETVAULT_TOTP_SECRET" 2>&1 | grep -m1 -oP '(?<=--totp-code )\S+')

rocketvault users login --username admin --password admin123 --totp-code "$TOTP_CODE"
rocketvault vaults create policy-demo
rocketvault vault-access grant admin --role "Key Vault Administrator" --vault policy-demo

ADMIN_TOKEN=$(curl -s -X POST $BASE/users/login \
  -H "Content-Type: application/json" \
  -d "{\"username\":\"admin\",\"password\":\"admin123\",\"totp_code\":\"$TOTP_CODE\"}" \
  | jq -r .token)

VAULT_ID=$(curl -s $BASE/vaults/policy-demo -H "Authorization: Bearer $ADMIN_TOKEN" | jq -r .id)
```

Seed a secret and one principal with `Key Vault Secrets User` — the same
setup §6's deny-override test uses:

```bash
curl -s -X POST $BASE/vaults/policy-demo/secrets \
  -H "Authorization: Bearer $ADMIN_TOKEN" -H "Content-Type: application/json" \
  -d '{"name":"demo-secret","value":"s3cr3t"}' | jq .

OUT=$(rocketvault users create --new-username policy-user --new-password policyuser12345 --new-role user)
PU_ID=$(echo "$OUT" | grep -oP 'User ID: \K\S+')
PU_TOTP=$(echo "$OUT" | grep -oP 'TOTP Secret: \K\S+')
PU_CODE=$(go run scripts/totp_generator.go -secret="$PU_TOTP" 2>&1 | grep -m1 -oP '(?<=--totp-code )\S+')
PU_TOKEN=$(curl -s -X POST $BASE/users/login -H "Content-Type: application/json" \
  -d "{\"username\":\"policy-user\",\"password\":\"policyuser12345\",\"totp_code\":\"$PU_CODE\"}" | jq -r .token)

rocketvault vault-access grant policy-user --role "Key Vault Secrets User" --vault policy-demo
```

---

**1. Baseline positive read — confirm the role grant works normally,
before any policy exists:**
```bash
curl -s -o /dev/null -w "%{http_code}\n" $BASE/vaults/policy-demo/secrets \
  -H "Authorization: Bearer $PU_TOKEN"
```
Expect `200`.

**2. Deny-effect policy overrides the role grant — brief, since §6 already
proves this mechanic (`docs/testing/manual-testing-plan.md:2658-2663`):**
```bash
POLICY=$(curl -s -X POST $BASE/access-policies \
  -H "Authorization: Bearer $ADMIN_TOKEN" -H "Content-Type: application/json" \
  -d "{\"principal_id\":\"$PU_ID\",\"principal_type\":\"user\",\"resource_type\":\"secrets\",\"operation\":\"get\",\"effect\":\"deny\",\"vault_id\":\"$VAULT_ID\"}")
echo "$POLICY" | jq .
POLICY_ID=$(echo "$POLICY" | jq -r .id)

curl -s -o /dev/null -w "%{http_code}\n" $BASE/vaults/policy-demo/secrets \
  -H "Authorization: Bearer $PU_TOKEN"
```
Expect `201` on the create (`api/access_policies.go:130-132`) — the
`assignment_id` field is **absent** from the JSON entirely (not present as
`null`), since it's a `*uuid.UUID` with `json:"assignment_id,omitempty"`
(`model/access_policy.go:69`) and this is a hand-written policy, not one
generated from a role grant. Then expect `403` on the read — the deny
wins even though `policy-user` still holds `Key Vault Secrets User`.

**3. List-all and single-by-ID — filling the gap §6 doesn't cover:**
```bash
curl -s $BASE/access-policies -H "Authorization: Bearer $ADMIN_TOKEN" | jq .
curl -s $BASE/access-policies/$POLICY_ID -H "Authorization: Bearer $ADMIN_TOKEN" | jq .
```
Expect the list call wrapped as `{"access_policies":[...],"total":N}`
(`api/access_policies.go:58-62`) — every policy in the system, not just
`policy-demo`'s. Expect the single-by-ID call to return the raw object
(no `assignment_id` key, per step 2's note):
```json
{
  "id": "...",
  "principal_id": "<PU_ID>",
  "principal_type": "user",
  "resource_type": "secrets",
  "operation": "get",
  "effect": "deny",
  "vault_id": "<VAULT_ID>",
  "created_at": "..."
}
```

**4. `PUT` — confirm only `effect` is accepted, and watch what flipping it
actually restores (and why):**
```bash
curl -s -X PUT $BASE/access-policies/$POLICY_ID \
  -H "Authorization: Bearer $ADMIN_TOKEN" -H "Content-Type: application/json" \
  -d '{"effect":"allow"}' | jq .

curl -s -o /dev/null -w "%{http_code}\n" $BASE/vaults/policy-demo/secrets \
  -H "Authorization: Bearer $PU_TOKEN"
```
Expect the `PUT` body accepted as `{"effect": "allow"}` only
(`api/access_policies.go:172-174`) and the read to return `200` again.
Don't read this as "the allow policy granted access" — `policy-user`
still holds `Key Vault Secrets User` from Setup, and the role check
(which always runs) is what's actually passing now that the deny is gone.
This is the first piece of evidence for gotcha #5, before step 6 proves it
outright.

**5. `DELETE` — confirm removal doesn't change anything, since the policy
was already inert as an allow:**
```bash
curl -s -o /dev/null -w "%{http_code}\n" -X DELETE $BASE/access-policies/$POLICY_ID \
  -H "Authorization: Bearer $ADMIN_TOKEN"

curl -s -o /dev/null -w "%{http_code}\n" $BASE/vaults/policy-demo/secrets \
  -H "Authorization: Bearer $PU_TOKEN"
```
Expect `200` (`ReturnStatusOK`, `api/access_policies.go:224`) on the
delete, and the read to remain `200` afterward — access reverts to
"whatever the role-assignment layer alone grants," which is unchanged by
this whole detour, exactly as §10's own checklist wording predicts.

**6. THE headline step — an allow-effect policy for a principal with ZERO
role assignments in the vault:**
```bash
OUT2=$(rocketvault users create --new-username policy-user-2 --new-password policyuser2xyz --new-role user)
PU2_ID=$(echo "$OUT2" | grep -oP 'User ID: \K\S+')
PU2_TOTP=$(echo "$OUT2" | grep -oP 'TOTP Secret: \K\S+')
PU2_CODE=$(go run scripts/totp_generator.go -secret="$PU2_TOTP" 2>&1 | grep -m1 -oP '(?<=--totp-code )\S+')
PU2_TOKEN=$(curl -s -X POST $BASE/users/login -H "Content-Type: application/json" \
  -d "{\"username\":\"policy-user-2\",\"password\":\"policyuser2xyz\",\"totp_code\":\"$PU2_CODE\"}" | jq -r .token)
# Deliberately no `vault-access grant` for policy-user-2 in policy-demo.

curl -s -X POST $BASE/access-policies \
  -H "Authorization: Bearer $ADMIN_TOKEN" -H "Content-Type: application/json" \
  -d "{\"principal_id\":\"$PU2_ID\",\"principal_type\":\"user\",\"resource_type\":\"secrets\",\"operation\":\"get\",\"effect\":\"allow\",\"vault_id\":\"$VAULT_ID\"}" | jq .

curl -s -o /dev/null -w "%{http_code}\n" $BASE/vaults/policy-demo/secrets \
  -H "Authorization: Bearer $PU2_TOKEN"
```
Expect the `POST` to succeed — `201`, `"effect":"allow"`, no validation
error, no warning of any kind — and the read to come back `403` anyway.
This is the standout result of this section: the API happily stores a
policy that says "allow this principal to read secrets here," and that
policy does nothing whatsoever, because nothing in the codebase ever lets
an `AccessAllowed` decision stand in for the role check that runs
unconditionally afterward. If you're auditing access policies as a
security control, an `effect: "allow"` row is not evidence of a working
grant — only the role-assignment table is.

##### Cleanup

```bash
curl -s -X DELETE $BASE/access-policies/<any policy id created in step 6> \
  -H "Authorization: Bearer $ADMIN_TOKEN"
rocketvault users delete "$PU_ID"
rocketvault users delete "$PU2_ID"
rocketvault vaults delete policy-demo        # soft-delete
rocketvault vaults purge policy-demo         # if you want it fully gone
```

---

## 11. Multi-Vault Isolation (cross-cutting)

- [ ] With two vaults and two users each granted access to only one vault,
      confirm neither user can list, read, or reference the other vault's
      resources by ID even if they somehow obtain the UUID (IDs are not
      globally guessable, but confirm the vault-scoped route rejects a
      cross-vault ID rather than silently succeeding).
- [ ] Confirm the `default` vault behaves identically to a named vault for every
      operation in §7–§10 (it's not special-cased anywhere except non-deletability,
      per §5).
- [ ] `vaultcache` sanity: with `cache.vaults.enabled: true`, rename/update a vault
      via `PATCH`, then immediately `GET` it via a **different** API path that also
      resolves the vault by name (e.g. a secrets list under the old vs. new state)
      — confirm you don't get a stale cached vault record within the TTL window in
      a way that causes incorrect authorization decisions. This is a genuinely
      security-relevant cache — worth being deliberate about, not just a perf check.

### 11.1 Per-vault rate limiting (noisy-neighbour guard)

Added 2026-09-03 (`rate_limit.per_vault`, default 600/min, enforced by
`VaultRateLimitMiddleware` in `internal/middleware/vault_rate_limit.go`). This is
a token bucket per **vault**, layered on top of — not replacing — the existing
per-IP `rate_limit.default` / `rate_limit.auth` buckets from §3.1. Test it with a
low `per_vault` value in your scratch config (e.g. `10`) so you don't have to
send hundreds of requests.

- [ ] Set `rate_limit.per_vault: 10`, restart, then send >10 requests/min against
      one vault's routes → the excess returns **429** with `Vault rate limit
      exceeded`.
- [ ] Response headers on rate-limited routes are `X-RateLimit-Vault-Limit`,
      `-Remaining`, `-Reset` — **deliberately distinct names** from the per-IP
      limiter's `X-RateLimit-*` so the two cannot clobber each other. Confirm both
      families are present and moving independently; a request that consumes vault
      budget should also consume IP budget.
- [ ] **The bucket is per vault, not per caller.** Drain vault A's budget from one
      user, then hit vault A as a *different* user from a *different* IP → still
      429. That is the whole point of the guard; a pass for the second user would
      mean it's keyed wrong.
- [ ] **Isolation**: with vault A rate-limited, vault B's routes still serve
      normally. Neither vault can spend the other's budget.
- [ ] **Health probes are exempt.** With vault A's budget fully drained,
      `/health/live`, `/health/ready` and `/health/database` still return 200.
      They skip `VaultResolutionMiddleware` and so have no vault to count against —
      if a drained vault could 429 a liveness probe, an orchestrator would restart
      a healthy instance.
- [ ] **Routes that resolve no vault count against `default`.** Vault-management
      routes and the legacy flat resource paths have no vault of their own; confirm
      hammering those drains the `default` vault's budget, not some other vault's.
- [ ] Middleware **ordering**: the vault is unknown before `VaultResolutionMiddleware`
      runs, so `VaultRateLimitMiddleware` must sit after it in `api/api.go`'s chain.
      A behavioral proxy for this: if per-vault limiting silently never triggers on
      vault-scoped routes while the config is set, suspect the ordering.
- [ ] With `monitoring.enable_metrics: true`, each rejection increments
      `rocketvault_vault_rate_limit_exceeded_total{vault="<name>"}` — check
      `GET /metrics` and confirm the label carries the right vault name.
#### Worked example: draining one vault's budget without ever being authorized

> **Concept: the limiter counts requests, not successful ones.** It sits after
> `VaultResolutionMiddleware` (so it knows the vault) but its rejection is
> decided before the handler's authorization outcome matters — a request that
> goes on to return `403` has already spent a token. So a caller with **no
> permissions at all** in a vault can exhaust that vault's per-minute budget
> and deny service to legitimate callers of the same vault. Whether that is
> acceptable is a deployment question; that it happens is not in doubt,
> reproduced live below.

Captured live 2026-09-03 with `rate_limit.per_vault: 5` in a scratch config
(the 600 default would need 600 requests to demonstrate).

#### Walkthrough

**1. Set a small budget and restart.** In your scratch config:

```yaml
rate_limit:
  per_vault: 5
```

**2. Send 8 requests to a vault-scoped route as a caller with no role in it.**

```bash
for i in $(seq 1 8); do
  curl -s -o /dev/null -w "req $i: %{http_code}\n" -H "Authorization: Bearer $TOKEN" \
    $BASE/vaults/default/secrets
done
```
```
req 1: 403
req 2: 403
req 3: 403
req 4: 403
req 5: 403
req 6: 429
req 7: 429
req 8: 429
```

Five refusals consumed the whole budget; the sixth request was throttled. The
caller never had access to a single secret.

**3. Both header families are present and independent.**

```bash
curl -s -D - -o /dev/null -H "Authorization: Bearer $TOKEN" $BASE/vaults/default/secrets \
  | grep -iE '^HTTP|ratelimit'
```
```
HTTP/1.1 429 Too Many Requests
X-Ratelimit-Limit: 300
X-Ratelimit-Remaining: 292
X-Ratelimit-Reset: 1788452404
X-Ratelimit-Vault-Limit: 5
X-Ratelimit-Vault-Remaining: 0
X-Ratelimit-Vault-Reset: 1788452404
```

The per-IP budget still has 292 of 300 left. Only the vault budget is spent —
which is exactly the separation the distinct header names exist to make visible.

**4. Health probes stay up while the vault is throttled.**

```bash
curl -s -o /dev/null -w "%{http_code}\n" $BASE/health/live    # 200
curl -s -o /dev/null -w "%{http_code}\n" $BASE/health/ready   # 200
```

If these ever returned `429`, an orchestrator would restart a healthy instance
because one tenant was busy.

**5. A different vault is unaffected.**

```bash
curl -s -o /dev/null -w "create: %{http_code}\n" -X POST $BASE/vaults \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' -d '{"name":"acme-prod"}'
curl -s -o /dev/null -w "acme-prod: %{http_code}\n" -H "Authorization: Bearer $TOKEN" $BASE/vaults/acme-prod/secrets
curl -s -o /dev/null -w "default:   %{http_code}\n" -H "Authorization: Bearer $TOKEN" $BASE/vaults/default/secrets
```
```
create: 201
acme-prod: 403
default:   429
```

`acme-prod` reaches the authorization layer and is refused on the merits;
`default` never gets that far. Two different failures, and telling them apart
is the point of the exercise.

#### Teardown

Restore `rate_limit.per_vault` to `600` (or remove it) and restart. Purge
`acme-prod` if you created it.

- [ ] **There is no off switch.** Unset or non-positive `per_vault` falls back to
      `defaultVaultRateLimit` (600/min, double the per-IP default) — it does **not**
      disable the limiter. Remove the key from your scratch config and confirm
      `X-RateLimit-Vault-Limit: 600` still comes back. An operator who never
      configures this is still rate-limited; that is intended, but worth knowing
      before diagnosing a 429 in production.

---

## 12. Audit Logs

- [ ] `GET /api/v1/audit/logs` (admin) / `rocketvault audit logs ...` → recent
      events from everything you've done above should appear (login, secret
      create, vault delete, etc.).
- [ ] Filter by `--from`/`--to`, `--action`, `--outcome`, `--user-id`,
      `--resource-type`, `--limit` — confirm each filter narrows results correctly,
      not just accepted without effect.
- [ ] `rocketvault audit report --type soc2 --from ... --to ...` (JSON and
      `--format csv`) → generates a report; spot-check a few entries against
      what you know you did.
- [ ] `rocketvault audit report --type gdpr --from ... --to ... --subject-id <user-id>`
      → report scoped to one data subject.
- [ ] `GET /api/v1/audit/config` → current retention config;
      `PATCH /api/v1/audit/config` / `rocketvault audit config --retention-days 90`
      → updates it; confirm `GET` reflects the change.
- [ ] Non-admin hitting any `/audit/*` route → `403`.

---

## 13. Backup & Restore (system-level, whole-database)

Admin-only, whole-DB scope — not vault-scoped (see `requireBackupAdmin` in `cmd/backup.go`).

- [ ] ```bash
      rocketvault backup create --output /tmp/rv-backup.enc.backup   # encrypted by default
      rocketvault backup create --output /tmp/rv-backup.plain.backup --encrypt=false
      rocketvault backup list --dir /tmp
      ```
- [ ] Create some new data (a secret, a vault) *after* taking the backup, then:
      ```bash
      rocketvault backup restore --file /tmp/rv-backup.enc.backup
      rocketvault backup restore --file /tmp/rv-backup.plain.backup --decrypt=false
      ```
      Confirm the post-backup data is gone after restore (i.e. restore actually
      replaces state) and pre-backup data is intact.
- [ ] Confirm `backup` requires admin login — per `[[bug-backup-command-unauthenticated]]`
      memory this was previously an unauthenticated command (fixed commit `47c89fe`,
      2026-08-13). Run any `backup` subcommand with no cached session / as a
      non-admin user → must be rejected, not silently proceed.
- [ ] Restoring an encrypted backup with `--decrypt=false`, or vice versa, should
      fail cleanly (wrong mode), not corrupt the DB — test this on a throwaway
      instance only, don't risk it against real data.

---

## 14. Vault Client Library (`internal/vaultclient`, `examples/consumer-service`)

This is the client-side library other applications use to fetch secrets from a
running RocketVault instance — distinct from the RocketVault server itself.

- [ ] There's an **untracked `consumer-service` directory** at the repo root
      (separate from `examples/consumer-service`, per `git status` at session
      start) — check whether it's a work-in-progress copy or scratch output
      before treating it as part of this test; don't assume it's the canonical
      example.
- [ ] Configure a service account (§3.5), set `vault_client.client_id` to its name
      and `VAULT_CLIENT_SECRET` env var to its secret, add an entry under
      `vault_client.secrets` mapping a secret UUID to a `viper_key`.
- [ ] Run `examples/consumer-service` (or your app) against the running server,
      confirm it fetches the secret and the value lands at the configured
      `viper_key` in that service's own config.
- [ ] Rotate or delete the underlying secret in the vault, confirm the consumer
      picks up the change according to whatever caching/refresh behavior the
      client library implements (check its README/code for the actual refresh
      semantics rather than assuming push vs. poll).

---

## 15. Caching (secrets / keys / vaults)

- [ ] With `cache.secrets.enabled: true`, `ttl: 5m`: read a secret, update it via
      a different path (direct DB or a second API call), re-read within the TTL —
      confirm you get the *updated* value (cache should invalidate on write, not
      just expire on TTL) rather than a stale cached one.
- [ ] Same check for `cache.keys` (60s TTL) and `cache.vaults` (5m TTL, backs
      `VaultResolutionMiddleware`'s per-request vault-by-name lookup).
- [ ] Set `cache.secrets.max_entries` low (e.g. 5) in a scratch config, create more
      than that many secrets, access them all, confirm LRU eviction doesn't cause
      incorrect data — just cache misses that fall through to the DB.
- [ ] Confirm `cache.certificates.*`/`cache.users.*` being `enabled: false` in the
      shipped config doesn't error — they're accepted-but-reserved per CLAUDE.md,
      not wired to any actual cache yet.

---

## 16. Retry / Circuit Breaker (light touch)

This is heavily unit-tested already (`internal/retry/retry.go`) — manual testing
here is about confirming it's *wired in*, not re-deriving backoff math.

- [ ] Stop the OIDC test issuer (or point `oidc.issuer_url` at an unreachable
      host) and attempt `GET /oidc/login` → observe retry attempts in logs
      (external_services or interactive policy, per known-bugs B8) before the
      final failure — should fail within a few seconds, not hang past a typical
      30s proxy timeout.
- [ ] Briefly make the DB connection fail (e.g. wrong `database.connection` path
      that exists-then-vanishes, or a Postgres instance you can stop/start) during
      a request, confirm the `database` retry policy kicks in per its configured
      `max_attempts`/backoff rather than failing on the first transient error.
- [ ] `retry.service_operations` has no production caller yet (intentional, see
      known-bugs I1) — don't spend time trying to trigger it through the API.

---

## 17. CLI Cross-Cutting Checks

- [ ] Run every write-y command (`create`/`update`/`delete`/`rotate`/`grant`/
      `revoke`) with **no** credentials and no cached session → each fails with a
      clear auth error, none silently succeeds. This is the CLI authorization
      contract from CLAUDE.md: HTTP gets middleware for free, CLI commands must
      each reproduce the check themselves — a command that skips this has no other
      enforcement point.
- [ ] For each of `secrets`, `keys`, `certificates`: confirm the command calls
      through `vaultcli.RequireDataAction` after `vaultcli.ResolveVaultID` (behavior
      check, not code reading — a user with no role in the target vault should get
      `403` even if they're a valid, logged-in user with access elsewhere).
- [ ] For `vaults` lifecycle and `vault-access` grant/revoke: confirm the
      package-local authz helpers are actually gating (a user with only data-plane
      access, no `Key Vault Data Access Administrator`/vault-manage grant, should
      be refused).
- [ ] `--config` flag override works for every command (used throughout this plan
      already) — confirm a command with **no** `--config` falls back to
      `.rocketvault.yaml` in the cwd, per `initConfig()` in `cmd/root.go`.

---

## 18. Master Key Rotation

Admin-only, offline operation. Full reference: `docs/runbooks/master-key-rotation.md`.
The master key seals `secrets.value`, `secret_versions.value`, `keys.value`,
`key_versions.value`, and `certificates.private_key` with AES-256-GCM.
PKCS#11/HSM-backed keys (`pkcs11:`-prefixed) are unaffected — their material
never leaves the token, and the rotation tool skips them (`SKIPPED (HSM)` in
its report).

- [ ] Stop the server first — a concurrent write during rotation aborts the run.
- [ ] Back up the database before touching anything:
      ```bash
      cp /tmp/rv-test.db /tmp/rv-test.db.pre-rotation
      ```
- [ ] Generate a new key and **do not** name the variable `MASTER_KEY` — Viper
      gives env vars precedence over the config file, so an exported
      `MASTER_KEY` would make the tool's own "old key from config" default
      silently resolve to the new key instead. The command detects this and
      refuses to run, but a differently-named variable avoids the detour:
      ```bash
      export NEW_MASTER_KEY="$(openssl rand -base64 32)"
      ```
- [ ] Log in as admin, then dry-run first:
      ```bash
      rocketvault --config /tmp/rv-test.yaml users login --username admin --password admin123 --totp-code "$(go run scripts/totp_generator.go 2>&1 | grep -m1 -oP '(?<=--totp-code )\S+')"
      rocketvault --config /tmp/rv-test.yaml master-key rotate --new-key-env NEW_MASTER_KEY --dry-run
      ```
      Expect a per-table report: `ROWS`/`RE-ENCRYPTED`/`ALREADY NEW KEY`/
      `SKIPPED (HSM)`. `ALREADY NEW KEY` should be `0` on a first run;
      `SKIPPED (HSM)` should be `0` unless the scratch config has
      `hsm.enabled: true` with real keys created under it.
- [ ] Run for real (identical row counts to the dry run is the pass condition):
      ```bash
      rocketvault --config /tmp/rv-test.yaml master-key rotate --new-key-env NEW_MASTER_KEY --yes
      ```
- [ ] Update `master_key` in `/tmp/rv-test.yaml` to `$NEW_MASTER_KEY`'s value,
      restart the server, then confirm real secrets decrypt:
      ```bash
      rocketvault --config /tmp/rv-test.yaml secrets list --vault default
      ```
      `secrets list` decrypts every row in the vault, not just one, so it's a
      stronger check than fetching a single ID with `secrets get <id>` (which
      takes a UUID, not a name — get the ID from this same `list` output
      first if you want to single one out). A successful read is real proof
      rotation and config agree — the server also refuses to boot at all on a
      key that fails validation (wrong length, the known-compromised
      placeholder, or low-entropy), so a clean startup is itself part of the
      check.
- [ ] Interrupt a rotation partway (e.g. `Ctrl+C` mid-run on a DB with enough
      rows to take a moment) and re-run the identical command — confirm it
      resumes cleanly: rows already on the new key are detected and skipped
      (`ALREADY NEW KEY` reflects them on the second run), nothing is
      double-encrypted.
- [ ] Negative — run with a deliberately wrong `--old-key-env` (pointing at
      neither the actual old nor the new key) → the command should abort with
      zero rows written, not partially re-encrypt. This is the
      classify-before-write guarantee — verify via a direct ciphertext check
      (`sqlite3`, compare a row's `value` column before/after) rather than
      trusting the tool's own report alone.
- [ ] Confirm old `rocketvault backup create` files taken before the rotation
      still only restore under the **old** key — they are not migrated by
      this command.
- [ ] Watch for: **the server startup guard only gates `serve`, not CLI
      write-path commands.** `secrets create`/`keys create` run against
      whatever `master_key` is currently configured, even a weak one — this
      is a known, documented gap (`docs/known-bugs.md` § B12), not
      something rotation itself is expected to catch.

#### Worked example: rotating a scratch instance's master key, and the four ways it goes sideways

**New to this repo?** This is a fully self-contained, copy-pasteable
walkthrough — you shouldn't need to read any other file first. It bootstraps
its own admin, seeds one secret, runs a real rotation, then deliberately
triggers each of the four gotchas below so you see the exact error text
before you ever hit it for real.

##### Prerequisites

- A **fresh** scratch config/DB per **§0 Environment Setup** — start from an
  empty `/tmp/rv-test.db` (delete it first if you're reusing one from an
  earlier section).
- `rocketvault` CLI built and on your `PATH` (`go build -o rocketvault .`
  from repo root, or substitute `go run main.go` for every `rocketvault ...`
  command below).
- **The server must not be running against this DB for any step below.**
  Unlike §3.5's worked example, nothing here needs HTTP: `master-key
  rotate`, `users admin`, `users login`, and `secrets create`/`list` all open
  the database directly via `persistentPreRun` (`cmd/root.go:270-272`), the
  same way §2's admin bootstrap does. There's no reason to run `serve` at
  all in this walkthrough, and doing so risks the exact "concurrent write"
  abort the checklist's first bullet above warns about.
- The `ROCKETVAULT_TOTP_SECRET` convention from §2 — you'll set this fresh in
  step 1, since admin is bootstrapped from scratch here rather than reused
  from a prior session.

##### The four gotchas this example is built to surface

All four are real, verified-against-source behaviors — you will hit them if
you don't know about them going in.

1. **An exported `MASTER_KEY` environment variable silently shadows the
   config file, and which of two different error messages you get depends
   on exactly how the shadowed value compares to the "new" key.** Viper's
   `AutomaticEnv()` (`cmd/root.go:128`, no prefix, no key replacer) means
   `viper.GetString("master_key")` — the tool's "old key from config"
   default — transparently returns an exported `MASTER_KEY`'s value instead
   of the file's, with nothing in the output telling you that happened.
   - If the shadowed old key's base64 string is **textually identical** to
     the new key's, `resolveRotationKeys` (`cmd/master_key.go:147-151`)
     catches it before any parsing: `the new master key is identical to the
     old one (old key source: config file (master_key)); note that an
     exported MASTER_KEY environment variable takes precedence over the
     config file`.
   - If the two strings **differ but decode to the same 32 bytes**, that
     check doesn't fire — `ValidateMasterKey` passes it as a normal,
     well-formed key — and it's only caught deeper, by `Rekeyer.Run`'s
     `bytes.Equal(opts.OldKey, opts.NewKey)`
     (`internal/rekey/rekey.go:107-111`), surfaced by the CLI
     (`cmd/master_key.go:221`) as `master key rotation failed: the new
     master key is identical to the old one — nothing to rotate (if
     MASTER_KEY is exported in this shell it takes precedence over the
     config file, so the old key resolved to the new one)`.
2. **After a real rotation, if the config's `master_key` isn't updated, the
   *next* CLI command already fails — no running server required to see
   it.** `EncryptSecret`/`DecryptSecret` (`common/encrypt.go:152-176`) call
   `viper.GetString("master_key")` fresh on every single invocation; nothing
   caches the master key itself. (`internal/cache`/`internal/keycache`
   cache *decrypted secret/key values*, but only inside a long-lived server
   process — a fresh CLI process never has one to mask the desync.) `secrets
   list` is the sharpest detector because it decrypts every row and fails on
   the first bad one (`internal/services/secrets/secret_service.go:369-376`),
   even though its table output doesn't print `Value` at all — the failure
   happens in the service layer, before the formatter ever runs.
3. **The weak-key guard runs on the new key only, before a single row is
   touched.** `common.ValidateMasterKey(newEncoded)`
   (`cmd/master_key.go:157-159`) rejects the known-compromised committed
   default, an all-printable-ASCII key, and a key with fewer than 16
   distinct byte values — all three checked before `resolveRotationKeys`
   even returns, let alone before `Rekeyer.Run` opens a row. This
   walkthrough demonstrates the known-compromised case only; the other two
   reject with the same shape of error, different text
   (`common/masterkey.go:50-60`).
4. **Admin-only is a direct role-equality check, with no vault-scoped escape
   hatch and no override flag.** `requireMasterKeyAdmin`
   (`cmd/master_key.go:100-109`) checks `claims.Role != model.RoleAdmin`
   directly — not `common.HasRequiredRole`, which has a role hierarchy — so
   a `Key Vault Administrator` grant in every vault on the instance does
   nothing here. It's the very first thing `runMasterKeyRotate` does (line
   170), before any key parsing or DB access. Exact error: `forbidden:
   requires admin role`, followed by cobra's full `Usage:` block, since no
   command in this repo sets `SilenceUsage`.

##### Setup

```bash
CFG=/tmp/rv-test.yaml
DB=/tmp/rv-test.db
rm -f "$DB"
cp .rocketvault.yaml "$CFG"
# edit $CFG per §0: database.connection -> /tmp/rv-test.db, and set
# hsm.enabled / oidc.enabled to false if the source file has them on — this
# walkthrough doesn't need SoftHSM2 or a real OIDC issuer, and disabling them
# keeps the rotation report free of HSM rows to explain.
BOOTSTRAP_TOKEN=$(grep '^bootstrap_token:' "$CFG" | cut -d'"' -f2)
```
If `$BOOTSTRAP_TOKEN` comes back empty, the `grep`/`cut` pair only matches a
double-quoted `bootstrap_token: "..."` line — confirm `$CFG` still has one in
that exact form (`grep bootstrap_token "$CFG"`) before continuing; step 1
below fails with an unhelpful bootstrap-token error otherwise.

---

**1. Bootstrap an admin, log in, and grant yourself access to `default`.**
`master-key rotate` needs an authenticated admin session, and — same as any
vault, `default` included — a fresh admin has zero data-plane role grants
until they self-grant one:
```bash
rocketvault --config "$CFG" users admin \
  --admin-username admin --admin-password admin123 \
  --bootstrap-token "$BOOTSTRAP_TOKEN"
```
Capture the `otpauth://...` URL this prints as `OTPAUTH_URL`, export the
secret, and log in:
```bash
export ROCKETVAULT_TOTP_SECRET=$(echo "$OTPAUTH_URL" | sed -n 's/.*secret=\([A-Z2-7]*\).*/\1/p')
TOTP_CODE=$(go run scripts/totp_generator.go 2>&1 | grep -m1 -oP '(?<=--totp-code )\S+')
rocketvault --config "$CFG" users login --username admin --password admin123 --totp-code "$TOTP_CODE"
rocketvault --config "$CFG" vault-access grant admin --role "Key Vault Administrator" --vault default
```
Expect the grant's confirmation: `granted Key Vault Administrator to admin in
vault (assignment <id>)`. Skipping this makes the next step fail with
`forbidden: no role grants Microsoft.KeyVault/vaults/secrets/setSecret/action
in this vault`.

**2. Seed exactly one secret**, so the rotation report below has a small,
easy-to-eyeball row count:
```bash
rocketvault --config "$CFG" secrets create ci-token "s3cr3t-value" --vault default
```
Expect a confirmation table with the new secret's ID, `Version 1`,
`Enabled: true`.

**3. Generate the new key and dry-run the rotation.** Per the checklist
above, name the variable anything but `MASTER_KEY`:
```bash
export NEW_MASTER_KEY="$(openssl rand -base64 32)"
rocketvault --config "$CFG" master-key rotate --new-key-env NEW_MASTER_KEY --dry-run
```
Expect, verbatim (`printRotationReport`, `cmd/master_key.go:237-247`):
```
Old master key source: config file (master_key)
New master key source: environment variable NEW_MASTER_KEY
Mode: DRY RUN (no rows will be written)

TABLE            COLUMN       ROWS  RE-ENCRYPTED  ALREADY NEW KEY  SKIPPED (HSM)
secrets          value        1     1             0                0
secret_versions  value        0     0             0                0
keys             value        0     0             0                0
key_versions     value        0     0             0                0
certificates     private_key  0     0             0                0

Total rows re-encrypted: 1

Dry run complete. No rows were modified.
```

**4. Run it for real, non-interactively:**
```bash
rocketvault --config "$CFG" master-key rotate --new-key-env NEW_MASTER_KEY --yes
```
Expect the identical table with `Mode: REAL RUN (rows will be rewritten)`,
followed by, verbatim (`cmd/master_key.go:228-231`):
```
Rotation complete. Set the new key as master_key in the configuration (or as the MASTER_KEY environment variable) and restart the server.
Reminder: existing database backup files were sealed under the old key and are not affected by this rotation — they will not restore once the old key is retired.
```
(Without `--yes` you'd first see `This rewrites every master-key-encrypted
row in the database.` / `Stop the RocketVault server and take a database
backup before continuing.` / `Type 'yes' to continue:` — declining, or
piping in anything other than `yes`, prints `Aborted.` and exits `0`,
indistinguishable from success at the shell level unless you check the row
counts.)

**5. Resume-safety — cheap proof, no need to actually kill a process
mid-run.** Do this now, **before** touching the config file — run the
identical rotate command a second time:
```bash
rocketvault --config "$CFG" master-key rotate --new-key-env NEW_MASTER_KEY --yes
```
Expect `ALREADY NEW KEY` equal to `ROWS` for every target and `Total rows
re-encrypted: 0` — `classify` (`internal/rekey/classify.go:59-61`) tries the
new key first, so every row is recognized as already migrated. This is what
makes "interrupt mid-run and re-run" (checklist above) safe, without
actually simulating a crash. (Doing this step *after* step 7 below would
instead hit gotcha #1's first case — the config's `master_key` would by then
already equal `$NEW_MASTER_KEY`, so the default old-key-from-config and
`--new-key-env NEW_MASTER_KEY` would be textually identical before the tool
ever gets to classify a single row. Order matters here.)

**6. Gotcha #2, live — try to read before updating the config:**
```bash
rocketvault --config "$CFG" secrets list --vault default
```
Expect:
```
Error: failed to list secrets: error is not retryable: failed to decrypt secret <secret-uuid>: failed to decrypt secret: failed to decrypt: cipher: message authentication failed
```
No server was ever started for this to happen — the CLI process itself
decrypts with whatever `master_key` its own config currently holds, and
that's still the old, already-retired key.

**7. Fix the config and confirm the desync is gone:**
```bash
sed -i "s|^master_key:.*|master_key: \"$NEW_MASTER_KEY\"|" "$CFG"
rocketvault --config "$CFG" secrets list --vault default
```
Expect a normal listing containing `ci-token` (headers `ID`/`Name`/
`Version`/`Enabled`/`Tags`/`Created` — the table never prints `Value`, but
`ListSecrets` decrypts it internally to build each row, which is exactly
what makes this the reliable verification the checklist item above asks
for, stronger than fetching one ID with `secrets get <id>`).

**8. Gotcha #4 — a non-admin can't even attempt this.** Create a plain
`user`-role account and log in as them (this switches the CLI's cached
"current" session):
```bash
rocketvault --config "$CFG" users create \
  --new-username qa-user --new-password qa-password123 --new-role user
```
Capture that command's own `TOTP Secret: otpauth://...` line as
`QA_OTPAUTH_URL`, then log in as `qa-user` without disturbing
`ROCKETVAULT_TOTP_SECRET` (still admin's, needed again in a moment):
```bash
QA_TOTP_SECRET=$(echo "$QA_OTPAUTH_URL" | sed -n 's/.*secret=\([A-Z2-7]*\).*/\1/p')
QA_TOTP_CODE=$(ROCKETVAULT_TOTP_SECRET="$QA_TOTP_SECRET" go run scripts/totp_generator.go 2>&1 | grep -m1 -oP '(?<=--totp-code )\S+')
rocketvault --config "$CFG" users login --username qa-user --password qa-password123 --totp-code "$QA_TOTP_CODE"
rocketvault --config "$CFG" master-key rotate --new-key-env NEW_MASTER_KEY --dry-run
```
Expect:
```
Error: forbidden: requires admin role
```
followed by cobra's full `Usage:` block. Log back in as admin before
continuing — the rest of this walkthrough needs an admin session:
```bash
TOTP_CODE=$(go run scripts/totp_generator.go 2>&1 | grep -m1 -oP '(?<=--totp-code )\S+')
rocketvault --config "$CFG" users login --username admin --password admin123 --totp-code "$TOTP_CODE"
```

**9. Gotcha #3 — the weak-key guard rejects the known-compromised default
before touching a row.** This is the same placeholder every fresh clone's
`.rocketvault.yaml.example` warns about (`docs/known-bugs.md` § B12):
```bash
export WEAK_KEY="MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY="   # base64 of "0123456789abcdef0123456789abcdef"
rocketvault --config "$CFG" master-key rotate --new-key-env WEAK_KEY --dry-run
```
Expect:
```
Old master key source: config file (master_key)
New master key source: environment variable WEAK_KEY
Mode: DRY RUN (no rows will be written)

Error: new master key: master key is the known-compromised default committed to this repository (it decodes to "0123456789abcdef0123456789abcdef"); generate a new key with "openssl rand -base64 32" and migrate existing data with "rocketvault master-key rotate"
```
No table prints — `resolveRotationKeys` fails before `Rekeyer.Run` is ever
called. (The other two guards — all-printable-ASCII, and fewer than 16
distinct byte values — reject with the same shape of error and aren't
reproduced here.)

**10. Gotcha #1, first case — exported `MASTER_KEY` shadows the config,
textually identical to the new key.** Generate one fresh key and, by
mistake, export it under both the reserved name and the flag's named
variable — a very plausible slip if you're used to typing `export
MASTER_KEY=...` out of habit:
```bash
grep '^master_key:' "$CFG"    # confirm the file's real key is NOT $FRESH_KEY below
export FRESH_KEY="$(openssl rand -base64 32)"
export MASTER_KEY="$FRESH_KEY"
export SAME_KEY="$FRESH_KEY"
rocketvault --config "$CFG" master-key rotate --new-key-env SAME_KEY --dry-run
```
Expect:
```
Error: the new master key is identical to the old one (old key source: config file (master_key)); note that an exported MASTER_KEY environment variable takes precedence over the config file
```
even though the `grep` above just showed the file's real key is something
else entirely — proof the shadow, not the file, drove this resolution. The
`old key source` label still says "config file" — the tool has no way to
know its own default was shadowed; that mislabeling is exactly what the
trailing clause is warning you to double-check by hand.

**11. Gotcha #1, second case — same shadow, but the two base64 strings
don't match textually.** The harder variant: two *different-looking* key
strings that decode to the same 32 bytes, because base64's last
pre-padding character has 2 bits of encoding slack that a non-strict decoder
— which is what `ParseMasterKey` (`common/encrypt.go:50`) uses — ignores.
Build one from `$FRESH_KEY` (still exported as `MASTER_KEY` from step 10):
```bash
B64='ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
prefix="${FRESH_KEY%??}"
lastchar="${FRESH_KEY: -2:1}"
idx=$(( $(expr index "$B64" "$lastchar") - 1 ))
altchar="${B64:$(( idx ^ 1 )):1}"
export DIFFERENT_TEXT_SAME_BYTES="${prefix}${altchar}="
[ "$FRESH_KEY" != "$DIFFERENT_TEXT_SAME_BYTES" ] && echo "strings differ, as expected"
rocketvault --config "$CFG" master-key rotate --new-key-env DIFFERENT_TEXT_SAME_BYTES --dry-run
```
Expect the *deeper* guard this time:
```
Old master key source: config file (master_key)
New master key source: environment variable DIFFERENT_TEXT_SAME_BYTES
Mode: DRY RUN (no rows will be written)

Error: master key rotation failed: the new master key is identical to the old one — nothing to rotate (if MASTER_KEY is exported in this shell it takes precedence over the config file, so the old key resolved to the new one)
```
`resolveRotationKeys`'s string-equality check (step 10) doesn't fire this
time because the strings really are different, so both keys pass
`ValidateMasterKey` and parsing — it's only `Rekeyer.Run`'s byte-level
`bytes.Equal` that catches it.

##### Cleanup

```bash
unset MASTER_KEY SAME_KEY WEAK_KEY FRESH_KEY DIFFERENT_TEXT_SAME_BYTES NEW_MASTER_KEY
rocketvault --config "$CFG" users logout
rm -f "$CFG" "$DB" "$DB-journal" "$DB-wal" "$DB-shm"
```

---

## 19. MCP Server (`rocketvault mcp`)

Shipped 2026-08-24. A Model Context Protocol server over **stdio**, exposing the
vault to an MCP host such as Claude Code or Claude Desktop. Guide:
`docs/mcp-server.md`; design:
`docs/superpowers/specs/2026-08-21-mcp-server-design.md`. Configured under the
`mcp:` section of `.rocketvault.yaml` (see §20's block for every key and its
default).

This has no Azure Key Vault counterpart, so it is not a row in
`docs/architecture/azure-keyvault-parity.md` — but it is a real, authenticated surface onto
every resource type, so it belongs in a plan that claims to cover every feature.

**The thing to internalise before testing:** capability gating is *structural*.
A disabled tier's tools are **not registered at all**, so they are absent from the
tool list rather than present-and-refusing. Every "is this tier off?" check below
is therefore a check that the tool is **missing**, not that it returns an error.
The flags are read once at startup, and no code path leads from a tool back to
them.

### 19.1 Preflight

- [ ] `rocketvault mcp --check` → prints the server it will talk to, the identity
      it will act as, whether that identity actually works, and the exact list of
      tools it would expose. Run this after **every** config change below; it is
      the only place a misconfiguration surfaces legibly. Inside a host, the same
      problem appears as an unexplained startup failure.
- [ ] With no identity, `--check` fails fast and tells you how to fix it —
      captured live 2026-09-03:
      ```
      Error: no identity is configured: run `rocketvault users login`, or set
      mcp.client_id and ROCKETVAULT_MCP_CLIENT_SECRET to use a service account
      ```
      Run `rocketvault users login --username admin` first. Real default-posture
      output:
      ```
      RocketVault MCP server preflight

        Server:    http://127.0.0.1:8774
        Identity:  cached session for "admin"
        Vault:     default
        Reachable: yes (2 vault(s) visible)

        Enabled tiers: read
        Max results per list: 50
        Secret values are not returned to the model.

        Exposed tools (10):
          get_certificate / get_key / get_secret / list_certificates /
          list_deleted / list_keys / list_role_assignments / list_secrets /
          list_vaults / query_audit_log
      ```
- [ ] Turn every tier on (`allow_write`, `allow_destructive`, `allow_crypto`,
      `allow_secret_values`, `allow_interactive_login`) → `--check` reports
      `Enabled tiers: read, write, destructive, crypto, login` and
      **`Exposed tools (28)`**, with
      `Secret values CAN be returned to the model (allow_secret_values is on).`
      Verified live 2026-09-03. Note `docs/mcp-server.md` says 27 — the doc is
      off by one; `--check` is authoritative, since it enumerates what
      `RegisterAllTools` actually registered.
- [ ] Register it with a host and confirm the tools appear:
      ```json
      { "mcpServers": { "rocketvault": {
          "command": "/absolute/path/to/rocketvault", "args": ["mcp"] } } }
      ```
      The path **must be absolute** — the host does not resolve it against `PATH`.
      A relative path is the most common first-run failure.

### 19.2 Default posture (everything off)

- [ ] With no `mcp:` changes, `--check` lists **10 read-only tools and no secret
      values**: `list_secrets`, `get_secret`, `list_keys`, `get_key`,
      `list_certificates`, `get_certificate`, `list_deleted`, `list_vaults`,
      `list_role_assignments`, `query_audit_log`.
- [ ] `get_secret` returns metadata, expiry, tags and version history — and **no
      plaintext value**. This is the single most important check in the section:
      a value appearing here with `allow_secret_values: false` is a disclosure bug.
- [ ] Every write/destructive/crypto tool name is **absent** from `--check`'s list.

### 19.3 Each tier, one at a time

Enable one flag, restart, re-run `--check`, confirm exactly the expected tools
appear and nothing else moves. Counts below are from `RegisterAllTools`
(`internal/mcpserver/register.go`) — if a total disagrees with `--check`, trust
`--check` and note the discrepancy.

- [ ] `allow_write: true` → adds 9: `set_secret`, `create_key`, `rotate_key`,
      `set_key_rotation_policy`, `create_certificate`, `set_certificate_policy`,
      `create_vault`, `grant_vault_role`, `recover_deleted`.
- [ ] `allow_destructive: true` → adds 4: `delete_item`, `purge_item`,
      `purge_vault`, `revoke_vault_role`.
- [ ] `allow_crypto: true` → adds 4: `sign`, `verify`, `encrypt`, `decrypt`.
- [ ] `allow_secret_values: true` → adds **no** tool; it changes `get_secret` in
      place so it can return plaintext. Confirm the tool count is unchanged and
      the behavior is not.
- [ ] `allow_interactive_login: true` → adds 1: `login`. Confirm it is absent by
      default, and see §19.5 for why that default matters.

### 19.4 Gating cannot widen authorization

- [ ] **A tier only narrows what the principal's role assignments already allow.**
      Enable `allow_destructive` under an identity holding, say, only
      `Key Vault Secrets User` in the target vault → `purge_item` is registered
      (the tier is on) but every call returns a permission error naming the missing
      data action. The API enforces authorization independently; the flags are not
      an authorization layer and must never be tested as one.
- [ ] `allowed_vaults: [default]` with `vault: default` → tools that name a
      different vault are refused. Confirm `vault` must itself be a member of
      `allowed_vaults` when that list is non-empty.
- [ ] `max_results: 50` caps rows per list tool; the hard ceiling is **200**. Ask
      for more than 200 → clamped, not honoured. Verify against `query_audit_log`
      specifically, which is the tool that would otherwise pour thousands of rows
      into a model's context.
- [ ] `rate_limit.reads_per_minute` / `writes_per_minute` → a looping agent
      degrades its own calls, not the vault. Confirm exceeding a bucket fails the
      tool call rather than reaching the API.
- [ ] `request_timeout` is a per-tool-call deadline — confirm a slow call fails at
      the deadline instead of hanging the host.

### 19.5 Identity and audit

- [ ] By **default** the server reuses the cached CLI session (§3.4), so the agent
      acts as the logged-in human and its actions are indistinguishable from theirs
      in the audit log. Confirm that is what happens — then set
      `require_service_account: true`, confirm the cached session is now **refused**
      and a service account (§3.5) is required. This is the production posture; the
      audit-trail consequence is the reason.
- [ ] `ROCKETVAULT_MCP_CLIENT_SECRET` takes precedence over `mcp.client_secret` in
      the config file. Set both to different values and confirm the env var wins,
      so the secret need never be written to disk.
- [ ] `confirm_destructive: true` (the default) makes destructive tools echo the
      exact resource name before acting. Call one with a wrong or missing name →
      refused. Leave this on: it costs one argument and blocks a drive-by purge
      triggered by injected text.
- [ ] Every MCP tool call is audit-logged like any other API call. After a session,
      cross-check §12's audit queries and confirm the calls appear with a sensible
      actor.
- [ ] The server writes structured logs to **stderr**, one line per tool call, with
      the tool name, outcome, duration and a correlation ID. Confirm that ID also
      appears on the corresponding audit entry — that link is what makes a tool call
      traceable end to end.

**Watch for:** a tool you expected is missing → its tier is off, and `--check`
lists both the enabled tiers and every exposed tool. A tool returning a permission
error names the missing data action — that is the API's authorization, working as
designed, not a gating bug.

---

## 20. Configuration Reference (`.rocketvault.yaml`)

This is a copy of the committed `.rocketvault.yaml.example` template — the
one you actually get via `cp .rocketvault.yaml.example .rocketvault.yaml`
during first-time setup (see the project README / CLAUDE.md). **Never use
the live `.rocketvault.yaml`** as a reference source for a doc like this —
it holds real, currently-active secret values (`master_key`,
`bootstrap_token`) once a real instance is bootstrapped, and copying those
into a tracked file is exactly the incident `docs/known-bugs.md` § B10
describes.

This block is a point-in-time copy for quick reference; if it looks out of
sync with the two `GENERATE_WITH` placeholders or any section below, treat
`.rocketvault.yaml.example` in the repo root as the source of truth and
refresh this copy from it.

```yaml
# Copy this file to .rocketvault.yaml and fill in every secret value before
# running RocketVault:
#
#   cp .rocketvault.yaml.example .rocketvault.yaml
#   # then replace the two GENERATE_WITH placeholders below
#
# Generate random secrets with:
#   openssl rand -base64 32
#
# NEVER commit .rocketvault.yaml to version control — it is already in
# .gitignore. See docs/known-bugs.md (search "B10") and
# docs/security/security-incident-2026-03-07.md for what happens when a config file
# like this one gets committed anyway.

# Development Environment Configuration
# Optimized for local development and testing

# Security Configuration
# 32 random bytes, base64-encoded. Losing this key makes every stored secret
# permanently unrecoverable — back it up somewhere safe (a password manager or
# secrets vault, not another git-tracked file).
master_key: "GENERATE_WITH: openssl rand -base64 32"

# JWT signing configuration (asymmetric — RS256/ES256, no shared secret).
jwt:
  key_source: "os_store"      # os_store | self_pki | external_pki
  key_cn: "rocketvault"       # CN to search for in OS cert store
  expiry: "1h"                # token TTL
  rotation_overlap: "1h"      # old key stays in JWKS this long after rotation
  signing_key_file: ""        # ExternalPKIProvider: path to PEM private key file

# One-time token consumed by `rocketvault users admin` to bootstrap the first
# admin account. Rotate it again after that first run (set to "" or remove the
# line — seedBootstrapToken() only seeds it once).
bootstrap_token: "GENERATE_WITH: openssl rand -base64 32"

# Environment configuration affects database pool settings
environment: "development"

# Database Configuration
database:
  connection: "./dev-rocketvault.db"
  driver: "sqlite3"
  # Supported drivers: "sqlite3" (default, local file) and "postgres".
  #
  # PostgreSQL example (URL form):
  #   driver: "postgres"
  #   connection: "postgres://user:password@localhost:5432/rocketvault?sslmode=require"
  #
  # PostgreSQL example (DSN keyword form):
  #   driver: "postgres"
  #   connection: "host=localhost port=5432 user=rv password=secret dbname=rocketvault sslmode=require"
  #
  # sslmode options (Postgres): disable, require, verify-ca, verify-full.
  # Use "require" or stronger in production. If driver is omitted, it is
  # inferred from the connection string shape.

# Logging Configuration
log:
  level: "debug"
  file: "./logs/development.log"
  format: "text"
  pretty_print: true
  max_backups: 3
  max_age_days: 7
  max_size_mb: 10
  rotation_method: "size"

# Rate Limiting Configuration
rate_limit:
  default: 300  # requests per minute per IP for all endpoints
  auth: 5       # requests per minute per IP for login/refresh/oauth2 endpoints
  # Requests per minute per VAULT, across every caller of that vault. This is
  # the noisy-neighbour guard: without it one busy vault can spend the whole
  # instance's request budget. Applies to every authenticated API route after
  # the vault is resolved; health probes are exempt. Routes that resolve no
  # vault of their own (vault management, legacy flat resource paths) count
  # against the default vault. Rejections return 429 and are reported under the
  # X-RateLimit-Vault-* response headers.
  per_vault: 600

# Server Configuration
server:
  listen_addr: ":8774"
  read_timeout: "30s"
  write_timeout: "30s"
  idle_timeout: "120s"
  cors_allowed_origins:
    - "http://localhost:3000"
    # Add your own frontend origin(s) here.
  http2:
    enabled: true   # HTTP/2 is enabled by default.
  tls:
    enabled: false     # Set true with cert_file/key_file to enable HTTPS.
    cert_file: ""      # Path to PEM TLS certificate.
    key_file: ""       # Path to PEM TLS private key.

# Performance Monitoring
monitoring:
  enable_metrics: true
  metrics_interval: "60s"
  slow_query_threshold: "500ms"

# Rotation scheduler intervals for secrets, certificates, and keys. This
# section is optional -- omitting it entirely is equivalent to the defaults
# shown below. secrets/certificates defaults match this file's previous
# hardcoded behavior (1h / 24h); keys is a new capability as of this
# section's introduction (key rotation policies were CRUD-only before, with
# nothing executing them), enabled by default since it closes a real
# security gap rather than changing existing behavior.
rotation:
  secrets:
    enabled: true
    interval: "1h"
  certificates:
    enabled: true
    interval: "24h"
  keys:
    enabled: true
    interval: "1h"

# Health Check Configuration
health:
  check_interval: "60s"
  database_timeout: "10s"
  enable_detailed_metrics: true

# Development-specific features
development:
  enable_debug_endpoints: true
  detailed_error_responses: true
  cors_enabled: true

# Retry Logic Configuration
retry:
  database:
    enabled: true
    max_attempts: 2
    initial_delay: "50ms"
    max_delay: "1s"
    backoff_multiplier: 2.0
    retryable_errors:
      - "connection refused"
      - "database is locked"
      - "busy"
      - "timeout"
    jitter_enabled: true

  external_services:
    enabled: true
    max_attempts: 3
    initial_delay: "100ms"
    max_delay: "5s"
    backoff_multiplier: 2.0
    retryable_errors:
      - "connection refused"
      - "no such host"
      - "timeout"
      - "temporary failure"
      - "service unavailable"
      - "too many requests"
      - "internal server error"
      - "bad gateway"
    jitter_enabled: true

  interactive:
    enabled: true
    max_attempts: 2
    initial_delay: "250ms"
    max_delay: "2s"
    backoff_multiplier: 2.0
    retryable_errors:
      - "connection refused"
      - "no such host"
      - "timeout"
      - "temporary failure"
      - "service unavailable"
      - "too many requests"
      - "internal server error"
      - "bad gateway"
    jitter_enabled: true

  service_operations:
    enabled: true
    max_attempts: 2
    initial_delay: "100ms"
    max_delay: "1s"
    backoff_multiplier: 1.5
    retryable_errors:
      - "connection refused"
      - "timeout"
      - "temporary failure"
    jitter_enabled: true

  circuit_breaker:
    failure_threshold: 3
    timeout: "30s"
    half_open_requests: 2

soft_delete:
  enabled: true
  retention_days: 30
  purge_protection: false

# Unified cache config for secrets, keys, vaults, and (reserved for future
# use) certificates/users. See docs/superpowers/specs/2026-08-14-generic-cache-config-design.md.
cache:
  secrets:
    enabled: true
    ttl: "5m"
    cleanup_interval: "1m"
    max_entries: 1000
  keys:
    enabled: true
    ttl: "60s"
    cleanup_interval: "30s"
    max_entries: 500
  vaults:
    enabled: true
    ttl: "5m"
    cleanup_interval: "1m"
    max_entries: 500
  certificates:
    enabled: false
    ttl: "5m"
    cleanup_interval: "1m"
    max_entries: 500
  users:
    enabled: false
    ttl: "5m"
    cleanup_interval: "1m"
    max_entries: 500

oauth2:
  token_expiry: "30m"
  issuer: "http://localhost:8774"  # production: your real HTTPS issuer URL

# OIDC login is additive to local username/password/TOTP and disabled by
# default. Set enabled: true and fill in your issuer's real values to turn it
# on — see CLAUDE.md's OIDCService note for exactly what happens at startup
# when it's on.
oidc:
  enabled: false
  issuer_url: ""
  client_id: ""
  client_secret: ""
  redirect_url: ""
  scopes: ["openid", "profile", "email"]
  # Path to a PEM-encoded CA certificate to trust in addition to the system
  # store, for issuers whose TLS certificate is signed by a private CA. Leave
  # unset to use the system trust store only.
  ca_cert_path: ""

# Vault client configuration for secret consumption.
# Used by OTHER applications that need to fetch secrets from this RocketVault
# instance. RocketVault does NOT fetch from itself — leave client_id empty on
# the vault server itself. client_secret is intentionally absent here — set
# the VAULT_CLIENT_SECRET environment variable instead.
vault_client:
  url: "http://localhost:8774"
  client_id: ""  # service account NAME (not UUID) — leave empty on the vault server itself
  secrets: []
  # Example entry once you have a real secret to consume:
  #   secrets:
  #     - name: DB_PASSWORD
  #       uuid: "<secret-uuid-from-this-vault>"
  #       viper_key: "database.password"

# Frontend configuration exposed via GET /api/v1/config
frontend:
  public_api_url: "http://localhost:8774"
  sentry_dsn: ""

# HSM / PKCS#11 configuration.
# Set hsm.enabled: true and configure lib_path, token_label, and pin to route
# all key generation and crypto operations through a hardware security module
# or SoftHSM2. When disabled (default), the built-in Go crypto path is used
# and all keys are stored as AES-GCM encrypted PEM in the database.
#
# Dev/test setup with SoftHSM2:
#   sudo apt install softhsm2
#   softhsm2-util --init-token --slot 0 --label rocketvault --pin <your-pin> --so-pin <your-so-pin>
#
# Rotating an existing token's PIN is a separate manual procedure — see
# docs/runbooks/hsm-pin-rotation.md. Never reuse a PIN that was ever committed
# to version control.
hsm:
  enabled: false
  lib_path: /usr/lib/softhsm/libsofthsm2.so
  token_label: rocketvault
  pin: "GENERATE_WITH: a PIN of your choosing, never committed"
  slot_id: 0   # 0 = auto-detect by token_label

# Model Context Protocol server (`rocketvault mcp`).
#
# Every capability below defaults to false. With no changes, the server exposes
# 10 read-only tools and no secret values. Each flag only narrows what the
# authenticated principal's role assignments already permit -- it can never
# widen them, because the API enforces authorization independently.
mcp:
  # Default vault for tools that do not name one.
  vault: default

  # Pin the server to specific vaults. Empty means any vault the principal can
  # reach. If set, `vault` above must be one of these.
  allowed_vaults: []

  # Capability tiers. Each is independent.
  allow_write: false          # create and update: set_secret, create_key, ...
  allow_destructive: false    # delete, purge, revoke
  allow_crypto: false         # sign, verify, encrypt, decrypt
  allow_secret_values: false  # let get_secret return plaintext
  allow_interactive_login: false  # let a chat message log in as a different user

  # Refuse the cached CLI session and require a service account. Set this true
  # in production: under a session the agent acts as the logged-in human, and
  # its actions become indistinguishable from theirs in the audit log.
  require_service_account: false

  # Require destructive tools to echo the exact resource name. Leave this on
  # unless you have a specific reason: it costs one argument and blocks a
  # drive-by purge triggered by injected text.
  confirm_destructive: true

  # Cap rows returned per list tool. Hard ceiling is 200 -- an unbounded audit
  # query would otherwise pour thousands of rows into the model's context.
  max_results: 50

  # Per-tool-call deadline.
  request_timeout: "30s"

  # Bound how fast tools may be called, so a looping agent degrades its own
  # calls rather than the vault.
  rate_limit:
    reads_per_minute: 120
    writes_per_minute: 20

  # Service-account credentials. Prefer the environment variable
  # ROCKETVAULT_MCP_CLIENT_SECRET, which takes precedence over the value here,
  # so the secret need not be written to disk at all.
  #
  # Never commit a real secret to this example file.
  client_id: ""
  client_secret: ""
```

---

## Wrap-up

- [ ] Re-run `go test ./...` once more after manual testing — manual testing
      shouldn't have needed any code changes, but if you touched code to work
      around something, confirm you didn't break the suite.
- [ ] File anything unexpected in `docs/known-bugs.md` following its existing
      format (Status/Severity/File/root-cause/fix-recipe) rather than a scratch
      note — that file is the living source of truth for bug status.
- [ ] Delete the scratch config/DB (`/tmp/rv-test.yaml`, `/tmp/rv-test.db`,
      `/tmp/rv-backup*.backup`) when done.
