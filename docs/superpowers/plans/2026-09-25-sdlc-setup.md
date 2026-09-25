# SDLC Gaps Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close the three SDLC gaps identified against Anthropic's AI-Native SDLC playbook: an advisory security-review CI pass, an unattended PR/CI watchdog, and a committed pre-design `intent.md` convention.

**Architecture:** Three independent, additive deliverables — a new GitHub Actions workflow file, a cloud-hosted routine created via the `schedule` skill's `RemoteTrigger` tool (not a repo file), and two new documentation files plus one CLAUDE.md pointer line. None of the three depend on each other's output; they can be done in any order, but are ordered docs-first since they're the cheapest to verify.

**Tech Stack:** GitHub Actions (YAML), `anthropics/claude-code-action`, Anthropic cloud routines (`RemoteTrigger` tool), Markdown.

**Spec:** [docs/superpowers/specs/2026-09-25-sdlc-setup-design.md](../specs/2026-09-25-sdlc-setup-design.md)

## Global Constraints

- Security-review workflow must be **advisory only** — never fails the CI check or blocks merge, regardless of findings (spec §1).
- Security-review workflow reuses the exact pinned action SHAs already vetted in `.github/workflows/claude-review.yml`: `actions/checkout@11d5960a326750d5838078e36cf38b85af677262` (v4) and `anthropics/claude-code-action@9171db3e57d6a3140a37ddc2ba92788584e0ead6` (v1) — do not fetch different pins.
- PR watchdog routine must **never** push commits, merge, or resolve review threads — report-only except for re-running flaky CI (spec §2).
- PR watchdog cadence is every 2 hours, cron `7 */2 * * *` UTC, environment `env_012TzmZwUFxmRiLWZhVkBk4u` (Default) — both explicit user choices, not defaults to reconsider.
- `intent.md` convention is documentation-only — do not modify the shared `superpowers:brainstorming` plugin skill (spec §3).
- Out of scope (do not touch): re-enabling the disabled `Lint`/`Security Scan` jobs in `.github/workflows/go.yml`, backfilling `intent.md` for past work, any form of proactive/autonomous bug-hunting beyond the exact watchdog scope above.

## Review Focus

- **A PR with zero findings**: the security-review prompt must still post a short "no findings" comment, not silence — a missing comment reads as "the check didn't run," not "it's clean" (spec §1, "If there are no HIGH or MEDIUM severity findings, post a short one-line comment saying so").
- **A draft PR**: `security-review.yml`'s `if: github.event.pull_request.draft == false` must actually suppress the job on drafts, matching `claude-review.yml`'s existing behavior — verified by the YAML structure matching, not a live test (no draft-PR test available in this plan).
- **The watchdog's very first run**: must be checked via `get_run_log` before trusting the schedule at all — if `gh` commands come back permission-denied in the cloud sandbox, the routine is silently useless every 2 hours until someone notices. This is Task 3's explicit verification step, not an assumption.
- **Re-running the same flaky check repeatedly**: the watchdog prompt does not cap retries — a check that is flaky on every attempt (not just transiently) would get re-run every single 2-hour cycle forever. Not fixed in this pass (spec doesn't ask for a retry cap); flagged here so a future session investigating "why does this PR have 40 rerun events" finds the answer already written down.
- **CLAUDE.md's docs index growing unbounded**: adding the `intent-convention.md` pointer must go in the existing index list, matching its established one-line-per-doc style, not as a new freeform paragraph — otherwise the index stops being skimmable (see CLAUDE.md's own `Additional Documentation` section for the pattern to match).

---

## Task 1: `intent.md` convention documentation

**Files:**
- Create: `.claude/intent-convention.md`
- Modify: `CLAUDE.md` (add one line to the `## Additional Documentation` section, after the `Setup Guide` entry)

**Interfaces:**
- Consumes: nothing (pure docs).
- Produces: the convention doc other sessions read before starting brainstorming's architectural path. `docs/superpowers/intents/2026-09-25-sdlc-setup.md` (already committed in `20d64c7`) is referenced as the worked example.

- [ ] **Step 1: Write `.claude/intent-convention.md`**

```markdown
# Intent Convention

Before brainstorming's **architectural** path begins its design conversation
for a new feature or subsystem, write and commit a short intent file first:
`docs/superpowers/intents/YYYY-MM-DD-<topic>.md`.

Bounded and spike work do not get one — only architectural-path work, the
same scope that already gets a written spec.

## Shape

Four short sections, a few sentences each:

- **What** — the concrete ask, in plain terms.
- **Why** — the motivation. What breaks or stays missing if this isn't done?
- **Scope** — the specific deliverables this pass covers.
- **Out of scope** — adjacent things explicitly *not* covered, so a later
  session doesn't assume they were considered and rejected silently, or
  redo work that was deliberately deferred.

## When

Written and committed *before* the design conversation starts, not
alongside or after the spec. It's the anchor the spec argues from — if the
"why" is unclear when the spec is being written, that's a sign to go back
and clarify the intent first, not to skip it.

## Example

[docs/superpowers/intents/2026-09-25-sdlc-setup.md](../docs/superpowers/intents/2026-09-25-sdlc-setup.md)
is the first file written under this convention — it's also the intent
behind the convention itself.
```

- [ ] **Step 2: Add the CLAUDE.md pointer**

In `CLAUDE.md`, find this existing line inside `## Additional Documentation`:

```markdown
- **[Setup Guide](doc/setup.md)**: Installation and initial configuration
```

Add immediately after it:

```markdown
- **[Intent Convention](.claude/intent-convention.md)**: Before brainstorming's architectural path starts designing, write a short `docs/superpowers/intents/YYYY-MM-DD-<topic>.md` first — what/why/scope/out-of-scope, a few sentences each
```

- [ ] **Step 3: Verify the link resolves**

Run: `test -f /home/numericlabs/data/rocket/rocketvault/.claude/intent-convention.md && echo "convention file exists"`
Run: `grep -n "Intent Convention" /home/numericlabs/data/rocket/rocketvault/CLAUDE.md`
Expected: both commands print output (the file exists; the CLAUDE.md line was added).

Run: `grep -n "intents/2026-09-25-sdlc-setup.md" /home/numericlabs/data/rocket/rocketvault/.claude/intent-convention.md`
Expected: prints the "Example" line — confirms the relative link path (`../docs/superpowers/intents/...` from `.claude/`) is written correctly relative to the file's own location.

- [ ] **Step 4: Commit**

Use the `dev-workflow-skills:1-git-commit` skill (per this project's CLAUDE.md — never a freeform `git commit -m`) to commit:
```
.claude/intent-convention.md
CLAUDE.md
```

---

## Task 2: Advisory security-review CI workflow

**Files:**
- Create: `.github/workflows/security-review.yml`

**Interfaces:**
- Consumes: nothing (standalone workflow file).
- Produces: nothing other tasks depend on.

- [ ] **Step 1: Write `.github/workflows/security-review.yml`**

```yaml
name: Claude Security Review

on:
  pull_request:
    types: [opened, synchronize, ready_for_review, reopened]
    branches: [v-4.0.0, main]

concurrency:
  group: claude-security-review-${{ github.event.pull_request.number }}
  cancel-in-progress: true

jobs:
  security-review:
    if: github.event.pull_request.draft == false
    runs-on: ubuntu-latest
    permissions:
      contents: read
      pull-requests: write
      issues: read
      id-token: write
    steps:
      - name: Checkout
        uses: actions/checkout@11d5960a326750d5838078e36cf38b85af677262 # v4
        with:
          fetch-depth: 0

      - name: Claude Security Review
        uses: anthropics/claude-code-action@9171db3e57d6a3140a37ddc2ba92788584e0ead6 # v1
        with:
          claude_code_oauth_token: ${{ secrets.CLAUDE_CODE_OAUTH_TOKEN }}
          prompt: |
            /security-review

            After completing the review, post the full markdown report as a
            single comment on PR #${{ github.event.pull_request.number }} in
            ${{ github.repository }} via `gh pr comment`. If there are no
            HIGH or MEDIUM severity findings, post a short one-line comment
            saying so instead of an empty report. This check is advisory
            only -- never fail this job or block the merge regardless of
            findings.
          claude_args: '--allowedTools "Bash(gh pr view:*),Bash(gh pr diff:*),Bash(gh pr comment:*)"'
```

Note on `fetch-depth: 0` vs. `claude-review.yml`'s `fetch-depth: 1`: `/security-review`'s own prompt template runs `git status`/`git diff` against the PR's merge base to build its report, which needs real history — a 1-commit shallow clone would make that diff empty or wrong.

- [ ] **Step 2: Validate YAML syntax**

Run:
```bash
python3 -c "import yaml; yaml.safe_load(open('/home/numericlabs/data/rocket/rocketvault/.github/workflows/security-review.yml'))" && echo "YAML OK"
```
Expected: `YAML OK` with no exception.

- [ ] **Step 3: Compare structure against the existing review workflow**

Run:
```bash
diff <(grep -E "^(on:|types:|branches:|concurrency:|group:|cancel-in-progress:|runs-on:|if:)" /home/numericlabs/data/rocket/rocketvault/.github/workflows/claude-review.yml) \
     <(grep -E "^(on:|types:|branches:|concurrency:|group:|cancel-in-progress:|runs-on:|if:)" /home/numericlabs/data/rocket/rocketvault/.github/workflows/security-review.yml)
```
Expected: no output, or only differences in the `group:` line (which intentionally uses `claude-security-review-` instead of `claude-review-` as its prefix) — confirms the two workflows share the same trigger/concurrency/draft-skip shape.

- [ ] **Step 4: Confirm the zero-findings instruction survived**

Run:
```bash
grep -q "HIGH or MEDIUM severity findings" /home/numericlabs/data/rocket/rocketvault/.github/workflows/security-review.yml && echo "zero-findings instruction present"
```
Expected: `zero-findings instruction present`. This pins the specific requirement that a clean PR still gets a short comment (not silence, which would read as "the check didn't run") — there's no way to test this against a live PR from within this plan, so this grep is the closest available check that the instruction text wasn't lost or reworded away during Step 1.

- [ ] **Step 5: Commit**

Use the `dev-workflow-skills:1-git-commit` skill to commit:
```
.github/workflows/security-review.yml
```

- [ ] **Step 6: Note the live-fire verification (not a plan step — informational)**

This workflow will run for real the first time this branch's own pull request opens (once Task 1-3 are all committed and pushed), since GitHub Actions evaluates workflow files present in the PR branch. No separate test PR is needed in this plan — watch that PR's checks after opening it.

---

## Task 3: PR/CI watchdog cloud routine + discoverability doc

**Files:**
- Create: `.claude/pr-watchdog.md`

**Interfaces:**
- Consumes: the `RemoteTrigger` tool (load via `ToolSearch select:RemoteTrigger` if not already loaded in the current session).
- Produces: a routine ID, recorded in `.claude/pr-watchdog.md` after creation.

- [ ] **Step 1: Load the RemoteTrigger tool**

Call `ToolSearch` with `query: "select:RemoteTrigger"`, `max_results: 1`.
Expected: the tool's full schema is returned and it becomes callable.

- [ ] **Step 2: Create the routine**

Call `RemoteTrigger` with `action: "create"` and this exact body (generate a fresh lowercase v4 UUID for `events[].data.uuid` — do not reuse the example below):

```json
{
  "name": "rocketvault-pr-watchdog",
  "cron_expression": "7 */2 * * *",
  "enabled": true,
  "job_config": {
    "ccr": {
      "environment_id": "env_012TzmZwUFxmRiLWZhVkBk4u",
      "session_context": {
        "model": "claude-sonnet-5",
        "sources": [
          {"git_repository": {"url": "https://github.com/Snehal1112/rocketvault"}}
        ],
        "allowed_tools": ["Bash", "Read", "Grep"]
      },
      "events": [
        {"data": {
          "uuid": "GENERATE-A-FRESH-V4-UUID-HERE",
          "session_id": "",
          "type": "user",
          "parent_tool_use_id": null,
          "message": {
            "role": "user",
            "content": "You are a PR/CI watchdog for Snehal1112/rocketvault. For every open pull request: check CI status (`gh pr checks`), unresolved review threads, and whether the branch has fallen behind its base.\n\nFor any failed check that looks flaky (timeout, runner died, transient network error -- inspect the failing job's log via `gh run view --log-failed`), re-run it with `gh run rerun --failed`. Do this automatically, no confirmation needed.\n\nFor everything else worth a human's attention -- a real (non-flaky) CI failure, an unresolved review thread, a branch significantly behind its base -- post one summary comment on that PR describing what you found and what you recommend, unless you already posted a comment saying the same thing on a previous run (check recent PR comments first to avoid duplicate noise).\n\nDo not modify code, push commits, resolve review threads, or merge anything. Do not comment on a PR with nothing to report. Keep comments concise."
          }
        }}
      ]
    }
  }
}
```

Expected: the call returns a routine ID (shape `trigger_...` or similar). Record it — it's needed for the next steps and for `.claude/pr-watchdog.md`.

- [ ] **Step 3: Run it once immediately to verify GitHub write access**

Call `RemoteTrigger` with `action: "run"`, `trigger_id: "<the ID from Step 2>"`.

Then call `RemoteTrigger` with `action: "list_runs"`, `trigger_id: "<the ID>"` to get the new run's `session_id`.

Then call `RemoteTrigger` with `action: "get_run_log"`, `session_id: "<that session_id>"`.

Expected: the log shows successful `gh pr checks` / `gh run view` / `gh pr comment` calls (if it had anything to report) with no permission-denied or authentication errors. **If the log shows a `gh` auth failure**, stop here and report it — the routine is not usable until write access is resolved (this is outside this plan's scope; it needs GitHub credentials configured for the cloud environment, which cannot be done from this session).

- [ ] **Step 4: Write `.claude/pr-watchdog.md`**

```markdown
# PR/CI Watchdog

A scheduled Anthropic cloud routine, not a file in this repository -- it
runs independently of any local Claude Code session.

- **Name**: `rocketvault-pr-watchdog`
- **Routine**: https://claude.ai/code/routines/<ROUTINE-ID-FROM-STEP-2>
- **Cadence**: every 2 hours (`7 */2 * * *` UTC)
- **Environment**: Default (`env_012TzmZwUFxmRiLWZhVkBk4u`)
- **Scope**: for every open PR on `Snehal1112/rocketvault`, checks CI
  status, unresolved review threads, and how far behind base the branch
  is. Automatically re-runs CI checks it judges flaky (timeout, runner
  died, transient network). Everything else -- real failures, stale
  review threads, a branch far behind base -- gets a summary comment,
  not an automatic fix.
- **Explicitly does not**: push commits, resolve review threads, or
  merge anything. This is a deliberate scope limit (see
  `docs/superpowers/specs/2026-09-25-sdlc-setup-design.md` §2) --
  broadening it is a decision for a future session, not an assumed
  next step.
- **To change or inspect**: use the `schedule` skill (`RemoteTrigger`
  tool) -- `list`/`get` to inspect, `update` to change cadence/prompt,
  `list_runs`/`get_run_log` to debug a misfire. Routines cannot be
  deleted from this tool; use https://claude.ai/code/routines for that.
```

Replace `<ROUTINE-ID-FROM-STEP-2>` with the real ID before committing.

- [ ] **Step 5: Commit**

Use the `dev-workflow-skills:1-git-commit` skill to commit:
```
.claude/pr-watchdog.md
```
