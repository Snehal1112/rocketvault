# Design: Close three SDLC gaps (security-review gate, PR watchdog, intent.md convention)

**Intent**: [docs/superpowers/intents/2026-09-25-sdlc-setup.md](../intents/2026-09-25-sdlc-setup.md)

## 1. Security-review CI gate

**File**: `.github/workflows/security-review.yml` (new)

Mirrors `.github/workflows/claude-review.yml`'s structure exactly (same
trigger events, branch filter, concurrency group pattern, draft-skip), so it
behaves consistently with the existing PR-review workflow developers already
know:

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
      pull-requests: write   # write: this job posts its own PR comment via gh,
                              # unlike claude-review.yml which only reads because
                              # its plugin posts inline comments through its own
                              # GitHub App auth, not gh CLI.
      issues: read
      id-token: write
    steps:
      - name: Checkout
        uses: actions/checkout@<pinned-sha> # v4
        with:
          fetch-depth: 0   # security-review diffs against the base branch;
                            # needs real history, not a 1-commit shallow clone.

      - name: Claude Security Review
        uses: anthropics/claude-code-action@<pinned-sha> # v1
        with:
          claude_code_oauth_token: ${{ secrets.CLAUDE_CODE_OAUTH_TOKEN }}
          prompt: |
            /security-review

            After completing the review, post the full markdown report as a
            single comment on PR #${{ github.event.pull_request.number }} in
            ${{ github.repository }} via `gh pr comment`. If there are no
            HIGH or MEDIUM severity findings, post a short one-line comment
            saying so instead of an empty report. This check is advisory
            only — never fail this job or block the merge regardless of
            findings.
          claude_args: '--allowedTools "Bash(gh pr view:*),Bash(gh pr diff:*),Bash(gh pr comment:*)"'
```

**Key decisions**:
- `fetch-depth: 0`, not `1` like `claude-review.yml` — `/security-review`'s
  own prompt template runs `git status`/`git diff` against the PR's merge
  base, which needs real history. Verified by invoking `/security-review`
  directly in this session: its prompt gathers `git status`, modified files,
  commits, and full diff content itself, with no PR-link argument (unlike
  `/code-review:code-review --comment <repo>/pull/<n>`).
- `/security-review`'s own contract ends with "Your final reply must contain
  the markdown report and nothing else" — it does **not** post comments on
  its own the way `/code-review --comment` does. The wrapping prompt above
  explicitly instructs the extra step (`gh pr comment`) to get the same
  visible-on-the-PR behavior.
- Advisory only, per Snehal's choice: the job's own exit status is never
  tied to findings. A separate future decision (not in this pass) could make
  specific high-confidence categories blocking.
- No `plugin_marketplaces`/`plugins` input: unlike `code-review` (pulled
  from the `claude-code-plugins` marketplace), `security-review` is a
  built-in Claude Code skill, confirmed by its absence from
  `~/.claude/plugins/` on disk and its lack of a namespace prefix in the
  skill listing.

## 2. Maintain-phase PR/CI watchdog (cloud routine)

Not a repository file — created via the `schedule` skill (`RemoteTrigger`
tool) as an Anthropic-hosted cloud routine, independent of any local
session. Documented in `.claude/pr-watchdog.md` (new) for discoverability,
since nothing in the repo itself shows it exists otherwise.

**Configuration**:
- Name: `rocketvault-pr-watchdog`
- Cadence: every 2 hours, cron `7 */2 * * *` UTC (off-mark per scheduling
  convention)
- Environment: Default (`env_012TzmZwUFxmRiLWZhVkBk4u`)
- Repo source: `https://github.com/Snehal1112/rocketvault`
- Allowed tools: `Bash`, `Read`, `Grep` (gh CLI runs through Bash)

**Prompt** (self-contained — the cloud session starts with zero context):

> You are a PR/CI watchdog for `Snehal1112/rocketvault`. For every open pull
> request: check CI status (`gh pr checks`), unresolved review threads, and
> whether the branch has fallen behind its base.
>
> For any failed check that looks flaky (timeout, runner died, transient
> network error — inspect the failing job's log via
> `gh run view --log-failed`), re-run it with `gh run rerun --failed`. Do
> this automatically, no confirmation needed.
>
> For everything else worth a human's attention — a real (non-flaky) CI
> failure, an unresolved review thread, a branch significantly behind its
> base — post one summary comment on that PR describing what you found and
> what you recommend, unless you already posted a comment saying the same
> thing on a previous run (check recent PR comments first to avoid
> duplicate noise).
>
> Do not modify code, push commits, resolve review threads, or merge
> anything. Do not comment on a PR with nothing to report. Keep comments
> concise.

**Key decisions**:
- Autonomy level per Snehal's choice: fixes only the fully-reversible,
  no-code-change action (CI re-run); everything else is report-only. Matches
  the playbook's own "agent does everything up to the production gate, never
  crosses it" principle, applied conservatively for a solo-maintained
  secrets-vault project.
- **Untested assumption, flagged explicitly**: whether the cloud sandbox's
  `gh` CLI has write access (posting comments, viewing run logs, re-running
  jobs) to a repo it only received as a `git_repository` source is unknown
  until the routine actually runs. The implementation plan must include a
  manual "run once, inspect the log via `get_run_log`" verification step
  right after creation, before trusting the recurring schedule.
- Cadence and environment are both Snehal's explicit picks (every 2 hours;
  Default environment, since "Rocketapp" is unconfirmed as
  RocketVault-specific).

## 3. `intent.md` convention

**Files**:
- `docs/superpowers/intents/` (new directory) — one file per architectural
  design, `YYYY-MM-DD-<topic>.md`, written *before* brainstorming's design
  conversation for that topic begins.
- `.claude/intent-convention.md` (new) — describes the convention itself:
  what goes in an intent file (What/Why/Scope/Out-of-scope, a few sentences
  each), when to write one (start of brainstorming's architectural path
  only — bounded and spike paths don't get one), and that it's committed
  before the spec, not alongside it.
- `CLAUDE.md` gets one new line in its docs index pointing at
  `.claude/intent-convention.md`, matching the existing pattern for
  `multi-vault.md`/`azure-keyvault-parity.md`/etc.
- `docs/superpowers/intents/2026-09-25-sdlc-setup.md` (already written, this
  pass's own intent) serves as the first worked example the convention doc
  points to.

**Key decision**: this is a **documentation-only** convention, not a skill
or hook. It does not modify `superpowers:brainstorming` (a shared plugin
skill used by other projects) — a project-level instruction is sufficient,
the same way this project already layers its own conventions
(`dev-workflow-skills:1-git-commit` requirement, DDD layer rules, etc.) on
top of generic skills via CLAUDE.md rather than by editing plugin source.

## Testing

- Security-review workflow: cannot be fully verified without a real PR
  (needs `secrets.CLAUDE_CODE_OAUTH_TOKEN` and the actual GitHub Actions
  runner). Verify YAML validity locally (`actionlint` or `yamllint` if
  available) and open a small test PR after merging to confirm the comment
  posts.
- PR watchdog: `RemoteTrigger action: "run"` once immediately after
  creation, then `get_run_log` on that run to confirm `gh` commands
  succeeded (not permission-denied) before trusting the schedule.
- `intent.md` convention: no test beyond the worked example already in
  place.
