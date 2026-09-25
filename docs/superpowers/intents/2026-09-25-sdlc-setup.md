# Intent: Close three SDLC gaps against Anthropic's AI-Native SDLC playbook

**What**: Snehal asked to "set up the Anthropic SDLC" for RocketVault. An
audit against Anthropic's published AI-Native SDLC playbook
(Plan/Design/Build/Test/Deploy/Maintain) found most phases already covered —
CLAUDE.md, `/code-review` and `/security-review` skills, the superpowers
plugin (brainstorming/TDD/systematic-debugging), `claude-review.yml`, and the
`known-bugs.md` <-> GitHub-issue convention. Three gaps remained: no
automated security-review pass in CI, no unattended monitoring of open PRs,
and no committed pre-design artifact for the Plan phase.

**Why**: closing these makes the existing, already-strong setup match the
playbook's full loop rather than stopping at Deploy. A solo developer
benefits most from the two automation pieces (security review, PR watchdog)
catching problems before they're noticed manually; the `intent.md`
convention is cheap and gives every future architectural design a committed
one-paragraph anchor for "why are we doing this" before the spec exists.

**Scope for this pass**:
1. `.github/workflows/security-review.yml` — advisory-only, mirrors
   `claude-review.yml`.
2. A cloud routine (`schedule` skill / `RemoteTrigger`) — PR/CI watchdog
   only, no proactive bug-hunting, no autonomous push/thread-resolution.
   Re-enqueues flaky-shaped CI failures; reports everything else.
3. `.claude/intent-convention.md` + a CLAUDE.md pointer, documenting this
   file's own convention (this file is the first example).

**Out of scope**: re-enabling the currently-disabled Lint/Security-Scan jobs
in `go.yml` (Snehal disabled those deliberately 2026-09-25, reason not
stated — not this task's to second-guess), backfilling `intent.md` for past
work, broader autonomous bug-hunting.
