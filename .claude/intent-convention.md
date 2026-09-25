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
