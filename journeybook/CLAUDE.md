# CLAUDE.md

Guidance for Claude Code when working in `journeybook/`.

## What this is

A single-file, offline HTML page that a QA engineer opens from disk to work
through RocketVault's vault, user and access journeys, recording a pass or fail
against each check. 23 journeys, 247 checks, transcribed from
`../docs/VAULT_USER_ACCESS_JOURNEYS_v3.md`.

It is a **static artifact**, not an app: it never talks to a RocketVault
instance, holds no credentials, and stores verdicts only in the tester's own
browser.

## Before editing the cases

Read [.claude/authoring-cases.md](.claude/authoring-cases.md). It carries the
seven rules that make this page trustworthy — chiefly that commands and
expected output are transcribed from the journeys document, never invented, and
that case ids are permanent because verdicts are keyed on them.

## Commands

Package manager is **bun**; `bun.lock` is committed.

```bash
bun run dev         # Vite dev server on :5174
bun run build       # emits dist/index.html and dist/journeybook.html
bun run typecheck   # keep the -b, see README
bun run lint        # keep --error-on-warnings, see README
bun run format      # prettier, run after editing class strings
```

There is no test runner. If tests are wanted, add one rather than assuming
`bun test` is wired up.

## Stack

Mirrors `../web` deliberately, so the two projects stay learnable together:
React 19 + TypeScript strict on Vite 8, Tailwind v4 CSS-first (no
`tailwind.config.js` — tokens live in `src/index.css`), shadcn `base-luma` on
`@base-ui/react`, Biome for linting and Prettier for formatting with their
respective formatters disabled so they never fight.

It diverges from `../web` in three ways, all on purpose:

- **`vite-plugin-singlefile`** plus `assetsInlineLimit: Infinity` inlines every
  asset, including the woff2 subsets. The output has to survive being emailed
  as one file.
- **`base: "./"`**, not `/app/` — this is opened from `file://`, not served
  behind Caddy.
- **JetBrains Mono Variable for everything**, where `../web` pairs Noto Sans
  with the same mono face. This page carries no sans at all: `--font-sans` and
  `--font-mono` both resolve to JetBrains Mono, so headings, prose, labels and
  transcripts share one advance width. Keep both token names — the vendored
  components in `src/components/ui/` reference them and must stay
  byte-identical to the registry.

**Light no longer tracks `../web`.** It started as the base-luma "mist" scale
copied from `../web/src/index.css`, but that scale put `--background` and
`--card` both at pure white, so a panel was drawn by nothing but a 1.25:1
hairline and eight real pairings failed WCAG AA — including the Pass and Fail
labels on every row, and `--untested`, which left the run strip a blank band
until something was recorded.

It has its own strategy now, and it is the inverse of dark's: **the panel
floats on paper.** The ground drops to an off-white and panels stay pure white
on top of it, so the surface step does the work that dark has to get from
edges. Every chrome token sits on one hue (225) at chroma ≤ 0.008 — that
ceiling is the lesson from the earlier pass that tinted the ground green and
fought the component library. Saturation is spent only on teal (identity),
green (passed) and red (failed).

`--border` and `--input` are no longer the same value: `--border` is a
decorative panel edge, `--input` bounds a control and has to clear the 3:1
WCAG asks of one. If you add a control, use `border-input`.

**Run `bun scripts/check-contrast.mjs` after touching any colour token.** It
parses `src/index.css` directly and checks every pairing the components use, in
both themes. It reports zero failures today; keep it there.

**Dark diverges deliberately** and is not `../web`'s. It separates surfaces
with borders rather than fill: `--card` sits 0.03 above `--background` and
`--border` is 14% white. Read the design notes in
`.claude/authoring-cases.md` before changing colour, radius, or reaching for a
hand-rolled control.

**The rail (`src/components/rail.tsx`) folds itself to fit shorter screens.**
The Keyboard panel and the "Jump to a section" panel (the old two link groups,
retitled and demoted to `h3` now that the panel owns the `h2`) are both
`CollapsiblePanel`s — Keyboard collapsed by default, Jump to a section
expanded, since one is reference and the other is navigation. The Journeys
heading carries a density `Toggle` that drops the per-journey tick strip and
switches the title to `truncate`. None of this animates open or shut: the
reduced-motion reset in `index.css` needs `!important` to beat Tailwind's
animation layer, and a height transition was not worth fighting that for. All
three preferences (`journeybook-rail-keyboard`, `journeybook-rail-sections`,
`journeybook-journeys-compact`, via `useStoredFlag` in
`src/lib/stored-flag.ts`) live inside `Rail` rather than being lifted into
`App.tsx` the way theme, shortcuts and the run are — each of those three is
lifted for a concrete reason (theme lands on `<html>`, shortcuts gates App's
keydown handler, the run is read by every row), and nothing outside `Rail`
reads a rail view preference, so lifting these would copy that pattern's shape
without its reason.

## Things that will bite

- **A `why`, `verify` or `after` with no `source` fails `bun run check:links`.**
  That is deliberate, not a lint annoyance: a claim a reader cannot trace is
  the one failure mode this page cannot survive. If you cannot cite it, delete
  it — an absent field is honest. Note that a claim can be *true* and still
  fail the spirit of this: cite where the fact actually lives, not the nearest
  plausible section.
- **Enrichment is applied by `scripts/apply-enrichment.mjs`, not by hand.** It
  locates the case object structurally and refuses to apply a field twice.
  Hand-editing 247 cases is how transcription errors get back in. The refusal
  is a feature — during the backfill it caught three separate collisions that
  would otherwise have silently overwritten or duplicated a field.
- `bunx shadcn add` needs network access to `ui.shadcn.com`. When that is
  unavailable, copy the component from `../web/src/components/ui/`, which
  vendors the full registry at the same `base-luma`/`mist` settings.
- `src/components/ui/` is in `.prettierignore` to keep those files
  byte-identical to the registry. Wrap or compose rather than editing one.
- The reduced-motion reset in `src/index.css` needs `!important` and carries a
  `biome-ignore` saying why: Tailwind's animation utilities sit in a later
  cascade layer than anything a base-layer rule can declare.
- Every keyboard shortcut is a bare letter, so any new input must not swallow
  them — the handler in `src/App.tsx` already skips inputs, textareas and
  contenteditable.
- **JetBrains Mono ligatures are switched off document-wide** in
  `src/index.css` — on `body`, then restated on `code`, `kbd`, `pre`, `samp`
  and `.font-mono` so no nested rule can bring them back where a command
  lives. Expected output has to be transcribable character for character, and
  a ligature renders `!=` as a glyph that is not in the text a tester compares
  against their terminal. Do not re-enable them.
- **Prose carries `letter-spacing: -0.011em`** from `body`, and anything
  compared against a terminal resets it to `normal`. If you add a new block
  that shows output, make sure it inherits that reset (use `.transcript`, or
  `font-mono`) rather than sitting on tightened prose tracking.
- **Hand-rolled `<button>`s need `.focus-ring`.** The registry components in
  `src/components/ui/` ship their own focus treatment; a bare `<button>` gets
  only the base-layer outline. Four of them had no usable focus indicator at
  all until this class existed.
- **The verdict pill's active state is an outline, not a deeper wash.** The
  label is the same hue as the fill behind it, so every extra step of fill eats
  the contrast between them — in dark the old 20%/30% washes put the label at
  2.5–3.6:1. Fill is fixed per theme; the border carries the state.
- **The shell transcript belongs to its theme.** `--term*` is defined
  separately in `:root` and `.dark`, and nothing in `Terminal`, `GateDiagram`
  or `ErrorPanel` assumes either: light is a cool grey **well** stepping down
  off the white panel, dark is level with `--background`. Light was an
  inverted near-black until 2026-09-04 — see the note in
  `.claude/authoring-cases.md` for why that lost, and do not put it back.
- **Code chips outside a transcript need `whitespace-nowrap`.** The footer's
  provenance chips broke mid-token before it — `v-4.0.0` wrapped as "v-" /
  "4.0.0" across two lines, which reads as a broken build rather than a branch
  name. Pair it with `overflow-x-auto` on the wrapper so a long value scrolls
  itself instead of forcing the page to.
- **The RocketVault mark lives in two places, both inlined**:
  `src/components/brand.tsx` (masthead) and the `<link rel="icon">` data URI in
  `index.html` (tab). Both are transcriptions of
  `../web/public/rocketvault-icon.svg`. Neither can become a file reference —
  this page is opened from `file://`, so a sibling asset resolves to nothing
  once it is emailed on. If the mark is redrawn upstream, redraw both.
- **Single-character shortcuts must stay switchable off** (WCAG 2.1.4). The
  switch is in the rail's Keyboard panel and persists to `localStorage`. If you
  add a bare-letter binding, it goes inside the same gated handler.
- **The Keyboard panel's On/Off switch must stay in the header, never inside
  the collapsible body.** The panel is collapsed by default, and a shortcut
  kill-switch you have to open a panel to reach is not meaningfully
  "switchable off" for someone whose screen reader needs `f` and `e`. If you
  refactor `CollapsiblePanel` in `src/components/rail.tsx`, keep the WCAG
  switch as the `aside`, outside the fold.
- **The compact journey list uses `truncate`, not `line-clamp-1`,** in
  `src/components/rail.tsx`. A single-line clamp still reserves the taller
  block line box a two-line clamp uses, so it would give back only about a
  third of the height compact mode is meant to save. Don't "simplify" this to
  `line-clamp-1` for consistency with the clamp used in the expanded state.
- Shell blocks use the `.transcript` / `.transcript-line` pair, not raw
  `font-mono` utilities, so line height, `tab-size` and the hanging indent
  stay consistent everywhere a command appears.
- **`.transcript-line` must never sit on the same element as a `px-*`
  utility.** Its hanging indent is a padding/text-indent pair, and Tailwind
  utilities are in a later cascade layer — a `px-*` beside it wins the padding
  half, keeps the negative text-indent, and drags the first line clean out of
  the box. Put it on an inner element with no padding utilities, as
  `Terminal`, `GateDiagram` and `ErrorPanel` all do.
