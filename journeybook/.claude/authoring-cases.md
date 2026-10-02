# Authoring journeybook cases

The data in `src/data/` is the whole product. The UI is a way to read and
record against it, and is much less likely to need changing than the cases are.

## Where things live

| File | Holds |
| --- | --- |
| `src/data/types.ts` | `Case`, `Suite`, `Gate`, `Surface` |
| `src/data/journeys-a-f.ts` | Journeys A–F |
| `src/data/journeys-g-m.ts` | Journeys G–M |
| `src/data/journeys-n-u.ts` | Journeys N–U |
| `src/data/journeys-v-w.ts` | Journeys V–W |
| `src/data/reference.ts` | Setup script, cast, gates, error table, capability matrix, flag traps, corrections |
| `src/data/index.ts` | Flattens the suites, and records which document revision this was built from |
| `scripts/apply-enrichment.mjs` | Merges enrichment JSON into the case data. Agents never edit `src/data/` directly |
| `scripts/check-links.mjs` | Fails on a dangling `related` id or a claim with no `source` |

Split by letter only to keep files readable. Nothing about the split is
meaningful — move a journey between files freely.

## The rules

**1. Transcribe, never invent.** Every `command` and `expected` comes from
`docs/VAULT_USER_ACCESS_JOURNEYS_v3.md`, which in turn takes them from `cmd/`.
If a capability has no CLI command, write a case that asserts the absence
(see `C21`, key import) rather than inventing an invocation that looks right.
This rule is the reason the page is worth anything.

**2. Case ids are permanent.** Verdicts are keyed on `id` in `localStorage`
under `journeybook-run-v1`. Renaming `A7` silently discards every tester's
recorded verdict for it. Adding `A13` is free; an unknown id reads back as
untested and a removed one is ignored. Only bump the storage key if the shape
of a stored run changes, which reordering and rewording do not.

**3. One assertion per case.** `assert` is what a tester scans on the collapsed
row to decide whether their run matched. "Denied — global admin does not bypass
the vault check" is an assertion; "Check the vault" is not. If a case needs two
`assert` lines, it is two cases.

**4. Expected output is verbatim, including the error string.** Three different
403s mean three different things in RocketVault, and a case that expects only
"403" cannot tell them apart. Copy the exact message.

**5. `gate` classifies which check produced the outcome**, not what the command
does. `keys create` refused for lack of `crypto_manager` is `global-role`; the
same command refused for lack of a vault role is `vault-role`. Use `none` when
the case asserts ordinary behaviour rather than a denial.

**6. `flag` is for the findings, not decoration.** `trap` is something that will
bite an unprepared tester, `divergence` is CLI and HTTP disagreeing, `gap` is a
capability that does not exist or a value that is stored and never read. Most
cases carry no flag.

**7. `notes` explains why the case exists**, or what is easy to get wrong. It
renders a two-marker subset of markdown — `` `code` `` and `**bold**` — and
nothing else. Anything else appears literally, deliberately, so a real error
message containing an asterisk is not silently eaten.

**8. A claim needs a citation or it does not ship.** `why`, `verify` and
`after` each require `source` — a document section
(`VAULT_USER_ACCESS_JOURNEYS_v3.md § Journey J — the purge trap`) or a code
location (`internal/services/vaults/vault_service.go:214`).
`scripts/check-links.mjs` fails the build if one is missing.

**Omission is a correct outcome.** A case with no `why` is honest. A case
with a plausible-sounding invented one is the failure this rule exists to
prevent, and it is worse than the thin case it replaced — a thin check sends
a tester to the document, a confidently wrong one sends them to file a defect
against working software.

A claim that is true but not supported by *its own* citation still fails this
rule. When the backfill was verified, nine of the seventeen corrections were
exactly that: accurate sentences pointing at a section that did not establish
them. Cite where the fact lives, not where the case sits.

**9. `verify.command` is transcribed or confirmed, never inferred.** Copy it
from the journeys document, or build it only from flags you have read in the
cobra registration in `cmd/`. Never from a flag name, a help string, or the
shape of a neighbouring command. A verification command carrying a flag that
does not exist teaches a tester to distrust the whole page.

**10. When the document and the code disagree, say so — do not choose.**
`VAULT_USER_ACCESS_JOURNEYS_v3.md` is dated and the CLI has drifted before. A
case quietly corrected from the code contradicts the document a tester is
reading beside it, and hides what may be a real defect. Raise it.

**11. No hedging.** No "should", "presumably", "likely", "appears to". A claim
you cannot state flatly from a source is not written. Hedged text reads as
information while carrying none, and a tester cannot act on it.

**12. `why` and `notes` do not overlap.** `why` is the system's mechanism;
`notes` is what a tester should do or watch out for. Where a note already
carries mechanism, move that half to `why` and leave the actionable half.
Never duplicate, and never drop the actionable half. See `J6` for the worked
split. If nothing survives once the mechanism moves, delete `notes` rather
than leaving a sentence that repeats `why` in shorter words.

**How much of this is enforced.** Only rule 8 has a mechanical check behind it.
`check-links.mjs` catches a missing `source` and a dangling `related` id, and
nothing else here is verifiable by a script — 9 through 12 rely on the reviewer.
That asymmetry is worth knowing rather than assuming the build has your back:
provenance is enforced, judgment is not.

## The detail fields

Beyond `command`, `expected` and `assert`, a case can carry five optional
fields. They render in one fixed order — Why, Before, Run, Expected, Verify,
After, Note, Related, Source — as a definition list with labels right-aligned
in a 3.5rem gutter.

| Field | Holds | Required with it |
| --- | --- | --- |
| `why` | The mechanism. Why the system behaves this way, not what the command does | `source` |
| `verify` | `{ command?, look }` — how to settle pass from fail when `expected` leaves a margin | `source` |
| `after` | What the check leaves behind, and what to undo first | `source` |
| `related` | `{ id, rel }[]` — `depends`, `diverges` or `contrasts` | ids must resolve |
| `source` | Provenance. Document section or `file.go:line`, several joined by `; ` | — |

`Suite.context` holds the journey-level prose as one string per paragraph.

Most cases carry none of these — 83 of the 247 are deliberately bare, because
the sources do not explain them. `verify` earns its place only where the
expected line genuinely leaves room for doubt; `after` only where the check
leaves state behind. Journey J is the reference for all of them, and `J2`
specifically is the precedent for carrying no `why` at all: the document shows
its command and does not explain it, so nothing was written.

## When the CLI changes

Update `source` in `src/data/index.ts` — `doc`, `branch` and `asOf` are printed
in the footer so a tester filing a defect can quote the revision their run came
from. A page claiming to match a document it no longer matches is the failure
mode worth guarding against.

## Design notes

**The shadcn token block in `src/index.css` is the base-luma "mist" scale,
copied verbatim from `../web/src/index.css`** — the same source the ten
vendored components came from. Keeping it byte-identical is the point: the
components were designed against near-neutral chrome (chroma 0.001–0.021) with
brand teal as `--primary`, and they look wrong on anything else.

Do not tint those tokens. An earlier pass grounded the page in a green-cast
paper with a tightened `--radius`, which fought the component library on every
surface — `base-luma` builds its controls as pills (`rounded-4xl` buttons,
`rounded-3xl` badges and inputs), so square 6px controls sitting next to them
read as a different product.

Three tokens are added on top, all sitting on the same scale:

- `--success` pairs with the stock `--destructive`, so a run has two verdicts
  that read the way every other product's do: green passed, red failed.
- `--untested` is a neutral just below `--border`.
- `--term` is the surface for shell transcripts, and each theme defines it for
  itself — see "Dark is not light inverted" below.

`--success` and `--destructive` appear at **full strength in exactly one
place** — the verdict gutter. Everywhere else, including the 200-odd Pass/Fail
controls, they use the registry's own tinted treatment (a 10% wash behind
coloured text, the shape `variant="destructive"` already ships). That is what
keeps the rail the thing your eye lands on rather than 400 shouting chips.
Never tint a border or a heading with either.

## Dark is not light inverted

Light separates surfaces with hairline borders on white. **Dark separates with
edges, not fill.** `--card` sits only 0.03 lightness above `--background`, and
`--border` is 14% white — strong enough that a panel is drawn by its outline
rather than by being paler than what is behind it.

This replaced a first pass that lifted `--card` a full 0.070 above the ground
with borders at 10% white, so every panel was a pale grey slab and the edges
did nothing. If you find yourself raising `--card` to make a panel visible, the
fix is the border, not the fill.

`--term` follows the same rule, in both directions. In dark it sits **level
with `--background`**: a transcript is the natural ground of this page rather
than a hole punched through a lighter card, and the border tells you where it
starts.

In light it is a **well** — a cool grey step *down* off the white panel, which
is the panel's own move inverted one level out. The page then reads as three
consistent depths: paper, panel, well.

Light used to be an inverted near-black here, on the argument that a tester is
comparing a transcript against a real terminal a few centimetres away. That
argument lost: a near-black block appearing twenty times per screen, with its
own edge treatment and its own idea of what ink is, was the one thing on the
page that did not belong to the theme. What actually carries the terminal
reading is the mono face, the tone split between command and output, and the
hanging indent — none of which needs an inverted ground. Do not reintroduce
one.

## The two type roles

The page is set in **JetBrains Mono throughout** — headings, prose, labels and
transcripts alike. There is no second family. The two roles below are still
real, but they are now separated by size and tracking rather than by face:

- **Labels** — identifiers and machine-side text: journey letters, case ids,
  counts, surface tags, transcript captions, rail section headings, the
  wordmark. Use the `.label` class (11.5px, `letter-spacing: 0.015em`) rather
  than assembling `font-mono text-[11.5px]` by hand.
- **Prose** — titles and language, including `assert` and `notes`. Inherits
  from `body`, which carries `letter-spacing: -0.011em` to pull a monospace
  line back toward a readable measure. A tester reads a lot of `notes`, so if
  you set prose anywhere by hand, do not cancel that tracking.

Anything a tester compares against a terminal — `code`, `kbd`, `pre`, `samp`,
`.font-mono`, `.transcript` — resets to `letter-spacing: normal`, because
output has to sit at the face's natural advance width, column for column.

Labels stay sentence case. Size and tracking already mark them as machine-side;
a tracked-out caps eyebrow over every heading would be two devices doing one
job, and is the most generic move available here.

## Scrollbars

Every scroll region uses a thin rounded thumb that is transparent until the
container is hovered or focused within (`--scrollbar-thumb`, set in both
themes). The gutter is always reserved and only the thumb's colour changes, so
nothing reflows when it appears — a scrollbar that took up space on hover would
shift a table sideways under the reader's cursor.

Note that Chrome ≥121 prefers the standard `scrollbar-width`/`scrollbar-color`
properties over `::-webkit-scrollbar` rules when both are present. Both are in
the stylesheet so older engines still get the treatment; the standard pair is
what actually runs on a current browser.

## Transcript typography

Every shell block goes through `.transcript` (the box) and `.transcript-line`
(one per logical line), both in `src/index.css`. Do not hand-roll a code block
with `font-mono text-[12px]` — three settings there are load-bearing:

- **`line-height: 1.7`.** JetBrains Mono has a tall x-height and generous
  sidebearings; at a 1.5 default, stacked output lines crowd each other.
- **`font-variant-ligatures: none`.** JetBrains Mono ships coding ligatures on.
  A tester compares expected output against a real terminal character by
  character, so `!=` must not render as a glyph that is not in the text.
- **A hanging indent** — `padding-left: 3ch; text-indent: -3ch` on a
  `pre-wrap` block. 123 of the 703 transcript lines here are over 78
  characters, so wrapping is the common case. Without the hang, a wrapped
  line folds back to column zero and reads as a new command.

Lines are separate block elements rather than one text node, which is what
makes the per-line hanging indent possible. Selecting across them still yields
newlines (browsers insert them between block elements when serialising a
selection), and the Copy button writes the source string directly, bypassing
the DOM entirely.

## Prefer the vendored components

Reach for `src/components/ui/` before writing a control by hand — `Button`,
`Badge`, `Input`, `Kbd` and `ToggleGroup` are all in use and carry the radii,
focus rings and hover states the rest of the page is calibrated against. The
one deliberate exception is `VerdictControl`, which composes two `Button`s
rather than a `ToggleGroup` because its two options are independently
clearable and need different colours per option.

Note that CSS `capitalize` changes only the rendering — an accessible name
comes from the DOM text, so write labels capitalised rather than lowercasing
them and fixing it in CSS.

The **verdict gutter** — the unbroken rail down the left of the case list — is
the page's one memorable element. Width carries state before colour does:
untested is a hairline, a recorded verdict is the full 4px. That ordering keeps
the run legible in greyscale and to a colourblind reader, so keep it if you
change the styling.

The page opens on the **three-gate diagram** rather than a headline number,
because knowing which gate produced a 403 is the thing a RocketVault tester has
to hold in their head. The numbering is earned — the gates genuinely run in
that order.

## Components

`src/components/ui/` holds ten components copied from `../web/src/components/ui/`,
which vendors the full shadcn `base-luma` registry. They are byte-identical to
the registry and excluded from Prettier for that reason. `bunx shadcn add` needs
network access to `ui.shadcn.com`; if that is unavailable, copy from `../web`
instead, which is how these ten arrived.
