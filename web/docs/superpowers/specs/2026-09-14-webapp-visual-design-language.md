# RocketVault Dashboard — Visual Design Language

**Date:** 2026-09-14
**Status:** Active — every epic plan (02 onward) must follow this
**Supersedes:** nothing; extends `2026-09-08-webapp-dashboard-epics-design.md` § 1

## Problem

Epics 00-01 shipped functionally correct but visually generic screens — the
vault picker is a plain `<h1>` plus a bare `<Table>`. Nothing is wrong with
the components used, but the composition reads as a scaffold, not a product.
This doc pins down the layout/composition vocabulary every subsequent screen
must reuse, so 12 more epics don't each reinvent (or under-invest in) the
same decisions.

## Non-negotiables (unchanged from the epics-design spec)

- **shadcn/ui only.** Every primitive comes from the 61 already-vendored
  components in `src/components/ui/`. Never add a different component
  library, never hand-roll a primitive shadcn already provides.
- **Check `src/components/patterns/` before writing a new presentational
  component.** This is the app's own internal component layer, built on top
  of the shadcn primitives: `StatTile`/`StatGrid` (summary-row tiles),
  `CardGrid`/`RESOURCE_CARD_LINK_CLASS` (the responsive card-grid list
  layout), `ResourceCardShell` (the title+status+metadata card shell),
  `ResourceListSkeleton` (loading state matching a resource list's real
  proportions), `DangerZoneCard`/`DangerAction` (the red-bordered
  destructive-actions section). Epics 00-03 each defined several of these
  independently before the duplication was caught and consolidated
  (2026-09-14) — the pattern to avoid is writing a fourth copy of something
  that already exists here for three other resource types. If a genuinely
  new presentational pattern emerges in a later epic and looks reusable
  (i.e., a fourth resource type would want it too), add it here rather than
  inlining it in that epic's own component file.
- **Reuse existing tokens, invent nothing new.** Primary teal
  (`#0A6B62` light / `#0FA89A` dark), `font-heading` = JetBrains Mono
  Variable, `font-sans` = Noto Sans Variable, `--radius-4xl` rounded
  surfaces, `shadow-md ring-1 ring-foreground/5` elevation, plus the
  `--success`/`--warning`/`--destructive` status tokens already in
  `src/index.css`. This doc is about composition and hierarchy, not palette.

## The signature idea

The landing page's one distinctive visual idea is the **Hero terminal
card** (`src/components/landing/hero.tsx`'s `Terminal` component): a small
chrome header bar over monospace `$`-prefixed lines. That is RocketVault's
visual signature — a security tool that is CLI-native at heart, with a
dashboard layered on top. Every dashboard screen should feel like the
product that terminal belongs to, without literally repeating a fake
terminal on every page (that would be a gimmick, not a system). The
concrete, disciplined carry-through:

1. **Names and identifiers are always `font-heading` (monospace)** —
   vault names, secret/key/cert names, IDs, role names, client IDs. Prose
   (descriptions, empty-state copy, helper text) is always `font-sans`.
   This one rule is what makes the dashboard read as the same product as
   the landing page's terminal panel.
2. **Status is a colored dot + word, never a bare badge alone** — `●
   Enabled` / `○ Disabled`, `● Active` / `● Expiring soon` (warning) /
   `● Expired` (destructive). Reads like a process list, which is exactly
   what an operator scanning a vault list is doing.
3. **A stat row above the primary list**, when the resource has more than
   one meaningful count (e.g. vaults: total/enabled/disabled; secrets:
   total/expiring soon/deleted). Big `font-heading` numeral, small
   `font-sans` label underneath. Skip it when there's nothing worth
   summarizing — don't force three tiles onto a screen with one count.

## Layout vocabulary

### List/picker screens (vaults, secrets, keys, certs, users, ...)

Replace "title + bare table" with:

```
┌──────────────────────────────────────────────────────────┐
│  Vaults                                  [+ Create vault] │  <- font-heading
│  Isolated security boundaries you operate in.             │  <- font-sans, muted
│                                                             │
│  ┌───────────┐  ┌───────────┐  ┌───────────┐              │
│  │ 3          │  │ 2          │  │ 1          │  <- stat row (optional,
│  │ Total      │  │ Active     │  │ Disabled   │     see rule 3 above)
│  └───────────┘  └───────────┘  └───────────┘              │
│                                                             │
│  ┌────────────────┐ ┌────────────────┐ ┌────────────────┐│
│  │ ● payments      │ │ ● staging       │ │ ○ archive      ││ <- card grid,
│  │ 30d retention   │ │ 90d retention   │ │ 7d retention   ││    not a table,
│  │ created 3w ago  │ │ created 1d ago  │ │ created 6mo ago││    for anything
│  └────────────────┘ └────────────────┘ └────────────────┘│    the operator
└──────────────────────────────────────────────────────────┘    picks/enters
```

Use a **card grid** (responsive `grid-cols-1 sm:grid-cols-2 lg:grid-cols-3`,
`Card` + `shadow-md ring-1 ring-foreground/5`, hover raises to
`ring-foreground/10` with a small `transition-shadow`) for any list where
the item is something the operator navigates *into* — vaults, and each
vault's secrets/keys/certs top-level lists. This is a resource picker, not
a report; Vercel/Linear/Supabase's project-grid pattern is the reference,
not a spreadsheet.

Use a **dense `Table`** instead, when the list is inspected/filtered more
than clicked-into — audit logs, role assignments, sessions. Rule of thumb:
if the primary action per row is "open this," use cards; if it's "scan
many rows for one," use a table.

### Detail/settings screens

Section into distinct `Card`s by concern, never one long form. A
destructive section (delete/purge/revoke) gets its own card with
`border-destructive/30` and a `text-destructive` heading — it should look
different at a glance, not just have a red button at the bottom of a
normal-looking form.

### Empty states

Already-correct pattern (`Empty`/`EmptyMedia`/`EmptyTitle`/
`EmptyDescription`/`EmptyContent` from `src/components/ui/empty.tsx`) —
keep using it, keep icon + one-sentence explanation + the primary create
action inline. Per the design skill: an empty screen is an invitation to
act, not an apology.

### Navigation chrome

`TopBar` (`src/components/app-shell/top-bar.tsx`) currently renders a
single static crumb ("Vault" / "Admin"). It should render the real path —
vault name, then the current section — so the breadcrumb is actually
useful for orientation, not decorative.

## Motion

Keep it to purposeful micro-interactions only, per the design skill's
restraint principle: card hover elevation (~150ms), a subtle
appear-on-load stagger for stat tiles/cards is optional and should be cut
if it starts to feel decorative rather than orienting. No page-load
animation sequences, no scroll-triggered reveals — this is an operator
tool used many times a day; motion that's charming once is friction on
the hundredth visit.

## Copy

Per the design skill: name things by what the operator controls, active
voice, no filler. "Create vault," not "Add new vault resource." Danger-zone
copy states the consequence plainly ("This permanently deletes the vault
and everything in it. This cannot be undone.") rather than a generic
"Are you sure?".

## What this doc does NOT change

- No new colors, fonts, or radii — see Non-negotiables.
- No change to routes, API contracts, or auth model — those are governed
  by the epics-design spec and each epic's own plan.
- Table-based screens (audit, sessions, role assignments) are unaffected
  in kind, just in polish (status-dot convention, spacing).
