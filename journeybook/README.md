# RocketVault Journeybook

A single-file, offline HTML page that walks a QA engineer through every
RocketVault vault, user and access journey — 23 journeys, 247 checks — and
records a pass or fail against each one.

Most checks carry more than a command and an expected line: why the system
behaves that way, how to settle a result the expected line leaves ambiguous,
what the check leaves behind, and which other checks it depends on or
contradicts. A tester whose run does not match has something to reason with
rather than only a mismatch.

Built from [`docs/VAULT_USER_ACCESS_JOURNEYS_v3.md`](../docs/VAULT_USER_ACCESS_JOURNEYS_v3.md).
Every command and every expected line is transcribed from that document, never
invented. Where a capability has no CLI equivalent, the check says so rather
than showing a plausible-looking invocation. Cases the sources do not explain
carry no explanation — an absent field is honest, an invented one is not.

## For the QA team

Open `journeybook.html`. That is the whole setup — no server, no install, no
network. It works from a downloaded file, a shared drive, or a USB stick.

- **Verdicts are saved in your own browser** (`localStorage`). Nothing is sent
  anywhere, and nobody else can see your run.
- **Clearing site data clears the run.** So does a different browser or a
  private window. If a run matters, copy the summary out before you finish.
- **"Copy the result summary"** puts a plain-text report on your clipboard,
  failures first, each with the command and the expected output. Paste it into
  a ticket or a standup message.

### Keyboard

| Key | Does |
| --- | --- |
| `j` / `k` | Move between checks |
| `n` | Jump to the next untested check |
| `p` / `f` | Record a pass or a fail |
| `x` | Clear the verdict |
| `o` | Open or close the focused check |
| `e` | Expand every check |
| `/` | Search |

Short on vertical space? The rail's Keyboard and "Jump to a section" panels
collapse, and the density toggle on the Journeys heading compacts the list —
together they cut the rail from ~2094px to ~1006px at 1440px wide.

### Before you run anything

Point at a scratch instance, never a shared dev database. The page's
**Before you run anything** panel carries the exact setup script.

## Building it

The package manager is **bun** (`bun.lock` is committed — do not add a second
lockfile by switching to npm, yarn or pnpm).

```bash
bun install
bun run dev         # Vite dev server on :5174
bun run build       # tsc -b, vite build, then dist/journeybook.html
bun run typecheck   # tsc -b --noEmit
bun run lint        # biome lint --error-on-warnings
bun run format      # prettier --write
```

`bun run build` emits two identical files into `dist/`: `index.html` (so
`bun run preview` works) and `journeybook.html` (the one you hand to QA).
Both are fully self-contained — JS, CSS and the JetBrains Mono woff2 subsets
are inlined, roughly 678 kB, 250 kB gzipped.

Two flags in those scripts are load-bearing, and for the same reasons they are
in `../web`:

- `typecheck` must keep **`-b`**. The root `tsconfig.json` is a solution file,
  and a plain `tsc --noEmit` would check zero files and always exit 0.
- `lint` must keep **`--error-on-warnings`**. Most Biome rules report at
  warning level, and plain `biome lint` exits 0 on warnings.

## Keeping it true

The cases are the contract. When the CLI changes, this page is wrong until
somebody updates it — see [`.claude/authoring-cases.md`](.claude/authoring-cases.md)
for how the data is structured and what the rules are for editing it.

Every explanation a case carries cites where it came from — a section of the
journeys document, or a `file.go:line`. That is not decoration: `bun run
check:links` fails the build on a claim with no citation, or on a
cross-reference pointing at a case id that does not exist. If you cannot cite
it, delete it.

If a check and the code disagree, read the code, then fix whichever one is
wrong. A check that has quietly drifted is worse than no check.
