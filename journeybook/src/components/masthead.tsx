import * as React from "react"
import { caseCount, source, suites } from "@/data"
import { cn } from "@/lib/utils"
import type { Theme } from "@/lib/theme"
import type { RunSummary } from "@/lib/summary"
import { BrandMark } from "@/components/brand"
import { RunStrip } from "@/components/verdict"
import { ToggleGroup, ToggleGroupItem } from "@/components/ui/toggle-group"

function ThemeToggle({
  theme,
  setTheme,
}: {
  theme: Theme
  setTheme: (t: Theme) => void
}) {
  // Labels are capitalised in the markup, not with a `capitalize` class:
  // CSS casing is visual only, so a screen reader would announce "dark".
  const options: Array<[Theme, string]> = [
    ["system", "System"],
    ["light", "Light"],
    ["dark", "Dark"],
  ]
  return (
    <ToggleGroup
      aria-label="Colour theme"
      variant="outline"
      size="sm"
      spacing={0}
      value={[theme]}
      onValueChange={(v) => setTheme(((v as Theme[])[0] ?? "system") as Theme)}
    >
      {options.map(([value, label]) => (
        <ToggleGroupItem key={value} value={value}>
          {label}
        </ToggleGroupItem>
      ))}
    </ToggleGroup>
  )
}

/**
 * Memoised because the strip below is 245 ticks in 23 groups, and App
 * re-renders on every search keystroke, every j/k and every expand. `summary`
 * is itself memoised on the run map, so a verdict changing is one of only two
 * things that reaches this.
 *
 * The other is `activeSuite`, which the strip needs to mark where the reader
 * is. It changes when the section in view changes -- around 23 times over a
 * full read, not once per scroll event -- so it costs a couple of dozen
 * redraws across a whole run, and the memo still earns its place against the
 * hundreds of keystroke renders it turns away.
 */
export const Masthead = React.memo(function Masthead({
  summary,
  activeSuite,
  theme,
  setTheme,
}: {
  summary: RunSummary
  activeSuite: string | null
  theme: Theme
  setTheme: (t: Theme) => void
}) {
  const { groups, pass, fail, todo } = summary
  const { header, readout } = usePinnedReadout()

  return (
    // The whole header is the sticky element, parked at a negative top so it
    // rides up until only the readout is left standing. See usePinnedReadout.
    <header
      ref={header}
      className="z-30 border-b border-border bg-card sm:sticky"
    >
      <div className="mx-auto max-w-[92rem] px-5 py-6 md:px-8 md:py-8">
        <div className="flex flex-wrap items-start justify-between gap-x-8 gap-y-5">
          <div className="min-w-0">
            {/* The mark is decorative here: the h1 beside it already says
                "RocketVault", so announcing it again would double the name for
                a screen reader. `aria-hidden` beats dropping the label inside
                BrandMark, which is also used where it stands alone. */}
            <div className="flex items-center gap-3">
              <BrandMark
                aria-hidden="true"
                className="size-8 shrink-0 rounded-[7px] md:size-9"
              />
              <h1 className="font-mono text-[22px] leading-none font-semibold tracking-tight md:text-[27px]">
                <span className="text-primary">RocketVault</span> Journeybook
              </h1>
            </div>
            <p className="mt-2.5 max-w-[62ch] text-[14px] leading-relaxed text-muted-foreground">
              {suites.length} journeys, {caseCount} checks. Every command and
              every expected line below is transcribed from{" "}
              <code className="rounded-[3px] bg-muted px-1 py-px font-mono text-[0.9em]">
                {source.doc}
              </code>
              , never invented — where a capability has no CLI equivalent, the
              check says so instead of showing something plausible.
            </p>
          </div>

          <div className="shrink-0">
            <ThemeToggle theme={theme} setTheme={setTheme} />
          </div>
        </div>

        {/* Everything from here down is what stays on screen. The masthead's
            identity block above scrolls away behind it; this is the part a
            tester needs at check 180 as much as at check 1. */}
        <div ref={readout} className="pt-6">
          {/* The run at a glance: a tick per check, grouped by journey, each
              group as wide as its share of the 247. Below sm the ticks would
              be under a pixel wide, so the proportional bar takes over there
              -- still true, just coarser, rather than a row of invisible
              marks. */}
          <RunStrip
            groups={groups}
            activeKey={activeSuite}
            className="hidden sm:flex"
          />
          <div
            aria-hidden="true"
            className="flex h-1.5 overflow-hidden rounded-full bg-untested sm:hidden"
          >
            <span
              className="bg-success transition-[width] duration-300"
              style={{ width: `${(pass / caseCount) * 100}%` }}
            />
            <span
              className="bg-destructive transition-[width] duration-300"
              style={{ width: `${(fail / caseCount) * 100}%` }}
            />
          </div>

          {/* The figures are the accessible readout for every bar on the page
              -- the run strip and the phone bar above are both aria-hidden.
              Baseline-aligned so the 22px numerals, the 11.5px labels and the
              12.5px sentence all sit on one line. */}
          <div className="mt-2.5 flex flex-wrap items-baseline gap-x-6 gap-y-2">
            <Figure n={pass} label="passed" tone="pass" />
            <Figure n={fail} label="failed" tone="fail" />
            <Figure n={todo} label="untested" tone="todo" />
            <p className="max-w-[52ch] text-[12.5px] leading-relaxed text-muted-foreground sm:ml-auto sm:text-right">
              {runNote(summary)}
            </p>
          </div>
        </div>
      </div>
    </header>
  )
})

/** Widths at and above which the masthead pins. Matches Tailwind's `sm`. */
const PIN_FROM = "(min-width: 40rem)"

/**
 * Pins the masthead by scrolling most of it away.
 *
 * The header is `position: sticky` with a *negative* top -- the exact height
 * of everything above the readout. So it scrolls normally until the readout
 * reaches the top of the viewport, and from then on it stays, with the mark,
 * the title, the provenance sentence and the theme toggle held just above the
 * top edge where they cost nothing.
 *
 * This is why it is sticky rather than a fixed copy or a fixed swap. Sticky
 * keeps the header in flow at full height, so there is no placeholder to keep
 * in sync, no layout jump at the moment of pinning, and no chance of the jump
 * feeding back into whatever triggered it. The only thing measured is the
 * offset, and getting it wrong shows up as the header sitting a few pixels
 * high or low -- never as a broken page.
 *
 * The measurement is a subtraction of two rects taken in the same frame, so it
 * is unaffected by whether the header happens to be stuck at that instant:
 * both rects shift together and the difference between them does not move.
 *
 * It also publishes the standing height as `--pin-h`, because three things
 * downstream -- the checks toolbar, the rail, and every `scroll-mt` anchor --
 * have to clear it, and a number they each hardcode is a number that goes
 * stale the first time a word is added to the sentence above.
 *
 * Both writes are imperative -- straight onto the header's `style` and onto
 * `document.documentElement` -- rather than routed through state, because
 * neither `top` nor `--pin-h` is read by JSX. Going through state would mean a
 * `setOffset` on every one of the many identical callbacks a resize drag
 * fires, and each of those re-renders `Masthead`'s 245-tick strip for a number
 * that did not change. The last written offset and pin height are cached so a
 * callback that recomputes an unchanged pair is a no-op rather than a style
 * write that can invalidate layout.
 */
function usePinnedReadout() {
  const header = React.useRef<HTMLElement>(null)
  const readout = React.useRef<HTMLDivElement>(null)

  React.useLayoutEffect(() => {
    const headerEl = header.current
    const readoutEl = readout.current
    if (!headerEl || !readoutEl) return

    const query = window.matchMedia(PIN_FROM)
    // Locals rather than refs. The cleanup below clears both writes, so a
    // cache that outlived the effect would let a remount match its own stale
    // numbers, skip the write, and leave the header with no top at all.
    let lastOffset: number | null = null
    let lastPinH: number | null = null

    const measure = () => {
      // Below sm the header does not pin at all: a readout this tall standing
      // permanently on a phone would cost more viewport than it repays, and
      // the coarse bar it would be holding up there is the least useful of
      // the three drawings anyway.
      if (!query.matches) {
        if (lastOffset === 0 && lastPinH === 0) return
        lastOffset = 0
        lastPinH = 0
        headerEl.style.top = "0px"
        document.documentElement.style.setProperty("--pin-h", "0px")
        return
      }
      const head = headerEl.getBoundingClientRect()
      const read = readoutEl.getBoundingClientRect()
      const above = read.top - head.top
      const pinH = head.height - above
      if (above === lastOffset && pinH === lastPinH) return
      lastOffset = above
      lastPinH = pinH
      headerEl.style.top = `${-above}px`
      document.documentElement.style.setProperty("--pin-h", `${pinH}px`)
    }

    measure()
    // The header's own box changes when the provenance sentence rewraps; the
    // readout's changes when the run note does. Watching both covers a window
    // resize and a font finishing loading without a scroll listener.
    const observer = new ResizeObserver(measure)
    observer.observe(headerEl)
    observer.observe(readoutEl)
    query.addEventListener("change", measure)
    return () => {
      observer.disconnect()
      query.removeEventListener("change", measure)
      // The hook owns both writes, so it cleans up both: an unmounted
      // Masthead should not leave a stale --pin-h or a stuck top behind for
      // whatever renders next.
      document.documentElement.style.removeProperty("--pin-h")
      headerEl.style.top = ""
    }
  }, [])

  return { header, readout }
}

/**
 * Journey letters read as a phrase. The strip above is grouped by journey and
 * every section heading leads with the letter, so the letter is the handle a
 * tester already has. Past three, naming them stops being navigation and
 * starts being a list.
 */
function journeyList(keys: string[]) {
  if (keys.length > 3) return `${keys.length} journeys`
  if (keys.length === 1) return `journey ${keys[0]}`
  return `journeys ${keys.slice(0, -1).join(", ")} and ${keys[keys.length - 1]}`
}

/**
 * What the strip means, in a sentence. Failures are attributed to journeys
 * only once there are some -- that is the moment the strip has just drawn a
 * tall red tick somewhere in the middle of the run and the sentence's job is
 * to say where.
 */
function runNote({ done, fail, failedSuites }: RunSummary) {
  if (done === 0) {
    return (
      <>
        {/* A bare kbd, not the Kbd component: that one is a 22px inline-flex
            chip, which would inflate this line box and drag the sentence off
            the figures' baseline. */}
        Nothing recorded yet. Press <kbd className="text-foreground">n</kbd> to
        open the first check — verdicts stay in this browser.
      </>
    )
  }
  if (done === caseCount) {
    return fail === 0
      ? "Run complete, nothing failed."
      : `Run complete. ${fail} ${fail === 1 ? "check" : "checks"} to write up, in ${journeyList(failedSuites)}.`
  }
  if (fail === 0) return `${done} of ${caseCount} recorded, nothing failed yet.`
  return `${done} of ${caseCount} recorded. ${
    fail === 1 ? "One failure" : `${fail} failures`
  } in ${journeyList(failedSuites)}.`
}

function Figure({
  n,
  label,
  tone,
}: {
  n: number
  label: string
  tone: "pass" | "fail" | "todo"
}) {
  return (
    <div className="flex items-baseline gap-2">
      {/* 22px, not the 30px this used to be. It sat alone in the top-right
          corner then; under a full-width strip that size would out-shout the
          h1, and 22px rhymes with the tick height directly above. */}
      <span
        className={cn(
          "text-[22px] leading-none font-semibold tabular-nums",
          tone === "pass" && "text-success",
          tone === "fail" && "text-destructive",
          tone === "todo" && "text-muted-foreground"
        )}
      >
        {n}
      </span>
      <span className="label text-muted-foreground">{label}</span>
    </div>
  )
}
