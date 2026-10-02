import * as React from "react"
import { Search } from "lucide-react"
import { allCases, caseCount, suites } from "@/data"
import type { FlatCase } from "@/data"
import { buildReport } from "@/lib/report"
import { useRunState, type Verdict } from "@/lib/run-state"
import { summarise } from "@/lib/summary"
import { useTheme } from "@/lib/theme"
import { CaseRow } from "@/components/case-row"
import { Footer } from "@/components/footer"
import { GateDiagram } from "@/components/gate-diagram"
import { Masthead } from "@/components/masthead"
import { Prose } from "@/components/prose"
import { Rail } from "@/components/rail"
import { Input } from "@/components/ui/input"
import { ToggleGroup, ToggleGroupItem } from "@/components/ui/toggle-group"
import {
  CapabilityPanel,
  CastPanel,
  CommandPanel,
  CorrectionsPanel,
  ErrorPanel,
  SetupPanel,
} from "@/components/reference-panels"

type Filter = "all" | "todo" | "pass" | "fail"

const filters: Array<[Filter, string]> = [
  ["all", "All"],
  ["todo", "Untested"],
  ["pass", "Passed"],
  ["fail", "Failed"],
]

/**
 * Honour the reduced-motion preference for JS-driven scrolling. The CSS block
 * in index.css resets `scroll-behavior`, which only governs scrolling the
 * browser starts; a `behavior: "smooth"` passed straight to the scroll API
 * ignores it, so every j/k press animated regardless of the setting.
 */
function scrollBehavior(): ScrollBehavior {
  return window.matchMedia("(prefers-reduced-motion: reduce)").matches
    ? "auto"
    : "smooth"
}

const SHORTCUTS_KEY = "journeybook-shortcuts"

/**
 * Fields a search query is matched against, keyed by case id. Ids are included
 * so "A7" works.
 *
 * Joined once at module load rather than inside the filter: the cases never
 * change after import, and building them per call meant assembling 245 strings
 * out of eight fields each on every character typed into the search box.
 */
const haystacks = new Map<string, string>(
  allCases.map((c) => [
    c.id,
    [
      c.id,
      c.title,
      c.assert,
      c.command,
      c.expected,
      c.precondition,
      c.notes,
      c.suiteTitle,
    ]
      .filter(Boolean)
      .join(" ")
      .toLowerCase(),
  ])
)

export default function App() {
  const { run, setVerdict, reset, verdictOf } = useRunState()
  const { theme, setTheme } = useTheme()

  const [filter, setFilter] = React.useState<Filter>("all")
  const [query, setQuery] = React.useState("")
  const [open, setOpen] = React.useState<Set<string>>(() => new Set())
  const [focusId, setFocusId] = React.useState<string | null>(null)
  const [copied, setCopied] = React.useState(false)
  const [activeSuite, setActiveSuite] = React.useState<string | null>(null)
  const searchRef = React.useRef<HTMLInputElement>(null)

  /*
   * Every binding here is a single unmodified character, which WCAG 2.1.4
   * only permits if it can be turned off, remapped, or confined to a focused
   * component. This is the "turned off" arm. It also matters in practice:
   * f and e are JAWS quick-nav keys, so a screen-reader user needs a way to
   * stop this page competing for them.
   */
  const [shortcuts, setShortcuts] = React.useState(() => {
    try {
      return localStorage.getItem(SHORTCUTS_KEY) !== "off"
    } catch {
      return true
    }
  })
  const toggleShortcuts = React.useCallback(() => {
    setShortcuts((on) => {
      try {
        localStorage.setItem(SHORTCUTS_KEY, on ? "off" : "on")
      } catch {
        // Storage blocked; the choice still holds for this session.
      }
      return !on
    })
  }, [])

  // One pass over the run, keyed on the run itself -- so typing in the search
  // box no longer re-tallies 208 cases, and the masthead's strip and figures
  // come from a single derivation rather than agreeing by coincidence.
  const summary = React.useMemo(() => summarise(run), [run])

  const q = query.trim().toLowerCase()
  const matches = React.useCallback(
    (c: FlatCase) => {
      if (filter !== "all" && verdictOf(c.id) !== filter) return false
      if (q && !(haystacks.get(c.id) ?? "").includes(q)) return false
      return true
    },
    [filter, q, verdictOf]
  )

  /** The cases currently on screen, in document order -- j/k walk this. */
  const visible = React.useMemo(() => allCases.filter(matches), [matches])

  /**
   * The same list, cut into journeys. Each section takes its share from this
   * one filtered pass; it used to re-filter its own cases, so a keystroke ran
   * the predicate over all 247 cases twenty-four times rather than once.
   */
  const visibleBySuite = React.useMemo(() => {
    const bySuite = new Map<string, FlatCase[]>()
    for (const c of visible) {
      const shown = bySuite.get(c.suiteKey)
      if (shown) shown.push(c)
      else bySuite.set(c.suiteKey, [c])
    }
    return bySuite
  }, [visible])

  const toggleOpen = React.useCallback((id: string) => {
    setOpen((prev) => {
      const next = new Set(prev)
      if (next.has(id)) next.delete(id)
      else next.add(id)
      return next
    })
  }, [])

  const focusCase = React.useCallback((id: string) => {
    setFocusId(id)
    const el = document.getElementById(`case-${id}`)
    el?.scrollIntoView({ block: "center", behavior: scrollBehavior() })
    // Move real focus, not just the highlight. The bg-accent tint alone is
    // invisible to a screen reader and to forced-colors mode, and it left the
    // "current" row disconnected from the browser's own focus, so Tab carried
    // on from wherever it had been. preventScroll because the line above has
    // already placed the row.
    el?.querySelector<HTMLButtonElement>("button")?.focus({
      preventScroll: true,
    })
  }, [])

  // The two handlers every row gets. They take the id back from the row rather
  // than closing over it, so all 245 rows share one pair and CaseRow's memo
  // holds through a keystroke, a focus move, or a scroll into a new journey.
  const recordVerdict = React.useCallback(
    (id: string, v: Verdict) => {
      setVerdict(id, v)
      setFocusId(id)
    },
    [setVerdict]
  )

  const toggleCase = React.useCallback(
    (id: string) => {
      toggleOpen(id)
      setFocusId(id)
    },
    [toggleOpen]
  )

  /*
   * nextTodo reads the focus through a ref instead of the state it mirrors.
   * It is a prop of the memoised Rail, and taking `focusId` as a dependency
   * gave it a new identity on every j/k press -- which re-rendered the rail,
   * and its 23 tick strips, on each one. The keydown handler below still reads
   * `focusId` directly, because it genuinely has to re-subscribe.
   */
  const focusRef = React.useRef(focusId)
  React.useEffect(() => {
    focusRef.current = focusId
  }, [focusId])

  const nextTodo = React.useCallback(() => {
    const at = focusRef.current
    const from = at ? allCases.findIndex((c) => c.id === at) + 1 : 0
    const order = [...allCases.slice(from), ...allCases.slice(0, from)]
    const target = order.find((c) => verdictOf(c.id) === "todo")
    if (target) focusCase(target.id)
  }, [verdictOf, focusCase])

  const copyReport = React.useCallback(async () => {
    try {
      await navigator.clipboard.writeText(buildReport(verdictOf))
      setCopied(true)
      window.setTimeout(() => setCopied(false), 1800)
    } catch {
      // Clipboard blocked. Nothing useful to fall back to here.
    }
  }, [verdictOf])

  const clearRun = React.useCallback(() => {
    if (
      window.confirm(
        "Clear every recorded verdict? This cannot be undone, and the summary is not saved anywhere else."
      )
    ) {
      reset()
    }
  }, [reset])

  // Keyboard. Every binding is a bare letter, so it must not fire while the
  // tester is typing into the search box.
  React.useEffect(() => {
    if (!shortcuts) return
    const onKey = (e: KeyboardEvent) => {
      const t = e.target as HTMLElement | null
      const typing =
        t &&
        (t.tagName === "INPUT" ||
          t.tagName === "TEXTAREA" ||
          t.isContentEditable)

      // A held key should not record 40 verdicts.
      if (e.repeat) return

      if (e.key === "/" && !typing) {
        e.preventDefault()
        searchRef.current?.focus()
        return
      }
      if (e.key === "Escape" && t === searchRef.current) {
        searchRef.current?.blur()
        return
      }
      if (typing || e.metaKey || e.ctrlKey || e.altKey) return

      const idx = focusId ? visible.findIndex((c) => c.id === focusId) : -1

      switch (e.key) {
        case "j": {
          e.preventDefault()
          const next = visible[Math.min(idx + 1, visible.length - 1)]
          if (next) focusCase(next.id)
          break
        }
        case "k": {
          e.preventDefault()
          const prev = visible[Math.max(idx - 1, 0)]
          if (prev) focusCase(prev.id)
          break
        }
        case "n":
          e.preventDefault()
          nextTodo()
          break
        case "p":
          if (focusId) setVerdict(focusId, "pass")
          break
        case "f":
          if (focusId) setVerdict(focusId, "fail")
          break
        case "x":
          if (focusId) setVerdict(focusId, "todo")
          break
        case "o":
          if (focusId) toggleOpen(focusId)
          break
        case "e":
          setOpen((prev) =>
            prev.size >= visible.length
              ? new Set()
              : new Set(visible.map((c) => c.id))
          )
          break
        default:
          break
      }
    }
    window.addEventListener("keydown", onKey)
    return () => window.removeEventListener("keydown", onKey)
  }, [visible, focusId, focusCase, nextTodo, setVerdict, toggleOpen, shortcuts])

  /*
   * True while a journey link is animating the page to its target.
   *
   * The observer below reports whatever journey is passing the top of the
   * viewport, which is right when a reader is scrolling and wrong when the
   * page is travelling on their behalf. Jumping from A to W sweeps every
   * journey between them through the band in a few hundred milliseconds, and
   * the strip's marker would strobe across twenty groups before landing --
   * motion nobody asked for, drawing the eye away from where they are going.
   * So the marker is set once, to the target, and held there until the page
   * stops moving.
   */
  const jumping = React.useRef(false)

  React.useEffect(() => {
    let release: number | undefined

    const settle = () => {
      jumping.current = false
      window.clearTimeout(release)
    }

    // Every journey link on the page is a plain anchor -- deliberately, since
    // the rail is the page's real navigation -- so one delegated listener
    // catches the rail's links and the run strip's alike, and keeps both
    // components unaware of this.
    const onClick = (e: MouseEvent) => {
      const target = e.target as HTMLElement | null
      const link = target?.closest?.<HTMLAnchorElement>('a[href^="#suite-"]')
      if (!link) return
      jumping.current = true
      setActiveSuite(link.getAttribute("href")?.slice(7) ?? null)
      // scrollend is exact where it exists. The timeout is the fallback, and
      // is deliberately longer than any native smooth scroll: releasing late
      // costs one stale frame, releasing early brings the strobe back.
      window.clearTimeout(release)
      release = window.setTimeout(settle, 1200)
    }

    // A reader who grabs the wheel mid-flight has taken over, so the marker
    // goes back to following them immediately rather than waiting out a
    // journey they have abandoned.
    const takeover = () => {
      if (jumping.current) settle()
    }

    document.addEventListener("click", onClick)
    window.addEventListener("scrollend", settle)
    window.addEventListener("wheel", takeover, { passive: true })
    window.addEventListener("touchstart", takeover, { passive: true })
    return () => {
      document.removeEventListener("click", onClick)
      window.removeEventListener("scrollend", settle)
      window.removeEventListener("wheel", takeover)
      window.removeEventListener("touchstart", takeover)
      window.clearTimeout(release)
    }
  }, [])

  // Highlight the journey the reader is actually looking at.
  React.useEffect(() => {
    const observer = new IntersectionObserver(
      (entries) => {
        if (jumping.current) return
        const shown = entries
          .filter((en) => en.isIntersecting)
          .sort(
            (a, b) => a.boundingClientRect.top - b.boundingClientRect.top
          )[0]
        if (shown) setActiveSuite(shown.target.id.replace("suite-", ""))
      },
      { rootMargin: "-15% 0px -70% 0px" }
    )
    for (const s of suites) {
      const el = document.getElementById(`suite-${s.key}`)
      if (el) observer.observe(el)
    }
    return () => observer.disconnect()
  }, [])

  return (
    <div className="min-h-dvh">
      {/* Roughly thirty tab stops sit between the top of the page and the
          first check -- the theme toggle, then the whole rail. */}
      <a
        href="#checks"
        className="focus-ring sr-only rounded-lg bg-card px-4 py-2 text-[13px] font-medium focus:not-sr-only focus:absolute focus:top-3 focus:left-3 focus:z-50 focus:border focus:border-border"
      >
        Skip to the checks
      </a>
      <Masthead
        summary={summary}
        activeSuite={activeSuite}
        theme={theme}
        setTheme={setTheme}
      />

      <div className="mx-auto max-w-[92rem] px-5 py-6 md:px-8 md:py-8">
        <GateDiagram />

        <div className="mt-8 grid gap-8 lg:grid-cols-[17rem_minmax(0,1fr)] lg:gap-10">
          <Rail
            groups={summary.groups}
            activeSuite={activeSuite}
            onNextTodo={nextTodo}
            onReset={clearRun}
            onCopyReport={copyReport}
            copied={copied}
            shortcuts={shortcuts}
            onToggleShortcuts={toggleShortcuts}
          />

          <main className="min-w-0">
            {/* Prerequisites, so they come before the thing they prepare you
                for. Both fold away and remember the choice, because a tester
                on their third session has already run setup. */}
            <div className="mb-8 space-y-4">
              <SetupPanel />
              <CastPanel />
            </div>

            <div
              id="checks"
              // --pin-h is the masthead's standing height, published by its
              // own measurement, and 0px below sm where it does not pin. So
              // this parks under the masthead rather than behind it without
              // either file having to know the other's dimensions.
              className="sticky top-[var(--pin-h)] z-10 flex scroll-mt-[calc(var(--pin-h)+1rem)] flex-wrap items-center gap-3 bg-background/95 py-3 backdrop-blur"
            >
              <div className="relative basis-full sm:min-w-[13rem] sm:flex-1 sm:basis-auto">
                <Search
                  aria-hidden="true"
                  className="pointer-events-none absolute top-1/2 left-3.5 z-1 size-3.5 -translate-y-1/2 text-muted-foreground"
                />
                <Input
                  ref={searchRef}
                  type="search"
                  aria-label="Search checks"
                  value={query}
                  onChange={(e) => setQuery(e.target.value)}
                  placeholder="Search commands, errors, or a check id"
                  className="border-input bg-card pl-9"
                />
              </div>

              <ToggleGroup
                aria-label="Filter by result"
                variant="outline"
                size="sm"
                spacing={0}
                value={[filter]}
                onValueChange={(v) =>
                  setFilter(((v as Filter[])[0] ?? "all") as Filter)
                }
                className="bg-card"
              >
                {filters.map(([f, label]) => (
                  <ToggleGroupItem key={f} value={f}>
                    {label}
                  </ToggleGroupItem>
                ))}
              </ToggleGroup>

              <span
                aria-live="polite"
                className="text-[12.5px] text-muted-foreground tabular-nums"
              >
                {visible.length} of {caseCount}
              </span>
            </div>

            {visible.length === 0 ? (
              <p className="rounded-lg border border-dashed border-border px-5 py-10 text-center text-[14px] text-muted-foreground">
                Nothing matches that. Clear the search, or switch the filter
                back to All.
              </p>
            ) : (
              <div className="space-y-8">
                {suites.map((s, i) => {
                  const shown = visibleBySuite.get(s.key)
                  if (!shown?.length) return null
                  // summarise() walks the same `suites` array in order, so the
                  // tally at this index is this journey's.
                  const tally = summary.groups[i]

                  return (
                    <section
                      key={s.key}
                      id={`suite-${s.key}`}
                      aria-labelledby={`suite-${s.key}-heading`}
                      // Clears both standing bands: the masthead's readout,
                      // plus the ~56px checks toolbar under it, and some air.
                      className="scroll-mt-[calc(var(--pin-h)+4.5rem)]"
                    >
                      <div className="flex flex-wrap items-baseline justify-between gap-x-4 gap-y-1">
                        {/* The letter is inside the heading, not beside it,
                            so a narrow viewport cannot wrap it away from the
                            title it identifies. */}
                        <h2
                          id={`suite-${s.key}-heading`}
                          className="flex min-w-0 items-baseline gap-3 text-[17px] leading-tight font-semibold"
                        >
                          <span className="shrink-0 font-mono text-[15px] text-primary">
                            {s.key}
                          </span>
                          <span className="min-w-0">{s.title}</span>
                        </h2>
                        <span className="shrink-0 font-mono text-[12.5px] text-muted-foreground tabular-nums">
                          {tally.fail > 0 ? (
                            <span className="mr-2 text-destructive">
                              {tally.fail} failed
                            </span>
                          ) : null}
                          {tally.pass}/{tally.count}
                        </span>
                      </div>
                      <p className="mt-1 pl-[1.6rem] text-[13px] text-muted-foreground">
                        {s.actor}
                      </p>
                      <p className="mt-2.5 max-w-[74ch] pl-[1.6rem] text-[13.5px] leading-relaxed text-muted-foreground">
                        <Prose>{s.premise}</Prose>
                      </p>

                      {s.context?.map((para) => (
                        <p
                          key={para.slice(0, 48)}
                          className="mt-2.5 max-w-[74ch] pl-[1.6rem] text-[13.5px] leading-relaxed text-muted-foreground"
                        >
                          <Prose>{para}</Prose>
                        </p>
                      ))}

                      <ul className="mt-4 overflow-hidden rounded-lg border border-border bg-card">
                        {shown.map((c) => (
                          <CaseRow
                            key={c.id}
                            item={c}
                            verdict={verdictOf(c.id)}
                            onVerdict={recordVerdict}
                            open={open.has(c.id)}
                            onToggle={toggleCase}
                            focused={focusId === c.id}
                          />
                        ))}
                      </ul>
                    </section>
                  )
                })}
              </div>
            )}

            {/* Lookups, not prerequisites: consulted mid-run when a result
                surprises you. The prep panels moved above the checks. */}
            <div className="mt-12 space-y-6">
              <ErrorPanel />
              <CapabilityPanel />
              <CommandPanel />
              <CorrectionsPanel />
            </div>
          </main>
        </div>
      </div>

      <Footer
        onBackToTop={() =>
          window.scrollTo({ top: 0, behavior: scrollBehavior() })
        }
      />
    </div>
  )
}
