const MINUTE = 60_000
const HOUR = 60 * MINUTE
const DAY = 24 * HOUR
const WEEK = 7 * DAY
const MONTH = 30 * DAY
const YEAR = 365 * DAY

/**
 * Renders an ISO timestamp as a short, scannable age -- "3w ago", "6mo
 * ago". Deliberately coarse: an operator scanning a vault list wants the
 * order of magnitude, not a precise date. Unparseable input yields
 * "unknown" rather than "Invalid Date", and a future timestamp (clock
 * skew between server and browser) collapses to "just now".
 */
export function formatRelativeTime(iso: string, now: Date = new Date()) {
  const then = Date.parse(iso)
  if (Number.isNaN(then)) {
    return "unknown"
  }

  const elapsed = now.getTime() - then
  if (elapsed < MINUTE) {
    return "just now"
  }
  if (elapsed < HOUR) {
    return `${Math.floor(elapsed / MINUTE)}m ago`
  }
  if (elapsed < DAY) {
    return `${Math.floor(elapsed / HOUR)}h ago`
  }
  if (elapsed < WEEK) {
    return `${Math.floor(elapsed / DAY)}d ago`
  }
  if (elapsed < MONTH) {
    return `${Math.floor(elapsed / WEEK)}w ago`
  }
  if (elapsed < YEAR) {
    return `${Math.floor(elapsed / MONTH)}mo ago`
  }
  return `${Math.floor(elapsed / YEAR)}y ago`
}
