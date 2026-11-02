import { describe, expect, it } from "vitest"

import { formatRelativeTime } from "@/lib/format"

const now = new Date("2026-09-14T12:00:00Z")

function ago(milliseconds: number) {
  return new Date(now.getTime() - milliseconds).toISOString()
}

describe("formatRelativeTime", () => {
  it("collapses anything under a minute to 'just now'", () => {
    expect(formatRelativeTime(ago(10_000), now)).toBe("just now")
  })

  it("steps through minutes, hours, days, weeks, months, and years", () => {
    expect(formatRelativeTime(ago(5 * 60_000), now)).toBe("5m ago")
    expect(formatRelativeTime(ago(3 * 3_600_000), now)).toBe("3h ago")
    expect(formatRelativeTime(ago(3 * 86_400_000), now)).toBe("3d ago")
    expect(formatRelativeTime(ago(21 * 86_400_000), now)).toBe("3w ago")
    expect(formatRelativeTime(ago(180 * 86_400_000), now)).toBe("6mo ago")
    expect(formatRelativeTime(ago(800 * 86_400_000), now)).toBe("2y ago")
  })

  it("treats a future timestamp as 'just now' rather than a negative age", () => {
    expect(formatRelativeTime(ago(-60_000), now)).toBe("just now")
  })

  it("returns 'unknown' for an unparseable timestamp", () => {
    expect(formatRelativeTime("not-a-date", now)).toBe("unknown")
  })
})
