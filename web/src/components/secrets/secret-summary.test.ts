import { describe, expect, it } from "vitest"

import type { Secret } from "@/api/secrets"
import {
  filterSecrets,
  summarizeSecrets,
} from "@/components/secrets/secret-summary"

function secret(overrides: Partial<Secret> & { name: string }): Secret {
  return {
    id: overrides.name,
    version: 1,
    enabled: true,
    createdAt: "2026-01-01T00:00:00Z",
    ...overrides,
  }
}

describe("summarizeSecrets", () => {
  it("counts the whole list and the enabled subset", () => {
    const summary = summarizeSecrets(
      [
        secret({ name: "a" }),
        secret({ name: "b", enabled: false }),
        secret({ name: "c" }),
      ],
      0
    )

    expect(summary).toEqual({ total: 3, enabled: 2, deleted: 0 })
  })

  it("passes the deleted count straight through", () => {
    expect(summarizeSecrets([], 4).deleted).toBe(4)
  })

  it("reports an unavailable deleted count as null rather than zero", () => {
    // Listing deleted secrets is a separate permission, so a 403 there must
    // not be rendered as "0 deleted" -- that would read as a fact.
    expect(summarizeSecrets([secret({ name: "a" })], null)).toEqual({
      total: 1,
      enabled: 1,
      deleted: null,
    })
  })
})

describe("filterSecrets", () => {
  const secrets = [
    secret({ name: "db-password", tags: ["env=prod"] }),
    secret({ name: "api-token", tags: ["env=staging", "team=platform"] }),
  ]

  it("returns everything for a blank query", () => {
    expect(filterSecrets(secrets, "   ")).toEqual(secrets)
  })

  it("matches on name, case-insensitively", () => {
    expect(filterSecrets(secrets, "DB-PASS").map((item) => item.name)).toEqual([
      "db-password",
    ])
  })

  it("matches on a tag", () => {
    expect(filterSecrets(secrets, "platform").map((item) => item.name)).toEqual(
      ["api-token"]
    )
  })

  it("returns an empty list when nothing matches", () => {
    expect(filterSecrets(secrets, "nope")).toEqual([])
  })
})
