import { describe, expect, it } from "vitest"

import type { Vault } from "@/api/vaults"
import { summarizeVaults } from "@/components/vaults/vault-summary"

function vault(overrides: Partial<Vault>): Vault {
  return {
    id: "v1",
    name: "prod",
    enabled: true,
    purgeProtection: false,
    retentionDays: 90,
    createdBy: "u1",
    createdAt: "2026-01-01T00:00:00Z",
    ...overrides,
  }
}

describe("summarizeVaults", () => {
  it("returns zeros for an empty list", () => {
    expect(summarizeVaults([])).toEqual({ total: 0, enabled: 0, disabled: 0 })
  })

  it("splits the total into enabled and disabled", () => {
    const summary = summarizeVaults([
      vault({ id: "v1", enabled: true }),
      vault({ id: "v2", enabled: true }),
      vault({ id: "v3", enabled: false }),
    ])

    expect(summary).toEqual({ total: 3, enabled: 2, disabled: 1 })
  })

  it("excludes soft-deleted vaults from every count", () => {
    const summary = summarizeVaults([
      vault({ id: "v1", enabled: true }),
      vault({ id: "v2", enabled: false, deletedAt: "2026-02-01T00:00:00Z" }),
    ])

    expect(summary).toEqual({ total: 1, enabled: 1, disabled: 0 })
  })
})
