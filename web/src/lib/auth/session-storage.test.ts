import { beforeEach, describe, expect, it } from "vitest"

import {
  clear,
  getRecentVaults,
  getRefreshToken,
  pushRecentVault,
  setRefreshToken,
} from "@/lib/auth/session-storage"

beforeEach(() => {
  localStorage.clear()
})

describe("refresh token storage", () => {
  it("round-trips through localStorage", () => {
    expect(getRefreshToken()).toBeNull()

    setRefreshToken("abc123")
    expect(getRefreshToken()).toBe("abc123")

    clear()
    expect(getRefreshToken()).toBeNull()
  })
})

describe("recent vaults MRU list", () => {
  it("returns an empty list when nothing is stored", () => {
    expect(getRecentVaults()).toEqual([])
  })

  it("caps the list at 10 entries", () => {
    for (let i = 0; i < 12; i++) {
      pushRecentVault(`vault-${i}`)
    }

    expect(getRecentVaults()).toHaveLength(10)
    expect(getRecentVaults()[0]).toBe("vault-11")
  })

  it("moves a re-pushed entry to the front without duplicating it", () => {
    pushRecentVault("prod")
    pushRecentVault("staging")
    pushRecentVault("prod")

    expect(getRecentVaults()).toEqual(["prod", "staging"])
  })
})
