import { beforeEach, describe, expect, it } from "vitest"

import {
  getLastVault,
  resolveIndexRedirect,
  setLastVault,
} from "@/lib/current-vault"

beforeEach(() => {
  localStorage.clear()
})

describe("last vault storage", () => {
  it("round-trips through localStorage", () => {
    expect(getLastVault()).toBeNull()

    setLastVault("prod")
    expect(getLastVault()).toBe("prod")
  })
})

describe("resolveIndexRedirect", () => {
  it("falls back to the vault picker when neither an explicit vault nor a stored one exists", () => {
    expect(resolveIndexRedirect(undefined)).toBe("/vaults")
  })

  it("prefers the stored last-used vault when no explicit vault is given", () => {
    setLastVault("staging")

    expect(resolveIndexRedirect(undefined)).toBe("/vaults/staging/secrets")
  })

  it("prefers an explicit vault over the stored last-used vault", () => {
    setLastVault("staging")

    expect(resolveIndexRedirect("prod")).toBe("/vaults/prod/secrets")
  })
})
