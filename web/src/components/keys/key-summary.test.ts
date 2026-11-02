import { describe, expect, it } from "vitest"

import type { Key } from "@/api/keys"
import { keyStatusOf, summarizeKeys } from "@/components/keys/key-summary"

const now = new Date("2026-06-01T00:00:00Z")

function makeKey(overrides: Partial<Key> = {}): Key {
  return {
    id: "k1",
    name: "signing-key",
    type: "RSA",
    userId: "u1",
    revoked: false,
    createdAt: "2026-01-01T00:00:00Z",
    tags: [],
    enabled: true,
    bits: 2048,
    publicJwk: {},
    ...overrides,
  }
}

describe("keyStatusOf", () => {
  it("reports a healthy key as enabled", () => {
    expect(keyStatusOf(makeKey(), now)).toEqual({
      tone: "on",
      label: "Enabled",
    })
  })

  it("ranks revoked above every other state", () => {
    const key = makeKey({ revoked: true, enabled: false })

    expect(keyStatusOf(key, now)).toEqual({ tone: "danger", label: "Revoked" })
  })

  it("reports a disabled key", () => {
    expect(keyStatusOf(makeKey({ enabled: false }), now)).toEqual({
      tone: "off",
      label: "Disabled",
    })
  })

  it("reports an elapsed expiry as expired", () => {
    const key = makeKey({ expiresAt: "2026-05-01T00:00:00Z" })

    expect(keyStatusOf(key, now)).toEqual({ tone: "danger", label: "Expired" })
  })

  it("warns inside the 30-day expiry window", () => {
    const key = makeKey({ expiresAt: "2026-06-20T00:00:00Z" })

    expect(keyStatusOf(key, now)).toEqual({
      tone: "warning",
      label: "Expiring soon",
    })
  })

  it("leaves an expiry beyond the window alone", () => {
    const key = makeKey({ expiresAt: "2027-06-20T00:00:00Z" })

    expect(keyStatusOf(key, now).label).toBe("Enabled")
  })

  it("warns when the key is not valid yet", () => {
    const key = makeKey({ notBefore: "2026-07-01T00:00:00Z" })

    expect(keyStatusOf(key, now)).toEqual({
      tone: "warning",
      label: "Not yet valid",
    })
  })

  it("ignores an unparseable timestamp instead of rendering a bogus state", () => {
    const key = makeKey({ expiresAt: "not-a-date" })

    expect(keyStatusOf(key, now).label).toBe("Enabled")
  })
})

describe("summarizeKeys", () => {
  it("counts total, HSM-backed, expiring soon, and unavailable keys", () => {
    const keys = [
      makeKey({ id: "a" }),
      makeKey({ id: "b", type: "RSA-HSM" }),
      makeKey({ id: "c", type: "oct-HSM", expiresAt: "2026-06-10T00:00:00Z" }),
      makeKey({ id: "d", enabled: false }),
      makeKey({ id: "e", revoked: true }),
    ]

    expect(summarizeKeys(keys, now)).toEqual({
      total: 5,
      hsmBacked: 2,
      expiringSoon: 1,
      unavailable: 2,
    })
  })

  it("counts an already-expired key as unavailable, not expiring soon", () => {
    const keys = [makeKey({ expiresAt: "2026-01-02T00:00:00Z" })]

    expect(summarizeKeys(keys, now)).toEqual({
      total: 1,
      hsmBacked: 0,
      expiringSoon: 0,
      unavailable: 1,
    })
  })

  it("returns zeroes for an empty vault", () => {
    expect(summarizeKeys([], now)).toEqual({
      total: 0,
      hsmBacked: 0,
      expiringSoon: 0,
      unavailable: 0,
    })
  })
})
