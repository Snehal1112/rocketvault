import { describe, expect, it } from "vitest"

import {
  formatTagList,
  MAX_SECRET_TAGS,
  parseTagList,
  validateTagList,
} from "@/components/secrets/secret-tags"

describe("parseTagList", () => {
  it("returns undefined for blank input so no tags key is sent", () => {
    expect(parseTagList("   ")).toBeUndefined()
  })

  it("splits on commas and trims each entry", () => {
    expect(parseTagList(" env=prod , team=platform ")).toEqual([
      "env=prod",
      "team=platform",
    ])
  })

  it("drops empty entries left by trailing or doubled commas", () => {
    expect(parseTagList("env=prod,,")).toEqual(["env=prod"])
  })

  it("de-duplicates repeated tags", () => {
    expect(parseTagList("a,b,a")).toEqual(["a", "b"])
  })
})

describe("formatTagList", () => {
  it("round-trips a parsed list back into the input string", () => {
    expect(formatTagList(["env=prod", "team=platform"])).toBe(
      "env=prod, team=platform"
    )
  })

  it("renders an absent list as an empty string", () => {
    expect(formatTagList(undefined)).toBe("")
  })
})

describe("validateTagList", () => {
  it("accepts a list within the backend's limits", () => {
    expect(validateTagList(["env=prod"])).toBeNull()
    expect(validateTagList(undefined)).toBeNull()
  })

  it("rejects more tags than the backend accepts", () => {
    const tooMany = Array.from(
      { length: MAX_SECRET_TAGS + 1 },
      (_unused, index) => `tag${index}`
    )

    expect(validateTagList(tooMany)).toMatch(/15/)
  })

  it("rejects a tag longer than the backend's per-tag limit", () => {
    expect(validateTagList(["x".repeat(257)])).toMatch(/256/)
  })
})
