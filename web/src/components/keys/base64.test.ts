import { describe, expect, it } from "vitest"

import {
  decodeUtf8Base64,
  encodeUtf8Base64,
  looksLikeBase64,
} from "@/components/keys/base64"

describe("encodeUtf8Base64", () => {
  it("round-trips ASCII", () => {
    expect(encodeUtf8Base64("hello")).toBe("aGVsbG8=")
    expect(decodeUtf8Base64("aGVsbG8=")).toBe("hello")
  })

  it("handles code points above U+00FF, which btoa alone cannot", () => {
    const encoded = encodeUtf8Base64("héllo ☃")

    expect(decodeUtf8Base64(encoded)).toBe("héllo ☃")
  })
})

describe("decodeUtf8Base64", () => {
  it("returns null for input that is not base64", () => {
    expect(decodeUtf8Base64("not base64!!")).toBeNull()
  })

  it("returns null for base64 that is not valid UTF-8, e.g. a signature", () => {
    expect(decodeUtf8Base64("//79")).toBeNull()
  })
})

describe("looksLikeBase64", () => {
  it("accepts correctly padded base64", () => {
    expect(looksLikeBase64("aGVsbG8=")).toBe(true)
    expect(looksLikeBase64("  aGVsbG8=  ")).toBe(true)
  })

  it("rejects empty input, bad padding, and base64url characters", () => {
    expect(looksLikeBase64("")).toBe(false)
    expect(looksLikeBase64("aGVsbG8")).toBe(false)
    expect(looksLikeBase64("a-_sbG8=")).toBe(false)
  })
})
