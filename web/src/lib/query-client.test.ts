import { describe, expect, it } from "vitest"

import { ApiError } from "@/api/types"
import { shouldRetry } from "@/lib/query-client"

describe("shouldRetry", () => {
  it("does not retry a 429 carrying a retry_after_seconds hint", () => {
    const error = new ApiError({
      id: "rate_limited",
      message: "too many requests",
      status_code: 429,
      retry_after_seconds: 5,
    })

    expect(shouldRetry(0, error)).toBe(false)
  })

  it("does not retry other 4xx client errors", () => {
    const error = new ApiError({ message: "forbidden", status_code: 403 })

    expect(shouldRetry(0, error)).toBe(false)
  })

  it("retries a 5xx server error up to the bound", () => {
    const error = new ApiError({ message: "internal error", status_code: 500 })

    expect(shouldRetry(0, error)).toBe(true)
    expect(shouldRetry(1, error)).toBe(true)
    expect(shouldRetry(2, error)).toBe(false)
  })

  it("retries a non-ApiError failure up to the bound", () => {
    expect(shouldRetry(0, new Error("network error"))).toBe(true)
    expect(shouldRetry(2, new Error("network error"))).toBe(false)
  })
})
