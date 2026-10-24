import { beforeEach, describe, expect, it, vi } from "vitest"

import { request } from "@/api/client"
import { ApiError } from "@/api/types"
import {
  getAuthSnapshot,
  resetAuthStateForTests,
  setSession,
} from "@/lib/auth/auth-context"

function jsonResponse(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  })
}

function unauthorized(): Response {
  return jsonResponse(401, {
    id: "unauthorized",
    message: "authentication required",
    detailed_error: "",
    status_code: 401,
  })
}

function forbidden(): Response {
  return jsonResponse(403, {
    id: "forbidden",
    message: "forbidden",
    detailed_error: "",
    status_code: 403,
  })
}

function refreshOk(token: string, refreshToken: string): Response {
  return jsonResponse(200, {
    token,
    refresh_token: refreshToken,
    user_id: "u1",
    username: "alice",
    roles: ["user"],
    expires_at: new Date().toISOString(),
  })
}

function ok(body: unknown): Response {
  return jsonResponse(200, body)
}

beforeEach(() => {
  localStorage.clear()
  resetAuthStateForTests()
  setSession("old-token", "old-refresh", {
    id: "u1",
    username: "alice",
    roles: ["user"],
  })
  vi.restoreAllMocks()
})

describe("request", () => {
  it("refreshes once on a 401 and retries the original request with the new token", async () => {
    const fetchMock = vi
      .spyOn(globalThis, "fetch")
      .mockResolvedValueOnce(unauthorized())
      .mockResolvedValueOnce(refreshOk("new-token", "new-refresh"))
      .mockResolvedValueOnce(ok({ data: "x" }))

    const result = await request<{ data: string }>("/secrets")

    expect(result).toEqual({ data: "x" })
    const refreshCalls = fetchMock.mock.calls.filter(
      ([url]: [RequestInfo | URL, RequestInit?]) =>
        String(url).includes("/users/refresh")
    )
    expect(refreshCalls).toHaveLength(1)

    const retryCall = fetchMock.mock.calls[2]
    const retryHeaders = new Headers(retryCall?.[1]?.headers)
    expect(retryHeaders.get("Authorization")).toBe("Bearer new-token")
  })

  it("dedupes concurrent 401s into a single refresh call", async () => {
    const fetchMock = vi
      .spyOn(globalThis, "fetch")
      .mockResolvedValueOnce(unauthorized())
      .mockResolvedValueOnce(unauthorized())
      .mockResolvedValueOnce(refreshOk("new-token", "new-refresh"))
      .mockImplementation(() => Promise.resolve(ok({ data: "x" })))

    await Promise.all([request("/secrets"), request("/keys")])

    const refreshCalls = fetchMock.mock.calls.filter(
      ([url]: [RequestInfo | URL, RequestInit?]) =>
        String(url).includes("/users/refresh")
    )
    expect(refreshCalls).toHaveLength(1)
  })

  it("clears the session and does not retry when refresh itself fails", async () => {
    vi.spyOn(globalThis, "fetch")
      .mockResolvedValueOnce(unauthorized())
      .mockResolvedValueOnce(
        jsonResponse(500, {
          id: "internal_error",
          message: "refresh failed",
          detailed_error: "",
          status_code: 500,
        })
      )

    await expect(request("/secrets")).rejects.toBeInstanceOf(ApiError)
    expect(getAuthSnapshot().status).toBe("anonymous")
  })

  it("never retries a 403 and rejects with an ApiError carrying status_code 403", async () => {
    const fetchMock = vi
      .spyOn(globalThis, "fetch")
      .mockResolvedValueOnce(forbidden())

    await expect(request("/secrets")).rejects.toMatchObject({ statusCode: 403 })
    expect(fetchMock).toHaveBeenCalledTimes(1)
  })

  it("maps a non-2xx JSON body onto ApiError's shape", async () => {
    vi.spyOn(globalThis, "fetch").mockResolvedValueOnce(
      jsonResponse(400, {
        id: "invalid_param",
        message: "name is required",
        detailed_error: "validation failed: name",
        request_id: "req-123",
        status_code: 400,
      })
    )

    expect.assertions(6)
    try {
      await request("/vaults")
    } catch (error) {
      expect(error).toBeInstanceOf(ApiError)
      const apiError = error as ApiError
      expect(apiError.id).toBe("invalid_param")
      expect(apiError.message).toBe("name is required")
      expect(apiError.detailedError).toBe("validation failed: name")
      expect(apiError.requestId).toBe("req-123")
      expect(apiError.statusCode).toBe(400)
    }
  })

  it("does not attach an Authorization header for /config", async () => {
    const fetchMock = vi
      .spyOn(globalThis, "fetch")
      .mockResolvedValueOnce(ok({ feature_flags: {} }))

    await request("/config")

    const call = fetchMock.mock.calls[0]
    const headers = new Headers(call?.[1]?.headers)
    expect(headers.has("Authorization")).toBe(false)
  })
})
