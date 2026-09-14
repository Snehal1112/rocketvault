import { act, renderHook } from "@testing-library/react"
import { beforeEach, describe, expect, it } from "vitest"

import {
  getAccessToken,
  resetAuthStateForTests,
  useAuth,
} from "@/lib/auth/auth-context"
import { getRefreshToken } from "@/lib/auth/session-storage"

beforeEach(() => {
  localStorage.clear()
  resetAuthStateForTests()
})

describe("useAuth", () => {
  it("starts in the loading status", () => {
    const { result } = renderHook(() => useAuth())

    expect(result.current.status).toBe("loading")
  })

  it("moves to authenticated on setSession and exposes the access token", () => {
    const { result } = renderHook(() => useAuth())

    act(() => {
      result.current.setSession("token-1", "refresh-1", {
        id: "u1",
        username: "alice",
        roles: ["user"],
      })
    })

    expect(result.current.status).toBe("authenticated")
    expect(getAccessToken()).toBe("token-1")
    expect(getRefreshToken()).toBe("refresh-1")
  })

  it("derives isGlobalAdmin from the user's roles", () => {
    const { result } = renderHook(() => useAuth())

    act(() => {
      result.current.setSession("token-1", "refresh-1", {
        id: "u1",
        username: "admin",
        roles: ["admin"],
      })
    })

    expect(result.current.isGlobalAdmin).toBe(true)
  })

  it("moves to anonymous on clearSession and clears the stored refresh token", () => {
    const { result } = renderHook(() => useAuth())

    act(() => {
      result.current.setSession("token-1", "refresh-1", {
        id: "u1",
        username: "alice",
        roles: ["user"],
      })
    })
    act(() => {
      result.current.clearSession()
    })

    expect(result.current.status).toBe("anonymous")
    expect(getAccessToken()).toBeNull()
    expect(getRefreshToken()).toBeNull()
  })
})
