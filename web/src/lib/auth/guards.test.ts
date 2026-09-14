import { isRedirect } from "@tanstack/react-router"
import { beforeEach, describe, expect, it, vi } from "vitest"

import { resetAuthStateForTests, setSession } from "@/lib/auth/auth-context"
import { requireAuth, requireGlobalAdmin } from "@/lib/auth/guards"
import { toast } from "@/components/ui/toast"

beforeEach(() => {
  localStorage.clear()
  resetAuthStateForTests()
})

describe("requireAuth", () => {
  it("throws a redirect to /login when not authenticated", () => {
    expect.assertions(2)
    try {
      requireAuth()
    } catch (error) {
      expect(isRedirect(error)).toBe(true)
      if (isRedirect(error)) {
        expect(error.options.to).toBe("/login")
      }
    }
  })

  it("does not throw when authenticated", () => {
    setSession("token", "refresh", {
      id: "u1",
      username: "alice",
      roles: ["user"],
    })

    expect(() => requireAuth()).not.toThrow()
  })
})

describe("requireGlobalAdmin", () => {
  it("redirects to /login when not authenticated", () => {
    expect.assertions(2)
    try {
      requireGlobalAdmin()
    } catch (error) {
      expect(isRedirect(error)).toBe(true)
      if (isRedirect(error)) {
        expect(error.options.to).toBe("/login")
      }
    }
  })

  it("redirects to / with a toast when authenticated but not a global admin", () => {
    setSession("token", "refresh", {
      id: "u1",
      username: "alice",
      roles: ["user"],
    })
    const addSpy = vi.spyOn(toast, "add")
    expect.assertions(3)

    try {
      requireGlobalAdmin()
    } catch (error) {
      expect(isRedirect(error)).toBe(true)
      if (isRedirect(error)) {
        expect(error.options.to).toBe("/")
      }
    }
    expect(addSpy).toHaveBeenCalled()
  })

  it("does not throw for a global admin", () => {
    setSession("token", "refresh", {
      id: "u1",
      username: "admin",
      roles: ["admin"],
    })

    expect(() => requireGlobalAdmin()).not.toThrow()
  })
})
