import { isRedirect } from "@tanstack/react-router"
import { beforeEach, describe, expect, it, vi } from "vitest"

import { resetAuthStateForTests, setSession } from "@/lib/auth/auth-context"
import {
  redirectAuthenticatedFromLanding,
  requireAuth,
  requireGlobalAdmin,
} from "@/lib/auth/guards"
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

describe("redirectAuthenticatedFromLanding", () => {
  it("does not throw when anonymous, so the landing page renders", () => {
    expect(() => redirectAuthenticatedFromLanding(null)).not.toThrow()
  })

  it("redirects to the given vault's secrets when authenticated", () => {
    setSession("token", "refresh", {
      id: "u1",
      username: "alice",
      roles: ["user"],
    })
    expect.assertions(3)

    try {
      redirectAuthenticatedFromLanding("prod")
    } catch (error) {
      expect(isRedirect(error)).toBe(true)
      if (isRedirect(error)) {
        expect(error.options.to).toBe("/vaults/$vaultName/secrets")
        expect(error.options.params).toEqual({ vaultName: "prod" })
      }
    }
  })

  it("redirects to the vault picker when authenticated with no vault", () => {
    setSession("token", "refresh", {
      id: "u1",
      username: "alice",
      roles: ["user"],
    })
    expect.assertions(2)

    try {
      redirectAuthenticatedFromLanding(null)
    } catch (error) {
      expect(isRedirect(error)).toBe(true)
      if (isRedirect(error)) {
        expect(error.options.to).toBe("/vaults")
      }
    }
  })
})
