import { describe, expect, it } from "vitest"

import { validateSecretName } from "@/components/secrets/secret-name"

describe("validateSecretName", () => {
  it("accepts a name the backend's pattern allows", () => {
    expect(validateSecretName("db-password")).toBeNull()
    expect(validateSecretName("Token2")).toBeNull()
  })

  it("rejects a blank name", () => {
    expect(validateSecretName("   ")).toBe("Name is required.")
  })

  it("rejects a name that does not start with a letter", () => {
    expect(validateSecretName("1password")).toMatch(/start with a letter/)
    expect(validateSecretName("-lead")).toMatch(/start with a letter/)
  })

  it("rejects characters outside letters, digits and hyphens", () => {
    expect(validateSecretName("db_password")).toMatch(/letters, numbers/)
    expect(validateSecretName("db password")).toMatch(/letters, numbers/)
  })

  it("rejects a name longer than the backend's limit", () => {
    expect(validateSecretName(`a${"b".repeat(127)}`)).toMatch(/127/)
  })
})
