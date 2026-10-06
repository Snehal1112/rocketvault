import { describe, expect, it } from "vitest"

import {
  describeKeyMaterial,
  isHsmBacked,
  isSecp256k1,
  keyFamily,
} from "@/components/keys/key-type"

describe("keyFamily", () => {
  it("groups every type string the backend can return", () => {
    expect(keyFamily("RSA")).toBe("rsa")
    expect(keyFamily("RSA-HSM")).toBe("rsa")
    expect(keyFamily("ECDSA")).toBe("ec")
    expect(keyFamily("ES256K")).toBe("ec")
    expect(keyFamily("EC-HSM")).toBe("ec")
    expect(keyFamily("oct")).toBe("oct")
    expect(keyFamily("oct-HSM")).toBe("oct")
  })

  it("reports an unrecognised type rather than guessing a family", () => {
    expect(keyFamily("QUANTUM")).toBe("unknown")
  })
})

describe("isHsmBacked", () => {
  it("is true only for the -HSM suffixed types the backend adds", () => {
    expect(isHsmBacked("RSA-HSM")).toBe(true)
    expect(isHsmBacked("EC-HSM")).toBe(true)
    expect(isHsmBacked("oct-HSM")).toBe(true)
    expect(isHsmBacked("RSA")).toBe(false)
    expect(isHsmBacked("ECDSA")).toBe(false)
  })
})

describe("isSecp256k1", () => {
  it("detects the ES256K type", () => {
    expect(isSecp256k1({ type: "ES256K" })).toBe(true)
  })

  it("detects it from the curve when the type was flattened to EC-HSM", () => {
    expect(isSecp256k1({ type: "EC-HSM", curve: "P-256K" })).toBe(true)
  })

  it("is false for the NIST curves", () => {
    expect(isSecp256k1({ type: "ECDSA", curve: "P-384" })).toBe(false)
  })
})

describe("describeKeyMaterial", () => {
  it("describes RSA by bit size", () => {
    expect(describeKeyMaterial({ type: "RSA", bits: 3072 })).toBe("RSA 3072")
  })

  it("describes EC by curve", () => {
    expect(describeKeyMaterial({ type: "ECDSA", curve: "P-384" })).toBe(
      "EC P-384"
    )
  })

  it("describes symmetric keys as AES, since oct keys are always AES here", () => {
    expect(describeKeyMaterial({ type: "oct-HSM", bits: 256 })).toBe("AES 256")
  })

  it("falls back to the raw type when the size or curve is missing", () => {
    expect(describeKeyMaterial({ type: "RSA" })).toBe("RSA")
    expect(describeKeyMaterial({ type: "ECDSA" })).toBe("EC")
  })
})
