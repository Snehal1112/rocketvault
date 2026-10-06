import { describe, expect, it } from "vitest"

import type { Key } from "@/api/keys"
import {
  algorithmsFor,
  defaultAlgorithmFor,
  supportedOperations,
  usesNonce,
} from "@/components/keys/key-algorithms"

function makeKey(overrides: Partial<Key> = {}): Key {
  return {
    id: "k1",
    name: "k",
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

describe("algorithmsFor: RSA", () => {
  const rsa = makeKey()

  it("offers the PKCS#1 and PSS signature algorithms", () => {
    expect(algorithmsFor(rsa, "sign")).toEqual([
      "RS256",
      "RS384",
      "RS512",
      "PS256",
      "PS384",
      "PS512",
    ])
    expect(algorithmsFor(rsa, "verify")).toEqual(algorithmsFor(rsa, "sign"))
  })

  it("offers RSA1_5 for encryption only on a software-backed key", () => {
    expect(algorithmsFor(rsa, "encrypt")).toContain("RSA1_5")
    expect(
      algorithmsFor(makeKey({ type: "RSA-HSM" }), "encrypt")
    ).not.toContain("RSA1_5")
  })

  it("excludes RSA1_5 from wrapping, which the backend allow-list rejects", () => {
    expect(algorithmsFor(rsa, "wrap")).toEqual(["RSA-OAEP-256", "RSA-OAEP"])
    expect(algorithmsFor(rsa, "unwrap")).toEqual(["RSA-OAEP-256", "RSA-OAEP"])
  })
})

describe("algorithmsFor: EC", () => {
  it("offers the NIST signature algorithms, curve-matched first", () => {
    const p384 = makeKey({ type: "ECDSA", curve: "P-384", bits: undefined })

    expect(algorithmsFor(p384, "sign")).toEqual(["ES384", "ES256", "ES512"])
  })

  it("offers only ES256K for a secp256k1 key", () => {
    const k1 = makeKey({ type: "ES256K", curve: "P-256K", bits: undefined })

    expect(algorithmsFor(k1, "sign")).toEqual(["ES256K"])
  })

  it("offers no encryption or wrapping at all -- the backend cannot do it", () => {
    const ec = makeKey({ type: "ECDSA", curve: "P-256", bits: undefined })

    expect(algorithmsFor(ec, "encrypt")).toEqual([])
    expect(algorithmsFor(ec, "wrap")).toEqual([])
  })
})

describe("algorithmsFor: symmetric", () => {
  it("matches the AES key-wrap algorithm to the key's size", () => {
    expect(
      algorithmsFor(makeKey({ type: "oct-HSM", bits: 192 }), "wrap")
    ).toEqual(["A192KW"])
    expect(
      algorithmsFor(makeKey({ type: "oct-HSM", bits: 256 }), "wrap")
    ).toEqual(["A256KW"])
  })

  it("offers CBC for encryption, plus GCM only at 256 bits", () => {
    expect(
      algorithmsFor(makeKey({ type: "oct-HSM", bits: 128 }), "encrypt")
    ).toEqual(["A128CBC"])
    expect(
      algorithmsFor(makeKey({ type: "oct-HSM", bits: 256 }), "encrypt")
    ).toEqual(["A256CBC", "AES256-GCM"])
  })

  it("offers no signing: every symmetric key is HSM-backed and the provider has no HMAC mechanism", () => {
    expect(
      algorithmsFor(makeKey({ type: "oct-HSM", bits: 256 }), "sign")
    ).toEqual([])
  })
})

describe("supportedOperations", () => {
  it("gives an RSA key the full set", () => {
    expect(supportedOperations(makeKey())).toEqual([
      "sign",
      "verify",
      "encrypt",
      "decrypt",
      "wrap",
      "unwrap",
    ])
  })

  it("limits an EC key to signing and verifying", () => {
    const ec = makeKey({ type: "ECDSA", curve: "P-256", bits: undefined })

    expect(supportedOperations(ec)).toEqual(["sign", "verify"])
  })

  it("limits a symmetric key to encryption and wrapping", () => {
    const oct = makeKey({ type: "oct-HSM", bits: 256 })

    expect(supportedOperations(oct)).toEqual([
      "encrypt",
      "decrypt",
      "wrap",
      "unwrap",
    ])
  })
})

describe("defaultAlgorithmFor", () => {
  it("picks the first offered algorithm", () => {
    expect(defaultAlgorithmFor(makeKey(), "sign")).toBe("RS256")
    expect(defaultAlgorithmFor(makeKey(), "encrypt")).toBe("RSA-OAEP-256")
  })

  it("returns an empty string when nothing is supported", () => {
    const ec = makeKey({ type: "ECDSA", curve: "P-256", bits: undefined })

    expect(defaultAlgorithmFor(ec, "wrap")).toBe("")
  })
})

describe("usesNonce", () => {
  it("is true for the AES modes that carry an IV or nonce", () => {
    expect(usesNonce("AES256-GCM")).toBe(true)
    expect(usesNonce("A128CBC")).toBe(true)
    expect(usesNonce("A256CBC")).toBe(true)
  })

  it("is false for the RSA modes and for key wrapping", () => {
    expect(usesNonce("RSA-OAEP-256")).toBe(false)
    expect(usesNonce("A256KW")).toBe(false)
  })
})
