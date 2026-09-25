import { beforeEach, describe, expect, it, vi } from "vitest"

vi.mock("@/api/client", () => ({
  request: vi.fn(),
}))

import { request } from "@/api/client"
import {
  backupKey,
  clearRotationPolicy,
  createKey,
  decryptData,
  deleteKey,
  encryptData,
  getKey,
  getKeyVersion,
  getRotationPolicy,
  importKey,
  listDeletedKeys,
  listKeys,
  listKeyVersions,
  purgeKey,
  restoreDeletedKey,
  restoreKey,
  rotateKey,
  setRotationPolicy,
  signData,
  unwrapKey,
  updateKey,
  verifySignature,
  wrapKey,
} from "@/api/keys"

const requestMock = vi.mocked(request)

const keyBody = {
  id: "k1",
  name: "signing-key",
  type: "RSA",
  user_id: "u1",
  revoked: false,
  created_at: "2026-01-01T00:00:00Z",
  tags: ["env=prod"],
  enabled: true,
  bits: 2048,
  n: "modulus",
  e: "AQAB",
}

beforeEach(() => {
  requestMock.mockReset()
})

describe("listKeys", () => {
  it("fetches the vault-scoped keys collection", async () => {
    requestMock.mockResolvedValueOnce({ keys: [] })

    await listKeys("payments")

    expect(requestMock).toHaveBeenCalledWith("/vaults/payments/keys")
  })

  it("appends only the filters that were supplied", async () => {
    requestMock.mockResolvedValueOnce({ keys: [] })

    await listKeys("payments", { type: "RSA", perPage: 200 })

    expect(requestMock).toHaveBeenCalledWith(
      "/vaults/payments/keys?type=RSA&per_page=200"
    )
  })

  it("maps response bodies onto camelCase Key objects", async () => {
    requestMock.mockResolvedValueOnce({ keys: [keyBody] })

    const keys = await listKeys("payments")

    expect(keys).toEqual([
      {
        id: "k1",
        name: "signing-key",
        type: "RSA",
        userId: "u1",
        revoked: false,
        createdAt: "2026-01-01T00:00:00Z",
        updatedAt: undefined,
        tags: ["env=prod"],
        enabled: true,
        expiresAt: undefined,
        notBefore: undefined,
        bits: 2048,
        curve: undefined,
        publicJwk: { n: "modulus", e: "AQAB" },
      },
    ])
  })

  it("normalises a null tags array to an empty array", async () => {
    requestMock.mockResolvedValueOnce({ keys: [{ ...keyBody, tags: null }] })

    const [key] = await listKeys("payments")

    expect(key.tags).toEqual([])
  })

  it("never carries private JWK material through, even if the server sends it", async () => {
    requestMock.mockResolvedValueOnce({
      keys: [{ ...keyBody, d: "PRIVATE", p: "PRIVATE", q: "PRIVATE" }],
    })

    const [key] = await listKeys("payments")

    expect(JSON.stringify(key)).not.toContain("PRIVATE")
    expect(Object.keys(key.publicJwk)).toEqual(["n", "e"])
  })
})

describe("getKey", () => {
  it("fetches one key by id", async () => {
    requestMock.mockResolvedValueOnce(keyBody)

    const key = await getKey("payments", "k1")

    expect(requestMock).toHaveBeenCalledWith("/vaults/payments/keys/k1")
    expect(key.name).toBe("signing-key")
  })
})

describe("createKey", () => {
  it("posts an RSA key with its bit size", async () => {
    requestMock.mockResolvedValueOnce(keyBody)

    await createKey("payments", {
      name: "signing-key",
      type: "RSA",
      bits: 3072,
    })

    expect(requestMock).toHaveBeenCalledWith("/vaults/payments/keys", {
      method: "POST",
      body: JSON.stringify({ name: "signing-key", type: "RSA", bits: 3072 }),
    })
  })

  it("posts an ECDSA key with its curve and no bit size", async () => {
    requestMock.mockResolvedValueOnce(keyBody)

    await createKey("payments", {
      name: "eck",
      type: "ECDSA",
      curve: "P-384",
      tags: ["a=b"],
    })

    expect(requestMock).toHaveBeenCalledWith("/vaults/payments/keys", {
      method: "POST",
      body: JSON.stringify({
        name: "eck",
        type: "ECDSA",
        curve: "P-384",
        tags: ["a=b"],
      }),
    })
  })
})

describe("importKey", () => {
  it("posts the JWK object verbatim", async () => {
    requestMock.mockResolvedValueOnce(keyBody)

    await importKey("payments", {
      name: "imported",
      jwk: { kty: "RSA", n: "x", e: "AQAB", d: "secret" },
    })

    expect(requestMock).toHaveBeenCalledWith("/vaults/payments/keys/import", {
      method: "POST",
      body: JSON.stringify({
        name: "imported",
        jwk: { kty: "RSA", n: "x", e: "AQAB", d: "secret" },
      }),
    })
  })
})

describe("updateKey", () => {
  it("sends only the explicitly-changed fields", async () => {
    requestMock.mockResolvedValueOnce(keyBody)

    await updateKey("payments", "k1", { enabled: false })

    expect(requestMock).toHaveBeenCalledWith("/vaults/payments/keys/k1", {
      method: "PUT",
      body: JSON.stringify({ enabled: false }),
    })
  })
})

describe("deleteKey", () => {
  it("soft-deletes and maps the recovery receipt", async () => {
    requestMock.mockResolvedValueOnce({
      id: "k1",
      name: "signing-key",
      deleted_at: "2026-02-01T00:00:00Z",
      scheduled_purge_at: "2026-03-01T00:00:00Z",
      recovery_id: "/deleted/keys/k1/restore",
    })

    const receipt = await deleteKey("payments", "k1")

    expect(requestMock).toHaveBeenCalledWith("/vaults/payments/keys/k1", {
      method: "DELETE",
    })
    expect(receipt).toEqual({
      id: "k1",
      name: "signing-key",
      deletedAt: "2026-02-01T00:00:00Z",
      scheduledPurgeAt: "2026-03-01T00:00:00Z",
      recoveryId: "/deleted/keys/k1/restore",
    })
  })
})

describe("rotateKey", () => {
  it("posts to the rotate sub-route", async () => {
    requestMock.mockResolvedValueOnce(keyBody)

    await rotateKey("payments", "k1")

    expect(requestMock).toHaveBeenCalledWith(
      "/vaults/payments/keys/k1/rotate",
      {
        method: "POST",
      }
    )
  })
})

describe("key versions", () => {
  it("lists versions", async () => {
    requestMock.mockResolvedValueOnce({
      versions: [
        { key_id: "k1", version: 1, created_at: "2026-01-01T00:00:00Z" },
      ],
    })

    const versions = await listKeyVersions("payments", "k1")

    expect(requestMock).toHaveBeenCalledWith(
      "/vaults/payments/keys/k1/versions"
    )
    expect(versions).toEqual([
      { keyId: "k1", version: 1, createdAt: "2026-01-01T00:00:00Z" },
    ])
  })

  it("gets one version and allow-lists its JWK components", async () => {
    requestMock.mockResolvedValueOnce({
      key_id: "k1",
      version: 2,
      created_at: "2026-01-02T00:00:00Z",
      x: "xcoord",
      y: "ycoord",
      d: "PRIVATE",
    })

    const version = await getKeyVersion("payments", "k1", 2)

    expect(requestMock).toHaveBeenCalledWith(
      "/vaults/payments/keys/k1/versions/2"
    )
    expect(version).toEqual({
      keyId: "k1",
      version: 2,
      createdAt: "2026-01-02T00:00:00Z",
      publicJwk: { x: "xcoord", y: "ycoord" },
    })
  })
})

describe("crypto operations", () => {
  it("wraps a key", async () => {
    requestMock.mockResolvedValueOnce({
      wrapped_key: "d3JhcHBlZA==",
      algorithm: "RSA-OAEP-256",
      version: 1,
    })

    const result = await wrapKey("payments", "k1", {
      plaintextKey: "cGxhaW4=",
      algorithm: "RSA-OAEP-256",
    })

    expect(requestMock).toHaveBeenCalledWith("/vaults/payments/keys/k1/wrap", {
      method: "POST",
      body: JSON.stringify({
        plaintext_key: "cGxhaW4=",
        algorithm: "RSA-OAEP-256",
      }),
    })
    expect(result).toEqual({
      wrappedKey: "d3JhcHBlZA==",
      algorithm: "RSA-OAEP-256",
      version: 1,
    })
  })

  it("unwraps a key at a pinned version", async () => {
    requestMock.mockResolvedValueOnce({
      plaintext_key: "cGxhaW4=",
      algorithm: "A256KW",
      version: 3,
    })

    const result = await unwrapKey("payments", "k1", {
      wrappedKey: "d3JhcHBlZA==",
      algorithm: "A256KW",
      version: 3,
    })

    expect(requestMock).toHaveBeenCalledWith(
      "/vaults/payments/keys/k1/unwrap",
      {
        method: "POST",
        body: JSON.stringify({
          wrapped_key: "d3JhcHBlZA==",
          algorithm: "A256KW",
          version: 3,
        }),
      }
    )
    expect(result.plaintextKey).toBe("cGxhaW4=")
  })

  it("signs data", async () => {
    requestMock.mockResolvedValueOnce({
      key_id: "k1",
      algorithm: "RS256",
      value: "c2ln",
      version: 1,
    })

    const result = await signData("payments", "k1", {
      value: "ZGF0YQ==",
      algorithm: "RS256",
    })

    expect(requestMock).toHaveBeenCalledWith("/vaults/payments/keys/k1/sign", {
      method: "POST",
      body: JSON.stringify({ value: "ZGF0YQ==", algorithm: "RS256" }),
    })
    expect(result).toEqual({
      keyId: "k1",
      algorithm: "RS256",
      value: "c2ln",
      version: 1,
    })
  })

  it("verifies a signature", async () => {
    requestMock.mockResolvedValueOnce({
      key_id: "k1",
      algorithm: "RS256",
      valid: true,
      version: 1,
    })

    const result = await verifySignature("payments", "k1", {
      value: "ZGF0YQ==",
      signature: "c2ln",
      algorithm: "RS256",
    })

    expect(requestMock).toHaveBeenCalledWith(
      "/vaults/payments/keys/k1/verify",
      {
        method: "POST",
        body: JSON.stringify({
          value: "ZGF0YQ==",
          signature: "c2ln",
          algorithm: "RS256",
        }),
      }
    )
    expect(result.valid).toBe(true)
  })

  it("encrypts and surfaces the AEAD nonce when the server returns one", async () => {
    requestMock.mockResolvedValueOnce({
      key_id: "k1",
      algorithm: "AES256-GCM",
      value: "Y2lwaGVy",
      nonce: "bm9uY2U=",
      version: 1,
    })

    const result = await encryptData("payments", "k1", {
      value: "ZGF0YQ==",
      algorithm: "AES256-GCM",
    })

    expect(requestMock).toHaveBeenCalledWith(
      "/vaults/payments/keys/k1/encrypt",
      {
        method: "POST",
        body: JSON.stringify({ value: "ZGF0YQ==", algorithm: "AES256-GCM" }),
      }
    )
    expect(result.nonce).toBe("bm9uY2U=")
  })

  it("decrypts, sending the nonce back only when one was supplied", async () => {
    requestMock.mockResolvedValueOnce({
      key_id: "k1",
      algorithm: "RSA-OAEP-256",
      value: "ZGF0YQ==",
      version: 1,
    })

    await decryptData("payments", "k1", {
      value: "Y2lwaGVy",
      algorithm: "RSA-OAEP-256",
    })

    expect(requestMock).toHaveBeenCalledWith(
      "/vaults/payments/keys/k1/decrypt",
      {
        method: "POST",
        body: JSON.stringify({ value: "Y2lwaGVy", algorithm: "RSA-OAEP-256" }),
      }
    )
  })
})

describe("rotation policy", () => {
  it("gets the policy", async () => {
    requestMock.mockResolvedValueOnce({
      id: "p1",
      key_id: "k1",
      user_id: "u1",
      vault_id: "v1",
      rotate_after_days: 90,
      notify_before_expiry_days: 30,
      expiry_days: 365,
      enabled: true,
      next_rotation_at: "2026-04-01T00:00:00Z",
      created_at: "2026-01-01T00:00:00Z",
      updated_at: "2026-01-01T00:00:00Z",
    })

    const policy = await getRotationPolicy("payments", "k1")

    expect(requestMock).toHaveBeenCalledWith(
      "/vaults/payments/keys/k1/rotationpolicy"
    )
    expect(policy).toEqual({
      id: "p1",
      keyId: "k1",
      userId: "u1",
      vaultId: "v1",
      rotateAfterDays: 90,
      notifyBeforeExpiryDays: 30,
      expiryDays: 365,
      enabled: true,
      lastRotatedAt: undefined,
      nextRotationAt: "2026-04-01T00:00:00Z",
      createdAt: "2026-01-01T00:00:00Z",
      updatedAt: "2026-01-01T00:00:00Z",
    })
  })

  it("puts all four policy fields, since the backend struct has no optional members", async () => {
    requestMock.mockResolvedValueOnce({
      id: "p1",
      key_id: "k1",
      user_id: "u1",
      vault_id: "v1",
      rotate_after_days: 30,
      notify_before_expiry_days: 7,
      expiry_days: 180,
      enabled: true,
      next_rotation_at: "2026-04-01T00:00:00Z",
      created_at: "2026-01-01T00:00:00Z",
      updated_at: "2026-01-01T00:00:00Z",
    })

    await setRotationPolicy("payments", "k1", {
      rotateAfterDays: 30,
      notifyBeforeExpiryDays: 7,
      expiryDays: 180,
      enabled: true,
    })

    expect(requestMock).toHaveBeenCalledWith(
      "/vaults/payments/keys/k1/rotationpolicy",
      {
        method: "PUT",
        body: JSON.stringify({
          rotate_after_days: 30,
          notify_before_expiry_days: 7,
          expiry_days: 180,
          enabled: true,
        }),
      }
    )
  })

  it("clears the policy", async () => {
    requestMock.mockResolvedValueOnce({ status: "OK" })

    await clearRotationPolicy("payments", "k1")

    expect(requestMock).toHaveBeenCalledWith(
      "/vaults/payments/keys/k1/rotationpolicy",
      { method: "DELETE" }
    )
  })
})

describe("backup and restore", () => {
  it("unwraps the blob envelope on backup", async () => {
    requestMock.mockResolvedValueOnce({ blob: "YmxvYg==" })

    const blob = await backupKey("payments", "k1")

    expect(requestMock).toHaveBeenCalledWith(
      "/vaults/payments/keys/k1/backup",
      {
        method: "POST",
      }
    )
    expect(blob).toBe("YmxvYg==")
  })

  it("posts the blob back on restore", async () => {
    requestMock.mockResolvedValueOnce({ status: "OK" })

    await restoreKey("payments", "YmxvYg==")

    expect(requestMock).toHaveBeenCalledWith("/vaults/payments/keys/restore", {
      method: "POST",
      body: JSON.stringify({ blob: "YmxvYg==" }),
    })
  })
})

describe("deleted keys", () => {
  it("lists soft-deleted keys in the vault", async () => {
    requestMock.mockResolvedValueOnce({
      deleted_keys: [
        {
          id: "k1",
          name: "signing-key",
          type: "RSA",
          deleted_at: "2026-02-01T00:00:00Z",
          purge_protection: true,
        },
      ],
      total: 1,
    })

    const keys = await listDeletedKeys("payments")

    expect(requestMock).toHaveBeenCalledWith("/vaults/payments/deleted/keys")
    expect(keys).toEqual([
      {
        id: "k1",
        name: "signing-key",
        type: "RSA",
        deletedAt: "2026-02-01T00:00:00Z",
        purgeProtection: true,
      },
    ])
  })

  it("restores a deleted key", async () => {
    requestMock.mockResolvedValueOnce({ id: "k1", message: "Key recovered" })

    await restoreDeletedKey("payments", "k1")

    expect(requestMock).toHaveBeenCalledWith(
      "/vaults/payments/deleted/keys/k1/restore",
      { method: "POST" }
    )
  })

  it("purges a deleted key", async () => {
    requestMock.mockResolvedValueOnce({ status: "OK" })

    await purgeKey("payments", "k1")

    expect(requestMock).toHaveBeenCalledWith(
      "/vaults/payments/deleted/keys/k1/purge",
      { method: "DELETE" }
    )
  })
})
