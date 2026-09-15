import { beforeEach, describe, expect, it, vi } from "vitest"

vi.mock("@/api/client", () => ({
  request: vi.fn(),
}))

import { request } from "@/api/client"
import {
  backupCertificate,
  createCertificate,
  deleteCertificate,
  deleteCertificatePolicy,
  getCertificate,
  getCertificatePolicy,
  listCertificates,
  listDeletedCertificates,
  purgeCertificate,
  recoverCertificate,
  restoreCertificate,
  updateCertificate,
  upsertCertificatePolicy,
} from "@/api/certificates"
import { ApiError } from "@/api/types"

const requestMock = vi.mocked(request)

const CERT_ID = "11111111-1111-1111-1111-111111111111"

const certBody = {
  id: CERT_ID,
  name: "api.example.com",
  user_id: "u1",
  created_at: "2026-01-01T00:00:00Z",
  tags: ["env=prod"],
  auto_renew: true,
  renewal_days: 30,
  expires_at: "2027-01-01T00:00:00Z",
  enabled: true,
  not_before: "2026-01-02T00:00:00Z",
}

function bodyOf(call: [string, RequestInit?]): Record<string, unknown> {
  const init = call[1]
  return JSON.parse(String(init?.body)) as Record<string, unknown>
}

beforeEach(() => {
  requestMock.mockReset()
})

describe("listCertificates", () => {
  it("fetches the vault-scoped certificates collection", async () => {
    requestMock.mockResolvedValueOnce({ certificates: [] })

    await listCertificates("payments")

    expect(requestMock).toHaveBeenCalledWith("/vaults/payments/certificates")
  })

  it("maps response bodies onto camelCase Certificate objects", async () => {
    requestMock.mockResolvedValueOnce({ certificates: [certBody] })

    const certificates = await listCertificates("payments")

    expect(certificates).toEqual([
      {
        id: CERT_ID,
        name: "api.example.com",
        userId: "u1",
        createdAt: "2026-01-01T00:00:00Z",
        tags: ["env=prod"],
        autoRenew: true,
        renewalDays: 30,
        expiresAt: "2027-01-01T00:00:00Z",
        enabled: true,
        notBefore: "2026-01-02T00:00:00Z",
      },
    ])
  })

  it("normalises a null tags array to an empty array", async () => {
    requestMock.mockResolvedValueOnce({
      certificates: [{ ...certBody, tags: null }],
    })

    const [certificate] = await listCertificates("payments")

    expect(certificate.tags).toEqual([])
  })

  it("never carries PEM or private material through, even if the server sends it", async () => {
    requestMock.mockResolvedValueOnce({
      certificates: [
        {
          ...certBody,
          certificate: "-----BEGIN CERTIFICATE-----LEAK",
          private_key: "-----BEGIN PRIVATE KEY-----LEAK",
        },
      ],
    })

    const [certificate] = await listCertificates("payments")

    expect(JSON.stringify(certificate)).not.toContain("LEAK")
    expect(Object.keys(certificate)).not.toContain("certificate")
    expect(Object.keys(certificate)).not.toContain("privateKey")
  })

  it("percent-encodes a vault name with a slash in it", async () => {
    requestMock.mockResolvedValueOnce({ certificates: [] })

    await listCertificates("team/payments")

    expect(requestMock).toHaveBeenCalledWith(
      "/vaults/team%2Fpayments/certificates"
    )
  })
})

describe("getCertificate", () => {
  it("fetches one certificate by id", async () => {
    requestMock.mockResolvedValueOnce(certBody)

    const certificate = await getCertificate("payments", CERT_ID)

    expect(requestMock).toHaveBeenCalledWith(
      `/vaults/payments/certificates/${CERT_ID}`
    )
    expect(certificate.name).toBe("api.example.com")
  })
})

describe("createCertificate", () => {
  it("posts the required issuance fields", async () => {
    requestMock.mockResolvedValueOnce(certBody)

    await createCertificate("payments", {
      name: "api.example.com",
      keyId: "key-1",
      validityDays: 365,
    })

    const [path, init] = requestMock.mock.calls[0] as [string, RequestInit]
    expect(path).toBe("/vaults/payments/certificates")
    expect(init.method).toBe("POST")
    expect(JSON.parse(String(init.body))).toEqual({
      name: "api.example.com",
      key_id: "key-1",
      validity_days: 365,
    })
  })

  it("omits ca_cert_id entirely when no CA was chosen", async () => {
    requestMock.mockResolvedValueOnce(certBody)

    await createCertificate("payments", {
      name: "api.example.com",
      keyId: "key-1",
      validityDays: 365,
      isCa: false,
    })

    const body = bodyOf(requestMock.mock.calls[0] as [string, RequestInit])
    expect(body).not.toHaveProperty("ca_cert_id")
    expect(body.is_ca).toBe(false)
  })

  it("sends ca_cert_id when a signing CA was chosen", async () => {
    requestMock.mockResolvedValueOnce(certBody)

    await createCertificate("payments", {
      name: "api.example.com",
      keyId: "key-1",
      validityDays: 365,
      caCertId: "ca-1",
    })

    expect(
      bodyOf(requestMock.mock.calls[0] as [string, RequestInit]).ca_cert_id
    ).toBe("ca-1")
  })

  it("never sends ca_key_id -- the backend field is unused", async () => {
    requestMock.mockResolvedValueOnce(certBody)

    await createCertificate("payments", {
      name: "api.example.com",
      keyId: "key-1",
      validityDays: 365,
      caCertId: "ca-1",
    })

    expect(
      String((requestMock.mock.calls[0][1] as RequestInit).body)
    ).not.toContain("ca_key_id")
  })
})

describe("updateCertificate", () => {
  it("sends only the fields the caller explicitly changed", async () => {
    requestMock.mockResolvedValueOnce(certBody)

    await updateCertificate("payments", CERT_ID, { enabled: false })

    const [path, init] = requestMock.mock.calls[0] as [string, RequestInit]
    expect(path).toBe(`/vaults/payments/certificates/${CERT_ID}`)
    expect(init.method).toBe("PUT")

    const body = JSON.parse(String(init.body)) as Record<string, unknown>
    expect(body).toEqual({ enabled: false })
    // An untouched field must be ABSENT, not null: the backend rejects a body
    // whose every field is unset with a 400, and a null would also clobber a
    // stored value the operator never touched.
    expect(body).not.toHaveProperty("name")
    expect(body).not.toHaveProperty("auto_renew")
    expect(body).not.toHaveProperty("renewal_days")
  })

  it("can send a false boolean without it being treated as absent", async () => {
    requestMock.mockResolvedValueOnce(certBody)

    await updateCertificate("payments", CERT_ID, {
      autoRenew: false,
      purgeProtection: false,
    })

    expect(bodyOf(requestMock.mock.calls[0] as [string, RequestInit])).toEqual({
      auto_renew: false,
      purge_protection: false,
    })
  })

  it("has no way to send key_id or ca_cert_id -- both are fixed at issuance", async () => {
    requestMock.mockResolvedValueOnce(certBody)

    await updateCertificate("payments", CERT_ID, {
      name: "renamed",
      tags: ["a"],
      autoRenew: true,
      renewalDays: 14,
      enabled: true,
      notBefore: "2026-02-01T00:00:00Z",
      purgeProtection: true,
    })

    const body = bodyOf(requestMock.mock.calls[0] as [string, RequestInit])
    expect(body).not.toHaveProperty("key_id")
    expect(body).not.toHaveProperty("ca_cert_id")
    expect(body).toEqual({
      name: "renamed",
      tags: ["a"],
      auto_renew: true,
      renewal_days: 14,
      enabled: true,
      not_before: "2026-02-01T00:00:00Z",
      purge_protection: true,
    })
  })
})

describe("deleteCertificate", () => {
  it("soft-deletes by id", async () => {
    requestMock.mockResolvedValueOnce({ status: "OK" })

    await deleteCertificate("payments", CERT_ID)

    expect(requestMock).toHaveBeenCalledWith(
      `/vaults/payments/certificates/${CERT_ID}`,
      { method: "DELETE" }
    )
  })
})

const policyBody = {
  id: "p1",
  certificate_id: CERT_ID,
  user_id: "u1",
  validity_months: 12,
  key_type: "RSA",
  key_size: 2048,
  curve: "",
  subject: "CN=api.example.com",
  sans: "api.example.com,www.example.com",
  auto_renew: true,
  days_before_expiry: 30,
  issuer_name: "RocketVault CA",
  created_at: "2026-01-01T00:00:00Z",
  updated_at: "2026-01-02T00:00:00Z",
}

describe("getCertificatePolicy", () => {
  it("maps the policy onto camelCase", async () => {
    requestMock.mockResolvedValueOnce(policyBody)

    const policy = await getCertificatePolicy("payments", CERT_ID)

    expect(requestMock).toHaveBeenCalledWith(
      `/vaults/payments/certificates/${CERT_ID}/policy`
    )
    expect(policy).toEqual({
      id: "p1",
      certificateId: CERT_ID,
      userId: "u1",
      validityMonths: 12,
      keyType: "RSA",
      keySize: 2048,
      curve: "",
      subject: "CN=api.example.com",
      sans: "api.example.com,www.example.com",
      autoRenew: true,
      daysBeforeExpiry: 30,
      issuerName: "RocketVault CA",
      createdAt: "2026-01-01T00:00:00Z",
      updatedAt: "2026-01-02T00:00:00Z",
    })
  })

  it("maps a 404 to null so 'no policy yet' is an empty state, not an error", async () => {
    requestMock.mockRejectedValueOnce(
      new ApiError({ status_code: 404, message: "Unable to find the policy" })
    )

    await expect(getCertificatePolicy("payments", CERT_ID)).resolves.toBeNull()
  })

  it("still throws on any other failure", async () => {
    requestMock.mockRejectedValueOnce(
      new ApiError({ status_code: 403, message: "Insufficient permissions" })
    )

    await expect(getCertificatePolicy("payments", CERT_ID)).rejects.toThrow(
      /insufficient permissions/i
    )
  })
})

describe("upsertCertificatePolicy", () => {
  it("PUTs the full policy -- the backend struct has no pointers", async () => {
    requestMock.mockResolvedValueOnce(policyBody)

    await upsertCertificatePolicy("payments", CERT_ID, {
      validityMonths: 12,
      keyType: "RSA",
      keySize: 2048,
      subject: "CN=api.example.com",
      sans: "api.example.com",
      autoRenew: true,
      daysBeforeExpiry: 30,
      issuerName: "RocketVault CA",
    })

    const [path, init] = requestMock.mock.calls[0] as [string, RequestInit]
    expect(path).toBe(`/vaults/payments/certificates/${CERT_ID}/policy`)
    expect(init.method).toBe("PUT")
    expect(JSON.parse(String(init.body))).toEqual({
      validity_months: 12,
      key_type: "RSA",
      key_size: 2048,
      subject: "CN=api.example.com",
      sans: "api.example.com",
      auto_renew: true,
      days_before_expiry: 30,
      issuer_name: "RocketVault CA",
    })
  })
})

describe("deleteCertificatePolicy", () => {
  it("clears the policy", async () => {
    requestMock.mockResolvedValueOnce({ status: "OK" })

    await deleteCertificatePolicy("payments", CERT_ID)

    expect(requestMock).toHaveBeenCalledWith(
      `/vaults/payments/certificates/${CERT_ID}/policy`,
      { method: "DELETE" }
    )
  })
})

describe("backupCertificate", () => {
  it("returns the opaque blob -- there is no PEM anywhere in this API", async () => {
    requestMock.mockResolvedValueOnce({ blob: "BLOB" })

    await expect(backupCertificate("payments", CERT_ID)).resolves.toBe("BLOB")
    expect(requestMock).toHaveBeenCalledWith(
      `/vaults/payments/certificates/${CERT_ID}/backup`,
      { method: "POST" }
    )
  })
})

describe("restoreCertificate", () => {
  it("posts the blob to the collection-level restore route", async () => {
    requestMock.mockResolvedValueOnce({ status: "OK" })

    await restoreCertificate("payments", "BLOB")

    const [path, init] = requestMock.mock.calls[0] as [string, RequestInit]
    expect(path).toBe("/vaults/payments/certificates/restore")
    expect(init.method).toBe("POST")
    expect(JSON.parse(String(init.body))).toEqual({ blob: "BLOB" })
  })
})

describe("listDeletedCertificates", () => {
  it("maps the four fields the deleted row carries -- and only those", async () => {
    requestMock.mockResolvedValueOnce({
      deleted_certificates: [
        {
          id: CERT_ID,
          name: "api.example.com",
          deleted_at: "2026-03-01T00:00:00Z",
          purge_protection: true,
        },
      ],
      total: 1,
    })

    const deleted = await listDeletedCertificates("payments")

    expect(requestMock).toHaveBeenCalledWith(
      "/vaults/payments/deleted/certificates"
    )
    expect(deleted).toEqual([
      {
        id: CERT_ID,
        name: "api.example.com",
        deletedAt: "2026-03-01T00:00:00Z",
        purgeProtection: true,
      },
    ])
  })

  it("tolerates a null deleted_at", async () => {
    requestMock.mockResolvedValueOnce({
      deleted_certificates: [
        {
          id: CERT_ID,
          name: "api.example.com",
          deleted_at: null,
          purge_protection: false,
        },
      ],
      total: 1,
    })

    const [deleted] = await listDeletedCertificates("payments")

    expect(deleted.deletedAt).toBeUndefined()
  })
})

describe("recoverCertificate", () => {
  it("returns the server's own recovery message", async () => {
    requestMock.mockResolvedValueOnce({
      id: CERT_ID,
      message: "Certificate recovered successfully",
    })

    const result = await recoverCertificate("payments", CERT_ID)

    expect(requestMock).toHaveBeenCalledWith(
      `/vaults/payments/deleted/certificates/${CERT_ID}/restore`,
      { method: "POST" }
    )
    expect(result).toEqual({
      id: CERT_ID,
      message: "Certificate recovered successfully",
    })
  })
})

describe("purgeCertificate", () => {
  it("permanently purges by id", async () => {
    requestMock.mockResolvedValueOnce({ status: "OK" })

    await purgeCertificate("payments", CERT_ID)

    expect(requestMock).toHaveBeenCalledWith(
      `/vaults/payments/deleted/certificates/${CERT_ID}/purge`,
      { method: "DELETE" }
    )
  })
})

describe("the module's surface", () => {
  it("exposes no renewCertificate -- no HTTP renew route exists", async () => {
    const module = await import("@/api/certificates")

    expect(module).not.toHaveProperty("renewCertificate")
  })
})
