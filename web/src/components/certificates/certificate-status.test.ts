import { describe, expect, it } from "vitest"

import type { Certificate } from "@/api/certificates"
import {
  certificateStatusOf,
  summarizeCertificates,
} from "@/components/certificates/certificate-status"

const NOW = new Date("2026-06-01T00:00:00Z")

function days(count: number): string {
  return new Date(NOW.getTime() + count * 24 * 60 * 60 * 1000).toISOString()
}

function makeCertificate(overrides: Partial<Certificate> = {}): Certificate {
  return {
    id: "c1",
    name: "api.example.com",
    userId: "u1",
    createdAt: "2026-01-01T00:00:00Z",
    tags: [],
    autoRenew: false,
    renewalDays: 30,
    expiresAt: days(200),
    enabled: true,
    ...overrides,
  }
}

describe("certificateStatusOf", () => {
  it("reports a healthy certificate as valid", () => {
    expect(certificateStatusOf(makeCertificate(), NOW)).toEqual({
      tone: "on",
      label: "Valid",
    })
  })

  it("reports a disabled certificate as disabled, whatever its expiry", () => {
    expect(
      certificateStatusOf(makeCertificate({ enabled: false }), NOW)
    ).toEqual({ tone: "off", label: "Disabled" })
  })

  it("reports an already-past expiry as expired", () => {
    expect(
      certificateStatusOf(makeCertificate({ expiresAt: days(-1) }), NOW)
    ).toEqual({ tone: "danger", label: "Expired" })
  })

  it("warns inside the certificate's OWN renewal_days window", () => {
    const status = certificateStatusOf(
      makeCertificate({ expiresAt: days(12), renewalDays: 30 }),
      NOW
    )

    expect(status.tone).toBe("warning")
    expect(status.label).toBe("Expires in 12 days")
  })

  it("does not warn outside that window -- the window is per-certificate", () => {
    // 12 days out is inside a 30-day window but comfortably outside a 7-day
    // one, so the same expiry must read differently for the two certificates.
    expect(
      certificateStatusOf(
        makeCertificate({ expiresAt: days(12), renewalDays: 7 }),
        NOW
      ).tone
    ).toBe("on")
  })

  it("falls back to a 30-day window when renewal_days is unset", () => {
    expect(
      certificateStatusOf(
        makeCertificate({ expiresAt: days(10), renewalDays: 0 }),
        NOW
      ).tone
    ).toBe("warning")
  })

  it("says 'tomorrow' rather than 'in 0 days' for a same-day expiry", () => {
    expect(
      certificateStatusOf(makeCertificate({ expiresAt: days(0.5) }), NOW).label
    ).toBe("Expires in 1 day")
  })

  it("treats a certificate with no expiry as valid rather than expired", () => {
    expect(
      certificateStatusOf(makeCertificate({ expiresAt: undefined }), NOW)
    ).toEqual({ tone: "on", label: "Valid" })
  })

  it("warns about a certificate that is not valid yet", () => {
    expect(
      certificateStatusOf(makeCertificate({ notBefore: days(5) }), NOW)
    ).toEqual({ tone: "warning", label: "Not yet valid" })
  })

  it("ignores an unparseable timestamp rather than inventing a state", () => {
    expect(
      certificateStatusOf(makeCertificate({ expiresAt: "not-a-date" }), NOW)
        .tone
    ).toBe("on")
  })
})

describe("summarizeCertificates", () => {
  it("counts total, expiring-soon and expired", () => {
    const summary = summarizeCertificates(
      [
        makeCertificate({ id: "a" }),
        makeCertificate({ id: "b", expiresAt: days(5) }),
        makeCertificate({ id: "c", expiresAt: days(-5) }),
        makeCertificate({ id: "d", enabled: false }),
      ],
      NOW
    )

    expect(summary).toEqual({ total: 4, expiringSoon: 1, expired: 1 })
  })
})
