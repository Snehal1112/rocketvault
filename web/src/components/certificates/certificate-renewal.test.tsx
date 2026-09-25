import { QueryClient, QueryClientProvider } from "@tanstack/react-query"
import { render, screen } from "@testing-library/react"
import userEvent from "@testing-library/user-event"
import type { ReactNode } from "react"
import { beforeEach, describe, expect, it, vi } from "vitest"

vi.mock("@/api/certificates", () => ({
  updateCertificate: vi.fn(),
  getCertificatePolicy: vi.fn(),
  upsertCertificatePolicy: vi.fn(),
  deleteCertificatePolicy: vi.fn(),
}))

import type { Certificate, CertificatePolicy } from "@/api/certificates"
import {
  deleteCertificatePolicy,
  getCertificatePolicy,
  updateCertificate,
  upsertCertificatePolicy,
} from "@/api/certificates"
import { CertificatePolicyForm } from "@/components/certificates/certificate-policy-form"
import { CertificateRenewalCard } from "@/components/certificates/certificate-renewal-card"

const updateCertificateMock = vi.mocked(updateCertificate)
const getCertificatePolicyMock = vi.mocked(getCertificatePolicy)
const upsertCertificatePolicyMock = vi.mocked(upsertCertificatePolicy)
const deleteCertificatePolicyMock = vi.mocked(deleteCertificatePolicy)

const CERT_ID = "11111111-1111-1111-1111-111111111111"

function makeCertificate(overrides: Partial<Certificate> = {}): Certificate {
  return {
    id: CERT_ID,
    name: "api.example.com",
    userId: "u1",
    createdAt: "2026-01-01T00:00:00Z",
    tags: [],
    autoRenew: false,
    renewalDays: 30,
    expiresAt: "2027-01-01T00:00:00Z",
    enabled: true,
    ...overrides,
  }
}

function makePolicy(overrides: Partial<CertificatePolicy> = {}) {
  return {
    id: "p1",
    certificateId: CERT_ID,
    userId: "u1",
    validityMonths: 12,
    keyType: "RSA",
    keySize: 2048,
    subject: "CN=api.example.com",
    sans: "DNS:api.example.com",
    autoRenew: false,
    daysBeforeExpiry: 30,
    issuerName: "RocketVault CA",
    createdAt: "2026-01-01T00:00:00Z",
    updatedAt: "2026-01-01T00:00:00Z",
    ...overrides,
  } satisfies CertificatePolicy
}

function renderWithQuery(ui: ReactNode) {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  })
  return render(
    <QueryClientProvider client={queryClient}>{ui}</QueryClientProvider>
  )
}

beforeEach(() => {
  updateCertificateMock.mockReset()
  getCertificatePolicyMock.mockReset().mockResolvedValue(null)
  upsertCertificatePolicyMock.mockReset()
  deleteCertificatePolicyMock.mockReset()
})

describe("CertificateRenewalCard", () => {
  it("turns the certificate's own auto-renewal on through updateCertificate", async () => {
    const certificate = makeCertificate()
    updateCertificateMock.mockResolvedValue(
      makeCertificate({ autoRenew: true })
    )

    renderWithQuery(
      <CertificateRenewalCard vaultName="payments" certificate={certificate} />
    )

    await userEvent.click(
      screen.getByRole("switch", { name: /renew automatically/i })
    )

    expect(updateCertificateMock).toHaveBeenCalledWith("payments", CERT_ID, {
      autoRenew: true,
    })
  })

  it("saves the renewal window as the certificate's own renewal_days", async () => {
    updateCertificateMock.mockResolvedValue(
      makeCertificate({ autoRenew: true, renewalDays: 14 })
    )

    renderWithQuery(
      <CertificateRenewalCard
        vaultName="payments"
        certificate={makeCertificate({ autoRenew: true })}
      />
    )

    const days = screen.getByRole("spinbutton", { name: /days before expiry/i })
    await userEvent.clear(days)
    await userEvent.type(days, "14")
    await userEvent.click(screen.getByRole("button", { name: /save/i }))

    expect(updateCertificateMock).toHaveBeenCalledWith("payments", CERT_ID, {
      renewalDays: 14,
    })
  })

  it("says plainly that this is the setting the renewal scheduler reads", async () => {
    renderWithQuery(
      <CertificateRenewalCard
        vaultName="payments"
        certificate={makeCertificate()}
      />
    )

    expect(screen.getByText(/renewal scheduler/i)).toBeInTheDocument()
  })

  it("offers no manual renew action — the HTTP route does not exist", async () => {
    renderWithQuery(
      <CertificateRenewalCard
        vaultName="payments"
        certificate={makeCertificate()}
      />
    )

    // Deliberately negative. There is no POST /certificates/{id}/renew route:
    // the CLI calls CertificateService.RenewCertificate directly. A future
    // contributor adding a "Renew now" button has to consciously delete this
    // test, and read why it was here.
    expect(
      screen.queryByRole("button", { name: /renew now/i })
    ).not.toBeInTheDocument()
    expect(
      screen.getByText(/rocketvault certificates renew/i)
    ).toBeInTheDocument()
  })
})

describe("CertificatePolicyForm", () => {
  it("shows an empty state, not an error, when no policy is set", async () => {
    getCertificatePolicyMock.mockResolvedValue(null)

    renderWithQuery(
      <CertificatePolicyForm
        vaultName="payments"
        certificate={makeCertificate()}
      />
    )

    expect(await screen.findByText(/no policy set/i)).toBeInTheDocument()
  })

  it("requires subject and validity months client-side, mirroring the CLI", async () => {
    getCertificatePolicyMock.mockResolvedValue(null)

    renderWithQuery(
      <CertificatePolicyForm
        vaultName="payments"
        certificate={makeCertificate()}
      />
    )

    await userEvent.click(
      await screen.findByRole("button", { name: /^set a policy$/i })
    )
    await userEvent.click(screen.getByRole("button", { name: /save policy/i }))

    expect(upsertCertificatePolicyMock).not.toHaveBeenCalled()
    expect(await screen.findByText(/subject is required/i)).toBeInTheDocument()
  })

  it("upserts the whole policy — the backend replaces it wholesale", async () => {
    getCertificatePolicyMock.mockResolvedValue(makePolicy())
    upsertCertificatePolicyMock.mockResolvedValue(makePolicy())

    renderWithQuery(
      <CertificatePolicyForm
        vaultName="payments"
        certificate={makeCertificate()}
      />
    )

    await userEvent.click(
      await screen.findByRole("button", { name: /save policy/i })
    )

    expect(upsertCertificatePolicyMock).toHaveBeenCalledWith(
      "payments",
      CERT_ID,
      expect.objectContaining({
        validityMonths: 12,
        subject: "CN=api.example.com",
        keyType: "RSA",
        daysBeforeExpiry: 30,
        autoRenew: false,
      })
    )
  })

  it("warns when the policy's auto-renew is on but the certificate's is off", async () => {
    getCertificatePolicyMock.mockResolvedValue(makePolicy({ autoRenew: true }))

    renderWithQuery(
      <CertificatePolicyForm
        vaultName="payments"
        certificate={makeCertificate({ autoRenew: false })}
      />
    )

    // This combination looks like working auto-renewal and is not: the
    // scheduler reads the certificate's own auto_renew, never the policy's.
    expect(
      await screen.findByText(/not read by the renewal scheduler/i)
    ).toBeInTheDocument()
  })

  it("does not nag when the certificate's own auto-renew is already on", async () => {
    getCertificatePolicyMock.mockResolvedValue(makePolicy({ autoRenew: true }))

    renderWithQuery(
      <CertificatePolicyForm
        vaultName="payments"
        certificate={makeCertificate({ autoRenew: true })}
      />
    )

    await screen.findByRole("button", { name: /save policy/i })
    expect(
      screen.queryByText(/not read by the renewal scheduler/i)
    ).not.toBeInTheDocument()
  })

  it("clears the policy behind a confirmation", async () => {
    getCertificatePolicyMock.mockResolvedValue(makePolicy())
    deleteCertificatePolicyMock.mockResolvedValue(undefined)

    renderWithQuery(
      <CertificatePolicyForm
        vaultName="payments"
        certificate={makeCertificate()}
      />
    )

    await userEvent.click(
      await screen.findByRole("button", { name: /delete policy/i })
    )
    await userEvent.click(
      await screen.findByRole("button", { name: /^delete$/i })
    )

    expect(deleteCertificatePolicyMock).toHaveBeenCalledWith(
      "payments",
      CERT_ID
    )
  })
})
