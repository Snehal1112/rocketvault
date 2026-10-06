import { QueryClient, QueryClientProvider } from "@tanstack/react-query"
import {
  createMemoryHistory,
  createRootRoute,
  createRouter,
  RouterProvider,
} from "@tanstack/react-router"
import { render, screen } from "@testing-library/react"
import userEvent from "@testing-library/user-event"
import { beforeEach, describe, expect, it, vi } from "vitest"

vi.mock("@/api/certificates", () => ({
  getCertificate: vi.fn(),
  updateCertificate: vi.fn(),
  deleteCertificate: vi.fn(),
  getCertificatePolicy: vi.fn(),
  upsertCertificatePolicy: vi.fn(),
  deleteCertificatePolicy: vi.fn(),
  backupCertificate: vi.fn(),
}))

import type { Certificate } from "@/api/certificates"
import {
  getCertificate,
  getCertificatePolicy,
  updateCertificate,
} from "@/api/certificates"
import { ApiError } from "@/api/types"
import { CertificateDetail } from "@/components/certificates/certificate-detail"

const getCertificateMock = vi.mocked(getCertificate)
const updateCertificateMock = vi.mocked(updateCertificate)
const getCertificatePolicyMock = vi.mocked(getCertificatePolicy)

const CERT_ID = "11111111-1111-1111-1111-111111111111"

function makeCertificate(overrides: Partial<Certificate> = {}): Certificate {
  return {
    id: CERT_ID,
    name: "api.example.com",
    userId: "u1",
    createdAt: "2026-01-01T00:00:00Z",
    tags: ["env=prod"],
    autoRenew: false,
    renewalDays: 30,
    expiresAt: "2027-01-01T00:00:00Z",
    enabled: true,
    ...overrides,
  }
}

function renderDetail() {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  })
  const testRootRoute = createRootRoute({
    component: () => (
      <CertificateDetail vaultName="payments" certificateId={CERT_ID} />
    ),
  })
  const router = createRouter({
    routeTree: testRootRoute,
    history: createMemoryHistory({ initialEntries: ["/"] }),
  })
  return render(
    <QueryClientProvider client={queryClient}>
      <RouterProvider router={router} />
    </QueryClientProvider>
  )
}

beforeEach(() => {
  getCertificateMock.mockReset()
  updateCertificateMock.mockReset()
  getCertificatePolicyMock.mockReset().mockResolvedValue(null)
})

describe("CertificateDetail", () => {
  it("renders the certificate's name, id and validity window", async () => {
    getCertificateMock.mockResolvedValue(makeCertificate())

    renderDetail()

    expect(
      await screen.findByRole("heading", { name: "api.example.com" })
    ).toBeInTheDocument()
    expect(screen.getByText(CERT_ID)).toBeInTheDocument()
    expect(screen.getByText(/2027-01-01 00:00 UTC/)).toBeInTheDocument()
  })

  it("never renders certificate or private-key material, even when the response carries it", async () => {
    getCertificateMock.mockResolvedValue({
      ...makeCertificate(),
      // Both exist on model.Certificate but are absent from
      // CertificateResponse. Cast so this pins the component's own allow-list
      // independently of the API layer's.
      certificate: "-----BEGIN CERTIFICATE-----LEAK-----",
      private_key: "-----BEGIN PRIVATE KEY-----LEAK-----",
    } as Certificate)

    renderDetail()

    await screen.findByRole("heading", { name: "api.example.com" })
    expect(document.body.textContent).not.toContain("LEAK")
    expect(document.body.textContent).not.toContain("BEGIN CERTIFICATE")
    expect(document.body.textContent).not.toContain("BEGIN PRIVATE KEY")
  })

  it("explains a lifecycle 403 as a certificate state, not a permission problem", async () => {
    getCertificateMock.mockRejectedValue(
      new ApiError({
        status_code: 403,
        message: "certificate is disabled or outside its valid time window",
      })
    )

    renderDetail()

    expect(
      await screen.findByText(/disabled or outside its valid time window/i)
    ).toBeInTheDocument()
    expect(screen.queryByText(/don't have permission/i)).not.toBeInTheDocument()
    expect(screen.queryByText(/Key Vault Certificates Officer/)).toBeNull()
  })

  it("keeps a way back to the list on the error state", async () => {
    getCertificateMock.mockRejectedValue(
      new ApiError({
        status_code: 403,
        message: "certificate is disabled or outside its valid time window",
      })
    )

    renderDetail()

    const back = await screen.findByRole("link", {
      name: /all certificates/i,
    })
    expect(back).toHaveAttribute("href", "/vaults/payments/certificates")
  })
})

describe("CertificateAttributesForm", () => {
  it("sends only the attribute the operator actually changed", async () => {
    getCertificateMock.mockResolvedValue(makeCertificate())
    updateCertificateMock.mockResolvedValue(
      makeCertificate({ name: "renamed.example.com" })
    )

    renderDetail()

    const nameField = await screen.findByRole("textbox", { name: /^name$/i })
    await userEvent.clear(nameField)
    await userEvent.type(nameField, "renamed.example.com")
    await userEvent.click(screen.getByRole("button", { name: /save changes/i }))

    expect(updateCertificateMock).toHaveBeenCalledWith("payments", CERT_ID, {
      name: "renamed.example.com",
    })
  })

  it("refuses a save that would change nothing, rather than posting an empty body", async () => {
    getCertificateMock.mockResolvedValue(makeCertificate())

    renderDetail()

    await userEvent.click(
      await screen.findByRole("button", { name: /save changes/i })
    )

    // The backend answers 400 to a body with every field unset, which would
    // read as a server fault rather than as "nothing to save".
    expect(updateCertificateMock).not.toHaveBeenCalled()
    expect(await screen.findByText(/nothing to save/i)).toBeInTheDocument()
  })

  it("toggles enabled through updateCertificate on its own", async () => {
    getCertificateMock.mockResolvedValue(makeCertificate())
    updateCertificateMock.mockResolvedValue(makeCertificate({ enabled: false }))

    renderDetail()

    await userEvent.click(
      await screen.findByRole("switch", { name: /^enabled$/i })
    )

    expect(updateCertificateMock).toHaveBeenCalledWith("payments", CERT_ID, {
      enabled: false,
    })
  })

  it("says the signing key and CA issuer are fixed at issuance, and offers no control for either", async () => {
    getCertificateMock.mockResolvedValue(makeCertificate())

    renderDetail()

    expect(await screen.findByText(/fixed at issuance/i)).toBeInTheDocument()
    expect(screen.queryByLabelText(/signing key/i)).not.toBeInTheDocument()
    expect(screen.queryByLabelText(/ca certificate/i)).not.toBeInTheDocument()
  })
})
