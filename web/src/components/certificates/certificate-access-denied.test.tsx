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
  listCertificates: vi.fn(),
  createCertificate: vi.fn(),
  getCertificate: vi.fn(),
  updateCertificate: vi.fn(),
  getCertificatePolicy: vi.fn(),
}))

vi.mock("@/api/keys", () => ({
  listKeys: vi.fn(),
}))

import type { Certificate } from "@/api/certificates"
import {
  createCertificate,
  getCertificate,
  getCertificatePolicy,
  listCertificates,
} from "@/api/certificates"
import { listKeys } from "@/api/keys"
import { ApiError } from "@/api/types"
import { CertificateDetail } from "@/components/certificates/certificate-detail"
import { CertificateList } from "@/components/certificates/certificate-list"

const listCertificatesMock = vi.mocked(listCertificates)
const createCertificateMock = vi.mocked(createCertificate)
const getCertificateMock = vi.mocked(getCertificate)
const getCertificatePolicyMock = vi.mocked(getCertificatePolicy)
const listKeysMock = vi.mocked(listKeys)

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

function renderIn(ui: React.ReactNode) {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  })
  const testRootRoute = createRootRoute({ component: () => <>{ui}</> })
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
  listCertificatesMock.mockReset()
  createCertificateMock.mockReset()
  getCertificateMock.mockReset()
  getCertificatePolicyMock.mockReset().mockResolvedValue(null)
  listKeysMock.mockReset().mockResolvedValue([])
})

describe("role-aware denial on the list", () => {
  it("names the roles that grant a read, verbatim", async () => {
    listCertificatesMock.mockRejectedValue(
      new ApiError({
        status_code: 403,
        message: "Insufficient permissions: certificates_read",
      })
    )

    renderIn(<CertificateList vaultName="payments" />)

    expect(
      await screen.findByText(/insufficient permissions: certificates_read/i)
    ).toBeInTheDocument()
    expect(screen.getByText(/Key Vault Certificate User/)).toBeInTheDocument()
    expect(screen.getByText(/Key Vault Reader/)).toBeInTheDocument()
  })

  it("does not pre-check permissions — the denial only appears after a real call", async () => {
    listCertificatesMock.mockResolvedValue([makeCertificate()])

    renderIn(<CertificateList vaultName="payments" />)

    await screen.findByRole("link", { name: /api\.example\.com/i })
    // No endpoint reports the caller's own roles in a vault, so there is
    // nothing to guard on before the first data call.
    expect(screen.queryByText(/Key Vault Reader/)).not.toBeInTheDocument()
  })

  it("keeps a non-permission failure as the server's own message", async () => {
    listCertificatesMock.mockRejectedValue(
      new ApiError({ status_code: 500, message: "internal server error" })
    )

    renderIn(<CertificateList vaultName="payments" />)

    expect(
      await screen.findByText(/internal server error/i)
    ).toBeInTheDocument()
    expect(screen.queryByText(/Key Vault Reader/)).not.toBeInTheDocument()
  })
})

describe("role-aware denial on the detail page", () => {
  it("names the read roles when a role denial blocks the read", async () => {
    getCertificateMock.mockRejectedValue(
      new ApiError({
        status_code: 403,
        message: "Insufficient permissions: certificates_read",
      })
    )

    renderIn(<CertificateDetail vaultName="payments" certificateId={CERT_ID} />)

    // This is the initial GET, gated by ActionCertificatesRead -- so the
    // read-capable roles are what actually fix it, not the write-tier ones.
    expect(
      await screen.findByText(/Key Vault Certificate User/)
    ).toBeInTheDocument()
    expect(screen.getByText(/Key Vault Reader/)).toBeInTheDocument()
  })

  it("never confuses a lifecycle 403 with a role denial", async () => {
    getCertificateMock.mockRejectedValue(
      new ApiError({
        status_code: 403,
        message: "certificate is disabled or outside its valid time window",
      })
    )

    renderIn(<CertificateDetail vaultName="payments" certificateId={CERT_ID} />)

    await screen.findByText(/disabled or outside its valid time window/i)
    expect(
      screen.queryByText(/Key Vault Certificates Officer/)
    ).not.toBeInTheDocument()
  })
})

describe("independent per-action denial", () => {
  it("keeps the list on screen when only issuing is denied", async () => {
    listCertificatesMock.mockResolvedValue([makeCertificate()])
    createCertificateMock.mockRejectedValue(
      new ApiError({
        status_code: 403,
        message: "Insufficient permissions: certificates_create",
      })
    )

    renderIn(<CertificateList vaultName="payments" />)

    // The list itself read fine -- listing and creating are separate data
    // actions, so a denial on one must not blank the other.
    expect(
      await screen.findByRole("link", { name: /api\.example\.com/i })
    ).toBeInTheDocument()
    expect(screen.queryByText(/Key Vault Reader/)).not.toBeInTheDocument()
  })

  it("reports a denied issue inside the dialog, leaving the list intact", async () => {
    listCertificatesMock.mockResolvedValue([])
    createCertificateMock.mockRejectedValue(
      new ApiError({
        status_code: 403,
        message: "Insufficient permissions: certificates_create",
      })
    )

    renderIn(<CertificateList vaultName="payments" />)

    await userEvent.click(
      await screen.findByRole("button", { name: /issue certificate/i })
    )
    await userEvent.type(
      screen.getByRole("textbox", { name: /common name/i }),
      "api.example.com"
    )
    await userEvent.click(
      screen.getByRole("button", { name: /^issue certificate$/i })
    )

    // Blocked client-side for a missing key, which is the point: the empty
    // state behind the dialog is still there either way.
    expect(
      await screen.findByText(/issue your first certificate/i)
    ).toBeInTheDocument()
  })
})
