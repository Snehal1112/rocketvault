import { QueryClient, QueryClientProvider } from "@tanstack/react-query"
import {
  createMemoryHistory,
  createRootRoute,
  createRouter,
  RouterProvider,
} from "@tanstack/react-router"
import { render, screen, within } from "@testing-library/react"
import { beforeEach, describe, expect, it, vi } from "vitest"

vi.mock("@/api/certificates", () => ({
  listCertificates: vi.fn(),
  createCertificate: vi.fn(),
}))

vi.mock("@/api/keys", () => ({
  listKeys: vi.fn(),
}))

import type { Certificate } from "@/api/certificates"
import { listCertificates } from "@/api/certificates"
import { listKeys } from "@/api/keys"
import { ApiError } from "@/api/types"
import { CertificateList } from "@/components/certificates/certificate-list"

const listCertificatesMock = vi.mocked(listCertificates)
const listKeysMock = vi.mocked(listKeys)

const CERT_ID = "11111111-1111-1111-1111-111111111111"

function inDays(count: number): string {
  return new Date(Date.now() + count * 24 * 60 * 60 * 1000).toISOString()
}

function makeCertificate(overrides: Partial<Certificate> = {}): Certificate {
  return {
    id: CERT_ID,
    name: "api.example.com",
    userId: "u1",
    createdAt: "2026-01-01T00:00:00Z",
    tags: [],
    autoRenew: false,
    renewalDays: 30,
    expiresAt: inDays(300),
    enabled: true,
    ...overrides,
  }
}

function renderList() {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  })
  const testRootRoute = createRootRoute({
    component: () => <CertificateList vaultName="payments" />,
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
  listCertificatesMock.mockReset()
  listKeysMock.mockReset().mockResolvedValue([])
})

describe("CertificateList", () => {
  it("renders one card per certificate, linking to the detail page by id", async () => {
    listCertificatesMock.mockResolvedValue([makeCertificate()])

    renderList()

    const link = await screen.findByRole("link", { name: /api\.example\.com/i })
    expect(link).toHaveAttribute(
      "href",
      `/vaults/payments/certificates/${CERT_ID}`
    )
  })

  it("warns about a certificate inside its own renewal window, saying how long is left", async () => {
    listCertificatesMock.mockResolvedValue([
      makeCertificate({ expiresAt: inDays(9), renewalDays: 30 }),
    ])

    renderList()

    // Asserted through the accessible label rather than a CSS class: the point
    // of the warning is that a screen-reader user learns the same urgency a
    // sighted user reads off the amber dot.
    expect(await screen.findByText(/expires in 9 days/i)).toBeInTheDocument()
  })

  it("marks an already-expired certificate as expired, not merely expiring", async () => {
    listCertificatesMock.mockResolvedValue([
      makeCertificate({ expiresAt: inDays(-2) }),
    ])

    renderList()

    const card = await screen.findByRole("link", { name: /api\.example\.com/i })
    expect(within(card).getByText("Expired")).toBeInTheDocument()
    expect(within(card).queryByText(/expires in/i)).not.toBeInTheDocument()
  })

  it("summarizes the collection above the grid", async () => {
    listCertificatesMock.mockResolvedValue([
      makeCertificate({ id: "a" }),
      makeCertificate({ id: "b", expiresAt: inDays(3) }),
      makeCertificate({ id: "c", expiresAt: inDays(-3) }),
    ])

    renderList()

    const stats = await screen.findByRole("region", {
      name: /certificate counts/i,
    })
    expect(within(stats).getByText("Total")).toBeInTheDocument()
    expect(within(stats).getByText("Expiring soon")).toBeInTheDocument()
    expect(within(stats).getByText("Expired")).toBeInTheDocument()
    // One expiring, one expired, one healthy.
    expect(within(stats).getAllByText("1")).toHaveLength(2)
    expect(within(stats).getByText("3")).toBeInTheDocument()
  })

  it("renders tags as badges on the card", async () => {
    listCertificatesMock.mockResolvedValue([
      makeCertificate({ tags: ["env=prod", "team=platform"] }),
    ])

    renderList()

    expect(await screen.findByText("env=prod")).toBeInTheDocument()
    expect(screen.getByText("team=platform")).toBeInTheDocument()
  })

  it("never renders certificate or private-key material, even if a response carries it", async () => {
    listCertificatesMock.mockResolvedValue([
      {
        ...makeCertificate(),
        // Fields the domain type has but the API response does not. Cast so
        // this pins the component independently of the API layer's own
        // allow-list.
        certificate: "-----BEGIN CERTIFICATE-----LEAK",
        private_key: "-----BEGIN PRIVATE KEY-----LEAK",
      } as Certificate,
    ])

    renderList()

    await screen.findByText("api.example.com")
    expect(document.body.textContent).not.toContain("LEAK")
    expect(document.body.textContent).not.toContain("BEGIN CERTIFICATE")
  })

  it("invites the operator to issue a certificate when the vault has none", async () => {
    listCertificatesMock.mockResolvedValue([])

    renderList()

    expect(
      await screen.findByText(/issue your first certificate/i)
    ).toBeInTheDocument()
    expect(
      screen.getByRole("button", { name: /issue certificate/i })
    ).toBeInTheDocument()
  })

  it("surfaces a denied read rather than showing an empty vault", async () => {
    listCertificatesMock.mockRejectedValue(
      new ApiError({
        status_code: 403,
        message: "Insufficient permissions: certificates_read",
      })
    )

    renderList()

    expect(
      await screen.findByText(/insufficient permissions: certificates_read/i)
    ).toBeInTheDocument()
  })
})
