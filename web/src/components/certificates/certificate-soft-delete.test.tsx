import { QueryClient, QueryClientProvider } from "@tanstack/react-query"
import {
  createMemoryHistory,
  createRootRoute,
  createRouter,
  RouterProvider,
} from "@tanstack/react-router"
import { render, screen, within } from "@testing-library/react"
import userEvent from "@testing-library/user-event"
import type { ReactNode } from "react"
import { beforeEach, describe, expect, it, vi } from "vitest"

const { navigateMock } = vi.hoisted(() => ({ navigateMock: vi.fn() }))

vi.mock("@tanstack/react-router", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@tanstack/react-router")>()
  return { ...actual, useNavigate: () => navigateMock }
})

vi.mock("@/api/certificates", () => ({
  deleteCertificate: vi.fn(),
  listDeletedCertificates: vi.fn(),
  recoverCertificate: vi.fn(),
  purgeCertificate: vi.fn(),
  backupCertificate: vi.fn(),
  restoreCertificate: vi.fn(),
}))

import {
  backupCertificate,
  deleteCertificate,
  listDeletedCertificates,
  purgeCertificate,
  recoverCertificate,
  restoreCertificate,
} from "@/api/certificates"
import { ApiError } from "@/api/types"
import { CertificateBackupCard } from "@/components/certificates/certificate-backup-card"
import { CertificateDangerZone } from "@/components/certificates/certificate-danger-zone"
import { CertificateDeletedList } from "@/components/certificates/certificate-deleted-list"
import { CertificateRestoreDialog } from "@/components/certificates/certificate-restore-dialog"

const deleteCertificateMock = vi.mocked(deleteCertificate)
const listDeletedCertificatesMock = vi.mocked(listDeletedCertificates)
const recoverCertificateMock = vi.mocked(recoverCertificate)
const purgeCertificateMock = vi.mocked(purgeCertificate)
const backupCertificateMock = vi.mocked(backupCertificate)
const restoreCertificateMock = vi.mocked(restoreCertificate)

const CERT_ID = "11111111-1111-1111-1111-111111111111"

function renderWithProviders(ui: ReactNode) {
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
  deleteCertificateMock.mockReset()
  listDeletedCertificatesMock.mockReset()
  recoverCertificateMock.mockReset()
  purgeCertificateMock.mockReset()
  backupCertificateMock.mockReset()
  restoreCertificateMock.mockReset()
  navigateMock.mockReset()
})

describe("CertificateDangerZone", () => {
  it("deletes only after confirming, then returns to the certificate list", async () => {
    deleteCertificateMock.mockResolvedValue(undefined)

    renderWithProviders(
      <CertificateDangerZone
        vaultName="payments"
        certificateId={CERT_ID}
        certificateName="api.example.com"
      />
    )

    await userEvent.click(
      await screen.findByRole("button", { name: /^delete certificate$/i })
    )
    expect(deleteCertificateMock).not.toHaveBeenCalled()

    await userEvent.click(screen.getByRole("button", { name: /^delete$/i }))

    expect(deleteCertificateMock).toHaveBeenCalledWith("payments", CERT_ID)
    expect(navigateMock).toHaveBeenCalledWith({
      to: "/vaults/$vaultName/certificates",
      params: { vaultName: "payments" },
    })
  })

  it("surfaces a denied delete instead of navigating away", async () => {
    deleteCertificateMock.mockRejectedValue(
      new ApiError({
        status_code: 403,
        message: "Insufficient permissions: certificates_delete",
      })
    )

    renderWithProviders(
      <CertificateDangerZone
        vaultName="payments"
        certificateId={CERT_ID}
        certificateName="api.example.com"
      />
    )

    await userEvent.click(
      await screen.findByRole("button", { name: /^delete certificate$/i })
    )
    await userEvent.click(screen.getByRole("button", { name: /^delete$/i }))

    expect(
      await screen.findByText(/insufficient permissions: certificates_delete/i)
    ).toBeInTheDocument()
    expect(navigateMock).not.toHaveBeenCalled()
  })
})

describe("CertificateDeletedList", () => {
  it("renders the four fields the deleted row carries, and no invented ones", async () => {
    listDeletedCertificatesMock.mockResolvedValue([
      {
        id: CERT_ID,
        name: "api.example.com",
        deletedAt: "2026-03-01T00:00:00Z",
        purgeProtection: true,
      },
    ])

    renderWithProviders(<CertificateDeletedList vaultName="payments" />)

    const row = await screen.findByRole("row", { name: /api\.example\.com/i })
    expect(within(row).getByText(CERT_ID)).toBeInTheDocument()
    expect(within(row).getByText(/purge protected/i)).toBeInTheDocument()
    // The deleted-certificate row has no created_at, unlike the deleted-secret
    // one -- so nothing here may claim an issue date.
    expect(within(row).queryByText(/issued/i)).not.toBeInTheDocument()
  })

  it("shows the server's own recovery message", async () => {
    listDeletedCertificatesMock.mockResolvedValue([
      {
        id: CERT_ID,
        name: "api.example.com",
        deletedAt: "2026-03-01T00:00:00Z",
        purgeProtection: false,
      },
    ])
    recoverCertificateMock.mockResolvedValue({
      id: CERT_ID,
      message: "Certificate recovered successfully",
    })

    renderWithProviders(<CertificateDeletedList vaultName="payments" />)

    await userEvent.click(
      await screen.findByRole("button", { name: /recover/i })
    )

    expect(recoverCertificateMock).toHaveBeenCalledWith("payments", CERT_ID)
    expect(
      await screen.findByText(/certificate recovered successfully/i)
    ).toBeInTheDocument()
  })

  it("lets a purge-protected row be attempted, and reports the server's 403 verbatim", async () => {
    listDeletedCertificatesMock.mockResolvedValue([
      {
        id: CERT_ID,
        name: "api.example.com",
        deletedAt: "2026-03-01T00:00:00Z",
        purgeProtection: true,
      },
    ])
    purgeCertificateMock.mockRejectedValue(
      new ApiError({
        status_code: 403,
        message: "certificate has purge protection enabled",
      })
    )

    renderWithProviders(<CertificateDeletedList vaultName="payments" />)

    // NOT pre-blocked client-side: the row's own flag is one of three
    // independent protections (certificate, vault, instance-wide), and the
    // other two are invisible here -- so a client-side guard would be wrong
    // in both directions.
    const purge = await screen.findByRole("button", { name: /^purge$/i })
    expect(purge).toBeEnabled()

    await userEvent.click(purge)
    await userEvent.click(
      await screen.findByRole("button", { name: /purge permanently/i })
    )

    expect(purgeCertificateMock).toHaveBeenCalledWith("payments", CERT_ID)
    expect(
      await screen.findByText(/has purge protection enabled/i)
    ).toBeInTheDocument()
  })

  it("purges a row the server accepts", async () => {
    listDeletedCertificatesMock.mockResolvedValue([
      {
        id: CERT_ID,
        name: "api.example.com",
        deletedAt: "2026-03-01T00:00:00Z",
        purgeProtection: false,
      },
    ])
    purgeCertificateMock.mockResolvedValue(undefined)

    renderWithProviders(<CertificateDeletedList vaultName="payments" />)

    await userEvent.click(
      await screen.findByRole("button", { name: /^purge$/i })
    )
    await userEvent.click(
      await screen.findByRole("button", { name: /purge permanently/i })
    )

    expect(purgeCertificateMock).toHaveBeenCalledWith("payments", CERT_ID)
  })
})

describe("CertificateBackupCard", () => {
  it("creates a blob on demand and shows it for copying", async () => {
    backupCertificateMock.mockResolvedValue("YmxvYg==")

    renderWithProviders(
      <CertificateBackupCard
        vaultName="payments"
        certificateId={CERT_ID}
        certificateName="api.example.com"
      />
    )

    await userEvent.click(
      await screen.findByRole("button", { name: /create backup/i })
    )

    expect(backupCertificateMock).toHaveBeenCalledWith("payments", CERT_ID)
    expect(await screen.findByText("YmxvYg==")).toBeInTheDocument()
  })

  it("says the blob is not a PEM — there is no certificate download anywhere", async () => {
    renderWithProviders(
      <CertificateBackupCard
        vaultName="payments"
        certificateId={CERT_ID}
        certificateName="api.example.com"
      />
    )

    expect(await screen.findByText(/not a PEM/i)).toBeInTheDocument()
    expect(document.body.textContent).not.toContain("BEGIN CERTIFICATE")
  })
})

describe("CertificateRestoreDialog", () => {
  it("posts a pasted blob and refuses an empty one", async () => {
    restoreCertificateMock.mockResolvedValue(undefined)

    renderWithProviders(<CertificateRestoreDialog vaultName="payments" />)

    await userEvent.click(
      await screen.findByRole("button", { name: /restore from backup/i })
    )
    await userEvent.click(screen.getByRole("button", { name: /^restore$/i }))

    expect(restoreCertificateMock).not.toHaveBeenCalled()
    expect(await screen.findByText(/paste a backup blob/i)).toBeInTheDocument()

    await userEvent.type(screen.getByLabelText(/backup blob/i), "YmxvYg==")
    await userEvent.click(screen.getByRole("button", { name: /^restore$/i }))

    expect(restoreCertificateMock).toHaveBeenCalledWith("payments", "YmxvYg==")
  })

  it("surfaces an invalid-blob 400 on the control, not as a page-level error", async () => {
    restoreCertificateMock.mockRejectedValue(
      new ApiError({
        status_code: 400,
        message: "Invalid or missing blob parameter",
      })
    )

    renderWithProviders(<CertificateRestoreDialog vaultName="payments" />)

    await userEvent.click(
      await screen.findByRole("button", { name: /restore from backup/i })
    )
    await userEvent.type(screen.getByLabelText(/backup blob/i), "not-a-blob")
    await userEvent.click(screen.getByRole("button", { name: /^restore$/i }))

    const message = await screen.findByText(/invalid or missing blob/i)
    expect(message).toBeInTheDocument()
    // Still inside the dialog, so the operator can fix the input in place
    // rather than losing it to a page-level banner.
    expect(screen.getByRole("dialog")).toContainElement(message)
  })
})
