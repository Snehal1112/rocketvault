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

const { navigateMock } = vi.hoisted(() => ({ navigateMock: vi.fn() }))

vi.mock("@tanstack/react-router", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@tanstack/react-router")>()
  return { ...actual, useNavigate: () => navigateMock }
})

vi.mock("@/api/keys", () => ({
  backupKey: vi.fn(),
  restoreKey: vi.fn(),
  deleteKey: vi.fn(),
}))

import { backupKey, deleteKey, restoreKey } from "@/api/keys"
import { ApiError } from "@/api/types"
import { KeyBackupCard } from "@/components/keys/key-backup-card"
import { KeyDangerZone } from "@/components/keys/key-danger-zone"
import { KeyRestoreDialog } from "@/components/keys/key-restore-dialog"

const backupKeyMock = vi.mocked(backupKey)
const restoreKeyMock = vi.mocked(restoreKey)
const deleteKeyMock = vi.mocked(deleteKey)

function renderWithProviders(ui: React.ReactNode) {
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
  backupKeyMock.mockReset()
  restoreKeyMock.mockReset()
  deleteKeyMock.mockReset()
  navigateMock.mockReset()
})

describe("KeyBackupCard", () => {
  it("fetches the blob on demand and shows it for copying", async () => {
    backupKeyMock.mockResolvedValue("YmxvYg==")

    renderWithProviders(
      <KeyBackupCard vaultName="payments" keyId="k1" keyName="signing-key" />
    )

    await userEvent.click(
      await screen.findByRole("button", { name: /create backup/i })
    )

    expect(backupKeyMock).toHaveBeenCalledWith("payments", "k1")
    expect(await screen.findByText("YmxvYg==")).toBeInTheDocument()
  })

  it("warns that the blob is unencrypted key material", async () => {
    renderWithProviders(
      <KeyBackupCard vaultName="payments" keyId="k1" keyName="signing-key" />
    )

    expect(await screen.findByText(/is not encrypted/i)).toBeInTheDocument()
  })
})

describe("KeyRestoreDialog", () => {
  it("posts the pasted blob and refuses an empty one", async () => {
    restoreKeyMock.mockResolvedValue(undefined)

    renderWithProviders(<KeyRestoreDialog vaultName="payments" />)

    await userEvent.click(
      await screen.findByRole("button", { name: /restore from backup/i })
    )
    await userEvent.click(screen.getByRole("button", { name: /^restore$/i }))

    expect(restoreKeyMock).not.toHaveBeenCalled()
    expect(await screen.findByText(/paste a backup blob/i)).toBeInTheDocument()

    await userEvent.type(screen.getByLabelText(/backup blob/i), "YmxvYg==")
    await userEvent.click(screen.getByRole("button", { name: /^restore$/i }))

    expect(restoreKeyMock).toHaveBeenCalledWith("payments", "YmxvYg==")
  })
})

describe("KeyDangerZone", () => {
  it("deletes only after confirming, then returns to the key list", async () => {
    deleteKeyMock.mockResolvedValue({
      id: "k1",
      name: "signing-key",
      deletedAt: "2026-02-01T00:00:00Z",
      scheduledPurgeAt: "2026-03-01T00:00:00Z",
    })

    renderWithProviders(
      <KeyDangerZone vaultName="payments" keyId="k1" keyName="signing-key" />
    )

    await userEvent.click(
      await screen.findByRole("button", { name: /^delete key$/i })
    )
    expect(deleteKeyMock).not.toHaveBeenCalled()

    await userEvent.click(screen.getByRole("button", { name: /^delete$/i }))

    expect(deleteKeyMock).toHaveBeenCalledWith("payments", "k1")
    expect(navigateMock).toHaveBeenCalledWith({
      to: "/vaults/$vaultName/keys",
      params: { vaultName: "payments" },
    })
  })

  it("surfaces a denied delete instead of navigating away", async () => {
    deleteKeyMock.mockRejectedValue(
      new ApiError({
        status_code: 403,
        message: "Insufficient permissions: keys_delete",
      })
    )

    renderWithProviders(
      <KeyDangerZone vaultName="payments" keyId="k1" keyName="signing-key" />
    )

    await userEvent.click(
      await screen.findByRole("button", { name: /^delete key$/i })
    )
    await userEvent.click(screen.getByRole("button", { name: /^delete$/i }))

    expect(
      await screen.findByText(/insufficient permissions: keys_delete/i)
    ).toBeInTheDocument()
    expect(navigateMock).not.toHaveBeenCalled()
  })
})
