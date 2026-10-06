import { QueryClient, QueryClientProvider } from "@tanstack/react-query"
import { render, screen } from "@testing-library/react"
import userEvent from "@testing-library/user-event"
import { beforeEach, describe, expect, it, vi } from "vitest"

vi.mock("@/api/keys", () => ({
  listDeletedKeys: vi.fn(),
  restoreDeletedKey: vi.fn(),
  purgeKey: vi.fn(),
}))

import { listDeletedKeys, purgeKey, restoreDeletedKey } from "@/api/keys"
import { ApiError } from "@/api/types"
import { KeyDeletedList } from "@/components/keys/key-deleted-list"

const listDeletedKeysMock = vi.mocked(listDeletedKeys)
const restoreDeletedKeyMock = vi.mocked(restoreDeletedKey)
const purgeKeyMock = vi.mocked(purgeKey)

function renderList() {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  })
  return render(
    <QueryClientProvider client={queryClient}>
      <KeyDeletedList vaultName="payments" />
    </QueryClientProvider>
  )
}

beforeEach(() => {
  listDeletedKeysMock.mockReset()
  restoreDeletedKeyMock.mockReset()
  purgeKeyMock.mockReset()
})

describe("KeyDeletedList", () => {
  it("says so plainly when nothing is waiting to be recovered", async () => {
    listDeletedKeysMock.mockResolvedValue([])

    renderList()

    expect(await screen.findByText(/nothing deleted/i)).toBeInTheDocument()
  })

  it("lists each deleted key with its type and when it went", async () => {
    listDeletedKeysMock.mockResolvedValue([
      {
        id: "k1",
        name: "signing-key",
        type: "RSA",
        deletedAt: "2026-01-01T00:00:00Z",
        purgeProtection: false,
      },
    ])

    renderList()

    expect(await screen.findByText("signing-key")).toBeInTheDocument()
    expect(screen.getByText("RSA")).toBeInTheDocument()
  })

  it("recovers a key", async () => {
    listDeletedKeysMock.mockResolvedValue([
      {
        id: "k1",
        name: "signing-key",
        type: "RSA",
        deletedAt: "2026-01-01T00:00:00Z",
        purgeProtection: false,
      },
    ])
    restoreDeletedKeyMock.mockResolvedValue(undefined)

    renderList()

    await userEvent.click(
      await screen.findByRole("button", { name: /recover/i })
    )

    expect(restoreDeletedKeyMock).toHaveBeenCalledWith("payments", "k1")
  })

  it("purges only after a confirmation that states the consequence", async () => {
    listDeletedKeysMock.mockResolvedValue([
      {
        id: "k1",
        name: "signing-key",
        type: "RSA",
        deletedAt: "2026-01-01T00:00:00Z",
        purgeProtection: false,
      },
    ])
    purgeKeyMock.mockResolvedValue(undefined)

    renderList()

    await userEvent.click(
      await screen.findByRole("button", { name: /^purge$/i })
    )
    expect(purgeKeyMock).not.toHaveBeenCalled()
    expect(screen.getByText(/cannot be undone/i)).toBeInTheDocument()

    await userEvent.click(
      screen.getByRole("button", { name: /purge permanently/i })
    )

    expect(purgeKeyMock).toHaveBeenCalledWith("payments", "k1")
  })

  it("disables purge for a purge-protected key and explains why", async () => {
    listDeletedKeysMock.mockResolvedValue([
      {
        id: "k1",
        name: "protected-key",
        type: "RSA",
        deletedAt: "2026-01-01T00:00:00Z",
        purgeProtection: true,
      },
    ])

    renderList()

    expect(
      await screen.findByRole("button", { name: /^purge$/i })
    ).toBeDisabled()
    expect(screen.getByText(/purge protected/i)).toBeInTheDocument()
  })

  it("surfaces a denied purge rather than silently doing nothing", async () => {
    listDeletedKeysMock.mockResolvedValue([
      {
        id: "k1",
        name: "signing-key",
        type: "RSA",
        deletedAt: "2026-01-01T00:00:00Z",
        purgeProtection: false,
      },
    ])
    purgeKeyMock.mockRejectedValue(
      new ApiError({
        status_code: 403,
        message: "Insufficient permissions: keys_purge",
      })
    )

    renderList()

    await userEvent.click(
      await screen.findByRole("button", { name: /^purge$/i })
    )
    await userEvent.click(
      screen.getByRole("button", { name: /purge permanently/i })
    )

    expect(
      await screen.findByText(/insufficient permissions: keys_purge/i)
    ).toBeInTheDocument()
  })
})
