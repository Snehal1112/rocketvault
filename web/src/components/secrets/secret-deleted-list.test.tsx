import { QueryClient, QueryClientProvider } from "@tanstack/react-query"
import { render, screen, within } from "@testing-library/react"
import userEvent from "@testing-library/user-event"
import { beforeEach, describe, expect, it, vi } from "vitest"

vi.mock("@/api/secrets", async () => {
  const actual =
    await vi.importActual<typeof import("@/api/secrets")>("@/api/secrets")
  return {
    ...actual,
    listDeletedSecrets: vi.fn(),
    restoreDeletedSecret: vi.fn(),
    purgeSecret: vi.fn(),
  }
})

import {
  listDeletedSecrets,
  purgeSecret,
  restoreDeletedSecret,
} from "@/api/secrets"
import { ApiError } from "@/api/types"
import { SecretDeletedList } from "@/components/secrets/secret-deleted-list"

const listDeletedSecretsMock = vi.mocked(listDeletedSecrets)
const restoreDeletedSecretMock = vi.mocked(restoreDeletedSecret)
const purgeSecretMock = vi.mocked(purgeSecret)

function renderDeletedList() {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  })
  return render(
    <QueryClientProvider client={queryClient}>
      <SecretDeletedList vaultName="payments" />
    </QueryClientProvider>
  )
}

beforeEach(() => {
  listDeletedSecretsMock.mockReset()
  restoreDeletedSecretMock.mockReset()
  purgeSecretMock.mockReset()
  listDeletedSecretsMock.mockResolvedValue([
    {
      id: "abc-123",
      name: "db-password",
      version: 3,
      createdAt: "2026-01-01T00:00:00Z",
      deletedAt: "2026-02-01T00:00:00Z",
    },
  ])
})

describe("SecretDeletedList", () => {
  it("lists soft-deleted secrets with both recovery actions", async () => {
    renderDeletedList()

    expect(await screen.findByText("db-password")).toBeInTheDocument()
    expect(screen.getByRole("button", { name: "Recover" })).toBeInTheDocument()
    expect(screen.getByRole("button", { name: "Purge" })).toBeInTheDocument()
  })

  it("recovers without a confirmation step", async () => {
    const user = userEvent.setup()
    restoreDeletedSecretMock.mockResolvedValueOnce(undefined)
    renderDeletedList()

    await user.click(await screen.findByRole("button", { name: "Recover" }))

    expect(restoreDeletedSecretMock).toHaveBeenCalledWith("payments", "abc-123")
  })

  it("purges only after its own confirmation", async () => {
    const user = userEvent.setup()
    purgeSecretMock.mockResolvedValueOnce(undefined)
    renderDeletedList()

    await user.click(await screen.findByRole("button", { name: "Purge" }))
    expect(purgeSecretMock).not.toHaveBeenCalled()

    const confirm = within(await screen.findByRole("alertdialog"))
    await user.click(confirm.getByRole("button", { name: /confirm/i }))

    expect(purgeSecretMock).toHaveBeenCalledWith("payments", "abc-123")
  })

  it("explains a refused purge inline rather than silently failing", async () => {
    const user = userEvent.setup()
    purgeSecretMock.mockRejectedValueOnce(
      new ApiError({ message: "Access denied", status_code: 403 })
    )
    renderDeletedList()

    await user.click(await screen.findByRole("button", { name: "Purge" }))
    const confirm = within(await screen.findByRole("alertdialog"))
    await user.click(confirm.getByRole("button", { name: /confirm/i }))

    expect(await screen.findByRole("alert")).toHaveTextContent(
      /purge-protected|purge permission/i
    )
  })

  it("invites nothing when there is nothing deleted", async () => {
    listDeletedSecretsMock.mockReset()
    listDeletedSecretsMock.mockResolvedValue([])

    renderDeletedList()

    expect(await screen.findByText(/nothing deleted/i)).toBeInTheDocument()
  })
})
