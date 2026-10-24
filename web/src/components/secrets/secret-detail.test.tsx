import { QueryClient, QueryClientProvider } from "@tanstack/react-query"
import {
  createMemoryHistory,
  createRootRoute,
  createRouter,
  RouterProvider,
} from "@tanstack/react-router"
import { render, screen, within } from "@testing-library/react"
import userEvent from "@testing-library/user-event"
import { beforeEach, describe, expect, it, vi } from "vitest"

vi.mock("@/api/secrets", async () => {
  const actual =
    await vi.importActual<typeof import("@/api/secrets")>("@/api/secrets")
  return {
    ...actual,
    getSecret: vi.fn(),
    updateSecret: vi.fn(),
    deleteSecret: vi.fn(),
    backupSecret: vi.fn(),
    listSecretVersions: vi.fn(),
    getSecretVersion: vi.fn(),
  }
})

vi.mock("@/components/secrets/download", () => ({
  downloadBlob: vi.fn(),
  downloadText: vi.fn(),
}))

import {
  deleteSecret,
  getSecret,
  getSecretVersion,
  listSecretVersions,
  type Secret,
  updateSecret,
} from "@/api/secrets"
import { SecretDetail } from "@/components/secrets/secret-detail"

const getSecretMock = vi.mocked(getSecret)
const updateSecretMock = vi.mocked(updateSecret)
const deleteSecretMock = vi.mocked(deleteSecret)
const listSecretVersionsMock = vi.mocked(listSecretVersions)
const getSecretVersionMock = vi.mocked(getSecretVersion)

const secret: Secret = {
  id: "abc-123",
  name: "db-password",
  value: "hunter2",
  version: 3,
  enabled: true,
  contentType: "text/plain",
  tags: ["env=prod"],
  createdAt: "2026-01-01T00:00:00Z",
}

function renderDetail() {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  })
  const testRootRoute = createRootRoute({
    component: () => <SecretDetail vaultName="payments" secretId="abc-123" />,
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
  getSecretMock.mockReset()
  updateSecretMock.mockReset()
  deleteSecretMock.mockReset()
  listSecretVersionsMock.mockReset()
  getSecretVersionMock.mockReset()
  getSecretMock.mockResolvedValue(secret)
  listSecretVersionsMock.mockResolvedValue([
    {
      id: "v3",
      secretId: "abc-123",
      name: "db-password",
      version: 3,
      createdAt: "2026-01-01T00:00:00Z",
    },
    {
      id: "v2",
      secretId: "abc-123",
      name: "db-password",
      version: 2,
      createdAt: "2025-12-01T00:00:00Z",
    },
  ])
})

describe("SecretDetail", () => {
  it("never renders the current value unprompted", async () => {
    renderDetail()

    expect(
      await screen.findByRole("heading", { name: "db-password" })
    ).toBeInTheDocument()
    expect(screen.queryByText("hunter2")).not.toBeInTheDocument()
    expect(screen.getAllByText("••••••••").length).toBeGreaterThan(0)
  })

  it("keeps the new-value box empty rather than pre-filling the plaintext", async () => {
    renderDetail()

    const newValue = await screen.findByLabelText(/new value/i)
    expect(newValue).toHaveValue("")
  })

  it("disables Save until something actually differs, since a no-op update is a 400", async () => {
    const user = userEvent.setup()
    renderDetail()

    const save = await screen.findByRole("button", { name: /save changes/i })
    expect(save).toBeDisabled()

    await user.type(screen.getByLabelText(/new value/i), "rotated")

    expect(save).toBeEnabled()
  })

  it("sends only the changed fields on save", async () => {
    const user = userEvent.setup()
    updateSecretMock.mockResolvedValueOnce({ ...secret, version: 4 })
    renderDetail()

    await user.type(await screen.findByLabelText(/new value/i), "rotated")
    await user.click(screen.getByRole("button", { name: /save changes/i }))

    expect(updateSecretMock).toHaveBeenCalledWith("payments", "abc-123", {
      value: "rotated",
    })
  })

  it("fetches a historical value only when that version is inspected", async () => {
    const user = userEvent.setup()
    getSecretVersionMock.mockResolvedValue({
      id: "v2",
      secretId: "abc-123",
      userId: "u1",
      name: "db-password",
      version: 2,
      value: "old-value",
      createdAt: "2025-12-01T00:00:00Z",
    })
    renderDetail()

    const versionRow = (await screen.findByText("v2")).closest("tr")
    expect(getSecretVersionMock).not.toHaveBeenCalled()

    await user.click(
      within(versionRow as HTMLElement).getByRole("button", {
        name: /inspect/i,
      })
    )

    expect(getSecretVersionMock).toHaveBeenCalledWith("payments", "abc-123", 2)
    // The historical value is masked too -- inspecting a version must not
    // print an old credential on screen.
    expect(await screen.findByText(/value stored at/i)).toBeInTheDocument()
    expect(screen.queryByText("old-value")).not.toBeInTheDocument()
  })

  it("soft-deletes only behind a confirmation", async () => {
    const user = userEvent.setup()
    deleteSecretMock.mockResolvedValueOnce(undefined)
    renderDetail()

    await user.click(
      await screen.findByRole("button", { name: /delete secret/i })
    )
    expect(deleteSecretMock).not.toHaveBeenCalled()

    const confirm = within(await screen.findByRole("alertdialog"))
    await user.click(confirm.getByRole("button", { name: /confirm/i }))

    expect(deleteSecretMock).toHaveBeenCalledWith("payments", "abc-123")
  })
})
