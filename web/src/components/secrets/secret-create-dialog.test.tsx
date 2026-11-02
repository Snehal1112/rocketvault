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
    createSecret: vi.fn(),
    generateSecret: vi.fn(),
  }
})

import { createSecret, generateSecret, type Secret } from "@/api/secrets"
import { SecretCreateDialog } from "@/components/secrets/secret-create-dialog"

const createSecretMock = vi.mocked(createSecret)
const generateSecretMock = vi.mocked(generateSecret)

const created: Secret = {
  id: "abc-123",
  name: "db-password",
  version: 1,
  enabled: true,
  createdAt: "2026-01-01T00:00:00Z",
}

function renderDialog() {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  })
  const testRootRoute = createRootRoute({
    component: () => <SecretCreateDialog vaultName="payments" />,
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
  createSecretMock.mockReset()
  generateSecretMock.mockReset()
})

describe("SecretCreateDialog", () => {
  it("posts a manually-entered value to createSecret", async () => {
    const user = userEvent.setup()
    createSecretMock.mockResolvedValueOnce(created)
    renderDialog()

    await user.click(
      await screen.findByRole("button", { name: /create secret/i })
    )
    const dialog = within(await screen.findByRole("dialog"))
    await user.type(dialog.getByLabelText("Name"), "db-password")
    await user.type(dialog.getByLabelText("Value"), "hunter2")
    await user.click(dialog.getByRole("button", { name: /^create secret$/i }))

    expect(createSecretMock).toHaveBeenCalledWith("payments", {
      name: "db-password",
      value: "hunter2",
      tags: undefined,
      contentType: undefined,
    })
  })

  it("rejects a name the backend's pattern would refuse, without calling the API", async () => {
    const user = userEvent.setup()
    renderDialog()

    await user.click(
      await screen.findByRole("button", { name: /create secret/i })
    )
    const dialog = within(await screen.findByRole("dialog"))
    await user.type(dialog.getByLabelText("Name"), "1-bad-name")
    await user.type(dialog.getByLabelText("Value"), "hunter2")
    await user.click(dialog.getByRole("button", { name: /^create secret$/i }))

    expect(
      await screen.findByText(/name must start with a letter/i)
    ).toBeInTheDocument()
    expect(createSecretMock).not.toHaveBeenCalled()
  })

  it("posts to the server-side generate endpoint from the Generate tab", async () => {
    const user = userEvent.setup()
    generateSecretMock.mockResolvedValueOnce({ ...created, value: "Xk29" })
    renderDialog()

    await user.click(
      await screen.findByRole("button", { name: /create secret/i })
    )
    const dialog = within(await screen.findByRole("dialog"))
    await user.click(dialog.getByRole("tab", { name: /generate/i }))
    await user.type(dialog.getByLabelText("Name"), "api-token")
    await user.click(dialog.getByRole("button", { name: /generate secret/i }))

    expect(generateSecretMock).toHaveBeenCalledWith("payments", {
      name: "api-token",
      length: 32,
      useLowercase: true,
      useUppercase: true,
      useNumbers: true,
      useSymbols: false,
    })
    expect(createSecretMock).not.toHaveBeenCalled()
  })

  it("refuses to generate with every character set turned off", async () => {
    const user = userEvent.setup()
    renderDialog()

    await user.click(
      await screen.findByRole("button", { name: /create secret/i })
    )
    const dialog = within(await screen.findByRole("dialog"))
    await user.click(dialog.getByRole("tab", { name: /generate/i }))
    await user.type(dialog.getByLabelText("Name"), "api-token")
    await user.click(dialog.getByRole("checkbox", { name: /lowercase/i }))
    await user.click(dialog.getByRole("checkbox", { name: /uppercase/i }))
    await user.click(dialog.getByRole("checkbox", { name: /numbers/i }))
    await user.click(dialog.getByRole("button", { name: /generate secret/i }))

    expect(
      await screen.findByText(/at least one character set/i)
    ).toBeInTheDocument()
    expect(generateSecretMock).not.toHaveBeenCalled()
  })
})
