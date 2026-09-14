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

vi.mock("@/api/vaults", () => ({
  createVault: vi.fn(),
}))

import { createVault } from "@/api/vaults"
import { VaultCreateDialog } from "@/components/vaults/vault-create-dialog"

const createVaultMock = vi.mocked(createVault)

function renderDialog() {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  })
  const testRootRoute = createRootRoute({ component: VaultCreateDialog })
  const router = createRouter({
    routeTree: testRootRoute,
    history: createMemoryHistory({ initialEntries: ["/"] }),
  })
  const view = render(
    <QueryClientProvider client={queryClient}>
      <RouterProvider router={router} />
    </QueryClientProvider>
  )
  return { queryClient, ...view }
}

beforeEach(() => {
  createVaultMock.mockReset()
  navigateMock.mockReset()
})

describe("VaultCreateDialog", () => {
  it("submits name and tags, invalidates the vaults query, and navigates to the new vault", async () => {
    createVaultMock.mockResolvedValueOnce({
      id: "v1",
      name: "prod",
      enabled: true,
      purgeProtection: false,
      retentionDays: 90,
      createdBy: "u1",
      createdAt: "2026-01-01T00:00:00Z",
    })

    const { queryClient } = renderDialog()
    const invalidateSpy = vi.spyOn(queryClient, "invalidateQueries")

    await userEvent.click(
      await screen.findByRole("button", { name: /create vault/i })
    )
    await userEvent.type(screen.getByLabelText(/^name$/i), "prod")
    await userEvent.type(screen.getByLabelText(/tags/i), "env=prod")
    await userEvent.click(screen.getByRole("button", { name: /^create$/i }))

    expect(createVaultMock).toHaveBeenCalledWith(
      { name: "prod", tags: { env: "prod" } },
      expect.anything()
    )
    expect(invalidateSpy).toHaveBeenCalled()
    expect(navigateMock).toHaveBeenCalledWith({
      to: "/vaults/$vaultName/secrets",
      params: { vaultName: "prod" },
    })
  })
})
