import { QueryClient, QueryClientProvider } from "@tanstack/react-query"
import {
  createMemoryHistory,
  createRootRoute,
  createRouter,
  RouterProvider,
} from "@tanstack/react-router"
import { render, screen } from "@testing-library/react"
import { beforeEach, describe, expect, it, vi } from "vitest"

vi.mock("@/api/vaults", () => ({
  listVaults: vi.fn(),
  createVault: vi.fn(),
}))

import { listVaults } from "@/api/vaults"
import { VaultList } from "@/components/vaults/vault-list"

const listVaultsMock = vi.mocked(listVaults)

function renderVaultList() {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  })
  const testRootRoute = createRootRoute({ component: VaultList })
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
  listVaultsMock.mockReset()
})

describe("VaultList", () => {
  it("renders one row per vault, linking to its secrets tab", async () => {
    listVaultsMock.mockResolvedValueOnce([
      {
        id: "v1",
        name: "prod",
        enabled: true,
        purgeProtection: false,
        retentionDays: 90,
        createdBy: "u1",
        createdAt: "2026-01-01T00:00:00Z",
      },
    ])

    renderVaultList()

    const link = await screen.findByRole("link", { name: /prod/i })
    expect(link).toHaveAttribute("href", "/vaults/prod/secrets")
  })

  it("renders an empty state with a create CTA when there are no vaults", async () => {
    listVaultsMock.mockResolvedValueOnce([])

    renderVaultList()

    expect(await screen.findByText(/no vaults yet/i)).toBeInTheDocument()
    expect(
      screen.getByRole("button", { name: /create vault/i })
    ).toBeInTheDocument()
  })
})
