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

vi.mock("@/api/vaults", () => ({
  deleteVault: vi.fn(),
  purgeVault: vi.fn(),
}))

import { deleteVault, purgeVault } from "@/api/vaults"
import { ApiError } from "@/api/types"
import { VaultDangerZone } from "@/components/vaults/vault-danger-zone"

const deleteVaultMock = vi.mocked(deleteVault)
const purgeVaultMock = vi.mocked(purgeVault)

function renderDangerZone(vaultName: string) {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  })
  const testRootRoute = createRootRoute({
    component: () => <VaultDangerZone vaultName={vaultName} />,
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
  deleteVaultMock.mockReset()
  purgeVaultMock.mockReset()
})

describe("VaultDangerZone", () => {
  it("disables the delete action for the default vault", async () => {
    renderDangerZone("default")

    expect(
      await screen.findByRole("button", { name: /delete vault/i })
    ).toBeDisabled()
  })

  it("surfaces a 403 from purge independently of delete's permission", async () => {
    purgeVaultMock.mockRejectedValue(
      new ApiError({ status_code: 403, message: "forbidden" })
    )

    renderDangerZone("prod")

    await userEvent.click(
      await screen.findByRole("button", { name: /purge vault/i })
    )
    await userEvent.click(screen.getByRole("button", { name: /confirm/i }))

    expect(
      await screen.findByText(/don't have permission to purge/i)
    ).toBeInTheDocument()
    expect(screen.getByRole("button", { name: /delete vault/i })).toBeEnabled()
  })
})
