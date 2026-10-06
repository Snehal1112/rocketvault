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
    listSecrets: vi.fn(),
    listDeletedSecrets: vi.fn(),
    createSecret: vi.fn(),
    generateSecret: vi.fn(),
  }
})

import { listDeletedSecrets, listSecrets, type Secret } from "@/api/secrets"
import { SecretList } from "@/components/secrets/secret-list"

const listSecretsMock = vi.mocked(listSecrets)
const listDeletedSecretsMock = vi.mocked(listDeletedSecrets)

function secret(overrides: Partial<Secret> & { id: string; name: string }) {
  return {
    version: 1,
    enabled: true,
    createdAt: "2026-01-01T00:00:00Z",
    ...overrides,
  } satisfies Secret
}

function renderSecretList() {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  })
  const testRootRoute = createRootRoute({
    component: () => <SecretList vaultName="payments" />,
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
  listSecretsMock.mockReset()
  listDeletedSecretsMock.mockReset()
  listDeletedSecretsMock.mockResolvedValue([])
})

describe("SecretList", () => {
  it("renders one card per secret, linking to the id-addressed detail route", async () => {
    listSecretsMock.mockResolvedValueOnce([
      secret({ id: "abc-123", name: "db-password" }),
    ])

    renderSecretList()

    const link = await screen.findByRole("link", { name: /db-password/i })
    expect(link).toHaveAttribute("href", "/vaults/payments/secrets/abc-123")
  })

  it("summarises total and enabled counts above the grid", async () => {
    listSecretsMock.mockResolvedValueOnce([
      secret({ id: "1", name: "a" }),
      secret({ id: "2", name: "b", enabled: false }),
    ])

    renderSecretList()

    const stats = within(
      await screen.findByRole("region", { name: /secret counts/i })
    )
    expect(stats.getByText("Total").previousSibling).toHaveTextContent("2")
    expect(stats.getByText("Enabled").previousSibling).toHaveTextContent("1")
    expect(stats.getByText("Deleted")).toBeInTheDocument()
  })

  it("shows the deleted count as an em dash when that list is unreadable", async () => {
    listSecretsMock.mockResolvedValueOnce([secret({ id: "1", name: "a" })])
    listDeletedSecretsMock.mockReset()
    listDeletedSecretsMock.mockRejectedValue(new Error("forbidden"))

    renderSecretList()

    expect(await screen.findByText("—")).toBeInTheDocument()
  })

  it("filters the grid by name as the operator types", async () => {
    const user = userEvent.setup()
    listSecretsMock.mockResolvedValueOnce([
      secret({ id: "1", name: "db-password" }),
      secret({ id: "2", name: "api-token" }),
    ])

    renderSecretList()
    await screen.findByRole("link", { name: /db-password/i })

    await user.type(screen.getByLabelText(/filter secrets/i), "api")

    expect(screen.getByRole("link", { name: /api-token/i })).toBeInTheDocument()
    expect(
      screen.queryByRole("link", { name: /db-password/i })
    ).not.toBeInTheDocument()
  })

  it("offers a create action from the empty state", async () => {
    listSecretsMock.mockResolvedValueOnce([])

    renderSecretList()

    expect(
      await screen.findByText(/no secrets in this vault/i)
    ).toBeInTheDocument()
    expect(
      screen.getByRole("button", { name: /create secret/i })
    ).toBeInTheDocument()
  })
})
