import { QueryClient, QueryClientProvider } from "@tanstack/react-query"
import {
  createMemoryHistory,
  createRootRoute,
  createRouter,
  RouterProvider,
} from "@tanstack/react-router"
import { render, screen } from "@testing-library/react"
import { beforeEach, describe, expect, it, vi } from "vitest"

vi.mock("@/api/keys", () => ({
  listKeys: vi.fn(),
  createKey: vi.fn(),
  importKey: vi.fn(),
  restoreKey: vi.fn(),
}))

import type { Key } from "@/api/keys"
import { listKeys } from "@/api/keys"
import { KeyList } from "@/components/keys/key-list"

const listKeysMock = vi.mocked(listKeys)

function makeKey(overrides: Partial<Key> = {}): Key {
  return {
    id: "11111111-1111-1111-1111-111111111111",
    name: "signing-key",
    type: "RSA",
    userId: "u1",
    revoked: false,
    createdAt: "2026-01-01T00:00:00Z",
    tags: [],
    enabled: true,
    bits: 2048,
    publicJwk: {},
    ...overrides,
  }
}

function renderKeyList() {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  })
  const testRootRoute = createRootRoute({
    component: () => <KeyList vaultName="payments" />,
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
  listKeysMock.mockReset()
})

describe("KeyList", () => {
  it("renders one card per key, linking to the key's detail page by id", async () => {
    listKeysMock.mockResolvedValueOnce([makeKey()])

    renderKeyList()

    const link = await screen.findByRole("link", { name: /signing-key/i })
    expect(link).toHaveAttribute(
      "href",
      "/vaults/payments/keys/11111111-1111-1111-1111-111111111111"
    )
  })

  it("describes the key material and its HSM backing on the card", async () => {
    listKeysMock.mockResolvedValueOnce([
      makeKey({ type: "oct-HSM", bits: 256 }),
    ])

    renderKeyList()

    expect(await screen.findByText("AES 256")).toBeInTheDocument()
    expect(screen.getByText(/stored in hsm/i)).toBeInTheDocument()
  })

  it("summarizes the collection above the grid", async () => {
    listKeysMock.mockResolvedValueOnce([
      makeKey({ id: "a" }),
      makeKey({ id: "b", type: "RSA-HSM" }),
    ])

    renderKeyList()

    const totals = await screen.findByText("Total")
    expect(totals).toBeInTheDocument()
    expect(screen.getByText("HSM-backed")).toBeInTheDocument()
  })

  it("invites the operator to create a key when the vault has none", async () => {
    listKeysMock.mockResolvedValueOnce([])

    renderKeyList()

    expect(await screen.findByText(/no keys yet/i)).toBeInTheDocument()
    expect(
      screen.getByRole("button", { name: /create key/i })
    ).toBeInTheDocument()
  })

  it("surfaces a denied read as a permission message, not an empty vault", async () => {
    listKeysMock.mockRejectedValueOnce(
      new (await import("@/api/types")).ApiError({
        status_code: 403,
        message: "Insufficient permissions: keys_read",
      })
    )

    renderKeyList()

    expect(
      await screen.findByText(/insufficient permissions: keys_read/i)
    ).toBeInTheDocument()
  })
})
