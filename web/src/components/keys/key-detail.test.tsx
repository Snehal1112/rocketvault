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

vi.mock("@/api/keys", () => ({
  getKey: vi.fn(),
  updateKey: vi.fn(),
  listKeyVersions: vi.fn(),
  rotateKey: vi.fn(),
  getRotationPolicy: vi.fn(),
  setRotationPolicy: vi.fn(),
  clearRotationPolicy: vi.fn(),
  deleteKey: vi.fn(),
  backupKey: vi.fn(),
  signData: vi.fn(),
  verifySignature: vi.fn(),
  encryptData: vi.fn(),
  decryptData: vi.fn(),
  wrapKey: vi.fn(),
  unwrapKey: vi.fn(),
}))

import {
  getKey,
  type Key,
  listKeyVersions,
  getRotationPolicy,
  updateKey,
} from "@/api/keys"
import { ApiError } from "@/api/types"
import { KeyDetail } from "@/components/keys/key-detail"

const getKeyMock = vi.mocked(getKey)
const updateKeyMock = vi.mocked(updateKey)
const listKeyVersionsMock = vi.mocked(listKeyVersions)
const getRotationPolicyMock = vi.mocked(getRotationPolicy)

function makeKey(overrides: Partial<Key> = {}): Key {
  return {
    id: "11111111-1111-1111-1111-111111111111",
    name: "signing-key",
    type: "RSA",
    userId: "u1",
    revoked: false,
    createdAt: "2026-01-01T00:00:00Z",
    tags: ["env=prod"],
    enabled: true,
    bits: 2048,
    publicJwk: { n: "MODULUS", e: "AQAB" },
    ...overrides,
  }
}

function renderDetail() {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  })
  const testRootRoute = createRootRoute({
    component: () => (
      <KeyDetail
        vaultName="payments"
        keyId="11111111-1111-1111-1111-111111111111"
      />
    ),
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
  getKeyMock.mockReset()
  updateKeyMock.mockReset()
  listKeyVersionsMock.mockReset().mockResolvedValue([])
  getRotationPolicyMock
    .mockReset()
    .mockRejectedValue(new ApiError({ status_code: 404, message: "not found" }))
})

describe("KeyDetail", () => {
  it("renders the key's name, material description and id", async () => {
    getKeyMock.mockResolvedValue(makeKey())

    renderDetail()

    expect(await screen.findByText("signing-key")).toBeInTheDocument()
    // Once in the page header, once in the overview card.
    expect(screen.getAllByText("RSA 2048")).toHaveLength(2)
    expect(
      screen.getByText("11111111-1111-1111-1111-111111111111")
    ).toBeInTheDocument()
  })

  it("renders the public JWK components", async () => {
    getKeyMock.mockResolvedValue(makeKey())

    renderDetail()

    expect(await screen.findByText("MODULUS")).toBeInTheDocument()
    expect(screen.getByText("AQAB")).toBeInTheDocument()
  })

  it("renders EC coordinates rather than RSA components for an EC key", async () => {
    getKeyMock.mockResolvedValue(
      makeKey({
        type: "ECDSA",
        curve: "P-384",
        bits: undefined,
        publicJwk: { x: "XCOORD", y: "YCOORD" },
      })
    )

    renderDetail()

    expect(await screen.findByText("XCOORD")).toBeInTheDocument()
    expect(screen.getByText("YCOORD")).toBeInTheDocument()
  })

  it("never renders private JWK material, even when the response carries it", async () => {
    getKeyMock.mockResolvedValue(
      makeKey({
        publicJwk: {
          n: "MODULUS",
          e: "AQAB",
          // A JWK field this component must not know how to display. Cast
          // because the API layer's own type already excludes it -- this
          // pins the component's allow-list independently of that.
          d: "PRIVATE-EXPONENT",
          p: "PRIVATE-PRIME",
        } as Key["publicJwk"],
      })
    )

    renderDetail()

    await screen.findByText("MODULUS")
    expect(screen.queryByText("PRIVATE-EXPONENT")).not.toBeInTheDocument()
    expect(screen.queryByText("PRIVATE-PRIME")).not.toBeInTheDocument()
    expect(document.body.textContent).not.toContain("PRIVATE")
  })

  it("explains why an HSM-backed key exposes no JWK components", async () => {
    getKeyMock.mockResolvedValue(makeKey({ type: "RSA-HSM", publicJwk: {} }))

    renderDetail()

    expect(await screen.findByText(/never leaves the hsm/i)).toBeInTheDocument()
  })

  it("revokes the key through updateKey", async () => {
    getKeyMock.mockResolvedValue(makeKey())
    updateKeyMock.mockResolvedValue(makeKey({ revoked: true }))

    renderDetail()

    await userEvent.click(
      await screen.findByRole("switch", { name: /^revoked$/i })
    )

    expect(updateKeyMock).toHaveBeenCalledWith(
      "payments",
      "11111111-1111-1111-1111-111111111111",
      { revoked: true }
    )
  })

  it("shows the server's message when the key cannot be read", async () => {
    getKeyMock.mockRejectedValue(
      new ApiError({ status_code: 404, message: "key not found" })
    )

    renderDetail()

    expect(await screen.findByText(/key not found/i)).toBeInTheDocument()
  })
})
