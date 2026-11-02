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

vi.mock("@/api/keys", () => ({
  createKey: vi.fn(),
  importKey: vi.fn(),
}))

import { createKey, importKey, type Key } from "@/api/keys"
import { ApiError } from "@/api/types"
import { KeyCreateDialog } from "@/components/keys/key-create-dialog"

const createKeyMock = vi.mocked(createKey)
const importKeyMock = vi.mocked(importKey)

const createdKey: Key = {
  id: "k1",
  name: "signing-key",
  type: "RSA",
  userId: "u1",
  revoked: false,
  createdAt: "2026-01-01T00:00:00Z",
  tags: [],
  enabled: true,
  bits: 2048,
  publicJwk: {},
}

function renderDialog() {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  })
  const testRootRoute = createRootRoute({
    component: () => <KeyCreateDialog vaultName="payments" />,
  })
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

async function openDialog() {
  await userEvent.click(
    await screen.findByRole("button", { name: /create key/i })
  )
}

beforeEach(() => {
  createKeyMock.mockReset()
  importKeyMock.mockReset()
  navigateMock.mockReset()
})

describe("KeyCreateDialog: generate", () => {
  it("sends an RSA key with the chosen size and no curve", async () => {
    createKeyMock.mockResolvedValueOnce(createdKey)

    renderDialog()
    await openDialog()

    await userEvent.type(screen.getByLabelText(/^name$/i), "signing-key")
    await userEvent.selectOptions(screen.getByLabelText(/key size/i), "4096")
    await userEvent.click(screen.getByRole("button", { name: /^generate$/i }))

    expect(createKeyMock).toHaveBeenCalledWith("payments", {
      name: "signing-key",
      type: "RSA",
      bits: 4096,
      tags: undefined,
    })
  })

  it("swaps the size field for a curve field when the type is ECDSA", async () => {
    createKeyMock.mockResolvedValueOnce(createdKey)

    renderDialog()
    await openDialog()

    await userEvent.type(screen.getByLabelText(/^name$/i), "eck")
    await userEvent.selectOptions(screen.getByLabelText(/^type$/i), "ECDSA")

    expect(screen.queryByLabelText(/key size/i)).not.toBeInTheDocument()

    await userEvent.selectOptions(screen.getByLabelText(/curve/i), "P-384")
    await userEvent.click(screen.getByRole("button", { name: /^generate$/i }))

    expect(createKeyMock).toHaveBeenCalledWith("payments", {
      name: "eck",
      type: "ECDSA",
      curve: "P-384",
      tags: undefined,
    })
  })

  it("sends the required bit size for a symmetric key", async () => {
    createKeyMock.mockResolvedValueOnce(createdKey)

    renderDialog()
    await openDialog()

    await userEvent.type(screen.getByLabelText(/^name$/i), "wrapper")
    await userEvent.selectOptions(screen.getByLabelText(/^type$/i), "OCT")
    await userEvent.click(screen.getByRole("button", { name: /^generate$/i }))

    expect(createKeyMock).toHaveBeenCalledWith("payments", {
      name: "wrapper",
      type: "OCT",
      bits: 256,
      tags: undefined,
    })
  })

  it("surfaces the server's HSM-required error for OCT keys rather than pre-blocking it", async () => {
    createKeyMock.mockRejectedValueOnce(
      new ApiError({
        status_code: 400,
        message:
          "Invalid or missing parameter: type: OCT key creation requires an HSM-backed key provider (hsm.enabled: true)",
      })
    )

    renderDialog()
    await openDialog()

    await userEvent.type(screen.getByLabelText(/^name$/i), "wrapper")
    await userEvent.selectOptions(screen.getByLabelText(/^type$/i), "OCT")
    await userEvent.click(screen.getByRole("button", { name: /^generate$/i }))

    expect(
      await screen.findByText(/OCT key creation requires an HSM-backed/i)
    ).toBeInTheDocument()
  })

  it("navigates to the new key once it is created", async () => {
    createKeyMock.mockResolvedValueOnce(createdKey)

    renderDialog()
    await openDialog()

    await userEvent.type(screen.getByLabelText(/^name$/i), "signing-key")
    await userEvent.click(screen.getByRole("button", { name: /^generate$/i }))

    expect(navigateMock).toHaveBeenCalledWith({
      to: "/vaults/$vaultName/keys/$keyId",
      params: { vaultName: "payments", keyId: "k1" },
    })
  })
})

describe("KeyCreateDialog: import", () => {
  it("parses the pasted JWK and posts it as an object", async () => {
    importKeyMock.mockResolvedValueOnce(createdKey)

    renderDialog()
    await openDialog()

    await userEvent.click(screen.getByRole("tab", { name: /import/i }))
    await userEvent.type(screen.getByLabelText(/^name$/i), "imported")
    await userEvent.type(
      screen.getByLabelText(/jwk/i),
      '{{"kty":"RSA","n":"x","e":"AQAB","d":"s"}'
    )
    await userEvent.click(screen.getByRole("button", { name: /^import$/i }))

    expect(importKeyMock).toHaveBeenCalledWith("payments", {
      name: "imported",
      jwk: { kty: "RSA", n: "x", e: "AQAB", d: "s" },
      tags: undefined,
    })
  })

  it("rejects malformed JSON before sending anything to the server", async () => {
    renderDialog()
    await openDialog()

    await userEvent.click(screen.getByRole("tab", { name: /import/i }))
    await userEvent.type(screen.getByLabelText(/^name$/i), "imported")
    await userEvent.type(screen.getByLabelText(/jwk/i), "not json")
    await userEvent.click(screen.getByRole("button", { name: /^import$/i }))

    expect(await screen.findByText(/not valid json/i)).toBeInTheDocument()
    expect(importKeyMock).not.toHaveBeenCalled()
  })
})
