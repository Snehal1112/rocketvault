import { QueryClient, QueryClientProvider } from "@tanstack/react-query"
import { render, screen } from "@testing-library/react"
import userEvent from "@testing-library/user-event"
import { beforeEach, describe, expect, it, vi } from "vitest"

vi.mock("@/api/keys", () => ({
  listKeyVersions: vi.fn(),
  getKeyVersion: vi.fn(),
  rotateKey: vi.fn(),
}))

import { getKeyVersion, listKeyVersions, rotateKey } from "@/api/keys"
import { KeyVersions } from "@/components/keys/key-versions"

const listKeyVersionsMock = vi.mocked(listKeyVersions)
const getKeyVersionMock = vi.mocked(getKeyVersion)
const rotateKeyMock = vi.mocked(rotateKey)

function renderVersions() {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  })
  return render(
    <QueryClientProvider client={queryClient}>
      <KeyVersions vaultName="payments" keyId="k1" />
    </QueryClientProvider>
  )
}

beforeEach(() => {
  listKeyVersionsMock.mockReset()
  getKeyVersionMock.mockReset()
  rotateKeyMock.mockReset()
})

describe("KeyVersions", () => {
  it("lists every version, newest first, marking the current one", async () => {
    listKeyVersionsMock.mockResolvedValue([
      { keyId: "k1", version: 1, createdAt: "2026-01-01T00:00:00Z" },
      { keyId: "k1", version: 3, createdAt: "2026-03-01T00:00:00Z" },
      { keyId: "k1", version: 2, createdAt: "2026-02-01T00:00:00Z" },
    ])

    renderVersions()

    const rows = await screen.findAllByRole("row")
    // One header row plus three version rows.
    expect(rows).toHaveLength(4)
    expect(rows[1]).toHaveTextContent("3")
    expect(rows[1]).toHaveTextContent(/current/i)
    expect(rows[3]).toHaveTextContent("1")
  })

  it("loads a version's public components on demand", async () => {
    listKeyVersionsMock.mockResolvedValue([
      { keyId: "k1", version: 1, createdAt: "2026-01-01T00:00:00Z" },
    ])
    getKeyVersionMock.mockResolvedValue({
      keyId: "k1",
      version: 1,
      createdAt: "2026-01-01T00:00:00Z",
      publicJwk: { n: "OLD-MODULUS", e: "AQAB" },
    })

    renderVersions()

    await userEvent.click(
      await screen.findByRole("button", { name: /public key for version 1/i })
    )

    expect(getKeyVersionMock).toHaveBeenCalledWith("payments", "k1", 1)
    expect(await screen.findByText("OLD-MODULUS")).toBeInTheDocument()
  })

  it("rotates only after confirming, and says old material is retained", async () => {
    listKeyVersionsMock.mockResolvedValue([
      { keyId: "k1", version: 1, createdAt: "2026-01-01T00:00:00Z" },
    ])

    renderVersions()

    await userEvent.click(
      await screen.findByRole("button", { name: /rotate now/i })
    )

    expect(rotateKeyMock).not.toHaveBeenCalled()
    expect(screen.getByText(/previous versions are kept/i)).toBeInTheDocument()

    await userEvent.click(screen.getByRole("button", { name: /^rotate$/i }))

    expect(rotateKeyMock).toHaveBeenCalledWith("payments", "k1")
  })
})
