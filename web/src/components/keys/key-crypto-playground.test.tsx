import { QueryClient, QueryClientProvider } from "@tanstack/react-query"
import { render, screen } from "@testing-library/react"
import userEvent from "@testing-library/user-event"
import { beforeEach, describe, expect, it, vi } from "vitest"

vi.mock("@/api/keys", () => ({
  signData: vi.fn(),
  verifySignature: vi.fn(),
  encryptData: vi.fn(),
  decryptData: vi.fn(),
  wrapKey: vi.fn(),
  unwrapKey: vi.fn(),
}))

import {
  decryptData,
  encryptData,
  type Key,
  signData,
  verifySignature,
} from "@/api/keys"
import { ApiError } from "@/api/types"
import { KeyCryptoPlayground } from "@/components/keys/key-crypto-playground"

const signDataMock = vi.mocked(signData)
const verifySignatureMock = vi.mocked(verifySignature)
const encryptDataMock = vi.mocked(encryptData)
const decryptDataMock = vi.mocked(decryptData)

function makeKey(overrides: Partial<Key> = {}): Key {
  return {
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
    ...overrides,
  }
}

function renderPlayground(keyRecord: Key = makeKey()) {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  })
  return render(
    <QueryClientProvider client={queryClient}>
      <KeyCryptoPlayground vaultName="payments" keyRecord={keyRecord} />
    </QueryClientProvider>
  )
}

beforeEach(() => {
  signDataMock.mockReset()
  verifySignatureMock.mockReset()
  encryptDataMock.mockReset()
  decryptDataMock.mockReset()
})

describe("KeyCryptoPlayground", () => {
  it("offers only the operations the key can actually perform", () => {
    renderPlayground(
      makeKey({ type: "ECDSA", curve: "P-256", bits: undefined })
    )

    expect(screen.getByRole("tab", { name: /^sign$/i })).toBeInTheDocument()
    expect(screen.getByRole("tab", { name: /^verify$/i })).toBeInTheDocument()
    expect(
      screen.queryByRole("tab", { name: /^wrap$/i })
    ).not.toBeInTheDocument()
    expect(
      screen.queryByRole("tab", { name: /^encrypt$/i })
    ).not.toBeInTheDocument()
  })

  it("explains itself rather than rendering an empty panel for an unusable key", () => {
    renderPlayground(makeKey({ type: "QUANTUM" }))

    expect(
      screen.getByText(/no cryptographic operations are available/i)
    ).toBeInTheDocument()
  })

  it("signs the pasted base64 with the selected algorithm", async () => {
    signDataMock.mockResolvedValue({
      keyId: "k1",
      algorithm: "PS256",
      value: "U0lHTkFUVVJF",
      version: 2,
    })

    renderPlayground()

    await userEvent.type(screen.getByLabelText(/data to sign/i), "ZGF0YQ==")
    await userEvent.selectOptions(screen.getByLabelText(/algorithm/i), "PS256")
    await userEvent.click(screen.getByRole("button", { name: /^sign$/i }))

    expect(signDataMock).toHaveBeenCalledWith("payments", "k1", {
      value: "ZGF0YQ==",
      algorithm: "PS256",
      version: undefined,
    })
    expect(await screen.findByText("U0lHTkFUVVJF")).toBeInTheDocument()
  })

  it("pins the request to a specific version when one is given", async () => {
    signDataMock.mockResolvedValue({
      keyId: "k1",
      algorithm: "RS256",
      value: "U0lH",
      version: 1,
    })

    renderPlayground()

    await userEvent.type(screen.getByLabelText(/data to sign/i), "ZGF0YQ==")
    await userEvent.type(screen.getByLabelText(/version/i), "1")
    await userEvent.click(screen.getByRole("button", { name: /^sign$/i }))

    expect(signDataMock).toHaveBeenCalledWith("payments", "k1", {
      value: "ZGF0YQ==",
      algorithm: "RS256",
      version: 1,
    })
  })

  it("base64-encodes plain text input before sending it", async () => {
    signDataMock.mockResolvedValue({
      keyId: "k1",
      algorithm: "RS256",
      value: "U0lH",
      version: 1,
    })

    renderPlayground()

    await userEvent.click(screen.getByRole("switch", { name: /plain text/i }))
    await userEvent.type(screen.getByLabelText(/data to sign/i), "hello")
    await userEvent.click(screen.getByRole("button", { name: /^sign$/i }))

    expect(signDataMock).toHaveBeenCalledWith("payments", "k1", {
      value: "aGVsbG8=",
      algorithm: "RS256",
      version: undefined,
    })
  })

  it("round-trips a signature into verify and reports it valid", async () => {
    signDataMock.mockResolvedValue({
      keyId: "k1",
      algorithm: "RS256",
      value: "U0lHTkFUVVJF",
      version: 1,
    })
    verifySignatureMock.mockResolvedValue({
      keyId: "k1",
      algorithm: "RS256",
      valid: true,
      version: 1,
    })

    renderPlayground()

    await userEvent.type(screen.getByLabelText(/data to sign/i), "ZGF0YQ==")
    await userEvent.click(screen.getByRole("button", { name: /^sign$/i }))
    await screen.findByText("U0lHTkFUVVJF")

    await userEvent.click(
      screen.getByRole("button", { name: /verify this signature/i })
    )
    await userEvent.click(screen.getByRole("button", { name: /^verify$/i }))

    expect(verifySignatureMock).toHaveBeenCalledWith("payments", "k1", {
      value: "ZGF0YQ==",
      signature: "U0lHTkFUVVJF",
      algorithm: "RS256",
      version: undefined,
    })
    expect(await screen.findByText(/signature is valid/i)).toBeInTheDocument()
  })

  it("reports a rejected signature distinctly from a failed request", async () => {
    verifySignatureMock.mockResolvedValue({
      keyId: "k1",
      algorithm: "RS256",
      valid: false,
      version: 1,
    })

    renderPlayground()

    await userEvent.click(screen.getByRole("tab", { name: /^verify$/i }))
    await userEvent.type(screen.getByLabelText(/signed data/i), "ZGF0YQ==")
    await userEvent.type(screen.getByLabelText(/signature/i), "QkFE")
    await userEvent.click(screen.getByRole("button", { name: /^verify$/i }))

    expect(
      await screen.findByText(/signature is not valid/i)
    ).toBeInTheDocument()
  })

  it("carries the AEAD nonce from encrypt straight into decrypt", async () => {
    const octKey = makeKey({ type: "oct-HSM", bits: 256 })
    encryptDataMock.mockResolvedValue({
      keyId: "k1",
      algorithm: "A256CBC",
      value: "Q0lQSEVS",
      nonce: "Tk9OQ0U=",
      version: 1,
    })
    decryptDataMock.mockResolvedValue({
      keyId: "k1",
      algorithm: "A256CBC",
      value: "ZGF0YQ==",
      version: 1,
    })

    renderPlayground(octKey)

    await userEvent.type(screen.getByLabelText(/data to encrypt/i), "ZGF0YQ==")
    await userEvent.click(screen.getByRole("button", { name: /^encrypt$/i }))
    await screen.findByText("Q0lQSEVS")

    await userEvent.click(
      screen.getByRole("button", { name: /decrypt this output/i })
    )
    await userEvent.click(screen.getByRole("button", { name: /^decrypt$/i }))

    expect(decryptDataMock).toHaveBeenCalledWith("payments", "k1", {
      value: "Q0lQSEVS",
      algorithm: "A256CBC",
      nonce: "Tk9OQ0U=",
      version: undefined,
    })
  })

  it("surfaces the server's error verbatim when an operation fails", async () => {
    signDataMock.mockRejectedValue(
      new ApiError({
        status_code: 403,
        message: "Insufficient permissions: key_access",
      })
    )

    renderPlayground()

    await userEvent.type(screen.getByLabelText(/data to sign/i), "ZGF0YQ==")
    await userEvent.click(screen.getByRole("button", { name: /^sign$/i }))

    expect(
      await screen.findByText(/insufficient permissions: key_access/i)
    ).toBeInTheDocument()
  })
})
