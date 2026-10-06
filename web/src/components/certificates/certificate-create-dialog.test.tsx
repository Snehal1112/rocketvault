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

vi.mock("@/api/certificates", () => ({
  createCertificate: vi.fn(),
  listCertificates: vi.fn(),
}))

vi.mock("@/api/keys", () => ({
  listKeys: vi.fn(),
}))

import type { Certificate } from "@/api/certificates"
import { createCertificate, listCertificates } from "@/api/certificates"
import type { Key } from "@/api/keys"
import { listKeys } from "@/api/keys"
import { CertificateCreateDialog } from "@/components/certificates/certificate-create-dialog"

const createCertificateMock = vi.mocked(createCertificate)
const listCertificatesMock = vi.mocked(listCertificates)
const listKeysMock = vi.mocked(listKeys)

const KEY_ID = "22222222-2222-2222-2222-222222222222"
const CA_ID = "33333333-3333-3333-3333-333333333333"

const issuedCertificate: Certificate = {
  id: "11111111-1111-1111-1111-111111111111",
  name: "api.example.com",
  userId: "u1",
  createdAt: "2026-01-01T00:00:00Z",
  tags: [],
  autoRenew: false,
  renewalDays: 30,
  enabled: true,
}

const signingKey: Key = {
  id: KEY_ID,
  name: "web-tls-key",
  type: "RSA",
  userId: "u1",
  revoked: false,
  createdAt: "2026-01-01T00:00:00Z",
  tags: [],
  enabled: true,
  bits: 2048,
  publicJwk: {},
}

const caCertificate: Certificate = {
  ...issuedCertificate,
  id: CA_ID,
  name: "internal-root-ca",
}

function renderDialog() {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  })
  const testRootRoute = createRootRoute({
    component: () => <CertificateCreateDialog vaultName="payments" />,
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

async function openDialog() {
  renderDialog()
  await userEvent.click(
    await screen.findByRole("button", { name: /issue certificate/i })
  )
  await screen.findByRole("textbox", { name: /common name/i })
}

/** Types into a combobox and picks the single matching option. */
async function pick(fieldLabel: RegExp, optionName: RegExp) {
  await userEvent.click(screen.getByRole("combobox", { name: fieldLabel }))
  await userEvent.click(await screen.findByRole("option", { name: optionName }))
}

beforeEach(() => {
  createCertificateMock.mockReset().mockResolvedValue(issuedCertificate)
  listKeysMock.mockReset().mockResolvedValue([signingKey])
  listCertificatesMock.mockReset().mockResolvedValue([caCertificate])
})

describe("CertificateCreateDialog", () => {
  it("refuses to submit without a key rather than posting an empty key_id", async () => {
    await openDialog()

    await userEvent.type(
      screen.getByRole("textbox", { name: /common name/i }),
      "api.example.com"
    )
    await userEvent.click(
      screen.getByRole("button", { name: /^issue certificate$/i })
    )

    expect(createCertificateMock).not.toHaveBeenCalled()
    expect(
      await screen.findByText(/pick the key this certificate is issued over/i)
    ).toBeInTheDocument()
  })

  it("submits the issuance fields with the chosen key", async () => {
    await openDialog()

    await userEvent.type(
      screen.getByRole("textbox", { name: /common name/i }),
      "api.example.com"
    )
    await pick(/signing key/i, /web-tls-key/i)
    await userEvent.click(
      screen.getByRole("button", { name: /^issue certificate$/i })
    )

    expect(createCertificateMock).toHaveBeenCalledTimes(1)
    const [vault, input] = createCertificateMock.mock.calls[0]
    expect(vault).toBe("payments")
    expect(input).toMatchObject({
      name: "api.example.com",
      keyId: KEY_ID,
      validityDays: 365,
      autoRenew: false,
      isCa: false,
      enabled: true,
      purgeProtection: false,
    })
  })

  it("omits ca_cert_id entirely when no CA was chosen -- that is the self-signed path", async () => {
    await openDialog()

    await userEvent.type(
      screen.getByRole("textbox", { name: /common name/i }),
      "api.example.com"
    )
    await pick(/signing key/i, /web-tls-key/i)
    await userEvent.click(
      screen.getByRole("button", { name: /^issue certificate$/i })
    )

    expect(createCertificateMock.mock.calls[0][1]).not.toHaveProperty(
      "caCertId"
    )
  })

  it("sends caCertId when a signing CA was chosen", async () => {
    await openDialog()

    await userEvent.type(
      screen.getByRole("textbox", { name: /common name/i }),
      "api.example.com"
    )
    await pick(/signing key/i, /web-tls-key/i)
    await pick(/sign with a ca certificate/i, /internal-root-ca/i)
    await userEvent.click(
      screen.getByRole("button", { name: /^issue certificate$/i })
    )

    expect(createCertificateMock.mock.calls[0][1]).toMatchObject({
      caCertId: CA_ID,
    })
  })

  it("offers no ca_key_id field -- the backend struct's field is unused", async () => {
    await openDialog()

    expect(screen.queryByLabelText(/ca key/i)).not.toBeInTheDocument()
  })

  it("surfaces the server's refusal instead of a generic failure", async () => {
    createCertificateMock.mockRejectedValue(
      new (await import("@/api/types")).ApiError({
        status_code: 403,
        message: "Insufficient permissions: certificates_create",
      })
    )

    await openDialog()
    await userEvent.type(
      screen.getByRole("textbox", { name: /common name/i }),
      "api.example.com"
    )
    await pick(/signing key/i, /web-tls-key/i)
    await userEvent.click(
      screen.getByRole("button", { name: /^issue certificate$/i })
    )

    expect(
      await screen.findByText(/insufficient permissions: certificates_create/i)
    ).toBeInTheDocument()
  })
})
