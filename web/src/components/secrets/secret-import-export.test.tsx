import { QueryClient, QueryClientProvider } from "@tanstack/react-query"
import { render, screen, within } from "@testing-library/react"
import userEvent from "@testing-library/user-event"
import { beforeEach, describe, expect, it, vi } from "vitest"

vi.mock("@/api/secrets", async () => {
  const actual =
    await vi.importActual<typeof import("@/api/secrets")>("@/api/secrets")
  return {
    ...actual,
    exportSecrets: vi.fn(),
    importSecrets: vi.fn(),
    restoreSecret: vi.fn(),
  }
})

vi.mock("@/components/secrets/download", () => ({
  downloadBlob: vi.fn(),
  downloadText: vi.fn(),
}))

import { exportSecrets, importSecrets, restoreSecret } from "@/api/secrets"
import { downloadBlob } from "@/components/secrets/download"
import { SecretTransferDialog } from "@/components/secrets/secret-import-export"

const exportSecretsMock = vi.mocked(exportSecrets)
const importSecretsMock = vi.mocked(importSecrets)
const restoreSecretMock = vi.mocked(restoreSecret)
const downloadBlobMock = vi.mocked(downloadBlob)

function renderTransferDialog() {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  })
  return render(
    <QueryClientProvider client={queryClient}>
      <SecretTransferDialog vaultName="payments" />
    </QueryClientProvider>
  )
}

async function openDialog(user: ReturnType<typeof userEvent.setup>) {
  renderTransferDialog()
  await user.click(
    await screen.findByRole("button", { name: /import \/ export/i })
  )
  return within(await screen.findByRole("dialog"))
}

beforeEach(() => {
  exportSecretsMock.mockReset()
  importSecretsMock.mockReset()
  restoreSecretMock.mockReset()
  downloadBlobMock.mockReset()
})

describe("SecretTransferDialog export", () => {
  it("downloads a JSON export under the filename the API supplies", async () => {
    const user = userEvent.setup()
    const blob = new Blob(["[]"], { type: "application/json" })
    exportSecretsMock.mockResolvedValueOnce({
      blob,
      filename: "secrets-export-20260101-120000.json",
    })

    const dialog = await openDialog(user)
    await user.click(dialog.getByRole("button", { name: /export secrets/i }))

    expect(exportSecretsMock).toHaveBeenCalledWith("payments", {
      format: "json",
      includeTags: true,
      encrypt: false,
      passphrase: undefined,
    })
    expect(downloadBlobMock).toHaveBeenCalledWith(
      blob,
      "secrets-export-20260101-120000.json"
    )
  })

  it("exports CSV when that format is chosen", async () => {
    const user = userEvent.setup()
    const blob = new Blob(["name,value\n"], { type: "text/csv" })
    exportSecretsMock.mockResolvedValueOnce({
      blob,
      filename: "secrets-export-20260101-120000.csv",
    })

    const dialog = await openDialog(user)
    await user.selectOptions(dialog.getByLabelText("Format"), "csv")
    await user.click(dialog.getByRole("button", { name: /export secrets/i }))

    expect(exportSecretsMock).toHaveBeenCalledWith(
      "payments",
      expect.objectContaining({ format: "csv" })
    )
    expect(downloadBlobMock).toHaveBeenCalledWith(
      blob,
      "secrets-export-20260101-120000.csv"
    )
  })

  it("refuses to seal an export with no passphrase, without calling the API", async () => {
    const user = userEvent.setup()

    const dialog = await openDialog(user)
    await user.click(dialog.getByRole("checkbox", { name: /seal with a/i }))
    await user.click(dialog.getByRole("button", { name: /export secrets/i }))

    expect(
      await screen.findByText(/passphrase is required/i)
    ).toBeInTheDocument()
    expect(exportSecretsMock).not.toHaveBeenCalled()
  })
})

describe("SecretTransferDialog import", () => {
  it("uploads the chosen file and reports the counts the API returns", async () => {
    const user = userEvent.setup()
    importSecretsMock.mockResolvedValueOnce({
      success: true,
      message: "Successfully imported 8/10 secrets",
      importedCount: 8,
      totalCount: 10,
      format: "json",
      importedAt: "2026-02-01T00:00:00Z",
    })

    const dialog = await openDialog(user)
    await user.click(dialog.getByRole("tab", { name: /import/i }))

    const file = new File(["[]"], "secrets.json", { type: "application/json" })
    await user.upload(dialog.getByLabelText("File"), file)
    await user.click(dialog.getByRole("button", { name: /import secrets/i }))

    expect(importSecretsMock).toHaveBeenCalledWith("payments", {
      file,
      format: "json",
      overwrite: false,
      passphrase: undefined,
    })
    expect(await screen.findByText("8/10")).toBeInTheDocument()
  })

  it("says the API cannot name the rows that did not import", async () => {
    const user = userEvent.setup()
    importSecretsMock.mockResolvedValueOnce({
      success: true,
      message: "Successfully imported 8/10 secrets",
      importedCount: 8,
      totalCount: 10,
      format: "json",
      importedAt: "2026-02-01T00:00:00Z",
    })

    const dialog = await openDialog(user)
    await user.click(dialog.getByRole("tab", { name: /import/i }))
    await user.upload(
      dialog.getByLabelText("File"),
      new File(["[]"], "secrets.json", { type: "application/json" })
    )
    await user.click(dialog.getByRole("button", { name: /import secrets/i }))

    expect(
      await screen.findByText(/does not report which/i)
    ).toBeInTheDocument()
  })
})

describe("SecretTransferDialog restore", () => {
  it("posts a pasted backup blob to the vault-scoped restore endpoint", async () => {
    const user = userEvent.setup()
    restoreSecretMock.mockResolvedValueOnce(undefined)

    const dialog = await openDialog(user)
    await user.click(dialog.getByRole("tab", { name: /restore/i }))
    await user.type(dialog.getByLabelText(/backup blob/i), "YmxvYg==")
    await user.click(dialog.getByRole("button", { name: /restore secret/i }))

    expect(restoreSecretMock).toHaveBeenCalledWith("payments", "YmxvYg==")
    expect(await screen.findByText(/secret restored/i)).toBeInTheDocument()
  })
})
