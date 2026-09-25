import { QueryClient, QueryClientProvider } from "@tanstack/react-query"
import { render, screen } from "@testing-library/react"
import userEvent from "@testing-library/user-event"
import { beforeEach, describe, expect, it, vi } from "vitest"

vi.mock("@/api/vaults", () => ({
  getVault: vi.fn(),
  updateVault: vi.fn(),
}))

import { getVault, updateVault } from "@/api/vaults"
import { VaultSettingsForm } from "@/components/vaults/vault-settings-form"

const getVaultMock = vi.mocked(getVault)
const updateVaultMock = vi.mocked(updateVault)

const baseVault = {
  id: "v1",
  name: "prod",
  enabled: true,
  purgeProtection: false,
  retentionDays: 90,
  createdBy: "u1",
  createdAt: "2026-01-01T00:00:00Z",
}

function renderForm() {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  })
  return render(
    <QueryClientProvider client={queryClient}>
      <VaultSettingsForm vaultName="prod" />
    </QueryClientProvider>
  )
}

beforeEach(() => {
  getVaultMock.mockReset()
  updateVaultMock.mockReset()
})

describe("VaultSettingsForm", () => {
  it("pre-fills from getVault and submits only the changed field", async () => {
    getVaultMock.mockResolvedValue(baseVault)
    updateVaultMock.mockResolvedValueOnce({ ...baseVault, retentionDays: 30 })

    renderForm()

    const retentionInput = await screen.findByLabelText(/retention/i)
    expect(retentionInput).toHaveValue(90)

    await userEvent.clear(retentionInput)
    await userEvent.type(retentionInput, "30")
    await userEvent.click(screen.getByRole("button", { name: /save/i }))

    expect(updateVaultMock).toHaveBeenCalledWith("prod", {
      retentionDays: 30,
    })
  })
})
