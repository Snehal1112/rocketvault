import { beforeEach, describe, expect, it, vi } from "vitest"

vi.mock("@/api/client", () => ({
  request: vi.fn(),
}))

import { request } from "@/api/client"
import {
  createVault,
  deleteVault,
  getVault,
  listVaults,
  purgeVault,
  updateVault,
} from "@/api/vaults"

const requestMock = vi.mocked(request)

const vaultBody = {
  id: "v1",
  name: "prod",
  enabled: true,
  purge_protection: false,
  retention_days: 90,
  created_by: "u1",
  created_at: "2026-01-01T00:00:00Z",
}

beforeEach(() => {
  requestMock.mockReset()
})

describe("listVaults", () => {
  it("fetches GET /vaults with no query string by default", async () => {
    requestMock.mockResolvedValueOnce({ vaults: [], total: 0 })

    await listVaults()

    expect(requestMock).toHaveBeenCalledWith("/vaults")
  })

  it("fetches GET /vaults?include_deleted=true when requested", async () => {
    requestMock.mockResolvedValueOnce({ vaults: [], total: 0 })

    await listVaults(true)

    expect(requestMock).toHaveBeenCalledWith("/vaults?include_deleted=true")
  })

  it("maps the response body onto camelCase Vault objects", async () => {
    requestMock.mockResolvedValueOnce({ vaults: [vaultBody], total: 1 })

    const vaults = await listVaults()

    expect(vaults).toEqual([
      {
        id: "v1",
        name: "prod",
        enabled: true,
        purgeProtection: false,
        retentionDays: 90,
        createdBy: "u1",
        createdAt: "2026-01-01T00:00:00Z",
        deletedAt: undefined,
        scheduledPurgeAt: undefined,
        tags: undefined,
        updatedAt: undefined,
        updatedBy: undefined,
      },
    ])
  })
})

describe("getVault", () => {
  it("fetches GET /vaults/{name}", async () => {
    requestMock.mockResolvedValueOnce(vaultBody)

    const vault = await getVault("prod")

    expect(requestMock).toHaveBeenCalledWith("/vaults/prod")
    expect(vault.name).toBe("prod")
  })
})

describe("createVault", () => {
  it("posts to /vaults", async () => {
    requestMock.mockResolvedValueOnce(vaultBody)

    await createVault({ name: "prod", tags: { env: "prod" } })

    expect(requestMock).toHaveBeenCalledWith("/vaults", {
      method: "POST",
      body: JSON.stringify({
        name: "prod",
        enabled: undefined,
        purge_protection: undefined,
        retention_days: undefined,
        tags: { env: "prod" },
      }),
    })
  })
})

describe("updateVault", () => {
  it("only sends explicitly-changed fields, not null/empty for unset ones", async () => {
    requestMock.mockResolvedValueOnce(vaultBody)

    await updateVault("prod", { retentionDays: 30 })

    expect(requestMock).toHaveBeenCalledWith("/vaults/prod", {
      method: "PATCH",
      body: JSON.stringify({ retention_days: 30 }),
    })
  })

  it("sends every explicitly-changed field when several are passed", async () => {
    requestMock.mockResolvedValueOnce(vaultBody)

    await updateVault("prod", { enabled: false, purgeProtection: true })

    expect(requestMock).toHaveBeenCalledWith("/vaults/prod", {
      method: "PATCH",
      body: JSON.stringify({ enabled: false, purge_protection: true }),
    })
  })
})

describe("deleteVault", () => {
  it("sends DELETE /vaults/{name}", async () => {
    requestMock.mockResolvedValueOnce(undefined)

    await deleteVault("prod")

    expect(requestMock).toHaveBeenCalledWith("/vaults/prod", {
      method: "DELETE",
    })
  })
})

describe("purgeVault", () => {
  it("sends DELETE /vaults/{name}/purge", async () => {
    requestMock.mockResolvedValueOnce(undefined)

    await purgeVault("prod")

    expect(requestMock).toHaveBeenCalledWith("/vaults/prod/purge", {
      method: "DELETE",
    })
  })
})
