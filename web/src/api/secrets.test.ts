import { afterEach, beforeEach, describe, expect, it, vi } from "vitest"

vi.mock("@/api/client", () => ({
  request: vi.fn(),
}))

vi.mock("@/lib/auth/auth-context", () => ({
  getAccessToken: vi.fn(() => "test-token"),
}))

import { request } from "@/api/client"
import {
  backupSecret,
  createSecret,
  deleteSecret,
  exportSecrets,
  generateSecret,
  getLatestSecretVersion,
  getSecret,
  getSecretVersion,
  importSecrets,
  listDeletedSecrets,
  listSecrets,
  listSecretVersions,
  parseAttachmentFilename,
  purgeSecret,
  restoreDeletedSecret,
  restoreSecret,
  updateSecret,
} from "@/api/secrets"

const requestMock = vi.mocked(request)

const secretBody = {
  id: "s1",
  name: "db-password",
  tags: ["env=prod"],
  version: 3,
  content_type: "text/plain",
  created_at: "2026-01-01T00:00:00Z",
  enabled: true,
}

beforeEach(() => {
  requestMock.mockReset()
})

afterEach(() => {
  vi.unstubAllGlobals()
})

describe("listSecrets", () => {
  it("unwraps the {secrets, total} envelope onto camelCase objects", async () => {
    requestMock.mockResolvedValueOnce({ secrets: [secretBody], total: 1 })

    const secrets = await listSecrets("payments")

    expect(requestMock).toHaveBeenCalledWith("/vaults/payments/secrets")
    expect(secrets).toEqual([
      {
        id: "s1",
        name: "db-password",
        value: undefined,
        tags: ["env=prod"],
        version: 3,
        contentType: "text/plain",
        createdAt: "2026-01-01T00:00:00Z",
        updatedAt: undefined,
        enabled: true,
        expiresAt: undefined,
        notBefore: undefined,
      },
    ])
  })

  it("sends tags, page and per_page as query params when given", async () => {
    requestMock.mockResolvedValueOnce({ secrets: [], total: 0 })

    await listSecrets("payments", {
      tags: ["env=prod", "team=platform"],
      page: 0,
      perPage: 200,
    })

    expect(requestMock).toHaveBeenCalledWith(
      "/vaults/payments/secrets?tags=env%3Dprod%2Cteam%3Dplatform&page=0&per_page=200"
    )
  })

  it("encodes a vault name that needs it", async () => {
    requestMock.mockResolvedValueOnce({ secrets: [], total: 0 })

    await listSecrets("a b")

    expect(requestMock).toHaveBeenCalledWith("/vaults/a%20b/secrets")
  })
})

describe("getSecret", () => {
  it("fetches the id-addressed detail route and keeps the value", async () => {
    requestMock.mockResolvedValueOnce({ ...secretBody, value: "s3cr3t" })

    const secret = await getSecret("payments", "s1")

    expect(requestMock).toHaveBeenCalledWith("/vaults/payments/secrets/s1")
    expect(secret.value).toBe("s3cr3t")
  })
})

describe("createSecret", () => {
  it("posts name and value, omitting fields that were not supplied", async () => {
    requestMock.mockResolvedValueOnce(secretBody)

    await createSecret("payments", { name: "db-password", value: "hunter2" })

    expect(requestMock).toHaveBeenCalledWith("/vaults/payments/secrets", {
      method: "POST",
      body: JSON.stringify({ name: "db-password", value: "hunter2" }),
    })
  })

  it("maps optional fields onto their snake_case wire names", async () => {
    requestMock.mockResolvedValueOnce(secretBody)

    await createSecret("payments", {
      name: "db-password",
      value: "hunter2",
      tags: ["env=prod"],
      contentType: "text/plain",
      enabled: false,
      expiresAt: "2027-01-01T00:00:00Z",
    })

    expect(requestMock).toHaveBeenCalledWith("/vaults/payments/secrets", {
      method: "POST",
      body: JSON.stringify({
        name: "db-password",
        value: "hunter2",
        tags: ["env=prod"],
        content_type: "text/plain",
        enabled: false,
        expires_at: "2027-01-01T00:00:00Z",
      }),
    })
  })
})

describe("updateSecret", () => {
  it("PUTs only the explicitly-changed fields", async () => {
    requestMock.mockResolvedValueOnce(secretBody)

    await updateSecret("payments", "s1", { value: "rotated" })

    expect(requestMock).toHaveBeenCalledWith("/vaults/payments/secrets/s1", {
      method: "PUT",
      body: JSON.stringify({ value: "rotated" }),
    })
  })

  it("sends an explicit false for enabled rather than dropping it", async () => {
    requestMock.mockResolvedValueOnce(secretBody)

    await updateSecret("payments", "s1", { enabled: false, tags: [] })

    expect(requestMock).toHaveBeenCalledWith("/vaults/payments/secrets/s1", {
      method: "PUT",
      body: JSON.stringify({ tags: [], enabled: false }),
    })
  })
})

describe("deleteSecret", () => {
  it("sends DELETE to the vault-scoped detail route", async () => {
    requestMock.mockResolvedValueOnce(undefined)

    await deleteSecret("payments", "s1")

    expect(requestMock).toHaveBeenCalledWith("/vaults/payments/secrets/s1", {
      method: "DELETE",
    })
  })
})

describe("generateSecret", () => {
  it("posts the server-side generate options", async () => {
    requestMock.mockResolvedValueOnce({ ...secretBody, value: "Xk29!" })

    const secret = await generateSecret("payments", {
      name: "api-token",
      length: 32,
      useSymbols: true,
      useNumbers: true,
      useUppercase: true,
      useLowercase: false,
    })

    expect(requestMock).toHaveBeenCalledWith(
      "/vaults/payments/secrets/generate",
      {
        method: "POST",
        body: JSON.stringify({
          name: "api-token",
          length: 32,
          use_symbols: true,
          use_numbers: true,
          use_uppercase: true,
          use_lowercase: false,
        }),
      }
    )
    expect(secret.value).toBe("Xk29!")
  })
})

describe("versions", () => {
  const versionBody = {
    id: "v1",
    secret_id: "s1",
    name: "db-password",
    version: 2,
    created_at: "2026-01-02T00:00:00Z",
  }

  it("reads the versions list as a bare array, not an envelope", async () => {
    requestMock.mockResolvedValueOnce([versionBody])

    const versions = await listSecretVersions("payments", "s1")

    expect(requestMock).toHaveBeenCalledWith(
      "/vaults/payments/secrets/s1/versions"
    )
    expect(versions).toEqual([
      {
        id: "v1",
        secretId: "s1",
        name: "db-password",
        version: 2,
        createdAt: "2026-01-02T00:00:00Z",
      },
    ])
  })

  it("fetches one version's decrypted value by number", async () => {
    requestMock.mockResolvedValueOnce({
      ...versionBody,
      user_id: "u1",
      value: "old-value",
    })

    const version = await getSecretVersion("payments", "s1", 2)

    expect(requestMock).toHaveBeenCalledWith(
      "/vaults/payments/secrets/s1/versions/2"
    )
    expect(version.value).toBe("old-value")
    expect(version.userId).toBe("u1")
  })

  it("fetches the latest version through its dedicated route", async () => {
    requestMock.mockResolvedValueOnce({
      ...versionBody,
      user_id: "u1",
      value: "current",
    })

    await getLatestSecretVersion("payments", "s1")

    expect(requestMock).toHaveBeenCalledWith(
      "/vaults/payments/secrets/s1/versions/latest"
    )
  })
})

describe("backup and restore", () => {
  it("unwraps the {blob} envelope from backup", async () => {
    requestMock.mockResolvedValueOnce({ blob: "YmxvYg==" })

    const blob = await backupSecret("payments", "s1")

    expect(requestMock).toHaveBeenCalledWith(
      "/vaults/payments/secrets/s1/backup",
      { method: "POST" }
    )
    expect(blob).toBe("YmxvYg==")
  })

  it("posts the blob back to the vault-scoped restore route", async () => {
    requestMock.mockResolvedValueOnce({ status: "OK" })

    await restoreSecret("payments", "YmxvYg==")

    expect(requestMock).toHaveBeenCalledWith(
      "/vaults/payments/secrets/restore",
      {
        method: "POST",
        body: JSON.stringify({ blob: "YmxvYg==" }),
      }
    )
  })
})

describe("soft-delete", () => {
  it("unwraps the {deleted_secrets, total} envelope", async () => {
    requestMock.mockResolvedValueOnce({
      deleted_secrets: [
        {
          id: "s1",
          name: "db-password",
          version: 3,
          created_at: "2026-01-01T00:00:00Z",
          deleted_at: "2026-02-01T00:00:00Z",
        },
      ],
      total: 1,
    })

    const deleted = await listDeletedSecrets("payments")

    expect(requestMock).toHaveBeenCalledWith("/vaults/payments/deleted/secrets")
    expect(deleted).toEqual([
      {
        id: "s1",
        name: "db-password",
        version: 3,
        createdAt: "2026-01-01T00:00:00Z",
        deletedAt: "2026-02-01T00:00:00Z",
      },
    ])
  })

  it("recovers through POST .../restore", async () => {
    requestMock.mockResolvedValueOnce({ id: "s1", message: "ok" })

    await restoreDeletedSecret("payments", "s1")

    expect(requestMock).toHaveBeenCalledWith(
      "/vaults/payments/deleted/secrets/s1/restore",
      { method: "POST" }
    )
  })

  it("purges through DELETE .../purge", async () => {
    requestMock.mockResolvedValueOnce({ status: "OK" })

    await purgeSecret("payments", "s1")

    expect(requestMock).toHaveBeenCalledWith(
      "/vaults/payments/deleted/secrets/s1/purge",
      { method: "DELETE" }
    )
  })
})

describe("parseAttachmentFilename", () => {
  it("reads the backend's unquoted filename", () => {
    expect(
      parseAttachmentFilename(
        "attachment; filename=secrets-export-20260101-120000.csv",
        "fallback.csv"
      )
    ).toBe("secrets-export-20260101-120000.csv")
  })

  it("reads a quoted filename too", () => {
    expect(
      parseAttachmentFilename(
        'attachment; filename="my secrets.json"',
        "fallback.json"
      )
    ).toBe("my secrets.json")
  })

  it("falls back when the header is absent or unparseable", () => {
    expect(parseAttachmentFilename(null, "fallback.json")).toBe("fallback.json")
    expect(parseAttachmentFilename("attachment", "fallback.json")).toBe(
      "fallback.json"
    )
  })
})

describe("exportSecrets", () => {
  it("posts the format in the body and returns blob + filename", async () => {
    const fetchMock = vi.fn(
      async (_url: string, _init?: RequestInit) =>
        new Response("name,value\n", {
          status: 200,
          headers: {
            "Content-Type": "text/csv",
            "Content-Disposition":
              "attachment; filename=secrets-export-20260101-120000.csv",
          },
        })
    )
    vi.stubGlobal("fetch", fetchMock)

    const result = await exportSecrets("payments", {
      format: "csv",
      includeTags: true,
    })

    const [url, init] = fetchMock.mock.calls[0] ?? []
    expect(url).toBe("/api/v1/vaults/payments/secrets/export")
    expect(init?.method).toBe("POST")
    expect(init?.body).toBe(
      JSON.stringify({ format: "csv", encrypt: false, include_tags: true })
    )
    expect(result.filename).toBe("secrets-export-20260101-120000.csv")
    expect(await result.blob.text()).toBe("name,value\n")
  })

  it("throws an ApiError carrying a plain-text middleware rejection", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(
        async () =>
          new Response("Forbidden: access policy denied\n", { status: 403 })
      )
    )

    await expect(exportSecrets("payments", { format: "json" })).rejects.toThrow(
      /access policy denied/
    )
  })
})

describe("importSecrets", () => {
  it("uploads multipart/form-data without forcing a JSON content type", async () => {
    const fetchMock = vi.fn(
      async (_url: string, _init?: RequestInit) =>
        new Response(
          JSON.stringify({
            success: true,
            message: "Successfully imported 8/10 secrets",
            imported_count: 8,
            total_count: 10,
            format: "json",
            imported_at: "2026-02-01T00:00:00Z",
          }),
          { status: 200, headers: { "Content-Type": "application/json" } }
        )
    )
    vi.stubGlobal("fetch", fetchMock)

    const file = new File(["[]"], "secrets.json", { type: "application/json" })
    const result = await importSecrets("payments", {
      file,
      format: "json",
      overwrite: true,
    })

    const [url, init] = fetchMock.mock.calls[0] ?? []
    expect(url).toBe("/api/v1/vaults/payments/secrets/import")
    const form = init?.body as FormData
    expect(form.get("format")).toBe("json")
    expect(form.get("overwrite")).toBe("true")
    expect(form.get("file")).toBe(file)
    const headers = init?.headers as Headers
    expect(headers.get("Content-Type")).toBeNull()
    expect(result).toEqual({
      success: true,
      message: "Successfully imported 8/10 secrets",
      importedCount: 8,
      totalCount: 10,
      format: "json",
      importedAt: "2026-02-01T00:00:00Z",
    })
  })
})
