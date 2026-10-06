import { beforeEach, describe, expect, it, vi } from "vitest"

vi.mock("@/api/client", () => ({
  request: vi.fn(),
}))

import { request } from "@/api/client"
import { getConfig } from "@/api/config"

const requestMock = vi.mocked(request)

beforeEach(() => {
  requestMock.mockReset()
})

describe("getConfig", () => {
  it("fetches GET /config", async () => {
    requestMock.mockResolvedValueOnce({
      feature_flags: { oidc_enabled: false },
      public_api_url: "",
      sentry_dsn: "",
    })

    const config = await getConfig()

    expect(requestMock).toHaveBeenCalledWith("/config")
    expect(config.feature_flags.oidc_enabled).toBe(false)
  })
})
