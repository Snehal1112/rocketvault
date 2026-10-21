import { beforeEach, describe, expect, it, vi } from "vitest"

vi.mock("@/api/client", () => ({
  request: vi.fn(),
}))

import { request } from "@/api/client"
import {
  listSessions,
  login,
  refresh,
  revokeAllSessions,
  revokeSession,
} from "@/api/auth"

const requestMock = vi.mocked(request)

beforeEach(() => {
  requestMock.mockReset()
})

describe("login", () => {
  it("posts username, password, and totp_code to /users/login", async () => {
    requestMock.mockResolvedValueOnce({
      token: "t",
      refresh_token: "r",
      user_id: "u1",
      username: "alice",
      roles: ["user"],
    })

    const result = await login("alice", "hunter2", "123456")

    expect(requestMock).toHaveBeenCalledWith("/users/login", {
      method: "POST",
      body: JSON.stringify({
        username: "alice",
        password: "hunter2",
        totp_code: "123456",
      }),
    })
    expect(result).toEqual({
      token: "t",
      refreshToken: "r",
      userId: "u1",
      username: "alice",
      roles: ["user"],
    })
  })
})

describe("refresh", () => {
  it("posts refresh_token to /users/refresh", async () => {
    requestMock.mockResolvedValueOnce({
      token: "t2",
      refresh_token: "r2",
      user_id: "u1",
      username: "alice",
      roles: ["user"],
      expires_at: "2026-01-01T00:00:00Z",
    })

    const result = await refresh("r1")

    expect(requestMock).toHaveBeenCalledWith("/users/refresh", {
      method: "POST",
      body: JSON.stringify({ refresh_token: "r1" }),
    })
    expect(result).toEqual({
      token: "t2",
      refreshToken: "r2",
      userId: "u1",
      username: "alice",
      roles: ["user"],
      expiresAt: "2026-01-01T00:00:00Z",
    })
  })
})

describe("sessions", () => {
  it("lists sessions from GET /users/sessions", async () => {
    requestMock.mockResolvedValueOnce({
      sessions: [
        {
          id: "s1",
          device_info: "Chrome",
          ip_address: "1.2.3.4",
          user_agent: "ua",
          expires_at: "e",
          last_used_at: "l",
          created_at: "c",
          revoked: false,
        },
      ],
      total: 1,
    })

    const sessions = await listSessions()

    expect(requestMock).toHaveBeenCalledWith("/users/sessions")
    expect(sessions).toEqual([
      {
        id: "s1",
        deviceInfo: "Chrome",
        ipAddress: "1.2.3.4",
        userAgent: "ua",
        expiresAt: "e",
        lastUsedAt: "l",
        createdAt: "c",
        revoked: false,
      },
    ])
  })

  it("revokes a specific session via DELETE /users/sessions/{id}", async () => {
    requestMock.mockResolvedValueOnce({ status: "OK" })

    await revokeSession("s1")

    expect(requestMock).toHaveBeenCalledWith("/users/sessions/s1", {
      method: "DELETE",
    })
  })

  it("revokes all sessions via DELETE /users/sessions", async () => {
    requestMock.mockResolvedValueOnce({ status: "OK" })

    await revokeAllSessions()

    expect(requestMock).toHaveBeenCalledWith("/users/sessions", {
      method: "DELETE",
    })
  })
})
