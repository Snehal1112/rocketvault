import { request } from "@/api/client"

interface LoginResponseBody {
  token: string
  refresh_token: string
  user_id: string
  username: string
  roles: string[]
}

export interface LoginResult {
  token: string
  refreshToken: string
  userId: string
  username: string
  roles: string[]
}

/** POST /users/login. Login is one call -- username, password, and TOTP
 * code together -- there is no separate TOTP-challenge round trip. */
export async function login(
  username: string,
  password: string,
  totpCode: string
): Promise<LoginResult> {
  const body = await request<LoginResponseBody>("/users/login", {
    method: "POST",
    body: JSON.stringify({
      username,
      password,
      totp_code: totpCode,
    }),
  })

  return {
    token: body.token,
    refreshToken: body.refresh_token,
    userId: body.user_id,
    username: body.username,
    roles: body.roles,
  }
}

interface RefreshResponseBody extends LoginResponseBody {
  expires_at: string
}

export interface RefreshResult extends LoginResult {
  expiresAt: string
}

/**
 * POST /users/refresh. Used for the silent-refresh-on-boot attempt wired
 * into __root.tsx's beforeLoad; the 401-retry path in src/api/client.ts
 * posts to this same endpoint directly (raw fetch) instead of calling this
 * function, to avoid recursing back into client.ts's own interceptor.
 */
export async function refresh(refreshToken: string): Promise<RefreshResult> {
  const body = await request<RefreshResponseBody>("/users/refresh", {
    method: "POST",
    body: JSON.stringify({ refresh_token: refreshToken }),
  })

  return {
    token: body.token,
    refreshToken: body.refresh_token,
    userId: body.user_id,
    username: body.username,
    roles: body.roles,
    expiresAt: body.expires_at,
  }
}

/**
 * Client-side logout. No dedicated server-side single-session logout route
 * exists -- verified against api/users.go (InitUsers): it registers
 * /users/login, /users/refresh, and /users/sessions (GET + two DELETE
 * variants), but no /users/logout, and neither LoginResponse nor
 * RefreshTokenResponse carry a session_id the frontend could target with
 * DELETE /users/sessions/{id}. This matches the CLI's own "users logout"
 * precedent (see ../CLAUDE.md): clearing local session state is the whole
 * of "logout" here too. A user who wants to invalidate every session
 * (including this one) has revokeAllSessions() for that, from the account
 * page's session list.
 */
export async function logout(): Promise<void> {
  await Promise.resolve()
}

interface SessionSummaryBody {
  id: string
  device_info: string
  ip_address: string
  user_agent: string
  expires_at: string
  last_used_at: string
  created_at: string
  revoked: boolean
}

export interface SessionSummary {
  id: string
  deviceInfo: string
  ipAddress: string
  userAgent: string
  expiresAt: string
  lastUsedAt: string
  createdAt: string
  revoked: boolean
}

/** GET /users/sessions. */
export async function listSessions(): Promise<SessionSummary[]> {
  const body = await request<{ sessions: SessionSummaryBody[]; total: number }>(
    "/users/sessions"
  )

  return body.sessions.map((session) => ({
    id: session.id,
    deviceInfo: session.device_info,
    ipAddress: session.ip_address,
    userAgent: session.user_agent,
    expiresAt: session.expires_at,
    lastUsedAt: session.last_used_at,
    createdAt: session.created_at,
    revoked: session.revoked,
  }))
}

/** DELETE /users/sessions/{session_id}. */
export async function revokeSession(sessionId: string): Promise<void> {
  await request(`/users/sessions/${sessionId}`, { method: "DELETE" })
}

/** DELETE /users/sessions. */
export async function revokeAllSessions(): Promise<void> {
  await request("/users/sessions", { method: "DELETE" })
}
