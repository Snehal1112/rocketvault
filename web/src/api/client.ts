import { ApiError, type ApiErrorBody } from "@/api/types"
import {
  clearSession,
  getAccessToken,
  setSession,
} from "@/lib/auth/auth-context"
import { getRefreshToken } from "@/lib/auth/session-storage"

const API_BASE = "/api/v1"

// Paths the backend serves publicly -- no Authorization header attached even
// when a token is present, and never subject to the 401-refresh-retry flow.
const PUBLIC_PATHS = ["/users/login", "/users/refresh", "/config"]

function isPublicPath(path: string): boolean {
  return PUBLIC_PATHS.some(
    (publicPath) => path === publicPath || path.startsWith(`${publicPath}?`)
  )
}

function buildHeaders(init: RequestInit, token: string | null): Headers {
  const headers = new Headers(init.headers)
  if (init.body && !headers.has("Content-Type")) {
    headers.set("Content-Type", "application/json")
  }
  if (token) {
    headers.set("Authorization", `Bearer ${token}`)
  }
  return headers
}

async function parseErrorBody(response: Response): Promise<ApiError> {
  let body: Partial<ApiErrorBody> = {}
  try {
    body = (await response.json()) as Partial<ApiErrorBody>
  } catch {
    // The body wasn't JSON (or was empty) -- fall through with the response
    // status as the only information available.
  }

  return new ApiError({
    message: body.message ?? response.statusText ?? "Request failed",
    id: body.id,
    detailed_error: body.detailed_error,
    request_id: body.request_id,
    status_code: body.status_code ?? response.status,
    retry_after_seconds: body.retry_after_seconds,
  })
}

async function parseSuccessBody<T>(response: Response): Promise<T> {
  if (response.status === 204) {
    return undefined as T
  }
  const text = await response.text()
  return (text ? JSON.parse(text) : undefined) as T
}

interface RefreshResponseBody {
  token: string
  refresh_token: string
  user_id: string
  username: string
  roles: string[]
}

// The 401-retry path posts to /users/refresh directly (raw fetch) rather
// than going through api/auth.ts's refresh() -- that module calls back into
// this one's request(), which would recurse into this same interceptor.
async function performRefresh(): Promise<string | null> {
  const refreshToken = getRefreshToken()
  if (!refreshToken) {
    return null
  }

  const response = await fetch(`${API_BASE}/users/refresh`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ refresh_token: refreshToken }),
  })

  if (!response.ok) {
    return null
  }

  const data = (await response.json()) as RefreshResponseBody
  setSession(data.token, data.refresh_token, {
    id: data.user_id,
    username: data.username,
    roles: data.roles,
  })

  return data.token
}

// Concurrent 401s must trigger exactly one refresh call -- the refresh
// endpoint rotates the refresh token server-side, so a second concurrent
// refresh would invalidate the first one's new token. Every caller that 401s
// while a refresh is already in flight awaits the same promise instead of
// starting its own.
let refreshPromise: Promise<string | null> | null = null

function refreshAccessToken(): Promise<string | null> {
  if (!refreshPromise) {
    refreshPromise = performRefresh().finally(() => {
      refreshPromise = null
    })
  }
  return refreshPromise
}

/**
 * Makes a request to the RocketVault API. `path` is relative to `/api/v1`
 * (e.g. "/vaults", "/users/login"). Attaches the current access token unless
 * `path` is a public route. On a 401 from a non-public route, attempts
 * exactly one deduped token refresh and retries the original request once;
 * a 403, or a failed refresh, is never retried.
 */
export async function request<T>(
  path: string,
  init: RequestInit = {}
): Promise<T> {
  const isPublic = isPublicPath(path)
  const token = isPublic ? null : getAccessToken()
  const headers = buildHeaders(init, token)

  const response = await fetch(`${API_BASE}${path}`, { ...init, headers })

  if (response.status === 401 && !isPublic) {
    const newToken = await refreshAccessToken()
    if (!newToken) {
      clearSession()
      throw await parseErrorBody(response)
    }

    const retryHeaders = buildHeaders(init, newToken)
    const retryResponse = await fetch(`${API_BASE}${path}`, {
      ...init,
      headers: retryHeaders,
    })
    if (!retryResponse.ok) {
      throw await parseErrorBody(retryResponse)
    }
    return parseSuccessBody<T>(retryResponse)
  }

  if (!response.ok) {
    throw await parseErrorBody(response)
  }

  return parseSuccessBody<T>(response)
}
