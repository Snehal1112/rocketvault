// Browser-persisted auth/session state. The access token itself is
// deliberately NOT stored here -- it lives in memory only, inside
// auth-context.tsx (XSS blast-radius reduction, see the design doc's Auth &
// Session Model section). Only the refresh token (which the backend already
// hands back in the JSON body rather than an HttpOnly cookie) and the
// most-recently-used vault list live in localStorage.

const REFRESH_TOKEN_KEY = "rocketvault_refresh_token"
const RECENT_VAULTS_KEY = "rocketvault_recent_vaults"
const MAX_RECENT_VAULTS = 10

export function getRefreshToken(): string | null {
  return localStorage.getItem(REFRESH_TOKEN_KEY)
}

export function setRefreshToken(token: string): void {
  localStorage.setItem(REFRESH_TOKEN_KEY, token)
}

/** Clears the stored refresh token. Does not touch the recent-vaults list. */
export function clear(): void {
  localStorage.removeItem(REFRESH_TOKEN_KEY)
}

export function getRecentVaults(): string[] {
  const raw = localStorage.getItem(RECENT_VAULTS_KEY)
  if (!raw) {
    return []
  }

  try {
    const parsed: unknown = JSON.parse(raw)
    if (!Array.isArray(parsed)) {
      return []
    }
    return parsed.filter((entry): entry is string => typeof entry === "string")
  } catch {
    return []
  }
}

/**
 * Records `name` as the most recently used vault. Re-pushing an already
 * present entry moves it to the front instead of duplicating it. Capped at
 * `MAX_RECENT_VAULTS` -- this is a client-side mitigation for the fact that
 * `GET /vaults` only returns vaults the caller can manage, not every vault
 * they hold a data-plane role in (see the design doc's Deferred section).
 */
export function pushRecentVault(name: string): void {
  const deduped = getRecentVaults().filter((vaultName) => vaultName !== name)
  const updated = [name, ...deduped].slice(0, MAX_RECENT_VAULTS)
  localStorage.setItem(RECENT_VAULTS_KEY, JSON.stringify(updated))
}
