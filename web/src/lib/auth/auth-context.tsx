import { useSyncExternalStore } from "react"

import {
  clear as clearStoredRefreshToken,
  setRefreshToken,
} from "@/lib/auth/session-storage"

export type AuthStatus = "loading" | "authenticated" | "anonymous"

export interface AuthUser {
  id: string
  username: string
  roles: string[]
}

interface AuthState {
  status: AuthStatus
  accessToken: string | null
  user: AuthUser | null
}

// The access token lives here, in memory only -- never in localStorage --
// per the design doc's Auth & Session Model (XSS blast-radius reduction).
// Implemented with useSyncExternalStore rather than a React Context Provider
// (or Redux) because a plain module-level store lets non-React code --
// src/api/client.ts's request()/refresh interceptor -- read and clear the
// current session without needing to be inside the React tree.
let state: AuthState = { status: "loading", accessToken: null, user: null }
const listeners = new Set<() => void>()

function emitChange(): void {
  for (const listener of listeners) {
    listener()
  }
}

function subscribe(listener: () => void): () => void {
  listeners.add(listener)
  return () => {
    listeners.delete(listener)
  }
}

function getSnapshot(): AuthState {
  return state
}

/**
 * The current in-memory access token, or null when not authenticated. A
 * plain function (not a hook) so src/api/client.ts can read it outside React.
 */
export function getAccessToken(): string | null {
  return state.accessToken
}

/**
 * A plain-function snapshot of the current session, for use outside React --
 * route `beforeLoad` guards (src/lib/auth/guards.ts) run before any component
 * renders, so they cannot call the useAuth() hook.
 */
export function getAuthSnapshot(): {
  status: AuthStatus
  user: AuthUser | null
} {
  return { status: state.status, user: state.user }
}

/**
 * Moves the session to "authenticated", storing the access token in memory
 * and persisting the refresh token to localStorage.
 */
export function setSession(
  token: string,
  refreshToken: string,
  user: AuthUser
): void {
  state = { status: "authenticated", accessToken: token, user }
  setRefreshToken(refreshToken)
  emitChange()
}

/**
 * Moves the session to "anonymous", clearing the in-memory access token and
 * the stored refresh token.
 */
export function clearSession(): void {
  state = { status: "anonymous", accessToken: null, user: null }
  clearStoredRefreshToken()
  emitChange()
}

/** Test-only: resets the module-level store to its initial "loading" state. */
export function resetAuthStateForTests(): void {
  state = { status: "loading", accessToken: null, user: null }
}

export function useAuth() {
  const snapshot = useSyncExternalStore(subscribe, getSnapshot)
  const isGlobalAdmin = snapshot.user?.roles.includes("admin") ?? false

  return {
    status: snapshot.status,
    user: snapshot.user,
    isGlobalAdmin,
    setSession,
    clearSession,
  }
}
