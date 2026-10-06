import { createRootRoute, Outlet } from "@tanstack/react-router"
import { QueryClientProvider } from "@tanstack/react-query"

import { refresh } from "@/api/auth"
import {
  clearSession,
  getAuthSnapshot,
  setSession,
} from "@/lib/auth/auth-context"
import { getRefreshToken } from "@/lib/auth/session-storage"
import { queryClient } from "@/lib/query-client"

function RootComponent() {
  return (
    <QueryClientProvider client={queryClient}>
      <Outlet />
    </QueryClientProvider>
  )
}

// Attempts one silent refresh from a stored refresh token before the app
// renders anything, so a returning user with a still-valid refresh token
// never sees the login screen. A missing or rejected refresh token just
// leaves the session anonymous -- this is not a route guard, so it never
// throws a redirect itself.
async function bootstrapSession(): Promise<void> {
  if (getAuthSnapshot().status !== "loading") {
    // Already resolved by a previous navigation in this session.
    return
  }

  const storedRefreshToken = getRefreshToken()
  if (!storedRefreshToken) {
    clearSession()
    return
  }

  try {
    const result = await refresh(storedRefreshToken)
    setSession(result.token, result.refreshToken, {
      id: result.userId,
      username: result.username,
      roles: result.roles,
    })
  } catch {
    clearSession()
  }
}

export const rootRoute = createRootRoute({
  beforeLoad: async () => {
    await bootstrapSession()
  },
  component: RootComponent,
})
