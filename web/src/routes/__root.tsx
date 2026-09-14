import { createRootRoute, Outlet } from "@tanstack/react-router"
import { QueryClientProvider } from "@tanstack/react-query"

import { queryClient } from "@/lib/query-client"

function RootComponent() {
  return (
    <QueryClientProvider client={queryClient}>
      <Outlet />
    </QueryClientProvider>
  )
}

export const rootRoute = createRootRoute({
  // Silent-refresh-on-boot (attempt one token refresh from a stored refresh
  // token before the app renders) is wired here once Task 5 adds
  // src/lib/auth/auth-context.tsx.
  beforeLoad: async () => {},
  component: RootComponent,
})
