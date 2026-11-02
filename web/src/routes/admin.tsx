import { createRoute, Outlet } from "@tanstack/react-router"

import { AppShell } from "@/components/app-shell/app-shell"
import { requireGlobalAdmin } from "@/lib/auth/guards"
import { rootRoute } from "@/routes/__root"

// Layout for every /admin/* route. Unlike the vault branch, the global
// admin role IS derivable purely from the JWT-derived `roles` claim already
// in session state, so this guard can check it directly (design doc §2).
export const adminRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/admin",
  beforeLoad: () => {
    requireGlobalAdmin()
  },
  component: () => (
    <AppShell>
      <Outlet />
    </AppShell>
  ),
})
