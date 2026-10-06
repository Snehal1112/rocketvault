import { createRoute, Outlet } from "@tanstack/react-router"

import { requireAuth } from "@/lib/auth/guards"
import { rootRoute } from "@/routes/__root"

// Layout for everything under /vaults/*. The picker itself (vaults.index.tsx)
// and the per-vault branch (vaults.$vaultName.tsx) are its children.
export const vaultsRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/vaults",
  beforeLoad: () => {
    requireAuth()
  },
  component: Outlet,
})
