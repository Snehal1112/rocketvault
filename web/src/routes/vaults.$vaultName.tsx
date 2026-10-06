import { createRoute, Outlet } from "@tanstack/react-router"

import { AppShell } from "@/components/app-shell/app-shell"
import { requireAuth } from "@/lib/auth/guards"
import { pushRecentVault } from "@/lib/auth/session-storage"
import { setLastVault } from "@/lib/current-vault"
import { vaultsRoute } from "@/routes/vaults"

/**
 * Layout for every /vaults/$vaultName/* route. Per the design doc §2, a
 * vault-scoped route's guard cannot be pre-checked client-side -- no
 * "which vaults am I in" endpoint exists -- so this only confirms the
 * caller is logged in at all; the first real data call's 403/404 is the
 * actual authorization boundary, rendered by that page's own error
 * boundary once it exists.
 */
export const vaultLayoutRoute = createRoute({
  getParentRoute: () => vaultsRoute,
  path: "$vaultName",
  beforeLoad: ({ params }) => {
    requireAuth()
    pushRecentVault(params.vaultName)
    setLastVault(params.vaultName)
  },
  component: () => (
    <AppShell>
      <Outlet />
    </AppShell>
  ),
})
