import { createRoute, redirect } from "@tanstack/react-router"

import { requireAuth } from "@/lib/auth/guards"
import { getLastVault } from "@/lib/current-vault"
import { rootRoute } from "@/routes/__root"

interface IndexSearch {
  vault?: string
}

/**
 * "/" always redirects: to the vault named in an explicit `?vault=` search
 * param if present, else the stored last-used vault (src/lib/current-vault.ts),
 * else the vault picker. The branching here mirrors
 * current-vault.ts's resolveIndexRedirect (tested in isolation there) but is
 * reimplemented with structured `params` rather than a pre-built path
 * string, because TanStack Router's typed `redirect({ to })` requires a
 * literal route path, not an arbitrary computed string.
 */
export const indexRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/",
  validateSearch: (search: Record<string, unknown>): IndexSearch => ({
    vault: typeof search.vault === "string" ? search.vault : undefined,
  }),
  beforeLoad: ({ search }) => {
    requireAuth()

    const vaultName = search.vault ?? getLastVault()
    if (vaultName) {
      throw redirect({
        to: "/vaults/$vaultName/secrets",
        params: { vaultName },
        replace: true,
      })
    }
    throw redirect({ to: "/vaults", replace: true })
  },
})
