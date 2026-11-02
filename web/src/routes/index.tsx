import { createRoute } from "@tanstack/react-router"

import App from "@/App"
import { redirectAuthenticatedFromLanding } from "@/lib/auth/guards"
import { getLastVault } from "@/lib/current-vault"
import { rootRoute } from "@/routes/__root"

interface IndexSearch {
  vault?: string
}

/**
 * "/" is the public marketing landing page (src/App.tsx) for an anonymous
 * visitor -- matching how Azure's own Key Vault has no login-gated landing
 * screen of its own, since portal.azure.com and its marketing site are
 * separate surfaces. An authenticated session is redirected straight past
 * it (redirectAuthenticatedFromLanding, tested in guards.test.ts): to the
 * vault named in an explicit `?vault=` search param if present, else the
 * stored last-used vault (src/lib/current-vault.ts), else the vault picker.
 */
export const indexRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/",
  validateSearch: (search: Record<string, unknown>): IndexSearch => ({
    vault: typeof search.vault === "string" ? search.vault : undefined,
  }),
  beforeLoad: ({ search }) => {
    redirectAuthenticatedFromLanding(search.vault ?? getLastVault())
  },
  component: App,
})
