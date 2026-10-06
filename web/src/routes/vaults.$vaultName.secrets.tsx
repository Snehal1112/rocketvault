import { createRoute, Outlet } from "@tanstack/react-router"

import { vaultLayoutRoute } from "@/routes/vaults.$vaultName"

/**
 * Layout for the secrets section. The section's own screens are children:
 * the index (list), "deleted" (soft-delete recovery), and "$secretId"
 * (detail). Secrets are addressed by UUID, not name -- the backend
 * registers "{secret_id:[A-Fa-f0-9-]+}" and has no name-addressed route
 * (../../../api/secrets.go:62).
 */
export const vaultSecretsRoute = createRoute({
  getParentRoute: () => vaultLayoutRoute,
  path: "secrets",
  component: () => <Outlet />,
})
