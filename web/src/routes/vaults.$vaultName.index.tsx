import { createRoute, redirect } from "@tanstack/react-router"

import { vaultLayoutRoute } from "@/routes/vaults.$vaultName"

// "/vaults/$vaultName" with no further segment redirects to the default
// tab, "secrets" -- see Epic 01's plan, Task 3, which relies on this.
export const vaultIndexRoute = createRoute({
  getParentRoute: () => vaultLayoutRoute,
  path: "/",
  beforeLoad: ({ params }) => {
    throw redirect({
      to: "/vaults/$vaultName/secrets",
      params: { vaultName: params.vaultName },
      replace: true,
    })
  },
})
