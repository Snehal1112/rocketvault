import { createRouter } from "@tanstack/react-router"

import { accountRoute } from "@/routes/account"
import { adminRoute } from "@/routes/admin"
import { adminIndexRoute } from "@/routes/admin.index"
import { indexRoute } from "@/routes/index"
import { loginRoute } from "@/routes/login"
import { oidcCallbackRoute } from "@/routes/oidc.callback"
import { vaultsRoute } from "@/routes/vaults"
import { vaultLayoutRoute } from "@/routes/vaults.$vaultName"
import { vaultIndexRoute } from "@/routes/vaults.$vaultName.index"
import { vaultSecretsRoute } from "@/routes/vaults.$vaultName.secrets"
import { vaultsIndexRoute } from "@/routes/vaults.index"
import { rootRoute } from "@/routes/__root"

const vaultLayoutWithChildren = vaultLayoutRoute.addChildren([
  vaultIndexRoute,
  vaultSecretsRoute,
])

const vaultsWithChildren = vaultsRoute.addChildren([
  vaultsIndexRoute,
  vaultLayoutWithChildren,
])

const adminWithChildren = adminRoute.addChildren([adminIndexRoute])

const routeTree = rootRoute.addChildren([
  indexRoute,
  loginRoute,
  oidcCallbackRoute,
  accountRoute,
  vaultsWithChildren,
  adminWithChildren,
])

export const router = createRouter({ routeTree, basepath: "/app" })

declare module "@tanstack/react-router" {
  interface Register {
    router: typeof router
  }
}
