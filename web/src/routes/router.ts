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
import { vaultKeysRoute } from "@/routes/vaults.$vaultName.keys"
import { vaultKeyDetailRoute } from "@/routes/vaults.$vaultName.keys.$keyId"
import { vaultSecretsRoute } from "@/routes/vaults.$vaultName.secrets"
import { vaultSecretDetailRoute } from "@/routes/vaults.$vaultName.secrets.$secretId"
import { vaultSecretsDeletedRoute } from "@/routes/vaults.$vaultName.secrets.deleted"
import { vaultSecretsIndexRoute } from "@/routes/vaults.$vaultName.secrets.index"
import { vaultSettingsRoute } from "@/routes/vaults.$vaultName.settings"
import { vaultsIndexRoute } from "@/routes/vaults.index"
import { rootRoute } from "@/routes/__root"

// "deleted" is registered alongside "$secretId": TanStack ranks a static
// segment above a dynamic one, so /secrets/deleted resolves to the
// deleted-items screen rather than being read as a secret id.
const vaultSecretsWithChildren = vaultSecretsRoute.addChildren([
  vaultSecretsIndexRoute,
  vaultSecretsDeletedRoute,
  vaultSecretDetailRoute,
])

const vaultLayoutWithChildren = vaultLayoutRoute.addChildren([
  vaultIndexRoute,
  vaultSecretsWithChildren,
  vaultKeysRoute,
  vaultKeyDetailRoute,
  vaultSettingsRoute,
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
