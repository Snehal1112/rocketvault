import { createRoute } from "@tanstack/react-router"

import { KeyDetail } from "@/components/keys/key-detail"
import { vaultLayoutRoute } from "@/routes/vaults.$vaultName"

function VaultKeyDetailPage() {
  const { vaultName, keyId } = vaultKeyDetailRoute.useParams()

  return <KeyDetail vaultName={vaultName} keyId={keyId} />
}

export const vaultKeyDetailRoute = createRoute({
  getParentRoute: () => vaultLayoutRoute,
  path: "keys/$keyId",
  component: VaultKeyDetailPage,
})
