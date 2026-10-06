import { createRoute } from "@tanstack/react-router"

import { SecretDetail } from "@/components/secrets/secret-detail"
import { vaultSecretsRoute } from "@/routes/vaults.$vaultName.secrets"

function VaultSecretDetailPage() {
  const { vaultName, secretId } = vaultSecretDetailRoute.useParams()

  return (
    <div className="mx-auto flex w-full max-w-3xl flex-col gap-6 p-6">
      <SecretDetail vaultName={vaultName} secretId={secretId} />
    </div>
  )
}

export const vaultSecretDetailRoute = createRoute({
  getParentRoute: () => vaultSecretsRoute,
  path: "$secretId",
  component: VaultSecretDetailPage,
})
