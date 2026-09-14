import { createRoute } from "@tanstack/react-router"

import { VaultDangerZone } from "@/components/vaults/vault-danger-zone"
import { VaultSettingsForm } from "@/components/vaults/vault-settings-form"
import { vaultLayoutRoute } from "@/routes/vaults.$vaultName"

function VaultSettingsPage() {
  const { vaultName } = vaultSettingsRoute.useParams()

  return (
    <div className="mx-auto flex max-w-2xl flex-col gap-8 p-6">
      <h1 className="font-heading text-2xl font-medium">Vault settings</h1>
      <VaultSettingsForm vaultName={vaultName} />
      <VaultDangerZone vaultName={vaultName} />
    </div>
  )
}

export const vaultSettingsRoute = createRoute({
  getParentRoute: () => vaultLayoutRoute,
  path: "settings",
  component: VaultSettingsPage,
})
