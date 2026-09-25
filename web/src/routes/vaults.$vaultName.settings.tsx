import { createRoute } from "@tanstack/react-router"

import { VaultDangerZone } from "@/components/vaults/vault-danger-zone"
import { VaultSettingsForm } from "@/components/vaults/vault-settings-form"
import { vaultLayoutRoute } from "@/routes/vaults.$vaultName"

function VaultSettingsPage() {
  const { vaultName } = vaultSettingsRoute.useParams()

  return (
    <div className="mx-auto flex w-full max-w-3xl flex-col gap-6 p-6">
      <header>
        <h1 className="font-heading text-2xl font-medium tracking-tight">
          Settings
        </h1>
        <p className="mt-1 max-w-[60ch] text-sm text-muted-foreground">
          How <span className="font-heading text-foreground">{vaultName}</span>{" "}
          behaves, and what it takes to remove it.
        </p>
      </header>
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
