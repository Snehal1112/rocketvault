import { createRoute } from "@tanstack/react-router"

import { VaultList } from "@/components/vaults/vault-list"
import { vaultsRoute } from "@/routes/vaults"

function VaultsIndexPage() {
  return (
    <div className="mx-auto flex max-w-4xl flex-col gap-6 p-6">
      <h1 className="font-heading text-2xl font-medium">Vaults</h1>
      <VaultList />
    </div>
  )
}

export const vaultsIndexRoute = createRoute({
  getParentRoute: () => vaultsRoute,
  path: "/",
  component: VaultsIndexPage,
})
