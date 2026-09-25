import { createRoute } from "@tanstack/react-router"

import { AppShell } from "@/components/app-shell/app-shell"
import { VaultCreateDialog } from "@/components/vaults/vault-create-dialog"
import { VaultList } from "@/components/vaults/vault-list"
import { vaultsRoute } from "@/routes/vaults"

// The picker is the one /vaults/* screen outside vaultLayoutRoute's
// $vaultName branch (routes/vaults.$vaultName.tsx), so unlike every other
// vault-mode page it must mount AppShell itself rather than inheriting it
// from a parent layout route.
function VaultsIndexPage() {
  return (
    <AppShell>
      <div className="mx-auto flex w-full max-w-6xl flex-col gap-8 p-6">
        <header className="flex flex-wrap items-start justify-between gap-4">
          <div>
            <h1 className="font-heading text-2xl font-medium tracking-tight">
              Vaults
            </h1>
            <p className="mt-1 max-w-[60ch] text-sm text-muted-foreground">
              Isolated security boundaries you operate in. Open one to work with
              its secrets, keys, and certificates.
            </p>
          </div>
          <VaultCreateDialog />
        </header>
        <VaultList />
      </div>
    </AppShell>
  )
}

export const vaultsIndexRoute = createRoute({
  getParentRoute: () => vaultsRoute,
  path: "/",
  component: VaultsIndexPage,
})
