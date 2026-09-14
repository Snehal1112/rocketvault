import { createRoute } from "@tanstack/react-router"

import { KeyCreateDialog } from "@/components/keys/key-create-dialog"
import { KeyList } from "@/components/keys/key-list"
import { vaultLayoutRoute } from "@/routes/vaults.$vaultName"

function VaultKeysPage() {
  const { vaultName } = vaultKeysRoute.useParams()

  return (
    <div className="flex w-full flex-col gap-6 p-2">
      <header className="flex flex-wrap items-start justify-between gap-4">
        <div>
          <h1 className="font-heading text-2xl font-medium tracking-tight">
            Keys
          </h1>
          <p className="mt-1 max-w-[60ch] text-sm text-muted-foreground">
            Cryptographic keys you sign, verify, encrypt and wrap with. Private
            material never leaves{" "}
            <span className="font-heading text-foreground">{vaultName}</span>.
          </p>
        </div>
        <KeyCreateDialog vaultName={vaultName} />
      </header>
      <KeyList vaultName={vaultName} />
    </div>
  )
}

export const vaultKeysRoute = createRoute({
  getParentRoute: () => vaultLayoutRoute,
  path: "keys",
  component: VaultKeysPage,
})
