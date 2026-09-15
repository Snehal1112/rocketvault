import { createRoute, Link } from "@tanstack/react-router"
import { ArchiveIcon } from "lucide-react"

import { KeyCreateDialog } from "@/components/keys/key-create-dialog"
import { KeyList } from "@/components/keys/key-list"
import { KeyRestoreDialog } from "@/components/keys/key-restore-dialog"
import { Button } from "@/components/ui/button"
import { vaultLayoutRoute } from "@/routes/vaults.$vaultName"

function VaultKeysPage() {
  const { vaultName } = vaultKeysRoute.useParams()

  return (
    <div className="mx-auto flex w-full max-w-6xl flex-col gap-8 p-6">
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
        <div className="flex flex-wrap items-center gap-3">
          <Button
            variant="ghost"
            render={
              <Link
                to="/vaults/$vaultName/keys/deleted"
                params={{ vaultName }}
              />
            }
          >
            <ArchiveIcon />
            Deleted
          </Button>
          <KeyRestoreDialog vaultName={vaultName} />
          <KeyCreateDialog vaultName={vaultName} />
        </div>
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
