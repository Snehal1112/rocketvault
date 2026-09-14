import { createRoute, Link } from "@tanstack/react-router"
import { ArrowLeftIcon } from "lucide-react"

import { KeyDeletedList } from "@/components/keys/key-deleted-list"
import { Button } from "@/components/ui/button"
import { vaultLayoutRoute } from "@/routes/vaults.$vaultName"

function VaultDeletedKeysPage() {
  const { vaultName } = vaultKeysDeletedRoute.useParams()

  return (
    <div className="flex w-full flex-col gap-6 p-2">
      <header className="flex flex-wrap items-start justify-between gap-4">
        <div>
          <h1 className="font-heading text-2xl font-medium tracking-tight">
            Deleted keys
          </h1>
          <p className="mt-1 max-w-[60ch] text-sm text-muted-foreground">
            Keys removed from{" "}
            <span className="font-heading text-foreground">{vaultName}</span>{" "}
            that are still inside the retention window. Recover one, or purge it
            for good.
          </p>
        </div>
        <Button
          variant="outline"
          render={<Link to="/vaults/$vaultName/keys" params={{ vaultName }} />}
        >
          <ArrowLeftIcon />
          Back to keys
        </Button>
      </header>
      <KeyDeletedList vaultName={vaultName} />
    </div>
  )
}

export const vaultKeysDeletedRoute = createRoute({
  getParentRoute: () => vaultLayoutRoute,
  path: "keys/deleted",
  component: VaultDeletedKeysPage,
})
