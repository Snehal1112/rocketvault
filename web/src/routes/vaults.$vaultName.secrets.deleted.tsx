import { createRoute, Link } from "@tanstack/react-router"
import { ArrowLeftIcon } from "lucide-react"

import { SecretDeletedList } from "@/components/secrets/secret-deleted-list"
import { vaultSecretsRoute } from "@/routes/vaults.$vaultName.secrets"

function VaultDeletedSecretsPage() {
  const { vaultName } = vaultSecretsDeletedRoute.useParams()

  return (
    <div className="mx-auto flex w-full max-w-4xl flex-col gap-6 p-6">
      <header className="flex flex-col gap-3">
        <Link
          to="/vaults/$vaultName/secrets"
          params={{ vaultName }}
          className="inline-flex w-fit items-center gap-1.5 text-sm text-muted-foreground underline-offset-4 hover:text-foreground hover:underline"
        >
          <ArrowLeftIcon className="size-4" />
          All secrets
        </Link>
        <div>
          <h1 className="font-heading text-2xl font-medium tracking-tight">
            Deleted secrets
          </h1>
          <p className="mt-1 max-w-[60ch] text-sm text-muted-foreground">
            Secrets removed from{" "}
            <span className="font-heading text-foreground">{vaultName}</span>{" "}
            but still recoverable. Once the vault's retention window closes they
            are purged automatically.
          </p>
        </div>
      </header>
      <SecretDeletedList vaultName={vaultName} />
    </div>
  )
}

export const vaultSecretsDeletedRoute = createRoute({
  getParentRoute: () => vaultSecretsRoute,
  path: "deleted",
  component: VaultDeletedSecretsPage,
})
