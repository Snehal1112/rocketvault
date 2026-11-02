import { createRoute } from "@tanstack/react-router"

import { SecretCreateDialog } from "@/components/secrets/secret-create-dialog"
import { SecretList } from "@/components/secrets/secret-list"
import { SecretTransferDialog } from "@/components/secrets/secret-import-export"
import { vaultSecretsRoute } from "@/routes/vaults.$vaultName.secrets"

function VaultSecretsPage() {
  const { vaultName } = vaultSecretsIndexRoute.useParams()

  return (
    <div className="mx-auto flex w-full max-w-6xl flex-col gap-8 p-6">
      <header className="flex flex-wrap items-start justify-between gap-4">
        <div>
          <h1 className="font-heading text-2xl font-medium tracking-tight">
            Secrets
          </h1>
          <p className="mt-1 max-w-[60ch] text-sm text-muted-foreground">
            Values{" "}
            <span className="font-heading text-foreground">{vaultName}</span>{" "}
            holds on behalf of your applications. Open one to reveal, rotate, or
            retire it.
          </p>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <SecretTransferDialog vaultName={vaultName} />
          <SecretCreateDialog vaultName={vaultName} />
        </div>
      </header>
      <SecretList vaultName={vaultName} />
    </div>
  )
}

export const vaultSecretsIndexRoute = createRoute({
  getParentRoute: () => vaultSecretsRoute,
  path: "/",
  component: VaultSecretsPage,
})
