import { createRoute, Link } from "@tanstack/react-router"
import { ArrowLeftIcon } from "lucide-react"

import { CertificateDeletedList } from "@/components/certificates/certificate-deleted-list"
import { vaultCertificatesRoute } from "@/routes/vaults.$vaultName.certificates"

function VaultDeletedCertificatesPage() {
  const { vaultName } = vaultCertificatesDeletedRoute.useParams()

  return (
    <div className="mx-auto flex w-full max-w-4xl flex-col gap-6 p-6">
      <header className="flex flex-col gap-3">
        <Link
          to="/vaults/$vaultName/certificates"
          params={{ vaultName }}
          className="inline-flex w-fit items-center gap-1.5 text-sm text-muted-foreground underline-offset-4 hover:text-foreground hover:underline"
        >
          <ArrowLeftIcon className="size-4" />
          All certificates
        </Link>
        <div>
          <h1 className="font-heading text-2xl font-medium tracking-tight">
            Deleted certificates
          </h1>
          <p className="mt-1 max-w-[60ch] text-sm text-muted-foreground">
            Certificates removed from{" "}
            <span className="font-heading text-foreground">{vaultName}</span>{" "}
            but still recoverable. Once the vault's retention window closes they
            are purged automatically.
          </p>
        </div>
      </header>
      <CertificateDeletedList vaultName={vaultName} />
    </div>
  )
}

export const vaultCertificatesDeletedRoute = createRoute({
  getParentRoute: () => vaultCertificatesRoute,
  path: "deleted",
  component: VaultDeletedCertificatesPage,
})
