import { createRoute } from "@tanstack/react-router"

import { CertificateCreateDialog } from "@/components/certificates/certificate-create-dialog"
import { CertificateList } from "@/components/certificates/certificate-list"
import { vaultCertificatesRoute } from "@/routes/vaults.$vaultName.certificates"

function VaultCertificatesPage() {
  const { vaultName } = vaultCertificatesIndexRoute.useParams()

  return (
    <div className="mx-auto flex w-full max-w-6xl flex-col gap-8 p-6">
      <header className="flex flex-wrap items-start justify-between gap-4">
        <div>
          <h1 className="font-heading text-2xl font-medium tracking-tight">
            Certificates
          </h1>
          <p className="mt-1 max-w-[60ch] text-sm text-muted-foreground">
            X.509 certificates issued over keys{" "}
            <span className="font-heading text-foreground">{vaultName}</span>{" "}
            holds. Open one to edit its attributes, its policy, or its renewal
            schedule.
          </p>
        </div>
        <div className="flex flex-wrap items-center gap-3">
          <CertificateCreateDialog vaultName={vaultName} />
        </div>
      </header>
      <CertificateList vaultName={vaultName} />
    </div>
  )
}

export const vaultCertificatesIndexRoute = createRoute({
  getParentRoute: () => vaultCertificatesRoute,
  path: "/",
  component: VaultCertificatesPage,
})
