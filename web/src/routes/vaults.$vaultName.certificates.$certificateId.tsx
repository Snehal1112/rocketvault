import { createRoute } from "@tanstack/react-router"

import { CertificateDetail } from "@/components/certificates/certificate-detail"
import { vaultCertificatesRoute } from "@/routes/vaults.$vaultName.certificates"

function VaultCertificateDetailPage() {
  const { vaultName, certificateId } = vaultCertificateDetailRoute.useParams()

  return (
    <div className="mx-auto flex w-full max-w-3xl flex-col gap-6 p-6">
      <CertificateDetail vaultName={vaultName} certificateId={certificateId} />
    </div>
  )
}

export const vaultCertificateDetailRoute = createRoute({
  getParentRoute: () => vaultCertificatesRoute,
  path: "$certificateId",
  component: VaultCertificateDetailPage,
})
