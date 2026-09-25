import { backupCertificate } from "@/api/certificates"
import { BackupCard } from "@/components/patterns/backup-card"

/**
 * A single-certificate backup, using the shared <BackupCard> pattern.
 *
 * Worth stating plainly in the UI: this blob is NOT a PEM. No certificate
 * endpoint returns the certificate or its private key -- CertificateResponse
 * carries metadata only -- so an operator who came here looking for
 * "download the certificate" needs to know this is not that, and that no
 * such feature exists to look for elsewhere.
 */
export function CertificateBackupCard({
  vaultName,
  certificateId,
  certificateName,
}: {
  vaultName: string
  certificateId: string
  certificateName: string
}) {
  return (
    <BackupCard
      description="A portable copy of this certificate, restorable into this or another vault."
      warning="The blob is an opaque backup envelope, not a PEM — it is only useful as input to a restore, and the API exposes no way to download the certificate itself. It is not encrypted, so store it where you would store private key material."
      filename={`${certificateName}.certbackup`}
      errorFallback="Failed to create a backup."
      onCreate={() => backupCertificate(vaultName, certificateId)}
    />
  )
}
