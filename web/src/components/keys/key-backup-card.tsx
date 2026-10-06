import { backupKey } from "@/api/keys"
import { BackupCard } from "@/components/patterns/backup-card"

/**
 * A single-key backup. The blob is the only way to restore a key into a
 * different vault or instance, and the backend does NOT encrypt it -- so the
 * warning below is load-bearing, not boilerplate.
 *
 * The card itself is the shared <BackupCard> pattern. This component was the
 * original of that pattern, extracted once certificates needed the identical
 * shape rather than copied a second time.
 */
export function KeyBackupCard({
  vaultName,
  keyId,
  keyName,
}: {
  vaultName: string
  keyId: string
  keyName: string
}) {
  return (
    <BackupCard
      description="A portable copy of this key and its version history, restorable into this or another vault."
      warning="The backup blob is not encrypted. Treat it exactly as you would the private key itself — store it somewhere that already protects key material."
      filename={`${keyName}.keybackup`}
      errorFallback="Failed to create a backup."
      onCreate={() => backupKey(vaultName, keyId)}
    />
  )
}
