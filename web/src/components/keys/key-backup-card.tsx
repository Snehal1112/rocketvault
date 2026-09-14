import { useMutation } from "@tanstack/react-query"
import { DownloadIcon } from "lucide-react"

import { backupKey } from "@/api/keys"
import { ApiError } from "@/api/types"
import { CopyValue } from "@/components/keys/copy-value"
import { Button } from "@/components/ui/button"
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card"

/** Offers the blob as a file download in addition to copy-to-clipboard. Not
 * every environment exposes createObjectURL (jsdom does not), so a failure
 * here is silent -- the blob is on screen either way. */
function offerDownload(blob: string, keyName: string) {
  try {
    const url = URL.createObjectURL(new Blob([blob], { type: "text/plain" }))
    const anchor = document.createElement("a")
    anchor.href = url
    anchor.download = `${keyName}.keybackup`
    anchor.click()
    URL.revokeObjectURL(url)
  } catch {
    // No object-URL support; the operator can still copy the blob.
  }
}

/**
 * A single-key backup. The blob is the only way to restore a key into a
 * different vault or instance, and the backend does NOT encrypt it -- so the
 * warning below is load-bearing, not boilerplate.
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
  const backup = useMutation({
    mutationFn: () => backupKey(vaultName, keyId),
    onSuccess: (blob) => offerDownload(blob, keyName),
  })

  return (
    <Card>
      <CardHeader>
        <CardTitle>Backup</CardTitle>
        <CardDescription>
          A portable copy of this key and its version history, restorable into
          this or another vault.
        </CardDescription>
      </CardHeader>
      <CardContent className="flex flex-col gap-4">
        <p className="text-sm text-muted-foreground">
          The backup blob is not encrypted. Treat it exactly as you would the
          private key itself — store it somewhere that already protects key
          material.
        </p>
        <div>
          <Button
            variant="outline"
            disabled={backup.isPending}
            onClick={() => backup.mutate()}
          >
            <DownloadIcon />
            {backup.isPending ? "Creating…" : "Create backup"}
          </Button>
        </div>
        {backup.error && (
          <p role="alert" className="text-sm text-destructive">
            {backup.error instanceof ApiError
              ? backup.error.message
              : "Failed to create a backup."}
          </p>
        )}
        {backup.data && (
          <div className="flex flex-col gap-2">
            <p className="text-sm text-muted-foreground">Backup blob</p>
            <CopyValue value={backup.data} label="backup blob" />
          </div>
        )}
      </CardContent>
    </Card>
  )
}
