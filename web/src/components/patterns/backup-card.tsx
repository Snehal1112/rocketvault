import type { ReactNode } from "react"
import { useMutation } from "@tanstack/react-query"
import { DownloadIcon } from "lucide-react"

import { ApiError } from "@/api/types"
import { CopyValue } from "@/components/patterns/copy-value"
import { Button } from "@/components/ui/button"
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card"

/**
 * Offers the blob as a file download in addition to copy-to-clipboard. Not
 * every environment exposes createObjectURL (jsdom does not), so a failure
 * here is silent -- the blob is on screen either way.
 */
function offerDownload(blob: string, filename: string) {
  try {
    const url = URL.createObjectURL(new Blob([blob], { type: "text/plain" }))
    const anchor = document.createElement("a")
    anchor.href = url
    anchor.download = filename
    anchor.click()
    URL.revokeObjectURL(url)
  } catch {
    // No object-URL support; the operator can still copy the blob.
  }
}

/**
 * The single-item backup card: one button that asks the server for a portable
 * blob, then offers it as both a download and a copyable value.
 *
 * Extracted from the keys epic's own copy once certificates needed the
 * identical card (design language doc: a third resource type wanting the same
 * presentational shape is the point at which it belongs here rather than in
 * one epic's folder). Every difference between the two -- the warning copy,
 * the filename extension, the error fallback -- is a prop, because those are
 * the only things that genuinely differ per resource.
 */
export function BackupCard({
  description,
  warning,
  filename,
  errorFallback,
  onCreate,
}: {
  description: ReactNode
  /** Why this blob has to be handled carefully. Load-bearing, not
   * boilerplate: the backend does not encrypt these. */
  warning: ReactNode
  filename: string
  errorFallback: string
  onCreate: () => Promise<string>
}) {
  const backup = useMutation({
    mutationFn: onCreate,
    onSuccess: (blob) => offerDownload(blob, filename),
  })

  return (
    <Card>
      <CardHeader>
        <CardTitle>Backup</CardTitle>
        <CardDescription>{description}</CardDescription>
      </CardHeader>
      <CardContent className="flex flex-col gap-4">
        <p className="text-sm text-muted-foreground">{warning}</p>
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
              : errorFallback}
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
