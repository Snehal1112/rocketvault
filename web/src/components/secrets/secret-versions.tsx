import { useState } from "react"
import { useQuery } from "@tanstack/react-query"

import { getSecretVersion, listSecretVersions } from "@/api/secrets"
import { SecretValue } from "@/components/secrets/secret-value"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Skeleton } from "@/components/ui/skeleton"
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table"
import { formatRelativeTime } from "@/lib/format"

/**
 * Version history is a table, not a card grid: the design doc's rule is
 * cards for "open this one", tables for "scan many for one". Nothing is
 * navigated into here -- a version is inspected in place.
 *
 * The versions list carries metadata only; historical values are never
 * decrypted on that endpoint by design. Selecting a version issues its own
 * fetch, so no old plaintext is pulled into the browser unasked.
 */
export function SecretVersions({
  vaultName,
  secretId,
  currentVersion,
}: {
  vaultName: string
  secretId: string
  currentVersion: number
}) {
  const [selected, setSelected] = useState<number | null>(null)

  const { data: versions, isLoading } = useQuery({
    queryKey: ["secrets", vaultName, "versions", secretId],
    queryFn: () => listSecretVersions(vaultName, secretId),
  })

  const { data: version, isFetching } = useQuery({
    queryKey: ["secrets", vaultName, "version", secretId, selected],
    queryFn: () => getSecretVersion(vaultName, secretId, selected as number),
    enabled: selected !== null,
  })

  if (isLoading) {
    return (
      <div className="flex flex-col gap-2">
        <Skeleton className="h-8 w-full" />
        <Skeleton className="h-8 w-full" />
      </div>
    )
  }

  if (!versions || versions.length === 0) {
    return (
      <p className="text-sm text-muted-foreground">
        No version history recorded for this secret.
      </p>
    )
  }

  const ordered = [...versions].sort((a, b) => b.version - a.version)

  return (
    <div className="flex flex-col gap-4">
      <Table>
        <TableHeader>
          <TableRow>
            <TableHead>Version</TableHead>
            <TableHead>Created</TableHead>
            <TableHead className="text-right">Value</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {ordered.map((item) => (
            <TableRow key={item.id}>
              <TableCell className="font-heading">
                <span className="inline-flex items-center gap-2">
                  v{item.version}
                  {item.version === currentVersion && (
                    <Badge variant="secondary">Current</Badge>
                  )}
                </span>
              </TableCell>
              <TableCell className="text-muted-foreground">
                {formatRelativeTime(item.createdAt)}
              </TableCell>
              <TableCell className="text-right">
                <Button
                  type="button"
                  variant="ghost"
                  size="sm"
                  onClick={() =>
                    setSelected((current) =>
                      current === item.version ? null : item.version
                    )
                  }
                >
                  {selected === item.version ? "Close" : "Inspect"}
                </Button>
              </TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>

      {selected !== null && (
        <div className="flex flex-col gap-2 rounded-3xl bg-muted/40 p-4">
          <p className="text-xs text-muted-foreground">
            Value stored at{" "}
            <span className="font-heading text-foreground">v{selected}</span>
          </p>
          <SecretValue value={version?.value} isLoading={isFetching} />
        </div>
      )}
    </div>
  )
}
