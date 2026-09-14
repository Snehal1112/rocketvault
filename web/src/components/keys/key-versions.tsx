import { useState } from "react"
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query"
import { RotateCwIcon } from "lucide-react"

import { getKeyVersion, listKeyVersions, rotateKey } from "@/api/keys"
import { ApiError } from "@/api/types"
import { CopyValue } from "@/components/keys/copy-value"
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
  AlertDialogTrigger,
} from "@/components/ui/alert-dialog"
import { Badge } from "@/components/ui/badge"
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card"
import { Button } from "@/components/ui/button"
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table"
import { Skeleton } from "@/components/ui/skeleton"
import { formatRelativeTime } from "@/lib/format"

/**
 * Version history is a table, not a card grid: the operator scans it for one
 * row (design language doc, "Layout vocabulary"). Rotation lives here rather
 * than in the rotation-policy card because the two are genuinely different
 * actions -- this one happens now, that one happens on a schedule.
 */
export function KeyVersions({
  vaultName,
  keyId,
}: {
  vaultName: string
  keyId: string
}) {
  const queryClient = useQueryClient()
  const [confirmOpen, setConfirmOpen] = useState(false)
  const [expanded, setExpanded] = useState<number | null>(null)

  const { data, isLoading } = useQuery({
    queryKey: ["keys", vaultName, "versions", keyId],
    queryFn: () => listKeyVersions(vaultName, keyId),
  })

  const rotation = useMutation({
    mutationFn: () => rotateKey(vaultName, keyId),
    onSuccess: async () => {
      setConfirmOpen(false)
      await queryClient.invalidateQueries({ queryKey: ["keys", vaultName] })
    },
    onError: () => setConfirmOpen(false),
  })

  // The backend returns versions in insertion order; the newest one is the
  // one an operator cares about, so it goes first.
  const versions = [...(data ?? [])].sort((a, b) => b.version - a.version)
  const current = versions[0]?.version

  return (
    <Card>
      <CardHeader className="flex flex-row flex-wrap items-start justify-between gap-3">
        <div>
          <CardTitle>Versions</CardTitle>
          <CardDescription>
            Every rotation adds a version. Older versions stay usable for
            verification and decryption.
          </CardDescription>
        </div>
        <AlertDialog open={confirmOpen} onOpenChange={setConfirmOpen}>
          <AlertDialogTrigger render={<Button variant="outline" />}>
            <RotateCwIcon />
            Rotate now
          </AlertDialogTrigger>
          <AlertDialogContent>
            <AlertDialogHeader>
              <AlertDialogTitle>Rotate this key now?</AlertDialogTitle>
              <AlertDialogDescription>
                A new version is generated and becomes the one used by default
                for signing and encrypting. Previous versions are kept, not
                destroyed — existing signatures stay verifiable and data
                encrypted under an older version can still be decrypted.
              </AlertDialogDescription>
            </AlertDialogHeader>
            <AlertDialogFooter>
              <AlertDialogCancel>Cancel</AlertDialogCancel>
              <AlertDialogAction
                render={<Button />}
                onClick={() => rotation.mutate()}
              >
                Rotate
              </AlertDialogAction>
            </AlertDialogFooter>
          </AlertDialogContent>
        </AlertDialog>
      </CardHeader>
      <CardContent className="flex flex-col gap-3">
        {rotation.error && (
          <p role="alert" className="text-sm text-destructive">
            {rotation.error instanceof ApiError
              ? rotation.error.message
              : "Failed to rotate the key."}
          </p>
        )}

        {isLoading && <Skeleton className="h-24 w-full rounded-3xl" />}

        {!isLoading && versions.length === 0 && (
          <p className="text-sm text-muted-foreground">
            No version history is available for this key.
          </p>
        )}

        {versions.length > 0 && (
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Version</TableHead>
                <TableHead>Created</TableHead>
                <TableHead className="text-right">Public key</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {versions.map((version) => (
                <TableRow key={version.version}>
                  <TableCell className="font-heading">
                    {version.version}
                    {version.version === current && (
                      <Badge variant="secondary" className="ml-2">
                        Current
                      </Badge>
                    )}
                  </TableCell>
                  <TableCell className="text-muted-foreground">
                    {formatRelativeTime(version.createdAt)}
                  </TableCell>
                  <TableCell className="text-right">
                    <Button
                      variant="ghost"
                      size="sm"
                      onClick={() =>
                        setExpanded(
                          expanded === version.version ? null : version.version
                        )
                      }
                    >
                      {expanded === version.version
                        ? `Hide public key for version ${version.version}`
                        : `Show public key for version ${version.version}`}
                    </Button>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        )}

        {expanded !== null && (
          <VersionPublicKey
            vaultName={vaultName}
            keyId={keyId}
            version={expanded}
          />
        )}
      </CardContent>
    </Card>
  )
}

/** Fetched only when a row is expanded -- the list endpoint deliberately
 * carries no key material at all, so the components need their own request. */
function VersionPublicKey({
  vaultName,
  keyId,
  version,
}: {
  vaultName: string
  keyId: string
  version: number
}) {
  const { data, isLoading, error } = useQuery({
    queryKey: ["keys", vaultName, "versions", keyId, version],
    queryFn: () => getKeyVersion(vaultName, keyId, version),
  })

  if (isLoading) {
    return <Skeleton className="h-20 w-full rounded-3xl" />
  }

  if (error || !data) {
    return (
      <p role="alert" className="text-sm text-destructive">
        {error instanceof ApiError
          ? error.message
          : `Could not load version ${version}.`}
      </p>
    )
  }

  const { n, e, x, y } = data.publicJwk
  const components: [string, string][] = []
  if (n) {
    components.push(["n", n])
  }
  if (e) {
    components.push(["e", e])
  }
  if (x) {
    components.push(["x", x])
  }
  if (y) {
    components.push(["y", y])
  }

  return (
    <div className="flex flex-col gap-2 rounded-3xl border p-4">
      <p className="font-heading text-sm">Version {version}</p>
      {components.length === 0 ? (
        <p className="text-sm text-muted-foreground">
          No public components are exposed for this version.
        </p>
      ) : (
        components.map(([name, value]) => (
          <div key={name} className="flex flex-col gap-1">
            <p className="font-heading text-xs text-muted-foreground">{name}</p>
            <CopyValue value={value} label={`version ${version} ${name}`} />
          </div>
        ))
      )}
    </div>
  )
}
